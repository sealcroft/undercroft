//! SQLite-backed palace storage, one database per vault.
//!
//! Mirrors mempalace's `sqlite_exact` backend shape (documents +
//! metadata_json + embedding blob + FTS5 when available) with the vault
//! security layer threaded through every read and write:
//!
//! * content / embeddings pass through [`Vault::content_at_rest`] — sealed
//!   vaults store only ciphertext, and nothing content-derived (including
//!   the FTS index) is persisted in plaintext;
//! * every row carries an HMAC tag over `id \x1f meta_json \x1f content`,
//!   verified on read and re-walkable via [`PalaceStore::verify`];
//! * an append-only `audit` table records the tag of every write in order,
//!   which must replay to the manifest's HMAC chain head.

pub mod kg;
pub mod manage;
pub mod remote;

pub use kg::{KgStats, Triple};
pub use manage::{DedupReport, DrawerSummary, Hallway, PalaceStats, Tunnel};

use rusqlite::{params, Connection, OptionalExtension};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use undercroft_core::embed::{cosine, Embedder};
use undercroft_core::{Drawer, DrawerMeta, HashEmbedder};
use undercroft_vault::{SecurityLevel, Vault, VaultError};

/// Drawer count at which the BM25 prefilter engages for hmac-only vaults.
/// Below this a full decrypt-free scan is cheap and keeps semantic-only
/// recall exact; above it the FTS5 candidate cut dominates search cost.
const DEFAULT_FTS_PREFILTER_MIN: usize = 2048;

/// How the semantic and lexical signals are combined at rank time.
///
/// `Bm25` (the default) blends cosine with a real Okapi BM25 lexical score
/// (IDF-weighted, length-normalized) computed over the decrypted candidate
/// set, plus recency. `Legacy` is the older behavior: the lexical term is a
/// flat term-overlap fraction that weights every matched query term equally
/// — measurably worse (see benchmarks/RESULTS.md; BM25 lifts LongMemEval-S
/// R@5 from 90.4% to 95.0% with the hash embedder, almost entirely on
/// paraphrase-heavy preference questions). `Rrf` fuses the cosine and BM25
/// rankings with reciprocal-rank fusion — scale-free, but it discards score
/// magnitude and benchmarked below `Bm25`. All three verify HMACs
/// identically; fusion only reorders already-trusted candidates.
///
/// Override at open with `UNDERCROFT_FUSION` (`bm25` / `legacy` / `rrf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fusion {
    Legacy,
    Bm25,
    Rrf,
}

impl Fusion {
    fn from_env() -> Self {
        match std::env::var("UNDERCROFT_FUSION").ok().as_deref() {
            Some(v) if v.eq_ignore_ascii_case("legacy") => Fusion::Legacy,
            Some(v) if v.eq_ignore_ascii_case("rrf") => Fusion::Rrf,
            _ => Fusion::Bm25,
        }
    }
}

// Okapi BM25 constants (the standard defaults).
const BM25_K1: f32 = 1.2;
const BM25_B: f32 = 0.75;
// Reciprocal-rank-fusion damping — the canonical value from the original
// RRF paper; larger flattens the contribution of top ranks.
const RRF_K: f32 = 60.0;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("corrupt row {id}: {reason}")]
    CorruptRow { id: String, reason: String },
    #[error("integrity failure on record {0} — HMAC mismatch")]
    Integrity(String),
    #[error(
        "vault was embedded with {stored:?} ({stored_dim}d) but the current embedder is \
         {current:?} ({current_dim}d); searching across a model swap silently degrades recall. \
         Set UNDERCROFT_FORCE_EMBEDDER=1 to record the new identity, then run `undercroft repair` \
         to re-embed."
    )]
    EmbedderMismatch {
        stored: String,
        stored_dim: usize,
        current: String,
        current_dim: usize,
    },
    #[error("remote index error: {0}")]
    Index(#[from] undercroft_index::IndexError),
}

/// Raw drawer row as read for search: (id, meta_json, content, embedding, tag).
type SearchRow = (String, String, Vec<u8>, Vec<u8>, Vec<u8>);

pub(crate) fn canonical(id: &str, meta_json: &[u8], content_at_rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(id.len() + meta_json.len() + content_at_rest.len() + 2);
    out.extend_from_slice(id.as_bytes());
    out.push(0x1f);
    out.extend_from_slice(meta_json);
    out.push(0x1f);
    out.extend_from_slice(content_at_rest);
    out
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub drawer: Drawer,
    pub score: f32,
    pub semantic: f32,
    pub lexical: f32,
}

#[derive(Debug, Default, Clone)]
pub struct SearchOptions {
    pub wing: Option<String>,
    pub room: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub records_checked: u64,
    pub bad_records: Vec<String>,
    pub chain_ok: bool,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.bad_records.is_empty() && self.chain_ok
    }
}

pub struct PalaceStore {
    conn: Connection,
    vault: Vault,
    embedder: Box<dyn Embedder + Send>,
    /// In-process decrypted-embedding cache for long-running servers
    /// (serve-mcp / serve-http / daemon): sealed vaults pay AEAD decryption
    /// of every embedding once instead of on every search. Never persisted
    /// — this is the in-memory role embedded ChromaDB's index played
    /// upstream, without writing plaintext-derived data to disk.
    emb_cache: std::cell::RefCell<Option<std::collections::HashMap<String, Vec<f32>>>>,
    /// Whether the FTS5 BM25 prefilter index exists. Only ever true for
    /// hmac-only vaults — sealed vaults must not persist anything
    /// plaintext-derived, an FTS index included.
    fts: bool,
    /// Drawer count at which the prefilter engages; `None` disables it.
    fts_min: Option<usize>,
    /// How semantic and lexical signals are combined at rank time.
    fusion: Fusion,
}

impl PalaceStore {
    /// Open with the default deterministic hashed n-gram embedder.
    pub fn open(vault: Vault) -> Result<Self, StoreError> {
        Self::open_with_embedder(vault, Box::new(HashEmbedder))
    }

    /// Open with an explicit embedder. The embedder's identity (model name
    /// and dimension) is recorded on first use and enforced afterwards:
    /// searching across a silent model swap degrades recall, so a mismatch
    /// is an error unless `UNDERCROFT_FORCE_EMBEDDER=1` re-records it
    /// (follow with `repair` to re-embed).
    pub fn open_with_embedder(
        vault: Vault,
        embedder: Box<dyn Embedder + Send>,
    ) -> Result<Self, StoreError> {
        let store = Self::open_inner(vault, embedder)?;
        store.enforce_embedder_identity()?;
        Ok(store)
    }

    fn enforce_embedder_identity(&self) -> Result<(), StoreError> {
        let stored_name: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'embedder_name'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let stored_dim: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'embedder_dim'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let current_name = self.embedder.model_name().to_string();
        let current_dim = self.embedder.dimension();
        match (stored_name, stored_dim) {
            (Some(name), Some(dim)) => {
                let dim: usize = dim.parse().unwrap_or(0);
                if name != current_name || (dim != 0 && dim != current_dim) {
                    if std::env::var("UNDERCROFT_FORCE_EMBEDDER").ok().as_deref() == Some("1") {
                        self.record_embedder_identity()?;
                        return Ok(());
                    }
                    return Err(StoreError::EmbedderMismatch {
                        stored: name,
                        stored_dim: dim,
                        current: current_name,
                        current_dim,
                    });
                }
                Ok(())
            }
            _ => self.record_embedder_identity(),
        }
    }

    fn record_embedder_identity(&self) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('embedder_name', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![self.embedder.model_name()],
        )?;
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('embedder_dim', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![self.embedder.dimension().to_string()],
        )?;
        Ok(())
    }

    fn open_inner(vault: Vault, embedder: Box<dyn Embedder + Send>) -> Result<Self, StoreError> {
        let conn = Connection::open(vault.db_path())?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS drawers (
                 seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                 id         TEXT NOT NULL UNIQUE,
                 wing       TEXT NOT NULL,
                 room       TEXT NOT NULL,
                 meta_json  TEXT NOT NULL,
                 content    BLOB NOT NULL,
                 embedding  BLOB NOT NULL,
                 tag        BLOB NOT NULL,
                 filed_at   TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_drawers_wing_room ON drawers(wing, room);
             CREATE TABLE IF NOT EXISTS audit (
                 seq       INTEGER PRIMARY KEY AUTOINCREMENT,
                 record_id TEXT NOT NULL,
                 tag       BLOB NOT NULL,
                 at        TEXT NOT NULL
             );",
        )?;
        let fts_min = match std::env::var("UNDERCROFT_FTS_PREFILTER_MIN") {
            Ok(v) if v.eq_ignore_ascii_case("off") => None,
            Ok(v) => Some(v.parse().unwrap_or(DEFAULT_FTS_PREFILTER_MIN)),
            Err(_) => Some(DEFAULT_FTS_PREFILTER_MIN),
        };
        let mut store = Self {
            conn,
            vault,
            embedder,
            emb_cache: std::cell::RefCell::new(None),
            fts: false,
            fts_min,
            fusion: Fusion::from_env(),
        };
        store.fts = store.init_fts_schema()?;
        store.init_kg_schema()?;
        store.init_manage_schema()?;
        Ok(store)
    }

    /// hmac-only vaults keep a plaintext FTS5 index over drawer content as
    /// a BM25 prefilter (triggers keep it coherent through every insert /
    /// content update / delete). Sealed vaults never get one. Returns
    /// whether the index is usable; `false` (e.g. an SQLite build without
    /// the fts5 module) means search falls back to the full scan.
    fn init_fts_schema(&self) -> Result<bool, StoreError> {
        if !matches!(self.vault.level(), SecurityLevel::HmacOnly) {
            return Ok(false);
        }
        if self
            .conn
            .execute_batch(
                "CREATE VIRTUAL TABLE IF NOT EXISTS drawers_fts USING fts5(
                     content, content='drawers', content_rowid='seq'
                 );
                 CREATE TRIGGER IF NOT EXISTS drawers_fts_ai AFTER INSERT ON drawers BEGIN
                     INSERT INTO drawers_fts(rowid, content) VALUES (new.seq, new.content);
                 END;
                 CREATE TRIGGER IF NOT EXISTS drawers_fts_ad AFTER DELETE ON drawers BEGIN
                     INSERT INTO drawers_fts(drawers_fts, rowid, content)
                     VALUES ('delete', old.seq, old.content);
                 END;
                 CREATE TRIGGER IF NOT EXISTS drawers_fts_au AFTER UPDATE OF content ON drawers BEGIN
                     INSERT INTO drawers_fts(drawers_fts, rowid, content)
                     VALUES ('delete', old.seq, old.content);
                     INSERT INTO drawers_fts(rowid, content) VALUES (new.seq, new.content);
                 END;",
            )
            .is_err()
        {
            return Ok(false);
        }
        // Backfill drawers written before the index existed (a vault
        // predating this feature, or a dropped index): an external-content
        // rebuild re-reads every row from `drawers`.
        let n_drawers: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM drawers", [], |r| r.get(0))?;
        let n_fts: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM drawers_fts", [], |r| r.get(0))?;
        if n_fts != n_drawers {
            self.conn
                .execute("INSERT INTO drawers_fts(drawers_fts) VALUES('rebuild')", [])?;
        }
        Ok(true)
    }

    /// Tune when the BM25 prefilter engages on hmac-only vaults: it runs
    /// once the palace holds at least `min` drawers; `None` disables it
    /// entirely. Also settable at open via `UNDERCROFT_FTS_PREFILTER_MIN`
    /// (a number, or `off`).
    pub fn set_fts_prefilter_min(&mut self, min: Option<usize>) {
        self.fts_min = min;
    }

    /// Select the rank-time fusion strategy. Defaults to the value of
    /// `UNDERCROFT_FUSION` at open (`legacy` / `bm25` / `rrf`, legacy
    /// otherwise). See [`Fusion`].
    pub fn set_fusion(&mut self, fusion: Fusion) {
        self.fusion = fusion;
    }

    /// Decrypt every drawer embedding into an in-memory map so subsequent
    /// searches skip per-row AEAD work. Kept coherent by `upsert` /
    /// `delete_drawer`. Returns the number of cached vectors.
    pub fn warm_embedding_cache(&self) -> Result<usize, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id, embedding FROM drawers")?;
        let rows: Vec<(String, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut map = std::collections::HashMap::with_capacity(rows.len());
        for (id, emb_rest) in rows {
            let emb = self
                .vault
                .embedding_from_rest(&id, &emb_rest)
                .map_err(|e| StoreError::CorruptRow {
                    id: id.clone(),
                    reason: e.to_string(),
                })?;
            map.insert(id, emb);
        }
        let n = map.len();
        *self.emb_cache.borrow_mut() = Some(map);
        Ok(n)
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM drawers", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// Insert or replace a drawer. Returns `true` if the id was new.
    pub fn upsert(&mut self, drawer: &Drawer) -> Result<bool, StoreError> {
        let meta_json =
            serde_json::to_string(&drawer.meta).map_err(|e| StoreError::CorruptRow {
                id: drawer.id.clone(),
                reason: e.to_string(),
            })?;
        let content_rest = self
            .vault
            .content_at_rest(&drawer.id, drawer.content.as_bytes());
        let embedding = self.embedder.embed(&drawer.content);
        let emb_rest = self.vault.embedding_at_rest(&drawer.id, &embedding);
        let tag = self
            .vault
            .tag(&canonical(&drawer.id, meta_json.as_bytes(), &content_rest));
        let fp = self.fingerprint(&drawer.content);
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("rfc3339 now");

        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT seq FROM drawers WHERE id = ?1",
                params![drawer.id],
                |r| r.get(0),
            )
            .optional()?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO drawers (id, wing, room, meta_json, content, embedding, tag, fp, filed_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT(id) DO UPDATE SET
                 wing = excluded.wing,
                 room = excluded.room,
                 meta_json = excluded.meta_json,
                 content = excluded.content,
                 embedding = excluded.embedding,
                 tag = excluded.tag,
                 fp = excluded.fp,
                 updated_at = excluded.updated_at",
            params![
                drawer.id,
                drawer.meta.wing,
                drawer.meta.room,
                meta_json,
                content_rest,
                emb_rest,
                tag.as_slice(),
                fp,
                now,
            ],
        )?;
        tx.execute(
            "INSERT INTO audit (record_id, tag, at) VALUES (?1, ?2, ?3)",
            params![drawer.id, tag.as_slice(), now],
        )?;
        tx.commit()?;
        self.vault.commit_write(&tag)?;
        if let Some(cache) = self.emb_cache.borrow_mut().as_mut() {
            cache.insert(drawer.id.clone(), embedding);
        }
        Ok(existing.is_none())
    }

    /// Fetch one drawer by id, verifying its HMAC and decrypting content.
    pub fn get(&self, id: &str) -> Result<Option<Drawer>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, meta_json, content, tag FROM drawers WHERE id = ?1",
                params![id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((id, meta_json, content_rest, tag)) => {
                self.vault
                    .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                    .map_err(|_| StoreError::Integrity(id.clone()))?;
                Ok(Some(self.decode(&id, &meta_json, &content_rest)?))
            }
        }
    }

    fn decode(&self, id: &str, meta_json: &str, content_rest: &[u8]) -> Result<Drawer, StoreError> {
        let meta: DrawerMeta =
            serde_json::from_str(meta_json).map_err(|e| StoreError::CorruptRow {
                id: id.into(),
                reason: e.to_string(),
            })?;
        let plain = self
            .vault
            .content_from_rest(id, content_rest)
            .map_err(|e| StoreError::CorruptRow {
                id: id.into(),
                reason: e.to_string(),
            })?;
        let content = String::from_utf8(plain).map_err(|e| StoreError::CorruptRow {
            id: id.into(),
            reason: e.to_string(),
        })?;
        Ok(Drawer {
            id: id.to_string(),
            content,
            meta,
        })
    }

    /// Most recently filed drawers (optionally scoped to a wing) — the
    /// palace's "essential story" feed used by wake-up.
    pub fn recent(&self, wing: Option<&str>, limit: usize) -> Result<Vec<Drawer>, StoreError> {
        let mut sql = String::from("SELECT id, meta_json, content, tag FROM drawers");
        if wing.is_some() {
            sql.push_str(" WHERE wing = ?1");
        }
        sql.push_str(" ORDER BY updated_at DESC, seq DESC LIMIT ");
        sql.push_str(&limit.to_string());
        let mut stmt = self.conn.prepare(&sql)?;
        let map = |r: &rusqlite::Row<'_>| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        };
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = match wing {
            Some(w) => stmt.query_map(params![w], map)?.collect::<Result<_, _>>()?,
            None => stmt.query_map([], map)?.collect::<Result<_, _>>()?,
        };
        let mut out = Vec::with_capacity(rows.len());
        for (id, meta_json, content_rest, tag) in rows {
            self.vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .map_err(|_| StoreError::Integrity(id.clone()))?;
            out.push(self.decode(&id, &meta_json, &content_rest)?);
        }
        Ok(out)
    }

    /// Hybrid search: hashed-embedding cosine + lexical term overlap +
    /// recency decay. Sealed vaults decrypt-scan; nothing derived from
    /// plaintext is read from disk indexes. hmac-only vaults above the
    /// prefilter threshold first cut candidates to the FTS5 BM25 top-K
    /// (final scoring is unchanged — the index only narrows the scan).
    pub fn search(&self, query: &str, opts: &SearchOptions) -> Result<Vec<SearchHit>, StoreError> {
        let limit = if opts.limit == 0 { 10 } else { opts.limit };
        let qvec = self.embedder.embed(query);
        let qterms: Vec<String> = query
            .to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() > 1)
            .map(str::to_string)
            .collect();

        let candidates = match self.fts_min {
            Some(min) if self.fts && !qterms.is_empty() && self.count()? >= min as u64 => {
                self.fts_candidates(&qterms, std::cmp::max(256, limit * 32))
            }
            _ => None,
        };

        let mut sql = String::from("SELECT id, meta_json, content, embedding, tag FROM drawers");
        let mut clauses: Vec<String> = Vec::new();
        let mut binds: Vec<String> = Vec::new();
        if let Some(seqs) = &candidates {
            let list: Vec<String> = seqs.iter().map(i64::to_string).collect();
            clauses.push(format!("seq IN ({})", list.join(",")));
        }
        if let Some(w) = &opts.wing {
            binds.push(w.clone());
            clauses.push(format!("wing = ?{}", binds.len()));
        }
        if let Some(r) = &opts.room {
            binds.push(r.clone());
            clauses.push(format!("room = ?{}", binds.len()));
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: Vec<SearchRow> = stmt
            .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;

        // Pass 1: verify + decrypt every candidate, and gather the signals
        // that don't need corpus statistics (cosine, recency). Content
        // tokens are kept only when a BM25-based fusion needs them.
        let now = OffsetDateTime::now_utc();
        let mut cands: Vec<Candidate> = Vec::with_capacity(rows.len());
        for (id, meta_json, content_rest, emb_rest, tag) in rows {
            self.vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .map_err(|_| StoreError::Integrity(id.clone()))?;
            let drawer = self.decode(&id, &meta_json, &content_rest)?;
            let cached = self
                .emb_cache
                .borrow()
                .as_ref()
                .and_then(|c| c.get(&id).cloned());
            let emb = match cached {
                Some(e) => e,
                None => self
                    .vault
                    .embedding_from_rest(&id, &emb_rest)
                    .map_err(|e| StoreError::CorruptRow {
                        id: id.clone(),
                        reason: e.to_string(),
                    })?,
            };
            let semantic = ((cosine(&qvec, &emb) + 1.0) / 2.0).clamp(0.0, 1.0);
            let recency = recency_boost(&drawer.meta.filed_at, now);
            let tokens = if self.fusion == Fusion::Legacy {
                Vec::new()
            } else {
                tokenize(&drawer.content)
            };
            cands.push(Candidate {
                drawer,
                semantic,
                recency,
                tokens,
            });
        }

        // Pass 2: derive the lexical signal (per fusion mode) and combine.
        let mut hits = match self.fusion {
            Fusion::Legacy => cands
                .into_iter()
                .map(|c| {
                    let lexical = lexical_score(&qterms, query, &c.drawer.content);
                    let score = 0.55 * c.semantic + 0.35 * lexical + 0.10 * c.recency;
                    SearchHit {
                        drawer: c.drawer,
                        score,
                        semantic: c.semantic,
                        lexical,
                    }
                })
                .collect::<Vec<_>>(),
            Fusion::Bm25 => {
                let bm25 = bm25_scores(&qterms, &cands);
                cands
                    .into_iter()
                    .zip(bm25)
                    .map(|(c, lexical)| {
                        let score = 0.55 * c.semantic + 0.35 * lexical + 0.10 * c.recency;
                        SearchHit {
                            drawer: c.drawer,
                            score,
                            semantic: c.semantic,
                            lexical,
                        }
                    })
                    .collect::<Vec<_>>()
            }
            Fusion::Rrf => rrf_fuse(&qterms, cands),
        };

        // Relevance gate: an unrelated record still scores ~0.35 from the
        // neutral cosine midpoint + recency alone. Require actual evidence —
        // a lexical match or a clearly positive semantic signal.
        hits.retain(|h| h.lexical > 0.0 || h.semantic > 0.56);
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hits.truncate(limit);
        Ok(hits)
    }

    /// BM25 top-`k` candidate seqs from the FTS5 index. `None` means "no
    /// usable cut" — nothing matched, or the query produced no tokens —
    /// and the caller falls back to the full scan, which preserves
    /// semantic-only recall when the query shares no term with any drawer.
    fn fts_candidates(&self, qterms: &[String], k: usize) -> Option<Vec<i64>> {
        let mut parts: Vec<String> = Vec::with_capacity(qterms.len() * 2);
        for t in qterms {
            parts.push(format!("\"{t}\""));
            // The scorer tolerates one typo in terms of 5+ chars; a 4-char
            // prefix match keeps most such variants in the candidate pool.
            if t.chars().count() >= 5 {
                let prefix: String = t.chars().take(4).collect();
                parts.push(format!("\"{prefix}\"*"));
            }
        }
        if parts.is_empty() {
            return None;
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT rowid FROM drawers_fts WHERE drawers_fts MATCH ?1
                 ORDER BY rank LIMIT ?2",
            )
            .ok()?;
        let seqs: Vec<i64> = stmt
            .query_map(params![parts.join(" OR "), k as i64], |r| r.get(0))
            .ok()?
            .collect::<Result<_, _>>()
            .ok()?;
        if seqs.is_empty() {
            None
        } else {
            Some(seqs)
        }
    }

    /// Score one already-decrypted drawer against a query (used by the
    /// remote-index path, where the embedding is recomputed locally from
    /// the verified plaintext rather than trusted from the server).
    pub(crate) fn score_drawer(
        &self,
        drawer: undercroft_core::Drawer,
        query: &str,
        qvec: &[f32],
    ) -> SearchHit {
        let qterms: Vec<String> = query
            .to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() > 1)
            .map(str::to_string)
            .collect();
        let emb = self.embedder.embed(&drawer.content);
        let semantic = ((cosine(qvec, &emb) + 1.0) / 2.0).clamp(0.0, 1.0);
        let lexical = lexical_score(&qterms, query, &drawer.content);
        let recency = recency_boost(&drawer.meta.filed_at, OffsetDateTime::now_utc());
        let score = 0.55 * semantic + 0.35 * lexical + 0.10 * recency;
        SearchHit {
            drawer,
            score,
            semantic,
            lexical,
        }
    }

    /// Walk every record verifying its HMAC, then replay the audit chain
    /// against the manifest head.
    pub fn verify(&self) -> Result<VerifyReport, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, meta_json, content, tag FROM drawers ORDER BY seq")?;
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        let mut bad = Vec::new();
        let mut checked = 0u64;
        for (id, meta_json, content_rest, tag) in rows {
            checked += 1;
            if self
                .vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .is_err()
            {
                bad.push(id);
            }
        }
        // Knowledge-graph and tunnel rows are integrity-tagged too.
        checked += self.kg_count()?;
        bad.extend(self.kg_verify()?);
        checked += self.tunnel_count()?;
        bad.extend(self.tunnels_verify()?);
        let mut stmt = self.conn.prepare("SELECT tag FROM audit ORDER BY seq")?;
        let tags: Vec<Vec<u8>> = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<Result<_, _>>()?;
        let chain_ok = self.vault.verify_chain(&tags);
        Ok(VerifyReport {
            records_checked: checked,
            bad_records: bad,
            chain_ok,
        })
    }

    /// Decrypted export of every drawer (for backup / migration).
    pub fn export_all(&self) -> Result<Vec<Drawer>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, meta_json, content, tag FROM drawers ORDER BY seq")?;
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, meta_json, content_rest, tag) in rows {
            self.vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .map_err(|_| StoreError::Integrity(id.clone()))?;
            out.push(self.decode(&id, &meta_json, &content_rest)?);
        }
        Ok(out)
    }

    /// Distinct wings and per-wing drawer counts.
    pub fn wings(&self) -> Result<Vec<(String, u64)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT wing, COUNT(*) FROM drawers GROUP BY wing ORDER BY wing")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }
}

/// One verified, decrypted candidate carried between search's two passes:
/// the signals computable per-document up front (cosine, recency) plus the
/// content tokens BM25 needs once corpus statistics are known. `tokens` is
/// left empty under `Fusion::Legacy`, which never inspects them.
struct Candidate {
    drawer: Drawer,
    semantic: f32,
    recency: f32,
    tokens: Vec<String>,
}

/// Lowercase alphanumeric tokens of length > 1 — the same tokenization the
/// query goes through, so BM25 term matching is symmetric with the query.
fn tokenize(content: &str) -> Vec<String> {
    content
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 1)
        .map(str::to_string)
        .collect()
}

/// Raw Okapi BM25 per candidate over the candidate set as the corpus, plus
/// `k_sat` — the mean IDF of query terms that actually occur, used as the
/// saturation constant when squashing raw scores into [0,1]. Term matching
/// carries the same one-typo tolerance (5+ char terms) as lexical search,
/// so a misspelled query still contributes.
fn bm25_raw(qterms: &[String], cands: &[Candidate]) -> (Vec<f32>, f32) {
    let n = cands.len();
    if n == 0 || qterms.is_empty() {
        return (vec![0.0; n], 0.0);
    }
    // tf[doc][term] = occurrences of qterms[term] in the doc's tokens.
    let mut tf = vec![vec![0u32; qterms.len()]; n];
    let mut lengths = vec![0f32; n];
    for (i, c) in cands.iter().enumerate() {
        lengths[i] = c.tokens.len() as f32;
        for tok in &c.tokens {
            for (j, q) in qterms.iter().enumerate() {
                if tok == q || (q.len() >= 5 && within_one_edit(q, tok)) {
                    tf[i][j] += 1;
                    break; // a token fills at most one query-term slot
                }
            }
        }
    }
    let avgdl = (lengths.iter().sum::<f32>() / n as f32).max(1.0);
    let mut idf = vec![0f32; qterms.len()];
    let mut present_idf_sum = 0f32;
    let mut present_cnt = 0f32;
    for (j, idf_j) in idf.iter_mut().enumerate() {
        let df = tf.iter().filter(|row| row[j] > 0).count() as f32;
        // Okapi probabilistic IDF, +1 inside the log to stay non-negative.
        *idf_j = (1.0 + (n as f32 - df + 0.5) / (df + 0.5)).ln();
        if df > 0.0 {
            present_idf_sum += *idf_j;
            present_cnt += 1.0;
        }
    }
    let k_sat = if present_cnt > 0.0 {
        present_idf_sum / present_cnt
    } else {
        0.0
    };
    let mut raw = vec![0f32; n];
    for (i, raw_i) in raw.iter_mut().enumerate() {
        let len_norm = 1.0 - BM25_B + BM25_B * lengths[i] / avgdl;
        let mut s = 0f32;
        for (j, idf_j) in idf.iter().enumerate() {
            let f = tf[i][j] as f32;
            if f > 0.0 {
                s += idf_j * (f * (BM25_K1 + 1.0)) / (f + BM25_K1 * len_norm);
            }
        }
        *raw_i = s;
    }
    (raw, k_sat)
}

/// BM25 squashed into [0,1] for the linear blend: `raw / (raw + k_sat)`,
/// so one strong term match sits near 0.5 and additional evidence climbs
/// toward 1 without ever forcing a top candidate to exactly 1.0.
fn bm25_scores(qterms: &[String], cands: &[Candidate]) -> Vec<f32> {
    let (raw, k_sat) = bm25_raw(qterms, cands);
    if k_sat <= 0.0 {
        return vec![0.0; cands.len()];
    }
    raw.iter()
        .map(|&r| if r > 0.0 { r / (r + k_sat) } else { 0.0 })
        .collect()
}

/// 1-based ranks by descending value, ties broken by original index.
fn ranks_desc(vals: &[f32]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..vals.len()).collect();
    idx.sort_by(|&a, &b| {
        vals[b]
            .partial_cmp(&vals[a])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.cmp(&b))
    });
    let mut rank = vec![0usize; vals.len()];
    for (r, &i) in idx.iter().enumerate() {
        rank[i] = r + 1;
    }
    rank
}

/// Like [`ranks_desc`] but only entries with a positive value are ranked;
/// the rest get `None` so they contribute nothing to the RRF sum (a zero
/// BM25 must not earn rank credit just for existing).
fn ranks_desc_positive(vals: &[f32]) -> Vec<Option<usize>> {
    let mut idx: Vec<usize> = (0..vals.len()).filter(|&i| vals[i] > 0.0).collect();
    idx.sort_by(|&a, &b| {
        vals[b]
            .partial_cmp(&vals[a])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.cmp(&b))
    });
    let mut rank = vec![None; vals.len()];
    for (r, &i) in idx.iter().enumerate() {
        rank[i] = Some(r + 1);
    }
    rank
}

/// Reciprocal-rank fusion of the cosine ranking and the BM25 ranking, with
/// recency as a lightly-weighted third ranker (0.10, matching the linear
/// blend's recency weight). Scale-free: no semantic/lexical weight to tune,
/// only rank positions. `lexical` is reported as the squashed BM25 so the
/// caller's relevance gate treats it exactly like the BM25 blend.
fn rrf_fuse(qterms: &[String], cands: Vec<Candidate>) -> Vec<SearchHit> {
    let (raw, k_sat) = bm25_raw(qterms, &cands);
    let sem: Vec<f32> = cands.iter().map(|c| c.semantic).collect();
    let rec: Vec<f32> = cands.iter().map(|c| c.recency).collect();
    let sem_rank = ranks_desc(&sem);
    let rec_rank = ranks_desc(&rec);
    let bm_rank = ranks_desc_positive(&raw);
    cands
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            let mut score = 1.0 / (RRF_K + sem_rank[i] as f32);
            if let Some(r) = bm_rank[i] {
                score += 1.0 / (RRF_K + r as f32);
            }
            score += 0.10 * (1.0 / (RRF_K + rec_rank[i] as f32));
            let lexical = if k_sat > 0.0 && raw[i] > 0.0 {
                raw[i] / (raw[i] + k_sat)
            } else {
                0.0
            };
            SearchHit {
                drawer: c.drawer,
                score,
                semantic: c.semantic,
                lexical,
            }
        })
        .collect()
}

/// Fraction of query terms present in the content, with a phrase bonus.
/// Terms of 5+ chars also match with one typo (edit distance 1) — the
/// port of mempalace's spellcheck extra, done at query time instead of
/// with a dictionary.
fn lexical_score(qterms: &[String], raw_query: &str, content: &str) -> f32 {
    if qterms.is_empty() {
        return 0.0;
    }
    let lower = content.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let matched = qterms
        .iter()
        .filter(|t| {
            lower.contains(t.as_str())
                || (t.len() >= 5 && words.iter().any(|w| within_one_edit(t, w)))
        })
        .count() as f32;
    let mut score = matched / qterms.len() as f32;
    let phrase = raw_query.trim().to_lowercase();
    if phrase.len() > 3 && lower.contains(&phrase) {
        score = (score + 0.5).min(1.0);
    }
    score
}

/// True when `a` and `b` are within Levenshtein distance 1 (single
/// substitution, insertion, or deletion). O(len) — no DP table.
fn within_one_edit(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (la, lb) = (a.len(), b.len());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    let (short, long) = if la <= lb { (&a, &b) } else { (&b, &a) };
    let mut i = 0;
    let mut j = 0;
    let mut edits = 0;
    while i < short.len() && j < long.len() {
        if short[i] == long[j] {
            i += 1;
            j += 1;
            continue;
        }
        edits += 1;
        if edits > 1 {
            return false;
        }
        if short.len() == long.len() {
            i += 1; // substitution
        }
        j += 1; // skip in the longer (insertion/deletion)
    }
    edits + (long.len() - j) + (short.len() - i) <= 1
}

/// Exponential recency decay with a 30-day half-life.
fn recency_boost(filed_at: &str, now: OffsetDateTime) -> f32 {
    match OffsetDateTime::parse(filed_at, &Rfc3339) {
        Ok(t) => {
            let days = (now - t).whole_seconds().max(0) as f32 / 86_400.0;
            (0.5f32).powf(days / 30.0)
        }
        Err(_) => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use undercroft_vault::{SecurityLevel, VaultManager};
    use tempfile::TempDir;

    fn store(level: SecurityLevel) -> (TempDir, PalaceStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", level).unwrap();
        (dir, PalaceStore::open(vault).unwrap())
    }

    fn drawer(wing: &str, room: &str, content: &str, idx: u32) -> Drawer {
        Drawer::new(
            wing,
            room,
            content.into(),
            Some("test.md".into()),
            idx,
            "test",
        )
    }

    #[test]
    fn upsert_get_roundtrip_sealed() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let dr = drawer(
            "work",
            "decisions",
            "we chose graphql over rest for the api",
            0,
        );
        assert!(s.upsert(&dr).unwrap());
        let back = s.get(&dr.id).unwrap().unwrap();
        assert_eq!(back.content, dr.content);
        assert_eq!(back.meta.wing, "work");
        // Re-upsert same slot is an update, not a new record.
        assert!(!s.upsert(&dr).unwrap());
        assert_eq!(s.count().unwrap(), 1);
    }

    #[test]
    fn sealed_content_is_not_plaintext_on_disk() {
        let (dir, mut s) = store(SecurityLevel::Sealed);
        let secret = "the launch code is very-secret-phrase-42";
        s.upsert(&drawer("w", "r", secret, 0)).unwrap();
        drop(s);
        let db = std::fs::read(dir.path().join("vaults/test/palace.db")).unwrap();
        let needle = b"very-secret-phrase-42";
        assert!(
            !db.windows(needle.len()).any(|w| w == needle),
            "plaintext leaked into sealed vault database"
        );
    }

    #[test]
    fn hmac_only_content_is_plaintext_but_tagged() {
        let (dir, mut s) = store(SecurityLevel::HmacOnly);
        s.upsert(&drawer("w", "r", "findable plaintext content", 0))
            .unwrap();
        drop(s);
        let db = std::fs::read(dir.path().join("vaults/test/palace.db")).unwrap();
        assert!(db.windows(8).any(|w| w == b"findable"));
    }

    #[test]
    fn search_ranks_relevant_first() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer(
            "work",
            "api",
            "we switched to graphql because rest was chatty",
            0,
        ))
        .unwrap();
        s.upsert(&drawer("home", "pets", "the cat likes the windowsill", 1))
            .unwrap();
        s.upsert(&drawer(
            "work",
            "infra",
            "postgres migration completed friday",
            2,
        ))
        .unwrap();
        let hits = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(hits[0].drawer.meta.room, "api");
        assert!(hits[0].score > hits.last().unwrap().score);
    }

    #[test]
    fn search_scopes_to_wing() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("a", "r", "shared topic alpha content", 0))
            .unwrap();
        s.upsert(&drawer("b", "r", "shared topic alpha content", 1))
            .unwrap();
        let hits = s
            .search(
                "alpha",
                &SearchOptions {
                    wing: Some("a".into()),
                    room: None,
                    limit: 10,
                },
            )
            .unwrap();
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|h| h.drawer.meta.wing == "a"));
    }

    #[test]
    fn verify_clean_store_passes() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        for i in 0..5 {
            s.upsert(&drawer("w", "r", &format!("memory number {i}"), i))
                .unwrap();
        }
        let report = s.verify().unwrap();
        assert!(report.ok());
        assert_eq!(report.records_checked, 5);
    }

    #[test]
    fn verify_detects_row_tampering() {
        let (dir, mut s) = store(SecurityLevel::HmacOnly);
        let dr = drawer("w", "r", "original truthful memory", 0);
        s.upsert(&dr).unwrap();
        drop(s);
        // Tamper with the row directly, bypassing the store.
        let conn = Connection::open(dir.path().join("vaults/test/palace.db")).unwrap();
        conn.execute(
            "UPDATE drawers SET content = ?1 WHERE id = ?2",
            params![b"forged memory".as_slice(), dr.id],
        )
        .unwrap();
        drop(conn);
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let s = PalaceStore::open(mgr.unlock("test").unwrap()).unwrap();
        let report = s.verify().unwrap();
        assert!(!report.ok());
        assert_eq!(report.bad_records, vec![dr.id.clone()]);
        // Reads of the tampered record must refuse, not return forged data.
        assert!(matches!(s.get(&dr.id), Err(StoreError::Integrity(_))));
    }

    #[test]
    fn verify_detects_audit_chain_tampering() {
        let (dir, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "one", 0)).unwrap();
        s.upsert(&drawer("w", "r", "two", 1)).unwrap();
        drop(s);
        // Delete an audit row (hide a write).
        let conn = Connection::open(dir.path().join("vaults/test/palace.db")).unwrap();
        conn.execute("DELETE FROM audit WHERE seq = 1", []).unwrap();
        drop(conn);
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let s = PalaceStore::open(mgr.unlock("test").unwrap()).unwrap();
        assert!(!s.verify().unwrap().chain_ok);
    }

    #[test]
    fn embedding_cache_stays_coherent() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer(
            "w",
            "r",
            "the original cached memory about databases",
            0,
        ))
        .unwrap();
        assert_eq!(s.warm_embedding_cache().unwrap(), 1);
        // Search via cache finds it.
        let hits = s
            .search("cached memory databases", &SearchOptions::default())
            .unwrap();
        assert_eq!(hits.len(), 1);
        // New upsert while warm must be searchable (cache updated).
        s.upsert(&drawer(
            "w",
            "r",
            "a second note about kubernetes upgrades",
            1,
        ))
        .unwrap();
        let hits = s
            .search("kubernetes upgrades", &SearchOptions::default())
            .unwrap();
        assert!(hits.iter().any(|h| h.drawer.content.contains("kubernetes")));
        // Delete while warm removes it from results.
        let id = hits[0].drawer.id.clone();
        s.delete_drawer(&id).unwrap();
        let hits = s
            .search("kubernetes upgrades", &SearchOptions::default())
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn fuzzy_search_tolerates_one_typo() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer(
            "w",
            "r",
            "the kubernetes cluster upgrade finished",
            0,
        ))
        .unwrap();
        // "kubernets" (missing e) and "clutser" (transposed = 2 edits, won't
        // match) — the single-typo term still anchors the hit.
        let hits = s
            .search("kubernets upgrade", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty());
        assert!(hits[0].drawer.content.contains("kubernetes"));
    }

    #[test]
    fn within_one_edit_cases() {
        assert!(within_one_edit("kubernetes", "kubernets")); // deletion
        assert!(within_one_edit("color", "colour")); // insertion
        assert!(within_one_edit("grafana", "grafena")); // substitution
        assert!(!within_one_edit("cluster", "clutser")); // transposition = 2 edits
        assert!(!within_one_edit("abc", "xyz"));
    }

    #[test]
    fn closet_index_lines() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        for i in 0..3 {
            s.upsert(&drawer(
                "team",
                "standups",
                &format!("Update {i}: Alice shipped the Billing Portal migration"),
                i,
            ))
            .unwrap();
        }
        let lines = s.closet_index(Some("team")).unwrap();
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert!(line.starts_with("team/standups n=3"));
        assert!(line.contains("alice"));
        assert!(line.contains("ids="));
    }

    #[test]
    fn fts_index_exists_only_in_hmac_only_vaults() {
        let count_fts = |s: &PalaceStore| -> i64 {
            s.conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'drawers_fts%'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        s.upsert(&drawer("w", "r", "indexed plaintext", 0)).unwrap();
        assert!(s.fts);
        assert!(count_fts(&s) > 0);
        // Sealed vaults must not persist a plaintext-derived index.
        let (_d2, s2) = store(SecurityLevel::Sealed);
        assert!(!s2.fts);
        assert_eq!(count_fts(&s2), 0);
    }

    #[test]
    fn fts_prefilter_agrees_with_full_scan() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        for i in 0..30 {
            s.upsert(&drawer("w", "r", &format!("routine note number {i}"), i))
                .unwrap();
        }
        s.upsert(&drawer(
            "w",
            "api",
            "we switched to graphql because rest was chatty",
            100,
        ))
        .unwrap();
        s.set_fts_prefilter_min(None);
        let full = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        s.set_fts_prefilter_min(Some(0));
        let pre = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(pre[0].drawer.id, full[0].drawer.id);
        assert!(pre[0].drawer.content.contains("graphql"));
    }

    #[test]
    fn fts_stays_coherent_through_update_and_delete() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        // Assert against the index itself — the full-scan fallback in
        // search() would mask a stale index.
        let fts_matches = |s: &PalaceStore, term: &str| -> i64 {
            s.conn
                .query_row(
                    "SELECT COUNT(*) FROM drawers_fts WHERE drawers_fts MATCH ?1",
                    params![term],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let mut dr = drawer("w", "r", "the elephant walked to the river", 0);
        s.upsert(&dr).unwrap();
        assert_eq!(fts_matches(&s, "elephant"), 1);
        // Same id, new content: the old term must leave the index.
        dr.content = "the giraffe reached the savanna".into();
        s.upsert(&dr).unwrap();
        assert_eq!(fts_matches(&s, "elephant"), 0);
        assert_eq!(fts_matches(&s, "giraffe"), 1);
        s.delete_drawer(&dr.id).unwrap();
        assert_eq!(fts_matches(&s, "giraffe"), 0);
        // And the prefiltered search path agrees.
        s.set_fts_prefilter_min(Some(0));
        let hits = s
            .search("giraffe savanna", &SearchOptions::default())
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn fts_prefilter_keeps_one_typo_matches() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        s.set_fts_prefilter_min(Some(0));
        s.upsert(&drawer(
            "w",
            "r",
            "the kubernetes cluster upgrade finished",
            0,
        ))
        .unwrap();
        // "kubernets" shares the 4-char prefix, so the prefilter keeps the
        // row and the fuzzy scorer still anchors the hit.
        let hits = s
            .search("kubernets upgrade", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty());
        assert!(hits[0].drawer.content.contains("kubernetes"));
    }

    #[test]
    fn fts_backfills_missing_index_on_open() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::HmacOnly).unwrap();
        let mut s = PalaceStore::open(vault).unwrap();
        s.upsert(&drawer("w", "r", "memory written before the index", 0))
            .unwrap();
        drop(s);
        // Simulate a vault predating the feature (or a dropped index).
        let conn = Connection::open(dir.path().join("vaults/test/palace.db")).unwrap();
        conn.execute_batch(
            "DROP TRIGGER drawers_fts_ai; DROP TRIGGER drawers_fts_ad;
             DROP TRIGGER drawers_fts_au; DROP TABLE drawers_fts;",
        )
        .unwrap();
        drop(conn);
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let mut s = PalaceStore::open(mgr.unlock("test").unwrap()).unwrap();
        s.set_fts_prefilter_min(Some(0));
        let hits = s
            .search("memory written before", &SearchOptions::default())
            .unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn bm25_ranks_rare_term_over_common_term() {
        // A term that appears in almost every drawer (IDF≈0) should lose to
        // a rare, discriminating term — something the legacy term-overlap
        // fraction, which weights every matched term equally, cannot do.
        let (_d, mut s) = store(SecurityLevel::Sealed);
        for i in 0..12 {
            s.upsert(&drawer("w", "r", &format!("the system logged an event {i}"), i))
                .unwrap();
        }
        // One drawer additionally mentions a rare term.
        s.upsert(&drawer(
            "w",
            "r",
            "the system logged an event about xylophone calibration",
            99,
        ))
        .unwrap();
        s.set_fusion(Fusion::Bm25);
        let hits = s
            .search("system xylophone", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("xylophone"));
    }

    #[test]
    fn bm25_and_rrf_still_find_relevant_first() {
        // Both fusion modes must preserve the basic ranking contract.
        for mode in [Fusion::Bm25, Fusion::Rrf] {
            let (_d, mut s) = store(SecurityLevel::Sealed);
            s.upsert(&drawer(
                "work",
                "api",
                "we switched to graphql because rest was chatty",
                0,
            ))
            .unwrap();
            s.upsert(&drawer("home", "pets", "the cat likes the windowsill", 1))
                .unwrap();
            s.upsert(&drawer("work", "infra", "postgres migration completed friday", 2))
                .unwrap();
            s.set_fusion(mode);
            let hits = s
                .search("why did we switch to graphql", &SearchOptions::default())
                .unwrap();
            assert_eq!(hits[0].drawer.meta.room, "api", "mode {mode:?}");
        }
    }

    #[test]
    fn bm25_fusion_tolerates_one_typo() {
        // The typo tolerance carries into BM25 term matching.
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "the kubernetes cluster upgrade finished", 0))
            .unwrap();
        s.upsert(&drawer("w", "r", "unrelated note about the weather", 1))
            .unwrap();
        s.set_fusion(Fusion::Bm25);
        let hits = s
            .search("kubernets upgrade", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty());
        assert!(hits[0].drawer.content.contains("kubernetes"));
    }

    #[test]
    fn export_roundtrips_all_records() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "alpha", 0)).unwrap();
        s.upsert(&drawer("w", "r", "beta", 1)).unwrap();
        let all = s.export_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].content, "alpha");
    }
}
