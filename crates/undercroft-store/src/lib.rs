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

#[cfg(feature = "hnsw")]
mod hnsw;
pub mod kg;
mod latestage;
pub mod manage;
pub mod pq;
mod pqidx;
pub mod remote;

pub use kg::{KgStats, Triple};
pub use manage::{DedupReport, DrawerSummary, Hallway, PalaceStats, Tunnel};

use rusqlite::{params, Connection, OptionalExtension};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use undercroft_core::embed::{cosine, Embedder};
use undercroft_core::{Drawer, DrawerMeta, HashEmbedder, Reranker};
use undercroft_vault::{SecurityLevel, Vault, VaultError};

/// Drawer count at which the BM25 prefilter engages for hmac-only vaults.
/// Below this a full decrypt-free scan is cheap and keeps semantic-only
/// recall exact; above it the FTS5 candidate cut dominates search cost.
const DEFAULT_FTS_PREFILTER_MIN: usize = 2048;
/// Default number of fusion-ranked candidates a reranker re-scores per search
/// (override with `UNDERCROFT_RERANK_TOP_N`). One cross-encoder forward pass
/// runs per candidate, so this bounds the added latency.
const DEFAULT_RERANK_TOP_N: usize = 50;

/// One decrypted sealed-PQ cache row: `(seq, list, code)`.
pub(crate) type PqCacheRow = (i64, i64, Vec<u8>);

/// Append an audit entry **and** advance the committed chain head, inside
/// the caller's open transaction (a [`rusqlite::Transaction`] derefs to
/// `Connection`, so both work). Returns `(new_head_hex, writes)` for the
/// post-commit [`Vault::anchor_manifest`] call. Every mutation site pairs
/// its data statements with exactly one `chain_append` in one transaction —
/// the invariant that makes a crash unable to separate a record from its
/// chain entry.
pub(crate) fn chain_append(
    conn: &rusqlite::Connection,
    vault: &Vault,
    record_id: &str,
    tag: &[u8],
    at: &str,
) -> Result<(String, u64), StoreError> {
    conn.execute(
        "INSERT INTO audit (record_id, tag, at) VALUES (?1, ?2, ?3)",
        params![record_id, tag, at],
    )?;
    let head: String =
        conn.query_row("SELECT value FROM chain_meta WHERE key = 'head'", [], |r| {
            r.get(0)
        })?;
    let next = vault.chain_next_hex(&head, tag)?;
    let writes: u64 =
        conn.query_row(
            "SELECT value FROM chain_meta WHERE key = 'writes'",
            [],
            |r| r.get::<_, String>(0),
        )?
        .parse::<u64>()
        .map_err(|e| StoreError::CorruptRow {
            id: "chain_meta/writes".into(),
            reason: e.to_string(),
        })? + 1;
    conn.execute(
        "UPDATE chain_meta SET value = ?1 WHERE key = 'head'",
        params![next],
    )?;
    conn.execute(
        "UPDATE chain_meta SET value = ?1 WHERE key = 'writes'",
        params![writes.to_string()],
    )?;
    Ok((next, writes))
}

pub(crate) fn rerank_top_n() -> usize {
    std::env::var("UNDERCROFT_RERANK_TOP_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_RERANK_TOP_N)
}

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
    #[error("this vault uses external embeddings; writes must supply a vector")]
    ExternalVault,
    #[error("this vault computes its own embeddings; a vector may not be supplied")]
    NotExternalVault,
    #[error("embedding dimension mismatch: vault expects {expected}, got {got}")]
    EmbeddingDim { expected: usize, got: usize },
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

/// Result of [`PalaceStore::save_with_dedup`]: the drawer id that now holds
/// the content, whether it was a fresh insert, and whether an existing
/// near-duplicate was refreshed in place.
#[derive(Debug, Clone)]
pub struct SaveOutcome {
    pub id: String,
    pub created: bool,
    pub deduped: bool,
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
    /// Optional second-stage cross-encoder reranker. When present, the
    /// fusion-ranked top-N candidates are re-scored by `(query, content)`
    /// pairs before the final `limit` cut. `None` ⇒ first-pass ranking only.
    reranker: Option<Box<dyn Reranker + Send + Sync>>,
    /// Optional late-interaction (ColBERT) second stage: writes store
    /// per-token matrices, searches MaxSim-rescore the fusion top-N in one
    /// query forward. The cross-encoder wins when both are set. See
    /// `latestage`.
    late: Option<Box<dyn undercroft_core::late::LateInteraction + Send + Sync>>,
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
    /// `Some(dim)` when this vault's embeddings are supplied by the caller
    /// (embedder identity `external:<name>@<dim>`): writes must carry a
    /// vector of exactly `dim`, and the store never computes an embedding.
    external_dim: Option<usize>,
    /// When true, search uses the local in-memory HNSW ANN prefilter instead
    /// of the full cosine scan. Opt-in; requires the `hnsw` build feature.
    hnsw_enabled: bool,
    /// Lazily-built in-memory HNSW index (RAM only, never persisted). Dropped
    /// on any write and rebuilt on the next search.
    #[cfg(feature = "hnsw")]
    hnsw: std::cell::RefCell<Option<hnsw::HnswIndex>>,
    /// When true (hmac-only vaults only), search prefilters candidates via the
    /// on-disk PQ codes — bounded RAM at any corpus size. See `pqidx`.
    pq_enabled: bool,
    /// The cached PQ codebook (the on-disk copy in `pq_meta` is authoritative).
    pq: std::cell::RefCell<Option<pq::ProductQuantizer>>,
    /// The cached IVF coarse quantizer (on-disk copy in `pq_meta`, key `ivf`).
    ivf: std::cell::RefCell<Option<pq::CoarseQuantizer>>,
    /// Sealed vaults only: `(seq, list, code)` rows decrypted once per open
    /// (~52 B per drawer — bounded), scanned in RAM. See `pqidx`.
    pq_cache: std::cell::RefCell<Option<Vec<PqCacheRow>>>,
    /// Whether the PQ index passed its coherence check since the last event
    /// that could break it (open, or a write that failed to encode). While
    /// true, searches skip the O(corpus) verification entirely. See `pqidx`.
    pq_verified: std::cell::Cell<bool>,
    /// Live drawer count as of the last verification, maintained on writes —
    /// drives the IVF thresholds without per-search `COUNT(*)`.
    pq_live: std::cell::Cell<i64>,
    /// Corpus size at which the PQ prefilter partitions into IVF inverted
    /// lists (`usize::MAX` ⇒ never). See `pqidx`.
    ivf_min: usize,
    /// Inverted lists probed per query (`None` ⇒ `max(8, nlist/4)`).
    ivf_nprobe: Option<usize>,
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
        let external_dim = embedder
            .model_name()
            .starts_with("external:")
            .then(|| embedder.dimension());
        let mut store = Self {
            conn,
            vault,
            embedder,
            reranker: None,
            late: None,
            emb_cache: std::cell::RefCell::new(None),
            fts: false,
            fts_min,
            fusion: Fusion::from_env(),
            external_dim,
            hnsw_enabled: false,
            #[cfg(feature = "hnsw")]
            hnsw: std::cell::RefCell::new(None),
            pq_enabled: false,
            pq: std::cell::RefCell::new(None),
            ivf: std::cell::RefCell::new(None),
            pq_cache: std::cell::RefCell::new(None),
            pq_verified: std::cell::Cell::new(false),
            pq_live: std::cell::Cell::new(0),
            ivf_min: match std::env::var("UNDERCROFT_IVF_MIN") {
                Ok(v) if v.eq_ignore_ascii_case("off") => usize::MAX,
                Ok(v) => v.parse().unwrap_or(pqidx::IVF_MIN_DEFAULT),
                Err(_) => pqidx::IVF_MIN_DEFAULT,
            },
            ivf_nprobe: std::env::var("UNDERCROFT_IVF_NPROBE")
                .ok()
                .and_then(|v| v.parse().ok()),
        };
        store.fts = store.init_fts_schema()?;
        store.init_kg_schema()?;
        store.init_manage_schema()?;
        store.init_chain()?;
        Ok(store)
    }

    /// Initialize (or reconcile) the transactional chain head.
    ///
    /// The committed head lives in `chain_meta` and advances **inside the
    /// same SQLite transaction** as the data + audit row it covers, so a
    /// crash can never separate a record from its chain entry. The manifest
    /// keeps a MAC'd copy as an *out-of-database rollback anchor*, written
    /// after each commit — which means a crash between commit and anchor
    /// legitimately leaves the manifest **behind**. Reconciliation:
    ///
    /// * manifest head == database head → nothing to do;
    /// * manifest head appears in the chain the audit rows reproduce
    ///   (strictly behind) → crash artifact → fast-forward the anchor;
    /// * anything else → the database was rolled back or forked relative to
    ///   an anchor it never produced → `ManifestTampered`.
    ///
    /// A power loss is not a tamper alarm; a restored old database still is.
    fn init_chain(&mut self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chain_meta (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );",
        )?;
        let db_head: Option<String> = self
            .conn
            .query_row("SELECT value FROM chain_meta WHERE key = 'head'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let Some(db_head) = db_head else {
            // Legacy adoption (pre-chain_meta database) or a fresh vault:
            // seed from the manifest, which was authoritative until now.
            self.conn.execute(
                "INSERT INTO chain_meta (key, value) VALUES ('head', ?1), ('writes', ?2)",
                params![self.vault.chain_head_hex(), self.vault.writes().to_string()],
            )?;
            return Ok(());
        };
        let anchor = self.vault.chain_head_hex().to_string();
        if anchor == db_head {
            return Ok(());
        }
        // Heads differ: replay the audit rows and decide crash vs rollback.
        let mut stmt = self.conn.prepare("SELECT tag FROM audit ORDER BY seq")?;
        let tags: Vec<Vec<u8>> = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<Result<_, _>>()?;
        drop(stmt);
        let mut head = undercroft_vault::Vault::chain_genesis_hex();
        let mut anchor_seen = head == anchor;
        for tag in &tags {
            head = self.vault.chain_next_hex(&head, tag)?;
            if head == anchor {
                anchor_seen = true;
            }
        }
        if head != db_head {
            // The committed head doesn't match its own audit rows — this is
            // in-database corruption, not an anchoring artifact.
            return Err(StoreError::Integrity("audit-chain head".into()));
        }
        if !anchor_seen {
            return Err(StoreError::Vault(
                undercroft_vault::VaultError::ManifestTampered,
            ));
        }
        // Crash artifact: the anchor is a strict ancestor. Fast-forward it.
        let writes: u64 = self
            .conn
            .query_row(
                "SELECT value FROM chain_meta WHERE key = 'writes'",
                [],
                |r| r.get::<_, String>(0),
            )?
            .parse()
            .unwrap_or(tags.len() as u64);
        self.vault.anchor_manifest(&db_head, writes)?;
        Ok(())
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

    /// Attach (or clear) a second-stage cross-encoder reranker. With one set,
    /// `search` re-scores the fusion-ranked top-N candidates by the full
    /// `(query, content)` pair before the final `limit` cut. Idempotent and
    /// additive — leaving it unset preserves first-pass ranking exactly.
    pub fn set_reranker(&mut self, reranker: Option<Box<dyn Reranker + Send + Sync>>) {
        self.reranker = reranker;
    }

    /// Enable (or disable) the local in-memory HNSW ANN prefilter. When on,
    /// search cuts candidates to the vector top-K via an O(log n) graph walk
    /// instead of the O(n) full cosine scan. The index is built lazily on the
    /// first search, held in RAM only, and rebuilt after any write. Requires
    /// the `hnsw` build feature; a no-op flag otherwise (falls back to scan).
    pub fn set_hnsw(&mut self, on: bool) {
        self.hnsw_enabled = on;
    }

    /// Vector top-`k` candidate `seq`s via the HNSW index, building it lazily
    /// from the (decrypted) corpus on first use. `None` ⇒ empty corpus, so the
    /// caller falls back to a full scan (which also yields nothing).
    #[cfg(feature = "hnsw")]
    fn hnsw_candidates(&self, qvec: &[f32], k: usize) -> Result<Option<Vec<i64>>, StoreError> {
        if self.hnsw.borrow().is_none() {
            let mut stmt = self
                .conn
                .prepare("SELECT seq, id, embedding FROM drawers")?;
            let rows: Vec<(i64, String, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?;
            if rows.is_empty() {
                return Ok(None);
            }
            let mut items = Vec::with_capacity(rows.len());
            for (seq, id, emb_rest) in rows {
                let emb = self
                    .vault
                    .embedding_from_rest(&id, &emb_rest)
                    .map_err(|e| StoreError::CorruptRow {
                        id: id.clone(),
                        reason: e.to_string(),
                    })?;
                items.push((seq, emb));
            }
            *self.hnsw.borrow_mut() = Some(hnsw::HnswIndex::build(items));
        }
        Ok(Some(self.hnsw.borrow().as_ref().unwrap().query(qvec, k)))
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

    /// Whether this vault seals content at rest. Used to suppress wing/room
    /// names in live telemetry events for sealed vaults.
    fn is_sealed(&self) -> bool {
        matches!(self.vault.level(), SecurityLevel::Sealed)
    }

    pub fn count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM drawers", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// Whether this vault stores caller-supplied embeddings
    /// (`external:<name>@<dim>` identity). Such vaults reject
    /// [`upsert`](Self::upsert) — use [`upsert_external`](Self::upsert_external).
    pub fn is_external(&self) -> bool {
        self.external_dim.is_some()
    }

    /// Read a vault's recorded embedder identity `(name, dim)` without
    /// opening a full store — lets a caller (e.g. the multi-tenant server)
    /// pick the right embedder before opening. `None` if nothing is
    /// recorded yet (a fresh, never-written vault).
    pub fn recorded_embedder(vault: &Vault) -> Result<Option<(String, usize)>, StoreError> {
        let conn = Connection::open(vault.db_path())?;
        let name: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'embedder_name'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        let dim: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'embedder_dim'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        Ok(match (name, dim) {
            (Some(n), Some(d)) => Some((n, d.parse().unwrap_or(0))),
            _ => None,
        })
    }

    /// Insert or replace a drawer, computing its embedding with the vault's
    /// embedder. Returns `true` if the id was new. Refused on external
    /// vaults, which must supply a vector via
    /// [`upsert_external`](Self::upsert_external).
    pub fn upsert(&mut self, drawer: &Drawer) -> Result<bool, StoreError> {
        let _span = undercroft_obs::scope("save", self.vault.id());
        if self.external_dim.is_some() {
            return Err(StoreError::ExternalVault);
        }
        let embedding = self.embedder.embed(&drawer.content);
        let created = self.write_drawer(drawer, embedding)?;
        undercroft_obs::drawer_write(undercroft_obs::WriteOutcome::Created);
        undercroft_obs::event_drawer_saved(
            self.vault.id(),
            &drawer.meta.wing,
            &drawer.meta.room,
            false,
            self.is_sealed(),
        );
        Ok(created)
    }

    /// Insert or replace a drawer on an external-embedding vault using the
    /// caller-supplied `vector`, which must match the recorded dimension
    /// exactly. Returns `true` if the id was new. Errors on a non-external
    /// vault or a dimension mismatch.
    pub fn upsert_external(
        &mut self,
        drawer: &Drawer,
        vector: Vec<f32>,
    ) -> Result<bool, StoreError> {
        let _span = undercroft_obs::scope("save", self.vault.id());
        match self.external_dim {
            None => Err(StoreError::NotExternalVault),
            Some(dim) if vector.len() != dim => Err(StoreError::EmbeddingDim {
                expected: dim,
                got: vector.len(),
            }),
            Some(_) => {
                let created = self.write_drawer(drawer, vector)?;
                undercroft_obs::drawer_write(undercroft_obs::WriteOutcome::Created);
                undercroft_obs::event_drawer_saved(
                    self.vault.id(),
                    &drawer.meta.wing,
                    &drawer.meta.room,
                    false,
                    self.is_sealed(),
                );
                Ok(created)
            }
        }
    }

    /// Seal + tag + persist a drawer with an already-computed `embedding`,
    /// advancing the audit chain and keeping the warm cache coherent. The
    /// embedding source (local embedder or caller-supplied) is the caller's
    /// concern; the at-rest sealing and integrity handling are identical.
    fn write_drawer(&mut self, drawer: &Drawer, embedding: Vec<f32>) -> Result<bool, StoreError> {
        let meta_json =
            serde_json::to_string(&drawer.meta).map_err(|e| StoreError::CorruptRow {
                id: drawer.id.clone(),
                reason: e.to_string(),
            })?;
        let content_rest = self
            .vault
            .content_at_rest(&drawer.id, drawer.content.as_bytes());
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
        let (head, writes) = chain_append(&tx, &self.vault, &drawer.id, &tag, &now)?;
        tx.commit()?;
        self.vault.anchor_manifest(&head, writes)?;
        // Keep the on-disk PQ codes coherent (advisory; self-heals on search).
        self.pq_encode_row(&drawer.id, &embedding, existing.is_none());
        // Store the late-interaction token matrix (advisory; a drawer
        // without one keeps its fusion rank at rescore time).
        self.late_encode_row(&drawer.id, &drawer.content);
        if let Some(cache) = self.emb_cache.borrow_mut().as_mut() {
            cache.insert(drawer.id.clone(), embedding);
        }
        // The ANN index is now stale; drop it so the next search rebuilds.
        #[cfg(feature = "hnsw")]
        self.hnsw.borrow_mut().take();
        Ok(existing.is_none())
    }

    /// Save a drawer, collapsing near-duplicates. If some existing drawer
    /// in the SAME wing+room has embedding cosine `>= threshold` against the
    /// incoming one, that drawer is refreshed in place — its text, metadata,
    /// and recency updated while its id is kept — and the outcome reports
    /// `deduped`. Otherwise it is a normal insert/update. Makes re-ingesting
    /// an updated corpus idempotent: unchanged facts refresh instead of
    /// piling up as near-copies. The refresh is an ordinary audited update
    /// (re-tagged, chain advanced), never a silent overwrite. Refused on
    /// external vaults — use [`save_with_dedup_vec`](Self::save_with_dedup_vec).
    pub fn save_with_dedup(
        &mut self,
        drawer: &Drawer,
        threshold: f32,
    ) -> Result<SaveOutcome, StoreError> {
        if self.external_dim.is_some() {
            return Err(StoreError::ExternalVault);
        }
        let embedding = self.embedder.embed(&drawer.content);
        self.save_with_dedup_vec(drawer, embedding, threshold)
    }

    /// [`save_with_dedup`](Self::save_with_dedup) with a caller-supplied
    /// embedding — the external-vault path (dimension-checked there).
    pub fn save_with_dedup_vec(
        &mut self,
        drawer: &Drawer,
        embedding: Vec<f32>,
        threshold: f32,
    ) -> Result<SaveOutcome, StoreError> {
        let _span = undercroft_obs::scope("save", self.vault.id());
        if let Some(dim) = self.external_dim {
            if embedding.len() != dim {
                return Err(StoreError::EmbeddingDim {
                    expected: dim,
                    got: embedding.len(),
                });
            }
        }
        // Scan the same wing+room for the closest existing drawer. Scope
        // the statement so its borrow of `self.conn` is released before the
        // `&mut self` write below.
        let rows: Vec<(String, Vec<u8>)> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id, embedding FROM drawers WHERE wing = ?1 AND room = ?2")?;
            let rows = stmt
                .query_map(params![drawer.meta.wing, drawer.meta.room], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?
                .collect::<Result<_, _>>()?;
            rows
        };
        let mut best: Option<(String, f32)> = None;
        for (id, emb_rest) in rows {
            let emb = self
                .vault
                .embedding_from_rest(&id, &emb_rest)
                .map_err(|e| StoreError::CorruptRow {
                    id: id.clone(),
                    reason: e.to_string(),
                })?;
            let sim = cosine(&embedding, &emb);
            if sim >= threshold && best.as_ref().map(|(_, s)| sim > *s).unwrap_or(true) {
                best = Some((id, sim));
            }
        }

        if let Some((match_id, _)) = best {
            // Refresh the matched drawer in place: keep its id, take the
            // incoming content/metadata and a fresh recency.
            let refreshed = Drawer {
                id: match_id.clone(),
                content: drawer.content.clone(),
                meta: drawer.meta.clone(),
            };
            self.write_drawer(&refreshed, embedding)?;
            undercroft_obs::drawer_write(undercroft_obs::WriteOutcome::Deduped);
            undercroft_obs::event_drawer_saved(
                self.vault.id(),
                &drawer.meta.wing,
                &drawer.meta.room,
                true,
                self.is_sealed(),
            );
            Ok(SaveOutcome {
                id: match_id,
                created: false,
                deduped: true,
            })
        } else {
            let created = self.write_drawer(drawer, embedding)?;
            undercroft_obs::drawer_write(undercroft_obs::WriteOutcome::Created);
            undercroft_obs::event_drawer_saved(
                self.vault.id(),
                &drawer.meta.wing,
                &drawer.meta.room,
                false,
                self.is_sealed(),
            );
            Ok(SaveOutcome {
                id: drawer.id.clone(),
                created,
                deduped: false,
            })
        }
    }

    /// Decrypted export of every drawer together with its embedding vector,
    /// for lossless migration (verified import elsewhere, then drop the
    /// source). Ordered by insertion. Unlike [`export_all`](Self::export_all)
    /// this carries the vector so an external-embedding vault round-trips
    /// without a model.
    pub fn export_all_with_vectors(&self) -> Result<Vec<(Drawer, Vec<f32>)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, meta_json, content, embedding, tag FROM drawers ORDER BY seq")?;
        let rows: Vec<SearchRow> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, meta_json, content_rest, emb_rest, tag) in rows {
            self.vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .map_err(|_| {
                    undercroft_obs::hmac_verify_failed("drawer");
                    undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                    StoreError::Integrity(id.clone())
                })?;
            let drawer = self.decode(&id, &meta_json, &content_rest)?;
            let emb = self
                .vault
                .embedding_from_rest(&id, &emb_rest)
                .map_err(|e| StoreError::CorruptRow {
                    id: id.clone(),
                    reason: e.to_string(),
                })?;
            out.push((drawer, emb));
        }
        Ok(out)
    }

    /// Import one drawer, the inverse of a migration export. On an external
    /// vault a `vector` is required (dimension-checked). On a normal vault a
    /// matching-dimension `vector` is preserved verbatim; otherwise the
    /// drawer is re-embedded with the vault's own embedder. Returns whether
    /// the id was new.
    pub fn import_record(
        &mut self,
        drawer: &Drawer,
        vector: Option<Vec<f32>>,
    ) -> Result<bool, StoreError> {
        match self.external_dim {
            Some(dim) => {
                let v = vector.ok_or(StoreError::ExternalVault)?;
                if v.len() != dim {
                    return Err(StoreError::EmbeddingDim {
                        expected: dim,
                        got: v.len(),
                    });
                }
                self.write_drawer(drawer, v)
            }
            None => match vector {
                Some(v) if v.len() == self.embedder.dimension() => self.write_drawer(drawer, v),
                _ => self.upsert(drawer),
            },
        }
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
                    .map_err(|_| {
                        undercroft_obs::hmac_verify_failed("drawer");
                        undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                        StoreError::Integrity(id.clone())
                    })?;
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
                .map_err(|_| {
                    undercroft_obs::hmac_verify_failed("drawer");
                    undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                    StoreError::Integrity(id.clone())
                })?;
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
        if self.external_dim.is_some() {
            return Err(StoreError::ExternalVault);
        }
        let qvec = self.embedder.embed(query);
        self.search_inner(query, qvec, opts)
    }

    /// Search an external-embedding vault with a caller-supplied query
    /// vector (same embedding space as the stored drawers); `query` still
    /// drives the lexical/BM25 half. The vector must match the recorded
    /// dimension. Errors on a non-external vault or a dimension mismatch.
    pub fn search_with_vector(
        &self,
        query: &str,
        qvec: Vec<f32>,
        opts: &SearchOptions,
    ) -> Result<Vec<SearchHit>, StoreError> {
        match self.external_dim {
            None => Err(StoreError::NotExternalVault),
            Some(dim) if qvec.len() != dim => Err(StoreError::EmbeddingDim {
                expected: dim,
                got: qvec.len(),
            }),
            Some(_) => self.search_inner(query, qvec, opts),
        }
    }

    fn search_inner(
        &self,
        query: &str,
        qvec: Vec<f32>,
        opts: &SearchOptions,
    ) -> Result<Vec<SearchHit>, StoreError> {
        let _span = undercroft_obs::scope("search", self.vault.id());
        let obs_start = std::time::Instant::now();
        let limit = if opts.limit == 0 { 10 } else { opts.limit };
        let qterms: Vec<String> = query
            .to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() > 1)
            .map(str::to_string)
            .collect();

        let candidates = if self.pq_enabled {
            // On-disk PQ prefilter (hmac-only): stream ADC over the code rows,
            // bounded RAM at any corpus size. Over-fetch generously so BM25
            // fusion still has material.
            self.pq_candidates(&qvec, std::cmp::max(256, limit * 32))?
        } else if self.hnsw_enabled {
            // Semantic ANN prefilter: cut to the vector top-K before verify +
            // fusion. Over-fetch generously so BM25 fusion still has material.
            #[cfg(feature = "hnsw")]
            {
                self.hnsw_candidates(&qvec, std::cmp::max(256, limit * 32))?
            }
            #[cfg(not(feature = "hnsw"))]
            {
                None
            }
        } else {
            match self.fts_min {
                Some(min) if self.fts && !qterms.is_empty() && self.count()? >= min as u64 => {
                    self.fts_candidates(&qterms, std::cmp::max(256, limit * 32))
                }
                _ => None,
            }
        };
        let obs_prefiltered = candidates.is_some();

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
                .map_err(|_| {
                    undercroft_obs::hmac_verify_failed("drawer");
                    undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                    StoreError::Integrity(id.clone())
                })?;
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

        // Optional second stage: a cross-encoder re-scores the top-N
        // fusion-ranked candidates using the full (query, content) pair — the
        // interaction a bi-encoder can't capture — then we re-sort. `score` is
        // overwritten with the reranker score; `semantic`/`lexical` are kept
        // for transparency. Bounded to `rerank_top_n()` forward passes.
        if let Some(reranker) = &self.reranker {
            // Rerank only the top `top_n` fusion candidates — a true latency
            // cap, since each candidate costs one cross-encoder forward pass.
            // Candidates below `top_n` keep their fusion rank, so a small
            // `top_n` never drops results, it only leaves the tail unreranked.
            // `score_batch` is the whole-pool interface: each backend
            // parallelizes it as it best can (the tract backend fans the
            // independent passes across cores with rayon; an ORT backend runs
            // one batched forward). 16.6s → ~0.7s measured with tract on 24
            // cores at top_n=20.
            let pool = hits.len().min(rerank_top_n());
            let passages: Vec<&str> = hits[..pool]
                .iter()
                .map(|h| h.drawer.content.as_str())
                .collect();
            let scores = reranker.score_batch(query, &passages);
            for (h, s) in hits[..pool].iter_mut().zip(scores) {
                h.score = s;
            }
            hits[..pool].sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        } else {
            // Late-interaction alternative: MaxSim over ingest-time token
            // matrices, one query-encode forward total (no-op when unset).
            self.late_rescore(query, &mut hits);
        }
        hits.truncate(limit);

        let fusion_label = match self.fusion {
            Fusion::Legacy => "legacy",
            Fusion::Bm25 => "bm25",
            Fusion::Rrf => "rrf",
        };
        undercroft_obs::search_completed(
            obs_start.elapsed(),
            hits.len(),
            fusion_label,
            obs_prefiltered,
        );
        undercroft_obs::event_search(
            self.vault.id(),
            opts.wing.as_deref(),
            opts.room.as_deref(),
            hits.len(),
            self.is_sealed(),
        );
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
        drop(stmt);
        // Two-part chain check. (1) The audit rows must reproduce exactly
        // the committed head in chain_meta — they advanced in the same
        // transactions, so any mismatch is corruption, not timing. (2) The
        // manifest anchor must appear somewhere in that chain: equal in
        // steady state, strictly behind after a crash-before-anchor (legal),
        // and absent only when the database was rolled back or forked
        // relative to an anchor it never produced.
        let anchor = self.vault.chain_head_hex().to_string();
        let mut head = Vault::chain_genesis_hex();
        let mut anchor_seen = head == anchor;
        for tag in &tags {
            head = self.vault.chain_next_hex(&head, tag)?;
            if head == anchor {
                anchor_seen = true;
            }
        }
        let db_head: Option<String> = self
            .conn
            .query_row("SELECT value FROM chain_meta WHERE key = 'head'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let chain_ok = db_head.as_deref() == Some(head.as_str()) && anchor_seen;
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
                .map_err(|_| {
                    undercroft_obs::hmac_verify_failed("drawer");
                    undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                    StoreError::Integrity(id.clone())
                })?;
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

    fn external_store(level: SecurityLevel, dim: usize) -> (TempDir, PalaceStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", level).unwrap();
        let emb = Box::new(undercroft_core::ExternalEmbedder::new("acme-embed", dim));
        (dir, PalaceStore::open_with_embedder(vault, emb).unwrap())
    }

    /// A deterministic reranker that scores purely by passage length — used to
    /// prove the rerank pass actually re-orders results independently of the
    /// first-pass fusion score.
    struct LenReranker;
    impl Reranker for LenReranker {
        fn model_name(&self) -> &str {
            "len-mock"
        }
        fn score(&self, _query: &str, passage: &str) -> f32 {
            passage.chars().count() as f32
        }
    }

    /// A deterministic late-interaction encoder: one "token" per word,
    /// each a unit one-hot picked by a word hash. MaxSim then counts
    /// (normalized) query-word coverage — enough to prove ordering flows
    /// from the stored matrices.
    struct WordLate;
    impl undercroft_core::late::LateInteraction for WordLate {
        fn model_name(&self) -> &str {
            "word-mock"
        }
        fn dim(&self) -> usize {
            16
        }
        fn encode_doc(&self, text: &str) -> Vec<f32> {
            let mut m = Vec::new();
            for w in text.split_whitespace() {
                let mut row = vec![0f32; 16];
                let h = w.bytes().fold(0usize, |a, b| (a * 31 + b as usize) % 16);
                row[h] = 1.0;
                m.extend(row);
            }
            m
        }
        fn encode_query(&self, text: &str) -> Vec<f32> {
            self.encode_doc(text)
        }
    }

    #[test]
    fn late_interaction_rescore_orders_by_stored_matrices() {
        for level in [SecurityLevel::HmacOnly, SecurityLevel::Sealed] {
            let (_d, mut s) = store(level);
            s.set_late(Some(Box::new(WordLate)));
            // Both mention the query word once; the second covers more of
            // the query's words, so MaxSim must rank it first even though
            // both fuse similarly.
            s.upsert(&drawer("w", "r", "kafka pipeline notes", 0))
                .unwrap();
            s.upsert(&drawer("w", "r", "kafka stream backlog rework", 1))
                .unwrap();
            let hits = s
                .search(
                    "kafka stream backlog",
                    &SearchOptions {
                        wing: None,
                        room: None,
                        limit: 2,
                    },
                )
                .unwrap();
            assert_eq!(hits.len(), 2);
            assert!(
                hits[0].drawer.content.contains("backlog"),
                "MaxSim coverage must lead at level {level:?}: got {:?}",
                hits[0].drawer.content
            );

            // The token store exists and, on sealed vaults, never holds the
            // plaintext-derived matrix in clear: our mock rows are one-hot
            // (byte 0x7F after int8 quantization at scale 1/127 appears
            // per word) — a sealed blob must not equal the plain packing.
            let (blob, plain): (Vec<u8>, Vec<u8>) = {
                let b: Vec<u8> = s
                    .conn
                    .query_row(
                        "SELECT tok FROM drawer_tok WHERE id = (SELECT id FROM drawers LIMIT 1)",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                let m = undercroft_core::late::LateInteraction::encode_doc(
                    &WordLate,
                    "kafka pipeline notes",
                );
                (b, undercroft_core::late::quantize_tokens(&m, 16))
            };
            match level {
                SecurityLevel::HmacOnly => assert_eq!(blob, plain),
                SecurityLevel::Sealed => assert_ne!(
                    blob, plain,
                    "sealed vault must not store plaintext-derived tokens in clear"
                ),
            }

            // Deleting purges the token row.
            let id = hits[0].drawer.id.clone();
            s.delete_drawer(&id).unwrap();
            let left: i64 = s
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM drawer_tok WHERE id = ?1",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(left, 0, "delete must purge the token matrix");
        }
    }

    /// A LateInteraction encoder that panics on doc encodes — proves a
    /// restore path never re-runs the expensive per-drawer forward.
    struct QueryOnlyLate;
    impl undercroft_core::late::LateInteraction for QueryOnlyLate {
        fn model_name(&self) -> &str {
            "word-mock" // must match WordLate so imported artifacts are used
        }
        fn dim(&self) -> usize {
            16
        }
        fn encode_doc(&self, _text: &str) -> Vec<f32> {
            panic!("restore must not re-encode documents");
        }
        fn encode_query(&self, text: &str) -> Vec<f32> {
            WordLate.encode_doc(text)
        }
    }

    #[test]
    fn token_artifacts_round_trip_without_reencoding() {
        // Source vault: sealed, encoder attached, matrices stored at write.
        let (_d1, mut src) = store(SecurityLevel::Sealed);
        src.set_late(Some(Box::new(WordLate)));
        src.upsert(&drawer("w", "r", "kafka pipeline notes", 0))
            .unwrap();
        src.upsert(&drawer("w", "r", "kafka stream backlog rework", 1))
            .unwrap();

        // Export drawers + vectors + artifacts (artifacts come out as
        // plaintext packing regardless of the source's sealing).
        let records = src.export_all_with_vectors().unwrap();
        let artifacts: Vec<Option<(String, Vec<u8>)>> = records
            .iter()
            .map(|(d, _)| src.token_artifact(&d.id).unwrap())
            .collect();
        assert!(artifacts.iter().all(Option::is_some));

        // Destination vault (also sealed, different keys): import WITHOUT
        // any encoder — then attach a query-only encoder that panics on any
        // doc encode. Rescoring must work purely from imported artifacts.
        let (_d2, mut dst) = store(SecurityLevel::Sealed);
        for ((d, v), tok) in records.iter().zip(&artifacts) {
            dst.import_record(d, Some(v.clone())).unwrap();
            let (model, packed) = tok.as_ref().unwrap();
            dst.import_token_artifact(&d.id, model, packed).unwrap();
        }
        dst.set_late(Some(Box::new(QueryOnlyLate)));
        let hits = dst
            .search("kafka stream backlog", &SearchOptions::default())
            .unwrap();
        assert!(
            hits[0].drawer.content.contains("backlog"),
            "imported matrices must drive MaxSim order: {:?}",
            hits[0].drawer.content
        );

        // The destination's at-rest blob must be re-sealed under ITS key —
        // not the source's bytes, not plaintext.
        let (src_blob, dst_blob): (Vec<u8>, Vec<u8>) = {
            let get = |s: &PalaceStore, id: &str| -> Vec<u8> {
                s.conn
                    .query_row(
                        "SELECT tok FROM drawer_tok WHERE id = ?1",
                        params![id],
                        |r| r.get(0),
                    )
                    .unwrap()
            };
            let id = &records[0].0.id;
            (get(&src, id), get(&dst, id))
        };
        let plain = &artifacts[0].as_ref().unwrap().1;
        assert_ne!(
            &dst_blob, plain,
            "sealed destination must not store plaintext"
        );
        assert_ne!(dst_blob, src_blob, "artifact must be re-sealed, not copied");

        // Garbage artifacts are rejected up front.
        assert!(dst
            .import_token_artifact("some-id", "word-mock", &[9, 9, 9])
            .is_err());
    }

    #[test]
    fn late_rescore_leaves_unencoded_rows_at_fusion_rank() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        // Written BEFORE the encoder is attached — no stored matrix.
        s.upsert(&drawer("w", "r", "kafka stream backlog rework", 0))
            .unwrap();
        s.set_late(Some(Box::new(WordLate)));
        let hits = s
            .search("kafka stream backlog", &SearchOptions::default())
            .unwrap();
        // The drawer is still found with its fusion score intact (not sunk).
        assert!(!hits.is_empty());
        assert!(hits[0].score > 0.0);
    }

    #[test]
    fn late_backfill_encodes_missing_matrices_in_bounded_passes() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        // Three drawers ingested with no encoder → zero matrices.
        for (i, text) in ["alpha fact", "beta fact", "gamma fact"].iter().enumerate() {
            s.upsert(&drawer("w", "r", text, i as u32)).unwrap();
        }
        // Without an encoder, backfill refuses clearly.
        assert!(s.late_backfill(10).is_err());

        s.set_late(Some(Box::new(WordLate)));
        let (encoded, remaining) = s.late_backfill(2).unwrap();
        assert_eq!((encoded, remaining), (2, 1), "bounded pass");
        let (encoded, remaining) = s.late_backfill(2).unwrap();
        assert_eq!((encoded, remaining), (1, 0), "second pass completes");
        let (encoded, remaining) = s.late_backfill(2).unwrap();
        assert_eq!((encoded, remaining), (0, 0), "idempotent when covered");

        let rows: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_tok", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 3, "every drawer carries a matrix after backfill");
    }

    #[test]
    fn reranker_reorders_top_k() {
        let (_d, mut store) = store(SecurityLevel::HmacOnly);
        // Three candidates that all match the query term, of increasing length.
        store.upsert(&drawer("w", "r", "graphql", 0)).unwrap();
        store
            .upsert(&drawer("w", "r", "graphql over rest for the mobile api", 1))
            .unwrap();
        store
            .upsert(&drawer(
                "w",
                "r",
                "graphql was chosen because the mobile app needed far fewer round \
                 trips and one flexible endpoint instead of many rest calls",
                2,
            ))
            .unwrap();
        let opts = SearchOptions {
            wing: None,
            room: None,
            limit: 3,
        };

        // Baseline (no reranker) returns all three, fusion-ordered.
        let base = store.search("graphql", &opts).unwrap();
        assert_eq!(base.len(), 3);

        // With the length reranker attached, the longest passage must be first
        // — proving the rerank score drives the final order.
        store.set_reranker(Some(Box::new(LenReranker)));
        let reranked = store.search("graphql", &opts).unwrap();
        let longest = reranked
            .iter()
            .max_by_key(|h| h.drawer.content.chars().count())
            .unwrap()
            .drawer
            .content
            .clone();
        assert_eq!(
            reranked[0].drawer.content, longest,
            "reranker should rank the longest passage first"
        );

        // Clearing the reranker restores first-pass behaviour.
        store.set_reranker(None);
        let after = store.search("graphql", &opts).unwrap();
        assert_eq!(after[0].drawer.content, base[0].drawer.content);
    }

    #[test]
    fn external_vault_enforces_vector_and_dimension() {
        let (_d, mut s) = external_store(SecurityLevel::Sealed, 4);
        assert!(s.is_external());
        let dr = drawer("w", "r", "customer prefers dark mode", 0);
        // Auto-embedding paths are refused.
        assert!(matches!(s.upsert(&dr), Err(StoreError::ExternalVault)));
        assert!(matches!(
            s.search("dark mode", &SearchOptions::default()),
            Err(StoreError::ExternalVault)
        ));
        // Wrong dimension is refused on write and on search.
        assert!(matches!(
            s.upsert_external(&dr, vec![0.1, 0.2]),
            Err(StoreError::EmbeddingDim {
                expected: 4,
                got: 2
            })
        ));
        // Correct dimension round-trips, and search uses the supplied vector.
        s.upsert_external(&dr, vec![1.0, 0.0, 0.0, 0.0]).unwrap();
        let hits = s
            .search_with_vector(
                "dark mode",
                vec![1.0, 0.0, 0.0, 0.0],
                &SearchOptions::default(),
            )
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].drawer.content, "customer prefers dark mode");
        assert!(matches!(
            s.search_with_vector("x", vec![1.0, 0.0], &SearchOptions::default()),
            Err(StoreError::EmbeddingDim {
                expected: 4,
                got: 2
            })
        ));
    }

    #[test]
    fn external_identity_recorded_and_reenforced() {
        let (dir, mut s) = external_store(SecurityLevel::Sealed, 8);
        s.upsert_external(&drawer("w", "r", "note", 0), vec![0.5; 8])
            .unwrap();
        drop(s);
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.unlock("test").unwrap();
        assert_eq!(
            PalaceStore::recorded_embedder(&vault).unwrap(),
            Some(("external:acme-embed".to_string(), 8))
        );
        // Opening the external vault with the plain hash embedder must be
        // refused — a silent embedder swap degrades recall.
        assert!(matches!(
            PalaceStore::open(mgr.unlock("test").unwrap()),
            Err(StoreError::EmbedderMismatch { .. })
        ));
    }

    #[test]
    fn external_vault_seals_supplied_vector() {
        let (dir, mut s) = external_store(SecurityLevel::Sealed, 3);
        s.upsert_external(
            &drawer("w", "r", "top-secret preference", 0),
            vec![0.11, 0.22, 0.33],
        )
        .unwrap();
        drop(s);
        let db = std::fs::read(dir.path().join("vaults/test/palace.db")).unwrap();
        assert!(
            !db.windows(9).any(|w| w == b"top-secre"),
            "external sealed vault leaked plaintext content"
        );
    }

    #[test]
    fn dedup_refresh_is_idempotent_and_audited() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let d1 = drawer("team", "facts", "the deploy target is us-east-1", 0);
        let o1 = s.save_with_dedup(&d1, 0.95).unwrap();
        assert!(o1.created && !o1.deduped);
        // Same corpus re-ingested with a fresh id: a near-duplicate refresh,
        // not a new record.
        let d2 = drawer("team", "facts", "the deploy target is us-east-1", 99);
        assert_ne!(d1.id, d2.id);
        let o2 = s.save_with_dedup(&d2, 0.95).unwrap();
        assert!(o2.deduped && !o2.created);
        assert_eq!(o2.id, d1.id, "refresh keeps the original id");
        assert_eq!(s.count().unwrap(), 1, "no near-duplicate piled up");
        // A genuinely different fact in the same room is not deduped.
        let o3 = s
            .save_with_dedup(
                &drawer("team", "facts", "the on-call rotation is weekly", 1),
                0.95,
            )
            .unwrap();
        assert!(o3.created && !o3.deduped);
        assert_eq!(s.count().unwrap(), 2);
        // The refresh was an audited update, so the chain still verifies.
        assert!(s.verify().unwrap().ok());
    }

    #[test]
    fn dedup_refresh_updates_text_in_place() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.save_with_dedup(&drawer("w", "r", "alice works at acme corporation", 0), 0.9)
            .unwrap();
        // Near-duplicate with updated wording refreshes the existing drawer.
        let o = s
            .save_with_dedup(
                &drawer("w", "r", "alice works at acme corporation now", 1),
                0.9,
            )
            .unwrap();
        assert!(o.deduped);
        let back = s.get(&o.id).unwrap().unwrap();
        assert_eq!(back.content, "alice works at acme corporation now");
    }

    #[test]
    fn crash_before_anchor_heals_without_alarm() {
        let (dir, mut s) = store(SecurityLevel::HmacOnly);
        s.upsert(&drawer("w", "r", "first fact", 0)).unwrap();
        let old_head = s.vault.chain_head_hex().to_string();
        s.upsert(&drawer("w", "r", "second fact", 1)).unwrap();
        s.upsert(&drawer("w", "r", "third fact", 2)).unwrap();

        // Simulate a crash between transaction commit and manifest anchor:
        // the database holds three chained writes, the manifest only saw
        // the first. A power loss must NOT read as tampering.
        s.vault.anchor_manifest(&old_head, 1).unwrap();
        assert!(
            s.verify().unwrap().chain_ok,
            "a behind-anchor (crash artifact) must not fail verification"
        );
        drop(s);

        // Reopen: reconciliation fast-forwards the anchor to the committed
        // head and the palace is fully healthy again.
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let s = PalaceStore::open(mgr.unlock("test").unwrap()).unwrap();
        assert_eq!(s.vault.writes(), 3, "anchor fast-forwarded");
        let db_head: String = s
            .conn
            .query_row("SELECT value FROM chain_meta WHERE key = 'head'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(s.vault.chain_head_hex(), db_head);
        assert!(s.verify().unwrap().chain_ok);
    }

    #[test]
    fn database_rollback_is_detected_at_open() {
        let (dir, mut s) = store(SecurityLevel::HmacOnly);
        s.upsert(&drawer("w", "r", "first fact", 0)).unwrap();
        s.upsert(&drawer("w", "r", "second fact", 1)).unwrap();
        let h2 = s.vault.chain_head_hex().to_string();
        s.upsert(&drawer("w", "r", "third fact", 2)).unwrap();
        drop(s);

        // Restore-an-old-database attack in miniature: erase the third
        // write from the db (data + audit + committed head) while the
        // manifest anchor still points at a head this database never
        // produces. Internally the rolled-back db is self-consistent — only
        // the out-of-database anchor exposes it.
        let db = rusqlite::Connection::open(dir.path().join("vaults/test/palace.db")).unwrap();
        db.execute(
            "DELETE FROM audit WHERE seq = (SELECT MAX(seq) FROM audit)",
            [],
        )
        .unwrap();
        db.execute(
            "DELETE FROM drawers WHERE seq = (SELECT MAX(seq) FROM drawers)",
            [],
        )
        .unwrap();
        db.execute(
            "UPDATE chain_meta SET value = ?1 WHERE key = 'head'",
            params![h2],
        )
        .unwrap();
        db.execute("UPDATE chain_meta SET value = '2' WHERE key = 'writes'", [])
            .unwrap();
        drop(db);

        let mgr = VaultManager::open(dir.path(), None).unwrap();
        match PalaceStore::open(mgr.unlock("test").unwrap()) {
            Err(StoreError::Vault(VaultError::ManifestTampered)) => {}
            Err(e) => panic!("rollback must map to ManifestTampered, got: {e}"),
            Ok(_) => panic!("rollback must be detected at open"),
        }
    }

    #[test]
    fn import_roundtrip_preserves_records() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "first memory", 0)).unwrap();
        s.upsert(&drawer("w", "r", "second memory", 1)).unwrap();
        let exported = s.export_all_with_vectors().unwrap();
        assert_eq!(exported.len(), 2);
        // Import into a fresh vault, mirroring a migration.
        let (_d2, mut s2) = store(SecurityLevel::Sealed);
        let mut n = 0u64;
        for (dr, vec) in &exported {
            if s2.import_record(dr, Some(vec.clone())).unwrap() {
                n += 1;
            }
        }
        assert_eq!(n, 2);
        assert_eq!(s2.count().unwrap(), 2);
        assert!(s2.verify().unwrap().ok());
        let hits = s2
            .search("second memory", &SearchOptions::default())
            .unwrap();
        assert!(hits.iter().any(|h| h.drawer.content == "second memory"));
    }

    #[test]
    fn external_import_requires_vector() {
        let (_d, mut s) = external_store(SecurityLevel::Sealed, 4);
        let dr = drawer("w", "r", "x", 0);
        assert!(matches!(
            s.import_record(&dr, None),
            Err(StoreError::ExternalVault)
        ));
        assert!(s.import_record(&dr, Some(vec![0.0; 4])).unwrap());
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
    fn pq_prefilter_agrees_with_full_scan() {
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
        let full = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        s.set_pq(true);
        let pre = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(pre[0].drawer.id, full[0].drawer.id);
        // The index must actually exist (not the full-scan fallback).
        let coded: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq", [], |r| r.get(0))
            .unwrap();
        assert_eq!(coded, 31, "every drawer must be PQ-coded");
        // Incremental coherence: a drawer written after the build is found.
        s.upsert(&drawer(
            "w",
            "api",
            "kafka handles the event stream backlog now",
            200,
        ))
        .unwrap();
        let hits = s
            .search("kafka event stream backlog", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("kafka"));
    }

    #[test]
    fn ivf_partitions_agree_with_flat_pq_and_self_heal() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        for i in 0..120 {
            s.upsert(&drawer("w", "r", &format!("routine note number {i}"), i))
                .unwrap();
        }
        s.upsert(&drawer(
            "w",
            "api",
            "we switched to graphql because rest was chatty",
            500,
        ))
        .unwrap();
        s.set_pq(true);

        // Flat PQ baseline (IVF off).
        s.set_ivf(usize::MAX, None);
        let flat = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();

        // IVF on, generous probe: same result, and the rows are partitioned.
        s.set_ivf(32, Some(4));
        let ivf = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(ivf[0].drawer.id, flat[0].drawer.id);
        let listed: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq WHERE list >= 0", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(listed, 121, "every code row must carry a list id");
        let stored_ivf: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM pq_meta WHERE key = 'ivf'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stored_ivf, 1, "IVF centroids must persist");

        // Incremental write gets a list id and stays findable through the
        // probed path.
        s.upsert(&drawer(
            "w",
            "api",
            "kafka handles the event stream backlog now",
            600,
        ))
        .unwrap();
        let unlisted: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM drawer_pq p JOIN drawers d ON d.seq = p.seq \
                 WHERE p.list = -1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(unlisted, 0, "incremental writes must be list-assigned");
        let hits = s
            .search("kafka event stream backlog", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("kafka"));

        // Outgrown partitions retrain: tripling the corpus past 2× the
        // trained size must bump trained_n on the persisted centroids.
        let before = s
            .conn
            .query_row("SELECT value FROM pq_meta WHERE key = 'ivf'", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map(|b| pq::CoarseQuantizer::from_bytes(&b).unwrap().trained_n())
            .unwrap();
        for i in 0..400 {
            s.upsert(&drawer(
                "w",
                "grow",
                &format!("expansion fact {i}"),
                1000 + i,
            ))
            .unwrap();
        }
        let _ = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        let after = s
            .conn
            .query_row("SELECT value FROM pq_meta WHERE key = 'ivf'", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map(|b| pq::CoarseQuantizer::from_bytes(&b).unwrap().trained_n())
            .unwrap();
        assert!(
            after > before * 2,
            "outgrown IVF must retrain (trained_n {before} -> {after})"
        );

        // Below the threshold a rebuild drops the partitions, not leaves
        // them stale. Model a crash that lost a code row: the row vanishes
        // AND the next open starts unverified (coherence is checked on the
        // first search after open, not per query).
        s.set_ivf(usize::MAX, None);
        s.conn
            .execute(
                "DELETE FROM drawer_pq WHERE seq IN (SELECT seq FROM drawer_pq LIMIT 1)",
                [],
            )
            .unwrap();
        s.pq_verified.set(false);
        let _ = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        let stored_ivf: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM pq_meta WHERE key = 'ivf'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stored_ivf, 0, "sub-threshold rebuild must drop IVF");
    }

    #[test]
    fn ivf_probe_finds_the_target_in_a_strict_subset() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        let target = drawer("w", "r", "topic 3 detail number 13", 13);
        for i in 0..200 {
            s.upsert(&drawer(
                "w",
                "r",
                &format!("topic {} detail number {i}", i % 10),
                i,
            ))
            .unwrap();
        }
        s.set_pq(true);
        s.set_ivf(64, Some(2));
        // Small k so the probed lists satisfy it and the early-return branch
        // (not the full-scan fallback) is what's under test.
        let qvec = s.embedder.embed("topic 3 detail number 13");
        let cands = s.pq_candidates(&qvec, 20).unwrap().expect("PQ index");
        assert_eq!(cands.len(), 20);
        let target_seq: i64 = s
            .conn
            .query_row("SELECT seq FROM drawers WHERE id = ?1", [&target.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(
            cands.contains(&target_seq),
            "the query's own drawer must survive a 2-list probe"
        );
        // And the probe really is a strict subset: no two lists cover the
        // whole corpus (nlist = 16 at N=200).
        let max_two_lists: i64 = s
            .conn
            .query_row(
                "SELECT COALESCE(SUM(c), 0) FROM (SELECT COUNT(*) c FROM drawer_pq \
                 GROUP BY list ORDER BY c DESC LIMIT 2)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            max_two_lists < 200,
            "a 2-list probe must scan a strict subset ({max_two_lists}/200)"
        );
    }

    #[test]
    fn pq_legacy_layout_migrates_and_updates_leave_no_duplicates() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        // A pre-IVF (v0.14.0) drawer_pq: seq-keyed rowid table.
        s.conn
            .execute_batch(
                "CREATE TABLE drawer_pq (seq INTEGER PRIMARY KEY, code BLOB NOT NULL);
                 INSERT INTO drawer_pq VALUES (1, x'00');",
            )
            .unwrap();
        for i in 0..40 {
            s.upsert(&drawer("w", "r", &format!("migration note {i}"), i))
                .unwrap();
        }
        s.set_pq(true);
        let hits = s
            .search("migration note 7", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("note 7"));
        // The legacy table must have been replaced by the clustered layout
        // and fully re-encoded.
        let (sql, rows): (String, i64) = (
            s.conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE name = 'drawer_pq'",
                    [],
                    |r| r.get(0),
                )
                .unwrap(),
            s.conn
                .query_row("SELECT COUNT(*) FROM drawer_pq", [], |r| r.get(0))
                .unwrap(),
        );
        assert!(sql.contains("WITHOUT ROWID"), "must migrate: {sql}");
        assert_eq!(rows, 40);

        // Updating a drawer (same id ⇒ same seq, embedding changes) must not
        // leave a stale row in the old list.
        let mut updated = drawer("w", "r", "migration note 3", 3);
        updated.content = "completely different content about zebras".into();
        s.upsert(&updated).unwrap();
        let dup: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) - COUNT(DISTINCT seq) FROM drawer_pq",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dup, 0, "an updated drawer must occupy exactly one list");

        // Deleting a drawer purges its code row (the scan doesn't join
        // drawers, so orphans would linger as dead candidate slots).
        let victim = drawer("w", "r", "migration note 5", 5);
        assert!(s.delete_drawer(&victim.id).unwrap());
        let orphans: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM drawer_pq WHERE seq NOT IN (SELECT seq FROM drawers)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0, "delete must purge the PQ code row");
    }

    #[test]
    fn sealed_pq_stores_nothing_plaintext_derived_in_clear() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
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

        // Sealed baseline (decrypt-scan), then the sealed PQ path: results
        // must agree.
        let full = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        s.set_pq(true);
        let pre = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(pre[0].drawer.id, full[0].drawer.id);

        // The index exists — but nothing on disk is in clear.
        // (1) Every row's blob must differ from the plain (list ‖ code)
        //     packing of its embedding, and the list column must carry no
        //     information.
        let coded: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq", [], |r| r.get(0))
            .unwrap();
        assert_eq!(coded, 31, "sealed vaults get the PQ index too");
        let clear_lists: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq WHERE list != -1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(clear_lists, 0, "list ids must never be stored in clear");
        {
            let pq_ref = s.pq.borrow();
            let pq = pq_ref.as_ref().expect("codebook cached");
            let emb = s
                .embedder
                .embed("we switched to graphql because rest was chatty");
            let plain_code = pq.encode(&emb);
            let blobs: Vec<Vec<u8>> = s
                .conn
                .prepare("SELECT code FROM drawer_pq")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(
                blobs.iter().all(|b| !b
                    .windows(plain_code.len())
                    .any(|w| w == plain_code.as_slice())),
                "no sealed row may contain a plain code"
            );
        }
        // (2) The codebook/IVF metadata must not decode as plaintext.
        let meta: Vec<u8> = s
            .conn
            .query_row(
                "SELECT value FROM pq_meta WHERE key = 'codebook'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            pq::ProductQuantizer::from_bytes(&meta).is_none(),
            "sealed codebook must not be readable without the vault key"
        );

        // Incremental sealed write stays findable (cache kept coherent).
        s.upsert(&drawer(
            "w",
            "api",
            "kafka handles the event stream backlog now",
            200,
        ))
        .unwrap();
        let hits = s
            .search("kafka event stream backlog", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("kafka"));

        // Reopen semantics: a fresh cache (decrypt-on-open path) reproduces
        // the same candidates.
        s.pq_cache.borrow_mut().take();
        s.pq_verified.set(false);
        let again = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(again[0].drawer.id, full[0].drawer.id);
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
            s.upsert(&drawer(
                "w",
                "r",
                &format!("the system logged an event {i}"),
                i,
            ))
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
            s.upsert(&drawer(
                "work",
                "infra",
                "postgres migration completed friday",
                2,
            ))
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
        s.upsert(&drawer(
            "w",
            "r",
            "the kubernetes cluster upgrade finished",
            0,
        ))
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
