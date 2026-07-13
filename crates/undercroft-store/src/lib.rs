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

use rusqlite::{params, Connection, OptionalExtension};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use undercroft_core::embed::{cosine, Embedder};
use undercroft_core::{Drawer, DrawerMeta, HashEmbedder};
use undercroft_vault::{Vault, VaultError};

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
}

fn canonical(id: &str, meta_json: &[u8], content_at_rest: &[u8]) -> Vec<u8> {
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
    embedder: HashEmbedder,
}

impl PalaceStore {
    /// Open (creating if needed) the store for an unlocked vault.
    pub fn open(vault: Vault) -> Result<Self, StoreError> {
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
        Ok(Self { conn, vault, embedder: HashEmbedder })
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn count(&self) -> Result<u64, StoreError> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM drawers", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// Insert or replace a drawer. Returns `true` if the id was new.
    pub fn upsert(&mut self, drawer: &Drawer) -> Result<bool, StoreError> {
        let meta_json = serde_json::to_string(&drawer.meta)
            .map_err(|e| StoreError::CorruptRow { id: drawer.id.clone(), reason: e.to_string() })?;
        let content_rest = self.vault.content_at_rest(&drawer.id, drawer.content.as_bytes());
        let embedding = self.embedder.embed(&drawer.content);
        let emb_rest = self.vault.embedding_at_rest(&drawer.id, &embedding);
        let tag = self.vault.tag(&canonical(&drawer.id, meta_json.as_bytes(), &content_rest));
        let now = OffsetDateTime::now_utc().format(&Rfc3339).expect("rfc3339 now");

        let existing: Option<i64> = self
            .conn
            .query_row("SELECT seq FROM drawers WHERE id = ?1", params![drawer.id], |r| r.get(0))
            .optional()?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO drawers (id, wing, room, meta_json, content, embedding, tag, filed_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
             ON CONFLICT(id) DO UPDATE SET
                 wing = excluded.wing,
                 room = excluded.room,
                 meta_json = excluded.meta_json,
                 content = excluded.content,
                 embedding = excluded.embedding,
                 tag = excluded.tag,
                 updated_at = excluded.updated_at",
            params![
                drawer.id,
                drawer.meta.wing,
                drawer.meta.room,
                meta_json,
                content_rest,
                emb_rest,
                tag.as_slice(),
                now,
            ],
        )?;
        tx.execute(
            "INSERT INTO audit (record_id, tag, at) VALUES (?1, ?2, ?3)",
            params![drawer.id, tag.as_slice(), now],
        )?;
        tx.commit()?;
        self.vault.commit_write(&tag)?;
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

    fn decode(
        &self,
        id: &str,
        meta_json: &str,
        content_rest: &[u8],
    ) -> Result<Drawer, StoreError> {
        let meta: DrawerMeta = serde_json::from_str(meta_json)
            .map_err(|e| StoreError::CorruptRow { id: id.into(), reason: e.to_string() })?;
        let plain = self
            .vault
            .content_from_rest(id, content_rest)
            .map_err(|e| StoreError::CorruptRow { id: id.into(), reason: e.to_string() })?;
        let content = String::from_utf8(plain)
            .map_err(|e| StoreError::CorruptRow { id: id.into(), reason: e.to_string() })?;
        Ok(Drawer { id: id.to_string(), content, meta })
    }

    /// Most recently filed drawers (optionally scoped to a wing) — the
    /// palace's "essential story" feed used by wake-up.
    pub fn recent(&self, wing: Option<&str>, limit: usize) -> Result<Vec<Drawer>, StoreError> {
        let mut sql = String::from(
            "SELECT id, meta_json, content, tag FROM drawers",
        );
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
    /// plaintext is read from disk indexes.
    pub fn search(&self, query: &str, opts: &SearchOptions) -> Result<Vec<SearchHit>, StoreError> {
        let limit = if opts.limit == 0 { 10 } else { opts.limit };
        let qvec = self.embedder.embed(query);
        let qterms: Vec<String> = query
            .to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() > 1)
            .map(str::to_string)
            .collect();

        let mut sql = String::from("SELECT id, meta_json, content, embedding, tag FROM drawers");
        let mut clauses: Vec<String> = Vec::new();
        let mut binds: Vec<String> = Vec::new();
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
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>, Vec<u8>)> = stmt
            .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                ))
            })?
            .collect::<Result<_, _>>()?;

        let now = OffsetDateTime::now_utc();
        let mut hits: Vec<SearchHit> = Vec::new();
        for (id, meta_json, content_rest, emb_rest, tag) in rows {
            self.vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .map_err(|_| StoreError::Integrity(id.clone()))?;
            let drawer = self.decode(&id, &meta_json, &content_rest)?;
            let emb = self
                .vault
                .embedding_from_rest(&id, &emb_rest)
                .map_err(|e| StoreError::CorruptRow { id: id.clone(), reason: e.to_string() })?;

            let semantic = ((cosine(&qvec, &emb) + 1.0) / 2.0).clamp(0.0, 1.0);
            let lexical = lexical_score(&qterms, query, &drawer.content);
            let recency = recency_boost(&drawer.meta.filed_at, now);
            let score = 0.55 * semantic + 0.35 * lexical + 0.10 * recency;
            hits.push(SearchHit { drawer, score, semantic, lexical });
        }
        // Relevance gate: an unrelated record still scores ~0.35 from the
        // neutral cosine midpoint + recency alone. Require actual evidence —
        // a lexical match or a clearly positive semantic signal.
        hits.retain(|h| h.lexical > 0.0 || h.semantic > 0.56);
        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        hits.truncate(limit);
        Ok(hits)
    }

    /// Walk every record verifying its HMAC, then replay the audit chain
    /// against the manifest head.
    pub fn verify(&self) -> Result<VerifyReport, StoreError> {
        let mut stmt =
            self.conn.prepare("SELECT id, meta_json, content, tag FROM drawers ORDER BY seq")?;
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
        let mut stmt = self.conn.prepare("SELECT tag FROM audit ORDER BY seq")?;
        let tags: Vec<Vec<u8>> =
            stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?.collect::<Result<_, _>>()?;
        let chain_ok = self.vault.verify_chain(&tags);
        Ok(VerifyReport { records_checked: checked, bad_records: bad, chain_ok })
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
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)))?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }
}

/// Fraction of query terms present in the content, with a phrase bonus.
fn lexical_score(qterms: &[String], raw_query: &str, content: &str) -> f32 {
    if qterms.is_empty() {
        return 0.0;
    }
    let lower = content.to_lowercase();
    let matched = qterms.iter().filter(|t| lower.contains(t.as_str())).count() as f32;
    let mut score = matched / qterms.len() as f32;
    let phrase = raw_query.trim().to_lowercase();
    if phrase.len() > 3 && lower.contains(&phrase) {
        score = (score + 0.5).min(1.0);
    }
    score
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
        Drawer::new(wing, room, content.into(), Some("test.md".into()), idx, "test")
    }

    #[test]
    fn upsert_get_roundtrip_sealed() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let dr = drawer("work", "decisions", "we chose graphql over rest for the api", 0);
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
        s.upsert(&drawer("w", "r", "findable plaintext content", 0)).unwrap();
        drop(s);
        let db = std::fs::read(dir.path().join("vaults/test/palace.db")).unwrap();
        assert!(db.windows(8).any(|w| w == b"findable"));
    }

    #[test]
    fn search_ranks_relevant_first() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("work", "api", "we switched to graphql because rest was chatty", 0))
            .unwrap();
        s.upsert(&drawer("home", "pets", "the cat likes the windowsill", 1)).unwrap();
        s.upsert(&drawer("work", "infra", "postgres migration completed friday", 2)).unwrap();
        let hits = s.search("why did we switch to graphql", &SearchOptions::default()).unwrap();
        assert_eq!(hits[0].drawer.meta.room, "api");
        assert!(hits[0].score > hits.last().unwrap().score);
    }

    #[test]
    fn search_scopes_to_wing() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("a", "r", "shared topic alpha content", 0)).unwrap();
        s.upsert(&drawer("b", "r", "shared topic alpha content", 1)).unwrap();
        let hits = s
            .search(
                "alpha",
                &SearchOptions { wing: Some("a".into()), room: None, limit: 10 },
            )
            .unwrap();
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|h| h.drawer.meta.wing == "a"));
    }

    #[test]
    fn verify_clean_store_passes() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        for i in 0..5 {
            s.upsert(&drawer("w", "r", &format!("memory number {i}"), i)).unwrap();
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
    fn export_roundtrips_all_records() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "alpha", 0)).unwrap();
        s.upsert(&drawer("w", "r", "beta", 1)).unwrap();
        let all = s.export_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].content, "alpha");
    }
}
