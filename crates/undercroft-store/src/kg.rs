//! Temporal knowledge graph, ported from mempalace's `knowledge_graph.py`.
//!
//! Entities + triples with validity windows: a fact holds from
//! `valid_from` until `valid_to` (open-ended when `None`). Facts are never
//! deleted — `invalidate` closes the window, `supersede` closes the old
//! fact and opens the new one, and `timeline` replays history.
//!
//! Security: triples live in the vault database and follow the vault's
//! rules — in sealed vaults the *object* (the fact's value) is AEAD-
//! encrypted at rest, while subject/predicate stay queryable structure
//! (the same trade-off as plaintext wing/room names on sealed drawers).
//! Every entity and triple carries an HMAC tag, verified on read and
//! covered by `verify`, and every graph write advances the audit chain.

use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{PalaceStore, StoreError};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Triple {
    pub id: String,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub confidence: f64,
    pub source_drawer_id: Option<String>,
    pub extracted_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KgStats {
    pub entities: u64,
    pub triples: u64,
    pub active: u64,
    pub closed: u64,
}

/// Normalize a date or datetime string to a sortable comparison key.
/// Date-only values are treated as midnight UTC so mixed granularity
/// compares correctly (mirrors `_temporal_start_key` upstream).
fn temporal_key(value: &str) -> String {
    let v = value.trim();
    if v.len() == 10 && v.as_bytes().get(4) == Some(&b'-') {
        format!("{v}T00:00:00Z")
    } else {
        v.to_string()
    }
}

fn triple_id(subject: &str, predicate: &str, object: &str, valid_from: Option<&str>) -> String {
    let mut h = Sha256::new();
    for part in [subject, predicate, object, valid_from.unwrap_or("")] {
        h.update(part.as_bytes());
        h.update([0x1f]);
    }
    hex::encode(&h.finalize()[..16])
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("rfc3339 now")
}

fn triple_canonical(
    id: &str,
    subject: &str,
    predicate: &str,
    object_at_rest: &[u8],
    valid_from: &Option<String>,
    valid_to: &Option<String>,
    confidence: f64,
) -> Vec<u8> {
    let mut out = Vec::new();
    for part in [
        id,
        subject,
        predicate,
        valid_from.as_deref().unwrap_or(""),
        valid_to.as_deref().unwrap_or(""),
    ] {
        out.extend_from_slice(part.as_bytes());
        out.push(0x1f);
    }
    out.extend_from_slice(&confidence.to_le_bytes());
    out.push(0x1f);
    out.extend_from_slice(object_at_rest);
    out
}

impl PalaceStore {
    pub(crate) fn init_kg_schema(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kg_entities (
                 id         TEXT PRIMARY KEY,
                 name       TEXT NOT NULL UNIQUE,
                 etype      TEXT NOT NULL DEFAULT 'unknown',
                 tag        BLOB NOT NULL,
                 created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS kg_triples (
                 seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                 id          TEXT NOT NULL UNIQUE,
                 subject     TEXT NOT NULL,
                 predicate   TEXT NOT NULL,
                 object      BLOB NOT NULL,
                 valid_from  TEXT,
                 valid_to    TEXT,
                 confidence  REAL NOT NULL DEFAULT 1.0,
                 source_drawer_id TEXT,
                 tag         BLOB NOT NULL,
                 extracted_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_kg_triples_subject ON kg_triples(subject);
             CREATE INDEX IF NOT EXISTS idx_kg_triples_predicate ON kg_triples(predicate);",
        )?;
        Ok(())
    }

    fn ensure_entity(&mut self, name: &str) -> Result<(), StoreError> {
        let exists: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM kg_entities WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_some() {
            return Ok(());
        }
        let id = hex::encode(&Sha256::digest(name.as_bytes())[..16]);
        let created = now_rfc3339();
        let canonical = format!("{id}\x1f{name}\x1funknown\x1f{created}");
        let tag = self.vault.tag(canonical.as_bytes());
        self.conn.execute(
            "INSERT INTO kg_entities (id, name, etype, tag, created_at) VALUES (?1, ?2, 'unknown', ?3, ?4)",
            params![id, name, tag.as_slice(), created],
        )?;
        Ok(())
    }

    /// Add a fact. Entities are created implicitly. Returns the triple id;
    /// re-adding the same (s, p, o, valid_from) is idempotent.
    #[allow(clippy::too_many_arguments)]
    pub fn kg_add(
        &mut self,
        subject: &str,
        predicate: &str,
        object: &str,
        valid_from: Option<&str>,
        valid_to: Option<&str>,
        confidence: f64,
        source_drawer_id: Option<&str>,
    ) -> Result<String, StoreError> {
        undercroft_core::validate_name(subject, "subject").map_err(|e| StoreError::CorruptRow {
            id: subject.into(),
            reason: e.to_string(),
        })?;
        undercroft_core::validate_name(predicate, "predicate").map_err(|e| {
            StoreError::CorruptRow {
                id: predicate.into(),
                reason: e.to_string(),
            }
        })?;
        self.ensure_entity(subject)?;
        let id = triple_id(subject, predicate, object, valid_from);
        let object_rest = self
            .vault
            .content_at_rest(&format!("kg/{id}"), object.as_bytes());
        let vf = valid_from.map(str::to_string);
        let vt = valid_to.map(str::to_string);
        let tag = self.vault.tag(&triple_canonical(
            &id,
            subject,
            predicate,
            &object_rest,
            &vf,
            &vt,
            confidence,
        ));
        let now = now_rfc3339();
        self.conn.execute(
            "INSERT INTO kg_triples (id, subject, predicate, object, valid_from, valid_to,
                                     confidence, source_drawer_id, tag, extracted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
                 object = excluded.object,
                 valid_to = excluded.valid_to,
                 confidence = excluded.confidence,
                 source_drawer_id = excluded.source_drawer_id,
                 tag = excluded.tag",
            params![
                id,
                subject,
                predicate,
                object_rest,
                vf,
                vt,
                confidence,
                source_drawer_id,
                tag.as_slice(),
                now
            ],
        )?;
        self.conn.execute(
            "INSERT INTO audit (record_id, tag, at) VALUES (?1, ?2, ?3)",
            params![format!("kg/{id}"), tag.as_slice(), now],
        )?;
        self.vault.commit_write(&tag)?;
        undercroft_obs::kg_write(undercroft_obs::KgKind::Triple);
        Ok(id)
    }

    fn decode_triple(&self, row: TripleRow) -> Result<Triple, StoreError> {
        self.vault
            .verify_tag(
                &triple_canonical(
                    &row.id,
                    &row.subject,
                    &row.predicate,
                    &row.object,
                    &row.valid_from,
                    &row.valid_to,
                    row.confidence,
                ),
                &row.tag,
            )
            .map_err(|_| {
                undercroft_obs::hmac_verify_failed("kg");
                StoreError::Integrity(format!("kg/{}", row.id))
            })?;
        let object = self
            .vault
            .content_from_rest(&format!("kg/{}", row.id), &row.object)
            .map_err(|e| StoreError::CorruptRow {
                id: row.id.clone(),
                reason: e.to_string(),
            })?;
        Ok(Triple {
            object: String::from_utf8(object).map_err(|e| StoreError::CorruptRow {
                id: row.id.clone(),
                reason: e.to_string(),
            })?,
            id: row.id,
            subject: row.subject,
            predicate: row.predicate,
            valid_from: row.valid_from,
            valid_to: row.valid_to,
            confidence: row.confidence,
            source_drawer_id: row.source_drawer_id,
            extracted_at: row.extracted_at,
        })
    }

    fn all_triples(&self) -> Result<Vec<Triple>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, subject, predicate, object, valid_from, valid_to, confidence,
                    source_drawer_id, tag, extracted_at
             FROM kg_triples ORDER BY seq",
        )?;
        let rows: Vec<TripleRow> = stmt
            .query_map([], TripleRow::from_row)?
            .collect::<Result<_, _>>()?;
        rows.into_iter().map(|r| self.decode_triple(r)).collect()
    }

    /// Facts about an entity. `direction`: "outgoing" (entity as subject),
    /// "incoming" (entity as object), or "both". `as_of` filters to facts
    /// valid at that instant.
    pub fn kg_query_entity(
        &self,
        name: &str,
        as_of: Option<&str>,
        direction: &str,
    ) -> Result<Vec<Triple>, StoreError> {
        let all = self.all_triples()?;
        let key = as_of.map(temporal_key);
        Ok(all
            .into_iter()
            .filter(|t| match direction {
                "incoming" => t.object == name,
                "both" => t.subject == name || t.object == name,
                _ => t.subject == name,
            })
            .filter(|t| valid_at(t, key.as_deref()))
            .collect())
    }

    /// Every fact using a predicate, optionally as of an instant.
    pub fn kg_query_relationship(
        &self,
        predicate: &str,
        as_of: Option<&str>,
    ) -> Result<Vec<Triple>, StoreError> {
        let key = as_of.map(temporal_key);
        Ok(self
            .all_triples()?
            .into_iter()
            .filter(|t| t.predicate == predicate)
            .filter(|t| valid_at(t, key.as_deref()))
            .collect())
    }

    /// Close the validity window of matching active facts. Returns how many
    /// facts were invalidated.
    pub fn kg_invalidate(
        &mut self,
        subject: &str,
        predicate: &str,
        object: Option<&str>,
        ended: Option<&str>,
    ) -> Result<u64, StoreError> {
        let ended = ended.map(str::to_string).unwrap_or_else(now_rfc3339);
        let matches: Vec<Triple> = self
            .all_triples()?
            .into_iter()
            .filter(|t| {
                t.subject == subject
                    && t.predicate == predicate
                    && t.valid_to.is_none()
                    && object.map(|o| t.object == o).unwrap_or(true)
            })
            .collect();
        let mut count = 0u64;
        for t in matches {
            let object_rest = self
                .vault
                .content_at_rest(&format!("kg/{}", t.id), t.object.as_bytes());
            let vt = Some(ended.clone());
            let tag = self.vault.tag(&triple_canonical(
                &t.id,
                &t.subject,
                &t.predicate,
                &object_rest,
                &t.valid_from,
                &vt,
                t.confidence,
            ));
            self.conn.execute(
                "UPDATE kg_triples SET object = ?1, valid_to = ?2, tag = ?3 WHERE id = ?4",
                params![object_rest, ended, tag.as_slice(), t.id],
            )?;
            self.conn.execute(
                "INSERT INTO audit (record_id, tag, at) VALUES (?1, ?2, ?3)",
                params![format!("kg/{}", t.id), tag.as_slice(), now_rfc3339()],
            )?;
            self.vault.commit_write(&tag)?;
            undercroft_obs::kg_write(undercroft_obs::KgKind::Supersede);
            count += 1;
        }
        Ok(count)
    }

    /// Replace the current value of (subject, predicate): invalidate every
    /// active fact and add the new one starting at `changed_at`.
    pub fn kg_supersede(
        &mut self,
        subject: &str,
        predicate: &str,
        new_object: &str,
        changed_at: Option<&str>,
    ) -> Result<String, StoreError> {
        let at = changed_at.map(str::to_string).unwrap_or_else(now_rfc3339);
        self.kg_invalidate(subject, predicate, None, Some(&at))?;
        self.kg_add(subject, predicate, new_object, Some(&at), None, 1.0, None)
    }

    /// Full history, optionally scoped to one entity, ordered by validity
    /// start (facts with no start sort first).
    pub fn kg_timeline(&self, entity: Option<&str>) -> Result<Vec<Triple>, StoreError> {
        let mut out: Vec<Triple> = self
            .all_triples()?
            .into_iter()
            .filter(|t| {
                entity
                    .map(|e| t.subject == e || t.object == e)
                    .unwrap_or(true)
            })
            .collect();
        out.sort_by(|a, b| {
            let ka = a
                .valid_from
                .as_deref()
                .map(temporal_key)
                .unwrap_or_default();
            let kb = b
                .valid_from
                .as_deref()
                .map(temporal_key)
                .unwrap_or_default();
            ka.cmp(&kb)
                .then_with(|| a.extracted_at.cmp(&b.extracted_at))
        });
        Ok(out)
    }

    pub fn kg_stats(&self) -> Result<KgStats, StoreError> {
        let entities: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM kg_entities", [], |r| r.get(0))?;
        let triples: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM kg_triples", [], |r| r.get(0))?;
        let closed: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM kg_triples WHERE valid_to IS NOT NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(KgStats {
            entities: entities as u64,
            triples: triples as u64,
            active: (triples - closed) as u64,
            closed: closed as u64,
        })
    }

    /// Verify every KG row's HMAC; returns ids that fail.
    pub(crate) fn kg_verify(&self) -> Result<Vec<String>, StoreError> {
        let mut bad = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT id, subject, predicate, object, valid_from, valid_to, confidence,
                    source_drawer_id, tag, extracted_at
             FROM kg_triples ORDER BY seq",
        )?;
        let rows: Vec<TripleRow> = stmt
            .query_map([], TripleRow::from_row)?
            .collect::<Result<_, _>>()?;
        for row in rows {
            let canonical = triple_canonical(
                &row.id,
                &row.subject,
                &row.predicate,
                &row.object,
                &row.valid_from,
                &row.valid_to,
                row.confidence,
            );
            if self.vault.verify_tag(&canonical, &row.tag).is_err() {
                bad.push(format!("kg/{}", row.id));
            }
        }
        Ok(bad)
    }

    /// Number of KG rows checked by `kg_verify` (for verify reporting).
    pub(crate) fn kg_count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM kg_triples", [], |r| r.get(0))?;
        Ok(n as u64)
    }
}

struct TripleRow {
    id: String,
    subject: String,
    predicate: String,
    object: Vec<u8>,
    valid_from: Option<String>,
    valid_to: Option<String>,
    confidence: f64,
    source_drawer_id: Option<String>,
    tag: Vec<u8>,
    extracted_at: String,
}

impl TripleRow {
    fn from_row(r: &rusqlite::Row<'_>) -> Result<Self, rusqlite::Error> {
        Ok(TripleRow {
            id: r.get(0)?,
            subject: r.get(1)?,
            predicate: r.get(2)?,
            object: r.get(3)?,
            valid_from: r.get(4)?,
            valid_to: r.get(5)?,
            confidence: r.get(6)?,
            source_drawer_id: r.get(7)?,
            tag: r.get(8)?,
            extracted_at: r.get(9)?,
        })
    }
}

fn valid_at(t: &Triple, as_of_key: Option<&str>) -> bool {
    let Some(key) = as_of_key else {
        // No as_of: only currently-active facts.
        return t.valid_to.is_none();
    };
    let starts_ok = t
        .valid_from
        .as_deref()
        .map(|v| temporal_key(v).as_str() <= key)
        .unwrap_or(true);
    let ends_ok = t
        .valid_to
        .as_deref()
        .map(|v| temporal_key(v).as_str() > key)
        .unwrap_or(true);
    starts_ok && ends_ok
}

#[cfg(test)]
mod tests {
    use crate::{PalaceStore, SearchOptions};
    use undercroft_vault::{SecurityLevel, VaultManager};
    use tempfile::TempDir;

    fn store(level: SecurityLevel) -> (TempDir, PalaceStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("kg-test", level).unwrap();
        (dir, PalaceStore::open(vault).unwrap())
    }

    #[test]
    fn add_query_roundtrip() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.kg_add(
            "alice",
            "works_at",
            "acme",
            Some("2024-01-01"),
            None,
            1.0,
            None,
        )
        .unwrap();
        s.kg_add("alice", "lives_in", "berlin", None, None, 0.9, None)
            .unwrap();
        let facts = s.kg_query_entity("alice", None, "outgoing").unwrap();
        assert_eq!(facts.len(), 2);
        assert!(facts.iter().any(|t| t.object == "acme"));
    }

    #[test]
    fn supersede_closes_and_replaces() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.kg_add(
            "alice",
            "works_at",
            "acme",
            Some("2024-01-01"),
            None,
            1.0,
            None,
        )
        .unwrap();
        s.kg_supersede("alice", "works_at", "globex", Some("2025-06-01"))
            .unwrap();

        // Now: only globex is active.
        let now = s.kg_query_entity("alice", None, "outgoing").unwrap();
        assert_eq!(now.len(), 1);
        assert_eq!(now[0].object, "globex");

        // As of 2024: acme was the valid fact.
        let then = s
            .kg_query_entity("alice", Some("2024-06-15"), "outgoing")
            .unwrap();
        assert_eq!(then.len(), 1);
        assert_eq!(then[0].object, "acme");

        // Timeline shows both, in order.
        let tl = s.kg_timeline(Some("alice")).unwrap();
        assert_eq!(tl.len(), 2);
        assert_eq!(tl[0].object, "acme");
        assert_eq!(tl[1].object, "globex");
    }

    #[test]
    fn invalidate_specific_object() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        s.kg_add("bob", "uses", "python", None, None, 1.0, None)
            .unwrap();
        s.kg_add("bob", "uses", "rust", None, None, 1.0, None)
            .unwrap();
        let n = s
            .kg_invalidate("bob", "uses", Some("python"), Some("2026-01-01"))
            .unwrap();
        assert_eq!(n, 1);
        let active = s.kg_query_entity("bob", None, "outgoing").unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].object, "rust");
    }

    #[test]
    fn sealed_kg_object_not_plaintext_on_disk() {
        let (dir, mut s) = store(SecurityLevel::Sealed);
        s.kg_add(
            "alice",
            "secret_project",
            "operation-blue-heron-77",
            None,
            None,
            1.0,
            None,
        )
        .unwrap();
        drop(s);
        let db = std::fs::read(dir.path().join("vaults/kg-test/palace.db")).unwrap();
        let needle = b"operation-blue-heron-77";
        assert!(!db.windows(needle.len()).any(|w| w == needle));
        // Subject stays queryable structure.
        assert!(db.windows(5).any(|w| w == b"alice"));
    }

    #[test]
    fn kg_rows_covered_by_verify() {
        let (dir, mut s) = store(SecurityLevel::HmacOnly);
        s.kg_add("alice", "works_at", "acme", None, None, 1.0, None)
            .unwrap();
        assert!(s.verify().unwrap().ok());
        drop(s);
        let conn = rusqlite::Connection::open(dir.path().join("vaults/kg-test/palace.db")).unwrap();
        conn.execute("UPDATE kg_triples SET confidence = 0.1", [])
            .unwrap();
        drop(conn);
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let s = PalaceStore::open(mgr.unlock("kg-test").unwrap()).unwrap();
        let report = s.verify().unwrap();
        assert!(!report.ok());
        assert!(report.bad_records[0].starts_with("kg/"));
    }

    #[test]
    fn kg_and_drawers_share_audit_chain() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let dr = undercroft_core::Drawer::new("w", "r", "content".into(), None, 0, "t");
        s.upsert(&dr).unwrap();
        s.kg_add("alice", "works_at", "acme", None, None, 1.0, None)
            .unwrap();
        let report = s.verify().unwrap();
        assert!(report.ok(), "chain must cover drawer + kg writes");
        // Searching still works alongside KG data.
        assert!(s.search("content", &SearchOptions::default()).is_ok());
    }
}
