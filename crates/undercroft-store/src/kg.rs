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

use crate::{chain_append, PalaceStore, StoreError};

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
    /// Where the fact rests, when that was ever evaluated. `None` is
    /// `Grounding::Unevaluated` and is not the same as an empty evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support: Option<undercroft_core::support::Support>,
}

impl Triple {
    /// Whether this fact rests on the note's own words, on the extractor's
    /// background knowledge, or was never checked.
    pub fn grounding(&self) -> undercroft_core::support::Grounding {
        undercroft_core::support::Support::grounding(self.support.as_ref())
    }
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

// Every field of a triple that the tamper tag covers, so the argument list is
// the fact itself rather than an assortment. Splitting it would only move the
// coupling somewhere less obvious.
#[allow(clippy::too_many_arguments)]
pub(crate) fn triple_canonical(
    id: &str,
    subject: &str,
    predicate: &str,
    object_at_rest: &[u8],
    valid_from: &Option<String>,
    valid_to: &Option<String>,
    confidence: f64,
    support_at_rest: Option<&[u8]>,
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
    // Appended only when a grounding evaluation exists. Every fact written
    // before grounding did has none, so its canonical bytes are unchanged to
    // the byte and its tag still verifies — no re-tagging, no rewrite of a
    // tamper-evident table, no chain churn. The separator goes inside the
    // branch for the same reason.
    if let Some(sup) = support_at_rest {
        out.push(0x1f);
        out.extend_from_slice(sup);
    }
    out
}

/// Unkeyed fingerprint of a source drawer's verbatim content, captured
/// when a fact is distilled. Unkeyed (plain SHA-256) on purpose: it must
/// survive key rotation unchanged so a receipt stays valid across
/// rotations, while the *keyed* `receipt_tag` (below) is what makes the
/// citation unforgeable. A change here means the cited source was edited
/// out from under the fact — surfaced as `SourceChanged`, never hidden.
pub(crate) fn content_fp(content: &str) -> Vec<u8> {
    Sha256::digest(content.as_bytes()).to_vec()
}

/// Canonical bytes of a **receipt**: the tamper-covered binding of a
/// distilled fact to the verbatim drawer it was derived from. Keyed with
/// the vault mac (like every other tag), so an offline attacker cannot
/// swap the citation or the source fingerprint without failing
/// `verify_tag`. The triple id is inside the binding, so a receipt cannot
/// be moved to a different fact.
pub(crate) fn receipt_canonical(
    triple_id: &str,
    source_drawer_id: &str,
    source_fp: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(triple_id.as_bytes());
    out.push(0x1f);
    out.extend_from_slice(source_drawer_id.as_bytes());
    out.push(0x1f);
    out.extend_from_slice(source_fp);
    out
}

/// Outcome of verifying one fact's receipt against its cited source.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVerdict {
    /// Citation intact and the cited drawer still hashes to the recorded fp.
    Verified,
    /// Citation intact, cited drawer present, but its content changed since
    /// the fact was distilled — the fact may no longer reflect its source.
    SourceChanged,
    /// Citation intact but the cited drawer no longer exists.
    Dangling,
    /// The receipt binding itself failed its HMAC — offline tampering.
    Tampered,
}

/// A fact's receipt and its verification outcome.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReceiptStatus {
    pub triple_id: String,
    pub source_drawer_id: String,
    pub verdict: ReceiptVerdict,
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
                 extracted_at TEXT NOT NULL,
                 source_fp   BLOB,
                 receipt_tag BLOB,
                 -- Sealed grounding evaluation. NULL means the check never
                 -- ran, which is NOT the same as running it and finding no
                 -- support; see core::support::Grounding.
                 support     BLOB
             );
             CREATE INDEX IF NOT EXISTS idx_kg_triples_subject ON kg_triples(subject);
             CREATE INDEX IF NOT EXISTS idx_kg_triples_predicate ON kg_triples(predicate);",
        )?;
        // Migrate palaces created before the receipt columns existed. SQLite
        // has no ADD COLUMN IF NOT EXISTS; a duplicate-column error just
        // means the migration already ran, so it is swallowed.
        for col in ["source_fp BLOB", "receipt_tag BLOB", "support BLOB"] {
            let _ = self
                .conn
                .execute(&format!("ALTER TABLE kg_triples ADD COLUMN {col}"), []);
        }
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
    /// re-adding the same (s, p, o, valid_from) is idempotent. The citation
    /// (`source_drawer_id`) is recorded but *not* tamper-covered — for an
    /// evidence-grade citation use [`kg_add_receipted`].
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
        self.kg_add_inner(
            subject,
            predicate,
            object,
            valid_from,
            valid_to,
            confidence,
            source_drawer_id,
            None,
            None,
        )
    }

    /// Add a distilled fact **with a receipt**: an HMAC-covered citation to
    /// the verbatim `source` drawer it was derived from. `source` is
    /// `(drawer_id, drawer_content)`; the content is fingerprinted (unkeyed
    /// SHA-256) so the receipt later proves both *which* drawer the fact
    /// came from and that the drawer has not changed under it. The fact's
    /// verbatim source is never altered — this only *adds* a provable link.
    #[allow(clippy::too_many_arguments)]
    pub fn kg_add_receipted(
        &mut self,
        subject: &str,
        predicate: &str,
        object: &str,
        valid_from: Option<&str>,
        valid_to: Option<&str>,
        confidence: f64,
        source: (&str, &str),
    ) -> Result<String, StoreError> {
        self.kg_add_grounded(
            subject, predicate, object, valid_from, valid_to, confidence, source, None,
        )
    }

    /// As [`kg_add_receipted`], recording **where the fact rests**: `support`
    /// is the outcome of checking the extractor's quotations against the
    /// source drawer.
    ///
    /// `None` records that no such check was run — distinct from
    /// `Some(Support::default())`, which records that it ran and the note
    /// supported nothing. A fact resting on background knowledge is not a
    /// lesser fact; it is the edge that answers what a single note cannot.
    #[allow(clippy::too_many_arguments)]
    pub fn kg_add_grounded(
        &mut self,
        subject: &str,
        predicate: &str,
        object: &str,
        valid_from: Option<&str>,
        valid_to: Option<&str>,
        confidence: f64,
        source: (&str, &str),
        support: Option<&undercroft_core::support::Support>,
    ) -> Result<String, StoreError> {
        let (drawer_id, drawer_content) = source;
        let fp = content_fp(drawer_content);
        self.kg_add_inner(
            subject,
            predicate,
            object,
            valid_from,
            valid_to,
            confidence,
            Some(drawer_id),
            Some(fp),
            support,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn kg_add_inner(
        &mut self,
        subject: &str,
        predicate: &str,
        object: &str,
        valid_from: Option<&str>,
        valid_to: Option<&str>,
        confidence: f64,
        source_drawer_id: Option<&str>,
        source_fp: Option<Vec<u8>>,
        support: Option<&undercroft_core::support::Support>,
    ) -> Result<String, StoreError> {
        let _span = undercroft_obs::scope("kg", self.vault.id());
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
        // Sealed like the object, under its own AAD domain: spans are
        // metadata about verbatim content and a sealed vault keeps no
        // plaintext-derived artifact in the clear.
        let support_rest = support
            .map(|s| serde_json::to_vec(s).unwrap_or_default())
            .map(|bytes| {
                self.vault
                    .content_at_rest(&format!("kg/{id}/support"), &bytes)
            });
        let tag = self.vault.tag(&triple_canonical(
            &id,
            subject,
            predicate,
            &object_rest,
            &vf,
            &vt,
            confidence,
            support_rest.as_deref(),
        ));
        // Receipt: a separate keyed tag over (triple id, citation, source
        // fingerprint). Kept distinct from the triple tag so it composes
        // without touching the fact's own canonical, and so legacy facts
        // (no receipt) are unaffected.
        let receipt_tag = source_fp
            .as_ref()
            .zip(source_drawer_id)
            .map(|(fp, did)| self.vault.tag(&receipt_canonical(&id, did, fp)));
        let now = now_rfc3339();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO kg_triples (id, subject, predicate, object, valid_from, valid_to,
                                     confidence, source_drawer_id, tag, extracted_at,
                                     source_fp, receipt_tag, support)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(id) DO UPDATE SET
                 object = excluded.object,
                 valid_to = excluded.valid_to,
                 confidence = excluded.confidence,
                 source_drawer_id = excluded.source_drawer_id,
                 tag = excluded.tag,
                 source_fp = excluded.source_fp,
                 receipt_tag = excluded.receipt_tag,
                 support = excluded.support",
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
                now,
                source_fp,
                receipt_tag.as_ref().map(|t| t.as_slice()),
                support_rest.as_deref(),
            ],
        )?;
        let (head, writes) = chain_append(&tx, &self.vault, &format!("kg/{id}"), &tag, &now)?;
        tx.commit()?;
        self.vault.anchor_manifest(&head, writes)?;
        undercroft_obs::kg_write(undercroft_obs::KgKind::Triple);
        undercroft_obs::event_kg_triple(self.vault.id());
        Ok(id)
    }

    /// Verify every fact that carries a receipt against its cited verbatim
    /// source. Returns one [`ReceiptStatus`] per receipted fact:
    /// `Verified` (citation intact, source unchanged), `SourceChanged`
    /// (source edited since distillation), `Dangling` (source deleted), or
    /// `Tampered` (the receipt binding failed its HMAC). Facts without a
    /// receipt are skipped — they never claimed a provable citation.
    pub fn kg_verify_receipts(&self) -> Result<Vec<ReceiptStatus>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, source_drawer_id, source_fp, receipt_tag
             FROM kg_triples WHERE receipt_tag IS NOT NULL ORDER BY seq",
        )?;
        // (triple id, cited drawer id, source fingerprint, receipt tag)
        type ReceiptRow = (String, Option<String>, Option<Vec<u8>>, Vec<u8>);
        let rows: Vec<ReceiptRow> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, drawer_id, fp, receipt_tag) in rows {
            // A receipt_tag is only ever written alongside both fields.
            let (Some(drawer_id), Some(fp)) = (drawer_id, fp) else {
                out.push(ReceiptStatus {
                    triple_id: id,
                    source_drawer_id: String::new(),
                    verdict: ReceiptVerdict::Tampered,
                });
                continue;
            };
            let verdict = if self
                .vault
                .verify_tag(&receipt_canonical(&id, &drawer_id, &fp), &receipt_tag)
                .is_err()
            {
                ReceiptVerdict::Tampered
            } else {
                match self.get(&drawer_id)? {
                    None => ReceiptVerdict::Dangling,
                    Some(d) if content_fp(&d.content) == fp => ReceiptVerdict::Verified,
                    Some(_) => ReceiptVerdict::SourceChanged,
                }
            };
            out.push(ReceiptStatus {
                triple_id: id,
                source_drawer_id: drawer_id,
                verdict,
            });
        }
        Ok(out)
    }

    fn decode_triple(&self, row: TripleRow) -> Result<Triple, StoreError> {
        self.vault
            .verify_tag(&row.canonical(), &row.tag)
            .map_err(|_| {
                undercroft_obs::hmac_verify_failed("kg");
                undercroft_obs::event_hmac_fail(self.vault.id(), "kg");
                StoreError::Integrity(format!("kg/{}", row.id))
            })?;
        let object = self
            .vault
            .content_from_rest(&format!("kg/{}", row.id), &row.object)
            .map_err(|e| StoreError::CorruptRow {
                id: row.id.clone(),
                reason: e.to_string(),
            })?;
        // Absent support stays absent: `Unevaluated` is a real state and must
        // not be quietly rendered as "checked, found nothing".
        let support = row
            .support
            .as_deref()
            .map(|sealed| {
                self.vault
                    .content_from_rest(&format!("kg/{}/support", row.id), sealed)
                    .map_err(|e| StoreError::CorruptRow {
                        id: row.id.clone(),
                        reason: e.to_string(),
                    })
                    .map(|bytes| serde_json::from_slice(&bytes).unwrap_or_default())
            })
            .transpose()?;
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
            support,
        })
    }

    fn all_triples(&self) -> Result<Vec<Triple>, StoreError> {
        let sql = format!("SELECT {TRIPLE_COLUMNS} FROM kg_triples ORDER BY seq");
        let mut stmt = self.conn.prepare(&sql)?;
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
            // Closing a validity window does not re-evaluate grounding, so
            // the sealed support is re-sealed byte-for-byte from what the
            // fact already carried. Recomputing the tag without it would
            // report tampering on every grounded fact that was superseded.
            let support_rest = t.support.as_ref().map(|s| {
                self.vault.content_at_rest(
                    &format!("kg/{}/support", t.id),
                    &serde_json::to_vec(s).unwrap_or_default(),
                )
            });
            let tag = self.vault.tag(&triple_canonical(
                &t.id,
                &t.subject,
                &t.predicate,
                &object_rest,
                &t.valid_from,
                &vt,
                t.confidence,
                support_rest.as_deref(),
            ));
            let tx = self.conn.transaction()?;
            tx.execute(
                "UPDATE kg_triples SET object = ?1, valid_to = ?2, tag = ?3, support = ?4
                 WHERE id = ?5",
                params![object_rest, ended, tag.as_slice(), support_rest, t.id],
            )?;
            let (head, writes) = chain_append(
                &tx,
                &self.vault,
                &format!("kg/{}", t.id),
                &tag,
                &now_rfc3339(),
            )?;
            tx.commit()?;
            self.vault.anchor_manifest(&head, writes)?;
            undercroft_obs::kg_write(undercroft_obs::KgKind::Supersede);
            undercroft_obs::event_kg_triple(self.vault.id());
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

    /// Paged entity summaries `(name, etype, created_at)`, tag-verified on
    /// the way out like every other read.
    pub fn kg_entities(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<(String, String, String)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, etype, tag, created_at FROM kg_entities \
             ORDER BY name LIMIT ?1 OFFSET ?2",
        )?;
        let rows: Vec<(String, String, String, Vec<u8>, String)> = stmt
            .query_map(params![limit as i64, offset as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, name, etype, tag, created) in rows {
            let canonical = format!("{id}\x1f{name}\x1f{etype}\x1f{created}");
            self.vault
                .verify_tag(canonical.as_bytes(), &tag)
                .map_err(|_| StoreError::Integrity(id.clone()))?;
            out.push((name, etype, created));
        }
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
        let sql = format!("SELECT {TRIPLE_COLUMNS} FROM kg_triples ORDER BY seq");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: Vec<TripleRow> = stmt
            .query_map([], TripleRow::from_row)?
            .collect::<Result<_, _>>()?;
        for row in rows {
            if self.vault.verify_tag(&row.canonical(), &row.tag).is_err() {
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
    /// Sealed grounding evaluation, or `None` when the check never ran.
    /// Every path that recomputes the tag must carry this through unchanged
    /// — it is inside the canonical bytes, so dropping it invalidates a
    /// grounded fact's tag and reports tampering where there was none.
    support: Option<Vec<u8>>,
}

/// Columns every triple read needs, in the order `TripleRow::from_row`
/// expects. Kept in one place so a new column cannot reach one query and
/// miss another — the failure mode there is a false tamper alarm.
const TRIPLE_COLUMNS: &str = "id, subject, predicate, object, valid_from, valid_to, confidence, \
                              source_drawer_id, tag, extracted_at, support";

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
            support: r.get(10)?,
        })
    }

    /// Canonical bytes for this row, support included when present.
    fn canonical(&self) -> Vec<u8> {
        triple_canonical(
            &self.id,
            &self.subject,
            &self.predicate,
            &self.object,
            &self.valid_from,
            &self.valid_to,
            self.confidence,
            self.support.as_deref(),
        )
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
    use super::ReceiptVerdict;
    use crate::{PalaceStore, SearchOptions};
    use undercroft_vault::{SecurityLevel, VaultManager};
    use tempfile::TempDir;

    fn store(level: SecurityLevel) -> (TempDir, PalaceStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("kg-test", level).unwrap();
        (dir, PalaceStore::open(vault).unwrap())
    }

    // ---- grounding: where a fact rests ----------------------------------

    const NOTE: &str = "Ana works as a radiologist at St. Mary's hospital in Leeds.";

    fn grounded(s: &mut PalaceStore, predicate: &str, object: &str, quote: Option<&str>) -> String {
        let support = undercroft_core::support::Support::evaluate(
            NOTE,
            quote.map(|q| [q]).unwrap_or_default().as_slice(),
        );
        s.kg_add_grounded(
            "ana",
            predicate,
            object,
            None,
            None,
            0.8,
            ("drawer-1", NOTE),
            Some(&support),
        )
        .unwrap()
    }

    /// The three states have to survive a round trip through sealing and the
    /// tamper tag, because that is where the distinction actually lives.
    #[test]
    fn grounding_survives_a_round_trip() {
        use undercroft_core::support::Grounding;
        let (_d, mut s) = store(SecurityLevel::Sealed);
        grounded(
            &mut s,
            "works_as",
            "radiologist",
            Some("works as a radiologist"),
        );
        grounded(
            &mut s,
            "located_in",
            "United Kingdom",
            Some("United Kingdom"),
        );
        // No grounding evaluation at all — the pre-grounding write path.
        s.kg_add("ana", "knows", "bob", None, None, 1.0, None)
            .unwrap();

        let facts = s.kg_query_entity("ana", None, "outgoing").unwrap();
        let by = |p: &str| facts.iter().find(|t| t.predicate == p).unwrap().grounding();

        assert_eq!(by("works_as"), Grounding::Stated, "the note says it");
        assert_eq!(
            by("located_in"),
            Grounding::Background,
            "checked, and the note does not contain 'United Kingdom'"
        );
        assert_eq!(
            by("knows"),
            Grounding::Unevaluated,
            "never checked — must not read as Background"
        );
    }

    #[test]
    fn a_stated_fact_records_where_in_the_note_it_came_from() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        grounded(
            &mut s,
            "works_as",
            "radiologist",
            Some("works as a radiologist"),
        );
        let facts = s.kg_query_entity("ana", None, "outgoing").unwrap();
        let spans = &facts[0].support.as_ref().unwrap().spans;
        assert_eq!(spans.len(), 1);
        let (o, l) = (spans[0].offset as usize, spans[0].len as usize);
        assert_eq!(&NOTE[o..o + l], "works as a radiologist");
    }

    /// Support is inside the triple's canonical bytes, so every path that
    /// recomputes a tag has to carry it. `verify` is where a miss shows up —
    /// as a tamper alarm on a fact nobody touched.
    #[test]
    fn grounded_facts_pass_verification() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        grounded(
            &mut s,
            "works_as",
            "radiologist",
            Some("works as a radiologist"),
        );
        grounded(&mut s, "located_in", "United Kingdom", None);
        s.kg_add("ana", "knows", "bob", None, None, 1.0, None)
            .unwrap();
        assert!(
            s.kg_verify().unwrap().is_empty(),
            "no fact was tampered with"
        );
    }

    /// Closing a validity window re-tags the row. It must re-seal the
    /// grounding it already had rather than dropping it.
    #[test]
    fn superseding_a_grounded_fact_keeps_its_grounding_and_its_tag() {
        use undercroft_core::support::Grounding;
        let (_d, mut s) = store(SecurityLevel::Sealed);
        grounded(
            &mut s,
            "works_as",
            "radiologist",
            Some("works as a radiologist"),
        );
        s.kg_supersede("ana", "works_as", "consultant", Some("2024-06-01"))
            .unwrap();
        assert!(
            s.kg_verify().unwrap().is_empty(),
            "superseding must not look like tampering"
        );
        let closed = s
            .kg_timeline(Some("ana"))
            .unwrap()
            .into_iter()
            .find(|t| t.object == "radiologist")
            .unwrap();
        assert_eq!(
            closed.grounding(),
            Grounding::Stated,
            "the closed fact still rests on the words it always did"
        );
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

    fn src_drawer(content: &str) -> undercroft_core::Drawer {
        undercroft_core::Drawer::new("w", "r", content.into(), Some("t.md".into()), 0, "t")
    }

    #[test]
    fn receipt_verifies_then_flags_source_change() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let src = src_drawer("Ada migrated auth to PASETO in June.");
        let src_id = src.id.clone();
        s.upsert(&src).unwrap();
        let tid = s
            .kg_add_receipted(
                "ada",
                "migrated_auth_to",
                "paseto",
                None,
                None,
                0.8,
                (&src_id, &src.content),
            )
            .unwrap();

        let r = s.kg_verify_receipts().unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].triple_id, tid);
        assert_eq!(r[0].source_drawer_id, src_id);
        assert_eq!(r[0].verdict, ReceiptVerdict::Verified);

        // Edit the cited source in place (same recipe → same id, new words):
        // the receipt must surface that the fact's source moved under it.
        s.upsert(&src_drawer("Ada decided to keep JWT after all."))
            .unwrap();
        let r = s.kg_verify_receipts().unwrap();
        assert_eq!(r[0].verdict, ReceiptVerdict::SourceChanged);
    }

    #[test]
    fn receipt_dangling_when_source_absent() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.kg_add_receipted("x", "rel", "y", None, None, 0.8, ("no-such-drawer", "text"))
            .unwrap();
        let r = s.kg_verify_receipts().unwrap();
        assert_eq!(r[0].verdict, ReceiptVerdict::Dangling);
    }

    #[test]
    fn plain_facts_carry_no_receipt() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let src = src_drawer("some verbatim source");
        s.upsert(&src).unwrap();
        s.kg_add("a", "rel", "b", None, None, 1.0, Some(&src.id))
            .unwrap();
        s.kg_add_receipted("c", "rel", "d", None, None, 0.8, (&src.id, &src.content))
            .unwrap();
        // Only the receipted fact is verified; the plain citation (stored
        // but not tamper-covered) is not treated as a receipt.
        let r = s.kg_verify_receipts().unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].verdict, ReceiptVerdict::Verified);
    }

    #[test]
    fn receipt_tamper_is_detected() {
        let (dir, mut s) = store(SecurityLevel::Sealed);
        let src = src_drawer("source words for the receipt");
        let src_id = src.id.clone();
        s.upsert(&src).unwrap();
        s.kg_add_receipted("a", "rel", "b", None, None, 0.8, (&src_id, &src.content))
            .unwrap();
        drop(s);

        // Offline attacker rewrites the citation binding.
        let db = rusqlite::Connection::open(dir.path().join("vaults/kg-test/palace.db")).unwrap();
        db.execute(
            "UPDATE kg_triples SET receipt_tag = X'0011' WHERE receipt_tag IS NOT NULL",
            [],
        )
        .unwrap();
        drop(db);

        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let s2 = PalaceStore::open(mgr.unlock("kg-test").unwrap()).unwrap();
        let r = s2.kg_verify_receipts().unwrap();
        assert_eq!(r[0].verdict, ReceiptVerdict::Tampered);
    }
}
