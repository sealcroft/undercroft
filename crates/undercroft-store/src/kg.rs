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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    /// The authority tier, all three DECLARED and HMAC-covered — never
    /// inferred. `None` throughout means the fact was never placed on the
    /// tier (the default for every extracted or added fact, semantically
    /// `stated`/`unreviewed`). See [`PalaceStore::kg_set_authority`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_state: Option<String>,
    /// The exact-lookup slot [`PalaceStore::lookup_canonical`] answers by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_key: Option<String>,
    /// Which model/agent extracted this fact — the embedder-identity
    /// pattern one level up, DECLARED by the write path and HMAC-covered.
    /// `None` means never recorded: every fact written before the field
    /// existed, and every manual add.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extractor: Option<String>,
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
    authority: Option<&[u8]>,
    extractor: Option<&[u8]>,
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
    // The authority tier rides the same precedent — and under a DIFFERENT
    // separator (0x1e), so sealed support bytes and an authority extension
    // can never alias each other's position in the canonical.
    if let Some(auth) = authority {
        out.push(0x1e);
        out.extend_from_slice(auth);
    }
    // Extractor identity takes the third separator (0x1d) under the same
    // rule: a fact that never recorded its extractor keeps byte-identical
    // canonical bytes, and no extension can alias another's position.
    if let Some(ext) = extractor {
        out.push(0x1d);
        out.extend_from_slice(ext);
    }
    out
}

/// Canonical bytes of the extractor identity, or `None` when none was ever
/// recorded — the `support`/authority precedent, so facts written before
/// extractor identity existed are never re-tagged.
///
/// Inside the fact's HMAC on purpose: which model claimed a fact is
/// provenance an offline attacker must not be able to rewrite — a flipped
/// column fails `verify_tag` on read, exactly like a flipped
/// `review_state`.
pub(crate) fn extractor_ext(extractor: Option<&str>) -> Option<Vec<u8>> {
    extractor.map(|e| {
        let mut out = vec![0x1f];
        out.extend_from_slice(e.as_bytes());
        out
    })
}

/// Canonical bytes of the authority tier, or `None` when no field was ever
/// declared — a fact never placed on the tier keeps its canonical bytes
/// unchanged to the byte (the `support` precedent), so nothing written
/// before the tier existed is re-tagged.
///
/// The three fields are inside the fact's HMAC on purpose: an offline
/// attacker must not be able to promote poison to `approved`/`canonical`
/// by flipping a column — a flipped row fails `verify_tag` on read.
pub(crate) fn authority_ext(
    authority_class: Option<&str>,
    review_state: Option<&str>,
    canonical_key: Option<&str>,
) -> Option<Vec<u8>> {
    if authority_class.is_none() && review_state.is_none() && canonical_key.is_none() {
        return None;
    }
    let mut out = Vec::new();
    for part in [
        authority_class.unwrap_or(""),
        review_state.unwrap_or(""),
        canonical_key.unwrap_or(""),
    ] {
        out.push(0x1f);
        out.extend_from_slice(part.as_bytes());
    }
    Some(out)
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
    /// The link was declared but never bound: the cited drawer was absent
    /// when the link was written (an out-of-order import), so there is no
    /// receipt to check. Only drawer supersessions produce this — a KG
    /// receipt is always written with its fact.
    Unreceipted,
}

/// A fact's receipt and its verification outcome.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReceiptStatus {
    pub triple_id: String,
    pub source_drawer_id: String,
    pub verdict: ReceiptVerdict,
}

/// A drawer's supersession link and its verification outcome — the drawer
/// analogue of [`ReceiptStatus`], produced by
/// [`PalaceStore::verify_supersessions`](crate::PalaceStore).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SupersessionStatus {
    pub drawer_id: String,
    pub supersedes: String,
    pub verdict: ReceiptVerdict,
}

/// One exported fact: the decoded, verified triple plus its receipt's
/// unkeyed source fingerprint (hex) when the fact was receipted — enough
/// for an importing vault to re-key the receipt under its own mac without
/// ever seeing the source content (the rotation precedent, across vaults).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TripleExport {
    pub triple: Triple,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_fp: Option<String>,
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
                 support     BLOB,
                 -- The authority tier: DECLARED closed-vocabulary fields,
                 -- HMAC-covered via the canonical's authority extension.
                 -- NULL throughout = never placed on the tier (stated /
                 -- unreviewed by default). canonical_key is queryable
                 -- structure like subject/predicate — the same sealed-vault
                 -- trade the file header records.
                 authority_class TEXT,
                 review_state    TEXT,
                 canonical_key   TEXT,
                 -- Which model/agent extracted the fact (the embedder-identity
                 -- pattern, one level up). DECLARED by the write path, inside
                 -- the fact's HMAC via the canonical's extractor extension.
                 -- NULL = never recorded (every fact written before the field
                 -- existed, and every manual add).
                 extractor       TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_kg_triples_subject ON kg_triples(subject);
             CREATE INDEX IF NOT EXISTS idx_kg_triples_predicate ON kg_triples(predicate);",
        )?;
        // Migrate palaces created before the receipt columns existed. SQLite
        // has no ADD COLUMN IF NOT EXISTS; a duplicate-column error just
        // means the migration already ran, so it is swallowed.
        for col in [
            "source_fp BLOB",
            "receipt_tag BLOB",
            "support BLOB",
            "authority_class TEXT",
            "review_state TEXT",
            "canonical_key TEXT",
            "extractor TEXT",
        ] {
            let _ = self
                .conn
                .execute(&format!("ALTER TABLE kg_triples ADD COLUMN {col}"), []);
        }
        // After the columns exist (fresh table or migration): the exact-
        // authority door is an INDEXED equality — `lookup_canonical` must
        // never ride an O(graph) `all_triples` decode.
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_kg_triples_canonical ON kg_triples(canonical_key)",
            [],
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
        extractor: Option<&str>,
    ) -> Result<String, StoreError> {
        self.kg_add_grounded(
            subject, predicate, object, valid_from, valid_to, confidence, source, None, extractor,
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
        extractor: Option<&str>,
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
            extractor,
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
        extractor: Option<&str>,
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
        let ext = extractor_ext(extractor);
        let tag = self.vault.tag(&triple_canonical(
            &id,
            subject,
            predicate,
            &object_rest,
            &vf,
            &vt,
            confidence,
            support_rest.as_deref(),
            // A new fact is never born on the authority tier: placement is
            // a separate, audited declaration (`kg_set_authority`).
            None,
            ext.as_deref(),
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
                                     source_fp, receipt_tag, support, extractor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(id) DO UPDATE SET
                 object = excluded.object,
                 valid_to = excluded.valid_to,
                 confidence = excluded.confidence,
                 source_drawer_id = excluded.source_drawer_id,
                 tag = excluded.tag,
                 source_fp = excluded.source_fp,
                 receipt_tag = excluded.receipt_tag,
                 support = excluded.support,
                 extractor = excluded.extractor",
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
                extractor,
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

    /// Every fact, decoded and tag-verified, paired with its receipt's
    /// unkeyed source fingerprint (hex) where one exists — the export half
    /// of closing the meta-rows gap. The fingerprint travels so the
    /// importing vault can re-key the receipt under its own mac without
    /// ever seeing the source content (exactly what rotation does).
    pub fn kg_export(&self) -> Result<Vec<TripleExport>, StoreError> {
        let sql =
            format!("SELECT {TRIPLE_COLUMNS}, source_fp, receipt_tag FROM kg_triples ORDER BY seq");
        let mut stmt = self.conn.prepare(&sql)?;
        // (row, source fingerprint, receipt tag)
        type ExportRow = (TripleRow, Option<Vec<u8>>, Option<Vec<u8>>);
        let rows: Vec<ExportRow> = stmt
            .query_map([], |r| {
                Ok((TripleRow::from_row(r)?, r.get(15)?, r.get(16)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (row, fp, receipt) in rows {
            let triple = self.decode_triple(row)?;
            out.push(TripleExport {
                triple,
                // The fingerprint is receipt material: exported only when
                // a receipt exists to re-key at the destination.
                source_fp: receipt.and(fp).map(hex::encode),
            });
        }
        Ok(out)
    }

    /// Entity rows for export: `(name, etype)`, tag-verified.
    pub fn kg_export_entities(&self) -> Result<Vec<(String, String)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, etype, tag, created_at FROM kg_entities ORDER BY name")?;
        let rows: Vec<(String, String, String, Vec<u8>, String)> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, name, etype, tag, created) in rows {
            let canonical = format!("{id}\x1f{name}\x1f{etype}\x1f{created}");
            self.vault
                .verify_tag(canonical.as_bytes(), &tag)
                .map_err(|_| StoreError::Integrity(id.clone()))?;
            out.push((name, etype));
        }
        Ok(out)
    }

    /// Import one exported fact into this vault: re-sealed under this
    /// vault's keys, re-tagged with every extension the fact carries
    /// (support, authority, extractor), the receipt re-keyed from the
    /// traveling fingerprint. History imports as history — a closed fact
    /// stays closed. Idempotent by fact id.
    pub fn kg_import(&mut self, exp: &TripleExport) -> Result<String, StoreError> {
        let t = &exp.triple;
        undercroft_core::validate_name(&t.subject, "subject").map_err(|e| {
            StoreError::CorruptRow {
                id: t.subject.clone(),
                reason: e.to_string(),
            }
        })?;
        undercroft_core::validate_name(&t.predicate, "predicate").map_err(|e| {
            StoreError::CorruptRow {
                id: t.predicate.clone(),
                reason: e.to_string(),
            }
        })?;
        self.ensure_entity(&t.subject)?;
        // The id is re-derived, never trusted from the wire: the same
        // deterministic recipe every locally-written fact gets.
        let id = triple_id(&t.subject, &t.predicate, &t.object, t.valid_from.as_deref());
        let object_rest = self
            .vault
            .content_at_rest(&format!("kg/{id}"), t.object.as_bytes());
        let support_rest = t
            .support
            .as_ref()
            .map(|s| serde_json::to_vec(s).unwrap_or_default())
            .map(|bytes| {
                self.vault
                    .content_at_rest(&format!("kg/{id}/support"), &bytes)
            });
        let auth = authority_ext(
            t.authority_class.as_deref(),
            t.review_state.as_deref(),
            t.canonical_key.as_deref(),
        );
        let ext = extractor_ext(t.extractor.as_deref());
        let tag = self.vault.tag(&triple_canonical(
            &id,
            &t.subject,
            &t.predicate,
            &object_rest,
            &t.valid_from,
            &t.valid_to,
            t.confidence,
            support_rest.as_deref(),
            auth.as_deref(),
            ext.as_deref(),
        ));
        let source_fp = exp
            .source_fp
            .as_deref()
            .map(hex::decode)
            .transpose()
            .map_err(|e| StoreError::CorruptRow {
                id: id.clone(),
                reason: format!("source_fp is not hex: {e}"),
            })?;
        let receipt_tag = source_fp
            .as_ref()
            .zip(t.source_drawer_id.as_deref())
            .map(|(fp, did)| self.vault.tag(&receipt_canonical(&id, did, fp)));
        let now = now_rfc3339();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO kg_triples (id, subject, predicate, object, valid_from, valid_to,
                                     confidence, source_drawer_id, tag, extracted_at,
                                     source_fp, receipt_tag, support,
                                     authority_class, review_state, canonical_key, extractor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(id) DO UPDATE SET
                 object = excluded.object,
                 valid_to = excluded.valid_to,
                 confidence = excluded.confidence,
                 source_drawer_id = excluded.source_drawer_id,
                 tag = excluded.tag,
                 source_fp = excluded.source_fp,
                 receipt_tag = excluded.receipt_tag,
                 support = excluded.support,
                 authority_class = excluded.authority_class,
                 review_state = excluded.review_state,
                 canonical_key = excluded.canonical_key,
                 extractor = excluded.extractor",
            params![
                id,
                t.subject,
                t.predicate,
                object_rest,
                t.valid_from,
                t.valid_to,
                t.confidence,
                t.source_drawer_id,
                tag.as_slice(),
                // extracted_at is provenance from the source vault, kept.
                t.extracted_at,
                source_fp,
                receipt_tag.as_ref().map(|r| r.as_slice()),
                support_rest.as_deref(),
                t.authority_class,
                t.review_state,
                t.canonical_key,
                t.extractor,
            ],
        )?;
        let (head, writes) = chain_append(&tx, &self.vault, &format!("kg/{id}"), &tag, &now)?;
        tx.commit()?;
        self.vault.anchor_manifest(&head, writes)?;
        undercroft_obs::kg_write(undercroft_obs::KgKind::Triple);
        undercroft_obs::event_kg_triple(self.vault.id());
        Ok(id)
    }

    /// Import one entity row: created when absent, and an `unknown` etype
    /// is refined by the imported one; a more specific local etype is
    /// never overwritten by an import.
    pub fn kg_import_entity(&mut self, name: &str, etype: &str) -> Result<(), StoreError> {
        undercroft_core::validate_name(name, "entity").map_err(|e| StoreError::CorruptRow {
            id: name.into(),
            reason: e.to_string(),
        })?;
        self.ensure_entity(name)?;
        if etype == "unknown" {
            return Ok(());
        }
        let existing: Option<(String, String, String)> = self
            .conn
            .query_row(
                "SELECT id, etype, created_at FROM kg_entities WHERE name = ?1",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((id, cur, created)) = existing {
            if cur == "unknown" {
                let canonical = format!("{id}\x1f{name}\x1f{etype}\x1f{created}");
                let tag = self.vault.tag(canonical.as_bytes());
                self.conn.execute(
                    "UPDATE kg_entities SET etype = ?1, tag = ?2 WHERE id = ?3",
                    params![etype, tag.as_slice(), id],
                )?;
            }
        }
        Ok(())
    }

    /// One triple's raw row by id, tag NOT yet verified.
    fn triple_row(&self, triple_id: &str) -> Result<Option<TripleRow>, StoreError> {
        let sql = format!("SELECT {TRIPLE_COLUMNS} FROM kg_triples WHERE id = ?1");
        Ok(self
            .conn
            .prepare(&sql)?
            .query_row(params![triple_id], TripleRow::from_row)
            .optional()?)
    }

    /// Place a fact on the authority tier — or take it off. Everything here
    /// is a DECLARATION: a closed vocabulary, validated, audited through
    /// the chain, and covered by the fact's HMAC — never an inference.
    ///
    /// `authority_class` is `stated` or `canonical`; `review_state` is
    /// `unreviewed`, `approved` or `rejected`. `canonical_key` names the
    /// exact-lookup slot [`Self::lookup_canonical`] answers by — required
    /// for `canonical`, forbidden for `stated`. The key is queryable
    /// structure in the clear (the subject/predicate trade recorded in the
    /// file header): name it like an identifier, never with content words
    /// that should stay sealed.
    ///
    /// Promoting an approved canonical fact onto a key another active
    /// approved canonical fact already holds CLOSES the older fact's
    /// validity window in the same call — audited like any supersession —
    /// so the door answers with at most one current value per key.
    ///
    /// The row's existing tag is verified before anything is rewritten:
    /// this operation must never launder a tampered row into a freshly
    /// tagged one.
    pub fn kg_set_authority(
        &mut self,
        triple_id: &str,
        authority_class: &str,
        review_state: &str,
        canonical_key: Option<&str>,
    ) -> Result<(), StoreError> {
        // `Invalid`, not `CorruptRow` — the same rule the write choke point
        // states: a value the closed vocabulary does not contain, or an id
        // that names no fact, is the CALLER's error. `CorruptRow` reads as
        // "corrupt row <id>: …" and maps to HTTP 500, so a typo'd
        // `authority_class` told an operator their knowledge graph was
        // broken (and a client library that retries 5xx retried a request
        // that can never succeed) instead of returning 400.
        let bad = |reason: String| StoreError::Invalid(format!("fact {triple_id}: {reason}"));
        if !matches!(authority_class, "stated" | "canonical") {
            return Err(bad(format!(
                "authority_class must be stated|canonical, got {authority_class:?}"
            )));
        }
        if !matches!(review_state, "unreviewed" | "approved" | "rejected") {
            return Err(bad(format!(
                "review_state must be unreviewed|approved|rejected, got {review_state:?}"
            )));
        }
        match (authority_class, canonical_key) {
            ("canonical", None) => {
                return Err(bad("canonical requires a canonical_key".into()));
            }
            ("stated", Some(_)) => {
                return Err(bad("a stated fact carries no canonical_key".into()));
            }
            _ => {}
        }
        if let Some(k) = canonical_key {
            undercroft_core::validate_name(k, "canonical_key").map_err(|e| bad(e.to_string()))?;
        }
        let row = self
            .triple_row(triple_id)?
            .ok_or_else(|| bad("no such fact".into()))?;
        self.vault
            .verify_tag(&row.canonical(), &row.tag)
            .map_err(|_| StoreError::Integrity(format!("kg/{triple_id}")))?;

        // The one-current-value-per-key guarantee: close every OTHER active
        // approved canonical fact on this key first (per-row transactions,
        // the kg_invalidate shape — promotions are rare and each close is
        // its own audited event).
        if authority_class == "canonical" && review_state == "approved" {
            let key = canonical_key.expect("checked above");
            let sql = format!(
                "SELECT {TRIPLE_COLUMNS} FROM kg_triples \
                 WHERE canonical_key = ?1 AND authority_class = 'canonical' \
                   AND review_state = 'approved' AND valid_to IS NULL AND id != ?2"
            );
            let holders: Vec<TripleRow> = self
                .conn
                .prepare(&sql)?
                .query_map(params![key, triple_id], TripleRow::from_row)?
                .collect::<Result<_, _>>()?;
            for held in holders {
                self.vault
                    .verify_tag(&held.canonical(), &held.tag)
                    .map_err(|_| StoreError::Integrity(format!("kg/{}", held.id)))?;
                let ended = now_rfc3339();
                let vt = Some(ended.clone());
                let auth = authority_ext(
                    held.authority_class.as_deref(),
                    held.review_state.as_deref(),
                    held.canonical_key.as_deref(),
                );
                let ext = extractor_ext(held.extractor.as_deref());
                let tag = self.vault.tag(&triple_canonical(
                    &held.id,
                    &held.subject,
                    &held.predicate,
                    &held.object,
                    &held.valid_from,
                    &vt,
                    held.confidence,
                    held.support.as_deref(),
                    auth.as_deref(),
                    ext.as_deref(),
                ));
                let tx = self.conn.transaction()?;
                tx.execute(
                    "UPDATE kg_triples SET valid_to = ?1, tag = ?2 WHERE id = ?3",
                    params![ended, tag.as_slice(), held.id],
                )?;
                let (head, writes) =
                    chain_append(&tx, &self.vault, &format!("kg/{}", held.id), &tag, &ended)?;
                tx.commit()?;
                self.vault.anchor_manifest(&head, writes)?;
                undercroft_obs::kg_write(undercroft_obs::KgKind::Supersede);
                undercroft_obs::event_kg_triple(self.vault.id());
            }
        }

        let auth = authority_ext(Some(authority_class), Some(review_state), canonical_key);
        let ext = extractor_ext(row.extractor.as_deref());
        let tag = self.vault.tag(&triple_canonical(
            &row.id,
            &row.subject,
            &row.predicate,
            &row.object,
            &row.valid_from,
            &row.valid_to,
            row.confidence,
            row.support.as_deref(),
            auth.as_deref(),
            ext.as_deref(),
        ));
        let now = now_rfc3339();
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE kg_triples SET authority_class = ?1, review_state = ?2, \
                                   canonical_key = ?3, tag = ?4 WHERE id = ?5",
            params![
                authority_class,
                review_state,
                canonical_key,
                tag.as_slice(),
                triple_id
            ],
        )?;
        let (head, writes) = chain_append(
            &tx,
            &self.vault,
            &format!("kg/{triple_id}/authority"),
            &tag,
            &now,
        )?;
        tx.commit()?;
        self.vault.anchor_manifest(&head, writes)?;
        undercroft_obs::kg_write(undercroft_obs::KgKind::Triple);
        undercroft_obs::event_kg_triple(self.vault.id());
        Ok(())
    }

    /// The exact-authority door: an INDEXED SQL equality on
    /// `canonical_key`, returning the one active, approved, canonical fact
    /// for the key — or nothing, never a semantic guess. Consulted before
    /// semantic recall for exact or high-risk asks. Deliberately not a
    /// rider on `all_triples`, whose full decode is O(graph); this path
    /// touches exactly the rows the index names, and no candidate pool of
    /// any kind is involved — which is what makes it immune to every
    /// crowding and starvation shape the retrieval side has to defend
    /// against.
    pub fn lookup_canonical(&self, key: &str) -> Result<Option<Triple>, StoreError> {
        let sql = format!(
            "SELECT {TRIPLE_COLUMNS} FROM kg_triples \
             WHERE canonical_key = ?1 AND authority_class = 'canonical' \
               AND review_state = 'approved' AND valid_to IS NULL \
             ORDER BY extracted_at DESC, seq DESC LIMIT 1"
        );
        let row = self
            .conn
            .prepare(&sql)?
            .query_row(params![key], TripleRow::from_row)
            .optional()?;
        row.map(|r| self.decode_triple(r)).transpose()
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
            authority_class: row.authority_class,
            review_state: row.review_state,
            canonical_key: row.canonical_key,
            extractor: row.extractor,
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
            // Authority fields ride through unchanged, exactly like support:
            // closing a window is not a review, and dropping them from the
            // tag would report tampering on every promoted fact superseded.
            let auth = authority_ext(
                t.authority_class.as_deref(),
                t.review_state.as_deref(),
                t.canonical_key.as_deref(),
            );
            let ext = extractor_ext(t.extractor.as_deref());
            let tag = self.vault.tag(&triple_canonical(
                &t.id,
                &t.subject,
                &t.predicate,
                &object_rest,
                &t.valid_from,
                &vt,
                t.confidence,
                support_rest.as_deref(),
                auth.as_deref(),
                ext.as_deref(),
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
    /// Authority tier fields — inside the canonical (via the authority
    /// extension) whenever any is set, so they carry the same warning as
    /// `support`: drop them from a re-tag and every promoted fact reads as
    /// tampered.
    authority_class: Option<String>,
    review_state: Option<String>,
    canonical_key: Option<String>,
    /// Extractor identity — inside the canonical (via the extractor
    /// extension) whenever set, same warning as `support`: drop it from a
    /// re-tag and every attributed fact reads as tampered.
    extractor: Option<String>,
}

/// Columns every triple read needs, in the order `TripleRow::from_row`
/// expects. Kept in one place so a new column cannot reach one query and
/// miss another — the failure mode there is a false tamper alarm.
const TRIPLE_COLUMNS: &str = "id, subject, predicate, object, valid_from, valid_to, confidence, \
                              source_drawer_id, tag, extracted_at, support, \
                              authority_class, review_state, canonical_key, extractor";

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
            authority_class: r.get(11)?,
            review_state: r.get(12)?,
            canonical_key: r.get(13)?,
            extractor: r.get(14)?,
        })
    }

    /// Canonical bytes for this row, support and authority included when
    /// present.
    fn canonical(&self) -> Vec<u8> {
        let auth = authority_ext(
            self.authority_class.as_deref(),
            self.review_state.as_deref(),
            self.canonical_key.as_deref(),
        );
        let ext = extractor_ext(self.extractor.as_deref());
        triple_canonical(
            &self.id,
            &self.subject,
            &self.predicate,
            &self.object,
            &self.valid_from,
            &self.valid_to,
            self.confidence,
            self.support.as_deref(),
            auth.as_deref(),
            ext.as_deref(),
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
    use crate::{PalaceStore, SearchOptions, StoreError};
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
            None,
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
                None,
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
        s.kg_add_receipted(
            "x",
            "rel",
            "y",
            None,
            None,
            0.8,
            ("no-such-drawer", "text"),
            None,
        )
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
        s.kg_add_receipted(
            "c",
            "rel",
            "d",
            None,
            None,
            0.8,
            (&src.id, &src.content),
            None,
        )
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
        s.kg_add_receipted(
            "a",
            "rel",
            "b",
            None,
            None,
            0.8,
            (&src_id, &src.content),
            None,
        )
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

    #[test]
    fn the_authority_door_answers_by_key_and_only_when_approved() {
        for level in [SecurityLevel::HmacOnly, SecurityLevel::Sealed] {
            let (_d, mut s) = store(level);
            let id = s
                .kg_add("user", "timezone", "Europe/Berlin", None, None, 1.0, None)
                .unwrap();
            // Not on the tier: the door answers nothing.
            assert!(s.lookup_canonical("user-timezone").unwrap().is_none());
            // Promoted but unreviewed: still nothing — approval is its own
            // declaration, made by whoever reviews, not by whoever promotes.
            s.kg_set_authority(&id, "canonical", "unreviewed", Some("user-timezone"))
                .unwrap();
            assert!(s.lookup_canonical("user-timezone").unwrap().is_none());
            s.kg_set_authority(&id, "canonical", "approved", Some("user-timezone"))
                .unwrap();
            let hit = s
                .lookup_canonical("user-timezone")
                .unwrap()
                .expect("the door answers an approved canonical fact");
            assert_eq!(hit.object, "Europe/Berlin");
            assert_eq!(hit.canonical_key.as_deref(), Some("user-timezone"));
            // Rejected: the door closes again — and every row still
            // verifies, because the state change was re-tagged, not flipped.
            s.kg_set_authority(&id, "canonical", "rejected", Some("user-timezone"))
                .unwrap();
            assert!(s.lookup_canonical("user-timezone").unwrap().is_none());
            assert!(s.kg_verify().unwrap().is_empty());
        }
    }

    #[test]
    fn promotion_supersedes_the_previous_holder_of_the_key() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let old = s
            .kg_add("user", "editor", "vim", None, None, 1.0, None)
            .unwrap();
        s.kg_set_authority(&old, "canonical", "approved", Some("user-editor"))
            .unwrap();
        let new = s
            .kg_add("user", "editor", "helix", None, None, 1.0, None)
            .unwrap();
        s.kg_set_authority(&new, "canonical", "approved", Some("user-editor"))
            .unwrap();
        let hit = s
            .lookup_canonical("user-editor")
            .unwrap()
            .expect("the door answers");
        assert_eq!(
            hit.object, "helix",
            "the door holds one current value per key"
        );
        // The superseded holder is closed, never deleted — history replays.
        let old_fact = s
            .kg_timeline(None)
            .unwrap()
            .into_iter()
            .find(|t| t.id == old)
            .expect("history keeps the old holder");
        assert!(old_fact.valid_to.is_some());
        assert!(s.kg_verify().unwrap().is_empty());
    }

    #[test]
    fn a_flipped_review_state_fails_verification_not_the_door() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let id = s
            .kg_add(
                "service",
                "api-base",
                "internal.example",
                None,
                None,
                1.0,
                None,
            )
            .unwrap();
        s.kg_set_authority(&id, "canonical", "unreviewed", Some("service-api-base"))
            .unwrap();
        // An offline attacker without the mac key flips the column.
        s.conn
            .execute(
                "UPDATE kg_triples SET review_state = 'approved' WHERE id = ?1",
                rusqlite::params![id],
            )
            .unwrap();
        // The door refuses with an integrity error — poison cannot approve
        // itself by editing a column, because the state is inside the HMAC.
        assert!(matches!(
            s.lookup_canonical("service-api-base"),
            Err(crate::StoreError::Integrity(_))
        ));
        assert_eq!(s.kg_verify().unwrap(), vec![format!("kg/{id}")]);
    }

    /// Extractor identity: recorded on the fact, readable back, and inside
    /// the HMAC — a flipped attribution fails verification exactly like a
    /// flipped review_state. Facts that never recorded one stay verifiable
    /// (every other test in this module writes extractor-less facts).
    #[test]
    fn extractor_identity_is_recorded_and_tamper_covered() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let src = src_drawer("Ada moved the deploys to Tuesdays.");
        let src_id = src.id.clone();
        s.upsert(&src).unwrap();
        let id = s
            .kg_add_receipted(
                "ada",
                "deploys_on",
                "tuesdays",
                None,
                None,
                0.8,
                (&src_id, &src.content),
                Some("llama3.2:1b"),
            )
            .unwrap();
        let fact = s
            .kg_query_entity("ada", None, "outgoing")
            .unwrap()
            .into_iter()
            .find(|t| t.id == id)
            .expect("fact readable");
        assert_eq!(fact.extractor.as_deref(), Some("llama3.2:1b"));
        assert!(s.kg_verify().unwrap().is_empty());

        // An offline attacker rewrites the attribution — which model claimed
        // a fact is provenance, so the flip must fail verification.
        s.conn
            .execute(
                "UPDATE kg_triples SET extractor = 'gpt-x' WHERE id = ?1",
                rusqlite::params![id],
            )
            .unwrap();
        assert_eq!(s.kg_verify().unwrap(), vec![format!("kg/{id}")]);
    }

    /// The meta-rows export gap, closed and pinned: facts cross vaults
    /// with their receipts (re-keyed), grounding, authority tier,
    /// extractor identity and validity windows intact — and verify clean
    /// under the destination's keys.
    #[test]
    fn kg_export_import_roundtrip_preserves_everything() {
        let (_d1, mut src_store) = store(SecurityLevel::Sealed);
        let source = src_drawer("Ada moved the standup to 09:30 on Mondays.");
        src_store.upsert(&source).unwrap();
        let fact_id = src_store
            .kg_add_receipted(
                "ada",
                "standup_at",
                "0930-mondays",
                Some("2026-01-01"),
                None,
                0.8,
                (&source.id, &source.content),
                Some("llama3.2:1b"),
            )
            .unwrap();
        src_store
            .kg_set_authority(&fact_id, "canonical", "approved", Some("ada-standup"))
            .unwrap();
        // A closed fact: history must import as history.
        src_store
            .kg_add(
                "ada",
                "office",
                "berlin",
                Some("2024-01-01"),
                Some("2025-06-30"),
                1.0,
                None,
            )
            .unwrap();

        let facts = src_store.kg_export().unwrap();
        assert_eq!(facts.len(), 2);
        assert!(facts.iter().any(|f| f.source_fp.is_some()));
        let entities = src_store.kg_export_entities().unwrap();

        let (_d2, mut dst) = store(SecurityLevel::Sealed);
        // Drawer first (as an import stream orders it), then the graph.
        dst.upsert(&source).unwrap();
        for (name, etype) in &entities {
            dst.kg_import_entity(name, etype).unwrap();
        }
        for exp in &facts {
            dst.kg_import(exp).unwrap();
        }

        // Everything verifies under the DESTINATION's keys.
        assert!(dst.kg_verify().unwrap().is_empty());
        // The receipt re-keyed and binds against the imported drawer.
        let receipts = dst.kg_verify_receipts().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].verdict, ReceiptVerdict::Verified);
        // The authority tier crossed: the exact door answers.
        let hit = dst
            .lookup_canonical("ada-standup")
            .unwrap()
            .expect("canonical fact imported");
        assert_eq!(hit.object, "0930-mondays");
        assert_eq!(hit.extractor.as_deref(), Some("llama3.2:1b"));
        // History stayed history.
        let closed = dst
            .kg_timeline(None)
            .unwrap()
            .into_iter()
            .find(|t| t.predicate == "office")
            .expect("closed fact imported");
        assert_eq!(closed.valid_to.as_deref(), Some("2025-06-30"));
    }

    #[test]
    fn the_authority_vocabulary_is_closed() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let id = s
            .kg_add("user", "locale", "de-DE", None, None, 1.0, None)
            .unwrap();
        // Premise: the same call with in-vocabulary values succeeds, so
        // every refusal below is about the value, not about the fixture.
        s.kg_set_authority(&id, "canonical", "approved", Some("user-locale"))
            .unwrap();

        // Every refusal is `Invalid` — the CALLER's error, 400 on /v1 —
        // and names the fact. It was `CorruptRow` ("corrupt row <id>: …",
        // mapped to 500), so a typo'd vocabulary value told the operator
        // their knowledge graph was damaged and invited a client library
        // to retry a request that can never succeed.
        let refused = |r: Result<(), StoreError>, what: &str| match r {
            Err(StoreError::Invalid(msg)) => assert!(
                msg.contains(&id),
                "{what}: the refusal should name the fact, got {msg:?}"
            ),
            other => panic!("{what}: expected StoreError::Invalid, got {other:?}"),
        };
        // Unknown class or state: rejected, never coerced.
        refused(
            s.kg_set_authority(&id, "golden", "approved", Some("user-locale")),
            "unknown authority_class",
        );
        refused(
            s.kg_set_authority(&id, "canonical", "maybe", Some("user-locale")),
            "unknown review_state",
        );
        // canonical without a key, and stated with one: both refused.
        refused(
            s.kg_set_authority(&id, "canonical", "approved", None),
            "canonical without a key",
        );
        refused(
            s.kg_set_authority(&id, "stated", "unreviewed", Some("user-locale")),
            "stated with a key",
        );
        // A key with a path separator never reaches the table.
        refused(
            s.kg_set_authority(&id, "canonical", "approved", Some("user/locale")),
            "canonical_key with a path separator",
        );
        // Naming a fact that does not exist is an input error too — the
        // one arm that is about the id rather than the vocabulary.
        match s.kg_set_authority("kg-nope", "stated", "unreviewed", None) {
            Err(StoreError::Invalid(msg)) => assert!(msg.contains("no such fact"), "got {msg:?}"),
            other => panic!("unknown fact id: expected StoreError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn rotation_carries_the_authority_tier() {
        let (dir, mut s) = store(SecurityLevel::Sealed);
        let id = s
            .kg_add("user", "timezone", "Europe/Berlin", None, None, 1.0, None)
            .unwrap();
        s.kg_set_authority(&id, "canonical", "approved", Some("user-timezone"))
            .unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let candidate = mgr.rotation_candidate("kg-test").unwrap();
        s.rotate_keys(candidate).unwrap();
        // The promoted fact's tag was recomputed under the new key WITH the
        // authority extension — dropping it there would read as tampering.
        assert!(s.kg_verify().unwrap().is_empty());
        let hit = s
            .lookup_canonical("user-timezone")
            .unwrap()
            .expect("the door still answers after rotation");
        assert_eq!(hit.object, "Europe/Berlin");
    }
}
