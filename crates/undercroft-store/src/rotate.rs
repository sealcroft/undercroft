//! In-place key rotation: re-seal every key-derived artifact under a fresh
//! vault salt (⇒ fresh enc/mac/manifest keys) inside **one SQLite
//! transaction**, with a two-phase manifest swap so a crash at any moment
//! leaves the vault openable under exactly one key generation.
//!
//! Protocol:
//!
//! 1. Transform everything in memory under the old keys → new keys:
//!    AEAD blobs are re-sealed **byte-exact** at the seal layer (no
//!    decompress/requantize round trips; AAD domains preserved), HMAC tags
//!    and keyed fingerprints are recomputed over the new at-rest bytes.
//! 2. Replay the audit chain under the new mac key and stage the next
//!    manifest durably as `vault.json.next` (fsync + dir sync).
//! 3. One transaction rewrites every row **and** flips the `keycheck` meta
//!    value — the committed marker.
//! 4. Promote `vault.json.next` over `vault.json`.
//!
//! Crash windows: before the commit, the database still answers to the old
//! keys and open-time reconciliation discards the staging file; after the
//! commit, the database answers to the new keys and reconciliation promotes
//! it. Either way the palace opens clean — a crash is never a tamper alarm.
//!
//! Audit history: the tags of superseded or deleted content cannot be
//! recomputed (their plaintext is gone by design), so rotation preserves
//! every `audit.tag` byte verbatim as historical evidence and re-keys the
//! **chain over them** — `verify` replays the same bytes under the new mac
//! key to the new head.
//!
//! Not covered: copies of sealed content previously pushed to a remote
//! index are stale after rotation (they hold old-key ciphertext) — re-run
//! `index push`. Remote search correctness is unaffected either way: every
//! candidate is re-verified and decrypted locally.

use undercroft_vault::Vault;
use rusqlite::{params, OptionalExtension};

use crate::{canonical, PalaceStore, StoreError};

/// What one rotation re-sealed / re-tagged.
#[derive(Debug, Default, serde::Serialize)]
pub struct RotationReport {
    pub drawers: usize,
    pub kg_entities: usize,
    pub kg_triples: usize,
    pub tunnels: usize,
    pub token_matrices: usize,
    pub pq_rows: usize,
    /// Sealed PQ pages re-sealed (the opt-in page tier; 0 in per-row mode).
    pub pq_pages: usize,
    /// Per-wing PQ rows re-sealed (the wing-as-retrieval-unit tier; 0 when
    /// no wing has crossed its floor).
    pub wing_pq_rows: usize,
    pub fde_rows: usize,
    pub audit_entries: usize,
    /// Sealed meta artifacts re-sealed (codebooks, IVF centroids, FDE params).
    pub meta_artifacts: usize,
    /// Wing trust assignments re-tagged. Tag-only and level-independent —
    /// nothing here is sealed, so this is non-zero on hmac-only vaults too.
    pub wing_trusts: usize,
    /// Retention policies re-tagged. Same shape as `wing_trusts`.
    pub retention_policies: usize,
}

impl PalaceStore {
    /// Rotate this vault onto `next`'s keys (obtain `next` from
    /// [`undercroft_vault::VaultManager::rotation_candidate`]). On return the
    /// store itself operates under the new keys; RAM caches of decrypted
    /// artifacts are dropped and rebuild lazily. Requires the exclusive
    /// handle it takes — do not rotate a vault another process is serving.
    pub fn rotate_keys(&mut self, mut next: Vault) -> Result<RotationReport, StoreError> {
        if next.id() != self.vault.id() {
            return Err(StoreError::Invalid(format!(
                "rotation candidate is for vault {:?}, this store holds {:?}",
                next.id(),
                self.vault.id()
            )));
        }
        // Make sure every derived table exists so the sweeps below see them.
        self.late_schema()?;
        self.pq_schema()?;
        self.fde_schema()?;

        let mut report = RotationReport::default();
        let sealed = self.vault.level() == undercroft_vault::SecurityLevel::Sealed;

        // ---- Phase 1: transform in memory (old keys → new keys) ----

        // drawers: content / embedding re-sealed, tag over the new at-rest
        // bytes, keyed fingerprint recomputed from the plaintext.
        struct DrawerUpd {
            seq: i64,
            content: Vec<u8>,
            emb: Vec<u8>,
            tag: Vec<u8>,
            fp: Option<Vec<u8>>,
            /// Re-keyed supersession receipt, `None` for the (near-total)
            /// majority of drawers that supersede nothing.
            sup_receipt: Option<Vec<u8>>,
        }
        let mut drawer_upds = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT seq, id, meta_json, content, embedding, fp, \
                        supersedes, supersedes_fp, supersedes_receipt \
                 FROM drawers ORDER BY seq",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, Option<Vec<u8>>>(5)?,
                    (
                        r.get::<_, Option<String>>(6)?,
                        r.get::<_, Option<Vec<u8>>>(7)?,
                        r.get::<_, Option<Vec<u8>>>(8)?,
                    ),
                ))
            })?;
            for row in rows {
                let (seq, id, meta_json, content, emb, fp, sup3) = row?;
                let new_content = self.vault.reseal_at_rest(&next, &id, &content)?;
                let new_emb = self
                    .vault
                    .reseal_at_rest(&next, &format!("{id}/emb"), &emb)?;
                let tag = next
                    .tag(&canonical(&id, meta_json.as_bytes(), &new_content))
                    .to_vec();
                let fp = match fp {
                    Some(_) => {
                        let plain = self.vault.content_from_rest(&id, &content)?;
                        let text = String::from_utf8(plain).map_err(|_| {
                            StoreError::Invalid(format!("drawer {id} content is not UTF-8"))
                        })?;
                        let mut buf = Vec::with_capacity(text.len() + 3);
                        buf.extend_from_slice(b"fp\x1f");
                        buf.extend_from_slice(text.as_bytes());
                        Some(next.tag(&buf)[..16].to_vec())
                    }
                    None => None,
                };
                // Re-key the supersession receipt when present — unchanged
                // canonical (drawer id + superseded id + the fingerprint,
                // which is keyed with the STORED secret and therefore does
                // not move here), new mac key: the kg receipt re-key one
                // level up. An unreceipted link stays unreceipted.
                let sup_receipt = match &sup3 {
                    (Some(old_id), Some(sup_fp), Some(_)) => Some(
                        next.tag(&crate::supersession_canonical(&id, old_id, sup_fp))
                            .to_vec(),
                    ),
                    _ => None,
                };
                drawer_upds.push(DrawerUpd {
                    seq,
                    content: new_content,
                    emb: new_emb,
                    tag,
                    fp,
                    sup_receipt,
                });
            }
        }
        report.drawers = drawer_upds.len();

        // kg entities: tag over the stored fields, and the sealed NAME
        // re-sealed like every other blob.
        //
        // That second half was missing for one commit and the e2e caught
        // it, not the unit tests: `name_rest` is sealed under the enc key,
        // rotation replaces the enc key, and nothing re-sealed it — so the
        // first rotation after A10 left every entity name undecryptable and
        // `export`, `kg entities` and `kg query` all failed on the row. The
        // triples' `terms` blob one block down had been handled; its
        // neighbour had not. Any future sealed column needs a line here,
        // which is exactly why rotation's contract is byte-exact reseal of
        // *every* artifact rather than most of them.
        let mut entity_upds: Vec<(String, Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT id, name, etype, created_at, name_rest FROM kg_entities")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?;
            for row in rows {
                let (id, name, etype, created, name_rest) = row?;
                // The AAD domain is `kgname/{blind}`, and the blind value
                // is keyed with the KG secret — which rotation re-seals
                // rather than re-derives — so the domain is unchanged and
                // only the enc key moves.
                let new_name_rest = name_rest
                    .map(|sealed| {
                        self.vault
                            .reseal_at_rest(&next, &format!("kgname/{name}"), &sealed)
                    })
                    .transpose()?;
                // `kg::entity_canonical`, NOT a local copy of its bytes.
                // This was an inline `format!` of the same four fields —
                // correct at the time and a landmine: the moment that
                // canonical gained its `name_rest` extension, rotation would
                // have kept computing the old shape and marked every entity
                // in the vault tampered, on the first rotation after the
                // change. The sealed name is re-sealed above, so the NEW
                // bytes are what the new tag covers, exactly as the triple
                // arm covers its new `terms`.
                let can = crate::kg::entity_canonical(
                    &id,
                    &name,
                    &etype,
                    &created,
                    new_name_rest.as_deref(),
                );
                entity_upds.push((id, next.tag(&can).to_vec(), new_name_rest));
            }
        }
        report.kg_entities = entity_upds.len();

        // kg triples: object re-sealed (content domain `kg/{id}`), tag over
        // the new at-rest object. A fact carrying a receipt also gets its
        // keyed receipt_tag re-computed under the new key — the receipt's
        // source fingerprint is keyed with the STORED `kg_secret`, which
        // rotation re-seals and never regenerates, so it stays
        // byte-identical and the citation binding survives verbatim (U12).
        #[allow(clippy::type_complexity)]
        let mut triple_upds: Vec<(
            String,
            Vec<u8>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        )> = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT id, subject, predicate, object, valid_from, valid_to, confidence, \
                        source_drawer_id, source_fp, receipt_tag, support, \
                        authority_class, review_state, canonical_key, extractor, terms \
                 FROM kg_triples",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, f64>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<Vec<u8>>>(8)?,
                    r.get::<_, Option<Vec<u8>>>(9)?,
                    r.get::<_, Option<Vec<u8>>>(10)?,
                    (
                        r.get::<_, Option<String>>(11)?,
                        r.get::<_, Option<String>>(12)?,
                        r.get::<_, Option<String>>(13)?,
                        r.get::<_, Option<String>>(14)?,
                    ),
                    r.get::<_, Option<Vec<u8>>>(15)?,
                ))
            })?;
            for row in rows {
                let (
                    id,
                    s,
                    p,
                    object,
                    vf,
                    vt,
                    conf,
                    src_id,
                    src_fp,
                    receipt_tag,
                    support,
                    auth4,
                    terms,
                ) = row?;
                let new_object = self
                    .vault
                    .reseal_at_rest(&next, &format!("kg/{id}"), &object)?;
                // The grounding blob is sealed under its own AAD domain, so
                // rotation must re-seal it like any other artifact — and the
                // new bytes are what the new tag has to cover, since support
                // is inside the triple's canonical.
                let new_support = support
                    .map(|sealed| {
                        self.vault
                            .reseal_at_rest(&next, &format!("kg/{id}/support"), &sealed)
                    })
                    .transpose()?;
                // Authority fields are plain columns inside the canonical
                // (like validity), so rotation carries them into the new tag
                // unchanged — dropping them would mark every promoted fact
                // tampered after the first rotation.
                let (a_class, a_review, a_key, x_id) = auth4;
                let auth = crate::kg::authority_ext(
                    a_class.as_deref(),
                    a_review.as_deref(),
                    a_key.as_deref(),
                );
                // Extractor identity is a plain column inside the canonical
                // (via its extension), so rotation carries it into the new
                // tag unchanged — dropping it would mark every attributed
                // fact tampered after the first rotation.
                let ext = crate::kg::extractor_ext(x_id.as_deref());
                // The sealed subject/predicate (A10) are re-sealed like the
                // object and the grounding blob, and the NEW bytes are what
                // the new tag covers — they are inside the canonical via the
                // terms extension.
                //
                // The blind COLUMNS and the ids are deliberately untouched.
                // They are keyed with the vault's KG blind secret, which is
                // a stored value rotation RE-SEALS rather than a derived key
                // rotation replaces — and that is the whole reason it is a
                // stored secret. Re-deriving them here would change every id
                // in the graph on every rotation, orphaning the audit
                // records written under `kg/{id}` (rotation re-keys over
                // PRESERVED audit bytes) and breaking the deterministic-id
                // idempotency the module rests on: re-adding the same fact
                // after a rotation would insert a second row.
                let new_terms = terms
                    .map(|sealed| {
                        self.vault
                            .reseal_at_rest(&next, &format!("kgterms/{id}"), &sealed)
                    })
                    .transpose()?;
                let tag = next
                    .tag(&crate::kg::triple_canonical(
                        &id,
                        &s,
                        &p,
                        &new_object,
                        &vf,
                        &vt,
                        conf,
                        new_support.as_deref(),
                        auth.as_deref(),
                        ext.as_deref(),
                        crate::kg::terms_ext(new_terms.as_deref()).as_deref(),
                    ))
                    .to_vec();
                // Re-key the receipt binding when present (unchanged
                // canonical: id + citation + the source fingerprint, which
                // is stored-secret-keyed and does not move on a rotation).
                let new_receipt = match (receipt_tag, src_id, src_fp) {
                    (Some(_), Some(did), Some(fp)) => Some(
                        next.tag(&crate::kg::receipt_canonical(&id, &did, &fp))
                            .to_vec(),
                    ),
                    _ => None,
                };
                triple_upds.push((id, new_object, tag, new_receipt, new_support, new_terms));
            }
        }
        report.kg_triples = triple_upds.len();

        // tunnels: tag only (nothing sealed).
        let mut tunnel_upds: Vec<(String, Vec<u8>)> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT id, from_wing, to_wing, label, created_at FROM tunnels")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (id, from, to, label, created) = row?;
                let can = crate::manage::tunnel_canonical(&id, &from, &to, &label, &created);
                tunnel_upds.push((id, next.tag(&can).to_vec()));
            }
        }
        report.tunnels = tunnel_upds.len();

        // wing_trust and retention_policy: tag only, and **outside the
        // `if sealed` block below** because neither holds sealed bytes — the
        // tag is the whole key-derived content, at both security levels.
        //
        // These were missing entirely until 2026-08-06, and the cost was not
        // cosmetic: both tags are verified ON READ and raise
        // `StoreError::Integrity` (`wing_trusts` in manage.rs, the sweep's
        // per-policy check in retention.rs). So a routine key rotation — the
        // operation the docs recommend — made `wing_trusts()` fail forever,
        // which takes `trust_clause` with it and therefore every search
        // carrying a trust floor, while `trust_clause`'s own comment asserts
        // "every row it rests on was tag-verified by `wing_trusts`". A
        // declared retention policy stopped listing and stopped sweeping the
        // same way. Found by two independent review lenses; the enumeration
        // gate below is what stops the class rather than these two rows.
        let mut trust_upds: Vec<(String, Vec<u8>)> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT wing, trust, assigned_at FROM wing_trust")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (wing, trust, at) = row?;
                let can = crate::manage::wing_trust_canonical(&wing, &trust, &at);
                trust_upds.push((wing, next.tag(&can).to_vec()));
            }
        }
        report.wing_trusts = trust_upds.len();

        let mut retention_upds: Vec<(String, String, Vec<u8>)> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT wing, room, max_age_days, assigned_at FROM retention_policy")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u32>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (wing, room, days, at) = row?;
                let can = crate::retention::retention_canonical(&wing, &room, days, &at);
                retention_upds.push((wing, room, next.tag(&can).to_vec()));
            }
        }
        report.retention_policies = retention_upds.len();

        // Sealed-only artifact sweeps: for hmac-only vaults these blobs are
        // stored in clear and carry no key material — nothing to rewrite.
        let mut tok_upds: Vec<(String, Vec<u8>)> = Vec::new();
        let mut pq_upds: Vec<(i64, Vec<u8>)> = Vec::new();
        let mut page_upds: Vec<(i64, i64, Vec<u8>)> = Vec::new();
        let mut wing_pq_upds: Vec<(String, i64, Vec<u8>)> = Vec::new();
        let mut fde_upds: Vec<(String, Vec<u8>)> = Vec::new();
        let mut meta_upds: Vec<(&'static str, &'static str, Vec<u8>)> = Vec::new();
        let mut meta_dyn_upds: Vec<(String, Vec<u8>)> = Vec::new();
        if sealed {
            {
                let mut stmt = self.conn.prepare("SELECT id, tok FROM drawer_tok")?;
                let rows = stmt.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })?;
                for row in rows {
                    let (id, tok) = row?;
                    let new = self
                        .vault
                        .reseal_at_rest(&next, &format!("{id}/tok"), &tok)?;
                    tok_upds.push((id, new));
                }
            }
            {
                let mut stmt = self.conn.prepare("SELECT seq, code FROM drawer_pq")?;
                let rows =
                    stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
                for row in rows {
                    let (seq, code) = row?;
                    let new =
                        self.vault
                            .reseal_at_rest(&next, &format!("pqrow/{seq}/pq"), &code)?;
                    pq_upds.push((seq, new));
                }
            }
            {
                // Sealed PQ pages (the opt-in page tier): byte-exact reseal
                // under the exact (list, pageno)-bound domain.
                let mut stmt = self
                    .conn
                    .prepare("SELECT list, pageno, blob FROM pq_page")?;
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                })?;
                for row in rows {
                    let (list, pageno, blob) = row?;
                    let new = self.vault.reseal_at_rest(
                        &next,
                        &format!("pqpage/{list}/{pageno}/pq"),
                        &blob,
                    )?;
                    page_upds.push((list, pageno, new));
                }
            }
            {
                // Per-wing PQ rows: same reseal as the global rows, one
                // dimension up — the AAD carries the wing so a row cannot be
                // replayed into another wing's index.
                let mut stmt = self
                    .conn
                    .prepare("SELECT wing, seq, code FROM drawer_pq_wing")?;
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                })?;
                for row in rows {
                    let (wing, seq, code) = row?;
                    let new = self.vault.reseal_at_rest(
                        &next,
                        &format!("pqrow/{wing}/{seq}/pq"),
                        &code,
                    )?;
                    wing_pq_upds.push((wing, seq, new));
                }
            }
            {
                let mut stmt = self.conn.prepare("SELECT id, fde FROM drawer_fde")?;
                let rows = stmt.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })?;
                for row in rows {
                    let (id, fde) = row?;
                    let new = self
                        .vault
                        .reseal_at_rest(&next, &format!("fde/{id}/tok"), &fde)?;
                    fde_upds.push((id, new));
                }
            }
            // Sealed meta artifacts, each under its exact seal-layer domain.
            for (table, key, domain) in [
                // The knowledge graph's blind-index secret (A10). It is a
                // STORED value rotation must re-seal and must NOT
                // regenerate: the graph's ids and blind columns are keyed
                // with it, so a fresh one would orphan every audit record
                // written under `kg/{id}` and make every existing lookup
                // miss. `reseal_at_rest` is exactly that — open under the
                // old key, seal under the new, same bytes.
                ("meta", "kg_blind_secret", "kg/blind-secret"),
                ("tok_meta", "codebook", "tok/codebook/tok"),
                ("pq_meta", "codebook", "pq/codebook/pq"),
                ("pq_meta", "ivf", "pq/ivf/pq"),
                ("pq_meta", "rowcount", "pq/rowcount/pq"),
                ("pq_meta", "deleted", "pq/deleted/pq"),
                ("fde_meta", "params", "fde/params/tok"),
                ("fde_meta", "codebook", "fde/codebook/tok"),
                ("fde_meta", "ivf", "fde/ivf/tok"),
            ] {
                let stored: Option<Vec<u8>> = self
                    .conn
                    .query_row(
                        &format!("SELECT value FROM {table} WHERE key = ?1"),
                        [key],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(blob) = stored {
                    let new = self.vault.reseal_at_rest(&next, domain, &blob)?;
                    meta_upds.push((table, key, new));
                }
            }
            // Per-wing codebooks and centroids are dynamic keys — a fixed
            // list cannot enumerate them, and a key rotation that missed one
            // would leave a wing's index sealed under retired keys (it would
            // self-heal by rebuild, but rotation's contract is byte-exact
            // reseal of *every* artifact, not most of them).
            {
                let mut stmt = self.conn.prepare(
                    "SELECT key, value FROM pq_meta \
                     WHERE key LIKE 'codebook/%' OR key LIKE 'ivf/%'",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })?;
                for row in rows {
                    let (key, blob) = row?;
                    let new = self
                        .vault
                        .reseal_at_rest(&next, &format!("pq/{key}/pq"), &blob)?;
                    meta_dyn_upds.push((key, new));
                }
            }
        }
        report.token_matrices = tok_upds.len();
        report.pq_rows = pq_upds.len();
        report.pq_pages = page_upds.len();
        report.wing_pq_rows = wing_pq_upds.len();
        report.fde_rows = fde_upds.len();
        report.meta_artifacts = meta_upds.len() + meta_dyn_upds.len();

        // ---- Phase 2: replay the chain under the new mac key; stage ----
        let audit_tags: Vec<Vec<u8>> = {
            let mut stmt = self.conn.prepare("SELECT tag FROM audit ORDER BY seq")?;
            let tags = stmt
                .query_map([], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<Result<_, _>>()?;
            tags
        };
        report.audit_entries = audit_tags.len();
        let mut head = Vault::chain_genesis_hex();
        for tag in &audit_tags {
            head = next.chain_next_hex(&head, tag)?;
        }
        // **The rotation records ITSELF (ROADMAP A19).** This is the largest
        // single mutation the engine can perform — every artifact re-sealed,
        // every tag re-keyed, a new key generation adopted — and until
        // 2026-08-06 it appended nothing, so the one operation an auditor
        // most needs to see left no evidence that it happened. Against the
        // invariant "every write must update the audit chain atomically with
        // its data", which rotation is the standing exception to and nothing
        // failed.
        //
        // Tagged with the NEW mac key and folded into the head BEFORE the
        // manifest is staged, so the anchor commits the record along with
        // everything else and `verify` replays to the same head. Appended,
        // never rewriting a preserved tag — historical evidence stays
        // verbatim, which is why the rotation gate checks audit labels as a
        // PREFIX rather than for equality.
        //
        // The canonical binds the generation it moved TO plus what it
        // touched. It deliberately does not bind the OLD keycheck: that value
        // is overwritten by this same transaction, so nothing could
        // recompute the canonical afterwards and a component nobody can
        // reproduce is decoration, not evidence.
        let rotated_at = crate::manage::now_rfc3339();
        let rotate_canonical = format!(
            "rotate\x1f{}\x1f{rotated_at}\x1f{}\x1f{}\x1f{}",
            next.keycheck_hex(),
            report.drawers,
            report.kg_triples,
            report.kg_entities
        );
        let rotate_tag = next.tag(rotate_canonical.as_bytes()).to_vec();
        head = next.chain_next_hex(&head, &rotate_tag)?;
        let writes: u64 = self
            .conn
            .query_row(
                "SELECT value FROM chain_meta WHERE key = 'writes'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| self.vault.writes());
        // The rotation record is a write, so the counter has to count it or
        // the anchor commits a height the chain does not have.
        let writes = writes + 1;
        next.save_manifest_pending(&head, writes)?;

        // ---- Phase 3: one transaction applies everything ----
        {
            let tx = self.conn.transaction()?;
            {
                let mut up = tx.prepare(
                    "UPDATE drawers SET content = ?2, embedding = ?3, tag = ?4, fp = ?5, \
                                        supersedes_receipt = \
                                            COALESCE(?6, supersedes_receipt) \
                     WHERE seq = ?1",
                )?;
                for d in &drawer_upds {
                    up.execute(params![d.seq, d.content, d.emb, d.tag, d.fp, d.sup_receipt])?;
                }
                let mut up =
                    tx.prepare("UPDATE kg_entities SET tag = ?2, name_rest = ?3 WHERE id = ?1")?;
                for (id, tag, name_rest) in &entity_upds {
                    up.execute(params![id, tag, name_rest])?;
                }
                let mut up = tx.prepare(
                    "UPDATE kg_triples SET object = ?2, tag = ?3, receipt_tag = ?4, support = ?5,
                            terms = ?6
                     WHERE id = ?1",
                )?;
                for (id, object, tag, receipt_tag, support, terms) in &triple_upds {
                    up.execute(params![id, object, tag, receipt_tag, support, terms])?;
                }
                let mut up = tx.prepare("UPDATE tunnels SET tag = ?2 WHERE id = ?1")?;
                for (id, tag) in &tunnel_upds {
                    up.execute(params![id, tag])?;
                }
                let mut up = tx.prepare("UPDATE wing_trust SET tag = ?2 WHERE wing = ?1")?;
                for (wing, tag) in &trust_upds {
                    up.execute(params![wing, tag])?;
                }
                let mut up = tx.prepare(
                    "UPDATE retention_policy SET tag = ?3 WHERE wing = ?1 AND room = ?2",
                )?;
                for (wing, room, tag) in &retention_upds {
                    up.execute(params![wing, room, tag])?;
                }
                let mut up = tx.prepare("UPDATE drawer_tok SET tok = ?2 WHERE id = ?1")?;
                for (id, tok) in &tok_upds {
                    up.execute(params![id, tok])?;
                }
                let mut up = tx.prepare("UPDATE drawer_pq SET code = ?2 WHERE seq = ?1")?;
                for (seq, code) in &pq_upds {
                    up.execute(params![seq, code])?;
                }
                let mut up =
                    tx.prepare("UPDATE drawer_pq_wing SET code = ?3 WHERE wing = ?1 AND seq = ?2")?;
                for (wing, seq, code) in &wing_pq_upds {
                    up.execute(params![wing, seq, code])?;
                }
                let mut up = tx.prepare("UPDATE pq_meta SET value = ?2 WHERE key = ?1")?;
                for (key, blob) in &meta_dyn_upds {
                    up.execute(params![key, blob])?;
                }
                let mut up =
                    tx.prepare("UPDATE pq_page SET blob = ?3 WHERE list = ?1 AND pageno = ?2")?;
                for (list, pageno, blob) in &page_upds {
                    up.execute(params![list, pageno, blob])?;
                }
                let mut up = tx.prepare("UPDATE drawer_fde SET fde = ?2 WHERE id = ?1")?;
                for (id, fde) in &fde_upds {
                    up.execute(params![id, fde])?;
                }
                for (table, key, blob) in &meta_upds {
                    tx.execute(
                        &format!("UPDATE {table} SET value = ?2 WHERE key = ?1"),
                        params![key, blob],
                    )?;
                }
            }
            // The rotation's own audit row, inside the same transaction as
            // everything it describes. Appended last so its `seq` orders
            // after every row it covers, which is also the order phase 2
            // folded it into the head in.
            tx.execute(
                "INSERT INTO audit (record_id, tag, at) VALUES (?1, ?2, ?3)",
                params![
                    format!("rotate/{}", &next.keycheck_hex()[..16]),
                    rotate_tag,
                    rotated_at
                ],
            )?;
            tx.execute(
                "UPDATE chain_meta SET value = ?1 WHERE key = 'head'",
                params![head],
            )?;
            tx.execute(
                "UPDATE chain_meta SET value = ?1 WHERE key = 'writes'",
                params![writes.to_string()],
            )?;
            // The committed marker: reconciliation reads this to decide
            // whether a crash left the staging manifest promotable.
            tx.execute(
                "INSERT INTO meta (key, value) VALUES ('keycheck', ?1) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![next.keycheck_hex()],
            )?;
            tx.commit()?;
        }

        // ---- Phase 4: promote and adopt ----
        next.promote_manifest()?;
        self.vault = next;
        self.drop_derived_caches();
        Ok(report)
    }

    /// Drop every RAM cache holding plaintext derived under the previous
    /// keys; they rebuild lazily from the re-sealed rows.
    pub(crate) fn drop_derived_caches(&self) {
        *self.emb_cache.borrow_mut() = None;
        *self.pq.borrow_mut() = None;
        *self.ivf.borrow_mut() = None;
        *self.pq_cache.borrow_mut() = None;
        self.pq_verified.set(false);
        self.wing_pq.borrow_mut().clear();
        *self.tok_pq.borrow_mut() = None;
        self.tok_pq_checked.set(false);
        *self.fde_encoder.borrow_mut() = None;
        *self.fde_cache.borrow_mut() = None;
        self.fde_checked.set(false);
        *self.fde_pq.borrow_mut() = None;
        *self.fde_ivf.borrow_mut() = None;
        self.fde_ivf_checked.set(false);
        self.fde_pq_checked.set(false);
        *self.qmatrix_cache.borrow_mut() = None;
        #[cfg(feature = "hnsw")]
        {
            *self.hnsw.borrow_mut() = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::PalaceStore;
    use crate::StoreError;
    use undercroft_core::Drawer;
    use undercroft_vault::{SecurityLevel, VaultManager};
    use tempfile::TempDir;

    fn drawer(content: &str, idx: u32) -> Drawer {
        Drawer::new(
            "wing",
            "room",
            content.into(),
            Some("t.md".into()),
            idx,
            "t",
        )
    }

    fn seeded(level: SecurityLevel) -> (TempDir, PalaceStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("r", level).unwrap();
        let mut store = PalaceStore::open(vault).unwrap();
        store
            .upsert(&drawer("the heron files verbatim drawers", 0))
            .unwrap();
        store
            .upsert(&drawer("the vault seals with chacha", 1))
            .unwrap();
        store
            .upsert(&drawer("rotation must not lose a word", 2))
            .unwrap();
        store
            .kg_add("heron", "nests-in", "the reeds", None, None, 0.9, None)
            .unwrap();
        store.create_tunnel("wing", "wing", "self-link").unwrap();
        (dir, store)
    }

    fn reopen(dir: &TempDir) -> PalaceStore {
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        PalaceStore::open(mgr.unlock("r").unwrap()).unwrap()
    }

    /// Every durable reference this vault hands out, in one snapshot: the
    /// things a rotation must NOT move, and beside them the keyed values it
    /// MUST — see [`no_durable_reference_moves_on_a_key_rotation`].
    #[derive(Debug, PartialEq, Eq)]
    struct References {
        /// Must not move: identifiers, blind indexes, content fingerprints.
        stable: Vec<String>,
        /// Audit labels, in chain order. Must not move either — but this
        /// list GROWS whenever anything is written, including an idempotent
        /// re-write (the chain records that an operation happened, not only
        /// that it changed something), so it is compared as a prefix rather
        /// than for equality wherever a write sits between two snapshots.
        audit: Vec<String>,
        /// Must move: keyed lookup keys and keyed receipts, which rotation
        /// recomputes by design — **grouped, and asserted per group**, since
        /// a flat vector compared with `assert_ne!` is satisfied by any one
        /// element changing.
        rekeyed: Vec<(&'static str, Vec<String>)>,
        /// Every public reader whose contract is "tag-verified on the way
        /// out", called and required to answer `Ok` — because the snapshot
        /// arms above cannot see a table rotation forgot to RE-TAG. That is
        /// not hypothetical: this test planted a `wing_trust` row from the
        /// day it was written and read only its audit label, so it walked
        /// straight past a rotation that made `wing_trusts()` raise
        /// `Integrity` forever (and `retention_policies()` with it). A
        /// reference that is byte-identical but no longer verifies is not a
        /// surviving reference.
        verified: Vec<String>,
    }

    fn references(s: &PalaceStore) -> References {
        let rows = |sql: &str, tag: &str| -> Vec<String> {
            let mut stmt = s.conn.prepare(sql).unwrap();
            let n = stmt.column_count();
            let out: Vec<String> = stmt
                .query_map([], |r| {
                    let mut cells = Vec::with_capacity(n);
                    for i in 0..n {
                        cells.push(r.get::<_, Option<String>>(i)?.unwrap_or_default());
                    }
                    Ok(cells.join("|"))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            out.into_iter().map(|r| format!("{tag}:{r}")).collect()
        };
        let mut stable = Vec::new();
        // Drawer id, its supersession LINK and the fingerprint that binds
        // it. `supersedes_fp` is keyed with the STORED `kg_secret` since
        // U12, never with a vault key, precisely so this arm keeps holding.
        stable.extend(rows(
            "SELECT id, supersedes, hex(supersedes_fp) FROM drawers ORDER BY seq",
            "drawer",
        ));
        // Fact id, both blind index columns, and the citation fingerprint.
        stable.extend(rows(
            "SELECT id, subject, predicate, hex(source_fp) FROM kg_triples ORDER BY seq",
            "triple",
        ));
        stable.extend(rows(
            "SELECT id, name FROM kg_entities ORDER BY id",
            "entity",
        ));
        stable.extend(rows("SELECT id FROM tunnels ORDER BY id", "tunnel"));
        // The blind-index secret itself: a STORED value rotation re-seals
        // and never regenerates. Compared as plaintext, because the sealed
        // bytes are expected to change.
        let secret = s.kg_secret().unwrap();
        stable.push(format!("kg-secret:{}", hex::encode(secret)));
        // The blind-index RECIPE, re-derived rather than read. A stored
        // column cannot show a recipe that moved with the key — rotation
        // leaves the columns alone — and the one public read door
        // (`kg_query_entity`) decrypts `terms` and filters in RAM, so it
        // cannot see it either. Deriving it here is the only place the
        // property is observable.
        for (kind, term) in [("s", "heron"), ("p", "nests-in"), ("e", "heron")] {
            stable.push(format!(
                "blind-{kind}:{}",
                crate::kg::kg_term_at_rest(&s.vault, &secret, kind, term)
            ));
        }
        // U2. `canonical_key` is the authority door's exact-lookup key —
        // operator-declared, never keyed, and a durable reference in the same
        // sense a fact id is: `lookup_canonical` resolves it and a promotion
        // closes the previous holder's window against it.
        stable.extend(rows(
            "SELECT canonical_key FROM kg_triples ORDER BY seq",
            "canonical-key",
        ));

        // Grouped and asserted GROUP BY GROUP, because a flat vector plus
        // `assert_ne!` is satisfied by any single element — and the last one
        // used to be `sample_rank`, which is computed live from the new key
        // and therefore moves on every rotation no matter what happened to
        // the stored rows. So the arm that claimed "the keyed values are
        // asserted to change" could not fail for a rotation that swapped the
        // keys and never recomputed `drawers.fp`, `supersedes_receipt` or
        // `receipt_tag`. Empty components are dropped: an unreceipted drawer
        // has no receipt to re-key and would otherwise make its group
        // permanently unequal-to-itself.
        let group = |sql: &str, tag: &str| -> Vec<String> {
            rows(sql, tag)
                .into_iter()
                .filter(|r| !r.split(':').nth(1).unwrap_or("").is_empty())
                .collect()
        };
        let mut rekeyed: Vec<(&'static str, Vec<String>)> = vec![
            (
                "drawers.fp",
                group("SELECT hex(fp) FROM drawers ORDER BY seq", "fp"),
            ),
            (
                "drawers.supersedes_receipt",
                group(
                    "SELECT hex(supersedes_receipt) FROM drawers ORDER BY seq",
                    "sup",
                ),
            ),
            (
                "kg_triples.receipt_tag",
                group(
                    "SELECT hex(receipt_tag) FROM kg_triples ORDER BY seq",
                    "rcpt",
                ),
            ),
            // U2: the two policy tables, as VALUES rather than only through
            // the reader that verifies them. The `verified` arm proves they
            // still VERIFY; this proves they were actually re-keyed, which is
            // a different claim — a rotation that skipped the sweep and also
            // skipped changing the mac key would satisfy the first and not
            // the second.
            (
                "wing_trust.tag",
                group("SELECT hex(tag) FROM wing_trust ORDER BY wing", "trust"),
            ),
            (
                "retention_policy.tag",
                group(
                    "SELECT hex(tag) FROM retention_policy ORDER BY wing, room",
                    "ret",
                ),
            ),
        ];
        // Keyed, and deliberately rotation-SENSITIVE: it chooses a training
        // sample and nothing holds a reference to it. Deliberately its OWN
        // group, and deliberately NOT part of the "the rows were rewritten"
        // evidence — it proves only that a key changed.
        rekeyed.push((
            "sample_rank",
            vec![format!("{}", s.vault.sample_rank("sample", b"probe"))],
        ));
        // The audit chain's own references — the thing an audit trail IS —
        // label AND tag together.
        //
        // U2: the TAG belongs here rather than in `stable`, and putting it
        // there first is what proved it: rotation's contract is to preserve
        // audit tags verbatim (the tags of superseded or destroyed content
        // cannot be recomputed, their plaintext being gone by design), so a
        // rotation that "helpfully" re-tagged them would destroy evidence and
        // the label-only comparison could not see it. But this list GROWS —
        // A19 appends the rotation's own record — so it is prefix-compared
        // like the labels, and an equality assertion here failed exactly as
        // it should have. The tag also carries the read-audit query
        // fingerprint, which lives inside it rather than in a column and is
        // not otherwise snapshot-able.
        let audit = rows(
            "SELECT record_id, hex(tag) FROM audit ORDER BY seq",
            "audit",
        );

        // Every tag-verifying public reader, by name, with its verdict. A
        // `Vec<String>` rather than assertions inside this helper so the
        // BEFORE snapshot proves the premise (they all answered Ok to begin
        // with) and the diff names the one that broke.
        let ok = |label: &str, r: Result<(), StoreError>| {
            format!(
                "{label}:{}",
                match r {
                    Ok(()) => "ok".to_string(),
                    Err(e) => format!("ERR {e}"),
                }
            )
        };
        // **A receipt walk's VERDICTS, not merely that it returned `Ok`.**
        // Both walks answer `Ok` for a vault in which every receipt reads
        // `Tampered` or `SourceChanged`, so mapping them to `()` asserted
        // only that the query ran. That was blind to the whole class this
        // arm exists for — and U12 moved a value INTO those bindings, so a
        // rotation that re-keyed a receipt without preserving what the
        // receipt binds would have passed the gate while breaking every
        // provenance claim in the vault.
        let all_verified =
            |what: &str, vs: Vec<crate::kg::ReceiptVerdict>| -> Result<(), StoreError> {
                let bad: Vec<String> = vs
                    .iter()
                    .filter(|v| **v != crate::kg::ReceiptVerdict::Verified)
                    .map(|v| format!("{v:?}"))
                    .collect();
                if bad.is_empty() {
                    Ok(())
                } else {
                    Err(StoreError::Integrity(format!("{what} verdicts: {bad:?}")))
                }
            };
        let verified = vec![
            ok("wing_trusts", s.wing_trusts().map(|_| ())),
            ok("retention_policies", s.retention_policies().map(|_| ())),
            ok(
                "verify_supersessions",
                s.verify_supersessions().and_then(|v| {
                    all_verified("supersession", v.into_iter().map(|x| x.verdict).collect())
                }),
            ),
            ok(
                "kg_verify_receipts",
                s.kg_verify_receipts().and_then(|v| {
                    all_verified("receipt", v.into_iter().map(|x| x.verdict).collect())
                }),
            ),
            ok("kg_export_entities", s.kg_export_entities().map(|_| ())),
            ok("kg_export", s.kg_export().map(|_| ())),
            ok("list_tunnels", s.list_tunnels(None).map(|_| ())),
            ok(
                "verify",
                s.verify().and_then(|v| {
                    if v.ok() {
                        Ok(())
                    } else {
                        Err(StoreError::Integrity(format!(
                            "bad_records={:?} chain_ok={}",
                            v.bad_records, v.chain_ok
                        )))
                    }
                }),
            ),
        ];
        References {
            stable,
            audit,
            rekeyed,
            verified,
        }
    }

    /// **The invariant, enforced instead of written down.**
    ///
    /// *An identifier is never derived from rotatable key material. Neither
    /// is a blind-index key.* That rule was already legible in this tree —
    /// `content_fp` and `supersedes_fp` carry comments about surviving a
    /// rotation unchanged — and A10's first implementation
    /// keyed `triple_id`/`entity_id` with `Vault::tag` anyway, which key
    /// rotation replaces. Every fact and entity id would have moved on every
    /// rotation: orphaning the audit records written under `kg/{id}` (whose
    /// contract is to re-key over PRESERVED bytes), breaking every receipt,
    /// breaking deterministic-id idempotency so re-adding a fact inserts a
    /// duplicate, and invalidating any id held by an export or by an agent
    /// across sessions. It was caught by a rotation pass failing, not by
    /// design, and the invariant it produced then lived only in prose — in
    /// CLAUDE.md, the ROADMAP, the CHANGELOG, THREAT_MODEL and one comment.
    /// **Prose is what failed the first time.** This is the gate.
    ///
    /// It is deliberately GENERAL: it covers every durable reference the
    /// vault hands out rather than the two ids that were wrong, so the next
    /// blind index or id — A10's unit 2 (`wing`/`room`/`source_file`) and
    /// unit 3 (the dates) both add one — is covered on the day it lands
    /// instead of on the day someone remembers to test it.
    ///
    /// **Two arms, because one of them cannot see the defect.** The first
    /// version of this test had only the snapshot arm, and it PASSED with
    /// the original mistake reproduced verbatim (`triple_id` keyed with
    /// `Vault::tag`) — because rotation deliberately does not re-derive ids,
    /// so the columns are untouched no matter what the recipe depends on.
    /// **A moved recipe only shows up the next time the id is DERIVED.** So:
    ///
    /// * the **snapshot** arm catches rotation *rewriting* a reference —
    ///   an id re-derivation creeping into `rotate.rs`, or an audit label
    ///   orphaned the way A10's migration orphaned `kg/{old_id}`;
    /// * the **re-derivation** arm catches the recipe itself depending on a
    ///   rotating key, by deriving each reference again after the rotation
    ///   and requiring it to land on the row that is already there.
    ///
    /// **It fails in both directions**, which is the half that makes the
    /// snapshot meaningful: the keyed values rotation is SUPPOSED to
    /// recompute are asserted to change. Without that arm, "nothing moved"
    /// would also pass for a rotation that silently did nothing at all.
    #[test]
    fn no_durable_reference_moves_on_a_key_rotation() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("r", SecurityLevel::Sealed).unwrap();
        let mut store = PalaceStore::open(vault).unwrap();

        // One of every referenceable kind, so the snapshot cannot be
        // accidentally narrow.
        let src = drawer("Ada migrated auth to PASETO in June.", 0);
        let src_id = src.id.clone();
        store.upsert(&src).unwrap();
        store
            .upsert(
                &drawer("Ada moved auth back to JWT in July.", 1)
                    .with_supersedes(Some(src_id.clone())),
            )
            .unwrap();
        store
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
        store
            .kg_add("heron", "nests-in", "the reeds", None, None, 0.9, None)
            .unwrap();
        let tunnel_id = store.create_tunnel("wing", "wing", "self-link").unwrap();
        // An audit label carrying a NAME rather than an id — the shape A10's
        // unit 2 has to keep stable when wing names stop being clear. Both
        // of these also carry a tag that is verified ON READ, which is the
        // property the `verified` arm below exists to check.
        store.set_wing_trust("wing", "trusted").unwrap();
        store.set_retention("wing", Some("room"), 3650).unwrap();

        let counts_before = {
            let kg = store.kg_stats().unwrap();
            (kg.triples, kg.entities, store.count().unwrap())
        };
        let before = references(&store);
        assert!(
            before.stable.len() > 10
                && before.audit.len() > 5
                && before.audit.iter().any(|a| a.contains("trust/wing")),
            "premise: the snapshot actually captured references: {before:?}"
        );
        assert!(
            before.verified.iter().all(|v| v.ends_with(":ok")),
            "premise: every tag-verifying reader answers Ok BEFORE the \
             rotation, so a failure after it is the rotation's: {:?}",
            before.verified
        );

        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let candidate = mgr.rotation_candidate("r").unwrap();
        store.rotate_keys(candidate).unwrap();

        let after = references(&store);
        // Report only what MOVED: the snapshot is long, and a gate whose
        // whole job is to be read at 3am should not print two full lists.
        let diff = |b: &[String], a: &[String]| -> String {
            b.iter()
                .zip(a.iter())
                .filter(|(b, a)| b != a)
                .map(|(b, a)| format!("\n  {b}\n→ {a}"))
                .collect::<Vec<_>>()
                .join("")
        };
        let moved = diff(&before.stable, &after.stable);
        assert!(
            moved.is_empty() && before.stable.len() == after.stable.len(),
            "a rotation MOVED a durable reference — an identifier, a blind \
             index or an unkeyed fingerprint. Whatever moved is derived from \
             rotatable key material; see this test's doc comment and the \
             CLAUDE.md invariant.{moved}"
        );
        // Audit labels: a PREFIX check, not equality. Rotation must not
        // rewrite an existing label — but it is legitimate for it to APPEND
        // one, and ROADMAP A19 is the open item that says it should (a key
        // rotation is the largest single mutation the engine can perform and
        // currently leaves no chain record of itself). Asserting equality
        // here would have turned A19's own fix into a failing gate with a
        // message accusing it of rewriting history.
        let relabelled = diff(&before.audit, &after.audit);
        assert!(
            relabelled.is_empty() && after.audit.starts_with(&before.audit),
            "a rotation MOVED an audit label. An audit trail whose references \
             have moved is not an audit trail. (Appending a label is allowed \
             — see A19.){relabelled}"
        );

        // A19: the rotation recorded ITSELF. Exactly one appended label, and
        // it names the rotation — so the largest mutation the engine performs
        // is no longer invisible in the chain. Asserted here rather than
        // left incidental, because the audit arm above only says "nothing
        // moved", which a rotation that recorded nothing also satisfies.
        assert_eq!(
            after.audit.len(),
            before.audit.len() + 1,
            "a rotation must append exactly one audit record — its own"
        );
        assert!(
            after.audit.last().unwrap().contains(":rotate/"),
            "and that record names the rotation, got {:?}",
            after.audit.last()
        );

        // The readers whose contract is "tag-verified on the way out". This
        // is the arm that catches a table rotation forgot to re-tag; the
        // snapshot arms cannot, because such a row is byte-identical and
        // simply stops verifying.
        let unverified = diff(&before.verified, &after.verified);
        assert!(
            unverified.is_empty() && before.verified == after.verified,
            "a rotation left a tag-verifying reader failing. Some table's tag \
             was not re-keyed — every table carrying a `tag` column needs a \
             sweep in `rotate_keys`.{unverified}"
        );
        // Per GROUP, not over the whole vector: each keyed family rotation is
        // supposed to recompute must actually have moved. The fixture
        // populates all four, so an empty group is itself a failure.
        for ((name, b), (_, a)) in before.rekeyed.iter().zip(after.rekeyed.iter()) {
            assert!(
                !b.is_empty(),
                "premise: the fixture must populate {name} for this arm to \
                 mean anything"
            );
            assert_ne!(
                b, a,
                "rotation did NOT re-key {name}. It is keyed with the vault \
                 mac, which this rotation replaced, so leaving it makes every \
                 later read of it fail — and if it is unchanged the \
                 stability assertions above prove nothing, because the \
                 rotation may simply not have run"
            );
        }

        // ---- the re-derivation arm ------------------------------------
        // Derive every reference AGAIN, under the new keys, and require it
        // to land on the row that is already there. This is the arm that
        // sees a recipe keyed with rotatable material; the snapshot above
        // cannot, because rotation does not re-derive ids.
        assert_eq!(
            drawer("Ada migrated auth to PASETO in June.", 0).id,
            src_id,
            "a drawer id moved: it is derived from vault key material"
        );
        store
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
        store
            .kg_add("heron", "nests-in", "the reeds", None, None, 0.9, None)
            .unwrap();
        store.upsert(&src).unwrap();
        assert_eq!(
            store.create_tunnel("wing", "wing", "self-link").unwrap(),
            tunnel_id,
            "a tunnel id moved after rotation"
        );
        let counts_after = {
            let kg = store.kg_stats().unwrap();
            (kg.triples, kg.entities, store.count().unwrap())
        };
        assert_eq!(
            counts_before, counts_after,
            "re-deriving a reference after the rotation created a SECOND row \
             instead of landing on the first: (triples, entities, drawers). \
             An identifier is derived from rotatable key material — the A10 \
             defect, verbatim"
        );
        // The re-derivation arm WROTE — an idempotent write still appends an
        // audit record, which is correct: the chain records that the
        // operation happened, not only that it changed something. So the
        // reference list grows by those labels and nothing else moves.
        let settled = references(&store);
        assert_eq!(
            before.stable, settled.stable,
            "re-deriving a reference rewrote one of the existing ones"
        );
        assert!(
            settled.audit.starts_with(&before.audit),
            "re-deriving APPENDED audit labels, which is correct, but it must \
             not have reordered or rewritten the ones already there:\n{:?}\n{:?}",
            before.audit,
            settled.audit
        );
        assert!(
            settled.audit.len() > before.audit.len(),
            "premise: the re-derivation arm really did write"
        );

        // And a cold reopen agrees, so the stability is on disk rather than
        // in this handle's caches.
        drop(store);
        let store = reopen(&dir);
        let cold = references(&store);
        assert_eq!(
            settled.stable, cold.stable,
            "references moved across a reopen"
        );
        assert_eq!(
            settled.audit, cold.audit,
            "audit labels moved across a reopen"
        );
        assert!(store.verify().unwrap().ok());
    }

    /// **The gate that makes "rotation forgot an artifact" un-repeatable.**
    ///
    /// This class has now cost four separate defects, each found by a
    /// different accident and never by a test: `terms` was re-sealed and its
    /// neighbour `name_rest` was not (caught by the e2e, on `export`);
    /// `meta.kg_blind_secret` was not in the re-seal list either (caught by a
    /// new rotation test); and `wing_trust` + `retention_policy` were never
    /// re-TAGGED at all, so a routine rotation broke the trust floor and
    /// retention enforcement permanently (caught by a review, not by the
    /// suite). CLAUDE.md's rule — *every sealed column and every sealed meta
    /// value needs a line in `rotate.rs`* — was prose, and prose is what
    /// keeps failing.
    ///
    /// Two halves, both **source-level**, on the
    /// `admission_divert_has_exactly_one_caller` /
    /// `write_telemetry_has_exactly_one_emitter` precedent. A behavioural
    /// test cannot serve here: it can only cover the artifact families the
    /// fixture happens to populate, which is exactly how a missing line
    /// stayed invisible each time.
    ///
    /// 1. **Every at-rest AAD domain the crate seals under must be named in
    ///    `rotate.rs`.** Extracted from the format-string literal passed to
    ///    `content_at_rest` / `index_at_rest` / `tokens_at_rest`, reduced to
    ///    its leading static prefix so `format!("kgname/{blind}")` and
    ///    `format!("kgname/{name}")` compare equal — a mismatched *variable*
    ///    is a different (and real) hazard that the behavioural gate covers
    ///    by reading rows back.
    /// 2. **Every table carrying a `tag` column must be named in
    ///    `rotate.rs`.** A tag is by definition keyed with the vault mac,
    ///    which rotation replaces, so a tagged table with no sweep is a table
    ///    that stops verifying. Extracted from the `CREATE TABLE` statements
    ///    in the crate's own schema, not from a hand-written list.
    ///
    /// It fails in **both** directions: a new artifact with no reseal line
    /// fails, and this test naming something the crate no longer has fails
    /// too, so the allow-lists cannot rot into decoration.
    #[test]
    fn rotation_names_every_key_derived_artifact() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let read = |name: &str| {
            std::fs::read_to_string(src.join(name)).expect("the crate's own sources are readable")
        };
        // **Only the non-test half of `rotate.rs` counts.** The first version
        // of this gate searched the whole file, and this test's own fixture
        // says `set_wing_trust` and `set_retention` — so half 2 would have
        // been satisfied by the test text and passed with the sweeps deleted.
        // A gate that its own fixture satisfies is the failure mode this
        // project keeps paying for; verified by deleting each sweep.
        let rotate_full = read("rotate.rs");
        let rotate_prod = rotate_full
            .split_once("#[cfg(test)]")
            .map(|(prod, _)| prod)
            .expect("rotate.rs has a test module");
        // **Comments do not count, and neither does a struct field name.**
        // The second version of this gate used `contains` over the whole
        // production text and passed with the retention sweep's SQL deleted,
        // because the words `retention_policy` still appeared in a doc
        // comment and in `RotationReport::retention_policies`. A gate
        // satisfied by prose is not a gate — the same mistake as a substring
        // scan against a hex digest, third instance in this branch. So:
        // strip comment lines, and require the name in a real SQL context.
        let rotate_src: String = rotate_prod
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !(t.starts_with("//") || t.starts_with("*") || t.starts_with("/*"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        let mut all = String::new();
        for entry in std::fs::read_dir(&src).expect("readable") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                all.push_str(&std::fs::read_to_string(&path).unwrap());
                all.push('\n');
            }
        }

        // ---- half 1: sealed AAD domains ----
        // The needles are split so this test's own text is not a match.
        let seals = [
            concat!("content", "_at_rest("),
            concat!("index", "_at_rest("),
            concat!("tokens", "_at_rest("),
        ];
        let mut domains: std::collections::BTreeSet<String> = Default::default();
        for line in all.lines() {
            let t = line.trim_start();
            if t.starts_with("//") || t.starts_with("///") || t.starts_with("*") {
                continue;
            }
            for needle in seals {
                let Some(at) = line.find(needle) else {
                    continue;
                };
                let rest = &line[at + needle.len()..];
                // The domain is the first string literal on the line after
                // the call: `"kg/blind-secret"` or `&format!("kg/{id}")`.
                let Some(q) = rest.find('"') else { continue };
                let after = &rest[q + 1..];
                let Some(end) = after.find('"') else { continue };
                let lit = &after[..end];
                // Reduce to the leading static prefix: everything before the
                // first `{`. A bare `"{id}"`-style domain reduces to empty
                // and is skipped — the drawer content domain is the record id
                // itself and has no prefix to name.
                let prefix: String = lit.chars().take_while(|c| *c != '{').collect();
                if prefix.is_empty() {
                    continue;
                }
                domains.insert(prefix);
            }
        }
        assert!(
            domains.len() >= 8,
            "premise: the extractor actually found the sealed domains, got {domains:?}"
        );
        let missing: Vec<&String> = domains
            .iter()
            .filter(|d| !rotate_src.contains(d.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "these at-rest AAD domains are sealed somewhere in this crate and \
             are named NOWHERE in rotate.rs, so a key rotation leaves them \
             sealed under retired keys and they become unreadable: {missing:?}\n\
             (found domains: {domains:?})"
        );

        // ---- half 2: tables carrying a `tag` column ----
        // Parsed from the crate's own CREATE TABLE statements: a table whose
        // body mentions a `tag` column is HMAC-covered, and rotation replaces
        // the mac key.
        let mut tagged: std::collections::BTreeSet<String> = Default::default();
        let mut rest = all.as_str();
        while let Some(at) = rest.find("CREATE TABLE IF NOT EXISTS ") {
            rest = &rest[at + "CREATE TABLE IF NOT EXISTS ".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            // The body up to the closing paren of the statement.
            let body_end = rest.find(");").unwrap_or(rest.len());
            let body = &rest[..body_end];
            if body.contains("tag ") || body.contains("tag  ") {
                tagged.insert(name);
            }
        }
        assert!(
            tagged.len() >= 5,
            "premise: the schema parser found the tagged tables, got {tagged:?}"
        );
        // One exemption, and it carries its reason — the `priced` inventory's
        // rule that every table is either covered or justified as not.
        // Adding a name here is where someone has to argue for it in review.
        const NOT_RETAGGED: &[(&str, &str)] = &[(
            "audit",
            "rotation preserves every audit.tag byte VERBATIM as historical \
             evidence and re-keys the CHAIN over them instead — the tags of \
             superseded or deleted content cannot be recomputed because their \
             plaintext is gone by design. It is SELECTed, never UPDATEd.",
        )];
        // Both directions: an exemption for a table that no longer carries a
        // tag is a stale entry and fails too.
        let stale: Vec<&str> = NOT_RETAGGED
            .iter()
            .map(|(t, _)| *t)
            .filter(|t| !tagged.contains(*t))
            .collect();
        assert!(
            stale.is_empty(),
            "these tables are exempted from re-tagging but no longer carry a \
             `tag` column — delete the exemption: {stale:?}"
        );
        // A SQL context, not a mere mention: rotation must actually SELECT
        // from and UPDATE the table.
        let untouched: Vec<&String> = tagged
            .iter()
            .filter(|t| !NOT_RETAGGED.iter().any(|(x, _)| *x == t.as_str()))
            .filter(|t| {
                !(rotate_src.contains(&format!("FROM {t}"))
                    && rotate_src.contains(&format!("UPDATE {t} ")))
            })
            .collect();
        assert!(
            untouched.is_empty(),
            "these tables carry an HMAC `tag` column and are named NOWHERE in \
             rotate.rs, so a key rotation leaves the tag keyed with the \
             retired mac key and every read of the row raises a FALSE \
             integrity verdict: {untouched:?}\n(found tagged tables: {tagged:?})"
        );
    }

    /// A10: the graph's SEALED words survive a rotation, on every surface
    /// that reads them.
    ///
    /// This is the test that was missing when `terms` was re-sealed and its
    /// neighbour `name_rest` was not: the unit suite passed, and the e2e
    /// failed on `export`, `kg entities` and `kg query` at once, because a
    /// blob sealed under the OLD enc key cannot be opened under the new
    /// one. Rotation's contract is byte-exact reseal of *every* artifact,
    /// and a sealed column with no line in that pass is simply lost.
    ///
    /// Driven through the public readers rather than the columns, because
    /// that is where the failure showed: `all_triples` collects into a
    /// `Result`, so one unreadable row takes out every KG read at once.
    #[test]
    fn rotation_keeps_the_sealed_graph_readable() {
        let (dir, mut store) = seeded(SecurityLevel::Sealed);
        store
            .kg_add("heron", "feeds-on", "small fish", None, None, 0.8, None)
            .unwrap();
        let before = store.kg_query_entity("heron", None, "outgoing").unwrap();
        assert_eq!(before.len(), 2, "premise: two facts before rotating");

        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let next = mgr.rotation_candidate("r").unwrap();
        store.rotate_keys(next).unwrap();

        for (what, mut s) in [("in-place", store), ("reopened", reopen(&dir))] {
            let facts = s.kg_query_entity("heron", None, "outgoing").unwrap();
            assert_eq!(facts.len(), 2, "{what}: facts lost");
            assert!(
                facts.iter().any(|t| t.object == "the reeds"),
                "{what}: objects lost"
            );
            assert!(
                facts.iter().all(|t| t.subject == "heron"),
                "{what}: the sealed SUBJECT did not survive: {facts:?}"
            );
            assert!(
                s.kg_entities(10, 0)
                    .unwrap()
                    .iter()
                    .any(|(n, _, _)| n == "heron"),
                "{what}: the sealed entity NAME did not survive"
            );
            // Export decodes every row, so it fails on the first bad one —
            // the shape the e2e hit.
            assert_eq!(s.kg_export().unwrap().len(), 2, "{what}: export");
            assert!(!s.kg_export_entities().unwrap().is_empty(), "{what}");
            assert!(s.verify().unwrap().ok(), "{what}: verify");
            // And a fact re-added after the rotation still lands on the
            // same row: ids are keyed with the KG secret, which rotation
            // re-seals rather than re-derives.
            s.kg_add("heron", "feeds-on", "small fish", None, None, 0.8, None)
                .unwrap();
            assert_eq!(s.kg_stats().unwrap().triples, 2, "{what}: id stability");
        }
    }

    #[test]
    fn rotation_reseals_everything_and_survives_reopen() {
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let (dir, mut store) = seeded(level);
            // Sealed leg also exercises the opt-in PQ page tier: pages are
            // key-derived artifacts and must rotate byte-exact like rows.
            let old_page_blob: Option<Vec<u8>> = if level == SecurityLevel::Sealed {
                store.set_pq(true);
                store.set_pq_pages(1);
                let _ = store
                    .search(
                        "heron verbatim",
                        &crate::SearchOptions {
                            morph_lang: Default::default(),
                            wing: None,
                            room: None,
                            limit: 3,
                            room_cap: None,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                Some(
                    store
                        .conn
                        .query_row("SELECT blob FROM pq_page LIMIT 1", [], |r| r.get(0))
                        .expect("page tier built"),
                )
            } else {
                None
            };
            let old_salt = {
                let raw = std::fs::read_to_string(dir.path().join("vaults/r/vault.json")).unwrap();
                raw
            };
            let old_content_blob: Vec<u8> = store
                .conn
                .query_row("SELECT content FROM drawers WHERE seq = 1", [], |r| {
                    r.get(0)
                })
                .unwrap();

            let mgr = VaultManager::open(dir.path(), None).unwrap();
            let candidate = mgr.rotation_candidate("r").unwrap();
            let report = store.rotate_keys(candidate).unwrap();
            assert_eq!(report.drawers, 3);
            assert_eq!(report.kg_triples, 1);
            assert_eq!(report.tunnels, 1);
            assert!(report.audit_entries >= 5);

            // Same store keeps working under the new keys.
            assert!(store.verify().unwrap().ok());
            let hits = store
                .search(
                    "heron verbatim",
                    &crate::SearchOptions {
                        morph_lang: Default::default(),
                        wing: None,
                        room: None,
                        limit: 3,
                        room_cap: None,
                        ..Default::default()
                    },
                )
                .unwrap();
            assert!(hits.iter().any(|h| h.drawer.content.contains("heron")));

            // Manifest swapped in place, staging file gone, salt changed.
            let new_manifest =
                std::fs::read_to_string(dir.path().join("vaults/r/vault.json")).unwrap();
            assert_ne!(old_salt, new_manifest);
            assert!(!dir.path().join("vaults/r/vault.json.next").exists());

            // Sealed blobs actually changed bytes; hmac-only stores plaintext.
            let new_content_blob: Vec<u8> = store
                .conn
                .query_row("SELECT content FROM drawers WHERE seq = 1", [], |r| {
                    r.get(0)
                })
                .unwrap();
            match level {
                SecurityLevel::Sealed => assert_ne!(old_content_blob, new_content_blob),
                SecurityLevel::HmacOnly => assert_eq!(old_content_blob, new_content_blob),
            }
            if let Some(old_blob) = &old_page_blob {
                assert!(report.pq_pages >= 1, "pages must be in the reseal sweep");
                let new_blob: Vec<u8> = store
                    .conn
                    .query_row("SELECT blob FROM pq_page LIMIT 1", [], |r| r.get(0))
                    .unwrap();
                assert_ne!(old_blob, &new_blob, "page blobs re-sealed");
                assert_eq!(
                    store.pq_count_get("rowcount").unwrap(),
                    3,
                    "sealed commitment readable under the new keys"
                );
            }

            // A cold reopen derives the new keys from the swapped manifest.
            drop(store);
            let store = reopen(&dir);
            assert!(store.verify().unwrap().ok());

            // Keyed fingerprints were re-keyed: duplicate lookup still hits.
            assert!(store
                .check_duplicate("the heron files verbatim drawers")
                .unwrap()
                .is_some());
        }
    }

    #[test]
    fn crash_before_commit_discards_staging_manifest() {
        let (dir, store) = seeded(SecurityLevel::Sealed);
        drop(store);
        // Stage a candidate manifest but never run the re-seal transaction —
        // the crash-before-commit window.
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let mut candidate = mgr.rotation_candidate("r").unwrap();
        candidate
            .save_manifest_pending(&undercroft_vault::Vault::chain_genesis_hex(), 0)
            .unwrap();
        assert!(dir.path().join("vaults/r/vault.json.next").exists());

        let store = reopen(&dir);
        assert!(store.verify().unwrap().ok(), "old keys must still verify");
        assert!(
            !dir.path().join("vaults/r/vault.json.next").exists(),
            "stale staging manifest must be discarded"
        );
    }

    #[test]
    fn crash_after_commit_promotes_staging_manifest() {
        let (dir, mut store) = seeded(SecurityLevel::Sealed);
        let old_manifest = std::fs::read(dir.path().join("vaults/r/vault.json")).unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let candidate = mgr.rotation_candidate("r").unwrap();
        store.rotate_keys(candidate).unwrap();
        drop(store);
        // Reconstruct the crash-after-commit window: the database committed
        // under the new keys, but the manifest swap never happened — put the
        // promoted manifest back into staging and restore the old one.
        let vdir = dir.path().join("vaults/r");
        std::fs::rename(vdir.join("vault.json"), vdir.join("vault.json.next")).unwrap();
        std::fs::write(vdir.join("vault.json"), &old_manifest).unwrap();

        let store = reopen(&dir);
        assert!(store.verify().unwrap().ok(), "promoted keys must verify");
        assert!(
            !vdir.join("vault.json.next").exists(),
            "staging manifest must have been promoted"
        );
        assert!(store
            .check_duplicate("rotation must not lose a word")
            .unwrap()
            .is_some());
    }

    /// The grounding blob is sealed under its own AAD domain *and* sits
    /// inside the triple's canonical bytes, so rotation has to re-seal it and
    /// then tag the new bytes. Missing either half turns every grounded fact
    /// into a tamper alarm the moment the key changes.
    #[test]
    fn grounding_survives_rotation() {
        use undercroft_core::support::{Grounding, Support};
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let dir = TempDir::new().unwrap();
            let mgr = VaultManager::open(dir.path(), None).unwrap();
            let vault = mgr.create("r", level).unwrap();
            let mut store = PalaceStore::open(vault).unwrap();
            let note = "Ada migrated auth to PASETO in June.";
            let src = drawer(note, 0);
            let src_id = src.id.clone();
            store.upsert(&src).unwrap();

            let stated = Support::evaluate(note, &["migrated auth to PASETO"]);
            store
                .kg_add_grounded(
                    "ada",
                    "migrated_auth_to",
                    "paseto",
                    None,
                    None,
                    0.8,
                    (&src_id, note),
                    Some(&stated),
                    // Attributed to a named extractor so this test also pins
                    // that rotation carries extractor identity into the new
                    // tag (kg_verify below fails if it is dropped).
                    Some("test-extractor-1b"),
                )
                .unwrap();
            // Checked, unsupported — must stay distinguishable from both the
            // stated fact and from a fact nobody ever checked.
            store
                .kg_add_grounded(
                    "ada",
                    "works_with",
                    "rust",
                    None,
                    None,
                    0.8,
                    (&src_id, note),
                    Some(&Support::default()),
                    None,
                )
                .unwrap();
            store
                .kg_add("ada", "knows", "bob", None, None, 1.0, None)
                .unwrap();

            let mgr = VaultManager::open(dir.path(), None).unwrap();
            let candidate = mgr.rotation_candidate("r").unwrap();
            store.rotate_keys(candidate).unwrap();
            drop(store);

            let store = reopen(&dir);
            assert!(
                store.kg_verify().unwrap().is_empty(),
                "{level:?}: rotation must not read as tampering"
            );
            let facts = store.kg_query_entity("ada", None, "outgoing").unwrap();
            let by = |p: &str| {
                facts
                    .iter()
                    .find(|t| t.predicate == p)
                    .unwrap_or_else(|| panic!("{p} missing"))
                    .grounding()
            };
            assert_eq!(by("migrated_auth_to"), Grounding::Stated, "{level:?}");
            assert_eq!(by("works_with"), Grounding::Background, "{level:?}");
            assert_eq!(by("knows"), Grounding::Unevaluated, "{level:?}");
            // And the span still points at the right words after re-sealing.
            let spans = &facts
                .iter()
                .find(|t| t.predicate == "migrated_auth_to")
                .unwrap()
                .support
                .as_ref()
                .unwrap()
                .spans;
            let (o, l) = (spans[0].offset as usize, spans[0].len as usize);
            assert_eq!(&note[o..o + l], "migrated auth to PASETO", "{level:?}");
        }
    }

    #[test]
    fn receipts_survive_rotation() {
        use crate::kg::ReceiptVerdict;
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let dir = TempDir::new().unwrap();
            let mgr = VaultManager::open(dir.path(), None).unwrap();
            let vault = mgr.create("r", level).unwrap();
            let mut store = PalaceStore::open(vault).unwrap();
            let src = drawer("Ada migrated auth to PASETO in June.", 0);
            let src_id = src.id.clone();
            store.upsert(&src).unwrap();
            store
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
            assert_eq!(
                store.kg_verify_receipts().unwrap()[0].verdict,
                ReceiptVerdict::Verified
            );
            // A drawer supersession rides the same rotation: its keyed
            // receipt must re-key beside the KG one.
            let newer = drawer("Ada moved auth back to JWT in July.", 1)
                .with_supersedes(Some(src_id.clone()));
            store.upsert(&newer).unwrap();
            assert_eq!(
                store.verify_supersessions().unwrap()[0].verdict,
                ReceiptVerdict::Verified
            );

            let mgr = VaultManager::open(dir.path(), None).unwrap();
            let candidate = mgr.rotation_candidate("r").unwrap();
            store.rotate_keys(candidate).unwrap();
            drop(store);

            // After a full key rotation the keyed receipt_tag is re-computed
            // under the new key while the source fingerprint — keyed with the
            // STORED secret — is unchanged: the citation must still verify,
            // not read as tamper.
            let store = reopen(&dir);
            let r = store.kg_verify_receipts().unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(
                r[0].verdict,
                ReceiptVerdict::Verified,
                "receipt must re-key and still verify after rotation ({level:?})"
            );
            let sup = store.verify_supersessions().unwrap();
            assert_eq!(sup.len(), 1);
            assert_eq!(
                sup[0].verdict,
                ReceiptVerdict::Verified,
                "supersession receipt must re-key and still verify after rotation ({level:?})"
            );
            assert!(store.verify().unwrap().ok());
        }
    }
}
