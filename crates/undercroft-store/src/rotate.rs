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
                // canonical (drawer id + superseded id + unkeyed
                // fingerprint), new mac key: the kg receipt re-key one
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
                let can = format!("{id}\x1f{name}\x1f{etype}\x1f{created}");
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
                entity_upds.push((id, next.tag(can.as_bytes()).to_vec(), new_name_rest));
            }
        }
        report.kg_entities = entity_upds.len();

        // kg triples: object re-sealed (content domain `kg/{id}`), tag over
        // the new at-rest object. A fact carrying a receipt also gets its
        // keyed receipt_tag re-computed under the new key — the receipt's
        // source fingerprint is unkeyed SHA-256 and stays byte-identical, so
        // the citation binding survives rotation verbatim.
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
                // canonical: id + citation + unkeyed source fingerprint).
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
            tx.execute(
                "UPDATE chain_meta SET value = ?1 WHERE key = 'head'",
                params![head],
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
            // under the new key while the unkeyed source fingerprint is
            // unchanged — the citation must still verify, not read as tamper.
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
