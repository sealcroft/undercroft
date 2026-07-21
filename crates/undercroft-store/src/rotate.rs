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
        }
        let mut drawer_upds = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT seq, id, meta_json, content, embedding, fp FROM drawers ORDER BY seq",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, Option<Vec<u8>>>(5)?,
                ))
            })?;
            for row in rows {
                let (seq, id, meta_json, content, emb, fp) = row?;
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
                drawer_upds.push(DrawerUpd {
                    seq,
                    content: new_content,
                    emb: new_emb,
                    tag,
                    fp,
                });
            }
        }
        report.drawers = drawer_upds.len();

        // kg entities: tag over the stored fields.
        let mut entity_upds: Vec<(String, Vec<u8>)> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT id, name, etype, created_at FROM kg_entities")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (id, name, etype, created) = row?;
                let can = format!("{id}\x1f{name}\x1f{etype}\x1f{created}");
                entity_upds.push((id, next.tag(can.as_bytes()).to_vec()));
            }
        }
        report.kg_entities = entity_upds.len();

        // kg triples: object re-sealed (content domain `kg/{id}`), tag over
        // the new at-rest object.
        let mut triple_upds: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT id, subject, predicate, object, valid_from, valid_to, confidence \
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
                ))
            })?;
            for row in rows {
                let (id, s, p, object, vf, vt, conf) = row?;
                let new_object = self
                    .vault
                    .reseal_at_rest(&next, &format!("kg/{id}"), &object)?;
                let tag = next
                    .tag(&crate::kg::triple_canonical(
                        &id,
                        &s,
                        &p,
                        &new_object,
                        &vf,
                        &vt,
                        conf,
                    ))
                    .to_vec();
                triple_upds.push((id, new_object, tag));
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
        let mut fde_upds: Vec<(String, Vec<u8>)> = Vec::new();
        let mut meta_upds: Vec<(&'static str, &'static str, Vec<u8>)> = Vec::new();
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
                ("tok_meta", "codebook", "tok/codebook/tok"),
                ("pq_meta", "codebook", "pq/codebook/pq"),
                ("pq_meta", "ivf", "pq/ivf/pq"),
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
        }
        report.token_matrices = tok_upds.len();
        report.pq_rows = pq_upds.len();
        report.fde_rows = fde_upds.len();
        report.meta_artifacts = meta_upds.len();

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
                    "UPDATE drawers SET content = ?2, embedding = ?3, tag = ?4, fp = ?5 \
                     WHERE seq = ?1",
                )?;
                for d in &drawer_upds {
                    up.execute(params![d.seq, d.content, d.emb, d.tag, d.fp])?;
                }
                let mut up = tx.prepare("UPDATE kg_entities SET tag = ?2 WHERE id = ?1")?;
                for (id, tag) in &entity_upds {
                    up.execute(params![id, tag])?;
                }
                let mut up =
                    tx.prepare("UPDATE kg_triples SET object = ?2, tag = ?3 WHERE id = ?1")?;
                for (id, object, tag) in &triple_upds {
                    up.execute(params![id, object, tag])?;
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
    fn drop_derived_caches(&self) {
        *self.emb_cache.borrow_mut() = None;
        *self.pq.borrow_mut() = None;
        *self.ivf.borrow_mut() = None;
        *self.pq_cache.borrow_mut() = None;
        self.pq_verified.set(false);
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

    #[test]
    fn rotation_reseals_everything_and_survives_reopen() {
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let (dir, mut store) = seeded(level);
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
                        wing: None,
                        room: None,
                        limit: 3,
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
}
