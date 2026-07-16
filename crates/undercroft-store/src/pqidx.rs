//! On-disk PQ candidate prefilter — bounded-RAM retrieval for hmac-only vaults.
//!
//! The semantic analogue of the FTS5 BM25 prefilter, and like it **hmac-only
//! vaults only**: PQ codes are plaintext-derived, and sealed vaults never
//! persist plaintext-derived indexes to disk (an encrypted-at-rest variant is
//! the sealed-tier follow-up — see docs/RETRIEVAL_SCALING.md).
//!
//! Each drawer's embedding is product-quantized to a few dozen bytes
//! ([`crate::pq`]) and stored in a `drawer_pq` table; the trained codebook
//! (~hundreds of KB) is persisted once in `pq_meta` and cached in RAM. A
//! search computes per-query ADC tables and streams the codes from SQLite —
//! resident memory is the codebook + tables, **not** O(corpus) vectors, unlike
//! the in-memory HNSW prototype.
//!
//! Coherence: `write_drawer` encodes each new/updated row incrementally with
//! the persisted codebook; a cheap matched-count check on every search
//! detects drift (crash between writes, missed rows) and re-encodes from
//! scratch — mirroring the FTS index's self-heal. Deleted drawers leave
//! orphaned code rows that the `JOIN drawers` excludes; they're swept on the
//! next rebuild.

use undercroft_vault::SecurityLevel;
use rusqlite::{params, OptionalExtension};

use crate::pq::ProductQuantizer;
use crate::{PalaceStore, StoreError};

/// k-means iterations and training-sample cap: PQ codebooks tolerate sampling
/// well, and training is a one-time cost we keep to seconds.
const PQ_TRAIN_ITERS: usize = 12;
const PQ_TRAIN_SAMPLE: usize = 4096;

impl PalaceStore {
    /// Enable (or disable) the on-disk PQ ANN prefilter. **hmac-only vaults
    /// only** — on sealed vaults this is a documented no-op (the invariant
    /// forbids plaintext-derived indexes on disk), mirroring the FTS5 rule.
    pub fn set_pq(&mut self, on: bool) {
        self.pq_enabled = on && matches!(self.vault.level(), SecurityLevel::HmacOnly);
    }

    fn pq_schema(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS drawer_pq (
                 seq  INTEGER PRIMARY KEY,
                 code BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS pq_meta (
                 key   TEXT PRIMARY KEY,
                 value BLOB NOT NULL
             );",
        )?;
        Ok(())
    }

    /// Vector top-`k` candidate `seq`s by streaming ADC over the on-disk
    /// codes. `None` ⇒ no usable index (empty corpus, or a dimension PQ can't
    /// split); the caller falls back to the full scan.
    pub(crate) fn pq_candidates(
        &self,
        qvec: &[f32],
        k: usize,
    ) -> Result<Option<Vec<i64>>, StoreError> {
        self.pq_schema()?;
        let drawers: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM drawers", [], |r| r.get(0))?;
        if drawers == 0 {
            return Ok(None);
        }
        // Self-heal: every live drawer must have a code row (orphans from
        // deletes are excluded by the join and are harmless).
        let matched: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM drawer_pq p JOIN drawers d ON d.seq = p.seq",
            [],
            |r| r.get(0),
        )?;
        if (self.pq.borrow().is_none() || matched != drawers) && !self.pq_build()? {
            return Ok(None);
        }
        let pq_ref = self.pq.borrow();
        let Some(pq) = pq_ref.as_ref() else {
            return Ok(None);
        };
        let tables = pq.distance_tables(qvec);
        let mut stmt = self
            .conn
            .prepare("SELECT p.seq, p.code FROM drawer_pq p JOIN drawers d ON d.seq = p.seq")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut scored: Vec<(f32, i64)> = Vec::new();
        for row in rows {
            let (seq, code) = row?;
            scored.push((pq.adc(&tables, &code), seq));
        }
        if scored.len() > k {
            scored.select_nth_unstable_by(k - 1, |a, b| {
                a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
            });
            scored.truncate(k);
        }
        Ok(Some(scored.into_iter().map(|(_, seq)| seq).collect()))
    }

    /// Load-or-train the codebook and (re)encode every drawer. Returns `false`
    /// when the corpus can't be quantized (empty, or dimension not divisible
    /// into subspaces) — the caller falls back to the full scan.
    fn pq_build(&self) -> Result<bool, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, id, embedding FROM drawers")?;
        let rows: Vec<(i64, String, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        if rows.is_empty() {
            return Ok(false);
        }
        let mut items = Vec::with_capacity(rows.len());
        for (seq, id, rest) in rows {
            let emb =
                self.vault
                    .embedding_from_rest(&id, &rest)
                    .map_err(|e| StoreError::CorruptRow {
                        id: id.clone(),
                        reason: e.to_string(),
                    })?;
            items.push((seq, emb));
        }

        let stored: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM pq_meta WHERE key = 'codebook'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let pq = match stored.and_then(|b| ProductQuantizer::from_bytes(&b)) {
            Some(pq) => pq,
            None => {
                // Subspaces of 8 dims (fall back to 4) — every common
                // embedding dim (384/512/768/1024) divides by 8.
                let dim = items[0].1.len();
                let Some(m) = [8usize, 4]
                    .iter()
                    .find(|&&dsub| dim % dsub == 0)
                    .map(|&dsub| dim / dsub)
                else {
                    return Ok(false);
                };
                // Train on an even sample; codebooks tolerate sampling well.
                let stride = items.len().div_ceil(PQ_TRAIN_SAMPLE).max(1);
                let sample: Vec<Vec<f32>> = items
                    .iter()
                    .step_by(stride)
                    .map(|(_, v)| v.clone())
                    .collect();
                let Some(pq) = ProductQuantizer::train(&sample, m, PQ_TRAIN_ITERS) else {
                    return Ok(false);
                };
                self.conn.execute(
                    "INSERT OR REPLACE INTO pq_meta (key, value) VALUES ('codebook', ?1)",
                    params![pq.to_bytes()],
                )?;
                pq
            }
        };

        self.conn.execute("DELETE FROM drawer_pq", [])?;
        let mut ins = self
            .conn
            .prepare("INSERT OR REPLACE INTO drawer_pq (seq, code) VALUES (?1, ?2)")?;
        for (seq, vec) in &items {
            ins.execute(params![seq, pq.encode(vec)])?;
        }
        *self.pq.borrow_mut() = Some(pq);
        Ok(true)
    }

    /// Incrementally encode one written drawer with the cached codebook
    /// (called from `write_drawer` after commit). Missing codebook or any
    /// failure is fine: the next search's matched-count check rebuilds.
    pub(crate) fn pq_encode_row(&self, id: &str, embedding: &[f32]) {
        if !self.pq_enabled {
            return;
        }
        let code = match self.pq.borrow().as_ref() {
            Some(pq) => pq.encode(embedding),
            None => return,
        };
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO drawer_pq (seq, code)
             SELECT seq, ?2 FROM drawers WHERE id = ?1",
            params![id, code],
        );
    }
}
