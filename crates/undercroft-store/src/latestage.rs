//! Late-interaction (ColBERT) second stage — stored token matrices + MaxSim.
//!
//! The cross-encoder reranker costs one transformer forward **per candidate
//! per query**; this stage moves that work to ingest. When a
//! [`LateInteraction`] encoder is attached, every written drawer's content is
//! encoded once into a per-token matrix, int8-quantized
//! ([`undercroft_core::late::quantize_tokens`]), passed through
//! [`Vault::tokens_at_rest`] and stored in `drawer_tok`. A search encodes the
//! query in **one** forward and re-scores the fusion top-N by MaxSim over the
//! stored matrices — plain arithmetic, no per-candidate inference, so query
//! latency is independent of `top_n` and of core count.
//!
//! Security tiering: token matrices are plaintext-derived, but unlike the
//! PQ/FTS *prefilters* (plaintext side-tables, hmac-only only) this is a
//! per-candidate **rescore** store — sealed vaults get it too, because every
//! blob is AEAD-sealed under the `/tok` AAD domain. The
//! no-plaintext-derived-data-in-clear invariant holds at every level.
//!
//! Coherence is advisory like the PQ codes: a drawer written while the
//! encoder is attached carries its matrix; one written without (or whose
//! encode failed) simply has none and **keeps its fusion rank** during
//! rescore — enable the encoder before ingest for full coverage. Matrices
//! recorded under a different model name are ignored the same way (never
//! silently mixed). `delete_drawer` purges the row.

use undercroft_core::late::{dequantize_tokens, maxsim, quantize_tokens, LateInteraction};
use rusqlite::{params, OptionalExtension};

use crate::pq::ProductQuantizer;
use crate::{rerank_top_n, PalaceStore, SearchHit, StoreError, CODEBOOK_TOK};

/// Stored-matrix count at which the token codebook trains (v2 packing).
/// Below it, int8 (v1) is already small and PQ would train on too few
/// tokens. `UNDERCROFT_TOK_PQ_MIN` overrides; `off` disables v2 entirely.
pub(crate) const TOK_PQ_MIN_DEFAULT: usize = 256;
/// Sampling cap and k-means iterations for token-codebook training —
/// tokens are plentiful (hundreds per drawer), so a modest sample is ample.
const TOK_PQ_SAMPLE: usize = 16_384;
const TOK_PQ_ITERS: usize = 10;

/// Pack a PQ-coded token matrix (format v2): `[2][dim:u32][rows:u32]` then
/// `rows × code_len` bytes. Reading it back needs the vault's token
/// codebook — which is why portable artifacts always travel as v1.
fn pack_v2(dim: usize, rows: usize, codes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + codes.len());
    out.push(2u8);
    out.extend((dim as u32).to_le_bytes());
    out.extend((rows as u32).to_le_bytes());
    out.extend_from_slice(codes);
    out
}

pub(crate) fn unpack_v2(data: &[u8], code_len: usize) -> Option<(usize, usize, &[u8])> {
    if data.len() < 9 || data[0] != 2 {
        return None;
    }
    let dim = u32::from_le_bytes(data[1..5].try_into().ok()?) as usize;
    let rows = u32::from_le_bytes(data[5..9].try_into().ok()?) as usize;
    let codes = &data[9..];
    if dim == 0 || codes.len() != rows * code_len {
        return None;
    }
    Some((dim, rows, codes))
}

impl PalaceStore {
    /// Attach (or clear) the late-interaction encoder. With one set, writes
    /// store per-token matrices and searches re-score the fusion top-N by
    /// MaxSim. If a cross-encoder reranker is also set, the reranker wins
    /// (it is the more accurate, more expensive option).
    pub fn set_late(&mut self, late: Option<Box<dyn LateInteraction + Send + Sync>>) {
        self.late = late;
    }

    pub(crate) fn late_schema(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS drawer_tok (
                 id    TEXT PRIMARY KEY,
                 model TEXT NOT NULL,
                 tok   BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tok_meta (
                 key   TEXT PRIMARY KEY,
                 value BLOB NOT NULL
             );",
        )?;
        Ok(())
    }

    /// Load-or-train the token codebook (once per session). Returns whether
    /// a codebook is now cached. Training happens when at least
    /// `tok_pq_min` matrices exist for `model`; every stored v1 row is then
    /// repacked to v2 (PQ codes, ~8× smaller than int8) in one pass —
    /// pure re-encoding, no transformer forwards. The codebook persists in
    /// `tok_meta`, sealed like the matrices themselves; a codebook trained
    /// for a different model is discarded and retrained.
    pub(crate) fn tok_pq_ensure(&self, model: &str) -> bool {
        if self.tok_pq.borrow().is_some() {
            return true;
        }
        if self.tok_pq_checked.get() {
            return false;
        }
        self.tok_pq_checked.set(true);
        if self.late_schema().is_err() {
            return false;
        }
        // Stored codebook?
        let stored_model: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM tok_meta WHERE key = 'codebook_model'",
                [],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        if stored_model.as_deref() == Some(model.as_bytes()) {
            let blob: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT value FROM tok_meta WHERE key = 'codebook'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .ok()
                .flatten();
            if let Some(pq) = blob
                .and_then(|b| self.vault.tokens_from_rest("tok/codebook", &b).ok())
                .and_then(|b| ProductQuantizer::from_bytes(&b))
            {
                *self.tok_pq.borrow_mut() = Some(pq);
                return true;
            }
        }
        // Train when the corpus warrants it.
        let rows: i64 = match self.conn.query_row(
            "SELECT COUNT(*) FROM drawer_tok WHERE model = ?1",
            params![model],
            |r| r.get(0),
        ) {
            Ok(n) => n,
            Err(_) => return false,
        };
        if (rows as usize) < self.tok_pq_min {
            return false;
        }
        self.tok_pq_train_and_repack(model).unwrap_or(false)
    }

    /// Train the token codebook from the stored v1 matrices and repack them
    /// all to v2. Returns whether a codebook is now cached.
    fn tok_pq_train_and_repack(&self, model: &str) -> Result<bool, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, tok FROM drawer_tok WHERE model = ?1")?;
        let blobs: Vec<(String, Vec<u8>)> = stmt
            .query_map(params![model], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        drop(stmt);
        // Gather a keyed sample of token rows across the v1 matrices.
        let mut v1: Vec<(String, Vec<f32>, usize)> = Vec::new();
        for (id, blob) in &blobs {
            let Ok(packed) = self.vault.tokens_from_rest(id, blob) else {
                continue;
            };
            let Some((matrix, dim)) = dequantize_tokens(&packed) else {
                continue; // already v2, or garbage — skip
            };
            v1.push((id.clone(), matrix, dim));
        }
        let total_rows: usize = v1.iter().map(|(_, m, d)| m.len() / (*d).max(1)).sum();
        if total_rows == 0 {
            return Ok(false);
        }
        // Rank every token row under the vault's sample key and keep the
        // lowest — the same draw the PQ codebooks use, per (drawer, row), so a
        // bulk writer cannot predict which of their tokens shape the codebook
        // every other drawer's tokens are then coded against.
        // Rank every token row twice in one walk: once for the training draw,
        // once for an independent probe used to check the trained codebook.
        // The flattened walk order is the stratification axis, so row `i`
        // keeps its position in both. Below the cap neither is needed — the
        // whole corpus trains and a probe would sit inside the sample.
        let (chosen, ranks_probe): (Vec<usize>, Vec<u64>) = if TOK_PQ_SAMPLE >= total_rows {
            ((0..total_rows).collect(), Vec::new())
        } else {
            let mut ranks: Vec<u64> = Vec::with_capacity(total_rows);
            let mut probe: Vec<u64> = Vec::with_capacity(total_rows);
            for (id, matrix, dim) in &v1 {
                let mut ident = Vec::with_capacity(id.len() + 4);
                for r in 0..matrix.len() / (*dim).max(1) {
                    ident.clear();
                    ident.extend_from_slice(id.as_bytes());
                    ident.extend((r as u32).to_le_bytes());
                    ranks.push(self.vault.sample_rank(CODEBOOK_TOK, &ident));
                    probe.push(self.vault.sample_rank("tok-fit-probe", &ident));
                }
            }
            (
                crate::pqidx::stratified_keyed(total_rows, TOK_PQ_SAMPLE, |i| ranks[i]),
                probe,
            )
        };
        let mut sample: Vec<Vec<f32>> = Vec::with_capacity(chosen.len());
        let mut next = chosen.iter().peekable();
        let mut i = 0usize;
        for (_, matrix, dim) in &v1 {
            for row in matrix.chunks_exact(*dim) {
                if next.peek() == Some(&&i) {
                    sample.push(row.to_vec());
                    next.next();
                }
                i += 1;
            }
        }
        let dim = v1[0].2;
        let Some(m) = [8usize, 4]
            .iter()
            .find(|&&d| dim.is_multiple_of(d))
            .map(|&d| dim / d)
        else {
            return Ok(false);
        };
        let Some(pq) = ProductQuantizer::train(&sample, m, TOK_PQ_ITERS) else {
            return Ok(false);
        };
        // Check the fresh codebook against rows it did not train on — a second
        // keyed draw over the same walk, so it is not the training sample.
        // Only meaningful above the cap, where a sample was actually drawn.
        if total_rows > TOK_PQ_SAMPLE {
            let probe_at =
                crate::pqidx::stratified_keyed(total_rows, crate::pqidx::PQ_FIT_PROBE, |i| {
                    ranks_probe[i]
                });
            let mut probe: Vec<Vec<f32>> = Vec::with_capacity(probe_at.len());
            let mut next = probe_at.iter().peekable();
            let mut i = 0usize;
            for (_, matrix, dim) in &v1 {
                for row in matrix.chunks_exact(*dim) {
                    if next.peek() == Some(&&i) {
                        probe.push(row.to_vec());
                        next.next();
                    }
                    i += 1;
                }
            }
            self.warn_unrepresentative(CODEBOOK_TOK, &pq, &sample, &probe);
        }
        // Persist (sealed on sealed vaults), then repack every v1 row.
        let blob = self.vault.tokens_at_rest("tok/codebook", &pq.to_bytes());
        self.conn.execute(
            "INSERT OR REPLACE INTO tok_meta (key, value) VALUES ('codebook', ?1)",
            params![blob],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO tok_meta (key, value) VALUES ('codebook_model', ?1)",
            params![model.as_bytes()],
        )?;
        self.codebook_generation_bump(CODEBOOK_TOK);
        for (id, matrix, dim) in &v1 {
            let rows = matrix.len() / dim;
            let mut codes = Vec::with_capacity(rows * pq.code_len());
            for row in matrix.chunks_exact(*dim) {
                codes.extend(pq.encode(row));
            }
            let blob = self.vault.tokens_at_rest(id, &pack_v2(*dim, rows, &codes));
            self.conn.execute(
                "UPDATE drawer_tok SET tok = ?1 WHERE id = ?2",
                params![blob, id],
            )?;
        }
        *self.tok_pq.borrow_mut() = Some(pq);
        Ok(true)
    }

    /// Encode + store one written drawer's token matrix (called from
    /// `write_drawer` after commit). Advisory: any failure leaves the drawer
    /// without a matrix, which rescoring treats as "keep fusion rank".
    pub(crate) fn late_encode_row(&self, id: &str, content: &str) {
        let Some(late) = &self.late else {
            return;
        };
        if self.late_schema().is_err() {
            return;
        }
        let matrix = late.encode_doc(content);
        if matrix.is_empty() {
            return;
        }
        let packed = self.late_pack(&matrix, late.dim());
        let blob = self.vault.tokens_at_rest(id, &packed);
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO drawer_tok (id, model, tok) VALUES (?1, ?2, ?3)",
            params![id, late.model_name(), blob],
        );
        // MUVERA FDE from the matrix already in hand (no-op unless enabled).
        self.fde_encode_row(id, late.model_name(), &matrix, late.dim());
    }

    /// Pack a token matrix in the best live format: v2 (PQ codes, ~8× below
    /// int8) when the token codebook is cached, v1 (int8) otherwise. The two
    /// coexist and rescoring reads both, so packing upgrades are never a
    /// migration event.
    fn late_pack(&self, matrix: &[f32], dim: usize) -> Vec<u8> {
        match self.tok_pq.borrow().as_ref() {
            Some(pq) if dim > 0 && matrix.len().is_multiple_of(dim) => {
                let rows = matrix.len() / dim;
                let mut codes = Vec::with_capacity(rows * pq.code_len());
                for row in matrix.chunks_exact(dim) {
                    codes.extend(pq.encode(row));
                }
                pack_v2(dim, rows, &codes)
            }
            _ => quantize_tokens(matrix, dim),
        }
    }

    /// Purge a deleted drawer's token row (mirrors the PQ purge), and its
    /// FDE beside it.
    pub(crate) fn late_purge_row(&self, id: &str) {
        let _ = self
            .conn
            .execute("DELETE FROM drawer_tok WHERE id = ?1", params![id]);
        self.fde_purge_row(id);
    }

    /// Export one drawer's stored token matrix as a **portable artifact**:
    /// `(model_name, packed_plaintext)`. Token matrices are the expensive
    /// derived data (one transformer forward per drawer at ingest), and they
    /// are a pure function of `(content, model)` — so a migration bundle
    /// that carries them makes restore a copy instead of a recompute.
    /// `None` when the drawer has no stored matrix.
    pub fn token_artifact(&self, id: &str) -> Result<Option<(String, Vec<u8>)>, StoreError> {
        self.late_schema()?;
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT model, tok FROM drawer_tok WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((model, blob)) = row else {
            return Ok(None);
        };
        let packed =
            self.vault
                .tokens_from_rest(id, &blob)
                .map_err(|e| StoreError::CorruptRow {
                    id: id.to_string(),
                    reason: e.to_string(),
                })?;
        // Artifacts travel in the universal v1 (int8) packing: v2 needs this
        // vault's codebook, which doesn't leave the vault. Decode PQ rows
        // back to their centroid reconstruction and re-quantize.
        if packed.first() == Some(&2) {
            self.tok_pq_ensure(&model);
            let tok_pq = self.tok_pq.borrow();
            let Some(pq) = tok_pq.as_ref() else {
                return Err(StoreError::CorruptRow {
                    id: id.to_string(),
                    reason: "v2 token matrix without a codebook".into(),
                });
            };
            let Some((dim, rows, codes)) = unpack_v2(&packed, pq.code_len()) else {
                return Err(StoreError::CorruptRow {
                    id: id.to_string(),
                    reason: "v2 token matrix does not parse".into(),
                });
            };
            let mut matrix = Vec::with_capacity(rows * dim);
            for code in codes.chunks_exact(pq.code_len()) {
                matrix.extend(pq.decode(code));
            }
            return Ok(Some((model, quantize_tokens(&matrix, dim))));
        }
        Ok(Some((model, packed)))
    }

    /// Import a portable token artifact for `id`, re-sealed under **this**
    /// vault's key. Safe by construction: the packed matrix must parse, it
    /// is stored under its `model` name (rescoring only ever reads matrices
    /// whose model matches the attached encoder), and served results are
    /// still HMAC-verified — a wrong or malicious artifact can only
    /// mis-rank, never forge content. Restore therefore skips the
    /// per-drawer encode forward entirely.
    pub fn import_token_artifact(
        &mut self,
        id: &str,
        model: &str,
        packed: &[u8],
    ) -> Result<(), StoreError> {
        if dequantize_tokens(packed).is_none() {
            return Err(StoreError::CorruptRow {
                id: id.to_string(),
                reason: "token artifact does not parse".into(),
            });
        }
        self.late_schema()?;
        let blob = self.vault.tokens_at_rest(id, packed);
        self.conn.execute(
            "INSERT OR REPLACE INTO drawer_tok (id, model, tok) VALUES (?1, ?2, ?3)",
            params![id, model, blob],
        )?;
        Ok(())
    }

    /// Backfill token matrices for up to `limit` drawers that lack one under
    /// the attached encoder's model — the recovery path for palaces ingested
    /// before the encoder was attached, or restored from artifact-less
    /// bundles. Each pass is bounded so callers (CLI `repair`, a daemon
    /// tick) can spread the transformer forwards over time; searches served
    /// meanwhile keep fusion rank for unencoded drawers and improve as
    /// coverage grows. Returns `(encoded_this_pass, still_missing)`.
    pub fn late_backfill(&mut self, limit: usize) -> Result<(u64, u64), StoreError> {
        let Some(late) = &self.late else {
            return Err(StoreError::CorruptRow {
                id: "-".into(),
                reason: "no late-interaction encoder attached (set UNDERCROFT_RERANKER=colbert)"
                    .into(),
            });
        };
        self.late_schema()?;
        let missing: Vec<String> = self
            .conn
            .prepare(
                "SELECT d.id FROM drawers d
                 LEFT JOIN drawer_tok t ON t.id = d.id AND t.model = ?1
                 WHERE t.id IS NULL ORDER BY d.seq",
            )?
            .query_map(params![late.model_name()], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let total = missing.len() as u64;
        let mut encoded = 0u64;
        for id in missing.into_iter().take(limit) {
            let Some(d) = self.get(&id)? else { continue };
            let late = self.late.as_ref().expect("checked above");
            let matrix = late.encode_doc(&d.content);
            if matrix.is_empty() {
                continue;
            }
            let packed = self.late_pack(&matrix, late.dim());
            let blob = self.vault.tokens_at_rest(&id, &packed);
            self.conn.execute(
                "INSERT OR REPLACE INTO drawer_tok (id, model, tok) VALUES (?1, ?2, ?3)",
                params![id, late.model_name(), blob],
            )?;
            let (model, dim) = (late.model_name().to_string(), late.dim());
            self.fde_encode_row(&id, &model, &matrix, dim);
            encoded += 1;
        }
        Ok((encoded, total - encoded))
    }

    /// Re-score the fusion top-N hits by MaxSim over stored matrices, then
    /// re-sort that head. One query-encode forward total. Hits without a
    /// stored matrix (pre-attach writes, failed encodes, other model)
    /// keep their fusion score untouched — they compete on the original
    /// scale rather than being sunk to zero.
    pub(crate) fn late_rescore(&self, query: &str, hits: &mut [SearchHit]) {
        let Some(late) = &self.late else {
            return;
        };
        if self.late_schema().is_err() {
            return;
        }
        // Reuse the query matrix FDE candidate generation already encoded
        // for this exact query, if present (take() so a stale entry can
        // never leak across searches); otherwise pay the one forward here.
        let cached = self.qmatrix_cache.borrow_mut().take();
        let qmatrix = match cached {
            Some((q, m)) if q == query => m,
            _ => late.encode_query(query),
        };
        if qmatrix.is_empty() {
            return;
        }
        let pool = hits.len().min(rerank_top_n());
        let mut stmt = match self
            .conn
            .prepare("SELECT tok FROM drawer_tok WHERE id = ?1 AND model = ?2")
        {
            Ok(s) => s,
            Err(_) => return,
        };
        // MaxSim scores are sums over query tokens (unbounded scale) while
        // fusion scores live in ~[0,1]; mixing raw values would let every
        // scored hit trample the unscored ones. Normalize by query rows so
        // a MaxSim score is a mean cosine in [-1,1], then map into [0,1] —
        // same scale as fusion, comparable with unscored hits.
        let dim = late.dim().max(1);
        let qrows = (qmatrix.len() / dim).max(1) as f32;
        // The LUT kernel: with PQ-packed (v2) matrices, each query row's
        // dot-product tables are built ONCE here, and scoring a candidate
        // token is `m` table adds instead of a `dim`-wide dot product.
        self.tok_pq_ensure(late.model_name());
        let tok_pq = self.tok_pq.borrow();
        let qtables: Option<Vec<Vec<f32>>> = tok_pq.as_ref().map(|pq| {
            qmatrix
                .chunks_exact(dim)
                .map(|q| pq.dot_tables(q).unwrap_or_default())
                .collect()
        });
        for h in hits[..pool].iter_mut() {
            let blob: Option<Vec<u8>> = stmt
                .query_row(params![h.drawer.id, late.model_name()], |r| r.get(0))
                .ok();
            let Some(blob) = blob else {
                continue;
            };
            let Ok(packed) = self.vault.tokens_from_rest(&h.drawer.id, &blob) else {
                continue;
            };
            let s = match packed.first() {
                Some(2) => {
                    // v2: PQ codes + per-query-row LUTs.
                    let (Some(pq), Some(qtables)) = (tok_pq.as_ref(), qtables.as_ref()) else {
                        continue;
                    };
                    let Some((vdim, rows, codes)) = unpack_v2(&packed, pq.code_len()) else {
                        continue;
                    };
                    if vdim != dim || rows == 0 {
                        continue;
                    }
                    let mut total = 0f32;
                    for tables in qtables {
                        if tables.is_empty() {
                            continue;
                        }
                        let mut best = f32::NEG_INFINITY;
                        for code in codes.chunks_exact(pq.code_len()) {
                            let d = pq.adc_dot(tables, code);
                            if d > best {
                                best = d;
                            }
                        }
                        total += best;
                    }
                    total / qrows
                }
                _ => {
                    // v1: int8 → f32 MaxSim.
                    let Some((matrix, vdim)) = dequantize_tokens(&packed) else {
                        continue;
                    };
                    if vdim != dim {
                        continue;
                    }
                    maxsim(&qmatrix, &matrix, dim) / qrows
                }
            };
            h.score = ((s + 1.0) / 2.0).clamp(0.0, 1.0);
        }
        hits[..pool].sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
}
