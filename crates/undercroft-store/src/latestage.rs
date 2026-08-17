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

use rusqlite::{params, OptionalExtension};
use undercroft_core::late::{dequantize_tokens, maxsim, quantize_tokens, LateInteraction};

use crate::pq::ProductQuantizer;
use crate::{PalaceStore, SearchHit, StoreError, CODEBOOK_TOK};

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

/// Ident bytes for one token row in the codebook draws: the drawer's id
/// followed by the row index as LE u32. **Frozen** — the draw is keyed on
/// these bytes, so changing them moves every existing vault's training
/// sample for no gain.
fn tok_row_ident(id: &str, row: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(id.len() + 4);
    out.extend_from_slice(id.as_bytes());
    out.extend(row.to_le_bytes());
    out
}

impl PalaceStore {
    /// The token codebook's training draw over the flattened `(drawer, row)`
    /// walk: keyed, stratified, and **capped per source** — the quota
    /// grouping by the DRAWER's wing and agent claim, because that is where
    /// a token row came from.
    ///
    /// Extracted from the training pass so the density bound can be measured
    /// directly (`the_token_codebook_draw_is_capped_per_wing`): the effect is
    /// a property of the DRAW, and asserting it through a trained codebook's
    /// reconstruction error would measure k-means, not the quota.
    pub(crate) fn tok_training_draw(
        &self,
        ids: &[String],
        flat: &[(u32, u32)],
        source_of: &[(String, Option<String>)],
        want: usize,
    ) -> Vec<usize> {
        self.keyed_sample_capped(
            CODEBOOK_TOK,
            flat,
            want,
            |(d, r)| tok_row_ident(&ids[*d as usize], *r),
            |(d, _)| source_of[*d as usize].clone(),
        )
    }

    /// Attach (or clear) the late-interaction encoder. With one set, writes
    /// store per-token matrices and searches re-score the fusion top-N by
    /// MaxSim. If a cross-encoder reranker is also set, the reranker wins
    /// (it is the more accurate, more expensive option).
    pub fn set_late(&mut self, late: Option<Box<dyn LateInteraction + Send + Sync>>) {
        self.late = late;
    }

    /// How many fusion-ranked candidates this stage re-scores.
    ///
    /// **Not the cross-encoder's `UNDERCROFT_RERANK_TOP_N`**, which is a
    /// latency cap of one transformer forward per candidate; MaxSim is
    /// arithmetic over matrices built at ingest, so this stage can afford to
    /// look much deeper. Defaults from `UNDERCROFT_LATE_TOP_N` at open — see
    /// [`crate::DEFAULT_LATE_TOP_N`] for what the default rests on, and what
    /// it does not.
    pub fn set_late_top_n(&mut self, n: usize) {
        self.late_top_n = n.max(1);
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
        // R1 again: the schema call is a write. A read-only store reads the
        // stored codebook if the table is there and trains nothing — v1
        // int8 matrices rescore without a codebook, so the stage degrades to
        // arithmetic rather than to nothing.
        if self.may_build_indexes() {
            if self.late_schema().is_err() {
                return false;
            }
        } else if !matches!(self.table_exists("tok_meta"), Ok(true)) {
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
        // Train when the corpus warrants it — never on a read-only store
        // (R1): training the codebook also REPACKS every stored matrix from
        // v1 to v2, so this is the largest write a search could trigger.
        if !self.may_build_indexes() {
            return false;
        }
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
        // The draw is over token ROWS, keyed per (drawer, row) under the
        // vault's sample key, so a bulk writer cannot predict which of their
        // tokens shape the codebook every other drawer's tokens are then
        // coded against. `flat` is that flattened walk, and its order is the
        // stratification axis.
        //
        // **Capped per source since 2026-08-05 (ROADMAP A27).** This was the
        // one trained artifact still calling the raw primitive while
        // CLAUDE.md's density paragraph read as though every site were
        // covered: owning fraction *f* of the corpus bought ≈*f* of this
        // sample. It matters more here than anywhere, not less — the token
        // codebook decides SCORE (every drawer's tokens are quantized
        // against it and MaxSim reads the result), and the poison-resistance
        // invariant classifies coupling in scoring as integrity, where
        // coupling in candidate generation is only availability. The quota
        // groups by the DRAWER's wing and agent claim, because that is where
        // a token row came from: a flooding wing's tokens are its wing's.
        // A corpus whose wings sit inside their quotas trains on exactly the
        // rows it did before — the cap only truncates a group that exceeded
        // its share.
        let flat: Vec<(u32, u32)> = v1
            .iter()
            .enumerate()
            .flat_map(|(d, (_, matrix, dim))| {
                (0..(matrix.len() / (*dim).max(1)) as u32).map(move |r| (d as u32, r))
            })
            .collect();
        let ids: Vec<String> = v1.iter().map(|(id, _, _)| id.clone()).collect();
        let source_by_id = self.source_by_drawer_id()?;
        let source_of: Vec<(String, Option<String>)> = ids
            .iter()
            .map(|id| source_by_id.get(id).cloned().unwrap_or_default())
            .collect();
        let row_at = |i: usize| -> Vec<f32> {
            let (d, r) = flat[i];
            let (_, matrix, dim) = &v1[d as usize];
            matrix[r as usize * dim..(r as usize + 1) * dim].to_vec()
        };
        let sample: Vec<Vec<f32>> = self
            .tok_training_draw(&ids, &flat, &source_of, TOK_PQ_SAMPLE)
            .into_iter()
            .map(row_at)
            .collect();
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
        // Deliberately UNCAPPED, like the PQ tier's probe: it represents the
        // corpus as it is, so a capped sample facing a skewed corpus can
        // legitimately warn — that skew being visible is information.
        if total_rows > TOK_PQ_SAMPLE {
            let probe: Vec<Vec<f32>> = self
                .keyed_sample(
                    "tok-fit-probe",
                    &flat,
                    crate::pqidx::PQ_FIT_PROBE,
                    |(d, r)| tok_row_ident(&ids[*d as usize], *r),
                )
                .into_iter()
                .map(row_at)
                .collect();
            self.warn_unrepresentative(CODEBOOK_TOK, &pq, &sample, &probe);
        }
        // Persist (sealed on sealed vaults), then repack every v1 row —
        // **as one transaction** (ROADMAP A20). The codebook used to be
        // written first and each repacked row to autocommit after it, so an
        // interruption left a v2 codebook beside v1 rows and every row cost
        // its own fsync under `synchronous=FULL`. The first was survivable
        // only because the readers accept both packings, i.e. by luck.
        let blob = self.vault.tokens_at_rest("tok/codebook", &pq.to_bytes());
        self.one_rewrite(|| {
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
            Ok(())
        })?;
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
    /// Whether a ColBERT token matrix is filed under `id`.
    ///
    /// A read, for the callers that need to tell "this drawer has no matrix"
    /// from "this drawer's matrix is filed under a different id" — which is
    /// exactly the difference C6 was: the artifact was sealed under the id
    /// the payload aimed at rather than the one the row landed under.
    pub fn has_token_artifact(&self, id: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM drawer_tok WHERE id = ?1",
                params![id],
                |_| Ok(()),
            )
            .optional()
            .unwrap_or(None)
            .is_some()
    }

    pub fn import_token_artifact(
        &mut self,
        id: &str,
        model: &str,
        packed: &[u8],
    ) -> Result<(), StoreError> {
        // A drawer id is DERIVED, never declared, and it is an AEAD
        // associated-data component: content seals under `{id}`, the
        // embedding under `{id}/emb`, token matrices under `{id}/tok`, FDE
        // rows under `fde/{id}`. `is_drawer_id` was called at exactly one
        // site — inside `write_drawer`, whose comment claims "the shape
        // closes it for every write path at once" — and this is not a
        // `write_drawer` path. A caller could post `id: "fde/<32 hex>"`
        // with a valid `tok` and get a blob sealed under another drawer's
        // FDE domain, which is the property the AAD exists to provide
        // (ROADMAP C6).
        if !crate::is_drawer_id(id) {
            return Err(StoreError::Invalid(format!(
                "token artifact id {id:?} is not a drawer id (32 lowercase hex): a drawer id is derived, and it is an AEAD associated-data component"
            )));
        }
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
        // R1: `late_schema` is `CREATE TABLE IF NOT EXISTS`, i.e. a write on
        // any vault that has never stored a token matrix — and a rescore
        // stage riding on it turned a read-only search into one. A read-only
        // store asks whether the table is there instead; if it is not, there
        // are no matrices to rescore against and the fusion ranking stands.
        if self.may_build_indexes() {
            if self.late_schema().is_err() {
                return;
            }
        } else if !matches!(self.table_exists("drawer_tok"), Ok(true)) {
            self.ro_prefilter_fallback("late-interaction rescore");
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
        // Rescore depth, NOT the cross-encoder's latency cap: MaxSim costs
        // arithmetic per candidate, not a forward pass, so this stage can look
        // far deeper than a reranker can afford to. Note `hits` is the
        // un-truncated candidate list — on a sealed vault with no prefilter
        // that is the whole corpus, so this depth is what decides how much of
        // it gets a second opinion.
        let pool = hits.len().min(self.late_top_n);
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

#[cfg(test)]
mod tests {
    use crate::PalaceStore;
    use undercroft_vault::{SecurityLevel, VaultManager};

    fn store() -> (tempfile::TempDir, PalaceStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::HmacOnly).unwrap();
        (dir, PalaceStore::open(vault).unwrap())
    }

    /// One wing floods the corpus; a second holds a handful of drawers. The
    /// draw is over TOKEN ROWS, so the flooder's share of the sample is its
    /// share of the tokens — which is what the density channel buys.
    fn flooded_corpus(flood: usize, rest: usize, rows_each: u32) -> Corpus {
        let mut ids = Vec::new();
        let mut source_of = Vec::new();
        for i in 0..flood + rest {
            ids.push(format!("drawer-{i}"));
            let wing = if i < flood { "flood" } else { "quiet" };
            source_of.push((wing.to_string(), None));
        }
        let flat: Vec<(u32, u32)> = (0..ids.len() as u32)
            .flat_map(|d| (0..rows_each).map(move |r| (d, r)))
            .collect();
        Corpus {
            ids,
            flat,
            source_of,
        }
    }

    struct Corpus {
        ids: Vec<String>,
        flat: Vec<(u32, u32)>,
        source_of: Vec<(String, Option<String>)>,
    }

    /// A27: the token codebook was the one trained artifact whose draw called
    /// the raw primitive, so owning fraction *f* of the corpus bought ≈*f* of
    /// the sample — on the artifact that decides SCORE (every drawer's tokens
    /// are quantized against it), which the poison-resistance invariant
    /// classifies as integrity rather than availability.
    ///
    /// The counterfactual arm is the whole point: with the cap disabled the
    /// flooder takes essentially the sample, which is what this draw did
    /// before the fix, so the test cannot pass for the wrong reason.
    #[test]
    fn the_token_codebook_draw_is_capped_per_wing() {
        let (_d, mut s) = store();
        let c = flooded_corpus(950, 50, 8);
        let want = 200usize;
        let flooders = |chosen: &[usize]| -> usize {
            chosen
                .iter()
                .filter(|&&i| c.source_of[c.flat[i].0 as usize].0 == "flood")
                .count()
        };

        // Premise: uncapped, the flooder owns 95% of the rows and takes ~95%
        // of the draw.
        s.train_source_cap = usize::MAX;
        let uncapped = s.tok_training_draw(&c.ids, &c.flat, &c.source_of, want);
        assert_eq!(uncapped.len(), want);
        assert!(
            flooders(&uncapped) * 100 / want >= 90,
            "premise: an uncapped draw is bought by density ({} of {want})",
            flooders(&uncapped)
        );

        // Capped (the shipped default divisor, 4): two wings, so the quota is
        // an even split and the flooder cannot exceed half the sample.
        s.train_source_cap = 4;
        let capped = s.tok_training_draw(&c.ids, &c.flat, &c.source_of, want);
        assert_eq!(
            capped.len(),
            want,
            "soft cap: the sample must never shrink — a smaller training set \
             is a quality cost every wing pays"
        );
        assert!(
            flooders(&capped) <= want.div_ceil(2),
            "the flooding wing took {} of {want}, above its quota",
            flooders(&capped)
        );
    }

    /// The other half of the cap's contract, and the one a regression would
    /// break silently: a corpus inside its quota must train on **exactly**
    /// the rows it trained on before, or every existing vault's codebook
    /// moves for no reason.
    #[test]
    fn a_within_quota_corpus_draws_exactly_what_it_always_did() {
        let (_d, mut s) = store();
        // One wing, no agent claims — the ordinary vault, where the cap has
        // nothing to bound.
        let c = flooded_corpus(200, 0, 8);
        let want = 100usize;
        s.train_source_cap = 4;
        let capped = s.tok_training_draw(&c.ids, &c.flat, &c.source_of, want);
        s.train_source_cap = usize::MAX;
        let uncapped = s.tok_training_draw(&c.ids, &c.flat, &c.source_of, want);
        assert_eq!(capped, uncapped);
        assert!(
            capped.windows(2).all(|w| w[0] < w[1]),
            "and it is still the ascending stratified draw"
        );
    }

    /// Below the sampling cap the whole corpus trains, capped or not — the
    /// draw has nothing to bias and truncating would only shrink it.
    #[test]
    fn below_the_sample_cap_every_token_row_trains() {
        let (_d, mut s) = store();
        let c = flooded_corpus(90, 10, 4);
        s.train_source_cap = 4;
        let chosen = s.tok_training_draw(&c.ids, &c.flat, &c.source_of, c.flat.len() + 1);
        assert_eq!(chosen, (0..c.flat.len()).collect::<Vec<_>>());
    }
}
