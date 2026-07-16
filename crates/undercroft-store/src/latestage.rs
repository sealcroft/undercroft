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

use crate::{rerank_top_n, PalaceStore, SearchHit, StoreError};

impl PalaceStore {
    /// Attach (or clear) the late-interaction encoder. With one set, writes
    /// store per-token matrices and searches re-score the fusion top-N by
    /// MaxSim. If a cross-encoder reranker is also set, the reranker wins
    /// (it is the more accurate, more expensive option).
    pub fn set_late(&mut self, late: Option<Box<dyn LateInteraction + Send + Sync>>) {
        self.late = late;
    }

    fn late_schema(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS drawer_tok (
                 id    TEXT PRIMARY KEY,
                 model TEXT NOT NULL,
                 tok   BLOB NOT NULL
             );",
        )?;
        Ok(())
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
        let packed = quantize_tokens(&matrix, late.dim());
        let blob = self.vault.tokens_at_rest(id, &packed);
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO drawer_tok (id, model, tok) VALUES (?1, ?2, ?3)",
            params![id, late.model_name(), blob],
        );
    }

    /// Purge a deleted drawer's token row (mirrors the PQ purge).
    pub(crate) fn late_purge_row(&self, id: &str) {
        let _ = self
            .conn
            .execute("DELETE FROM drawer_tok WHERE id = ?1", params![id]);
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
        let qmatrix = late.encode_query(query);
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
        let qrows = (qmatrix.len() / late.dim().max(1)).max(1) as f32;
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
            let Some((matrix, dim)) = dequantize_tokens(&packed) else {
                continue;
            };
            if dim != late.dim() {
                continue;
            }
            let s = maxsim(&qmatrix, &matrix, dim) / qrows;
            h.score = ((s + 1.0) / 2.0).clamp(0.0, 1.0);
        }
        hits[..pool].sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
}
