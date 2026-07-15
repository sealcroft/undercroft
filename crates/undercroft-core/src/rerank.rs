//! Cross-encoder reranker trait.
//!
//! A reranker is the optional second retrieval stage: after first-pass hybrid
//! search surfaces a candidate pool, a cross-encoder re-scores the top
//! candidates using the full `(query, passage)` pair — which captures
//! interactions a bi-encoder embedding cannot — and the pool is re-ordered by
//! that score.
//!
//! Like [`Embedder`](crate::embed::Embedder), a `Reranker` is **infallible on
//! the hot path**: a runtime inference failure must degrade gracefully (e.g. a
//! neutral score) rather than poison a search.

/// Scores query/passage relevance for reranking retrieved candidates.
pub trait Reranker {
    /// Stable identity of the underlying model (for logging/diagnostics).
    fn model_name(&self) -> &str;

    /// Relevance of `passage` to `query` — higher is more relevant. The
    /// absolute scale is model-specific; only the ordering is contractual.
    fn score(&self, query: &str, passage: &str) -> f32;

    /// Score several passages against one query. The default maps
    /// [`score`](Reranker::score); a model-backed impl may override to batch.
    fn score_batch(&self, query: &str, passages: &[&str]) -> Vec<f32> {
        passages.iter().map(|p| self.score(query, p)).collect()
    }
}
