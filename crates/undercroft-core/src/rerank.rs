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

    /// How many `(query, passage)` scores this reranker has degraded to a
    /// neutral value since it was constructed (ROADMAP O131).
    ///
    /// **A degraded rerank is worse than a degraded embed, and the reason is
    /// where the number lands.** The store OVERWRITES a candidate's fusion
    /// score with the reranker's (`h.score = s`) and re-sorts, so a failed
    /// pass writes `0.0` and actively SINKS that candidate to the bottom of
    /// the reranked window — and `0.0` is also what a genuinely irrelevant
    /// passage scores, so the two are indistinguishable afterwards. A failed
    /// embed at least leaves a zero vector a re-embed can find; a failed
    /// score leaves no artifact at all. The only evidence is this count.
    ///
    /// **Required rather than defaulted**, for the reason
    /// [`Embedder::embed_failures`](crate::embed::Embedder::embed_failures)
    /// gives: a default of zero is the silent shape being closed, so the
    /// compiler enumerates every implementation. One per degraded
    /// `(query, passage)` pair — a batch that fails wholesale counts its
    /// passages, not one — and a reranker that cannot fail returns 0.
    ///
    /// The count belongs to the reranker instance for the life of the
    /// process, exactly as the embedder's does.
    fn score_failures(&self) -> u64;
}
