//! In-memory HNSW ANN prefilter (pure Rust, `instant-distance`).
//!
//! A local approximate-nearest-neighbour index over the vault's *decrypted*
//! embeddings, used to cut the candidate set to the vector top-K before the
//! usual verify + hybrid-fusion pipeline — the semantic analogue of the FTS5
//! BM25 prefilter. It replaces the O(n) full cosine scan with an O(log n)
//! graph walk for large palaces.
//!
//! **Invariant:** this index lives in RAM only and is never persisted. It is
//! built on demand from embeddings that are decrypted transiently during a
//! search anyway (exactly like [`warm_embedding_cache`]), so it introduces no
//! new on-disk plaintext-derived structure — sealed vaults keep the
//! no-plaintext-index-on-disk guarantee. It is dropped whenever the corpus
//! changes and rebuilt on the next search.

use instant_distance::{Builder, HnswMap, Point, Search};

/// A wrapped embedding vector with a cosine-distance metric. HNSW only needs
/// a consistent ordering, and cosine distance (`1 - cosine similarity`) gives
/// the same nearest-neighbour ordering the full-scan path uses.
#[derive(Clone)]
struct Emb(Vec<f32>);

impl Point for Emb {
    fn distance(&self, other: &Self) -> f32 {
        let (mut dot, mut na, mut nb) = (0f32, 0f32, 0f32);
        let n = self.0.len().min(other.0.len());
        for i in 0..n {
            dot += self.0[i] * other.0[i];
            na += self.0[i] * self.0[i];
            nb += other.0[i] * other.0[i];
        }
        let denom = (na.sqrt() * nb.sqrt()).max(1e-12);
        1.0 - dot / denom
    }
}

/// An HNSW index mapping decrypted embeddings to their drawer `seq` ids.
pub(crate) struct HnswIndex {
    map: HnswMap<Emb, i64>,
}

impl HnswIndex {
    /// Build from `(seq, embedding)` pairs. Caller guarantees a non-empty set
    /// (an empty corpus needs no prefilter — the caller falls back to a scan).
    pub(crate) fn build(items: Vec<(i64, Vec<f32>)>) -> Self {
        let mut points = Vec::with_capacity(items.len());
        let mut values = Vec::with_capacity(items.len());
        for (seq, vec) in items {
            points.push(Emb(vec));
            values.push(seq);
        }
        let map = Builder::default().build(points, values);
        Self { map }
    }

    /// The `k` nearest drawer `seq`s to `query`, ascending by distance.
    pub(crate) fn query(&self, query: &[f32], k: usize) -> Vec<i64> {
        let mut search = Search::default();
        let qp = Emb(query.to_vec());
        self.map
            .search(&qp, &mut search)
            .take(k)
            .map(|item| *item.value)
            .collect()
    }
}
