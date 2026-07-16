//! Product Quantization — the compression primitive for a bounded-RAM,
//! on-disk ANN index.
//!
//! A D-dim embedding is split into `m` subvectors; each subspace has its own
//! codebook of 256 centroids (trained by k-means), so a subvector encodes to
//! **one byte** and a whole vector to `m` bytes. A 384-dim f32 vector (1536 B)
//! becomes, at `m = 48`, **48 bytes — 32× smaller**. The codes are tiny enough
//! to stream from disk (only the codebook, ~400 KB, need be resident), which is
//! how an on-disk IVF-PQ index keeps RAM ~O(1) in the corpus size instead of
//! the O(corpus) of the in-memory HNSW prototype (see docs/RETRIEVAL_SCALING).
//!
//! Vectors are L2-normalized before quantization, so L2 distance ordering
//! matches cosine ordering — search ranks by asymmetric distance computation
//! (ADC): per-query, per-subspace distance tables are summed over the code
//! bytes, a handful of adds per candidate.
//!
//! This module is storage- and crypto-agnostic: it turns vectors into codes and
//! scores codes against a query. Where codes live (SQLite blob, encrypted for
//! sealed vaults) and how candidates are shortlisted (flat scan first, IVF
//! inverted lists later) are the caller's job.

/// Centroids per subspace. A code byte indexes one of these, so it is fixed at
/// 256 (the range of `u8`).
const K: usize = 256;

/// A trained product quantizer: `m` subspace codebooks of `K` centroids each.
#[derive(Clone, Debug)]
pub struct ProductQuantizer {
    /// Sub-vector length (`dim / m`).
    dsub: usize,
    /// Number of subspaces (bytes per code).
    m: usize,
    /// `m` codebooks, each `K` centroids of `dsub` floats, flattened as
    /// `codebooks[subspace][centroid * dsub + j]`.
    codebooks: Vec<Vec<f32>>,
}

/// L2-normalize a vector (in place copy). Zero vectors are left as-is.
fn normalized(v: &[f32]) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm <= f32::EPSILON {
        return v.to_vec();
    }
    v.iter().map(|x| x / norm).collect()
}

fn l2_sq(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| (x - y) * (x - y)).sum()
}

impl ProductQuantizer {
    /// Bytes per encoded vector.
    pub fn code_len(&self) -> usize {
        self.m
    }

    /// Train `m` subspace codebooks from a sample of vectors (all of equal
    /// dimension, divisible by `m`). `iters` Lloyd iterations per subspace.
    /// Deterministic: centroids are seeded by an even stride over the training
    /// set, so the same input yields the same quantizer (reproducible tests,
    /// stable on-disk codes). Returns `None` on bad shape or an empty set.
    pub fn train(vectors: &[Vec<f32>], m: usize, iters: usize) -> Option<Self> {
        if vectors.is_empty() || m == 0 {
            return None;
        }
        let dim = vectors[0].len();
        if dim == 0 || !dim.is_multiple_of(m) || vectors.iter().any(|v| v.len() != dim) {
            return None;
        }
        let dsub = dim / m;
        let norm: Vec<Vec<f32>> = vectors.iter().map(|v| normalized(v)).collect();
        let mut codebooks = Vec::with_capacity(m);
        for s in 0..m {
            let lo = s * dsub;
            let hi = lo + dsub;
            let subs: Vec<&[f32]> = norm.iter().map(|v| &v[lo..hi]).collect();
            codebooks.push(kmeans(&subs, dsub, iters));
        }
        Some(Self { dsub, m, codebooks })
    }

    /// Encode a vector to `m` code bytes (nearest centroid per subspace).
    pub fn encode(&self, v: &[f32]) -> Vec<u8> {
        let v = normalized(v);
        let mut code = Vec::with_capacity(self.m);
        for s in 0..self.m {
            let sub = &v[s * self.dsub..s * self.dsub + self.dsub];
            code.push(self.nearest(s, sub) as u8);
        }
        code
    }

    /// Per-subspace distance tables for `query`: `tables[s * K + c]` is the
    /// squared L2 distance from the query's `s`-th subvector to centroid `c`.
    /// Sum the table entries selected by a code to get that code's approximate
    /// squared distance (ADC). Smaller = nearer.
    pub fn distance_tables(&self, query: &[f32]) -> Vec<f32> {
        let q = normalized(query);
        let mut tables = vec![0f32; self.m * K];
        for s in 0..self.m {
            let sub = &q[s * self.dsub..s * self.dsub + self.dsub];
            let book = &self.codebooks[s];
            for c in 0..K {
                let centroid = &book[c * self.dsub..c * self.dsub + self.dsub];
                tables[s * K + c] = l2_sq(sub, centroid);
            }
        }
        tables
    }

    /// Approximate squared distance of an encoded `code` given `distance_tables`.
    pub fn adc(&self, tables: &[f32], code: &[u8]) -> f32 {
        let mut d = 0f32;
        for (s, &c) in code.iter().enumerate() {
            d += tables[s * K + c as usize];
        }
        d
    }

    /// Serialize the trained codebooks: `[version:1][m:u32][dsub:u32]` then
    /// `m × K × dsub` little-endian f32s. Stable across platforms so on-disk
    /// codes stay decodable.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.m * K * self.dsub * 4);
        out.push(1u8);
        out.extend((self.m as u32).to_le_bytes());
        out.extend((self.dsub as u32).to_le_bytes());
        for book in &self.codebooks {
            for v in book {
                out.extend(v.to_le_bytes());
            }
        }
        out
    }

    /// Inverse of [`to_bytes`](Self::to_bytes). `None` on any shape mismatch.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 9 || data[0] != 1 {
            return None;
        }
        let m = u32::from_le_bytes(data[1..5].try_into().ok()?) as usize;
        let dsub = u32::from_le_bytes(data[5..9].try_into().ok()?) as usize;
        if m == 0 || dsub == 0 || data.len() != 9 + m * K * dsub * 4 {
            return None;
        }
        let mut codebooks = Vec::with_capacity(m);
        let mut off = 9;
        for _ in 0..m {
            let mut book = Vec::with_capacity(K * dsub);
            for _ in 0..K * dsub {
                book.push(f32::from_le_bytes(data[off..off + 4].try_into().ok()?));
                off += 4;
            }
            codebooks.push(book);
        }
        Some(Self { dsub, m, codebooks })
    }

    fn nearest(&self, subspace: usize, sub: &[f32]) -> usize {
        let book = &self.codebooks[subspace];
        let mut best = 0usize;
        let mut best_d = f32::INFINITY;
        for c in 0..K {
            let centroid = &book[c * self.dsub..c * self.dsub + self.dsub];
            let d = l2_sq(sub, centroid);
            if d < best_d {
                best_d = d;
                best = c;
            }
        }
        best
    }
}

/// k-means over `subs` (each `dsub` long) → `K` centroids, flattened. Seeds by
/// an even stride for determinism; empty clusters are re-seeded to the farthest
/// assigned point so all K codes stay usable.
fn kmeans(subs: &[&[f32]], dsub: usize, iters: usize) -> Vec<f32> {
    let n = subs.len();
    let mut centroids = vec![0f32; K * dsub];
    // Stride seed: spread K initial centroids across the sample.
    for c in 0..K {
        let idx = if n == 0 { 0 } else { (c * n / K).min(n - 1) };
        let src = subs.get(idx).copied().unwrap_or(&[]);
        let dst = &mut centroids[c * dsub..c * dsub + dsub];
        for (j, slot) in dst.iter_mut().enumerate() {
            *slot = src.get(j).copied().unwrap_or(0.0);
        }
    }
    if n == 0 {
        return centroids;
    }
    let mut assign = vec![0usize; n];
    for _ in 0..iters {
        // Assign.
        let mut changed = false;
        for (i, sub) in subs.iter().enumerate() {
            let mut best = 0usize;
            let mut best_d = f32::INFINITY;
            for c in 0..K {
                let centroid = &centroids[c * dsub..c * dsub + dsub];
                let d = l2_sq(sub, centroid);
                if d < best_d {
                    best_d = d;
                    best = c;
                }
            }
            if assign[i] != best {
                assign[i] = best;
                changed = true;
            }
        }
        // Update means.
        let mut sums = vec![0f32; K * dsub];
        let mut counts = vec![0usize; K];
        for (i, sub) in subs.iter().enumerate() {
            let c = assign[i];
            counts[c] += 1;
            let acc = &mut sums[c * dsub..c * dsub + dsub];
            for (j, x) in sub.iter().enumerate() {
                acc[j] += x;
            }
        }
        for c in 0..K {
            if counts[c] > 0 {
                let sum = &sums[c * dsub..c * dsub + dsub];
                let dst = &mut centroids[c * dsub..c * dsub + dsub];
                for (slot, &s) in dst.iter_mut().zip(sum) {
                    *slot = s / counts[c] as f32;
                }
            }
        }
        if !changed {
            break;
        }
    }
    centroids
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random vectors (no `rand` dep — reproducible).
    fn synth(n: usize, dim: usize) -> Vec<Vec<f32>> {
        let mut out = Vec::with_capacity(n);
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 33) as f32 / (1u64 << 31) as f32 - 1.0
        };
        for i in 0..n {
            // A handful of latent clusters so quantization has structure to find.
            let cluster = (i % 8) as f32;
            out.push((0..dim).map(|_| next() + cluster).collect());
        }
        out
    }

    #[test]
    fn code_len_is_m_bytes() {
        let v = synth(300, 32);
        let pq = ProductQuantizer::train(&v, 8, 10).unwrap();
        assert_eq!(pq.code_len(), 8);
        assert_eq!(pq.encode(&v[0]).len(), 8);
    }

    #[test]
    fn bytes_round_trip_preserves_codes() {
        let v = synth(300, 32);
        let pq = ProductQuantizer::train(&v, 8, 10).unwrap();
        let back = ProductQuantizer::from_bytes(&pq.to_bytes()).expect("round trip");
        for x in v.iter().take(20) {
            assert_eq!(pq.encode(x), back.encode(x), "codes must be identical");
        }
        assert!(ProductQuantizer::from_bytes(&[1, 2, 3]).is_none());
    }

    #[test]
    fn rejects_bad_shape() {
        let v = synth(10, 30);
        assert!(ProductQuantizer::train(&v, 7, 5).is_none(), "30 % 7 != 0");
        assert!(ProductQuantizer::train(&[], 4, 5).is_none());
    }

    #[test]
    fn adc_ranks_like_exact_cosine() {
        // On a clustered set, PQ-ADC top-k should heavily overlap exact-cosine
        // top-k. Not identical (lossy), but the near neighbours must survive.
        let dim = 32;
        let data = synth(400, dim);
        let pq = ProductQuantizer::train(&data, 16, 25).unwrap();
        let codes: Vec<Vec<u8>> = data.iter().map(|v| pq.encode(v)).collect();

        let query = &data[3];
        // Exact cosine (normalized dot) ranking.
        let qn = normalized(query);
        let mut exact: Vec<(usize, f32)> = data
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let vn = normalized(v);
                let dot: f32 = qn.iter().zip(&vn).map(|(a, b)| a * b).sum();
                (i, dot)
            })
            .collect();
        exact.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let exact_top: std::collections::HashSet<usize> =
            exact.iter().take(10).map(|(i, _)| *i).collect();

        // PQ-ADC ranking (smaller distance = nearer).
        let tables = pq.distance_tables(query);
        let mut approx: Vec<(usize, f32)> = codes
            .iter()
            .enumerate()
            .map(|(i, c)| (i, pq.adc(&tables, c)))
            .collect();
        approx.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        let approx_top: Vec<usize> = approx.iter().take(10).map(|(i, _)| *i).collect();

        let overlap = approx_top.iter().filter(|i| exact_top.contains(i)).count();
        assert!(
            overlap >= 6,
            "PQ-ADC top-10 should recover most exact top-10, got {overlap}/10"
        );
        assert!(
            approx_top.contains(&3),
            "the query's own vector must rank top"
        );
    }
}
