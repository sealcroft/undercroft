//! Late-interaction (ColBERT-style) scoring — the core-count-independent
//! second retrieval stage.
//!
//! A cross-encoder reranker runs one transformer forward **per candidate at
//! query time** — O(top_n / cores). Late interaction moves that work to
//! ingest: each passage is encoded **once** into a per-token embedding
//! matrix and stored; a query is encoded in **one** forward, and each
//! candidate is scored by **MaxSim** — for every query token, the maximum
//! cosine against the passage's tokens, summed. Plain SIMD-friendly
//! arithmetic, no transformer per candidate: query latency is ~one forward
//! regardless of `top_n` or core count.
//!
//! This module defines the encoder trait and the MaxSim kernel. Where the
//! matrices live (SQLite blob, sealed for encrypted vaults), how they're
//! quantized, and when scoring runs are the store's concern.

/// A late-interaction encoder: text → per-token embedding matrix.
///
/// Matrices are row-major `rows × dim()` with **L2-normalized rows**, so a
/// dot product is a cosine and [`maxsim`] needs no further normalization.
/// Implementations are infallible like [`crate::embed::Embedder`]: encoding
/// failure degrades to an empty matrix (candidates keep their fusion rank).
pub trait LateInteraction {
    /// Stable identity recorded alongside stored matrices — mixing models
    /// silently would corrupt every score.
    fn model_name(&self) -> &str;
    /// Per-token embedding width (ColBERT convention: 128).
    fn dim(&self) -> usize;
    /// Encode a stored passage (document side, `[D]`-marked).
    fn encode_doc(&self, text: &str) -> Vec<f32>;
    /// Encode a search query (query side, `[Q]`-marked / mask-augmented).
    fn encode_query(&self, text: &str) -> Vec<f32>;
}

/// MaxSim over two row-major matrices of unit rows: for each query row, the
/// maximum dot product against any doc row, summed over query rows.
/// Degenerate inputs (empty matrices, length not a multiple of `dim`) score
/// zero rather than panicking — a candidate without stored tokens simply
/// keeps its fusion-rank position.
pub fn maxsim(query: &[f32], doc: &[f32], dim: usize) -> f32 {
    if dim == 0
        || query.is_empty()
        || doc.is_empty()
        || !query.len().is_multiple_of(dim)
        || !doc.len().is_multiple_of(dim)
    {
        return 0.0;
    }
    let mut total = 0f32;
    for q in query.chunks_exact(dim) {
        let mut best = f32::NEG_INFINITY;
        for d in doc.chunks_exact(dim) {
            let dot: f32 = q.iter().zip(d).map(|(a, b)| a * b).sum();
            if dot > best {
                best = dot;
            }
        }
        total += best;
    }
    total
}

/// Quantize a token matrix to int8 with one scale per row (max-abs). ~4×
/// smaller on disk; [`dequantize_tokens`] restores f32 for scoring. Format:
/// `[version:1][dim:u32][rows:u32]` then per row `scale:f32le` + `dim` i8s.
pub fn quantize_tokens(matrix: &[f32], dim: usize) -> Vec<u8> {
    let rows = if dim == 0 { 0 } else { matrix.len() / dim };
    let mut out = Vec::with_capacity(9 + rows * (4 + dim));
    out.push(1u8);
    out.extend((dim as u32).to_le_bytes());
    out.extend((rows as u32).to_le_bytes());
    for r in 0..rows {
        let row = &matrix[r * dim..(r + 1) * dim];
        let max = row.iter().fold(0f32, |m, v| m.max(v.abs()));
        let scale = if max > 0.0 { max / 127.0 } else { 1.0 };
        out.extend(scale.to_le_bytes());
        for v in row {
            out.push((v / scale).round().clamp(-127.0, 127.0) as i8 as u8);
        }
    }
    out
}

/// Inverse of [`quantize_tokens`]. Returns `(matrix, dim)`; `None` on any
/// shape mismatch (treated upstream as "no stored tokens").
pub fn dequantize_tokens(data: &[u8]) -> Option<(Vec<f32>, usize)> {
    if data.len() < 9 || data[0] != 1 {
        return None;
    }
    let dim = u32::from_le_bytes(data[1..5].try_into().ok()?) as usize;
    let rows = u32::from_le_bytes(data[5..9].try_into().ok()?) as usize;
    if dim == 0 || data.len() != 9 + rows * (4 + dim) {
        return None;
    }
    let mut matrix = Vec::with_capacity(rows * dim);
    let mut off = 9;
    for _ in 0..rows {
        let scale = f32::from_le_bytes(data[off..off + 4].try_into().ok()?);
        off += 4;
        for _ in 0..dim {
            matrix.push(data[off] as i8 as f32 * scale);
            off += 1;
        }
    }
    Some((matrix, dim))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(v: &mut [f32]) {
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        v.iter_mut().for_each(|x| *x /= n);
    }

    #[test]
    fn maxsim_prefers_matching_tokens() {
        let dim = 4;
        // Doc A shares a token direction with the query; doc B is orthogonal.
        let mut q = vec![1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0];
        let mut a = vec![1.0, 0.1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0];
        let mut b = vec![0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0];
        for m in [&mut q, &mut a, &mut b] {
            for row in m.chunks_mut(dim) {
                unit(row);
            }
        }
        assert!(maxsim(&q, &a, dim) > maxsim(&q, &b, dim));
    }

    #[test]
    fn maxsim_degenerate_inputs_score_zero() {
        assert_eq!(maxsim(&[], &[1.0], 1), 0.0);
        assert_eq!(maxsim(&[1.0], &[], 1), 0.0);
        assert_eq!(maxsim(&[1.0, 2.0], &[1.0], 0), 0.0);
        assert_eq!(maxsim(&[1.0, 2.0, 3.0], &[1.0, 2.0], 2), 0.0);
    }

    #[test]
    fn token_quantization_round_trips_scores() {
        let dim = 8;
        let mut matrix: Vec<f32> = (0..dim * 5)
            .map(|i| ((i * 37 % 17) as f32 - 8.0) / 8.0)
            .collect();
        for row in matrix.chunks_mut(dim) {
            unit(row);
        }
        let packed = quantize_tokens(&matrix, dim);
        let (back, bdim) = dequantize_tokens(&packed).expect("round trip");
        assert_eq!(bdim, dim);
        assert_eq!(back.len(), matrix.len());
        // int8 with per-row scale: values within ~1% of unit-range rows.
        for (a, b) in matrix.iter().zip(&back) {
            assert!((a - b).abs() < 0.01, "{a} vs {b}");
        }
        // And MaxSim through the quantized matrix stays put.
        let q = &matrix[..dim * 2];
        let exact = maxsim(q, &matrix, dim);
        let approx = maxsim(q, &back, dim);
        assert!((exact - approx).abs() < 0.05, "{exact} vs {approx}");
    }

    #[test]
    fn dequantize_rejects_garbage() {
        assert!(dequantize_tokens(&[]).is_none());
        assert!(dequantize_tokens(&[9, 1, 0, 0, 0, 1, 0, 0, 0]).is_none());
        let mut ok = quantize_tokens(&[0.5, 0.5], 2);
        ok.pop();
        assert!(dequantize_tokens(&ok).is_none());
    }
}
