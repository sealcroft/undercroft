//! MUVERA fixed-dimensional encodings (FDEs) — single-vector proxies for
//! MaxSim (arXiv:2405.19504).
//!
//! A token matrix (ColBERT-style, unit rows) is compressed into **one**
//! fixed-length vector such that a plain inner product of a query FDE and a
//! doc FDE approximates the Chamfer/MaxSim similarity. Construction is
//! model-free randomization: per repetition, SimHash hyperplanes partition
//! the embedding space into `2^ksim` buckets; each bucket's token vectors
//! aggregate (**sum** on the query side, **mean** on the doc side — the
//! asymmetry is what makes the inner product approximate a sum over query
//! tokens of their best-bucket match), an optional random ±1 projection
//! reduces each aggregate `d → dproj`, and everything concatenates across
//! buckets and repetitions. Doc-side empty buckets are filled with the
//! nearest token by Hamming distance of SimHash codes (the paper's
//! `fill_empty_clusters`), so sparse matrices still score.
//!
//! Everything derives **deterministically from a seed**: two vaults sharing
//! `(seed, params, dim)` produce identical encoders, so query FDEs computed
//! at search time match doc FDEs computed at ingest. No external deps, no
//! `rand` — a splitmix64 stream feeds Box-Muller for the Gaussian planes.
//!
//! Like [`crate::late`], this module is pure math; where FDEs are stored
//! (sealed for encrypted vaults), cached, and searched is the store's
//! concern.

/// FDE construction parameters. `dim = reps × 2^ksim × dproj`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdeParams {
    /// Independent repetitions (variance reduction). More reps → better
    /// approximation, linearly bigger FDEs.
    pub reps: usize,
    /// SimHash bits per repetition; buckets per repetition = `2^ksim`.
    pub ksim: usize,
    /// Per-bucket projected width. `dproj == token dim` ⇒ identity (no
    /// projection).
    pub dproj: usize,
    /// PRNG seed; persisted alongside stored FDEs — query and doc encoders
    /// must agree bit-for-bit.
    pub seed: u64,
}

/// The construction defaults, as named constants rather than literals inside
/// `Default::default()`.
///
/// ROADMAP O52: `undercroft-store`'s `TUNED` table states each declared knob's
/// unset value ONCE, so the pre-flight and the engine cannot disagree about it
/// — and a `const` table cannot call `Default::default()`. Naming them here
/// keeps one statement of each default and makes `Default` a consumer of it
/// rather than the place it lives.
pub const FDE_REPS_DEFAULT: usize = 8;
/// See [`FDE_REPS_DEFAULT`]. Bounded above at 16: buckets per repetition are
/// `2^ksim`, so this is a real ceiling and not a stylistic one.
pub const FDE_KSIM_DEFAULT: usize = 4;
/// See [`FDE_REPS_DEFAULT`].
pub const FDE_DPROJ_DEFAULT: usize = 16;
/// See [`FDE_REPS_DEFAULT`]. `"muvera.1"` as bytes.
pub const FDE_SEED_DEFAULT: u64 = 0x6d75_7665_7261_2e31;
/// The inclusive upper bound on `ksim`, stated so the declaration's parse and
/// the construction agree. It used to be a `.clamp(1, 16)` applied AFTER an
/// `unwrap_or`, so `UNDERCROFT_FDE_KSIM=32` was silently taken as 16.
pub const FDE_KSIM_MAX: usize = 16;
/// The inclusive upper bound on a DECLARED `reps` (`UNDERCROFT_FDE_REPS`,
/// through the store's `TUNED` row, so `config check` sees it). It had
/// none, so `UNDERCROFT_FDE_REPS=100000000` passed the pre-flight and
/// allocated ~200 GB of SimHash planes at the first build (ROADMAP O111).
/// The paper's largest configuration uses 20; 64 leaves that a 3× margin
/// and nothing else. A PERSISTED construction is bounded by
/// [`FdeParams::dim_for`] alone.
pub const FDE_REPS_MAX: usize = 64;
/// The inclusive upper bound on a DECLARED `dproj`. A projection wider than
/// the token dimension is already the identity (see [`FdeEncoder::new`]), so
/// nothing above any served model's width means anything; 4096 covers every
/// late-interaction export this project has measured with room to spare.
pub const FDE_DPROJ_MAX: usize = 4096;
/// The most floats one FDE may hold: `reps · 2^ksim · dproj_eff`. The three
/// per-field ceilings compose to ~1.7·10¹⁰, so the PRODUCT needs its own
/// bound — `FdeEncoder::encode` allocates exactly this many floats per call,
/// and a persisted `params` blob that an offline writer wrote (clear and
/// untagged on an hmac-only vault) chose the construction for every later
/// open. 2²⁰ floats is 4 MiB per vector, five hundred times the default.
pub const FDE_DIM_MAX: usize = 1 << 20;

impl FdeParams {
    /// The FDE width this construction produces for token dimension `d`, or
    /// `None` where it CANNOT WORK: a zero field, a product that wraps, or
    /// a width past [`FDE_DIM_MAX`] — checked arithmetic throughout, because
    /// a wrapped product is how a length check stops being a bound (ROADMAP
    /// O111). The one door both the declaration and the persisted blob go
    /// through before an encoder is built. Deliberately NOT the per-field
    /// ceilings: those bound the DECLARATION (the `TUNED` rows, where
    /// `config check` sees them), while a persisted construction an operator
    /// chose under an older build is kept for as long as it works, since
    /// refusing it costs a rebuild of every FDE from the stored token
    /// matrices.
    pub fn dim_for(&self, d: usize) -> Option<usize> {
        if self.reps == 0 || self.ksim == 0 || self.dproj == 0 || d == 0 {
            return None;
        }
        let dproj_eff = if self.dproj >= d { d } else { self.dproj };
        let dim = self
            .reps
            .checked_mul(1usize.checked_shl(self.ksim as u32)?)?
            .checked_mul(dproj_eff)?;
        (dim <= FDE_DIM_MAX).then_some(dim)
    }
}

impl Default for FdeParams {
    /// `8 × 2^4 × 16` → 2048-dim FDEs (8 KB f32 per drawer): the small end
    /// of the paper's quality band, sized for drawer-scale token counts
    /// (~10²) rather than web-passage corpora.
    fn default() -> Self {
        Self {
            reps: FDE_REPS_DEFAULT,
            ksim: FDE_KSIM_DEFAULT,
            dproj: FDE_DPROJ_DEFAULT,
            seed: FDE_SEED_DEFAULT,
        }
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn unit_f64(state: &mut u64) -> f64 {
    // 53 uniform bits in (0, 1] — never 0, safe for ln().
    ((splitmix64(state) >> 11) as f64 + 1.0) / (1u64 << 53) as f64
}

/// One standard Gaussian via Box-Muller.
fn gaussian(state: &mut u64) -> f32 {
    let u1 = unit_f64(state);
    let u2 = unit_f64(state);
    ((-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()) as f32
}

/// A deterministic MUVERA encoder for token matrices of width `d`.
pub struct FdeEncoder {
    params: FdeParams,
    d: usize,
    /// Gaussian SimHash planes, `reps × ksim × d` row-major.
    planes: Vec<f32>,
    /// ±1/√dproj projection, `reps × dproj × d` row-major (empty ⇒ identity).
    proj: Vec<f32>,
}

impl FdeEncoder {
    /// Build the encoder for token dim `d`. Fully determined by
    /// `(d, params)` — the same pair always yields the same encoder.
    pub fn new(d: usize, params: FdeParams) -> Self {
        let mut state = params.seed ^ (d as u64).rotate_left(17);
        let planes = (0..params.reps * params.ksim * d)
            .map(|_| gaussian(&mut state))
            .collect();
        let proj = if params.dproj >= d {
            Vec::new()
        } else {
            let scale = 1.0 / (params.dproj as f32).sqrt();
            (0..params.reps * params.dproj * d)
                .map(|_| {
                    if splitmix64(&mut state) & 1 == 1 {
                        scale
                    } else {
                        -scale
                    }
                })
                .collect()
        };
        Self {
            params,
            d,
            planes,
            proj,
        }
    }

    /// The construction parameters this encoder was built with.
    pub fn params(&self) -> FdeParams {
        self.params
    }

    /// Token dim this encoder accepts.
    pub fn token_dim(&self) -> usize {
        self.d
    }

    /// Output FDE length: `reps × 2^ksim × dproj_effective`.
    pub fn dim(&self) -> usize {
        self.params.reps * (1 << self.params.ksim) * self.dproj_eff()
    }

    fn dproj_eff(&self) -> usize {
        if self.proj.is_empty() {
            self.d
        } else {
            self.params.dproj
        }
    }

    /// SimHash code of `vec` under repetition `rep` (`ksim` sign bits).
    fn code(&self, rep: usize, vec: &[f32]) -> usize {
        let mut code = 0usize;
        for bit in 0..self.params.ksim {
            let plane = &self.planes[(rep * self.params.ksim + bit) * self.d..][..self.d];
            let dot: f32 = plane.iter().zip(vec).map(|(a, b)| a * b).sum();
            if dot >= 0.0 {
                code |= 1 << bit;
            }
        }
        code
    }

    /// Project a `d`-wide aggregate into the output slice for
    /// `(rep, bucket)`.
    fn emit(&self, rep: usize, bucket: usize, agg: &[f32], out: &mut [f32]) {
        let w = self.dproj_eff();
        let base = (rep * (1 << self.params.ksim) + bucket) * w;
        if self.proj.is_empty() {
            out[base..base + w].copy_from_slice(agg);
        } else {
            for j in 0..w {
                let row = &self.proj[(rep * self.params.dproj + j) * self.d..][..self.d];
                out[base + j] = row.iter().zip(agg).map(|(a, b)| a * b).sum();
            }
        }
    }

    /// Shared skeleton: bucket every token per repetition, aggregate, emit.
    /// `mean` selects the doc side (centroid + empty-bucket fill); the query
    /// side sums and leaves empty buckets zero.
    fn encode(&self, matrix: &[f32], mean: bool) -> Vec<f32> {
        let mut out = vec![0f32; self.dim()];
        if self.d == 0 || matrix.is_empty() || !matrix.len().is_multiple_of(self.d) {
            return out;
        }
        let rows: Vec<&[f32]> = matrix.chunks_exact(self.d).collect();
        let nbuckets = 1usize << self.params.ksim;
        let mut agg = vec![0f32; self.d];
        for rep in 0..self.params.reps {
            let codes: Vec<usize> = rows.iter().map(|r| self.code(rep, r)).collect();
            for bucket in 0..nbuckets {
                agg.iter_mut().for_each(|v| *v = 0.0);
                let mut count = 0usize;
                for (row, &code) in rows.iter().zip(&codes) {
                    if code == bucket {
                        for (a, b) in agg.iter_mut().zip(*row) {
                            *a += b;
                        }
                        count += 1;
                    }
                }
                if count == 0 {
                    if !mean {
                        continue; // query side: empty bucket contributes 0
                    }
                    // Doc side `fill_empty_clusters`: the token nearest this
                    // bucket by SimHash Hamming distance stands in, so every
                    // query token finds *something* to match against.
                    let nearest = codes
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, &c)| (c ^ bucket).count_ones())
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    agg.copy_from_slice(rows[nearest]);
                } else if mean {
                    let inv = 1.0 / count as f32;
                    agg.iter_mut().for_each(|v| *v *= inv);
                }
                self.emit(rep, bucket, &agg, &mut out);
            }
        }
        out
    }

    /// Doc-side FDE: per-bucket **centroids**, empty buckets filled with the
    /// Hamming-nearest token. Degenerate input ⇒ zero vector (scores 0, the
    /// candidate keeps its fusion rank — mirrors [`crate::late`]).
    pub fn encode_doc(&self, matrix: &[f32]) -> Vec<f32> {
        self.encode(matrix, true)
    }

    /// Query-side FDE: per-bucket **sums**, empty buckets zero.
    pub fn encode_query(&self, matrix: &[f32]) -> Vec<f32> {
        self.encode(matrix, false)
    }
}

/// Plain dot product — the FDE similarity. (FDEs are *not* unit vectors;
/// the raw inner product is the MaxSim estimate.)
pub fn fde_dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::late::maxsim;

    /// ROADMAP O111: the product ceiling is one door, and the door is
    /// checked arithmetic. `ksim = 40` is the value a 25-byte persisted blob
    /// could carry (2^40 buckets — the product wraps rather than merely
    /// exceeding); three fields each inside its declaration ceiling still
    /// compose past `FDE_DIM_MAX`; a construction above a per-field ceiling
    /// but inside the product one is KEPT, because it works; and the default
    /// passes.
    #[test]
    fn a_construction_that_cannot_work_has_no_width() {
        let d = 128;
        assert_eq!(FdeParams::default().dim_for(d), Some(8 * 16 * 16));
        let over_ksim = FdeParams {
            ksim: 40,
            ..FdeParams::default()
        };
        assert_eq!(over_ksim.dim_for(d), None);
        // Every field within its declaration range, the product past the
        // ceiling: 64 · 2^16 · 128 = 2^29 floats.
        let composed = FdeParams {
            reps: FDE_REPS_MAX,
            ksim: FDE_KSIM_MAX,
            dproj: FDE_DPROJ_MAX,
            ..FdeParams::default()
        };
        assert_eq!(composed.dim_for(d), None);
        // Above the declaration ceiling on `reps`, inside the product one:
        // a persisted construction that works is not refused.
        let wide_reps = FdeParams {
            reps: FDE_REPS_MAX + 1,
            ..FdeParams::default()
        };
        assert_eq!(wide_reps.dim_for(d), Some((FDE_REPS_MAX + 1) * 16 * 16));
        assert_eq!(
            FdeParams {
                reps: 0,
                ..FdeParams::default()
            }
            .dim_for(d),
            None
        );
        // And the identity rule: a dproj above the token dim projects to d.
        let wide = FdeParams {
            dproj: 4096,
            ..FdeParams::default()
        };
        assert_eq!(wide.dim_for(16), Some(8 * 16 * 16));
    }

    /// Deterministic pseudo-random unit token: direction picked from `topic`
    /// with small per-token jitter, so same-topic matrices are close in
    /// cosine and different-topic matrices are far.
    fn token(state: &mut u64, dim: usize, topic: u64) -> Vec<f32> {
        let mut base = topic.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let mut v: Vec<f32> = (0..dim).map(|_| gaussian(&mut base)).collect();
        for x in v.iter_mut() {
            *x += 0.15 * gaussian(state);
        }
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        v.iter_mut().for_each(|x| *x /= n);
        v
    }

    fn matrix(state: &mut u64, dim: usize, topics: &[u64], per_topic: usize) -> Vec<f32> {
        let mut m = Vec::new();
        for &t in topics {
            for _ in 0..per_topic {
                m.extend(token(state, dim, t));
            }
        }
        m
    }

    #[test]
    fn same_seed_same_encoder() {
        let a = FdeEncoder::new(32, FdeParams::default());
        let b = FdeEncoder::new(32, FdeParams::default());
        assert_eq!(a.planes, b.planes);
        assert_eq!(a.proj, b.proj);
        let mut s = 7u64;
        let m = matrix(&mut s, 32, &[1, 2], 4);
        assert_eq!(a.encode_doc(&m), b.encode_doc(&m));
    }

    #[test]
    fn degenerate_inputs_yield_zero_vectors() {
        let e = FdeEncoder::new(16, FdeParams::default());
        assert!(e.encode_doc(&[]).iter().all(|&v| v == 0.0));
        // Length not a multiple of dim.
        assert!(e.encode_query(&[0.5; 17]).iter().all(|&v| v == 0.0));
        assert_eq!(e.encode_doc(&[]).len(), e.dim());
    }

    #[test]
    fn fde_ranking_tracks_maxsim() {
        // 12 docs over distinct topic mixes; queries drawn from one topic
        // must rank their home doc(s) the way exact MaxSim does — the FDE
        // top-1 must sit in MaxSim's top 3 (approximation tolerance), and
        // over all queries the exact-MaxSim top-1 must land in the FDE
        // top 3 at least 10/12 times.
        let dim = 32;
        let e = FdeEncoder::new(dim, FdeParams::default());
        let mut s = 42u64;
        let docs: Vec<Vec<f32>> = (0..12)
            .map(|i| matrix(&mut s, dim, &[i as u64 * 3 + 1, i as u64 * 3 + 2], 6))
            .collect();
        let dfdes: Vec<Vec<f32>> = docs.iter().map(|d| e.encode_doc(d)).collect();
        let mut hits = 0;
        for i in 0..12 {
            let q = matrix(&mut s, dim, &[i as u64 * 3 + 1], 4);
            let qfde = e.encode_query(&q);
            let mut by_exact: Vec<(f32, usize)> = docs
                .iter()
                .enumerate()
                .map(|(j, d)| (maxsim(&q, d, dim), j))
                .collect();
            let mut by_fde: Vec<(f32, usize)> = dfdes
                .iter()
                .enumerate()
                .map(|(j, d)| (fde_dot(&qfde, d), j))
                .collect();
            by_exact.sort_by(|a, b| b.0.total_cmp(&a.0));
            by_fde.sort_by(|a, b| b.0.total_cmp(&a.0));
            let exact_top = by_exact[0].1;
            if by_fde[..3].iter().any(|&(_, j)| j == exact_top) {
                hits += 1;
            }
        }
        assert!(hits >= 10, "FDE ranking agreed on only {hits}/12 queries");
    }

    #[test]
    fn doc_and_query_sides_differ() {
        let dim = 16;
        let e = FdeEncoder::new(dim, FdeParams::default());
        let mut s = 3u64;
        let m = matrix(&mut s, dim, &[5, 9], 3);
        // Sum vs mean aggregation must differ on multi-token buckets.
        assert_ne!(e.encode_doc(&m), e.encode_query(&m));
    }
}
