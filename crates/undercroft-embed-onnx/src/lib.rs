//! ONNX sentence-embedding backend for Undercroft.
//!
//! Runs MiniLM-class sentence-transformer models exported to ONNX (e.g.
//! `sentence-transformers/all-MiniLM-L6-v2`) with mean pooling + L2
//! normalization — the standard sentence-embedding recipe. Inference uses
//! [tract](https://github.com/sonos/tract), a pure-Rust ONNX runtime: no
//! native binaries, no network at build or run time.
//!
//! The model stays a *user-supplied file* (Undercroft never downloads
//! anything): export or fetch `model.onnx` + `tokenizer.json` yourself and
//! point `UNDERCROFT_ONNX_MODEL` / `UNDERCROFT_ONNX_TOKENIZER` at them.
//!
//! Plugs into the palace through `undercroft_core::embed::Embedder`; the
//! store's embedder-identity tracking prevents silently mixing vectors
//! from different models.

use tokenizers::Tokenizer;
use tract_onnx::prelude::*;
use undercroft_core::contain::contain;
use undercroft_core::embed::Embedder;

// ROADMAP O150. Every role's inner body is wrapped in
// `undercroft_core::contain::contain`, which catches an UNWINDING panic. Under
// `panic = "abort"` there is no unwind to catch, so the boundary would be gone
// with nothing to say so and an out-of-table id would end the process again.
// Refused here because nothing else can see it: Cargo ignores `panic` for test
// targets, and a check of `Cargo.toml` cannot see `CARGO_PROFILE_RELEASE_PANIC`,
// `RUSTFLAGS` or `.cargo/config`.
#[cfg(panic = "abort")]
compile_error!(
    "undercroft-embed-onnx requires panic = \"unwind\": its model panics are contained with catch_unwind (ROADMAP O150), and an abort build turns them back into a process crash"
);

const MAX_LEN: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum OnnxError {
    #[error("failed to load tokenizer: {0}")]
    Tokenizer(String),
    #[error("failed to load/compile onnx model: {0}")]
    Model(String),
    #[error("inference failed: {0}")]
    Inference(String),
    /// A panic inside a model body, caught by `contain` and carrying the
    /// panic's own message (ROADMAP O150). It reaches the same counted
    /// degrade as [`OnnxError::Inference`]; the separate variant is what lets
    /// a degrade line, and a test, tell a contained crash from a typed error.
    #[error("inference panicked: {0}")]
    Panicked(String),
}

type RunnableOnnx = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

pub struct OnnxEmbedder {
    model: RunnableOnnx,
    tokenizer: Tokenizer,
    n_inputs: usize,
    dim: usize,
    name: String,
    /// Embeds degraded to a zero vector (ROADMAP O122). Atomic because the
    /// bench shares one of these behind an `Arc` across threads.
    failures: std::sync::atomic::AtomicU64,
}

impl OnnxEmbedder {
    /// Load a sentence-transformer ONNX export + its `tokenizer.json`.
    /// `model_name` is the identity recorded in the vault (pick something
    /// stable like `"all-MiniLM-L6-v2"`).
    pub fn load(
        model_path: &std::path::Path,
        tokenizer_path: &std::path::Path,
        model_name: &str,
    ) -> Result<Self, OnnxError> {
        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| OnnxError::Tokenizer(e.to_string()))?;
        let mut inference = tract_onnx::onnx()
            .model_for_path(model_path)
            .map_err(|e| OnnxError::Model(e.to_string()))?;
        let n_inputs = inference
            .input_outlets()
            .map_err(|e| OnnxError::Model(e.to_string()))?
            .len();
        for i in 0..n_inputs {
            inference = inference
                .with_input_fact(
                    i,
                    InferenceFact::dt_shape(i64::datum_type(), tvec!(1, MAX_LEN as i64)),
                )
                .map_err(|e| OnnxError::Model(e.to_string()))?;
        }
        let model = inference
            .into_optimized()
            .map_err(|e| OnnxError::Model(e.to_string()))?
            .into_runnable()
            .map_err(|e| OnnxError::Model(e.to_string()))?;

        // Probe the hidden dimension with a dry run.
        let mut me = Self {
            model,
            tokenizer,
            n_inputs,
            dim: 0,
            name: model_name.to_string(),
            failures: std::sync::atomic::AtomicU64::new(0),
        };
        let probe = me
            .embed_inner("dimension probe")
            .map_err(|e| OnnxError::Model(e.to_string()))?;
        me.dim = probe.len();
        Ok(me)
    }

    /// One embed, CONTAINED (ROADMAP O150). The tokenizer, the plan run and
    /// the shape handling after it all sit inside `contain`, because each can
    /// panic on a real model pair: an id past the embedding table panics in
    /// tract's `Gather` kernel, and `outputs[0]`, `shape[1]`/`shape[2]` and
    /// `hidden[[0, t, d]]` index with no rank check. A panic comes back as
    /// [`OnnxError::Panicked`] and reaches the counted degrade in `embed`
    /// instead of ending the process; the load probe calls this too, so a
    /// model that panics on the probe refuses to load.
    fn embed_inner(&self, text: &str) -> Result<Vec<f32>, OnnxError> {
        contain(
            || {
                let enc = self
                    .tokenizer
                    .encode(text, true)
                    .map_err(|e| OnnxError::Inference(e.to_string()))?;
                let mut ids: Vec<i64> = enc.get_ids().iter().map(|&v| v as i64).collect();
                let mut mask: Vec<i64> =
                    enc.get_attention_mask().iter().map(|&v| v as i64).collect();
                let mut types: Vec<i64> = enc.get_type_ids().iter().map(|&v| v as i64).collect();
                ids.truncate(MAX_LEN);
                mask.truncate(MAX_LEN);
                types.truncate(MAX_LEN);
                while ids.len() < MAX_LEN {
                    ids.push(0);
                    mask.push(0);
                    types.push(0);
                }

                let to_tensor = |v: &[i64]| -> Result<Tensor, OnnxError> {
                    tract_ndarray::Array2::from_shape_vec((1, MAX_LEN), v.to_vec())
                        .map(Tensor::from)
                        .map_err(|e| OnnxError::Inference(e.to_string()))
                };
                let mut inputs: TVec<TValue> =
                    tvec!(to_tensor(&ids)?.into(), to_tensor(&mask)?.into());
                if self.n_inputs >= 3 {
                    inputs.push(to_tensor(&types)?.into());
                }
                let outputs = self
                    .model
                    .run(inputs)
                    .map_err(|e| OnnxError::Inference(e.to_string()))?;
                let hidden = outputs[0]
                    .to_array_view::<f32>()
                    .map_err(|e| OnnxError::Inference(e.to_string()))?;
                // hidden: (1, MAX_LEN, dim) — masked mean pool + L2 normalize.
                let shape = hidden.shape();
                let (seq, dim) = (shape[1], shape[2]);
                let mut pooled = vec![0f32; dim];
                let mut denom = 0f32;
                for t in 0..seq.min(MAX_LEN) {
                    if mask[t] == 0 {
                        continue;
                    }
                    denom += 1.0;
                    for d in 0..dim {
                        pooled[d] += hidden[[0, t, d]];
                    }
                }
                if denom > 0.0 {
                    for v in &mut pooled {
                        *v /= denom;
                    }
                }
                let norm = pooled.iter().map(|x| x * x).sum::<f32>().sqrt();
                if norm > 0.0 {
                    for v in &mut pooled {
                        *v /= norm;
                    }
                }
                Ok(pooled)
            },
            OnnxError::Panicked,
        )
    }
}

impl Embedder for OnnxEmbedder {
    /// tract runs the model inside this process, so an embed sends nothing
    /// anywhere (ROADMAP O167).
    fn egress_destination(&self) -> Option<String> {
        None
    }

    fn model_name(&self) -> &str {
        &self.name
    }

    fn dimension(&self) -> usize {
        self.dim
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        // The Embedder trait is infallible by design (the hash embedder
        // cannot fail). A runtime inference failure degrades to a zero
        // vector rather than poisoning the write path; the record itself
        // (verbatim content) is unaffected and `repair` can re-embed.
        // Since ROADMAP O122 the degradation is COUNTED and said, exactly
        // as the served embedder's is — it was `.unwrap_or_else(|_| zeros)`
        // with no trace at all.
        match self.embed_inner(text) {
            Ok(v) => v,
            Err(e) => {
                let n = self
                    .failures
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;
                undercroft_obs::embed_failed("onnx");
                undercroft_obs::diag_error!(
                    "embed failed ({e}); storing a zero vector — this drawer is \
                     lexically findable but semantically invisible until re-embedded. \
                     Failures so far: {n}"
                );
                vec![0.0; self.dim.max(1)]
            }
        }
    }

    fn embed_failures(&self) -> u64 {
        self.failures.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Load the ONNX embedder from `UNDERCROFT_ONNX_MODEL`,
/// `UNDERCROFT_ONNX_TOKENIZER`, and optional `UNDERCROFT_ONNX_NAME`.
pub fn from_env() -> Result<OnnxEmbedder, OnnxError> {
    let model = std::env::var("UNDERCROFT_ONNX_MODEL")
        .map_err(|_| OnnxError::Model("UNDERCROFT_ONNX_MODEL is not set".into()))?;
    let tokenizer = std::env::var("UNDERCROFT_ONNX_TOKENIZER")
        .map_err(|_| OnnxError::Tokenizer("UNDERCROFT_ONNX_TOKENIZER is not set".into()))?;
    let name = std::env::var("UNDERCROFT_ONNX_NAME").unwrap_or_else(|_| {
        undercroft_obs::diag_warn!(
            "{}",
            undercroft_core::config::undeclared_model_identity(
                "UNDERCROFT_ONNX_NAME",
                undercroft_core::config::SHARED_MODEL_IDENTITY,
                &model,
            )
        );
        undercroft_core::config::SHARED_MODEL_IDENTITY.into()
    });
    OnnxEmbedder::load(
        std::path::Path::new(&model),
        std::path::Path::new(&tokenizer),
        &name,
    )
}

mod late;
mod rerank;
pub use late::{colbert_from_env, OnnxColbert};
pub use rerank::OnnxReranker;

// The GENERATED model fixture (ROADMAP O134a). `any(test, feature = …)` is
// a disjunction and both arms are load-bearing: the `test` arm makes it
// reachable from this crate's own tests with no command-line flag, and the
// feature arm is a NORMAL compilation of this crate, which is how
// `undercroft-embed-ort` reaches the same generator through a
// dev-dependency. Neither arm is on in a shipped build.
#[cfg(any(test, feature = "test-fixture"))]
pub mod fixture;

#[cfg(test)]
// The anchor lesson, cheaply: a scripted edit that eats a `#[test]`
// attribute turns a live gate into dead code and no test can report it —
// the test IS the thing that stopped running. `dead_code` says so
// (ROADMAP O134a).
#[deny(dead_code, unused)]
mod tests {
    use super::*;

    /// **The embed arm: a degraded embed is COUNTED, and a healthy one is
    /// not** (ROADMAP O122, executed for the first time by O134a).
    ///
    /// Three phases, and the count is asserted SEPARATELY from the degraded
    /// value so a counterfactual names which half failed. Restore
    /// `embed_inner(text).unwrap_or_else(|_| vec![0.0; dim])` at the call
    /// site and this fails on its COUNT assertion with the value assertion
    /// still passing; map the tokenizer `Err` to `Ok(zeros)` INSIDE
    /// `embed_inner` and it fails the same way — which is the discriminator
    /// a source assertion cannot see, because the text "embed calls the
    /// degrade path" stays true. Both were run; the second reports
    /// `left: 0, right: 1` on the count with the zero-vector assertion
    /// already passed.
    #[test]
    fn onnx_embed_counts_each_degraded_embed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (model, tok) = fixture::write_into(dir.path()).expect("write fixture");
        let e = OnnxEmbedder::load(&model, &tok, "fixture").expect("fixture loads");

        // PREMISE: a healthy call is finite, correctly shaped and NOT the
        // degrade value — a fixture that cannot exceed the threshold is a
        // gate that cannot fail.
        assert_eq!(
            e.embed_failures(),
            0,
            "load must not have counted a failure"
        );
        let healthy = e.embed(fixture::HEALTHY);
        assert_eq!(healthy.len(), fixture::DIM);
        assert!(
            healthy.iter().all(|x| x.is_finite()),
            "a healthy embed must be finite"
        );
        assert!(
            healthy.iter().any(|x| *x != 0.0),
            "a healthy embed must not be the zero vector"
        );
        assert_eq!(
            e.embed_failures(),
            0,
            "a healthy embed must not move the count"
        );

        // DEGRADE: the documented value, and exactly one count.
        let degraded = e.embed(fixture::REFUSED_WORD);
        assert_eq!(
            degraded,
            vec![0.0; fixture::DIM],
            "a failed embed must degrade to a zero vector"
        );
        assert_eq!(
            e.embed_failures(),
            1,
            "a failed embed must be counted exactly once"
        );

        // RECOVERY: the count is a count, not a latch.
        let again = e.embed(fixture::HEALTHY);
        assert_eq!(
            again, healthy,
            "a healthy embed after a failure must be unchanged"
        );
        assert_eq!(
            e.embed_failures(),
            1,
            "a healthy embed must not move the count"
        );
    }

    /// Bit patterns, so "unchanged" means the same floats rather than floats
    /// that merely compare equal.
    pub(crate) fn bits(v: &[f32]) -> Vec<u32> {
        v.iter().map(|x| x.to_bits()).collect()
    }

    /// The contained panic an out-of-table id must come back as, on tract.
    ///
    /// The VARIANT, not "some error": a typed `Inference` reaching the degrade
    /// counts 1 as well, which is exactly how the classifier this replaces
    /// passed on either outcome (ROADMAP O150, defect 1). The substring is the
    /// panic's CLASS, narrowed from the payload observed on tract 0.22.3 —
    /// "range end index 16388 out of range for slice of length 512", a bounds
    /// panic in the `Gather` kernel where 16388 = (OUT_OF_TABLE_ID + 1) × DIM
    /// — so a reworded tract message fails loudly with its new wording, and
    /// the pin is re-derived from that run.
    pub(crate) fn assert_contained_bounds_panic<T: std::fmt::Debug>(
        got: Result<T, OnnxError>,
        door: &str,
    ) {
        match got {
            Err(OnnxError::Panicked(m)) => assert!(
                m.contains("out of range"),
                "{door}: contained, but not the bounds panic this arm pins — a different panic is a different defect: {m}"
            ),
            other => panic!(
                "{door}: an out-of-table id must come back as the CONTAINED panic (ROADMAP O150), got {other:?}"
            ),
        }
    }

    /// **Route R, embed: an id past the embedding table is CONTAINED**
    /// (ROADMAP O150).
    ///
    /// tract 0.22.3 PANICS on this input, and the panic used to unwind out of
    /// the `/v1` and MCP loops and end the process. The classifier this
    /// replaces accepted either outcome, so the fix would have changed what it
    /// meant with nothing visible: it was made to FAIL on the contained
    /// outcome, the red run was recorded, and this is the re-pin. Three
    /// halves, asserted apart so a counterfactual names which one failed:
    ///
    /// * the inner body returns the contained bounds panic;
    /// * the door returns its documented zero vector and counts exactly once;
    /// * the instance is still sound — a healthy embed before and after three
    ///   out-of-table calls is bit-identical.
    ///
    /// No `catch_unwind` and no hook swap: an escaped panic fails this test by
    /// itself, and a swapped hook is a process global under libtest's
    /// parallel runner.
    #[test]
    fn onnx_route_r_embed_contains_an_out_of_table_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (model, tok) = fixture::write_into(dir.path()).expect("write fixture");
        let e = OnnxEmbedder::load(&model, &tok, "fixture").expect("fixture loads");
        let before = bits(&e.embed(fixture::HEALTHY));

        assert_contained_bounds_panic(e.embed_inner(fixture::OUT_OF_TABLE_WORD), "embed_inner");
        assert_eq!(
            e.embed(fixture::OUT_OF_TABLE_WORD),
            vec![0.0; fixture::DIM],
            "a contained panic must degrade to the documented zero vector"
        );
        assert_eq!(
            e.embed_failures(),
            1,
            "a contained panic must be counted exactly once"
        );
        assert_contained_bounds_panic(e.embed_inner(fixture::OUT_OF_TABLE_WORD), "embed_inner");

        assert_eq!(
            bits(&e.embed(fixture::HEALTHY)),
            before,
            "an embed after three caught panics must be bit-identical to one before them"
        );
        assert_eq!(
            e.embed_failures(),
            1,
            "a healthy embed must not move the count"
        );
    }

    /// Full inference test against a REAL user-supplied model. Ignored by
    /// default rather than returning early: this used to print "skipping"
    /// and report PASSED, so a green suite said nothing about whether it had
    /// ever run (ROADMAP O134a). `expect` on the variable, so `--ignored`
    /// without a model fails loudly instead of passing quietly.
    #[test]
    #[ignore = "requires a user-supplied model via UNDERCROFT_ONNX_MODEL + UNDERCROFT_ONNX_TOKENIZER"]
    fn embeds_when_model_available() {
        std::env::var("UNDERCROFT_ONNX_MODEL")
            .expect("UNDERCROFT_ONNX_MODEL must be set to run this test");
        let e = from_env().expect("model loads");
        let a = e.embed("the build failed because of a stale lockfile");
        let b = e.embed("ci broke due to an outdated lock file");
        let c = e.embed("the cat enjoys sunbathing on the windowsill");
        assert_eq!(a.len(), e.dimension());
        let sim = |x: &[f32], y: &[f32]| -> f32 { x.iter().zip(y).map(|(p, q)| p * q).sum() };
        assert!(sim(&a, &b) > sim(&a, &c), "related texts must score higher");
    }
}
