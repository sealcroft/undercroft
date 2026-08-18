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
use undercroft_core::embed::Embedder;

const MAX_LEN: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum OnnxError {
    #[error("failed to load tokenizer: {0}")]
    Tokenizer(String),
    #[error("failed to load/compile onnx model: {0}")]
    Model(String),
    #[error("inference failed: {0}")]
    Inference(String),
}

type RunnableOnnx = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

pub struct OnnxEmbedder {
    model: RunnableOnnx,
    tokenizer: Tokenizer,
    n_inputs: usize,
    dim: usize,
    name: String,
}

impl OnnxEmbedder {
    /// Load a sentence-transformer ONNX export + its `tokenizer.json`.
    /// `model_name` is the identity recorded in the palace (pick something
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
        };
        let probe = me
            .embed_inner("dimension probe")
            .map_err(|e| OnnxError::Model(e.to_string()))?;
        me.dim = probe.len();
        Ok(me)
    }

    fn embed_inner(&self, text: &str) -> Result<Vec<f32>, OnnxError> {
        let enc = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| OnnxError::Inference(e.to_string()))?;
        let mut ids: Vec<i64> = enc.get_ids().iter().map(|&v| v as i64).collect();
        let mut mask: Vec<i64> = enc.get_attention_mask().iter().map(|&v| v as i64).collect();
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
        let mut inputs: TVec<TValue> = tvec!(to_tensor(&ids)?.into(), to_tensor(&mask)?.into());
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
    }
}

impl Embedder for OnnxEmbedder {
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
        self.embed_inner(text)
            .unwrap_or_else(|_| vec![0.0; self.dim.max(1)])
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
                "onnx-sentence",
                &model,
            )
        );
        "onnx-sentence".into()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Full inference test, gated on a user-provided model
    /// (set UNDERCROFT_ONNX_MODEL + UNDERCROFT_ONNX_TOKENIZER to run).
    #[test]
    fn embeds_when_model_available() {
        if std::env::var("UNDERCROFT_ONNX_MODEL").is_err() {
            eprintln!("skipping: UNDERCROFT_ONNX_MODEL not set");
            return;
        }
        let e = from_env().expect("model loads");
        let a = e.embed("the build failed because of a stale lockfile");
        let b = e.embed("ci broke due to an outdated lock file");
        let c = e.embed("the cat enjoys sunbathing on the windowsill");
        assert_eq!(a.len(), e.dimension());
        let sim = |x: &[f32], y: &[f32]| -> f32 { x.iter().zip(y).map(|(p, q)| p * q).sum() };
        assert!(sim(&a, &b) > sim(&a, &c), "related texts must score higher");
    }
}
