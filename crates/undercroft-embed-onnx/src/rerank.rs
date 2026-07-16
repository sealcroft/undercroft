//! ONNX cross-encoder reranker backend for Undercroft.
//!
//! Runs a sequence-classification cross-encoder (e.g.
//! `mixedbread-ai/mxbai-rerank-xsmall-v1` or
//! `cross-encoder/ms-marco-MiniLM-L-6-v2`) exported to ONNX: the query and
//! passage are encoded as a **pair** (`[CLS] query [SEP] passage [SEP]`) and
//! the model emits a single relevance logit, which we squash to `[0,1]` with a
//! sigmoid. Higher = more relevant. Inference uses [tract](https://github.com/sonos/tract)
//! (pure Rust) — no native binaries, no network.
//!
//! Like the embedder, the model stays a *user-supplied file*: point
//! `UNDERCROFT_RERANK_MODEL` / `UNDERCROFT_RERANK_TOKENIZER` at a `model.onnx` +
//! `tokenizer.json` you exported yourself. Plugs into search via
//! `undercroft_core::rerank::Reranker`.

use crate::{OnnxError, RunnableOnnx, MAX_LEN};
use undercroft_core::rerank::Reranker;
use tokenizers::Tokenizer;
use tract_onnx::prelude::*;

/// Cross-encoder reranker over a tract-run ONNX model.
pub struct OnnxReranker {
    model: RunnableOnnx,
    tokenizer: Tokenizer,
    n_inputs: usize,
    name: String,
}

impl OnnxReranker {
    /// Load a cross-encoder ONNX export + its `tokenizer.json`. `model_name`
    /// is a stable identity used only for logging. A probe forward pass runs
    /// at load so an incompatible model fails fast here rather than mid-search.
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

        let me = Self {
            model,
            tokenizer,
            n_inputs,
            name: model_name.to_string(),
        };
        // Fail-fast probe: exercise the full pair-encode + forward path.
        me.score_inner("query", "passage")
            .map_err(|e| OnnxError::Model(e.to_string()))?;
        Ok(me)
    }

    /// Load from `UNDERCROFT_RERANK_MODEL`, `UNDERCROFT_RERANK_TOKENIZER`, and
    /// optional `UNDERCROFT_RERANK_NAME`.
    pub fn from_env() -> Result<Self, OnnxError> {
        let model = std::env::var("UNDERCROFT_RERANK_MODEL")
            .map_err(|_| OnnxError::Model("UNDERCROFT_RERANK_MODEL is not set".into()))?;
        let tokenizer = std::env::var("UNDERCROFT_RERANK_TOKENIZER")
            .map_err(|_| OnnxError::Tokenizer("UNDERCROFT_RERANK_TOKENIZER is not set".into()))?;
        let name =
            std::env::var("UNDERCROFT_RERANK_NAME").unwrap_or_else(|_| "onnx-reranker".into());
        Self::load(
            std::path::Path::new(&model),
            std::path::Path::new(&tokenizer),
            &name,
        )
    }

    fn score_inner(&self, query: &str, passage: &str) -> Result<f32, OnnxError> {
        // Pair encode → [CLS] query [SEP] passage [SEP] with token_type_ids
        // marking the two segments (the cross-encoder input contract).
        let enc = self
            .tokenizer
            .encode((query, passage), true)
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
        let logits = outputs[0]
            .to_array_view::<f32>()
            .map_err(|e| OnnxError::Inference(e.to_string()))?;
        // Sequence-classification head: shape (1, num_labels). A single-label
        // reranker gives (1,1); a 2-label head gives (1,2) — take the last
        // (positive/relevant) logit. Squash to [0,1] for a bounded, monotonic
        // ranking score.
        let flat: Vec<f32> = logits.iter().copied().collect();
        let raw = match flat.last() {
            Some(&v) => v,
            None => return Err(OnnxError::Inference("empty reranker output".into())),
        };
        Ok(sigmoid(raw))
    }
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

impl Reranker for OnnxReranker {
    fn model_name(&self) -> &str {
        &self.name
    }

    fn score(&self, query: &str, passage: &str) -> f32 {
        // Infallible on the hot path: a runtime failure degrades to a neutral
        // low score rather than aborting the search. `load` already ran a
        // probe, so failures here are rare (e.g. a pathological input).
        self.score_inner(query, passage).unwrap_or(0.0)
    }

    fn score_batch(&self, query: &str, passages: &[&str]) -> Vec<f32> {
        // tract runs one batch-dim-1 forward per pair, but the passes are
        // independent — fan them across cores. This is where the whole-pool
        // parallelism lives (the store just calls `score_batch`).
        use rayon::prelude::*;
        passages.par_iter().map(|p| self.score(query, p)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loads a real cross-encoder from `UNDERCROFT_RERANK_MODEL`/`_TOKENIZER`
    /// and asserts it (a) runs in tract at all — the load probe — and (b)
    /// ranks a relevant passage above an irrelevant one. Ignored by default;
    /// run with the env set:
    ///   UNDERCROFT_RERANK_MODEL=… UNDERCROFT_RERANK_TOKENIZER=… \
    ///   cargo test -p undercroft-embed-onnx --features "" rerank -- --ignored --nocapture
    #[test]
    #[ignore = "requires a user-supplied cross-encoder ONNX model via env"]
    fn ranks_relevant_above_irrelevant() {
        let rr = OnnxReranker::from_env().expect("load reranker from env");
        let query = "When did Caroline join the LGBTQ support group?";
        let relevant = "Caroline mentioned she went to an LGBTQ support group meeting last week.";
        let irrelevant = "The gateway rate limits use a token bucket algorithm.";
        let s_rel = rr.score(query, relevant);
        let s_irr = rr.score(query, irrelevant);
        println!(
            "relevant={s_rel:.4} irrelevant={s_irr:.4} model={}",
            rr.model_name()
        );
        assert!(
            s_rel > s_irr,
            "expected relevant > irrelevant, got {s_rel} vs {s_irr}"
        );
    }
}
