//! ColBERT late-interaction encoder on tract (pure Rust).
//!
//! Runs a ColBERT checkpoint exported to ONNX **with its projection layer**
//! (BERT → linear(128) → per-row L2 normalize baked into the graph, so the
//! model output *is* the token matrix). A plain feature-extraction export
//! won't work — it drops the projection. See the export recipe in
//! docs/RETRIEVAL_SCALING.md.
//!
//! ColBERT input conventions (v2):
//! - **doc**:   `[CLS] [D] tokens… [SEP]` (`[D]` = `[unused1]`, id 2);
//!   matrix keeps the attended rows.
//! - **query**: `[CLS] [Q] tokens… [SEP]` (`[Q]` = `[unused0]`, id 1),
//!   **mask-augmented** to `QUERY_LEN` with `[MASK]` (id 103) tokens that DO
//!   attend — the model emits query-expansion embeddings at those positions,
//!   and all `QUERY_LEN` rows participate in MaxSim.
//!
//! Like every model here: user-supplied files, no download, no network.
//! `UNDERCROFT_COLBERT_MODEL` / `_TOKENIZER` / optional `_NAME`.

use undercroft_core::late::LateInteraction;
use tokenizers::Tokenizer;
use tract_onnx::prelude::*;

use crate::{OnnxError, RunnableOnnx};

/// Fixed compiled sequence lengths (tract wants static shapes). Docs are
/// drawer chunks (~100–200 tokens); queries follow ColBERT's canonical 32.
const DOC_LEN: usize = 256;
const QUERY_LEN: usize = 32;

const CLS: i64 = 101;
const SEP: i64 = 102;
const MASK: i64 = 103;
const Q_MARKER: i64 = 1; // [unused0]
const D_MARKER: i64 = 2; // [unused1]

/// ColBERT encoder over two tract plans (query- and doc-length) compiled
/// from one ONNX file.
pub struct OnnxColbert {
    doc_model: RunnableOnnx,
    query_model: RunnableOnnx,
    tokenizer: Tokenizer,
    dim: usize,
    name: String,
}

impl OnnxColbert {
    /// Load the exported models (fixed-shape doc + query variants — see the
    /// export recipe: dynamic-axis exports carry `Range`/symbolic-dim ops
    /// tract rejects) + `tokenizer.json`. A probe forward runs at load so an
    /// incompatible export fails here, not mid-search.
    pub fn load(
        doc_model_path: &std::path::Path,
        query_model_path: &std::path::Path,
        tokenizer_path: &std::path::Path,
        model_name: &str,
    ) -> Result<Self, OnnxError> {
        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| OnnxError::Tokenizer(e.to_string()))?;
        let compile =
            |model_path: &std::path::Path, len: usize| -> Result<RunnableOnnx, OnnxError> {
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
                            InferenceFact::dt_shape(i64::datum_type(), tvec!(1, len as i64)),
                        )
                        .map_err(|e| OnnxError::Model(e.to_string()))?;
                }
                inference
                    .into_optimized()
                    .map_err(|e| OnnxError::Model(e.to_string()))?
                    .into_runnable()
                    .map_err(|e| OnnxError::Model(e.to_string()))
            };
        let mut me = Self {
            doc_model: compile(doc_model_path, DOC_LEN)?,
            query_model: compile(query_model_path, QUERY_LEN)?,
            tokenizer,
            dim: 0,
            name: model_name.to_string(),
        };
        let probe = me
            .run(&me.query_model, &[CLS, Q_MARKER, SEP], QUERY_LEN, true)
            .map_err(|e| OnnxError::Model(format!("probe forward failed: {e}")))?;
        if probe.1 == 0 {
            return Err(OnnxError::Model(
                "probe produced an empty token matrix".into(),
            ));
        }
        me.dim = probe.1;
        Ok(me)
    }

    /// Tokenize `text` without special tokens, returning raw ids.
    fn word_ids(&self, text: &str) -> Result<Vec<i64>, OnnxError> {
        let enc = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| OnnxError::Inference(e.to_string()))?;
        Ok(enc.get_ids().iter().map(|&v| v as i64).collect())
    }

    /// Run one forward over `ids` padded/framed to `len`. `augment` = pad
    /// with attending `[MASK]` tokens (query side) instead of ignored zeros
    /// (doc side). Returns `(row-major matrix of kept rows, dim)`.
    fn run(
        &self,
        model: &RunnableOnnx,
        ids: &[i64],
        len: usize,
        augment: bool,
    ) -> Result<(Vec<f32>, usize), OnnxError> {
        let mut input: Vec<i64> = ids.to_vec();
        input.truncate(len);
        let mut mask: Vec<i64> = vec![1; input.len()];
        while input.len() < len {
            input.push(if augment { MASK } else { 0 });
            mask.push(if augment { 1 } else { 0 });
        }
        let to_tensor = |v: &[i64]| -> Result<Tensor, OnnxError> {
            tract_ndarray::Array2::from_shape_vec((1, len), v.to_vec())
                .map(Tensor::from)
                .map_err(|e| OnnxError::Inference(e.to_string()))
        };
        let outputs = model
            .run(tvec!(to_tensor(&input)?.into(), to_tensor(&mask)?.into()))
            .map_err(|e| OnnxError::Inference(e.to_string()))?;
        let hidden = outputs[0]
            .to_array_view::<f32>()
            .map_err(|e| OnnxError::Inference(e.to_string()))?;
        let shape = hidden.shape();
        let (seq, dim) = (shape[1], shape[2]);
        let mut matrix = Vec::with_capacity(seq * dim);
        for t in 0..seq.min(len) {
            if mask[t] == 0 {
                continue; // pad rows never participate
            }
            for d in 0..dim {
                matrix.push(hidden[[0, t, d]]);
            }
        }
        Ok((matrix, dim))
    }

    fn frame(&self, marker: i64, text: &str, len: usize) -> Result<Vec<i64>, OnnxError> {
        let mut ids = self.word_ids(text)?;
        ids.truncate(len - 3);
        let mut framed = Vec::with_capacity(ids.len() + 3);
        framed.push(CLS);
        framed.push(marker);
        framed.extend(ids);
        framed.push(SEP);
        Ok(framed)
    }
}

impl LateInteraction for OnnxColbert {
    fn model_name(&self) -> &str {
        &self.name
    }

    fn dim(&self) -> usize {
        self.dim
    }

    fn encode_doc(&self, text: &str) -> Vec<f32> {
        // Infallible like the Embedder: failure degrades to an empty matrix
        // (the candidate keeps its fusion rank; `repair` can re-encode).
        self.frame(D_MARKER, text, DOC_LEN)
            .and_then(|ids| self.run(&self.doc_model, &ids, DOC_LEN, false))
            .map(|(m, _)| m)
            .unwrap_or_default()
    }

    fn encode_query(&self, text: &str) -> Vec<f32> {
        self.frame(Q_MARKER, text, QUERY_LEN)
            .and_then(|ids| self.run(&self.query_model, &ids, QUERY_LEN, true))
            .map(|(m, _)| m)
            .unwrap_or_default()
    }
}

/// Load from `UNDERCROFT_COLBERT_MODEL` (doc-length export),
/// `UNDERCROFT_COLBERT_QUERY_MODEL` (query-length export),
/// `UNDERCROFT_COLBERT_TOKENIZER`, and optional `UNDERCROFT_COLBERT_NAME`.
pub fn colbert_from_env() -> Result<OnnxColbert, OnnxError> {
    let doc = std::env::var("UNDERCROFT_COLBERT_MODEL")
        .map_err(|_| OnnxError::Model("UNDERCROFT_COLBERT_MODEL is not set".into()))?;
    let query = std::env::var("UNDERCROFT_COLBERT_QUERY_MODEL")
        .map_err(|_| OnnxError::Model("UNDERCROFT_COLBERT_QUERY_MODEL is not set".into()))?;
    let tokenizer = std::env::var("UNDERCROFT_COLBERT_TOKENIZER")
        .map_err(|_| OnnxError::Tokenizer("UNDERCROFT_COLBERT_TOKENIZER is not set".into()))?;
    let name = std::env::var("UNDERCROFT_COLBERT_NAME").unwrap_or_else(|_| "colbert".into());
    OnnxColbert::load(
        std::path::Path::new(&doc),
        std::path::Path::new(&query),
        std::path::Path::new(&tokenizer),
        &name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use undercroft_core::late::maxsim;

    /// Full inference test, gated on a user-provided export
    /// (set UNDERCROFT_COLBERT_MODEL + UNDERCROFT_COLBERT_TOKENIZER to run).
    #[test]
    fn late_interaction_ranks_related_passages_higher() {
        if std::env::var("UNDERCROFT_COLBERT_MODEL").is_err() {
            eprintln!("skipping: UNDERCROFT_COLBERT_MODEL not set");
            return;
        }
        let c = colbert_from_env().expect("model loads");
        let q = c.encode_query("why did the build break");
        let rel = c.encode_doc("the build failed because of a stale lockfile in ci");
        let unrel = c.encode_doc("the cat enjoys sunbathing on the warm windowsill");
        assert!(!q.is_empty() && !rel.is_empty() && !unrel.is_empty());
        assert_eq!(q.len() % c.dim(), 0);
        let (s_rel, s_unrel) = (maxsim(&q, &rel, c.dim()), maxsim(&q, &unrel, c.dim()));
        assert!(
            s_rel > s_unrel,
            "related passage must outscore unrelated: {s_rel} vs {s_unrel}"
        );
    }
}
