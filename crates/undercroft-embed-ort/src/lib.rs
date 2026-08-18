//! ONNX Runtime (`ort`) inference backend for Undercroft.
//!
//! A faster, **opt-in** alternative to the default pure-Rust `tract` backend
//! ([`undercroft-embed-onnx`]): same user-supplied ONNX models, same
//! sentence-embedding recipe (mean pool + L2 norm) and cross-encoder scoring,
//! but run through ONNX Runtime's optimized (SIMD/VNNI) C++ kernels — measured
//! ~2.5× faster per forward than tract, ~2× more with int8. It **links ONNX
//! Runtime's C++ library**, so it is not pure-Rust and is offered as a separate
//! crate you compile only when you want it (see the `ort-build` compose
//! service). Accuracy is identical to tract for the same weights.
//!
//! Plugs into the palace through the same [`Embedder`] / [`Reranker`] traits.
//! The reranker overrides [`Reranker::score_batch`] to score the whole pool in
//! **one batched forward** (ORT handles a dynamic batch dimension natively,
//! unlike tract's fixed batch-1 load) — the store calls `score_batch`, so the
//! backend picks its own parallel strategy. The ColBERT late-interaction
//! encoder lives in [`late`] (same fixed-shape exports as the tract backend).

mod late;
pub use late::{colbert_from_env, OrtColbert};

use std::sync::Mutex;

use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::Tensor;
use tokenizers::Tokenizer;
use undercroft_core::embed::Embedder;
use undercroft_core::rerank::Reranker;

const MAX_LEN: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum OrtError {
    #[error("failed to load tokenizer: {0}")]
    Tokenizer(String),
    #[error("failed to load onnx model: {0}")]
    Model(String),
    #[error("inference failed: {0}")]
    Inference(String),
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// `(ids, mask, type_ids)`, each padded / truncated to `MAX_LEN`.
type Encoded = (Vec<i64>, Vec<i64>, Vec<i64>);

/// Tokenize `a` (and optional pair `b`) → [`Encoded`].
fn encode(tok: &Tokenizer, a: &str, b: Option<&str>) -> Result<Encoded, OrtError> {
    let enc = match b {
        Some(bb) => tok.encode((a, bb), true),
        None => tok.encode(a, true),
    }
    .map_err(|e| OrtError::Inference(e.to_string()))?;
    let pad = |v: &[u32]| -> Vec<i64> {
        let mut o: Vec<i64> = v.iter().take(MAX_LEN).map(|&x| x as i64).collect();
        o.resize(MAX_LEN, 0);
        o
    };
    Ok((
        pad(enc.get_ids()),
        pad(enc.get_attention_mask()),
        pad(enc.get_type_ids()),
    ))
}

fn cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn build_session(path: &str, threads: usize) -> Result<(Session, usize), OrtError> {
    let threads = threads.max(1);
    let session = Session::builder()
        .map_err(|e| OrtError::Model(e.to_string()))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|e| OrtError::Model(e.to_string()))?
        .with_intra_threads(threads)
        .map_err(|e| OrtError::Model(e.to_string()))?
        .commit_from_file(path)
        .map_err(|e| OrtError::Model(e.to_string()))?;
    let n_inputs = session.inputs.len();
    Ok((session, n_inputs))
}

/// Run a `[b, len]` batch → `(output dims, flat output data)`.
fn run_batch(
    session: &mut Session,
    n_inputs: usize,
    b: usize,
    len: usize,
    ids: Vec<i64>,
    mask: Vec<i64>,
    types: Vec<i64>,
) -> Result<(Vec<usize>, Vec<f32>), OrtError> {
    let mk = |v: Vec<i64>| {
        Tensor::from_array(([b, len], v)).map_err(|e| OrtError::Inference(e.to_string()))
    };
    let outputs = if n_inputs >= 3 {
        session.run(ort::inputs![
            "input_ids" => mk(ids)?,
            "attention_mask" => mk(mask)?,
            "token_type_ids" => mk(types)?,
        ])
    } else {
        session.run(ort::inputs![
            "input_ids" => mk(ids)?,
            "attention_mask" => mk(mask)?,
        ])
    }
    .map_err(|e| OrtError::Inference(e.to_string()))?;
    let (shape, data) = outputs[0]
        .try_extract_tensor::<f32>()
        .map_err(|e| OrtError::Inference(e.to_string()))?;
    let dims: Vec<usize> = shape.iter().map(|&d| d as usize).collect();
    Ok((dims, data.to_vec()))
}

// ---------------------------------------------------------------------------
// Embedder
// ---------------------------------------------------------------------------

pub struct OrtEmbedder {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    n_inputs: usize,
    dim: usize,
    name: String,
}

impl OrtEmbedder {
    pub fn load(
        model_path: &std::path::Path,
        tokenizer_path: &std::path::Path,
        model_name: &str,
    ) -> Result<Self, OrtError> {
        let tokenizer =
            Tokenizer::from_file(tokenizer_path).map_err(|e| OrtError::Tokenizer(e.to_string()))?;
        let (session, n_inputs) = build_session(&model_path.to_string_lossy(), cores())?;
        let mut me = Self {
            session: Mutex::new(session),
            tokenizer,
            n_inputs,
            dim: 0,
            name: model_name.to_string(),
        };
        me.dim = me.embed_inner("dimension probe")?.len();
        Ok(me)
    }

    fn embed_inner(&self, text: &str) -> Result<Vec<f32>, OrtError> {
        let (ids, mask, types) = encode(&self.tokenizer, text, None)?;
        let (dims, data) = {
            let mut guard = self.session.lock().expect("ort session mutex");
            run_batch(
                &mut guard,
                self.n_inputs,
                1,
                MAX_LEN,
                ids,
                mask.clone(),
                types,
            )?
        };
        // dims: (1, seq, dim) — masked mean pool + L2 normalize.
        if dims.len() < 3 {
            return Err(OrtError::Inference(
                "unexpected embedder output rank".into(),
            ));
        }
        let (seq, dim) = (dims[1], dims[2]);
        let mut pooled = vec![0f32; dim];
        let mut denom = 0f32;
        for t in 0..seq.min(MAX_LEN) {
            if mask[t] == 0 {
                continue;
            }
            denom += 1.0;
            for d in 0..dim {
                pooled[d] += data[t * dim + d];
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

impl Embedder for OrtEmbedder {
    fn model_name(&self) -> &str {
        &self.name
    }
    fn dimension(&self) -> usize {
        self.dim
    }
    fn embed(&self, text: &str) -> Vec<f32> {
        self.embed_inner(text)
            .unwrap_or_else(|_| vec![0.0; self.dim.max(1)])
    }
}

/// Load the ORT embedder from `UNDERCROFT_ONNX_MODEL` / `_TOKENIZER` / `_NAME`
/// (same env as the tract embedder — same model file works).
pub fn embedder_from_env() -> Result<OrtEmbedder, OrtError> {
    let model = std::env::var("UNDERCROFT_ONNX_MODEL")
        .map_err(|_| OrtError::Model("UNDERCROFT_ONNX_MODEL is not set".into()))?;
    let tokenizer = std::env::var("UNDERCROFT_ONNX_TOKENIZER")
        .map_err(|_| OrtError::Tokenizer("UNDERCROFT_ONNX_TOKENIZER is not set".into()))?;
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
    OrtEmbedder::load(
        std::path::Path::new(&model),
        std::path::Path::new(&tokenizer),
        &name,
    )
}

// ---------------------------------------------------------------------------
// Reranker
// ---------------------------------------------------------------------------

pub struct OrtReranker {
    /// A pool of single-threaded sessions: the independent `(query, passage)`
    /// forwards fan out across them (one per core), so a `top_n ≤ pool` rerank
    /// costs ~one single-thread forward instead of a linearly-scaling batched
    /// one. Pool size defaults to the core count; `UNDERCROFT_ORT_POOL` tunes it
    /// (each session holds its own copy of the model — memory scales with it).
    sessions: Vec<Mutex<Session>>,
    tokenizer: Tokenizer,
    n_inputs: usize,
    name: String,
}

impl OrtReranker {
    pub fn load(
        model_path: &std::path::Path,
        tokenizer_path: &std::path::Path,
        model_name: &str,
    ) -> Result<Self, OrtError> {
        let tokenizer =
            Tokenizer::from_file(tokenizer_path).map_err(|e| OrtError::Tokenizer(e.to_string()))?;
        let pool = std::env::var("UNDERCROFT_ORT_POOL")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or_else(cores);
        // pool == 1 ⇒ a single all-core session (the batched/few-core mode);
        // pool > 1 ⇒ single-thread sessions the forwards fan out across.
        let per_session_threads = if pool > 1 { 1 } else { cores() };
        let path = model_path.to_string_lossy().to_string();
        // Session creation costs ~seconds each — build the pool in parallel.
        use rayon::prelude::*;
        let built: Result<Vec<(Session, usize)>, OrtError> = (0..pool)
            .into_par_iter()
            .map(|_| build_session(&path, per_session_threads))
            .collect();
        let built = built?;
        let n_inputs = built.first().map(|(_, n)| *n).unwrap_or(0);
        let sessions = built.into_iter().map(|(s, _)| Mutex::new(s)).collect();
        let me = Self {
            sessions,
            tokenizer,
            n_inputs,
            name: model_name.to_string(),
        };
        // Fail-fast probe.
        me.score_batch_inner("query", &["passage"])?;
        Ok(me)
    }

    /// One `(query, passage)` forward on pool slot `slot`.
    fn score_one(&self, slot: usize, query: &str, passage: &str) -> Result<f32, OrtError> {
        let (ids, mask, types) = encode(&self.tokenizer, query, Some(passage))?;
        let (dims, data) = {
            let mut guard = self.sessions[slot].lock().expect("ort session mutex");
            run_batch(&mut guard, self.n_inputs, 1, MAX_LEN, ids, mask, types)?
        };
        // dims: (1, num_labels) — take the last (positive) logit.
        let labels = if dims.len() >= 2 { dims[1].max(1) } else { 1 };
        Ok(sigmoid(data.get(labels - 1).copied().unwrap_or(0.0)))
    }

    /// Fan the independent pair-forwards across the session pool: each rayon
    /// worker owns a pool slot, so `top_n ≤ pool` completes in ~one wave.
    fn score_batch_inner(&self, query: &str, passages: &[&str]) -> Result<Vec<f32>, OrtError> {
        if passages.is_empty() {
            return Ok(Vec::new());
        }
        use rayon::prelude::*;
        passages
            .par_iter()
            .map(|p| {
                let slot = rayon::current_thread_index().unwrap_or(0) % self.sessions.len();
                self.score_one(slot, query, p)
            })
            .collect()
    }
}

impl Reranker for OrtReranker {
    fn model_name(&self) -> &str {
        &self.name
    }
    fn score(&self, query: &str, passage: &str) -> f32 {
        self.score_batch_inner(query, &[passage])
            .ok()
            .and_then(|v| v.first().copied())
            .unwrap_or(0.0)
    }
    fn score_batch(&self, query: &str, passages: &[&str]) -> Vec<f32> {
        self.score_batch_inner(query, passages)
            .unwrap_or_else(|_| vec![0.0; passages.len()])
    }
}

/// Load the ORT reranker from `UNDERCROFT_RERANK_MODEL` / `_TOKENIZER` / `_NAME`.
pub fn reranker_from_env() -> Result<OrtReranker, OrtError> {
    let model = std::env::var("UNDERCROFT_RERANK_MODEL")
        .map_err(|_| OrtError::Model("UNDERCROFT_RERANK_MODEL is not set".into()))?;
    let tokenizer = std::env::var("UNDERCROFT_RERANK_TOKENIZER")
        .map_err(|_| OrtError::Tokenizer("UNDERCROFT_RERANK_TOKENIZER is not set".into()))?;
    let name = std::env::var("UNDERCROFT_RERANK_NAME").unwrap_or_else(|_| {
        undercroft_obs::diag_warn!(
            "{}",
            undercroft_core::config::undeclared_model_identity(
                "UNDERCROFT_RERANK_NAME",
                "onnx-reranker",
                &model,
            )
        );
        "onnx-reranker".into()
    });
    OrtReranker::load(
        std::path::Path::new(&model),
        std::path::Path::new(&tokenizer),
        &name,
    )
}
