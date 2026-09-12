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
    /// Embeds degraded to a zero vector (ROADMAP O122). Atomic because the
    /// multi-tenant server shares ONE of these across every vault, so the
    /// count is process-wide there and `stats` on any vault reports it.
    failures: std::sync::atomic::AtomicU64,
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
            failures: std::sync::atomic::AtomicU64::new(0),
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
        // Infallible by contract, so a runtime failure degrades to a zero
        // vector rather than failing the write — and since ROADMAP O122 it
        // is COUNTED and said, exactly as the served embedder's is. It was
        // `.unwrap_or_else(|_| zeros)` with no trace at all: a corpus of
        // holes that reported a clean vector space on every surface.
        match self.embed_inner(text) {
            Ok(v) => v,
            Err(e) => {
                let n = self
                    .failures
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;
                undercroft_obs::embed_failed("ort");
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
                undercroft_core::config::SHARED_MODEL_IDENTITY,
                &model,
            )
        );
        undercroft_core::config::SHARED_MODEL_IDENTITY.into()
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
    /// Scores degraded to 0.0 (ROADMAP O131). Atomic: the pair-forwards fan
    /// across rayon workers, and the server shares one reranker per process.
    failures: std::sync::atomic::AtomicU64,
}

impl OrtReranker {
    pub fn load(
        model_path: &std::path::Path,
        tokenizer_path: &std::path::Path,
        model_name: &str,
    ) -> Result<Self, OrtError> {
        let tokenizer =
            Tokenizer::from_file(tokenizer_path).map_err(|e| OrtError::Tokenizer(e.to_string()))?;
        // ROADMAP O52: an unreadable declaration used to be swallowed, so
        // `UNDERCROFT_ORT_POOL=4x` silently used the core count with no signal.
        // The fallback is unchanged — absence and garbage both mean "derive it
        // from the cores" — but it is reported now.
        let pool_raw = std::env::var("UNDERCROFT_ORT_POOL").ok();
        let pool = match undercroft_core::config::positive_usize(
            "UNDERCROFT_ORT_POOL",
            pool_raw.as_deref(),
        ) {
            Ok(n) => n,
            Err(f) => {
                undercroft_obs::diag_warn!("{}", f.why);
                f.value
            }
        }
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
            failures: std::sync::atomic::AtomicU64::new(0),
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

    /// Count `n` degraded scores and say so once (ROADMAP O131). One place,
    /// so the two `Reranker` arms cannot report the failure differently.
    fn note_failures(&self, n: u64, why: &str) {
        if n == 0 {
            return;
        }
        let total = self
            .failures
            .fetch_add(n, std::sync::atomic::Ordering::SeqCst)
            + n;
        undercroft_obs::rerank_failed("ort", n);
        undercroft_obs::diag_error!(
            "rerank failed ({why}); scoring {n} candidate(s) 0.0 — they sink to the \
             bottom of the reranked window and are indistinguishable from irrelevant \
             passages. Failures so far: {total}"
        );
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
    /// One pair, one forward — straight onto [`OrtReranker::score_one`].
    ///
    /// **This used to route through `score_batch_inner`, and that gave it a
    /// counted arm nothing could ever reach** (ROADMAP O134a). With exactly
    /// one passage that function returns either `Err` or a one-element `Vec`
    /// — the empty early return needs `passages.is_empty()` — so the
    /// `Ok(v) => v.first() … unwrap_or_else(|| note_failures(1, …))` arm was
    /// dead code wearing the shape of a degrade. Dead is not harmless here:
    /// it sat in the inventory of arms a test is required to exercise, so it
    /// could only ever be covered by a test asserting a thing that cannot
    /// happen.
    ///
    /// Removed by RESTRUCTURING rather than by deletion. `v[0]` would turn
    /// dead-but-safe code into a panic, and `unwrap_or(0.0)` would put back
    /// the uncounted degrade O131 closed.
    ///
    /// The slot expression is preserved VERBATIM from `score_batch_inner`.
    /// This is result-preserving, not scheduling-preserving: that function
    /// evaluates the expression inside a `par_iter`, so a direct call from a
    /// non-rayon caller now pins slot 0 where it used to pin whichever
    /// worker rayon happened to fold the one-element producer onto. No value
    /// moves — every session in the pool is an identical copy of one file.
    ///
    /// Residual, stated rather than fixed here: `score_one` ends in
    /// `data.get(labels - 1).copied().unwrap_or(0.0)`, which is a SECOND and
    /// still-uncounted degrade one line below the arm this edit touches. It
    /// is deliberately left alone and filed separately — see ROADMAP O152.
    fn score(&self, query: &str, passage: &str) -> f32 {
        let slot = rayon::current_thread_index().unwrap_or(0) % self.sessions.len();
        match self.score_one(slot, query, passage) {
            Ok(s) => s,
            Err(e) => {
                self.note_failures(1, &e.to_string());
                0.0
            }
        }
    }
    fn score_batch(&self, query: &str, passages: &[&str]) -> Vec<f32> {
        match self.score_batch_inner(query, passages) {
            Ok(v) => v,
            Err(e) => {
                // The WHOLE batch degraded, so this is `passages.len()`
                // failures and not one: every candidate in the reranked
                // window is about to be scored 0.0 and re-sorted against
                // the others (ROADMAP O131).
                self.note_failures(passages.len() as u64, &e.to_string());
                vec![0.0; passages.len()]
            }
        }
    }
    fn score_failures(&self) -> u64 {
        self.failures.load(std::sync::atomic::Ordering::SeqCst)
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
                undercroft_core::config::SHARED_RERANKER_IDENTITY,
                &model,
            )
        );
        undercroft_core::config::SHARED_RERANKER_IDENTITY.into()
    });
    OrtReranker::load(
        std::path::Path::new(&model),
        std::path::Path::new(&tokenizer),
        &name,
    )
}

#[cfg(test)]
// The anchor lesson, cheaply: a scripted edit that eats a `#[test]`
// attribute turns a live gate into dead code and no test can report it —
// the test IS the thing that stopped running. `dead_code` says so
// (ROADMAP O134a).
#[deny(dead_code, unused)]
mod tests {
    use super::*;
    use undercroft_embed_onnx::fixture;

    /// The healthy score this fixture produces. Both rerankers read a
    /// PADDING position, so the raw logit is [`fixture::PAD_LAST`] — neither
    /// `0.0` (the degrade) nor `0.5` (the filed empty-logit value).
    fn healthy_score() -> f32 {
        1.0 / (1.0 + (-fixture::PAD_LAST).exp())
    }

    fn load_fixture_reranker(dir: &std::path::Path) -> OrtReranker {
        let (model, tok) = fixture::write_into(dir).expect("write fixture");
        OrtReranker::load(&model, &tok, "fixture").expect("fixture loads")
    }

    /// **The generator's premise on THIS backend: one generated file runs in
    /// both runtimes.**
    ///
    /// The whole of ROADMAP O134a rests on it. tract binds graph inputs by
    /// POSITION and ORT binds them by NAME, and the two disagree about
    /// almost nothing else — so if one file ever stopped serving both, every
    /// arm test in this crate would fail for a reason unrelated to the arm
    /// it names. This is what tells those apart.
    #[test]
    fn the_fixture_loads_in_ort_and_runs_a_healthy_forward() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (model, tok) = fixture::write_into(dir.path()).expect("write fixture");
        let e = OrtEmbedder::load(&model, &tok, "fixture").expect("the fixture must load in ORT");
        assert_eq!(
            e.dimension(),
            fixture::DIM,
            "the probe forward must report the fixture's hidden size"
        );

        let v = e.embed(fixture::HEALTHY);
        assert_eq!(v.len(), fixture::DIM);
        assert!(
            v.iter().all(|x| x.is_finite()),
            "a healthy embed must be finite"
        );
        assert!(
            v.iter().any(|x| *x != 0.0),
            "a healthy embed must be distinguishable from the zero-vector degrade"
        );
        assert_eq!(
            e.embed_failures(),
            0,
            "a healthy embed must not count a failure"
        );
    }

    /// **The embed arm: a degraded embed is COUNTED** (ROADMAP O122,
    /// executed for the first time by O134a).
    #[test]
    fn ort_embed_counts_each_degraded_embed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (model, tok) = fixture::write_into(dir.path()).expect("write fixture");
        let e = OrtEmbedder::load(&model, &tok, "fixture").expect("fixture loads");

        // PREMISE.
        assert_eq!(
            e.embed_failures(),
            0,
            "load must not have counted a failure"
        );
        let healthy = e.embed(fixture::HEALTHY);
        assert!(
            healthy.iter().any(|x| *x != 0.0),
            "a healthy embed must not be the zero vector"
        );
        assert_eq!(
            e.embed_failures(),
            0,
            "a healthy embed must not move the count"
        );

        // DEGRADE.
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

        // RECOVERY.
        assert_eq!(
            e.embed(fixture::HEALTHY),
            healthy,
            "a healthy embed after a failure must be unchanged"
        );
        assert_eq!(
            e.embed_failures(),
            1,
            "a healthy embed must not move the count"
        );
    }

    /// **The score arm: a degraded single score is COUNTED once** (ROADMAP
    /// O131, executed for the first time by O134a).
    ///
    /// This is also the behaviour gate on O134a's own shipped-code change:
    /// `score` was restructured off `score_batch_inner` onto `score_one` to
    /// delete an unreachable counted arm. Value and count must be exactly
    /// what they were.
    #[test]
    fn ort_rerank_counts_each_degraded_score() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rr = load_fixture_reranker(dir.path());

        // PREMISE.
        assert_eq!(
            rr.score_failures(),
            0,
            "load must not have counted a failure"
        );
        let healthy = rr.score("query", fixture::HEALTHY);
        assert!(
            (healthy - healthy_score()).abs() < 1e-5,
            "a healthy score must be sigmoid(PAD_LAST), got {healthy}"
        );
        assert_eq!(
            rr.score_failures(),
            0,
            "a healthy score must not move the count"
        );

        // DEGRADE.
        assert_eq!(
            rr.score("query", fixture::REFUSED_WORD),
            0.0,
            "a failed score must degrade to 0.0"
        );
        assert_eq!(
            rr.score_failures(),
            1,
            "a failed score must be counted exactly once"
        );

        // RECOVERY.
        assert!((rr.score("query", fixture::HEALTHY) - healthy).abs() < 1e-6);
        assert_eq!(
            rr.score_failures(),
            1,
            "a healthy score must not move the count"
        );
    }

    /// **PINNED BEHAVIOUR, UNDER REVIEW — see ROADMAP O151.**
    ///
    /// ORT's `score_batch` collapses the WHOLE reranked window when ONE pair
    /// fails: `score_batch_inner` collects a `Result` over rayon, so the
    /// first `Err` discards seven healthy scores and `note_failures` counts
    /// eight. The tract backend degrades per passage for the same input
    /// (`onnx_rerank_score_batch_counts_each_poisoned_passage`), so one
    /// decision has two implementations.
    ///
    /// This pins the COUPLING and not merely the count. Phase 1 scores the
    /// seven healthy passages ALONE and shows they score; phase 2 shows the
    /// same seven come back `0.0` inside a batch with one poisoned peer.
    /// Without phase 1 the pin could not exceed its own threshold — all-zero
    /// would be indistinguishable from a fixture that never scored anything.
    ///
    /// O151 decides the semantics. When it lands per-passage, THIS TEST goes
    /// red, by name, and that is the intended signal.
    #[test]
    fn ort_rerank_score_batch_degrades_the_whole_window_pinned_cost() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rr = load_fixture_reranker(dir.path());

        let poisoned_at = 3usize;
        let owned: Vec<String> = (0..8)
            .map(|i| {
                if i == poisoned_at {
                    format!("{} {}", fixture::HEALTHY, fixture::REFUSED_WORD)
                } else {
                    fixture::HEALTHY.to_string()
                }
            })
            .collect();
        let passages: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();

        // PHASE 1: every passage except the poisoned one scores on its own.
        for (i, p) in passages.iter().enumerate() {
            if i == poisoned_at {
                continue;
            }
            let s = rr.score("query", p);
            assert!(
                (s - healthy_score()).abs() < 1e-5,
                "passage {i} must score healthily ALONE, got {s}"
            );
        }
        assert_eq!(
            rr.score_failures(),
            0,
            "seven healthy single scores must count nothing"
        );

        // PHASE 2: the same seven, batched with one poisoned peer.
        let scores = rr.score_batch("query", &passages);
        assert_eq!(scores.len(), 8);
        assert!(
            scores.iter().all(|s| *s == 0.0),
            "PINNED COST (ROADMAP O151): one failing pair zeroes the WHOLE window, including the seven that just scored healthily — got {scores:?}"
        );
        assert_eq!(
            rr.score_failures(),
            8,
            "PINNED COST (ROADMAP O151): the whole window is counted, not the one pair that failed"
        );
    }

    /// **Route R: what ONNX Runtime does with an id past the embedding
    /// table — CLASSIFIED, not predicted** (ROADMAP O134a, O150).
    ///
    /// The tract backend PANICS here (observed, pinned in that crate's own
    /// route-R arm). Whether ORT agrees is the thing this measures rather
    /// than assumes — and it does not: ORT reports a typed error that
    /// reaches the counted degrade, so the same misconfiguration crashes one
    /// backend and is absorbed by the other.
    #[test]
    fn ort_route_r_classifies_an_out_of_table_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (model, tok) = fixture::write_into(dir.path()).expect("write fixture");
        let e = OrtEmbedder::load(&model, &tok, "fixture").expect("fixture loads");

        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            e.embed(fixture::OUT_OF_TABLE_WORD)
        }));
        std::panic::set_hook(prev);

        match outcome {
            Err(payload) => {
                let what = payload
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("<non-string panic payload>");
                println!(
                    "ROUTE-R ort: ONNX Runtime PANICKED on an out-of-table id. Payload: {what}"
                );
                assert_eq!(
                    e.embed_failures(),
                    0,
                    "a panic is not a degrade: nothing may have been counted"
                );
            }
            Ok(v) => {
                let counted = e.embed_failures();
                println!(
                    "ROUTE-R ort: ONNX Runtime returned a value, {counted} counted failure(s)"
                );
                assert_eq!(
                    counted, 1,
                    "ORT did not panic, so the out-of-table id MUST have reached the counted degrade — it returned {v:?} with {counted} counted. An Ok here is a silently wrong uncounted vector landing in the corpus."
                );
                assert_eq!(
                    v,
                    vec![0.0; fixture::DIM],
                    "a counted degrade must be the documented zero vector"
                );
            }
        }
    }
}
