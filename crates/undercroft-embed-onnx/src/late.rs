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

use tokenizers::Tokenizer;
use tract_onnx::prelude::*;
use undercroft_core::late::LateInteraction;

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
    /// Encodes degraded to an empty matrix, both sides (ROADMAP O131).
    failures: std::sync::atomic::AtomicU64,
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
            failures: std::sync::atomic::AtomicU64::new(0),
        };
        let probe = me
            .run(&me.query_model, &[CLS, Q_MARKER, SEP], QUERY_LEN, true, &[])
            .map_err(|e| OnnxError::Model(format!("probe forward failed: {e}")))?;
        if probe.1 == 0 {
            return Err(OnnxError::Model(
                "probe produced an empty token matrix".into(),
            ));
        }
        me.dim = probe.1;
        Ok(me)
    }

    /// Tokenize `text` without special tokens, returning raw ids plus a
    /// per-token "punctuation-only" flag (the token string, minus any
    /// wordpiece `##` prefix, contains no alphanumeric character).
    fn word_ids(&self, text: &str) -> Result<(Vec<i64>, Vec<bool>), OnnxError> {
        let enc = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| OnnxError::Inference(e.to_string()))?;
        let ids = enc.get_ids().iter().map(|&v| v as i64).collect();
        let punct = enc
            .get_tokens()
            .iter()
            .map(|t| {
                !t.trim_start_matches("##")
                    .chars()
                    .any(|c| c.is_alphanumeric())
            })
            .collect();
        Ok((ids, punct))
    }

    /// Run one forward over `ids` padded/framed to `len`. `augment` = pad
    /// with attending `[MASK]` tokens (query side) instead of ignored zeros
    /// (doc side). `skip` marks positions that attend normally but are
    /// **excluded from the output matrix** — ColBERT's doc-side punctuation
    /// filter (fewer stored rows, and the noise tokens can't win a MaxSim).
    /// Returns `(row-major matrix of kept rows, dim)`.
    fn run(
        &self,
        model: &RunnableOnnx,
        ids: &[i64],
        len: usize,
        augment: bool,
        skip: &[bool],
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
            if mask[t] == 0 || skip.get(t).copied().unwrap_or(false) {
                continue; // pad rows never participate; skipped rows attend
                          // but aren't stored
            }
            for d in 0..dim {
                matrix.push(hidden[[0, t, d]]);
            }
        }
        Ok((matrix, dim))
    }

    /// Frame `text` as `[CLS] marker tokens… [SEP]`, returning the ids and
    /// the aligned skip flags (special tokens are always kept; word tokens
    /// inherit their punctuation flag when `filter_punct`).
    fn frame(
        &self,
        marker: i64,
        text: &str,
        len: usize,
        filter_punct: bool,
    ) -> Result<(Vec<i64>, Vec<bool>), OnnxError> {
        let (mut ids, mut punct) = self.word_ids(text)?;
        ids.truncate(len - 3);
        punct.truncate(len - 3);
        let mut framed = Vec::with_capacity(ids.len() + 3);
        let mut skip = Vec::with_capacity(ids.len() + 3);
        framed.push(CLS);
        skip.push(false);
        framed.push(marker);
        skip.push(false);
        framed.extend(ids);
        skip.extend(punct.into_iter().map(|p| filter_punct && p));
        framed.push(SEP);
        skip.push(false);
        Ok((framed, skip))
    }
}

impl OnnxColbert {
    /// Count one degraded encode, say so, and hand back the empty matrix the
    /// callers below return (ROADMAP O131). One place, so the doc and query
    /// sides cannot report the same failure differently.
    fn note_failure(&self, side: &str, why: &OnnxError) -> Vec<f32> {
        let n = self
            .failures
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        undercroft_obs::late_failed("onnx", side);
        undercroft_obs::diag_error!(
            "late-interaction {side} encode failed ({why}); returning an empty matrix — \
             a doc failure leaves this drawer with no token matrix at rest, a query \
             failure retires the late stage for this search. Failures so far: {n}"
        );
        Vec::new()
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
        // Punctuation rows attend but aren't stored (ColBERT convention).
        // ROADMAP O131: counted and said, because `late_encode_row` returns
        // early on an empty matrix — so the row is a DURABLE hole in the
        // token space, and nothing at rest distinguishes it from a drawer
        // that was simply never encoded.
        self.frame(D_MARKER, text, DOC_LEN, true)
            .and_then(|(ids, skip)| self.run(&self.doc_model, &ids, DOC_LEN, false, &skip))
            .map(|(m, _)| m)
            .unwrap_or_else(|e| self.note_failure("doc", &e))
    }

    fn encode_query(&self, text: &str) -> Vec<f32> {
        // An empty QUERY matrix makes MaxSim zero for every candidate, so the
        // late stage silently contributes nothing to this one search.
        self.frame(Q_MARKER, text, QUERY_LEN, false)
            .and_then(|(ids, _)| self.run(&self.query_model, &ids, QUERY_LEN, true, &[]))
            .map(|(m, _)| m)
            .unwrap_or_else(|e| self.note_failure("query", &e))
    }

    fn encode_failures(&self) -> u64 {
        self.failures.load(std::sync::atomic::Ordering::SeqCst)
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
    let name = std::env::var("UNDERCROFT_COLBERT_NAME").unwrap_or_else(|_| {
        undercroft_obs::diag_warn!(
            "{}",
            undercroft_core::config::undeclared_model_identity(
                "UNDERCROFT_COLBERT_NAME",
                undercroft_core::config::SHARED_COLBERT_IDENTITY,
                &format!("{doc} (doc) + {query} (query)"),
            )
        );
        undercroft_core::config::SHARED_COLBERT_IDENTITY.into()
    });
    OnnxColbert::load(
        std::path::Path::new(&doc),
        std::path::Path::new(&query),
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
    use crate::fixture;
    use undercroft_core::late::maxsim;

    /// The doc and query exports are the SAME generated file — the fixture
    /// graph carries a symbolic sequence dim, so one file compiles at
    /// `DOC_LEN` and at `QUERY_LEN`, which is the arrangement a real ColBERT
    /// pair of exports has.
    fn load_fixture_colbert(dir: &std::path::Path) -> OnnxColbert {
        let (model, tok) = fixture::write_into(dir).expect("write fixture");
        OnnxColbert::load(&model, &model, &tok, "fixture").expect("fixture loads")
    }

    /// **The doc-encode arm: a degraded doc encode is COUNTED** (ROADMAP
    /// O131, executed for the first time by O134a).
    ///
    /// A doc failure is the worst of the three late-interaction outcomes:
    /// `late_encode_row` returns early on an empty matrix, so the row is a
    /// DURABLE hole in the token space and nothing at rest distinguishes it
    /// from a drawer that was never encoded.
    #[test]
    fn onnx_colbert_counts_a_degraded_doc_encode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = load_fixture_colbert(dir.path());

        // PREMISE.
        assert_eq!(
            c.encode_failures(),
            0,
            "load must not have counted a failure"
        );
        assert_eq!(c.dim(), fixture::DIM);
        let healthy = c.encode_doc(fixture::HEALTHY);
        assert!(
            !healthy.is_empty(),
            "a healthy doc encode must not be the empty-matrix degrade"
        );
        assert_eq!(
            healthy.len() % c.dim(),
            0,
            "a token matrix must be a whole number of rows"
        );
        assert!(
            healthy.iter().all(|x| x.is_finite()),
            "a healthy doc encode must be finite"
        );
        assert_eq!(
            c.encode_failures(),
            0,
            "a healthy doc encode must not move the count"
        );

        // DEGRADE.
        let degraded = c.encode_doc(fixture::REFUSED_WORD);
        assert!(
            degraded.is_empty(),
            "a failed doc encode must degrade to an empty matrix"
        );
        assert_eq!(
            c.encode_failures(),
            1,
            "a failed doc encode must be counted exactly once"
        );

        // RECOVERY.
        assert_eq!(
            c.encode_doc(fixture::HEALTHY),
            healthy,
            "a healthy doc encode after a failure must be unchanged"
        );
        assert_eq!(
            c.encode_failures(),
            1,
            "a healthy doc encode must not move the count"
        );
    }

    /// **The query-encode arm: a degraded query encode is COUNTED**
    /// (ROADMAP O131, executed for the first time by O134a).
    ///
    /// A SEPARATE receiver from the doc test on purpose. Both arms route
    /// through one `note_failure`, so a single test driving both could not
    /// tell "the query arm counted" from "the doc arm counted twice" — and
    /// the side literal they differ by is gated separately, in `parity.rs`.
    #[test]
    fn onnx_colbert_counts_a_degraded_query_encode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = load_fixture_colbert(dir.path());

        // PREMISE. The query side is mask-augmented, so every one of the
        // QUERY_LEN positions attends and the matrix is full width.
        assert_eq!(
            c.encode_failures(),
            0,
            "load must not have counted a failure"
        );
        let healthy = c.encode_query(fixture::HEALTHY);
        assert!(
            !healthy.is_empty(),
            "a healthy query encode must not be the empty-matrix degrade"
        );
        assert_eq!(
            healthy.len(),
            QUERY_LEN * fixture::DIM,
            "mask augmentation must make every query position attend"
        );
        assert!(
            healthy.iter().all(|x| x.is_finite()),
            "a healthy query encode must be finite"
        );
        assert_eq!(
            c.encode_failures(),
            0,
            "a healthy query encode must not move the count"
        );

        // DEGRADE.
        let degraded = c.encode_query(fixture::REFUSED_WORD);
        assert!(
            degraded.is_empty(),
            "a failed query encode must degrade to an empty matrix"
        );
        assert_eq!(
            c.encode_failures(),
            1,
            "a failed query encode must be counted exactly once"
        );

        // RECOVERY.
        assert_eq!(
            c.encode_query(fixture::HEALTHY),
            healthy,
            "a healthy query encode after a failure must be unchanged"
        );
        assert_eq!(
            c.encode_failures(),
            1,
            "a healthy query encode must not move the count"
        );
    }

    /// Full inference test against a REAL user-supplied export. Ignored by
    /// default rather than returning early — it used to print "skipping" and
    /// report PASSED (ROADMAP O134a).
    #[test]
    #[ignore = "requires a user-supplied ColBERT export via UNDERCROFT_COLBERT_MODEL + _QUERY_MODEL + _TOKENIZER"]
    fn late_interaction_ranks_related_passages_higher() {
        std::env::var("UNDERCROFT_COLBERT_MODEL")
            .expect("UNDERCROFT_COLBERT_MODEL must be set to run this test");
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
