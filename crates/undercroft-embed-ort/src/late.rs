//! ColBERT late-interaction encoder on ONNX Runtime.
//!
//! Same user-supplied fixed-shape exports, tokenizer, and `[Q]`/`[D]`/`[MASK]`
//! framing as the tract implementation (`undercroft-embed-onnx/src/late.rs`) —
//! this backend only swaps the forward pass onto ORT's optimized kernels.
//! The query forward sits on the search path (one per query), so it is the
//! latency lever; identical token matrices for the same weights.
//!
//! Env: `UNDERCROFT_COLBERT_MODEL` (doc-length export),
//! `UNDERCROFT_COLBERT_QUERY_MODEL` (query-length export),
//! `UNDERCROFT_COLBERT_TOKENIZER`, optional `UNDERCROFT_COLBERT_NAME` —
//! the same variables the tract backend reads.

use std::sync::Mutex;

use ort::session::Session;
use tokenizers::Tokenizer;
use undercroft_core::late::LateInteraction;

use crate::{build_session, cores, run_batch, OrtError};

/// Fixed exported sequence lengths (the shared exports compile static shapes
/// for tract's benefit; ORT runs them as-is). Docs are drawer chunks
/// (~100–200 tokens); queries follow ColBERT's canonical 32.
const DOC_LEN: usize = 256;
const QUERY_LEN: usize = 32;

const CLS: i64 = 101;
const SEP: i64 = 102;
const MASK: i64 = 103;
const Q_MARKER: i64 = 1; // [unused0]
const D_MARKER: i64 = 2; // [unused1]

/// ColBERT encoder over two ORT sessions (query- and doc-length exports).
pub struct OrtColbert {
    doc_session: Mutex<Session>,
    query_session: Mutex<Session>,
    doc_inputs: usize,
    query_inputs: usize,
    tokenizer: Tokenizer,
    dim: usize,
    name: String,
    /// Encodes degraded to an empty matrix, both sides (ROADMAP O131).
    failures: std::sync::atomic::AtomicU64,
}

impl OrtColbert {
    /// Load the fixed-shape doc + query exports plus `tokenizer.json`. A probe
    /// forward runs at load so an incompatible export fails here, not
    /// mid-search.
    pub fn load(
        doc_model_path: &std::path::Path,
        query_model_path: &std::path::Path,
        tokenizer_path: &std::path::Path,
        model_name: &str,
    ) -> Result<Self, OrtError> {
        let tokenizer =
            Tokenizer::from_file(tokenizer_path).map_err(|e| OrtError::Tokenizer(e.to_string()))?;
        let (doc_session, doc_inputs) = build_session(&doc_model_path.to_string_lossy(), cores())?;
        let (query_session, query_inputs) =
            build_session(&query_model_path.to_string_lossy(), cores())?;
        let mut me = Self {
            doc_session: Mutex::new(doc_session),
            query_session: Mutex::new(query_session),
            doc_inputs,
            query_inputs,
            tokenizer,
            dim: 0,
            name: model_name.to_string(),
            failures: std::sync::atomic::AtomicU64::new(0),
        };
        let probe = me
            .run(
                &me.query_session,
                me.query_inputs,
                &[CLS, Q_MARKER, SEP],
                QUERY_LEN,
                true,
                &[],
            )
            .map_err(|e| OrtError::Model(format!("probe forward failed: {e}")))?;
        if probe.1 == 0 {
            return Err(OrtError::Model(
                "probe produced an empty token matrix".into(),
            ));
        }
        me.dim = probe.1;
        Ok(me)
    }

    /// Tokenize `text` without special tokens, returning raw ids plus a
    /// per-token "punctuation-only" flag (the token string, minus any
    /// wordpiece `##` prefix, contains no alphanumeric character).
    fn word_ids(&self, text: &str) -> Result<(Vec<i64>, Vec<bool>), OrtError> {
        let enc = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| OrtError::Inference(e.to_string()))?;
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
    /// filter. Returns `(row-major matrix of kept rows, dim)`.
    fn run(
        &self,
        session: &Mutex<Session>,
        n_inputs: usize,
        ids: &[i64],
        len: usize,
        augment: bool,
        skip: &[bool],
    ) -> Result<(Vec<f32>, usize), OrtError> {
        let mut input: Vec<i64> = ids.to_vec();
        input.truncate(len);
        let mut mask: Vec<i64> = vec![1; input.len()];
        while input.len() < len {
            input.push(if augment { MASK } else { 0 });
            mask.push(if augment { 1 } else { 0 });
        }
        let (dims, data) = {
            let mut guard = session.lock().expect("ort session mutex");
            run_batch(
                &mut guard,
                n_inputs,
                1,
                len,
                input,
                mask.clone(),
                vec![0; len],
            )?
        };
        // dims: (1, seq, dim) — the export bakes in projection + L2 norm.
        if dims.len() < 3 {
            return Err(OrtError::Inference("unexpected colbert output rank".into()));
        }
        let (seq, dim) = (dims[1], dims[2]);
        let mut matrix = Vec::with_capacity(seq * dim);
        for t in 0..seq.min(len) {
            if mask[t] == 0 || skip.get(t).copied().unwrap_or(false) {
                continue; // pad rows never participate; skipped rows attend
                          // but aren't stored
            }
            matrix.extend_from_slice(&data[t * dim..(t + 1) * dim]);
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
    ) -> Result<(Vec<i64>, Vec<bool>), OrtError> {
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

impl OrtColbert {
    /// Count one degraded encode, say so, and hand back the empty matrix the
    /// callers below return (ROADMAP O131). One place, so the doc and query
    /// sides cannot report the same failure differently.
    fn note_failure(&self, side: &str, why: &OrtError) -> Vec<f32> {
        let n = self
            .failures
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        undercroft_obs::late_failed("ort", side);
        undercroft_obs::diag_error!(
            "late-interaction {side} encode failed ({why}); returning an empty matrix — a doc failure leaves this drawer with no token matrix at rest, a query failure retires the late stage for this search. Failures so far: {n}"
        );
        Vec::new()
    }
}

impl LateInteraction for OrtColbert {
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
        self.frame(D_MARKER, text, DOC_LEN, true)
            .and_then(|(ids, skip)| {
                self.run(
                    &self.doc_session,
                    self.doc_inputs,
                    &ids,
                    DOC_LEN,
                    false,
                    &skip,
                )
            })
            .map(|(m, _)| m)
            .unwrap_or_else(|e| self.note_failure("doc", &e))
    }

    fn encode_query(&self, text: &str) -> Vec<f32> {
        self.frame(Q_MARKER, text, QUERY_LEN, false)
            .and_then(|(ids, _)| {
                self.run(
                    &self.query_session,
                    self.query_inputs,
                    &ids,
                    QUERY_LEN,
                    true,
                    &[],
                )
            })
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
pub fn colbert_from_env() -> Result<OrtColbert, OrtError> {
    let doc = std::env::var("UNDERCROFT_COLBERT_MODEL")
        .map_err(|_| OrtError::Model("UNDERCROFT_COLBERT_MODEL is not set".into()))?;
    let query = std::env::var("UNDERCROFT_COLBERT_QUERY_MODEL")
        .map_err(|_| OrtError::Model("UNDERCROFT_COLBERT_QUERY_MODEL is not set".into()))?;
    let tokenizer = std::env::var("UNDERCROFT_COLBERT_TOKENIZER")
        .map_err(|_| OrtError::Tokenizer("UNDERCROFT_COLBERT_TOKENIZER is not set".into()))?;
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
    OrtColbert::load(
        std::path::Path::new(&doc),
        std::path::Path::new(&query),
        std::path::Path::new(&tokenizer),
        &name,
    )
}

#[cfg(test)]
// See the sibling module in lib.rs: `dead_code` is the cheap catch for a
// `#[test]` attribute eaten by a scripted edit (ROADMAP O134a).
#[deny(dead_code, unused)]
mod tests {
    use super::*;
    use undercroft_core::late::maxsim;
    use undercroft_embed_onnx::fixture;

    fn load_fixture_colbert(dir: &std::path::Path) -> OrtColbert {
        let (model, tok) = fixture::write_into(dir).expect("write fixture");
        OrtColbert::load(&model, &model, &tok, "fixture").expect("fixture loads")
    }

    /// **The doc-encode arm: a degraded doc encode is COUNTED** (ROADMAP
    /// O131, executed for the first time by O134a).
    #[test]
    fn ort_colbert_counts_a_degraded_doc_encode() {
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
        assert_eq!(
            c.encode_failures(),
            0,
            "a healthy doc encode must not move the count"
        );

        // DEGRADE.
        assert!(
            c.encode_doc(fixture::REFUSED_WORD).is_empty(),
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
    /// A separate receiver from the doc test: both arms route through one
    /// `note_failure`, so one test driving both could not tell which side
    /// counted. The side LITERAL they differ by is gated in `parity.rs`.
    #[test]
    fn ort_colbert_counts_a_degraded_query_encode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = load_fixture_colbert(dir.path());

        // PREMISE.
        assert_eq!(
            c.encode_failures(),
            0,
            "load must not have counted a failure"
        );
        let healthy = c.encode_query(fixture::HEALTHY);
        assert_eq!(
            healthy.len(),
            QUERY_LEN * fixture::DIM,
            "mask augmentation must make every query position attend"
        );
        assert_eq!(
            c.encode_failures(),
            0,
            "a healthy query encode must not move the count"
        );

        // DEGRADE.
        assert!(
            c.encode_query(fixture::REFUSED_WORD).is_empty(),
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
