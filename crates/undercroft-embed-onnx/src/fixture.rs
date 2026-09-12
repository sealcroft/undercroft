//! A model fixture **generated in-test** — no committed bytes.
//!
//! ROADMAP O134a. O122 and O131 made every model role count the failures it
//! used to swallow, and the gates covered the trait-to-surface plumbing
//! through test doubles. The nine arms that actually degrade live in this
//! crate and in `undercroft-embed-ort`, need model weights the battery does
//! not carry, and were executed by NOTHING. A hostile reading is that the
//! counting code itself is unexercised; the honest answer was that it is.
//!
//! **Why a real runtime and not a seam.** [`crate::OnnxEmbedder`] holds a
//! compiled tract `SimplePlan` and `OrtEmbedder` an ORT `Session`, so the
//! real receiver cannot exist without a real `load()`. A `#[cfg(test)]` seam
//! would need a test-only constructor and would then be testing a type state
//! production never creates — which is not "the counting code executed" in
//! any sense the entry's own gate would accept.
//!
//! **Why generated and not committed.** The premise of every counterfactual
//! here — which word is refused, which id is out of range, that a healthy
//! output differs from the degrade value — has to be readable in a diff. A
//! blob would need a regenerate-and-compare gate of its own to avoid the
//! `docs/diagrams` drift class, and it would touch the binary-artifact
//! governance (a `NOTICE` row, the `vendor/SHA256SUMS` inventory whose
//! premise is `tiny_http`-specific, a `.gitattributes` attribute, and the
//! no-trace scanner's `SKIP_BIN`, which has no `onnx`). None of that is owed
//! by ~2 KB this file can emit.
//!
//! # The graph
//!
//! Two inputs, `input_ids` then `attention_mask` — that order and those
//! names are both load-bearing, because tract binds inputs by POSITION and
//! ORT binds them by NAME. Both `int64 [batch, seq]` with symbolic dims, so
//! ONE file compiles at `seq = 256` (embedder, reranker, ColBERT doc) and at
//! `seq = 32` (ColBERT query).
//!
//! ```text
//!   input_ids ──► Gather(emb[128,4], axis=0) ──► [b,s,4] ─┐
//!                                                         ├─► Add ─► hidden
//!   attention_mask ──► Gather(msk[2,4], axis=0) ► [b,s,4] ─┘
//! ```
//!
//! **Gathering the mask rather than casting it** is what removes every op
//! this fixture would otherwise have had to bet on. An attention mask is 0
//! or 1, so a two-row table indexes directly — no `Cast`, and no `Unsqueeze`,
//! whose ONNX signature MOVED at opset 13 (axes became an input) and which
//! would have put a version bet in the one file both runtimes must agree on.
//! Both branches come out `[b, s, DIM]`, so the `Add` needs no broadcasting.
//!
//! The mask is genuinely CONSUMED, which is the property that matters: an
//! optimizer that pruned it would change `n_inputs` and the loaders' own
//! shape handling with it.
//!
//! **`Add`, not `Mul`.** Under `Mul` every padding row is exactly zero, so a
//! reranker's healthy score is `sigmoid(0.0) = 0.5` on both backends — and
//! `0.5` is exactly the value the separately-filed ORT empty-logit defect
//! produces, so a healthy run and that defect would be indistinguishable.
//! Under `Add` row 0 carries [`PAD_LAST`] and the healthy score is
//! `sigmoid(2.0)`, distinguishable from the `0.0` degrade AND from `0.5`.
//!
//! **Both rerankers read a PADDING position, and that is why [`PAD_LAST`]
//! decides the healthy score.** tract takes `flat.last()`, i.e. `[0, s-1, 3]`;
//! ORT takes `data.get(dims[1].max(1) - 1)`, i.e. flat index `s - 1`, which
//! for `s = 256` is `[0, 63, 3]`. They agree only while BOTH positions are
//! padding — so **every reranker pair this fixture scores must encode to
//! fewer than 64 tokens**. That constraint is pinned by
//! `a_reranker_pair_stays_under_the_position_both_backends_read`.
//!
//! # The two triggers, which fail in two different LAYERS
//!
//! * [`REFUSED_WORD`] is absent from the vocabulary while `unk_token` names
//!   a token the vocabulary does not contain, so `WordLevel::tokenize`
//!   returns `Err(MissingUnkToken)`. That is the MODEL layer of the
//!   tokenizer, which `encode(text, true)`, `encode((q, p), true)` and
//!   `encode(text, false)` all pass through — one trigger, every call shape.
//! * [`OUT_OF_TABLE_WORD`] IS in the vocabulary and maps to
//!   [`OUT_OF_TABLE_ID`], which is `>= EMB_ROWS`, so tokenization succeeds
//!   and the `Gather` fails at RUNTIME. That is the route-R trigger, and the
//!   two backends are not known to answer it the same way.

use prost::Message;
use tract_onnx::pb::{
    attribute_proto, tensor_proto, tensor_shape_proto, type_proto, AttributeProto, GraphProto,
    ModelProto, NodeProto, OperatorSetIdProto, TensorProto, TensorShapeProto, TypeProto,
    ValueInfoProto,
};

/// The hidden size the fixture emits. Small on purpose: every assertion in
/// every arm test is written by hand against it.
pub const DIM: usize = 4;

/// Rows in the embedding table. Must exceed the largest id any caller sends
/// without going through the vocabulary — the ColBERT loaders hard-code
/// `[CLS] = 101`, `[SEP] = 102` and `[MASK] = 103` and never consult the
/// tokenizer at all, so anything under 104 makes the probe forward fail at
/// `load` and no arm is ever reached.
pub const EMB_ROWS: usize = 128;

/// Last component of the padding row, and therefore the raw logit both
/// rerankers read for a short pair. Chosen non-zero so `sigmoid` of it is
/// neither the `0.0` degrade nor the `0.5` of the filed empty-logit defect.
pub const PAD_LAST: f32 = 2.0;

/// The id [`OUT_OF_TABLE_WORD`] maps to: in range for `i64`, out of range
/// for a `Gather` over [`EMB_ROWS`] rows.
pub const OUT_OF_TABLE_ID: u32 = 4096;

/// A word the vocabulary does not contain. Refused in the tokenizer's MODEL
/// layer because `unk_token` is named and absent — see the module docs.
pub const REFUSED_WORD: &str = "qwxzvv";

/// A word the vocabulary DOES contain, mapped past the embedding table so
/// the failure happens in the runtime rather than in the tokenizer.
pub const OUT_OF_TABLE_WORD: &str = "beyondtable";

/// Text every arm's PREMISE phase uses: all words present, all ids in range.
pub const HEALTHY: &str = "alpha beta gamma";

/// A second healthy text, distinct from [`HEALTHY`] in every token, so a
/// test can assert two healthy calls differ rather than only that one is
/// non-zero.
pub const HEALTHY_OTHER: &str = "delta epsilon zeta";

/// The token that names `unk_token` without appearing in the vocabulary.
const UNK: &str = "[UNK]";

/// The vocabulary, written out rather than generated, because which word is
/// refused and which is merely out of range is the premise of every
/// counterfactual in this unit and has to be readable in a diff.
///
/// Ids sit in `10..=99`: clear of `0` (padding), `1`/`2` (the ColBERT `[Q]`
/// and `[D]` markers) and `101`/`102`/`103` (`[CLS]`/`[SEP]`/`[MASK]`), so a
/// vocabulary word never shares an embedding row with a framing token.
///
/// The first four entries are NOT optional: they are the words the shipped
/// loaders' own fail-fast probes tokenize (`"dimension probe"` for both
/// embedders, `("query", "passage")` for both rerankers). Without them
/// `load` fails and no test in this unit reaches an arm.
pub fn vocab() -> Vec<(&'static str, u32)> {
    vec![
        ("dimension", 10),
        ("probe", 11),
        ("query", 12),
        ("passage", 13),
        ("alpha", 20),
        ("beta", 21),
        ("gamma", 22),
        ("delta", 23),
        ("epsilon", 24),
        ("zeta", 25),
        ("the", 30),
        ("build", 31),
        ("failed", 32),
        (OUT_OF_TABLE_WORD, OUT_OF_TABLE_ID),
    ]
}

/// One row of the embedding table.
///
/// Row 0 is RESERVED as the padding row and is the only one written by hand;
/// its last component is [`PAD_LAST`]. Every other row is derived from the
/// index through four coprime moduli, which keeps the rows mixed-sign and
/// spread — L2-normalized embeddings then stay angularly separated, so two
/// different texts produce two different vectors rather than one direction.
///
/// All 128 rows are DISTINCT: the tuple `(i % 7, i % 11, i % 13, i % 5)`
/// repeats only after `lcm = 5005`, and the offsets keep row 0 out of the
/// derived family (its last component `2.0` is not in `{-1.25, -0.25, 0.75,
/// 1.75, 2.75}`). No component is ever zero and no row is ever the zero
/// vector, so a zero result can only have come from a degrade.
///
/// No NaN row. One was specified when this fixture was expected to carry the
/// non-finite-output entry too; that entry is filed separately (ROADMAP
/// O151) and its cheapest arm is `HttpEmbedder`, in a default member. An
/// unused NaN row here would only invite a test that silently depends on it.
pub fn emb_row(i: usize) -> [f32; DIM] {
    if i == 0 {
        return [0.5, -0.25, 0.125, PAD_LAST];
    }
    let a = (i % 7) as f32 - 3.0;
    let b = (i % 11) as f32 - 5.0;
    let c = (i % 13) as f32 - 6.0;
    let d = (i % 5) as f32 - 2.0;
    [a + 0.5, b - 0.25, c + 0.125, d + 0.75]
}

/// The mask table: row 0 for an ignored position, row 1 for an attended one.
/// A small non-zero attended value keeps the two distinguishable in the
/// output without swamping the embedding rows.
fn msk_row(i: usize) -> [f32; DIM] {
    if i == 0 {
        [0.0; DIM]
    } else {
        [0.25; DIM]
    }
}

fn f32_initializer(name: &str, dims: Vec<i64>, data: Vec<f32>) -> TensorProto {
    TensorProto {
        dims,
        data_type: tensor_proto::DataType::Float as i32,
        float_data: data,
        name: name.to_string(),
        ..Default::default()
    }
}

/// An `int64 [batch, seq]` graph input. Both dims are SYMBOLIC and share
/// their parameter names across the two inputs, which is what lets one file
/// compile at 256 and at 32 and what tells ORT the two inputs must agree.
fn int64_input(name: &str) -> ValueInfoProto {
    let dim = |p: &str| tensor_shape_proto::Dimension {
        value: Some(tensor_shape_proto::dimension::Value::DimParam(
            p.to_string(),
        )),
        ..Default::default()
    };
    ValueInfoProto {
        name: name.to_string(),
        r#type: Some(TypeProto {
            value: Some(type_proto::Value::TensorType(type_proto::Tensor {
                elem_type: tensor_proto::DataType::Int64 as i32,
                shape: Some(TensorShapeProto {
                    dim: vec![dim("batch"), dim("seq")],
                }),
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn gather(data: &str, indices: &str, out: &str) -> NodeProto {
    NodeProto {
        input: vec![data.to_string(), indices.to_string()],
        output: vec![out.to_string()],
        name: format!("gather_{out}"),
        op_type: "Gather".to_string(),
        attribute: vec![AttributeProto {
            name: "axis".to_string(),
            r#type: attribute_proto::AttributeType::Int as i32,
            i: 0,
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// The fixture model, as ONNX protobuf bytes.
///
/// `ir_version = 7` and a single `opset_import` at version 13. Both
/// initializers go in `graph.initializer` ONLY and never also in
/// `graph.input`: listing them twice is legal in old IR versions and is
/// exactly the shape that makes `n_inputs` disagree between runtimes.
pub fn onnx_model_bytes() -> Vec<u8> {
    let mut emb = Vec::with_capacity(EMB_ROWS * DIM);
    for i in 0..EMB_ROWS {
        emb.extend_from_slice(&emb_row(i));
    }
    let mut msk = Vec::with_capacity(2 * DIM);
    for i in 0..2 {
        msk.extend_from_slice(&msk_row(i));
    }

    let out_dim = |v: tensor_shape_proto::dimension::Value| tensor_shape_proto::Dimension {
        value: Some(v),
        ..Default::default()
    };
    let output = ValueInfoProto {
        name: "hidden".to_string(),
        r#type: Some(TypeProto {
            value: Some(type_proto::Value::TensorType(type_proto::Tensor {
                elem_type: tensor_proto::DataType::Float as i32,
                shape: Some(TensorShapeProto {
                    dim: vec![
                        out_dim(tensor_shape_proto::dimension::Value::DimParam(
                            "batch".into(),
                        )),
                        out_dim(tensor_shape_proto::dimension::Value::DimParam("seq".into())),
                        out_dim(tensor_shape_proto::dimension::Value::DimValue(DIM as i64)),
                    ],
                }),
            })),
            ..Default::default()
        }),
        ..Default::default()
    };

    let graph = GraphProto {
        node: vec![
            gather("emb", "input_ids", "tok"),
            gather("msk", "attention_mask", "att"),
            NodeProto {
                input: vec!["tok".to_string(), "att".to_string()],
                output: vec!["hidden".to_string()],
                name: "add_hidden".to_string(),
                op_type: "Add".to_string(),
                ..Default::default()
            },
        ],
        name: "undercroft_fixture".to_string(),
        initializer: vec![
            f32_initializer("emb", vec![EMB_ROWS as i64, DIM as i64], emb),
            f32_initializer("msk", vec![2, DIM as i64], msk),
        ],
        input: vec![int64_input("input_ids"), int64_input("attention_mask")],
        output: vec![output],
        ..Default::default()
    };

    ModelProto {
        ir_version: 7,
        opset_import: vec![OperatorSetIdProto {
            domain: String::new(),
            version: 13,
        }],
        producer_name: "undercroft-fixture".to_string(),
        graph: Some(graph),
        ..Default::default()
    }
    .encode_to_vec()
}

/// The fixture `tokenizer.json`: a `WordLevel` model over [`vocab`] behind a
/// `Whitespace` pre-tokenizer, with no normalizer, no post-processor and no
/// padding.
///
/// `unk_token` NAMES `[UNK]` and the vocabulary does NOT contain it. That is
/// deliberate and it is the whole unit trigger: `WordLevel::tokenize` falls
/// through to `Err(MissingUnkToken)` for any word it does not know.
///
/// A pre-tokenizer is not optional — without one the whole text arrives as a
/// single token and EVERY input is out of vocabulary, so the fixture would
/// refuse its own healthy path.
///
/// No `truncation` key. The length trigger and its two strategies belong to
/// the corpus arm, which is O134b; carrying an unused truncation config here
/// would be a configuration no test reads.
pub fn tokenizer_json() -> String {
    let entries: Vec<String> = vocab()
        .into_iter()
        .map(|(w, id)| format!("\"{w}\":{id}"))
        .collect();
    let vocab_json = entries.join(",");
    format!(
        "{{\"version\":\"1.0\",\"truncation\":null,\"padding\":null,\"added_tokens\":[],\"normalizer\":null,\"pre_tokenizer\":{{\"type\":\"Whitespace\"}},\"post_processor\":null,\"decoder\":null,\"model\":{{\"type\":\"WordLevel\",\"vocab\":{{{vocab_json}}},\"unk_token\":\"{UNK}\"}}}}"
    )
}

/// Write the fixture into `dir` and hand back `(model path, tokenizer path)`.
///
/// `std::fs` only. The temporary directory itself is each crate's own
/// business — a `tempfile` dependency here would have to be a NORMAL one, so
/// that the `test-fixture` feature carried it for the other crate, and this
/// module is not worth an edge in a shipped dependency graph.
pub fn write_into(
    dir: &std::path::Path,
) -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let model = dir.join("fixture.onnx");
    let tokenizer = dir.join("tokenizer.json");
    std::fs::write(&model, onnx_model_bytes())?;
    std::fs::write(&tokenizer, tokenizer_json())?;
    Ok((model, tokenizer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenizers::Tokenizer;

    /// **The fixture self-test, and it runs before any backend is built.**
    ///
    /// A fixture that cannot refuse the trigger, or that refuses the healthy
    /// path, produces arm tests that fail for a reason unrelated to the arms
    /// — and on a clean tree those read exactly like coverage. Every claim
    /// the arm tests rest on is asserted here first.
    #[test]
    fn the_fixture_tokenizer_refuses_only_what_it_is_meant_to() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_, tok_path) = write_into(dir.path()).expect("write fixture");
        let tok = Tokenizer::from_file(&tok_path).expect("fixture tokenizer loads");

        // The shipped loaders' OWN probes. If these ever stop tokenizing,
        // `load` fails and every arm test in this unit dies upstream of the
        // thing it tests.
        for probe in ["dimension probe", HEALTHY, HEALTHY_OTHER] {
            assert!(
                tok.encode(probe, true).is_ok(),
                "healthy text must tokenize: {probe}"
            );
            assert!(
                tok.encode(probe, false).is_ok(),
                "healthy text must tokenize unframed: {probe}"
            );
        }
        assert!(
            tok.encode(("query", "passage"), true).is_ok(),
            "the reranker load probe must tokenize"
        );

        // The unit trigger, in ALL THREE call shapes the six backends use.
        assert!(
            tok.encode(REFUSED_WORD, true).is_err(),
            "single-sequence encode must refuse the trigger"
        );
        assert!(
            tok.encode(REFUSED_WORD, false).is_err(),
            "unframed encode must refuse the trigger"
        );
        assert!(
            tok.encode((HEALTHY, REFUSED_WORD), true).is_err(),
            "pair encode must refuse the trigger"
        );

        // The route-R trigger is the OTHER layer: it tokenizes fine and is
        // out of range for the table.
        let enc = tok
            .encode(OUT_OF_TABLE_WORD, false)
            .expect("the route-R word must tokenize");
        assert_eq!(
            enc.get_ids(),
            [OUT_OF_TABLE_ID],
            "the route-R word must map to the out-of-table id"
        );
        assert!(
            OUT_OF_TABLE_ID as usize >= EMB_ROWS,
            "the route-R id must be out of range for a {EMB_ROWS}-row table"
        );
    }

    /// Every embedding row is finite, non-zero and distinct, so a zero or a
    /// NaN observed in an arm test can only have come from a degrade.
    #[test]
    fn every_embedding_row_is_finite_non_zero_and_distinct() {
        let mut seen: Vec<[u32; DIM]> = Vec::with_capacity(EMB_ROWS);
        for i in 0..EMB_ROWS {
            let row = emb_row(i);
            assert!(row.iter().all(|v| v.is_finite()), "row {i} must be finite");
            assert!(
                row.iter().all(|v| *v != 0.0),
                "row {i} must have no zero component"
            );
            seen.push(row.map(|v| v.to_bits()));
        }
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            EMB_ROWS,
            "every embedding row must be distinct"
        );
        assert_eq!(
            emb_row(0)[DIM - 1],
            PAD_LAST,
            "row 0 is the padding row both rerankers read"
        );
    }

    /// **The generator's premise: the bytes this module emits are a model a
    /// real runtime loads and runs.**
    ///
    /// Everything downstream of here — nine arm tests across two crates —
    /// assumes it. If the graph stops compiling in tract, or the probe
    /// forward inside `load` stops producing a rank-3 output, every one of
    /// those tests fails for a reason that has nothing to do with the arm it
    /// names, and on a clean tree that reads like a regression in the
    /// counting code. This test is what tells the two apart.
    #[test]
    fn the_fixture_loads_in_tract_and_runs_a_healthy_forward() {
        use undercroft_core::embed::Embedder;
        let dir = tempfile::tempdir().expect("tempdir");
        let (model, tok) = write_into(dir.path()).expect("write fixture");
        let e = crate::OnnxEmbedder::load(&model, &tok, "fixture")
            .expect("the fixture must load in tract");
        assert_eq!(
            e.dimension(),
            DIM,
            "the probe forward must report the fixture's hidden size"
        );

        let v = e.embed(HEALTHY);
        assert_eq!(v.len(), DIM);
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

        let other = e.embed(HEALTHY_OTHER);
        assert_ne!(
            v, other,
            "two different texts must produce two different vectors"
        );
    }

    /// **The constraint the whole reranker premise rests on.**
    ///
    /// tract reads `[0, s-1, 3]` and ORT reads flat index `s-1`, i.e.
    /// `[0, 63, 3]` at `s = 256`. The two agree only while BOTH positions are
    /// padding, so a fixture pair that encoded to 64 tokens or more would
    /// make the backends disagree about a healthy score for a reason no arm
    /// test mentions.
    #[test]
    fn a_reranker_pair_stays_under_the_position_both_backends_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_, tok_path) = write_into(dir.path()).expect("write fixture");
        let tok = Tokenizer::from_file(&tok_path).expect("fixture tokenizer loads");
        let enc = tok
            .encode((HEALTHY, HEALTHY_OTHER), true)
            .expect("pair encodes");
        assert!(
            enc.get_ids().len() < 64,
            "a fixture reranker pair must stay under 64 tokens, got {}",
            enc.get_ids().len()
        );
    }
}
