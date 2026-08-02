//! Retrieval benchmarks, ported from mempalace's `benchmarks/` harnesses.
//!
//! Two modes:
//!
//! * `longmemeval <dataset.json>` — the real LongMemEval(-S) protocol, same
//!   as upstream's `longmemeval_bench.py`: for each question, ingest its
//!   haystack sessions into a fresh palace, query with the question, and
//!   score session-level Recall@k / NDCG@k against the ground-truth answer
//!   sessions. Dataset is user-supplied (see benchmarks/README.md).
//! * `synth` — a deterministic, self-contained benchmark that needs no
//!   external dataset, so CI can watch for retrieval regressions: generate
//!   a corpus of distinct fact documents, query each fact with a paraphrase
//!   template, and report Recall@1/@5 + latency.
//!
//! Honesty note (mirrors upstream's BENCHMARKS.md): scores depend on the
//! embedder. Upstream's published numbers used a sentence-transformer
//! model; run with `UNDERCROFT_EMBEDDER=onnx` and a MiniLM-class model for
//! comparable conditions. The default hash embedder is weaker on semantic
//! paraphrase but has zero setup.

mod vs;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::time::Instant;

use undercroft_core::Drawer;
use undercroft_store::{PalaceStore, SearchHit, SearchOptions};
use undercroft_vault::{SecurityLevel, VaultManager};

#[derive(Parser)]
#[command(name = "undercroft-bench", about = "Retrieval benchmarks for Undercroft")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// LongMemEval protocol against a user-supplied dataset JSON
    Longmemeval {
        /// Path to longmemeval_s(.cleaned).json
        dataset: std::path::PathBuf,
        /// Evaluate only the first N questions (after --skip)
        #[arg(long)]
        limit: Option<usize>,
        /// Skip the first N questions (for sharded parallel runs)
        #[arg(long, default_value_t = 0)]
        skip: usize,
        /// Report recall/ndcg at this k
        #[arg(short = 'k', long, default_value_t = 5)]
        k: usize,
        /// Vault security level to benchmark under
        #[arg(long, default_value = "sealed")]
        level: String,
    },
    /// MUVERA FDE mechanics at scale: candidate recall vs exact MaxSim +
    /// scan throughput over synthetic clustered token matrices — corpus
    /// sizes no transformer could encode within a bench run
    FdeSynth {
        /// Number of synthetic documents (token matrices)
        #[arg(long, default_value_t = 50_000)]
        n: usize,
        /// Ground-truth queries (each costs one exact MaxSim pass over all
        /// N docs — the expensive part; sampled evenly across topics)
        #[arg(long, default_value_t = 50)]
        queries: usize,
        /// Tokens per synthetic document
        #[arg(long, default_value_t = 32)]
        doc_tokens: usize,
        /// Tokens per query (ColBERT mask-augments to 32)
        #[arg(long, default_value_t = 32)]
        query_tokens: usize,
        /// Token embedding dim (ColBERT convention)
        #[arg(long, default_value_t = 128)]
        dim: usize,
    },
    /// Sealed-tier page-level decryption spike (research): today's per-row
    /// seals + decrypt-once full RAM cache vs one AEAD page per IVF list
    /// (AAD `pqpage/{list}`) decrypted lazily per probe. Codes are synthetic
    /// random bytes — both variants scan byte-identical codes, so recall is
    /// invariant by construction; the questions are cost-shaped: at-rest
    /// size, open cost, per-probe decrypt cost, resident RAM.
    PqpageSynth {
        /// Corpus size (drawers); the trigger zone is 10⁶–10⁷
        #[arg(long, default_value_t = 1_000_000)]
        n: usize,
        /// Embedding dim (fixes the PQ code length at dim/8 bytes)
        #[arg(long, default_value_t = 384)]
        dim: usize,
        /// Queries per probe-fraction cell
        #[arg(long, default_value_t = 30)]
        queries: usize,
        /// IVF list count (0 = the store's default: √N clamped to 16..=1024)
        #[arg(long, default_value_t = 0)]
        nlist: usize,
        /// Candidate pool per query (the store requests ≥256)
        #[arg(long, default_value_t = 256)]
        k: usize,
    },
    /// Wing-as-retrieval-unit scaling: scoped vs unscoped recall and
    /// latency on a multi-wing corpus, under the per-wing PQ tier. The
    /// number that matters is scoped R@5 as the corpus grows: corpus-wide
    /// candidates intersected with a wing starve it, a wing's own index
    /// does not. Run at two corpus sizes ≥4x apart and on both sides of
    /// the floor (--wing-pq-min) before believing any figure.
    Wingscale {
        /// Total drawers across all wings
        #[arg(long, default_value_t = 16_384)]
        n: usize,
        /// Number of wings (round-robin ingest; every wing is n/wings)
        #[arg(long, default_value_t = 16)]
        wings: usize,
        /// Queries per pass (evenly sampled over the subject wing's facts)
        #[arg(long, default_value_t = 200)]
        queries: usize,
        /// Comma-separated per-wing floors to measure against ONE ingested
        /// corpus: numbers, `default` (the store's own floor), or `off`
        /// (tier disabled — scoped queries intersect corpus-wide
        /// candidates, the pre-tier behavior).
        #[arg(long, default_value = "default,off")]
        floors: String,
        #[arg(long, default_value = "sealed")]
        level: String,
    },
    /// Unscoped PQ latency versus corpus size, one cumulative vault,
    /// pushed until it degrades. The single number that settles the R1
    /// query claim: flat to 10^6 means the per-wing tier is a build-cost
    /// optimisation; a break between 10^5 and 10^6 is where scoped wins.
    Pqscale {
        /// Cumulative corpus checkpoints, comma-separated ascending
        #[arg(long, default_value = "131072,262144,524288,1048576")]
        sizes: String,
        /// Timed queries per checkpoint (evenly sampled over the corpus so far)
        #[arg(long, default_value_t = 200)]
        queries: usize,
        /// Candidate-pool sweep per checkpoint, comma-separated (the
        /// recall-leak fix instrument: recall-vs-pool with hydration cost
        /// beside it). Pools are rounded up to the engine's limit*32 grid.
        #[arg(long, default_value = "256,512,1024,2048")]
        pools: String,
        /// Ingest batch size (`upsert_many` — one transaction + one
        /// manifest anchor per batch, the engine's bulk path). 1 = the
        /// interactive single-write path, which pays its durability fsyncs
        /// per drawer and measures a different product surface.
        #[arg(long, default_value_t = 4096)]
        batch: usize,
        /// Corpus-scaled pool divisor for the run: unset = the engine's
        /// shipped default (the pools below then act as floors under the
        /// live policy — this measures the SHIPPED config); `off` =
        /// scaling disabled, so the pools sweep raw candidate counts (the
        /// instrument mode that produced the recall-vs-pool curve).
        #[arg(long)]
        pool_div: Option<String>,
        #[arg(long, default_value = "sealed")]
        level: String,
    },
    /// Scoped-recall-at-scale: does a FIXED wing (and a fixed room inside
    /// it) keep 100% recall while the corpus grows around it? One
    /// cumulative vault; a probe wing ingested first and never grown; four
    /// query passes per checkpoint (unscoped control, wing-scoped,
    /// room-scoped, wing+room). This is the instrument the per-wing tier's
    /// recall claim was waiting for — and the scope filter's first
    /// at-scale measurement. No gate mid-run: the curves are the result.
    Scopescale {
        /// Cumulative TOTAL corpus checkpoints (probe included), ascending
        #[arg(long, default_value = "131072,262144,524288,1048576")]
        sizes: String,
        /// Fixed probe-wing size (default above UNDERCROFT_WING_PQ_MIN so
        /// the wing earns its own index)
        #[arg(long, default_value_t = 8192)]
        wing_size: usize,
        /// Fixed probe-room size inside the probe wing (default above the
        /// 256-candidate hydration floor at limit 5, so the scoped
        /// membership-filter path is on trial, not the exact-scan escape)
        #[arg(long, default_value_t = 512)]
        room_size: usize,
        /// Timed queries per pass per checkpoint
        #[arg(long, default_value_t = 100)]
        queries: usize,
        /// Ingest batch size (`upsert_many`)
        #[arg(long, default_value_t = 4096)]
        batch: usize,
        #[arg(long, default_value = "sealed")]
        level: String,
    },
    /// Cross-lingual retrieval instrument: ingest the TARGET sentence of
    /// every pair, query with the SOURCE sentence, report R@1/R@5 per
    /// language pair — plus a verbatim-recovery sanity column (querying
    /// with the target itself must find it, or the harness is broken).
    /// The embedder is taken from the environment and printed as
    /// configuration: the default hash embedder is the measured-zero
    /// baseline (it matches surface forms only), a served multilingual
    /// model (`UNDERCROFT_EMBEDDER=http`) is the capability under test.
    /// Pairs are operator-supplied (TSV: src_lang, tgt_lang, src_text,
    /// tgt_text) — parallel corpora carry their own licenses and are not
    /// shipped in this repo.
    Xlingual {
        /// TSV file: src_lang \t tgt_lang \t src_text \t tgt_text
        #[arg(long)]
        pairs: String,
        /// Cap pairs read per language pair (0 = all)
        #[arg(long, default_value_t = 0)]
        limit: usize,
        #[arg(long, default_value = "sealed")]
        level: String,
    },
    /// Deterministic self-contained benchmark (no dataset needed)
    Synth {
        /// Number of fact documents
        #[arg(long, default_value_t = 200)]
        n: usize,
        #[arg(long, default_value = "sealed")]
        level: String,
        /// Cap the query phase to this many queries (default: one per fact).
        /// Recall is reported over the queries actually run — an even sample
        /// across the corpus, so large-N sweeps finish in minutes.
        #[arg(long)]
        queries: Option<usize>,
    },
    /// LoCoMo protocol (10 conversations, ~200 QA): session-level retrieval
    /// recall against evidence dialog ids
    Locomo {
        /// Path to locomo10.json
        dataset: std::path::PathBuf,
        #[arg(short = 'k', long, default_value_t = 10)]
        k: usize,
        /// Evaluate at most N conversations (the top-level shard unit), after
        /// --skip. Omit for all. Recall is additive, so sharding by
        /// conversation and summing the RAW lines reproduces the full number.
        #[arg(long)]
        limit: Option<usize>,
        /// Skip the first N conversations (pairs with --limit for sharding).
        #[arg(long, default_value_t = 0)]
        skip: usize,
        /// Retrieval backend: `local` (SQLite full-scan + fusion + optional
        /// reranker) or a remote vector index used as an ANN accelerator
        /// (`qdrant` / `weaviate` / `chroma` / `pgvector` / `milvus`). The
        /// remote path re-verifies + re-scores candidates locally but does
        /// NOT run BM25 fusion or the reranker (see `search_with_index`).
        #[arg(long, default_value = "local")]
        backend: String,
        /// Ingest chunk size in bytes. Sweeping this is how we learn whether
        /// the *unit* is the lever, which is only interpretable against a
        /// fixed `--budget-bytes`: smaller chunks otherwise win for free by
        /// letting more of them into a fixed slot count.
        #[arg(long, default_value_t = 800)]
        chunk_size: usize,
        /// Reader context budget in bytes for the budget-selected row, with
        /// overlapping text charged once. Held constant across a chunk-size
        /// sweep so any gain is more *distinct evidence* in the same context,
        /// not more text.
        #[arg(long, default_value_t = 8000)]
        budget_bytes: usize,
        /// How a session body is cut into drawers: `window` (the shipped
        /// `chunk_text` sliding window) or `turn` (one drawer per dialogue
        /// turn).
        ///
        /// These separate two things `--chunk-size` measures together. A
        /// 200-byte window holds fragments of two turns; a 138-byte turn holds
        /// one whole one. The sweep that found finer units worse only varied
        /// the window, so it says nothing about boundaries the *writer* made —
        /// which is the declared-unit question, and the one that generalises
        /// to code and prose where an arbitrary cut lands mid-function.
        #[arg(long, default_value = "window")]
        unit: String,
        /// Candidate pool size passed to `search` as `limit`. 0 keeps the
        /// historical `k*6`.
        ///
        /// This must be scaled when sweeping `--chunk-size`, or the sweep is
        /// confounded: `k*6` counts *chunks*, so halving the chunk size also
        /// halves the bytes of corpus the selector may choose from, and
        /// "smaller chunks are worse" becomes indistinguishable from "a
        /// smaller pool is worse".
        #[arg(long, default_value_t = 0)]
        pool: usize,
        /// Assert the R3 paging contract per turn-scored query: four calls
        /// of limit 10 at offsets 0/10/20/30 under one pinned `ranked_at`
        /// must tile one call of limit 40 exactly (ids and order), the
        /// all-gold they deliver must equal the depth CDF's ≤40 row, and an
        /// unpinned repeat records what the host clock drifts.
        #[arg(long)]
        paging_contract: bool,
    },
    /// Head-to-head vs external memory systems (competitive track C1.1):
    /// the LoCoMo protocol + scorer, driven through a system adapter —
    /// `undercroft` runs the native store; `mem0` / `supermemory` drive a
    /// locally hosted instance over its REST surface. One system per
    /// invocation; identical corpus, identical scoring, RAW lines for
    /// sharding. See docs/BENCHMARKS_VS.md for the fairness contract.
    Vs {
        /// Path to locomo10.json
        dataset: std::path::PathBuf,
        /// System under test: undercroft | mem0 | supermemory
        #[arg(long)]
        system: String,
        #[arg(short = 'k', long, default_value_t = 10)]
        k: usize,
        /// Evaluate at most N conversations (after --skip)
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long, default_value_t = 0)]
        skip: usize,
        /// Cap QA per conversation (0 = all) — extraction systems pay an
        /// LLM call per ingested chunk; document any subset used
        #[arg(long, default_value_t = 0)]
        qa_limit: usize,
        /// Base URL for HTTP systems (or UNDERCROFT_VS_URL)
        #[arg(long, default_value = "")]
        url: String,
    },
    /// C3.1 distillation ship-gate: does adding LLM-distilled
    /// facts-with-receipts to the retrieval surface beat the verbatim
    /// retrieval-only baseline on LoCoMo session-recall? One model per run
    /// (UNDERCROFT_LLM_URL/MODEL/API); measures baseline vs augmented R@k on
    /// the identical corpus and scorer, and counts receipts verified.
    Distill {
        /// Path to locomo10.json
        dataset: std::path::PathBuf,
        #[arg(short = 'k', long, default_value_t = 10)]
        k: usize,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long, default_value_t = 0)]
        skip: usize,
        /// Cap QA per conversation (0 = all)
        #[arg(long, default_value_t = 0)]
        qa_limit: usize,
    },
    /// ConvoMem protocol: message-level evidence recall
    Convomem {
        /// Path to a ConvoMem category JSON (array of items)
        dataset: std::path::PathBuf,
        #[arg(short = 'k', long, default_value_t = 10)]
        k: usize,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// MemBench (ACL 2025) protocol: turn-level target-step recall
    Membench {
        /// Path to a MemBench category JSON (topic- or role-keyed)
        dataset: std::path::PathBuf,
        /// Topic filter for topic-keyed files
        #[arg(long, default_value = "movie")]
        topic: String,
        #[arg(short = 'k', long, default_value_t = 5)]
        k: usize,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Evaluate the configured local LLM (UNDERCROFT_LLM_URL) on the
    /// extraction tasks used by `undercroft refine`, against the labeled
    /// multilingual datasets in benchmarks/model_eval/datasets
    ModelEval {
        /// Task: calibration | entities | memories
        task: String,
        /// Dataset directory
        #[arg(long, default_value = "benchmarks/model_eval/datasets")]
        dataset_dir: std::path::PathBuf,
        /// Language suffix (e.g. de, fr, zh) — default is English
        #[arg(long)]
        lang: Option<String>,
        /// Evaluate only the first N items
        #[arg(long)]
        limit: Option<usize>,
    },
}

fn level_of(s: &str) -> SecurityLevel {
    if s == "hmac-only" {
        SecurityLevel::HmacOnly
    } else {
        SecurityLevel::Sealed
    }
}

fn fresh_store(level: SecurityLevel) -> Result<(tempfile::TempDir, PalaceStore)> {
    fresh_store_id(level, "bench")
}

/// Like [`fresh_store`] but with a caller-chosen vault id. The remote-backend
/// LoCoMo path needs one collection per conversation (collection name derives
/// from the vault id), so it passes a unique id per convo to avoid cross-convo
/// vector collisions in the shared index.
fn fresh_store_id(level: SecurityLevel, id: &str) -> Result<(tempfile::TempDir, PalaceStore)> {
    let dir = tempfile::TempDir::new()?;
    let mgr = VaultManager::open(dir.path(), None)?;
    let vault = mgr.create(id, level)?;
    #[allow(unused_mut)]
    let mut store = match std::env::var("UNDERCROFT_EMBEDDER").as_deref() {
        Ok("onnx") => {
            // The `ort` (ONNX Runtime) backend takes precedence over `onnx`
            // (tract) when both features are built — same model file, faster.
            #[cfg(feature = "ort")]
            {
                PalaceStore::open_with_embedder(vault, ort_embedder_shared())?
            }
            #[cfg(all(feature = "onnx", not(feature = "ort")))]
            {
                PalaceStore::open_with_embedder(vault, onnx_shared())?
            }
            #[cfg(not(any(feature = "onnx", feature = "ort")))]
            anyhow::bail!("UNDERCROFT_EMBEDDER=onnx requires --features onnx or ort");
        }
        // A model served over HTTP (`UNDERCROFT_EMBED_URL`) — no feature gate,
        // so the default build can benchmark a real embedder without ONNX
        // exports. One request per drawer at ingest: expect the ingest phase
        // to be dominated by it.
        Ok("http") => {
            let embedder = undercroft_llm::HttpEmbedder::from_env()
                .map_err(|e| anyhow::anyhow!("connecting to the embeddings endpoint: {e}"))?;
            PalaceStore::open_with_embedder(vault, Box::new(embedder))?
        }
        _ => PalaceStore::open(vault)?,
    };
    // Optional second-stage reranker (pairs with either embedder). ORT wins
    // over tract when both are built.
    #[cfg(feature = "ort")]
    if std::env::var("UNDERCROFT_RERANKER").as_deref() == Ok("onnx") {
        store.set_reranker(Some(ort_reranker_shared()));
    }
    #[cfg(all(feature = "onnx", not(feature = "ort")))]
    if std::env::var("UNDERCROFT_RERANKER").as_deref() == Ok("onnx") {
        store.set_reranker(Some(rerank_shared()));
    }
    // Late-interaction (ColBERT) second stage: token matrices stored at
    // ingest, one query forward + MaxSim at search. ORT wins over tract when
    // both are built (same exports, faster forwards).
    #[cfg(feature = "ort")]
    if std::env::var("UNDERCROFT_RERANKER").as_deref() == Ok("colbert") {
        store.set_late(Some(ort_colbert_shared()));
    }
    #[cfg(all(feature = "onnx", not(feature = "ort")))]
    if std::env::var("UNDERCROFT_RERANKER").as_deref() == Ok("colbert") {
        store.set_late(Some(colbert_shared()));
    }
    // Optional local HNSW ANN prefilter (replaces the full cosine scan).
    if std::env::var("UNDERCROFT_RETRIEVAL").as_deref() == Ok("hnsw") {
        #[cfg(feature = "hnsw")]
        store.set_hnsw(true);
        #[cfg(not(feature = "hnsw"))]
        eprintln!("note: UNDERCROFT_RETRIEVAL=hnsw ignored — built without --features hnsw");
    }
    // Optional on-disk PQ ANN prefilter (bounded RAM).
    if std::env::var("UNDERCROFT_RETRIEVAL").as_deref() == Ok("pq") {
        store.set_pq(true);
    }
    // Optional MUVERA FDE candidate generation (needs the colbert encoder).
    if std::env::var("UNDERCROFT_RETRIEVAL").as_deref() == Ok("fde") {
        store.set_fde(true);
    }
    Ok((dir, store))
}

/// The ONNX model is loaded once and shared across every per-question
/// palace — model load costs seconds and LongMemEval creates 500 stores.
#[cfg(feature = "onnx")]
fn onnx_shared() -> Box<dyn undercroft_core::embed::Embedder + Send> {
    use std::sync::{Arc, OnceLock};
    static SHARED: OnceLock<Arc<undercroft_embed_onnx::OnnxEmbedder>> = OnceLock::new();
    let arc = SHARED
        .get_or_init(|| {
            Arc::new(undercroft_embed_onnx::from_env().expect("loading ONNX embedder from env"))
        })
        .clone();

    struct Shared(Arc<undercroft_embed_onnx::OnnxEmbedder>);
    impl undercroft_core::embed::Embedder for Shared {
        fn model_name(&self) -> &str {
            self.0.model_name()
        }
        fn dimension(&self) -> usize {
            self.0.dimension()
        }
        fn embed(&self, text: &str) -> Vec<f32> {
            self.0.embed(text)
        }
    }
    Box::new(Shared(arc))
}

/// The cross-encoder reranker, loaded once and shared across every per-question
/// palace (same rationale as `onnx_shared`).
#[cfg(feature = "onnx")]
fn rerank_shared() -> Box<dyn undercroft_core::rerank::Reranker + Send + Sync> {
    use std::sync::{Arc, OnceLock};
    static SHARED: OnceLock<Arc<undercroft_embed_onnx::OnnxReranker>> = OnceLock::new();
    let arc = SHARED
        .get_or_init(|| {
            Arc::new(
                undercroft_embed_onnx::OnnxReranker::from_env()
                    .expect("loading ONNX reranker from env"),
            )
        })
        .clone();

    struct Shared(Arc<undercroft_embed_onnx::OnnxReranker>);
    impl undercroft_core::rerank::Reranker for Shared {
        fn model_name(&self) -> &str {
            self.0.model_name()
        }
        fn score(&self, query: &str, passage: &str) -> f32 {
            self.0.score(query, passage)
        }
    }
    Box::new(Shared(arc))
}

/// The ColBERT late-interaction encoder, loaded once and shared across every
/// per-question palace (same rationale as `onnx_shared`).
#[cfg(feature = "onnx")]
fn colbert_shared() -> Box<dyn undercroft_core::late::LateInteraction + Send + Sync> {
    use std::sync::{Arc, OnceLock};
    static SHARED: OnceLock<Arc<undercroft_embed_onnx::OnnxColbert>> = OnceLock::new();
    let arc = SHARED
        .get_or_init(|| {
            Arc::new(
                undercroft_embed_onnx::colbert_from_env().expect("loading ColBERT encoder from env"),
            )
        })
        .clone();

    struct Shared(Arc<undercroft_embed_onnx::OnnxColbert>);
    impl undercroft_core::late::LateInteraction for Shared {
        fn model_name(&self) -> &str {
            self.0.model_name()
        }
        fn dim(&self) -> usize {
            self.0.dim()
        }
        fn encode_doc(&self, text: &str) -> Vec<f32> {
            self.0.encode_doc(text)
        }
        fn encode_query(&self, text: &str) -> Vec<f32> {
            self.0.encode_query(text)
        }
    }
    Box::new(Shared(arc))
}

/// ORT (ONNX Runtime) embedder, loaded once and shared, mirroring `onnx_shared`.
#[cfg(feature = "ort")]
fn ort_embedder_shared() -> Box<dyn undercroft_core::embed::Embedder + Send> {
    use std::sync::{Arc, OnceLock};
    static SHARED: OnceLock<Arc<undercroft_embed_ort::OrtEmbedder>> = OnceLock::new();
    let arc = SHARED
        .get_or_init(|| {
            Arc::new(
                undercroft_embed_ort::embedder_from_env().expect("loading ORT embedder from env"),
            )
        })
        .clone();
    struct Shared(Arc<undercroft_embed_ort::OrtEmbedder>);
    impl undercroft_core::embed::Embedder for Shared {
        fn model_name(&self) -> &str {
            self.0.model_name()
        }
        fn dimension(&self) -> usize {
            self.0.dimension()
        }
        fn embed(&self, text: &str) -> Vec<f32> {
            self.0.embed(text)
        }
    }
    Box::new(Shared(arc))
}

/// ORT reranker, loaded once and shared, mirroring `rerank_shared`.
#[cfg(feature = "ort")]
fn ort_reranker_shared() -> Box<dyn undercroft_core::rerank::Reranker + Send + Sync> {
    use std::sync::{Arc, OnceLock};
    static SHARED: OnceLock<Arc<undercroft_embed_ort::OrtReranker>> = OnceLock::new();
    let arc = SHARED
        .get_or_init(|| {
            Arc::new(
                undercroft_embed_ort::reranker_from_env().expect("loading ORT reranker from env"),
            )
        })
        .clone();
    struct Shared(Arc<undercroft_embed_ort::OrtReranker>);
    impl undercroft_core::rerank::Reranker for Shared {
        fn model_name(&self) -> &str {
            self.0.model_name()
        }
        fn score(&self, query: &str, passage: &str) -> f32 {
            self.0.score(query, passage)
        }
        fn score_batch(&self, query: &str, passages: &[&str]) -> Vec<f32> {
            self.0.score_batch(query, passages)
        }
    }
    Box::new(Shared(arc))
}

/// ORT ColBERT encoder, loaded once and shared, mirroring `colbert_shared`.
#[cfg(feature = "ort")]
fn ort_colbert_shared() -> Box<dyn undercroft_core::late::LateInteraction + Send + Sync> {
    use std::sync::{Arc, OnceLock};
    static SHARED: OnceLock<Arc<undercroft_embed_ort::OrtColbert>> = OnceLock::new();
    let arc = SHARED
        .get_or_init(|| {
            Arc::new(
                undercroft_embed_ort::colbert_from_env()
                    .expect("loading ORT ColBERT encoder from env"),
            )
        })
        .clone();
    struct Shared(Arc<undercroft_embed_ort::OrtColbert>);
    impl undercroft_core::late::LateInteraction for Shared {
        fn model_name(&self) -> &str {
            self.0.model_name()
        }
        fn dim(&self) -> usize {
            self.0.dim()
        }
        fn encode_doc(&self, text: &str) -> Vec<f32> {
            self.0.encode_doc(text)
        }
        fn encode_query(&self, text: &str) -> Vec<f32> {
            self.0.encode_query(text)
        }
    }
    Box::new(Shared(arc))
}

// ---------------------------------------------------------------------------
// Metrics (same definitions as upstream's harness)
// ---------------------------------------------------------------------------

fn dcg(relevances: &[f32], k: usize) -> f32 {
    relevances
        .iter()
        .take(k)
        .enumerate()
        .map(|(i, rel)| rel / ((i + 2) as f32).log2())
        .sum()
}

fn ndcg(ranked_ids: &[String], correct: &[String], k: usize) -> f32 {
    let rels: Vec<f32> = ranked_ids
        .iter()
        .take(k)
        .map(|id| if correct.contains(id) { 1.0 } else { 0.0 })
        .collect();
    let mut ideal = rels.clone();
    ideal.sort_by(|a, b| b.partial_cmp(a).unwrap());
    let idcg = dcg(&ideal, k);
    if idcg == 0.0 {
        0.0
    } else {
        dcg(&rels, k) / idcg
    }
}

// ---------------------------------------------------------------------------
// LongMemEval
// ---------------------------------------------------------------------------

fn run_longmemeval(
    dataset: &std::path::Path,
    limit: Option<usize>,
    k: usize,
    level: SecurityLevel,
    skip: usize,
) -> Result<()> {
    let raw = std::fs::read_to_string(dataset)
        .with_context(|| format!("reading dataset {}", dataset.display()))?;
    let mut items: Vec<Value> =
        serde_json::from_str(&raw).context("dataset must be a JSON array")?;
    if skip > 0 {
        items.drain(..skip.min(items.len()));
    }
    let total = limit.unwrap_or(items.len()).min(items.len());

    let mut recall_any_sum = 0f32;
    let mut recall_all_sum = 0f32;
    let mut ndcg_sum = 0f32;
    let mut by_type: std::collections::BTreeMap<String, (f32, u32)> = Default::default();
    let started = Instant::now();

    for (qi, item) in items.iter().take(total).enumerate() {
        let question = item
            .get("question")
            .and_then(Value::as_str)
            .context("item missing 'question'")?;
        let qtype = item
            .get("question_type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let sessions = item
            .get("haystack_sessions")
            .and_then(Value::as_array)
            .context("item missing 'haystack_sessions'")?;
        let session_ids: Vec<String> = item
            .get("haystack_session_ids")
            .and_then(Value::as_array)
            .context("item missing 'haystack_session_ids'")?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        let correct: Vec<String> = item
            .get("answer_session_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        // Fresh palace per question, one room per haystack session
        // (upstream's session-granularity protocol).
        let (_tmp, mut store) = fresh_store(level)?;
        for (si, session) in sessions.iter().enumerate() {
            let sid = session_ids
                .get(si)
                .cloned()
                .unwrap_or_else(|| format!("s{si}"));
            let turns = session.as_array().cloned().unwrap_or_default();
            let text: Vec<String> = turns
                .iter()
                .filter_map(|t| {
                    let role = t.get("role").and_then(Value::as_str)?;
                    let content = t.get("content").and_then(Value::as_str)?;
                    Some(format!("{role}: {content}"))
                })
                .collect();
            let body = undercroft_core::normalize_content(&text.join("\n"));
            if body.is_empty() {
                continue;
            }
            for (ci, chunk) in
                undercroft_core::chunk_text(&body, undercroft_core::ChunkOptions::default())
                    .into_iter()
                    .enumerate()
            {
                let drawer = Drawer::new("haystack", &sid, chunk, None, ci as u32, "bench");
                store.upsert(&drawer)?;
            }
        }

        // Retrieve, dedupe hits to session (room) ranking.
        let hits = store.search(
            question,
            &SearchOptions {
                morph_lang: Default::default(),
                wing: None,
                room: None,
                limit: k * 8,
                room_cap: None,
                ..Default::default()
            },
        )?;
        let mut ranked_sessions: Vec<String> = Vec::new();
        for h in &hits {
            if !ranked_sessions.contains(&h.drawer.meta.room) {
                ranked_sessions.push(h.drawer.meta.room.clone());
            }
        }

        let topk: Vec<&String> = ranked_sessions.iter().take(k).collect();
        let recall_any = if correct.iter().any(|c| topk.contains(&c)) {
            1.0
        } else {
            0.0
        };
        let recall_all = if !correct.is_empty() && correct.iter().all(|c| topk.contains(&c)) {
            1.0
        } else {
            0.0
        };
        let n = ndcg(&ranked_sessions, &correct, k);
        recall_any_sum += recall_any;
        recall_all_sum += recall_all;
        ndcg_sum += n;
        let e = by_type.entry(qtype).or_insert((0.0, 0));
        e.0 += recall_any;
        e.1 += 1;

        if (qi + 1) % 25 == 0 {
            eprintln!(
                "  {}/{total}  R@{k}(any) so far: {:.1}%",
                qi + 1,
                100.0 * recall_any_sum / (qi + 1) as f32
            );
        }
    }

    let n = total as f32;
    // RAW numerators so sharded runs sum to the exact R@k / NDCG (per-shard
    // percentages would round-drift). skip/limit define the shard window.
    println!(
        "LME_RAW total={total} recall_any_sum={recall_any_sum:.4} recall_all_sum={recall_all_sum:.4} ndcg_sum={ndcg_sum:.4}"
    );
    println!("LongMemEval — {total} questions, session granularity, k={k}");
    println!("  Recall@{k} (any): {:.1}%", 100.0 * recall_any_sum / n);
    println!("  Recall@{k} (all): {:.1}%", 100.0 * recall_all_sum / n);
    println!("  NDCG@{k}:         {:.3}", ndcg_sum / n);
    println!("  wall clock:      {:.1}s", started.elapsed().as_secs_f32());
    println!("  by question type (R@{k} any):");
    for (t, (sum, cnt)) in by_type {
        println!("    {t:<28} {:.1}%  ({cnt})", 100.0 * sum / cnt as f32);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Synthetic benchmark
// ---------------------------------------------------------------------------

const TOPICS: &[&str] = &[
    "database migration",
    "kitchen renovation",
    "marathon training",
    "tax filing",
    "guitar practice",
    "camping trip",
    "api gateway",
    "book club",
    "solar panels",
    "language learning",
];

const FACT_TEMPLATES: &[&str] = &[
    "For the {topic} project we decided that {detail} after a long discussion.",
    "Note from the {topic} meeting: {detail}, agreed by everyone present.",
    "Important: regarding {topic}, remember that {detail}.",
    "The {topic} plan changed — now {detail} going forward.",
];

const QUERY_TEMPLATES: &[&str] = &[
    "what did we decide about {topic} {key}",
    "remind me about the {key} for {topic}",
];

fn run_synth(n: usize, level: SecurityLevel, queries: Option<usize>) -> Result<()> {
    let (_tmp, mut store) = fresh_store(level)?;
    // Deterministic distinct facts: each carries a unique key token that the
    // query paraphrases around (tests retrieval, not string equality —
    // queries never repeat the full fact sentence).
    let mut keys = Vec::with_capacity(n);
    let ingest_started = Instant::now();
    for i in 0..n {
        let topic = TOPICS[i % TOPICS.len()];
        let key = format!(
            "{}-{:04}",
            ["budget", "deadline", "vendor", "owner"][i % 4],
            i
        );
        let detail = format!("the {key} is finalized as option {}", (i * 7) % 100);
        let fact = FACT_TEMPLATES[i % FACT_TEMPLATES.len()]
            .replace("{topic}", topic)
            .replace("{detail}", &detail);
        let drawer = Drawer::new("bench", topic, fact, None, i as u32, "bench");
        store.upsert(&drawer)?;
        keys.push((key, topic.to_string(), drawer.id));
    }
    let ingest_secs = ingest_started.elapsed().as_secs_f32();

    // Query either every fact or an even sample of `queries` of them.
    let stride = queries
        .map(|q| keys.len().div_ceil(q.max(1)))
        .unwrap_or(1)
        .max(1);
    let q_total = keys.iter().step_by(stride).count();

    let mut r1 = 0u32;
    let mut r5 = 0u32;
    let query_started = Instant::now();
    for (i, (key, topic, id)) in keys.iter().enumerate().step_by(stride) {
        let query = QUERY_TEMPLATES[i % QUERY_TEMPLATES.len()]
            .replace("{topic}", topic)
            .replace("{key}", &key[..key.find('-').unwrap_or(key.len())]);
        // Make the query unique to its fact via the key token.
        let query = format!("{query} {key}");
        let hits = store.search(
            &query,
            &SearchOptions {
                morph_lang: Default::default(),
                wing: None,
                room: None,
                limit: 5,
                room_cap: None,
                ..Default::default()
            },
        )?;
        if hits.first().map(|h| &h.drawer.id) == Some(id) {
            r1 += 1;
        }
        if hits.iter().any(|h| &h.drawer.id == id) {
            r5 += 1;
        }
    }
    let query_secs = query_started.elapsed().as_secs_f32();

    println!("Synthetic benchmark — {n} facts, {q_total} queries, level={level:?}");
    println!("  Recall@1: {:.1}%", 100.0 * r1 as f32 / q_total as f32);
    println!("  Recall@5: {:.1}%", 100.0 * r5 as f32 / q_total as f32);
    println!(
        "  ingest:   {:.2}s ({:.1} docs/s)",
        ingest_secs,
        n as f32 / ingest_secs
    );
    println!(
        "  query:    {:.2}s ({:.1} q/s)",
        query_secs,
        q_total as f32 / query_secs
    );
    let r5_pct = 100.0 * r5 as f32 / q_total as f32;
    if r5_pct < 95.0 {
        anyhow::bail!("regression: synthetic Recall@5 {r5_pct:.1}% (expected >= 95%)");
    }
    println!("SYNTH OK");
    Ok(())
}

/// Unscoped-PQ scaling probe: ONE cumulative vault, ingested to each
/// checkpoint in turn, an untimed warm-up at each (which pays whatever the
/// event-driven machinery owes at that size — verify pass, codebook train,
/// IVF retrain when the corpus doubled — and is reported as the maintenance
/// cost curve), then a timed unscoped pass sampled evenly over everything
/// ingested so far. No gate: whatever the recall and latency curves do IS
/// the result, and a probe that bails on the interesting region would be
/// the stride landmine again.
fn run_pqscale(
    sizes: &str,
    queries: usize,
    pools: &str,
    batch: usize,
    pool_div: Option<&str>,
    level: SecurityLevel,
) -> Result<()> {
    let checkpoints: Vec<usize> = sizes
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|_| anyhow::anyhow!("--sizes entries are numbers, got {s:?}"))
        })
        .collect::<Result<_>>()?;
    if checkpoints.is_empty() {
        anyhow::bail!("--sizes is empty");
    }
    // Candidate pools map through `limit`: the prefilter fetches
    // max(256, limit*32) candidates, so a requested pool rounds up to that
    // grid. R@5 is always scored over the first five hits.
    let pool_limits: Vec<(usize, usize)> = pools
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| -> Result<(usize, usize)> {
            let p: usize = s
                .parse()
                .map_err(|_| anyhow::anyhow!("--pools entries are numbers, got {s:?}"))?;
            let limit = p.div_ceil(32).max(8);
            Ok((limit.saturating_mul(32).max(256), limit))
        })
        .collect::<Result<_>>()?;
    if pool_limits.is_empty() {
        anyhow::bail!("--pools is empty");
    }
    let batch = batch.max(1);
    let (_tmp, mut store) = fresh_store(level)?;
    store.set_pq(true);
    let div_label = match pool_div {
        Some(v) if v.eq_ignore_ascii_case("off") => {
            store.set_pool_div(usize::MAX);
            "off".to_string()
        }
        Some(v) => {
            let d: usize = v
                .parse()
                .map_err(|_| anyhow::anyhow!("--pool-div takes a number or `off`, got {v:?}"))?;
            store.set_pool_div(d);
            d.to_string()
        }
        None => "default".to_string(),
    };

    // Every 512th fact is a query candidate — bounded memory at 10^6.
    const KEY_STRIDE: usize = 512;
    let mut keys: Vec<(String, String, String)> = Vec::new();
    let mut ingested = 0usize;
    println!(
        "Pqscale — level={level:?} retrieval=pq checkpoints={checkpoints:?} \
         pools={pool_limits:?} batch={batch} pool_div={div_label}"
    );
    for &target in &checkpoints {
        let seg_start = ingested;
        let ingest_started = Instant::now();
        let mut pending: Vec<Drawer> = Vec::with_capacity(batch.min(target));
        while ingested < target {
            let i = ingested;
            let topic = TOPICS[i % TOPICS.len()];
            let key = format!(
                "{}-{:07}",
                ["budget", "deadline", "vendor", "owner"][i % 4],
                i
            );
            let detail = format!("the {key} is finalized as option {}", (i * 7) % 100);
            let fact = FACT_TEMPLATES[i % FACT_TEMPLATES.len()]
                .replace("{topic}", topic)
                .replace("{detail}", &detail);
            let drawer = Drawer::new("bench", topic, fact, None, i as u32, "bench");
            if i.is_multiple_of(KEY_STRIDE) {
                keys.push((key, topic.to_string(), drawer.id.clone()));
            }
            pending.push(drawer);
            if pending.len() >= batch {
                store.upsert_many(&pending)?;
                pending.clear();
            }
            ingested += 1;
        }
        if !pending.is_empty() {
            store.upsert_many(&pending)?;
        }
        let ingest_secs = ingest_started.elapsed().as_secs_f32();
        let db_gb = store.stats().map(|s| s.db_bytes).unwrap_or(0) as f64 / 1e9;

        let stride = keys.len().div_ceil(queries.max(1)).max(1);
        let sampled: Vec<&(String, String, String)> = keys.iter().step_by(stride).collect();
        let q_total = sampled.len();
        let query_for = |qi: usize, key: &str, topic: &str| {
            let q = QUERY_TEMPLATES[qi % QUERY_TEMPLATES.len()]
                .replace("{topic}", topic)
                .replace("{key}", &key[..key.find('-').unwrap_or(key.len())]);
            format!("{q} {key}")
        };

        // Warm-up: one query that pays the size's event-driven debts
        // (verify pass, codebook train, IVF retrain) outside every timed
        // column below.
        let (wk, wt, _) = sampled[0];
        let warm_started = Instant::now();
        store.search(
            &query_for(0, wk, wt),
            &SearchOptions {
                limit: 5,
                ..Default::default()
            },
        )?;
        let warmup_s = warm_started.elapsed().as_secs_f32();
        println!(
            "  n={ingested:>8}  db {db_gb:.2} GB  ingest {ingest_secs:.1}s \
             ({:.0} docs/s)  warmup {warmup_s:.1}s  ({q_total} queries/pool)",
            ((target - seg_start) as f32 / ingest_secs.max(f32::EPSILON))
        );

        for &(pool, limit) in &pool_limits {
            let mut r5 = 0u32;
            let timed = Instant::now();
            for (qi, (key, topic, id)) in sampled.iter().copied().enumerate() {
                let hits = store.search(
                    &query_for(qi, key, topic),
                    &SearchOptions {
                        limit,
                        ..Default::default()
                    },
                )?;
                if hits.iter().take(5).any(|h| &h.drawer.id == id) {
                    r5 += 1;
                }
            }
            let secs = timed.elapsed().as_secs_f32();
            println!(
                "    pool={pool:>5}  unscoped R@5 {:.1}%  {:.1} ms/q",
                100.0 * r5 as f32 / q_total.max(1) as f32,
                1000.0 * secs / q_total.max(1) as f32,
            );
        }
    }
    println!("PQSCALE DONE");
    Ok(())
}

/// Scoped-recall-at-scale. The design, stated before anything runs:
/// a FIXED probe wing (default 8192 — the wing tier engages) holding a
/// FIXED probe room (default 512 — past the exact-scan floor, so the
/// scoped membership-filter path carries the recall), ingested FIRST into
/// one cumulative vault; the corpus then grows around them in another
/// wing to each checkpoint. Four passes per checkpoint — unscoped
/// (control: the shipped-default gate), wing-scoped, room-scoped (the
/// pure room filter over the global index), wing+room (the room filter
/// inside the wing tier's index). Per-pass warm-up is reported
/// separately (the wing tier builds its index on the first scoped query —
/// folding a one-time build into a per-query average manufactured a 15×
/// "effect" in wingscale's first version). The scoped columns are what a
/// recall claim for the tier and the scope filter must cite; a leak in
/// any of them at any checkpoint is a defect, not a property.
fn run_scopescale(
    sizes: &str,
    wing_size: usize,
    room_size: usize,
    queries: usize,
    batch: usize,
    level: SecurityLevel,
) -> Result<()> {
    let checkpoints: Vec<usize> = sizes
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|_| anyhow::anyhow!("--sizes entries are numbers, got {s:?}"))
        })
        .collect::<Result<_>>()?;
    if checkpoints.is_empty() {
        anyhow::bail!("--sizes is empty");
    }
    let wing_size = wing_size.max(16);
    let room_size = room_size.min(wing_size).max(8);
    if checkpoints[0] <= wing_size {
        anyhow::bail!("first checkpoint must exceed --wing-size (the probe is ingested first)");
    }
    let batch = batch.max(1);
    let (_tmp, mut store) = fresh_store(level)?;
    store.set_pq(true);
    println!(
        "Scopescale — level={level:?} retrieval=pq checkpoints={checkpoints:?} \
         probe wing={wing_size} room={room_size} batch={batch}"
    );

    // The probe: fixed for the whole run. Keys are collected for the room
    // (all of it) and the wing (strided to the query budget), each with
    // the drawer's OWN topic — querying with a rotated topic pollutes the
    // query with wrong-topic tokens and measures the pollution, not the
    // scope (this harness's own first smoke run demonstrated it).
    let mut room_keys: Vec<(String, String, String)> = Vec::new(); // (key, topic, id)
    let mut wing_keys: Vec<(String, String, String)> = Vec::new();
    {
        let mut pending: Vec<Drawer> = Vec::with_capacity(batch.min(wing_size));
        for j in 0..wing_size {
            let topic = TOPICS[j % TOPICS.len()];
            let key = format!("probe-{:05}", j);
            let detail = format!("the {key} is finalized as option {}", (j * 7) % 100);
            let fact = FACT_TEMPLATES[j % FACT_TEMPLATES.len()]
                .replace("{topic}", topic)
                .replace("{detail}", &detail);
            let room = if j < room_size {
                "proberoom".to_string()
            } else {
                format!("room-{}", j % 8)
            };
            let drawer = Drawer::new("probe", &room, fact, None, j as u32, "bench");
            if j < room_size {
                room_keys.push((key.clone(), topic.to_string(), drawer.id.clone()));
            } else if j.is_multiple_of(16) {
                wing_keys.push((key.clone(), topic.to_string(), drawer.id.clone()));
            }
            pending.push(drawer);
            if pending.len() >= batch {
                store.upsert_many(&pending)?;
                pending.clear();
            }
        }
        if !pending.is_empty() {
            store.upsert_many(&pending)?;
        }
    }

    // Growth corpus: the pqscale generator, in its own wing, with keys for
    // the unscoped control column.
    const KEY_STRIDE: usize = 512;
    let mut global_keys: Vec<(String, String, String)> = Vec::new();
    let mut ingested = wing_size;
    type Keys = [(String, String, String)];
    let sample = |keys: &Keys, want: usize| -> Vec<(String, String, String)> {
        let stride = keys.len().div_ceil(want.max(1)).max(1);
        keys.iter().step_by(stride).cloned().collect()
    };
    let query_for = |qi: usize, key: &str, topic: &str| {
        let q = QUERY_TEMPLATES[qi % QUERY_TEMPLATES.len()]
            .replace("{topic}", topic)
            .replace("{key}", &key[..key.find('-').unwrap_or(key.len())]);
        format!("{q} {key}")
    };
    for &target in &checkpoints {
        let seg_start = ingested;
        let ingest_started = Instant::now();
        let mut pending: Vec<Drawer> = Vec::with_capacity(batch);
        while ingested < target {
            let i = ingested;
            let topic = TOPICS[i % TOPICS.len()];
            let key = format!(
                "{}-{:07}",
                ["budget", "deadline", "vendor", "owner"][i % 4],
                i
            );
            let detail = format!("the {key} is finalized as option {}", (i * 7) % 100);
            let fact = FACT_TEMPLATES[i % FACT_TEMPLATES.len()]
                .replace("{topic}", topic)
                .replace("{detail}", &detail);
            let drawer = Drawer::new("bench", topic, fact, None, i as u32, "bench");
            if i.is_multiple_of(KEY_STRIDE) {
                global_keys.push((key, topic.to_string(), drawer.id.clone()));
            }
            pending.push(drawer);
            if pending.len() >= batch {
                store.upsert_many(&pending)?;
                pending.clear();
            }
            ingested += 1;
        }
        if !pending.is_empty() {
            store.upsert_many(&pending)?;
        }
        let ingest_secs = ingest_started.elapsed().as_secs_f32();
        let db_gb = store.stats().map(|s| s.db_bytes).unwrap_or(0) as f64 / 1e9;
        println!(
            "  n={ingested:>8}  db {db_gb:.2} GB  ingest {ingest_secs:.1}s \
             ({:.0} docs/s)",
            ((target - seg_start) as f32 / ingest_secs.max(f32::EPSILON))
        );

        // (label, wing filter, room filter, key set)
        #[allow(clippy::type_complexity)]
        let passes: [(
            &str,
            Option<&str>,
            Option<&str>,
            Vec<(String, String, String)>,
        ); 4] = [
            ("unscoped ", None, None, sample(&global_keys, queries)),
            (
                "wing     ",
                Some("probe"),
                None,
                sample(&wing_keys, queries),
            ),
            (
                "room     ",
                None,
                Some("proberoom"),
                sample(&room_keys, queries),
            ),
            (
                "wing+room",
                Some("probe"),
                Some("proberoom"),
                sample(&room_keys, queries),
            ),
        ];
        for (label, wing, room, keys) in &passes {
            let opts = || SearchOptions {
                wing: wing.map(str::to_string),
                room: room.map(str::to_string),
                limit: 5,
                ..Default::default()
            };
            let (wk, wt, _) = &keys[0];
            let warm_started = Instant::now();
            store.search(&query_for(0, wk, wt), &opts())?;
            let warmup_s = warm_started.elapsed().as_secs_f32();
            let mut r5 = 0u32;
            let timed = Instant::now();
            for (qi, (key, topic, id)) in keys.iter().enumerate() {
                let hits = store.search(&query_for(qi, key, topic), &opts())?;
                if hits.iter().take(5).any(|h| &h.drawer.id == id) {
                    r5 += 1;
                }
            }
            let secs = timed.elapsed().as_secs_f32();
            println!(
                "    {label}  R@5 {:>5.1}%  {:>7.1} ms/q  (warmup {warmup_s:.1}s, {} queries)",
                100.0 * r5 as f32 / keys.len().max(1) as f32,
                1000.0 * secs / keys.len().max(1) as f32,
                keys.len(),
            );
        }
    }
    println!("SCOPESCALE DONE");
    Ok(())
}

/// Cross-lingual retrieval instrument. See the subcommand doc for the
/// design; the metric is fixed here BEFORE any run: per language pair,
/// R@1 and R@5 of querying with the source sentence for the drawer
/// holding its target-language translation, over a corpus of every
/// pair's target sentence (each pair's competitors are all the others).
/// The `verbatim` column queries with the target sentence itself — a
/// harness sanity floor, not a capability claim.
fn run_xlingual(pairs_path: &str, limit: usize, level: SecurityLevel) -> Result<()> {
    let raw = std::fs::read_to_string(pairs_path)
        .map_err(|e| anyhow::anyhow!("cannot read --pairs {pairs_path:?}: {e}"))?;
    // (src_lang, tgt_lang, src_text, tgt_text)
    let mut by_pair: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for (ln, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.splitn(4, '\t');
        let (Some(sl), Some(tl), Some(st), Some(tt)) = (f.next(), f.next(), f.next(), f.next())
        else {
            anyhow::bail!("--pairs line {} is not 4 tab-separated fields", ln + 1);
        };
        let bucket = by_pair.entry(format!("{sl}->{tl}")).or_default();
        if limit == 0 || bucket.len() < limit {
            bucket.push((st.to_string(), tt.to_string()));
        }
    }
    if by_pair.is_empty() {
        anyhow::bail!("--pairs {pairs_path:?} holds no usable rows");
    }
    let embedder = std::env::var("UNDERCROFT_EMBEDDER").unwrap_or_else(|_| "hash".into());
    let (_tmp, mut store) = fresh_store(level)?;
    let total: usize = by_pair.values().map(Vec::len).sum();
    println!(
        "Xlingual — level={level:?} embedder={embedder} pairs={} ({} language pairs) \
         [config is the variable: hash = the measured-zero baseline]",
        total,
        by_pair.len()
    );

    // Ingest every pair's TARGET sentence; the drawer id is the gold.
    let mut gold: Vec<(String, String, String, String)> = Vec::new(); // (pair, src, tgt, id)
    let mut pending: Vec<Drawer> = Vec::with_capacity(256);
    for (pair, rows) in &by_pair {
        for (i, (src, tgt)) in rows.iter().enumerate() {
            let d = Drawer::new("xling", pair, tgt.clone(), None, i as u32, "bench");
            gold.push((pair.clone(), src.clone(), tgt.clone(), d.id.clone()));
            pending.push(d);
            if pending.len() >= 256 {
                store.upsert_many(&pending)?;
                pending.clear();
            }
        }
    }
    if !pending.is_empty() {
        store.upsert_many(&pending)?;
    }

    let opts = || SearchOptions {
        limit: 5,
        ..Default::default()
    };
    let mut rows: Vec<(String, usize, u32, u32, u32)> = Vec::new();
    for pair in by_pair.keys() {
        let (mut r1, mut r5, mut verbatim) = (0u32, 0u32, 0u32);
        let mine: Vec<_> = gold.iter().filter(|(p, ..)| p == pair).collect();
        for (_, src, tgt, id) in &mine {
            let hits = store.search(src, &opts())?;
            if hits.first().is_some_and(|h| &h.drawer.id == id) {
                r1 += 1;
            }
            if hits.iter().take(5).any(|h| &h.drawer.id == id) {
                r5 += 1;
            }
            let vh = store.search(tgt, &opts())?;
            if vh.first().is_some_and(|h| &h.drawer.id == id) {
                verbatim += 1;
            }
        }
        rows.push((pair.clone(), mine.len(), r1, r5, verbatim));
    }
    println!("  pair          n     R@1     R@5   verbatim-R@1");
    for (pair, n, r1, r5, v) in &rows {
        let pct = |x: &u32| 100.0 * *x as f32 / (*n).max(1) as f32;
        println!(
            "  {pair:<12} {n:>4}  {:>5.1}%  {:>5.1}%  {:>5.1}%",
            pct(r1),
            pct(r5),
            pct(v)
        );
        if pct(v) < 90.0 {
            println!(
                "    WARNING: verbatim recovery under 90% — suspect the harness \
                 or the corpus before reading the cross-lingual columns"
            );
        }
    }
    println!("XLINGUAL DONE");
    Ok(())
}

/// Wing-as-retrieval-unit scaling harness. Round-robin ingest across
/// `wings` wings (deliberately periodic — that is ordinary ingest order and
/// exactly what the keyed training draw must tolerate) ONCE, then for each
/// requested floor two query passes over the subject wing's facts: scoped
/// to that wing, and unscoped. Scoped R@5 is the gated number — it is what
/// corpus-wide candidate sets take away from a wing and what the per-wing
/// tier restores.
///
/// Each pass runs ONE untimed warm-up query first and reports its cost
/// separately: the first search after open trains/builds whatever index its
/// path needs, and folding minutes of one-time build into a per-query
/// average is how this harness's own first version produced a 15x
/// scoped-vs-unscoped "difference" that was really "which pass paid the
/// build". Timed columns are steady state; `warmup` carries the build.
/// The columns also include hydration and fusion, not candidate generation
/// alone, so at equal candidate counts the passes converge — recall and
/// warmup are where the tier shows.
fn run_wingscale(
    n: usize,
    wings: usize,
    queries: usize,
    floors: &str,
    level: SecurityLevel,
) -> Result<()> {
    let (_tmp, mut store) = fresh_store(level)?;
    store.set_pq(true);
    let wings = wings.max(1);
    let subject = "wing-000";

    let ingest_started = Instant::now();
    let mut keys: Vec<(String, String, String)> = Vec::new();
    for i in 0..n {
        let wing = format!("wing-{:03}", i % wings);
        let topic = TOPICS[i % TOPICS.len()];
        let key = format!(
            "{}-{:05}",
            ["budget", "deadline", "vendor", "owner"][i % 4],
            i
        );
        let detail = format!("the {key} is finalized as option {}", (i * 7) % 100);
        let fact = FACT_TEMPLATES[i % FACT_TEMPLATES.len()]
            .replace("{topic}", topic)
            .replace("{detail}", &detail);
        let drawer = Drawer::new(&wing, topic, fact, None, i as u32, "bench");
        store.upsert(&drawer)?;
        if i % wings == 0 {
            keys.push((key, topic.to_string(), drawer.id));
        }
    }
    let ingest_secs = ingest_started.elapsed().as_secs_f32();
    let wing_size = keys.len();
    println!(
        "Wingscale — n={n} wings={wings} wing_size={wing_size} level={level:?} \
         ingest {ingest_secs:.2}s ({:.1} docs/s)",
        n as f32 / ingest_secs
    );

    if keys.is_empty() {
        anyhow::bail!("no drawers in the subject wing — raise --n or lower --wings");
    }
    let stride = keys.len().div_ceil(queries.max(1)).max(1);
    let sampled: Vec<&(String, String, String)> = keys.iter().step_by(stride).collect();
    let q_total = sampled.len();

    let query_for = |qi: usize, key: &str, topic: &str| {
        let q = QUERY_TEMPLATES[qi % QUERY_TEMPLATES.len()]
            .replace("{topic}", topic)
            .replace("{key}", &key[..key.find('-').unwrap_or(key.len())]);
        format!("{q} {key}")
    };

    for floor_spec in floors.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let floor_label = if floor_spec.eq_ignore_ascii_case("off") {
            store.set_wing_pq_min(usize::MAX);
            "off".to_string()
        } else if floor_spec.eq_ignore_ascii_case("default") {
            store.set_wing_pq_min(undercroft_store::WING_PQ_MIN_DEFAULT);
            format!("default({})", undercroft_store::WING_PQ_MIN_DEFAULT)
        } else {
            let min: usize = floor_spec.parse().map_err(|_| {
                anyhow::anyhow!(
                    "--floors entries are numbers, `default` or `off`, got {floor_spec:?}"
                )
            })?;
            store.set_wing_pq_min(min);
            min.to_string()
        };

        let pass = |wing: Option<String>| -> Result<(f32, f32, f32)> {
            // Warm-up: the one query that pays index build/train for this
            // path, reported on its own so the timed loop is steady state.
            let (key, topic, _) = sampled[0];
            let warm_started = Instant::now();
            store.search(
                &query_for(0, key, topic),
                &SearchOptions {
                    wing: wing.clone(),
                    limit: 5,
                    ..Default::default()
                },
            )?;
            let warmup_ms = 1000.0 * warm_started.elapsed().as_secs_f32();
            let mut r5 = 0u32;
            let started = Instant::now();
            for (qi, (key, topic, id)) in sampled.iter().copied().enumerate() {
                let hits = store.search(
                    &query_for(qi, key, topic),
                    &SearchOptions {
                        wing: wing.clone(),
                        limit: 5,
                        ..Default::default()
                    },
                )?;
                if hits.iter().any(|h| &h.drawer.id == id) {
                    r5 += 1;
                }
            }
            let secs = started.elapsed().as_secs_f32();
            Ok((
                100.0 * r5 as f32 / q_total.max(1) as f32,
                1000.0 * secs / q_total.max(1) as f32,
                warmup_ms,
            ))
        };
        let (scoped_r5, scoped_ms, scoped_warm) = pass(Some(subject.to_string()))?;
        let (unscoped_r5, unscoped_ms, unscoped_warm) = pass(None)?;

        // Whether the scoped pass actually probed a wing index: the tier
        // must be on AND the wing's codebook trained. Reading only the
        // generation counter lied here — a codebook trained by an earlier
        // floor entry persists in meta while `off` routes around it.
        let tier_on = !floor_spec.eq_ignore_ascii_case("off");
        let wing_indexed = tier_on
            && store
                .stats()?
                .codebooks
                .iter()
                .any(|(a, g)| a == &format!("{subject}/pq-codebook") && *g > 0);

        println!("floor={floor_label} wing_index_used={wing_indexed} ({q_total} queries)");
        println!(
            "  scoped:   R@5 {scoped_r5:.1}%  {scoped_ms:.1} ms/q  (warmup {scoped_warm:.0} ms)"
        );
        println!(
            "  unscoped: R@5 {unscoped_r5:.1}%  {unscoped_ms:.1} ms/q  (warmup {unscoped_warm:.0} ms)"
        );
        // `off` entries exist to document the pre-tier behavior (corpus-wide
        // candidates crowding out the wing) — that is the measurement, not a
        // regression, so only tier-on entries are gated.
        if !floor_spec.eq_ignore_ascii_case("off") && scoped_r5 < 95.0 {
            anyhow::bail!(
                "regression: scoped Recall@5 {scoped_r5:.1}% (expected >= 95%) — a wing-scoped \
                 query must be answered from its wing at any corpus size"
            );
        }
    }
    println!("WINGSCALE OK");
    Ok(())
}

// ---------------------------------------------------------------------------
// model_eval — score the configured local LLM on refine's extraction tasks
// ---------------------------------------------------------------------------

fn load_jsonl(path: &std::path::Path) -> Result<Vec<Value>> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(Into::into))
        .collect()
}

fn run_model_eval(
    task: &str,
    dataset_dir: &std::path::Path,
    lang: Option<&str>,
    limit: Option<usize>,
) -> Result<()> {
    let llm = undercroft_llm::LlmClient::from_env()
        .map_err(|e| anyhow::anyhow!("{e} (model-eval scores a local LLM)"))?;
    let (subdir, file) = match task {
        "calibration" => ("calibration", "dataset"),
        "entities" => ("entity_extraction", "dataset"),
        "memories" => ("memory_extraction", "dataset"),
        other => {
            anyhow::bail!("unknown task {other:?} (expected: calibration, entities, memories)")
        }
    };
    let suffix = lang.map(|l| format!(".{l}")).unwrap_or_default();
    let data = load_jsonl(
        &dataset_dir
            .join(subdir)
            .join(format!("{file}{suffix}.jsonl")),
    )?;
    let labels = load_jsonl(&dataset_dir.join(subdir).join("labels.jsonl"))?;
    let label_by_id: std::collections::HashMap<&str, &Value> = labels
        .iter()
        .filter_map(|l| Some((l.get("id")?.as_str()?, l)))
        .collect();
    let total = limit.unwrap_or(data.len()).min(data.len());

    match task {
        "calibration" => {
            let mut correct = 0u32;
            for item in data.iter().take(total) {
                let id = item.get("id").and_then(Value::as_str).context("item id")?;
                let text = item
                    .get("text")
                    .and_then(Value::as_str)
                    .context("item text")?;
                let classes: Vec<String> = item
                    .get("classes")
                    .and_then(Value::as_array)
                    .context("item classes")?
                    .iter()
                    .filter_map(|c| c.as_str().map(str::to_string))
                    .collect();
                let expected = label_by_id
                    .get(id)
                    .and_then(|l| l.get("label"))
                    .and_then(Value::as_str)
                    .context("label")?;
                let got = llm
                    .classify(text, &classes)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                if got.eq_ignore_ascii_case(expected) {
                    correct += 1;
                }
            }
            println!(
                "calibration{} — {}/{} correct ({:.1}%) with {}",
                suffix,
                correct,
                total,
                100.0 * correct as f32 / total as f32,
                llm.model()
            );
        }
        "entities" => {
            let (mut tp, mut fp, mut fn_) = (0f32, 0f32, 0f32);
            for item in data.iter().take(total) {
                let id = item.get("id").and_then(Value::as_str).context("item id")?;
                let text = item
                    .get("text")
                    .and_then(Value::as_str)
                    .context("item text")?;
                let expected: std::collections::BTreeSet<String> = label_by_id
                    .get(id)
                    .and_then(|l| l.get("entities"))
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|e| e.get("name")?.as_str().map(|s| s.to_lowercase()))
                            .collect()
                    })
                    .unwrap_or_default();
                let got: std::collections::BTreeSet<String> = llm
                    .extract_entities(text)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .into_iter()
                    .map(|e| e.name.to_lowercase())
                    .collect();
                tp += got.intersection(&expected).count() as f32;
                fp += got.difference(&expected).count() as f32;
                fn_ += expected.difference(&got).count() as f32;
            }
            let p = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
            let r = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
            let f1 = if p + r > 0.0 {
                2.0 * p * r / (p + r)
            } else {
                0.0
            };
            println!(
                "entities{} — P {:.1}%  R {:.1}%  F1 {:.1}%  ({} items, {})",
                suffix,
                100.0 * p,
                100.0 * r,
                100.0 * f1,
                total,
                llm.model()
            );
        }
        "memories" => {
            // SQuAD-style token F1 with greedy one-to-one alignment: a
            // predicted memory matches a gold memory when their token F1 is
            // >= 0.5. Reported: match-level P/R/F1, mean token-F1 over
            // matched pairs, and type accuracy on matches.
            let mut match_tp = 0f32;
            let mut pred_total = 0f32;
            let mut gold_total = 0f32;
            let mut tokf1_sum = 0f32;
            let mut type_hits = 0f32;
            for item in data.iter().take(total) {
                let id = item.get("id").and_then(Value::as_str).context("item id")?;
                let text = item
                    .get("text")
                    .and_then(Value::as_str)
                    .context("item text")?;
                let gold: Vec<(String, String)> = label_by_id
                    .get(id)
                    .and_then(|l| l.get("memories"))
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|m| {
                                Some((
                                    m.get("type")?.as_str().unwrap_or("unknown").to_string(),
                                    m.get("content")?.as_str()?.to_string(),
                                ))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let pred: Vec<(String, String)> = llm
                    .extract_memories(text)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .into_iter()
                    .map(|m| (m.memory_type, m.content))
                    .collect();
                pred_total += pred.len() as f32;
                gold_total += gold.len() as f32;
                for (p_idx, g_idx, f1) in greedy_align(&pred, &gold, 0.5) {
                    match_tp += 1.0;
                    tokf1_sum += f1;
                    if pred[p_idx].0.eq_ignore_ascii_case(&gold[g_idx].0) {
                        type_hits += 1.0;
                    }
                }
            }
            let p = if pred_total > 0.0 {
                match_tp / pred_total
            } else {
                0.0
            };
            let r = if gold_total > 0.0 {
                match_tp / gold_total
            } else {
                0.0
            };
            let f1 = if p + r > 0.0 {
                2.0 * p * r / (p + r)
            } else {
                0.0
            };
            println!(
                "memories{} — match P {:.1}%  R {:.1}%  F1 {:.1}%  | mean token-F1 {:.2}  \
                 type-acc {:.1}%  ({} items, {})",
                suffix,
                100.0 * p,
                100.0 * r,
                100.0 * f1,
                if match_tp > 0.0 {
                    tokf1_sum / match_tp
                } else {
                    0.0
                },
                if match_tp > 0.0 {
                    100.0 * type_hits / match_tp
                } else {
                    0.0
                },
                total,
                llm.model()
            );
        }
        _ => unreachable!(),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LoCoMo / ConvoMem / MemBench adapters — same protocol as the upstream
// harnesses (session/message/turn-level evidence recall)
// ---------------------------------------------------------------------------

/// LoCoMo: one item = a conversation with `session_N` dialog arrays and QA
/// pairs whose evidence is dialog ids like "D3:12" (session 3). Session-
/// granularity retrieval: rank sessions, score R@k against evidence
/// sessions. Returns (recall_sum, evaluated, per_category).
/// Per-category (recall_sum, count) accumulator.
type CategoryScores = std::collections::BTreeMap<String, (f32, u32)>;

/// Wall-clock split between the two dominant bench phases. Rerank (when
/// enabled) runs inside `store.search`, so it is folded into `search_secs`;
/// query/passage embedding likewise sits inside its owning phase. The point
/// is to *measure* the ingest⋈search split instead of inferring it.
#[derive(Default, Clone, Copy)]
struct PhaseTiming {
    ingest_secs: f32,
    search_secs: f32,
}

/// The native row for the head-to-head harness: the same
/// store-per-conversation, room-per-session shape as [`locomo_eval`],
/// expressed through the [`vs::MemorySystem`] trait so every system runs
/// the identical loop. Sealed level, embedder from `UNDERCROFT_EMBEDDER`
/// exactly like the standalone LoCoMo row — the default hash embedder is
/// the "fully sealed, zero external calls" column.
struct NativeSystem {
    store: Option<(tempfile::TempDir, PalaceStore)>,
    chunk_idx: u32,
}

impl vs::MemorySystem for NativeSystem {
    fn name(&self) -> &str {
        "undercroft"
    }

    fn begin_conversation(&mut self, _convo: usize) -> Result<()> {
        self.store = Some(fresh_store(SecurityLevel::Sealed)?);
        self.chunk_idx = 0;
        Ok(())
    }

    fn add(&mut self, session: &str, text: &str) -> Result<()> {
        let (_, store) = self.store.as_mut().context("no conversation open")?;
        let d = Drawer::new(
            "locomo",
            session,
            text.into(),
            None,
            self.chunk_idx,
            "bench",
        );
        self.chunk_idx += 1;
        store.upsert(&d)?;
        Ok(())
    }

    fn search_sessions(&mut self, question: &str, k: usize) -> Result<Vec<String>> {
        let (_, store) = self.store.as_mut().context("no conversation open")?;
        let opts = SearchOptions {
            morph_lang: Default::default(),
            wing: None,
            room: None,
            limit: k * 6,
            room_cap: None,
            ..Default::default()
        };
        let hits = store.search(question, &opts)?;
        let mut rooms: Vec<String> = Vec::new();
        for h in &hits {
            if !rooms.contains(&h.drawer.meta.room) {
                rooms.push(h.drawer.meta.room.clone());
            }
        }
        Ok(rooms)
    }
}

/// One LoCoMo dialogue turn as it is ingested.
///
/// LoCoMo is a **multimodal** corpus: 1,226 of its 5,882 turns carry a
/// `blip_caption` describing an image the speaker shared, and 1,064 of the
/// 2,806 gold-evidence turn references — **37.9%** — point at one of them.
/// Formatting only `speaker` and `text` stored those turns incomplete and then
/// scored retrieval on its failure to find them, which books a corpus defect
/// as a memory failure. The caption is how a text-only memory sees the image,
/// so omitting it is not a modality choice, it is dropping content.
///
/// `query` and `img_url` stay out deliberately: they are the dataset's own
/// scaffolding for sourcing the image, not anything a participant said or saw.
fn locomo_turn_text(d: &Value) -> Option<String> {
    let speaker = d.get("speaker").and_then(Value::as_str).unwrap_or("?");
    let said = d.get("text").and_then(Value::as_str)?;
    let mut line = format!("{speaker} said, \"{said}\"");
    if let Some(cap) = d.get("blip_caption").and_then(Value::as_str) {
        let cap = cap.trim();
        if !cap.is_empty() {
            line.push_str(" [shared an image: ");
            line.push_str(cap);
            line.push(']');
        }
    }
    Some(line)
}

/// A byte range inside one session's normalized body.
type Span = (usize, usize);

/// Merge overlapping or touching spans into disjoint intervals, ascending.
fn merge_spans(mut v: Vec<Span>) -> Vec<Span> {
    v.sort_unstable();
    let mut out: Vec<Span> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// Bytes of `spans` that `have` does not already cover. `have` must be sorted
/// and disjoint (i.e. straight out of [`merge_spans`]).
///
/// This is what a slot *actually costs the reader*: two adjacent 800-byte
/// windows overlap by 100, so the second one delivers 700 bytes of new text
/// and 100 bytes the reader already has. Charging both at 800 is what makes a
/// slot-counted budget lie about how much evidence fits.
fn marginal_bytes(have: &[Span], spans: &[Span]) -> usize {
    let mut total = 0usize;
    for &(s, e) in spans {
        let mut cur = s;
        for &(hs, he) in have {
            if he <= cur {
                continue;
            }
            if hs >= e {
                break;
            }
            if hs > cur {
                total += hs.min(e) - cur;
            }
            cur = cur.max(he);
            if cur >= e {
                break;
            }
        }
        if cur < e {
            total += e - cur;
        }
    }
    total
}

/// Select hits in score order until `budget` bytes of *new* text are spent,
/// charging each hit only for what it adds beyond what is already selected.
///
/// This is the honest frame for comparing selections: a reader has a context
/// budget, not a slot count. Holding bytes fixed means a change cannot win by
/// simply returning more text — the k=30 mistake — and it lets selections with
/// different chunk sizes compete on equal terms.
fn select_within_budget(
    hits: &[SearchHit],
    chunk_span: &std::collections::HashMap<String, Vec<Span>>,
    budget: usize,
) -> Vec<usize> {
    let mut per_room: std::collections::HashMap<&str, Vec<Span>> = Default::default();
    let mut spent = 0usize;
    let mut picked: Vec<usize> = Vec::new();
    for (i, h) in hits.iter().enumerate() {
        let Some(spans) = chunk_span.get(&h.drawer.id) else {
            continue;
        };
        let room = h.drawer.meta.room.as_str();
        let have = per_room.entry(room).or_default();
        let add = marginal_bytes(have, spans);
        // Adds nothing the reader does not already have: pure redundancy, and
        // the only thing a dedup step can remove without losing evidence.
        if add == 0 {
            continue;
        }
        if spent + add > budget {
            continue;
        }
        spent += add;
        have.extend(spans.iter().copied());
        let merged = merge_spans(std::mem::take(have));
        *have = merged;
        picked.push(i);
    }
    picked
}

/// Smallest prefix of the ranked hits whose union covers **every** gold turn,
/// or `None` if the whole candidate list never does.
///
/// This is the ceiling diagnostic, and it separates the two failures that
/// look identical from the top-k: evidence that was *retrieved and ranked*
/// but sat below the cut, versus evidence the matcher never surfaced at any
/// depth. The first is recoverable by a better second stage over the same
/// candidates; the second is the first-stage matcher's floor and no amount of
/// reranking reaches it.
fn rank_covering_all(
    hits: &[SearchHit],
    chunk_span: &std::collections::HashMap<String, Vec<Span>>,
    wanted: &[(&str, Span)],
) -> Option<usize> {
    let mut per_room: std::collections::HashMap<&str, Vec<Span>> = Default::default();
    for (i, h) in hits.iter().enumerate() {
        if let Some(spans) = chunk_span.get(&h.drawer.id) {
            let have = per_room.entry(h.drawer.meta.room.as_str()).or_default();
            have.extend(spans.iter().copied());
            let merged = merge_spans(std::mem::take(have));
            *have = merged;
        }
        let all = wanted
            .iter()
            .all(|(room, sp)| per_room.get(room).is_some_and(|m| covers(m, *sp)));
        if all {
            return Some(i + 1);
        }
    }
    None
}

/// Depths at which the ceiling diagnostic is bucketed.
const RANK_BUCKETS: [usize; 5] = [10, 20, 40, 80, 160];

/// Whether `needle` sits wholly inside one of the merged intervals.
///
/// The union, rather than any single chunk, is what a prompt actually shows:
/// ingest windows an 800-byte chunk with 100 bytes of overlap over a session
/// body that is one long paragraph, so a turn lands across a boundary
/// routinely, and the two chunks either side *together* carry the evidence.
/// Asking each chunk alone would book that as a retrieval miss the reader
/// never suffered — the exact class of error this instrument exists to stop.
fn covers(merged: &[Span], needle: Span) -> bool {
    merged.iter().any(|&(s, e)| s <= needle.0 && needle.1 <= e)
}

/// Byte ranges of `chunk` inside `body`, scanning forward from `cursor`.
///
/// `chunk_text` emits verbatim slices of the body in order, so a rolling scan
/// is exact and cheap. The cursor advances to each chunk's *start*, not its
/// end, because consecutive windows overlap. The one chunk that is not a
/// single slice is the trailing runt, which `chunk_text` merges into its
/// predecessor with a `\n\n` join — hence pieces, and hence a `Vec`.
fn locate_chunk(body: &str, chunk: &str, cursor: &mut usize) -> Vec<Span> {
    let mut out = Vec::new();
    for piece in chunk.split("\n\n") {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let from = (*cursor).min(body.len());
        if let Some(rel) = body[from..].find(piece) {
            let s = from + rel;
            out.push((s, s + piece.len()));
            *cursor = s;
        }
    }
    out
}

/// How many of `wanted` gold turns the selected slots actually put in front
/// of a reader, testing each turn against the union of that session's
/// selected chunk ranges.
fn covered_turns(
    selected: &[&SearchHit],
    chunk_span: &std::collections::HashMap<String, Vec<Span>>,
    wanted: &[(&str, Span)],
) -> usize {
    let mut by_room: std::collections::HashMap<&str, Vec<Span>> = Default::default();
    for h in selected {
        if let Some(spans) = chunk_span.get(&h.drawer.id) {
            by_room
                .entry(h.drawer.meta.room.as_str())
                .or_default()
                .extend(spans.iter().copied());
        }
    }
    let merged: std::collections::HashMap<&str, Vec<Span>> = by_room
        .into_iter()
        .map(|(r, v)| (r, merge_spans(v)))
        .collect();
    wanted
        .iter()
        .filter(|(room, sp)| merged.get(room).is_some_and(|m| covers(m, *sp)))
        .count()
}

/// Per-document caps the gap-2 counterfactual is measured at. `1` is the
/// strongest form of "one slot per document"; `2` is the softest cap that
/// still removes anything, so a negative result covers the family rather
/// than only its extreme.
const DOC_CAPS: [usize; 2] = [1, 2];

/// Indices of a selection over `hits` that allows at most `cap` slots per
/// source document, capped at `k` and refilled in score order — the same
/// soft-cap-then-refill shape `diversify_by_room` gives `room_cap`.
fn cap_per_document(hits: &[SearchHit], k: usize, cap: usize) -> Vec<usize> {
    let mut seen: std::collections::BTreeMap<&str, usize> = Default::default();
    let mut picked: Vec<usize> = Vec::new();
    for (i, h) in hits.iter().enumerate() {
        if picked.len() == k {
            break;
        }
        let n = seen.entry(h.drawer.meta.room.as_str()).or_insert(0);
        if *n < cap {
            *n += 1;
            picked.push(i);
        }
    }
    if picked.len() < k {
        let taken: std::collections::BTreeSet<usize> = picked.iter().copied().collect();
        for i in 0..hits.len() {
            if picked.len() == k {
                break;
            }
            if !taken.contains(&i) {
                picked.push(i);
            }
        }
    }
    picked.sort_unstable();
    picked
}

/// Gold-evidence recall at two granularities, plus the one-slot-per-document
/// counterfactual.
///
/// The row this harness has always printed is `session_any`: at least one gold
/// *session* somewhere in the top-k rooms. It cannot tell a memory failure
/// from a reader failure, and it is blind to chunk choice — every gold turn
/// can be absent from the prompt while the number reads 100%, because the
/// session is "present" on the strength of a chunk that says nothing relevant.
/// That blindness is not hypothetical: `room_cap` was adopted on document
/// presence and measured −5.6pp, and the post-mortem was that the right
/// *chunk* must be present, not the right document.
///
/// The AMB run measured 83.0% all-gold / 94.1% any-gold at session
/// granularity against 87.6% end-to-end accuracy — 104 of 189 failures had
/// every required document in context. These fields make that split standing
/// and reproducible, and they cost no model calls: the evidence ids ship with
/// the dataset.
#[derive(Default, Clone, Copy)]
struct GoldRecall {
    /// Queries scored at session granularity (the historical denominator).
    queries: u32,
    /// ≥1 / every gold session among the top-k distinct rooms, where those
    /// rooms are collected by scanning the **whole** `k*6` candidate pool.
    /// This is the row the harness has always printed.
    session_any: f32,
    session_all: f32,
    /// The same two over the rooms present in the `k` slots actually
    /// returned — the depth the turn rows are scored at.
    ///
    /// Without these, comparing the pool-depth session row against the
    /// slot-depth turn row measures **depth and granularity at once**: a room
    /// first appearing at hit 47 counts for the former and cannot count for
    /// the latter, so part of any gap between them is simply one row looking
    /// six times deeper. These two isolate granularity.
    slot_session_any: f32,
    slot_session_all: f32,
    /// ≥1 / every gold *turn* inside the top-k slots actually returned.
    turn_any: f32,
    turn_all: f32,
    /// The same two under `cap_per_document`, one entry per [`DOC_CAPS`] —
    /// what ROADMAP gap 2 would do to the very prompt the reader sees.
    /// Measured, not assumed.
    dedup_turn_any: [f32; DOC_CAPS.len()],
    dedup_turn_all: [f32; DOC_CAPS.len()],
    /// Slots filled by a document already represented, over slots returned.
    /// This is the "14% of slots are repeat chunks" figure, re-derived.
    repeat_slots: u32,
    slots: u32,
    /// The repeat slots split by whether they are actually redundant. A repeat
    /// slot whose span **touches or overlaps** one already selected from the
    /// same document duplicates text the reader has (`repeat_adjacent`); one
    /// that is disjoint carries different sentences of the same document and
    /// is not redundant at all (`repeat_disjoint`). The per-document cap
    /// deleted both indiscriminately, which is why it lost evidence — and this
    /// split says how much genuine redundancy there was to remove.
    repeat_adjacent: u32,
    repeat_disjoint: u32,
    /// Bytes the reader is handed **twice**, over bytes handed to them at
    /// all, across the k slots.
    ///
    /// The slot counts above say how many slots *touch* text already
    /// returned; this says how much text that actually is. They are very
    /// different questions: two adjacent 800-byte windows overlap by 100, so
    /// the slot reads as "redundant" while 87.5% of it is new. Only this
    /// ratio bounds what a dedup step could ever recover.
    dup_bytes: u64,
    slot_bytes: u64,
    /// How deep the ranked list must go before every gold turn is covered,
    /// bucketed by [`RANK_BUCKETS`] with a final bucket for "never, at any
    /// depth in the pool".
    ///
    /// The first bucket is what we deliver today. Everything between it and
    /// the last bucket is evidence the matcher *found and ranked* but placed
    /// below the cut — the headroom a second stage can reach without a better
    /// first stage. The last bucket is the first-stage floor.
    gold_all_rank: [u32; 7],
    /// Turn coverage under [`select_within_budget`] — same bytes to the
    /// reader, redundancy charged once, slot count free to vary.
    budget_turn_any: f32,
    budget_turn_all: f32,
    /// Chunks that fit in the budget, summed, so the mean is reportable.
    budget_slots: u32,
    /// Gold turns whose text could not be located in the ingested body, and
    /// the queries that lost *every* gold turn that way and are therefore
    /// excluded from the turn rows. Reported rather than absorbed: a silent
    /// drop here would flatter exactly the numbers it touches.
    unlocatable_turns: u32,
    /// Denominator for the turn-level rows.
    turn_queries: u32,
    /// Turn-level all-gold, split by how many gold turns the query needs
    /// (1, 2, 3, 4, 5+) and by LoCoMo category. `.0` is the numerator,
    /// `.1` the denominator.
    ///
    /// This decides whether the remaining failures are a *ranking* problem or
    /// a *budget* one. A query needing one turn that misses is a scoring
    /// failure and more ranking work can reach it. A query needing six turns
    /// spread over four sessions is competing for ten slots, and no reordering
    /// fixes arithmetic — only more slots or more bytes do.
    by_goldcount: [(f32, u32); 5],
    by_category: [(f32, u32); 6],
    /// The same split for the ≤2-per-document cap and for byte-budget
    /// selection.
    ///
    /// The cap measured −17.5pp / −1.8pp *averaged over the corpus*, which is
    /// 79% single-evidence questions where forcing a second document can only
    /// displace the one right chunk. Multi-evidence questions need 2.68
    /// distinct sessions, which is what a cap forces. An average over two
    /// populations with opposite responses says nothing about either.
    by_goldcount_cap2: [(f32, u32); 5],
    by_goldcount_budget: [(f32, u32); 5],
    /// R3 paging-contract tallies (populated only under `--paging-contract`):
    /// queries checked, exact-tiling mismatches (four pinned pages of ten vs
    /// one pinned call of forty — ids and order), all-gold delivered by
    /// those four pages, and unpinned repeats that differed from the pinned
    /// ranking (the documented host-clock recency drift).
    page_queries: u32,
    page_mismatches: u32,
    page_all: f32,
    page_unpinned_drift: u32,
}

#[allow(clippy::too_many_arguments)]
fn locomo_eval(
    samples: &[Value],
    k: usize,
    backend: &str,
    chunk_size: usize,
    budget: usize,
    pool: usize,
    turn_units: bool,
    paging: bool,
) -> Result<(f32, u32, CategoryScores, PhaseTiming, GoldRecall)> {
    let mut recall_sum = 0f32;
    let mut evaluated = 0u32;
    let mut per_cat: CategoryScores = Default::default();
    let mut timing = PhaseTiming::default();
    let mut gold = GoldRecall::default();
    let total = samples.len();
    // Optional remote ANN accelerator. `local` ⇒ full-scan fusion path.
    let mut index = match backend {
        "local" => None,
        other => Some(undercroft_index::from_env(other)?),
    };
    for (si, sample) in samples.iter().enumerate() {
        let conv = sample
            .get("conversation")
            .context("sample missing conversation")?;
        // One collection per conversation in remote mode (collection name
        // derives from the vault id), so convos don't share vectors.
        let (_tmp, mut store) = if index.is_some() {
            fresh_store_id(SecurityLevel::Sealed, &format!("benchc{si}"))?
        } else {
            fresh_store(SecurityLevel::Sealed)?
        };
        // Ingest: one room per session.
        //
        // Alongside it, two maps that make turn-level gold recall possible:
        // where each dialog turn sits in its session body, and which of that
        // body each stored chunk covers. Both are byte ranges over the same
        // normalized string, so "was this turn in the prompt" becomes an
        // interval test rather than a substring guess.
        let ingest_started = Instant::now();
        let mut n = 1;
        let mut turn_span: std::collections::HashMap<String, (String, Span)> = Default::default();
        let mut chunk_span: std::collections::HashMap<String, Vec<Span>> = Default::default();
        while let Some(dialogs) = conv.get(format!("session_{n}")).and_then(Value::as_array) {
            let room = format!("session_{n}");
            let turns: Vec<(String, String)> = dialogs
                .iter()
                .filter_map(|d| {
                    let line = locomo_turn_text(d)?;
                    let id = d
                        .get("dia_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    Some((id, line))
                })
                .collect();
            let text: Vec<String> = turns.iter().map(|(_, l)| l.clone()).collect();
            let body = undercroft_core::normalize_content(&text.join("\n"));
            // Locate every turn in the body it was ingested into. The scan
            // rolls forward because turns keep their order; a turn that
            // normalization reshaped is simply not recorded, and the query
            // loop counts that rather than treating it as a miss.
            let mut tcur = 0usize;
            for (id, line) in &turns {
                if id.is_empty() {
                    continue;
                }
                let probe = undercroft_core::normalize_content(line);
                let probe = probe.trim();
                if probe.is_empty() {
                    continue;
                }
                let from = tcur.min(body.len());
                if let Some(rel) = body[from..].find(probe) {
                    let s = from + rel;
                    turn_span.insert(id.clone(), (room.clone(), (s, s + probe.len())));
                    tcur = s + probe.len();
                }
            }
            let mut ccur = 0usize;
            let copts = undercroft_core::ChunkOptions {
                chunk_size,
                ..Default::default()
            };
            // Same bytes either way — only where the cuts fall differs.
            let pieces: Vec<String> = if turn_units {
                turns
                    .iter()
                    .map(|(_, l)| undercroft_core::normalize_content(l))
                    .filter(|s| !s.trim().is_empty())
                    .collect()
            } else {
                undercroft_core::chunk_text(&body, copts)
            };
            for (ci, chunk) in pieces.into_iter().enumerate() {
                let spans = locate_chunk(&body, &chunk, &mut ccur);
                let d = Drawer::new("locomo", &room, chunk, None, ci as u32, "bench");
                chunk_span.insert(d.id.clone(), spans);
                store.upsert(&d)?;
            }
            n += 1;
        }
        // In remote mode, publishing to the ANN index is part of ingest.
        if let Some(idx) = index.as_mut() {
            store.index_push(idx.as_mut())?;
        }
        timing.ingest_secs += ingest_started.elapsed().as_secs_f32();
        let qa_pairs = sample
            .get("qa")
            .and_then(Value::as_array)
            .context("sample missing qa")?;
        for qa in qa_pairs.iter() {
            let question = qa
                .get("question")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let evidence: Vec<String> = qa
                .get("evidence")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if question.is_empty() || evidence.is_empty() {
                continue; // adversarial category has no evidence
            }
            // "D3:12" → session_3
            let correct: std::collections::BTreeSet<String> = evidence
                .iter()
                .filter_map(|e| {
                    let s = e.trim_start_matches('D');
                    let sess = s.split(':').next()?;
                    Some(format!("session_{sess}"))
                })
                .collect();
            let opts = SearchOptions {
                morph_lang: Default::default(),
                wing: None,
                room: None,
                limit: if pool > 0 { pool } else { k * 6 },
                room_cap: None,
                ..Default::default()
            };
            let search_started = Instant::now();
            let hits = match index.as_mut() {
                Some(idx) => store.search_with_index(idx.as_mut(), question, &opts)?,
                None => store.search(question, &opts)?,
            };
            timing.search_secs += search_started.elapsed().as_secs_f32();
            let mut rooms: Vec<String> = Vec::new();
            for h in &hits {
                if !rooms.contains(&h.drawer.meta.room) {
                    rooms.push(h.drawer.meta.room.clone());
                }
            }
            let topk: Vec<&String> = rooms.iter().take(k).collect();
            let recall = if correct.iter().any(|c| topk.contains(&c)) {
                1.0
            } else {
                0.0
            };
            recall_sum += recall;
            evaluated += 1;

            // ---- gold-evidence recall: no model calls, ids ship with the
            // dataset. The session rows restate what the line above scored;
            // the turn rows say whether the evidence itself was in the
            // prompt, which is the only one of the two a reader can use.
            gold.queries += 1;
            gold.session_any += recall;
            if correct.iter().all(|c| topk.contains(&c)) {
                gold.session_all += 1.0;
            }
            let slots: Vec<&SearchHit> = hits.iter().take(k).collect();
            let mut slot_rooms: Vec<&str> = Vec::new();
            // Per document, the spans already handed to the reader — so a
            // repeat slot can be classified as duplicating text or as adding
            // different text from the same document.
            let mut seen_spans: std::collections::HashMap<&str, Vec<Span>> = Default::default();
            for h in &slots {
                gold.slots += 1;
                let room = h.drawer.meta.room.as_str();
                let spans = chunk_span.get(&h.drawer.id).cloned().unwrap_or_default();
                let full: usize = spans.iter().map(|(s, e)| e - s).sum();
                let fresh = marginal_bytes(seen_spans.entry(room).or_default(), &spans);
                gold.slot_bytes += full as u64;
                gold.dup_bytes += (full - fresh) as u64;
                if slot_rooms.contains(&room) {
                    gold.repeat_slots += 1;
                    if fresh < full {
                        gold.repeat_adjacent += 1;
                    } else {
                        gold.repeat_disjoint += 1;
                    }
                } else {
                    slot_rooms.push(room);
                }
                let have = seen_spans.entry(room).or_default();
                have.extend(spans);
                let merged = merge_spans(std::mem::take(have));
                *have = merged;
            }
            // Session presence at the depth the turn rows are scored at.
            if correct.iter().any(|c| slot_rooms.contains(&c.as_str())) {
                gold.slot_session_any += 1.0;
            }
            if correct.iter().all(|c| slot_rooms.contains(&c.as_str())) {
                gold.slot_session_all += 1.0;
            }
            let mut wanted: Vec<(&str, Span)> = Vec::new();
            for e in &evidence {
                match turn_span.get(e.as_str()) {
                    Some((room, sp)) => wanted.push((room.as_str(), *sp)),
                    None => gold.unlocatable_turns += 1,
                }
            }
            if !wanted.is_empty() {
                gold.turn_queries += 1;
                // ---- R3 paging contract, asserted end to end. Pages are
                // defined as ranks [offset, offset+limit) of the one ranking
                // a single deeper call would produce, with `ranked_at`
                // pinning the clock — so four pinned pages of ten must tile
                // one pinned call of forty exactly, and the all-gold they
                // deliver must equal what the depth CDF says sits within
                // top-40. An unpinned repeat is run purely to record what
                // the host clock actually drifts.
                if paging {
                    gold.page_queries += 1;
                    let pinned = time::OffsetDateTime::now_utc();
                    let popts = |offset: usize, limit: usize, at: Option<time::OffsetDateTime>| {
                        SearchOptions {
                            limit,
                            offset,
                            ranked_at: at,
                            ..Default::default()
                        }
                    };
                    fn same_ids(a: &[SearchHit], b: &[SearchHit]) -> bool {
                        a.len() == b.len()
                            && a.iter()
                                .zip(b.iter())
                                .all(|(x, y)| x.drawer.id == y.drawer.id)
                    }
                    let single = store.search(question, &popts(0, 40, Some(pinned)))?;
                    let mut paged: Vec<SearchHit> = Vec::new();
                    for page in 0..4 {
                        paged.extend(store.search(question, &popts(page * 10, 10, Some(pinned)))?);
                    }
                    if !same_ids(&single, &paged) {
                        gold.page_mismatches += 1;
                    }
                    let prefs: Vec<&SearchHit> = paged.iter().collect();
                    if covered_turns(&prefs, &chunk_span, &wanted) == wanted.len() {
                        gold.page_all += 1.0;
                    }
                    let mut unpinned: Vec<SearchHit> = Vec::new();
                    for page in 0..4 {
                        unpinned.extend(store.search(question, &popts(page * 10, 10, None))?);
                    }
                    if !same_ids(&unpinned, &paged) {
                        gold.page_unpinned_drift += 1;
                    }
                }
                let got = covered_turns(&slots, &chunk_span, &wanted);
                if got > 0 {
                    gold.turn_any += 1.0;
                }
                let delivered = if got == wanted.len() {
                    gold.turn_all += 1.0;
                    1.0
                } else {
                    0.0
                };
                let gc = (wanted.len().clamp(1, 5)) - 1;
                gold.by_goldcount[gc].0 += delivered;
                gold.by_goldcount[gc].1 += 1;
                let cat = qa
                    .get("category")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .min(5) as usize;
                gold.by_category[cat].0 += delivered;
                gold.by_category[cat].1 += 1;
                // The gap-2 counterfactual, over the same retrieval: at most
                // `cap` slots per document, refilled in score order. Same k,
                // same pool, so any difference is the cap and nothing else.
                // How deep the ranked list must go before all gold is in hand.
                match rank_covering_all(&hits, &chunk_span, &wanted) {
                    Some(r) => {
                        let b = RANK_BUCKETS
                            .iter()
                            .position(|&t| r <= t)
                            .unwrap_or(RANK_BUCKETS.len());
                        gold.gold_all_rank[b] += 1;
                    }
                    // Deeper than the last bucket, but still found: still
                    // second-stage headroom, not a first-stage floor.
                    None => gold.gold_all_rank[RANK_BUCKETS.len() + 1] += 1,
                }
                // Same bytes to the reader, redundancy charged once, slot
                // count free to vary. This is the comparison a per-document
                // cap should have been measured against: it removes only text
                // the reader already has, and spends what it saves.
                let budget_sel: Vec<&SearchHit> = select_within_budget(&hits, &chunk_span, budget)
                    .into_iter()
                    .map(|i| &hits[i])
                    .collect();
                gold.budget_slots += budget_sel.len() as u32;
                let bgot = covered_turns(&budget_sel, &chunk_span, &wanted);
                if bgot > 0 {
                    gold.budget_turn_any += 1.0;
                }
                let gcb = (wanted.len().clamp(1, 5)) - 1;
                gold.by_goldcount_budget[gcb].1 += 1;
                if bgot == wanted.len() {
                    gold.budget_turn_all += 1.0;
                    gold.by_goldcount_budget[gcb].0 += 1.0;
                }
                for (ci, cap) in DOC_CAPS.iter().enumerate() {
                    let dedup: Vec<&SearchHit> = cap_per_document(&hits, k, *cap)
                        .into_iter()
                        .map(|i| &hits[i])
                        .collect();
                    let dgot = covered_turns(&dedup, &chunk_span, &wanted);
                    if dgot > 0 {
                        gold.dedup_turn_any[ci] += 1.0;
                    }
                    if dgot == wanted.len() {
                        gold.dedup_turn_all[ci] += 1.0;
                    }
                    if *cap == 2 {
                        let g2 = (wanted.len().clamp(1, 5)) - 1;
                        gold.by_goldcount_cap2[g2].1 += 1;
                        if dgot == wanted.len() {
                            gold.by_goldcount_cap2[g2].0 += 1.0;
                        }
                    }
                }
            }

            let cat = qa
                .get("category")
                .map(|c| c.to_string().trim_matches('"').to_string())
                .unwrap_or_else(|| "?".into());
            let e = per_cat.entry(cat).or_insert((0.0, 0));
            e.0 += recall;
            e.1 += 1;
        }
        eprintln!(
            "  convo {}/{total} done — {evaluated} q, R@{k} so far: {:.1}%",
            si + 1,
            100.0 * recall_sum / evaluated.max(1) as f32
        );
    }
    Ok((recall_sum, evaluated, per_cat, timing, gold))
}

/// One session-recall pass over a conversation's QA against the current
/// store contents (identical scoring to [`locomo_eval`]): returns
/// (recall_sum, evaluated). `wing` scopes retrieval: `None` searches
/// everything, `Some("locomo")` verbatim-only, `Some("facts")`
/// distilled-only — the three passes that separate verbatim from KG.
fn score_pass(
    store: &mut PalaceStore,
    qa_pairs: &[Value],
    k: usize,
    qa_limit: usize,
    wing: Option<&str>,
) -> Result<(f32, u32)> {
    let mut recall_sum = 0f32;
    let mut evaluated = 0u32;
    let mut asked = 0usize;
    for qa in qa_pairs {
        if qa_limit > 0 && asked >= qa_limit {
            break;
        }
        let question = qa
            .get("question")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let evidence: Vec<String> = qa
            .get("evidence")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if question.is_empty() || evidence.is_empty() {
            continue;
        }
        let correct: std::collections::BTreeSet<String> = evidence
            .iter()
            .filter_map(|e| {
                let s = e.trim_start_matches('D');
                let sess = s.split(':').next()?;
                Some(format!("session_{sess}"))
            })
            .collect();
        let hits = store.search(
            question,
            &SearchOptions {
                morph_lang: Default::default(),
                wing: wing.map(str::to_string),
                room: None,
                limit: k * 6,
                room_cap: None,
                ..Default::default()
            },
        )?;
        let mut rooms: Vec<String> = Vec::new();
        for h in &hits {
            if !rooms.contains(&h.drawer.meta.room) {
                rooms.push(h.drawer.meta.room.clone());
            }
        }
        let topk: Vec<&String> = rooms.iter().take(k).collect();
        if correct.iter().any(|c| topk.contains(&c)) {
            recall_sum += 1.0;
        }
        evaluated += 1;
        asked += 1;
    }
    Ok((recall_sum, evaluated))
}

/// C3.1 ship-gate. Per conversation: ingest verbatim (one room per
/// session) → score baseline → distill each drawer's durable facts through
/// the configured LLM, storing each as a *receipted* KG fact **and** as a
/// searchable fact-drawer filed into its source session's room → score
/// augmented over the same retrieval. The gate: augmented must beat
/// baseline for the distillation tier to ship as a recall feature; either
/// way the receipts are verified end-to-end.
fn distill_eval(samples: &[Value], k: usize, qa_limit: usize) -> Result<()> {
    let llm = undercroft_llm::LlmClient::from_env()
        .map_err(|e| anyhow::anyhow!("distill gate needs a local LLM (UNDERCROFT_LLM_URL): {e}"))?;
    let model = llm.model().to_string();
    let (mut base_sum, mut dist_sum, mut aug_sum) = (0f32, 0f32, 0f32);
    let (mut evaluated, mut facts_total, mut verified_total) = (0u32, 0u32, 0u32);
    let mut distill_secs = 0f32;
    let total = samples.len();
    for (si, sample) in samples.iter().enumerate() {
        let conv = sample
            .get("conversation")
            .context("sample missing conversation")?;
        let (_tmp, mut store) = fresh_store(SecurityLevel::Sealed)?;
        let mut n = 1;
        while let Some(dialogs) = conv.get(format!("session_{n}")).and_then(Value::as_array) {
            let text: Vec<String> = dialogs
                .iter()
                .filter_map(|d| {
                    Some(format!(
                        "{} said, \"{}\"",
                        d.get("speaker").and_then(Value::as_str).unwrap_or("?"),
                        d.get("text").and_then(Value::as_str)?
                    ))
                })
                .collect();
            let body = undercroft_core::normalize_content(&text.join("\n"));
            for (ci, chunk) in
                undercroft_core::chunk_text(&body, undercroft_core::ChunkOptions::default())
                    .into_iter()
                    .enumerate()
            {
                store.upsert(&Drawer::new(
                    "locomo",
                    &format!("session_{n}"),
                    chunk,
                    None,
                    ci as u32,
                    "bench",
                ))?;
            }
            n += 1;
        }
        let qa_pairs = sample
            .get("qa")
            .and_then(Value::as_array)
            .context("sample missing qa")?;

        // Baseline: verbatim retrieval only (nothing else in the store yet).
        let (b_rs, b_ev) = score_pass(&mut store, qa_pairs, k, qa_limit, None)?;

        // Distill: LLM facts → receipted KG fact + searchable fact-drawer in
        // the source session's room.
        let verbatim = store.recent(Some("locomo"), 1_000_000)?;
        let mut fact_idx = 0u32;
        let t0 = Instant::now();
        for d in &verbatim {
            match llm.extract_triples(&d.content) {
                Ok(triples) => {
                    for tri in triples {
                        let subj = tri.subject.to_lowercase();
                        let pred = tri.predicate.to_lowercase();
                        if undercroft_core::validate_name(&subj, "subject").is_err()
                            || undercroft_core::validate_name(&pred, "predicate").is_err()
                        {
                            continue;
                        }
                        store.kg_add_receipted(
                            &subj,
                            &pred,
                            &tri.object,
                            None,
                            None,
                            0.8,
                            (&d.id, &d.content),
                        )?;
                        store.upsert(&Drawer::new(
                            "facts",
                            &d.meta.room,
                            format!("{} {} {}", tri.subject, tri.predicate, tri.object),
                            None,
                            fact_idx,
                            "distill",
                        ))?;
                        fact_idx += 1;
                    }
                }
                Err(e) => eprintln!("  distill: triples failed for {}: {e}", d.id),
            }
        }
        distill_secs += t0.elapsed().as_secs_f32();
        facts_total += fact_idx;
        verified_total += store
            .kg_verify_receipts()?
            .iter()
            .filter(|r| matches!(r.verdict, undercroft_store::ReceiptVerdict::Verified))
            .count() as u32;

        // Distilled-only: retrieval restricted to the KG-fact surface —
        // what distillation achieves *without* the verbatim it was derived
        // from (the shape competitors ship, where extraction replaces text).
        let (d_rs, _d_ev) = score_pass(&mut store, qa_pairs, k, qa_limit, Some("facts"))?;

        // Augmented: verbatim + distilled facts together (no wing filter).
        let (a_rs, _a_ev) = score_pass(&mut store, qa_pairs, k, qa_limit, None)?;

        base_sum += b_rs;
        dist_sum += d_rs;
        aug_sum += a_rs;
        evaluated += b_ev;
        let ev = evaluated.max(1) as f32;
        eprintln!(
            "  [{model}] convo {}/{total} — verbatim {:.1}% distilled {:.1}% \
             verbatim+distilled {:.1}%, {fact_idx} facts",
            si + 1,
            100.0 * base_sum / ev,
            100.0 * dist_sum / ev,
            100.0 * aug_sum / ev,
        );
    }
    let ev = evaluated.max(1) as f32;
    println!(
        "DISTILL_RAW model={model} verbatim_sum={base_sum:.4} distilled_sum={dist_sum:.4} \
         augmented_sum={aug_sum:.4} evaluated={evaluated} facts={facts_total} \
         verified={verified_total} distill_secs={distill_secs:.1}"
    );
    println!(
        "DISTILL — {model} · verbatim R@{k} {:.1}% · distilled-only R@{k} {:.1}% · \
         verbatim+distilled R@{k} {:.1}% ({facts_total} facts, {verified_total} receipts \
         verified)",
        100.0 * base_sum / ev,
        100.0 * dist_sum / ev,
        100.0 * aug_sum / ev,
    );
    Ok(())
}

/// ConvoMem: one item = conversations of messages + `message_evidences`
/// (exact message texts). Message-granularity: one drawer per message;
/// recall = any evidence text among the top-k retrieved messages.
fn convomem_eval(items: &[Value], k: usize, limit: Option<usize>) -> Result<(f32, u32)> {
    let total = limit.unwrap_or(items.len()).min(items.len());
    let mut recall_sum = 0f32;
    let mut evaluated = 0u32;
    for item in items.iter().take(total) {
        let question = item
            .get("question")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let evidence: std::collections::BTreeSet<String> = item
            .get("message_evidences")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.get("text")?.as_str())
                    .map(|t| t.trim().to_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        if question.is_empty() || evidence.is_empty() {
            continue;
        }
        let (_tmp, mut store) = fresh_store(SecurityLevel::Sealed)?;
        let mut idx = 0u32;
        for (ci, conv) in item
            .get("conversations")
            .and_then(Value::as_array)
            .unwrap_or(&Vec::new())
            .iter()
            .enumerate()
        {
            for msg in conv
                .get("messages")
                .and_then(Value::as_array)
                .unwrap_or(&Vec::new())
            {
                let Some(text) = msg.get("text").and_then(Value::as_str) else {
                    continue;
                };
                let body = undercroft_core::normalize_content(text);
                if body.is_empty() {
                    continue;
                }
                let d = Drawer::new("convomem", &format!("c{ci}"), body, None, idx, "bench");
                store.upsert(&d)?;
                idx += 1;
            }
        }
        let hits = store.search(
            question,
            &SearchOptions {
                morph_lang: Default::default(),
                wing: None,
                room: None,
                limit: k,
                room_cap: None,
                ..Default::default()
            },
        )?;
        let recall = if hits
            .iter()
            .any(|h| evidence.contains(&h.drawer.content.trim().to_lowercase()))
        {
            1.0
        } else {
            0.0
        };
        recall_sum += recall;
        evaluated += 1;
    }
    Ok((recall_sum, evaluated))
}

/// MemBench: items with `message_list[0]` = turns `{user, assistant}` and
/// `QA.target_step_id` = indices of the answer-relevant turns. Turn-
/// granularity: one drawer per turn (chunk_index = step id); recall = any
/// target step among the top-k retrieved turns.
fn membench_eval(raw: &Value, topic: &str, k: usize, limit: Option<usize>) -> Result<(f32, u32)> {
    let mut items: Vec<&Value> = Vec::new();
    if let Some(obj) = raw.as_object() {
        for (t, topic_items) in obj {
            if t == topic || t == "roles" || t == "events" {
                if let Some(arr) = topic_items.as_array() {
                    items.extend(arr.iter());
                }
            }
        }
    }
    let total = limit.unwrap_or(items.len()).min(items.len());
    let mut recall_sum = 0f32;
    let mut evaluated = 0u32;
    for item in items.into_iter().take(total) {
        let turns = item
            .pointer("/message_list/0")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let qa = item.get("QA").cloned().unwrap_or_default();
        let question = qa
            .get("question")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let targets: std::collections::BTreeSet<u64> = qa
            .get("target_step_id")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();
        if turns.is_empty() || question.is_empty() || targets.is_empty() {
            continue;
        }
        let (_tmp, mut store) = fresh_store(SecurityLevel::Sealed)?;
        for (sid, turn) in turns.iter().enumerate() {
            let user = turn.get("user").and_then(Value::as_str).unwrap_or_default();
            let assistant = turn
                .get("assistant")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let body =
                undercroft_core::normalize_content(&format!("User: {user}\nAssistant: {assistant}"));
            if body.is_empty() {
                continue;
            }
            let d = Drawer::new("membench", "turns", body, None, sid as u32, "bench");
            store.upsert(&d)?;
        }
        let hits = store.search(
            question,
            &SearchOptions {
                morph_lang: Default::default(),
                wing: None,
                room: None,
                limit: k,
                room_cap: None,
                ..Default::default()
            },
        )?;
        let recall = if hits
            .iter()
            .any(|h| targets.contains(&(h.drawer.meta.chunk_index as u64)))
        {
            1.0
        } else {
            0.0
        };
        recall_sum += recall;
        evaluated += 1;
    }
    Ok((recall_sum, evaluated))
}

// ---------------------------------------------------------------------------
// Fuzzy-match scoring for memory extraction
// ---------------------------------------------------------------------------

/// Tokenize for F1: CJK codepoints become single-character tokens (Chinese
/// and friends have no spaces to split on); everything else splits into
/// lowercase alphanumeric words.
fn f1_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut Vec<String>| {
        if !word.is_empty() {
            out.push(std::mem::take(word));
        }
    };
    for c in text.chars() {
        let is_cjk = matches!(c as u32,
            0x4E00..=0x9FFF | 0x3400..=0x4DBF | 0x3040..=0x30FF | 0xAC00..=0xD7AF);
        if is_cjk {
            flush(&mut word, &mut out);
            out.push(c.to_string());
        } else if c.is_alphanumeric() {
            word.extend(c.to_lowercase());
        } else {
            flush(&mut word, &mut out);
        }
    }
    flush(&mut word, &mut out);
    out
}

/// SQuAD-style token F1 between two strings.
fn token_f1(a: &str, b: &str) -> f32 {
    let ta = f1_tokens(a);
    let tb = f1_tokens(b);
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<&str, i32> = Default::default();
    for t in &ta {
        *counts.entry(t.as_str()).or_insert(0) += 1;
    }
    let mut overlap = 0f32;
    for t in &tb {
        if let Some(c) = counts.get_mut(t.as_str()) {
            if *c > 0 {
                *c -= 1;
                overlap += 1.0;
            }
        }
    }
    if overlap == 0.0 {
        return 0.0;
    }
    let p = overlap / tb.len() as f32;
    let r = overlap / ta.len() as f32;
    2.0 * p * r / (p + r)
}

/// A matched (pred_idx, gold_idx, token_f1) alignment pair.
type AlignedPair = (usize, usize, f32);

/// Greedy one-to-one alignment of predictions to gold by descending token
/// F1; pairs below `threshold` never match.
fn greedy_align(
    pred: &[(String, String)],
    gold: &[(String, String)],
    threshold: f32,
) -> Vec<AlignedPair> {
    let mut scored: Vec<(usize, usize, f32)> = Vec::new();
    for (pi, p) in pred.iter().enumerate() {
        for (gi, g) in gold.iter().enumerate() {
            let f1 = token_f1(&p.1, &g.1);
            if f1 >= threshold {
                scored.push((pi, gi, f1));
            }
        }
    }
    scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    let mut used_p = vec![false; pred.len()];
    let mut used_g = vec![false; gold.len()];
    let mut out = Vec::new();
    for (pi, gi, f1) in scored {
        if !used_p[pi] && !used_g[gi] {
            used_p[pi] = true;
            used_g[gi] = true;
            out.push((pi, gi, f1));
        }
    }
    out
}

/// MUVERA FDE mechanics at scale, on synthetic clustered token matrices —
/// corpus sizes whose transformer ingest would take hours, isolating the two
/// numbers the real pipeline needs from FDEs: does the **exact-MaxSim top-10
/// survive inside the FDE candidate head** (that pool feeds the MaxSim
/// rescore, which restores exact order), and what does the single-vector
/// scan cost. Fully deterministic; within-run comparisons only, as always.
fn run_fde_synth(
    n: usize,
    queries: usize,
    doc_tokens: usize,
    query_tokens: usize,
    dim: usize,
) -> Result<()> {
    use undercroft_core::fde::{fde_dot, FdeEncoder, FdeParams};
    use undercroft_core::late::maxsim;
    use std::time::Instant;

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn gaussian(state: &mut u64) -> f32 {
        let u1 = ((splitmix(state) >> 11) as f64 + 1.0) / (1u64 << 53) as f64;
        let u2 = ((splitmix(state) >> 11) as f64 + 1.0) / (1u64 << 53) as f64;
        ((-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()) as f32
    }
    /// A unit token near its topic's base direction (deterministic base,
    /// small per-token jitter) — same-topic tokens are close in cosine.
    fn token(jitter: &mut u64, dim: usize, topic: u64) -> Vec<f32> {
        let mut base = topic.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x5eed;
        let mut v: Vec<f32> = (0..dim).map(|_| gaussian(&mut base)).collect();
        for x in v.iter_mut() {
            *x += 0.15 * gaussian(jitter);
        }
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-12);
        v.iter_mut().for_each(|x| *x /= norm);
        v
    }

    let params = FdeParams::default();
    let topics = ((n / 8).max(16)) as u64;
    println!(
        "FDE synth: n={n} docs × {doc_tokens} tokens, dim={dim}, topics={topics}, \
         params reps={} ksim={} dproj={}",
        params.reps, params.ksim, params.dproj
    );

    let mut jitter = 0xfde5_eed0_u64;
    let t0 = Instant::now();
    let docs: Vec<Vec<f32>> = (0..n)
        .map(|i| {
            // Two topics per doc — candidates must separate docs sharing
            // one topic from docs sharing none.
            let a = (i as u64) % topics;
            let b = (i as u64 * 7 + 3) % topics;
            let mut m = Vec::with_capacity(doc_tokens * dim);
            for t in 0..doc_tokens {
                m.extend(token(&mut jitter, dim, if t % 2 == 0 { a } else { b }));
            }
            m
        })
        .collect();
    let gen_secs = t0.elapsed().as_secs_f64();

    let enc = FdeEncoder::new(dim, params);
    let t0 = Instant::now();
    let fdes: Vec<Vec<f32>> = docs.iter().map(|d| enc.encode_doc(d)).collect();
    let build_secs = t0.elapsed().as_secs_f64();
    let ram_mb = (n * enc.dim() * 4) as f64 / 1e6;

    let top = |scored: &mut Vec<(f32, usize)>, k: usize| -> Vec<usize> {
        if scored.len() > k {
            scored.select_nth_unstable_by(k - 1, |a, b| b.0.total_cmp(&a.0));
            scored.truncate(k);
        }
        scored.sort_by(|a, b| b.0.total_cmp(&a.0));
        scored.iter().map(|&(_, j)| j).collect()
    };

    // PQ compression of the FDEs (the bounded-RAM tier): codebook trained
    // on an even sample, every FDE encoded to m = dim/8 bytes, scanning via
    // per-query dot-product LUTs. IVF partitions on top (RAM-side probe —
    // the FDE cache lives in RAM, so no disk layout is involved).
    use undercroft_store::pq::{CoarseQuantizer, ProductQuantizer};
    let sample_stride = n.div_ceil(4096).max(1);
    let sample: Vec<Vec<f32>> = fdes.iter().step_by(sample_stride).cloned().collect();
    let t0 = Instant::now();
    let pq = ProductQuantizer::train(&sample, enc.dim() / 8, 10)
        .ok_or_else(|| anyhow::anyhow!("FDE codebook failed to train"))?;
    let codes: Vec<Vec<u8>> = fdes.iter().map(|f| pq.encode(f)).collect();
    let pq_build_secs = t0.elapsed().as_secs_f64();
    let pq_ram_mb = (n * pq.code_len()) as f64 / 1e6;
    let nlist = ((n as f64).sqrt() as usize).clamp(16, 1024);
    let t0 = Instant::now();
    let ivf = CoarseQuantizer::train(&sample, nlist, 10, n as u64)
        .ok_or_else(|| anyhow::anyhow!("FDE IVF failed to train"))?;
    let lists: Vec<u32> = fdes.iter().map(|f| ivf.assign(f)).collect();
    // Slab-grouped codes per list — the shipped layout: each list's codes
    // sit in one contiguous buffer, so a probe scans sequentially with no
    // per-doc membership test and no pointer-chasing (an index-only
    // grouping measured slower than flat purely from cache misses).
    let cl = pq.code_len();
    let mut slabs: std::collections::HashMap<u32, (Vec<usize>, Vec<u8>)> = Default::default();
    for (j, l) in lists.iter().enumerate() {
        let e = slabs.entry(*l).or_default();
        e.0.push(j);
        e.1.extend_from_slice(&codes[j]);
    }
    let ivf_build_secs = t0.elapsed().as_secs_f64();
    // Two probe fractions: the pqidx default (a quarter of the lists) and
    // half — FDE space may cluster differently from embedding space, so
    // measure where the containment knee sits rather than assume.
    let nprobe = (ivf.nlist() / 4).max(8);
    let nprobe2 = (ivf.nlist() / 2).max(8);

    let queries = queries.max(1);
    let stride = (n / queries).max(1);
    let (mut in10, mut in100, mut denom) = (0usize, 0usize, 0usize);
    let (mut pq100_hits, mut ivf100_hits) = (0usize, 0usize);
    let mut ivf2_100_hits = 0usize;
    let mut ivf2_secs = 0f64;
    let (mut scan_secs, mut exact_secs) = (0f64, 0f64);
    let (mut pq_secs, mut ivf_secs) = (0f64, 0f64);
    for qi in 0..queries {
        // Query drawn from an evenly-sampled home doc's first topic.
        let topic = ((qi * stride % n) as u64) % topics;
        let mut qm = Vec::with_capacity(query_tokens * dim);
        for _ in 0..query_tokens {
            qm.extend(token(&mut jitter, dim, topic));
        }
        // Ground truth: exact MaxSim over every doc.
        let t0 = Instant::now();
        let mut exact: Vec<(f32, usize)> = docs
            .iter()
            .enumerate()
            .map(|(j, d)| (maxsim(&qm, d, dim), j))
            .collect();
        exact_secs += t0.elapsed().as_secs_f64();
        let exact10 = top(&mut exact, 10);
        // Raw-FDE candidates.
        let qfde = enc.encode_query(&qm);
        let t0 = Instant::now();
        let mut scored: Vec<(f32, usize)> = fdes
            .iter()
            .enumerate()
            .map(|(j, f)| (fde_dot(&qfde, f), j))
            .collect();
        scan_secs += t0.elapsed().as_secs_f64();
        let fde100 = top(&mut scored, 100);
        let fde10 = &fde100[..10.min(fde100.len())];
        // PQ-FDE candidates: one LUT per query, 256 table adds per doc.
        let t0 = Instant::now();
        let tables = pq
            .dot_tables(&qfde)
            .ok_or_else(|| anyhow::anyhow!("dot_tables dim mismatch"))?;
        let mut pq_scored: Vec<(f32, usize)> = codes
            .iter()
            .enumerate()
            .map(|(j, c)| (pq.adc_dot(&tables, c), j))
            .collect();
        pq_secs += t0.elapsed().as_secs_f64();
        let pq100 = top(&mut pq_scored, 100);
        // PQ + IVF-probed candidates over the slab layout (the shipped
        // inverted tier's scan shape).
        let t0 = Instant::now();
        let probed = ivf.probe(&qfde, nprobe);
        let mut ivf_scored: Vec<(f32, usize)> = Vec::new();
        for l in &probed {
            if let Some((idxs, buf)) = slabs.get(l) {
                for (i, &j) in idxs.iter().enumerate() {
                    ivf_scored.push((pq.adc_dot(&tables, &buf[i * cl..(i + 1) * cl]), j));
                }
            }
        }
        ivf_secs += t0.elapsed().as_secs_f64();
        let ivf100 = top(&mut ivf_scored, 100);
        let t0 = Instant::now();
        let probed2 = ivf.probe(&qfde, nprobe2);
        let mut ivf2_scored: Vec<(f32, usize)> = Vec::new();
        for l in &probed2 {
            if let Some((idxs, buf)) = slabs.get(l) {
                for (i, &j) in idxs.iter().enumerate() {
                    ivf2_scored.push((pq.adc_dot(&tables, &buf[i * cl..(i + 1) * cl]), j));
                }
            }
        }
        ivf2_secs += t0.elapsed().as_secs_f64();
        let ivf2_100 = top(&mut ivf2_scored, 100);
        for e in &exact10 {
            denom += 1;
            if fde10.contains(e) {
                in10 += 1;
            }
            if fde100.contains(e) {
                in100 += 1;
            }
            if pq100.contains(e) {
                pq100_hits += 1;
            }
            if ivf100.contains(e) {
                ivf100_hits += 1;
            }
            if ivf2_100.contains(e) {
                ivf2_100_hits += 1;
            }
        }
    }
    println!(
        "FDE_SYNTH n={n} fde_dim={} gen_s={gen_secs:.1} build_s={build_secs:.1} \
         exact_ms_per_q={:.0} scan_ms_per_q={:.1} scan_qps={:.1} \
         r10_in_fde10={:.3} r10_in_fde100={:.3} ram_mb={ram_mb:.0}",
        enc.dim(),
        1000.0 * exact_secs / queries as f64,
        1000.0 * scan_secs / queries as f64,
        queries as f64 / scan_secs.max(1e-9),
        in10 as f64 / denom.max(1) as f64,
        in100 as f64 / denom.max(1) as f64,
    );
    println!(
        "FDE_SYNTH_PQ n={n} code_b={} pq_build_s={pq_build_secs:.1} \
         ivf_build_s={ivf_build_secs:.1} nlist={} nprobe={nprobe}/{nprobe2} \
         pq_ms_per_q={:.1} ivf_ms_per_q={:.1} ivf2_ms_per_q={:.1} \
         r10_in_pq100={:.3} r10_in_ivf100={:.3} r10_in_ivf2_100={:.3} \
         ram_mb={pq_ram_mb:.0}",
        pq.code_len(),
        ivf.nlist(),
        1000.0 * pq_secs / queries as f64,
        1000.0 * ivf_secs / queries as f64,
        1000.0 * ivf2_secs / queries as f64,
        pq100_hits as f64 / denom.max(1) as f64,
        ivf100_hits as f64 / denom.max(1) as f64,
        ivf2_100_hits as f64 / denom.max(1) as f64,
    );
    Ok(())
}

/// Page-level decryption spike (ROADMAP sealed-tier research item).
///
/// Three shapes over byte-identical synthetic codes, per probe fraction:
///
/// * **A-flat** — today's sealed format verbatim: one AEAD blob per row
///   (AAD `pqrow/{seq}`), decrypt-once flat RAM cache, per-query list
///   filter over the whole cache.
/// * **A-grouped** — same at-rest format, cache regrouped by list once at
///   open (the incremental fix that needs no format change): a probe scans
///   only its lists' contiguous code slabs.
/// * **B-pages** — one AEAD blob per IVF list (AAD `pqpage/{list}`,
///   plaintext `count u32le ++ (seq i64le ++ code)*count` — the count is
///   the row-count commitment, covered by the AEAD), decrypted lazily per
///   probe; measured cold (no cache) and warm (decrypt-once page cache).
///
/// Recall is out of scope by construction (identical codes ⇒ identical
/// candidates); the measured axes are at-rest size, open cost, per-probe
/// decrypt cost, and resident RAM. List assignment is uniform — real
/// clusters skew, which widens per-probe tail latency but leaves the
/// bytes-per-probe mean (n/nlist × nprobe) unchanged.
fn run_pqpage_synth(
    n: usize,
    dim: usize,
    queries: usize,
    nlist_arg: usize,
    k: usize,
) -> Result<()> {
    use undercroft_store::pq::ProductQuantizer;
    use undercroft_vault::keys::{derive_vault_key, load_or_create_master, new_vault_salt};
    use undercroft_vault::seal::{open_content, seal_content};
    use rusqlite::{params, Connection};
    use std::collections::HashMap;

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn gaussian(state: &mut u64) -> f32 {
        let u1 = ((splitmix(state) >> 11) as f64 + 1.0) / (1u64 << 53) as f64;
        let u2 = ((splitmix(state) >> 11) as f64 + 1.0) / (1u64 << 53) as f64;
        ((-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()) as f32
    }
    fn unit_vec(state: &mut u64, dim: usize) -> Vec<f32> {
        let mut v: Vec<f32> = (0..dim).map(|_| gaussian(state)).collect();
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-12);
        v.iter_mut().for_each(|x| *x /= norm);
        v
    }
    /// Resident set from /proc/self/status (Linux — the bench runs in the
    /// Docker battery). None elsewhere; deltas are reported best-effort.
    fn vm_rss_mb() -> Option<f64> {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        let kb: f64 = s
            .lines()
            .find(|l| l.starts_with("VmRSS:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kb / 1024.0)
    }
    fn rss_str(v: Option<f64>) -> String {
        v.map_or_else(|| "n/a".into(), |m| format!("{m:.0}"))
    }
    fn top_k(scored: &mut Vec<(f32, i64)>, k: usize) {
        if scored.len() > k {
            scored.select_nth_unstable_by(k - 1, |a, b| {
                a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
            });
            scored.truncate(k);
        }
    }

    let m = dim / 8;
    anyhow::ensure!(m > 0 && dim.is_multiple_of(8), "dim must divide by 8");
    let nlist = if nlist_arg == 0 {
        ((n as f64).sqrt() as usize).clamp(16, 1024)
    } else {
        nlist_arg
    };
    let rows_per_list = n / nlist;
    println!(
        "PQPAGE spike: n={n} dim={dim} code={m}B nlist={nlist} \
         (~{rows_per_list} rows/list, ~{:.0} KB plaintext/page) k={k} queries={queries}",
        (rows_per_list * (8 + m)) as f64 / 1e3,
    );

    // Real derived key + real seal/open code path.
    let dir = tempfile::TempDir::new()?;
    let master = load_or_create_master(dir.path(), None)?;
    let salt = new_vault_salt();
    let enc = derive_vault_key(&master, &salt, "spike", "enc");

    // Real codebook trained on a small gaussian sample so distance_tables/
    // adc exercise the real scan path; the corpus codes are random bytes.
    let mut rng = 0x9a9e_5eed_u64;
    let sample: Vec<Vec<f32>> = (0..2048).map(|_| unit_vec(&mut rng, dim)).collect();
    let pq = ProductQuantizer::train(&sample, m, 8)
        .ok_or_else(|| anyhow::anyhow!("codebook failed to train"))?;
    drop(sample);

    // Synthetic corpus, generated once and shared by both builds.
    let t0 = Instant::now();
    let mut codes = vec![0u8; n * m];
    for chunk in codes.chunks_mut(8) {
        let bytes = splitmix(&mut rng).to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    let lists: Vec<u32> = (0..n)
        .map(|_| (splitmix(&mut rng) % nlist as u64) as u32)
        .collect();
    println!("corpus gen: {:.1}s", t0.elapsed().as_secs_f64());

    let bench_conn = |path: &std::path::Path| -> Result<Connection> {
        let conn = Connection::open(path)?;
        // Synthetic cost bench, not a durability test.
        conn.execute_batch("PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF;")?;
        Ok(conn)
    };

    // ---- Build A: per-row seals (today's drawer_pq shape verbatim). ----
    let row_db = dir.path().join("rows.sqlite");
    let t0 = Instant::now();
    let conn_a = bench_conn(&row_db)?;
    conn_a.execute_batch(
        "CREATE TABLE drawer_pq (
             list INTEGER NOT NULL, seq INTEGER NOT NULL, code BLOB NOT NULL,
             PRIMARY KEY (list, seq)) WITHOUT ROWID;",
    )?;
    conn_a.execute("BEGIN", [])?;
    {
        let mut ins =
            conn_a.prepare("INSERT INTO drawer_pq (list, seq, code) VALUES (-1, ?1, ?2)")?;
        let mut plain = Vec::with_capacity(4 + m);
        for seq in 0..n {
            plain.clear();
            plain.extend((lists[seq] as i32).to_le_bytes());
            plain.extend_from_slice(&codes[seq * m..(seq + 1) * m]);
            let blob = seal_content(&enc, "spike", &format!("pqrow/{seq}"), &plain);
            ins.execute(params![seq as i64, blob])?;
        }
    }
    conn_a.execute("COMMIT", [])?;
    let a_build_secs = t0.elapsed().as_secs_f64();
    let a_bytes = std::fs::metadata(&row_db)?.len();

    // ---- Build B: one sealed page per list. ----
    let page_db = dir.path().join("pages.sqlite");
    let t0 = Instant::now();
    let conn_b = bench_conn(&page_db)?;
    conn_b
        .execute_batch("CREATE TABLE pq_pages (list INTEGER PRIMARY KEY, page BLOB NOT NULL);")?;
    {
        let mut bodies: Vec<Vec<u8>> = vec![Vec::new(); nlist];
        let mut counts: Vec<u32> = vec![0; nlist];
        for seq in 0..n {
            let l = lists[seq] as usize;
            bodies[l].extend((seq as i64).to_le_bytes());
            bodies[l].extend_from_slice(&codes[seq * m..(seq + 1) * m]);
            counts[l] += 1;
        }
        conn_b.execute("BEGIN", [])?;
        let mut ins = conn_b.prepare("INSERT INTO pq_pages (list, page) VALUES (?1, ?2)")?;
        for (l, body) in bodies.iter().enumerate() {
            let mut plain = Vec::with_capacity(4 + body.len());
            plain.extend(counts[l].to_le_bytes());
            plain.extend_from_slice(body);
            let blob = seal_content(&enc, "spike", &format!("pqpage/{l}"), &plain);
            ins.execute(params![l as i64, blob])?;
        }
        conn_b.execute("COMMIT", [])?;
    }
    let b_build_secs = t0.elapsed().as_secs_f64();
    let b_bytes = std::fs::metadata(&page_db)?.len();
    println!(
        "at-rest: per-row {:.0} MB (build {a_build_secs:.1}s) | per-page {:.0} MB \
         (build {b_build_secs:.1}s) — seal overhead 40 B × {} vs 40 B × {nlist}",
        a_bytes as f64 / 1e6,
        b_bytes as f64 / 1e6,
        n,
    );

    // The generator arrays are not part of any measured variant.
    drop(codes);
    drop(lists);
    let rss_base = vm_rss_mb();

    // Shared per-(query, fraction) probe sets: sorted random distinct lists.
    // A real probe ranks lists by centroid distance; a random subset costs
    // the same to decrypt and scan.
    let fractions: [usize; 3] = [4, 16, 64];
    let mut probe_sets: HashMap<(usize, usize), Vec<i64>> = HashMap::new();
    for &div in &fractions {
        let nprobe = (nlist / div).max(1);
        for q in 0..queries {
            let mut set = std::collections::BTreeSet::new();
            while set.len() < nprobe {
                set.insert((splitmix(&mut rng) % nlist as u64) as i64);
            }
            probe_sets.insert((q, div), set.into_iter().collect());
        }
    }
    // One query vector per query index → one LUT per query, as in the store.
    let tables: Vec<Vec<f32>> = (0..queries)
        .map(|_| pq.distance_tables(&unit_vec(&mut rng, dim)))
        .collect();

    // ---- A: open cost (decrypt-once full cache, verbatim repr). ----
    let t0 = Instant::now();
    let mut cache: Vec<(i64, i64, Vec<u8>)> = Vec::with_capacity(n);
    {
        let mut stmt = conn_a.prepare("SELECT seq, code FROM drawer_pq")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let seq: i64 = r.get(0)?;
            let blob: Vec<u8> = r.get(1)?;
            let plain = open_content(&enc, "spike", &format!("pqrow/{seq}"), &blob)
                .map_err(|e| anyhow::anyhow!("row open: {e}"))?;
            let list = i32::from_le_bytes(plain[..4].try_into().unwrap()) as i64;
            cache.push((seq, list, plain[4..].to_vec()));
        }
    }
    let a_open_secs = t0.elapsed().as_secs_f64();
    let rss_a = vm_rss_mb();
    println!(
        "A open (decrypt-all {n} rows): {a_open_secs:.1}s | RSS {} MB (base {})",
        rss_str(rss_a),
        rss_str(rss_base),
    );

    // A-grouped: regroup the cache by list into contiguous slabs.
    let t0 = Instant::now();
    let mut grouped: HashMap<i64, (Vec<i64>, Vec<u8>)> = HashMap::new();
    for (seq, list, code) in &cache {
        let e = grouped.entry(*list).or_default();
        e.0.push(*seq);
        e.1.extend_from_slice(code);
    }
    let regroup_secs = t0.elapsed().as_secs_f64();
    let rss_grouped = vm_rss_mb();

    for &div in &fractions {
        let nprobe = (nlist / div).max(1);

        // A-flat: filter the whole flat cache per query (today's scan).
        let t0 = Instant::now();
        for q in 0..queries {
            let probe = &probe_sets[&(q, div)];
            let lut = &tables[q];
            let mut scored: Vec<(f32, i64)> = cache
                .iter()
                .filter(|(_, list, _)| probe.binary_search(list).is_ok())
                .map(|(seq, _, code)| (pq.adc(lut, code), *seq))
                .collect();
            top_k(&mut scored, k);
        }
        let a_flat_ms = 1000.0 * t0.elapsed().as_secs_f64() / queries as f64;

        // A-grouped: scan only the probed lists' slabs.
        let t0 = Instant::now();
        for q in 0..queries {
            let probe = &probe_sets[&(q, div)];
            let lut = &tables[q];
            let mut scored: Vec<(f32, i64)> = Vec::new();
            for l in probe {
                if let Some((seqs, slab)) = grouped.get(l) {
                    for (i, seq) in seqs.iter().enumerate() {
                        scored.push((pq.adc(lut, &slab[i * m..(i + 1) * m]), *seq));
                    }
                }
            }
            top_k(&mut scored, k);
        }
        let a_grp_ms = 1000.0 * t0.elapsed().as_secs_f64() / queries as f64;
        println!(
            "nprobe={nprobe} ({:.1}% of corpus): A-flat {a_flat_ms:.1} ms/q | \
             A-grouped {a_grp_ms:.2} ms/q",
            100.0 * nprobe as f64 / nlist as f64,
        );
    }
    drop(cache);
    drop(grouped);
    println!(
        "A-grouped regroup: {regroup_secs:.1}s, RSS after {} MB",
        rss_str(rss_grouped)
    );
    let rss_pre_b = vm_rss_mb();

    // ---- B: lazy page decryption, cold then warm. ----
    let mut page_stmt = conn_b.prepare("SELECT page FROM pq_pages WHERE list = ?1")?;
    let mut open_page = |l: i64| -> Result<(Vec<i64>, Vec<u8>)> {
        let blob: Vec<u8> = page_stmt.query_row(params![l], |r| r.get(0))?;
        let plain = open_content(&enc, "spike", &format!("pqpage/{l}"), &blob)
            .map_err(|e| anyhow::anyhow!("page open: {e}"))?;
        let count = u32::from_le_bytes(plain[..4].try_into().unwrap()) as usize;
        anyhow::ensure!(
            plain.len() == 4 + count * (8 + m),
            "row-count commitment mismatch"
        );
        let mut seqs = Vec::with_capacity(count);
        let mut slab = Vec::with_capacity(count * m);
        for i in 0..count {
            let off = 4 + i * (8 + m);
            seqs.push(i64::from_le_bytes(plain[off..off + 8].try_into().unwrap()));
            slab.extend_from_slice(&plain[off + 8..off + 8 + m]);
        }
        Ok((seqs, slab))
    };

    for &div in &fractions {
        let nprobe = (nlist / div).max(1);

        // Cold: decrypt every probed page, scan, drop.
        let t0 = Instant::now();
        let mut bytes_dec = 0usize;
        for q in 0..queries {
            let probe = &probe_sets[&(q, div)];
            let lut = &tables[q];
            let mut scored: Vec<(f32, i64)> = Vec::new();
            for &l in probe {
                let (seqs, slab) = open_page(l)?;
                bytes_dec += slab.len() + seqs.len() * 8;
                for (i, seq) in seqs.iter().enumerate() {
                    scored.push((pq.adc(lut, &slab[i * m..(i + 1) * m]), *seq));
                }
            }
            top_k(&mut scored, k);
        }
        let b_cold_ms = 1000.0 * t0.elapsed().as_secs_f64() / queries as f64;
        let mb_per_q = bytes_dec as f64 / queries as f64 / 1e6;

        // Warm: decrypt-once page cache; populate on the same probe sets,
        // then measure the second pass.
        let mut pcache: HashMap<i64, (Vec<i64>, Vec<u8>)> = HashMap::new();
        for q in 0..queries {
            for &l in &probe_sets[&(q, div)] {
                if let std::collections::hash_map::Entry::Vacant(e) = pcache.entry(l) {
                    e.insert(open_page(l)?);
                }
            }
        }
        let coverage = pcache.len() as f64 / nlist as f64;
        let rss_warm = vm_rss_mb();
        let t0 = Instant::now();
        for q in 0..queries {
            let probe = &probe_sets[&(q, div)];
            let lut = &tables[q];
            let mut scored: Vec<(f32, i64)> = Vec::new();
            for l in probe {
                if let Some((seqs, slab)) = pcache.get(l) {
                    for (i, seq) in seqs.iter().enumerate() {
                        scored.push((pq.adc(lut, &slab[i * m..(i + 1) * m]), *seq));
                    }
                }
            }
            top_k(&mut scored, k);
        }
        let b_warm_ms = 1000.0 * t0.elapsed().as_secs_f64() / queries as f64;
        println!(
            "nprobe={nprobe} ({:.1}% of corpus): B-cold {b_cold_ms:.1} ms/q \
             ({mb_per_q:.1} MB decrypted/q) | B-warm {b_warm_ms:.2} ms/q \
             (page cache {:.0}% of lists, RSS {} MB, pre-B {})",
            100.0 * nprobe as f64 / nlist as f64,
            100.0 * coverage,
            rss_str(rss_warm),
            rss_str(rss_pre_b),
        );
    }
    println!("PQPAGE spike done.");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Longmemeval {
            dataset,
            limit,
            k,
            level,
            skip,
        } => run_longmemeval(&dataset, limit, k, level_of(&level), skip),
        Command::Synth { n, level, queries } => run_synth(n, level_of(&level), queries),
        Command::Pqscale {
            sizes,
            queries,
            pools,
            batch,
            pool_div,
            level,
        } => run_pqscale(
            &sizes,
            queries,
            &pools,
            batch,
            pool_div.as_deref(),
            level_of(&level),
        ),
        Command::Scopescale {
            sizes,
            wing_size,
            room_size,
            queries,
            batch,
            level,
        } => run_scopescale(
            &sizes,
            wing_size,
            room_size,
            queries,
            batch,
            level_of(&level),
        ),
        Command::Xlingual {
            pairs,
            limit,
            level,
        } => run_xlingual(&pairs, limit, level_of(&level)),
        Command::Wingscale {
            n,
            wings,
            queries,
            floors,
            level,
        } => run_wingscale(n, wings, queries, &floors, level_of(&level)),
        Command::PqpageSynth {
            n,
            dim,
            queries,
            nlist,
            k,
        } => run_pqpage_synth(n, dim, queries, nlist, k),
        Command::FdeSynth {
            n,
            queries,
            doc_tokens,
            query_tokens,
            dim,
        } => run_fde_synth(n, queries, doc_tokens, query_tokens, dim),
        Command::Locomo {
            dataset,
            k,
            limit,
            skip,
            backend,
            chunk_size,
            budget_bytes,
            unit,
            pool,
            paging_contract,
        } => {
            let raw = std::fs::read_to_string(&dataset)
                .with_context(|| format!("reading {}", dataset.display()))?;
            let samples: Vec<Value> = serde_json::from_str(&raw)?;
            let total = samples.len();
            let start = skip.min(total);
            let end = limit.map(|l| (start + l).min(total)).unwrap_or(total);
            let shard = &samples[start..end];
            let (recall_sum, n, per_cat, timing, gold) = locomo_eval(
                shard,
                k,
                &backend,
                chunk_size,
                budget_bytes,
                pool,
                unit == "turn",
                paging_contract,
            )?;
            // RAW line carries the exact numerator/denominator so sharded runs
            // (convos [start,end)) sum to the full R@k without rounding drift.
            println!(
                "LOCOMO_RAW convos={start}..{end}/{total} recall_sum={recall_sum:.4} evaluated={n}"
            );
            // Phase split, machine-readable and additive across shards: total
            // wall-clock in each phase and the mean per-query search cost.
            let ingest = timing.ingest_secs;
            let search = timing.search_secs;
            println!(
                "LOCOMO_TIMING convos={start}..{end}/{total} ingest_secs={ingest:.3} search_secs={search:.3} evaluated={n} search_ms_per_q={:.1}",
                1000.0 * search / n.max(1) as f32
            );
            println!(
                "LoCoMo — {} questions, session granularity: R@{k} {:.1}%",
                n,
                100.0 * recall_sum / n.max(1) as f32
            );
            for (cat, (sum, cnt)) in per_cat {
                println!(
                    "  category {cat:<12} {:.1}%  ({cnt})",
                    100.0 * sum / cnt as f32
                );
            }
            // Gold-evidence recall. RAW first, with every numerator and
            // denominator, so sharded runs sum instead of averaging averages.
            let g = gold;
            println!(
                "LOCOMO_GOLD_RAW convos={start}..{end}/{total} queries={} session_any={:.4} \
                 session_all={:.4} slot_session_any={:.4} slot_session_all={:.4} \
                 turn_queries={} turn_any={:.4} turn_all={:.4} \
                 slots={} repeat_slots={} unlocatable_turns={}",
                g.queries,
                g.session_any,
                g.session_all,
                g.slot_session_any,
                g.slot_session_all,
                g.turn_queries,
                g.turn_any,
                g.turn_all,
                g.slots,
                g.repeat_slots,
                g.unlocatable_turns
            );
            for (ci, cap) in DOC_CAPS.iter().enumerate() {
                println!(
                    "LOCOMO_DOCCAP_RAW convos={start}..{end}/{total} cap={cap} \
                     turn_queries={} turn_any={:.4} turn_all={:.4}",
                    g.turn_queries, g.dedup_turn_any[ci], g.dedup_turn_all[ci]
                );
            }
            let pct = |num: f32, den: u32| 100.0 * num / den.max(1) as f32;
            // Three rows, two depths. Only the last two are a like-for-like
            // granularity comparison; the first scans the whole candidate
            // pool for distinct rooms and is therefore the most generous
            // reading available.
            println!(
                "Gold evidence, session, {}-hit pool scan: any {:.1}%  all {:.1}%   ({} q)",
                k * 6,
                pct(g.session_any, g.queries),
                pct(g.session_all, g.queries),
                g.queries
            );
            println!(
                "Gold evidence, session, in the {k} slots:  any {:.1}%  all {:.1}%   ({} q)",
                pct(g.slot_session_any, g.queries),
                pct(g.slot_session_all, g.queries),
                g.queries
            );
            println!(
                "Gold evidence, turn,    in the {k} slots:  any {:.1}%  all {:.1}%   ({} q)",
                pct(g.turn_any, g.turn_queries),
                pct(g.turn_all, g.turn_queries),
                g.turn_queries
            );
            for (ci, cap) in DOC_CAPS.iter().enumerate() {
                println!(
                    "  at most {cap} slot(s) per document:  any {:.1}%  all {:.1}%   \
                     (all {:+.1}pp vs the same retrieval uncapped)",
                    pct(g.dedup_turn_any[ci], g.turn_queries),
                    pct(g.dedup_turn_all[ci], g.turn_queries),
                    pct(g.dedup_turn_all[ci], g.turn_queries) - pct(g.turn_all, g.turn_queries)
                );
            }
            println!(
                "  budget-selected ({budget_bytes} B, overlap charged once): \
                 any {:.1}%  all {:.1}%   (all {:+.1}pp, mean {:.1} chunks)",
                pct(g.budget_turn_any, g.turn_queries),
                pct(g.budget_turn_all, g.turn_queries),
                pct(g.budget_turn_all, g.turn_queries) - pct(g.turn_all, g.turn_queries),
                g.budget_slots as f32 / g.turn_queries.max(1) as f32
            );
            println!(
                "  slots filled by an already-represented document: {}/{} = {:.1}%",
                g.repeat_slots,
                g.slots,
                pct(g.repeat_slots as f32, g.slots)
            );
            println!(
                "    of those, {} overlap text already returned and {} carry \
                 different text from the same document",
                g.repeat_adjacent, g.repeat_disjoint
            );
            println!(
                "  bytes handed to the reader twice: {}/{} = {:.1}%  \
                 (the ceiling on what any dedup can recover)",
                g.dup_bytes,
                g.slot_bytes,
                100.0 * g.dup_bytes as f64 / g.slot_bytes.max(1) as f64
            );
            // What the remaining failures are made of.
            for (i, (num, den)) in g.by_goldcount.iter().enumerate() {
                if *den > 0 {
                    let label = if i == 4 {
                        "5+".to_string()
                    } else {
                        (i + 1).to_string()
                    };
                    println!(
                        "  gold turns needed = {label:<3} all delivered {:.1}%  ({den} q)",
                        pct(*num, *den)
                    );
                }
            }
            // Does forcing a second document help the queries that need one?
            println!("  gold-turns-needed  baseline   cap<=2     budget");
            for i in 0..5 {
                let (n0, d0) = g.by_goldcount[i];
                if d0 == 0 {
                    continue;
                }
                let (n1, d1) = g.by_goldcount_cap2[i];
                let (n2, d2) = g.by_goldcount_budget[i];
                let label = if i == 4 {
                    "5+".to_string()
                } else {
                    (i + 1).to_string()
                };
                println!(
                    "    {label:<16} {:>6.1}%   {:>6.1}%   {:>6.1}%   ({d0} q)",
                    pct(n0, d0),
                    pct(n1, d1),
                    pct(n2, d2)
                );
            }
            for (c, (num, den)) in g.by_category.iter().enumerate() {
                if *den > 0 {
                    println!(
                        "  category {c:<2} all delivered {:.1}%  ({den} q)",
                        pct(*num, *den)
                    );
                }
            }
            // Ceiling diagnostic: how deep the ranked list must go before all
            // gold is in hand. Cumulative, so each row is "what a perfect
            // second stage over the top-N could deliver".
            let mut cum = 0u32;
            for (i, t) in RANK_BUCKETS.iter().enumerate() {
                cum += g.gold_all_rank[i];
                println!(
                    "  all gold covered within top-{t:<4} {:.1}%  (cumulative)",
                    pct(cum as f32, g.turn_queries)
                );
            }
            // [len()] is "deeper than the last bucket but still found";
            // [len()+1] is "never, at any depth".
            cum += g.gold_all_rank[RANK_BUCKETS.len()];
            println!(
                "  all gold covered anywhere in the pool: {:.1}%  \
                 — never, at any depth: {:.1}%  (the first-stage floor)",
                pct(cum as f32, g.turn_queries),
                pct(
                    g.gold_all_rank[RANK_BUCKETS.len() + 1] as f32,
                    g.turn_queries
                )
            );
            if g.page_queries > 0 {
                // The contract, delivered: the ≤40 CDF row is a diagnostic
                // about the ranking; the paged row is what four calls of
                // limit 10 actually hand a caller. R3's claim is that they
                // are the same number.
                let cdf40: u32 = g.gold_all_rank[..3].iter().sum();
                println!(
                    "  R3 paging contract ({} queries): tiling mismatches {} · \
                     all-gold via 4x10 pinned pages {:.1}% vs CDF within top-40 {:.1}% · \
                     unpinned repeats differing {}",
                    g.page_queries,
                    g.page_mismatches,
                    pct(g.page_all, g.page_queries),
                    pct(cdf40 as f32, g.turn_queries),
                    g.page_unpinned_drift
                );
            }
            if g.unlocatable_turns > 0 {
                println!(
                    "  {} gold turns could not be located in the ingested body \
                     and are excluded from the turn rows",
                    g.unlocatable_turns
                );
            }
            Ok(())
        }
        Command::Vs {
            dataset,
            system,
            k,
            limit,
            skip,
            qa_limit,
            url,
        } => {
            let raw = std::fs::read_to_string(&dataset)
                .with_context(|| format!("reading {}", dataset.display()))?;
            let samples: Vec<Value> = serde_json::from_str(&raw)?;
            let total = samples.len();
            let start = skip.min(total);
            let end = limit.map(|l| (start + l).min(total)).unwrap_or(total);
            let shard = &samples[start..end];
            let mut native;
            let mut mem0;
            let mut supermemory;
            let sys: &mut dyn vs::MemorySystem = match system.as_str() {
                "undercroft" => {
                    native = NativeSystem {
                        store: None,
                        chunk_idx: 0,
                    };
                    &mut native
                }
                "mem0" => {
                    mem0 = vs::Mem0::new(&url);
                    &mut mem0
                }
                "supermemory" => {
                    supermemory = vs::Supermemory::new(&url);
                    &mut supermemory
                }
                other => anyhow::bail!("unknown system {other:?} (undercroft|mem0|supermemory)"),
            };
            let score = vs::vs_eval(sys, shard, k, qa_limit)?;
            // RAW lines: additive across shards, zero rounding drift —
            // the same discipline as the standalone LoCoMo row.
            println!(
                "VS_RAW system={system} convos={start}..{end}/{total} qa_limit={qa_limit} \
                 recall_sum={:.4} evaluated={}",
                score.recall_sum, score.evaluated
            );
            println!(
                "VS_TIMING system={system} ingest_secs={:.3} ingest_chunks={} \
                 search_secs={:.3} search_ms_per_q={:.1}",
                score.ingest_secs,
                score.ingest_chunks,
                score.search_secs,
                1000.0 * score.search_secs / score.evaluated.max(1) as f32
            );
            println!(
                "VS — {} · {} questions · session granularity: R@{k} {:.1}%",
                system,
                score.evaluated,
                100.0 * score.recall_sum / score.evaluated.max(1) as f32
            );
            for (cat, (sum, cnt)) in score.per_cat {
                println!(
                    "  category {cat:<12} {:.1}%  ({cnt})",
                    100.0 * sum / cnt as f32
                );
            }
            Ok(())
        }
        Command::Distill {
            dataset,
            k,
            limit,
            skip,
            qa_limit,
        } => {
            let raw = std::fs::read_to_string(&dataset)
                .with_context(|| format!("reading {}", dataset.display()))?;
            let samples: Vec<Value> = serde_json::from_str(&raw)?;
            let total = samples.len();
            let start = skip.min(total);
            let end = limit.map(|l| (start + l).min(total)).unwrap_or(total);
            distill_eval(&samples[start..end], k, qa_limit)
        }
        Command::Convomem { dataset, k, limit } => {
            let raw = std::fs::read_to_string(&dataset)
                .with_context(|| format!("reading {}", dataset.display()))?;
            let items: Vec<Value> = serde_json::from_str(&raw)?;
            let (recall_sum, n) = convomem_eval(&items, k, limit)?;
            println!(
                "ConvoMem — {} items, message granularity: recall@{k} {:.1}%",
                n,
                100.0 * recall_sum / n.max(1) as f32
            );
            Ok(())
        }
        Command::Membench {
            dataset,
            topic,
            k,
            limit,
        } => {
            let raw = std::fs::read_to_string(&dataset)
                .with_context(|| format!("reading {}", dataset.display()))?;
            let value: Value = serde_json::from_str(&raw)?;
            let (recall_sum, n) = membench_eval(&value, &topic, k, limit)?;
            println!(
                "MemBench ({topic}) — {} items, turn granularity: R@{k} {:.1}%",
                n,
                100.0 * recall_sum / n.max(1) as f32
            );
            Ok(())
        }
        Command::ModelEval {
            task,
            dataset_dir,
            lang,
            limit,
        } => run_model_eval(&task, &dataset_dir, lang.as_deref(), limit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndcg_perfect_and_zero() {
        let ranked = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert!((ndcg(&ranked, &["a".to_string()], 3) - 1.0).abs() < 1e-6);
        assert_eq!(ndcg(&ranked, &["z".to_string()], 3), 0.0);
    }

    #[test]
    fn synth_small_run_passes() {
        run_synth(40, SecurityLevel::Sealed, None).expect("synthetic benchmark must pass");
    }

    #[test]
    fn token_f1_basics() {
        assert!((token_f1("switching to jaccard", "switching to jaccard") - 1.0).abs() < 1e-6);
        assert_eq!(token_f1("alpha beta", "gamma delta"), 0.0);
        // Partial overlap scores between 0 and 1.
        let f1 = token_f1(
            "switch the pipeline to jaccard similarity",
            "the pipeline switches to jaccard",
        );
        assert!(f1 > 0.4 && f1 < 1.0, "got {f1}");
    }

    #[test]
    fn token_f1_cjk_characters() {
        // Chinese has no spaces; per-character tokens still overlap.
        let f1 = token_f1("我们决定使用新数据库", "决定使用新数据库");
        assert!(f1 > 0.8, "got {f1}");
        assert_eq!(token_f1("我们决定", "完全不同"), 0.0);
    }

    #[test]
    fn locomo_adapter_scores_fixture() {
        let sample = serde_json::json!({
            "conversation": {
                "session_1": [
                    {"dia_id": "D1:1", "speaker": "Ana", "text": "I adopted a golden retriever puppy named Biscuit last weekend."},
                    {"dia_id": "D1:2", "speaker": "Ben", "text": "That is wonderful news, congratulations!"}
                ],
                "session_1_date_time": "2024-01-05",
                "session_2": [
                    {"dia_id": "D2:1", "speaker": "Ana", "text": "The quarterly report deadline moved to Friday."}
                ],
                "session_2_date_time": "2024-02-10"
            },
            "qa": [
                {"question": "What pet did Ana adopt?", "answer": "a golden retriever puppy",
                 "category": 1, "evidence": ["D1:1"]},
                {"question": "adversarial with no evidence", "category": 5}
            ]
        });
        let (recall, n, per_cat, _timing, gold) =
            // The trailing `true` runs the R3 paging contract inside the
            // fixture too — asserted below, so the contract check itself
            // has coverage rather than existing only when an operator
            // passes the flag.
            locomo_eval(&[sample], 5, "local", 800, 8000, 0, false, true).unwrap();
        assert_eq!(n, 1, "evidence-free QA must be skipped");
        assert_eq!(recall, 1.0, "evidence session must be retrieved");
        assert_eq!(per_cat.get("1").unwrap().1, 1);
        // Turn granularity must actually be exercised, not silently empty:
        // a fixture whose gold turns fail to locate would leave every turn
        // row at zero out of zero and pass any assertion phrased on the
        // ratio alone.
        assert_eq!(gold.unlocatable_turns, 0, "gold turn must be locatable");
        assert_eq!(gold.turn_queries, 1, "turn row must have a denominator");
        assert_eq!(
            gold.turn_all, 1.0,
            "the gold turn itself must be in the slots"
        );
        assert_eq!(gold.session_all, 1.0);
        // The paging contract on the fixture: pages tile, deliver the gold,
        // and the pinned repeat cannot drift.
        assert_eq!(gold.page_queries, 1, "the contract check must have run");
        assert_eq!(
            gold.page_mismatches, 0,
            "4x10 pinned pages must tile one call of 40"
        );
        assert_eq!(gold.page_all, 1.0, "the pages must deliver the gold turn");
    }

    #[test]
    fn a_shared_image_is_ingested_not_dropped() {
        // 37.9% of LoCoMo's gold-evidence turns carry a caption. A turn that
        // reaches the vault without it is stored incomplete, and the miss it
        // then causes is booked against retrieval.
        let with = serde_json::json!({
            "speaker": "Ana", "text": "Look where we ended up!",
            "blip_caption": "a photo of a lighthouse at sunset",
            "img_url": ["https://example.invalid/x.jpg"],
            "query": "lighthouse sunset photo"
        });
        let line = locomo_turn_text(&with).unwrap();
        assert!(line.contains("Look where we ended up!"));
        assert!(
            line.contains("a photo of a lighthouse at sunset"),
            "the caption is content and must reach the vault: {line}"
        );
        // The dataset's own sourcing scaffolding is not content and must not.
        assert!(!line.contains("example.invalid"), "img_url is not content");
        assert!(
            !line.contains("lighthouse sunset photo"),
            "query is not content"
        );
        // A turn with no image is unchanged, so the corpus only grows where
        // the dataset actually carries an image.
        let without = serde_json::json!({"speaker": "Ben", "text": "Nice."});
        assert_eq!(locomo_turn_text(&without).unwrap(), "Ben said, \"Nice.\"");
        // No text at all is still not a turn.
        assert!(locomo_turn_text(&serde_json::json!({"speaker": "Ben"})).is_none());
    }

    #[test]
    fn spans_merge_and_contain() {
        assert_eq!(
            merge_spans(vec![(0, 5), (3, 9), (20, 25)]),
            vec![(0, 9), (20, 25)]
        );
        // A turn split across a chunk boundary is covered by the union of the
        // two chunks either side, and by neither of them alone — the whole
        // reason coverage is tested against merged intervals.
        let left = (100usize, 200usize);
        let right = (190usize, 300usize);
        let turn = (180usize, 210usize);
        assert!(!covers(&[left], turn));
        assert!(!covers(&[right], turn));
        assert!(covers(&merge_spans(vec![left, right]), turn));
        // A gap in the union is a real gap.
        assert!(!covers(&merge_spans(vec![(0, 100), (250, 400)]), turn));
    }

    #[test]
    fn locate_chunk_walks_overlapping_windows() {
        let body = "alpha beta gamma delta epsilon";
        let mut cur = 0usize;
        assert_eq!(locate_chunk(body, "alpha beta", &mut cur), vec![(0, 10)]);
        // Windows overlap, so the next chunk starts *before* the previous one
        // ended; the cursor must not have skipped past it.
        assert_eq!(locate_chunk(body, "beta gamma", &mut cur), vec![(6, 16)]);
        // The trailing-runt merge joins two non-adjacent slices with "\n\n".
        let mut cur = 0usize;
        let spans = locate_chunk(body, "alpha\n\nepsilon", &mut cur);
        assert_eq!(spans, vec![(0, 5), (23, 30)]);
    }

    #[test]
    fn cap_per_document_caps_then_refills() {
        let mk = |room: &str, id: &str| SearchHit {
            drawer: Drawer::new("w", room, format!("body of {id}"), None, 0, "t"),
            score: 0.0,
            semantic: 0.0,
            lexical: 0.0,
            lexical_exact: 0.0,
            lexical_morph: 0.0,
        };
        let hits = vec![mk("s1", "a"), mk("s1", "b"), mk("s2", "c"), mk("s1", "d")];
        // Two documents, four slots asked for: the cap takes one of each, then
        // hands the remaining slots back in score order rather than returning
        // fewer memories than asked.
        assert_eq!(cap_per_document(&hits, 4, 1), vec![0, 1, 2, 3]);
        // When the slots are scarce the cap binds: s1's second chunk is
        // displaced by s2's first — the displacement gap 2 proposes, and the
        // one the LoCoMo run measures the cost of.
        assert_eq!(cap_per_document(&hits, 2, 1), vec![0, 2]);
        // A cap of 2 lets s1 keep its second chunk.
        assert_eq!(cap_per_document(&hits, 2, 2), vec![0, 1]);
    }

    #[test]
    fn convomem_adapter_scores_fixture() {
        let item = serde_json::json!({
            "question": "what instrument is Maya learning?",
            "answer": "the cello",
            "conversations": [
                {"messages": [
                    {"speaker": "Maya", "text": "I started learning the cello this month."},
                    {"speaker": "Sam", "text": "The weather has been terrible lately."}
                ]}
            ],
            "message_evidences": [ {"text": "I started learning the cello this month."} ]
        });
        let (recall, n) = convomem_eval(&[item], 5, None).unwrap();
        assert_eq!(n, 1);
        assert_eq!(recall, 1.0);
    }

    #[test]
    fn membench_adapter_scores_fixture() {
        let raw = serde_json::json!({
            "movie": [
                {
                    "tid": 1,
                    "message_list": [[
                        {"user": "I watched Arrival yesterday and loved the linguistics angle.",
                         "assistant": "Denis Villeneuve directed it; the score is haunting."},
                        {"user": "Remind me to buy groceries.",
                         "assistant": "Noted — groceries on the list."}
                    ]],
                    "QA": {
                        "question": "which movie with a linguistics angle did I watch?",
                        "ground_truth": "A",
                        "choices": {"A": "Arrival"},
                        "target_step_id": [0]
                    }
                }
            ]
        });
        let (recall, n) = membench_eval(&raw, "movie", 3, None).unwrap();
        assert_eq!(n, 1);
        assert_eq!(recall, 1.0);
    }

    #[test]
    fn greedy_alignment_is_one_to_one() {
        let mk = |s: &str| ("fact".to_string(), s.to_string());
        let pred = vec![
            mk("switching pipeline to jaccard"),
            mk("team lunch moved to friday"),
        ];
        let gold = vec![
            mk("switching the pipeline to jaccard similarity"),
            mk("the team lunch moved to friday"),
            mk("unrelated third gold memory about testing"),
        ];
        let matches = greedy_align(&pred, &gold, 0.5);
        assert_eq!(matches.len(), 2);
        // Each side used at most once.
        let mut gseen: Vec<usize> = matches.iter().map(|m| m.1).collect();
        gseen.dedup();
        assert_eq!(gseen.len(), 2);
    }
}
