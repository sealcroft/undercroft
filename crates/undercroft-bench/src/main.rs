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

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::time::Instant;

use undercroft_core::Drawer;
use undercroft_store::{PalaceStore, SearchOptions};
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
    // Optional local HNSW ANN prefilter (replaces the full cosine scan).
    if std::env::var("UNDERCROFT_RETRIEVAL").as_deref() == Ok("hnsw") {
        #[cfg(feature = "hnsw")]
        store.set_hnsw(true);
        #[cfg(not(feature = "hnsw"))]
        eprintln!("note: UNDERCROFT_RETRIEVAL=hnsw ignored — built without --features hnsw");
    }
    // Optional on-disk PQ ANN prefilter (hmac-only vaults; bounded RAM).
    if std::env::var("UNDERCROFT_RETRIEVAL").as_deref() == Ok("pq") {
        store.set_pq(true);
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
                wing: None,
                room: None,
                limit: k * 8,
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
                wing: None,
                room: None,
                limit: 5,
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

fn locomo_eval(
    samples: &[Value],
    k: usize,
    backend: &str,
) -> Result<(f32, u32, CategoryScores, PhaseTiming)> {
    let mut recall_sum = 0f32;
    let mut evaluated = 0u32;
    let mut per_cat: CategoryScores = Default::default();
    let mut timing = PhaseTiming::default();
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
        let ingest_started = Instant::now();
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
                let d = Drawer::new(
                    "locomo",
                    &format!("session_{n}"),
                    chunk,
                    None,
                    ci as u32,
                    "bench",
                );
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
                wing: None,
                room: None,
                limit: k * 6,
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
    Ok((recall_sum, evaluated, per_cat, timing))
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
                wing: None,
                room: None,
                limit: k,
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
                wing: None,
                room: None,
                limit: k,
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
        Command::Locomo {
            dataset,
            k,
            limit,
            skip,
            backend,
        } => {
            let raw = std::fs::read_to_string(&dataset)
                .with_context(|| format!("reading {}", dataset.display()))?;
            let samples: Vec<Value> = serde_json::from_str(&raw)?;
            let total = samples.len();
            let start = skip.min(total);
            let end = limit.map(|l| (start + l).min(total)).unwrap_or(total);
            let shard = &samples[start..end];
            let (recall_sum, n, per_cat, timing) = locomo_eval(shard, k, &backend)?;
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
            Ok(())
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
        let (recall, n, per_cat, _timing) = locomo_eval(&[sample], 5, "local").unwrap();
        assert_eq!(n, 1, "evidence-free QA must be skipped");
        assert_eq!(recall, 1.0, "evidence session must be retrieved");
        assert_eq!(per_cat.get("1").unwrap().1, 1);
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
