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
        /// Evaluate only the first N questions
        #[arg(long)]
        limit: Option<usize>,
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
    },
    /// Evaluate the configured local LLM (UNDERCROFT_LLM_URL) on the
    /// extraction tasks used by `undercroft refine`, against the labeled
    /// multilingual datasets in benchmarks/model_eval/datasets
    ModelEval {
        /// Task: calibration | entities
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
    let dir = tempfile::TempDir::new()?;
    let mgr = VaultManager::open(dir.path(), None)?;
    let vault = mgr.create("bench", level)?;
    Ok((dir, PalaceStore::open(vault)?))
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
) -> Result<()> {
    let raw = std::fs::read_to_string(dataset)
        .with_context(|| format!("reading dataset {}", dataset.display()))?;
    let items: Vec<Value> = serde_json::from_str(&raw).context("dataset must be a JSON array")?;
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
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();

        // Fresh palace per question, one room per haystack session
        // (upstream's session-granularity protocol).
        let (_tmp, mut store) = fresh_store(level)?;
        for (si, session) in sessions.iter().enumerate() {
            let sid = session_ids.get(si).cloned().unwrap_or_else(|| format!("s{si}"));
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
            &SearchOptions { wing: None, room: None, limit: k * 8 },
        )?;
        let mut ranked_sessions: Vec<String> = Vec::new();
        for h in &hits {
            if !ranked_sessions.contains(&h.drawer.meta.room) {
                ranked_sessions.push(h.drawer.meta.room.clone());
            }
        }

        let topk: Vec<&String> = ranked_sessions.iter().take(k).collect();
        let recall_any =
            if correct.iter().any(|c| topk.contains(&c)) { 1.0 } else { 0.0 };
        let recall_all =
            if !correct.is_empty() && correct.iter().all(|c| topk.contains(&c)) { 1.0 } else { 0.0 };
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
    "database migration", "kitchen renovation", "marathon training", "tax filing",
    "guitar practice", "camping trip", "api gateway", "book club", "solar panels",
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

fn run_synth(n: usize, level: SecurityLevel) -> Result<()> {
    let (_tmp, mut store) = fresh_store(level)?;
    // Deterministic distinct facts: each carries a unique key token that the
    // query paraphrases around (tests retrieval, not string equality —
    // queries never repeat the full fact sentence).
    let mut keys = Vec::with_capacity(n);
    let ingest_started = Instant::now();
    for i in 0..n {
        let topic = TOPICS[i % TOPICS.len()];
        let key = format!("{}-{:04}", ["budget", "deadline", "vendor", "owner"][i % 4], i);
        let detail = format!("the {key} is finalized as option {}", (i * 7) % 100);
        let fact = FACT_TEMPLATES[i % FACT_TEMPLATES.len()]
            .replace("{topic}", topic)
            .replace("{detail}", &detail);
        let drawer = Drawer::new("bench", topic, fact, None, i as u32, "bench");
        store.upsert(&drawer)?;
        keys.push((key, topic.to_string(), drawer.id));
    }
    let ingest_secs = ingest_started.elapsed().as_secs_f32();

    let mut r1 = 0u32;
    let mut r5 = 0u32;
    let query_started = Instant::now();
    for (i, (key, topic, id)) in keys.iter().enumerate() {
        let query = QUERY_TEMPLATES[i % QUERY_TEMPLATES.len()]
            .replace("{topic}", topic)
            .replace("{key}", &key[..key.find('-').unwrap_or(key.len())]);
        // Make the query unique to its fact via the key token.
        let query = format!("{query} {key}");
        let hits = store.search(&query, &SearchOptions { wing: None, room: None, limit: 5 })?;
        if hits.first().map(|h| &h.drawer.id) == Some(id) {
            r1 += 1;
        }
        if hits.iter().any(|h| &h.drawer.id == id) {
            r5 += 1;
        }
    }
    let query_secs = query_started.elapsed().as_secs_f32();

    println!("Synthetic benchmark — {n} facts, level={level:?}");
    println!("  Recall@1: {:.1}%", 100.0 * r1 as f32 / n as f32);
    println!("  Recall@5: {:.1}%", 100.0 * r5 as f32 / n as f32);
    println!("  ingest:   {:.2}s ({:.1} docs/s)", ingest_secs, n as f32 / ingest_secs);
    println!("  query:    {:.2}s ({:.1} q/s)", query_secs, n as f32 / query_secs);
    let r5_pct = 100.0 * r5 as f32 / n as f32;
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
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
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
        other => anyhow::bail!("unknown task {other:?} (expected: calibration, entities)"),
    };
    let suffix = lang.map(|l| format!(".{l}")).unwrap_or_default();
    let data = load_jsonl(&dataset_dir.join(subdir).join(format!("{file}{suffix}.jsonl")))?;
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
                let text = item.get("text").and_then(Value::as_str).context("item text")?;
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
                let got = llm.classify(text, &classes).map_err(|e| anyhow::anyhow!("{e}"))?;
                if got.eq_ignore_ascii_case(expected) {
                    correct += 1;
                }
            }
            println!(
                "calibration{} — {}/{} correct ({:.1}%) with {}",
                suffix, correct, total,
                100.0 * correct as f32 / total as f32,
                llm.model()
            );
        }
        "entities" => {
            let (mut tp, mut fp, mut fn_) = (0f32, 0f32, 0f32);
            for item in data.iter().take(total) {
                let id = item.get("id").and_then(Value::as_str).context("item id")?;
                let text = item.get("text").and_then(Value::as_str).context("item text")?;
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
            let f1 = if p + r > 0.0 { 2.0 * p * r / (p + r) } else { 0.0 };
            println!(
                "entities{} — P {:.1}%  R {:.1}%  F1 {:.1}%  ({} items, {})",
                suffix, 100.0 * p, 100.0 * r, 100.0 * f1, total, llm.model()
            );
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Longmemeval { dataset, limit, k, level } => {
            run_longmemeval(&dataset, limit, k, level_of(&level))
        }
        Command::Synth { n, level } => run_synth(n, level_of(&level)),
        Command::ModelEval { task, dataset_dir, lang, limit } => {
            run_model_eval(&task, &dataset_dir, lang.as_deref(), limit)
        }
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
        run_synth(40, SecurityLevel::Sealed).expect("synthetic benchmark must pass");
    }
}
