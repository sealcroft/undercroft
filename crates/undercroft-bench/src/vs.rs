//! Head-to-head harness (competitive track C1.1): run external memory
//! systems through the **same LoCoMo protocol and scorer** as the native
//! rows, so published comparisons are apples-to-apples by construction.
//!
//! Fairness contract (docs/BENCHMARKS_VS.md is the canonical statement):
//!
//! * **Identical corpus text** — every system ingests the same
//!   normalized, chunked session text the native row ingests; no system
//!   gets tags, hints, or formatting the others don't.
//! * **Identical scoring** — evidence sessions from the dataset's
//!   `D<sess>:<turn>` ids; the system returns a ranked, deduplicated list
//!   of session ids; R@k = any gold session in the top k. Session
//!   identity travels as *metadata* on ingest and must come back on
//!   search results — that mapping (documented per adapter) is each
//!   system's own metadata feature, not a retrieval aid.
//! * **One conversation = one isolated scope** (fresh vault / user id /
//!   container), mirroring the native one-store-per-conversation rule.
//! * **Numbers are reported as measured**, favorable or not, with raw
//!   logs. Competitor configurations aim for their best *local* setup
//!   and are documented; corrections are accepted by PR.
//!
//! External systems are driven over plain HTTP (their documented REST
//! surfaces) so this crate stays pure Rust. Endpoints and auth are
//! env-overridable to absorb MemPalace API drift without a rebuild:
//! `UNDERCROFT_VS_URL`, `UNDERCROFT_VS_ADD_PATH`, `UNDERCROFT_VS_SEARCH_PATH`,
//! `UNDERCROFT_VS_BEARER`.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::time::Instant;

/// One memory system under test. Implementations must be honest
/// pass-throughs to the system's public surface — no local re-ranking,
/// no result caching.
pub trait MemorySystem {
    fn name(&self) -> &str;
    /// Open a fresh, isolated scope for one conversation.
    fn begin_conversation(&mut self, convo: usize) -> Result<()>;
    /// Ingest one chunk of one session (`session` like `session_3`).
    fn add(&mut self, session: &str, text: &str) -> Result<()>;
    /// Ranked, deduplicated session ids for a question (best first).
    /// May return more than `k`; the scorer truncates.
    fn search_sessions(&mut self, question: &str, k: usize) -> Result<Vec<String>>;
}

/// Scoreboard returned by [`vs_eval`] — the caller prints the RAW lines.
pub struct VsScore {
    pub recall_sum: f32,
    pub evaluated: u32,
    pub per_cat: std::collections::BTreeMap<String, (f32, u32)>,
    pub ingest_secs: f32,
    pub search_secs: f32,
    pub ingest_chunks: u32,
}

/// The shared evaluation loop: byte-identical ingest text and scoring for
/// every system. `qa_limit` caps questions per conversation (0 = all) —
/// extraction-based systems pay an LLM call per ingest chunk, so subset
/// runs are the practical unit; the methodology page records the subset.
pub fn vs_eval(
    system: &mut dyn MemorySystem,
    samples: &[Value],
    k: usize,
    qa_limit: usize,
) -> Result<VsScore> {
    let mut score = VsScore {
        recall_sum: 0.0,
        evaluated: 0,
        per_cat: Default::default(),
        ingest_secs: 0.0,
        search_secs: 0.0,
        ingest_chunks: 0,
    };
    let total = samples.len();
    for (si, sample) in samples.iter().enumerate() {
        let conv = sample
            .get("conversation")
            .context("sample missing conversation")?;
        system.begin_conversation(si)?;
        // Ingest: identical construction to the native LoCoMo row — one
        // "SPEAKER said, …" line per turn, joined per session, normalized,
        // chunked with the default options.
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
            let session = format!("session_{n}");
            for chunk in
                undercroft_core::chunk_text(&body, undercroft_core::ChunkOptions::default())
            {
                system.add(&session, &chunk)?;
                score.ingest_chunks += 1;
            }
            n += 1;
        }
        score.ingest_secs += ingest_started.elapsed().as_secs_f32();

        let qa_pairs = sample
            .get("qa")
            .and_then(Value::as_array)
            .context("sample missing qa")?;
        let mut asked = 0usize;
        for qa in qa_pairs.iter() {
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
                continue; // adversarial category has no evidence
            }
            let correct: std::collections::BTreeSet<String> = evidence
                .iter()
                .filter_map(|e| {
                    let s = e.trim_start_matches('D');
                    let sess = s.split(':').next()?;
                    Some(format!("session_{sess}"))
                })
                .collect();
            let search_started = Instant::now();
            let sessions = system.search_sessions(question, k)?;
            score.search_secs += search_started.elapsed().as_secs_f32();
            let topk = &sessions[..sessions.len().min(k)];
            let recall = if correct.iter().any(|c| topk.contains(c)) {
                1.0
            } else {
                0.0
            };
            score.recall_sum += recall;
            score.evaluated += 1;
            asked += 1;
            let cat = qa
                .get("category")
                .map(|c| c.to_string().trim_matches('"').to_string())
                .unwrap_or_else(|| "?".into());
            let e = score.per_cat.entry(cat).or_insert((0.0, 0));
            e.0 += recall;
            e.1 += 1;
        }
        eprintln!(
            "  [{}] convo {}/{total} done — {} q, R@{k} so far: {:.1}%",
            system.name(),
            si + 1,
            score.evaluated,
            100.0 * score.recall_sum / score.evaluated.max(1) as f32
        );
    }
    Ok(score)
}

// -- HTTP plumbing ----------------------------------------------------------

pub struct HttpConfig {
    pub base: String,
    pub add_path: String,
    pub search_path: String,
    pub bearer: Option<String>,
}

impl HttpConfig {
    /// Resolve from CLI/env with per-system defaults. Env wins over the
    /// defaults so MemPalace API drift is absorbable without a rebuild.
    pub fn resolve(url_flag: &str, default_base: &str, add: &str, search: &str) -> Self {
        let base = if !url_flag.is_empty() {
            url_flag.to_string()
        } else {
            std::env::var("UNDERCROFT_VS_URL").unwrap_or_else(|_| default_base.to_string())
        };
        Self {
            base: base.trim_end_matches('/').to_string(),
            add_path: std::env::var("UNDERCROFT_VS_ADD_PATH").unwrap_or_else(|_| add.into()),
            search_path: std::env::var("UNDERCROFT_VS_SEARCH_PATH")
                .unwrap_or_else(|_| search.into()),
            bearer: std::env::var("UNDERCROFT_VS_BEARER").ok(),
        }
    }
}

/// POST json with generous timeouts (extraction backends run an LLM per
/// call) and a couple of retries on transport errors / 5xx.
fn post_json(cfg: &HttpConfig, path: &str, body: &Value) -> Result<Value> {
    let url = format!("{}{}", cfg.base, path);
    let mut last_err = None;
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2 * attempt as u64));
        }
        let mut req = ureq::post(&url).timeout(std::time::Duration::from_secs(180));
        if let Some(b) = &cfg.bearer {
            req = req.set("Authorization", &format!("Bearer {b}"));
        }
        match req.send_json(body.clone()) {
            Ok(resp) => {
                return resp
                    .into_json::<Value>()
                    .or(Ok(Value::Null))
                    .map_err(|e: std::io::Error| anyhow::anyhow!("{url}: {e}"))
            }
            Err(ureq::Error::Status(code, resp)) if code < 500 => {
                let text = resp.into_string().unwrap_or_default();
                anyhow::bail!("{url}: HTTP {code}: {text}");
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(anyhow::anyhow!(
        "{url}: {}",
        last_err.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// Pull ranked session ids out of a search response: accepts the result
/// array at the root, under `results`, or under `memories`; each item's
/// session comes from `metadata.session` (falling back to
/// `metadata.metadata.session`, seen in some mem0 builds). Order is
/// preserved; duplicates collapse to first occurrence.
pub fn sessions_from_results(v: &Value) -> Vec<String> {
    let items = v
        .as_array()
        .or_else(|| v.get("results").and_then(Value::as_array))
        .or_else(|| v.get("memories").and_then(Value::as_array));
    let mut out: Vec<String> = Vec::new();
    if let Some(items) = items {
        for item in items {
            let session = item
                .get("metadata")
                .and_then(|m| m.get("session"))
                .and_then(Value::as_str)
                .or_else(|| {
                    item.get("metadata")
                        .and_then(|m| m.get("metadata"))
                        .and_then(|m| m.get("session"))
                        .and_then(Value::as_str)
                });
            if let Some(s) = session {
                if !out.iter().any(|x| x == s) {
                    out.push(s.to_string());
                }
            }
        }
    }
    out
}

// -- mem0 (OpenMemory, their flagship local server) -------------------------

/// mem0 local = OpenMemory (`mem0/openmemory-mcp`). Writes go through its
/// REST surface (`POST /api/v1/memories/` — carries `metadata`, triggers
/// server-side LLM extraction); semantic search is only exposed through
/// its MCP tools, so the adapter speaks MCP over the SSE transport
/// (`GET /mcp/{client}/sse/{user}` + JSON-RPC posts) exactly like any
/// MCP client would. Per-conversation isolation uses the server's own
/// `delete_all_memories` tool (single provisioned user). Search results
/// map to sessions via each memory's stored metadata (fetched by id over
/// REST and cached — the tool response carries ids, not metadata).
type SseReader = std::io::BufReader<Box<dyn std::io::Read + Send + Sync + 'static>>;
/// A live MCP session: (SSE line reader, message-post URL, next JSON-RPC id).
type McpSession = (SseReader, String, u64);

pub struct Mem0 {
    base: String,
    user: String,
    agent: ureq::Agent,
    mcp: Option<McpSession>,
    /// memory id → session (metadata cache).
    sessions: std::collections::HashMap<String, String>,
}

impl Mem0 {
    pub fn new(url_flag: &str) -> Self {
        let base = if !url_flag.is_empty() {
            url_flag.trim_end_matches('/').to_string()
        } else {
            std::env::var("UNDERCROFT_VS_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8765".into())
                .trim_end_matches('/')
                .to_string()
        };
        Self {
            base,
            user: std::env::var("UNDERCROFT_VS_MEM0_USER").unwrap_or_else(|_| "bench".into()),
            agent: ureq::AgentBuilder::new()
                .timeout_read(std::time::Duration::from_secs(600))
                .build(),
            mcp: None,
            sessions: std::collections::HashMap::new(),
        }
    }

    /// Read SSE frames until one complete event arrives; returns
    /// (event_name, data).
    fn sse_next(reader: &mut SseReader) -> Result<(String, String)> {
        use std::io::BufRead;
        let (mut event, mut data) = (String::new(), String::new());
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                anyhow::bail!("SSE stream closed");
            }
            let line = line.trim_end();
            if line.is_empty() {
                if !data.is_empty() {
                    return Ok((event, data));
                }
                continue;
            }
            if let Some(v) = line.strip_prefix("event:") {
                event = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(v.trim());
            }
        }
    }

    fn mcp_ensure(&mut self) -> Result<()> {
        if self.mcp.is_some() {
            return Ok(());
        }
        let resp = self
            .agent
            .get(&format!("{}/mcp/benchvs/sse/{}", self.base, self.user))
            .call()
            .map_err(|e| anyhow::anyhow!("MCP SSE connect: {e}"))?;
        let mut reader = std::io::BufReader::new(resp.into_reader());
        let (event, endpoint) = Self::sse_next(&mut reader)?;
        anyhow::ensure!(event == "endpoint", "expected endpoint event, got {event}");
        let post_url = format!("{}{}", self.base, endpoint);
        self.mcp = Some((reader, post_url, 1));
        // MCP handshake.
        self.mcp_send(json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": { "name": "undercroft-bench-vs", "version": "0" } }
        }))?;
        self.mcp_wait(0)?;
        self.mcp_send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;
        Ok(())
    }

    fn mcp_send(&mut self, msg: Value) -> Result<()> {
        let (_, url, _) = self.mcp.as_ref().context("MCP session not open")?;
        let url = url.clone();
        self.agent
            .post(&url)
            .send_json(msg)
            .map_err(|e| anyhow::anyhow!("MCP post: {e}"))?;
        Ok(())
    }

    /// Read SSE messages until the JSON-RPC response with `id` arrives.
    fn mcp_wait(&mut self, id: u64) -> Result<Value> {
        let (reader, _, _) = self.mcp.as_mut().context("MCP session not open")?;
        loop {
            let (_, data) = Self::sse_next(reader)?;
            let Ok(v) = serde_json::from_str::<Value>(&data) else {
                continue;
            };
            if v.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(err) = v.get("error") {
                    anyhow::bail!("MCP error: {err}");
                }
                return Ok(v.get("result").cloned().unwrap_or(Value::Null));
            }
        }
    }

    /// Idempotent MCP tool call with bounded reconnect-and-retry. The
    /// SSE session runs for hours; a hang or drop surfaces as one
    /// failed call, and both callers (`delete_all_memories`,
    /// `search_memory`) are safe to re-issue on a fresh session — both
    /// multi-hour runs so far died on the single un-retried call at the
    /// conversation boundary.
    fn mcp_tool_retry(&mut self, name: &str, args: Value) -> Result<Value> {
        let mut last = String::new();
        for attempt in 0..4 {
            if attempt > 0 {
                eprintln!("  [mem0] {name} retry {attempt} after: {last}");
                self.mcp = None;
                std::thread::sleep(std::time::Duration::from_secs(10 * attempt as u64));
            }
            match self.mcp_tool(name, args.clone()) {
                Ok(v) => return Ok(v),
                Err(e) => last = e.to_string(),
            }
        }
        anyhow::bail!("mem0 {name} (4 attempts): {last}")
    }

    fn mcp_tool(&mut self, name: &str, args: Value) -> Result<Value> {
        self.mcp_ensure()?;
        let id = {
            let (_, _, next) = self.mcp.as_mut().context("MCP session not open")?;
            let id = *next;
            *next += 1;
            id
        };
        self.mcp_send(json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": args }
        }))?;
        let result = self.mcp_wait(id)?;
        // Tool results carry their payload as text content.
        let text = result
            .get("content")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|c| c.get("text"))
            .and_then(Value::as_str)
            .unwrap_or("");
        Ok(serde_json::from_str(text).unwrap_or(Value::String(text.to_string())))
    }

    /// Session id for a memory id, via REST metadata (cached).
    fn session_of(&mut self, memory_id: &str) -> Option<String> {
        if let Some(s) = self.sessions.get(memory_id) {
            return Some(s.clone());
        }
        let url = format!("{}/api/v1/memories/{}", self.base, memory_id);
        let v: Value = self.agent.get(&url).call().ok()?.into_json().ok()?;
        let s = v
            .get("metadata_")
            .or_else(|| v.get("metadata"))
            .and_then(|m| m.get("session"))
            .and_then(Value::as_str)?
            .to_string();
        self.sessions.insert(memory_id.to_string(), s.clone());
        Some(s)
    }
}

impl MemorySystem for Mem0 {
    fn name(&self) -> &str {
        "mem0"
    }

    fn begin_conversation(&mut self, _convo: usize) -> Result<()> {
        // The server's own wipe tool — conversations run sequentially in
        // one provisioned user, cleaned between (mirrors fresh-store
        // isolation for a single-tenant surface).
        self.mcp_tool_retry("delete_all_memories", json!({}))?;
        self.sessions.clear();
        Ok(())
    }

    fn add(&mut self, session: &str, text: &str) -> Result<()> {
        let body = json!({
            "user_id": self.user,
            "text": text,
            "metadata": { "session": session },
            "app": "bench",
            "infer": true,
        });
        // A single hung/refused call must not kill a multi-hour run:
        // retry transport failures with backoff (a duplicate re-extraction
        // on the server is the worst case — content-neutral, and honest:
        // the retry count is bounded and identical for every system).
        let mut last = String::new();
        for attempt in 0..4 {
            if attempt > 0 {
                eprintln!("  [mem0] add retry {attempt} after: {last}");
                std::thread::sleep(std::time::Duration::from_secs(10 * attempt as u64));
            }
            match self
                .agent
                .post(&format!("{}/api/v1/memories/", self.base))
                .send_json(body.clone())
            {
                Ok(resp) => {
                    let v = resp.into_json::<Value>().unwrap_or(Value::Null);
                    match v.get("error") {
                        Some(err) => last = err.to_string(),
                        None => return Ok(()),
                    }
                }
                Err(e) => last = e.to_string(),
            }
        }
        anyhow::bail!("mem0 add (4 attempts): {last}")
    }

    fn search_sessions(&mut self, question: &str, _k: usize) -> Result<Vec<String>> {
        // Same resilience as `add`: a dropped SSE session re-opens with
        // bounded retries before the question is declared failed.
        let result = self.mcp_tool_retry("search_memory", json!({ "query": question }))?;
        let items = result
            .as_array()
            .cloned()
            .or_else(|| result.get("results").and_then(Value::as_array).cloned())
            .unwrap_or_default();
        let mut out: Vec<String> = Vec::new();
        for item in &items {
            let sess = item
                .get("metadata")
                .and_then(|m| m.get("session"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    item.get("id")
                        .and_then(Value::as_str)
                        .and_then(|id| self.session_of(id))
                });
            if let Some(s) = sess {
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
        Ok(out)
    }
}

// -- Supermemory (self-hosted) ----------------------------------------------

/// Supermemory's REST surface: `POST /v3/memories` with `content` +
/// `containerTag` + `metadata`, `POST /v3/search` with `q` +
/// `containerTag`.
pub struct Supermemory {
    cfg: HttpConfig,
    container: String,
}

impl Supermemory {
    pub fn new(url_flag: &str) -> Self {
        Self {
            cfg: HttpConfig::resolve(
                url_flag,
                "http://127.0.0.1:8080",
                "/v3/memories",
                "/v3/search",
            ),
            container: String::new(),
        }
    }
}

impl MemorySystem for Supermemory {
    fn name(&self) -> &str {
        "supermemory"
    }

    fn begin_conversation(&mut self, convo: usize) -> Result<()> {
        self.container = format!("vs-convo-{convo}");
        Ok(())
    }

    fn add(&mut self, session: &str, text: &str) -> Result<()> {
        let body = json!({
            "content": text,
            "containerTag": self.container,
            "metadata": { "session": session },
        });
        post_json(&self.cfg, &self.cfg.add_path.clone(), &body)?;
        Ok(())
    }

    fn search_sessions(&mut self, question: &str, k: usize) -> Result<Vec<String>> {
        let body = json!({
            "q": question,
            "containerTag": self.container,
            "limit": k * 6,
        });
        let resp = post_json(&self.cfg, &self.cfg.search_path.clone(), &body)?;
        Ok(sessions_from_results(&resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-process stand-in: remembers (session, chunk) pairs, "searches"
    /// by naive term overlap. Proves the eval loop scores through the
    /// trait exactly like the native LoCoMo scorer (same fixture shape).
    struct Fake {
        rows: Vec<(String, String)>,
    }

    impl MemorySystem for Fake {
        fn name(&self) -> &str {
            "fake"
        }
        fn begin_conversation(&mut self, _convo: usize) -> Result<()> {
            self.rows.clear();
            Ok(())
        }
        fn add(&mut self, session: &str, text: &str) -> Result<()> {
            self.rows.push((session.into(), text.to_lowercase()));
            Ok(())
        }
        fn search_sessions(&mut self, question: &str, _k: usize) -> Result<Vec<String>> {
            let terms: Vec<String> = question
                .to_lowercase()
                .split_whitespace()
                .map(str::to_string)
                .collect();
            let mut scored: Vec<(usize, &String)> = self
                .rows
                .iter()
                .map(|(s, t)| (terms.iter().filter(|w| t.contains(*w)).count(), s))
                .collect();
            scored.sort_by(|a, b| b.0.cmp(&a.0));
            let mut out: Vec<String> = Vec::new();
            for (_, s) in scored {
                if !out.contains(s) {
                    out.push(s.clone());
                }
            }
            Ok(out)
        }
    }

    #[test]
    fn vs_eval_scores_the_locomo_fixture_through_the_trait() {
        let sample = serde_json::json!({
            "conversation": {
                "session_1": [
                    { "speaker": "Ana", "text": "I adopted a golden retriever named Biscuit." },
                    { "speaker": "Ben", "text": "Congrats!" }
                ],
                "session_2": [
                    { "speaker": "Ana", "text": "We moved the launch to March." }
                ]
            },
            "qa": [
                { "question": "what dog did Ana adopt biscuit golden retriever",
                  "evidence": ["D1:1"], "category": 1 },
                { "question": "when is the launch march moved",
                  "evidence": ["D2:1"], "category": 2 },
                { "question": "unanswerable adversarial", "evidence": [], "category": 5 }
            ]
        });
        let mut sys = Fake { rows: Vec::new() };
        let score = vs_eval(&mut sys, std::slice::from_ref(&sample), 10, 0).unwrap();
        assert_eq!(score.evaluated, 2, "no-evidence QA is skipped");
        assert_eq!(score.recall_sum, 2.0, "both answerable questions hit");
        assert!(score.ingest_chunks > 0);
    }

    #[test]
    fn sessions_parse_from_common_response_shapes() {
        let root_array = serde_json::json!([
            { "metadata": { "session": "session_2" } },
            { "metadata": { "session": "session_1" } },
            { "metadata": { "session": "session_2" } }
        ]);
        assert_eq!(
            sessions_from_results(&root_array),
            vec!["session_2", "session_1"]
        );
        let nested = serde_json::json!({
            "results": [
                { "memory": "a fact", "metadata": { "metadata": { "session": "session_7" } } }
            ]
        });
        assert_eq!(sessions_from_results(&nested), vec!["session_7"]);
        assert!(sessions_from_results(&serde_json::json!({})).is_empty());
    }
}
