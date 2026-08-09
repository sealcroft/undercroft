//! Local-LLM client for optional refinement, ported from mempalace's
//! `llm_client.py` / `llm_refine.py` design.
//!
//! Rules inherited from the mission:
//!
//! * **Local runtimes only by default** — Ollama, llama.cpp server,
//!   LM Studio, vLLM: anything on the user's machine speaking either the
//!   Ollama native API or the OpenAI-compatible chat API. Nothing is ever
//!   contacted unless `UNDERCROFT_LLM_URL` is explicitly set.
//! * **Never touches the write path of verbatim content.** Refinement
//!   only *adds* derived structure: entities, knowledge-graph triples,
//!   topic labels. The drawer text is sacred.
//!
//! Extraction prompts force JSON output and parsing is defensive — a
//! chatty model that wraps JSON in prose still parses.

pub mod advisor;
pub mod embed;

pub use embed::HttpEmbedder;

use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("UNDERCROFT_LLM_URL is not set — refinement requires a local LLM runtime")]
    NotConfigured,
    #[error("llm http error: {0}")]
    Http(String),
    #[error("llm returned unusable output: {0}")]
    BadOutput(String),
    #[error("refused: {0}")]
    Refused(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKind {
    /// Ollama native `/api/chat`
    Ollama,
    /// OpenAI-compatible `/v1/chat/completions` (llama.cpp, LM Studio, vLLM)
    OpenAi,
}

pub struct LlmClient {
    base: String,
    model: String,
    kind: ApiKind,
    /// Optional bearer credential for the runtime. Empty for every local
    /// runtime (they take no auth); set only when the operator has pointed
    /// `UNDERCROFT_LLM_URL` at a gateway that demands one.
    key: String,
    agent: ureq::Agent,
}

impl LlmClient {
    pub fn new(base_url: &str, model: &str, kind: ApiKind) -> Result<Self, LlmError> {
        Self::with_key(base_url, model, kind, "")
    }

    /// As [`LlmClient::new`], with a bearer credential sent as
    /// `Authorization: Bearer <key>` on every request. An empty key sends
    /// no header at all — the local-runtime default.
    ///
    /// **Transport: TLS or loopback, nothing else** — the same refusal as
    /// the served embedder (operator decision 2026-08-03, extended here
    /// 2026-08-04): every consumer of this client sends drawer content to
    /// the endpoint (`refine` sends it verbatim, the admission advisor
    /// sends candidates), so cleartext http beyond loopback is refused at
    /// construction with no override. `UNDERCROFT_LLM_CA` declares a
    /// self-signed root as a PIN — the file's certificates become the
    /// ONLY roots this client trusts, and every failure shape refuses
    /// rather than falling back (un-pinning silently is the failure
    /// mode). The compose `embeddings-tls` terminator shape works here
    /// too: any TLS front plus a declared root.
    pub fn with_key(
        base_url: &str,
        model: &str,
        kind: ApiKind,
        key: &str,
    ) -> Result<Self, LlmError> {
        let base = base_url.trim_end_matches('/').to_string();
        let loopback = crate::embed::is_loopback(&base);
        let tls = base.starts_with("https://");
        if !tls && !loopback {
            return Err(LlmError::Refused(format!(
                "cleartext http to non-loopback {base} — drawer content would \
                 cross the network readable by anyone on the path, and no \
                 override exists. Serve the endpoint over TLS (the compose \
                 `embeddings-tls` terminator shape works) and declare a \
                 self-signed root with UNDERCROFT_LLM_CA=<pem>."
            )));
        }
        if !loopback {
            undercroft_obs::diag_warn!(
                "llm: {model} via {base} — TLS protects the wire, but the \
                 ENDPOINT still reads the content it is sent in plaintext. \
                 Sealing protects a vault at rest, not content handed to \
                 another process."
            );
        }
        // **This crate stopped building its own client.** The transport
        // policy lives in `undercroft-net` — which was EXTRACTED FROM this
        // crate — and two copies of a rule are two places for it to drift.
        // They had: the local copy applied a declared pin only `if tls`, so
        // a loopback-http base never read or validated the CA file while the
        // shared path does, and it treated `UNDERCROFT_LLM_CA=""` as no
        // pin at all — silently un-pinning exactly when the operator
        // believes they pinned. It also re-read and re-parsed the PEM on
        // every construction. One call now, resolved once per process.
        let agent = undercroft_net::agent_from_env(
            "the LLM endpoint",
            &base,
            "UNDERCROFT_LLM_CA",
            std::time::Duration::from_secs(120),
        )
        .map_err(|e| LlmError::Refused(e.to_string()))?;
        Ok(Self {
            base,
            model: model.to_string(),
            kind,
            key: key.to_string(),
            agent,
        })
    }

    /// Build from `UNDERCROFT_LLM_URL`, `UNDERCROFT_LLM_MODEL`, and optional
    /// `UNDERCROFT_LLM_API` (`ollama` | `openai`; default guesses `openai`
    /// when the URL path contains `/v1`, else `ollama`).
    ///
    /// `UNDERCROFT_LLM_KEY` is optional and unset by default: local runtimes
    /// take no credential, and leaving it unset keeps the request
    /// header-for-header what it has always been. Set it only to reach a
    /// runtime behind an authenticating gateway — which, unlike the local
    /// default, means drawer text leaves the machine.
    pub fn from_env() -> Result<Self, LlmError> {
        let base = std::env::var("UNDERCROFT_LLM_URL").map_err(|_| LlmError::NotConfigured)?;
        let model =
            std::env::var("UNDERCROFT_LLM_MODEL").unwrap_or_else(|_| "llama3.2".to_string());
        let kind = match std::env::var("UNDERCROFT_LLM_API").ok().as_deref() {
            Some("openai") => ApiKind::OpenAi,
            Some("ollama") => ApiKind::Ollama,
            _ if base.contains("/v1") => ApiKind::OpenAi,
            _ => ApiKind::Ollama,
        };
        let key = std::env::var("UNDERCROFT_LLM_KEY").unwrap_or_default();
        Self::with_key(&base, &model, kind, &key)
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// One chat completion, deterministic settings (temperature 0).
    pub fn complete(&self, system: &str, user: &str) -> Result<String, LlmError> {
        let (url, body) = match self.kind {
            ApiKind::Ollama => (
                format!("{}/api/chat", self.base),
                json!({
                    "model": self.model,
                    "stream": false,
                    "options": { "temperature": 0 },
                    "messages": [
                        { "role": "system", "content": system },
                        { "role": "user", "content": user }
                    ]
                }),
            ),
            ApiKind::OpenAi => (
                format!("{}/chat/completions", self.base),
                json!({
                    "model": self.model,
                    "temperature": 0,
                    "messages": [
                        { "role": "system", "content": system },
                        { "role": "user", "content": user }
                    ]
                }),
            ),
        };
        let mut req = self.agent.post(&url);
        if !self.key.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.key));
        }
        let resp: Value = req
            .send_json(body)
            .map_err(|e| LlmError::Http(e.to_string()))?
            .into_json()
            .map_err(|e| LlmError::BadOutput(e.to_string()))?;
        let text = match self.kind {
            ApiKind::Ollama => resp.pointer("/message/content").and_then(Value::as_str),
            ApiKind::OpenAi => resp
                .pointer("/choices/0/message/content")
                .and_then(Value::as_str),
        };
        text.map(str::to_string)
            .ok_or_else(|| LlmError::BadOutput(format!("no content field in {resp}")))
    }
}

// ---------------------------------------------------------------------------
// Extraction tasks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ExtractedEntity {
    pub name: String,
    #[serde(rename = "type", default = "unknown_type")]
    pub entity_type: String,
}

fn unknown_type() -> String {
    "unknown".into()
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ExtractedTriple {
    pub subject: String,
    pub predicate: String,
    pub object: String,
    /// The words in the note that say *when* this fact was established,
    /// copied verbatim — "three months ago", "last May". **Not a date.**
    ///
    /// The model is asked to point, not to compute: a span can be checked
    /// against the note it supposedly came from, and a date cannot. Whatever
    /// arrives here is verified and resolved by
    /// `undercroft_core::temporal::resolve_claimed_span`, which rejects
    /// anything the note does not literally contain. A model that answers
    /// with a date instead of a quotation therefore contributes nothing,
    /// which is the intended failure.
    #[serde(default)]
    pub when: Option<String>,
    /// The words in the note that support this fact, copied verbatim — again
    /// **not** a claim, a quotation.
    ///
    /// Checked by `undercroft_core::support::Support::evaluate`, which keeps
    /// the spans the note really contains. A fact with no quotable support
    /// is not thereby wrong: "Leeds is in the United Kingdom" is true and
    /// useful and simply is not in the note. The check records which of the
    /// two a fact is, and never asks the model to grade itself.
    #[serde(default)]
    pub quote: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ExtractedMemory {
    #[serde(rename = "type", default = "unknown_type")]
    pub memory_type: String,
    pub content: String,
}

/// Pull the first JSON array out of possibly-chatty model output.
pub fn extract_json_array(text: &str) -> Result<Value, LlmError> {
    let start = text
        .find('[')
        .ok_or_else(|| LlmError::BadOutput("no JSON array".into()))?;
    let end = text
        .rfind(']')
        .ok_or_else(|| LlmError::BadOutput("unterminated array".into()))?;
    if end < start {
        return Err(LlmError::BadOutput("malformed array".into()));
    }
    serde_json::from_str(&text[start..=end]).map_err(|e| LlmError::BadOutput(e.to_string()))
}

// --- Lenient extraction --------------------------------------------------
//
// Small local models emit imperfect JSON at a non-trivial rate (trailing
// commas, an array where a string was asked for, a missing field, an
// unterminated array). Treating any of that as a hard error and dropping
// the whole note's output is *our* fragility, not the model's — and it
// silently thins downstream recall. These helpers repair and salvage
// deterministically (no extra model calls) so a malformed element costs
// itself, not the whole note.

/// Coerce a JSON value to a plain string: strings pass through,
/// numbers/bools stringify, an array joins with ", " (models sometimes
/// answer a scalar field with a list). Null/object → `None` (unusable).
fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(a) => {
            let parts: Vec<String> = a.iter().filter_map(value_to_string).collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        _ => None,
    }
}

/// JSON-repair pass (dependency-free): drop trailing commas before `]`/`}`,
/// the most common model defect. Quote-aware so commas inside string values
/// are untouched; UTF-8-safe (only standalone ASCII commas are removed).
fn strip_trailing_commas(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let (mut in_str, mut esc, mut i) = (false, false, 0usize);
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == b',' {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len() && (b[j] == b']' || b[j] == b'}') {
                i += 1; // skip the trailing comma
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Last-resort salvage: scan for balanced top-level `{...}` objects and
/// parse each independently, so a syntactically broken *array* still yields
/// its intact objects. Quote-aware brace matching.
fn salvage_objects(s: &str) -> Vec<Value> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let (mut depth, mut start, mut in_str, mut esc, mut i) = (0usize, 0usize, false, false, 0usize);
    while i < b.len() {
        let c = b[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == b'{' {
            if depth == 0 {
                start = i;
            }
            depth += 1;
        } else if c == b'}' && depth > 0 {
            depth -= 1;
            if depth == 0 {
                if let Ok(v) = serde_json::from_str::<Value>(&s[start..=i]) {
                    out.push(v);
                }
            }
        }
        i += 1;
    }
    out
}

/// Best-effort array-of-objects from possibly-chatty/malformed output:
/// slice the outermost `[...]`, JSON-repair, parse whole; on failure,
/// salvage individual objects. Never errors — returns what it can.
pub fn lenient_objects(out: &str) -> Vec<Value> {
    let sliced = match (out.find('['), out.rfind(']')) {
        (Some(a), Some(b)) if b > a => &out[a..=b],
        _ => out,
    };
    let repaired = strip_trailing_commas(sliced);
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&repaired) {
        return items;
    }
    salvage_objects(&repaired)
}

/// Triples parsed leniently from raw model output: fields coerced to
/// strings, all three required, malformed elements skipped (not fatal).
pub fn triples_from_output(out: &str) -> Vec<ExtractedTriple> {
    lenient_objects(out)
        .iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            Some(ExtractedTriple {
                subject: value_to_string(o.get("subject")?)?,
                predicate: value_to_string(o.get("predicate")?)?,
                object: value_to_string(o.get("object")?)?,
                // Optional and never fatal: a model that omits it, or emits
                // null or an empty string, simply dates its fact from the
                // note as before.
                when: o
                    .get("when")
                    .and_then(value_to_string)
                    .filter(|s| !s.trim().is_empty()),
                quote: o
                    .get("quote")
                    .and_then(value_to_string)
                    .filter(|s| !s.trim().is_empty()),
            })
        })
        .collect()
}

/// Entities parsed leniently (name required; type defaults to unknown).
pub fn entities_from_output(out: &str) -> Vec<ExtractedEntity> {
    lenient_objects(out)
        .iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            Some(ExtractedEntity {
                name: value_to_string(o.get("name")?)?,
                entity_type: o
                    .get("type")
                    .and_then(value_to_string)
                    .unwrap_or_else(unknown_type),
            })
        })
        .collect()
}

/// Memories parsed leniently (content required; type defaults to unknown).
pub fn memories_from_output(out: &str) -> Vec<ExtractedMemory> {
    lenient_objects(out)
        .iter()
        .filter_map(|v| {
            let o = v.as_object()?;
            Some(ExtractedMemory {
                memory_type: o
                    .get("type")
                    .and_then(value_to_string)
                    .unwrap_or_else(unknown_type),
                content: value_to_string(o.get("content")?)?,
            })
        })
        .collect()
}

const ENTITY_SYSTEM: &str = "You extract named entities from notes. Reply with ONLY a JSON array \
of objects: [{\"name\": \"...\", \"type\": \"person|organization|project|place|unknown\"}]. \
No prose, no markdown fences.";

const TRIPLE_SYSTEM: &str = "You extract factual relationships from notes as knowledge-graph \
triples. Reply with ONLY a JSON array of objects: [{\"subject\": \"...\", \"predicate\": \
\"snake_case_relation\", \"object\": \"...\", \"when\": \"...\", \"quote\": \"...\"}]. Only \
durable facts (roles, locations, ownership, preferences, decisions) — no ephemera. \
Background knowledge that connects the note to what you already know is welcome. \
For \"when\", COPY THE EXACT WORDS from the note that say when the fact was established — \
\"three months ago\", \"last May\", \"on 2023-05-07\". For \"quote\", COPY THE EXACT WORDS \
from the note that state this fact. Copy both character for character from the note. Do NOT \
rewrite them, do NOT work out a date, and use null when the note does not say it — a fact you \
knew rather than read is still wanted, it just has no quote. No prose, no markdown fences.";

const MEMORY_SYSTEM: &str = "You extract the durable memories worth keeping from a note: \
decisions made, stated preferences, plans, and stable facts. Reply with ONLY a JSON array of \
objects: [{\"type\": \"decision|preference|plan|fact|event\", \"content\": \"one \
self-contained sentence per memory, in the note's language\"}]. Skip small talk and \
transient detail. No prose, no markdown fences.";

impl LlmClient {
    pub fn extract_entities(&self, text: &str) -> Result<Vec<ExtractedEntity>, LlmError> {
        Ok(entities_from_output(&self.complete(ENTITY_SYSTEM, text)?))
    }

    pub fn extract_triples(&self, text: &str) -> Result<Vec<ExtractedTriple>, LlmError> {
        Ok(triples_from_output(&self.complete(TRIPLE_SYSTEM, text)?))
    }

    pub fn extract_memories(&self, text: &str) -> Result<Vec<ExtractedMemory>, LlmError> {
        Ok(memories_from_output(&self.complete(MEMORY_SYSTEM, text)?))
    }

    /// Classify text into one of the given labels (used by room
    /// classification and the calibration eval).
    pub fn classify(&self, text: &str, labels: &[String]) -> Result<String, LlmError> {
        let system = format!(
            "Classify the user's text into exactly one of these labels: {}. \
             Reply with ONLY the label, nothing else.",
            labels.join(", ")
        );
        let out = self.complete(&system, text)?;
        let cleaned = out
            .trim()
            .trim_matches(|c| c == '"' || c == '`' || c == '.')
            .to_string();
        // Snap to the closest provided label (models love to decorate).
        let lower = cleaned.to_lowercase();
        for l in labels {
            if lower == l.to_lowercase() || lower.contains(&l.to_lowercase()) {
                return Ok(l.clone());
            }
        }
        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Stub LLM server: answers every chat request with a canned body.
    fn stub_server(reply: &'static str, kind: ApiKind) -> (String, Arc<tiny_http::Server>) {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = server.server_addr().to_ip().unwrap().port();
        let s2 = server.clone();
        std::thread::spawn(move || {
            for req in s2.incoming_requests() {
                let body = match kind {
                    ApiKind::Ollama => {
                        json!({ "message": { "role": "assistant", "content": reply } })
                    }
                    ApiKind::OpenAi => json!({
                        "choices": [ { "message": { "role": "assistant", "content": reply } } ]
                    }),
                };
                let _ = req.respond(
                    tiny_http::Response::from_string(body.to_string()).with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"application/json"[..],
                        )
                        .unwrap(),
                    ),
                );
            }
        });
        (format!("http://127.0.0.1:{port}"), server)
    }

    #[test]
    fn ollama_roundtrip_and_entity_parsing() {
        let (url, _s) = stub_server(
            r#"Sure! Here you go: [{"name": "Alice", "type": "person"}, {"name": "Acme", "type": "organization"}]"#,
            ApiKind::Ollama,
        );
        let client = LlmClient::new(&url, "test-model", ApiKind::Ollama).unwrap();
        let ents = client.extract_entities("Alice works at Acme").unwrap();
        assert_eq!(ents.len(), 2);
        assert_eq!(ents[0].name, "Alice");
        assert_eq!(ents[1].entity_type, "organization");
    }

    #[test]
    fn openai_roundtrip_and_triples() {
        let (url, _s) = stub_server(
            r#"[{"subject": "alice", "predicate": "works_at", "object": "acme"}]"#,
            ApiKind::OpenAi,
        );
        let client = LlmClient::new(&url, "test-model", ApiKind::OpenAi).unwrap();
        let triples = client.extract_triples("Alice works at Acme").unwrap();
        assert_eq!(triples[0].predicate, "works_at");
    }

    /// The transport policy, extended from the embedder to every LLM
    /// consumer (refine sends drawer content verbatim, the advisor sends
    /// candidates): cleartext beyond loopback refuses at construction
    /// with the fix named, loopback constructs as before (every
    /// stub-server test in this module is the standing proof).
    #[test]
    fn llm_client_refuses_cleartext_to_a_non_loopback_host() {
        let err = match LlmClient::new("http://llm-box:11434", "m", ApiKind::Ollama) {
            Err(e) => e,
            Ok(_) => panic!("a non-loopback http URL must refuse at construction"),
        };
        let msg = err.to_string();
        for needle in ["cleartext", "TLS", "UNDERCROFT_LLM_CA", "no override"] {
            assert!(msg.contains(needle), "refusal must carry {needle:?}: {msg}");
        }
    }

    #[test]
    fn classify_snaps_to_label() {
        let (url, _s) = stub_server("The label is: Question.", ApiKind::Ollama);
        let client = LlmClient::new(&url, "m", ApiKind::Ollama).unwrap();
        let labels: Vec<String> = ["question", "command"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            client.classify("what time is it?", &labels).unwrap(),
            "question"
        );
    }

    #[test]
    fn json_array_extraction_is_defensive() {
        assert!(extract_json_array("no array here").is_err());
        let v = extract_json_array("prefix [1, 2] suffix").unwrap();
        assert_eq!(v, json!([1, 2]));
    }

    #[test]
    fn lenient_triples_recover_from_real_model_defects() {
        // clean output — the happy path still works
        assert_eq!(
            triples_from_output(r#"[{"subject":"a","predicate":"knows","object":"b"}]"#).len(),
            1
        );
        // array where a string was asked for → coerced by joining
        let t = triples_from_output(
            r#"[{"subject":"ana","predicate":"likes","object":["tea","coffee"]}]"#,
        );
        assert_eq!(t[0].object, "tea, coffee");
        // one object missing a field → that element skipped, others kept
        let t = triples_from_output(
            r#"[{"subject":"a","predicate":"p","object":"o"},
                {"subject":"x","predicate":"y"},
                {"subject":"c","predicate":"q","object":"d"}]"#,
        );
        assert_eq!(t.len(), 2, "the incomplete triple is skipped, not fatal");
        // trailing comma (repair pass)
        assert_eq!(
            triples_from_output(r#"[{"subject":"a","predicate":"p","object":"o"},]"#).len(),
            1
        );
        // markdown fences + prose around the array
        assert_eq!(
            triples_from_output(
                "Sure:\n```json\n[{\"subject\":\"a\",\"predicate\":\"p\",\"object\":\"o\"}]\n```"
            )
            .len(),
            1
        );
        // syntactically broken *array* (unterminated) → salvage the intact object
        let t = triples_from_output(
            r#"[{"subject":"a","predicate":"p","object":"o"}, {"subject":"d","predicate":"#,
        );
        assert_eq!(t.len(), 1, "the one complete object is salvaged");
        // nothing usable → empty, never an error
        assert!(triples_from_output("I could not find any facts.").is_empty());
    }

    /// `when` is optional in every direction: a model that omits it, nulls
    /// it, or empties it dates its fact from the note, exactly as before.
    /// Whatever it *does* send is a quotation to be checked downstream, not
    /// a date to be believed — see `temporal::resolve_claimed_span`.
    #[test]
    fn triples_carry_an_optional_when_span() {
        let t = triples_from_output(
            r#"[{"subject":"ana","predicate":"quit","object":"smoking","when":"three months ago"}]"#,
        );
        assert_eq!(t[0].when.as_deref(), Some("three months ago"));

        for out in [
            r#"[{"subject":"a","predicate":"p","object":"o"}]"#,
            r#"[{"subject":"a","predicate":"p","object":"o","when":null}]"#,
            r#"[{"subject":"a","predicate":"p","object":"o","when":""}]"#,
            r#"[{"subject":"a","predicate":"p","object":"o","when":"   "}]"#,
        ] {
            let t = triples_from_output(out);
            assert_eq!(t.len(), 1, "{out}");
            assert!(t[0].when.is_none(), "{out}");
        }
    }

    #[test]
    fn lenient_entities_and_memories() {
        let e = entities_from_output(r#"[{"name":"Acme"},{"type":"person","name":"Ana"}]"#);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].entity_type, "unknown"); // defaulted
        let m = memories_from_output(r#"[{"content":"launch moved to March"},]"#);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn from_env_requires_url() {
        std::env::remove_var("UNDERCROFT_LLM_URL");
        assert!(matches!(
            LlmClient::from_env(),
            Err(LlmError::NotConfigured)
        ));
    }
}
