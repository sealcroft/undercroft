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
    agent: ureq::Agent,
}

impl LlmClient {
    pub fn new(base_url: &str, model: &str, kind: ApiKind) -> Self {
        Self {
            base: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            kind,
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(120))
                .build(),
        }
    }

    /// Build from `UNDERCROFT_LLM_URL`, `UNDERCROFT_LLM_MODEL`, and optional
    /// `UNDERCROFT_LLM_API` (`ollama` | `openai`; default guesses `openai`
    /// when the URL path contains `/v1`, else `ollama`).
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
        Ok(Self::new(&base, &model, kind))
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
        let resp: Value = self
            .agent
            .post(&url)
            .send_json(body)
            .map_err(|e| LlmError::Http(e.to_string()))?
            .into_json()
            .map_err(|e| LlmError::BadOutput(e.to_string()))?;
        let text = match self.kind {
            ApiKind::Ollama => resp.pointer("/message/content").and_then(Value::as_str),
            ApiKind::OpenAi => {
                resp.pointer("/choices/0/message/content").and_then(Value::as_str)
            }
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
}

/// Pull the first JSON array out of possibly-chatty model output.
pub fn extract_json_array(text: &str) -> Result<Value, LlmError> {
    let start = text.find('[').ok_or_else(|| LlmError::BadOutput("no JSON array".into()))?;
    let end = text.rfind(']').ok_or_else(|| LlmError::BadOutput("unterminated array".into()))?;
    if end < start {
        return Err(LlmError::BadOutput("malformed array".into()));
    }
    serde_json::from_str(&text[start..=end]).map_err(|e| LlmError::BadOutput(e.to_string()))
}

const ENTITY_SYSTEM: &str = "You extract named entities from notes. Reply with ONLY a JSON array \
of objects: [{\"name\": \"...\", \"type\": \"person|organization|project|place|unknown\"}]. \
No prose, no markdown fences.";

const TRIPLE_SYSTEM: &str = "You extract factual relationships from notes as knowledge-graph \
triples. Reply with ONLY a JSON array of objects: [{\"subject\": \"...\", \"predicate\": \
\"snake_case_relation\", \"object\": \"...\"}]. Only durable facts (roles, locations, \
ownership, preferences, decisions) — no ephemera. No prose, no markdown fences.";

impl LlmClient {
    pub fn extract_entities(&self, text: &str) -> Result<Vec<ExtractedEntity>, LlmError> {
        let out = self.complete(ENTITY_SYSTEM, text)?;
        let arr = extract_json_array(&out)?;
        serde_json::from_value(arr).map_err(|e| LlmError::BadOutput(e.to_string()))
    }

    pub fn extract_triples(&self, text: &str) -> Result<Vec<ExtractedTriple>, LlmError> {
        let out = self.complete(TRIPLE_SYSTEM, text)?;
        let arr = extract_json_array(&out)?;
        serde_json::from_value(arr).map_err(|e| LlmError::BadOutput(e.to_string()))
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
        let cleaned = out.trim().trim_matches(|c| c == '"' || c == '`' || c == '.').to_string();
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
                        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
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
        let client = LlmClient::new(&url, "test-model", ApiKind::Ollama);
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
        let client = LlmClient::new(&url, "test-model", ApiKind::OpenAi);
        let triples = client.extract_triples("Alice works at Acme").unwrap();
        assert_eq!(triples[0].predicate, "works_at");
    }

    #[test]
    fn classify_snaps_to_label() {
        let (url, _s) = stub_server("The label is: Question.", ApiKind::Ollama);
        let client = LlmClient::new(&url, "m", ApiKind::Ollama);
        let labels: Vec<String> = ["question", "command"].iter().map(|s| s.to_string()).collect();
        assert_eq!(client.classify("what time is it?", &labels).unwrap(), "question");
    }

    #[test]
    fn json_array_extraction_is_defensive() {
        assert!(extract_json_array("no array here").is_err());
        let v = extract_json_array("prefix [1, 2] suffix").unwrap();
        assert_eq!(v, json!([1, 2]));
    }

    #[test]
    fn from_env_requires_url() {
        std::env::remove_var("UNDERCROFT_LLM_URL");
        assert!(matches!(LlmClient::from_env(), Err(LlmError::NotConfigured)));
    }
}
