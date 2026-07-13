//! Conversation transcript parsing, ported from mempalace's `convo_miner.py`.
//!
//! Understands the JSONL session format written by Claude Code / Codex-style
//! agents: one JSON object per line with `type` = `user` / `assistant` and a
//! `message` whose `content` is either a string or a list of typed blocks.
//! Only real prose is kept — tool calls, tool results, and system noise are
//! skipped. Messages are paired into exchanges and packed into verbatim
//! chunks on exchange boundaries.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub role: String,
    pub text: String,
    /// 1-based line number in the source transcript (stable sweep id).
    pub line: u32,
}

/// Parse one JSONL transcript into ordered prose messages.
pub fn parse_transcript(jsonl: &str) -> Vec<Message> {
    let mut out = Vec::new();
    for (i, line) in jsonl.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        let role = match v.get("type").and_then(Value::as_str) {
            Some("user") => "user",
            Some("assistant") => "assistant",
            _ => continue,
        };
        let Some(content) = v.pointer("/message/content") else { continue };
        let text = extract_text(content);
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        // Skip harness-injected noise, mirroring convo_miner's filters.
        if text.starts_with("<local-command") || text.starts_with("Caveat:") {
            continue;
        }
        out.push(Message { role: role.into(), text: text.to_string(), line: (i + 1) as u32 });
    }
    out
}

fn extract_text(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => {
            let mut parts = Vec::new();
            for b in blocks {
                if b.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(t) = b.get("text").and_then(Value::as_str) {
                        parts.push(t.to_string());
                    }
                }
            }
            parts.join("\n")
        }
        _ => String::new(),
    }
}

/// Pack messages into verbatim chunks, breaking only on message boundaries.
/// Each message is rendered as `User:` / `Assistant:` prefixed text, exactly
/// as spoken (never summarized). Oversized single messages are passed through
/// whole — the drawer chunker downstream handles windows.
pub fn chunk_exchanges(messages: &[Message], chunk_size: usize) -> Vec<String> {
    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();
    for m in messages {
        let prefix = if m.role == "user" { "User" } else { "Assistant" };
        let block = format!("{}: {}", prefix, m.text);
        if !current.is_empty() && current.len() + block.len() + 2 > chunk_size {
            chunks.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push_str("\n\n");
        }
        current.push_str(&block);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"type":"user","message":{"role":"user","content":"why is the build failing?"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"The build fails because the lockfile is stale."},{"type":"tool_use","name":"Bash","input":{}}]}}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"exit 0"}]}}
{"summary":"a summary line","type":"summary"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Fixed — regenerating the lockfile solved it."}]}}"#;

    #[test]
    fn parses_prose_and_skips_tools() {
        let msgs = parse_transcript(SAMPLE);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].role, "user");
        assert!(msgs[1].text.contains("lockfile is stale"));
        assert!(!msgs[1].text.contains("tool_use"));
        assert_eq!(msgs[2].line, 5);
    }

    #[test]
    fn chunks_break_on_message_boundaries() {
        let msgs = parse_transcript(SAMPLE);
        let chunks = chunk_exchanges(&msgs, 80);
        assert!(chunks.len() >= 2);
        assert!(chunks[0].starts_with("User: why is the build failing?"));
        for c in &chunks {
            assert!(c.starts_with("User:") || c.starts_with("Assistant:"));
        }
    }

    #[test]
    fn handles_malformed_lines_gracefully() {
        let msgs = parse_transcript("not json\n{\"type\":\"user\",\"message\":{\"content\":\"hi there friend\"}}");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "hi there friend");
    }
}
