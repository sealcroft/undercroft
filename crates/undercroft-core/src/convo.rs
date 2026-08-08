//! Conversation transcript parsing, ported from mempalace's `convo_miner.py`.
//!
//! Understands the JSONL session format written by Claude Code / Codex-style
//! agents: one JSON object per line with a `type` and a `message` whose
//! `content` is either a string or a list of typed blocks.
//!
//! **Everything the transcript records is kept.** An earlier version dropped
//! every message that was not `user`/`assistant` and, within those, every
//! block that was not `text` — which discarded tool calls, tool results and
//! reasoning, i.e. most of what an agent session actually consists of, plus
//! per-message timestamps and ids. For a memory whose contract is "we do not
//! get rid of data" that was the wrong default. Non-prose blocks are now
//! rendered with a `[kind]` marker so a reader can tell a tool result from
//! something a human said, and the payload itself is preserved verbatim.
//!
//! Only genuine harness noise (local-command envelopes, caveat banners) is
//! still filtered, and only from prose.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// Transcript `type`: `user`, `assistant`, `system`, `summary`, …
    /// Kept as written rather than collapsed to a two-value enum.
    pub role: String,
    pub text: String,
    /// 1-based line number in the source transcript (stable sweep id).
    pub line: u32,
    /// When the message was sent, if the transcript records it (RFC 3339).
    /// Feeds the drawer's `content_date`, which anchors relative dates.
    pub timestamp: Option<String>,
    /// The transcript's own stable id for this message, where it has one.
    /// Lets a drawer be traced back to the exact turn it came from.
    pub id: Option<String>,
    /// Named speaker, when the transcript carries one. Multi-party
    /// conversations lose who-said-what if this is collapsed into `role`.
    pub speaker: Option<String>,
}

/// Parse one JSONL transcript into ordered prose messages.
pub fn parse_transcript(jsonl: &str) -> Vec<Message> {
    let mut out = Vec::new();
    for (i, line) in jsonl.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let role = v
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        // A summary line carries its payload at the top level, not under
        // `message`. It is still something the transcript recorded.
        let text = match v.pointer("/message/content") {
            Some(content) => extract_text(content),
            None => v
                .get("summary")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_default(),
        };
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        // Skip harness-injected noise, mirroring convo_miner's filters.
        if text.starts_with("<local-command") || text.starts_with("Caveat:") {
            continue;
        }
        out.push(Message {
            role,
            text: text.to_string(),
            line: (i + 1) as u32,
            timestamp: v
                .get("timestamp")
                .and_then(Value::as_str)
                .map(str::to_string),
            id: v
                .get("uuid")
                .or_else(|| v.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string),
            speaker: v
                .get("speaker")
                .or_else(|| v.pointer("/message/name"))
                .and_then(Value::as_str)
                .map(str::to_string),
        });
    }
    out
}

/// Render a message's content. Prose is emitted as written; every other
/// block kind is emitted with a `[kind]` marker followed by its payload, so
/// nothing is lost and a reader can still tell tool output from speech.
fn extract_text(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .map(render_block)
            .filter(|s| !s.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Null => String::new(),
        // An object or scalar we have no shape for is still content: keep it
        // rather than silently returning nothing.
        other => other.to_string(),
    }
}

/// One content block, rendered verbatim under a kind marker.
fn render_block(b: &Value) -> String {
    let kind = b.get("type").and_then(Value::as_str).unwrap_or("");
    match kind {
        "text" => b
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        // Reasoning the model recorded. Kept: it is the account of *why* a
        // thing was done, which is often the only place the reason exists.
        "thinking" | "reasoning" | "redacted_thinking" => {
            let t = b
                .get("thinking")
                .or_else(|| b.get("text"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if t.is_empty() {
                String::new()
            } else {
                format!("[thinking]\n{t}")
            }
        }
        // What the agent actually did, and what came back. For an agent
        // memory this is the substance of the session, not noise.
        "tool_use" | "tool_call" => {
            let name = b.get("name").and_then(Value::as_str).unwrap_or("tool");
            let input = b
                .get("input")
                .or_else(|| b.get("arguments"))
                .map(render_payload)
                .unwrap_or_default();
            format!("[tool_use: {name}]\n{input}")
                .trim_end()
                .to_string()
        }
        "tool_result" => {
            let body = b
                .get("content")
                .or_else(|| b.get("output"))
                .map(render_payload)
                .unwrap_or_default();
            format!("[tool_result]\n{body}").trim_end().to_string()
        }
        "image" => {
            // The bytes are not ours to inline here; record that an image was
            // present and any reference the transcript gives, so retrieval can
            // at least surface that something visual belongs to this turn.
            let src = b
                .pointer("/source/url")
                .or_else(|| b.pointer("/source/media_type"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if src.is_empty() {
                "[image]".to_string()
            } else {
                format!("[image: {src}]")
            }
        }
        "" => render_payload(b),
        other => format!("[{other}]\n{}", render_payload(b))
            .trim_end()
            .to_string(),
    }
}

/// A nested payload: a plain string stays plain, blocks recurse, anything
/// else is serialized rather than dropped.
fn render_payload(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(render_block)
            .filter(|s| !s.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// How a message is attributed in a rendered chunk. A named speaker wins:
/// collapsing everyone into `User`/`Assistant` loses who-said-what in any
/// conversation with more than two participants.
pub fn label(m: &Message) -> String {
    speaker_label(m)
}

fn speaker_label(m: &Message) -> String {
    if let Some(s) = m.speaker.as_deref().filter(|s| !s.trim().is_empty()) {
        return s.to_string();
    }
    let mut c = m.role.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => "Unknown".to_string(),
    }
}

/// Pack messages into verbatim chunks, breaking only on message boundaries.
/// Each message is rendered as `User:` / `Assistant:` prefixed text, exactly
/// as spoken (never summarized). Oversized single messages are passed through
/// whole — the drawer chunker downstream handles windows.
pub fn chunk_exchanges(messages: &[Message], chunk_size: usize) -> Vec<String> {
    chunk_exchanges_dated(messages, chunk_size)
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

/// As [`chunk_exchanges`], also reporting when each chunk *started* — the
/// timestamp of its first turn, or `None` when that turn carried none.
///
/// A chunk spans several turns, so it has no single instant; the opening
/// turn is the honest anchor for the relative dates inside it, and it is a
/// fact read off the transcript rather than an inference.
pub fn chunk_exchanges_dated(
    messages: &[Message],
    chunk_size: usize,
) -> Vec<(String, Option<String>)> {
    let mut chunks: Vec<(String, Option<String>)> = Vec::new();
    let mut current = String::new();
    let mut started_at: Option<String> = None;
    for m in messages {
        let block = format!("{}: {}", speaker_label(m), m.text);
        if !current.is_empty() && current.len() + block.len() + 2 > chunk_size {
            chunks.push((std::mem::take(&mut current), started_at.take()));
        }
        if current.is_empty() {
            started_at = m.timestamp.clone();
        } else {
            current.push_str("\n\n");
        }
        current.push_str(&block);
    }
    if !current.is_empty() {
        chunks.push((current, started_at));
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

    /// Replaces the former `parses_prose_and_skips_tools`, whose contract was
    /// the bug: it asserted tool blocks were discarded. They are the substance
    /// of an agent session and are now preserved.
    #[test]
    fn keeps_every_recorded_turn_including_tools() {
        let msgs = parse_transcript(SAMPLE);
        // 3 prose turns + the tool_result turn + the summary line.
        assert_eq!(msgs.len(), 5, "{msgs:#?}");
        assert_eq!(msgs[0].role, "user");
        assert!(msgs[1].text.contains("lockfile is stale"));
        assert!(
            msgs[1].text.contains("[tool_use: Bash]"),
            "tool call must survive: {}",
            msgs[1].text
        );
        assert!(
            msgs[2].text.contains("[tool_result]") && msgs[2].text.contains("exit 0"),
            "tool result must survive: {}",
            msgs[2].text
        );
        assert!(
            msgs.iter().any(|m| m.role == "summary"),
            "a summary line is recorded content too"
        );
        assert_eq!(msgs.last().unwrap().line, 5);
    }

    #[test]
    fn dated_chunks_report_the_opening_turn() {
        let msgs = parse_transcript(concat!(
            r#"{"type":"user","timestamp":"2023-05-08T10:00:00Z","message":{"content":"first turn"}}"#,
            "
",
            r#"{"type":"assistant","timestamp":"2023-05-08T10:05:00Z","message":{"content":"second turn"}}"#,
        ));
        assert_eq!(msgs.len(), 2);
        // One chunk big enough for both: the anchor is the FIRST turn.
        let together = chunk_exchanges_dated(&msgs, 4000);
        assert_eq!(together.len(), 1);
        assert_eq!(together[0].1.as_deref(), Some("2023-05-08T10:00:00Z"));
        // Forced apart: each chunk carries its own opening turn.
        let split = chunk_exchanges_dated(&msgs, 20);
        assert_eq!(split.len(), 2);
        assert_eq!(split[0].1.as_deref(), Some("2023-05-08T10:00:00Z"));
        assert_eq!(split[1].1.as_deref(), Some("2023-05-08T10:05:00Z"));
    }

    #[test]
    fn undated_transcripts_yield_no_anchor_rather_than_a_guess() {
        let msgs = parse_transcript(r#"{"type":"user","message":{"content":"no timestamp here"}}"#);
        let chunks = chunk_exchanges_dated(&msgs, 4000);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].1.is_none(), "must not invent a date");
    }

    #[test]
    fn regression_chunk_exchanges_text_unchanged_by_the_dated_variant() {
        let msgs = parse_transcript(SAMPLE);
        let plain = chunk_exchanges(&msgs, 80);
        let dated: Vec<String> = chunk_exchanges_dated(&msgs, 80)
            .into_iter()
            .map(|(t, _)| t)
            .collect();
        assert_eq!(plain, dated);
    }

    #[test]
    fn keeps_thinking_blocks() {
        let msgs = parse_transcript(
            r#"{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"the lockfile is stale"},{"type":"text","text":"visible answer"}]}}"#,
        );
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].text.contains("[thinking]"));
        assert!(msgs[0].text.contains("the lockfile is stale"));
        assert!(msgs[0].text.contains("visible answer"));
    }

    #[test]
    fn keeps_per_message_timestamp_id_and_speaker() {
        let msgs = parse_transcript(
            r#"{"type":"user","uuid":"abc-123","timestamp":"2023-05-08T13:56:00Z","speaker":"Caroline","message":{"content":"I went yesterday"}}"#,
        );
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].timestamp.as_deref(), Some("2023-05-08T13:56:00Z"));
        assert_eq!(msgs[0].id.as_deref(), Some("abc-123"));
        assert_eq!(msgs[0].speaker.as_deref(), Some("Caroline"));
    }

    #[test]
    fn named_speakers_survive_chunking() {
        let msgs = parse_transcript(
            "{\"type\":\"user\",\"speaker\":\"Caroline\",\"message\":{\"content\":\"hello there\"}}
{\"type\":\"user\",\"speaker\":\"Melanie\",\"message\":{\"content\":\"hi back\"}}",
        );
        let chunks = chunk_exchanges(&msgs, 4000);
        let all = chunks.join(
            "
",
        );
        assert!(all.contains("Caroline:"), "{all}");
        assert!(all.contains("Melanie:"), "{all}");
        assert!(
            !all.contains("User:"),
            "a named speaker must not collapse to User: {all}"
        );
    }

    #[test]
    fn image_blocks_are_recorded_not_dropped() {
        let msgs = parse_transcript(
            r#"{"type":"user","message":{"content":[{"type":"image","source":{"url":"https://x/y.png"}}]}}"#,
        );
        assert_eq!(msgs.len(), 1);
        assert!(
            msgs[0].text.contains("[image: https://x/y.png"),
            "{}",
            msgs[0].text
        );
    }

    #[test]
    fn unknown_block_kinds_are_preserved_rather_than_discarded() {
        let msgs = parse_transcript(
            r#"{"type":"assistant","message":{"content":[{"type":"future_kind","payload":"do not lose me"}]}}"#,
        );
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].text.contains("do not lose me"), "{}", msgs[0].text);
    }

    // ---- regression: behaviour that must NOT change --------------------

    #[test]
    fn regression_harness_noise_is_still_filtered() {
        let msgs = parse_transcript(
            "{\"type\":\"user\",\"message\":{\"content\":\"<local-command>ignore me</local-command>\"}}
{\"type\":\"user\",\"message\":{\"content\":\"Caveat: also ignore me\"}}
{\"type\":\"user\",\"message\":{\"content\":\"keep this one\"}}",
        );
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "keep this one");
    }

    #[test]
    fn regression_prose_text_is_still_verbatim() {
        // Interior whitespace, blank lines and punctuation must survive
        // byte-for-byte; only the outer trim applies.
        let line = concat!(
            r#"{"type":"user","message":{"content":"#,
            r#""  why is the build   failing?\n\nline two  "}}"#
        );
        let msgs = parse_transcript(line);
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert_eq!(msgs[0].text, "why is the build   failing?\n\nline two");
    }

    #[test]
    fn regression_empty_and_malformed_lines_still_skipped() {
        let msgs = parse_transcript(
            "

not json
{}
{\"type\":\"user\",\"message\":{\"content\":\"\"}}",
        );
        assert!(msgs.is_empty(), "{msgs:?}");
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
        let msgs = parse_transcript(
            "not json\n{\"type\":\"user\",\"message\":{\"content\":\"hi there friend\"}}",
        );
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "hi there friend");
    }
}
