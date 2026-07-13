//! Minimal MCP (Model Context Protocol) stdio server.
//!
//! Speaks JSON-RPC 2.0 over newline-delimited stdio, the transport MCP
//! clients (Claude Code, Cursor, etc.) use for local servers. Exposes the
//! palace's core surface as tools:
//!
//! * `undercroft_save`    — file one verbatim memory
//! * `undercroft_search`  — hybrid search over the vault
//! * `undercroft_wake_up` — recent essential memories for session start
//! * `undercroft_verify`  — HMAC + audit-chain integrity check

use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

use undercroft_core::{normalize_content, Drawer};
use undercroft_store::{PalaceStore, SearchOptions};

const PROTOCOL_VERSION: &str = "2024-11-05";

pub fn serve(mut store: PalaceStore) -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                write_msg(&mut out, &error_response(Value::Null, -32700, &format!("parse error: {e}")))?;
                continue;
            }
        };
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg.get("method").and_then(Value::as_str).unwrap_or_default();

        // Notifications (no id) get no response.
        if msg.get("id").is_none() {
            continue;
        }

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "undercroft", "version": env!("CARGO_PKG_VERSION") }
                }
            }),
            "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": tool_definitions() }
            }),
            "tools/call" => {
                let name = msg
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let args = msg.pointer("/params/arguments").cloned().unwrap_or(json!({}));
                match call_tool(&mut store, &name, &args) {
                    Ok(text) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [ { "type": "text", "text": text } ],
                            "isError": false
                        }
                    }),
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [ { "type": "text", "text": format!("error: {e}") } ],
                            "isError": true
                        }
                    }),
                }
            }
            _ => error_response(id, -32601, &format!("method not found: {method}")),
        };
        write_msg(&mut out, &response)?;
    }
    Ok(())
}

fn write_msg(out: &mut impl Write, msg: &Value) -> Result<()> {
    serde_json::to_writer(&mut *out, msg)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "undercroft_save",
            "description": "Save one memory verbatim into the palace (encrypted + integrity-tagged at rest).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "content": { "type": "string", "description": "Verbatim text to remember" },
                    "wing": { "type": "string", "description": "Person/project partition", "default": "general" },
                    "room": { "type": "string", "description": "Topic within the wing", "default": "inbox" }
                },
                "required": ["content"]
            }
        },
        {
            "name": "undercroft_search",
            "description": "Hybrid semantic + lexical search over stored memories.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "wing": { "type": "string" },
                    "limit": { "type": "integer", "default": 5 }
                },
                "required": ["query"]
            }
        },
        {
            "name": "undercroft_wake_up",
            "description": "Load session context: the most recent essential memories.",
            "inputSchema": { "type": "object", "properties": {
                "wing": { "type": "string" }
            } }
        },
        {
            "name": "undercroft_verify",
            "description": "Verify every record's HMAC and the vault's tamper-evident audit chain.",
            "inputSchema": { "type": "object", "properties": {} }
        }
    ])
}

fn call_tool(store: &mut PalaceStore, name: &str, args: &Value) -> Result<String> {
    match name {
        "undercroft_save" => {
            let content = args
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing required argument: content"))?;
            let wing = args.get("wing").and_then(Value::as_str).unwrap_or("general");
            let room = args.get("room").and_then(Value::as_str).unwrap_or("inbox");
            undercroft_core::validate_name(wing, "wing")?;
            undercroft_core::validate_name(room, "room")?;
            let normalized = normalize_content(content);
            if normalized.is_empty() {
                anyhow::bail!("content is empty after normalization");
            }
            let idx = store.count()? as u32;
            let drawer = Drawer::new(wing, room, normalized, None, idx, "mcp");
            store.upsert(&drawer)?;
            Ok(format!("saved drawer {} in {}/{}", drawer.id, wing, room))
        }
        "undercroft_search" => {
            let query = args
                .get("query")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing required argument: query"))?;
            let wing = args.get("wing").and_then(Value::as_str).map(str::to_string);
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(5) as usize;
            let hits = store.search(query, &SearchOptions { wing, room: None, limit })?;
            if hits.is_empty() {
                return Ok("no memories matched".into());
            }
            let mut out = String::new();
            for (i, h) in hits.iter().enumerate() {
                out.push_str(&format!(
                    "{}. [score {:.3}] ({}/{}, filed {})\n{}\n\n",
                    i + 1,
                    h.score,
                    h.drawer.meta.wing,
                    h.drawer.meta.room,
                    h.drawer.meta.filed_at,
                    h.drawer.content
                ));
            }
            Ok(out.trim_end().to_string())
        }
        "undercroft_wake_up" => {
            let wing = args.get("wing").and_then(Value::as_str);
            let recent = store.recent(wing, 15)?;
            if recent.is_empty() {
                return Ok("palace is empty".into());
            }
            let mut out = String::from("recent essential memories:\n");
            for d in recent {
                let line = d.content.lines().next().unwrap_or("");
                out.push_str(&format!("- [{}/{}] {}\n", d.meta.wing, d.meta.room, line));
            }
            Ok(out.trim_end().to_string())
        }
        "undercroft_verify" => {
            let report = store.verify()?;
            Ok(format!(
                "records checked: {}\nhmac failures: {}\naudit chain: {}\nresult: {}",
                report.records_checked,
                report.bad_records.len(),
                if report.chain_ok { "ok" } else { "BROKEN" },
                if report.ok() { "VERIFY OK" } else { "VERIFY FAILED" }
            ))
        }
        other => anyhow::bail!("unknown tool: {other}"),
    }
}
