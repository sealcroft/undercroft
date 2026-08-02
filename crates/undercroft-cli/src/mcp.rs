//! MCP (Model Context Protocol) stdio server.
//!
//! Speaks JSON-RPC 2.0 over newline-delimited stdio, the transport MCP
//! clients (Claude Code, Cursor, etc.) use for local servers. Covers the
//! palace surface the original mempalace MCP server exposed: drawer
//! reads/writes, search, wake-up, knowledge-graph operations, cross-wing
//! tunnels, hallways, agent diaries, stats, dedup, and integrity
//! verification — all on top of the vault security layer.

use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

use undercroft_core::{normalize_content, Drawer};
use undercroft_store::{PalaceStore, SearchOptions};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Tools that mutate the palace — rejected when the server runs read-only
/// (the team-server deployment exposes recall without write access).
const WRITE_TOOLS: &[&str] = &[
    "undercroft_save",
    "undercroft_add_drawer",
    "undercroft_update_drawer",
    "undercroft_delete_drawer",
    "undercroft_delete_by_source",
    "undercroft_create_tunnel",
    "undercroft_delete_tunnel",
    "undercroft_kg_add",
    "undercroft_kg_invalidate",
    "undercroft_kg_supersede",
    "undercroft_kg_set_authority",
    "undercroft_diary_write",
    "undercroft_dedup",
];

/// Transport-independent MCP message handler, shared by the stdio and HTTP
/// servers.
pub struct McpHandler {
    store: PalaceStore,
    read_only: bool,
}

impl McpHandler {
    pub fn new(store: PalaceStore, read_only: bool) -> Self {
        Self { store, read_only }
    }

    /// Handle one JSON-RPC message. Returns `None` for notifications.
    pub fn handle(&mut self, msg: &Value) -> Option<Value> {
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();

        // Notifications (no id) get no response.
        msg.get("id")?;

        let _span = undercroft_obs::scope_request(method, None);
        Some(match method {
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
                let args = msg
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or(json!({}));
                let result = if self.read_only && WRITE_TOOLS.contains(&name.as_str()) {
                    Err(anyhow::anyhow!(
                        "server is read-only: {name} is not allowed"
                    ))
                } else {
                    call_tool(&mut self.store, &name, &args)
                };
                match result {
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
        })
    }
}

pub fn serve(store: PalaceStore) -> Result<()> {
    let mut handler = McpHandler::new(store, false);
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
                write_msg(
                    &mut out,
                    &error_response(Value::Null, -32700, &format!("parse error: {e}")),
                )?;
                continue;
            }
        };
        if let Some(response) = handler.handle(&msg) {
            write_msg(&mut out, &response)?;
        }
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

/// Terse helper for tool definitions: (name, description, properties, required).
fn tool(name: &str, desc: &str, props: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": desc,
        "inputSchema": { "type": "object", "properties": props, "required": required }
    })
}

fn tool_definitions() -> Value {
    let s = |d: &str| json!({ "type": "string", "description": d });
    let i = |d: &str| json!({ "type": "integer", "description": d });
    let n = |d: &str| json!({ "type": "number", "description": d });
    json!([
        // --- palace core ---
        tool("undercroft_save", "Save one memory verbatim (encrypted + integrity-tagged at rest).",
            json!({ "content": s("verbatim text"), "wing": s("person/project partition"), "room": s("topic"), "kind": s("declared record kind: question|preference|decision|event|procedure|statement — a closed vocabulary, rejected if unknown; omit rather than guess"), "content_date": s("when the content happened, RFC 3339 or YYYY-MM-DD; anchors relative dates in the text") }),
            &["content"]),
        tool("undercroft_search", "Hybrid semantic + lexical search over stored memories.",
            json!({ "query": s("search query"), "wing": s("scope to wing"), "room": s("scope to room"), "kind": s("filter to a declared record kind: question|preference|decision|event|procedure|statement. Drawers with no declared kind are excluded while set, and the reply says how many"), "limit": i("max results"), "offset": i("rank to continue from — pass the offset a previous page's footer gave you to go deeper instead of re-asking the same question"), "ranked_at": s("RFC 3339 instant from a previous page's footer; repeat it so every page slices one identical ranking instead of one that drifts between calls"), "as_of": s("reference date (RFC 3339 or YYYY-MM-DD) — the engine reports how long before it each memory happened, exactly, instead of leaving you to work it out"), "language": s("language of the stored text: en (default) or ar. Arabic is a different grammar, not a word list — the past marker precedes the count and the dual is one word — and it reads Saturday-first weeks"), "date_order": s("which field a bare numeric date puts first: day_first or month_first. Omit and the engine uses any unambiguous date in the same drawer as evidence, then day-first. Cannot be guessed from the language — US English is month-first, Commonwealth day-first"), "calendar": s("which calendar counted the year across this corpus: gregorian (default), buddhist, minguo, hijri (Umm al-Qura), jalali, reiwa, heisei, showa, taisho, meiji. NEVER inferred — Thai script writes Gregorian dates and Thai numerals are a numeral system, not a calendar. An era marker in a memory's own words (พ.ศ. ค.ศ. هـ 民國 令和) outranks this, being the writer's statement about one date rather than yours about the whole corpus") }),
            &["query"]),
        tool("undercroft_wake_up", "Load session context: recent essential memories.",
            json!({ "wing": s("scope to wing") }), &[]),
        tool("undercroft_verify", "Verify every record's HMAC and the tamper-evident audit chain.",
            json!({}), &[]),
        tool("undercroft_status", "Palace statistics: records, wings, rooms, KG, size, security level.",
            json!({}), &[]),
        // --- drawers ---
        tool("undercroft_get_drawer", "Fetch one drawer verbatim by id.",
            json!({ "id": s("drawer id") }), &["id"]),
        tool("undercroft_add_drawer", "File a drawer with explicit wing/room/source.",
            json!({ "content": s("verbatim text"), "wing": s("wing"), "room": s("room"), "kind": s("declared record kind: question|preference|decision|event|procedure|statement — closed vocabulary, rejected if unknown; omit rather than guess"), "source_file": s("origin"), "content_date": s("when the content happened, RFC 3339 or YYYY-MM-DD; anchors relative dates in the text") }),
            &["content"]),
        tool("undercroft_update_drawer", "Replace a drawer's content in place (re-sealed, re-tagged).",
            json!({ "id": s("drawer id"), "content": s("new content") }), &["id", "content"]),
        tool("undercroft_delete_drawer", "Delete a drawer (logs a tamper-evident tombstone).",
            json!({ "id": s("drawer id") }), &["id"]),
        tool("undercroft_list_drawers", "Page through drawer summaries.",
            json!({ "wing": s("scope"), "room": s("scope"), "limit": i("page size"), "offset": i("page start") }), &[]),
        tool("undercroft_delete_by_source", "Delete every drawer mined from a source file.",
            json!({ "source_file": s("source path") }), &["source_file"]),
        tool("undercroft_check_duplicate", "Check whether exact content is already filed.",
            json!({ "content": s("content to check") }), &["content"]),
        // --- navigation ---
        tool("undercroft_list_wings", "Wings with drawer counts.", json!({}), &[]),
        tool("undercroft_list_rooms", "Rooms and counts within a wing.",
            json!({ "wing": s("wing") }), &["wing"]),
        tool("undercroft_get_taxonomy", "Full wing → room tree.", json!({}), &[]),
        tool("undercroft_create_tunnel", "Connect two wings.",
            json!({ "from_wing": s("origin"), "to_wing": s("destination"), "label": s("why related") }),
            &["from_wing", "to_wing"]),
        tool("undercroft_list_tunnels", "List tunnels, optionally touching one wing.",
            json!({ "wing": s("filter") }), &[]),
        tool("undercroft_follow_tunnel", "Recent drawers from a tunnel's destination wing.",
            json!({ "id": s("tunnel id"), "limit": i("max drawers") }), &["id"]),
        tool("undercroft_delete_tunnel", "Remove a tunnel.",
            json!({ "id": s("tunnel id") }), &["id"]),
        tool("undercroft_traverse", "Wings reachable from a start wing over tunnels (BFS).",
            json!({ "start": s("start wing"), "depth": i("max hops") }), &["start"]),
        tool("undercroft_list_hallways", "Entity pairs co-occurring across a wing's drawers.",
            json!({ "wing": s("wing"), "top": i("max pairs") }), &["wing"]),
        tool("undercroft_get_closet_index", "Compact scannable index: one line per room with counts, date span, key entities, and drawer ids — decide WHERE to look, then get_drawer.",
            json!({ "wing": s("scope to wing") }), &[]),
        // --- knowledge graph ---
        tool("undercroft_kg_add", "Add a temporal fact (subject, predicate, object).",
            json!({ "subject": s("entity"), "predicate": s("relation"), "object": s("value"),
                    "valid_from": s("ISO date fact starts"), "valid_to": s("ISO date fact ends"),
                    "confidence": n("0..1") }),
            &["subject", "predicate", "object"]),
        tool("undercroft_kg_query", "Facts about an entity, optionally as of an instant.",
            json!({ "entity": s("entity"), "as_of": s("ISO instant"), "direction": s("outgoing|incoming|both") }),
            &["entity"]),
        tool("undercroft_kg_invalidate", "Close the validity window of matching active facts.",
            json!({ "subject": s("entity"), "predicate": s("relation"), "object": s("only this value"), "ended": s("ISO end") }),
            &["subject", "predicate"]),
        tool("undercroft_kg_supersede", "Replace the current value of (subject, predicate).",
            json!({ "subject": s("entity"), "predicate": s("relation"), "new_object": s("new value"), "changed_at": s("ISO instant") }),
            &["subject", "predicate", "new_object"]),
        tool("undercroft_kg_timeline", "Fact history, optionally for one entity.",
            json!({ "entity": s("entity") }), &[]),
        tool("undercroft_kg_stats", "Knowledge-graph counts.", json!({}), &[]),
        tool("undercroft_lookup_canonical", "The exact-authority door: the one active, approved, canonical fact for a key. Consult BEFORE semantic recall for exact or high-risk asks — an empty answer means no declared truth exists, never a guess.",
            json!({ "key": s("canonical key") }), &["key"]),
        tool("undercroft_kg_set_authority", "Place a fact on the authority tier or take it off. authority_class stated|canonical, review_state unreviewed|approved|rejected; canonical_key required for canonical (promoting approved onto an occupied key supersedes the old holder, audited).",
            json!({ "triple_id": s("fact id"), "authority_class": s("stated|canonical"),
                    "review_state": s("unreviewed|approved|rejected"), "canonical_key": s("exact-lookup key") }),
            &["triple_id", "authority_class", "review_state"]),
        // --- agent diaries ---
        tool("undercroft_diary_write", "Append a diary entry for an agent.",
            json!({ "agent": s("agent name"), "entry": s("diary text") }), &["agent", "entry"]),
        tool("undercroft_diary_read", "Read an agent's recent diary entries.",
            json!({ "agent": s("agent name"), "limit": i("max entries") }), &["agent"]),
        tool("undercroft_list_agents", "Agents that have diaries.", json!({}), &[]),
        // --- maintenance ---
        tool("undercroft_dedup", "Report (or remove) exact-duplicate drawers.",
            json!({ "apply": { "type": "boolean", "description": "actually delete duplicates" } }), &[]),
    ])
}

fn call_tool(store: &mut PalaceStore, name: &str, args: &Value) -> Result<String> {
    match name {
        "undercroft_save" => {
            let content = args
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing required argument: content"))?;
            let wing = args
                .get("wing")
                .and_then(Value::as_str)
                .unwrap_or("general");
            let room = args.get("room").and_then(Value::as_str).unwrap_or("inbox");
            undercroft_core::validate_name(wing, "wing")?;
            undercroft_core::validate_name(room, "room")?;
            let normalized = normalize_content(content);
            if normalized.is_empty() {
                anyhow::bail!("content is empty after normalization");
            }
            let idx = store.next_append_index()? as u32;
            let kind = opt_str(args, "kind").map(str::to_string);
            if let Some(k) = kind.as_deref() {
                undercroft_core::validate_kind(k)?;
            }
            let drawer = Drawer::new(wing, room, normalized, None, idx, "mcp")
                .with_content_date(opt_str(args, "content_date").map(str::to_string))
                .with_kind(kind);
            store.upsert(&drawer)?;
            Ok(format!("saved drawer {} in {}/{}", drawer.id, wing, room))
        }
        "undercroft_search" => {
            let query = args
                .get("query")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing required argument: query"))?;
            let wing = opt_str(args, "wing").map(str::to_string);
            let room = opt_str(args, "room").map(str::to_string);
            // Declared-kind filter: closed vocabulary, validated by the
            // store — an unknown value errors with the vocabulary in the
            // message rather than returning a silently empty result.
            let kind = opt_str(args, "kind").map(str::to_string);
            let limit = opt_u64(args, "limit").unwrap_or(5) as usize;
            // Rank to continue from — the previous page's footer names it.
            let offset = opt_u64(args, "offset").unwrap_or(0) as usize;
            // The instant the ranking is computed as of. Resolved here so the
            // footer can state the exact value the next page must repeat:
            // pages of one iteration slice one ranking, pinned to one clock.
            // A value that does not parse is an error said out loud, never a
            // silent fall-back to the host clock.
            let ranked_at = match opt_str(args, "ranked_at") {
                Some(s) => {
                    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                        .map_err(|_| anyhow::anyhow!("ranked_at must be an RFC 3339 instant"))?
                }
                None => time::OffsetDateTime::now_utc(),
            };
            let hits = store.search(
                query,
                &SearchOptions {
                    // The same `language` the date scanner reads.
                    morph_lang: match opt_str(args, "language") {
                        Some("de") | Some("german") => undercroft_store::MorphLang::German,
                        Some("en") | Some("english") => undercroft_store::MorphLang::English,
                        Some("it") | Some("italian") => undercroft_store::MorphLang::Italian,
                        Some("es") | Some("spanish") => undercroft_store::MorphLang::Spanish,
                        Some("fr") | Some("french") => undercroft_store::MorphLang::French,
                        Some("pt") | Some("portuguese") => undercroft_store::MorphLang::Portuguese,
                        Some("ru") | Some("russian") => undercroft_store::MorphLang::Russian,
                        Some("el") | Some("greek") => undercroft_store::MorphLang::Greek,
                        Some("nl") | Some("dutch") => undercroft_store::MorphLang::Dutch,
                        Some("tr") | Some("turkish") => undercroft_store::MorphLang::Turkish,
                        Some("hi") | Some("hindi") => undercroft_store::MorphLang::Hindi,
                        Some("ka") | Some("georgian") => undercroft_store::MorphLang::Georgian,
                        Some("ko") | Some("korean") => undercroft_store::MorphLang::Korean,
                        _ => undercroft_store::MorphLang::Undeclared,
                    },
                    wing: wing.clone(),
                    room: room.clone(),
                    kind: kind.clone(),
                    limit,
                    room_cap: None,
                    offset,
                    ranked_at: Some(ranked_at),
                },
            )?;
            // The unlabeled-rows policy (docs/LABELS.md): while a kind
            // filter is set, say what it passed over, so a thin answer over
            // a thinly-labeled corpus is not read as a thin corpus.
            let unlabeled_note = match kind.as_deref() {
                Some(_) => {
                    let n = store.unkinded_in_scope(wing.as_deref(), room.as_deref())?;
                    (n > 0).then(|| {
                        format!("\n({n} in-scope drawers carry no declared kind and were not considered)")
                    })
                }
                None => None,
            };
            if hits.is_empty() {
                let mut msg = if offset > 0 {
                    format!("no more memories past rank {offset}")
                } else {
                    "no memories matched".to_string()
                };
                if let Some(note) = unlabeled_note {
                    msg.push_str(&note);
                }
                return Ok(msg);
            }
            // Reference date for elapsed time. The engine holds the dates, so
            // it does the calendar arithmetic — month lengths and leap years
            // are not a caller's problem, and least of all a language model's.
            let as_of = opt_str(args, "as_of").map(str::to_string);
            // Which language the drawers' own text is read in. Read-time,
            // because the reading is live: a corpus ingested while the engine
            // read English is answered correctly in Arabic without a rewrite.
            let locale = match opt_str(args, "language") {
                Some("ar") | Some("arabic") => undercroft_core::temporal::Locale::ARABIC,
                _ => undercroft_core::temporal::Locale::ENGLISH,
            };
            // Reading conventions, declared rather than detected. A numeric
            // date's field order cannot be derived from the language (US
            // month-first, Commonwealth day-first, both English) and a calendar
            // cannot be derived from the text at all — script is not evidence
            // and a numeral system is not a calendar.
            let locale = match opt_str(args, "date_order") {
                Some("month_first") | Some("mdy") | Some("us") => {
                    locale.with_date_order(undercroft_core::temporal::DateOrder::MonthFirst)
                }
                Some("day_first") | Some("dmy") => {
                    locale.with_date_order(undercroft_core::temporal::DateOrder::DayFirst)
                }
                _ => locale,
            };
            let locale = match opt_str(args, "calendar") {
                Some("buddhist") | Some("be") | Some("thai") => {
                    locale.with_calendar(undercroft_core::temporal::Calendar::Buddhist)
                }
                Some("minguo") | Some("roc") | Some("taiwan") => {
                    locale.with_calendar(undercroft_core::temporal::Calendar::Minguo)
                }
                Some("hijri") | Some("islamic") | Some("umalqura") => {
                    locale.with_calendar(undercroft_core::temporal::Calendar::Hijri)
                }
                Some("jalali") | Some("persian") | Some("solar_hijri") => {
                    locale.with_calendar(undercroft_core::temporal::Calendar::Jalali)
                }
                Some("reiwa") => locale.with_calendar(undercroft_core::temporal::Calendar::Reiwa),
                Some("heisei") => locale.with_calendar(undercroft_core::temporal::Calendar::Heisei),
                Some("showa") => locale.with_calendar(undercroft_core::temporal::Calendar::Showa),
                Some("taisho") => locale.with_calendar(undercroft_core::temporal::Calendar::Taisho),
                Some("meiji") => locale.with_calendar(undercroft_core::temporal::Calendar::Meiji),
                _ => locale,
            };
            let mut out = String::new();
            for (i, h) in hits.iter().enumerate() {
                // Report when the content happened when we know it, not only
                // when it was filed: an agent reading "I went yesterday" needs
                // the anchor to interpret it, and filed_at is the wrong one.
                let when = match &h.drawer.meta.content_date {
                    Some(d) => format!("happened {d}, filed {}", h.drawer.meta.filed_at),
                    None => format!("filed {}", h.drawer.meta.filed_at),
                };
                // "15 weeks before" rather than two dates and a subtraction.
                let ago = match (h.drawer.meta.content_date.as_deref(), as_of.as_deref()) {
                    (Some(d), Some(a)) => undercroft_core::temporal::describe_interval(a, d)
                        .map(|s| format!(", {s}"))
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                // Every day this text is known to have been recorded. One
                // entry is the ordinary case and says nothing extra.
                let seen = {
                    let all = h.drawer.all_occurrences();
                    if all.len() > 1 {
                        let days: Vec<&str> = all
                            .iter()
                            .filter_map(|o| o.content_date.as_deref())
                            .collect();
                        format!("\nalso recorded on: {}", days.join(", "))
                    } else {
                        String::new()
                    }
                };
                // Times written inside the text, resolved against this
                // drawer's own anchor and read live rather than from the seal.
                let mentions = {
                    let m = h.drawer.live_time_mentions_in(locale);
                    let resolved: Vec<String> = m
                        .iter()
                        .filter_map(|x| {
                            x.range().map(|(a, b)| {
                                if a == b {
                                    format!("{:?} = {a}", x.text)
                                } else {
                                    format!("{:?} = {a}..{b}", x.text)
                                }
                            })
                        })
                        .collect();
                    if resolved.is_empty() {
                        String::new()
                    } else {
                        format!("\ndates in the text: {}", resolved.join(" · "))
                    }
                };
                out.push_str(&format!(
                    "{}. [score {:.3}] ({}/{}, {}{}){}{}\n{}\n\n",
                    // Absolute rank, not position within the page: on a later
                    // page "1." would claim a rank this hit does not hold.
                    offset + i + 1,
                    h.score,
                    h.drawer.meta.wing,
                    h.drawer.meta.room,
                    when,
                    ago,
                    seen,
                    mentions,
                    h.drawer.content
                ));
            }
            // A full page may have more below it; say exactly how to continue.
            // A short page means the ranking is exhausted and says nothing.
            if hits.len() == limit {
                let echo = ranked_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default();
                out.push_str(&format!(
                    "— deeper results may exist: repeat this search with offset={} and ranked_at={echo}\n",
                    offset + hits.len(),
                ));
            }
            if let Some(note) = unlabeled_note {
                out.push_str(&note);
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
                if report.ok() {
                    "VERIFY OK"
                } else {
                    "VERIFY FAILED"
                }
            ))
        }
        "undercroft_status" => {
            let st = store.stats()?;
            Ok(serde_json::to_string_pretty(&st)?)
        }
        "undercroft_get_drawer" => {
            let id = req_str(args, "id")?;
            match store.get(id)? {
                Some(d) => Ok(serde_json::to_string_pretty(&d)?),
                None => anyhow::bail!("no drawer with id {id}"),
            }
        }
        "undercroft_add_drawer" => {
            let content = req_str(args, "content")?;
            let wing = opt_str(args, "wing").unwrap_or("general");
            let room = opt_str(args, "room").unwrap_or("inbox");
            undercroft_core::validate_name(wing, "wing")?;
            undercroft_core::validate_name(room, "room")?;
            let normalized = normalize_content(content);
            if normalized.is_empty() {
                anyhow::bail!("content is empty after normalization");
            }
            let idx = store.next_append_index()? as u32;
            let kind = opt_str(args, "kind").map(str::to_string);
            if let Some(k) = kind.as_deref() {
                undercroft_core::validate_kind(k)?;
            }
            let drawer = Drawer::new(
                wing,
                room,
                normalized,
                opt_str(args, "source_file").map(str::to_string),
                idx,
                "mcp",
            )
            .with_content_date(opt_str(args, "content_date").map(str::to_string))
            .with_kind(kind);
            store.upsert(&drawer)?;
            Ok(format!("added drawer {} in {}/{}", drawer.id, wing, room))
        }
        "undercroft_update_drawer" => {
            let id = req_str(args, "id")?;
            if store.update_drawer(id, req_str(args, "content")?)? {
                Ok(format!("updated drawer {id}"))
            } else {
                anyhow::bail!("no drawer with id {id}")
            }
        }
        "undercroft_delete_drawer" => {
            let id = req_str(args, "id")?;
            if store.delete_drawer(id)? {
                Ok(format!("deleted drawer {id}"))
            } else {
                anyhow::bail!("no drawer with id {id}")
            }
        }
        "undercroft_list_drawers" => {
            let rows = store.list_drawers(
                opt_str(args, "wing"),
                opt_str(args, "room"),
                opt_u64(args, "limit").unwrap_or(20) as usize,
                opt_u64(args, "offset").unwrap_or(0) as usize,
            )?;
            Ok(serde_json::to_string_pretty(&rows)?)
        }
        "undercroft_delete_by_source" => {
            let n = store.delete_by_source(req_str(args, "source_file")?)?;
            Ok(format!("deleted {n} drawer(s)"))
        }
        "undercroft_check_duplicate" => {
            match store.check_duplicate(&normalize_content(req_str(args, "content")?))? {
                Some(id) => Ok(format!("duplicate of {id}")),
                None => Ok("not filed".into()),
            }
        }
        "undercroft_list_wings" => {
            let wings = store.wings()?;
            Ok(serde_json::to_string_pretty(&wings)?)
        }
        "undercroft_list_rooms" => {
            let rooms = store.rooms(req_str(args, "wing")?)?;
            Ok(serde_json::to_string_pretty(&rooms)?)
        }
        "undercroft_get_taxonomy" => {
            let tax = store.taxonomy()?;
            Ok(serde_json::to_string_pretty(&tax)?)
        }
        "undercroft_create_tunnel" => {
            let id = store.create_tunnel(
                req_str(args, "from_wing")?,
                req_str(args, "to_wing")?,
                opt_str(args, "label").unwrap_or("related"),
            )?;
            Ok(format!("tunnel {id} created"))
        }
        "undercroft_list_tunnels" => {
            let t = store.list_tunnels(opt_str(args, "wing"))?;
            Ok(serde_json::to_string_pretty(&t)?)
        }
        "undercroft_follow_tunnel" => {
            let drawers = store.follow_tunnel(
                req_str(args, "id")?,
                opt_u64(args, "limit").unwrap_or(5) as usize,
            )?;
            Ok(serde_json::to_string_pretty(&drawers)?)
        }
        "undercroft_delete_tunnel" => {
            let id = req_str(args, "id")?;
            if store.delete_tunnel(id)? {
                Ok(format!("deleted tunnel {id}"))
            } else {
                anyhow::bail!("no tunnel with id {id}")
            }
        }
        "undercroft_traverse" => {
            let reach = store.traverse(
                req_str(args, "start")?,
                opt_u64(args, "depth").unwrap_or(3) as usize,
            )?;
            Ok(serde_json::to_string_pretty(&reach)?)
        }
        "undercroft_get_closet_index" => {
            let lines = store.closet_index(opt_str(args, "wing"))?;
            if lines.is_empty() {
                return Ok("palace is empty".into());
            }
            Ok(lines.join("\n"))
        }
        "undercroft_list_hallways" => {
            let halls = store.hallways(
                req_str(args, "wing")?,
                opt_u64(args, "top").unwrap_or(20) as usize,
            )?;
            Ok(serde_json::to_string_pretty(&halls)?)
        }
        "undercroft_kg_add" => {
            let id = store.kg_add(
                req_str(args, "subject")?,
                req_str(args, "predicate")?,
                req_str(args, "object")?,
                opt_str(args, "valid_from"),
                opt_str(args, "valid_to"),
                args.get("confidence")
                    .and_then(Value::as_f64)
                    .unwrap_or(1.0),
                None,
            )?;
            Ok(format!("fact {id} added"))
        }
        "undercroft_kg_query" => {
            let facts = store.kg_query_entity(
                req_str(args, "entity")?,
                opt_str(args, "as_of"),
                opt_str(args, "direction").unwrap_or("outgoing"),
            )?;
            Ok(serde_json::to_string_pretty(&facts)?)
        }
        "undercroft_kg_invalidate" => {
            let n = store.kg_invalidate(
                req_str(args, "subject")?,
                req_str(args, "predicate")?,
                opt_str(args, "object"),
                opt_str(args, "ended"),
            )?;
            Ok(format!("invalidated {n} fact(s)"))
        }
        "undercroft_kg_supersede" => {
            let id = store.kg_supersede(
                req_str(args, "subject")?,
                req_str(args, "predicate")?,
                req_str(args, "new_object")?,
                opt_str(args, "changed_at"),
            )?;
            Ok(format!("superseded; new fact {id}"))
        }
        "undercroft_kg_timeline" => {
            let tl = store.kg_timeline(opt_str(args, "entity"))?;
            Ok(serde_json::to_string_pretty(&tl)?)
        }
        "undercroft_kg_stats" => {
            let st = store.kg_stats()?;
            Ok(serde_json::to_string_pretty(&st)?)
        }
        "undercroft_lookup_canonical" => {
            let key = req_str(args, "key")?;
            match store.lookup_canonical(key)? {
                Some(fact) => Ok(serde_json::to_string_pretty(&fact)?),
                // Explicit prose, not an empty list: the caller must be able
                // to tell "no declared truth" from a tool failure, and must
                // not fall back to guessing on this key's behalf.
                None => Ok(format!("no approved canonical fact holds key {key:?}")),
            }
        }
        "undercroft_kg_set_authority" => {
            store.kg_set_authority(
                req_str(args, "triple_id")?,
                req_str(args, "authority_class")?,
                req_str(args, "review_state")?,
                opt_str(args, "canonical_key"),
            )?;
            Ok(format!(
                "authority set on fact {}",
                req_str(args, "triple_id")?
            ))
        }
        "undercroft_diary_write" => {
            let id = store.diary_write(req_str(args, "agent")?, req_str(args, "entry")?)?;
            Ok(format!("diary entry {id} written"))
        }
        "undercroft_diary_read" => {
            let entries = store.diary_read(
                req_str(args, "agent")?,
                opt_u64(args, "limit").unwrap_or(10) as usize,
            )?;
            Ok(serde_json::to_string_pretty(&entries)?)
        }
        "undercroft_list_agents" => {
            let agents = store.list_agents()?;
            Ok(serde_json::to_string_pretty(&agents)?)
        }
        "undercroft_dedup" => {
            let apply = args.get("apply").and_then(Value::as_bool).unwrap_or(false);
            let report = store.dedup(apply)?;
            Ok(serde_json::to_string_pretty(&report)?)
        }
        other => anyhow::bail!("unknown tool: {other}"),
    }
}

fn req_str<'a>(args: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {key}"))
}

fn opt_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn opt_u64(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(Value::as_u64)
}
