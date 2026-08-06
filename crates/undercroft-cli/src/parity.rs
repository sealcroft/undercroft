#![allow(dead_code)] // the inventory below is documentation its own tests consume
//! Surface parity — the inventory that fails when a surface drifts.
//!
//! A 14-agent audit once found **65 confirmed drifts** between the CLI, the
//! MCP tools and `/v1`: capabilities present on one surface and missing,
//! weaker, or differently-named on another. 55 of them failed *silently* —
//! a declared configuration that never took effect, a screen a route walked
//! past, an exclusion enforced on one read path and not its neighbour. Every
//! one was born the same way: someone added a capability to two surfaces and
//! forgot the third, and nothing said so.
//!
//! Choke points close a drift *class* where one exists (screening lives at
//! the write choke point; the read-only gate sits in front of dispatch). This
//! module closes the remaining hole, which is arithmetic rather than
//! architectural: **the inventory is written down, and the code is counted
//! against it.** A tool added without a line here fails the build, and a line
//! here without a tool fails it too — so the list cannot rot in either
//! direction, which is the failure mode a hand-maintained doc table has.
//!
//! What this deliberately does NOT assert: that every capability exists on
//! every surface. Some absences are boundaries, not drift — admission review
//! and wing-trust assignment are operator-only and must NEVER reach MCP, the
//! agent surface. Those are recorded in `OPERATOR_ONLY` and the test requires them
//! to be absent from MCP, so the boundary is enforced by the same mechanism
//! that enforces the parity.

/// The MCP tool inventory. Every tool the server advertises must appear
/// here exactly once, and every entry must name a real tool.
pub const MCP_TOOLS: &[&str] = &[
    // Memory: the agent surface proper.
    "undercroft_save",
    "undercroft_add_drawer",
    "undercroft_update_drawer",
    "undercroft_delete_drawer",
    "undercroft_delete_by_source",
    "undercroft_search",
    "undercroft_get_drawer",
    "undercroft_list_drawers",
    "undercroft_wake_up",
    "undercroft_check_duplicate",
    "undercroft_dedup",
    "undercroft_list_wings",
    "undercroft_list_rooms",
    "undercroft_get_taxonomy",
    "undercroft_get_closet_index",
    "undercroft_list_agents",
    "undercroft_diary_write",
    "undercroft_diary_read",
    "undercroft_create_tunnel",
    "undercroft_list_tunnels",
    // Audit-chain history, `HistoryScope::Agent`. On MCP deliberately: an
    // agent that cannot ask "what happened to this memory" cannot audit its
    // own recall, and traceability is what this store sells. Fenced rather
    // than raw — `manage::AGENT_FENCED_NAMESPACES` keeps the review queue,
    // the trust map, retention, destructions, exports, read audits and
    // rotations on the operator planes, which is why this is a tool and not
    // an `OPERATOR_ONLY` entry.
    "undercroft_history",
    "undercroft_delete_tunnel",
    "undercroft_list_hallways",
    "undercroft_follow_tunnel",
    "undercroft_traverse",
    "undercroft_status",
    "undercroft_verify",
    // Knowledge graph.
    "undercroft_kg_add",
    "undercroft_kg_query",
    "undercroft_kg_timeline",
    "undercroft_kg_invalidate",
    "undercroft_kg_supersede",
    "undercroft_kg_stats",
    "undercroft_lookup_canonical",
];

/// Capabilities that must NEVER appear on MCP. Not an oversight to be
/// "fixed" into parity: MCP is the surface an agent drives, and an agent
/// must not be able to rule on the queue that exists to contain it, nor
/// assign the trust class that decides what it may retrieve.
pub const OPERATOR_ONLY: &[&str] = &[
    "admission", // list / allow / deny — ruling on quarantined evidence
    "trust",     // wing trust-class assignment
    "retention", // retention policy declaration and sweeps
    "forget",    // attested destruction
    "rotate",    // key rotation
    // The golden-values authority tier. `lookup_canonical` is the door
    // docs/LABELS.md positions ABOVE semantic recall for exact and
    // high-risk asks, and promoting a fact to canonical/approved closes
    // the previous holder's validity window. An agent that could write it
    // could make its own fact the one answer that door returns — the same
    // reason trust assignment is operator-only, which LABELS.md states in
    // as many words while the authority tier shipped on MCP anyway.
    "authority",
    // Tightening the manifest rollback anchor (R3). It fsyncs a new
    // manifest, and the manifest is the out-of-database evidence a rollback
    // is detected against — so the surface an agent drives must not be able
    // to move it onto whatever the database currently says. Same shape as
    // `rotate`: an operation ON the integrity machinery, not through it.
    "anchor",
    // ---- absences that were absences, not boundaries, until they were
    // ---- written down (ROADMAP C14) --------------------------------------
    //
    // Each of the three below was simply MISSING from MCP with nothing
    // recorded, which under this project's own rule is the finding: "a
    // capability missing from one surface is a boundary or a drift, and
    // which one has to be written down". They are boundaries, and they are
    // asserted by the same test as the rest of this list.
    //
    // `export` moves the whole corpus out of the vault in the clear. It is
    // the egress act — chain-audited on every surface that has it — and an
    // agent that could call it could exfiltrate a palace in one tool call,
    // which no amount of per-drawer fencing would bound.
    "export",
    // `import` writes records the agent did not compose, carrying
    // caller-chosen ids, wings, provenance claims and a `filed_at` that is
    // the retention clock. It is the operator's restore path.
    "import",
    // `refine` spends an LLM budget and distils drawer text into facts the
    // NEXT agent reads as knowledge. An agent that could drive it could
    // launder its own text into the graph through a model.
    "refine",
];

/// Report structs the CLI projects **by hand**, and therefore the ones where
/// adding a field silently fails to reach an operator.
///
/// `/v1` serializes these whole (`serde_json::to_value(&report)`), so a new
/// field reaches the wire for free there. The CLI prints named fields one by
/// one — so the two surfaces drift the moment a struct grows, in the one
/// direction nothing complains about. CLAUDE.md already records this as "a
/// hand-projected handler: adding a struct field does not reach the wire",
/// and it happened again on 2026-08-06: `RotationReport` gained
/// `wing_trusts` and `retention_policies` and `undercroft vault rotate`
/// omitted both, in the same unit that existed to fix forgotten sweeps.
///
/// `(struct file, struct name, projecting file, projecting anchor)` — one
/// entry per (struct × surface), because a struct hand-projected on three
/// surfaces can drift on any one of them independently. `VerifyReport` is
/// exactly that: `main.rs` prints it, `mcp.rs` formats it into text and
/// `tenant.rs` builds a JSON object field by field, so its fourth leg
/// (`orphan_labels`) had to be added in three places and would have reached
/// none of them silently.
pub const HAND_PROJECTED: &[(&str, &str, &str, &str)] = &[
    (
        "rotate.rs",
        "RotationReport",
        "main.rs",
        "VaultAction::Rotate",
    ),
    ("lib.rs", "VerifyReport", "main.rs", "Command::Verify"),
    (
        "lib.rs",
        "VerifyReport",
        "mcp.rs",
        "\"undercroft_verify\" =>",
    ),
    ("lib.rs", "VerifyReport", "tenant.rs", "fn verify(&mut self"),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// **No tracked text file carries a CRLF line ending.**
    ///
    /// `.gitattributes` declares `* text=auto eol=lf` and says why in as many
    /// words: *"Docker-first project … Force LF on checkout so a Windows
    /// clone (core.autocrlf=true) doesn't smudge shell scripts into CRLF and
    /// break them in the containers."* That declaration was **enforced by
    /// nothing**, and on 2026-08-06 a batch of scripted edits written in text
    /// mode on Windows converted eleven files — including `tests/e2e.sh` —
    /// which died in the container with `$'\r': command not found` before a
    /// single check ran.
    ///
    /// It also poisons review: the same edits made `CLAUDE.md` show 1,415
    /// changed lines for a 100-line change, which is how a real defect hides
    /// inside a diff nobody can read.
    ///
    /// **Scope: `crates/` only, and that boundary is deliberate.** No
    /// container image carries the whole repo — the `test`/`lint` image
    /// COPYs `Cargo.toml`, `Cargo.lock` and `crates/` and nothing else, and
    /// each e2e service bind-mounts its single script. A test that walked the
    /// repo root would therefore scan 82 files in the battery and pass while
    /// seeing none of `tests/`, which is a gate that silently does not run —
    /// the failure mode this project spends its time closing. So this owns
    /// the subtree it can always see completely (where the 3,667-line
    /// `main.rs` corruption happened), and `tests/battery.sh` owns the whole
    /// tree host-side (where `tests/e2e.sh` lives). Two scopes, one rule,
    /// neither able to under-run in silence.
    #[test]
    fn no_source_file_has_crlf_line_endings() {
        // The `crates/` subtree: present and complete in every context this
        // test runs in — a full checkout in CI, a mounted repo locally, and
        // the partial COPY inside the test image.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
            .expect("the crates directory is one level up from this crate");
        // Extensions whose CRLF either breaks execution or wrecks a diff.
        const TEXT: &[&str] = &[
            "sh", "rs", "md", "toml", "yml", "yaml", "html", "json", "css", "js", "svg", "txt",
            "sql", "lock",
        ];
        // Directories that are build output, vendored, or not ours.
        const SKIP: &[&str] = &["target", ".git", "book", "node_modules", "assets", "pdf"];
        let mut offenders: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                let name = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if p.is_dir() {
                    if !SKIP.contains(&name.as_str()) && !name.starts_with('.') {
                        stack.push(p);
                    }
                    continue;
                }
                let ext = p
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_string();
                if !TEXT.contains(&ext.as_str()) {
                    continue;
                }
                let Ok(bytes) = std::fs::read(&p) else {
                    continue;
                };
                scanned += 1;
                let crlf = bytes.windows(2).filter(|w| w == b"\r\n").count();
                if crlf > 0 {
                    offenders.push(format!(
                        "{} ({crlf} CRLF)",
                        p.strip_prefix(&root).unwrap_or(&p).display()
                    ));
                }
            }
        }
        assert!(
            scanned > 50,
            "premise: the walker actually found the crates tree, scanned only {scanned} files"
        );
        offenders.sort();
        assert!(
            offenders.is_empty(),
            "these tracked text files have CRLF line endings, which \
             `.gitattributes` forbids (`* text=auto eol=lf`) because a CRLF \
             shell script fails in the containers and a CRLF rewrite makes a \
             small change unreviewable. Normalise them in BINARY mode — a \
             text-mode write on Windows is what introduced them:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// **Every field of a hand-projected report reaches the CLI.**
    ///
    /// The gate for the drift class CLAUDE.md names and this branch kept
    /// paying for: a report struct grows, `/v1` serializes it whole and picks
    /// the field up for free, and the CLI's hand-written `println!` block
    /// does not — so the operator surface silently reports less than the REST
    /// surface. Nothing in the type system or the test suite notices, because
    /// both surfaces still compile and still pass.
    ///
    /// Field names are read out of the struct definition in the store crate
    /// and each one is required to appear in the CLI's projecting function.
    /// It fails in both directions: a new field with no `println!` fails, and
    /// an entry in `HAND_PROJECTED` naming a struct or function that no
    /// longer exists fails too, so the inventory cannot rot into decoration.
    #[test]
    fn every_hand_projected_report_field_reaches_the_cli() {
        let store_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../undercroft-store/src")
            .canonicalize()
            .expect("the store crate sits beside this one");
        for (struct_file, struct_name, proj_file, proj_fn) in HAND_PROJECTED {
            let text = std::fs::read_to_string(store_src.join(struct_file))
                .unwrap_or_else(|e| panic!("{struct_file}: {e}"));
            // The struct body: from `pub struct <name> {` to its closing brace
            // at column 0.
            let needle = format!("pub struct {struct_name} {{");
            let at = text.find(&needle).unwrap_or_else(|| {
                panic!("{struct_name} is not defined in {struct_file} any more")
            });
            let body = &text[at + needle.len()..];
            let end = body.find("\n}").unwrap_or(body.len());
            let fields: Vec<String> = body[..end]
                .lines()
                .filter_map(|l| {
                    let t = l.trim();
                    // `pub name: Type,` — doc comments and attributes skipped.
                    let rest = t.strip_prefix("pub ")?;
                    let name = rest.split(':').next()?.trim();
                    (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
                        .then(|| name.to_string())
                })
                .collect();
            assert!(
                fields.len() >= 3,
                "premise: the field extractor actually read {struct_name}, got {fields:?}"
            );

            // The projecting function's body in the CLI.
            let cli = match *proj_file {
                "main.rs" => include_str!("main.rs"),
                "mcp.rs" => include_str!("mcp.rs"),
                "tenant.rs" => include_str!("tenant.rs"),
                other => panic!("no reader wired for {other}"),
            };
            let at = cli.find(proj_fn).unwrap_or_else(|| {
                panic!("{proj_fn} is not in {proj_file} any more — stale HAND_PROJECTED entry")
            });
            // Bounded window, scanning FORWARD from the anchor — so the
            // anchor must be the START of the projecting block. Anchoring
            // mid-handler reported a false drift on `supersessions`, which
            // MCP consumes into `sup_line` a few lines ABOVE its format
            // string. A generous slice is fine: a field name appearing
            // anywhere in the block is what we require.
            let window = &cli[at..cli.len().min(at + 4000)];
            let missing: Vec<&String> = fields
                .iter()
                .filter(|f| !window.contains(f.as_str()))
                .collect();
            assert!(
                missing.is_empty(),
                "{struct_name} has fields the CLI's {proj_fn} never prints, so \
                 `/v1` (which serializes the struct whole) reports them and the \
                 operator surface does not: {missing:?}"
            );
        }
    }

    /// The MCP tool surface matches its inventory, in BOTH directions.
    ///
    /// A tool added to the server without a line here fails; a line here
    /// naming a tool that no longer exists fails too. The second half is
    /// what stops the inventory becoming the stale doc table it replaces.
    #[test]
    fn the_mcp_tool_surface_matches_its_inventory() {
        let src = include_str!("mcp.rs");
        // Every tool the server advertises, taken from the definitions
        // themselves rather than from a count someone maintains by hand.
        // Tools are declared as `tool("undercroft_x", ...)` in
        // `tool_definitions`, so that call is the surface of record.
        let advertised: std::collections::BTreeSet<&str> = src
            .match_indices("tool(\"undercroft_")
            .map(|(i, _)| {
                let rest = &src[i + "tool(\"".len()..];
                &rest[..rest.find('"').expect("a closing quote")]
            })
            .collect();
        assert!(
            !advertised.is_empty(),
            "found no tool definitions — the extraction, not the surface, is broken"
        );

        let inventoried: std::collections::BTreeSet<&str> = MCP_TOOLS.iter().copied().collect();
        assert_eq!(
            MCP_TOOLS.len(),
            inventoried.len(),
            "a tool is listed twice in MCP_TOOLS"
        );

        let missing: Vec<_> = advertised.difference(&inventoried).collect();
        let stale: Vec<_> = inventoried.difference(&advertised).collect();
        assert!(
            missing.is_empty(),
            "these MCP tools are not in the parity inventory — add them with a \
             line, deciding whether every surface should host them: {missing:?}"
        );
        assert!(
            stale.is_empty(),
            "these inventory entries name tools that no longer exist: {stale:?}"
        );
    }

    /// Operator-only capabilities are absent from MCP — the boundary, not
    /// a gap. Enforced by the same mechanism as the parity so the two
    /// cannot disagree about what MCP is allowed to reach.
    #[test]
    fn operator_only_capabilities_never_reach_mcp() {
        let src = include_str!("mcp.rs");
        for cap in OPERATOR_ONLY {
            // The capability ANYWHERE in a tool name, not only as a prefix.
            // `tool("undercroft_{cap}` could not express "no MCP tool may
            // write the authority tier", because the tool was called
            // `undercroft_kg_set_authority` — so the boundary was
            // inexpressible in this list and the check silently passed on
            // zero matches. A list that cannot state a boundary is worse
            // than no list, because it reads as though it did.
            for advertised in MCP_TOOLS {
                assert!(
                    !advertised.contains(cap),
                    "{advertised} carries the operator-only capability                      {cap:?}. An agent must not rule on the queue that                      contains it, assign the trust class that decides what                      it may retrieve, or write the authority tier its own                      lookups read. If deliberate, that is a threat-model                      change, not a test change."
                );
            }
            let tool = format!("tool(\"undercroft_{cap}");
            assert!(
                !src.contains(&tool),
                "undercroft_{cap}* is exposed over MCP. That is an operator \
                 surface: an agent must not rule on the queue that contains \
                 it, or assign the trust class that decides what it can \
                 retrieve. If this was deliberate, it needs a threat-model \
                 change, not a test change."
            );
        }
    }

    /// Every mutating MCP tool is listed in `WRITE_TOOLS`, so `--read-only`
    /// refuses it. The audit found `--read-only` leaking on other paths;
    /// this keeps the MCP half honest as tools are added.
    #[test]
    fn every_mutating_tool_is_refused_when_read_only() {
        let src = include_str!("mcp.rs");
        let write_list = {
            let start = src.find("const WRITE_TOOLS").expect("WRITE_TOOLS exists");
            let end = src[start..].find("];").expect("its terminator") + start;
            &src[start..end]
        };
        // A tool whose name says it changes something must be refused.
        for name in MCP_TOOLS {
            let mutating = ["_save", "_add", "_update", "_delete", "_create", "_write"]
                .iter()
                .any(|v| name.contains(v))
                || name.ends_with("_dedup")
                || name.contains("_invalidate")
                || name.contains("_supersede")
                || name.contains("_set_authority");
            if mutating {
                assert!(
                    write_list.contains(name),
                    "{name} mutates but is not in WRITE_TOOLS, so a --read-only \
                     server would serve it"
                );
            }
        }
        // And the OTHER direction, which this test did not have: every name in
        // `WRITE_TOOLS` must be a tool that still exists. Without it the list
        // rots exactly as a doc table does — removing
        // `undercroft_kg_set_authority` from the surface left its entry behind,
        // and nothing failed. That is the rot this module's header claims to
        // prevent in BOTH directions; it was true of `MCP_TOOLS` only.
        for line in write_list.lines() {
            let Some(name) = line.trim().strip_prefix('"') else {
                continue;
            };
            let Some(name) = name.split('"').next() else {
                continue;
            };
            if !name.starts_with("undercroft_") {
                continue;
            }
            assert!(
                MCP_TOOLS.contains(&name),
                "WRITE_TOOLS lists {name}, which is not an advertised tool — a \
                 stale entry here reads as a boundary that is being enforced \
                 and is not"
            );
        }
    }
}
