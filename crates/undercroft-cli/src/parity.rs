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

#[cfg(test)]
mod tests {
    use super::*;

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
