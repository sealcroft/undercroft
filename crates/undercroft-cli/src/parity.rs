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
//! agent surface. Those are recorded as `Operator` and the test requires them
//! to be absent from MCP, so the boundary is enforced by the same mechanism
//! that enforces the parity.

/// Where a capability is reachable from. The point of the type is that a
/// new capability cannot be added without answering the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Reachable from every surface that could sensibly host it.
    Everywhere,
    /// Operator-only: CLI and `/v1`, and **never** MCP. Reaching one of
    /// these from MCP is a security-boundary violation, not a convenience.
    Operator,
    /// Deliberately one-surface, with the reason recorded beside it.
    Scoped(&'static str),
}

/// The MCP tool inventory. Every tool the server advertises must appear
/// here exactly once, and every entry must name a real tool.
pub const MCP_TOOLS: &[(&str, Reach)] = &[
    // Memory: the agent surface proper.
    ("undercroft_save", Reach::Everywhere),
    ("undercroft_add_drawer", Reach::Everywhere),
    ("undercroft_update_drawer", Reach::Everywhere),
    ("undercroft_delete_drawer", Reach::Everywhere),
    ("undercroft_delete_by_source", Reach::Everywhere),
    ("undercroft_search", Reach::Everywhere),
    ("undercroft_get_drawer", Reach::Everywhere),
    ("undercroft_list_drawers", Reach::Everywhere),
    ("undercroft_wake_up", Reach::Everywhere),
    ("undercroft_check_duplicate", Reach::Everywhere),
    ("undercroft_dedup", Reach::Everywhere),
    ("undercroft_list_wings", Reach::Everywhere),
    ("undercroft_list_rooms", Reach::Everywhere),
    ("undercroft_get_taxonomy", Reach::Everywhere),
    ("undercroft_get_closet_index", Reach::Everywhere),
    ("undercroft_list_agents", Reach::Everywhere),
    ("undercroft_diary_write", Reach::Everywhere),
    ("undercroft_diary_read", Reach::Everywhere),
    ("undercroft_create_tunnel", Reach::Everywhere),
    ("undercroft_list_tunnels", Reach::Everywhere),
    ("undercroft_delete_tunnel", Reach::Everywhere),
    ("undercroft_list_hallways", Reach::Everywhere),
    ("undercroft_follow_tunnel", Reach::Everywhere),
    ("undercroft_traverse", Reach::Everywhere),
    ("undercroft_status", Reach::Everywhere),
    ("undercroft_verify", Reach::Everywhere),
    // Knowledge graph.
    ("undercroft_kg_add", Reach::Everywhere),
    ("undercroft_kg_query", Reach::Everywhere),
    ("undercroft_kg_timeline", Reach::Everywhere),
    ("undercroft_kg_invalidate", Reach::Everywhere),
    ("undercroft_kg_supersede", Reach::Everywhere),
    ("undercroft_kg_stats", Reach::Everywhere),
    ("undercroft_kg_set_authority", Reach::Everywhere),
    ("undercroft_lookup_canonical", Reach::Everywhere),
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

        let inventoried: std::collections::BTreeSet<&str> =
            MCP_TOOLS.iter().map(|(n, _)| *n).collect();
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
             Reach, deciding whether every surface should host them: {missing:?}"
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
        for (name, _) in MCP_TOOLS {
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
    }
}
