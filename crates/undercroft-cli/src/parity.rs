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
/// **Every `UNDERCROFT_*` variable the engine honours - the inventory the
/// code is counted against, in both directions.**
///
/// There was no gate for this at all: the counts in `CLAUDE.md` and
/// `architecture/index.html` were hand-maintained prose, and the dimension
/// whose whole job is "a declared configuration that never took effect" had
/// its own census go stale and be repaired by hand. A number in prose is a
/// claim about the moment someone last counted.
///
/// `undercroft-bench` is excluded deliberately - its `UNDERCROFT_VS_*` and
/// `UNDERCROFT_TEST_*` belong to the harness rather than to the engine, and
/// the canonical count in `CLAUDE.md` has always excluded them.
///
/// Adding a variable means adding a line here. That is the point.
/// How a declaration behaves when its value does not parse.
///
/// **Derived from the configuration doctrine `architecture/index.html`
/// already states**, not invented for this list. That page's header is
/// *"everything is environment-driven, and every default is the conservative
/// choice"*, and its four stated reasons include *"integrity is not a tier"*
/// and *"outward paths are explicit — setting it is a visible decision about
/// data leaving the machine"*.
///
/// Read together those give the rule the tree had been applying
/// inconsistently, one call site at a time:
///
/// * If the default is already conservative and a declaration merely ADJUSTS
///   it, falling back on garbage costs the operator their tuning and nothing
///   else. Warn, keep the conservative default.
/// * If the DECLARATION is what turns a protection on, pins an outward path,
///   or names which vector space a vault is in, then the default is "off" and
///   falling back **removes what the operator asked for** — silently, on a
///   deployment that believes it is protected. Refuse.
///
/// The second is "integrity is not a tier" extended by one step: a protection
/// an operator declared must not become a tier by typo. Every variable is
/// classified, and `every_engine_env_var_is_inventoried_and_every_entry_is_read`
/// counts the list against the code in both directions — so a new variable
/// does not compile until someone decides which it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigClass {
    /// The declaration turns a protection on, pins an outward path, or names
    /// the vector space. Garbage REFUSES to open.
    Protects,
    /// A knob over a default that is already the conservative choice.
    /// Garbage warns and keeps that default.
    Tunes,
}

/// **Whether `undercroft config check` runs a real parse for a declaration.**
///
/// ROADMAP O52 (round-four #25, the reporting half). `check_one` falls to a
/// catch-all that renders an unknown name as `Finding::Accepted`, printed as
/// *"no parse to run; the consumer validates it"* — and that message is
/// indistinguishable between a variable that genuinely has nothing to parse
/// (a path, a URL, a bearer, a model name) and one whose parse somebody
/// forgot to wire up. The `Protects` half of that gap was closed by
/// round-four #9's both-directions gate; the `Tunes` half was not, and O48
/// widened it by teaching eleven `Tunes` resolvers to validate values the
/// pre-flight still described as unvalidated.
///
/// So the axis is declared per variable and counted against the code in BOTH
/// directions by [`super::config_check::tests`]: a `Checked` variable the
/// pre-flight runs no parse for fails the build, and an `Opaque` one that IS
/// pre-flighted fails it too — good news that has to be recorded rather than
/// left to rot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parse {
    /// `undercroft config check` runs the real resolver for this declaration.
    Checked,
    /// There is no parse to run. Its only real validation is the thing that
    /// consumes it — an endpoint that answers, a file that opens, a model
    /// that loads. Saying so is honest; saying "checked" would not be.
    Opaque,
}

use ConfigClass::{Protects, Tunes};
use Parse::{Checked, Opaque};

pub const ENGINE_ENV_VARS: &[(&str, ConfigClass, Parse)] = &[
    ("UNDERCROFT_ADMISSION", Protects, Checked),
    ("UNDERCROFT_ADMISSION_LLM", Protects, Checked),
    ("UNDERCROFT_ADMISSION_RATE", Protects, Checked),
    ("UNDERCROFT_ADMIT_TRUSTED_SOURCES", Protects, Opaque),
    ("UNDERCROFT_ASSERTION_SECRET", Protects, Checked),
    ("UNDERCROFT_CHROMA_URL", Tunes, Opaque),
    ("UNDERCROFT_COLBERT_MODEL", Tunes, Opaque),
    ("UNDERCROFT_COLBERT_NAME", Tunes, Opaque),
    ("UNDERCROFT_COLBERT_QUERY_MODEL", Tunes, Opaque),
    ("UNDERCROFT_COLBERT_TOKENIZER", Tunes, Opaque),
    ("UNDERCROFT_EMBEDDER", Protects, Checked),
    ("UNDERCROFT_EMBED_API", Tunes, Checked),
    ("UNDERCROFT_EMBED_CA", Protects, Checked),
    ("UNDERCROFT_EMBED_DIM", Tunes, Checked),
    ("UNDERCROFT_EMBED_KEY", Tunes, Opaque),
    ("UNDERCROFT_EMBED_MODEL", Tunes, Opaque),
    ("UNDERCROFT_EMBED_URL", Tunes, Opaque),
    ("UNDERCROFT_FDE_DPROJ", Tunes, Checked),
    ("UNDERCROFT_FDE_IVF_MIN", Tunes, Checked),
    ("UNDERCROFT_FDE_KSIM", Tunes, Checked),
    ("UNDERCROFT_FDE_NPROBE", Tunes, Checked),
    ("UNDERCROFT_FDE_PQ_MIN", Tunes, Checked),
    ("UNDERCROFT_FDE_REPS", Tunes, Checked),
    ("UNDERCROFT_FDE_SEED", Tunes, Checked),
    ("UNDERCROFT_FORCE_EMBEDDER", Protects, Opaque),
    ("UNDERCROFT_FTS_PREFILTER_MIN", Tunes, Checked),
    ("UNDERCROFT_FUSION", Tunes, Checked),
    ("UNDERCROFT_FUSION_WEIGHT", Tunes, Checked),
    ("UNDERCROFT_HOME", Tunes, Opaque),
    ("UNDERCROFT_INDEX_CA", Protects, Checked),
    ("UNDERCROFT_IVF_MIN", Tunes, Checked),
    ("UNDERCROFT_IVF_NPROBE", Tunes, Checked),
    ("UNDERCROFT_LANG", Tunes, Opaque),
    ("UNDERCROFT_LATE_TOP_N", Tunes, Checked),
    ("UNDERCROFT_LLM_API", Tunes, Checked),
    ("UNDERCROFT_LLM_CA", Protects, Checked),
    ("UNDERCROFT_LLM_KEY", Tunes, Opaque),
    ("UNDERCROFT_LLM_MODEL", Tunes, Opaque),
    ("UNDERCROFT_LLM_URL", Tunes, Opaque),
    ("UNDERCROFT_LOG", Tunes, Opaque),
    ("UNDERCROFT_LOG_FORMAT", Tunes, Opaque),
    ("UNDERCROFT_MCP_HTTP_TOKEN", Protects, Checked),
    ("UNDERCROFT_METRICS", Tunes, Checked),
    ("UNDERCROFT_MILVUS_URL", Tunes, Opaque),
    ("UNDERCROFT_ONNX_MODEL", Tunes, Opaque),
    ("UNDERCROFT_ONNX_NAME", Tunes, Opaque),
    ("UNDERCROFT_ONNX_TOKENIZER", Tunes, Opaque),
    ("UNDERCROFT_ORCH_ADDR", Tunes, Opaque),
    ("UNDERCROFT_ORCH_ADMIN_TOKEN", Protects, Checked),
    ("UNDERCROFT_ORCH_DB", Tunes, Opaque),
    ("UNDERCROFT_ORCH_ENGINE_CA", Protects, Checked),
    ("UNDERCROFT_ORCH_KEY", Protects, Checked),
    // The control plane's metrics listener (O20). `_ADDR` is `Protects`
    // because declaring it OPENS a network surface, and `_TOKEN` because it
    // is what makes a non-loopback listener legal at all.
    ("UNDERCROFT_ORCH_METRICS_ADDR", Protects, Checked),
    ("UNDERCROFT_ORCH_METRICS_TOKEN", Protects, Checked),
    ("UNDERCROFT_ORCH_RATE_LIMIT", Protects, Checked),
    ("UNDERCROFT_ORT_POOL", Tunes, Checked),
    // An OUTWARD PATH, and `architecture/index.html` has always named it as
    // one of the four. `Tunes` made `config check` print "warn … keeps the
    // conservative default" for a declaration that now stops the process,
    // because the pre-flight derives fatal-vs-warn from this class alone.
    ("UNDERCROFT_OTLP_ENDPOINT", Protects, Checked),
    ("UNDERCROFT_OTLP_CA", Protects, Checked),
    ("UNDERCROFT_OTLP_HEADERS", Tunes, Opaque),
    ("UNDERCROFT_PASSPHRASE", Protects, Checked),
    ("UNDERCROFT_PGVECTOR_DSN", Tunes, Opaque),
    ("UNDERCROFT_POOL_DIV", Tunes, Checked),
    ("UNDERCROFT_PQ_PAGE_MIN", Tunes, Checked),
    ("UNDERCROFT_QDRANT_URL", Tunes, Opaque),
    ("UNDERCROFT_READ_AUDIT", Protects, Checked),
    ("UNDERCROFT_RERANKER", Tunes, Checked),
    ("UNDERCROFT_RERANK_MODEL", Tunes, Opaque),
    ("UNDERCROFT_RERANK_NAME", Tunes, Opaque),
    ("UNDERCROFT_RERANK_TOKENIZER", Tunes, Opaque),
    ("UNDERCROFT_RERANK_TOP_N", Tunes, Checked),
    ("UNDERCROFT_RETRIEVAL", Protects, Checked),
    ("UNDERCROFT_SAMPLE_INTERVAL_MS", Tunes, Checked),
    ("UNDERCROFT_SEARCH_TRACE", Tunes, Opaque),
    ("UNDERCROFT_SEMANTIC_FLOOR", Tunes, Checked),
    ("UNDERCROFT_SEMANTIC_GATE", Protects, Checked),
    ("UNDERCROFT_SERVICE_NAME", Tunes, Opaque),
    ("UNDERCROFT_TOK_PQ_MIN", Tunes, Checked),
    ("UNDERCROFT_TRAIN_SOURCE_CAP", Tunes, Checked),
    ("UNDERCROFT_TRUST_FLOOR", Protects, Checked),
    ("UNDERCROFT_WEAVIATE_URL", Tunes, Opaque),
    ("UNDERCROFT_WING_PQ_MIN", Tunes, Checked),
];

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
    // ---- written down, and counted against the code -----------------------
    //
    // (Closed as ROADMAP C14; the id is a breadcrumb into the CHANGELOG,
    // not a pointer to a live entry — see ROADMAP's "identifier scheme".)
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
/// How a capability's absence from a surface is ruled (ROADMAP M16).
///
/// `CLAUDE.md`: *"A capability missing from one surface is a boundary or a
/// drift, and which one has to be written down."* `OPERATOR_ONLY` does this
/// for the MCP axis and `OPS_DELIBERATELY_ABSENT` for the orchestrator's ops
/// plane. **Nothing did it for the CLI axis**, so every CLI-only capability
/// was an unrecorded gap by construction — round-four #34.
///
/// Measured before this existed: **74** CLI operations (24 leaf `Command`
/// variants plus 50 sub-actions across 14 action enums), of which `parity.rs`
/// named **17**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absence {
    /// Deliberate, with a reason that is an argument rather than a
    /// restatement. The reason must say what would go wrong if the
    /// capability were exposed there.
    Boundary,
    /// The capability cannot meaningfully exist on that surface — it opens no
    /// vault, mints a local secret, or IS the process. Not a decision anyone
    /// could make differently.
    Structural,
    /// A gap. Something that should be reachable and is not, with a target.
    /// **Never a principled refusal wearing a reason**, which `CLAUDE.md`
    /// forbids in as many words.
    Drift,
    /// Measured, not yet ruled. The honest state for a capability whose
    /// absence is a PRODUCT decision rather than one the code or the doctrine
    /// settles. A row here is not a smaller `Boundary`: it says nobody has
    /// decided, and it carries the entry where the decision is filed.
    ///
    /// This variant exists because the alternative was inventing thirty-odd
    /// reasons, and an inventory whose reasons were guessed reads as ruled
    /// while being fiction — strictly worse than no inventory, because it
    /// stops the next reader looking.
    Unruled,
}

/// Every CLI operation that is NOT reachable from all three engine surfaces,
/// with its ruling. `(cli_anchor, absent_from, kind, reason)`.
///
/// `cli_anchor` is the dispatch anchor in `main.rs` — `Command::Dedup`,
/// `BackupAction::Restore` — on the `HAND_PROJECTED` precedent, because an
/// anchor is derivable from source and a prose name is not. `absent_from` is
/// `"mcp"`, `"v1"`, or `"mcp+v1"`.
///
/// Counted in BOTH directions by
/// `every_cli_capability_is_reachable_or_ruled_absent`: a new `Command`
/// variant fails the build until it is here or in `SURFACE_COMPLETE`, and a
/// row naming an anchor `main.rs` no longer has fails it too.
pub const SURFACE_ABSENCES: &[(&str, &str, Absence, &str)] = &[
    // ---- Boundaries the MCP axis already recorded, restated on this axis --
    // These are the `OPERATOR_ONLY` entries. They are repeated here rather
    // than cross-referenced because this inventory must PARTITION the CLI
    // surface: an anchor missing from both lists is what the gate catches,
    // and "it is in another list" would be a hole in the arithmetic.
    ("AdmissionAction::List", "mcp", Absence::Boundary,
     "an agent must not read the queue that exists to contain its own diverted writes"),
    ("AdmissionAction::Allow", "mcp", Absence::Boundary,
     "ruling on quarantined evidence is the operator's; an agent allowing its own write defeats the screen"),
    ("AdmissionAction::Deny", "mcp", Absence::Boundary,
     "deny DESTROYS through forget_with_proof and hands back an attestation"),
    ("TrustAction::Set", "mcp", Absence::Boundary,
     "trust decides what a query may retrieve; an agent assigning it chooses its own floor"),
    ("TrustAction::List", "mcp", Absence::Boundary,
     "reading the trust map tells an agent exactly which wing to write into to be believed"),
    ("RetentionAction::Set", "mcp", Absence::Boundary,
     "a retention policy is a standing authorisation to destroy; declaring it is operator-only"),
    ("RetentionAction::Clear", "mcp", Absence::Boundary,
     "clearing a policy removes a destruction bound the operator set"),
    ("RetentionAction::List", "mcp", Absence::Boundary,
     "paired with Set: the surface that may not declare a policy has no business enumerating them"),
    ("RetentionAction::Sweep", "mcp", Absence::Boundary,
     "the sweep is the destruction itself, receipted per run"),
    ("Command::Forget", "mcp", Absence::Boundary,
     "attested destruction; the receipt is the product and an agent must not mint one"),
    ("VaultAction::Rotate", "mcp", Absence::Boundary,
     "the largest single mutation the engine performs, re-keying every sealed artifact"),
    ("VaultAction::Anchor", "mcp", Absence::Boundary,
     "it moves the out-of-database evidence a rollback is detected against (R3)"),
    ("KgAction::Authority", "mcp", Absence::Boundary,
     "promotion closes the previous canonical holder's window, so an agent could make its own fact the one answer lookup_canonical returns"),
    ("Command::Export", "mcp", Absence::Boundary,
     "egress. Chain-audited unconditionally, and an agent must not choose the recipient"),
    ("Command::Import", "mcp", Absence::Boundary,
     "an import writes a whole corpus past the surface an agent is scoped to"),
    ("Command::Refine", "mcp", Absence::Boundary,
     "distillation drives an LLM over vault content; the model is itself an injection target"),

    // ---- Structural: not a decision anyone could make differently ---------
    ("Command::Hooks", "mcp+v1", Absence::Structural,
     "prints agent hook configuration to stdout and opens no vault"),
    ("TranscriptAction::Render", "mcp+v1", Absence::Structural,
     "renders a local file to text; it opens no vault, so there is nothing remote to expose"),
    ("ConfigAction::Check", "mcp+v1", Absence::Structural,
     "pre-flights THIS process's environment. A remote route would answer about the server's, which is a different question the server already answers by starting"),
    ("Command::ConfigCheck", "mcp+v1", Absence::Structural,
     "the legacy spelling of ConfigAction::Check, same dispatch arm"),
    ("Command::ServeMcp", "mcp+v1", Absence::Structural,
     "it IS the MCP surface; a surface cannot expose its own process mode"),
    ("Command::ServeHttp", "mcp+v1", Absence::Structural,
     "it IS the /v1 surface; a running server cannot expose the act of starting itself, and a route that spawned another would be a process manager rather than a memory engine"),
    ("DaemonAction::Run", "mcp+v1", Absence::Structural,
     "a process mode, not a capability"),
    ("Command::AssertHeader", "mcp+v1", Absence::Boundary,
     "mints a per-vault assertion from a local secret. A server that minted your credential for you would be the thing the assertion exists to prove against"),
    ("Command::Init", "mcp+v1", Absence::Boundary,
     "creates a palace on local disk. /v1 has vault-create for an EXISTING installation; bootstrapping the installation itself is not a remote act"),
    ("VaultAction::Create", "mcp", Absence::Boundary,
     "vault lifecycle is control-plane. An agent operates WITHIN a vault it was granted, and creating one is how it would escape that scope"),
    ("VaultAction::List", "mcp", Absence::Boundary,
     "enumerating vaults tells an agent what exists beyond its own"),

    // ---- Boundaries this unit ruled, each with a citable argument ---------
    ("Command::Mine", "mcp+v1", Absence::Boundary,
     "reads a directory path the CALLER names. Remotely that is a caller directing server-side filesystem reads, which is a traversal primitive rather than a memory operation"),
    ("Command::Sweep", "mcp+v1", Absence::Boundary,
     "same as Mine: a caller-named path on the server's filesystem"),
    ("IndexAction::Push", "mcp+v1", Absence::Boundary,
     "EGRESS. Every push carries embeddings, which are plaintext-derived; an agent choosing when and where the corpus leaves is the decision undercroft-net exists to keep operator-side"),
    ("BundleAction::Keygen", "mcp+v1", Absence::Boundary,
     "mints a SECRET key. A server that generated your identity would hold the half only you may hold"),
    ("BundleAction::SignKeygen", "mcp+v1", Absence::Boundary,
     "mints a signing secret; same argument as Keygen"),
    ("BundleAction::Recipient", "mcp+v1", Absence::Boundary,
     "derives a public identity from a local secret file, which the surface does not have"),
    ("BundleAction::Sender", "mcp+v1", Absence::Boundary,
     "reads a local signing secret to attest a bundle"),
    ("Command::Repair", "mcp", Absence::Boundary,
     "operates ON the storage machinery rather than through it — it rewrites fingerprints, re-embeds and vacuums. Same shape as Rotate and Anchor, which are operator-only for the same reason"),
    ("BackupAction::Restore", "mcp", Absence::Boundary,
     "remove_dir_all on a live vault directory, replaced wholesale. The most destructive operation in the tree"),
    ("BackupAction::Create", "mcp", Absence::Boundary,
     "writes an archive to a caller-named server path, and gates on the verify verdict"),
    ("BackupAction::List", "mcp", Absence::Boundary,
     "enumerates archive paths on the server's filesystem"),

    // ---- Drift: a gap with a target, not a refusal ------------------------
    // The same anchor may appear twice under different surfaces, because the
    // ruling genuinely differs per surface — that is the whole point of
    // keying on (anchor, absent_from) rather than on the anchor alone.
    // `Command::Repair` is the worked example: a Boundary on MCP, above, and
    // it CARRIED a `Drift` row here for `/v1` until M17 closed it by adding
    // `POST /v1/vaults/{id}/repair`. The row is gone because the absence is.
    //
    // **`Absence::Drift` had no instances when M16 wrote this inventory, and
    // that was reported here as a result.** It is no longer true: M26 ruled
    // all 21 remaining `Unruled` rows and every one came back `Drift`, so the
    // variant is now the largest single verdict on this axis after
    // `Boundary`. The sentence stood for a day and was found by re-verifying
    // the filing that quoted it — a comment asserting a COUNT, in the file
    // whose whole job is to stop counts being asserted.
    //
    // What survives of the original point: the variant exists because the
    // doctrine's sentence is *"a boundary or a drift"*, and a vocabulary
    // missing the word for the bad case cannot record the bad case. It is
    // now carrying that weight rather than sitting unused.

    // ---- RULED 2026-08-21 (M26): all of these came back `Drift` -----------
    // This block was headed "Unruled: measured, and the decision is the
    // maintainer's" until every row in it was ruled, and the header outlived
    // the state by one commit — there are now ZERO `Unruled` rows in this
    // file. Kept as a lesson rather than silently retitled: a section header
    // is a claim about what is under it, and it goes stale the moment the
    // rows do.
    //
    // Each row below is a capability reachable from the CLI and from MCP but
    // NOT from `/v1`. That is the classic two-of-three shape, and whether the
    // remote plane should carry the agent-facing memory surface is a PRODUCT
    // decision rather than one the code or the doctrine settles. Filed as
    // ROADMAP O66 — and `Unruled` is deliberately not a quiet `Boundary`.
    //
    // **The kg WRITE family interrupts this block and is NOT Unruled**, for
    // the reason given at its own comment: a document already ruled it in the
    // present tense, and the first pass recorded it as undecided anyway.
    // Before adding a row here, check whether some surface has already said
    // so — `Unruled` is for what nobody has decided, not for what nobody
    // looked up.
    // **RULED 2026-08-21 (ROADMAP O66): `/v1` carries the agent-facing
    // memory surface.** The maintainer was given three readings — full agent
    // surface, operator-and-search plane, or reads-yes-writes-no — and took
    // the first. So every row below is a GAP, not a boundary, and
    // `docs/remote-server.md`'s "for programmatic (non-MCP) callers" is kept
    // as written because the ruling makes it true rather than aspirational.
    //
    // **Target: O68**, which is the scheduling decision, deliberately not a
    // version. Ruling that something is a gap and deciding when it is closed
    // are two questions; this file records the first and O68 holds the
    // second. A `Drift` row MUST name a target — the variant's own doc says
    // "with a target" — and `every_cli_capability_is_reachable_or_ruled_absent`
    // enforces it, so a gap cannot become `Unruled` wearing a different
    // variant by having nowhere to go.
    // ---- The kg WRITE family: already ruled, by a document, in the present
    // tense. `docs/AGENTS.md` says "/v1 has no DIRECT KG *write* routes
    // except POST …/kg/authority … That is a present-tense boundary, not a
    // future item." These three left `Unruled` on the reading that it ruled
    // the FAMILY and not each capability — but a family boundary that names
    // its one exception has decided every member, and treating a written
    // ruling as undecided pushes a settled question back to the maintainer.
    //
    // The argument the doc states, restated as what would go wrong: a fact
    // carries the EXTRACTOR IDENTITY inside its HMAC (canonical extension
    // 0x1d), and the authority tier promotes facts into the one answer
    // `lookup_canonical` returns. A caller-supplied subject/predicate/object
    // over REST mints a fact attributable to a bearer rather than to a named
    // extractor, under a plane whose token reaches every route. `refine` is
    // the deliberate contrast and the reason "direct" is in the rule: it
    // CREATES facts on this plane, from drawer text, through an extractor
    // whose identity is recorded and HMAC-covered.
    ("KgAction::Add", "v1", Absence::Boundary,
     "a REST-asserted fact would carry a bearer as its provenance instead of a named extractor, and the extractor identity is inside the fact's HMAC; refine creates facts here and is attributable, which is the distinction (docs/AGENTS.md)"),
    ("KgAction::Invalidate", "v1", Absence::Boundary,
     "invalidating is asserting a fact is wrong, and it is audited against the asserter; the same provenance argument as Add, and /v1 carries no direct kg write except authority (docs/AGENTS.md)"),
    ("KgAction::Supersede", "v1", Absence::Boundary,
     "superseding CLOSES the previous holder's window, so a bearer could make its own fact the one answer lookup_canonical returns — which is why authority promotion is operator-only in the first place (docs/AGENTS.md)"),
    // **RULED 2026-08-21 (ROADMAP O66), the four singletons.** Both READS
    // (`kg rel`, `index status`) are gaps on the same reasoning as the block
    // above: a read belongs on the surfaces that read. Both VERIFICATION
    // reads (`kg receipts`, `verify-forgetting`) are gaps too — the shape
    // that made them look like boundaries is the INVERSE of the operator-only
    // one (present on `/v1`, absent from MCP), and the operator-only argument
    // therefore never applied to them.
    ("KgAction::Rel", "mcp+v1", Absence::Drift,
     "query facts by predicate — the only kg READ shape neither agent surface has, and it is not composable from the entity-shaped kg_query they do have (target O68)"),
    ("KgAction::Receipts", "mcp", Absence::Drift,
     "per-fact receipt verdicts. MCP's undercroft_verify already reports the aggregate KG-receipt leg, so an agent learns THAT a citation is forged and cannot learn WHICH (target O68)"),
    ("Command::VerifyForgetting", "mcp", Absence::Drift,
     "check a caller-supplied erasure attestation against this vault. Present on /v1 and absent from MCP, which is the inverse of the operator-only shape, so that reasoning never explained it (target O68)"),
    ("IndexAction::Status", "mcp+v1", Absence::Drift,
     "remote-index mirror status. A pure read, unlike Push which is egress — so Push's boundary does not cover it (target O68)"),
    // **RULED 2026-08-21 (ROADMAP O66): all three backup operations reach
    // `/v1`.** The maintainer took the full-parity option over keeping the
    // destructive half on the engine host. Two consequences are recorded
    // here because the ruling does not remove them, it schedules them:
    //
    // * These are PALACE-scoped filesystem operations on the palace root —
    //   `list` opens no vault at all — so they do not fit `/v1/vaults/{id}/`
    //   and need a new path family (`/v1/backups`). That is a shape decision
    //   the route work owes, not a reason to leave them out.
    // * `restore` calls `remove_dir_all` on a live vault directory. On Linux
    //   that succeeds with a server holding an open SQLite handle, leaving
    //   the process serving unlinked inodes and writing them back. A route
    //   MUST close the handle first; O68 carries that as a blocker rather
    //   than a detail.
    ("BackupAction::Create", "v1", Absence::Drift,
     "a fleet operator whose only door is /v1 has no snapshot path and must reach the engine host's filesystem; create is also the one caller that gates archiving on the verify verdict (target O68)"),
    ("BackupAction::List", "v1", Absence::Drift,
     "opens no vault, so a route is trivial — which is exactly what made the absence read as forgotten rather than fenced (target O68)"),
    ("BackupAction::Restore", "v1", Absence::Drift,
     "the most destructive operation in the tree, and ruled reachable. Blocked on a handle-close protocol: remove_dir_all under an open SQLite handle leaves a server serving unlinked inodes (target O68)"),
];

/// CLI operations reachable from all three engine surfaces. The other half of
/// the partition: together with `SURFACE_ABSENCES` this must account for every
/// dispatch anchor in `main.rs`, which is what makes the gate both-directional
/// rather than a list someone tops up.
///
/// A new `Command` variant belongs in exactly one of the two lists, and the
/// build fails until its author says which. That is the whole mechanism —
/// `CLAUDE.md`: *"a tool without a line fails the build and a line without a
/// tool fails it too, which a hand-maintained doc table cannot do."*
pub const SURFACE_COMPLETE: &[&str] = &[
    // Drawer maintenance, landed on `/v1` by ROADMAP O68 (2026-08-31).
    "Command::Dedup",
    "DrawerAction::CheckDup",
    "DrawerAction::DeleteBySource",
    // Diary + session context, landed on `/v1` by ROADMAP O68 (2026-08-31).
    // `wake-up` is the partial one and says so at its handler: the CLI's L0
    // IDENTITY layer reads a per-INSTALLATION file, which a per-vault route
    // proxying a tenant token must not return. The vault-scoped half is here.
    "Command::WakeUp",
    "Command::Closets",
    "Command::Hallways",
    "DiaryAction::Write",
    "DiaryAction::Read",
    "DiaryAction::Agents",
    // The tunnel family, landed on `/v1` by ROADMAP O68 (2026-08-31). All
    // five were `Absence::Drift` with `target O68`; they are reachable from
    // CLI, MCP and `/v1` now, so they move here rather than being edited.
    "TunnelAction::Create",
    "TunnelAction::List",
    "TunnelAction::Follow",
    "TunnelAction::Delete",
    "TunnelAction::Traverse",
    "Command::Remember",
    "Command::Search",
    "Command::Stats",
    "Command::Taxonomy",
    "Command::History",
    "Command::Verify",
    "KgAction::Query",
    "KgAction::Timeline",
    "KgAction::Stats",
    "KgAction::Canonical",
    "DrawerAction::Get",
    "DrawerAction::List",
    "DrawerAction::Update",
    "DrawerAction::Delete",
    "VaultAction::Status",
];

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
        "undercroft-store/src/rotate.rs",
        "RotationReport",
        "undercroft-cli/src/main.rs",
        "VaultAction::Rotate",
    ),
    (
        "undercroft-store/src/lib.rs",
        "VerifyReport",
        "undercroft-cli/src/main.rs",
        "Command::Verify",
    ),
    (
        "undercroft-store/src/lib.rs",
        "VerifyReport",
        "undercroft-cli/src/mcp.rs",
        "\"undercroft_verify\" =>",
    ),
    (
        "undercroft-store/src/lib.rs",
        "VerifyReport",
        "undercroft-cli/src/tenant.rs",
        // Was `fn verify(&mut self` until M17 gave `/v1` a `repair` route.
        // Both routes answer the same verdict shape, so the projection moved
        // into ONE function they share rather than being written out twice —
        // and this gate is what said the anchor had gone stale, listing every
        // field it could no longer see. That is the row doing its job: the
        // fields did not stop being projected, they stopped being projected
        // HERE, and only an anchor that follows them can tell the difference.
        "fn verify_report_json",
    ),
    // **The FOURTH renderer, and the doctrine's four surfaces do not name
    // it.** `ui.html` is `include_str!`'d into every build and served at
    // `GET /ui`; it is a `/v1` CLIENT, so a new leg reaches its wire for free
    // and stops dead unless someone renders it by hand. That is this gate's
    // exact shape one layer out, and it sat outside the gate.
    //
    // Adding the entry immediately found two legs the console had NEVER
    // shown — `orphan_labels` and `mirror_drift`, both of which drive the
    // ✔/✘ verdict it prints — so it could report FAILED while its own
    // breakdown named nothing. Which is the argument for the entry, made by
    // the entry.
    (
        "undercroft-store/src/lib.rs",
        "VerifyReport",
        "undercroft-cli/src/ui.html",
        "async function runVerify()",
    ),
    // `PalaceStats` is the struct CLAUDE.md names as the FIRST one this
    // class of drift bit, and it was the one struct missing from this list
    // — so the gate written after it went straight past it. Added with two
    // live omissions on the CLI (`chain_head`, `read_only`), which is what
    // an inventory nobody counts against looks like from the inside.
    (
        "undercroft-store/src/manage.rs",
        "PalaceStats",
        "undercroft-cli/src/main.rs",
        "Command::Stats",
    ),
    // And `/v1`, which hand-projects it too and says so in its own
    // comment. The first version of this entry added ONE line for a
    // struct the same commit described as hand-projected on TWO
    // surfaces — the rule three lines up spells out why that is not
    // enough.
    (
        "undercroft-store/src/manage.rs",
        "PalaceStats",
        "undercroft-cli/src/tenant.rs",
        "fn stats(&mut self",
    ),
    // **And the FIFTH renderer** (M5). The entry four rows up added
    // `ui.html` for `VerifyReport` and stopped there — so the console, which
    // is a `/v1` CLIENT served at `GET /ui`, stayed outside the gate for the
    // struct `CLAUDE.md` names as the FIRST one this drift class bit.
    //
    // Adding the row found four fields the console had never read:
    // `unhealed`, `read_only`, `codebooks`, and `records` (which it showed
    // only under the route's `drawers` alias). The first two are the ones an
    // operator opens a console to find — `unhealed` exists on `stats` at all
    // *"because a long-lived read-only server's start-up was hours ago"*,
    // and this page is where that operator is looking. Same argument, same
    // file, same shape: which is the argument for the row, made by the row.
    (
        "undercroft-store/src/manage.rs",
        "PalaceStats",
        "undercroft-cli/src/ui.html",
        "async function loadOverview()",
    ),
    // MCP serializes `DedupReport` whole and the CLI hand-projects it, so
    // `dates_kept` — "the difference between collapsing text and losing
    // history", by its own doc comment — reached one surface only. `/v1`
    // has no dedup route at all.
    (
        "undercroft-store/src/manage.rs",
        "DedupReport",
        "undercroft-cli/src/main.rs",
        "Command::Dedup",
    ),
    // **The four the inventory did not name**, each with a
    // whole-serializing counterpart on another surface, so each is exactly
    // the shape this gate exists for: `/v1` reports a new field for free
    // and the operator surface silently does not.
    (
        "undercroft-store/src/manage.rs",
        "AuditRecord",
        "undercroft-cli/src/main.rs",
        "Command::History",
    ),
    (
        "undercroft-store/src/admission.rs",
        "PendingAdmission",
        "undercroft-cli/src/main.rs",
        "AdmissionAction::List",
    ),
    (
        "undercroft-store/src/retention.rs",
        "RetentionPolicy",
        "undercroft-cli/src/main.rs",
        "RetentionAction::List",
    ),
    // The sharpest of the four: `RetentionSweep`'s whole-JSON dump is
    // conditional on `--out`, so without the flag the hand projection is
    // the ONLY report an operator gets.
    (
        "undercroft-store/src/retention.rs",
        "RetentionSweep",
        "undercroft-cli/src/main.rs",
        "RetentionAction::Sweep",
    ),
    // **`RefineReport` was structurally outside this gate's reach**: the
    // reader resolved struct files only under `../undercroft-store/src`,
    // and this one lives in the CLI crate. So the gate could not have
    // caught the drift the fix that added it was closing — it is
    // hand-projected on BOTH surfaces. Paths are crates-relative now,
    // which is what makes a second root a data change rather than a code
    // change.
    (
        "undercroft-cli/src/refine.rs",
        "RefineReport",
        "undercroft-cli/src/main.rs",
        "Command::Refine",
    ),
    (
        "undercroft-cli/src/refine.rs",
        "RefineReport",
        "undercroft-cli/src/tenant.rs",
        "fn refine(&mut self",
    ),
    // **The four the round-three audit found, and the one the old
    // projecting root could not have reached.** Each has a
    // whole-serializing counterpart on another surface, so each is the
    // shape this gate exists for.
    (
        "undercroft-store/src/manage.rs",
        "DrawerSummary",
        "undercroft-cli/src/main.rs",
        "DrawerAction::List",
    ),
    (
        "undercroft-store/src/kg.rs",
        "KgStats",
        "undercroft-cli/src/main.rs",
        "KgAction::Stats",
    ),
    (
        "undercroft-store/src/retention.rs",
        "RetentionSweepEntry",
        "undercroft-cli/src/main.rs",
        "RetentionAction::Sweep",
    ),
    // The orchestrator's own report, in the crate the gate could not read
    // until the projecting path was generalised. `level` is precisely the
    // field whose doc says it exists because "a migration has to recreate
    // the vault on the destination and had no way to ask" — and it was the
    // one `tenant-list` dropped.
    (
        "undercroft-orchestrator/src/state.rs",
        "Tenant",
        "undercroft-orchestrator/src/main.rs",
        "Command::TenantList",
    ),
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
    /// COPYs `Cargo.toml`, `Cargo.lock`, `crates/` and `deploy/` (the last
    /// so `undercroft-obs` can gate the alert rules against the series it
    /// exports) and nothing else, and each e2e service bind-mounts its
    /// single script. `deploy/` is deliberately NOT added to this gate's
    /// scope: it is YAML and JSON that no shell executes, and widening a
    /// gate to whatever happens to be in the image is how its stated scope
    /// stops matching its real one. A test that walked the
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

    /// **No message literal carries a rustfmt-collapsed space run** (O40).
    ///
    /// A `\`-continued string keeps the continued line's indentation, and
    /// **rustfmt does not reformat string literals** — so a wrapped literal
    /// can end up carrying 10–34 spaces mid-sentence and the operator reads a
    /// gap in the middle of a word. Twenty such lines were live across eight
    /// crates before this gate, every one a user-facing refusal, warning or
    /// pre-flight message.
    ///
    /// **The allowlist is the load-bearing half**, because prose continuation
    /// and deliberate column alignment are byte-identical and no pattern over
    /// spaces separates them. A sweep that assumed otherwise was RUN while
    /// closing O40: it matched 58 lines and ate the padding in `config
    /// check`'s aligned output. Measured, the populations are bimodal —
    /// alignment clusters at 3–9 spaces (157 instances, all genuine) and
    /// continuations at 18/22/26/34, the Rust indent depths — but they
    /// overlap at 10–14, which is why the exceptions are named one at a time
    /// rather than inferred.
    #[test]
    fn no_message_literal_carries_a_collapsed_space_run() {
        // Each entry is a claim that the spaces are CONTENT: a table column,
        // SQL, or a deliberate multi-line indent.
        const ALIGNED: &[&str] = &[
            "pair          n",         // bench: an R@k table header
            "tunnels:             {}", // CLI stats: an output column
            "Assign wing trust",       // MCP: a deliberate \n-indented message
            "-> [",                    // core/script.rs: a doc comment's example
            "INSERT INTO kg_entities", // SQL
            "kg_blind_secret",         // SQL
            "FROM kg_entities",        // SQL
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
            .expect("the crates directory is one level up from this crate");
        let mut offenders: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    let name = p
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if name != "target" && name != ".git" {
                        stack.push(p);
                    }
                    continue;
                }
                if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&p) else {
                    continue;
                };
                scanned += 1;
                for (i, line) in text.lines().enumerate() {
                    if !line.contains('"') || ALIGNED.iter().any(|a| line.contains(a)) {
                        continue;
                    }
                    let b = line.as_bytes();
                    let mut run = 0usize;
                    for (j, ch) in b.iter().enumerate() {
                        if *ch == b' ' {
                            run += 1;
                            continue;
                        }
                        if run >= 10 && j > run && b[j - run - 1] != b' ' {
                            offenders.push(format!(
                                "{}:{} ({run} spaces)",
                                p.strip_prefix(&root).unwrap_or(&p).display(),
                                i + 1
                            ));
                            break;
                        }
                        run = 0;
                    }
                }
            }
        }
        // PREMISE: a walker that finds no files reports exactly what a clean
        // tree reports, which is the failure this whole family is about.
        assert!(
            scanned > 50,
            "premise: the walker actually found the crates tree, scanned only {scanned} files"
        );
        offenders.sort();
        assert!(
            offenders.is_empty(),
            "these message literals carry a run of 10+ spaces — a wrapped line whose \
             indentation survived, which an operator reads as a gap mid-sentence. Rejoin \
             the literal, or add a distinctive substring to ALIGNED if the spaces really \
             are content:\n  {}",
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
        // **Two roots, because one of them could not see `RefineReport`.**
        // Struct paths are relative to `crates/`, so a report that lives in
        // the CLI crate — as `RefineReport` does — is a data entry rather
        // than a code change. The old reader joined `../undercroft-store/src`
        // unconditionally, which is why the gate written to catch that
        // struct's drift could not have caught it.
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/ is this crate's parent")
            .to_path_buf();
        for (struct_path, struct_name, proj_file, proj_fn) in HAND_PROJECTED {
            let text = std::fs::read_to_string(crates.join(struct_path))
                .unwrap_or_else(|e| panic!("{struct_path}: {e}"));
            // The struct body: from `[pub[(crate)]] struct <name> {` to its
            // closing brace at column 0. `pub(crate)` is matched too —
            // `RefineReport` is one, and skipping it would have made this
            // gate examine an EMPTY field list and pass.
            let needle = [
                format!("pub struct {struct_name} {{"),
                format!("pub(crate) struct {struct_name} {{"),
            ]
            .into_iter()
            .find(|n| text.contains(n.as_str()))
            .unwrap_or_else(|| panic!("{struct_name} is not defined in {struct_path} any more"));
            let at = text.find(&needle).expect("just found it");
            let body = &text[at + needle.len()..];
            let end = body.find("\n}").unwrap_or(body.len());
            let fields: Vec<String> = body[..end]
                .lines()
                .filter_map(|l| {
                    let t = l.trim();
                    // `pub name: Type,` / `pub(crate) name: Type,` — doc
                    // comments and attributes skipped.
                    let rest = t
                        .strip_prefix("pub(crate) ")
                        .or_else(|| t.strip_prefix("pub "))?;
                    let name = rest.split(':').next()?.trim();
                    (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
                        .then(|| name.to_string())
                })
                .collect();
            assert!(
                fields.len() >= 3,
                "premise: the field extractor actually read {struct_name}, got {fields:?}"
            );

            // **The projecting file is crates-relative too.** The struct
            // root was generalised and this one was left as three hard-coded
            // `include_str!` arms, all under `undercroft-cli/src` — so an
            // orchestrator projection was structurally unreachable, and
            // worse, a bare `main.rs` would have silently read the CLI's.
            // That is how `Tenant.level` — the field that exists because a
            // migration has to ask for it — sat dropped from
            // `tenant-list` with an inventory that could not name it.
            //
            // Read at test time rather than `include_str!`ed: the same
            // mechanism the struct side uses, and the image COPYs `crates/`.
            let cli = std::fs::read_to_string(crates.join(proj_file))
                .unwrap_or_else(|e| panic!("{proj_file}: {e}"));
            let cli = cli.as_str();
            let at = cli.find(proj_fn).unwrap_or_else(|| {
                panic!("{proj_fn} is not in {proj_file} any more — stale HAND_PROJECTED entry")
            });
            // **The window ends at the next projecting block in the same
            // file**, not 4000 characters later. Measured on the old
            // version: the window opened at `Command::Stats` ran through
            // `Command::Taxonomy` and all of `Command::Dedup`, so deleting
            // `println!("rooms: …")` still passed — the word `rooms`
            // appears in a neighbour.
            let from = at + proj_fn.len();
            let tail = &cli[from..];
            // Two kinds of boundary, whichever comes first: the next
            // projecting block in the same file, and the next sibling
            // construct (a new `match` arm, a new method). Either alone
            // leaves a gap — the anchors do not partition a file, and a
            // struct can be projected in the middle of a long method.
            let next = HAND_PROJECTED
                .iter()
                .filter(|(_, _, f, other)| f == proj_file && other != proj_fn)
                .filter_map(|(_, _, _, other)| tail.find(other))
                .chain(
                    // `mcp.rs` has one anchor and no `Command::` arms, so
                    // without a boundary of its own the window ran to the end
                    // of `call_tool` — 14 kB, 3.6x the fixed cap this rule
                    // replaced, i.e. LOOSER on the one file it was meant to
                    // tighten. A tool arm is that file's sibling construct.
                    // The needle is split so this line is not itself one.
                    [
                        "\n        Command::",
                        "\n    fn ",
                        concat!("\n        \"under", "croft_"),
                        // `ui.html`'s sibling construct. Without it the
                        // window runs from `runVerify` to end of file — every
                        // field "found" somewhere in 400 lines of unrelated
                        // console code, which is a gate that cannot fail.
                        "\nasync function ",
                        "\nfunction ",
                    ]
                    .iter()
                    .filter_map(|b| tail.find(b)),
                )
                .min()
                .map(|rel| from + rel)
                .unwrap_or(cli.len());
            let window = &cli[at..next];
            // The premise: a boundary that lands on the anchor itself
            // leaves an empty window, and every field then reads as
            // missing — a failure that looks like a drift and is not.
            assert!(
                window.len() > 200,
                "the window for {proj_fn} in {proj_file} is {} bytes — the boundary rule, \
                 not the projection, is wrong",
                window.len()
            );
            // **And the field must be ACCESSED, not merely spelled.** For 8
            // of 12 `PalaceStats` fields the printed label equals the field
            // name, so substring containment could not tell "prints the
            // value" from "prints the word" — a projection that dropped the
            // value and kept the label passed. `.field` is what a
            // projection has to write to read one.
            // **A field ACCESS, and neither a method call nor a longer
            // name.** Bare `.{field}` containment is receiver-blind and
            // prefix-blind: `PalaceStats.level` was reported satisfied by
            // `/v1`'s `vault.level()` — a different object's METHOD, while
            // the struct field was never read — and `.tag` would match
            // `.tags`, `.at` would match `.attestation`, `.kg` would match
            // `.kg_stats()`. So the character after the name must END it,
            // and must not open a call.
            let reads = |f: &str| {
                let needle = format!(".{f}");
                window.match_indices(&needle).any(|(i, _)| {
                    match window[i + needle.len()..].chars().next() {
                        None => true,
                        Some(c) => !c.is_alphanumeric() && c != '_' && c != '(',
                    }
                })
            };
            let missing: Vec<&String> = fields.iter().filter(|f| !reads(f)).collect();
            assert!(
                missing.is_empty(),
                "{struct_name} has fields the CLI's {proj_fn} never reads, so \
                 `/v1` (which serializes the struct whole) reports them and the \
                 operator surface does not: {missing:?}"
            );
        }
    }

    /// **The Palace Monitor escapes wire data before it becomes HTML**
    /// (ROADMAP M6).
    ///
    /// `log()` builds an `innerHTML` string, and its `text` argument carries
    /// wing and room names straight off the SSE stream. `validate_name`
    /// rejects control characters and path separators but NOT `<`, `>` or
    /// quotes, so `<img src=x onerror=…>` is a legal wing name — and on a
    /// tamper frame the location is read from a row whose HMAC has already
    /// failed, i.e. from bytes an offline writer chose.
    ///
    /// This was reachable before M6 for any non-sealed vault; M6 carries
    /// names on every level and therefore had to close it rather than widen
    /// it. The gate reads the SINK, not the call sites: escaping per call
    /// site is what a future ninth call site forgets.
    #[test]
    fn the_palace_monitor_escapes_what_it_puts_in_html() {
        let src = include_str!("monitor.html");
        // PREMISE: the sink still exists and is still an innerHTML build, or
        // this test is asserting something about a file that moved on.
        let at = src
            .find("function log(kind, text, ts)")
            .expect("monitor.html has no log() sink any more — stale gate");
        let body = &src[at..at + 600];
        assert!(
            body.contains("row.innerHTML"),
            "premise: log() no longer writes innerHTML, so this gate is \
             guarding a sink that is gone: {body}"
        );
        assert!(
            body.contains("${esc(text)}"),
            "log() interpolates `text` into innerHTML unescaped. A wing name \
             may legally contain `<`, and a tamper frame's location comes \
             off a row that failed its own HMAC: {body}"
        );
        assert!(
            src.contains("function esc(v)") && src.contains("replace(/&/g,'&amp;')"),
            "the escaper itself is missing, so `esc(text)` above resolves to \
             nothing and the gate would pass on a broken page"
        );
    }

    /// **The console says what it wants before you can get it wrong.**
    ///
    /// `/ui` rendered a blank shell with an empty status line: no vaults, no
    /// stats, and nothing saying a bearer was required. Reported as "I see
    /// nothing", which is exactly what it looked like. And the server answers
    /// a bare `unauthorized`, so even after pressing CONNECT the message
    /// named neither what was rejected nor what to do.
    ///
    /// Both halves are asserted because they fail independently: a hint can
    /// be deleted without touching the error path, and vice versa.
    #[test]
    fn the_console_names_the_credential_it_needs() {
        let src = include_str!("ui.html");
        assert!(
            src.contains("paste the bearer"),
            "the pre-connect state must say what it is waiting for — a blank \
             page reads as broken, not as unauthenticated"
        );
        assert!(
            src.contains("the bearer was rejected"),
            "a 401 must name the credential; the server's own body is a bare \
             `unauthorized`, which tells an operator nothing actionable"
        );
        // PREMISE: the 401 branch lives in the connect path, not in a comment
        // that happens to quote it.
        let at = src
            .find("async function connect()")
            .expect("connect() is not in ui.html any more — stale gate");
        let window = &src[at..(at + 1800).min(src.len())];
        assert!(
            window.contains("401"),
            "the 401 branch is not inside connect()"
        );
    }

    /// The MCP tool surface matches its inventory, in BOTH directions.
    ///
    /// A tool added to the server without a line here fails; a line here
    /// naming a tool that no longer exists fails too. The second half is
    /// what stops the inventory becoming the stale doc table it replaces.
    /// The MCP tool-name prefix, in ONE place. Every gate below scans
    /// `mcp.rs` as text and keys on it, and a copy left behind by a rename
    /// would search for a string that cannot occur — which passes green
    /// while inspecting nothing. That is the failure this module exists to
    /// prevent, so its own needles may not be spelled out per site.
    const TOOL_PREFIX: &str = "undercroft_";

    /// Every tool the server advertises, taken from the definitions
    /// themselves rather than from a count someone maintains by hand.
    /// Tools are declared as `tool("<prefix>x", ...)` in `tool_definitions`,
    /// so that call is the surface of record.
    ///
    /// It asserts its own premise. An extraction that finds nothing means
    /// the extraction is broken, never that the surface is empty, and
    /// returning an empty set quietly is how every caller downstream turns
    /// into a test that examines zero things and reports success.
    fn advertised_tools(src: &str) -> std::collections::BTreeSet<&str> {
        let needle = format!("tool(\"{TOOL_PREFIX}");
        let found: std::collections::BTreeSet<&str> = src
            .match_indices(&needle)
            .map(|(i, _)| {
                let rest = &src[i + "tool(\"".len()..];
                &rest[..rest.find('"').expect("a closing quote")]
            })
            .collect();
        assert!(
            !found.is_empty(),
            "found no tool definitions matching {needle:?} — the extraction, \
             not the surface, is broken"
        );
        found
    }

    /// Every dispatch anchor `main.rs` defines, DERIVED from its source.
    ///
    /// The enum bodies rather than the dispatch arms: an arm can be written
    /// `Command::Kg { action }` and delegate, so arms under-count the leaves.
    /// Variants are the operations a user can actually reach.
    fn cli_anchors(src: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut current: Option<String> = None;
        // Action enums seen. A `Command` variant that DELEGATES is a router,
        // not an operation — its actions are the operations.
        //
        // Derived from the enum names rather than from the variant line, and
        // that distinction is the whole of why the first version of this
        // extractor was wrong: a router is written
        //   `Kg {`  /  `#[command(subcommand)]`  /  `action: KgAction,`
        // so the VARIANT line contains no "Action" at all and a substring test
        // on it excluded nothing. The gate then reported all fourteen routers
        // as unruled operations — correctly, by its own lights, which is how
        // it said the extractor was broken.
        let mut action_enums: Vec<String> = Vec::new();
        for line in src.lines() {
            if let Some(rest) = line.strip_prefix("enum ") {
                let name = rest.trim_end_matches(" {").trim();
                if name.ends_with("Action") {
                    action_enums.push(name.to_string());
                }
                current = if name == "Command" || name.ends_with("Action") {
                    Some(name.to_string())
                } else {
                    None
                };
                continue;
            }
            if line == "}" {
                current = None;
                continue;
            }
            let Some(en) = current.as_deref() else {
                continue;
            };
            // A variant line is exactly four spaces then an uppercase ident.
            let Some(rest) = line.strip_prefix("    ") else {
                continue;
            };
            if rest.starts_with(' ') || rest.starts_with("//") || rest.starts_with('#') {
                continue;
            }
            let ident: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            if ident.is_empty() || !ident.starts_with(|c: char| c.is_ascii_uppercase()) {
                continue;
            }
            out.push(format!("{en}::{ident}"));
        }
        // Drop the routers: `Command::Kg` exists only to reach `KgAction`.
        out.retain(|a| {
            let Some(v) = a.strip_prefix("Command::") else {
                return true;
            };
            !action_enums.iter().any(|e| e == &format!("{v}Action"))
        });
        out.sort();
        out.dedup();
        out
    }

    /// ROADMAP M16. The CLI axis had NO inventory, so every CLI-only
    /// capability was an unrecorded gap by construction (round-four #34) —
    /// while `OPERATOR_ONLY` did exactly this job for the MCP axis and
    /// `OPS_DELIBERATELY_ABSENT` for the orchestrator's ops plane.
    ///
    /// Both directions, which is the property a doc table cannot have:
    /// a new `Command` variant fails until it is ruled, and a row naming an
    /// anchor `main.rs` no longer defines fails too.
    #[test]
    fn every_cli_capability_is_reachable_or_ruled_absent() {
        let src = include_str!("main.rs");
        let anchors = cli_anchors(src);

        // PREMISE. An extractor that found nothing reports exactly what a
        // fully-inventoried tree reports — the failure this whole file is
        // about. The CLI has had dozens of operations for its whole life.
        assert!(
            anchors.len() > 50,
            "premise: the anchor extractor found {} operations in main.rs, \
             which is implausibly few — the extractor is broken, and a broken \
             extractor agrees with any inventory",
            anchors.len()
        );

        let ruled: std::collections::BTreeSet<&str> =
            SURFACE_ABSENCES.iter().map(|(a, _, _, _)| *a).collect();
        let complete: std::collections::BTreeSet<&str> = SURFACE_COMPLETE.iter().copied().collect();

        // Direction 1: every operation is accounted for exactly once.
        let unaccounted: Vec<&String> = anchors
            .iter()
            .filter(|a| !ruled.contains(a.as_str()) && !complete.contains(a.as_str()))
            .collect();
        assert!(
            unaccounted.is_empty(),
            "these CLI operations are in NEITHER inventory, so nobody has said \
             whether their absence from MCP or /v1 is a boundary or a drift:\n  \
             {unaccounted:#?}\nAdd each to SURFACE_ABSENCES with a ruling, or to \
             SURFACE_COMPLETE if it is reachable from all three surfaces."
        );

        let both: Vec<&&str> = ruled.intersection(&complete).collect();
        assert!(
            both.is_empty(),
            "these anchors claim to be BOTH absent from a surface and reachable \
             from all three: {both:#?}"
        );

        // Direction 2: no row outlives its anchor. This is the half a
        // hand-maintained table cannot do — a row naming a removed command
        // reads as a ruling being enforced when nothing is.
        let known: std::collections::BTreeSet<&str> = anchors.iter().map(|s| s.as_str()).collect();
        let stale: Vec<&str> = ruled
            .iter()
            .chain(complete.iter())
            .copied()
            .filter(|a| !known.contains(a))
            .collect();
        assert!(
            stale.is_empty(),
            "these inventory rows name a dispatch anchor main.rs no longer \
             defines: {stale:#?}"
        );

        // Every ruling must carry an argument. An empty reason is a row that
        // looks decided and is not.
        for (anchor, surface, kind, reason) in SURFACE_ABSENCES {
            assert!(
                matches!(*surface, "mcp" | "v1" | "mcp+v1"),
                "{anchor}: absent_from must be mcp, v1 or mcp+v1, not {surface:?}"
            );
            assert!(
                reason.len() > 30,
                "{anchor} ({surface}): the reason is {} characters, which cannot \
                 be an argument. A ruling must say what would go wrong",
                reason.len()
            );
            // An `Unruled` row must name where the decision is filed, or it is
            // just an absence with a shrug.
            if *kind == Absence::Unruled {
                assert!(
                    reason.contains("ROADMAP"),
                    "{anchor} ({surface}): an Unruled row must cite the entry the \
                     decision is filed under"
                );
            }
            // **A `Drift` row must name a TARGET**, because the variant's own
            // doc says "with a target" and without one a gap is `Unruled`
            // wearing a different variant — decided in name, parked in fact,
            // and no longer visible to the reader who was told these are the
            // undecided ones. The target may be a ROADMAP id or a version;
            // what it may not be is absent.
            //
            // This arm arrived when 21 rows were ruled `Drift` in one pass
            // (ROADMAP O66) with their scheduling deliberately deferred to a
            // separate entry. Deferring the schedule is legitimate; leaving
            // the row with nowhere to point is what this prevents.
            if *kind == Absence::Drift {
                let has_target = reason.contains("target ")
                    || reason.contains("ROADMAP")
                    || reason.contains("1.")
                    || reason.contains("2.");
                assert!(
                    has_target,
                    "{anchor} ({surface}): a Drift row names a gap and must say \
                     where it is scheduled — a target release or the entry that \
                     holds the scheduling decision. Without one it is Unruled \
                     under another name"
                );
            }
        }
    }

    #[test]
    fn the_mcp_tool_surface_matches_its_inventory() {
        let src = include_str!("mcp.rs");
        let advertised = advertised_tools(src);

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
        // Read from the SOURCE as well as from the inventory, so a tool
        // advertised without a line in `MCP_TOOLS` is still caught. This
        // used to be `src.contains(&format!("tool(\"undercroft_{cap}"))` —
        // a needle spelled out here, which a rename of the tool prefix
        // would have left matching nothing at all while still passing.
        let from_source = advertised_tools(src);
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
                    "{advertised} carries the operator-only capability {cap:?}. An agent must not rule on the queue that contains it, assign the trust class that decides what it may retrieve, or write the authority tier its own lookups read. If deliberate, that is a threat-model change, not a test change."
                );
            }
            for advertised in &from_source {
                assert!(
                    !advertised.contains(cap),
                    "{advertised} is exposed over MCP and carries the \
                     operator-only capability {cap:?}. An agent must not rule \
                     on the queue that contains it, or assign the trust class \
                     that decides what it can retrieve. If this was \
                     deliberate, it needs a threat-model change, not a test \
                     change."
                );
            }
        }
    }

    /// **Every `UNDERCROFT_*` the code reads is in the inventory, and every
    /// inventory entry is read by the code.**
    ///
    /// The one dimension of the drift audit that had no gate at all. Its
    /// census lived as hand-maintained prose in two documents, and went
    /// stale — which is precisely the failure this dimension exists to
    /// catch, one level up: a number nobody can recompute is a claim about
    /// when it was last counted.
    ///
    /// Scanned over `crates/` at test time (the image COPYs it, which is
    /// what makes this runnable at all), excluding `undercroft-bench`
    /// exactly as the canonical count in `CLAUDE.md` does.
    ///
    /// **With a premise probe.** A scanner that finds nothing reports
    /// exactly what a clean tree reports, and this project has shipped one
    /// that did. The needle is split with `concat!` so this file — which is
    /// inside the scanned tree and lists all 78 names — cannot satisfy its
    /// own probe by accident; the probe requires a variable found in a
    /// DIFFERENT crate.
    #[test]
    fn every_engine_env_var_is_inventoried_and_every_entry_is_read() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/ is this crate's parent")
            .to_path_buf();

        let prefix = concat!("UNDER", "CROFT_");
        let mut found: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        let mut files = 0usize;
        let mut stack = vec![crates.clone()];
        while let Some(dir) = stack.pop() {
            // The harness's own variables are not the engine's.
            if dir.file_name().and_then(|n| n.to_str()) == Some("undercroft-bench") {
                continue;
            }
            for entry in std::fs::read_dir(&dir).expect("crates/ is readable") {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                files += 1;
                let text = std::fs::read_to_string(&path).unwrap();
                // String literals only, which is how every one of these is
                // actually read (`std::env::var("UNDERCROFT_…")`).
                let mut rest = text.as_str();
                while let Some(i) = rest.find(&format!("\"{prefix}")) {
                    let tail = &rest[i + 1..];
                    let name: String = tail
                        .chars()
                        .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                        .collect();
                    if tail.as_bytes().get(name.len()) == Some(&b'"') && name.len() > prefix.len() {
                        found
                            .entry(name)
                            .or_default()
                            .push(path.display().to_string());
                    }
                    rest = &rest[i + 1..];
                }
            }
        }
        assert!(
            files > 20,
            "the scan found {files} source files — the walk, not the tree, is broken"
        );
        // The probe: a variable that must be found, and found somewhere
        // other than this file, or a zero below would mean nothing.
        let probe = concat!("UNDER", "CROFT_HOME");
        let sites = found
            .get(probe)
            .unwrap_or_else(|| panic!("premise: {probe} must be read somewhere"));
        assert!(
            sites.iter().any(|p| !p.ends_with("parity.rs")),
            "premise: the scan must reach crates other than this one"
        );

        let inventoried: std::collections::BTreeSet<&str> =
            ENGINE_ENV_VARS.iter().map(|(n, _, _)| *n).collect();
        assert_eq!(
            inventoried.len(),
            ENGINE_ENV_VARS.len(),
            "a variable is listed twice in ENGINE_ENV_VARS"
        );
        // Direction 1 — the code reads something nobody wrote down. This is
        // the half that catches a new knob shipping undocumented.
        for (name, sites) in &found {
            assert!(
                inventoried.contains(name.as_str()),
                "{name} is read by the code but is not in ENGINE_ENV_VARS \
                 (read at: {sites:?}). Add it there, and to the env table in \
                 architecture/index.html."
            );
        }
        // Direction 2 — the inventory names something the code stopped
        // reading. A documented variable that does nothing is worse than an
        // undocumented one: an operator sets it and believes it took.
        // **Read off sites OUTSIDE this file, and the first version did
        // not.** `parity.rs` lives inside the scanned tree and spells every
        // name as a string literal, so `found` was guaranteed to contain
        // every entry — sourced from the inventory itself. Delete the last
        // real read of a variable and this loop stayed green. The premise
        // probe above already carried exactly this filter; the half that
        // DECIDES did not, which is the "ask what the checker sees when it
        // reads itself" trap inside a checker written to avoid it.
        for (name, _, _) in ENGINE_ENV_VARS {
            let read_for_real = found
                .get(*name)
                .is_some_and(|sites| sites.iter().any(|p| !p.ends_with("parity.rs")));
            assert!(
                read_for_real,
                "ENGINE_ENV_VARS lists {name}, which no crate reads outside this inventory — a variable documented and honoured by nothing"
            );
        }
    }

    /// **No crate builds its own HTTP client except `undercroft-net`.**
    ///
    /// The transport policy — TLS or loopback, nothing else, no override —
    /// lives in one crate because two copies are two places for it to drift,
    /// and they DID drift: `undercroft-llm`, the crate the policy was
    /// extracted from, kept its own `AgentBuilder` and applied a declared
    /// pin only `if tls`, so a loopback-http base never validated the CA
    /// file while the shared path did. One declaration, checked on one hop
    /// and not another.
    ///
    /// The first version of this gate was scoped to the orchestrator crate
    /// and could not see either. Workspace-wide now, and recursive — the
    /// orchestrator-local copy is gone, because one property with two gates
    /// is the duplication this file exists to prevent.
    #[test]
    fn no_crate_but_undercroft_net_builds_its_own_http_client() {
        // Split so this file, which is inside the scanned tree, is not a hit.
        let needle = concat!("AgentB", "uilder");
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/ is this crate's parent")
            .to_path_buf();

        // Two exemptions, each with its reason, each REQUIRED to be reached —
        // a walk that missed one would report a clean tree for the wrong
        // reason, and a rename would silently widen the exemption.
        //
        // `undercroft-net` IS the policy.
        //
        // `undercroft-bench` is a measurement harness, not a product
        // surface: it drives a comparison target with a public benchmark
        // corpus and carries no vault data, and its `UNDERCROFT_VS_*`
        // variables are already excluded from `ENGINE_ENV_VARS` on exactly
        // that argument. Refusing cleartext there would stop a researcher
        // measuring a competitor on a lab network, for no gain to anything
        // this project ships. Exempt DELIBERATELY, and named here rather
        // than silently unmatched.
        let exempt = ["undercroft-net", "undercroft-bench"];
        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        let mut exempted: Vec<&str> = Vec::new();
        let mut stack = vec![crates.clone()];
        while let Some(dir) = stack.pop() {
            let owner = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if let Some(name) = exempt.iter().find(|e| **e == owner) {
                exempted.push(name);
                continue;
            }
            for entry in std::fs::read_dir(&dir).expect("crates/ is readable") {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                scanned += 1;
                let text = std::fs::read_to_string(&path).unwrap();
                for (n, line) in text.lines().enumerate() {
                    let t = line.trim_start();
                    if t.starts_with("//") {
                        continue;
                    }
                    if t.contains(needle) {
                        offenders.push(format!("{}:{}: {t}", path.display(), n + 1));
                    }
                }
            }
        }
        assert!(
            scanned > 40,
            "the walk found {scanned} files — the scan, not the tree, is broken"
        );
        exempted.sort_unstable();
        let mut want = exempt;
        want.sort_unstable();
        assert_eq!(
            exempted, want,
            "the walk must reach and skip each exempt crate exactly once — a rename that stops matching silently widens the exemption"
        );
        let policy = crates.join("undercroft-net/src/lib.rs");
        assert!(
            std::fs::read_to_string(&policy).unwrap().contains(needle),
            "premise: the needle must match where the one legal construction \
             lives, or a zero above means nothing"
        );
        assert!(
            offenders.is_empty(),
            "every outbound client must come from `undercroft_net` — TLS or \
             loopback, nothing else, no override. Found:\n{}",
            offenders.join("\n")
        );
    }

    /// The gate above scans SOURCE for `ureq`'s builder token — which is
    /// precisely the observable round-four #8 did not move. The OTLP span
    /// exporter was a second outbound HTTP client built by *someone else's*
    /// library (`reqwest`, via `opentelemetry-otlp`'s
    /// `reqwest-blocking-client` feature), so it was structurally invisible
    /// to a scan for a token it never contained. CLAUDE.md's rule, third
    /// instance: ask what a gate can SEE, not what it asserts.
    ///
    /// This one measures the DEPENDENCY EDGE instead, which is the thing
    /// that actually moved — and the removal of that feature is what makes
    /// the absence byte-readable at all.
    ///
    /// It also caught the second half of #8: `reqwest` resolved with NO TLS
    /// crate in its dependency list, so an `https://` collector could not
    /// work and failed silently inside the span processor. A client this
    /// workspace cannot see is also a client nobody checked could do TLS.
    #[test]
    fn no_second_http_client_is_linked_into_the_workspace() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/ is this crate's parent")
            .parent()
            .expect("the workspace root is crates/'s parent");
        let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect(
            "Cargo.lock must be readable — a gate that cannot read its input \
             reports exactly what a clean tree reports",
        );
        // PREMISE. Without it an empty or truncated lock file passes every
        // assertion below by containing nothing at all.
        assert!(
            lock.contains(concat!("name = \"u", "req\"")),
            "premise failed: this does not look like the workspace lock file \
             — `ureq`, the transport `undercroft-net` is built on, is absent"
        );
        assert!(
            !lock.contains(concat!("name = \"re", "qwest\"")),
            "a second outbound HTTP client is linked into the workspace. The \
             OTLP exporter used to be one: unpoliced by `undercroft-net`, and \
             resolved with no TLS backend at all, so `https://` silently \
             exported nothing. If a dependency legitimately needs it, route \
             it through `undercroft_net` first and then decide what this gate \
             should say."
        );
    }

    /// **The read-only gate FAILS CLOSED.** A name it has never seen is a
    /// write, so forgetting to classify a new tool refuses a read rather
    /// than serving a write. This is the whole behavioural difference from
    /// the `WRITE_TOOLS.contains(name)` gate it replaced, and it cannot be
    /// seen by testing the tools that exist — only by asking about one that
    /// does not.
    #[test]
    fn the_read_only_gate_fails_closed_on_a_tool_it_has_never_seen() {
        use crate::mcp::refused_when_read_only as refused;
        assert!(
            refused("undercroft_merge_wings"),
            "an unclassified tool must be REFUSED on a read-only server, not served"
        );
        assert!(refused("undercroft_promote_canonical"));
        assert!(refused(""));
        // The classified cases still behave, in both directions — a gate
        // that refused everything would pass the assertions above.
        assert!(refused("undercroft_save"));
        assert!(refused("undercroft_delete_drawer"));
        assert!(!refused("undercroft_search"));
        assert!(!refused("undercroft_verify"));
    }

    /// **The read-only gate is an inventory of READS, counted both ways.**
    ///
    /// It used to be an inventory of writes consulted as
    /// `WRITE_TOOLS.contains(name)` — a gate that fails OPEN, so a tool
    /// added later was SERVED by a `--read-only` server until somebody
    /// remembered the list. The compensating check here was a name
    /// heuristic blind to `_merge`, `_move`, `_import`, `_forget`,
    /// `_prune`, `_promote` and `_sweep`; `/v1` decided the same question
    /// with "anything not GET is a write unless named" and got it right.
    ///
    /// Now `READ_TOOLS` is the runtime list and this counts it against the
    /// advertised surface in both directions, so an unclassified tool
    /// cannot exist: it is refused at runtime AND it fails the build.
    ///
    /// The name heuristic survives as a SECOND opinion in one direction
    /// only — a tool whose name says it mutates must not be in the read
    /// list. It can no longer be the whole gate, which is what it was.
    #[test]
    fn the_read_only_gate_classifies_every_advertised_tool() {
        // The CONSTANTS, not their source text. The sibling gate scrapes
        // `mcp.rs` because it measures what is ADVERTISED (built at
        // runtime from a `json!` block); this one measures two lists that
        // are already Rust values, and a scraper here would only add a way
        // to silently examine nothing.
        let reads = crate::mcp::READ_TOOLS;
        let writes = crate::mcp::WRITE_TOOLS;

        // Direction 1: every classified name is a tool that still exists.
        for name in reads.iter().chain(writes.iter()) {
            assert!(
                MCP_TOOLS.contains(name),
                "{name} is classified for the read-only gate but is not an \
                 advertised tool — a stale entry reads as a boundary that is \
                 being enforced and is not"
            );
        }
        // Direction 2: every advertised tool is classified, exactly once.
        // This is the half a write-list could never have: an unclassified
        // tool used to be silently servable.
        for name in MCP_TOOLS {
            let r = reads.contains(name);
            let w = writes.contains(name);
            assert!(
                r || w,
                "{name} is advertised but classified neither read nor write. \
                 It is refused on a read-only server (the gate fails closed), \
                 which is the safe direction — but say which it is."
            );
            assert!(!(r && w), "{name} is classified as both a read and a write");
        }

        // The name heuristic, as a second opinion in ONE direction. It was
        // never sufficient — these are the endings it cannot see — but a
        // tool whose name says it mutates must never be a read.
        for name in reads {
            let mutating = [
                "_save",
                "_add",
                "_update",
                "_delete",
                "_create",
                "_write",
                "_merge",
                "_move",
                "_import",
                "_forget",
                "_prune",
                "_promote",
                "_sweep",
                "_dedup",
                "_invalidate",
                "_supersede",
                "_set_",
            ]
            .iter()
            .any(|v| name.contains(v));
            assert!(
                !mutating,
                "{name} is in READ_TOOLS but its name says it mutates — a \
                 read-only server would serve it"
            );
        }
    }

    /// **The browser importer must refuse every encrypted bundle, not the
    /// one version that existed when the guard was written.**
    ///
    /// `ui.html` reads the chosen file and, when it looks like a bundle,
    /// says so and stops: the file is recipient-encrypted and `/v1`'s import
    /// route takes NDJSON, so only the CLI with an identity key can open it.
    /// The guard tested for the v1 magic *exactly*, so the hybrid
    /// post-quantum v2 bundle introduced by C3.4 walked past it and was
    /// POSTed as NDJSON — the operator got a parse failure where the product
    /// had a sentence ready telling them what to do.
    ///
    /// The gate does not compare the guard against a **copy** of the magic.
    /// It reads the magics out of `undercroft-vault`'s own source and
    /// requires the guard to be exactly their longest common prefix, so it
    /// fails in both directions: a guard pinned to one version (the defect)
    /// refuses to be a prefix of the others, and a guard loosened past the
    /// shared stem stops equalling it. A `BUNDLE_MAGIC_V3` declared tomorrow
    /// is in scope the moment it exists, with no list here to update.
    #[test]
    fn the_browser_importer_refuses_every_bundle_version() {
        // Every `pub const BUNDLE_MAGIC*` the vault crate declares, read from
        // the source rather than imported, so a magic that is not `pub` — or
        // is declared and not yet wired — still counts. Comment lines are
        // skipped: bundle.rs documents both layouts in its module header.
        let bundle_rs = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("undercroft-vault")
            .join("src")
            .join("bundle.rs");
        let src = std::fs::read_to_string(&bundle_rs)
            .expect("the vault crate's sources sit beside this one");
        let magics: Vec<&str> = src
            .lines()
            .map(str::trim_start)
            .filter(|l| !l.starts_with("//"))
            .filter(|l| l.contains("const BUNDLE_MAGIC"))
            .filter_map(|l| l.split_once("b\"")?.1.split_once('"').map(|(m, _)| m))
            .collect();
        // The premise. One magic found would make "every magic starts with
        // the guard" true of the v1-only guard this test exists to fail.
        assert!(
            magics.len() >= 2,
            "found {} bundle magic(s) in {} — the extraction is broken, and \
             with fewer than two this assertion could not distinguish a \
             version-pinned guard from a version-agnostic one",
            magics.len(),
            bundle_rs.display()
        );

        // The guard as the shipped page actually spells it.
        let ui = include_str!("ui.html");
        let guards: Vec<&str> = ui
            .match_indices("startsWith(\"UNDERCROFT")
            .filter_map(|(i, _)| ui[i..].split_once('"')?.1.split_once('"').map(|(g, _)| g))
            .collect();
        assert_eq!(
            guards.len(),
            1,
            "expected exactly one bundle guard in ui.html, found {guards:?}"
        );

        // Longest common prefix, sliced on a character boundary rather than
        // on a count — the magics are ASCII today and nothing says the next
        // one has to be.
        let common = magics.iter().skip(1).fold(magics[0], |acc, m| {
            let end = acc
                .char_indices()
                .zip(m.chars())
                .take_while(|((_, a), b)| a == b)
                .map(|((i, a), _)| i + a.len_utf8())
                .last()
                .unwrap_or(0);
            &acc[..end]
        });
        assert_eq!(
            guards[0], common,
            "ui.html guards {:?} but the bundle formats declared in \
             undercroft-vault are {:?}, whose shared prefix is {:?}. A guard \
             narrower than that lets a bundle through the browser importer; \
             a guard wider than it refuses files that are not bundles",
            guards[0], magics, common
        );
    }
}
