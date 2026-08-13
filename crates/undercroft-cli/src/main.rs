//! `undercroft` — hardened, local-first AI memory.
//!
//! Rust conversion of MemPalace with a security-first management layer:
//! memories live in isolated vaults with per-vault derived keys, AEAD
//! encryption, and HMAC integrity verification.

mod assertion;
mod config_check;
mod http;
mod i18n;
mod mcp;
mod parity;
mod refine;
mod search;
mod tenant;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use std::path::{Path, PathBuf};

use i18n::{fill, tr};
use undercroft_core::normalize::mode_for_path;
use undercroft_core::{chunk_text, normalize_content, ChunkOptions, Drawer};
use undercroft_store::{PalaceStore, SearchOptions};
use undercroft_vault::{SecurityLevel, Vault, VaultManager};

#[derive(Parser)]
#[command(
    name = "undercroft",
    version,
    about = "Undercroft — hardened local-first AI memory (encrypted, integrity-verified vaults)",
    long_about = "Undercroft — hardened local-first AI memory.\n\n\
                  Stores verbatim memories in isolated vaults.\n\
                  Each vault has its own database and its own keys (HKDF domain \n\
                  separation from a palace master key); content is encrypted with \n\
                  XChaCha20-Poly1305 and every record carries an HMAC-SHA256 \n\
                  integrity tag plus a tamper-evident audit chain."
)]
struct Cli {
    /// Palace data directory (default: $UNDERCROFT_HOME or ~/.undercroft)
    #[arg(long, global = true, env = "UNDERCROFT_HOME")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LevelArg {
    /// Encrypt content + embeddings (AEAD) and HMAC-tag every record
    Sealed,
    /// Plaintext content, but HMAC integrity tags + audit chain
    HmacOnly,
}

impl From<LevelArg> for SecurityLevel {
    fn from(v: LevelArg) -> Self {
        match v {
            LevelArg::Sealed => SecurityLevel::Sealed,
            LevelArg::HmacOnly => SecurityLevel::HmacOnly,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Initialize the palace: master key + a default vault
    Init {
        /// Security level for the default vault
        #[arg(long, value_enum, default_value = "sealed")]
        level: LevelArg,
    },
    /// Manage vaults (isolated, individually-keyed memory namespaces)
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    /// Store one memory verbatim
    Remember {
        /// The content to remember (verbatim; never summarized)
        content: String,
        #[arg(long, default_value = "default")]
        vault: String,
        /// Wing = person / project partition
        #[arg(long, default_value = "general")]
        wing: String,
        /// Room = topic within the wing
        #[arg(long, default_value = "inbox")]
        room: String,
        /// When the content happened (RFC 3339 or YYYY-MM-DD), as opposed to
        /// now, when it is being filed. Anchors relative dates in the text.
        #[arg(long)]
        content_date: Option<String>,
        /// Id of the drawer this memory replaces. Records a receipted
        /// update link (check with `undercroft verify`); the old drawer is
        /// never deleted or hidden.
        #[arg(long)]
        supersedes: Option<String>,
        /// Declared record kind, from the closed vocabulary
        /// (question|preference|decision|event|procedure|statement).
        /// Absent is always valid — the label is declared, never inferred.
        /// `search --kind` shipped without this, so the CLI could FILTER
        /// by a label it had no way to write, and a kind-filtered search
        /// (which excludes kind-less drawers by design) silently omitted
        /// everything the CLI had written.
        #[arg(long)]
        kind: Option<String>,
        /// Provenance claim: which agent wrote this (recorded and
        /// tamper-covered, never a trust boundary)
        #[arg(long)]
        agent: Option<String>,
        /// Provenance claim: origin class (e.g. user|tool-output|scrape)
        #[arg(long)]
        channel: Option<String>,
        /// Provenance claim: the session this was written in
        #[arg(long)]
        session: Option<String>,
    },
    /// Mine a directory into the palace (text files, or agent transcripts)
    Mine {
        /// Directory (or single file) to mine
        path: PathBuf,
        #[arg(long, default_value = "default")]
        vault: String,
        #[arg(long, default_value = "mined")]
        wing: String,
        /// "files" for documents, "convos" for Claude Code / Codex JSONL
        /// session transcripts
        #[arg(long, default_value = "files")]
        mode: String,
    },
    /// Sweep transcripts: one verbatim drawer per user/assistant message
    /// (idempotent, resume-safe)
    Sweep {
        /// Directory of .jsonl transcripts (or a single file)
        path: PathBuf,
        #[arg(long, default_value = "default")]
        vault: String,
        #[arg(long, default_value = "convos")]
        wing: String,
    },
    /// Search memories (hybrid semantic + lexical + recency)
    Search {
        query: String,
        #[arg(long, default_value = "default")]
        vault: String,
        #[arg(long)]
        wing: Option<String>,
        #[arg(long)]
        room: Option<String>,
        /// Filter to a declared record kind
        /// (question|preference|decision|event|procedure|statement)
        #[arg(long)]
        kind: Option<String>,
        /// Minimum deployment-assigned wing trust for this query
        /// (quarantined|standard|trusted). Wings below it never enter the
        /// candidate competition; unassigned wings count as standard.
        #[arg(long)]
        min_trust: Option<String>,
        /// Language of the stored text, declared not detected: en, de, nl,
        /// it, es, fr, pt, tr, ru, el, hi, ka, ko. Reaches word forms one
        /// script cannot settle — German -er takes Kind→Kinder, and the
        /// Romance/Dutch/Turkish tables need saying too
        #[arg(long)]
        language: Option<String>,
        /// Max results
        #[arg(short = 'n', long, default_value_t = search::DEFAULT_LIMIT)]
        limit: usize,
        /// Rank to continue from: ranks [offset, offset+limit) of the same
        /// ranking a single deeper call would produce
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// RFC 3339 instant to rank as of — repeat the one the previous page
        /// printed, so every page slices ONE ranking. Without it each call
        /// re-measures recency against a fresh clock and pages can repeat or
        /// skip hits
        #[arg(long)]
        ranked_at: Option<String>,
        /// Soft cap on how many results may come from any single room, so an
        /// answer spanning several sessions is not starved by the most
        /// verbose one. Leftover slots refill in score order
        #[arg(long)]
        room_cap: Option<usize>,
        /// Retrieval backend: local (scan), or a remote vector index
        /// (qdrant | chroma | pgvector) used as an untrusted accelerator —
        /// results are always re-verified and re-ranked locally
        #[arg(long, default_value = "local")]
        backend: String,
    },
    /// Remote vector indexes: push sealed records, check status
    Index {
        #[command(subcommand)]
        action: IndexAction,
        #[arg(long, global = true, default_value = "default")]
        vault: String,
    },
    /// Load session context: identity + recent essential memories
    WakeUp {
        #[arg(long, default_value = "default")]
        vault: String,
        #[arg(long)]
        wing: Option<String>,
    },
    /// Verify every record's HMAC and the vault's audit chain
    Verify {
        #[arg(long, default_value = "default")]
        vault: String,
    },
    /// Destroy drawers through the audit chain and emit a verifiable
    /// attestation that the named content was destroyed and nothing else
    /// changed (C3.2 — GDPR/RTBF with a receipt)
    Forget {
        /// Drawer ids to destroy
        #[arg(required = true)]
        ids: Vec<String>,
        #[arg(long, default_value = "default")]
        vault: String,
        /// Write the attestation JSON here (default: stdout)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Signing identity file (`bundle sign-keygen`) — attests the
        /// operator as sender, which is what a third party verifies
        #[arg(long)]
        sign: Option<PathBuf>,
        /// Also delete these drawers from a remote index this vault was
        /// pushed to (qdrant | chroma | pgvector | milvus | weaviate).
        /// Without it, the attestation WARNS that a mirror copy may
        /// survive — `index push` moves the at-rest blob to a third party,
        /// and destroying the local row does not reach it
        #[arg(long)]
        backend: Option<String>,
    },
    /// Verify a forgetting attestation against a vault (replays the
    /// chain segment with the key in hand; also checks the signature
    /// when the attestation carries one)
    VerifyForgetting {
        /// Attestation JSON written by `forget`
        file: PathBuf,
        #[arg(long, default_value = "default")]
        vault: String,
    },
    /// Review writes the admission screen quarantined (an operator
    /// surface; enable screening with UNDERCROFT_ADMISSION=quarantine)
    Admission {
        #[command(subcommand)]
        action: AdmissionAction,
        #[arg(long, global = true, default_value = "default")]
        vault: String,
    },
    /// Retention policies per wing/room — declared, audited, and enforced
    /// only by an explicit sweep that destroys through the attested
    /// forgetting path (an operator surface, never MCP)
    Retention {
        #[command(subcommand)]
        action: RetentionAction,
        #[arg(long, global = true, default_value = "default")]
        vault: String,
    },
    /// Audit-chain history: what happened to a record, when, and the tamper
    /// tag as of each write. Never content — the audit table holds none.
    /// Operator scope: every namespace, including review rulings, trust and
    /// retention policy, destructions, exports and rotations. The agent
    /// surface gets the same capability fenced.
    History {
        /// A drawer, fact or entity id — or a whole label like
        /// `trust/legal`. Omit for recent activity across the vault.
        #[arg(long)]
        subject: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value = "default")]
        vault: String,
    },
    /// Deployment-assigned wing trust classes — the receiving principal's
    /// declaration (an operator surface: agents cannot assign trust over
    /// MCP, only read with a floor)
    Trust {
        #[command(subcommand)]
        action: TrustAction,
        #[arg(long, global = true, default_value = "default")]
        vault: String,
    },
    /// Export the palace as JSONL (backup / migration): a signed-able
    /// manifest line, then every drawer, KG entity, fact (receipts and
    /// authority tier included) and tunnel. With --to, the export is
    /// sealed to a recipient's public key instead — the file never exists
    /// in plaintext (see `bundle keygen`).
    Export {
        #[arg(long, default_value = "default")]
        vault: String,
        /// Recipient public key (hex, from `bundle keygen`): write an
        /// encrypted bundle only that identity can open
        #[arg(long)]
        to: Option<String>,
        /// Output file for the encrypted bundle (required with --to)
        #[arg(long, requires = "to")]
        out: Option<PathBuf>,
        /// Signing identity file (from `bundle sign-keygen`): attest the
        /// manifest with Ed25519 so the importer can pin the sender
        #[arg(long)]
        sign: Option<PathBuf>,
        /// Sender-declared trust class recorded in the manifest — a claim
        /// for the receiving deployment's policy, never a trust boundary
        #[arg(long)]
        trust: Option<String>,
        /// RFC 3339 instant after which importers must refuse the bundle
        #[arg(long)]
        expires: Option<String>,
    },
    /// Serve the MCP stdio server (full palace / KG / diary tool surface)
    ServeMcp {
        #[arg(long, default_value = "default")]
        vault: String,
        /// Refuse every write tool, and open the vault read-only.
        ///
        /// `serve-http` has had this since it existed; stdio did not, and
        /// the docs said "write tools are refused when the server runs
        /// `--read-only`" without qualifying which transport. The posture
        /// is not only about tool refusal: a read-write open also runs the
        /// embedder migration and appends a read-audit record per search.
        #[arg(long)]
        read_only: bool,
    },
    /// Serve MCP + the multi-tenant REST surface over HTTP. Requires
    /// UNDERCROFT_MCP_HTTP_TOKEN for any non-loopback bind; set
    /// UNDERCROFT_ASSERTION_SECRET to require a per-vault assertion on every
    /// `/v1` request.
    ServeHttp {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 8765)]
        port: u16,
        #[arg(long, default_value = "default")]
        vault: String,
        /// Expose recall without write access. A posture on the whole
        /// process, not a route filter: both stores it opens (MCP and each
        /// /v1 tenant vault) are opened read-only, so no embedder migration
        /// runs and UNDERCROFT_READ_AUDIT records nothing
        #[arg(long)]
        read_only: bool,
    },
    /// Print an `X-Vault-Assertion` header value for a vault, signed with
    /// UNDERCROFT_ASSERTION_SECRET. For orchestrators (and tests) minting
    /// per-request assertions; the engine verifies these independently.
    AssertHeader {
        /// Vault id the assertion authorizes.
        vault: String,
    },
    /// Background auto-save loop: periodically sweep a transcript directory
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Work with raw agent transcripts
    Transcript {
        #[command(subcommand)]
        action: TranscriptAction,
    },
    /// Import memories from a JSONL export (undercroft or mempalace format)
    /// or an encrypted bundle (`export --to`; pass --identity)
    Import {
        /// JSONL file (one drawer per line) or encrypted bundle
        file: PathBuf,
        #[arg(long, default_value = "default")]
        vault: String,
        /// Wing for records that do not carry one
        #[arg(long, default_value = "imported")]
        wing: String,
        /// Identity key file (from `bundle keygen`) for encrypted bundles
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Require the manifest to be signed by exactly this sender (hex,
        /// from `bundle sign-keygen`); refuse the import otherwise. Without
        /// it, signature status is reported but not enforced.
        #[arg(long)]
        sender: Option<String>,
    },
    /// Recipient identities for encrypted export bundles
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
    /// Knowledge graph: temporal facts with validity windows
    Kg {
        #[command(subcommand)]
        action: KgAction,
        #[arg(long, global = true, default_value = "default")]
        vault: String,
    },
    /// Manage individual drawers
    Drawer {
        #[command(subcommand)]
        action: DrawerAction,
        #[arg(long, global = true, default_value = "default")]
        vault: String,
    },
    /// Agent diaries (each agent gets its own wing)
    Diary {
        #[command(subcommand)]
        action: DiaryAction,
        #[arg(long, global = true, default_value = "default")]
        vault: String,
    },
    /// Cross-wing tunnels: create, follow, traverse
    Tunnel {
        #[command(subcommand)]
        action: TunnelAction,
        #[arg(long, global = true, default_value = "default")]
        vault: String,
    },
    /// Compact LLM-scannable index of the palace (port of AAAK closets)
    Closets {
        #[arg(long)]
        wing: Option<String>,
        #[arg(long, default_value = "default")]
        vault: String,
    },
    /// LLM-assisted refinement: extract entities + knowledge-graph facts
    /// from drawers using a local LLM runtime (requires UNDERCROFT_LLM_URL)
    Refine {
        #[arg(long, default_value = "default")]
        vault: String,
        #[arg(long)]
        wing: Option<String>,
        /// Only distil drawers in this room (default: every room but
        /// --fact-room, so a re-run never distils its own output)
        #[arg(long)]
        room: Option<String>,
        /// Room the searchable fact-drawers land in, inside their source
        /// drawer's wing — the same default as `/v1 …/refine`
        #[arg(long, default_value = "facts")]
        fact_room: String,
        /// Refine at most N drawers (0 = all)
        #[arg(long, default_value_t = 0)]
        limit: usize,
        /// Only report what would be extracted; write nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Within-wing entity co-occurrence connections
    Hallways {
        wing: String,
        #[arg(long, default_value_t = 20)]
        top: usize,
        #[arg(long, default_value = "default")]
        vault: String,
    },
    /// Palace statistics (records, wings, rooms, KG, size)
    Stats {
        #[arg(long, default_value = "default")]
        vault: String,
    },
    /// Wing → room taxonomy tree
    Taxonomy {
        #[arg(long, default_value = "default")]
        vault: String,
    },
    /// Find (and optionally remove) exact-duplicate drawers
    Dedup {
        #[arg(long, default_value = "default")]
        vault: String,
        /// Actually delete duplicates (default: report only)
        #[arg(long)]
        apply: bool,
    },
    /// Repair: backfill fingerprints, vacuum, re-verify
    Repair {
        #[arg(long, default_value = "default")]
        vault: String,
        /// Backfill late-interaction token matrices instead (requires
        /// UNDERCROFT_RERANKER=colbert or colbert-ort): encodes every drawer
        /// missing one,
        /// in bounded batches. Restores from artifact-less bundles serve at
        /// fusion quality immediately and improve as this progresses.
        #[arg(long)]
        tokens: bool,
    },
    /// Vault backups: create, list, restore
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Configuration: validate this environment's `UNDERCROFT_*` declarations
    ///
    /// **The spelling every doc publishes.** `UPGRADING.md`'s own pre-upgrade
    /// command, the release flow in `CLAUDE.md`, `README`, `docs/AGENTS.md`
    /// and the architecture page all write `undercroft config check` with a
    /// SPACE, while clap derived `config-check` from the variant name — so
    /// the command an operator was told to run before every upgrade did not
    /// exist. A clap `alias` cannot express it (aliases are one token), so
    /// the two-word form is a subcommand group.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Validate every `UNDERCROFT_*` declaration in this environment
    /// WITHOUT opening a vault or binding a port — so an upgrade is tested
    /// in a pipeline rather than discovered at restart.
    ///
    /// Exit 1 if any declaration that turns a protection on would refuse to
    /// start; exit 0 otherwise. Warnings do not fail the run: those are
    /// declarations whose default is already the conservative choice.
    ///
    /// Kept beside `config check` rather than replaced: this is the spelling
    /// that has always WORKED, so removing it would break the scripts that
    /// found the doc wrong and adapted.
    ConfigCheck {
        /// Also print the declarations that resolve cleanly
        #[arg(long)]
        verbose: bool,
    },
    /// Print auto-save hook settings for an agent client
    ///
    /// This doc comment sat above `ConfigCheck` for as long as that variant
    /// existed: something was inserted BETWEEN a doc comment and the thing it
    /// documented, so `config-check --help` described hooks and `hooks` had
    /// no help at all. Nothing in this tree can see that class — clap accepts
    /// it, rustfmt accepts it, and no gate reads help strings — which is why
    /// it is gated below by `every_subcommand_has_its_own_about`.
    Hooks {
        /// Client: claude-code
        #[arg(default_value = "claude-code")]
        client: String,
    },
}

/// `config check` — the two-word spelling every doc publishes.
#[derive(Subcommand)]
enum ConfigAction {
    /// Validate every `UNDERCROFT_*` declaration in this environment
    /// WITHOUT opening a vault or binding a port
    Check {
        /// Also print the declarations that resolve cleanly
        #[arg(long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
enum KgAction {
    /// Add a fact: subject predicate object
    Add {
        subject: String,
        predicate: String,
        object: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value_t = 1.0)]
        confidence: f64,
    },
    /// Facts about an entity
    Query {
        entity: String,
        #[arg(long)]
        as_of: Option<String>,
        /// outgoing | incoming | both
        #[arg(long, default_value = "outgoing")]
        direction: String,
    },
    /// Facts using a predicate
    Rel {
        predicate: String,
        #[arg(long)]
        as_of: Option<String>,
    },
    /// Close the validity window of matching active facts
    Invalidate {
        subject: String,
        predicate: String,
        #[arg(long)]
        object: Option<String>,
        #[arg(long)]
        ended: Option<String>,
    },
    /// Replace the current value of (subject, predicate)
    Supersede {
        subject: String,
        predicate: String,
        new_object: String,
        #[arg(long)]
        at: Option<String>,
    },
    /// Full history, optionally for one entity
    Timeline {
        #[arg(long)]
        entity: Option<String>,
    },
    /// Graph statistics
    Stats,
    /// Verify distilled facts against their cited verbatim sources
    Receipts {
        /// Only list facts whose receipt is not fully verified
        #[arg(long)]
        problems_only: bool,
    },
    /// Place a fact on the authority tier (or take it off): a declared,
    /// audited, HMAC-covered state — never an inference
    Authority {
        triple_id: String,
        /// stated | canonical
        #[arg(long)]
        class: String,
        /// unreviewed | approved | rejected
        #[arg(long)]
        review: String,
        /// Exact-lookup key (required for canonical, forbidden for stated)
        #[arg(long)]
        key: Option<String>,
    },
    /// The exact-authority door: the one active, approved, canonical fact
    /// for a key — or nothing, never a guess
    Canonical { key: String },
}

#[derive(Subcommand)]
enum DrawerAction {
    /// Print one drawer verbatim
    Get { id: String },
    /// List drawer summaries
    List {
        #[arg(long)]
        wing: Option<String>,
        #[arg(long)]
        room: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Replace a drawer's content in place
    Update { id: String, content: String },
    /// Delete one drawer (tamper-evident tombstone)
    Delete { id: String },
    /// Delete every drawer mined from a source file
    DeleteBySource { source: String },
    /// Check whether exact content is already filed
    CheckDup { content: String },
}

#[derive(Subcommand)]
enum DiaryAction {
    /// Append a diary entry for an agent
    Write { agent: String, entry: String },
    /// Read an agent's recent diary entries
    Read {
        agent: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// List agents with diaries
    Agents,
}

#[derive(Subcommand)]
enum TunnelAction {
    /// Connect two wings
    Create {
        from: String,
        to: String,
        #[arg(long, default_value = "related")]
        label: String,
    },
    /// List tunnels (optionally touching one wing)
    List {
        #[arg(long)]
        wing: Option<String>,
    },
    /// Recent drawers from a tunnel's destination wing
    Follow {
        id: String,
        #[arg(long, default_value_t = 5)]
        limit: usize,
    },
    /// Remove a tunnel
    Delete { id: String },
    /// BFS reachable wings from a starting wing
    Traverse {
        start: String,
        #[arg(long, default_value_t = 3)]
        depth: usize,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Run the sweep loop in the foreground (systemd/compose manage the
    /// process; MemPalace's start/stop/jobs machinery is replaced by them)
    Run {
        /// Transcript directory to watch
        #[arg(long, default_value = "~/.claude/projects")]
        watch: String,
        /// Seconds between sweeps
        #[arg(long, default_value_t = 300)]
        interval: u64,
        #[arg(long, default_value = "default")]
        vault: String,
        #[arg(long, default_value = "claude-code")]
        wing: String,
        /// Sweep once and exit (for tests / cron)
        #[arg(long)]
        once: bool,
    },
}

#[derive(Subcommand)]
enum TranscriptAction {
    /// Render a JSONL agent transcript as readable prose
    Render {
        file: PathBuf,
        /// Show at most N messages (0 = all)
        #[arg(long, default_value_t = 0)]
        max: usize,
    },
}

#[derive(Subcommand)]
enum IndexAction {
    /// Upload every drawer (at-rest content + embedding) to a remote index
    Push {
        /// qdrant | chroma | pgvector
        backend: String,
        /// Push an **hmac-only** vault, whose at-rest content is the
        /// PLAINTEXT. Refused without this: a remote index is an untrusted
        /// accelerator in another trust domain, and every document about
        /// this feature says "sealed content only".
        #[arg(long)]
        allow_plaintext: bool,
    },
    /// Show a remote index's record count for this vault
    Status {
        /// qdrant | chroma | pgvector
        backend: String,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Snapshot a vault into backups/
    Create {
        #[arg(long, default_value = "default")]
        vault: String,
    },
    /// List available backups
    List,
    /// Restore a backup over its vault
    Restore {
        name: String,
        /// Overwrite the existing vault
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum VaultAction {
    /// Create a new isolated vault
    Create {
        name: String,
        #[arg(long, value_enum, default_value = "sealed")]
        level: LevelArg,
    },
    /// List vaults
    List,
    /// Show one vault's status (level, records, writes, chain head)
    Status { name: String },
    /// Rotate the vault onto fresh derived keys: every sealed blob is
    /// re-encrypted and every integrity tag re-keyed, in one transaction.
    /// Crash-safe at any point. Re-run `index push` afterwards if this
    /// vault was pushed to a remote index (remote copies hold old-key
    /// ciphertext). Do not rotate a vault another process is serving.
    Rotate { name: String },
    /// Fast-forward the manifest's rollback anchor onto the committed
    /// audit-chain head. A **write** (it fsyncs a new manifest), and the
    /// only way to close the anchor-lag window without manufacturing one:
    /// `verify` does not anchor, and a long-lived server caches its handle
    /// so it never re-opens either. Reports how far behind the anchor was;
    /// a rolled-back database is still an integrity verdict here (exit 2),
    /// because declining to heal is not declining to look.
    Anchor { name: String },
}

#[derive(clap::Subcommand)]
enum AdmissionAction {
    /// Drawers awaiting a ruling: signals, intended destination, age
    List,
    /// Re-file a quarantined drawer where it was headed (chain-audited)
    Allow { id: String },
    /// Destroy a quarantined drawer's content through the attested
    /// forgetting path: audited ruling + keyed tombstone + a verifiable
    /// receipt (the trail remains, the content does not)
    Deny {
        id: String,
        /// Write the attestation JSON here (default: stdout)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Signing identity file (`bundle sign-keygen`) — attests the
        /// operator as sender on the deny receipt
        #[arg(long)]
        sign: Option<PathBuf>,
    },
}

#[derive(clap::Subcommand)]
enum RetentionAction {
    /// Declare how long a wing (or one room) keeps drawers. Audited;
    /// a flipped policy fails verification. The quarantine wing is
    /// refused — its doors are `admission allow`/`deny`.
    Set {
        wing: String,
        #[arg(long)]
        room: Option<String>,
        #[arg(long)]
        days: u32,
    },
    /// Remove a declared policy (an explicit, audited act)
    Clear {
        wing: String,
        #[arg(long)]
        room: Option<String>,
    },
    /// Every declared policy, tag-verified
    List,
    /// Destroy what has aged out, through the attested forgetting path.
    /// Nothing runs automatically — a sweep happens when you run it.
    Sweep {
        /// Report what would be destroyed without destroying anything
        #[arg(long)]
        dry_run: bool,
        /// Write the sweep report (with attestation) here (default: stdout)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Signing identity file — attests the operator on the sweep's
        /// destruction receipt
        #[arg(long)]
        sign: Option<PathBuf>,
    },
}

#[derive(clap::Subcommand)]
enum TrustAction {
    /// Assign a wing's trust class (quarantined|standard|trusted).
    /// Audited through the chain; a flipped row fails verification.
    Set { wing: String, class: String },
    /// Every assigned wing trust class (absent wings read as standard)
    List,
}

#[derive(clap::Subcommand)]
enum BundleAction {
    /// Generate a recipient identity: the secret key goes to a private
    /// file, the shareable public recipient string prints to stdout
    Keygen {
        /// Where to write the identity secret (default: <data-dir>/bundle.key)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the public recipient string for an identity file
    Recipient {
        /// Identity key file written by `bundle keygen`
        identity: PathBuf,
    },
    /// Generate a SIGNING identity (Ed25519): attests who produced a
    /// bundle, beside the recipient identity that says who may read it
    SignKeygen {
        /// Where to write the signing secret (default: <data-dir>/bundle-sign.key)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the public sender string for a signing identity file
    Sender {
        /// Signing key file written by `bundle sign-keygen`
        identity: PathBuf,
    },
}

/// Write a secret to `path` with owner-only permissions (like the palace
/// master key). Refuses to overwrite an existing identity.
fn write_identity(path: &std::path::Path, secret_hex: &str) -> Result<()> {
    if path.exists() {
        bail!(
            "{} already exists — refusing to overwrite an identity key \
             (bundles sealed to it would become unreadable)",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, secret_hex.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Build the full export payload: a manifest line, then typed records —
/// every drawer, KG entity, fact (receipts and authority tier included)
/// and tunnel. This is what closed the meta-rows export gap: an export
/// used to carry drawers alone, so a migrated palace silently lost its
/// whole knowledge graph. The manifest carries what is NOT importable
/// state as provenance instead (embedder identity, audit-chain head).
fn build_export_payload(
    store: &undercroft_store::PalaceStore,
    signing_secret: Option<&str>,
    trust: Option<&str>,
    expires: Option<&str>,
) -> Result<Vec<u8>> {
    use undercroft_vault::bundle;
    let mut records = Vec::new();
    let mut counts = bundle::ManifestCounts::default();
    for drawer in store.export_all()? {
        serde_json::to_writer(&mut records, &serde_json::json!({ "drawer": drawer }))?;
        records.push(b'\n');
        counts.drawers += 1;
    }
    for (name, etype) in store.kg_export_entities()? {
        serde_json::to_writer(
            &mut records,
            &serde_json::json!({ "entity": { "name": name, "etype": etype } }),
        )?;
        records.push(b'\n');
        counts.kg_entities += 1;
    }
    for exp in store.kg_export()? {
        serde_json::to_writer(&mut records, &serde_json::json!({ "triple": exp }))?;
        records.push(b'\n');
        counts.kg_triples += 1;
    }
    for t in store.list_tunnels(None)? {
        serde_json::to_writer(&mut records, &serde_json::json!({ "tunnel": t }))?;
        records.push(b'\n');
        counts.tunnels += 1;
    }
    let (vault_id, level, embedder, chain_head) = store.manifest_facts()?;
    let mut manifest = bundle::BundleManifest {
        version: 1,
        vault: vault_id,
        level,
        created_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?,
        counts,
        embedder: Some(embedder),
        chain_head: Some(chain_head),
        trust: trust.map(str::to_string),
        expires: expires.map(str::to_string),
        sender: None,
        payload_sha256: bundle::payload_digest(&records),
        sig: None,
    };
    if let Some(secret) = signing_secret {
        manifest
            .sign(secret)
            .map_err(|e| anyhow::anyhow!("signing manifest: {e}"))?;
    }
    Ok(bundle::frame_payload(&manifest, &records))
}

/// Bulk-ingest batch size: bounds RAM (embeddings in flight) and how long
/// one transaction holds the write lock.
const INGEST_BATCH: usize = 256;

/// Flush drawers through the store's single-transaction bulk path in
/// bounded chunks, accumulating the per-batch outcomes so a caller can
/// report the diverted count as well as the created one.
fn upsert_batched(
    store: &mut undercroft_store::PalaceStore,
    drawers: &[Drawer],
) -> Result<undercroft_store::BulkOutcome> {
    let mut total = undercroft_store::BulkOutcome::default();
    for (c, chunk) in drawers.chunks(INGEST_BATCH).enumerate() {
        // Name the batch a store-guard refusal came from, the way a parse
        // error already names its line. Six refusal classes reached this
        // path with this branch and every one of them reported the reason
        // and no position, over a file that can hold a million records
        // (ROADMAP C10). A batch is a transaction, so the failing RECORD is
        // not individually identifiable here — what is honest is the range,
        // and saying so is better than saying nothing. `/v1` commits per
        // record and names the record; both surfaces say where now.
        let out = store.upsert_many(chunk).with_context(|| {
            let first = c * INGEST_BATCH + 1;
            let last = first + chunk.len() - 1;
            format!(
                "importing records {first}-{last} (this batch is one transaction, so none of                  it was written; records before it were)"
            )
        })?;
        total.created += out.created;
        total.quarantined += out.quarantined;
    }
    Ok(total)
}

/// The line every bulk ingest prints when the screen diverted part of the
/// batch. `undercroft import` printed "imported 500" while an arbitrary
/// number of those drawers sat in `quarantine-pending` — unretrievable by
/// any search, and invisible unless the operator separately thought to run
/// `admission list`. Nothing is printed when nothing was diverted, so the
/// default (screening off) output is byte-identical.
fn report_quarantined(quarantined: usize) {
    if quarantined > 0 {
        println!(
            "{quarantined} of these tripped the admission screen and were quarantined \
             pending review — they are NOT retrievable where they were filed. \
             Review with `undercroft admission list`."
        );
    }
}

/// The user's home directory — the anchor for the default palace and for
/// `~/` expansion.
///
/// **`HOME` alone is a Unix assumption and the released Windows binary paid
/// for it.** Native Windows sets `USERPROFILE` and not `HOME`, so
/// [`data_dir`] fell through to `"."` and every vault landed in whatever
/// directory the user happened to be standing in: a different palace per
/// shell, none of them found again, and no error at any point. It survived
/// because every environment this was ever exercised in — Linux, macOS, the
/// Docker battery, and Git Bash or WSL on a Windows host — sets `HOME`. The
/// one configuration that does not is the one the release ships a binary for.
fn home_dir() -> Option<PathBuf> {
    // A concrete signature, not `std::env::var_os` passed bare: that is
    // generic over `AsRef<OsStr>`, so the fn item it names is bound to one
    // specific lifetime and does not satisfy the higher-ranked `Fn(&str)`
    // the parameter asks for.
    fn from_env(key: &str) -> Option<std::ffi::OsString> {
        std::env::var_os(key)
    }
    home_dir_from(from_env)
}

/// The lookup itself, split from the environment so it can be tested without
/// mutating process state — `set_var` races every other test in the binary.
///
/// An **empty** value is treated as absent. `HOME=` set to nothing is not a
/// home directory, and taking it would skip the fallback that exists for
/// exactly the case where the first variable is not usable.
fn home_dir_from(get: impl Fn(&str) -> Option<std::ffi::OsString>) -> Option<PathBuf> {
    ["HOME", "USERPROFILE"]
        .into_iter()
        .filter_map(&get)
        .find(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn data_dir(cli: &Cli) -> PathBuf {
    cli.data_dir
        .clone()
        .unwrap_or_else(|| home_dir().unwrap_or_else(|| ".".into()).join(".undercroft"))
}

/// The declared passphrase, through the ONE resolver `config check` also
/// runs — never `.filter(|p| !p.is_empty())`, which is what silently turned a
/// failed interpolation into "no passphrase" and wrote a key to disk.
fn passphrase() -> Result<Option<String>> {
    let raw = std::env::var("UNDERCROFT_PASSPHRASE").ok();
    undercroft_store::resolve_passphrase(raw.as_deref()).map_err(|e| anyhow::anyhow!(e))
}

fn manager(cli: &Cli) -> Result<VaultManager> {
    let dir = data_dir(cli);
    let pw = passphrase()?;
    VaultManager::open(&dir, pw.as_deref())
        .with_context(|| format!("opening palace at {}", dir.display()))
}

/// Whether a store this process opens is allowed to write to the vault.
///
/// A required argument on [`open_store_as`], not a defaulted flag: the
/// `serve-http --read-only` process opens TWO handles on the same vault (one
/// for `/mcp`, one per tenant vault inside `Tenancy`), and for a while only
/// the second one honoured the flag — so a "read-only" server re-embedded
/// every drawer on the `--vault` vault at start-up (a bulk write, plus
/// dropping the PQ/IVF tables) and, under `UNDERCROFT_READ_AUDIT=chain`,
/// appended a chain record per `/mcp` search. Whether the vault was written
/// depended on which port path opened it. Making the posture something a
/// caller must state is what keeps the two handles from drifting apart again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Posture {
    ReadWrite,
    ReadOnly,
}

fn open_store(cli: &Cli, vault: &str) -> Result<PalaceStore> {
    open_store_as(cli, vault, Posture::ReadWrite)
}

fn open_store_as(cli: &Cli, vault: &str, posture: Posture) -> Result<PalaceStore> {
    let mgr = manager(cli)?;
    // The posture reaches the UNLOCK, not only the store open. Unlocking is
    // not passive: it deletes a `vault.json.next` it cannot authenticate, so
    // a read-only process that stated its posture only one call later had
    // already destroyed a concurrent writer's staging manifest by the time
    // the store could decline to (ROADMAP A32/R4).
    let v = match posture {
        Posture::ReadOnly => mgr.unlock_as(vault, undercroft_vault::Access::ReadOnly)?,
        Posture::ReadWrite => mgr.unlock(vault)?,
    };
    // One place decides what the posture means, so every embedder reaches the
    // same two opens. `open_read_only` declines the embedder migration (warn
    // and serve, the replica precedent) and force-disables read auditing.
    let open = |v: Vault, e: Box<dyn undercroft_core::embed::Embedder + Send>| match posture {
        Posture::ReadOnly => PalaceStore::open_read_only(v, e),
        Posture::ReadWrite => PalaceStore::open_with_embedder(v, e),
    };
    let mut store = match std::env::var("UNDERCROFT_EMBEDDER").as_deref() {
        Ok("onnx") => {
            #[cfg(feature = "onnx")]
            {
                let embedder = undercroft_embed_onnx::from_env()
                    .map_err(|e| anyhow::anyhow!("loading ONNX embedder: {e}"))?;
                open(v, Box::new(embedder))?
            }
            #[cfg(not(feature = "onnx"))]
            bail!(
                "UNDERCROFT_EMBEDDER=onnx requires a build with the 'onnx' feature \
                 (cargo build -p undercroft-cli --features onnx)"
            );
        }
        Ok("ort") => {
            #[cfg(feature = "ort")]
            {
                let embedder = undercroft_embed_ort::embedder_from_env()
                    .map_err(|e| anyhow::anyhow!("loading ORT embedder: {e}"))?;
                open(v, Box::new(embedder))?
            }
            #[cfg(not(feature = "ort"))]
            bail!(
                "UNDERCROFT_EMBEDDER=ort requires a build with the 'ort' feature \
                 (cargo build -p undercroft-cli --features ort)"
            );
        }
        // A model served over HTTP — Ollama, llama.cpp server, LM Studio,
        // vLLM, text-embeddings-inference. No feature gate: the client is
        // `ureq`, which the LLM crate already links for `refine`.
        Ok("http") => {
            let embedder = undercroft_llm::HttpEmbedder::from_env()
                .map_err(|e| anyhow::anyhow!("connecting to the embeddings endpoint: {e}"))?;
            open(v, Box::new(embedder))?
        }
        Ok("hash") | Ok("") | Err(_) => open(v, Box::new(undercroft_core::HashEmbedder))?,
        Ok(other) => {
            // The message comes from the SAME validator `config check` runs,
            // so the pre-flight and the start-up can never disagree about
            // what is legal. The named arms above matched every legal value,
            // so this is an error by construction.
            bail!(check_embedder(other)
                .expect_err("every legal embedder name is matched by an arm above"))
        }
    };
    attach_reranker(&mut store)?;
    attach_retrieval(&mut store)?;
    attach_admission_advisor(&mut store)?;
    Ok(store)
}

/// Wire the optional tier-2 admission advisor
/// (`UNDERCROFT_ADMISSION_LLM=advisory` + the `UNDERCROFT_LLM_*` family).
/// Declared-but-unusable refuses to open — a screen that silently isn't
/// running is worse than a refusal to start.
pub(crate) fn attach_admission_advisor(store: &mut PalaceStore) -> Result<()> {
    if let Some(advisor) = undercroft_llm::advisor::LlmAdmissionAdvisor::from_env()
        .map_err(|e| anyhow::anyhow!("admission advisor: {e}"))?
    {
        store.set_admission_advisor(Some(Box::new(advisor)));
    }
    Ok(())
}

/// The `UNDERCROFT_EMBEDDER` vocabulary, and what THIS BUILD can honour.
///
/// **One implementation, two callers**: the open path below and
/// `undercroft config check`. The parse used to live only inside that
/// path's `match`, so the pre-flight had nothing to call — `check_declaration`
/// fell through to its catch-all and the command printed *"no parse to run;
/// the consumer validates it"* about a value that bails before the port is
/// bound. Round-four #9: the pre-flight said "This environment starts" for
/// environments that do not.
///
/// Validates the NAME only. It must not construct anything — `config check`
/// opens nothing and makes no outbound call, and loading a model is both.
pub(crate) fn check_embedder(raw: &str) -> Result<(), String> {
    match raw {
        "" | "hash" | "http" | "external" => Ok(()),
        "onnx" if !cfg!(feature = "onnx") => Err(
            "UNDERCROFT_EMBEDDER=onnx requires a build with the 'onnx' feature \
             (cargo build -p undercroft-cli --features onnx)"
                .to_string(),
        ),
        "ort" if !cfg!(feature = "ort") => Err(
            "UNDERCROFT_EMBEDDER=ort requires a build with the 'ort' feature \
             (cargo build -p undercroft-cli --features ort)"
                .to_string(),
        ),
        "onnx" | "ort" => Ok(()),
        other => Err(format!(
            "unknown UNDERCROFT_EMBEDDER {other:?} (expected: hash, onnx, ort, http)"
        )),
    }
}

/// The `UNDERCROFT_RETRIEVAL` vocabulary, and what this build can honour.
/// Same shape and same reason as [`check_embedder`].
pub(crate) fn check_retrieval(raw: &str) -> Result<(), String> {
    match raw {
        "" | "pq" | "fde" => Ok(()),
        "hnsw" if !cfg!(feature = "hnsw") => Err(
            "UNDERCROFT_RETRIEVAL=hnsw requires a build with the 'hnsw' feature \
             (cargo build -p undercroft-cli --features hnsw)"
                .to_string(),
        ),
        "hnsw" => Ok(()),
        other => Err(format!(
            "unknown UNDERCROFT_RETRIEVAL {other:?} (expected: pq, fde, hnsw)"
        )),
    }
}

/// Select the candidate-generation strategy via `UNDERCROFT_RETRIEVAL`
/// (same contract as the bench harness). Unset ⇒ the default full scan with
/// the FTS prefilter. `pq` enables the on-disk PQ/IVF prefilter — plain
/// codes on hmac-only vaults, AEAD-sealed rows + a decrypt-once RAM cache
/// on sealed vaults.
fn attach_retrieval(store: &mut PalaceStore) -> Result<()> {
    let raw = std::env::var("UNDERCROFT_RETRIEVAL").unwrap_or_default();
    // The vocabulary is decided ONCE, by the same function `config check`
    // runs, so the pre-flight and the start-up cannot disagree about what is
    // legal. Everything below is application, not validation — which is why
    // the final arm can be a bare `_` with no second error message.
    check_retrieval(&raw).map_err(|e| anyhow::anyhow!(e))?;
    match raw.as_str() {
        "pq" => store.set_pq(true),
        "fde" => store.set_fde(true),
        #[cfg(feature = "hnsw")]
        "hnsw" => store.set_hnsw(true),
        _ => {}
    }
    Ok(())
}

/// Attach the second retrieval stage via `UNDERCROFT_RERANKER`: `onnx` /
/// `colbert` load the tract backend (`onnx` feature), `ort` / `colbert-ort`
/// the ONNX Runtime backend (`ort` feature) — same model files and
/// `UNDERCROFT_RERANK_*` / `UNDERCROFT_COLBERT_*` variables either way.
/// Unset ⇒ first-pass ranking only.
#[cfg_attr(not(any(feature = "onnx", feature = "ort")), allow(unused_variables))]
fn attach_reranker(store: &mut PalaceStore) -> Result<()> {
    match std::env::var("UNDERCROFT_RERANKER").as_deref() {
        Ok("onnx") => {
            #[cfg(feature = "onnx")]
            {
                let rr = undercroft_embed_onnx::OnnxReranker::from_env()
                    .map_err(|e| anyhow::anyhow!("loading ONNX reranker: {e}"))?;
                store.set_reranker(Some(Box::new(rr)));
                Ok(())
            }
            #[cfg(not(feature = "onnx"))]
            bail!(
                "UNDERCROFT_RERANKER=onnx requires a build with the 'onnx' feature \
                 (cargo build -p undercroft-cli --features onnx)"
            );
        }
        Ok("colbert") => {
            #[cfg(feature = "onnx")]
            {
                let c = undercroft_embed_onnx::colbert_from_env()
                    .map_err(|e| anyhow::anyhow!("loading ColBERT encoder: {e}"))?;
                store.set_late(Some(Box::new(c)));
                Ok(())
            }
            #[cfg(not(feature = "onnx"))]
            bail!(
                "UNDERCROFT_RERANKER=colbert requires a build with the 'onnx' feature \
                 (cargo build -p undercroft-cli --features onnx)"
            );
        }
        Ok("ort") => {
            #[cfg(feature = "ort")]
            {
                let rr = undercroft_embed_ort::reranker_from_env()
                    .map_err(|e| anyhow::anyhow!("loading ORT reranker: {e}"))?;
                store.set_reranker(Some(Box::new(rr)));
                Ok(())
            }
            #[cfg(not(feature = "ort"))]
            bail!(
                "UNDERCROFT_RERANKER=ort requires a build with the 'ort' feature \
                 (cargo build -p undercroft-cli --features ort)"
            );
        }
        Ok("colbert-ort") => {
            #[cfg(feature = "ort")]
            {
                let c = undercroft_embed_ort::colbert_from_env()
                    .map_err(|e| anyhow::anyhow!("loading ORT ColBERT encoder: {e}"))?;
                store.set_late(Some(Box::new(c)));
                Ok(())
            }
            #[cfg(not(feature = "ort"))]
            bail!(
                "UNDERCROFT_RERANKER=colbert-ort requires a build with the 'ort' feature \
                 (cargo build -p undercroft-cli --features ort)"
            );
        }
        Ok("") | Err(_) => Ok(()),
        Ok(other) => {
            bail!(
                "unknown UNDERCROFT_RERANKER {other:?} \
                 (expected: onnx, ort, colbert, colbert-ort, or unset)"
            )
        }
    }
}

fn open_index(backend: &str) -> Result<Box<dyn undercroft_index::VectorIndex>> {
    Ok(undercroft_index::from_env(backend)?)
}

/// Build the per-vault embedder factory for the multi-tenant server: a
/// vault that recorded an `external:<name>@<dim>` identity reconstructs an
/// [`undercroft_core::ExternalEmbedder`]; every other vault gets the
/// configured default (`UNDERCROFT_EMBEDDER`).
fn embedder_factory() -> tenant::EmbedderFactory {
    Box::new(
        |vault: &Vault| -> Result<Box<dyn undercroft_core::embed::Embedder + Send>> {
            if let Some((name, dim)) = PalaceStore::recorded_embedder(vault)? {
                if let Some(bare) = name.strip_prefix("external:") {
                    return Ok(Box::new(undercroft_core::ExternalEmbedder::new(bare, dim)));
                }
            }
            match std::env::var("UNDERCROFT_EMBEDDER").as_deref() {
                Ok("onnx") => {
                    #[cfg(feature = "onnx")]
                    {
                        Ok(Box::new(undercroft_embed_onnx::from_env().map_err(
                            |e| anyhow::anyhow!("loading ONNX embedder: {e}"),
                        )?))
                    }
                    #[cfg(not(feature = "onnx"))]
                    bail!(
                        "UNDERCROFT_EMBEDDER=onnx requires a build with the 'onnx' feature \
                         (cargo build -p undercroft-cli --features onnx)"
                    )
                }
                Ok("ort") => {
                    #[cfg(feature = "ort")]
                    {
                        // One session pool shared across every tenant vault —
                        // the pool holds a model copy per core, so per-vault
                        // loads would multiply RAM for identical weights.
                        use std::sync::{Arc, OnceLock};
                        static SHARED: OnceLock<Arc<undercroft_embed_ort::OrtEmbedder>> =
                            OnceLock::new();
                        let arc = match SHARED.get() {
                            Some(a) => a.clone(),
                            None => {
                                let e = undercroft_embed_ort::embedder_from_env()
                                    .map_err(|e| anyhow::anyhow!("loading ORT embedder: {e}"))?;
                                SHARED.get_or_init(|| Arc::new(e)).clone()
                            }
                        };
                        Ok(Box::new(SharedOrtEmbedder(arc)))
                    }
                    #[cfg(not(feature = "ort"))]
                    bail!(
                        "UNDERCROFT_EMBEDDER=ort requires a build with the 'ort' feature \
                         (cargo build -p undercroft-cli --features ort)"
                    )
                }
                // A model served over HTTP. The CLI resolver has always had
                // this arm; the server's had not, so `UNDERCROFT_EMBEDDER=http`
                // worked for `remember` and answered 500 on every `/v1` write
                // — the served posture unreachable from the surface teams
                // actually deploy, with the TLS terminator and CA pin shipped
                // for it. Found by driving the engine as AMB's provider.
                Ok("http") => {
                    let embedder = undercroft_llm::HttpEmbedder::from_env().map_err(|e| {
                        anyhow::anyhow!("connecting to the embeddings endpoint: {e}")
                    })?;
                    Ok(Box::new(embedder))
                }
                Ok("hash") | Ok("") | Err(_) => Ok(Box::new(undercroft_core::HashEmbedder)),
                Ok(other) => {
                    bail!("unknown UNDERCROFT_EMBEDDER {other:?} (expected: hash, http, onnx, ort)")
                }
            }
        },
    )
}

/// A cheap handle onto the one shared [`undercroft_embed_ort::OrtEmbedder`]
/// session pool the multi-tenant server loaded.
#[cfg(feature = "ort")]
struct SharedOrtEmbedder(std::sync::Arc<undercroft_embed_ort::OrtEmbedder>);

#[cfg(feature = "ort")]
impl undercroft_core::embed::Embedder for SharedOrtEmbedder {
    fn model_name(&self) -> &str {
        self.0.model_name()
    }
    fn dimension(&self) -> usize {
        self.0.dimension()
    }
    fn embed(&self, text: &str) -> Vec<f32> {
        self.0.embed(text)
    }
}

/// Build the shared reranker factory for the multi-tenant server. When
/// `UNDERCROFT_RERANKER=onnx`, the cross-encoder model is loaded **once** here
/// and every tenant vault shares that single model (each `store_for` gets a
/// cheap `Arc`-clone handle) — mirroring how a single-vault server attaches
/// its reranker, without loading a copy per vault. Unset ⇒ `None` (first-pass
/// ranking only, the default).
#[cfg_attr(not(any(feature = "onnx", feature = "ort")), allow(unused_variables))]
fn reranker_factory() -> Result<Option<tenant::RerankerFactory>> {
    match std::env::var("UNDERCROFT_RERANKER").as_deref() {
        Ok("onnx") => {
            #[cfg(feature = "onnx")]
            {
                use std::sync::Arc;
                let shared = Arc::new(
                    undercroft_embed_onnx::OnnxReranker::from_env()
                        .map_err(|e| anyhow::anyhow!("loading ONNX reranker: {e}"))?,
                );
                let factory: tenant::RerankerFactory =
                    Box::new(move || Box::new(SharedReranker(shared.clone())));
                Ok(Some(factory))
            }
            #[cfg(not(feature = "onnx"))]
            bail!(
                "UNDERCROFT_RERANKER=onnx requires a build with the 'onnx' feature \
                 (cargo build -p undercroft-cli --features onnx)"
            );
        }
        Ok("ort") => {
            #[cfg(feature = "ort")]
            {
                use std::sync::Arc;
                let shared = Arc::new(
                    undercroft_embed_ort::reranker_from_env()
                        .map_err(|e| anyhow::anyhow!("loading ORT reranker: {e}"))?,
                );
                let factory: tenant::RerankerFactory =
                    Box::new(move || Box::new(SharedOrtReranker(shared.clone())));
                Ok(Some(factory))
            }
            #[cfg(not(feature = "ort"))]
            bail!(
                "UNDERCROFT_RERANKER=ort requires a build with the 'ort' feature \
                 (cargo build -p undercroft-cli --features ort)"
            );
        }
        Ok("colbert") | Ok("colbert-ort") => bail!(
            "the ColBERT late-interaction stage is not available on the \
             multi-tenant server (use UNDERCROFT_RERANKER=onnx or ort, or serve \
             a single vault)"
        ),
        Ok("") | Err(_) => Ok(None),
        Ok(other) => bail!("unknown UNDERCROFT_RERANKER {other:?} (expected: onnx, ort, or unset)"),
    }
}

/// A cheap handle onto the one shared [`undercroft_embed_ort::OrtReranker`] the
/// multi-tenant server loaded. Forwards `score_batch` — the ORT backend scores
/// the whole pool in one batched forward, which is where its speedup lives.
#[cfg(feature = "ort")]
struct SharedOrtReranker(std::sync::Arc<undercroft_embed_ort::OrtReranker>);

#[cfg(feature = "ort")]
impl undercroft_core::rerank::Reranker for SharedOrtReranker {
    fn model_name(&self) -> &str {
        self.0.model_name()
    }
    fn score(&self, query: &str, passage: &str) -> f32 {
        self.0.score(query, passage)
    }
    fn score_batch(&self, query: &str, passages: &[&str]) -> Vec<f32> {
        self.0.score_batch(query, passages)
    }
}

/// A cheap handle onto the one shared [`OnnxReranker`] the multi-tenant server
/// loaded — every tenant store scores against the same model.
#[cfg(feature = "onnx")]
struct SharedReranker(std::sync::Arc<undercroft_embed_onnx::OnnxReranker>);

#[cfg(feature = "onnx")]
impl undercroft_core::rerank::Reranker for SharedReranker {
    fn model_name(&self) -> &str {
        self.0.model_name()
    }
    fn score(&self, query: &str, passage: &str) -> f32 {
        self.0.score(query, passage)
    }
}

/// Exit 2 — an INTEGRITY VERDICT: the engine detected that stored evidence
/// does not verify. Reserved for that and nothing else, because a compliance
/// script keys its retry logic on the class.
const EXIT_INTEGRITY: u8 = 2;
/// Exit 1 — the run itself failed: bad arguments, a missing file, an
/// unreadable vault. Retryable in the sense that a retry might succeed.
const EXIT_FAILURE: u8 = 1;

/// Is this error an integrity verdict, or an ordinary run failure?
///
/// **`verify`, `repair`, `backup create` and `verify-forgetting` each decided
/// this for themselves, by calling `std::process::exit(2)` at the point they
/// printed their own verdict — and every OTHER route to the same verdict
/// exited 1.** A vault rolled back under a still-valid manifest, or a manifest
/// edited offline, is detected inside `open_store`, before any command's own
/// checking begins: `undercroft search`, `undercroft recent`, `undercroft stats`
/// on a tampered palace all bubbled that up through `?` as an anyhow error and
/// exited 1 — the code docs/AGENTS.md promises means "the run failed, retry
/// it". A compliance script did exactly that, forever, against a vault whose
/// answer will never change.
///
/// So the decision moves to the one place every command returns through. The
/// classes are deliberately the same set `/v1` marks **`class: "integrity"`**
/// (`tenant::store_err` / `tenant::vault_err`), so the two surfaces cannot
/// state different doctrines about the same bytes.
///
/// **Not "the set `/v1` answers 409 for", which is what this line said until
/// 2026-08-10 and is false.** `ReadOnlyUnmigrated` answers 409 and is
/// deliberately not a verdict here — an intact vault under a wrong posture —
/// and so does a co-resident refusal. That is precisely why the `class`
/// marker exists rather than the status carrying the meaning, and a claim
/// pinned to the status could hold while the doctrine drifted. The two sets
/// are counted against each other by
/// `tenant::tests::the_cli_exit_2_set_and_v1s_integrity_class_are_one_set`.
///
/// **The stated cost**: a wrong `UNDERCROFT_PASSPHRASE` derives a different
/// manifest key, so the MAC fails and this reports an integrity verdict for
/// what is really operator error. That is not a classification bug — it is
/// what a MAC *is*, the engine has no evidence separating the two, and the
/// message it already printed ("possible tampering") has always said so. The
/// exit code now agrees with the message instead of contradicting it.
fn integrity_verdict(e: &anyhow::Error) -> bool {
    use undercroft_store::StoreError as S;
    use undercroft_vault::VaultError as V;
    // Walk the whole chain: `open_store` and friends add `.with_context`, and
    // the verdict is then several links down from the anyhow head.
    e.chain().any(|link| {
        if let Some(s) = link.downcast_ref::<S>() {
            return matches!(
                s,
                S::Integrity(_)
                    | S::Attestation(_)
                    // A manifest that describes a database which is not
                    // there is stored evidence contradicting itself, and
                    // retrying only re-detects it (R4/A33). Its neighbour
                    // `ReadOnlyUnmigrated` is deliberately NOT here: the
                    // vault is intact, the posture is simply wrong for it.
                    | S::DatabaseMissing { .. }
                    | S::Vault(V::ManifestTampered | V::CorruptManifest(_))
            );
        }
        if let Some(v) = link.downcast_ref::<V>() {
            return matches!(v, V::ManifestTampered | V::CorruptManifest(_));
        }
        false
    })
}

fn main() -> std::process::ExitCode {
    // `fn main() -> Result<()>` let the std `Termination` impl choose the
    // code, and it only knows one failure: 1. Everything this CLI wants to
    // say about a failure has to be said here.
    // **Exit 1 for a usage error, not clap's default 2.** `docs/AGENTS.md`
    // states the doctrine without qualification — exit 2 means an integrity
    // verdict, exit 1 means the run itself failed, "bad arguments, a missing
    // file" — and clap's `USAGE_CODE` is 2, so a typo or a renamed flag
    // reached a compliance script as a TAMPER VERDICT. The doctrine and the
    // parser disagreed, and the doctrine is the one that is published.
    // `--help`/`--version` still exit 0, which is what `use_stderr` decides.
    let parsed = <Cli as clap::Parser>::try_parse().unwrap_or_else(|e| {
        let _ = e.print();
        std::process::exit(if e.use_stderr() { 1 } else { 0 });
    });
    // Telemetry is a no-op unless built with `--features telemetry`. The
    // guard flushes providers on any return path (including `?` out of `run`).
    //
    // It runs AFTER the parse because it can now FAIL — the OTLP endpoint is
    // an outward path, so a cleartext non-loopback collector is refused
    // rather than silently exported to in the clear. Nothing between the two
    // emits a span, so no signal is lost by the move.
    let _telemetry = match undercroft_obs::init() {
        Ok(g) => Some(g),
        // `config check` is EXEMPT, and the exemption is the point of the
        // command: it exists to diagnose an environment that will not start,
        // so a version of it that cannot itself start in that environment is
        // useless. It carries on without telemetry and reports the same
        // declaration as a finding of its own.
        // BOTH spellings, because `config check` and `config-check` are two
        // variants bound to one dispatch arm (see `Command::Config`) and
        // matching only the hyphenated one would exempt the spelling every
        // doc publishes from nothing at all.
        Err(e)
            if matches!(
                parsed.command,
                Command::ConfigCheck { .. } | Command::Config { .. }
            ) =>
        {
            eprintln!("warning: telemetry disabled — {e}");
            None
        }
        Err(e) => {
            eprintln!("Error: {e}");
            return std::process::ExitCode::from(EXIT_FAILURE);
        }
    };
    match run(parsed) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // Byte-for-byte what `Termination` printed before, so no
            // operator's grep changes meaning along with the exit code.
            eprintln!("Error: {e:?}");
            std::process::ExitCode::from(if integrity_verdict(&e) {
                EXIT_INTEGRITY
            } else {
                EXIT_FAILURE
            })
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::Init { level } => {
            let mgr = manager(&cli)?;
            if mgr.exists("default") {
                println!(
                    "{}",
                    fill(
                        tr("palace-already"),
                        &[("path", mgr.root().display().to_string())]
                    )
                );
            } else {
                mgr.create("default", (*level).into())?;
                println!(
                    "{}",
                    fill(
                        tr("palace-initialized"),
                        &[("path", mgr.root().display().to_string())]
                    )
                );
                println!(
                    "{}",
                    fill(
                        tr("vault-created"),
                        &[
                            ("name", "default".to_string()),
                            ("level", SecurityLevel::from(*level).to_string()),
                        ]
                    )
                );
                if passphrase()?.is_some() {
                    println!("Master key: derived from UNDERCROFT_PASSPHRASE (Argon2id)");
                } else {
                    println!("Master key: {}/master.key (0600)", mgr.root().display());
                }
            }
        }
        Command::Bundle { action } => match action {
            BundleAction::Keygen { out } => {
                let path = out
                    .clone()
                    .unwrap_or_else(|| data_dir(&cli).join("bundle.key"));
                let (secret_hex, recipient_hex) = undercroft_vault::bundle::keygen();
                write_identity(&path, &secret_hex)?;
                println!(
                    "Identity key written to {} (keep it private).",
                    path.display()
                );
                println!(
                    "Hybrid post-quantum identity (X25519 + ML-KEM-768). Legacy \
                     X25519 identities and their bundles keep working."
                );
                println!("Recipient (shareable): {recipient_hex}");
                println!("Seal an export with: undercroft export --to {recipient_hex} --out palace.bundle");
            }
            BundleAction::Recipient { identity } => {
                let secret = std::fs::read_to_string(identity)
                    .with_context(|| format!("reading identity {}", identity.display()))?;
                let recipient = undercroft_vault::bundle::recipient_of(&secret)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("{recipient}");
            }
            BundleAction::SignKeygen { out } => {
                let path = out
                    .clone()
                    .unwrap_or_else(|| data_dir(&cli).join("bundle-sign.key"));
                let (secret_hex, sender_hex) = undercroft_vault::bundle::sign_keygen();
                write_identity(&path, &secret_hex)?;
                println!(
                    "Signing key written to {} (keep it private).",
                    path.display()
                );
                println!("Sender (importers pin this): {sender_hex}");
                println!(
                    "Sign an export with: undercroft export --sign {} …; \
                     verify with: undercroft import --sender {sender_hex} …",
                    path.display()
                );
            }
            BundleAction::Sender { identity } => {
                let secret = std::fs::read_to_string(identity)
                    .with_context(|| format!("reading signing identity {}", identity.display()))?;
                let sender = undercroft_vault::bundle::signer_of(&secret)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("{sender}");
            }
        },
        Command::Vault { action } => match action {
            VaultAction::Create { name, level } => {
                let mgr = manager(&cli)?;
                let v = mgr.create(name, (*level).into())?;
                println!(
                    "{}",
                    fill(
                        tr("vault-created"),
                        &[
                            ("name", v.id().to_string()),
                            ("level", v.level().to_string()),
                        ]
                    )
                );
            }
            VaultAction::List => {
                let mgr = manager(&cli)?;
                let vaults = mgr.list()?;
                if vaults.is_empty() {
                    println!("No vaults. Run: undercroft init");
                }
                for name in vaults {
                    let v = mgr.unlock(&name)?;
                    let store = PalaceStore::open(v)?;
                    println!(
                        "{:<20} level={:<10} records={}",
                        name,
                        store.vault().level().to_string(),
                        store.count()?
                    );
                }
            }
            VaultAction::Status { name } => {
                let store = open_store(&cli, name)?;
                // The DATABASE's chain clock, never the handle's cached
                // manifest fields (`Vault::writes`/`chain_head_hex`).
                // CLAUDE.md names those two calls as the ones a reporting
                // surface must not make — they are loaded once at unlock and
                // never reloaded, so under `serve-http`'s two handles the
                // one that did not write reports a frozen height beside a
                // climbing live count. This surface was still making them
                // (ROADMAP A21).
                let (chain_head, writes) = store.chain_state()?;
                let v = store.vault();
                println!("vault:      {}", v.id());
                println!("level:      {}", v.level());
                println!("records:    {}", store.count()?);
                println!("writes:     {writes}");
                println!("chain head: {chain_head}");
                println!("db:         {}", v.db_path().display());
            }
            VaultAction::Anchor { name } => {
                use undercroft_store::AnchorState;
                let mut store = open_store(&cli, name)?;
                // What the OPEN found, because on this surface the open has
                // already healed it: `open_store` runs the same
                // reconciliation, so by the time this command can ask, the
                // answer is "current" and the lag it closed would go
                // unreported. The route on a long-lived server is the case
                // where the CALL does the work — there the handle is cached
                // and never re-opens (A31).
                let at_open = store.anchor_at_open();
                match (store.tighten_anchor()?, at_open) {
                    (AnchorState::Unseeded, _) => {
                        println!(
                            "Vault '{name}' has no committed chain head yet; nothing to anchor."
                        );
                    }
                    (_, AnchorState::Healed { behind_by }) => {
                        println!(
                            "Anchored '{name}': the manifest was {behind_by} record(s) behind \
                             the committed chain head and now names it (the open did the \
                             fast-forward — on this surface it always gets there first)."
                        );
                    }
                    (AnchorState::Healed { behind_by }, _) => {
                        println!(
                            "Anchored '{name}': the manifest was {behind_by} record(s) behind \
                             and now names the committed chain head."
                        );
                    }
                    (AnchorState::Current, _) => {
                        println!("Anchor for '{name}' already names the committed chain head.");
                    }
                }
            }
            VaultAction::Rotate { name } => {
                let mgr = manager(&cli)?;
                let candidate = mgr.rotation_candidate(name)?;
                let mut store = open_store(&cli, name)?;
                let report = store.rotate_keys(candidate)?;
                println!("Rotated vault '{name}' onto fresh keys.");
                println!("  drawers re-sealed:   {}", report.drawers);
                println!(
                    "  kg entities/triples: {}/{}",
                    report.kg_entities, report.kg_triples
                );
                println!("  tunnels:             {}", report.tunnels);
                // Re-tagged, not re-sealed, and level-independent. Printed
                // because a rotation that silently skipped these is what
                // broke the trust floor and retention enforcement outright —
                // an operator watching a rotation should see the two tables
                // whose tags are verified on every read. `/v1` serializes the
                // whole struct and got them for free; this projection is
                // hand-written, which is the trap CLAUDE.md records and
                // `every_hand_projected_report_field_reaches_the_cli` now
                // fails on.
                println!(
                    "  policy tags re-keyed: {} wing trust, {} retention",
                    report.wing_trusts, report.retention_policies
                );
                println!(
                    "  derived artifacts:   {} token, {} pq (+{} pages, +{} wing rows), {} fde, {} meta",
                    report.token_matrices,
                    report.pq_rows,
                    report.pq_pages,
                    report.wing_pq_rows,
                    report.fde_rows,
                    report.meta_artifacts
                );
                println!(
                    "  chain re-keyed over: {} audit entries",
                    report.audit_entries
                );
                // The DATABASE's head, not the handle's cached manifest
                // field — the third and last A21 caller.
                let (chain_head, _) = store.chain_state()?;
                println!("  new chain head:      {chain_head}");
                println!(
                    "If this vault was pushed to a remote index, re-run: undercroft index push"
                );
            }
        },
        Command::Remember {
            content,
            vault,
            wing,
            room,
            content_date,
            supersedes,
            kind,
            agent,
            channel,
            session,
        } => {
            // Checked here as well as at the store's write choke point, so
            // an over-sized argument fails before a vault is unlocked. The
            // choke point is what makes the bound the ENGINE's rather than
            // this command's — MCP and /v1 had no check at all.
            undercroft_core::validate_content_len(content)?;
            undercroft_core::validate_name(wing, "wing")?;
            undercroft_core::validate_name(room, "room")?;
            if let Some(k) = kind.as_deref() {
                undercroft_core::validate_kind(k)?;
            }
            let mut store = open_store(&cli, vault)?;
            let normalized = normalize_content(content);
            if normalized.is_empty() {
                bail!("nothing to remember: content is empty after normalization");
            }
            // A unique append slot, never `count()`. `COUNT(*)` goes *down*
            // after a delete, so the next save is handed an index still in
            // use, the derived id collides, and `ON CONFLICT(id) DO UPDATE`
            // overwrites the unrelated drawer holding it — a record destroyed
            // by writing a different one. The `/v1` and MCP save paths already
            // use this; the CLI was the last one that did not.
            let idx = store.next_append_index()? as u32;
            let drawer = Drawer::new(wing, room, normalized, None, idx, "cli")
                .with_content_date(content_date.clone())
                .with_kind(kind.clone())
                .with_supersedes(supersedes.clone())
                .with_provenance(agent.clone(), channel.clone(), session.clone());
            // Screened: a diverted save must not print "filed in <wing>",
            // which is exactly what the caller did NOT get.
            let out = store.upsert_screened(&drawer)?;
            if out.quarantined {
                println!(
                    "Quarantined pending review: the content tripped the admission \
                     screen and is NOT retrievable in {wing}/{room}. \
                     Review with `undercroft admission list`."
                );
            } else {
                println!(
                    "{}",
                    fill(
                        tr("drawer-filed"),
                        &[
                            ("id", drawer.id.clone()),
                            ("wing", wing.clone()),
                            ("room", room.clone()),
                            ("vault", vault.clone()),
                        ]
                    )
                );
            }
        }
        Command::Mine {
            path,
            vault,
            wing,
            mode,
        } => {
            undercroft_core::validate_name(wing, "wing")?;
            let mut store = open_store(&cli, vault)?;
            let (files, drawers) = match mode.as_str() {
                "files" => mine_files(&mut store, path, wing)?,
                "convos" => mine_convos(&mut store, path, wing)?,
                other => bail!("unknown mine mode {other:?} (expected: files, convos)"),
            };
            println!(
                "{}",
                fill(
                    tr("mined-summary"),
                    &[
                        ("files", files.to_string()),
                        ("vault", vault.clone()),
                        ("wing", wing.clone()),
                        ("drawers", drawers.to_string()),
                    ]
                )
            );
        }
        Command::Sweep { path, vault, wing } => {
            undercroft_core::validate_name(wing, "wing")?;
            let mut store = open_store(&cli, vault)?;
            let (files, filed, skipped) = sweep_path(&mut store, path, wing, true)?;
            println!(
                "{}",
                fill(
                    tr("swept-summary"),
                    &[
                        ("files", files.to_string()),
                        ("filed", filed.to_string()),
                        ("skipped", skipped.to_string()),
                    ]
                )
            );
        }
        Command::Search {
            query,
            vault,
            wing,
            room,
            kind,
            min_trust,
            language,
            limit,
            offset,
            ranked_at,
            room_cap,
            backend,
        } => {
            let store = open_store(&cli, vault)?;
            // The instant the ranking is measured as of. Resolved HERE, printed
            // in the continuation line, and repeatable — because `--offset`
            // without it slices two different rankings: recency decay is
            // measured against a fresh clock on every call, so hits repeat
            // across pages or vanish between them. This surface shipped the
            // offset and not the clock that makes it mean anything.
            // A value that does not parse is said out loud, never a silent
            // fall-back to the host clock.
            let ranked_at = match ranked_at.as_deref() {
                Some(s) => {
                    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                        .map_err(|_| anyhow::anyhow!("--ranked-at must be an RFC 3339 instant"))?
                }
                None => time::OffsetDateTime::now_utc(),
            };
            let opts = SearchOptions {
                // Whose inflection applies, declared by the caller and parsed
                // from the same vocabulary MCP and `/v1` use. Undeclared, the
                // CLI reached only what the script settles (Greek, Georgian,
                // Hangul, Cyrillic, Devanagari) and the common suffix set —
                // German `-er` and the Romance/Dutch/Turkish tables need
                // saying, and this surface had no way to say them.
                morph_lang: undercroft_store::MorphLang::declared(language.as_deref()),
                wing: wing.clone(),
                room: room.clone(),
                kind: kind.clone(),
                min_trust: min_trust.clone(),
                limit: *limit,
                room_cap: *room_cap,
                offset: *offset,
                ranked_at: Some(ranked_at),
            };
            let hits = if backend == "local" {
                store.search(query, &opts)?
            } else {
                // A remote index answers through the legacy fusion and its own
                // candidate loop, which consults neither the declared
                // morphology nor the per-room cap. Refused rather than
                // ignored: a declaration this path cannot honour must not look
                // like one it did — that silence is the drift, one flag over.
                if language.is_some() || room_cap.is_some() {
                    bail!(
                        "--language and --room-cap are not honoured by --backend {backend} \
                         (the remote path ranks with the legacy fusion); drop the flag or \
                         search --backend local"
                    );
                }
                let mut index = open_index(backend)?;
                store.search_with_index(index.as_mut(), query, &opts)?
            };
            if hits.is_empty() {
                println!("{}", tr("no-matches"));
            }
            // What this request's own filters kept out of the competition
            // (docs/LABELS.md): a thin answer under a `kind` filter or a trust
            // floor must not be mistaken for a thin corpus. Counted by the same
            // helper every surface uses.
            for note in search::Exclusions::measure(&store, &opts)?.notes() {
                println!("{note}");
            }
            // The remote path has no `lexical_morph` channel at all:
            // `lexical_score`'s exact leg counts whole-word containment as
            // EXACT evidence there. So a `morph 0.000` on a remote hit means
            // "not computed on this path", not "no morphological relation" —
            // said once, because the evidence lines below otherwise read
            // exactly as the local ones do.
            if backend != "local" && !hits.is_empty() {
                println!(
                    "(remote backend: morphological evidence is folded into the exact channel)"
                );
            }
            for (i, hit) in hits.iter().enumerate() {
                println!(
                    "{}. [{:.3}] {}/{} — {} ({})",
                    // Absolute rank: on a page past the first, "1." would
                    // claim a rank the hit does not hold.
                    offset + i + 1,
                    hit.score,
                    hit.drawer.meta.wing,
                    hit.drawer.meta.room,
                    snippet(&hit.drawer.content, query, 100),
                    hit.drawer.meta.filed_at
                );
                // The id, on its own line so the hit line keeps its shape.
                // `drawer get|update|delete`, `forget` and `admission` all take
                // an id this surface never printed, so acting on a search
                // result meant hunting for it through `drawer list`. The line
                // also names the door back to the verbatim text, which the
                // 100-character snippet above is not.
                println!(
                    "   id {} — undercroft drawer get {}",
                    hit.drawer.id, hit.drawer.id
                );
                // Why this hit is here, in the channels that decided it —
                // rendered by the one function `/v1`'s neighbours use. A
                // blended score alone cannot say whether the drawer SAID the
                // word, holds a word built on it, or merely embedded near it,
                // so a surprising hit was reproducible on `/v1` and nowhere
                // else. See `search::evidence`.
                println!("   {}", search::evidence(hit));
            }
            // A full page may have more below it; say exactly how to continue,
            // clock included. A short page means the ranking is exhausted and
            // says nothing.
            if hits.len() == *limit {
                let echo = ranked_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default();
                println!(
                    "— deeper results may exist: repeat with --offset {} --ranked-at {echo}",
                    offset + hits.len()
                );
            }
        }
        Command::WakeUp { vault, wing } => {
            let dir = data_dir(&cli);
            let identity_path = dir.join("identity.txt");
            println!("## L0 — IDENTITY");
            match std::fs::read_to_string(&identity_path) {
                Ok(text) => println!("{}", text.trim()),
                Err(_) => println!("No identity configured. Create {}", identity_path.display()),
            }
            println!("\n## L1 — ESSENTIAL STORY (vault '{vault}')");
            let store = open_store(&cli, vault)?;
            let recent = store.recent(wing.as_deref(), 15)?;
            if recent.is_empty() {
                // "Empty" only when it IS empty. A declared trust floor above
                // `standard` with no wing yet assigned that class empties
                // this read entirely, and saying "empty" over an intact
                // corpus is a false statement the caller cannot see through.
                match store.trust_floor() {
                    Some(f) => println!(
                        "No drawers meet the declared trust floor '{f}' — the palace is NOT \
                         empty. Assign wing trust with `undercroft trust set`, or lower \
                         UNDERCROFT_TRUST_FLOOR."
                    ),
                    None => {
                        println!("Palace is empty. File memories with: undercroft remember / mine")
                    }
                }
            }
            for d in recent {
                println!(
                    "- [{}/{}] {}",
                    d.meta.wing,
                    d.meta.room,
                    first_line(&d.content, 120)
                );
            }
        }
        Command::Verify { vault } => {
            let store = open_store(&cli, vault)?;
            let report = store.verify()?;
            println!("records checked: {}", report.records_checked);
            println!("hmac failures:   {}", report.bad_records.len());
            for id in &report.bad_records {
                println!("  TAMPERED: {id}");
            }
            println!(
                "audit chain:     {}",
                if report.chain_ok { "ok" } else { "BROKEN" }
            );
            // The fourth leg: a graph label naming a record that is not
            // there. `record_id` is the one part of an audit row the chain
            // does not authenticate, so this is the only place a relabel
            // shows up.
            println!("orphan labels:   {}", report.orphan_labels.len());
            for l in &report.orphan_labels {
                println!("  ORPHANED: {l} — names no live record");
            }
            // A28: an indexed mirror that disagrees with the covered meta.
            // The record is intact; the COLUMN was edited offline.
            println!("mirror drift:    {}", report.mirror_drift.len());
            for m in &report.mirror_drift {
                println!("  MIRROR: {m}");
            }
            // Drawer supersession links are part of the vault's integrity
            // story: a receipted link that fails its HMAC is tampering,
            // reported with the same severity as a bad record. The leg now
            // rides inside the report (one walk, and `report.ok()` covers
            // it on every surface); this only renders it.
            let links = &report.supersessions;
            if !links.is_empty() {
                use undercroft_store::ReceiptVerdict as V;
                let count = |v: V| links.iter().filter(|l| l.verdict == v).count();
                println!(
                    "supersessions:   {} verified · {} source-changed · {} dangling · \
                     {} unreceipted · {} tampered",
                    count(V::Verified),
                    count(V::SourceChanged),
                    count(V::Dangling),
                    count(V::Unreceipted),
                    report.tampered_supersessions()
                );
                for l in links.iter().filter(|l| l.verdict == V::Tampered) {
                    println!("  TAMPERED LINK: {} → {}", l.drawer_id, l.supersedes);
                }
            }
            // The sixth leg, and the same story one level up: a fact's
            // receipt binds it to the verbatim drawer it was distilled
            // from, keyed, in columns no drawer HMAC covers. It rides
            // inside the report now — until it did, `VERIFY OK` printed
            // over a forged citation and `backup create` archived it.
            let receipts = &report.receipts;
            if !receipts.is_empty() {
                use undercroft_store::ReceiptVerdict as V;
                let count = |v: V| receipts.iter().filter(|r| r.verdict == v).count();
                println!(
                    "fact receipts:   {} verified · {} source-changed · {} dangling · \
                     {} unreceipted · {} tampered",
                    count(V::Verified),
                    count(V::SourceChanged),
                    count(V::Dangling),
                    count(V::Unreceipted),
                    report.tampered_receipts()
                );
                for r in receipts.iter().filter(|r| r.verdict == V::Tampered) {
                    println!(
                        "  TAMPERED RECEIPT: {} ← {}",
                        r.triple_id, r.source_drawer_id
                    );
                }
            }
            if report.ok() {
                println!("{}", tr("verify-ok"));
            } else {
                println!("{}", tr("verify-failed"));
                std::process::exit(EXIT_INTEGRITY.into());
            }
        }
        Command::Forget {
            ids,
            vault,
            out,
            sign,
            backend,
        } => {
            let mut store = open_store(&cli, vault)?;
            // Named backend: the remote delete goes first, so a failure
            // there leaves the vault intact and the operator can retry.
            // Unnamed: the attestation says so itself when this vault was
            // ever pushed — `VectorIndex::delete` was implemented by every
            // backend and called by nothing, so "destroyed" was being
            // attested over content still sitting on a third-party mirror.
            let mut att = match backend {
                Some(b) => {
                    let mut index = open_index(b)?;
                    store.forget_with_proof_mirrored(ids, index.as_mut())?
                }
                None => store.forget_with_proof(ids)?,
            };
            if let Some(note) = &att.mirror {
                eprintln!("warning: {note}");
            }
            if let Some(path) = sign {
                let secret = std::fs::read_to_string(path)
                    .with_context(|| format!("reading signing identity {}", path.display()))?;
                att.sign(&secret)?;
            }
            let json = serde_json::to_string_pretty(&att)?;
            match out {
                Some(path) => {
                    std::fs::write(path, &json)?;
                    println!(
                        "{} drawer(s) destroyed; attestation written to {} \
                         (verify with: undercroft verify-forgetting {})",
                        att.drawers.len(),
                        path.display(),
                        path.display()
                    );
                }
                None => println!("{json}"),
            }
        }
        Command::VerifyForgetting { file, vault } => {
            let store = open_store(&cli, vault)?;
            let raw = std::fs::read_to_string(file)
                .with_context(|| format!("reading {}", file.display()))?;
            let att: undercroft_store::ForgetAttestation = serde_json::from_str(&raw)
                .with_context(|| format!("{} is not an attestation", file.display()))?;
            // Exit 2 is this CLI's integrity verdict — the code `verify`
            // and `repair` already reserve for "tampering detected". A
            // forged signature or a tag that is not this vault's exited 1
            // here, the same code as "no such file", so a compliance
            // script that retries run errors retried a forged document
            // and ignored it. Only the attestation verdict takes exit 2;
            // an I/O or SQLite failure stays an ordinary error.
            let verdict = match store.verify_forget_attestation(&att) {
                Ok(v) => v,
                Err(undercroft_store::StoreError::Attestation(why)) => {
                    println!("ATTESTATION FAILED: {why}");
                    std::process::exit(EXIT_INTEGRITY.into());
                }
                Err(other) => return Err(other.into()),
            };
            // Attestation fields come from a caller-supplied JSON file;
            // byte-slicing them panics on a multi-byte boundary, and these
            // lines run while printing a verdict.
            let before: String = att.head_before.chars().take(12).collect();
            let after: String = att.head_after.chars().take(12).collect();
            // **Both fields, not `sig` alone.** This read `att.sig.is_some()`
            // and printed "sender signature verified" — a claim the code had
            // not established, because verification only ran when `sender`
            // was ALSO present, and `sender` is the public key the signature
            // is checked against. A document with it stripped was verified by
            // nothing and reported as verified. The store refuses that shape
            // now, so the two can no longer disagree; stating the condition
            // the message claims is what keeps it true if that ever moves.
            let signature = match (att.sender.as_deref(), att.sig.as_deref()) {
                (Some(who), Some(_)) => {
                    let who: String = who.chars().take(16).collect();
                    format!("; signature verified, sender {who}…")
                }
                _ => "; unsigned".to_string(),
            };
            match verdict {
                undercroft_store::AttestationVerdict::Verified => println!(
                    "ATTESTATION VERIFIED: {} drawer(s) destroyed between heads \
                     {before}… and {after}…, nothing else changed{signature}",
                    att.drawers.len()
                ),
                // **A third verdict, and it exits 0** (ROADMAP O13). It is
                // not a failure: the run succeeded and the evidence is real.
                // Exit 1 would tell a compliance script "retry", and no
                // retry will ever change this answer — the key that would
                // change it was destroyed on purpose. Exit 2 is the tamper
                // verdict and this is not tampering. The verdict WORD leads
                // the line, so a script matching on `ATTESTATION VERIFIED`
                // still tells the two apart.
                undercroft_store::AttestationVerdict::Recorded { rotations_since } => {
                    let rotations = match rotations_since {
                        0 => String::new(),
                        n => format!(
                            " This vault records {n} key rotation(s) after the \
                             attested interval."
                        ),
                    };
                    println!(
                        "ATTESTATION RECORDED (keyed replay unavailable): {} drawer(s) \
                         destroyed; this vault's audit trail holds exactly these \
                         tombstones, contiguously and in order, and the drawers are \
                         gone{signature}. The MAC key that made them is not this \
                         vault's current one — a key rotation destroys it by \
                         design.{rotations} NOT re-checked: that those bytes are \
                         genuine tags, and the recorded heads {before}…/{after}…, \
                         so \"nothing else changed\" narrows to \"nothing else \
                         happened between the first and last attested record\". \
                         Run `undercroft verify` to check the trail itself.",
                        att.drawers.len()
                    )
                }
            }
        }
        Command::Admission { action, vault } => {
            let mut store = open_store(&cli, vault)?;
            match action {
                AdmissionAction::List => {
                    let pending = store.admission_pending()?;
                    if pending.is_empty() {
                        println!("Nothing awaits review.");
                    }
                    for p in pending {
                        let codes: Vec<&str> = p.signals.iter().map(|s| s.code.as_str()).collect();
                        println!(
                            "  {}  → {}/{}  [{}]  filed {}",
                            p.id,
                            p.intended_wing,
                            p.intended_room,
                            codes.join(", "),
                            p.filed_at
                        );
                    }
                }
                AdmissionAction::Allow { id } => {
                    let restored = store.admission_allow(id)?;
                    println!("Allowed: re-filed as {restored} (ruling audited).");
                }
                AdmissionAction::Deny { id, out, sign } => {
                    let mut att = store.admission_deny(id)?;
                    if let Some(path) = sign {
                        let secret = std::fs::read_to_string(path).with_context(|| {
                            format!("reading signing identity {}", path.display())
                        })?;
                        att.sign(&secret)?;
                    }
                    let json = serde_json::to_string_pretty(&att)?;
                    match out {
                        Some(path) => {
                            std::fs::write(path, &json)?;
                            println!(
                                "Denied: content destroyed, ruling audited; attestation \
                                 written to {} (verify with: undercroft verify-forgetting {})",
                                path.display(),
                                path.display()
                            );
                        }
                        None => {
                            println!("Denied: content destroyed, ruling audited.");
                            println!("{json}");
                        }
                    }
                }
            }
        }
        Command::Retention { action, vault } => {
            let mut store = open_store(&cli, vault)?;
            match action {
                RetentionAction::Set { wing, room, days } => {
                    store.set_retention(wing, room.as_deref(), *days)?;
                    match room {
                        Some(r) => println!(
                            "Retention declared: {wing}/{r} keeps drawers {days} day(s) (audited)."
                        ),
                        None => println!(
                            "Retention declared: {wing} keeps drawers {days} day(s) (audited)."
                        ),
                    }
                }
                RetentionAction::Clear { wing, room } => {
                    store.clear_retention(wing, room.as_deref())?;
                    println!("Retention policy cleared (audited).");
                }
                RetentionAction::List => {
                    let rows = store.retention_policies()?;
                    if rows.is_empty() {
                        println!("No retention policies declared.");
                    }
                    for p in rows {
                        let scope = if p.room.is_empty() {
                            p.wing.clone()
                        } else {
                            format!("{}/{}", p.wing, p.room)
                        };
                        println!(
                            "  {scope}: {} day(s), declared {}",
                            p.max_age_days, p.assigned_at
                        );
                    }
                }
                RetentionAction::Sweep { dry_run, out, sign } => {
                    let mut sweep = store.retention_sweep(*dry_run)?;
                    if let (Some(path), Some(att)) = (sign, sweep.attestation.as_mut()) {
                        let secret = std::fs::read_to_string(path).with_context(|| {
                            format!("reading signing identity {}", path.display())
                        })?;
                        att.sign(&secret)?;
                    }
                    if sweep.dry_run {
                        println!("DRY RUN — nothing destroyed.");
                    }
                    for e in &sweep.policies {
                        let scope = if e.room.is_empty() {
                            e.wing.clone()
                        } else {
                            format!("{}/{}", e.wing, e.room)
                        };
                        println!(
                            "  {scope} (> {} day(s)): {} expired",
                            e.max_age_days,
                            e.expired.len()
                        );
                    }
                    println!("Destroyed: {} drawer(s).", sweep.destroyed);
                    let json = serde_json::to_string_pretty(&sweep)?;
                    match out {
                        Some(path) => {
                            std::fs::write(path, &json)?;
                            println!("Sweep report written to {}", path.display());
                        }
                        None if sweep.attestation.is_some() => println!("{json}"),
                        None => {}
                    }
                }
            }
        }
        Command::History {
            subject,
            limit,
            offset,
            vault,
        } => {
            let store = open_store(&cli, vault)?;
            let rows = store.history(
                undercroft_store::manage::HistoryScope::Operator,
                subject.as_deref(),
                *limit,
                *offset,
            )?;
            if rows.is_empty() {
                println!("No audit records match.");
            }
            for r in &rows {
                // The tag is the evidence and the label is navigation, so the
                // label leads and the tag is abbreviated — an operator
                // chasing a record reads the label; one verifying it reads
                // the full value off `/v1` or a forgetting attestation.
                println!(
                    "  #{:<6} {}  {:<40} {}…",
                    r.seq,
                    r.at,
                    r.record_id,
                    &r.tag[..16.min(r.tag.len())]
                );
            }
            println!("{} record(s).", rows.len());
        }
        Command::Trust { action, vault } => {
            let mut store = open_store(&cli, vault)?;
            match action {
                TrustAction::Set { wing, class } => {
                    store.set_wing_trust(wing, class)?;
                    println!("Wing '{wing}' assigned trust class '{class}' (audited).");
                }
                TrustAction::List => {
                    let rows = store.wing_trusts()?;
                    if rows.is_empty() {
                        println!("No wing carries an assignment — every wing reads as 'standard'.");
                    }
                    for (wing, class) in rows {
                        println!("  {wing:<24} {class}");
                    }
                }
            }
        }
        Command::Export {
            vault,
            to,
            out,
            sign,
            trust,
            expires,
        } => {
            let mut store = open_store(&cli, vault)?;
            let signing = sign
                .as_ref()
                .map(|p| {
                    std::fs::read_to_string(p)
                        .with_context(|| format!("reading signing identity {}", p.display()))
                })
                .transpose()?;
            let payload = build_export_payload(
                &store,
                signing.as_deref(),
                trust.as_deref(),
                expires.as_deref(),
            )?;
            // Every full-palace egress leaves a chain record binding the
            // export's own manifest digest — the audit trail and the
            // exported file corroborate each other.
            if let (Some(m), _) = undercroft_vault::bundle::split_payload(&payload)
                .map_err(|e| anyhow::anyhow!("{e}"))?
            {
                store.audit_export("cli", &m.counts, &m.payload_sha256, to.as_deref())?;
            }
            match to {
                Some(recipient) => {
                    let path = out
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("--to requires --out <file>"))?;
                    let sealed = undercroft_vault::bundle::encrypt_for(recipient, &payload)
                        .map_err(|e| anyhow::anyhow!("sealing bundle: {e}"))?;
                    std::fs::write(path, &sealed)?;
                    println!(
                        "Sealed bundle written to {} ({} drawers, {} bytes{}) — only the \
                         matching identity key can open it.",
                        path.display(),
                        store.count()?,
                        sealed.len(),
                        if signing.is_some() {
                            ", sender-signed"
                        } else {
                            ", unsigned"
                        }
                    );
                }
                None => {
                    let stdout = std::io::stdout();
                    let mut out = stdout.lock();
                    out.write_all(&payload)?;
                }
            }
        }
        Command::ServeMcp { vault, read_only } => {
            // The posture is STATED, exactly as `serve-http` states it — and
            // it reaches the open, not only the tool gate, so a read-only
            // stdio server does not migrate the embedder or append a
            // read-audit record per search.
            let store = open_store_as(
                &cli,
                vault,
                if *read_only {
                    Posture::ReadOnly
                } else {
                    Posture::ReadWrite
                },
            )?;
            if let Ok(n) = store.warm_embedding_cache() {
                undercroft_obs::diag_info!("warmed embedding cache: {n} vector(s)");
            }
            mcp::serve(store, *read_only)?;
        }
        Command::ServeHttp {
            host,
            port,
            vault,
            read_only,
        } => {
            // Both handles this process opens take the SAME posture. The
            // `/mcp` store used to be opened read-write regardless, so a
            // `--read-only` server migrated embeddings and audited reads on
            // the very vault the flag exists to protect.
            let posture = if *read_only {
                Posture::ReadOnly
            } else {
                Posture::ReadWrite
            };
            let store = open_store_as(&cli, vault, posture)?;
            if let Ok(n) = store.warm_embedding_cache() {
                undercroft_obs::diag_info!("warmed embedding cache: {n} vector(s)");
            }
            let mut tenancy = tenant::Tenancy::new(manager(&cli)?, embedder_factory(), *read_only)?
                // `/v1` must know which vault the `/mcp` handle above holds:
                // rotating or deleting it from under a second live handle is
                // the one thing two handles in one process cannot survive.
                .with_mcp_vault(vault.clone());
            if let Some(reranker) = reranker_factory()? {
                tenancy = tenancy.with_reranker(reranker);
            }
            http::serve_http(store, tenancy, host, *port, *read_only)?;
        }
        Command::AssertHeader { vault } => {
            // The SAME resolver the enforcing side runs. These were two
            // inline copies of one decision and they disagreed: this side
            // hard-errored on an empty value while `Tenancy::new` read it as
            // "assertions off" and let every bearer address every vault.
            let secret = undercroft_store::resolve_assertion_secret(
                std::env::var("UNDERCROFT_ASSERTION_SECRET").ok().as_deref(),
            )?
            .ok_or_else(|| anyhow::anyhow!("UNDERCROFT_ASSERTION_SECRET is not set"))?;
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            println!("{}", assertion::header_value(secret.as_bytes(), vault, now));
        }
        Command::Daemon { action } => match action {
            DaemonAction::Run {
                watch,
                interval,
                vault,
                wing,
                once,
            } => {
                undercroft_core::validate_name(wing, "wing")?;
                let watch_path = expand_home(watch);
                let mut store = open_store(&cli, vault)?;
                let _ = store.warm_embedding_cache();
                loop {
                    match sweep_path(&mut store, &watch_path, wing, false) {
                        Ok((files, filed, skipped)) => {
                            println!(
                                "[daemon] swept {files} transcript(s): {filed} filed, {skipped} present"
                            );
                        }
                        Err(e) => undercroft_obs::diag_error!("[daemon] sweep failed: {e}"),
                    }
                    if *once {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(*interval));
                }
            }
        },
        Command::Transcript { action } => match action {
            TranscriptAction::Render { file, max } => {
                let text = std::fs::read_to_string(file)
                    .with_context(|| format!("reading {}", file.display()))?;
                let messages = undercroft_core::convo::parse_transcript(&text);
                if messages.is_empty() {
                    bail!("no prose messages found in {}", file.display());
                }
                let shown = if *max == 0 {
                    messages.len()
                } else {
                    (*max).min(messages.len())
                };
                for msg in &messages[..shown] {
                    let who = if msg.role == "user" {
                        "User"
                    } else {
                        "Assistant"
                    };
                    println!("── {who} (line {}) ──", msg.line);
                    println!("{}\n", msg.text);
                }
                if shown < messages.len() {
                    println!("… {} more message(s)", messages.len() - shown);
                }
            }
        },
        Command::Import {
            file,
            vault,
            wing,
            identity,
            sender,
        } => {
            undercroft_core::validate_name(wing, "wing")?;
            let mut store = open_store(&cli, vault)?;
            let raw = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
            let text = if undercroft_vault::bundle::is_bundle(&raw) {
                let id_path = identity.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "{} is an encrypted bundle — pass --identity <keyfile> to open it",
                        file.display()
                    )
                })?;
                let secret = std::fs::read_to_string(id_path)
                    .with_context(|| format!("reading identity {}", id_path.display()))?;
                let plain = undercroft_vault::bundle::decrypt_with(&secret, &raw)
                    .map_err(|e| anyhow::anyhow!("opening bundle: {e}"))?;
                String::from_utf8(plain).context("bundle payload is not UTF-8 JSONL")?
            } else {
                String::from_utf8(raw)
                    .with_context(|| format!("{} is not UTF-8 text", file.display()))?
            };
            // The manifest, when the payload carries one: verified digest
            // always (split_payload refuses a mismatch), signature and
            // expiry per the flags. Absence is a recorded fact — a legacy
            // export imports as before, unattested and said so.
            let (manifest, record_bytes) = undercroft_vault::bundle::split_payload(text.as_bytes())
                .map_err(|e| anyhow::anyhow!("bundle manifest: {e}"))?;
            let text = String::from_utf8(record_bytes.to_vec())
                .context("bundle records are not UTF-8 JSONL")?;
            // The attestation decision is `BundleManifest::attest`, the same
            // call `/v1` makes (ROADMAP C5). This surface used to make its
            // own, and it had no `else`: with no `--sender` it printed
            // `signed-by=<16 hex> (unverified — pass --sender to enforce)`
            // and imported. The digest is checked unconditionally, so an
            // attacker swapping a signed bundle's payload had to break the
            // signature but could keep the trusted sender's key — and this
            // command then printed that sender's prefix above attacker
            // content. Provenance-display laundering, on the surface every
            // operator backup restore uses.
            if let Some(m) = &manifest {
                let now = time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)?;
                if m.expired_at(&now) {
                    bail!(
                        "bundle expired at {} — the sender bounded its validity, refusing",
                        m.expires.as_deref().unwrap_or("(unparseable expiry)")
                    );
                }
            }
            let attested = undercroft_vault::bundle::BundleManifest::attest(
                manifest.as_ref(),
                sender.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("manifest attestation failed: {e}"))?;
            if let Some(m) = &manifest {
                println!(
                    "manifest: vault={} level={} created={}{}{}{}",
                    m.vault,
                    m.level,
                    m.created_at,
                    m.trust
                        .as_deref()
                        .map(|t| format!(" trust={t} (sender's claim, not a boundary)"))
                        .unwrap_or_default(),
                    match attested.verified_sender() {
                        // Char-wise, never `&s[..16]`: this string is
                        // attacker-authored, and byte-slicing it panicked
                        // (exit 101) before any write.
                        Some(s) => format!(
                            " signed-by={} (verified){}",
                            s.chars().take(16).collect::<String>(),
                            if sender.is_some() {
                                ""
                            } else {
                                " — the signature checks out; pass --sender to pin WHO"
                            }
                        ),
                        None => " unsigned".to_string(),
                    },
                    m.embedder
                        .as_deref()
                        .map(|e| format!(" embedder={e}"))
                        .unwrap_or_default(),
                );
            }
            let mut skipped = 0usize;
            let mut kg_facts = 0usize;
            let mut kg_entities = 0usize;
            let mut tunnels = 0usize;
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut batch: Vec<Drawer> = Vec::new();
            let mut kg_batch: Vec<undercroft_store::TripleExport> = Vec::new();
            let mut entity_batch: Vec<(String, String)> = Vec::new();
            let mut tunnel_batch: Vec<(String, String, String)> = Vec::new();
            for (lineno, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let v: serde_json::Value = serde_json::from_str(line)
                    .with_context(|| format!("line {} is not valid JSON", lineno + 1))?;
                // Typed records (the manifest-era format). KG and tunnel
                // rows import through their own re-seal/re-key paths.
                if let Some(t) = v.get("triple") {
                    kg_batch.push(
                        serde_json::from_value(t.clone())
                            .with_context(|| format!("line {}: bad triple record", lineno + 1))?,
                    );
                    continue;
                }
                if let Some(e) = v.get("entity") {
                    let name = e.get("name").and_then(serde_json::Value::as_str);
                    let etype = e
                        .get("etype")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    if let Some(name) = name {
                        entity_batch.push((name.to_string(), etype.to_string()));
                    }
                    continue;
                }
                if let Some(t) = v.get("tunnel") {
                    let g = |k: &str| {
                        t.get(k)
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string)
                    };
                    if let (Some(f), Some(to_w), Some(l)) =
                        (g("from_wing"), g("to_wing"), g("label"))
                    {
                        tunnel_batch.push((f, to_w, l));
                    }
                    continue;
                }
                let v = match v.get("drawer") {
                    Some(d) => d.clone(),
                    None => v,
                };
                let drawer = if v.get("meta").is_some() {
                    // Native undercroft export: full Drawer JSON — including
                    // a `meta.added_by` this payload wrote itself. Re-stamped
                    // with the importing surface, because that field is the
                    // key the admission screen's trusted-source auto-admit
                    // rides and it is only sound while a caller cannot set
                    // it (see `PalaceStore::import_stamp`); a bundle
                    // claiming `added_by: "cli"` otherwise walks past the
                    // screen on any vault that declares `cli` trusted.
                    let d = serde_json::from_value::<Drawer>(v)
                        .with_context(|| format!("line {}: not a undercroft drawer", lineno + 1))?;
                    undercroft_store::PalaceStore::import_stamp(
                        &d,
                        undercroft_store::IMPORT_SURFACE,
                    )
                } else if let Some(doc) = v.get("document").and_then(serde_json::Value::as_str) {
                    // MemPalace export shape: { id?, document, metadata:{wing,room,...} }.
                    let meta = v.get("metadata").cloned().unwrap_or_default();
                    let g = |k: &str| {
                        meta.get(k)
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string)
                    };
                    Drawer::new(
                        &g("wing").unwrap_or_else(|| wing.clone()),
                        &g("room").unwrap_or_else(|| "imported".into()),
                        normalize_content(doc),
                        g("source_file"),
                        meta.get("chunk_index")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(0) as u32,
                        undercroft_store::IMPORT_SURFACE,
                    )
                    // Carried across an import rather than reset to the
                    // import's own date: a mempalace export records when the
                    // content happened, and losing it here would strand every
                    // relative date in the text.
                    .with_content_date(g("content_date"))
                } else {
                    bail!(
                        "line {}: unrecognized record (expected undercroft export with 'meta' \
                         or mempalace export with 'document'/'metadata')",
                        lineno + 1
                    );
                };
                if seen.contains(&drawer.content)
                    || store.check_duplicate(&drawer.content)?.is_some()
                {
                    skipped += 1;
                    continue;
                }
                seen.insert(drawer.content.clone());
                batch.push(drawer);
            }
            let imported = batch.len();
            let bulk = upsert_batched(&mut store, &batch)?;
            // KG and tunnel records go after drawers so receipts can bind
            // against drawers arriving in the same payload.
            for (name, etype) in &entity_batch {
                store.kg_import_entity(name, etype)?;
                kg_entities += 1;
            }
            for exp in &kg_batch {
                store.kg_import(exp)?;
                kg_facts += 1;
            }
            for (f, t, l) in &tunnel_batch {
                store.create_tunnel(f, t, l)?;
                tunnels += 1;
            }
            println!(
                "{}",
                fill(
                    tr("imported-summary"),
                    &[
                        ("n", imported.to_string()),
                        ("vault", vault.clone()),
                        ("skipped", skipped.to_string()),
                    ]
                )
            );
            report_quarantined(bulk.quarantined);
            if kg_facts + kg_entities + tunnels > 0 {
                println!(
                    "knowledge graph: {kg_facts} fact(s) (receipts re-keyed), \
                     {kg_entities} entit(y/ies), {tunnels} tunnel(s)"
                );
            }
        }
        Command::Kg { action, vault } => {
            let mut store = open_store(&cli, vault)?;
            match action {
                KgAction::Add {
                    subject,
                    predicate,
                    object,
                    from,
                    to,
                    confidence,
                } => {
                    let id = store.kg_add(
                        subject,
                        predicate,
                        object,
                        from.as_deref(),
                        to.as_deref(),
                        *confidence,
                        None,
                    )?;
                    println!("Added fact {id}: {subject} --{predicate}--> {object}");
                }
                KgAction::Query {
                    entity,
                    as_of,
                    direction,
                } => {
                    let facts = store.kg_query_entity(entity, as_of.as_deref(), direction)?;
                    print_triples(&facts);
                }
                KgAction::Rel { predicate, as_of } => {
                    let facts = store.kg_query_relationship(predicate, as_of.as_deref())?;
                    print_triples(&facts);
                }
                KgAction::Invalidate {
                    subject,
                    predicate,
                    object,
                    ended,
                } => {
                    let n = store.kg_invalidate(
                        subject,
                        predicate,
                        object.as_deref(),
                        ended.as_deref(),
                    )?;
                    println!("Invalidated {n} fact(s)");
                }
                KgAction::Supersede {
                    subject,
                    predicate,
                    new_object,
                    at,
                } => {
                    let id = store.kg_supersede(subject, predicate, new_object, at.as_deref())?;
                    println!("Superseded: {subject} --{predicate}--> {new_object} ({id})");
                }
                KgAction::Timeline { entity } => {
                    let facts = store.kg_timeline(entity.as_deref())?;
                    print_triples(&facts);
                }
                KgAction::Stats => {
                    let st = store.kg_stats()?;
                    println!(
                        "entities: {}  triples: {}  active: {}  closed: {}",
                        st.entities, st.triples, st.active, st.closed
                    );
                }
                KgAction::Receipts { problems_only } => {
                    use undercroft_store::ReceiptVerdict;
                    let receipts = store.kg_verify_receipts()?;
                    if receipts.is_empty() {
                        println!("No facts carry a receipt yet (run `refine` to distill some).");
                    }
                    let mut counts = [0usize; 5];
                    let mut shown = 0usize;
                    for r in &receipts {
                        let (label, idx) = match r.verdict {
                            ReceiptVerdict::Verified => ("verified", 0),
                            ReceiptVerdict::SourceChanged => ("source-changed", 1),
                            ReceiptVerdict::Dangling => ("dangling", 2),
                            ReceiptVerdict::Tampered => ("TAMPERED", 3),
                            // Reachable for a FACT since U12: a fact can
                            // cite a drawer without a binding — a plain
                            // `kg_add` with a source id, or an import whose
                            // payload did not carry the cited drawer, since
                            // a keyed fingerprint cannot travel. This used
                            // to say "drawer supersessions only".
                            ReceiptVerdict::Unreceipted => ("unreceipted", 4),
                        };
                        counts[idx] += 1;
                        let ok = matches!(r.verdict, ReceiptVerdict::Verified);
                        if !(*problems_only && ok) {
                            println!("  [{label}] {} ← {}", r.triple_id, r.source_drawer_id);
                            shown += 1;
                        }
                    }
                    if *problems_only && shown == 0 {
                        println!("All {} receipt(s) verified.", receipts.len());
                    }
                    // `unreceipted` is printed, not merely counted: the
                    // bucket was written and never read, so a fact citing a
                    // drawer it has no binding for was tallied into a number
                    // no surface showed. It became reachable with U12.
                    println!(
                        "receipts: {} verified · {} source-changed · {} dangling · \
                         {} unreceipted · {} tampered",
                        counts[0], counts[1], counts[2], counts[4], counts[3]
                    );
                    // A tampered receipt is a hard integrity failure, and it
                    // exits 2 — the code `verify`, `repair`, `backup create`
                    // and `verify-forgetting` all reserve for "tampering
                    // detected". `bail!` exits 1, which this CLI's own
                    // documented doctrine gives to bad arguments and
                    // ordinary run errors, so a compliance script that
                    // retries a 1 retried a forged citation and then moved
                    // on. Exactly the defect `verify-forgetting` records
                    // fixing in its own arm, on the same class of artifact.
                    if counts[3] > 0 {
                        println!(
                            "{} fact receipt(s) failed integrity — vault tampering",
                            counts[3]
                        );
                        std::process::exit(EXIT_INTEGRITY.into());
                    }
                }
                KgAction::Authority {
                    triple_id,
                    class,
                    review,
                    key,
                } => {
                    store.kg_set_authority(triple_id, class, review, key.as_deref())?;
                    println!(
                        "Fact {triple_id}: authority_class={class} review_state={review}{}",
                        key.as_deref()
                            .map(|k| format!(" canonical_key={k}"))
                            .unwrap_or_default()
                    );
                }
                KgAction::Canonical { key } => match store.lookup_canonical(key)? {
                    Some(t) => {
                        println!("{} --{}--> {}", t.subject, t.predicate, t.object);
                        println!(
                            "id: {}  key: {}  since: {}",
                            t.id,
                            t.canonical_key.as_deref().unwrap_or("-"),
                            t.valid_from.as_deref().unwrap_or("-")
                        );
                    }
                    None => println!("No approved canonical fact holds key {key:?}."),
                },
            }
        }
        Command::Drawer { action, vault } => {
            let mut store = open_store(&cli, vault)?;
            match action {
                DrawerAction::Get { id } => match store.get(id)? {
                    Some(d) => {
                        println!("id:     {}", d.id);
                        println!("wing:   {}/{}", d.meta.wing, d.meta.room);
                        println!("filed:  {}", d.meta.filed_at);
                        if let Some(src) = &d.meta.source_file {
                            println!("source: {src}");
                        }
                        println!("---\n{}", d.content);
                    }
                    None => {
                        println!("No drawer with id {id}");
                        std::process::exit(EXIT_FAILURE.into());
                    }
                },
                DrawerAction::List {
                    wing,
                    room,
                    limit,
                    offset,
                } => {
                    let rows =
                        store.list_drawers(wing.as_deref(), room.as_deref(), *limit, *offset)?;
                    if rows.is_empty() {
                        println!("No drawers.");
                    }
                    for d in rows {
                        // `source_file` reached `/v1` and MCP (both
                        // serialize the struct whole) and not this line —
                        // so the operator surface could not tell a mined
                        // drawer from an API save, which is the one field
                        // that says where a memory came from. Rendered as
                        // a suffix so the existing column layout is
                        // unchanged for a drawer that has none.
                        let src = d
                            .source_file
                            .as_deref()
                            .map(|f| format!("  <- {f}"))
                            .unwrap_or_default();
                        println!(
                            "{}  {}/{}  {}  {}{src}",
                            d.id,
                            d.wing,
                            d.room,
                            d.filed_at,
                            first_line(&d.preview, 60)
                        );
                    }
                }
                DrawerAction::Update { id, content } => {
                    match store.update_drawer(id, content, "cli")? {
                        undercroft_store::UpdateOutcome::Updated => println!("Updated drawer {id}"),
                        undercroft_store::UpdateOutcome::Quarantined => println!(
                            "Update to {id} quarantined pending review — the drawer \
                             keeps its previous content (see `undercroft admission list`)."
                        ),
                        undercroft_store::UpdateOutcome::NotFound => {
                            bail!("no drawer with id {id}")
                        }
                    }
                }
                DrawerAction::Delete { id } => {
                    if store.delete_drawer(id)? {
                        println!("Deleted drawer {id}");
                    } else {
                        bail!("no drawer with id {id}");
                    }
                }
                DrawerAction::DeleteBySource { source } => {
                    let n = store.delete_by_source(source)?;
                    println!("Deleted {n} drawer(s) from {source}");
                }
                DrawerAction::CheckDup { content } => {
                    match store.check_duplicate(&normalize_content(content))? {
                        Some(id) => println!("duplicate of {id}"),
                        None => println!("not filed"),
                    }
                }
            }
        }
        Command::Diary { action, vault } => {
            let mut store = open_store(&cli, vault)?;
            match action {
                DiaryAction::Write { agent, entry } => {
                    // Screened like every other save: a diverted entry must
                    // not be reported as written for the agent, because
                    // `diary read` will not find it.
                    let out = store.diary_write(agent, entry, "cli")?;
                    if out.quarantined {
                        println!(
                            "Quarantined pending review: the entry tripped the admission \
                             screen and is NOT readable in agent '{agent}'s diary. \
                             Review with `undercroft admission list`."
                        );
                    } else {
                        println!("Diary entry {} written for agent '{agent}'", out.id);
                    }
                }
                DiaryAction::Read { agent, limit } => {
                    let entries = store.diary_read(agent, *limit)?;
                    if entries.is_empty() {
                        println!("No diary entries for agent '{agent}'.");
                    }
                    for e in entries {
                        println!("[{}] {}", e.meta.filed_at, e.content);
                    }
                }
                DiaryAction::Agents => {
                    for a in store.list_agents()? {
                        println!("{a}");
                    }
                }
            }
        }
        Command::Tunnel { action, vault } => {
            let mut store = open_store(&cli, vault)?;
            match action {
                TunnelAction::Create { from, to, label } => {
                    let id = store.create_tunnel(from, to, label)?;
                    println!("Tunnel {id}: {from} <-> {to} ({label})");
                }
                TunnelAction::List { wing } => {
                    let tunnels = store.list_tunnels(wing.as_deref())?;
                    if tunnels.is_empty() {
                        println!("No tunnels.");
                    }
                    for t in tunnels {
                        println!("{}  {} <-> {}  ({})", t.id, t.from_wing, t.to_wing, t.label);
                    }
                }
                TunnelAction::Follow { id, limit } => {
                    let drawers = store.follow_tunnel(id, *limit)?;
                    for d in drawers {
                        println!(
                            "- [{}/{}] {}",
                            d.meta.wing,
                            d.meta.room,
                            first_line(&d.content, 100)
                        );
                    }
                }
                TunnelAction::Delete { id } => {
                    if store.delete_tunnel(id)? {
                        println!("Deleted tunnel {id}");
                    } else {
                        bail!("no tunnel with id {id}");
                    }
                }
                TunnelAction::Traverse { start, depth } => {
                    for (wing, d) in store.traverse(start, *depth)? {
                        println!("{}{}", "  ".repeat(d), wing);
                    }
                }
            }
        }
        Command::Closets { wing, vault } => {
            let store = open_store(&cli, vault)?;
            let lines = store.closet_index(wing.as_deref())?;
            if lines.is_empty() {
                println!("Palace is empty — nothing to index.");
            }
            for line in lines {
                println!("{line}");
            }
        }
        Command::Refine {
            vault,
            wing,
            room,
            fact_room,
            limit,
            dry_run,
        } => {
            let llm = undercroft_llm::LlmClient::from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
            undercroft_core::validate_name(fact_room, "fact_room")?;
            let mut store = open_store(&cli, vault)?;
            // One implementation, shared with `POST /v1/vaults/{id}/refine`
            // (crate::refine): the same UNDERCROFT_LLM_* configuration used to
            // build two different vaults from this command depending on which
            // surface ran it — no validity window, no `Support` verdict
            // (which means "no check was run", not "unsupported"), no date
            // resolved from the note's own words, no searchable mirror, and a
            // second extractor call per drawer whose answer was counted and
            // thrown away. That was fixed once and a merge took it back; the
            // gate against a third round is `refine.rs`'s
            // `distillation_has_exactly_one_implementation`.
            //
            // The quarantine refusal lives inside `refine::refine` too, so it
            // cannot go missing here the way it did. One ordering note: the
            // LLM client is built first, so an operator with no
            // UNDERCROFT_LLM_URL is told that before being told the wing is
            // refused. Nothing is read either way.
            let opts = refine::RefineOptions {
                wing: wing.as_deref(),
                room: room.as_deref(),
                fact_room,
                limit: if *limit == 0 { 100_000 } else { *limit },
                dry_run: *dry_run,
            };
            let rep = refine::refine(&mut store, &llm, &opts)?;
            if rep.sources == 0 {
                bail!("no drawers to refine");
            }
            println!("Refined {} drawer(s) with {} …", rep.sources, llm.model());
            for (s, p, o) in &rep.preview {
                println!("  would add: {s} --{p}--> {o}");
            }
            println!(
                "Refinement {}: {} fact(s) into the knowledge graph",
                if *dry_run { "dry run" } else { "complete" },
                rep.facts
            );
            if !*dry_run {
                // The same counts /v1 answers with, because it is the same
                // run. `stated` vs background is which facts the notes' own
                // words support; `dated_from_text` is how often the extractor
                // pointed at a real span instead of the note's date. Both are
                // how you tell a working extractor from one that is inventing.
                println!(
                    "  mirrored into room '{}' · {} stated / {} background",
                    fact_room,
                    rep.stated,
                    rep.facts.saturating_sub(rep.stated)
                );
                println!(
                    "  {} dated from the text · {} duplicate(s), {} skipped, {} failed",
                    rep.dated_from_text, rep.duplicates, rep.skipped, rep.failed
                );
                // The line above claims the mirrors are in `fact_room`. When
                // the screen diverted some, they are not — the fact is in the
                // graph, the mirror is not retrievable, and saying nothing
                // makes the previous line false.
                if rep.quarantined > 0 {
                    println!(
                        "  {} of these mirrors tripped the admission screen and are NOT \
                         retrievable in '{}' — the facts are in the graph, the drawers are \
                         in review. See `undercroft admission list`.",
                        rep.quarantined, fact_room
                    );
                }
            }
        }
        Command::Hallways { wing, top, vault } => {
            let store = open_store(&cli, vault)?;
            let halls = store.hallways(wing, *top)?;
            if halls.is_empty() {
                println!(
                    "No hallways in wing '{wing}' (need entities co-occurring in 2+ drawers)."
                );
            }
            for h in halls {
                println!(
                    "{} <-> {}  (strength {})",
                    h.entity_a, h.entity_b, h.strength
                );
            }
        }
        Command::Stats { vault } => {
            let store = open_store(&cli, vault)?;
            let st = store.stats()?;
            println!("vault:   {} (level: {})", store.vault().id(), st.level);
            println!("records: {}", st.records);
            println!("rooms:   {}", st.rooms);
            println!("tunnels: {}", st.tunnels);
            println!(
                "kg:      {} triples ({} active)",
                st.kg.triples, st.kg.active
            );
            println!("writes:  {}", st.writes);
            // The committed audit-chain head. `/v1` and MCP have always
            // carried it and the CLI silently did not — the hand-projection
            // drift, on the struct CLAUDE.md names as the first one it bit.
            // It is what an operator compares against a receipt or a
            // colleague's copy, so a surface that omits it is the surface
            // that cannot answer "are we looking at the same chain?".
            println!("chain:   {}", st.chain_head);
            println!("db size: {} bytes", st.db_bytes);
            // The posture this handle was opened under. Silence here read as
            // "writable" on a replica.
            if st.read_only {
                println!("posture: read-only");
            }
            // Trained index artifacts, but only the ones that exist: a
            // generation of 0 means this vault never trained that codebook,
            // and listing five zeroes on every default vault would bury the
            // one line that matters — a generation that moved.
            let trained: Vec<String> = st
                .codebooks
                .iter()
                .filter(|(_, gen)| *gen > 0)
                .map(|(a, gen)| format!("{a} gen {gen}"))
                .collect();
            if !trained.is_empty() {
                println!("codebooks: {}", trained.join(", "));
            }
            // R4: a read-only open detects instead of healing, and this is
            // where it says what it left. **No longer empty by construction on
            // a writable open**: since 2026-08-06 a writable open also reports
            // knowledge-graph rows the A10 migration could not move, because
            // their own HMAC does not verify and migrating one would launder a
            // tampered row. That exposure is a state to READ, not a warning
            // someone had to be watching stderr to catch.
            for note in &st.unhealed {
                println!("unhealed: {note}");
            }
            println!("wings:");
            for (w, n) in st.wings {
                println!("  {w:<24} {n}");
            }
        }
        Command::Taxonomy { vault } => {
            let store = open_store(&cli, vault)?;
            for (wing, rooms) in store.taxonomy()? {
                println!("{wing}/");
                for (room, n) in rooms {
                    println!("  {room} ({n})");
                }
            }
        }
        Command::Dedup { vault, apply } => {
            let mut store = open_store(&cli, vault)?;
            let report = store.dedup(*apply)?;
            println!(
                "{} duplicate group(s), {} extra drawer(s) {}",
                report.duplicate_groups,
                report.removed.len(),
                if report.applied {
                    "removed"
                } else {
                    "found (use --apply to remove)"
                }
            );
            // `dates_kept` is, in its own doc comment, "the difference
            // between collapsing text and losing history" — the survivor
            // absorbs the duplicates' occurrence dates before they are
            // deleted. MCP has always shown it (it serializes the report
            // whole) and the CLI silently did not.
            if report.dates_kept > 0 {
                println!(
                    "{} occurrence date(s) absorbed into the surviving drawer(s)",
                    report.dates_kept
                );
            }
            if report.quarantined > 0 {
                println!(
                    "{} group(s) LEFT INTACT — the surviving drawer's rewrite tripped the \
                     admission screen, so nothing was deleted and no dates were absorbed \
                     for them. Review with `undercroft admission list`.",
                    report.quarantined
                );
            }
        }
        Command::Repair { vault, tokens } => {
            let mut store = open_store(&cli, vault)?;
            if *tokens {
                let mut done = 0u64;
                loop {
                    let (encoded, remaining) = store.late_backfill(64)?;
                    done += encoded;
                    println!("token matrices encoded: {done} (remaining: {remaining})");
                    if remaining == 0 || encoded == 0 {
                        break;
                    }
                }
                return Ok(());
            }
            let (report, backfilled) = store.repair()?;
            println!("fingerprints backfilled: {backfilled}");
            println!("records checked: {}", report.records_checked);
            println!(
                "integrity: {}",
                if report.ok() {
                    "ok"
                } else {
                    "FAILED — see verify"
                }
            );
            if !report.ok() {
                std::process::exit(EXIT_INTEGRITY.into());
            }
        }
        Command::Backup { action } => {
            let root = data_dir(&cli);
            match action {
                BackupAction::Create { vault } => {
                    // Verify before snapshotting — never archive a bad palace.
                    // The refusal is an integrity verdict, so it exits 2
                    // like `verify` and `repair` rather than 1: a script
                    // that treats 1 as "retry the run" must not retry a
                    // vault that failed its HMACs.
                    let store = open_store(&cli, vault)?;
                    if !store.verify()?.ok() {
                        println!(
                            "refusing to back up vault '{vault}': integrity verification \
                             failed (run `undercroft verify --vault {vault}` for the detail)"
                        );
                        std::process::exit(EXIT_INTEGRITY.into());
                    }
                    drop(store);
                    let stamp = time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)?
                        .replace([':', '.'], "-");
                    let src = root.join("vaults").join(vault);
                    let dst = root.join("backups").join(format!("{vault}-{stamp}"));
                    copy_dir(&src, &dst)?;
                    prune_backups(&root.join("backups"), vault, 10)?;
                    println!("Backup created: {}", dst.display());
                }
                BackupAction::List => {
                    let dir = root.join("backups");
                    let mut names: Vec<String> = match std::fs::read_dir(&dir) {
                        Ok(rd) => rd
                            .filter_map(|e| e.ok())
                            .map(|e| e.file_name().to_string_lossy().to_string())
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    names.sort();
                    if names.is_empty() {
                        println!("No backups.");
                    }
                    for n in names {
                        println!("{n}");
                    }
                }
                BackupAction::Restore { name, force } => {
                    let src = root.join("backups").join(name);
                    if !src.join("vault.json").exists() {
                        bail!("no backup named {name}");
                    }
                    let vault_name = name.rsplitn(2, "-20").last().unwrap_or(name).to_string();
                    let dst = root.join("vaults").join(&vault_name);
                    if dst.exists() && !force {
                        bail!(
                            "vault '{vault_name}' exists; pass --force to overwrite it with the backup"
                        );
                    }
                    if dst.exists() {
                        std::fs::remove_dir_all(&dst)?;
                    }
                    copy_dir(&src, &dst)?;
                    println!("Restored {} -> vault '{}'", name, vault_name);
                }
            }
        }
        Command::Index { action, vault } => {
            // Mutable because `index_push` now chain-records its own egress
            // — a whole-corpus mirror to a third party is exactly the event
            // an audit trail is for, and it was the one export path leaving
            // no record.
            let mut store = open_store(&cli, vault)?;
            match action {
                IndexAction::Push {
                    backend,
                    allow_plaintext,
                } => {
                    let mut index = open_index(backend)?;
                    let plaintext = if *allow_plaintext {
                        undercroft_store::PlaintextPush::Allow
                    } else {
                        undercroft_store::PlaintextPush::Refuse
                    };
                    let n = store.index_push(index.as_mut(), plaintext)?;
                    // "sealed" only when it IS sealed. The old line said it
                    // unconditionally, over a push that had base64'd the
                    // plaintext column for an hmac-only vault (ROADMAP C8).
                    let kind = if store.vault().level() == undercroft_vault::SecurityLevel::Sealed {
                        "sealed"
                    } else {
                        "PLAINTEXT"
                    };
                    println!(
                        "Pushed {n} {kind} record(s) from vault '{vault}' to {backend} \
                         (collection {})",
                        store.index_collection()
                    );
                }
                IndexAction::Status { backend } => {
                    let mut index = open_index(backend)?;
                    let (name, count) = store.index_status(index.as_mut())?;
                    println!("backend:    {name}");
                    println!("collection: {}", store.index_collection());
                    println!("records:    {count}");
                    println!("local:      {}", store.count()?);
                }
            }
        }
        // **Both spellings, ONE implementation.** `config check` is what every
        // doc publishes and `config-check` is what has always run; binding
        // them to the same arm is the point, because two arms would be two
        // places for the verdict to drift — the defect class this tree spends
        // its time closing.
        Command::Config {
            action: ConfigAction::Check { verbose },
        }
        | Command::ConfigCheck { verbose } => {
            println!("Checking every UNDERCROFT_* declaration in this environment.");
            println!(
                "Nothing is opened: no vault, no database, no socket, no outbound call.
"
            );
            let (fatal, warned, validated, accepted) = config_check::run(*verbose);
            if validated + accepted == 0 {
                println!("  (no UNDERCROFT_* variables are declared here)");
            }
            println!();
            println!(
                "{validated} declaration(s) validated against the resolver that runs at start-up."
            );
            println!("{accepted} more are declared with no parse to run — this command has NOT");
            println!("checked those: a path, a URL, a token or a model name is validated by the");
            println!("thing that consumes it, and claiming otherwise would be a stronger");
            println!("statement than the truth.");
            println!("{fatal} would REFUSE to start. {warned} would warn and keep the default.");
            if fatal > 0 {
                // Exit 1, deliberately, and not the integrity code: a
                // configuration that will not start is a run failure, not a
                // verdict about stored evidence.
                bail!("this environment would not start");
            }
            println!("This environment starts.");
        }
        Command::Hooks { client } => match client.as_str() {
            "claude-code" => {
                println!("{}", claude_code_hooks_json());
            }
            other => bail!("unknown client {other:?} (supported: claude-code)"),
        },
    }
    Ok(())
}

fn print_triples(facts: &[undercroft_store::Triple]) {
    if facts.is_empty() {
        println!("No facts.");
    }
    for t in facts {
        let window = match (&t.valid_from, &t.valid_to) {
            (Some(f), Some(u)) => format!(" [{f} .. {u}]"),
            (Some(f), None) => format!(" [{f} ..]"),
            (None, Some(u)) => format!(" [.. {u}]"),
            (None, None) => String::new(),
        };
        println!("{} --{}--> {}{}", t.subject, t.predicate, t.object, window);
    }
}

fn mine_files(
    store: &mut undercroft_store::PalaceStore,
    path: &Path,
    wing: &str,
) -> Result<(usize, usize)> {
    let files = collect_files(path)?;
    if files.is_empty() {
        bail!("no minable text files under {}", path.display());
    }
    let mut drawers = 0usize;
    let mut screened = 0usize;
    let mut batch: Vec<Drawer> = Vec::new();
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        // Scripts and config normalize in Code mode: indentation is
        // semantics and a trailing space is a real diff, so mining a source
        // tree must not quietly reformat it.
        let normalized =
            undercroft_core::normalize::normalize_content_mode(&text, mode_for_path(file));
        let room = room_for_file(file);
        for (idx, chunk) in chunk_text(&normalized, ChunkOptions::default())
            .into_iter()
            .enumerate()
        {
            batch.push(Drawer::new(
                wing,
                &room,
                chunk,
                Some(file.display().to_string()),
                idx as u32,
                "miner",
            ));
            drawers += 1;
            if batch.len() >= INGEST_BATCH {
                screened += upsert_batched(store, &batch)?.quarantined;
                batch.clear();
            }
        }
    }
    screened += upsert_batched(store, &batch)?.quarantined;
    report_quarantined(screened);
    Ok((files.len(), drawers))
}

fn mine_convos(
    store: &mut undercroft_store::PalaceStore,
    path: &Path,
    wing: &str,
) -> Result<(usize, usize)> {
    let files = collect_transcripts(path)?;
    if files.is_empty() {
        bail!("no .jsonl transcripts under {}", path.display());
    }
    let mut drawers = 0usize;
    let mut screened = 0usize;
    let mut batch: Vec<Drawer> = Vec::new();
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        let messages = undercroft_core::convo::parse_transcript(&text);
        if messages.is_empty() {
            continue;
        }
        let room = room_for_file(file);
        for (idx, (chunk, started_at)) in
            undercroft_core::convo::chunk_exchanges_dated(&messages, 800)
                .into_iter()
                .enumerate()
        {
            batch.push(
                Drawer::new(
                    wing,
                    &room,
                    normalize_content(&chunk),
                    Some(file.display().to_string()),
                    idx as u32,
                    "convo-miner",
                )
                // When the exchange opened — read off the transcript, not
                // inferred, and the anchor for relative dates inside it.
                .with_content_date(started_at),
            );
            drawers += 1;
            if batch.len() >= INGEST_BATCH {
                screened += upsert_batched(store, &batch)?.quarantined;
                batch.clear();
            }
        }
    }
    screened += upsert_batched(store, &batch)?.quarantined;
    report_quarantined(screened);
    Ok((files.len(), drawers))
}

/// Sweep every transcript under `path`: one drawer per prose message,
/// idempotent via keyed content fingerprints. Returns (files, filed,
/// skipped). With `require_files`, an empty directory is an error (CLI
/// sweep); the daemon treats it as a quiet pass.
fn sweep_path(
    store: &mut undercroft_store::PalaceStore,
    path: &Path,
    wing: &str,
    require_files: bool,
) -> Result<(usize, usize, usize)> {
    let files = collect_transcripts(path)?;
    if files.is_empty() {
        if require_files {
            bail!("no .jsonl transcripts under {}", path.display());
        }
        return Ok((0, 0, 0));
    }
    let mut filed = 0usize;
    let mut skipped = 0usize;
    let mut screened = 0usize;
    let mut batch: Vec<Drawer> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        let room = room_for_file(file);
        for msg in undercroft_core::convo::parse_transcript(&text) {
            // Attribute by named speaker where the transcript has one, so a
            // multi-party conversation does not collapse to two roles.
            let content = format!("{}: {}", undercroft_core::convo::label(&msg), msg.text);
            let normalized = normalize_content(&content);
            // One drawer per message, keyed by (file, line) — re-sweeps
            // are no-ops for already-filed messages. The in-batch set
            // covers duplicates not yet flushed to the store.
            if seen.contains(&normalized) || store.check_duplicate(&normalized)?.is_some() {
                skipped += 1;
                continue;
            }
            seen.insert(normalized.clone());
            batch.push(
                Drawer::new(
                    wing,
                    &room,
                    normalized,
                    Some(file.display().to_string()),
                    msg.line,
                    "sweeper",
                )
                // The turn's own timestamp, when the transcript records one:
                // it is when the exchange happened, which is what anchors
                // "yesterday" in the text.
                .with_content_date(msg.timestamp.clone()),
            );
            filed += 1;
            if batch.len() >= INGEST_BATCH {
                screened += upsert_batched(store, &batch)?.quarantined;
                batch.clear();
            }
        }
    }
    screened += upsert_batched(store, &batch)?.quarantined;
    report_quarantined(screened);
    Ok((files.len(), filed, skipped))
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        // Same lookup as the default palace: `~/` meant nothing on native
        // Windows for the same reason, and a watch path that silently stayed
        // literal (`./~/notes`) is the same class of quiet wrong answer.
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn room_for_file(file: &Path) -> String {
    file.file_stem()
        .map(|s| undercroft_core::normalize_wing_name(&s.to_string_lossy()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unsorted".into())
}

fn collect_transcripts(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        bail!("{} does not exist", path.display());
    }
    let mut out = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let p = entry?.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().map(|e| e == "jsonl").unwrap_or(false) {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

fn prune_backups(dir: &Path, vault: &str, keep: usize) -> Result<()> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with(&format!("{vault}-")))
        .collect();
    names.sort();
    while names.len() > keep {
        let victim = names.remove(0);
        std::fs::remove_dir_all(dir.join(victim))?;
    }
    Ok(())
}

fn claude_code_hooks_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "hooks": {
            "Stop": [ {
                "hooks": [ {
                    "type": "command",
                    "command": "undercroft sweep ~/.claude/projects --wing claude-code"
                } ]
            } ],
            "PreCompact": [ {
                "hooks": [ {
                    "type": "command",
                    "command": "undercroft sweep ~/.claude/projects --wing claude-code"
                } ]
            } ]
        }
    }))
    .expect("static json serializes")
}

fn first_line(text: &str, max: usize) -> String {
    let line = text.lines().next().unwrap_or("");
    let mut s: String = line.chars().take(max).collect();
    if line.chars().count() > max {
        s.push('…');
    }
    s
}

/// One-line result preview centered on the first query-term match, so the
/// evidence for the hit is visible even when it sits deep in the chunk.
fn snippet(content: &str, query: &str, max: usize) -> String {
    let flat: String = content.split_whitespace().collect::<Vec<_>>().join(" ");
    let lower = flat.to_lowercase();
    let hit = query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 1)
        .filter_map(|t| lower.find(t))
        .min();
    match hit {
        None | Some(0) => first_line(&flat, max),
        Some(pos) => {
            // `pos` is a byte offset into the LOWERCASED copy, and lowercasing
            // is not length-preserving: `İ` (2 bytes) folds to `i` + U+0307 (3),
            // Turkish `I` to `ı` (1 → 2). So past any such character the offset
            // runs ahead of `flat` and can land mid-character or past the end —
            // `flat[start..pos]` then panics with "byte index is not a char
            // boundary" on an ordinary `undercroft search` over ordinary stored
            // text. Same class as the attacker-authored bundle sender that
            // panicked `import`; this one needs no attacker.
            //
            // Clamp and walk back to a boundary rather than rebuilding the fold
            // with an offset map: `str::to_lowercase` is contextual (Greek final
            // sigma) and a per-character map would quietly change what matches.
            // The residual is stated: when a fold did change length the preview
            // window opens a character or two early. It is a 100-character
            // preview of text the id line leads to verbatim — a display cost,
            // where the alternative was exit 101.
            let mut pos = pos.min(flat.len());
            while !flat.is_char_boundary(pos) {
                pos -= 1;
            }
            if pos == 0 {
                return first_line(&flat, max);
            }
            // Back up to a word boundary a bit before the match.
            let mut start = pos.saturating_sub(max / 3);
            while !flat.is_char_boundary(start) {
                start -= 1;
            }
            if let Some(space) = flat[start..pos].find(' ') {
                start += space + 1;
            }
            let tail: String = flat[start..].chars().take(max).collect();
            let mut s = String::new();
            if start > 0 {
                s.push('…');
            }
            s.push_str(tail.trim_end());
            if flat[start..].chars().count() > max {
                s.push('…');
            }
            s
        }
    }
}

const MINABLE_EXTENSIONS: &[&str] = &["md", "txt", "markdown", "rst", "org", "log", "jsonl"];

fn collect_files(path: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if path.is_file() {
        out.push(path.to_path_buf());
        return Ok(out);
    }
    if !path.is_dir() {
        bail!("{} does not exist", path.display());
    }
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let p = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
            } else if p
                .extension()
                .map(|e| MINABLE_EXTENSIONS.contains(&e.to_string_lossy().as_ref()))
                .unwrap_or(false)
            {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use tempfile::TempDir;

    /// **Every advertised subcommand carries its OWN help text, and the
    /// documented two-word `config check` runs.**
    ///
    /// Two defects in one clap block, both invisible to every other gate in
    /// this tree. `ConfigCheck` was inserted BETWEEN `Hooks`'s doc comment
    /// and `Hooks`, so clap attached that comment to the wrong variant:
    /// `config-check --help` opened with "Print auto-save hook settings for
    /// an agent client" and `hooks` had no help at all. Nothing could see it
    /// — clap does not care which variant a comment lands on, rustfmt does
    /// not reformat doc comments, and no test reads help strings.
    ///
    /// And `undercroft config check` — the spelling in `UPGRADING.md`'s
    /// pre-upgrade command, the release flow, the README, `docs/AGENTS.md`
    /// and the architecture page — did not exist, because clap derives
    /// `config-check` from the variant name. The command an operator is told
    /// to run before every upgrade returned a usage error.
    ///
    /// Driven through clap's own rendered help, not through the source: a
    /// gate that re-read the doc comments would agree with them by
    /// construction and could not see which variant they attach to.
    #[test]
    fn every_subcommand_has_its_own_about_and_config_check_runs() {
        use clap::CommandFactory;
        let cmd = Cli::command();

        // Both spellings parse. `config check` is the documented one; the
        // hyphenated form stays because it is what has always worked.
        assert!(
            Cli::try_parse_from(["undercroft", "config", "check"]).is_ok(),
            "`undercroft config check` is the spelling every doc publishes \
             and it must run"
        );
        assert!(
            Cli::try_parse_from(["undercroft", "config-check"]).is_ok(),
            "the hyphenated spelling has always worked and must keep working"
        );

        // No two subcommands may share an `about`, and none may be missing
        // one — a stolen doc comment produces exactly those two symptoms at
        // once, on the pair either side of the insertion.
        let mut seen: std::collections::HashMap<String, String> = Default::default();
        for sub in cmd.get_subcommands() {
            let name = sub.get_name().to_string();
            let about = sub
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default()
                .trim()
                .to_string();
            assert!(
                !about.is_empty(),
                "subcommand `{name}` advertises no help text — the usual cause \
                 is a variant inserted between a doc comment and the variant it \
                 documented, which leaves this one bare and the other one wearing \
                 two"
            );
            if let Some(other) = seen.insert(about.clone(), name.clone()) {
                panic!(
                    "`{name}` and `{other}` advertise the SAME help text {about:?} — \
                     one of them has taken the other's doc comment"
                );
            }
        }
        // Premise: the walk actually examined the surface. An empty or tiny
        // subcommand list would satisfy every assertion above.
        assert!(
            cmd.get_subcommands().count() > 30,
            "premise: this gate must have walked the real command surface, \
             found {}",
            cmd.get_subcommands().count()
        );
    }

    /// The default palace must resolve on a machine that sets `USERPROFILE`
    /// and not `HOME` — i.e. on native Windows, which is a target the
    /// release publishes a binary for.
    ///
    /// Driven through [`home_dir_from`] rather than the environment: a test
    /// that called `set_var` would race every other test in this binary, and
    /// the failure it introduces is intermittent and blamed elsewhere.
    ///
    /// Four arms, because only the second one fails before the fix and a
    /// single-arm test would also pass if the order were inverted — which
    /// would break every Unix host instead.
    #[test]
    fn the_home_directory_falls_back_to_userprofile() {
        let one = |want: &'static str, value: &'static str| {
            move |k: &str| (k == want).then(|| OsString::from(value))
        };

        // Both set: `HOME` wins. Git Bash and WSL set both, and taking
        // `USERPROFILE` there would move an existing palace.
        assert_eq!(
            home_dir_from(|k| match k {
                "HOME" => Some(OsString::from("/home/a")),
                "USERPROFILE" => Some(OsString::from("C:\\Users\\a")),
                _ => None,
            }),
            Some(PathBuf::from("/home/a"))
        );
        // `USERPROFILE` only — the native Windows case, and the one that
        // resolved to `"."` before this fix.
        assert_eq!(
            home_dir_from(one("USERPROFILE", "C:\\Users\\a")),
            Some(PathBuf::from("C:\\Users\\a"))
        );
        // An empty `HOME` is not a home directory; the fallback still runs.
        assert_eq!(
            home_dir_from(|k| match k {
                "HOME" => Some(OsString::new()),
                "USERPROFILE" => Some(OsString::from("C:\\Users\\a")),
                _ => None,
            }),
            Some(PathBuf::from("C:\\Users\\a"))
        );
        // Neither: the caller decides. `data_dir` keeps its historical `"."`,
        // so this fix changes no behaviour where `HOME` is set.
        assert_eq!(home_dir_from(|_| None), None);
    }

    /// **An integrity verdict on a READ path exited 1**, the code
    /// docs/AGENTS.md reserves for "the run failed, retry it".
    ///
    /// `verify`, `repair`, `backup create` and `verify-forgetting` each call
    /// `process::exit(2)` themselves, so the doctrine looked implemented and
    /// ROADMAP A22 was filed closed. But a rolled-back or offline-edited
    /// palace is detected in `open_store`, before any of those commands does
    /// its own checking — and every command that merely READS it (`search`,
    /// `stats`, `recent`, `drawer get` …) bubbled that verdict out through
    /// `?` and exited 1, indistinguishable from "no such vault". A compliance
    /// script that retries exit 1 retried tampering forever.
    ///
    /// This drives `run` — the whole dispatch every subcommand goes through —
    /// over a real palace on disk, not a hand-built error, and it asserts
    /// BOTH directions: the verdict must be 2, and an ordinary run failure
    /// must stay 1, or a classifier that answered 2 for everything would pass.
    #[test]
    fn an_integrity_verdict_exits_2_where_an_ordinary_failure_stays_1() {
        let home = TempDir::new().unwrap();
        let mgr = VaultManager::open(home.path(), None).unwrap();
        mgr.create("acme", SecurityLevel::Sealed).unwrap();
        let root = home.path().to_str().unwrap().to_string();
        let argv = |args: &[&str]| {
            let mut v = vec!["undercroft", "--data-dir", root.as_str()];
            v.extend_from_slice(args);
            Cli::try_parse_from(v).unwrap()
        };

        // Premise: the palace reads clean, so what fails below is the
        // tampering and not the fixture.
        run(argv(&["search", "anything", "--vault", "acme"])).unwrap();

        // Premise, the other way: a run failure the operator can fix by
        // fixing the command. Exit 1, and it must stay 1.
        let e = run(argv(&["search", "x", "--vault", "nope"])).unwrap_err();
        assert!(
            !integrity_verdict(&e),
            "a missing vault is not a tamper verdict: {e:?}"
        );

        // Edit the manifest offline. `level` is covered by the manifest MAC,
        // so this is exactly the downgrade the MAC exists to catch.
        let mpath = home.path().join("vaults/acme/vault.json");
        let text = std::fs::read_to_string(&mpath)
            .unwrap()
            .replace("sealed", "hmac-only");
        std::fs::write(&mpath, text).unwrap();

        // Was exit 1 — the same code as the missing vault two lines up.
        let e = run(argv(&["search", "anything", "--vault", "acme"])).unwrap_err();
        assert!(integrity_verdict(&e), "search on a tampered palace: {e:?}");
        // A second command, because this is a property of the palace and not
        // of `search`: one command classifying correctly is how the four
        // `process::exit(2)` call sites made the gap invisible.
        let e = run(argv(&["stats", "--vault", "acme"])).unwrap_err();
        assert!(integrity_verdict(&e), "stats on a tampered palace: {e:?}");
    }

    /// The classes are the ones `/v1` answers 409 for, and no others.
    ///
    /// Stated as its own test because the *set* is the decision: widen it and
    /// exit 2 stops meaning "tampering"; narrow it and a verdict goes back to
    /// looking retryable. Both directions asserted.
    ///
    /// **Renamed 2026-08-10 to what it actually proves.** It was
    /// `…_are_exactly_the_ones_v1_answers_409_for`, which was wrong twice:
    /// `/v1` answers 409 for `ReadOnlyUnmigrated` too, which is deliberately
    /// NOT a verdict, and nothing here read `/v1`'s side at all — both sets
    /// were hand-written literals in different files. It also omitted
    /// `DatabaseMissing`, so it could not have failed if either surface
    /// dropped the newest member of the set. The cross-surface equality now
    /// lives in `tenant::tests::the_cli_exit_2_set_and_v1s_integrity_class_are_one_set`,
    /// which calls both classifiers; what stays here is this surface's own
    /// membership plus the context-walking behaviour that has no analogue on
    /// the other side.
    #[test]
    fn the_integrity_verdict_set_is_pinned_on_this_surface() {
        use undercroft_store::StoreError as S;
        use undercroft_vault::VaultError as V;
        for e in [
            anyhow::Error::from(S::Integrity("record".into())),
            anyhow::Error::from(S::Attestation("forged signature".into())),
            anyhow::Error::from(S::Vault(V::ManifestTampered)),
            anyhow::Error::from(S::Vault(V::CorruptManifest("truncated".into()))),
            anyhow::Error::from(V::ManifestTampered),
            anyhow::Error::from(V::CorruptManifest("truncated".into())),
            // The member the old list did not have.
            anyhow::Error::from(S::DatabaseMissing {
                id: "acme".into(),
                path: "/vaults/acme/palace.db".into(),
            }),
        ] {
            assert!(integrity_verdict(&e), "must be a verdict: {e:?}");
        }
        for e in [
            anyhow::Error::from(V::NotFound("acme".into())),
            anyhow::Error::from(S::Invalid("unknown kind".into())),
            anyhow::Error::from(S::NotFound("drawer".into())),
            anyhow::Error::from(V::Io(std::io::Error::other("disk"))),
            // 409 on `/v1`, and deliberately not a verdict: the vault is
            // intact and the posture is wrong for it. The pair above and
            // below is the whole reason the set is not the 409 set.
            anyhow::Error::from(S::ReadOnlyUnmigrated {
                missing: "kg_triples.terms".into(),
            }),
            anyhow::anyhow!("plain failure"),
        ] {
            assert!(!integrity_verdict(&e), "must stay exit 1: {e:?}");
        }
        // Context layers are what `open_store`'s callers add, and the anyhow
        // head is then the context string. Walking only the head would have
        // classed this as an ordinary failure.
        let wrapped = anyhow::Error::from(V::ManifestTampered)
            .context("opening palace at /tmp/x")
            .context("undercroft search");
        assert!(integrity_verdict(&wrapped), "{wrapped:?}");
    }

    /// A search preview never panics on text whose lowercase is longer than
    /// itself.
    ///
    /// `snippet` located the query inside a lowercased COPY and then sliced the
    /// ORIGINAL with that offset. Lowercasing is not length-preserving — `İ`
    /// (2 bytes) folds to `i`+U+0307 (3), Turkish `I` (1) to `ı` (2) — so past
    /// one of those the offset runs ahead of the original, and it then lands
    /// either mid-character or past the end. Both are a panic: exit 101 out of
    /// an ordinary `undercroft search`, over stored text nobody had to craft.
    /// Same class as the attacker-authored bundle sender that panicked
    /// `import`, with no attacker in it.
    ///
    /// Every non-ASCII row here panicked before the clamp; the ASCII rows are
    /// the premise, proving the window still opens where it always did.
    #[test]
    fn a_snippet_survives_text_whose_lowercase_is_longer_than_itself() {
        // Five `İ` push the offset five bytes on, landing inside the 3-byte
        // `本` that follows the match. Before: "byte index is not a char
        // boundary".
        let mid = "İİİİİ abc 日本語テキスト tail";
        assert!(
            snippet(mid, "abc", 100).contains("abc"),
            "the window must still open on the match"
        );

        // Turkish dotless-i, the other growing fold, same shape.
        let turkish = "IIIIIIII kod 日本語テキスト son";
        assert!(snippet(turkish, "kod", 100).contains("kod"));

        // A match at the very end: the drifted offset exceeds the original's
        // length outright, which was a slice-out-of-range rather than a
        // boundary panic.
        assert!(snippet("İİİİİİİİ tail", "tail", 100).contains("tail"));

        // Premise: the ordinary ASCII paths are unchanged.
        assert_eq!(
            snippet("alpha beta gamma", "alpha", 100),
            "alpha beta gamma"
        );
        let long = "one two three four five six seven eight nine ten eleven twelve";
        let windowed = snippet(long, "twelve", 20);
        assert!(
            windowed.starts_with('…') && windowed.contains("twelve"),
            "a deep match is still windowed with an ellipsis: {windowed}"
        );
    }
}
