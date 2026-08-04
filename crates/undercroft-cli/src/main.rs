//! `undercroft` — hardened, local-first AI memory.
//!
//! Rust conversion of MemPalace with a security-first management layer:
//! memories live in isolated vaults with per-vault derived keys, AEAD
//! encryption, and HMAC integrity verification.

mod assertion;
mod http;
mod i18n;
mod mcp;
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
    /// Print auto-save hook settings for an agent client
    Hooks {
        /// Client: claude-code
        #[arg(default_value = "claude-code")]
        client: String,
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
    /// process; upstream's start/stop/jobs machinery is replaced by them)
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
    /// Upload every drawer (sealed content + embedding) to a remote index
    Push {
        /// qdrant | chroma | pgvector
        backend: String,
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
    for chunk in drawers.chunks(INGEST_BATCH) {
        let out = store.upsert_many(chunk)?;
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

fn data_dir(cli: &Cli) -> PathBuf {
    cli.data_dir.clone().unwrap_or_else(|| {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| ".".into());
        home.join(".undercroft")
    })
}

fn passphrase() -> Option<String> {
    std::env::var("UNDERCROFT_PASSPHRASE")
        .ok()
        .filter(|p| !p.is_empty())
}

fn manager(cli: &Cli) -> Result<VaultManager> {
    let dir = data_dir(cli);
    let pw = passphrase();
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
    let v = mgr.unlock(vault)?;
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
            bail!("unknown UNDERCROFT_EMBEDDER {other:?} (expected: hash, http, onnx, ort)")
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

/// Select the candidate-generation strategy via `UNDERCROFT_RETRIEVAL`
/// (same contract as the bench harness). Unset ⇒ the default full scan with
/// the FTS prefilter. `pq` enables the on-disk PQ/IVF prefilter — plain
/// codes on hmac-only vaults, AEAD-sealed rows + a decrypt-once RAM cache
/// on sealed vaults.
fn attach_retrieval(store: &mut PalaceStore) -> Result<()> {
    match std::env::var("UNDERCROFT_RETRIEVAL").as_deref() {
        Ok("pq") => store.set_pq(true),
        Ok("fde") => store.set_fde(true),
        Ok("hnsw") => {
            #[cfg(feature = "hnsw")]
            store.set_hnsw(true);
            #[cfg(not(feature = "hnsw"))]
            bail!(
                "UNDERCROFT_RETRIEVAL=hnsw requires a build with the 'hnsw' feature \
                 (cargo build -p undercroft-cli --features hnsw)"
            );
        }
        Ok("") | Err(_) => {}
        Ok(other) => bail!("unknown UNDERCROFT_RETRIEVAL {other:?} (expected: pq, fde, hnsw)"),
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
                        Ok(Box::new(undercroft_embed_onnx::from_env().map_err(|e| {
                            anyhow::anyhow!("loading ONNX embedder: {e}")
                        })?))
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

fn main() -> Result<()> {
    // Telemetry is a no-op unless built with `--features telemetry`. The
    // guard flushes providers on any return path (including `?`).
    let _telemetry = undercroft_obs::init();
    let cli = Cli::parse();
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
                if passphrase().is_some() {
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
                let v = store.vault();
                println!("vault:      {}", v.id());
                println!("level:      {}", v.level());
                println!("records:    {}", store.count()?);
                println!("writes:     {}", v.writes());
                println!("chain head: {}", v.chain_head_hex());
                println!("db:         {}", v.db_path().display());
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
                println!("  new chain head:      {}", store.vault().chain_head_hex());
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
                println!("Palace is empty. File memories with: undercroft remember / mine");
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
            if report.ok() {
                println!("{}", tr("verify-ok"));
            } else {
                println!("{}", tr("verify-failed"));
                std::process::exit(2);
            }
        }
        Command::Forget {
            ids,
            vault,
            out,
            sign,
        } => {
            let mut store = open_store(&cli, vault)?;
            let mut att = store.forget_with_proof(ids)?;
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
            if let Err(e) = store.verify_forget_attestation(&att) {
                match e {
                    undercroft_store::StoreError::Attestation(why) => {
                        println!("ATTESTATION FAILED: {why}");
                        std::process::exit(2);
                    }
                    other => return Err(other.into()),
                }
            }
            println!(
                "ATTESTATION VERIFIED: {} drawer(s) destroyed between heads \
                 {}… and {}…, nothing else changed{}",
                att.drawers.len(),
                &att.head_before[..12.min(att.head_before.len())],
                &att.head_after[..12.min(att.head_after.len())],
                if att.sig.is_some() {
                    "; sender signature verified"
                } else {
                    "; unsigned"
                }
            );
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
        Command::ServeMcp { vault } => {
            let store = open_store(&cli, vault)?;
            if let Ok(n) = store.warm_embedding_cache() {
                undercroft_obs::diag_info!("warmed embedding cache: {n} vector(s)");
            }
            mcp::serve(store)?;
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
            let mut tenancy = tenant::Tenancy::new(manager(&cli)?, embedder_factory(), *read_only)
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
            let secret = std::env::var("UNDERCROFT_ASSERTION_SECRET")
                .ok()
                .filter(|s| !s.is_empty())
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
            match &manifest {
                Some(m) => {
                    let now = time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)?;
                    if m.expired_at(&now) {
                        bail!(
                            "bundle expired at {} — the sender bounded its validity, refusing",
                            m.expires.as_deref().unwrap_or("(unparseable expiry)")
                        );
                    }
                    if let Some(expected) = sender.as_deref() {
                        m.verify_against(expected).map_err(|e| {
                            anyhow::anyhow!(
                                "manifest attestation failed against the pinned sender: {e}"
                            )
                        })?;
                    }
                    println!(
                        "manifest: vault={} level={} created={}{}{}{}",
                        m.vault,
                        m.level,
                        m.created_at,
                        m.trust
                            .as_deref()
                            .map(|t| format!(" trust={t} (sender's claim, not a boundary)"))
                            .unwrap_or_default(),
                        match (&m.sender, &m.sig) {
                            (Some(s), Some(_)) => format!(
                                " signed-by={}{}",
                                &s[..16.min(s.len())],
                                if sender.is_some() {
                                    " (verified)"
                                } else {
                                    " (unverified — pass --sender to enforce)"
                                }
                            ),
                            _ => " unsigned".to_string(),
                        },
                        m.embedder
                            .as_deref()
                            .map(|e| format!(" embedder={e}"))
                            .unwrap_or_default(),
                    );
                }
                None if sender.is_some() => {
                    bail!("--sender was pinned but the payload carries no manifest to verify")
                }
                None => {}
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
                    undercroft_store::PalaceStore::import_stamp(&d, undercroft_store::IMPORT_SURFACE)
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
                            // Drawer supersessions only; a KG receipt is
                            // always written with its fact. Covered so the
                            // match stays exhaustive.
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
                    println!(
                        "receipts: {} verified · {} source-changed · {} dangling · {} tampered",
                        counts[0], counts[1], counts[2], counts[3]
                    );
                    // A tampered receipt is a hard integrity failure.
                    if counts[3] > 0 {
                        bail!(
                            "{} fact receipt(s) failed integrity — vault tampering",
                            counts[3]
                        );
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
                        std::process::exit(1);
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
                        println!(
                            "{}  {}/{}  {}  {}",
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
            limit,
            dry_run,
        } => {
            let llm = undercroft_llm::LlmClient::from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
            let mut store = open_store(&cli, vault)?;
            let drawers =
                store.recent(wing.as_deref(), if *limit == 0 { 100_000 } else { *limit })?;
            if drawers.is_empty() {
                bail!("no drawers to refine");
            }
            println!(
                "Refining {} drawer(s) with {} …",
                drawers.len(),
                llm.model()
            );
            let mut entities_added = 0usize;
            let mut facts_added = 0usize;
            for d in &drawers {
                match llm.extract_triples(&d.content) {
                    Ok(triples) => {
                        for t in triples {
                            if undercroft_core::validate_name(&t.subject, "subject").is_err()
                                || undercroft_core::validate_name(&t.predicate, "predicate").is_err()
                            {
                                continue;
                            }
                            if *dry_run {
                                println!(
                                    "  would add: {} --{}--> {}",
                                    t.subject, t.predicate, t.object
                                );
                            } else {
                                // Distilled facts carry a receipt: an
                                // HMAC-covered citation to the verbatim drawer
                                // they were derived from, checkable later via
                                // `undercroft kg receipts`.
                                store.kg_add_receipted(
                                    &t.subject.to_lowercase(),
                                    &t.predicate.to_lowercase(),
                                    &t.object,
                                    None,
                                    None,
                                    0.8, // model-extracted: below human-asserted confidence
                                    (&d.id, &d.content),
                                    Some(llm.model()),
                                )?;
                            }
                            facts_added += 1;
                        }
                    }
                    Err(e) => undercroft_obs::diag_error!("  triples failed for {}: {e}", d.id),
                }
                match llm.extract_entities(&d.content) {
                    Ok(ents) => entities_added += ents.len(),
                    Err(e) => undercroft_obs::diag_error!("  entities failed for {}: {e}", d.id),
                }
            }
            println!(
                "Refinement {}: {} fact(s) into the knowledge graph, {} entit(ies) seen",
                if *dry_run { "dry run" } else { "complete" },
                facts_added,
                entities_added
            );
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
            println!("db size: {} bytes", st.db_bytes);
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
                std::process::exit(2);
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
                        std::process::exit(2);
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
            let store = open_store(&cli, vault)?;
            match action {
                IndexAction::Push { backend } => {
                    let mut index = open_index(backend)?;
                    let n = store.index_push(index.as_mut())?;
                    println!(
                        "Pushed {n} sealed record(s) from vault '{vault}' to {backend} \
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
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
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
