//! `undercroft` — hardened, local-first AI memory.
//!
//! Rust conversion of MemPalace with a security-first management layer:
//! memories live in isolated vaults with per-vault derived keys, AEAD
//! encryption, and HMAC integrity verification.

mod assertion;
mod http;
mod i18n;
mod mcp;
mod tenant;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use std::path::{Path, PathBuf};

use i18n::{fill, tr};
use undercroft_core::normalize::mode_for_path;
use undercroft_core::{chunk_text, normalize_content, ChunkOptions, Drawer, MAX_CONTENT_BYTES};
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
        /// Max results
        #[arg(short = 'n', long, default_value_t = 5)]
        limit: usize,
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
    /// Export all memories as decrypted JSONL (backup / migration). With
    /// --to, the export is sealed to a recipient's public key instead —
    /// the file never exists in plaintext (see `bundle keygen`).
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
        /// Expose recall without write access
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

/// Bulk-ingest batch size: bounds RAM (embeddings in flight) and how long
/// one transaction holds the write lock.
const INGEST_BATCH: usize = 256;

/// Flush drawers through the store's single-transaction bulk path in
/// bounded chunks. Returns how many were newly created.
fn upsert_batched(store: &mut undercroft_store::PalaceStore, drawers: &[Drawer]) -> Result<usize> {
    let mut created = 0;
    for chunk in drawers.chunks(INGEST_BATCH) {
        created += store.upsert_many(chunk)?;
    }
    Ok(created)
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

fn open_store(cli: &Cli, vault: &str) -> Result<PalaceStore> {
    let mgr = manager(cli)?;
    let v = mgr.unlock(vault)?;
    let mut store = match std::env::var("UNDERCROFT_EMBEDDER").as_deref() {
        Ok("onnx") => {
            #[cfg(feature = "onnx")]
            {
                let embedder = undercroft_embed_onnx::from_env()
                    .map_err(|e| anyhow::anyhow!("loading ONNX embedder: {e}"))?;
                PalaceStore::open_with_embedder(v, Box::new(embedder))?
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
                PalaceStore::open_with_embedder(v, Box::new(embedder))?
            }
            #[cfg(not(feature = "ort"))]
            bail!(
                "UNDERCROFT_EMBEDDER=ort requires a build with the 'ort' feature \
                 (cargo build -p undercroft-cli --features ort)"
            );
        }
        Ok("hash") | Ok("") | Err(_) => PalaceStore::open(v)?,
        Ok(other) => bail!("unknown UNDERCROFT_EMBEDDER {other:?} (expected: hash, onnx, ort)"),
    };
    attach_reranker(&mut store)?;
    attach_retrieval(&mut store)?;
    Ok(store)
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
                Ok("hash") | Ok("") | Err(_) => Ok(Box::new(undercroft_core::HashEmbedder)),
                Ok(other) => {
                    bail!("unknown UNDERCROFT_EMBEDDER {other:?} (expected: hash, onnx, ort)")
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
                    "  derived artifacts:   {} token, {} pq (+{} pages), {} fde, {} meta",
                    report.token_matrices,
                    report.pq_rows,
                    report.pq_pages,
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
        } => {
            if content.len() > MAX_CONTENT_BYTES {
                bail!(
                    "content too large ({} bytes, max {})",
                    content.len(),
                    MAX_CONTENT_BYTES
                );
            }
            undercroft_core::validate_name(wing, "wing")?;
            undercroft_core::validate_name(room, "room")?;
            let mut store = open_store(&cli, vault)?;
            let normalized = normalize_content(content);
            if normalized.is_empty() {
                bail!("nothing to remember: content is empty after normalization");
            }
            let count_before = store.count()?;
            let drawer = Drawer::new(wing, room, normalized, None, count_before as u32, "cli")
                .with_content_date(content_date.clone());
            store.upsert(&drawer)?;
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
            limit,
            backend,
        } => {
            let store = open_store(&cli, vault)?;
            let opts = SearchOptions {
                wing: wing.clone(),
                room: room.clone(),
                limit: *limit,
            };
            let hits = if backend == "local" {
                store.search(query, &opts)?
            } else {
                let mut index = open_index(backend)?;
                store.search_with_index(index.as_mut(), query, &opts)?
            };
            if hits.is_empty() {
                println!("{}", tr("no-matches"));
            }
            for (i, hit) in hits.iter().enumerate() {
                println!(
                    "{}. [{:.3}] {}/{} — {} ({})",
                    i + 1,
                    hit.score,
                    hit.drawer.meta.wing,
                    hit.drawer.meta.room,
                    snippet(&hit.drawer.content, query, 100),
                    hit.drawer.meta.filed_at
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
            if report.ok() {
                println!("{}", tr("verify-ok"));
            } else {
                println!("{}", tr("verify-failed"));
                std::process::exit(2);
            }
        }
        Command::Export { vault, to, out } => {
            let store = open_store(&cli, vault)?;
            match to {
                Some(recipient) => {
                    let path = out
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("--to requires --out <file>"))?;
                    let mut plain = Vec::new();
                    for drawer in store.export_all()? {
                        serde_json::to_writer(&mut plain, &drawer)?;
                        plain.push(b'\n');
                    }
                    let sealed = undercroft_vault::bundle::encrypt_for(recipient, &plain)
                        .map_err(|e| anyhow::anyhow!("sealing bundle: {e}"))?;
                    std::fs::write(path, &sealed)?;
                    println!(
                        "Sealed bundle written to {} ({} drawers, {} bytes) — only the \
                         matching identity key can open it.",
                        path.display(),
                        store.count()?,
                        sealed.len()
                    );
                }
                None => {
                    let stdout = std::io::stdout();
                    let mut out = stdout.lock();
                    for drawer in store.export_all()? {
                        serde_json::to_writer(&mut out, &drawer)?;
                        out.write_all(b"\n")?;
                    }
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
            let store = open_store(&cli, vault)?;
            if let Ok(n) = store.warm_embedding_cache() {
                undercroft_obs::diag_info!("warmed embedding cache: {n} vector(s)");
            }
            let mut tenancy = tenant::Tenancy::new(manager(&cli)?, embedder_factory(), *read_only);
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
            let mut skipped = 0usize;
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut batch: Vec<Drawer> = Vec::new();
            for (lineno, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let v: serde_json::Value = serde_json::from_str(line)
                    .with_context(|| format!("line {} is not valid JSON", lineno + 1))?;
                let drawer = if v.get("meta").is_some() {
                    // Native undercroft export: full Drawer JSON.
                    serde_json::from_value::<Drawer>(v)
                        .with_context(|| format!("line {}: not a undercroft drawer", lineno + 1))?
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
                        "import",
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
            upsert_batched(&mut store, &batch)?;
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
                    let mut counts = [0usize; 4];
                    let mut shown = 0usize;
                    for r in &receipts {
                        let (label, idx) = match r.verdict {
                            ReceiptVerdict::Verified => ("verified", 0),
                            ReceiptVerdict::SourceChanged => ("source-changed", 1),
                            ReceiptVerdict::Dangling => ("dangling", 2),
                            ReceiptVerdict::Tampered => ("TAMPERED", 3),
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
                    if store.update_drawer(id, content)? {
                        println!("Updated drawer {id}");
                    } else {
                        bail!("no drawer with id {id}");
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
                    let id = store.diary_write(agent, entry)?;
                    println!("Diary entry {id} written for agent '{agent}'");
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
                    let store = open_store(&cli, vault)?;
                    if !store.verify()?.ok() {
                        bail!("refusing to back up vault '{vault}': integrity verification failed");
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
                upsert_batched(store, &batch)?;
                batch.clear();
            }
        }
    }
    upsert_batched(store, &batch)?;
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
        for (idx, chunk) in undercroft_core::convo::chunk_exchanges(&messages, 800)
            .into_iter()
            .enumerate()
        {
            batch.push(Drawer::new(
                wing,
                &room,
                normalize_content(&chunk),
                Some(file.display().to_string()),
                idx as u32,
                "convo-miner",
            ));
            drawers += 1;
            if batch.len() >= INGEST_BATCH {
                upsert_batched(store, &batch)?;
                batch.clear();
            }
        }
    }
    upsert_batched(store, &batch)?;
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
    let mut batch: Vec<Drawer> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for file in &files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        let room = room_for_file(file);
        for msg in undercroft_core::convo::parse_transcript(&text) {
            let content = format!(
                "{}: {}",
                if msg.role == "user" {
                    "User"
                } else {
                    "Assistant"
                },
                msg.text
            );
            let normalized = normalize_content(&content);
            // One drawer per message, keyed by (file, line) — re-sweeps
            // are no-ops for already-filed messages. The in-batch set
            // covers duplicates not yet flushed to the store.
            if seen.contains(&normalized) || store.check_duplicate(&normalized)?.is_some() {
                skipped += 1;
                continue;
            }
            seen.insert(normalized.clone());
            batch.push(Drawer::new(
                wing,
                &room,
                normalized,
                Some(file.display().to_string()),
                msg.line,
                "sweeper",
            ));
            filed += 1;
            if batch.len() >= INGEST_BATCH {
                upsert_batched(store, &batch)?;
                batch.clear();
            }
        }
    }
    upsert_batched(store, &batch)?;
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
