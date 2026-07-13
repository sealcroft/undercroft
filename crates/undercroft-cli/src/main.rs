//! `undercroft` — hardened, local-first AI memory.
//!
//! Rust conversion of MemPalace with a security-first management layer:
//! memories live in isolated vaults with per-vault derived keys, AEAD
//! encryption, and HMAC integrity verification.

mod mcp;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use std::path::{Path, PathBuf};

use undercroft_core::{chunk_text, normalize_content, ChunkOptions, Drawer, MAX_CONTENT_BYTES};
use undercroft_store::{PalaceStore, SearchOptions};
use undercroft_vault::{SecurityLevel, VaultManager};

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
    },
    /// Mine a directory of text files into the palace
    Mine {
        /// Directory (or single file) to mine
        path: PathBuf,
        #[arg(long, default_value = "default")]
        vault: String,
        #[arg(long, default_value = "mined")]
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
    /// Export all memories as decrypted JSONL (backup / migration)
    Export {
        #[arg(long, default_value = "default")]
        vault: String,
    },
    /// Serve the MCP stdio server (tools: save, search, wake_up, verify)
    ServeMcp {
        #[arg(long, default_value = "default")]
        vault: String,
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
}

fn data_dir(cli: &Cli) -> PathBuf {
    cli.data_dir.clone().unwrap_or_else(|| {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| ".".into());
        home.join(".undercroft")
    })
}

fn passphrase() -> Option<String> {
    std::env::var("UNDERCROFT_PASSPHRASE").ok().filter(|p| !p.is_empty())
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
    Ok(PalaceStore::open(v)?)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Init { level } => {
            let mgr = manager(&cli)?;
            if mgr.exists("default") {
                println!("Palace already initialized at {}", mgr.root().display());
            } else {
                mgr.create("default", (*level).into())?;
                println!("Palace initialized at {}", mgr.root().display());
                println!("Created vault 'default' (level: {})", SecurityLevel::from(*level));
                if passphrase().is_some() {
                    println!("Master key: derived from UNDERCROFT_PASSPHRASE (Argon2id)");
                } else {
                    println!("Master key: {}/master.key (0600)", mgr.root().display());
                }
            }
        }
        Command::Vault { action } => match action {
            VaultAction::Create { name, level } => {
                let mgr = manager(&cli)?;
                let v = mgr.create(name, (*level).into())?;
                println!("Created vault '{}' (level: {})", v.id(), v.level());
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
        },
        Command::Remember { content, vault, wing, room } => {
            if content.len() > MAX_CONTENT_BYTES {
                bail!("content too large ({} bytes, max {})", content.len(), MAX_CONTENT_BYTES);
            }
            undercroft_core::validate_name(wing, "wing")?;
            undercroft_core::validate_name(room, "room")?;
            let mut store = open_store(&cli, vault)?;
            let normalized = normalize_content(content);
            if normalized.is_empty() {
                bail!("nothing to remember: content is empty after normalization");
            }
            let count_before = store.count()?;
            let drawer = Drawer::new(wing, room, normalized, None, count_before as u32, "cli");
            store.upsert(&drawer)?;
            println!("Filed drawer {} in {}/{} (vault '{}')", drawer.id, wing, room, vault);
        }
        Command::Mine { path, vault, wing } => {
            undercroft_core::validate_name(wing, "wing")?;
            let mut store = open_store(&cli, vault)?;
            let files = collect_files(path)?;
            if files.is_empty() {
                bail!("no minable text files under {}", path.display());
            }
            let mut drawers = 0usize;
            for file in &files {
                let Ok(text) = std::fs::read_to_string(file) else { continue };
                let normalized = normalize_content(&text);
                let room = file
                    .file_stem()
                    .map(|s| undercroft_core::normalize_wing_name(&s.to_string_lossy()))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "unsorted".into());
                for (idx, chunk) in
                    chunk_text(&normalized, ChunkOptions::default()).into_iter().enumerate()
                {
                    let drawer = Drawer::new(
                        wing,
                        &room,
                        chunk,
                        Some(file.display().to_string()),
                        idx as u32,
                        "miner",
                    );
                    store.upsert(&drawer)?;
                    drawers += 1;
                }
            }
            println!(
                "Mined {} file(s) into vault '{}' wing '{}': {} drawer(s) filed",
                files.len(),
                vault,
                wing,
                drawers
            );
        }
        Command::Search { query, vault, wing, room, limit } => {
            let store = open_store(&cli, vault)?;
            let hits = store.search(
                query,
                &SearchOptions { wing: wing.clone(), room: room.clone(), limit: *limit },
            )?;
            if hits.is_empty() {
                println!("No memories matched.");
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
                Err(_) => println!(
                    "No identity configured. Create {}",
                    identity_path.display()
                ),
            }
            println!("\n## L1 — ESSENTIAL STORY (vault '{vault}')");
            let store = open_store(&cli, vault)?;
            let recent = store.recent(wing.as_deref(), 15)?;
            if recent.is_empty() {
                println!("Palace is empty. File memories with: undercroft remember / mine");
            }
            for d in recent {
                println!("- [{}/{}] {}", d.meta.wing, d.meta.room, first_line(&d.content, 120));
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
            println!("audit chain:     {}", if report.chain_ok { "ok" } else { "BROKEN" });
            if report.ok() {
                println!("VERIFY OK");
            } else {
                println!("VERIFY FAILED");
                std::process::exit(2);
            }
        }
        Command::Export { vault } => {
            let store = open_store(&cli, vault)?;
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for drawer in store.export_all()? {
                serde_json::to_writer(&mut out, &drawer)?;
                out.write_all(b"\n")?;
            }
        }
        Command::ServeMcp { vault } => {
            let store = open_store(&cli, vault)?;
            mcp::serve(store)?;
        }
    }
    Ok(())
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
    let flat: String = content
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
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
