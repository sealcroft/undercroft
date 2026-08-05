//! `undercroft-orchestrator` — the optional multi-tenant control plane.
//!
//! Routing, tenant→vault mapping, token minting, and migration for fleets
//! of Undercroft engine instances, exactly as designed in
//! docs/MULTI_TENANCY.md: a **separate tool** that talks to engines over
//! their documented `/v1` surface. The engine remains tree-blind and never
//! depends on this crate.
//!
//! Environment:
//! - `UNDERCROFT_ORCH_DB`     — state database path (default `orchestrator.db`)
//! - `UNDERCROFT_ORCH_KEY`    — 32-byte hex key sealing instance credentials
//!   and MAC-ing tenant tokens (generate one with `keygen`)
//! - `UNDERCROFT_ORCH_ADMIN_TOKEN` — bearer for the `/admin` plane (`serve`)
//! - `UNDERCROFT_ORCH_ADDR`   — listen address (default `127.0.0.1:8900`)

mod engine;
mod proxy;
mod state;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rand::RngCore;
use state::Orch;

#[derive(Parser)]
#[command(name = "undercroft-orchestrator", version, about)]
struct Cli {
    /// State database path
    #[arg(long, env = "UNDERCROFT_ORCH_DB", default_value = "orchestrator.db")]
    db: std::path::PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh orchestrator key (and a suggested admin token)
    Keygen,
    /// Serve the routing proxy + admin plane
    Serve {
        #[arg(long, env = "UNDERCROFT_ORCH_ADDR", default_value = "127.0.0.1:8900")]
        addr: String,
        /// Serve as a read replica: open the state database read-only and
        /// expose only the `/t/*` data plane (admin plane and console
        /// refuse — they live on the single writer). Point `--db` at the
        /// writer's file on a shared volume, or at a replicated snapshot.
        #[arg(long, default_value_t = false)]
        read_replica: bool,
    },
    /// Register (or update) an engine instance
    InstanceAdd {
        name: String,
        /// Engine base URL (its serve-http address)
        url: String,
        /// The engine's palace bearer (UNDERCROFT_MCP_HTTP_TOKEN)
        #[arg(long)]
        bearer: String,
        /// The engine's per-vault assertion secret (UNDERCROFT_ASSERTION_SECRET)
        #[arg(long)]
        assertion_secret: String,
    },
    /// List instances (with tenant counts and live health)
    InstanceList,
    /// Remove an instance (refused while tenants still map to it)
    InstanceRemove { name: String },
    /// Create a tenant: pick an instance, create its vault, mint its token
    TenantCreate {
        name: String,
        /// Placement override (default: least-loaded instance)
        #[arg(long)]
        instance: Option<String>,
        /// Vault security level for the tenant
        #[arg(long, default_value = "sealed")]
        level: String,
    },
    /// List tenants
    TenantList,
    /// Delete a tenant (engine vault + mapping)
    TenantDelete { id: String },
    /// Rotate a tenant's token (the old one dies immediately; the new one
    /// prints once)
    TenantRotate { id: String },
    /// Reach one tenant's engine OPERATOR plane: verify, admission review
    /// and rulings, wing trust, retention, attested forgetting, anchor
    /// tightening, supersession receipts.
    ///
    /// These ten routes landed on the admin plane on the argument that they
    /// "were reachable from nowhere in a fleet", and then WERE reachable
    /// from nowhere but `curl`: the console has no element for any of them
    /// and this CLI had no subcommand, while docs/MULTI_TENANCY.md said the
    /// CLI "mirrors the admin plane for scripted use" (ROADMAP C9).
    ///
    /// A closed vocabulary of `(method, subpath)` pairs, checked here
    /// against the same list the proxy enforces, so this cannot become a
    /// second, wider door.
    Ops {
        /// Tenant id
        id: String,
        /// One of: verify, anchor, supersessions, admission, admission-rule,
        /// trust, trust-set, retention, retention-set, retention-sweep,
        /// forget
        op: String,
        /// JSON body for the operations that take one (rulings, trust and
        /// retention assignment, forget)
        #[arg(long)]
        body: Option<String>,
    },
    /// Migrate a tenant's vault to another instance (export → import →
    /// count-verified → mapping flip → source delete)
    Migrate {
        id: String,
        /// Destination instance
        #[arg(long)]
        to: String,
        /// Keep the source vault instead of deleting it after the flip
        #[arg(long, default_value_t = false)]
        keep_source: bool,
    },
}

fn orch_key() -> Result<String> {
    std::env::var("UNDERCROFT_ORCH_KEY")
        .context("UNDERCROFT_ORCH_KEY is not set (generate one with `keygen`)")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            let mut admin = [0u8; 24];
            rand::thread_rng().fill_bytes(&mut admin);
            println!("UNDERCROFT_ORCH_KEY={}", hex::encode(key));
            println!("UNDERCROFT_ORCH_ADMIN_TOKEN={}", hex::encode(admin));
            Ok(())
        }
        Command::Serve { addr, read_replica } => {
            if read_replica {
                // No admin token: the replica has no admin plane to gate.
                let orch = Orch::open_read_only(&cli.db, &orch_key()?)?;
                return proxy::serve(&orch, &addr, proxy::Role::ReadReplica);
            }
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            let admin = std::env::var("UNDERCROFT_ORCH_ADMIN_TOKEN")
                .context("UNDERCROFT_ORCH_ADMIN_TOKEN is not set")?;
            if admin.len() < 16 {
                bail!("UNDERCROFT_ORCH_ADMIN_TOKEN must be at least 16 characters");
            }
            proxy::serve(
                &orch,
                &addr,
                proxy::Role::Writer {
                    admin_token: &admin,
                },
            )
        }
        Command::InstanceAdd {
            name,
            url,
            bearer,
            assertion_secret,
        } => {
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            orch.instance_add(&name, &url, &bearer, &assertion_secret)?;
            println!("registered instance {name} -> {url}");
            Ok(())
        }
        Command::InstanceList => {
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            for i in orch.instance_list()? {
                let healthy = orch
                    .instance_creds(&i.name)
                    .map(|c| engine::health(&c.url))
                    .unwrap_or(false);
                println!(
                    "{}\t{}\ttenants={}\thealthy={healthy}",
                    i.name, i.url, i.tenants
                );
            }
            Ok(())
        }
        Command::InstanceRemove { name } => {
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            let removed = orch.instance_remove(&name)?;
            println!("{}", if removed { "removed" } else { "not found" });
            Ok(())
        }
        Command::TenantCreate {
            name,
            instance,
            level,
        } => {
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            let instance = match instance {
                Some(i) => i,
                None => orch
                    .instance_least_loaded()?
                    .context("no instances registered")?,
            };
            let creds = orch.instance_creds(&instance)?;
            let (tenant, token) = orch.tenant_create(&name, &instance, &level)?;
            if let Err(e) = engine::create_vault(&creds, &tenant.vault, &level) {
                let _ = orch.tenant_delete(&tenant.id);
                bail!("engine vault create failed: {e}");
            }
            println!("tenant  {}", tenant.id);
            println!("vault   {} on {}", tenant.vault, tenant.instance);
            println!("token   {token}");
            println!("(the token is shown once and stored only as a MAC)");
            Ok(())
        }
        Command::TenantList => {
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            for t in orch.tenant_list()? {
                println!(
                    "{}\t{}\t{} @ {}\t{}",
                    t.id, t.name, t.vault, t.instance, t.created_at
                );
            }
            Ok(())
        }
        Command::TenantDelete { id } => {
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            let tenant = orch.tenant_get(&id)?.context("unknown tenant")?;
            let creds = orch.instance_creds(&tenant.instance)?;
            engine::delete_vault(&creds, &tenant.vault).map_err(|e| anyhow::anyhow!(e))?;
            orch.tenant_delete(&id)?;
            println!(
                "deleted {id} (vault {} on {})",
                tenant.vault, tenant.instance
            );
            Ok(())
        }
        Command::TenantRotate { id } => {
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            let token = orch.tenant_rotate_token(&id)?;
            println!("token   {token}");
            println!("(the old token is revoked; this one is shown once)");
            Ok(())
        }
        Command::Ops { id, op, body } => {
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            let (method, subpath) =
                proxy::ops_alias(&op).with_context(|| format!("unknown operation {op:?}"))?;
            let tenant = orch
                .tenant_get(&id)?
                .with_context(|| format!("unknown tenant {id}"))?;
            let creds = orch.instance_creds(&tenant.instance)?;
            let payload = body.unwrap_or_default();
            let r = engine::vault_request(
                &creds,
                &tenant.vault,
                method,
                subpath,
                "",
                "application/json",
                payload.as_bytes(),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            // The engine's own body, verbatim — the admin plane relays it
            // rather than re-summarising, and so does this.
            println!("{}", String::from_utf8_lossy(&r.body));
            if r.status >= 400 {
                bail!("engine answered {}", r.status);
            }
            Ok(())
        }
        Command::Migrate {
            id,
            to,
            keep_source,
        } => {
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            let summary = proxy::migrate_tenant(&orch, &id, &to, keep_source)
                .map_err(|e| anyhow::anyhow!(e))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
    }
}
