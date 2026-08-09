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
    /// These eleven routes landed on the admin plane on the argument that they
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

/// An integrity verdict, on the fleet's scripted operator door exactly as
/// on the engine's own CLI.
///
/// `docs/AGENTS.md` states the doctrine without qualification — *"Exit 2
/// means an integrity verdict, on every command"* — and this binary had no
/// exit-code doctrine at all: `fn main() -> Result<()>` gives 1 for
/// everything, and `ops … verify` keyed only on the HTTP status, which is
/// **200** when a vault fails verification (the verdict travels as
/// `"ok": false` in the body, correctly). So a scripted fleet check over a
/// tampered vault printed `"ok":false` and exited 0. That is engine defect
/// A22 verbatim, one plane out.
const EXIT_INTEGRITY: u8 = 2;

/// Classify an engine reply for the scripted operator door.
///
/// Two shapes carry an integrity verdict and neither is the status alone:
/// a 200 whose body says `"ok": false` (verify — and ONLY verify; the
/// supersessions route reports `summary.tampered` with no `ok` field, so it
/// is NOT covered here and is recorded as open), and an
/// error whose body carries `"class": "integrity"` — which the engine
/// emits precisely because 409 is also how a co-resident refusal and a
/// wrong read-only posture answer, and those must not page anyone.
fn is_integrity_verdict(status: u16, body: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    if status < 400 {
        return v.get("ok") == Some(&serde_json::Value::Bool(false));
    }
    v.get("class").and_then(|c| c.as_str()) == Some("integrity")
}

/// Whether a migration failure is an integrity verdict from the engine.
///
/// The engine's refusal travels as `MigrateError::Engine(status, message)`,
/// where the message is the relayed body wrapped in prose
/// (`"engine export failed (409): {json}"`). So this finds the JSON and
/// hands it to the SAME classifier `ops` uses — never a substring scan for
/// the class name, which would match the word appearing in any error text
/// and is the gate shape this tree has been bitten by twice.
fn migrate_is_integrity(e: &proxy::MigrateError) -> bool {
    match e {
        proxy::MigrateError::Engine(status, msg) => msg
            .find('{')
            .is_some_and(|i| is_integrity_verdict(*status, &msg.as_bytes()[i..])),
        // **The control plane's OWN tamper verdict.** `Unsealable` is "a
        // tamper verdict or a wrong key" by its own doc, and it exited 1 on
        // every subcommand while every ENGINE-side integrity verdict exited
        // 2 — so the fleet's state file failing to open was, to a compliance
        // script, an ordinary failed run.
        proxy::MigrateError::State(state::StateError::Unsealable) => true,
        _ => false,
    }
}

/// The same verdict for a bare state error, on the subcommands that do not
/// go through `MigrateError`.
fn state_is_integrity(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<state::StateError>(),
        Some(state::StateError::Unsealable)
    )
}

fn main() -> Result<()> {
    // Exit 2 for an integrity verdict raised anywhere in this binary, not
    // only on the two doors that were given one by hand. `Unsealable` is the
    // control plane's own tamper verdict and reached `?` on `ops`,
    // `tenant-create`, `tenant-delete` and `tenant-rotate` as an ordinary
    // error.
    let out = run();
    if let Err(e) = &out {
        if state_is_integrity(e) {
            eprintln!(
                "INTEGRITY VERDICT: {e}. This is the orchestrator's own state, not an                  engine's — a credential blob that will not open under the declared key                  is a tamper verdict or a wrong key, never a transient condition."
            );
            std::process::exit(EXIT_INTEGRITY.into());
        }
    }
    out
}

fn run() -> Result<()> {
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
    let cli = parsed;
    // The engine hop's TLS pin, resolved and VALIDATED before anything is
    // served or sent — the rule `RateLimiter::from_env` already states in
    // front of the bind, applied to the other declaration this process
    // reads. It used to be resolved inside every outbound call, so an
    // unreadable or certificate-less `UNDERCROFT_ORCH_ENGINE_CA` bound the
    // port, answered `/healthz` and then failed every proxied request.
    //
    // Here rather than in `serve` so it covers `migrate`, `instance-add`
    // and the rest: each of those makes an outbound call too, and a
    // configuration refusal belongs at the start of the command, not
    // halfway through a tenant migration.
    //
    // Unconditional, and the cost is stated: `keygen` makes no call and is
    // refused too when the declaration is broken. The alternative is a list
    // of exempt subcommands, and a list somebody has to remember to add to
    // is the exact shape this tree keeps paying for. An undeclared pin —
    // the default — resolves to `Ok(None)` and costs nothing, so only an
    // operator whose fleet is already misconfigured ever sees this.
    engine::init_transport().map_err(|e| anyhow::anyhow!(e))?;
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
                // A refusal is not an outage, and printing it as one sent
                // operators to look at an engine that was fine. `healthy`
                // keeps its meaning; the reason is appended when there is
                // one to give.
                // `instance_creds` makes no network call: its failures are
                // a wrong orchestrator key, a tampered credential blob or a
                // SQLite error. Flattening those to `Unreachable` would
                // commit the exact error `Health` exists to stop — claiming
                // an outage for a local condition — one variant over from
                // where it was just fixed. They are refusals, and they say
                // what they are.
                let health = match orch.instance_creds(&i.name) {
                    Ok(c) => engine::health(&c.url),
                    Err(e) => engine::Health::Refused(e.to_string()),
                };
                let note = match health.refusal() {
                    Some(why) => format!("\trefused={why}"),
                    None => String::new(),
                };
                println!(
                    "{}\t{}\ttenants={}\thealthy={}{note}",
                    i.name,
                    i.url,
                    i.tenants,
                    health.is_healthy()
                );
            }
            Ok(())
        }
        Command::InstanceRemove { name } => {
            let orch = Orch::open(&cli.db, &orch_key()?)?;
            // A delete of a name that is not registered is NOT a success —
            // the same doctrine `DELETE /admin/instances/{name}` states,
            // under a comment calling the cheerful 200 "verbatim the
            // anti-pattern the engine eradicated". This door printed
            // "not found" and exited 0, so a decommission script read it as
            // done. Two doors, opposite answers, on one call.
            if orch.instance_remove(&name)? {
                println!("removed");
                Ok(())
            } else {
                bail!("no instance {name:?}")
            }
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
                // `level` reached `GET /admin/tenants` (which serializes the
                // struct whole) and not this line — and it is precisely the
                // field whose doc says it exists because "a migration has to
                // recreate the vault on the destination and had no way to
                // ask". The surface an operator reads BEFORE a migration was
                // the one that could not show it.
                println!(
                    "{}	{}	{} @ {}	{}	{}",
                    t.id, t.name, t.vault, t.instance, t.level, t.created_at
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
            // An integrity verdict exits 2 BEFORE the status check, because
            // the verdict that matters most arrives on a 200: `verify`
            // answers `{"ok": false}` with a perfectly successful HTTP
            // status, and this door used to exit 0 on it.
            if is_integrity_verdict(r.status, &r.body) {
                eprintln!(
                    "INTEGRITY VERDICT from vault '{}' — this is not a failed run to retry. \
                     Follow the tamper runbook.",
                    tenant.vault
                );
                std::process::exit(EXIT_INTEGRITY.into());
            }
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
            // **The same exit-code doctrine as `ops`, on the other door
            // that talks to an engine.** `migrate` returned `Result<()>`,
            // so every failure exited 1 — including a source vault whose
            // export came back 409 `"class": "integrity"`, which is a
            // tamper verdict and not a run to retry. A migration is exactly
            // where that matters: the retry loop that treats exit 1 as
            // transient will keep asking a tampered vault to export itself.
            match proxy::migrate_tenant(&orch, &id, &to, keep_source) {
                Ok(summary) => {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                    Ok(())
                }
                Err(e) => {
                    if migrate_is_integrity(&e) {
                        eprintln!(
                            "INTEGRITY VERDICT from the engine during migration of tenant '{id}' — the \
                             source is left authoritative and untouched. This is not a failed run to \
                             retry. Follow the tamper runbook."
                        );
                        eprintln!("{e}");
                        std::process::exit(EXIT_INTEGRITY.into());
                    }
                    Err(anyhow::anyhow!(e))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A fleet-wide integrity check must not report success on a
    /// tampered vault.**
    ///
    /// `ops <tenant> verify` keyed its exit code on `r.status >= 400`
    /// alone, and the engine answers verify with **200** — the verdict
    /// rides in the body as `"ok": false`, which is correct for HTTP and
    /// fatal for a scripted operator. So a nightly fleet check over a
    /// broken chain printed `"ok":false` and exited 0.
    ///
    /// Both shapes are asserted, and so are the near misses, because the
    /// obvious over-fix — treating every 409 as an integrity verdict —
    /// would page someone for a co-resident refusal or a wrong read-only
    /// posture, which are ordinary refusals on the same status.
    /// **`migrate` had no exit-code doctrine at all.**
    ///
    /// `fn main() -> Result<()>` gives 1 for everything, so a migration
    /// whose source vault answered its export with 409 `"class":
    /// "integrity"` — a tamper verdict — exited the same code as a typo'd
    /// destination. A retry loop that treats 1 as transient keeps asking a
    /// tampered vault to export itself.
    ///
    /// The classifier is the SAME one `ops` uses, applied to the JSON found
    /// inside the wrapped message. Not a substring scan for the class name:
    /// that would match the word wherever it appeared in prose, which is
    /// the gate shape this tree has paid for twice.
    #[test]
    fn a_migration_refused_for_integrity_is_distinguishable_from_a_bad_request() {
        use proxy::MigrateError as M;
        // The verdict: the engine relayed a classed 409 through export.
        assert!(migrate_is_integrity(&M::Engine(
            409,
            r#"engine export failed (409): {"error":"vault manifest failed integrity verification","class":"integrity"}"#.into(),
        )));
        // ...and through import, which wraps its body the same way.
        assert!(migrate_is_integrity(&M::Engine(
            409,
            r#"engine import failed (409): {"error":"bad hmac","class":"integrity"}"#.into(),
        )));

        // Every near miss stays exit 1. A 409 is ALSO how a co-resident
        // refusal and a wrong read-only posture answer, and paging someone
        // for those is the over-fix this classifier exists to avoid.
        assert!(!migrate_is_integrity(&M::Engine(
            409,
            r#"engine export failed (409): {"error":"vault already exists"}"#.into(),
        )));
        assert!(!migrate_is_integrity(&M::Engine(
            502,
            "engine unreachable: connection refused".into(),
        )));
        // The word appearing in prose is not the class — the substring
        // scan this deliberately is not.
        assert!(!migrate_is_integrity(&M::Engine(
            400,
            r#"engine import failed (400): {"error":"integrity is not a valid kind"}"#.into(),
        )));
        // And nothing that is not an engine refusal is one.
        assert!(!migrate_is_integrity(&M::UnknownTenant("acme".into())));
        assert!(!migrate_is_integrity(&M::AlreadyThere));
        assert!(!migrate_is_integrity(&M::Unfaithful(
            "count mismatch: 9 of 10".into()
        )));
    }

    #[test]
    fn an_integrity_verdict_is_recognised_on_a_200_and_on_a_classed_error() {
        // The case that exited 0: a successful HTTP status carrying a
        // failed verdict.
        assert!(is_integrity_verdict(200, br#"{"ok":false,"drawers":12}"#));
        // The engine's classed error, which status alone cannot express.
        assert!(is_integrity_verdict(
            409,
            br#"{"error":"integrity failure on drawer x","class":"integrity"}"#
        ));

        // A clean verify is not a verdict.
        assert!(!is_integrity_verdict(200, br#"{"ok":true,"drawers":12}"#));
        // A 409 that is NOT an integrity verdict — a co-resident refusal,
        // a wrong read-only posture. These must stay exit 1.
        assert!(!is_integrity_verdict(
            409,
            br#"{"error":"vault is served over /mcp by this process"}"#
        ));
        assert!(!is_integrity_verdict(
            409,
            br#"{"error":"schema needs migration","class":"posture"}"#
        ));
        // An unrelated failure, and a body that is not JSON at all: the
        // classifier must not manufacture a verdict from either.
        assert!(!is_integrity_verdict(404, br#"{"error":"no such vault"}"#));
        assert!(!is_integrity_verdict(500, b"internal error"));
        assert!(!is_integrity_verdict(200, b""));
        // `ok` on an ERROR body is not the verdict channel — only the
        // class is, or a 200 could be contradicted by its own status.
        assert!(!is_integrity_verdict(400, br#"{"ok":false}"#));
    }
}
