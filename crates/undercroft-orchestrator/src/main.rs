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

mod config_check;
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
    /// Inspect this deployment's configuration (see `config check`)
    ///
    /// The two-word spelling every document publishes. It exists beside the
    /// hyphenated one from the start rather than being added after a doc was
    /// found wrong — the engine shipped only `config-check` while every
    /// document published `config check`, and the published form did not run
    /// (ROADMAP O18).
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Validate every `UNDERCROFT_ORCH_*` declaration WITHOUT opening the
    /// state database or binding a port
    ///
    /// Exit 1 if any declaration that turns a protection on would refuse to
    /// start; exit 0 otherwise. Warnings do not fail the run.
    ///
    /// `undercroft config check` covers the ENGINE and cannot run this
    /// binary's resolvers — the two do not link. A fleet runs both.
    ConfigCheck {
        /// Also print the declarations that resolve cleanly
        #[arg(long)]
        verbose: bool,
    },
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
        /// One of: verify, repair, anchor, supersessions, admission,
        /// admission-rule, trust, trust-set, retention, retention-set,
        /// retention-sweep, forget, verify-forgetting, authority
        op: String,
        /// JSON body for the operations that take one (rulings, trust and
        /// retention assignment, forget, the authority declaration, and the
        /// attestation document verify-forgetting checks)
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

/// `config check` — the two-word spelling every doc publishes.
#[derive(Subcommand)]
enum ConfigAction {
    /// Validate every `UNDERCROFT_ORCH_*` declaration in this environment
    /// WITHOUT opening the state database or binding a port
    Check {
        /// Also print the declarations that resolve cleanly
        #[arg(long)]
        verbose: bool,
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
/// a 200 whose body says `"ok": false`, and an
/// error whose body carries `"class": "integrity"` — which the engine
/// emits precisely because 409 is also how a co-resident refusal and a
/// wrong read-only posture answer, and those must not page anyone.
///
/// **The `"ok": false` arm used to say "verify — and ONLY verify", naming
/// the supersessions route as a recorded gap.** That gap was closed in the
/// same campaign that wrote the comment: `/v1 …/supersessions` answers `ok`
/// now, and since 2026-08-10 so does `/v1 …/kg/receipts`, which had the
/// identical hole and was described in its own doc as the analogue of the
/// route that got the fix. A classifier documenting a gap its own engine has
/// closed under-reports forever, silently, and reads as deliberate scope.
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
                "INTEGRITY VERDICT: {e}. This is the orchestrator's own state, not an engine's — a credential blob that will not open under the declared key is a tamper verdict or a wrong key, never a transient condition."
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
    // …with ONE exemption, and it is the same one the engine's CLI makes for
    // the same command: `config check` exists to diagnose an environment that
    // will not start, so a version of it that cannot itself start in that
    // environment is useless. It carries on and REPORTS the declaration as a
    // finding of its own — including this one, since
    // `UNDERCROFT_ORCH_ENGINE_CA` has an arm. Both spellings, because
    // matching only the hyphenated one would exempt the spelling every doc
    // publishes from nothing at all.
    //
    // This is the exempt list the comment above declines to keep, and the
    // difference is that it has exactly one member with an argument rather
    // than being a place to add subcommands somebody found inconvenient.
    let preflight = matches!(
        cli.command,
        Command::ConfigCheck { .. } | Command::Config { .. }
    );
    // Telemetry comes up before anything is served (ROADMAP O20). It is a
    // no-op without `--features telemetry`, and the guard is held for the
    // process rather than dropped, because dropping it shuts the providers
    // down.
    //
    // **Its own service name**: both binaries in this workspace defaulted to
    // `"undercroft"`, so a fleet running an engine and a control plane under
    // one env file produced traces that could not be told apart. A declared
    // `UNDERCROFT_SERVICE_NAME` still wins.
    //
    // `config check` is exempt from a failure here for the same reason it is
    // exempt from the engine-hop refusal below: a command whose job is
    // diagnosing an environment that will not start is useless if it cannot
    // start in one.
    match undercroft_obs::init_as("undercroft-orchestrator") {
        Ok(guard) => std::mem::forget(guard),
        Err(e) if preflight => eprintln!("warning: telemetry disabled — {e}"),
        Err(e) => return Err(anyhow::anyhow!(e)),
    }
    match engine::init_transport() {
        Ok(()) => {}
        Err(e) if preflight => eprintln!("warning: engine hop unusable — {e}"),
        Err(e) => return Err(anyhow::anyhow!(e)),
    }
    match cli.command {
        Command::Config {
            action: ConfigAction::Check { verbose },
        }
        | Command::ConfigCheck { verbose } => {
            let (fatal, warned, validated, accepted) = config_check::run(verbose);
            println!(
                "checked {validated} declaration(s) of the control plane: \
                 {fatal} refusing, {warned} warning, {accepted} seen but not validated"
            );
            if fatal > 0 {
                bail!("this environment would refuse to start");
            }
            println!(
                "`undercroft-orchestrator serve` would start in this environment. \
                 Note this covers the CONTROL PLANE only — run `undercroft config check` \
                 on each engine as well."
            );
            Ok(())
        }
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
            // The SAME resolver `config check` runs — the length floor used
            // to live here as an inline `if`, which a pre-flight cannot
            // reach and which a trailing newline clears at 17 characters.
            let admin = proxy::resolve_admin_token(
                std::env::var("UNDERCROFT_ORCH_ADMIN_TOKEN").ok().as_deref(),
            )?;
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
            // Instances whose credential blob would not open. Collected
            // rather than raised inline so the listing completes (M20).
            let mut integrity: Vec<String> = Vec::new();
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
                    Err(e) => {
                        // **Remember the VERDICT before stringifying it**
                        // (ROADMAP M20). The line below is right about the
                        // display — a refusal is not an outage — and it was
                        // the whole story, so an `Unsealable` was flattened
                        // to a string, never escaped `run()`, and the exit-2
                        // hook in `main` never fired. This command reported
                        // the control plane's own tamper verdict and exited
                        // **0**, which is the answer a compliance script
                        // reads as "fine".
                        //
                        // The listing still lists — M18's rule, and the
                        // reason this is not simply a `?` here: one bad blob
                        // must not hide the other instances. The verdict is
                        // raised after the walk instead.
                        if e.is_integrity() {
                            integrity.push(i.name.clone());
                        }
                        engine::Health::Refused(e.to_string())
                    }
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
            // The walk finished; now the verdict. Raised as the error itself
            // so `main`'s existing exit-2 hook classifies it — one
            // classifier, not a second exit path spelled differently here.
            if !integrity.is_empty() {
                eprintln!(
                    "credential blob(s) that would not open: {}",
                    integrity.join(", ")
                );
                return Err(state::StateError::Unsealable.into());
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

    /// **The engine's help gate, on the binary that did not have one.**
    ///
    /// Found by the drift check for O21 rather than by the unit itself:
    /// `every_subcommand_has_its_own_about_and_config_check_runs` existed
    /// only in `undercroft-cli`, so the class it guards — a variant inserted
    /// BETWEEN a doc comment and the variant it documented, which leaves one
    /// subcommand bare and the other wearing two — was ungated in this
    /// binary the whole time. That is exactly the shape of ROADMAP O18, and
    /// this unit had just added two variants here.
    ///
    /// Nothing in the tree can see that class otherwise: clap accepts it,
    /// rustfmt accepts it, and no other gate reads help strings.
    #[test]
    fn every_subcommand_has_its_own_about_and_config_check_runs() {
        use clap::CommandFactory;
        let cmd = Cli::command();

        // Both spellings parse. Unlike the engine, this binary shipped them
        // together — the engine published `config check` in every doc while
        // only `config-check` ran, and there is no reason to repeat that.
        assert!(
            Cli::try_parse_from(["undercroft-orchestrator", "config", "check"]).is_ok(),
            "the two-word spelling is what the docs publish and it must run"
        );
        assert!(
            Cli::try_parse_from(["undercroft-orchestrator", "config-check"]).is_ok(),
            "the hyphenated spelling must run too"
        );

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
                 documented, which leaves this one bare and the other one \
                 wearing two"
            );
            if let Some(other) = seen.insert(about.clone(), name.clone()) {
                panic!(
                    "`{name}` and `{other}` advertise the SAME help text \
                     {about:?} — one of them has taken the other's doc comment"
                );
            }
        }
        // Premise: the walk examined the real surface. An empty or tiny
        // subcommand list satisfies every assertion above.
        assert!(
            cmd.get_subcommands().count() >= 10,
            "premise: this gate must have walked the real command surface, \
             found {}",
            cmd.get_subcommands().count()
        );
    }

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
