//! Thin client for the engine's `/v1` surface.
//!
//! The orchestrator talks to engines exactly like any other caller: palace
//! bearer + short-lived per-vault assertion, both over the documented HTTP
//! surface. Nothing here links engine crates — the engine stays tree-blind
//! and this stays an ordinary, replaceable client.

use crate::state::InstanceCreds;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Mint an `X-Vault-Assertion` header value for `vault` at the current
/// time: `<ts>:<hex>` where `hex = HMAC-SHA256(secret, "<ts>|<vault>")` —
/// the engine's `assertion.rs` format, recomputed here rather than linked
/// (the header layout is part of the documented `/v1` contract).
pub fn mint_assertion(secret: &str, vault: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(format!("{ts}|{vault}").as_bytes());
    format!("{ts}:{}", hex::encode(mac.finalize().into_bytes()))
}

/// One relayed engine response.
pub struct EngineResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// `UNDERCROFT_ORCH_ENGINE_CA` — a self-signed root to PIN for the hop to
/// the engines, replacing the public roots (never adding to them), exactly
/// as `UNDERCROFT_INDEX_CA` / `_EMBED_CA` / `_LLM_CA` do on their hops.
const CA_VAR: &str = "UNDERCROFT_ORCH_ENGINE_CA";

/// The declared pin, resolved ONCE per process.
///
/// **A garbage pin used to bind the port and report healthy.** `agent` read
/// the variable, read the file and parsed the PEM on every outbound call —
/// twice per proxied drawer request — so an unreadable or certificate-less
/// CA file produced a 502 per request from a process that had already told
/// the load balancer it was up. The same binary states the opposite rule
/// one module over, where `RateLimiter::from_env` sits deliberately in
/// front of `Server::http`: *"a refusal about configuration must not arrive
/// after the port is open"*. A pin is configuration; this is the same rule.
///
/// The `Result` is what is cached, not just the success: a declaration that
/// does not resolve must keep refusing, identically, for the life of the
/// process. Re-reading the file per call also made the pin **mutable at
/// runtime** by anything that could rewrite the path — silently un-pinning
/// a live fleet is exactly the failure `undercroft-net` refuses to allow at
/// construction.
static ENGINE_PIN: std::sync::OnceLock<Result<Option<undercroft_net::Pin>, String>> =
    std::sync::OnceLock::new();

/// The resolution rule, as a pure function of the variable's value.
///
/// Pure for the reason the store states on its own resolvers: `set_var` is
/// process-global and the suite runs tests in parallel, so an env-driven
/// test of this is a flake generator aimed at every test beside it. It is
/// also the shape `resolve_rate_limit` already uses one module over — the
/// sibling declaration this one was measured against.
fn resolve_engine_pin(declared: Option<&str>) -> Result<Option<undercroft_net::Pin>, String> {
    match declared {
        // An empty declaration pins nothing, and the policy's answer to
        // that is to refuse rather than fall back — the same verdict
        // `pinned_roots` gives an empty file. Falling back here would
        // un-pin a fleet on a typo, silently.
        Some(p) if p.trim().is_empty() => Err(format!(
            "{CA_VAR} is set to an empty value. A declared trust root that names no file pins \
             nothing; unset it to use the public roots, or point it at a PEM. There is no \
             silent fallback"
        )),
        Some(p) => undercroft_net::resolve_pin("the engine", p)
            .map(Some)
            .map_err(|e| e.to_string()),
        None => Ok(None),
    }
}

fn engine_pin() -> &'static Result<Option<undercroft_net::Pin>, String> {
    ENGINE_PIN.get_or_init(|| resolve_engine_pin(std::env::var(CA_VAR).ok().as_deref()))
}

/// Resolve the engine hop's transport pin **before anything is served**.
///
/// Called first thing in `main`, so every subcommand — not only `serve` —
/// refuses a bad declaration at its own construction moment rather than at
/// its first request.
pub fn init_transport() -> Result<(), String> {
    engine_pin().as_ref().map(|_| ()).map_err(Clone::clone)
}

/// An agent that obeys the project's ONE transport policy: TLS or
/// loopback, nothing else, no override — refused at construction, before a
/// byte moves.
///
/// This hop had no policy at all. `undercroft-net` exists because the rule
/// was implemented once for the embedder and LLM clients while the remote
/// index backends had none, and its own header says it is "the only
/// implementation of them" — yet the control plane that fronts every
/// request in a fleet built a bare `ureq` agent and never referenced the
/// crate. What travels here is not incidental: the palace bearer, a minted
/// `X-Vault-Assertion`, search bodies, and whole-corpus export/import
/// NDJSON during a migration. `docs/MULTI_TENANCY.md` stated it as
/// operator advice ("point the instance `url` at an HTTPS reverse proxy"),
/// which made the no-override rule advisory on exactly one surface.
///
/// A refusal is a `String`, like every other failure this module reports,
/// and deliberately NOT a `ureq` transport error: nothing reached the wire,
/// so dressing it as one would tell an operator the engine was unreachable
/// when the truth is that this process declined to speak to it in clear.
fn agent(base: &str) -> Result<ureq::Agent, String> {
    let pin = engine_pin().as_ref().map_err(Clone::clone)?;
    undercroft_net::agent_pinned(
        "the engine",
        base,
        pin.as_ref(),
        std::time::Duration::from_secs(600),
    )
    .map_err(|e| e.to_string())
}

/// Send `method` + `body` to `{url}/v1/vaults/{vault}/{subpath}` (or the
/// vault root when `subpath` is empty) with bearer + assertion attached.
/// Engine error statuses are *relayed*, not treated as transport failures.
pub fn vault_request(
    creds: &InstanceCreds,
    vault: &str,
    method: &str,
    subpath: &str,
    // The caller's query string WITHOUT the `?` (empty = none). Required
    // rather than optional because dropping it was silent and total: the
    // proxy split the query off the request target and never forwarded it,
    // so `GET /t/drawers?limit=500&offset=50&wing=legal` reached the engine
    // as a bare `/v1/vaults/<v>/drawers` and got page one of the defaults.
    // A paginating client looped on the first page forever, at HTTP 200,
    // and every filter a tenant declared through the control plane was
    // discarded. Making it an argument means a new call site has to decide.
    query: &str,
    content_type: &str,
    body: &[u8],
) -> Result<EngineResponse, String> {
    let path = if subpath.is_empty() {
        format!("{}/v1/vaults/{vault}", creds.url)
    } else {
        format!("{}/v1/vaults/{vault}/{subpath}", creds.url)
    };
    // The query rides after `?`, so it cannot re-enter the path grammar —
    // `url` parses everything past the first `?` as the query component.
    // A `#` would start a fragment, which is dropped rather than sent.
    let path = if query.is_empty() {
        path
    } else {
        format!("{path}?{}", query.split('#').next().unwrap_or(""))
    };
    // The transport refusal is an outcome no engine can see: it happens
    // before a byte moves, so nothing downstream records it (ROADMAP O20).
    let req = match agent(&creds.url) {
        Ok(a) => a,
        Err(e) => {
            undercroft_obs::orch_engine_call("refused");
            return Err(e);
        }
    }
    .request(method, &path)
    .set("Authorization", &format!("Bearer {}", &*creds.bearer))
    .set(
        "X-Vault-Assertion",
        &mint_assertion(&creds.assertion_secret, vault),
    )
    .set("Content-Type", content_type);
    let result = if body.is_empty() && (method == "GET" || method == "DELETE") {
        req.call()
    } else {
        req.send_bytes(body)
    };
    let resp = match result {
        Ok(r) => r,
        // 4xx/5xx from the engine are still responses to relay.
        Err(ureq::Error::Status(_, r)) => r,
        Err(ureq::Error::Transport(t)) => {
            undercroft_obs::orch_engine_call("unreachable");
            return Err(format!("engine unreachable: {t}"));
        }
    };
    let status = resp.status();
    // `ok` vs `status` rather than the code itself: a status label here would
    // duplicate what the engine already counts, and the fact worth having at
    // this hop is that ONE tenant write becomes TWO engine calls via the
    // drawer probe — an amplification nothing else reports.
    undercroft_obs::orch_engine_call(if status < 400 { "ok" } else { "status" });
    let content_type = resp.content_type().to_string();
    let mut body = Vec::new();
    use std::io::Read;
    resp.into_reader()
        .take(256 * 1024 * 1024)
        .read_to_end(&mut body)
        .map_err(|e| format!("engine response read: {e}"))?;
    Ok(EngineResponse {
        status,
        content_type,
        body,
    })
}

/// Create a vault on an instance. Idempotent-ish for our use: an engine
/// "already exists" error surfaces as the relayed status.
pub fn create_vault(creds: &InstanceCreds, vault: &str, level: &str) -> Result<(), String> {
    let body = serde_json::json!({ "id": vault, "level": level }).to_string();
    let path = format!("{}/v1/vaults", creds.url);
    let result = agent(&creds.url)?
        .post(&path)
        .set("Authorization", &format!("Bearer {}", &*creds.bearer))
        .set(
            "X-Vault-Assertion",
            &mint_assertion(&creds.assertion_secret, vault),
        )
        .set("Content-Type", "application/json")
        .send_string(&body);
    match result {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(code, r)) => Err(format!(
            "engine refused vault create ({code}): {}",
            r.into_string().unwrap_or_default()
        )),
        Err(ureq::Error::Transport(t)) => Err(format!("engine unreachable: {t}")),
    }
}

pub fn delete_vault(creds: &InstanceCreds, vault: &str) -> Result<(), String> {
    match vault_request(creds, vault, "DELETE", "", "", "application/json", &[]) {
        Ok(r) if r.status == 200 || r.status == 404 => Ok(()),
        Ok(r) => Err(format!(
            "engine refused vault delete ({}): {}",
            r.status,
            String::from_utf8_lossy(&r.body)
        )),
        Err(e) => Err(e),
    }
}

/// Export a vault as NDJSON (v0.18 artifact-carrying format).
pub fn export_vault(creds: &InstanceCreds, vault: &str) -> Result<String, String> {
    let r = vault_request(creds, vault, "GET", "export", "", "application/json", &[])?;
    if r.status != 200 {
        return Err(format!(
            "engine export failed ({}): {}",
            r.status,
            String::from_utf8_lossy(&r.body)
        ));
    }
    String::from_utf8(r.body).map_err(|_| "export was not UTF-8".into())
}

/// Import NDJSON into a vault; returns the engine's imported count.
/// What one engine import reported: drawers plus (since the manifest-era
/// export format) the knowledge-graph records that rode the same stream.
/// The additive keys default to zero against an older engine.
pub struct ImportCounts {
    pub drawers: u64,
    pub kg_triples: u64,
    pub kg_entities: u64,
    pub tunnels: u64,
    /// How many of `drawers` the destination's admission screen DIVERTED
    /// into `quarantine-pending`. The engine has always reported this and
    /// this struct dropped it, so `migrate_tenant`'s count check compared
    /// `imported` (which counts diverted rows) against the source count,
    /// found them equal, and **deleted the source vault** — destroying the
    /// only copy that had those drawers filed where they belonged. A
    /// migration is a burst from one writer identity, which is exactly what
    /// a declared `UNDERCROFT_ADMISSION_RATE` diverts, so this was reachable
    /// by configuration rather than by attack.
    pub quarantined: u64,
}

pub fn import_vault(
    creds: &InstanceCreds,
    vault: &str,
    ndjson: &str,
) -> Result<ImportCounts, String> {
    let r = vault_request(
        creds,
        vault,
        "POST",
        "import",
        "",
        "application/json",
        ndjson.as_bytes(),
    )?;
    if r.status != 200 {
        return Err(format!(
            "engine import failed ({}): {}",
            r.status,
            String::from_utf8_lossy(&r.body)
        ));
    }
    let v = serde_json::from_slice::<serde_json::Value>(&r.body)
        .map_err(|_| "engine import response did not parse".to_string())?;
    let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
    if v.get("imported")
        .and_then(serde_json::Value::as_u64)
        .is_none()
    {
        return Err("engine import response did not parse".into());
    }
    Ok(ImportCounts {
        drawers: n("imported"),
        kg_triples: n("kg_triples"),
        kg_entities: n("kg_entities"),
        tunnels: n("tunnels"),
        quarantined: n("quarantined"),
    })
}

/// What an instance probe found.
///
/// **Three states, because two of them were being reported as the third.**
/// `health` used to be a `bool` built with `let Ok(a) = agent(url) else {
/// return false }`, so a cleartext instance URL and an unresolvable CA pin —
/// both decisions this process made about itself, before a byte moved — came
/// out as `healthy: false` on `/admin/instances/{name}/health`, on the
/// instance list and in the fleet console. An operator reading that goes and
/// looks at the engine, which is fine. Nothing anywhere said the refusal was
/// local, and the transport layer deliberately does not dress a refusal as a
/// `ureq` transport error for exactly this reason: *"nothing reached the
/// wire, so dressing it as one would tell an operator the engine was
/// unreachable when the truth is that this process declined to speak to it
/// in clear."* Then the one consumer flattened it anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// `/healthz` answered 200.
    Healthy,
    /// Reached, and did not answer 200.
    Unhealthy,
    /// Never reached: no route, refused connection, timeout, TLS failure.
    Unreachable,
    /// **This process refused to speak to it**, carrying the reason.
    Refused(String),
}

impl Health {
    /// The boolean the wire has always carried. Kept so the field's meaning
    /// does not change under existing clients — a refusal is not healthy —
    /// while the reason travels beside it.
    pub fn is_healthy(&self) -> bool {
        matches!(self, Health::Healthy)
    }

    /// The operator-facing reason, when there is one to give.
    pub fn refusal(&self) -> Option<&str> {
        match self {
            Health::Refused(why) => Some(why),
            _ => None,
        }
    }
}

/// Probe an instance's unauthenticated `/healthz`.
pub fn health(url: &str) -> Health {
    let a = match agent(url) {
        Ok(a) => a,
        Err(why) => return Health::Refused(why),
    };
    match a.get(&format!("{url}/healthz")).call() {
        Ok(r) if r.status() == 200 => Health::Healthy,
        // A status the engine actually produced: it is up and answering.
        Ok(_) | Err(ureq::Error::Status(_, _)) => Health::Unhealthy,
        Err(ureq::Error::Transport(_)) => Health::Unreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_matches_the_engine_contract() {
        // Recompute the documented format independently: <ts>:<hex> with
        // hex = HMAC-SHA256(secret, "<ts>|<vault>").
        let h = mint_assertion("sekrit", "tenant-abc");
        let (ts, mac_hex) = h.split_once(':').expect("ts:hex");
        let mut mac = Hmac::<Sha256>::new_from_slice(b"sekrit").unwrap();
        mac.update(format!("{ts}|tenant-abc").as_bytes());
        assert_eq!(mac_hex, hex::encode(mac.finalize().into_bytes()));
        // And a different vault yields a different MAC (the core guarantee).
        let h2 = mint_assertion("sekrit", "tenant-xyz");
        assert_ne!(h.split_once(':').unwrap().1, h2.split_once(':').unwrap().1);
    }

    /// A declaration that cannot be honoured refuses; a missing one does
    /// not. Both directions, because "refuses on garbage" is half a gate:
    /// one that refused everything would pass it and take the fleet down.
    #[test]
    fn a_pin_that_cannot_be_honoured_refuses_rather_than_falling_back() {
        assert!(
            resolve_engine_pin(None)
                .expect("no declaration is not a refusal")
                .is_none(),
            "an undeclared pin resolves to the public roots"
        );
        for empty in ["", "   "] {
            let err = resolve_engine_pin(Some(empty)).expect_err("must refuse");
            assert!(err.contains(CA_VAR), "{err}");
            assert!(err.contains("no silent fallback"), "{err}");
        }
        let dir = tempfile::TempDir::new().unwrap();
        // Unreadable: the path names nothing.
        let missing = dir.path().join("nope.pem");
        let err = resolve_engine_pin(Some(missing.to_str().unwrap())).expect_err("must refuse");
        assert!(err.contains("the engine"), "{err}");
        // Readable and pins nothing — the failure `undercroft-net` exists
        // to make loud, since silently un-pinning is the bad direction.
        let empty_pem = dir.path().join("empty.pem");
        std::fs::write(&empty_pem, b"").unwrap();
        let err = resolve_engine_pin(Some(empty_pem.to_str().unwrap())).expect_err("must refuse");
        assert!(err.contains("pins nothing"), "{err}");
    }

    /// **The environment is read ONCE, and this is the gate that says so.**
    ///
    /// The defect was not that the pin was wrong — it was that `agent`
    /// resolved it per outbound call, so a bad declaration bound the port,
    /// answered `/healthz`, and then 502'd every request. That is a
    /// property of WHERE the read happens, and no behavioural test can see
    /// it without mutating a process-global variable underneath every test
    /// running in parallel. So it is checked at the source, the way this
    /// tree already checks its telemetry emitters and its rotation list.
    ///
    /// The needle is split with `concat!` because this file IS the haystack
    /// — a gate whose own text is part of what it measures has fired twice
    /// in this project — and comment lines are skipped for the same reason.
    #[test]
    fn the_engine_transport_reads_its_environment_exactly_once() {
        let src = include_str!("engine.rs");
        let needle = concat!("env", "::var(");
        let reads: Vec<&str> = src
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//") && !l.starts_with("///"))
            .filter(|l| l.contains(needle))
            .collect();
        assert_eq!(
            reads.len(),
            1,
            "the engine hop's configuration must be read once, inside the OnceLock \
             initialiser — anything else resolves it per request again. Found: {reads:#?}"
        );
        // …and that one read is inside the cached initialiser, not merely
        // somewhere in the file. Sliced on the function rather than matched
        // on the line, so rustfmt wrapping the expression cannot turn a
        // real gate into a failing one.
        let body = src
            .split_once("fn engine_pin(")
            .expect("premise: the cached accessor exists")
            .1
            .split_once("\n}\n")
            .expect("premise: it has a body")
            .0;
        assert!(
            body.contains(needle),
            "the one read must be the cached one, not a fresh lookup"
        );
    }

    /// **A refusal is not an outage.** Three conditions used to arrive as
    /// one `false`, and the only one an operator can act on from here — the
    /// one where this process declined to speak — was the one that looked
    /// exactly like the engine being down.
    ///
    /// Cleartext beyond loopback is refused at construction, so this makes
    /// no network call and cannot flake on a sandbox with no DNS.
    #[test]
    fn a_transport_refusal_is_reported_as_a_refusal_not_as_an_outage() {
        let h = health("http://engine.internal:8800");
        assert_eq!(
            h,
            Health::Refused(
                undercroft_net::require_secure_transport(
                    "the engine",
                    "http://engine.internal:8800"
                )
                .expect_err("premise: the policy refuses this URL")
                .to_string()
            ),
            "a policy refusal must carry its reason, not read as an unreachable engine"
        );
        assert!(!h.is_healthy(), "a refusal is still not healthy");
        assert!(
            h.refusal().is_some_and(|w| w.contains("no override")),
            "the reason must name the fix: {h:?}"
        );
        // And the states stay distinct where it matters.
        assert!(Health::Healthy.is_healthy());
        assert!(Health::Unreachable.refusal().is_none());
        assert!(Health::Unhealthy.refusal().is_none());
    }
}
