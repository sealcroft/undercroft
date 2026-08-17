//! The orchestrator HTTP surface: a tenant-facing routing proxy plus an
//! admin control plane, in one single-threaded `tiny_http` loop (the same
//! serving model as the engine — simple, auditable, no async runtime).
//!
//! **Data plane** — `/t/<subpath>` with a tenant bearer token: the token
//! resolves (by MAC) to its tenant, the request forwards to the tenant's
//! engine instance as `/v1/vaults/{vault}/<subpath>` with the engine
//! bearer + a freshly minted per-vault assertion, and the engine response
//! relays back verbatim. A tenant token addresses exactly its own vault —
//! there is no path shape that reaches another tenant, and even a routing
//! bug downstream fails cryptographically (the assertion and the vault
//! AAD both carry the vault id).
//!
//! **Admin plane** — `/admin/*` behind `UNDERCROFT_ORCH_ADMIN_TOKEN`:
//! instance registry, tenant lifecycle (create = pick instance → create
//! engine vault → record mapping → return the token once), migration
//! (export → import → count-verified → mapping flip → source delete), and
//! the **operator plane** `/admin/tenants/{id}/ops/<subpath>` — attested
//! forgetting, retention policy, wing trust, admission review and verify,
//! forwarded to the tenant's engine over a closed vocabulary
//! ([`OPS_ROUTES`]). Note `/admin/tenants/{id}/rotate` rotates the tenant's
//! BEARER TOKEN, while `ops/…` reaches the engine's own routes; the vault
//! KEY rotation `/v1/.../rotate` is deliberately not among them, since it
//! must not run while a process is serving the vault.
//!
//! **Read-replica mode** (`serve --read-replica`) opens the state database
//! read-only and serves *only* `/healthz` and the `/t/*` data plane —
//! token resolution is a pure MAC lookup, so replicas scale read routing
//! without ever minting, rotating, or migrating anything. `/admin/*` and
//! `/ui` answer 403 pointing at the writer. `/healthz` on both roles
//! carries `mode` and the state's `last_write` stamp, so lag between the
//! writer and a replica is directly observable.
//!
//! Auth failures are uniform 401s with no reason detail, mirroring the
//! engine's assertion handling.

use crate::engine;
use crate::state::{Orch, StateError};
use subtle_ct::ct_eq;
use tiny_http::{Header, Method, Response, Server};

/// Constant-time string compare without pulling `subtle` into this crate's
/// public surface — a length leak here is fine (token lengths are public).
mod subtle_ct {
    pub fn ct_eq(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.bytes().zip(b.bytes()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

/// Per-tenant fixed-window rate limiter (requests per minute). Off unless
/// `UNDERCROFT_ORCH_RATE_LIMIT` is set to a positive integer. Single-writer
/// like the serve loop itself, so plain interior state suffices. Windows
/// are keyed by tenant id — one noisy tenant is throttled, the rest are
/// untouched (the blast-radius posture, applied to request volume).
pub(crate) struct RateLimiter {
    per_minute: u64,
    windows: std::cell::RefCell<std::collections::HashMap<String, (u64, u64)>>,
}

/// Read `UNDERCROFT_ORCH_RATE_LIMIT`: unset, empty, `off` or `0` = off;
/// a positive integer declares requests per tenant per minute. Anything
/// else REFUSES to start.
///
/// It used to be `parse().ok().unwrap_or(0)`, i.e. every unreadable
/// declaration became "off" with nothing printed — and the two typos a
/// reader of this project is most likely to make are `100/min` and
/// `1_000`, the first because the engine's own rate variable really is
/// `<count>/<seconds>`. An operator who declared a limit believes noisy
/// tenants are throttled; silently serving unlimited is the failure
/// mode, and neither `/healthz` nor the console would have said so.
/// This is the engine's `resolve_read_audit` /
/// `resolve_admission_rate` posture applied to the control plane: a
/// declaration this process cannot read is a startup refusal, not a
/// default. Pure, so the parse is tested without touching the
/// environment.
/// The `/admin` bearer and the rate screen, re-exported from
/// `undercroft-config`.
///
/// **Both parses moved out of this crate** (ROADMAP O24): `undercroft config
/// check` promises to validate every `UNDERCROFT_*` declaration, six surfaces
/// including the doctrine say so, and it could not reach a parse that lived
/// here — the engine never links the control plane. They are re-exported
/// rather than re-implemented so every existing call site is unchanged and
/// there is still exactly one implementation of each.
pub(crate) use undercroft_config::{resolve_admin_token, resolve_rate_limit};

impl RateLimiter {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let per_minute =
            resolve_rate_limit(std::env::var("UNDERCROFT_ORCH_RATE_LIMIT").ok().as_deref())?;
        Ok(Self {
            per_minute,
            windows: std::cell::RefCell::new(std::collections::HashMap::new()),
        })
    }

    #[cfg(test)]
    fn with_limit(per_minute: u64) -> Self {
        Self {
            per_minute,
            windows: std::cell::RefCell::new(std::collections::HashMap::new()),
        }
    }

    /// Record one request for `tenant` at unix-minute `minute`; `false` ⇒
    /// over the limit (the request should 429).
    fn allow_at(&self, tenant: &str, minute: u64) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        let mut windows = self.windows.borrow_mut();
        let entry = windows.entry(tenant.to_string()).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        entry.1 += 1;
        entry.1 <= self.per_minute
    }

    pub(crate) fn allow(&self, tenant: &str) -> bool {
        let minute = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 60)
            .unwrap_or(0);
        self.allow_at(tenant, minute)
    }
}

/// Subpath allowlist for the data plane: the first segment must be one of
/// the engine's vault subroutes. An empty subpath (the vault root — its
/// DELETE endpoint) is refused: vault lifecycle belongs to the admin
/// plane, not to a data token.
fn data_subpath_ok(subpath: &str) -> bool {
    // The WHOLE subpath, never its first segment — because an approved
    // prefix used to authorize an arbitrary suffix. `drawers/../admission`
    // passed this gate (first segment `drawers`), and the engine URL is
    // built by interpolation, so `ureq`'s `url` parse collapsed the `..`
    // per the WHATWG path rules and the engine received
    // `/v1/vaults/<t>/admission` — a tenant token ruling on the admission
    // queue that screened its own writes, assigning its own trust, running
    // retention sweeps, forgetting, ROTATING KEYS (a capability deliberately
    // absent even from the admin plane) and deleting the vault. Worse, the
    // suffix can climb past the vault: `search/../../other/search` reached
    // ANOTHER TENANT'S vault, bounded only by the assertion MAC — which
    // `Tenancy::assert_or_401` skips entirely when no secret is declared.
    //
    // Two independent barriers, because one silent misconfiguration must not
    // remove the only one: every segment is shape-checked (so nothing that
    // could normalize reaches the match), and the match is exhaustive over a
    // closed vocabulary of whole shapes, exactly as `OPS_ROUTES` already is.
    let segs: Vec<&str> = subpath.split('/').collect();
    let segment_is_safe = |s: &&str| {
        !s.is_empty()
            // `.` and `..` (and any dots-only spelling) are the traversal;
            // `%` catches the encoded forms (`%2e`) that `url` also decodes.
            && !s.bytes().all(|b| b == b'.')
            && !s.contains('%')
            && !s.contains('\\')
    };
    if !segs.iter().all(segment_is_safe) {
        return false;
    }
    // A closed allowlist of whole shapes, and the absences are decisions.
    //
    // **`["history"]` is deliberately NOT here.** The engine's
    // `GET /v1/vaults/{id}/history` is OPERATOR scope — the whole audit
    // chain, including `admission/{id}/{verdict}` (the reviewer's view of the
    // queue that screened this tenant's own writes) and `trust/{wing}` (the
    // retrieval policy deciding what it may retrieve). Forwarding it to a
    // tenant is A13 verbatim, one capability later. The agent-facing scope of
    // that capability exists and is fenced, but it lives on MCP against a
    // local vault, not on a plane that proxies a tenant into someone else's
    // operator surface. `["stats", "history"]` below is unrelated — metrics
    // over time, not the audit chain.
    matches!(
        segs.as_slice(),
        ["drawers"]
            | ["drawers", _]
            | ["search"]
            | ["stats"]
            | ["stats", "history"]
            | ["export"]
            | ["import"]
    )
}

// -- the quarantine fence, one plane up --------------------------------------

/// The engine's reserved admission-review wing.
///
/// Spelled out here rather than imported: this crate links no engine crate
/// — `engine::mint_assertion` recomputes the assertion header format for
/// exactly the same reason — so the wing name travels as part of the
/// documented `/v1` contract. Renaming it in the engine means renaming it
/// here; nothing in this crate can notice, which is the price of staying a
/// replaceable client.
const QUARANTINE_WING: &str = "quarantine-pending";

/// What the data plane says when the fence fires. Names the surface that
/// *does* hold the capability, like the ops-route refusal next to it — a
/// bare "no" is what made these capabilities look absent from the product.
const QUARANTINE_REFUSAL: &str = "quarantine-pending is the admission review queue — pending \
     review evidence is not readable with a tenant token. It is an operator \
     surface: GET/POST /admin/tenants/{id}/ops/admission on the writer";

/// Minimal percent-decoding (`%XX`, `+` as space), so a query value is
/// compared as what the ENGINE will read rather than as what was typed.
/// The engine hands most query values on raw but `pct_decode`s some, and a
/// fence that only recognises one spelling of a name is not a fence.
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(
                    std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"),
                    16,
                ) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn json_names_reserved_wing(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::String(s) => s == QUARANTINE_WING,
        serde_json::Value::Array(a) => a.iter().any(json_names_reserved_wing),
        serde_json::Value::Object(o) => o.values().any(json_names_reserved_wing),
        _ => false,
    }
}

/// **The quarantine fence, one plane up.** The engine deliberately serves
/// the review queue to a request that NAMES the reserved wing — that is
/// the reviewer's view (`resolve_search_policy` returns early, `recent`
/// and `list_drawers` only exclude when no wing is named). On `/v1` that
/// is right, because `/v1` is the operator's surface. Through `/t/*` it is
/// not: the token belongs to the tenant whose own writes the screen
/// diverted, so `POST /t/search {"wing":"quarantine-pending"}` handed an
/// agent back the injected text it was quarantined for, verbatim and with
/// no traversal. The ruling half of that boundary moved to the admin plane
/// when [`OPS_ROUTES`] was written; the READING half did not.
///
/// The rule is the MCP fence's, applied to a request instead of to a tool
/// call: no value a tenant sends may be the reserved wing's name — in the
/// subpath, in a query value, or anywhere in the body. Deliberately not a
/// key allowlist (`wing`, `from_wing`, …): a checklist of argument names
/// goes stale the moment a route grows one, which is the failure mode the
/// fence exists to remove.
///
/// Its price is pinned rather than hidden, exactly as MCP's is: the match
/// is on the VALUE, so saving a drawer whose entire text is the literal
/// string `quarantine-pending` is refused too, and the refusal says what
/// happened. The walk is recursive where MCP's is one level, because `/v1`
/// bodies nest — an import record declares its wing at
/// `drawer.meta.wing`, not at the top.
fn request_names_reserved_wing(subpath: &str, query: &str, body: &[u8]) -> bool {
    if subpath.split('/').any(|s| s == QUARANTINE_WING) {
        return true;
    }
    if query.split('&').any(|kv| {
        let v = kv.split_once('=').map(|(_, v)| v).unwrap_or(kv);
        v == QUARANTINE_WING || pct_decode(v) == QUARANTINE_WING
    }) {
        return true;
    }
    if body.is_empty() {
        return false;
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) => json_names_reserved_wing(&v),
        // NDJSON (`import`) — the whole body is not one value. A line that
        // is not JSON declares nothing the engine will read either.
        Err(_) => body.split(|b| *b == b'\n').any(|line| {
            serde_json::from_slice::<serde_json::Value>(line)
                .map(|v| json_names_reserved_wing(&v))
                .unwrap_or(false)
        }),
    }
}

/// Does an engine `GET drawers/{id}` body describe a drawer in the
/// reserved wing? Field-precise (`drawer.meta.wing`), not the blunt value
/// walk above: this reads the ENGINE's own answer, where a drawer whose
/// content merely says `quarantine-pending` is a legitimate row and
/// refusing it would be a false positive on a read the tenant owns.
fn drawer_body_is_quarantined(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/drawer/meta/wing")
                .and_then(serde_json::Value::as_str)
                .map(|w| w == QUARANTINE_WING)
        })
        .unwrap_or(false)
}

/// Does an export payload carry review evidence? Same field-precise test,
/// per NDJSON record.
fn export_carries_reserved_wing(body: &[u8]) -> bool {
    body.split(|b| *b == b'\n').any(|line| {
        serde_json::from_slice::<serde_json::Value>(line)
            .ok()
            .and_then(|v| {
                v.pointer("/drawer/meta/wing")
                    .and_then(serde_json::Value::as_str)
                    .map(|w| w == QUARANTINE_WING)
            })
            .unwrap_or(false)
    })
}

/// `drawers/{id}` — the one data-plane shape that DEREFERENCES to a wing
/// without naming one, which is why the name fence alone cannot cover it.
/// MCP closes the same indirection by probing `is_quarantine_pending` on
/// every id-shaped argument; this crate has no store, so the probe is a
/// `/v1` read.
fn single_drawer_route(subpath: &str) -> bool {
    matches!(
        subpath.split('/').collect::<Vec<_>>().as_slice(),
        ["drawers", _]
    )
}

/// The operator capabilities the admin plane forwards to an engine, as
/// `(method, subpath)` — a **closed vocabulary**, so extending the operator
/// surface is a deliberate edit here rather than a wildcard proxy that
/// quietly grows into one.
///
/// These exist on the engine's `/v1` and were reachable from nowhere in a
/// fleet: the data-plane allowlist was written to keep vault *lifecycle*
/// off a tenant token and, as a side effect, kept attested forgetting,
/// retention, wing trust, admission review and verify off every plane. The
/// one deletion a fleet operator could reach was `DELETE /t/…/drawers/{id}`
/// — the receipt-LESS one. A right-to-erasure request answered through the
/// orchestrator produced a bare tombstone while the surface next door
/// produced a signed-able attestation; that is the asymmetry this closes.
///
/// They live on the ADMIN plane, never the data plane: a tenant token must
/// not rule on the admission queue that screened its own writes, nor assign
/// the trust its wings are floored by. Same boundary the engine draws
/// between `/v1` and MCP, one level up.
const OPS_ROUTES: &[(&str, &str)] = &[
    ("POST", "verify"),
    ("GET", "supersessions"),
    ("POST", "forget"),
    // **Minting without checking is the asymmetry above, one step on**
    // (ROADMAP O14). `forget` has been forwardable since this table was
    // written; verifying the receipt it returns was reachable from nowhere
    // in a fleet, because the engine had no route for it at all. A
    // right-to-erasure receipt an operator cannot verify through the only
    // door they have is the same defect this table's own comment describes.
    ("POST", "verify-forgetting"),
    ("GET", "admission"),
    ("POST", "admission"),
    ("GET", "retention"),
    ("POST", "retention"),
    ("POST", "retention/sweep"),
    ("GET", "trust"),
    ("POST", "trust"),
    // Tightening the manifest rollback anchor (engine R3). Unlike the vault
    // KEY rotation two lines of prose up, this one is safe while the engine
    // is serving: it fsyncs a manifest that names the head the database
    // already committed, and the engine refuses it on a read-only handle.
    ("POST", "anchor"),
];

/// **What the ops plane deliberately does NOT reach, and why.**
///
/// `OPERATOR_ONLY` in the engine's `parity.rs` records the MCP absences and
/// nothing recorded these: the CLI↔`/v1`↔ops axes had no counted inventory
/// at all, so four capabilities were missing from the ops vocabulary with no
/// written reason and no way to tell an omission from a boundary. That is
/// the same "is it a boundary or a drift" question the whole drift audit
/// exists to answer, on the axis nobody had counted.
///
/// Gated below, in both directions, against the engine's own `/v1` surface.
#[cfg(test)]
pub(crate) const OPS_DELIBERATELY_ABSENT: &[(&str, &str)] = &[
    // A KEY rotation invalidates every in-flight assertion and re-seals the
    // whole vault. It belongs on the engine host, run by someone who can
    // see the process, not on a control plane that would fire it remotely
    // while the engine serves.
    (
        "rotate",
        "belongs on the engine host, not a remote control plane",
    ),
    // Content. The ops plane is an OPERATOR plane; drawer reads are the
    // tenant's own data and travel through `/t/*` under the tenant's token,
    // never through an admin bearer that can reach every tenant.
    (
        "drawers",
        "content belongs to the tenant's own token, not the admin bearer",
    ),
    (
        "search",
        "content belongs to the tenant's own token, not the admin bearer",
    ),
    // Whole-corpus movement. `migrate` is the supported path and it is
    // count-verified end to end; a bare export or import through the ops
    // plane would be the same egress with none of that.
    (
        "export",
        "use `migrate`, which count-verifies; a bare egress has no such check",
    ),
    (
        "import",
        "use `migrate`, which count-verifies; a bare ingest has no such check",
    ),
    // Distillation calls an LLM and WRITES facts. It is a content-producing
    // operation, not an operator one, and it needs `UNDERCROFT_LLM_*` on the
    // engine host anyway.
    (
        "refine",
        "content-producing, and its LLM configuration lives on the engine",
    ),
    // The agent's own audit view. `ops` is the operator door; the operator
    // reads history on the engine, where the scope is `Operator` rather than
    // the fenced `Agent`.
    (
        "history",
        "operator history is read on the engine, at operator scope",
    ),
];

/// The operator-plane vocabulary as NAMES, for the CLI (ROADMAP C9).
///
/// Each alias resolves to a pair that must also be in [`OPS_ROUTES`] —
/// asserted by test — so the scripted door and the HTTP door are the same
/// door. A name rather than a raw `<METHOD> <subpath>` passthrough on
/// purpose: a passthrough would be a second, wider vocabulary the moment
/// someone typed a subpath the proxy does not allow.
pub(crate) fn ops_alias(op: &str) -> Option<(&'static str, &'static str)> {
    Some(match op {
        "verify" => ("POST", "verify"),
        "anchor" => ("POST", "anchor"),
        "supersessions" => ("GET", "supersessions"),
        "admission" => ("GET", "admission"),
        "admission-rule" => ("POST", "admission"),
        "trust" => ("GET", "trust"),
        "trust-set" => ("POST", "trust"),
        "retention" => ("GET", "retention"),
        "retention-set" => ("POST", "retention"),
        "retention-sweep" => ("POST", "retention/sweep"),
        "forget" => ("POST", "forget"),
        "verify-forgetting" => ("POST", "verify-forgetting"),
        _ => return None,
    })
}

fn ops_route_ok(method: &str, subpath: &str) -> bool {
    OPS_ROUTES
        .iter()
        .any(|(m, s)| *m == method && *s == subpath)
}

fn bearer(req: &tiny_http::Request) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
        .map(str::to_string)
}

fn json_response(status: u16, body: &serde_json::Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let bytes = body.to_string().into_bytes();
    Response::from_data(bytes)
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", "application/json").expect("header"))
}

fn err_response(status: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(status, &serde_json::json!({ "error": msg }))
}

/// Answer a control-plane state failure with the class the error itself
/// carries. **One place**, because the previous arrangement mapped per
/// CALL SITE: `instance_add` answered 400, `tenant_rotate_token` 404,
/// `instance_remove` 409, and every `instance_creds` failure a flat 502
/// "instance unavailable" — so the status described which line raised the
/// error rather than what happened, and a contended SQLite (`SQLITE_BUSY`;
/// this database runs WAL + `synchronous=FULL`) was reported to the
/// operator as a bad request, a missing tenant or a conflict depending on
/// where it landed. The message is the error's own, so `Unsealable` —
/// which names its remedy — survives instead of being flattened.
fn state_error_response(e: &StateError) -> Response<std::io::Cursor<Vec<u8>>> {
    err_response(e.status(), &e.to_string())
}

/// What this process is allowed to serve: the single writer (full admin
/// plane + console), or a read replica (data plane only, state read-only).
pub enum Role<'a> {
    Writer { admin_token: &'a str },
    ReadReplica,
}

/// Run the proxy loop forever.
/// Bring up the control plane's metrics endpoint on its own address, if one
/// is declared. `Ok(())` with nothing bound is the default and the common
/// case.
///
/// **Refuses rather than degrades**, per the configuration doctrine: a
/// non-loopback address without `UNDERCROFT_ORCH_METRICS_TOKEN` is refused
/// here, before any port opens, exactly as the engine refuses a
/// network-exposed bind without its bearer. Silently binding it open would
/// publish a fleet's request rates to anyone who could reach it.
fn spawn_metrics_listener() -> anyhow::Result<()> {
    let Some(addr) = undercroft_config::resolve_metrics_addr(
        std::env::var("UNDERCROFT_ORCH_METRICS_ADDR")
            .ok()
            .as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?
    else {
        return Ok(());
    };
    let token = undercroft_config::resolve_metrics_token(
        &addr,
        std::env::var("UNDERCROFT_ORCH_METRICS_TOKEN")
            .ok()
            .as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let server =
        Server::http(&addr).map_err(|e| anyhow::anyhow!("bind metrics listener {addr}: {e}"))?;
    eprintln!("undercroft-orchestrator metrics listening on http://{addr}/metrics");
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let authed = match &token {
                None => true,
                Some(expected) => request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
                    .is_some_and(|p| bytes_eq(p.as_bytes(), expected.as_bytes())),
            };
            if !authed {
                undercroft_obs::orch_auth_rejected("metrics");
                let _ =
                    request.respond(Response::from_string("unauthorized").with_status_code(401));
                continue;
            }
            if request.url().split('?').next().unwrap_or("") != "/metrics" {
                let _ = request.respond(Response::from_string("not found").with_status_code(404));
                continue;
            }
            let (code, body) = match undercroft_obs::render_prometheus() {
                Some(text) => (200, text),
                None => (
                    503,
                    "metrics require building undercroft-orchestrator with --features telemetry (this binary was built without it)
"
                        .to_string(),
                ),
            };
            let ct = Header::from_bytes(&b"Content-Type"[..], &b"text/plain; version=0.0.4"[..])
                .expect("static header");
            let _ = request.respond(
                Response::from_string(body)
                    .with_status_code(code)
                    .with_header(ct),
            );
        }
    });
    Ok(())
}

/// Constant-time byte comparison for the metrics bearer — the same property
/// every other secret comparison in this fleet already has.
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

pub fn serve(orch: &Orch, addr: &str, role: Role<'_>) -> anyhow::Result<()> {
    // Resolved BEFORE the bind: a refusal about configuration must not
    // arrive after the port is open and a load balancer has started
    // sending traffic to it.
    let limiter = RateLimiter::from_env()?;
    // The metrics listener is resolved before the bind too, and on its OWN
    // address (ROADMAP O20). Everything else this function serves — /healthz,
    // /t/*, /admin/*, /ui — shares one port that a fleet must expose to
    // tenants, so a `/metrics` PATH there would be network-exposed in every
    // real deployment and "loopback is the gate" would be a comfort
    // production never gets. A separate listener lets the data plane sit on
    // 0.0.0.0 while metrics sit on 127.0.0.1 for a sidecar scraper, and it is
    // what makes `--read-replica` work unchanged: the replica resolves no
    // admin token and needs none for this.
    spawn_metrics_listener()?;
    let server = Server::http(addr).map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?;
    let mode = match role {
        Role::Writer { .. } => "writer",
        Role::ReadReplica => "read replica",
    };
    eprintln!("undercroft-orchestrator ({mode}) listening on http://{addr}");
    for mut request in server.incoming_requests() {
        let method = request.method().clone();
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        // Kept, not discarded: `limit`, `offset`, `wing`, `room` and every
        // other engine query parameter live here, and splitting them off
        // without forwarding them meant a paginating tenant got page one
        // forever at HTTP 200.
        let query = url
            .split_once('?')
            .map(|(_, q)| q.to_string())
            .unwrap_or_default();
        let mut body = Vec::new();
        use std::io::Read;
        let _ = request
            .as_reader()
            .take(256 * 1024 * 1024)
            .read_to_end(&mut body);

        let target = Target {
            path: &path,
            query: &query,
        };
        let started = std::time::Instant::now();
        let response = route(orch, &role, &limiter, &request, &method, target, &body);
        // A route CLASS from a closed set, never the URL: the forwarded query
        // string carries `wing=` and `room=`, which is exactly what the
        // engine's own telemetry suppresses for sealed vaults.
        let route_class = if path == "/healthz" {
            "healthz"
        } else if path == "/ui" {
            "ui"
        } else if path == "/admin" || path.starts_with("/admin/") {
            "admin"
        } else if path.starts_with("/t/") {
            "tenant"
        } else {
            "other"
        };
        undercroft_obs::orch_request(route_class, response.status_code().0, started.elapsed());
        let _ = request.respond(response);
    }
    Ok(())
}

/// One request's target: the path the router matches on and the query the
/// data plane must forward. Bundled because they always travel together —
/// splitting the query off and forwarding only the path is exactly the
/// defect this pair exists to prevent.
#[derive(Clone, Copy)]
struct Target<'a> {
    path: &'a str,
    query: &'a str,
}

fn route(
    orch: &Orch,
    role: &Role<'_>,
    limiter: &RateLimiter,
    request: &tiny_http::Request,
    method: &Method,
    target: Target<'_>,
    body: &[u8],
) -> Response<std::io::Cursor<Vec<u8>>> {
    let Target { path, query } = target;
    // Unauthenticated liveness, mirroring the engine. `mode` + `last_write`
    // let an operator diff a replica against the writer to read the lag.
    if method == &Method::Get && path == "/healthz" {
        let mode = match role {
            Role::Writer { .. } => "writer",
            Role::ReadReplica => "read-replica",
        };
        let last_write = orch.last_write().ok().flatten();
        return json_response(
            200,
            &serde_json::json!({ "ok": true, "mode": mode, "last_write": last_write }),
        );
    }

    if let Some(sub) = path.strip_prefix("/t/") {
        // A read replica serves READS. The data plane dispatched before the
        // writer-only check below, and `data_plane` never took a role, so
        // `POST /t/drawers` and `DELETE /t/drawers/{id}` were proxied to the
        // engine and answered 200 — while `require_writable()`, the only code
        // that says "mutations belong to the writer", was reachable only from
        // the replica's own state writes, which the data plane never performs.
        // It was therefore unreachable over HTTP in either role.
        //
        // Decided in FRONT of dispatch and failing CLOSED, exactly as the
        // engine's `mutates()` does: anything that is not a GET is a write
        // unless named, so a data-plane route added later is refused on a
        // replica until someone classifies it deliberately. `POST …/search`
        // is the one named read, matching the engine's own exception list.
        if matches!(role, Role::ReadReplica) {
            let sub_path = sub.split('?').next().unwrap_or("");
            let is_read = method == &Method::Get || sub_path == "search";
            if !is_read {
                return err_response(
                    403,
                    "read replica: writes belong to the writer — point mutations at \
                     the writer's /t/ endpoint",
                );
            }
        }
        return data_plane(orch, limiter, request, method, sub, query, body);
    }
    if path == "/t" || path == "/t/" {
        return err_response(404, "missing subpath");
    }

    // Everything below is writer-only surface.
    let admin_token = match role {
        Role::Writer { admin_token } => *admin_token,
        Role::ReadReplica => {
            if path == "/ui" || path == "/admin" || path.starts_with("/admin/") {
                return err_response(
                    403,
                    "read replica: admin plane and console live on the writer",
                );
            }
            return err_response(404, "not found");
        }
    };

    // The fleet console — like the engine's /ui, a self-contained static
    // page carrying no secrets: the operator pastes the admin token into
    // the page, which attaches it to its /admin/* fetches.
    if method == &Method::Get && path == "/ui" {
        return Response::from_data(include_str!("ui.html").as_bytes().to_vec())
            .with_header(
                Header::from_bytes("Content-Type", "text/html; charset=utf-8")
                    .expect("static header"),
            )
            // no-cache: console updates must arrive on a plain reload.
            .with_header(Header::from_bytes("Cache-Control", "no-cache").expect("static header"));
    }

    if path == "/admin" || path.starts_with("/admin/") {
        // Admin gate first; uniform 401.
        match bearer(request) {
            Some(t) if ct_eq(&t, admin_token) => {}
            _ => {
                undercroft_obs::orch_auth_rejected("admin");
                return err_response(401, "unauthorized");
            }
        }
        return admin_plane(orch, method, path, body);
    }

    err_response(404, "not found")
}

// -- data plane -------------------------------------------------------------

fn data_plane(
    orch: &Orch,
    limiter: &RateLimiter,
    request: &tiny_http::Request,
    method: &Method,
    subpath: &str,
    query: &str,
    body: &[u8],
) -> Response<std::io::Cursor<Vec<u8>>> {
    let Some(token) = bearer(request) else {
        undercroft_obs::orch_auth_rejected("tenant");
        return err_response(401, "unauthorized");
    };
    let tenant = match orch.tenant_by_token(&token) {
        Ok(Some(t)) => t,
        Ok(None) => {
            undercroft_obs::orch_auth_rejected("tenant");
            return err_response(401, "unauthorized");
        }
        // The typed class, not a bare 500. A tampered token table
        // (`Unsealable`, permanent, 409 everywhere else) answered 500 here —
        // the class that tells a caller to retry.
        Err(e) => return state_error_response(&e),
    };
    // Rate limit after auth (unauthenticated traffic never occupies a
    // window), per tenant — one noisy tenant can't starve the rest.
    if !limiter.allow(&tenant.id) {
        // An operator who declared UNDERCROFT_ORCH_RATE_LIMIT had no surface
        // saying it ever fired: the refusal happens here and no engine sees
        // the request. Unlabelled on purpose — WHICH tenant is rate-limited
        // is a per-tenant fact and belongs on the admin plane.
        undercroft_obs::orch_rate_limited();
        return err_response(429, "rate limited");
    }
    if !data_subpath_ok(subpath) {
        // Say WHICH kind of "no". A bare "unknown route" made an operator
        // capability that exists one plane over look like a capability the
        // product does not have — the reason forgetting, retention, trust,
        // admission and verify were reported as missing rather than as
        // admin-plane routes.
        if ops_route_ok(method.as_str(), subpath) {
            return err_response(
                404,
                "operator route: not reachable with a tenant token — \
                 POST/GET /admin/tenants/{id}/ops/<subpath> on the writer",
            );
        }
        return err_response(404, "unknown route");
    }
    // The reading half of the boundary [`OPS_ROUTES`] already draws for the
    // ruling half.
    if request_names_reserved_wing(subpath, query, body) {
        return err_response(404, QUARANTINE_REFUSAL);
    }
    let creds = match orch.instance_creds(&tenant.instance) {
        Ok(c) => c,
        // Was a flat 502 "instance unavailable", which is a claim about the
        // ENGINE — and `instance_creds` performs no network I/O at all. A
        // wrong `UNDERCROFT_ORCH_KEY` or a tampered credential blob is a
        // permanent, operator-fixable condition whose message names the
        // remedy; 502 threw the message away and told every retry layer the
        // condition was transient.
        Err(e) => return state_error_response(&e),
    };
    let content_type = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Content-Type"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_else(|| "application/json".to_string());
    // A single-drawer request resolves its wing at the engine before it is
    // allowed to act. For a GET the probe IS the answer — it is the same
    // request — so a read costs no extra round trip and only a write pays a
    // lookup, which is what the fence is worth.
    if single_drawer_route(subpath) {
        let probe = engine::vault_request(
            &creds,
            &tenant.vault,
            "GET",
            subpath,
            if method == &Method::Get { query } else { "" },
            "application/json",
            &[],
        );
        match probe {
            Ok(r) => {
                if r.status == 200 && drawer_body_is_quarantined(&r.body) {
                    return err_response(404, QUARANTINE_REFUSAL);
                }
                if method == &Method::Get {
                    return relay(r);
                }
            }
            Err(e) => return engine_response(&e),
        }
    }
    match engine::vault_request(
        &creds,
        &tenant.vault,
        method.as_str(),
        subpath,
        query,
        &content_type,
        body,
    ) {
        Ok(r) => {
            // An export names no wing and carries every row, so neither the
            // name fence nor the drawer probe can see it. It is REFUSED
            // rather than filtered: the manifest's `payload_sha256` covers
            // the payload, so dropping records here would hand the tenant an
            // artifact its own re-import rejects — a silent corruption in
            // place of a leak. Refusing and naming the remedy is the branch
            // `migrate_tenant` already takes when a copy is unfaithful.
            // Inert wherever the screen is off (default), since nothing
            // lands in the wing.
            if subpath == "export" && r.status == 200 && export_carries_reserved_wing(&r.body) {
                return err_response(
                    409,
                    "export carries drawer(s) in quarantine-pending, and the manifest \
                     digest covers the payload, so they cannot be filtered out of it \
                     without invalidating the artifact. Rule on the queue first \
                     (GET/POST /admin/tenants/{id}/ops/admission on the writer), then \
                     export",
                );
            }
            relay(r)
        }
        Err(e) => engine_response(&e),
    }
}

/// Relay one engine response verbatim — status, body, and its own
/// content type (falling back to JSON when the engine sent something the
/// header codec refuses).
fn relay(r: engine::EngineResponse) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(r.body)
        .with_status_code(r.status)
        .with_header(
            Header::from_bytes("Content-Type", r.content_type.as_bytes()).unwrap_or_else(|_| {
                Header::from_bytes("Content-Type", "application/json").unwrap()
            }),
        )
}

// -- admin plane ------------------------------------------------------------

fn admin_plane(
    orch: &Orch,
    method: &Method,
    path: &str,
    body: &[u8],
) -> Response<std::io::Cursor<Vec<u8>>> {
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    let body_json =
        || -> serde_json::Value { serde_json::from_slice(body).unwrap_or(serde_json::Value::Null) };
    let s = |v: &serde_json::Value, k: &str| -> Option<String> {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };

    match (method.as_str(), segs.as_slice()) {
        ("POST", ["admin", "instances"]) => {
            let v = body_json();
            let (Some(name), Some(url), Some(bearer), Some(secret)) = (
                s(&v, "name"),
                s(&v, "url"),
                s(&v, "bearer"),
                s(&v, "assertion_secret"),
            ) else {
                return err_response(400, "need name, url, bearer, assertion_secret");
            };
            match orch.instance_add(&name, &url, &bearer, &secret) {
                Ok(()) => json_response(200, &serde_json::json!({ "added": name })),
                Err(e) => state_error_response(&e),
            }
        }
        ("GET", ["admin", "instances"]) => match orch.instance_list() {
            Ok(list) => json_response(200, &serde_json::json!({ "instances": list })),
            Err(e) => state_error_response(&e),
        },
        // `healthy` keeps its meaning (only a 200 from `/healthz` is
        // healthy) and the VERDICT travels beside it, because three
        // different conditions used to arrive as the same `false`: the
        // engine is down, the engine answered something else, and this
        // process refused to speak to it at all. Only the third is
        // actionable here, and it was the one indistinguishable from an
        // outage. `state` is additive; `refused` carries the reason and is
        // absent unless there is one.
        ("GET", ["admin", "instances", name, "health"]) => match orch.instance_creds(name) {
            Ok(c) => {
                let h = engine::health(&c.url);
                let mut body = serde_json::json!({
                    "name": name,
                    "healthy": h.is_healthy(),
                    "state": match h {
                        engine::Health::Healthy => "healthy",
                        engine::Health::Unhealthy => "unhealthy",
                        engine::Health::Unreachable => "unreachable",
                        engine::Health::Refused(_) => "refused",
                    },
                });
                if let Some(why) = h.refusal() {
                    body["refused"] = serde_json::Value::String(why.to_string());
                }
                json_response(200, &body)
            }
            Err(e) => state_error_response(&e),
        },
        // A delete of a name that is not registered is NOT a success. This
        // answered `200 {"removed": false}` — verbatim the anti-pattern the
        // engine eradicated on `DELETE /v1/…/drawers/{id}` — and `ui.html`
        // toasts "removed <name>" on any 2xx, so a decommission script and
        // a human were both told the teardown worked while the instance
        // stayed registered and routing. `removed` stays for the callers
        // that read it, and is now always `true` on a 200.
        ("DELETE", ["admin", "instances", name]) => match orch.instance_remove(name) {
            Ok(true) => json_response(200, &serde_json::json!({ "removed": true })),
            Ok(false) => err_response(404, &format!("no instance {name:?}")),
            Err(e) => state_error_response(&e),
        },
        ("POST", ["admin", "tenants"]) => {
            let v = body_json();
            let Some(name) = s(&v, "name") else {
                return err_response(400, "need name");
            };
            let level = s(&v, "level").unwrap_or_else(|| "sealed".to_string());
            let instance = match s(&v, "instance") {
                Some(i) => i,
                None => match orch.instance_least_loaded() {
                    Ok(Some(i)) => i,
                    Ok(None) => return err_response(409, "no instances registered"),
                    Err(e) => return state_error_response(&e),
                },
            };
            create_tenant(orch, &name, &instance, &level)
        }
        ("GET", ["admin", "tenants"]) => match orch.tenant_list() {
            Ok(list) => json_response(200, &serde_json::json!({ "tenants": list })),
            Err(e) => state_error_response(&e),
        },
        ("GET", ["admin", "tenants", id, "stats"]) => tenant_stats(orch, id),
        ("DELETE", ["admin", "tenants", id]) => delete_tenant(orch, id),
        ("POST", ["admin", "tenants", id, "rotate"]) => match orch.tenant_rotate_token(id) {
            // The fresh token appears in this response and nowhere else;
            // the old one is already dead.
            Ok(token) => json_response(200, &serde_json::json!({ "tenant": id, "token": token })),
            Err(e) => state_error_response(&e),
        },
        ("POST", ["admin", "tenants", id, "migrate"]) => {
            let v = body_json();
            let Some(to) = s(&v, "to") else {
                return err_response(400, "need to");
            };
            let keep = v.get("keep_source").and_then(serde_json::Value::as_bool) == Some(true);
            match migrate_tenant(orch, id, &to, keep) {
                Ok(summary) => json_response(200, &summary),
                // **The `class` survives.** This stringified the engine's
                // classed body into `error`, so the one field this fleet's
                // docs tell a client to read was lost on the one route that
                // documents it — and `AlreadyThere`, `Unfaithful` and a
                // relayed integrity 409 became indistinguishable.
                Err(MigrateError::Engine(status, msg)) => {
                    let _ = status;
                    engine_response(&msg)
                }
                Err(e) => err_response(e.status(), &e.to_string()),
            }
        }
        (m, ["admin", "tenants", id, "ops", rest @ ..]) => {
            tenant_ops(orch, m, id, &rest.join("/"), body)
        }
        _ => err_response(404, "unknown admin route"),
    }
}

/// Forward one operator capability to the tenant's engine. The verb and
/// subpath must be in [`OPS_ROUTES`]; the response relays verbatim, so the
/// engine's own status classes and bodies (a 400 for a bad wing name, a 409
/// for an integrity failure, the `ForgetAttestation` JSON) reach the
/// operator unchanged rather than being re-invented here.
fn tenant_ops(
    orch: &Orch,
    method: &str,
    tenant_id: &str,
    subpath: &str,
    body: &[u8],
) -> Response<std::io::Cursor<Vec<u8>>> {
    if !ops_route_ok(method, subpath) {
        // Named, not a bare 404: the data plane's "unknown route" was
        // indistinguishable from "does not exist", which is how these
        // capabilities stayed invisible.
        return err_response(
            404,
            &format!(
                "{method} {subpath} is not an operator route; allowed: {}",
                OPS_ROUTES
                    .iter()
                    .map(|(m, s)| format!("{m} {s}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    let tenant = match orch.tenant_get(tenant_id) {
        Ok(Some(t)) => t,
        Ok(None) => return err_response(404, "unknown tenant"),
        Err(e) => return state_error_response(&e),
    };
    let creds = match orch.instance_creds(&tenant.instance) {
        Ok(c) => c,
        Err(e) => return state_error_response(&e),
    };
    // No quarantine fence here, deliberately: this IS the operator plane,
    // and `GET/POST …/ops/admission` — the reviewer's own view of the queue
    // — is one of the routes it exists to carry. The fence belongs to the
    // tenant token, not to the capability.
    match engine::vault_request(
        &creds,
        &tenant.vault,
        method,
        subpath,
        "",
        "application/json",
        body,
    ) {
        Ok(r) => relay(r),
        Err(e) => engine_response(&e),
    }
}

fn create_tenant(
    orch: &Orch,
    name: &str,
    instance: &str,
    level: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let creds = match orch.instance_creds(instance) {
        Ok(c) => c,
        Err(e) => return state_error_response(&e),
    };
    // Record the mapping first (so a crash can't leave an unmapped vault
    // holding data), then create the vault; roll the row back on failure.
    let (tenant, token) = match orch.tenant_create(name, instance, level) {
        Ok(x) => x,
        Err(e) => return state_error_response(&e),
    };
    if let Err(e) = engine::create_vault(&creds, &tenant.vault, level) {
        let _ = orch.tenant_delete(&tenant.id);
        return engine_response(&e);
    }
    // The token appears in this response and nowhere else, ever.
    json_response(
        200,
        &serde_json::json!({ "tenant": tenant, "token": token }),
    )
}

/// Metadata-only stats for one tenant's vault, fetched with the stored
/// engine creds and relayed verbatim — the admin plane sees counts, sizes,
/// and the chain head; drawer content stays unreachable from here (the
/// data-plane allowlist is unchanged and requires the tenant's own token).
fn tenant_stats(orch: &Orch, id: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let tenant = match orch.tenant_get(id) {
        Ok(Some(t)) => t,
        Ok(None) => return err_response(404, "unknown tenant"),
        Err(e) => return state_error_response(&e),
    };
    let creds = match orch.instance_creds(&tenant.instance) {
        Ok(c) => c,
        Err(e) => return state_error_response(&e),
    };
    match engine::vault_request(
        &creds,
        &tenant.vault,
        "GET",
        "stats",
        "",
        "application/json",
        &[],
    ) {
        Ok(r) => Response::from_data(r.body)
            .with_status_code(r.status)
            .with_header(
                Header::from_bytes("Content-Type", "application/json").expect("static header"),
            ),
        Err(e) => engine_response(&e),
    }
}

fn delete_tenant(orch: &Orch, id: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let tenant = match orch.tenant_get(id) {
        Ok(Some(t)) => t,
        Ok(None) => return err_response(404, "unknown tenant"),
        Err(e) => return state_error_response(&e),
    };
    // This was `if let Ok(creds) = …` with **no else**: a credential
    // failure — a tampered blob, a wrong `UNDERCROFT_ORCH_KEY`, an unknown
    // instance, a sqlite error — skipped the vault deletion in silence and
    // then deleted the mapping row anyway, answering `200 {"deleted": id}`.
    // So an erasure request was reported as done while the engine still
    // held every drawer AND the only record of which vault belonged to that
    // tenant was gone: the data both retained and unattributable. The CLI
    // path has always used `?` and aborted; this is that, on the surface a
    // compliance workflow actually drives.
    let creds = match orch.instance_creds(&tenant.instance) {
        Ok(c) => c,
        Err(e) => return state_error_response(&e),
    };
    if let Err(e) = engine::delete_vault(&creds, &tenant.vault) {
        return engine_response(&e);
    }
    match orch.tenant_delete(id) {
        Ok(true) => json_response(200, &serde_json::json!({ "deleted": id })),
        // The row went away between the lookup and here (a concurrent
        // delete). The vault is gone either way; say so honestly rather
        // than claiming this call performed the erasure.
        Ok(false) => err_response(404, "unknown tenant"),
        Err(e) => state_error_response(&e),
    }
}

/// How a migration failed, **as a class**.
///
/// `migrate_tenant` used to return `Result<Value, String>` and the handler
/// answered **502 for every one of them**: an unknown tenant, a caller
/// naming a destination that is not registered, a tenant already on the
/// target, an integrity verdict from the count check, and a genuinely
/// unreachable engine were one undifferentiated failure. 502 is the status
/// retry layers treat as transient, so the four that can never succeed on
/// a retry were hammered forever while the operator was told the engine
/// was down.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error("{0}")]
    State(#[from] StateError),
    #[error("unknown tenant {0:?}")]
    UnknownTenant(String),
    /// The destination is a value the CALLER supplied in the body, so an
    /// unregistered one is malformed input (400) — not a missing resource
    /// (404), which is what the tenant in the path would be.
    #[error("unknown destination instance {0:?} — register it first")]
    UnknownDestination(String),
    #[error("tenant is already on that instance")]
    AlreadyThere,
    /// The engine answered and its answer was a refusal; the relayed status
    /// rides along so an engine 409 stays a 409.
    #[error("{1}")]
    Engine(u16, String),
    /// The copy is not faithful, or the source must not be dropped. The
    /// source is left authoritative and the remedy is a real decision, not
    /// a retry.
    #[error("{0}")]
    Unfaithful(String),
}

impl MigrateError {
    pub(crate) fn status(&self) -> u16 {
        match self {
            MigrateError::State(e) => e.status(),
            MigrateError::UnknownTenant(_) => 404,
            MigrateError::UnknownDestination(_) => 400,
            MigrateError::AlreadyThere => 409,
            MigrateError::Engine(status, _) => *status,
            MigrateError::Unfaithful(_) => 409,
        }
    }
}

/// Turn one of `engine.rs`'s stringified failures back into a class.
///
/// `engine.rs` renders a relayed refusal with the status in parentheses
/// (`engine import failed (409): …`), so recovering it here is a coupling
/// to that formatting — deliberate, and stated: the alternative is a typed
/// engine client, which is the right fix and a much larger one. A 4xx is
/// the ENGINE's verdict on the request and is kept verbatim; anything else
/// (a transport failure, an engine 5xx) is what 502 actually means.
/// Turn an `engine::*` String failure into a response that keeps what the
/// engine said.
///
/// **Every site used a bare 502**, so the engine's `409 "vault already
/// exists"` and its co-resident delete refusal arrived as the one status
/// retry layers hammer — the exact defect `engine_err` was written to fix,
/// applied on `migrate` and on none of its neighbours. A local transport
/// REFUSAL was reported as a gateway failure too: `agent()` declines before
/// a byte moves, and `health` says `refused` while every other plane said
/// "bad gateway".
///
/// The classed body travels as `class` rather than being stringified into
/// `error`, because that is the field this fleet's own docs tell a client to
/// read and the migrate route was losing it.
fn engine_response(msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let e = engine_err(msg.to_string());
    let MigrateError::Engine(status, _) = &e else {
        return err_response(502, msg);
    };
    // A refusal this process made about itself is not a gateway failure.
    // `undercroft-net`'s errors name the client and say "no override".
    if *status == 502 && (msg.contains("no override") || msg.contains("trust root")) {
        return err_response(
            502,
            &format!("{msg} (this is a local transport refusal, not an unreachable engine)"),
        );
    }
    let class = msg
        .find('{')
        .and_then(|i| serde_json::from_str::<serde_json::Value>(&msg[i..]).ok())
        .and_then(|v| v.get("class").and_then(|c| c.as_str()).map(str::to_string));
    match class {
        Some(c) => json_response(*status, &serde_json::json!({ "error": msg, "class": c })),
        None => err_response(*status, msg),
    }
}

fn engine_err(msg: String) -> MigrateError {
    let b = msg.as_bytes();
    for i in 0..b.len().saturating_sub(4) {
        if b[i] == b'(' && b[i + 4] == b')' && b[i + 1..i + 4].iter().all(u8::is_ascii_digit) {
            if let Ok(code) = msg[i + 1..i + 4].parse::<u16>() {
                if (400..500).contains(&code) {
                    return MigrateError::Engine(code, msg);
                }
            }
        }
    }
    MigrateError::Engine(502, msg)
}

/// Migration: export (artifact-carrying, v0.18) → import on the target →
/// **count-verified** → mapping flip → source delete (unless kept). Any
/// failure before the flip leaves the tenant untouched on its source.
/// Shared by the HTTP admin plane and the CLI `migrate` subcommand.
pub(crate) fn migrate_tenant(
    orch: &Orch,
    id: &str,
    to: &str,
    keep_source: bool,
) -> Result<serde_json::Value, MigrateError> {
    let tenant = orch
        .tenant_get(id)?
        .ok_or_else(|| MigrateError::UnknownTenant(id.to_string()))?;
    if tenant.instance == to {
        return Err(MigrateError::AlreadyThere);
    }
    let src = orch.instance_creds(&tenant.instance)?;
    let dst = orch.instance_creds(to).map_err(|e| match e {
        StateError::NotFound(_) => MigrateError::UnknownDestination(to.to_string()),
        other => MigrateError::State(other),
    })?;

    let ndjson = engine::export_vault(&src, &tenant.vault).map_err(engine_err)?;
    // The export leads with a manifest line since 0.43.0, and it DECLARES
    // the record counts — the count-verify below checks against that
    // declaration rather than a raw line count, which the manifest line
    // and the typed KG/tunnel records would inflate. A legacy engine (no
    // manifest) keeps the old contract: every non-empty line is a drawer.
    let manifest = ndjson
        .lines()
        .next()
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v.get("undercroft_manifest").cloned());
    let expected: (u64, u64, u64, u64) = match &manifest {
        Some(m) => {
            let n = |k: &str| m["counts"][k].as_u64().unwrap_or(0);
            (
                n("drawers"),
                n("kg_triples"),
                n("kg_entities"),
                n("tunnels"),
            )
        }
        None => (
            ndjson.lines().filter(|l| !l.trim().is_empty()).count() as u64,
            0,
            0,
            0,
        ),
    };
    // The tenant's OWN level, not a literal. This was the only hard-coded
    // one of the three `create_vault` call sites, and since no surface can
    // change a vault's level afterwards, migrating an `hmac-only` tenant
    // silently and permanently converted it (ROADMAP C3). It fails toward
    // the stronger level, so this was a contract defect and not a security
    // one — which is exactly why nothing noticed.
    //
    // The export manifest declares a level too, and it is used as a
    // CROSS-CHECK that refuses on disagreement, never as the source: taking
    // it would make the destination's posture a function of bytes the
    // source engine produced, which docs/LABELS.md forbids.
    let declared = manifest
        .as_ref()
        .and_then(|m| m["level"].as_str())
        .unwrap_or(tenant.level.as_str());
    if declared != tenant.level {
        return Err(MigrateError::Unfaithful(format!(
            "the source vault exports level {declared:?} while the control plane has this tenant recorded as {:?} — refusing rather than choosing one. Reconcile the record before migrating",
            tenant.level
        )));
    }
    engine::create_vault(&dst, &tenant.vault, &tenant.level).map_err(engine_err)?;
    // C4: the import-failure branch returned early with no cleanup where
    // both sibling branches below call `delete_vault`, so a retry answered
    // 409 "already exists" with a cause that named nothing.
    let got = engine::import_vault(&dst, &tenant.vault, &ndjson).map_err(|e| {
        let _ = engine::delete_vault(&dst, &tenant.vault);
        engine_err(e)
    })?;
    // A diverted drawer is COUNTED in `imported` but is not filed where the
    // payload aimed it: it sits in `quarantine-pending`, excluded from
    // search, recent and listing. So an equal count is not a faithful copy,
    // and treating it as one is how this deleted the source vault while the
    // destination held part of the corpus in quarantine. Refuse before the
    // mapping flip — the same "leave the source authoritative" branch a
    // count mismatch already takes — and name the remedy, because the
    // operator's fix is a real decision (rule on the queue, or migrate with
    // `keep_source`), not a retry.
    // Consulted only when the source is about to be DROPPED. The first
    // version of this guard fired unconditionally and then named two
    // remedies, neither of which worked: it deleted the destination vault one
    // line before telling the operator to "rule on the queue there", and it
    // ran ahead of `keep_source`, so "re-run with keep_source" reached the
    // identical refusal. With a rate screen declared on the destination —
    // where a migration is by definition a burst from one writer identity —
    // that made migration permanently impossible with no escape hatch.
    //
    // With `keep_source`, nothing is lost: the mapping flips, the source
    // stays, and the response carries the count so the operator can rule on
    // the destination's queue at their leisure. Without it, refuse and remove
    // the partial copy so the retry is clean, and name the remedy that
    // actually exists.
    if got.quarantined > 0 && !keep_source {
        let _ = engine::delete_vault(&dst, &tenant.vault);
        return Err(MigrateError::Unfaithful(format!(
            "destination screened {} of {} drawer(s) into quarantine-pending, so \
             the copy is not faithful and the source must not be dropped. The \
             partial copy was removed so this can be retried: re-run with \
             keep_source=true, rule on the destination's queue (`admission \
             list`/`allow`), then drop the source yourself once it is clean",
            got.quarantined, got.drawers
        )));
    }
    let counts_match = got.drawers == expected.0
        && (manifest.is_none()
            || (got.kg_triples == expected.1
                && got.kg_entities == expected.2
                && got.tunnels == expected.3));
    if !counts_match {
        // Leave the source authoritative; remove the partial copy.
        let _ = engine::delete_vault(&dst, &tenant.vault);
        return Err(MigrateError::Unfaithful(format!(
            "import count mismatch (drawers {} of {}, kg {} of {}) — source left authoritative",
            got.drawers, expected.0, got.kg_triples, expected.1
        )));
    }
    let imported = got.drawers;
    orch.tenant_set_instance(id, to)?;
    let source_deleted = if keep_source {
        false
    } else {
        engine::delete_vault(&src, &tenant.vault).is_ok()
    };
    Ok(serde_json::json!({
        "tenant": id,
        "from": tenant.instance,
        "to": to,
        "records": imported,
        // Echoed so an operator can see the destination was created at the
        // tenant's own level rather than at whatever the code defaulted to.
        "level": tenant.level,
        // Counted in `records` (they were written) but NOT filed where the
        // payload aimed them — the destination's own screen diverted them.
        // Reachable only with `keep_source`, since the branch above refuses
        // to drop a source when the copy is unfaithful. Always 0 when the
        // destination does not screen, so the response shape is unchanged
        // for every deployment that does not.
        "quarantined": got.quarantined,
        "source_deleted": source_deleted,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C9: the scripted door and the HTTP door are the SAME door.
    ///
    /// Every CLI alias must resolve to a pair the proxy already allows, and
    /// every allowed pair must have an alias — otherwise the CLI is either
    /// wider than the plane it mirrors, or it "mirrors" it while leaving
    /// routes reachable by curl alone, which is the finding.
    #[test]
    fn every_ops_alias_is_an_allowed_route_and_every_route_has_an_alias() {
        let aliases = [
            "verify",
            "anchor",
            "supersessions",
            "admission",
            "admission-rule",
            "trust",
            "trust-set",
            "retention",
            "retention-set",
            "retention-sweep",
            "forget",
            "verify-forgetting",
        ];
        let mut resolved = Vec::new();
        for a in aliases {
            let pair = ops_alias(a).unwrap_or_else(|| panic!("{a} has no alias"));
            assert!(
                ops_route_ok(pair.0, pair.1),
                "{a} resolves to {pair:?}, which the proxy does not allow"
            );
            resolved.push(pair);
        }
        for (m, sp) in OPS_ROUTES {
            assert!(
                resolved.contains(&(*m, *sp)),
                "{m} {sp} is on the admin plane with no CLI alias — reachable by curl alone"
            );
        }
        assert!(
            ops_alias("rotate").is_none(),
            "key rotation is not an ops route"
        );
        assert!(ops_alias("drawers").is_none());
    }

    /// **Every operator capability the engine offers is either reachable
    /// through the ops plane or recorded as deliberately absent.**
    ///
    /// `OPERATOR_ONLY` counts the MCP absences and nothing counted these, so
    /// four capabilities were missing from the ops vocabulary with no
    /// written reason — and an omission and a boundary look identical from
    /// the outside. That is the question this whole audit exists to answer,
    /// on the axis nobody had counted.
    ///
    /// Both directions: a capability in neither list fails the build, and an
    /// entry in the absent list that has become reachable fails it too.
    #[test]
    fn every_operator_capability_is_reachable_or_recorded_as_absent() {
        // The engine's operator-plane subpaths, as `/v1` exposes them. This
        // list is what the two halves are counted against; a new engine
        // capability lands here first and then has to be classified.
        let engine_ops = [
            "verify",
            "anchor",
            "supersessions",
            "forget",
            // **Added with the engine route it names** (ROADMAP O14). This
            // list is a hand-maintained literal, which means a new `/v1`
            // operator route absent from it is counted in NEITHER direction
            // — so the gate whose whole job is to force every capability
            // into *reachable* or *recorded-as-absent* stays green over one
            // nobody classified. That is the failure mode it exists to
            // prevent, reachable through its own inventory.
            "verify-forgetting",
            "admission",
            "retention",
            "retention/sweep",
            "trust",
            "rotate",
            "drawers",
            "search",
            "export",
            "import",
            "refine",
            "history",
        ];
        let reachable: std::collections::BTreeSet<&str> =
            OPS_ROUTES.iter().map(|(_, p)| *p).collect();
        let absent: std::collections::BTreeSet<&str> =
            OPS_DELIBERATELY_ABSENT.iter().map(|(c, _)| *c).collect();
        assert!(
            reachable.len() > 5 && absent.len() > 3,
            "premise: both inventories were read ({} reachable, {} absent)",
            reachable.len(),
            absent.len()
        );
        for cap in engine_ops {
            let r = reachable.contains(cap);
            let a = absent.contains(cap);
            assert!(
                r || a,
                "{cap} is an engine operator capability that the ops plane neither reaches nor records as deliberately absent. Say which — an omission and a boundary look identical from outside."
            );
            assert!(!(r && a), "{cap} is both reachable and recorded absent");
        }
        // And every recorded absence carries a reason, not an empty string.
        for (cap, why) in OPS_DELIBERATELY_ABSENT {
            assert!(
                !why.trim().is_empty(),
                "{cap} is recorded absent with no reason — that is an omission with a list entry, which is worse than an omission"
            );
            assert!(
                engine_ops.contains(cap),
                "{cap} is recorded absent but is not an engine capability — a stale entry reads as a boundary being enforced"
            );
        }
    }

    #[test]
    fn data_subpath_allowlist_blocks_vault_lifecycle() {
        assert!(data_subpath_ok("drawers"));
        assert!(data_subpath_ok("search"));
        assert!(data_subpath_ok("stats/history"));
        assert!(data_subpath_ok("export"));
        assert!(data_subpath_ok("import"));
        // Vault root (DELETE /v1/vaults/{id}) and anything else: refused.
        assert!(!data_subpath_ok(""));
        assert!(!data_subpath_ok("delete"));
        assert!(!data_subpath_ok("../vaults"));
    }

    /// An approved FIRST SEGMENT must not authorize an arbitrary suffix.
    ///
    /// This gate used to be `subpath.split('/').next()`, so every string
    /// below passed it. The engine URL is built by interpolation and `ureq`
    /// parses it with the `url` crate, which collapses `..` per the WHATWG
    /// path rules — verified live: a client asking for
    /// `/v1/vaults/t/drawers/../admission` puts
    /// `POST /v1/vaults/t/admission` on the wire. So a tenant data token
    /// reached the operator plane (admission rulings, trust assignment,
    /// retention sweeps, forgetting, KEY ROTATION, vault deletion) and, by
    /// climbing two levels, ANOTHER TENANT'S vault.
    ///
    /// The premise is asserted first: the legitimate shapes these traversals
    /// are built from must still be allowed, so this cannot pass by refusing
    /// everything.
    #[test]
    fn an_approved_first_segment_does_not_authorize_the_rest_of_the_path() {
        // Premise: the prefixes the escapes are built on are legitimate.
        assert!(data_subpath_ok("drawers"));
        assert!(data_subpath_ok("search"));
        assert!(data_subpath_ok("drawers/a1b2c3"));

        // Operator plane, reached from an approved prefix.
        for escape in [
            "drawers/../admission",
            "drawers/../trust",
            "drawers/../retention",
            "drawers/../retention/sweep",
            "drawers/../forget",
            "drawers/../rotate",
            "drawers/../kg/authority",
            "search/../verify",
            "drawers/..",
        ] {
            assert!(
                !data_subpath_ok(escape),
                "{escape} must not pass the data-plane allowlist"
            );
        }

        // Cross-tenant: climbing past the vault segment entirely.
        for escape in [
            "search/../../globex/search",
            "drawers/../../globex/export",
            "import/../../globex/import",
        ] {
            assert!(
                !data_subpath_ok(escape),
                "{escape} must not reach another tenant's vault"
            );
        }

        // The percent-encoded spellings `url` also decodes.
        for escape in [
            "drawers/%2e%2e/admission",
            "drawers/%2E%2E/rotate",
            "drawers/%2e%2e%2f%2e%2e/globex/search",
        ] {
            assert!(!data_subpath_ok(escape), "{escape} must not pass encoded");
        }

        // Dot-only segments in every spelling, and backslash separators.
        assert!(!data_subpath_ok("drawers/./admission"));
        assert!(!data_subpath_ok("drawers/.../admission"));
        assert!(!data_subpath_ok("drawers//admission"));
        assert!(!data_subpath_ok("drawers\\..\\admission"));

        // And the shapes that are genuinely two segments stay refused for
        // the ordinary reason: they are not in the vocabulary.
        assert!(!data_subpath_ok("drawers/a1b2/extra"));
        assert!(!data_subpath_ok("admission"));
        assert!(!data_subpath_ok("rotate"));
    }

    // -- the quarantine fence ------------------------------------------

    /// `POST /t/search {"wing":"quarantine-pending"}` returned the tenant's
    /// own quarantined content verbatim — no traversal needed. The engine
    /// serves the reviewer's view to any request that NAMES the wing, which
    /// is right on `/v1` (an operator surface) and wrong through a tenant
    /// token, whose writes are what the screen diverted.
    ///
    /// Every string below passed before the fence existed.
    #[test]
    fn a_tenant_token_cannot_name_the_reserved_wing() {
        // Premise: an ordinary wing declaration is untouched, on every
        // carrier the fence inspects — so this cannot pass by refusing
        // everything.
        assert!(!request_names_reserved_wing(
            "search",
            "",
            br#"{"query":"q","wing":"legal"}"#
        ));
        assert!(!request_names_reserved_wing(
            "drawers",
            "wing=legal&limit=50",
            b""
        ));
        assert!(!request_names_reserved_wing("drawers/a1b2c3", "", b""));
        assert!(!request_names_reserved_wing("export", "", b""));

        // The reviewer's view, asked for by name.
        assert!(request_names_reserved_wing(
            "search",
            "",
            br#"{"query":"","wing":"quarantine-pending"}"#
        ));
        assert!(request_names_reserved_wing(
            "drawers",
            "wing=quarantine-pending&limit=500",
            b""
        ));
        // The engine `pct_decode`s some query values, so one spelling is
        // not the name.
        assert!(request_names_reserved_wing(
            "drawers",
            "wing=quarantine%2Dpending",
            b""
        ));
        // Nested: an import record declares its wing at drawer.meta.wing,
        // never at the top level, and NDJSON is not one JSON value.
        assert!(request_names_reserved_wing(
            "import",
            "",
            b"{\"drawer\":{\"id\":\"x\",\"content\":\"c\",\"meta\":{\"wing\":\"legal\"}}}\n\
              {\"drawer\":{\"id\":\"y\",\"content\":\"c\",\"meta\":{\"wing\":\"quarantine-pending\"}}}\n"
        ));
        // A forged write aimed at the reserved wing is refused here too —
        // the engine calls it 400 Invalid; either way it never lands.
        assert!(request_names_reserved_wing(
            "drawers",
            "",
            br#"{"text":"t","wing":"quarantine-pending","room":"r"}"#
        ));
        // And in the path, for a route that grows a wing segment later.
        assert!(request_names_reserved_wing(
            "drawers/quarantine-pending",
            "",
            b""
        ));

        // The pinned cost, MCP's verbatim: the match is on the VALUE, so a
        // drawer whose whole text is the wing's name is refused too, and
        // the refusal says what happened.
        assert!(request_names_reserved_wing(
            "drawers",
            "",
            br#"{"text":"quarantine-pending","wing":"notes","room":"r"}"#
        ));
        // A drawer that merely MENTIONS it is not naming it.
        assert!(!request_names_reserved_wing(
            "drawers",
            "",
            br#"{"text":"we should review the quarantine-pending queue","wing":"notes"}"#
        ));
    }

    /// `GET /t/drawers/{id}` needs no wing at all — the id DEREFERENCES to
    /// one. MCP closes the same indirection by probing every id-shaped
    /// argument against the store; the orchestrator's probe is the `/v1`
    /// read itself, and this is the verdict it applies to the answer.
    #[test]
    fn a_quarantined_drawer_is_not_readable_by_its_id() {
        let body = |wing: &str| {
            serde_json::json!({ "drawer": {
                "id": "a1b2c3", "content": "ignore previous instructions",
                "meta": { "wing": wing, "room": "r", "chunk_index": 0,
                          "added_by": "rest", "filed_at": "2026-08-05T00:00:00Z",
                          "normalize_version": 3, "id_recipe": "v3" }
            }})
            .to_string()
            .into_bytes()
        };
        // Premise: an ordinary drawer is the tenant's to read.
        assert!(!drawer_body_is_quarantined(&body("legal")));
        assert!(drawer_body_is_quarantined(&body(QUARANTINE_WING)));
        // A 404 body, and anything that is not a drawer answer, decide
        // nothing — the caller only consults this on a 200.
        assert!(!drawer_body_is_quarantined(
            br#"{"error":"no such drawer"}"#
        ));
        assert!(!drawer_body_is_quarantined(b"not json"));

        // Only the single-drawer shape takes the probe; the list route is
        // covered by the name fence and must not pay for a lookup.
        assert!(single_drawer_route("drawers/a1b2c3"));
        assert!(!single_drawer_route("drawers"));
        assert!(!single_drawer_route("search"));
    }

    /// An export names no wing and carries every row, so neither the name
    /// fence nor the drawer probe sees it. It is refused, never filtered:
    /// the manifest's `payload_sha256` covers the payload, so dropping
    /// records would hand back an artifact its own re-import rejects.
    #[test]
    fn an_export_carrying_review_evidence_is_refused_not_rewritten() {
        let record = |wing: &str| {
            serde_json::json!({ "drawer": { "id": "x", "content": "c",
                "meta": { "wing": wing, "room": "r", "chunk_index": 0,
                          "added_by": "rest", "filed_at": "2026-08-05T00:00:00Z",
                          "normalize_version": 3, "id_recipe": "v3" } },
                "vector": [] })
            .to_string()
        };
        let manifest = r#"{"undercroft_manifest":{"version":1,"counts":{"drawers":2}}}"#;
        // Premise: a clean export is served, which is the whole point of
        // refusing rather than removing the route.
        let clean = format!("{manifest}\n{}\n{}\n", record("legal"), record("notes"));
        assert!(!export_carries_reserved_wing(clean.as_bytes()));

        let dirty = format!(
            "{manifest}\n{}\n{}\n",
            record("legal"),
            record(QUARANTINE_WING)
        );
        assert!(export_carries_reserved_wing(dirty.as_bytes()));
    }

    /// The fence belongs to the TENANT TOKEN, not to the capability: the
    /// operator's route to the same queue must keep working, and it is on
    /// the plane that never consults the fence.
    #[test]
    fn the_operator_route_to_the_queue_is_untouched() {
        assert!(ops_route_ok("GET", "admission"));
        assert!(ops_route_ok("POST", "admission"));
        // …and it was never reachable with a tenant token in the first
        // place, which is the boundary the fence completes.
        assert!(!data_subpath_ok("admission"));
    }

    #[test]
    fn ct_eq_behaves() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "ab"));
    }

    #[test]
    fn rate_limiter_is_per_tenant_and_per_window() {
        let l = RateLimiter::with_limit(2);
        assert!(l.allow_at("acme", 100));
        assert!(l.allow_at("acme", 100));
        assert!(!l.allow_at("acme", 100), "third request in-window trips");
        // Another tenant is untouched by acme's window.
        assert!(l.allow_at("globex", 100));
        // A new minute resets acme.
        assert!(l.allow_at("acme", 101));
        // Limit 0 = disabled.
        let off = RateLimiter::with_limit(0);
        for _ in 0..100 {
            assert!(off.allow_at("acme", 100));
        }
    }

    // -- error classes on the control plane ----------------------------

    fn orch_for_tests() -> (tempfile::TempDir, Orch) {
        let dir = tempfile::TempDir::new().unwrap();
        let o = Orch::open(
            &dir.path().join("orch.db"),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap();
        (dir, o)
    }

    /// Drive one admin route and read back its status. The admin plane is
    /// a pure function of (method, path, body, state) for every branch
    /// that does not reach an engine, so the surface itself is testable
    /// rather than only the helpers under it.
    fn admin_status(orch: &Orch, method: &str, path: &str, body: &str) -> u16 {
        let m: Method = method.parse().expect("method");
        admin_plane(orch, &m, path, body.as_bytes()).status_code().0
    }

    /// A delete of a name that is not registered answered `200
    /// {"removed": false}` — the anti-pattern the engine eradicated on
    /// `DELETE /v1/…/drawers/{id}` — and the console toasts on any 2xx, so
    /// a decommission script tore down a VM that was still registered and
    /// routing while a human read "removed".
    #[test]
    fn deleting_an_unregistered_instance_is_404_not_a_cheerful_200() {
        let (_d, o) = orch_for_tests();
        o.instance_add("alpha", "https://a", "b", "s").unwrap();
        // Premise: a real removal is still a 200, and still says so.
        assert_eq!(
            admin_status(&o, "DELETE", "/admin/instances/alpha", ""),
            200
        );
        assert_eq!(
            admin_status(&o, "DELETE", "/admin/instances/alpha", ""),
            404
        );
        assert_eq!(
            admin_status(&o, "DELETE", "/admin/instances/never-registered", ""),
            404
        );
        // The guard that already worked keeps its class.
        o.instance_add("beta", "https://b", "b", "s").unwrap();
        o.tenant_create("acme", "beta", "sealed").unwrap();
        assert_eq!(admin_status(&o, "DELETE", "/admin/instances/beta", ""), 409);
    }

    /// Every migration failure was a 502 — the status retry layers treat
    /// as transient — so the four that can never succeed on a retry were
    /// hammered forever while the operator was told the engine was down.
    /// None of these branches reaches an engine.
    #[test]
    fn a_migration_failure_carries_its_own_class() {
        let (_d, o) = orch_for_tests();
        o.instance_add("alpha", "https://a", "b", "s").unwrap();
        let (t, _) = o.tenant_create("acme", "alpha", "sealed").unwrap();

        // Unknown tenant: a missing resource in the path.
        assert_eq!(
            migrate_tenant(&o, "nope", "alpha", false)
                .unwrap_err()
                .status(),
            404
        );
        // Already there: well-formed, addressed at something real, refused
        // by the state's shape.
        assert_eq!(
            migrate_tenant(&o, &t.id, "alpha", false)
                .unwrap_err()
                .status(),
            409
        );
        // Unknown destination: a value the CALLER supplied in the body.
        assert_eq!(
            migrate_tenant(&o, &t.id, "ghost", false)
                .unwrap_err()
                .status(),
            400
        );
        // …and the same three through the route that answered 502 for all
        // of them.
        assert_eq!(
            admin_status(
                &o,
                "POST",
                &format!("/admin/tenants/{}/migrate", t.id),
                r#"{"to":"alpha"}"#
            ),
            409
        );
        assert_eq!(
            admin_status(
                &o,
                "POST",
                "/admin/tenants/nope/migrate",
                r#"{"to":"alpha"}"#
            ),
            404
        );
        assert_eq!(
            admin_status(
                &o,
                "POST",
                &format!("/admin/tenants/{}/migrate", t.id),
                r#"{"to":"ghost"}"#
            ),
            400
        );
        // A missing `to` was already caller error and stays one.
        assert_eq!(
            admin_status(
                &o,
                "POST",
                &format!("/admin/tenants/{}/migrate", t.id),
                "{}"
            ),
            400
        );
    }

    /// A refusal the ENGINE issued keeps the engine's class; anything else
    /// is a transport failure, which is what 502 means.
    #[test]
    fn a_relayed_engine_refusal_keeps_its_status() {
        // The shapes engine.rs actually formats.
        assert_eq!(
            engine_err("engine import failed (409): vault already exists".into()).status(),
            409
        );
        assert_eq!(
            engine_err("engine refused vault create (400): bad level".into()).status(),
            400
        );
        // An engine 5xx is not the caller's fault and is not the engine's
        // verdict on the request — 502, as before.
        assert_eq!(
            engine_err("engine export failed (500): corrupt row".into()).status(),
            502
        );
        assert_eq!(
            engine_err("engine unreachable: connection refused".into()).status(),
            502
        );
        // The message survives either way — it is the operator's only
        // account of what the engine said.
        let e = engine_err("engine import failed (409): vault already exists".into());
        assert!(e.to_string().contains("vault already exists"));
    }

    /// A `StateError` reaching the wire is classified once, by the error,
    /// not by whichever handler happened to catch it.
    #[test]
    fn state_failures_are_classified_by_the_error_not_the_call_site() {
        let (dir, o) = orch_for_tests();
        // Not registered: 404 on every route that resolves an instance,
        // where `health` said 404 and the data/ops planes said 502.
        assert_eq!(
            admin_status(&o, "GET", "/admin/instances/ghost/health", ""),
            404
        );
        // Caller input the state layer refuses: 400, unchanged.
        assert_eq!(
            admin_status(
                &o,
                "POST",
                "/admin/instances",
                r#"{"name":"bad name!","url":"https://a","bearer":"b","assertion_secret":"s"}"#
            ),
            400
        );
        // A tampered credential blob is a tamper verdict (409), and its
        // message — which names the remedy — survives instead of being
        // flattened into "instance unavailable".
        o.instance_add("alpha", "https://a", "b", "s").unwrap();
        let other = Orch::open(
            &dir.path().join("orch.db"),
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        )
        .unwrap();
        let resp = admin_plane(&other, &Method::Get, "/admin/instances/alpha/health", b"");
        assert_eq!(resp.status_code().0, 409);
        let mut said = String::new();
        use std::io::Read;
        resp.into_reader().read_to_string(&mut said).unwrap();
        assert!(
            said.contains("UNDERCROFT_ORCH_KEY"),
            "the refusal names the remedy: {said}"
        );
    }

    #[test]
    fn an_unreadable_rate_limit_declaration_refuses_to_start() {
        // The premise: 0 really is always-allow, so "parsed as 0" and
        // "refused" are two different worlds and this test can tell them
        // apart.
        assert!(RateLimiter::with_limit(0).allow_at("acme", 1));

        // Off is declarable three ways, and a plain integer is honoured.
        assert_eq!(resolve_rate_limit(None).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some("")).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some("off")).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some("0")).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some(" 600 ")).unwrap(), 600);

        // Garbage refuses instead of resolving to the always-allow 0 —
        // `100/min` (the engine's `<count>/<seconds>` shape borrowed by
        // mistake) and `1_000` are the two typos that used to disable
        // rate limiting in silence.
        for bad in ["100/min", "1_000", "600rpm", "-5", "unlimited"] {
            let err = resolve_rate_limit(Some(bad))
                .expect_err("an unreadable declaration must refuse, not default to off");
            let msg = err.to_string();
            assert!(msg.contains(bad), "the refusal quotes what was read: {msg}");
            assert!(
                msg.contains("requests per minute"),
                "the refusal names the fix: {msg}"
            );
        }
    }
}
