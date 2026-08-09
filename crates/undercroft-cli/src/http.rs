//! HTTP transport for the MCP server — the "remote team server" mode,
//! ported from mempalace's `serve` command.
//!
//! One shared palace, reachable by a team's MCP clients over HTTP:
//!
//! ```text
//! undercroft serve-http --host 0.0.0.0 --port 8765 [--read-only]
//! claude mcp add --transport http undercroft http://HOST:8765/mcp \
//!     --header "Authorization: Bearer $UNDERCROFT_MCP_HTTP_TOKEN"
//! ```
//!
//! Security posture (matches MemPalace's rules, enforced not documented):
//! a bearer token (`UNDERCROFT_MCP_HTTP_TOKEN`) is **mandatory for any
//! non-loopback bind** — the server refuses to start without one. The
//! transport itself is plaintext HTTP; for anything beyond a trusted
//! private network, front it with a TLS-terminating reverse proxy.
//! `/healthz` is unauthenticated for load-balancer probes.
//!
//! When `UNDERCROFT_ASSERTION_SECRET` is declared, **both** transports
//! require a valid `X-Vault-Assertion` for the vault they address: `/v1`
//! per handler, `/mcp` for the vault named by `--vault`. The banner says
//! "per-vault assertions required" without qualification, and it now means
//! it — a bearer alone reaches no vault on either path.

use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde_json::Value;
use time::OffsetDateTime;
use tiny_http::{Header, Method, Response, Server};

use crate::mcp::McpHandler;
use crate::tenant::Tenancy;
use undercroft_store::PalaceStore;

/// Does `header` carry exactly `Bearer <expected>`, compared in constant
/// time?
///
/// The scheme prefix is checked normally — it is public — and only the
/// secret half goes through `ct_eq`. The length guard is separate and
/// deliberate: `ct_eq` requires equal lengths, and a differing length is
/// already observable from the header itself, so nothing is leaked by
/// returning early on it.
fn bearer_matches(header: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return false;
    };
    presented.len() == expected.len() && bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
}

pub fn serve_http(
    store: PalaceStore,
    tenancy: Tenancy,
    host: &str,
    port: u16,
    read_only: bool,
) -> Result<()> {
    let token = std::env::var("UNDERCROFT_MCP_HTTP_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    let loopback = host == "127.0.0.1" || host == "localhost" || host == "::1";
    if !loopback && token.is_none() {
        bail!(
            "refusing to bind {host}:{port} without UNDERCROFT_MCP_HTTP_TOKEN — a network-exposed \
             memory server must require a bearer token"
        );
    }

    // Prometheus /metrics is opt-in (loopback + behind the bearer gate).
    let metrics_enabled = std::env::var("UNDERCROFT_METRICS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut handler = McpHandler::new(store, read_only);
    let mut tenancy = tenancy;
    let server =
        Server::http((host, port)).map_err(|e| anyhow::anyhow!("binding {host}:{port}: {e}"))?;
    undercroft_obs::diag_info!(
        "undercroft server listening on http://{host}:{port} — /mcp (MCP) + /v1 (REST){} ({}{}{})",
        if metrics_enabled { " + /metrics" } else { "" },
        if read_only { "read-only, " } else { "" },
        if token.is_some() {
            "bearer auth"
        } else {
            "loopback, no auth"
        },
        if tenancy.requires_assertion() {
            ", per-vault assertions required"
        } else {
            ""
        }
    );

    let json_header =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header");

    // The loop wakes on this interval even when idle so the telemetry
    // sampler can tick between requests (negligible cost; only the tick body
    // is feature-gated).
    let sample_interval = Duration::from_millis(
        std::env::var("UNDERCROFT_SAMPLE_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&ms| ms >= 100)
            .unwrap_or(2000),
    );

    // Track the last sampler tick by wall clock, not by loop idleness: under
    // sustained load `recv_timeout` always returns a request within the
    // window, so the sampler must fire on elapsed time or it starves exactly
    // when there is the most to observe.
    #[cfg(feature = "telemetry")]
    let mut last_sample = Instant::now();

    loop {
        let maybe_request = match server.recv_timeout(sample_interval) {
            Ok(req) => req,
            Err(_) => break,
        };
        #[cfg(feature = "telemetry")]
        if last_sample.elapsed() >= sample_interval {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            tenancy.sample(now);
            last_sample = Instant::now();
        }
        let mut request = match maybe_request {
            Some(request) => request,
            None => continue,
        };
        let start = Instant::now();
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        // /healthz is unauthenticated for load-balancer probes.
        if request.method() == &Method::Get && path == "/healthz" {
            let _ = request.respond(Response::from_string("ok"));
            undercroft_obs::http_request("healthz", 200, start.elapsed());
            continue;
        }
        // /monitor serves the Palace Monitor UI — a self-contained static
        // page (no secrets) that connects to the SSE stream with a bearer
        // the user supplies in the page. Only present in telemetry builds.
        #[cfg(feature = "telemetry")]
        if request.method() == &Method::Get && path == "/monitor" {
            let ct = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
                .expect("static header");
            let cc =
                Header::from_bytes(&b"Cache-Control"[..], &b"no-cache"[..]).expect("static header");
            let _ = request.respond(
                Response::from_string(include_str!("monitor.html"))
                    .with_header(ct)
                    .with_header(cc),
            );
            undercroft_obs::http_request("monitor", 200, start.elapsed());
            continue;
        }
        // /ui serves the admin console — like /monitor, a self-contained
        // static page carrying no secrets: the operator pastes the bearer
        // (and, under assertion isolation, the assertion secret) into the
        // page, which attaches them to its /v1 fetches. Served on every
        // build — management is core function, unlike the telemetry-gated
        // monitor.
        if request.method() == &Method::Get && path == "/ui" {
            let ct = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
                .expect("static header");
            // no-cache: console updates must arrive on a plain reload — a
            // cached copy silently pins operators to old behavior.
            let cc =
                Header::from_bytes(&b"Cache-Control"[..], &b"no-cache"[..]).expect("static header");
            let _ = request.respond(
                Response::from_string(include_str!("ui.html"))
                    .with_header(ct)
                    .with_header(cc),
            );
            undercroft_obs::http_request("ui", 200, start.elapsed());
            continue;
        }
        // Palace-wide bearer gates every non-health route (MCP and REST).
        //
        // Compared in CONSTANT TIME. This was `==` on a `format!`, which
        // short-circuits on the first differing byte and so leaks the shared
        // prefix length to anyone who can time the 401 — on the outermost
        // gate in front of `/mcp`, `/v1` and `/metrics`. Both neighbouring
        // secret comparisons in this fleet already do it properly
        // (`assertion.rs` via `ConstantTimeEq`, the orchestrator's admin
        // token via its own `ct_eq`), so this was the odd one out rather
        // than a considered trade.
        if let Some(expected) = &token {
            let ok = request
                .headers()
                .iter()
                .find(|h| h.field.equiv("Authorization"))
                .map(|h| bearer_matches(h.value.as_str(), expected))
                .unwrap_or(false);
            if !ok {
                let _ =
                    request.respond(Response::from_string("unauthorized").with_status_code(401));
                undercroft_obs::auth_rejected("bearer");
                undercroft_obs::http_request("unauthorized", 401, start.elapsed());
                continue;
            }
        }
        // Prometheus metrics — opt-in, behind the bearer gate above.
        if metrics_enabled && request.method() == &Method::Get && path == "/metrics" {
            let (code, body) = match undercroft_obs::render_prometheus() {
                Some(text) => (200, text),
                None => (
                    503,
                    "metrics require building undercroft with --features telemetry\n".to_string(),
                ),
            };
            let ct = Header::from_bytes(&b"Content-Type"[..], &b"text/plain; version=0.0.4"[..])
                .expect("static header");
            let _ = request.respond(
                Response::from_string(body)
                    .with_status_code(code)
                    .with_header(ct),
            );
            undercroft_obs::http_request("metrics", code, start.elapsed());
            continue;
        }
        // Live SSE telemetry stream — hijack the connection onto its own
        // thread (the Request is Send) so the single-threaded main loop keeps
        // serving. The thread touches only the obs broker, never a store.
        #[cfg(feature = "telemetry")]
        if request.method() == &Method::Get && path.starts_with("/v1/") && path.ends_with("/stream")
        {
            let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
            if segs.len() == 4 && segs[0] == "v1" && segs[1] == "vaults" && segs[3] == "stream" {
                let id = segs[2];
                let now = OffsetDateTime::now_utc().unix_timestamp();
                match tenancy.authorize(id, &request, now) {
                    Ok(_sealed) => {
                        let vault = id.to_string();
                        undercroft_obs::http_request("v1_stream", 200, start.elapsed());
                        let writer = request.into_writer();
                        std::thread::spawn(move || {
                            undercroft_obs::run_sse(writer, vault);
                        });
                    }
                    Err(code) => {
                        let _ = request.respond(Response::from_string("").with_status_code(code));
                        undercroft_obs::http_request("v1_stream", code, start.elapsed());
                    }
                }
                continue;
            }
        }
        // Multi-tenant REST surface (per-request metrics recorded inside).
        if path.starts_with("/v1/") || path == "/v1" {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            tenancy.handle(request, now);
            continue;
        }
        let mut status: u16 = 200;
        match (request.method().clone(), path.as_str()) {
            (Method::Post, "/mcp") => {
                // The per-vault assertion covers this transport too. /v1
                // checked it on every handler and /mcp checked it nowhere,
                // so declaring UNDERCROFT_ASSERTION_SECRET left the
                // `--vault` vault fully readable and writable to anyone
                // with the palace bearer — the exact isolation the secret
                // is set to buy. Unset secret ⇒ this is a no-op.
                let now = OffsetDateTime::now_utc().unix_timestamp();
                if let Err(code) = tenancy.assert_transport(handler.vault_id(), &request, now) {
                    let _ = request
                        .respond(Response::from_string("unauthorized").with_status_code(code));
                    undercroft_obs::http_request("mcp", code, start.elapsed());
                    continue;
                }
                let mut body = String::new();
                if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
                    let _ =
                        request.respond(Response::from_string("bad request").with_status_code(400));
                    undercroft_obs::http_request("mcp", 400, start.elapsed());
                    continue;
                }
                let msg: Value = match serde_json::from_str(&body) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = request.respond(
                            Response::from_string(format!("{{\"error\":\"parse error: {e}\"}}"))
                                .with_status_code(400)
                                .with_header(json_header.clone()),
                        );
                        undercroft_obs::http_request("mcp", 400, start.elapsed());
                        continue;
                    }
                };
                match handler.handle(&msg) {
                    Some(response) => {
                        let _ = request.respond(
                            Response::from_string(response.to_string())
                                .with_header(json_header.clone()),
                        );
                    }
                    // Notification: acknowledge with 202, no body.
                    None => {
                        status = 202;
                        let _ = request.respond(Response::empty(202));
                    }
                }
                undercroft_obs::http_request("mcp", status, start.elapsed());
            }
            _ => {
                let _ = request.respond(Response::from_string("not found").with_status_code(404));
                undercroft_obs::http_request("other", 404, start.elapsed());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The palace-wide bearer is compared in constant time, and it still
    /// compares the *right thing*.
    ///
    /// The constant-time property itself is not observable from a unit test
    /// — timing is not a value — so this pins the behaviour a naive
    /// "fix" would break instead: exact match required, scheme required,
    /// no prefix match, no length-only match. The odd one out here was
    /// `h.value.as_str() == format!("Bearer {expected}")`, which
    /// short-circuits on the first differing byte while its two neighbours
    /// in this fleet (`assertion.rs`, the orchestrator's admin token) do
    /// not.
    #[test]
    fn the_bearer_is_matched_exactly_and_only_with_its_scheme() {
        assert!(bearer_matches("Bearer s3cret", "s3cret"));

        // A prefix must not pass — this is the case a byte-wise compare
        // leaks a position at a time.
        assert!(!bearer_matches("Bearer s3cre", "s3cret"));
        assert!(!bearer_matches("Bearer s3crett", "s3cret"));
        // Same length, different content.
        assert!(!bearer_matches("Bearer s3crec", "s3cret"));
        // The scheme is not optional, and is not part of the secret.
        assert!(!bearer_matches("s3cret", "s3cret"));
        assert!(!bearer_matches("bearer s3cret", "s3cret"));
        assert!(!bearer_matches("Bearer  s3cret", "s3cret"));
        assert!(!bearer_matches("", "s3cret"));
        // A non-ASCII secret must not panic on a byte-length guard.
        assert!(bearer_matches("Bearer pässwörd", "pässwörd"));
        assert!(!bearer_matches("Bearer passwörd", "pässwörd"));
    }
}
