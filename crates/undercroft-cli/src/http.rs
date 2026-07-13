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
//! Security posture (matches upstream's rules, enforced not documented):
//! a bearer token (`UNDERCROFT_MCP_HTTP_TOKEN`) is **mandatory for any
//! non-loopback bind** — the server refuses to start without one. The
//! transport itself is plaintext HTTP; for anything beyond a trusted
//! private network, front it with a TLS-terminating reverse proxy.
//! `/healthz` is unauthenticated for load-balancer probes.

use anyhow::{bail, Result};
use serde_json::Value;
use tiny_http::{Header, Method, Response, Server};

use crate::mcp::McpHandler;
use undercroft_store::PalaceStore;

pub fn serve_http(store: PalaceStore, host: &str, port: u16, read_only: bool) -> Result<()> {
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

    let mut handler = McpHandler::new(store, read_only);
    let server =
        Server::http((host, port)).map_err(|e| anyhow::anyhow!("binding {host}:{port}: {e}"))?;
    eprintln!(
        "undercroft MCP server listening on http://{host}:{port}/mcp ({}{})",
        if read_only { "read-only, " } else { "" },
        if token.is_some() {
            "bearer auth"
        } else {
            "loopback, no auth"
        }
    );

    let json_header =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header");

    for mut request in server.incoming_requests() {
        let url = request.url().to_string();
        match (request.method().clone(), url.as_str()) {
            (Method::Get, "/healthz") => {
                let _ = request.respond(Response::from_string("ok"));
            }
            (Method::Post, "/mcp") => {
                if let Some(expected) = &token {
                    let ok = request
                        .headers()
                        .iter()
                        .find(|h| h.field.equiv("Authorization"))
                        .map(|h| h.value.as_str() == format!("Bearer {expected}"))
                        .unwrap_or(false);
                    if !ok {
                        let _ = request
                            .respond(Response::from_string("unauthorized").with_status_code(401));
                        continue;
                    }
                }
                let mut body = String::new();
                if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
                    let _ =
                        request.respond(Response::from_string("bad request").with_status_code(400));
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
                        let _ = request.respond(Response::empty(202));
                    }
                }
            }
            _ => {
                let _ = request.respond(Response::from_string("not found").with_status_code(404));
            }
        }
    }
    Ok(())
}
