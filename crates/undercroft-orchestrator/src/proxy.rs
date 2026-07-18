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
//! engine vault → record mapping → return the token once), and migration
//! (export → import → count-verified → mapping flip → source delete).
//!
//! Auth failures are uniform 401s with no reason detail, mirroring the
//! engine's assertion handling.

use crate::engine;
use crate::state::Orch;
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

/// Subpath allowlist for the data plane: the first segment must be one of
/// the engine's vault subroutes. An empty subpath (the vault root — its
/// DELETE endpoint) is refused: vault lifecycle belongs to the admin
/// plane, not to a data token.
fn data_subpath_ok(subpath: &str) -> bool {
    matches!(
        subpath.split('/').next(),
        Some("drawers") | Some("search") | Some("stats") | Some("export") | Some("import")
    )
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

/// Run the proxy loop forever. `admin_token` gates `/admin/*`.
pub fn serve(orch: &Orch, addr: &str, admin_token: &str) -> anyhow::Result<()> {
    let server = Server::http(addr).map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?;
    eprintln!("undercroft-orchestrator listening on http://{addr}");
    for mut request in server.incoming_requests() {
        let method = request.method().clone();
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        let mut body = Vec::new();
        use std::io::Read;
        let _ = request
            .as_reader()
            .take(256 * 1024 * 1024)
            .read_to_end(&mut body);

        let response = route(orch, admin_token, &request, &method, &path, &body);
        let _ = request.respond(response);
    }
    Ok(())
}

fn route(
    orch: &Orch,
    admin_token: &str,
    request: &tiny_http::Request,
    method: &Method,
    path: &str,
    body: &[u8],
) -> Response<std::io::Cursor<Vec<u8>>> {
    // Unauthenticated liveness, mirroring the engine.
    if method == &Method::Get && path == "/healthz" {
        return json_response(200, &serde_json::json!({ "ok": true }));
    }

    if let Some(sub) = path.strip_prefix("/t/") {
        return data_plane(orch, request, method, sub, body);
    }
    if path == "/t" || path == "/t/" {
        return err_response(404, "missing subpath");
    }

    if path == "/admin" || path.starts_with("/admin/") {
        // Admin gate first; uniform 401.
        match bearer(request) {
            Some(t) if ct_eq(&t, admin_token) => {}
            _ => return err_response(401, "unauthorized"),
        }
        return admin_plane(orch, method, path, body);
    }

    err_response(404, "not found")
}

// -- data plane -------------------------------------------------------------

fn data_plane(
    orch: &Orch,
    request: &tiny_http::Request,
    method: &Method,
    subpath: &str,
    body: &[u8],
) -> Response<std::io::Cursor<Vec<u8>>> {
    let Some(token) = bearer(request) else {
        return err_response(401, "unauthorized");
    };
    let tenant = match orch.tenant_by_token(&token) {
        Ok(Some(t)) => t,
        Ok(None) => return err_response(401, "unauthorized"),
        Err(_) => return err_response(500, "state error"),
    };
    if !data_subpath_ok(subpath) {
        return err_response(404, "unknown route");
    }
    let creds = match orch.instance_creds(&tenant.instance) {
        Ok(c) => c,
        Err(_) => return err_response(502, "instance unavailable"),
    };
    let content_type = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Content-Type"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_else(|| "application/json".to_string());
    match engine::vault_request(
        &creds,
        &tenant.vault,
        method.as_str(),
        subpath,
        &content_type,
        body,
    ) {
        Ok(r) => Response::from_data(r.body)
            .with_status_code(r.status)
            .with_header(
                Header::from_bytes("Content-Type", r.content_type.as_bytes()).unwrap_or_else(
                    |_| Header::from_bytes("Content-Type", "application/json").unwrap(),
                ),
            ),
        Err(e) => err_response(502, &e),
    }
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
                Err(e) => err_response(400, &e.to_string()),
            }
        }
        ("GET", ["admin", "instances"]) => match orch.instance_list() {
            Ok(list) => json_response(200, &serde_json::json!({ "instances": list })),
            Err(e) => err_response(500, &e.to_string()),
        },
        ("GET", ["admin", "instances", name, "health"]) => match orch.instance_creds(name) {
            Ok(c) => json_response(
                200,
                &serde_json::json!({ "name": name, "healthy": engine::health(&c.url) }),
            ),
            Err(e) => err_response(404, &e.to_string()),
        },
        ("DELETE", ["admin", "instances", name]) => match orch.instance_remove(name) {
            Ok(removed) => json_response(200, &serde_json::json!({ "removed": removed })),
            Err(e) => err_response(409, &e.to_string()),
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
                    Err(e) => return err_response(500, &e.to_string()),
                },
            };
            create_tenant(orch, &name, &instance, &level)
        }
        ("GET", ["admin", "tenants"]) => match orch.tenant_list() {
            Ok(list) => json_response(200, &serde_json::json!({ "tenants": list })),
            Err(e) => err_response(500, &e.to_string()),
        },
        ("DELETE", ["admin", "tenants", id]) => delete_tenant(orch, id),
        ("POST", ["admin", "tenants", id, "migrate"]) => {
            let v = body_json();
            let Some(to) = s(&v, "to") else {
                return err_response(400, "need to");
            };
            let keep = v.get("keep_source").and_then(serde_json::Value::as_bool) == Some(true);
            match migrate_tenant(orch, id, &to, keep) {
                Ok(summary) => json_response(200, &summary),
                Err(e) => err_response(502, &e),
            }
        }
        _ => err_response(404, "unknown admin route"),
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
        Err(e) => return err_response(404, &e.to_string()),
    };
    // Record the mapping first (so a crash can't leave an unmapped vault
    // holding data), then create the vault; roll the row back on failure.
    let (tenant, token) = match orch.tenant_create(name, instance) {
        Ok(x) => x,
        Err(e) => return err_response(500, &e.to_string()),
    };
    if let Err(e) = engine::create_vault(&creds, &tenant.vault, level) {
        let _ = orch.tenant_delete(&tenant.id);
        return err_response(502, &e);
    }
    // The token appears in this response and nowhere else, ever.
    json_response(
        200,
        &serde_json::json!({ "tenant": tenant, "token": token }),
    )
}

fn delete_tenant(orch: &Orch, id: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let tenant = match orch.tenant_get(id) {
        Ok(Some(t)) => t,
        Ok(None) => return err_response(404, "unknown tenant"),
        Err(e) => return err_response(500, &e.to_string()),
    };
    if let Ok(creds) = orch.instance_creds(&tenant.instance) {
        if let Err(e) = engine::delete_vault(&creds, &tenant.vault) {
            return err_response(502, &e);
        }
    }
    match orch.tenant_delete(id) {
        Ok(_) => json_response(200, &serde_json::json!({ "deleted": id })),
        Err(e) => err_response(500, &e.to_string()),
    }
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
) -> Result<serde_json::Value, String> {
    let tenant = orch
        .tenant_get(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("unknown tenant {id:?}"))?;
    if tenant.instance == to {
        return Err("tenant is already on that instance".into());
    }
    let src = orch
        .instance_creds(&tenant.instance)
        .map_err(|e| e.to_string())?;
    let dst = orch.instance_creds(to).map_err(|e| e.to_string())?;

    let ndjson = engine::export_vault(&src, &tenant.vault)?;
    let exported = ndjson.lines().filter(|l| !l.trim().is_empty()).count() as u64;
    engine::create_vault(&dst, &tenant.vault, "sealed")?;
    let imported = engine::import_vault(&dst, &tenant.vault, &ndjson)?;
    if imported != exported {
        // Leave the source authoritative; remove the partial copy.
        let _ = engine::delete_vault(&dst, &tenant.vault);
        return Err(format!(
            "import count mismatch ({imported} of {exported}) — source left authoritative"
        ));
    }
    orch.tenant_set_instance(id, to)
        .map_err(|e| e.to_string())?;
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
        "source_deleted": source_deleted,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn ct_eq_behaves() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "ab"));
    }
}
