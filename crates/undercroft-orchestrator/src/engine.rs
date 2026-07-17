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

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(600))
        .build()
}

/// Send `method` + `body` to `{url}/v1/vaults/{vault}/{subpath}` (or the
/// vault root when `subpath` is empty) with bearer + assertion attached.
/// Engine error statuses are *relayed*, not treated as transport failures.
pub fn vault_request(
    creds: &InstanceCreds,
    vault: &str,
    method: &str,
    subpath: &str,
    content_type: &str,
    body: &[u8],
) -> Result<EngineResponse, String> {
    let path = if subpath.is_empty() {
        format!("{}/v1/vaults/{vault}", creds.url)
    } else {
        format!("{}/v1/vaults/{vault}/{subpath}", creds.url)
    };
    let req = agent()
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
        Err(ureq::Error::Transport(t)) => return Err(format!("engine unreachable: {t}")),
    };
    let status = resp.status();
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
    let result = agent()
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
    match vault_request(creds, vault, "DELETE", "", "application/json", &[]) {
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
    let r = vault_request(creds, vault, "GET", "export", "application/json", &[])?;
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
pub fn import_vault(creds: &InstanceCreds, vault: &str, ndjson: &str) -> Result<u64, String> {
    let r = vault_request(
        creds,
        vault,
        "POST",
        "import",
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
    serde_json::from_slice::<serde_json::Value>(&r.body)
        .ok()
        .and_then(|v| v.get("imported").and_then(serde_json::Value::as_u64))
        .ok_or_else(|| "engine import response did not parse".into())
}

/// Probe an instance's unauthenticated `/healthz`.
pub fn health(url: &str) -> bool {
    agent()
        .get(&format!("{url}/healthz"))
        .call()
        .map(|r| r.status() == 200)
        .unwrap_or(false)
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
        assert_ne!(
            h.split_once(':').unwrap().1,
            h2.split_once(':').unwrap().1
        );
    }
}
