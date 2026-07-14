//! Multi-tenant REST surface for `serve-http`.
//!
//! The MCP-over-HTTP mode treats the whole palace as one trust domain: a
//! single palace-wide bearer token, and whoever holds it can address every
//! vault. A multi-tenant host (an orchestration platform where vault =
//! customer) needs the engine to enforce per-vault access on every request
//! and to manage vault lifecycle over HTTP. This module adds a versioned
//! REST layer, in the same process and behind the same bearer, that:
//!
//! * resolves `/v1/vaults/{id}/...` to a per-vault [`PalaceStore`] (opened
//!   on demand and cached), picking an external-embedding identity when the
//!   vault records one;
//! * requires, when `UNDERCROFT_ASSERTION_SECRET` is set, a valid
//!   [`crate::assertion`] for the exact vault each request addresses;
//! * provides vault create/delete, drawer save/search/delete, stats, and a
//!   lossless export/import pair for migrating a vault between instances.
//!
//! One palace per process stays the model — tenancy is vaults, not palaces.

use std::collections::HashMap;

use anyhow::Result;
use serde_json::{json, Value};
use tiny_http::{Header, Request, Response};

use undercroft_core::{normalize_content, validate_name, Drawer};
use undercroft_store::{PalaceStore, SaveOutcome, SearchOptions, StoreError};
use undercroft_vault::{SecurityLevel, Vault, VaultManager};

use crate::assertion::{self, AssertionError};

/// Produces the embedder a given vault should open with. Lives in `main`
/// (it knows the `onnx` feature and env config); this module just calls it.
pub type EmbedderFactory =
    Box<dyn Fn(&Vault) -> Result<Box<dyn undercroft_core::embed::Embedder + Send>>>;

/// The multi-tenant engine state behind the `/v1` routes. Single-threaded
/// (the `tiny_http` request loop is sequential), so the store cache needs
/// no locking.
pub struct Tenancy {
    manager: VaultManager,
    factory: EmbedderFactory,
    stores: HashMap<String, PalaceStore>,
    read_only: bool,
    /// Per-request vault-assertion secret; when present every vault-
    /// addressing request must carry a valid `X-Vault-Assertion`.
    secret: Option<Vec<u8>>,
    window: i64,
}

/// A response body: structured JSON, or a raw stream (the export NDJSON).
enum Body {
    Json(Value),
    Ndjson(String),
}

/// A REST error carrying an HTTP status code and a safe message.
struct RestError {
    code: u16,
    message: String,
}

impl RestError {
    fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

type RestResult = Result<(u16, Body), RestError>;

impl Tenancy {
    pub fn new(manager: VaultManager, factory: EmbedderFactory, read_only: bool) -> Self {
        let secret = std::env::var("UNDERCROFT_ASSERTION_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .map(String::into_bytes);
        Self {
            manager,
            factory,
            stores: HashMap::new(),
            read_only,
            secret,
            window: assertion::DEFAULT_WINDOW_SECS,
        }
    }

    /// True when this server enforces per-vault assertions.
    pub fn requires_assertion(&self) -> bool {
        self.secret.is_some()
    }

    /// Consume and answer one `/v1/...` request. The body is read up front
    /// (tiny_http hands it out only via `&mut Request`); everything after
    /// routes on the borrowed request plus that body string.
    pub fn handle(&mut self, mut req: Request, now: i64) {
        let mut body = String::new();
        let _ = std::io::Read::read_to_string(req.as_reader(), &mut body);
        let reply = self.route(&req, &body, now);
        match reply {
            Ok((code, Body::Json(v))) => respond(req, code, &v.to_string(), "application/json"),
            Ok((code, Body::Ndjson(s))) => respond(req, code, &s, "application/x-ndjson"),
            Err(e) => respond(
                req,
                e.code,
                &json!({ "error": e.message }).to_string(),
                "application/json",
            ),
        }
    }

    fn route(&mut self, req: &Request, body: &str, now: i64) -> RestResult {
        let path = req.url().split('?').next().unwrap_or("").to_string();
        let method = req.method().to_string().to_uppercase();
        let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
        match (method.as_str(), segs.as_slice()) {
            ("POST", &["v1", "vaults"]) => self.create_vault(req, body, now),
            ("DELETE", &["v1", "vaults", id]) => self.delete_vault(id, req, now),
            ("GET", &["v1", "vaults", id, "stats"]) => self.stats(id, req, now),
            ("POST", &["v1", "vaults", id, "drawers"]) => self.save_drawer(id, req, body, now),
            ("POST", &["v1", "vaults", id, "search"]) => self.search(id, req, body, now),
            ("DELETE", &["v1", "vaults", id, "drawers", drawer_id]) => {
                self.delete_drawer(id, drawer_id, req, now)
            }
            ("GET", &["v1", "vaults", id, "export"]) => self.export(id, req, now),
            ("POST", &["v1", "vaults", id, "import"]) => self.import(id, req, body, now),
            _ => Err(RestError::new(404, "no such route")),
        }
    }

    // ---- lifecycle ----------------------------------------------------

    fn create_vault(&mut self, req: &Request, body: &str, now: i64) -> RestResult {
        self.deny_read_only()?;
        let body = parse_json(body)?;
        let id = body_str(&body, "id")?;
        self.assert_or_401(&id, req, now)?;
        validate_name(&id, "vault").map_err(|e| RestError::new(400, e.to_string()))?;
        let level = match body.get("level").and_then(Value::as_str) {
            Some("hmac-only") | Some("hmac_only") => SecurityLevel::HmacOnly,
            _ => SecurityLevel::Sealed,
        };
        if self.manager.exists(&id) {
            return Err(RestError::new(409, "vault already exists"));
        }
        let vault = self
            .manager
            .create(&id, level)
            .map_err(|e| RestError::new(400, e.to_string()))?;
        // If an external embedder was requested, open once to record the
        // identity so subsequent opens enforce it.
        if let Some(spec) = body.get("embedder").and_then(Value::as_str) {
            if let Some((name, dim)) = undercroft_core::parse_external_spec(spec) {
                let emb = Box::new(undercroft_core::ExternalEmbedder::new(&name, dim));
                PalaceStore::open_with_embedder(vault, emb)
                    .map_err(|e| RestError::new(500, e.to_string()))?;
            } else if spec != "hash" && !spec.is_empty() {
                return Err(RestError::new(
                    400,
                    "embedder must be 'hash' or 'external:<name>@<dim>'",
                ));
            }
        }
        Ok((
            201,
            Body::Json(json!({ "id": id, "level": level.to_string(), "created": true })),
        ))
    }

    fn delete_vault(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.deny_read_only()?;
        self.assert_or_401(id, req, now)?;
        self.stores.remove(id);
        let deleted = self
            .manager
            .delete(id)
            .map_err(|e| RestError::new(400, e.to_string()))?;
        if deleted {
            Ok((200, Body::Json(json!({ "id": id, "deleted": true }))))
        } else {
            Err(RestError::new(404, "no such vault"))
        }
    }

    fn stats(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let count = store.count().map_err(err500)?;
        let external = store.is_external();
        let vault = store.vault();
        Ok((
            200,
            Body::Json(json!({
                "id": id,
                "drawers": count,
                "level": vault.level().to_string(),
                "external": external,
                "writes": vault.writes(),
                "chain_head": vault.chain_head_hex(),
            })),
        ))
    }

    // ---- drawers ------------------------------------------------------

    fn save_drawer(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.deny_read_only()?;
        self.assert_or_401(id, req, now)?;
        let body = parse_json(body)?;
        let text = body_str(&body, "text")?;
        let wing = body
            .get("wing")
            .and_then(Value::as_str)
            .unwrap_or("general");
        let room = body.get("room").and_then(Value::as_str).unwrap_or("inbox");
        validate_name(wing, "wing").map_err(|e| RestError::new(400, e.to_string()))?;
        validate_name(room, "room").map_err(|e| RestError::new(400, e.to_string()))?;
        let normalized = normalize_content(&text);
        if normalized.is_empty() {
            return Err(RestError::new(400, "text is empty after normalization"));
        }
        let vector = parse_vector(&body, "vector")?;
        let dedup = body
            .get("dedup_threshold")
            .and_then(Value::as_f64)
            .map(|v| v as f32);

        let store = self.store_for(id)?;
        let idx = store.count().map_err(err500)? as u32;
        let drawer = Drawer::new(wing, room, normalized, None, idx, "rest");

        let out = if store.is_external() {
            let v =
                vector.ok_or_else(|| RestError::new(400, "external vault requires 'vector'"))?;
            match dedup {
                Some(t) => store
                    .save_with_dedup_vec(&drawer, v, t)
                    .map_err(store_err)?,
                None => {
                    let created = store.upsert_external(&drawer, v).map_err(store_err)?;
                    SaveOutcome {
                        id: drawer.id.clone(),
                        created,
                        deduped: false,
                    }
                }
            }
        } else {
            match dedup {
                Some(t) => store.save_with_dedup(&drawer, t).map_err(store_err)?,
                None => {
                    let created = store.upsert(&drawer).map_err(store_err)?;
                    SaveOutcome {
                        id: drawer.id.clone(),
                        created,
                        deduped: false,
                    }
                }
            }
        };
        Ok((
            200,
            Body::Json(json!({ "id": out.id, "created": out.created, "deduped": out.deduped })),
        ))
    }

    fn search(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let body = parse_json(body)?;
        let query = body_str(&body, "query")?;
        let opts = SearchOptions {
            wing: body.get("wing").and_then(Value::as_str).map(String::from),
            room: body.get("room").and_then(Value::as_str).map(String::from),
            limit: body.get("limit").and_then(Value::as_u64).unwrap_or(10) as usize,
        };
        let vector = parse_vector(&body, "vector")?;
        let store = self.store_for(id)?;
        let hits = if store.is_external() {
            let v =
                vector.ok_or_else(|| RestError::new(400, "external vault requires 'vector'"))?;
            store
                .search_with_vector(&query, v, &opts)
                .map_err(store_err)?
        } else {
            store.search(&query, &opts).map_err(store_err)?
        };
        let hits: Vec<Value> = hits
            .into_iter()
            .map(|h| {
                json!({
                    "id": h.drawer.id,
                    "content": h.drawer.content,
                    "wing": h.drawer.meta.wing,
                    "room": h.drawer.meta.room,
                    "score": h.score,
                    "semantic": h.semantic,
                    "lexical": h.lexical,
                })
            })
            .collect();
        Ok((200, Body::Json(json!({ "hits": hits }))))
    }

    fn delete_drawer(&mut self, id: &str, drawer_id: &str, req: &Request, now: i64) -> RestResult {
        self.deny_read_only()?;
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let deleted = store.delete_drawer(drawer_id).map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({ "id": drawer_id, "deleted": deleted })),
        ))
    }

    // ---- migration ----------------------------------------------------

    fn export(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let records = store.export_all_with_vectors().map_err(store_err)?;
        // JSONL: one {drawer, vector} object per line.
        let mut out = String::new();
        for (drawer, vector) in records {
            out.push_str(&json!({ "drawer": drawer, "vector": vector }).to_string());
            out.push('\n');
        }
        Ok((200, Body::Ndjson(out)))
    }

    fn import(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.deny_read_only()?;
        self.assert_or_401(id, req, now)?;
        // Parse every line before writing anything, so a malformed body
        // fails cleanly without a partial import.
        let mut records: Vec<(Drawer, Option<Vec<f32>>)> = Vec::new();
        for (n, line) in body.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let obj: Value = serde_json::from_str(line)
                .map_err(|e| RestError::new(400, format!("line {}: {e}", n + 1)))?;
            let drawer_val = obj.get("drawer").cloned().unwrap_or_else(|| obj.clone());
            let drawer: Drawer = serde_json::from_value(drawer_val)
                .map_err(|e| RestError::new(400, format!("line {}: {e}", n + 1)))?;
            let vector = obj.get("vector").and_then(Value::as_array).map(|a| {
                a.iter()
                    .filter_map(|v| v.as_f64().map(|f| f as f32))
                    .collect()
            });
            records.push((drawer, vector));
        }
        let store = self.store_for(id)?;
        let mut imported = 0u64;
        for (drawer, vector) in &records {
            store
                .import_record(drawer, vector.clone())
                .map_err(store_err)?;
            imported += 1;
        }
        Ok((200, Body::Json(json!({ "imported": imported }))))
    }

    // ---- helpers ------------------------------------------------------

    /// Open (or fetch the cached) store for `vault_id`, mapping a missing
    /// vault to 404.
    fn store_for(&mut self, vault_id: &str) -> Result<&mut PalaceStore, RestError> {
        if !self.stores.contains_key(vault_id) {
            if !self.manager.exists(vault_id) {
                return Err(RestError::new(404, "no such vault"));
            }
            let vault = self
                .manager
                .unlock(vault_id)
                .map_err(|e| RestError::new(500, e.to_string()))?;
            let embedder =
                (self.factory)(&vault).map_err(|e| RestError::new(500, e.to_string()))?;
            let store = PalaceStore::open_with_embedder(vault, embedder)
                .map_err(|e| RestError::new(500, e.to_string()))?;
            self.stores.insert(vault_id.to_string(), store);
        }
        Ok(self.stores.get_mut(vault_id).expect("just inserted"))
    }

    fn deny_read_only(&self) -> Result<(), RestError> {
        if self.read_only {
            Err(RestError::new(403, "server is read-only"))
        } else {
            Ok(())
        }
    }

    /// Verify the per-vault assertion, if a secret is set. The reason is
    /// logged server-side but never returned — it would leak whether a
    /// vault exists or how close a forgery got.
    fn assert_or_401(&self, vault_id: &str, req: &Request, now: i64) -> Result<(), RestError> {
        let Some(secret) = &self.secret else {
            return Ok(());
        };
        let header = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-Vault-Assertion"))
            .map(|h| h.value.as_str());
        assertion::verify(secret, vault_id, header, now, self.window).map_err(
            |e: AssertionError| {
                eprintln!("vault assertion rejected for {vault_id}: {e}");
                RestError::new(401, "unauthorized")
            },
        )
    }
}

fn store_err(e: StoreError) -> RestError {
    let code = match &e {
        StoreError::ExternalVault
        | StoreError::NotExternalVault
        | StoreError::EmbeddingDim { .. } => 400,
        StoreError::Integrity(_) => 409,
        _ => 500,
    };
    RestError::new(code, e.to_string())
}

fn err500(e: StoreError) -> RestError {
    RestError::new(500, e.to_string())
}

fn parse_json(body: &str) -> Result<Value, RestError> {
    serde_json::from_str(body).map_err(|e| RestError::new(400, format!("invalid JSON body: {e}")))
}

fn body_str(body: &Value, key: &str) -> Result<String, RestError> {
    body.get(key)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| RestError::new(400, format!("missing required field: {key}")))
}

fn parse_vector(body: &Value, key: &str) -> Result<Option<Vec<f32>>, RestError> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) => {
            let mut v = Vec::with_capacity(a.len());
            for x in a {
                let f = x
                    .as_f64()
                    .ok_or_else(|| RestError::new(400, "vector must be an array of numbers"))?;
                v.push(f as f32);
            }
            Ok(Some(v))
        }
        Some(_) => Err(RestError::new(400, "vector must be an array of numbers")),
    }
}

fn respond(req: Request, code: u16, body: &str, content_type: &str) {
    let header = Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes())
        .expect("valid content-type header");
    let _ = req.respond(
        Response::from_string(body)
            .with_status_code(code)
            .with_header(header),
    );
}
