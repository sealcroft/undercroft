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

/// Whole days from a drawer's `content_date` to the caller's reference date.
/// `None` whenever either side is missing or unparseable — an absent number
/// is honest, a guessed one is not.
fn elapsed_days(content_date: &Option<String>, as_of: Option<&str>) -> Option<i64> {
    let (d, a) = (content_date.as_deref()?, as_of?);
    undercroft_core::temporal::days_between(d, a)
}

/// Calendar weeks and months crossed between the content's date and the
/// reference — the units "how long since" is actually asked in. Reported
/// from the content's point of view, so a past drawer yields positive counts.
fn elapsed_calendar(
    content_date: &Option<String>,
    as_of: Option<&str>,
) -> (Option<i64>, Option<i64>) {
    let Some((d, a)) = content_date.as_deref().zip(as_of) else {
        return (None, None);
    };
    (
        undercroft_core::temporal::calendar_weeks_between(d, a),
        undercroft_core::temporal::calendar_months_between(d, a),
    )
}

/// The same interval phrased for a human or a prompt ("15 weeks before").
fn elapsed_phrase(content_date: &Option<String>, as_of: Option<&str>) -> Option<String> {
    let (d, a) = content_date.as_deref().zip(as_of)?;
    // Phrased from the reference looking back at the content, which is how
    // the question is put: "15 weeks before now", not "after".
    undercroft_core::temporal::describe_interval(a, d)
}

/// A drawer's time mentions with the same arithmetic applied to each one.
///
/// The drawer's `content_date` says when it was *written*; a mention inside it
/// says when the thing it describes *happened*, and those are different days.
/// A note written on the 8th saying "I went yesterday" is about the 7th, so
/// "how long ago did she go" answered from `content_date` is off by exactly
/// the day the mention resolution exists to recover.
///
/// Both are returned, neither is picked for the caller, and neither is left as
/// arithmetic homework — which is what hiding these behind the raw text was.
/// A mention naming a period carries the count from each end, since "some time
/// in May 2023" is genuinely a span of answers, not one.
fn mentions_with_elapsed(
    mentions: &[undercroft_core::temporal::TimeMention],
    as_of: Option<&str>,
) -> Vec<Value> {
    use undercroft_core::temporal::{days_between, describe_interval};
    mentions
        .iter()
        .map(|m| {
            let mut v = serde_json::to_value(m).unwrap_or_else(|_| json!({}));
            let (Some(obj), Some(a)) = (v.as_object_mut(), as_of) else {
                return v;
            };
            let Some((first, last)) = m.range() else {
                return v;
            };
            obj.insert("elapsed_days".into(), json!(days_between(first, a)));
            obj.insert("elapsed".into(), json!(describe_interval(a, first)));
            if m.is_period() {
                obj.insert("elapsed_days_end".into(), json!(days_between(last, a)));
            }
            v
        })
        .collect()
}

/// Produces the embedder a given vault should open with. Lives in `main`
/// (it knows the `onnx` feature and env config); this module just calls it.
pub type EmbedderFactory =
    Box<dyn Fn(&Vault) -> Result<Box<dyn undercroft_core::embed::Embedder + Send>>>;

/// Produces a second-stage reranker to attach to each per-vault store. The
/// model is loaded **once** in `main` and every call hands back a cheap
/// handle onto that single shared model (an `Arc` clone), so all tenant
/// vaults share one ONNX reranker instead of loading a copy apiece.
pub type RerankerFactory = Box<dyn Fn() -> Box<dyn undercroft_core::rerank::Reranker + Send + Sync>>;

/// The multi-tenant engine state behind the `/v1` routes. Single-threaded
/// (the `tiny_http` request loop is sequential), so the store cache needs
/// no locking.
pub struct Tenancy {
    manager: VaultManager,
    factory: EmbedderFactory,
    /// Optional shared second-stage reranker, attached to every store as it
    /// is opened. `None` ⇒ first-pass ranking only (the default).
    reranker: Option<RerankerFactory>,
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
            reranker: None,
            stores: HashMap::new(),
            read_only,
            secret,
            window: assertion::DEFAULT_WINDOW_SECS,
        }
    }

    /// Attach a shared second-stage reranker, applied to every per-vault
    /// store as it is opened. The model is loaded once by the caller; the
    /// factory only clones a handle onto it.
    pub fn with_reranker(mut self, factory: RerankerFactory) -> Self {
        self.reranker = Some(factory);
        self
    }

    /// True when this server enforces per-vault assertions.
    pub fn requires_assertion(&self) -> bool {
        self.secret.is_some()
    }

    /// Consume and answer one `/v1/...` request. The body is read up front
    /// (tiny_http hands it out only via `&mut Request`); everything after
    /// routes on the borrowed request plus that body string.
    pub fn handle(&mut self, mut req: Request, now: i64) {
        let start = std::time::Instant::now();
        let route_label = rest_route_label(req.url());
        let _span = undercroft_obs::scope_request(route_label, None);
        let mut body = String::new();
        let _ = std::io::Read::read_to_string(req.as_reader(), &mut body);
        let reply = self.route(&req, &body, now);
        let status = match &reply {
            Ok((code, _)) => *code,
            Err(e) => e.code,
        };
        undercroft_obs::http_request(route_label, status, start.elapsed());
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
            ("GET", &["v1", "vaults"]) => self.list_vaults(),
            ("DELETE", &["v1", "vaults", id]) => self.delete_vault(id, req, now),
            ("GET", &["v1", "vaults", id, "stats"]) => self.stats(id, req, now),
            ("GET", &["v1", "vaults", id, "stats", "history"]) => self.stats_history(id, req, now),
            ("POST", &["v1", "vaults", id, "drawers"]) => self.save_drawer(id, req, body, now),
            ("GET", &["v1", "vaults", id, "drawers"]) => self.list_drawers(id, req, now),
            ("POST", &["v1", "vaults", id, "search"]) => self.search(id, req, body, now),
            ("GET", &["v1", "vaults", id, "drawers", drawer_id]) => {
                self.get_drawer(id, drawer_id, req, now)
            }
            ("PUT", &["v1", "vaults", id, "drawers", drawer_id]) => {
                self.update_drawer(id, drawer_id, req, body, now)
            }
            ("DELETE", &["v1", "vaults", id, "drawers", drawer_id]) => {
                self.delete_drawer(id, drawer_id, req, now)
            }
            ("GET", &["v1", "vaults", id, "taxonomy"]) => self.taxonomy(id, req, now),
            ("GET", &["v1", "vaults", id, "kg", "stats"]) => self.kg_stats(id, req, now),
            ("GET", &["v1", "vaults", id, "kg", "entities"]) => self.kg_entities(id, req, now),
            ("GET", &["v1", "vaults", id, "kg", "query"]) => self.kg_query(id, req, now),
            ("GET", &["v1", "vaults", id, "kg", "timeline"]) => self.kg_timeline(id, req, now),
            ("GET", &["v1", "vaults", id, "kg", "receipts"]) => self.kg_receipts(id, req, now),
            ("POST", &["v1", "vaults", id, "refine"]) => self.refine(id, req, body, now),
            ("POST", &["v1", "vaults", id, "verify"]) => self.verify(id, req, now),
            ("POST", &["v1", "vaults", id, "rotate"]) => self.rotate(id, req, now),
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

    /// `GET /v1/vaults` — list vault ids (for the Palace Monitor picker).
    /// Palace-wide, so it is disabled under per-vault assertion isolation;
    /// operators there address vaults by a known id instead.
    fn list_vaults(&mut self) -> RestResult {
        if self.requires_assertion() {
            return Err(RestError::new(
                403,
                "vault listing is disabled under per-vault assertions",
            ));
        }
        let ids = self
            .manager
            .list()
            .map_err(|e| RestError::new(500, e.to_string()))?;
        Ok((200, Body::Json(json!({ "vaults": ids }))))
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
        let full = store.stats().map_err(store_err)?;
        let external = store.is_external();
        let vault = store.vault();
        undercroft_obs::set_gauge("drawers", id, full.records as f64);
        undercroft_obs::set_gauge("audit_chain_height", id, vault.writes() as f64);
        // Original fields kept verbatim (clients depend on them); the
        // management fields ride along. Wing names are fine here — this
        // route is authorized per vault, unlike the telemetry sampler which
        // withholds them for sealed vaults.
        Ok((
            200,
            Body::Json(json!({
                "id": id,
                "drawers": full.records,
                "level": vault.level().to_string(),
                "external": external,
                "writes": vault.writes(),
                "chain_head": vault.chain_head_hex(),
                "wings": full.wings
                    .iter()
                    .map(|(w, c)| json!({ "wing": w, "count": c }))
                    .collect::<Vec<_>>(),
                "rooms": full.rooms,
                "kg": serde_json::to_value(&full.kg).unwrap_or_else(|_| json!({})),
                "tunnels": full.tunnels,
                "db_bytes": full.db_bytes,
            })),
        ))
    }

    /// `GET /v1/vaults/{id}/stats/history?window=N` — the recent sample ring
    /// buffer (aggregate counts only) so a fresh stream client can backfill.
    /// Requires the `telemetry` feature; a plain build returns 501.
    #[cfg(feature = "telemetry")]
    fn stats_history(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        self.store_for(id)?; // 404s if the vault does not exist
        let window = req
            .url()
            .split('?')
            .nth(1)
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("window=")))
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(300)
            .min(300);
        let samples = undercroft_obs::history(id, window);
        Ok((
            200,
            Body::Json(serde_json::to_value(samples).unwrap_or_else(|_| json!([]))),
        ))
    }

    #[cfg(not(feature = "telemetry"))]
    fn stats_history(&mut self, _id: &str, _req: &Request, _now: i64) -> RestResult {
        Err(RestError::new(
            501,
            "history requires a build with --features telemetry",
        ))
    }

    /// Authorize a stream connection: verify the per-vault assertion and open
    /// (cache) the store so the sampler can read it. Returns whether the
    /// vault is sealed, or the HTTP status to reject with. `telemetry` only.
    #[cfg(feature = "telemetry")]
    pub fn authorize(&mut self, id: &str, req: &Request, now: i64) -> Result<bool, u16> {
        self.assert_or_401(id, req, now).map_err(|e| e.code)?;
        let store = self.store_for(id).map_err(|e| e.code)?;
        Ok(matches!(store.vault().level(), SecurityLevel::Sealed))
    }

    /// Sample every currently-watched vault into the telemetry ring buffer
    /// and refresh the per-vault Prometheus gauges. Called on the sampler
    /// tick; samples only vaults with an active stream subscriber, so it
    /// costs nothing when no dashboard is connected. `telemetry` only.
    #[cfg(feature = "telemetry")]
    pub fn sample(&self, now: i64) {
        for id in undercroft_obs::subscribed_vaults() {
            let Some(store) = self.stores.get(&id) else {
                continue;
            };
            let Ok(stats) = store.stats() else { continue };
            let sealed = matches!(store.vault().level(), SecurityLevel::Sealed);
            undercroft_obs::set_gauge("drawers", &id, stats.records as f64);
            undercroft_obs::set_gauge("audit_chain_height", &id, stats.writes as f64);
            undercroft_obs::set_gauge("kg_triples", &id, stats.kg.triples as f64);
            undercroft_obs::set_gauge("kg_entities", &id, stats.kg.entities as f64);
            undercroft_obs::set_gauge("store_bytes", &id, stats.db_bytes as f64);
            undercroft_obs::publish_sample(undercroft_obs::Sample {
                ts: now,
                vault: id.clone(),
                sealed,
                drawers: stats.records,
                rooms: stats.rooms,
                wings: if sealed { Vec::new() } else { stats.wings },
                kg_triples: stats.kg.triples,
                kg_entities: stats.kg.entities,
                kg_active: stats.kg.active,
                tunnels: stats.tunnels,
                chain_height: stats.writes,
                db_bytes: stats.db_bytes,
            });
        }
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

        // When the content happened, if the caller knows it. Distinct from
        // filed_at (when we wrote it down) and preserved rather than dropped:
        // conversational text leans on relative time ("yesterday", "last
        // Tuesday") that cannot be resolved without it.
        let content_date = body
            .get("content_date")
            .and_then(Value::as_str)
            .map(String::from);

        let store = self.store_for(id)?;
        let idx = store.count().map_err(err500)? as u32;
        let drawer =
            Drawer::new(wing, room, normalized, None, idx, "rest").with_content_date(content_date);

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
            // Soft per-room cap: spreads the returned hits across rooms so a
            // question whose answer spans several sessions is not starved by
            // the most verbose one. Absent ⇒ pure score order, as before.
            room_cap: body
                .get("room_cap")
                .and_then(Value::as_u64)
                .map(|v| v as usize),
        };
        let vector = parse_vector(&body, "vector")?;
        // Reference date for elapsed-time computation. The engine holds the
        // dates, so it does the calendar arithmetic — month lengths and leap
        // years are not a caller's problem, and certainly not a language
        // model's. Absent ⇒ no elapsed fields, nothing invented.
        let as_of = body.get("as_of").and_then(Value::as_str).map(String::from);
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
                    // When the content happened. A caller assembling an LLM
                    // context needs this to interpret relative time in the
                    // text; null when the writer did not know it.
                    "content_date": h.drawer.meta.content_date,
                    "filed_at": h.drawer.meta.filed_at,
                    // Dates written inside the text, already resolved against
                    // the drawer's own anchor at write time. Returned so a
                    // reader never has to re-derive what we computed exactly —
                    // including how long ago each one was, which is a
                    // different question from how old the drawer is.
                    "time_mentions": mentions_with_elapsed(
                        &h.drawer.meta.time_mentions,
                        as_of.as_deref(),
                    ),
                    "entities": h.drawer.meta.entities,
                    // Exact whole-day offsets from `as_of`, computed here
                    // rather than left to the reader. `elapsed` is the same
                    // interval phrased for display; both are omitted when the
                    // date is unknown or `as_of` was not supplied.
                    "elapsed_days": elapsed_days(&h.drawer.meta.content_date, as_of.as_deref()),
                    // Calendar counts, not day division: "how many weeks
                    // since" asks how many week boundaries were crossed, and
                    // 104 days spans 15 of them, not 14.
                    "elapsed_weeks": elapsed_calendar(&h.drawer.meta.content_date, as_of.as_deref()).0,
                    "elapsed_months": elapsed_calendar(&h.drawer.meta.content_date, as_of.as_deref()).1,
                    "elapsed": elapsed_phrase(&h.drawer.meta.content_date, as_of.as_deref()),
                    // Local-day counts assume both timestamps share a frame.
                    // When their UTC offsets differ they can disagree with
                    // absolute ordering — occasionally in sign — so say so
                    // rather than present one reading as the only one.
                    "same_frame": h
                        .drawer
                        .meta
                        .content_date
                        .as_deref()
                        .zip(as_of.as_deref())
                        .map(|(d, a)| undercroft_core::temporal::same_frame(d, a)),
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

    // ---- management (admin UI surface) --------------------------------

    /// `GET /v1/vaults/{id}/drawers?wing=&room=&limit=&offset=` — page
    /// through drawer summaries (id, wing/room, 120-char preview). Every
    /// row's HMAC is verified on the way out, like every other read.
    fn list_drawers(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let wing = query_param(req, "wing");
        let room = query_param(req, "room");
        let limit = query_param(req, "limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(50)
            .min(500);
        let offset = query_param(req, "offset")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let store = self.store_for(id)?;
        let rows = store
            .list_drawers(wing.as_deref(), room.as_deref(), limit, offset)
            .map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({
                "drawers": serde_json::to_value(rows).unwrap_or_else(|_| json!([]))
            })),
        ))
    }

    /// `GET /v1/vaults/{id}/drawers/{drawer_id}` — one full drawer
    /// (verbatim content), HMAC-verified.
    fn get_drawer(&mut self, id: &str, drawer_id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        match store.get(drawer_id).map_err(store_err)? {
            Some(d) => Ok((200, Body::Json(json!({ "drawer": d })))),
            None => Err(RestError::new(404, "no such drawer")),
        }
    }

    /// `PUT /v1/vaults/{id}/drawers/{drawer_id}` — replace one drawer's
    /// content (`{text}`). The content is stored verbatim (normalized like
    /// every other write path); id, wing, and room are immutable.
    fn update_drawer(
        &mut self,
        id: &str,
        drawer_id: &str,
        req: &Request,
        body: &str,
        now: i64,
    ) -> RestResult {
        self.deny_read_only()?;
        self.assert_or_401(id, req, now)?;
        let body = parse_json(body)?;
        let text = body_str(&body, "text")?;
        let normalized = normalize_content(&text);
        if normalized.is_empty() {
            return Err(RestError::new(400, "text is empty after normalization"));
        }
        let store = self.store_for(id)?;
        let updated = store
            .update_drawer(drawer_id, &normalized)
            .map_err(store_err)?;
        if updated {
            Ok((200, Body::Json(json!({ "id": drawer_id, "updated": true }))))
        } else {
            Err(RestError::new(404, "no such drawer"))
        }
    }

    /// `GET /v1/vaults/{id}/taxonomy` — the wing → room tree with drawer
    /// counts.
    fn taxonomy(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let tree = store.taxonomy().map_err(store_err)?;
        let wings: Vec<Value> = tree
            .into_iter()
            .map(|(wing, rooms)| {
                json!({
                    "wing": wing,
                    "rooms": rooms
                        .into_iter()
                        .map(|(room, count)| json!({ "room": room, "count": count }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        Ok((200, Body::Json(json!({ "wings": wings }))))
    }

    /// `POST /v1/vaults/{id}/verify` — walk every record verifying its
    /// HMAC and replay the audit chain. Read-only despite the verb (POST
    /// because it is an expensive action, not a resource read).
    fn verify(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let report = store.verify().map_err(store_err)?;
        let ok = report.ok();
        Ok((
            200,
            Body::Json(json!({
                "ok": ok,
                "records_checked": report.records_checked,
                "bad_records": report.bad_records,
                "chain_ok": report.chain_ok,
            })),
        ))
    }

    /// `POST /v1/vaults/{id}/rotate` — rotate the vault onto fresh keys
    /// (fresh salt ⇒ all three derived keys change; every artifact is
    /// re-sealed in one transaction). The caller must be the only writer —
    /// same contract as the CLI `vault rotate`. Remote-index copies go
    /// stale; the response says so.
    fn rotate(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.deny_read_only()?;
        self.assert_or_401(id, req, now)?;
        let candidate = self
            .manager
            .rotation_candidate(id)
            .map_err(|e| RestError::new(400, e.to_string()))?;
        let store = self.store_for(id)?;
        let report = store.rotate_keys(candidate).map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({
                "id": id,
                "rotated": true,
                "report": serde_json::to_value(&report).unwrap_or_else(|_| json!({})),
                "chain_head": store.vault().chain_head_hex(),
                "note": "remote index copies are stale; re-run `undercroft index push` if used",
            })),
        ))
    }

    // ---- knowledge graph (read-only browse) ---------------------------

    /// `GET /v1/vaults/{id}/kg/stats` — entity/triple/active/closed counts.
    fn kg_stats(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let stats = store.kg_stats().map_err(store_err)?;
        Ok((
            200,
            Body::Json(serde_json::to_value(&stats).unwrap_or_else(|_| json!({}))),
        ))
    }

    /// `GET /v1/vaults/{id}/kg/entities?limit=&offset=` — paged entity
    /// summaries, tag-verified.
    fn kg_entities(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let limit = query_param(req, "limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(100)
            .min(500);
        let offset = query_param(req, "offset")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let store = self.store_for(id)?;
        let rows = store.kg_entities(limit, offset).map_err(store_err)?;
        let entities: Vec<Value> = rows
            .into_iter()
            .map(|(name, etype, created)| {
                json!({ "name": name, "etype": etype, "created_at": created })
            })
            .collect();
        Ok((200, Body::Json(json!({ "entities": entities }))))
    }

    /// `GET /v1/vaults/{id}/kg/query?entity=&direction=&as_of=` — facts
    /// about one entity (direction outgoing|incoming|both; `as_of` filters
    /// to facts valid at that instant).
    fn kg_query(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let entity = query_param(req, "entity")
            .map(|v| pct_decode(&v))
            .ok_or_else(|| RestError::new(400, "entity query parameter required"))?;
        let direction = query_param(req, "direction").unwrap_or_else(|| "both".into());
        let as_of = query_param(req, "as_of").map(|v| pct_decode(&v));
        let store = self.store_for(id)?;
        let triples = store
            .kg_query_entity(&entity, as_of.as_deref(), &direction)
            .map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({
                "entity": entity,
                "triples": serde_json::to_value(triples).unwrap_or_else(|_| json!([]))
            })),
        ))
    }

    /// `GET /v1/vaults/{id}/kg/timeline?entity=` — every fact (open and
    /// closed) in temporal order, optionally scoped to one entity.
    fn kg_timeline(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let entity = query_param(req, "entity").map(|v| pct_decode(&v));
        let store = self.store_for(id)?;
        let triples = store.kg_timeline(entity.as_deref()).map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({
                "triples": serde_json::to_value(triples).unwrap_or_else(|_| json!([]))
            })),
        ))
    }

    /// `GET /v1/vaults/{id}/kg/receipts` — verify every distilled fact
    /// against its cited verbatim source. Each entry reports a verdict
    /// (verified | source_changed | dangling | tampered); the summary counts
    /// let a caller alert on `tampered` without walking the list.
    fn kg_receipts(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let receipts = store.kg_verify_receipts().map_err(store_err)?;
        let mut summary = serde_json::Map::new();
        for verdict in ["verified", "source_changed", "dangling", "tampered"] {
            let n = receipts
                .iter()
                .filter(|r| {
                    serde_json::to_value(&r.verdict)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .as_deref()
                        == Some(verdict)
                })
                .count();
            summary.insert(verdict.into(), json!(n));
        }
        Ok((
            200,
            Body::Json(json!({
                "receipts": serde_json::to_value(&receipts).unwrap_or_else(|_| json!([])),
                "summary": summary,
            })),
        ))
    }

    /// `POST /v1/vaults/{id}/refine` — distil the vault's verbatim drawers
    /// into receipted knowledge-graph facts, and mirror each fact as a
    /// searchable drawer so distillation reaches the retrieval surface.
    ///
    /// Body: `{ wing?, room?, limit?, fact_room? }`. `wing`/`room` scope
    /// which verbatim drawers are read (`room` defaults to everything except
    /// `fact_room`, so re-running never distils its own output); `fact_room`
    /// (default `facts`) is the room the fact-drawers land in, inside their
    /// *source drawer's* wing. That keeps per-wing isolation intact and lets
    /// a caller retrieve verbatim-only, distilled-only, or both by varying
    /// the room filter on `/search`.
    ///
    /// A fact restated across several source chunks is cited once per source
    /// in the graph but mirrored to the retrieval surface only once, so one
    /// fact cannot occupy several slots of a single top-k. `duplicates`
    /// reports how often that collapse fired.
    ///
    /// Requires `UNDERCROFT_LLM_URL` — without it the vault is untouched and
    /// this answers 400. The verbatim drawers are never modified.
    fn refine(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.deny_read_only()?;
        self.assert_or_401(id, req, now)?;
        let body = parse_json(body)?;
        let wing = body.get("wing").and_then(Value::as_str);
        let room = body.get("room").and_then(Value::as_str);
        let fact_room = body
            .get("fact_room")
            .and_then(Value::as_str)
            .unwrap_or("facts");
        validate_name(fact_room, "fact_room").map_err(|e| RestError::new(400, e.to_string()))?;
        let limit = body
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(1_000_000) as usize;

        let llm =
            undercroft_llm::LlmClient::from_env().map_err(|e| RestError::new(400, e.to_string()))?;
        let store = self.store_for(id)?;

        // Read the verbatim side only: never re-distil fact-drawers, or a
        // second call would compound its own output into the graph.
        let sources: Vec<Drawer> = store
            .recent(wing, limit)
            .map_err(store_err)?
            .into_iter()
            .filter(|d| d.meta.room != fact_room)
            .filter(|d| room.is_none_or(|r| d.meta.room == r))
            .collect();

        // The knowledge graph already collapses a repeated triple onto one
        // row (`triple_id` is content-derived, ON CONFLICT DO UPDATE). The
        // searchable mirror has to match that, or a fact restated across
        // several source chunks would occupy several slots of one top-k and
        // crowd out distinct evidence. Keyed on the triple id the graph
        // itself returns, so the two notions of identity cannot drift.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let (mut facts, mut duplicates, mut skipped, mut failed) = (0u32, 0u32, 0u32, 0u32);
        let mut dated_from_text = 0u32;
        for d in &sources {
            let anchor = d
                .meta
                .content_date
                .as_deref()
                .and_then(undercroft_core::temporal::parse_anchor);
            let triples = match llm.extract_triples(&d.content) {
                Ok(t) => t,
                Err(e) => {
                    undercroft_obs::diag_error!("refine: triples failed for {}: {e}", d.id);
                    failed += 1;
                    continue;
                }
            };
            for t in triples {
                let subject = t.subject.to_lowercase();
                let predicate = t.predicate.to_lowercase();
                if validate_name(&subject, "subject").is_err()
                    || validate_name(&predicate, "predicate").is_err()
                {
                    skipped += 1;
                    continue;
                }
                // When the fact was established, which is not the same as
                // when the note was written: "I quit smoking three months
                // ago" is a fact about February in a note dated May. The
                // extractor is asked to point at the words that say so and
                // is not permitted to supply a date — `resolve_claimed_span`
                // rejects any span the note does not literally contain and
                // resolves the rest deterministically. Anything unverified
                // falls back to the note's own date, which is what every
                // fact used to get.
                let dated = t.when.as_deref().and_then(|claim| {
                    undercroft_core::temporal::resolve_claimed_span(&d.content, claim, anchor)
                });
                if dated.is_some() {
                    dated_from_text += 1;
                }
                let fact_date = dated
                    .as_ref()
                    .and_then(|m| m.resolved.clone())
                    .or_else(|| d.meta.content_date.clone());
                // The receipt is an HMAC-covered citation back to the
                // verbatim drawer this fact came from — checkable later via
                // `GET /v1/vaults/{id}/kg/receipts`.
                // `valid_to` stays open even when the span named a period.
                // A period says when the event *happened*; it does not say
                // the fact stopped holding, and "in May 2023" must not be
                // read as "expired on the 31st".
                let triple_id = store
                    .kg_add_receipted(
                        &subject,
                        &predicate,
                        &t.object,
                        fact_date.as_deref(),
                        None,
                        0.8, // model-extracted: below human-asserted confidence
                        (&d.id, &d.content),
                    )
                    .map_err(store_err)?;
                // Restating a known fact still re-cites it in the graph — the
                // receipt above is refreshed either way — but it must not add
                // a second copy to the retrieval surface.
                if !seen.insert(triple_id) {
                    duplicates += 1;
                    continue;
                }
                store
                    .upsert(
                        &Drawer::new(
                            &d.meta.wing,
                            fact_room,
                            format!("{} {} {}", t.subject, t.predicate, t.object),
                            None,
                            facts,
                            "distill",
                        )
                        .with_content_date(fact_date),
                    )
                    .map_err(store_err)?;
                facts += 1;
            }
        }

        Ok((
            200,
            Body::Json(json!({
                "sources": sources.len(),
                "facts": facts,
                "duplicates": duplicates,
                "skipped": skipped,
                "failed": failed,
                // How many facts were dated by words in the note rather than
                // by the note's own date. Reported because it is the only
                // visible measure of whether the extractor is pointing at
                // real spans — a model that answers with dates instead of
                // quotations drives this to zero without erroring.
                "dated_from_text": dated_from_text,
                "fact_room": fact_room,
                "model": llm.model(),
            })),
        ))
    }

    // ---- migration ----------------------------------------------------

    fn export(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let records = store.export_all_with_vectors().map_err(store_err)?;
        // JSONL: one {drawer, vector[, tok]} object per line. `tok` is the
        // drawer's late-interaction token matrix as a portable artifact
        // (model name + base64 of the packed plaintext) — the expensive
        // derived data, carried so an import restores it by copy instead of
        // re-running one transformer forward per drawer.
        let mut out = String::new();
        for (drawer, vector) in records {
            let mut line = json!({ "drawer": drawer, "vector": vector });
            if let Some((model, packed)) = store.token_artifact(&drawer.id).map_err(store_err)? {
                line["tok"] = json!({ "model": model, "b64": b64encode(&packed) });
            }
            out.push_str(&line.to_string());
            out.push('\n');
        }
        Ok((200, Body::Ndjson(out)))
    }

    fn import(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.deny_read_only()?;
        self.assert_or_401(id, req, now)?;
        // Parse every line before writing anything, so a malformed body
        // fails cleanly without a partial import.
        type ImportLine = (Drawer, Option<Vec<f32>>, Option<(String, Vec<u8>)>);
        let mut records: Vec<ImportLine> = Vec::new();
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
            // Optional portable token artifact: {"model": "...", "b64": "..."}.
            let tok = match obj.get("tok") {
                Some(t) => {
                    let model = t.get("model").and_then(Value::as_str).ok_or_else(|| {
                        RestError::new(400, format!("line {}: tok.model missing", n + 1))
                    })?;
                    let b64 = t.get("b64").and_then(Value::as_str).ok_or_else(|| {
                        RestError::new(400, format!("line {}: tok.b64 missing", n + 1))
                    })?;
                    let packed = b64decode(b64).map_err(|e| {
                        RestError::new(400, format!("line {}: tok.b64: {e}", n + 1))
                    })?;
                    // Validate here so a bad artifact fails the whole body
                    // cleanly (parse-before-write), not mid-import.
                    if undercroft_core::late::dequantize_tokens(&packed).is_none() {
                        return Err(RestError::new(
                            400,
                            format!("line {}: tok artifact does not parse", n + 1),
                        ));
                    }
                    Some((model.to_string(), packed))
                }
                None => None,
            };
            records.push((drawer, vector, tok));
        }
        let store = self.store_for(id)?;
        let mut imported = 0u64;
        for (drawer, vector, tok) in &records {
            store
                .import_record(drawer, vector.clone())
                .map_err(store_err)?;
            if let Some((model, packed)) = tok {
                // Re-sealed under this vault's key; restore skips the
                // per-drawer encode forward.
                store
                    .import_token_artifact(&drawer.id, model, packed)
                    .map_err(store_err)?;
            }
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
            let mut store = PalaceStore::open_with_embedder(vault, embedder)
                .map_err(|e| RestError::new(500, e.to_string()))?;
            if let Some(make_reranker) = &self.reranker {
                store.set_reranker(Some(make_reranker()));
            }
            // Same retrieval contract as the CLI: UNDERCROFT_RETRIEVAL=pq
            // enables the on-disk PQ/IVF prefilter per tenant vault (plain
            // on hmac-only; AEAD-sealed rows + RAM cache on sealed).
            if std::env::var("UNDERCROFT_RETRIEVAL").as_deref() == Ok("pq") {
                store.set_pq(true);
            }
            self.stores.insert(vault_id.to_string(), store);
            undercroft_obs::vault_opened();
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
                undercroft_obs::diag_warn!("vault assertion rejected for {vault_id}: {e}");
                undercroft_obs::auth_rejected("assertion");
                RestError::new(401, "unauthorized")
            },
        )
    }
}

/// Coarse, cardinality-safe route label for metrics (ids stripped).
fn rest_route_label(url: &str) -> &'static str {
    let path = url.split('?').next().unwrap_or("");
    if path.ends_with("/search") {
        "v1_search"
    } else if path.ends_with("/stats/history") {
        "v1_stats_history"
    } else if path.ends_with("/stream") {
        "v1_stream"
    } else if path.ends_with("/stats") {
        "v1_stats"
    } else if path.ends_with("/export") {
        "v1_export"
    } else if path.ends_with("/import") {
        "v1_import"
    } else if path.ends_with("/taxonomy") {
        "v1_taxonomy"
    } else if path.contains("/kg/") {
        "v1_kg"
    } else if path.ends_with("/verify") {
        "v1_verify"
    } else if path.ends_with("/rotate") {
        "v1_rotate"
    } else if path.contains("/drawers") {
        "v1_drawers"
    } else {
        "v1_vaults"
    }
}

/// First value of a query-string key (raw; no percent-decoding — vault,
/// wing, and room names are `validate_name`-restricted anyway; values that
/// can hold free text go through [`pct_decode`] at the call site).
fn query_param(req: &Request, key: &str) -> Option<String> {
    req.url().split('?').nth(1)?.split('&').find_map(|kv| {
        kv.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
            .map(String::from)
    })
}

/// Minimal percent-decoding for query values that carry free text (entity
/// names): `%XX` escapes and `+` as space. Invalid escapes pass through.
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn b64encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
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
