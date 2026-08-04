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
// The read-time declarations (`language`, `week_start`, `date_order`,
// `calendar`) and the honest-exclusion counts are parsed in `crate::search`,
// which MCP shares verbatim — the two surfaces read the same key names off the
// same JSON, and re-implementing them here is how `week_start` came to work on
// one of them only.
use crate::search::{locale_from, morph_lang_from, Exclusions};

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

/// Triples as JSON, each labelled with where it rests.
///
/// `grounding` is `stated` (the note's own words support it, at the recorded
/// spans), `background` (checked, and the note supports none of it), or
/// `unevaluated` (never checked — every fact distilled before grounding
/// existed). Three states, because "we did not look" and "we looked and found
/// nothing" are different claims.
///
/// Optionally narrowed by `?grounding=`. **Never narrowed by default**: a
/// background fact is what connects entities across notes that never mention
/// each other, so filtering them out silently would break exactly the
/// multi-hop questions the graph exists to answer.
fn triples_json(triples: Vec<undercroft_store::Triple>, want: Option<&str>) -> Value {
    let rows: Vec<Value> = triples
        .into_iter()
        .filter_map(|t| {
            let label = match t.grounding() {
                undercroft_core::support::Grounding::Stated => "stated",
                undercroft_core::support::Grounding::Background => "background",
                undercroft_core::support::Grounding::Unevaluated => "unevaluated",
            };
            if want.is_some_and(|w| w != label) {
                return None;
            }
            let mut v = serde_json::to_value(&t).ok()?;
            if let Some(o) = v.as_object_mut() {
                o.insert("grounding".into(), json!(label));
            }
            Some(v)
        })
        .collect();
    json!(rows)
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
    /// The vault this same process ALSO holds open behind `/mcp`, when the
    /// binary is running `serve-http` (which opens one store for MCP and
    /// lets `Tenancy` open its own per vault). Two independent handles over
    /// one vault directory is fine for reads and ordinary writes — SQLite
    /// arbitrates those — but not for an operation that retires the keys or
    /// removes the files under the other handle. See [`Self::deny_co_resident`].
    mcp_vault: Option<String>,
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
            mcp_vault: None,
            secret,
            window: assertion::DEFAULT_WINDOW_SECS,
        }
    }

    /// Declare the vault this process also serves over `/mcp`, so the two
    /// routes that would pull the ground out from under that second handle
    /// — key rotation and vault deletion — can refuse instead of corrupting
    /// it. `serve-http` is the only caller; a bare `/v1` deployment holds
    /// exactly one handle per vault and needs none of this.
    pub fn with_mcp_vault(mut self, vault: impl Into<String>) -> Self {
        self.mcp_vault = Some(vault.into());
        self
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

    /// The same assertion gate every `/v1` handler runs, for a transport
    /// that is not `/v1`.
    ///
    /// `/mcp` is mounted on this server, in this process, and serves the
    /// full read/write tool surface of the vault named by `--vault`. It had
    /// no assertion check, so an operator who declared
    /// `UNDERCROFT_ASSERTION_SECRET` — precisely to stop one bearer from
    /// addressing every vault — still left that one vault open to anyone
    /// holding the palace bearer, while the startup banner claimed
    /// "per-vault assertions required" without qualification. Isolation is
    /// a property of the engine, not of which port path you drive.
    /// Unset secret ⇒ `Ok`, so a deployment that never declared it sees no
    /// change at all.
    pub fn assert_transport(&self, vault_id: &str, req: &Request, now: i64) -> Result<(), u16> {
        self.assert_or_401(vault_id, req, now).map_err(|e| e.code)
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
        // The read-only posture is decided HERE, once, in front of dispatch —
        // not by a guard at the top of each mutating handler. There were
        // thirteen such guards and fourteen mutating routes: `POST
        // .../kg/authority` was simply never given one, so a `--read-only`
        // server rewrote HMAC-covered authority columns, superseded the
        // previous canonical holder and appended to the audit chain while
        // answering 200 — and the identical capability over `/mcp` in the same
        // process answered "server is read-only". One forgotten call is a
        // silent write door, so the decision moved to the one place every
        // request passes through, and it fails CLOSED (see `mutates`).
        if self.read_only && mutates(method.as_str(), segs.as_slice()) {
            return Err(RestError::new(403, "server is read-only"));
        }
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
            ("GET", &["v1", "vaults", id, "supersessions"]) => {
                self.drawer_supersessions(id, req, now)
            }
            ("POST", &["v1", "vaults", id, "trust"]) => self.set_trust(id, req, body, now),
            ("GET", &["v1", "vaults", id, "trust"]) => self.list_trust(id, req, now),
            ("GET", &["v1", "vaults", id, "admission"]) => self.admission_list(id, req, now),
            ("POST", &["v1", "vaults", id, "forget"]) => self.forget(id, req, body, now),
            ("POST", &["v1", "vaults", id, "admission"]) => self.admission_rule(id, req, body, now),
            ("GET", &["v1", "vaults", id, "retention"]) => self.retention_list(id, req, now),
            ("POST", &["v1", "vaults", id, "retention"]) => self.retention_set(id, req, body, now),
            ("POST", &["v1", "vaults", id, "retention", "sweep"]) => {
                self.retention_sweep(id, req, body, now)
            }
            ("GET", &["v1", "vaults", id, "kg", "canonical", key]) => {
                self.kg_canonical(id, key, req, now)
            }
            ("POST", &["v1", "vaults", id, "kg", "authority"]) => {
                self.kg_authority(id, req, body, now)
            }
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
        self.assert_or_401(id, req, now)?;
        // Dropping the Tenancy's handle does not close the `/mcp` one.
        self.deny_co_resident(id, "deleting a vault", "delete it while nothing serves it")?;
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
        // The COMMITTED height (`PalaceStats`, i.e. `chain_meta`), never
        // this handle's cached manifest: in `serve-http` the MCP store is
        // a second handle on the same vault, and whichever handle did not
        // write kept reporting the head it last anchored — a frozen gauge
        // beside a climbing `drawers` count.
        undercroft_obs::set_gauge("audit_chain_height", id, full.writes as f64);
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
                "writes": full.writes,
                "chain_head": full.chain_head,
                "wings": full.wings
                    .iter()
                    .map(|(w, c)| json!({ "wing": w, "count": c }))
                    .collect::<Vec<_>>(),
                "rooms": full.rooms,
                "kg": serde_json::to_value(&full.kg).unwrap_or_else(|_| json!({})),
                "tunnels": full.tunnels,
                "db_bytes": full.db_bytes,
                // Trained index artifacts and how many times each has been
                // trained here. Projected by hand like every field above —
                // this route does NOT serialize `PalaceStats`, so a field
                // added to that struct does not reach the wire until it is
                // added here too.
                "codebooks": full.codebooks
                    .iter()
                    .map(|(artifact, generation)| json!({
                        "artifact": artifact,
                        "generation": generation,
                    }))
                    .collect::<Vec<_>>(),
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
        // The declared record kind — closed vocabulary, validated here so a
        // typo is a 400 with the vocabulary in it, never a silently
        // unreachable label. Absent is always valid.
        let kind = body.get("kind").and_then(Value::as_str).map(String::from);
        if let Some(k) = kind.as_deref() {
            undercroft_core::validate_kind(k).map_err(|e| RestError::new(400, e.to_string()))?;
        }
        // A declared supersession link: this save replaces the named
        // drawer. The store receipts the link at its write choke point;
        // the superseded drawer is never deleted or hidden.
        let supersedes = body
            .get("supersedes")
            .and_then(Value::as_str)
            .map(String::from);

        // Provenance CLAIMS (recorded + HMAC-covered, never trusted):
        // which agent, over which channel class, in which session. The
        // surface identity itself is `added_by = "rest"`, stamped here.
        let prov = |k: &str| body.get(k).and_then(Value::as_str).map(String::from);
        let (agent, channel, session) = (prov("agent"), prov("channel"), prov("session"));

        let store = self.store_for(id)?;
        let idx = store.next_append_index().map_err(err500)? as u32;
        let drawer = Drawer::new(wing, room, normalized, None, idx, "rest")
            .with_content_date(content_date)
            .with_kind(kind)
            .with_supersedes(supersedes)
            .with_provenance(agent, channel, session);

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
                        quarantined: false,
                    }
                }
            }
        } else {
            match dedup {
                Some(t) => store.save_with_dedup(&drawer, t).map_err(store_err)?,
                // The SCREENED save: when admission diverts, the response
                // must say so and carry the id the drawer actually landed
                // under — the update path's typed outcome, owed by the
                // save path too (the scripted-attacker gate found this
                // surface still reporting a plain `created: true`).
                None => store.upsert_screened(&drawer).map_err(store_err)?,
            }
        };
        let status = if out.quarantined { 202 } else { 200 };
        Ok((
            status,
            Body::Json(json!({
                "id": out.id,
                "created": out.created,
                "deduped": out.deduped,
                "quarantined": out.quarantined,
            })),
        ))
    }

    fn search(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let body = parse_json(body)?;
        let query = body_str(&body, "query")?;
        // The instant this ranking is computed as of. Resolved here — not
        // inside the store — so the response can echo the exact value a
        // second page must repeat: pages of one iteration slice one ranking,
        // pinned to one clock, and the caller pins it by sending this field
        // back verbatim. A value that does not parse is a caller error, said
        // out loud rather than silently ranked against the host clock.
        let ranked_at = match body.get("ranked_at").and_then(Value::as_str) {
            Some(s) => {
                time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                    .map_err(|_| RestError::new(400, "ranked_at must be an RFC 3339 instant"))?
            }
            None => time::OffsetDateTime::now_utc(),
        };
        let opts = SearchOptions {
            // The SAME `language` the date scanner reads. One declaration per
            // request; each consumer documents what it supports and falls back
            // rather than guessing. Morphology knows en and de; the temporal
            // scanner knows en and ar.
            morph_lang: morph_lang_from(&body),
            wing: body.get("wing").and_then(Value::as_str).map(String::from),
            room: body.get("room").and_then(Value::as_str).map(String::from),
            // Declared-kind filter (closed vocabulary; the store rejects an
            // unknown value as an error, surfaced as a 400 below).
            kind: body.get("kind").and_then(Value::as_str).map(String::from),
            // Trust floor for this query (closed vocabulary, 400 if
            // unknown): wings assigned below it never enter the
            // competition. Assignment itself is an operator action —
            // POST /trust — never part of a search.
            min_trust: body
                .get("min_trust")
                .and_then(Value::as_str)
                .map(String::from),
            // One default page size for every surface (`crate::search`): this
            // route answered 10 while the CLI and MCP answered 5, so "the same
            // search" returned a different number of hits per transport.
            limit: body
                .get("limit")
                .and_then(Value::as_u64)
                .map(|v| v as usize)
                .unwrap_or(crate::search::DEFAULT_LIMIT),
            // Rank-space page start: pass the previous response's
            // `next_offset` (with its `ranked_at`) to continue deeper instead
            // of re-asking the same question.
            offset: body.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize,
            ranked_at: Some(ranked_at),
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
        // Which language the drawers' own text should be read in. Read-time,
        // because the reading is live — a corpus ingested under one locale is
        // answered correctly under another without being rewritten.
        let locale = locale_from(&body);
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
                    // Every day this same text is known to have been recorded,
                    // earliest first. More than one entry means dedup collapsed
                    // identical wording written on different days — the text is
                    // one record, the chronology is all of them.
                    "occurrences": serde_json::to_value(h.drawer.all_occurrences())
                        .unwrap_or_else(|_| json!([])),
                    // Dates written inside the text, already resolved against
                    // the drawer's own anchor at write time. Returned so a
                    // reader never has to re-derive what we computed exactly —
                    // including how long ago each one was, which is a
                    // different question from how old the drawer is.
                    // Read live, not from the seal. The resolution is derived
                    // from the drawer's own text and `content_date`, both
                    // immutable, so re-reading costs a linear scan and makes
                    // every improvement to the scanner retroactive across
                    // every existing vault — no migration, no re-ingest.
                    "time_mentions": mentions_with_elapsed(
                        &h.drawer.live_time_mentions_in(locale),
                        as_of.as_deref(),
                    ),
                    // Present only when this build disagrees with the sealed
                    // reading: the drawer was written by an older
                    // understanding of the language. Not an error, and not
                    // something to resolve silently.
                    "mentions_restated": h.drawer.time_mentions_differ()
                        .then_some(true),
                    // Derived at read: names are words out of the content, and unsealed
                    // metadata must not carry them. See Drawer::meta_at_rest.
                    "entities": h.drawer.live_entities(),
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
                    "lexical_exact": h.lexical_exact,
                    "lexical_morph": h.lexical_morph,
                })
            })
            .collect();
        // The continuation, spelled out: repeat the request with
        // `offset: next_offset` and this same `ranked_at` for the next page.
        // A page shorter than `limit` means the ranking is exhausted. Both
        // fields are additive — a caller that ignores them sees exactly the
        // response this route always returned.
        let next_offset = opts.offset + hits.len();
        let ranked_at_echo = ranked_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        // What this request's own filters kept out of the competition
        // (docs/LABELS.md), counted once for every surface in `crate::search`:
        // a thin result under a `kind` filter or a `min_trust` floor is
        // otherwise indistinguishable from a thin corpus. Both keys are
        // additive and present only while their filter is.
        let excluded = {
            let store = self.store_for(id)?;
            Exclusions::measure(store, &opts).map_err(store_err)?
        };
        let mut resp = json!({
            "hits": hits,
            "next_offset": next_offset,
            "ranked_at": ranked_at_echo,
        });
        if let Some(n) = excluded.unlabeled {
            resp["unlabeled_excluded"] = json!(n);
        }
        if let Some(n) = excluded.trust_excluded {
            resp["trust_excluded_wings"] = json!(n);
        }
        Ok((200, Body::Json(resp)))
    }

    fn delete_drawer(&mut self, id: &str, drawer_id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        // A delete of an id that is not here is NOT a success. This
        // answered 200 `{"deleted": false}`, so a client checking only the
        // status was told the delete worked when the id was a typo, a
        // stale id or an already-swept drawer — while CLI `drawer delete`
        // and MCP `undercroft_delete_drawer` both treat it as an error, and
        // GET/PUT on the same id answer 404. The `deleted` key stays for
        // the callers that read it; it is now always `true` on a 200.
        if !store.delete_drawer(drawer_id).map_err(store_err)? {
            return Err(RestError::new(404, format!("no drawer {drawer_id}")));
        }
        Ok((200, Body::Json(json!({ "id": drawer_id, "deleted": true }))))
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
            Some(d) => {
                // Same rule as search: the sealed reading is the record, the
                // live one is the answer. `drawer` stays byte-faithful to
                // what is stored so an export and a fetch cannot disagree
                // about the record itself.
                let live = d.live_time_mentions();
                let restated = live != d.meta.time_mentions;
                let mut body = json!({ "drawer": d });
                if restated {
                    body["live_time_mentions"] =
                        serde_json::to_value(&live).unwrap_or_else(|_| json!([]));
                    body["mentions_restated"] = json!(true);
                }
                Ok((200, Body::Json(body)))
            }
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
        self.assert_or_401(id, req, now)?;
        let body = parse_json(body)?;
        let text = body_str(&body, "text")?;
        let normalized = normalize_content(&text);
        if normalized.is_empty() {
            return Err(RestError::new(400, "text is empty after normalization"));
        }
        let store = self.store_for(id)?;
        match store
            .update_drawer(drawer_id, &normalized, "rest")
            .map_err(store_err)?
        {
            undercroft_store::UpdateOutcome::Updated => {
                Ok((200, Body::Json(json!({ "id": drawer_id, "updated": true }))))
            }
            undercroft_store::UpdateOutcome::Quarantined => Ok((
                202,
                Body::Json(json!({ "id": drawer_id, "updated": false,
                                    "quarantined": true })),
            )),
            undercroft_store::UpdateOutcome::NotFound => Err(RestError::new(404, "no such drawer")),
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
    /// HMAC, replay the audit chain, and check every drawer supersession
    /// receipt. Read-only despite the verb (POST because it is an
    /// expensive action, not a resource read).
    ///
    /// `ok` is the vault's whole verdict, the same one CLI `verify` exits
    /// 2 on and MCP prints as VERIFY FAILED. It used to be narrower here:
    /// the supersession leg was a second store call only those two
    /// surfaces made, so this route — and the admin console reading it —
    /// answered green on a vault with a tampered link. The counts are the
    /// same breakdown `GET …/supersessions` returns, so an alert can stay
    /// on this one route.
    fn verify(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let report = store.verify().map_err(store_err)?;
        use undercroft_store::ReceiptVerdict as V;
        let count = |v: V| {
            report
                .supersessions
                .iter()
                .filter(|l| l.verdict == v)
                .count()
        };
        let bad_supersessions: Vec<&str> = report
            .supersessions
            .iter()
            .filter(|l| l.verdict == V::Tampered)
            .map(|l| l.drawer_id.as_str())
            .collect();
        Ok((
            200,
            Body::Json(json!({
                "ok": report.ok(),
                "records_checked": report.records_checked,
                "bad_records": report.bad_records,
                "chain_ok": report.chain_ok,
                "supersessions": {
                    "verified": count(V::Verified),
                    "source_changed": count(V::SourceChanged),
                    "dangling": count(V::Dangling),
                    "unreceipted": count(V::Unreceipted),
                    "tampered": count(V::Tampered),
                },
                "bad_supersessions": bad_supersessions,
            })),
        ))
    }

    /// `POST /v1/vaults/{id}/rotate` — rotate the vault onto fresh keys
    /// (fresh salt ⇒ all three derived keys change; every artifact is
    /// re-sealed in one transaction). The caller must be the only writer —
    /// same contract as the CLI `vault rotate` — and, since that contract is
    /// about being the ONLY handle, this refuses (409) for the vault the same
    /// process also serves over `/mcp`. Remote-index copies go stale; the
    /// response says so.
    fn rotate(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        self.deny_co_resident(id, "rotating keys", "run `undercroft vault rotate <name>`")?;
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
        // Opt-in narrowing only; absent means every fact, whatever it rests on.
        let grounding = query_param(req, "grounding").map(|v| pct_decode(&v));
        let store = self.store_for(id)?;
        let triples = store
            .kg_query_entity(&entity, as_of.as_deref(), &direction)
            .map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({
                "entity": entity,
                "triples": triples_json(triples, grounding.as_deref())
            })),
        ))
    }

    /// `GET /v1/vaults/{id}/kg/timeline?entity=` — every fact (open and
    /// closed) in temporal order, optionally scoped to one entity.
    fn kg_timeline(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let entity = query_param(req, "entity").map(|v| pct_decode(&v));
        let grounding = query_param(req, "grounding").map(|v| pct_decode(&v));
        let store = self.store_for(id)?;
        let triples = store.kg_timeline(entity.as_deref()).map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({
                "triples": triples_json(triples, grounding.as_deref())
            })),
        ))
    }

    /// `GET /v1/vaults/{id}/kg/canonical/{key}` — the exact-authority door:
    /// an indexed equality on `canonical_key`, answering with the one
    /// active, approved, canonical fact for the key, or 404. Meant to be
    /// consulted before semantic recall for exact or high-risk asks —
    /// declared, reviewed truth outranking learned similarity.
    fn kg_canonical(&mut self, id: &str, key: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let key = pct_decode(key);
        let store = self.store_for(id)?;
        match store.lookup_canonical(&key).map_err(store_err)? {
            Some(t) => Ok((200, Body::Json(json!({ "fact": t })))),
            None => Err(RestError::new(
                404,
                "no approved canonical fact holds this key",
            )),
        }
    }

    /// `POST /v1/vaults/{id}/kg/authority` — place a fact on the authority
    /// tier or take it off: body `{triple_id, authority_class,
    /// review_state, canonical_key?}`. Closed vocabulary, audited through
    /// the chain, and the resulting state lands inside the fact's HMAC —
    /// a column flip without the vault key fails verification on read.
    ///
    /// The only mutation among the `/v1` KG routes, and for a long time the
    /// only mutating route anywhere in this file with no read-only guard;
    /// `route` now decides that for every route at once.
    fn kg_authority(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let v: Value =
            serde_json::from_str(body).map_err(|_| RestError::new(400, "body must be JSON"))?;
        let triple_id = v
            .get("triple_id")
            .and_then(Value::as_str)
            .ok_or_else(|| RestError::new(400, "triple_id required"))?;
        let class = v
            .get("authority_class")
            .and_then(Value::as_str)
            .ok_or_else(|| RestError::new(400, "authority_class required"))?;
        let review = v
            .get("review_state")
            .and_then(Value::as_str)
            .ok_or_else(|| RestError::new(400, "review_state required"))?;
        let key = v.get("canonical_key").and_then(Value::as_str);
        let store = self.store_for(id)?;
        store
            .kg_set_authority(triple_id, class, review, key)
            .map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({ "ok": true, "triple_id": triple_id })),
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

    /// `GET /v1/vaults/{id}/supersessions` — verify every drawer's declared
    /// supersession link against the drawer it claims to replace, the
    /// drawer-level analogue of `/kg/receipts` with the same verdicts plus
    /// `unreceipted` (link written while its target was absent). The
    /// summary counts let a caller alert on `tampered` without walking the
    /// list.
    fn drawer_supersessions(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let links = store.verify_supersessions().map_err(store_err)?;
        let mut summary = serde_json::Map::new();
        for verdict in [
            "verified",
            "source_changed",
            "dangling",
            "tampered",
            "unreceipted",
        ] {
            let n = links
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
                "supersessions": serde_json::to_value(&links).unwrap_or_else(|_| json!([])),
                "summary": summary,
            })),
        ))
    }

    /// `POST /v1/vaults/{id}/forget` — destroy the named drawers through
    /// the audit chain and return the attestation (`{ids: [...]}` in;
    /// unsigned out — the signing identity is an operator file, so
    /// signing happens via the CLI). C3.2: GDPR/RTBF with a receipt.
    fn forget(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let body = parse_json(body)?;
        let ids: Vec<String> = body
            .get("ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if ids.is_empty() {
            return Err(RestError::new(400, "ids must be a non-empty array"));
        }
        let store = self.store_for(id)?;
        let att = store.forget_with_proof(&ids).map_err(store_err)?;
        Ok((
            200,
            Body::Json(serde_json::to_value(&att).unwrap_or_else(|_| json!({}))),
        ))
    }

    /// `GET /v1/vaults/{id}/admission` — every drawer awaiting an
    /// admission ruling: signal codes + offsets (structure, never
    /// content), intended destination, age. Enable the screen itself with
    /// `UNDERCROFT_ADMISSION=quarantine` on the engine.
    fn admission_list(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let pending = store.admission_pending().map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({
                "pending": serde_json::to_value(&pending).unwrap_or_else(|_| json!([])),
                "screening": store.admission_on(),
            })),
        ))
    }

    /// `POST /v1/vaults/{id}/admission` — rule on a quarantined drawer:
    /// `{drawer_id, verdict: "allow"|"deny"}`. An operator surface,
    /// deliberately absent from MCP (an agent whose write was quarantined
    /// must not be able to rule on it). Both verdicts are chain-audited.
    fn admission_rule(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let body = parse_json(body)?;
        let drawer_id = body_str(&body, "drawer_id")?;
        let verdict = body_str(&body, "verdict")?;
        let store = self.store_for(id)?;
        match verdict.as_str() {
            "allow" => {
                let restored = store.admission_allow(&drawer_id).map_err(store_err)?;
                Ok((
                    200,
                    Body::Json(json!({ "drawer_id": drawer_id, "verdict": "allowed",
                                        "restored_id": restored })),
                ))
            }
            "deny" => {
                // The deny destroys through the attested-forgetting path
                // (C3.2), so the response carries the receipt — unsigned,
                // like /forget: the signing identity is an operator file.
                let att = store.admission_deny(&drawer_id).map_err(store_err)?;
                Ok((
                    200,
                    Body::Json(json!({ "drawer_id": drawer_id, "verdict": "denied",
                                        "attestation": serde_json::to_value(&att)
                                            .unwrap_or_else(|_| json!({})) })),
                ))
            }
            _ => Err(RestError::new(400, "verdict must be 'allow' or 'deny'")),
        }
    }

    /// `GET /v1/vaults/{id}/retention` — every declared retention policy,
    /// tag-verified.
    fn retention_list(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let rows = store.retention_policies().map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({
                "policies": serde_json::to_value(&rows).unwrap_or_else(|_| json!([])),
            })),
        ))
    }

    /// `POST /v1/vaults/{id}/retention` — declare or clear a policy:
    /// `{wing, room?, days}` declares; `{wing, room?, clear: true}`
    /// clears. An operator surface, deliberately absent from MCP — an
    /// agent must not shorten the life of the memory it writes or reads.
    fn retention_set(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let body = parse_json(body)?;
        let wing = body_str(&body, "wing")?;
        let room = body.get("room").and_then(Value::as_str).map(str::to_string);
        let store = self.store_for(id)?;
        if body.get("clear").and_then(Value::as_bool) == Some(true) {
            store
                .clear_retention(&wing, room.as_deref())
                .map_err(store_err)?;
            return Ok((
                200,
                Body::Json(json!({ "wing": wing, "room": room, "cleared": true })),
            ));
        }
        let days = body
            .get("days")
            .and_then(Value::as_u64)
            .and_then(|d| u32::try_from(d).ok())
            .ok_or_else(|| RestError::new(400, "days must be a positive integer"))?;
        store
            .set_retention(&wing, room.as_deref(), days)
            .map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({ "wing": wing, "room": room, "days": days, "declared": true })),
        ))
    }

    /// `POST /v1/vaults/{id}/retention/sweep` — destroy what has aged
    /// out, through the attested forgetting path (`{dry_run: true}` to
    /// preview). Nothing runs automatically: a sweep happens when the
    /// operator asks for one. The attestation in the response is the
    /// receipt (unsigned — the signing identity is an operator file).
    fn retention_sweep(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let dry_run = (!body.trim().is_empty())
            .then(|| parse_json(body))
            .transpose()?
            .and_then(|b| b.get("dry_run").and_then(Value::as_bool))
            == Some(true);
        let store = self.store_for(id)?;
        let sweep = store.retention_sweep(dry_run).map_err(store_err)?;
        Ok((
            200,
            Body::Json(serde_json::to_value(&sweep).unwrap_or_else(|_| json!({}))),
        ))
    }

    /// `POST /v1/vaults/{id}/trust` — assign a wing's trust class
    /// (`{wing, trust}`; closed vocabulary, 400 if unknown). The receiving
    /// principal's declaration: an OPERATOR surface, deliberately absent
    /// from MCP — an agent that writes content must not be able to raise
    /// its own standing (docs/LABELS.md). Audited through the chain.
    fn set_trust(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let body = parse_json(body)?;
        let wing = body_str(&body, "wing")?;
        let trust = body_str(&body, "trust")?;
        undercroft_core::validate_trust(&trust).map_err(|e| RestError::new(400, e.to_string()))?;
        let store = self.store_for(id)?;
        store.set_wing_trust(&wing, &trust).map_err(store_err)?;
        Ok((
            200,
            Body::Json(json!({ "wing": wing, "trust": trust, "assigned": true })),
        ))
    }

    /// `GET /v1/vaults/{id}/trust` — every assigned wing trust class,
    /// tag-verified. Wings absent here read as `standard`.
    fn list_trust(&mut self, id: &str, req: &Request, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        let store = self.store_for(id)?;
        let rows = store.wing_trusts().map_err(store_err)?;
        let assignments: Vec<Value> = rows
            .into_iter()
            .map(|(wing, trust)| json!({ "wing": wing, "trust": trust }))
            .collect();
        Ok((
            200,
            Body::Json(json!({ "assignments": assignments, "default": "standard" })),
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

        // The distillation itself lives in `crate::refine`, driven
        // identically by `undercroft refine` — same LLM configuration must
        // not mean two different vaults (it did: no fact date resolved
        // from the note's words, no grounding verdict and no searchable
        // mirror on the CLI side).
        let rep = crate::refine::refine(
            store,
            &llm,
            &crate::refine::RefineOptions {
                wing,
                room,
                fact_room,
                limit,
                dry_run: false,
            },
        )
        .map_err(store_err)?;

        Ok((
            200,
            Body::Json(json!({
                "sources": rep.sources,
                "facts": rep.facts,
                "duplicates": rep.duplicates,
                "skipped": rep.skipped,
                "failed": rep.failed,
                // How many facts were dated by words in the note rather than
                // by the note's own date. Reported because it is the only
                // visible measure of whether the extractor is pointing at
                // real spans — a model that answers with dates instead of
                // quotations drives this to zero without erroring.
                "dated_from_text": rep.dated_from_text,
                // Facts the note's own words support, against facts that rest
                // on the extractor's background knowledge. Both are wanted:
                // the second is what lets the graph answer across notes.
                "stated": rep.stated,
                "background": rep.facts.saturating_sub(rep.stated),
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
        let mut counts = undercroft_vault::bundle::ManifestCounts::default();
        for (drawer, vector) in records {
            let mut line = json!({ "drawer": drawer, "vector": vector });
            if let Some((model, packed)) = store.token_artifact(&drawer.id).map_err(store_err)? {
                line["tok"] = json!({ "model": model, "b64": b64encode(&packed) });
            }
            out.push_str(&line.to_string());
            out.push('\n');
            counts.drawers += 1;
        }
        // The meta-rows gap, closed on this surface too: entities, facts
        // (receipts and authority tier travel; receipt tags re-key at the
        // destination) and tunnels ride the same NDJSON stream.
        for (name, etype) in store.kg_export_entities().map_err(store_err)? {
            out.push_str(&json!({ "entity": { "name": name, "etype": etype } }).to_string());
            out.push('\n');
            counts.kg_entities += 1;
        }
        for exp in store.kg_export().map_err(store_err)? {
            out.push_str(&json!({ "triple": exp }).to_string());
            out.push('\n');
            counts.kg_triples += 1;
        }
        for t in store.list_tunnels(None).map_err(store_err)? {
            out.push_str(&json!({ "tunnel": t }).to_string());
            out.push('\n');
            counts.tunnels += 1;
        }
        // Manifest first line — unsigned on this surface (the signing key
        // is an operator file, not a server secret; the CLI signs).
        let (vault_id, level, embedder, chain_head) = store.manifest_facts().map_err(store_err)?;
        let manifest = undercroft_vault::bundle::BundleManifest {
            version: 1,
            vault: vault_id,
            level,
            created_at: rfc3339_now(),
            counts,
            embedder: Some(embedder),
            chain_head: Some(chain_head),
            trust: None,
            expires: None,
            sender: None,
            payload_sha256: undercroft_vault::bundle::payload_digest(out.as_bytes()),
            sig: None,
        };
        let framed = undercroft_vault::bundle::frame_payload(&manifest, out.as_bytes());
        let framed = String::from_utf8(framed)
            .map_err(|e| RestError::new(500, format!("payload not UTF-8: {e}")))?;
        // Every full-palace egress leaves a chain record binding the
        // export's manifest digest. A read-only replica must not write,
        // so it serves the export and SAYS the egress went unaudited —
        // the replica precedent: warn and serve.
        if self.read_only {
            undercroft_obs::diag_warn!("export served read-only; egress not chain-audited");
        } else {
            let counts = manifest.counts.clone();
            let digest = manifest.payload_sha256.clone();
            let store = self.store_for(id)?;
            store
                .audit_export("http", &counts, &digest, None)
                .map_err(store_err)?;
        }
        Ok((200, Body::Ndjson(framed)))
    }

    fn import(&mut self, id: &str, req: &Request, body: &str, now: i64) -> RestResult {
        self.assert_or_401(id, req, now)?;
        // A manifest first line, when present: the digest is always
        // enforced (a payload that does not match its own declaration is
        // refused), expiry is enforced, and signature status is reported
        // via the response. Legacy payloads (no manifest) import as ever.
        let (manifest, record_bytes) = undercroft_vault::bundle::split_payload(body.as_bytes())
            .map_err(|e| RestError::new(400, format!("bundle manifest: {e}")))?;
        if let Some(m) = &manifest {
            if m.expired_at(&rfc3339_now()) {
                return Err(RestError::new(
                    400,
                    format!(
                        "bundle expired at {}",
                        m.expires.as_deref().unwrap_or("(unparseable expiry)")
                    ),
                ));
            }
        }
        let body = std::str::from_utf8(record_bytes)
            .map_err(|e| RestError::new(400, format!("records not UTF-8: {e}")))?;
        // Parse every line before writing anything, so a malformed body
        // fails cleanly without a partial import.
        type ImportLine = (Drawer, Option<Vec<f32>>, Option<(String, Vec<u8>)>);
        let mut records: Vec<ImportLine> = Vec::new();
        let mut kg_records: Vec<undercroft_store::TripleExport> = Vec::new();
        let mut entity_records: Vec<(String, String)> = Vec::new();
        let mut tunnel_records: Vec<(String, String, String)> = Vec::new();
        for (n, line) in body.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let obj: Value = serde_json::from_str(line)
                .map_err(|e| RestError::new(400, format!("line {}: {e}", n + 1)))?;
            if let Some(t) = obj.get("triple") {
                kg_records.push(
                    serde_json::from_value(t.clone())
                        .map_err(|e| RestError::new(400, format!("line {}: {e}", n + 1)))?,
                );
                continue;
            }
            if let Some(e) = obj.get("entity") {
                let name = e
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RestError::new(400, format!("line {}: entity.name", n + 1)))?;
                let etype = e.get("etype").and_then(Value::as_str).unwrap_or("unknown");
                entity_records.push((name.to_string(), etype.to_string()));
                continue;
            }
            if let Some(t) = obj.get("tunnel") {
                let g = |k: &str| t.get(k).and_then(Value::as_str).map(str::to_string);
                if let (Some(f), Some(to_w), Some(l)) = (g("from_wing"), g("to_wing"), g("label")) {
                    tunnel_records.push((f, to_w, l));
                }
                continue;
            }
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
        let mut quarantined = 0u64;
        for (drawer, vector, tok) in &records {
            // `import_record` re-stamps `added_by` with the importing
            // surface: the payload's own value is the key the admission
            // screen's trusted-source auto-admit rides, and a caller must
            // not be able to set it.
            let out = store
                .import_record(drawer, vector.clone(), undercroft_store::IMPORT_SURFACE)
                .map_err(store_err)?;
            if out.quarantined {
                quarantined += 1;
            }
            if let Some((model, packed)) = tok {
                // Re-sealed under this vault's key; restore skips the
                // per-drawer encode forward.
                store
                    .import_token_artifact(&drawer.id, model, packed)
                    .map_err(store_err)?;
            }
            imported += 1;
        }
        // KG and tunnel rows after drawers, so receipts can bind against
        // drawers arriving in the same payload.
        for (name, etype) in &entity_records {
            store.kg_import_entity(name, etype).map_err(store_err)?;
        }
        for exp in &kg_records {
            store.kg_import(exp).map_err(store_err)?;
        }
        for (f, t, l) in &tunnel_records {
            store.create_tunnel(f, t, l).map_err(store_err)?;
        }
        // Additive keys: a caller that ignores them sees the response this
        // route always returned.
        Ok((
            200,
            Body::Json(json!({
                "imported": imported,
                // How many of those the admission screen diverted: counted
                // in `imported` (they were written) but NOT retrievable
                // where the payload aimed them. Always 0 while screening is
                // off, so the default response shape is unchanged.
                "quarantined": quarantined,
                "kg_triples": kg_records.len(),
                "kg_entities": entity_records.len(),
                "tunnels": tunnel_records.len(),
                "manifest": manifest.map(|m| json!({
                    "vault": m.vault,
                    "created_at": m.created_at,
                    "trust": m.trust,
                    "signed": m.sig.is_some(),
                })),
            })),
        ))
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
            // A read-only server must not rewrite the vault it is serving —
            // an embedder migration is a bulk write, and the operator asked
            // this process not to make any.
            let opened = if self.read_only {
                PalaceStore::open_read_only(vault, embedder)
            } else {
                PalaceStore::open_with_embedder(vault, embedder)
            };
            let mut store = opened.map_err(|e| RestError::new(500, e.to_string()))?;
            if let Some(make_reranker) = &self.reranker {
                store.set_reranker(Some(make_reranker()));
            }
            // Same admission contract as the CLI: the optional tier-2
            // advisor attaches per vault when the deployment declared it.
            crate::attach_admission_advisor(&mut store)
                .map_err(|e| RestError::new(500, e.to_string()))?;
            // The SAME retrieval contract as the CLI, and it must stay the
            // same: this arm once matched only "pq", so a server told
            // UNDERCROFT_RETRIEVAL=fde silently served the default instead —
            // a config the operator declared and never got, with no error.
            // A typo behaved identically. `hnsw` stays CLI-only (the index
            // is per-process RAM and the feature gate is a build choice),
            // but it is REFUSED here rather than ignored.
            match std::env::var("UNDERCROFT_RETRIEVAL").as_deref() {
                Ok("pq") => store.set_pq(true),
                Ok("fde") => store.set_fde(true),
                Ok("hnsw") => {
                    return Err(RestError::new(
                        500,
                        "UNDERCROFT_RETRIEVAL=hnsw is not available on the multi-tenant                          server (in-process index); use pq or fde, or serve a single vault",
                    ))
                }
                Ok("") | Err(_) => {}
                Ok(other) => {
                    return Err(RestError::new(
                        500,
                        format!("unknown UNDERCROFT_RETRIEVAL {other:?} (expected: pq, fde)"),
                    ))
                }
            }
            self.stores.insert(vault_id.to_string(), store);
            undercroft_obs::vault_opened();
        }
        Ok(self.stores.get_mut(vault_id).expect("just inserted"))
    }

    /// Refuse an operation that would retire the keys of, or delete the
    /// files under, a vault a SECOND live handle in this same process is
    /// holding — the `/mcp` store `serve-http` opened at start-up.
    ///
    /// `rotate_keys` documents a sole-writer contract, and every doc states
    /// it at PROCESS granularity ("do not rotate a vault another process is
    /// serving"). Inside `serve-http` that contract was unsatisfiable: the
    /// second reader is in the operator's own process, reachable from the
    /// console's own ROTATE KEYS button, and no external discipline can
    /// prevent it. Rotating through the `/v1` handle left the `/mcp` handle
    /// on the retired keys — every read after it surfaced as
    /// `StoreError::Integrity` (the agent is told the vault is TAMPERED when
    /// the operator merely rotated), and any write it made was sealed and
    /// chain-appended under the retired MAC key and then re-anchored the
    /// manifest from its own stale cache, reverting `salt_hex` while the
    /// rows on disk stayed under the new keys. `delete_vault` is the same
    /// shape one level up: it drops the Tenancy's handle and removes the
    /// directory while the MCP handle keeps an open connection to files that
    /// no longer exist.
    ///
    /// So the refusal is the fix: it makes the documented contract
    /// satisfiable by naming the one route that does it — stop the server,
    /// hold the only handle, then rotate. Other tenant vaults are untouched:
    /// only the `--vault` one is co-resident.
    fn deny_co_resident(&self, id: &str, what: &str, remedy: &str) -> Result<(), RestError> {
        if self.mcp_vault.as_deref() == Some(id) {
            return Err(RestError::new(
                409,
                format!(
                    "vault '{id}' is also open on this process's /mcp surface; {what} needs the \
                     only handle — stop the server, then {remedy}"
                ),
            ));
        }
        Ok(())
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

fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn b64decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
}

/// Does this request change the vault? Consulted once, in front of
/// dispatch, to decide what a `--read-only` server refuses.
///
/// **Fails closed by construction**: a request mutates unless it is a `GET`
/// or one of the two `POST`s named below. A route added later is refused on
/// a read-only server until someone deliberately adds it to that list — the
/// opposite of the per-handler guard this replaced, where forgetting a line
/// opened a write door and nothing said so.
///
/// The two exceptions are POST for cost, not for effect: `search` reads (its
/// optional read-audit record is already suppressed by `open_read_only`),
/// and `verify` walks HMACs and replays the chain. `GET .../export` is a
/// read here too — the egress chain record it would otherwise write is
/// skipped on a read-only server, which warns and serves.
fn mutates(method: &str, segs: &[&str]) -> bool {
    if method == "GET" {
        return false;
    }
    !matches!(
        (method, segs),
        ("POST", &["v1", "vaults", _, "search"]) | ("POST", &["v1", "vaults", _, "verify"])
    )
}

fn store_err(e: StoreError) -> RestError {
    let code = match &e {
        StoreError::ExternalVault
        | StoreError::NotExternalVault
        | StoreError::EmbeddingDim { .. }
        // A rejected input — an unknown vocabulary value, a save aimed at
        // the reserved wing, a ruling on an id that is not quarantined —
        // is the caller's error, not the server's.
        | StoreError::Invalid(_) => 400,
        // Both are verdicts about stored evidence rather than about the
        // request: an HMAC that does not verify, or an attestation that
        // does not describe what this vault did. 409, never 5xx — the
        // server is working exactly as designed when it says so.
        StoreError::Integrity(_) | StoreError::Attestation(_) => 409,
        // "That record is not here" has ONE status class across every
        // route: `forget` and `admission` used to answer 400 for it while
        // GET/PUT on the same id answered 404, so a client could not key
        // retry or alerting logic on the class at all.
        StoreError::NotFound(_) => 404,
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

// The read-time convention tests moved with `locale_from` into
// `crate::search`, where both surfaces that parse those declarations live.
