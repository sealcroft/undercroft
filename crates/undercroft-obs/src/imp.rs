//! Real telemetry implementation, compiled only under the `telemetry`
//! feature. Everything here is metadata/counts only.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, Once, OnceLock};
use std::time::Duration;

use crate::Sample;

use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::TracerProvider;
use opentelemetry_sdk::Resource;
use prometheus::Encoder;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use crate::DiagLevel;

const METER_NAME: &str = "undercroft";

use crate::GAUGE_NAMES;

fn gauges() -> &'static Mutex<HashMap<(String, String), f64>> {
    static G: OnceLock<Mutex<HashMap<(String, String), f64>>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(HashMap::new()))
}

static METER_PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();
static TRACER_PROVIDER: OnceLock<TracerProvider> = OnceLock::new();
static REGISTRY: OnceLock<prometheus::Registry> = OnceLock::new();

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

fn attrs(labels: &[(&str, &str)]) -> Vec<KeyValue> {
    labels
        .iter()
        .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
        .collect()
}

pub(crate) fn counter_add(name: &'static str, value: u64, labels: &[(&str, &str)]) {
    // Instruments are (re)built per call rather than cached: the SDK
    // deduplicates identical instruments by name+scope, and this keeps
    // recording order-independent from telemetry init (a cache populated
    // before `init()` would pin no-op handles).
    global::meter(METER_NAME)
        .u64_counter(name)
        .build()
        .add(value, &attrs(labels));
}

pub(crate) fn histogram_record(name: &'static str, value: f64, labels: &[(&str, &str)]) {
    global::meter(METER_NAME)
        .f64_histogram(name)
        .build()
        .record(value, &attrs(labels));
}

pub(crate) fn search_completed(duration: Duration, hits: usize, fusion: &str, prefiltered: bool) {
    counter_add("undercroft_search_total", 1, &[("fusion", fusion)]);
    if prefiltered {
        counter_add("undercroft_search_prefiltered_total", 1, &[]);
    }
    histogram_record(
        "undercroft_search_duration_seconds",
        duration.as_secs_f64(),
        &[],
    );
    histogram_record("undercroft_search_hits", hits as f64, &[]);
}

pub(crate) fn http_request(route: &str, status: u16, duration: Duration) {
    let status = status.to_string();
    counter_add(
        "undercroft_http_requests_total",
        1,
        &[("route", route), ("status", &status)],
    );
    histogram_record(
        "undercroft_http_request_duration_seconds",
        duration.as_secs_f64(),
        &[("route", route)],
    );
}

pub(crate) fn set_gauge(name: &str, vault: &str, value: f64) {
    gauges()
        .lock()
        .unwrap()
        .insert((name.to_string(), vault.to_string()), value);
}

// ---------------------------------------------------------------------------
// Spans (bridged to OTLP by the tracing_opentelemetry layer set up in init)
// ---------------------------------------------------------------------------

/// Wraps an entered span; dropping it closes the span (and exports it when an
/// OTLP endpoint is configured). Named span constructors keep the span name a
/// static string (as `tracing`'s macros require) while the vault/route stay
/// fields — always metadata, never content.
pub(crate) struct SpanGuard(#[allow(dead_code)] tracing::span::EnteredSpan);

pub(crate) fn enter_op(op: &'static str, vault: &str) -> SpanGuard {
    let span = match op {
        "search" => tracing::info_span!(target: "undercroft", "search", vault = vault),
        "save" => tracing::info_span!(target: "undercroft", "save", vault = vault),
        "kg" => tracing::info_span!(target: "undercroft", "kg", vault = vault),
        "commit" => tracing::info_span!(target: "undercroft", "commit", vault = vault),
        other => tracing::info_span!(target: "undercroft", "op", op = other, vault = vault),
    };
    SpanGuard(span.entered())
}

pub(crate) fn enter_request(route: &str, vault: &str) -> SpanGuard {
    SpanGuard(
        tracing::info_span!(target: "undercroft", "request", route = route, vault = vault)
            .entered(),
    )
}

pub(crate) fn diag(level: DiagLevel, args: std::fmt::Arguments<'_>) {
    let msg = args.to_string();
    match level {
        DiagLevel::Info => tracing::info!(target: "undercroft", "{msg}"),
        DiagLevel::Warn => tracing::warn!(target: "undercroft", "{msg}"),
        DiagLevel::Error => tracing::error!(target: "undercroft", "{msg}"),
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// An env read that treats an empty declaration as unset.
///
/// **Correct only for the variables it is still used for, and that is the
/// whole of its contract**: `UNDERCROFT_SERVICE_NAME` (a label with a
/// documented default), `UNDERCROFT_OTLP_HEADERS` (`Tunes` — no headers is a
/// working configuration) and `UNDERCROFT_LOG_FORMAT` (a vocabulary, where
/// empty is a third spelling of the default). For each, falling back grants
/// the conservative default and costs the operator nothing they declared.
///
/// It is **not** correct for an outward path or a secret — those are opaque
/// payload, where empty can only be a failed interpolation and a fallback
/// removes what was asked for. `UNDERCROFT_OTLP_ENDPOINT` was read through
/// here and is now resolved by `undercroft_net::declared_endpoint`; do not
/// bring it, or anything of its class, back to this function.
fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// The OTLP exporter's HTTP client — the policed `ureq` agent
/// `undercroft-net` built, wearing `opentelemetry-http`'s trait.
///
/// It exists so the exporter cannot reach the network by any other route.
/// `undercroft-net`'s own doc says it is "the only implementation" of the
/// transport rules; a `--features telemetry` build used to falsify that
/// sentence, and no gate could see it because the gate scans for `ureq`'s
/// builder token and this client was somebody else's library.
#[derive(Debug)]
struct PolicedOtlpClient {
    agent: ureq::Agent,
}

#[async_trait::async_trait]
impl opentelemetry_http::HttpClient for PolicedOtlpClient {
    async fn send(
        &self,
        request: opentelemetry_http::Request<Vec<u8>>,
    ) -> Result<
        opentelemetry_http::Response<opentelemetry_http::Bytes>,
        opentelemetry_http::HttpError,
    > {
        // Blocking inside an `async fn` is correct HERE and would not be
        // elsewhere: this stack is deliberately runtime-free — a
        // `SimpleSpanProcessor` exporting per span — which is exactly what
        // reqwest's BLOCKING client was doing before. There is no executor
        // to starve.
        let (parts, body) = request.into_parts();
        let mut req = self.agent.post(&parts.uri.to_string());
        for (name, value) in parts.headers.iter() {
            if let Ok(v) = value.to_str() {
                req = req.set(name.as_str(), v);
            }
        }
        let resp = match req.send_bytes(&body) {
            Ok(r) => r,
            // A 4xx/5xx IS a response, and the exporter interprets the
            // status itself. Turning it into a transport error here would
            // hide a collector's own "429 slow down" behind "send failed".
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(Box::new(e)),
        };
        let status = resp.status();
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut buf)?;
        Ok(opentelemetry_http::Response::builder()
            .status(status)
            .body(opentelemetry_http::Bytes::from(buf))?)
    }
}

/// Bring up telemetry, or say why it cannot come up.
///
/// Fallible since the OTLP endpoint is an OUTWARD PATH: under this project's
/// configuration doctrine a declaration that turns one on must REFUSE rather
/// than fall back, because a silent fallback removes exactly what the
/// operator asked for.
pub(crate) fn init() -> Result<(), String> {
    init_as("undercroft")
}

/// As [`init`], with the service name's DEFAULT supplied by the caller.
///
/// `UNDERCROFT_SERVICE_NAME` still wins when declared. The parameter exists
/// because two binaries shipped from this workspace both defaulted to
/// `"undercroft"`, so a fleet running an engine and a control plane under one
/// env file produced traces that could not be told apart (ROADMAP O20).
pub(crate) fn init_as(default_service: &str) -> Result<(), String> {
    static ONCE: Once = Once::new();
    // The verdict is memoized beside the `Once`, so a second call gets the
    // SAME answer rather than a silent `Ok` — `call_once` runs the body once
    // and would otherwise discard the only report of a refused transport.
    static RESULT: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    ONCE.call_once(|| {
        let _ = RESULT.set(real_init(default_service));
    });
    RESULT.get().cloned().unwrap_or(Ok(()))
}

fn real_init(default_service: &str) -> Result<(), String> {
    let service_name =
        env("UNDERCROFT_SERVICE_NAME").unwrap_or_else(|| default_service.to_string());
    let resource = Resource::new(vec![KeyValue::new("service.name", service_name)]);

    // --- metrics: Prometheus registry is always wired; OTLP is opt-in ---
    let registry = prometheus::Registry::new();
    let prom = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        // Our counter instruments are already named `..._total`; without this
        // the exporter would append a second `_total` (`..._total_total`),
        // which is non-idiomatic and breaks dashboard/alert queries.
        .without_counter_suffixes()
        .build()
        .expect("build prometheus exporter");
    let mp = SdkMeterProvider::builder()
        .with_reader(prom)
        .with_resource(resource.clone());

    // **Not `env()`.** That helper maps an empty declaration to `None`, which
    // for a label like `UNDERCROFT_SERVICE_NAME` is a harmless fallback to a
    // default and here silently disabled the whole export — the operator
    // declared a collector, got no traces, and got no signal either, four
    // lines above a comment saying that is worse than refusing to start.
    // `declared_endpoint` is the one resolver `undercroft config check` runs,
    // so the pre-flight's verdict and this one cannot differ.
    let otlp_endpoint = undercroft_net::declared_endpoint(
        "the OTLP collector",
        std::env::var("UNDERCROFT_OTLP_ENDPOINT").ok().as_deref(),
    )
    .map_err(|e| e.to_string())?;
    let mut tracer_provider: Option<TracerProvider> = None;

    // OTLP carries traces, exported synchronously per span (no async
    // runtime). Metrics are surfaced via the Prometheus pull model wired
    // above — the OTLP metric push path needs a periodic-reader runtime
    // this fully-synchronous stack deliberately avoids.
    if let Some(endpoint) = otlp_endpoint {
        // UNDERCROFT_OTLP_ENDPOINT is a base URL (e.g. http://collector:4318);
        // `with_endpoint` wants the full per-signal path, so append the
        // standard OTLP/HTTP traces path unless the caller already did.
        let traces_endpoint = if endpoint.ends_with("/v1/traces") {
            endpoint
        } else {
            format!("{}/v1/traces", endpoint.trim_end_matches('/'))
        };
        // UNDERCROFT_OTLP_HEADERS: comma-separated `key=value` pairs sent
        // with every export request (e.g. `authorization=Bearer tok`) —
        // how authenticated collectors are reached. Values may contain
        // `=`; pairs without one are ignored.
        let headers: std::collections::HashMap<String, String> = env("UNDERCROFT_OTLP_HEADERS")
            .map(|raw| {
                raw.split(',')
                    .filter_map(|pair| {
                        let (k, v) = pair.split_once('=')?;
                        let k = k.trim();
                        (!k.is_empty()).then(|| (k.to_string(), v.trim().to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        // **The hop obeys the one transport policy**, like every other
        // outbound client in this workspace: TLS or loopback, nothing else,
        // no override, plus an optional pinned root. This used to be an
        // unpoliced `reqwest` client that `undercroft-net` knew nothing
        // about — and worse, the feature set linked reqwest with NO TLS
        // backend, so an `https://` collector could not work at all and
        // failed silently inside the span processor. The headers this
        // exporter sends are documented to carry a bearer token, and the
        // spans carry vault ids and route labels.
        let agent = undercroft_net::agent_from_env(
            "the OTLP collector",
            &traces_endpoint,
            "UNDERCROFT_OTLP_CA",
            std::time::Duration::from_secs(30),
        )
        .map_err(|e| e.to_string())?;
        // A builder failure used to be swallowed by `if let Ok(..)`, so an
        // operator got no traces and no message. Telemetry that silently
        // does not export is worse than telemetry that refuses to start.
        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(traces_endpoint)
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_headers(headers)
            .with_http_client(PolicedOtlpClient { agent })
            .build()
            .map_err(|e| format!("OTLP span exporter: {e}"))?;
        tracer_provider = Some(
            TracerProvider::builder()
                .with_simple_exporter(span_exporter)
                .with_resource(resource)
                .build(),
        );
    }

    let meter_provider = mp.build();
    global::set_meter_provider(meter_provider.clone());
    register_gauges();
    let _ = METER_PROVIDER.set(meter_provider);
    let _ = REGISTRY.set(registry);

    // --- tracing subscriber (+ OTLP span bridge if enabled) ---
    let filter = tracing_subscriber::EnvFilter::try_from_env("UNDERCROFT_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,undercroft=info"));
    let json = env("UNDERCROFT_LOG_FORMAT").as_deref() == Some("json");
    let fmt_layer = if json {
        tracing_subscriber::fmt::layer().json().boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .boxed()
    };

    let otel_layer = tracer_provider.as_ref().map(|tp| {
        let tracer = opentelemetry::trace::TracerProvider::tracer(tp, METER_NAME);
        tracing_opentelemetry::layer().with_tracer(tracer)
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    if let Some(tp) = tracer_provider {
        global::set_tracer_provider(tp.clone());
        let _ = TRACER_PROVIDER.set(tp);
    }
    Ok(())
}

fn register_gauges() {
    let meter = global::meter(METER_NAME);
    for &name in GAUGE_NAMES {
        let full = format!("undercroft_{name}");
        let base = name;
        let _gauge = meter
            .f64_observable_gauge(full)
            .with_callback(move |observer| {
                let g = gauges().lock().unwrap();
                for ((n, vault), v) in g.iter() {
                    if n == base {
                        observer.observe(*v, &[KeyValue::new("vault", vault.clone())]);
                    }
                }
            })
            .build();
    }
}

pub(crate) fn render_prometheus() -> Option<String> {
    render_prometheus_filtered(false)
}

/// The exposition, optionally with every **vault-labelled** series removed
/// (ROADMAP O25).
///
/// `/metrics` is served after the palace bearer and BEFORE per-vault
/// assertion — the route addresses no single vault, so the per-vault gate does
/// not apply to it. On a deployment that declared
/// `UNDERCROFT_ASSERTION_SECRET`, whose whole purpose is that *"a bearer alone
/// reaches no vault on either path"*, that let a caller holding the bearer and
/// an assertion for vault A read vault B's record counts, chain height, KG
/// size and database bytes.
///
/// **Suppression rather than filtering-to-the-caller, and the reason is that
/// an assertion binds exactly ONE vault id** (`"<ts>|<vault_id>"`). Filtering
/// the exposition to what the caller may assert therefore yields a single
/// vault, which is useless to the scraper `/metrics` exists for: Prometheus
/// would need one time-boxed assertion per vault per scrape.
///
/// **Aggregating instead of suppressing was considered and is WRONG**: a
/// caller who knows vault A's counts — which they legitimately do, from
/// `/v1/…/stats` — recovers B exactly by subtracting from a two-vault sum.
///
/// Nothing that alerts is lost. Every series `deploy/observability/alerts.yml`
/// evaluates is a vault-BLIND counter or histogram; the vault-labelled gauges
/// feed dashboard panels. Those panels go empty under assertions, and the
/// per-vault detail they showed lives on `/v1/…/stats`, which IS
/// assertion-gated — the correct home for it.
///
/// The suppressed set is derived from [`crate::GAUGE_NAMES`] rather than
/// listed again here, so a gauge added later is suppressed without anyone
/// remembering to.
pub(crate) fn render_prometheus_filtered(hide_vault_series: bool) -> Option<String> {
    let registry = REGISTRY.get()?;
    let mut buf = Vec::new();
    let encoder = prometheus::TextEncoder::new();
    encoder.encode(&registry.gather(), &mut buf).ok()?;
    let text = String::from_utf8(buf).ok()?;
    if !hide_vault_series {
        return Some(text);
    }
    // `format!("undercroft_{name}")` is exactly what `register_gauges` builds
    // the metric name with; if that ever moves, both must move together.
    let hidden: Vec<String> = crate::GAUGE_NAMES
        .iter()
        .map(|g| format!("undercroft_{g}"))
        .collect();
    // Drops the sample lines AND their `# HELP` / `# TYPE` headers: a bare
    // header with no samples is a series the scrape still learns exists.
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| {
            let name = line
                .strip_prefix("# HELP ")
                .or_else(|| line.strip_prefix("# TYPE "))
                .map(|r| r.split(' ').next().unwrap_or(""))
                .unwrap_or_else(|| line.split(['{', ' ']).next().unwrap_or(""));
            !hidden.iter().any(|h| h == name)
        })
        .collect();
    Some(kept.join("\n") + "\n")
}

pub(crate) fn shutdown() {
    if let Some(mp) = METER_PROVIDER.get() {
        let _ = mp.shutdown();
    }
    if let Some(tp) = TRACER_PROVIDER.get() {
        let _ = tp.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Live telemetry broker: bounded per-vault ring buffer + SSE pub/sub.
//
// The main server thread publishes samples/events; each SSE connection runs
// on its own thread that touches ONLY this broker (never a store), which is
// why the whole thing is thread-safe behind one Mutex. Frames are
// pre-serialized SSE strings pushed over an mpsc channel per subscriber.
// ---------------------------------------------------------------------------

const HISTORY_CAP: usize = 300;
const MAX_SUBS: usize = 32;
const HEARTBEAT: Duration = Duration::from_secs(15);

struct Sub {
    id: u64,
    vault: String,
    tx: Sender<String>,
}

struct Broker {
    history: HashMap<String, VecDeque<Sample>>,
    subs: Vec<Sub>,
    next_id: u64,
}

fn broker() -> &'static Mutex<Broker> {
    static B: OnceLock<Mutex<Broker>> = OnceLock::new();
    B.get_or_init(|| {
        Mutex::new(Broker {
            history: HashMap::new(),
            subs: Vec::new(),
            next_id: 1,
        })
    })
}

fn sse_frame(event: &str, data: &str) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

/// Send `msg` to every subscriber of `vault`, pruning any whose receiver has
/// gone away.
fn broadcast(b: &mut Broker, vault: &str, msg: &str) {
    b.subs
        .retain(|s| s.vault != vault || s.tx.send(msg.to_string()).is_ok());
}

fn emit(vault: &str, kind: &str, data: serde_json::Value) {
    let msg = sse_frame(kind, &data.to_string());
    broadcast(&mut broker().lock().unwrap(), vault, &msg);
}

pub(crate) fn publish_sample(sample: Sample) {
    let json = serde_json::to_string(&sample).unwrap_or_default();
    let vault = sample.vault.clone();
    let mut b = broker().lock().unwrap();
    {
        let ring = b.history.entry(vault.clone()).or_default();
        ring.push_back(sample);
        while ring.len() > HISTORY_CAP {
            ring.pop_front();
        }
    }
    broadcast(&mut b, &vault, &sse_frame("sample", &json));
}

pub(crate) fn event_drawer_saved(vault: &str, wing: &str, room: &str, deduped: bool, sealed: bool) {
    let data = if sealed {
        serde_json::json!({ "vault": vault, "deduped": deduped })
    } else {
        serde_json::json!({ "vault": vault, "wing": wing, "room": room, "deduped": deduped })
    };
    emit(vault, "drawer-saved", data);
}

pub(crate) fn event_drawer_quarantined(
    vault: &str,
    intended_wing: &str,
    room: &str,
    signals: &[&str],
    sealed: bool,
) {
    // Signal codes are a closed vocabulary, so they are metadata and ship
    // even for a sealed vault; the intended location is a name and is
    // suppressed with every other name.
    let data = if sealed {
        serde_json::json!({ "vault": vault, "signals": signals })
    } else {
        serde_json::json!({
            "vault": vault,
            "intended_wing": intended_wing,
            "room": room,
            "signals": signals,
        })
    };
    emit(vault, "drawer-quarantined", data);
}

pub(crate) fn event_drawer_deleted(vault: &str) {
    emit(
        vault,
        "drawer-deleted",
        serde_json::json!({ "vault": vault }),
    );
}

pub(crate) fn event_search(
    vault: &str,
    wing: Option<&str>,
    room: Option<&str>,
    hits: usize,
    sealed: bool,
) {
    let data = if sealed {
        serde_json::json!({ "vault": vault, "hits": hits })
    } else {
        serde_json::json!({ "vault": vault, "wing": wing, "room": room, "hits": hits })
    };
    emit(vault, "search", data);
}

pub(crate) fn event_kg_triple(vault: &str) {
    emit(vault, "kg-triple", serde_json::json!({ "vault": vault }));
}

pub(crate) fn event_chain_commit(vault: &str, records: u64) {
    emit(
        vault,
        "chain-commit",
        serde_json::json!({ "vault": vault, "records": records }),
    );
}

pub(crate) fn event_hmac_fail(vault: &str, surface: &str) {
    emit(
        vault,
        "hmac-fail",
        serde_json::json!({ "vault": vault, "surface": surface }),
    );
}

pub(crate) fn history(vault: &str, window: usize) -> Vec<Sample> {
    let b = broker().lock().unwrap();
    match b.history.get(vault) {
        Some(ring) => {
            let start = ring.len().saturating_sub(window);
            ring.iter().skip(start).cloned().collect()
        }
        None => Vec::new(),
    }
}

pub(crate) fn subscribed_vaults() -> Vec<String> {
    let b = broker().lock().unwrap();
    let mut v: Vec<String> = b.subs.iter().map(|s| s.vault.clone()).collect();
    v.sort();
    v.dedup();
    v
}

fn subscribe(vault: &str) -> Option<(u64, Receiver<String>)> {
    let mut b = broker().lock().unwrap();
    if b.subs.len() >= MAX_SUBS {
        return None;
    }
    let (tx, rx) = mpsc::channel();
    let id = b.next_id;
    b.next_id += 1;
    b.subs.push(Sub {
        id,
        vault: vault.to_string(),
        tx,
    });
    Some((id, rx))
}

fn unsubscribe(id: u64) {
    broker().lock().unwrap().subs.retain(|s| s.id != id);
}

pub(crate) fn run_sse(mut writer: Box<dyn Write + Send>, vault: String) -> bool {
    let Some((id, rx)) = subscribe(&vault) else {
        let _ = writer.write_all(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\n\
              Connection: close\r\n\r\nstream subscriber limit reached\n",
        );
        return false;
    };

    let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                 Cache-Control: no-cache\r\nConnection: close\r\nX-Accel-Buffering: no\r\n\r\n";
    let write = |w: &mut Box<dyn Write + Send>, bytes: &[u8]| -> bool {
        w.write_all(bytes).and_then(|_| w.flush()).is_ok()
    };

    if !write(&mut writer, head) {
        unsubscribe(id);
        return true;
    }
    // Replay recent history so a fresh client can draw the past.
    for s in history(&vault, HISTORY_CAP) {
        let json = serde_json::to_string(&s).unwrap_or_default();
        if !write(&mut writer, sse_frame("sample", &json).as_bytes()) {
            unsubscribe(id);
            return true;
        }
    }
    let _ = write(&mut writer, b": connected\n\n");

    loop {
        match rx.recv_timeout(HEARTBEAT) {
            Ok(msg) => {
                if !write(&mut writer, msg.as_bytes()) {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if !write(&mut writer, b": ping\n\n") {
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    unsubscribe(id);
    true
}
