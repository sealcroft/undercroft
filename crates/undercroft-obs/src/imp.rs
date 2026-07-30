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

fn histogram_record(name: &'static str, value: f64, labels: &[(&str, &str)]) {
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
        tracing::info_span!(target: "undercroft", "request", route = route, vault = vault).entered(),
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

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

pub(crate) fn init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(real_init);
}

fn real_init() {
    let service_name = env("UNDERCROFT_SERVICE_NAME").unwrap_or_else(|| "undercroft".to_string());
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

    let otlp_endpoint = env("UNDERCROFT_OTLP_ENDPOINT");
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
        if let Ok(span_exporter) = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(traces_endpoint)
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_headers(headers)
            .build()
        {
            tracer_provider = Some(
                TracerProvider::builder()
                    .with_simple_exporter(span_exporter)
                    .with_resource(resource)
                    .build(),
            );
        }
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
    let registry = REGISTRY.get()?;
    let mut buf = Vec::new();
    let encoder = prometheus::TextEncoder::new();
    encoder.encode(&registry.gather(), &mut buf).ok()?;
    String::from_utf8(buf).ok()
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

pub(crate) fn event_chain_commit(vault: &str) {
    emit(vault, "chain-commit", serde_json::json!({ "vault": vault }));
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
