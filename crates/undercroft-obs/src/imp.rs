//! Real telemetry implementation, compiled only under the `telemetry`
//! feature. Everything here is metadata/counts only.

use std::collections::HashMap;
use std::sync::{Mutex, Once, OnceLock};
use std::time::Duration;

use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::TracerProvider;
use opentelemetry_sdk::Resource;
use prometheus::Encoder;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use crate::DiagLevel;

const METER_NAME: &str = "undercroft";

/// Base names of the gauges we surface. Each is exported as
/// `undercroft_<name>{vault="…"}`.
const GAUGE_NAMES: &[&str] = &[
    "drawers",
    "kg_triples",
    "kg_entities",
    "audit_chain_height",
    "store_bytes",
];

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
        if let Ok(span_exporter) = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
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
