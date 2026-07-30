//! # undercroft-obs
//!
//! Observability shim for Undercroft. The entire public surface below is
//! stable regardless of build features so call sites in the other crates
//! never need `#[cfg(...)]`.
//!
//! * **Without** the `telemetry` feature (the default): every function is
//!   an inlined no-op, the diagnostic macros expand to `eprintln!`, and
//!   this crate has **zero dependencies**. Default builds are byte-for-byte
//!   unaffected beyond routing the handful of pre-existing `eprintln!`
//!   diagnostics through one macro.
//! * **With** `telemetry`: structured logs (`tracing`), a Prometheus
//!   registry, and OTLP export (traces + metrics) come online. See the
//!   [`imp`] module.
//!
//! Everything reported here is **metadata and counts only** — never drawer
//! content or key material — matching Undercroft's local-first, opt-in
//! stance.

#[cfg(feature = "telemetry")]
mod imp;

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Severity for [`_diag`]. Public only because the `diag_*!` macros expand
/// to a reference to it; treat it as an implementation detail.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum DiagLevel {
    Info,
    Warn,
    Error,
}

/// Backing function for the `diag_*!` macros. Compiled once here so it picks
/// up *this* crate's feature flag rather than the caller's.
#[doc(hidden)]
#[cfg(not(feature = "telemetry"))]
pub fn _diag(level: DiagLevel, args: std::fmt::Arguments<'_>) {
    match level {
        DiagLevel::Info => eprintln!("{args}"),
        DiagLevel::Warn => eprintln!("warning: {args}"),
        DiagLevel::Error => eprintln!("error: {args}"),
    }
}

#[doc(hidden)]
#[cfg(feature = "telemetry")]
pub fn _diag(level: DiagLevel, args: std::fmt::Arguments<'_>) {
    imp::diag(level, args);
}

/// Emit an informational diagnostic. `eprintln!`-compatible format args.
#[macro_export]
macro_rules! diag_info {
    ($($arg:tt)*) => { $crate::_diag($crate::DiagLevel::Info, format_args!($($arg)*)) };
}

/// Emit a warning diagnostic.
#[macro_export]
macro_rules! diag_warn {
    ($($arg:tt)*) => { $crate::_diag($crate::DiagLevel::Warn, format_args!($($arg)*)) };
}

/// Emit an error diagnostic.
#[macro_export]
macro_rules! diag_error {
    ($($arg:tt)*) => { $crate::_diag($crate::DiagLevel::Error, format_args!($($arg)*)) };
}

// ---------------------------------------------------------------------------
// Metrics — counters & histograms
// ---------------------------------------------------------------------------

/// Outcome of a drawer write, used as a metric label.
#[derive(Clone, Copy)]
pub enum WriteOutcome {
    Created,
    Deduped,
}

impl WriteOutcome {
    #[cfg(feature = "telemetry")]
    fn as_str(self) -> &'static str {
        match self {
            WriteOutcome::Created => "created",
            WriteOutcome::Deduped => "deduped",
        }
    }
}

/// A knowledge-graph mutation kind, used as a metric label.
#[derive(Clone, Copy)]
pub enum KgKind {
    Entity,
    Triple,
    Supersede,
}

impl KgKind {
    #[cfg(feature = "telemetry")]
    fn as_str(self) -> &'static str {
        match self {
            KgKind::Entity => "entity",
            KgKind::Triple => "triple",
            KgKind::Supersede => "supersede",
        }
    }
}

/// Record a completed search: wall-clock duration, hit count, the active
/// fusion mode, and whether the FTS BM25 prefilter fired.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn search_completed(
    duration: std::time::Duration,
    hits: usize,
    fusion: &str,
    prefiltered: bool,
) {
    #[cfg(feature = "telemetry")]
    imp::search_completed(duration, hits, fusion, prefiltered);
}

/// Record a drawer write (created or deduplicated).
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn drawer_write(outcome: WriteOutcome) {
    #[cfg(feature = "telemetry")]
    imp::counter_add(
        "undercroft_drawer_writes_total",
        1,
        &[("outcome", outcome.as_str())],
    );
}

/// Record a drawer deletion.
pub fn drawer_delete() {
    #[cfg(feature = "telemetry")]
    imp::counter_add("undercroft_drawer_deletes_total", 1, &[]);
}

/// Record a knowledge-graph write.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn kg_write(kind: KgKind) {
    #[cfg(feature = "telemetry")]
    imp::counter_add("undercroft_kg_writes_total", 1, &[("kind", kind.as_str())]);
}

/// Record an audit-chain commit (fires once per mutation).
pub fn chain_commit() {
    #[cfg(feature = "telemetry")]
    imp::counter_add("undercroft_chain_commits_total", 1, &[]);
}

/// Record an HMAC / integrity verification failure — the tamper signal.
/// `surface` is one of `drawer`, `kg`, `tunnel`, `manifest`.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn hmac_verify_failed(surface: &str) {
    #[cfg(feature = "telemetry")]
    {
        imp::counter_add(
            "undercroft_hmac_verify_failures_total",
            1,
            &[("surface", surface)],
        );
        imp::diag(
            DiagLevel::Error,
            format_args!("integrity failure — HMAC verification failed on {surface}"),
        );
    }
}

/// Record a vault store open (cache miss in the multi-tenant server).
pub fn vault_opened() {
    #[cfg(feature = "telemetry")]
    imp::counter_add("undercroft_vault_opens_total", 1, &[]);
}

/// Record an HTTP request: route class, status code, and duration.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn http_request(route: &str, status: u16, duration: std::time::Duration) {
    #[cfg(feature = "telemetry")]
    imp::http_request(route, status, duration);
}

/// Record an auth rejection. `kind` is `bearer` or `assertion`.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn auth_rejected(kind: &str) {
    #[cfg(feature = "telemetry")]
    imp::counter_add("undercroft_auth_rejections_total", 1, &[("kind", kind)]);
}

// ---------------------------------------------------------------------------
// Tracing spans (OTLP traces)
// ---------------------------------------------------------------------------

/// RAII guard for an open trace span. Hold it for the duration of the
/// operation; the span closes (and, with an OTLP endpoint set, exports to a
/// collector such as Tempo) when this drops.
///
/// **Metadata only** — spans carry the operation name plus low-cardinality
/// identifiers (vault id, route). They never carry query text, drawer
/// content, wing/room names, or key material.
///
/// Without the `telemetry` feature this is a zero-sized no-op.
#[must_use = "bind the span guard to a local (`let _s = …`) so it stays open for the operation"]
pub struct Scope {
    #[cfg(feature = "telemetry")]
    _guard: imp::SpanGuard,
}

/// Open a span for an operation (`search`, `save`, `kg`, `commit`), tagged
/// with the vault id. Nests under whatever span is already open on this
/// thread, so a request span becomes the parent of the work it drives.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn scope(op: &'static str, vault: &str) -> Scope {
    Scope {
        #[cfg(feature = "telemetry")]
        _guard: imp::enter_op(op, vault),
    }
}

/// Open a request-root span for an inbound call, tagged with its route
/// class (e.g. `v1_search`) and optional vault id.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn scope_request(route: &str, vault: Option<&str>) -> Scope {
    Scope {
        #[cfg(feature = "telemetry")]
        _guard: imp::enter_request(route, vault.unwrap_or("")),
    }
}

// ---------------------------------------------------------------------------
// Gauges (metadata sampled from stats)
// ---------------------------------------------------------------------------

/// Base names of the gauges this build exports, each as
/// `undercroft_<name>{vault="…"}`.
///
/// **A gauge set under a name that is not in this list is silently dropped.**
/// One observable gauge is registered per name and its callback only reports
/// map entries matching that name, so an unlisted name accumulates values
/// nothing ever reads — write-only telemetry that looks live at the call site
/// and is absent from `/metrics`. Public so a producer can pin the names it
/// emits against the names that are actually registered, in a build without
/// the `telemetry` feature.
pub const GAUGE_NAMES: &[&str] = &[
    "drawers",
    "kg_triples",
    "kg_entities",
    "audit_chain_height",
    "store_bytes",
    // Trained index artifacts: how many times each codebook or centroid set
    // has been trained in this vault (see
    // `PalaceStore::codebook_generation_bump`). A step means every row coded
    // against the previous generation was re-coded.
    "codebook_generation_pq_codebook",
    "codebook_generation_pq_ivf",
    "codebook_generation_fde_codebook",
    "codebook_generation_fde_ivf",
    "codebook_generation_tok_codebook",
];

/// Set a gauge value for a vault. Atomic-backed and Send-safe; read on
/// scrape by both the Prometheus renderer and the OTLP observable gauges.
/// `name` must be one of [`GAUGE_NAMES`] — anything else is dropped without
/// a trace.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn set_gauge(name: &str, vault: &str, value: f64) {
    #[cfg(feature = "telemetry")]
    imp::set_gauge(name, vault, value);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// RAII guard returned by [`init`]. Hold it for the lifetime of the
/// process; its `Drop` flushes and shuts telemetry providers down, so
/// buffered OTLP spans/metrics are exported even on early `?` returns.
#[must_use = "hold the telemetry guard until process exit so telemetry is flushed"]
pub struct TelemetryGuard(());

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        #[cfg(feature = "telemetry")]
        imp::shutdown();
    }
}

/// Initialize telemetry from `UNDERCROFT_*` environment variables. Call
/// once at process start and keep the returned guard alive. No-op (and a
/// zero-sized guard) without the `telemetry` feature.
///
/// Reads: `UNDERCROFT_LOG` (EnvFilter directives), `UNDERCROFT_LOG_FORMAT`
/// (`json`|`text`), `UNDERCROFT_OTLP_ENDPOINT` (unset ⇒ no network egress),
/// `UNDERCROFT_SERVICE_NAME`, `UNDERCROFT_OTLP_HEADERS`.
pub fn init() -> TelemetryGuard {
    #[cfg(feature = "telemetry")]
    imp::init();
    TelemetryGuard(())
}

/// Render the current metrics in Prometheus text exposition format.
/// Returns `None` when built without the `telemetry` feature, so callers
/// can distinguish "not compiled in" from "no metrics yet".
pub fn render_prometheus() -> Option<String> {
    #[cfg(feature = "telemetry")]
    {
        imp::render_prometheus()
    }
    #[cfg(not(feature = "telemetry"))]
    {
        None
    }
}

// ---------------------------------------------------------------------------
// Live telemetry — discrete event pings (v0.10)
// ---------------------------------------------------------------------------
//
// These are SEPARATE from the Prometheus counters above: they carry vault +
// location so a live UI can animate individual actions, without polluting
// counter label cardinality. Sealed vaults pass `sealed = true` and their
// wing/room is suppressed before it leaves the process. All no-op without
// the `telemetry` feature.

/// A drawer was filed (created or deduped) in `vault` at `wing`/`room`.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn event_drawer_saved(vault: &str, wing: &str, room: &str, deduped: bool, sealed: bool) {
    #[cfg(feature = "telemetry")]
    imp::event_drawer_saved(vault, wing, room, deduped, sealed);
}

/// A drawer was deleted from `vault` (location not resolved at this site).
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn event_drawer_deleted(vault: &str) {
    #[cfg(feature = "telemetry")]
    imp::event_drawer_deleted(vault);
}

/// A search ran against `vault` (optionally wing/room scoped) with `hits`.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn event_search(
    vault: &str,
    wing: Option<&str>,
    room: Option<&str>,
    hits: usize,
    sealed: bool,
) {
    #[cfg(feature = "telemetry")]
    imp::event_search(vault, wing, room, hits, sealed);
}

/// A knowledge-graph triple was written/superseded in `vault`.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn event_kg_triple(vault: &str) {
    #[cfg(feature = "telemetry")]
    imp::event_kg_triple(vault);
}

/// The audit chain advanced for `vault`.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn event_chain_commit(vault: &str) {
    #[cfg(feature = "telemetry")]
    imp::event_chain_commit(vault);
}

/// An HMAC / integrity verification failed on `vault` — the live tamper
/// signal for the Palace Monitor alarm. `surface` is `drawer`/`kg`/
/// `tunnel`/`manifest`. Metadata only (vault + surface tag).
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn event_hmac_fail(vault: &str, surface: &str) {
    #[cfg(feature = "telemetry")]
    imp::event_hmac_fail(vault, surface);
}

// ---------------------------------------------------------------------------
// Live telemetry — periodic sampler + SSE stream (telemetry feature only)
// ---------------------------------------------------------------------------

/// One point-in-time snapshot of a vault's aggregate counts. All fields are
/// counts/metadata — never content. For a sealed vault `wings` is empty
/// (names suppressed); the scalar counts still flow.
#[cfg(feature = "telemetry")]
#[derive(Clone, serde::Serialize)]
pub struct Sample {
    pub ts: i64,
    pub vault: String,
    pub sealed: bool,
    pub drawers: u64,
    pub rooms: u64,
    pub wings: Vec<(String, u64)>,
    pub kg_triples: u64,
    pub kg_entities: u64,
    pub kg_active: u64,
    pub tunnels: u64,
    pub chain_height: u64,
    pub db_bytes: u64,
}

/// Push a sample into the ring buffer and broadcast it to subscribers.
#[cfg(feature = "telemetry")]
pub fn publish_sample(sample: Sample) {
    imp::publish_sample(sample);
}

/// The most recent `window` samples for `vault` (oldest→newest).
#[cfg(feature = "telemetry")]
pub fn history(vault: &str, window: usize) -> Vec<Sample> {
    imp::history(vault, window)
}

/// Distinct vault ids with at least one active stream subscriber — so the
/// sampler only samples what someone is watching.
#[cfg(feature = "telemetry")]
pub fn subscribed_vaults() -> Vec<String> {
    imp::subscribed_vaults()
}

/// Run one SSE connection to completion on the calling thread: subscribe to
/// `vault`, write the HTTP head + `text/event-stream`, replay recent
/// history, then stream live frames until the client disconnects. `writer`
/// is the hijacked socket (`tiny_http::Request::into_writer()`), kept out of
/// this crate's type surface so obs never depends on the HTTP server.
/// Returns `false` if the subscriber cap is reached (caller should 503).
#[cfg(feature = "telemetry")]
pub fn run_sse(writer: Box<dyn std::io::Write + Send>, vault: String) -> bool {
    imp::run_sse(writer, vault)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_op_calls_never_panic() {
        // The whole surface must be callable regardless of feature state.
        diag_info!("boot {}", 1);
        diag_warn!("warn {}", 2);
        diag_error!("err {}", 3);
        search_completed(std::time::Duration::from_millis(5), 3, "bm25", true);
        drawer_write(WriteOutcome::Created);
        drawer_write(WriteOutcome::Deduped);
        drawer_delete();
        kg_write(KgKind::Triple);
        kg_write(KgKind::Supersede);
        chain_commit();
        hmac_verify_failed("drawer");
        vault_opened();
        http_request("v1_search", 200, std::time::Duration::from_millis(1));
        auth_rejected("bearer");
        set_gauge("drawers", "personal", 42.0);
        event_drawer_saved("personal", "eng", "decisions", false, false);
        event_drawer_deleted("personal");
        event_search("personal", Some("eng"), None, 3, false);
        event_kg_triple("personal");
        event_chain_commit("personal");
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn broker_history_is_a_bounded_ring() {
        let mk = |ts: i64| Sample {
            ts,
            vault: "ring-test".into(),
            sealed: false,
            drawers: ts as u64,
            rooms: 0,
            wings: vec![],
            kg_triples: 0,
            kg_entities: 0,
            kg_active: 0,
            tunnels: 0,
            chain_height: 0,
            db_bytes: 0,
        };
        for i in 0..350 {
            publish_sample(mk(i));
        }
        let all = history("ring-test", 10_000);
        assert!(
            all.len() <= 300,
            "ring should cap at 300, got {}",
            all.len()
        );
        assert_eq!(all.last().unwrap().ts, 349, "newest sample retained");
        let win = history("ring-test", 5);
        assert_eq!(win.len(), 5, "window slices to the last N");
        assert_eq!(win.first().unwrap().ts, 345);
        assert!(history("no-such-vault", 10).is_empty());
    }

    #[cfg(not(feature = "telemetry"))]
    #[test]
    fn render_is_none_without_feature() {
        assert!(render_prometheus().is_none());
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn render_contains_recorded_metrics() {
        let _g = init();
        chain_commit();
        drawer_write(WriteOutcome::Created);
        hmac_verify_failed("drawer");
        let text = render_prometheus().expect("telemetry build renders metrics");
        assert!(
            text.contains("undercroft_chain_commits"),
            "missing chain_commits; rendered:\n{text}"
        );
        assert!(
            text.contains("undercroft_drawer_writes"),
            "missing drawer_writes; rendered:\n{text}"
        );
        assert!(
            text.contains("undercroft_hmac_verify_failures"),
            "missing hmac_verify_failures; rendered:\n{text}"
        );
    }
}
