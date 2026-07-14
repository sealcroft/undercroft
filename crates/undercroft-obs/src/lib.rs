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
// Gauges (metadata sampled from stats)
// ---------------------------------------------------------------------------

/// Set a gauge value for a vault. Atomic-backed and Send-safe; read on
/// scrape by both the Prometheus renderer and the OTLP observable gauges.
/// `name` is a bare metric name (e.g. `drawers`, `kg_triples`,
/// `audit_chain_height`, `store_bytes`).
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
