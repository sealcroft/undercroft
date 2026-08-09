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
    /// The admission screen diverted the write. Its own label rather than
    /// `created`, because `drawer_writes_total{outcome="created"}` counted
    /// diverted writes as created on every write arm — a positively
    /// misleading durable signal, not merely a missing one, and the exact
    /// counterpart of the `drawer-saved` frame that used to travel beside
    /// the honest `drawer-quarantined` one (ROADMAP C11/R5).
    Quarantined,
}

impl WriteOutcome {
    #[cfg(feature = "telemetry")]
    fn as_str(self) -> &'static str {
        match self {
            WriteOutcome::Created => "created",
            WriteOutcome::Deduped => "deduped",
            WriteOutcome::Quarantined => "quarantined",
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

/// Record how many per-wing indexes served one query's candidate set — the
/// honest cost metric for anything fan-out shaped. The dual-index tier
/// probes exactly one (the scoped wing); a future cross-wing fan-out must
/// report its real count here rather than let an unbounded fan-out hide
/// inside one query. Content-free: a count, never a wing name.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn search_wings_probed(wings: u64) {
    #[cfg(feature = "telemetry")]
    imp::counter_add("undercroft_search_wings_probed_total", wings, &[]);
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

/// Record `records` audit-chain records committed by one manifest anchor
/// — so the counter advances by the chain's actual growth, one per
/// mutation, whatever batching the write path used.
///
/// It used to take no argument and fire once per ANCHOR. A bulk ingest
/// anchors once per 256-drawer transaction and read-audit records do not
/// anchor at all, so the natural "is the audit chain advancing" alert
/// read bulk ingest as near-idle and read auditing as absent. The
/// anchor-lag boundary remains (records appended without an anchor are
/// counted by the next one) and is documented on the read path.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn chain_commit(records: u64) {
    #[cfg(feature = "telemetry")]
    if records > 0 {
        imp::counter_add("undercroft_chain_commits_total", records, &[]);
    }
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

/// Full names of the counter series this build exports.
///
/// Unlike [`GAUGE_NAMES`] this list registers nothing — counters are built
/// per call from a literal at the emit site. It is an **inventory**, kept so
/// that something outside this crate can ask *what series does the binary
/// actually export?* without running it under the `telemetry` feature and
/// scraping. `the_series_inventory_matches_the_emit_sites` counts it against
/// those literals in both directions, so it cannot rot into decoration.
pub const COUNTER_NAMES: &[&str] = &[
    "undercroft_auth_rejections_total",
    "undercroft_chain_commits_total",
    "undercroft_drawer_deletes_total",
    "undercroft_drawer_writes_total",
    "undercroft_hmac_verify_failures_total",
    "undercroft_http_requests_total",
    "undercroft_kg_writes_total",
    "undercroft_search_prefiltered_total",
    "undercroft_search_total",
    "undercroft_search_wings_probed_total",
    "undercroft_vault_opens_total",
];

/// Full names of the histogram series this build exports. Each renders as
/// three Prometheus series — `<name>_bucket`, `<name>_sum`, `<name>_count` —
/// which is why a consumer looking one of these up has to strip the suffix
/// first. Same inventory contract as [`COUNTER_NAMES`].
pub const HISTOGRAM_NAMES: &[&str] = &[
    "undercroft_http_request_duration_seconds",
    "undercroft_search_duration_seconds",
    "undercroft_search_hits",
];

/// Every series name this build can export, gauges included and fully
/// qualified. The deployment configs under `deploy/observability/` are
/// checked against this: an alert or dashboard panel naming a series the
/// binary does not export never fires and never errors, which is a monitor
/// that reads healthy because it is looking at nothing.
pub fn series_names() -> Vec<String> {
    COUNTER_NAMES
        .iter()
        .chain(HISTOGRAM_NAMES)
        .map(|s| s.to_string())
        .chain(GAUGE_NAMES.iter().map(|g| format!("undercroft_{g}")))
        .collect()
}

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

/// A write was DIVERTED by the admission screen into the quarantine wing
/// of `vault`. `intended_wing`/`room` are where it was headed (suppressed
/// for a sealed vault like every other location here); `signals` are the
/// tier-1 signal CODES — a closed vocabulary, never the flagged text and
/// never its offsets.
///
/// Its own event rather than a `drawer-saved` into a wing that happens to
/// be named `quarantine-pending`: the single-save paths emitted nothing at
/// all for a diversion and the bulk paths emitted an ordinary save, so
/// "did anything get quarantined just now?" was answered differently by
/// the same stream depending on which surface wrote. An operator watching
/// the monitor during a poisoning attempt is exactly the person this
/// signal exists for.
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn event_drawer_quarantined(
    vault: &str,
    intended_wing: &str,
    room: &str,
    signals: &[&str],
    sealed: bool,
) {
    #[cfg(feature = "telemetry")]
    imp::event_drawer_quarantined(vault, intended_wing, room, signals, sealed);
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

/// The audit chain advanced for `vault` by `records` records — one
/// anchor, however many records it committed (see [`chain_commit`]).
#[cfg_attr(not(feature = "telemetry"), allow(unused_variables))]
pub fn event_chain_commit(vault: &str, records: u64) {
    #[cfg(feature = "telemetry")]
    if records > 0 {
        imp::event_chain_commit(vault, records);
    }
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
        chain_commit(1);
        chain_commit(256);
        hmac_verify_failed("drawer");
        vault_opened();
        http_request("v1_search", 200, std::time::Duration::from_millis(1));
        auth_rejected("bearer");
        set_gauge("drawers", "personal", 42.0);
        event_drawer_saved("personal", "eng", "decisions", false, false);
        event_drawer_deleted("personal");
        event_search("personal", Some("eng"), None, 3, false);
        event_kg_triple("personal");
        event_chain_commit("personal", 1);
        event_drawer_quarantined(
            "personal",
            "eng",
            "decisions",
            &["imperative-instruction"],
            false,
        );
    }

    /// Every `undercroft_…` series literal in this crate's production code,
    /// read from the source. `imp.rs` compiles only under the `telemetry`
    /// feature but the file is on disk either way, which is the point: the
    /// inventory has to be checkable in the build everyone actually runs.
    fn emitted_series_literals() -> Vec<String> {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        for file in ["lib.rs", "imp.rs"] {
            let text = std::fs::read_to_string(src.join(file))
                .expect("this crate's own sources are readable");
            // Production half only. The test module below asserts on rendered
            // metric text using deliberately TRUNCATED names, which would
            // otherwise enter the inventory as series that do not exist.
            let prod = text.split("#[cfg(test)]").next().unwrap_or(&text);
            for line in prod.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with('*') {
                    continue;
                }
                let mut rest = line;
                while let Some(i) = rest.find("\"undercroft_") {
                    let after = &rest[i + 1..];
                    let Some(end) = after.find('"') else { break };
                    let name = &after[..end];
                    // `format!("undercroft_{name}")` builds the gauge names
                    // from GAUGE_NAMES and is not a series literal.
                    if name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                    {
                        out.push(name.to_string());
                    }
                    rest = &after[end + 1..];
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// **The series inventory is counted against the emit sites, both ways.**
    ///
    /// [`COUNTER_NAMES`] and [`HISTOGRAM_NAMES`] exist so that something
    /// outside this crate can ask what the binary exports without building it
    /// under the `telemetry` feature and scraping it. A hand-written list
    /// that answers that question is worth exactly as much as its accuracy,
    /// and nothing was checking it — so a counter added at a call site would
    /// have been absent from the inventory, and the deployment-config gate
    /// that consumes the inventory would then have called a perfectly good
    /// alert a reference to a non-existent series.
    ///
    /// Both directions, because each failure is real and they are different
    /// failures: a name emitted but not listed under-reports what exists, and
    /// a name listed but not emitted is a series the configs may reference
    /// and that will never appear.
    #[test]
    fn the_series_inventory_matches_the_emit_sites() {
        let emitted = emitted_series_literals();
        // The premise. Every assertion below is a loop, and a broken
        // extractor makes all of them vacuous at once.
        assert!(
            emitted.len() >= 10,
            "extracted only {} series literals from this crate's sources — \
             the extraction is broken, not the inventory: {emitted:?}",
            emitted.len()
        );
        let inventory: Vec<&str> = COUNTER_NAMES
            .iter()
            .chain(HISTOGRAM_NAMES)
            .copied()
            .collect();
        for name in &emitted {
            assert!(
                inventory.contains(&name.as_str()),
                "{name} is emitted but is in neither COUNTER_NAMES nor \
                 HISTOGRAM_NAMES, so anything reading the inventory does not \
                 know this series exists"
            );
        }
        for name in &inventory {
            assert!(
                emitted.iter().any(|e| e == name),
                "{name} is in the inventory but nothing emits it — a config \
                 may reference it and the series will never appear"
            );
        }
    }

    /// **Nothing under `deploy/observability/` may name a series the binary
    /// does not export.**
    ///
    /// An alert whose expression names a series that does not exist never
    /// fires and never errors: Prometheus evaluates it to an empty vector
    /// forever, the rule shows as `inactive`, and the monitor reads healthy
    /// because it is looking at nothing. A dashboard panel does the same
    /// thing and merely looks empty. Nothing in the stack reports either
    /// case, which is why this is a build-time check and not an operational
    /// one.
    ///
    /// **Deliberately one-directional.** Every series a config names must
    /// exist; the reverse — that every exported series appears in some
    /// dashboard — is not a requirement and must not become one, or adding a
    /// counter would force a panel nobody asked for.
    #[test]
    fn every_series_the_deployment_configs_name_is_one_the_binary_exports() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");
        let files = [
            "deploy/observability/alerts.yml",
            "deploy/observability/alerts_test.yml",
            "deploy/observability/grafana/dashboards/undercroft.json",
            "deploy/observability/RUNBOOK.md",
            "deploy/observability/README.md",
        ];

        let known = series_names();
        let mut checked = 0usize;
        for rel in files {
            let path = root.join(rel);
            // Absent is a failure, not a skip: this gate lives in a crate the
            // test image builds from a partial COPY, and the whole point is
            // that it must not pass by seeing nothing.
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!(
                    "{} is not readable ({e}). The deploy tree must be in the \
                     build context for this gate to mean anything",
                    path.display()
                )
            });

            let bytes = text.as_bytes();
            let mut i = 0;
            while let Some(p) = text[i..].find("undercroft_") {
                let start = i + p;
                let mut end = start;
                while end < bytes.len()
                    && (bytes[end].is_ascii_lowercase()
                        || bytes[end].is_ascii_digit()
                        || bytes[end] == b'_')
                {
                    end += 1;
                }
                let name = &text[start..end];
                i = end.max(start + 1);
                // `undercroft_*` in prose is a wildcard, not a series.
                if name.ends_with('_') {
                    continue;
                }
                checked += 1;
                // A histogram renders as three series; the configs name the
                // rendered ones.
                let stem = ["_bucket", "_sum", "_count"]
                    .iter()
                    .find_map(|suf| name.strip_suffix(suf))
                    .unwrap_or(name);
                assert!(
                    known.iter().any(|k| k == name) || HISTOGRAM_NAMES.contains(&stem),
                    "{rel} names the series {name:?}, which this build does \
                     not export. An alert on it would stay inactive forever \
                     and a panel would stay empty, with no error anywhere. \
                     Exported series: {known:?}"
                );
            }
        }
        assert!(
            checked >= 8,
            "found only {checked} series references across the deployment \
             configs — the extraction is broken, and every assertion above \
             it was vacuous"
        );
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
        chain_commit(1);
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
