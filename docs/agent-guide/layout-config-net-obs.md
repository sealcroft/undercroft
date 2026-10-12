# Agent guide — configuration, transport and observability crates

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the Layout entries for
`crates/undercroft-config` (the shared declaration resolvers),
`crates/undercroft-net` (the outbound transport policy, CA pins, the body
ceiling, and asking the transport's own parser which host a request reaches),
the OTLP traces hop, and `crates/undercroft-obs` (the stdio door, telemetry,
and the exported series inventory). Read it when your work touches one of
those crates, an `UNDERCROFT_*` resolver, an outbound client, a CA pin, an
HTTP body, stdout, or a metric.

It was moved here unchanged when the guide was split (ROADMAP O433,
2026-10-12), and it governs over any one-line statement of the same rule in
the core. In the moved text, "this file" and "here" mean the guide as a whole
— the core and its reference documents.

---

- `crates/undercroft-config` — the declaration resolvers the engine and the
  control plane SHARE (`resolve_orch_key`, `resolve_admin_token`,
  `resolve_rate_limit`, `resolve_orch_addr`, `resolve_metrics_addr`,
  `resolve_metrics_token`, and the listen-host loopback predicate
  `host_is_loopback`, which `addr_is_loopback` and the engine's
  refuse-to-bind rule both ask — ROADMAP O177: they were two copies of the
  literals, recorded as byte-identical, and an address predicate handed a
  bare `::1` reads host `":"`, so the drop-in would have refused
  `serve-http --host ::1`. A source gate here, `loopback_tests.rs`, refuses
  any of the three literals as a string token in non-test code outside that
  one function. It allows `"localhost"` once in each of the two OUTBOUND
  predicates, `undercroft-net`'s `is_loopback` and `undercroft-index`'s
  `dsn_is_loopback`, which compare it against a parser's typed host and
  cannot share a listen-host predicate (the O90/O92 rule). It also allows
  `serve-http`'s `127.0.0.1` default `--host`, a value bound rather than a
  decision. Test code is read from the module tree, not from file names). Its own
  crate on `undercroft-net`'s precedent: a
  policy several crates need has one implementation, and when the crates that
  need it cannot link each other it gets a home neither owns. Six surfaces
  including the doctrine promised `undercroft config check` validates every
  `UNDERCROFT_*` declaration; three were not, because their parses sat inside
  `undercroft-orchestrator` — and the first fix attempt narrowed all six
  documents to match the code instead (ROADMAP O24, and **O24a keeps that
  draft**, because what separated right from wrong was not new evidence but
  reading the inventory the command already iterates). **The dependency list
  is the design** — `thiserror` and `hex`, nothing else: both consumers pay
  for whatever lands here, which is why this is not in `undercroft-core`
  (unicode normalization and a calendar library, for a handful of string
  parses) and
  not in `undercroft-net`, whose domain is transport and which correctly
  keeps the two declaration resolvers that ARE transport (`declared_pin`,
  `declared_endpoint`)
- `crates/undercroft-net` — the outbound transport policy, in ONE place:
  **TLS or loopback, nothing else, no override** (refused at construction,
  before a byte moves) plus CA pinning, where a declared root REPLACES the
  public roots rather than adding to them and a file that pins nothing
  refuses instead of falling back — **and, since O111, the one body ceiling
  every listener and every hop reads through** (`MAX_BODY_BYTES`,
  `read_body_bounded`, `read_json_bounded`: 256 MiB, a declared length over
  it refused before a byte is read, an arriving body refused one past it,
  never truncated). It lives here rather than in the CLI because the
  orchestrator, the index backends, the LLM client and the OTLP exporter all
  need it and none can link the CLI. It is its own crate because it was
  implemented once in `undercroft-llm` for the embedder and LLM clients
  while the remote **index** backends had no transport policy at all
  (ROADMAP C8) — and every index push carries EMBEDDINGS, which are
  plaintext-derived, so the sealed-vault invariant's own reasoning applies
  one hop out. `is_loopback` delegates to the transport's own `url` parser
  rather than re-deriving the host, because a hand-rolled predicate
  inverted this gate twice (`http://127.0.0.1:8080@evil.com/` read as
  loopback).
  **A third instance landed in an AUDIT RECORD rather than in a gate (O92)**:
  `LlmClient::destination` hand-parsed the authority to strip userinfo,
  ending it at the first `/`, `?` or `#` — and for a special scheme the
  parser also ends it on a backslash, so the refine egress record named
  loopback while the corpus went to an attacker-chosen host, inside an HMAC'd
  canonical. So the rule is wider than a predicate: **anything that must know
  WHICH HOST a request reaches — to gate it, or to write it down — asks the
  parser the transport uses.** Note that the enumerating fix passes review
  easily, because a list of separators looks exhaustive until someone names
  the one missing from it; the durable test is a PROPERTY (this host equals
  the parser's host), never a longer table.
  **A FOURTH instance was the pgvector DSN (O90), and it adds the sharpest
  lesson of the three**: `dsn_is_loopback` scanned for a literal `host=`
  prefix and ended `saw_host || !d.is_empty()`, so a host spelled `hostaddr=`
  or `host = ` (whitespace libpq allows) read as LOOPBACK and skipped a
  cleartext refusal whose own text says *"There is no override"* — pushing
  plaintext-derived embeddings over the network. It had **no test at all**.
  The lesson is about the API you reason against: `postgres::Config` exposes
  `get_hosts()` and NO `get_hostaddrs()`, keeps its inner
  `tokio_postgres::Config` private, and the crate re-exports neither — so the
  key that defeats the guard is **invisible from the surface a guard author
  naturally reads**, and no amount of care with that surface would have found
  it. Ask which type the connector actually builds (`Client::connect` is
  `params.parse::<Config>()?.connect(tls)`) and parse with THAT, even when it
  costs a dependency edge.
  **The policy covers the DECLARATION as well as the client, and for two
  releases it only covered the client** (ROADMAP O82c). `agent_from_env` is
  documented as "the one constructor every hop that reads a `*_CA` variable
  should use" — but a hop that does not speak HTTP cannot use it, and
  pgvector is exactly that: `tokio_postgres_rustls`, which wants a
  `rustls::ClientConfig`. So it read `UNDERCROFT_INDEX_CA` with a bare
  `std::env::var`, and ONE declaration got **two answers across five
  backends** (the other four trim it and refuse a whitespace-only value
  through `declared_pin`) while **re-reading the PEM per construction**,
  which `pin_from_env` caches deliberately because re-reading per call is
  "silent un-pinning by another name" — on `index/status`, the one hop
  reachable per request. `rustls_config_from_env` is the door for a non-`ureq`
  hop; `Pin`'s field stays private, so the policy crate remains the only
  place a `ClientConfig` can be assembled. **Both existing transport gates
  were blind to it by construction**: one scans source for ureq's builder
  token, the other reads a dependency edge out of `Cargo.lock`, and a bare
  `env::var` moves neither — so the third gate matches the READ, which is the
  observable this class actually moves. Fourth instance of *ask what a gate
  can SEE*
- **The OTLP traces hop was the one outbound client that never obeyed any of
  this, and the gate could not see it (round-four #8).** `undercroft-obs`
  built its span exporter on `opentelemetry-otlp`'s `reqwest-blocking-client`
  feature, so it went through a second HTTP library `undercroft-net` knew
  nothing about — no cleartext refusal, no loopback check, no pin — while
  `UNDERCROFT_OTLP_HEADERS` is documented to carry a bearer token and spans
  carry vault ids and route labels. Worse, that feature set linked reqwest
  with **no TLS backend at all**, so `https://` could not work and the
  builder failure was swallowed by an `if let Ok(..)`: no traces, no error.
  The exporter now runs on the policed `ureq` agent through
  `opentelemetry-http`'s `HttpClient` trait, and `UNDERCROFT_OTLP_CA` pins
  its root. **The gate is the lesson**:
  `no_crate_but_undercroft_net_builds_its_own_http_client` scans source for
  ureq's builder token — the observable this defect does not move, since the
  client was somebody else's library. Its sibling
  `no_second_http_client_is_linked_into_the_workspace` reads the DEPENDENCY
  EDGE out of `Cargo.lock` instead, which is why dropping that feature (so
  reqwest leaves the lock entirely) is part of the fix rather than tidying.
  Third instance of *ask what a gate can SEE, not what it asserts.*
- `crates/undercroft-obs` — observability shim: no-op + **zero deps** by default;
  under `--features telemetry` brings up `tracing` logs, Prometheus `/metrics`,
  OTLP traces (metadata-only spans), and the live SSE broker. **And on every
  build `stdio.rs`, the one door the two binaries' own code writes stdout
  through (ROADMAP O287)**: `outln!` never panics — on `BrokenPipe` it latches
  that the reader left and discards the rest, so a command runs on to its own
  verdict — and `errln!` is a best-effort stderr line; each binary's `main`
  flushes the door explicitly and folds the exit status in one order, an
  integrity verdict 2, a failed run 1, the reader leaving 141, then 0
  (`exit_status`). `println!` panicked on a closed reader, so `verify | head`
  over a tampered vault was 101. Both binaries' roots
  `#![deny(clippy::print_stdout, clippy::print_stderr)]`, and two source
  counts in `stdio.rs` cover the code no lint leg compiles (O153): no print
  escapes the door in either binary, and NO production code in any crate
  holds a print macro — the default build's `diag_*!` write through `errln!`'s
  line since O328, so a server whose log reader went away keeps serving.
  `serve-mcp`'s closed client is a session end, exit 0. Exit 0 is no proof of
  delivery: output that fits in a pipe's buffer can be lost to a reader that
  dies after the last write. The one stdout write outside the door is a
  telemetry build's `UNDERCROFT_LOG_FORMAT=json` log layer (O333). Two contracts
  worth knowing: `chain_commit(records)` counts audit-chain **records**, not
  manifest anchors (a 256-drawer batch anchors once and advances it by 256;
  records appended without an anchor — read audits — are counted by the next
  one; `chain_replayed()` beside it counts the label guard's FULL replays,
  unlabelled on the per-wing-codebook rule — a vault-shaped label has a value
  set created by use, and the per-vault figure is already on
  `/v1/…/stats`), and **a diversion is a `drawer-quarantined` frame decided
  by ONE classifier**: `admission::save_event` classifies by WHERE THE ROW LANDED,
  `write_drawer` emits at the choke point, and `upsert_many` — which owns
  its transaction and cannot reach the choke point — runs the same
  classifier over its batch. The frame carries the intended wing/room and
  the closed-vocabulary signal codes; **since M6 the names travel on every
  level too** — a frame only ever reaches a subscriber that proved per-vault
  authorization, and that same caller reads those names from `/v1/…/stats`,
  so blanking them blinded the owner and withheld nothing from anyone else.
  Offsets and content never travel, which is what the gates pin now. `monitor.html` dispatches on
  `drawer-quarantined`; `website/src/observability.md` documents it.
  **The counter travels with the frame since 2026-08-05 (C11/R5)**: both
  are emitted by ONE function (`VaultStore::emit_write_event`) off ONE
  `save_event` classification, and `drawer_writes_total` gained a third VALUE on its one
  `outcome` label, `quarantined` (not a third label — the counter has
  exactly one). It used to be a hard-coded
  `WriteOutcome::Created` one line above the branch that decided the
  frame, on all five write arms, so the monitor showed
  `drawer-quarantined` while the counter climbed as `created` — a durable
  signal that was *wrong* rather than missing. Gated by a SOURCE count
  (`write_telemetry_has_exactly_one_emitter`), because the counter is a
  no-op without the telemetry feature and no test that merely drives a
  save could ever have seen it. **The exported series are an INVENTORY,
  and the whole of it is now counted (2026-08-09, ROADMAP O4)**:
  `GAUGE_NAMES` + `COUNTER_NAMES` + `HISTOGRAM_NAMES`, pinned to the emit
  sites by `the_series_inventory_matches_the_emit_sites` (both
  directions), and consumed by two gates that could not exist before it.
  `every_gauge_name_is_registered_and_every_registered_name_is_emitted`
  (in `undercroft-store`, where `CODEBOOK_ARTIFACTS` lives) covers all
  **ten** gauges — it covered the five codebook ones and the other five
  were bare literals in `tenant.rs` with nothing pinning them, i.e. the
  exact arrangement whose first instance shipped five dead names; a gauge
  outside `GAUGE_NAMES` is dropped with no error at any level.
  `every_series_the_deployment_configs_name_is_one_the_binary_exports`
  reads `deploy/observability/` (hence the Dockerfile's `COPY deploy`)
  and is deliberately ONE-directional: every series a config names must
  exist, never the reverse — an alert on a series the binary does not
  export stays `inactive` forever and a panel merely looks empty, and
  nothing in the stack reports either
