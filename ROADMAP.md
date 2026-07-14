# Undercroft Roadmap

Undercroft is the Rust conversion of MemPalace with a hardened memory-management
layer (isolated vaults, XChaCha20-Poly1305 encryption, HMAC integrity).

## v0.2.0 — Feature parity + Python removal (done)

- Legacy Python implementation and tooling fully removed
- Knowledge graph: temporal facts with validity windows (add / query /
  invalidate / supersede / timeline / stats), objects sealed in encrypted
  vaults, triples HMAC-tagged and audit-chained
- Conversation mining (`mine --mode convos`) for Claude Code / Codex JSONL
  transcripts + idempotent per-message `sweep`
- Drawer management (get / list / update / delete / delete-by-source /
  check-dup with keyed fingerprints), dedup, stats, taxonomy
- Agent diaries (per-agent wings), cross-wing tunnels (create / follow /
  traverse), computed hallways (entity co-occurrence)
- Verified backups (create / list / restore, keeps last 10), repair
- Auto-save hook settings output for Claude Code
- MCP server: 32 tools across palace core, drawers, navigation, KG,
  diaries, maintenance

## v0.1.0 — Core port + vault layer (done)

- Rust workspace; palace domain model; deterministic drawer ids; chunking
- Vault layer: per-vault HKDF key derivation, AEAD sealing, HMAC record
  tags, tamper-evident audit chain, MAC'd manifests, sealed / hmac-only
- SQLite per-vault storage; hybrid search; CLI; Docker-first test harness

## v0.3.0 — Remote backends + pluggable embedders (done)

- Remote vector indexes as untrusted accelerators: Qdrant, Chroma (REST v2),
  pgvector — content sealed client-side before upload, candidates re-verified
  (HMAC) and re-ranked locally; `index push/status`, `search --backend`
- Embedder identity tracking per vault (record on first write, refuse silent
  model swaps, `UNDERCROFT_FORCE_EMBEDDER=1` + `repair` to re-embed)
- ONNX sentence-embedder crate (MiniLM-class exports) on tract, pure Rust,
  feature-gated (`--features onnx`), models always user-supplied
- Compose services + `backends-e2e` suite against real servers

## v0.4.0 — Ecosystem parity (done)

- `undercroft-bench`: LongMemEval harness (same protocol/metrics as
  upstream) + synthetic CI benchmark
- MCP HTTP team server (`serve-http`, token-enforced, read-only mode) and
  `deploy/` (compose + systemd)
- `daemon run`, `transcript render`, `import` (mempalace migration path)
- Claude Code plugin, hooks, commands, skills, Cursor rules, integrations
  protocol, docs (architecture / security / PARITY), examples, devcontainer

## v0.5.0 — Final parity gaps (done)

- Milvus backend (REST v2), tested live alongside qdrant/chroma/pgvector
- Local-LLM refinement (`undercroft-llm`, `refine`) + restored model_eval
  datasets and scoring harness
- Closets compact index (AAAK port), typo-tolerant search, mdBook site

## v0.6.0 — Benchmark adapters + vector cache (done)

- LoCoMo / ConvoMem / MemBench adapters (fixture-tested), in-memory
  embedding cache for server modes; PARITY "not ported" list emptied

## v0.7.1 — FTS5 BM25 prefilter (done)

- hmac-only vaults keep an external-content FTS5 index over drawer
  content, maintained by triggers through every mutation path and
  self-healed (rebuilt) on open when it goes missing or stale
- Search above a drawer-count threshold (default 2048, tunable via
  `UNDERCROFT_FTS_PREFILTER_MIN` / `PalaceStore::set_fts_prefilter_min`)
  cuts candidates to the BM25 top-K before the usual verify + hybrid
  re-rank; full-scan fallback when FTS matches nothing, preserving
  semantic-only recall. Sealed vaults are untouched — no plaintext-derived
  index is ever created for them.

## v0.7.2 — BM25 rank fusion (done)

- Real Okapi BM25 lexical scoring over the verified candidate set,
  blended with cosine, now the search default (`UNDERCROFT_FUSION=bm25`;
  `legacy` and `rrf` selectable). Measured with the hash embedder:
  LongMemEval-S R@5 90.4 → 95.0, LoCoMo R@10 92.7 → 94.6, both above the
  prior numbers; the single-session-preference category nearly doubles.
  Embedder- and security-level-independent; re-ranks HMAC-verified
  candidates only.

## v0.8.0 — Multi-tenant server (done)

- `serve-http` is now a first-class per-tenant memory engine (vault =
  tenant), additive over the team-server mode: per-vault `X-Vault-Assertion`
  HMAC authorization, a versioned `/v1` REST surface (vault lifecycle +
  drawer ops + lossless export/import migration), caller-supplied
  (`external:<name>@<dim>`) embeddings, dedup-refresh on save, and an
  orchestrated one-instance-per-tenant deployment path.

## v0.9.0 — Observability & telemetry (done)

- Opt-in observability behind `--features telemetry` (off by default, zero
  extra deps / zero overhead): `tracing` structured logs (`UNDERCROFT_LOG`,
  `UNDERCROFT_LOG_FORMAT`), a Prometheus `/metrics` endpoint
  (`UNDERCROFT_METRICS=1`, loopback + bearer-gated), and OTLP trace export
  (`UNDERCROFT_OTLP_ENDPOINT`, unset ⇒ no egress). Metadata/counts only;
  the headline signal is `undercroft_hmac_verify_failures_total` (tamper on
  read). New `undercroft-obs` shim crate; fully synchronous (no tokio).
  First stage of the Operability track below.

## v0.10.0 — Live memory telemetry (done)

- The point-in-time observability becomes a **live push stream**: an SSE
  endpoint `GET /v1/vaults/{id}/stream` pushing periodic aggregate
  `sample` frames plus discrete event pings (`drawer-saved`,
  `drawer-deleted`, `search`, `kg-triple`, `chain-commit`) as they happen,
  a bounded per-vault sampler ring buffer (tick only for watched vaults),
  and a `stats/history` backfill. Each connection runs on its own thread
  reading only the in-process broker — never a store — so the sync server
  keeps serving and streaming can't touch content. Sealed vaults suppress
  wing/room names. Opt-in (`--features telemetry`). Second stage of the
  Operability track; feeds the v0.11 Palace Monitor UI.

## v0.11.0 — Palace Monitor UI (done)

- A self-contained pixel-art dashboard at `GET /monitor` (unauthenticated
  static page, telemetry build only), driven by the v0.10 SSE stream: an
  archivist files drawers into wings as writes land, searches pulse the
  wings, the chain stamps on commits, and an **ambulance beacon** fires on
  a real HMAC-verify failure — powered by a new `hmac-fail` stream event
  wired to every tamper site. Demo mode until the bearer + vault are
  entered; uses `fetch()` streaming (so it can send the bearer, unlike
  `EventSource`); fully inlined, same-origin only. Adds `GET /v1/vaults`
  (bearer-gated; disabled under per-vault assertions) for the picker.
  Final stage of the Operability track.

## Next

- **Retrieval quality**: cross-encoder reranker over the top-k (ONNX,
  the next accuracy lever — targets the residual preference/paraphrase
  gap). (MiniLM rows already re-measured under BM25 — see RESULTS.md:
  LongMemEval-S 99.4%, LoCoMo 94.6%.)
- **Scale**: L2 on-demand room loading heuristics; ANN index (HNSW) atop
  the warmed cache for very large palaces; share one ONNX model across
  tenant vaults in the multi-tenant server.
- **Ecosystem**: key rotation (re-seal under new derived keys); export
  bundles with recipient encryption.
- **Operability** (planned track below): observability/telemetry
  (v0.9.0), live memory telemetry (v0.10.0), and a retro real-time
  Palace Monitor UI (v0.11.0).

---

## Operability track (planned)

Observability and a management/visualization surface for the stack. The
whole track obeys the project's core stance — **local-first, opt-in,
zero external by default, no plaintext or key material ever exposed**:

- **Default-off, loopback-only.** No metrics port, telemetry export, or
  UI is served unless explicitly enabled; when enabled it binds loopback
  and sits behind the existing palace bearer / `X-Vault-Assertion` auth.
- **Feature-gated**, mirroring the `--features onnx` pattern — a build
  without the feature carries zero extra dependencies and zero overhead.
- **Metadata and counts only.** Everything below exposes structure,
  aggregate counts, rates, and latencies — never drawer content, drawer
  names beyond what `stats` already surfaces, or anything key-derived.
  Sealed vaults expose only aggregate distribution, preserving the
  no-plaintext-derived-index invariant (in-memory samples are counts,
  not content, and are never persisted for sealed vaults).

### v0.9.0 — Observability & telemetry (done)

Instrumentation foundation the higher layers read from. Shipped in the
new `undercroft-obs` shim crate; fully synchronous (no async runtime).

- **Structured logging** via `tracing` + `tracing-subscriber`, replacing
  the ad-hoc `eprintln`s. Level via `UNDERCROFT_LOG`; human format by
  default, JSON via `UNDERCROFT_LOG_FORMAT=json`. No content or key
  material is logged (`SecretKey` stays non-`Debug`).
- **Prometheus** `/metrics` endpoint (text exposition format) on the HTTP
  server, gated by `UNDERCROFT_METRICS=1`, loopback + bearer-gated.
  Counters/histograms for search, drawer writes/deletes, dedup, KG ops,
  audit-chain commits, HMAC verify failures, HTTP requests, auth
  rejections, vault opens; per-vault gauges (drawers, chain height).
  Metadata only.
- **OpenTelemetry** OTLP **trace** export behind `UNDERCROFT_OTLP_ENDPOINT`
  (unset ⇒ no network egress). Metrics are surfaced via the Prometheus
  pull model — OTLP metric push needs a periodic-reader runtime this sync
  stack deliberately avoids; deferrable follow-up.
- **Hot-path instrumentation** at search, save/dedup, KG writes, vault
  seal/commit, and every HMAC-verify failure site.
- All behind `--features telemetry` — default builds carry zero extra
  deps and zero overhead.

### v0.10.0 — Live memory telemetry (done)

Turns point-in-time `PalaceStats`/`KgStats` into a streaming time series.
Shipped: per-connection SSE thread reading a thread-safe broker (the
sync server + `!Send` stores made this the only sound model), sampler
that only ticks watched vaults, and sealed-vault wing/room suppression.

- **In-process sampler**: periodic snapshot of `PalaceStats` + `KgStats`
  + cache/index gauges into a bounded in-memory ring buffer (window and
  resolution configurable). No disk writes for sealed-vault derived data.
- **SSE stream**: `GET /v1/vaults/{id}/stream` (and a palace-wide roll-up)
  pushing sampled deltas over chunked HTTP (supported by the current
  `tiny_http` server). Auth-gated, opt-in.
- **Discrete event pings** on the same stream, so a UI can animate
  individual actions rather than only sampled totals: `drawer-saved`
  (wing/room), `drawer-deleted`, `search` (wing/room hits), `kg-triple`,
  `chain-commit`. Payload is type + location + counts — metadata only,
  never drawer text or names beyond what `stats` already exposes.
- **History backfill**: `GET /v1/vaults/{id}/stats/history?window=…`
  returns the ring buffer so a fresh client can draw the recent past on
  connect.
- Exposed signals: wing/room populations, drawer add/delete rate, search
  QPS + latency, KG triple counts, cache hit rate, FTS prefilter ratio,
  audit-chain height — all counts and rates, never text.

### v0.11.0 — Palace Monitor: pixel-art memory world (done)

Shipped: served at `GET /monitor` (self-contained, `fetch()`-streamed so it
can send the bearer), demo mode until connected, a live `hmac-fail` event
driving the tamper beacon, and a `GET /v1/vaults` picker. Verified live
against a real server.

A real-time, game-style pixel-art view of how memory is distributed
across the palace, reading the v0.10 stream. Inspiration:
`pixel-agents-hq/pixel-agents` (agents-as-characters in a live office) —
reimagined around Undercroft's own metaphor: the palace *is* the world,
and an **archivist** files drawers into wings and rooms as writes land.

- **Self-contained local UI** served at `/monitor`. Vanilla Canvas-2D +
  a sprite sheet embedded as a data-URI — **no framework, no external
  CDN/fonts/assets, zero runtime JS toolchain** (hand-written, or a Vite
  bundle inlined at build time). One self-contained asset, CSP-safe,
  faithful to the local-first ethos. (Deliberate divergence from the
  reference's Node/React/Fastify stack, which the Rust runtime avoids.)
- **Pixel-art game world**: the palace rendered as an explorable
  top-down / isometric building. Wings are wings/floors, rooms are
  chambers, drawers are filing cabinets whose fill/brightness tracks
  drawer density. A lightweight game loop with sprite animation and a
  character state machine (idle → walk → file/pull).
- **Live, event-driven animation** off the v0.10 discrete pings:
  - *Archivist* walks to the target room and **files a drawer** on each
    `drawer-saved` (and on `mine`/`sweep` bursts); pulls and highlights
    drawers on `search` hits.
  - *KG hallways* — corridors drawn between co-occurring rooms, pulsing
    when a new `kg-triple` forms; entities as a constellation overlay.
  - *Audit-chain* — a stamp/ledger animation on each `chain-commit`,
    with the running chain height shown.
  - *Activity ticker + gauges* — search latency, QPS, cache hit rate,
    FTS prefilter ratio, drawer add/delete rate.
- **Sealed vaults stay opaque**: a sealed room renders as a locked
  vault-door showing only an aggregate silhouette (drawer *count*),
  never names or content — same no-plaintext invariant as the rest of
  the stack.
- **Read-only, metadata-only, default-off, loopback, auth-gated.**
  Multi-tenant aware: one building per vault/tenant plus a palace-wide
  roll-up (mirrors the reference's multi-agent view).
