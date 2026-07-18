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

## v0.11.1 — Palace Monitor fixes (done)

- Fixes to the monitor UI after live testing: the archivist now animates
  (searches no longer freeze it; walk-cycle and idle wander restored), the
  speed slider scales the whole sim, the sound toggle gives audible feedback,
  and per-wing drawer tiles grow on an absolute log scale as writes land.
  Adds the website "Palace Monitor" section with real screenshots. No API or
  on-disk changes.

## v0.12.0 — Full observability & alerting stack (done)

- Turns `deploy/observability/` into the full picture: **Alertmanager** +
  Prometheus rules (headline `PalaceTamperDetected`, by `surface`), **Loki**
  logs, **Tempo** traces, an expanded Grafana dashboard, and a
  `grafana-image-renderer` for PNG export. Adds metadata-only trace **spans**
  to the Rust hot paths (zero-dep no-op without telemetry) and a **tamper
  runbook** (confirm/mitigate/fix/prevent). Fixes surfaced en route: exporter
  double-`_total` counter names, and OTLP traces missing the `/v1/traces` path.
  Site gains an "Operate it" section. No API/on-disk changes.

## v0.13.0 — Cross-encoder reranker (done)

- Optional second retrieval stage: a cross-encoder re-scores the fusion-ranked
  top-N candidates by the full `(query, passage)` pair before the final `limit`
  cut. New `Reranker` trait (`undercroft-core`) + `OnnxReranker`
  (`undercroft-embed-onnx`, reusing the tract/tokenizer machinery, pair-encode →
  relevance logit). Feature-gated (`onnx`), model user-supplied via
  `UNDERCROFT_RERANK_MODEL`/`_TOKENIZER` + `UNDERCROFT_RERANKER=onnx`;
  `UNDERCROFT_RERANK_TOP_N` (default 50) bounds latency. **tract 0.22 can't run
  DeBERTa rerankers** (mxbai-rerank was `Sign`-op-rejected) → ships targeting
  the BERT-family `cross-encoder/ms-marco-MiniLM-L-6-v2`. Wired into `search` /
  serve-mcp / daemon / bench. Full sharded benchmark + landing headline bars =
  follow-up; multi-tenant `/v1` reranker = follow-up (with shared-model item).

## v0.14.0 — Retrieval performance & scaling (done)

Every retrieval lever measured end to end; the expensive ones retired.
Reranker query cost **16.6 s → 101–327 ms at ~98% R@10**; bounded-RAM on-disk
ANN for large hmac-only corpora. All opt-in; defaults unchanged.

- **Reranker latency ladder**: rayon-parallel scoring → `RERANK_TOP_N` as a
  true pool cap (knee ≈20) → `score_batch` whole-pool trait interface → new
  **`undercroft-embed-ort`** crate (ONNX Runtime backend, opt-in C++ dep,
  ~2.5× tract per forward, identical scores) with a session pool
  (`UNDERCROFT_ORT_POOL`, `pool=1` = batched) + int8 model support. Ingest
  embedding 24 s → ~5 s.
- **On-disk PQ prefilter** (hmac-only vaults): 48 B codes + ~400 KB codebook,
  incremental encode, self-heal; recall flat in N (98.9% at 50k) with
  codebook-only RAM. `set_pq(true)`; sealed vaults untouched (invariant
  test-asserted). **Experimental in-memory HNSW** (`hnsw` feature): fastest,
  but O(corpus) RAM and needs `ef` scaling — RAM-only, never persisted.
- Remote vector backends measured under load: idle untrusted accelerators
  (by design) — never a latency/accuracy lever.
- Docs: `docs/RETRIEVAL_SCALING.md`, the public "Retrieval, scoring &
  scaling" page, RESULTS.md "every lever" + scenario recipes.

Also closes the v0.13.0 follow-up items:

- **Shared-model `/v1` reranker**: the multi-tenant server loads one
  `OnnxReranker` and hands every per-vault store a cheap `Arc` handle onto
  it (`RerankerFactory` + `Tenancy::with_reranker` in `tenant.rs`), so all
  tenant vaults share a single ONNX model instead of a copy apiece. Off by
  default (`UNDERCROFT_RERANKER=onnx`; bails without the `onnx` feature). See
  [docs/MULTI_TENANCY.md](docs/MULTI_TENANCY.md).
- **Full sharded LoCoMo benchmark**: the reranker lifts LoCoMo R@10
  **94.6 → 97.68** (1936/1982), summed exactly across 5 conversation-shards.
  RESULTS.md + the landing benchmark bars updated. `undercroft-bench locomo`
  gained `--skip`, conversation-scoped `--limit`, and machine-readable
  `LOCOMO_RAW`/`LME_RAW` numerator lines so sharded runs sum with no rounding
  drift.
- **No LongMemEval reranker row (deliberate)**: the MiniLM baseline is
  already saturated at 99.4% (497/500), so a second stage can only move it
  ≤0.6 pts — not worth the multi-hour run. Documented as a footnote rather
  than a row.

## v0.15.0 — IVF inverted lists & PQ scan-path fixes (done)

- **IVF** partitions the PQ codes (`nlist ≈ √N` coarse centroids, probe the
  nearest quarter — recall tracks the probed fraction and a quarter is exact
  parity: 99.6%/99.1% R@5 at N=20k/50k). Codes clustered on disk by list;
  self-healing, doubling-triggered retrain, in-place migration.
- Benchmarking it exposed three scan-path costs, all fixed: random-access row
  layout → clustered `(list, seq)`; per-search coherence join → event-driven
  verification; per-row `JOIN drawers` in the scan → codes-only scan with
  delete-time purge. **Flat PQ itself gained ~45%** (23.9 → 34.4 q/s at 20k,
  10.1 → 14.8 at 50k, within-run); IVF adds +7–11% on top, growing with N.
- `UNDERCROFT_RETRIEVAL=pq|hnsw` wired through the CLI and multi-tenant `/v1`
  (was bench-only); `UNDERCROFT_IVF_MIN` / `UNDERCROFT_IVF_NPROBE` /
  `set_ivf`; bench `synth --queries` sampling.

## v0.16.0 — ColBERT late interaction (done)

- The core-count-independent second stage: drawers encoded once at ingest
  into int8 per-token matrices, one query forward + MaxSim rescore at
  search. **LoCoMo 94.6 → 96.77% R@10 at a flat 92.7 ms/query** (tract,
  colbertv2.0) — same on 4 cores or 24, vs the cross-encoder's 97.68% at
  many-core prices. `UNDERCROFT_RERANKER=colbert`, models user-supplied
  (fixed-shape ONNX exports; recipe in RETRIEVAL_SCALING).
- Sealed vaults AEAD-seal every matrix under a distinct `/tok` AAD domain —
  the **first encrypted-at-rest derived store** (rescore stores can be
  sealed; plaintext prefilters remain hmac-only).

## v0.17.0 — Sealed-tier encrypted-at-rest index (done)

- Sealed vaults run the PQ/IVF prefilter: rows/codebook/centroids
  AEAD-sealed (`/pq` AAD domain, list ids never in clear), search decrypts
  once per open into a ~52 B/drawer RAM cache and scans there. **Sealed
  search 2.1 → 33.4 q/s at N=20k (×16), 1.1 → 11.8 at 50k (×11)** — parity
  with the plaintext index; encryption is no longer a query-time cost.
  Invariant test strengthened (no plain codes, undecodable metadata,
  baseline-agreeing results across cache rebuilds).

## v0.18.0 — Portable derived artifacts & token backfill (done)

- Restore economics tiers 1–2: `/v1` export bundles carry token matrices as
  content-addressed artifacts (`tok = {model, b64}`, re-sealed under the
  destination vault on import — restore is a copy, not one transformer
  forward per drawer); `repair --tokens` backfills artifact-less palaces in
  bounded batches while searches serve at fusion quality and climb.

## v0.19.0 — Atomic audit chain (done)

- The committed chain head lives in `chain_meta` and advances inside the
  same SQLite transaction as the data + audit row at every mutation site;
  the manifest is a lagging out-of-database rollback anchor, reconciled at
  open (crash ⇒ silent fast-forward, rollback/fork ⇒ `ManifestTampered`).
  A power loss is no longer a false tamper alarm; a restored old database
  still alarms. Both crash states test-simulated.

## v0.20.0 — Token-store PQ & LUT MaxSim (done)

- Late-interaction matrices PQ-compress **8.2×** (16 B/token; ~150-token
  drawer 19.8 KB → 2.4 KB) at −0.2 pts on LoCoMo (96.57%, gate ≥96.5% met).
  Codebook trains from the vault's own tokens, persists sealed, repacks
  in-place; MaxSim scores v2 via per-query-row dot LUTs; punctuation rows
  pruned at encode; artifacts still export as universal v1.

## v0.21.0 — ColBERT forwards on ONNX Runtime (done)

- `OrtColbert` in `undercroft-embed-ort`: same fixed-shape exports, framing,
  and env as the tract encoder, forwards on ORT. LoCoMo search 96.7 →
  **70.3 ms/q** (tok-PQ LUT), ingest 3.3×, recall gate met and
  runtime-invariant (int8 path identical 1918/1982). Unmasked the v0.20
  LUT win (+4 ms under tract → −11 ms under ORT) and corrected the
  estimate: the query forward was ~11 ms of search, the residual ~70 ms/q
  is store-side — the next lever.

## v0.22.0 — Unified PQ cache, HNSW ef-scaling, MUVERA note (done)

- hmac-only PQ scan moved onto the sealed tier's load-once RAM cache:
  measured **parity within run-to-run noise** (the loaded-host win didn't
  reproduce) — kept for the single code path.
- HNSW recall collapse root-caused (fixed `ef_search=100` beam under a
  ≥256-candidate request) and fixed with corpus-scaled `ef`: R@5
  71.7→**96.3%** at N=50k, LoCoMo parity with the scan.
- MUVERA/FDE research note in RETRIEVAL_SCALING — the "beyond MaxSim"
  candidate, deferred below multi-million-drawer scale.

## v0.23.0 — MUVERA FDE candidate generation (done)

- Token-aware candidates through fixed-dimensional encodings
  (`UNDERCROFT_RETRIEVAL=fde`): seed-deterministic construction, sealed
  `drawer_fde` rows + `fde_meta` params, transformer-free backfill, shared
  query forward. Measured: LoCoMo R@10 **identical** to fusion (1913/1982)
  at **52.9 vs 70.3 ms/q (−25%)**; mechanics at N=2k/50k/200k: exact
  top-10 ⊆ FDE top-100 = **100%** at every size, 38–40× below exact cost.

## v0.24.0 — Bounded-RAM FDE tier (done)

- FDE rows PQ-compress 32× event-driven (codebook sealed in `fde_meta`,
  one-pass repack); containment held **perfect** through compression at
  N=2k/50k/200k, ADC scan ~8× faster, LoCoMo gate identical (1913/1982,
  fourth consecutive configuration). IVF over FDE space measured
  net-negative (containment loss + O(N·nprobe) filter cost) and
  deliberately not shipped; the pack format reserves its list field.

## v0.25.0 — Multi-tenant orchestrator (done)

- `undercroft-orchestrator`: the separate optional control plane from
  [docs/MULTI_TENANCY.md](docs/MULTI_TENANCY.md) — instance registry,
  tenant→vault mapping (creds sealed, tokens HMAC-only), the `/t/*`
  routing proxy, and count-verified live migration on the v0.18
  export/import primitive. Pure `/v1` client; engine stays tree-blind.
  24-check e2e against two live engines.

## v0.26.0 — Orchestrator hardening (done)

- Token rotation (revocation-in-the-same-statement), per-tenant
  fixed-window rate limiting (`UNDERCROFT_ORCH_RATE_LIMIT`), deployment
  hardening docs (TLS both hops, secrets hygiene, state backup, the
  documented single-writer stance). e2e grown to 30 checks.

## Next
- **Orchestrator, later**: multi-orchestrator read-replica proxy — when a
  fleet actually needs it (deliberately deferred; single-writer stance
  documented in MULTI_TENANCY.md).
- **Inverted FDE tier** (list-grouped RAM slices, no per-row membership
  test) — the correct sub-linear construction, pays past ~10⁶ drawers.
- **Sealed-tier page-level decryption** (research): decrypt only probed
  lists — matters past multi-million drawers.
- **Retrieval wiring**: env surface for the ort backend outside the bench.
- **Durability**: ingest fsync (audit-chain atomicity shipped in v0.19.0).
- **Ecosystem**: key rotation (re-seal under new derived keys); export
  bundles with recipient encryption.

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
