# Changelog

## 0.15.0 — IVF inverted lists & the PQ scan-path fixes

IVF partitioning on top of the v0.14.0 PQ codes — and, more consequentially,
the three structural scan-path costs that benchmarking it exposed and removed.
Net effect (synthetic corpus, hmac-only, within-run comparisons): **flat PQ
~45% faster at N=20–50k** (23.9 → 34.4 q/s at 20k, 10.1 → 14.8 at 50k) with
IVF adding **+7–11% on top at exact recall parity** (99.6%/99.1% R@5), a share
that grows with corpus size — the probed scan is the only query cost that
scales with N.

- **IVF inverted lists** (`pqidx.rs` + `CoarseQuantizer` in `pq.rs`):
  `nlist ≈ √N` deterministic k-means centroids partition the corpus; a query
  ADC-scans the `nprobe` nearest lists. Non-residual — codes are unchanged;
  probes that return fewer than `k` rows widen to the flat scan, so IVF can
  narrow the candidate set but never empty it. On by default above
  `UNDERCROFT_IVF_MIN` (8192, `off` restores flat), probe count via
  `UNDERCROFT_IVF_NPROBE` (default `nlist/4` — recall tracks the probed
  *fraction*: 3% → 68.7%, 11% → 86.9%, ~25% → parity). Partitions persist in
  `pq_meta`, self-heal, and retrain when the corpus doubles past their
  training size. hmac-only vaults only, unchanged invariant.
- **Scan-path fixes** (each exposed by a measured sweep, each re-measured):
  codes physically clustered `WITHOUT ROWID, PRIMARY KEY (list, seq)` — a
  probed list is one sequential range scan, not per-row B-tree fetches
  (which had made a 23%-fraction probe *slower* than the flat scan);
  coherence verification is **event-driven** (first search after open or
  after a failed encode — never per query; the guard join was costing more
  than the scan it guarded); the ADC scan reads `drawer_pq` alone
  (`delete_drawer` purges its code row; the per-row `JOIN drawers` existed
  only for delete-orphans, which hydration filters anyway). v0.14.0 tables
  migrate in place.
- **CLI + `/v1` wiring**: `UNDERCROFT_RETRIEVAL=pq|hnsw` now works in the
  `undercroft` binary (search / serve-mcp / daemon) and per-tenant in the
  multi-tenant server — previously bench-only. `hnsw` requires the new cli
  `hnsw` pass-through feature and errors clearly without it. +5 e2e checks
  including the sealed-vault no-PQ-tables invariant on disk.
- **Bench**: `synth --queries N` caps the query phase to an even sample so
  large-N sweeps finish in minutes; recall is reported over the sampled
  queries.
- Docs: RETRIEVAL_SCALING / RESULTS "every lever" / the public retrieval
  page updated with the full fix ladder and final tables.

## 0.14.0 — Retrieval performance & scaling

The retrieval-performance track: every configurable lever measured end to end
(LoCoMo + synthetic corpora, 24-core host, in Docker), and the expensive ones
retired. Headline: the optional cross-encoder reranker drops **16.6 s → 101–327
ms per query at ~98% R@10**, and large hmac-only corpora get a bounded-RAM
on-disk ANN prefilter. Everything is opt-in; default search behaviour and the
default build are unchanged.

- **Reranker latency, step by step** (302-QA LoCoMo subset, R@10 ≈98%
  throughout): rayon-parallel scoring across cores (16.6 s → 694 ms) →
  `UNDERCROFT_RERANK_TOP_N` is now a true rerank-pool cap (accuracy plateaus at
  ≈20; a real latency knob) → `Reranker::score_batch` becomes the whole-pool
  trait interface so the backend owns parallelization → ONNX Runtime backend +
  int8 models take top_n=20 to **327 ms** and top_n=5 to **101 ms**.
- **New `undercroft-embed-ort` crate**: an ONNX Runtime inference backend
  (embedder + reranker) as an opt-in alternative to the pure-Rust tract
  default (~2.5× faster per forward, identical scores; C++ dependency — see
  the `ort-build` compose service). Session pool sized to cores
  (`UNDERCROFT_ORT_POOL`; `pool=1` = batched mode for few-core boxes). int8
  quantized models (4× smaller files, user-supplied, no code change) attack
  the memory-bandwidth bound; ingest embedding drops 24 s → ~5 s.
- **On-disk Product-Quantization prefilter** for hmac-only vaults: 48-byte PQ
  codes per drawer (`drawer_pq`) + a ~400 KB codebook (`pq_meta`), incremental
  encode on write, count-mismatch self-heal on open. Recall is *flat in corpus
  size* (98.6% at N=20k → 98.9% at N=50k) with codebook-only RAM, while
  in-memory ANN recall collapses untuned. Opt-in via
  `PalaceStore::set_pq(true)` (bench: `UNDERCROFT_RETRIEVAL=pq`). **Sealed
  vaults are untouched** — the no-plaintext-derived-index-on-disk invariant
  holds and is test-asserted; CLI wiring is a follow-up.
- **Experimental in-memory HNSW prefilter** (`hnsw` feature, off by default):
  fastest option measured (378 q/s at N=50k) but O(corpus) RAM and recall
  needs `ef`/over-fetch scaling with N — kept as a raw-speed option, RAM-only,
  never persisted.
- **Multi-tenant `/v1` shared-model reranker**: the tenant server loads one
  ONNX model and hands every per-vault store an `Arc` handle
  (`Tenancy::with_reranker`), closing the v0.13.0 follow-up.
- **Benchmarks**: full sharded LoCoMo reranker run — R@10 **94.6 → 97.68**
  (1936/1982); conversation-scoped `--skip`/`--limit` sharding +
  machine-readable `LOCOMO_RAW`/`LME_RAW` numerator lines; per-phase
  `LOCOMO_TIMING` (ingest vs search); `--backend` for measuring remote
  vector backends (confirmed idle untrusted accelerators — never a latency
  or accuracy lever).
- **Docs**: `docs/RETRIEVAL_SCALING.md` (architecture + every measured
  number + the IVF/ColBERT plan), the public "Retrieval, scoring & scaling"
  site page, `docs/MULTI_TENANCY.md`, and the `benchmarks/RESULTS.md`
  "every lever" section with scenario recipes.
- `.gitattributes` forces LF checkout (Windows clones broke bind-mounted
  scripts inside the Docker test containers).

## 0.13.0 — Cross-encoder reranker

An optional second retrieval stage. After hybrid search's cosine+BM25 fusion
ranks a candidate pool, a cross-encoder re-scores the top-N with the full
`(query, passage)` pair — the interaction a bi-encoder embedding can't capture —
and re-orders them before the final `limit` cut. Off by default; when unset,
search behaviour is byte-for-byte unchanged.

- **`Reranker` trait** (`undercroft-core`) + **`OnnxReranker`**
  (`undercroft-embed-onnx`, under the existing `onnx` feature) — reuses the
  tract/tokenizer machinery, pair-encodes, reads the relevance logit, sigmoids.
  Model is **user-supplied**: `UNDERCROFT_RERANK_MODEL` / `_TOKENIZER` +
  `UNDERCROFT_RERANKER=onnx`. `UNDERCROFT_RERANK_TOP_N` (default 50) bounds latency.
- Wired into `search`, `serve-mcp`, the daemon, and the `longmemeval`/`locomo`
  benchmark harness. Pairs with either embedder (hash or ONNX).
- **Targets BERT-family cross-encoders** (`cross-encoder/ms-marco-MiniLM-L-6-v2`):
  tract 0.22 can't run DeBERTa rerankers (mxbai-rerank hits an unsupported `Sign`
  op), so that's the shipped default.
- **Directional lift** (subset smoke, hash embedder + ms-marco reranker, real
  data): LongMemEval-S R@5 **98.3 → 100.0** (60-question subset), LoCoMo R@10
  **94.6 → 97.2** (full 1,982 QA). The full sharded LongMemEval-500 +
  MiniLM-embedder matched-model run and the landing headline bars are a
  follow-up; the multi-tenant `/v1` reranker pairs with the shared-model item.

## 0.12.0 — Full observability & alerting stack

Metrics were already there; this turns `deploy/observability/` into the full
operability picture — **logs, traces, and alerting** — and adds a tamper
runbook. No API or on-disk format changes; default (non-telemetry) builds are
unaffected.

- **Distributed traces.** New metadata-only spans on the request/search/save/KG
  hot paths (`undercroft-obs`; zero-dep no-op without `--features telemetry`),
  exported over OTLP to **Tempo**. Spans carry operation, route, and vault id —
  never query text, drawer content, wing/room names, or keys.
- **Alerting.** **Alertmanager** + Prometheus rules: `PalaceTamperDetected`
  (critical, broken out by `surface`), `AuditChainStalled`, `UndercroftDown`,
  `HighSearchLatencyP95`, `HttpServerErrors`, `AuthRejectionsSpike`. Routed to a
  self-contained webhook `alert-sink` (swap in Slack/email/PagerDuty).
- **Logs.** **Loki** + promtail ship Undercroft's structured JSON logs
  (`UNDERCROFT_LOG_FORMAT=json`) — metadata only.
- **Grafana.** Loki/Tempo/Alertmanager datasources; the dashboard gains
  tamper-by-surface, HTTP 5xx, auth rejections, an active-alerts table, logs,
  and traces panels. A `grafana-image-renderer` sidecar enables PNG export.
- **Tamper runbook** (`RUNBOOK.md` + docs) — where it happened, and how to
  confirm (`verify`), mitigate (`--read-only`, preserve evidence), fix (verbatim
  restore from `backup`), and prevent. The alert's `runbook_url` links to it.
- **Fixes surfaced while wiring this up:** the OTLP→Prometheus exporter emitted
  double-`_total` counter names (`without_counter_suffixes`), and OTLP traces
  posted to the base URL instead of `/v1/traces` (404); both fixed. The
  observability compose now initializes the palace before `serve-http`.
- **Site.** Landing gains an "Operate it" section; observability docs gain
  alerting/logs/traces sections with real screenshots.

## 0.11.1 — Palace Monitor fixes

Bug fixes to the Palace Monitor UI (`GET /monitor`), plus a website section
showcasing it with real screenshots. No API or on-disk changes.

- **Archivist now animates.** Search events no longer freeze the archivist in
  its `read` pose (under load it was permanently stuck); filing walks run
  uninterrupted, the walk-cycle bob is fixed (it checked states that never
  existed), and the archivist gently wanders between wings during lulls.
- **Speed slider works.** It now scales the whole simulation tempo instead of
  only the (previously frozen) archivist. The tamper beacon's real-time
  duration stays unscaled.
- **Sound button works.** A confirmation chirp on enable plus throttled soft
  ticks on live save/search events, alongside the existing tamper siren.
- **Drawer tiles grow with writes.** The per-wing grid uses an absolute
  log-scale fill so it visibly fills as a wing accumulates drawers, instead of
  a relative-to-busiest scale that barely moved (and lit all tiles for a
  brand-new wing).
- **Website.** New "Palace Monitor" section on the landing page and screenshots
  in the Observability docs, captured from the monitor connected live to a
  vault filed from the LoCoMo benchmark, including a real `hmac-fail` tamper
  alarm.

## 0.11.0 — Palace Monitor UI

A self-contained pixel-art dashboard served at **`GET /monitor`**, driven
by the v0.10 SSE stream. Opt-in behind `--features telemetry`; the page is
unauthenticated static HTML (no secrets), metadata only, sealed vaults show
aggregates only.

- **Palace Monitor** — a retro game-world view: an archivist files drawers
  into wings as writes land, searches pulse the wings, the audit chain
  stamps on each commit, and an **ambulance beacon** fires on a real tamper.
  Runs in demo mode until you enter the bearer token and pick a vault.
  Fully inlined (no external requests); uses `fetch()` streaming so it can
  send the bearer (`EventSource` can't).
- **Live tamper alarm** — new `hmac-fail` stream event, emitted at every
  HMAC-verify-failure site (drawer/kg/tunnel/manifest), powers the beacon.
- **`GET /v1/vaults`** — lists vault ids for the picker (bearer-gated;
  disabled under per-vault assertions).

## 0.10.0 — Live memory telemetry

Turns the v0.9.0 point-in-time observability into a **live push stream** —
the foundation the Palace Monitor UI will consume. Opt-in behind
`--features telemetry`, default build untouched, metadata/counts only,
sealed vaults expose only aggregates. Additive and non-breaking.

- **SSE stream** — `GET /v1/vaults/{id}/stream` (bearer + per-vault
  assertion) pushes a periodic `sample` frame (aggregate counts) plus
  discrete **event pings** (`drawer-saved`, `drawer-deleted`, `search`,
  `kg-triple`, `chain-commit`) as they happen. Each connection is served
  on its own thread that reads only an in-process broker — never a store —
  so the single-threaded server keeps serving and streaming can never
  touch content. Sealed vaults suppress wing/room names.
- **In-process sampler** — a bounded per-vault ring buffer, filled on a
  tick (default 2s, `UNDERCROFT_SAMPLE_INTERVAL_MS`) but only for vaults
  with an active subscriber, so it costs nothing when nobody is watching.
  Also populates the previously-unset `kg_triples`/`kg_entities`/
  `store_bytes` Prometheus gauges.
- **History backfill** — `GET /v1/vaults/{id}/stats/history?window=N`
  returns the recent samples so a fresh client can draw the past.

## 0.9.0 — Observability & telemetry

An **opt-in** observability layer, off by default with zero extra
dependencies and zero overhead unless built with `--features telemetry`.
Everything reported is metadata and counts only — never drawer content or
key material — and nothing leaves the process unless explicitly pointed
somewhere. Additive and non-breaking.

- **Structured logs.** The pre-existing `eprintln!` diagnostics route
  through one macro; with `telemetry` on they become `tracing` events,
  level via `UNDERCROFT_LOG`, `json` output via `UNDERCROFT_LOG_FORMAT`.
- **Prometheus `/metrics`.** Opt-in via `UNDERCROFT_METRICS=1`, served on
  the bind address behind the existing bearer token (absent otherwise).
  Counters for search / drawer writes+deletes / KG writes / chain commits
  / **HMAC verify failures** (the tamper signal) / HTTP requests / auth
  rejections / vault opens; histograms for search and request latency;
  per-vault gauges for drawer count and audit-chain height.
- **OpenTelemetry export.** Set `UNDERCROFT_OTLP_ENDPOINT` to export traces
  over OTLP/HTTP (unset ⇒ no network egress). Fully synchronous — no async
  runtime is introduced; metrics stay on the Prometheus pull model.
- **New crate `undercroft-obs`** — a shim every instrumented crate depends
  on that compiles to no-ops (and pulls no dependencies) without the
  feature. Enable end-to-end with `--features telemetry` on the CLI.

## 0.8.0 — Multi-tenant server support

`serve-http` becomes a first-class per-tenant memory engine (one vault per
customer), additive and non-breaking — MCP stdio, the `/mcp` HTTP surface,
and single-vault behavior are unchanged.

- **Per-vault request authorization.** Set `UNDERCROFT_ASSERTION_SECRET` and
  every `/v1` request must carry `X-Vault-Assertion: <ts>:<hmac>` where
  `hmac = HMAC-SHA256(secret, "<ts>|<vault_id>")`, verified within ±120s
  with a constant-time compare. An assertion minted for vault A cannot
  authorize vault B. `undercroft assert-header <vault>` mints one.
- **Versioned REST surface** (`/v1`) in the same process, same bearer:
  create/delete vault, stats, save/search/delete drawer, and a lossless
  NDJSON export/import pair (import returns the exact record count) for
  migrating a vault between instances.
- **Externally-supplied embeddings.** A vault created with
  `embedder: external:<name>@<dim>` stores caller-provided vectors, refuses
  writes/searches without one, and enforces the dimension — sealing those
  vectors like internally-computed ones.
- **Semantic dedup-refresh on save.** `dedup_threshold` on a write refreshes
  an existing same-wing/room drawer in place (cosine ≥ threshold, id kept)
  as an audited update, making bulk re-ingestion idempotent.
- **Orchestrated deployment** documented: headless `init` from
  `UNDERCROFT_PASSPHRASE`, key never logged, one instance per tenant (compose
  example in docs/remote-server.md).

## 0.7.2 — BM25 rank fusion (new search default)

- Search now blends cosine with a real **Okapi BM25** lexical score
  (IDF-weighted, `k1=1.2`/`b=0.75` length normalization, one-typo
  tolerant) computed over the decrypted, HMAC-verified candidate set,
  replacing the old flat term-overlap fraction. Measured lift with the
  zero-model hash embedder: **LongMemEval-S R@5 90.4% → 95.0%** (the
  paraphrase-heavy preference category 36.7% → 66.7%), **LoCoMo session
  R@10 92.7% → 94.6%** — where the hash embedder now edges past the
  earlier MiniLM run. See benchmarks/RESULTS.md for the full ablation.
- Fusion is selectable with `UNDERCROFT_FUSION`: `bm25` (default),
  `legacy` (the prior term-overlap blend, reproduces the old numbers
  exactly), or `rrf` (reciprocal-rank fusion — scale-free but benchmarks
  below bm25). Fusion only re-ranks already-verified candidates; every
  security guarantee is unchanged, and it is embedder- and
  security-level-independent.

## 0.7.1 — FTS5 BM25 prefilter for hmac-only vaults

- hmac-only vaults now carry an external-content FTS5 index over drawer
  content (trigger-maintained through upsert/update/delete/dedup/restore,
  rebuilt on open if missing or stale). Searches over palaces of 2048+
  drawers prefilter candidates to the BM25 top-K before the usual
  HMAC-verify + hybrid re-rank; if FTS matches nothing the full scan runs
  instead, so semantic-only recall is preserved. Tune or disable with
  `UNDERCROFT_FTS_PREFILTER_MIN` (a number, or `off`).
- Sealed vaults are unchanged: no plaintext-derived index is ever created
  (test-asserted), search remains decrypt-scan by design.

## 0.7.0 — Measured benchmarks, Weaviate, compressed storage

- First measured benchmark results, in-repo (benchmarks/RESULTS.md), with
  the zero-model hash embedder: LoCoMo session R@10 92.7% (beats
  upstream's published raw and hybrid), LongMemEval-S R@5 90.4% (6.2 pts
  under upstream's model-based raw; gap isolated to the
  single-session-preference type).
- Weaviate backend (REST + GraphQL, vectorizer:none) — fifth live-tested
  remote index; PUT-vs-POST upsert semantics handled.
- Storage growth control: zstd compress-then-encrypt for sealed content
  (legacy records stay readable) and int8 embedding quantization with
  per-vector scale (4x smaller, cosine drift < 0.1%), both test-covered.


## 0.6.0 — Benchmark adapters + in-process vector cache; PARITY complete

- `undercroft-bench locomo|convomem|membench`: adapters for the remaining
  three upstream benchmarks (session / message / turn-level evidence
  recall, same protocols as the Python harnesses), fixture-tested so the
  scoring is trustworthy before any dataset is downloaded.
- `PalaceStore::warm_embedding_cache`: decrypt-once in-memory vector cache
  for long-running modes (serve-mcp / serve-http / daemon), kept coherent
  across upsert/delete/repair — fills embedded ChromaDB's in-process index
  role without persisting anything plaintext-derived.
- docs/PARITY.md "not ported" list is now empty.


## 0.5.1 — Memory-extraction eval + CLI localization

- `undercroft-bench model-eval memories`: SQuAD-style token-F1 with greedy
  one-to-one alignment (threshold 0.5, CJK-aware per-character tokens);
  reports match P/R/F1, mean token-F1, and type accuracy.
  `extract_memories` added to undercroft-llm.
- CLI result strings localized in the 9 model_eval dataset languages
  (de/es/fr/hi/it/ko/pt/ru/zh) via UNDERCROFT_LANG, English default and
  fallback; placeholder-preservation enforced by tests. Errors/help stay
  English (exit codes are the scripting contract).


## 0.5.0 — Final parity gaps closed

- Milvus backend (RESTful v2, standalone) in undercroft-index — all four
  remote backends now tested live in compose.
- undercroft-llm crate: local-runtime client (Ollama + OpenAI-compatible);
  `undercroft refine` extracts entities and KG facts from drawers (opt-in
  via UNDERCROFT_LLM_URL; verbatim content never modified).
- model_eval restored: multilingual datasets (10 languages) +
  `undercroft-bench model-eval calibration|entities [--lang]`.
- Closets: `undercroft closets` + `undercroft_get_closet_index` MCP tool —
  deterministic compact index (the AAAK port), computed on demand.
- Typo-tolerant search: Levenshtein-1 fuzzy term matching in the lexical
  scorer (spellcheck port).
- mdBook documentation site in website/ (`docker compose run --rm site`).


## 0.4.0 — Ecosystem parity: benchmarks, team server, integrations

- `undercroft-bench`: LongMemEval-protocol harness (session R@k, NDCG@k,
  per-type breakdown) + deterministic synthetic benchmark wired into CI.
- `serve-http`: MCP over HTTP for shared team servers — bearer token
  mandatory on non-loopback binds, `--read-only` mode, `/healthz`.
- `daemon run` (periodic transcript sweep), `transcript render`,
  `import` (undercroft + mempalace export formats).
- Recreated ecosystem directories natively: `deploy/` (compose server,
  systemd units), `.claude-plugin/` (commands, hooks, skills, MCP),
  `hooks/`, `commands/`, `skills/`, `rules/`, `integrations/`, `docs/`
  (incl. PARITY.md), `examples/`, `.devcontainer/`, SVG logo.


## 0.3.0 — Remote backends + pluggable embedders

- Remote vector indexes (Qdrant, Chroma, pgvector) as untrusted search
  accelerators: sealed content uploaded, candidates HMAC-verified and
  re-ranked locally; `index push/status`, `search --backend`.
- Pluggable embedders with per-vault identity tracking; ONNX
  sentence-embedder crate (tract, feature-gated).
- Compose services + backends-e2e suite against real servers.


## 0.2.0 — Python removal + feature parity port

- Removed the legacy Python implementation and all Python tooling; the Rust
  workspace is now the only implementation.
- Ported: knowledge graph (temporal triples with validity windows),
  conversation mining (Claude Code / Codex JSONL transcripts) + sweep,
  drawer management, agent diaries, hallways/tunnels navigation, dedup,
  stats, backups, repair, hooks output, expanded MCP tool surface.

## 0.1.0 — Rust conversion + vault layer

- Rust workspace: undercroft-core / undercroft-vault / undercroft-store /
  undercroft-cli (fork of MemPalace, Python).
- New hardened memory-management layer: isolated vaults, per-vault HKDF key
  derivation, XChaCha20-Poly1305 sealed content, HMAC-SHA256 integrity tags,
  tamper-evident audit chain, sealed / hmac-only levels.
- Docker-first build + test harness (unit, integration, e2e UI/UX suites).
