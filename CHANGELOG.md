# Changelog

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
