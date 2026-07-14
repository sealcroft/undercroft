# Changelog

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
