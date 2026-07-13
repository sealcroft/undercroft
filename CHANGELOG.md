# Changelog

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
