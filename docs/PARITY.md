# Parity with upstream MemPalace

Feature-by-feature comparison against `MemPalace/mempalace` (the Python
original this repo was forked from), updated 2026-07-13.

## Ported (Rust equivalent exists)

| Upstream | Undercroft equivalent |
|---|---|
| Palace model (wings/rooms/drawers, verbatim) | `undercroft-core` (same metadata fields, deterministic ids) |
| `sqlite_exact` backend | `undercroft-store` (SQLite system of record) |
| Chroma/Qdrant/pgvector server backends | `undercroft-index` — **sealed client-side** (upstream sent plaintext) |
| Embedder + identity tracking (RFC 001) | `Embedder` trait + per-vault identity enforcement |
| Model embeddings (sentence-transformers) | `undercroft-embed-onnx` (tract, feature-gated, user-supplied model) |
| File miner | `mine --mode files` |
| Conversation miner (`--mode convos`) | `mine --mode convos` |
| Sweep (per-message drawers) | `sweep` (idempotent via keyed fingerprints) |
| Wake-up layers L0/L1 | `wake-up` (identity.txt + essential story) |
| Knowledge graph (temporal, validity windows) | `kg add/query/rel/invalidate/supersede/timeline/stats` |
| Tunnels (cross-wing) | `tunnel create/list/follow/delete/traverse` |
| Hallways (entity co-occurrence) | `hallways` (computed on demand; never persisted) |
| Drawer CRUD, delete-by-source, dup check | `drawer …`, keyed fingerprints |
| Agent diaries + list_agents | `diary write/read/agents` |
| Dedup / stats / taxonomy | `dedup`, `stats`, `taxonomy` |
| Backups | `backup create/list/restore` (verifies before snapshot) |
| Repair | `repair` (fingerprint backfill, re-embed, vacuum, verify) |
| Export / migrate | `export` (JSONL) + `import` (undercroft & mempalace formats) |
| MCP stdio server (~35 tools) | 30 tools (daemon/sync/session tools inapplicable — see below) |
| MCP HTTP team server (`serve`) | `serve-http` (bearer token enforced, `--read-only`) |
| Daemon / jobs / start / stop / wait | `daemon run` + systemd/compose units (`deploy/`) — process management belongs to the OS |
| `tools/render_jsonl.py` | `transcript render` |
| Auto-save hooks (Claude Code/Codex/Cursor) | `hooks/`, `.claude-plugin/hooks/`, `undercroft hooks claude-code` |
| Claude Code plugin (commands/skills/MCP) | `.claude-plugin/` + root `commands/`, `skills/`, `rules/` |
| Benchmarks (LongMemEval harness) | `undercroft-bench longmemeval` (same protocol/metrics) + `synth` CI benchmark |
| Deploy (compose server, systemd) | `deploy/` |
| Docs / examples | `docs/`, `examples/` |

**Security features that exist only here:** vault isolation with per-vault
HKDF keys, XChaCha20-Poly1305 sealing, HMAC record tags, tamper-evident
audit chain, MAC'd manifests, keyed dup fingerprints, token-mandatory HTTP
bind, read-only serving. Upstream stored everything in plaintext.

## Not ported (deliberate, with reasons)

| Upstream | Status |
|---|---|
| Embedded ChromaDB default | Python library; the bundled SQLite store fills this role |
| Milvus backend | gRPC-only client + heavy deployment; opt-in extra upstream. Candidate: REST v2 client |
| LLM refinement pipeline (`llm_refine`, `closet_llm`, local NLP extractors) | Requires an LLM runtime (Ollama etc.); planned — the heuristic extractors it falls back to are ported |
| AAAK dialect compression (`dialect.py`) | Upstream-specific index format tied to the LLM pipeline; closets are represented by drawer line metadata instead |
| `model_eval` benchmark suite (multilingual calibration datasets) | Evaluates the unported LLM extraction models; N/A until that pipeline lands |
| Spellcheck / i18n of CLI output | Low value relative to weight; CLI is English-only for now |
| Website / landing page | Marketing site, not code; README + docs/ serve this repo |
| LoCoMo / ConvoMem / MemBench harnesses | Same protocol as the LongMemEval harness; add dataset adapters to `undercroft-bench` when needed |

## Behavioral differences to know about

- Sealed vaults trade FTS5 indexing for encryption (decrypt-scan search);
  `hmac-only` vaults keep plaintext searchability with integrity tags.
- Remote backends receive sealed content; upstream uploaded plaintext.
- Benchmark numbers with the default hash embedder are not comparable to
  upstream's published model-based numbers — use `--features onnx` with a
  MiniLM-class model for like-for-like conditions.
