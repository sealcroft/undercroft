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
| MCP stdio server (~35 tools) | 32 tools (daemon/sync/session tools inapplicable — process management moved to the OS) |
| MCP HTTP team server (`serve`) | `serve-http` (bearer token enforced, `--read-only`) |
| Daemon / jobs / start / stop / wait | `daemon run` + systemd/compose units (`deploy/`) — process management belongs to the OS |
| `tools/render_jsonl.py` | `transcript render` |
| Auto-save hooks (Claude Code/Codex/Cursor) | `hooks/`, `.claude-plugin/hooks/`, `undercroft hooks claude-code` |
| Claude Code plugin (commands/skills/MCP) | `.claude-plugin/` + root `commands/`, `skills/`, `rules/` |
| Benchmarks (LongMemEval harness) | `undercroft-bench longmemeval` (same protocol/metrics) + `synth` CI benchmark |
| LoCoMo / ConvoMem / MemBench harnesses | `undercroft-bench locomo|convomem|membench` — session / message / turn-level evidence recall, same protocols as upstream's harnesses, adapter logic fixture-tested |
| Embedded ChromaDB's in-process index role | Bundled SQLite store is the system of record; `warm_embedding_cache` gives long-running servers (serve-mcp / serve-http / daemon) a decrypt-once in-memory vector cache — the in-process index role, with nothing plaintext-derived persisted |
| Deploy (compose server, systemd) | `deploy/` |
| Docs / examples | `docs/`, `examples/` |

**Capabilities that exist only here:** Weaviate backend; zstd
compress-then-encrypt for sealed content; int8 embedding quantization
(4x smaller vectors); measured benchmark results in-repo
(benchmarks/RESULTS.md).

**Security features that exist only here:** vault isolation with per-vault
HKDF keys, XChaCha20-Poly1305 sealing, HMAC record tags, tamper-evident
audit chain, MAC'd manifests, keyed dup fingerprints, token-mandatory HTTP
bind, read-only serving. Upstream stored everything in plaintext.

## Ported in v0.5.0 (previously listed as gaps)

| Upstream | Undercroft equivalent |
|---|---|
| Milvus backend | `undercroft-index` REST v2 client (`--backend milvus`), tested against live standalone Milvus in compose |
| LLM refinement pipeline (`llm_refine`, `llm_client`) | `undercroft-llm` crate (Ollama + OpenAI-compatible local runtimes) + `undercroft refine` — extracts entities and KG triples from drawers; never touches verbatim content; only runs when `UNDERCROFT_LLM_URL` is explicitly set |
| `model_eval` multilingual datasets + harness | Datasets restored (10 languages × calibration / entity / memory / room tasks); `undercroft-bench model-eval calibration|entities|memories [--lang de]` scores the configured local LLM (accuracy, P/R/F1, and SQuAD-style greedy token-F1 alignment for memories) |
| AAAK dialect / closets (`dialect.py`) | `undercroft closets` + `undercroft_get_closet_index` MCP tool — deterministic compact index (one scannable line per room: counts, date span, key entities, drawer ids); computed on demand, nothing persisted |
| Spellcheck (query typo tolerance) | Levenshtein-1 fuzzy term matching built into the lexical scorer (5+ char terms) |
| Website | Rust-native mdBook site in `website/` reusing docs/ (`docker compose run --rm site`) |

| Memory-extraction eval task | `undercroft-bench model-eval memories` — SQuAD-style token-F1 with greedy one-to-one alignment (threshold 0.5), CJK-aware tokenization; reports match P/R/F1, mean token-F1, type accuracy |
| i18n (`mempalace/i18n`) | CLI result strings localized in the 9 dataset languages (de/es/fr/hi/it/ko/pt/ru/zh) via `UNDERCROFT_LANG`, English default + fallback; errors/help stay English by design (exit codes are the script contract) |

## Not ported

Nothing remains. The one permanent role-replacement worth restating:
embedded ChromaDB is a Python library and cannot be linked from Rust — its
*roles* (embedded zero-config store + in-process vector index) are filled by
the bundled SQLite store and the in-memory embedding cache respectively.

## Behavioral differences to know about

- Sealed vaults trade FTS5 indexing for encryption (decrypt-scan search);
  `hmac-only` vaults keep plaintext searchability with integrity tags and,
  above ~2k drawers, an FTS5 BM25 prefilter (tunable via
  `UNDERCROFT_FTS_PREFILTER_MIN`, `off` to disable) that narrows the
  candidate scan without changing final scoring.
- Remote backends receive sealed content; upstream uploaded plaintext.
- Benchmark numbers with the default hash embedder are not comparable to
  upstream's published model-based numbers — use `--features onnx` with a
  MiniLM-class model for like-for-like conditions.
