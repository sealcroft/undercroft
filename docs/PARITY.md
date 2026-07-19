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

## What exists only here (updated for v0.33.0)

Everything below has **no upstream equivalent** — it is original work of
this project, which is why the two codebases share concepts but not code
(and why this project's license is independent of upstream's; see the
"License lineage" section at the end).

**Security layer** (upstream stored everything in plaintext):

- Vault isolation: per-vault SQLite databases with per-vault
  HKDF-SHA256-derived keys (enc/mac/manifest domains) from one master key
  (file or Argon2id passphrase).
- Sealed-at-rest storage: XChaCha20-Poly1305 over content *and*
  embeddings *and* every derived artifact (ColBERT token matrices, PQ
  code rows + codebooks + IVF centroids, MUVERA FDE rows + params), each
  under its own AAD domain bound to vault + record id — cross-vault
  replay fails cryptographically.
- Integrity: HMAC-SHA256 tag on every drawer, KG entity/triple, and
  tunnel; a tamper-evident audit chain advancing **inside the same
  transaction** as each write; a MAC'd manifest as an out-of-database
  rollback anchor with open-time crash-vs-rollback reconciliation.
- Durability: WAL + `synchronous=FULL` pinned, fsynced manifest anchor
  (atomic rename + directory sync), fsynced key material; bulk ingest
  batches whole transactions (measured ~55× fewer disk syncs).
- **Key rotation** (`vault rotate`): fresh derived keys, every sealed
  blob re-encrypted byte-exact and every tag/chain re-keyed in one
  transaction; crash-safe at any instant via a two-phase manifest swap.
- **Recipient-encrypted export bundles** (`bundle keygen`,
  `export --to`): X25519 ephemeral-static → HKDF → XChaCha20-Poly1305 —
  a backup never exists in plaintext.
- Keyed duplicate fingerprints, token-mandatory non-loopback HTTP bind,
  per-vault request assertions, read-only serving mode.

**Retrieval stack beyond upstream's cosine search:**

- Hybrid semantic + lexical (BM25) + recency fusion with typo tolerance.
- Optional ONNX embedders on two runtimes (pure-Rust tract, or ONNX
  Runtime at ~2.5×/forward with int8) selected by env at runtime.
- Cross-encoder reranking (measured LoCoMo R@10 94.6 → 97.7%).
- ColBERT late interaction: encode-at-ingest token matrices
  (PQ-compressed ~16 B/token), one query forward + MaxSim at search
  (~96.5–96.8% at a flat ~70–93 ms/q independent of core count).
- Bounded-RAM candidate tiers: PQ/IVF prefilter (~48 B/vector, recall
  flat in corpus size, sealed-vault-capable) and MUVERA FDE token-aware
  candidates (recall measured identical to fusion at −25% latency, rows
  PQ-compressed 32×).
- Every number above is measured and reproduced in
  [benchmarks/RESULTS.md](https://github.com/compufreq/undercroft/blob/main/benchmarks/RESULTS.md)
  and [RETRIEVAL_SCALING.md](https://github.com/compufreq/undercroft/blob/main/docs/RETRIEVAL_SCALING.md).

**Multi-tenancy & fleet operation:**

- Versioned `/v1` REST engine: per-vault assertions, external
  embeddings, dedup-refresh, lossless export/import (vectors + token
  artifacts ride along — restore is a copy, not a re-embed).
- `undercroft-orchestrator`: a separate control plane (instance registry
  with sealed credentials, HMAC-only tenant tokens shown once, routing
  proxy with subpath allowlist, token rotation, per-tenant rate limits,
  count-verified live migration) — the engine never links it.

**Operations:**

- Opt-in, metadata-only observability: Prometheus `/metrics`, OTLP
  traces (with header auth), structured logs, live SSE, the Palace
  Monitor UI, and a full Grafana/Alertmanager/Loki/Tempo deploy stack
  with a tamper runbook. Zero telemetry deps in default builds.
- Scenario-driven [agents implementation guide](https://compufreq.github.io/undercroft/docs/agents.html)
  covering every deployment shape with the complete tool/route/env
  reference.

**Also only here:** Weaviate backend; sealed-client remote indexing (all
five backends receive ciphertext; upstream uploaded plaintext); zstd
compress-then-encrypt; int8 embedding quantization; deterministic
offline hash embedder as the default.

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

## License lineage

Upstream MemPalace is Python, published under the MIT License. Undercroft
is a from-scratch Rust implementation of the *concepts* documented in
this file and **contains no MemPalace source code** — the two projects
share behavior specifications, not expression. Undercroft is therefore
licensed independently, under the
[Business Source License 1.1](https://github.com/compufreq/undercroft/blob/main/LICENSE)
(free use including production, one hosted/embedded non-compete
carve-out, automatic conversion to MPL 2.0 four years after each
release). The MIT notice for MemPalace's conceptual heritage is
preserved in [NOTICE](https://github.com/compufreq/undercroft/blob/main/NOTICE).
