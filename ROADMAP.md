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

## Next

- **Retrieval quality**: cross-encoder reranker over the top-k (ONNX,
  the next accuracy lever — targets the residual preference/paraphrase
  gap); re-measure the MiniLM rows under BM25.
- **Scale**: L2 on-demand room loading heuristics; ANN index (HNSW) atop
  the warmed cache for very large palaces.
- **v0.8 — Ecosystem**: key rotation (re-seal under new derived keys);
  export bundles with recipient encryption
