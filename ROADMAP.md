# Undercroft Roadmap

Undercroft is the Rust conversion of MemPalace with a hardened memory-management
layer (isolated vaults, XChaCha20-Poly1305 encryption, HMAC integrity). This
roadmap tracks the conversion; the upstream Python roadmap lives in the
[MemPalace repo](https://github.com/MemPalace/mempalace).

## v0.1.0 — Core port + vault layer (done)

- Rust workspace: `undercroft-core`, `undercroft-vault`, `undercroft-store`, `undercroft-cli`
- Domain model port: palace / wings / rooms / drawers, deterministic drawer ids,
  MemPalace-compatible metadata fields, 800/100/50 chunking, normalization
- **Vault layer (new)**: per-vault HKDF-SHA256 key derivation from a master key
  (key file or Argon2id passphrase), XChaCha20-Poly1305 sealed content and
  embeddings, HMAC-SHA256 record tags, append-only audit table + HMAC chain,
  MAC'd manifests, `sealed` / `hmac-only` security levels, `verify` command
- SQLite per-vault storage; hybrid search (hashed n-gram embedding cosine +
  lexical overlap + 30-day-half-life recency)
- CLI: init, vault create/list/status, remember, mine, search, wake-up,
  verify, export, serve-mcp
- MCP stdio server: `undercroft_save`, `undercroft_search`, `undercroft_wake_up`,
  `undercroft_verify`
- Docker-first build + test harness (unit, integration, e2e UI/UX suites)

## v0.2 — Retrieval quality

- Model-based embedder behind the existing `Embedder` trait (ONNX runtime /
  candle; embeddinggemma-class model) with embedder-identity tracking on
  collections, as in MemPalace RFC 001
- FTS5 BM25 candidate pre-filter for `hmac-only` vaults
- Closets (per-file line index) and halls (keyword categories)
- LongMemEval / LoCoMo benchmark harness parity to measure the port honestly

## v0.3 — Miners and layers

- Conversation miner (Claude Code / Codex JSONL transcripts) and sweep
- Full 4-layer wake-up stack (L1 essential-story selection heuristics, L2
  on-demand rooms)
- Knowledge graph (temporal entity-relationship store) on the vault layer

## v0.4 — Ecosystem

- Server backends behind the store trait (pgvector, qdrant) with the same
  vault sealing applied client-side before bytes leave the process
- Auto-save hooks for Claude Code / Codex / Cursor
- Key rotation (re-seal a vault under a new derived key) and vault export
  bundles with recipient encryption

## Legacy Python tree

`mempalace/` (with `Dockerfile.python`, `docker-compose.python.yml`) is the
upstream implementation, kept as the reference during conversion. It will be
removed once v0.3 reaches feature parity for the local-first path.
