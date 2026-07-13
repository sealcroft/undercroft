# Undercroft — agent guide

Undercroft is a Rust conversion of MemPalace: hardened, local-first AI memory.
Verbatim drawers filed into wings/rooms, stored in isolated **vaults** with
per-vault HKDF-derived keys, XChaCha20-Poly1305 content sealing, and
HMAC-SHA256 integrity tags + a tamper-evident audit chain.

## Layout

- `Cargo.toml` — workspace root
- `crates/undercroft-core` — domain model, chunking, ids, normalization, hashed
  n-gram embedder
- `crates/undercroft-vault` — security layer (keys.rs: master key + HKDF;
  seal.rs: AEAD + HMAC; lib.rs: VaultManager/Vault + manifest + chain)
- `crates/undercroft-store` — per-vault SQLite storage, hybrid search, verify,
  knowledge graph (kg.rs), management surface (manage.rs), remote-index
  integration (remote.rs)
- `crates/undercroft-index` — remote vector backends (Qdrant/Chroma/pgvector)
  as untrusted accelerators; sealed content only, results re-verified locally
- `crates/undercroft-embed-onnx` — feature-gated ONNX embedder (tract);
  excluded from default-members, built via the `onnx-build` compose service
- `crates/undercroft-cli` — `undercroft` binary (main.rs: CLI, mcp.rs: MCP stdio
  server); integration tests in `tests/cli.rs`
- `tests/e2e.sh`, `tests/e2e-backends.sh` — end-to-end suites (run in Docker)

The upstream Python implementation (the MemPalace project) is *not* in
this repo and no longer linked as a fork; its behavior is documented in
docs/PARITY.md. Never reintroduce Python code here.

## Build & test — Docker only

Build and test **inside containers**, not on the host (project policy):

```bash
docker compose run --rm test   # cargo unit + integration tests
docker compose run --rm e2e    # e2e UI/UX suite against the release binary
docker build -t undercroft .    # runtime image
```

## Invariants to preserve (inherited from MemPalace's mission + vault layer)

- Content is stored **verbatim** — never summarize, paraphrase, or lossy-
  compress user data on the write path. Retrieval returns the exact words.
- Local-first, zero external API by default: no telemetry, no phone-home; the
  default embedder is deterministic and offline.
- Drawer ids are deterministic over (wing, room, source, chunk_index,
  normalize_version); re-mining must stay idempotent and append-only — a crash
  mid-operation must leave the existing palace untouched.
- Sealed vaults must never persist plaintext or plaintext-derived indexes
  (including embeddings and FTS) to disk; there are tests asserting this.
- Every write must update the audit chain (`Vault::commit_write`); every read
  must verify the record HMAC before returning data.
- Cross-vault access must fail cryptographically (AAD binds vault id), not
  just logically.
- Vault/wing/room names go through `undercroft_core::validate_name` (path
  traversal guard).

## Conventions

- Rust 2021, workspace-level dependency versions, `thiserror` per-crate error
  enums, `anyhow` only in the CLI.
- Keys live in `SecretKey` (zeroize-on-drop); never `Debug`-print key material.
- Git identity for this repo: compufreq <compufreq@proton.me>.
