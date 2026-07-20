# Undercroft — agent guide

Undercroft is a Rust conversion of MemPalace: hardened, local-first AI memory.
Verbatim drawers filed into wings/rooms, stored in isolated **vaults** with
per-vault HKDF-derived keys, XChaCha20-Poly1305 content sealing, and
HMAC-SHA256 integrity tags + a tamper-evident audit chain.

## Layout

- `Cargo.toml` — workspace root (11 crates; `undercroft-embed-onnx` and
  `undercroft-embed-ort` excluded from default-members — heavy ML deps,
  built explicitly)
- `crates/undercroft-core` — domain model, chunking, ids, normalization, hashed
  n-gram embedder (`embed.rs`: `Embedder` trait + `HashEmbedder`), reranker
  trait (`rerank.rs`: `Reranker`), late-interaction trait + MaxSim + int8
  token packing (`late.rs`: `LateInteraction`), conversation parsing, entities
- `crates/undercroft-vault` — security layer (keys.rs: master key + HKDF;
  seal.rs: AEAD + HMAC; lib.rs: VaultManager/Vault + manifest-as-rollback-
  anchor + pure chain arithmetic + key rotation primitives
  (rotation_candidate, byte-exact reseal_at_rest, two-phase
  vault.json.next staging, keycheck marker); bundle.rs:
  recipient-encrypted export bundles (X25519 ephemeral-static → HKDF →
  XChaCha20-Poly1305); at-rest AAD domains: content, `/emb`, `/tok`
  token matrices, `/pq` index artifacts)
- `crates/undercroft-store` — per-vault SQLite storage, hybrid search (cosine +
  BM25 fusion) + optional cross-encoder rerank + ColBERT late-interaction
  stage (latestage.rs: token store, event-driven token-PQ codebook, LUT
  MaxSim), PQ/IVF candidate prefilter for both vault levels (pq.rs primitive,
  pqidx.rs index; both levels scan a load-once RAM code cache), MUVERA FDE
  token-aware candidates (fdeidx.rs; core fde.rs construction; sealed
  `drawer_fde` + `fde_meta`), experimental in-memory HNSW (hnsw.rs, `hnsw`
  feature), transactional audit chain (`chain_meta` + `chain_append`),
  verify, knowledge graph (kg.rs), management surface (manage.rs),
  remote-index integration (remote.rs), in-place key rotation
  (rotate.rs: one-transaction re-seal of every artifact + chain re-key
  over preserved audit bytes, crash-reconciled at open), bulk ingest
  (`upsert_many`: one transaction + one manifest anchor per batch —
  advisory encode paths must never BEGIN or batching breaks)
- `crates/undercroft-obs` — observability shim: no-op + **zero deps** by default;
  under `--features telemetry` brings up `tracing` logs, Prometheus `/metrics`,
  OTLP traces (metadata-only spans), and the live SSE broker
- `crates/undercroft-index` — remote vector backends (Qdrant/Chroma/pgvector/
  Milvus/Weaviate) as untrusted accelerators; sealed content only, re-verified
- `crates/undercroft-llm` — local LLM runtimes (Ollama/OpenAI-compatible) for
  `refine` → KG extraction; no external API by default
- `crates/undercroft-embed-onnx` — feature-gated ONNX embedder, cross-encoder
  reranker, **and** ColBERT late-interaction encoder (tract, pure Rust; two
  fixed-shape plans per ColBERT export — dynamic-axis exports carry ops tract
  rejects); built via the `onnx-build` compose service. Models are
  user-supplied; tract 0.22 runs BERT-family models, **not** DeBERTa rerankers
- `crates/undercroft-embed-ort` — opt-in ONNX Runtime backend (C++ dep;
  `ort-build` compose service): session-pool embedder + reranker + ColBERT
  encoder (late.rs — same exports/env as the tract one), ~2.5× tract per
  forward, int8 model support; pinned `ort = 2.0.0-rc.10`. Wired into the
  CLI via `--features ort` (`UNDERCROFT_EMBEDDER=ort`,
  `UNDERCROFT_RERANKER=ort|colbert-ort`; multi-tenant server shares one
  session pool across vaults)
- `crates/undercroft-cli` — `undercroft` binary (main.rs: CLI; mcp.rs: MCP stdio;
  http.rs/tenant.rs: HTTP + multi-tenant `/v1` incl. management routes
  (drawers list/get/update, taxonomy, verify, rotate); ui.html: the vault
  admin console, `include_str!`'d and served at `GET /ui` on every build;
  monitor.html: the Palace Monitor
  UI, `include_str!`'d and served at `GET /monitor` on telemetry builds);
  integration tests in `tests/cli.rs`
- `crates/undercroft-orchestrator` — `undercroft-orchestrator` binary: the
  optional multi-tenant control plane (docs/MULTI_TENANCY.md) — instance
  registry + tenant→vault map in its own SQLite (engine creds sealed,
  tokens stored as HMACs), `/t/*` routing proxy, `/admin/*` plane,
  count-verified migration. Pure `/v1` client; never linked by the engine
- `crates/undercroft-bench` — LongMemEval/LoCoMo/ConvoMem/MemBench/model-eval
  harnesses (`--features onnx` for model rows; `--skip`/`--limit` sharding)
- `deploy/observability/` — Prometheus + Alertmanager + Loki + Tempo + Grafana
  stack (see its README.md + RUNBOOK.md)
- `website/` — GitHub Pages: `landing/index.html` (custom landing) + mdBook docs
  under `src/`
- `tests/e2e.sh`, `tests/e2e-backends.sh`, `tests/e2e-telemetry.sh`,
  `tests/e2e-orchestrator.sh` — end-to-end suites (run in Docker)
- `docs/AGENTS.md` — the scenario-driven agent implementation guide
  (published as docs/agents.html); its tool/route/env reference must be
  kept in sync when the MCP surface, `/v1` routes, or `UNDERCROFT_*`
  variables change
- `SECURITY.md` (disclosure policy; private vulnerability reporting is
  enabled on the repo), `NOTICE` (MemPalace MIT heritage attribution),
  `LICENSE` (BUSL 1.1 — see Conventions)
- `.github/workflows/release.yml` — on every `v*` tag: five binary
  targets (linux x86_64/arm64 native, macOS Intel cross-compiled on
  macos-latest + Apple Silicon, windows) uploaded to the release with
  sha256, and the multi-arch `ghcr.io/compufreq/undercroft` image
  (per-arch native builds merged into one manifest; index annotations
  carry the package description)

The upstream Python implementation (the MemPalace project) is *not* in
this repo and no longer linked as a fork; its behavior is documented in
docs/PARITY.md. Never reintroduce Python code here.

## Build & test — Docker only

Build and test **inside containers**, not on the host (project policy):

```bash
docker compose run --rm test          # cargo unit + integration tests (176)
docker compose run --rm lint          # rustfmt --check + clippy -D warnings
docker compose run --rm e2e           # e2e UI/UX suite against the release binary (135 checks)
docker compose run --rm orchestrator-e2e  # two engines + orchestrator (30 checks)
docker compose run --rm e2e-telemetry # telemetry build + /metrics gating (16 checks)
docker compose run --rm backends-e2e  # five live vector DBs (47 checks; weaviate
                                      # readiness gates on /v1/schema==200 — it
                                      # answers HTTP before its Raft leader exists)
docker compose run --rm onnx-build    # compile-check the ONNX embedder+reranker feature
docker compose run --rm ort-build    # compile-check CLI with --features onnx,ort
                                      # (CI clippy never sees non-default features —
                                      # clippy ort-gated code here explicitly)
docker compose run --rm site          # build the mdBook docs (mdbook pinned 0.5.4;
                                      # mermaid via vendored website/assets/mermaid.min.js)
docker build -t undercroft .           # runtime image
```

CI runs `cargo fmt --all --check` + `cargo clippy --all-targets -- -D warnings`
(no `--workspace`, so the excluded onnx crate is fmt'd but not clippy'd in CI).
Heavy cargo work: use the `undercroft-target` volume + `CARGO_TARGET_DIR=/build`
(host bind-mounted `target/` SIGBUSes under memory pressure).

## Invariants to preserve (inherited from MemPalace's mission + vault layer)

- Content is stored **verbatim** — never summarize, paraphrase, or lossy-
  compress user data on the write path. Retrieval returns the exact words.
- Local-first, zero external API by default: no phone-home; the default
  embedder is deterministic and offline. Observability is **opt-in** behind
  `--features telemetry` — default builds carry zero telemetry deps and emit
  nothing; when on, signals are **metadata/counts only** (never drawer content
  or keys) and nothing leaves the process unless an endpoint is set.
- Drawer ids are deterministic over (wing, room, source, chunk_index,
  normalize_version); re-mining must stay idempotent and append-only — a crash
  mid-operation must leave the existing palace untouched.
- Sealed vaults must never persist plaintext or plaintext-derived data **in
  clear** on disk: FTS never exists for them; embeddings, PQ code rows and
  codebooks, and ColBERT token matrices are AEAD-sealed under distinct AAD
  domains (search uses decrypt-once RAM caches). Tests assert the at-rest
  bytes; new derived artifacts must follow the same pattern.
- Every write must update the audit chain **atomically with its data**: the
  committed head lives in `chain_meta` and advances via `chain_append` inside
  the same SQLite transaction (the manifest holds a lagging rollback anchor,
  reconciled at open — crash ⇒ fast-forward, rollback ⇒ tamper). Every read
  must verify the record HMAC before returning data.
- Durability is pinned, not assumed: SQLite runs WAL + `synchronous=FULL`
  on both binaries, the manifest anchor is fsynced through an atomic
  rename (+ dir sync), and key material is fsynced at creation. The
  anchor must never run **ahead** of the database — that combination is
  what makes a power loss reconcile as a crash instead of a tamper alarm.
- Cross-vault access must fail cryptographically (AAD binds vault id), not
  just logically.
- Vault/wing/room names go through `undercroft_core::validate_name` (path
  traversal guard).

## Conventions

- Rust 2021, workspace-level dependency versions, `thiserror` per-crate error
  enums, `anyhow` only in the CLI.
- Keys live in `SecretKey` (zeroize-on-drop); never `Debug`-print key material.
- Git identity for this repo: compufreq <compufreq@proton.me>.
- License: **BUSL-1.1** (source-available; rolling 4-year conversion to
  MPL 2.0; `NOTICE` carries the MemPalace MIT heritage attribution).
  Never reintroduce MIT as the project license or publish under it.
- Release flow: full Docker battery (always `--build`) → PR → CI green →
  explicit maintainer approval → merge → tag `vX.Y.Z` → `gh release
  create` (the tag also fires release.yml: binaries + GHCR image) →
  post-merge CI green → Pages live-verified. Version bumps touch
  workspace `Cargo.toml` + `Cargo.lock` (via a Docker `cargo update
  --workspace` — battery images COPY source and never update the host
  lock), `.claude-plugin/plugin.json`, CHANGELOG, ROADMAP, and the
  landing hero release button.
