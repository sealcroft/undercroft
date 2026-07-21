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

## v0.8.0 — Multi-tenant server (done)

- `serve-http` is now a first-class per-tenant memory engine (vault =
  tenant), additive over the team-server mode: per-vault `X-Vault-Assertion`
  HMAC authorization, a versioned `/v1` REST surface (vault lifecycle +
  drawer ops + lossless export/import migration), caller-supplied
  (`external:<name>@<dim>`) embeddings, dedup-refresh on save, and an
  orchestrated one-instance-per-tenant deployment path.

## v0.9.0 — Observability & telemetry (done)

- Opt-in observability behind `--features telemetry` (off by default, zero
  extra deps / zero overhead): `tracing` structured logs (`UNDERCROFT_LOG`,
  `UNDERCROFT_LOG_FORMAT`), a Prometheus `/metrics` endpoint
  (`UNDERCROFT_METRICS=1`, loopback + bearer-gated), and OTLP trace export
  (`UNDERCROFT_OTLP_ENDPOINT`, unset ⇒ no egress). Metadata/counts only;
  the headline signal is `undercroft_hmac_verify_failures_total` (tamper on
  read). New `undercroft-obs` shim crate; fully synchronous (no tokio).
  First stage of the Operability track below.

## v0.10.0 — Live memory telemetry (done)

- The point-in-time observability becomes a **live push stream**: an SSE
  endpoint `GET /v1/vaults/{id}/stream` pushing periodic aggregate
  `sample` frames plus discrete event pings (`drawer-saved`,
  `drawer-deleted`, `search`, `kg-triple`, `chain-commit`) as they happen,
  a bounded per-vault sampler ring buffer (tick only for watched vaults),
  and a `stats/history` backfill. Each connection runs on its own thread
  reading only the in-process broker — never a store — so the sync server
  keeps serving and streaming can't touch content. Sealed vaults suppress
  wing/room names. Opt-in (`--features telemetry`). Second stage of the
  Operability track; feeds the v0.11 Palace Monitor UI.

## v0.11.0 — Palace Monitor UI (done)

- A self-contained pixel-art dashboard at `GET /monitor` (unauthenticated
  static page, telemetry build only), driven by the v0.10 SSE stream: an
  archivist files drawers into wings as writes land, searches pulse the
  wings, the chain stamps on commits, and an **ambulance beacon** fires on
  a real HMAC-verify failure — powered by a new `hmac-fail` stream event
  wired to every tamper site. Demo mode until the bearer + vault are
  entered; uses `fetch()` streaming (so it can send the bearer, unlike
  `EventSource`); fully inlined, same-origin only. Adds `GET /v1/vaults`
  (bearer-gated; disabled under per-vault assertions) for the picker.
  Final stage of the Operability track.

## v0.11.1 — Palace Monitor fixes (done)

- Fixes to the monitor UI after live testing: the archivist now animates
  (searches no longer freeze it; walk-cycle and idle wander restored), the
  speed slider scales the whole sim, the sound toggle gives audible feedback,
  and per-wing drawer tiles grow on an absolute log scale as writes land.
  Adds the website "Palace Monitor" section with real screenshots. No API or
  on-disk changes.

## v0.12.0 — Full observability & alerting stack (done)

- Turns `deploy/observability/` into the full picture: **Alertmanager** +
  Prometheus rules (headline `PalaceTamperDetected`, by `surface`), **Loki**
  logs, **Tempo** traces, an expanded Grafana dashboard, and a
  `grafana-image-renderer` for PNG export. Adds metadata-only trace **spans**
  to the Rust hot paths (zero-dep no-op without telemetry) and a **tamper
  runbook** (confirm/mitigate/fix/prevent). Fixes surfaced en route: exporter
  double-`_total` counter names, and OTLP traces missing the `/v1/traces` path.
  Site gains an "Operate it" section. No API/on-disk changes.

## v0.13.0 — Cross-encoder reranker (done)

- Optional second retrieval stage: a cross-encoder re-scores the fusion-ranked
  top-N candidates by the full `(query, passage)` pair before the final `limit`
  cut. New `Reranker` trait (`undercroft-core`) + `OnnxReranker`
  (`undercroft-embed-onnx`, reusing the tract/tokenizer machinery, pair-encode →
  relevance logit). Feature-gated (`onnx`), model user-supplied via
  `UNDERCROFT_RERANK_MODEL`/`_TOKENIZER` + `UNDERCROFT_RERANKER=onnx`;
  `UNDERCROFT_RERANK_TOP_N` (default 50) bounds latency. **tract 0.22 can't run
  DeBERTa rerankers** (mxbai-rerank was `Sign`-op-rejected) → ships targeting
  the BERT-family `cross-encoder/ms-marco-MiniLM-L-6-v2`. Wired into `search` /
  serve-mcp / daemon / bench. Full sharded benchmark + landing headline bars =
  follow-up; multi-tenant `/v1` reranker = follow-up (with shared-model item).

## v0.14.0 — Retrieval performance & scaling (done)

Every retrieval lever measured end to end; the expensive ones retired.
Reranker query cost **16.6 s → 101–327 ms at ~98% R@10**; bounded-RAM on-disk
ANN for large hmac-only corpora. All opt-in; defaults unchanged.

- **Reranker latency ladder**: rayon-parallel scoring → `RERANK_TOP_N` as a
  true pool cap (knee ≈20) → `score_batch` whole-pool trait interface → new
  **`undercroft-embed-ort`** crate (ONNX Runtime backend, opt-in C++ dep,
  ~2.5× tract per forward, identical scores) with a session pool
  (`UNDERCROFT_ORT_POOL`, `pool=1` = batched) + int8 model support. Ingest
  embedding 24 s → ~5 s.
- **On-disk PQ prefilter** (hmac-only vaults): 48 B codes + ~400 KB codebook,
  incremental encode, self-heal; recall flat in N (98.9% at 50k) with
  codebook-only RAM. `set_pq(true)`; sealed vaults untouched (invariant
  test-asserted). **Experimental in-memory HNSW** (`hnsw` feature): fastest,
  but O(corpus) RAM and needs `ef` scaling — RAM-only, never persisted.
- Remote vector backends measured under load: idle untrusted accelerators
  (by design) — never a latency/accuracy lever.
- Docs: `docs/RETRIEVAL_SCALING.md`, the public "Retrieval, scoring &
  scaling" page, RESULTS.md "every lever" + scenario recipes.

Also closes the v0.13.0 follow-up items:

- **Shared-model `/v1` reranker**: the multi-tenant server loads one
  `OnnxReranker` and hands every per-vault store a cheap `Arc` handle onto
  it (`RerankerFactory` + `Tenancy::with_reranker` in `tenant.rs`), so all
  tenant vaults share a single ONNX model instead of a copy apiece. Off by
  default (`UNDERCROFT_RERANKER=onnx`; bails without the `onnx` feature). See
  [docs/MULTI_TENANCY.md](docs/MULTI_TENANCY.md).
- **Full sharded LoCoMo benchmark**: the reranker lifts LoCoMo R@10
  **94.6 → 97.68** (1936/1982), summed exactly across 5 conversation-shards.
  RESULTS.md + the landing benchmark bars updated. `undercroft-bench locomo`
  gained `--skip`, conversation-scoped `--limit`, and machine-readable
  `LOCOMO_RAW`/`LME_RAW` numerator lines so sharded runs sum with no rounding
  drift.
- **No LongMemEval reranker row (deliberate)**: the MiniLM baseline is
  already saturated at 99.4% (497/500), so a second stage can only move it
  ≤0.6 pts — not worth the multi-hour run. Documented as a footnote rather
  than a row.

## v0.15.0 — IVF inverted lists & PQ scan-path fixes (done)

- **IVF** partitions the PQ codes (`nlist ≈ √N` coarse centroids, probe the
  nearest quarter — recall tracks the probed fraction and a quarter is exact
  parity: 99.6%/99.1% R@5 at N=20k/50k). Codes clustered on disk by list;
  self-healing, doubling-triggered retrain, in-place migration.
- Benchmarking it exposed three scan-path costs, all fixed: random-access row
  layout → clustered `(list, seq)`; per-search coherence join → event-driven
  verification; per-row `JOIN drawers` in the scan → codes-only scan with
  delete-time purge. **Flat PQ itself gained ~45%** (23.9 → 34.4 q/s at 20k,
  10.1 → 14.8 at 50k, within-run); IVF adds +7–11% on top, growing with N.
- `UNDERCROFT_RETRIEVAL=pq|hnsw` wired through the CLI and multi-tenant `/v1`
  (was bench-only); `UNDERCROFT_IVF_MIN` / `UNDERCROFT_IVF_NPROBE` /
  `set_ivf`; bench `synth --queries` sampling.

## v0.16.0 — ColBERT late interaction (done)

- The core-count-independent second stage: drawers encoded once at ingest
  into int8 per-token matrices, one query forward + MaxSim rescore at
  search. **LoCoMo 94.6 → 96.77% R@10 at a flat 92.7 ms/query** (tract,
  colbertv2.0) — same on 4 cores or 24, vs the cross-encoder's 97.68% at
  many-core prices. `UNDERCROFT_RERANKER=colbert`, models user-supplied
  (fixed-shape ONNX exports; recipe in RETRIEVAL_SCALING).
- Sealed vaults AEAD-seal every matrix under a distinct `/tok` AAD domain —
  the **first encrypted-at-rest derived store** (rescore stores can be
  sealed; plaintext prefilters remain hmac-only).

## v0.17.0 — Sealed-tier encrypted-at-rest index (done)

- Sealed vaults run the PQ/IVF prefilter: rows/codebook/centroids
  AEAD-sealed (`/pq` AAD domain, list ids never in clear), search decrypts
  once per open into a ~52 B/drawer RAM cache and scans there. **Sealed
  search 2.1 → 33.4 q/s at N=20k (×16), 1.1 → 11.8 at 50k (×11)** — parity
  with the plaintext index; encryption is no longer a query-time cost.
  Invariant test strengthened (no plain codes, undecodable metadata,
  baseline-agreeing results across cache rebuilds).

## v0.18.0 — Portable derived artifacts & token backfill (done)

- Restore economics tiers 1–2: `/v1` export bundles carry token matrices as
  content-addressed artifacts (`tok = {model, b64}`, re-sealed under the
  destination vault on import — restore is a copy, not one transformer
  forward per drawer); `repair --tokens` backfills artifact-less palaces in
  bounded batches while searches serve at fusion quality and climb.

## v0.19.0 — Atomic audit chain (done)

- The committed chain head lives in `chain_meta` and advances inside the
  same SQLite transaction as the data + audit row at every mutation site;
  the manifest is a lagging out-of-database rollback anchor, reconciled at
  open (crash ⇒ silent fast-forward, rollback/fork ⇒ `ManifestTampered`).
  A power loss is no longer a false tamper alarm; a restored old database
  still alarms. Both crash states test-simulated.

## v0.20.0 — Token-store PQ & LUT MaxSim (done)

- Late-interaction matrices PQ-compress **8.2×** (16 B/token; ~150-token
  drawer 19.8 KB → 2.4 KB) at −0.2 pts on LoCoMo (96.57%, gate ≥96.5% met).
  Codebook trains from the vault's own tokens, persists sealed, repacks
  in-place; MaxSim scores v2 via per-query-row dot LUTs; punctuation rows
  pruned at encode; artifacts still export as universal v1.

## v0.21.0 — ColBERT forwards on ONNX Runtime (done)

- `OrtColbert` in `undercroft-embed-ort`: same fixed-shape exports, framing,
  and env as the tract encoder, forwards on ORT. LoCoMo search 96.7 →
  **70.3 ms/q** (tok-PQ LUT), ingest 3.3×, recall gate met and
  runtime-invariant (int8 path identical 1918/1982). Unmasked the v0.20
  LUT win (+4 ms under tract → −11 ms under ORT) and corrected the
  estimate: the query forward was ~11 ms of search, the residual ~70 ms/q
  is store-side — the next lever.

## v0.22.0 — Unified PQ cache, HNSW ef-scaling, MUVERA note (done)

- hmac-only PQ scan moved onto the sealed tier's load-once RAM cache:
  measured **parity within run-to-run noise** (the loaded-host win didn't
  reproduce) — kept for the single code path.
- HNSW recall collapse root-caused (fixed `ef_search=100` beam under a
  ≥256-candidate request) and fixed with corpus-scaled `ef`: R@5
  71.7→**96.3%** at N=50k, LoCoMo parity with the scan.
- MUVERA/FDE research note in RETRIEVAL_SCALING — the "beyond MaxSim"
  candidate, deferred below multi-million-drawer scale.

## v0.23.0 — MUVERA FDE candidate generation (done)

- Token-aware candidates through fixed-dimensional encodings
  (`UNDERCROFT_RETRIEVAL=fde`): seed-deterministic construction, sealed
  `drawer_fde` rows + `fde_meta` params, transformer-free backfill, shared
  query forward. Measured: LoCoMo R@10 **identical** to fusion (1913/1982)
  at **52.9 vs 70.3 ms/q (−25%)**; mechanics at N=2k/50k/200k: exact
  top-10 ⊆ FDE top-100 = **100%** at every size, 38–40× below exact cost.

## v0.24.0 — Bounded-RAM FDE tier (done)

- FDE rows PQ-compress 32× event-driven (codebook sealed in `fde_meta`,
  one-pass repack); containment held **perfect** through compression at
  N=2k/50k/200k, ADC scan ~8× faster, LoCoMo gate identical (1913/1982,
  fourth consecutive configuration). IVF over FDE space measured
  net-negative (containment loss + O(N·nprobe) filter cost) and
  deliberately not shipped; the pack format reserves its list field.

## v0.25.0 — Multi-tenant orchestrator (done)

- `undercroft-orchestrator`: the separate optional control plane from
  [docs/MULTI_TENANCY.md](docs/MULTI_TENANCY.md) — instance registry,
  tenant→vault mapping (creds sealed, tokens HMAC-only), the `/t/*`
  routing proxy, and count-verified live migration on the v0.18
  export/import primitive. Pure `/v1` client; engine stays tree-blind.
  24-check e2e against two live engines.

## v0.26.0 — Orchestrator hardening (done)

- Token rotation (revocation-in-the-same-statement), per-tenant
  fixed-window rate limiting (`UNDERCROFT_ORCH_RATE_LIMIT`), deployment
  hardening docs (TLS both hops, secrets hygiene, state backup, the
  documented single-writer stance). e2e grown to 30 checks.

## v0.27.0 — ONNX Runtime backend in the CLI (done)

- The `ort` cargo feature on `undercroft-cli`: `UNDERCROFT_EMBEDDER=ort`,
  `UNDERCROFT_RERANKER=ort` (batched cross-encoder) and `colbert-ort`
  (late interaction) select ONNX Runtime at runtime — same models and
  env variables as tract, so the measured wins (reranker ~100–160×,
  ColBERT 70.3 ms/q, ingest embed 4–5×) reach real deployments. The
  multi-tenant server shares one session pool across all vaults;
  `ort-build` now compile-checks the CLI with both backends.

## v0.28.0 — Ingest durability (done)

- SQLite pinned WAL + `synchronous=FULL` on both the engine store and
  the orchestrator control plane; manifest anchor fsync'd through an
  atomic rename (+ directory sync); key material fsync'd at creation.
  Completes the durability arc the v0.19.0 chain atomicity started: a
  power loss now always lands in the reconciler's healed crash case,
  never the tamper case.

## v0.29.0 — Key rotation (done)

- `undercroft vault rotate`: fresh salt ⇒ fresh derived keys; every
  sealed blob re-sealed byte-exact (all AAD domains), every tag /
  fingerprint / chain re-keyed, in one transaction with a two-phase
  manifest swap (`vault.json.next` + db `keycheck` marker) — crash-safe
  at any instant, on both vault levels.

## v0.30.0 — Recipient-encrypted export bundles (done)

- `bundle keygen` + `export --to <recipient> --out <file>` +
  `import --identity <keyfile>`: X25519 ephemeral-static → HKDF →
  XChaCha20-Poly1305 sealed bundles; a backup never exists in
  plaintext. Closes the ecosystem track (key rotation + bundles).

## v0.31.0 — Bulk-ingest transaction batching (done)

- `upsert_many`: one transaction (+ one manifest anchor) per batch
  across import/mine/sweep — measured 26 fsyncs for a 200-drawer
  import (0.13/drawer) vs ~7/drawer per-item, ~55× fewer disk syncs,
  chain + verify intact. The durability model is unchanged — fewer
  commits, not weaker ones.

## v0.32.0 — Agents guide + landing walkthrough + OTLP headers (done)

- docs/AGENTS.md (scenario-driven, full tool/route/env reference,
  verification checklist) published as docs/agents.html; landing
  use-cases + 7-step walkthrough + CTA; UNDERCROFT_OTLP_HEADERS
  implemented (was documented-only).

## v0.33.0 — License change to BUSL 1.1 (done)

- MIT → Business Source License 1.1 across the project and its history:
  free production use, hosted/embedded non-compete carve-out, rolling
  4-year conversion to MPL 2.0. MemPalace heritage attribution moved to
  NOTICE; PARITY gained the full "what exists only here" inventory.

## v0.34.0 — Distribution & security policy (done)

- Release workflow: prebuilt binaries (linux/macos×2/windows, sha256) on
  every tag + `ghcr.io/compufreq/undercroft` image; SECURITY.md expanded
  to a full disclosure policy with private reporting enabled.

## v0.35.0 — Vault admin console (done)

- `GET /ui`: self-contained admin console on every `serve-http` build —
  vault lifecycle, stats, verify, key rotation, taxonomy-driven drawer
  browser (verbatim view/edit/delete), search, export/import. Bearer +
  assertion secret stay client-side (WebCrypto-minted assertions);
  type-the-name guards on destructive operations.
- `/v1` management routes: drawers list/get/update, taxonomy, verify,
  rotate, full-stats. First release of the admin-UI arc; the
  orchestrator fleet console is the second.

## v0.36.0 — Fleet console (done)

- `GET /ui` on the orchestrator: instance registry with health checks,
  tenant lifecycle with the one-time token reveal, guarded token
  rotation/deletion, count-verified migration with keep-source choice.
  Completes the admin-UI arc — both binaries now carry their console.

## v0.37.0 — Console monitoring + KG explorer (done)

- Vault console MONITOR tab (live charts + ticker; SSE on telemetry
  builds, 3 s polling everywhere) and KNOWLEDGE tab (entity browser,
  valid-now facts, temporal timeline) over new read-only `/v1` KG
  routes (stats, entities, query, timeline). Also PALACE (the pixel-art
  monitor embedded seamlessly with the console session) and GRAFANA
  (the observability dashboard, embeddable out of the box). First
  release of the advanced-console arc.

## v0.38.0 — Fleet live-ops (done)

- Fleet console 10 s sweep: auto health pills, per-tenant metadata
  stats columns, fleet totals bar; new admin route
  `GET /admin/tenants/{id}/stats` (metadata relay via stored creds).
  Completes the advanced-console arc.

## v0.40.0 — Orchestrator read replicas (done)

- `serve --read-replica`: state db opened read-only, data plane only
  (`/t/*` + `/healthz`); admin plane and console 403 to the writer.
  `/healthz` gains `mode` + `last_write` on both roles so lag is
  observable. Shared-volume (zero lag) and replicated-snapshot
  deployment shapes documented; single-writer stance unchanged.

## Next (all demand-driven — planned, not scheduled)

Nothing below should be built until its trigger fires; each entry
records the design so a future session starts from a plan, not a blank
page.

### 1. Inverted FDE tier (BUILT v0.39.0 — measured, shipped OPT-IN)

- **Outcome** (fde-synth, contiguous-slab harness, within-run): the
  machinery shipped — event-driven centroids over decoded FDEs, in-place
  list rewrite (no migration), slab-grouped cache,
  `UNDERCROFT_FDE_IVF_MIN` / `UNDERCROFT_FDE_NPROBE` — but the gate
  FAILED on both axes at N=200k/500k: containment 0.960–0.967
  (quarter-probe) / 0.993–1.000 (half-probe) vs flat's 1.000, and the
  probed scan measured slower than flat ADC (243 vs 79 ms/q at 500k).
  Flat ADC + LUT stays the recommended configuration at every measured
  scale; the tier is **default OFF** — opt in via
  `UNDERCROFT_FDE_IVF_MIN=<n>` past ~10⁶ only after validating
  containment on the real corpus. Logs
  `.handover/fde_slab_sweep{,2}.log`.
- **Trigger** (original): a real palace approaching ~10⁶ drawers where the flat
  PQ-ADC FDE scan (measured 33 ms/q @ 200k, linear in N) exceeds the
  latency budget. Below that scale it measured net-negative — the
  O(N·nprobe) membership filter loses to flat 256-add ADC (v0.24.0
  finding; bench evidence in `.handover/fde_pq_sweep.log`).
- **Design**: group the RAM code cache by IVF list (contiguous
  per-list slices built once at load — no per-row `lists.contains`
  test at query time), coarse-quantize the query FDE, scan only the
  probed lists' slices. The v2 on-disk pack already reserves the list
  field (written as `-1` today), so rows re-partition by rewriting
  that field only — **no format migration**.
- **Steps**: (1) event-driven list assignment past a threshold
  (mirror `tok_pq_ensure`'s train-and-repack pattern); (2) slice-grouped
  cache in `fdeidx.rs`; (3) `UNDERCROFT_FDE_NPROBE` (default nlist/4,
  mirroring PQ/IVF); (4) fde-synth sweep at N=200k/10⁶ — gate:
  containment must stay ≥ flat's (it degraded to 0.84–0.99 in the
  naive attempt; the slice construction must not repeat that).
- **Effort**: ~1 release; the risky part is proving containment, not
  the code.

### 2. Orchestrator read-replica proxy (SHIPPED v0.40.0)

- **Outcome**: built to this plan — `--read-replica` serve mode over a
  read-only state handle (mutations refused at the state layer and by
  the connection), `/healthz` mode + `last_write` lag surface, e2e
  writer+replica convergence (44 checks). The lag trade documented as
  designed: a revoked token dies on a replica after at most the
  replication window; the writer stays the only place rotation is
  immediate.
- **Trigger** (original): a deployment that needs orchestrator availability beyond
  one process, or read throughput beyond one proxy (single-writer
  stance documented in MULTI_TENANCY.md holds until then).
- **Design**: keep exactly one writer (all `/admin/*` mutations);
  replicas open the state db read-only (SQLite WAL supports concurrent
  readers; ship the db via litestream-style file replication or a
  shared volume) and serve only the `/t/*` data plane. Token
  resolution is a pure HMAC lookup — replicas never mint or rotate.
  Stale-read window = replication lag; acceptable because tokens die
  by row deletion (a revoked token fails on the replica after lag, and
  rotation already treats old-token death as immediate only on the
  writer — document the lag as the availability trade).
- **Steps**: (1) `--read-replica` serve mode refusing `/admin/*`;
  (2) health/lag surface in `/healthz`; (3) e2e: writer + replica,
  rotate on writer, assert replica converges; (4) MULTI_TENANCY.md
  deployment section.
- **Effort**: ~1 release, mostly e2e work.

### 3. Sealed-tier page-level decryption (SHIPPED — v0.41.0 slab cache + v0.42.0 page tier, opt-in)

- **Outcome**: built to the spike's decisions across two releases.
  v0.41.0 shipped the format-free fix (slab-grouped cache, nlist clamp
  4096). v0.42.0 shipped the page format itself, **default off**: one
  AEAD page per IVF list (`pqpage/{list}/{pageno}`, 4096-row caps),
  lazy per-probe decryption, row-count commitment + sealed
  total/deleted counters (no Merkle), per-row tail folded per
  `upsert_many` batch (the write-amplification bound), event-driven
  repack migration both directions, rotation coverage. The trigger
  stance survives as configuration: flip `UNDERCROFT_PQ_PAGE_MIN` when
  a sealed deployment's RAM/open-time wall bites — no release needed.

- **Trigger** (stands): sealed vaults at multi-million drawers where the
  decrypt-once RAM caches (PQ ~52 B/drawer, FDE 256 B/drawer) stop
  fitting, i.e. RAM budget — not latency — becomes the binding
  constraint.
- **Spike result** (`undercroft-bench pqpage-synth`, 10⁶–10⁷ synthetic
  drawers; measured section in RETRIEVAL_SCALING.md, raw log
  `.handover/pqpage_spike.log`): pages (one AEAD blob per IVF list,
  AAD `pqpage/{list}`) win on at-rest size (2.1×), open cost
  (22 s → 0 at 10⁷) and RAM (630 MB warm vs ~1 GB) once the trigger
  fires — but the *urgent* 10⁶+ problem is the flat cache's O(N·nprobe)
  per-query list filter, fixed by slab-grouping the existing cache with
  **no format change**. Design questions answered: integrity needs only
  a row-count commitment inside the sealed page + a sealed total-count
  in `pq_meta` (no Merkle — the page is one AEAD unit, which is
  *stronger* than per-row against intra-page tampering; stale-page
  replay is the same advisory-index trust class as today's stale-row
  replay); the real new cost is **write amplification** (~550 KB reseal
  per single-drawer write at 10⁷/1024), so the format needs per-row
  tail rows compacted per `upsert_many` batch and/or `(list, pageno)`
  page caps, and the nlist clamp (1024) must lift to ~√N.
- **Next when triggered**: slab-grouped RAM cache first (cheap,
  format-neutral, also prescribed by item 1); then the page format +
  event-driven repack migration. Effort: likely 2 releases (format +
  migration), as planned.

### 4. FDE page tier (extend v0.42.0's page machinery to the next cache)

- **Trigger**: a sealed vault at multi-million drawers with the MUVERA
  FDE tier enabled, where the FDE code cache (256 B/drawer — 5× the PQ
  cache; ~2.5 GB at 10⁷) is the binding RAM/open-time cost. Same wall
  as item 3, bigger artifact.
- **Design**: direct analog of the shipped PQ page tier — the FDE index
  already has the two prerequisites (v2 rows carry a list field since
  v0.39.0; `FdeCache::Coded` is slab-grouped). One AEAD page per list
  under a new `fdepage/{list}/{pageno}` label in the existing `/tok`
  domain family, sealed `count ‖ (seq ‖ code)*` plaintext, sealed
  total/deleted counters in `fde_meta`, per-row tail folded per
  `upsert_many` batch, lazy per-probe load into the slabs, two-way
  event-driven repack, rotation reseal. **Scope note**: per-candidate
  ColBERT token matrices stay per-row — they are random-access
  hydrations at rescore, not list scans; paging them would trade one
  wall for a worse one. The token-PQ code cache is scan-shaped and may
  qualify — measure before designing.
- **Steps**: (1) mirror (or extract a shared seam from) the `pqidx`
  page helpers into `fdeidx`; (2) counters + verify-equation extension;
  (3) lazy list loads in `fde_candidates`; (4) rotation + at-rest
  tests; (5) gate on `fde-synth` at 10⁶–10⁷: open time and RAM must
  beat the flat cache with containment unchanged (it is byte-identical
  by construction, so the gate is cost-only).
- **Effort**: ~1 release — the machinery is proven; the work is the
  seam and the tests.

### 5. Re-embed migration (`undercroft vault reembed`)

- **Trigger**: switching embedders on a live palace — hash → ONNX
  model, or a model upgrade — which today means a new vault and a full
  re-ingest. The ORT backend makes this a real upgrade path, not a
  hypothetical.
- **Design**: content is stored verbatim, so re-embedding is a pure
  derived-data operation: batched over drawers (`upsert_many`-sized
  transactions), embed with the new embedder, rewrite each sealed
  embedding under its existing AAD, then drop every embedding-derived
  artifact (PQ codes/pages + codebook + IVF, FDE rows + codebook) and
  let the event-driven seams rebuild them. The embedder identity lock
  updates atomically at the end (two-phase, rotation-style staged
  marker reconciled at open — a crash mid-run must leave the old
  identity + old embeddings authoritative); the audit chain records a
  keyed re-embed entry. ColBERT token matrices come from the late
  encoder, not the embedder — a separate `--colbert` flag re-encodes
  those only when that model changed. Remote-index copies go stale —
  print the re-push reminder (rotation precedent).
- **Steps**: (1) `store::reembed_all(new_embedder)` with a resumable
  progress row; (2) CLI subcommand with the type-the-name guard +
  env-selected target embedder; (3) identity-lock flip + chain entry +
  crash-window tests (both sides); (4) e2e: re-embed to a
  different-dim embedder, VERIFY OK, search returns verbatim content;
  (5) gate: LoCoMo R@10 with the real model before/after — re-embed
  must reproduce the from-scratch-ingest quality exactly.
- **Effort**: ~1 release; the risky part is the crash windows, and
  rotation already mapped that territory.

### 6. Backup/restore + disaster-recovery runbook

- **Trigger**: any production deployment — this is an operability gap,
  not a performance one. All primitives exist (v0.18 artifact-carrying
  export, v0.30 recipient-encrypted bundles, count-verified import,
  verify); what's missing is the one-command shape and the documented
  recovery semantics.
- **Design**: `undercroft vault backup <name> --to <recipient-hex>
  --out <file>` = consistent snapshot as a recipient-encrypted bundle;
  `undercroft vault restore <file> --identity <key>` = import into a
  fresh vault + **mandatory full verify** + count check (refuse a
  silently-partial restore — the migration discipline). A daemon/cron
  flag for scheduled backups. The runbook documents what each failure
  loses and what survives: file loss (restore = RPO of last backup),
  key loss (backups are recipient-encrypted — the bundle identity key
  is the recovery root, store it separately), tamper (restored chain
  is a fork from the backup point — the manifest anchor and chain
  head semantics across restore, stated explicitly). Orchestrator
  state-db backup recipe alongside (file copy; sealed creds + MAC-only
  tokens mean a copied file without `UNDERCROFT_ORCH_KEY` yields
  nothing).
- **Steps**: (1) backup/restore subcommands over the existing
  export/bundle/import path; (2) verify-on-restore gate; (3)
  `docs/RUNBOOK` DR section (loss matrices, restore drill); (4) e2e:
  backup → destroy vault → restore → VERIFY OK + search parity +
  chain-fork semantics asserted.
- **Effort**: ~1 release, mostly e2e and documentation.

---

## Competitive track (ordered 2026-07-22 — compete hard and exceed)

The market (mem0, Zep/Graphiti, Letta, Cognee, Supermemory, plus the
MCP-server long tail) competes on **convenience**: extraction-based
"smart memory," bolt-on SDKs, hosted APIs, graph reasoning. None of
them has a security story — no sealed indexes, no tamper evidence, no
offline default, no cryptographic tenant isolation. The strategy in
one line: **close the convenience gap, make the trust gap
unfollowable.** Everything below preserves the invariants (verbatim,
local-first, sealed at rest, audit-chained); several items weaponize
them. Phases are the intended build order; each item ships as its own
release with the usual battery + measured gates.

### Phase C1 — prove it (weeks, mostly bench + writing)

- **C1.1 Head-to-head benchmark publication.** Run mem0 (local/
  OpenMemory), Zep/Graphiti self-hosted, Letta, and Supermemory's
  local binary against undercroft on the harnesses `undercroft-bench`
  already carries (LongMemEval, LoCoMo, ConvoMem, MemBench) —
  identical corpora, within-run comparisons, raw logs published, every
  competitor's best local configuration documented. Include the column
  only we can fill: quality **while fully sealed, zero external
  calls**. Publish as docs/BENCHMARKS_VS.md + a landing section.
  *Gate*: numbers reported as measured, favorable or not — the
  methodology page IS the product.
- **C1.2 Security comparison page.** One table, us vs the five named
  competitors: content encryption / derived-index encryption / tamper
  evidence / verified reads / key rotation / cross-tenant crypto
  isolation / offline default / audit chain / export encryption.
  Sourced claims, dated, PR-able by competitors if they object.
  Docs page + landing block.
- **C1.3 Threat-model whitepaper.** Formalize what SECURITY.md +
  seal.rs already implement (adversary classes, what each layer
  defeats, honest non-goals), framed against the 2026 "agent memory
  is an attack surface" literature. The artifact security buyers
  forward to their teams.

### Phase C2 — meet them (parity; each ~1 release)

- **C2.1 Python + TypeScript SDKs.** Thin typed clients over the
  existing `/v1` surface (vault lifecycle, drawers, search, KG
  browse, verify, export/import; assertion minting included). Publish
  to PyPI/npm with the same version cadence as the binary. This is
  the single biggest adoption gap — every competitor evaluation
  starts with `pip install`.
- **C2.2 Framework adapters.** LangChain + LlamaIndex memory/retriever
  classes and a CrewAI/AutoGen adapter, each a thin wrapper over the
  SDKs, each with an example repo. Gets us onto the shelf where
  bake-offs happen.
- **C2.3 Working-memory blocks (Letta parity).** A reserved wing +
  MCP tool sugar (`memory_pin`, `memory_edit`, `memory_unpin`) giving
  agents editable, always-in-context core memory on top of verbatim
  drawers — pinned blocks are still drawers: sealed, chained,
  verifiable.
- **C2.4 Local document ingestion.** `mine` learns PDF/DOCX/HTML →
  text extraction, fully local (no OCR cloud), chunked through the
  existing deterministic pipeline. Closes the Cognee/Supermemory
  "feed it your documents" gap without touching the no-phone-home
  stance.
- **C2.5 KG deepening.** `/v1` KG **write** routes (create/supersede/
  close facts — console gains editing), multi-hop graph queries, and
  richer local-LLM extraction prompts for `refine`. Removes
  Zep/Graphiti's cleanest talking point; our temporal model (valid-now,
  timelines, auto-supersede) is already competitive underneath.

### Phase C3 — exceed them (category-defining; nobody can follow)

- **C3.1 Facts-with-receipts distillation.** Opt-in automatic pass
  (local LLM, riding the existing `refine`→KG seam): distilled facts,
  contradiction handling via the existing temporal supersede, and —
  the part extraction-based competitors structurally cannot offer —
  every fact carries an HMAC-verified citation to its verbatim source
  drawer. Their pitch (smart memory) becomes our subset; our pitch
  (provable memory) stays exclusive. *Gate*: LoCoMo/LongMemEval with
  the distillation tier on must beat our retrieval-only baseline.
- **C3.2 Provable forgetting.** Retention policies per wing/room +
  `forget --prove`: deletion executes through the audit chain
  (tombstones already exist), emitting a verifiable attestation that
  named content was destroyed and nothing else changed. GDPR/RTBF
  with a receipt. Extraction-based systems cannot know what their
  LLM absorbed where — this feature is unreachable for them.
- **C3.3 Memory-poisoning defense.** Provenance labels on every
  drawer (writing agent/source/session, tamper-covered by the record
  HMAC), a quarantine wing for untrusted ingest with search-time
  trust filters, and a review/promote flow. First-mover answer to the
  documented memory-poisoning attack class: memory that can't be
  silently seeded *or* silently altered.
- **C3.4 Post-quantum export bundles.** Hybrid KEM (X25519 + ML-KEM)
  option in `bundle.rs` for recipient-encrypted exports; PQ notes for
  the at-rest layer (XChaCha20-Poly1305 is already PQ-comfortable).
  "Quantum-resistant memory vault" on the label before anyone asks
  the competitors the question.

Sequencing note: C1 needs no code beyond bench runners and can start
immediately; C2 items are independent of each other; C3.1 depends on
nothing but benefits from C1.1's baselines; scale items 4–6 above
(FDE pages, reembed, backup/DR) interleave on their own triggers.

---

## Operability track (planned)

Observability and a management/visualization surface for the stack. The
whole track obeys the project's core stance — **local-first, opt-in,
zero external by default, no plaintext or key material ever exposed**:

- **Default-off, loopback-only.** No metrics port, telemetry export, or
  UI is served unless explicitly enabled; when enabled it binds loopback
  and sits behind the existing palace bearer / `X-Vault-Assertion` auth.
- **Feature-gated**, mirroring the `--features onnx` pattern — a build
  without the feature carries zero extra dependencies and zero overhead.
- **Metadata and counts only.** Everything below exposes structure,
  aggregate counts, rates, and latencies — never drawer content, drawer
  names beyond what `stats` already surfaces, or anything key-derived.
  Sealed vaults expose only aggregate distribution, preserving the
  no-plaintext-derived-index invariant (in-memory samples are counts,
  not content, and are never persisted for sealed vaults).

### v0.9.0 — Observability & telemetry (done)

Instrumentation foundation the higher layers read from. Shipped in the
new `undercroft-obs` shim crate; fully synchronous (no async runtime).

- **Structured logging** via `tracing` + `tracing-subscriber`, replacing
  the ad-hoc `eprintln`s. Level via `UNDERCROFT_LOG`; human format by
  default, JSON via `UNDERCROFT_LOG_FORMAT=json`. No content or key
  material is logged (`SecretKey` stays non-`Debug`).
- **Prometheus** `/metrics` endpoint (text exposition format) on the HTTP
  server, gated by `UNDERCROFT_METRICS=1`, loopback + bearer-gated.
  Counters/histograms for search, drawer writes/deletes, dedup, KG ops,
  audit-chain commits, HMAC verify failures, HTTP requests, auth
  rejections, vault opens; per-vault gauges (drawers, chain height).
  Metadata only.
- **OpenTelemetry** OTLP **trace** export behind `UNDERCROFT_OTLP_ENDPOINT`
  (unset ⇒ no network egress). Metrics are surfaced via the Prometheus
  pull model — OTLP metric push needs a periodic-reader runtime this sync
  stack deliberately avoids; deferrable follow-up.
- **Hot-path instrumentation** at search, save/dedup, KG writes, vault
  seal/commit, and every HMAC-verify failure site.
- All behind `--features telemetry` — default builds carry zero extra
  deps and zero overhead.

### v0.10.0 — Live memory telemetry (done)

Turns point-in-time `PalaceStats`/`KgStats` into a streaming time series.
Shipped: per-connection SSE thread reading a thread-safe broker (the
sync server + `!Send` stores made this the only sound model), sampler
that only ticks watched vaults, and sealed-vault wing/room suppression.

- **In-process sampler**: periodic snapshot of `PalaceStats` + `KgStats`
  + cache/index gauges into a bounded in-memory ring buffer (window and
  resolution configurable). No disk writes for sealed-vault derived data.
- **SSE stream**: `GET /v1/vaults/{id}/stream` (and a palace-wide roll-up)
  pushing sampled deltas over chunked HTTP (supported by the current
  `tiny_http` server). Auth-gated, opt-in.
- **Discrete event pings** on the same stream, so a UI can animate
  individual actions rather than only sampled totals: `drawer-saved`
  (wing/room), `drawer-deleted`, `search` (wing/room hits), `kg-triple`,
  `chain-commit`. Payload is type + location + counts — metadata only,
  never drawer text or names beyond what `stats` already exposes.
- **History backfill**: `GET /v1/vaults/{id}/stats/history?window=…`
  returns the ring buffer so a fresh client can draw the recent past on
  connect.
- Exposed signals: wing/room populations, drawer add/delete rate, search
  QPS + latency, KG triple counts, cache hit rate, FTS prefilter ratio,
  audit-chain height — all counts and rates, never text.

### v0.11.0 — Palace Monitor: pixel-art memory world (done)

Shipped: served at `GET /monitor` (self-contained, `fetch()`-streamed so it
can send the bearer), demo mode until connected, a live `hmac-fail` event
driving the tamper beacon, and a `GET /v1/vaults` picker. Verified live
against a real server.

A real-time, game-style pixel-art view of how memory is distributed
across the palace, reading the v0.10 stream. Inspiration:
`pixel-agents-hq/pixel-agents` (agents-as-characters in a live office) —
reimagined around Undercroft's own metaphor: the palace *is* the world,
and an **archivist** files drawers into wings and rooms as writes land.

- **Self-contained local UI** served at `/monitor`. Vanilla Canvas-2D +
  a sprite sheet embedded as a data-URI — **no framework, no external
  CDN/fonts/assets, zero runtime JS toolchain** (hand-written, or a Vite
  bundle inlined at build time). One self-contained asset, CSP-safe,
  faithful to the local-first ethos. (Deliberate divergence from the
  reference's Node/React/Fastify stack, which the Rust runtime avoids.)
- **Pixel-art game world**: the palace rendered as an explorable
  top-down / isometric building. Wings are wings/floors, rooms are
  chambers, drawers are filing cabinets whose fill/brightness tracks
  drawer density. A lightweight game loop with sprite animation and a
  character state machine (idle → walk → file/pull).
- **Live, event-driven animation** off the v0.10 discrete pings:
  - *Archivist* walks to the target room and **files a drawer** on each
    `drawer-saved` (and on `mine`/`sweep` bursts); pulls and highlights
    drawers on `search` hits.
  - *KG hallways* — corridors drawn between co-occurring rooms, pulsing
    when a new `kg-triple` forms; entities as a constellation overlay.
  - *Audit-chain* — a stamp/ledger animation on each `chain-commit`,
    with the running chain height shown.
  - *Activity ticker + gauges* — search latency, QPS, cache hit rate,
    FTS prefilter ratio, drawer add/delete rate.
- **Sealed vaults stay opaque**: a sealed room renders as a locked
  vault-door showing only an aggregate silhouette (drawer *count*),
  never names or content — same no-plaintext invariant as the rest of
  the stack.
- **Read-only, metadata-only, default-off, loopback, auth-gated.**
  Multi-tenant aware: one building per vault/tenant plus a palace-wide
  roll-up (mirrors the reference's multi-agent view).
