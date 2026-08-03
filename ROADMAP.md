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

## Unreleased — the comparison layer, and dates that are declared (done)

- **Dates are declared, never guessed.** `Locale` carries `language`,
  `week_start`, `date_order` and `calendar`, all read-time, so an ingested
  corpus answers correctly the moment its conventions are declared — no
  migration, no re-embed. Ten calendars; Hijri (Umm al-Qura) and Jalali convert
  whole dates via `calendrical_calculations`.
- **An era the writer typed outranks the calendar the caller declared.**
  `พ.ศ.`, `ค.ศ.`, `هـ`, `民國`, `令和` and the rest, read before, after or glued
  to a year. Japanese eras are bounded, because an era's first and last years
  are partial. A bare year is a mention only where a marker names it.
- **Morphology: 191 audited pairs, 19 languages, 100% on the lexical channel —
  declared or not.** Five pairwise rules, none building an equivalence class:
  suffix, substitutive inflection, agglutinative stacking, Arabic root identity,
  and a table of irregulars. Language resolved by declaration, else by script
  where a script settles it, else by the drawer's own function words.
- **48 negative controls, which did not exist before.** The audit driving this
  work contained none: every pair in it was a true relation, so a rule admitting
  everything scored 100%. Each rule's price is now a pinned test row.
- **Rejections recorded with their measurements**, because they are the
  expensive part: Snowball (spec-correct and still wrong here — it builds a
  class one false friend poisons), Arabic subsequence in three families, and a
  blind union of the Latin tables.

## Next (all demand-driven — planned, not scheduled)

Nothing below should be built until its trigger fires; each entry
records the design so a future session starts from a plan, not a blank
page.

### Retrieval quality — measured end to end (LoCoMo, 2026-07-29)

The first run of `docs/AMB_REPLICATION.md`: AMB's protocol, AMB's
prompts, `k=10`, Sonnet 5 in both model roles, sealed vault, no external
API. **1349/1540 = 87.6%.** Using AMB's own `gold_ids`, retrieval put
**all** required evidence in context for 83.0% of queries and some for
94.1%; accuracy was 91.8% when all gold was present, 68.2% when partial,
65.6% when none.

**Category labels throughout this section use LoCoMo's own integers:
`1 = multi-hop, 2 = temporal, 3 = open-domain, 4 = single-hop,
5 = adversarial`.** The counts fix this (841 questions are category 4;
281 are category 1; 89 are category 3), and so do the evidence
statistics: category 1 carries a mean of **3.13 evidence turns over 2.68
distinct sessions** while category 4 carries **1.07 over 1.00**. The
mapping decides prioritisation, because the 43.4% all-gold figure
belongs to **multi-hop** — where 3.13 turns across 2.68 sessions makes
it unremarkable — while **single-hop measures 97.1%**.

#### Three metrics, stated together

Any one of these quoted alone misleads. The strict row in particular is a
diagnostic and not the system's standing:

| metric | default | + ColBERT |
|---|---|---|
| session any-gold `R@10` — **what this project publishes** | **95.5%** | **96.9%** |
| turn all-gold in the k slots — a strict *lower* bound | 74.2% | 79.1% |
| turn any-gold in the k slots — an *upper* bound | 84.1% | 89.5% |

`BENCHMARKS_VS.md` publishes 94.6% and v0.23.0 published 96.5%, both on
the first row. The turn rows are a newer diagnostic: they
ask whether the required *sentence* reached the reader, which the session
row structurally cannot see. The truth about evidence delivery lies
between them, because LoCoMo's evidence lists are partly **disjunctive** —
for at least 34.1% of multi-evidence multi-hop questions a single listed
turn alone carries the answer, so all-gold demands more than the question
does.

#### Where the deficit actually is

Delivery is almost entirely a function of how many evidence turns a
question needs, not of ranking quality:

| evidence turns needed | queries | all delivered |
|---|---|---|
| 1 | 1554 (79%) | 85.7% |
| 2 | 241 | 44.4% |
| 3 | 81 | 27.2% |
| 4 | 58 | 8.6% |
| 5+ | 43 | 2.3% |

By category: single-hop 86.9% · temporal 77.8% · open-domain 34.8% ·
multi-hop 21.7% · adversarial 88.6%.

And the evidence is *found*: the smallest prefix of the ranked output
covering every gold turn is within top-10 for 74.2%, top-40 for 85.9%,
top-80 for 92.3%, and **somewhere in the output for 99.8%** — 0.2% is
never retrieved at any depth. Holds at 10× corpus (1271 drawers, one
vault, cross-conversation distractors): floor still 0.2%. **This is an
ordering problem, not a matching problem.**

#### Reach is the problem, in three distinct senses

1. **Candidate reach** — who is considered. A full scan is perfect at 127
   drawers and O(N): 0.91 ms/drawer means **~913 s/query at 10⁶**. At scale
   the prefilter decides, and it is governed by the *weakest*
   representation. The benchmark cannot see this, because at 127 drawers
   the hash gates nothing.
2. **Delivery reach** — how deep the returned set goes. `k=10` with rescore
   capped at 50, while gold sits to top-40 (85.9%) and top-80 (92.3%).
3. **Representation reach** — the default embedder cannot match paraphrase.
   Not binding at this scale (MiniLM = +0.3pp); binding once a prefilter
   gates candidates.

#### Priority, by dependency and by who it impacts

**Phase 0 — guardrails. DONE.** *Maintainers and the security posture;
cheap, and without them the later work is unmeasurable.*

- **A footprint assertion test — BUILT.** "Never grow large" was a
  first-class constraint and the only load-bearing property here with no
  test, while the metadata-exposure inventory and the false-friend controls
  were both pinned in both directions.
  `one_drawer_costs_exactly_this_many_bytes` measures a real 804-byte prose
  chunk on a sealed vault. **One `priced` table drives both halves** — each
  artifact's measuring query beside the formula it must equal, with the
  inventory assertion built from the same array, so an artifact cannot be
  silenced by adding a name. That is the second design: the first kept the
  halves separate and **one added string literal made it green with zero
  bytes measured**, which is why the mechanism is worth stating and not just
  the assertions. Formulas: sealed embedding `40+6+dim`, PQ row
  `40+4+dim/8`, v1 token matrix `40+9+rows·(4+dim)`, raw FDE
  `40+1+reps·2^ksim·dproj·4`. Equality, so a shrink fails too. The inventory
  is the **whole schema** (every table priced per-drawer or justified as not),
  not a `drawer%` prefix, and `drawers`' **columns** are pinned because a
  column is the cheapest unpriced per-drawer byte. Measured at rest: content
  **515 B**, embedding **430 B = 0.83×** it, every tier at once **11,304 B =
  22×**. Sealed is the level with the strictest *guarantees*, not the larger
  footprint — hmac-only adds plaintext plus an fts5 index and four shadow
  tables.
  *Found while writing it:* with the FDE tier enabled, `search` never
  builds the PQ index — the prefilters are an `else if` chain and FDE wins
  it. The FDE cost per drawer is **8,233 B raw below `fde_pq_min` (256 rows)
  and 301 B PQ'd above it**, so "8 KB per drawer" describes a small corpus,
  not the steady state.
- **The per-drawer-independent-compression invariant**, written down in
  CLAUDE.md's invariants, plus the prohibition on compressing the 4096-row
  PQ pages.
- **A codebook generation counter — BUILT.** All five trained artifacts
  (`pq-codebook`, `pq-ivf`, `fde-codebook`, `fde-ivf`, `tok-codebook`) count
  their training events, each covered by a test. Nothing in a row's bytes
  says which generation produced it — the same invisibility one level down
  that `KNOWN_EMBEDDER_UPGRADES` exists to prevent. **What a step means
  differs by artifact:** the three codebooks mean *re-quantization* (every
  code byte recomputed), `pq-ivf`/`fde-ivf` mean *re-partitioning* (code
  bytes byte-identical; what moves is which candidates a probe offers —
  availability, not score). Counters live in `meta`, not in the artifact's
  own table, precisely because `invalidate_embedding_space` drops `pq_meta`
  wholesale and that drop is the event most worth counting; the test asserts
  the generation *survives* it and reads 2, not 1. A rebuild that reuses the
  stored codebook is **not** a new generation — pinned by forcing a real
  drift-driven rebuild, since an assertion that only clears the caches cannot
  fail whatever the code does. Visible on `PalaceStats.codebooks`,
  `/v1/…/stats` (that handler projects fields by hand, so it had to be taught
  the field — adding it to the struct reached nothing), the MCP
  `undercroft_status` tool, `undercroft stats`, and a **registered** telemetry
  gauge: `undercroft_obs::GAUGE_NAMES` is an allowlist and any other name is
  silently dropped, so a test pins the five names against it.
  **Not integrity evidence** — the row is outside HMAC coverage, so it
  distinguishes honest ambiguity, not tampering.
- **A stratified keyed training-sample draw — BUILT**, replacing the even
  stride at all five sites: four capped at 4,096 **drawers**, the token
  codebook at 16,384 **token rows** (a different unit, 4× the figure). One row
  per equal block of insertion order, chosen by `Vault::sample_rank` (a fourth
  HKDF-derived subkey, label `sample`, separate from the MAC key so a rank
  never shares a key with record integrity; length-prefixed so no two
  label/ident pairs collide). The PQ codebook and the IVF centroids draw under
  **different labels**: two independent samples where the identical stride gave
  both the same rows.
  - The **security** reason: the stride told a bulk writer exactly which of
    their rows would train the quantizer every *other* row is encoded against
    (`seq ≡ 0 mod stride`), and k-means has an unbounded breakdown point.
  - The **correctness** reason, which was not anticipated and is the larger
    one: a systematic sample of a *periodic* population collapses when the
    interval shares a factor with the period. Measured on `synth`
    (`FACT_TEMPLATES[i % 4]`) with `UNDERCROFT_RETRIEVAL=pq`: at `--n 16384` the
    interval is exactly 4 and the stride scores **R@5 83.0%**, failing that
    harness's own ≥95% gate, where this draw scores **99.7%**. At `--n 20000`
    the interval is 5, coprime with the period, and the stride is a perfectly
    balanced systematic sample (99.8% vs 99.4%). **The stride's edge is
    alignment luck between two measured sizes and its collapse sits between
    them** — 20,000 and 50,000 are both coprime with the period, which is
    exactly why no published number ever showed it. Periodic insertion order
    is ordinary: round-robin per source, alternating speakers, one session per
    day.
- **L2 normalisation documented as the poison mitigation it already was**
  (`pq.rs` module docs), with the bound stated correctly: on the unit sphere
  an attacker cannot buy influence with *magnitude*, only with **count** —
  which is what makes the breakdown bounded at all. It is **not** a small
  displacement bound; with every point in the unit ball each centroid is
  already in that ball, so "at most the diameter" bounds nothing. Residuals
  named: **density** (owning fraction *f* buys ≈*f* of any uniform sample — a
  per-source cap's job) and **non-finite input** (a NaN from an `external:`
  embedder escapes it entirely).

*Named as gaps, not decisions:*

- The keyed draw is pinned by unit tests on both halves (`sample_rank`
  keying, `take_lowest` selection) rather than end-to-end — an end-to-end
  proof needs a corpus above a sampling cap, which no unit suite builds.
- **Above a cap the draw changes both the membership and the size of the
  sample** (the old stride took `n/⌈n/cap⌉` rows: 3,847 at n=50,000 where
  this takes 4,096), so a measurement taken above a cap is not reproduced by
  this build. Reproducibility is now **per vault**, not per corpus: two fresh
  vaults over identical content above a cap train different codebooks.
  **Scope, precisely:** `locomo_eval` builds a fresh vault per conversation
  (~127 drawers), below `TOK_PQ_MIN` and below every drawer-level cap, so no
  codebook trains there and every headline LoCoMo figure above — 95.5%,
  74.2%, and ColBERT's 79.1% / +4.9pp — is untouched. The 10⁷ page spike and
  the FDE-synth containment figures train on their own synthetic samples and
  are unaffected. Two sites were affected and both are re-measured: `synth`
  PQ/IVF (99.8% → **99.4%** R@5 at n=20,000) and the `TOK_PQ_MIN` boundary
  (~380 merged drawers), where hash reads **73.9%**, ColBERT-with-stride
  **78.1%** and ColBERT-with-keyed **78.9% / 78.1%** across two vault keys —
  the keyed spread brackets the stride, so **the draw makes no measurable
  difference there**.
- **The +6.5pp / 80.4% ColBERT boundary figure: reachable, but not
  attributable.** On `locomo3_merged` the hash baseline reproduces to the
  decimal (**73.9%**), which fixes corpus, chunking, `k`, pool and fusion.
  Against that, at the depth those runs used (50), five ColBERT
  configurations were measured:

  | configuration (rescore depth 50) | turn all-gold @10 |
  |---|---|
  | tract · stratified keyed draw · PQ-ADC | 78.9% / 78.1% (two vault keys) |
  | tract · even stride · PQ-ADC | 78.1% |
  | tract · exact int8 (`UNDERCROFT_TOK_PQ_MIN=off`) | 77.7% |
  | **ort** · stratified keyed draw · PQ-ADC | 78.7% |
  | recorded in session 20 | **80.4%** |

  Backend, training draw and packing side are all ruled out, and the export
  pair is ruled out because only one pair exists. But two later findings
  account for the gap without any of them, and **neither was recorded with the
  original number**: the **rescore depth** was governed by an environment
  variable and raising it moves this exact figure (see the R2 entry — the same
  corpus reaches 80.4% at depth 200 in one run), and the **per-vault training
  draw** puts ~1.5pp of spread on any single ColBERT number here. So 80.4% is
  reachable and is *not* an error in the record; it is simply not attributable
  to any one setting, and a lone run cannot separate a real effect from the
  draw. **A measurement recorded without its configuration is not a
  measurement** — every future figure carries backend, export, thresholds,
  rescore depth and repeat count beside it.
- **A vault built by the old stride keeps its codebook, and nothing repairs
  it.** Upgrading the binary deliberately does not re-quantize: the stored
  codebook and every code pointing at it stay exactly as they were, so an
  upgrade changes no ranking and costs no write. The consequence is that a
  vault whose corpus size aligned with its ingest period keeps a degenerate
  codebook until something forces a retrain. Remediation is manual (force a
  re-embed, or drop the index so the self-heal rebuilds). **Detection now
  exists**: every codebook is checked at train time against a second keyed
  draw it did not train on (`ProductQuantizer::fit_report`), and a sample that
  reconstructs its own rows more than 1.5× better than unseen ones warns with
  both errors and the ratio. That converts the whole class from "invisible
  until someone benchmarks the unlucky corpus size" into a line in the log at
  the moment it happens — but it fires only when a codebook is *trained*, so
  an already-degenerate vault stays silent until its next retrain.
- The seeding stride *inside* `kmeans` is not keyed. The sample arrives in
  insertion order, so seed slot *c* is its *c/k* quantile and a writer who
  owns a contiguous stretch of insertions and makes those rows identical can
  still land ≈*f·k* seeds. Accepted rather than fixed because at that same
  *f* they win ≈*f·k* centroids through **density** anyway: keying the seed
  order would convert a certainty into a same-mean probability while changing
  every codebook in every vault. The capability to remove is density, and the
  instrument is a per-source cap.
- Export/import copies no `meta` rows, so a migrated vault reports every
  generation as 0 — which reads as "never trained" rather than "unknown".
- A generation bump lost to a busy database warns rather than retries.

**Reach status, so the next session does not have to reconstruct it.** Reach
was the whole point of this plan, and only part of it has moved:

| sense | item | state |
|---|---|---|
| **candidate** — who is considered | R1 wing as retrieval unit | **built, phase 1; settled at 10⁶.** Build cost proven wing-shaped; query-latency claim dead (unscoped PQ holds 24→31 ms/q to 1M, no break); **open defect filed: fixed-pool recall leak at scale (100→96.8) — fix = corpus-scaled pool, gated on R@5 ~100% at 10⁶** |
| | R4 FDE as generator | untouched |
| **delivery** — how deep the set goes | R2 rescore depth | **built** (value in the shipped config unestablished) |
| | R3 pagination | **built + delivered: 74.2% → 85.9% all-gold via 4×10 pages, 0/1977 tiling mismatches — the largest measured gain in the program** |
| **representation** — what can match | served embedder | **done, unplanned: +3.2–4.2pp** |

**R1 phase 2 — cross-wing fan-out — is designed but deliberately not built**
until scoped queries prove the model. Its three hard requirements are
recorded now, because R3's pagination contract imposes them: the merge must
be **deterministic** (sorted wing iteration, ties broken on drawer id — score
ties are common and `sort_by` only preserves input order), `ranked_at` must
thread into **every** wing's ranking or the pages-slice-one-ranking promise
dies at the merge, and the fan-out must be **bounded** (cap wings probed per
query and report `wings_probed` — the obs counter already exists) or it is
the linear scan with extra bookkeeping. Note R2 nudges candidate reach the
wrong way: rescoring 200 instead of 50 adds per-query work to the path that
is already the bottleneck.

**Phase 1 — reach, with no new storage and no new model.** *Users and agents;
this is where the measured headroom is.*

- **Split rescore depth from the latency cap — BUILT.**
  `UNDERCROFT_LATE_TOP_N` (default **200**) is now separate from
  `UNDERCROFT_RERANK_TOP_N` (50). One constant served both, and the two budgets
  buy different things: a cross-encoder spends a forward pass per candidate, so
  its depth is a genuine latency cap, while MaxSim is arithmetic over
  ingest-time matrices. Late interaction was inheriting a cap it never spent.
  Measured on the merged corpus with the token codebook disabled (no codebook,
  no keyed draw, depth the only variable): **77.7% → 79.8% turn all-gold,
  +2.1pp, for +9% search time**. Under v2 packing the same depth is nearly free
  (334 → 337 ms/q). Setting only the old variable still drives both stages.
  **Three limits on that number, all of which an earlier draft of this entry
  got wrong:**
  - The **+2.1pp belongs to the codebook-disabled configuration**. Any corpus
    past `TOK_PQ_MIN` runs v2 PQ-ADC, and there the same step measured +1.7pp
    and +0.0pp on two runs — so the default-configuration value is
    **unmeasured**, bracketed by those two, both inside the draw's own spread.
  - **200 is a judgement, not a peak.** The claim that 400 "scores lower"
    rested on 79.6% against 79.8% — one question out of 495, one run per depth
    — while the two v2 sweeps put 400 *above* 200. Depth beyond 50 helps;
    100–400 are not separable by this evidence.
  - **It moves published ColBERT figures.** The rescore runs on the
    un-truncated candidate list, so on a sealed vault with no prefilter it
    reaches the whole corpus — a 127-drawer conversation goes from
    `min(127, 50)` to `min(127, 200)`. The full-corpus 79.1% / +4.9pp describe
    depth 50 and want re-measuring at the new default.

  *Instrument note:* the per-vault training draw contributes ~1.5pp of spread
  on this corpus (estimated from one pair of repeats, so treat it as an order
  of magnitude, not a figure), which is why any ColBERT comparison here needs
  the codebook disabled or repeated runs.
- **A tunable, bounded, logged fusion weight — BUILT** (2026-08-02,
  `UNDERCROFT_FUSION_WEIGHT`, clamped [0.20, 0.70], one global declaration
  never per-query). First sweep (harness-default 60-hit pool — NOT the
  published pool-400 config, rows compare only within): monotone toward
  low `w` on hash (0.35 → 72.1% turn all-gold vs 0.55 → 69.4%), curve
  still rising at the low end. **The default did not move**: one
  benchmark at one pool config, embedder-dependent optimum, and tuning
  the shipped default onto LoCoMo is benchmark-fitting. Full numbers in
  CHANGELOG.
- **Pagination on `SearchOptions` — BUILT.** `offset` (a page is ranks
  `[offset, offset + limit)` of the list one deeper call would produce) plus
  `ranked_at` (the clock recency decays against, repeated by every page so
  one iteration slices one ranking, not one per host-clock read). Letta
  measured iteration as *the* differentiator (74.0% with plain grep and tool
  rules); before this, call 2 could only re-ask call 1's question. Three
  hazards closed on the way: the room cap's refill was a function of
  requested depth (page 2 could re-select page 1's hits — the selection
  stream is now depth-independent, byte-identical at offset 0); every
  prefilter's over-fetch was `max(256, limit·32)` computed from `limit`
  alone (a page past the floor sliced into ranks never fetched); and the
  remote-index path ranked against its own clock. Surfaces: `/v1` search
  (`offset`/`ranked_at` in, `next_offset`/`ranked_at` echo out, additive),
  `undercroft_search` (absolute-rank numbering, a full page ends with its
  exact continuation), CLI `--offset`. An offset, not a keyset cursor —
  rescore and diversification re-order candidates, so a rank names a stable
  position and a last-seen score does not.
- **A query-side date filter** — small recall (~+1pp ceiling) but the only
  **poison-positive** item: `content_date` is HMAC-covered, so the filter
  rests on tamper-evident declared metadata rather than learned similarity.
- **Wing as the retrieval unit — BUILT (phase 1, dual index); build
  economics PROVEN, query-latency claim NOT.** Per-wing PQ
  codebooks/IVF/rows for wings past `UNDERCROFT_WING_PQ_MIN` (4096); a
  wing-scoped search probes the wing's own index, a below-floor wing
  full-scans itself (floor-bounded, exact), and unscoped queries keep the
  global index unchanged — no API contract change, which is what made
  phase 1 shippable without fan-out. Measured honestly (wingscale,
  corrected instrument — full table in CHANGELOG): **both** latency
  columns are flat across 4× corpus growth (scoped 24.1→23.8, unscoped
  24.0→24.5 ms/q at 16k→65k) — the global PQ tier already bounds the pool
  at these sizes, so the per-wing tier buys no query latency here and runs
  3.5× slower than tier-off. What it provably buys is **wing-shaped build
  cost**: 3.9/15.5 s vs the global index's 59/240 s, a maintenance
  property that compounds. The 913 s/query motivator was a full-scan
  figure; the residual claim lives at 10⁶ and 65k is 15× below it. The
  starvation delta (99.0 vs 100.0 scoped R@5, 2 queries in 196 against
  ±0.5pp draw wobble) is suggestive, not established; the catastrophic
  empty-wing shape is pinned by unit test, which needs no scale.
  **The settling number was run (`pqscale`, one cumulative vault to 10⁶):
  24.3 → 31.0 ms/q unscoped from 131k to 1M — no break, the query-latency
  claim is dead, and the tier is documented as a build-cost optimisation
  plus the scoped-starvation fix.** The probe also surfaced **an open
  defect and an open cost, both with named fixes — neither is accepted as
  a property**:
  - **Defect: unscoped recall leaks with corpus size — CLOSED, gate met
    at every checkpoint.** (Was: 100.0 → 96.8 R@5, fixed 256-candidate
    pool vs linearly growing competitors.) Shipped as a **two-stage
    pool**: `live/64` ADC net (`UNDERCROFT_POOL_DIV`) → exact-cosine cut
    to `live/512` (never below — a sealed vault has no lexical
    prefilter, so hydration is BM25's only door; cutting to the fixed
    floor by pure cosine measurably regressed 1M to 98.9%) → hydrate.
    Plus the 1.5× IVF freshness rule (`ivf_fresh`, retiring strictly-\>2×
    which let a corpus sit at exactly double its training size stale).
    **Measured in the shipped default: R@5 100.0% at 131k/262k/524k/1M —
    20.4/32.6/59.1/112.7 ms/q since the parallel-fuse pass (2026-08-02;
    was 34.4/69.6/138.4/280.6).** The linear price is the recorded cost
    of not losing answers, now paid across cores: the hotspot was
    `bm25_raw`'s serial per-candidate scan, found by the
    `UNDERCROFT_SEARCH_TRACE` phase trace after "parallel hydration"
    measured zero change — the queued lever was refuted, the instrument
    found the real one. dim/4 codes remain the unused shrink lever.
    Full narrative incl. the two instructive intermediate
    configurations in CHANGELOG.
  - **Cost: corpus-shaped maintenance debt — ROOT-CAUSED AND FIXED.** The
    17 min at 131k / 73 min at 524k per retrain were **not computation**:
    the rebuild loop wrote every code row as an autocommit INSERT — one
    fsync per row under `synchronous=FULL` (7.8–8.3 ms/row, arithmetic
    exact at both sizes). One transaction around the rewrite (an
    improvement to crash atomicity, not a trade) collapsed the smoke
    warm-up 36.2 s → 2.3 s at 8k; the wing build had the same disease
    (3.8 ms/row). Residual rebuild cost is CPU (train + encode + assign,
    single-threaded) — full-scale post-fix numbers come from the next
    pqscale run; rayon on the encode loop and assignment-only retrain
    remain second-order levers if that measurement asks for them.
  The instrument now exists (`scopescale`, 2026-08-02) and settled it in
  both directions: room-scoped and wing+room-scoped R@5 hold **100.0% at
  every checkpoint to 10⁶** (the scope filter's at-scale claim, earned).
  It also filed and then CLOSED a defect the same day: wing-scoped
  through the wing's own index read 89.6% flat, corpus-independent —
  wings live exactly in the size band where the corpus pool divisors
  collapse to the fixed 256 floor (the measured-leaky configuration),
  and the cosine-only stage-2 cut then starved the lexical door (pool
  sweep: 89.6→96.9 plateau). **Fixed by scope-sized pools**
  (`scoped_pool_k`/`scoped_keep`: stage 1 ≥ `min(scope, 2048)`,
  hydration ≥ `min(scope, 1024)`, small scopes exact, converging to the
  corpus divisors at scale). **Gate met: 100.0% in every scoped column
  at every checkpoint 131k→1M**, wing ~85 ms/q flat (1024-row hydration,
  the recorded price), unscoped untouched. The defect it closes is recall as much
  as cost: the global prefilter's top-k intersected with a wing can starve
  it entirely (pinned by test). Honest limits, recorded: BM25 IDF stays
  global (the wing isolates candidates, not scores; per-wing IDF was
  rejected — RRF-style rank fusion measured −7.3pp here and per-query
  channel rescaling −9.4pp, so no per-wing score normalisation either);
  the hmac FTS prefilter's scoped-starvation shape — and `room`'s, which
  had the same defect with no tier and no fallback at all — is **CLOSED**
  (2026-08-02) by scope-aware candidate generation: every declared filter
  a prefilter cannot see resolves to a seq set first; small scopes drop
  the prefilter for a bounded exact scan, large ones get
  membership-filtered candidates with the pool scaled to the scope's own
  population (pinned by room/FTS/wing-tier-off starvation tests with raw
  premises);
  ingest is now the un-addressed scaling axis — a served embedder costs
  11–29× ingest and per-wing indexes do not help writes. Phase 2 (fan-out
  for unscoped queries) waits on scoped queries proving the model; its
  three requirements are recorded beside the Reach table.

**The consultation-filtered track (2026-07-31).** An external architecture
consultation proposed a governance layer (typed memory objects, provenance
graph, authority tier, retrieval profiles, Postgres engine mode, signed
bundles). Every claim was checked against the code and this repo's
measurements — the full evidence, including what was refuted with numbers
(write gating −27.7pp, context packing +0.3pp vs paging's +11.7pp, weight
cleverness −5.6/−7.3/−9.4pp) and the two posture decisions (no RLS-tier
Postgres by default: cryptographic isolation is an invariant; no pruning:
expiry is metadata, not deletion), lives in
**docs/CONSULTATION_REVIEW.md**. Four items were adopted, in dependency
order: (1) an **authority tier on KG facts** (`authority_class`,
`review_state`, `canonical_key`, exact-authority lookup before semantic
recall on high-risk asks) — **BUILT 2026-08-02**: declared closed
vocabulary, HMAC-covered (a column flip without the vault key fails
verification), audited promotion with per-key supersession, indexed
`lookup_canonical` on store + `/v1` (`GET …/kg/canonical/{key}`,
`POST …/kg/authority`) + MCP (`undercroft_lookup_canonical`,
`undercroft_kg_set_authority`) + CLI (`kg authority`, `kg canonical`),
rotation carries the tier, five pinned tests incl. the
poison-cannot-self-approve tamper case; (2) **extractor identity + generalized
supersession** — **BUILT 2026-08-03**: extractor recorded inside the
fact's HMAC via a third canonical extension (0x1d, the support/authority
precedent — old facts byte-identical), both refine paths pass the model,
a flipped column fails verification; receipted `supersedes` on drawers —
meta_json link + mirror column + keyed receipt over the superseded
content's unkeyed fp in separate columns (the kg source_fp/receipt_tag
shape, so rotation re-keys it), five verdicts via
`verify_supersessions`/`/v1/…/supersessions`/CLI+MCP verify, superseding
never deletes; (3) **bundle
manifests** — **BUILT 2026-08-03**: Ed25519 sender attestation beside the
X25519 recipient flow, signed manifest (scope/trust-claim/expiry/counts/
provenance + unconditionally-checked payload digest), `--sender` pinning
at import, legacy bundles import unattested-and-said-so, and the
meta-rows export gap CLOSED on both surfaces (KG facts travel with
receipts re-keyed from the traveling fp, authority tier and extractor
intact; tunnels travel; embedder identity and chain head travel as
provenance, never as state); (4) **typed `kind` on promoted
records** — **BUILT 2026-08-02 for drawers** (pulled forward on user
decision once the doctrine and the scope machinery existed): declared
closed vocabulary, HMAC-covered, scope-safe filter, unlabeled-rows
count, value instrument (`tagvalue`) run first — no recall lift, a
latency win, exactly as the doctrine predicted (docs/LABELS.md). The review also recorded a new property worth knowing:
since the per-wing tier, a wing is an *enforceable trust zone* for scoped
retrieval — poison in another wing can neither crowd a scoped query's
candidates nor shape its codebook — which the C3.3 defense cluster builds
on. New confirmed gaps filed there: read-path/export auditing, entity
resolution, artifact references (image bytes), region-as-policy.

**Labeling discussion — RESOLVED (2026-08-02), doctrine written down.**
The 2026-07-31 open discussion ("labeling as a reachability feature")
closed with a code-verification pass and three user-ratified outcomes:
(1) **converge the doctrine, not the work unit** — the golden-values tier
shipped first and narrow, `kind` waits for its instrument; the shared
doctrine lives in **docs/LABELS.md** (filter-then-weight strictly, labels
never in scoring; cost ≠ trust; closed-vocab-or-blind-index on sealed
vaults; every filterable label owes the starvation machinery an index and
a scope-resolution entry). (2) The discussion's "exact label paths are
immune to the candidate-pool leak class" claim was **half-true**: true
for exact-key doors, false for filters-on-search — and `room` was found
carrying the wing-starvation shape live, with no tier and no fallback.
Fixed as its own defect unit (scope-aware candidate generation; see the
honest-limits block above). (3) Tagging cost tiers confirmed (declared ≈
zero; rule-derived ≈ free; model-derived ×10³–10⁴ ⇒ async enrichment
only, never a write gate — mem0's gate measured −27.7pp here); the
rule-vs-LLM tagging cost instrument is designed and queued.

**Phase 2 — representation, gated.** *Operators as much as users.*

- **Export v2 before any ColBERT default.** Portable artifacts travel as v1
  because the codebook does not leave the vault, so a 10⁶-drawer export is
  **~26.9 GB**. Ship the sealed codebook inside the bundle — `bundle.rs`
  already carries recipient-encrypted members.
- **Re-measure FDE containment** under a real encoder. It gates
  late-interaction-as-retriever, and that outcome decides whether a small
  ColBERT is a retriever or merely a rescorer.
- **The smallest acceptable footprint config** — 48 dims + token pooling ×2
  + PQ'd FDE ≈ 1.4 GB per 10⁶, 2.8× the content it indexes.

**If only two things get built: rescore depth and pagination.** They are where
measured headroom, zero footprint and zero invariant cost coincide.

#### Standing decisions, not to be re-litigated

- **The coupling rule.** Anything that couples drawers may **propose
  candidates**; it may never be the **final arbiter of score**. The same
  doctrine the repo already applies to remote vector backends — an
  untrusted accelerator may propose, never decide. Coupling in candidate
  generation is an *availability* risk (a legitimate drawer is not
  offered); coupling in scoring is an *integrity* risk (poisoned content is
  promoted), and it takes what decides the answer outside HMAC coverage.
- **Graph joint scoring (Personalized PageRank) is refused**, and this is a
  decision with a reason rather than an open gap. It is scoring, not
  candidate generation. The cost is stated plainly: it forecloses the
  mechanism behind every published multi-hop win (HippoRAG 2 lifts MuSiQue
  R@5 69.7→74.7, 2Wiki 76.5→90.4), so multi-hop stays structurally weaker
  here. Do not re-propose on the strength of those numbers alone.
- **Derived-structure scope is the poisoning blast radius**, and should match
  the isolation unit (wing), not the crypto unit (vault). Today every
  codebook and centroid set is vault-wide, so a poisoned drawer in one wing
  shifts the candidate generation of another.

#### The plan, reordered by what measurement says

1. **Late interaction is the only lever that moves anything** — and it
   is not in this plan today. ColBERT rescoring measures **+4.9pp** turn
   all-gold on the full corpus (74.2 → 79.1, session `R@10` 95.5 → 96.9)
   at 2.0× search and 43× ingest, and **+6.5pp** above the
   `TOK_PQ_MIN=256` boundary where MaxSim runs PQ-ADC rather than exact
   int8 (73.9 → 80.4). A cross-encoder is slightly better at +6.7pp and
   **58× search**, which is not viable. Both work for the same reason
   nothing else does: they score the query *against* the text instead of
   comparing two summaries of it.
   **The blocker is a design defect**: `DEFAULT_RERANK_TOP_N = 50`
   (`crates/undercroft-store/src/lib.rs:123`) is one constant serving as
   *both* the rescore depth and the latency budget. That was the same
   thing when the only second stage cost one forward pass per candidate;
   ColBERT's per-candidate cost is a MaxSim over precomputed matrices, so
   it inherits a budget it does not spend — while 85.9% of gold sits
   within top-40 and 92.3% within top-80, out of reach. Split the two.
2. **Wire a query-side date into search.** `SearchOptions` is
   `{morph_lang, wing, room, limit, room_cap}` — no date field. The
   temporal engine resolves dates *inside* drawers and was never
   connected to the query side, so "in September 2023" competes as a
   bare token against text saying "last week". 320 temporal questions
   deliver 77.8%; this is the one unwired subsystem with a category
   pointed straight at it.
3. **A token budget on search, not only a count.** `limit` is a count;
   every caller's real constraint is context. At a fixed 8000-byte
   budget with overlapping text charged once, selection delivers +0.3pp
   and fits 11.3 chunks where 10 fit before — small, but it is the
   *only* selection-policy change measured that loses nowhere, and it
   helps monotonically more as evidence count rises (+0.1pp at one turn,
   +2.4pp at five). A caller who can spend 32 KB reaches the 90.5%
   top-40 row instead of 79.1%. This is gap 2 done correctly (see
   below).
4. **Gold-evidence recall as a standing bench metric — BUILT.**
   `undercroft-bench locomo` reports all three rows above plus the
   per-evidence-count and per-category splits, the depth CDF, and the
   duplicated-byte share, with no model calls. Coverage is an interval
   test over byte ranges in the ingested body, so a turn split across a
   chunk boundary counts as present when both neighbours are returned.
   Unlocatable gold turns (9 of ~2800) are excluded **and printed**.
   Session rows are reported at *both* pool depth and slot depth,
   because comparing a 60-hit pool scan against a 10-slot prefix
   measures depth and granularity at once — that error inflated an
   early reading of this gap by 2.1pp.
5. **Abstention.** Still downstream of a scorer with a real floor:
   `lexical > 0` passes on any shared term, and the default embedder
   puts two unrelated drawers at cosine 0.73 against a 0.56 gate.
6. **A semantic embedder IS a large lever — this entry was wrong twice,
   and the second correction is the useful one.** It first claimed the
   embedder was *the* biggest lever, on a mislabelled category. It was
   then corrected to "NOT the biggest lever" on the strength of MiniLM
   ONNX moving turn all-gold **+0.3pp** (74.2 → 74.5) — a fact about
   MiniLM, generalised to model embedders as a class. Measured against
   four **served** models (`UNDERCROFT_EMBEDDER=http`, full corpus):

   | model | session `R@10` | turn all-gold | ingest | ms/q |
   |---|---|---|---|---|
   | hash (default) | 95.5% | 74.2% | 16 s | 110 |
   | nomic-embed-text (137M) | 96.8% | 77.4% | 177 s | 132 |
   | mxbai-embed-large (335M) | 96.9% | **78.4%** | 416 s | 149 |
   | bge-m3 (567M) | 96.9% | 77.9% | 469 s | 172 |
   | Qwen3-Embedding-0.6B Q8 | **97.0%** | 78.1% | 413 s | 171 |

   **+3.2 to +4.2pp**, comparable to ColBERT's +4.9pp, at no storage
   cost and no ONNX export. The dilution argument above (a bi-encoder
   pools an 800-byte chunk into one vector) is still true and still
   bounds the gain — it just does not bound it at +0.3pp. The other
   reading matters as much: the four modern models span **1.0pp**, so
   the lever is *using a real embedder at all*, and MTEB order does not
   transfer (Qwen3-0.6B is far above nomic publicly, +0.7pp here at 2.3×
   the ingest). **No winner is claimed** — one run each, and the served
   path is not shown run-to-run deterministic. Cross-lingual, the one
   thing hash provably cannot do, is now MEASURED (xlingual, 2026-08-03,
   bge-m3 served): **R@1 88–100% on a foreign-target corpus — the
   capability is real — and ~0% on a mixed corpus**, because the
   hash-calibrated cosine map lets same-language lexical noise crowd out
   translation golds. The defect entry below carries the root cause and
   the named fix; full controls in CHANGELOG.

#### Measured and failed — do not re-propose without new evidence

Every row is a full-corpus run through `undercroft-bench locomo` unless
noted, against turn all-gold:

| change | result |
|---|---|
| per-document cap, ≤1 / ≤2 slots | **−17.5 / −1.8pp**, and it loses at *every* evidence count — evidence averages 1.17 turns per session, so the cap blocks the second turn of the *right* session as often as it admits a new one |
| `Fusion::Rrf` | −7.3pp (session `R@10` 93.2%). **Configuration removed** (2026-08-02): the arm was deleted rather than left as a shipping footgun — `UNDERCROFT_FUSION=rrf` now warns and falls back to `bm25`; reproduce the measurement from git history. Same verdict as Bruch et al. (TOIS 2023, convex combination > RRF) and the vendor migrations away from rank fusion; the industry's *replacement* (per-query min-max/DBSF normalization) is the rescaling row below and stays rejected — result-set coupling is a poison channel |
| `Fusion::Legacy` | −8.2pp (session `R@10` 92.2%) |
| per-query channel rescaling to [0,1] | **−9.4pp**. The nominal 0.55/0.35 split realises as ≈21.5/78.5 because the channels have different spreads — but that compression was correctly *down-weighting* a weak signal, and forcing the hash cosine up to its declared share destroys ranking |
| chunk 400 B / 200 B, fixed 8 KB budget | −10 / −28pp; also worse under ColBERT (72.4 / 37.9 vs 81.1) |
| turn-aligned drawers (the writer's own boundaries), fixed budget | −6.8pp, and the first-stage floor rises 0.2% → 7.9%: a bare turn has no retrievable signal alone |
| `UNDERCROFT_SEMANTIC_GATE=off` | byte-identical. The gate discards nothing on this corpus |
| query decomposition · coverage/MMR selection · entity-anchored expansion · iterative retrieval/PRF | all measured against the corpus, all fail; 85.6% of multi-evidence questions have one gold turn already covering every query term any gold turn covers, and only 1.8% of missed gold carries a term the top-10 lacks |

**Still refused as benchmark-fitting rather than engineering:** raising
`k`; tuning chunk size to LoCoMo; making chronological assembly a
default because *this* corpus is temporal; conversational heuristics;
`room_cap` tuning.

#### Correctness defects found, worth fixing regardless of LoCoMo

- **BM25 IDF is scoped to the candidate set** (`lib.rs:3838`, df at
  `3919`). Inert on a sealed full-scan vault, where the candidate set
  *is* the corpus — but under any prefilter the set is
  `max(256, limit*32)` documents that all matched, so every `df` tends
  to `n` and rarity stops discriminating. A scaling correctness bug.
- **`recency_boost` decays on `filed_at`** (`lib.rs:4130`), not
  `content_date`. A freshly ingested five-year-old document outranks a
  year-old ingest of today's note. Inert in a single-pass ingest, where
  it is a constant 1.0 and changes no ordering.
- **BM25 document length mixes units across scripts** — one unit per
  word in delimiting scripts, one per character otherwise
  (`crates/undercroft-core/src/script.rs`), so `b = 0.75` systematically
  penalises CJK in a mixed-script vault.
- **Threshold-gated behaviour splits are untested on one side.**
  `TOK_PQ_MIN`, `FTS_PREFILTER_MIN`, `IVF_MIN`, `PQ_PAGE_MIN` and
  `FDE_IVF_MIN` each select between implementations by corpus size, and
  most have never been engaged by any benchmark here — the FTS
  prefilter not at 127 drawers nor at 1271. Both sides ship, so both
  sides are production and both must be measured.
- **The cosine affine map is calibrated to the hash space — CLOSED
  (2026-08-03, same day filed), both gates met.** Was: `(cos+1)/2`
  compressed a served embedder's semantic channel into the top quarter
  of [0,1] and same-language function-word overlap crowded out
  cross-lingual golds (mixed corpus ~0% R@5). Fixed by
  `Embedder::semantic_floor` + `calibrated_semantic`: the measured
  unrelated floor becomes the map's neutral point, hash DECLARES floor 0
  and takes the shipped expression verbatim (bit-identical default,
  pinned), the admission gate rides the same calibration. Gates:
  LoCoMo hash digit-for-digit (69.4 / 81.8); xlingual mixed R@5 0–4% →
  53–88% at the default weight, and 100.0% every pair (R@1 60–100%)
  under a deployment-declared `UNDERCROFT_FUSION_WEIGHT=0.70` — the map
  and the weight compose, and the default weight stays put. Full
  narrative in CHANGELOG.

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
  `benchmarks/logs/fde_slab_sweep{,2}.log`.
- **Trigger** (original): a real palace approaching ~10⁶ drawers where the flat
  PQ-ADC FDE scan (measured 33 ms/q @ 200k, linear in N) exceeds the
  latency budget. Below that scale it measured net-negative — the
  O(N·nprobe) membership filter loses to flat 256-add ADC (v0.24.0
  finding; bench evidence in `benchmarks/logs/fde_pq_sweep.log`).
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
  `benchmarks/logs/pqpage_spike.log`): pages (one AEAD blob per IVF list,
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
- **C1.2 Security comparison page (SHIPPED — docs/SECURITY_COMPARISON.md).** One table, us vs the five named
  competitors: content encryption / derived-index encryption / tamper
  evidence / verified reads / key rotation / cross-tenant crypto
  isolation / offline default / audit chain / export encryption.
  Sourced claims, dated, PR-able by competitors if they object.
  Docs page + landing block.
- **C1.3 Threat-model whitepaper (SHIPPED — docs/THREAT_MODEL.md).**
  Formalized what SECURITY.md + seal.rs already implement: eight
  adversary classes (offline reader/tamperer, cross-tenant, network,
  untrusted accelerator, exfil channels, memory poisoner, host —
  the last a stated non-goal), a layer→adversary map, verbatim-as-
  security-property, the operator custody boundary, and planned-work
  labeling for C3. Framed against the 2026 memory-attack literature
  (MINJA, AgentPoison, forged-reasoning/FragFuse). Published in the
  book as threat-model.html; linked from SECURITY.md.

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
- **C3.3 Memory-poisoning defense — write-path admission control.**
  **Phase 1 BUILT (2026-08-03): deployment-assigned wing trust classes**
  — `quarantined|standard|trusted` assigned by the operator (CLI +
  `/v1`, deliberately never MCP), HMAC-tagged and chain-audited (a
  flipped row fails verification and a floored search refuses),
  consumed as a candidate-set floor (`SearchOptions.min_trust`,
  `UNDERCROFT_TRUST_FLOOR`) riding the scope-resolved machinery —
  pinned starvation-free by a raw-premise test: a quarantined wing
  owning the corpus top-k cannot crowd out a standard wing's answer.
  This is the enforcement substrate the quarantine wing below plugs
  into. **The per-source cap SHIPPED (2026-08-03) behind its gate**:
  `keyed_sample_capped` bounds any wing at `1/UNDERCROFT_TRAIN_SOURCE_CAP`
  (default 4) of every global training draw (PQ codebook/IVF, FDE
  codebook/IVF), within-quota corpora byte-identical, soft refill never
  shrinks the sample, below-sampling-threshold deliberately inert
  (per-wing codebooks are that regime's isolation). Gates met before
  default-on: synth 16384 periodic shape 100.0/100.0, wingscale 16-wing
  scoped+unscoped 100.0% both floors. Per-writer caps still need
  admission-phase provenance.
  **Phase 2 BUILT (2026-08-03): the deterministic tier-1 detector +
  quarantine wing + audited rulings** — `undercroft_core::admission`
  (closed signal vocabulary, offsets not content, negative fixtures
  pinned), `UNDERCROFT_ADMISSION=quarantine` (default off; flagged
  saves divert sealed to the reserved wing on both save paths, the
  wing refuses forged residents, retrieval hard-excludes it except for
  the reviewer's own scope), CLI/`/v1` allow/deny with the verdict
  inside the ruling tag's canonical — never an MCP tool. Recorded
  gaps: update-path screening, deny-with-receipt (C3.2), the advisory
  LLM tier. The provenance foundation + posture are BUILT (2026-08-03):
  `agent`/`channel`/`session` claims on every save surface
  (HMAC-covered, never trusted) and `UNDERCROFT_ADMIT_TRUSTED_SOURCES`
  keyed on the surface-stamped `added_by` only — a channel CLAIM never
  bypasses the screen (pinned).
  Remaining pieces below. First-mover answer to the documented
  memory-poisoning attack class
  (MINJA, AgentPoison, forged-reasoning): screen memory **at ingest**,
  not just at retrieval, so poison never becomes retrievable while a
  human gate is pending. Full design in
  [THREAT_MODEL.md §8](THREAT_MODEL.md) (the three-zone boundary);
  the shipping mechanism:
  - **Provenance on every drawer** — writing agent / source / channel
    / session, tamper-covered by the record HMAC. This is the
    foundation the rest builds on and the cheapest first increment.
  - **Admission check on the write path** — outcomes admit /
    quarantine / reject. **Detector, two tiers**: (1) *deterministic,
    default-on, no model* — imperative-instruction patterns, embedded
    tool-call/code syntax, exfil & encoded-blob markers, provenance
    and rate anomalies, similarity to committed attack fixtures; pure
    functions over the candidate bytes + its deterministic embedding,
    so it is unit-testable as data with zero host impact. (2)
    *optional local LLM classifier, advisory-only* — can push a write
    toward quarantine, never auto-admit; hardened data-marked prompt;
    stated honestly as itself an injection target, never a gate that
    can be turned against us.
  - **Quarantine wing** — flagged writes land sealed and `pending` in
    a reserved wing, **excluded from all retrieval** (the agent never
    sees a quarantined drawer). Provenance-driven default posture:
    high-trust channels auto-admit; untrusted channels (tool output,
    scraped content, other agents) default to quarantine — keeping the
    human-review queue small and high-signal, surfaced in the admin
    console.
  - **Full lifecycle audit** — every transition is a chain-logged,
    tamper-evident event with its reason *retained across
    transitions*: `[quarantined: signal + provenance + ts + sealed
    fingerprint]` → `[allowed by Z: overrode signals N]` **or**
    `[denied by Z: reason; content deleted + keyed tombstone]`. The
    quarantine log doubles as a labeled dataset for improving the
    detector, and a pattern of quarantine events from one channel
    exposes a campaign even when each write was individually denied.
  - **Crash-safe allow/deny state machine** — the two-phase,
    open-time-reconciled pattern proven by key rotation
    (`rotate.rs`): a crash mid-decision reconciles to exactly
    pending / promoted / denied, never half. Deny rides C3.2's
    attested-forgetting path; promotion can require a C3.1 receipt.
  - **Honest boundaries (must ship in the docs)**: detection is
    heuristic — a poison from a channel you trust can still pass;
    every log stores a sealed fingerprint, never a cleartext payload
    (or the log becomes a re-injection vector); and this secures the
    memory and memory→agent zones only — the agent→host zone (an
    over-privileged agent inducing a malicious tool call) is the agent
    runtime's and OS's sandbox to enforce, the A8 non-goal. undercroft
    itself is an inert store that never executes retrieved content, so
    it is never the code-execution vector.
  - *Steps*: (1) provenance fields + HMAC coverage; (2) deterministic
    detector + attack fixtures; (3) quarantine wing + retrieval
    exclusion; (4) lifecycle audit events on the chain; (5) crash-safe
    allow/deny + admin-console review flow; (6) provenance posture
    policy; (7) optional LLM-classifier tier behind a flag. *Gate*:
    attack-fixture corpus quarantined at a target rate with a bounded
    false-positive rate on clean LoCoMo ingest; crash-window tests for
    the state machine; e2e scripted-attacker run over `/v1`.
  - *Effort*: ~2 releases (provenance + deterministic gate first;
    classifier tier and posture policy second).
- **C3.4 Post-quantum posture.** The stack is symmetric-first, so most
  of it is **already PQ-safe by construction**: XChaCha20-Poly1305
  sealing (256-bit keys — Grover-limited to ~128-bit effective, the
  accepted PQ bar), HMAC-SHA256 tags/chain/tokens/assertions,
  HKDF/Argon2id derivation. The **single quantum-vulnerable spot in
  the codebase** is `bundle.rs`'s X25519 exchange — exported bundles
  are exposed to harvest-now-decrypt-later. Ship: (1) hybrid KEM
  (X25519 + ML-KEM-768) bundle format, old format still importable;
  (2) a PQ posture page documenting the inventory above plus
  deployment guidance (hybrid-KEM TLS at the reverse proxy) and the
  release-signing path; (3) the honest boundary stated in writing —
  this is quantum-resistant **cryptography**; "quantum processing"
  for retrieval is vapor and we do not claim it. Competitors would
  have to retrofit PQ onto stacks they haven't encrypted at all; we
  touch one file. *Gate*: bundle round-trip + downgrade-refusal
  tests; RustSec-clean ML-KEM dependency (FIPS 203 final).

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
