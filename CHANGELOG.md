# Changelog

## 0.31.0 — Bulk-ingest transaction batching

Follow-up to v0.28.0's durability work, which made every commit a real
disk sync and exposed that one drawer write paid **several syncs**
(row+chain transaction, then each advisory derived-index statement as
its own implicit transaction, plus the manifest anchor).

- **New `PalaceStore::upsert_many`**: a batch of drawers commits in
  **one transaction** — rows, audit-chain advances, and derived-index
  writes (PQ codes, token matrices, FDEs) all join it — and the
  manifest anchors once after the commit. A mid-batch failure rolls the
  entire batch back (the existing palace is untouched); the anchor
  still never runs ahead of the database.
- **CLI bulk paths batched** (256/chunk): `import`, `mine` (files and
  convos), `sweep`, and the daemon's sweep loop. Single-drawer
  `remember` and the server save paths are unchanged. Duplicate
  detection gains an in-batch set so unflushed duplicates are still
  skipped.
- **Measured** (same binary, same container, back-to-back): importing
  200 drawers into a sealed vault = **26 fsyncs total (0.13/drawer)**
  vs ~7 fsyncs/drawer on the per-item path — **~55× fewer disk
  syncs** — completing in 0.7 s with `VERIFY OK` and the chain intact.
- Durability semantics preserved: `synchronous=FULL` still syncs every
  commit; batching changes how many commits there are, not whether
  they reach disk.

## 0.30.0 — Recipient-encrypted export bundles

The second ecosystem item: `undercroft export --to <recipient>` seals the
export so a backup or migration file **never exists in plaintext**.

- **`bundle keygen`**: X25519 recipient identity — the secret key goes
  to a private file (0600, refuses overwrite), the shareable public
  recipient string prints once. `bundle recipient <keyfile>` re-prints
  it.
- **`export --to <recipient> --out <file>`**: age-style construction —
  fresh ephemeral X25519 key per bundle, file key =
  HKDF-SHA256(salt = eph_pub ‖ recipient_pub, ikm = DH, info =
  `undercroft.v1/bundle`), payload sealed XChaCha20-Poly1305 with the
  magic + ephemeral key bound as AAD (a spliced header fails to open).
- **`import <bundle> --identity <keyfile>`**: bundles are detected by
  magic; plaintext JSONL imports are unchanged. Wrong identity or a
  tampered file is a clean refusal, not a partial import.
- The bundle identity is unrelated to the palace's at-rest keys —
  compromise of one does not touch the other.
- New dep: `x25519-dalek` 2 (pure Rust, zeroize-on-drop secrets), in
  `undercroft-vault` only.
- Tests: roundtrip, wrong-identity, tamper + header-splice, per-bundle
  ephemeral freshness, junk-input errors; e2e +6 checks (keygen →
  sealed export → not-plaintext assertion → import-needs-key →
  identity import → wrong-key refusal → overwrite refusal).

## 0.29.0 — Key rotation

`undercroft vault rotate <name>`: move a vault onto fresh derived keys
in place — first of the two ecosystem items (recipient-encrypted export
bundles are next).

- **Fresh salt ⇒ fresh enc/mac/manifest keys** (HKDF re-derivation);
  every AEAD blob is re-sealed **byte-exact at the seal layer** — no
  decompress/requantize round trips, AAD domains preserved — across all
  sealed stores: drawer content + embeddings, KG triple objects, ColBERT
  token matrices, PQ code rows + codebook + IVF centroids, FDE rows +
  params + codebook. Every HMAC tag (drawers, KG, tunnels), keyed
  fingerprint, and the audit chain are re-keyed.
- **Single-transaction, crash-safe anywhere**: the next manifest is
  staged durably as `vault.json.next`, the re-seal transaction flips a
  `keycheck` marker as its committed witness, and open-time
  reconciliation either promotes the staged manifest (crash after
  commit) or discards it (crash before) — a crashed rotation is never a
  tamper alarm, and the palace always opens under exactly one key
  generation.
- **Audit history semantics**: tags of superseded/deleted content are
  preserved verbatim (their plaintext is gone by design); the chain over
  them is what rotates. `verify` replays the same bytes to the new head.
- Remote-index copies hold old-key ciphertext after a rotation — the CLI
  reminds you to re-run `index push`.
- Tests: full-fidelity rotation on both vault levels (drawers, KG,
  tunnels, dedup fingerprints, cold reopen), plus both crash windows
  (staging discarded / staging promoted). e2e: rotate → verify → search
  → KG → dup-lookup → rotate again, 8 new checks.

## 0.28.0 — Ingest durability (fsync)

The durability refinement queued since the audit-chain atomicity work
(v0.19.0): every acknowledgement now implies bytes on disk, and a power
loss can only produce the healed crash case — never a false tamper
alarm.

- **SQLite pinned to WAL + `synchronous=FULL`** (was the compile-time
  default): the data+chain commit reaches disk before its post-commit
  manifest anchor possibly can, so the anchor can end up equal or
  *behind* the database (open-time reconciliation fast-forwards) but
  never *ahead* (which reads as rollback/tamper).
- **Manifest anchor written durably**: fsync the temp file before the
  atomic rename, fsync the directory entry after — a torn or reordered
  `vault.json` after power loss can no longer masquerade as tamper.
- **Key material fsynced at creation** (master key, KDF salt): written
  once, unrecoverable if lost.
- **Orchestrator control-plane db** gets the same WAL + FULL pin: a
  tenant token is shown exactly once — the row recording its HMAC must
  survive the moment it is acknowledged, as must a migration flip.
- Tests: pragma pins asserted on both engines' connections (both vault
  levels) and the anchor's durable-replace path leaves no temp file.

## 0.27.0 — ONNX Runtime backend in the CLI

The measured ORT wins (reranker ~100–160× end to end, ColBERT 96.7 →
70.3 ms/q, ingest embed ~4–5×) existed only behind the bench harness;
this release wires them into the `undercroft` binary for real
deployments.

- **New `ort` cargo feature on `undercroft-cli`** (opt-in, like `onnx`):
  links `undercroft-embed-ort` and exposes the backend at runtime —
  - `UNDERCROFT_EMBEDDER=ort` — session-pool sentence embedder;
  - `UNDERCROFT_RERANKER=ort` — cross-encoder scoring the whole pool in
    one batched forward (`score_batch` forwarded end to end);
  - `UNDERCROFT_RERANKER=colbert-ort` — the ColBERT late-interaction
    encoder (search + `repair --tokens` backfill).
  Same user-supplied model files and `UNDERCROFT_ONNX_*` / `RERANK_*` /
  `COLBERT_*` variables as the tract backend — switching runtimes is
  one env change, no re-ingest (identical weights ⇒ identical vectors).
- **Multi-tenant `/v1` server**: `ort` embedder and reranker load
  **once** and are shared across every tenant vault (the ORT session
  pool holds a model copy per core — per-vault loads would multiply
  RAM for identical weights). ColBERT stays single-vault-serve only,
  now with an explicit error instead of "unknown value".
- `ort-build` compose service now compile-checks the full CLI with
  `--features onnx,ort` (both backends coexisting) instead of the
  backend crate alone.
- Unknown-value errors for `UNDERCROFT_EMBEDDER` / `UNDERCROFT_RERANKER`
  enumerate the new values; docs updated (README, RETRIEVAL_SCALING,
  website retrieval page).

## 0.26.0 — Orchestrator hardening

The follow-ups queued at v0.25.0, minus one deliberately deferred.

- **Token rotation**: `POST /admin/tenants/{id}/rotate` + `tenant-rotate`
  CLI — a fresh token is minted and the old one revoked **in the same
  statement** (rotation is the revocation primitive; no grace window).
  Shown once, like at create.
- **Per-tenant rate limiting** (`UNDERCROFT_ORCH_RATE_LIMIT`,
  requests/minute, off by default): fixed-window, keyed per tenant,
  applied on the data plane after token resolution — one noisy tenant
  429s, the rest are untouched.
- **Deployment hardening docs** (MULTI_TENANCY.md): TLS via reverse
  proxy on both hops, loopback defaults, secrets hygiene, state
  backup, and the documented **single-writer stance** — multi-
  orchestrator replication is deferred until a fleet needs it, with the
  likely shape (read-replica proxy) recorded.
- Verified: 9 unit tests (+ rotation revocation, per-tenant/per-window
  limiter), e2e grown to **30 checks** including a deterministic
  burst-over-limit test (8 rapid requests across ≤2 windows guarantee a
  429 — no timing flake) and old-token-revoked-immediately.

## 0.25.0 — Multi-tenant orchestrator

The control plane docs/MULTI_TENANCY.md reserved: routing, tenant→vault
mapping, token minting, and live migration for fleets of engine
instances, shipped as the **separate optional `undercroft-orchestrator`
binary**. It is a pure client of the public `/v1` surface — the engine
stays tree-blind and never links it.

- **State** (own SQLite): instance registry + tenant→vault map. Engine
  credentials are **sealed at rest** (XChaCha20-Poly1305 under
  `UNDERCROFT_ORCH_KEY`, AAD-bound to the instance name — a blob copied
  onto another row fails to open); tenant tokens are **never stored**
  (domain-separated HMAC only; the token appears once, in the create
  response).
- **Data plane** `/t/<subpath>`: a tenant token routes to exactly its own
  vault as `/v1/vaults/{vault}/<subpath>` with the engine bearer + a
  freshly minted per-vault assertion; the subpath allowlist keeps vault
  lifecycle off the data plane (the vault root is unroutable). Even a
  routing bug downstream fails cryptographically — assertion and vault
  AAD both carry the vault id.
- **Admin plane** `/admin/*` (`UNDERCROFT_ORCH_ADMIN_TOKEN`, uniform
  401s): instance add/list/remove (+ live health probes; removal refused
  while tenants map to it), tenant lifecycle with least-loaded placement,
  and **migration**: artifact-carrying export (v0.18) → import →
  **count-verified** → mapping flip → source delete (`keep_source` opts
  out); any failure before the flip leaves the source authoritative.
- **CLI** mirrors the admin plane (`instance-add`, `tenant-create`,
  `migrate`, …) plus `keygen`; the runtime image now carries both
  binaries.
- **Verified**: 7 unit tests (AAD binding, wrong-key unsealable, token
  MAC resolution, placement + removal guard, assertion contract, subpath
  allowlist) + a 24-check e2e suite (`orchestrator-e2e` compose service)
  running two live engine instances through the whole story, including a
  migration after which the source engine provably no longer serves the
  vault.

## 0.24.0 — Bounded-RAM FDE tier (PQ codes)

The v0.23.0 honest-limits follow-up: FDE rows now upgrade event-driven
exactly like the token store. Raw f32 (v1) below `UNDERCROFT_FDE_PQ_MIN`
(256; `off` disables), then a codebook trains from the palace's own FDEs
(persisted sealed in `fde_meta`), every row repacks to `dim/8`-byte PQ
codes — **32× smaller** (8 KB → 256 B/drawer) — and the scan switches to
per-query dot-product LUTs. Legacy v0.23.0 rows are recognized and repack
in the same pass; a row that fails to open deletes back to "missing" and
the next backfill recreates it.

Measured (`fde-synth`, exact-MaxSim ground truth):

- Candidate containment stayed **perfect through the compression at every
  size** (exact top-10 ⊆ coded top-100 = 100% at N=2k/50k/200k), with the
  ADC scan ~8× faster than the raw dot scan (11.5 vs 97.3 ms/q @50k;
  33.2 vs 275.8 @200k) and RAM down 32× (51 MB at N=200k).
- End-to-end LoCoMo gate holds exactly: R@10 96.5% — the **identical
  1913/1982 for the fourth consecutive configuration** (fusion, raw FDE,
  PQ-coded FDE) — at 61.2 ms/q, parity-within-noise vs raw FDE's 52.9
  (the fixed per-query LUT build offsets ADC savings at small per-store
  corpora; the 256-row threshold keeps small palaces raw for exactly this
  reason).
- **IVF over FDE space: measured net-negative and deliberately not
  shipped** — it lost containment (0.84–0.99) *and* cost more than the
  flat ADC scan it replaced at every benchable size (the RAM-side list
  filter is O(N·nprobe)). The v2 pack format reserves a list field inside
  the sealed blob so a future properly-inverted tier (pays past ~10⁶
  docs) needs no migration. The bench cells recording this stay in
  `fde-synth`.

## 0.23.0 — MUVERA FDE candidate generation

The v0.22.0 research note, implemented and measured: token-aware candidate
generation through **fixed-dimensional encodings** (arXiv:2405.19504) —
each drawer's ColBERT token matrix compresses into one 2048-dim vector
whose dot product approximates MaxSim.

- **`undercroft-core/src/fde.rs`**: seed-deterministic, dependency-free
  MUVERA construction (SimHash buckets; query-side sums, doc-side
  centroids with Hamming `fill_empty_clusters`; ±1 projection). Same
  `(seed, params, dim)` ⇒ bit-identical encoders — restores keep scoring.
- **`undercroft-store/src/fdeidx.rs`** (`UNDERCROFT_RETRIEVAL=fde`):
  `drawer_fde` rows written from the token matrix already in hand at
  ingest, AEAD-sealed on sealed vaults (`/tok` domain, `fde/{id}` labels);
  params sealed in `fde_meta`; event-driven backfill from stored matrices
  (pure arithmetic, no transformer); load-once RAM cache; FDE dot
  candidates ahead of fusion, MaxSim rescore unchanged. The query forward
  is **shared** between candidate generation and rescore (the first run
  measured the duplication: 95.5 ms/q → 52.9 after the fix).
- **Measured, end-to-end** (LoCoMo full 1,982 QA, ort colbert + tok-PQ
  LUT): R@10 **96.5% — question-for-question identical** to the fusion
  baseline (1913/1982 both) at **52.9 vs 70.3 ms/q (−25%)** — the FDE head
  prunes the hydrate+verify pool that v0.21.0 measured as the dominant
  cost.
- **Measured, mechanics at scale** (`undercroft-bench fde-synth`, exact
  MaxSim ground truth): exact top-10 ⊆ FDE top-100 = **100% at N=2k, 50k,
  and 200k**, at 38–40× below exact scan cost (64 ms/q @50k, 246 @200k;
  8 KB/drawer RAM). FDE-alone top-10 ~60% — the MaxSim rescore stays, by
  design.
- Honest limits documented: the FDE scan is linear and the cache is
  O(corpus) RAM; the designed next tier is PQ/IVF over the FDEs (they are
  ordinary vectors — the bounded-RAM machinery composes directly).

## 0.22.0 — Unified PQ cache, HNSW ef-scaling, MUVERA note

Three follow-ups from the retrieval-scaling track, each measured.

- **PQ scan unified on the RAM code cache (both vault levels).** hmac-only
  vaults now ADC-scan the same load-once cache the sealed tier uses instead
  of streaming codes from SQLite per query. Honest result: a controlled
  before/after at N=20k/50k measured **parity within run-to-run noise**
  (hmac 36.1→34.1 q/s @20k, 14.3→15.2 @50k, while *unchanged* sealed cells
  swung ±8–10% between the same runs; recall identical everywhere) — the
  earlier loaded-host run that suggested a cache win did not reproduce.
  Kept for the simplification: one scan path, no per-query SQLite
  iteration, coherent cache updates from plaintext in hand.
- **HNSW recall collapse fixed.** Root cause: the store requests ≥256
  candidates but `instant-distance` builds with `ef_search=100` — every
  query tail came from an exhausted beam. `ef_search` now scales ~n/64
  (floor 320, cap 1024), `ef_construction` ~n/256. Measured: R@5
  93.1→**98.8%** at N=20k, 71.7→**96.3%** at N=50k, at 126–186 q/s (the
  bigger beam trades raw q/s for recall that degrades gently instead of
  collapsing); LoCoMo real-data parity with the full scan (R@10 94.6%
  both, 6.7 vs 5.3 ms/q). The `hnsw` feature stays experimental/off by
  default — O(corpus) RAM.
- **MUVERA research note** (docs/RETRIEVAL_SCALING.md): fixed-dimensional
  encodings as the honest "beyond MaxSim" candidate — token-aware
  candidate generation through the existing single-vector PQ/IVF + sealing
  machinery, attacking the store-side rescore cost v0.21.0 measured as
  dominant. Deliberately deferred below multi-million-drawer scale.

## 0.21.0 — ColBERT forwards on ONNX Runtime

The v0.20.0 follow-up: `OrtColbert` moves the ColBERT query/doc forwards
onto the opt-in ONNX Runtime backend. Same fixed-shape exports, same
`[Q]`/`[D]`/`[MASK]` framing, same `UNDERCROFT_COLBERT_*` env as the tract
encoder — only the runtime changes, and the bench prefers ORT over tract
when both features are built (matching the embedder/reranker precedence).

Measured (LoCoMo full 1,982 QA, hash embedder + colbertv2.0, same host):

- **Search 96.7 → 70.3 ms/q** with the token-PQ LUT (tract → ORT); ingest
  doc-encode phase **821 → 246 s (3.3×)**. Recall gate ≥96.5 met: 96.5%
  (1913/1982), and on the int8-MaxSim path recall is **identical** to tract
  (1918/1982 both) — runtime-invariance confirmed exactly.
- **The LUT win is unmasked as v0.20.0 predicted**: token-PQ LUT was +4 ms
  *slower* than int8 MaxSim under tract, and is **11 ms faster** under ORT
  (70.3 vs 81.6 ms/q).
- Honest correction to v0.20.0's estimate: the tract→ORT int8 delta shows
  the seq-32 query forward was ~11 ms of search, not ~80 ms — the residual
  ~70 ms/q is **store-side** (token fetch/decode + MaxSim + fusion), now
  the dominant term and the next optimization target.

Internal: `run_batch` gains a sequence-length parameter (the query export
is 32 tokens, not the embedder/reranker's 256).

## 0.20.0 — Token-store PQ & LUT MaxSim

Restore economics tier 3 — the PLAID move on our own primitive. The
late-interaction token store compresses **8.2×** (16 PQ bytes per token vs
128 int8 — a ~150-token drawer drops 19.8 KB → 2.4 KB) at **−0.2 pts** on
LoCoMo (96.57% vs 96.77%, above the ≥96.5% gate).

- **v2 pack format**: per-token PQ codes (`pq.rs` re-used at `m=16`). The
  codebook trains event-driven from the vault's own stored matrices once
  they cross `UNDERCROFT_TOK_PQ_MIN` (default 256; `off` keeps int8),
  persists **sealed** in `tok_meta` like every derived artifact, and every
  stored v1 row repacks in the same pass — no transformer forwards, no
  migration event; v1/v2 coexist and rescoring reads both.
- **LUT MaxSim**: per query row, dot-product tables over the codebook are
  built once (for all candidates); scoring a candidate token is then 16
  table adds instead of a 128-dim dot product (`dot_tables`/`adc_dot`).
  Honest timing note: LoCoMo search is 96.7 vs 92.7 ms/q — the bench
  amortizes each store's one-time train+repack into its query phase, and
  the ~80 ms tract query forward dominates either way; the LUT win becomes
  visible when the `ort` query-forward follow-up (~40 ms) lands.
- **Punctuation pruning** (ColBERT convention): doc-side punctuation rows
  attend normally but are excluded from the stored matrix.
- **Portable artifacts stay universal**: v2 matrices export decoded back to
  v1 int8 — the codebook never leaves the vault; imports work anywhere.

## 0.19.0 — Atomic audit chain

Durability: the last known correctness gap. The audit-chain head used to
live only in the vault manifest, written *after* the SQLite commit — so a
power loss in between left the chain and the data disagreeing, and the next
`verify` raised a **false tamper alarm** for a mere crash. Worse, several
mutation paths (delete, KG, tunnels) didn't even wrap their own data+audit
statement pairs in a transaction.

- **The committed head now lives in SQLite** (`chain_meta`) and advances via
  `chain_append` **inside the same transaction** as the data and audit row
  it covers — at all six mutation sites (drawer write, drawer delete, KG
  add, KG supersede/invalidate, tunnel create, tunnel delete). A crash can
  never separate a record from its chain entry.
- **The manifest becomes a lagging out-of-database rollback anchor**
  (`Vault::anchor_manifest`, written post-commit). Open-time reconciliation
  distinguishes the two failure shapes: an anchor **behind** the database
  chain is a crash artifact and is fast-forwarded silently; an anchor the
  database chain **never produced** means the database was rolled back or
  forked — `ManifestTampered`. A power loss is not a tamper alarm; a
  restored old database still is (both crash states are test-simulated).
- `verify` applies the same two-part check: audit rows must reproduce the
  committed head exactly, and the anchor must appear in that chain.
- Vault API: `commit_write` is replaced by pure `chain_next_hex` +
  `chain_genesis_hex` + `anchor_manifest` (the store owns *where* the head
  lives; the vault owns the key). Existing databases adopt `chain_meta`
  from the manifest on first open — no migration step.
- Known residual (documented): an attacker replacing db **and** manifest
  together with a mutually-consistent older pair remains undetectable
  without an external witness — unchanged from before, noted for a future
  remote-anchor option.

## 0.18.0 — Portable derived artifacts & token backfill

Restore economics, tiers 1–2. Token matrices are the expensive derived data
(one transformer forward per drawer — ~2 h per 20k drawers on tract) and a
pure function of `(content, model)`: legitimate content-addressed cache. So
migrations now carry them, and palaces that don't have them recover in
bounded background passes instead of blocking.

- **Portable artifacts**: `/v1` export lines gain optional
  `tok = {model, b64(packed)}`; import validates in the parse phase
  (bad artifacts fail the whole body cleanly) and re-seals each matrix
  under the **destination** vault's key. Store API:
  `token_artifact(id)` / `import_token_artifact(id, model, packed)`.
  Safe by construction: artifacts are advisory, model-matched at rescore
  time, and results are still HMAC-verified — a wrong or malicious
  artifact can only mis-rank, never forge. Test-asserted: a destination
  whose encoder panics on any doc-encode rescores correctly from imported
  artifacts alone, with at-rest bytes differing from both the source's and
  plaintext.
- **Bounded backfill**: `undercroft repair --tokens` (store:
  `late_backfill(limit)`) encodes drawers missing a matrix under the
  attached encoder's model, in batches — a restored or pre-encoder palace
  serves at fusion quality immediately and climbs to late-interaction
  quality as coverage grows.

## 0.17.0 — Sealed-tier encrypted-at-rest index

Sealed vaults had one retrieval mode: decrypt-scan every embedding on every
query. They now run the full PQ/IVF prefilter under the same invariant —
**nothing plaintext-derived ever touches sealed disk in clear** — and search
went from **2.1 → 33.4 q/s at N=20k (×16)** and 1.1 → 11.8 at 50k (×11), at
parity with the plaintext hmac-only index. Encryption stops being a
query-time cost.

- **Sealed index storage** (`Vault::index_at_rest`/`index_from_rest`, `/pq`
  AAD domain): every code row is sealed as `(list ‖ code)` bound to its row
  seq; the codebook and IVF centroids in `pq_meta` are sealed under synthetic
  record ids. The plaintext `list` column stays `-1` on sealed vaults — a
  clear list id would leak which drawers are semantically similar. Identity
  transform on hmac-only vaults, so existing indexes read unchanged.
- **Decrypt-once RAM cache**: search decrypts all rows one time per open
  (~52 B/drawer — 2.6 MB at N=50k, bounded) and ADC-scans + IVF-probes in
  RAM; writes keep the cache coherent with the plaintext in hand, deletes
  drop it. At N=50k the cache even out-ran the hmac path's per-query SQLite
  streaming — adopting the same cache for hmac-only is a noted follow-up.
- **Threat model**: an offline attacker sees fixed-size sealed blobs — i.e.
  the drawer count already visible from the drawers table. Nothing about
  content, similarity, or cluster structure.
- **Invariant test strengthened, not relaxed**: sealed vaults may now hold
  the PQ tables, but no row contains a plain code, the metadata doesn't
  decode without the vault key, list ids are never in clear, and results
  agree with the decrypt-scan baseline across a cache rebuild. e2e
  re-asserts the at-rest plaintext grep with the index present.
- `set_pq` / `UNDERCROFT_RETRIEVAL=pq` now applies to both security levels.
- Docs: sealed-tier measured tables, and a new **"Restore economics"**
  design section (portable content-addressed derived artifacts, background
  backfill, token-store PQ with register-LUT MaxSim — the roadmap for
  fast shard restore).

## 0.16.0 — ColBERT late interaction

The core-count-independent second retrieval stage. The cross-encoder reranker
runs one transformer forward per candidate per query — great on 24 cores,
painful on 4. Late interaction moves that work to ingest: each drawer is
encoded **once** into a per-token embedding matrix; a search encodes the query
in **one** forward and re-scores the fusion top-N by MaxSim over the stored
matrices. **Measured (LoCoMo, full 1,982 QA, hash embedder + colbertv2.0 on
tract): 94.6 → 96.77% R@10 at a flat 92.7 ms/query** — the same on any core
count, where the cross-encoder's 97.68% costs 101–327 ms on 24 cores and ~5×
that on 4. Off by default; the cross-encoder wins when both are configured.

- **`LateInteraction` trait + MaxSim kernel + int8 token pack**
  (`undercroft-core/src/late.rs`): row-major unit-row matrices, per-row-scale
  int8 quantization (~4× smaller, scores within noise — round-trip tested).
- **`OnnxColbert`** (`undercroft-embed-onnx`, `onnx` feature): tract-run, two
  fixed-shape plans (query 32, doc 256), faithful ColBERT v2 conventions —
  `[Q]`/`[D]` marker tokens and attending `[MASK]` query augmentation.
  Models are user-supplied: `UNDERCROFT_RERANKER=colbert` +
  `UNDERCROFT_COLBERT_MODEL` (doc export) / `_QUERY_MODEL` / `_TOKENIZER`.
  **Export recipe matters**: fixed-shape legacy exports only — the dynamo
  exporter's symbolic dims and dynamic-axes `Range` ops both fail in tract
  (recipe in docs/RETRIEVAL_SCALING.md).
- **Sealed-tier encrypted-at-rest token store**: `Vault::tokens_at_rest`
  seals every matrix under a `/tok` AAD domain (distinct from content and
  `/emb` — one drawer's blobs can never be swapped). Sealed vaults get the
  full feature: the first plaintext-derived store that is allowed on sealed
  disk, because it is never in clear (test-asserted at both levels). The
  hmac-only/plain vs sealed/encrypted tiering mirrors the rest of the stack.
- **Store stage** (`undercroft-store/src/latestage.rs`): advisory write-time
  encode (a drawer written before the encoder was attached keeps its fusion
  rank — never sunk); MaxSim normalized onto the fusion score scale;
  `delete_drawer` purges the matrix.
- Wired through the CLI (search / serve-mcp / daemon) and the bench harness
  (shared encoder across per-question palaces).

## 0.15.0 — IVF inverted lists & the PQ scan-path fixes

IVF partitioning on top of the v0.14.0 PQ codes — and, more consequentially,
the three structural scan-path costs that benchmarking it exposed and removed.
Net effect (synthetic corpus, hmac-only, within-run comparisons): **flat PQ
~45% faster at N=20–50k** (23.9 → 34.4 q/s at 20k, 10.1 → 14.8 at 50k) with
IVF adding **+7–11% on top at exact recall parity** (99.6%/99.1% R@5), a share
that grows with corpus size — the probed scan is the only query cost that
scales with N.

- **IVF inverted lists** (`pqidx.rs` + `CoarseQuantizer` in `pq.rs`):
  `nlist ≈ √N` deterministic k-means centroids partition the corpus; a query
  ADC-scans the `nprobe` nearest lists. Non-residual — codes are unchanged;
  probes that return fewer than `k` rows widen to the flat scan, so IVF can
  narrow the candidate set but never empty it. On by default above
  `UNDERCROFT_IVF_MIN` (8192, `off` restores flat), probe count via
  `UNDERCROFT_IVF_NPROBE` (default `nlist/4` — recall tracks the probed
  *fraction*: 3% → 68.7%, 11% → 86.9%, ~25% → parity). Partitions persist in
  `pq_meta`, self-heal, and retrain when the corpus doubles past their
  training size. hmac-only vaults only, unchanged invariant.
- **Scan-path fixes** (each exposed by a measured sweep, each re-measured):
  codes physically clustered `WITHOUT ROWID, PRIMARY KEY (list, seq)` — a
  probed list is one sequential range scan, not per-row B-tree fetches
  (which had made a 23%-fraction probe *slower* than the flat scan);
  coherence verification is **event-driven** (first search after open or
  after a failed encode — never per query; the guard join was costing more
  than the scan it guarded); the ADC scan reads `drawer_pq` alone
  (`delete_drawer` purges its code row; the per-row `JOIN drawers` existed
  only for delete-orphans, which hydration filters anyway). v0.14.0 tables
  migrate in place.
- **CLI + `/v1` wiring**: `UNDERCROFT_RETRIEVAL=pq|hnsw` now works in the
  `undercroft` binary (search / serve-mcp / daemon) and per-tenant in the
  multi-tenant server — previously bench-only. `hnsw` requires the new cli
  `hnsw` pass-through feature and errors clearly without it. +5 e2e checks
  including the sealed-vault no-PQ-tables invariant on disk.
- **Bench**: `synth --queries N` caps the query phase to an even sample so
  large-N sweeps finish in minutes; recall is reported over the sampled
  queries.
- Docs: RETRIEVAL_SCALING / RESULTS "every lever" / the public retrieval
  page updated with the full fix ladder and final tables.

## 0.14.0 — Retrieval performance & scaling

The retrieval-performance track: every configurable lever measured end to end
(LoCoMo + synthetic corpora, 24-core host, in Docker), and the expensive ones
retired. Headline: the optional cross-encoder reranker drops **16.6 s → 101–327
ms per query at ~98% R@10**, and large hmac-only corpora get a bounded-RAM
on-disk ANN prefilter. Everything is opt-in; default search behaviour and the
default build are unchanged.

- **Reranker latency, step by step** (302-QA LoCoMo subset, R@10 ≈98%
  throughout): rayon-parallel scoring across cores (16.6 s → 694 ms) →
  `UNDERCROFT_RERANK_TOP_N` is now a true rerank-pool cap (accuracy plateaus at
  ≈20; a real latency knob) → `Reranker::score_batch` becomes the whole-pool
  trait interface so the backend owns parallelization → ONNX Runtime backend +
  int8 models take top_n=20 to **327 ms** and top_n=5 to **101 ms**.
- **New `undercroft-embed-ort` crate**: an ONNX Runtime inference backend
  (embedder + reranker) as an opt-in alternative to the pure-Rust tract
  default (~2.5× faster per forward, identical scores; C++ dependency — see
  the `ort-build` compose service). Session pool sized to cores
  (`UNDERCROFT_ORT_POOL`; `pool=1` = batched mode for few-core boxes). int8
  quantized models (4× smaller files, user-supplied, no code change) attack
  the memory-bandwidth bound; ingest embedding drops 24 s → ~5 s.
- **On-disk Product-Quantization prefilter** for hmac-only vaults: 48-byte PQ
  codes per drawer (`drawer_pq`) + a ~400 KB codebook (`pq_meta`), incremental
  encode on write, count-mismatch self-heal on open. Recall is *flat in corpus
  size* (98.6% at N=20k → 98.9% at N=50k) with codebook-only RAM, while
  in-memory ANN recall collapses untuned. Opt-in via
  `PalaceStore::set_pq(true)` (bench: `UNDERCROFT_RETRIEVAL=pq`). **Sealed
  vaults are untouched** — the no-plaintext-derived-index-on-disk invariant
  holds and is test-asserted; CLI wiring is a follow-up.
- **Experimental in-memory HNSW prefilter** (`hnsw` feature, off by default):
  fastest option measured (378 q/s at N=50k) but O(corpus) RAM and recall
  needs `ef`/over-fetch scaling with N — kept as a raw-speed option, RAM-only,
  never persisted.
- **Multi-tenant `/v1` shared-model reranker**: the tenant server loads one
  ONNX model and hands every per-vault store an `Arc` handle
  (`Tenancy::with_reranker`), closing the v0.13.0 follow-up.
- **Benchmarks**: full sharded LoCoMo reranker run — R@10 **94.6 → 97.68**
  (1936/1982); conversation-scoped `--skip`/`--limit` sharding +
  machine-readable `LOCOMO_RAW`/`LME_RAW` numerator lines; per-phase
  `LOCOMO_TIMING` (ingest vs search); `--backend` for measuring remote
  vector backends (confirmed idle untrusted accelerators — never a latency
  or accuracy lever).
- **Docs**: `docs/RETRIEVAL_SCALING.md` (architecture + every measured
  number + the IVF/ColBERT plan), the public "Retrieval, scoring & scaling"
  site page, `docs/MULTI_TENANCY.md`, and the `benchmarks/RESULTS.md`
  "every lever" section with scenario recipes.
- `.gitattributes` forces LF checkout (Windows clones broke bind-mounted
  scripts inside the Docker test containers).

## 0.13.0 — Cross-encoder reranker

An optional second retrieval stage. After hybrid search's cosine+BM25 fusion
ranks a candidate pool, a cross-encoder re-scores the top-N with the full
`(query, passage)` pair — the interaction a bi-encoder embedding can't capture —
and re-orders them before the final `limit` cut. Off by default; when unset,
search behaviour is byte-for-byte unchanged.

- **`Reranker` trait** (`undercroft-core`) + **`OnnxReranker`**
  (`undercroft-embed-onnx`, under the existing `onnx` feature) — reuses the
  tract/tokenizer machinery, pair-encodes, reads the relevance logit, sigmoids.
  Model is **user-supplied**: `UNDERCROFT_RERANK_MODEL` / `_TOKENIZER` +
  `UNDERCROFT_RERANKER=onnx`. `UNDERCROFT_RERANK_TOP_N` (default 50) bounds latency.
- Wired into `search`, `serve-mcp`, the daemon, and the `longmemeval`/`locomo`
  benchmark harness. Pairs with either embedder (hash or ONNX).
- **Targets BERT-family cross-encoders** (`cross-encoder/ms-marco-MiniLM-L-6-v2`):
  tract 0.22 can't run DeBERTa rerankers (mxbai-rerank hits an unsupported `Sign`
  op), so that's the shipped default.
- **Directional lift** (subset smoke, hash embedder + ms-marco reranker, real
  data): LongMemEval-S R@5 **98.3 → 100.0** (60-question subset), LoCoMo R@10
  **94.6 → 97.2** (full 1,982 QA). The full sharded LongMemEval-500 +
  MiniLM-embedder matched-model run and the landing headline bars are a
  follow-up; the multi-tenant `/v1` reranker pairs with the shared-model item.

## 0.12.0 — Full observability & alerting stack

Metrics were already there; this turns `deploy/observability/` into the full
operability picture — **logs, traces, and alerting** — and adds a tamper
runbook. No API or on-disk format changes; default (non-telemetry) builds are
unaffected.

- **Distributed traces.** New metadata-only spans on the request/search/save/KG
  hot paths (`undercroft-obs`; zero-dep no-op without `--features telemetry`),
  exported over OTLP to **Tempo**. Spans carry operation, route, and vault id —
  never query text, drawer content, wing/room names, or keys.
- **Alerting.** **Alertmanager** + Prometheus rules: `PalaceTamperDetected`
  (critical, broken out by `surface`), `AuditChainStalled`, `UndercroftDown`,
  `HighSearchLatencyP95`, `HttpServerErrors`, `AuthRejectionsSpike`. Routed to a
  self-contained webhook `alert-sink` (swap in Slack/email/PagerDuty).
- **Logs.** **Loki** + promtail ship Undercroft's structured JSON logs
  (`UNDERCROFT_LOG_FORMAT=json`) — metadata only.
- **Grafana.** Loki/Tempo/Alertmanager datasources; the dashboard gains
  tamper-by-surface, HTTP 5xx, auth rejections, an active-alerts table, logs,
  and traces panels. A `grafana-image-renderer` sidecar enables PNG export.
- **Tamper runbook** (`RUNBOOK.md` + docs) — where it happened, and how to
  confirm (`verify`), mitigate (`--read-only`, preserve evidence), fix (verbatim
  restore from `backup`), and prevent. The alert's `runbook_url` links to it.
- **Fixes surfaced while wiring this up:** the OTLP→Prometheus exporter emitted
  double-`_total` counter names (`without_counter_suffixes`), and OTLP traces
  posted to the base URL instead of `/v1/traces` (404); both fixed. The
  observability compose now initializes the palace before `serve-http`.
- **Site.** Landing gains an "Operate it" section; observability docs gain
  alerting/logs/traces sections with real screenshots.

## 0.11.1 — Palace Monitor fixes

Bug fixes to the Palace Monitor UI (`GET /monitor`), plus a website section
showcasing it with real screenshots. No API or on-disk changes.

- **Archivist now animates.** Search events no longer freeze the archivist in
  its `read` pose (under load it was permanently stuck); filing walks run
  uninterrupted, the walk-cycle bob is fixed (it checked states that never
  existed), and the archivist gently wanders between wings during lulls.
- **Speed slider works.** It now scales the whole simulation tempo instead of
  only the (previously frozen) archivist. The tamper beacon's real-time
  duration stays unscaled.
- **Sound button works.** A confirmation chirp on enable plus throttled soft
  ticks on live save/search events, alongside the existing tamper siren.
- **Drawer tiles grow with writes.** The per-wing grid uses an absolute
  log-scale fill so it visibly fills as a wing accumulates drawers, instead of
  a relative-to-busiest scale that barely moved (and lit all tiles for a
  brand-new wing).
- **Website.** New "Palace Monitor" section on the landing page and screenshots
  in the Observability docs, captured from the monitor connected live to a
  vault filed from the LoCoMo benchmark, including a real `hmac-fail` tamper
  alarm.

## 0.11.0 — Palace Monitor UI

A self-contained pixel-art dashboard served at **`GET /monitor`**, driven
by the v0.10 SSE stream. Opt-in behind `--features telemetry`; the page is
unauthenticated static HTML (no secrets), metadata only, sealed vaults show
aggregates only.

- **Palace Monitor** — a retro game-world view: an archivist files drawers
  into wings as writes land, searches pulse the wings, the audit chain
  stamps on each commit, and an **ambulance beacon** fires on a real tamper.
  Runs in demo mode until you enter the bearer token and pick a vault.
  Fully inlined (no external requests); uses `fetch()` streaming so it can
  send the bearer (`EventSource` can't).
- **Live tamper alarm** — new `hmac-fail` stream event, emitted at every
  HMAC-verify-failure site (drawer/kg/tunnel/manifest), powers the beacon.
- **`GET /v1/vaults`** — lists vault ids for the picker (bearer-gated;
  disabled under per-vault assertions).

## 0.10.0 — Live memory telemetry

Turns the v0.9.0 point-in-time observability into a **live push stream** —
the foundation the Palace Monitor UI will consume. Opt-in behind
`--features telemetry`, default build untouched, metadata/counts only,
sealed vaults expose only aggregates. Additive and non-breaking.

- **SSE stream** — `GET /v1/vaults/{id}/stream` (bearer + per-vault
  assertion) pushes a periodic `sample` frame (aggregate counts) plus
  discrete **event pings** (`drawer-saved`, `drawer-deleted`, `search`,
  `kg-triple`, `chain-commit`) as they happen. Each connection is served
  on its own thread that reads only an in-process broker — never a store —
  so the single-threaded server keeps serving and streaming can never
  touch content. Sealed vaults suppress wing/room names.
- **In-process sampler** — a bounded per-vault ring buffer, filled on a
  tick (default 2s, `UNDERCROFT_SAMPLE_INTERVAL_MS`) but only for vaults
  with an active subscriber, so it costs nothing when nobody is watching.
  Also populates the previously-unset `kg_triples`/`kg_entities`/
  `store_bytes` Prometheus gauges.
- **History backfill** — `GET /v1/vaults/{id}/stats/history?window=N`
  returns the recent samples so a fresh client can draw the past.

## 0.9.0 — Observability & telemetry

An **opt-in** observability layer, off by default with zero extra
dependencies and zero overhead unless built with `--features telemetry`.
Everything reported is metadata and counts only — never drawer content or
key material — and nothing leaves the process unless explicitly pointed
somewhere. Additive and non-breaking.

- **Structured logs.** The pre-existing `eprintln!` diagnostics route
  through one macro; with `telemetry` on they become `tracing` events,
  level via `UNDERCROFT_LOG`, `json` output via `UNDERCROFT_LOG_FORMAT`.
- **Prometheus `/metrics`.** Opt-in via `UNDERCROFT_METRICS=1`, served on
  the bind address behind the existing bearer token (absent otherwise).
  Counters for search / drawer writes+deletes / KG writes / chain commits
  / **HMAC verify failures** (the tamper signal) / HTTP requests / auth
  rejections / vault opens; histograms for search and request latency;
  per-vault gauges for drawer count and audit-chain height.
- **OpenTelemetry export.** Set `UNDERCROFT_OTLP_ENDPOINT` to export traces
  over OTLP/HTTP (unset ⇒ no network egress). Fully synchronous — no async
  runtime is introduced; metrics stay on the Prometheus pull model.
- **New crate `undercroft-obs`** — a shim every instrumented crate depends
  on that compiles to no-ops (and pulls no dependencies) without the
  feature. Enable end-to-end with `--features telemetry` on the CLI.

## 0.8.0 — Multi-tenant server support

`serve-http` becomes a first-class per-tenant memory engine (one vault per
customer), additive and non-breaking — MCP stdio, the `/mcp` HTTP surface,
and single-vault behavior are unchanged.

- **Per-vault request authorization.** Set `UNDERCROFT_ASSERTION_SECRET` and
  every `/v1` request must carry `X-Vault-Assertion: <ts>:<hmac>` where
  `hmac = HMAC-SHA256(secret, "<ts>|<vault_id>")`, verified within ±120s
  with a constant-time compare. An assertion minted for vault A cannot
  authorize vault B. `undercroft assert-header <vault>` mints one.
- **Versioned REST surface** (`/v1`) in the same process, same bearer:
  create/delete vault, stats, save/search/delete drawer, and a lossless
  NDJSON export/import pair (import returns the exact record count) for
  migrating a vault between instances.
- **Externally-supplied embeddings.** A vault created with
  `embedder: external:<name>@<dim>` stores caller-provided vectors, refuses
  writes/searches without one, and enforces the dimension — sealing those
  vectors like internally-computed ones.
- **Semantic dedup-refresh on save.** `dedup_threshold` on a write refreshes
  an existing same-wing/room drawer in place (cosine ≥ threshold, id kept)
  as an audited update, making bulk re-ingestion idempotent.
- **Orchestrated deployment** documented: headless `init` from
  `UNDERCROFT_PASSPHRASE`, key never logged, one instance per tenant (compose
  example in docs/remote-server.md).

## 0.7.2 — BM25 rank fusion (new search default)

- Search now blends cosine with a real **Okapi BM25** lexical score
  (IDF-weighted, `k1=1.2`/`b=0.75` length normalization, one-typo
  tolerant) computed over the decrypted, HMAC-verified candidate set,
  replacing the old flat term-overlap fraction. Measured lift with the
  zero-model hash embedder: **LongMemEval-S R@5 90.4% → 95.0%** (the
  paraphrase-heavy preference category 36.7% → 66.7%), **LoCoMo session
  R@10 92.7% → 94.6%** — where the hash embedder now edges past the
  earlier MiniLM run. See benchmarks/RESULTS.md for the full ablation.
- Fusion is selectable with `UNDERCROFT_FUSION`: `bm25` (default),
  `legacy` (the prior term-overlap blend, reproduces the old numbers
  exactly), or `rrf` (reciprocal-rank fusion — scale-free but benchmarks
  below bm25). Fusion only re-ranks already-verified candidates; every
  security guarantee is unchanged, and it is embedder- and
  security-level-independent.

## 0.7.1 — FTS5 BM25 prefilter for hmac-only vaults

- hmac-only vaults now carry an external-content FTS5 index over drawer
  content (trigger-maintained through upsert/update/delete/dedup/restore,
  rebuilt on open if missing or stale). Searches over palaces of 2048+
  drawers prefilter candidates to the BM25 top-K before the usual
  HMAC-verify + hybrid re-rank; if FTS matches nothing the full scan runs
  instead, so semantic-only recall is preserved. Tune or disable with
  `UNDERCROFT_FTS_PREFILTER_MIN` (a number, or `off`).
- Sealed vaults are unchanged: no plaintext-derived index is ever created
  (test-asserted), search remains decrypt-scan by design.

## 0.7.0 — Measured benchmarks, Weaviate, compressed storage

- First measured benchmark results, in-repo (benchmarks/RESULTS.md), with
  the zero-model hash embedder: LoCoMo session R@10 92.7% (beats
  upstream's published raw and hybrid), LongMemEval-S R@5 90.4% (6.2 pts
  under upstream's model-based raw; gap isolated to the
  single-session-preference type).
- Weaviate backend (REST + GraphQL, vectorizer:none) — fifth live-tested
  remote index; PUT-vs-POST upsert semantics handled.
- Storage growth control: zstd compress-then-encrypt for sealed content
  (legacy records stay readable) and int8 embedding quantization with
  per-vector scale (4x smaller, cosine drift < 0.1%), both test-covered.


## 0.6.0 — Benchmark adapters + in-process vector cache; PARITY complete

- `undercroft-bench locomo|convomem|membench`: adapters for the remaining
  three upstream benchmarks (session / message / turn-level evidence
  recall, same protocols as the Python harnesses), fixture-tested so the
  scoring is trustworthy before any dataset is downloaded.
- `PalaceStore::warm_embedding_cache`: decrypt-once in-memory vector cache
  for long-running modes (serve-mcp / serve-http / daemon), kept coherent
  across upsert/delete/repair — fills embedded ChromaDB's in-process index
  role without persisting anything plaintext-derived.
- docs/PARITY.md "not ported" list is now empty.


## 0.5.1 — Memory-extraction eval + CLI localization

- `undercroft-bench model-eval memories`: SQuAD-style token-F1 with greedy
  one-to-one alignment (threshold 0.5, CJK-aware per-character tokens);
  reports match P/R/F1, mean token-F1, and type accuracy.
  `extract_memories` added to undercroft-llm.
- CLI result strings localized in the 9 model_eval dataset languages
  (de/es/fr/hi/it/ko/pt/ru/zh) via UNDERCROFT_LANG, English default and
  fallback; placeholder-preservation enforced by tests. Errors/help stay
  English (exit codes are the scripting contract).


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
