# Parity with MemPalace

Feature-by-feature comparison against `MemPalace/mempalace` (the Python
project whose concepts this one reimplements; no source code is shared,
see "License lineage" below), updated 2026-09-02.

## Ported (Rust equivalent exists)

| MemPalace | Undercroft equivalent |
|---|---|
| Palace model (wings/rooms/drawers, verbatim) | `undercroft-core` (same metadata fields, deterministic ids) |
| `sqlite_exact` backend | `undercroft-store` (SQLite system of record) |
| Chroma/Qdrant/pgvector server backends | `undercroft-index` — **sealed client-side** (MemPalace sent plaintext) |
| Embedder + identity tracking (RFC 001) | `Embedder` trait + per-vault identity enforcement (a swap is refused, not silently ranked; only hash→hash migrates automatically) |
| Model embeddings (sentence-transformers) | four postures — `undercroft-embed-onnx` (tract, pure Rust), `undercroft-embed-ort` (ONNX Runtime, ~2.5×/forward + int8), `http` (any served model, TLS-or-loopback enforced), or caller-supplied `external:<name>@<dim>`. Models are user-supplied throughout; see [EMBEDDERS.md](https://sealcroft.com/undercroft/docs/embedders.html) |
| File miner | `mine --mode files` |
| Conversation miner (`--mode convos`) | `mine --mode convos` |
| Sweep (per-message drawers) | `sweep` (idempotent via keyed fingerprints) |
| Wake-up layers L0/L1 | `wake-up` (identity.txt + essential story) |
| Knowledge graph (temporal, validity windows) | `kg add/query/rel/invalidate/supersede/timeline/stats`, plus three with no upstream equivalent: `kg receipts` (per-fact citation verdicts), `kg authority` and `kg canonical` (the golden-values tier) |
| Tunnels (cross-wing) | `tunnel create/list/follow/delete/traverse` |
| Hallways (entity co-occurrence) | `hallways` (computed on demand; never persisted) |
| Drawer CRUD, delete-by-source, dup check | `drawer …`, keyed fingerprints |
| Agent diaries + list_agents | `diary write/read/agents` |
| Dedup / stats / taxonomy | `dedup`, `stats`, `taxonomy` |
| Backups | `backup create/list/restore` (verifies before snapshot) |
| Repair | `repair` (fingerprint backfill, re-embed, drop the stale index, re-stamp the embedder identity, record the run, vacuum, verify — all of it inside **one transaction**, so an abort cannot leave a mixed vector space reporting itself as pure) |
| Export / migrate | `export` (JSONL) + `import` (undercroft & mempalace formats) |
| MCP stdio server (~35 tools) | 38 tools (daemon/sync/session tools inapplicable — process management moved to the OS). The count is not maintained by hand: `crates/undercroft-cli/src/parity.rs` holds the inventory and the code is counted against it **in both directions**, so a tool added without a line fails the build and a line naming a tool that no longer exists fails too |
| MCP HTTP team server (`serve`) | `serve-http` (bearer token enforced; `--read-only` is a posture on the whole process — both stores opened read-only, the route gate in front of dispatch, failing closed) |
| Daemon / jobs / start / stop / wait | `daemon run` + systemd/compose units (`deploy/`) — process management belongs to the OS |
| `tools/render_jsonl.py` | `transcript render` |
| Auto-save hooks (Claude Code/Codex/Cursor) | `hooks/`, `.claude-plugin/hooks/`, `undercroft hooks claude-code` |
| Claude Code plugin (commands/skills/MCP) | `.claude-plugin/` + root `commands/`, `skills/`, `rules/` |
| Benchmarks (LongMemEval harness) | `undercroft-bench longmemeval` (same protocol/metrics) + `synth` CI benchmark |
| LoCoMo / ConvoMem / MemBench harnesses | `undercroft-bench locomo|convomem|membench` — session / message / turn-level evidence recall, same protocols as MemPalace's harnesses, adapter logic fixture-tested |
| Embedded ChromaDB's in-process index role | Bundled SQLite store is the system of record; `warm_embedding_cache` gives long-running servers (serve-mcp / serve-http / daemon) a decrypt-once in-memory vector cache — the in-process index role, with nothing plaintext-derived persisted |
| Deploy (compose server, systemd) | `deploy/` |
| Docs / examples | `docs/`, `examples/` |

## What exists only here (updated for v1.2.0)

Everything below has **no upstream equivalent** — it is original work of
this project, which is why the two codebases share concepts but not code
(and why this project's license is independent of upstream's; see the
"License lineage" section at the end).

> **The `v1.2.0` label was earned on 2026-09-02, not bumped.** It is an
> *as-of* claim — moving it asserts that someone re-read this document
> against the code — which is why the `version surfaces` preflight refuses
> to move it with a release and why it sat at `v1.0.0` through three of them.
> That deferral was correct each time and had become its own stale: the rule
> is *re-verify it, then move it*, and only the first half was being applied.
>
> **What the re-read covered:** all 252 lines, with every checkable claim
> put against the code rather than read for plausibility — the CLI's real
> subcommand surface (`--help` on a freshly built binary, not the source),
> the MCP tool count against `parity.rs`, the `/v1` route count against
> `tenant.rs`'s dispatch, and each capability bullet against the crate that
> implements it. **Four drifts came back**, all of them things `1.2.0`
> moved and this file had not: the `kg` command list was missing
> `receipts`, `authority` and `canonical`; `repair` was described without
> the stale-index drop, the identity re-stamp, the run record or the single
> transaction; the read-audit bullet described `search`-only auditing, which
> is exactly the defect `1.2.0` closed across thirteen doors; and the `/v1`
> bullet predated the agent-facing surface landing there. All four are
> fixed above.
>
> **The measured figures were a second job, done 2026-09-02 (O89), and it
> is only PARTLY complete — which is stated here rather than left to
> inference.** Three LoCoMo arms were re-run on this tree under the recorded
> protocol: the base is **better** than published (94.6 → **95.51%** hash,
> **95.36%** MiniLM) and ColBERT reproduced at **96.92%**, which means its
> lift shrank from +2.2 pts to **+1.4** because the base moved and it did
> not.
>
> **Still carried at their July values, and each says why above:** the
> cross-encoder arm (no export available here), the served-model deltas (the
> weights are multi-GB and absent), and the FLORES cross-script figures
> (parallel corpora carry their own licences and never enter this repo).
> **Every latency is deliberately not re-measured** — the July runs were on
> different hardware, and a ms/q from this machine would neither confirm nor
> refute one from that one. Full protocol and the reasoning in
> [benchmarks/RESULTS.md](https://github.com/sealcroft/undercroft/blob/main/benchmarks/RESULTS.md).



**Security layer** (MemPalace stored everything in plaintext):

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
  `export --to`) — a backup never exists in plaintext, and since C3.4 the
  key exchange is **hybrid post-quantum**: `keygen` mints X25519 +
  ML-KEM-768 (`pq1` identities) and a v2 bundle derives its file key from
  **both** shared secrets, closing harvest-now-decrypt-later on the one
  asymmetric exchange in the codebase. Legacy bare-hex X25519 identities
  still parse and still receive openable v1 bundles, and a hybrid identity
  opens old v1 backups with its curve half — but a hybrid recipient never
  silently downgrades, and an X25519-only secret gets a typed refusal on a
  v2 bundle (pinned by test). Posture page: [PQ.md](https://sealcroft.com/undercroft/docs/pq.html).
- **Signed bundle manifests** — Ed25519 sender attestation beside the
  recipient flow: encryption says who may READ, the signature says who
  WROTE. Scope, trust claim, expiry, counts, provenance, and an
  unconditionally-checked payload digest. A sender-declared trust label is
  a **claim, never a boundary** ([LABELS.md](https://sealcroft.com/undercroft/docs/labels.html)); legacy payloads
  import unattested and say so.
- **Write-path admission control** — a deterministic tier-1 screen over a
  closed signal vocabulary (offsets, never content) plus attack-fixture
  similarity and an optional declared per-writer rate screen; flagged
  writes divert into a reserved quarantine wing that retrieval, `recent`
  and `list_drawers` all exclude and that MCP cannot read or destroy at
  all. Rulings are chain-audited, a deny is receipted, and the whole thing
  is default-off (a byte-identical write contract until a deployment
  declares it). Screening lives at the store's single write choke point
  behind a required argument, so a new write path does not compile until
  its author decides.
- **Provable forgetting and retention** — chain-attested destruction with
  heads, tombstone interval and unkeyed content fingerprints: the vault
  verifies by keyed replay, third parties verify the operator's Ed25519
  signature. Retention policies per wing/room are operator-only, HMAC
  tagged and audited, and enforce through an **explicit sweep** on the
  HMAC-covered clock — nothing expires on a timer.
- **Deployment-assigned wing trust** — a closed vocabulary the operator
  assigns (never MCP), HMAC-tagged so a flip fails verification, consumed
  as a candidate-set floor resolved before candidates are drawn.
- **Read and egress auditing** — exports are chain-audited unconditionally
  on every surface, and so is **LLM distillation**, which reads the corpus
  and POSTs it to a network endpoint: one `egress/refine` record per run,
  binding surface, destination host (credentials stripped), model, scope
  and counts, written on a dry run too because the corpus leaves
  identically either way. Reads are audited under
  `UNDERCROFT_READ_AUDIT=chain` across **thirteen doors** — nine that
  return drawer content and four knowledge-graph readers — one record per
  read, with a **keyed fingerprint of the subject, never its text**. The
  declaration is for insider/exfil accounting, and until `1.2.0` it
  covered `search` alone: every by-id and bulk read returned verbatim
  content and appended nothing, so walking the drawer list and then
  fetching each id left zero records where one search left one.
- Keyed duplicate fingerprints, token-mandatory non-loopback HTTP bind,
  per-vault request assertions, read-only serving posture.

**Retrieval stack beyond MemPalace's cosine search:**

- Hybrid semantic + lexical (BM25) + recency fusion with typo tolerance.
- Optional ONNX embedders on two runtimes (pure-Rust tract, or ONNX
  Runtime at ~2.5×/forward with int8) selected by env at runtime.
- Cross-encoder reranking (measured LoCoMo R@10 94.6 → 97.7% in 2026-07).
  **The base has since been re-measured at 95.5%**, so the lift that figure
  represents is smaller than it reads; the reranked arm itself has not been
  re-run (no cross-encoder export is available here) and is carried at its
  July value rather than restated.
- ColBERT late interaction: encode-at-ingest token matrices
  (PQ-compressed ~16 B/token), one query forward + MaxSim at search —
  **96.9% re-measured 2026-09-02**, at a flat ~70–93 ms/q independent of
  core count (the latency is the 2026-07 figure on that run's hardware and
  is not re-measured here). Its **lift over fusion is now +1.4 pts, not the
  +2.2 recorded**: the stage reproduced to within three questions while the
  base underneath it improved by eighteen.
- Bounded-RAM candidate tiers: PQ/IVF prefilter (~48 B/vector, recall
  flat in corpus size, sealed at rest with a decrypt-once slab cache, with
  an optional per-wing codebook/IVF tier) and MUVERA FDE token-aware
  candidates (recall measured identical to fusion at −25% latency, rows
  PQ-compressed 32×).
- **Starvation-free scoping**: every declared filter (wing, room, kind,
  trust floor, quarantine fence) is resolved into a scope *before*
  candidates are drawn, and pools are sized by the scope — a filter over
  globally generated candidates can otherwise come back empty while the
  scope holds the answer.
- **Measured to 10⁶ drawers**: shipped defaults hold **R@5 100.0%** at
  every checkpoint from 131k to 1M — unscoped, wing-scoped, room-scoped
  and wing+room — at 20.4–112.7 ms/q unscoped and ~13–32 ms/q flat when
  scoped. Both the two-stage candidate pool and the scope-sized pools
  exist because instruments filed recall defects against the previous
  fixed pool and the gate was not declared met until they closed.
- Every number above is measured and reproduced in
  [benchmarks/RESULTS.md](https://github.com/sealcroft/undercroft/blob/main/benchmarks/RESULTS.md)
  and [RETRIEVAL_SCALING.md](https://github.com/sealcroft/undercroft/blob/main/docs/RETRIEVAL_SCALING.md).

**Multi-tenancy & fleet operation:**

- Versioned `/v1` REST engine, **56 routes**: per-vault assertions,
  external embeddings, dedup-refresh, lossless export/import (vectors +
  token artifacts ride along — restore is a copy, not a re-embed), the
  full agent-facing memory surface (diary, tunnels, closets, hallways,
  wake-up, backups, drawer maintenance — 37 routes until `1.2.0` ruled
  every remaining absence and closed the ones that were drift rather than
  boundary), and operator-plane routes (wing trust, admission review,
  retention + sweep, attested forgetting) that are deliberately absent
  from MCP.
  Import re-stamps the writing surface and is admission-screened, so a
  restore or a tenant migration is not a route around the screen.
- `undercroft-orchestrator`: a separate control plane (instance registry
  with sealed credentials, HMAC-only tenant tokens shown once, routing
  proxy with subpath allowlist, token rotation, per-tenant rate limits,
  count-verified live migration) — the engine never links it.

**Operations:**

- Opt-in, metadata-only observability: Prometheus `/metrics`, OTLP
  traces (with header auth), structured logs, live SSE, the Palace
  Monitor UI, and a full Grafana/Alertmanager/Loki/Tempo deploy stack
  with a tamper runbook. Zero telemetry deps in default builds.
- Scenario-driven [agents implementation guide](https://sealcroft.com/undercroft/docs/agents.html)
  covering every deployment shape with the complete tool/route/env
  reference.

**Also only here:** Weaviate backend; sealed-client remote indexing (all
five backends receive ciphertext; MemPalace uploaded plaintext); zstd
compress-then-encrypt; int8 embedding quantization; deterministic
offline hash embedder as the default.

## Ported in v0.5.0 (previously listed as gaps)

| MemPalace | Undercroft equivalent |
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
- Remote backends receive sealed content; MemPalace uploaded plaintext. A
  mirror is an accelerator, not a different policy: remote search takes
  its trust floor, quarantine fence and closed vocabularies from the same
  resolver the local path uses.
- Benchmark numbers with the default hash embedder are not comparable to
  MemPalace's published model-based numbers — use a model posture with a
  MiniLM-class model for like-for-like conditions. Measured here, the
  choice matters more than this repo used to say: hash → *any* modern
  model is **+3.2 to +4.2pp** turn all-gold on LoCoMo, while four modern
  models span ≤1.0pp among themselves. (The old "a semantic embedder is
  not the biggest lever" conclusion rested on MiniLM's +0.3pp, and was a
  fact about MiniLM.)
- The default embedder is **single-language by construction**: feature
  hashing over surface forms matches only shared literal tokens and
  trigrams, so `car`/`automobile` do not meet and a translation pair
  scores below an unrelated sentence. Cross-lingual retrieval needs a
  multilingual model — and, since the script-disjoint fusion reweight,
  that one condition suffices even across scripts (FLORES-200
  cross-script pairs 36–44% → **95–100% R@5 at default weights**).

## License lineage

MemPalace is Python, published under the MIT License. Undercroft began as a fork and its feature surface was reimplemented in
Rust as documented in this file; it **contains no MemPalace source code** — the two projects
share behavior specifications, not expression. Undercroft is therefore
licensed independently, under the
[Business Source License 1.1](https://github.com/sealcroft/undercroft/blob/main/LICENSE)
(free use including production, one hosted/embedded non-compete
carve-out, automatic conversion to MPL 2.0 four years after each
release). The MIT notice for MemPalace's conceptual heritage is
preserved in [NOTICE](https://github.com/sealcroft/undercroft/blob/main/NOTICE).
