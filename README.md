<div align="center">

# Undercroft

**Hardened, local-first AI memory: encrypted, integrity-verified memory vaults with verbatim recall.**

[Website](https://compufreq.github.io/undercroft/) · [Documentation](https://compufreq.github.io/undercroft/docs/) · [Agents implementation guide](https://compufreq.github.io/undercroft/docs/agents.html) · [Security model](https://compufreq.github.io/undercroft/docs/security.html)

> **Implementing with an AI agent?** Point it at
> [docs/AGENTS.md](https://github.com/compufreq/undercroft/blob/main/docs/AGENTS.md) —
> a scenario-driven guide (personal agent memory, team server, multi-tenant
> engine, fleet orchestration, retrieval tiers, security operations) written
> so an agent can pick the right deployment shape and implement it
> correctly, with the full tool/route/env reference and a verification
> checklist.

</div>

---

## Why "Undercroft"?

In Greek mythology, **Undercroft** (νη-MOZ-ih-nee) is the Titaness of memory and
remembrance, daughter of Uranus and Gaia, and the mother of the nine Muses.
Before writing existed, the Greeks held that all knowledge — every epic, every
lineage, every law — survived only through her: memory was not a convenience
but the *guardian of everything worth keeping*. Orators drank from her spring;
in the underworld, initiates were told to pass the river Lethe (forgetting)
and drink instead from the pool of Undercroft to retain what they knew across
the crossing.

That is precisely this project's job description:

| Undercroft (myth) | undercroft (this project) |
|---|---|
| Guardian of memory before writing existed | Guards your AI's memory outside any single session |
| Mother of the Muses — memory begets creation | Retrieved context begets better answers, code, and writing |
| Her pool preserves knowledge across the crossing into the underworld | Memories survive the "crossing" between sessions, context compressions, and machines |
| Sacred, protected spring — not an open river | Memories live in **sealed vaults**: encrypted, isolated, tamper-evident |

The ancient *method of loci* — the "memory palace" technique MemPalace is named
for — was itself attributed to Undercroft's gift. Undercroft keeps the palace and
adds what the myth implies: the palace has **locks**.

## What it is

Undercroft stores conversation history and project knowledge as **verbatim
text** (never summarized on the way in) and retrieves it with hybrid
semantic + lexical + recency search. The index keeps MemPalace's structure —
people and projects are *wings*, topics are *rooms*, original content lives in
*drawers* — and adds a security-first **memory management layer**:

### The vault layer (new in this fork)

Every memory namespace is a **vault** — a hard isolation boundary:

- **Separation** — each vault has its own directory and its own SQLite
  database. There is no shared table space to leak across, and vault names are
  validated against path traversal.
- **Key isolation** — per-vault encryption and MAC keys are derived from one
  palace master key via **HKDF-SHA256 domain separation**. Vault A's keys are
  cryptographically useless against vault B's data. The master key is either a
  `0600` key file or derived from a passphrase with **Argon2id** (64 MiB, t=3);
  keys are zeroized in memory on drop.
- **Encryption** — in `sealed` vaults (the default), drawer content *and its
  embedding* are encrypted with **XChaCha20-Poly1305**. The AEAD associated
  data binds vault id + record id, so ciphertext cannot be replayed into
  another vault or another record slot. Nothing content-derived is written to
  disk in plaintext — search runs by decrypt-scan.
- **HMAC integrity** — every record carries an **HMAC-SHA256** tag (independent
  MAC key) over its id, metadata, and at-rest content; reads verify before
  returning data. An append-only audit table feeds a **tamper-evident HMAC
  chain** whose head lives in the vault manifest — and the manifest itself is
  MAC'd, so offline edits (chain resets, security-level downgrades) are caught
  at unlock. `undercroft verify` walks all of it.
- **Choice of level** — `sealed` (encrypt everything) or `hmac-only`
  (plaintext + full-text indexing, but still integrity-tagged and chained) for
  memories where searchability outweighs confidentiality.

**Threat model:** protects memories at rest against disk theft, cross-vault
bleed, and offline tampering of the database or manifest. It does *not* defend
against an attacker who can read process memory while a vault is unlocked.

Nothing leaves your machine by default. The default embedder is a
deterministic local hashed n-gram model — no downloads, no API calls, no
network at all.

## Storage & retrieval backends

The bundled SQLite store is the system of record — keys, HMAC tags, audit
chain, and knowledge graph always live there. Remote vector databases are
supported as **untrusted search accelerators**:

| Backend | Role | Configure with |
| --- | --- | --- |
| SQLite (bundled) | System of record + local search (default) | — |
| `qdrant` | Remote ANN index (REST) | `UNDERCROFT_QDRANT_URL` |
| `chroma` | Remote ANN index (REST v2, server mode) | `UNDERCROFT_CHROMA_URL` |
| `pgvector` | Remote ANN index (Postgres) | `UNDERCROFT_PGVECTOR_DSN` |
| `milvus` | Remote ANN index (REST v2, standalone) | `UNDERCROFT_MILVUS_URL` |
| `weaviate` | Remote ANN index (REST + GraphQL) | `UNDERCROFT_WEAVIATE_URL` |

Unlike upstream MemPalace — which stored plaintext documents in these
databases — Undercroft uploads only the **sealed** content blob plus the
embedding and wing/room labels. Remote search returns candidate ids; every
candidate is re-loaded from the local palace, HMAC-verified, decrypted, and
re-ranked locally. A compromised index can hide results but cannot forge,
alter, or inject them. The trade-off that remains: embeddings are visible
server-side (ANN cannot work otherwise) — if embedding-inversion leakage is
unacceptable, use local search.

```bash
undercroft index push qdrant            # upload sealed records
undercroft search "query" --backend qdrant
undercroft index status qdrant
```

## Embedders

The `Embedder` trait is pluggable and identity-tracked: the model name and
dimension are recorded per vault on first write, and a mismatch is refused
(silent model swaps degrade recall) unless `UNDERCROFT_FORCE_EMBEDDER=1` is
set, after which `undercroft repair` re-embeds every drawer.

- **`hash` (default)** — deterministic hashed n-gram embedder, zero
  dependencies, fully offline.
- **`onnx`** — MiniLM-class sentence-transformer ONNX exports via
  [tract](https://github.com/sonos/tract) (pure Rust, no native binaries).
  Build with `--features onnx`, then point `UNDERCROFT_ONNX_MODEL` and
  `UNDERCROFT_ONNX_TOKENIZER` at a user-supplied `model.onnx` +
  `tokenizer.json` and set `UNDERCROFT_EMBEDDER=onnx`. Undercroft never
  downloads models itself.
- **`ort`** — the same models through **ONNX Runtime** (~2.5× faster per
  forward, int8/VNNI support, ~4–5× faster ingest embed). Build with
  `--features ort` and set `UNDERCROFT_EMBEDDER=ort`; reads the same
  `UNDERCROFT_ONNX_*` variables, so switching backends is one env change.
  Opt-in because it links ONNX Runtime's C++ library — tract stays the
  pure-Rust default.

### Cross-encoder reranker (optional, `onnx` / `ort` features)

A second retrieval stage: after hybrid search surfaces a candidate pool, a
cross-encoder re-scores the top-N with the full `(query, passage)` pair and
re-orders them. Point `UNDERCROFT_RERANK_MODEL` / `UNDERCROFT_RERANK_TOKENIZER`
at a user-supplied cross-encoder ONNX export (a **BERT-family** model such as
`cross-encoder/ms-marco-MiniLM-L-6-v2`; note tract 0.22 does not run
DeBERTa-based rerankers) and set `UNDERCROFT_RERANKER=onnx` (tract) or
`UNDERCROFT_RERANKER=ort` (ONNX Runtime: one batched forward for the whole
pool + a session-pool fan-out, `--features ort`). Pairs with either
embedder; `UNDERCROFT_RERANK_TOP_N` (default 50) bounds the added latency.
Applies to `search`, `serve-mcp`, the daemon, and the multi-tenant `/v1`
surface (one shared model across vaults). Measured: LoCoMo R@10 94.6 →
**97.68%** at 101–327 ms/query on 24 cores (ONNX Runtime backend + int8).

### ColBERT late interaction (optional, `onnx` feature; `ort` runtime available)

The core-count-independent second stage: drawers are encoded **once at
ingest** into per-token matrices (PQ-compressed to ~16 bytes/token on disk,
AEAD-sealed in sealed vaults) and a search runs **one** query forward plus a
MaxSim re-score — no transformer per candidate. Measured: LoCoMo R@10 94.6 →
**96.5–96.8%** at a flat ~93 ms/query on *any* core count with the pure-Rust
tract runtime, **~70 ms/query** (and 3.3× faster ingest) on the opt-in ONNX
Runtime backend — recall identical across runtimes. Set
`UNDERCROFT_RERANKER=colbert` (tract) or `colbert-ort` (ONNX Runtime,
`--features ort`) + `UNDERCROFT_COLBERT_MODEL` (doc export) /
`_QUERY_MODEL` / `_TOKENIZER` (fixed-shape ONNX exports; recipe in
[docs/RETRIEVAL_SCALING.md](https://github.com/compufreq/undercroft/blob/main/docs/RETRIEVAL_SCALING.md)). Token matrices ride
export bundles as portable artifacts (restore = copy, not re-encode);
`repair --tokens` backfills palaces that predate the encoder.
**MUVERA FDE candidates** (`UNDERCROFT_RETRIEVAL=fde`) make the candidate
stage token-aware too: each matrix compresses to one fixed-dimensional
vector (sealed at rest, built with zero extra forwards) whose dot product
approximates MaxSim — measured on LoCoMo: recall identical to fusion,
question-for-question, at **−25% search latency**; at N=200k synthetic
docs the exact top-10 survives the FDE top-100 100% of the time at 40×
below exact-scan cost. Above a few hundred drawers the FDEs PQ-compress
**32×** (256 B/drawer, 51 MB RAM at N=200k) with containment still
perfect and the scan ~8× faster — bounded RAM like every other index
here.

### Scaling retrieval (PQ / IVF, both vault levels)

Large corpora can cut candidate generation from a full scan to a bounded-RAM
**product-quantization index with IVF inverted lists**
(`UNDERCROFT_RETRIEVAL=pq`): ~48 bytes/vector on disk, recall flat in corpus
size (99+% R@5 at N=50k). **Sealed vaults get it too** — code rows, codebook,
and centroids are AEAD-sealed and scanned via a decrypt-once RAM cache;
measured sealed search went from 2.1 → 33.4 q/s at N=20k (×16), parity with
the plaintext index. Full numbers: [benchmarks/RESULTS.md](https://github.com/compufreq/undercroft/blob/main/benchmarks/RESULTS.md).

## Quickstart (Docker — recommended)

Everything persists under `/data`, so mount a volume there:

```bash
docker build -t undercroft .

docker run --rm -v undercroft-data:/data undercroft init
docker run --rm -v undercroft-data:/data undercroft remember \
  "We chose GraphQL over REST for the mobile API" --wing backend --room decisions
docker run --rm -v undercroft-data:/data undercroft search "why graphql"
docker run --rm -v undercroft-data:/data undercroft verify
docker run -i --rm -v undercroft-data:/data undercroft serve-mcp   # MCP stdio server
```

Wire it into an MCP client (e.g. Claude Code):

```json
{
  "mcpServers": {
    "undercroft": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-v", "undercroft-data:/data", "undercroft", "serve-mcp"]
    }
  }
}
```

Or build natively: `cargo build --release` → `target/release/undercroft`.

## CLI

```text
undercroft init                       # master key + 'default' sealed vault
undercroft vault create work          # new isolated vault (own keys, own DB)
undercroft vault list | status <name>
undercroft vault rotate <name>        # fresh derived keys; re-seals everything, crash-safe
undercroft remember <text> [--vault --wing --room]
undercroft mine <dir> [--mode files|convos]  # documents, or Claude Code/Codex JSONL sessions
undercroft sweep <dir>                # one verbatim drawer per transcript message (idempotent)
undercroft search <query> [--vault --wing --room -n N]
undercroft wake-up [--vault --wing]   # L0 identity + L1 essential story
undercroft drawer get|list|update|delete|delete-by-source|check-dup
undercroft kg add|query|rel|invalidate|supersede|timeline|stats
undercroft diary write|read|agents    # per-agent diaries in their own wings
undercroft tunnel create|list|follow|delete|traverse   # cross-wing links
undercroft hallways <wing>            # within-wing entity co-occurrence
undercroft closets [--wing]           # compact LLM-scannable index (AAAK port)
undercroft refine [--dry-run]         # local-LLM extraction into the KG (UNDERCROFT_LLM_URL)
undercroft stats | taxonomy           # palace shape
undercroft dedup [--apply]            # exact-duplicate detection (keyed fingerprints)
undercroft backup create|list|restore # verified snapshots, keeps last 10
undercroft repair                     # backfill + vacuum + re-verify
undercroft verify [--vault]           # HMAC every record + replay audit chain
undercroft export [--vault]           # decrypted JSONL to stdout
undercroft export --to <pub> --out f  # sealed bundle only that recipient can open
undercroft import <file.jsonl>        # migrate from undercroft or mempalace exports
undercroft import <bundle> --identity <key>  # open + import an encrypted bundle
undercroft bundle keygen|recipient    # X25519 identities for sealed exports
undercroft transcript render <f.jsonl># pretty-print an agent transcript
undercroft daemon run [--watch --interval --once]  # background auto-save loop
undercroft hooks claude-code          # auto-save hook settings snippet
undercroft serve-mcp [--vault]        # MCP stdio server (32 tools)
undercroft serve-http [--host --port --read-only]  # MCP /mcp + multi-tenant REST /v1
undercroft assert-header <vault>      # mint an X-Vault-Assertion (per-tenant auth)
```

`serve-http` is both the shared team server (MCP over HTTP, bearer auth) and
a multi-tenant memory engine: a versioned `/v1` REST surface with vault
lifecycle, per-vault HMAC assertions (`UNDERCROFT_ASSERTION_SECRET`),
caller-supplied embeddings, dedup-refresh on save, and lossless
export/import for migrating a tenant between instances. See
[the remote-server guide](https://github.com/compufreq/undercroft/blob/main/docs/remote-server.md).

Fleets of engines get the **optional orchestrator**
(`undercroft-orchestrator`): instance registry, tenant creation with
one-time token minting, a routing proxy that maps each tenant token to
exactly its own vault, and count-verified live migration between
instances — a separate control plane speaking only the public `/v1`
surface, with engine credentials sealed at rest and tenant tokens stored
only as HMACs. Design + surface:
[docs/MULTI_TENANCY.md](https://github.com/compufreq/undercroft/blob/main/docs/MULTI_TENANCY.md).

Palace location: `$UNDERCROFT_HOME` (default `~/.undercroft`; `/data` in Docker).
Passphrase mode: set `UNDERCROFT_PASSPHRASE` before `init` and every command.

## MCP tools (32)

| Category | Tools |
|---|---|
| Palace core | `save`, `search`, `wake_up`, `verify`, `status` |
| Drawers | `get_drawer`, `add_drawer`, `update_drawer`, `delete_drawer`, `list_drawers`, `delete_by_source`, `check_duplicate` |
| Navigation | `list_wings`, `list_rooms`, `get_taxonomy`, `create_tunnel`, `list_tunnels`, `follow_tunnel`, `delete_tunnel`, `traverse`, `list_hallways` |
| Knowledge graph | `kg_add`, `kg_query`, `kg_invalidate`, `kg_supersede`, `kg_timeline`, `kg_stats` |
| Agent diaries | `diary_write`, `diary_read`, `list_agents` |
| Maintenance | `dedup` |

All tool names are prefixed `undercroft_`. The knowledge graph stores temporal
facts with validity windows — `kg_query --as-of 2024-06-15` answers "what was
true then", `kg_supersede` closes the old fact and opens the new one, and
`kg_timeline` replays history. KG facts live in the vault too: objects are
sealed in encrypted vaults, and every triple is HMAC-tagged and audit-chained.

## Testing (all in Docker)

```bash
docker compose run --rm test          # unit + integration tests (cargo)
docker compose run --rm e2e           # end-to-end UI/UX suite against the real binary
docker compose run --rm backends-e2e  # remote-index suite (spins up qdrant/chroma/pgvector)
docker compose run --rm onnx-build    # compile check for the ONNX embedder feature
```

The e2e suite drives the actual CLI the way a user would — help text, happy
paths, exit codes, vault isolation, plaintext-leak checks against the raw DB
file, deliberate on-disk tampering (must be detected), and a scripted MCP
JSON-RPC session. The backends suite runs the full push → remote search →
verify flow against real Qdrant, Chroma, and Postgres+pgvector servers.

## Architecture

```
crates/
  undercroft-core/    domain model: drawers, chunking, ids, normalization,
                     deterministic hashed n-gram embedder
  undercroft-vault/   security layer: VaultManager, HKDF key derivation,
                     XChaCha20-Poly1305 sealing, HMAC tags + audit chain
  undercroft-store/   SQLite per-vault storage + hybrid search
  undercroft-cli/     `undercroft` binary: CLI + MCP stdio server
```

Drawer metadata (wing, room, source_file, chunk_index, added_by, filed_at,
normalize_version, id_recipe, …) mirrors MemPalace's schema, and drawer ids
use the same deterministic-recipe idea (idempotent re-mining).

## Relationship to MemPalace

Undercroft began as a conversion of the MemPalace project (MIT-licensed,
Python), fully rewritten in Rust — no Python remains.
Ported: the palace model and miners (files + conversation transcripts +
sweep), wake-up layers, knowledge graph, tunnels/hallways navigation, agent
diaries, drawer management, dedup/stats/backups/repair, hooks output, the
MCP tool surface, remote vector backends (Qdrant, Chroma, pgvector — with
client-side sealing, unlike upstream's plaintext uploads), and model-based
embeddings (ONNX via tract, feature-gated). Not carried over: Milvus
(gRPC-only, opt-in extra upstream) and embedded ChromaDB (a Python library;
the bundled SQLite store fills that role).

## Benchmarks (measured, not inherited)

Full methodology and reproduce commands: [benchmarks/RESULTS.md](https://github.com/compufreq/undercroft/blob/main/benchmarks/RESULTS.md).
Matched-model conditions (all-MiniLM-L6-v2, the class upstream used):
**LoCoMo session R@10 93.8%** (upstream: 60.3% raw / 88.9% hybrid) and
**LongMemEval-S R@5 97.4%** on the full 500 (upstream raw: 96.6%; their
tuned hybrid: 98.4%). The zero-model hash embedder — no download, ~95x
faster — holds 92.7% / 90.4% respectively.

## Storage that doesn't balloon

- Sealed content is **zstd-compressed before encryption** (compress-then-
  encrypt — ciphertext can't be compressed after the fact), with a raw
  fallback when compression doesn't pay. Legacy records stay readable.
- Embeddings are **int8-quantized** (4× smaller than f32; the vector is
  usually bigger than the text it embeds) with per-vector scaling —
  ranking-neutral (cosine drift < 0.1%) and covered by tests.
- Exact-duplicate detection (keyed fingerprints), `dedup --apply`, and
  `repair` (vacuum + re-embed) keep the palace tight.

## More

- [Getting started](https://github.com/compufreq/undercroft/blob/main/docs/getting-started.md) · [Architecture](https://github.com/compufreq/undercroft/blob/main/docs/architecture.md) ·
  [Security model](https://github.com/compufreq/undercroft/blob/main/docs/security.md) · [Integrations](https://github.com/compufreq/undercroft/blob/main/docs/integrations.md) ·
  [Remote team server](https://github.com/compufreq/undercroft/blob/main/docs/remote-server.md)
- [Parity with upstream MemPalace](https://github.com/compufreq/undercroft/blob/main/docs/PARITY.md) — what's ported, what's
  deliberately different, what's pending
- [Benchmarks](https://github.com/compufreq/undercroft/blob/main/benchmarks/README.md) — LongMemEval harness + synthetic CI benchmark
- [Deploy](https://github.com/compufreq/undercroft/blob/main/deploy/README.md) — compose team server, systemd units
- Claude Code plugin: [.claude-plugin/](https://github.com/compufreq/undercroft/tree/main/.claude-plugin) · hooks: [hooks/](https://github.com/compufreq/undercroft/tree/main/hooks) ·
  examples: [examples/](https://github.com/compufreq/undercroft/tree/main/examples)

## License

**Business Source License 1.1** — see
[LICENSE](https://github.com/compufreq/undercroft/blob/main/LICENSE).
In practice:

- **Free for almost everything**: use, modify, self-host, and run in
  production — personal, internal, and commercial — at no cost.
- **The one carve-out**: you may not offer Undercroft itself to third
  parties as a paid hosted or embedded product that competes with the
  Licensor's commercial offerings.
- **Time-limited by design**: each release automatically converts to the
  open-source **MPL 2.0** four years after publication.

Undercroft is a from-scratch Rust implementation of concepts from the
MIT-licensed MemPalace project and contains no code from it — see
[NOTICE](https://github.com/compufreq/undercroft/blob/main/NOTICE) for the
heritage attribution and
[docs/PARITY.md](https://github.com/compufreq/undercroft/blob/main/docs/PARITY.md)
for the full feature-by-feature relationship.
