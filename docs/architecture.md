# Architecture

## The palace

```
Palace (data dir, one master key)
└── Vaults (isolation boundary: own DB file, own derived keys)
    ├── Wings   (people / projects)          ── connected by Tunnels
    │   └── Rooms (topics)
    │       └── Drawers (verbatim chunks, ~800 chars)
    ├── Knowledge graph (temporal triples with validity windows)
    ├── Audit chain (append-only, HMAC-chained writes)
    └── Hallways (entity co-occurrence, computed on demand — never persisted)
```

## Components and dependencies

Eleven crates. Solid arrows are `Cargo.toml` dependencies; the dashed
arrow is the one deliberate non-dependency in the design — the
orchestrator talks to engines **only over HTTP** (`/v1`), so the engine
stays tree-blind and portable.

```mermaid
flowchart TB
    subgraph engine["Engine (ships in the box)"]
        core["undercroft-core<br/><i>domain, chunking, ids,<br/>hash embedder, FDE, MaxSim</i>"]
        vault["undercroft-vault<br/><i>HKDF keys, AEAD sealing,<br/>HMAC tags, audit chain</i>"]
        store["undercroft-store<br/><i>per-vault SQLite, hybrid search,<br/>PQ/IVF, ColBERT stage, FDE index, KG</i>"]
        index["undercroft-index<br/><i>remote vector backends<br/>(untrusted accelerators)</i>"]
        llm["undercroft-llm<br/><i>local LLM runtimes<br/>(refine → KG)</i>"]
        obs["undercroft-obs<br/><i>observability shim<br/>(no-op by default)</i>"]
        cli["undercroft-cli<br/><b>undercroft</b> binary<br/><i>CLI + MCP + HTTP /v1</i>"]
    end
    subgraph optional["Opt-in inference backends"]
        onnx["undercroft-embed-onnx<br/><i>tract: embedder, reranker, ColBERT</i>"]
        ort["undercroft-embed-ort<br/><i>ONNX Runtime: same trio, faster</i>"]
    end
    bench["undercroft-bench<br/><i>LongMemEval / LoCoMo /<br/>fde-synth harnesses</i>"]
    orch["undercroft-orchestrator<br/><b>undercroft-orchestrator</b> binary<br/><i>multi-tenant control plane</i>"]

    vault --> core
    vault --> obs
    store --> core
    store --> vault
    store --> index
    store --> obs
    cli --> core
    cli --> vault
    cli --> store
    cli --> index
    cli --> llm
    cli --> obs
    cli -. "feature onnx" .-> onnx
    onnx --> core
    ort --> core
    bench --> core
    bench --> vault
    bench --> store
    bench --> index
    bench --> llm
    bench -. "features onnx / ort" .-> onnx
    bench -. "features onnx / ort" .-> ort
    orch -. "HTTP /v1 only —<br/>no crate dependency" .-> cli
```

| Crate | Responsibility |
|---|---|
| `undercroft-core` | Domain types, chunking, deterministic ids, normalization, hash embedder, MUVERA FDE construction, MaxSim kernel, transcript parsing, entity detection |
| `undercroft-vault` | Master key (file or Argon2id), HKDF per-vault keys, XChaCha20-Poly1305 sealing, HMAC tags, audit-chain arithmetic, MAC'd manifests |
| `undercroft-store` | Per-vault SQLite (system of record), hybrid search, PQ/IVF prefilter, ColBERT token store + LUT MaxSim, FDE candidate index, knowledge graph, management, remote-index integration |
| `undercroft-index` | Qdrant / Chroma / pgvector / Milvus / Weaviate clients — untrusted accelerators, sealed content only |
| `undercroft-llm` | Local LLM runtimes (Ollama / OpenAI-compatible) for `refine` → KG extraction |
| `undercroft-obs` | Observability shim: zero-dep no-op by default; logs, `/metrics`, OTLP, SSE under `--features telemetry` |
| `undercroft-cli` | `undercroft` binary: CLI + MCP stdio + HTTP (MCP `/mcp` + multi-tenant `/v1`) |
| `undercroft-embed-onnx` | Feature-gated tract backend: sentence embedder, cross-encoder reranker, ColBERT encoder |
| `undercroft-embed-ort` | Opt-in ONNX Runtime backend: the same trio, ~2.5× per forward, int8 support |
| `undercroft-bench` | Benchmark harnesses (LongMemEval, LoCoMo, ConvoMem, MemBench, fde-synth) |
| `undercroft-orchestrator` | Optional multi-tenant control plane: routing, tenant→vault map, token minting, migration |

## Key hierarchy and AAD domains

Isolation is cryptographic, not logical. One master key; every vault
derives its own keys via HKDF, and **every sealing operation binds the
vault id (and an artifact-specific label) into the AAD** — ciphertext
moved across vaults, rows, or artifact kinds fails to open rather than
decrypting wrongly.

```mermaid
flowchart TB
    master["Master key<br/><i>file or Argon2id passphrase</i>"]
    master -- "HKDF(vault A)" --> ka["vault A keys<br/>enc · mac · fingerprint"]
    master -- "HKDF(vault B)" --> kb["vault B keys<br/>enc · mac · fingerprint"]
    ka --> doms["AAD domains (vault A)<br/><br/>content — drawer text<br/>{id}/emb — embeddings<br/>{id}/tok — token matrices<br/>fde/{id}/tok — FDE rows<br/>{rec}/pq — PQ index artifacts"]
    kb -. "vault B ciphertext under<br/>vault A keys ⇒ fails to open" .-> ka
```

Sealed vaults never persist plaintext or plaintext-derived data in clear:
embeddings, PQ code rows and codebooks, ColBERT token matrices, and FDE
rows are all AEAD-sealed under their distinct domains, and search runs
from decrypt-once RAM caches.

## Write path

Every write is verbatim (never summarized), deterministic (same logical
drawer ⇒ same id ⇒ idempotent re-mining), and **atomic with its audit
entry** — the chain head lives in SQLite and advances inside the same
transaction as the data it covers.

```mermaid
sequenceDiagram
    participant C as Caller (CLI / MCP / REST)
    participant S as store
    participant V as vault
    participant DB as SQLite (one transaction)
    C->>S: save(content, wing, room)
    S->>S: normalize (verbatim-preserving) → chunk → deterministic id
    S->>S: embed (hash / onnx / external vector)
    S->>V: seal content + embedding (sealed vaults — AAD binds vault id + label)
    S->>V: HMAC tag over id ␟ meta ␟ content
    S->>DB: BEGIN
    DB->>DB: drawer row (sealed blobs + tag)
    DB->>DB: audit row + chain_append → chain_meta head advances
    DB->>DB: COMMIT  — data and chain move together or not at all
    S->>V: anchor manifest (lagging rollback anchor, post-commit)
    Note over S: derived artifacts, advisory, from plaintext in hand:<br/>token matrix (ColBERT) → FDE → PQ code row
```

Crash between COMMIT and the manifest anchor? The next open replays the
audit rows: an anchor *inside* the replayed chain is a crash artifact
(silent fast-forward); an anchor *outside* it is a rollback or fork
(`ManifestTampered`). A power cut is never a false alarm; a restored old
database still alarms.

## Search pipeline

Candidate generation is pluggable; everything downstream is identical on
every path, and **every candidate's HMAC is verified before its content
is returned**.

```mermaid
flowchart LR
    q["query"] --> cand{{"candidate stage"}}
    cand -- "UNDERCROFT_RETRIEVAL=fde" --> fde["FDE dot product<br/><i>token-aware, PQ-coded cache</i>"]
    cand -- "=pq" --> pq["PQ / IVF ADC scan<br/><i>bounded RAM</i>"]
    cand -- "=hnsw" --> hnsw["in-memory HNSW<br/><i>experimental</i>"]
    cand -- "default" --> fts["FTS5 BM25 prefilter<br/><i>hmac-only, large corpora</i><br/>or full cosine scan"]
    fde --> hyd
    pq --> hyd
    hnsw --> hyd
    fts --> hyd
    hyd["hydrate candidates<br/>+ <b>HMAC verify each</b><br/>+ decrypt (sealed)"] --> fuse["fusion score<br/><i>cosine + BM25 + recency</i>"]
    fuse --> second{{"second stage"}}
    second -- "UNDERCROFT_RERANKER=onnx" --> ce["cross-encoder rerank<br/><i>top-N forwards</i>"]
    second -- "=colbert" --> ms["MaxSim rescore<br/><i>stored token matrices,<br/>PQ-LUT, one query forward</i>"]
    second -- "unset" --> out
    ce --> out["verbatim hits"]
    ms --> out
```

The FDE and MaxSim stages share one query forward per search; sealed
vaults serve all of this from decrypt-once RAM caches. Measured numbers
for every stage live in
[RETRIEVAL_SCALING.md](https://github.com/sealcroft/undercroft/blob/main/docs/RETRIEVAL_SCALING.md).

## Multi-tenant deployment

One engine hosts many cryptographically isolated vaults; fleets add the
optional orchestrator — topology, request routing, and the migration
sequence are diagrammed in
[MULTI_TENANCY.md](https://github.com/sealcroft/undercroft/blob/main/docs/MULTI_TENANCY.md).
