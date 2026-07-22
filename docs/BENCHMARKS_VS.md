# Head-to-head: undercroft vs the memory-layer market

This page is the canonical methodology and scoreboard for comparing
undercroft against external AI-memory systems (mem0, Supermemory, and —
as adapters land — Zep/Graphiti and Letta). It exists because published
memory benchmarks are usually run by the vendor with undocumented
configurations. Ours are reproducible to the byte: same corpus, same
scorer, same hardware, raw logs published, and **numbers reported as
measured, favorable or not**. If you represent one of these systems and
believe a configuration misrepresents you, open a PR — corrections are
accepted.

## The protocol

The harness is `undercroft-bench vs` ([source](../crates/undercroft-bench/src/vs.rs)),
which drives every system — including undercroft itself — through one
trait and one evaluation loop:

- **Dataset**: LoCoMo (`locomo10.json`, 10 long conversations, ~2k QA
  with evidence annotations). LongMemEval and ConvoMem harnesses exist
  in the same crate and extend the same way.
- **Ingest**: for each conversation, each session's turns are rendered
  as `SPEAKER said, "…"` lines, joined, normalized, and chunked by
  undercroft's default chunker. **Every system receives exactly these
  chunks** — no system gets tags, formatting, or hints another doesn't.
  Session identity (`session_N`) travels as *metadata* on the add call,
  using each system's own metadata feature.
- **Isolation**: one conversation = one fresh scope (undercroft: a fresh
  sealed vault; mem0: a distinct `user_id`; Supermemory: a distinct
  `containerTag`).
- **Query**: each QA question is submitted verbatim to the system's
  search. The system returns ranked results; the adapter maps them back
  to session ids via the metadata they carried and deduplicates in rank
  order.
- **Score**: R@k (k=10), session granularity — a hit iff any
  gold-evidence session (from the dataset's `D<sess>:<turn>` ids)
  appears in the top-k distinct sessions. Identical to the scorer used
  for every undercroft number in
  [RETRIEVAL_SCALING.md](RETRIEVAL_SCALING.md).
- **Sharding**: `--skip/--limit/--qa-limit` shard by conversation and
  cap QA; `VS_RAW` output lines carry exact numerators/denominators so
  shards sum without rounding drift. Any subset used is documented in
  the results table.

## Fairness rules

1. Adapters are honest pass-throughs to each system's public API — no
   local re-ranking, no caching, no retries that change results.
2. Each competitor runs its **best documented local configuration**
   (their published Docker/self-host path). Extraction-based systems
   need an LLM + embedder; the local backend (LM Studio or Ollama,
   models pinned) is recorded per row. We do not run competitors
   against paid cloud APIs — the comparison is local-vs-local, which is
   undercroft's arena, and no row in a published run makes any
   off-machine call.
3. Ingest and search wall-clock are recorded (`VS_TIMING`) — the cost
   of LLM-extraction pipelines is part of the result, not hidden.
4. All rows run on the same machine in the same session (within-run
   comparison, the project's standing bench discipline), inside Docker.
5. Raw logs land in the repo alongside the results.

## The column only we can fill

Every undercroft row runs **fully sealed** (XChaCha20-Poly1305 content +
sealed indexes, HMAC-verified reads, audit chain live) with **zero
external calls** in its default configuration (deterministic offline
embedder). No competitor has an equivalent mode: their local setups
still run plaintext stores, and their extraction pipelines call an LLM
on every write. When reading the table, remember what the undercroft
number is paying for and the others are not.

Note also what each system *stores*: undercroft retrieval returns the
**verbatim** conversation text; extraction-based systems return
LLM-distilled facts. Session-recall scoring is neutral to that
difference (metadata either comes back or it doesn't), but the products
are answering different questions about trust.

## Results

Hardware/context for all rows: one Windows 11 host, Docker Desktop
(same VM for every row), CPU-only. k=10, session granularity.

Every row in a published run is **fully local** — no system makes any
off-machine call; that is the ground rule, not a differentiator. The
"model runtime" column records what each system additionally requires
*on* the machine: undercroft's default path calls no model at all
(deterministic embedder; neural embedders optional, never an LLM),
while extraction-based systems invoke a local LLM + embedder on every
write — their architecture, reported as such.

| System | Config | Corpus | R@10 | search ms/q | Sealed at rest | Model runtime | Notes |
|---|---|---|---|---|---|---|---|
| **undercroft** (native) | sealed vault, default offline hash embedder, BM25+cosine fusion | LoCoMo full (10 convos, 1982 QA) | **94.6%** (1875/1982) | 5.5 | **yes** | **none** | zero-setup row; ingest 16.5 s / 1271 chunks; log `.handover/vs_native_locomo.log` |
| **undercroft** (best local) | sealed, MiniLM ONNX + ColBERT rescore (`colbert-ort`) | LoCoMo full | **96.5%** (1913/1982) | 52.9 | **yes** | local neural embedder + ColBERT (no LLM) | measured v0.23.0, log `.handover/colbert_fde_locomo2.log`; question-for-question stable across 4 configs |
| **undercroft** (native, subset) | as above (same-subset comparator for the mem0 row) | LoCoMo convos 1–2 (302 QA) | **96.7%** (292/302) | 3.8 | **yes** | **none** | ingest **2.5 s** / 177 chunks; log `.handover/vs_native_locomo_subset.log` |
| **undercroft** (MiniLM, subset) | sealed, MiniLM ONNX embedder (tract) — the neural-vs-neural comparator: their nomic vs our MiniLM, still no LLM | LoCoMo convos 1–2 (302 QA) | **97.4%** (294/302) | 125.7 | **yes** | local neural embedder (no LLM) | ingest **24.4 s** / 177 chunks; log `.handover/vs_native_onnx_subset.log` |
| **mem0** (local, measured) | OpenMemory (`mem0/openmemory-mcp`) + qdrant; LM Studio backend: qwen3.6-35B-A3B (MoE, thinking off) extraction + nomic-embed-text-v1.5; REST add, MCP semantic search | LoCoMo convos 1–2 (302 QA) | **67.9%** (205/302) | 93.2 | no (plaintext qdrant) | local LLM + embedder per write | ingest **4 h 07 m** / 177 chunks (~84 s/chunk, extraction-bound); 55 memories retained of 177 chunks — the Personal-Information-Organizer rubric discards non-personal content by design (raw traffic shows `{"facts": []}` for e.g. project-launch turns; log `.handover/vs_mem0_locomo.log`). Two documented transport adaptations, content-neutral: `response_format json_object→(none)` for LM Studio 0.4.19, embeddings zero-padded 768→1536 for OpenMemory's fixed qdrant dims (cosine-order preserving) — `deploy/bench-vs/lmstudio-shim.js` |
| Supermemory (self-host) | local binary/container | *pending* | *pending* | — | no | per its config | adapter shipped |
| Zep/Graphiti | — | — | *adapter pending* | — | no | local LLM per write | graph build cost expected to dominate ingest |
| Letta | — | — | *adapter pending* | — | no | local LLM runtime | archival-memory surface |

Reproduce any row:

```bash
docker compose run --rm test \
  cargo run --release -p undercroft-bench -- vs \
  /path/to/locomo10.json --system undercroft -k 10
# HTTP systems: bring their stack up (deploy/bench-vs/), then
#   ... vs /path/to/locomo10.json --system mem0 --url http://host:8000
```

Competitor stacks and pinned configurations live in
[`deploy/bench-vs/`](../deploy/bench-vs/README.md). Endpoint paths are
env-overridable (`UNDERCROFT_VS_URL`, `UNDERCROFT_VS_ADD_PATH`,
`UNDERCROFT_VS_SEARCH_PATH`, `UNDERCROFT_VS_BEARER`) so upstream API
drift is absorbable without a rebuild.

### Reading the mem0 row

The 67.9% vs 96.7% gap on the identical subset is not an artifact of the
harness — both systems saw byte-identical chunks and the same scorer,
and the mem0 pipeline ran their published server with a strong local
model (raw request/response traffic logged). The gap has two designed
causes, both worth understanding on their own terms:

1. **Extraction discards by rubric.** mem0's system prompt extracts
   *personal* facts (preferences, relationships, plans). Conversation
   content outside that rubric returns `{"facts": []}` and is simply
   never stored — 177 ingested chunks became 55 memories. LoCoMo's
   questions frequently target exactly the discarded material. This is
   the architecture, not a bug: extraction-based memory answers "what
   should I remember about this user," verbatim memory answers "what
   was said."
2. **Write cost is the price of extraction.** ~84 s per chunk on this
   host (two-plus LLM calls per write) versus 14 ms for the sealed
   vault — ingest of the same corpus took 4 h 07 m against 2.5 s, a
   ~6,000× difference that no amount of GPU shrinks to parity, because
   one design calls a language model per write and the other never
   does.

## Honest caveats

- Session-recall favors systems that preserve provenance metadata; it
  does not measure answer *synthesis* quality. Extraction systems may
  score differently on end-to-end QA metrics — that is a different
  benchmark, stated openly.
- LoCoMo's conversations are synthetic-ish research data; results are
  comparative signals, not product guarantees.
- Competitor APIs evolve; each published row records the image digest /
  version it ran against.
