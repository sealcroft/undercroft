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
   need an LLM + embedder; the local stack (Ollama, model pinned) is
   recorded per row. We do not run competitors against paid cloud APIs —
   the comparison is local-vs-local, which is undercroft's arena.
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

| System | Config | Corpus | R@10 | search ms/q | Sealed at rest | External calls | Notes |
|---|---|---|---|---|---|---|---|
| **undercroft** (native) | sealed vault, default offline hash embedder, BM25+cosine fusion | LoCoMo full (10 convos, 1982 QA) | **94.6%** (1875/1982) | 5.5 | **yes** | **none** | zero-setup row; ingest 16.5 s / 1271 chunks; log `.handover/vs_native_locomo.log` |
| **undercroft** (best local) | sealed, MiniLM ONNX + ColBERT rescore (`colbert-ort`) | LoCoMo full | **96.5%** (1913/1982) | 52.9 | **yes** | none (local models) | measured v0.23.0, log `.handover/colbert_fde_locomo2.log`; question-for-question stable across 4 configs |
| mem0 (OSS, local) | OpenMemory/mem0 server + Ollama (model TBD at run) | *pending* | *pending* | — | no | local LLM per write | adapter shipped; live run requires the mem0 stack up |
| Supermemory (self-host) | local binary/container | *pending* | *pending* | — | no | depends on config | adapter shipped |
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

## Honest caveats

- Session-recall favors systems that preserve provenance metadata; it
  does not measure answer *synthesis* quality. Extraction systems may
  score differently on end-to-end QA metrics — that is a different
  benchmark, stated openly.
- LoCoMo's conversations are synthetic-ish research data; results are
  comparative signals, not product guarantees.
- Competitor APIs evolve; each published row records the image digest /
  version it ran against.
