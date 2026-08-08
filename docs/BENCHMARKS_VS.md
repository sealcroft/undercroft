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
   (Transport-level retries of *idempotent* calls — a timed-out write
   re-issued, a dropped session reconnected — are allowed, bounded,
   identical policy for every system, and visible in the raw logs; a
   multi-hour run must not die to one network hiccup.)
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
   When a row costs days of wall-clock (extraction pipelines), it may
   be sharded **by conversation** across runs on the identical pinned
   stack — `VS_RAW` lines carry exact numerators so shards sum without
   drift, and every shard log is published individually.
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
| **undercroft** (native) | sealed vault, default offline hash embedder, BM25+cosine fusion | LoCoMo full (10 convos, 1982 QA) | **94.6%** (1875/1982) | 5.5 | **yes** | **none** | zero-setup row; ingest 16.5 s / 1271 chunks; log [`benchmarks/logs/vs_native_locomo.log`](../benchmarks/logs/vs_native_locomo.log) |
| **undercroft** (best local) | sealed, MiniLM ONNX + ColBERT rescore (`colbert-ort`) | LoCoMo full | **96.5%** (1913/1982) | 52.9 | **yes** | local neural embedder + ColBERT (no LLM) | measured v0.23.0, log [`benchmarks/logs/colbert_fde_locomo2.log`](../benchmarks/logs/colbert_fde_locomo2.log); question-for-question stable across 4 configs |
| **undercroft** (native, subset) | as above (same-subset comparator for the mem0 row) | LoCoMo convos 1–2 (302 QA) | **96.7%** (292/302) | 3.8 | **yes** | **none** | ingest **2.5 s** / 177 chunks; log [`benchmarks/logs/vs_native_locomo_subset.log`](../benchmarks/logs/vs_native_locomo_subset.log) |
| **undercroft** (MiniLM, subset) | sealed, MiniLM ONNX embedder (tract) — the neural-vs-neural comparator: their nomic vs our MiniLM, still no LLM | LoCoMo convos 1–2 (302 QA) | **97.4%** (294/302) | 125.7 | **yes** | local neural embedder (no LLM) | ingest **24.4 s** / 177 chunks; log [`benchmarks/logs/vs_native_onnx_subset.log`](../benchmarks/logs/vs_native_onnx_subset.log) |
| **mem0** (local, measured) | OpenMemory (`mem0/openmemory-mcp`) + qdrant; LM Studio backend: qwen3.6-35B-A3B (MoE, thinking off) extraction + nomic-embed-text-v1.5; REST add, MCP semantic search | **LoCoMo full (10 convos, 1982 QA)** | **66.9%** (1326/1982) | 93–210 (per shard) | no (plaintext qdrant) | local LLM + embedder per write | Full corpus, sharded by conversation across four runs on the identical pinned stack (`VS_RAW` shard-additive by design): convos 1–2 = 205/302 · convo 3 = 112/193 · convo 4 = 166/260 · convos 5–10 = 843/1227; per-conversation R@10 spans **58.0–70.9%**. Ingest measured **92 s/chunk** (extraction-bound: 4 h 07 m/177 chunks + 21 h 13 m/814 chunks; ≈32 h full-corpus equivalent vs 16.5 s native). Extraction discards by rubric — 55 memories retained of 177 chunks on the measured subset (raw traffic shows `{"facts": []}` for non-personal content). Logs: [`vs_mem0_locomo.log`](../benchmarks/logs/vs_mem0_locomo.log), [`vs_mem0_convo3.log`](../benchmarks/logs/vs_mem0_convo3.log), [`vs_mem0_convo4.log`](../benchmarks/logs/vs_mem0_convo4.log), [`vs_mem0_locomo_5_10.log`](../benchmarks/logs/vs_mem0_locomo_5_10.log). Two documented transport adaptations, content-neutral: `response_format json_object→(none)` for LM Studio 0.4.19, embeddings zero-padded 768→1536 for OpenMemory's fixed qdrant dims (cosine-order preserving) — `deploy/bench-vs/lmstudio-shim.js` |
| Supermemory (self-host) | local binary/container | *pending* | *pending* | — | no | per its config | adapter shipped |
| Zep/Graphiti | — | — | *adapter pending* | — | no | local LLM per write | graph build cost expected to dominate ingest |
| Letta | — | — | *adapter pending* | — | no | local LLM runtime | archival-memory surface |

## Run it yourself

Ready-made runners live in [`benchmarks/`](../benchmarks/) for every
shell — each is a thin wrapper around the exact containerized
invocation the published rows used (nothing in a wrapper can bias a
number):

| Shell | Script |
|---|---|
| bash | [`benchmarks/run-vs.sh`](../benchmarks/run-vs.sh) |
| zsh | [`benchmarks/run-vs.zsh`](../benchmarks/run-vs.zsh) |
| PowerShell | [`benchmarks/run-vs.ps1`](../benchmarks/run-vs.ps1) |

**Requirements**: Docker with compose (no host toolchain needed), and
the LoCoMo dataset file — user-supplied research data from
[snap-research/locomo](https://github.com/snap-research/locomo), not
redistributed here. Competitor rows additionally need that system's
local stack ([deploy/bench-vs/](../deploy/bench-vs/README.md)) plus a
local LLM backend (LM Studio or Ollama), and hours of wall-clock —
extraction-based systems call an LLM on every write.

**Process**:

```bash
cp benchmarks/vs.env.example benchmarks/vs.env   # edit: dataset path, system, shard
./benchmarks/run-vs.sh                            # or run-vs.zsh / run-vs.ps1
```

The summary prints `VS_RAW`/`VS_TIMING` lines; the full log lands in
`benchmarks/logs/local/` (gitignored — only reviewed logs are published,
per [`benchmarks/logs/README.md`](../benchmarks/logs/README.md)). All
configuration is in the one env file
([`benchmarks/vs.env.example`](../benchmarks/vs.env.example), documented
inline); the raw harness invocation remains available for anyone who
wants to bypass the wrappers:

```bash
docker compose run --rm -v /path/to/dataset-dir:/data:ro test \
  cargo run --release -p undercroft-bench -- vs \
  /data/locomo10.json --system undercroft -k 10
```

Competitor stacks and pinned configurations live in
[`deploy/bench-vs/`](../deploy/bench-vs/README.md). Endpoint paths are
env-overridable (`UNDERCROFT_VS_URL`, `UNDERCROFT_VS_ADD_PATH`,
`UNDERCROFT_VS_SEARCH_PATH`, `UNDERCROFT_VS_BEARER`) so MemPalace API
drift is absorbable without a rebuild.

### Reading the mem0 row

The 66.9% vs 94.6% full-corpus gap (27.7 points over the same 1,982
questions) is not an artifact of the harness — both systems saw
byte-identical chunks and the same scorer, and the mem0 pipeline ran
their published server with a strong local model (raw request/response
traffic logged). The result is also stable: all ten conversations land
between 58.0% and 70.9%, so no subset choice could have changed the
story. The gap has two designed causes, both worth understanding on
their own terms:

1. **Extraction discards by rubric.** mem0's system prompt extracts
   *personal* facts (preferences, relationships, plans). Conversation
   content outside that rubric returns `{"facts": []}` and is simply
   never stored — 177 ingested chunks became 55 memories on the
   measured subset. LoCoMo's questions frequently target exactly the
   discarded material. This is the architecture, not a bug:
   extraction-based memory answers "what should I remember about this
   user," verbatim memory answers "what was said."
2. **Write cost is the price of extraction.** 92 s per chunk measured
   on this host (two-plus LLM calls per write) versus 13 ms for the
   sealed vault — full-corpus ingest ≈32 h against 16.5 s, a ~7,000×
   difference that no amount of GPU shrinks to parity, because one
   design calls a language model per write and the other never does.

**Server behavior observed during the run** (documented as evidence,
with the caveat that none of it affects the scored retrieval path):

- OpenMemory's background *categorization* feature is non-functional
  in the shipped `mem0/openmemory-mcp` image: it calls
  `chat.completions.with_response_format(...)`, an API that does not
  exist in any release of the bundled `openai` SDK (verified
  in-container; MemPalace `main` has since been corrected to
  `beta.chat.completions.parse`, but the published image still carries
  the broken call, erroring continuously — and even the corrected
  version hardcodes `model="gpt-4o-mini"` regardless of configured
  backend). Categories do not feed retrieval, so the row stands.
- `delete_all_memories` (the per-conversation isolation wipe)
  consistently exceeded a 600 s response timeout at every conversation
  boundary, succeeding on a reconnect-and-retry — visible verbatim in
  the shard logs. The adapter's bounded idempotent retries (fairness
  rule 1) exist because of this.
- Neither mem0's code (0.1.108) nor its documentation mentions
  thinking/reasoning models at all. Disabling qwen3.6's thinking mode
  (required for sane extraction latency, and only possible in the LM
  Studio UI — their API surface offers no lever) was a
  favorable-to-mem0 configuration choice we made and document here.

## Honest caveats

- Session-recall favors systems that preserve provenance metadata; it
  does not measure answer *synthesis* quality. Extraction systems may
  score differently on end-to-end QA metrics — that is a different
  benchmark, stated openly.
- LoCoMo's conversations are synthetic-ish research data; results are
  comparative signals, not product guarantees.
- Competitor APIs evolve; each published row records the image digest /
  version it ran against.
