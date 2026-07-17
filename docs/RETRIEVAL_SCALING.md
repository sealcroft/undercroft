# Retrieval scaling & latency

How Undercroft retrieves, where the time and memory actually go (measured), and
the architecture for scaling to large corpora **without** trading one problem
for another. Local-first and the sealed-vault invariants constrain the design
throughout: sealed vaults never persist a plaintext-derived index to disk.

## The pipeline today

`search` runs three stages:

1. **Candidate generation** — pull candidates. Default: full O(n) cosine scan
   over the decrypted embeddings (an FTS5 BM25 prefilter narrows it for large
   *hmac-only* vaults). An experimental in-memory HNSW prefilter exists behind
   the off-by-default `hnsw` feature.
2. **Fusion** — cosine + Okapi BM25 (+ recency), the hybrid rank.
3. **Reranking (optional)** — a cross-encoder re-scores the top-N by the full
   `(query, passage)` pair.

## Measured costs (LoCoMo, 1,982 QA, and synthetic corpora)

Two costs dominate, and they are **independent** — conflating them is the trap.

### Cost 1 — scoring: the reranker

| Config | R@10 | Latency/query |
|---|---|---|
| hash + BM25 (no model, no reranker) | 94.6% | ~6 ms |
| MiniLM + BM25 (bi-encoder) | 94.6% | ~128 ms |
| + cross-encoder reranker | ~98% | **~16,600 ms** |

The reranker buys **+3 pts** but costs **~2,700×** the fusion-only search: it
runs ~60 full cross-encoder forward passes per query (one per candidate,
~277 ms each). The embedder choice is noise next to it (hash+reranker and
MiniLM+reranker are within 1%). BM25 fusion, by contrast, is a **free** +1.9 pts
over legacy/rrf. On LoCoMo, MiniLM over hash is a wash under BM25 — the model
earns its keep only with weaker fusion.

### Cost 2 — candidate generation at scale (synthetic, hash embedder)

| N | full-scan q/s | in-mem HNSW q/s | speedup | HNSW Recall@5 |
|---|---|---|---|---|
| 2,000 | 31.4 | 402.7 | 12.8× | 100.0% |
| 5,000 | 12.3 | 390.7 | 31.7× | 99.7% |
| 20,000 | ~3 | 321.2 | ~100× | 92.4% |
| 50,000 | ~1.2 | 271.0 | ~225× | 60.3% |

Full-scan is O(n)/query; HNSW holds ~270–400 q/s regardless of n. The win is
real and grows without bound — **but** the in-memory prototype has two flaws:

- **RAM is O(corpus)** (~1.5 KB/vector + graph edges → ~2–2.5 GB per million
  vectors), plus a full-corpus decrypt + rebuild on every open. Infeasible for
  IoT or billion-scale. *In-memory solves latency by creating a memory problem.*
- **Recall collapses at a fixed over-fetch** (256): fine to ~5k, then 92% at
  20k, 60% at 50k. `ef_search`/over-fetch must scale with n.

So in-memory HNSW is a **proof the algorithm helps**, not the destination.

## The architecture: two costs, two purpose-built fixes

### Retrieval → on-disk PQ (bounded RAM), not in-memory HNSW

Product Quantization compresses each vector ~32× (1.5 KB → 48 bytes). Only the
~400 KB codebook stays resident; the codes live **on disk** and search streams
ADC over them. RAM is bounded at any corpus size — the standard
billion-scale-on-modest-RAM design.

**Shipped (flat PQ prefilter, hmac-only vaults)** — the invariant rule mirrors
FTS5: hmac-only vaults may hold plaintext-derived indexes on disk, sealed
vaults never do (their encrypted-at-rest variant is the research follow-up).
`set_pq(true)` / `UNDERCROFT_RETRIEVAL=pq`; codes maintained incrementally on
write with FTS-style self-heal. Measured (synth, hmac-only, N=20k):

| Mode | N=20k q/s | N=20k R@5 | N=50k q/s | N=50k R@5 | RAM |
|---|---|---|---|---|---|
| true full-scan | ~6.6 (extrap.) | 100% | ~2.6 (extrap.) | 100% | transient O(n) |
| FTS prefilter (default) | 76.7 | 100% | 33.2 | 100% | on-disk |
| **PQ prefilter** | 59.2 | **98.6%** | 18.6 | **98.9%** | **codebook only** |
| in-memory HNSW | 454.1 | **93.1%** | 377.7 | **71.7%** | O(corpus) |

The differentiator, now confirmed at both sizes: **PQ recall is flat in N**
(98.6% → 98.9% — ADC is exhaustive over the codes, quantization error only),
where HNSW's graph approximation collapses without per-N tuning (93% → 72%).
PQ's flat scan is still O(n) — q/s falls ~linearly (59 → 19), ~3–9× the true
scan. HNSW stays the raw-speed option when RAM allows and its `ef` is tuned.
**Still open:** the sealed-tier encrypted index.

### IVF inverted lists — and the three scan bottlenecks the sweeps exposed

IVF was built to make the flat ADC scan sub-linear: a coarse quantizer
(`nlist ≈ √N` centroids, same deterministic k-means) partitions the codes,
and a query ADC-scans only the `nprobe` nearest lists. Benchmarking it
(synthetic corpus, hash embedder, hmac-only, 4,000 sampled queries per cell,
second 24-core host — absolute q/s not comparable to the tables above;
every comparison below is within one run) surfaced three structural costs,
each fixed and re-measured:

1. **Random-access layout.** With codes keyed by `seq` + a secondary `list`
   index, every probed row was a point B-tree fetch — a 23%-fraction probe
   ran *slower* than the sequential flat scan (16.6–22.6 q/s vs 26.5 flat
   at N=20k, and recall tracks the probed **fraction**: 3% → 68.7%,
   11% → 86.9%, 23% → 99.6% = flat parity). Fix: cluster the table
   `WITHOUT ROWID, PRIMARY KEY (list, seq)` so a probed list is one
   sequential range scan, and default `nprobe = nlist/4` (a fixed count
   would silently lose recall as N grows). Result: probed 23% beat flat
   28.6 vs 23.9 q/s at recall parity.
2. **Per-search coherence check.** The matched-count `JOIN` that guarded
   against index drift cost more at N=50k than the probed scan it guarded
   (IVF only +13% over flat). Fix: verification is event-driven — first
   search after open, or after a write that couldn't encode; a successful
   incremental encode is coherent by construction. Crash drift is still
   caught (a fresh open starts unverified).
3. **Per-row join in the scan itself.** The scan joined `drawers` on every
   code row only to exclude delete-orphans — one point lookup into the big
   drawers B-tree per code (12.5k/query probed, 50k flat). Fix: scan
   `drawer_pq` alone; `delete_drawer` purges its code row; a crash-window
   orphan wastes one of 256 over-fetched candidate slots and is swept by
   the next rebuild.

**Final numbers** (within one uncontended run, after all three fixes):

| N | flat PQ q/s | IVF-default q/s | R@5 (both) |
|---|---|---|---|
| 20,000 | 34.4 | **38.3** (+11%) | 99.6% |
| 50,000 | 14.8 | **15.9** (+7%) | 99.1% |

The fixes lifted the **flat** path itself ~45% (23.9 → 34.4 q/s at N=20k,
10.1 → 14.8 at 50k, same-host same-run comparisons) — every PQ user gets
that. IVF's *marginal* win on top is +7–11% at these sizes because the pure
ADC arithmetic is now only ~4–6 ms even at 50k; its share (the only part of
query cost that scales with N) grows with the corpus, so IVF is kept on by
default above `UNDERCROFT_IVF_MIN` (8192; `off` restores the flat scan,
`UNDERCROFT_IVF_NPROBE` overrides the probe count). Recall parity, in-place
migration from the v0.14.0 layout, and self-healing partitions (retrain when
the corpus doubles past their training size) are all test-asserted.

### Scoring → two strategies, chosen by the deployment

The +3 pts comes from a **cross-encoder** reranker, which runs one full forward
**per candidate at query time**. That per-candidate cost is the whole problem,
and the right handling depends on how many cores the box has.

#### Cross-encoder + rayon — the many-core option (shipped)

Rerank the top `top_n` fusion candidates, fanning the independent forward passes
across cores. Measured on LoCoMo:

- **rayon (done):** sequential 16,600 ms → **1,103 ms/query on 24 cores (~15×)**,
  R@10 99.0% unchanged.
- **`top_n` as a true pool cap (done):** rerank exactly the top `top_n`, the tail
  keeps fusion order. `top_n=20` → **694 ms @ 98.7%** (the accuracy knee),
  `top_n=10` → **389 ms @ 97.4%**. Net ~24–43× over the original.

**But this is O(top_n / cores):** latency ≈ ⌈`top_n`/cores⌉ × one-forward. On a
24-core host `top_n=20` is one wave; on a **4-core** box it is 5 waves (~270 ms)
— the strategy doesn't scale *down*. Sweet spot: `top_n = min(accuracy-plateau,
cores)`; when `top_n < cores`, give each forward `cores/top_n` intra-op threads
so no core sits idle. This is fundamentally a **many-core optimization.**

#### ColBERT late interaction — the core-independent option (shipped, measured)

A cross-encoder is slow because it encodes each `(query, passage)` pair at query
time. Late interaction encodes passage tokens **once at ingest** (stored on
disk, int8-quantized; sealed vaults AEAD-seal every matrix under a distinct
`/tok` AAD domain — the first encrypted-at-rest derived store) and, per query,
does **one** query-encode forward plus a cheap **MaxSim** (max-cosine per query
token, summed) — plain arithmetic, **no transformer per candidate**. Query cost
is **~one forward, independent of `top_n` and of core count**. ColBERT is
BERT-family, so it runs in tract (unlike the DeBERTa rerankers tract rejects).

**Measured** (LoCoMo full 1,982 QA, hash embedder + colbertv2.0 on tract):

| Second stage | R@10 | search ms/q | scales w/ cores |
|---|---|---|---|
| none (bm25 fusion) | 94.6% | ~6 | — |
| **ColBERT late interaction (tract)** | **96.77%** | **92.7** | **no — same on 4 or 24** |
| cross-encoder (ort int8, `top_n=20`) | 97.68% | 101–327 *(24-core)* | yes — ~5× worse on 4 cores |

+2.2 pts over fusion at a flat ~93 ms/query; the cross-encoder buys ~1 more
point but only at many-core prices. Ingest carries the moved cost (~0.37 s per
drawer on tract — one doc forward at write time). Enable with
`UNDERCROFT_RERANKER=colbert` + `UNDERCROFT_COLBERT_MODEL` (doc export) /
`_QUERY_MODEL` (query export) / `_TOKENIZER`; the cross-encoder wins when both
stages are configured. Drawers written before the encoder was attached keep
their fusion rank (never sunk); export recipe below.

**Export recipe** (models are user-supplied, as always): wrap the checkpoint's
BERT + its `linear.weight` projection + L2-normalize in one module and export
**fixed-shape** ONNX at query (32) and doc (256) lengths — the dynamo exporter
emits `Min(512, seq)` symbolic dims and dynamic-axes legacy exports emit a
`Range` op, both of which tract rejects; fixed shapes bake `arange` into
constants and load clean.

**So: cross-encoder+rayon is the accuracy ceiling on big boxes; ColBERT is the
portable answer for the common 4-core / edge deployment.**

### Inference runtime → tract (pure-Rust) or ONNX Runtime (fast)

Every forward above goes through an inference runtime. Per-forward latency, same
onnx models, seq 256, on this CPU (`avx512_vnni`, no GPU reachable):

| Model | tract (pure-Rust) | ORT fp32 1-thr | ORT fp32 all | ORT int8 1-thr | ORT int8 all |
|---|---|---|---|---|---|
| MiniLM embed | ~128 ms | 53.7 | 28.1 | 24.9 | **15.0** |
| cross-encoder | ~140–277 ms | 56.2 | 26.8 | 24.4 | **13.3** |

**ORT is ~2.5× faster than tract per forward, int8 (VNNI) ~2× more** — validated
in Rust via the `ort` crate (matches Python onnxruntime; same C++ backend).
Accuracy is **runtime-invariant** (identical weights). Tradeoff: `ort` links
ORT's **C++** library, breaking the pure-Rust / zero-C-dep property (audit
surface, wasm/IoT — though ORT ships mobile/wasm builds). Offered
**feature-gated (`ort`), tract kept as the pure-Rust fallback**
([`undercroft-embed-ort`](../crates/undercroft-embed-ort)).

Measured **end-to-end** on LoCoMo (convos 0-1, 302 QA), this 24-core host.
`OrtReranker` holds a **session pool** (default = core count,
`UNDERCROFT_ORT_POOL`; `pool=1` = one all-core batched session, the few-core
mode) and fans the independent forwards across it:

| Reranker config | top_n=20 | top_n=10 | top_n=5 | R@10 |
|---|---|---|---|---|
| tract + rayon | 694 ms | 389 ms | 321 ms | 98.7 / 97.4 / 97.4 |
| ORT batched (pool=1) | 614 ms | 386 ms | 251 ms | same |
| ORT session-pool fp32 | 427 ms | 214 ms | 142 ms | same |
| **ORT session-pool int8** | **327 ms** | **171 ms** | **101 ms** | 98.3 / 98.0 / 98.0 |

Ingest embed: tract ~24 s → ORT ~5 s (**~4–5×**). int8 accuracy is within noise
of fp32 (±1–2 questions of 302). Net: the reranker went **16.6 s → ~101–171 ms
(~100–160×)** at ~98% R@10. Two structural notes: (1) concurrent forwards
contend for memory bandwidth (BERT is memory-bound), so a wave costs more than
an isolated forward — int8's 4× smaller weights attack exactly that, and int8
needs **no code change** (point `UNDERCROFT_RERANK_MODEL` at a quantized file);
(2) on a **4-core** box use `pool=1` (batched) — tract+rayon degrades to waves
there while one ORT forward uses whatever cores exist. On a GPU target,
ORT-CUDA takes each forward to ~1–5 ms.

### ColBERT build plan (shipped — see the measured section above)

Landed as designed: `LateInteraction` trait (`undercroft-core/src/late.rs`) +
`OnnxColbert` on tract (`undercroft-embed-onnx/src/late.rs`, two fixed-shape
plans); ingest-time doc encode → int8 token matrices (per-row scale) in
`drawer_tok`, sealed vaults AEAD-seal each matrix (`Vault::tokens_at_rest`,
`/tok` AAD domain); one query forward + MaxSim rescore of the fusion top-N
(`undercroft-store/src/latestage.rs`), opt-in via `UNDERCROFT_RERANKER=colbert`.

Still open on this path:
1. **`ort` backend for the query forward** (~2.5× per forward — would take
   ~93 ms/q toward ~40 ms).
2. **PLAID-style residual/PQ compression** of the token store (int8 today,
   ~4×; PQ would give ~32× like the retrieval codes).
3. **Punctuation filtering** on doc rows (ColBERT convention; small win).
4. **Cross-encoder path** (independent): a true batched
   `OnnxReranker::score_batch` in tract (blocked by a fixed batch-dim-1
   model load).

## Security tiering (same invariant, applied per level)

| Vault level | Retrieval index | Token/rescore store | RAM |
|---|---|---|---|
| **hmac-only** | on-disk IVF-PQ (plain) — shipped | on-disk ColBERT tokens (plain) — shipped | bounded |
| **sealed** | IVF-PQ **encrypted at rest** — shipped | ColBERT tokens **encrypted at rest** — shipped | bounded (decrypt-once cache) |

**Sealed IVF-PQ, measured** (synth, 4,000 sampled queries, within one run):
every code row is AEAD-sealed (`list ‖ code`, bound to its seq under the
`/pq` AAD domain — a plaintext list id would leak semantic clustering), the
codebook/centroids are sealed in `pq_meta`, and search decrypts all rows
**once per open** into a ~52 B/drawer RAM cache and ADC-scans there. An
offline attacker sees fixed-size sealed blobs — the drawer count it already
knows.

| Sealed vault | N=20k q/s | N=20k R@5 | N=50k q/s | N=50k R@5 |
|---|---|---|---|---|
| decrypt-scan (old only option) | 2.1 | 99.9% | 1.1 | 99.9% |
| **sealed IVF-PQ** | **33.4 (×16)** | 99.6% | **11.8 (×11)** | 99.1% |
| hmac-only IVF-PQ (within-run ref) | 37.1 | 99.6% | 8.1 | 99.1% |

Encryption stops being a query-time cost: at 20k the sealed path runs at
~90% of the plaintext index, and at 50k it *beat* the within-run plaintext
reference — the decrypt-once RAM cache skips the per-query SQLite code
streaming that hmac-only still pays (cross-run note: a quieter v0.15 run
measured hmac@50k at 14.8 q/s, so treat the 50k ordering as parity, not a
sealed win). Obvious follow-up: give hmac-only the same RAM cache.

hmac-only content is already unencrypted on disk, so on-disk indexes are
invariant-consistent — this mirrors the existing on-disk FTS5, which sealed
vaults never get (FTS is inherently a plaintext structure). Sealed vaults now
keep the same PQ/IVF structures **encrypted at rest** with a decrypt-once RAM
cache (~52 B/drawer — 5 MB per 100k drawers, bounded). The remaining research
refinement is *page-level* decryption (decrypt only probed lists instead of
all codes at open) — worthwhile only past the multi-million-drawer mark where
the cache warmup itself gets heavy.

## Restore economics — derived data is a portable, verifiable cache

Restoring or importing a shard today rebuilds the derived artifacts, and they
are wildly asymmetric: FTS re-triggers in seconds, PQ/IVF retrains in ~10–20 s
at 20k drawers — but **ColBERT token matrices cost one transformer forward
per drawer** (~2 h for 20k on tract, serial). The plan, in leverage order:

1. **Portable artifacts (transport beats recompute) — shipped.** Every
   derived artifact is a pure function of `(content, model identity)`, and
   drawer ids are already deterministic — so token matrices are
   *content-addressed cache* and ship inside `/v1` export bundles (each
   JSONL line carries optional `tok = {model, b64}`); import re-seals them
   under the destination vault's key. Restore becomes copy + verify, zero
   forwards. The architecture makes this uniquely safe: artifacts are
   advisory, model identity is matched before use, and every served result
   is still HMAC-verified — an imported artifact can only mis-rank, never
   forge (test: a destination whose encoder panics on doc-encode rescores
   correctly from imported artifacts alone).
2. **Instant restore, background accuracy — shipped.** Drawers without
   token matrices keep their fusion rank, so a restored shard serves at
   bm25 quality immediately; `undercroft repair --tokens` (or a daemon tick
   calling `late_backfill`) covers the gap in bounded batches — with ort
   int8 + batching + rayon (still open), ~10 min for 20k drawers instead
   of ~2 h.
3. **Token-store PQ + pruning (the PLAID move) — shipped, measured.**
   [pq.rs](../crates/undercroft-store/src/pq.rs) re-used on the token
   vectors: a 128-dim token is **16 PQ bytes (8.2× below int8, 33× below
   f32** — a ~150-token drawer's matrix drops 19.8 KB → 2.4 KB), and MaxSim
   scores v2 matrices via per-query-row **dot-product LUTs** (tables built
   once per query row; each candidate token costs 16 adds instead of a
   128-dim dot). Doc-side punctuation rows attend but aren't stored. The
   codebook trains event-driven from the vault's own matrices past
   `UNDERCROFT_TOK_PQ_MIN` (default 256), persists **sealed** in `tok_meta`,
   and repacks every stored row in the same pass; v1/v2 coexist and
   portable artifacts always export as universal v1.
   **Gate met**: LoCoMo 96.57% R@10 (1914/1982) vs 96.77% plain — −0.2 pts
   for 8× storage. Search 96.7 vs 92.7 ms/q: *neutral, honestly read* —
   the bench amortizes each store's one-time train+repack into the query
   phase, and the ~80 ms tract query-forward masks the LUT win until the
   `ort` query-forward (~40 ms) lands. The 4-bit register-LUT (`std::arch`)
   variant remains a micro-optimization for after that.

Nothing standard offers this combination: late-interaction retrieval whose
entire derived state is **AEAD-sealed at rest, content-addressed, portable
across backups, self-healing, and scored via register-LUT MaxSim over PQ
codes**. Recompute-everything is slow; plaintext indexes are leaky; this is
neither.

## Configurable — pick per deployment, not one-size-fits-all

Retrieval, scoring, and runtime are **independent, user-selectable axes**. The
defaults stay local-first and pure-Rust; every faster option is opt-in.

**Retrieval (candidate generation)**

| Option | RAM | Best for | Status |
|---|---|---|---|
| Full-scan cosine + BM25 | O(corpus) transient | small palaces (default) | shipped |
| In-memory HNSW (`hnsw`) | O(corpus) | moderate corpora, raw speed | experimental |
| **On-disk PQ + IVF** (`set_pq`, `UNDERCROFT_RETRIEVAL=pq`) | ~O(codebook) | large corpora, edge/IoT (hmac-only) | **shipped** |
| + sealed encrypted tier | ~O(codebook) | sealed vaults | planned |

**Scoring**

| Option | Latency (4-core) | Accuracy | Best for |
|---|---|---|---|
| No reranker (bi-encoder + BM25) | ~one embed forward | good | fastest / edge |
| Cross-encoder + rayon (`top_n`) | O(⌈top_n/cores⌉) | best | many-core servers |
| ColBERT late interaction | ~one forward, flat | ~best | portable default, edge |

**Inference runtime**

| Option | Speed | Portability |
|---|---|---|
| tract | baseline | pure-Rust, zero C dep (default) |
| `ort` (ONNX Runtime) | ~2.5–10× | links C++ ORT; opt-in feature |
| `ort` + GPU (CUDA/etc.) | ~50× | needs GPU |

A 4-core edge box picks **IVF-PQ + ColBERT + tract-or-ort-int8**; a many-core
server can add the **cross-encoder + rayon** fast path; a GPU box turns on
**ort-CUDA**. Same engine, config-selected.

## Phased plan

1. **Reranker latency (done):** rayon parallelism (16,600 → ~1,100 ms) + `top_n`
   true cap → **694 ms @ 98.7% (top_n=20), 389 ms @ 97.4% (top_n=10)** — ~24–43×.
2. **`ort` runtime backend (done, incl. session pool + int8):** feature-gated
   ONNX Runtime behind the embedder/reranker traits (`undercroft-embed-ort`),
   tract kept as fallback. Measured: ingest ~4–5× faster; reranker
   **327 ms @ 98.3% (top_n=20) / 101 ms @ 98.0% (top_n=5)** with the session
   pool + int8 models — ~100–160× over the original sequential reranker.
3. **On-disk PQ retrieval (done, flat + IVF):** bounded-RAM prefilter for
   hmac-only vaults — codebook-only RAM, recall holds where HNSW's collapses.
   IVF inverted lists shipped on top (clustered `(list, seq)` layout,
   `nprobe = nlist/4`, self-healing partitions) and the scan-path fixes they
   motivated lifted flat PQ itself ~45%; IVF adds +7–11% at N=20–50k and
   grows with N. Remaining: the sealed-tier encrypted-at-rest index.
4. **ColBERT late interaction (done):** the core-independent second stage —
   LoCoMo 94.6 → **96.77% R@10 at a flat 92.7 ms/query** on tract (the
   cross-encoder's 97.68% costs 101–327 ms on 24 cores and ~5× that on 4).
   Sealed vaults AEAD-seal the token store — the first encrypted-at-rest
   derived store. Remaining: `ort` query-forward backend, PLAID-style token
   compression.
5. **Sealed-tier encrypted-at-rest retrieval index (done):** the token
   *rescore* store shipped sealed in (4), and the IVF-PQ *prefilter* now
   ships sealed too — AEAD rows + decrypt-once RAM cache; sealed search
   **2.1 → 33.4 q/s at N=20k (×16)**, parity with the plaintext index.
   Remaining refinements: the hmac-only path can adopt the same RAM cache;
   page-level decryption matters only past multi-million drawers.
6. **Restore economics** (next): portable derived artifacts in export
   bundles, background backfill, token-store PQ with register-LUT MaxSim —
   see "Restore economics" above.

The in-memory HNSW (`hnsw` feature) stays as an experimental fast path for
moderate sealed corpora and as the benchmark baseline — not the default.
