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

### Retrieval → on-disk IVF-PQ (bounded RAM), not in-memory HNSW

Product Quantization compresses each vector ~16–32× (1.5 KB → ~48–96 bytes).
Only the codebook + PQ codes stay resident (or are mmap'd); full-precision
vectors live **on disk** and are fetched only for the final handful of
candidates that get re-scored. RAM becomes ~O(√corpus) / O(codes), not
O(corpus). This is the standard billion-scale-on-modest-RAM design. The int8
embedding quantization already in the vault layer is the first step toward PQ.

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

#### ColBERT late interaction — the core-independent default

A cross-encoder is slow because it encodes each `(query, passage)` pair at query
time. Late interaction encodes passage tokens **once at ingest** (stored on disk,
quantized) and, per query, does **one** query-encode forward plus a cheap
**MaxSim** (max-cosine per query token, summed) — plain SIMD-friendly linear
algebra, **no transformer per candidate**. Query cost is therefore **~one
forward, independent of `top_n` and of core count** — the same ~40–130 ms on 4
cores or 24. Cross-encoder-competitive accuracy at bi-encoder latency; the
expensive work moves to ingest + disk. ColBERT is BERT-family, so it runs in
tract (unlike the DeBERTa rerankers tract rejects).

| Reranker (4 cores) | latency | scales w/ `top_n` | scales w/ cores |
|---|---|---|---|
| cross-encoder + rayon (`top_n=20`) | ~270 ms | yes | yes |
| **ColBERT late interaction** | **~40–130 ms** | **no** | **no** |
| bi-encoder only (no rerank) | ~40–130 ms | no | no |

**So: cross-encoder+rayon is the fast path on big boxes; ColBERT is the portable
default and the answer to the common 4-core / edge deployment.**

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

### ColBERT build plan

1. **Model + runtime.** A BERT-family ColBERT checkpoint exported to ONNX
   (user-supplied, like the embedder); tract for pure-Rust, `ort` for speed.
2. **Ingest.** Encode each drawer's passage tokens → a per-token vector matrix;
   quantize (int8 / PQ, reusing [pq.rs](../crates/undercroft-store/src/pq.rs)) and
   store. hmac-only: plain on disk (mirrors FTS5); sealed: a new **sealed token
   store, encrypted at rest** like drawer content.
3. **Query.** One forward to encode the query tokens; MaxSim against the stored
   passage-token matrices of the IVF-PQ candidate shortlist; aggregate → score;
   blend with or replace the fusion rank.
4. **Storage.** Per-token vectors are larger than one embedding — PLAID-style
   residual/PQ compression keeps them on-disk-cheap; only the shortlist's tokens
   are read per query (bounded).
5. **Trait fit.** A new `LateInteraction` scorer behind the same opt-in wiring as
   the reranker; off by default. tract + `ort` backends behind it.
6. **Still open on the cross-encoder path** (near-term, independent of ColBERT):
   int8 quantization and a true batched `OnnxReranker::score_batch` (blocked
   today by a fixed batch-dim-1 model load).

## Security tiering (same invariant, applied per level)

| Vault level | Retrieval index | Token/rescore store | RAM |
|---|---|---|---|
| **hmac-only** | on-disk IVF-PQ (plain) | on-disk ColBERT tokens (plain) | bounded |
| **sealed** | IVF-PQ **encrypted at rest** | ColBERT tokens **encrypted at rest** | working set only |

hmac-only content is already unencrypted on disk, so on-disk indexes are
invariant-consistent — this mirrors the existing on-disk FTS5, which sealed
vaults never get. Sealed vaults keep the same structures but encrypted at rest,
with only the working set decrypted transiently (like the emb cache). The
encrypted-at-rest, page-decryptable sealed index is the genuine research item.

## Configurable — pick per deployment, not one-size-fits-all

Retrieval, scoring, and runtime are **independent, user-selectable axes**. The
defaults stay local-first and pure-Rust; every faster option is opt-in.

**Retrieval (candidate generation)**

| Option | RAM | Best for | Status |
|---|---|---|---|
| Full-scan cosine + BM25 | O(corpus) transient | small palaces (default) | shipped |
| In-memory HNSW (`hnsw`) | O(corpus) | moderate corpora, many-core | experimental |
| On-disk IVF-PQ | ~O(codebook) | large corpora, edge/IoT | planned (pq.rs primitive done) |

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
3. **On-disk IVF-PQ retrieval** (bounded RAM; hmac-only plain, sealed encrypted).
   Retire in-memory HNSW as a default.
4. **ColBERT late interaction** — the core-independent scoring default (the
   4-core answer); cross-encoder+rayon stays as the many-core fast path.
5. **Sealed-tier encrypted-at-rest** IVF-PQ + ColBERT token store (research).

The in-memory HNSW (`hnsw` feature) stays as an experimental fast path for
moderate sealed corpora and as the benchmark baseline — not the default.
