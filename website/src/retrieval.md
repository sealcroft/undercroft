# Retrieval, scoring & scaling

Undercroft's search is a configurable pipeline, not a fixed stack. This page
documents how it works, what was **measured** (full datasets, inside Docker, on
real hardware), and which options to pick for which deployment — from a 4-core
edge box to a many-core server.

Every measurement below is reproducible with the harnesses in the repo; recall
figures and exact commands are in
[`benchmarks/RESULTS.md`](https://github.com/compufreq/undercroft/blob/main/benchmarks/RESULTS.md).
The engineering rationale is in
[`docs/RETRIEVAL_SCALING.md`](https://github.com/compufreq/undercroft/blob/main/docs/RETRIEVAL_SCALING.md).

## The pipeline

1. **Candidate generation** — shortlist drawers for a query.
2. **Fusion** — hybrid rank of the candidates (semantic cosine + Okapi BM25 +
   recency).
3. **Scoring (optional)** — a second stage that re-orders the top candidates
   for accuracy.

The two dominant costs — *candidate generation at scale* and *scoring* — are
**independent**, and each has its own purpose-built option.

## Measured results

All on **LoCoMo** (1,982 evaluable QA, session-recall @10) unless noted;
synthetic corpora for the pure scaling curves.

### Fusion is a free accuracy win

Hash embedder, no reranker, all three fusion modes:

| Fusion | R@10 | Latency/query |
|---|---|---|
| **BM25 (default)** | **94.6%** | ~6 ms |
| legacy | 92.7% | ~5 ms |
| rrf | 92.5% | ~6 ms |

BM25 buys **+1.9 pts at zero latency cost** — it re-ranks already-verified
candidates and is embedder-independent.

### The embedder is a wash under BM25

| Embedder (BM25) | R@10 | Query embed | Ingest (full corpus) |
|---|---|---|---|
| hash (zero-model) | 94.6% | ~6 ms | ~9 s |
| MiniLM-L6 (ONNX) | 94.6% | ~128 ms | ~221 s |

On LoCoMo the model adds **~128 ms/query and ~24× ingest for no accuracy gain**
under BM25 — it only helps with weaker fusion. The zero-model hash embedder is
the fast default.

### The reranker: big accuracy, big cost — then tamed

A cross-encoder re-scores the top candidates by the full `(query, passage)`
pair. It lifts LoCoMo R@10 to **~98%** (+3 pts) but naively costs one forward
per candidate:

| Reranker config | Latency/query | R@10 |
|---|---|---|
| sequential (pool ~60) | ~16,600 ms | ~98% |
| rayon-parallel, 24 cores | ~1,100 ms | 99.0% |
| + `top_n=20` cap | **694 ms** | **98.7%** |
| + `top_n=10` cap | 389 ms | 97.4% |

Parallelizing the independent passes and capping the pool at `top_n` takes it
from unusable to **~24–43× faster at full accuracy**. Latency scales as
`⌈top_n / cores⌉` — see [Scaling to few cores](#scaling-to-few-cores).

### Candidate generation at scale (synthetic, hash embedder)

Full-scan is O(n) per query; an ANN index (HNSW prototype) stays flat:

| Corpus N | full-scan | HNSW | speedup | HNSW Recall@5 |
|---|---|---|---|---|
| 2,000 | 31 q/s | 403 q/s | 12.8× | 100.0% |
| 5,000 | 12 q/s | 391 q/s | 31.7× | 99.7% |
| 20,000 | ~3 q/s | 321 q/s | ~100× | 92.4% |
| 50,000 | ~1 q/s | 271 q/s | ~225× | 60.3% |

The speedup is real and grows without bound. The in-memory HNSW is a *proof the
algorithm helps*, but it costs O(corpus) RAM and its recall falls off at a fixed
over-fetch — so the durable design is **on-disk IVF-PQ** (Product Quantization
compresses each vector ~32×, codes stream from disk, only a small codebook stays
resident). The PQ primitive is implemented and unit-tested.

### Remote vector backends are untrusted accelerators, not a store swap

Undercroft can push **sealed** content + embeddings to Qdrant / Weaviate /
pgvector / Milvus / Chroma, but they only return candidate **ids** — every
candidate is re-verified (HMAC) and re-scored locally. Measured on LoCoMo, the
remote backends sat at **~0.5% CPU** while the client did all the work, and were
**slower** than the local full-scan for corpora this size (network + a bounded
local decrypt per candidate outweigh ANN when the palace is small). They earn
their keep only on very large corpora — and even then the scoring stays local.
Accuracy and integrity never depend on the untrusted index.

### Inference runtime: tract vs ONNX Runtime

Per-forward latency, same ONNX models, seq 256, on a CPU with `avx512_vnni`
(no GPU):

| Model | tract (pure-Rust) | ORT fp32 1-thr | ORT fp32 all | ORT int8 1-thr | ORT int8 all |
|---|---|---|---|---|---|
| MiniLM embed | ~128 ms | 53.7 | 28.1 | 24.9 | **15.0** |
| cross-encoder | ~140–277 ms | 56.2 | 26.8 | 24.4 | **13.3** |

ONNX Runtime is **~2.5× faster than tract** at the same precision, and **int8
(VNNI) ~2× more** — validated in Rust via the `ort` crate. Accuracy is
**runtime-invariant** (identical weights). With ORT int8 + parallel passes, an
end-to-end reranked query lands around **~40 ms** on a many-core host; on a GPU,
ORT-CUDA puts each forward at ~1–5 ms.

## Scaling to few cores

The reranker's parallel strategy is `⌈top_n / cores⌉` waves of one forward each.
On 24 cores `top_n=20` is one wave; on **4 cores** it is 5 waves (~270 ms). More
cores buy headroom, not a lower floor; the floor is **one forward**. So on
constrained devices the answer isn't more parallelism — it's **doing fewer
query-time forwards**:

- **ColBERT late interaction** encodes passage tokens once **at ingest** and, per
  query, does **one** forward + a cheap MaxSim (no transformer per candidate).
  Query cost is **~one forward, independent of `top_n` and of core count** — the
  same ~40–130 ms on 4 cores or 24, at ~cross-encoder accuracy.
- **A stronger bi-encoder with no reranker** is also one forward, core- and
  `top_n`-independent, at some accuracy cost.

So the cross-encoder + rayon path is a *many-core* optimization; ColBERT is the
*portable, core-independent* default.

## Configurable — choose per deployment

Retrieval, scoring, and runtime are **independent, user-selectable axes**.
Defaults are local-first and pure-Rust; every faster option is opt-in.

**Retrieval**

| Option | RAM | Best for |
|---|---|---|
| Full-scan + BM25 (default) | transient | small palaces |
| In-memory HNSW (`hnsw` feature) | O(corpus) | moderate corpora, many-core |
| On-disk IVF-PQ | ~O(codebook) | large corpora, edge/IoT |

**Scoring**

| Option | Latency (4-core) | Accuracy | Best for |
|---|---|---|---|
| No reranker (bi-encoder + BM25) | ~one embed | good | fastest / edge |
| Cross-encoder + rayon (`top_n`) | O(⌈top_n/cores⌉) | best | many-core servers |
| ColBERT late interaction | ~one forward (flat) | ~best | portable default, edge |

**Inference runtime**

| Option | Speed | Portability |
|---|---|---|
| tract (default) | baseline | pure-Rust, zero C dependency |
| `ort` (ONNX Runtime) | ~2.5–10× | links C++ ORT; opt-in |
| `ort` + GPU | ~50× | needs a GPU |

A 4-core edge box picks **IVF-PQ + ColBERT + int8**; a many-core server can add
the **cross-encoder + rayon** fast path; a GPU box turns on **ort-CUDA**. Same
engine, config-selected — never a rewrite.

## Invariants preserved throughout

Every option obeys the vault rules: sealed vaults never persist a
plaintext-derived index to disk (in-memory ANN is RAM-only; on-disk indexes for
sealed vaults are encrypted at rest, mirroring drawer sealing). Remote backends
are untrusted — content is sealed before upload and every result re-verified
locally. Faster never means less safe.
