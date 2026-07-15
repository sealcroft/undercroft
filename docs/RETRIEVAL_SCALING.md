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

### Scoring → late interaction (ColBERT-style), not a query-time cross-encoder

A cross-encoder is slow because it encodes each `(query, passage)` pair **at
query time**. Late interaction encodes passages **per-token at ingest** (once,
stored on disk, quantized) and, at query time, does a cheap MaxSim aggregation:
**cross-encoder-competitive accuracy at bi-encoder latency (~ms)**. The
expensive work moves to ingest and to disk — exactly the right direction. And
ColBERT is BERT-family, so it runs in tract (unlike the DeBERTa rerankers tract
rejects).

### Near-term pragmatic win (today's model, no new architecture)

Make the existing cross-encoder usable before ColBERT lands: **int8-quantize +
batch (one forward over the pool) + drop `top_n` to ≤10**. Estimated
~16,600 ms → **~200–400 ms** (40–80×) while keeping most of the +3 pts. The
batched `score_batch` call site (the `#6` change) is the hook; the missing
piece is a batched `OnnxReranker::score_batch` (blocked today by a fixed
batch-dim-1 model load) and int8 quantization.

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

## Phased plan

1. **Reranker latency (cheapest, biggest win):** int8 + batch + `top_n` ≤ 10.
   Target < 400 ms/query at ~+3 pts. Benchmark against the 16,600 ms baseline.
2. **On-disk IVF-PQ retrieval** for hmac-only vaults (bounded RAM, mirrors the
   FTS precedent). Retire the in-memory HNSW prototype as the default.
3. **Late interaction (ColBERT)** scoring as the reranker replacement.
4. **Sealed-tier encrypted-at-rest** IVF-PQ + token store (the research track).

The in-memory HNSW behind the `hnsw` feature stays as an experimental fast path
for moderate sealed corpora and as the benchmark baseline — not the default.
