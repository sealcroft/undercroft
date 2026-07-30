# Measured results

Run 2026-07-14, sealed-level scoring pipeline, inside Docker on Apple
Silicon (aarch64). Two embedder configurations: the default **hash
embedder** (zero model, zero network) and **all-MiniLM-L6-v2 via ONNX**
(`--features onnx`) — the same model class upstream MemPalace used, making
the model rows the like-for-like comparison. Reproduce with the exact
commands shown.

Rank-time fusion defaults to **BM25** (`UNDERCROFT_FUSION=bm25`): cosine
blended with a real Okapi BM25 lexical score over the decrypted candidate
set. The hash rows below reflect that default. The MiniLM rows were
measured under the older `legacy` fusion (a flat term-overlap lexical
signal) and are re-measured under BM25 only where noted — the fusion
change is embedder-independent, so it holds or helps. See
[Retrieval fusion](#retrieval-fusion) for the ablation.

## LongMemEval-S (full 500 questions, session granularity)

Dataset: `xiaowu0162/longmemeval-cleaned` → `longmemeval_s_cleaned.json`
(the same file upstream MemPalace benchmarked).

```
undercroft-bench longmemeval longmemeval_s_cleaned.json --k 5
# model rows: build with --features onnx, then
UNDERCROFT_EMBEDDER=onnx UNDERCROFT_ONNX_MODEL=model.onnx \
UNDERCROFT_ONNX_TOKENIZER=tokenizer.json \
undercroft-bench longmemeval longmemeval_s_cleaned.json --k 5
# (500 questions were sharded with --skip/--limit across 8 containers)
```

| Metric | Undercroft hash (no model) | **Undercroft + MiniLM** | MemPalace raw (model) | MemPalace hybrid v4 |
|---|---|---|---|---|
| Recall@5 (any) | 95.0% | **99.4%** (497/500) | 96.6% | 98.4% |
| NDCG@5 | 0.888 | 0.948 | — | — |
| Wall clock | 305 s / 500 q | ≈ 92 s/question | — | — |

Both configurations use the default **BM25 fusion**. The MiniLM rows were
re-measured under BM25 (8-way sharded, full 500).

Matched-model reading: with the same embedding-model class upstream used
and BM25 fusion, Undercroft's raw pipeline reaches **99.4%** — **above
upstream's own tuned hybrid (98.4%)**, not just their raw number (96.6%).
The zero-model hash embedder reaches 95.0% — within 4.4 points of the
model and above upstream raw, closing most of the semantics gap with no
download.

Per-type (R@5 any):

| Type | hash + BM25 | MiniLM + BM25 |
|---|---|---|
| knowledge-update | 100.0 | 100.0 |
| multi-session | 96.2 | 99.2 |
| single-session-assistant | 98.2 | 100.0 |
| single-session-user | 98.6 | 100.0 |
| temporal-reasoning | 94.0 | 99.2 |
| single-session-preference | 66.7 | **96.7** |

The paraphrase-heavy single-session-preference category — the historical
weak spot (36.7 under legacy fusion) — is where BM25 and the model both
help most: 96.7 with MiniLM.

## LoCoMo (1,982 evaluable QA, session granularity)

Dataset: `snap-research/locomo` → `locomo10.json`.

```
undercroft-bench locomo locomo10.json --k 10
```

| Metric | Undercroft hash | **Undercroft + MiniLM** | MemPalace raw | MemPalace hybrid v5 |
|---|---|---|---|---|
| Session R@10 | 94.6% | **94.6%** | 60.3% | 88.9% |

Both under BM25 fusion. Here the model and the zero-model hash embedder
converge at 94.6% — both above upstream's best (88.9%).

Per-category (hash + BM25): 1: 94.7 · 2: 90.3 · 3: 81.5 · 4: 96.3 · 5: 97.1
(the hardest multi-hop category 3 rises from 75.0 under legacy to 81.5).
With BM25, the **zero-model hash embedder (94.6%) now edges past the
earlier MiniLM number (93.8%)** on this suite.

### Cross-encoder reranker (second stage)

Run 2026-07-15, MiniLM embedder + BM25 fusion + an optional cross-encoder
second stage (`UNDERCROFT_RERANKER=onnx`, `ms-marco-MiniLM-L-6-v2`,
`top_n=50`) that re-scores the fusion-ranked top-N by the full
`(query, passage)` pair before the final `limit` cut. Summed exactly across
5 conversation-shards.

```
# build with --features onnx, then
UNDERCROFT_EMBEDDER=onnx UNDERCROFT_ONNX_MODEL=model.onnx \
UNDERCROFT_ONNX_TOKENIZER=tokenizer.json UNDERCROFT_FUSION=bm25 \
UNDERCROFT_RERANKER=onnx UNDERCROFT_RERANK_MODEL=reranker/model.onnx \
UNDERCROFT_RERANK_TOKENIZER=reranker/tokenizer.json \
undercroft-bench locomo locomo10.json --k 10 --skip N --limit M
# (5 conversation-shards; LOCOMO_RAW numerator lines summed for the exact R@k)
```

| Metric | MiniLM + BM25 | **+ cross-encoder reranker** | Δ |
|---|---|---|---|
| Session R@10 | 94.6% | **97.68%** (1936/1982) | **+3.08 pts** |

The reranker lifts LoCoMo R@10 to **97.68%** — above the pre-reranker
pipeline and far above upstream's best (88.9%). It is **off by default**
(the fusion-ranked result is already strong); enabling it costs a second
tract pass per top-N candidate, so `UNDERCROFT_RERANK_TOP_N` bounds latency.

**No LongMemEval reranker row (deliberate):** the MiniLM baseline there is
already **99.4% (497/500)** — saturated. A second-stage reranker can only
move it ≤0.6 pts, indistinguishable from noise, and the multi-hour run
isn't worth it. The reranker's value shows on LoCoMo, which has headroom.

### ColBERT late interaction (second stage, core-count-independent)

Run 2026-07-16, hash embedder + BM25 fusion + the ColBERT late-interaction
stage (`UNDERCROFT_RERANKER=colbert`, `colbertv2.0` exported to fixed-shape
ONNX, tract runtime): passage token matrices are encoded **once at ingest**
(int8 on disk; AEAD-sealed in sealed vaults) and a search runs **one** query
forward + MaxSim over the fusion top-N — no transformer per candidate.

```
# build with --features onnx, then
UNDERCROFT_RERANKER=colbert UNDERCROFT_COLBERT_MODEL=colbert/model.d256.onnx \
UNDERCROFT_COLBERT_QUERY_MODEL=colbert/model.q32.onnx \
UNDERCROFT_COLBERT_TOKENIZER=colbert/tokenizer.json \
undercroft-bench locomo locomo10.json --k 10
```

| Second stage (hash + bm25 base) | Session R@10 | search ms/q | scales w/ cores |
|---|---|---|---|
| none | 94.6% | ~6 | — |
| **ColBERT late interaction** | **96.77%** (1918/1982) | **92.7** | **no — flat on 4 or 24** |
| cross-encoder (ort int8, top_n=20) | 97.68% | 101–327 *(24-core)* | yes (~5× worse on 4) |

+2.2 pts over fusion at a flat ~93 ms/query on **any** core count — the
portable second stage for few-core boxes, where the cross-encoder's last
point costs many-core parallelism it doesn't have. Ingest carries the moved
cost (~0.37 s/drawer on tract). Off by default; the cross-encoder wins when
both are configured.

**Token-store PQ (v2 packing, run 2026-07-17):** the stored matrices
PQ-compress to 16 B/token — **8.2× below int8** (a ~150-token drawer:
19.8 KB → 2.4 KB) — with MaxSim scored via per-query-row dot-product LUTs
and punctuation rows pruned at encode:

| Token store | LoCoMo R@10 | search ms/q | bytes/drawer (~150 tok) |
|---|---|---|---|
| int8 (v1) | 96.77% | 92.7 | ~19.8 KB |
| **PQ codes (v2) + punct pruning** | **96.57%** | 96.7¹ | **~2.4 KB** |

¹ Includes each store's one-time codebook train + repack amortized into the
bench's query phase; per-query cost is dominated by the ~80 ms tract query
forward either way — the LUT win becomes visible when the `ort` query
forward (~40 ms) lands. **Impact:** 8× smaller late-interaction store at
−0.2 pts. **Recommendation:** on by default above `UNDERCROFT_TOK_PQ_MIN`
(256 matrices; `off` keeps int8).

## Retrieval fusion

Ablation on the default hash embedder, all three fusion modes, full suites
(`UNDERCROFT_FUSION=legacy|bm25|rrf`):

| Fusion | LongMemEval-S R@5 | LongMemEval NDCG@5 | LoCoMo R@10 | preference (LME) |
|---|---|---|---|---|
| legacy (old default) | 90.4% | 0.832 | 92.7% | 36.7% |
| **bm25 (default)** | **95.0%** | **0.888** | **94.6%** | **66.7%** |
| rrf | 93.8% | 0.867 | 92.5% | 66.7% |

- **legacy** — linear blend of cosine, a flat term-overlap lexical
  fraction, and recency. Every matched query term counts equally.
- **bm25** — the term-overlap fraction becomes a real Okapi BM25 score
  (IDF weights rare terms, `k1=1.2`/`b=0.75` length normalization, same
  one-typo tolerance), computed over the decrypted candidate set and
  squashed to [0,1] for the blend. Wins on every category of both suites.
- **rrf** — reciprocal-rank fusion of the cosine and BM25 rankings
  (`k=60`), recency a light third ranker. Scale-free but discards score
  magnitude; benchmarks below `bm25`, so it is an option, not the default.

The `legacy` numbers reproduce the earlier published figures exactly,
confirming the refactor left that path unchanged. BM25 is embedder- and
security-level-independent (it re-ranks already-HMAC-verified candidates),
and the lift carries to the model: MiniLM went **97.4 → 99.4** on
LongMemEval and **93.8 → 94.6** on LoCoMo under BM25.

## Honest reading

- **Matched-model conditions (the fair comparison):** with the same model
  class and BM25 fusion, LongMemEval **99.4% clears upstream's tuned hybrid
  (98.4%)** — not just their raw (96.6%) — and LoCoMo **94.6% is well above
  upstream's best (88.9%)**. Undercroft's pipeline is at or above upstream on
  both benchmarks.
- **Zero-model rows now close most of the gap:** with BM25 the hash
  embedder reaches 95.0 on LongMemEval (was 90.4) and 94.6 on LoCoMo (was
  92.7) — no download, ~95x faster per question, and on LoCoMo it now
  edges past the earlier MiniLM figure.
- Differences to keep in mind: upstream evaluated 1,986 LoCoMo questions
  to our 1,982 evaluable (no-evidence QA skipped); their numbers come from
  their own harness implementation; our MiniLM inference runs tract
  (pure Rust) with 256-token truncation and mean pooling.

## Retrieval performance: every lever, measured (run 2026-07-15/16, 24-core `avx512_vnni` host, inside Docker)

The retrieval-quality track measured **every configurable lever** end to end.
Full engineering rationale: [docs/RETRIEVAL_SCALING.md](../docs/RETRIEVAL_SCALING.md);
rendered docs: the "Retrieval, scoring & scaling" page on the site.

### Lever 1 — rank fusion (free accuracy)

LoCoMo R@10, hash embedder: **bm25 94.6%** > legacy 92.7% > rrf 92.5%, all
~6 ms/query. **Impact:** +1.9 pts for free. **Recommendation:** always
`UNDERCROFT_FUSION=bm25` (the default).

### Lever 2 — embedder (latency, not accuracy, under BM25)

LoCoMo R@10: hash 94.6% @ ~6 ms/query vs MiniLM 94.6% @ ~128 ms/query (tract);
ingest 9 s vs 221 s. **Impact:** under BM25 the model buys nothing on LoCoMo and
costs ~20× query latency, ~24× ingest. **Recommendation:** hash by default; a
model embedder earns its keep only with weaker fusion or model-favoring corpora
— measure before paying for it.

### Lever 3 — cross-encoder reranker (+3 pts, tamed from 16.6 s to ~0.1 s)

The reranker lifts LoCoMo R@10 94.6 → ~98%. Its cost was retired step by step
(302-QA subset, R@10 held ≈98% throughout):

| Step | top_n=20 | top_n=10 | top_n=5 |
|---|---|---|---|
| sequential tract (baseline, pool ~60) | ~16,600 ms | — | — |
| + rayon across cores | 694 ms | 389 ms | 321 ms |
| + ORT runtime (batched) | 614 ms | 386 ms | 251 ms |
| + ORT session pool | 427 ms | 214 ms | 142 ms |
| + **int8 models** | **327 ms** | **171 ms** | **101 ms** |

`top_n` is a true pool cap (accuracy plateaus at top_n≈20); ORT ≈2.5× tract per
forward (identical fp32 accuracy — runtime never changes scores); int8 (a 4×
smaller user-supplied model file, no code change) attacks the memory-bandwidth
bound of concurrent forwards; ingest embed drops 24 s → ~5 s with ORT.
**Recommendation:** reranker on = `UNDERCROFT_RERANKER=onnx`, `top_n=20`, the
`ort` backend where the C++ dep is acceptable, int8 models, pool = cores
(`UNDERCROFT_ORT_POOL`; `pool=1` on few-core boxes = batched mode). Pure-Rust
tract remains the default fallback. On few-core boxes prefer
**`UNDERCROFT_RERANKER=colbert`** (see the ColBERT section above): 96.77% at a
flat 92.7 ms/query, independent of core count.

### Lever 4 — candidate index at scale (synthetic corpus, hmac-only)

| Mode | N=20k q/s | N=20k R@5 | N=50k q/s | N=50k R@5 | RAM |
|---|---|---|---|---|---|
| true full-scan | ~6.6 | 100% | ~2.6 | 100% | transient O(n) |
| FTS prefilter (default) | 76.7 | 100% | 33.2 | 100% | on-disk |
| **PQ prefilter** | 59.2 | 98.6% | 18.6 | **98.9%** | **codebook only (~400 KB)** |
| in-memory HNSW | 454.1 | 93.1% | 377.7 | **71.7%** | O(corpus) |

**Impact:** PQ (on-disk codes, 48 B/vector) gives bounded RAM with recall that
is *flat in corpus size*; HNSW is fastest but holds everything in RAM and its
recall collapses without per-size `ef` tuning; the FTS prefilter stays excellent
on lexical-friendly corpora. **Recommendation:** hmac-only large corpora →
`set_pq(true)` / `UNDERCROFT_RETRIEVAL=pq`; RAM-rich + tuned → HNSW; sealed
vaults get the sealed IVF-PQ variant (see the sealed section below).

#### IVF inverted lists + the PQ scan-path fixes (second host; within-run comparisons)

Adding IVF (coarse quantizer, `nlist ≈ √N`, probe the nearest `nlist/4` lists)
exposed and fixed three structural costs in the PQ scan path — measured on a
second 24-core host, so these tables compare only within their own runs:

| Fix (each re-measured) | flat @20k | probed @20k, ~23–25% fraction |
|---|---|---|
| baseline (seq-keyed codes + per-row join) | 26.5 q/s | 19.4 q/s (**slower than flat**) |
| + clustered `(list, seq)` layout | 23.9 | 28.6 |
| + event-driven coherence (no per-search join-count) | — | ~+14% on probed cells |
| + scan without the per-row `drawers` join | **34.4** | **38.3** |

Recall tracked the probed **fraction**: 3% → 68.7%, 11% → 86.9%, 23% → 99.6%
= flat parity — hence the fraction-based `nprobe` default. It was also
identical across every version at the time, because the training sample was a
deterministic function of position; **that is no longer true** — see the
codebook-draw section below.

Final (all fixes, one uncontended run):

| N | flat PQ | IVF-default | R@5 (both) |
|---|---|---|---|
| 20,000 | 34.4 q/s | **38.3 q/s** (+11%) | 99.6% |
| 50,000 | 14.8 q/s | **15.9 q/s** (+7%) | 99.1% |

#### The codebook training draw: the even stride was a landmine

The samples above were drawn by an even stride over insertion order
(`step_by(⌈n/4096⌉)`). That is a **systematic sample**, and a systematic
sample of a *periodic* population collapses when the interval shares a factor
with the period. `synth` is periodic by construction —
`FACT_TEMPLATES[i % 4]`, `["budget","deadline","vendor","owner"][i % 4]` — and
at `--n 16384` the interval is exactly `⌈16384/4096⌉ = 4`, so every sampled
fact carries one template and one key prefix.

Within-run, one host, `UNDERCROFT_RETRIEVAL=pq`, hmac-only, 2,000 queries:

| N | interval | draw | R@1 | R@5 |
|---|---|---|---|---|
| 20,000 | 5 (coprime with 4) | even stride | 99.2% | 99.8% |
| 20,000 | — | stratified keyed | 97.9% | 99.4% |
| **16,384** | **4 (aligned)** | **even stride** | **82.5%** | **83.0%** |
| 16,384 | — | stratified keyed | **98.9%** | **99.7%** |

83.0% fails this harness's own `>= 95%` regression gate. The stride's edge at
20,000 is alignment luck between two measured sizes, and its failure sits
between them: 20,000 and 50,000 (interval 13) are both coprime with the
period, which is why the numbers above never showed it.

The draw is now **stratified and keyed**: one row per equal block of insertion
order, chosen by a per-vault HKDF-keyed rank. Blocks keep the coverage,
the keyed choice inside each block breaks the residue alignment, and a bulk
writer can no longer predict which of their rows trains the codebook. Two
consequences for reading this file: the PQ figures above move by a few tenths
(99.8% → 99.4% R@5 at 20,000), and recall is now reproducible **per vault**
rather than per corpus — three keyed runs at n=20,000 spanned R@1 97.4–97.9%,
R@5 99.4–99.6%.

**Impact:** the fixes lifted **flat PQ itself ~45%** at both sizes — every PQ
user gets that. IVF's marginal gain is +7–11% here because the pure ADC
arithmetic is only ~4–6 ms even at 50k; it is the only query cost that scales
with N, so its share grows with the corpus. **Recommendation:** leave IVF on
(default above `UNDERCROFT_IVF_MIN=8192`); recall parity and self-healing
partitions are test-asserted.

#### Sealed vaults get the index too (encrypted at rest, run 2026-07-16)

Sealed vaults previously had one retrieval mode: decrypt-scan every
embedding per query. The PQ/IVF prefilter now applies at both security
levels — sealed rows, codebook, and centroids are AEAD-sealed (`/pq` AAD
domain; list ids never in clear) and search ADC-scans a RAM cache decrypted
once per open (~52 B/drawer):

| Sealed vault | N=20k q/s | N=50k q/s | R@5 (20k/50k) |
|---|---|---|---|
| decrypt-scan (before) | 2.1 | 1.1 | 99.9% / 99.9% |
| **sealed IVF-PQ** | **33.4 (×16)** | **11.8 (×11)** | 99.6% / 99.1% |
| hmac-only IVF-PQ (within-run ref) | 37.1 | 8.1 | 99.6% / 99.1% |

**Impact:** encrypted-at-rest search at plaintext-index speed (parity with
the hmac path; the sealed RAM cache even skips hmac's per-query SQLite
streaming at 50k). Nothing plaintext-derived touches sealed disk —
test-asserted. **Recommendation:** sealed + large corpus →
`UNDERCROFT_RETRIEVAL=pq`, same as hmac-only.

### Lever 5 — remote vector backends (they don't offload work)

Qdrant/Weaviate sat at ~0.5% CPU while the client did all crypto + scoring
locally (by design: untrusted accelerators get sealed blobs, return only ids);
at LoCoMo scale they were slower than the local scan. **Recommendation:** only
for corpora too large to scan locally — never for latency, never for accuracy.

### Scenario recipes

| Deployment | Recipe | Expected |
|---|---|---|
| Personal palace (default) | hash + bm25, no reranker | ~6 ms/q, 94.6% |
| Accuracy-critical, many-core | + reranker top_n=20, ort+int8, pool=cores | ~330 ms/q, ~98% |
| Fast + accurate compromise | + reranker top_n=5–10, ort+int8 | ~100–170 ms/q, ~98% |
| 4-core / edge, large corpus | hmac-only + PQ/IVF prefilter (`UNDERCROFT_RETRIEVAL=pq`); **ColBERT** (`UNDERCROFT_RERANKER=colbert`) | bounded RAM; ~93 ms/q @ 96.8% |
| GPU box | ort CUDA EP (each forward ~1–5 ms) | reranked query well under 50 ms |
| Huge corpus, RAM-rich | HNSW (tune `ef`/over-fetch with N) or PQ+IVF (shipped) | 300+ q/s (HNSW) / bounded-RAM (PQ+IVF) |
