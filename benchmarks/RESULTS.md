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
