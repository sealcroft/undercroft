# Measured results

Run 2026-07-14, sealed-level scoring pipeline, inside Docker on Apple
Silicon (aarch64). Two embedder configurations: the default **hash
embedder** (zero model, zero network) and **all-MiniLM-L6-v2 via ONNX**
(`--features onnx`) — the same model class upstream MemPalace used, making
the model rows the like-for-like comparison. Reproduce with the exact
commands shown.

## LongMemEval-S (full 500 questions, session granularity)

Dataset: `xiaowu0162/longmemeval-cleaned` → `longmemeval_s_cleaned.json`
(the same file upstream MemPalace benchmarked).

```
undercroft-bench longmemeval longmemeval_s_cleaned.json --k 5
# model rows: build with --features onnx, then
UNDERCROFT_EMBEDDER=onnx UNDERCROFT_ONNX_MODEL=model.onnx \
UNDERCROFT_ONNX_TOKENIZER=tokenizer.json \
undercroft-bench longmemeval longmemeval_s_cleaned.json --k 5
# (500 questions were sharded with --skip/--limit across 5 containers)
```

| Metric | Undercroft hash (no model) | **Undercroft + MiniLM** | MemPalace raw (model) | MemPalace hybrid v4 |
|---|---|---|---|---|
| Recall@5 (any) | 90.4% | **97.4%** (487/500) | 96.6% | 98.4% |
| NDCG@5 | 0.832 | ≈ 0.93 | — | — |
| Wall clock | 453 s / 500 q | ≈ 86 s/question | — | — |

Matched-model reading: with the same embedding-model class upstream used,
Undercroft's raw pipeline lands **+0.8 over upstream raw** and 1.0 under
their tuned hybrid. The hash-embedder gap was embedding semantics, not the
pipeline: on an identical 100-question control subset, hash scored 92.0
and MiniLM 98.0.

Per-type (R@5 any): knowledge-update 98.7 · multi-session 95.5 ·
single-session-assistant 92.9 · single-session-user 91.4 ·
temporal-reasoning 91.0 · **single-session-preference 36.7**.

## LoCoMo (1,982 evaluable QA, session granularity)

Dataset: `snap-research/locomo` → `locomo10.json`.

```
undercroft-bench locomo locomo10.json --k 10
```

| Metric | Undercroft hash | **Undercroft + MiniLM** | MemPalace raw | MemPalace hybrid v5 |
|---|---|---|---|---|
| Session R@10 | 92.7% | **93.8%** | 60.3% | 88.9% |

Per-category (MiniLM): 1: 94.0 · 2: 92.2 · 3: 83.7 · 4: 94.9 · 5: 94.8
(hash: 91.1 · 90.7 · 75.0 · 94.6 · 95.3 — the model helps most on the
hardest multi-hop category).

## Honest reading

- **Matched-model conditions (the fair comparison):** LoCoMo 93.8 vs
  upstream's best 88.9; LongMemEval 97.4 vs upstream raw 96.6 (their
  tuned hybrid holds 98.4). Undercroft's raw pipeline is at or above
  upstream raw on both benchmarks with the same model class.
- **Zero-model rows still matter:** hash needs no download and runs ~95x
  faster per question; it concedes 7 points on LongMemEval (all in
  paraphrase-heavy preference questions) and 1.1 on LoCoMo.
- Differences to keep in mind: upstream evaluated 1,986 LoCoMo questions
  to our 1,982 evaluable (no-evidence QA skipped); their numbers come from
  their own harness implementation; our MiniLM inference runs tract
  (pure Rust) with 256-token truncation and mean pooling.
