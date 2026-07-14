# Measured results

Run 2026-07-14 on the default **hash embedder** (zero model, zero network),
sealed-level scoring pipeline, inside Docker on Apple Silicon (aarch64).
Reproduce with the exact commands shown.

## LongMemEval-S (full 500 questions, session granularity)

Dataset: `xiaowu0162/longmemeval-cleaned` → `longmemeval_s_cleaned.json`
(the same file upstream MemPalace benchmarked).

```
undercroft-bench longmemeval longmemeval_s_cleaned.json --k 5
```

| Metric | Undercroft (hash, no model) | MemPalace raw (embedding model) | MemPalace hybrid v4 (held-out) |
|---|---|---|---|
| Recall@5 (any) | **90.4%** | 96.6% | 98.4% |
| Recall@5 (all) | 72.8% | — | — |
| NDCG@5 | 0.832 | — | — |
| Wall clock | 452.8 s / 500 q | — | — |

Per-type (R@5 any): knowledge-update 98.7 · multi-session 95.5 ·
single-session-assistant 92.9 · single-session-user 91.4 ·
temporal-reasoning 91.0 · **single-session-preference 36.7**.

## LoCoMo (1,982 evaluable QA, session granularity)

Dataset: `snap-research/locomo` → `locomo10.json`.

```
undercroft-bench locomo locomo10.json --k 10
```

| Metric | Undercroft (hash, no model) | MemPalace raw | MemPalace hybrid v5 |
|---|---|---|---|
| Session R@10 | **92.7%** | 60.3% | 88.9% |

Per-category: 1: 91.1 · 2: 90.7 · 3: 75.0 · 4: 94.6 · 5: 95.3.

## Honest reading

- **LoCoMo:** Undercroft's hybrid scorer (semantic + lexical + typo-tolerant
  + recency) beats upstream's published raw *and* hybrid numbers without
  any embedding model.
- **LongMemEval:** we land 6.2 points under upstream's model-based raw
  score. The gap is concentrated in one question type —
  *single-session-preference* (36.7%) — where questions paraphrase heavily
  ("what do I prefer…") and share almost no words with the evidence;
  exactly what a trained embedder fixes. Running with `--features onnx`
  and a MiniLM-class model is the like-for-like comparison and the obvious
  next measurement.
- Differences to keep in mind: upstream evaluated 1,986 LoCoMo questions
  to our 1,982 evaluable (no-evidence QA skipped), and their numbers come
  from their own harness implementation.
