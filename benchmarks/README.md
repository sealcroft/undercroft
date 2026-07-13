# Benchmarks

The harness is a Rust binary: `undercroft-bench` (crates/undercroft-bench).

## Synthetic regression benchmark (no dataset needed)

```bash
docker compose run --rm bench                    # 200 facts, asserts R@5 >= 95%
cargo run -p undercroft-bench -- synth --n 500    # native
```

Deterministic corpus, paraphrase queries, reports Recall@1/@5 + ingest and
query throughput. CI runs it to catch retrieval regressions.

## LongMemEval

Same protocol as upstream's `longmemeval_bench.py`: per question, ingest the
haystack sessions into a fresh palace (one room per session), retrieve with
the question, score session-level Recall@k and NDCG@k.

```bash
# dataset: https://github.com/xiaowu0162/LongMemEval (longmemeval_s)
cargo run --release -p undercroft-bench -- longmemeval longmemeval_s.json --k 5
cargo run --release -p undercroft-bench -- longmemeval longmemeval_s.json --limit 50   # quick pass
```

## model-eval (local LLM extraction quality)

Scores the runtime configured via `UNDERCROFT_LLM_URL` on the tasks
`undercroft refine` relies on, against labeled multilingual datasets
(`model_eval/datasets`, 10 languages):

```bash
export UNDERCROFT_LLM_URL=http://localhost:11434   # e.g. Ollama
cargo run -p undercroft-bench -- model-eval calibration            # accuracy
cargo run -p undercroft-bench -- model-eval entities --lang de     # P/R/F1
cargo run -p undercroft-bench -- model-eval memories               # greedy token-F1 alignment
```

The memories task uses SQuAD-style token F1 with greedy one-to-one
alignment (a prediction matches a gold memory at F1 >= 0.5; per-character
tokens for CJK), reporting match-level P/R/F1, mean token-F1 of matches,
and type accuracy.

## Honesty notes

- Upstream's published numbers (96.6% R@5 raw) were produced with a
  sentence-transformer embedding model. The default hash embedder here is
  much weaker on semantic paraphrase; for comparable conditions build with
  `--features onnx` and set `UNDERCROFT_EMBEDDER=onnx` with a MiniLM-class
  model.
- Sealed vaults decrypt-scan during search; benchmark both levels
  (`--level sealed|hmac-only`) if you care about the crypto overhead.
- No result files are committed until they can be reproduced from this
  repo's code; when they are, they land under `benchmarks/results_*` with
  the exact command line.
