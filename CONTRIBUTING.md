# Contributing to Undercroft

Thanks for wanting to help. Undercroft is source-available (BUSL-1.1) and welcomes
contributions of all sizes.

## Getting started

```bash
# Fork on GitHub first, then:
git clone https://github.com/<your-username>/undercroft.git
cd undercroft
```

The project is a Rust workspace (`crates/`). Building and testing happen
**inside Docker** — you do not need a local Rust toolchain:

```bash
docker compose run --rm test   # cargo unit + integration tests
docker compose run --rm lint   # rustfmt --check + clippy -D warnings
docker compose run --rm e2e    # end-to-end UI/UX suite against the real binary
docker build -t undercroft .    # runtime image
```

If you prefer a local toolchain, `cargo test --workspace` works too, but CI
and reviews are based on the Docker flow. ONNX embedder/reranker and telemetry
are feature-gated (`--features onnx` / `--features telemetry`); the `onnx-build`
and `e2e-telemetry` compose services compile-check them.

## Ground rules

- **Verbatim always** — never summarize, paraphrase, or lossy-compress user
  data on the write path.
- **Local-first** — no phone-home, no external API required for core memory;
  the default embedder must stay offline and deterministic. Observability is
  **opt-in** behind `--features telemetry` (default builds carry zero telemetry
  deps); when on it emits **metadata/counts only**, never content or keys.
- **Security invariants** — sealed vaults must never persist plaintext (or
  plaintext-derived indexes) to disk; every write updates the audit chain;
  every read verifies the record HMAC. Tests assert these; keep them green.
- New functionality needs unit tests, and user-facing behavior needs coverage
  in `tests/e2e.sh`.

## PR flow

1. Branch from `main`.
2. Make the change + tests; run the Docker suites (`test`, `lint`, and `e2e`
   for user-facing behavior).
3. Open a PR against `main` with a clear description of behavior changes. CI
   (lint, audit, Trivy fs + image, the full Docker test battery) must be green.
