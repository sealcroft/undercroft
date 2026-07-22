#!/usr/bin/env bash
# Head-to-head benchmark runner (bash) — reproduces the rows published in
# docs/BENCHMARKS_VS.md on your own machine.
#
# REQUIREMENTS
#   * Docker (Desktop or engine) with the compose plugin — everything runs
#     in containers; no Rust toolchain needed on the host.
#   * The LoCoMo dataset file (user-supplied): github.com/snap-research/locomo
#   * ~5 minutes for the undercroft rows. Competitor rows additionally need
#     that system's local stack up (deploy/bench-vs/README.md) plus a local
#     LLM backend (LM Studio or Ollama) — and hours of wall-clock, because
#     extraction-based systems call an LLM on every write.
#
# PROCESS
#   1. cp benchmarks/vs.env.example benchmarks/vs.env   # then edit it
#   2. ./benchmarks/run-vs.sh                           # from anywhere
#   3. Read the summary; the full log lands in benchmarks/logs/local/
#      (gitignored — publish only reviewed logs, see benchmarks/logs/README.md)
#
# The script is a thin, honest wrapper around:
#   docker compose run --rm test cargo run --release -p undercroft-bench -- vs …
# — the exact invocation the published rows used. Scoring, chunking, and
# corpus handling all live in the harness; nothing here can bias a number.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="$repo/benchmarks/vs.env"

[ -f "$env_file" ] || { echo "error: $env_file not found — cp benchmarks/vs.env.example benchmarks/vs.env and edit it"; exit 1; }
# shellcheck disable=SC1090
set -a; . "$env_file"; set +a

command -v docker >/dev/null || { echo "error: docker not found"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "error: docker compose plugin not found"; exit 1; }
[ -n "${LOCOMO_JSON:-}" ] && [ -f "$LOCOMO_JSON" ] || { echo "error: LOCOMO_JSON does not point at a file (get it from github.com/snap-research/locomo)"; exit 1; }

system="${SYSTEM:-undercroft}"
k="${K:-10}"
args=(vs "/data/$(basename "$LOCOMO_JSON")" --system "$system" -k "$k" --skip "${SKIP:-0}" --qa-limit "${QA_LIMIT:-0}")
[ -n "${LIMIT:-}" ] && args+=(--limit "$LIMIT")

run_env=()
features=()
if [ "$system" = "undercroft" ] && [ -n "${ONNX_MODEL:-}" ]; then
  [ -f "$ONNX_MODEL" ] && [ -f "${ONNX_TOKENIZER:-}" ] || { echo "error: ONNX_MODEL/ONNX_TOKENIZER set but files missing"; exit 1; }
  features=(--features onnx)
  run_env+=(-e UNDERCROFT_EMBEDDER=onnx -e "UNDERCROFT_ONNX_MODEL=/models/$(basename "$ONNX_MODEL")" -e "UNDERCROFT_ONNX_TOKENIZER=/models/$(basename "$ONNX_TOKENIZER")")
fi
if [ "$system" != "undercroft" ]; then
  run_env+=(-e "UNDERCROFT_VS_URL=${VS_URL:-http://host.docker.internal:8765}")
  echo "note: '$system' must already be up and configured — see deploy/bench-vs/README.md"
fi

mkdir -p "$repo/benchmarks/logs/local"
log="$repo/benchmarks/logs/local/${system}-$(date +%Y%m%d-%H%M%S).log"

mounts=(-v "$(dirname "$LOCOMO_JSON"):/data:ro")
[ ${#features[@]} -gt 0 ] && mounts+=(-v "$(dirname "$ONNX_MODEL"):/models:ro")

echo "== building the bench image (first run takes a few minutes) =="
( cd "$repo" && MSYS_NO_PATHCONV=1 docker compose build test )
echo "== running: system=$system k=$k skip=${SKIP:-0} limit=${LIMIT:-all} qa_limit=${QA_LIMIT:-0} =="
( cd "$repo" && MSYS_NO_PATHCONV=1 docker compose run --rm "${mounts[@]}" "${run_env[@]}" test \
    cargo run --release "${features[@]}" -p undercroft-bench -- "${args[@]}" ) 2>&1 | tee "$log"

echo ""
echo "== done — full log: $log =="
grep -E "^VS_(RAW|TIMING)|^VS — " "$log" || true
