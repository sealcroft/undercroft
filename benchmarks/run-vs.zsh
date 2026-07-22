#!/usr/bin/env zsh
# Head-to-head benchmark runner (zsh) — reproduces the rows published in
# docs/BENCHMARKS_VS.md. Same requirements and process as run-vs.sh:
#
#   1. cp benchmarks/vs.env.example benchmarks/vs.env   # then edit it
#   2. ./benchmarks/run-vs.zsh
#   3. Summary prints; full log lands in benchmarks/logs/local/ (gitignored)
#
# Requirements: Docker + compose plugin; the LoCoMo dataset
# (github.com/snap-research/locomo); for competitor rows, that system's
# local stack (deploy/bench-vs/README.md) + a local LLM backend.

set -eu
setopt pipefail

repo="${0:A:h:h}"
env_file="$repo/benchmarks/vs.env"

[[ -f "$env_file" ]] || { print "error: $env_file not found — cp benchmarks/vs.env.example benchmarks/vs.env and edit it"; exit 1 }
set -a; source "$env_file"; set +a

command -v docker >/dev/null || { print "error: docker not found"; exit 1 }
docker compose version >/dev/null 2>&1 || { print "error: docker compose plugin not found"; exit 1 }
[[ -n "${LOCOMO_JSON:-}" && -f "$LOCOMO_JSON" ]] || { print "error: LOCOMO_JSON does not point at a file (get it from github.com/snap-research/locomo)"; exit 1 }

system="${SYSTEM:-undercroft}"
k="${K:-10}"
typeset -a args run_env features mounts
args=(vs "/data/${LOCOMO_JSON:t}" --system "$system" -k "$k" --skip "${SKIP:-0}" --qa-limit "${QA_LIMIT:-0}")
[[ -n "${LIMIT:-}" ]] && args+=(--limit "$LIMIT")

if [[ "$system" == "undercroft" && -n "${ONNX_MODEL:-}" ]]; then
  [[ -f "$ONNX_MODEL" && -f "${ONNX_TOKENIZER:-}" ]] || { print "error: ONNX_MODEL/ONNX_TOKENIZER set but files missing"; exit 1 }
  features=(--features onnx)
  run_env+=(-e UNDERCROFT_EMBEDDER=onnx -e "UNDERCROFT_ONNX_MODEL=/models/${ONNX_MODEL:t}" -e "UNDERCROFT_ONNX_TOKENIZER=/models/${ONNX_TOKENIZER:t}")
fi
if [[ "$system" != "undercroft" ]]; then
  run_env+=(-e "UNDERCROFT_VS_URL=${VS_URL:-http://host.docker.internal:8765}")
  print "note: '$system' must already be up and configured — see deploy/bench-vs/README.md"
fi

mkdir -p "$repo/benchmarks/logs/local"
log="$repo/benchmarks/logs/local/${system}-$(date +%Y%m%d-%H%M%S).log"

mounts=(-v "${LOCOMO_JSON:h}:/data:ro")
(( ${#features} )) && mounts+=(-v "${ONNX_MODEL:h}:/models:ro")

print "== building the bench image (first run takes a few minutes) =="
( cd "$repo" && MSYS_NO_PATHCONV=1 docker compose build test )
print "== running: system=$system k=$k skip=${SKIP:-0} limit=${LIMIT:-all} qa_limit=${QA_LIMIT:-0} =="
( cd "$repo" && MSYS_NO_PATHCONV=1 docker compose run --rm $mounts $run_env test \
    cargo run --release $features -p undercroft-bench -- $args ) 2>&1 | tee "$log"

print ""
print "== done — full log: $log =="
grep -E "^VS_(RAW|TIMING)|^VS — " "$log" || true
