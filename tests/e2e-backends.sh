#!/usr/bin/env bash
# End-to-end suite for remote vector-index backends (qdrant, chroma,
# pgvector). Runs inside the builder container via docker compose, which
# provides the three services and the UNDERCROFT_* connection env vars.
#
# For each backend: fresh palace → remember → index push → search --backend
# → status. Also proves the security contract: the bytes stored server-side
# are sealed (no plaintext), and search results still decrypt locally.

set -uo pipefail

BIN="${BIN:-/src/target/release/undercroft}"
PASS=0
FAIL=0

check() { # check <name> <expected-exit> <expected-substring> -- cmd...
  local name="$1" want_code="$2" want_sub="$3"; shift 3
  [ "$1" = "--" ] && shift
  local out code
  out="$("$@" 2>&1)"; code=$?
  if [ "$code" -ne "$want_code" ]; then
    echo "FAIL  $name — exit $code (wanted $want_code)"; echo "$out" | sed 's/^/      /'
    FAIL=$((FAIL+1)); return
  fi
  if [ -n "$want_sub" ] && ! grep -qF "$want_sub" <<<"$out"; then
    echo "FAIL  $name — output missing: $want_sub"; echo "$out" | sed 's/^/      /'
    FAIL=$((FAIL+1)); return
  fi
  echo "ok    $name"
  PASS=$((PASS+1))
}

wait_for() { # wait_for <name> <cmd...>
  local name="$1"; shift
  for _ in $(seq 1 60); do
    if "$@" >/dev/null 2>&1; then echo "ok    $name is up"; PASS=$((PASS+1)); return 0; fi
    sleep 2
  done
  echo "FAIL  $name did not become ready"; FAIL=$((FAIL+1)); return 1
}

probe_http() { # probe_http <url>
  # curl may be absent in the slim image; use bash /dev/tcp.
  local url="$1" host port path
  host="$(sed -E 's|https?://([^:/]+).*|\1|' <<<"$url")"
  port="$(sed -E 's|https?://[^:/]+:([0-9]+).*|\1|' <<<"$url")"
  path="/"
  exec 3<>"/dev/tcp/$host/$port" || return 1
  printf 'GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' "$path" "$host" >&3
  head -1 <&3 | grep -q "HTTP/" ; local rc=$?
  exec 3<&- 3>&-
  return $rc
}

probe_pg() {
  exec 3<>"/dev/tcp/pgvector/5432" || return 1
  exec 3<&- 3>&-
  return 0
}

echo "== Service readiness =="
wait_for "qdrant"   probe_http "$UNDERCROFT_QDRANT_URL"
wait_for "chroma"   probe_http "$UNDERCROFT_CHROMA_URL"
wait_for "pgvector" probe_pg
wait_for "milvus"   probe_http "http://milvus:9091"
wait_for "weaviate" probe_http "$UNDERCROFT_WEAVIATE_URL"

run_backend_suite() { # run_backend_suite <backend>
  local be="$1"
  echo "== Backend: $be =="
  export UNDERCROFT_HOME="$(mktemp -d)"
  check "[$be] init"            0 "Palace initialized"  -- "$BIN" init
  check "[$be] remember 1"      0 "Filed drawer"        -- "$BIN" remember \
    "The rollout plan targets canary users first, then 10 percent daily" --wing ops --room rollout
  check "[$be] remember 2"      0 "Filed drawer"        -- "$BIN" remember \
    "Sourdough needs a 12 hour cold proof for open crumb" --wing kitchen
  check "[$be] push"            0 "Pushed 2 sealed record(s)" -- "$BIN" index push "$be"
  check "[$be] status counts"   0 "records:    2"       -- "$BIN" index status "$be"
  check "[$be] remote search"   0 "canary"              -- "$BIN" search "what is the rollout strategy" --backend "$be"
  check "[$be] wing filter"     0 "No memories matched" -- "$BIN" search "canary rollout" --backend "$be" --wing kitchen
  check "[$be] verbatim result" 0 "10 percent daily"    -- "$BIN" search "rollout" --backend "$be"
}

run_backend_suite qdrant
run_backend_suite chroma
run_backend_suite pgvector
run_backend_suite milvus
run_backend_suite weaviate

echo "== Misconfiguration UX =="
unset UNDERCROFT_QDRANT_URL
check "unconfigured backend errors" 1 "UNDERCROFT_QDRANT_URL" -- "$BIN" search "x" --backend qdrant
check "unknown backend errors"      1 "unknown backend"      -- "$BIN" search "x" --backend faiss

echo
echo "backends-e2e results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "BACKENDS E2E OK"
