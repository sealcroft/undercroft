#!/usr/bin/env bash
# End-to-end checks for the v0.9.0 observability layer. Requires a binary
# built WITH `--features telemetry`; the `e2e-telemetry` compose service
# compiles it first, then runs this script.
#
#   docker compose run --rm e2e-telemetry
#
# Covers the opt-in gating (loopback + bearer + env flag) and that real
# traffic advances the Prometheus counters.
set -u

BIN="${BIN:-/src/target/release/undercroft}"
unset UNDERCROFT_PASSPHRASE 2>/dev/null || true
PASS=0
FAIL=0
pass() { echo "ok    $1"; PASS=$((PASS + 1)); }
fail() {
  echo "FAIL  $1"
  shift
  [ "$#" -gt 0 ] && echo "$*" | sed 's/^/      /'
  FAIL=$((FAIL + 1))
}

HOME_DIR="$(mktemp -d)"
export UNDERCROFT_HOME="$HOME_DIR"
TOKEN="e2e-telemetry-token"
"$BIN" init >/dev/null 2>&1

wait_up() { # <port>
  for _ in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$1/healthz" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

echo "== /metrics enabled (UNDERCROFT_METRICS=1, behind bearer) =="
UNDERCROFT_MCP_HTTP_TOKEN="$TOKEN" UNDERCROFT_METRICS=1 \
  "$BIN" serve-http --host 127.0.0.1 --port 8795 >/tmp/tserve.log 2>&1 &
S1=$!
wait_up 8795 || fail "server did not start" "$(cat /tmp/tserve.log)"

grep -q "/metrics" /tmp/tserve.log && pass "startup banner advertises /metrics" \
  || fail "banner missing /metrics" "$(cat /tmp/tserve.log)"

code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8795/metrics)
[ "$code" = "401" ] && pass "/metrics without bearer -> 401" || fail "/metrics no-bearer ($code)"

out=$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8795/metrics)
grep -q "# TYPE" <<<"$out" && pass "/metrics returns Prometheus text" || fail "/metrics not prometheus" "$out"

# Drive a search over the single-vault MCP surface, then re-scrape: the
# search + HTTP counters must now be present.
body='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"undercroft_search","arguments":{"query":"hello world"}}}'
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "$body" http://127.0.0.1:8795/mcp >/dev/null
out=$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8795/metrics)
grep -q "undercroft_http_requests_total" <<<"$out" && pass "http_requests_total recorded" \
  || fail "http_requests_total missing" "$out"
grep -q "undercroft_search_total" <<<"$out" && pass "search_total recorded after a search" \
  || fail "search_total missing" "$out"

kill "$S1" 2>/dev/null
wait "$S1" 2>/dev/null

echo "== /metrics disabled (flag unset -> 404) =="
UNDERCROFT_MCP_HTTP_TOKEN="$TOKEN" \
  "$BIN" serve-http --host 127.0.0.1 --port 8796 >/tmp/tserve2.log 2>&1 &
S2=$!
wait_up 8796 || fail "server did not start" "$(cat /tmp/tserve2.log)"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8796/metrics)
[ "$code" = "404" ] && pass "/metrics 404 when UNDERCROFT_METRICS unset" || fail "/metrics disabled ($code)"
kill "$S2" 2>/dev/null
wait "$S2" 2>/dev/null

echo "== SSE stream + event pings (v0.10) =="
UNDERCROFT_MCP_HTTP_TOKEN="$TOKEN" \
  "$BIN" serve-http --host 127.0.0.1 --port 8797 >/tmp/tstream.log 2>&1 &
S3=$!
wait_up 8797 || fail "stream server did not start" "$(cat /tmp/tstream.log)"
AUTH=(-H "Authorization: Bearer $TOKEN")
BASE="http://127.0.0.1:8797/v1/vaults"

# hmac-only vault: live events keep wing/room.
curl -s "${AUTH[@]}" -X POST "$BASE" -d '{"id":"plain","level":"hmac-only"}' >/dev/null
curl -sN --max-time 4 "${AUTH[@]}" "$BASE/plain/stream" >/tmp/plain.sse 2>/dev/null &
C1=$!
sleep 1
curl -s "${AUTH[@]}" -X POST "$BASE/plain/drawers" \
  -d '{"text":"we chose postgres for billing","wing":"eng","room":"decisions"}' >/dev/null
curl -s "${AUTH[@]}" -X POST "$BASE/plain/search" -d '{"query":"which database"}' >/dev/null
wait $C1 2>/dev/null
grep -q "event: drawer-saved" /tmp/plain.sse && pass "stream emits drawer-saved" \
  || fail "no drawer-saved frame" "$(cat /tmp/plain.sse)"
grep -q "event: search" /tmp/plain.sse && pass "stream emits search" || fail "no search frame"
grep -q "event: sample" /tmp/plain.sse && pass "stream emits sampler frame" || fail "no sample frame"
grep -q '"wing":"eng"' /tmp/plain.sse && pass "hmac-only stream carries wing/room" \
  || fail "wing/room missing on hmac-only vault"

# sealed vault: live events suppress wing/room names.
curl -s "${AUTH[@]}" -X POST "$BASE" -d '{"id":"sealed","level":"sealed"}' >/dev/null
curl -sN --max-time 3 "${AUTH[@]}" "$BASE/sealed/stream" >/tmp/sealed.sse 2>/dev/null &
C2=$!
sleep 1
curl -s "${AUTH[@]}" -X POST "$BASE/sealed/drawers" \
  -d '{"text":"acquisition plan","wing":"topsecret","room":"boardroom"}' >/dev/null
wait $C2 2>/dev/null
grep -q "event: drawer-saved" /tmp/sealed.sse && pass "sealed stream emits drawer-saved" \
  || fail "no sealed drawer-saved frame"
if grep -qE "topsecret|boardroom" /tmp/sealed.sse; then
  fail "sealed stream leaked wing/room names" "$(cat /tmp/sealed.sse)"
else
  pass "sealed stream suppresses wing/room"
fi

# history backfill endpoint returns the sample ring.
hist=$(curl -s "${AUTH[@]}" "$BASE/plain/stats/history")
grep -q '"drawers"' <<<"$hist" && pass "stats/history returns samples" \
  || fail "history empty" "$hist"

kill "$S3" 2>/dev/null
wait "$S3" 2>/dev/null

echo
echo "telemetry e2e results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "TELEMETRY E2E OK"
