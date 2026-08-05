#!/usr/bin/env bash
# End-to-end suite for the multi-tenant orchestrator: two real engine
# instances + the orchestrator control plane in one container. Exercises
# the whole story — instance registry, tenant creation with token minting,
# the routed data plane, cross-tenant isolation through the proxy, a
# count-verified live migration between instances, and a read replica
# converging on the writer's state.

set -uo pipefail

BIN="${BIN:-/src/target/release/undercroft}"
ORCH="${ORCH:-/src/target/release/undercroft-orchestrator}"

PASS=0
FAIL=0

ok()   { echo "ok    $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL  $1"; shift; [ $# -gt 0 ] && echo "$*" | sed 's/^/      /'; FAIL=$((FAIL+1)); }

body_has() { # <name> <expected-substr> -- <curl args...>
  local name="$1" want="$2"; shift 3
  local out; out="$(curl -s "$@" 2>&1)"
  grep -qF "$want" <<<"$out" && ok "$name" || fail "$name" "wanted: $want" "got: $out"
}
code_is() { # <name> <expected-code> -- <curl args...>
  local name="$1" want="$2"; shift 3
  local code; code="$(curl -s -o /dev/null -w '%{http_code}' "$@")"
  [ "$code" = "$want" ] && ok "$name" || fail "$name" "wanted HTTP $want, got $code"
}

# ---- two engine instances -------------------------------------------------

HOME_A="$(mktemp -d)"; HOME_B="$(mktemp -d)"
SECRET_A="assertion-secret-alpha"; SECRET_B="assertion-secret-beta"
BEARER_A="engine-bearer-alpha"; BEARER_B="engine-bearer-beta"
PORT_A=18801; PORT_B=18802; PORT_O=18900

UNDERCROFT_HOME="$HOME_A" "$BIN" init >/dev/null 2>&1
UNDERCROFT_HOME="$HOME_B" "$BIN" init >/dev/null 2>&1
UNDERCROFT_HOME="$HOME_A" UNDERCROFT_MCP_HTTP_TOKEN="$BEARER_A" \
  UNDERCROFT_ASSERTION_SECRET="$SECRET_A" \
  "$BIN" serve-http --host 127.0.0.1 --port "$PORT_A" >/tmp/engine-a.log 2>&1 &
ENGINE_A=$!
UNDERCROFT_HOME="$HOME_B" UNDERCROFT_MCP_HTTP_TOKEN="$BEARER_B" \
  UNDERCROFT_ASSERTION_SECRET="$SECRET_B" \
  "$BIN" serve-http --host 127.0.0.1 --port "$PORT_B" >/tmp/engine-b.log 2>&1 &
ENGINE_B=$!

# ---- orchestrator ---------------------------------------------------------

export UNDERCROFT_ORCH_DB="$(mktemp -d)/orch.db"
export UNDERCROFT_ORCH_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
export UNDERCROFT_ORCH_ADMIN_TOKEN="e2e-admin-token-0123456789"
"$ORCH" serve --addr "127.0.0.1:$PORT_O" >/tmp/orch.log 2>&1 &
ORCH_PID=$!
trap 'kill $ENGINE_A $ENGINE_B $ORCH_PID ${REPLICA_PID:-} 2>/dev/null' EXIT

for p in $PORT_A $PORT_B $PORT_O; do
  for _ in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$p/healthz" >/dev/null 2>&1 && break; sleep 0.1
  done
done

O="http://127.0.0.1:$PORT_O"
ADMIN=(-H "Authorization: Bearer $UNDERCROFT_ORCH_ADMIN_TOKEN")

echo "== Liveness and admin gate =="
body_has "orchestrator healthz"        '"ok":true'    -- "$O/healthz"
body_has "/ui serves fleet console"    'Fleet Console' -- "$O/ui"
code_is  "admin without token is 401"  401            -- "$O/admin/instances"
code_is  "admin with wrong token 401"  401            -- -H "Authorization: Bearer wrong-token-aaaaaaaa" "$O/admin/instances"

echo "== Instance registry =="
body_has "register engine-a" '"added":"engine-a"' -- -X POST "${ADMIN[@]}" \
  -d "{\"name\":\"engine-a\",\"url\":\"http://127.0.0.1:$PORT_A\",\"bearer\":\"$BEARER_A\",\"assertion_secret\":\"$SECRET_A\"}" \
  "$O/admin/instances"
body_has "register engine-b" '"added":"engine-b"' -- -X POST "${ADMIN[@]}" \
  -d "{\"name\":\"engine-b\",\"url\":\"http://127.0.0.1:$PORT_B\",\"bearer\":\"$BEARER_B\",\"assertion_secret\":\"$SECRET_B\"}" \
  "$O/admin/instances"
body_has "instance list has both"  '"engine-b"'      -- "${ADMIN[@]}" "$O/admin/instances"
body_has "instance health probes"  '"healthy":true'  -- "${ADMIN[@]}" "$O/admin/instances/engine-a/health"

echo "== Tenant creation (auto-placement + token minting) =="
ACME="$(curl -s -X POST "${ADMIN[@]}" -d '{"name":"acme"}' "$O/admin/tenants")"
ACME_ID="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$ACME")"
ACME_TOKEN="$(sed -n 's/.*"token":"\([0-9a-f]*\)".*/\1/p' <<<"$ACME")"
[ -n "$ACME_ID" ] && [ -n "$ACME_TOKEN" ] && ok "acme created with token" \
  || fail "acme created with token" "$ACME"
GLOBEX="$(curl -s -X POST "${ADMIN[@]}" -d '{"name":"globex"}' "$O/admin/tenants")"
GLOBEX_TOKEN="$(sed -n 's/.*"token":"\([0-9a-f]*\)".*/\1/p' <<<"$GLOBEX")"
grep -qF '"instance":"engine-b"' <<<"$GLOBEX" && ok "least-loaded placement spreads" \
  || fail "least-loaded placement spreads" "$GLOBEX"

echo "== Routed data plane =="
AUTH_ACME=(-H "Authorization: Bearer $ACME_TOKEN")
AUTH_GLOBEX=(-H "Authorization: Bearer $GLOBEX_TOKEN")
body_has "save through the proxy" '"created":true' -- -X POST "${AUTH_ACME[@]}" \
  -d '{"text":"the flux capacitor needs 1.21 gigawatts to engage","wing":"eng","room":"notes"}' \
  "$O/t/drawers"
body_has "search returns verbatim" 'gigawatts' -- -X POST "${AUTH_ACME[@]}" \
  -d '{"query":"flux capacitor power"}' "$O/t/search"

echo "== Admin tenant stats (fleet live-ops) =="
# Metadata-only stats via the admin plane (stored engine creds, no tenant token).
body_has "admin tenant stats"      '"drawers":1'  -- "${ADMIN[@]}" "$O/admin/tenants/$ACME_ID/stats"
code_is  "stats for unknown tenant 404" 404       -- "${ADMIN[@]}" "$O/admin/tenants/ffffffffffffffff/stats"
body_has "/ui has fleet totals"    'ENGINES UP'   -- "$O/ui"
body_has "stats route relays"      '"id":"tenant-' -- "${AUTH_ACME[@]}" "$O/t/stats"
code_is  "bad token is 401"        401 -- -H "Authorization: Bearer 0000000000000000" -X POST \
  -d '{"query":"x"}' "$O/t/search"
code_is  "tokenless is 401"        401 -- -X POST -d '{"query":"x"}' "$O/t/search"
code_is  "vault root not routable" 404 -- -X DELETE "${AUTH_ACME[@]}" "$O/t/"
code_is  "unknown subpath is 404"  404 -- -X POST "${AUTH_ACME[@]}" -d '{}' "$O/t/frobnicate"

echo "== Cross-tenant isolation through the proxy =="
GX_SEARCH="$(curl -s -X POST "${AUTH_GLOBEX[@]}" -d '{"query":"flux capacitor power"}' "$O/t/search")"
grep -qF 'gigawatts' <<<"$GX_SEARCH" \
  && fail "globex cannot see acme data" "$GX_SEARCH" \
  || ok "globex cannot see acme data"

echo "== Live migration engine-a → engine-b =="
MIG="$(curl -s -X POST "${ADMIN[@]}" -d '{"to":"engine-b"}' "$O/admin/tenants/$ACME_ID/migrate")"
grep -qF '"records":1' <<<"$MIG" && ok "migration count-verified" || fail "migration count-verified" "$MIG"
grep -qF '"source_deleted":true' <<<"$MIG" && ok "source vault deleted" || fail "source vault deleted" "$MIG"
body_has "same token still works post-migration" 'gigawatts' -- -X POST "${AUTH_ACME[@]}" \
  -d '{"query":"flux capacitor power"}' "$O/t/search"
body_has "mapping flipped"  '"instance":"engine-b"' -- "${ADMIN[@]}" "$O/admin/tenants"
# The source engine no longer serves the vault (assertion minted directly
# against engine A — the vault is gone, so the store open 404s).
SIGN_A="$(UNDERCROFT_ASSERTION_SECRET="$SECRET_A" "$BIN" assert-header "tenant-$ACME_ID")"
code_is "source engine lost the vault" 404 -- -X POST \
  -H "Authorization: Bearer $BEARER_A" -H "X-Vault-Assertion: $SIGN_A" \
  -d '{"query":"flux"}' "http://127.0.0.1:$PORT_A/v1/vaults/tenant-$ACME_ID/search"

echo "== Instance removal guard =="
body_has "empty instance removes"    '"removed":true' -- -X DELETE "${ADMIN[@]}" "$O/admin/instances/engine-a"
code_is  "hosting instance refuses"  409              -- -X DELETE "${ADMIN[@]}" "$O/admin/instances/engine-b"

echo "== Token rotation =="
ROT="$(curl -s -X POST "${ADMIN[@]}" "$O/admin/tenants/$ACME_ID/rotate")"
ACME_TOKEN2="$(sed -n 's/.*"token":"\([0-9a-f]*\)".*/\1/p' <<<"$ROT")"
[ -n "$ACME_TOKEN2" ] && [ "$ACME_TOKEN2" != "$ACME_TOKEN" ] && ok "rotation mints a fresh token" \
  || fail "rotation mints a fresh token" "$ROT"
code_is  "old token revoked immediately" 401 -- -X POST "${AUTH_ACME[@]}" \
  -d '{"query":"flux"}' "$O/t/search"
AUTH_ACME2=(-H "Authorization: Bearer $ACME_TOKEN2")
body_has "rotated token serves" 'gigawatts' -- -X POST "${AUTH_ACME2[@]}" \
  -d '{"query":"flux capacitor power"}' "$O/t/search"
code_is  "rotate unknown tenant is 404" 404 -- -X POST "${ADMIN[@]}" "$O/admin/tenants/ffffffffffffffff/rotate"

echo "== Data-plane boundary: traversal, replica writes, query forwarding =="
# A DEDICATED tenant, for two reasons the first draft of this block learned
# the hard way: acme's token was deliberately rotated out above (so it answers
# 401 before the route is consulted), and acme is still inside the per-tenant
# rate-limit window the burst check above filled (so it answers 429). Either
# one makes a traversal check pass for a reason that has nothing to do with
# the gate under test.
BND="$(curl -s -X POST "${ADMIN[@]}" -d '{"name":"boundary"}' "$O/admin/tenants")"
BND_TOKEN="$(grep -o '"token":"[0-9a-f]*"' <<<"$BND" | head -1 | cut -d'"' -f4)"
BND_AUTH=(-H "Authorization: Bearer $BND_TOKEN")
curl -s -X POST "${BND_AUTH[@]}"   -d '{"text":"boundary tenant first drawer gigawatts","wing":"w","room":"r"}'   "$O/t/drawers" >/dev/null

# `--path-as-is` is load-bearing: curl squashes `../` in the path CLIENT-side
# by default, so without it the orchestrator never sees a traversal and the
# check proves nothing about our gate.
#
# The escalation this suite could not see. `data_subpath_ok` matched only the
# FIRST path segment while the engine URL is built by interpolation, so ureq's
# `url` parse collapsed `..` and the engine received an operator route. Proven
# on the wire: asking for `/drawers/../admission` sent
# `POST /v1/vaults/<t>/admission`. A tenant data token therefore reached
# admission rulings, trust, retention sweeps, forget, KEY ROTATION and vault
# deletion — and by climbing two levels, another tenant's vault.
for escape in   "drawers/../admission"   "drawers/../trust"   "drawers/../retention"   "drawers/../forget"   "drawers/../rotate"   "search/../verify"   "drawers/%2e%2e/admission" ; do
  code_is "traversal refused: $escape" 404 -- --path-as-is -X POST     "${BND_AUTH[@]}" -d '{}' "$O/t/$escape"
done
# Climbing past the vault entirely — cross-tenant read.
code_is "traversal refused: cross-tenant" 404 -- --path-as-is -X POST   "${BND_AUTH[@]}" -d '{"query":"flux"}' "$O/t/search/../../globex/search"
# Premise: the legitimate prefixes those escapes are built from still serve,
# so the checks above cannot pass by refusing everything (or by 401).
body_has "premise: plain search still serves" 'gigawatts' -- -X POST   "${BND_AUTH[@]}" -d '{"query":"boundary tenant drawer"}' "$O/t/search"

# The query string was split off the request target and never forwarded, so
# every engine parameter a tenant declared was silently dropped: a paginating
# client got page one forever at HTTP 200.
curl -s -X POST "${BND_AUTH[@]}"   -d '{"text":"a second drawer for paging","wing":"w","room":"r"}'   "$O/t/drawers" >/dev/null
PAGED="$(curl -s "${BND_AUTH[@]}" "$O/t/drawers?limit=1")"
UNPAGED="$(curl -s "${BND_AUTH[@]}" "$O/t/drawers")"
N_PAGED="$(grep -o '"id"' <<<"$PAGED" | wc -l)"
N_UNPAGED="$(grep -o '"id"' <<<"$UNPAGED" | wc -l)"
if [ "$N_PAGED" -eq 1 ] && [ "$N_UNPAGED" -gt 1 ]; then
  ok "query string reaches the engine (limit honoured)"
else
  fail "query string dropped" "limit=1 gave $N_PAGED id(s), unlimited gave $N_UNPAGED"
fi


echo "== Per-tenant rate limiting =="
kill $ORCH_PID 2>/dev/null; wait $ORCH_PID 2>/dev/null
UNDERCROFT_ORCH_RATE_LIMIT=3 "$ORCH" serve --addr "127.0.0.1:$PORT_O" >>/tmp/orch.log 2>&1 &
ORCH_PID=$!
for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$PORT_O/healthz" >/dev/null 2>&1 && break; sleep 0.1
done
# 8 rapid requests against a limit of 3/min: even if a minute boundary
# rolls mid-burst, one window necessarily holds >=4 of them, so at least
# one 429 is guaranteed — deterministic, no timing flake.
LIMITED=0
for i in 1 2 3 4 5 6 7 8; do
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${AUTH_ACME2[@]}" -d '{"query":"flux"}' "$O/t/search")"
  [ "$code" = "429" ] && LIMITED=1
done
[ "$LIMITED" = "1" ] && ok "burst over the limit trips 429" || fail "burst over the limit trips 429"
code_is "another tenant is untouched" 200 -- -X POST "${AUTH_GLOBEX[@]}" \
  -d '{"query":"anything"}' "$O/t/search"

echo "== Read replica (shared state volume) =="
PORT_R=18901
R="http://127.0.0.1:$PORT_R"
"$ORCH" serve --addr "127.0.0.1:$PORT_R" --read-replica >/tmp/orch-replica.log 2>&1 &
REPLICA_PID=$!
for _ in $(seq 1 100); do
  curl -sf "$R/healthz" >/dev/null 2>&1 && break; sleep 0.1
done
body_has "replica healthz declares mode"  '"mode":"read-replica"' -- "$R/healthz"
body_has "writer healthz declares mode"   '"mode":"writer"'       -- "$O/healthz"
body_has "healthz carries last_write"     '"last_write":1'        -- "$O/healthz"
code_is  "replica refuses admin plane"    403 -- "${ADMIN[@]}" "$R/admin/instances"
code_is  "replica refuses the console"    403 -- "$R/ui"
# The replica's own limiter is off (no env), so the data plane serves even
# though the writer's window for acme is still hot from the burst above.
body_has "replica serves the data plane"  'gigawatts' -- -X POST "${AUTH_ACME2[@]}" \
  -d '{"query":"flux capacitor power"}' "$R/t/search"
# Rotate on the writer; the replica converges immediately (same file —
# the zero-lag bound of the shared-volume deployment).
ROT2="$(curl -s -X POST "${ADMIN[@]}" "$O/admin/tenants/$ACME_ID/rotate")"
ACME_TOKEN3="$(sed -n 's/.*"token":"\([0-9a-f]*\)".*/\1/p' <<<"$ROT2")"
code_is  "replica converges: rotated-out token dies" 401 -- -X POST "${AUTH_ACME2[@]}" \
  -d '{"query":"flux"}' "$R/t/search"
body_has "replica converges: fresh token serves" 'gigawatts' -- -X POST \
  -H "Authorization: Bearer $ACME_TOKEN3" \
  -d '{"query":"flux capacitor power"}' "$R/t/search"
# A tenant minted on the writer after replica start resolves through it.
INITECH="$(curl -s -X POST "${ADMIN[@]}" -d '{"name":"initech"}' "$O/admin/tenants")"
INITECH_TOKEN="$(sed -n 's/.*"token":"\([0-9a-f]*\)".*/\1/p' <<<"$INITECH")"
body_has "new tenant resolves via replica" '"id":"tenant-' -- \
  -H "Authorization: Bearer $INITECH_TOKEN" "$R/t/stats"
# A replica never creates state: pointing it at a missing db must fail.
if UNDERCROFT_ORCH_DB=/tmp/definitely-absent/orch.db "$ORCH" serve \
     --addr 127.0.0.1:18999 --read-replica >/dev/null 2>&1; then
  fail "replica refuses a missing state db"
else
  ok "replica refuses a missing state db"
fi

echo "== Data-plane boundary: replica writes =="
# A read replica serves reads. `/t/*` dispatched before the writer-only role
# check and `data_plane` took no role, so `require_writable()` was unreachable
# over HTTP in either role and a replica proxied writes at 200.
code_is "replica refuses a data-plane write" 403 -- -X POST -H "Authorization: Bearer $ACME_TOKEN3"   -d '{"text":"written to a replica","wing":"w","room":"r"}' "$R/t/drawers"
code_is "replica refuses a data-plane delete" 403 -- -X DELETE   -H "Authorization: Bearer $ACME_TOKEN3" "$R/t/drawers/deadbeef"
body_has "replica still serves POST search" 'gigawatts' -- -X POST   -H "Authorization: Bearer $ACME_TOKEN3" -d '{"query":"flux capacitor power"}' "$R/t/search"


echo ""
echo "orchestrator e2e results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ORCHESTRATOR E2E OK" || exit 1
