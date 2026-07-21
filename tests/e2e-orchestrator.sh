#!/usr/bin/env bash
# End-to-end suite for the multi-tenant orchestrator: two real engine
# instances + the orchestrator control plane in one container. Exercises
# the whole story — instance registry, tenant creation with token minting,
# the routed data plane, cross-tenant isolation through the proxy, and a
# count-verified live migration between instances.

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
trap 'kill $ENGINE_A $ENGINE_B $ORCH_PID 2>/dev/null' EXIT

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

echo ""
echo "orchestrator e2e results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ORCHESTRATOR E2E OK" || exit 1
