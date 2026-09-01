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
# ROADMAP O64 — RFC 9110 §11.6.1 makes a challenge header a MUST on any 401,
# and it was missing from every 401 in the fleet. The control plane's BODIES
# were already right (`err_response` has always answered JSON), which is what
# made the engine's two plain-text gate sites the outlier rather than a second
# valid convention — so this asserts the half that was actually absent here.
hdrs="$(curl -s -D - -o /dev/null "$O/admin/instances")"
if grep -qi '^WWW-Authenticate: *Bearer' <<<"$hdrs"; then
  ok "an admin 401 names its scheme"
else
  fail "an admin 401 names its scheme" "no WWW-Authenticate in: $(tr -d '\r' <<<"$hdrs" | head -4 | tr '\n' ' ')"
fi

echo "== Instance registry =="
body_has "register engine-a" '"added":"engine-a"' -- -X POST "${ADMIN[@]}" \
  -d "{\"name\":\"engine-a\",\"url\":\"http://127.0.0.1:$PORT_A\",\"bearer\":\"$BEARER_A\",\"assertion_secret\":\"$SECRET_A\"}" \
  "$O/admin/instances"
body_has "register engine-b" '"added":"engine-b"' -- -X POST "${ADMIN[@]}" \
  -d "{\"name\":\"engine-b\",\"url\":\"http://127.0.0.1:$PORT_B\",\"bearer\":\"$BEARER_B\",\"assertion_secret\":\"$SECRET_B\"}" \
  "$O/admin/instances"
# **A registration whose assertion secret names no secret is refused, on the
# SERVER door.** `ui.html` blocked an empty secret client-side only, which is
# exactly why the server gap stayed invisible: every hand-driven registration
# was stopped and nothing else was. `proxy.rs` calls its path guard and the
# assertion MAC "two independent barriers, because one silent misconfiguration
# must not remove the only one" — an empty secret removed one of them at
# registration, and the instance then routed and reported healthy.
# Whitespace is the arm a fix mapping empty-to-absent would miss: it is not
# empty, so it would be stored and used as a real key.
code_is  "empty assertion secret is 400"      400 -- -X POST "${ADMIN[@]}" \
  -d "{\"name\":\"engine-x\",\"url\":\"http://127.0.0.1:$PORT_A\",\"bearer\":\"b\",\"assertion_secret\":\"\"}" \
  "$O/admin/instances"
code_is  "whitespace assertion secret is 400" 400 -- -X POST "${ADMIN[@]}" \
  -d "{\"name\":\"engine-x\",\"url\":\"http://127.0.0.1:$PORT_A\",\"bearer\":\"b\",\"assertion_secret\":\"   \"}" \
  "$O/admin/instances"
# A refusal must not half-register: the name stays absent from the list.
if curl -s "${ADMIN[@]}" "$O/admin/instances" | grep -q 'engine-x'; then
  # The message must not collide with the check at the bottom of this file,
  # which carries the same words for a DIFFERENT refusal — a failure line is
  # the only thing a reader gets, so two of them reading alike sends someone
  # to the wrong test.
  echo "FAIL  a secretless registration must not appear in the list"; FAIL=$((FAIL+1))
else
  echo "ok    a secretless registration is not registered"; PASS=$((PASS+1))
fi
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

# ROADMAP O67. Eight of the engine's 28 per-vault subpaths were reachable from
# NEITHER plane — not the ops plane, not here — so a tenant asking for their
# own taxonomy or their own distilled facts got a bare "unknown route", which
# reads as a capability the product does not have. These are the tenant's own
# vault; `drawers` and `search` two blocks up already return its content.
code_is  "taxonomy reaches the tenant"      200 -- "${AUTH_ACME[@]}" "$O/t/taxonomy"
body_has "taxonomy names the tenant's wing" 'eng' -- "${AUTH_ACME[@]}" "$O/t/taxonomy"
code_is  "kg/stats reaches the tenant"      200 -- "${AUTH_ACME[@]}" "$O/t/kg/stats"
code_is  "kg/query reaches the tenant"      200 -- "${AUTH_ACME[@]}" "$O/t/kg/query?entity=nobody"
code_is  "kg/entities reaches the tenant"   200 -- "${AUTH_ACME[@]}" "$O/t/kg/entities"
code_is  "kg/timeline reaches the tenant"   200 -- "${AUTH_ACME[@]}" "$O/t/kg/timeline?entity=nobody"
code_is  "kg/receipts reaches the tenant"   200 -- "${AUTH_ACME[@]}" "$O/t/kg/receipts"
# And the one that must NOT: `kg/authority` is a WRITE and is in the engine's
# OPERATOR_ONLY — promotion closes the previous canonical holder's window, so
# a tenant token must never carry it. It went to the ops plane instead, and
# the refusal must SAY that rather than 404ing as though it did not exist.
code_is  "kg/authority refused on the data plane" 404 -- -X POST "${AUTH_ACME[@]}" \
  -d '{"triple_id":"x","authority_class":"golden"}' "$O/t/kg/authority"
body_has "kg/authority names the ops plane" 'operator route' -- -X POST "${AUTH_ACME[@]}" \
  -d '{"triple_id":"x","authority_class":"golden"}' "$O/t/kg/authority"
# The quarantine fence still applies to every widened route.
code_is  "fence still covers kg/query" 404 -- "${AUTH_ACME[@]}" \
  "$O/t/kg/query?entity=quarantine-pending"

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

echo "== Operator plane: every ops route, positively (C9/C15) =="
# Ten routes landed on the admin plane on the argument that they "were
# reachable from nowhere in a fleet" — and then this suite drove NONE of
# them, so what was proved was the refusals and never the capability. Each
# one is exercised here through the admin plane AND through the CLI alias,
# because docs/MULTI_TENANCY.md says the CLI mirrors this plane and it had
# no subcommand at all until 2026-08-05.
OPS_T="$(curl -s -X POST "${ADMIN[@]}" -d '{"name":"opsy"}' "$O/admin/tenants")"
OPS_ID="$(grep -o '"id":"[0-9a-f]*"' <<<"$OPS_T" | head -1 | cut -d'"' -f4)"
OPS_TOKEN="$(grep -o '"token":"[0-9a-f]*"' <<<"$OPS_T" | head -1 | cut -d'"' -f4)"
curl -s -X POST -H "Authorization: Bearer $OPS_TOKEN"   -d '{"text":"the ops tenant filed a drawer about turbines","wing":"w","room":"r"}'   "$O/t/drawers" >/dev/null

body_has "ops verify"        '"ok":true'   -- -X POST "${ADMIN[@]}" "$O/admin/tenants/$OPS_ID/ops/verify"
body_has "ops anchor"        '"anchored"'  -- -X POST "${ADMIN[@]}" "$O/admin/tenants/$OPS_ID/ops/anchor"
body_has "ops supersessions" 'supersessions' -- "${ADMIN[@]}" "$O/admin/tenants/$OPS_ID/ops/supersessions"
body_has "ops admission list" 'pending'    -- "${ADMIN[@]}" "$O/admin/tenants/$OPS_ID/ops/admission"
body_has "ops trust list"    'assignments' -- "${ADMIN[@]}" "$O/admin/tenants/$OPS_ID/ops/trust"
# Backups on the OPERATOR plane (ROADMAP O68). They are `Absence::Boundary` on
# MCP and must never reach the tenant data plane, so this is the only door a
# fleet operator has — which is the entire justification for the routes.
body_has "ops backup create" '"backup"'  -- -X POST "${ADMIN[@]}" "$O/admin/tenants/$OPS_ID/ops/backups"
body_has "ops backup list"   '"backups"' -- "${ADMIN[@]}" "$O/admin/tenants/$OPS_ID/ops/backups"
# The tenant plane must REFUSE them, and name the plane that holds them
# rather than 404ing as though the capability did not exist.
code_is  "backups are not on the tenant data plane" 404 -- \
  -H "Authorization: Bearer $OPS_TOKEN" "$O/t/backups"
body_has "ops trust assign"  '"trust":"trusted"' -- -X POST "${ADMIN[@]}"   -d '{"wing":"w","trust":"trusted"}' "$O/admin/tenants/$OPS_ID/ops/trust"
body_has "ops retention list" 'policies'   -- "${ADMIN[@]}" "$O/admin/tenants/$OPS_ID/ops/retention"
body_has "ops retention set" '"days":3650' -- -X POST "${ADMIN[@]}"   -d '{"wing":"w","days":3650}' "$O/admin/tenants/$OPS_ID/ops/retention"
body_has "ops retention sweep" 'destroyed' -- -X POST "${ADMIN[@]}"   -d '{}' "$O/admin/tenants/$OPS_ID/ops/retention/sweep"
# **ROADMAP O14 — the plane that MINTS a receipt can now CHECK one.**
# `forget` has been forwardable since this table was written; verifying what
# it returns was reachable from nowhere in a fleet, because the engine had no
# route for it at all. A right-to-erasure receipt an operator cannot verify
# through their only door is the asymmetry this table's own comment describes,
# one step on. The ROUND TRIP is the assertion — minted here, checked here,
# the same document — because either half alone proves nothing about the pair.
O14_ID="$(curl -s -X POST -H "Authorization: Bearer $OPS_TOKEN" \
  -d '{"text":"a fleet note the data subject asked us to erase","wing":"w","room":"r"}' \
  "$O/t/drawers" | grep -o '"id":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)"
O14_ATT="$(curl -s -X POST "${ADMIN[@]}" -d "{\"ids\":[\"$O14_ID\"]}" \
  "$O/admin/tenants/$OPS_ID/ops/forget")"
if [ -n "$O14_ID" ] && grep -q '"head_after"' <<<"$O14_ATT"; then
  ok "o14 premise: the ops plane minted an attestation"
else
  fail "o14 premise: id='$O14_ID' body='$(head -c 160 <<<"$O14_ATT")'"
fi
body_has "ops verify-forgetting" '"verdict":"verified"' -- -X POST "${ADMIN[@]}" \
  -d "$O14_ATT" "$O/admin/tenants/$OPS_ID/ops/verify-forgetting"
# And through the CLI alias, which `docs/MULTI_TENANCY.md` says mirrors the
# plane — the half that has shipped missing before. Captured, never piped:
# `set -o pipefail` makes `if cmd | grep` see the command's status.
O14_CLI="$("$ORCH" --db "$UNDERCROFT_ORCH_DB" ops "$OPS_ID" verify-forgetting --body "$O14_ATT" 2>&1)"
if grep -q '"verdict":"verified"' <<<"$O14_CLI"; then
  ok "orchestrator CLI ops verify-forgetting"
else
  fail "orchestrator CLI ops verify-forgetting: $(head -c 160 <<<"$O14_CLI")"
fi
# A route that is NOT on the plane stays off it, so the block above is not
# passing because everything is forwarded.
code_is  "ops refuses key rotation" 404 -- -X POST "${ADMIN[@]}" "$O/admin/tenants/$OPS_ID/ops/rotate"
code_is  "ops refuses drawer reads" 404 -- "${ADMIN[@]}" "$O/admin/tenants/$OPS_ID/ops/drawers"

# The CLI mirrors it — the half docs promised and nothing shipped.
if "$ORCH" --db "$UNDERCROFT_ORCH_DB" ops "$OPS_ID" verify 2>&1 | grep -q '"ok":true'; then
  ok "orchestrator CLI ops verify"
else
  fail "orchestrator CLI ops verify"
fi
if "$ORCH" --db "$UNDERCROFT_ORCH_DB" ops "$OPS_ID" trust 2>&1 | grep -q 'assignments'; then
  ok "orchestrator CLI ops trust"
else
  fail "orchestrator CLI ops trust"
fi
# Captured rather than piped: `set -o pipefail` makes an `if cmd | grep`
# see the FAILING command's status, so a refusal that greps correctly still
# reads as a failed check — which is what this one did on its first run.
OPS_ERR="$("$ORCH" --db "$UNDERCROFT_ORCH_DB" ops "$OPS_ID" frobnicate 2>&1)"
if grep -q 'unknown operation' <<<"$OPS_ERR"; then
  ok "orchestrator CLI ops refuses an unknown operation"
else
  fail "orchestrator CLI ops refuses an unknown operation" "$OPS_ERR"
fi

echo "== Transport policy and exit-code doctrine on the control plane =="
# All of this was unit-tested only. The definition of done asks for the
# surface a user drives, and the surface is where the wiring lives.

# A cleartext instance URL is refused AT REGISTRATION, not at first request.
code_is  "cleartext instance refused 400" 400 -- -X POST "${ADMIN[@]}" \
  -d '{"name":"cleartext","url":"http://engine.internal:8800","bearer":"b","assertion_secret":"s"}' \
  "$O/admin/instances"
body_has "and it names the fix"   'no override' -- -X POST "${ADMIN[@]}" \
  -d '{"name":"cleartext","url":"http://engine.internal:8800","bearer":"b","assertion_secret":"s"}' \
  "$O/admin/instances"
body_has "refused means not registered" '"instances":[' -- "${ADMIN[@]}" "$O/admin/instances"
if curl -s "${ADMIN[@]}" "$O/admin/instances" | grep -qF '"cleartext"'; then
  fail "a refused registration must not appear in the list"
else
  ok "a refused registration must not appear in the list"
fi

# Health answers a STATE, so a local refusal is distinguishable from an
# outage. `engine-a` was deregistered earlier in this suite, so this asks
# `engine-b` — the one still registered. The `refused` arm cannot be
# reached through this door at all now, because the registration check
# above proves a cleartext instance can no longer be STORED; it is covered
# by the unit test on `Health` instead, and that split is the point: the
# door refuses earlier than the probe can observe.
body_has "health carries a state"   '"state":"healthy"' -- "${ADMIN[@]}" \
  "$O/admin/instances/engine-b/health"

# A garbage CA pin refuses to START, rather than binding the port and
# 502-ing every request afterwards.
BADCA="$(mktemp)"; : > "$BADCA"
if UNDERCROFT_ORCH_ENGINE_CA="$BADCA" "$ORCH" --db "$UNDERCROFT_ORCH_DB" instance-list >/dev/null 2>&1; then
  fail "a CA pin that resolves to nothing must refuse to start"
else
  ok "a CA pin that resolves to nothing must refuse to start"
fi
PIN_ERR="$(UNDERCROFT_ORCH_ENGINE_CA="$BADCA" "$ORCH" --db "$UNDERCROFT_ORCH_DB" instance-list 2>&1)"
if grep -qF 'pins nothing' <<<"$PIN_ERR"; then
  ok "and it says what is wrong with the pin"
else
  fail "and it says what is wrong with the pin" "$PIN_ERR"
fi
# ...and the refusal is a run failure (exit 1), never the integrity code.
UNDERCROFT_ORCH_ENGINE_CA="$BADCA" "$ORCH" --db "$UNDERCROFT_ORCH_DB" instance-list >/dev/null 2>&1
if [ $? -eq 1 ]; then
  ok "a configuration refusal exits 1, not the integrity code"
else
  fail "a configuration refusal exits 1, not the integrity code"
fi
rm -f "$BADCA"

# ── the control plane's OWN tamper verdict reaches the exit code (M20) ──────
# `instance-list` resolves each instance's sealed credential blob. Under a
# DIFFERENT (valid-shaped) key those blobs will not open — which state.rs
# calls "a tamper verdict or a wrong key, never a transient condition" — and
# the command caught that error into a `refused=` note, stringified it, and
# returned Ok(()). So the fleet's own integrity verdict printed on stdout and
# **exited 0**, which is what a compliance script reads as fine. The exit-2
# hook in `main` never fired because the error never escaped `run()`.
#
# Note this is the SAME command as the CA-pin arm above, and the two verdicts
# must stay distinguishable: a configuration refusal is exit 1, a tamper
# verdict is exit 2. Asserting them one after the other is what pins that.
WRONGKEY="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
WK_OUT="$(UNDERCROFT_ORCH_KEY="$WRONGKEY" "$ORCH" --db "$UNDERCROFT_ORCH_DB" instance-list 2>&1)"
WK_CODE=$?
if [ $WK_CODE -eq 2 ]; then
  ok "a credential blob that will not open exits 2, not 0"
else
  fail "a credential blob that will not open exits 2, not 0" "exit $WK_CODE: $WK_OUT"
fi
# A listing must still LIST — one unopenable blob must not hide the fleet.
if grep -q 'engine-b' <<<"$WK_OUT"; then
  ok "and the listing still names every instance"
else
  fail "and the listing still names every instance" "$WK_OUT"
fi
if grep -q 'INTEGRITY VERDICT' <<<"$WK_OUT"; then
  ok "and it says the verdict is the control plane's own"
else
  fail "and it says the verdict is the control plane's own" "$WK_OUT"
fi

# **A usage error exits 1, not clap's default 2.** Exit 2 is reserved for an
# integrity verdict on every command, so a typo reaching a compliance script
# as a tamper verdict is the collision this pins.
"$ORCH" --db "$UNDERCROFT_ORCH_DB" migrate acme >/dev/null 2>&1
CODE=$?
if [ "$CODE" -eq 1 ]; then
  ok "a usage error exits 1, not the integrity code"
else
  fail "a usage error exits 1, not the integrity code" "exit $CODE"
fi
"$ORCH" --help >/dev/null 2>&1
if [ $? -eq 0 ]; then
  ok "--help still exits 0"
else
  fail "--help still exits 0"
fi

# Removing an unregistered instance is not a success on EITHER door.
"$ORCH" --db "$UNDERCROFT_ORCH_DB" instance-remove nosuchinstance >/dev/null 2>&1
if [ $? -ne 0 ]; then
  ok "CLI: removing an unregistered instance fails"
else
  fail "CLI: removing an unregistered instance fails"
fi
code_is  "HTTP: same, 404"          404 -- -X DELETE "${ADMIN[@]}" \
  "$O/admin/instances/nosuchinstance"

echo "== Integrity doctrine: a tampered vault exits 2 on the fleet's door =="
# **The gap that let the last regression ship.** `is_integrity_verdict` had
# only a unit test over hand-written bodies — and a unit test fed a
# fabricated body cannot see that the engine never emits the class. It
# didn't: `vault_err` classed nothing, so `ops verify` over a tampered
# vault exited 1 while the engine's own `verify` exited 2 on the same
# bytes. Two surfaces, two doctrines, one vault.
#
# Both arms, because they arrive by different routes and only one of them
# is a 4xx:
#   1. a 200 whose body says {"ok":false} — `verify` succeeded at HTTP and
#      is telling you the vault is bad;
#   2. a 4xx carrying {"class":"integrity"} — the vault would not even
#      open, which is the arm the regression lived in.
#
# Both vaults are tampered while the ENGINE HAS NEVER OPENED THEM. That is
# not incidental: `store_for` caches a handle for the life of the process,
# so editing a database the server already holds open measures SQLite's
# page cache rather than the tamper detection. A tenant that has never been
# routed to has no cached handle, so the next `ops` call opens it cold.
tamper_vault_of() { # <tenant-id> -> echoes the vault DIRECTORY on its engine
  local tid="$1" inst home
  # The tenant list is one JSON object per tenant; splitting on `}` gives
  # one per line, so the id and the instance that are read here are
  # guaranteed to come from the SAME tenant. Grepping the whole document
  # for `"instance"` would happily return a neighbour's.
  inst="$(curl -s "${ADMIN[@]}" "$O/admin/tenants" | tr '}' '\n' \
    | grep -F "\"id\":\"$tid\"" \
    | sed -n 's/.*"instance":"\([a-z0-9-]*\)".*/\1/p')"
  case "$inst" in
    engine-a) home="$HOME_A" ;;
    engine-b) home="$HOME_B" ;;
    *) return 1 ;;
  esac
  echo "$home/vaults/tenant-$tid"
}

# Every forgery below asserts that it CHANGED THE FILE. Both of these
# silently matched nothing on their first run — one wrong subcommand, one
# regex that missed a space in pretty-printed JSON — and the suite then
# reported a clean vault, which reads exactly like a broken exit code. A
# fixture that cannot fire is indistinguishable from a defect it cannot
# find, so it says so itself.
forged() { # <name> <file> <before-md5>
  local name="$1" file="$2" before="$3"
  if [ "$(md5sum "$file" | cut -d' ' -f1)" != "$before" ]; then
    ok "$name"
  else
    fail "$name" "the forgery matched nothing in $file — this test would now \
pass for the wrong reason"
  fi
}

# ---- arm 1: the verdict that arrives on a 200 ------------------------------
HOT="$(curl -s -X POST "${ADMIN[@]}" -d '{"name":"tamper-row"}' "$O/admin/tenants")"
HOT_ID="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$HOT")"
HOT_DIR="$(tamper_vault_of "$HOT_ID")"
if [ -n "$HOT_DIR" ] && [ -d "$HOT_DIR" ]; then
  ok "tamper fixture: located the tenant vault"
else
  fail "tamper fixture: located the tenant vault" "got: '$HOT_DIR'"
fi
# Content written by a SEPARATE CLI process against the same home. The
# server has never opened this vault, so there is no second handle and no
# stale page cache — and the forgery below is what the HMAC must catch.
UNDERCROFT_HOME="$(dirname "$(dirname "$HOT_DIR")")" \
  "$BIN" remember "the turbine bearing was replaced in March" \
  --vault "tenant-$HOT_ID" --wing w --room r >/dev/null 2>&1
HOT_BEFORE="$(md5sum "$HOT_DIR/palace.db" | cut -d' ' -f1)"
# Same length, so the SQLite file stays structurally valid and only the
# record HMAC can catch it.
perl -0777 -pi -e 's/"wing":"w"/"wing":"x"/' "$HOT_DIR/palace.db"
forged "tamper fixture: the drawer row was forged" "$HOT_DIR/palace.db" "$HOT_BEFORE"
OUT="$("$ORCH" --db "$UNDERCROFT_ORCH_DB" ops "$HOT_ID" verify 2>&1)"; CODE=$?
if [ "$CODE" -eq 2 ] && grep -q '"ok":false' <<<"$OUT"; then
  ok "tampered vault: ops verify exits 2 on a 200 + ok:false"
else
  fail "tampered vault: ops verify exits 2 on a 200 + ok:false" "exit $CODE" "$OUT"
fi

# ---- arm 2: the verdict that arrives as a classed 4xx ----------------------
COLD="$(curl -s -X POST "${ADMIN[@]}" -d '{"name":"tamper-manifest"}' "$O/admin/tenants")"
COLD_ID="$(sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' <<<"$COLD")"
COLD_DIR="$(tamper_vault_of "$COLD_ID")"
COLD_BEFORE="$(md5sum "$COLD_DIR/vault.json" | cut -d' ' -f1)"
# The manifest MAC covers `writes`, so moving it is an offline edit the
# unlock must refuse. Structure-preserving, so this is ManifestTampered
# rather than a parse failure — the sharper of the two classed verdicts.
# The JSON is pretty-printed, hence `\s*`.
perl -0777 -pi -e 's/"writes":\s*\d+/"writes": 4242/' "$COLD_DIR/vault.json"
forged "tamper fixture: the manifest was forged" "$COLD_DIR/vault.json" "$COLD_BEFORE"
BODY="$(curl -s -X POST "${ADMIN[@]}" "$O/admin/tenants/$COLD_ID/ops/verify")"
CODE_HTTP="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${ADMIN[@]}" \
  "$O/admin/tenants/$COLD_ID/ops/verify")"
if [ "$CODE_HTTP" = "409" ] && grep -qF '"class":"integrity"' <<<"$BODY"; then
  ok "tampered manifest: the engine EMITS class integrity (409)"
else
  fail "tampered manifest: the engine EMITS class integrity (409)" \
    "HTTP $CODE_HTTP" "$BODY"
fi
OUT="$("$ORCH" --db "$UNDERCROFT_ORCH_DB" ops "$COLD_ID" verify 2>&1)"; CODE=$?
if [ "$CODE" -eq 2 ]; then
  ok "tampered manifest: ops verify exits 2 on a classed 4xx"
else
  fail "tampered manifest: ops verify exits 2 on a classed 4xx" "exit $CODE" "$OUT"
fi
# The premise both arms rest on: an INTACT vault still exits 0, so this is
# a verdict and not a door that always says 2.
if "$ORCH" --db "$UNDERCROFT_ORCH_DB" ops "$OPS_ID" verify >/dev/null 2>&1; then
  ok "an intact vault still exits 0"
else
  fail "an intact vault still exits 0"
fi

echo "== Data-plane quarantine fence (C15) =="
# The fence had ZERO occurrences in this suite: the reading half of the
# boundary OPS_ROUTES draws for the ruling half, tested only in a unit test.
# It refuses BEFORE any engine call, so naming the reserved wing on any
# data-plane route is refused whether or not the tenant has anything in it.
OPS_AUTH=(-H "Authorization: Bearer $OPS_TOKEN")
body_has "fence: search naming the wing"  'quarantine' -- -X POST "${OPS_AUTH[@]}"   -d '{"query":"x","wing":"quarantine-pending"}' "$O/t/search"
body_has "fence: drawers?wing="           'quarantine' -- "${OPS_AUTH[@]}"   "$O/t/drawers?wing=quarantine-pending"
body_has "fence: save aimed at the wing"  'quarantine' -- -X POST "${OPS_AUTH[@]}"   -d '{"text":"forged","wing":"quarantine-pending"}' "$O/t/drawers"
code_is  "fence: refuses with 404"    404 -- "${OPS_AUTH[@]}"   "$O/t/drawers?wing=quarantine-pending"
# Premise: the same routes serve an ordinary wing, so the refusals above
# are about the wing and not about the routes.
body_has "premise: ordinary wing serves" 'turbines' -- -X POST "${OPS_AUTH[@]}"   -d '{"query":"turbines","wing":"w"}' "$O/t/search"

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


echo "== config check: the pre-flight and the serve path agree (ROADMAP O21) =="
# The control plane had no pre-flight at all, so three Protects declarations
# sat on the ENGINE's exempt list as "orchestrator-owned" while
# `UPGRADING.md` told operators that exit 0 means nothing affects them.
#
# What is asserted here is AGREEMENT, which is the whole point: the same
# declaration must produce the same verdict from the pre-flight and from a
# real `serve`. A pre-flight that merely runs is worth nothing.
orch_pre() { # orch_pre <VAR> <value> -> prints "<preflight-exit> <serve-exit>"
  local var="$1" val="$2" pc sc
  env "$var=$val" "$ORCH" config check >/tmp/orch-cc.log 2>&1; pc=$?
  # `timeout` because a serve that does NOT refuse binds and blocks forever —
  # which is the regression these checks exist to catch, and without it the
  # suite hangs instead of failing. 124 is neither 0 nor 1, so it reports.
  timeout 5 env "$var=$val" "$ORCH" serve --addr "127.0.0.1:18999" \
    >/tmp/orch-serve.log 2>&1; sc=$?
  echo "$pc $sc"
}

# Both spellings dispatch, since the engine shipped only the hyphenated one
# while every doc published the two-word form (ROADMAP O18).
"$ORCH" config check >/dev/null 2>&1 && ok "two-word 'config check' runs" \
  || fail "two-word 'config check' did not run" "$("$ORCH" config check 2>&1 | tail -3)"
"$ORCH" config-check >/dev/null 2>&1 && ok "hyphenated 'config-check' runs" \
  || fail "hyphenated 'config-check' did not run"

read -r PC SC <<<"$(orch_pre UNDERCROFT_ORCH_RATE_LIMIT lots)"
if [ "$PC" = "1" ] && [ "$SC" = "1" ]; then
  ok "a garbage rate limit is refused by the pre-flight AND by serve"
else
  fail "pre-flight and serve disagree on a garbage rate limit" "preflight=$PC serve=$SC"
fi
grep -q "requests per minute" /tmp/orch-cc.log \
  && ok "the pre-flight names the fix for a garbage rate limit" \
  || fail "pre-flight refused without naming the fix" "$(tail -3 /tmp/orch-cc.log)"

# The admin token, and this is the live defect O22 found on the engine's
# identical path. A trailing newline CLEARS the 16-character floor that was
# the only check here — a newline has length — so the control plane started
# cleanly and refused every /admin request forever, 401 naming no cause.
#
# The newline is a LITERAL inside single quotes, never `$(printf …)`: command
# substitution strips trailing newlines, so the tidier spelling passes a
# perfectly valid token, `serve` starts, and the check hangs instead of
# proving anything. It did exactly that on its first run.
TOKEN_WITH_NEWLINE='e2e-admin-token-0123456789
'
read -r PC SC <<<"$(orch_pre UNDERCROFT_ORCH_ADMIN_TOKEN "$TOKEN_WITH_NEWLINE")"
if [ "$PC" = "1" ] && [ "$SC" = "1" ]; then
  ok "an admin token ending in a newline is refused by both"
else
  fail "a token no client can present started a control plane" "preflight=$PC serve=$SC"
fi
grep -q "ends in whitespace" /tmp/orch-cc.log \
  && ok "the diagnosis is the trailing whitespace, not the length floor" \
  || fail "wrong diagnosis for a trailing-newline admin token" "$(tail -3 /tmp/orch-cc.log)"

read -r PC SC <<<"$(orch_pre UNDERCROFT_ORCH_ADMIN_TOKEN "")"
if [ "$PC" = "1" ] && [ "$SC" = "1" ]; then
  ok "an empty admin token is refused by both"
else
  fail "an empty admin token was accepted somewhere" "preflight=$PC serve=$SC"
fi

# …and a healthy environment passes, so the checks above are not a command
# that refuses everything. This is the premise the four of them rest on.
if "$ORCH" config check >/tmp/orch-cc-ok.log 2>&1; then
  ok "the environment this suite runs in passes its own pre-flight"
else
  fail "the pre-flight refuses a working environment" "$(tail -5 /tmp/orch-cc-ok.log)"
fi
grep -q "CONTROL PLANE only" /tmp/orch-cc-ok.log \
  && ok "the pass message says it covers the control plane only" \
  || fail "the pre-flight implied it covered the engines too"

echo ""
echo "orchestrator e2e results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ORCHESTRATOR E2E OK" || exit 1
