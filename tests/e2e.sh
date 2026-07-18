#!/usr/bin/env bash
# End-to-end UI/UX test suite for the undercroft CLI and MCP server.
#
# Runs inside the builder container against the release binary. Exercises
# the surfaces a human (or an MCP client) actually touches: help text,
# happy paths, output formatting, exit codes, error messages, and the
# tamper-detection story.

set -uo pipefail

BIN="${BIN:-/src/target/release/undercroft}"
export UNDERCROFT_HOME="$(mktemp -d)"
unset UNDERCROFT_PASSPHRASE 2>/dev/null || true

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

echo "== UX: help, version, error surfaces =="
check "help shows purpose"        0 "hardened local-first AI memory" -- "$BIN" --help
check "help lists commands"       0 "wake-up"                        -- "$BIN" --help
check "version prints"            0 "undercroft"                      -- "$BIN" --version
check "unknown cmd fails w/usage" 2 "Usage"                          -- "$BIN" frobnicate
check "search before init fails"  1 "not found"                      -- "$BIN" search anything

echo "== Core flow: init → remember → search → wake-up =="
check "init"                      0 "Palace initialized"             -- "$BIN" init
check "init is idempotent"        0 "already initialized"            -- "$BIN" init
check "remember files a drawer"   0 "Filed drawer"                   -- "$BIN" remember \
  "We migrated the search stack to Rust for memory safety" --wing eng --room decisions
check "second memory"             0 "Filed drawer"                   -- "$BIN" remember \
  "Team lunch every Thursday at the ramen place" --wing social
check "search finds relevant"     0 "eng/decisions"                  -- "$BIN" search "why rust migration"
check "search scoped empty"       0 "No memories matched"            -- "$BIN" search "rust" --wing social
check "wake-up shows layers"      0 "L1 — ESSENTIAL STORY"           -- "$BIN" wake-up
check "wake-up surfaces memory"   0 "Rust"                           -- "$BIN" wake-up

echo "== Identity file (L0) =="
echo "I am the team's memory keeper." > "$UNDERCROFT_HOME/identity.txt"
check "wake-up reads identity"    0 "memory keeper"                  -- "$BIN" wake-up

echo "== Vault management & isolation =="
check "vault create"              0 "Created vault 'work'"           -- "$BIN" vault create work
check "vault create dup fails"    1 "already exists"                 -- "$BIN" vault create work
check "vault traversal rejected"  1 ""                               -- "$BIN" vault create "../escape"
check "remember into work vault"  0 "Filed drawer"                   -- "$BIN" remember \
  "the acquisition codename is BLUE HERON" --vault work
check "default cannot see work"   0 "No memories matched"            -- "$BIN" search "acquisition codename"
check "work vault sees its own"   0 "BLUE HERON"                     -- "$BIN" search "acquisition codename" --vault work
check "vault list shows both"     0 "work"                           -- "$BIN" vault list
check "vault status"              0 "chain head"                     -- "$BIN" vault status work

echo "== Encryption at rest =="
if grep -qF "BLUE HERON" "$UNDERCROFT_HOME/vaults/work/palace.db" 2>/dev/null; then
  echo "FAIL  sealed vault leaked plaintext to disk"; FAIL=$((FAIL+1))
else
  echo "ok    sealed vault has no plaintext on disk"; PASS=$((PASS+1))
fi

echo "== FTS5 BM25 prefilter (hmac-only vaults) =="
check "hmac-only vault create"    0 "Created vault 'plain'"          -- "$BIN" vault create plain --level hmac-only
check "remember into plain vault" 0 "Filed drawer"                   -- "$BIN" remember \
  "the staging cluster runs kubernetes one-thirty" --vault plain
check "prefiltered search hits"   0 "kubernetes"                     -- \
  env UNDERCROFT_FTS_PREFILTER_MIN=1 "$BIN" search "staging kubernetes cluster" --vault plain
check "prefilter off still hits"  0 "kubernetes"                     -- \
  env UNDERCROFT_FTS_PREFILTER_MIN=off "$BIN" search "staging kubernetes cluster" --vault plain
if grep -qF "drawers_fts" "$UNDERCROFT_HOME/vaults/plain/palace.db" 2>/dev/null; then
  echo "ok    hmac-only vault has an FTS index"; PASS=$((PASS+1))
else
  echo "FAIL  hmac-only vault missing its FTS index"; FAIL=$((FAIL+1))
fi
if grep -qF "drawers_fts" "$UNDERCROFT_HOME/vaults/work/palace.db" 2>/dev/null; then
  echo "FAIL  sealed vault grew an FTS index"; FAIL=$((FAIL+1))
else
  echo "ok    sealed vault has no FTS index"; PASS=$((PASS+1))
fi

echo "== PQ/IVF prefilter (UNDERCROFT_RETRIEVAL=pq, both vault levels) =="
check "pq search hits"            0 "kubernetes"                     -- \
  env UNDERCROFT_RETRIEVAL=pq "$BIN" search "staging kubernetes cluster" --vault plain
check "bad retrieval mode fails"  1 "unknown UNDERCROFT_RETRIEVAL"    -- \
  env UNDERCROFT_RETRIEVAL=nope "$BIN" search "anything" --vault plain
if grep -qF "drawer_pq" "$UNDERCROFT_HOME/vaults/plain/palace.db" 2>/dev/null; then
  echo "ok    hmac-only vault has PQ codes on disk"; PASS=$((PASS+1))
else
  echo "FAIL  hmac-only vault missing its PQ codes"; FAIL=$((FAIL+1))
fi
check "pq search on sealed vault" 0 "BLUE HERON"                     -- \
  env UNDERCROFT_RETRIEVAL=pq "$BIN" search "acquisition codename" --vault work
# The sealed vault gets the index too — but every artifact is AEAD-sealed
# (the unit suite asserts no plaintext-derived bytes; here we re-assert the
# at-rest check now that the PQ tables exist in the same db file).
if grep -qF "BLUE HERON" "$UNDERCROFT_HOME/vaults/work/palace.db" 2>/dev/null; then
  echo "FAIL  sealed vault leaked plaintext into the db"; FAIL=$((FAIL+1))
else
  echo "ok    sealed vault db stays sealed with PQ on"; PASS=$((PASS+1))
fi

echo "== Mining files =="
MINE_DIR="$(mktemp -d)"
printf '# Retro\n\nWhat went well: the release train.\n\nWhat to fix: flaky CI on arm64.\n' \
  > "$MINE_DIR/retro-2026-07.md"
check "mine directory"            0 "drawer(s) filed"                -- "$BIN" mine "$MINE_DIR" --wing team
check "mined content searchable"  0 "flaky CI"                       -- "$BIN" search "what should we fix in CI" --wing team
check "export emits jsonl"        0 "retro-2026-07"                  -- "$BIN" export

echo "== Conversation mining + sweep =="
CONVO_DIR="$(mktemp -d)"
cat > "$CONVO_DIR/session-abc.jsonl" <<'JSONL'
{"type":"user","message":{"role":"user","content":"how do we handle rate limiting in the gateway?"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"The gateway uses a token bucket with 100 requests per minute per client."},{"type":"tool_use","name":"Bash","input":{}}]}}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"noise"}]}}
JSONL
check "mine convos"               0 "drawer(s) filed"                -- "$BIN" mine "$CONVO_DIR" --mode convos --wing claude
check "convo content searchable"  0 "token bucket"                   -- "$BIN" search "how is rate limiting handled" --wing claude
check "sweep transcripts"         0 "message drawer(s) filed"        -- "$BIN" sweep "$CONVO_DIR" --wing swept
check "sweep is idempotent"       0 "0 message drawer(s) filed"      -- "$BIN" sweep "$CONVO_DIR" --wing swept
check "bad mine mode fails"       1 "unknown mine mode"              -- "$BIN" mine "$CONVO_DIR" --mode nope

echo "== Knowledge graph =="
check "kg add"                    0 "Added fact"                     -- "$BIN" kg add alice works_at acme --from 2024-01-01
check "kg query finds fact"       0 "acme"                           -- "$BIN" kg query alice
check "kg supersede"              0 "globex"                         -- "$BIN" kg supersede alice works_at globex --at 2025-06-01
check "kg query shows current"    0 "globex"                         -- "$BIN" kg query alice
check "kg as-of shows history"    0 "acme"                           -- "$BIN" kg query alice --as-of 2024-06-15
check "kg timeline"               0 "acme"                           -- "$BIN" kg timeline --entity alice
check "kg stats"                  0 "triples: 2"                     -- "$BIN" kg stats

echo "== Drawer management =="
DRAWER_ID="$("$BIN" drawer list --wing eng --limit 1 | awk '{print $1}')"
check "drawer list"               0 "eng/decisions"                  -- "$BIN" drawer list --wing eng
check "drawer get verbatim"       0 "memory safety"                  -- "$BIN" drawer get "$DRAWER_ID"
check "check-dup finds filed"     0 "duplicate of"                   -- "$BIN" drawer check-dup "We migrated the search stack to Rust for memory safety"
check "check-dup misses novel"    0 "not filed"                      -- "$BIN" drawer check-dup "never stored anywhere"
check "drawer delete"             0 "Deleted drawer"                 -- "$BIN" drawer delete "$DRAWER_ID"
check "deleted drawer gone"       1 "No drawer"                      -- "$BIN" drawer get "$DRAWER_ID"
check "verify ok after delete"    0 "VERIFY OK"                      -- "$BIN" verify

echo "== Agent diaries =="
check "diary write"               0 "written for agent"              -- "$BIN" diary write scout "mapped the auth flow today"
check "diary read"                0 "auth flow"                      -- "$BIN" diary read scout
check "list agents"               0 "scout"                          -- "$BIN" diary agents

echo "== Tunnels & taxonomy & stats =="
check "tunnel create"             0 "Tunnel"                         -- "$BIN" tunnel create eng claude --label "code discussions"
check "tunnel list"               0 "eng <-> claude"                 -- "$BIN" tunnel list
check "traverse reaches wing"     0 "claude"                         -- "$BIN" tunnel traverse eng
check "taxonomy tree"             0 "claude/"                        -- "$BIN" taxonomy
check "stats output"              0 "records:"                       -- "$BIN" stats
check "stats counts kg"           0 "triples"                        -- "$BIN" stats

echo "== Dedup =="
"$BIN" remember "duplicate payload content" --wing dup >/dev/null
"$BIN" remember "duplicate payload content" --wing dup --room second >/dev/null
check "dedup reports"             0 "1 duplicate group(s)"           -- "$BIN" dedup
check "dedup applies"             0 "removed"                        -- "$BIN" dedup --apply
check "verify ok after dedup"     0 "VERIFY OK"                      -- "$BIN" verify

echo "== Closets, fuzzy search, refine gating =="
"$BIN" remember "We migrated the search stack to Rust for speed and memory safety" --wing eng --room decisions >/dev/null
check "closets index lines"       0 "eng/decisions"                  -- "$BIN" closets --wing eng
check "closets show counts"       0 "n="                             -- "$BIN" closets
check "fuzzy search one typo"     0 "eng/decisions"                  -- "$BIN" search "migrated the serch stack"
check "refine needs llm url"      1 "UNDERCROFT_LLM_URL"              -- "$BIN" refine

echo "== Key rotation =="
check "rotate default vault"      0 "Rotated vault 'default'"        -- "$BIN" vault rotate default
check "verify ok after rotate"    0 "VERIFY OK"                      -- "$BIN" verify
check "search ok after rotate"    0 "eng/decisions"                  -- "$BIN" search "migrated the search stack"
check "kg survives rotate"        0 "triples"                        -- "$BIN" stats
check "dup lookup after rotate"   0 "duplicate of"                   -- "$BIN" drawer check-dup "We migrated the search stack to Rust for speed and memory safety"
check "second rotate idempotent"  0 "Rotated vault 'default'"        -- "$BIN" vault rotate default
check "verify ok after 2nd rotate" 0 "VERIFY OK"                     -- "$BIN" verify

echo "== Backups & repair =="
check "backup create"             0 "Backup created"                 -- "$BIN" backup create
check "backup list"               0 "default-"                       -- "$BIN" backup list
check "repair passes"             0 "integrity: ok"                  -- "$BIN" repair
check "hooks prints settings"     0 "PreCompact"                     -- "$BIN" hooks claude-code

echo "== Integrity: verify + tamper detection =="
check "verify clean vault"        0 "VERIFY OK"                      -- "$BIN" verify --vault work
# Forge the record's metadata in place (same length, so the SQLite file
# stays structurally valid — only the HMAC can catch it).
DB="$UNDERCROFT_HOME/vaults/work/palace.db"
perl -0777 -pi -e 's/"added_by":"cli"/"added_by":"clj"/' "$DB"
out="$("$BIN" verify --vault work 2>&1)"; code=$?
if [ "$code" -eq 2 ] && grep -q "VERIFY FAILED" <<<"$out"; then
  echo "ok    tampered vault detected (exit 2, VERIFY FAILED)"; PASS=$((PASS+1))
else
  echo "FAIL  tamper detection — exit $code"; echo "$out" | sed 's/^/      /'; FAIL=$((FAIL+1))
fi

echo "== Transcripts: render, import, daemon =="
T_DIR="$(mktemp -d)"
cat > "$T_DIR/session-x.jsonl" <<'JSONL'
{"type":"user","message":{"role":"user","content":"where do we keep the deploy runbook?"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"The runbook lives in ops/runbooks/deploy.md — release train section."}]}}
JSONL
check "transcript render"         0 "release train"                  -- "$BIN" transcript render "$T_DIR/session-x.jsonl"
check "transcript render max"     0 "more message(s)"                -- "$BIN" transcript render "$T_DIR/session-x.jsonl" --max 1
check "daemon --once sweeps"      0 "swept 1 transcript(s)"          -- "$BIN" daemon run --watch "$T_DIR" --once --wing daemon-test
check "daemon result searchable"  0 "runbook"                        -- "$BIN" search "deploy runbook location" --wing daemon-test

EXPORT_FILE="$(mktemp)"
"$BIN" export > "$EXPORT_FILE"
IMPORT_HOME="$(mktemp -d)"
UNDERCROFT_HOME="$IMPORT_HOME" "$BIN" init >/dev/null
out="$(UNDERCROFT_HOME="$IMPORT_HOME" "$BIN" import "$EXPORT_FILE" 2>&1)"; code=$?
if [ $code -eq 0 ] && grep -q "Imported" <<<"$out"; then
  echo "ok    import from export"; PASS=$((PASS+1))
else
  echo "FAIL  import from export"; echo "$out" | sed 's/^/      /'; FAIL=$((FAIL+1))
fi
# Mempalace-format line imports too.
MEMPAL_FILE="$(mktemp)"
echo '{"document":"legacy memory from the python palace","metadata":{"wing":"legacy","room":"misc","chunk_index":0}}' > "$MEMPAL_FILE"
out="$(UNDERCROFT_HOME="$IMPORT_HOME" "$BIN" import "$MEMPAL_FILE" 2>&1)"; code=$?
if [ $code -eq 0 ] && UNDERCROFT_HOME="$IMPORT_HOME" "$BIN" search "legacy python palace" | grep -q "legacy"; then
  echo "ok    mempalace-format import"; PASS=$((PASS+1))
else
  echo "FAIL  mempalace-format import"; echo "$out" | sed 's/^/      /'; FAIL=$((FAIL+1))
fi

echo "== Encrypted export bundles =="
BUNDLE_KEY="$(mktemp -u)"
RECIPIENT="$("$BIN" bundle keygen --out "$BUNDLE_KEY" | grep "Recipient" | awk '{print $3}')"
check "keygen prints recipient"   0 "$RECIPIENT"                     -- "$BIN" bundle recipient "$BUNDLE_KEY"
BUNDLE_FILE="$(mktemp -u)"
check "sealed export writes"      0 "Sealed bundle written"          -- "$BIN" export --to "$RECIPIENT" --out "$BUNDLE_FILE"
if ! grep -q "retro-2026-07" "$BUNDLE_FILE" 2>/dev/null; then
  echo "ok    bundle is not plaintext"; PASS=$((PASS+1))
else
  echo "FAIL  bundle leaked plaintext"; FAIL=$((FAIL+1))
fi
check "bundle import needs key"   1 "encrypted bundle"               -- env UNDERCROFT_HOME="$IMPORT_HOME" "$BIN" import "$BUNDLE_FILE"
out="$(UNDERCROFT_HOME="$IMPORT_HOME" "$BIN" import "$BUNDLE_FILE" --identity "$BUNDLE_KEY" 2>&1)"; code=$?
if [ $code -eq 0 ] && grep -q "Imported" <<<"$out"; then
  echo "ok    bundle import with identity"; PASS=$((PASS+1))
else
  echo "FAIL  bundle import with identity"; echo "$out" | sed 's/^/      /'; FAIL=$((FAIL+1))
fi
WRONG_KEY="$(mktemp -u)"
"$BIN" bundle keygen --out "$WRONG_KEY" >/dev/null
check "wrong identity refused"    1 "wrong identity key"             -- env UNDERCROFT_HOME="$IMPORT_HOME" "$BIN" import "$BUNDLE_FILE" --identity "$WRONG_KEY"
check "keygen refuses overwrite"  1 "refusing to overwrite"          -- "$BIN" bundle keygen --out "$BUNDLE_KEY"

echo "== HTTP MCP server =="
# Non-loopback bind without token must be refused.
check "http refuses tokenless 0.0.0.0" 1 "UNDERCROFT_MCP_HTTP_TOKEN" -- "$BIN" serve-http --host 0.0.0.0 --port 18765
export UNDERCROFT_MCP_HTTP_TOKEN="e2e-secret-token"
"$BIN" serve-http --host 127.0.0.1 --port 18765 &
HTTP_PID=$!
sleep 1
http_req() { # http_req <path> <body-or-empty> [auth]
  local path="$1" body="$2" auth="${3:-}"
  exec 3<>/dev/tcp/127.0.0.1/18765
  if [ -n "$body" ]; then
    printf 'POST %s HTTP/1.0\r\nContent-Type: application/json\r\n%sContent-Length: %d\r\n\r\n%s' \
      "$path" "$auth" "${#body}" "$body" >&3
  else
    printf 'GET %s HTTP/1.0\r\n\r\n' "$path" >&3
  fi
  cat <&3
  exec 3<&- 3>&-
}
out="$(http_req /healthz "")"
if grep -q "^ok$" <<<"$out" || grep -q "ok" <<<"$out"; then
  echo "ok    healthz"; PASS=$((PASS+1))
else
  echo "FAIL  healthz"; echo "$out" | sed 's/^/      /'; FAIL=$((FAIL+1))
fi
out="$(http_req /mcp '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"
if grep -q "401" <<<"$out"; then
  echo "ok    http rejects missing token"; PASS=$((PASS+1))
else
  echo "FAIL  http rejects missing token"; echo "$out" | head -3 | sed 's/^/      /'; FAIL=$((FAIL+1))
fi
out="$(http_req /mcp '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' $'Authorization: Bearer e2e-secret-token\r\n')"
if grep -q "undercroft_kg_add" <<<"$out"; then
  echo "ok    http tools/list with token"; PASS=$((PASS+1))
else
  echo "FAIL  http tools/list with token"; echo "$out" | head -3 | sed 's/^/      /'; FAIL=$((FAIL+1))
fi
kill $HTTP_PID 2>/dev/null
# Read-only server rejects writes.
"$BIN" serve-http --host 127.0.0.1 --port 18766 --read-only &
RO_PID=$!
sleep 1
out="$(exec 3<>/dev/tcp/127.0.0.1/18766; body='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"undercroft_save","arguments":{"content":"nope"}}}'; printf 'POST /mcp HTTP/1.0\r\nContent-Type: application/json\r\nAuthorization: Bearer e2e-secret-token\r\nContent-Length: %d\r\n\r\n%s' "${#body}" "$body" >&3; cat <&3; exec 3<&- 3>&-)"
if grep -q "read-only" <<<"$out"; then
  echo "ok    read-only rejects writes"; PASS=$((PASS+1))
else
  echo "FAIL  read-only rejects writes"; echo "$out" | head -3 | sed 's/^/      /'; FAIL=$((FAIL+1))
fi
kill $RO_PID 2>/dev/null
unset UNDERCROFT_MCP_HTTP_TOKEN

echo "== Localization (UNDERCROFT_LANG) =="
L_HOME="$(mktemp -d)"
out="$(UNDERCROFT_HOME="$L_HOME" UNDERCROFT_LANG=de "$BIN" init 2>&1)"
if grep -q "Palast initialisiert" <<<"$out"; then
  echo "ok    german init output"; PASS=$((PASS+1))
else
  echo "FAIL  german init output"; echo "$out" | sed 's/^/      /'; FAIL=$((FAIL+1))
fi
out="$(UNDERCROFT_HOME="$L_HOME" UNDERCROFT_LANG=zh "$BIN" remember "多语言测试记忆" 2>&1)"
if grep -q "已归档到" <<<"$out"; then
  echo "ok    chinese remember output"; PASS=$((PASS+1))
else
  echo "FAIL  chinese remember output"; echo "$out" | sed 's/^/      /'; FAIL=$((FAIL+1))
fi
out="$(UNDERCROFT_HOME="$L_HOME" UNDERCROFT_LANG=ru "$BIN" verify 2>&1)"
if grep -q "ПРОВЕРКА ПРОЙДЕНА" <<<"$out"; then
  echo "ok    russian verify verdict"; PASS=$((PASS+1))
else
  echo "FAIL  russian verify verdict"; echo "$out" | sed 's/^/      /'; FAIL=$((FAIL+1))
fi
check "unknown lang falls back"   0 "Palace already initialized"     -- env UNDERCROFT_HOME="$L_HOME" UNDERCROFT_LANG=tlh "$BIN" init
check "model-eval memories gated" 1 "UNDERCROFT_LLM_URL"              -- "${BIN%/*}/undercroft-bench" model-eval memories

echo "== Benchmark harness =="
check "bench synth passes"        0 "SYNTH OK"                       -- "${BIN%/*}/undercroft-bench" synth --n 60

echo "== MCP server (JSON-RPC over stdio) =="
MCP_OUT="$(printf '%s\n%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"undercroft_save","arguments":{"content":"mcp saved this memory","wing":"agents"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"undercroft_search","arguments":{"query":"mcp saved"}}}' \
  | "$BIN" serve-mcp 2>/dev/null)"
mcp_check() {
  local name="$1" sub="$2"
  if grep -qF "$sub" <<<"$MCP_OUT"; then
    echo "ok    $name"; PASS=$((PASS+1))
  else
    echo "FAIL  $name — missing: $sub"; echo "$MCP_OUT" | sed 's/^/      /'; FAIL=$((FAIL+1))
  fi
}
mcp_check "initialize handshake"    '"serverInfo"'
mcp_check "tools/list has 4 tools"  '"undercroft_verify"'
mcp_check "save tool works"         'saved drawer'
mcp_check "search tool round-trips" 'mcp saved this memory'

echo "== Multi-tenant HTTP REST surface =="
REST_HOME="$(mktemp -d)"
PORT=8791
SECRET="e2e-assertion-secret-key-material"
UNDERCROFT_HOME="$REST_HOME" UNDERCROFT_ASSERTION_SECRET="$SECRET" "$BIN" init >/dev/null 2>&1
UNDERCROFT_HOME="$REST_HOME" UNDERCROFT_ASSERTION_SECRET="$SECRET" \
  "$BIN" serve-http --host 127.0.0.1 --port "$PORT" >/tmp/serve.log 2>&1 &
SRV=$!
for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.1
done

API="http://127.0.0.1:$PORT/v1"
sign() { UNDERCROFT_ASSERTION_SECRET="$SECRET" "$BIN" assert-header "$1"; }

rest_body() { # <name> <expected-substr> -- <curl args...>
  local name="$1" sub="$2"; shift 2; [ "$1" = "--" ] && shift
  local out; out="$(curl -s "$@" 2>&1)"
  if grep -qF "$sub" <<<"$out"; then echo "ok    $name"; PASS=$((PASS+1))
  else echo "FAIL  $name — missing: $sub"; echo "$out" | sed 's/^/      /'; FAIL=$((FAIL+1)); fi
}
rest_code() { # <name> <expected-code> -- <curl args...>
  local name="$1" want="$2"; shift 2; [ "$1" = "--" ] && shift
  local code; code="$(curl -s -o /dev/null -w '%{http_code}' "$@")"
  if [ "$code" = "$want" ]; then echo "ok    $name"; PASS=$((PASS+1))
  else echo "FAIL  $name — code $code (wanted $want)"; FAIL=$((FAIL+1)); fi
}

rest_body "create vault"        '"created":true'  -- -X POST "$API/vaults" \
  -H "X-Vault-Assertion: $(sign acme)" -d '{"id":"acme","level":"sealed"}'
rest_code "missing assertion 401" 401 -- -X POST "$API/vaults/acme/search" -d '{"query":"x"}'
rest_body "save drawer"         '"created":true'  -- -X POST "$API/vaults/acme/drawers" \
  -H "X-Vault-Assertion: $(sign acme)" \
  -d '{"text":"we picked postgres for the billing service","wing":"eng","room":"decisions"}'
rest_body "search finds it"     'postgres'        -- -X POST "$API/vaults/acme/search" \
  -H "X-Vault-Assertion: $(sign acme)" -d '{"query":"which database for billing"}'
rest_body "stats"               '"drawers":1'     -- "$API/vaults/acme/stats" \
  -H "X-Vault-Assertion: $(sign acme)"

# The core multi-tenant guarantee: an assertion minted for one vault must
# not authorize another.
rest_body "create globex"       '"created":true'  -- -X POST "$API/vaults" \
  -H "X-Vault-Assertion: $(sign globex)" -d '{"id":"globex"}'
ACME_ASSERT="$(sign acme)"
rest_code "acme assertion on globex 401" 401 -- -X POST "$API/vaults/globex/search" \
  -H "X-Vault-Assertion: $ACME_ASSERT" -d '{"query":"x"}'

# Export → verified import → drop, with an exact record count.
curl -s "$API/vaults/acme/export" -H "X-Vault-Assertion: $(sign acme)" > /tmp/acme.jsonl
rest_body "create acme2"        '"created":true'  -- -X POST "$API/vaults" \
  -H "X-Vault-Assertion: $(sign acme2)" -d '{"id":"acme2"}'
rest_body "import count"        '"imported":1'    -- -X POST "$API/vaults/acme2/import" \
  -H "X-Vault-Assertion: $(sign acme2)" --data-binary @/tmp/acme.jsonl
rest_body "import verified"     '"drawers":1'     -- "$API/vaults/acme2/stats" \
  -H "X-Vault-Assertion: $(sign acme2)"

# Portable derived artifacts: an import line may carry the drawer's
# late-interaction token matrix (tok = model + base64 packed) — accepted and
# stored without re-encoding; garbage artifacts are a clean 400.
TOK_LINE="$(head -1 /tmp/acme.jsonl | sed 's/}$/,"tok":{"model":"m","b64":"AQEAAAABAAAAAACAP38="}}/')"
rest_body "import with artifact" '"imported":1'   -- -X POST "$API/vaults/acme2/import" \
  -H "X-Vault-Assertion: $(sign acme2)" --data-binary "$TOK_LINE"
BAD_LINE="$(head -1 /tmp/acme.jsonl | sed 's/}$/,"tok":{"model":"m","b64":"AAAA"}}/')"
rest_code "garbage artifact 400" 400 -- -X POST "$API/vaults/acme2/import" \
  -H "X-Vault-Assertion: $(sign acme2)" --data-binary "$BAD_LINE"

# Semantic dedup-refresh: re-ingesting the same fact refreshes, not piles up.
rest_body "dedup first insert"  '"deduped":false' -- -X POST "$API/vaults/acme/drawers" \
  -H "X-Vault-Assertion: $(sign acme)" \
  -d '{"text":"the release train ships on thursday","wing":"eng","room":"process","dedup_threshold":0.9}'
rest_body "dedup refresh"       '"deduped":true'  -- -X POST "$API/vaults/acme/drawers" \
  -H "X-Vault-Assertion: $(sign acme)" \
  -d '{"text":"the release train ships on thursday","wing":"eng","room":"process","dedup_threshold":0.9}'

# External-embedding vault: dimension enforced exactly.
rest_body "create external"     '"created":true'  -- -X POST "$API/vaults" \
  -H "X-Vault-Assertion: $(sign ext)" -d '{"id":"ext","embedder":"external:acme-embed@4"}'
rest_body "external needs vector" 'requires'      -- -X POST "$API/vaults/ext/drawers" \
  -H "X-Vault-Assertion: $(sign ext)" -d '{"text":"customer prefers dark mode"}'
rest_body "external wrong dim"  'dimension'       -- -X POST "$API/vaults/ext/drawers" \
  -H "X-Vault-Assertion: $(sign ext)" -d '{"text":"customer prefers dark mode","vector":[0.1,0.2]}'
rest_body "external ok dim"     '"created":true'  -- -X POST "$API/vaults/ext/drawers" \
  -H "X-Vault-Assertion: $(sign ext)" -d '{"text":"customer prefers dark mode","vector":[1,0,0,0]}'

rest_body "delete vault"        '"deleted":true'  -- -X DELETE "$API/vaults/globex" \
  -H "X-Vault-Assertion: $(sign globex)"
rest_code "deleted vault gone 404" 404 -- "$API/vaults/globex/stats" \
  -H "X-Vault-Assertion: $(sign globex)"

# Vault listing is disabled under per-vault assertions (this server sets one).
rest_code "vault list 403 under assertions" 403 -- "$API/vaults"
# The Palace Monitor UI is telemetry-only; absent from this default build.
rest_code "/monitor 404 without telemetry" 404 -- "http://127.0.0.1:$PORT/monitor"

kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null

echo
echo "e2e results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "E2E OK"
