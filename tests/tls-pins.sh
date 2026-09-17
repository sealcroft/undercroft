#!/usr/bin/env bash
# Every shipped CA pin is READABLE by the identity that pins it.
#
# ─ why this suite exists ───────────────────────────────────────────────────
#
# `deploy/observability` shipped unstartable for two releases. The engine
# pinned its OTLP trust root at a path inside Caddy's PKI tree; Caddy writes
# that tree as root — cert 0600 inside directories at 0700 — because it also
# holds the CA PRIVATE key. The engine image runs as `USER undercroft`
# (uid 10001), so the pin was unreadable and the engine REFUSED to start:
#
#   Error: the OTLP collector: the declared trust root
#   /tls/caddy/pki/authorities/local/root.crt could not be read:
#   Permission denied (os error 13)
#
# The refusal is correct — `undercroft-net` never falls back to the public
# roots, since a pin that silently un-pins is the failure mode it exists to
# prevent. The defect was the PATH, and the reason it survived is that
# **nothing in this repo ever brought a terminator up**. `obs-config`
# validates Prometheus and Alertmanager CONFIGS at their pinned versions and
# never starts a container; a config can be flawless for a stack that cannot
# boot.
#
# The same shape was latent in the embeddings recipe: published for
# "cli/bench", where `bench` builds the BUILDER stage (root, works) and `cli`
# builds the RUNTIME stage (uid 10001, does not). One recipe, working or
# failing by which service you picked.
#
# ─ what this checks, and what it deliberately does not ─────────────────────
#
# It starts the real Caddy terminators and the real exporters, then reads the
# published path AS UID 10001 — the engine's uid, taken from the Dockerfile
# rather than hardcoded here, so the two cannot drift apart. It also asserts
# the CA private key stayed unreadable, because "make it work" has an obvious
# wrong fix (chmod the tree) that this must never pass.
#
# The readability half needs no Rust build and three small images, and it is
# the half that would have caught the actual defect. Since ROADMAP O63 this
# file ALSO brings the whole observability deployment up and proves it boots,
# and since ROADMAP O172 it does the same for the team-server recipe — see the
# last two sections, which carry the cost (two engine builds, one with
# telemetry and one with the default features the recipe ships) and the
# reason the cheap half was never sufficient on its own.
#
# ─ a counterfactual hook, and why it can never read as a pass ──────────────
#
# TLSPINS_SERVER_EXTRA_COMPOSE names one more compose file, applied to the
# team-server boot only. It exists so a counterfactual runs THIS suite against
# a deliberately broken recipe, rather than a copy of the suite. A run with it
# set never prints `TLS-PINS OK` and always exits 3, so a counterfactual that
# failed to break anything cannot be mistaken for a green run.
set -u

PASS=0
FAIL=0
pass() { echo "ok    $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL  $1"; [ $# -gt 1 ] && echo "$2" | sed 's/^/      /'; FAIL=$((FAIL + 1)); }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

# ─ the team-server recipe's bearer (ROADMAP O172) ──────────────────────────
#
# `deploy/docker-compose.server.yml` declares
# `${UNDERCROFT_MCP_HTTP_TOKEN:?…}`, and Compose interpolates the whole file
# when it LOADS it, for `down` as much as for `up`. So the value has to exist
# before the first compose call on that file and before the EXIT trap below.
# Assigned later, the trap's teardown of that file would fail silently (its
# output is discarded) and leak the throwaway volumes.
#
# It is deliberately NOT exported. The observability file reads the same
# variable with a demo default, and its Prometheus scrape credential repeats
# that default verbatim, so an exported value would make the engine refuse
# the scrape and fail a check that has nothing to do with this recipe.
# `token_for` hands the token to the server file alone, and withholds the
# variable from every other file, which also keeps a developer's own exported
# token out of the observability stack.
SERVER_FILE="deploy/docker-compose.server.yml"
SERVER_TOKEN="tlspins-throwaway-bearer-$$-0123456789abcdef"
token_for() {
  if [ "$1" = "$SERVER_FILE" ]; then
    echo "UNDERCROFT_MCP_HTTP_TOKEN=$SERVER_TOKEN"
  else
    echo "-u UNDERCROFT_MCP_HTTP_TOKEN"
  fi
}
EXTRA_COMPOSE="${TLSPINS_SERVER_EXTRA_COMPOSE:-}"
if [ -n "$EXTRA_COMPOSE" ]; then
  echo "COUNTERFACTUAL RUN: the team-server boot also applies $EXTRA_COMPOSE"
  echo "                    this run is not a verdict and exits 3"
fi

# The engine's uid, READ from the Dockerfile. Hardcoding 10001 here would let
# a future `useradd --uid` change pass this suite while breaking every pin.
ENGINE_UID="$(grep -oE 'useradd[^&]*--uid[[:space:]]+[0-9]+' Dockerfile | grep -oE '[0-9]+$' | head -1)"
if [ -z "${ENGINE_UID:-}" ]; then
  fail "could not read the engine uid from Dockerfile" \
       "this suite cannot check readability without knowing who reads"
  echo ""
  echo "tls-pins results: $PASS passed, $FAIL failed"
  exit 1
fi
pass "engine uid read from Dockerfile: $ENGINE_UID"

# **Each stack runs under its OWN throwaway compose project**, and that is not
# tidiness — the first version of this suite ran `down -v` against the REAL
# projects, so a battery run destroyed a developer's live observability stack,
# its Grafana state and its mined corpus. It did exactly that once, which is
# how this comment came to exist.
#
# A private project also makes the suite hermetic: fresh volumes every run, so
# a leftover exported root from a previous run cannot make it pass vacuously.
#
# <compose file>|<terminator>|<exporter>|<volume>|<published path>|<project>
STACKS="
docker-compose.yml|embeddings-tls|embed-tls-export|undercroft-embed-tls|/tls/root.crt|tlspins-embed
deploy/observability/docker-compose.observability.yml|tempo-tls|tls-export|tempo-tls-data|/tls/root.crt|tlspins-obs
deploy/docker-compose.server.yml|qdrant-tls|qdrant-tls-export|qdrant-tls-data|/tls/root.crt|tlspins-qdrant
"

# The boot sections' throwaway projects, `<project>|<file>` separated by
# spaces, each added before its stack is first touched. Every teardown below
# is written as a literal `docker compose -p …` line on purpose: the
# `destructive compose scope` preflight reads this file for exactly that
# shape, and a wrapper function would hide a teardown from it.
BOOTED=""

cleanup() {
  while IFS='|' read -r file term exporter vol path proj; do
    [ -z "${file:-}" ] && continue
    # `$(token_for …)` is unquoted on purpose: its words are `env` arguments.
    env $(token_for "$file") docker compose -p "$proj" -f "$file" down -v >/dev/null 2>&1 || true
  done <<EOF
$STACKS
EOF
  # Guarded by the default: `set -u` is on and this trap can fire before the
  # list gains an entry.
  for booted in ${BOOTED:-}; do
    env $(token_for "${booted#*|}") docker compose -p "${booted%%|*}" -f "${booted#*|}" down -v >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

while IFS='|' read -r file term exporter vol path proj; do
  [ -z "${file:-}" ] && continue
  label="$(basename "$(dirname "$file")")/$term"

  # A clean slate: a leftover volume from a previous run could carry an
  # already-exported root and pass this suite without the exporter working.
  env $(token_for "$file") docker compose -p "$proj" -f "$file" down -v >/dev/null 2>&1 || true

  # `--no-deps`, and it is load-bearing. The terminator drags in services
  # that PUBLISH ports — `tempo` on 3200 for the observability stack —
  # which collide with an operator running that stack even under a private
  # project name, because a published port is a HOST resource the project
  # prefix does not scope. None of them is needed either: Caddy provisions
  # its internal CA at startup whether or not the upstream it proxies is
  # reachable, and that CA is the only thing this suite is about.
  if ! env $(token_for "$file") docker compose -p "$proj" -f "$file" up -d --no-deps "$term" >/dev/null 2>&1; then
    fail "$label: the terminator came up" \
         "$(env $(token_for "$file") docker compose -p "$proj" -f "$file" logs "$term" 2>&1 | tail -5)"
    continue
  fi
  if ! env $(token_for "$file") docker compose -p "$proj" -f "$file" up -d --no-deps "$exporter" >/dev/null 2>&1; then
    fail "$label: the exporter came up" \
         "$(env $(token_for "$file") docker compose -p "$proj" -f "$file" logs "$exporter" 2>&1 | tail -5)"
    continue
  fi

  # The exporter is a one-shot; wait for it to finish, bounded.
  i=0
  until [ "$(env $(token_for "$file") docker compose -p "$proj" -f "$file" ps -a --status exited -q "$exporter" | wc -l)" -gt 0 ]; do
    i=$((i + 1))
    if [ "$i" -gt 90 ]; then
      fail "$label: the exporter finished" "still running after 90s"
      break
    fi
    sleep 1
  done

  # The project prefix names the volume on the host, and here it is the
  # THROWAWAY project above rather than the file's own `name:` — which is
  # precisely what keeps this suite off the operator's real volumes.
  full="${proj}_${vol}"

  # PREMISE. If the volume has no PKI at all, every readability assertion
  # below would pass on an empty mount — the exact failure this file is about.
  if ! docker run --rm -v "$full":/tls alpine:3.20 \
        sh -c 'test -s /tls/caddy/pki/authorities/local/root.crt' >/dev/null 2>&1; then
    fail "$label: premise — Caddy generated a CA on $full" \
         "no root.crt in the PKI tree; this suite examined nothing"
    continue
  fi
  pass "$label: Caddy generated its CA"

  # THE CHECK. Read the published pin as the engine's uid.
  if docker run --rm --user "$ENGINE_UID:$ENGINE_UID" -v "$full":/tls:ro alpine:3.20 \
       sh -c "test -r '$path' && head -c 27 '$path' | grep -q 'BEGIN CERTIFICATE'" >/dev/null 2>&1; then
    pass "$label: uid $ENGINE_UID can read the pin at $path"
  else
    fail "$label: uid $ENGINE_UID can read the pin at $path" \
         "$(docker run --rm -v "$full":/tls:ro alpine:3.20 sh -c "ls -ln '$path' 2>&1; ls -ldn /tls/caddy/pki 2>&1")"
  fi

  # AND the obvious wrong fix must still be wrong: exporting the certificate
  # must not have opened up the CA private key.
  if docker run --rm --user "$ENGINE_UID:$ENGINE_UID" -v "$full":/tls:ro alpine:3.20 \
       sh -c 'test -r /tls/caddy/pki/authorities/local/root.key' >/dev/null 2>&1; then
    fail "$label: the CA PRIVATE key is readable by uid $ENGINE_UID" \
         "exporting the certificate must not chmod the tree that holds the key"
  else
    pass "$label: the CA private key stays unreadable"
  fi
done <<EOF
$STACKS
EOF

# ─ a whole deployment starts (ROADMAP O63, O172) ───────────────────────────
#
# Everything above proves a PIN is readable. The rest proves the stacks that
# depend on one actually boot — the half ROADMAP M7 deferred on cost.
#
# It is worth being precise about why the cheap half was not enough.
# `obs-config` validates the Prometheus and Alertmanager CONFIGS at their
# pinned versions and starts no container, and the readability section above
# reads a file out of a volume. A config can be flawless and a pin perfectly
# readable while the deployment still fails to come up — nothing here had ever
# executed `up` on the observability file, which is how a CA-path defect
# shipped for two releases with every gate green. The team-server recipe was
# worse: no file under tests/ referenced it, and it could not start at all.
#
# PORTS are the one thing that makes a full stack awkward to test, and the
# awkwardness is the same fact the `--no-deps` comment above turns on: a
# PUBLISHED PORT IS A HOST RESOURCE THAT A PRIVATE PROJECT NAME DOES NOT
# SCOPE. The observability file publishes six (8765, 9090, 9093, 3100, 3200,
# 3000) and on an ordinary developer machine most are already taken —
# measured on the maintainer's, five of the six. So every mapping is rewritten
# to an EPHEMERAL host port and read back with `compose port`.
#
# It has to be `!override`, and that is not a detail. Compose MERGES
# list-valued keys, so an override that simply restates `ports:` APPENDS a
# second mapping and the original collision survives untouched — a fix that
# looks applied, reports nothing, and is not applied. Verified by running
# `compose config` on a two-file pair before relying on it.

# The stack a boot is about. `boot_stack` sets them; `dc_boot` reads them.
BOOT_LABEL=""
BOOT_PROJ=""
BOOT_FILE=""
BOOT_OVERRIDE=""
BOOT_EXTRA=""
BOOT_UP=""
BOOT_PORT=""

dc_boot() {
  local extra=()
  [ -n "$BOOT_EXTRA" ] && extra=(-f "$BOOT_EXTRA")
  # `$(token_for …)` is unquoted on purpose: its words are `env` arguments.
  env $(token_for "$BOOT_FILE") docker compose -p "$BOOT_PROJ" -f "$BOOT_FILE" \
    -f "$BOOT_OVERRIDE" ${extra[@]+"${extra[@]}"} "$@"
}

# boot_stack <label> <project> <file> <override> <exporter> <extra file>
#
# Brings one stack up and runs the five checks every engine stack owes: the
# file resolves to services, `up` succeeds, the exporter published the root,
# the engine answers /healthz against its real pin, and every long-running
# service is running. Sets BOOT_UP when the stack came up and BOOT_PORT to the
# engine's ephemeral host port. The observability labels are the ones O63
# shipped, byte for byte, so a log from before this function reads the same.
boot_stack() {
  BOOT_LABEL="$1"; BOOT_PROJ="$2"; BOOT_FILE="$3"; BOOT_OVERRIDE="$4"
  local exporter="$5"
  BOOT_EXTRA="$6"
  BOOT_UP=""; BOOT_PORT=""
  BOOTED="$BOOTED $BOOT_PROJ|$BOOT_FILE"

  # A clean slate, written out literally for the teardown-scope preflight.
  env $(token_for "$BOOT_FILE") docker compose -p "$BOOT_PROJ" -f "$BOOT_FILE" down -v >/dev/null 2>&1 || true

  # PREMISE. If the file resolves to no services, every assertion below would
  # pass over an empty stack — the failure mode this whole suite is about.
  local services n
  services="$(dc_boot config --services 2>/dev/null | sort)"
  n="$(printf '%s\n' "$services" | grep -c . || true)"
  if [ "${n:-0}" -lt 2 ]; then
    fail "$BOOT_LABEL: premise — the compose file resolves to services" \
         "got ${n:-0}; the override or the file failed to parse, so nothing was examined"
    return
  fi
  pass "$BOOT_LABEL: compose resolves $n services"

  # The engine image is BUILT here. That build is the entire cost of a boot;
  # everything after it is seconds.
  if ! dc_boot up -d >/dev/null 2>&1; then
    fail "$BOOT_LABEL: the stack came up" \
         "$(dc_boot logs --tail 20 2>&1 | tail -20)"
    return
  fi
  pass "$BOOT_LABEL: the stack came up"
  BOOT_UP=1

  # The exporter is the one true one-shot: it copies the public root out of
  # Caddy's root-only tree and exits. Everything else carries `restart:`.
  local i=0 rc
  until [ -n "$(dc_boot ps -a --status exited -q "$exporter" 2>/dev/null)" ]; do
    i=$((i + 1))
    if [ "$i" -gt 90 ]; then break; fi
    sleep 1
  done
  rc="$(docker inspect -f '{{.State.ExitCode}}' \
          "$(dc_boot ps -a -q "$exporter" 2>/dev/null | head -1)" 2>/dev/null || echo "")"
  if [ "${rc:-1}" = "0" ]; then
    pass "$BOOT_LABEL: $exporter published the root and exited 0"
  else
    fail "$BOOT_LABEL: $exporter published the root and exited 0" \
         "exit=${rc:-<none>}; $(dc_boot logs --tail 10 "$exporter" 2>&1 | tail -10)"
  fi

  # The engine refuses to start when its declared trust root is unreadable,
  # which is correct and is exactly what shipped. A reachable /healthz is the
  # difference between a stack that boots and a config that merely validates.
  BOOT_PORT="$(dc_boot port undercroft 8765 2>/dev/null | sed 's/.*://')"
  if [ -z "${BOOT_PORT:-}" ]; then
    # A container that exits and restarts publishes no port, so this is also
    # how a crash-looping engine shows up. Its log says why.
    fail "$BOOT_LABEL: the engine published a port" \
         "compose port returned nothing; the engine's log:
$(dc_boot logs --tail 10 undercroft 2>&1 | tail -10)"
  else
    local ok=""
    i=0
    until [ -n "$ok" ]; do
      if curl -sf "http://127.0.0.1:$BOOT_PORT/healthz" >/dev/null 2>&1; then ok=1; break; fi
      i=$((i + 1))
      # BOUNDED. An unbounded poll for a container that will never become
      # healthy is a hang, not a wait.
      if [ "$i" -gt 90 ]; then break; fi
      sleep 1
    done
    if [ -n "$ok" ]; then
      pass "$BOOT_LABEL: the engine answers /healthz against its real pin"
    else
      fail "$BOOT_LABEL: the engine answers /healthz against its real pin" \
           "$(dc_boot logs --tail 20 undercroft 2>&1 | tail -20)"
    fi
  fi

  # A crash-looping service is a stack that did not start, even though `up -d`
  # returned 0. One check names every service that is not running rather than
  # one check per service.
  local notrunning="" svc st
  for svc in $services; do
    [ "$svc" = "$exporter" ] && continue
    st="$(docker inspect -f '{{.State.Status}}' \
           "$(dc_boot ps -a -q "$svc" 2>/dev/null | head -1)" 2>/dev/null || echo missing)"
    [ "$st" = "running" ] || notrunning="$notrunning $svc($st)"
  done
  if [ -z "$notrunning" ]; then
    pass "$BOOT_LABEL: every long-running service is running"
  else
    fail "$BOOT_LABEL: every long-running service is running" "not running:$notrunning"
  fi
}

OVERRIDES="$(mktemp -d 2>/dev/null || { mkdir -p "${TMPDIR:-/tmp}/tlspins.$$" && echo "${TMPDIR:-/tmp}/tlspins.$$"; })"

# ─ the observability deployment (ROADMAP O63) ──────────────────────────────
cat > "$OVERRIDES/obs-ports.yml" <<'YAML'
services:
  undercroft:
    ports: !override ["0:8765"]
  prometheus:
    ports: !override ["0:9090"]
  alertmanager:
    ports: !override ["0:9093"]
  loki:
    ports: !override ["0:3100"]
  tempo:
    ports: !override ["0:3200"]
  grafana:
    ports: !override ["0:3000"]
YAML

# The observability engine is built with `UNDERCROFT_FEATURES=telemetry`.
boot_stack "observability" "tlspins-stack" \
  "deploy/observability/docker-compose.observability.yml" \
  "$OVERRIDES/obs-ports.yml" "tls-export" ""

if [ -n "$BOOT_UP" ]; then
  # And the join: Prometheus actually SCRAPES the engine. This is the one
  # assertion that spans the whole deployment — it needs the engine up, its
  # bearer-gated /metrics reachable on the compose network, and the scrape
  # config correct. `scrape_interval` is 15s, so the wait is generous.
  pport="$(dc_boot port prometheus 9090 2>/dev/null | sed 's/.*://')"
  if [ -z "${pport:-}" ]; then
    fail "observability: prometheus published a port" "compose port returned nothing"
  else
    i=0; up=""
    until [ -n "$up" ]; do
      if curl -sf "http://127.0.0.1:$pport/api/v1/targets?state=active" 2>/dev/null \
           | tr ',' '\n' | grep -q '"health":"up"'; then up=1; break; fi
      i=$((i + 1))
      if [ "$i" -gt 120 ]; then break; fi
      sleep 1
    done
    if [ -n "$up" ]; then
      pass "observability: prometheus reports a healthy scrape target"
    else
      fail "observability: prometheus reports a healthy scrape target" \
           "$(curl -s "http://127.0.0.1:$pport/api/v1/targets?state=active" 2>&1 | head -c 400)"
    fi
  fi
fi
# The stack is torn down now rather than at exit, so the team-server boot
# below does not run beside eleven idle services.
env $(token_for "$BOOT_FILE") docker compose -p "$BOOT_PROJ" -f "$BOOT_FILE" down -v >/dev/null 2>&1 || true

# ─ the team-server recipe (ROADMAP O172) ───────────────────────────────────
#
# The recipe could not start: it served with no `init`, so a fresh volume
# exited `vault "default" not found` and `restart:` looped. Its Qdrant URL was
# cleartext beyond loopback, which the index client refuses at construction.
#
# **A boot check alone cannot see the second defect.** `serve-http` builds no
# index at start. The URL is read only when an index call is made, and the
# resolved pin is cached, a refusal included, for the life of the process. So
# /healthz answers 200 with the cleartext URL or an unreadable pin in place,
# and this section drives the index path THROUGH the running server: the /v1
# status route, and the CLI inside the engine container, which reads the same
# environment the server does. The engine here is built with the DEFAULT
# features, because that is what the recipe ships.
cat > "$OVERRIDES/server-ports.yml" <<'YAML'
services:
  undercroft:
    ports: !override ["0:8765"]
YAML

boot_stack "team-server" "tlspins-server" "$SERVER_FILE" \
  "$OVERRIDES/server-ports.yml" "qdrant-tls-export" "$EXTRA_COMPOSE"

# srv_exec <args…> runs the CLI inside the engine container. `-T` because this
# suite has no TTY, and `exec` rather than `run` because the point is the
# environment the running server was started with.
srv_exec() { dc_boot exec -T undercroft undercroft "$@"; }

# srv_v1 <method> <path> [json body] prints the body, then the status code on
# a line of its own.
srv_v1() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -s -w '\n%{http_code}' -X "$method" \
      -H "Authorization: Bearer $SERVER_TOKEN" -H 'content-type: application/json' \
      -d "$body" "http://127.0.0.1:$BOOT_PORT$path" 2>&1
  else
    curl -s -w '\n%{http_code}' -X "$method" \
      -H "Authorization: Bearer $SERVER_TOKEN" \
      "http://127.0.0.1:$BOOT_PORT$path" 2>&1
  fi
}

# The two /v1 calls the arms make. Each succeeds only on a 200 and prints the
# body either way, so a failing arm shows what came back.
srv_v1_status() {
  local reply
  reply="$(srv_v1 GET "/v1/vaults/default/index/status?backend=qdrant")"
  printf '%s\n' "${reply%$'\n'*}"
  [ "${reply##*$'\n'}" = "200" ]
}
srv_v1_save() {
  local reply
  reply="$(srv_v1 POST /v1/vaults/default/drawers \
             "{\"text\":\"$CANARY\",\"wing\":\"tlspins\",\"room\":\"canary\"}")"
  printf '%s\n' "${reply%$'\n'*}"
  [ "${reply##*$'\n'}" = "200" ]
}

# One arm, one check, whatever happened: a command's exit code and a pattern
# its output must contain. Captured WITHOUT a pipe, because a pipeline's
# status is its last command's.
# expect <label> <want exit> <pattern> -- <command…>
expect() {
  local label="$1" want="$2" pat="$3"; shift 4
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" = "$want" ] && printf '%s\n' "$out" | grep -qE -- "$pat"; then
    pass "team-server: $label"
  else
    fail "team-server: $label" "exit=$rc (wanted $want), wanted /$pat/; got:
$(printf '%s\n' "$out" | tail -8)"
  fi
}

if [ -n "$BOOT_UP" ] && [ -n "$BOOT_PORT" ]; then
  CANARY="mirror canary: the team server reaches qdrant through its terminator"

  expect "config check passes on the recipe's own environment" 0 \
    '^0 would REFUSE to start' \
    -- srv_exec config check

  expect "/v1 index status reaches qdrant, and no mirror exists yet" 0 \
    '"remote_records": ?null' \
    -- srv_v1_status

  expect "a canary drawer lands through /v1 and is not quarantined" 0 \
    '"quarantined": ?false' \
    -- srv_v1_save

  expect "index push mirrors the vault to qdrant, sealed" 0 \
    'Pushed 1 sealed record\(s\)' \
    -- srv_exec index push qdrant

  expect "index status counts the pushed record" 0 \
    'records: +1$' \
    -- srv_exec index status qdrant

  expect "/v1 index status reports the mirror beside the local count" 0 \
    '"local_records": ?1,.*"remote_records": ?1|"remote_records": ?1,.*"local_records": ?1' \
    -- srv_v1_status

  expect "a search through the qdrant mirror returns the canary" 0 \
    'reaches qdrant through its terminator' \
    -- srv_exec search "mirror canary" --backend qdrant

  expect "the vault verifies after a push beside the live server" 0 \
    'VERIFY OK' \
    -- srv_exec verify

  # PREMISE. The arms above pass only if the index client really refuses
  # cleartext; this is the same call with the URL the recipe used to declare.
  expect "premise: the cleartext URL the recipe used to declare is refused" 1 \
    'no override' \
    -- dc_boot exec -T -e UNDERCROFT_QDRANT_URL=http://qdrant:6333 undercroft \
       undercroft index status qdrant

  # A passphrase in the operator's env file reaches the engine. The recipe
  # read only the variables it names, and it did not name this one, so a
  # declared passphrase was dropped and the first start wrote a random
  # master.key to the volume instead. The declaration has no value in the
  # recipe, so when it is NOT declared the variable stays unset, and the boot
  # above is the proof: an empty passphrase refuses to start.
  printf 'UNDERCROFT_PASSPHRASE=tlspins-passphrase-probe\n' > "$OVERRIDES/passphrase.env"
  expect "a passphrase declared in the env file reaches the engine" 0 \
    'UNDERCROFT_PASSPHRASE: tlspins-passphrase-probe' \
    -- dc_boot --env-file "$OVERRIDES/passphrase.env" config
fi
rm -rf "$OVERRIDES" 2>/dev/null || true

echo ""
echo "tls-pins results: $PASS passed, $FAIL failed"
if [ -n "$EXTRA_COMPOSE" ]; then
  echo "COUNTERFACTUAL RUN — not a verdict (applied $EXTRA_COMPOSE)"
  exit 3
fi
[ "$FAIL" -eq 0 ] || exit 1
echo "TLS-PINS OK"
