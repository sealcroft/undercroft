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
# file ALSO brings the whole deployment up and proves it boots — see the last
# section, which carries the cost (one telemetry engine build) and the reason
# the cheap half was never sufficient on its own.
set -u

PASS=0
FAIL=0
pass() { echo "ok    $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL  $1"; [ $# -gt 1 ] && echo "$2" | sed 's/^/      /'; FAIL=$((FAIL + 1)); }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

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
"

cleanup() {
  while IFS='|' read -r file term exporter vol path proj; do
    [ -z "${file:-}" ] && continue
    docker compose -p "$proj" -f "$file" down -v >/dev/null 2>&1 || true
  done <<EOF
$STACKS
EOF
  # The O63 section's own throwaway project. Guarded: `set -u` is on and this
  # trap can fire before the variable is assigned.
  if [ -n "${STACK_PROJ:-}" ] && [ -n "${STACK_FILE:-}" ]; then
    docker compose -p "$STACK_PROJ" -f "$STACK_FILE" down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

while IFS='|' read -r file term exporter vol path proj; do
  [ -z "${file:-}" ] && continue
  label="$(basename "$(dirname "$file")")/$term"

  # A clean slate: a leftover volume from a previous run could carry an
  # already-exported root and pass this suite without the exporter working.
  docker compose -p "$proj" -f "$file" down -v >/dev/null 2>&1 || true

  # `--no-deps`, and it is load-bearing. The terminator drags in services
  # that PUBLISH ports — `tempo` on 3200 for the observability stack —
  # which collide with an operator running that stack even under a private
  # project name, because a published port is a HOST resource the project
  # prefix does not scope. None of them is needed either: Caddy provisions
  # its internal CA at startup whether or not the upstream it proxies is
  # reachable, and that CA is the only thing this suite is about.
  if ! docker compose -p "$proj" -f "$file" up -d --no-deps "$term" >/dev/null 2>&1; then
    fail "$label: the terminator came up" \
         "$(docker compose -p "$proj" -f "$file" logs "$term" 2>&1 | tail -5)"
    continue
  fi
  if ! docker compose -p "$proj" -f "$file" up -d --no-deps "$exporter" >/dev/null 2>&1; then
    fail "$label: the exporter came up" \
         "$(docker compose -p "$proj" -f "$file" logs "$exporter" 2>&1 | tail -5)"
    continue
  fi

  # The exporter is a one-shot; wait for it to finish, bounded.
  i=0
  until [ "$(docker compose -p "$proj" -f "$file" ps -a --status exited -q "$exporter" | wc -l)" -gt 0 ]; do
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

# ─ the whole deployment starts (ROADMAP O63) ───────────────────────────────
#
# Everything above proves a PIN is readable. This proves the stack that
# depends on it actually boots — the half ROADMAP M7 deferred on cost, and
# which this file carried as its own stated gap until now.
#
# It is worth being precise about why the cheap half was not enough.
# `obs-config` validates the Prometheus and Alertmanager CONFIGS at their
# pinned versions and starts no container, and the readability section above
# reads a file out of a volume. A config can be flawless and a pin perfectly
# readable while the deployment still fails to come up — nothing here had ever
# executed `up` on this file, which is how a CA-path defect shipped for two
# releases with every gate green.
#
# PORTS are the one thing that makes the full stack awkward to test, and the
# awkwardness is the same fact the `--no-deps` comment above turns on: a
# PUBLISHED PORT IS A HOST RESOURCE THAT A PRIVATE PROJECT NAME DOES NOT
# SCOPE. This file publishes six (8765, 9090, 9093, 3100, 3200, 3000) and on
# an ordinary developer machine most are already taken — measured on the
# maintainer's, five of the six. So every mapping is rewritten to an EPHEMERAL
# host port and read back with `compose port`.
#
# It has to be `!override`, and that is not a detail. Compose MERGES
# list-valued keys, so an override that simply restates `ports:` APPENDS a
# second mapping and the original collision survives untouched — a fix that
# looks applied, reports nothing, and is not applied. Verified by running
# `compose config` on a two-file pair before relying on it.
STACK_PROJ="tlspins-stack"
STACK_FILE="deploy/observability/docker-compose.observability.yml"
STACK_OVERRIDE="$(mktemp -t obsports.XXXXXX.yml 2>/dev/null || echo "${TMPDIR:-/tmp}/obsports.$$.yml")"

cat > "$STACK_OVERRIDE" <<'YAML'
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

dc_stack() { docker compose -p "$STACK_PROJ" -f "$STACK_FILE" -f "$STACK_OVERRIDE" "$@"; }

# Registered with the trap below via STACK_PROJ; see cleanup().
dc_stack down -v >/dev/null 2>&1 || true

# PREMISE. If the file resolves to no services, every assertion below would
# pass over an empty stack — the failure mode this whole suite is about.
STACK_SERVICES="$(dc_stack config --services 2>/dev/null | sort)"
STACK_N="$(printf '%s\n' "$STACK_SERVICES" | grep -c . || true)"
if [ "${STACK_N:-0}" -lt 2 ]; then
  fail "observability: premise — the compose file resolves to services" \
       "got ${STACK_N:-0}; the override or the file failed to parse, so nothing was examined"
else
  pass "observability: compose resolves $STACK_N services"

  # The engine image is BUILT here (UNDERCROFT_FEATURES=telemetry). That build
  # is the entire cost of this section; everything after it is seconds.
  if ! dc_stack up -d >/dev/null 2>&1; then
    fail "observability: the stack came up" \
         "$(dc_stack logs --tail 20 2>&1 | tail -20)"
  else
    pass "observability: the stack came up"

    # `tls-export` is the one true one-shot: it copies the public root out of
    # Caddy's root-only tree and exits. Everything else carries `restart:`.
    i=0
    until [ -n "$(dc_stack ps -a --status exited -q tls-export 2>/dev/null)" ]; do
      i=$((i + 1))
      if [ "$i" -gt 90 ]; then break; fi
      sleep 1
    done
    tls_rc="$(docker inspect -f '{{.State.ExitCode}}' \
                "$(dc_stack ps -a -q tls-export 2>/dev/null | head -1)" 2>/dev/null || echo "")"
    if [ "${tls_rc:-1}" = "0" ]; then
      pass "observability: tls-export published the root and exited 0"
    else
      fail "observability: tls-export published the root and exited 0" \
           "exit=${tls_rc:-<none>}; $(dc_stack logs --tail 10 tls-export 2>&1 | tail -10)"
    fi

    # THE CHECK THIS SECTION EXISTS FOR. The engine refuses to start when its
    # declared trust root is unreadable, which is correct and is exactly what
    # shipped. A reachable /healthz is the difference between a stack that
    # boots and a config that merely validates.
    eport="$(dc_stack port undercroft 8765 2>/dev/null | sed 's/.*://')"
    if [ -z "${eport:-}" ]; then
      fail "observability: the engine published a port" "compose port returned nothing"
    else
      i=0; ok=""
      until [ -n "$ok" ]; do
        if curl -sf "http://127.0.0.1:$eport/healthz" >/dev/null 2>&1; then ok=1; break; fi
        i=$((i + 1))
        # BOUNDED. An unbounded poll for a container that will never become
        # healthy is a hang, not a wait.
        if [ "$i" -gt 90 ]; then break; fi
        sleep 1
      done
      if [ -n "$ok" ]; then
        pass "observability: the engine answers /healthz against its real pin"
      else
        fail "observability: the engine answers /healthz against its real pin" \
             "$(dc_stack logs --tail 20 undercroft 2>&1 | tail -20)"
      fi
    fi

    # A crash-looping collector is a stack that did not start, even though
    # `up -d` returned 0. One check names every service that is not running
    # rather than one check per service.
    notrunning=""
    for svc in $STACK_SERVICES; do
      [ "$svc" = "tls-export" ] && continue
      st="$(docker inspect -f '{{.State.Status}}' \
             "$(dc_stack ps -a -q "$svc" 2>/dev/null | head -1)" 2>/dev/null || echo missing)"
      [ "$st" = "running" ] || notrunning="$notrunning $svc($st)"
    done
    if [ -z "$notrunning" ]; then
      pass "observability: every long-running service is running"
    else
      fail "observability: every long-running service is running" "not running:$notrunning"
    fi

    # And the join: Prometheus actually SCRAPES the engine. This is the one
    # assertion that spans the whole deployment — it needs the engine up, its
    # bearer-gated /metrics reachable on the compose network, and the scrape
    # config correct. `scrape_interval` is 15s, so the wait is generous.
    pport="$(dc_stack port prometheus 9090 2>/dev/null | sed 's/.*://')"
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
fi
rm -f "$STACK_OVERRIDE" 2>/dev/null || true

echo ""
echo "tls-pins results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "TLS-PINS OK"
