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
# It does NOT prove the whole observability stack starts: that needs the full
# engine image and four containers, and the cost argument for deferring it is
# in ROADMAP M7. This suite is the cheap half — no Rust build at all, three
# small images — and it is the half that would have caught the actual defect.
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

echo ""
echo "tls-pins results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "TLS-PINS OK"
