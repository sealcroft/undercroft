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

probe_http_200() { # probe_http_200 <url> <path> — up only when <path> answers 200
  local url="$1" path="$2" host port
  host="$(sed -E 's|https?://([^:/]+).*|\1|' <<<"$url")"
  port="$(sed -E 's|https?://[^:/]+:([0-9]+).*|\1|' <<<"$url")"
  exec 3<>"/dev/tcp/$host/$port" || return 1
  printf 'GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' "$path" "$host" >&3
  head -1 <&3 | grep -q " 200 "; local rc=$?
  exec 3<&- 3>&-
  return $rc
}

# ---- TLS: the suite runs over the shipped terminators -------------------
#
# The engine refuses cleartext http to a non-loopback host with no override
# (ROADMAP C8) — a push carries embeddings, and an embedding is
# plaintext-derived. So this suite reaches every backend over TLS: the four
# HTTP ones through the `backends-tls` Caddy, pgvector through TLS in the
# server itself. Two authorities, ONE pinned file: a declared CA replaces
# the public roots, and the PEM reader takes every certificate in the file.
echo "== TLS trust =="
: > "$UNDERCROFT_INDEX_CA"
CADDY_ROOT=/tls/caddy/pki/authorities/local/root.crt
for _ in $(seq 1 60); do [ -s "$CADDY_ROOT" ] && break; sleep 2; done
if [ -s "$CADDY_ROOT" ] && [ -s /pgtls/ca.crt ]; then
  cat "$CADDY_ROOT" /pgtls/ca.crt > "$UNDERCROFT_INDEX_CA"
  echo "ok    pinned both roots into $UNDERCROFT_INDEX_CA"; PASS=$((PASS+1))
else
  echo "FAIL  the terminator roots are not on the mounted volumes"
  ls -l "$CADDY_ROOT" /pgtls/ca.crt 2>&1 | sed 's/^/      /'; FAIL=$((FAIL+1))
fi

echo "== Service readiness =="
# Probe the BACKENDS directly (plain HTTP, container-internal): readiness is
# about the service being up, and the terminator in front of it is proved
# by the suite below actually pushing through it.
wait_for "qdrant"   probe_http "http://qdrant:6333"
wait_for "chroma"   probe_http "http://chroma:8000"
wait_for "pgvector" probe_pg
wait_for "milvus"   probe_http "http://milvus:9091"
# Weaviate answers plain HTTP before its Raft leader is elected — schema
# writes 422 "leader not found" until then (flaked CI + local runs). Gate
# on the schema endpoint actually serving 200: the exact surface the
# suite writes to first.
wait_for "weaviate" probe_http_200 "http://weaviate:8080" /v1/schema
# Caddy serves only the https:// site blocks here, so probe the TLS port
# at the TCP level rather than asking for an HTTP response on 80.
probe_tls() { exec 3<>"/dev/tcp/backends-tls/443" || return 1; exec 3<&- 3>&-; return 0; }
wait_for "backends-tls" probe_tls

run_backend_suite() { # run_backend_suite <backend>
  local be="$1"
  echo "== Backend: $be =="
  export UNDERCROFT_HOME="$(mktemp -d)"
  check "[$be] init"            0 "Palace initialized"  -- "$BIN" init
  check "[$be] remember 1"      0 "Filed drawer"        -- "$BIN" remember \
    "The rollout plan targets canary users first, then 10 percent daily" --wing ops --room rollout
  check "[$be] remember 2"      0 "Filed drawer"        -- "$BIN" remember \
    "Sourdough needs a 12 hour cold proof for open crumb" --wing kitchen
  # ROADMAP O83, proven PER BACKEND rather than inferred from qdrant: a
  # status call on a vault nothing has pushed must report NO MIRROR, and must
  # not create one. **The SECOND call is what proves the non-creation** —
  # before O83 this ran `ensure` first, so the first call CREATED the
  # collection and then reported `records:    0`, and "there is no mirror"
  # was unsayable on every backend.
  #
  # A fresh, uniquely-named vault deliberately: these backends are shared
  # containers that outlive a suite run, so asking about `default` would
  # depend on whether a previous run left a collection behind.
  local probe="o83${be}$$"
  check "[$be] probe vault"        0 "Created vault"  -- "$BIN" vault create "$probe" --level sealed
  check "[$be] absent is not zero" 0 "no mirror"      -- "$BIN" index status "$be" --vault "$probe"
  check "[$be] status creates none" 0 "no mirror"     -- "$BIN" index status "$be" --vault "$probe"
  check "[$be] push"            0 "Pushed 2 sealed record(s)" -- "$BIN" index push "$be"
  # C8: the transport policy is enforced at CONSTRUCTION, so pointing the
  # same backend at cleartext beyond loopback refuses before a byte moves.
  # Run per backend rather than once, because each one builds its own
  # client and the check has to be in all of them.
  check "[$be] refuses cleartext" 1 "no override" -- env     UNDERCROFT_QDRANT_URL=http://qdrant:6333     UNDERCROFT_CHROMA_URL=http://chroma:8000     UNDERCROFT_MILVUS_URL=http://milvus:19530     UNDERCROFT_WEAVIATE_URL=http://weaviate:8080     UNDERCROFT_PGVECTOR_DSN=postgresql://undercroft:undercroft@pgvector:5432/undercroft     "$BIN" index push "$be"
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

echo "== Transport policy (C8) =="
# An hmac-only vault's at-rest content IS the plaintext, so pushing it is a
# decision the operator has to state. Premise first: the same vault pushes
# once told to, and says PLAINTEXT rather than "sealed".
export UNDERCROFT_HOME="$(mktemp -d)"
"$BIN" init --level hmac-only >/dev/null
"$BIN" remember "the kelp harvest quota is confidential" >/dev/null
check "hmac-only push refused"     1 "PLAINTEXT" -- "$BIN" index push qdrant
check "hmac-only push when told"   0 "PLAINTEXT record(s)" -- "$BIN" index push qdrant --allow-plaintext
# A declared CA that pins nothing refuses rather than falling back to the
# public roots — the same rule the embedder's CA pin follows.
: > /tmp/empty-ca.pem
check "empty CA pin refuses" 1 "pins nothing" -- env UNDERCROFT_INDEX_CA=/tmp/empty-ca.pem   "$BIN" index status qdrant

echo "== Misconfiguration UX =="
unset UNDERCROFT_QDRANT_URL
check "unconfigured backend errors" 1 "UNDERCROFT_QDRANT_URL" -- "$BIN" search "x" --backend qdrant
check "unknown backend errors"      1 "unknown backend"      -- "$BIN" search "x" --backend faiss

echo
echo "backends-e2e results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "BACKENDS E2E OK"
