#!/usr/bin/env bash
# The house page publishes figures about THIS engine, from a repository this
# one cannot reach (ROADMAP O65). `sealcroft/sealcroft.github.io` has no CI,
# nothing in this tree reads it, and the `published figures` preflight matches
# `data-count="N"` markup that page does not use — so porting the gate is not
# a copy.
#
# Round four filed the drift (656 tests against a tree running 689). It went
# unfixed for eleven days and widened to 765. Its sibling — the house serving
# cleartext — went the same way and is what ROADMAP O37 calls "the most severe
# process failure". A figure nobody can check is a figure that rots.
#
# **This check needs the INTERNET, which no other suite in this tree does.**
# That is why it is its own script rather than a `tests/battery.sh` preflight:
# the preflights run on every local battery, and a network-dependent arm there
# would fail for anyone working offline. It runs in CI, where the network is a
# given. See the premise rule below for what it does when it cannot reach the
# page — it does NOT pass.
#
# **`--update` writes.** Everything above describes the CHECK, which is what
# CI runs and which touches nothing. `--update` is the operator half: it
# patches the tiles that moved and pushes to the house repository, using the
# CALLER's `gh` auth. It is deliberately never run by CI — a gate that can
# rewrite the thing it measures cannot fail, and CI holding a write
# credential for a second repository is a much larger blast radius than a
# stale number. The check runs everywhere; the write runs when a person asks.
set -u

UPDATE=0
[ "${1:-}" = "--update" ] && UPDATE=1
HOUSE_REPO="${HOUSE_REPO:-sealcroft/sealcroft.github.io}"

PAGE="${HOUSE_PAGE_URL:-https://sealcroft.com/}"
PASS=0
FAIL=0
pass() { printf 'ok    %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL  %s\n' "$1"; [ $# -gt 1 ] && printf '      %s\n' "$2"; FAIL=$((FAIL + 1)); }

cd "$(dirname "$0")/.." || exit 1

# ---- the truth side, from the tree ------------------------------------------
# Both are read the way the tree's own gates read them, never from prose.
TRUE_MCP=$(awk '/pub const MCP_TOOLS/,/^\];/' crates/undercroft-cli/src/parity.rs \
           | grep -cE '^\s*"undercroft_[a-z_]+",' || true)
# The cargo test count as CLAUDE.md publishes it, which `tests/battery.sh`
# already compares against a real run — so this reads the published figure
# rather than re-deriving it, and the battery is what keeps that honest.
TRUE_TESTS=$(grep -oE 'cargo unit \+ integration tests \([0-9]+ run' CLAUDE.md \
             | grep -oE '[0-9]+' | head -1)

if [ -z "${TRUE_TESTS:-}" ] || [ "${TRUE_MCP:-0}" -lt 10 ]; then
  echo "FAIL  a truth-side reader came back empty: tests='${TRUE_TESTS:-}' mcp='${TRUE_MCP:-}'"
  echo "      A reader that examined nothing agrees with any page."
  echo ""
  echo "HOUSE FIGURES FAILED — premise"
  exit 1
fi

# ---- the page side ----------------------------------------------------------
BODY=$(curl -sS --max-time 30 "$PAGE" 2>/dev/null)
CURL_RC=$?

# PREMISE, and it is the whole reason this file is careful. An unreachable
# page and a correct page must NOT produce the same verdict — that is the
# "a checker that cannot run reports the same thing as a clean tree" trap this
# project has hit repeatedly. Unreachable is a FAILURE, not a skip.
if [ "$CURL_RC" -ne 0 ] || [ -z "$BODY" ]; then
  echo "FAIL  could not fetch $PAGE (curl exit $CURL_RC)"
  echo "      This is a failure, not a skip: an unreachable page and an"
  echo "      accurate one must never produce the same verdict."
  echo ""
  echo "HOUSE FIGURES FAILED — premise"
  exit 1
fi

# Match the ELEMENT and normalise, never the rendered value string. The page
# splits `99.4` from its `%` across a nested <span>, so a literal `99.4%`
# search returns zero ON THE PAGE THAT PUBLISHES IT — which is exactly how a
# 2026-08-20 verification concluded the figure had been removed. Strip tags
# from the value, then read the label that follows.
tile() { # tile <label>  -> the numeric value published under that label
  printf '%s' "$BODY" \
    | grep -oE '<div class="n[^"]*">.*?</div><div class="l">[^<]+' \
    | sed -E 's/<div class="n[^"]*">//; s#</div><div class="l">#\t#' \
    | sed -E 's/<[^>]*>//g' \
    | awk -F'\t' -v want="$1" '$2 ~ want { gsub(/[^0-9.]/,"",$1); print $1; exit }'
}

TILE_COUNT=$(printf '%s' "$BODY" | grep -cE '<div class="n[^"]*">' || true)
if [ "${TILE_COUNT:-0}" -lt 1 ]; then
  echo "FAIL  no <div class=\"n\"> tiles found on $PAGE"
  echo "      The markup moved. This reader examined nothing, which is not"
  echo "      the same as a page carrying no figures."
  echo ""
  echo "HOUSE FIGURES FAILED — premise"
  exit 1
fi

echo "== House page figures ($PAGE) =="
echo "   tiles found: $TILE_COUNT"

GOT_TESTS=$(tile 'tests passing')
GOT_MCP=$(tile 'MCP tools')

if [ -z "$GOT_TESTS" ]; then
  fail "no 'tests passing' tile" "the label moved; a missing tile is not a passing one"
elif [ "$GOT_TESTS" = "$TRUE_TESTS" ]; then
  pass "tests passing: $GOT_TESTS matches the tree"
else
  fail "tests passing: the house publishes $GOT_TESTS, the tree runs $TRUE_TESTS"
fi

if [ -z "$GOT_MCP" ]; then
  fail "no 'MCP tools' tile" "the label moved; a missing tile is not a passing one"
elif [ "$GOT_MCP" = "$TRUE_MCP" ]; then
  pass "MCP tools: $GOT_MCP matches MCP_TOOLS"
else
  fail "MCP tools: the house publishes $GOT_MCP, MCP_TOOLS holds $TRUE_MCP"
fi

# A published BENCHMARK figure names its configuration. Every in-repo surface
# already does — the landing page renders "95.0% (hash, zero model)" and labels
# its MiniLM bar — and the house page was the only surface publishing one
# without. 99.4 is the +MiniLM column; the shipped zero-model default measures
# 95.0. This arm does not police WHICH number is published, only that the tile
# says which configuration produced it: an unqualified benchmark headline is
# the half of round-four #42 that a value fix does not close.
BENCH_LABEL=$(printf '%s' "$BODY" \
  | grep -oE '<div class="l">[^<]*LongMemEval[^<]*' | sed 's/<div class="l">//' | head -1)
if [ -z "$BENCH_LABEL" ]; then
  pass "no benchmark tile to qualify"
elif printf '%s' "$BENCH_LABEL" | grep -qiE 'hash|minilm|zero model'; then
  pass "benchmark tile names its configuration: $BENCH_LABEL"
else
  fail "benchmark tile is unqualified: '$BENCH_LABEL'" \
       "99.4 is the +MiniLM column; the shipped default measures 95.0"
fi

# **The VERSION claims, which the original filing never asked about.** O65 was
# scoped to "figures", so it found figures: the test count and the benchmark
# headline. The same page also announces a RELEASE in two places, and both had
# been two releases stale since 1.1.0 shipped — "Undercroft 1.0 is out" and
# "Shipping · v1.0.0" against a latest release of v1.1.1. Nobody had recorded
# them because a scoping phrase in a filed question decides what the answer can
# contain, which is a rule this project already writes down for gates (O29/O32)
# and had not applied to its own filings.
#
# Truth is the latest PUBLISHED RELEASE, not the workspace version: the tree
# carries the next version during release prep, and the house page should
# follow the tag. Public API, no auth needed.
REL=$(curl -sS --max-time 30 https://api.github.com/repos/sealcroft/undercroft/releases/latest 2>/dev/null \
      | sed -nE 's/.*"tag_name" *: *"v?([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' | head -1)
if [ -z "$REL" ]; then
  fail "could not read the latest release tag" \
       "unreachable is a failure, not a skip — see the premise rule above"
else
  # Both spellings, because they drifted together and a check that reads one
  # passes while the other is wrong.
  BANNER=$(printf '%s' "$BODY" | grep -oE 'Undercroft [0-9]+(\.[0-9]+)* is out' | head -1)
  SHIPPING=$(printf '%s' "$BODY" | grep -oE 'Shipping[^<]*v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  REL_MINOR="${REL%.*}"
  if [ -z "$BANNER" ]; then
    pass "no release banner to check"
  elif printf '%s' "$BANNER" | grep -qE "Undercroft ($REL|$REL_MINOR) is out"; then
    pass "release banner names the current release: $BANNER"
  else
    fail "release banner is stale: '$BANNER', latest release is v$REL"
  fi
  if [ -z "$SHIPPING" ]; then
    pass "no shipping badge to check"
  elif printf '%s' "$SHIPPING" | grep -qF "v$REL"; then
    pass "shipping badge names the current release: v$REL"
  else
    fail "shipping badge is stale: '$SHIPPING', latest release is v$REL"
  fi
fi

echo ""
echo "house-figures results: $PASS passed, $FAIL failed"

if [ "$FAIL" -ne 0 ] && [ "$UPDATE" -eq 1 ]; then
  echo ""
  echo "== --update: patching the house page =="
  command -v gh >/dev/null 2>&1 || { echo "FAIL  gh is not installed"; exit 1; }
  src=$(gh api "repos/$HOUSE_REPO/contents/index.html" --jq '.content' 2>/dev/null | base64 -d)
  sha=$(gh api "repos/$HOUSE_REPO/contents/index.html" --jq '.sha' 2>/dev/null)
  if [ -z "$src" ] || [ -z "$sha" ]; then
    echo "FAIL  could not read $HOUSE_REPO/index.html — is gh authenticated?"
    exit 1
  fi
  # Only the tiles this script KNOWS how to derive. The benchmark headline is
  # deliberately not patched: which configuration the house publishes is a
  # product decision, not a number this tree can compute, and a script that
  # silently rewrote it would be making that decision on its own.
  patched="$src"
  changed=0
  for pair in "tests passing|$TRUE_TESTS" "MCP tools|$TRUE_MCP"; do
    label="${pair%%|*}"; want="${pair#*|}"
    cur=$(printf '%s' "$patched" \
      | grep -oE "<div class=\"n\">[0-9]+</div><div class=\"l\">$label</div>" | head -1)
    [ -z "$cur" ] && continue
    new="<div class=\"n\">$want</div><div class=\"l\">$label</div>"
    if [ "$cur" != "$new" ]; then
      patched="${patched//$cur/$new}"
      echo "  $label: $(printf '%s' "$cur" | grep -oE '>[0-9]+<' | tr -d '><') -> $want"
      changed=$((changed + 1))
    fi
  done
  if [ "$changed" -eq 0 ]; then
    echo "FAIL  nothing this script can derive was stale — the remaining"
    echo "      failure needs a human (the benchmark tile, or the release"
    echo "      claims, which follow the published tag rather than this tree)"
    exit 1
  fi
  printf '%s' "$patched" | base64 -w0 > /tmp/house.b64
  gh api -X PUT "repos/$HOUSE_REPO/contents/index.html" \
    -f message="published figures: $changed tile(s) refreshed from sealcroft/undercroft

Pushed by tests/house-figures.sh --update. The figures are gated from that
repository (its own CI job), so this page going stale turns that repo's CI
red rather than sitting unnoticed." \
    -f content="@/tmp/house.b64" -f sha="$sha" --jq '.commit.sha' >/dev/null || {
      echo "FAIL  push to $HOUSE_REPO rejected"; exit 1; }
  rm -f /tmp/house.b64
  echo "  pushed. waiting for Pages, then re-checking the LIVE page —"
  echo "  a commit is not a deploy, and this script verifies the deploy."
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 20
    if bash "$0" >/dev/null 2>&1; then
      echo "  live and correct after $((i * 20))s"
      exit 0
    fi
  done
  echo "FAIL  page still not serving the new figures after 200s"
  exit 1
fi

if [ "$FAIL" -ne 0 ]; then
  echo "HOUSE FIGURES FAILED"
  [ "$UPDATE" -eq 0 ] && echo "  (run 'bash tests/house-figures.sh --update' to patch the derivable tiles)"
  exit 1
fi
echo "HOUSE FIGURES OK"
