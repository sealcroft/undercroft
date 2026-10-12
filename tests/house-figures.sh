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

# An override that is set but EMPTY is a failed interpolation, never a request
# for the default: read as the default, an empty `HOUSE_RELEASE_URL` meant to
# show a failed read would read the real release and pass (ROADMAP O331, the
# rule `GH_TOKEN` follows below).
for v in HOUSE_REPO HOUSE_PAGE_URL HOUSE_RELEASE_URL; do
  if [ -n "${!v+x}" ] && [ -z "${!v}" ]; then
    echo "FAIL  $v is set but empty — a failed interpolation, not a request for the default"
    echo ""
    echo "HOUSE FIGURES FAILED — premise"
    exit 1
  fi
done
HOUSE_REPO="${HOUSE_REPO-sealcroft/sealcroft.github.io}"

PAGE="${HOUSE_PAGE_URL-https://sealcroft.com/}"
# The latest PUBLISHED release, which the page's version claims follow (O65).
# Overridable beside the page so that a failed read can be shown to name its
# cause: point it at a release that does not exist (ROADMAP O331).
RELEASE_URL="${HOUSE_RELEASE_URL-https://api.github.com/repos/sealcroft/undercroft/releases/latest}"
PASS=0
FAIL=0
pass() { printf 'ok    %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { # fail <what> [detail ...] — one indented line per non-empty detail
  printf 'FAIL  %s\n' "$1"; shift
  for d in "$@"; do [ -z "$d" ] || printf '      %s\n' "$d"; done
  FAIL=$((FAIL + 1))
}

cd "$(dirname "$0")/.." || exit 1

# What each network read leaves for its verdict — the body, the response
# headers and curl's own error line — removed on every exit.
TMP=$(mktemp -d) || { echo "FAIL  could not create a temporary directory"; exit 1; }
trap 'rm -rf "$TMP"' EXIT
# On Git Bash, curl is a native Windows program and a `/tmp/...` argument
# reaches it converted only while MSYS path conversion is on; a mixed path
# (`C:/...`) reads the same to both, whatever `MSYS_NO_PATHCONV` says.
if command -v cygpath >/dev/null 2>&1; then
  MIXED=$(cygpath -m "$TMP") && [ -d "$MIXED" ] && TMP="$MIXED"
fi

# ONE reader for both network reads, so that a failed read can say WHY
# (ROADMAP O331). It keeps the three things the release read used to throw
# away: `-sS` without `-f` exits 0 on an HTTP error and left the cause in a
# body a `sed` turned into an empty string, `2>/dev/null` discarded the line
# naming a DNS failure or a timeout, and the pipeline lost curl's exit status.
# So a rate limit, an API outage, a DNS failure and a malformed answer all
# printed one line, the one written for an unreachable page. No `-L`: a
# redirect is an answer to report, not one to follow.
#   fetch <name> <url> [token]
# sets FETCH_RC (curl's exit status) and FETCH_HTTP (the status, "000" when
# no HTTP answer arrived), and leaves $TMP/<name>.body, .head and .err. A
# token travels on curl's STDIN (`-H @-`), never on its command line, where
# any process on the host can read it. `-q`, which must come first, keeps a
# caller's `~/.curlrc` out: a `--verbose` there would write the header into
# the error line this script prints.
fetch() {
  local name="$1" url="$2" token="${3:-}"
  : > "$TMP/$name.body"; : > "$TMP/$name.head"; : > "$TMP/$name.err"
  if [ -n "$token" ]; then
    FETCH_HTTP=$(printf 'Authorization: Bearer %s\n' "$token" \
      | curl -q -sS --max-time 30 -H @- -D "$TMP/$name.head" -o "$TMP/$name.body" \
             -w '%{http_code}' "$url" 2>"$TMP/$name.err")
    FETCH_RC=$?
  else
    FETCH_HTTP=$(curl -q -sS --max-time 30 -D "$TMP/$name.head" -o "$TMP/$name.body" \
             -w '%{http_code}' "$url" 2>"$TMP/$name.err")
    FETCH_RC=$?
  fi
  case "$FETCH_HTTP" in [0-9][0-9][0-9]) ;; *) FETCH_HTTP=000 ;; esac
}

# A line read off the network, made fit for a CI log: line breaks become
# spaces, every other control character goes — an escape sequence, or a line
# break (a lone carriage return included) that would start a `::` workflow
# command — trailing blanks go, and at most 300 bytes stay. Everything this
# script prints that it read off the network goes through it: the API's
# message, curl's line, and the strings it quotes from the page. The answer
# is GitHub's or the house page's, but both URLs can be pointed anywhere.
# Byte-wise (`LC_ALL=C`): under a UTF-8 locale BSD `tr` and `sed` stop at the
# first invalid byte instead of passing it.
oneline() {
  LC_ALL=C tr '\r\n\t' '   ' | LC_ALL=C tr -d '\000-\037\177' | LC_ALL=C sed 's/ *$//' \
    | LC_ALL=C cut -c1-300
}

# The `message` an API error answers with, or nothing.
api_message() {
  LC_ALL=C sed -nE 's/.*"message" *: *"([^"]*)".*/\1/p' "$1" | head -1 | oneline
}

# The rate-limit headers an answer carried, as one phrase, or nothing. The
# reset is counted from now with `date +%s`, which GNU and BSD share; reading
# an epoch back into a date takes options they do not.
rate_limit() {
  local h="$1" lim rem res reset mins
  lim=$(grep -i '^x-ratelimit-limit:' "$h" | tail -1 | tr -cd '0-9')
  [ -n "$lim" ] || return 0
  rem=$(grep -i '^x-ratelimit-remaining:' "$h" | tail -1 | tr -cd '0-9')
  res=$(grep -i '^x-ratelimit-resource:' "$h" | tail -1 | sed 's/^[^:]*://' | tr -cd 'a-z_')
  reset=$(grep -i '^x-ratelimit-reset:' "$h" | tail -1 | tr -cd '0-9' | cut -c1-12)
  mins=""
  if [ -n "$reset" ]; then
    # base 10 stated: a leading zero would otherwise read as octal
    mins=$(( (10#$reset - $(date +%s) + 59) / 60 ))
    [ "$mins" -ge 0 ] || mins=0
  fi
  printf 'rate limit %s%s, %s remaining%s' "$lim" "${res:+ ($res)}" "${rem:-?}" \
    "${mins:+, resets in $mins min}"
}

# ---- the truth side, from the tree ------------------------------------------
# Both are read the way the tree's own gates read them, never from prose.
TRUE_MCP=$(awk '/pub const MCP_TOOLS/,/^\];/' crates/undercroft-cli/src/parity.rs \
           | grep -cE '^\s*"undercroft_[a-z_]+",' || true)
# The cargo test count as the agent guide publishes it, which
# `tests/battery.sh` already compares against a real run — so this reads the
# published figure rather than re-deriving it, and the battery is what keeps
# that honest. It sat in `CLAUDE.md` until the guide was split (ROADMAP O436);
# the file below is the battery's `FIGURES_DOC`, and the premise beneath
# refuses an empty read, so a figure that moves again fails here loudly.
TRUE_TESTS=$(grep -oE 'cargo unit \+ integration tests \([0-9]+ run' docs/agent-guide/build-and-test.md \
             | grep -oE '[0-9]+' | head -1)

if [ -z "${TRUE_TESTS:-}" ] || [ "${TRUE_MCP:-0}" -lt 10 ]; then
  echo "FAIL  a truth-side reader came back empty: tests='${TRUE_TESTS:-}' mcp='${TRUE_MCP:-}'"
  echo "      A reader that examined nothing agrees with any page."
  echo ""
  echo "HOUSE FIGURES FAILED — premise"
  exit 1
fi

# ---- the page side ----------------------------------------------------------
# Never with the token: it is GitHub's, and this is the house's host.
fetch page "$PAGE"
BODY=$(cat "$TMP/page.body")

# PREMISE, and it is the whole reason this file is careful. An unreachable
# page and a correct page must NOT produce the same verdict — that is the
# "a checker that cannot run reports the same thing as a clean tree" trap this
# project has hit repeatedly. Unreachable is a FAILURE, not a skip. An answer
# that is not a 200 is unreachable too: curl exits 0 on one, so a 404 or a 503
# page used to reach the tile reader and fail as "the markup moved"
# (ROADMAP O331).
if [ "$FETCH_RC" -ne 0 ] || [ "$FETCH_HTTP" != 200 ] || [ -z "$BODY" ]; then
  echo "FAIL  could not fetch $PAGE (HTTP $FETCH_HTTP, curl exit $FETCH_RC)"
  [ -s "$TMP/page.err" ] && echo "      $(oneline < "$TMP/page.err")"
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
  | grep -oE '<div class="l">[^<]*LongMemEval[^<]*' | sed 's/<div class="l">//' | head -1 | oneline)
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
# follow the tag.
#
# **The read authenticates where a token exists (ROADMAP O331).** It was an
# unauthenticated call from a hosted runner, whose IP — and with it the 60
# requests an hour GitHub gives an unauthenticated caller — is shared with
# every other tenant of that IP: three of the eight times this job went red
# between 2026-08-30 and 2026-10-07 were this read alone, and its log could
# not say why. CI passes the job's own token as `GH_TOKEN`; the workflow
# grants it `contents: read`, and the checkout step already leaves it in the
# job's git configuration (`persist-credentials` defaults to true), so the
# step holds no credential it did not hold before. It is sent ONLY under
# GitHub's API origin — a prefix that ends in the slash closing the host, so
# no URL it passes names another host — and never to the page. A person with
# no token reads unauthenticated, which is plenty for one person's runs; one
# behind an address many people share can run it as
# `GH_TOKEN=$(gh auth token) bash tests/house-figures.sh`, the login `gh`
# already holds. An exported `GH_TOKEN` is sent on every run, so an expired
# one answers 401 here — and `gh` itself prefers it over its stored login, so
# `--update`'s write uses it too.
#
# Inside GitHub Actions an unauthenticated read FAILS. It is the shape this
# arm exists to end, and without the failure a workflow that stopped passing
# the token would show it again only one run in a hundred, as a failed
# release read. An empty `GH_TOKEN` fails everywhere: it is a failed
# interpolation, never a request to read unauthenticated.
REL_TOKEN=""
REL_AUTH="without a token"
REL_EMPTY=0
if [ -z "${GH_TOKEN+x}" ]; then
  :
elif [ -z "$GH_TOKEN" ]; then
  REL_EMPTY=1
  fail "GH_TOKEN is set but empty" \
       "an empty token is a failed interpolation: unset it to read without one, or give it the token"
else
  case "$RELEASE_URL" in
    https://api.github.com/*) REL_TOKEN="$GH_TOKEN"; REL_AUTH="with GH_TOKEN" ;;
    *) REL_AUTH="without a token (GH_TOKEN goes only under https://api.github.com/)" ;;
  esac
fi
# An empty token has failed already, for the cause that names it.
if [ "${GITHUB_ACTIONS:-}" = true ] && [ -z "$REL_TOKEN" ] && [ "$REL_EMPTY" -eq 0 ]; then
  fail "the release read is unauthenticated inside GitHub Actions" \
       "pass the job its own token as GH_TOKEN (ROADMAP O331): a hosted runner shares the unauthenticated 60 an hour with every tenant of its IP"
fi

fetch release "$RELEASE_URL" "$REL_TOKEN"
REL_LIMIT=$(rate_limit "$TMP/release.head")
echo "   release read: HTTP $FETCH_HTTP, $REL_AUTH${REL_LIMIT:+; $REL_LIMIT}"
REL=""
if [ "$FETCH_RC" -eq 0 ] && [ "$FETCH_HTTP" = 200 ]; then
  REL=$(sed -nE 's/.*"tag_name" *: *"v?([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' "$TMP/release.body" | head -1)
fi
if [ -z "$REL" ]; then
  # The cause on the FAIL line itself: the HTTP status, the API's own message
  # and curl's exit status, then curl's error line. The rate limit is on the
  # `release read` line above it.
  REL_MSG=$(api_message "$TMP/release.body")
  if [ "$FETCH_HTTP" = 000 ]; then
    REL_WHY="no HTTP answer"
  elif [ "$FETCH_HTTP" = 200 ] && [ "$FETCH_RC" -eq 0 ]; then
    REL_WHY="HTTP 200 with no \"tag_name\" of the form vX.Y.Z"
  else
    REL_WHY="HTTP $FETCH_HTTP${REL_MSG:+ \"$REL_MSG\"}"
  fi
  fail "could not read the latest release tag: $REL_WHY (curl exit $FETCH_RC, $REL_AUTH)" \
       "from $RELEASE_URL" \
       "$(oneline < "$TMP/release.err")" \
       "unreachable is a failure, not a skip — see the premise rule above"
else
  # Both spellings, because they drifted together and a check that reads one
  # passes while the other is wrong.
  BANNER=$(printf '%s' "$BODY" | grep -oE 'Undercroft [0-9]+(\.[0-9]+)* is out' | head -1 | oneline)
  SHIPPING=$(printf '%s' "$BODY" | grep -oE 'Shipping[^<]*v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | oneline)
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
    echo "FAIL  nothing this script can derive was stale — the failure above"
    echo "      needs a human: the benchmark tile, the release claims (which"
    echo "      follow the published tag rather than this tree), or the release"
    echo "      read or its token, whose FAIL line names the cause"
    exit 1
  fi
  # `-f` sends a literal string; it does NOT read a file, so `-f content=@path`
  # uploads the path itself and GitHub answers 422 "content is not valid
  # Base64". It did, the first time this ran for real — the patch logic and
  # the no-op path had both been tested, and the PUSH had not.
  b64=$(printf '%s' "$patched" | base64 -w0)
  gh api -X PUT "repos/$HOUSE_REPO/contents/index.html" \
    -f message="published figures: $changed tile(s) refreshed from sealcroft/undercroft

Pushed by tests/house-figures.sh --update. The figures are gated from that
repository (its own CI job), so this page going stale turns that repo's CI
red rather than sitting unnoticed." \
    -f content="$b64" -f sha="$sha" --jq '.commit.sha' >/dev/null || {
      echo "FAIL  push to $HOUSE_REPO rejected"; exit 1; }

  echo "  pushed. waiting for Pages, then re-checking the LIVE page —"
  echo "  a commit is not a deploy, and this script verifies the deploy."
  # Each re-check is this script, so it reads the release the same way the
  # first run did. Its output is kept and the last one printed if none
  # passes: the re-check can fail for a cause that is not the page — the
  # release read's own (ROADMAP O331) — and a timeout that hid the cause
  # would say "not deployed" over it.
  last=""
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 20
    if last=$(bash "$0" 2>&1); then
      echo "  live and correct after $((i * 20))s"
      exit 0
    fi
  done
  echo "FAIL  the live page did not pass the check within 200s; the last check said:"
  printf '%s\n' "$last" | sed 's/^/      /'
  exit 1
fi

if [ "$FAIL" -ne 0 ]; then
  echo "HOUSE FIGURES FAILED"
  [ "$UPDATE" -eq 0 ] && echo "  (run 'bash tests/house-figures.sh --update' to patch the derivable tiles)"
  exit 1
fi
echo "HOUSE FIGURES OK"
