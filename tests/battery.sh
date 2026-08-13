#!/usr/bin/env bash
# The full Docker battery, at the tree as it stands, with RAW EXIT CODES.
#
# CLAUDE.md's definition of done asks for exactly this and nothing had ever
# provided it, so every session assembled the battery by hand and paid for it
# twice on 2026-08-06:
#
#   * a summary was built by piping `cargo test` through `awk` and reading a
#     field that did not exist, so it reported `failed=0` from an EMPTY
#     string — a false green derived from output SHAPE rather than from the
#     exit code that was sitting right there;
#   * `lint` was run locally BEFORE the last edit and then reported as green,
#     while the battery failed on a `needless_borrow` introduced after it.
#
# Both are the same defect: a verdict taken from something other than the
# thing that decides it. So this script never parses suite output to decide
# pass/fail — the exit code is the verdict, full stop — and it runs every
# suite in one pass over one tree, which is what makes "I ran it before the
# last edit" impossible rather than merely discouraged.
#
# Usage, from the repo root:
#     bash tests/battery.sh              # everything
#     bash tests/battery.sh test lint    # a subset, same reporting
#
# Exit code: 0 only if every suite selected exited 0.
set -u

cd "$(dirname "$0")/.."

# Order matters: the cheap suites that fail fastest come first, so a broken
# tree is reported in a minute instead of forty.
ALL=(lint obs-config test e2e orchestrator-e2e e2e-telemetry backends-e2e site)

# `--preflight-only` exists so CI can run the host-side preflights without
# Docker. They are host-side because no image carries `ROADMAP.md`, the
# compose files or `.gitattributes`' whole scope — and until this flag existed
# they therefore ran NOWHERE on a pull request, since `ci.yml` named this
# script only inside comments. A gate that runs only where its author
# remembers to run it is a gate the next person does not have.
PREFLIGHT_ONLY=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --preflight-only) PREFLIGHT_ONLY=1 ;;
    # Exit 1, never 2. Exit 2 is this project's integrity verdict on every
    # command; a mistyped flag borrowing it is the defect T11 closed in the
    # binaries, and it would be no less wrong here.
    -*) echo "unknown option: $a" >&2; exit 1 ;;
    *) ARGS+=("$a") ;;
  esac
done
SUITES=("${ARGS[@]:-}")
if [ -z "${SUITES[0]:-}" ]; then SUITES=("${ALL[@]}"); fi

declare -a NAMES=() CODES=()
OVERALL=0

# ── preflight: line endings over the WHOLE tree ─────────────────────────────
# `.gitattributes` declares `* text=auto eol=lf` and says why: a CRLF shell
# script breaks in the containers. Nothing enforced it until 2026-08-06, when
# scripted edits written in text mode on Windows converted eleven files and
# `tests/e2e.sh` died with `$'\r': command not found` before a check ran.
#
# The companion gate `no_source_file_has_crlf_line_endings` owns `crates/`,
# because that subtree is complete inside every image. This owns everything
# else — `tests/`, `docs/`, `website/`, the compose files — which NO image
# carries: the test image COPYs only `crates/`, and each e2e service
# bind-mounts its single script. Host-side is the only place the whole tree
# exists, so this runs before any suite rather than inside one.
echo "═══ preflight: line endings ═══"
# `git ls-files --eol` — git owns this concept, so ask git. It prints the
# index ending, the WORKING-TREE ending and the attribute that governs the
# file: `i/lf  w/crlf  attr/text=auto eol=lf`. A `w/crlf` against an `eol=lf`
# attribute is precisely the violation, with no byte-level detection to get
# wrong, no extension allowlist to keep in step, and no dependency on Python.
#
# Two hand-rolled attempts preceded this and each was broken in a DIFFERENT
# direction, which is why both are exercised below rather than assumed:
#   * `grep -qU $'\r'` inside a `while read` subshell — the `$'\r'` never
#     expanded, so the pattern was empty, `grep -q ''` matched every file and
#     the check declared the whole repo corrupt (false POSITIVE);
#   * `awk 'index($0, cr)'` — awk on Windows treats CRLF as the line
#     terminator and strips the CR before `$0` is seen, so a fully-CRLF file
#     read as clean (false NEGATIVE).
# A check whose output does not measure what it claims is the same defect
# whichever way it points.
# The attribute is field 4, not 3 (`i/lf  w/crlf  attr/text=auto  eol=lf`) —
# matching on `$3` was this check's third bug and read every file as clean.
# Hence `$0`, and hence the two-direction test that finally caught it.
CRLF_HITS=$(git ls-files --eol 2>/dev/null \
  | awk '$2 == "w/crlf" && $0 ~ /eol=lf/ { print $NF }' \
  | grep -v '^crates/' || true)
if [ -n "$CRLF_HITS" ]; then
  echo "FAIL  these tracked files have CRLF line endings, which .gitattributes"
  echo "      forbids (a CRLF script fails in the containers). Normalise in"
  echo "      BINARY mode — a text-mode write on Windows is what introduces them:"
  printf '        %s\n' $CRLF_HITS
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    no CRLF outside crates/ (crates/ is gated by cargo test)"

# ── preflight: a ROADMAP heading must state its own status ──────────────────
# `CLAUDE.md`: "a heading, a doc claim, a CHANGELOG bullet and a test NAME are
# not verification — headings here have been wrong repeatedly and are the most
# expensive artifact this project produces."
#
# `O2`'s heading read "the site loads three font families from Google" for a
# day while its own body said **CLOSED**, so a handover was nearly written
# around an item that did not exist. Its siblings carry their status in the
# heading; that one did not, and nothing could say so.
#
# Host-side with the line-ending check, for the same reason: no image carries
# `ROADMAP.md`, so a `cargo test` cannot read it. Cheap, and it makes "do not
# forget" mechanical instead of remembered — which is this project's whole
# position on inventories versus prose.
# ---------------------------------------------------------------------------
# The `test` suite's count, read by PAIRING rather than by summing (ROADMAP
# O15).
#
# `docker compose run` SOMETIMES replays the tail of the container's stream,
# so `.battery/test.log` ends with a duplicated block. Summing every
# `test result:` line then reports a run that executed 694/4 as 1016/8. It is
# INTERMITTENT — two batteries the same hour on the same tree produced one
# duplicated log and one clean one — which is worse than a constant error,
# because nobody re-derives a number that looked right last time.
#
# So: pair each target HEADER (`Running …` / `Doc-tests …`) with the result
# that follows it, and sum only paired results. A duplicated tail has no
# header above it, so its result lines are ORPHANS.
#
# **An orphan is reported as a PREMISE FAILURE, never dropped.** It is the
# only visible symptom of the replay; a reader that quietly ignored one would
# be unable to say the stream had been duplicated at all, which is the same
# defect one level down from the one this fixes.
#
# A function, not inline awk, because the gate below runs the SAME code on
# synthetic input. A gate that re-implements what it checks agrees with itself
# by construction — this file's own first ROADMAP-heading check shipped broken
# for exactly that reason.
test_summary() { # test_summary <log>
  awk '
    /^[[:space:]]*(Running|Doc-tests)[[:space:]]/ { hdr = 1; next }
    /^test result:/ {
      if (hdr) {
        for (i = 1; i <= NF; i++) {
          if ($(i+1) ~ /^passed/)  p += $i
          if ($(i+1) ~ /^failed/)  f += $i
          if ($(i+1) ~ /^ignored/) g += $i
        }
        t++; hdr = 0
      } else { orphan++ }
    }
    END {
      if (t == 0 && orphan == 0) {
        printf "no result lines found — this reader examined nothing"
        exit
      }
      printf "%d passed, %d failed, %d ignored over %d targets", p, f, g, t
      if (orphan > 0)
        printf "  ** PREMISE FAILURE: %d orphan result line(s) — the log tail was replayed; this count is not trustworthy (ROADMAP O15) **", orphan
    }' "$1" 2>/dev/null
}

# **The same class one suite over (ROADMAP O27).** `test_summary` can name a
# replayed tail because it pairs cargo's target HEADERS with their results —
# but `Running` and `Doc-tests` are cargo's, and no other suite emits them, so
# O15's detector covered ONE suite of eight. The seven shell suites print a
# single `<suite> results: N passed, M failed` line as their FINAL statement
# (`tests/e2e-backends.sh:157` and its siblings), so more than one in a log is
# not a heuristic signal: that log is not the record of a single run.
#
# Observed rather than theorised. A `backends-e2e` log on this branch carried
# `56 passed, 1 failed` AND `54 passed, 3 failed`, and the `| tail -1` this
# replaces printed the second with nothing saying the first existed.
suite_summary() { # suite_summary <log>
  awk '
    /^[a-z0-9-]+([ ][a-z0-9-]+)* results: [0-9]+ passed, [0-9]+ failed/ {
      n++; last = $0
    }
    END {
      if (n == 0) {
        printf "no results line found — this reader examined nothing"
        exit
      }
      printf "%s", last
      if (n > 1)
        printf "  ** PREMISE FAILURE: %d summary lines in one log — it holds more than one run, so this count is not trustworthy (ROADMAP O27) **", n
    }' "$1" 2>/dev/null
}

# The gate for it, run host-side because no image carries this script. Both
# arms come from the filed shape: a log reports the same figure with and
# without a duplicated tail, and the orphan is counted and NAMED.
echo "═══ preflight: the test-count reader ═══"
SUM_TMP="$(mktemp -d)"
cat >"$SUM_TMP/clean.log" <<'SUMEOF'
     Running unittests src/lib.rs (target/release/deps/a-1)
test result: ok. 10 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out
     Running tests/cli.rs (target/release/deps/b-2)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
   Doc-tests undercroft_core
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
SUMEOF
# The replay: the tail block again, with NO header above it.
cp "$SUM_TMP/clean.log" "$SUM_TMP/replayed.log"
cat >>"$SUM_TMP/replayed.log" <<'SUMEOF'
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
SUMEOF
SUM_CLEAN=$(test_summary "$SUM_TMP/clean.log")
SUM_REPLAY=$(test_summary "$SUM_TMP/replayed.log")
SUM_EMPTY=$(test_summary /dev/null)
SUM_FAIL=0
case "$SUM_CLEAN" in
  "16 passed, 0 failed, 2 ignored over 3 targets") ;;
  *) echo "FAIL  the reader miscounts a clean log: $SUM_CLEAN"; SUM_FAIL=1 ;;
esac
case "$SUM_REPLAY" in
  "16 passed, 0 failed, 2 ignored over 3 targets"*) ;;
  *) echo "FAIL  a replayed tail changed the count: $SUM_REPLAY"; SUM_FAIL=1 ;;
esac
case "$SUM_REPLAY" in
  *"PREMISE FAILURE: 1 orphan"*) ;;
  *) echo "FAIL  the replay was absorbed silently: $SUM_REPLAY"; SUM_FAIL=1 ;;
esac
# A reader that examined nothing must say so rather than print a clean zero.
case "$SUM_EMPTY" in
  *"examined nothing"*) ;;
  *) echo "FAIL  an empty log reported a count: $SUM_EMPTY"; SUM_FAIL=1 ;;
esac

# ...and the same three arms for the SUITE reader (ROADMAP O27), because the
# same class needs the same proof: a doubled log must be NAMED rather than
# silently reduced to its last line, and a scanner that examined nothing must
# say so. The replayed fixture uses the exact numbers the real contaminated
# log carried, so this arm fails if the reader ever goes back to `tail -1`.
cat >"$SUM_TMP/suite-clean.log" <<'SUMEOF'
ok    [qdrant] push
backends-e2e results: 57 passed, 0 failed
SUMEOF
cp "$SUM_TMP/suite-clean.log" "$SUM_TMP/suite-replayed.log"
cat >>"$SUM_TMP/suite-replayed.log" <<'SUMEOF'
ok    [weaviate] verbatim result
backends-e2e results: 54 passed, 3 failed
SUMEOF
SUI_CLEAN=$(suite_summary "$SUM_TMP/suite-clean.log")
SUI_REPLAY=$(suite_summary "$SUM_TMP/suite-replayed.log")
SUI_EMPTY=$(suite_summary /dev/null)
case "$SUI_CLEAN" in
  "backends-e2e results: 57 passed, 0 failed") ;;
  *) echo "FAIL  the suite reader misreads a clean log: $SUI_CLEAN"; SUM_FAIL=1 ;;
esac
case "$SUI_REPLAY" in
  *"PREMISE FAILURE: 2 summary lines"*) ;;
  *) echo "FAIL  two summaries in one log were absorbed silently: $SUI_REPLAY"; SUM_FAIL=1 ;;
esac
case "$SUI_EMPTY" in
  *"examined nothing"*) ;;
  *) echo "FAIL  the suite reader reported a verdict over an empty log: $SUI_EMPTY"; SUM_FAIL=1 ;;
esac
rm -rf "$SUM_TMP"
if [ "$SUM_FAIL" -ne 0 ]; then
  echo "      the summary is reporting-only and decides nothing, but it is the"
  echo "      number a session copies into CLAUDE.md — an unreproducible doc claim"
  # `exit 1`, like every other preflight here. The first version of this line
  # incremented a `FAIL` counter that does not exist in this script, so the
  # gate would have printed its complaint and let the battery continue — a
  # checker that cannot fail, inside the gate written to catch that class.
  exit 1
else
  echo "ok    counts by pairing (cargo) and by counting summaries (suites);"
  echo "      a replayed tail or a doubled log is named, not absorbed"
fi

# ---------------------------------------------------------------------------
# The former-name trace check, INVOKED (ROADMAP O10).
#
# `tests/no-trace/verify.py` covers seven file-content classes a plain grep
# cannot: a non-Latin spelling sharing no byte with the Latin one, a truncated
# root used as an identifier stem, base64 inside a certificate, the identity
# carried without the name, and — since O26 — a Flate-compressed PDF stream,
# which is the class the rule was written about and the one the scanner
# implementing that rule could not read. It used to live in a gitignored directory
# and was run BY HAND — so a fresh clone did not carry it and nothing invoked
# it. A verifier nobody runs is a verifier you do not have, and the instance is
# on record: a comment added to explain the derived-name defect quoted the
# former name, the verifier would have caught it, and the battery was green.
#
# In a CONTAINER, because a gate needing Python on the host is a gate that does
# not run on the next machine. The tracked list is piped in so the image needs
# no `git` and no `apt-get`.
#
# **Docker absent is a FAILURE, not a skip** — a preflight that skips reports
# exactly what a clean tree reports, which is the whole defect class this file
# exists to close.
echo "═══ preflight: former-name trace ═══"
if ! command -v docker >/dev/null 2>&1; then
  echo "FAIL  docker is not available, so this check cannot run — that is a"
  echo "      failure and not a skip: a scanner that did not run reports what a"
  echo "      clean tree reports"
  exit 1
fi
NOTRACE_IMG="python:3-slim"
# The self-test first, on synthetic input: a known-positive file must be
# CAUGHT. Its content is assembled here from fragments for the same reason the
# scanner's needles are — this script is scanned too.
# The plant lives INSIDE the repo (in gitignored `.battery/`) rather than in a
# second mount: a Git Bash `mktemp -d` path passed through `MSYS_NO_PATHCONV`
# does not resolve for Docker, so the file simply did not exist in the
# container and the scanner "found nothing" — a self-test that silently tested
# an empty directory, which is the exact shape it exists to prevent.
mkdir -p .battery
NOTRACE_PROBE=".battery/notrace-probe.md"
printf 'a clean line\nthe %s%s%s name\n' "mne" "mos" "yne" > "$NOTRACE_PROBE"
# NOTE the sense: the scanner exits NON-ZERO when it finds something, so
# catching the plant is a FAILING exit and this `if` fires on exit ZERO. The
# first version of this line had the `!` and reported a working scanner as
# broken — an inverted gate, which is the one kind that fails loudly rather
# than silently, and the only reason it was cheap.
if git ls-files | MSYS_NO_PATHCONV=1 docker run --rm -i \
     -v "$(pwd):/r" -w /r "$NOTRACE_IMG" \
     python tests/no-trace/verify.py --stdin "$NOTRACE_PROBE" >/dev/null 2>&1; then
  echo "FAIL  the scanner did not catch a planted known-positive — it cannot be believed"
  rm -f "$NOTRACE_PROBE"
  exit 1
fi
rm -f "$NOTRACE_PROBE"
# …then the tree itself.
NOTRACE_OUT=$(git ls-files | MSYS_NO_PATHCONV=1 docker run --rm -i \
  -v "$(pwd):/r" -w /r "$NOTRACE_IMG" python tests/no-trace/verify.py --stdin 2>&1)
if [ $? -ne 0 ]; then
  # Two different failures share this exit code, and saying the wrong one is
  # its own defect: a disarmed scanner is not a dirty tree.
  case "$NOTRACE_OUT" in
    *"PREMISE FAILED"*)
      echo "FAIL  the trace scanner cannot be believed — it did not check what it claims:" ;;
    *)
      echo "FAIL  the former name is present in tracked content:" ;;
  esac
  echo "$NOTRACE_OUT" | sed 's/^/      /'
  exit 1
fi
# Print the scanner's own coverage lines rather than reformatting one of them.
# The previous version cut the output at `files scanned: ` and re-inserted the
# words with `sed`, which is a second copy of the scanner's format living here
# — and it stopped matching the moment the scanner gained a line. What a gate
# reports about its own reach is the last thing that should be reassembled by
# a caller, so both lines are passed through verbatim.
echo "ok    the former name is absent from tracked content"
echo "$NOTRACE_OUT" | grep -E '^  (files scanned|pdf streams):' | sed 's/^  /      /'

echo "═══ preflight: ROADMAP headings ═══"
ROADMAP_DRIFT=$(awk '
  function flush() {
    if (sec != "") { seen++; if (body ~ /CLOSED/ && sec !~ /CLOSED/) print sec }
  }
  /^### [A-Z][0-9]+/ { flush(); sec = $0; body = ""; next }
  /^## /              { flush(); sec = "";  body = ""; next }
  { if (sec != "") body = body " " $0 }
  END {
    flush()
    # The premise. An awk that cannot run prints nothing, and nothing is
    # exactly what a clean tree prints — which is how the FIRST version of
    # this gate reported ok having examined zero sections for a whole
    # commit. It said so only because the battery surfaced awk stderr.
    if (seen == 0) print "PREMISE-FAILED-no-sections-examined"
  }
' ROADMAP.md)
if [ "$ROADMAP_DRIFT" = "PREMISE-FAILED-no-sections-examined" ]; then
  echo "FAIL  the ROADMAP heading scan examined NO sections. The scanner is"
  echo "      broken, not the tree — a checker that cannot run reports exactly"
  echo "      what a clean tree reports."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
if [ -n "$ROADMAP_DRIFT" ]; then
  echo "FAIL  these ROADMAP entries say CLOSED in the body and not in the heading."
  echo "      A reader skims headings; one that contradicts its own section is"
  echo "      how an item that does not exist ends up in a handover:"
  printf '        %s
' "$ROADMAP_DRIFT"
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    every closed ROADMAP entry says so in its heading"

# ── preflight: every compose file DECLARES its project name ────────────────
# Undeclared, Compose derives the project from the DIRECTORY, so every
# container, image, volume and network inherits whatever the clone is called.
# On the maintainer's machine that was the project's FORMER name, which
# branded every build artifact while appearing in NO tracked file — invisible
# to `.handover/verify-no-trace.py`, which scans file CONTENTS. That is the
# seventh class of name occurrence and the reason this check reads the FILES
# rather than trusting the verifier's zero.
#
# Host-side with its siblings: no image carries the compose files, so no
# `cargo test` can read them. Counted BOTH ways — a compose file with no
# `name:` fails, and a declared name that is not in the expected set fails
# too, so a future file cannot quietly pick a colliding project.
echo "═══ preflight: compose project names ═══"
COMPOSE_FILES=$(git ls-files | grep -E '(^|/)docker-compose[a-z.-]*\.ya?ml$' || true)
# PREMISE PROBE. A glob that matches nothing reports exactly what a clean tree
# reports. This check is worthless unless it found compose files to examine.
COMPOSE_N=$(printf '%s\n' "$COMPOSE_FILES" | grep -c . || true)
if [ "${COMPOSE_N:-0}" -lt 3 ]; then
  echo "FAIL  the compose scan found $COMPOSE_N file(s); at least 3 are tracked."
  echo "      The scanner is broken, not the tree — a checker that cannot run"
  echo "      reports exactly what a clean tree reports."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
COMPOSE_BAD=""
for f in $COMPOSE_FILES; do
  # `name:` at column 0 — a `name:` nested under a service is a different key.
  n=$(grep -m1 '^name:[[:space:]]*' "$f" | sed 's/^name:[[:space:]]*//' | tr -d '\r')
  case "$n" in
    undercroft|undercroft-server|undercroft-observability|undercroft-bench-vs) ;;
    "") COMPOSE_BAD="$COMPOSE_BAD\n        $f — declares no project name" ;;
    *)  COMPOSE_BAD="$COMPOSE_BAD\n        $f — declares unexpected name '$n'" ;;
  esac
done
if [ -n "$COMPOSE_BAD" ]; then
  echo "FAIL  every compose file must DECLARE its project name, or Compose"
  echo "      derives it from the directory and brands every artifact with"
  echo "      whatever the clone is called:"
  printf "$COMPOSE_BAD\n"
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    all $COMPOSE_N compose files declare a project name"

# ── preflight: every published figure has an inventory row ─────────────────
# **A number in prose is a claim about the moment someone last counted**, and
# this project's published ones have rotted repeatedly: the landing page's
# cargo-test tile was set to 660 by the very commit that added four tests, and
# on 2026-08-13 its e2e tile read 508 against a true 541 — stale BEFORE the
# session that found it, with nothing able to say so. `docs/MULTI_TENANCY.md`
# was published claiming a suite runs 95 checks while it ran 110.
#
# So: an INVENTORY the surfaces are counted against, in BOTH directions. A new
# tile with no row fails; a row naming no tile fails. That is the half a
# hand-maintained doc table cannot do, and it is the same mechanism
# `parity.rs` uses for MCP tools and `GAUGE_NAMES` for metric series.
#
# **Three classes, because the figures do not have one provenance and
# pretending they do would be the dishonest part.**
#   derived  — checkable from the tree RIGHT NOW; the value is recomputed here
#              and a mismatch fails.
#   measured — only a battery run produces it. Checked two ways: every surface
#              publishing it must AGREE (static, and it is what catches a doc
#              going stale), and the full battery re-checks it against what it
#              actually measured (below, after the suites).
#   claim    — not a count at all. Recorded with its reason so it cannot be
#              mistaken for an unchecked number.
#
# **Scope, stated so it is not mistaken for complete.** This covers the
# landing page's `data-count` tiles and the per-suite check counts wherever
# they are published — the figures the battery itself measures, which move on
# almost every unit and have demonstrably rotted. It does NOT cover figures
# with their own gate (`UNDERCROFT_*` variables are counted by
# `ENGINE_ENV_VARS` both ways) or measurements needing an instrument run
# (IRREGULAR pairs, paradigm counts). Those are a different question, and
# widening a gate past what it can actually verify is how a check starts
# reading as though it covered more than it does.
echo "═══ preflight: published figures ═══"

LANDING="website/landing/index.html"
# label|class|source
PUBLISHED_FIGURES=(
  "cargo tests|measured|test"
  "e2e checks|measured|SUM:e2e,orchestrator-e2e,e2e-telemetry,backends-e2e"
  "live backends|derived|BACKENDS"
  "mcp tools|derived|MCP_TOOLS"
  "bytes phoned home|claim|the local-first invariant — a promise, not a count"
)

FIG_FAIL=0
# The tiles as PUBLISHED, read out of the page rather than assumed.
TILES=$(grep -oE 'data-count="[0-9]+">0</div><div class="l">[^<]+' "$LANDING" \
        | sed -E 's/data-count="([0-9]+)">0<\/div><div class="l">(.*)/\2=\1/')
TILE_N=$(printf '%s\n' "$TILES" | grep -c '=' || true)
# PREMISE. An extractor that matches nothing reports what a clean page
# reports — the failure this whole family is about. The page has had five
# tiles for its whole life; zero means the markup moved, not that the page
# is fine.
if [ "$TILE_N" -lt 1 ]; then
  echo "FAIL  no data-count tiles found in $LANDING — this reader examined nothing,"
  echo "      which is not the same as a page with no figures on it"
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi

# Direction 1: every published tile has a row. This is the arm that stops a
# NEW ungated figure from shipping.
while IFS= read -r t; do
  [ -z "$t" ] && continue
  label="${t%=*}"
  found=0
  for row in "${PUBLISHED_FIGURES[@]}"; do
    [ "${row%%|*}" = "$label" ] && found=1
  done
  if [ "$found" -eq 0 ]; then
    echo "FAIL  the landing page publishes \"$label\" with no inventory row —"
    echo "      classify it (derived / measured / claim) in PUBLISHED_FIGURES"
    FIG_FAIL=1
  fi
done <<< "$TILES"

# Direction 2: every row names a real tile. A row that has outlived its figure
# reads as a gate being enforced when nothing is.
for row in "${PUBLISHED_FIGURES[@]}"; do
  label="${row%%|*}"
  if ! grep -q "^$label=" <<< "$TILES"; then
    echo "FAIL  PUBLISHED_FIGURES names \"$label\", which the landing page no longer"
    echo "      publishes — a stale row reads as a checked figure"
    FIG_FAIL=1
  fi
done

fig_value() { grep -oE "^$1=[0-9]+" <<< "$TILES" | head -1 | cut -d= -f2; }

# The `derived` rows, recomputed from their source of truth.
BACKENDS_N=$(grep -cE '^run_backend_suite ' tests/e2e-backends.sh || true)
MCP_N=$(awk '/pub const MCP_TOOLS/,/^\];/' crates/undercroft-cli/src/parity.rs \
        | grep -cE '^\s*"undercroft_[a-z_]+",' || true)
# Premise on both sources: a zero here is a broken extractor, and it would
# make the comparison below pass only when the page is ALSO wrong.
if [ "$BACKENDS_N" -lt 1 ] || [ "$MCP_N" -lt 1 ]; then
  echo "FAIL  a derived source read as empty (backends=$BACKENDS_N mcp=$MCP_N) —"
  echo "      the extractor is broken, which is not evidence about the page"
  FIG_FAIL=1
else
  for pair in "live backends=$BACKENDS_N" "mcp tools=$MCP_N"; do
    lbl="${pair%=*}"; want="${pair#*=}"; got=$(fig_value "$lbl")
    if [ "$got" != "$want" ]; then
      echo "FAIL  the landing page publishes $lbl=$got; the tree says $want"
      FIG_FAIL=1
    fi
  done
fi

# The `measured` rows: every surface publishing one must AGREE. Static, and it
# is what catches a doc going stale between units — `docs/MULTI_TENANCY.md`
# claimed 95 for a suite running 110 while every other surface was current.
#
# CLAUDE.md publishes them on its `docker compose run --rm <suite>` lines;
# other docs publish them as `tests/<script>.sh`, N checks`.
# `grep -oE` + `sed -E`, deliberately NOT awk's three-argument `match()`:
# that is a GNU extension and Ubuntu's default `awk` is mawk, which does not
# have it. CI runs these preflights on ubuntu-latest, so the gawk form would
# have produced an empty read there — caught by the premise arm below, but as
# a confusing failure on a clean tree rather than as the portability bug it
# is. A gate that only runs on its author's machine is the shape this whole
# file exists to remove.
declare_suite_counts() {
  grep -oE 'docker compose run --rm [a-z0-9-]+.*\([0-9]+ checks' CLAUDE.md 2>/dev/null \
    | sed -E 's/docker compose run --rm ([a-z0-9-]+).*\(([0-9]+) checks/\1=\2/'
}
SUITE_COUNTS=$(declare_suite_counts)
if [ -z "$SUITE_COUNTS" ]; then
  echo "FAIL  no per-suite check counts found in CLAUDE.md — the reader is broken,"
  echo "      and a broken reader agrees with every page it cannot read"
  FIG_FAIL=1
fi
suite_count() { grep -oE "^$1=[0-9]+" <<< "$SUITE_COUNTS" | head -1 | cut -d= -f2; }

# Any OTHER doc republishing a suite's count must match CLAUDE.md's.
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  f="${hit%%:*}"; rest="${hit#*:}"
  sc=$(sed -E 's#.*tests/([a-z0-9-]+)\.sh`?,? +([0-9]+) checks.*#\1=\2#' <<< "$rest")
  sname="${sc%=*}"; sval="${sc#*=}"
  # `tests/e2e-backends.sh` is the script; the suite is `backends-e2e`.
  case "$sname" in
    e2e-backends) sname="backends-e2e" ;;
    e2e-orchestrator) sname="orchestrator-e2e" ;;
  esac
  want=$(suite_count "$sname")
  if [ -n "$want" ] && [ "$sval" != "$want" ]; then
    echo "FAIL  $f publishes $sname=$sval; CLAUDE.md publishes $want"
    FIG_FAIL=1
  fi
done <<< "$(git grep -nE 'tests/[a-z0-9-]+\.sh`?,? +[0-9]+ checks' -- '*.md' ':!CHANGELOG.md' 2>/dev/null)"

# The `e2e checks` tile is a SUM, and the row says which components. Deriving
# it here is the difference between a tile that is checked and one that merely
# looks plausible.
SUM_SPEC=""
for row in "${PUBLISHED_FIGURES[@]}"; do
  case "$row" in "e2e checks|"*) SUM_SPEC="${row##*SUM:}" ;; esac
done
if [ -n "$SUM_SPEC" ] && [ -n "$SUITE_COUNTS" ]; then
  total=0; missing=""
  for s in ${SUM_SPEC//,/ }; do
    v=$(suite_count "$s")
    if [ -z "$v" ]; then missing="$missing $s"; else total=$((total + v)); fi
  done
  if [ -n "$missing" ]; then
    echo "FAIL  the e2e tile sums$missing, which CLAUDE.md does not publish"
    FIG_FAIL=1
  else
    got=$(fig_value "e2e checks")
    if [ "$got" != "$total" ]; then
      echo "FAIL  the landing page publishes e2e checks=$got; its named components"
      echo "      (${SUM_SPEC//,/ + }) sum to $total"
      FIG_FAIL=1
    fi
  fi
fi

if [ "$FIG_FAIL" -ne 0 ]; then
  echo "      A published figure is a claim to anyone reading it. Correct the"
  echo "      surface, or the inventory if the figure legitimately moved."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    $TILE_N published tiles, each with a row; derived values and"
echo "      cross-surface suite counts agree"

# ── preflight: the handover has not drifted ────────────────────────────────
# `.handover/` is gitignored on purpose and MUST stay so — 1.6 GB of working
# material including the 269 MB pre-rename bundle. It is still a governance
# surface: `SESSION_START.md`, `NEXT_SESSION.md` and `AUDIT_CONTINUATION.md`
# are what the next session acts on, and one describing a tree that no longer
# exists is worse than none.
#
# Being untracked is exactly why this needs a gate. CI clones fresh and never
# sees these files, `git status` never mentions them, and no diff ever shows
# them going stale — the last session wrote doctrine claiming the handover
# shipped in its commit, and `git add -A` skipped it silently.
#
# It fires only when the working tree is CLEAN, i.e. at the moment you would
# be finishing. During work the tree is dirty and a lagging handover is
# normal, so this stays quiet instead of crying wolf until it is ignored.
#
# This comment sat fifty lines above its own code for the length of one
# session: the compose block was inserted BETWEEN the comment and the `echo`
# it describes, which is CLAUDE.md's "read what is ADJACENT to the anchor"
# hazard landing on the very file that mechanises the other hazards.
echo "═══ preflight: handover freshness ═══"
HANDOVER_DIR=".handover"
HANDOVER_FILES="SESSION_START.md NEXT_SESSION.md AUDIT_CONTINUATION.md"
if [ ! -d "$HANDOVER_DIR" ]; then
  echo "warn  no $HANDOVER_DIR/ on this machine — it is gitignored, so a fresh"
  echo "      clone has none. Ask whoever handed you this tree for it."
elif [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "ok    working tree is dirty — handover freshness is checked when clean"
else
  MISSING=""
  for f in $HANDOVER_FILES; do
    [ -f "$HANDOVER_DIR/$f" ] || MISSING="$MISSING $f"
  done
  if [ -n "$MISSING" ]; then
    echo "FAIL  these governance handover files are absent:$MISSING"
    echo "      They are gitignored by design and governance nonetheless."
    echo ""
    echo "BATTERY FAILED — preflight"
    exit 1
  fi
  # The prompt records the commit it describes. A clean tree whose handover
  # names a different commit is a handover that has already gone stale.
  RECORDED=$(grep -oE 'handover-head: [0-9a-f]{7,40}' "$HANDOVER_DIR/SESSION_START.md" 2>/dev/null | awk '{print $2}' | head -1)
  HEAD_SHA=$(git rev-parse --short HEAD 2>/dev/null)
  if [ -z "$RECORDED" ]; then
    echo "FAIL  $HANDOVER_DIR/SESSION_START.md records no commit."
    echo "      Add a line containing: handover-head: $HEAD_SHA"
    echo "      Without it nothing can tell whether the handover is current."
    echo ""
    echo "BATTERY FAILED — preflight"
    exit 1
  fi
  if [ "${HEAD_SHA#"$RECORDED"}" = "$HEAD_SHA" ] && [ "${RECORDED#"$HEAD_SHA"}" = "$RECORDED" ]; then
    echo "FAIL  the handover describes $RECORDED; HEAD is $HEAD_SHA."
    echo "      The tree is clean, so this is the moment it should be current."
    echo "      Update the three files under $HANDOVER_DIR/ and re-run."
    echo ""
    echo "BATTERY FAILED — preflight"
    exit 1
  fi
  echo "ok    handover is current with HEAD ($HEAD_SHA)"
fi

# ── preflight: the CI verdict job depends on EVERY job ─────────────────────
# A required status check resolves against ONE context. That context is the
# aggregate, and the aggregate is only worth requiring if failing anything
# fails it. `needs: suites` alone left `lint`, `audit`, `trivy-fs`, `site` and
# `trivy-image` outside the verdict entirely — five jobs that could go red
# under a green required check.
#
# The workflow half of this fails CLOSED on its own: the verdict step counts
# its upstreams and refuses a narrowed `needs:`. That direction cannot see the
# other one — a NEW job nobody added to `needs:` — because a workflow cannot
# enumerate its own jobs. This reads the file and closes it, counted both
# ways, which is the same inventory idiom `parity.rs` uses on the MCP surface.
echo "═══ preflight: CI verdict covers every job ═══"
CI=".github/workflows/ci.yml"
VERDICT_JOB="verdict"
if [ ! -f "$CI" ]; then
  echo "FAIL  $CI is absent. The verdict inventory has nothing to read, and a"
  echo "      scanner with no input reports what a clean tree reports."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
# Job ids are the keys at exactly two spaces INSIDE the `jobs:` mapping.
# Anchoring on `jobs:` is load-bearing and was found the expensive way: `on:`
# carries `push:` and `pull_request:` at the very same indent, so an
# unanchored scan reports two jobs that do not exist and then "finds" them
# missing from `needs:`.
CI_JOBS=$(awk '
  /^jobs:/            { inj = 1; next }
  inj && /^[^ #]/     { inj = 0 }
  inj && /^  [a-z0-9_-]+:$/ { gsub(/[ :]/, ""); print }
' "$CI")
CI_N=$(printf '%s\n' "$CI_JOBS" | grep -c . || true)
# The verdict job's own `needs:`, as a bare word list.
CI_NEEDS=$(awk -v j="^  ${VERDICT_JOB}:\$" '
  $0 ~ j                    { inv = 1; next }
  inv && /^  [a-z0-9_-]+:$/ { inv = 0 }
  inv && /^    needs:/      { print }
' "$CI" | sed -e 's/.*needs:[[:space:]]*//' -e 's/^\[//' -e 's/\]//' -e 's/,/ /g')
CI_NEEDS_N=$(printf '%s\n' $CI_NEEDS | grep -c . || true)
# PREMISE PROBE, both halves. Either extractor returning nothing looks exactly
# like a tree where everything already agrees.
if [ "${CI_N:-0}" -lt 5 ] || [ "${CI_NEEDS_N:-0}" -lt 4 ]; then
  echo "FAIL  the CI scan found $CI_N job(s) and $CI_NEEDS_N need(s); the"
  echo "      workflow has at least 5 and the verdict at least 4. The scanner"
  echo "      is broken, or '$VERDICT_JOB' is not the verdict job's id."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
CI_BAD=""
for j in $CI_JOBS; do
  [ "$j" = "$VERDICT_JOB" ] && continue
  case " $CI_NEEDS " in
    *" $j "*) ;;
    *) CI_BAD="$CI_BAD\n        job '$j' is outside ${VERDICT_JOB}'s needs: it can go red under a green verdict" ;;
  esac
done
for n in $CI_NEEDS; do
  case " $(printf '%s ' $CI_JOBS) " in
    *" $n "*) ;;
    *) CI_BAD="$CI_BAD\n        ${VERDICT_JOB} needs '$n', which is not a job in $CI" ;;
  esac
done
if [ -n "$CI_BAD" ]; then
  echo "FAIL  the CI verdict does not cover every job:"
  printf "$CI_BAD\n"
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    $VERDICT_JOB needs all $CI_NEEDS_N other job(s) of $CI_N"

if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
  echo ""
  echo "preflights only — no suite was run, by request (--preflight-only)"
  exit 0
fi

for suite in "${SUITES[@]}"; do
  # `tests/e2e-backends.sh` asserts exact record counts and therefore assumes
  # FRESH backends; a second run against warm volumes flakes. Documented in
  # CLAUDE.md, mechanised here so nobody has to remember it.
  if [ "$suite" = "backends-e2e" ]; then
    docker compose down -v >/dev/null 2>&1 || true
  fi

  echo ""
  echo "═══ $suite ═══"
  # No pipe. A pipeline's exit status is its LAST command's, which is how a
  # `| grep` or `| tail` silently turns a failing suite into a passing one —
  # the hazard CLAUDE.md records as "never let a pipeline's tail mask an exit
  # code you depend on". Output goes straight to the terminal and to a log.
  mkdir -p .battery
  docker compose run --rm --build "$suite" 2>&1 | tee ".battery/$suite.log"
  # ${PIPESTATUS[0]} is the compose exit code, not tee's.
  code=${PIPESTATUS[0]}
  NAMES+=("$suite")
  CODES+=("$code")
  [ "$code" -eq 0 ] || OVERALL=1
done

echo ""
echo "════════════════════════════════════════════════════"
echo " battery — raw exit codes, at the tree as it stands"
echo "════════════════════════════════════════════════════"
for i in "${!NAMES[@]}"; do
  n=${NAMES[$i]}
  c=${CODES[$i]}
  # The result line is quoted from the suite's own log for the record. It is
  # REPORTING ONLY and never decides anything — the exit code above already
  # did that, which is the whole point of this script.
  #
  # `cargo test` prints one result line per target, so a `tail -1` here read
  # the LAST one — a doc-test target with zero tests — and printed
  # "0 passed" under a green battery. Harmless, and still a number that does
  # not measure what it appears to, which is the habit this file exists to
  # break. Summed instead.
  if [ "$n" = "lint" ]; then
    # **The one suite with no summary line, named rather than complained
    # about.** `cargo fmt --check` and `clippy` are silent on success, so
    # `lint` has never printed one — and the O27 reader below correctly
    # answered "this reader examined nothing", beside a green run, every
    # time. That is a message which misdescribes its own situation, and
    # worse: it is the SAME string that is a real signal for the other seven
    # suites, so printing it routinely here teaches the reader to skip it.
    # An alarm nobody can distinguish from a real failure is the thing this
    # project exists to remove.
    detail=""
  elif [ "$n" = "test" ]; then
    detail=$(test_summary ".battery/$n.log")
  else
    # Widened past `…e2e results:` when `obs-config` and `site` joined the
    # battery — the old pattern hard-coded `e2e` and silently printed nothing
    # for them, which reads as a suite that ran no checks.
    #
    # The character class must include DIGITS. The first widening used
    # `[a-z-]+`, which cannot match `e2e` — so it fixed the two new suites
    # and blanked the four existing ones, and the battery still said OK
    # because this line has never decided anything. A reporting line that
    # quietly stops reporting is the same defect as a summary read from an
    # empty field; it is only cheaper.
    # `| tail -1` until O27: it took the LAST summary and said nothing when
    # there was more than one, which is how a log holding two runs printed a
    # figure that measured neither. Same reader, one counted question added.
    detail=$(suite_summary ".battery/$n.log")
  fi
  printf ' %-18s exit %-3s %s\n' "$n" "$c" "${detail:-}"
done
echo "════════════════════════════════════════════════════"

# ── the published figures, against what this run MEASURED ──────────────────
# The preflight checks that every surface publishing a figure AGREES with the
# others. That cannot catch the case where they are all stale TOGETHER, which
# is the one that actually happened: `CLAUDE.md` published 335 e2e checks
# while the suite ran 348, and every surface was consistent with every other.
# Only a run knows the true number, so the comparison belongs here.
#
# Suites that did not run in THIS invocation are skipped — a subset run
# (`bash tests/battery.sh test`) must not report the other seven as drifted,
# which would be an alarm that fires on correct usage.
FIGURE_DRIFT=""
for i in "${!NAMES[@]}"; do
  n="${NAMES[$i]}"
  published=$(grep -oE "docker compose run --rm $n .*\([0-9]+ checks" CLAUDE.md 2>/dev/null \
              | sed -E 's/.*\(([0-9]+) checks/\1/' | head -1)
  [ -z "$published" ] && continue
  line=$(suite_summary ".battery/$n.log")
  measured=$(sed -E 's/.*results: ([0-9]+) passed, ([0-9]+) failed.*/\1 \2/' <<< "$line")
  case "$measured" in
    *" "*) measured=$(( ${measured%% *} + ${measured##* } )) ;;
    *)     continue ;;
  esac
  [ "$measured" -eq 0 ] && continue
  if [ "$measured" != "$published" ]; then
    FIGURE_DRIFT="$FIGURE_DRIFT  $n: CLAUDE.md publishes $published, this run measured $measured\n"
  fi
done

# **The cargo figure needs its own comparison, and finding that out is how
# this gate learned its own scope.** The loop above matches `(N checks`, and
# cargo publishes none — it is `(N run,` plus a compiled total in `CLAUDE.md`
# and a `cargo tests` tile on the landing page. So the first version of this
# check covered every suite EXCEPT the one whose number moves most often, and
# the unit that added it moved that number in the same commit. A gate whose
# scope is narrower than it reads is the defect this file keeps closing.
if printf '%s\n' "${NAMES[@]}" | grep -qx test; then
  tline=$(test_summary ".battery/test.log")
  tpass=$(sed -E 's/^([0-9]+) passed.*/\1/' <<< "$tline")
  tign=$(sed -E 's/.*, ([0-9]+) ignored.*/\1/' <<< "$tline")
  case "$tpass" in
    ''|*[!0-9]*) : ;;   # the reader said something else; it names its own failure
    *)
      cm_run=$(grep -oE 'integration tests \([0-9]+ run' CLAUDE.md | grep -oE '[0-9]+' | head -1)
      cm_comp=$(grep -oE '= [0-9]+ compiled' CLAUDE.md | grep -oE '[0-9]+' | head -1)
      tile=$(grep -oE 'data-count="[0-9]+">0</div><div class="l">cargo tests' "$LANDING" \
             | grep -oE '[0-9]+' | head -1)
      if [ -n "$cm_run" ] && [ "$cm_run" != "$tpass" ]; then
        FIGURE_DRIFT="$FIGURE_DRIFT  cargo tests: CLAUDE.md publishes $cm_run run, this run measured $tpass\n"
      fi
      if [ -n "$cm_comp" ] && [ -n "$tign" ]; then
        want=$(( tpass + tign ))
        [ "$cm_comp" != "$want" ] && FIGURE_DRIFT="$FIGURE_DRIFT  cargo tests: CLAUDE.md publishes $cm_comp compiled; run+ignored is $want\n"
      fi
      if [ -n "$tile" ] && [ "$tile" != "$tpass" ]; then
        FIGURE_DRIFT="$FIGURE_DRIFT  cargo tests: the landing tile publishes $tile, this run measured $tpass\n"
      fi
      ;;
  esac
fi

if [ -n "$FIGURE_DRIFT" ]; then
  echo ""
  echo "PUBLISHED FIGURES ARE STALE — the suites passed; the numbers describing"
  echo "them did not. This is a doc-drift verdict, NOT a suite failure:"
  printf "$FIGURE_DRIFT"
  echo "      Update CLAUDE.md, then the landing page tile (its e2e figure is the"
  echo "      SUM of the four e2e suites) and any doc republishing the count."
  OVERALL=1
fi

if [ "$OVERALL" -eq 0 ]; then
  echo "BATTERY OK — every suite exited 0"
else
  echo "BATTERY FAILED — see the non-zero codes above; logs in .battery/"
fi
exit "$OVERALL"
