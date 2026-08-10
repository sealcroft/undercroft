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
  if [ "$n" = "test" ]; then
    detail=$(awk '/^test result:/ { for (i=1;i<=NF;i++) {
                    if ($(i+1) ~ /^passed/) p+=$i
                    if ($(i+1) ~ /^failed/) f+=$i
                    if ($(i+1) ~ /^ignored/) g+=$i } }
                  END { printf "%d passed, %d failed, %d ignored (summed over %s targets)", p, f, g, "all" }' \
             ".battery/$n.log" 2>/dev/null)
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
    detail=$(grep -hoE '^[a-z0-9-]+( [a-z0-9-]+)* results: [0-9]+ passed, [0-9]+ failed' \
               ".battery/$n.log" 2>/dev/null | tail -1)
  fi
  printf ' %-18s exit %-3s %s\n' "$n" "$c" "${detail:-}"
done
echo "════════════════════════════════════════════════════"
if [ "$OVERALL" -eq 0 ]; then
  echo "BATTERY OK — every suite exited 0"
else
  echo "BATTERY FAILED — see the non-zero codes above; logs in .battery/"
fi
exit "$OVERALL"
