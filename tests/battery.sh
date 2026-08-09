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
SUITES=("${@:-}")
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
