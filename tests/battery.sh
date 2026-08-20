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
ALL=(lint obs-config arch-check test e2e orchestrator-e2e e2e-telemetry backends-e2e site tls-pins)

# `--preflight-only` exists so CI can run the host-side preflights without
# Docker. They are host-side because no image carries `ROADMAP.md`, the
# compose files or `.gitattributes`' whole scope — and until this flag existed
# they therefore ran NOWHERE on a pull request, since `ci.yml` named this
# script only inside comments. A gate that runs only where its author
# remembers to run it is a gate the next person does not have.
PREFLIGHT_ONLY=0
NO_PREFLIGHT=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --preflight-only) PREFLIGHT_ONLY=1 ;;
    # `--no-preflight` is the mirror image, and it exists for CI. Each matrix
    # leg runs ONE suite through this script rather than calling `docker
    # compose run` itself, so that the post-run check-count comparison — which
    # only a RUN can perform, and which therefore cannot be a preflight —
    # happens on a pull request instead of only on the maintainer's machine.
    # Without this flag every leg would re-run all twelve preflights, which
    # the dedicated `preflight` job already does once. ROADMAP M13.
    --no-preflight) NO_PREFLIGHT=1 ;;
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

# Suites that legitimately print no `<suite> results: N passed, M failed` line,
# so the O27 reader's "this reader examined nothing" is the WRONG message for
# them rather than a finding. `lint` is silent on success by construction;
# `arch-check` has three verification stages rather than a countable
# population, and inventing a metric so it could satisfy a reader is how a
# figure stops meaning anything. Both also publish no check count, which is
# consistent: nothing to compare, so nothing skipped silently.
NO_SUMMARY_SUITES=(lint arch-check)

if [ "$PREFLIGHT_ONLY" -eq 1 ] && [ "$NO_PREFLIGHT" -eq 1 ]; then
  echo "--preflight-only and --no-preflight are contradictory" >&2
  exit 1
fi

# Everything between here and the `--preflight-only` exit is the host-side
# preflight block. It is wrapped rather than re-indented DELIBERATELY: shell
# does not care about indentation, and re-indenting ~1,300 lines to add one
# condition would bury this change in a diff nobody could read — which is the
# hazard CLAUDE.md records about a 100-line edit showing as 1,415 lines.
if [ "$NO_PREFLIGHT" -eq 0 ]; then

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
# direction. Both are named here because the probe below is shaped by them:
#   * `grep -qU $'\r'` inside a `while read` subshell — the `$'\r'` never
#     expanded, so the pattern was empty, `grep -q ''` matched every file and
#     the check declared the whole repo corrupt (false POSITIVE);
#   * `awk 'index($0, cr)'` — awk on Windows treats CRLF as the line
#     terminator and strips the CR before `$0` is seen, so a fully-CRLF file
#     read as clean (false NEGATIVE).
# A check whose output does not measure what it claims is the same defect
# whichever way it points.
# The selection, as a FUNCTION so the probe below runs the SAME code rather
# than a second copy of it (ROADMAP O55). It reads `git ls-files --eol` output
# on stdin and prints the offending paths.
#
# The attribute is field 4, not 3 (`i/lf  w/crlf  attr/text=auto  eol=lf`) —
# matching on `$3` was this check's third bug and read every file as clean.
# Hence `$0`.
crlf_offenders() {
  awk '$2 == "w/crlf" && $0 ~ /eol=lf/ { print $NF }' | grep -v '^crates/' || true
}

# **The premise probe, in BOTH directions** (ROADMAP O55, round-four #37).
# This check had none — while the comment above it claimed the two historical
# failure modes were "exercised below rather than assumed", which they were
# not. A false claim about a gate is worse than a missing gate: a reader
# asking "is this probed?" reads the sentence and stops. Three versions of
# this check were broken and two of them read a dirty tree as CLEAN, which is
# indistinguishable from a clean tree in the output.
CRLF_PROBE=$(printf '%s\n' \
  'i/lf	w/crlf	attr/text=auto eol=lf	tests/dirty.sh' \
  'i/lf	w/lf	attr/text=auto eol=lf	tests/clean.sh' \
  'i/	w/	attr/-text	assets/binary.png' \
  'i/lf	w/crlf	attr/text=auto eol=lf	crates/excluded.rs' \
  | crlf_offenders)
if [ "$CRLF_PROBE" != "tests/dirty.sh" ]; then
  echo "FAIL  the CRLF selector does not select. On a fixture holding one CRLF"
  echo "      offender, one clean file, one binary and one crates/ path it"
  echo "      should print exactly 'tests/dirty.sh'; it printed:"
  printf '        %s\n' ${CRLF_PROBE:-<nothing>}
  echo "      A scanner that matches nothing reports exactly what a clean tree"
  echo "      reports, and this check has been broken that way twice before."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
CRLF_HITS=$(git ls-files --eol 2>/dev/null | crlf_offenders)
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
fi  # pause the preflight block: the readers below are shared with the RUN

# ---------------------------------------------------------------------------
# THE SHARED READERS. Everything from here to `suite_count` is used by BOTH
# the preflights above and the post-run comparison at the bottom, so it is
# defined OUTSIDE the `--no-preflight` wrap. Leaving them inside was my own
# defect and the run said so rather than the reading: `--no-preflight` printed
# `suite_summary: command not found` and `suite_count: command not found`, and
# the battery still exited 0 — the comparison silently examined nothing while
# reporting exactly what a clean tree reports. ROADMAP M13.
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

# What a suite's check count is PUBLISHED as. Defined here, beside the reader
# that measures it, because TWO phases ask the question and they used to ask
# it with two different implementations: the `published figures` preflight
# (do the surfaces agree with each other?) and the post-run comparison (does
# the run agree with the surfaces?). The second grew its own compose-shaped
# copy, so a host-side suite — `tls-pins`, published as
# `bash tests/tls-pins.sh … (N checks)` — resolved to an empty string there
# and was skipped: published, measured, and never compared. ROADMAP M13.
#
# `grep -oE` + `sed -E`, deliberately NOT awk's three-argument `match()`:
# that is a GNU extension and Ubuntu's default awk is mawk, which lacks it.
# CI runs this on ubuntu-latest, so the gawk form would read empty there.
declare_suite_counts() {
  # Compose-invoked suites, as CLAUDE.md publishes them.
  grep -oE 'docker compose run --rm [a-z0-9-]+.*\([0-9]+ checks' CLAUDE.md 2>/dev/null \
    | sed -E 's/docker compose run --rm ([a-z0-9-]+).*\(([0-9]+) checks/\1=\2/'
  # Host-side suites publish the same figure and are INVOKED differently, so
  # the reader above cannot see them. Both shapes or the gate is notation-
  # shaped rather than coverage-shaped.
  grep -oE 'bash tests/[a-z0-9-]+[.]sh.*[(][0-9]+ checks' CLAUDE.md 2>/dev/null \
    | sed -E 's#bash tests/([a-z0-9-]+)[.]sh.*[(]([0-9]+) checks#\1=\2#'
}
SUITE_COUNTS=$(declare_suite_counts)
suite_count() { grep -oE "^$1=[0-9]+" <<< "$SUITE_COUNTS" | head -1 | cut -d= -f2; }

if [ "$NO_PREFLIGHT" -eq 0 ]; then  # resume the preflight block

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

# ROADMAP O47 (round-four #36). This gate was ONE-DIRECTIONAL: it flagged a
# body saying CLOSED under a heading that did not, and could not flag the
# opposite — a heading claiming CLOSED over work that is not done. That is
# the direction a session WRITING closures gets wrong, and it underwrites
# every closure this campaign has recorded.
#
# **What is decidable, and what is not.** Whether the work is actually done is
# semantic; no textual gate decides it, and pretending otherwise would ship a
# scanner that reads as broader than it is (the O33 failure). Two proxies ARE
# decidable, and both were measured against the tree before being encoded:
#
#   * a closure must carry EVIDENCE — a gate, a test or a counterfactual.
#     Measured: 42 closed entries, 0 without. It is an invariant this file
#     already holds, so encoding it costs nothing and catches the closure
#     written in a hurry with nothing behind it.
#   * a closure must say WHEN. Measured: 1 legitimate exception, `CLOSED by
#     doctrine`, which is a ruling rather than a date and is named below.
#
# **What was REJECTED, and why it is recorded rather than attempted.** The
# obvious check — a CLOSED heading over a body still using open-work
# vocabulary ("Not scheduled", "Shape of a fix") — was built and measured at
# THREE false positives in 42, and `<details>` does not separate them: in
# O10, O20 and O25 that phrasing refers to OTHER work the entry mentions, not
# to its own status. At that rate the gate would be noise, and a noisy gate
# gets switched off (the O44 reasoning). Recorded as unreachable rather than
# shipped at 7% wrong.
#
# Note #36's own filing said this gate "examines 7 of ~25 `###` sections".
# Measured, it examines 47 of 60 — the 13 it skips are prose sections with no
# `[A-Z][0-9]+` id, which are correctly out of scope. The coverage half of
# that filing was stale; the one-directional half was right.
echo "═══ preflight: ROADMAP headings ═══"
ROADMAP_DRIFT=$(awk '
  function flush() {
    if (sec != "") {
      seen++
      if (body ~ /CLOSED/ && sec !~ /CLOSED/) print "body-closed-heading-open|" sec
      if (sec ~ /CLOSED/) {
        if (body !~ /[Gg]ate|[Cc]ounterfactual|test/) print "closure-without-evidence|" sec
        if (sec !~ /CLOSED [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/ &&
            sec !~ /CLOSED by doctrine/) print "closure-without-a-date|" sec
      }
    }
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
  while IFS='|' read -r kind sec; do
    [ -z "$kind" ] && continue
    case "$kind" in
      body-closed-heading-open)
        echo "FAIL  this entry says CLOSED in the body and not in the heading."
        echo "      A reader skims headings; one that contradicts its own section"
        echo "      is how an item that does not exist ends up in a handover:" ;;
      closure-without-evidence)
        echo "FAIL  this heading claims CLOSED and the body names no gate, test or"
        echo "      counterfactual. Every other closed entry here carries one, so"
        echo "      this is a closure with nothing behind it — the direction a"
        echo "      session writing closures gets wrong (ROADMAP O47):" ;;
      closure-without-a-date)
        echo "FAIL  this heading claims CLOSED without saying WHEN. Use"
        echo "      'CLOSED <yyyy-mm-dd>', or 'CLOSED by doctrine' for a ruling:" ;;
    esac
    printf '        %s\n' "$sec"
  done <<< "$ROADMAP_DRIFT"
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    every closed ROADMAP entry says so in its heading, with a date and"
echo "      its evidence (both directions; 'is the work done' stays semantic)"

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
# ── preflight: a declared CA pin must be READABLE by the engine ────────────
# The shipped observability stack could not start. Caddy writes its whole PKI
# as root — the CA cert 0600 inside directories at 0700, correctly, since that
# tree also holds the CA PRIVATE key — and the engine image runs as
# `USER undercroft` (uid 10001). So the declared pin was unreadable and the
# engine REFUSED to start, forever:
#
#   Error: the OTLP collector: the declared trust root
#   /tls/caddy/pki/authorities/local/root.crt could not be read:
#   Permission denied (os error 13)
#
# The refusal is right — `undercroft-net` never falls back to the public roots
# — so the defect is the PATH. Only the certificate needs sharing; the private
# key must not move. The fix exports the public root to a readable path, and
# this stops the deep path coming back.
#
# Host-side with its siblings: no image carries the compose files.
#
# **Scope, stated rather than implied.** This catches one class — a pin aimed
# inside a root-only PKI tree — for services running the ENGINE image, which
# is the only consumer with a non-root uid. The same deep path appears in
# dev/test recipes that run as root and are fine; narrowing on the image is
# what keeps this from failing them. It does NOT prove the stack starts; that
# needs a real bring-up, which is filed (ROADMAP M7) with its argument rather
# than pretended here.
echo "═══ preflight: CA pins are readable by the engine ═══"
CA_FAIL=0
CA_SEEN=0
for f in $(git ls-files '*docker-compose*.yml' 'deploy/**/*.yml' 2>/dev/null); do
  [ -f "$f" ] || continue
  # Only services that BUILD the engine image from this repo run as uid 10001.
  grep -q 'context: \.\./\.\.' "$f" || continue
  while IFS= read -r line; do
    case "$line" in *"#"*) continue ;; esac
    CA_SEEN=$((CA_SEEN + 1))
    case "$line" in
      *caddy/pki/*)
        echo "FAIL  $f declares a CA pin inside Caddy's root-only PKI tree:"
        echo "        $(echo "$line" | sed 's/^ *//')"
        echo "      The engine runs as uid 10001; that tree is root:0600 inside"
        echo "      0700 dirs, so the pin is unreadable and the engine refuses"
        echo "      to start. Export the PUBLIC root to a readable path instead"
        echo "      — the CA private key must not move."
        CA_FAIL=1 ;;
    esac
  done <<EOF
$(grep -nE 'UNDERCROFT_[A-Z0-9_]*_CA:' "$f" || true)
EOF
done
# PREMISE. A scanner that matched no declaration at all reports exactly what a
# correct tree reports, which is the failure this whole family is about.
if [ "$CA_SEEN" -eq 0 ]; then
  echo "FAIL  found no UNDERCROFT_*_CA declaration in any engine-building"
  echo "      compose file. This scanner examined nothing, which is not the"
  echo "      same as a tree with no pins."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
if [ "$CA_FAIL" -ne 0 ]; then
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    $CA_SEEN declared CA pin(s) on engine services, none inside a"
echo "      root-only PKI tree"

# ── preflight: a destructive compose teardown names the project it destroys ─
# ROADMAP M12. A compose teardown carrying the volumes flag removes every
# NAMED volume in the project it resolves to. With no `-p` and no `-f` that
# project is whatever `./docker-compose.yml` declares — here, `undercroft`,
# which is the developer's own — so the command reaches state that has nothing
# to do with the suite asking for it. The battery's own backends reset did
# exactly that: it destroyed the embedding model cache, the compose palace and
# the embeddings CA on every run, none of which any backend needs fresh.
#
# This is ROADMAP M10's lesson generalised. M10 fixed `tests/tls-pins.sh` by
# giving each stack a throwaway project after its first version destroyed a
# live observability stack an hour after it was committed; the same file's
# teardowns are the shape this gate ACCEPTS, and the battery's was the shape
# it rejects. A scoped teardown is fine at any blast radius, because the
# project name says what the radius is.
#
# SCOPE, stated rather than implied: `tests/*.sh` only. That is where this
# repo drives docker from — no image carries these scripts, so no `cargo test`
# can read them. It deliberately does NOT scan `deploy/` (those compose files
# are declarations, not drivers) or the workflows (CI runs compose services,
# never a teardown). A driver added anywhere else is outside this gate, and
# that is a real limit rather than an oversight.
echo "═══ preflight: destructive compose scope ═══"
# The needle is ASSEMBLED so this gate does not match its own source. That is
# the "a gate whose own text is part of what it measures" trap, this tree's
# most-repeated gate defect — ROADMAP M1 is the most recent instance and
# records four earlier ones for gates reading their own inventory FILE, M1
# itself being the first for a gate reading the function it guards. No count
# is asserted here beyond what M1 counted: the figure is in M1, and repeating
# it in a second place is how a number in prose goes stale.
# Written contiguously, the pattern below would match the line that defines it.
TD_VERB="do""wn"
# The arguments between `compose` and the verb are OPTIONAL, and getting that
# wrong is how the first version of this gate passed on the very line it was
# written to catch. Requiring a token there (`compose[[:space:]].*[[:space:]]`)
# means the unscoped form — where the verb follows `compose` directly — never
# matches, while every SCOPED form does, because `-p <proj> -f <file>` fills
# the gap. The gate then reported "every teardown is scoped" having examined
# only the teardowns that were already scoped. Caught by the counterfactual,
# not by reading it: this is the tree's own "ask what a gate can SEE, not what
# it asserts" rule landing on a gate written to enforce that rule.
TD_SCAN=$(grep -nE "docker[[:space:]]+compose[[:space:]]+(.*[[:space:]]+)?${TD_VERB}([[:space:]]|\$)" \
            tests/*.sh 2>/dev/null || true)
# Only the ones that carry the volumes flag destroy named volumes; a plain
# teardown removes containers and networks and is not this defect.
TD_HITS=$(printf '%s\n' "$TD_SCAN" | grep -E '[[:space:]](-v|--volumes)([[:space:]]|$)' || true)
TD_TOTAL=$(printf '%s\n' "$TD_HITS" | grep -c . || true)
# PREMISE. A scanner that matched nothing reports exactly what a clean tree
# reports — the failure this whole family is about, and the reason M7's CA
# gate refuses to pass on zero declarations. `tests/tls-pins.sh` has carried
# two scoped teardowns since M10, so zero here means the pattern broke, not
# that the tree is clean.
if [ "${TD_TOTAL:-0}" -lt 1 ]; then
  echo "FAIL  the teardown scan matched no compose teardown anywhere in tests/."
  echo "      tests/tls-pins.sh has carried two since ROADMAP M10, so this is a"
  echo "      broken scanner rather than a clean tree — and a broken scanner"
  echo "      reports what a clean tree reports."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
TD_FAIL=0
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  # An explicit project scope is the whole discriminator: it is what makes the
  # blast radius a stated one instead of an inherited one.
  if ! printf '%s\n' "$hit" | grep -qE '[[:space:]](-p|--project-name)[[:space:]]'; then
    echo "FAIL  this teardown destroys every named volume of whatever project it"
    echo "      resolves to, and it names no project — so it inherits the one"
    echo "      ./docker-compose.yml declares, which is the developer's own:"
    printf '        %s\n' "$hit"
    TD_FAIL=1
  fi
done <<< "$TD_HITS"
if [ "$TD_FAIL" -ne 0 ]; then
  echo ""
  echo "      Scope it with -p <throwaway-project> as tests/tls-pins.sh does,"
  echo "      or narrow it to the services you mean with 'rm -sfv <service>...',"
  echo "      which takes their anonymous volumes and leaves named ones alone."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    $TD_TOTAL destructive compose teardown(s) in tests/, every one"
echo "      scoped to a project it names"

echo "═══ preflight: published figures ═══"

LANDING="website/landing/index.html"
# label|class|source
PUBLISHED_FIGURES=(
  "cargo tests|measured|test"
  "e2e checks|measured|SUM:e2e,orchestrator-e2e,e2e-telemetry,backends-e2e,tls-pins"
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
# The reader itself is DEFINED ABOVE, beside `suite_summary`, because two
# phases need it: this preflight (do the surfaces agree with each other?) and
# the post-run comparison (does the run agree with the surfaces?). It lived
# here, inside the preflight, and the post-run block therefore grew its own
# second, compose-only copy — which could not see `tls-pins`. ROADMAP M13.
if [ -z "$SUITE_COUNTS" ]; then
  echo "FAIL  no per-suite check counts found in CLAUDE.md — the reader is broken,"
  echo "      and a broken reader agrees with every page it cannot read"
  FIG_FAIL=1
fi

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

# ── preflight: every version surface states the version the tree IS ────────
# **A version in prose is the same class of claim as a count in prose**, and
# the release flow was carrying it in someone's head. `CLAUDE.md` listed the
# surfaces a version bump touches — `Cargo.toml`, `Cargo.lock`,
# `plugin.json`, CHANGELOG, ROADMAP, the landing hero button — and the 1.0.0
# release commit (`6976983`) actually moved EIGHT, four of them not on that
# list. The 1.1.0 release-prep commit then bumped the six it named plus
# `CLAUDE.md`'s own sentence from memory, and left `architecture/index.html`
# stating the PREVIOUS version in all three of its places. That is the
# signature of a hand-recalled inventory: it drifts toward whatever the last
# person remembered, and nothing can say so.
#
# Note the markers below are split wherever this file has to NAME one, so the
# scan reads its own source clean instead of being excluded by path — the
# `verify-no-trace.py` precedent. Excluding it would make a real version claim
# in the battery itself invisible, which is the failure one level up.
#
# So: the same mechanism `PUBLISHED_FIGURES` uses one preflight up, on the
# other number this project publishes about itself. The source of truth is
# the workspace `Cargo.toml` version — not a literal repeated here, because a
# gate holding its own copy of the answer is a second place for it to be
# wrong.
#
# **Two classes, because these claims do not have one provenance.**
#   current — states the version the tree IS. Must equal the workspace
#             version; this is the arm that catches a forgotten bump.
#   as-of   — states when something was last VERIFIED ("updated for vX.Y.Z").
#             Deliberately NOT bumped: moving it asserts a re-verification
#             nobody performed, which is the doc-claim-as-evidence failure
#             this project's first rule is about. Checked only for naming a
#             release that exists, and reported so it stays visible.
#
# **Scope, stated so it is not mistaken for complete.** This finds a version
# behind one of the three IDENTITY MARKERS below. A surface that states the
# version some new way — "Undercroft 1.2", a badge, a JSON field — is
# invisible to it, and the honest close for that is a row here when it is
# written, not a wider regex that would sweep in the CHANGELOG's history and
# every `since 1.0.0` in the docs. Both halves of that boundary are probed
# below rather than asserted.
echo "═══ preflight: version surfaces ═══"

WS_VERSION=$(awk '/^\[workspace\.package\]/{p=1;next} p&&/^\[/{p=0} p&&/^version *=/{gsub(/[^0-9.]/,"");print;exit}' Cargo.toml)
if ! printf '%s' "$WS_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "FAIL  could not read the workspace version from Cargo.toml (got '$WS_VERSION')."
  echo "      Every comparison below is against it, so a broken read would compare"
  echo "      every surface to nothing and pass."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi

VER_IDENT='([Ee]ngine v|updated for v|releases/latest">v|"version": "|Current release \*\*)[0-9]+\.[0-9]+\.[0-9]+'
# label|class|file|pattern|count
#
# **The two entries at the bottom were named by `CLAUDE.md`'s release flow and
# counted by nothing** until the `1.1.1` cut (ROADMAP O60). That list says a
# version bump touches the plugin manifest and this file's own "Current
# release" sentence; this inventory covered three surfaces and neither of
# them. So the gate the doctrine points at — *"prose above, gate below, and
# the gate is the one to trust"* — was NARROWER than the prose pointing at it,
# which is the O24 shape: several documents describe a coverage the code does
# not have. Found by running the release, which is the only thing that
# exercises this path.
VERSION_SURFACES=(
  'architecture engine version|current|architecture/index.html|[Ee]ngine v|3'
  'landing release button|current|website/landing/index.html|releases/latest">v|1'
  'parity comparison as-of|as-of|docs/PARITY.md|updated for v|1'
  'plugin manifest|current|.claude-plugin/plugin.json|"version": "|1'
  'doctrine current-release sentence|current|CLAUDE.md|Current release \*\*|1'
)

# PREMISE, both directions. A matcher that finds nothing reports what a fully
# bumped tree reports, and a matcher that finds everything would "cover" the
# docs by flagging prose. Neither zero is believed until this passes.
PROBE_V='9.9.9'
PROBE_HIT=$(printf '%s\n' "  <p class=\"sb-foot\">Engine v${PROBE_V} · BUSL-1.1</p>" \
            | grep -oE "$VER_IDENT" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
if [ "$PROBE_HIT" != "$PROBE_V" ]; then
  echo "FAIL  the version extractor did not match a known-positive (got '$PROBE_HIT')."
  echo "      It examined nothing, which is not the same as a tree with no drift."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
if printf '%s\n' 'the columns were clear TEXT before 1.0.0 (ROADMAP A10)' \
   | grep -qE "$VER_IDENT"; then
  echo "FAIL  the version extractor matched historical prose. Widened this far it"
  echo "      would flag every 'since 1.0.0' in the docs, and a gate that cries"
  echo "      wolf on the CHANGELOG gets switched off."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi

VER_FAIL=0
# Direction 1: every file carrying a version identity has a row. This is the
# arm that stops a NEW ungated surface from shipping — the one a hand list
# cannot do, because nobody knows to add to it.
#
# `--untracked` is load-bearing and was measured, not assumed: without it a
# file states its version invisibly until someone runs `git add`, so the
# author who wrote it gets a green battery and the gate only bites in CI. It
# still honours `.gitignore`, so `.handover/`, `.battery/` and `target/` stay
# out — verified to return the identical file set on a clean tree, i.e. it
# widens coverage without buying noise.
VER_FILES=$(git grep -l --untracked -E "$VER_IDENT" -- . || true)
VER_FILE_N=$(printf '%s\n' "$VER_FILES" | grep -c . || true)
if [ "${VER_FILE_N:-0}" -lt 1 ]; then
  echo "FAIL  no file in the tree carries a version identity. The three markers"
  echo "      have all moved, so this preflight is now scanning for nothing."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
while IFS= read -r f; do
  [ -z "$f" ] && continue
  found=0
  for row in "${VERSION_SURFACES[@]}"; do
    IFS='|' read -r _l _c rfile _p _n <<< "$row"
    [ "$rfile" = "$f" ] && found=1
  done
  if [ "$found" -eq 0 ]; then
    echo "FAIL  $f states a version and has no VERSION_SURFACES row — classify it"
    echo "      (current / as-of) so the next release knows whether to move it"
    VER_FAIL=1
  fi
done <<< "$VER_FILES"

# Direction 2: every row still names a live surface, at the count it declares.
# A row whose pattern has stopped matching reads as a checked surface while
# checking nothing — the same stale-row failure PUBLISHED_FIGURES guards.
for row in "${VERSION_SURFACES[@]}"; do
  IFS='|' read -r label class rfile pat want <<< "$row"
  if [ ! -f "$rfile" ]; then
    echo "FAIL  VERSION_SURFACES names $rfile ($label), which does not exist"
    VER_FAIL=1
    continue
  fi
  got=$(grep -oE "$pat[0-9]+\.[0-9]+\.[0-9]+" "$rfile" | grep -c . || true)
  if [ "${got:-0}" -ne "$want" ]; then
    echo "FAIL  $label: $rfile carries $got version claim(s), the row declares $want."
    echo "      Either a surface was added without a row, or one was removed and"
    echo "      the row outlived it"
    VER_FAIL=1
    continue
  fi
  vers=$(grep -oE "$pat[0-9]+\.[0-9]+\.[0-9]+" "$rfile" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
  for v in $vers; do
    case "$class" in
      current)
        if [ "$v" != "$WS_VERSION" ]; then
          echo "FAIL  $label: $rfile says v$v, the workspace says $WS_VERSION."
          echo "      A release bumped the version and did not move this surface"
          VER_FAIL=1
        fi
        ;;
      as-of)
        # Not compared to the workspace ON PURPOSE — see the class note above.
        # It must still name a release that happened, or it is not an as-of
        # marker, it is a typo wearing one's clothes.
        if ! grep -qE "^## $v( |\$)" CHANGELOG.md; then
          echo "FAIL  $label: $rfile is marked as-of v$v, which is not a release"
          echo "      heading in CHANGELOG.md"
          VER_FAIL=1
        else
          echo "note  $label: $rfile records v$v (as-of; not bumped by a release —"
          echo "      moving it asserts a re-verification, so it moves when someone"
          echo "      re-verifies it, and the workspace is $WS_VERSION)"
        fi
        ;;
      *)
        echo "FAIL  $label: unknown class '$class' (want: current / as-of)"
        VER_FAIL=1
        ;;
    esac
  done
done

if [ "$VER_FAIL" -ne 0 ]; then
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    every version surface agrees with the workspace ($WS_VERSION), over $VER_FILE_N file(s)"

# ── preflight: a figure in prose is counted against the tree ───────────────
# ROADMAP O42, and it was filed because `CLAUDE.md` claimed "seven host-side
# preflights" while the tree ran eight, and nothing could say so. Closing it
# immediately paid for itself: the SAME sweep found that the architecture
# reference's coverage figure had been rewritten from a correct value to a
# wrong one (`all 81` / `17 abbreviated` -> `72 of the 81` / `8` / `9 absent`)
# by a round-five item whose entire purpose was correcting that figure. See
# ROADMAP O43.
#
# `PUBLISHED_FIGURES` above covers the landing page's tiles and the per-suite
# check counts. This covers the OTHER class: numbers the doctrine states about
# the tree in prose, which nothing recomputes.
#
# **The env-variable figures need ROW-SCOPED attribution, and that is the
# whole lesson of O43.** The architecture page abbreviates a family of
# variables to bare suffixes inside the row that owns them
# (`UNDERCROFT_ORCH_ADDR . _DB . _KEY . ...`). Counting only full names
# undercounts by 17; counting suffixes GLOBALLY credits `_NAME` from the ONNX
# row to `UNDERCROFT_COLBERT_NAME`, a different variable in a different row.
# Neither observable distinguishes documented from absent. The reconstruction
# below pairs each suffix only with full names in ITS OWN row, and it was
# cross-checked against an independent implementation in a second language
# before being believed — both return 64 + 17 + 0.
echo "═══ preflight: prose figures ═══"

pf_word() {
  case "$1" in
    one) echo 1;; two) echo 2;; three) echo 3;; four) echo 4;; five) echo 5;;
    six) echo 6;; seven) echo 7;; eight) echo 8;; nine) echo 9;; ten) echo 10;;
    eleven) echo 11;; twelve) echo 12;; thirteen) echo 13;; fourteen) echo 14;;
    fifteen) echo 15;; sixteen) echo 16;; seventeen) echo 17;;
    eighteen) echo 18;; nineteen) echo 19;; twenty) echo 20;;
    *) echo "$1";;
  esac
}

PF_ARCH="architecture/index.html"
PF_STORE="crates/undercroft-store/src/lib.rs"

# The engine's variables, from the crates. `undercroft-bench` is excluded
# because its UNDERCROFT_VS_*/UNDERCROFT_TEST_* belong to the harness, which
# is the same boundary CLAUDE.md's own counting recipe draws.
PF_VARS=$(git grep -hoE '"UNDERCROFT_[A-Z0-9_]+"' -- crates/ ':!crates/undercroft-bench' \
          | tr -d '"' | sort -u)
PF_ENV_TOTAL=$(printf '%s\n' "$PF_VARS" | grep -c . || true)

# Row-scoped reconstruction: family prefix of a full name in a row, joined to
# every bare suffix in the SAME row.
PF_RECON=$(awk '
  /<code>UNDERCROFT_/ {
    nf = 0; ns = 0; tmp = $0
    while (match(tmp, /<code>UNDERCROFT_[A-Z0-9_]+<\/code>/)) {
      fulls[++nf] = substr(tmp, RSTART + 6, RLENGTH - 13)
      tmp = substr(tmp, RSTART + RLENGTH)
    }
    tmp = $0
    while (match(tmp, /<code>_[A-Z0-9_]+<\/code>/)) {
      sufs[++ns] = substr(tmp, RSTART + 6, RLENGTH - 13)
      tmp = substr(tmp, RSTART + RLENGTH)
    }
    for (i = 1; i <= nf; i++) {
      f = fulls[i]; k = 0
      for (j = length(f); j > 0; j--) if (substr(f, j, 1) == "_") { k = j; break }
      if (k > 1) { fam = substr(f, 1, k - 1)
        for (m = 1; m <= ns; m++) print fam sufs[m] }
    }
    for (i = 1; i <= nf; i++) delete fulls[i]
    for (m = 1; m <= ns; m++) delete sufs[m]
  }' "$PF_ARCH" | sort -u)

PF_ENV_FULL=0; PF_ENV_ABBREV=0; PF_ENV_ABSENT=0; PF_ABSENT_LIST=""
while IFS= read -r v; do
  [ -z "$v" ] && continue
  if grep -q "<code>$v</code>" "$PF_ARCH"; then
    PF_ENV_FULL=$((PF_ENV_FULL + 1))
  elif printf '%s\n' "$PF_RECON" | grep -qx "$v"; then
    PF_ENV_ABBREV=$((PF_ENV_ABBREV + 1))
  else
    PF_ENV_ABSENT=$((PF_ENV_ABSENT + 1)); PF_ABSENT_LIST="$PF_ABSENT_LIST $v"
  fi
done <<< "$PF_VARS"

PF_PREFLIGHTS=$(grep -c '^echo "═══ preflight:' tests/battery.sh || true)
PF_CRATES=$(find crates -mindepth 1 -maxdepth 1 -type d | grep -c . || true)
PF_MCP=$(awk '/pub const MCP_TOOLS/,/^\];/' crates/undercroft-cli/src/parity.rs \
         | grep -cE '^\s*"undercroft_[a-z_]+",' || true)
PF_DIAGRAMS=$(find architecture/diagrams -name '*.svg' | grep -c . || true)
PF_IRREGULAR=$(awk '/^const IRREGULAR/,/^\];/' "$PF_STORE" | grep -oE '\),' | grep -c . || true)

# PREMISE. Every truth below is a count, and a broken extractor returns a
# number too — zero. A zero here would silently agree with nothing.
if [ "${PF_ENV_TOTAL:-0}" -lt 50 ] || [ "${PF_PREFLIGHTS:-0}" -lt 5 ] ||
   [ "${PF_CRATES:-0}" -lt 5 ] || [ "${PF_MCP:-0}" -lt 10 ] ||
   [ "${PF_DIAGRAMS:-0}" -lt 5 ] || [ "${PF_IRREGULAR:-0}" -lt 50 ]; then
  echo "FAIL  a truth-side reader came back implausibly small:"
  echo "      env=$PF_ENV_TOTAL preflights=$PF_PREFLIGHTS crates=$PF_CRATES"
  echo "      mcp=$PF_MCP diagrams=$PF_DIAGRAMS irregular=$PF_IRREGULAR"
  echo "      A reader that examined nothing reports what an accurate tree reports."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
if [ "$((PF_ENV_FULL + PF_ENV_ABBREV + PF_ENV_ABSENT))" -ne "$PF_ENV_TOTAL" ]; then
  echo "FAIL  the env classification lost a variable:"
  echo "      $PF_ENV_FULL + $PF_ENV_ABBREV + $PF_ENV_ABSENT != $PF_ENV_TOTAL"
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi

# label|file|sed-with-one-capture|truth
PROSE_FIGURES=(
  "host-side preflights|CLAUDE.md|s/.*runs the ([a-z]+) host-side preflights.*/\\1/p|$PF_PREFLIGHTS"
  "workspace crates|CLAUDE.md|s/.*workspace root \\(([0-9]+) crates.*/\\1/p|$PF_CRATES"
  "MCP tools|CLAUDE.md|s/.*\\*\\*([0-9]+) tools \\(incl\\..*/\\1/p|$PF_MCP"
  "architecture diagrams|CLAUDE.md|s/.*reference: ([a-z]+) theme-aware.*/\\1/p|$PF_DIAGRAMS"
  "engine env variables|CLAUDE.md|s/.*plus \\*\\*all ([0-9]+)\\*\\*.*/\\1/p|$PF_ENV_TOTAL"
  "env vars written in full|CLAUDE.md|s/.*— \\*\\*([0-9]+)\\*\\* written out in.*/\\1/p|$PF_ENV_FULL"
  "env vars abbreviated|CLAUDE.md|s/.*plus \\*\\*([0-9]+)\\*\\* siblings abbreviated.*/\\1/p|$PF_ENV_ABBREV"
  "IRREGULAR pairs|CLAUDE.md|s/.*\\(\\*\\*([0-9]+) pairs.*/\\1/p|$PF_IRREGULAR"
)

PROSE_FAIL=0
for row in "${PROSE_FIGURES[@]}"; do
  IFS='|' read -r label pfile pat truth <<< "$row"
  raw=$(sed -nE "$pat" "$pfile" | head -1)
  if [ -z "$raw" ]; then
    echo "FAIL  $label: the reader found no published figure in $pfile."
    echo "      Either the sentence was reworded (update the row) or it was"
    echo "      deleted — a row that matches nothing checks nothing."
    PROSE_FAIL=1
    continue
  fi
  got=$(pf_word "$raw")
  if [ "$got" != "$truth" ]; then
    echo "FAIL  $label: $pfile publishes $raw, the tree measures $truth"
    PROSE_FAIL=1
  fi
done

# The round-four open-row heading against the rows it lists. Self-consistent
# and therefore mechanically checkable, unlike the rows' contents — and it
# drifted the day it was written (heading 8, list 9), which is why it is here.
RF_HEAD=$(grep -oE '^### Still open from round four — [0-9]+ verified rows' ROADMAP.md           | grep -oE '[0-9]+' | head -1)
if [ -n "$RF_HEAD" ]; then
  # ONLY the list paragraph — the prose beneath it names closed rows too
  # (`#26 is CLOSED by O48`), and sweeping those in made this gate's first
  # run report 11 for a list of 9. Start after the heading, skip blanks, stop
  # at the first blank line that follows content.
  RF_LIST=$(awk '/^### Still open from round four/{f=1;next}
                 f&&/^$/{ if (seen) exit; next }
                 f{ seen=1; print }' ROADMAP.md             | grep -oE '`#[0-9]+`' | sort -u | grep -c . || true)
  if [ "${RF_LIST:-0}" -lt 1 ]; then
    echo "FAIL  the round-four open list matched no rows — the paragraph moved,"
    echo "      and a reader that finds nothing must not agree with any heading"
    PROSE_FAIL=1
  elif [ "$RF_HEAD" != "$RF_LIST" ]; then
    echo "FAIL  round-four open rows: the heading says $RF_HEAD, the list holds $RF_LIST"
    PROSE_FAIL=1
  fi
fi

if [ "$PF_ENV_ABSENT" -ne 0 ]; then
  echo "note  $PF_ENV_ABSENT engine variable(s) appear on $PF_ARCH in no form:$PF_ABSENT_LIST"
fi
if [ "$PROSE_FAIL" -ne 0 ]; then
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    ${#PROSE_FIGURES[@]} prose figures agree with the tree"
echo "      (env: $PF_ENV_FULL full + $PF_ENV_ABBREV row-abbreviated + $PF_ENV_ABSENT absent = $PF_ENV_TOTAL)"

# ── the `/v1` surface: TWO documents describe it, and both must be complete ─
# ROADMAP O45. `docs/remote-server.md` said "All 35 routes, counted against
# `route()` ... rather than remembered" while `route()` dispatched 36: O14
# added `POST …/verify-forgetting`, updated `docs/AGENTS.md` §10, and did not
# update the other route reference. A doc that PROMISES it was counted is the
# worst place for a stale count, because the promise is what stops the reader
# checking.
#
# Sets, not sizes, and in BOTH directions — a count alone passes when one
# route is swapped for another. The `{id}` placeholders are normalised to the
# binding names `route()` uses so the two spellings can be compared at all.
V1_ARMS=$(awk '/match \(method\.as_str\(\), segs\.as_slice\(\)\)/,/^        }$/' \
            crates/undercroft-cli/src/tenant.rs \
          | grep -oE '\("(GET|POST|PUT|PATCH|DELETE)", &\["[^]]*\]\)' \
          | sed -E 's/\("([A-Z]+)", &\[(.*)\]\)/\1 \2/' | tr -d '"' | sed 's/, /\//g' | sort -u)
V1_N=$(printf '%s\n' "$V1_ARMS" | grep -c . || true)
# PREMISE: the dispatch is the authority here, so a failed read must not be
# allowed to agree with a doc that lists nothing either.
if [ "${V1_N:-0}" -lt 20 ]; then
  echo "FAIL  read $V1_N route(s) out of tenant.rs's dispatch; it has dozens."
  echo "      The match block moved or was reshaped — this reader examined nothing."
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi

v1_doc_routes() { # v1_doc_routes <file> <extractor-regex>
  grep -ohE "$2" "$1" \
    | sed -E 's/^\| *//; s/ *\| *`/ /; s/`//g; s/^([A-Z]+) +/\1 /' \
    | sed -e 's#/v1#v1#' -e 's#{drawer_id}#drawer_id#g' -e 's#{key}#key#g' \
          -e 's#{id}#id#g' -e 's#{[a-z_]*}#X#g' \
    | awk '{print $1" "$2}' | sort -u
}
V1_RS=$(v1_doc_routes docs/remote-server.md '^(GET|POST|PUT|PATCH|DELETE) +/v1/[a-z{}/_-]+')
V1_AG=$(v1_doc_routes docs/AGENTS.md '^\| *(GET|POST|PUT|PATCH|DELETE) *\| *`/v1/[^`]*`')

V1_FAIL=0
for pair in "docs/remote-server.md|$V1_RS" "docs/AGENTS.md|$V1_AG"; do
  dfile="${pair%%|*}"; dlist="${pair#*|}"
  dn=$(printf '%s\n' "$dlist" | grep -c . || true)
  if [ "${dn:-0}" -lt 20 ]; then
    echo "FAIL  $dfile: the route extractor found $dn route(s). The table's shape"
    echo "      changed, and an extractor that reads nothing agrees with everything."
    V1_FAIL=1
    continue
  fi
  missing=$(comm -23 <(printf '%s\n' "$V1_ARMS") <(printf '%s\n' "$dlist"))
  extra=$(comm -13 <(printf '%s\n' "$V1_ARMS") <(printf '%s\n' "$dlist"))
  if [ -n "$missing" ]; then
    echo "FAIL  $dfile does not document $(printf '%s\n' "$missing" | grep -c .) live route(s):"
    printf '        %s\n' $(printf '%s\n' "$missing" | tr ' ' '~') | tr '~' ' '
    V1_FAIL=1
  fi
  if [ -n "$extra" ]; then
    echo "FAIL  $dfile documents $(printf '%s\n' "$extra" | grep -c .) route(s) that no longer exist:"
    printf '        %s\n' $(printf '%s\n' "$extra" | tr ' ' '~') | tr '~' ' '
    V1_FAIL=1
  fi
done
if [ "$V1_FAIL" -ne 0 ]; then
  echo ""
  echo "BATTERY FAILED — preflight"
  exit 1
fi
echo "ok    both /v1 route references match the dispatch exactly ($V1_N routes)"

fi  # end of the host-side preflight block (`--no-preflight` skips it)

if [ "$PREFLIGHT_ONLY" -eq 1 ]; then
  echo ""
  echo "preflights only — no suite was run, by request (--preflight-only)"
  exit 0
fi

for suite in "${SUITES[@]}"; do
  # `tests/e2e-backends.sh` asserts exact record counts and therefore assumes
  # FRESH backends; a second run against warm volumes flakes. Documented in
  # CLAUDE.md, mechanised here so nobody has to remember it.
  #
  # The reset is NARROW, and that is the whole of ROADMAP M12. It used to be a
  # project-wide teardown with the volumes flag and no `-p`/`-f`, so it
  # resolved to ./docker-compose.yml — whose declared project is `undercroft`,
  # i.e. the DEVELOPER'S OWN project — and removed every named volume that file
  # declares. Three of the five were pure collateral: `undercroft-models` (the
  # multi-GB weights of the four served embedders this project measures with),
  # `undercroft-data` (the compose palace, i.e. any mined corpus), and
  # `undercroft-embed-tls` (the embeddings CA that CLAUDE.md's own published
  # pin recipe mounts — destroying it makes that recipe mount a fresh empty
  # volume silently, which is the failure the recipe's own warning describes).
  #
  # None of that is state this suite needs fresh, and none of the five backends
  # declares a named volume at all: qdrant, chroma, milvus and weaviate have no
  # `volumes:` key, and pgvector's only mount is a read-only cert. Their data
  # lives in ANONYMOUS volumes, which `rm -v` removes — so the narrow form
  # delivers everything the wide one did for this suite, and nothing else.
  #
  # The terminator is recreated too, so it cannot serve a cached upstream
  # address for a container that has just been replaced; its CA is a NAMED
  # volume, which `rm -v` deliberately does not touch, so the pin the suite
  # mounts survives and Caddy reuses it.
  #
  # ROADMAP M10 learned this for `tests/tls-pins.sh` — a private compose
  # project name does not scope a shared host resource — and the lesson was
  # not carried one file over to the battery's own teardown. Not silenced:
  # a reset that fails leaves warm backends, and this suite's failure mode is
  # then an unexplainable count assertion.
  if [ "$suite" = "backends-e2e" ]; then
    docker compose rm -sfv \
      qdrant chroma pgvector milvus weaviate backends-tls || true
  fi

  echo ""
  echo "═══ $suite ═══"
  # `tls-pins` brings real Caddy terminators up and reads their volumes as
  # the engine uid, so it DRIVES docker rather than running inside a
  # container — the same reason this script is the one thing that runs on
  # the host. As a compose service it would need docker-in-docker to check
  # a permission question that needs no build at all.
  if [ "$suite" = "tls-pins" ]; then
    mkdir -p .battery
    bash tests/tls-pins.sh 2>&1 | tee ".battery/$suite.log"
    code=${PIPESTATUS[0]}
    NAMES+=("$suite")
    CODES+=("$code")
    [ "$code" -eq 0 ] || OVERALL=1
    continue
  fi
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
  if printf '%s\n' "${NO_SUMMARY_SUITES[@]}" | grep -qx "$n"; then
    # **The suites with no summary line, NAMED rather than complained about.**
    # `cargo fmt --check` and `clippy` are silent on success, so `lint` has
    # never printed one — and the O27 reader below correctly answered "this
    # reader examined nothing", beside a green run, every time. That is a
    # message which misdescribes its own situation, and worse: it is the SAME
    # string that is a real signal for every other suite, so printing it
    # routinely teaches the reader to skip it. An alarm nobody can distinguish
    # from a real failure is the thing this project exists to remove.
    #
    # A SET rather than a second `elif`, because `arch-check` joining the
    # battery (ROADMAP M14) made this a class of two, and a class of two
    # written as two special cases becomes a class of three written as three.
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
  # ONE reader, shared with the preflight. This used to be a second,
  # compose-shaped grep written out here — `docker compose run --rm $n` — so
  # it could not see a suite INVOKED any other way. `tls-pins` is published as
  # `bash tests/tls-pins.sh … (7 checks)`, so `published` came back empty and
  # the `continue` below skipped it: published, measured, and never compared.
  # M10's own entry claims "the published-count reader was widened to see
  # host-side suites, or the figure would have been published, measured and
  # never compared" — true of the PREFLIGHT reader it widened, and false of
  # this one, which is the arm that catches the case the preflight cannot
  # (every surface stale TOGETHER). Two implementations of one lookup, and
  # only one of them got the fix. ROADMAP M13.
  published=$(suite_count "$n")
  [ -z "$published" ] && continue
  line=$(suite_summary ".battery/$n.log")
  measured=$(sed -E 's/.*results: ([0-9]+) passed, ([0-9]+) failed.*/\1 \2/' <<< "$line")
  case "$measured" in
    # The sed above leaves the line UNCHANGED when it does not match, so
    # `measured` can be a whole sentence — including `suite_summary`'s own
    # "no results line found — this reader examined nothing". That contains
    # spaces, so it used to reach the arithmetic as $(( no + nothing )) and
    # abort the script under `set -u`, MASKING the suite failure that
    # produced it. A reader that crashes on the failure path cannot report.
    *[!0-9[:blank:]]*) continue ;;
    *" "*) measured=$(( ${measured%% *} + ${measured##* } )) ;;
    *)     continue ;;
  esac
  # A suite that printed a summary and counted ZERO is the LOUDEST case, not
  # the quietest, and this skipped it. Reaching here means the summary parsed
  # as two numbers (the `case` above diverts every other shape), so
  # `0 passed, 0 failed` is a suite that ran and executed nothing — a checker
  # that cannot run reporting exactly what a clean tree reports, which is the
  # failure this whole file is about. It is reported as its own drift line
  # rather than folded into the mismatch below, because "measured 0 against a
  # published 370" is a different fact from "measured 369". ROADMAP M13.
  if [ "$measured" -eq 0 ]; then
    FIGURE_DRIFT="$FIGURE_DRIFT  $n: published $published, this run measured ZERO — the suite printed a summary having executed nothing\n"
    continue
  fi
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
  echo "      SUM of the FIVE e2e suites named in PUBLISHED_FIGURES) and any doc"
  printf '%s\n' "      republishing the count."
  OVERALL=1
fi

if [ "$OVERALL" -eq 0 ]; then
  echo "BATTERY OK — every suite exited 0"
else
  echo "BATTERY FAILED — see the non-zero codes above; logs in .battery/"
fi
exit "$OVERALL"
