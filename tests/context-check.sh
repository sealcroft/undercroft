#!/usr/bin/env bash
# Measure how much of the context window this session is actually using.
#
# WHY THIS EXISTS. The agent repeatedly announced it was "near the context
# budget" and stopped taking work, by FEEL. Measured on 2026-08-18 it was at
# 54% while claiming to be near the ~90% stop-line — wrong by a wide margin,
# repeatedly, across this whole project. The root cause was assuming a
# 200,000-token window when the real one is 1,000,000, so every estimate was
# out by ~2.7x in the direction that stops work early.
#
# That is this project's own first rule turned on the agent itself: a figure
# in prose is a claim about the moment someone last counted, and CLAUDE.md's
# context-budget rule ("stop taking new units at roughly 90%") is worthless if
# the 90% is guessed. Count the truth, never a number in prose.
#
# HOW IT MEASURES. Claude Code writes a JSONL transcript per session under
# ~/.claude/projects/<project-slug>/<session-id>.jsonl. Every assistant turn
# records the API's own `usage` object. The tokens occupying the window on the
# most recent turn are:
#
#     input_tokens + cache_creation_input_tokens + cache_read_input_tokens
#
# i.e. the whole prompt that was actually sent, cached or not. That number is
# MEASURED and carries no assumption.
#
# THE WINDOW IS THE ONE ASSUMPTION, and it is labelled as such rather than
# folded into the result, on the same reasoning as the `current` vs `as-of`
# split in the version-surface gate: a measured value and a declared one must
# not be presented as the same kind of thing. Override with CONTEXT_WINDOW.
#
# Usage:  bash tests/context-check.sh [session-id-or-path]
#         bash tests/context-check.sh --self-test          # needs a real transcript
#         bash tests/context-check.sh --check-derivation   # needs none; a preflight
#
# TRACKED, not in `.handover/` where it was first written. That directory is
# gitignored, so a fresh clone would not carry this and nothing would invoke
# it — the exact defect O10 fixed for the former-name verifier one directory
# over. A tool that only exists on one machine is a tool that will be lost.
set -uo pipefail

# Claude Code slugs the project directory by replacing every path separator
# (and the drive colon) with `-`. Derived rather than hard-coded: this file is
# TRACKED, and a tracked tool carrying one machine's absolute path is the
# defect O10 fixed one directory over.
#
# **This line was `A && B || C && D` from 2026-08-18 to 2026-09-04, and that
# parses as `((A && B) || C) && D` (ROADMAP O106)**: on a shell where `pwd -W`
# succeeds — Git Bash, i.e. the maintainer's machine — BOTH `pwd`s ran and
# `ROOT` was two lines, `C:/…` and `/c/…`. The slug inherited the newline and
# no directory could match it, so the documented invocation, the session-id
# form, always refused; the full-path form never touched the slug and worked,
# which is how the defect hid behind O104's self-test. On a shell without
# `pwd -W` only the second arm printed, so the line READ as though it worked.
# The braces make the alternation one command.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd; })"
case "$ROOT" in
  *$'\n'*)
    echo "CONTEXT CHECK FAILED — the project root resolved to more than one line:"
    printf '%s\n' "$ROOT" | sed 's/^/  /'
    echo "No transcript directory can match a slug with a newline in it (ROADMAP O106)."
    exit 1 ;;
esac
SLUG="$(printf '%s' "$ROOT" | sed -E 's#[:/\\]#-#g')"
# `CLAUDE_PROJECT_DIR` is deliberately NOT honoured: the harness sets it to the
# REPO root, which holds no `.jsonl`, and until O106 this line still read it —
# so under a hook the session-id form pointed at the wrong directory while the
# comment below said exactly that. Only `HOME` locates the transcripts.
PROJ="$HOME/.claude/projects/$SLUG"
WINDOW="${CONTEXT_WINDOW:-1000000}"

# **`--check-derivation` — the half of the self-test that needs NO transcript
# (ROADMAP O106's residual, closed 2026-09-05).** Two of `--self-test`'s arms
# copy a real transcript from under `~/.claude`, and a CI runner has none, so
# no battery preflight could run the self-test without skipping on an empty
# machine — the pass-on-nothing shape. This mode exercises exactly what O106
# got wrong, the ROOT → SLUG derivation, against evidence the checkout itself
# carries: the multi-line guard above has already run by the time control
# reaches here, and the slug must end in the basename git reports for the
# checkout this script is INVOKED from — an independent derivation, so a copy
# of this script living somewhere else fails instead of agreeing with itself.
if [ "${1:-}" = "--check-derivation" ]; then
  REPO="$(basename "$(git rev-parse --show-toplevel 2>/dev/null)")"
  if [ -z "$REPO" ]; then
    echo "CHECK-DERIVATION FAILED — not invoked from inside a git checkout, so"
    echo "there is nothing independent to compare the slug against."
    exit 1
  fi
  case "$SLUG" in
    *"-$REPO") ;;
    *)
      echo "CHECK-DERIVATION FAILED — the slug does not name this checkout:"
      echo "  root: $ROOT"
      echo "  slug: $SLUG"
      echo "  git:  $REPO"
      echo "A session-id lookup under ~/.claude/projects/ would read the wrong"
      echo "directory (ROADMAP O106)."
      exit 1 ;;
  esac
  if [ ! -f "$ROOT/tests/context-check.sh" ]; then
    echo "CHECK-DERIVATION FAILED — the derived root is not where this script lives:"
    echo "  $ROOT"
    exit 1
  fi
  echo "ok    context-check derives a single-line root and the slug $SLUG"
  exit 0
fi

# **THIS FALLBACK USED TO PICK ANOTHER PROJECT, AND THAT IS ROADMAP O104.**
# It read "fall back to a search rather than failing on an unexpected slug",
# and the search was `ls -td ~/.claude/projects/*/ | head -1` — the most
# recently touched project on the machine, whichever repo that is. Observed
# 2026-09-04: this script measured a DIFFERENT PROJECT's session, reported
# 921,350 tokens remaining and the verdict PLENTY, while the live session was
# at 836k/1M. Two unsound guesses in series — wrong project, then wrong
# session inside it — each of which answers confidently.
#
# `CLAUDE_PROJECT_DIR` is part of the same confusion: the harness sets it to
# the REPO root, not to the transcripts directory, so honouring it here points
# at a directory that holds no `.jsonl` at all.
#
# A tool whose whole purpose is to stop people estimating must not estimate.
# It refuses now, and says what to pass.
# An explicit transcript path or session id wins over any of this — it is
# the one input that cannot be a guess.
if [ $# -lt 1 ] && [ ! -d "$PROJ" ]; then
  echo "CONTEXT CHECK REFUSED — no transcript directory for THIS project:"
  echo "  $PROJ"
  echo ""
  echo "It used to fall back to the most recently touched project on the"
  echo "machine and measure THAT — which is how it reported 8% for a session"
  echo "that was 84% full (ROADMAP O104). Guessing at which project, or which"
  echo "session, is what made the number wrong; refusing is the honest answer."
  echo ""
  echo "Pass the transcript explicitly — the path is in the system prompt:"
  echo "  bash tests/context-check.sh <path-to-session.jsonl>"
  exit 1
fi

# Calibration record, so the assumption can be re-checked rather than trusted:
# on 2026-08-18 this reader measured 541,100 prompt tokens while the operator
# independently reported 54% used. 541100/0.54 = 1,001,000 -> a 1,000,000
# window. If a future session's percentage disagrees with what the client
# shows, RE-CALIBRATE here; do not adjust the arithmetic above.

# **SELF-TEST: the two refusals must FIRE, and an explicit path must still
# work (ROADMAP O104).** Run as `bash tests/context-check.sh --self-test`.
#
# It exists because this tool answered confidently from the wrong project and
# the wrong session, and the only thing that caught it was a human reading the
# real number off the UI. A checker whose failure mode is a plausible number
# needs a check of its own.
if [ "${1:-}" = "--self-test" ]; then
  ST_FAIL=0
  ST_TMP=$(mktemp -d)
  # 1. A project directory that does not exist must REFUSE, not wander off to
  #    another project. This is the defect verbatim.
  if OUT=$(HOME="$ST_TMP" bash "$0" 2>&1); then
    echo "FAIL  a missing transcript directory did not refuse — it answered:"
    printf '%s
' "$OUT" | head -3 | sed 's/^/        /'
    ST_FAIL=1
  else
    case "$OUT" in
      *REFUSED*|*FAILED*) echo "ok    a missing transcript directory refuses rather than guessing" ;;
      *) echo "FAIL  it failed for some other reason: $OUT"; ST_FAIL=1 ;;
    esac
  fi
  # 2. PREMISE, the other direction: given a real transcript it must still
  #    MEASURE. A tool that refuses everything reports what a healthy one does.
  ST_REAL=$(ls -t "$HOME"/.claude/projects/*/*.jsonl 2>/dev/null | head -1)
  if [ -n "$ST_REAL" ]; then
    if OUT=$(bash "$0" "$ST_REAL" 2>&1) && printf '%s' "$OUT" | grep -q "remaining"; then
      echo "ok    ...and an explicit transcript is still measured"
    else
      echo "FAIL  an explicit transcript was not measured — the refusals are total"
      ST_FAIL=1
    fi
  else
    echo "FAIL  premise: no transcript anywhere to prove the happy path"
    ST_FAIL=1
  fi
  # 3. THE SESSION-ID FORM — the invocation the doctrine documents — must
  #    measure (ROADMAP O106). Built under a fake HOME so it exercises the slug
  #    derivation for THIS project rather than the full-path shortcut: a real
  #    transcript copied under `<HOME>/.claude/projects/<slug>/<id>.jsonl`, then
  #    asked for by id. Restoring the pre-O106 `ROOT` line fails exactly this
  #    arm, because the slug then carries a newline.
  if [ -n "$ST_REAL" ]; then
    ST_PROJ="$ST_TMP/.claude/projects/$SLUG"
    mkdir -p "$ST_PROJ" && cp "$ST_REAL" "$ST_PROJ/o106-probe.jsonl"
    if OUT=$(HOME="$ST_TMP" bash "$0" o106-probe 2>&1) && printf '%s' "$OUT" | grep -q "remaining"; then
      echo "ok    ...and the session-id form resolves this project's slug and measures"
    else
      echo "FAIL  the session-id form did not measure — the slug derivation is wrong:"
      printf '%s\n' "$OUT" | head -3 | sed 's/^/        /'
      ST_FAIL=1
    fi
    # 4. ...and it must keep measuring when the harness sets CLAUDE_PROJECT_DIR
    #    to the repo root, as hooks do — that variable names the wrong
    #    directory and must not be consulted.
    if OUT=$(CLAUDE_PROJECT_DIR="$ROOT" HOME="$ST_TMP" bash "$0" o106-probe 2>&1) && printf '%s' "$OUT" | grep -q "remaining"; then
      echo "ok    ...and CLAUDE_PROJECT_DIR (the repo root) is not mistaken for the transcripts"
    else
      echo "FAIL  CLAUDE_PROJECT_DIR steered the session-id form to the wrong directory"
      ST_FAIL=1
    fi
  fi
  rm -rf "$ST_TMP"
  [ "$ST_FAIL" -eq 0 ] && echo "context-check self-test: ok" || echo "context-check self-test: FAILED"
  exit "$ST_FAIL"
fi

if [ $# -ge 1 ] && [ -f "$1" ]; then
  F="$1"
elif [ $# -ge 1 ]; then
  F="$PROJ/$1.jsonl"
else
  # **"Newest transcript = the live session" IS A GUESS, AND IT WAS WRONG
  # (ROADMAP O104).** More than one Claude session can touch one project —
  # a second window, a resumed session, a subagent — and `ls -t` then picks
  # whichever was written most recently, which is not necessarily this one.
  #
  # Observed 2026-09-04: this script reported 921,350 tokens remaining and
  # the verdict PLENTY while the live session was at 836k/1M — 84% full. It
  # had selected another session's transcript. The arithmetic was right; the
  # FILE was wrong.
  #
  # That failure direction is the dangerous one. `CLAUDE.md` mandates this
  # script because estimating by feel went wrong before, and it went wrong
  # toward stopping too EARLY. Under-reporting tells a session to keep taking
  # units when it is nearly full, which is how work gets half-landed — the
  # one thing the session-end rule exists to prevent.
  #
  # So: prefer an explicit id, and when guessing, REFUSE if the guess is
  # ambiguous rather than answer confidently. A wrong number here is worse
  # than no number, which is this file's own oldest rule.
  if [ -n "${CLAUDE_SESSION_ID:-}" ] && [ -f "$PROJ/$CLAUDE_SESSION_ID.jsonl" ]; then
    F="$PROJ/$CLAUDE_SESSION_ID.jsonl"
  else
    F=$(ls -t "$PROJ"/*.jsonl 2>/dev/null | head -1)
    # Anything else touched in the last 5 minutes makes the pick a coin flip.
    RIVALS=$(find "$PROJ" -name '*.jsonl' -newermt '-5 minutes' 2>/dev/null | wc -l)
    if [ "${RIVALS:-0}" -gt 1 ]; then
      echo "CONTEXT CHECK REFUSED — $RIVALS transcripts were written in the last"
      echo "5 minutes, so 'the newest file' does not identify this session:"
      find "$PROJ" -name '*.jsonl' -newermt '-5 minutes' 2>/dev/null | sed 's|^|  |'
      echo ""
      echo "Pass the session id explicitly — it is in the system prompt's"
      echo "transcript path — or set CLAUDE_SESSION_ID:"
      echo "  bash tests/context-check.sh <session-id>"
      echo ""
      echo "Guessing here reported 8% on a session that was 84% full"
      echo "(ROADMAP O104), and under-reporting is the direction that gets"
      echo "work half-landed."
      exit 1
    fi
  fi
fi

if [ -z "${F:-}" ] || [ ! -f "$F" ]; then
  echo "CONTEXT CHECK FAILED — no transcript found under:"
  echo "  $PROJ"
  echo "A reader that examined nothing must not report a low number: an"
  echo "absent transcript and an empty context look identical downstream."
  exit 1
fi

LAST=$(grep -o '"usage":{[^}]*}' "$F" | tail -1)
if [ -z "$LAST" ]; then
  echo "CONTEXT CHECK FAILED — $(basename "$F") carries no usage record."
  echo "The transcript format may have changed. Refusing to print 0%, which"
  echo "reads as 'plenty of room' and is the exact failure this tool exists"
  echo "to prevent."
  exit 1
fi

num() { echo "$LAST" | grep -oE "\"$1\":[0-9]+" | grep -oE '[0-9]+' | tail -1; }
IN=$(num input_tokens)
CC=$(num cache_creation_input_tokens)
CR=$(num cache_read_input_tokens)
OUT=$(num output_tokens)
IN=${IN:-0}; CC=${CC:-0}; CR=${CR:-0}; OUT=${OUT:-0}

TOTAL=$((IN + CC + CR))
if [ "$TOTAL" -le 0 ]; then
  echo "CONTEXT CHECK FAILED — parsed a zero-token prompt from a usage record."
  echo "  raw: $LAST"
  echo "Zero is not a plausible live measurement; the field names moved."
  exit 1
fi

TURNS=$(grep -c '"usage"' "$F")

awk -v t="$TOTAL" -v w="$WINDOW" -v i="$IN" -v cc="$CC" -v cr="$CR" -v o="$OUT" \
    -v turns="$TURNS" -v f="$(basename "$F")" 'BEGIN {
  pct = 100 * t / w
  printf "context: %.1f%% of the window\n\n", pct
  printf "  MEASURED (no assumption)\n"
  printf "    prompt in window   %10d tokens\n", t
  printf "      input            %10d\n", i
  printf "      cache creation   %10d\n", cc
  printf "      cache read       %10d\n", cr
  printf "    last output        %10d tokens\n", o
  printf "    assistant turns    %10d\n", turns
  printf "    transcript         %s\n\n", f
  printf "  DECLARED (the one assumption; override with CONTEXT_WINDOW)\n"
  printf "    window             %10d tokens\n", w
  printf "    remaining          %10d tokens\n\n", (w - t > 0 ? w - t : 0)
  if (pct < 70)      v = "PLENTY — take the next unit. Do not claim to be near the budget."
  else if (pct < 85) v = "COMFORTABLE — a normal unit still fits; size the next one honestly."
  else if (pct < 90) v = "APPROACHING the 90% stop-line — start no unit you cannot finish."
  else               v = "STOP TAKING NEW UNITS (CLAUDE.md). Spend what is left on governance:\n           CHANGELOG, ROADMAP, CLAUDE.md, the three .handover files, marker at HEAD."
  printf "  VERDICT: %s\n", v
}'
