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
#
# TRACKED, not in `.handover/` where it was first written. That directory is
# gitignored, so a fresh clone would not carry this and nothing would invoke
# it — the exact defect O10 fixed for the former-name verifier one directory
# over. A tool that only exists on one machine is a tool that will be lost.
set -uo pipefail

# Claude Code slugs the project directory by replacing every path separator
# (and the drive colon) with `-`. Derived rather than hard-coded: this file is
# TRACKED, and a tracked tool carrying one machine's absolute path is the
# defect O10 fixed one directory over. Verified on 2026-08-18 that the
# derivation reproduces the real slug exactly.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -W 2>/dev/null || cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SLUG="$(printf '%s' "$ROOT" | sed -E 's#[:/\\]#-#g')"
PROJ="${CLAUDE_PROJECT_DIR:-$HOME/.claude/projects/$SLUG}"
WINDOW="${CONTEXT_WINDOW:-1000000}"

# Fall back to a search rather than failing on an unexpected slug: the mapping
# is a client-side convention, not a contract we own.
if [ ! -d "$PROJ" ] && [ -d "$HOME/.claude/projects" ]; then
  ALT=$(ls -td "$HOME"/.claude/projects/*/ 2>/dev/null | head -1)
  [ -n "$ALT" ] && PROJ="${ALT%/}"
fi

# Calibration record, so the assumption can be re-checked rather than trusted:
# on 2026-08-18 this reader measured 541,100 prompt tokens while the operator
# independently reported 54% used. 541100/0.54 = 1,001,000 -> a 1,000,000
# window. If a future session's percentage disagrees with what the client
# shows, RE-CALIBRATE here; do not adjust the arithmetic above.

if [ $# -ge 1 ] && [ -f "$1" ]; then
  F="$1"
elif [ $# -ge 1 ]; then
  F="$PROJ/$1.jsonl"
else
  # Newest transcript in the project = the live session.
  F=$(ls -t "$PROJ"/*.jsonl 2>/dev/null | head -1)
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
