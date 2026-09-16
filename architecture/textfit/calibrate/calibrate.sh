#!/usr/bin/env bash
# The text-fit table's calibration (ROADMAP O189, V3 of the font-version ruling). Run BY HAND,
# never by CI or the battery, on gen_advances.sh's precedent: it fetches fonts from the network
# and drives Chromium for tens of minutes. It changes nothing in the tree; everything it writes
# goes to a gitignored run folder, architecture/textfit/calibrate/runs/<run id>/.
#
#   bash architecture/textfit/calibrate/calibrate.sh [--no-canary] [--run-id ID [--from STEP] [--to STEP]]
#
# Git Bash needs no prefix: this script exports MSYS_NO_PATHCONV=1 for every docker command.
# Steps, in order (see README.md for what each checks):
#   meta             commit, dirty flag and the three images by digest
#   plan             the Debian image and every Debian font row agree with gen_advances.sh's pins
#   extract          the pinned Debian font packages, downloaded and unpacked (Debian image)
#   stage            every fonts.tsv file into the run folder, sha256-checked before use
#   canary           the newest upstream Noto monthly release, fetched and recorded (not gating)
#   pages            which files each page embeds and which stacks its passes name
#   platform         the render image's Chromium, HarfBuzz and fontconfig, recorded (render image)
#   cjk-font-data    the declared CJK faces' widest reachable advance and largest positive default-on
#                    adjustment, from their own tables (Debian image, fontTools at gen_advances.sh's pin)
#   fixture          the fixture strings, priced by textfit against the tree's table, its '-' cells
#                    checked both ways against the staged fonts
#   fixture-render   the fixture on every gating page (render image)
#   fixture-judge    the fixture judge, premise arms first
#   pa-render-<page> today's diagram text on each page, the canary page last (render image)
#   pa-judge-<page>  the P-A judge per page, premise arms first
#   summary          summary.json and summary.txt: digests of the tree, fonts, images and outputs
# --from STEP resumes an existing run at STEP; the steps before it are not repeated. --to STEP stops
# after STEP. `--run-id ID --from fixture-judge --to fixture-judge` judges a run again and renders nothing.
#
# Exit 0 when every gating judge is clean, 1 when one fails or a step cannot run, 2 when a
# judge's premise arm does not fire. The canary's verdict is recorded and never changes the exit.
set -u
export MSYS_NO_PATHCONV=1

PY_IMAGE=python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf
DEBIAN_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RENDER_IMAGE=minlag/mermaid-cli:10.9.1@sha256:f0e8d29ef5385d797724d78c2a1bb00c8398476e8370f0219c0da86cce07d44c

HERE=$(cd "$(dirname "$0")" && pwd)
ARCH=$(cd "$HERE/../.." && pwd)
REPO=$(cd "$ARCH/.." && pwd)

RUN_ID=""
FROM=""
TO=""
CANARY=1
while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) RUN_ID=${2:?--run-id needs a value}; shift 2 ;;
    --from) FROM=${2:?--from needs a step}; shift 2 ;;
    --to) TO=${2:?--to needs a step}; shift 2 ;;
    --no-canary) CANARY=0; shift ;;
    -h|--help) sed -n '2,/^set -u$/p' "$0"; exit 0 ;;
    *) echo "calibrate.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
if [ -n "$FROM" ] && [ -z "$RUN_ID" ]; then
  echo "calibrate.sh: --from resumes an existing run and needs --run-id" >&2
  exit 2
fi
if [ -z "$RUN_ID" ]; then
  RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
fi
case "$RUN_ID" in
  *[!A-Za-z0-9._-]*|'') echo "calibrate.sh: run id $RUN_ID must be letters, digits, dot, dash, underscore" >&2; exit 2 ;;
esac
RUN="$HERE/runs/$RUN_ID"
if [ -n "$FROM" ] && [ ! -d "$RUN" ]; then
  echo "calibrate.sh: no run folder $RUN to resume" >&2
  exit 2
fi
mkdir -p "$RUN/meta" "$RUN/logs"
echo "calibration run $RUN_ID -> $RUN"

STARTED=1
[ -n "$FROM" ] && STARTED=0
STOPPED=0
GATING_RC=0
CANARY_RC=""

# run_step NAME GATING COMMAND... — the command's own exit code is the step's, never a pipeline's.
run_step() {
  local name=$1 gating=$2 rc
  shift 2
  if [ "$STARTED" -eq 0 ]; then
    if [ "$name" = "$FROM" ]; then STARTED=1; else echo "== $name: skipped (resuming from $FROM)"; return 0; fi
  fi
  if [ "$STOPPED" -eq 1 ]; then
    echo "== $name: skipped (stopped after $TO)"
    return 0
  fi
  echo "== $name"
  "$@" > "$RUN/logs/$name.log" 2>&1
  rc=$?
  [ "$name" = "$TO" ] && STOPPED=1
  cat "$RUN/logs/$name.log"
  printf '%s\t%s\n' "$name" "$rc" >> "$RUN/meta/exit-codes.tsv"
  echo "-- $name exit $rc"
  if [ "$gating" = gating ] && [ "$rc" -ne 0 ]; then
    if [ "$rc" -eq 2 ] || [ "$GATING_RC" -eq 2 ]; then GATING_RC=2; else GATING_RC=1; fi
  fi
  return "$rc"
}

py() {
  docker run --rm -e CAL_TREE=/a -e CAL_RUN=/r -e CAL_RUN_ID="$RUN_ID" -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$ARCH:/a:ro" -v "$RUN:/r" -w /a/textfit/calibrate "$PY_IMAGE" python3 "$@"
}

render() {  # render MODE PAGES OUT
  docker run --rm --user root --entrypoint sh -e CAL_MODE="$1" -e CAL_PAGES="$2" -e CAL_OUT="$3" \
    -v "$ARCH:/a:ro" -v "$RUN:/r" "$RENDER_IMAGE" -c 'node /a/textfit/calibrate/render.js'
}

step_meta() {
  local head status n ref role
  # `cd` rather than `git -C`: with MSYS_NO_PATHCONV=1 exported, Git Bash hands a native git
  # the POSIX spelling of the path, which it cannot resolve.
  head=$(cd "$REPO" && git rev-parse HEAD) || return 1
  status=$(cd "$REPO" && git status --porcelain) || return 1
  n=0
  if [ -n "$status" ]; then n=$(printf '%s\n' "$status" | grep -c .); fi
  printf 'key\tvalue\nhead\t%s\ndirty\t%s\nchanged_paths\t%s\n' "$head" "$([ "$n" -gt 0 ] && echo true || echo false)" "$n" \
    > "$RUN/meta/git.tsv"
  printf '%s\n' "$status" > "$RUN/meta/git-status.txt"
  printf 'role\treference\trepo_digests\n' > "$RUN/meta/images.tsv"
  for role in python debian render; do
    case $role in python) ref=$PY_IMAGE ;; debian) ref=$DEBIAN_IMAGE ;; render) ref=$RENDER_IMAGE ;; esac
    if ! docker image inspect "$ref" > /dev/null; then
      docker pull "$ref" || return 1
    fi
    printf '%s\t%s\t%s\n' "$role" "$ref" "$(docker image inspect --format '{{json .RepoDigests}}' "$ref")" >> "$RUN/meta/images.tsv"
  done
  cat "$RUN/meta/git.tsv" "$RUN/meta/images.tsv"
}

step_extract() {
  docker run --rm -v "$RUN:/r" -w /r/fetch "$DEBIAN_IMAGE" sh -c '
    set -eu
    apt-get -qq update
    rm -f ./*.deb
    apt-get download $(cat debian-packages.txt)
    sha256sum ./*.deb > debs.sha256
    rm -rf debian-root
    for deb in ./*.deb; do dpkg-deb -x "$deb" debian-root; done
    cat debs.sha256'
}

step_cjk_font_data() {
  # The package pins come from the plan step, which read them out of gen_advances.sh; the script checks
  # them again against gen_advances.sh and dpkg before it reads a font.
  if [ ! -s "$RUN/fetch/cjk-font-data-packages.txt" ]; then
    echo "cjk-font-data: $RUN/fetch/cjk-font-data-packages.txt is absent; run the plan step first" >&2
    return 1
  fi
  docker run --rm -e CAL_TREE=/a -e CAL_RUN=/r -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$ARCH:/a:ro" -v "$RUN:/r" -w /a/textfit/calibrate "$DEBIAN_IMAGE" sh -c '
      set -eu
      apt-get -qq update >/dev/null
      apt-get -qq install -y --no-install-recommends $(cat /r/fetch/cjk-font-data-packages.txt) >/dev/null
      python3 cjk_font_data.py'
}

pages_where() {  # pages_where true|false -> comma-separated page ids
  local id gating out=""
  while IFS="$(printf '\t')" read -r id gating; do
    if [ "$id" != page ] && [ "$gating" = "$1" ]; then out="${out:+$out,}$id"; fi
  done < "$RUN/pages.tsv"
  printf '%s' "$out"
}

if [ -n "$FROM" ]; then
  case "$FROM" in
    meta|plan|extract|stage|canary|pages|platform|cjk-font-data|fixture|fixture-render|fixture-judge|pa-render-*|pa-judge-*|summary) ;;
    *) echo "calibrate.sh: --from $FROM is not a step" >&2; exit 2 ;;
  esac
fi

run_step meta gating step_meta || exit 1
run_step plan gating py fetch.py plan --debian-image "$DEBIAN_IMAGE" || exit 1
run_step extract gating step_extract || exit 1
run_step stage gating py fetch.py stage || exit 1
if [ "$CANARY" -eq 1 ]; then
  run_step canary canary py fetch.py canary
  CANARY_RC=$?
else
  echo "== canary: not run (--no-canary)"
fi
run_step pages gating py fetch.py pages || exit 1
run_step platform gating docker run --rm --user root --entrypoint sh -v "$ARCH:/a:ro" -v "$RUN:/r" \
  "$RENDER_IMAGE" /a/textfit/calibrate/platform.sh || exit 1
run_step cjk-font-data gating step_cjk_font_data || exit 1
run_step fixture gating py fixture.py || exit 1

GATING_PAGES=$(pages_where true)
CANARY_PAGES=$(pages_where false)
if [ -z "$GATING_PAGES" ]; then
  echo "calibrate.sh: pages.tsv lists no gating page" >&2
  exit 1
fi
run_step fixture-render gating render fixture "$GATING_PAGES" /r/fixture \
  && run_step fixture-judge gating py judge_fixture.py
for page in $(printf '%s' "$GATING_PAGES" | tr ',' ' '); do
  run_step "pa-render-$page" gating render pa "$page" "/r/pa/$page" \
    && run_step "pa-judge-$page" gating py judge_pa.py "$page"
done
for page in $(printf '%s' "$CANARY_PAGES" | tr ',' ' '); do
  run_step "pa-render-$page" canary render pa "$page" "/r/pa/$page" \
    && run_step "pa-judge-$page" canary py judge_pa.py "$page"
  CANARY_RC=$?
done
run_step summary gating py summary.py

if [ "$STARTED" -eq 0 ]; then
  echo "calibrate.sh: --from $FROM matched no step that ran" >&2
  exit 2
fi
if [ -n "$TO" ] && [ "$STOPPED" -eq 0 ]; then
  echo "calibrate.sh: --to $TO matched no step that ran" >&2
  exit 2
fi
echo "== verdict for run $RUN_ID"
cat "$RUN/meta/exit-codes.tsv"
echo "canary: ${CANARY_RC:-not run} (recorded, never gating)"
echo "gating exit: $GATING_RC"
exit "$GATING_RC"
