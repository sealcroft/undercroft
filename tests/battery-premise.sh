#!/usr/bin/env bash
# The premise every battery suite runs FIRST, inside its own container
# (ROADMAP O439). Installed in the battery and model images as
# `undercroft-battery-premise`; each compose service that runs on one of
# them names it ahead of its own command:
#
#     undercroft-battery-premise <the suite's command…>
#
# It proves two things and then execs the suite, so the suite's exit code is
# still the verdict and nothing is piped:
#
#   1. the image was built from the tree under test — the digest its build
#      recorded (`tests/tree-digest.sh`, run over the copy it compiled) must
#      equal `BATTERY_EXPECT_TREE`, which `tests/battery.sh` computes over
#      the checkout with the same script;
#   2. every binary the build recorded is byte for byte the one it produced —
#      `sha256sum -c` over the record, so a later layer, a cache or a hand
#      that replaced one is caught before a suite runs it.
#
# The build that wrote the record started from a dependency layer holding no
# workspace member's artifact (the Dockerfile asserts it), so those binaries
# were compiled from the recorded tree and nothing else. Together that is the
# doctrine's "prove the binary is fresh" made general: instead of probing for
# one symbol the newest change added, it ties every binary to the whole tree.
#
# A failure exits 1 and says PREMISE FAILURE. Run by hand without
# `BATTERY_EXPECT_TREE`, it checks the record, says loudly that it compared
# no tree, and runs the suite — a direct `docker compose run` is not a battery
# verdict, and `--build` is what keeps it current.
set -u
M=/opt/undercroft/build
die() {
  printf 'PREMISE FAILURE — %s\n' "$*" >&2
  echo "      (ROADMAP O439: a suite runs only against an image built from the tree under test)" >&2
  exit 1
}
[ -s "$M/tree" ] || die "this image carries no build record at $M/tree, so nothing ties it to a tree"
built=$(cat "$M/tree")
case "$built" in
  *[!0-9a-f]*|"") die "the build record at $M/tree is not a digest: '$built'" ;;
esac
[ "${#built}" -eq 64 ] || die "the build record at $M/tree is not a 64-character digest: '$built'"
kind=$(cat "$M/kind" 2>/dev/null || echo binaries)
if [ "$kind" = sources-only ]; then
  bins="no prebuilt binaries (this suite compiles from the recorded sources)"
else
  n=$(grep -c . "$M/bins.sha256" 2>/dev/null || true)
  [ "${n:-0}" -ge 2 ] || die "the build recorded ${n:-no} binaries at $M/bins.sha256; it builds at least two"
  if ! out=$(cd / && sha256sum -c --strict "$M/bins.sha256" 2>&1); then
    die "a binary is not the one its build recorded:
$out"
  fi
  bins="$n binaries match their build record"
fi
if [ -n "${BATTERY_EXPECT_TREE:-}" ]; then
  if [ "$built" != "$BATTERY_EXPECT_TREE" ]; then
    die "this image was built from tree $built, and the tree under test is $BATTERY_EXPECT_TREE —
      a stale image, another worktree's, or a build context that did not see the checkout"
  fi
  echo "premise: image built from tree $built, the tree under test; $bins"
else
  echo "premise: image built from tree $built; $bins" >&2
  echo "premise: NOT compared with any tree — BATTERY_EXPECT_TREE is unset; tests/battery.sh sets it" >&2
fi
[ "$#" -gt 0 ] || die "no suite command to run after the premise"
exec "$@"
