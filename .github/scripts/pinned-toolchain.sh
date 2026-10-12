#!/usr/bin/env bash
# The ONE Rust toolchain every native build uses (ROADMAP O294).
#
#   bash .github/scripts/pinned-toolchain.sh [<target-triple>]
#       installs the toolchain `rust-toolchain.toml` pins, adds <target> to it
#       when one is named, and fails unless `rustc` in this checkout IS that
#       toolchain — the compiler cargo will run in the steps after it.
#   bash .github/scripts/pinned-toolchain.sh --channel
#       prints the pinned version and touches nothing; the `supply chain is
#       pinned` preflight in tests/battery.sh reads the pin through it, so the
#       file has one reader and the preflight and CI cannot read it apart.
#
# Every suite, the lint and the Linux images build in `rust:<version>-slim-
# bookworm`, while `release.yml`'s ten binaries were built by whatever stable
# each runner image carried — Rust 1.98.1 for every one of v1.6.1's, read from
# the runner images their jobs logged, against the 1.90.0 every suite ran. So a
# claim about the toolchain the battery tests was not a claim about what
# shipped — and 1.90's std carries Unicode 16 where the binaries' carried 17,
# which the hash identity's tokens read (ROADMAP O421). The preflight holds the
# other half: the Docker images name the same version, and every workflow job
# that runs cargo outside a container calls this script before its first cargo
# line. undercroft-core refuses to compile on a std of another Unicode version.
#
# The pin is read from the file rather than asked of rustup, because the file
# is what rustup itself obeys in this checkout; the version is installed BY
# NAME, so this works on a rustup that cannot install from a toolchain file
# with no argument. `--no-self-update` keeps rustup from replacing itself
# mid-job. Exit 1 on anything it cannot prove — never a skip.
set -euo pipefail
cd "$(dirname "$0")/../.."

file=rust-toolchain.toml
if [ ! -f "$file" ]; then
  echo "pinned-toolchain: $file is absent, so nothing pins the toolchain (ROADMAP O294)" >&2
  exit 1
fi
# The file is held whole: its executed lines must be exactly these three. A
# `components` or `targets` line would make rustup fetch on every cargo call
# inside the offline Docker images, and a channel such as `stable` or `1.98`
# is not a pin (a minor-only name is not even the image's installed one, which
# is the full version, so rustup inside the image would go to the network for
# it — measured with `1.90` against `1.90.0` in that image).
body=$(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$file" || true)
channel=$(printf '%s\n' "$body" | sed -n 's/^channel = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"$/\1/p')
want=$(printf '[toolchain]\nchannel = "%s"\nprofile = "minimal"' "$channel")
if [ -z "$channel" ] || [ "$body" != "$want" ]; then
  echo "pinned-toolchain: $file must hold exactly three lines besides comments:" >&2
  echo '  [toolchain]' >&2
  echo '  channel = "<major>.<minor>.<patch>"' >&2
  echo '  profile = "minimal"' >&2
  echo "  and it holds:" >&2
  printf '%s\n' "$body" | sed 's/^/    /' >&2
  exit 1
fi

if [ "${1:-}" = "--channel" ]; then
  printf '%s\n' "$channel"
  exit 0
fi

target="${1:-}"
rustup toolchain install "$channel" --profile minimal --no-self-update
if [ -n "$target" ]; then
  rustup target add --toolchain "$channel" "$target"
fi
# The proof: the compiler this checkout resolves. A RUSTUP_TOOLCHAIN in the
# environment, or an override set for this directory, outranks the file, and
# either would leave the install above unused — so the check is what rustc
# answers here, not what was installed.
have=$(rustc --version)
case "$have" in
  "rustc $channel "*) ;;
  *)
    echo "pinned-toolchain: rustc in this checkout reports '$have', not the pinned $channel" >&2
    exit 1 ;;
esac
echo "pinned toolchain: $have${target:+, target $target}"
