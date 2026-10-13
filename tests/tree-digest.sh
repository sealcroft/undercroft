#!/usr/bin/env bash
# The digest of the tree a battery image compiles (ROADMAP O439).
#
#     bash tests/tree-digest.sh [root]      # prints 64 hex characters
#
# ONE definition, run in two places: `tests/battery.sh` runs it over the
# checkout, and the Dockerfile runs this very file over the copy it compiles
# and records the answer in the image. Every battery suite refuses to run
# when the two differ, so an image built from another tree — a stale build
# context, a tag another worktree moved, a cache that answered for different
# sources — fails as a premise instead of passing as a verdict.
#
# The inputs are what the image COPIES and the suites depend on: the
# workspace manifest and lock, every crate, the vendored crate and the
# deployment configs `cargo test` reads. Each file is hashed by content, in
# binary mode (Git Bash's sha256sum defaults to it and Linux's does not, so
# `-b` is what makes the two hosts print the same line), and the sorted list
# of `<hash> *<relative path>` lines is hashed again. Paths are relative to
# the root, so the copy at /src and a checkout anywhere agree. Line endings
# are the tree's own: the LF the line-ending preflight holds.
#
# SCOPE, stated: the Dockerfile is not an input. It is not copied into the
# image, and a layer cache keys every step by the Dockerfile's own text, so an
# image the battery or CI builds cannot carry another Dockerfile's commands;
# what the digest does not cover is an image built elsewhere from another
# Dockerfile and handed to BATTERY_PREBUILT under the expected tag. The suite
# scripts are not inputs either: each service bind-mounts its own, live.
set -euo pipefail
cd "${1:-.}"
for p in Cargo.toml Cargo.lock crates vendor deploy; do
  if [ ! -e "$p" ]; then
    echo "tree-digest: $PWD/$p is missing, so there is no tree to digest" >&2
    exit 1
  fi
done
find Cargo.toml Cargo.lock crates vendor deploy -type f -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 sha256sum -b \
  | sha256sum -b \
  | cut -c1-64
