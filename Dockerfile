# Undercroft — hardened local-first AI memory (Rust).
#
# Multi-stage build:
#   * base     — the pinned toolchain plus the packages every Rust stage uses
#   * skeleton — the workspace's manifests with every target root stubbed
#   * deps     — the release and test builds' dependencies, compiled once
#   * builder  — the workspace compiled over `deps` (the release build)
#   * test     — runs unit + integration tests (docker build --target test)
#   * battery-core — `builder` plus the premise every battery suite runs
#                first (ROADMAP O439)
#   * battery  — `battery-core` plus the telemetry binaries (`telemetry`, over
#                `deps-telemetry`) and mdBook (`mdbook`), from the same build
#   * models   — the model legs' sources over their compiled dependencies
#   * runtime  — minimal image with the `undercroft` and `undercroft-orchestrator` binaries
#
# The stages a target does not reach are never built: `docker build .` builds
# base, skeleton, deps, builder and runtime: the stages it always built,
# plus the two that hold the dependency layer.
#
# Everything persists under /data (palace: vaults, keys, identity), so
# mount a volume there:
#
#   docker build -t undercroft .
#   docker run --rm -v undercroft-data:/data undercroft init
#   docker run --rm -v undercroft-data:/data undercroft remember "hello"
#   docker run -i  --rm -v undercroft-data:/data undercroft serve-mcp   # MCP stdio

# The toolchain is the one `rust-toolchain.toml` pins, named in full so a
# Rust point release cannot move it under the minor tag (ROADMAP O294; the
# `supply chain is pinned` preflight holds the two equal). That file is not
# copied in: this image's own toolchain is the pin.
FROM rust:1.98.1-slim-bookworm AS base
WORKDIR /src
# curl is used by the e2e suite to exercise the HTTP REST surface, and
# sqlite3 is how it plays the OFFLINE WRITER: ROADMAP O237's gate needs the
# audit trail edited by a SECOND PROCESS while a server still holds the vault
# open, and that ruling's own words are that a test which re-opens the store
# passes over the defect. A byte edit with perl cannot do it — a writer that
# goes through SQLite is what moves the `data_version` cookie the open handle
# reads. Neither package is in the runtime stage.
#
# rustfmt and clippy are the `lint` suite's, installed once here instead of
# fetched on every run of that suite.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add rustfmt clippy

# ── the dependency layer (ROADMAP O439) ─────────────────────────────────────
# The equivalent of cargo-chef, in a few lines of shell rather than a
# third-party tool: the workspace's manifests, the lock, the vendored crate,
# and every TARGET ROOT replaced by a stub. Its output depends on nothing a
# source edit touches, so `deps` below — which compiles every dependency over
# it — stays cached in a layer until a manifest, the lock or `vendor/` moves.
# A root is a `src/lib.rs`, a `src/main.rs`, or a `path =` a manifest names;
# a lib's stub is empty and every other root's is `fn main() {}`.
#
# Measured from a cold cache on 2026-10-13, beside the rest of a battery's
# builds: `deps` 142 s, then the workspace over it 283 s. Before this layer
# every source edit paid both, in every image.
FROM base AS skeleton
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor
RUN set -eu; \
    mkdir -p /skeleton; \
    cp Cargo.toml Cargo.lock /skeleton/; \
    cp -a vendor /skeleton/vendor; \
    for man in crates/*/Cargo.toml; do \
      d=${man%/Cargo.toml}; \
      mkdir -p "/skeleton/$d"; \
      cp "$man" "/skeleton/$man"; \
      for root in src/lib.rs src/main.rs $(sed -n 's/^path *= *"\([^"]*\)".*/\1/p' "$man"); do \
        [ -f "$d/$root" ] || continue; \
        mkdir -p "$(dirname "/skeleton/$d/$root")"; \
        if [ "$root" = src/lib.rs ]; then : > "/skeleton/$d/$root"; \
        else echo 'fn main() {}' > "/skeleton/$d/$root"; fi; \
      done; \
    done

# Every dependency of the two commands `builder` runs, the release build and
# the test build, compiled once. Nothing more: the published image is built
# over this layer too, and it should pay for no dependency it does not link.
# The battery's other consumers cook their own over it, in stages of their own
# (`deps-telemetry`, `deps-models`).
#
# **Then every workspace member's artifacts are DELETED** (`cargo clean -p`,
# each member named from its own manifest), and that is the half that makes
# this layer safe. A stub that survived here would be "fresh" to cargo
# whenever a real source file's mtime is older than the stub's build — a COPY
# keeps the host's mtimes — and the release binary would link a stub. With the
# members gone there is nothing to reuse: every stage below compiles every
# member it needs from the sources it copied, whatever the clock says.
# `builder` asserts it before building.
FROM base AS deps
COPY --from=skeleton /skeleton/ ./
RUN cargo build --release \
    && cargo test --release --no-run \
    && cargo clean --release $(sed -n 's/^name *= *"\(undercroft-[a-z-]*\)".*/-p \1/p' crates/*/Cargo.toml)

FROM deps AS builder
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# The vendored, patched HTTP server crate (`[patch.crates-io]`, ROADMAP
# O114): a build without it resolves tiny_http from the registry and ships
# the unbounded drop-drain this tree exists to be rid of.
COPY vendor ./vendor
# The observability deployment configs. `undercroft-obs` gates them against
# the series inventory it exports — an alert naming a series the binary does
# not export never fires and never errors — and that gate must FAIL rather
# than skip when the files are absent, so they have to be in the image the
# battery runs `cargo test` in. Copied after `crates` so an edit here does
# not invalidate the dependency layer.
COPY deploy ./deploy
# The ONE definition of "the tree a build compiled" (ROADMAP O439), shared
# with the host: `tests/battery.sh` computes the same digest over the
# checkout, and every battery suite refuses to run unless the two agree.
COPY tests/tree-digest.sh /usr/local/lib/undercroft/tree-digest.sh
# Default members only — the onnx embedder crate is built by the
# dedicated `onnx-build` compose service.
#
# UNDERCROFT_FEATURES lets a downstream image build the CLI with extra
# features (e.g. `telemetry` for the observability stack). Unset — the
# default for the test/e2e/runtime images — keeps the standard build and
# pre-compiles the test targets. Set: builds only the CLI with the given
# features so the runtime binary carries them (no test overwrite).
ARG UNDERCROFT_FEATURES=""
# The features branch must still produce the orchestrator (the runtime
# stage copies BOTH binaries — a features-only build used to leave it
# missing, which only never fired because feature images stopped at the
# builder stage until the :ort runtime variant existed). Feature builds
# also need the ort toolchain deps (pkg-config/libssl-dev/g++ — the same
# set the `models` stage installs; openssl-sys fails without
# them, which is exactly how the first live docker-ort run died while
# the runner-built binary sailed: GitHub runners carry them natively).
# Installed only in the features branch so default images are untouched.
#
# The build record (ROADMAP O439) is written in the same RUN: the digest of
# the tree as copied, read BEFORE cargo runs, and the sha256 of each binary
# the build produced. The premise every battery suite runs first compares the
# first with the checkout and the second with the binaries it is about to
# run. The first statement is the dependency layer's guarantee, asserted: no
# workspace member's artifact may exist yet, so nothing here can be reused.
RUN set -eu; \
    mkdir -p /opt/undercroft/build; \
    bash /usr/local/lib/undercroft/tree-digest.sh /src > /opt/undercroft/build/tree; \
    if [ "$(ls target/release/.fingerprint/ | wc -l)" -lt 100 ]; then \
      echo "the dependency layer holds no compiled dependencies; this check examined nothing" >&2; exit 1; \
    fi; \
    if ls target/release/.fingerprint/ | grep -q '^undercroft-'; then \
      echo "the dependency layer left a workspace member's build behind:" >&2; \
      ls target/release/.fingerprint/ | grep '^undercroft-' >&2; exit 1; \
    fi; \
    if [ -n "$UNDERCROFT_FEATURES" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends pkg-config libssl-dev g++ \
        && rm -rf /var/lib/apt/lists/* \
        && cargo build --release -p undercroft-cli --features "$UNDERCROFT_FEATURES" \
        && cargo build --release -p undercroft-orchestrator; \
    else \
        cargo build --release && cargo test --release --no-run; \
    fi; \
    sha256sum -b /src/target/release/undercroft /src/target/release/undercroft-orchestrator \
        > /opt/undercroft/build/bins.sha256

FROM builder AS test
CMD ["cargo", "test", "--release"]

# The build record alone, for a reader that needs it without loading the
# builder image (ROADMAP O439): `tests/tls-pins.sh` exports it with
# `docker build --target build-record -o <dir>` — a cache hit over the build
# that produced the engine it booted — and compares it with that engine.
FROM scratch AS build-record
COPY --from=builder /opt/undercroft/build/ /

# ── the battery images (ROADMAP O439) ───────────────────────────────────────
# Built ONCE per battery and run by every suite that needs a binary or the
# toolchain. Each suite used to build its own image and the telemetry suite
# compiled two more binaries at run time, so a battery paid for the same
# compile up to eight times. Two targets of one build: `battery-core` is
# `builder` with the premise every suite runs first, and is what `test`,
# `lint`, `e2e`, `orchestrator-e2e` and `backends-e2e` run on; `battery` adds
# the telemetry binaries and mdBook for `e2e-telemetry` and `site`. A local
# battery builds both at once, BuildKit computing what they share once; a CI
# leg builds only the one its suite needs, so four legs never compile the
# telemetry binaries they do not run.
#
# The telemetry binaries are the two commands the `e2e-telemetry` suite ran
# at run time, unchanged, in their own stage — BuildKit compiles it beside
# `builder` — so neither overwrites the other's `target/`. Their dependencies
# are cooked over the skeleton first, like `deps`, and cleaned the same way.
FROM deps AS deps-telemetry
RUN cargo build --release -p undercroft-cli --features telemetry \
    && cargo build --release -p undercroft-orchestrator --features telemetry \
    && cargo clean --release $(sed -n 's/^name *= *"\(undercroft-[a-z-]*\)".*/-p \1/p' crates/*/Cargo.toml)

FROM deps-telemetry AS telemetry
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor
COPY deploy ./deploy
COPY tests/tree-digest.sh /usr/local/lib/undercroft/tree-digest.sh
RUN set -eu; \
    mkdir -p /out; \
    bash /usr/local/lib/undercroft/tree-digest.sh /src > /out/tree; \
    cargo build --release -p undercroft-cli --features telemetry; \
    cargo build --release -p undercroft-orchestrator --features telemetry; \
    cp target/release/undercroft target/release/undercroft-orchestrator /out/

# The `lint` suite checks its dependencies at run time, as it always has. A
# stage cooking them was built and measured, and dropped: `target/debug` is
# 632 MB, and copied into `battery` over a `builder` that moves with every
# commit it is re-exported on every build — and loaded by every CI leg, none
# of which runs `lint` (CI lints in a job of its own) — to save a suite that
# runs beside the others about a minute.

# mdBook, at the version pages.yml and the `site` job pin, installed once
# rather than compiled on every run of the `site` suite.
FROM base AS mdbook
RUN cargo install mdbook --version 0.5.4 --locked --root /opt/mdbook

FROM builder AS battery-core
COPY tests/battery-premise.sh /usr/local/bin/undercroft-battery-premise
RUN chmod 0755 /usr/local/bin/undercroft-battery-premise

FROM battery-core AS battery
COPY --from=telemetry /out/undercroft /out/undercroft-orchestrator /opt/undercroft/telemetry/
COPY --from=telemetry /out/tree /opt/undercroft/telemetry.tree
COPY --from=mdbook /opt/mdbook/bin/mdbook /usr/local/bin/mdbook
RUN set -eu; \
    if [ "$(cat /opt/undercroft/telemetry.tree)" != "$(cat /opt/undercroft/build/tree)" ]; then \
      echo "the telemetry stage compiled another tree than builder" >&2; exit 1; \
    fi; \
    rm /opt/undercroft/telemetry.tree; \
    sha256sum -b /opt/undercroft/telemetry/undercroft /opt/undercroft/telemetry/undercroft-orchestrator \
        >> /opt/undercroft/build/bins.sha256

# ── the model legs (CI's `onnx-build` and `ort-build`) ──────────────────────
# Their dependencies — tract, ONNX Runtime and the C++ toolchain it links —
# compiled over the skeleton like `deps`, then the sources. No workspace
# member is compiled here: each leg compiles and tests at run time, as it
# always has, so its verdict is still the exit code of its own commands.
FROM deps AS deps-models
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev g++ \
    && rm -rf /var/lib/apt/lists/*
RUN cargo build --release -p undercroft-cli --features onnx \
    && cargo test --release -p undercroft-embed-onnx --no-run \
    && cargo build --release -p undercroft-cli --features onnx,ort \
    && cargo test --release -p undercroft-embed-ort --no-run \
    && cargo test --release -p undercroft-cli --features onnx,ort,undercroft-embed-onnx/test-fixture --no-run \
    && cargo clean --release $(sed -n 's/^name *= *"\(undercroft-[a-z-]*\)".*/-p \1/p' crates/*/Cargo.toml)

FROM deps-models AS models
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor
COPY deploy ./deploy
COPY tests/tree-digest.sh /usr/local/lib/undercroft/tree-digest.sh
COPY tests/battery-premise.sh /usr/local/bin/undercroft-battery-premise
RUN set -eu; \
    mkdir -p /opt/undercroft/build; \
    bash /usr/local/lib/undercroft/tree-digest.sh /src > /opt/undercroft/build/tree; \
    echo sources-only > /opt/undercroft/build/kind; \
    chmod 0755 /usr/local/bin/undercroft-battery-premise

# ── the layers worth keeping between commits (ROADMAP O439) ──────────────────
# Every stage the `battery` image needs that depends on no source file — the
# dependency layers and mdBook — gathered into one target, so CI can export
# exactly those to the Actions cache (`cache-to: type=gha,mode=max`) without
# uploading the workspace's own layers, which no later commit can use. The
# model legs' half is the `deps-models` stage itself.
FROM scratch AS deps-all
COPY --from=deps-telemetry /src/Cargo.lock /deps/telemetry.lock
COPY --from=mdbook /opt/mdbook/bin/mdbook /deps/mdbook

FROM debian:bookworm-slim AS runtime
# **Security updates, because the base tag is not one (ROADMAP O159).**
# `debian:bookworm-slim` carries whatever was current when Debian last
# rebuilt that tag, and nothing here refreshed it — so a CVE fixed in the
# archive after that rebuild sat in the published image until Debian happened
# to rebuild again. Found by the `trivy-image` CI job on two HIGH pcre2
# advisories (CVE-2026-86145, CVE-2026-89161) whose fix, 10.42-1+deb12u1, was
# already in the archive: the exposure was ours, not Debian's.
#
# `upgrade`, never `dist-upgrade`: within a stable release the security
# archive lands through `upgrade`, and `dist-upgrade` may add or remove
# packages, which is a bigger change than this is asking for.
#
# **The reproducibility cost is real and is NOT new.** The image stops being
# a pure function of (Dockerfile, base tag) and becomes a function of the
# archive on the build date — but `debian:bookworm-slim` is a moving tag, so
# that was already true; this changes the degree, not the kind. Pinning the
# base by digest is the way to buy reproducibility back, and it would trade
# away exactly the property this line exists to provide.
#
# Note a warm Docker layer cache serves this RUN without contacting the
# archive, so a local rebuild can be stale. CI builds without a cache, which
# is why `trivy-image` is the authority on what the published image holds.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.title="Undercroft" \
      org.opencontainers.image.description="Hardened local-first AI memory: encrypted, integrity-verified vaults with verbatim recall, hybrid retrieval, MCP + multi-tenant REST" \
      org.opencontainers.image.source="https://github.com/sealcroft/undercroft" \
      org.opencontainers.image.url="https://sealcroft.com/undercroft/" \
      org.opencontainers.image.documentation="https://sealcroft.com/undercroft/docs/" \
      org.opencontainers.image.licenses="BUSL-1.1" \
      org.opencontainers.image.vendor="Sealcroft"
RUN useradd --create-home --uid 10001 undercroft \
    && mkdir -p /data && chown undercroft:undercroft /data
COPY --from=builder /src/target/release/undercroft /usr/local/bin/undercroft
COPY --from=builder /src/target/release/undercroft-orchestrator /usr/local/bin/undercroft-orchestrator
USER undercroft
ENV UNDERCROFT_HOME=/data
VOLUME ["/data"]
ENTRYPOINT ["undercroft"]
CMD ["--help"]
