# Undercroft — hardened local-first AI memory (Rust).
#
# Multi-stage build:
#   * builder — compiles the workspace with the full test toolchain
#   * test    — runs unit + integration tests (docker build --target test)
#   * runtime — minimal image with the `undercroft` and `undercroft-orchestrator` binaries
#
# Everything persists under /data (palace: vaults, keys, identity), so
# mount a volume there:
#
#   docker build -t undercroft .
#   docker run --rm -v undercroft-data:/data undercroft init
#   docker run --rm -v undercroft-data:/data undercroft remember "hello"
#   docker run -i  --rm -v undercroft-data:/data undercroft serve-mcp   # MCP stdio

FROM rust:1.90-slim-bookworm AS builder
WORKDIR /src
# curl is used by the e2e suite to exercise the HTTP REST surface.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
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
# set the compose ort-build service installs; openssl-sys fails without
# them, which is exactly how the first live docker-ort run died while
# the runner-built binary sailed: GitHub runners carry them natively).
# Installed only in the features branch so default images are untouched.
RUN if [ -n "$UNDERCROFT_FEATURES" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends pkg-config libssl-dev g++ \
        && rm -rf /var/lib/apt/lists/* \
        && cargo build --release -p undercroft-cli --features "$UNDERCROFT_FEATURES" \
        && cargo build --release -p undercroft-orchestrator; \
    else \
        cargo build --release && cargo test --release --no-run; \
    fi

FROM builder AS test
CMD ["cargo", "test", "--release"]

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
