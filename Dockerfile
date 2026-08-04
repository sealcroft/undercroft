# Undercroft — hardened local-first AI memory (Rust).
#
# Multi-stage build:
#   * builder — compiles the workspace with the full test toolchain
#   * test    — runs unit + integration tests (docker build --target test)
#   * runtime — minimal image with just the `undercroft` binary
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
LABEL org.opencontainers.image.title="Undercroft" \
      org.opencontainers.image.description="Hardened local-first AI memory: encrypted, integrity-verified vaults with verbatim recall, hybrid retrieval, MCP + multi-tenant REST" \
      org.opencontainers.image.source="https://github.com/compufreq/undercroft" \
      org.opencontainers.image.url="https://compufreq.github.io/undercroft/" \
      org.opencontainers.image.documentation="https://compufreq.github.io/undercroft/docs/" \
      org.opencontainers.image.licenses="BUSL-1.1" \
      org.opencontainers.image.vendor="compufreq"
RUN useradd --create-home --uid 10001 undercroft \
    && mkdir -p /data && chown undercroft:undercroft /data
COPY --from=builder /src/target/release/undercroft /usr/local/bin/undercroft
COPY --from=builder /src/target/release/undercroft-orchestrator /usr/local/bin/undercroft-orchestrator
USER undercroft
ENV UNDERCROFT_HOME=/data
VOLUME ["/data"]
ENTRYPOINT ["undercroft"]
CMD ["--help"]
