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
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Default members only — the onnx embedder crate is built by the
# dedicated `onnx-build` compose service.
RUN cargo build --release && cargo test --release --no-run

FROM builder AS test
CMD ["cargo", "test", "--release"]

FROM debian:bookworm-slim AS runtime
RUN useradd --create-home --uid 10001 undercroft \
    && mkdir -p /data && chown undercroft:undercroft /data
COPY --from=builder /src/target/release/undercroft /usr/local/bin/undercroft
USER undercroft
ENV UNDERCROFT_HOME=/data
VOLUME ["/data"]
ENTRYPOINT ["undercroft"]
CMD ["--help"]
