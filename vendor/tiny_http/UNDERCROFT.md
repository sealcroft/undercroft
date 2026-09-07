# `tiny_http` 0.12.0, vendored — why, what changed, how it is kept honest

This directory is `tiny_http` **0.12.0** exactly as published on crates.io
(`checksum 389915df…cdc82`, `Cargo.toml` normalized, `src/`, both license
texts, the README) plus one patch, and nothing else. The workspace takes it
through `[patch.crates-io]` in the root `Cargo.toml`, so `Cargo.lock` names
this path and no registry source for the crate.

## Why (ROADMAP O114)

Two of this project's binaries serve HTTP with `tiny_http`: the engine
(`serve-http`, both `/v1` and `/mcp`) and the orchestrator. In 0.12.0,
dropping a `Request` whose `Content-Length` body a handler never read runs
`EqualReader::drop`, which drains the remainder with

    let mut buf = vec![0; remaining_to_read];

— an allocation sized by the **client's declaration**, taken before a byte
is read. Every refusal answers without reading the body, the unauthenticated
bearer 401 first among them, so one header (`Content-Length: 999999999999`)
aborted the process on a heuristic-overcommit kernel (`handle_alloc_error`,
no unwinding). It was found by an e2e check of the 413 ceiling the round
before, on CI and not locally — WSL overcommits the allocation. Upstream
knows: tiny-http issue #290, open, with no release since 0.12.0.

A bounded drain would not have been enough: the crate sets **no socket read
timeout**, so a peer that declares a body and sends nothing parks the thread
that drops the request — this project's single-threaded request loop — for
as long as it likes, inside the drain.

## What changed (every line marked `UNDERCROFT PATCH`)

1. `src/util/equal_reader.rs` — `Drop` never reads. It sends the consumption
   verdict (`Ok(())` if the body was read whole, `Err` otherwise) on the
   signal the original created and discarded.
2. `src/request.rs` — `new_request_with_body_signal` hands that receiver
   back beside the `Request`; `new_request` keeps its signature and drops
   it, for any other caller.
3. `src/client.rs` — `ClientConnection` keeps the receiver as
   `pending_body` and, before parsing the next request on the same socket,
   waits for the verdict and **ends the connection** when the body was left
   unread: the bytes are neither drained nor parsed as a request. A
   keep-alive client whose body was read whole is unaffected. Two ceilings
   on the header block the crate also grew without bound: a header line
   above 16 KiB closes the connection, a request with more than 128
   headers is a 400.

Measured against the patched engine, in one container: three
`Content-Length: 999999999999` requests answer 413 and the server still
answers; a 20 KiB header line closes and the server still answers;
pipelined requests behind a body that WAS read are served, behind one that
was not, are not.

## How it is kept honest

- `vendor/SHA256SUMS` pins every file under `vendor/`, checked by the
  `vendored crates are pinned` preflight in `tests/battery.sh` in both
  directions (a listed file missing, a present file unlisted, a changed
  byte). Editing anything here means regenerating the sums ON PURPOSE:

      (cd vendor && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)

- `UNDERCROFT.patch` is `diff -ru` of the pristine 0.12.0 registry copy
  against this directory, regenerated whenever the patch changes, so a
  reviewer sees the whole difference without a registry.
- `NOTICE` attributes it (MIT OR Apache-2.0).

## When upstream fixes it

Drop this directory, the `[patch.crates-io]` block, the preflight's vendor
inventory and the NOTICE paragraph together, and take the release that
carries the fix. Until then a `cargo update` cannot move this crate.
