# Agent guide — deployment, test scripts, vendored code and releases

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the Layout entries for
`deploy/observability/` and its config-check image, the team-server recipe,
the end-to-end suite scripts and `tests/tls-pins.sh`, the vendored
`tiny_http`, and `.github/workflows/release.yml`. Read it when your work
touches `deploy/`, a test script under `tests/`, `vendor/`, or the release
workflow.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12). Where this full text and the core's one-line form of the same
rule differ, this full text governs, and the divergence is a defect, fixed in
the unit that finds it (ruled by the maintainer, 2026-10-12). In the moved
text, "this file" and "here" mean the guide as a whole — the core and its
reference documents.

---

- `deploy/observability/` — Prometheus + Alertmanager + Loki + Tempo + Grafana
  stack (see its README.md + RUNBOOK.md). **Every rule preserves `instance`
  — aggregated `by (instance)` or by a set containing it (`(instance, le)`
  under the latency quantile, `(instance, side)` for late-interaction
  failures), or left unaggregated so the label survives —
  and that is load-bearing, not cosmetic**: Alertmanager's
  inhibition scopes itself with `equal:`, and a label absent from BOTH the
  source and the target counts as EQUAL — so equalling on a label no rule
  emits does not narrow the inhibition, it makes it global. The shipped
  config equalled on `vault`, which nothing emitted (every rule was a
  `sum()`, an `up{}` or a `sum by (le)`), so one critical
  `PalaceTamperDetected` silenced every warning in the fleet for as long
  as it fired, and the only symptom of that class is an alert that never
  arrives. Gated by the `obs-config` suite: `promtool test rules` over
  `alerts_test.yml` asserts the exact label set each rule emits — real
  PromQL evaluation, so it cannot agree with the rules by construction the
  way a second copy of the expressions would — and `tests/obs-config.sh`
  then requires every `equal:` label to be present in all of them, and
  every rule to have a test block. Adding a rule means adding a block
- `deploy/observability/Dockerfile.config-check` — the `obs-config` image:
  `promtool` and `amtool` lifted from the pinned Prometheus/Alertmanager
  images onto debian. Pinning matters — a check that runs a different
  version than the deployment is a check of something else
- `deploy/docker-compose.server.yml` + `deploy/qdrant-tls/` — the team-server
  recipe (ROADMAP O172): the default-features engine behind one bearer,
  started as `undercroft init && exec undercroft serve-http …`, with an
  OPTIONAL Qdrant mirror behind its own Caddy terminator and an exported,
  pinned CA root. **It could not start until O172**: it served with no `init`,
  so a fresh volume crash-looped, and its Qdrant URL was cleartext beyond
  loopback, which the index client refuses — while `/healthz` answered 200,
  because serving builds no index and the pin is resolved, and a refusal
  cached, on first use. That is why `tests/tls-pins.sh` drives the index path
  THROUGH the running server rather than stopping at a boot check.
  `UNDERCROFT_PASSPHRASE` is declared with NO VALUE there: Compose passes it
  when `deploy/.env` sets it and leaves it unset otherwise, where
  `${…:-}` would pass an empty payload and refuse to start. The recipe had not
  named it at all, so a declared passphrase was dropped. MCP and `/v1` recall
  never consult the mirror, which
  `parity::no_served_surface_searches_through_a_remote_mirror` holds.
  **Every shipped `serve-http` recipe runs `init` first since O199/O200**:
  the observability engine had `init 2>/dev/null || true; exec …`, which hid
  a failed init behind serve-http's `vault "default" not found`, and
  `deploy/undercroft-server.service` had no `init` at all, so a fresh install
  restarted forever. The compose files use `init && exec`, the unit an
  unprefixed `ExecStartPre=` on the same executable plus
  `RequiresMountsFor=` on its `UNDERCROFT_HOME` — without it, an init that
  ran before the data directory's mount minted a second installation beneath
  the mount point and the server served it (the review of O200's first
  build, reproduced under systemd 252) — and the
  `every shipped serve-http recipe runs init first` preflight holds all three,
  reading a unit as systemd reads it, with a probe of the shipped broken lines
- `tests/e2e.sh`, `tests/e2e-backends.sh`, `tests/e2e-telemetry.sh`,
  `tests/e2e-orchestrator.sh`, `tests/obs-config.sh` — end-to-end and
  config suites (run in Docker)
- `tests/tls-pins.sh` — every shipped CA pin is READABLE by the identity
  that pins it (ROADMAP M7/M9/M10), and both shipped engine recipes BOOT
  (O63, O172). **Host-side, not in Docker**, because it
  DRIVES docker: it brings the real Caddy terminators up under throwaway
  compose projects and reads their volumes as the ENGINE's uid, taken from
  the `Dockerfile` so the two cannot drift. Two things it learned the hard
  way are encoded in it: a private project name does **not** scope a
  published PORT (hence `--no-deps`), and its first version ran `down -v` on
  the REAL projects and destroyed a live stack. A third arrived with O172:
  the team-server file needs a bearer to LOAD, `down` included, while the
  observability file's Prometheus repeats that variable's demo default — so
  the token is handed to the server file alone (`token_for`), never
  exported. Its teardowns stay literal `docker compose -p …` lines, because
  the teardown-scope preflight cannot see through a wrapper.
  `TLSPINS_SERVER_EXTRA_COMPOSE` applies one more file to the team-server
  boot, for counterfactuals, and a run with it set always exits 3
- `vendor/tiny_http` — **the one vendored crate** (ROADMAP O114, ruled
  option A): `tiny_http` 0.12.0 verbatim plus one patch, taken through
  `[patch.crates-io]` in the root `Cargo.toml`. The crate both listeners run
  on drained an unread request body on drop with `vec![0; remaining]` — an
  allocation of the CLIENT's declared `Content-Length`, on every refusal
  path including the unauthenticated bearer 401 — so one header killed
  `serve-http` and the orchestrator on a heuristic-overcommit kernel, and
  the local battery could not see it because WSL overcommits (upstream
  tiny-http #290, unfixed). **A bounded drain would not have been the fix**:
  the crate sets no socket read timeout, so any drain parks the
  single-threaded request loop for as long as a silent peer holds the
  socket. The patch drains nothing — the drop reports whether the body was
  consumed on a signal the original created and discarded, and the
  connection ENDS behind a refused body; a header line above 16 KiB and a
  request with more than 128 headers are refused too, the same class one
  read over. Every changed line is marked `UNDERCROFT PATCH`, the diff is
  `vendor/tiny_http/UNDERCROFT.patch`, the tree is pinned by
  `vendor/SHA256SUMS` through the `vendored crates are pinned` preflight
  (both directions, plus a probe that the patch is still present — a
  pristine copy would pin clean too), the Dockerfile COPYs it, and `NOTICE`
  attributes it. **Editing anything there means regenerating the sums on
  purpose**; the recipe is in `vendor/tiny_http/UNDERCROFT.md`. Two
  warnings the crate emits are upstream's own and are left alone: the diff
  carries the fix and nothing else
- `.github/workflows/release.yml` — on every `v*` tag: five binary
  targets (linux x86_64/arm64 native, macOS Intel cross-compiled on
  macos-latest + Apple Silicon, windows), each built on the toolchain
  `rust-toolchain.toml` pins (ROADMAP O294), uploaded to the release with
  sha256, and the multi-arch `ghcr.io/sealcroft/undercroft` image
  (per-arch native builds merged into one manifest; index annotations
  carry the package description). Since the posture-configs unit also
  the **`ort` variant**, and since 2026-08-04 at FULL target parity
  with the default artifacts: a `…-ort` binary asset for all five
  targets (same matrix, Intel-macOS smoke under Rosetta, installed
  explicitly) and a `:tag-ort` multi-arch image (amd64+arm64 per-arch
  builds + their own manifest job; `republish-ort-image` dispatch
  carries the same shape so a republish produces exactly what the tag
  would have), each smoke-probed — `--help`, then
  `UNDERCROFT_EMBEDDER=ort` must fail on
  MODEL CONFIG ("loading ORT embedder"), never on a missing feature,
  which is what a default binary under the asset name would say. The
  binary smoke runs against the PACKAGED layout, not the build tree —
  a binary that secretly needs a shared library beside it fails at CI,
  not on a user's machine — and packaging carries any onnxruntime
  runtime library the build drops beside the binary (statically linked
  on every probed target, so normally nothing matches; the copy is the
  honest fallback, not the expectation). The Dockerfile features
  branch also
  builds the orchestrator (the runtime stage copies both binaries — a
  features-only build used to leave it missing)
