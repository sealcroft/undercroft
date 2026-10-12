# Agent guide — CI and the release flow

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, how CI is built — the lint
job and why it runs cargo directly, the suite matrix, `windows-check`, the
pinned toolchain and supply chain, `house-figures`, the `CI verdict` — and the
pre-release drift check and the release flow. Read it when you touch
`.github/`, a toolchain pin, a release, a tag or a version bump.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12), and it governs over any one-line statement of the same rule in
the core. In the moved text, "this file" and "here" mean the guide as a whole
— the core and its reference documents.

---

CI runs `cargo fmt --all --check` + `cargo clippy --all-targets -- -D warnings`
(no `--workspace`, so the two excluded model crates are fmt'd but not clippy'd
in CI — O153),
**plus the same two telemetry-feature clippy runs the `lint` compose service
does** (O84).
**That job runs cargo DIRECTLY, not the compose service, and the two
definitions can disagree** — a fact worth knowing before adding a check to
either. It is not an oversight to route around: the job runs in a
`rust:1.98.1-slim-bookworm` container with no docker, so it cannot go through
`tests/battery.sh` the way M13 routed the suite legs. It bit immediately —
O84's first fix added the telemetry lint to the compose service alone, which
would have covered every local battery and NO pull request, i.e. exactly what
that entry's own gate requirement forbids. The `lint parity` preflight now
compares the two as SETS of clippy invocations, both directions, with a
premise arm on each extractor.
**Nine compose suites run as a `fail-fast: false` MATRIX** — eight since
`arch-check` joined (M14) and nine since `ort-build` joined (O142), and `tls-pins` is host-side and gets its own job
rather than a matrix leg, so CI runs ELEVEN jobs of which the matrix is one.
**The eleventh is `windows-check` (ROADMAP O102), and it exists because
NOTHING here compiled for Windows on a pull request.** `release.yml` builds
that target, and only on a TAG — so a Windows-only compile error was invisible
until the one moment it can no longer be fixed without a new version. `1.2.1`
shipped **16 assets instead of 20** that way: O90's fix named
`tokio_postgres::config::Host::Unix`, a variant that is `#[cfg(unix)]` and
does not exist off unix, and the ten-suite battery plus all seventeen other
CI checks were green because every one of them runs in a Linux container.
It is a `cargo check`, not a build: the class is code that does not COMPILE
for the target, and linking stays `release.yml`'s job. **A target you SHIP is
a target that must be compiled on a pull request** — the same rule as *ask
what a gate can SEE*, applied to the platform axis rather than to an
observable.
**One toolchain builds everything, and CI's supply chain is pinned (ROADMAP
O294, O326, O327).** `rust-toolchain.toml` names the version the Docker images
carry — the Dockerfile's builder and CI's lint container name it in full,
`rust:1.98.1-slim-bookworm` — and `.github/scripts/pinned-toolchain.sh` is the
one way CI installs it: by name, the job's target added, and a failure unless
`rustc` in the checkout reports exactly that version. Until it existed every
release binary was built by its runner image's own stable (1.97.1 or 1.98.x
across the v1.* releases, two compilers inside one release from v1.2.0 to
v1.5.1) while every suite and every image ran 1.90.0 — and **the pin's VALUE
is an identity decision**, which the first build missed: the hash embedder's
tokens read std's Unicode tables, 1.90's are Unicode 16 and every shipped
binary's were 17, so one `undercroft-hash-v3` named two token spaces (O421,
whose walk ships in the same release as this pin; no tag carries one without
the other). `undercroft-core` therefore asserts at COMPILE time that std's and
the locked `unicode-normalization`'s tables are both Unicode 17.0.0, so a
toolchain whose std moves Unicode version fails every build until someone
rules it (O422). Every third-party action is named by its
full commit SHA with its version in a comment (GitHub-owned `actions/*` by
version tag); every workflow reads by default and a job takes the write it
needs, checks out with `persist-credentials: false`, and keeps the token out
of every `env:` block but its step's — and out of any step that runs cargo.
The binary jobs still HOLD `contents: write` while their build scripts run,
which O325's separate upload jobs close. The `supply chain is pinned` preflight
holds all of it, and every container the preflights launch: by digest,
read-only, offline. **A toolchain bump is one change** to the file and both
image references, and the preflight names whichever was missed.
The tenth is **`house-figures`** (ROADMAP O65), and it is the ONLY check in
the tree that needs the INTERNET — which is exactly why it is a CI job and
not a `tests/battery.sh` preflight: the preflights run on every local battery
and a network arm there fails for anyone working offline. It reads the house
page's `<div class="n">` tiles and compares them to the tree, and it treats
an unreachable page as a FAILURE rather than a skip, because an unreachable
page and an accurate one must not produce the same verdict — this file's
oldest lesson, and the reason the check exists at all is that the same figure
sat stale for eleven days with nothing able to notice. Consequence, stated
rather than discovered: it can go red on a pull request that touched nothing,
because the house page is state this repo does not own. That is the signal,
not a defect in the gate. **One cause WAS a defect in the gate (ROADMAP
O331)**: its release read was an unauthenticated call from a hosted runner's
shared IP, and three of the job's eight red runs to 2026-10-07 were that read
alone, its cause thrown away — most likely the 60-an-hour limit, which nothing
logged could prove. It reads with the job's own `GH_TOKEN` now, sent only
under `https://api.github.com/`, fails inside Actions without one, and a
failed read names its HTTP status, the API's message and curl's exit code.
The matrix sentence above said "one job each" while also saying the matrix is one job,
which cannot both be true: a matrix expands to one check RUN per leg under a
single job id, which is why adding a leg does not move `verdict`'s `needs:`
and adding a job does. Corrected 2026-08-20; the count was stale too. Two
properties are load-bearing: the legs are independent, so wall-clock is the
slowest suite rather than their sum; and **every suite runs even when one
fails**, where the old serial job stopped at the first failure and hid the
state of the five behind it — a fix then landed blind.
**The verdict is the `verdict` job, published as the context `CI verdict`, and
that is the one context a required status check is configured against.** It
`needs:` every job and inspects every entry of `toJSON(needs)`, so `skipped`
and `cancelled` fail it too; it asserts its own upstream COUNT, so a narrowed
`needs:` fails closed; and `tests/battery.sh`'s CI-inventory preflight counts
the workflow's jobs against that `needs:` in both directions, because a
workflow cannot enumerate its own jobs and the other direction — a new job
nobody wired in — is invisible from inside it.
**Three claims that stood here until 2026-08-10 were false, and the shape of
the error is the lesson.** (1) *"the aggregate is kept under the name `test`
because that is what a required status check resolves against"* — **no repo
had `required_status_checks` at all** (verified against the API on both), so
the rule protected a configuration that did not exist, and the published
context is a job's `name`, which was `Suites (aggregate)` and never `test`,
while the matrix leg published one literally called `test`. (2) *"needs:
suites"* left five jobs outside the verdict. (3) *"named from the same strings
`tests/battery.sh` uses so CI and a local battery cannot drift into different
sets"* — measured, the sets differ in BOTH directions and always have: the
matrix carries the two model-crate legs and the battery does not, and the
battery carries `lint` and `site` which CI runs as their own jobs. **`ort-build`
was a compose service run by NEITHER** while `release.yml` shipped an `ort`
binary for five targets — a published artifact compiled on no pull request,
which is O102's *"a target you SHIP is a target that must be compiled on a
pull request"* on the FEATURE axis rather than the platform one. O142 added it
to the matrix (verified green locally first, because a leg that fails on
arrival teaches everyone to ignore it). What remains of the difference is a
DECISION and is stated as one: the two model-crate legs run in CI and not in a
local battery, both being heavy and one needing a C++ toolchain. Each of the
three survived because it was asserted in prose beside the thing it described
and nothing counted it — *a comment is not a gate*, which
is this file's own first rule applied to this file.
Heavy cargo work: use the `undercroft-target` volume + `CARGO_TARGET_DIR=/build`
(host bind-mounted `target/` SIGBUSes under memory pressure).

- **Drift check before every release**, not only when something feels off.
  The 65-drift audit found capabilities present on one surface and missing,
  weaker or silently ignored on another — 55 of them failing with no signal
  at all. Re-run it as a fan-out over the same seven dimensions (config
  wiring incl. every `UNDERCROFT_*` variable per surface, write path, search
  path, operational capabilities, error/status classes, audit-chain coverage,
  docs vs code) with an adversarial verifier per dimension. `parity.rs` holds
  the line between audits; the audit is what finds what a fixed inventory
  cannot express.
- Release flow: full Docker battery (always `--build`) → **`UPGRADING.md`
  updated if anything can stop a running deployment, and `undercroft config
  check` able to detect it** → **set the CHANGELOG and ROADMAP release date
  to the date the tag will actually be cut, as the LAST edit before tagging**
  (it is written when the release is prepared and the tag is a separate,
  later step, so it drifts by exactly as long as the prep sits in review —
  `1.1.0` was prepared on 2026-08-14 and dated that, three days before it
  could be tagged, **and then drifted a second time while still unreleased**,
  which is the argument for making this a step rather than a number someone
  sets once and trusts. A release date is not a fact about the work; it is a
  fact about the tag, and the tag does not exist yet) → PR → CI green →
  explicit maintainer approval → merge (a branch behind `main` is updated first;
  `gh pr update-branch` gives it a new head, which needs the maintainer's word
  again before a merge pinned with `--match-head-commit`, O313) → tag `vX.Y.Z`
  IMMEDIATELY, before any other pull request is updated or merged, annotated
  (`git tag -a`; the ROADMAP preflight refuses a lightweight release tag, O309),
  and never moved afterwards: a ruleset refuses a move or a deletion for
  everyone (O313), so a mis-cut tag is superseded by the next PATCH, or the
  maintainer lifts the ruleset for one recorded deletion → `gh release
  create` (the tag also fires release.yml: binaries + GHCR image) →
  post-merge CI green → Pages live-verified → **the HOUSE PAGE
  (`sealcroft.com`, a different repo) refreshed and live-verified**, which is
  `bash tests/house-figures.sh --update` for the derivable tiles and a hand
  edit for the two release claims, since those follow the published TAG
  rather than this tree and so can only move after it exists. Its CI job goes
  red until they do, which is the intended order rather than a nuisance.
  Version bumps touch
  workspace `Cargo.toml` + `Cargo.lock` (via a Docker `cargo update
  --workspace` — battery images COPY source and never update the host
  lock), `.claude-plugin/plugin.json`, CHANGELOG, ROADMAP, `CLAUDE.md`'s
  own "Current release" sentence, the landing hero release button, and
  **`architecture/index.html`'s three `Engine v…` strings**.
  **That list is no longer the authority, and this is why.** The `1.0.0`
  release commit moved **five** version-identity strings across **three**
  files, and the list named only ONE of those three (the landing hero) —
  so the `1.1.0` release-prep commit bumped that one and left the other
  two behind, which is what a hand-recalled inventory always does: drift
  toward whatever the last person remembered, with nothing able to say
  so. (Counted from `git show 6976983`, not recalled — an earlier draft
  of this very paragraph said "eight surfaces, four omitted" and was
  wrong in both figures.) The
  authority is the **`version surfaces` preflight** in
  `tests/battery.sh`, which reads the workspace version out of
  `Cargo.toml` (never a literal of its own) and counts every version
  claim in the tree against it, in both directions: a surface that
  forgot to move fails, and a NEW surface with no inventory row fails
  too. Prose above, gate below — and the gate is the one to trust.
  Note it classifies claims, because they do not share a provenance: a
  `current` claim states the version the tree IS, while an **`as-of`**
  claim (`docs/PARITY.md`'s "updated for v…") states when something was
  last VERIFIED and is deliberately NOT bumped by a release — moving it
  would assert a re-verification nobody performed. Re-verify it, then
  move it.
