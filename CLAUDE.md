# Undercroft — agent guide

Undercroft is a Rust conversion of MemPalace: hardened, local-first AI memory.
Verbatim drawers filed into wings/rooms, stored in isolated **vaults** with
per-vault HKDF-derived keys, XChaCha20-Poly1305 content sealing, and
HMAC-SHA256 integrity tags + a tamper-evident audit chain.

Published by **Sealcroft** at `github.com/sealcroft/undercroft`, site at
`https://sealcroft.com/undercroft/`, house page at `https://sealcroft.com/`
(repo `sealcroft/sealcroft.github.io`). Current release **1.6.1** — a PATCH over `1.6.0`, and PATCH is right by this
file's own test: **all three entries are fixes whose only observable change is
that a defect is gone**, no documented contract moves, and the one thing that
looks like new capability is not. `UNDERCROFT_AUDIT_CEILING` (O250) adds a
surface that REPORTS an existing silence, which the 2026-09-08 ruling settles
as a fix — the defect was the silence. Its spine is **the audit trail's cost
becoming something an operator can SEE**, which is the other half of the
1.6.0 spine: that release made the trail evidence a reader can decide from,
and this one makes its SIZE and its COST observable. **O250** — the growth was
published with nothing to read it against and `LabelGuard::replays` was
`#[cfg(test)]`, so a **+213%** regression on the flagship deployment (O242)
was found by a reviewer reading code and the observable that would have found
it existed only in test builds; the ceiling REPORTS and never deletes, because
the replay starts at a constant and a stored start point makes an emptied
`audit` verify clean (O244's ruling). **O251** — `reconcile_chain` and
`chain_verdict` made the same replay over the same rows, and the open now
hands its verdict forward, ONLY when it appended nothing afterwards: the
cookie is read BEFORE the replay so a foreign commit leaves the guard
replaying, while this connection's own commits move no cookie and are caught
by the committed head and height. **Measured at 93.0 ms** on 102,361 audit
records, replicating O237's 88 ms by a different instrument — and worth
exactly ZERO on an ordinary writable deployment, which anchors after every
write and never replays at open. **O238** — the manifest `version` was written
by every build and read by none; a binary now refuses one above its own as
AGE rather than tampering (exit 1, a class-less 409), and **its own entry's
gate was wrong**: hand-editing the number breaks the MAC and already refused,
so the proposed gate passed over an absent check. It fences nothing today,
and that is the point — O241 ruling 4 sequenced it ahead of any canonical
change because a bump PLUS a canonical field makes every older binary answer
`ManifestTampered` on an intact vault. `UPGRADING.md` records which release
the fence starts in, the fact a future upgrade needs and nobody could derive
later. **The tree carried `1.6.1` only
once the release PR merged (tagged `v1.6.1`); the TAG stays
a separate, explicit step for every release** — a build reporting a version it
was never tagged as is worse than one reporting the last release. `main` is
branch protected on both repos: force pushes and deletions blocked — GitHub
applies both to administrators too — and `CI verdict` is a required check on
this one; `enforce_admins` is off, which lets an administrator merge past that
check, not force push. Since 2026-10-06 (ROADMAP O313) a branch must also be
up to date with `main` before it merges, and a ruleset with NO bypass refuses
a move or a deletion of any `v*` tag — administrators, and so every agent
session, included.
Forking cannot be disabled while the repos are public, and they must stay
public — GitHub Free will not serve Pages from a private repo.

## How this guide is organised

This file is the agent guide's CORE: what every agent needs on every turn. The
rest of the guide lives in reference documents under `docs/agent-guide/`, each
opened only when the work touches its area; the last section of this file is
the index that says which document covers what. The split (ROADMAP O436,
2026-10-12, ruled by the maintainer: *"1 -> split and 2 also let that be the
standard"*) deleted nothing: every paragraph this file held before it is in
exactly one place, here or verbatim in a reference document. **Where this
core's one-line form of a rule and the full text in the document it names
differ, the full text governs — and any divergence found is a defect, fixed in
the unit that finds it** (ruled by the maintainer, 2026-10-12). Wherever the
guide says "this file", it means the whole guide — this core and its reference
documents.

**The split is the standard (O436).** The core stays at or under 60 KiB (ruled
by the maintainer, 2026-10-12): a budget for the one file every agent pays for
on every turn. New layout, lessons and doctrine go into
the reference document that owns the area, with at most a one-line pointer
here; an area with no document gets one, and a row in the index. A figure a
gate reads lives in ONE file, the one its gate reads, and a one-line statement
here never repeats it. The `prose figures` preflight holds the size and the
index in both directions.

## Who works on this project — the role every agent takes

**Every agent on this project — the session agent and every subagent it
spawns — works as an expert Senior Engineer holding three competencies at
once: Software Engineering, Agentic Memory Architecture and design, and
Security.** Not one of the three in turn, and not a generic coder. This is a
role statement, not a flourish: it is what the work has repeatedly needed and
what its absence has repeatedly cost.

- **Software Engineering** — the change compiles, is tested on both sides of
  its premise, is verified on every surface that reaches it, and leaves no
  second implementation of one decision.
- **Agentic Memory Architecture and design** — reason about **identity,
  lifetime, provenance and traceability BEFORE writing code.** A stored
  memory's value is that a reference to it still resolves later: across a key
  rotation, across a migration, across an export, and across an agent's own
  sessions. For any identifier or index key the question is one line: *what
  holds a reference to this, and what is that reference's lifetime?* The
  worked example is A10 — a rotating key used to derive identifiers, which
  would have orphaned every audit record, receipt and agent-held id at once.
- **Security** — assume the offline reader, the malicious writer and the
  injected drawer. Ask what a gate can **SEE**, not what it asserts: the two
  most expensive defects in this tree were gates measuring an observable the
  defect does not move (a substring scan against a hex digest; a column
  snapshot against a recipe that only moves when next derived).

Consequences that are binding, not advisory:

- **Verify by reading code. A heading, a doc claim, a CHANGELOG bullet and a
  test NAME are not verification** — headings here have been wrong
  repeatedly and are the most expensive artifact this project produces.
- **Report your own defects as your own**, never as discoveries. A fix that
  introduces a hole and reports it as a finding is worse than the hole.
- **Do the impact analysis first**: establish what a change touches and what
  could fail *silently*, plan it, prove it, then present the diff.
- **GROUND THE DECISION BEFORE ACTING — the doctrine is the first place to
  look, not the last.** The order is: read the architecture files and folders,
  read this doctrine, read the code, **and look for a ruling already made** —
  search `ROADMAP.md` case-insensitively for `rul(ed|ing)` inside the entry
  that owns the question and inside every entry it names, because rulings here
  are written as `#### RULED` subsections, bold `**RULED …**` lines and plain
  prose alike. If they answer the question, **follow them** — that is not a
  decision to narrate, it is the standard. If they do NOT answer it, do not
  fall back on your own judgement and report afterwards ("I did X, here is
  why" hands the maintainer a fait accompli dressed as a status update), and
  do not hand the maintainer an option list either: **a ruling panel decides
  it** (ROADMAP O173). The maintainer, 2026-09-14, verbatim: *"fanout
  specialized agents in Agentic memory for the options that require ruling,
  and if there was an exiting ruling then follow it if it was best practice
  otherwise revise it and refute it first, no need to keep repeating the same
  questions at every new session"*.
  **The minimum panel.** At least THREE lens agents, each holding this role,
  one of them always Agentic Memory Architecture and the others chosen by
  what the question moves; one written brief; read-only; no sight of each
  other's answers. **Plus an adversarial refuter on EVERY ruling, not only
  when the lenses split**: it verifies every load-bearing claim in the lenses
  and the brief by reading code, finds and judges any prior ruling,
  re-measures any figure the verdict contradicts, reports what is wrong in
  the brief, and says what would make the verdict fail silently. Convergence
  is not correctness: O38 passed three lenses 3/3 on a false figure, and
  O160's record, from a review with three converging lenses and no refuter,
  called an inline three-literal comparison a byte-identical copy of a
  function that answers differently for `::1`. A split is settled by
  evidence, never by vote; where only execution can settle it, the panel
  names the probe and the integrator runs it (O157's `required-features`
  probe). Builds, tests and the battery never belong to a panel (the fan-out
  rule below).
  **A prior ruling is FOLLOWED when it is best practice.** Otherwise the panel
  REFUTES it with evidence first, recorded beside it, and only then revises
  it — never deviated from on taste, never deleted in place of its revision
  (O137, on the O24a precedent). A question with a recorded ruling is not
  asked again, of the maintainer or of another panel, unless new evidence
  contradicts the ruling.
  **Record every ruling where the next session looks**: a
  `#### RULED <yyyy-mm-dd> by <the maintainer | the lenses it ran, and the refuter>`
  subsection in the ROADMAP entry that owns the question. It carries the
  question; the prior ruling found, or the search that found none, and its
  disposition; each option with its cost and why it lost; the claims refuted,
  including the brief's; any probe run; dissent; and what remains. A question
  with no entry gets one first — under `## Open` if it is work, under
  `## Unversioned` with its `UNVERSIONED_CLOSED` row if it is a pure
  decision. A panel's working directory is material, never the record, and a
  ruling that lives only in a handover, auto-memory, a commit message or a
  transcript has not been recorded — O135's was written only into the
  handover, and its entry still read unruled when this rule was written.
  **What a panel does not decide.** A panel rules design and engineering
  questions the tree and best practice can settle. It grants no permission,
  because no agent's verdict is the maintainer's consent: commits, pushes,
  opening or merging a pull request, tags and releases, launching a benchmark
  or long run, and any outward-facing or irreversible change (the house page,
  a GitHub or Pages setting, a published image) are asked for exactly as
  before. **Escalated to the maintainer with the panel's analysis attached**:
  a product, business, licence or naming choice, including what a surface
  offers (O66's three readings were the maintainer's); a question the refuter
  states neither the tree nor best practice settles; and any verdict that
  would overturn a ruling the maintainer made on such a choice. A
  maintainer's DESIGN ruling is a prior ruling like any other — followed if
  best practice, otherwise refuted and revised in the open, in the pull
  request the maintainer approves. A change to THIS FILE is ruled the same
  way and lands only through that approval, because this file's worst
  doctrine errors were caught by the maintainer and not by a gate.
  The corollary survives the change: a brief assembled without the reading is
  a guess wearing a question mark and pushes the grounding onto the panel. Do
  the reading, THEN convene, and only where the reading genuinely ran out.
  No gate sees this rule broken — re-asking a settled question moves no text
  a gate can read — so the lookup and the tracked record are the whole
  mechanism.
  Applied backwards, as a rule here must be: it CONFIRMS the drift-direction
  doctrine, the impact-analysis rule and O24, where the reading answered and
  nothing needed ruling. It CONFIRMS the panels on O113 and O137/O138 and the
  2026-09-12 panel over O134, O135 and O140, each determined rather than
  chosen and ratified by the maintainer. It also CONFIRMS O112 as the
  escalation path, a naming question determined by agents and ruled by the
  maintainer, and the 2026-09-13 fleet over O157, O160 and O161, each merged
  through a pull request the maintainer approved. It RECLASSIFIES the ask step
  of M6 and M11 as a panel's step without moving either decision. It
  RECLASSIFIES the maintainer's design rulings on O131, O138's re-scope, O154
  and O155 as questions a panel could now answer, their verdicts standing as
  prior rulings, and the 2026-09-13 practice of a refuter only on a split as
  short of the minimum. It still RECLASSIFIES the M9/M10 scoping and the
  `tls-pins` repair as wrong, because acting and then reporting is not a
  panel. It does not touch O5, O6, O37, O66, the house-tile ruling or any
  commit or push. Its history is those panels, all between 2026-09-09 and
  2026-09-14, the minimum of three is grounded in that practice rather than
  in any measured comparison against two, and this is its first application
  as binding text.
- **A gap is a gap** — never dressed up as a principled refusal.
- **A RULE written into this file gets the same scrutiny as code, and the
  test is the same one: apply it backwards.** Before a doctrine lands here,
  run it over decisions the tree has already made and see what it
  reclassifies. If it changes nothing, it is describing what is already done
  — say that, or do not write it. If it changes a lot, the rule is probably
  wrong, and every past decision it overturns owes its own argument.
  This is not hypothetical. A versioning doctrine was written here as *"MAJOR
  carries anything that can stop a deployment which worked before"*, and it
  read as obviously correct. Applied backwards it would have made most of
  this project's past security fixes major releases, and none of them were —
  which is the signal that the RULE was wrong, not the history. The real test
  is a **documented contract** that changes; "a deployment could stop" is a
  different question with a different answer, and conflating them would have
  inflated every future hardening fix into a major. The maintainer caught it,
  not a gate.
  **"It changes nothing" has two meanings and they are opposite.** Either the
  rule describes what the tree already does — fine, say so — or there is no
  history to test it against, which is not validation at all. Applying the
  CORRECTED versioning test backwards returns the second: `1.0.0` is the only
  release under it and it was a version RESET, so nothing before it promised
  an upgrade path. The rule is therefore **untested by history and this
  release is its first real application**, which is a caveat that has to be
  written down rather than mistaken for a pass.
  So: a doctrine is a claim about the tree, and an unverified claim about the
  tree is exactly what the rule above forbids for code. **The reasoning that
  produces a rule fails in the same ways the code does, and it is harder to
  notice because prose does not fail to compile.**
- When fanning out subagents, they inherit this role and the read-only rule
  that goes with parallel work (a shared cargo target dir yields false
  greens; builds and the battery belong to the integrator).

## Layout

What every crate, directory, workflow and vendored file holds — with the
decisions and defects that shaped it — is in the `layout-*` reference
documents; the index at the end of this file says which one covers which path.
These stay in the core:

- `Cargo.toml` — workspace root (13 crates; `undercroft-embed-onnx` and
  `undercroft-embed-ort` excluded from default-members — heavy ML deps,
  built explicitly)
- `SECURITY.md` (disclosure policy; private vulnerability reporting is
  enabled on the repo), `NOTICE` (MemPalace MIT heritage attribution, and
  the vendored `tiny_http`), `LICENSE` (BUSL 1.1 — see Conventions)

The upstream Python implementation (the MemPalace project) is *not* in
this repo and no longer linked as a fork; its behavior is documented in
docs/PARITY.md. Never reintroduce Python code here.

## Build & test — Docker only

Build and test **inside containers**, not on the host (project policy):

Prefer `bash tests/battery.sh`; a direct `docker compose run` always takes
`--build` (below). The suites and what each covers:

```bash
bash tests/battery.sh                     # every suite in one pass, or name a subset
bash tests/battery.sh --preflight-only    # the host-side preflights and no suite (CI's preflight job)
bash tests/battery.sh --no-preflight <s>  # suites without the preflights (CI's suite legs)
docker compose run --rm test              # cargo unit + integration tests
docker compose run --rm lint              # rustfmt --check + clippy -D warnings, default AND telemetry builds
docker compose run --rm e2e               # e2e UI/UX suite against the release binary
docker compose run --rm orchestrator-e2e  # two engines + orchestrator
docker compose run --rm e2e-telemetry     # telemetry build + /metrics gating
docker compose run --rm backends-e2e      # five live vector DBs over TLS
bash tests/tls-pins.sh                    # CA pins readable + both shipped stacks start; host-side
docker compose run --rm arch-check        # both architecture diagram sets' gates, read-only mount
docker compose run --rm obs-config        # the observability config suite
docker compose run --rm onnx-build        # the tract backend + its tests
docker compose run --rm ort-build         # the ORT backend + the CLI model join
docker compose run --rm site              # build AND assemble the site
docker build -t undercroft .              # runtime image
```

**Every published suite figure** — a shell suite's check count, a cargo leg's
run and ignored counts, the cargo test totals and the host-side preflight
count — is in `docs/agent-guide/build-and-test.md`, the one file the battery's
figure comparison and `tests/house-figures.sh` read. Update a figure THERE
when a count moves.

**Essentials** — each in full in `build-and-test.md`, `build-pitfalls.md` or
`ci-and-release.md`:

- **The exit code is the verdict.** `tests/battery.sh` never parses suite
  output to decide pass/fail and never pipes a suite; it runs every suite in
  one pass over one tree. Never let a pipeline's tail mask an exit code you
  depend on. Logs land in `.battery/`. Since O439 it builds its images once per
  run from one `builder`, runs the suites side by side on them (`--serial` for
  one at a time) with the preflights beside them, and every suite on them first
  proves its image was built from the tree under test
  (`undercroft-battery-premise`).
- **Heavy cargo work** uses the `undercroft-target` volume with
  `CARGO_TARGET_DIR=/build` (a host bind-mounted `target/` SIGBUSes). Always
  pair the volume mount with `CARGO_TARGET_DIR`, and give each parallel agent
  a private target dir (`CARGO_TARGET_DIR=/build/<agent>`) — a shared one gives
  a FALSE GREEN.
- **Prove a freshly built binary is fresh** before trusting a run: probe it
  for a symbol only the new code has. When an error contradicts the source you
  are reading, suspect a cached artifact or a stale compose build context
  before suspecting the code.
- **Git Bash mangles container paths** in `-v`/`-e`/`-w` values: prefix a
  docker command that carries them with `MSYS_NO_PATHCONV=1`.
- **A scripted edit is a change you have not read**: never carry an index
  across a mutation, read what is ADJACENT to an anchor, byte-scan what a
  script wrote, never redirect a checker's stderr, read the whole diff of a
  regex sweep, chain a counterfactual's run behind its edit so a failed apply
  STOPS, and exercise the ARTIFACT, never a copy. Compile after EVERY
  structural edit, before making the next one.
- **Bound every wait**, and watch the PROCESS, not a sentinel in a file it may
  never write.
- **Line endings are LF and enforced**: write files in BINARY mode, and cite
  `git ls-files --eol`, never `grep -c $'\r'`.
- **Union** is the right conflict resolution for CHANGELOG bullets and the
  WRONG one for code.
- **CI** runs fmt and clippy DIRECTLY, not through the compose service (the
  `lint parity` preflight compares the two), runs the suites as a
  `fail-fast: false` matrix through `bash tests/battery.sh --no-preflight
  <suite>`, and publishes `CI verdict`, the one required context. A target or
  a feature this project SHIPS is compiled on every pull request.

**`cargo build -p <crate>` does not compile that crate's integration tests.**
`tests/*.rs` needs `--tests`. Three unbalanced-brace defects survived several
"green" targeted builds this way and only surfaced in the compose battery, one
at a time, as different build targets reached each file.

**Always pass `--build`.** The battery images COPY the source, they do not
mount it — `docker compose run --rm test` without `--build` silently
re-runs whatever was baked into the last image, so a "green" run can be
testing code you already changed. rustfmt cannot fix host files from those
images either; mount the repo instead:
`docker run --rm -v "<repo>:/src" -w /src rust:1.98.1-slim-bookworm sh -c "rustup component add rustfmt; cargo fmt --all"`

## Invariants to preserve (inherited from MemPalace's mission + vault layer)

One line each here; the full text — the mechanism, the worked example and
what each cost — is in `docs/agent-guide/invariants-storage.md`,
`invariants-retrieval.md` and `invariants-surfaces.md`, and where a line here
and its full text differ, the full text governs and the difference is a defect
to fix.

- Content is stored **verbatim** — never summarize, paraphrase, or lossy-
  compress user data on the write path. Retrieval returns the exact words.
- Local-first, zero external API by default: no phone-home; the default
  embedder is deterministic and offline. Observability is **opt-in** behind
  `--features telemetry` — default builds carry zero telemetry deps and emit
  nothing; when on, signals are **metadata/counts only** (never drawer content
  or keys) and nothing leaves the process unless an endpoint is set.
- Derived structure that is recomputable from content must **not** be
  persisted in clear beside it, and where it is recomputable at read it
  generally should not be persisted at all — `time_mentions` and `entities`
  are both read live (`live_time_mentions_in`, `live_entities`), which is
  also what makes a scanner fix and a language choice reach existing vaults
  with no migration.
- Drawer ids are deterministic over (wing, room, source, chunk_index,
  normalize_version); re-mining stays idempotent and append-only. An API
  save's `chunk_index` is a unique append index (`next_append_index`), never
  `count()`; a second id space gets a DOMAIN TAG and keeps every component —
  never substitute a constant for one. (`invariants-storage.md`)
- Sealed vaults never persist plaintext or plaintext-derived data **in
  clear**: FTS never exists for them, every derived artifact is AEAD-sealed
  under its own AAD domain, nothing that copies words lives in the unsealed
  `meta_json`, and what a drawer costs and what metadata it exposes are pinned
  by tests that fail in both directions. (`invariants-storage.md`)
- Cross-lingual retrieval is the **embedder's** job and the default hash
  embedder cannot do it; a served multilingual embedder is the measured lever.
  Reading dates inside the text is the scanner's job. (`invariants-retrieval.md`)
- Every write updates the audit chain **atomically with its data**
  (`chain_append` inside the same SQLite transaction; the manifest's lagging
  anchor reconciles at open — crash ⇒ fast-forward, rollback ⇒ tamper); every
  read verifies the record HMAC before returning data; anything that REPORTS
  the chain reads `chain_meta`. (`invariants-storage.md`)
- Durability is pinned, not assumed (WAL + `synchronous=FULL`, fsynced atomic
  renames with a directory sync, key material fsynced at creation); the anchor
  never runs **ahead** of the database, and ONE door writes it
  (`VaultStore::anchor()`). (`invariants-storage.md`)
- **A signal is read; a convention is declared; nothing is inferred** —
  evidence the writer typed or the caller declared is legitimate, a calendar,
  era or field order derived from anything else is not. (`invariants-retrieval.md`)
- **A recall measurement cannot justify a precision decision**: a rule feeding
  a channel that ADMITS needs negative controls (`false_friends_stay_apart`),
  not a link count. (`invariants-retrieval.md`)
- **No compression unit may ever span two drawers' plaintext**: no shared
  zstd dictionary, PQ pages never compressed, fixed-rate over entropy coding
  anywhere new, a decode buffer sized from the frame header, and a length
  check whose arithmetic cannot wrap. (`invariants-storage.md`)
- **Independent per-item scoring is a poison-resistance property, and
  spending it is a decision**: anything that couples drawers may PROPOSE
  candidates, never DECIDE score. BM25's pool-shaped IDF is a stated cost,
  never to be "fixed" by a corpus-wide count; codebook training draws are
  stratified, keyed and capped per wing and per agent claim.
  (`invariants-retrieval.md`)
- **A search cannot verify its own blind spot**: "none found" is a claim
  about the method — decompress rather than grep, cover other scripts,
  truncated roots and the identity, and ask what the tooling DERIVES; describe
  a hunted class, never the token. (`invariants-surfaces.md`)
- **A screen's scope must match the scope of the read it guards**: ask what
  the READ returns, and keep the covered set an inventory checked in both
  directions (`admission::SCREENED_FIELDS`). (`invariants-surfaces.md`)
- **A capability missing from one surface is a boundary or a drift, and
  which one is written down**: a choke point where the drift is a class, an
  inventory counted against THE CODE in both directions where it is arithmetic
  (`parity.rs`, `SURFACE_ABSENCES`, `OPERATOR_ONLY`). (`invariants-surfaces.md`)
- **A drift has a DIRECTION, decided by provenance**: a new capability, the
  code leads; a fix to something already promised, the documents lead; and a
  claim consistent across every surface INCLUDING the doctrine means the CODE
  is wrong. (`invariants-surfaces.md`)
- **An IDENTIFIER is never derived from rotatable key material, and neither
  is a blind-index key**: where keying is needed, use a per-vault secret stored
  sealed in `meta`, re-sealed by rotation and never regenerated. Before
  changing how any identifier is derived, enumerate what holds a reference to
  it and that reference's lifetime; a label IS evidence, so a migration that
  moves an identifier may not relabel in place. (`invariants-storage.md`)
- **Rotation completeness is ENFORCED, not remembered**: every sealed column
  and meta value is named in `rotate.rs`, held by two gates.
  (`invariants-storage.md`)
- **A clear MIRROR column is safe for a narrowing filter and unsafe for an
  EXCLUSION**: a security decision reads the HMAC-covered copy
  (`verified_meta_admits`), never the mirror. (`invariants-storage.md`)
- **A migration's ADD COLUMN list and `READ_SCHEMA` are ONE inventory,
  counted both ways.** (`invariants-storage.md`)
- **An at-rest migration marks itself complete only when it IS complete**:
  its marker written LAST and only on a clean walk, what is pending reported on
  `VaultStats.unhealed`, with a VACUUM and a byte-reading gate.
  (`invariants-storage.md`)
- **A struct is not a surface**: a hand-projected report goes into
  `parity.rs::HAND_PROJECTED` when it is created. (`invariants-surfaces.md`)
- Cross-vault access must fail cryptographically (AAD binds vault id), not
  just logically.
- Vault/wing/room names go through `undercroft_core::validate_name` (path
  traversal guard).
- **A guard runs BEFORE any step that rewrites the field it guards, and a
  guard names the field it refused**; its backwards test runs over every field
  the rewriting step touches, never only the one a filing names.
  (`invariants-storage.md`)

## Definition of done — every unit, no exceptions

A unit is not done when the code works. It is done when all of this is true,
and this list exists because a session shipped work that passed every check it
had and was still bypassable on the surface most deployments use.

1. **Unit tests AND integration tests.** Both, every time, for every change —
   not "where it made sense". A unit test proves the function; an integration
   test proves the SURFACE. The 65-drift audit happened because capabilities
   were verified through one surface and assumed on the others. If a change
   touches behaviour a user can reach, an e2e check exercises it *through the
   surface a user actually drives*, and if it touches more than one surface it
   is exercised through each of them.
2. **A test that would have failed before the fix.** Assert the premise, so it
   cannot pass for the wrong reason. A passing battery is not evidence a test
   is DETERMINISTIC — only repetition is: never assert an exact order over
   content that ties, and run a test touching PQ, FDE, a codebook or any keyed
   draw in a loop before believing a green. Counterfactual the FIX, not only
   the defect; and when a counterfactual fires on only SOME of your checks,
   the ones that stayed green are the finding. (Full text:
   `docs/agent-guide/definition-of-done.md`.)
3. **Drift check.** If the change touches a capability reachable from more
   than one of {CLI, MCP, `/v1`, orchestrator}, verify EVERY one of them —
   by reading the other surfaces' code, not by assuming symmetry. `cargo test`
   runs `parity.rs`, which counts the MCP tool surface against a written
   inventory in both directions and enforces the operator-only boundary; it
   catches an added or removed TOOL, and it cannot catch a capability that
   drifts in behaviour. That half is yours.
4. **Every governance surface updated in the same unit**: CHANGELOG, CLAUDE.md
   and whichever reference document under `docs/agent-guide/` states the
   claim, ROADMAP, **the three `.handover/` files and, when present,
   `NEXT_PROMPT.md`**, **the HOUSE PAGE at `sealcroft.com` when a figure it
   publishes moves** — `bash tests/house-figures.sh --update`, run BEFORE the
   push, then the live page verified — and whichever of docs/AGENTS.md,
   docs/THREAT_MODEL.md, README, architecture/index.html, website/ carry the
   claim you changed. A claim lives on every surface that states it. (Full
   text, with why the house page is the surface this rule keeps failing on:
   `docs/agent-guide/definition-of-done.md`.)
5. **The full Docker battery** at the final tree, with raw exit codes:
   `test`, `lint`, `obs-config`, `arch-check`, `e2e`, `orchestrator-e2e`,
   `e2e-telemetry`, `backends-e2e`, `site`, `tls-pins`. `cargo build -p <crate>` does **not** compile
   integration tests — `--tests` does. **Every time, never a subset** — and
   never piped: a pipeline's status is its LAST command's, so `| tail` reports
   success over a failing battery. Confirm it ran AFTER the last edit rather
   than assuming; `.battery/*.log` mtimes settle it in one line.
6. **Load a real corpus and drive the change through it.** A fixture proves
   logic and is structurally blind to cost, to schema ordering, and to
   anything that only appears at N > 3. Corpora on hand:
   `.handover/bench-data/` (LoCoMo, LongMemEval), `.handover/locomo_feed.txt`
   (minable), `crates/undercroft-store/testdata/*_50k.txt`,
   `benchmarks/model_eval/datasets/` (10 languages). Mining the LoCoMo feed
   into N wings gives a few thousand real drawers in seconds.
   **This is not belt-and-braces; it is the only thing that caught two
   defects on 2026-08-10, both written minutes earlier and both invisible to a
   green battery**: a `verify` leg issuing one query PER DRAWER against an
   unindexed column (fine on two rows, O(N) with an unindexed inner scan on a
   corpus), and a `CREATE INDEX` placed above its own `CREATE TABLE` in an
   ordered batch, which broke `init` outright — every command dead, and no
   unit test reached that path. Measure the thing you changed: `verify` went
   14→21 ms with deletions unindexed, 13→13 ms with the index.
7. **Count the renderers, not the surfaces.** `ui.html` and the orchestrator
   console are `/v1` clients that a new report field reaches for free and
   stops dead in: one `parity.rs::HAND_PROJECTED` row per (struct, renderer)
   pair, and a row for one struct says nothing about the next. Prove the
   binary carries the markup, then LOOK at the page; an exempt renderer is a
   decision written down, never a missing row. (Full text:
   `docs/agent-guide/definition-of-done.md`.)

## Session-end hygiene — leave no debt, drift or stale

Run this before ending a session, and record the result. The rule from the
maintainer: *we don't leave debts or drifts or even stales anywhere in this
project.*

**The working cycle, and the context-budget rule that bounds it.** Work is
**read → fix → test → commit**, one unit at a time; the full Docker battery
runs and a real corpus is loaded at every unit (definition of done, items 5
and 6). **When the context window reaches roughly 90%, STOP TAKING NEW UNITS
and spend what is left updating every governance surface** — CHANGELOG,
ROADMAP, this guide, whichever docs carry the claim you changed, and the three
`.handover/` files (and `NEXT_PROMPT.md`) with their first block naming
`HEAD`, except `AUDIT_CONTINUATION.md`. **MEASURE that 90%, never estimate it:
`bash tests/context-check.sh <session-id>`**, with the session id from the
system prompt's transcript path, never the no-argument form; the window is
1,000,000 tokens, not 200,000. A session that spends its last tokens on the
handover leaves an accurate map; one that half-lands one more fix leaves a
tree the next session cannot trust. (Full text, with its measured history:
`docs/agent-guide/session-end-hygiene.md`.)

**Never half-land a change that alters a security verdict, an on-disk format,
or an id recipe.** File it instead — with its mechanism, the alternatives you
rejected and why, and its gate. ROADMAP `O13` is the worked example: round
four's second CRITICAL, analysed far enough to establish that the fix is a
THIRD verdict state rather than a corrected one, and deliberately left
unwritten because a half-correct verdict is worse than a known-wrong one.

- **Docs vs code**: every number, tool table, route table and `UNDERCROFT_*`
  variable in README, CLAUDE.md, docs/*.md, architecture/index.html and
  website/ verified against the code — counted, not remembered. Landing-page
  stats and doc tables have gone generations stale before.
- **The published site**: `docker compose run --rm site` builds, and after a
  Pages deploy the live page is checked, not assumed.
- **The architecture reference**: if a diagram changed, `build.sh` re-run in
  Docker (diagrams/ is the only source; pdf/ and the inlined copies are
  derived, and the script fails if a heading and the rail disagree).
- **Open threads written down AS WORK**: every residual, gap and deferred
  decision recorded in ROADMAP with its reason, the shape of its fix, and a
  gate — a gap is a gap, and **"accepted" is not a resting state**. Anything a
  surface calls filed, or an open question, gets its own id heading (a
  sentence inside a finished entry is not a filing, O171), and relations
  between open entries live in the entries, as a bold `Relations:` line the
  partner names back (O169). (`session-end-hygiene.md`)
- **The handover is a GOVERNANCE SURFACE that is deliberately NOT
  committed**: `.handover/` stays gitignored — never un-ignore it — and
  `SESSION_START.md`, `NEXT_SESSION.md` and `AUDIT_CONTINUATION.md` (plus
  `NEXT_PROMPT.md` when present) are kept current in the same unit as the
  work. The handover-freshness preflight sees only whether the first block
  names `HEAD`, never whether its words are true. (`session-end-hygiene.md`)
- **Every ROADMAP entry states its own status in its HEADING**, matching its
  body, and a closed entry sits under the release that shipped it — a pure
  decision under `## Unversioned`, with its row in `tests/battery.sh`'s
  `UNVERSIONED_CLOSED`. An entry's subsections are `####`, never `##`; an
  open entry's body never carries the bare status token in capitals; a
  released heading never changes; a release tag is annotated. The `ROADMAP
  headings` preflight holds all of it — read
  `docs/agent-guide/session-end-hygiene.md` before you edit `ROADMAP.md`.

## Conventions

- Rust 2021, workspace-level dependency versions, `thiserror` per-crate error
  enums, `anyhow` only in the CLI.
- Keys live in `SecretKey` (zeroize-on-drop); never `Debug`-print key material.
- **The tree has ONE `unsafe` block** — `undercroft-store`'s
  `vault_db::descriptor_has_moved`, SQLite's moved-file check on a
  connection's own descriptor, which rusqlite does not wrap (ROADMAP O279,
  ruled by the maintainer 2026-09-27: "allow the unsafe"). Every safe
  alternative measures a path and had a measured hole. It carries a
  `// SAFETY:` comment, the store is `#![deny(unsafe_code)]` with one
  `#[allow]` on it, and a source gate counts exactly one `unsafe` in every
  crate's production code. A second one is a new decision for the
  maintainer, not an extension of this one.
- **Sealcroft is the HOUSE and never ships. Undercroft is this product.**
  Nothing is ever called bare `sealcroft` at the command line, in a crate, in
  an env var or in an MCP tool name — the product word carries the technical
  namespace, the house name carries only the org, the domain and the docs.
  The reason is mechanical, not aesthetic: `sealcroft-core` is ONE global
  crates.io name, so whichever product claims it locks the others out;
  `SEALCROFT_*` is ambiguous on a host running two of them; and **MCP tool
  namespaces are flat per agent**, so two Sealcroft servers collide by name in
  a client that has both. Binding for the planned sibling products (a security
  posture tool and an AI harness): each takes its own one-word namespace under
  `github.com/sealcroft`, exactly as `undercroft`/`UNDERCROFT_*`/
  `undercroft_*`/`undercroft-*` does here.
- **`compufreq` is a PERSON, not the org.** It stays in the LICENSE Licensor
  line, the NOTICE copyright, `Cargo.toml` authors, the git identity and the
  SECURITY contact. Only repository/registry/Pages URLs moved to `sealcroft`.
- Git identity for this repo: compufreq <compufreq@proton.me>.
- License: **BUSL-1.1** (source-available; rolling 4-year conversion to
  MPL 2.0; `NOTICE` carries the MemPalace MIT heritage attribution).
  Never reintroduce MIT as the project license or publish under it.
- **Semantic versioning, and the test for MAJOR is a DOCUMENTED CONTRACT
  that changes — not "a deployment could stop".** Those are different, and
  conflating them inflates a fix release into a major one. MAJOR is a removed
  or renamed surface, an on-disk format that will not open, a default that
  changes what is retrievable, a documented value that stops being accepted.
  MINOR is new capability, backward compatible. PATCH is a fix whose only
  observable change is that a defect is gone.
  **Tightening validation of input that was never documented as valid is a
  FIX, not a break.** A config value that was always a typo, an exit code
  that always contradicted the published doctrine, a refusal the policy
  always stated but enforced one step too late — closing those makes the code
  match the contract, and a deployment that "worked" on the old behaviour was
  running without the protection it declared. Say that plainly rather than
  reaching for a major.
  **Surface added to REPORT an existing silent defect, or to close a drift,
  is a fix too** (ruled 2026-09-08 for `1.5.2`). A counter, a stats field or
  an alert that makes a failure visible adds no capability — the defect was
  the silence, and the surface is how an operator sees it is gone; a flag
  that gives one surface a parse the other surfaces already shared is a
  drift closure, and a capability new to one surface but old to the product
  is not a feature. Applied backwards this reclassifies **nothing** — `1.5.0`
  stays MINOR because the per-vault database genuinely gained a name no
  surface had, and `1.2.1`/`1.2.2` stay PATCH — so it is describing what the
  tree already does, which is the honest thing to say about it rather than
  dressing it up as a new rule. Its whole history is one release.
  What such a fix DOES owe is warning: **anything that can stop a running
  deployment gets an `UPGRADING.md` entry in the same unit**, with symptom,
  cause and fix, and `undercroft config check` must be able to detect it
  before a restart. That is the obligation, and it is not the same as a
  version bump. ROADMAP is filed by target release.
- **A declared configuration is classified, and the class decides what a bad
  value does.** Where a declaration merely ADJUSTS a conservative default
  (`Tunes`), garbage warns and keeps the default; where the DECLARATION turns
  a protection on, pins an outward path or names a vector space (`Protects`),
  garbage REFUSES to open — and a mandatory operand inherits its selector's
  class. Every `UNDERCROFT_*` variable is a `(name, ConfigClass, Parse)` row
  in `parity.rs::ENGINE_ENV_VARS`, counted against the code on both axes, and
  `undercroft config check` runs each declaration through the resolver
  start-up runs. A closed vocabulary may read empty as its default and is
  trimmed; opaque payload — a secret, a path, a token — refuses empty and is
  never trimmed. (Full text, with the counted split: `config-classes.md`.)
- **A declaration that CANNOT WORK is refused, never quietly adjusted into
  one that can** — a bearer ending in whitespace, which HTTP strips, is
  refused rather than trimmed — and "cannot work" is measured, not reasoned
  about. (`config-classes.md`)
- **Merging a pull request (ROADMAP O313).** `main` takes only a branch that
  is up to date with it, so a branch behind `main` is updated first — and `gh
  pr update-branch` gives it a NEW head, which needs the maintainer's word
  again before a merge pinned to that head with `--match-head-commit`. Never
  merge past the gate with `--admin` or the interface's bypass box: the
  up-to-date rule binds an administrator only through gh's refusal and this
  doctrine. (The release flow in `ci-and-release.md` carries the same step.)
- **Drift check before every release**, re-run as a fan-out over its seven
  dimensions with an adversarial verifier per dimension, then the **release
  flow**: the battery (always `--build`) → `UPGRADING.md`, with `undercroft
  config check` able to detect it, for anything that can stop a running
  deployment → the release date set to the tag's day as the LAST edit → PR →
  CI green → explicit maintainer approval → merge → an ANNOTATED tag at once,
  never moved → `gh release create` → post-merge CI, Pages and the HOUSE PAGE
  live-verified. What a version bump touches is the `version surfaces`
  preflight's to say, never a remembered list. (`ci-and-release.md`)

## Reference documents — read the one your work touches

Each is under `docs/agent-guide/`, holds its part of the guide verbatim, and
names the gate that reads any figure in it. Open the one or two your work
touches before you change anything there; never all of them.

- `layout-core.md` — `crates/undercroft-core`: normalization and the
  retrieval fold, script segmentation, the hash embedder and its migrations,
  temporal extraction, calendars and locales, the model-panic boundary.
- `layout-vault.md` — `crates/undercroft-vault`: the database file and its
  legacy name, keys and HKDF, sealing, the manifest and its one writer, the
  archive, restore and delete filesystem sides, export bundles.
- `layout-store.md` — `crates/undercroft-store`: search and its channels,
  morphology, the semantic gate, prefilters and scope, the audit chain and
  label guard, `verify`, the knowledge graph, the import, backup, restore,
  delete and open doors, admission, forgetting, retention, trust, the read
  choke point, audit namespaces, egress, rotation, the witness.
- `layout-config-net-obs.md` — `crates/undercroft-config`,
  `crates/undercroft-net` (transport policy, CA pins, body ceiling), the OTLP
  hop, `crates/undercroft-obs` (the stdio door, telemetry, series inventory).
- `layout-models-index-llm.md` — `crates/undercroft-index`,
  `crates/undercroft-llm`, `crates/undercroft-embed-onnx`,
  `crates/undercroft-embed-ort`: remote indexes, served and in-process models.
- `layout-cli-orchestrator.md` — `crates/undercroft-cli` (posture, MCP,
  `parity.rs`, search declarations, `/v1`, `--read-only`, the consoles) and
  `crates/undercroft-orchestrator`.
- `layout-bench-research.md` — `crates/undercroft-bench`,
  `docs/AMB_REPLICATION.md`, `docs/research/`.
- `layout-docs-diagrams-site.md` — `architecture/` (and `DIAGRAM_LESSONS.md`,
  read before changing any diagram), `architecture/platform-views/`,
  `docs/diagrams/`, `website/`, `docs/AGENTS.md`.
- `layout-deploy-ci-vendor.md` — `deploy/`, the e2e and `tls-pins` suite
  scripts, `vendor/tiny_http`, `.github/workflows/release.yml`.
- `build-and-test.md` — the full command block with every published suite
  figure, the served-embedder TLS recipe, how `tests/battery.sh` and its
  preflights work, line endings, the local LLM. Read it before running the
  battery for a verdict, when a count moves, or when adding a suite or a
  preflight.
- `build-pitfalls.md` — stale binaries and artifacts, Git Bash path mangling,
  shared target dirs, scripted-edit and counterfactual traps, unbounded waits.
  Read it before a scripted edit or a counterfactual, or when a result
  contradicts the source.
- `ci-and-release.md` — CI's jobs, matrix and verdict, the pinned toolchain
  and supply chain, `house-figures`; the pre-release drift check and the full
  release flow. Read it when you touch `.github/`, a pin, a tag or a release,
  or merge a pull request.
- `invariants-storage.md`, `invariants-retrieval.md`,
  `invariants-surfaces.md` — the full invariants summarised above.
- `definition-of-done.md` — items 2, 4 and 7 in full.
- `session-end-hygiene.md` — the context budget, open threads, the handover,
  and every ROADMAP rule. Read it before editing `ROADMAP.md`.
- `config-classes.md` — the configuration-class doctrine in full. Read it
  when you add or change an `UNDERCROFT_*` variable or a resolver.
