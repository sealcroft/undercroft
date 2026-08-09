# Undercroft Roadmap

Undercroft is the Rust conversion of MemPalace with a hardened memory-management
layer (isolated vaults, XChaCha20-Poly1305 encryption, HMAC integrity).

---

## How this file is organised — semantic versioning

Work is filed under the release that will carry it, using the standard
convention. There was no versioning doctrine at all before this.

| | Carries | Test |
|---|---|---|
| **MAJOR** (`2.0.0`) | An incompatible change to a documented contract | A removed or renamed surface; an on-disk format that will not open; a default that changes what is retrievable; a **documented** value that stops being accepted |
| **MINOR** (`1.1.0`) | New capability, backward compatible | A new subcommand, route or tool; a new opt-in variable; a report gaining a field |
| **PATCH** (`1.0.1`) | Fixes whose only observable change is that a defect is gone | Including security fixes, and including stricter validation of input that was never documented as valid |

**The test is a documented contract that changes — not "a deployment could
stop".** Conflating those inflates a fix release into a major one, and the
first draft of this file did exactly that. Tightening validation of a value
that was always a typo, correcting an exit code that always contradicted the
published doctrine, or enforcing a stated policy one step earlier are FIXES:
they make the code match the contract, and a deployment that "worked" on the
old behaviour was running without the protection it had declared.

**What such a fix owes is warning, not a version bump.** Anything that can
stop a running deployment gets an `UPGRADING.md` entry in the same unit — with
symptom, cause and fix — and `undercroft config check` must be able to detect
it before a restart. That obligation is the point; the number is not.

---

## 1.1.0 — the release this branch is

MINOR: new capability, backward compatible. No documented contract changes.
Everything else on the branch is patch-level and folded in.

### New capability

* **`undercroft config check`** — validates every `UNDERCROFT_*` declaration
  through the resolver that runs at start-up, opening nothing (no vault, no
  database, no socket, no outbound call), and exits non-zero if the
  environment would refuse to start. Reports validated and merely-accepted
  separately, because only some variables have a parse to run.
* **Capability parity closed on four surfaces.** `POST /v1/…/refine` gained
  `dry_run` and `preview`; `POST /v1/…/forget` gained `backend`;
  `DrawerSummary.source_file` reaches the CLI; `Tenant.level` reaches
  `tenant-list`. Each was found by an inventory gate rather than by report.
* **`OPS_DELIBERATELY_ABSENT`** — the operator plane records the seven engine
  capabilities it does not reach, each with its reason, counted against the
  engine's own surface in both directions.

### Stricter validation — fixes, listed in `UPGRADING.md`

These can stop a *misconfigured* deployment, which is why they are in
`UPGRADING.md` and detectable by `config check`. None changes a documented
contract:

* A declaration that turns a protection on now refuses when it does not parse
  (`UNDERCROFT_TRUST_FLOOR`, `UNDERCROFT_ADMISSION`,
  `UNDERCROFT_SEMANTIC_GATE`). The documented values never included the typo;
  accepting it and silently disabling the protection was the defect.
* A cleartext engine URL is refused at REGISTRATION rather than at the first
  outbound request. The transport policy always said "TLS or loopback,
  nothing else, no override"; enforcing it at the door is the fix.
* `instance-remove <unknown>` exits non-zero, matching
  `DELETE /admin/instances/{name}`, which already answered 404.
* Usage errors exit 1 rather than clap's default 2. `docs/AGENTS.md` always
  said exit 2 means an integrity verdict and exit 1 means bad arguments; the
  parser was the outlier.

### Fixes folded in

The twenty defects on the pre-merge blocker list, the eleven regressions the
third audit round found inside those fixes, and T1–T15. All described in
CHANGELOG under `## Unreleased`. The two worth naming:

* **The remote search path decided the quarantine fence off the CLEAR mirror
  column** (A28 inverted) — one offline `UPDATE drawers SET wing = 'notes'`
  and `search_with_index` returned diverted content that `search` drops.
* **The chain-commit counter over-counted 2× on `serve-http`**, and the two
  at-rest migrations — whole-vault mutations that run unattended at the next
  writable open — left no chain record at all.

---

## 2.0.0 — nothing is filed here yet

Reserved for a documented contract that changes. The `palace` terminology
rename (below) is the candidate most likely to land here, since it would move
a CLI subcommand and a room literal.

---

## What `A12`, `C8`, `R4`, `U12` mean — the identifier scheme

Code comments and documents across this tree cite ids of the form
`ROADMAP <letter><number>`: **A** (audit findings), **C** (the completeness
audit), **R** (read-only-posture residuals), **U** (at-rest units), **O**
(open work after 1.0.0). Most of the ids cited across the tree resolve to no
heading here, which reads as rot and is not: **an `A`/`C`/`R`/`U` entry
lives in this file only while the item is OPEN.** (Count them yourself if
you need to — `grep -rhoE 'ROADMAP [ACRUO][0-9]+' . | sort -u`. The first
draft of this paragraph put the number in prose, which is the exact thing
this file tells you not to trust, and it was wrong twice over.) When it closes, the entry leaves — the file is a list of work, not
an archive — and the narrative moves to the CHANGELOG section of the release
that closed it.

So a citation is a **breadcrumb into the history, not a pointer to a
heading**, and the authoritative description of any closed item is the
comment at the citation site itself, which is written to stand alone. If you
are following one and want more, search CHANGELOG.md for the id.

Two consequences, both binding:

- **Cite an id only beside a description that stands without it.** A comment
  whose whole content is "see ROADMAP C14" tells a future reader nothing
  once C14 closes.
- **A newly OPENED item gets a heading here**, so an open item is always
  resolvable. That is what the `O` entries below are.

---

---

## The round-three audit — T1–T15, ALL CLOSED 2026-08-09

The seven-dimension audit run against the round-three fixes found eleven
regressions inside them (all closed in the same unit, described in CHANGELOG)
and fifteen further items. **This section listed those fifteen as open work;
every one is now closed**, because the maintainer's rule is that nothing
merges until it is fixed — not "recorded with a shape".

| | What | How it closed |
|---|---|---|
| T1 | `UNDERCROFT_ADMISSION` and `_SEMANTIC_GATE` warned and ignored | Both refuse and `.trim()`; the file holds ONE doctrine now, and the semantic gate's comment stating the opposite is gone |
| T2 | Four CA pins, three empty-value behaviours | `undercroft_net::declared_pin` — one rule, and an empty declaration refuses everywhere |
| T3 | `undercroft-llm` built its own client | It calls `agent_from_env`; the gate is workspace-wide, with two named-and-checked exemptions |
| T4 | `UNDERCROFT_INDEX_CA` resolved per call | `pin_from_env` caches per process, `Result` and all |
| T5 | `migrate_embedding_space` and `repair` recorded nothing | `audit_migration_standalone`; both bind what they moved and skipped |
| T6 | Tamper decision read a cached manifest | `Vault::anchored_head` — from disk, MAC-verified; `reconcile_chain` and `verify` both use it |
| T7 | Vault trust floor narrowed `search` silently | `Exclusions::measure` reads the EFFECTIVE floor; the e2e that pinned the silence now pins the disclosure |
| T8 | Projections uninventoried; orchestrator root unreachable | Projecting paths are crates-relative; five entries added — and the gate immediately found `DrawerSummary.source_file` and `Tenant.level` genuinely missing |
| T9 | `forget --backend` was CLI-only | `POST /v1/…/forget` takes `backend`, so the ops plane reaches it too |
| T10 | Engine refusals flattened to 502 | `engine_response` keeps the engine's status AND its `class`; a local transport refusal says so |
| T11 | clap usage errors exited 2 | Both binaries exit 1; the e2e check that PINNED the collision now pins the doctrine |
| T12 | Two integrity verdicts outside the doctrine | `supersessions` answers `ok`; `Unsealable` exits 2 on every subcommand |
| T13 | Coverage the fixes did not get | Nine new e2e arms across both suites, incl. the CA refusal, the usage-exit doctrine, and the migration record seen by the operator and refused to the agent |
| T14 | No inventory for the ops parity axis | `OPS_DELIBERATELY_ABSENT`, counted against the engine's capabilities in both directions, every absence carrying a reason |
| T15 | Residues stated | The query-vector egress boundary and the CA-rotation restart, both written where the code is |

**Two of these found live drifts while being closed** — `DrawerSummary.source_file`
never reached the CLI, and `Tenant.level` was dropped from `tenant-list`, which
is the field that exists because a migration has to ask for it. Both are fixed.

---

## Unversioned — decisions and external actions, not code

These are not releasable work: two are clicks in a web UI that no REST
endpoint exposes, and one is a naming decision. Kept out of the version
sections deliberately, so a release plan is not padded with things a
release cannot contain.

### OPEN after 1.0.0 — recorded as work, with a gate each

Nothing here is broken. Each is a decision or a gap with a known shape, and
"accepted" is not a resting state — so each has what would close it.

**Status 2026-08-09: O2, O3 and O4 are CLOSED, each with an executed gate
(below). O5 is RE-OPENED — its blocker turned out not to apply. What remains
open is O1's second half and O6 — both are clicks in the GitHub web UI that
no REST endpoint exposes, so no amount of engineering closes them from here.**

**D1–D8 — the pre-merge drift audit, CLOSED 2026-08-09.** The
seven-dimension audit this file's own conventions require before a release
was run before merging the above, and did not come back clean. Eight drifts,
every one re-verified against the code before it counted, none caused by the
O-work and all reachable on `main`: an unaudited whole-corpus `index push`
egress; a fleet integrity check exiting 0 on a tampered vault; a trust floor
governing one content read of three; an orchestrator→engine hop with no
transport policy; `refine`'s mirror on the bare `upsert`; `PalaceStats` and
`DedupReport` hand-projected with no inventory entry; `serve-mcp` with no
read-only posture; a non-constant-time bearer comparison. Each is described
with its evidence and its gate in CHANGELOG under "the drift audit that gated
the merge".

**D9-D14 - the RE-AUDIT of the fixed tree, 2026-08-09.** The seven
dimensions were re-run against the D1-D8 fixes, each auditor also asked to
check adversarially whether the fix closed its drift and whether it
introduced one. **It found four defects in the fix round itself**, which is
the finding that matters more than any single item:

- `vault_err` was never given the integrity class, so the fix's own headline
  case - a manifest edited offline, the fixture every `/v1` tamper test uses
  - still answered 409 unclassed and the fleet's `ops verify` still exited 1.
  `integrity_verdict` matches a BARE `VaultError` as well as a wrapped one;
  only the wrapped arm was mirrored. FIXED.
- `audit_index_push` derived its plaintext field from the caller's PERMISSION
  flag rather than the vault's level, so a sealed vault pushed with
  `--allow-plaintext` chain-recorded "plaintext". The CLI's own stdout on the
  same push reads the level. FIXED; the declaration is bound separately.
- The trust-floor widening empties `recent` whenever the floor is above
  `standard` and no wing is yet assigned that class - an ordinary state - and
  `wake_up` then said "Palace is empty" over an intact corpus. An exclusion
  nobody can see is the silence LABELS.md forbids. FIXED with a
  `trust_floor()` accessor and honest messages on CLI and MCP.
- The landing page's test count was set to 660 by the same commit that added
  four tests. FIXED to 664 compiled / 660 run.

Also found and FIXED: `dedup`'s survivor rewrite was on the bare `upsert`
(reported in the FIRST audit and omitted from the eight by mistake) - a
diverted survivor kept its old occurrences while the duplicates were deleted
anyway and the report claimed `dates_kept` for dates never written; it now
screens, skips the deletes for that group, and reports `quarantined`.
`HAND_PROJECTED` gained the `PalaceStats` x `/v1` entry the doctrine
requires.

**Recorded, NOT fixed at the time — ALL CLOSED 2026-08-09 (round three).**
This paragraph listed twenty items: the remote quarantine fence deciding off
the CLEAR mirror column; `UNDERCROFT_ORCH_ENGINE_CA` resolved per call and a
policy refusal rendering as "engine is down"; a cleartext instance URL
accepted at registration; `undercroft_chain_commits_total` over-counting on
two handles; the two at-rest migrations recording nothing; `forget` attesting
a destruction the mirror never hears about; a partial `index push` recording
zero; `RefineReport` outside the hand-projection gate's reach and that gate's
4000-char window passing on a neighbour's text; MCP's verify verdict as prose
inside `isError: false`; `migrate` with no exit-code doctrine; `WRITE_TOOLS`
failing OPEN; and the doc claims. Each is closed with a test that was run
against the reverted code and observed to fail — see CHANGELOG, "the
merge-blocker list is empty". What the round-three audit found in those fixes,
and what it found fresh, is above under **OPEN after the round-three audit**.

### O1 — PARTLY CLOSED 2026-08-09: binaries shipped, the image is still private
The `v1.0.0` release workflow completed successfully and **20 assets** are
published, correctly named `undercroft-v1.0.0-<target>[-ort].tar.gz` plus
`.sha256` — five targets, both variants. The release button on the landing
page is now honest.

**What remains:** `ghcr.io/sealcroft/undercroft` answers **HTTP 403 to an
anonymous pull token**. GHCR packages default to *private* visibility on
first push, so `docker pull ghcr.io/sealcroft/undercroft:1.0.0` — the first
command in the landing page's install walkthrough — fails for everyone who is
not the owner. **Shape:** flip the package to public (Packages → undercroft →
Package settings → Change visibility). **Gate:** an anonymous
`ghcr.io/token` + `tags/list` must return 200, not 403 — one curl:

```bash
T=$(curl -s "https://ghcr.io/token?scope=repository:sealcroft/undercroft:pull&service=ghcr.io" | sed -E 's/.*"token":"([^"]+)".*/\1/'); curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $T" https://ghcr.io/v2/sealcroft/undercroft/tags/list
```

**Re-verified 2026-08-09: still 403.** And it cannot be closed from a shell:
GitHub's Packages REST API exposes get / delete / restore and **no
visibility endpoint at all**, so the web UI is the only route. (The local
`gh` token additionally carries only `gist, read:org, repo, workflow` — no
`read:packages` — so it cannot even read the package's current visibility.)

### O2 — the site loads three font families from Google
`website/landing/index.html` head and `website/assets/undercroft.css:6`
(`@import`) fetch `GFS Didot`, `IBM Plex Mono` and `IBM Plex Sans` from
`fonts.googleapis.com`, on the landing page **and every docs page**. This does
not touch the binary and the "0 bytes phoned home" figure is a claim about the
product, which remains true. Two separate reasons to close it anyway: serving
Google Fonts to EU visitors has adverse case law (LG Munchen, 2022 — the
visitor's IP is transmitted), and `GFS Didot` is a Greek Font Society face
chosen to set Greek that no longer exists on the page.

**CLOSED 2026-08-09.** All three families are vendored under
`website/landing/assets/fonts/` — **20 `.woff2` faces, 482 KB including the
three SIL OFL 1.1 licence texts**, attributed in `NOTICE`.
`website/tools/vendor-fonts.sh` regenerates them and is run **by hand, never
by the build**: a build step that fetched fonts would defeat the point
exactly. It rewrites only the `src:` URLs and passes every `unicode-range`
through unchanged, so coverage for a vendored subset is identical to what the
site served before — hand-authoring those blocks is how a vendoring pass
silently drops a script.

**Only the subsets rendered text actually uses are vendored**, and that is
measured rather than assumed. The API offers seven; `latin`, `greek` and
`cyrillic` appear in rendered pages and `latin-ext`, `greek-ext`,
`cyrillic-ext` and `vietnamese` do not — 23 faces and 357 KB not shipped.
The distinction is not visible to a naive scan: characters from all seven
appear in the built site, because `mermaid.min.js` carries Unicode parser
tables and `mark.min.js` a diacritic map. Those are data inside a script,
never glyphs a browser paints, which is why the check scans **rendered
`.html` only**.

**Gates:** `website/build-site.sh` greps the assembled site for both font
hosts and fails on any hit; it scans every rendered page for characters in
the dropped ranges (recorded with their ranges in `dropped-subsets.txt`) and
fails naming the file, so a future page with Polish or Vietnamese on it is a
failing build rather than a silent fallback. Verified additionally in a
browser: all 8 distinct faces report `status: "loaded"`, `h1` computes to
`GFS Didot`, and the page lists **zero** external resource references.

**That second gate was born broken and its own premise probe is what caught
it.** The first version built a regex character class in the shell, `sed` ate
the backslashes, `perl` died on `[x{0102}-…]`, and `2>/dev/null` swallowed
the error — so it reported "no dropped subset is used" having examined
nothing, and passed a counterfactual with real Vietnamese and Polish text on
the page. It is numeric now, suppresses no stderr, treats a tool failure as a
FAIL, and **probes itself against a range that must match before its
zero-results are believed** — which then also caught that the site image
carries `perl-base`, with neither `File::Find` nor `PerlIO`. Three silent
failures, one probe.

### O3 — five pre-existing defects the rename audit surfaced — CLOSED 2026-08-09
Found by the 8-agent audit, none caused by the rename. All five closed:
- **The fleet-wide alert inhibition.**
  `deploy/observability/alertmanager/alertmanager.yml` inhibited on
  `equal: ["vault"]` and **no alert expression emitted a `vault` label** — all
  six were `sum()`/`up{}`/`sum by (le)` over counters. Absent-on-both reads as
  equal, so one critical `PalaceTamperDetected` silenced every warning
  fleet-wide. Now every rule aggregates `by (instance)` (which is also the
  more useful alert — it names the process) and the inhibition equals on
  `instance`. **Gate:** the new `obs-config` suite —
  `deploy/observability/alerts_test.yml` asserts the exact label set and
  annotations of every rule under `promtool test rules` (real PromQL
  evaluation plus a negative-control block where a healthy instance fires
  nothing), `amtool check-config` validates the route, and
  `tests/obs-config.sh` joins the two by requiring every `equal:` label to
  appear in every tested alert and every rule to have a test block.
  **Counterfactual executed**: with `equal: ["vault"]` restored on a scratch
  copy the suite exits 1 naming all six alerts; with the fix, 0.
- **The Windows palace location.** `data_dir` read `HOME` only and fell back
  to `"."`, so the released Windows binary created its palace in the current
  working directory — a different palace per shell, none found again, no
  error. `home_dir()` now takes `HOME` then `USERPROFILE`, treating an empty
  value as absent, and `expand_home` (`~/`) shares it. **Gate:**
  `the_home_directory_falls_back_to_userprofile`, driven through a pure
  lookup function rather than `set_var` (which would race every other test in
  the binary); four arms, and the second fails before the fix.
- **The browser importer's bundle guard.** `ui.html` tested for
  `UNDERCROFT-BUNDLE-1` exactly, so a v2 hybrid PQ bundle walked past it and
  was POSTed as NDJSON — a parse error where the product had a sentence ready.
  It now guards the shared prefix. **Gate:**
  `the_browser_importer_refuses_every_bundle_version` reads the magics out of
  `undercroft-vault`'s own source and requires the guard to equal their
  longest common prefix, so it fails both for a version-pinned guard and for
  one loosened past the shared stem, and a `BUNDLE_MAGIC_V3` is in scope the
  moment it is declared.
- **`SECURITY.md` "Out of scope".** It listed three closed gaps (R1, R4, and a
  `POST …/verify` anchor effect that does not occur per A31) — a security
  policy telling researchers not to look at surfaces that are now boundaries.
  Each was re-verified in code before editing (`may_build_indexes()` guards
  every prefilter tier; `verify` is `&self` and no `anchor_manifest` call site
  is inside it), the in-scope side now states the read-only posture
  positively, and what remains out of scope is the genuine residual: the
  anchor lag on audited reads, named together with the explicit closer
  (`undercroft vault anchor` / `POST …/anchor`), plus the WAL scaffolding a
  read-only open materialises.
- **`website/book.toml` had no `site-url`**, so the generated 404 resolved its
  assets as if the book were at the domain root — the one page a lost visitor
  sees was the one page with no stylesheet. Set to `/undercroft/docs/`.
  **Gate:** `build-site.sh` requires `404.html` to reference it, which is only
  checkable on the assembled tree.

### O4 — two gates that do not exist — CLOSED 2026-08-09
- `GAUGE_NAMES` was cross-checked for the five **codebook** gauges only. The
  other five — `drawers`, `audit_chain_height`, `kg_triples`, `kg_entities`,
  `store_bytes` — were set by bare literal in `tenant.rs` with nothing pinning
  them, and an unlisted name is **silently dropped** with no error at any
  level. Now `every_gauge_name_is_registered_and_every_registered_name_is_emitted`
  covers all ten in both directions: the codebook names computed as production
  computes them, the rest scanned out of the workspace's sources (comment
  lines dropped, calls found across rustfmt line breaks, non-literal
  forwarding calls skipped), with a premise assertion so a broken extractor
  fails instead of passing vacuously. Its first version matched **its own
  source** and reported a fragment of its own loop as an unregistered gauge —
  fixed with the `concat!` needle-splitting idiom already used one file over.
- Nothing compared the **emitted metric set** against `alerts.yml` and the
  Grafana dashboard; an alert naming a series the binary does not export never
  fires and never errors. `undercroft-obs` now publishes the whole inventory
  (`COUNTER_NAMES`, `HISTOGRAM_NAMES`, `GAUGE_NAMES`, `series_names()`), pinned
  to its emit sites by `the_series_inventory_matches_the_emit_sites` in both
  directions — which is what makes the second gate,
  `every_series_the_deployment_configs_name_is_one_the_binary_exports`, mean
  anything. That one reads `deploy/observability/` (hence `COPY deploy` in the
  Dockerfile and the `.dockerignore` allowance) and is deliberately
  one-directional: every series a config names must exist, never the reverse.
  Histogram `_bucket`/`_sum`/`_count` suffixes are resolved to their stem;
  `undercroft_*` in prose is skipped as a wildcard.
- **CI never built `--features telemetry`**, so `undercroft-obs/src/imp.rs`
  was not compiled in CI at all. The `test` job now runs `obs-config`,
  `orchestrator-e2e` and `e2e-telemetry`, and a new `site` job builds and
  checks the site on pull requests — `pages.yml` only fires on `main`, so
  until now nothing built the book before it was already published.

### O5 — terminology decision, RE-OPENED 2026-08-09: its premise was wrong
The recorded argument for keeping `palace` rested on two data hazards: a bare
`palace.db` rename presents as a false integrity verdict (`DatabaseMissing`,
409 / exit 2) on every existing vault, and `"diary"` is a room-name literal
inside `meta_json` — therefore inside the HMAC canonical and the drawer-id
recipe — so migrating it re-derives every id, the A10 failure by name.

**Both hazards are about EXISTING DATA, and there is none.** The maintainer
confirmed the vaults in question were test vaults, disposable. So the
decision was taken against a constraint that does not apply, and the analysis
is redone here from measurement rather than from that argument.

**Measured 2026-08-09** — 948 occurrences: crates 507, website 310, docs 86,
deploy 26, architecture 19. Of the 507 in crates, 251 are the type names
`PalaceStore`/`PalaceStats`, 188 sit in comments, 67 in string literals
(help text and errors) and 34 are the filename.

**What it does NOT touch, each checked rather than assumed:**
- the crypto domain separation — no HKDF info string, AEAD AAD prefix or
  keycheck marker contains it (those carry the *project* name and moved at
  the rename);
- any audit-chain record namespace (`kg/{id}`, `trust/{wing}`, … — none);
- the wire: no serde field name, no JSON key, no public struct field. Only
  type names, and serde emits fields, not the struct;
- MCP: no tool is named for it. The single hit in `parity.rs` is prose.

**Two load-bearing points, and that is all:**
1. **`palace.db`** — one production construction site,
   `Vault::db_path` in `undercroft-vault/src/lib.rs`, plus 34 test references
   and 14 in `tests/e2e.sh`, `docs/AGENTS.md`, `docs/MULTI_TENANCY.md`,
   `docs/remote-server.md`, `docs/security.md`, `website/src/runbook.md` and
   `architecture/index.html`.
2. **`diary`** — both a CLI subcommand (`Command::Diary`) and a room-name
   literal written into `meta_json` (`manage.rs`) and filtered on read. The
   id hazard is real but empty without data; the *surface* rename is not, and
   is a separate decision from the noun.

**A coherence finding the first analysis missed, and it argues the other
way:** `palace.db` is **per-vault** — `Vault::db_path()` joins it onto one
vault's directory — while "palace" elsewhere names the whole installation
(the master key is the palace master key; the data directory is the palace).
The term is already doing duty at two levels of the hierarchy, which is a
defect in its own right and independent of the rename.

**The constraint that actually remains is vocabulary, not data.** The
obvious replacement is `vault`, and `vault` is already the name of a
different concept — the isolation and crypto unit — so reusing it would be
worse than the status quo. **Blocked on a target word, which is the
maintainer's call**, not on risk. `PalaceStore`/`PalaceStats` remain free
moves whatever is chosen.

### O6 — brand assets need two manual uploads
GitHub exposes **no REST endpoint** for org avatars (`avatar_url` is read-only
on the orgs API) or repo social previews. `assets/brand/` holds the marks;
`sealcroft.github.io/assets/` holds the house mark. Org avatar wants the
512x512 square, the repo social preview wants the **1280x640** card — they are
not interchangeable.

**Assets re-verified 2026-08-09** by reading each PNG's IHDR rather than
trusting its filename: `undercroft-mark-512.png` is 512×512 and
`undercroft-social-1280x640.png` is 1280×640. Both are ready to upload; the
upload itself remains a click.

- Org avatar → <https://github.com/organizations/sealcroft/settings/profile>
  → Upload a picture → `assets/brand/undercroft-mark-512.png` (or the house
  mark from `sealcroft.github.io/assets/`, which is the better choice for the
  ORG — the house is not the product).
- Repo social preview → <https://github.com/sealcroft/undercroft/settings> →
  Social preview → Edit → `assets/brand/undercroft-social-1280x640.png`.


---

## Beyond 2.0.0 — the competitive track

Phased rather than versioned: each phase is several releases and the
version each lands in is decided when it is scoped, not now.

### Competitive track (ordered 2026-07-22 — compete hard and exceed)

The market (mem0, Zep/Graphiti, Letta, Cognee, Supermemory, plus the
MCP-server long tail) competes on **convenience**: extraction-based
"smart memory," bolt-on SDKs, hosted APIs, graph reasoning. None of
them has a security story — no sealed indexes, no tamper evidence, no
offline default, no cryptographic tenant isolation. The strategy in
one line: **close the convenience gap, make the trust gap
unfollowable.** Everything below preserves the invariants (verbatim,
local-first, sealed at rest, audit-chained); several items weaponize
them. Phases are the intended build order; each item ships as its own
release with the usual battery + measured gates.

### Phase C1 — prove it (weeks, mostly bench + writing)

- **C1.1 Head-to-head benchmark publication.** Run mem0 (local/
  OpenMemory), Zep/Graphiti self-hosted, Letta, and Supermemory's
  local binary against undercroft on the harnesses `undercroft-bench`
  already carries (LongMemEval, LoCoMo, ConvoMem, MemBench) —
  identical corpora, within-run comparisons, raw logs published, every
  competitor's best local configuration documented. Include the column
  only we can fill: quality **while fully sealed, zero external
  calls**. Publish as docs/BENCHMARKS_VS.md + a landing section.
  *Gate*: numbers reported as measured, favorable or not — the
  methodology page IS the product.
- **C1.2 Security comparison page (SHIPPED — docs/SECURITY_COMPARISON.md).** One table, us vs the five named
  competitors: content encryption / derived-index encryption / tamper
  evidence / verified reads / key rotation / cross-tenant crypto
  isolation / offline default / audit chain / export encryption.
  Sourced claims, dated, PR-able by competitors if they object.
  Docs page + landing block.
- **C1.3 Threat-model whitepaper (SHIPPED — docs/THREAT_MODEL.md).**
  Formalized what SECURITY.md + seal.rs already implement: eight
  adversary classes (offline reader/tamperer, cross-tenant, network,
  untrusted accelerator, exfil channels, memory poisoner, host —
  the last a stated non-goal), a layer→adversary map, verbatim-as-
  security-property, the operator custody boundary, and planned-work
  labeling for C3. Framed against the 2026 memory-attack literature
  (MINJA, AgentPoison, forged-reasoning/FragFuse). Published in the
  book as threat-model.html; linked from SECURITY.md.

### Phase C2 — meet them (parity; each ~1 release)

- **C2.1 Python + TypeScript SDKs.** Thin typed clients over the
  existing `/v1` surface (vault lifecycle, drawers, search, KG
  browse, verify, export/import; assertion minting included). Publish
  to PyPI/npm with the same version cadence as the binary. This is
  the single biggest adoption gap — every competitor evaluation
  starts with `pip install`.
- **C2.2 Framework adapters.** LangChain + LlamaIndex memory/retriever
  classes and a CrewAI/AutoGen adapter, each a thin wrapper over the
  SDKs, each with an example repo. Gets us onto the shelf where
  bake-offs happen.
- **C2.3 Working-memory blocks (Letta parity).** A reserved wing +
  MCP tool sugar (`memory_pin`, `memory_edit`, `memory_unpin`) giving
  agents editable, always-in-context core memory on top of verbatim
  drawers — pinned blocks are still drawers: sealed, chained,
  verifiable.
- **C2.4 Local document ingestion.** `mine` learns PDF/DOCX/HTML →
  text extraction, fully local (no OCR cloud), chunked through the
  existing deterministic pipeline. Closes the Cognee/Supermemory
  "feed it your documents" gap without touching the no-phone-home
  stance.
- **C2.5 KG deepening.** `/v1` KG **write** routes (create/supersede/
  close facts — console gains editing), multi-hop graph queries, and
  richer local-LLM extraction prompts for `refine`. Removes
  Zep/Graphiti's cleanest talking point; our temporal model (valid-now,
  timelines, auto-supersede) is already competitive underneath.

### Phase C3 — exceed them (category-defining; nobody can follow)

- **C3.1 Facts-with-receipts distillation.** Opt-in automatic pass
  (local LLM, riding the existing `refine`→KG seam): distilled facts,
  contradiction handling via the existing temporal supersede, and —
  the part extraction-based competitors structurally cannot offer —
  every fact carries an HMAC-verified citation to its verbatim source
  drawer. Their pitch (smart memory) becomes our subset; our pitch
  (provable memory) stays exclusive. *Gate*: LoCoMo/LongMemEval with
  the distillation tier on must beat our retrieval-only baseline.
- **C3.2 Provable forgetting — phases 1 AND 2 BUILT (2026-08-03).**
  Phase 1: `undercroft forget` destroys named drawers through the chain
  and emits a `ForgetAttestation` (ids + unkeyed content fps, heads
  before/after, the exact tombstone interval; optional Ed25519
  signature); `verify-forgetting` replays with the key in hand and
  refuses every forgery shape (pinned five ways). Honest boundary:
  third parties verify the operator's SIGNATURE, not the replay — the
  chain step is keyed, and an unkeyed public chain is its own design
  decision, not a rider. **Phase 2 (same day): retention policies per
  wing/room** — declared on the wing-trust pattern (operator-only,
  HMAC-tagged, chain-audited, flip fails list AND sweep), enforced only
  by an explicit sweep that destroys through `forget_with_proof` (a
  receipt per sweep; nothing automatic at open or on a timer; the
  quarantine wing refused; the clock is the HMAC-covered
  `meta.filed_at`, tag-verified per drawer before any destruction) —
  **and the receipted deny**: `admission deny` rides the same path and
  hands back the attestation. GDPR/RTBF with a receipt, now including
  retention-driven and review-driven destruction. Extraction-based
  systems cannot know what their LLM absorbed where — this feature is
  unreachable for them.
- **C3.3 Memory-poisoning defense — write-path admission control.**
  **Phase 1 BUILT (2026-08-03): deployment-assigned wing trust classes**
  — `quarantined|standard|trusted` assigned by the operator (CLI +
  `/v1`, deliberately never MCP), HMAC-tagged and chain-audited (a
  flipped row fails verification and a floored search refuses),
  consumed as a candidate-set floor (`SearchOptions.min_trust`,
  `UNDERCROFT_TRUST_FLOOR`) riding the scope-resolved machinery —
  pinned starvation-free by a raw-premise test: a quarantined wing
  owning the corpus top-k cannot crowd out a standard wing's answer.
  This is the enforcement substrate the quarantine wing below plugs
  into. **The per-source cap SHIPPED (2026-08-03) behind its gate**:
  `keyed_sample_capped` bounds any wing at `1/UNDERCROFT_TRAIN_SOURCE_CAP`
  (default 4) of every global training draw (PQ codebook/IVF, FDE
  codebook/IVF), within-quota corpora byte-identical, soft refill never
  shrinks the sample, below-sampling-threshold deliberately inert
  (per-wing codebooks are that regime's isolation). Gates met before
  default-on: synth 16384 periodic shape 100.0/100.0, wingscale 16-wing
  scoped+unscoped 100.0% both floors. **The per-AGENT accident cap is
  BUILT (2026-08-03)** on the provenance the admission phase recorded:
  the same draw also caps any `meta.agent` claim's share at the same
  quota — a runaway agent flooding across several within-quota wings no
  longer buys the combined share. Claim-less rows are exempt (absence
  of provenance is not a group); a claim is the writer's own statement,
  so this bounds ACCIDENTS, never adversaries — the wing grouping stays
  the adversarial bound.
  **Phase 2 BUILT (2026-08-03): the deterministic tier-1 detector +
  quarantine wing + audited rulings** — `undercroft_core::admission`
  (closed signal vocabulary, offsets not content, negative fixtures
  pinned), `UNDERCROFT_ADMISSION=quarantine` (default off; flagged
  saves divert sealed to the reserved wing on both save paths, the
  wing refuses forged residents, retrieval hard-excludes it except for
  the reviewer's own scope), CLI/`/v1` allow/deny with the verdict
  inside the ruling tag's canonical — never an MCP tool. Every phase-2
  recorded gap is now CLOSED (all 2026-08-03/04): deny-with-receipt
  (deny rides C3.2's `forget_with_proof` and hands back the
  attestation); update-path screening (`update_drawer` re-stamps
  `added_by` with the UPDATING surface before the screen, so an
  untrusted surface cannot ride the original writer's standing; a
  flagged update diverts with the drawer keeping its previous content
  and the outcome typed, never a bool; quarantine-pending drawers are
  not editable — the reviewer rules on exactly what the screen saw);
  and the **advisory LLM tier** (`UNDERCROFT_ADMISSION_LLM=advisory` on
  the `UNDERCROFT_LLM_*` runtime — `AdmissionAdvisor` trait, consulted
  only for tier-1-clean candidates, only toward quarantine
  (`llm-advisory` signal, offset 0, no content, no model reasoning),
  failure degrades to tier-1-only, declared-but-unusable refuses to
  open, TLS-or-loopback — since 2026-08-04 enforced by `LlmClient`
  itself for every consumer, with `UNDERCROFT_LLM_CA` pinning
  self-signed roots). **The tier-1 wishlist is CLOSED (2026-08-04):
  attack-fixture similarity** (committed fixture corpus in
  `undercroft_core::admission::ATTACK_FIXTURES`, windowed hash-embedder
  cosine so a 20-word variant inside 1,000 words of notes is still
  found; threshold 0.45 pinned from BOTH sides — hard negatives ≤
  0.369, marker-dodging variants ≥ 0.540 — and validated at corpus
  scale by the new `screenfp` bench instrument: **0/5,882 clean LoCoMo
  turns flagged, corpus max score 0.374, 18/18 fixtures trip**, which
  meets the stated gate) **and rate anomalies**
  (`UNDERCROFT_ADMISSION_RATE=<count>/<seconds>`, declared never
  defaulted since a write rate is deployment-shaped; identity = the
  `agent` claim else the surface-stamped `added_by` among claim-less
  rows, the training-cap grouping — accident bound per claim, surface
  floor under claim rotation; unreadable declarations refuse to open;
  checked in the store because a rate lives in the write history, not
  the candidate bytes). C3.3's shipping
  mechanism list is BUILT end to end, wishlist included. The provenance foundation + posture are BUILT (2026-08-03):
  `agent`/`channel`/`session` claims on every save surface
  (HMAC-covered, never trusted) and `UNDERCROFT_ADMIT_TRUSTED_SOURCES`
  keyed on the surface-stamped `added_by` only — a channel CLAIM never
  bypasses the screen (pinned).
  Remaining pieces below. First-mover answer to the documented
  memory-poisoning attack class
  (MINJA, AgentPoison, forged-reasoning): screen memory **at ingest**,
  not just at retrieval, so poison never becomes retrievable while a
  human gate is pending. Full design in
  [THREAT_MODEL.md §8](THREAT_MODEL.md) (the three-zone boundary);
  the shipping mechanism:
  - **Provenance on every drawer** — writing agent / source / channel
    / session, tamper-covered by the record HMAC. This is the
    foundation the rest builds on and the cheapest first increment.
  - **Admission check on the write path** — outcomes admit /
    quarantine / reject. **Detector, two tiers**: (1) *deterministic,
    default-on, no model* — imperative-instruction patterns, embedded
    tool-call/code syntax, exfil & encoded-blob markers, provenance
    and rate anomalies, similarity to committed attack fixtures; pure
    functions over the candidate bytes + its deterministic embedding,
    so it is unit-testable as data with zero host impact. (2)
    *optional local LLM classifier, advisory-only* — can push a write
    toward quarantine, never auto-admit; hardened data-marked prompt;
    stated honestly as itself an injection target, never a gate that
    can be turned against us.
  - **Quarantine wing** — flagged writes land sealed and `pending` in
    a reserved wing, **excluded from all retrieval** (the agent never
    sees a quarantined drawer). Provenance-driven default posture:
    high-trust channels auto-admit; untrusted channels (tool output,
    scraped content, other agents) default to quarantine — keeping the
    human-review queue small and high-signal, surfaced in the admin
    console.
  - **Full lifecycle audit** — every transition is a chain-logged,
    tamper-evident event with its reason *retained across
    transitions*: `[quarantined: signal + provenance + ts + sealed
    fingerprint]` → `[allowed by Z: overrode signals N]` **or**
    `[denied by Z: reason; content deleted + keyed tombstone]`. The
    quarantine log doubles as a labeled dataset for improving the
    detector, and a pattern of quarantine events from one channel
    exposes a campaign even when each write was individually denied.
  - **Crash-safe allow/deny state machine** — the two-phase,
    open-time-reconciled pattern proven by key rotation
    (`rotate.rs`): a crash mid-decision reconciles to exactly
    pending / promoted / denied, never half. Deny rides C3.2's
    attested-forgetting path; promotion can require a C3.1 receipt.
  - **Honest boundaries (must ship in the docs)**: detection is
    heuristic — a poison from a channel you trust can still pass;
    every log stores a sealed fingerprint, never a cleartext payload
    (or the log becomes a re-injection vector); and this secures the
    memory and memory→agent zones only — the agent→host zone (an
    over-privileged agent inducing a malicious tool call) is the agent
    runtime's and OS's sandbox to enforce, the A8 non-goal. undercroft
    itself is an inert store that never executes retrieved content, so
    it is never the code-execution vector.
  - *Steps*: (1) provenance fields + HMAC coverage; (2) deterministic
    detector + attack fixtures; (3) quarantine wing + retrieval
    exclusion; (4) lifecycle audit events on the chain; (5) crash-safe
    allow/deny + admin-console review flow; (6) provenance posture
    policy; (7) optional LLM-classifier tier behind a flag. *Gate*:
    attack-fixture corpus quarantined at a target rate with a bounded
    false-positive rate on clean LoCoMo ingest; crash-window tests for
    the state machine; e2e scripted-attacker run over `/v1`.
    **GATE MET (2026-08-04), THEN FOUND INSUFFICIENT AND RE-MET
    (2026-08-05)** — the correction matters more than the claim. The
    original three clauses passed as written; a surface-parity audit the
    next day then found the screen was **bypassable on `/v1` three ways**
    (a `dedup_threshold` in the save body, a caller-supplied `vector` on
    import — which made every backup-restore and orchestrator tenant
    migration re-admit corpora unscreened — and external-embedding vaults
    having no screened path at all), and that quarantined content reached
    the agent through `wake_up` and the closet index because exclusion
    lived in `search` alone. **The scripted-attacker clause passed because
    it knocked on the one door that was locked**: it exercised the plain
    `POST …/drawers` body and nothing else. All of it is closed by
    construction now — screening lives at the write choke point behind a
    required argument, so a write path that forgets it does not compile —
    and `every_write_path_is_screened` walks all five public entry points.
    The lesson recorded for the next gate: a clause that tests one route
    of a capability tests the capability's *documentation*, not the
    capability. Original clauses, for the record: the detector clause measured
    0/5,882 clean-corpus false positives with 18/18 fixtures tripping
    (`screenfp`); the crash-window clause pins all four partial states
    of the allow/deny machine converging with the chain green; the
    scripted-attacker clause runs over `/v1` end to end — and found two
    honesty defects on the way, both fixed in the same unit (save
    surfaces reported `created: true` with the aimed-at id while the
    content sat in quarantine; the reserved-wing refusal answered 500
    "corrupt row" for what is a 400-class input error).
  - *Effort*: ~2 releases (provenance + deterministic gate first;
    classifier tier and posture policy second).
- **C3.4 Post-quantum posture — BUILT (2026-08-04), all three items.**
  The stack is symmetric-first, so most
  of it was **already PQ-safe by construction**: XChaCha20-Poly1305
  sealing (256-bit keys — Grover-limited to ~128-bit effective, the
  accepted PQ bar), HMAC-SHA256 tags/chain/tokens/assertions,
  HKDF/Argon2id derivation. The **single quantum-vulnerable spot in
  the codebase** was `bundle.rs`'s X25519 exchange — exported bundles
  were exposed to harvest-now-decrypt-later. Shipped: (1) the hybrid
  KEM (X25519 + ML-KEM-768, FIPS 203 via RustCrypto `ml-kem`) v2
  bundle format — `keygen` is hybrid by default (`pq1` strings), the
  file key derives from BOTH shared secrets, magic+ephemeral+KEM-ct
  are all AAD; legacy identities still parse, still receive openable
  v1 bundles, hybrid identities open old v1 backups with their curve
  half, and NOTHING downgrades silently (a hybrid recipient always
  gets v2; an X25519-only secret gets a typed refusal on v2);
  (2) docs/PQ.md, the posture page — the inventory above, the compat
  matrix, hybrid-KEM TLS guidance (X25519MLKEM768 at the reverse
  proxy), and the signature story stated honestly (Ed25519 is a
  future-forgery risk, not a harvest risk; ML-DSA hybrid recorded as
  future work); (3) the honest boundary in writing on the same page —
  quantum-resistant **cryptography**; "quantum processing"
  for retrieval is vapor and we do not claim it.
  *Gate met*: round-trip + downgrade-refusal tests pinned in every
  direction (v1↔v2 × legacy/hybrid identities); `ml-kem` 0.2.3 through
  the RustSec audit in CI.

Sequencing note: C1 needs no code beyond bench runners and can start
immediately; C2 items are independent of each other; C3.1 depends on
nothing but benefits from C1.1's baselines; scale items 4–6 above
(FDE pages, reembed, backup/DR) interleave on their own triggers.

---

## Shipped — the operability track

Kept as a record of what each version carried.

### Operability track

Observability and a management/visualization surface for the stack. The
whole track obeys the project's core stance — **local-first, opt-in,
zero external by default, no plaintext or key material ever exposed**:

- **Default-off, loopback-only.** No metrics port, telemetry export, or
  UI is served unless explicitly enabled; when enabled it binds loopback
  and sits behind the existing palace bearer / `X-Vault-Assertion` auth.
- **Feature-gated**, mirroring the `--features onnx` pattern — a build
  without the feature carries zero extra dependencies and zero overhead.
- **Metadata and counts only.** Everything below exposes structure,
  aggregate counts, rates, and latencies — never drawer content, drawer
  names beyond what `stats` already surfaces, or anything key-derived.
  Sealed vaults expose only aggregate distribution, preserving the
  no-plaintext-derived-index invariant (in-memory samples are counts,
  not content, and are never persisted for sealed vaults).

### v0.9.0 — Observability & telemetry (done)

Instrumentation foundation the higher layers read from. Shipped in the
new `undercroft-obs` shim crate; fully synchronous (no async runtime).

- **Structured logging** via `tracing` + `tracing-subscriber`, replacing
  the ad-hoc `eprintln`s. Level via `UNDERCROFT_LOG`; human format by
  default, JSON via `UNDERCROFT_LOG_FORMAT=json`. No content or key
  material is logged (`SecretKey` stays non-`Debug`).
- **Prometheus** `/metrics` endpoint (text exposition format) on the HTTP
  server, gated by `UNDERCROFT_METRICS=1`, loopback + bearer-gated.
  Counters/histograms for search, drawer writes/deletes, dedup, KG ops,
  audit-chain commits, HMAC verify failures, HTTP requests, auth
  rejections, vault opens; per-vault gauges (drawers, chain height).
  Metadata only.
- **OpenTelemetry** OTLP **trace** export behind `UNDERCROFT_OTLP_ENDPOINT`
  (unset ⇒ no network egress). Metrics are surfaced via the Prometheus
  pull model — OTLP metric push needs a periodic-reader runtime this sync
  stack deliberately avoids; deferrable follow-up.
- **Hot-path instrumentation** at search, save/dedup, KG writes, vault
  seal/commit, and every HMAC-verify failure site.
- All behind `--features telemetry` — default builds carry zero extra
  deps and zero overhead.

### v0.10.0 — Live memory telemetry (done)

Turns point-in-time `PalaceStats`/`KgStats` into a streaming time series.
Shipped: per-connection SSE thread reading a thread-safe broker (the
sync server + `!Send` stores made this the only sound model), sampler
that only ticks watched vaults, and sealed-vault wing/room suppression.

- **In-process sampler**: periodic snapshot of `PalaceStats` + `KgStats`
  + cache/index gauges into a bounded in-memory ring buffer (window and
  resolution configurable). No disk writes for sealed-vault derived data.
- **SSE stream**: `GET /v1/vaults/{id}/stream` (and a palace-wide roll-up)
  pushing sampled deltas over chunked HTTP (supported by the current
  `tiny_http` server). Auth-gated, opt-in.
- **Discrete event pings** on the same stream, so a UI can animate
  individual actions rather than only sampled totals: `drawer-saved`
  (wing/room), `drawer-deleted`, `search` (wing/room hits), `kg-triple`,
  `chain-commit`. Payload is type + location + counts — metadata only,
  never drawer text or names beyond what `stats` already exposes.
- **History backfill**: `GET /v1/vaults/{id}/stats/history?window=…`
  returns the ring buffer so a fresh client can draw the recent past on
  connect.
- Exposed signals: wing/room populations, drawer add/delete rate, search
  QPS + latency, KG triple counts, cache hit rate, FTS prefilter ratio,
  audit-chain height — all counts and rates, never text.

### v0.11.0 — Palace Monitor: pixel-art memory world (done)

Shipped: served at `GET /monitor` (self-contained, `fetch()`-streamed so it
can send the bearer), demo mode until connected, a live `hmac-fail` event
driving the tamper beacon, and a `GET /v1/vaults` picker. Verified live
against a real server.

A real-time, game-style pixel-art view of how memory is distributed
across the palace, reading the v0.10 stream. Inspiration:
`pixel-agents-hq/pixel-agents` (agents-as-characters in a live office) —
reimagined around Undercroft's own metaphor: the palace *is* the world,
and an **archivist** files drawers into wings and rooms as writes land.

- **Self-contained local UI** served at `/monitor`. Vanilla Canvas-2D +
  a sprite sheet embedded as a data-URI — **no framework, no external
  CDN/fonts/assets, zero runtime JS toolchain** (hand-written, or a Vite
  bundle inlined at build time). One self-contained asset, CSP-safe,
  faithful to the local-first ethos. (Deliberate divergence from the
  reference's Node/React/Fastify stack, which the Rust runtime avoids.)
- **Pixel-art game world**: the palace rendered as an explorable
  top-down / isometric building. Wings are wings/floors, rooms are
  chambers, drawers are filing cabinets whose fill/brightness tracks
  drawer density. A lightweight game loop with sprite animation and a
  character state machine (idle → walk → file/pull).
- **Live, event-driven animation** off the v0.10 discrete pings:
  - *Archivist* walks to the target room and **files a drawer** on each
    `drawer-saved` (and on `mine`/`sweep` bursts); pulls and highlights
    drawers on `search` hits.
  - *KG hallways* — corridors drawn between co-occurring rooms, pulsing
    when a new `kg-triple` forms; entities as a constellation overlay.
  - *Audit-chain* — a stamp/ledger animation on each `chain-commit`,
    with the running chain height shown.
  - *Activity ticker + gauges* — search latency, QPS, cache hit rate,
    FTS prefilter ratio, drawer add/delete rate.
- **Sealed vaults stay opaque**: a sealed room renders as a locked
  vault-door showing only an aggregate silhouette (drawer *count*),
  never names or content — same no-plaintext invariant as the rest of
  the stack.
- **Read-only, metadata-only, default-off, loopback, auth-gated.**
  Multi-tenant aware: one building per vault/tenant plus a palace-wide
  roll-up (mirrors the reference's multi-agent view).
