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

**Status 2026-08-10: O1, O2, O3, O4 and O5 are CLOSED** — O1 with an executed
gate, O5 by maintainer's ruling (the components keep their names; the only
constraint is that nothing carries the former project name or `MemPalace`,
and that was tested, not assumed), **and O8 is CLOSED** — the compose project
name is declared rather than derived from the clone's directory, with a
preflight counted both ways. **What remains open is O6** — a click in the
GitHub web UI that no REST endpoint exposes, so no amount of engineering
closes it from here — **O7**, split out of O5 so the ruling is not mistaken
for having closed a defect it does not touch, **O10**, that the former-name trace verifier is
invoked by nothing and lives outside the tree — which is how O8's own unit put
the former name back into a tracked file with the battery green — and two
filed while closing O13: **O14**, `/v1` can MINT a forgetting attestation and
cannot check one, and **O15**, the battery's own test count over-reports
because `docker compose run` replays the tail of the stream.

**O13 is CLOSED 2026-08-11** — round four's second CRITICAL. A genuine
forgetting attestation reported FORGED with exit 2 after any key rotation;
the fix is the third verdict the entry specifies, not the key swap the sweep's
plan described, and all three gate arms plus contiguity were executed.

**O9 is CLOSED 2026-08-11** — the required status check on `main` resolves to
`CI verdict`, and a red suite was **observed** to block a merge on a
throwaway pull request rather than inferred from the workflow. **O11 and O12
were opened and closed on 2026-08-10**: the orphan-label leg now covers bare
drawer ids (the deletion-path enumeration that had blocked it is done), and a
hand-declared fact citation is declined by doctrine rather than left as a
question.

**Round four (2026-08-10) found 70 verified defects** across eleven
dimensions — 2 critical, 20 high, and **67 of 70 failing silently**. Full
findings and all 70 fix plans in `.handover/SWEEP4_FINDINGS.json` and
`.handover/SWEEP4_FIX_PLAN.md`; the synthesis groups them into ten units by
shared choke point. O8 above is the first of those units to land. Nothing
else from that sweep is applied yet, and no plan is a fix until it carries a
test that was run against the reverted code and observed to fail.

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

### O1 — CLOSED 2026-08-10: binaries shipped and the image is public
The `v1.0.0` release workflow completed successfully and **20 assets** are
published, correctly named `undercroft-v1.0.0-<target>[-ort].tar.gz` plus
`.sha256` — five targets, both variants. The release button on the landing
page is now honest.

**What was wrong:** `ghcr.io/sealcroft/undercroft` answered **HTTP 403 to an
anonymous pull token**. GHCR packages default to *private* visibility on
first push, so `docker pull ghcr.io/sealcroft/undercroft:latest` — the first
command in every install path (`README.md`, `docs/getting-started.md`,
`docs/AGENTS.md`, the landing page's install tab) — failed for everyone who
was not the owner. **The owner could not see it**, because their own pull is
authenticated: it failed only for the people the project is trying to reach,
none of whom would report it.

**What closed it, and the first attempt did not work.** Flipping the package
alone is not enough when the ORG forbids public packages: the package's own
visibility control renders greyed out with *"Setting is disabled by
organization administrators"* — shown even to the org owner, which is what
makes it read as a permissions problem rather than a policy one. Two steps,
in order:

1. **Organization → Packages policy** —
   <https://github.com/organizations/sealcroft/settings/packages> → **Package
   creation** → tick **Public**. Note the path is `/organizations/`
   (settings), not `/orgs/` (browsing).
2. **Package → visibility** —
   <https://github.com/orgs/sealcroft/packages/container/undercroft/settings>
   → Danger Zone → **Change visibility** → Public. The control is only
   active once step 1 has been applied.

Neither step has a REST endpoint: GitHub's Packages API exposes get / delete
/ restore and **no visibility endpoint at all**, and the org package-creation
policy is not in the orgs API response either. The web UI is the only route.
(The local `gh` token additionally carries only `gist, read:org, repo,
workflow` — no `read:packages` — so it cannot even read the package's
visibility.)

**Gate — EXECUTED 2026-08-10, anonymous throughout:**

| Check | Result |
|---|---|
| `tags/list` with an anonymous pull token | **200** (was 403) |
| Manifest fetch for `:latest` — what `docker pull` does | **200** |
| Architectures in that manifest list | `linux/amd64`, `linux/arm64` (the third, `unknown`, is the buildx attestation) |
| `v1.0.0-ort` manifest | **200** |
| **Negative control** — a package that does not exist | **403** |

The negative control is load-bearing: without it a 200 could mean the check
was answering 200 to everything, which is this project's standing rule that a
broken checker and a clean tree are indistinguishable.

**A correction this closure forced.** The paragraph above used to say the
walkthrough pulls `ghcr.io/sealcroft/undercroft:1.0.0`. It does not, and that
tag has never existed — measured **404**, because the release tags are
`v`-prefixed (`v1.0.0`). Every shipped install path uses `:latest`, which
resolves. The claim was wrong in the entry, not in the product, and it
survived because nobody ran it.

**Gate:** an anonymous `ghcr.io/token` + `tags/list` must return 200, not
403 — one curl:

```bash
T=$(curl -s "https://ghcr.io/token?scope=repository:sealcroft/undercroft:pull&service=ghcr.io" | sed -E 's/.*"token":"([^"]+)".*/\1/'); curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $T" https://ghcr.io/v2/sealcroft/undercroft/tags/list
```

**Re-run it after any change to the org's package policy**, since that policy
governs the package's visibility control and nothing in the repo does. A 403
here means step 1 above was not applied, or was reverted.

### O2 — the site loaded three font families from Google — CLOSED 2026-08-09
*(Heading corrected 2026-08-10: it still read as an open problem while the
body below said CLOSED. Its siblings carry their status in the heading and
this one did not, which is the "a heading is the most expensive artifact
this project produces" trap — found while verifying a handover rather than
by a gate. Verified against the tree: 20 vendored `.woff2` files, and zero
references to `fonts.googleapis` in the landing page or the stylesheet.)*
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

### O5 — terminology decision, CLOSED 2026-08-10: `palace` stays
**Maintainer's ruling, 2026-08-10: the architectural components keep their
names. The only naming constraint is that nothing is called by the former
project name or by `MemPalace`.** `palace` is neither — it is an ordinary
noun from the memory-palace metaphor, not a borrowed brand, and no rename is
owed. This closes the item as a DECISION with an argument, which is the only
way "accepted" is a resting state in this file.

**The condition was tested rather than assumed**, because it is testable:

- **The former name** — `.handover/verify-no-trace.py` over all 367 tracked
  files reports **0** across all six classes (Latin, truncated root, Greek,
  base64, mythic identity, inside-a-certificate). The scanner was itself
  probed first: every pattern sourced out of the file fires on a
  known-positive and none fires on clean text (`mnemonic` is correctly
  excluded by the `(?!nic)` lookahead), so the zero is a working scanner
  reporting a clean tree rather than a broken one reporting nothing — the
  distinction this project has paid for twice.
- **`MemPalace`** — present, and correctly so: `NOTICE`'s MIT heritage
  attribution, `docs/PARITY.md`, and code comments citing what was ported.
  Licence-adjacent; do not remove.

**What this ruling does NOT settle**, stated plainly rather than absorbed
into the closure: `palace` still names two different levels of the hierarchy
— `Vault::db_path()` joins `palace.db` onto ONE vault's directory
(`undercroft-vault/src/lib.rs:217`), while "the palace" elsewhere means the
whole installation (`keys.rs:60` "the palace master key"; `main.rs:68`
"Initialize the palace"). That is a coherence defect **independent of any
rename** and it survives this decision untouched. It is cosmetic — internal
vocabulary, no wire, no crypto domain, no id recipe — and it is recorded here
so it is not mistaken for something the ruling closed. Filed as **O7** below.

The measurement that informed the ruling is kept for the record.

---

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

**The constraint that actually remained was vocabulary, not data.** The
obvious replacement was `vault`, and `vault` already names a different
concept — the isolation and crypto unit — so reusing it would have been worse
than the status quo. That search is over: the ruling above is that no target
word is needed, because no rename is owed.

### O6 — the repo social preview is still not uploaded
GitHub exposes **no REST endpoint** for org avatars (`avatar_url` is read-only
on the orgs API) or repo social previews, which is why neither can be closed
from a shell. `assets/brand/` holds the marks; `sealcroft.github.io/assets/`
holds the house mark. The org avatar wants the 512x512 square, the social
preview the **1280x640** card — they are not interchangeable.

**Assets re-verified 2026-08-09** by reading each PNG's IHDR rather than
trusting its filename: `undercroft-mark-512.png` is 512×512 and
`undercroft-social-1280x640.png` is 1280×640.

**The org avatar is DONE — verified 2026-08-10, and this entry was stale.**
`https://avatars.githubusercontent.com/u/314753270` serves the **Sealcroft
house mark**, byte-for-byte the design at
`sealcroft.com/assets/sealcroft-mark-512.png` — which is the right choice of
the two, since the house is not the product. Nobody could have noticed from
inside the repo: an upload leaves no trace here.

**Note the two halves needed DIFFERENT checks, and only one was conclusive
from a URL.** A custom org avatar and a default identicon are served from the
same `avatars.githubusercontent.com/u/<id>` form, so the URL proves nothing;
file size hinted (33 KB at 460×460, where an identicon is flat geometry at
1–3 KB) and **rendering the image settled it**. That is the same lesson as
the Greek spelling on the landing page: the check nobody had run was looking
at it.

**What remains — the repo social preview.** `og:image` on
<https://github.com/sealcroft/undercroft> still resolves to
`opengraph.githubassets.com/…`, GitHub's auto-generated card, not to
`repository-images.githubusercontent.com/…` where a custom upload lands. So
every link shared to Slack, Discord, X or LinkedIn renders the generic card.
It fails **silently** — nothing breaks, the project just looks unbranded at
exactly the moment someone is deciding whether to look at it.

- Repo social preview → <https://github.com/sealcroft/undercroft/settings> →
  Social preview → Edit → `assets/brand/undercroft-social-1280x640.png`.

**Gate:** `og:image` on the repo page must point at
`repository-images.githubusercontent.com`, not `opengraph.githubassets.com`:

```bash
curl -sL https://github.com/sealcroft/undercroft | grep -oE '<meta[^>]*og:image[^>]*>'
```

That host distinction is the whole test, and it is conclusive — unlike the
avatar, no rendering is needed.

### O8 — the compose project name was derived, not declared — CLOSED 2026-08-10
Found by the round-four sweep (dimension D8, the maintainer's explicit ask).
No compose file declared a `name:` key, so Compose derived the project name
from **the directory the clone sits in** — on the maintainer's machine, still
the project's former name. Every container, image, volume and network the repo
built was branded with it: `<former>-site`, `<former>-lint`,
`<former>_default`, `<former>_undercroft-backends-tls`.

**Why nothing caught it.** `.handover/verify-no-trace.py` scans tracked file
CONTENTS across six classes and reported **0 hits over 367 files** — a correct
answer to the wrong question. The name was in no file. It is the fifth class
in CLAUDE.md's list now: *a derived identifier is a name too.*

**It had already falsified a document.** CLAUDE.md's volume-mount recipe named
`undercroft_undercroft-embed-tls`, which did not exist on a `<former>_`-prefixed
machine — one sentence after warning that a wrong volume name mounts a fresh
empty volume with no error. The doc handed you the failure it was warning about.

**Closed:** `name:` declared in all four compose files — `undercroft`,
`undercroft-server`, `undercroft-observability`, `undercroft-bench-vs`. Distinct
on purpose: sharing one project would let `docker compose down -v` in the repo
destroy a running team server's or observability stack's volumes.

**Gate:** a `tests/battery.sh` preflight counted BOTH ways — a compose file with
no `name:` fails, and a declared name outside the expected set fails, so a future
file cannot quietly pick a colliding or former-name project. It carries a premise
probe that refuses to pass if it found fewer than three compose files, because a
glob matching nothing reports exactly what a clean tree reports. Counterfactuals
executed in both directions on scratch copies. **The gate immediately found
`deploy/bench-vs/docker-compose.yml`, which the hand enumeration that preceded it
had missed** — the argument for an inventory over a listed set, demonstrated on
its own author.

**Residual, stated:** this preflight lives in `tests/battery.sh`, which **no CI
workflow invokes** (`ci.yml` mentions it only in comments). So it gates a local
battery and not a pull request, exactly like the three preflights beside it.
That is the round-four sweep's Unit 0 and is filed as **O9**.

Artifacts carrying the former name were purged from the maintainer's machine
after the maintainer confirmed the data was disposable test data: 13 containers,
10 volumes, 3 networks and ~35 images, each classified by its
`com.docker.compose.project` label and its mounts rather than by its name — a
first pass that classified by name alone mislabelled five of this project's own
ad-hoc containers as another project's.

### O9 — CLOSED 2026-08-11: the required check is configured and observed to block
Found by the round-four synthesis, which no single dimension filed. `ci.yml`
mentioned `battery.sh` only inside comments, so **all four preflights** (line
endings, ROADMAP headings, handover freshness, compose project names) were
local-only and gated nothing on a pull request. Compounding it, the aggregate
verdict job declared `needs: suites` alone, leaving `lint`, `audit`,
`trivy-fs`, `site` and `trivy-image` outside the verdict; its `name: Suites
(aggregate)` put the status context somewhere other than `test`, while the
matrix leg `name: ${{ matrix.suite }}` emitted a context literally called
`test` for one suite of seven, so the obvious required check would have bound
to a single cargo suite. The comment above it warned that renaming the job
"would silently un-gate the branch" — protecting a configuration that has
never existed.

**Fixed 2026-08-10, and each part was executed rather than reasoned about:**

- A `preflight` job runs `bash tests/battery.sh --preflight-only`, a new entry
  point that runs the host-side preflights and no suite. Unknown options exit
  1, never 2 — exit 2 is this project's integrity verdict.
- The aggregate is the `verdict` job, published as the context **`CI verdict`**
  — one no matrix leg can collide with. The matrix legs are `suite (<name>)`.
- `needs:` lists every job, and the step inspects **every entry** of
  `toJSON(needs)` rather than naming the ones it checks, so `skipped` and
  `cancelled` fail it too. Driven through four synthetic states — 7 green,
  one `failure`, one `skipped`, and a narrowed 6 — using the script
  **extracted out of `ci.yml`**, in a container, not a retyped copy.
- The step asserts its upstream COUNT, so a narrowed `needs:` fails closed.
  That is the only direction a workflow can enforce on itself: it cannot
  enumerate its own jobs, so a NEW job nobody wired in is invisible from
  inside it. `tests/battery.sh`'s CI-inventory preflight reads the file and
  closes that direction, counted both ways — counterfactuals executed in both
  (a job dropped from `needs:`; a `needs:` entry that is no job), with the
  file restored byte-identically and re-verified after each.
- The premise probe on that preflight earned itself immediately: job ids are
  keys at two spaces, and so are `push:` and `pull_request:` under `on:`, so
  an unanchored scan reports two jobs that do not exist.

**CLOSED 2026-08-11, and every arm was executed rather than read.** The branch
was pushed and PR #116 opened — note that pushing alone triggers nothing,
since `ci.yml` fires on `push` to `main` and on `pull_request`, so a PR is
what makes CI run at all. That run reported **14/14 green**, including
`suite (onnx-build)`, which CI runs and the local battery does not.

| Arm | Evidence |
|---|---|
| Preflights gate a PR | `Preflights (line endings, ROADMAP, compose, CI inventory)` — pass, 7 s |
| Legs cannot collide with the verdict | contexts are `suite (test)` etc.; no bare `test` |
| Required check configured | `PUT …/branches/main/protection` → read back `contexts: ["CI verdict"]`, every other setting preserved |
| It binds to a REPORTED context | #116 reads `MERGEABLE` / `CLEAN` — not the permanent-pending deadlock |
| **A red suite blocks a merge** | **negative-control PR #117**: deliberate rustfmt violation → `Lint` fail → `CI verdict` fail → merge state **BLOCKED**, the verdict job logging *"not green — see the individual jobs above: lint"*. Closed and its branch deleted immediately |

The negative control is the arm that could not be established by reading, and
this branch had already found three claims about CI that were false when
read. **Cost worth recording: it makes the repository's CI go red on purpose,
and the maintainer saw that before being told.** Announce it first next time —
an alarm nobody can distinguish from a real failure is the thing this project
exists to remove.

**Live residual until #116 merges:** `main`'s `ci.yml` has no `CI verdict`
job, so any OTHER pull request branched from `main` blocks on a check that
can never report. `enforce_admins` is false — deliberately preserved — so an
admin can still merge; that is the escape hatch, not the design.

**Still not reconciled, and filed rather than fixed:** CI and the battery run
different suite sets in both directions, and `ort-build` is run by neither
while `release.yml` ships an `ort` binary for five targets.

**Also filed here rather than absorbed:** CI and the battery run **different
suite sets**, in both directions, under a comment that asserted they cannot.
The matrix carries `onnx-build` and the battery does not; the battery carries
`lint` and `site`, which CI runs as their own jobs; and `ort-build` is a
compose service run by **neither**, while `release.yml` ships an `ort` binary
for all five targets — so nothing automated ever compile-checks that feature.
The comment is corrected; the sets are not reconciled. Reconciling them is a
decision about CI cost, not a defect to fix silently: state which set is
canonical, then count them against each other in the preflight that already
reads both files.

### O7 — `palace` names two levels of the hierarchy
Split out of O5 on 2026-08-10 so the ruling that closed O5 (the components
keep their names) is not mistaken for having closed this too. **It is a
separate defect and the ruling does not touch it**: the objection here is not
*which* word, it is that ONE word denotes two different things.

- `Vault::db_path()` joins `palace.db` onto a **single vault's** directory —
  `crates/undercroft-vault/src/lib.rs:217`.
- Everywhere else "the palace" is the **whole installation**: the palace
  master key (`crates/undercroft-vault/src/keys.rs:60`), `Initialize the
  palace` (`crates/undercroft-cli/src/main.rs:68`), `Mine a directory into
  the palace`, `Export the palace`.

So a reader is told the palace contains vaults, and also that each vault
contains a palace. That is confusing on its own terms and would still be
confusing under any replacement noun.

**Scope — this is cosmetic, and the boundary is what makes it cheap.** It
touches no wire format, no serde field, no crypto domain separation, no
audit-chain namespace and no id recipe (all four re-checked under O5 above).
The per-vault filename is the only on-disk artifact, and renaming a file
that an existing vault already carries presents as `DatabaseMissing` —
409 / exit 2, an integrity verdict — so it is **not** a free move on a
populated vault even though the vocabulary change is trivial.

**Shape of a fix:** rename the per-vault artifact, not the installation-level
noun — the installation sense is the older and more widely written one. A
migration would have to open the vault, rename within the same directory, and
leave the anchor untouched.

**Gate:** whatever lands, a vault created before the change must still open
without an integrity verdict, and `verify` must stay green across it.

**Not scheduled.** Filed because a gap is a gap; if it is judged not worth
doing, that is a decision with an argument and belongs here in writing rather
than as an item that quietly never moves.

### O10 — the former-name trace verifier is invoked by nothing
`.handover/verify-no-trace.py` is the only check the tree has for the six
file-content classes of the former project name (Latin, truncated root,
non-Latin script, base64, mythic identity, inside a certificate). It is run
**by hand**. It sits in a gitignored directory, so a fresh clone does not
carry it at all, and no suite, no `tests/battery.sh` preflight and no workflow
invokes it.

**This is not hypothetical, and the instance is from the unit that closed
O8.** The comment written into `docker-compose.yml` to explain the derived-name
defect **quoted the former name** while explaining that quoting it is how it
gets back into the tree. The verifier exited 1 naming two classes on one line;
nothing else in the repository could have seen it, and the battery was green
across it. That is the trap CLAUDE.md records against itself — *describe the
class, never the token* — recurring inside the change that documents the class,
which is the same shape as a gate written in the round that was fixing the
gate's own defect class.

**Shape of a fix, and two constraints decide the design.** Track the scanner
in the repo and invoke it from a preflight:

1. **A tracked scanner scans itself.** Its patterns must be needle-split (the
   `concat!` idiom `undercroft-obs`'s gauge gate already uses) so the file
   holds no matchable literal. Excluding it by path instead is the
   unfalsifiable-second-direction defect round three found, where the file
   holding the inventory sat inside the tree the gate scanned.
2. **It needs a premise probe.** Every pattern must fire on a synthesized
   known-positive and none on clean text before a zero-hit result is believed.
   The script has no probe today; it was probed by hand, once, in a session —
   which is a property of that session and not of the artifact.

It must run **in a container**, not on a host interpreter — this project
builds and tests in Docker, and a gate that needs Python on the host is a gate
that does not run on the next machine. A preflight that *skips* when its
interpreter is absent reports exactly what a clean tree reports, so the
container is the fix and detection is not.

**Land it with Unit 3, not alone.** The round-four synthesis groups the
preflight family into one unit precisely because scanners landed one at a time
produce differently-broken scanners — this tree has already shipped two.

**Gate:** the counterfactual executed by hand on 2026-08-10 becomes the
self-test — restore the token on a scratch copy and the preflight exits
non-zero naming file and line; remove it and it exits 0; empty the pattern set
and the premise probe fails rather than passing vacuously.

**Residual, the same one O9 carries:** a preflight in `tests/battery.sh` gates
a local run and nothing on a pull request until O9 lands.

### O11 — CLOSED 2026-08-10: the orphan-label leg now covers drawers too
Raised by the round-four sweep as a defect; **reclassified here as an open
question with an argument, because it is a recorded boundary and not a
drift.** `VerifyReport::orphan_labels` resolves audit labels only for
`kg/{id}`, `kg/{id}/authority` and `kg-entity/{id}`, and its doc comment
scopes that deliberately: nothing in the crate deletes from `kg_triples` or
`kg_entities`, so those labels must always resolve, while every other
namespace has a legitimate path to an absent subject — `del/{id}` names a
destroyed drawer *by definition*, a denied admission destroys its drawer,
`retention-clear/{wing}` removes the row `retention/{wing}` described, and
`read/`, `egress/` and `rotate/` name no row at all. Including them would
alarm on ordinary operation, which is worse than not having the leg.

**What the written reason does not address, and this is the real finding:**
a *discriminating* check is possible for drawers and was never considered —
a bare drawer-id label, zero live rows, **and no `del/{id}` record** is not
ordinary operation, it is a relabel onto a drawer that was never destroyed.
`record_id` is the one part of an audit row outside the chain hash, which is
the whole reason this leg exists; the argument for scoping it to the graph
is an argument about false positives, not about coverage.

**The enumeration was the work, and it came before the code.** The question
was whether every path that destroys a drawer writes `del/{id}`; if any did
not, the discriminating check would alarm on ordinary operation exactly as
the doc predicted. Answered by reading, 2026-08-10:

| | |
|---|---|
| Statements removing a drawer row in production | **exactly one** — `manage.rs`, inside `delete_drawer_ruled`. Every other `DELETE` touches a derived index table (`drawer_fde`, `drawer_pq`, `drawer_pq_wing`, `drawers_fts`); the one in `lib.rs` is inside a `#[test]` |
| Its shape | a declared **delete choke point** — *"a new delete path does not compile until its author decides"* |
| Callers | three, all of them: the public `delete_drawer`, admission **deny**, and `forget_with_proof` — which the retention sweep and `delete_by_source` ride |
| The record | `del/{id}`, appended **in the same transaction** as the delete |
| Bare labels | `&drawer.id` is the ONLY no-slash `record_id` the store mints — enumerated from every `chain_append` call site |

So "no live row and no tombstone" is unreachable legitimately, and the check
discriminates. **Closed by widening the leg**, not by a new one.

**Gate, both arms executed:**
`a_relabelled_drawer_audit_row_is_an_orphan_and_a_deleted_one_is_not` deletes
a drawer through the API and requires `verify` to stay green, then relabels a
surviving drawer's audit row onto an id no drawer ever had and requires the
verdict to fail naming it — with the other four legs pinned clean so the
failure is attributable. Counterfactual: reverting the leg to graph-only
makes the relabel invisible (`orphan_labels: []`). **Its premise probe earned
itself immediately** — the first fixture asserted one relabelled row and
moved two, because `src_drawer` fixes wing/room/source/chunk_index and the id
recipe deliberately excludes content, so two calls to it are one drawer
written twice.

### O12 — CLOSED by doctrine: a citation is DERIVED, never declared
Found on 2026-08-10 by an e2e check that FAILED: it asserted `undercroft
verify` printing its fact-receipt line, on a fixture where no fact cites
anything. `undercroft kg add` takes subject, predicate, object, `--from`,
`--to` and `--confidence` and **has no `--source`**; `/v1` has no KG write
route at all (browse plus `kg/authority`); so the only producers of a citing
fact are `refine`, which needs an LLM, and `import`.

**A correction to this entry's own first draft**, which said the machinery
was "unreachable by hand". It is not: `import` reaches it with no model at
all, and the e2e now does exactly that — export a vault, point the fact at
the drawer's derived id, add a `source_fp` CLAIM (the value is irrelevant and
deliberately not stored; the destination re-derives from the drawer it just
imported), drop the manifest line whose payload digest would otherwise
refuse the edit, and import. The result is a genuine keyed receipt reading
`1 verified`. So the true claim is narrower and still worth recording: there
is **no interactive path**, only a payload-construction one.

**The decision comes from the documents, not from preference, and they
settle it.** Three passages, in order of authority:

1. **`ROADMAP` C3.1** says what a receipt is FOR: "every fact carries an
   HMAC-verified citation to its verbatim source drawer … their pitch (smart
   memory) becomes our subset; our pitch (**provable** memory) stays
   exclusive."
2. **`architecture/index.html`, "A model may point, not assert"**: distillation
   "is asked for quotations … and the engine checks each span against the
   note it supposedly came from. A span the note does not literally contain
   is not evidence and contributes nothing." A receipt is the residue of a
   **derivation the engine checked**.
3. **`docs/LABELS.md`**: "a **self-declared label is never a trust
   boundary**", and "trust labeling belongs to deployment-assigned facts …
   controlled by the principal, not by the content's author."

A declared citation produces no derivation to check. The strongest verdict it
could ever earn is "someone asserted this, and that drawer's text has not
changed since" — a weaker claim wearing `Verified`, the word carrying the one
guarantee C3.1 calls exclusive. **That is laundering, and this tree's
standing answer to laundering is to distinguish, never absorb**: grounding is
`stated` / `background` / `unevaluated` because "we did not look" and "we
looked and found nothing" are different claims, and `Unreceipted` exists
because it "says something different" from `Dangling`. A `--source` flag as
proposed would have collapsed exactly that distinction.

**So: declined. `kg add` gains no `--source`.** The absence is a boundary,
not a drift, and it is recorded here as one.

**Applied backwards, as `CLAUDE.md` requires of any rule written down here,
it changes nothing — in the first sense, the good one.** The tree already
behaves this way everywhere: `kg add` never had the flag; a hand-added fact
records no extractor identity while a distilled one carries it inside the
fact's HMAC; trust assignment is refused on MCP for the same "not the
content's author" reason. The rule describes what is already done, which is
the outcome that validates it rather than the one that leaves it untested.

**What would REOPEN it, stated so this is a decision and not a wall.** If a
product case appears for hand-declared provenance, the doctrine already fixes
its shape and all three parts are mandatory:

- a **distinct verdict** (`Declared`, beside `Verified`), because the
  existing word means derived-and-checked;
- the **declarer's identity inside the fact's HMAC**, the extractor-identity
  precedent — `LABELS.md` requires identity and receipts before any surface
  may filter on a claim;
- **operator surfaces only, never MCP**, since an agent asserting its own
  provenance is precisely the content's author declaring its own trust.

Anything less re-opens the laundering this closure refuses.

**Settle it before adding the flag**, and record which way. If it lands:
`kg add --source <drawer-id>` writing through `kg_add_receipted`, MCP
deliberately excluded (an agent asserting its own provenance), and the e2e
arm above upgraded from "the leg is quiet" to "the leg renders and a forged
one fails".

### O13 — CLOSED 2026-08-11: a rotation makes the replay unavailable, not the attestation forged
Round-four finding #2, **CRITICAL**, and the analysis below goes past the
sweep's plan because the fix is not the one-line key swap it looks like.
Filed rather than half-landed on 2026-08-10: this changes a security VERDICT,
and a half-correct verdict is worse than a known-wrong one. Closed the
following day, along the shape the analysis specified.

**The mechanism, read in the code.** `verify_forget_attestation`
(`forget.rs`) re-checks each tombstone with `self.vault.verify_tag(b"del\x1f{id}", tag)`
and replays the chain with `self.vault.chain_next_hex` — both under the
**current** MAC key. `Vault::rotate` writes a fresh salt, which re-derives all
four subkeys including the MAC key, and re-keys the chain over preserved
`audit.tag` bytes. So after a routine rotation:

- every tombstone tag in the attestation fails `verify_tag` → the error is
  *"tombstone tag for {id} is not this vault's"* → `StoreError::Attestation`
  → **exit 2**, this project's tamper verdict;
- and `head_before`/`head_after` no longer correspond to the re-keyed chain,
  so the head comparison cannot pass either.

"We destroyed your data, here is the proof" becomes "this proof is forged",
the first time an operator does the thing the security model tells them to do
routinely. There is **no test coverage**: `verify-forgetting` appears nowhere
in `tests/` outside unrotated fixtures, so nothing would have caught it and
nothing will catch a regression in the fix.

**The blast radius is bounded and the boundary is the useful part.** The
third-party path is *unaffected*: `verify_detached(sender, att.canonical(),
sig)` checks the operator's Ed25519 signature and touches no vault key. So a
recipient holding the signed document still verifies it after any rotation —
it is the VAULT's own keyed replay that breaks. That asymmetry is already
documented ("third parties verify the operator's SIGNATURE, not the replay")
and it means this is a false alarm, never a lost proof.

**The fix is the doctrine's, not a key swap.** Old keys are destroyed by
rotation — that is the point of rotation — so the keyed replay is genuinely
unavailable, and the honest answer is a third state rather than a verdict:
`stated`/`background`/`unevaluated` exist because "we did not look" and "we
looked and found nothing" are different claims, and `Unreceipted` exists
because it says something different from `Dangling`. Three outcomes:

1. tag verifies under the current key and the heads chain → **verified**, as
   today;
2. tag FAILS `verify_tag` **but equals the tag stored in this vault's own
   `audit` row for `del/{id}`** — which rotation preserves verbatim — → the
   evidence is real and the replay is unavailable. A distinct verdict,
   **not** forged, **not** exit 2;
3. tag fails both → **forged**, exit 2, as today.

Note (2) needs no change to the attestation format and no new field to go
stale: the vault already holds the bytes, and comparing them is a structural
proof that the document names evidence this vault actually recorded. A
`key_generation` field was considered and rejected for that reason — it would
have to be optional for legacy documents, and an optional provenance field is
exactly the claim a verifier cannot rely on.

**Gate:** create an attestation, rotate the vault, verify → must report the
distinct verdict, must NOT say forged, must NOT exit 2; a tag forged after
the rotation must still fail with exit 2; and the third-party signature path
must verify across the rotation unchanged. All three arms, or the fix has
merely moved which case is wrong.

**What closed it, and the two places the shipped fix goes past the analysis
above.** `verify_forget_attestation` returns `AttestationVerdict::{Verified,
Recorded{rotations_since}}` instead of `Result<(), _>`; `Recorded` is exit 0
with its own verdict word, never exit 2. The enum is `#[must_use]`, which is
not decoration — it turned every existing `verify_forget_attestation(…)
.unwrap();` in the tree into a compile error until each one stated WHICH
verdict it meant, so the third state could not silently weaken an assertion
that used to mean "verified". The CLI's `match` is exhaustive for the same
reason: a fourth verdict cannot be added without the operator surface
failing to build, which is a stronger gate than an entry in `HAND_PROJECTED`
and is why one was not added.

1. **Contiguity, which the analysis did not ask for and the claim needs.**
   Checking only that each tag equals a stored `audit` row admits a document
   that omits a record from the MIDDLE of its own interval — exactly the
   claim the head replay provides on the keyed path. So the attested records
   must be a contiguous run of this vault's own trail, in order, every column
   compared. A candidate walk rather than a lookup, because a drawer id is
   deterministic: mine → destroy → re-mine → destroy writes two tombstones
   with the same `record_id` AND the same tag bytes.
2. **The heads are honestly unverifiable on this path**, so the CLI narrows
   its own claim rather than repeating "nothing else changed": it prints what
   was NOT re-checked, and points at `undercroft verify` for the trail
   itself.

`rotations_since` is read from the trail (`record_id LIKE 'rotate/%'` after
the run) and is **corroboration that never decides the verdict** — a rotation
before A19 appended no record, so a legacy vault legitimately reports zero,
and a check reading zero as "no rotation, therefore forged" would recreate
the defect for exactly the oldest vaults.

**Residual, stated rather than absorbed.** `Recorded` cannot separate a
preserved genuine tag from a preserved forged one — the key that could is
destroyed, which is a property of rotation and not of this check. An offline
writer who inserted a tombstone-shaped `audit` row and destroyed the drawer
reaches `Recorded` where the old code said forged. It is not unwitnessed: on
an unrotated vault that row breaks `verify`'s chain replay; on a rotated one
the operator's own rotation re-keyed the chain over it, which nothing here or
anywhere else can undo. The trade is a narrow ambiguity against a **certain**
false alarm on the routine path.

**Gate executed 2026-08-11**, all three arms plus two the entry did not ask
for. Unit: `a_key_rotation_makes_the_replay_unavailable_never_the_attestation_forged`
(forget.rs) — premise (unrotated → `Verified`), arm 1 (rotated genuine →
`Recorded{1}`), arm 2 (tag forged after the rotation, re-signed so the
signature is not what refuses it → `StoreError::Attestation`), arm 3
(`verify_detached` across the rotation, untouched), arm 4 (a record omitted
from the middle, refused on BOTH postures), and the count moving to 2 on a
second rotation so it cannot be hard-coded. **Counterfactual run:** the
pre-O13 refusal was restored in place and the test failed at arm 1 with
`Attestation("tombstone tag for … is not this vault's")`, then passed on
revert. Surface: `tests/e2e.sh` drives the CLI on both sides of a real
`vault rotate` — `verify-forgetting` had **zero occurrences under `tests/` on
any surface** before this, which is why nothing caught it and nothing would
have caught a regression. Real corpus: 4,080 audit records mined from
`.handover/locomo_feed.txt`; the recorded path costs ~1 ms over the forged
path (33 ms vs 32 ms end to end), and nothing multiplies by record count.

---

### O18 — CLOSED 2026-08-11: the documented pre-upgrade command runs, and every subcommand owns its help
Round-four findings **#10** and **#41**, closed together because they live in
one clap block and share a cause: nothing in this tree reads what the CLI
*advertises*.

**#10.** clap derived `config-check`; `UPGRADING.md`'s pre-upgrade command,
the release flow in `CLAUDE.md`, `README`, `docs/AGENTS.md` and
`architecture/index.html` all publish `undercroft config check`. The command
an operator is told to run before every upgrade returned a usage error. Fixed
as a subcommand group bound to the SAME dispatch arm as `config-check` — an
alias cannot express a two-token spelling, and a second arm would be a second
place for the verdict to drift. The hyphenated form stays; it is what has
always worked. **No doc changed — the docs were right and the code was wrong.**

**#41.** `ConfigCheck` had been inserted between `Hooks`'s doc comment and
`Hooks`, so `config-check --help` described hooks and `hooks` had none.

**Why it needed a gate rather than a fix.** This class is invisible to
everything the tree already runs: clap accepts a comment on any variant,
rustfmt does not reformat doc comments, and no test read help strings. The
gate walks clap's own RENDERED help — deliberately not the source, which
would agree with the doc comments by construction and could not tell which
variant they attach to — and fails on a subcommand with no `about` or on two
sharing one, the two symptoms a stolen comment produces simultaneously. A
premise assertion requires it to have walked a real surface (>30 subcommands).

**This also corrects the applied-list.** `.handover` recorded #10 as applied
and it was not; that was found by running `--help`, not by reading the list.
The other ten entries were then checked against code — #1, #3, #11, #12, #13,
#14, #15, #16 and #32 are genuinely applied — so the list had exactly one
wrong entry, now made true rather than annotated.

**Gate:** `every_subcommand_has_its_own_about_and_config_check_runs`
(main.rs), plus an `e2e.sh` check driving `undercroft config check` as an
operator types it. **Counterfactual executed:** the doc comment restored to
its wrong position, gate failed naming `hooks`, passed on revert. Verified
from the built binary: `config check` exits 0, `config-check` still works,
`hooks` has its help back.

---

### O17 — CLOSED 2026-08-11: the graph's screen is record-scoped, not object-scoped
Round-four finding **#5**, HIGH and silent.

**A field-scoped screen standing in front of a record-scoped read.**
`screen_kg_object` ran the detector on `object` alone and used
`subject`/`predicate` only for its error message, so it read as though it
covered the fact — and its doc comment said "this is the screen on it". Those
two fields had only `validate_name`, which admits any 128-byte string free of
control characters and path separators; every `IMPERATIVE_MARKERS` phrase
fits. `kg_query_entity` returns `Triple` serialized WHOLE, so a poisoned
subject reached the next session verbatim beside a clean object.
`kg_import_entity` screened nothing at all.

**Fixed at the choke point**: `screen_kg_record` over every field a read
returns, named by `KG_SCREENED_FIELDS`; import additionally screens
`canonical_key` and `extractor`, which arrive off the wire and are serialized
back by `kg_query`. **The inventory is bidirectional** — a table-driven test
proves every listed field is screened, and a `debug_assert` in the screen
proves no call site can name a field the inventory omits, which is the half a
test cannot do.

Wider than the finding stated: all three public add variants funnel through
`kg_add_inner`, so **`refine` is covered** — the LLM-distillation path, where
subject and predicate are model output over drawer text that may itself be
injected.

Deliberately unchanged: the size bound stays `object`-only (the rest are
already 128-byte bounded, and `validate_name` on an object would be a real
contract break); a flagged field is REFUSED, not diverted, because the graph
still has no review queue; and an undeclared vault is byte-identical, pinned
by `an_undeclared_vault_screens_no_kg_field` — without which the main gate
would pass on a screen that refused everything.

**Counterfactual executed:** the object-only scope restored in place, the gate
failed on the `subject` row (`got Ok(())`), passed on revert. No surface code
changed: every write reaches the graph through four store functions, and
`StoreError::Invalid` preserves CLI exit 1, MCP `isError` and `/v1` 400.

**Verified at the CLI and on a real corpus**: poisoned subject, predicate and
object each refuse naming the field; a clean fact still writes; 200 LoCoMo
candidates as all three fields with screening declared give 0 false
positives, behind a premise probe. That last arm matters — the FIRST corpus
run reported 0 false positives against a stale binary in which subjects were
not screened at all, so it measured nothing. The premise probe is what makes
a zero mean something.

**Filed, not bundled:** the tunnel `label` (`manage.rs`) is unvalidated,
unbounded, unscreened free text an agent writes and another reads back
verbatim via `list_tunnels` — the same class, found while scoping this, and
it is round-four finding #21 in its own right.

---

### O16 — CLOSED 2026-08-11: an empty assertion secret no longer removes per-vault isolation
Round-four finding **#4**, HIGH, and the only finding in the set where a
security boundary *silently ceased to exist in a configuration the shipped
documentation produces*.

**One line, failing in two opposite directions.** `Tenancy::new` resolved the
secret with `.filter(|s| !s.is_empty())`. `""` became `None`, and
`assert_or_401` returns `Ok(())` unconditionally on `None`, so every `/v1`
assertion gate, the `POST /mcp` transport gate and the SSE gate became no-ops
— with no warning, the banner merely omitting the clause that says assertions
are on. `" "` is **not** empty, so a whitespace-only value was stored as a
real secret: enforcement on, banner truthful, key one guessable byte. The
sweep filed only the first; a fix mapping empty to absent would have left the
second in place.

**Reachable from the shipped recipe.** `docs/remote-server.md` recommends
`UNDERCROFT_ASSERTION_SECRET: ${ASSERTION_SECRET}`; an unset shell variable
interpolates to empty and the variable IS then set in the container. The
recipe now uses `${ASSERTION_SECRET:?…}` so compose fails first.

**One resolver, three consumers.** `undercroft_store::resolve_assertion_secret`
is called by the enforcing side (`Tenancy::new`, now fallible), the MINTING
side (`assert-header`, which already hard-errored on empty while the enforcing
side accepted it — one decision, two inline copies, opposite answers) and
`check_declaration`, so `config check` catches it before a restart. It had
reported this variable `Accepted` — "no parse to run" — on exactly the
environment that had lost isolation, which is the one job that pre-flight has.

**The root cause was a distinction the doctrine implied and never stated**,
now written into `CLAUDE.md`: a declaration is either a **closed vocabulary**
or **opaque payload**. Vocabulary may read empty as a spelling of its default
and is trimmed; payload cannot express intent when empty and must never be
trimmed, because trimming changes the value — for a secret, the KEY, silently
invalidating every header already minted. That is why `UNDERCROFT_ADMISSION`
may read empty as `off` and this may not.

**Same decision, second door, closed in the same unit.** `instance_add`
accepted an empty `assertion_secret` on BOTH orchestrator routes while
`ui.html` refused it client-side only — which is why the server gap was
invisible: every hand-driven registration was blocked and nothing else was.
`proxy.rs` calls its path guard and the assertion MAC "two independent
barriers, because one silent misconfiguration must not remove the only one";
an empty secret removed one at registration and the instance then routed and
reported healthy.

**Counterfactual executed:** the pre-fix filter restored in place, the gate
failed on the `""` arm, passed on revert. **Gates:**
`a_declared_assertion_secret_that_names_no_secret_refuses` (both directions,
the no-trim rule, and the `check_declaration` arm);
`registering_an_instance_without_an_assertion_secret_is_refused` (four
whitespace shapes refused at the door, a real secret stored UNTRIMMED);
`tests/e2e.sh` drives `config-check` and `assert-header` through the CLI for
empty, whitespace-only and a real secret, with the real-secret arms present so
the refusals cannot pass by refusing everything. `UPGRADING.md` carries the
entry, since this can stop a misconfigured deployment at start-up.

**The two surfaces that matter most are GATED now, not probed once
(2026-08-11).** The original gate list covered `config check` and
`assert-header`; the SERVER refusal — the claim `UPGRADING.md` makes to
operators, *"on `serve-http` this happens before the port is bound"* — was
verified by a one-off container run that nothing would ever repeat, and the
orchestrator door not at all. Both are `tests/` checks now: `e2e.sh` asserts
that an empty and a whitespace secret each refuse to start AND never bind the
port, with an unset control so the pair cannot pass on a build that refuses
every configuration; `e2e-orchestrator.sh` asserts `POST /admin/instances`
answers 400 for both and that a refused registration does not appear in the
instance list. A verification that runs once is not a gate.

**Residual, stated:** an empty `bearer` is accepted at the same orchestrator
door and is the same shape one variable over. It is NOT the same boundary —
the bearer authenticates to the engine rather than separating tenants — so it
is named here rather than folded in silently, and it wants its own argument.

---

### O15 — the battery's own test count over-reports by a replayed tail
Found while counting the tree for O13's governance update, which is the only
way this class ever gets found: the number is only wrong when someone counts.

`docker compose run` **sometimes replays the tail of the container's
stream**, so `.battery/test.log` ends with a duplicated block — the giveaway
is a `test result:` line with no `Running`/`Doc-tests` header above it. Both
`tests/battery.sh`'s summary and CLAUDE.md's own instruction ("sum the
`test result:` lines") sum the whole file, so a run that executed **694
passed / 4 ignored** is reported as **1016 / 8**.

**It is INTERMITTENT, and that is the part that makes it worth fixing rather
than the arithmetic.** Two full batteries were run back to back on
2026-08-11, same tree, same command: the first log carried the duplicated
tail and summed to 1016/8, the second did not and summed to 694/4. A figure
that is sometimes right is far harder to catch than one that is always
wrong — nobody re-derives a number that looked plausible last time — and it
is why the fix below counts an orphan rather than quietly skipping it. The
first draft of this entry described the duplication as deterministic; the
re-run falsified that within the hour, which is the same lesson one level up:
**a defect observed once is not thereby characterised.**

**Counterfactual, run against the real artifacts** (the two `.battery/
test.log` files from 2026-08-11, not copies of them): summing every
`test result:` line gives 1016/8 on the first and 694/4 on the second;
pairing each target HEADER with the result that follows it gives 694/4 over
18 targets (11 binaries + 7 doc-tests) on **both**. 694 is independently
corroborated — it is the previous session's 693 plus the single test O13
added.

**It is not a verdict defect and that is exactly why it survived.**
`battery.sh` decides on **exit codes** and never parses output to reach a
pass/fail — deliberately, and written up in `CLAUDE.md` as the lesson that
built the script. So this line has always been decoration, and decoration is
what nobody checks. Its cost is real anyway: it is the number a session
copies into `CLAUDE.md`, and a governance surface carrying an inflated count
is a doc claim that cannot be reproduced.

**Filed rather than fixed in O13's unit, deliberately.** It is two lines of
`awk`, but it changes the tooling every other verdict in this session was
taken from, and validating its own output means another full battery — so
landing it beside a security-verdict change would muddy both. Not an excuse
for leaving it: the mechanism, the artifact and the counterfactual are all
above, so it is minutes of work for whoever takes it.

**Shape of the fix:** in the summary reader, pair `^ *(Running|Doc-tests)`
with the next `^test result:` and sum only paired results; count an orphan as
a **premise failure** rather than dropping it silently, since an orphan is the
only visible symptom of the replay and a reader that quietly ignores one would
stop being able to report that the stream was duplicated at all.

**Gate:** the summary reports 694/4 for the run whose log is on disk now, and
a synthetic log with a hand-appended duplicate tail reports the same figure as
the same log without it — plus the orphan counted and named.

---

### O14 — `/v1` can mint a forgetting attestation and cannot check one
Found while closing O13, and filed rather than absorbed because it is the
drift shape this project keeps paying for: a capability present on one
surface and absent on another, with nothing able to say so.

`POST /v1/vaults/{id}/forget` destroys drawers and returns the attestation.
Nothing on `/v1` verifies one — `verify_forget_attestation` has exactly one
non-test caller in the tree, `Command::VerifyForgetting`. So an operator
driving the HTTP plane can MINT a receipt they cannot check through the same
surface, and the multi-tenant deployment (where `/v1` is the only door an
operator has) cannot check one at all.

It is not obviously a drift rather than a boundary, which is why it is filed
and not fixed in O13's unit: verification takes a caller-supplied document,
and every other `/v1` operator route acts on state the vault already holds.
That is an argument to be made or refused, not assumed.

**Shape of the fix:** `POST /v1/vaults/{id}/verify-forgetting` taking the
attestation JSON as its body, answering the verdict as a typed field rather
than a string — `{"verdict":"verified"|"recorded","rotations_since":n}` —
with the tamper verdict as **409 + `class: "integrity"`**, which is the set
`integrity_verdict` and `tenant::store_err` are already counted against, so
the two surfaces cannot state different doctrines about the same bytes. It is
an operator route, so it belongs beside `rotate` and `forget` and never on
MCP.

**Gate:** the route answers all three verdicts, `e2e.sh` drives each through
`/v1` on both sides of a rotation, and the CLI and the route are shown to
agree on one attestation — the same document, the same verdict, from both
doors.

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
