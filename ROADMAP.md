# Undercroft Roadmap

Undercroft is the Rust conversion of MemPalace with a hardened memory-management
layer (isolated vaults, XChaCha20-Poly1305 encryption, HMAC integrity).


---

## OPEN after 1.0.0 — recorded as work, with a gate each

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

**Recorded, NOT fixed** - each needs its own unit and none is a boundary:
the remote path's quarantine fence decides inclusion off the CLEAR mirror
column (A28 inverted; the trust leg is correct); `UNDERCROFT_ORCH_ENGINE_CA`
is resolved per outbound call rather than at startup, so a bad pin binds the
port and 502s per request, and a policy refusal renders as "engine is down"
on the health surface; a cleartext instance URL is accepted at registration
and refused at request time; `undercroft_chain_commits_total` over-counts in
a two-handle `serve-http` because the record delta comes from the handle's
own stale manifest baseline; the two at-rest migrations (A10, U12) are
whole-vault mutations with no chain record, which is the hole A19 closed for
rotation; `forget` attests a destruction the remote mirror never hears about
(`VectorIndex::delete` has zero callers); a partially-successful `index push`
records zero rather than what left; `RefineReport` is hand-projected on both
surfaces and is structurally outside `HAND_PROJECTED`'s reach; that gate's
4000-char window can pass on a neighbouring handler's text; MCP returns a
verify verdict as prose inside `isError: false`; `migrate` has no exit-code
doctrine; `WRITE_TOOLS` fails OPEN behind a name heuristic. Docs still
stating superseded claims: the egress record (THREAT_MODEL, AGENTS,
architecture, CLAUDE), the trust floor's reach, `serve-mcp --read-only`,
`RefineReport.quarantined`, the new CA variable, and MULTI_TENANCY's framing
of the engine hop as advice.

**Still open from the docs-vs-code dimension** (found, verified in part, not
yet fixed — recorded here rather than left in a transcript): `undercroft-net`
is absent from `README.md`'s crate map and from `docs/architecture.md`; ~23
`ROADMAP <id>` citations across the tree (A10, C8, C14, R5, U12 …) resolve to
no heading in this file, including ones `parity.rs` and `undercroft-net`
point a future author at; `docs/AGENTS.md` routes the observability scenario
to a "Scenario G" that does not exist and omits `anchor` from the
orchestrator ops vocabulary; `docs/THREAT_MODEL.md` says the bundle
downgrade is "refused in every direction" where one direction is
deliberately allowed; two rustdoc comments and THREAT_MODEL list `filed_at`
as a compared mirror column when `verify` deliberately excludes it; the
1.0.0 CHANGELOG contradicts itself on suite counts.

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

## Competitive track (ordered 2026-07-22 — compete hard and exceed)

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

## Operability track (planned)

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
