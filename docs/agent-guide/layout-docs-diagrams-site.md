# Agent guide — documentation, diagrams and the site

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the Layout entries for
`architecture/DIAGRAM_LESSONS.md`, the `architecture/` reference and its
`build.sh`, the illustrative `architecture/platform-views/` set,
`docs/diagrams/`, `website/` and `docs/AGENTS.md`. Read it when your work
touches a diagram, the architecture reference, the site, or `docs/AGENTS.md`'s
tool, route or variable reference.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12), and it governs over any one-line statement of the same rule in
the core. In the moved text, "this file" and "here" mean the guide as a whole
— the core and its reference documents.

The diagram count and the environment-variable coverage figures in the
`architecture/` entry are read by the `prose figures` preflight in
`tests/battery.sh`; reword those sentences only together with their rows.

---

- `architecture/DIAGRAM_LESSONS.md` — **read it before changing any diagram, in
  any of the three sets**: which file is each set's source, the standards a change
  keeps (text fit included, O188), how width is estimated and measured, the fix
  order for a spill, and the traps already paid for
- `architecture/` — illustrated architecture reference: eleven theme-aware
  SVG diagrams (`diagrams/`), the same as PDF (`pdf/`), and `index.html`
  which inlines them and documents every layer plus **all 82**
  `UNDERCROFT_*` variables the engine honours — **65** written out in
  full across the env table's 61 rows, plus **17** siblings abbreviated
  to a suffix inside the row that owns them (`UNDERCROFT_ORCH_ADDR ·
  _DB · _KEY · _ADMIN_TOKEN · …` is one row; `_TOKENIZER` and `_NAME`
  appear once per model role), which is why grepping the page for full
  names undercounts it by exactly those 17.
  **This paragraph claimed "72 of the 81", "8 abbreviated" and "NINE
  absent" between 2026-08-14 and 2026-08-17, and all three were wrong**
  — ROADMAP **O43**. O38 rewrote a CORRECT line ("all 81", "17
  abbreviated") into a false one and asserted, confidently and in bold,
  that both halves of the original had been wrong. They had not. The
  page was never changed by O38 at all: `git log -- architecture/
  index.html` runs O24 → O20 → O14 → O30 → O32 and then straight to
  2026-08-17, so nothing about its coverage moved in round five.
  **What went wrong is a counting method that could not SEE what it was
  counting.** A bare `<code>_SUFFIX</code>` only tells you which
  variable it means once you attribute it to the ROW it sits in: `_NAME`
  in the ONNX row means `UNDERCROFT_ONNX_NAME` and says nothing about
  `UNDERCROFT_COLBERT_NAME`, which is abbreviated in its own row one
  line below. Count suffixes globally and you credit the wrong
  variables; count only full names and you miss all 17. O38 recognised
  eight of the abbreviations and read the other nine — the six
  `UNDERCROFT_ORCH_*` sharing one row, and the three `_NAME` — as
  absent, then wrote a scoping rationale explaining why they *ought* to
  be absent, which is the most expensive kind of wrong: a wrong
  measurement dressed in a reason. **This figure is now GATED** by the
  `prose figures` preflight, row-scoped, so it is counted rather than
  argued about.
  (77/62/58 until `UNDERCROFT_ORCH_ENGINE_CA` — the CA
  pin for the orchestrator→engine hop, which had no transport policy at
  all until the post-1.0.0 drift audit; 79/64/60 since
  `UNDERCROFT_OTLP_CA`, the pin for the traces hop, which had none
  either and whose exporter could not do TLS at all. Those historical
  figures are left as the record of what was believed at the time.)
  Count the truth,
  never a number in prose:
  `grep -rhoE '"UNDERCROFT_[A-Z0-9_]+"' crates/ | sort -u` over every
  crate except `undercroft-bench`, whose `UNDERCROFT_VS_*`/`UNDERCROFT_TEST_*`
  belong to the harness rather than the engine.
  **`diagrams/` is the only source; `pdf/` and
  the inlined copies are both DERIVED, and `build.sh` regenerates both
  — edit an SVG, re-run it, never hand-edit an inlined copy.** It also
  re-derives every `<h3>` id and the whole sidebar from the sections.
  **This sentence used to end "and fails if a heading and a rail entry
  disagree", and that was FALSE — measured, not argued (ROADMAP M14).**
  The old check stamped a fresh id onto every `<h3>`, collected those same
  ids, built the rail from them, substituted it in, and only THEN re-read
  the ids and the rail refs out of that same rewritten document. Both sides
  came from one list built in one pass, so it could not disagree; its
  protection was the regeneration silently fixing the problem, never the
  check. Proven by running the pre-M14 script's own bytes on a tree with a
  hand-added `<h3>`: **exit 0**, index.html silently rewritten, the heading
  stamped and given a manufactured rail entry. It also wrote the file
  BEFORE comparing, so a firing gate left it already mutated, and it had no
  premise probe — with zero sections both sets are empty and it passed
  having examined nothing.
  **`sh build.sh --check` is the verify half**: it derives everything in
  memory and fails if what is on disk differs, writing nothing at all. It
  runs as the `arch-check` compose service — a stock python image, no build,
  and a READ-ONLY mount so "writes nothing" is enforced rather than claimed
  — in the battery and as a CI matrix leg. Before M14 **nothing invoked this
  script**: no suite, no CI job, no compose service, every mention in the
  tree being prose telling a human to remember. Scope stated: `--check`
  verifies `index.html` and PDF COVERAGE in both directions, never PDF
  bytes, which are not a stable comparison target. librsvg
  has no CSS-variable support, so the PDF pass flattens each `var()` to
  its light fallback; it also needs `fonts-noto-core`/`-cjk` or Thai,
  Han, Kana and Devanagari render as tofu boxes — a defect the browser
  hides and only a rendered PDF page shows. The inline pass **strips
  each diagram's dark media query**: inlined, it sets `--d-*` on the
  `svg`, which beats the `:root` values, so the diagram would follow the
  SYSTEM theme while the page follows its manual toggle. `build.sh`
  fails if an inlined copy still carries one. The page shows **one
  section at a time** behind a sidebar, enabled by script (`body.paged`)
  so that with JS off every section stays visible and the document still
  reads end to end
- `architecture/platform-views/` — an **illustrative parallel set** of twenty-two
  self-contained HTML diagrams (surfaces, crate map, write path, retrieval
  stack, containment/keys, admission, lifecycle, agent session, deployment,
  capability matrix, integrity chain — and, since O105 on 2026-09-04, audit
  namespaces, key rotation, verify/repair/backup, the transport policy,
  forgetting, the three egress paths, the read choke point, the verification
  pipeline, configuration classes and the storage layout) in the product's own dark palette,
  colour tokens taken from `website/landing/index.html` (verified 2026-08-30:
  same hex values under renamed variables). **The TYPOGRAPHY was never the
  product's**, and that is worth knowing because the sentence above implies
  otherwise: the set shipped on Geist + Instrument Serif from a Google Fonts
  CDN, faces that appear in NO other file in this tree — the landing page and
  the whole vendored set are IBM Plex + GFS Didot. So "vendor them, as O2 did"
  was the wrong repair; it would have added three families the product does
  not use, for an unpublished directory. They were **system stacks**, matching
  the governed `architecture/index.html` beside them (ROADMAP O78), until the
  maintainer ruled on 2026-09-15 that **no proprietary font is named anywhere
  in the tree** (O189). Every font list, in both diagram sets, the consoles,
  the site and the brand assets, now names only openly licensed faces:
  `"DejaVu Sans", "Noto Sans", sans-serif`, `"DejaVu Sans Mono", monospace`
  and `"DejaVu Serif", "Noto Serif", serif`, or the IBM Plex and GFS Didot the
  site vendors. No font file is shipped for this, and the `fonts are openly
  licensed` preflight holds the rule.
  **`diagrams/` remains the authority** — this set is a second description of
  the same system. **Its published COUNTS are gated** since 2026-08-31 (ROADMAP
  O74, ruled *depend on the diagrams, they represent the facts we have now*):
  a `platform-views` block in the `prose figures` preflight joins MCP tools,
  MCP writes, `/v1` routes, CLI operations, the crate count; since the
  2026-09-14 drift sweep, the set's own diagram count and
  `20-verification-pipeline.html`'s process figures (host-side preflights,
  Docker suites, CI jobs, suites-matrix legs, the jobs the CI verdict needs,
  release targets per variant, release variants, binary archives and
  multi-arch images, each read wherever the set repeats it); and — since
  O155 — the `ENGINE_ENV_VARS` cross-tab on both axes to the tree, both arms
  probed.
  **O155 is what that last row cost to learn**: the decision tree published
  `Protects · 24` for five days after O121 moved `UNDERCROFT_RERANKER`, because
  a figure outside this table is bound by attention exactly like the prose two
  sentences down. Only ONE cell of the cross-tab is published — `Protects` ∩
  `Opaque`, the population of `PREFLIGHT_EXEMPT` — because the four totals plus
  81 leave the table short by exactly one number, and the two parenthetical
  splits it replaces were spelled identically (`(N protect, M tune)`) in both
  boxes, so no pattern could tell them apart. A figure a gate cannot address is
  a figure that rots. It lives in `tests/battery.sh` and NOT in `check.py`
  because `arch-check` mounts `./architecture` alone, read-only — that checker
  physically cannot see `crates/` and so cannot know what the truth is.
  **What is still bound by attention alone is PROSE**: a relational claim moves
  no count, so a figure gate cannot see it. That is not hypothetical — the
  deployment diagram's `<desc>` said `/ui` sat behind the palace bearer when
  `http.rs` serves it in FRONT of that gate, and the falsehood was in the text
  a screen-reader user gets while the visible label was correct. So a change to
  the engine must still move both sets or they disagree.
  **That sentence was not followed by the unit it was written for, and the
  drift it predicts arrived within four days (ROADMAP O105)**: O94 added the
  seventh verify leg and the integrity view kept saying six; a code-vs-diagram
  audit on 2026-09-04 also found a `store → llm` edge no manifest has in the
  crate map, a backup described as a signed recipient-sealed bundle in the
  lifecycle view, three wrong cells in the capability matrix, and the subkey
  count wrong in two of three key diagrams — none of it visible to the figure
  gate, because none of it is a count. The audit is the mechanism, and it has
  to be RUN: after any change to the engine, read every diagram that names
  the thing changed, in all three sets. `index.html` here is the entry point and
  `check.py` is the gate, run by the same `arch-check` service (one service,
  one CI leg): inventory counted in BOTH directions against `index.html`,
  the accessible-SVG contract, **offline assets with NO exception**, LF
  endings, a 9-node /
  2-accent budget, and the geometry rules a renderer would otherwise be needed
  to catch — no diagonal connector, none passing behind a non-endpoint box, no
  label mask painted over by a later node — and, since O188, **every `<text>`
  fits the box that holds it**. It exists because the geometry arms read rects
  and lines and never a text's width: 113 lines spilled out of their boxes
  under a green gate, seen by the maintainer on the rendered page. Since O189
  the width comes from `architecture/textfit/textfit.py`, the ONE fit
  implementation both diagram sets share. It reads a per-glyph advance table
  generated from the openly licensed faces the ruling names: the per-glyph
  maximum of DejaVu and Noto over two Noto releases, Debian's and notofonts'
  monthly release 23.7.1, Arabic priced by positional form, and the fallback
  faces a renderer really uses. **Every font file is pinned by sha256** in
  `architecture/textfit/fonts.tsv`, because a version string is not an
  identity (Debian's and Alpine's DejaVu 2.37 are different files), and
  `textfit/pins.py` fails `arch-check` when the table's header and its pins
  disagree. What the table cannot price it refuses: a line a shaper can
  recompose (O194), a character some modelled reader draws with no face — the
  readers are `textfit/readers.py`, ONE model the generator and the
  calibration share (O189, panel 2) — an unassigned codepoint in the CJK
  blocks, and any run on a Python whose Unicode version is not the table's.
  CJK is priced at 1.05 em, one em plus the largest default-on kern the
  declared CJK faces' own tables carry. The 4-unit padding is its declared
  error budget, which the table's own kerning can in principle exceed (O196),
  and it is
  calibrated in headless Chromium with every face EMBEDDED from the pinned
  files (`architecture/textfit/calibrate/`) — the image's digest pins the
  shaper and never pinned the fonts, which an unversioned `apk add` had
  supplied. A newer Noto is not covered yet (O193). It replaced
  two flat estimates that failed: 0.56 em flagged 83 lines and missed 3 real
  spills, and 0.60 em was called a monospace bound while DejaVu Sans Mono
  advances 0.60205. One font environment is not "fits": the Windows pane
  found 4 spills where DejaVu found 22. It carries a **premise probe**: the
  geometry checks must fail on a known-bad fixture before any clean result is
  believed. **`rx` is the discriminator between a node and a zone** (6 vs 8) —
  a first version treated every large stroked rect as a node and reported 96
  breaches across a set whose exemplar had already been verified by eye, which
  is the calibration rule in one line: *a check that flags the artifact you
  confirmed with your own eyes is wrong about the check*
- `docs/diagrams/` — the fourteen **Mermaid-sourced** SVGs of the manual, and
  they are DERIVED: the canonical sources are the fenced `mermaid` blocks in
  `docs/architecture.md`, `docs/security.md`, `docs/MULTI_TENANCY.md`,
  `docs/integrations.md`, `docs/RETRIEVAL_SCALING.md`,
  `website/src/observability.md` and `website/src/runbook.md`; `src/*.mmd`
  are extracted copies and the SVGs are rendered from those with the pinned
  `minlag/mermaid-cli:10.9.1` image (its README carries the recipe; on Docker
  Desktop add `--user root`, or the mount is not writable). **Nothing derives
  or checks this directory**, and on 2026-09-04 four of the fourteen had
  drifted from their own canonical blocks — a tool count two releases stale,
  a missing crate, a missing scope stage, three runbook labels — while the
  canonical blocks themselves carried a phantom `fingerprint` key and an
  orchestrator "no crate dependency" claim that its manifest contradicts
  (ROADMAP O105). The book renders the Mermaid inline and never shows the
  SVGs, so the drift was invisible everywhere it could be seen. A Mermaid
  semicolon ends a statement, which is how one edit failed to render.
- `website/` — GitHub Pages: `landing/index.html` (custom landing) + mdBook docs
  under `src/`. **`build-site.sh` is the ONE assembly**, run by both
  `pages.yml` and `docker compose run --rm site`; the two used to carry
  their own `cp` lines, so the local preview could not exercise the
  deployed layout — which is the only place the cross-directory paths
  resolve at all. Landing goes to the root and the book to `/docs`, so
  the manual's skin reaches the fonts via `../../assets/fonts/` and the
  404's links resolve only under `book.toml`'s `site-url`
  (`/undercroft/docs/`; unset, mdBook built them as if the book were at
  the domain root, so the one page a lost visitor sees was the one page
  with no stylesheet). **The three font families are vendored**, under
  `landing/assets/fonts/` with their OFL texts — regenerate with
  `tools/vendor-fonts.sh`, which is run BY HAND and never by the build,
  since a build step that fetched fonts would defeat the point. It passes
  every `unicode-range` through unchanged rather than hand-authoring the
  `@font-face` blocks, which is how a vendoring pass silently drops a
  script. **Only the subsets rendered text uses are shipped** — `latin`,
  `greek`, `cyrillic`; the other four are 357 KB nothing needs — and that
  is MEASURED over rendered `.html` only, because a scan that includes the
  vendored scripts finds all seven (`mermaid.min.js` carries Unicode parser
  tables, `mark.min.js` a diacritic map: data inside a script, never glyphs
  a browser paints). `build-site.sh` fails if the assembled site references
  a font CDN at all, and fails if rendered text needs a dropped subset —
  that second check was born broken (a shell-built regex class, `sed` ate
  the backslashes, `2>/dev/null` ate perl's death) and reported a clean
  result having scanned nothing, which is why it now **probes itself
  against a range that must match before its zero-results are believed**.
  The probe then also caught that the site image carries `perl-base`, with
  neither `File::Find` nor `PerlIO`
- `docs/AGENTS.md` — the scenario-driven agent implementation guide
  (published as docs/agents.html); its tool/route/env reference must be
  kept in sync when the MCP surface, `/v1` routes, or `UNDERCROFT_*`
  variables change. **`/v1` is described by TWO documents** — this one's §10
  and `docs/remote-server.md` — and keeping only one is what O45 was: O14
  added a route, updated §10, and left the other reference claiming "All 35
  routes, counted against `route()` … rather than remembered". Both are
  gated now, as SETS in both directions rather than counts, because a count
  passes when one route is swapped for another.
  **The count is gated too, SEPARATELY, and the gap between those two
  sentences was real for as long as only the first existed.** Comparing sets
  is the right choice and its cost is that the SENTENCE introducing the list
  — *"All N routes, counted against `route()` … rather than remembered"* — is
  not part of what the set comparison examines. It said 36 while the list
  under it held 37, from M17 (which added `POST …/repair` to the list and not
  to the sentence) until 2026-08-21, and the gate was green throughout,
  correctly. Generalise it: **a number in prose beside a gated list is the
  un-gated part of a gated claim, and it is the part that rots** — when a
  gate deliberately measures something other than a count, ask what the count
  is doing while nobody watches it.
  **A full-name scan of any reference in this repo UNDERCOUNTS, and the
  undercount reads as a documentation gap.** Every reference here groups
  families into one row and abbreviates the siblings to a suffix —
  `` `undercroft_list_wings` / `_list_rooms` / `_get_taxonomy` `` in the tool
  table, `UNDERCROFT_ORCH_ADDR · _DB · _KEY` on the architecture page,
  "`_KEY` carries a bearer, `_DIM` overrides the dimension" in
  `docs/EMBEDDERS.md`. Three separate sweeps have now "found" phantom gaps
  this way, including O38, which shipped its miscount as a correction. Match
  the suffix form too, or you are measuring the notation rather than the
  coverage
