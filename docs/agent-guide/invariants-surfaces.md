# Agent guide — surface and verification invariants

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the full text of the
invariants on a search's blind spot, a screen's scope, a capability missing
from one surface, the direction of a drift, and a struct that is not a
surface. Read it when your work adds or changes a capability on any surface, a
screen, an inventory gate, or a claim that something is absent.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12). PROPOSED with this split, for the maintainer's approval in its
pull request: this full text governs over any one-line statement of the same
rule in the core. In the moved text, "this file" and "here" mean the guide as
a whole — the core and its reference documents.

The CLI absence-partition figures in it are read by the `prose figures`
preflight in `tests/battery.sh`; reword that sentence only together with its
rows.

---

- **A search cannot verify its own blind spot. If a sweep matched a pattern,
  a checker built on that same pattern proves nothing.** The 2026-08-08 rename
  replaced three Latin-script spellings of the former name. Three separate
  verifiers then reported the tree clean — because all three searched for
  those same three strings. They agreed with each other by construction, and
  four whole classes sat untouched beneath the agreement:
  1. **A different script.** The former name also existed in Greek capitals,
     which share no byte with the Latin form. It was the first text on the
     landing page, a constant raining the old brand down the hero canvas, and
     the monogram on every documentation page.
  2. **A truncated root.** An identifier used the first five letters as a
     stem. The sweep matched whole words, so it survived — and it named the
     class created inside a user's *live* Weaviate instance.
  3. **An encoding.** A pinned test certificate carried the name inside
     base64-encoded DER, while the comment directly above it asserted the new
     one. A doc claim is not verification, restated as bytes.
  4. **The identity without the spelling.** A mythological epithet named the
     old project precisely and contained none of its letters. No string search
     of any kind could see it.
  5. **The name that is in no file at all** (found 2026-08-10, and it is the
     one that had branded every build artifact for two days). `docker-compose
     .yml` declared no `name:` key, so Compose derived the project name from
     the **DIRECTORY the clone sits in** — still the former name — and
     prefixed every container, image, volume and network with it:
     `<former>-site`, `<former>-lint`, `<former>_default`. It appears in zero
     tracked bytes, so a content scan of all 367 files reports six clean
     classes and is *correct*, and useless. It also silently falsified a doc:
     this file's own volume-mount recipe named an `undercroft_`-prefixed
     volume that did not exist on the maintainer's machine, one sentence
     after warning that a wrong volume name mounts a fresh empty volume with
     no error. **A derived identifier is a name too.** Ask what the tooling
     computes from the environment — directory names, hostnames, image tags,
     registry paths, cache keys — not only what the files say. Gated by the
     compose-project-name preflight in `tests/battery.sh`, counted both ways.
  One layer down, the same shape: **17 historical PDF blobs passed a clean
  `grep`** while still carrying the name inside Flate-compressed content
  streams — invisible to a byte scan, plainly visible to git's own
  `astextplain` textconv and to anyone who opened the file. The maintainer
  found the Greek by *looking at the rendered page*, which is the check nobody
  had run.
  So: any claim that a string is gone must **decompress rather than grep**,
  must cover **non-Latin scripts and truncated roots**, must hunt the
  **identity** as well as the spelling, and must ask what the TOOLING DERIVES
  from the environment. `tests/no-trace/verify.py` covers the **seven** classes
  a file-content scan can reach and fails on any hit. It is **tracked and run by
  a preflight, in a container** since O10 — it was gitignored and hand-run
  before, so a fresh clone did not carry it and nothing invoked it, which is
  how a comment quoting the former name shipped under a green battery. Its
  needles are assembled from fragments so it scans ITSELF clean rather than
  being excluded by path, and a premise probe fires every pattern on a
  known-positive (and requires silence on clean control text) before any zero
  is believed. **The seventh class is a Flate-compressed PDF stream** (O26,
  closed 2026-08-13): the walk inflates every `stream`/`endstream` payload
  whose dictionary declares `/FlateDecode` and runs the same needles over the
  result, counts what it could NOT inflate, and treats a PDF that declares
  `FlateDecode` while yielding no readable stream as a premise failure rather
  than a clean file.
  **How that gap was described is the lesson, and it is this file's own first
  rule turned on a filed item.** O26, this guide, and the commit that created
  the scanner all said it *skipped* `.pdf` via `SKIP_BIN`. The hand-run
  original does. The tracked port dropped `pdf` from that list and nobody read
  the line — so all eleven tracked PDFs were opened in TEXT mode, scanned for
  needles that cannot survive DEFLATE, and **counted in `files scanned`**.
  That is worse than the skip it was filed as: an admitted skip is at least
  visible in the arithmetic, while false coverage reads as a clean result.
  Two general shapes follow. **A gap inherited from a filing is a claim about
  the code and gets the same verification as any other** — three surfaces
  agreed here and all three were describing a different file. And **a coverage
  count must count what was EXAMINED, not what was listed**: the same line
  reported `len(paths)`, skipped entries included, which over-reported by 80.
  Class 5 above is
  **outside its reach by construction** and needs a different mechanism —
  which is the compose preflight, not a wider regex. Do not "extend" the
  verifier to cover it; extend the QUESTION.
  The general rule outlives this rename: **a negative result is only
  as good as the widest question you thought to ask, so "none found" is a
  claim about the method, never about the tree.** Note that writing this
  lesson down is itself the trap — the first draft quoted every string it
  warned about and reintroduced the name into the guide. Describe the class,
  never the token.
- **A SCREEN'S SCOPE MUST MATCH THE SCOPE OF THE READ IT GUARDS, and a screen
  that names the fields it ignores reads as though it covered them.**
  `screen_kg_object` ran the detector on `object` alone and consumed
  `subject`/`predicate` only to build its error message — so the signature
  said "record" while the body said "field", and its doc comment claimed
  "this is the screen on it". The read it stands in front of is
  record-scoped: `kg_query_entity` returns `Triple` and serde serializes it
  WHOLE, so a poisoned subject reached the next session verbatim beside a
  clean object, with `validate_name` the only guard — and that admits any
  128-byte string free of control characters and path separators, which every
  `IMPERATIVE_MARKERS` phrase fits. The scope had been chosen by which field
  someone thought of as content. So: **ask what the READ returns, not what
  the writer considers content**, and make the covered set an INVENTORY
  checked in both directions — a table-driven test proving every listed field
  is screened, plus an assertion inside the screen proving no call site can
  name a field the inventory omits, which is the half a test cannot do
  (O17). **And then the inventory's own NAME chose a second scope, which is
  the same defect one level up (O29, 2026-08-13).** It was
  `KG_SCREENED_FIELDS`, so `tunnels.label` — agent-written through
  `undercroft_create_tunnel`, read back verbatim through
  `undercroft_list_tunnels` — was outside the question it asked, for as long
  as it existed. It is `admission::SCREENED_FIELDS` now, keyed by
  `(owner, field)`, because a key is what lets one inventory span tables and
  a graph-shaped name is what hid the gap. The rule for a row is **an agent
  can write it and an agent can read it back** — never "it is content", which
  is the judgement that scoped O17's own screen to `object`.
  **The sibling sweep is part of the fix, and its WORDING is load-bearing.**
  O29 asked "which other such fields exist *outside `drawers` and the
  graph*?" and the answer was partly INSIDE `drawers`: an agent-chosen WING
  name reaches `taxonomy`, `closets` and `stats` unscreened (filed O32,
  measured). A scoping phrase in a filed question decides what the answer can
  contain, exactly as a scoping phrase in a gate does.
- **A capability missing from one surface is a boundary or a drift, and
  which one has to be written down.** A 14-agent audit of CLI vs MCP vs
  `/v1` found **65 confirmed drifts** — a capability present on one
  surface and missing, weaker, or differently named on another — of which
  **55 failed silently**: a declared configuration that never took effect,
  a screen a route walked past, an exclusion enforced on one read path and
  not its neighbour. Every one was born the same way, someone adding a
  capability to two surfaces and forgetting the third. Two mechanisms
  close them, and new work must use whichever fits. Where the drift is a
  CLASS, a **choke point**: screening at `write_drawer` behind a required
  `Screen`, the read-only gate in front of dispatch, one search-declaration
  parse in `cli/search.rs`, one diversion classifier in
  `admission::save_event`. Where it is arithmetic, an **inventory the code
  is counted against in both directions** (`cli/parity.rs`) — a tool
  without a line fails the build and a line without a tool fails it too,
  which a hand-maintained doc table cannot do.
  **"Against THE CODE" is the load-bearing half of that sentence, and two
  inventories agreeing with each other is not it** (ROADMAP O80). The
  audit-namespace gate iterated `MINTED` and `AGENT_FENCED_NAMESPACES` and
  compared them to one another while its own docstring claimed it *"counts
  the emitted prefixes"* — so it was both-directional, green, and
  structurally unable to see the one thing it existed for: a namespace the
  code mints and neither list names. Two lists are a closed system; they can
  be perfectly consistent and jointly wrong. Ask, of any inventory gate,
  *which side of this comparison is derived from the code* — and if the
  answer is neither, it is measuring agreement rather than truth. This is
  *ask what a gate can SEE* with the second list mistaken for the tree.
  Applied backwards it reclassifies exactly one gate, the one it was written
  for, and CONFIRMS the rest — `parity.rs` derives its universe from
  `MCP_TOOLS`, `SURFACE_ABSENCES` from `main.rs`'s dispatch, `ReadOp::ALL`
  from audit rows a driver really wrote, `GAUGE_NAMES` from the emit sites,
  `READ_SCHEMA` from the ADD COLUMN lists. One instance, and it is the
  existing rule being SHARPENED rather than a new one: the tree already said
  "against the code" and this is what the phrase costs when it is read
  loosely. Deliberate absences are
  entries in `OPERATOR_ONLY` carrying their reason (an agent must not rule
  on the queue that exists to contain it, nor assign the trust class that
  decides what it may retrieve), asserted by the same test as the parity,
  so the two can never disagree about what MCP is allowed to reach.
  **The CLI axis had no such inventory at all until M16**, so every CLI-only
  capability was an unrecorded gap by construction — measured, **74** CLI
  operations of which `parity.rs` named **17** (76 since O245 added the two
  witness operations). `SURFACE_ABSENCES` +
  `SURFACE_COMPLETE` now PARTITION it (43 rows over 43 anchors — 36
  `Boundary`, 7 `Structural`, 0 `Drift` — plus 33 reachable everywhere = 74.
  This parenthesis said 62/59/15 until 2026-09-05, figures from before the 21
  `Drift` rows closed and left the table, and before that said **63** rows
  until 2026-08-30, the 63rd `Absence::` being a COMMENT — the identical
  miscount O68 records having already caught one variant down: it corrected
  `Drift` 22 → 21 and left the TOTAL, one line up in the same sentence, still
  comment-inflated. The `= 74` was never wrong, because it derives from
  ANCHORS plus `SURFACE_COMPLETE` and not from rows — which is exactly why
  nothing noticed. **Gated since O100**: the `prose figures` preflight counts
  the rows, the anchors and `SURFACE_COMPLETE` against `parity.rs`), keyed on
  the `main.rs` dispatch anchor and on
  `(anchor, absent_from)` because a ruling differs per surface — `repair` is
  a boundary on MCP and a drift on `/v1`. **`Absence::Unruled` is a real
  verdict, not a smaller boundary**: where the absence is a PRODUCT decision
  the code does not settle, the row says nobody has decided and must cite the
  entry where it is filed, because an inventory whose reasons were guessed
  reads as ruled while being fiction — worse than none, since it stops the
  next reader looking. Scope, stated: the gate derives its universe from
  `main.rs`, so it is both-directional over the CLI axis only; an absence FROM
  the CLI of something present only on `/v1` (vault delete, the SSE stream) is
  filed in O66 rather than caught.
- **A drift has a DIRECTION, and it is decided by provenance — never by
  which side is cheaper to edit.** Finding that the code and the documents
  disagree is half the work; the other half is deciding which one is wrong,
  and that question has an answer rather than a preference. Ask the three
  places intent is recorded — `ROADMAP.md`, this file's doctrine, and
  `architecture/index.html` — **which one INTRODUCED the thing**:
  - **A new capability** (the ROADMAP files it, or the code adds something
    the documents never promised) → the **code leads**; update every surface
    that describes it, including the ones you did not grep for.
  - **A fix to something already promised** → the **documents lead**, and
    the code must be made to keep the promise. Narrowing a promise to match
    an implementation is how a gap silently becomes the design.
  **The discriminator is breadth, and it is nearly decisive: when a claim is
  consistent across every surface INCLUDING the doctrine, the prior is that
  the CODE is wrong.** Several documents do not independently invent the same
  promise. The worked example is O24 — six surfaces said
  `undercroft config check` validates every `UNDERCROFT_*` declaration, three
  of them were not validated, and the first fix narrowed all six. It was
  backwards, and three things in the tree said so: `ENGINE_ENV_VARS` already
  CONTAINS the six `UNDERCROFT_ORCH_*` entries, `UNDERCROFT_ORCH_ENGINE_CA`
  is already validated by that very command, and the three unvalidated parses
  are pure string→value — so *"never linked by the engine"*, which forbids a
  crate dependency, was used to license something it does not cover. Reading
  the inventory the command already iterates was all it took, and no gate
  caught it; the maintainer did.
  The converse case is real and has its own tell: a claim asserted in ONE
  place, recently, with nothing else agreeing, is a claim to TEST rather than
  a promise to keep — the versioning doctrine is that example, and history
  refuted it. Breadth plus the doctrine means keep; narrow and new means
  question.
  Applied backwards, as a new RULE here must be: it agrees with #40 (a
  detector shipped, the docs went stale, the code led), #54 and #55 (doc
  defects), #18 and O22 (the opaque-payload rule promised the refusal, the
  code was fixed to keep it) and round-four #8 (`undercroft-net`'s own doc
  claimed to be the only implementation; the code was made true). It
  reclassifies exactly one decision — O24's first draft — which is the one it
  was written for. Tested against roughly six decisions, all from this
  campaign; that is its whole history and it is stated rather than implied.
- **A struct is not a surface.** `/v1` serializes report structs whole, so a
  new field reaches the wire for free; the CLI prints named fields one by one
  and silently does not. This has bitten `VaultStats` and then
  `RotationReport` — the second time inside the very unit that existed to fix
  forgotten sweeps. `parity.rs::HAND_PROJECTED` +
  `every_hand_projected_report_field_reaches_the_cli` now fails when a field
  has no projection, in both directions. Add a hand-projected report to that
  list when you create one.
