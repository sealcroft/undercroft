# Agent guide — definition of done, in full

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the full text of items 2, 4
and 7 of the definition of done; the core states all seven, these three in one
line each. Read it when you write a test or a counterfactual, update a
governance surface or the house page, or add a renderer.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12), and it governs over any one-line statement of the same rule in
the core. In the moved text, "this file" and "here" mean the guide as a whole
— the core and its reference documents.

---

2. **A test that would have failed before the fix.** Assert the premise, so it
   cannot pass for the wrong reason. Several tests here carry an explicit
   counterfactual arm for exactly this.
   **And a passing battery is not evidence a test is DETERMINISTIC — only
   repetition is.** A retrieval test asserting the whole ranked id list over
   1,200 near-identical drawers passed several consecutive batteries and then
   went red on CI; run twelve times it measured 4 failures in 6. The tail of
   that list is not a property of the system: the PQ codebook trains on a
   KEYED sample (`sample_rank`, off a master key that is random per vault),
   so which rows train it differs per run and the ADC ordering moves at the
   margin. **Never assert an exact order over content that ties**; assert the
   one answer the query decisively matches, or a membership the geometry
   cannot move. And when a test touches PQ, FDE, the codebook or any keyed
   draw, **run it in a loop before believing a green** — the battery runs
   each test once, which for a coin flip is not a measurement.
   **And counterfactual the FIX, not only the defect.** A filing makes TWO
   claims — what is broken, and what to do about it — and only the first ever
   gets re-verified, because a remedy that matches an accurate description
   reads as done. ROADMAP M3 is the instance: its description was exact, and
   its prescribed fix ("report the same pair the CLI does") would have made a
   server re-announce one healed anchor window on every later call, forever,
   because the field it names is set at open and never cleared while a server
   caches its handle for its lifetime. The arm that caught it asserts the
   behaviour the FIX would break, which nothing in the filing asks for.
   Stated as this file requires of a new rule: applied backwards it
   reclassifies nothing and confirms nothing — the past fixes it could have
   examined were structural (a required argument, an inventory row) and had
   no alternative shape to get wrong. **One instance, untested by history,
   and this is its first application.**
   **And when a counterfactual fires on only SOME of your checks, the ones
   that stayed green are the finding** — they passed with the defect present,
   so they are measuring something else, and on a clean tree they read
   exactly like coverage. O82a is the worked example: six checks on the SSE
   route's failure reply, of which four drove a request with no bearer — which
   never reaches that route's error arm at all, because the palace bearer gate
   answers it several hundred lines earlier through a helper M43 had already
   fixed. Restoring the defect passed four of six, and the correct reading was
   not "mostly covered" but "four of these test a different gate". The rebuilt
   block drives an unknown VAULT, which authenticates at the door and fails
   inside `authorize`; the challenge check is kept, relabelled and scoped to
   what it does cover, because deleting it would lose a real assertion at a
   call site. So: **a partial counterfactual is a diagnostic, not a partial
   pass** — read every green in it as a claim that needs its own reason. This
   sharpens item 2's existing "cannot pass for the wrong reason" rather than
   adding a rule; applied backwards it reclassifies nothing, because no
   earlier counterfactual in this tree was ever run and found to fire
   partially. One instance, and it is this one.
4. **Every governance surface updated in the same unit**: CHANGELOG, CLAUDE.md,
   ROADMAP, **the three `.handover/` files and, when present,
   `NEXT_PROMPT.md`** (ignored by git, governance
   nonetheless — see session-end hygiene), **the HOUSE PAGE at
   `sealcroft.com` when a figure it publishes moves**, and whichever of
   docs/AGENTS.md, docs/THREAT_MODEL.md, README, architecture/index.html,
   website/ carry the claim you changed. A claim lives on every surface that
   states it, and an UNCOMMITTED surface is the one nobody notices going
   stale.
   **The house page is the surface this rule keeps failing on, because it is
   in ANOTHER REPOSITORY** (`sealcroft/sealcroft.github.io`, no CI of its
   own) and so is invisible to every in-repo gate and to `git status`. It
   published `656 tests` against a tree running 689, went unfixed for eleven
   days, and had widened to 765 before anything noticed — its sibling defect,
   the house serving cleartext, is what ROADMAP O37 calls "the most severe
   process failure". **It is not optional and not a nice-to-have: it moves
   with the unit that moves the number, exactly like CHANGELOG does.**
   It publishes FOUR figures and only one of them moves often — the test
   count, on nearly every unit that adds a test. The other three (MCP tools,
   the benchmark headline, `0 bytes phoned home`) move rarely or never.
   Dropping the volatile tile to remove that friction was PROPOSED and
   REJECTED by the maintainer: the page is the org's front door, and a front
   door that is quietly wrong is worse than one that costs a commit to keep
   right.
   **Do it with `bash tests/house-figures.sh --update`**, which reads the
   truth from this tree, patches only the tiles that moved, and pushes. Run
   it in the same unit, then verify the LIVE page rather than the commit —
   Pages takes a minute or two, and `--update` waits for it.
   **And run it BEFORE the push, not after.** "Same unit" is not enough,
   because `house-figures` is a CI job that reads the LIVE page: any push
   moving a published figure is red from the moment it lands until the page
   catches up, so pushing first does not risk a red window, it GUARANTEES
   one. Recovery is `--update`, verify live, then `gh run rerun <id>
   --failed` — and check the re-run PER JOB, since `CI verdict` fails
   alongside whatever it was waiting on and a run conclusion alone will not
   tell you which of them was the real one.
   Applied backwards, as a rule here must be: it reclassifies **exactly one**
   decision — the `M37` push on 2026-08-23, which went red for precisely this
   reason — and confirms the obligation above by making it precise rather
   than changing it. Every other unit that day moved landing-page figures the
   house does not publish, so none of them would have been caught. **One
   instance is the whole history this rule has**, and that is stated rather
   than implied: it is a sequencing rule earned from a single observed
   failure, not a pattern established across many.
7. **Count the renderers, not the surfaces.** The drift doctrine names four
   {CLI, MCP, `/v1`, orchestrator}, and that list is not the same as "everything
   that renders this struct". `ui.html` and the orchestrator console are
   `include_str!`'d `/v1` CLIENTS served at `GET /ui`: a new report field
   reaches their wire for free and stops dead. `VerifyReport` gained a leg on
   three gated surfaces and silently missed the fourth — and when `ui.html`
   was finally added to `parity.rs::HAND_PROJECTED`, the entry immediately
   found TWO legs it had never rendered (`orphan_labels`, `mirror_drift`),
   both of which drive the verdict tick it prints. Ask what else reads the
   struct before believing the gate covers it.
   **It happened again, to the struct this rule names first** (ROADMAP M5,
   2026-08-19). The `VerifyReport` row was added and the lesson stopped
   there, so `VaultStats` — the struct listed above as the FIRST one this
   drift bit — still had no `ui.html` row, and adding one found FOUR fields
   the console had never read, including `unhealed` and `read_only`, the two
   an operator opens a console to find. So the rule is not "add the console
   when you notice"; it is **one row per (struct, renderer) pair, and adding
   a row for one struct says nothing about the next**.
   Two things a gate cannot do for you here. It cannot tell you the page is
   STALE: `ui.html` is compiled in, so a release binary built before the edit
   serves the old console while every gate reads the new source — prove the
   binary carries the markup, then LOOK at the page. And it cannot tell you a
   renderer should be exempt: a fleet OVERVIEW is a summary by construction,
   so demanding every field there would enforce the wrong shape. Write that
   decision down; do not leave it as a missing row.
