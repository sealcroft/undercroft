# Agent guide — session-end hygiene and ROADMAP rules

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the context-budget rule with
its measured history, open threads as work, the handover rules, and every
ROADMAP heading and placement rule the `ROADMAP headings` preflight holds.
Read it before you edit `ROADMAP.md` or the handover, and when a session nears
its context budget.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12). PROPOSED with this split, for the maintainer's approval in its
pull request: this full text governs over any one-line statement of the same
rule in the core. In the moved text, "this file" and "here" mean the guide as
a whole — the core and its reference documents.

---

**The working cycle, and the context-budget rule that bounds it.** Work is
**read → fix → test → commit**, one unit at a time, repeating until the queue
is done; the full Docker battery runs at every unit and a real corpus is
loaded at every unit (definition of done, items 5 and 6). **When the context
window reaches roughly 90%, STOP TAKING NEW UNITS and spend what is left
updating every governance surface**
— and **MEASURE that 90%, never estimate it: `bash
tests/context-check.sh`** — **and pass it the session id from the
system prompt's transcript path** (ROADMAP O104: with no argument it guessed
at the project AND the session, measured a different project, and reported 8%
for a session that was 84% full; and O106: the session-id form itself REFUSED on Git Bash until 2026-09-04, because the root derivation put a newline in the slug, while the full-path form always worked — the O104 self-test drove only the latter. **The derivation is a battery preflight since 2026-09-05**: `--check-derivation` is the transcript-free half of the self-test, and it must resolve THIS checkout's slug on a single line, compared against the basename git reports rather than against itself; a copy of the script outside the checkout and a copy with a two-line root both refuse, probed on every run). This rule was stated for weeks with no way to
evaluate it, so it was applied by feel and applied WRONG, repeatedly and in
one direction: on 2026-08-18 the agent announced it was near the budget at a
measured **54%**, having assumed a 200,000-token window when the real one is
**1,000,000** — every estimate out by ~2.7×, always toward stopping early and
handing over work that could have been finished. A threshold nobody can
measure is not a rule, it is a mood; this file's own first rule — *count the
truth, never a number in prose* — applies to the agent's own state as much as
to the tree. The reader takes the live session transcript's `usage` records
(`input + cache_creation + cache_read`), which is MEASURED; only the window
is declared, it is labelled as such in the output, and it fails loudly rather
than printing 0% when it cannot read a transcript, because a broken reader
and an empty context look identical downstream — CHANGELOG, ROADMAP, this file, whichever
docs carry the claim you changed, and the three `.handover/` files (and
`NEXT_PROMPT.md`) with their first block naming `HEAD` — except
`AUDIT_CONTINUATION.md`, whose blocks track audit rounds rather than commits.

That is not tidiness, it is arithmetic. A session that spends its last tokens
half-landing one more fix leaves the next session a tree it cannot trust and a
handover describing a different one; a session that spends them on the
handover leaves an accurate map and one clearly-stated next action. The second
is worth more than the fix, because the fix survives being deferred and the
map does not.

- **Open threads written down AS WORK**: every residual, gap and deferred
  decision recorded in ROADMAP with its reason, the shape of its fix, and a
  gate. A gap is a gap, never dressed up as a principled refusal — and
  **"accepted" is not a resting state**. Nothing broken or half-baked stays a
  gap; if it is genuinely not worth fixing, that is a decision with an
  argument, written down, not a line item that quietly never moves.
  **A sentence inside a finished entry is not a filing (ROADMAP O171).** It
  cannot be picked, cited or shut: O9's body still read "filed rather than
  fixed" after O142 had done the work. So anything a surface calls filed, or
  an open question, gets its own id heading — under `Open` for work, under
  its target release once that is fixed, under `Unversioned` for a pure
  decision — and the comment that cites it names that id. A residual stated
  WITH its argument for remaining is a decision and needs no heading. The
  `ROADMAP headings` preflight holds the code-comment half: a `//` block in
  `crates/` that says filed, or open question, must name an entry whose
  heading is still open. It cannot see a citation of the wrong open entry, a
  synonym, or a filing written in a ROADMAP body or in this file.
  **Relations between open entries live in the entries too (O169):** a line
  beginning with the bold `Relations:` marker names the partner, and the same
  preflight requires the partner to be open and to name this entry back.
  There is no separate dependency map; the last one went stale within five
  days. Applied backwards, the filing rule CONFIRMS M15's O62–O65, O142's lift
  of O9, O157's split out of O134b, O136 to O143 and O111 to O112, and
  reclassifies the seven items O171 named plus one id-less `2.0.0` item; no
  stated residual moves. Its history is that one application.
- **The handover is a GOVERNANCE SURFACE that is deliberately NOT committed,
  and both halves of that are binding.**
  `.handover/` is gitignored on purpose (`.gitignore:44`, *"local only — never
  committed"*) and **must stay that way**: the directory holds 1.6 GB of
  working material including the 269 MB pre-rename history bundle, and none of
  it belongs in the repo. Do not "fix" this by un-ignoring it or by adding
  negation patterns.
  It is nonetheless a governance surface with the same standing as `ROADMAP`
  or `CHANGELOG`: **kept current in the same unit as the work, and
  drift-checked like everything else.** Three files carry that weight —
  `SESSION_START.md` (session state; its top block is current),
  `NEXT_SESSION.md` (project state) and `AUDIT_CONTINUATION.md` (audit
  state) — plus, when present, `NEXT_PROMPT.md`, the prompt a new session is
  actually handed. A handover describing a tree that no longer exists is
  worse than none, because the next session acts on it.
  **This paragraph replaces one that said the opposite.** It read "it ships in
  the same commit as the work it describes" — a rule the repo forbids, written
  without checking whether it was satisfiable. The commit that introduced it
  (`a60b342`) is titled "handover: the session-start prompt…" and its diffstat
  is three files, none of them the handover: `git add -A` skips ignored paths
  SILENTLY, the output said "3 files changed", and nobody read which three.
  A doctrine that cannot be obeyed is not a high standard, it is a false
  claim — and this one was asserted in the same commit that added the
  verification doctrine.
  **What the handover-freshness preflight in `tests/battery.sh` sees, and
  what it does not (ROADMAP O165).** On a clean tree, the first dated
  paragraph of `SESSION_START.md`, the first dated row of `NEXT_SESSION.md`
  and, when it exists, `NEXT_PROMPT.md` (anywhere in it) must name HEAD's
  commit;
  `AUDIT_CONTINUATION.md` is checked for existence only. Whether those words
  are TRUE is not examined — a sha pasted into a stale sentence passes — nor
  is any text below the first block or row, and a dirty tree prints `skip`
  rather than a verdict. The free-standing `handover-head:` marker it used to
  compare is retired: the handover's own instructions re-pointed it without
  the text it vouched for.
- **Every ROADMAP entry states its own status in its HEADING**, matching its
  body. `O2`'s heading read "the site loads three font families from Google"
  while its own body said CLOSED, and a handover was nearly written around an
  item that did not exist — the "a heading is the most expensive artifact this
  project produces" rule, on the file that plans the work. Gated in
  `tests/battery.sh`'s preflight, host-side beside the line-ending check,
  because no image carries `ROADMAP.md` so no `cargo test` can read it.
  **And a closed entry lives under the release that shipped it** (O101,
  2026-09-06): the same preflight refuses a `CLOSED` entry under
  `## Unversioned` or `## Open`, whose headers promise no releasable work and
  open work only — seventy closed engine entries sat under those headers for
  weeks. The closed entries that BELONG under `Unversioned` — decisions,
  external actions and closures by measurement — are `UNVERSIONED_CLOSED`,
  an inventory with reasons counted
  both ways, because the scanner cannot judge releasability.
  **And a closed entry sits only where its status is READABLE (O305,
  2026-10-05).** The two arms above were a deny-list, so O291 — closed
  2026-09-29 — sat under `## 1.6.1 — released 2026-09-22` with every preflight
  green, and a closed entry under `## 2.0.0`, `Beyond 2.0.0` or `Shipped`
  printed nothing. Placement is an allowlist now: a release whose status, the
  token right after the dash, reads `released <yyyy-mm-dd>` — and then no date
  in the entry's HEADING may be later, the latest heading date deciding and
  never a body date, because bodies carry records corrected beside — or
  `unreleased`, or `Open` and `Unversioned` under their own arms; anything else
  is refused, and every closed entry re-sectioned by O161's defect below is
  refused by a message that names O161, ahead of O161's own arm — the
  `Unversioned` roster now defers to such a row, where it used to fire first
  and tell the editor to delete a correct exemption. Two writing constraints follow: a
  release heading's status word comes RIGHT after its dash (a description may
  follow the date — the 1.2.0 release prep wrote one, and an end-anchored
  reader refused its 27 entries), and a correction made after a release goes in
  the body or a new entry, never as a later date in a closed heading. The scan
  runs under `LC_ALL=C`, defensively: the arm takes every offset from an ASCII
  pattern, but an offset past the em dash is one unit in a UTF-8 gawk and three
  bytes in mawk, so a change of that shape would read a date under gawk and
  garbage under mawk — which CI's second preflight pass runs since O314, while
  this sentence said "in CI" until then; a premise asserts the pin, since no
  fixture can see it go.
  What a date cannot see is O309's, below: a
  closure is dated when it is BUILT, so an entry merged under a release cut
  while its branch was open passes, and only the tag's own `ROADMAP.md` can
  say what shipped. Applied backwards over all 222 first-parent versions of
  the file, the arm refuses `66dafb3`'s O291, one pre-convention 1.2.0
  heading, six versions holding O161's real defect and one early
  `## OPEN after 1.0.0`, and confirms every other version.
  **And what a release shipped is read from its TAG (O309, 2026-10-05).** The
  preflight's last arm reads each `v*` tag's own `ROADMAP.md` — one
  `for-each-ref`, one `cat-file --batch`, under `GIT_NO_LAZY_FETCH=1`, never a
  history walk, because ancestry is silently false in a depth-1 clone — and
  refuses an entry under a released section that does not read finished now,
  or did not ship finished under a byte-identical heading at its own tag; one
  finished at an EARLIER release (a lower version under a released section,
  any tag at all under an unreleased one, which has shipped in none); a
  release date that is not its tag's creator day; an untagged released section
  other than the one release in its window (the newest, above every tag, at the
  workspace version, its date not yet passed by a readable HEAD day); a tagged
  section not marked released; a lightweight `v*` tag, or one that is not a
  plain `v<n>.<n>.<n>` (suffixes are refused until ruled, as `version
  surfaces` refuses a suffixed workspace version); and a clone with no release
  tags. Its reader probe runs isolated from the caller's `GIT_*` environment:
  inherited from a worktree hook, it committed into the real repository
  (found by the independent review). Three writing constraints follow: a released HEADING never
  changes (a correction goes in the body, O305's rule enforced; a scrub needs a
  `RELEASED_RECORDS` row of the heading kind), a release tag is ANNOTATED
  (`git tag -a`), and a record that is not work under a released section is
  listed in `RELEASED_RECORDS` with its reason. Applied backwards they describe
  what the tree already does — 205 of 205 released headings are byte-identical
  at their tags, 13 of 13 tags are annotated, two records exist — and over all
  223 first-parent versions the arm refuses only `66dafb3`'s O291, enforcing
  O101's placement "by the release window, against the tag times" with the tags
  themselves. **The preflights now need the release tags**: a plain `git clone`
  has them; CI's `preflight` job fetches them in a step of its own, because the
  checkout's `fetch-tags: true` at depth 1 fetches none (measured); a checkout
  older than the newest release fails this arm, so run it with
  `--no-preflight`. What it cannot see — a stale pull request under
  `strict: false`, a tag moved without a ruleset — is O313's, escalated.
  **An entry's SUBSECTIONS are `####`, never `##` (O161, 2026-09-13).** The
  scanner takes its enclosing section from any `^## ` line, so a level-2
  heading written inside an entry re-sections the file from there on: every
  LATER entry is attributed to `## Gates` instead of `## Open`, and both
  placement arms stop firing for all of them — silently, which is what a clean
  tree looks like (until O305: a CLOSED entry so re-sectioned is refused now,
  by the allowlist above, and only an open one still goes unseen before
  O161's own arm runs). It also truncates the entry's own body at that line, which
  blinded `body-closed-heading-open` and let one entry satisfy
  `closure-without-evidence` on the word "gate" in an unrelated sentence.
  `####` was already the file's convention in nine places; fourteen headings in
  three entries had drifted. A preflight arm now refuses any `^## ` that is not
  a section heading — release sections by semver SHAPE, the seven prose
  sections by a roster counted both ways — and it lives OUTSIDE the awk
  deliberately, because that program sits in a single-quoted shell string where
  one apostrophe ends the string and kills the script. **The structural
  argument outranks the parser one**: a heading level is a containment claim,
  so `## Gates` declared itself a sibling of `## 1.5.2 — released`, and an
  agent grepping `^## ` as an index into a 14,696-line memory artifact got it
  back as a peer of the release sections.
  Two writing constraints follow, both learned by tripping them. An OPEN
  entry's body may not contain the bare status token in capitals: the
  `body-closed-heading-open` arm matches it anywhere, even inside an
  identifier, and O162's ruling panel KEPT that bluntness — a narrowed match
  measurably silenced glued markers, and a loud false positive beats a silent
  miss — so describe such an identifier rather than naming it; the refusal
  names the line. And a heading-shaped line at levels 2–6 inside a fenced
  block is REFUSED (O162): every reader of this file is line-based — the
  scanner, O161's arm, the prose figures, the ruled O169 and O171 arms, an
  agent's grep — so ONE detector runs before all of them and each stays
  line-based. Only a column-0 three-backtick fence is accepted; to quote a
  heading-shaped line, indent it one space. **O162 also refuted O161 on one
  point: a release SHAPE is not enough** — an unfenced release-shaped heading
  inside an entry re-sectioned the file with exit 0 — so the level-2 headings
  are held to their one order, every version once.
