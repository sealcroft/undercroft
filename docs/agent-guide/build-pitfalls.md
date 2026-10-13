# Agent guide — build and edit pitfalls

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the ways a run here has
silently used the wrong binary or a stale artifact, and the traps of scripted
edits, counterfactuals and unbounded waits — each with the defect that taught
it. Read it before a scripted edit or a counterfactual, when a build result
contradicts the source, or when you poll for a result.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12). Where this full text and the core's one-line form of the same
rule differ, this full text governs, and the divergence is a defect, fixed in
the unit that finds it (ruled by the maintainer, 2026-10-12). In the moved
text, "this file" and "here" mean the guide as a whole — the core and its
reference documents.

Where the moved text points outside this document: "the `--build` hazard
above", in its first paragraph, is the core's **Always pass `--build`**
paragraph, in its Build & test section.

---

**The `undercroft-target` volume can serve a STALE artifact.** `cargo` reused a
release rlib of `undercroft-vault` that predated a new method, and the resulting
"no method named …" error looked exactly like a source bug for three attempts
while the same tree compiled clean elsewhere. `cargo clean --release -p <crate>`
is the fix. Same family as the `--build` hazard above, one level down: **when an
error contradicts the source you are reading, suspect a cached artifact before
suspecting the code.**

**Two more ways a run silently uses the wrong binary** (both fired in one
session; together they put a pre-change binary under a measurement whose
matching numbers then proved nothing):
- **Git Bash mangles container paths in `-e` and `-w` values** (MSYS path
  conversion): `-e CARGO_TARGET_DIR=/build` became a `C:\…` path inside the
  container, cargo failed with "path segment contains separator", and the
  failure hid behind a `| grep … ; echo` pipeline that exited 0 — so the
  volume kept serving its old binary. Prefix every docker command that
  carries `-v`/`-e`/`-w` container paths with `MSYS_NO_PATHCONV=1`, and
  never let a pipeline's tail mask an exit code you depend on.
- **`docker compose build` can serve a STALE BUILD CONTEXT** (Docker
  Desktop file-share cache): the image's `/src` was hours older than the
  host file and a rebuild did not refresh it, while a *mounted* build
  (`docker run -v <repo>:/src`) saw the current bytes. When compose output
  looks impossibly cached, verify `/src` content in-container
  (`grep -c <new-symbol> …`) and fall back to a mounted build.
**Parallel agents sharing one `CARGO_TARGET_DIR` give a FALSE GREEN.** Every
worktree mounts at `/src`, so cargo's fingerprints collide in a shared
`undercroft-target` volume: a build "finished in 5.18s" replaying *another
worktree's* warnings, having compiled nothing of its own. Give each parallel
agent a private target dir (`CARGO_TARGET_DIR=/build/<agent>`), and re-verify
every agent's build claim in the integrated tree rather than trusting it —
found when a fix fleet's own report flagged it, which is the only reason it
was not believed.

**Union is the right conflict resolution for CHANGELOG bullets and the WRONG
one for code.** Applying it blindly across a 7-way merge spliced away closing
braces in three `.rs` files. Resolve code conflicts on their merits; reserve
union for additive prose.

**A SCRIPTED EDIT IS A CHANGE YOU HAVE NOT READ.** Four defects in one
session, all the same root — a `python`/`sed` edit that matched its anchor and
damaged what was around it — and the expensive one was invisible to every
test by construction:

- **An offset computed before a length-changing replace.** `j = s.index(...)`,
  then a `replace()` that shifts everything, then `s[:i] + block + s[j:]` — the
  block landed in the MIDDLE of a string literal. **Never carry an index
  across a mutation.** Re-find after every change, or edit by line index.
- **An anchor matched on a `fn` line with an attribute above it.** The
  insertion took that `#[test]`, so a live parity gate silently became dead
  code — and no test could report it, because the test was the thing that
  stopped running. Only `clippy`'s "never used" caught it. **Read what is
  ADJACENT to the anchor**: an attribute, a doc comment and a closing brace
  all belong to something.
- **Escape handling.** A Python octal escape wrote a raw `\x01` into a shell
  script, and `bash -n` parsed it happily; doubled backslashes collapsed two
  Rust string literals onto one line with 30-space runs, and **rustfmt does
  not reformat string literals**, so no gate sees that class. Prefer raw
  strings and line-index edits; **byte-scan** anything a script wrote
  (control bytes, CRLF, space runs inside literals).
- **`2>/dev/null` on a formatter.** It swallowed the failure, and the drift
  surfaced a battery later. **Never redirect a checker's stderr** — that is
  the documented "a checker that cannot run reports the same thing as a clean
  tree" trap, one level up.
- **A SCRIPTED COUNTERFACTUAL THAT FAILS TO APPLY STILL PRINTS A PASS**, and
  the pass is the thing you will read. A revert-run-restore pipeline whose
  anchor no longer matches leaves the file untouched, so the test that follows
  exercises the FIXED tree and reports `test result: ok` — which is exactly
  what a working counterfactual would print if the fix were absent, i.e. the
  one output that cannot distinguish the two cases. Observed 2026-08-14: the
  `assert a in s` fired and said `anchor`, and the pipeline ran the test
  anyway, one line below. **The assert is necessary and not sufficient — the
  pipeline must STOP.** Chain the run behind the edit (`&&`), or check the
  edit landed before believing anything after it. Same family as the
  `2>/dev/null` on a formatter, one level up: a step that failed and a step
  that succeeded must not produce the same transcript.
- **A REGEX SWEEP DAMAGES WHAT IT WAS NOT AIMED AT, and "I verified the
  instances" does not cover the ones the pattern also matches.** Same day: a
  pass to collapse rustfmt-mangled space runs inside message literals — six
  instances read and verified first — matched 58 lines across 13 files, and
  ate the deliberate column padding in `config check`'s output
  (`"  ok      {name}"`, `"  warn    {name}"`), which is alignment rather than
  damage. Caught only by reading the diff. **A sweep is a hypothesis about
  every line it will touch, not about the lines you sampled**; read the whole
  diff or fix the instances by hand. Where the class is genuinely tree-wide,
  the answer is a GATE plus per-instance fixes, never a blind pattern.
- **A counterfactual must exercise the ARTIFACT, not a copy of it.** The
  ROADMAP-heading gate was "proved" by typing a correct `awk` inline in the
  shell while the version written to `tests/battery.sh` carried a literal
  newline inside a string literal. awk died, printed nothing, and the check
  reported `ok` — a broken scanner and a clean tree are indistinguishable, so
  it shipped. Source the code out of the file, or invoke the command, and
  give every scanner a **premise probe** that fails when it examined nothing.

**A WAIT THAT CANNOT TIME OUT IS NOT A WAIT, IT IS A HANG.** On 2026-08-18
two background shells polled `until grep -q 'BATTERY OK\|BATTERY FAILED'
<log>; do sleep 30; done` for nearly three hours. The sentinel never arrived
because the battery had aborted under `set -u` *before* printing its verdict
line — so the loop was waiting on a string that could not appear, and had no
bound that would make it say so. Nothing was lost (they held no locks and
wrote nothing) but nothing was learned either, and the real failure was
already visible in the log.

Two rules follow, and they are the premise-probe discipline applied to the
agent's own tooling rather than to a gate. **Bound every wait** — an
iteration cap and a loud failure when it expires, because "not finished yet"
and "will never finish" are indistinguishable to an unbounded poller, which
is this file's oldest lesson wearing different clothes. And **watch the
PROCESS, not a sentinel in a file it may never write**: a backgrounded
command already notifies on exit, so polling its output for a magic string
adds a failure mode the notification does not have.

**So: compile after EVERY structural edit, before making the next one.**
Batching them hides which edit broke what, and this session batched them four
times. The cost of a rebuild is seconds; the cost of a disabled gate is a
release.

**Before trusting any run of a freshly built binary, prove the binary is
fresh**: probe it for a symbol only the new code has (`--help | grep -c
<new-flag>`). A stale binary passes every old test by construction.

**The specific way that happens here, because it produced a FALSE DEFECT
REPORT on 2026-08-11:** an ad-hoc container that mounts the target volume
(`-v undercroft_undercroft-target:/build`) but forgets
`-e CARGO_TARGET_DIR=/build` builds into `/src/target` while the script runs
`/build/release/<binary>` — so `cargo build` succeeds, prints `Finished`, and
the run exercises a binary from before the change. The session concluded a
fix "worked in the store's tests but not through the CLI", wrote it up as an
unresolved CLI-vs-store discrepancy, and stopped the unit. There was no
discrepancy. Worse, the `cargo clean --release -p …` run used to TEST the
stale-artifact hypothesis had the same missing flag, so it changed nothing
and appeared to refute it. The same omission separately made an orchestrator
arm print "binary absent — skipped", which reads as benign.
**So: always pair the volume mount with `CARGO_TARGET_DIR`, give every
ad-hoc arm a premise probe that fails when the binary lacks the new
behaviour, and never let "absent" be a skip.** One missing flag produced one
invented defect, one silent skip, and a corpus measurement that proved
nothing (subjects were unscreened in the binary that "passed" it).
