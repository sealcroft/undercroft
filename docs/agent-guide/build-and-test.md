# Agent guide — build and test

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the guide's full Build & test
command block — with every suite's PUBLISHED figure and the served embedder's
TLS recipe — and how `tests/battery.sh` works: the battery, its host-side
preflights, `--preflight-only` and `--no-preflight`, the shared readers, line
endings, and the local LLM. Read it when you run the battery or a suite, when
a test or check count moves, or when you add a suite or a preflight.

It was moved here unchanged when the guide was split (ROADMAP O433,
2026-10-12), and it governs over any one-line statement of the same rule in
the core. In the moved text, "this file" and "here" mean the guide as a whole
— the core and its reference documents.

**The figures live here and nowhere else in the guide.** The `(N checks)` and
`(N run, M ignored)` figures in the command block below and its cargo totals
are the battery's `FIGURES_DOC`, read by `tests/battery.sh` and by
`tests/house-figures.sh`; the host-side preflight count is read by a `prose
figures` row; and the battery refuses a core that republishes a suite figure.
Where the moved text says a figure is `CLAUDE.md`'s, it means this document
since O433: update a figure HERE when a count moves.

---

```bash
docker compose run --rm test          # cargo unit + integration tests (1425 run,
                                      # 17 #[ignore]d = 1442 compiled. Counted from
                                      # a battery run at the INTEGRATED tree,
                                      # never inherited and never from one
                                      # agent's own slice — a fleet member wrote
                                      # 556 here from its own worktree, which was
                                      # 551 plus the five tests it had added and
                                      # blind to the forty-five its seven
                                      # neighbours were adding in parallel.
                                      # **Do NOT sum the `test result:` lines of
                                      # the log**, which is what this line said
                                      # until 2026-08-11: `docker compose run`
                                      # SOMETIMES replays the tail of the
                                      # container's stream, leaving `.battery/
                                      # test.log` with a duplicated block
                                      # (visible as a `test result:` with no
                                      # `Running`/`Doc-tests` header above it),
                                      # and summing such a file gives 1016/8 for
                                      # a run that executed 694/4. INTERMITTENT —
                                      # two batteries the same hour on the same
                                      # tree produced one duplicated log and one
                                      # clean one, which is worse than a constant
                                      # error: nobody re-derives a number that
                                      # looked right last time. Count the target
                                      # HEADERS and let each result consume one —
                                      # 20 targets, 12 binaries + 8 doc-tests —
                                      # and treat an orphan as a PREMISE FAILURE,
                                      # since it is the only visible symptom of
                                      # the replay. **`tests/battery.sh` DOES
                                      # this now (O15, closed 2026-08-12)**: its
                                      # `test_summary` counts headers against
                                      # results and prints a loud PREMISE FAILURE
                                      # naming the orphan count, so a replayed
                                      # tail is reported rather than absorbed.
                                      # **COUNT, never pair by adjacency (O107,
                                      # closed 2026-09-04)**: CI's runner merges
                                      # cargo's stderr headers into the stdout
                                      # stream by timestamp, and the next target's
                                      # header landed mid-line ABOVE the previous
                                      # target's result — a GREEN suite read as
                                      # one orphan and the battery went red.
                                      # Anchoring the header anywhere in the line
                                      # (the filed fix) reproduces that failure
                                      # verbatim; only counting outstanding
                                      # headers survives the reordering, and it
                                      # also names a target that never reported.
                                      # A red `suite (test)` whose log ends
                                      # `exit 0` is never a reason to edit a
                                      # figure. It stays
                                      # informational — the script decides on EXIT
                                      # CODES, never on parsed output, by design —
                                      # but the number it prints is now the one
                                      # you can copy here. A host-side preflight
                                      # exercises the reader itself on a synthetic
                                      # replayed log, because the summary had
                                      # never been checked by anything.
                                      # **That reader covered ONE suite of eight
                                      # until O27 (closed 2026-08-13)**: it pairs
                                      # cargo's `Running`/`Doc-tests` headers, and
                                      # no other suite emits them. The seven shell
                                      # suites print ONE summary line as their
                                      # final statement, so more than one in a log
                                      # is definitive rather than heuristic — and
                                      # a real `backends-e2e` log carried TWO with
                                      # different numbers (56/1 and 54/3) while
                                      # the `| tail -1` that read it printed the
                                      # second and said nothing about the first.
                                      # `suite_summary` counts them and names a
                                      # doubled log; same three premise arms.
                                      # **And the figure itself is now GATED
                                      # (O28, closed 2026-08-13)**: every
                                      # published per-suite count is compared
                                      # to what the run measured, reported as
                                      # a doc-drift verdict distinct from a
                                      # suite failure, and the battery fails.
                                      # A `published figures` preflight counts
                                      # the landing tiles against
                                      # `PUBLISHED_FIGURES` both ways, checks
                                      # the derived ones against the tree, and
                                      # requires every surface republishing a
                                      # count to agree. So the numbers in this
                                      # block are checked rather than
                                      # remembered — do not hand-edit one to
                                      # silence the gate; it is measuring the
                                      # suite, not this comment.
                                      # The 17 ignored are 3 measurements needing
                                      # testdata/*_50k.txt, one in lib.rs, and four
                                      # in anchor_tests.rs (ROADMAP O254, O257): the
                                      # multi-process gate's child entry point,
                                      # which returns at once unless a parent
                                      # names a role, the P2 latency
                                      # measurement, and O257's two probes (the
                                      # exclusive hold across a commit, and the
                                      # rotation's hold time), each run by name,
                                      # and three in snapshot_tests.rs (ROADMAP
                                      # O253's soak, cost and -wal measurements,
                                      # also run by name), and two in
                                      # backup_tests.rs (ROADMAP O256's soak and
                                      # its cost at ~10^5, run by name), and one in
                                      # restore_tests.rs (ROADMAP O268's cost at
                                      # ~10^5, run by name), and one in
                                      # open_race_tests.rs (ROADMAP O279's
                                      # cross-process child entry, which returns
                                      # at once unless its parent names a root),
                                      # and one in legacy_rename_tests.rs
                                      # (ROADMAP O281's cross-process holder,
                                      # which returns at once unless its parent
                                      # names a role), and one in
                                      # delete_tests.rs (ROADMAP O291's
                                      # cross-process holder, the same shape).
                                      # Run the first
                                      # four with `cargo test --release -- --ignored`:
                                      # 3 pass, and `measure_relation_promiscuity`
                                      # FAILS on missing data, not on logic — it
                                      # wants ar/el/he word lists and the tree
                                      # carries ar/de/en, so two are simply absent
                                      # (hermitdave/FrequencyWords, MIT, gitignored
                                      # corpora). Verified 2026-08-10. It is not a
                                      # measurement anyone can reproduce here until
                                      # those two lists are fetched; the
                                      # onnx crate's own ignored test is outside
                                      # default-members and never in this count,
                                      # and neither is `model_e2e` (O157): it lives in
                                      # a default member, but its required-features
                                      # skip it on the unnamed invocation this runs)
docker compose run --rm lint          # rustfmt --check + clippy -D warnings, on the
                                      # default build AND the TELEMETRY build of
                                      # both feature-bearing binaries (O84).
                                      # `--all-targets` alone lints default
                                      # members with DEFAULT features, so
                                      # everything behind
                                      # `#[cfg(feature = "telemetry")]` was linted
                                      # by nothing and two dead wrappers survived
                                      # from O20 and O25. Publishes no check count
                                      # deliberately. **`#![warn(missing_docs)]` is
                                      # on in the eight default-member library
                                      # crates (O110, 2026-09-07)** (the two
                                      # model crates carry none, and nothing
                                      # lints them: O153), so this refuses a public
                                      # item with no doc — 372 of them when it
                                      # went on, three times the 113 O99's scanner
                                      # counted, because struct fields and enum
                                      # variants are items and the scanner saw
                                      # neither, and 12 of the 372 only under the
                                      # TELEMETRY build, which the default check
                                      # never compiles. It sees an orphan, never a doc on
                                      # the wrong item; that half stays by eye
docker compose run --rm e2e           # e2e UI/UX suite against the release binary (878 checks)
docker compose run --rm orchestrator-e2e  # two engines + orchestrator (201 checks)
docker compose run --rm e2e-telemetry # telemetry build + /metrics gating (62 checks)
docker compose run --rm backends-e2e  # five live vector DBs over TLS (157 checks; weaviate
                                      # readiness gates on /v1/schema==200 — it
                                      # answers HTTP before its Raft leader exists)
bash tests/tls-pins.sh                # CA pins readable + both stacks start (32 checks).
                                      # Every shipped pin, read as the ENGINE's uid.
                                      # Host-side
                                      # because it DRIVES docker: it brings the real
                                      # Caddy terminators up and reads their volumes
                                      # as the ENGINE's uid, taken from the Dockerfile
                                      # rather than hardcoded so the two cannot drift.
                                      # It exists because `deploy/observability`
                                      # shipped UNSTARTABLE for two releases — the
                                      # engine pinned a path inside Caddy's PKI tree,
                                      # which is root:0600 inside 0700 dirs because it
                                      # holds the CA private key, and the engine runs
                                      # as uid 10001. Nothing caught it because
                                      # nothing ever brought a terminator up:
                                      # `obs-config` validates CONFIG FILES and starts
                                      # no container, and a config can be flawless for
                                      # a stack that cannot boot. It also asserts the
                                      # CA PRIVATE key stays unreadable, because the
                                      # obvious wrong fix (chmod the tree) would
                                      # otherwise pass. **Since ROADMAP O63 it also
                                      # brings the WHOLE deployment up** — all 11
                                      # services under a throwaway project — and
                                      # asserts the engine answers /healthz against
                                      # its real pin, every long-running service is
                                      # running, and PROMETHEUS ACTUALLY SCRAPES it.
                                      # That last one is the only assertion spanning
                                      # the whole stack. Measured 3m04s end to end
                                      # with a warm image cache; the engine build is
                                      # the entire cost. Ports are the catch: the file
                                      # publishes six and a developer machine holds
                                      # most of them, so every mapping is rewritten to
                                      # an EPHEMERAL host port with `!override` —
                                      # Compose MERGES list keys, so an override that
                                      # merely restates `ports:` appends and the
                                      # collision survives untouched.
                                      # **Since ROADMAP O172 it boots the TEAM-SERVER
                                      # recipe as well**, on the default-features
                                      # engine that recipe ships, and drives the index
                                      # path through the running server: config check,
                                      # /v1 index status, a push, a search through the
                                      # mirror, verify. A boot check alone is blind
                                      # there — the recipe's cleartext Qdrant URL and
                                      # an unreadable pin both left /healthz at 200,
                                      # measured by counterfactual. The whole suite
                                      # measured 104 s locally with both engine images
                                      # already built; a cold CI run pays two builds,
                                      # measured 12 min 2 s against 5 min 15 s with one.
                                      # **Since ROADMAP O199** it also replaces the
                                      # observability engine over a volume whose
                                      # `vaults/default` is a regular file, and requires
                                      # init's own error in the log, not serve-http's
docker compose run --rm arch-check    # TWO verifications, one service: the
                                      # architecture reference is what
                                      # diagrams/ and its own headings derive
                                      # to, AND platform-views/check.py gates
                                      # the illustrative parallel set, which
                                      # has no build step so a checker is the
                                      # only thing keeping it honest.
                                      # No build, stock python, READ-ONLY
                                      # mount — `--check` must write nothing,
                                      # and the old gate's real defect was
                                      # writing index.html BEFORE comparing.
                                      # Publishes no check count deliberately,
                                      # like `lint` and `onnx-build`: it has
                                      # three verification stages rather than
                                      # a countable population, and inventing
                                      # a metric to satisfy a gate is how a
                                      # figure stops meaning anything
docker compose run --rm obs-config    # the observability CONFIG suite (17 checks):
                                      # promtool check/test rules + amtool
                                      # check-config at the versions the stack
                                      # deploys, plus the join between them —
                                      # every label alertmanager's `equal:` names
                                      # must be one the alerts actually emit. It
                                      # equalled on a label NOTHING emitted, and
                                      # alertmanager reads absent-on-both as
                                      # equal, so one critical silenced every
                                      # warning fleet-wide. The only symptom of
                                      # that class is an alert that never
                                      # arrives, which is why it needs a suite
docker compose run --rm onnx-build    # build the tract backend + RUN its tests (14 run, 3 ignored)
                                      # `cargo build` does not compile #[cfg(test)] code,
                                      # so until O134a these tests were compiled by
                                      # NOTHING — three of the four that existed returned
                                      # early and reported PASSED. The figure is READ and
                                      # COMPARED since O134b; O134a deliberately published
                                      # none, because a count nothing gates is the part
                                      # that rots. `(N run, M ignored)` carries BOTH
                                      # numbers: three tests here are #[ignore]d, and a
                                      # single `run` figure cannot tell a deleted test
                                      # from a newly ignored one
docker compose run --rm ort-build     # the ORT backend + the CLI model join (18 run, 1 ignored), built
                                      # --features onnx,ort. No cargo test target runs in two legs,
                                      # or a figure is counted twice: this leg tests
                                      # undercroft-embed-ort and runs ONE target from outside it,
                                      # the CLI's `model_e2e` (ROADMAP O157), whose required-features
                                      # no other leg enables and which `test` skips. The figure spans both.
                                      # NOT a clippy run: this line once claimed it
                                      # lint-checked ort-gated code (corrected
                                      # 2026-09-12), and the leg has never run clippy —
                                      # it runs `cargo build` and, since O134a,
                                      # `cargo test`. Neither model
                                      # crate is linted by anything — filed, O153
docker compose run --rm site          # build AND ASSEMBLE the site (7 checks) via
                                      # website/build-site.sh — the same script
                                      # pages.yml deploys with, because the
                                      # checks that matter are true only of the
                                      # assembled tree: the manual's skin reaches
                                      # the fonts by a path that leaves the book
                                      # and re-enters the landing assets, and the
                                      # 404's links resolve only under site-url.
                                      # Fails if any page references a font CDN.
                                      # (mdbook pinned 0.5.4; mermaid via
                                      # vendored website/assets/mermaid.min.js;
                                      # fonts vendored under
                                      # website/landing/assets/fonts — regenerate
                                      # with website/tools/vendor-fonts.sh, which
                                      # is run BY HAND and never by the build)
docker build -t undercroft .           # runtime image

# A quantized text embedder on the compose network, CPU only — so a
# measurement is reproducible instead of depending on a desktop app on the
# host (which the bench container cannot reach anyway). Reached through
# the embeddings-tls terminator ONLY: the engine refuses cleartext http
# to any non-loopback host, no override. The client container mounts the
# terminator's CA volume and PINS the root:
docker compose up -d embeddings embeddings-tls
docker compose run --rm embed-tls-export  # publish the PUBLIC CA root readably
docker compose run --rm embed-pull    # one-time model fetch into a volume
#   then run cli/bench with (project-prefixed volume name — a bare
#   undercroft-embed-tls mounts a fresh empty volume silently. The
#   `undercroft_` prefix is TRUE because every compose file now DECLARES
#   `name:`; until 2026-08-10 none did, Compose derived the project from the
#   clone's DIRECTORY, and on the maintainer's machine this line named a
#   volume that did not exist — the silent-empty-mount failure the sentence
#   before it warns about):
#     -v undercroft_undercroft-embed-tls:/tls:ro
#     UNDERCROFT_EMBEDDER=http UNDERCROFT_EMBED_URL=https://embeddings-tls
#     UNDERCROFT_EMBED_CA=/tls/root.crt
#   The pin is the EXPORTED root, not the path inside Caddy's PKI tree.
#   Caddy writes that tree as root (cert 0600 inside 0700 dirs) because it
#   holds the CA private key, so uid 10001 cannot read it — and `cli`/`mcp`
#   build the RUNTIME stage, which runs as exactly that uid, while `bench`
#   builds the builder stage and runs as root. This recipe therefore worked
#   or failed depending on which service you picked (ROADMAP M9).
#     UNDERCROFT_EMBED_MODEL=nomic-embed-text
```

**Run the battery with `bash tests/battery.sh`** (all ten suites, or name a
subset). It exists because two mistakes on 2026-08-06 were the same defect —
a verdict taken from something other than the thing that decides it:
a summary built by piping `cargo test` through `awk` reported `failed=0` from
an EMPTY field, and `lint` was run locally *before* the last edit and reported
green while the battery failed on a lint introduced after it. So the script
never parses suite output to decide pass/fail — **the exit code is the
verdict** — and it runs every suite in one pass over one tree, which makes "I
ran it before the last edit" impossible rather than merely discouraged. It
also handles the `backends-e2e` reset and never pipes a suite (a
pipeline's status is its LAST command's, which is how `| grep` turns a failing
suite into a passing one). **That reset is NARROW, and it was not always** —
ROADMAP M12. It was a project-wide teardown carrying the volumes flag and no
`-p`/`-f`, so it resolved to `docker-compose.yml`'s declared project,
`undercroft`, which is the DEVELOPER'S OWN — and removed every named volume
that file declares. Three were pure collateral: `undercroft-models` (the
multi-GB weights of the four served embedders this project measures with),
`undercroft-data` (the compose palace, i.e. any mined corpus) and
`undercroft-embed-tls` (the embeddings CA that the pin recipe above mounts —
destroying it makes that recipe mount a fresh empty volume silently, which is
the failure the recipe's own warning describes). It needed none of them: the
four HTTP backends declare no `volumes:` key at all and pgvector's only mount
is a read-only cert, so their state is in ANONYMOUS volumes that
`rm -sfv <service>` takes. **This is M10's lesson one file over** — a private
compose project name does not scope a shared host resource — and the battery's
own teardown was the place it had not been applied. Gated by the
`destructive compose scope` preflight, which requires every compose teardown
in `tests/` to name the project it destroys; `tests/tls-pins.sh`'s two scoped
teardowns are the accepted shape. Logs land in `.battery/` (gitignored).
**`bash tests/battery.sh --preflight-only` runs the twenty-four host-side preflights
and no suite**, which is what CI invokes. They read the release tags since
O309: a `--depth 1` clone fetches them first, as CI's `preflight` job does. **A count the battery cannot trust is never compared to a published figure, and there are TWO ways to earn that (O97/O103): the suite EXITED NON-ZERO — `cargo test` aborts at the first failing target, so a numeric, replay-free count arrives over a fraction of them — or the reader disowned it with a `PREMISE FAILURE` marker. `count_untrustworthy` is the one place that question is answered, because it used to be answered twice and differently: the cargo arm guarded on the marker, the shell arm stripped it with a trailing `.*`, and neither looked at the exit code. It fails either way — a gate that cannot measure must not report clean — and the verdict names WHICH cause, because the message was written for a replay and told the reader to re-run a failure that was deterministic. (This sentence said "seven" while
the tree ran eight, and nothing could say so — and then "ten" while the tree
ran eleven, which the gate caught inside the very unit that caused it.
It caught the twelfth the same way, in the unit that added it.
**It is gated now** — ROADMAP
**O42** — by the `prose figures` preflight, which counts this number and
the other figures the doctrine states about the tree against what the tree
actually measures (the row count is printed by the preflight, never here). It caught its own arrival: adding that preflight made the
count ten while this sentence still said nine.) The script is the one thing that
runs on the host rather than in a container, and it has to be: it *drives*
Docker, and the preflights read `ROADMAP.md`, the compose files, `ci.yml` and
`git ls-files --eol` over the WHOLE tree — none of which any image carries.
Everything a preflight cannot do with git, bash 4.4 or later, GNU grep, sed
and xargs, coreutils' `sha256sum` and awk belongs in a container it launches,
not in a host interpreter — and Docker is required, since the preflights
launch containers of their own: a gate that needs Python on the host is a gate
that does not run on the next machine. That contract is also why a stock macOS
or Alpine host cannot run them, for reasons that are not awk (ROADMAP O314,
its ruling of 2026-10-06).
**And "awk" there means TWO awks (ROADMAP O314).** The preflights run under
whatever awk the host carries. On 2026-10-06 both hosts that ran them — the
maintainer's Git Bash and CI's runner — carried gawk, while eight comments in
`tests/battery.sh` said CI ran mawk and one unit skipped a mawk measurement on
that belief. CI's `preflight` job now runs them a second time under Debian 12's
mawk 1.3.4 20200120, the oldest awk the tree's own images run, brought in by
image digest and binary sha256 and asserted through the same PATH lookup, in a
step the last preflight requires to be exactly what it executes; and the
script records the exit status of every awk call its PREFLIGHT BLOCK makes
(not the post-run phase, not a child script), its last preflight failing on
any that did not succeed. That is the general detector for a reader that fails
OPEN: a mutation planted in one made mawk print `syntax error` while the gate
printed `ok`, and with the recorder in place the same plant fails the pass and
names the program. So a program here runs under both:
no three-argument `match()`, no `gensub`, no `IGNORECASE`, no interval
expression, and no exit status used as an answer. **No comment states what
CI's awk IS** — the step prints it, and a runner image moves.

**`--no-preflight` is the mirror image and it is what CI's SUITE legs use**
(ROADMAP M13). Every matrix leg and the `tls-pins` job run
`bash tests/battery.sh --no-preflight <suite>` rather than
`docker compose run` directly, so CI and a local battery execute the SAME
code — including the post-run comparison of each suite's MEASURED check count
against the figure `CLAUDE.md` publishes for it. That comparison needs a RUN
and therefore cannot be a preflight, so until M13 it ran nowhere on a pull
request and a leg dropping from 370 checks to 3 was green. The flag skips the
twenty-four preflights because the dedicated `preflight` job already runs them
(twice since O314, the second time under Debian 12's mawk). **The shared readers — `test_summary`, `suite_summary`,
`declare_suite_counts`, `suite_count` — are deliberately defined OUTSIDE the
skipped block**, and that is not tidiness: with them inside, `--no-preflight`
printed `command not found` twice and the battery still exited 0, the
comparison examining nothing while reporting exactly what a clean tree
reports.

**Line endings are enforced, in two scopes, because no image carries the whole
tree.** `.gitattributes` declares `* text=auto eol=lf` so a CRLF shell script
cannot break in the containers — and nothing checked it until scripted
text-mode edits on Windows converted eleven files and `tests/e2e.sh` died with
`$'\r': command not found` before a single check ran (it also made a 100-line
CLAUDE.md change show as 1,415 lines, which is how a real defect hides in an
unreadable diff). `crates/` is gated by
`no_source_file_has_crlf_line_endings` (complete inside every image, since the
test image COPYs that whole subtree — it also COPYs `deploy/`, deliberately
NOT in this gate's scope: that is YAML and JSON no shell executes, and a gate
widened to whatever happens to be in the image is a gate whose stated scope
has stopped matching its real one); everything else — `tests/`, `deploy/`,
`docs/`, `website/`, compose files — by the `tests/battery.sh` preflight, host-side,
via `git ls-files --eol` (git owns the concept, so ask git rather than
hand-rolling byte detection: three hand-rolled attempts each failed, twice as
a false negative and once declaring the whole repo corrupt — and its selector
is PROBED in both directions since O55, because it had no probe at all while
its own comment claimed the two failure modes were exercised). **Write files
in BINARY mode on this repo.** **And never quote `grep -c $'\r'` from this
harness's shell**: on 2026-09-04 it returned 0 on a known CRLF sample, so
every zero it had reported that day had measured nothing — a premise probe
is what caught it, and `git ls-files --eol` is the only reader worth citing.

**A local LLM is available for consultation** (maintainer's machine): LM Studio
on `http://localhost:1234/v1`, OpenAI-compatible, model id `deephat-v1-7b` — a
security-oriented model, with `qwen/qwen3.5-9b` and
`deepseek/deepseek-r1-0528-qwen3-8b` also loaded. Loopback, so the engine's own
transport policy permits it. Useful as a cheap second opinion on a security or
crypto decision. **Calibrate honestly**: asked about the U12 fingerprint
exposure it listed "unkeyed so they survive rotation" as a *low-risk factor*
and then recommended keying them — contradicting the constraint in the question
— and raised irrelevant points. Argue with it; never cite it as authority, and
verify anything it says against the code.
