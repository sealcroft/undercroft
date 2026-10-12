# Agent guide — benchmarks and research runs

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the Layout entries for
`crates/undercroft-bench` and its instruments, `docs/AMB_REPLICATION.md`, and
the gitignored `docs/research/` working sets. Read it when you run or change a
benchmark, a measurement instrument, or a published benchmark figure.

It was moved here unchanged when the guide was split (ROADMAP O433,
2026-10-12), and it governs over any one-line statement of the same rule in
the core. In the moved text, "this file" and "here" mean the guide as a whole
— the core and its reference documents.

---

- `crates/undercroft-bench` — LongMemEval/LoCoMo/ConvoMem/MemBench/model-eval
  harnesses (`--features onnx` for model rows; `--skip`/`--limit` sharding),
  plus synthetic instruments: `synth`, `wingscale` (per-wing tier: scoped vs
  unscoped R@5 + steady-state ms/q, ONE ingest per corpus with `--floors`
  iterated in-process, per-pass warm-up reported separately — folding a
  one-time index build into a per-query average manufactured a 15× "effect"
  in this instrument's own first version), `pqscale` (the unscoped tier AT
  SCALE: one cumulative sealed vault grown 131k→1M, R@5 and ms/q per
  candidate pool — and, since O23, `--offsets`: a page of five at each deep
  start, timed beside the single deeper call whose tail it must equal byte
  for byte under one pinned clock, a start past the corpus required EMPTY,
  and the run FAILS on any page that is not that slice — so a deep offset's
  cost is measured while its answer stays pinned), `scopescale` (scoped
  recall AT SCALE: a fixed 8192-drawer probe wing holding a fixed 512-row
  probe room,
  corpus grown around them to each checkpoint, four passes — unscoped
  control / wing / room / wing+room — the instrument any scoped-recall
  claim must cite), `xlingual` (cross-lingual R@1/R@5 per language pair
  over operator-supplied TSV pairs — parallel corpora carry their own
  licenses and never enter the repo; the embedder env is the printed
  variable, hash being the measured-zero baseline; a verbatim-recovery
  sanity column guards the harness itself), and `screenfp` (the C3.3
  detector gate: the tier-1 screen over a clean LoCoMo-shaped corpus —
  per-class trips, flagged fraction, fixture-score distribution for
  threshold headroom, plus the true-positive arm where every committed
  fixture must trip; deterministic, no vault, no model). **The LoCoMo
  harness names its floor (O76, 2026-09-06)**: every question whose gold
  turns no hit in the pool covers is printed as a `LOCOMO_MISS` line with
  its conversation, question, category and turn ids, so a claim about the
  first-stage floor is judged on ids rather than on a bucket count that can
  absorb one question leaving and another arriving. Measured that way, the
  "residual one percent" was eleven named questions, three of them gold no
  text matcher can reach, and a served bge-m3 reached four of the fifteen
- `docs/AMB_REPLICATION.md` — how to run the Agent Memory Benchmark's
  own protocol against this engine with **Claude subagents in the two
  model roles and no external LLM API**. Deliberately carries **no AMB
  prompt text and no AMB code** — their clone ships no LICENSE, so it is
  all-rights-reserved by default and must never enter this repo or its
  history; the procedure asks the operator for their clone path and maps
  prompts, schemas and cached splits from there. Covers the five judged
  datasets and warns they are not interchangeable (`personamem` is MCQ
  with **no judge at all**, `beam` is a continuous rubric whose
  `build_judge_prompt` is never called, `locomo` alone skips a category);
  a **sixth**, `sdebench`, is cached and deliberately out of scope — it is
  `task_type: "coding"`, scored by pytest, with no answer model and no
  judge. Its traps section is load-bearing: `task_type: "open"` needs a
  reasoning+answer schema, `query_timestamp` uses a LEXICOGRAPHIC
  session sort, and `k` defaults to **10** — at k=30 that was 34% of a
  whole conversation and the resulting 94.4% was uninterpretable.
  **LoCoMo's category ints are `1` MULTI-HOP and `4` SINGLE-HOP** (2
  temporal, 3 open-domain, 5 adversarial). This line said the opposite
  until 2026-08-22, having copied the CLONE's `_CATEGORY_NAMES`, which
  rotates three of the five labels — so the guide and
  `docs/AMB_REPLICATION.md` contradicted each other and the guide was the
  wrong one. Measured on the full split: cat 1 carries **3.13** evidence
  turns over **2.67** sessions, cat 4 carries **1.07/1.00**, and cat 4 is
  by far the largest at 841 of 1,540 — a single-hop question cannot span
  three turns in three sessions. The lesson is this file's own: a claim
  copied from a third party's source is not verified by having been
  written down, and the data settles it in one query.
  **The context model carries NO timestamps for any provider** —
  `modes/rag.py` uses `doc.content` alone and AMB's BM25 baseline drops
  `Document.timestamp` — while `locomo`'s prompt tells the model to mind
  the timestamps. Measured, that single field is worth **+64 points of
  temporal accuracy** (20.9% → 85.0%) and **+12 overall**; 76.0% of
  temporal golds are dates absent from the retrieved text. Choose and
  REPORT the context shape before running
- `docs/research/` — **gitignored** benchmark-run working sets, on the
  `.handover/` pattern: ignored by git, a governance surface anyway. It
  exists because a run's working set holds the third-party corpus and that
  benchmark's **rendered prompt text** verbatim, which is its source in
  string form — and their clone ships no LICENSE, so it must never enter
  this repo *or its history*. **Gitignoring is what makes keeping the full
  run data safe**; the alternative was discarding the per-question answers
  and verdicts, i.e. the evidence any later challenge to a figure would
  need. Aggregate figures carrying no corpus content publish the normal
  way — `benchmarks/logs/` and `benchmarks/RESULTS.md`, under that
  directory's own standing rule (*"never benchmark-corpus content"*, which
  the existing LoCoMo logs hold to). **A fresh clone has none of it**, so
  anything a later session must not lose belongs in a TRACKED file; each
  run folder therefore carries a README stating its findings in prose
  rather than leaving them implicit in the data. Holds
  `amb-locomo10-2026-08-22/` (M32)
