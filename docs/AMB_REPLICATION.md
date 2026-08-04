# Running the Agent Memory Benchmark against Undercroft, without an external LLM API

**What this is.** A procedure for running AMB's own protocol — its datasets, its
document model, its prompts, its judging rule — against Undercroft, with **Claude
subagents standing in for the two model roles** that AMB normally fills with a
hosted API. No API key, no Gemini, no OpenAI, no local LLM server.

**What this is not.** It is not a new benchmark, and it does not change the
protocol. Every scoring decision belongs to AMB. The only substitution is which
model writes the answer and which model grades it, and that substitution is
exactly why the numbers it produces **are not comparable to AMB's published
leaderboard rows** — those were produced by different models. See
[Reporting](#7-reporting) for how to state a result honestly.

> **No third-party text lives in this repository.**
> The AMB clone carries **no LICENSE file**, so its source — including its
> prompt templates — is all-rights-reserved by default. This document therefore
> contains **no AMB prompt text and no AMB code**. Every prompt is read out of
> *your* clone at run time. That is a deliberate licensing decision, not an
> oversight: do not paste their prompts into this file, into the repo, or into
> a commit message.

---

## 1. What you need before starting

| Requirement | Notes |
|---|---|
| A clone of the Agent Memory Benchmark | **Ask the operator for its path.** Nothing here hardcodes it — see [§2](#2-ask-for-the-clone-and-map-it). |
| Docker | The engine runs in a container, as everything in this repo does. |
| The `undercroft` runtime image | `docker build -t undercroft .` from the repo root. |
| Python 3.12 with `tiktoken` | Only needed for chunking. AMB's own virtualenv already has it; otherwise any container with `tiktoken`. |

You do **not** need network access if the clone already has its dataset cache
populated (see [§3](#3-choose-a-dataset-and-split)). You do **not** need an
`OPENAI_API_KEY`, `GEMINI_API_KEY`, or a local model server. If any step asks
for one, something has gone wrong — stop.

---

## 2. Ask for the clone, and map it

**Do not guess this path and do not reuse a path from an old session.** Ask:

> Where is your Agent Memory Benchmark clone?

Everything else is derived from that answer. Set `AMB` to it and resolve:

| What | Path under `$AMB` |
|---|---|
| Dataset adapters | `src/memory_bench/dataset/<dataset>.py` |
| Generic judge fallback | `src/memory_bench/judge.py` |
| RAG mode, answer schemas, MCQ scoring | `src/memory_bench/modes/rag.py` |
| Chunking (`CHUNK_SIZE`, `chunk_text`) | `src/memory_bench/utils.py` |
| Cached, normalised data per split | `data/<dataset>/<split>/` |

Verify the clone before relying on it:

```bash
ls "$AMB/src/memory_bench/dataset" && ls "$AMB/data"
```

If `data/<dataset>/<split>/` is empty, that split has never been fetched in this
clone. Populating it is a download and is the operator's call — ask first.

---

## 3. Choose a dataset and split

**Ask the operator which one to run.** Do not assume LoCoMo. Report the scale
first so the choice is informed — query count drives model cost, corpus size
drives ingest time.

| Dataset | Split | Queries | Docs | Corpus | Task | Scoring |
|---|---|---|---|---|---|---|
| `locomo` | `locomo10` | 1,540 | 272 | 1.3M ch | open | LLM judge, pass/fail |
| `longmemeval` | `s` | 500 | 23,867 | 256M ch | open | LLM judge, pass/fail |
| `personamem` | `32k` | 589 | 195 | 5.4M ch | **mcq** | **exact letter — no judge** |
| `personamem` | `128k` | 2,727 | 2,148 | 71M ch | **mcq** | **exact letter — no judge** |
| `personamem` | `1M` | 2,674 | 1,966 | 156M ch | **mcq** | **exact letter — no judge** |
| `lifebench` | `en` | 2,003 | 3,605 | 49M ch | open | LLM judge, pass/fail |
| `beam` | `100k` | 400 | 170 | 12M ch | open | **rubric, continuous 0–1** |
| `beam` | `1m` | 700 | 1,830 | 162M ch | open | **rubric, continuous 0–1** |
| `beam` | `10m` | 200 | 10 | 468M ch | open | **rubric, continuous 0–1** |

Counts above were measured from a populated cache; re-measure rather than trust
them if the clone differs.

Three of these are not interchangeable, and picking without reading this costs a
whole run:

* **`personamem` is multiple-choice.** Scoring is exact letter match in
  `modes/rag.py`, with **no judge model at all**. Only the answer role is a
  model. This is the most objective number available here.
* **`beam` is scored by a continuous rubric**, averaged per question, via the
  dataset's own `score_result`. It is **not** pass/fail, so its numbers live on
  a different scale and must never be averaged with the others. Its
  `build_judge_prompt` exists but is **never called** — do not implement it.
* **`locomo` alone skips a category** (adversarial). Every other dataset scores
  everything it loads.

---

## 4. Read the protocol out of the clone

For the chosen dataset, read these and follow what they actually say. They are
the specification; this document is only a map.

1. **`dataset/<name>.py`** — `task_type`, `isolation_unit`, how one `Document`
   is built, how `timestamp` and `meta.query_timestamp` are derived, the
   category map, any skip set, and whether it **overrides** `build_rag_prompt`
   and `build_judge_prompt`.
2. **`base.py`** — the default open and MCQ prompts, used only where a dataset
   does not override.
3. **`judge.py`** — the generic judge prompt, used only where a dataset's
   `build_judge_prompt` returns `None`.
4. **`modes/rag.py`** — the answer schema and the MCQ scorer.

### The contract, per dataset

Verified by reading the adapters. Prompt **text** is deliberately absent.

| Dataset | Document unit | Answer prompt | Judge prompt | Skips |
|---|---|---|---|---|
| `locomo` | one session of one conversation | overrides | overrides | category 5 (adversarial) |
| `longmemeval` | one haystack session of one question | overrides | **per-question-type, via `get_judge_prompt_fn`** — NOT the base fallback | none |
| `personamem` | one session of a shared context | overrides (MCQ template) | **none — no judge** | none |
| `lifebench` | one session of one user (one calendar day) | overrides | overrides | none — including its `unanswerable` category |
| `beam` | one session, sub-chunked to ~100k chars | overrides | **never called** | none |

### Traps that silently corrupt a re-implementation

Each of these was found by reading the source, and several of them bit this
procedure on its first attempt.

* **`task_type: "open"` does not mean "return a string."** `modes/rag.py` uses
  an open schema requiring **both** a reasoning field and an answer field, and
  only the answer field is judged. Emitting a bare answer changes the task.
* **`query_timestamp` is computed over a lexicographic session sort.** Session
  keys are sorted as strings, so `session_10` and `session_11` order *before*
  `session_2`, and walking backwards starts at `session_9`. Reproducing this
  with a numeric sort yields the wrong timestamp for any conversation with ten
  or more sessions. **Consuming the cached `queries.json.gz` avoids this
  entirely**, because the cache already holds AMB's computed value — which is
  the main reason to prefer the cache over re-deriving from raw data.
* **Category integers are not intuitive, and AMB's own label map disagrees
  with the evidence structure.** What AMB *does* — the only thing that matters
  for replication — is `_CATEGORY_NAMES` in `dataset/locomo.py`: `1`
  **single-hop**, `2` temporal, `3` **multi-hop**, `4` **open-domain**, `5`
  adversarial (skipped). **Use those names.** Consuming the cached
  `queries.json.gz` gets them for free, because `load_queries` resolves each
  integer to its name before caching — so the trap cannot bite a run that
  reads the cache, only one that re-derives the map.

  Recorded because it is real: measured from the cache, the category AMB
  labels **single-hop** carries **2.67** gold sessions per query, while the
  one it labels **open-domain** carries exactly **1.00** and is by far the
  largest (841 of 1,540). A single-hop question cannot span 2.67 sessions,
  so AMB's `1`/`3`/`4` names look transposed against their own data. That is
  **AMB's defect to carry, not ours to silently fix**: replicating means
  using their labels, and any per-category table we publish must footnote
  this so a reader comparing against LoCoMo's paper is not misled. An earlier
  version of this document "corrected" the map, which would have made every
  per-category figure incomparable to the thing it claims to replicate.
* **`gold_answers` is a list**, and judges may use only its first element.
* **`retrieval_query`** falls back to the raw question when a dataset does not
  set it; where a dataset *does* set it, retrieving on the raw question is wrong.
* **Empty context short-circuits.** The runner marks a query incorrect without
  calling the judge when retrieval returned nothing. Reproduce that, or the
  score is inflated. Note the branch **precedes the MCQ branch**, so it applies
  to `personamem` too — an empty context is wrong even where no judge exists.
* **The context string has an exact shape**, built in `modes/rag.py` from the
  retrieved documents: each document becomes `## Memory <i>` on its own line
  (1-based) followed by its content, and the blocks are joined by a blank
  line. Concatenating the drawers any other way changes the prompt.
* **The answer prompt may take a raw provider response instead of that
  string.** `locomo`'s `build_rag_prompt` uses the provider's raw response
  JSON *when the provider returns one*, falling back to the context string
  otherwise. Our provider returns none, so the fallback is what runs — keep it
  that way, or the prompt stops matching the run being replicated.
* **The MCQ answer field is `choice`, not `answer`**, and the letter is
  normalised (`strip → lowercase → strip "(). " → first character`) on both
  the model's choice and every gold before comparison. `_score_mcq` checks
  the answer against **all** gold answers, not just the first.
* **The `query_timestamp` quirk fires on every LoCoMo query, not just long
  conversations.** All ten conversations hold 19–32 sessions, so the
  lexicographic maximum is always `session_9`, and every cached timestamp is
  that session's date — **3 to 6 months before the conversation actually
  ends**. The "current date" line LoCoMo injects into the answer prompt is
  therefore mid-conversation for all 1,540 queries. Reading the cache
  reproduces this exactly, which is the point: it is AMB's behaviour, and a
  "corrected" timestamp would be a different benchmark.
* **Six LoCoMo gold answers are integers, not strings.** Calling a string
  method on gold crashes or silently reformats; AMB's f-string formatting
  tolerates them, so coerce with `str()` at the boundary.
* **Nine LoCoMo queries carry empty `gold_ids`.** Harmless for standard
  scoring (gold ids are unused outside oracle mode), fatal to any recall
  metric computed against them.
* **LoCoMo turns carry image fields.** 1,226 of 5,882 turns hold
  `blip_caption`/`img_url` keys, serialised into the document content — and
  sometimes the evidence *is* the caption. Ingest the cached content
  verbatim; re-serialising only speaker and text drops that evidence.
* **`personamem` declares no `isolation_unit`**, so AMB ingests all its
  documents up front and isolates only by `user_id` at retrieval, while
  `locomo` runs unit-sequentially with memory accumulating across
  conversations and never reset. Wing-scoped retrieval reproduces both, but
  the ingest ORDER differs and an order-sensitive system would notice. Note
  also that personamem's `gold_ids` are *all history before the question*,
  not evidence annotations — a recall metric against them is meaningless.

---

## 4b. Defects in AMB, and why this procedure reproduces them

Reading the harness closely turned up defects in it. **None of them are fixed
here, and none of them may be.** A replication's entire value is that its
number can be set beside theirs; correct a defect and the delta becomes
unattributable — it could be the memory layer or it could be the fix, and no
reader can tell which. This document already contains one cautionary example:
an earlier version "corrected" the category map, which would have made every
per-category figure incomparable to the thing it claims to replicate.

So: reproduce the behaviour, record the defect, and let the report carry it.

| Defect | Confidence | What it does | What we do |
|---|---|---|---|
| **`query_timestamp` is the wrong session's date.** `_session_keys` sorts lexicographically, so the maximum is always `session_9`; every conversation has 19–32 sessions. Their own docstring says "the date of the last session". | Certain — code, comment and data all agree | Fires on **100% of 1,540 queries**. The "current date" handed to the answer model sits **3–6 months before the conversation ends**, while the prompt instructs the model to resolve relative time against it. Distorts the 321 temporal questions most. | Consume the cached value. It IS their value. |
| **`k` is chosen by the provider, not the harness.** `RAGMode` never passes `k`; bm25/hindsight default to 10, hybrid-search/qdrant to 50. | High | Published rows may compare systems given a **5× different retrieval budget** before any memory-quality difference enters. | Use 10, and state the budget against whichever row is being compared. |
| **Category labels `1`/`3`/`4` look transposed.** What they label single-hop needs 2.67 evidence sessions (95% span ≥2); what they label open-domain spans exactly 1 in 840 of 841. | Probable, not provable offline — `evidence` may list all mentions rather than required hops, and settling it needs LoCoMo's paper | Their per-category tables are likely mislabeled. No effect on an overall score. | Use their labels. Footnote the anomaly in any per-category table. |
| **Their CLI crashes on a LoCoMo subset run** — the runner passes `user_ids` to `load_documents`, which LoCoMo's adapter does not accept. | Certain | The README's own smoke recipe raises `TypeError` for this dataset; only full-split or `--oracle` runs avoid the branch. | Run full splits. Do not "repair" it into different document-loading semantics. |
| Minor: `--llm` is parsed but unused; the README names a different answerer than the code defaults to; `longmemeval.build_judge_prompt` is a dead stub returning `None`; MCQ summaries still record a judge model although no judge ran. | Certain | Documentation drift. The dead stub is what misled **this document** into describing the wrong judge for longmemeval. | Read the code, not the README — including theirs. |

**If you want to know how much a defect costs, measure it — as a second,
clearly-labeled arm.** Run the faithful configuration first and publish that as
the AMB-protocol result; then, if it is worth knowing, run one variable changed
(corrected timestamps, say) and publish it as *ours, not comparable*. The delta
is then an honest statement about the defect rather than a contaminated
statement about the memory layer. Never let the corrected arm stand in for the
faithful one.

**Upstreaming is the other half.** Recording a defect here helps our readers;
telling AMB helps everyone, and it is the difference between an audit and a
grudge. That is the operator's call, not this document's — but note the clone
carries no LICENSE, so a patch may not be redistributable and an issue may be
the only available venue.

---

## 5. Run the provider step as code

This is the part AMB implements as a `MemoryProvider`, and it must stay
deterministic — **no model touches it**. Undercroft is driven over `/v1`, exactly
as the real adapter drives it.

```bash
docker build -t undercroft .
docker volume create amb-data
docker run --rm -v amb-data:/data undercroft init
docker run -d --name amb-engine -v amb-data:/data --network undercroft_default \
  -e UNDERCROFT_MCP_HTTP_TOKEN=bench \
  undercroft serve-http --host 0.0.0.0 --port 8080
```

Then, from the cached split:

1. **Ingest.** Read `documents.json.gz`. For each document, chunk its `content`
   with AMB's `chunk_text` (`cl100k_base`, `CHUNK_SIZE` tokens — read the value,
   do not assume it) and `POST /v1/vaults/default/drawers` with `text`, `wing`
   (the document's `user_id`, which is AMB's isolation unit), `room` (the
   document id or its session key), and `content_date` (the document
   `timestamp`) where present.
2. **Retrieve.** Read `queries.json.gz`. For each query, `POST
   /v1/vaults/default/search` with the query text, `limit` = **`k`**, and `wing`
   set to the query's `user_id`. **Scoping by wing is not optional** — it is
   AMB's isolation unit, and omitting it lets one conversation answer another's
   questions.

   **`k` defaults to 10** — that is the signature in `memory/base.py`, and it is
   the value a faithful run uses. Raising it is a legitimate experiment but it
   is no longer AMB's configuration, so say so in the report.

   **But know whose default you are matching.** `RAGMode` never passes `k`, so
   the **provider's own default governs**: the bm25 and hindsight baselines
   take the 10 above, while AMB's hybrid-search/qdrant baseline overrides to
   **50**. A `k=10` run set beside a published hybrid-search row differs by a
   10-vs-50 retrieval budget *before* any model difference — name that in the
   report rather than letting it read as a memory-layer result.

   Before choosing `k`, work out **what fraction of one isolation unit it
   actually returns**: divide the drawer count by the number of units. On
   `locomo10` the corpus is ~876 drawers over 10 conversations, so ~88 per
   conversation — meaning `k=10` is 11% of a conversation and `k=30` is **34%**.
   At a third of the conversation in context, the exercise stops measuring
   retrieval and starts measuring reading comprehension, and the score rises for
   a reason that has nothing to do with the memory layer. This is not
   hypothetical: a run here at `k=30` scored 94.4% and the number was
   uninterpretable because of it.
3. **Emit** one JSONL row per query carrying: query id, category, question,
   gold answers, `query_timestamp`, and the retrieved context.

**Split gold out of the file the answer model will read.** Write two files — one
with `{id, question, context}` and one with `{id, question, gold, category}`.
Confirm the answer file's keys are exactly the three expected before going
further. On the first attempt at this procedure the gold answers sat in the same
file the answerer was given, which would have voided the run.

---

## 6. Run the two model roles as Claude subagents

Use the workflow tool. Batch the queries (20 per agent is comfortable) and
pipeline them, so a batch is judged as soon as it is answered.

**Batching is a declared deviation, not a free optimisation.** AMB answers
**one query per schema-enforced call**, so nothing can travel between two
questions. An agent holding twenty questions and their contexts can carry
information across them — and because batches mix conversations, that is
information AMB's isolation makes unavailable. Answering one query per agent
would remove the deviation and cost 1,540 agents on `locomo10`; batching is
the practical choice, so it must be **named in the report's
non-comparability list** ([§7](#7-reporting)) and mitigated by telling each
agent to treat every query in its batch as independent and to use only that
query's own context.

### Pin the model, for both roles

Run **the latest Sonnet** — at time of writing Sonnet 5, `claude-sonnet-5`,
which the workflow tool selects as `model: 'sonnet'`. Set it explicitly on the
answer agent *and* the judge agent. Do not let either inherit whatever model the
session happens to be running.

Three reasons, and the first is the one that matters:

* **A run whose model tier drifts is not comparable to the previous run.**
  Inheriting the session model means the benchmark silently re-scores itself
  whenever someone opens a session on a different model, and two runs a week
  apart stop meaning the same thing. Pinning is what makes the number a
  measurement rather than a snapshot of today's configuration.
* **Tier honesty.** AMB's own reference rows were produced by small, fast hosted
  models. Answering with a frontier model measures a different system than the
  rows anyone might compare against, and inflates the result for a reason that
  has nothing to do with the memory layer.
* **Throughput.** A full split is ~154 agents. Sonnet finishes a run in a
  fraction of the wall-clock and tokens a frontier model takes, which is what
  makes re-running after a configuration change practical rather than a decision.

Record the exact model in the report ([§7](#7-reporting)). If you change it,
you have changed the benchmark, and no delta against an earlier run is
attributable to anything else.

**Answer agent** — give it the gold-free batch file only.
* Use the dataset's own prompt, read from the clone in [§4](#4-read-the-protocol-out-of-the-clone). Do not
  write your own, and do not "improve" it. An added instruction to be terse, to
  abstain, or to avoid outside knowledge changes what is being measured.
* Match the schema in `modes/rag.py`: reasoning **and** answer for open tasks;
  the MCQ schema for `personamem`.
* Inject `query_timestamp` where the dataset's prompt does.

**Judge agent** — give it question, gold and candidate, and **not** the context.
* Use the dataset's judge prompt, or the generic fallback where the dataset
  does not override, per the table in [§4](#4-read-the-protocol-out-of-the-clone).
* Skip entirely for `personamem` — score by letter.
* For `beam`, implement `score_result`'s rubric average instead of a verdict.

**Verify before believing the number**, every time:

```
answered batches == judged batches == expected
answers per batch == batch size, for every batch
unique query ids answered == unique judged == expected total
every verdict's id appears in the ANSWER set          <- see below
abstentions graded correct == 0   (where every query has a gold)
```

**A judge asked for N verdicts will pad to N.** Observed here: one answer agent
returned 19 answers instead of 20, and its judge returned 20 verdicts anyway by
duplicating an id — a grade for a question nobody had answered. It was 1 of
1540, so no aggregate check caught it; only reconciling verdict ids against
answer ids did. Reject any verdict whose id is not in that batch's answer set,
**count the rejections, and report the count** rather than quietly dropping
them. Tell the judge explicitly not to pad, and tell the answerer to count the
lines in its file — but verify anyway, because instructions are not guarantees.

**Pin the verdict format and the denominator, or two careful people produce
different bookkeeping from the same run.** The judge's output schema is
`correct` (boolean) and `reason` (string), both required — that is the schema
in `judge.py`, and every per-dataset judge prompt family embeds the same
contract. A subagent replying in prose instead of that shape is a **parse
failure, not a verdict**: reject it exactly as you reject a fabricated id.
AMB's accuracy is `correct / len(results)`, so a query whose verdict was
rejected is **still in the denominator** — re-run it if you can, and if you
cannot, score it incorrect and say how many were scored that way. Silently
dropping it inflates the result.

Then read a sample of graded-correct and graded-incorrect pairs. A judge that
agrees with everything is as broken as one that agrees with nothing, and the
only way to see either is to look.

---

## 7. Reporting

Report per category and overall, and state plainly:

* the exact model in each role, by name and version;
* the retrieval `k`, **and what share of one isolation unit it returned**;
* how many verdicts were rejected as fabricated, even when that is zero;
* the rest of the retrieval configuration — wing scoping, result ordering,
  chunk size;
* the ingest shape, because per-turn and per-session drawers are different
  systems under test;
* the **declared deviations**, in one place: batched answering (AMB answers one
  query per call), the retrieval budget against whichever baseline is being
  compared (`k=10` here vs the hybrid-search baseline's 50), and the prompt
  path — LoCoMo's builder substitutes a provider's raw-response JSON for the
  context string when one exists, so a provider returning none (ours) is
  answering from the `## Memory` context that bm25-style baselines produce,
  not the JSON that qdrant-style rows produced;
* that the numbers are **not comparable** to AMB's published rows, because the
  models differ — and not comparable to any of our earlier runs that used a
  different answering model, judge, `k`, or ingest granularity.

If more than one of those moved between two runs, **no delta in the table is
attributable to any single one of them.** Say so rather than implying a cause.

---

## 8. Cleaning up

```bash
docker rm -f amb-engine
docker volume rm amb-data
```

Leave them running only if a follow-up run is imminent, and say so in the
handover — a populated vault is state, and a later session will not know what is
in it.
