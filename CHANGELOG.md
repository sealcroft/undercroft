# Changelog

## Unreleased — a served embedder, and a standing conclusion overturned

- **`UNDERCROFT_EMBEDDER=http` — an `Embedder` backed by a served model.** The
  engine could embed exactly three ways: the built-in hash, an ONNX file on
  disk (`onnx`/`ort`), or not at all (`external:` is an *identity* for vaults
  whose vectors the caller computes elsewhere — its `embed()` returns a zero
  vector and is documented as unreachable). A model served over HTTP had no
  route in, though the same runtimes have driven `refine` since v0.5.0.
  `undercroft_llm::HttpEmbedder` closes that, reusing the LLM client's
  conventions rather than inventing new ones: both API shapes (OpenAI
  `/v1/embeddings` and Ollama native, both verified against a live server),
  `UNDERCROFT_EMBED_URL`/`_MODEL`/`_API`/`_KEY`/`_DIM`, and the same default-off
  posture — nothing is contacted unless a URL is set.
  - **The dimension is probed, not assumed**: one embed at construction, whose
    length is the dimension. Reading it is evidence; inferring 768 from a model
    name would be inference.
  - **Identity is `http:<model>`**, so the existing embedder-swap refusal
    covers a silently changed served model exactly as it covers an ONNX swap.
  - **Two hazards stated rather than hidden.** Drawer text is sent **in the
    clear** — warned at construction when the host is not loopback, because
    sealing protects a vault at rest, not content handed to another host. And
    a failed embed cannot fail a write (`Embedder::embed` has no error
    channel), so it degrades to a **counted** zero vector: the drawer stays
    verbatim and lexically findable, but is semantically invisible until
    re-embedded.
- **`embeddings` + `embed-pull` compose services** run a quantized embedder on
  the compose network, **CPU only**. A desktop runtime on the host is neither
  reproducible nor reachable from the bench container; this is, and it keeps
  the Docker-only rule intact.
- **The standing conclusion "a semantic embedder is NOT the biggest lever" is
  overturned.** It rested on MiniLM measuring **+0.3pp** of turn all-gold on
  LoCoMo — a fact about MiniLM, generalised to model embedders as a class.
  Four served models, full corpus, same k and pool:

  | model | params | session `R@10` | turn all-gold | ingest | ms/q |
  |---|---|---|---|---|---|
  | hash (default) | — | 95.5% | 74.2% | 16 s | 110 |
  | nomic-embed-text | 137M | 96.8% | 77.4% | 177 s | 132 |
  | mxbai-embed-large | 335M | 96.9% | **78.4%** | 416 s | 149 |
  | bge-m3 | 567M | 96.9% | 77.9% | 469 s | 172 |
  | Qwen3-Embedding-0.6B (Q8) | 600M | **97.0%** | 78.1% | 413 s | 171 |

  **+3.2 to +4.2pp** over hash — comparable to ColBERT's +4.9pp, at no storage
  cost and with no ONNX export. And the second reading matters as much: the
  four modern models span **1.0pp**, so the lever is *using a real embedder at
  all*, not choosing the best one. Public leaderboard order does not transfer —
  Qwen3-0.6B sits far above nomic on MTEB and lands within 0.7pp here at 2.3×
  the ingest cost.
  - **No winner is claimed.** One run per model, and the served path has not
    been shown run-to-run deterministic; a 1.0pp spread deserves the same
    suspicion that already cost this session two retracted findings.
  - **Untested, and it is the part that would matter most:** LoCoMo is English,
    so bge-m3's and Qwen3's multilingual training buys nothing visible here.
    Cross-lingual is the one capability the hash embedder provably cannot do at
    all, and none of the above measures it.
  - Qwen3-Embedding is **not** in Ollama's library at 0.5.7–0.11.4; it was
    pulled from `hf.co/Qwen/Qwen3-Embedding-0.6B-GGUF`. Mistral's embedder is
    API-only (no weights, so it cannot run in the container and would be real
    external egress); the open Mistral-family embedders are all 7B, ~10× the
    CPU cost of the 0.6B, and were not run.

## Unreleased — the rescore depth was a latency cap in disguise

- **Late interaction gets its own depth, `UNDERCROFT_LATE_TOP_N` (200).** It
  shared `UNDERCROFT_RERANK_TOP_N` (50) with the cross-encoder, and the two
  budgets buy different things: a cross-encoder spends one transformer forward
  per candidate, so its depth *is* a latency cap, while MaxSim is arithmetic
  over matrices built at ingest. Late interaction was therefore inheriting a
  cap it never spent — the single largest measured constraint on how deep the
  engine looks.
- **Measured on the merged LoCoMo corpus with the token codebook disabled**, so
  no codebook is trained, there is no keyed draw, and rescore depth is the only
  variable (turn all-gold in the 10 slots, against search ms/query):

  | depth | all-gold | ms/q |
  |---|---|---|
  | 50 (the old shared cap) | 77.7% | 342 |
  | 100 | 78.7% | 352 |
  | **200 (new default)** | **79.8%** | **374** |
  | 400 | 79.6% | 417 |

  **+2.1pp for +9% search time in that configuration** — and the qualifier is
  load-bearing. Any corpus past `TOK_PQ_MIN` (256 matrices) runs v2 PQ-ADC
  instead, and this one does; there the same 50 → 200 step measured **+1.7pp
  in one run and +0.0pp in another**, both inside the per-vault draw's spread.
  **The default-configuration value of the change is therefore unmeasured**,
  bracketed by 0.0 and 1.7. Under v2 the same sweep moved 334 → 337 ms/q, so
  the depth is nearly free there: a coded row costs `m` table lookups, not a
  full-dimension dot.
- **200 is a judgement, not a measured optimum.** An earlier draft of this
  entry called it a peak because 400 scored 79.6% against 200's 79.8% — a
  difference of **one question out of 495**, from one run per depth, while the
  two other sweeps in the same record put 400 *above* 200 (80.6 vs 80.4; 80.2
  vs 78.9). What the evidence supports is that depth beyond 50 helps and that
  100–400 are not separable here. 200 takes the measured gain without paying
  unbounded rescore on a large candidate set.
- **This moves published ColBERT figures, and they have not been re-measured.**
  `late_rescore` runs on the un-truncated candidate list, so on a sealed vault
  with no prefilter the depth reaches the whole corpus: a 127-drawer LoCoMo
  conversation goes from `min(127, 50)` to `min(127, 200)` — every drawer
  rescored rather than 50. The full-corpus ColBERT numbers (79.1%, +4.9pp)
  describe depth 50 and no longer describe the default.
- **Deconfounding was necessary, and the first attempt at this measurement did
  not do it.** A sweep with the codebook live reported +1.7pp and put depth 200
  at exactly the 80.4% that a previous session had recorded — both of which
  evaporated on a repeat run at the same settings (78.9%). Each fresh vault
  draws its own training sample, so per-vault spread is ~1.5pp on this corpus,
  the same size as the effect. Numbers here come from the configuration where
  that variance does not exist.
- Setting only `UNDERCROFT_RERANK_TOP_N` still drives both stages, so a
  deployment that pinned the old knob keeps exactly the behaviour it pinned.

## Unreleased — what a drawer costs, and who gets to shape a codebook

The guardrails the measurement work needed before anything built on it:
footprint is now asserted rather than computed, and the two cross-drawer
objects in the engine are no longer either guessable or silent.

- **A drawer's on-disk cost is pinned, per artifact, in both directions.**
  "Never grow large" is a first-class constraint of this project and was the
  only load-bearing property with no test — the byte formulas lived in
  comments and the totals in arithmetic over them, so a change that doubled
  the per-drawer footprint would have shipped green.
  `one_drawer_costs_exactly_this_many_bytes` measures a real 804-byte prose
  chunk on a **sealed** vault and asserts every artifact against its formula:
  sealed embedding `40+6+dim` = **430 B** at 384 dims, sealed PQ row
  `40+4+dim/8` = **92 B**, v1 token matrix `40+9+rows·(4+dim)`, raw FDE
  `40+1+reps·2^ksim·dproj·4` = **8,233 B** — the 40 being XChaCha20's 24-byte
  nonce plus Poly1305's 16-byte tag. Equality, not an upper bound, so a
  *shrink* fails too and good news has to be recorded instead of quietly
  absorbed. Measured at rest for that chunk: content **515 B**, so the default
  configuration's only derived artifact — the embedding — is **0.83×** the
  content it indexes, and every tier at once is **11,304 B, 22×**.
  - **The mechanism is one table driving both halves.** `priced` names each
    artifact with the query that measures it *and* the formula it must equal,
    and the inventory assertion is built from that same array — so a new
    artifact cannot be silenced by adding a name, because a name with no
    formula beside it does not compile. The first version of this test kept the
    halves separate and was refuted for exactly that: **one string literal made
    it green with zero bytes measured.**
  - The inventory is now the **whole schema**, not a `drawer%` prefix: every
    table is either priced per-drawer or listed as not-per-drawer with its
    reason. A prefix is a naming convention, and a future store called
    `sparse_terms` would have passed it silently. `drawers`' **column list** is
    pinned too, because a column is the cheapest way to add per-drawer bytes
    and no table-level check can see one.
  - Sealed is the level with the strictest *guarantees*, **not** the larger
    footprint: hmac-only keeps content as plaintext and adds an fts5 index plus
    four shadow tables over it. The earlier claim that sealed is "the worst
    case" was wrong.
  - Found while writing it: **with the FDE tier enabled, `search` never builds
    the PQ index** — the prefilters are an `else if` chain with FDE first. The
    per-drawer FDE cost depends on which side of `fde_pq_min` (256 rows) the
    corpus is: **8,233 B raw below it, 301 B PQ'd above it**. Any statement
    about "8 KB per drawer" is about a small corpus, not the steady state.

- **The training sample of every trained index artifact is now a stratified
  keyed draw, not an even stride — and the stride turned out to be a latent
  recall landmine, not only a predictable one.** It was `div_ceil` + `step_by`
  at all five sites: four capped at 4,096 **drawers** (PQ codebook, IVF
  centroids, FDE codebook, FDE IVF centroids), the token codebook at 16,384
  **token rows** — a different unit and 4× the figure.
  - **The security reason it changed.** The stride is reproducible, and equally
    reproducible to a writer who never held the vault key: `seq ≡ 0 mod stride`
    told them exactly which of their rows would train the quantizer every
    *other* row is then encoded against. k-means has an unbounded breakdown
    point, so that is a lever on unrelated drawers' recall, invisible to every
    HMAC because nothing was tampered with.
  - **The correctness reason it had to change, measured.** A fixed interval
    over a corpus whose insertion order is *periodic* samples one residue
    class. `synth` builds facts from `FACT_TEMPLATES[i % 4]`, and at
    `--n 16384` the interval is exactly `⌈16384/4096⌉ = 4`: every sampled fact
    shares one template and one key prefix. Within-run, one host,
    `UNDERCROFT_RETRIEVAL=pq`, hmac-only, 2,000 queries:

    | n | interval | draw | R@1 | R@5 |
    |---|---|---|---|---|
    | 20,000 | 5 (coprime with 4) | stride | 99.2% | 99.8% |
    | 20,000 | — | stratified keyed | 97.9% | 99.4% |
    | **16,384** | **4 (aligned)** | **stride** | **82.5%** | **83.0%** |
    | 16,384 | — | stratified keyed | **98.9%** | **99.7%** |

    The stride's edge at 20,000 is alignment luck between two measured points;
    its collapse sits between them, and at 16,384 it **fails `synth`'s own
    ≥95% regression gate** — a shipped default that a benchmark already in this
    repo would have caught at a corpus size nobody happened to run. Periodic
    insertion order is not exotic: round-robin ingest per source, alternating
    speakers, one session per day all produce it.
  - **Stratified, not simply lowest-ranked.** Blocks keep the coverage the
    stride had; the keyed choice *inside* each block breaks the residue
    alignment that made it fragile. The two keyed variants are within noise of
    each other (uniform 97.8/99.4 against stratified 97.9/99.4 at n=20,000), so
    the strata are kept for the reasoning they support, not for a recall win.
  - **And the failure class now announces itself.** Fixing the draw does not
    help a vault trained by an older build, and an unrepresentative corpus can
    arrive by other routes (one enormous near-duplicate cluster, an `external:`
    embedder with a degenerate space). So every codebook is checked at train
    time against a **second keyed draw it did not train on**
    (`ProductQuantizer::fit_report`): reconstruct its own sample more than 1.5×
    better than unseen vectors and it warns, with both errors and the ratio.
    Pinned in both directions by a test built to the exact shape of the real
    failure — a four-cluster corpus sampled at stride 4 must fire, the same
    corpus at stride 5 must not, because a detector that cries wolf on healthy
    corpora gets muted. Advisory: it never fails a training pass, and it is
    silent until a codebook is actually trained, so an already-degenerate vault
    stays quiet until its next retrain.
  - `sample_rank` is keyed by a **fourth HKDF-derived subkey** (label
    `sample`), deliberately not the MAC key: these ranks are published by
    their effects — which rows shaped a codebook — and must not share a key
    with record integrity. The label is **length-prefixed, not delimited**, so
    no two (label, ident) pairs can re-cut into one rank.
  - **Below a cap it is exactly a no-op** — the whole corpus trains, as it did
    at `stride == 1`. **Above a cap both the membership and the size of the
    sample change**: the old stride took `n/⌈n/cap⌉` rows, so a 50,000-row
    corpus trained on 3,847 where this trains on 4,096. A measurement taken
    above a cap is therefore **not reproduced by this build**.
  - **Which published numbers that touches, exactly** — because the answer is
    narrower than it first looks. `locomo_eval` builds a **fresh vault per
    conversation** (~127 drawers), which is below `TOK_PQ_MIN` (256) and below
    every drawer-level cap, so **no codebook of any kind trains there**: the
    headline LoCoMo figures (session `R@10` 95.5%, turn all-gold 74.2%, and
    ColBERT's 79.1% / +4.9pp) are untouched, and ColBERT runs there as exact
    int8 MaxSim. Affected: the **`synth` PQ/IVF recall** figures — measured
    above, 99.8% → **99.4%** R@5 at n=20,000 — and the **`TOK_PQ_MIN` boundary
    run**, re-measured below. Unaffected for a third reason: the 10⁷ page-tier
    spike and the FDE-synth containment numbers train on their harnesses' own
    synthetic samples, not the store's.
  - **The token-codebook site, re-measured** (`locomo3_merged`, ~380 drawers,
    ~47,500 token rows against a 16,384 cap — the one place a LoCoMo run
    trains a codebook). Turn all-gold in the 10 slots: hash baseline **73.9%**,
    ColBERT with the stride **78.1%**, ColBERT with the stratified keyed draw
    **78.9%** and **78.1%** on two runs with different vault keys. The keyed
    spread brackets the stride, so **at this site the draw makes no measurable
    difference**.
  - **A recorded figure, and what it took to account for it.** That same
    corpus previously reported ColBERT at **80.4% (+6.5pp)**. The hash
    baseline reproduces to the decimal (73.9%), fixing corpus, chunking, `k`,
    pool and fusion, so the difference had to be in the ColBERT path. Tested
    and eliminated there: the training draw (stride 78.1%, keyed 78.9%/78.1%),
    the packing boundary (exact int8, 77.7%), the backend (**ort**, 78.7%),
    and the export pair (only one exists). Two things were then found that
    together account for it, and **neither was recorded with the number**:
    - **Rescore depth.** It was governed by `UNDERCROFT_RERANK_TOP_N`, an
      environment variable, and raising it moves this exact figure — see the
      R2 entry below, where depth 200 measures 79.8% against 77.7% at 50.
    - **Per-vault variance of ~1.5pp.** With the token codebook live, two runs
      at identical settings scored 80.4% and 78.9%, because each fresh vault
      draws a different training sample. Any single ColBERT number on this
      corpus carries that spread.

    So 80.4% is reachable — it is not an error in the record — but it is not
    attributable to any one setting, and a lone run cannot distinguish a real
    +1.5pp from the draw. **Both facts are instrument defects that this
    session's own first sweep walked straight into**, reading a single run and
    concluding depth was worth +1.7pp. The deconfounded sweep (codebook
    disabled, so the draw is out of the picture) is what the R2 numbers rest
    on. A figure without its backend, export, thresholds and repeat count is
    not defensible later.
  - **`benchmarks/RESULTS.md`'s "Recall is identical across every version
    (deterministic pipeline)" is now false** and is corrected there: the draw
    is keyed on a per-vault subkey, so two fresh vaults over identical content
    above a cap train different codebooks. The observed spread across three
    keyed runs at n=20,000 was R@1 97.4–97.9%, R@5 99.4–99.6%.
  - Reproducibility is now **per vault**, not per corpus. Two fresh vaults
    ingesting identical content above a cap train different codebooks, so a
    bench harness that builds a new vault per run no longer reproduces itself
    exactly at that scale.
  - The PQ codebook and the IVF centroids draw under **different labels** —
    two independent samples where one stride gave both the same rows.
  - Pinned by unit tests on both halves (keying, selection). Stated as a
    gap: not end-to-end, which would need a corpus above a cap.

- **Every codebook write bumps a visible generation counter.** Nothing in a
  row's bytes says which generation of a trained artifact produced it, so "the
  index was rebuilt from the artifact it already had" and "the artifact was
  replaced and every row re-derived" look identical from outside — the same
  class of invisible change to a vector space that `KNOWN_EMBEDDER_UPGRADES`
  exists to make explicit, one level down.
  - **What a step means differs by artifact**: for the three codebooks it is
    **re-quantization** (every code byte recomputed); for `pq-ivf` and
    `fde-ivf` it is **re-partitioning** — the code bytes are byte-identical and
    what changes is which candidates a probe *offers*. Availability, not score.
  - Counters live in `meta` rather than in each artifact's own table because
    `invalidate_embedding_space` drops `pq_meta` wholesale and **that drop is
    the event most worth counting**; the test asserts the generation survives it
    and reads 2, not 1. A rebuild that reuses the stored codebook is **not** a
    new generation — pinned by forcing a real drift-driven rebuild, because an
    assertion that merely clears the caches cannot fail whatever the code does.
  - Visible on `PalaceStats.codebooks`, `GET /v1/vaults/{id}/stats` (the
    handler projects fields by hand and had to be taught the new one — adding
    it to the struct was not enough), the MCP `undercroft_status` tool,
    `undercroft stats`, and as a **registered** telemetry gauge:
    `undercroft_obs::GAUGE_NAMES` is an allowlist and a gauge set under any
    other name is silently dropped, so all five names are listed there and
    `every_codebook_gauge_name_is_registered_in_obs` pins the mapping.
  - **It is not integrity evidence.** The row is outside HMAC coverage, so
    anyone who can write the database file can reset or forge it; it
    distinguishes honest ambiguity, not tampering. Two stated gaps:
    export/import copies no `meta` rows, so a migrated vault reports 0 — which
    reads as "never trained" rather than "unknown"; and a bump lost to a busy
    database is warned about, not retried.

- **L2 normalisation is documented as the poison mitigation it already was**
  (`pq.rs` module docs) — and the bound is stated correctly this time. With
  every point on the unit sphere an attacker cannot buy influence with
  *magnitude*, only with **count**, which is what makes the breakdown bounded
  at all. What it does **not** give is a small displacement bound: with all
  points in the unit ball every centroid is already in that ball, so "at most
  the diameter" bounds nothing. Two residual channels are named rather than
  implied: **density** (owning a fraction *f* of the corpus buys ≈*f* of any
  uniform sample — a per-source cap's job, not a sampling scheme's) and
  **non-finite input** (a NaN from an `external:` embedder escapes the bound
  entirely). The seeding stride inside `kmeans` is likewise **not** keyed, and
  the residual is written down where it lives.

## Unreleased — gold evidence, and a data-destroying append index

- **`remember` no longer derives a drawer id from `count()`.**
  `crates/undercroft-cli/src/main.rs` now uses `next_append_index()`, matching
  the `/v1` and MCP save paths. `COUNT(*)` goes *down* after a delete, so the
  next save was handed an index still in use, the derived id collided, and
  `ON CONFLICT(id) DO UPDATE` overwrote the unrelated drawer holding it — a
  record destroyed by writing a different one, which is exactly the failure
  the store documents and `CLAUDE.md` pins as an invariant. Regression test
  drives the real binary through remember → remember → `drawer delete` →
  remember and asserts the survivor is intact; reintroducing `count()` makes
  it fail, so it is not vacuous. Vaults that have never deleted are
  unaffected — `next_append_index()` equals `count()` there, so no existing
  id moves.

- **`undercroft-bench locomo` reports gold-evidence recall at turn
  granularity**, alongside the session-level row it has always printed, and
  still without a single model call — the evidence ids ship with the dataset.
  The historical row asks whether a gold *session* appears among the top-k
  rooms; the new one asks whether the gold *turn* is inside the k drawers a
  reader is handed. Full corpus at `k=10`: session **any 95.5% / all 87.9%**
  at pool depth and **94.3% / 85.8%** within the 10 slots, turn **any 84.1% /
  all 74.2%**.
- **Session rows are reported at two depths, because the two granularities are
  only comparable at equal depth.** The session row collects distinct rooms by
  scanning the whole `k*6` candidate pool; the turn row sees only the `k`
  returned slots, so a room first appearing at hit 47 counts for the former and
  cannot count for the latter. Measured against each other at equal depth, the
  granularity difference is **11.6pp** and the depth difference **2.1pp** —
  reported separately so neither is mistaken for the other.
- Coverage is an interval test over byte ranges in the ingested body, not a
  substring search. Ingest windows 800-byte chunks with 100 bytes of overlap
  over a session that is one long paragraph, so turns land across boundaries
  routinely; testing each chunk alone would book a miss the reader never
  suffered, while the union of the returned chunks is exactly what the prompt
  contains. Gold turns that cannot be located (9 of roughly 2,800) are
  excluded **and printed**, so the denominator cannot quietly shrink.
- **LoCoMo image captions now reach the vault.** The corpus is multimodal:
  `blip_caption` appears on 1,226 of 5,882 turns, including 1,064 of the 2,806
  gold-evidence turn references — **37.9%**. The harness formatted `speaker`
  and `text` only, so those turns were stored incomplete. Now ingested;
  `img_url` and `query` stay out, being the dataset's own sourcing scaffolding
  rather than anything a participant said. Retrieval moves ±0.2pp: a
  corpus-fidelity fix, not a quality one.
- **Deduplicating retrieval candidates by source document: a per-document cap
  is refused, byte-level redundancy removal is a small win.** The cap costs
  **−17.5pp** of turn all-gold at ≤1 slot and **−1.8pp** at ≤2, and split by
  population it loses at *every* evidence count — evidence averages 1.17 turns
  per session, so a cap blocks the second turn of the *right* session as often
  as it admits a new one. Removing only *duplicated bytes* — byte-budget
  selection with overlapping text charged once — **gains +0.3pp** and fits 11.3
  chunks where 10 fit before, the only selection-policy change measured that
  loses nowhere. Its ceiling is now known: duplicated bytes are **2.1%** of what
  the reader receives. Both counterfactuals stay in the harness (`DOC_CAPS`,
  `select_within_budget`) so they are re-measured rather than re-proposed.
- **LoCoMo's category integers are `1 = multi-hop, 2 = temporal,
  3 = open-domain, 4 = single-hop, 5 = adversarial`.** The counts and the
  evidence statistics both fix this: category 1 carries a mean 3.13 evidence
  turns over 2.68 distinct sessions, category 4 carries 1.07 over 1.00, and 841
  questions are category 4. Per-category figures elsewhere in this file and in
  ROADMAP are labelled to this mapping. It matters for prioritisation: the
  43.4% all-gold figure belongs to **multi-hop**, where 3.13 turns across 2.68
  sessions makes it unremarkable, while **single-hop measures 97.1%**.
- **Late interaction is the only retrieval change measured to help.** ColBERT
  rescoring: **+4.9pp** turn all-gold on the full corpus (74.2 → 79.1) and
  session `R@10` 95.5 → **96.9%**, at 2.0× search and 43× ingest; **+6.5pp**
  above the `TOK_PQ_MIN=256` boundary where MaxSim runs PQ-ADC instead of
  exact int8. A cross-encoder reaches +6.7pp at **58× search**. Against them:
  a MiniLM bi-encoder is +0.3pp, `Fusion::Rrf` −7.3pp, `Fusion::Legacy`
  −8.2pp, per-query channel rescaling −9.4pp, finer chunks −10 to −28pp,
  writer-declared turn boundaries −6.8pp, and the semantic gate off is
  byte-identical. ROADMAP records the full list so none of it is
  re-proposed.

## Unreleased — AMB, run against ourselves without an external API

- **`docs/AMB_REPLICATION.md`** — a procedure for running the Agent Memory
  Benchmark's own protocol (its datasets, document model, prompts and judging
  rules) against Undercroft, with Claude subagents filling the two model roles
  AMB normally fills with a hosted API. No key, no Gemini, no local model
  server. Covers all five datasets with local caches and records that they are
  not interchangeable: `personamem` is multiple-choice with **no judge model at
  all**, `beam` is a continuous rubric whose `build_judge_prompt` is never
  called, and `locomo` is the only one that skips a category.
- **It carries no AMB prompt text and no AMB code, deliberately.** Their clone
  ships no LICENSE file, so the source is all-rights-reserved by default and
  must not enter a BUSL-1.1 repository or its history. The procedure asks the
  operator for their clone path and maps every prompt, schema and cached split
  from there, which also makes it portable rather than pinned to one machine.
- **First result: 1349/1540 = 87.6%** on `locomo10` at AMB's default `k=10`,
  Sonnet 5 in both roles, sealed vault, 876 drawers from 272 session documents.
  Integrity: 0 fabricated verdicts, 0 missing, 0 extra, every qid graded once.
  Not comparable to AMB's published rows — different models — and not
  comparable to our earlier Gemini-judged 72.6%, which also differed in judge,
  ingest granularity and `k`.
- **Gold-evidence recall, measured for the first time.** Using AMB's own
  `gold_ids`: all required evidence reached the context for **83.0%** of
  queries, some for 94.1%. Accuracy was 91.8% with all gold present, 68.2% with
  partial, 65.6% with none. **104 of 189 failures had every required document in
  context** — more than half of what we would have booked as a memory failure
  was the answering model. We have been reporting memory+reader as one number.
- Four defects in the harness were found before any number was believed, three
  of which would have produced a publishable-looking result: prompts written by
  us rather than read from AMB (67.9%), a `k` of 30 that fed the model a third
  of each conversation (94.4%), gold answers sitting in the answering model's
  own input file, and a judge that padded to 20 verdicts by duplicating an id —
  a grade for a question nobody answered, which passed every aggregate check and
  was caught only by reconciling verdict ids against answer ids.
- ROADMAP gains the measured retrieval gaps and the list of changes explicitly
  refused as benchmark-fitting.

## Unreleased — the security model, drawn

- **Three diagrams for the security section**, which was a wall of prose about
  the one part of the system readers most need to be precise about.
  `security-levels` puts Sealed and HmacOnly side by side artifact by artifact —
  content, embeddings, token matrices, PQ artifacts, the fts5 index, metadata,
  the row tag, the chain entry — and carries the unsealed-metadata inventory.
  `security-keys` shows HKDF deriving a separate encryption and MAC key per
  vault, the AAD every blob authenticates, rotation, and recipient-encrypted
  export. `security-integrity` walks a write, a read and an open, including the
  anchor reconciliation that separates a crash from a rollback.
- Each diagram states the boundary rather than implying there isn't one. A
  running process holds the derived keys, so an operator hosting the engine is
  inside the boundary; and anyone holding the master key can rewrite history and
  re-tag it so it verifies. The chain proves the file was not altered *by
  someone without the key* — external anchoring is what would close that, and it
  is not built.
- The section gained four headings, so it now has rail entries; it previously
  had none.
- **`build.sh` now re-derives every `<h3>` id and the whole sidebar from the
  sections**, and fails if a heading and a rail entry disagree. Adding a heading
  by hand gives it no id and no rail entry and nothing complains — the page just
  grows a heading nobody can link to. That happened while writing this change,
  which is why it is now generated rather than maintained.

## Unreleased — the architecture reference gets a language chapter and a sidebar

- **Three new diagrams covering how the engine handles languages**, which was
  the largest undocumented area of the reference: `language-tokens` (the
  six-stage retrieval fold, then the script-aware split into whole words,
  bigrams or unigrams), `language-morphology` (language resolved by
  declaration → script → the drawer's own function words, the five pairwise
  rules, and what each declaration costs), and `language-dates` (an era marker
  outranking a declared calendar, field order's four signals, ten calendars,
  and the two open gaps).
- **`architecture/index.html` now shows one section at a time behind a
  sidebar.** Ten sections had become one unnavigable scroll. Paging is added by
  script (`body.paged`), never in the markup, so with JS off or broken every
  section stays visible and the document still reads end to end; print does the
  same. Deep links, back/forward and prev/next all route through one handler.
- **`build.sh` now regenerates the inlined copies in `index.html` too**, so
  `diagrams/` is the single source and `pdf/` plus the inlined copies are both
  derived. This is not tidying — inlining by hand had already reintroduced the
  bug it prevents. A standalone SVG needs its own dark media query to be
  readable when opened directly, but **inlined, that block sets `--d-*` on the
  `svg` element and beats the `:root` values the page sets**, so the diagram
  follows the system theme while the page follows its manual toggle and the two
  disagree. The build now strips it and *fails* if an inlined copy still has one.
- **The PDF pass needed CJK and Thai fonts.** Without `fonts-noto-core` and
  `fonts-noto-cjk`, librsvg renders `พ.ศ.`, `令和`, `๒๐๒๖` and `नमस्ते` as tofu
  boxes. The browser has those families and the container did not, so this was
  a defect visible only in the PDF — check a rendered page, never just the SVG.
- Corrected two things the new diagrams surfaced in existing text. The
  relevance gate was still documented as `semantic > 0.56`, a fixed number the
  per-embedder gate had just made false. And the Arabic altitude case
  (`على ارتفاع ٢٥٠٠م`, which is **2500 metres** and reads as the year 2500) was
  written up as an accepted trade on the grounds that no string relation
  separates it from a year — which is wrong. The governing noun `ارتفاع` is
  right there in the token stream, and a year noun is *already* read as
  confirming evidence; a measurement noun pointing the other way is the same
  class of signal and is simply not consulted yet. That is a gap, not a
  principled refusal, and it is now recorded as one. What would still not be
  legitimate is a range check on the number — magnitude is not evidence of kind.

## Unreleased — the relevance gate belongs to the vector space, not to a constant

- **A model embedder used to retire the relevance gate by being installed.**
  `SEMANTIC_ADMISSION_GATE` was one `const`, 0.56, calibrated against
  `HashEmbedder` — feature hashing over surface forms puts unrelated text at
  cosine ~0, so 0.56 sat comfortably above its floor. A trained encoder does
  not. E5- and BGE-family models put *unrelated* pairs near 0.75 in the same
  `semantic` space, which is **above** the gate: the disjunct in `hits.retain`
  became vacuously true for every hit, the whole candidate set was kept, and a
  query with no good match returned whatever ranked highest instead of nothing.
  Silently, for every query in every language, by configuration rather than by
  code.
  - Now `Embedder::semantic_admission_gate()`, resolved **once per open** into
    a store field. Reading it inside `hits.retain` would have put forward
    passes in the hot path — the mistake `language_of_drawer` made last
    session with string comparisons.
  - **The default implementation measures the embedder in hand.** Fourteen
    pairs of texts that share no subject, gate = worst observed + 0.06. Reading
    what a model actually does to unrelated text is evidence; deriving a gate
    from the string `bge-m3` would be inference, and this project does not
    infer.
  - **Half the probe pairs are same-language on purpose.** Two unrelated
    sentences in one language share function words, register and syntax, and
    score well above an unrelated pair that also crosses a script boundary. A
    cross-lingual-only probe set measures the wrong floor, under-estimates it,
    and leaves the gate partly retired — the exact failure being closed.
  - The 0.06 margin is the one part that is convention rather than
    measurement: it is the shipped hash gate's own headroom (0.56 against a
    ~0.50 floor) carried across rather than re-invented.
- **The default vault does not move.** `HashEmbedder` declares 0.56 rather than
  re-deriving it — calibration would shift it by a hundredth and the battery
  pins several pairs at "a hair over the gate". `the_default_vault_gate_is_
  still_the_shipped_number` writes 0.56 out longhand, so editing the constant
  alone cannot make the test agree with it again.
- **An external vault now refuses semantic-only admission instead of borrowing
  a number.** Its `embed` is unreachable by construction and
  `search_with_vector` scores caller-supplied vectors, so every `semantic` on
  that path is a real cosine from a model this process has never seen — and it
  was being gated at `HashEmbedder`'s floor, well below where a gateway-hosted
  encoder puts unrelated text. Refusing errs in the safe direction: it can
  narrow admission, never widen it. The remedy is a declaration, not a guess.
- **A failing embedder no longer calibrates.** Both model backends report an
  inference failure as a zero vector; calibrating through one would measure the
  failure and report a hash-shaped gate near 0.56, which a later *successful*
  inference would sail straight over. Any probe embedding to zero returns
  "no semantic-only admission" instead.
- `UNDERCROFT_SEMANTIC_GATE` overrides whatever the embedder says — a number in
  `0.0..=1.0` declares the gate, `off` refuses semantic-only admission. For an
  operator who has measured their own corpus, which beats fourteen probe pairs.
  A value that parses as neither falls back to the embedder rather than failing
  the open: the fallback is the safe direction, and bricking a server on a
  typo'd env var is worse than ignoring it.
- **Measured, and exercised in both directions.** Pinned back to the old const,
  `a_high_floor_embedder_does_not_admit_unrelated_drawers` admits two unrelated
  drawers at `semantic` **0.7693** and **0.7609** against a 0.56 gate. Those
  two numbers are the bug.
- **Stated as a gap, because it is one.** No model weights exist in the test
  environment, so what is pinned is the *mechanism* — via a stand-in embedder
  whose vectors carry a shared constant component and therefore a high floor —
  and not the floor of any real encoder. The 0.75 figure for E5/BGE is a
  citation to `.handover/EMBEDDER_RESEARCH.md`, not a measurement made here.
  Max-of-fourteen is also a crude estimator: it is conservative in the
  direction that matters, but fourteen pairs cannot describe a distribution,
  and a model whose true floor is higher than anything probed will still admit
  too much.

## Unreleased — morphology gets the other half of its evidence

- **A corpus that declares nothing now reaches 100% too — the drawer says what
  language it is.** Undeclared recall goes **62.8% → 100.0%** across all
  nineteen languages, with zero pairs left to the embedder.
  - Script settles Greek, Georgian and Hangul; it cannot settle Latin, which is
    why `MorphLang` exists at all. But the DRAWER can: a text carrying `der`,
    `die`, `und`, `nicht` is German. `language_of_drawer` reads the function
    words of the candidate being scored — **evidence, not inference**, the same
    class of act as reading `พ.ศ.` beside a year. Nothing is derived from the
    shape of a word; the writer's own commonest words are read.
  - **Decisive or nothing**: the winner needs three hits and twice the
    runner-up, because `is` votes for English and Dutch alike. Where the words
    disagree the drawer says nothing and the corpus is left exactly as it was.
  - Consulted **only** where the caller declared nothing. A declaration is a
    deliberate statement about a corpus and outranks one drawer's vocabulary —
    the reverse of the era-marker precedence, and for the reverse reason: an era
    marker sits beside the very date it qualifies, a stray quotation does not.
  - Only closed-class words vote — articles, pronouns, prepositions,
    auxiliaries. Content words travel between languages and a loanword should
    not get a vote. Portuguese is identified by its contractions (`da`, `do`,
    `ao`, `na`) precisely because `que`, `para` and `mas` vote for Spanish too
    and so decide nothing.
  - **Two controls flipped from `Apart` to `Cost`, and that is the feature.**
    Dutch `kop`/`kopen` and `man`/`manen` now merge in an undeclared Dutch
    drawer, because the drawer identifies as Dutch and `-en` is Dutch's known
    price. What the engine no longer does is hand Dutch text the English ending
    set merely because the caller said nothing.
  - **The blind union was tried first and failed**: all eight Latin tables broke
    5 controls, the Romance subset broke 2 (`cover`/`cove`, `cover`/`coven`).
    Applying every table to every Latin word is not the same as knowing which
    language the text is in.

- **A corpus that declares nothing now gets 86.4% instead of 62.8%.** Five
  languages were silently degrading for callers who never set `language`:
  measured undeclared, Greek 40.8%, Russian 16.7%, Hindi 25.0%, Georgian 33.3%,
  Korean 80.0% — against 100% each when declared. All five now read **100%
  undeclared**, and pairs left to the embedder alone fall from 21 to 9.
  - `morph_lang_by_script` applies a table wherever its own script appears.
    **This is not the inference the never-guess contract forbids**: deriving a
    *calendar* from script is forbidden because Thai script writes Gregorian
    dates constantly, so the script says nothing about the claim. Here it is
    reversed — a Greek `-ος` ending can only ever match a Greek word, so
    applying the Greek table asserts nothing the characters do not already say,
    and applying it to an English corpus costs exactly zero.
  - **Two of the five are an approximation, and are labelled as one.** Greek,
    Georgian and Hangul are used by one language apiece, so the mapping is a
    fact. Cyrillic is also Ukrainian, Bulgarian and Serbian; Devanagari is also
    Marathi and Nepali. Those two get the majority language's table, whose
    endings the family largely shares — approximate morphology instead of none,
    and an ending that is wrong for the corpus simply fails to match.
  - `suffix_family` is deliberately **not** widened. Its endings are Latin, and
    Latin is exactly the case no script can settle: German needs `-er`, English
    cannot have it. The eight Latin-script languages still require the
    declaration, and that is irreducible rather than unfinished.

- **Arabic reaches 100%, and so does every other language: 191/191.**
  Eight Arabic suppletives and irregular plurals join `IRREGULAR` — `امرأة`/`نساء`
  (م-ر-أ against ن-س-و), `إنسان`/`ناس`, `فم`/`أفواه`, `أخ`/`إخوة`. Their plural is
  built on a *different root*, so no root table reaches them, exactly as no
  suffix rule reaches `go`/`went`.
  - **This was an inconsistency, not a finding.** Suppletion had been put in
    `IRREGULAR` for eight languages already — `человек`/`люди`, `βλέπω`/`είδα`,
    `gehen`/`ging` — while Arabic's was written up as needing a multilingual
    encoder. Same class, same table.
  - Written in the **folded** orthography, because that is what the rule sees:
    `search_key` maps `ة`→`ه` and every hamza-bearing alef to `ا`, so `امرأة`
    arrives as `امراه`. The citation form would have matched nothing — the exact
    failure the Greek final sigma caused twice, checked this time before writing
    rather than after measuring.
- **Arabic 85.7% → 97.6%, by roots rather than by shape.** The whole
  19-language audit now reads **190/191 = 99.5%** on the lexical channel, with
  zero pairs resting on the embedder.
  - Arabic pours a three-consonant ROOT into a template — ك-ت-ب gives كتب,
    كتاب, كاتب, مكتوب, كتابة — so `ar_root_family` asks only whether two words
    are explained by the same root. 144 roots × 20 templates, generated once.
  - **It is an allowlist, and that is the whole safety argument.** A form the
    table cannot generate matches nothing. `بيت`→`بيوت` and `يجب`→`يجيب` are the
    same string operation, so no rule over surface shape could ever admit one
    and refuse the other — but only the first is generable from a known root.
  - **Half as promiscuous as the rule it sits beside**: mean 3.25 against the
    shipped skeleton rule's 6.67, linking nothing at all for 86.2% of queries,
    while recovering five of the six drops. Every axis improves at once.
  - `يجب`/`يجيب`, `أجل`/`أجمل`, `ليس`/`لويس`, `لكن`/`المكان` and `سيارة`/`أسرة`
    are pinned as controls — each was a false merge under one of the three
    rejected subsequence families.
  - **No dependency, and none possible.** Every mature Arabic morphology
    resource is GPL, research-only or LDC-non-redistributable, including CAMeL
    Tools, whose code is MIT but whose database is not. The roots are ordinary
    vocabulary and the templates are textbook description — facts about the
    language, not anyone's compilation.
  - Remaining, in 191 pairs: **one**. `امرأة`/`نساء`, م-ر-أ against ن-س-و — two
    roots in one paradigm, which is suppletion and reaches no morphology in any
    language.

- **Eighteen of nineteen languages reach 100% of their audited paradigm on the
  LEXICAL channel.** Aggregate 191 pairs: **55.0% → 96.9%**, and the count of
  pairs carried by the embedder alone falls from 20 to **zero**. Only Arabic is
  short, at 85.7%, and its six are measured-unreachable rather than untried.
  - **Greek 83.7% → 100%**, Russian 66.7% → 100%, French 85.7% → 100%,
    English 80.0% → 100%.
  - `derivations_for` — endings whose stem must be LONGER, because the ending is
    short enough to be an accident on a short word. Two languages, three
    endings, gated at five characters: English `-ion` separates
    `encrypt`/`encryption` (7) from `mill`/`million` (4); French `-e` separates
    `grand`/`grande` (5) from `port`/`porte` (4). This IS a length threshold —
    the instrument that produced the floor-8→5 mistake — so it is deliberately
    confined and every pair it decides is pinned as a control on one side or
    the other.
  - **The Greek final sigma cost 40 points across two commits.** Written into
    the table it matches nothing, because `inflection_family` canonicalises its
    inputs to the ordinary sigma. It was fixed once, then reintroduced by the
    next batch of entries and had to be fixed again — a table whose entries are
    invisible to the rule that reads them looks exactly like a table that is
    merely incomplete.
  - 38 negative controls, all green, now including the price of *declaring*
    Dutch (`kop`/`kopen`, `man`/`manen`) beside the proof that an undeclared
    corpus is untouched.

- **Sixteen of nineteen languages now reach 100% of their audited paradigm.**
  Aggregate lexical recall over 191 pairs: **55.0% → 89.5%**. Three mechanisms
  finished the job, each language-scoped through `MorphLang`:
  - `agglutinative_family` — prefix-anchored, because `strip_suffix` cannot see
    a four-morpheme stack. Turkish `kitaplarımızdan` is `kitap`+`lar`+`ımız`+
    `dan` and no fixed ending matches it; what identifies it is that the
    remainder *begins* with a real plural morpheme. **Turkish 16.7% → 100%**,
    Korean 40% → 100%. Single-vowel suffixes are excluded deliberately: Turkish
    dative `-a`/`-e` would merge `kar`/`kara`, which is a control.
  - Inflection tables for Dutch, Hindi and Georgian — all three to **100%**.
  - ~60 more `IRREGULAR` entries: the suppletive cores of Italian, French,
    Portuguese, Dutch, Russian, Greek, Persian and Korean.
  - **Greek 38.8% → 83.7%, and 24 of those points were one character.** The
    table was written with the FINAL sigma while `inflection_family`
    canonicalises inputs to the ordinary one, so every `-ος` noun in the
    language — the largest declension there is — matched nothing while the
    entries sat there looking correct. Greek also gained the aorist augment and
    the labial/velar/`-ζω` stem mutations.
  - **Persian 83.3% → 100%** by naming the token that exists: the ZWNJ in the
    present stem is not alphanumeric, so the segmenter splits it and the
    drawer's token is the bare stem, never the citation form.
  - Still short, and measured: Arabic 85.7% (six templatic pairs, priced and
    rejected in `ARABIC_SKELETON_DECISION.md`), French 85.7%, English 80.0%
    (`encrypt`/`encryption`, seven characters against a floor of eight),
    Russian 66.7%, Greek 83.7%.

- **Substitutive morphology, which is what almost everything left was.** Three
  languages measured **0.0%** on the lexical channel — Italian, Russian, Dutch —
  and the reason is structural: every rule the engine owned was ADDITIVE.
  `libri` is not `libro` plus anything; it is `libro` with its ending replaced.
  Italian, Russian, Greek and every Romance verb paradigm work this way.
  - **A generic shared-prefix rule cannot do this job, at any threshold.**
    `libro`/`libri` shares four characters and differs by one on each side — and
    so does `porto`/`porta`. Identical shape, so any threshold admitting the
    plural admits the false pair. What separates them is not length but
    *identity*: `o`→`i` is an Italian plural and `o`→`a` is not.
  - So `inflections_for` is a table of the mappings each language actually has,
    scoped by `MorphLang` — data one can read and check, rather than a number
    one can only tune. Six languages added: Italian, Spanish, French,
    Portuguese, Russian, Greek.

  | language | lexical before | after |
  |---|---|---|
  | Spanish | 57.1% | **100.0%** |
  | Italian | **0.0%** | 83.3% |
  | Portuguese | 33.3% | 83.3% |
  | French | 28.6% | 71.4% |
  | Greek | 38.8% | 53.1% |
  | Russian | **0.0%** | 50.0% |

  Aggregate lexical over 191 pairs in 19 languages: **55.0% → 69.1%**, with the
  pairs carried by the embedder alone falling from 20 to 12.
  - **Zero new false merges.** `caso`/`casa`, `porto`/`porta`, `город`/`горох`,
    `сообщение`/`сообщество` all stay apart, and are now pinned in the shipped
    controls (32, up from 27) with the language declared — a rule scoped to a
    language is not exercised at all by an undeclared control.
  - **One named price:** Italian `pesca`/`pesce` merges, because `a`→`e` carries
    the entire feminine plural. Recorded as `Verdict::Cost`, exactly as
    παράδειγμα/παράδεισος is for Greek.

- **Spanish reaches 100%, and the untested Latin languages are now measured.**
  27 Spanish irregular verb forms join `IRREGULAR` (`ser`/`fue`, `ir`/`va`,
  `tener`/`tiene` …), taking Spanish from 85.7% to **100%** of its audited
  pairs. Stated honestly: that is 100% *admitted* and **4/7 lexical** — the
  three `hablar` forms are substitutive and remain semantic-only.
  - **French, Italian, Portuguese and Dutch had never been measured at all.**
    First numbers, lexical channel only: Portuguese 33.3%, French 28.6%,
    Dutch 20.0%, **Italian 0.0%**.
  - **Italian is the new Hebrew.** Not one pair reaches a lexical channel,
    because Italian inflection **substitutes** rather than appends: `libri` is
    not `libro` plus anything. Every additive rule the engine owns is
    structurally blind to it. Fixing it needs a Romance prefix-family rule with
    a threshold far below Greek's 7 — and that threshold is exactly what needs
    controls, since `caso`/`casa` and `porto`/`porta` are one character apart too.
  - **`-en` is now German-only, because Dutch caught it.** In the common set it
    admitted `kop`/`kopen` (cup / to buy) and `man`/`manen` (man / manes) while
    buying English nothing — every English `-en` form is irregular and named in
    the table. Both are pinned in the shipped controls under
    `dutch (undeclared)`, an undeclared corpus being exactly what gets the
    common set. An ending has to earn its place in every language that might be
    undeclared, not only the one it was added for.
  - Aggregate over the 167-pair audit: **64.1% → 70.1%**, seven languages at
    100% (English, German, Spanish, Hebrew, Japanese, Chinese, Thai).

- **German reaches 100%, because the caller can now say it is German.**
  `MorphLang` joins `SearchOptions`, driven by the request's existing
  `language` field — one declaration, two consumers: the date scanner (`en`,
  `ar`) and morphology (`en`, `de`). Declared German enables `-er`, and
  `Kind`/`Kinder`, `Haus`/`Häuser` and `Buch`/`Bücher` all reach the **lexical**
  channel; `Bücher` had been semantic-only. Measured end to end: German
  **50% → 100%** of its audited pairs, all eight on `lexical_morph`.
  - Read-time and declared, never detected, exactly like `calendar` and
    `date_order`. German and English share a script, so nothing in the bytes
    says which endings are legal. Undeclared behaves exactly as before.
  - **The price of declaring is pinned by test**: under `MorphLang::German`,
    `flow`/`flower` *does* meet. That is correct — the caller said this corpus
    is German — and it is precisely why the choice is per request.

- **English reaches its own inflected forms.** Two pairwise rules, neither a
  stemmer and neither a floor. `suffix_family` asks whether one word is the
  other plus one ending from a **closed six-item set**, with final-consonant
  undoubling so `running` reaches `run`. `IRREGULAR` is a table of ~110 forms no
  rule over letters can relate — English suppletion and strong verbs, irregular
  plurals, German strong verbs — because `go`/`went` is not a spelling variant
  of a stem and 58% of all remaining audit drops are exactly this class.
  - **Shape, not length, is what makes a 3-character stem safe.** Containment at
    floor 3 asks "does `run` appear anywhere in this word" and answers yes for
    `brunt`, `prune`, `runway`: measured, mean **33.3** English words per query
    and **68.5** German, peaking at 1,996. `suffix_family` asks "is this exactly
    `run` plus one of six endings" and measures **1.08** and **0.98**, bounded at
    5 links. Unlike a stemmer it builds no equivalence class, so no single bad
    ending can poison one.
  - **`-er` is excluded, and it cost German its plurals.** `Kind`/`Kinder` and
    `Haus`/`Häuser` need it. Enabling it admitted `flow`/`flower`, `tow`/`tower`,
    `corn`/`corner`, `butt`/`butter` and `cow`/`cower` — five false pairs for
    two real ones, because English also builds agent nouns with `-er`. One
    suffix set cannot serve two languages that share a script and disagree; that
    needs a **language input**, the same wall the containment floor hit. The
    umlaut would have discriminated (`Häuser` carries one, `flower` cannot) but
    `search_key` folds it away first, and `Kind`/`Kinder` has none anyway.
  - **Promiscuity did not catch `-er`; the controls did.** Adding it moved the
    population figure by **+0.21 links per query** — indistinguishable from
    safe. The negative controls failed it five times over. A population metric
    is no more a precision test than a recall metric is.
  - **A wrong belief, corrected by asserting the channel.** `encrypt`/`encryption`
    reads as *admitted* in the audit and reaches **no lexical channel at all**:
    `encrypt` is seven characters, one below `contains_a_long_word`'s floor of
    eight, so it has only ever been a semantic hit. Every per-language audit
    percentage mixes lexical and embedder admissions and none of them is a
    lexical-recall figure.

- **Negative controls, at last.** The 167-pair morphology audit that drove the
  comparison layer contains **no false friends** — every row in it is a true
  relation, so a rule admitting every string pair would score 100% on it. That
  is precisely how the containment floor went 8 → 5 on a "safe" reading and
  admitted `other`/`mother`. `false_friends_stay_apart` closes the gap: 20 known
  false friends across English, German, Arabic and Greek, measured end to end
  through the real `search` at realistic drawer length, asserting only the
  **lexical** channels — a semantic-only hit is the embedder's opinion, not a
  rule's, and pinning it would make this a test of `HashEmbedder`.
  - It **fails in both directions**. A pair that gains a lexical channel is a
    new over-admission; a pair that loses one is good news the test refuses to
    absorb silently.
  - Verified load-bearing: de-scoping `greek_word_family` to all scripts makes
    `university`/`universe`, `conversation`/`conversion`,
    `internal`/`international` and `processor`/`procession` admit on
    `lexical_morph` at 0.309, and the test names each one.
  - **Three Arabic false friends already admit** and are pinned as such:
    `سيارة`/`أسرة`, `كريم`/`كرم`, `قطار`/`قطر` all share a consonantal skeleton
    once the weak letters ا و ي are stripped. The audit named them and never ran
    them; this is the first measurement of the shipped rule's price.
  - Padding is asserted disjoint from every control word. The first run of this
    instrument reported `πολύ`/`πόλη` — the pair `lib.rs` records as having
    killed Snowball Greek — as *already related*, because the filler literally
    contained `πολύ` and the query matched its own padding. A contaminated
    control fails flatteringly, which is the dangerous direction.

## Unreleased — the comparison layer, and dates that are declared rather than guessed

- **An era the writer typed outranks the calendar the caller declared.** `พ.ศ.`,
  `ค.ศ.`, `هـ`, `هجري`, `ميلادي`, `民國`, `公元`, `西暦`, `令和`, `平成`, `昭和`,
  `大正`, `明治` and their unabbreviated forms are read wherever they stand
  beside a year — before it, after it, or glued to it. A declaration is a
  statement about a corpus; a marker is the writer's statement about one date,
  so the more specific evidence wins. This is still reading and never inference:
  the era is written down, exactly as an unambiguous `13/05` states a field
  order by example. Markers that disagree on both sides settle nothing and leave
  the declaration standing, which is what `order_demonstrated_by` already does
  for a contradictory field order.
  - **The tokenizer was the blocker, and Latin is deliberately not fixed.**
    `tokens()` kept any run of alphanumerics together, so `1447هـ`, `2568พ.ศ.`,
    `ค.ศ.2023` and `令和6年` arrived as one mixed token in which the digits were
    not a number and the marker was not a marker — a fully specified date read
    as nothing at all. The break is taken only where a digit meets a letter from
    a script that attaches without a delimiter. The delimiting scripts glue
    **identifiers** — `covid19`, `mp3`, `H1N1`, `5th` — and breaking those would
    hand `count_of` a bare number that the `<n> <unit> ago` arm reads as a count,
    inventing a date out of a product name. `-` and `/` stay opaque to the break
    or `٢٠٢٣-أيار-٠٧` would split at its month name; `.` is transparent so that
    `ค.ศ.2023` breaks after the marker.
  - **A bare year is a mention only where a marker names it.** `2568` alone is a
    quantity, a room, a part code; `พ.ศ. 2568` is the year 2025 and resolves as
    a whole-year period. It is the trade `month_name_is_deliberate` already
    makes for a bare "May", and the only route by which `令和` and `民國` mean
    anything, since those eras are written with a year and no month at all. A
    two-digit year is still never given a century, marker or no marker.
  - **Japanese eras are bounded, because their first and last years are
    partial.** 令和 began on 1 May 2019, so `令和1年` is that May to December —
    reading it as the whole of 2019 would claim four months that were `平成31年`,
    a wrong date rather than a rounded one. `平成31年` ends 30 April 2019 and
    `昭和64年` ran seven days. Declarable too: `reiwa`, `heisei`, `showa`,
    `taisho`, `meiji` on `/v1/search` and `undercroft_search`.
  - **A marker that is also an ordinary word is read in context, because
    Arabic is.** Bare `م` and `ه` abbreviate ميلادي and هجري — and `م` is also
    *metres*, `ه` a list letter — so the word alone settles nothing. Two signals
    confirm it, strongest first, the shape `DateOrder` already uses. **A year
    noun governing the number**: `سنة ٢٠٢٣م`, `عام ١٩٩٥ م`, `في العام ٢٠٠٠م`,
    spaced or glued. The vocabulary is `AR_UNITS`' own `Unit::Year` set through
    `ar_unit`, so it inherits every spelling, plural and article the relative
    arms already match — confirming evidence, never a blocklist, which is the
    trade the `من` guard makes and for the reason it records. Failing that,
    **the marker glued to the year with no separator at all**: `١٩٩٥م` is how
    Arabic writes a year, `١٥٠٠ م` with the space is how it writes a quantity,
    and SI asks for that space. A spaced marker with no year noun stays unread.
  - **The cost of the glued signal is real and pinned by test.** Arabic
    geography writes `على ارتفاع ٢٥٠٠م` — an altitude — glued, and it now reads
    as the year 2500. Nothing in the string separates the two, and reading the
    number's *size* would be the inference this module refuses. The collision is
    confined to four-digit quantities written without their space, the Gregorian
    gate wanting four digits and `٥٠٠م` having three. The same trade day-first
    takes: a wrong year is in the record and correctable, where silence is
    neither.
  - **Two gaps, stated rather than glossed.** The month-name arms in both
    scanners build Gregorian-only and always have, so a *declared* calendar
    never reached them either. CJK numeric dates (`2023年5月7日`) are still
    unparsed.
- **A date's calendar and field order are DECLARED, never inferred.** `Locale`
  gains `calendar` and `date_order` beside `language` and `week_start`, all
  read-time, so an already-ingested corpus answers correctly the moment a caller
  declares its conventions — no migration, no re-embed, no FTS rebuild.
  Calendars: Gregorian, Buddhist (`-543`), Minguo (`+1911`), Hijri
  (**Umm al-Qura**, the Saudi civil calendar) and Jalali. The last two are not
  renumbered Gregorian years — lunar drift is ~11 days a year and Jalali turns
  at the vernal equinox with different month lengths — so conversion is
  whole-date and delegated to `calendrical_calculations` (Apache-2.0, three
  transitive deps, pure algorithm with no data files, Unicode Consortium /
  ICU4X). Tabular Hijri was the easy implementation and is wrong by a day or two
  against what documents actually carry.
  - **Two guesses removed.** `iso_token` subtracted 543 from any year written in
    Thai numerals, so `๒๐๒๖-๐๕-๐๗` — an ordinary Gregorian 2026 — resolved to
    **1483**, in a function whose docstring said "exact rather than heuristic".
    A numeral system is not a calendar. The next attempt guarded on range and
    made `2566-05-13` vanish instead, losing the dates in a novel, an astronomy
    note or a century-scale plan. `GREGORIAN_MAX = 2199` is retired: it existed
    only to stop Buddhist 2566 reading as Gregorian 2566, and once a calendar
    could be declared it began causing the harm it was built to prevent.
  - **Field order takes four signals, strongest first:** declared on `Locale`;
    demonstrated by the text (`13/05` can only be day-first, so an unambiguous
    date states the writer's convention by example — evidence, not inference);
    implied by the language (CLDR gives `ar` as `d/M/y` in every Arabic
    territory, while English splits US/Commonwealth and implies nothing); and
    failing all three, day-first, the majority convention worldwide. This
    reverses a considered position — the module recorded `05/07/2023` unresolved
    because "picking one would be a coin flip reported as a fact" — on the
    grounds that a memory returning no date is unusable. Cost, pinned by test: a
    US corpus that never declares `MonthFirst` reads `07/05` as 7 May.
- **Ordinary Arabic prose stopped inventing dates.** `AR_AGO` contained `من`,
  among the commonest words in the language, and the branch required no
  confirming evidence — so `الخامس من الشهر` ("the fifth OF THE MONTH") resolved
  to a month before the anchor and `أكثر من ثلاثة أيام` ("more THAN three days")
  to three days ago. `ar_ago_is_temporal` now needs clause-initial position, a
  count reaching a unit, and no range marker closing it: an allowlist, because a
  blocklist of quantifiers fabricates on the first one nobody enumerated while an
  allowlist fails by going quiet. Stated cost: a mid-sentence
  `كان الاجتماع من ثلاثة أيام` is no longer read. Also `قبل الشهر الماضي` is
  "before LAST month" — `قبل` yields the noun to a following period modifier
  instead of resolving one unit back and stranding `الماضي`.
- **Numeric dates read in any digit system** — Arabic-Indic, Persian,
  Devanagari, Bengali, Thai, fullwidth. `٢٠٢٣-٠٥-٠٧` was unread *even under*
  `Language::Arabic`, because the parsers used `str::parse`, which is ASCII-only:
  the numeric channel was closed to exactly the languages whose word-forms the
  module also cannot read. And a month NAME joined by hyphens now reads —
  `2023-May-07`, `٠٧-أيار-٢٠٢٣` — where both languages previously yielded
  **nothing**, because `-` is a token character so the whole date arrived as one
  token the digit readers declined and the month-name arms never saw.
- **Six readers now agree about the same date.** `iso_token`, `dmy_token`,
  `named_date_token`, both English month-name arms and the Arabic one gated years
  at two different bounds, so `iso_token("2566-05-13")` refused while
  `May 13, 2566` one screen away resolved. Pinned as an invariant rather than a
  constant, since the constant has since been right, wrong and removed while the
  invariant never changed.
- **Hebrew was the only language in a 15-language audit to admit nothing at
  all** — 0 of 8 pairs, at every drawer length, on every channel. It writes with
  spaces, so `Script::Other` treated it as delimiting, which handed it an
  8-character floor for 3-character stems *and* excluded it from `shares_a_stem`.
  Its clitics attach with no delimiter, exactly as Arabic's do. Now
  `Script::Hebrew`, non-delimiting, with the points (niqqud) folded for the same
  reason the Arabic harakat already are — `maqaf`, `paseq` and `sof pasuq` are
  deliberately excluded, being delimiters.
- **One morphological rule table, dispatched per script.** The engine had a
  single relation — substring containment — with one global constant, and across
  15 languages and 189 real paradigm pairs it dropped **51.5%** of morphological
  relations at realistic drawer length. Three different shapes, one constant:
  Arabic's root is a *subsequence* (`كتب` inside `كتاب`), Greek's ending
  *substitutes* so the stem is a shared *prefix*, and Turkish is purely additive
  yet scored 16.7% because its stems are shorter than the floor. Arabic and
  Hebrew are one family and take one tool — a consonantal skeleton, equality at a
  ≥3-radical floor, measured **7× tighter** than the containment rule already
  shipped. Greek gets a script-scoped shared-prefix rule; Latin does not, because
  its documented cost (`conversation`/`conversion`) is Latin and the nine
  beneficiaries are Greek.
  - **A recall-only measurement is not a precision justification.** The
    delimiting floor was lowered 8→5 on a promiscuity figure (3.03 mean links for
    English) that counts *how many* words a rule reaches and cannot see whether
    any of them is correct. Measured against the engine afterwards it admitted
    `other`/`mother`, `count`/`accounting`, `press`/`depression`,
    `stand`/`understand`. Reverted; Turkish, Hindi, Spanish and English return to
    their prior numbers, and reaching them needs a per-LANGUAGE floor, since
    Turkish and English share a script and disagree about the right value.
- **A shared fragment is not evidence — Arabic was admitting the whole vault.**
  Measured against the shipped code on a real 50k-word Arabic frequency corpus
  with control drawers: **one Arabic content word admitted 74.3% of a
  120-drawer vault.** The same code, same drawer length, on Greek: 6.9%. A
  10.8x difference produced by one line in `script.rs`. Arabic is
  non-delimiting, so `segment` emits character bigrams for the *query* as well
  as the document, bigram met bigram by literal equality, and literal equality
  fills the exact slot — so a shared two-character substring in an unvocalised
  abjad was read as "the drawer said your word". It is the failure
  `is_logographic` documents for unigrams, one n-gram order lower, in a script
  the module claims to serve. The grades were indistinguishable, which is the
  proof: `كتاب`/`كتب` (book/books) shares one bigram and ranked 13, while
  `كريم`/`كرم` (a name / generosity) ranked **1** and `مصر`/`مصرف`
  (Egypt / bank) ranked **2**. `Segmented` now flags n-grams from
  non-delimiting, non-logographic scripts and they are refused the exact slot;
  Han is deliberately unflagged, because there a character is a morpheme.
  Clitics are carried instead by whole-word containment (`shares_a_stem`, ≥3
  chars, into `lexical_morph`), so `كتاب`→`الكتاب`, `مكتبة`→`بالمكتبة` and
  `معلم`→`المعلمون` still work — on a contiguous chain over the stem rather
  than one fragment. The 3-character floor runs at 0.519 morphological
  precision (0.820 at four, 0.911 at five); it is labelled and discounted, and
  it admits, which is why that number is stated. Verified **monotone** over
  665,750 query/drawer pairs — it admits nothing the previous code did not, so
  it cannot introduce a new false merge. No dependency, and no identity bump:
  `segment`'s tokens are byte-identical and only the flags are new.
- **Recorded, not fixed: stripping Greek accents over-merges in the exact
  channel.** `πότε` (when) folds onto `ποτέ` (never), and `καλά` onto `κάλα` —
  one token, so they meet by literal equality and are admitted at rank 1. Not a
  bug to revert: the accent strip is what lets an all-caps or carelessly-typed
  Greek query find anything, and it is what makes our fold comparable to
  Lucene's accent-stripped Greek analysis. It is a cost of the fold, it is
  pinned by test, and it is written at `search_key` because five rounds of
  review looked past it.
- **A key for finding a word, distinct from a key for being it.** `match_key`
  answers "is this the same text?" — it is what `fingerprint()` compares, so
  folding there would make 中國 and 中国 the same *drawer* for dedup, and it
  deliberately pins `ﬁ != fi`, `① != 1` and surviving tatweel. Retrieval asks
  a different question, and the answer was no in ways that were not bad
  rankings but empty result sets: `قَرَأتُ الكِتَابَ` shared no whole-word
  token with `الكتاب`, `İzmir` tokenized to `["zmi"]`, `Straße` never met
  `strasse`, `٢٠٢٣` never met `2023`, a PDF's `ﬁnal conﬁguration` never met
  `final configuration`, `ΑΘΗΝΑ` never met `Αθήνα`. `search_key` is that
  second key, and every tokenizer now uses it — `match_key` is left to dedup.
  Order carries the design: lowercase precedes the mark strip because `İ` is
  not a mark and lowercasing *manufactures* the U+0307 the strip removes,
  which fixes Turkish with no Turkic tailoring and so keeps ı/i minimal pairs.
  Not blanket NFKC: an alphanumeric-to-alphanumeric guard rejects `ﷺ` (18
  chars, category So — it would inject a phrase into every religious drawer's
  term frequency) and `﷼` (Sc, a delimiter that would become letters);
  CJK radicals invert that guard, being themselves So. Cyrillic gets almost
  nothing on purpose — only a *loose* stress mark and `ё→е`, since a blanket
  decompose-and-strip would turn `й` into `и`. ZWSP, ZWNJ and ZWJ are pinned
  as **not** stripped: ZWSP is Khmer's word delimiter, ZWNJ splitting
  `کتاب‌ها` yields an exact hit on the stem, and ZWJ is contrastive in
  Malayalam. Every fold's conflation is pinned by test rather than left to a
  bug report: على/علي, كتابة/كتابه, Masse/Maße, πότε/ποτέ, все/всё. They are
  taken because the unmarked spelling is the default register in each of those
  orthographies — the corpus already made the merge.
- **Evidence that admits a drawer, kept apart from evidence that ranks it.**
  The relevance gate was `lexical > 0.0`, and `lexical` mixed a literal term
  match with a forgiven edit — and now with a fold that makes two spellings
  one token. On one channel each of those is a *membership* decision, which is
  how a shared alef made `قطار` match `المستشفى`. `SearchHit` now carries
  `lexical_exact`; both gates test it, ranking keeps the blend, and
  approximate evidence contributes at half weight capped at one occurrence per
  query slot — uncapped, `document documents documented documenting` reaches
  tf = 4 against a query for `documentation` while the drawer that says
  `documentation` reaches tf = 1. The cost is deliberate: a drawer whose only
  relationship to the query is morphological must now also clear
  `semantic > 0.56`.
- **Morphology, the half of it that is reachable without a language tag.**
  `same_word_family` matches when one word is nearly a prefix of the other —
  ≥7 shared characters, divergent tail ≤3 on the shorter side. That connects
  `documentation`/`document`, `encryption`/`encrypt`,
  `Konfiguration`/`Konfigurationen`, `ბიბლიოთეკა`/`ბიბლიოთეკაში`. The
  thresholds were chosen by what they *reject*: a prefix of 6 would admit the
  systematic `-tive`/`-tion` class (`positive`/`position`,
  `creative`/`creation`) which is length-symmetric, plus
  `сообщение`/`сообщество` and `κατάσταση`/`κατάστημα`. It feeds the
  approximate channel only, so the three false pairs that survive
  (`conversation`/`conversion`, `processor`/`procession`,
  `internal`/`international`) can reorder a result set but never populate one.
  **Named as gaps, not refusals:** Russian nominal case and Greek inflection
  (`книга`/`книге` share 4 characters, and so do `город`/`горох` — the
  information separating them *is* Russian morphology), English short stems
  (`running`/`run`), German compounds on the BM25 leg (a suffix relation; the
  embedder's trigrams already carry it on the cosine leg), and stem-rewriting
  morphology — Arabic broken plurals and Korean conjugation share **zero**
  n-grams at n=3, 4 or 5, verified by direct computation. Only a multilingual
  model reaches those.
- **The FTS prefilter cut the drawer it was meant to find, again.**
  `drawers_fts` was external-content over raw bytes under unicode61, which
  folds Latin diacritics and `ς→σ` and nothing else — so it disagreed with
  folded query terms on ß, ё, Turkish İ and every Arabic mark. Query `izmir`
  against a drawer saying `İzmir` returned a non-empty *wrong* set, which
  became `seq IN (...)` and removed the right drawer from the scan and the
  cosine path with it. The obvious query-side guard is dead code: every term
  `needs_full_scan` sees has already been folded by `tokenize`. So the index
  is folded instead — a standalone fts5 table over `search_key(content)`,
  rebuilt on a `fts_key_version` mismatch, which makes unicode61's token set a
  superset of ours over the same text: it can over-return, which the scan
  filters, but never under-return.
- **A number is never a typo.** After the digit fold `١٠٠٠٠٠` is ASCII
  `100000`, which cleared the byte gate and fuzzy-matched `200000`, `100001`
  and `190000`. All-numeric terms no longer forgive an edit, which also closes
  the same latent hole for numbers that were always Latin-typed.
- **The embedder was reading a different alphabet than the tokenizer.**
  `HashEmbedder::tokens()` had its own copy of the split and applied neither
  `match_key` nor segmentation, so the cosine leg disagreed with the lexical
  one about what a word is. Composed `أحمد` and its decomposed twin shared one
  feature of three; `ёلка`, `οδός` and `más` shared **none**. On a sealed
  vault that is not a second opinion — cosine is the only retrieval signal
  there is. It now uses exactly the store's rules, which changes the vectors
  and therefore the embedder's identity: **`undercroft-hash-v1` →
  `undercroft-hash-v2`**.
- **Upgrading the binary migrates the vault instead of refusing to open it.**
  A recorded identity that no longer matches was an error telling the user to
  set `UNDERCROFT_FORCE_EMBEDDER=1` and run `repair` — reasonable for a model
  swap the user chose, wrong for a built-in embedder that changed underneath
  them. Known, dimension-preserving upgrades of the default embedder now
  re-embed on open. Embeddings are derived data and carry no HMAC, so the walk
  never touches a drawer tag or the audit chain — this is why a re-embed is
  not a rotation. It is batched (a 100k-drawer vault must not hold one write
  lock for the whole pass), idempotent, and records the new identity **last**,
  so an interrupted migration simply runs again. Every drawer is read through
  `get`, so each record's HMAC is verified on the way past. Swaps to or from a
  *model* embedder are still refused — that is hours of inference and a
  decision the user should make.
  Three things the migration is careful about, each found by reviewing it
  rather than by running it:
  **One damaged drawer does not cost you the rest.** Verifying every record on
  the way past means a corrupt or tampered row makes the walk fail, and a walk
  inside `open` failing means the vault does not open *at all* — including for
  `verify`, the one tool that can name the damage, and `repair`, the one that
  can clear it. Unreadable rows are now skipped with a warning naming the id,
  the rest migrate, and the vault opens. (`search` is still intolerant of a
  corrupt row; that predates this and is not addressed here.)
  **`UNDERCROFT_FORCE_EMBEDDER=1` comes first.** Checked after the migration
  branch it was dead code for the only transition that does fallible work,
  which removed the documented escape from exactly the situation needing one.
  **A read-only role does not migrate.** `serve --read-only` guards its write
  *routes*, but every route opens the store, so the migration would have
  performed a bulk rewrite the operator explicitly forbade. `open_read_only`
  warns and leaves the vectors alone; the lexical leg still serves.
- **A remote index went on answering with vectors from a space that no longer
  existed.** `index_collection()` is derived from the vault id alone, so
  nothing recorded which embedder a mirror was built with. After an upgrade the
  query was embedded locally under v2 and matched against v1 vectors on the
  remote: candidates come back effectively at random, local re-scoring then
  drops them, and the user gets an empty result from a vault that holds the
  answer — with no error. `index push` now records the embedder, and
  `search_with_index` refuses a mismatched mirror and names the fix. This one
  is not specific to v1→v2; it was wrong for any embedder change.
- **A one-character CJK query was a wildcard.** `北` is one insertion from
  *every* bigram containing it, so a single occurrence in a drawer about
  Siberian tigers (东北虎) was counted three times — 北, 东北, 北虎 — and
  competed with genuine 北京 hits. The insertion/deletion tolerance now
  requires two characters on both sides, which keeps 한국어/한국어는 and
  北京/北京市 and drops only the wildcard.
- **A stale PQ codebook outlived the vectors it encoded.** `repair` re-embedded
  without invalidating the quantized index, whose codes and codebook describe
  the old vector space. That failure is silent: the index does not error, it
  returns the wrong candidates. Both `repair` and the new migration now drop
  `drawer_pq` / `pq_page` / `pq_meta` and let the existing self-heal rebuild.
  ColBERT token matrices and the FDE index are built from the late-interaction
  model rather than this one and are correctly left alone.
- **A document containing the query term verbatim was scored as containing a
  different word.** In `bm25_raw` a token filled the first query slot it
  matched, and exact and one-edit matches had equal standing. For a query like
  `دفتر دفاتر`, a document saying `دفاتر` was counted as evidence for `دفتر`
  while `دفاتر` — literally present — kept `df = 0` and therefore maximal IDF
  for a term that occurs. Exact matches now claim their token first.
- **A query for a word the drawer contains returned nothing.** Not a bad
  ranking — an empty array that reads as an empty vault. Tokenizing splits on
  `!char::is_alphanumeric()`, which finds a boundary only in scripts that
  mark one. `我昨天去了北京参加会议` was **one token**, so a query for `北京`
  matched no term; the hash embedder shared no feature either, giving cosine
  exactly 0.0 and `semantic` exactly 0.500; and the relevance gate
  (`lexical > 0.0 || semantic > 0.56`) then dropped the only drawer holding
  the answer. Measured, on the real tokenizer: `北京` 0/1, `東京` 0/1,
  `ភ្នំពេញ` 0/2, `한국어` vs `한국어는` 0/1, and `كتاب` 0/1 against a drawer
  reading `قرأت الكتاب أمس`.
  Khmer, Thai and Myanmar failed *differently* and worse. Their marks are
  combining but not `Other_Alphabetic` (Khmer COENG U+17D2, Thai tone marks,
  Myanmar ASAT), so they **do** split — into fragments positioned by whatever
  word follows. The same Thai word matched when it ended the document and
  missed when it began it. Han and Kana at least produced one stable token
  both sides agreed on.
  Boundaries now come from `script::segment`: character bigrams over maximal
  same-**script** subruns, plus unigrams only where a character is a word.
  That last qualifier is load-bearing in both directions — without Han
  unigrams `好` stops being findable, and with unigrams everywhere `قطار`
  matches `المستشفى` on a shared alef, which does not merely add noise but
  retires the relevance gate for every query in the script. Latin and digit
  subruns stay whole, so `Kubernetes` inside Chinese is still matchable
  instead of being shredded into `wi, in, nd`. Delimiting scripts — Latin,
  Cyrillic, Greek, Georgian, and Tibetan, which delimits on the tsheg — are
  untouched and pinned byte-identical by test.
- **Two characters is not a typo, it is a different city.** The one-edit
  tolerance is gated on `q.len() >= 5`, and that is a *byte* count, so it
  opened at three characters of Cyrillic and at **two** of anything CJK —
  where one substitution turns 北京 into 東京, 中国 into 美国, 한국 into 중국.
  Segmenting into bigrams would have made every CJK term a wildcard. Terms
  written entirely in a non-delimiting script now allow insertion and
  deletion only, which is a particle or clitic arriving, never substitution.
  Deliberately *not* done by making the gate character-based: Korean query
  terms are two to four syllables and would all have fallen below it.
- **The FTS5 prefilter cut the drawer it was supposed to find.** It is only
  fail-safe when it matches nothing — `fts_candidates` returns `None` and the
  scan runs. A non-empty *wrong* answer becomes `seq IN (...)`, removing the
  right drawer from the scan and from the cosine path with it. `drawers_fts`
  is external-content with no `tokenize=` option, so it indexes raw text
  under unicode61 and cannot agree with segmented query terms. Queries
  carrying a segmented script now bypass it and take the full scan.
- **BM25 no longer charges a drawer for being segmented.** Length
  normalization divided by token count, which the n-gram expansion roughly
  tripled for exactly the documents segmentation exists to serve. Candidates
  now carry content units — a run counts once per character, not once per
  emitted n-gram.

- **Arabic, and a scanner per language rather than a word list.** Extraction
  was English-only and failed *silently* — an Arabic corpus produced no
  mentions at all and the vault looked like it had worked. Researched before
  implementing, and the sources changed the design: the past marker
  **precedes** the count (قبل/منذ ثلاثة أيام), the **dual** is one inflected
  word with no numeral to read (يومين، أسبوعين، شهرين، سنتين، عامين), and a
  period modifier **follows** its noun (الأسبوع الماضي) while هذا precedes
  it. Both current Gregorian month-name systems are matched — the
  Levantine/Aramaic set (كانون الثاني، شباط…) and the Latin-derived set
  (يناير، فبراير…) — since neither is a dialect of the other and a corpus can
  mix them. Numerals are read in both genders. `WeekStart` gains **Saturday**
  (Egypt, Saudi Arabia, the UAE — CLDR is the authority), and it is the
  Arabic default because getting the language right and leaving the week
  European is subtly rather than obviously wrong. Arabic-Indic (U+0660–0669)
  and Extended Arabic-Indic (U+06F0–06F9) digits are now digits; `str::parse`
  takes ASCII only, so "٣ أيام" was invisible. The locale is a **read-time**
  parameter (`language` on `/v1/search` and `undercroft_search`), which is the
  payoff of reading live: a corpus ingested under one locale answers
  correctly under another with no re-ingest. One bug was found by the tests
  rather than by reading — اليوم is both "the day" and "today", and the unit
  reading claimed the token then dropped it, so "today" went missing.
- **The same word in two encodings is one word.** Nothing canonicalised
  before comparing, so أ written as U+0623 or as alef plus a combining hamza
  — the class covering أحمد، إبراهيم، مؤمن، رئيس — was two different pieces
  of content: different fingerprint so dedup never paired them, different
  tokens so a query in one encoding could not find a drawer in the other.
  `normalize::match_key` composes to NFC and derives the **comparison keys**
  only: stored bytes are untouched, because the promise is verbatim and
  because `NORMALIZE_VERSION` is inside the drawer id, so folding on the
  write path would move every future id. NFC and not NFKC — compatibility
  folding rewrites ﬁ to fi, which changes content rather than encoding.
- **A sealed vault no longer writes fragments of its content in the clear.**
  `meta_json` is stored unsealed — fine for wing, room, dates and counts, the
  same trade-off plaintext wing/room names already make. It is not fine for
  two fields that derivation lifts *verbatim* out of the content:
  `time_mentions[].text` held every date expression as written, and
  `entities` held every name. A vault that encrypts the sentence and writes
  its dates and names beside the ciphertext has not sealed the sentence, and
  the invariant says exactly that. Found by widening the at-rest test, which
  had used a secret containing neither a date nor a name and so could not see
  it; proved against the bytes on disk, which reported `["zerlinda",
  "three weeks ago"]`. `Drawer::meta_at_rest()` empties both before the row is
  written, and the tag covers what is actually stored. Nothing is lost: both
  are derived structure the reader recomputes from content it has already
  decrypted, mentions were already being read live, and `entities` is now
  derived at read too. What survives storage is the *resolutions* — offsets
  and ISO dates, which are not content — so a stored reading stays comparable
  with a live one. Applied at both security levels, so there is one storage
  contract rather than two. **Existing vaults keep the fragments already
  written**; purging them needs a rewrite pass, which the queued re-seal
  migration is the natural home for.
- **Deduplication collapses the text and keeps every date.** The content
  fingerprint covers content only, so `dedup --apply` grouped byte-identical
  drawers vault-wide and deleted all but the first — and the same words
  written on two different days are two things that happened, so a date was
  destroyed with each deleted row, unrecoverably. `save_with_dedup` had the
  same blindness from the other side: it took the incoming metadata wholesale,
  so the survivor adopted the newer date and the earlier appearance silently
  stopped existing. Found while explaining why 5 of 500 measured contexts
  carried the same passage twice — the answer was that the corpus records it
  on two different days, which is exactly the case that was being erased.
  `DrawerMeta` gains `occurrences`: the further days this same content was
  recorded, folded onto the survivor before the duplicate row goes.
  `Drawer::all_occurrences()` returns the full chronology including the
  drawer's own, earliest first; appearances are deduplicated by
  `content_date`, so re-ingesting a corpus five times is one appearance filed
  five ways rather than five appearances. The sweep reports `dates_kept`, and
  a dry run reports the same number it would preserve. Empty serializes to
  nothing, so every existing row keeps its bytes and keeps verifying.
- **The reading of a drawer's times is live; the seal is the record.**
  `time_mentions` was computed once in `Drawer::new` and sealed, which froze
  it at whatever the writing binary understood — a drawer written before
  "last month" was read as a month still carried it as a single day, and the
  only way to benefit from the fix was to rewrite every drawer. But a mention
  is derived from two things the drawer stores permanently and immutably, its
  own text and its `content_date`, so nothing about it needs to be frozen.
  Read surfaces now answer from `Drawer::live_time_mentions()` — deliberately
  the same call `with_content_date` makes, so the two readings cannot drift
  apart — and every future improvement to the scanner reaches every existing
  vault with no migration and no re-ingest. The sealed copy stays as the
  record of what was understood at the time, and `mentions_restated: true`
  appears wherever the two disagree, rather than one silently winning.
  `GET /drawers/{id}` keeps `drawer` byte-faithful to storage and adds
  `live_time_mentions` beside it, so a fetch and an export never disagree
  about the record itself.

Retrieval was never the weak link on conversational memory; what we stored
was. A drawer recorded only when it was *filed*, so a year-old conversation
ingested today carried today's date, and text like "I went yesterday" had no
reference point at all. Measured on LoCoMo: 272 of 272 documents carry a
timestamp, 233 (86%) lean on a relative expression, and exactly **one**
document in 272 spells a date out in its text.

- **`content_date`** — when the content happened, as distinct from
  `filed_at`. Declared on `DrawerMeta` since the mempalace port and never
  populated by anything; now carried end-to-end: REST `POST /drawers`, CLI
  `remember --content-date`, MCP `undercroft_save` / `undercroft_add_drawer`
  (declared in the tool schemas so agents can discover it), and `import`,
  which carries it across rather than stamping every imported drawer with
  the date of the import. Returned on search hits and reported by MCP search
  as `happened <date>, filed <date>`. It rides inside `meta_json`, so it is
  HMAC-covered for free, needs no schema migration, and leaves existing rows
  byte-identical; it does not enter the drawer id, so re-mining a corpus
  with dates now available stays idempotent. It also feeds
  `kg_add_receipted`'s `valid_from`, so the graph's validity windows finally
  describe when a fact *held*.
- **`core::temporal`** — dates and times written *into* the text. Scans for
  absolute ("7 May 2023") and relative ("yesterday", "last Tuesday", "three
  weeks ago") expressions, keeps each span verbatim with its byte offset,
  and resolves what the anchor allows. Deterministic, offline, no model, no
  network. With no anchor a mention is recorded **unresolved** — an honest
  gap beats an invented date. The scan runs inside `Drawer::new`, so no
  write path can forget it.
- **Conversation transcripts keep what the session actually was.**
  `parse_transcript` dropped every non-`user`/`assistant` message and every
  non-`text` block, discarding tool calls, tool results and reasoning — most
  of an agent session — plus per-message timestamps, ids and speaker names.
  Now every recorded turn survives, non-prose blocks render under a
  `[kind]` marker with payloads verbatim, unknown future block kinds are
  preserved, and named speakers no longer collapse to User/Assistant.
  `chunk_exchanges_dated` reports each chunk's opening turn, feeding
  `content_date` on the convo miner and sweeper.
- **Code-aware normalization** — `NormalizeMode::{Prose, Code}` plus
  `mode_for_path`. Normalization trimmed trailing whitespace and collapsed
  blank runs on every drawer; harmless for prose, a silent edit for a
  script, where indentation is semantics. Code mode applies only the safety
  floor (NUL/control stripping, CRLF→LF); Prose additionally leaves fenced
  blocks untouched. `NORMALIZE_VERSION` → 2.
- **`POST /v1/vaults/{id}/refine`** — the `/v1` KG surface was read-only and
  CLI `refine` wrote triples only, not the searchable fact-drawers that put
  distillation on the retrieval path. Fact-drawers land in their source
  drawer's wing under `fact_room` (default `facts`), so a caller selects
  verbatim / distilled / both purely by varying the room filter on
  `/search`. Each distinct fact is mirrored once, keyed on the triple id the
  graph itself returns, so a fact restated across chunks cannot occupy
  several slots of one top-k.
- **`UNDERCROFT_LLM_KEY`** — optional bearer for the LLM runtime, unset by
  default. An empty key sends no header, so a default build's requests are
  byte-identical to before. Set it only to reach a runtime behind an
  authenticating gateway — which, unlike the local default, means drawer
  text leaves the machine.

- **`DrawerMeta.entities` populated** — declared since the mempalace port
  and never assigned (every "entities" reference in the codebase was to
  *knowledge-graph* entities, a different thing). Now extracted in
  `Drawer::new` by the existing deterministic offline extractor, so the
  structure travels with an export instead of being recomputed to be read.
  Empty stays empty and is omitted from serialized meta, keeping existing
  rows byte-identical.

Tests 177 → **249**, including regression coverage pinning what must not
change: fence-free prose normalizes byte-for-byte as v1 across ten cases,
harness noise is still filtered, prose is still verbatim, and
`chunk_exchanges` text is identical to the dated variant.

- **Retrieval selection** — `SearchOptions.room_cap`, a soft per-room cap that
  spreads the top-k across rooms and then refills by score, so a
  single-room question still receives the full limit. Default off, and
  measured 5.6 points *worse* on a corpus where evidence is concentrated:
  forcing diversity displaces the chunks that hold the answer. Kept because
  the knob is sound and the measurement is the guidance.
- **The engine computes elapsed time instead of delegating it.** Diagnosing
  the remaining benchmark losses showed most had all their gold evidence in
  context already — asked how long between a flu recovery and a jog, the
  generator quoted both correct dates and answered "11.7 weeks" against a
  truth of 104 days. Calendar arithmetic is deterministic work over data we
  hold, so `core::temporal` now does it: `days_between` (exact, correct
  across month lengths and leap years), `calendar_weeks_between` and
  `calendar_months_between` (boundaries crossed — "how many weeks since" is
  a calendar question, and `days / 7` silently answers a different one),
  `hours_between` on absolute instants, and `describe_interval` for display.
  `POST /v1/search` takes `as_of` and returns `elapsed_days`,
  `elapsed_weeks`, `elapsed_months`, the phrase, and `same_frame`.
- **Timestamps carry the actor's frame, never the host's.** A local date comes
  from the UTC offset the timestamp itself declares, so the same vault
  answers identically on every machine and no IANA database — which ships
  several releases a year — can retroactively change an answer the audit
  chain already attests to. Across differing offsets, local-day counting and
  absolute-instant counting can disagree in *sign* (an evening in Los
  Angeles and the next morning in Tokyo is +1 local day but −7.5 hours), so
  both are reported rather than one silently chosen.
- **`WeekStart::{Monday, Sunday}`** — ISO says Monday, but the US, Canada,
  Japan and Israel count from Sunday, and first-day-of-week moves every
  boundary. Monday remains the default; `calendar_weeks_between_with` lets a
  locale-aware caller say otherwise.
- **Search hits also return `time_mentions` and `entities`** — computed at
  write time, sealed on every drawer, and until now unreachable through the
  only surface that reads them.
- **A mention resolves to a period, not to its first day.** "May 2023" was
  recorded as 2023-05-01, which makes it indistinguishable from "1 May 2023"
  — precision the writer never offered, and the same class of invention this
  module exists to prevent. `TimeMention` now carries `resolved_end` (and a
  `range()` accessor) whenever the text named something wider than a day, so
  a month stays a month. The phrases that name calendar periods were also
  being read as offsets from the anchor: "last month" resolved to the same
  day-of-month one month back, "last year" to the same day one year back, and
  "last week" to seven days ago. They now resolve to the previous month, year
  and week. `"N units ago"` is displacement arithmetic and still names a day,
  which is a genuinely different shape.
- **"this Friday" and "next Friday" were the same date.** Both walked forward
  from the anchor, so every "this" was read as a "next". "This <weekday>" now
  means the one inside the anchor's current week — which makes it depend on
  where the week begins, so `WeekStart` is threaded through extraction as
  `extract_time_mentions_with`, alongside `describe_interval_with`.
- **Hostile input no longer panics the write path.** Drawer content is
  arbitrary user text and extraction runs on every write, so "999999999 days
  ago" reached an unchecked date shift and panicked. Every shift is now
  checked and resolves to nothing when it leaves the calendar. Relatedly,
  `shift_months` returned the *unshifted* date when the target was
  unrepresentable — reporting the anchor as though it were the answer, a
  wrong date wearing a right one's costume. It returns `None`.
- **`describe_interval` counted years as `days / 365`.** A span containing a
  leap day is longer than 365 days per year, so the division rounded up into
  a year that had not finished: 2023-01-01 to 2024-12-31 is 730 days and one
  year, and it read "2 years". Years are now counted on the calendar like
  every other band.
- **Month names are also ordinary English words.** A bare lowercase "may",
  "march" or "august" was recorded as a temporal mention on every drawer that
  used the verb. A bare month carries no resolvable date anyway, so it is now
  kept only where the writer's capitalization actually chose — never where
  capitalization is forced, at the start of a line or sentence. Anything with
  a day or a year attached is a date whatever its case.
- **A fact records where it rests: the note's words, or the extractor's
  background knowledge.** Distilling "Ana works as a radiologist at St. Mary's
  in Leeds" yields both `ana works_as radiologist`, which the note states, and
  `leeds city_of United Kingdom`, which it does not — and the second is the
  edge that answers which country Ana works in. Both belong in the graph;
  until now they were indistinguishable. `core::support` adds the same
  contract `when` uses: the extractor **quotes**, and the engine **checks** the
  quote against the note, so the label comes from a substring test rather than
  from a model grading itself. Three states, not two — `stated`, `background`,
  and `unevaluated` for every fact distilled before this existed, because "we
  did not look" and "we looked and found nothing" are different claims and
  defaulting the first to the second would assert something about facts nobody
  checked. Spans are stored as offsets into the source drawer, never as copied
  text, sealed under `kg/{id}/support` like the object beside them. `kg/query`
  and `kg/timeline` expose `grounding` and take an **opt-in** `?grounding=`
  filter — never a default, since excluding background facts breaks the
  multi-hop questions the graph exists to answer. Existing facts keep verifying
  untouched: support joins the triple's canonical bytes only when present, so
  a fact without it hashes exactly as it always did.
- **A distilled fact is dated by the note's words, not by the note.** `refine`
  stamped every extracted fact with the drawer's `content_date`, so "I quit
  smoking three months ago" produced a fact whose validity began the day the
  note was written — the same bug class as reading elapsed time from
  `content_date` when the drawer already held a more precise resolution.
  `ExtractedTriple` gains an optional `when`, and the contract on it is that
  **the model may point at words, it may not supply a date**: it returns the
  span verbatim, `temporal::resolve_claimed_span` refuses anything the note
  does not literally contain, and the deterministic scanner resolves what
  survives against the note's anchor. An invented span, a rewritten one, or a
  date in place of a quotation all yield nothing and fall back to
  `content_date`, which is exactly the old behaviour — so the approximate
  component can only help, never corrupt. `valid_to` stays open even for a
  period: "in May 2023" says when the event happened, not that the fact
  expired on the 31st. The response reports `dated_from_text`, the only
  visible signal that the extractor is quoting rather than computing.
- **Each `time_mention` carries its own elapsed counts.** A drawer's
  `content_date` is when it was *written*; a mention inside it is when the
  thing it describes *happened*. A note written on the 8th saying "I went
  yesterday" is about the 7th, so "how long ago" answered from `content_date`
  is off by exactly the day the mention resolution exists to recover. Both
  are returned, neither is chosen for the caller, and neither is left as
  arithmetic homework.

**Measured (AMB harness, gemini-3.1-flash-lite answer+judge, verbatim
surface, k=10 — internal numbers, not protocol-comparable with AMB's
published vendor-reported rows):**

- **LoCoMo locomo10, before → after the anchor work: 72.6% → 85.6%**
  (1540 judged QA; same corpus, judge and retrieval — one variable).
  Temporal **35.2% → 85.4% (+50.2)**, open-domain 89.5 → 93.8, multi-hop
  64.6 → 66.7, single-hop 67.4 → 67.7. The failing shape had been: retrieval
  fetched the right session, the context held zero dates ("I went
  *yesterday*"), and the model invented one.
- **LongMemEval s: 74.8%** (500 q, 23,867 docs — ~90× LoCoMo; ingest 28 min,
  retrieve 40 ms avg). Temporal-reasoning 72.9% on a corpus never tuned
  against — the anchor work generalises. Single-session-user 98.6%,
  knowledge-update 83.3%, **multi-session 51.1%** (retrieval breadth, the
  next frontier).
- **BEAM 100k: 56.2%** (400 rubric-scored q). Contradiction-resolution
  40/40, preference-following 92.5%, **abstention 60%** (we fabricate on
  40% of deliberately unanswerable questions), knowledge-update 42.5%,
  **event-ordering 17.5%** — absolute anchoring is fixed, *relative
  ordering* is not: dates are stored but retrieval returns
  relevance-ordered context with no sequence signal.

## 0.42.0 — Sealed PQ page tier (opt-in)

- Sealed vaults can now keep their PQ codes as **one AEAD page per IVF
  list** (`pq_page` table, AAD `pqpage/{list}/{pageno}`, capped at 4096
  rows/page) instead of per-row seals — the format the page-level spike
  measured at **2.1× smaller at rest, 22 s → 0 open cost, and 630 MB vs
  ~1 GB warm RAM at 10⁷ drawers**. Probed lists decrypt **lazily**: a
  query touches only its lists' pages, never the whole index.
- **Integrity = the row-count commitment**: each page seals
  `count ‖ (seq ‖ code)*` as one AEAD unit (intra-page splicing or
  selective deletion is impossible without the key — stronger than
  per-row seals), and a sealed total-count in `pq_meta` keeps the
  matched-count self-heal exact. Deletes and updates of paged rows
  balance through a sealed `deleted` counter — no page rewrite, no
  spurious rebuilds.
- **Write amplification is bounded by design**: single writes land as
  per-row *tail* rows (searchable immediately) and fold into their
  lists' pages once per `upsert_many` batch (or past 256 tail rows at
  a verify pass) — one reseal per touched list per batch.
- **Event-driven migration, both directions**: flipping
  `UNDERCROFT_PQ_PAGE_MIN` (or `set_pq_pages`) repacks per-row ⇄ pages
  at the next search's verify pass without re-embedding anything.
  Key rotation re-seals pages byte-exact like every other artifact
  (`RotationReport.pq_pages`).
- **Default off** (`UNDERCROFT_PQ_PAGE_MIN` unset ⇒ never): per the
  spike's decision the per-row format stays recommended until a
  deployment's RAM/open-time wall actually bites — this ships the
  format and its migration so that trigger is a config flip, not a
  release. Completes ROADMAP item 3.

## 0.41.0 — Slab-grouped PQ cache

- The PQ RAM code cache (both vault levels) is now **slab-grouped by
  IVF list** — a probe scans its lists' contiguous slabs instead of
  filtering every cached row through a per-row membership test. The
  page-level spike measured that flat filter at 0.3–1.4 s/q at 10⁷
  drawers versus 10–36 ms/q for the grouped layout
  (`benchmarks/logs/pqpage_spike.log`, docs/RETRIEVAL_SCALING.md); the
  shipped path previously used a linear `contains`, so the win is a
  floor. **Zero at-rest change** — cache layout only; recall is
  byte-identical by construction. Mirrors the inverted-FDE tier's
  slab cache (v0.39.0), as the page-format plan prescribed.
- IVF `nlist` clamp lifted 1024 → 4096: √N keeps tracking the corpus
  past 10⁶ drawers (at 10⁷/1024 every probe slab held ~10k rows),
  matching the FDE tier's clamp. Corpora below ~1M are unaffected;
  larger ones repartition on their existing double-growth trigger.
- First step of the page-level at-rest format arc (ROADMAP item 3):
  the format-free fix ships first, the opt-in page format + repack
  migration follow.

## 0.40.0 — Orchestrator read replicas

- `undercroft-orchestrator serve --read-replica`: opens the state
  database **read-only** and serves only `/healthz` and the `/t/*`
  data plane — token resolution is a pure HMAC lookup, so replicas
  scale read routing horizontally while the fleet keeps exactly one
  writer. `/admin/*` and `/ui` answer 403 pointing at the writer, a
  replica never creates or mutates state (guarded at the state layer
  *and* by a read-only connection), and it refuses to start on a
  missing database.
- `/healthz` on both roles now reports `mode`
  (`writer`/`read-replica`) and `last_write` — the unix-seconds stamp
  of the last control-plane mutation, maintained by the writer — so
  replication lag is directly observable by diffing a replica against
  the writer.
- Deployment shapes documented in MULTI_TENANCY.md: shared volume
  (zero lag; SQLite WAL supports concurrent readers) or
  litestream-style replicated snapshots (lag = replication interval;
  a revoked token dies on a replica after at most that window).
- Orchestrator e2e grows 34 → 44 checks: writer+replica convergence
  (rotation kills the old token through the replica immediately),
  admin refusal, and the missing-db guard.

## 0.39.0 — Inverted FDE tier (opt-in)

- The MUVERA FDE index gains an **inverted tier**: coarse centroids
  train event-driven over the palace's own decoded FDEs, every v2
  row's reserved list field rewrites in place (**no migration** — the
  pack anticipated this since v0.24.0), and the RAM cache groups into
  per-list slabs so a probe scans only its lists contiguously.
  Centroids persist sealed in `fde_meta` and are covered by key
  rotation; skewed probes widen to the full scan.
- **Shipped opt-in, default off** — the honest result of its own gate:
  measured on synthetic corpora at N=200k/500k, probed containment
  stayed *below* the flat scan's (0.960–0.993 vs 1.000) and the probed
  scan ran slower than flat ADC (243 vs 79 ms/q at 500k). Flat ADC +
  LUT remains the recommended configuration at every measured scale.
  Operators past ~10⁶ drawers can opt in with
  `UNDERCROFT_FDE_IVF_MIN=<n>` (+ `UNDERCROFT_FDE_NPROBE`) after
  validating containment on their corpus.

## 0.38.0 — Fleet live-ops

- **The fleet console goes live**: a 10 s sweep auto-refreshes engine
  health (UP/DOWN pills, no clicking), pulls per-tenant metadata stats
  (drawer counts, store size), and keeps a fleet totals bar — engines
  up, tenants, Σ drawers, Σ store, last-sweep clock. An engine outage
  and its recovery both surface within one sweep.
- **New admin route** `GET /admin/tenants/{id}/stats`: relays the
  tenant vault's metadata stats using the orchestrator's stored engine
  credentials — counts, sizes, and the chain head only; tenant content
  remains reachable solely through the tenant's own token on the data
  plane.
- Completes the advanced-console arc (v0.37.0 was the engine half).

## 0.37.0 — Console monitoring + knowledge-graph explorer

- **MONITOR tab** in the vault admin console: live sparkline charts
  (drawers, chain height, KG triples, store size) and an activity
  ticker. The data source auto-negotiates — telemetry builds backfill
  from the stats ring buffer and ride the SSE stream; default builds
  poll `/stats` every 3 s — so **every build gets a live view**,
  metadata only, per the observability invariant.
- **KNOWLEDGE tab**: the temporal knowledge graph is finally visible
  outside the CLI — paged entity browser, per-entity facts (valid
  now), and the full temporal timeline with open/closed validity
  pills and confidence.
- **New read-only `/v1` KG routes** backing it: `kg/stats`,
  `kg/entities` (paged, tag-verified), `kg/query?entity=&direction=&as_of=`,
  `kg/timeline?entity=`. Mutations stay on the CLI/MCP surface.
- **PALACE tab**: the pixel-art Palace Monitor embedded in the console
  (telemetry builds; default builds get a clear note instead of a
  broken frame).
- **GRAFANA tab**: embed the "Undercroft — Palace" dashboard from the
  `deploy/observability` stack (URL remembered per-browser; the stack
  now ships with `GF_SECURITY_ALLOW_EMBEDDING` so the iframe works out
  of the box).

## 0.36.0 — Fleet console

- **`GET /ui` on the orchestrator** — a fleet administration console in
  the same self-contained single-page style as the engine's vault
  console (v0.35.0): register engines (credentials sealed into the
  orchestrator's state db), per-instance health checks, tenant creation
  with the **one-time token reveal** (the orchestrator stores only an
  HMAC — the page makes that unmissable), guarded token rotation
  (old bearer dies instantly), guarded tenant deletion, and
  **count-verified migration** between engines with a keep-source
  choice. The admin token stays in the browser tab; destructive
  operations require typing the target's name.

## 0.35.0 — Vault admin console

- **`GET /ui` — a vault administration console** served by `serve-http`
  on every build: one self-contained static page (no dependencies, no
  telemetry requirement) in the Palace Monitor's phosphor-terminal
  style. Vault list/create/delete, live stats dashboard, one-click
  HMAC + audit-chain verification, key rotation, a taxonomy-driven
  drawer browser with verbatim view/edit/delete, a search console, and
  NDJSON export/import. The bearer — and, under per-vault isolation,
  the assertion secret — stay in the browser tab; assertions are
  minted client-side with WebCrypto. Every destructive operation
  requires typing the target's name.
- **New `/v1` management routes** backing the console (and any other
  client): `GET …/drawers` (paged summaries with wing/room filters),
  `GET`/`PUT …/drawers/{id}` (full drawer, verbatim content replace),
  `GET …/taxonomy`, `POST …/verify`, `POST …/rotate`, and stats
  extended with wings, rooms, KG counts, tunnels, and store size. Same
  auth model as the rest of `/v1`; mutations 403 on read-only servers.
- Research spike shipped alongside (merged separately): sealed-tier
  page-level decryption measured at 10⁶–10⁷ drawers — see
  `docs/RETRIEVAL_SCALING.md`; format deferred to its RAM trigger.

## 0.34.2 — Container image metadata + landing navigation

- OCI labels on the runtime image and index-level annotations on the
  multi-arch manifest (title, description, source, docs, license) — the
  GHCR package page now shows a description and links back to the
  repository.
- **Landing page navigation**: a fixed scroll-spy rail on the right edge
  (per-section dots, active section lit with its label, click to jump)
  plus a reading-progress bar along the top — the long page now always
  shows where you are. Desktop only; hidden under 900 px.

## 0.34.1 — Multi-arch distribution + weaviate readiness fix

- **linux/arm64 everywhere**: the GHCR image is now a multi-arch
  manifest (amd64 + arm64, each built natively on GitHub's arm runners —
  no QEMU), and releases gain an `aarch64-unknown-linux-gnu` binary
  (Raspberry Pi, Graviton, and other ARM servers).
- **backends-e2e flake fixed**: weaviate answers HTTP before its Raft
  leader is elected, so the readiness probe could pass and the first
  schema write then failed 422 "leader not found" (flaked the v0.34.0
  post-merge CI and one local run, 5 checks each time). The probe now
  gates on `/v1/schema` returning 200 — the exact surface the suite
  writes to first.

## 0.34.0 — Distribution & security policy

Adoption no longer requires building from source, and vulnerability
reporting has a real front door.

- **Prebuilt release binaries**: every version tag now builds and
  attaches `undercroft` + `undercroft-orchestrator` archives for Linux
  x86_64, macOS Intel, macOS Apple Silicon, and Windows x86_64 — with
  SHA-256 checksums, LICENSE/NOTICE included, default features (offline,
  zero telemetry deps).
- **Published container image**: `ghcr.io/compufreq/undercroft:<tag>` and
  `:latest`, built from the same Dockerfile as always, pushed by the
  release workflow.
- **SECURITY.md expanded** into a full policy: GitHub private
  vulnerability reporting (now enabled on the repo) + email channel,
  response expectations (72 h acknowledgment / 7-day assessment /
  coordinated disclosure), latest-release support statement, and an
  explicit in-scope / out-of-scope list matching the documented threat
  model.
- Install docs updated everywhere (README, getting-started, agents
  guide, landing walkthrough) to lead with `docker pull` and release
  binaries.

## 0.33.0 — License change: MIT → Business Source License 1.1

Undercroft is now **source-available under BUSL 1.1** (the
MariaDB/HashiCorp license), effective this release and applied to the
repository's entire history.

- **What stays free**: use, modification, self-hosting, and production
  use — personal, internal, and commercial — at no cost.
- **The one restriction**: offering Undercroft itself to third parties as
  a paid hosted or embedded product competing with the Licensor's
  commercial offerings requires a commercial license.
- **The open-source guarantee**: each release automatically converts to
  **MPL 2.0** four years after publication (rolling, per release).
- **Heritage**: Undercroft remains a from-scratch Rust implementation of
  concepts from the MIT-licensed MemPalace project, containing none of
  its code; that attribution now lives in `NOTICE`, and
  `docs/PARITY.md` gained a comprehensive "what exists only here"
  section (security layer, retrieval stack, multi-tenancy/fleet,
  operations) plus a license-lineage note.
- Mechanics: `LICENSE` replaced (canonical BUSL 1.1 text, parameters:
  Licensor compufreq, Change Date four years from publication, Change
  License MPL 2.0), `NOTICE` added, workspace `license = "BUSL-1.1"`,
  CONTRIBUTING contribution-licensing terms, README license section,
  landing footer.

## 0.32.0 — Agents guide, landing walkthrough, OTLP headers

- **`docs/AGENTS.md`** — a scenario-driven implementation guide written
  for AI agents: a deployment decision table and seven scenarios
  (single-agent memory, team server, multi-tenant engine, orchestrator
  fleet, retrieval-tier selection, security operations, telemetry),
  followed by the complete machine-facing reference — all 32 MCP tools
  (write tools marked), every `/v1` and orchestrator route with its auth,
  every `UNDERCROFT_*` variable with defaults — and a verification
  checklist. Published in the book as `docs/agents.html`; linked from
  the README header and the landing page.
- **Landing page**: six use-case cards ("what to build with it"), a
  7-step hands-on walkthrough with copyable real commands (install →
  init → feed → ask → wire an agent → share → operate), a closing CTA,
  and refreshed stat counters (176 cargo tests, 228 e2e checks across
  the four suites).
- **`UNDERCROFT_OTLP_HEADERS` implemented** (was documented but not read
  anywhere): comma-separated `key=value` pairs attached to every OTLP
  trace export — authenticated collectors (e.g.
  `authorization=Bearer <token>`) now work as the docs always claimed.
  Telemetry builds only; still nothing leaves the process without
  `UNDERCROFT_OTLP_ENDPOINT`.

## 0.31.0 — Bulk-ingest transaction batching

Follow-up to v0.28.0's durability work, which made every commit a real
disk sync and exposed that one drawer write paid **several syncs**
(row+chain transaction, then each advisory derived-index statement as
its own implicit transaction, plus the manifest anchor).

- **New `PalaceStore::upsert_many`**: a batch of drawers commits in
  **one transaction** — rows, audit-chain advances, and derived-index
  writes (PQ codes, token matrices, FDEs) all join it — and the
  manifest anchors once after the commit. A mid-batch failure rolls the
  entire batch back (the existing palace is untouched); the anchor
  still never runs ahead of the database.
- **CLI bulk paths batched** (256/chunk): `import`, `mine` (files and
  convos), `sweep`, and the daemon's sweep loop. Single-drawer
  `remember` and the server save paths are unchanged. Duplicate
  detection gains an in-batch set so unflushed duplicates are still
  skipped.
- **Measured** (same binary, same container, back-to-back): importing
  200 drawers into a sealed vault = **26 fsyncs total (0.13/drawer)**
  vs ~7 fsyncs/drawer on the per-item path — **~55× fewer disk
  syncs** — completing in 0.7 s with `VERIFY OK` and the chain intact.
- Durability semantics preserved: `synchronous=FULL` still syncs every
  commit; batching changes how many commits there are, not whether
  they reach disk.

## 0.30.0 — Recipient-encrypted export bundles

The second ecosystem item: `undercroft export --to <recipient>` seals the
export so a backup or migration file **never exists in plaintext**.

- **`bundle keygen`**: X25519 recipient identity — the secret key goes
  to a private file (0600, refuses overwrite), the shareable public
  recipient string prints once. `bundle recipient <keyfile>` re-prints
  it.
- **`export --to <recipient> --out <file>`**: age-style construction —
  fresh ephemeral X25519 key per bundle, file key =
  HKDF-SHA256(salt = eph_pub ‖ recipient_pub, ikm = DH, info =
  `undercroft.v1/bundle`), payload sealed XChaCha20-Poly1305 with the
  magic + ephemeral key bound as AAD (a spliced header fails to open).
- **`import <bundle> --identity <keyfile>`**: bundles are detected by
  magic; plaintext JSONL imports are unchanged. Wrong identity or a
  tampered file is a clean refusal, not a partial import.
- The bundle identity is unrelated to the palace's at-rest keys —
  compromise of one does not touch the other.
- New dep: `x25519-dalek` 2 (pure Rust, zeroize-on-drop secrets), in
  `undercroft-vault` only.
- Tests: roundtrip, wrong-identity, tamper + header-splice, per-bundle
  ephemeral freshness, junk-input errors; e2e +6 checks (keygen →
  sealed export → not-plaintext assertion → import-needs-key →
  identity import → wrong-key refusal → overwrite refusal).

## 0.29.0 — Key rotation

`undercroft vault rotate <name>`: move a vault onto fresh derived keys
in place — first of the two ecosystem items (recipient-encrypted export
bundles are next).

- **Fresh salt ⇒ fresh enc/mac/manifest keys** (HKDF re-derivation);
  every AEAD blob is re-sealed **byte-exact at the seal layer** — no
  decompress/requantize round trips, AAD domains preserved — across all
  sealed stores: drawer content + embeddings, KG triple objects, ColBERT
  token matrices, PQ code rows + codebook + IVF centroids, FDE rows +
  params + codebook. Every HMAC tag (drawers, KG, tunnels), keyed
  fingerprint, and the audit chain are re-keyed.
- **Single-transaction, crash-safe anywhere**: the next manifest is
  staged durably as `vault.json.next`, the re-seal transaction flips a
  `keycheck` marker as its committed witness, and open-time
  reconciliation either promotes the staged manifest (crash after
  commit) or discards it (crash before) — a crashed rotation is never a
  tamper alarm, and the palace always opens under exactly one key
  generation.
- **Audit history semantics**: tags of superseded/deleted content are
  preserved verbatim (their plaintext is gone by design); the chain over
  them is what rotates. `verify` replays the same bytes to the new head.
- Remote-index copies hold old-key ciphertext after a rotation — the CLI
  reminds you to re-run `index push`.
- Tests: full-fidelity rotation on both vault levels (drawers, KG,
  tunnels, dedup fingerprints, cold reopen), plus both crash windows
  (staging discarded / staging promoted). e2e: rotate → verify → search
  → KG → dup-lookup → rotate again, 8 new checks.

## 0.28.0 — Ingest durability (fsync)

The durability refinement queued since the audit-chain atomicity work
(v0.19.0): every acknowledgement now implies bytes on disk, and a power
loss can only produce the healed crash case — never a false tamper
alarm.

- **SQLite pinned to WAL + `synchronous=FULL`** (was the compile-time
  default): the data+chain commit reaches disk before its post-commit
  manifest anchor possibly can, so the anchor can end up equal or
  *behind* the database (open-time reconciliation fast-forwards) but
  never *ahead* (which reads as rollback/tamper).
- **Manifest anchor written durably**: fsync the temp file before the
  atomic rename, fsync the directory entry after — a torn or reordered
  `vault.json` after power loss can no longer masquerade as tamper.
- **Key material fsynced at creation** (master key, KDF salt): written
  once, unrecoverable if lost.
- **Orchestrator control-plane db** gets the same WAL + FULL pin: a
  tenant token is shown exactly once — the row recording its HMAC must
  survive the moment it is acknowledged, as must a migration flip.
- Tests: pragma pins asserted on both engines' connections (both vault
  levels) and the anchor's durable-replace path leaves no temp file.

## 0.27.0 — ONNX Runtime backend in the CLI

The measured ORT wins (reranker ~100–160× end to end, ColBERT 96.7 →
70.3 ms/q, ingest embed ~4–5×) existed only behind the bench harness;
this release wires them into the `undercroft` binary for real
deployments.

- **New `ort` cargo feature on `undercroft-cli`** (opt-in, like `onnx`):
  links `undercroft-embed-ort` and exposes the backend at runtime —
  - `UNDERCROFT_EMBEDDER=ort` — session-pool sentence embedder;
  - `UNDERCROFT_RERANKER=ort` — cross-encoder scoring the whole pool in
    one batched forward (`score_batch` forwarded end to end);
  - `UNDERCROFT_RERANKER=colbert-ort` — the ColBERT late-interaction
    encoder (search + `repair --tokens` backfill).
  Same user-supplied model files and `UNDERCROFT_ONNX_*` / `RERANK_*` /
  `COLBERT_*` variables as the tract backend — switching runtimes is
  one env change, no re-ingest (identical weights ⇒ identical vectors).
- **Multi-tenant `/v1` server**: `ort` embedder and reranker load
  **once** and are shared across every tenant vault (the ORT session
  pool holds a model copy per core — per-vault loads would multiply
  RAM for identical weights). ColBERT stays single-vault-serve only,
  now with an explicit error instead of "unknown value".
- `ort-build` compose service now compile-checks the full CLI with
  `--features onnx,ort` (both backends coexisting) instead of the
  backend crate alone.
- Unknown-value errors for `UNDERCROFT_EMBEDDER` / `UNDERCROFT_RERANKER`
  enumerate the new values; docs updated (README, RETRIEVAL_SCALING,
  website retrieval page).

## 0.26.0 — Orchestrator hardening

The follow-ups queued at v0.25.0, minus one deliberately deferred.

- **Token rotation**: `POST /admin/tenants/{id}/rotate` + `tenant-rotate`
  CLI — a fresh token is minted and the old one revoked **in the same
  statement** (rotation is the revocation primitive; no grace window).
  Shown once, like at create.
- **Per-tenant rate limiting** (`UNDERCROFT_ORCH_RATE_LIMIT`,
  requests/minute, off by default): fixed-window, keyed per tenant,
  applied on the data plane after token resolution — one noisy tenant
  429s, the rest are untouched.
- **Deployment hardening docs** (MULTI_TENANCY.md): TLS via reverse
  proxy on both hops, loopback defaults, secrets hygiene, state
  backup, and the documented **single-writer stance** — multi-
  orchestrator replication is deferred until a fleet needs it, with the
  likely shape (read-replica proxy) recorded.
- Verified: 9 unit tests (+ rotation revocation, per-tenant/per-window
  limiter), e2e grown to **30 checks** including a deterministic
  burst-over-limit test (8 rapid requests across ≤2 windows guarantee a
  429 — no timing flake) and old-token-revoked-immediately.

## 0.25.0 — Multi-tenant orchestrator

The control plane docs/MULTI_TENANCY.md reserved: routing, tenant→vault
mapping, token minting, and live migration for fleets of engine
instances, shipped as the **separate optional `undercroft-orchestrator`
binary**. It is a pure client of the public `/v1` surface — the engine
stays tree-blind and never links it.

- **State** (own SQLite): instance registry + tenant→vault map. Engine
  credentials are **sealed at rest** (XChaCha20-Poly1305 under
  `UNDERCROFT_ORCH_KEY`, AAD-bound to the instance name — a blob copied
  onto another row fails to open); tenant tokens are **never stored**
  (domain-separated HMAC only; the token appears once, in the create
  response).
- **Data plane** `/t/<subpath>`: a tenant token routes to exactly its own
  vault as `/v1/vaults/{vault}/<subpath>` with the engine bearer + a
  freshly minted per-vault assertion; the subpath allowlist keeps vault
  lifecycle off the data plane (the vault root is unroutable). Even a
  routing bug downstream fails cryptographically — assertion and vault
  AAD both carry the vault id.
- **Admin plane** `/admin/*` (`UNDERCROFT_ORCH_ADMIN_TOKEN`, uniform
  401s): instance add/list/remove (+ live health probes; removal refused
  while tenants map to it), tenant lifecycle with least-loaded placement,
  and **migration**: artifact-carrying export (v0.18) → import →
  **count-verified** → mapping flip → source delete (`keep_source` opts
  out); any failure before the flip leaves the source authoritative.
- **CLI** mirrors the admin plane (`instance-add`, `tenant-create`,
  `migrate`, …) plus `keygen`; the runtime image now carries both
  binaries.
- **Verified**: 7 unit tests (AAD binding, wrong-key unsealable, token
  MAC resolution, placement + removal guard, assertion contract, subpath
  allowlist) + a 24-check e2e suite (`orchestrator-e2e` compose service)
  running two live engine instances through the whole story, including a
  migration after which the source engine provably no longer serves the
  vault.

## 0.24.0 — Bounded-RAM FDE tier (PQ codes)

The v0.23.0 honest-limits follow-up: FDE rows now upgrade event-driven
exactly like the token store. Raw f32 (v1) below `UNDERCROFT_FDE_PQ_MIN`
(256; `off` disables), then a codebook trains from the palace's own FDEs
(persisted sealed in `fde_meta`), every row repacks to `dim/8`-byte PQ
codes — **32× smaller** (8 KB → 256 B/drawer) — and the scan switches to
per-query dot-product LUTs. Legacy v0.23.0 rows are recognized and repack
in the same pass; a row that fails to open deletes back to "missing" and
the next backfill recreates it.

Measured (`fde-synth`, exact-MaxSim ground truth):

- Candidate containment stayed **perfect through the compression at every
  size** (exact top-10 ⊆ coded top-100 = 100% at N=2k/50k/200k), with the
  ADC scan ~8× faster than the raw dot scan (11.5 vs 97.3 ms/q @50k;
  33.2 vs 275.8 @200k) and RAM down 32× (51 MB at N=200k).
- End-to-end LoCoMo gate holds exactly: R@10 96.5% — the **identical
  1913/1982 for the fourth consecutive configuration** (fusion, raw FDE,
  PQ-coded FDE) — at 61.2 ms/q, parity-within-noise vs raw FDE's 52.9
  (the fixed per-query LUT build offsets ADC savings at small per-store
  corpora; the 256-row threshold keeps small palaces raw for exactly this
  reason).
- **IVF over FDE space: measured net-negative and deliberately not
  shipped** — it lost containment (0.84–0.99) *and* cost more than the
  flat ADC scan it replaced at every benchable size (the RAM-side list
  filter is O(N·nprobe)). The v2 pack format reserves a list field inside
  the sealed blob so a future properly-inverted tier (pays past ~10⁶
  docs) needs no migration. The bench cells recording this stay in
  `fde-synth`.

## 0.23.0 — MUVERA FDE candidate generation

The v0.22.0 research note, implemented and measured: token-aware candidate
generation through **fixed-dimensional encodings** (arXiv:2405.19504) —
each drawer's ColBERT token matrix compresses into one 2048-dim vector
whose dot product approximates MaxSim.

- **`undercroft-core/src/fde.rs`**: seed-deterministic, dependency-free
  MUVERA construction (SimHash buckets; query-side sums, doc-side
  centroids with Hamming `fill_empty_clusters`; ±1 projection). Same
  `(seed, params, dim)` ⇒ bit-identical encoders — restores keep scoring.
- **`undercroft-store/src/fdeidx.rs`** (`UNDERCROFT_RETRIEVAL=fde`):
  `drawer_fde` rows written from the token matrix already in hand at
  ingest, AEAD-sealed on sealed vaults (`/tok` domain, `fde/{id}` labels);
  params sealed in `fde_meta`; event-driven backfill from stored matrices
  (pure arithmetic, no transformer); load-once RAM cache; FDE dot
  candidates ahead of fusion, MaxSim rescore unchanged. The query forward
  is **shared** between candidate generation and rescore (the first run
  measured the duplication: 95.5 ms/q → 52.9 after the fix).
- **Measured, end-to-end** (LoCoMo full 1,982 QA, ort colbert + tok-PQ
  LUT): R@10 **96.5% — question-for-question identical** to the fusion
  baseline (1913/1982 both) at **52.9 vs 70.3 ms/q (−25%)** — the FDE head
  prunes the hydrate+verify pool that v0.21.0 measured as the dominant
  cost.
- **Measured, mechanics at scale** (`undercroft-bench fde-synth`, exact
  MaxSim ground truth): exact top-10 ⊆ FDE top-100 = **100% at N=2k, 50k,
  and 200k**, at 38–40× below exact scan cost (64 ms/q @50k, 246 @200k;
  8 KB/drawer RAM). FDE-alone top-10 ~60% — the MaxSim rescore stays, by
  design.
- Honest limits documented: the FDE scan is linear and the cache is
  O(corpus) RAM; the designed next tier is PQ/IVF over the FDEs (they are
  ordinary vectors — the bounded-RAM machinery composes directly).

## 0.22.0 — Unified PQ cache, HNSW ef-scaling, MUVERA note

Three follow-ups from the retrieval-scaling track, each measured.

- **PQ scan unified on the RAM code cache (both vault levels).** hmac-only
  vaults now ADC-scan the same load-once cache the sealed tier uses instead
  of streaming codes from SQLite per query. Honest result: a controlled
  before/after at N=20k/50k measured **parity within run-to-run noise**
  (hmac 36.1→34.1 q/s @20k, 14.3→15.2 @50k, while *unchanged* sealed cells
  swung ±8–10% between the same runs; recall identical everywhere) — the
  earlier loaded-host run that suggested a cache win did not reproduce.
  Kept for the simplification: one scan path, no per-query SQLite
  iteration, coherent cache updates from plaintext in hand.
- **HNSW recall collapse fixed.** Root cause: the store requests ≥256
  candidates but `instant-distance` builds with `ef_search=100` — every
  query tail came from an exhausted beam. `ef_search` now scales ~n/64
  (floor 320, cap 1024), `ef_construction` ~n/256. Measured: R@5
  93.1→**98.8%** at N=20k, 71.7→**96.3%** at N=50k, at 126–186 q/s (the
  bigger beam trades raw q/s for recall that degrades gently instead of
  collapsing); LoCoMo real-data parity with the full scan (R@10 94.6%
  both, 6.7 vs 5.3 ms/q). The `hnsw` feature stays experimental/off by
  default — O(corpus) RAM.
- **MUVERA research note** (docs/RETRIEVAL_SCALING.md): fixed-dimensional
  encodings as the honest "beyond MaxSim" candidate — token-aware
  candidate generation through the existing single-vector PQ/IVF + sealing
  machinery, attacking the store-side rescore cost v0.21.0 measured as
  dominant. Deliberately deferred below multi-million-drawer scale.

## 0.21.0 — ColBERT forwards on ONNX Runtime

The v0.20.0 follow-up: `OrtColbert` moves the ColBERT query/doc forwards
onto the opt-in ONNX Runtime backend. Same fixed-shape exports, same
`[Q]`/`[D]`/`[MASK]` framing, same `UNDERCROFT_COLBERT_*` env as the tract
encoder — only the runtime changes, and the bench prefers ORT over tract
when both features are built (matching the embedder/reranker precedence).

Measured (LoCoMo full 1,982 QA, hash embedder + colbertv2.0, same host):

- **Search 96.7 → 70.3 ms/q** with the token-PQ LUT (tract → ORT); ingest
  doc-encode phase **821 → 246 s (3.3×)**. Recall gate ≥96.5 met: 96.5%
  (1913/1982), and on the int8-MaxSim path recall is **identical** to tract
  (1918/1982 both) — runtime-invariance confirmed exactly.
- **The LUT win is unmasked as v0.20.0 predicted**: token-PQ LUT was +4 ms
  *slower* than int8 MaxSim under tract, and is **11 ms faster** under ORT
  (70.3 vs 81.6 ms/q).
- Honest correction to v0.20.0's estimate: the tract→ORT int8 delta shows
  the seq-32 query forward was ~11 ms of search, not ~80 ms — the residual
  ~70 ms/q is **store-side** (token fetch/decode + MaxSim + fusion), now
  the dominant term and the next optimization target.

Internal: `run_batch` gains a sequence-length parameter (the query export
is 32 tokens, not the embedder/reranker's 256).

## 0.20.0 — Token-store PQ & LUT MaxSim

Restore economics tier 3 — the PLAID move on our own primitive. The
late-interaction token store compresses **8.2×** (16 PQ bytes per token vs
128 int8 — a ~150-token drawer drops 19.8 KB → 2.4 KB) at **−0.2 pts** on
LoCoMo (96.57% vs 96.77%, above the ≥96.5% gate).

- **v2 pack format**: per-token PQ codes (`pq.rs` re-used at `m=16`). The
  codebook trains event-driven from the vault's own stored matrices once
  they cross `UNDERCROFT_TOK_PQ_MIN` (default 256; `off` keeps int8),
  persists **sealed** in `tok_meta` like every derived artifact, and every
  stored v1 row repacks in the same pass — no transformer forwards, no
  migration event; v1/v2 coexist and rescoring reads both.
- **LUT MaxSim**: per query row, dot-product tables over the codebook are
  built once (for all candidates); scoring a candidate token is then 16
  table adds instead of a 128-dim dot product (`dot_tables`/`adc_dot`).
  Honest timing note: LoCoMo search is 96.7 vs 92.7 ms/q — the bench
  amortizes each store's one-time train+repack into its query phase, and
  the ~80 ms tract query forward dominates either way; the LUT win becomes
  visible when the `ort` query-forward follow-up (~40 ms) lands.
- **Punctuation pruning** (ColBERT convention): doc-side punctuation rows
  attend normally but are excluded from the stored matrix.
- **Portable artifacts stay universal**: v2 matrices export decoded back to
  v1 int8 — the codebook never leaves the vault; imports work anywhere.

## 0.19.0 — Atomic audit chain

Durability: the last known correctness gap. The audit-chain head used to
live only in the vault manifest, written *after* the SQLite commit — so a
power loss in between left the chain and the data disagreeing, and the next
`verify` raised a **false tamper alarm** for a mere crash. Worse, several
mutation paths (delete, KG, tunnels) didn't even wrap their own data+audit
statement pairs in a transaction.

- **The committed head now lives in SQLite** (`chain_meta`) and advances via
  `chain_append` **inside the same transaction** as the data and audit row
  it covers — at all six mutation sites (drawer write, drawer delete, KG
  add, KG supersede/invalidate, tunnel create, tunnel delete). A crash can
  never separate a record from its chain entry.
- **The manifest becomes a lagging out-of-database rollback anchor**
  (`Vault::anchor_manifest`, written post-commit). Open-time reconciliation
  distinguishes the two failure shapes: an anchor **behind** the database
  chain is a crash artifact and is fast-forwarded silently; an anchor the
  database chain **never produced** means the database was rolled back or
  forked — `ManifestTampered`. A power loss is not a tamper alarm; a
  restored old database still is (both crash states are test-simulated).
- `verify` applies the same two-part check: audit rows must reproduce the
  committed head exactly, and the anchor must appear in that chain.
- Vault API: `commit_write` is replaced by pure `chain_next_hex` +
  `chain_genesis_hex` + `anchor_manifest` (the store owns *where* the head
  lives; the vault owns the key). Existing databases adopt `chain_meta`
  from the manifest on first open — no migration step.
- Known residual (documented): an attacker replacing db **and** manifest
  together with a mutually-consistent older pair remains undetectable
  without an external witness — unchanged from before, noted for a future
  remote-anchor option.

## 0.18.0 — Portable derived artifacts & token backfill

Restore economics, tiers 1–2. Token matrices are the expensive derived data
(one transformer forward per drawer — ~2 h per 20k drawers on tract) and a
pure function of `(content, model)`: legitimate content-addressed cache. So
migrations now carry them, and palaces that don't have them recover in
bounded background passes instead of blocking.

- **Portable artifacts**: `/v1` export lines gain optional
  `tok = {model, b64(packed)}`; import validates in the parse phase
  (bad artifacts fail the whole body cleanly) and re-seals each matrix
  under the **destination** vault's key. Store API:
  `token_artifact(id)` / `import_token_artifact(id, model, packed)`.
  Safe by construction: artifacts are advisory, model-matched at rescore
  time, and results are still HMAC-verified — a wrong or malicious
  artifact can only mis-rank, never forge. Test-asserted: a destination
  whose encoder panics on any doc-encode rescores correctly from imported
  artifacts alone, with at-rest bytes differing from both the source's and
  plaintext.
- **Bounded backfill**: `undercroft repair --tokens` (store:
  `late_backfill(limit)`) encodes drawers missing a matrix under the
  attached encoder's model, in batches — a restored or pre-encoder palace
  serves at fusion quality immediately and climbs to late-interaction
  quality as coverage grows.

## 0.17.0 — Sealed-tier encrypted-at-rest index

Sealed vaults had one retrieval mode: decrypt-scan every embedding on every
query. They now run the full PQ/IVF prefilter under the same invariant —
**nothing plaintext-derived ever touches sealed disk in clear** — and search
went from **2.1 → 33.4 q/s at N=20k (×16)** and 1.1 → 11.8 at 50k (×11), at
parity with the plaintext hmac-only index. Encryption stops being a
query-time cost.

- **Sealed index storage** (`Vault::index_at_rest`/`index_from_rest`, `/pq`
  AAD domain): every code row is sealed as `(list ‖ code)` bound to its row
  seq; the codebook and IVF centroids in `pq_meta` are sealed under synthetic
  record ids. The plaintext `list` column stays `-1` on sealed vaults — a
  clear list id would leak which drawers are semantically similar. Identity
  transform on hmac-only vaults, so existing indexes read unchanged.
- **Decrypt-once RAM cache**: search decrypts all rows one time per open
  (~52 B/drawer — 2.6 MB at N=50k, bounded) and ADC-scans + IVF-probes in
  RAM; writes keep the cache coherent with the plaintext in hand, deletes
  drop it. At N=50k the cache even out-ran the hmac path's per-query SQLite
  streaming — adopting the same cache for hmac-only is a noted follow-up.
- **Threat model**: an offline attacker sees fixed-size sealed blobs — i.e.
  the drawer count already visible from the drawers table. Nothing about
  content, similarity, or cluster structure.
- **Invariant test strengthened, not relaxed**: sealed vaults may now hold
  the PQ tables, but no row contains a plain code, the metadata doesn't
  decode without the vault key, list ids are never in clear, and results
  agree with the decrypt-scan baseline across a cache rebuild. e2e
  re-asserts the at-rest plaintext grep with the index present.
- `set_pq` / `UNDERCROFT_RETRIEVAL=pq` now applies to both security levels.
- Docs: sealed-tier measured tables, and a new **"Restore economics"**
  design section (portable content-addressed derived artifacts, background
  backfill, token-store PQ with register-LUT MaxSim — the roadmap for
  fast shard restore).

## 0.16.0 — ColBERT late interaction

The core-count-independent second retrieval stage. The cross-encoder reranker
runs one transformer forward per candidate per query — great on 24 cores,
painful on 4. Late interaction moves that work to ingest: each drawer is
encoded **once** into a per-token embedding matrix; a search encodes the query
in **one** forward and re-scores the fusion top-N by MaxSim over the stored
matrices. **Measured (LoCoMo, full 1,982 QA, hash embedder + colbertv2.0 on
tract): 94.6 → 96.77% R@10 at a flat 92.7 ms/query** — the same on any core
count, where the cross-encoder's 97.68% costs 101–327 ms on 24 cores and ~5×
that on 4. Off by default; the cross-encoder wins when both are configured.

- **`LateInteraction` trait + MaxSim kernel + int8 token pack**
  (`undercroft-core/src/late.rs`): row-major unit-row matrices, per-row-scale
  int8 quantization (~4× smaller, scores within noise — round-trip tested).
- **`OnnxColbert`** (`undercroft-embed-onnx`, `onnx` feature): tract-run, two
  fixed-shape plans (query 32, doc 256), faithful ColBERT v2 conventions —
  `[Q]`/`[D]` marker tokens and attending `[MASK]` query augmentation.
  Models are user-supplied: `UNDERCROFT_RERANKER=colbert` +
  `UNDERCROFT_COLBERT_MODEL` (doc export) / `_QUERY_MODEL` / `_TOKENIZER`.
  **Export recipe matters**: fixed-shape legacy exports only — the dynamo
  exporter's symbolic dims and dynamic-axes `Range` ops both fail in tract
  (recipe in docs/RETRIEVAL_SCALING.md).
- **Sealed-tier encrypted-at-rest token store**: `Vault::tokens_at_rest`
  seals every matrix under a `/tok` AAD domain (distinct from content and
  `/emb` — one drawer's blobs can never be swapped). Sealed vaults get the
  full feature: the first plaintext-derived store that is allowed on sealed
  disk, because it is never in clear (test-asserted at both levels). The
  hmac-only/plain vs sealed/encrypted tiering mirrors the rest of the stack.
- **Store stage** (`undercroft-store/src/latestage.rs`): advisory write-time
  encode (a drawer written before the encoder was attached keeps its fusion
  rank — never sunk); MaxSim normalized onto the fusion score scale;
  `delete_drawer` purges the matrix.
- Wired through the CLI (search / serve-mcp / daemon) and the bench harness
  (shared encoder across per-question palaces).

## 0.15.0 — IVF inverted lists & the PQ scan-path fixes

IVF partitioning on top of the v0.14.0 PQ codes — and, more consequentially,
the three structural scan-path costs that benchmarking it exposed and removed.
Net effect (synthetic corpus, hmac-only, within-run comparisons): **flat PQ
~45% faster at N=20–50k** (23.9 → 34.4 q/s at 20k, 10.1 → 14.8 at 50k) with
IVF adding **+7–11% on top at exact recall parity** (99.6%/99.1% R@5), a share
that grows with corpus size — the probed scan is the only query cost that
scales with N.

- **IVF inverted lists** (`pqidx.rs` + `CoarseQuantizer` in `pq.rs`):
  `nlist ≈ √N` deterministic k-means centroids partition the corpus; a query
  ADC-scans the `nprobe` nearest lists. Non-residual — codes are unchanged;
  probes that return fewer than `k` rows widen to the flat scan, so IVF can
  narrow the candidate set but never empty it. On by default above
  `UNDERCROFT_IVF_MIN` (8192, `off` restores flat), probe count via
  `UNDERCROFT_IVF_NPROBE` (default `nlist/4` — recall tracks the probed
  *fraction*: 3% → 68.7%, 11% → 86.9%, ~25% → parity). Partitions persist in
  `pq_meta`, self-heal, and retrain when the corpus doubles past their
  training size. hmac-only vaults only, unchanged invariant.
- **Scan-path fixes** (each exposed by a measured sweep, each re-measured):
  codes physically clustered `WITHOUT ROWID, PRIMARY KEY (list, seq)` — a
  probed list is one sequential range scan, not per-row B-tree fetches
  (which had made a 23%-fraction probe *slower* than the flat scan);
  coherence verification is **event-driven** (first search after open or
  after a failed encode — never per query; the guard join was costing more
  than the scan it guarded); the ADC scan reads `drawer_pq` alone
  (`delete_drawer` purges its code row; the per-row `JOIN drawers` existed
  only for delete-orphans, which hydration filters anyway). v0.14.0 tables
  migrate in place.
- **CLI + `/v1` wiring**: `UNDERCROFT_RETRIEVAL=pq|hnsw` now works in the
  `undercroft` binary (search / serve-mcp / daemon) and per-tenant in the
  multi-tenant server — previously bench-only. `hnsw` requires the new cli
  `hnsw` pass-through feature and errors clearly without it. +5 e2e checks
  including the sealed-vault no-PQ-tables invariant on disk.
- **Bench**: `synth --queries N` caps the query phase to an even sample so
  large-N sweeps finish in minutes; recall is reported over the sampled
  queries.
- Docs: RETRIEVAL_SCALING / RESULTS "every lever" / the public retrieval
  page updated with the full fix ladder and final tables.

## 0.14.0 — Retrieval performance & scaling

The retrieval-performance track: every configurable lever measured end to end
(LoCoMo + synthetic corpora, 24-core host, in Docker), and the expensive ones
retired. Headline: the optional cross-encoder reranker drops **16.6 s → 101–327
ms per query at ~98% R@10**, and large hmac-only corpora get a bounded-RAM
on-disk ANN prefilter. Everything is opt-in; default search behaviour and the
default build are unchanged.

- **Reranker latency, step by step** (302-QA LoCoMo subset, R@10 ≈98%
  throughout): rayon-parallel scoring across cores (16.6 s → 694 ms) →
  `UNDERCROFT_RERANK_TOP_N` is now a true rerank-pool cap (accuracy plateaus at
  ≈20; a real latency knob) → `Reranker::score_batch` becomes the whole-pool
  trait interface so the backend owns parallelization → ONNX Runtime backend +
  int8 models take top_n=20 to **327 ms** and top_n=5 to **101 ms**.
- **New `undercroft-embed-ort` crate**: an ONNX Runtime inference backend
  (embedder + reranker) as an opt-in alternative to the pure-Rust tract
  default (~2.5× faster per forward, identical scores; C++ dependency — see
  the `ort-build` compose service). Session pool sized to cores
  (`UNDERCROFT_ORT_POOL`; `pool=1` = batched mode for few-core boxes). int8
  quantized models (4× smaller files, user-supplied, no code change) attack
  the memory-bandwidth bound; ingest embedding drops 24 s → ~5 s.
- **On-disk Product-Quantization prefilter** for hmac-only vaults: 48-byte PQ
  codes per drawer (`drawer_pq`) + a ~400 KB codebook (`pq_meta`), incremental
  encode on write, count-mismatch self-heal on open. Recall is *flat in corpus
  size* (98.6% at N=20k → 98.9% at N=50k) with codebook-only RAM, while
  in-memory ANN recall collapses untuned. Opt-in via
  `PalaceStore::set_pq(true)` (bench: `UNDERCROFT_RETRIEVAL=pq`). **Sealed
  vaults are untouched** — the no-plaintext-derived-index-on-disk invariant
  holds and is test-asserted; CLI wiring is a follow-up.
- **Experimental in-memory HNSW prefilter** (`hnsw` feature, off by default):
  fastest option measured (378 q/s at N=50k) but O(corpus) RAM and recall
  needs `ef`/over-fetch scaling with N — kept as a raw-speed option, RAM-only,
  never persisted.
- **Multi-tenant `/v1` shared-model reranker**: the tenant server loads one
  ONNX model and hands every per-vault store an `Arc` handle
  (`Tenancy::with_reranker`), closing the v0.13.0 follow-up.
- **Benchmarks**: full sharded LoCoMo reranker run — R@10 **94.6 → 97.68**
  (1936/1982); conversation-scoped `--skip`/`--limit` sharding +
  machine-readable `LOCOMO_RAW`/`LME_RAW` numerator lines; per-phase
  `LOCOMO_TIMING` (ingest vs search); `--backend` for measuring remote
  vector backends (confirmed idle untrusted accelerators — never a latency
  or accuracy lever).
- **Docs**: `docs/RETRIEVAL_SCALING.md` (architecture + every measured
  number + the IVF/ColBERT plan), the public "Retrieval, scoring & scaling"
  site page, `docs/MULTI_TENANCY.md`, and the `benchmarks/RESULTS.md`
  "every lever" section with scenario recipes.
- `.gitattributes` forces LF checkout (Windows clones broke bind-mounted
  scripts inside the Docker test containers).

## 0.13.0 — Cross-encoder reranker

An optional second retrieval stage. After hybrid search's cosine+BM25 fusion
ranks a candidate pool, a cross-encoder re-scores the top-N with the full
`(query, passage)` pair — the interaction a bi-encoder embedding can't capture —
and re-orders them before the final `limit` cut. Off by default; when unset,
search behaviour is byte-for-byte unchanged.

- **`Reranker` trait** (`undercroft-core`) + **`OnnxReranker`**
  (`undercroft-embed-onnx`, under the existing `onnx` feature) — reuses the
  tract/tokenizer machinery, pair-encodes, reads the relevance logit, sigmoids.
  Model is **user-supplied**: `UNDERCROFT_RERANK_MODEL` / `_TOKENIZER` +
  `UNDERCROFT_RERANKER=onnx`. `UNDERCROFT_RERANK_TOP_N` (default 50) bounds latency.
- Wired into `search`, `serve-mcp`, the daemon, and the `longmemeval`/`locomo`
  benchmark harness. Pairs with either embedder (hash or ONNX).
- **Targets BERT-family cross-encoders** (`cross-encoder/ms-marco-MiniLM-L-6-v2`):
  tract 0.22 can't run DeBERTa rerankers (mxbai-rerank hits an unsupported `Sign`
  op), so that's the shipped default.
- **Directional lift** (subset smoke, hash embedder + ms-marco reranker, real
  data): LongMemEval-S R@5 **98.3 → 100.0** (60-question subset), LoCoMo R@10
  **94.6 → 97.2** (full 1,982 QA). The full sharded LongMemEval-500 +
  MiniLM-embedder matched-model run and the landing headline bars are a
  follow-up; the multi-tenant `/v1` reranker pairs with the shared-model item.

## 0.12.0 — Full observability & alerting stack

Metrics were already there; this turns `deploy/observability/` into the full
operability picture — **logs, traces, and alerting** — and adds a tamper
runbook. No API or on-disk format changes; default (non-telemetry) builds are
unaffected.

- **Distributed traces.** New metadata-only spans on the request/search/save/KG
  hot paths (`undercroft-obs`; zero-dep no-op without `--features telemetry`),
  exported over OTLP to **Tempo**. Spans carry operation, route, and vault id —
  never query text, drawer content, wing/room names, or keys.
- **Alerting.** **Alertmanager** + Prometheus rules: `PalaceTamperDetected`
  (critical, broken out by `surface`), `AuditChainStalled`, `UndercroftDown`,
  `HighSearchLatencyP95`, `HttpServerErrors`, `AuthRejectionsSpike`. Routed to a
  self-contained webhook `alert-sink` (swap in Slack/email/PagerDuty).
- **Logs.** **Loki** + promtail ship Undercroft's structured JSON logs
  (`UNDERCROFT_LOG_FORMAT=json`) — metadata only.
- **Grafana.** Loki/Tempo/Alertmanager datasources; the dashboard gains
  tamper-by-surface, HTTP 5xx, auth rejections, an active-alerts table, logs,
  and traces panels. A `grafana-image-renderer` sidecar enables PNG export.
- **Tamper runbook** (`RUNBOOK.md` + docs) — where it happened, and how to
  confirm (`verify`), mitigate (`--read-only`, preserve evidence), fix (verbatim
  restore from `backup`), and prevent. The alert's `runbook_url` links to it.
- **Fixes surfaced while wiring this up:** the OTLP→Prometheus exporter emitted
  double-`_total` counter names (`without_counter_suffixes`), and OTLP traces
  posted to the base URL instead of `/v1/traces` (404); both fixed. The
  observability compose now initializes the palace before `serve-http`.
- **Site.** Landing gains an "Operate it" section; observability docs gain
  alerting/logs/traces sections with real screenshots.

## 0.11.1 — Palace Monitor fixes

Bug fixes to the Palace Monitor UI (`GET /monitor`), plus a website section
showcasing it with real screenshots. No API or on-disk changes.

- **Archivist now animates.** Search events no longer freeze the archivist in
  its `read` pose (under load it was permanently stuck); filing walks run
  uninterrupted, the walk-cycle bob is fixed (it checked states that never
  existed), and the archivist gently wanders between wings during lulls.
- **Speed slider works.** It now scales the whole simulation tempo instead of
  only the (previously frozen) archivist. The tamper beacon's real-time
  duration stays unscaled.
- **Sound button works.** A confirmation chirp on enable plus throttled soft
  ticks on live save/search events, alongside the existing tamper siren.
- **Drawer tiles grow with writes.** The per-wing grid uses an absolute
  log-scale fill so it visibly fills as a wing accumulates drawers, instead of
  a relative-to-busiest scale that barely moved (and lit all tiles for a
  brand-new wing).
- **Website.** New "Palace Monitor" section on the landing page and screenshots
  in the Observability docs, captured from the monitor connected live to a
  vault filed from the LoCoMo benchmark, including a real `hmac-fail` tamper
  alarm.

## 0.11.0 — Palace Monitor UI

A self-contained pixel-art dashboard served at **`GET /monitor`**, driven
by the v0.10 SSE stream. Opt-in behind `--features telemetry`; the page is
unauthenticated static HTML (no secrets), metadata only, sealed vaults show
aggregates only.

- **Palace Monitor** — a retro game-world view: an archivist files drawers
  into wings as writes land, searches pulse the wings, the audit chain
  stamps on each commit, and an **ambulance beacon** fires on a real tamper.
  Runs in demo mode until you enter the bearer token and pick a vault.
  Fully inlined (no external requests); uses `fetch()` streaming so it can
  send the bearer (`EventSource` can't).
- **Live tamper alarm** — new `hmac-fail` stream event, emitted at every
  HMAC-verify-failure site (drawer/kg/tunnel/manifest), powers the beacon.
- **`GET /v1/vaults`** — lists vault ids for the picker (bearer-gated;
  disabled under per-vault assertions).

## 0.10.0 — Live memory telemetry

Turns the v0.9.0 point-in-time observability into a **live push stream** —
the foundation the Palace Monitor UI will consume. Opt-in behind
`--features telemetry`, default build untouched, metadata/counts only,
sealed vaults expose only aggregates. Additive and non-breaking.

- **SSE stream** — `GET /v1/vaults/{id}/stream` (bearer + per-vault
  assertion) pushes a periodic `sample` frame (aggregate counts) plus
  discrete **event pings** (`drawer-saved`, `drawer-deleted`, `search`,
  `kg-triple`, `chain-commit`) as they happen. Each connection is served
  on its own thread that reads only an in-process broker — never a store —
  so the single-threaded server keeps serving and streaming can never
  touch content. Sealed vaults suppress wing/room names.
- **In-process sampler** — a bounded per-vault ring buffer, filled on a
  tick (default 2s, `UNDERCROFT_SAMPLE_INTERVAL_MS`) but only for vaults
  with an active subscriber, so it costs nothing when nobody is watching.
  Also populates the previously-unset `kg_triples`/`kg_entities`/
  `store_bytes` Prometheus gauges.
- **History backfill** — `GET /v1/vaults/{id}/stats/history?window=N`
  returns the recent samples so a fresh client can draw the past.

## 0.9.0 — Observability & telemetry

An **opt-in** observability layer, off by default with zero extra
dependencies and zero overhead unless built with `--features telemetry`.
Everything reported is metadata and counts only — never drawer content or
key material — and nothing leaves the process unless explicitly pointed
somewhere. Additive and non-breaking.

- **Structured logs.** The pre-existing `eprintln!` diagnostics route
  through one macro; with `telemetry` on they become `tracing` events,
  level via `UNDERCROFT_LOG`, `json` output via `UNDERCROFT_LOG_FORMAT`.
- **Prometheus `/metrics`.** Opt-in via `UNDERCROFT_METRICS=1`, served on
  the bind address behind the existing bearer token (absent otherwise).
  Counters for search / drawer writes+deletes / KG writes / chain commits
  / **HMAC verify failures** (the tamper signal) / HTTP requests / auth
  rejections / vault opens; histograms for search and request latency;
  per-vault gauges for drawer count and audit-chain height.
- **OpenTelemetry export.** Set `UNDERCROFT_OTLP_ENDPOINT` to export traces
  over OTLP/HTTP (unset ⇒ no network egress). Fully synchronous — no async
  runtime is introduced; metrics stay on the Prometheus pull model.
- **New crate `undercroft-obs`** — a shim every instrumented crate depends
  on that compiles to no-ops (and pulls no dependencies) without the
  feature. Enable end-to-end with `--features telemetry` on the CLI.

## 0.8.0 — Multi-tenant server support

`serve-http` becomes a first-class per-tenant memory engine (one vault per
customer), additive and non-breaking — MCP stdio, the `/mcp` HTTP surface,
and single-vault behavior are unchanged.

- **Per-vault request authorization.** Set `UNDERCROFT_ASSERTION_SECRET` and
  every `/v1` request must carry `X-Vault-Assertion: <ts>:<hmac>` where
  `hmac = HMAC-SHA256(secret, "<ts>|<vault_id>")`, verified within ±120s
  with a constant-time compare. An assertion minted for vault A cannot
  authorize vault B. `undercroft assert-header <vault>` mints one.
- **Versioned REST surface** (`/v1`) in the same process, same bearer:
  create/delete vault, stats, save/search/delete drawer, and a lossless
  NDJSON export/import pair (import returns the exact record count) for
  migrating a vault between instances.
- **Externally-supplied embeddings.** A vault created with
  `embedder: external:<name>@<dim>` stores caller-provided vectors, refuses
  writes/searches without one, and enforces the dimension — sealing those
  vectors like internally-computed ones.
- **Semantic dedup-refresh on save.** `dedup_threshold` on a write refreshes
  an existing same-wing/room drawer in place (cosine ≥ threshold, id kept)
  as an audited update, making bulk re-ingestion idempotent.
- **Orchestrated deployment** documented: headless `init` from
  `UNDERCROFT_PASSPHRASE`, key never logged, one instance per tenant (compose
  example in docs/remote-server.md).

## 0.7.2 — BM25 rank fusion (new search default)

- Search now blends cosine with a real **Okapi BM25** lexical score
  (IDF-weighted, `k1=1.2`/`b=0.75` length normalization, one-typo
  tolerant) computed over the decrypted, HMAC-verified candidate set,
  replacing the old flat term-overlap fraction. Measured lift with the
  zero-model hash embedder: **LongMemEval-S R@5 90.4% → 95.0%** (the
  paraphrase-heavy preference category 36.7% → 66.7%), **LoCoMo session
  R@10 92.7% → 94.6%** — where the hash embedder now edges past the
  earlier MiniLM run. See benchmarks/RESULTS.md for the full ablation.
- Fusion is selectable with `UNDERCROFT_FUSION`: `bm25` (default),
  `legacy` (the prior term-overlap blend, reproduces the old numbers
  exactly), or `rrf` (reciprocal-rank fusion — scale-free but benchmarks
  below bm25). Fusion only re-ranks already-verified candidates; every
  security guarantee is unchanged, and it is embedder- and
  security-level-independent.

## 0.7.1 — FTS5 BM25 prefilter for hmac-only vaults

- hmac-only vaults now carry an external-content FTS5 index over drawer
  content (trigger-maintained through upsert/update/delete/dedup/restore,
  rebuilt on open if missing or stale). Searches over palaces of 2048+
  drawers prefilter candidates to the BM25 top-K before the usual
  HMAC-verify + hybrid re-rank; if FTS matches nothing the full scan runs
  instead, so semantic-only recall is preserved. Tune or disable with
  `UNDERCROFT_FTS_PREFILTER_MIN` (a number, or `off`).
- Sealed vaults are unchanged: no plaintext-derived index is ever created
  (test-asserted), search remains decrypt-scan by design.

## 0.7.0 — Measured benchmarks, Weaviate, compressed storage

- First measured benchmark results, in-repo (benchmarks/RESULTS.md), with
  the zero-model hash embedder: LoCoMo session R@10 92.7% (beats
  upstream's published raw and hybrid), LongMemEval-S R@5 90.4% (6.2 pts
  under upstream's model-based raw; gap isolated to the
  single-session-preference type).
- Weaviate backend (REST + GraphQL, vectorizer:none) — fifth live-tested
  remote index; PUT-vs-POST upsert semantics handled.
- Storage growth control: zstd compress-then-encrypt for sealed content
  (legacy records stay readable) and int8 embedding quantization with
  per-vector scale (4x smaller, cosine drift < 0.1%), both test-covered.


## 0.6.0 — Benchmark adapters + in-process vector cache; PARITY complete

- `undercroft-bench locomo|convomem|membench`: adapters for the remaining
  three upstream benchmarks (session / message / turn-level evidence
  recall, same protocols as the Python harnesses), fixture-tested so the
  scoring is trustworthy before any dataset is downloaded.
- `PalaceStore::warm_embedding_cache`: decrypt-once in-memory vector cache
  for long-running modes (serve-mcp / serve-http / daemon), kept coherent
  across upsert/delete/repair — fills embedded ChromaDB's in-process index
  role without persisting anything plaintext-derived.
- docs/PARITY.md "not ported" list is now empty.


## 0.5.1 — Memory-extraction eval + CLI localization

- `undercroft-bench model-eval memories`: SQuAD-style token-F1 with greedy
  one-to-one alignment (threshold 0.5, CJK-aware per-character tokens);
  reports match P/R/F1, mean token-F1, and type accuracy.
  `extract_memories` added to undercroft-llm.
- CLI result strings localized in the 9 model_eval dataset languages
  (de/es/fr/hi/it/ko/pt/ru/zh) via UNDERCROFT_LANG, English default and
  fallback; placeholder-preservation enforced by tests. Errors/help stay
  English (exit codes are the scripting contract).


## 0.5.0 — Final parity gaps closed

- Milvus backend (RESTful v2, standalone) in undercroft-index — all four
  remote backends now tested live in compose.
- undercroft-llm crate: local-runtime client (Ollama + OpenAI-compatible);
  `undercroft refine` extracts entities and KG facts from drawers (opt-in
  via UNDERCROFT_LLM_URL; verbatim content never modified).
- model_eval restored: multilingual datasets (10 languages) +
  `undercroft-bench model-eval calibration|entities [--lang]`.
- Closets: `undercroft closets` + `undercroft_get_closet_index` MCP tool —
  deterministic compact index (the AAAK port), computed on demand.
- Typo-tolerant search: Levenshtein-1 fuzzy term matching in the lexical
  scorer (spellcheck port).
- mdBook documentation site in website/ (`docker compose run --rm site`).


## 0.4.0 — Ecosystem parity: benchmarks, team server, integrations

- `undercroft-bench`: LongMemEval-protocol harness (session R@k, NDCG@k,
  per-type breakdown) + deterministic synthetic benchmark wired into CI.
- `serve-http`: MCP over HTTP for shared team servers — bearer token
  mandatory on non-loopback binds, `--read-only` mode, `/healthz`.
- `daemon run` (periodic transcript sweep), `transcript render`,
  `import` (undercroft + mempalace export formats).
- Recreated ecosystem directories natively: `deploy/` (compose server,
  systemd units), `.claude-plugin/` (commands, hooks, skills, MCP),
  `hooks/`, `commands/`, `skills/`, `rules/`, `integrations/`, `docs/`
  (incl. PARITY.md), `examples/`, `.devcontainer/`, SVG logo.


## 0.3.0 — Remote backends + pluggable embedders

- Remote vector indexes (Qdrant, Chroma, pgvector) as untrusted search
  accelerators: sealed content uploaded, candidates HMAC-verified and
  re-ranked locally; `index push/status`, `search --backend`.
- Pluggable embedders with per-vault identity tracking; ONNX
  sentence-embedder crate (tract, feature-gated).
- Compose services + backends-e2e suite against real servers.


## 0.2.0 — Python removal + feature parity port

- Removed the legacy Python implementation and all Python tooling; the Rust
  workspace is now the only implementation.
- Ported: knowledge graph (temporal triples with validity windows),
  conversation mining (Claude Code / Codex JSONL transcripts) + sweep,
  drawer management, agent diaries, hallways/tunnels navigation, dedup,
  stats, backups, repair, hooks output, expanded MCP tool surface.

## 0.1.0 — Rust conversion + vault layer

- Rust workspace: undercroft-core / undercroft-vault / undercroft-store /
  undercroft-cli (fork of MemPalace, Python).
- New hardened memory-management layer: isolated vaults, per-vault HKDF key
  derivation, XChaCha20-Poly1305 sealed content, HMAC-SHA256 integrity tags,
  tamper-evident audit chain, sealed / hmac-only levels.
- Docker-first build + test harness (unit, integration, e2e UI/UX suites).
