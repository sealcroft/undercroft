# Agent guide — retrieval invariants

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the full text of the
invariants on cross-lingual retrieval, signal versus inference, recall versus
precision, and independent per-item scoring as a poison-resistance property.
Read it when your work touches search, fusion, morphology, the temporal
scanner, a codebook or a training sample.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12). PROPOSED with this split, for the maintainer's approval in its
pull request: this full text governs over any one-line statement of the same
rule in the core. In the moved text, "this file" and "here" mean the guide as
a whole — the core and its reference documents.

---

- Cross-lingual retrieval is the **embedder's** job and the default cannot do
  it: `HashEmbedder` is feature hashing over surface forms (word unigrams +
  bigrams + char trigrams, SHA-256 into 384 buckets), so texts match only on
  shared literal tokens/trigrams — measured, an EN/AR translation pair scores
  *below* an unrelated sentence, and `car`/`automobile` do not match either.
  Needs a multilingual model via `onnx`/`ort`/**`http`**, or an external
  vault. Measured 2026-08-03 (first real xlingual run, bge-m3 served):
  R@1 88–100% per pair on a foreign-target corpus; the mixed-corpus
  collapse that run filed (~0% — the hash-calibrated `(cos+1)/2` map
  compressed a served model's semantic channel under same-language BM25
  noise) is **CLOSED the same day** by `Embedder::semantic_floor` +
  `calibrated_semantic`: the measured unrelated floor becomes the map's
  neutral, hash declares floor 0 and keeps the shipped expression
  verbatim (bit-identical default, pinned), the admission gate rides the
  same calibration, `UNDERCROFT_SEMANTIC_FLOOR` declares it for external
  vaults. Gates: LoCoMo hash digit-for-digit; mixed R@5 0–4%→53–88% at
  the default weight, 100.0% every pair under a declared
  `UNDERCROFT_FUSION_WEIGHT=0.70` — map and weight compose, the default
  weight stays put. Replicated on a public corpus 2026-08-03 (FLORES-200
  dev, 12 pairs en↔{ar,de,el,ru,zh,th} on disjoint blocks, sealed,
  bge-m3 through the shipped TLS terminator; digit-identical over both
  transports): pre-reweight defaults R@5 36.2–98.8% — a
  lexical-evidence gradient with cross-SCRIPT pairs at 36–44%. **The
  script-disjoint fusion reweight (2026-08-04) made the default honest
  and the claim ONE-conditioned (a multilingual embedder suffices)**: a
  (query, candidate) pair sharing no letter script takes the blend at
  the weight ceiling — pairwise byte-readable evidence
  (`script::letter_script_mask`, finer than the segmentation enum which
  lumps Latin/Greek/Cyrillic; digits cancel nothing; unknown scripts
  never disjoint), never language-ID. Gates: LoCoMo hash
  digit-for-digit; FLORES arm A cross-script 36–44→**95–100% R@5 at
  defaults** with same-script rows digit-identical; declared-w arm
  digit-identical (the arithmetics coincide at the ceiling);
  false-friends untouched. Full tables + recipe in CHANGELOG. Reading dates *inside* the text is the
  **scanner's** job (`language`
  per request) and is independent of which embedder found the drawer.
  **A served embedder is worth far more than the repo used to think.** The
  standing conclusion was "a semantic embedder is NOT the biggest lever",
  resting on MiniLM measuring **+0.3pp** of turn all-gold on LoCoMo. That was
  a fact about MiniLM. Four served models measured on the same corpus give
  **+3.2 to +4.2pp** (hash 74.2% → nomic-embed-text 77.4, Qwen3-Embedding-0.6B
  78.1, bge-m3 77.9, mxbai-embed-large 78.4), i.e. the jump from hash to *any*
  modern embedder is the lever, and the spread *between* modern embedders is
  ≤1.0pp — public leaderboard order does not transfer here. Cost is 11–29×
  ingest (one HTTP call per drawer) and +20–57% search.
- **A signal is read; a convention is declared; nothing is inferred.** The
  never-guess contract forbids INFERENCE, not EVIDENCE — a distinction that cost
  five attempts to get right. Reading an era marker the writer typed, or a
  field order an unambiguous date in the same drawer demonstrates, or a
  convention the caller declared on `Locale`, are all legitimate. Deriving a
  calendar from surrounding script, or an era from a numeral system, or a field
  order from a numeric range, are not. Where no signal exists the honest answers
  are a documented default (day-first) or a recorded-but-unresolved mention —
  never a confident value, and never silence.
- **A recall measurement cannot justify a precision decision.** The
  promiscuity instrument (how many words of a real 50k vocabulary one query
  links to) counts reach and is blind to correctness; used to justify lowering
  the delimiting floor 8→5 it admitted `other`/`mother` and
  `count`/`accounting`. Any rule feeding a channel that ADMITS needs negative
  controls, not just a link count. **The controls now exist**:
  `false_friends_stay_apart` (store lib.rs) runs **58 rows in 10 control
  sets** — 49 `Apart` plus 9 pinned `Cost` — across en (declared and
  undeclared), nl (declared and identified-from-the-drawer), de, ar, fr,
  it, ru and el, end-to-end through `search` at realistic drawer length,
  asserting only the LEXICAL channels (a sem-only hit is the embedder's
  opinion, not a rule's) and failing in BOTH directions — `Verdict::Apart` must not gain a
  channel, `Verdict::Cost` is a pinned known price whose disappearance is good
  news that must be recorded rather than absorbed. Padding is asserted disjoint
  from every control word: the first run of this instrument reported the
  decisive Greek pair as already-related because the filler literally contained
  the query, so it measured the padding — flatteringly, and in the one place
  it mattered most.
- **Independent per-item scoring is a poison-resistance property, and
  spending it is a decision.** A poisoned drawer can win its own slot and
  nothing else: `HashEmbedder` is a function of one drawer's text, `maxsim`
  maximises over one drawer's rows, the admission gate is a constant from
  probe pairs, and the lexical channels are deliberately **pairwise** ("a
  stemmer builds an equivalence class one false friend poisons"). The only
  cross-drawer objects are BM25's IDF and the trained codebooks. So: anything
  that couples drawers may **propose candidates**, never **decide score** —
  the same rule `undercroft-index` applies to remote backends. Coupling in
  candidate generation risks *availability* (a legitimate drawer is not
  offered); coupling in scoring risks *integrity* and moves what decides the
  answer outside HMAC coverage.
  **BM25's IDF is the one place this rule is not held, and it is not held
  in the direction people assume.** This file used to say the IDF "stays
  global". It does not: `bm25_raw` computes `n = cands.len()` and counts
  `df` across that same candidate slice, so both IDF and `avgdl` describe
  the **retrieved pool**, not the corpus — a drawer that merely enters the
  pool changes every other candidate's score. Do not "fix" this by making
  it global: a corpus-wide `df` is *more* coupling, not less, and would put
  a genuinely vault-wide, unauthenticated quantity into the scoring path
  the invariant exists to keep narrow. State the real cost instead —
  **pool-shaping makes df-flooding cheaper by roughly corpus/pool.** To
  suppress a rare term's IDF an attacker must raise its `df`; against a
  corpus-wide count that means flooding a corpus-sized fraction, against a
  `max(256, depth·32)` pool it means only landing enough drawers *in that
  pool*, which the same query's own selection does for them. The damage is
  bounded to rank order within one answer and never reaches HMAC-covered
  bytes, but it is a real lever and it is written down rather than
  described as isolation it never provided. Codebook k-means is bounded only because
  vectors are L2-normalized before both training and encoding (`pq.rs`): on
  the unit sphere an attacker cannot buy influence with **magnitude**, only
  with **count**, which is what makes an unbounded breakdown point bounded at
  all — so that normalization is a security property, not only a
  distance-ordering one. It is **not** a small displacement bound (every
  centroid is a mean of in-ball points, so "at most the diameter" bounds
  nothing). The **NaN/Inf** channel (a non-finite vector from an
  `external:` embedder escaped normalization entirely — NaN/x = NaN)
  is CLOSED at the **write choke point** (`write_drawer_stmts`,
  2026-08-05): every write path inherits the refusal, including the
  batch that owns its own transaction. It was closed at
  `upsert_external` alone on 2026-08-04, and **this line's own claim
  that "the caller-supplied path was the one door" is what made that
  look sufficient** — there were three: `save_with_dedup_vec` (reached
  by a `dedup_threshold` in a `/v1` save body) and BOTH arms of
  `import_record` (every backup restore, and the orchestrator's tenant
  migration), the non-external arm of which means an ordinary hash
  vault was reachable. `1e39` is an unremarkable finite JSON number and
  `1e39_f64 as f32` is infinity. The
  **density** channel (owning fraction *f* bought ≈*f* of any uniform
  sample) is CLOSED at the draw (2026-08-03): `keyed_sample_capped`
  bounds any wing at `1/UNDERCROFT_TRAIN_SOURCE_CAP` (default 4) of every
  global training sample — within-quota corpora byte-identical, soft
  refill never shrinks the sample, deliberately inert below the sampling
  threshold where the per-wing codebook tier is the isolation instead;
  per-WING (adversarial bound) plus per-AGENT-CLAIM (accident bound,
  2026-08-03): a runaway agent flooding across several wings is capped
  by its `meta.agent` claim on the same quota; claim-less rows are
  deliberately exempt (no claims must not mean one giant pseudo-agent),
  and since a claim is the writer's own statement the wing grouping
  remains the security claim.
  **Which** rows train is a **stratified keyed** draw, never a stride:
  `pqidx::stratified_keyed` takes one row per equal block of insertion order,
  chosen by `Vault::sample_rank` (a fourth HKDF subkey, label `sample`,
  deliberately not the MAC key, length-prefixed) — reproducible **per vault**
  (not per corpus), unguessable to a bulk writer, exactly a no-op below the
  sampling cap, and a different label per artifact so the PQ codebook and the
  IVF centroids no longer train on the same rows. **An even stride was not
  only predictable, it was a landmine**: a systematic sample of a periodic
  corpus collapses when the interval shares a factor with the period —
  measured on `synth --n 16384` (interval 4, `FACT_TEMPLATES[i % 4]`) at
  **R@5 83.0%** against this draw's 99.7%, failing that harness's own gate,
  while `--n 20000` (interval 5) makes the stride look *better* at 99.8% vs
  99.4%. Never reintroduce position-only sampling; periodic insertion order
  is ordinary (round-robin per source, alternating speakers, one file a day). Caps differ by unit: 4,096 **drawers** at four sites, 16,384
  **token rows** for the token codebook. **Above a cap the sample's size and
  membership both change**, so a measurement taken there does not reproduce
  across builds or across vaults. The `kmeans` seed stride is *not* keyed and
  the residual is documented in `pq.rs` — accepted because density grants the
  same expected capture anyway. Every codebook write bumps a **generation
  counter** in `meta` (not in the artifact's own table —
  `invalidate_embedding_space` drops `pq_meta`, and that drop is the event
  most worth counting), surfaced on `VaultStats.codebooks`, `/v1/…/stats`
  (a hand-projected handler: adding a struct field does not reach the wire),
  and a gauge whose name must be in `undercroft_obs::GAUGE_NAMES` or it is
  silently dropped. A step means **re-quantization** for the three codebooks
  and **re-partitioning** for `pq-ivf`/`fde-ivf` (code bytes unchanged; the
  candidate set moves). A rebuild that reuses the stored codebook is not a new
  generation. The counter is outside HMAC coverage, so it is evidence about
  ambiguity, never about tampering.
