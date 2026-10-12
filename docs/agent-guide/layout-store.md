# Agent guide — `crates/undercroft-store`

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the Layout entry for
`crates/undercroft-store` — the largest in the guide: hybrid search and its
lexical channels, morphology, the semantic gate, the PQ/IVF/FDE prefilters and
scope resolution, the audit chain and the label guard, `verify` and its legs,
the knowledge graph, supersession, the import door, the backup, restore and
delete doors, the open-by-path door, admission control, forgetting, retention,
wing trust, remote-index search, the read choke point, the audit-namespace
vocabulary, egress auditing, key rotation and the external witness. Read it
when your work touches that crate. Search it for the module or door you are
changing rather than reading it end to end.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12), and it governs over any one-line statement of the same rule in
the core. In the moved text, "this file" and "here" mean the guide as a whole
— the core and its reference documents.

The `IRREGULAR` pair count in it is read by the `prose figures` preflight in
`tests/battery.sh`; reword that sentence only together with its row.

---

- `crates/undercroft-store` — per-vault SQLite storage, hybrid search (cosine +
  BM25 fusion; `SearchHit` carries **three** lexical channels — `lexical_exact`
  (the drawer said the word) and `lexical_morph` (it holds a word built on it —
  every pairwise relation `morph_relation` admits: whole-word containment
  (`shares_a_stem`, then plain containment once the shorter word reaches a
  per-script floor — 3 in the non-delimiting scripts, 8 in the delimiting
  ones, 8 being the threshold `contains_a_long_word` measured; Han takes no
  morph rule at all), the Arabic/Hebrew consonant skeleton,
  `ar_root_family`, `IRREGULAR`, `suffix_family`, the per-language inflection
  tables, and Greek's prefix family) both **admit** via `hits.retain`, kept
  apart so a caller can tell the two claims from each other; `lexical` ranks and
  discounts both morph and approximate evidence at half weight, capped at one
  per query slot. On `Fusion::Legacy` and the remote path `lexical_morph` is 0
  because `lexical_score`'s exact leg is unrestricted substring containment and
  already counts that relation as exact — a shipped asymmetry, now narrowed.
  The gate's third leg is the cosine, and it belongs to the **vector space**,
  not to the search code: `Embedder::semantic_admission_gate` is MEASURED from
  the embedder in hand (14 known-unrelated probe pairs, worst + a 0.06 margin;
  half same-language on purpose, because a cross-lingual-only set under-
  estimates the floor), resolved ONCE at open into a field — reading it per hit
  would put forward passes in the hot path. `HashEmbedder` declares the shipped
  0.56 rather than re-deriving it, so the default vault does not move;
  `ExternalEmbedder` refuses semantic-only admission outright, its vectors
  coming from a model this process has never seen; a probe that embeds to zero
  is an inference FAILURE, not a floor, and also refuses. One const for every
  embedder was how installing an E5/BGE model — unrelated pairs near 0.75,
  i.e. ABOVE the gate — retired the relevance gate silently, by configuration
  rather than by code. `UNDERCROFT_SEMANTIC_GATE` declares it (`off` = lexical
  channels only). A fold makes two words
  one token and `fuzzy_eq`/`same_word_family` forgive difference, so on one
  channel each of those would be a *membership* decision; `same_word_family`
  is the reachable half of morphology — nearly-a-prefix, ≥7 shared chars,
  tail ≤3, which excludes the `-tive`/`-tion` class at exactly 6 and cannot
  reach Russian case or Arabic broken plurals at all. `suffix_family` +
  `IRREGULAR` (**201 pairs** — counted, not remembered; the table grew from
  ~110 across several language passes and this line did not follow. A line
  regex answers 194 and is WRONG: rustfmt wraps the Cyrillic, Greek, Persian
  and Korean entries across three lines each, so count `),` terminators or
  quoted strings ÷ 2) admit on `lexical_morph`: SHAPE not length, which is
  what makes a 3-char stem safe here when floor-3 containment measured 33.3
  (en) / 68.5 (de) mean links and this measures 1.08 / 0.98, capped at 5. Both
  are PAIRWISE — a stemmer builds an equivalence class one false friend
  poisons (`πολύ`/`πόλη` is why Snowball Greek was rejected).
  `AR_ROOTS` × `AR_PATTERNS` → `ar_root_family` is the same channel's Arabic
  arm and lives here too, in this crate — the guide filed it under
  `undercroft-core`'s `temporal.rs` until 2026-08-17, interleaved into the era
  material, which is a map pointing at the wrong crate: Arabic is
  root-and-pattern, so 144 roots poured into 20 templates generate **2859**
  forms once (verified by re-implementing the generator and running it —
  2,880 instances, 2,859 distinct) and two words meet only when ONE ROOT
  explains both. An ALLOWLIST — a form the table cannot generate matches
  nothing — which is why it succeeds where three subsequence families failed:
  `بيت`→`بيوت` and `يجب`→`يجيب` are the same string operation and no rule over
  shape separates them. Measured HALF the shipped skeleton rule's promiscuity
  (3.25 vs 6.67) while taking 5 of its 6 drops. Ours, of necessity: every
  mature Arabic resource is GPL, research-only or LDC-non-redistributable
  (CAMeL Tools' code is MIT, its database is not). Note the era-marker
  machinery it used to sit beside — `AR_UNITS`, `ar_unit` — genuinely IS in
  `undercroft-core`, which is what made the misfiling easy to read past.
  `-er` is
  German-only via `MorphLang` on `SearchOptions` (`suffixes_for`), fed by the
  request's existing `language` — ONE declaration, two consumers: the date
  scanner (en/ar) and morphology (the thirteen `MorphLang::CODES`). For
  English `-er` admits
  `flow`/`flower`, `corn`/`corner`, `butt`/`butter`; declared German it takes
  `Kind`/`Kinder`, `Haus`/`Häuser`, `Buch`/`Bücher` and German goes 50%→**100%**,
  all on the lexical channel. **Declared FIRST, then detected** — this line
  said "declared, never detected" long after `language_of_drawer` shipped, and
  that was wrong in a way that matters: a declaration outranks the text, but
  when the caller declares NOTHING the drawer's own closed-class function
  words decide, per CANDIDATE, because a vault may hold several languages and
  the drawer is the unit that has one. A word two languages both claim votes
  for neither. So the price below is pinned for **detected** German too:
  under German, `flow`/`flower` DOES meet — and a drawer that merely reads as
  German gets German endings without anyone declaring them. Note promiscuity
  moved only +0.21 for `-er`, i.e. **the population metric could not see it and
  the negative controls could**. `drawers_fts` is a
  **standalone** fts5 table over `search_key(content)`, rebuilt on a
  `fts_key_version` mismatch: external-content over raw bytes disagreed with
  folded query terms, and the prefilter is only safe when it finds *nothing*)
  + optional cross-encoder rerank + ColBERT late-interaction
  stage (latestage.rs: token store, event-driven token-PQ codebook, LUT
  MaxSim), PQ/IVF candidate prefilter for both vault levels (pq.rs primitive,
  pqidx.rs index; both levels scan a load-once RAM code cache, slab-grouped
  by IVF list since v0.41.0; opt-in sealed page tier since v0.42.0 —
  `UNDERCROFT_PQ_PAGE_MIN`, one AEAD page per list + lazy per-probe
  decrypt + tail fold per batch, default off; **per-wing tier** — the wing
  is the retrieval unit a caller scopes to, and the global prefilter was
  wing-blind: its top-k can starve a wing entirely (candidates ∩
  `WHERE wing` = ∅ while the wing holds the answer — pinned by test) and
  its BUILD cost is corpus-shaped. What the tier provably buys is the
  build economics (wing-shaped vs corpus-shaped — though the headline
  build figures once quoted here, 17/73 min global retrains and 3.9/15.5 s
  wing builds, were ~95% a per-row-autocommit fsync BUG in the rebuild
  loops, since fixed with one transaction: smoke warm-up 36.2→2.3 s;
  post-fix builds are CPU-bound, full-scale numbers pending) and the
  starvation fix; its QUERY-LATENCY benefit is **dead,
  settled at 10⁶** (`pqscale`: unscoped PQ holds 24.3 → 31.0 ms/q from
  131k to 1M, no break — the 913 s/query figure was the *full-scan*
  path, which the global PQ tier answers alone). `pqscale` also filed a
  recall-leak defect (unscoped R@5 100.0 → 96.8 to 1M; fixed 256 pool vs
  growing competitors), **CLOSED by a two-stage pool + a freshness
  rule**: stage 1 fetches `live/64` ADC candidates (`UNDERCROFT_POOL_DIV`,
  `off` = the measured-leaky fixed floor), stage 2 cuts by exact cosine
  over just those candidates' embeddings to `stage1/8` = `live/512` —
  NEVER below, because a sealed vault has no lexical prefilter, so
  **hydration is the only door through which BM25 evidence reaches
  fusion**, and cutting to the fixed floor by pure cosine measurably
  regressed 1M to 98.9% — stage 3 hydrates as before; IVF partitions
  retrain at 1.5× training size (`ivf_fresh`, every site incl. FDE — the
  strictly-\>2× rule let a corpus sit at exactly 2.0× stale, and
  retrains cost seconds post-fsync-fix). **Shipped default measures R@5
  100.0% at every checkpoint 131k→1M — 20.4/32.6/59.1/112.7 ms/q since
  the parallel-fuse pass** (was 34.4/69.6/138.4/280.6; the search
  hotspot was `bm25_raw`'s serial per-candidate scan, found by the
  opt-in `UNDERCROFT_SEARCH_TRACE=1` phase-and-POOL trace AFTER parallel
  hydration measured zero — hydration, stage-2 decrypts and the BM25 tf
  rows now all fan out with rayon, order-preserving and byte-identical;
  dim/4 codes remain the unused shrink lever). Scoped queries:
  wing ~32 ms/q flat, room ~14, wing+room ~13 (scopescale).
  Wings past `UNDERCROFT_WING_PQ_MIN` (4096, `off` = no per-wing indexes;
  scoped queries then ride the scope filter over global candidates —
  starvation-free, but corpus-shaped generation)
  carry their own codebook/IVF/rows (`drawer_pq_wing`, sealed under
  `pqrow/<wing>/<seq>`; meta keys `codebook/<wing>`/`ivf/<wing>`, resealed
  dynamically at rotation since a fixed list cannot enumerate them);
  below the floor a scoped query full-scans its wing — bounded by the
  floor, exact, and still starvation-free. **Every other declared filter
  is scope-resolved before candidates are drawn** (`resolve_scope` →
  `resolve_seq_filter` → `*_candidates_in` — the ROUTING is its own
  function since O19, because WHICH call `resolve_seq_filter` receives is
  the decision, and a test of that function alone passes on both trees.
  A wing the per-wing tier already generates inside, beside a pure
  exclusion, no longer materializes the wing's own membership set: the
  wing leaves the NARROWING, never the query, and the exclusion rides as
  an `AllBut`. Recall cannot regress and the argument is arithmetic
  rather than sampled — `scoped_pool_k` is monotonic in its population
  and an exclusion's `narrows()` false is what makes the tier re-apply
  the corpus divisor):
  `room` was a plain `WHERE` over globally generated
  candidates — the wing defect with no tier and no fallback — and the FTS
  prefilter shared the shape (both were recorded gaps, both closed
  2026-08-02). A narrowing scope that fits the exact-scan ceiling
  (`max(hydrate_k, SCOPE_HYDRATE_FLOOR)` = `max(256, depth·32, 1024)`) drops
  the prefilter and is scanned exactly; a larger one
  gets membership-filtered candidates (PQ/wing-PQ/FDE filter during
  selection and widen when a probe under-delivers IN-SCOPE; FTS/HNSW
  filter their top-k and surrender to the bounded exact scan when the
  scope's share cannot fill the page), pools SIZED BY THE SCOPE.
  **"Cannot fill the page" was `inscope.len() >= depth` — five — until O53,
  and that test cannot answer its own question.** It conflates two things: a
  source that returned FEWER than `k` rows was NOT truncated, so its in-scope
  subset is COMPLETE and exact at any size (one candidate is a correct pool),
  while a source that returned exactly `k` may be hiding deeper in-scope rows
  below the cut. `seqs.len() >= k` is the exact, free answer, and the old test
  was wrong in BOTH directions — surrendering on small complete pools and
  accepting thin truncated ones. The floor when truncated is now
  `scoped_keep`, capped at the scope's own population, i.e. the same policy
  every semantic tier already used. It could not fire before: the expected
  in-scope count is `scope_live·k/n` ≈ `scope_live/64`, and any scope reaching
  this code is above `SCOPE_HYDRATE_FLOOR`, so `>= 5` was unreachable and
  nothing reported it. Measured on 6,940 hmac-only drawers with a 1,730-row
  wing: **70–80 scoped candidates against 256 unscoped**, and 2 of 18 queries
  answered differently from the exact scope scan; after, 1 of 18, against an
  unscoped control that differs at 2 of 19 — i.e. the scoped path stopped
  being worse than the prefilter's own baseline. Latency unchanged (69 ms both
  ways), because the scan it surrenders to is bounded by the scope.
  `VaultStore::accept_filtered_pool` is the one place both arms ask it.
  **A NARROWING and an EXCLUSION are not the same relation and
  `SeqFilter::{Only,AllBut}` is what keeps them apart** — one
  representation served both until 2026-08-11 and it was always the wrong
  one for half its callers. A declared `wing`/`room`/`kind` (or a trust
  `Allow`) is small relative to the corpus, so materializing its MEMBERS is
  the cheap side and its cardinality is a real population to size pools by.
  A bare trust `Exclude` — the shape the quarantine fence and a `standard`
  floor BOTH produce — is the complement of a small set, so materializing
  its in-scope side is O(corpus) **per query** and its cardinality is the
  corpus wearing a scope's name. One diverted drawer therefore reclassified
  every search on a prefilter-enabled vault as scoped: measured on a
  1,190-drawer real corpus under `UNDERCROFT_RETRIEVAL=pq`, **76 → 140
  ms/q** from a single quarantined row, and 77 → 69 (noise) once `AllBut`
  answered `narrows()` with `false`. So: **the scoped floors below apply to
  narrowings only**, `SeqFilter::admits` is the one membership door and
  `scope_population` the one geometry door, and the fence is unchanged —
  the SQL clause was always the accelerator and `verified_meta_admits` the
  boundary (A28). Note what the arithmetic hides: `scoped_pool_k` and the
  unscoped `max(hydrate_k, live/64)` coincide **exactly at live = 131,072**,
  which is the floor of the pqscale/scopescale grid, so every checkpoint
  either instrument measures reads 1.0× and neither could ever have seen
  this. Measure a scope-geometry claim at ~10³–10⁴, not on the grid.
  (`scoped_pool_k`/`scoped_keep`: stage 1 ≥ `min(scope, 2048)`,
  hydration ≥ `min(scope, 1024)`, floors measured by scopescale — the
  corpus divisors collapse to the fixed 256 floor exactly at wing sizes,
  which read R@5 89.6% until the scope-sized policy closed it at 100.0%
  gate-verified 131k→1M; scoped queries pay for it in latency that is
  **flat across 8× corpus growth**, which is the property scoping is for —
  wing ~32 ms/q, room ~14, wing+room ~13 — the same scopescale figures
  quoted a few lines up in this bullet. The "~85 ms/q" this line carried is the
  PRE-parallel-fuse number and was superseded on the same day it was
  written; it survives only as the "before" column in
  website/src/retrieval.md). Rejected deliberately: retry-on-empty
  (masks legitimate empties) and post-ranking filters (spend the pool on
  excluded rows — the defect restated). `idx_drawers_room` serves
  room-only resolution; the composite index is leftmost-prefix. A wing's population is MORE
  homogeneous than the vault's, so its codebook fits better, and
  derived-structure scope matches the isolation unit (wing) rather than
  the crypto unit (vault) — a writer in one wing no longer shapes the
  codebook scoring another. Stated honestly: the wing isolates candidates,
  not scores — BM25's IDF is **pool-shaped**, computed inside `bm25_raw`
  over `cands` (`n = cands.len()`, `df` counted across the same slice), so
  it never described the vault to begin with and does not describe the wing
  either; per-wing generation counters
  are dynamic artifacts `<wing>/pq-codebook` on the same stats surface,
  deliberately NOT per-wing gauges — cardinality), MUVERA FDE
  token-aware candidates (fdeidx.rs; core fde.rs construction; sealed
  `drawer_fde` + `fde_meta`; opt-in inverted tier via
  `UNDERCROFT_FDE_IVF_MIN` — slab-grouped cache + sealed centroids, kept
  default-off by its measured containment gate), experimental in-memory
  HNSW (hnsw.rs, `hnsw` feature), transactional audit chain (`chain_meta` + `chain_append`,
  and **chain.rs, the chain's one owner since ROADMAP O233**: the regime, the
  committed head and one streaming replay for `verify`, reconciliation and a
  rotation. The version-2 step folds each record's LABEL and TIME with its
  tag under a fifth HKDF subkey, `chain`, because a label is evidence — one
  relabel plus one deleted row lifted a quarantine floor with `verify` green.
  A vault switches at its first writable open by appending a
  `migrate/chain-v2` commitment whose tag is an UNKEYED digest of every
  earlier row, and the live head moves to `head_v2` while `head` is FROZEN —
  which is what makes a 1.5.x binary refuse the vault instead of appending
  version-1 steps to it; measured, and without the fence it wrote and
  rotated and left 1.6.0 unable to open the vault.
  **And since O237 it holds the LABEL GUARD, the door every reader that
  DECIDES from a label goes through.** O233 made a relabel break `verify`; it
  did not stop the readers acting on one first, and each of them found its
  record by `record_id` and replayed nothing — so one `UPDATE audit SET
  record_id` plus one `DELETE FROM wing_trust` took a floored search from
  zero hits to returning the quarantined drawer, with `verify` failing on
  `chain_ok` ALONE, i.e. only once somebody ran it. Two mechanisms, because
  one alone is unaffordable or unsound. **One lazy full replay per handle,
  on the first guarded read** — never at open, because the open is FLAT in
  `audit` (36 ms at 102k rows, 35 ms at 1M) while a replay is LINEAR (88 ms,
  836 ms) and `audit` has no compaction anywhere in the tree, so a
  replay-at-open charges every process an unbounded cost for a protection
  that covers a server only at boot (A31); and never per read, which is
  +240% on O234's own measured budget. **Plus a per-key APPEND-ONLY PREFIX
  invariant on every guarded read** (every read that looks a label up
  THROUGH the handle — `refuse_replayed` finds drawer records in its own SQL
  and pins none, corrected by O247's ruling), at O(keys) over rows the scan
  already fetches: `audit` is append-only in production, so a key that vanishes, a
  newest record that moves backwards or a tag that changes under a seq
  already read is always tampering. Not an incremental replay from a
  watermark, which is UNSOUND here because the attack rewrites rows BELOW
  any watermark. `PRAGMA data_version` is the ACCELERATOR between them and
  never the boundary (A28's shape): measured with a real second process, the
  handle's own commit does not move it and another connection or process
  does, so it may short-circuit the REPLAY and may never gate the prefix
  check. It is comparable only within ONE connection — a fresh one reads
  what a quiet long-lived one did before any foreign commit (O266's P5) —
  so a handle that replaces its connection forgets the verdict (O276), as a
  rotation's own re-step does (O266). Refusal is `IntegrityFinding`, and **`Regime::V1` /
  `LabelCommitment::Pending` MUST NOT refuse** — a clean legacy chain
  replays with labels bound by nothing, and refusing there would brick every
  pre-1.6.0 vault served `--read-only`, a documented contract change and
  therefore MAJOR; such a vault gets the invariant and nothing else. The
  guard sits on `trust_policy_scan` and `retention_policy_scan` — the SCANS,
  because `verify` already reaches them past the public wrappers — behind a
  REQUIRED `LabelUse` witness, so `verify` still returns a verdict rather
  than an error over a chain the readers refuse; at the TOP of
  `forget_with_proof_ruled`, never inside `mirror_note`, where the drawers
  are already destroyed (O91); and inside `refuse_replayed`, the hottest
  label decision in the tree. Measured: warm search +1.7% under the PQ tier
  at 102k, +73 ms once per handle. **And the replay is COUNTED in production
  since O250** — `LabelGuard::replays` was `#[cfg(test)]`, so the
  once-per-handle bound this whole design rests on had no observable outside
  a test build, which is how O242 broke it at +213% for a release and was
  found by a reviewer reading code. It is now `VaultStats.chain_replays` on
  all four renderers plus `undercroft_chain_replays_total`, and it is the
  HANDLE's number by construction, `LabelGuard` living on the store handle.
  **And it is ONE replay per process where it used to be two (O251)**:
  `reconcile_chain` makes the same `chain::replay` call over the same rows
  against the same anchor, so the open now hands its verdict forward — but
  ONLY when the open appended nothing afterwards, which the committed head
  and height decide, because this connection's own commits move no cookie.
  The arithmetic lives once, in `chain::verdict`. Zero in the steady state
  (the open short-circuits on a current anchor and never replays); one whole
  replay after a crash-heal, on a read-only replica, and on every command of
  a read-audited deployment, where `audit_read` appends without anchoring so
  the anchor always lags.
  **What it cannot see, stated: an APPEND
  is legitimate**, so a forged row appended beneath SQLite is invisible to a
  handle that already replayed until it re-opens — only the MAC key
  separates a forged append from a real one, and **no in-band structure
  changes that** — O241 proposed an authenticated census in the MAC'd
  manifest and was RULED against, because a census catches a key that
  VANISHES and never one that APPEARS, which is the direction this residual
  runs, and because the manifest is restorable from the vault's own
  `backups/`. The mechanism that would close it is an out-of-band witness,
  O245. **Both of those last claims were wrong, and O247's ruling
  (2026-09-24) corrected them beside:** a witness commits to a prefix of the
  rows and does not close an append (O245 ruling item 3); "no in-band
  structure" holds only against a KEY-HOLDER, since against a writer without
  the key the live handle holds what it lacks; and the window is wider than
  an append — under an unmoved cookie a relabel or a delete that moves no
  height re-points a label's newest record, and a replayed policy governs,
  the sweep destroys with `ok: true` and a replayed drawer is served
  (O252, measured and pinned as a cost). **The whole guard defends against
  a writer who does NOT hold the key** — on a deployment keeping
  `master.key` in a file beside the database, a writer who can edit the
  database can usually read the key as well. **And every judgement reads
  ONE state since O253**: a legitimate CONCURRENT writer made the guard
  refuse as tampering, `verify` report a broken chain and `vault anchor`
  fail, because what each compared was read in several WAL snapshots —
  measured, 478 false refusals at every step of seven doors. `chain::replay`
  and `chain::prefix` REQUIRE a `Snapshot`, which only the helper
  (`query_only`, `BEGIN DEFERRED`, the cookie read first, ownership COUNTED
  on the handle) and the two write-lock guards can mint; `guarded` is the
  door — a hit runs the body in the snapshot that read the cookie, a miss
  ends it, reads the manifest anchor, and replays in a second — and the
  anchor is read BEFORE the snapshot everywhere, because read after the pin
  it names heads the rows never produced (counterfactual: false refusals at
  exactly the pinning statement)),
  verify (**`VerifyReport` is the whole verdict and it has NINE legs**: record
  HMACs, the chain replay, the label commitment (O233), drawer supersession
  receipts, **KG fact receipts**, orphan graph labels, mirror drift,
  **declared-policy drift**, **version replay (O234)**.
  **The first leg is `bad_records`, a `Vec<BadRecord>` since O231**: a record
  id and a `BadReason` — a failed HMAC, or a drawer whose HMAC VERIFIES over
  covered meta that does not parse, which `verify` counted and reported in no
  leg, answering OK over a drawer every read refuses. Each serializes as one
  string (a bare id for a failed HMAC, `"<id>: <reason>"` otherwise), the CLI
  prints them as `hmac failures:` and `unreadable:`, and
  `rotation_blockers()` matches every reason with no `_` and blocks on a
  failed HMAC alone (O232's ruling: "never on … an O231 row"). Such a row needs
  no key: the drawer canonical joins id, meta and content with a 0x1f and no
  lengths, so the meta/content boundary moves with the tag intact
  (O406).
  The rule that keeps growing
  it: *a keyed claim living in columns no drawer HMAC and no chain step
  covers must have a leg, or nothing sees it.* **The NINTH is that rule
  applied to the tables that hold the CORPUS (O234)**: a drawer, a fact, an
  entity and a tunnel each append their tag to the chain when written and
  then have that tag recomputed IN PLACE on the next write, and no leg
  compared the two — so an older version of a row, written back offline,
  verified under the current key over a record id that still exists.
  Measured: a `drawer update` that corrected an account number, then the
  earlier row's four columns restored with sqlite3, read the old number again
  under `VERIFY OK`. Three arms, and the boundaries are the whole of it: a
  newer record above `max(the last rotation, O233's switch)` — the switch
  half because the rotations from `cc0e1c7` to `55af8d1` re-tagged every row
  with NO `rotate/` record, so a bound on rotation alone false-alarms on
  every vault they touched; the row's own tag sitting in an OLDER record,
  which is unbounded and is what finds a replay made before the upgrade; and
  a row present after a newer DESTRUCTION record, through an exhaustive
  `Namespace::is_destruction` rather than a `strip_prefix("del/")`, because
  O205 has a second destruction namespace filed. Findings fail `verify` and
  block a rotation. **The READ half lands with it**: a `Read::Returned` door
  refuses on the whole CONSULTED set through one helper — `get`, `recent`,
  `search_inner`, and the graph's `kg_query_entity`/`_relationship`/
  `kg_timeline`/`lookup_canonical` — while an INTERNAL lookup never refuses,
  because the remedy for a replayed row is the write that replaces it
  (`import_verdict`, O215) and refusing there would block the restore.
  Measured at 102,000 sealed drawers, four interleaved rounds: **+7.7% warm
  search** under the PQ tier (36.8 → 39.7 ms/q) and **+7.7%** with no
  prefilter tier at all (9.74 → 10.49 s/q, where the consulted set is the
  whole corpus) — under the 10% the ruling set as its condition.
  **The seventh leg is that same rule one table over (O94)**: `wing_trust` and `retention_policy` are
  operator declarations, HMAC-tagged, outside every drawer's coverage, and
  `verify()` mentioned neither table. A FLIP failed closed on the retrieval
  path (`wing_trusts()` raises `Integrity`) while `verify` still answered OK
  on all four renderers; a DELETION failed closed NOWHERE — `trust_clause`
  finds an empty exclusion list and returns `Ok(None)`, so a wing classed
  `quarantined` silently becomes retrievable under a `standard` floor. The
  evidence to detect it already existed and nothing read it: each assignment
  appends `trust/{wing}`, and that record id survives everything.
  **The leg must assert only what survives a ROTATION, and its first version
  did not**: comparing the row's tag to the chain record's is the obvious
  check and it alarms on every rotated vault, because rotation re-tags the
  policy rows under the new keys while PRESERVING audit tags verbatim as
  historical evidence — O13's asymmetry one table over, *a keyed replay has a
  shorter lifetime than the document it checks*. What survives is the row's
  own tag recomputed under the CURRENT key (so a flip still fails) and the
  EXISTENCE of the record id (so a deletion still shows).
  **Absence discriminates for trust and not for retention, which is why one
  leg needs two rules**: no `DELETE FROM wing_trust` exists in the crate, so
  an orphaned `trust/` record is unambiguous — the choke-point argument
  `orphan_labels` makes for a bare drawer id — while `retention_policy` IS
  deletable through `clear_retention`, which appends `retention-clear/`, so a
  missing retention row is legitimate exactly when that record is NEWER than
  the assignment. Supersessions got one for
  exactly that reason and the identical structure one table over —
  `kg_triples.receipt_tag` / `source_fp` — did not until 2026-08-10, so
  `kg_verify_receipts` was reachable from `kg receipts`, `/v1 …/kg/receipts`
  and the bench and **from no verify path at all**: a forged citation
  answered `VERIFY OK` on every surface, and `backup create` gates on this
  verdict, so it archived the forgery as clean. A detector nobody calls is
  not a check. `parity.rs::HAND_PROJECTED` lists `VerifyReport` × CLI × MCP ×
  `/v1` **and the admin console at `ui.html`, a FOURTH renderer**, so a new
  leg fails the build until all four project it. This sentence said the
  console was *"outside that gate"* until 2026-08-19, and it had been inside
  it since the entry that found `orphan_labels` and `mirror_drift` unrendered
  — a doctrine line describing the tree before its own worked example, which
  is the shape this file keeps recording. `VaultStats` joined it the same
  day (ROADMAP M5), with the same result: four fields the console had never
  read),
  knowledge graph (kg.rs — incl. the golden-values authority
  tier: `authority_class`/`review_state`/`canonical_key` DECLARED on
  closed vocabulary, HMAC-covered via a canonical extension on the
  `support` precedent so untouched facts keep byte-identical canonicals;
  `lookup_canonical` = indexed exact door, at most one active approved
  fact per key, promotion supersedes the previous holder audited; a
  column flip without the vault key fails verification — see
  docs/LABELS.md for the label doctrine it instantiates.
  **On a sealed vault the graph's WORDS are not on disk (A10, 2026-08-05)**:
  `kg_triples.subject`/`predicate` and `kg_entities.name` hold a truncated
  keyed HMAC — SQL equality, so every lookup stays indexed — and the words
  live in sealed blobs — `terms`, covered by the fact's tag through a FOURTH
  canonical extension (0x1c), and `name_rest`, covered by the entity's tag
  through a FIFTH (0x1b, added once `name_rest` was found outside every
  canonical) — so nothing written earlier is re-tagged.
  `triple_id`/`entity_id` are keyed too, and that is not optional:
  they were unkeyed SHA-256 of the same words, so blinding the columns alone
  leaves a confirmation oracle for anyone with a candidate list — and a
  substring gate cannot see it, which is how this would have closed green.
  **The key is a STORED secret, never a vault key**: rotation re-derives
  vault keys, so keyed ids would move on every rotation, orphaning the audit
  records written under `kg/{id}` and breaking deterministic-id idempotency.
  32 random bytes sealed in `meta`, re-sealed by rotation, never
  regenerated. Legacy vaults migrate once at the next writable open
  (tamper-failing rows SKIPPED, not laundered) and **the migration ends in a
  VACUUM** — an in-place UPDATE leaves the old row images in freed pages, so
  the words were still in the FILE until it did; any future at-rest
  migration needs the same, and a gate that reads bytes rather than rows),
  **and neither is a DIGEST of a drawer's words (U12, 2026-08-06)**:
  `kg_triples.source_fp` and `drawers.supersedes_fp` were unkeyed
  `sha256(verbatim content)` in clear columns — the same confirmation
  oracle one table over, and the pinned exposure inventory could not see
  them because its fixture superseded a NONEXISTENT id and used plain
  `kg_add`, so both columns were NULL in the only vault it ever measured.
  Now `HMAC(kg_secret, sha256(content))`, on the A10 key for the A10
  reason. **Keying the digest rather than the content is what makes the
  migration total**: the stored legacy value IS that digest, so every row
  re-wraps without reading a drawer — which matters because a source that
  was legitimately EDITED since its receipt has no original bytes left,
  and re-deriving from content would have forced a choice between
  laundering a real `SourceChanged` into `Verified` and leaving the oracle
  in the file forever. The receipt is re-tagged (the fingerprint is inside
  it), so it is VERIFIED first and a failing row is skipped, not laundered
  — reported on `VaultStats.unhealed`, marker withheld, retried. Readers
  are shape-aware (`fp_matches`): a read-only open cannot migrate, so
  comparing a pre-U12 row under the keyed recipe would call an intact
  vault `SourceChanged`. The cost is PORTABILITY and it is paid at
  import: a keyed fingerprint cannot be recomputed at a destination, so
  `kg_import` re-derives from the source drawer it just imported (both
  import surfaces already order drawers first) and writes NO binding when
  the payload lacks it — reported `Unreceipted`, not `Dangling`, because
  no receipt was ever written. `forget.rs`'s attestation fp stays
  unkeyed: it is verified by a third party without the vault key),
  extractor identity (which model claimed each distilled fact, inside the
  fact's HMAC via the third canonical extension — 0x1d, the
  support/authority precedent, so untouched facts keep byte-identical
  canonicals; a flipped attribution fails verification), receipted drawer
  supersession (`meta.supersedes` under the drawer HMAC + mirror column +
  keyed receipt over the superseded content's fingerprint in separate
  columns — the kg source_fp/receipt_tag shape one level up, the receipt
  re-keyed on rotation while the fingerprint does not move; five verdicts
  via `verify_supersessions`; superseding NEVER deletes),
  **the import door** (`import_many` + `import_verdict`, ROADMAP O215 — the
  one place both import surfaces decide what an incoming record DOES to the
  vault, in four outcomes: a record the vault lacks is written, one it holds
  byte for byte writes nothing, one whose metadata moved is written with the
  vector the vault already holds, and one whose content differs — or whose row
  fails its HMAC — is written and embedded, because a restore is the remedy for
  a tampered row. It reads the drawer through `get`, never the `fp` column,
  which is NFC-folded and outside HMAC coverage. It is its own door because
  none of the alternatives could hold it: the CLI cannot know the landing id, a
  boundary check may not read database state, and `upsert_many` also serves
  `mine` and the sweep, where a no-op rule would silently make re-mining a
  no-op. The CLI used to decide instead, by asking whether the TEXT existed
  anywhere in the vault — wing-blind, so a restore of a vault holding one text
  in eight wings kept 85 of 680 drawers while `verify` said OK, and any writer
  who saved that text first could deny the restore. **One record it refuses
  before any outcome (O216): one naming a row that awaits an admission
  ruling.** Pending evidence was neither deletable nor editable except by
  `allow`/`deny`, and the import was the door left open — through
  `/t/import`, the agent whose save was diverted could erase its own
  evidence, the 202 having handed it the queue id. The HMAC-covered wing
  decides, the clear column only where the row fails its tag (then the
  refusal is `Integrity`), and it is checked after a queue record's unwrap
  and before the screen, reading no admission setting. A batch-local arm in
  `upsert_many_held` refuses an unscreened row landing on an id the same
  batch just diverted, because the door's verdicts all precede the batch's
  writes. A clear-column boundary in `write_drawer_stmts` was REJECTED: it
  would strand an ordinary row whose clear column was flipped to the
  reserved wing, which `drawer update` is the one door able to heal.
  What it does not stop is substitution by diversion — O220),
  whole-vault export/import (typed records: drawers + KG
  entities/facts/tunnels; a receipt is RE-DERIVED at the destination from the
  drawer it just imported, never re-keyed from the traveling value — this line
  said "receipts re-key from the traveling fp" until 2026-09-09 and that
  contradicted the U12 paragraph above it in this bullet, which states the
  mechanism correctly and which the code agrees with (`kg_import` calls
  `keyed_content_fp` over the imported source; a keyed fingerprint cannot be
  recomputed anywhere else, which is the whole reason U12 keys the DIGEST
  rather than the content). One claim, two places, and the wrong one was the
  summary — the shape this file records for headings, one bullet over;
  the manifest carries embedder identity and chain head as
  provenance, never as state),
  **`backup create`, one door (backup.rs, ROADMAP O256)** — both surfaces
  verified, DROPPED the store and copied the directory as files, so beside
  a writer 11 of 40 copies failed, 2 of the rest restored as tampering and
  16 held a state no verify saw, and a rotation between two files paired
  two key generations. Now the manifest's exact bytes are read ONCE before
  the pin with no fall-back (`Vault::verified_manifest`, never
  `anchored_head`'s cached-head fall-back) — the manifest the rows answer
  to, which during a deferred rotation promote is `vault.json.next`'s bytes,
  archived as the archive's `vault.json` (O266, refining O256 item 3) — on
  the rotating handle alone since O212, which no surface keeps, so the
  report says nothing of it (`promote_deferred` left with O212's build, and
  O320's archive outside the data directory would restore it — open); inside ONE snapshot the door
  compares the key generation, verifies, and copies the pages with SQLite's
  online backup API (`Backup::new(snap.conn(), …).step(-1)`, `Done`
  checked — never `Connection::backup`, whose steps each take a fresh read
  transaction); the copy is synced and its head and height must EQUAL the
  snapshot's (an `immutable=1` reopen, never a second verify); and the
  vault crate's stage is published by one rename. **It refuses on a
  read-only handle as its FIRST statement, in restore's class
  (`VaultError::ReadOnly`, exit 1), before `kg_secret`, the manifest read
  and `Stage::begin` (O212)** — the copy only reads, but the door writes an
  archive, prunes the oldest once ten exist and sweeps stale stages, and
  `Stage::begin` sweeps before a `Drop` hides the stage, so a later refusal
  passes an end-state listing; a source gate holds the order, because a
  refusal after `kg_secret` moves nothing a test can see. The evidence copy
  is `cp -a`. It refuses nested or inline (`Invalid`), holds its
  connection so a rotation is refused throughout, and reports `writes`,
  `chain_head` and `anchor_behind_by` — the anchor carried AS FOUND, never
  healed into the archive (A2/O246). `backup_pause.rs` holds its test pause
  points (the page copy runs no VM, so a progress handler never fires in
  it), and `/v1` no longer evicts its handle to take one,
  **`backup restore`, one door (restore.rs, `restore_archive`, ROADMAP
  O268)** — both surfaces took O69's hold, REMOVED the vault and copied the
  archive in, knowing only that it held a `vault.json` whose id they never
  verified: a manifest ahead of its rows, a truncated database, a foreign
  archive and one flipped byte each restored at exit 0 over a working vault
  that then refused to open. Now, STAGE FIRST, HOLD LAST: the archive is
  staged (the vault crate's `restores.rs`), unlocked through the stage (the
  manifest's MAC is keyed by the id it names, so a planted id fails before
  anything is removed), opened WRITABLE with the surface's one embedder
  factory (`EmbedderFor` — what is swapped in is the verified post-migration
  state; a read-only open refuses every older schema), verified over all
  nine legs, checked with `PRAGMA integrity_check` (`verify` reads no index:
  a flipped index byte passed it on four of seven pages, and `quick_check`
  on all seven), closed, and held to a post-condition (exactly two files, an
  `immutable=1` head and height EQUAL to the verified ones) — and only then
  is O69's hold taken, with `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE` read back so
  its drop never folds a dead writer's `-wal` into the live vault (measured:
  it did; SQLite skips that only once the file has moved, and only on unix),
  and the stage swapped in. A refusal the archive causes therefore changes no
  byte of the live vault. Errors raised by the STAGE's handle alone map
  SQLite's corruption codes onto `IntegrityFinding` — sound there and only
  there, the stage being a private copy of the archive (the live `verify`'s
  class is O269's). `--read-only` refuses before any effect, in the door
  (O212's restore half). `RestoreReport` carries the archive's chain as
  found, the chain swapped in, the open's `unhealed` notes (O246's heal, which
  the restored vault's next open can no longer see), a re-recorded embedder,
  `key_generation_differs`, `replaced` and `skipped`. `restore_pause.rs` holds
  its pause points; the swap's renames take the vault crate's fixture faults
  (`SwapAside`, `SwapIn`, `SwapBack`, and `fail_in_turn` for the crash state).
  **The swap replaces a vault only under a hold** (O282 — a vault that
  appeared at an absent target was renamed aside unheld and removed) **and
  never a symbolic link** (O283, the maintainer's ruling: a linked
  `vaults/<id>`, database or manifest was renamed aside as the LINK, orphaning
  what it named) **nor a directory holding any entry that is not a regular
  file** (O301: O283's check named three entries, so a linked
  `vault.json.next` was removed as a link with what it named left behind, and
  a linked `-wal` met SQLite's own `O_NOFOLLOW` only at the hold, as a raw
  "unable to open database file" after the archive was staged and verified)
  — `restores::irregular_target`, the vault DELETE's survey, asked by the door
  before anything is staged (`refuse_irregular_live_vault`, which `/v1`'s
  route also asks BEFORE it releases its own handle, whose close unlinks a
  `-wal` link by name) and by the swap under the hold, and
  `key_generation_differs` is read under the hold.
  **`DELETE /v1/vaults/{id}`, one door (delete.rs, `delete_vault`,
  ROADMAP O291)** — it removed the vault directory with nothing held:
  beside an idle writable handle in another process the delete answered
  `Ok` and so did that handle's next write, committed into the unlinked
  file and lost; a replica whose label guard was warm kept serving the
  deleted vault; a link answered "deleted" over what it named; a database
  with no manifest, or a restore's aside, answered 404, which the
  orchestrator reads as erased. Now, in the ruling's order and every step
  before the rename changing nothing: the posture, the name (`Invalid`),
  a restore's aside (`RestoreInterrupted`), the survey (any entry that is
  not a regular file is `Invalid` — a delete never follows a link, O283
  extended for the maintainer's ratification), two databases (integrity),
  an empty database created for a manifest-only vault, O69's hold taken
  as `hold_vault_exclusively(dir, HoldFor::Delete)` — the hold's purpose
  words its refusal, and restore's texts are byte-identical — the checks
  again under it, and ONE rename out of `vaults/` UNDER the hold (off unix
  try first, then release and retry once — O275), then the removal. A
  refusal after the hold undoes the empty database under it; a removal that
  fails names where the files are, and the next delete finishes it — a
  retry never answers 404 over them. `delete_pause.rs` holds its pause
  points (`Surveyed`, `Held` — where O147's check will go — `Aside`).
  Racing opens answer the reopen class where the vault's directory is gone
  (`vault_db::vault_gone`), in the writable and read-only connectors and
  `recorded_embedder`, never a raw "unable to open" or `DatabaseMissing`.
  `VaultManager::delete` is gone, and a source gate reads every production
  `remove_dir_all` in the workspace from the tree: `backups.rs`,
  `restores.rs`, `deletes.rs`, nothing else. What "deleted" covers is the
  vault directory — not `backups/`, a remote mirror or another hard link,
  escalated to the maintainer. **And every open of a vault's database by PATH goes through ONE door
  (`vault_db.rs`, `open_by_path`, ROADMAP O279)**: a connection takes its
  descriptor at `Connection::open` and its first lock at its first statement,
  and between them no fence sees it — O69's hold is granted beside it — so an
  open that raced a restore's swap held the database set aside while its
  `-wal`, `-shm` and manifest reads named the restored vault: measured, a
  writable open served the old vault and healed the restored manifest
  forward (the restored vault then refused as tampered), one save through it
  corrupted the restored database, and the restore said `Restored`. The door
  opens, turns checkpoint-on-close OFF (read back — every close before the
  check is inert; SQLite's own moved-file guard skips a database it reads as
  empty), runs the opener's first LOCKING statement, then proves the file:
  SQLite's `SQLITE_FCNTL_HAS_MOVED` on the connection's own descriptor AND the
  path SQLite resolved — read as bytes from `PRAGMA database_list`, never
  `Connection::path()`, which is `None` under a non-UTF-8 root — naming the
  same `(dev, ino)` as the path the open used. Each leg alone passes an unsafe
  case (a swapped symlinked vault; a path naming another file only at the
  open), both measured. A moved file is closed (never dropped) and refused
  with the reopen class, which the CLI and `/v1` retry once; the hold
  answers `VaultHeld` with its own wording. Every opener goes through it —
  the writable and read-only connectors (a moved file never reaches the
  `immutable=1` escalation, whose own probe is checked too),
  `recorded_embedder`, O69's hold, the legacy rename and the release probe —
  and a source gate counts every production open against the door and a
  reasoned allowlist. **No such open carries `SQLITE_OPEN_CREATE` unless the
  directory holds no database** (O280: the legacy rename CREATED an empty
  `palace.db` another open had just renamed away and renamed it over the vault
  — two upgrade-day opens emptied a 500-drawer vault, released since 1.5.0).
  `/v1`'s embedder factory answers a store refusal in the store's class and
  retries the reopen class (it was a 500 outside the retry — O257 items 1 and
  7), and `config check` pre-flights a filesystem whose inode numbers are
  unstable. Residuals: an `immutable=1` handle's file moving after its open
  (O285), a same-process racer beside a same-process handle of the restored
  vault (its `-shm` effects happen inside the first statement), and Windows (no
  moved-file check; O275); the legacy rename beneath an IDLE holder was a
  fourth until O281 gave it a hold. **And what the UNLOCK read is checked
  there too (O284)**: the unlock reads `vault.json.next` by path before any
  connection exists, so a restore between the two left a handle carrying the
  set-aside vault's notes; once the door has proved the file, both opens
  compare the digest of the `.next` bytes the unlock read — whenever it read
  one it could not authenticate, a torn or too-new one; a valid staged file is
  a rotation's, which the open still promotes (O254) — with the file there
  before the schema batch, a reconcile or any note,
  and a difference is the reopen class, its connection closed, never
  dropped. A directory pin lost on measurement — 28 of
  30 restores in a row landed on a recycled directory identity. The read-only
  legacy-name note is derived from the file the connector opened, and a test
  destructures `Vault` so a new unlock-era field is ruled before it compiles.
  **And the unlock reads `vault.json.next` FIRST, then `vault.json` (O288)**,
  O266's order, holding a `.next` read error until the manifest's MAC is
  judged and reading no `.next` that is not a regular file of a manifest's size
  (a planted FIFO blocked, `/dev/zero` never ended, ahead of the tamper
  verdict); the read-only open then asks, on the verdict its reconcile RETURNED,
  whether the files still say so — `Committed` through the manifest rule's own
  staged branch (`deferral_in_force`), `Abandoned` by `.next`'s digest —
  before a note is copied or a read served. Measured before it: an anchor and a
  deferred rotation between the old order's two reads answered a false
  `ManifestTampered`, and a promote, a discard or a restore after the unlock —
  an ORDINARY rotation beneath a read-only open that waited at its fence among
  them — left `RotationPromotionDeferred` or `RotationDiscardDeferred` on a
  vault holding no such file. A difference is the reopen class with no tamper
  event; the writable posture gets no REOPEN check (O254's P1), though the new
  order turns a rotation committing between its unlock's reads into one retry. A promote AFTER
  the check leaves the handle its note — worded since O289 as what the open
  found — and `deferred_over`, both for its life (clearing either is a latch),
  and since O289 neither changes what a later forged or absent `vault.json`
  answers; an absent one at the check itself is the integrity verdict since
  O290. What an offline writer could do inside a writable unlock's window
  with `vault.json` deleted, torn, forged or put back as the retired bytes —
  a rollback healed into a crash lag, a forged manifest overwritten — is
  closed by O290's licence (the rotation bullet below); the retired
  `vault.json`, the staged `.next` AND an older database put back together
  is still accepted by every open, A2's pair restore, which only the witness
  sees. `open_pause.rs` holds the pause points,
  reachable from the CLI's
  tests through the store's `test-fixture` feature,
  write-path admission control (admission.rs + core admission.rs — C3.3
  phase 2: deterministic tier-1 detector, closed signal vocabulary,
  offsets never content; **the screen lives at the write CHOKE POINT**
  (2026-08-04): `write_drawer` takes a REQUIRED `Screen` argument —
  `Apply`, or `Bypass(BypassReason::{AlreadyDiverted,OperatorRuling})`,
  one greppable token carrying the reason — so a new write path does not
  compile until its author decides, and adding a bypass variant is where
  someone has to justify it in review. Screening used to be applied per
  call site, and a surface audit found three ways past it on `/v1`
  alone: a `dedup_threshold` in the save body routed to
  `save_with_dedup`, a caller-supplied `vector` routed import to the raw
  writer (so backup-restore AND orchestrator tenant migration re-admitted
  whole corpora unscreened), and external-embedding vaults had no
  screened path at all — three call sites someone forgot, with nothing
  able to say so. `upsert`/`upsert_screened`, `upsert_external`,
  `save_with_dedup{,_vec}` and `import_record` all state `Apply` now;
  the operator's `allow` ruling is the one `OperatorRuling` bypass, since
  re-screening a human's verdict would trap every allowed drawer forever.
  **The screen runs AFTER the declaration is validated, and that ordering
  is the whole of O30 (2026-08-13)**: a diversion *rewrites the fields
  validation reads* — `admission_divert` moves the declared wing into
  `intended_wing` and puts the reserved constant in `meta.wing` — so
  validating downstream validated a value the store had chosen, and an
  invalidly-declared write was QUARANTINED rather than refused. It then
  could not leave: `admission_allow` restored `intended_wing` checking only
  that it was non-EMPTY, so the restore was refused by the choke point on
  the way back out, and the row could be denied but never allowed.
  `admission::validate_declaration` is the one function, called from
  `screen_and_divert`'s `Apply` arm (the DOOR — in front of the rewrite,
  and shared, so `upsert_many`'s own loop and `dedup`'s dry-run preview
  inherit it) and from `write_drawer_stmts` (the BOUNDARY), which is the
  `resolve_search_policy`/`verified_meta_admits` shape one level over.
  **It validated the wing and the room ALONE until O170 (2026-09-16)**, while
  every other declaration check sat in `write_drawer_stmts`, behind the same
  rewrite: a malformed id was quarantined because the id guard saw the 32-hex
  queue id; the vector and `filed_at` refusals formatted the queue id, so a
  400 told the caller the screen's verdict, the tier-2 advisor's included; the
  self-supersession guard compared the link with the rewritten id; and the
  advisor was shown writes the boundary then refused. Every check that is a
  pure function of the candidate now lives in that function — names, a
  stated vector's finiteness and dimension, the id's shape, `filed_at`,
  content length, kind, and supersession against all three filing slots
  (declared, recipe, queue: `admission::filing_ids`, the one derivation the
  diversion, the allow and the import unwrap share). `screen_and_divert`
  takes the vector and its three callers state `Some` or `None`;
  `upsert_many` validates a whole batch before screening any row;
  `import_unwrap_screened` refuses a malformed id before re-deriving it;
  `admission_allow` validates the whole restored declaration; and
  `write_drawer_stmts` keeps only the reserved-wing guard, a count a gate
  pins.
  **No write path embeds a drawer before that function has judged it (O198,
  2026-09-17).** `embed_declared` is the write paths' one door onto the
  embedder: `upsert_screened`, `save_with_dedup` and `upsert_many` call it, it
  judges a whole batch before embedding any row, and O167's custody gate
  refuses an arriving drawer embedded through a raw call. The embed used to
  come first, so a 200 MiB `/v1` save the store refused cost 43 s and a
  12.2 GB peak on the listener's one loop. `Drawer::new` and
  `with_content_date` scan only content within `MAX_CONTENT_BYTES`, because
  that scan was most of what remained.
  Two things that unit found and its filing had not: `validate_name(value,
  what)` **discarded `what`** at all 44 call sites, so no refusal anywhere
  in the tree could name its field — the gate was unreachable, not merely
  unmet — and `screen_and_divert`'s doc comment said "both write paths"
  while three callers existed. The reachable door was IMPORT, never save:
  the three save surfaces validate before they reach the store.
  **`upsert_many` is the stated exception**: a batch owns its transaction,
  so it cannot call `write_drawer`; it screens each drawer through the same
  `screen_and_divert(…, Screen::Apply)` into `BulkOutcome{created,
  quarantined}` — one decision reached from both paths since R5 closed
  2026-08-05, pinned by `admission_divert_has_exactly_one_caller`, and the
  telemetry half is shared too, both paths classifying through
  `admission::save_event`.
  `import_record` reports the `Landing` it receives — a diverted import
  answers `quarantined` with the id the row actually landed under, on
  every branch. **Every save arm does now (R5 closed 2026-08-05)**:
  `upsert_external` returns a `SaveOutcome` instead of a bare bool,
  `save_with_dedup_vec` takes `quarantined` and the landed id from its
  `Landing` on both branches, and `/v1` stopped rebuilding an outcome by
  hand around either — so the last place a surface could assert
  `quarantined: false` on its own authority is gone. The dedup-REFRESH
  branch is its own case and the worst one: a diverted refresh is not a
  refresh, so it answers `deduped: false` with the quarantine id, because
  the matched drawer kept its old text and describing it as updated was a
  claim about a write that never happened. No
  assertion about the reserved wing at the choke point: a CALLER may
  legitimately aim a write at it (a forgery attempt) and must reach the
  reserved-wing guard and be refused as invalid input, not trip an
  assertion; **the tier-1 wishlist is closed (2026-08-04)**:
  `ATTACK_FIXTURES` similarity — windowed hash-embedder cosine (32-word
  windows, stride 16, so a short variant inside a long drawer is found;
  whole-text cosine dilutes to invisibility), threshold 0.45 pinned from
  BOTH sides (`fixture_threshold_is_calibrated`: hard negatives ≤ 0.369
  incl. an instructions-shaped onboarding note, marker-dodging variants
  ≥ 0.540) and measured at corpus scale by bench `screenfp` (0/5,882
  clean LoCoMo turns flagged, corpus max 0.374, 18/18 fixtures trip) —
  and the declared per-writer rate screen `UNDERCROFT_ADMISSION_RATE=
  <count>/<seconds>` (unset = off: a write rate is deployment-shaped, so
  declared never defaulted; garbage REFUSES to open — the CA-pin
  precedent, not warn-and-fall-back; identity = `agent` claim else
  surface-stamped `added_by` among claim-less rows, groupings never mix;
  clock = the CLEAR `filed_at` column, stated: a rate screen diverts,
  never destroys, so it does not need retention's HMAC clock; the
  `filed_at` index is created only on vaults that declare a rate; rate
  lives in store admission.rs because the candidate bytes cannot carry
  it); **a diverted save SAYS so on every surface** (`upsert_screened` →
  `SaveOutcome{quarantined, id}` — the id the drawer ACTUALLY landed
  under; `/v1` answers 202 + `quarantined:true`, MCP and CLI say the
  write is not retrievable. The plain `upsert` returning "was the id
  new" is what let all three surfaces report success with the aimed-at
  id while the content sat in quarantine — found by the
  scripted-attacker gate, the update path's typed-outcome precedent
  applied one level down); forging the reserved wing or declaring an
  unknown `kind` is `StoreError::Invalid` → **400**, never a 500
  "corrupt row"; `UNDERCROFT_ADMISSION=quarantine` diverts flagged
  saves sealed into the reserved `quarantine-pending` wing, excluded from
  **every read that returns content** and not from `search` alone:
  `search` through `resolve_search_policy` (pre-candidate, so poison
  cannot crowd or starve — carried as a `SeqFilter::AllBut` over the
  EXCLUDED rows, which is what makes it cheap; see the retrieval bullet
  above for why the complement is the only affordable side). **The fence
  is raised by the ROWS, not by the flag**: `resolve_search_policy`'s
  `EXISTS` is not gated on `UNDERCROFT_ADMISSION`, so turning admission
  back off does not lower it while diverted rows exist — only ruling them
  does, which is correct (content the screen diverted must not become
  retrievable by flipping a setting) and is worth knowing before anyone
  reads a cost back to configuration), `recent` — which is what `wake_up` and the
  closet index call, i.e. the two surfaces whose whole job is loading
  context at session start, exactly where injected text wants to be —
  and `list_drawers`. Naming the wing is how the reviewer opts back in,
  and MCP may not: `mcp.rs`'s **quarantine fence** refuses any tool whose
  arguments name the reserved wing or an `*id` resident in it, so the
  agent whose write was diverted can neither read the evidence back nor
  delete it; allow/deny chain-audited
  with the verdict inside the ruling tag, each ruling ONE write lock with
  its effect (deny since O255, allow since O260); operator surfaces only, never
  MCP; default off = byte-identical write contract; **a pending row's text
  changes only by a ruling (O220)** — the queue id is a function of the
  filing, so a second flagged text for one filing (an edited re-mine, two
  flagged updates of one drawer, a restore) replaced the first; each
  distinct text now takes its own slot, `ids::quarantine_version_id` keyed
  with the STORED `kg_secret` (never a vault key, never unkeyed), chosen at
  the door with a batch-local map and backstopped inside the write
  transaction, and equal text converges — **carrying the pending row's
  whole covered declaration (O226)**, its signals the one field that grows
  (`admission::converged_meta`, at the door, in the batch's taken map, and
  checked by the backstop's `carries`), so a converger cannot back-date
  `filed_at` or attach a `kind` or `supersedes` the reviewer never saw;
  **"pending" is the HMAC-covered wing (O221)** — ONE predicate,
  `queue_standing`, reads the covered wing where the row verifies and the
  clear column only where it does not, for every destruction and write
  fence (both dedup doors included), the read fences refuse on EITHER
  copy over their own probe, and `admission list` walks the vault by the
  same rule and reports a row it cannot verify beside the rest (`ok`
  false, by `seq`, a malformed id only by its length) instead of failing
  on it; **an allow never replaces or
  re-creates what the screen never saw (O224)** — it re-filed over whatever
  the destination held, so a flagged update an agent parked over MCP before
  a clean one reverted the drawer when allowed, and a drawer forgotten in
  between came back and failed its own erasure receipt as tampered. The
  queue row records `queued_against` at the door (absent, or
  `queue_destination_key` — HMAC under the STORED `kg_secret` over the
  destination id and a digest of its verbatim content, because the record
  outlives that content); ONE comparison, `destination_state`, serves the
  list, the allow's door and an inline refusal inside `write_drawer_stmts`
  (the expectation travels on `BypassReason::OperatorRuling`); a convergence
  CARRIES the record, since restoring the vault's own backup converges every
  pending row; a queue record restored into another vault records
  `Unrecorded` — what its destination held there is unknowable — and such a
  row, like one queued before 1.6.0, allows only where nothing would be
  replaced; **deny is receipted**
  — it destroys through `forget_with_proof` and hands back the
  attestation; **updates are screened on the UPDATING surface** —
  `update_drawer` re-stamps `added_by` before the screen so an untrusted
  surface cannot ride the original writer's standing, a flagged update
  diverts with a typed `UpdateOutcome` and the drawer keeps its previous
  content, and quarantine-pending drawers are not editable; **the
  optional tier-2 advisor** (`UNDERCROFT_ADMISSION_LLM=advisory` on the
  `UNDERCROFT_LLM_*` runtime, `AdmissionAdvisor` trait wired like the
  reranker) is consulted only for tier-1-clean candidates and only
  toward quarantine — never auto-admit, the model being itself an
  injection target; failure degrades to tier-1-only, never a blocked
  write),
  provable forgetting (forget.rs — C3.2 phase 1: `forget`/
  `verify-forgetting`, chain-attested destruction with heads + tombstone
  interval + unkeyed content fps; vault-verifiable by keyed replay, third
  parties verify the operator's Ed25519 signature. **A document carrying
  what this build does not know is NOT CHECKED, never forged and never
  verified (O315)**: the three types, and the witness, capture every key
  they do not declare instead of dropping it, and `age_fence` — the
  verifier's first statement, ahead of the vault, the signature and every
  tag — refuses an unknown `version` or key unread (`Invalid`: exit 1,
  `/v1` 400 with no class), saying a newer build may have minted it OR it
  was altered, never which. Signature-first over a canonical recomputed
  without the key is how 1.1.0's `mirror` reads as forged to every older
  build. The cost, stated: a forgery that adds a key no build declares is
  exit 1 from every build, present and future, where without it it is
  exit 2 — whether "not checked" needs its own exit class is filed for the
  maintainer (O429). **The keyed replay has a
  SHORTER LIFETIME than the document it checks, and pretending otherwise was
  a CRITICAL** (O13): rotation destroys the mac key that made the tombstones,
  so every genuine receipt reported `ATTESTATION FAILED` at exit 2 — the
  tamper verdict — the first time an operator rotated. `AttestationVerdict::
  {Verified, Recorded{rotations_since}}` is the fix and the third state is
  the point, not a softened second one: `Recorded` = the replay is
  unavailable AND this vault's *preserved* audit trail holds exactly these
  tombstones as a **contiguous run** in order with the drawers gone, exit 0.
  Contiguity is what survives of "nothing else changed" once the heads are
  unverifiable strings, and tag equality alone would have admitted a document
  omitting a record from the middle of its own interval; the lookup is a
  candidate WALK because a drawer id is deterministic, so destroy/re-mine/
  destroy writes two tombstones sharing `record_id` *and* tag bytes.
  `rotations_since` is corroboration that never decides — a pre-A19 rotation
  appended no record, so reading zero as "no rotation, therefore forged"
  recreates the defect for the oldest vaults. Residual, stated: `Recorded`
  cannot separate a preserved genuine tag from a preserved forged one,
  because the key that could is destroyed — narrow, witnessed by `verify`'s
  chain replay on an unrotated vault, and traded against a CERTAIN false
  alarm on the routine path. The enum is `#[must_use]` so a third verdict
  could not silently weaken an existing `.unwrap();` that meant "verified",
  and the CLI's exhaustive `match` gates the projection better than an
  inventory entry would. **A whole destruction is ONE write lock since
  O255**: each drawer was destroyed in its own transaction, so another
  writer's commit landed inside the receipt's interval and the receipt never
  verified (7 of 65 in a sweep of every step), and a failure at drawer k
  left k−1 destroyed with no receipt a re-run could mint. Now `attest_in`
  (`forget`, the sweep and `admission deny` share it, deny appending its
  ruling first) reads existence, the fence, the fingerprints — from the
  bytes it destroys — the heads and the records inside the lock, asserts
  the records are exactly its tombstones before the COMMIT, and anchors
  once after it; `destroy_in` holds the crate's one `DELETE FROM drawers
  WHERE id`, propagates every statement's error, and checks
  `is_autocommit()` before each write, because a statement that fails can
  make SQLite roll the whole transaction back and the next one would then
  commit on its own (measured). The label guard stays OUTSIDE the lock,
  where a miss replays in a read snapshot. **The two unattested
  destructions take the same lock since O259/O260**: `delete_by_source`
  refuses review evidence at a door in front of its lock (a failing fence
  query refuses — it read as "not pending"; a refusal takes no lock and
  drops no cache), then reads the members again and destroys them in one
  lock (`delete_source_in`), and `admission allow` re-files, rules and
  removes the queue row in one lock (`allow_in`) through `write_drawer_in`,
  which takes only the operator's ruling and never screens, after
  re-reading the row and requiring it to be byte for byte the row its door
  judged — so a deny of the same row either wins whole or is refused, and
  the trail holds one verdict. **And the pending-evidence fence is a
  WITNESS, not a call-site check**: `destroy_in` takes the `Fenced` value
  `fence` mints inside the lock (refusing a pending drawer under `Protect`)
  and no id, nothing else constructs one, and `Ruled` is stated by the two
  rulings alone — the first build of O259/O260 had made it a call-site
  check again, and one swallowed `?` destroyed a pending member),
  retention policies (retention.rs — C3.2 phase 2: per wing/room on the
  wing-trust pattern, operator-only + HMAC-tagged + audited, flip fails
  list AND sweep; enforcement is an **explicit sweep** through
  `forget_with_proof` — receipt per sweep, nothing automatic, quarantine
  wing refused; the clock is the HMAC-covered `meta.filed_at`,
  tag-verified per drawer, never the clear column — a flipped column can
  neither launder a deletion through a keyed sweep nor hide a drawer
  from its declared retention. **The SCOPE is covered too since O206**:
  candidates came from the clear `wing`/`room` mirror, so a mirror
  flipped OUT of a policy kept its drawer silently; the sweep now walks
  every drawer once through `walk_covered` — the ONE streaming walker
  `verify`'s first two legs ride, tag over the at-rest bytes, nothing
  decrypted — and matches every policy in memory. What it cannot decide
  it names and never destroys (`unverifiable` from anywhere in the vault,
  `withheld` for an undatable member or one the pending-evidence fence
  refuses), it reports drift on what it destroyed and a deleted policy row
  (the retention half of the policy leg, one function), and any of those
  makes `ok` false: 200 on `/v1`, exit 2 on the CLI and the orchestrator.
  **And it destroys only what the policy IN FORCE at the destruction
  expires (O255)**: the decision is one guarded snapshot (policies, drift,
  the walk); the destroying lock compares the policy rows byte for byte
  with the decision's and re-classifies each member through the walk's own
  per-row decision (`covered_row`); a change makes it decide again outside
  once, then inside the lock — measured, 58 of 64 sweeps destroyed after a
  concurrent re-declaration before),
  management surface (manage.rs — incl. **deployment-assigned wing trust**:
  `undercroft_core::TRUST_VOCAB` closed vocabulary assigned by the operator
  only, never over MCP; HMAC-tagged + audited, flip = integrity failure;
  consumed as a
  candidate-set floor (`min_trust`/`UNDERCROFT_TRUST_FLOOR`) through the
  scope machinery so a quarantined wing cannot crowd or starve a floored
  query; unassigned = `standard`, explicit wing scope bypasses the vault
  floor, never a request's own),
  remote-index integration (remote.rs — a mirror records the embedder it was
  pushed with; `search_with_index` refuses a mismatch rather than ranking a
  v2 query against v1 vectors, which returned an empty result with no error,
  and refuses an external vault for the same reason one level earlier —
  `ExternalEmbedder::embed` degrades to a ZERO vector, so the mirror was
  probed with zeros. **Retrieval policy is the local path's, verbatim**:
  closed vocabularies + trust floor + quarantine fence all come from the
  shared `resolve_search_policy`, and the per-candidate decision is
  `verified_meta_admits` off the HMAC-verified `meta.wing` — the FUNCTION,
  not the clause it returns. That distinction is A28 inverted and it
  shipped exploitable: `resolve_search_policy` folds the reserved wing in
  only when an `EXISTS` over the CLEAR `wing` column finds a quarantined
  row, so one offline `UPDATE drawers SET wing = 'notes'` on the sole
  quarantined row defeats the probe and the clause arrives with no fence
  in it. The local path never cared, because `verified_meta_admits`
  refuses the reserved wing UNCONDITIONALLY before consulting any clause;
  this path checked `trust` alone and returned diverted content that
  `search` drops. Any future retrieval path calls the FUNCTION. Residue,
  stated: with the probe defeated the quarantined row still enters the
  candidate pool, so "poison cannot crowd or starve" degrades to an
  availability cost under an offline writer — who can also just delete
  rows. They were absent here until 2026-08-04, so an
  `index push` turned `--backend qdrant` into a route around admission
  control — the fix is a shared REQUIRED step, not a second copy. `index_push`
  still mirrors quarantined rows (an untrusted mirror can offer any id, so a
  push-side filter is not a boundary, and dropping them would empty the
  reviewer's own `--wing quarantine-pending` scope); the residue is stated —
  remotely the floor bounds what came BACK, not what was generated, i.e. an
  availability cost, never an integrity one. Telemetry is at parity too),
  **the READ choke point** (`Read::{Returned(ReadOp), Internal(InternalRead)}`,
  ROADMAP O50, 2026-08-18) — the peer of `Screen` on the other side. `get` and
  `recent` take a REQUIRED witness, so a new read path does not compile until
  its author says whether it returns content to a caller or is the engine
  reading for itself. It exists because `audit_read` had exactly TWO call
  sites, both `"search"`, while `UNDERCROFT_READ_AUDIT=chain` is documented
  for *insider/exfil accounting*: `get`, `recent`, `list_drawers`, diary,
  tunnel, closet, hallways and the admission queue returned verbatim content
  and recorded NOTHING, so walking `GET …/drawers` then `GET …/drawers/{id}`
  exfiltrated a vault leaving zero records while one search left one. Nine
  doors now record exactly one each; bulk doors pass `InternalRead::BulkMember`
  to their inner `recent` so the trail says one list rather than N gets; and
  `read/search` canonicals are BYTE-IDENTICAL to those written before, because
  the field order is untouched and non-search reads simply leave the scope
  fields empty. `ReadOp::ALL` is counted against the driver table both ways, so
  a variant added without a record fails the build. **The KG is a SECOND
  funnel and it records too since O51** — `kg-query` (both arms, one namespace
  because one TOOL is what a caller drives), `kg-timeline`, `kg-entities`,
  `kg-canonical`; the witness is required on each `pub` reader, so the
  compiler enumerated 49 store and 18 surface sites. Two lessons the second
  funnel taught that the first did not. **The record goes on the DOOR, never
  on the shared helper**: `all_triples` decodes the whole graph for every arm
  of `kg_query_entity`, which then filters, so recording there would say 40
  where 3 left — over-reporting an exfil trail is a false claim, not a
  conservative one. And **the filing named five doors and one was not a
  door**: `kg_verify_receipts` reaches neither decoder and returns
  `(triple_id, source_drawer_id, verdict)`, so it and `kg_stats` are
  DELIBERATE exclusions carrying that reason on three surfaces — auditing
  them to match a filing would put a read record on a door no content passes
  through. `VaultStore::record_read` is the ONE place deciding whether a
  read is written down; it was three inline copies after O50 and this unit
  would have made it eleven, which is how the write screen came to have three
  ways past it. Residual, stated: a new `pub` STORE reader on `all_triples`
  reusing an existing `ReadOp` still passes the namespace gate — the drawer
  funnel carries the same residual for a reader that avoids `get`/`recent`),
  **the audit-namespace vocabulary** (`manage::Namespace`, ROADMAP O80,
  2026-09-01) — the third choke point, and `chain_append` requires one, so
  the set of namespaces this store mints is a TYPE rather than twenty
  scattered `format!` strings. `prefix()` states the spelling once and
  `fenced_from_agent()` is the single place a namespace is ruled on for
  `HistoryScope::Agent`; both are exhaustive, so a new variant does not
  compile until someone has done both — which is what "nobody was forced to
  rule" cost when `tunnel/` was minted by `create_tunnel`, classified
  nowhere, and reached the agent surface because the fence excludes only
  what is LISTED. Two things it is worth knowing. **`rotate/` is minted by
  `rotate.rs`'s own `INSERT INTO audit`, not by `chain_append`** — it
  computes the head over preserved bytes itself — so any gate scoped to
  `chain_append` call sites is blind to it, and two of the others
  (`retention/`, `retention-clear/`) reached that function through a
  VARIABLE, which no source scan can follow. And **the record id is
  `prefix()` + the caller's rest, byte for byte what the call sites used to
  build**, pinned against hand-written literals rather than against "the
  suite still passes": the chain hashes `tag` and never `record_id`, so a
  mistyped prefix verifies perfectly clean while `forget.rs`'s
  `strip_prefix("del/")`, the graph's `strip_prefix("kg/")` and the fence's
  own `LIKE` all stop matching in silence,
  read/egress auditing (the consultation-filed gap, closed 2026-08-04:
  **exports chain-audited unconditionally on every surface** —
  `record_export`, the one step both surfaces call, with `audit_export`
  crate-private behind it, one `egress/export` record binding surface +
  recipient + counts + the export's own manifest digest; a read-only
  handle warns and serves on both surfaces, deciding from the HANDLE's
  posture (O176: the CLI called the writer unconditionally and failed
  inside SQLite, and a read-only `/v1` export failed at `token_artifact`'s
  schema write, which no one had executed); **and `refine` is an egress too, since O79** —
  `audit_refine`, one `egress/refine` per run binding surface +
  destination host (credentials stripped) + model + scope + counts +
  `dry_run`. It read the whole corpus verbatim, POSTed each drawer's
  plaintext to `UNDERCROFT_LLM_URL`, and appended NOTHING — under a
  declaration whose stated purpose is insider/exfil accounting, while the
  same caller's single `GET …/drawers/{id}` appended one, and with the
  `/v1` `limit` defaulting to a million. **Egress rather than a `ReadOp`,
  and the tree had already ruled it**: `InternalRead::ExportAudited`
  exists for exactly this shape — a read whose content leaves the vault,
  kept out of the opt-in `read/` trail because an unconditional `egress/`
  record covers it — and `refine` hands its caller facts, never drawer
  text, so a content-returning door would mis-describe it. The a fortiori
  argument is the tree's own: `index_push` records unconditionally for
  EMBEDDINGS, which are merely plaintext-derived. **A dry run records
  too**, because `dry_run` skips writing FACTS and the network egress is
  byte-identical; the documented "write nothing" was about the triples
  and now says so. **And the ERROR path records what left (O95,
  2026-09-04)**: the three writes after a drawer's POST can refuse on
  ordinary input, and until O95 that aborted the run with no record for
  the corpus prefix already on the endpoint — the residual excusing it
  said the gap was shared with `index_push`, which had in fact fixed it.
  `refine` counts drawers whose plaintext was POSTed, records that count
  through the ONE recording function on either exit, never
  `sources.len()`, and a run that selected nothing records nothing on
  either mode. The record lives in `refine.rs` — the one
  implementation both surfaces drive — not at each call site. The
  read-only warn-and-serve is reached from the CLI alone, and only by a
  DRY run: a read-only `/v1` server refuses `POST …/refine` in front of
  dispatch (`mutates`), dry run included, and since O184 a non-dry-run
  `--read-only refine` refuses before its first POST. This sentence said
  the warn-and-serve "reaches the CLI as well as `/v1`" until 2026-09-16,
  and no path ever took it there;
  **and a served model is an egress by CUSTODY, not by call site (O167)** —
  a POST owes `egress/` when its input was read out of a committed row
  within the same operation, so `repair` records `egress/embed/repair` in
  its own transaction after the COMMIT or the ROLLBACK (the last anchor
  naming the newest head, because `anchor_manifest` overwrites unchecked),
  `dedup` records `egress/advise/dedup` off a counter at the one `.assess(`
  site, and remote search, `admission allow` and `dedup` reuse the stored
  vector through `open_stored_embedding` and send nothing; a caller's
  arriving text — a save, an import, a query — is not recorded, and
  `every_embed_and_advisor_call_is_classified_by_custody` counts that line
  against the source. A mode whose writes cannot land read-only refuses
  before its first egress (`refuse_when_read_only`); a dry run warns and
  serves;
  **reads audited under `UNDERCROFT_READ_AUDIT=chain`** —
  `record_read`, the one recording function every content-returning door
  calls (the search and remote tails, get/recent/list and their siblings,
  the KG readers), writing through `audit_read` — one
  record per READ (per search until O50/O51) with a KEYED subject
  fingerprint (never text, pinned
  by a db+WAL byte scan), scope and hit count; runs behind `&self` via
  `unchecked_transaction` and deliberately does NOT anchor — the
  anchor-lag boundary is stated: read records anchor at the next store
  open, and a stripped unanchored tail is crash-indistinguishable until
  then. **A long-lived server never re-opens**, so R3 shipped the
  explicit closer the advice always assumed: `tighten_anchor` →
  `undercroft vault anchor` and `POST /v1/…/anchor` (an ops route on the
  orchestrator too), classified a WRITE everywhere and refused on a
  read-only handle — `anchor_manifest` writes a FILE, so `query_only`
  would not have stopped it. Operator-only, in `OPERATOR_ONLY` beside
  `rotate` and for the same reason: it moves the out-of-database
  evidence a rollback is detected against. One implementation
  (`reconcile_chain(heal)`) serves the open, the read-only report and
  the call, because the arithmetic IS the tamper detection and a second
  copy is a second place for the alarm to be subtly wrong; garbage
  declaration refuses to open, read-only open warns and disables),
  in-place key rotation
  (rotate.rs: one-transaction re-seal of every artifact + chain re-key
  over preserved audit bytes, crash-reconciled at open. **It re-keys only
  what it has checked (O232)**: re-keying recomputes every tag from the
  row's CURRENT columns, so it turned every tampering `verify` reported —
  a flipped trust class, an edited drawer, a deleted audit row, an
  hmac-only vault's content — into authentic data with `verify` green.
  One `verify()` now runs inside the rotation's own transaction and it
  refuses on `VerifyReport::rotation_blockers()`, destructured
  with no `..` so a new leg does not compile unruled, as
  `StoreError::IntegrityFinding` — the integrity family's variant for a
  verdict that compared no HMAC. **And a policy row must be its key's
  newest assignment (O230)**: `retention::policy_finding` is the ONE
  decision `verify`, `wing_trusts()` and `retention_policies()` share,
  comparing a row's tag with its newest chain record's above the last
  `rotate/` record, on indexed `record_id` probes; relabelling an audit
  row defeats it, because `record_id` is outside the chain hash — O233.
  **And it holds the vault ALONE (O257)**: that transaction is taken on an
  `ExclusiveHold` — `locking_mode=EXCLUSIVE` read back, `BEGIN EXCLUSIVE`,
  on the store's own connection — from before the checks until after the
  promote, because in that mode the lock SURVIVES the commit (measured). It
  is refused, changing nothing, while any other connection has the vault
  open — another process's, a `--read-only` one, or this process's own —
  as `StoreError::VaultHeld` (exit 1; 409 with no class). The release is
  PROVEN from a zero-timeout second connection (`prove_released`), never
  by reading the pragma back, and a handle whose release cannot be proven
  LETS GO of the vault (O278), counted on `lock_reconnects`: it closes its
  connection with `Connection::close()` — never by drop, which discards a
  failed close — through `replace_connection`, the ONE place a handle's
  connection is replaced (O276), which swaps in a schema-less placeholder
  under `query_only`, forgets the label guard's cached verdict and drops the
  derived caches, and it reattaches NOTHING. A reopen by path could not tell
  its own file from one a restore swapped in (measured: a connection opened
  before a directory swap reads the aside file and writes into the restored
  `-wal`); every open proves it now (O279, below), and the no-reattach
  ruling stands for its other reasons — no consumer, `/v1`'s one loop, a
  second implementation of the open's verdicts. The handle is
  `Retirement::Released`, which
  OVERWRITES a deferral and which the vault crate's one manifest resolver
  and the store's `snapshot` door refuse, so no manifest read by path can
  raise a false tamper verdict; every door answers the reopen class
  (`StaleUnlock`, whose prefix is now cause-neutral, or
  `VaultError::HandleReleased`; 409 with no class, exit 1), and a door that
  touches the placeholder first answers a loud "no such table", never Ok. A
  read-only handle is refused a rotation before the fence, and the rotation's
  report carries the head it committed, so neither surface reads the handle
  afterwards; `/v1` also closes its cached handle after every rotate, and the
  CLI exits. The promote writes the new
  manifest FROM MEMORY through `write_manifest_file` — idempotent, never
  lowering an anchor, removing `vault.json.next` only while it is still
  the bytes it staged — and a promote that fails every attempt answers Ok
  with `RotationReport.promote_deferred`, never an error that invites a
  second rotation. **A deferral is decided by whether `vault.json` verifies
  under the new keys after the attempts, never by `promote`'s error (O266)**
  — a promote that wrote the manifest and failed only to remove `.next` is
  done — and at a real one the handle reads against the staged manifest and
  RETIRES with the reopen class (`Retirement::PromotionDeferred` →
  `StaleUnlock`: 409, no class, exit 1) before anything commits, so
  `chain_append`, `tighten_anchor` and a second rotation all refuse; the
  label guard's cached verdict is reset when the new keys are adopted. Its
  partners: `chain_append` refuses a write whose
  handle's keycheck the database does not hold, absent included; the
  open's `reconcile_rotation` never overwrites a present foreign keycheck
  — a race (`StaleUnlock`, reopened once by the CLI and `/v1`), a heal
  when the chain replays under the manifest's keys and reaches its anchor,
  a rollback (`ManifestTampered`), or an integrity
  verdict — and takes the write lock only when there is something to
  decide; no unlock deletes a staged manifest. **And the open's promote is
  LICENSED (O290)**: `Vault::license_promotion` asks the manifest rule,
  under that lock, with the unlock's `manifest_seen` as the retired
  digest — the staged branch (`.next` still the staged bytes, `vault.json`
  still the retired bytes the unlock verified) writes, a `vault.json`
  verifying under the new key (a promote since, O254's P1) skips the write,
  and anything else is the rule's own refusal with nothing written; one body
  (`promote_as`) writes on that answer — no read of `vault.json` ORDERS the
  write; the re-ask before it (O304, below) can only refuse or withhold it —
  and removes `.next` only while `vault.json` verifies under the new
  key (a removal on the earlier answer alone lost the last key copy to a
  `vault.json` deleted in between, found by the unit's review), and the twin
  never keeps the digest. It used to heal whatever `vault.json` had
  become from the twin's anchor — the one the UNLOCK read — so a database
  rolled back beneath the open with `vault.json` deleted opened as a crash
  lag and a forged manifest was overwritten with no event; the rotation's
  own `promote` keeps that heal, its anchor being the head it just committed
  (O295 files its missing report). A leftover or an abandoned stage is
  removed only while `vault.json` verifies under the handle's key. **And
  every arm JUDGES before it acts (O296)**: under that lock, after the
  licence's ask (which writes nothing — `Licence::promote_licensed` makes the
  promote) and a foreign marker's race check, `judge_chain` — the ONE
  judgement `reconcile_chain` shares, which RETURNS a verdict each caller
  classifies — replays the audit chain, FORCED, under the keys the handle
  will hold against the anchor of the manifest it will answer to, and only
  then come the promote, the removals and the keycheck seed. The ordinary
  open keeps the `anchor == head` short-circuit (O237); here it is refused
  because `chain_meta`'s head is a clear value, and with it forged the open
  deleted `.next` or wrote S over R and opened Ok. Measured before it, a
  marker deleted or planted during a deferral, a pre-rotation database
  restored beside a stage, or one carrying the staged generation's copied
  marker each deleted `.next` — or wrote S over the only manifest that
  database answers to — and only then refused; no committed head beside a
  stage, or beside a foreign marker, now refuses too. What a replay cannot
  see, stated: a transplant or truncation of the chain's clear rows makes
  every value the reconcile reads name one generation, and the effect runs
  (`verify` fails) — what deleting the salt file achieves; a pre-rotation
  database restored exactly AT the anchor is a crash before the commit to
  every value there is, and its stage is discarded (A2's); and the licence,
  asked one forced replay before its write, is asked AGAIN just before it
  (O304) — a second ask that can only refuse in the rule's own class or
  withhold the write (a manifest of the new generation at the staged head is
  followed with nothing written; at another head it is the reopen class, and
  the reopen judges it), so an offline edit in that window is answered as at
  the licence, and what is left is the ask's distance to the rename, about one
  fsync. `chain_answers_to` is gone. **And no open adopts a chain
  with no committed head unless it is EMPTY (O303)**: `init_chain` seeded a
  head-less `chain_meta` FROM THE MANIFEST, replaying nothing, so a rollback
  with `chain_meta` and the version-2 commitment deleted opened, took writes
  and moved the anchor over the evidence. `judge_chain` now classifies a
  head-less chain in its own snapshot with no replay — `Headless::Empty` (no
  record, no height, the anchor at genesis), `Erased` (`ManifestTampered`),
  `Orphaned` (records or a height: `IntegrityFinding`) — and `head_state`
  reads the height, a head without one `Inconsistent`. Only `Empty` is
  adopted, in `adopt_empty_chain`, under the write lock, judged again there,
  with `chain::seed_empty`, which takes no value at all; the read-only open
  answers it O213's posture refusal, `ReadOnlyNoAnchoredWrite` (it was
  `ReadOnlyUnmigrated`). Seeding the REPLAYED head (the filing's
  shape) was measured worse: the store computed the keyed head over a row a
  writer without the key appended, and the switch bound its label. A
  database a source build older than 0.19.0 wrote — this repository's
  history was rewritten at the rename and derives the same keys — is refused
  with them. **And no open creates a database beside a manifest that
  records history (O308)**: one door, `absent.rs`, asked in
  `recorded_embedder`, at the head of both opens and on `connect_writable`'s
  one layout read — the crate's only `SQLITE_OPEN_CREATE` grant — surveys the
  directory by a stat that follows a link (no main file, or one of length 0,
  is no content), binds the unlock's values to `vault.json`'s bytes (a vault
  deleted and created again beneath the open is the reopen class, never a
  tamper page), names and keeps a non-empty `-wal`, and asks ONE predicate,
  `undercroft_vault::ManifestHistory` over the MAC-covered head and height:
  *History* is `DatabaseMissing` on both postures with nothing created, *Mixed*
  `ManifestTampered`, *Fresh* starts writable and is the read-only posture
  refusal (O213) — for an empty chain too, with or without its table. A
  read-only arm that reads the database's emptiness as an erased trail reads
  the manifest FIRST (O253's order) and never raises the integrity class on a
  BLIND handle, `immutable=1` beside a non-empty `-wal` it cannot read — the
  unit's first build did, measured by its review. Every open-path refusal after O7's rename or the schema
  batch says what it leaves as found (`CHAIN_AS_FOUND`, O322), never "nothing
  was written", and a source gate classifies every such literal. A dangling
  link at `vault.db` beside a fresh manifest still makes the writable open
  create the link's target outside the vault directory — filed, pinned as a
  cost. Test pause points live in
  `rotate_pause.rs`, never inline here — an inline `#[cfg(test)]` blinds
  `rotation_names_every_key_derived_artifact`),
  bulk ingest
  (`upsert_many`: one transaction + one manifest anchor per batch —
  advisory encode paths must never BEGIN or batching breaks),
  **and the external witness (witness.rs, ROADMAP O245)** — `ChainWitness`
  + `WitnessVerdict::{Extends, RolledBack}`, `witness_emit`/`witness_check`.
  The binding is `rows` + an unkeyed count-bound digest over the audit rows'
  preserved bytes (`chain::prefix`), NEVER the head: both steps are keyed, a
  rotation re-steps every head, and A2 holds the key — a head-only witness
  reads "superseded" on the rollback it exists to catch (O13's shape). It
  closes the REWIND direction below the witnessed height and nothing above
  it; three records that said it closes forged-append were corrected beside.
  Own door on the `verify-forgetting` precedent, CLI always read-only, typed
  verdict, foreign vault = integrity finding, an unknown version or key NOT
  CHECKED before the signature (O315, the receipt's fence); on `/v1` as `GET`/`POST
  …/witness` (the fourth POST that reads) and the orchestrator's ops plane;
  **not on MCP** by the maintainer's ruling. The emit refuses a genesis
  chain and a pending A10 walk, whose relabel moves the digest)
