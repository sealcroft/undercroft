# Undercroft — agent guide

Undercroft is a Rust conversion of MemPalace: hardened, local-first AI memory.
Verbatim drawers filed into wings/rooms, stored in isolated **vaults** with
per-vault HKDF-derived keys, XChaCha20-Poly1305 content sealing, and
HMAC-SHA256 integrity tags + a tamper-evident audit chain.

## Layout

- `Cargo.toml` — workspace root (12 crates; `undercroft-embed-onnx` and
  `undercroft-embed-ort` excluded from default-members — heavy ML deps,
  built explicitly)
- `crates/undercroft-core` — domain model, chunking, ids, normalization
  (`normalize.rs`: `NormalizeMode::{Prose,Code}` + `mode_for_path` — code
  and fenced blocks keep indentation/trailing space/blank runs; both modes
  keep the safety floor; `match_key` = NFC **comparison keys only**, never
  applied to stored bytes — the promise is verbatim and NORMALIZE_VERSION is
  inside the drawer id, so folding on the write path would move every future
  id; used by `fingerprint()` — i.e. **dedup**, which is why folding cannot go
  here: `中國` and `中国` must not become one drawer. **No tokenizer uses it
  any more**; they use `search_key`), the retrieval fold (`search_key` — NFC,
  scoped compatibility expansion, recompose, lowercase, mark strip, letter
  map, in that order: lowercase must precede the strip because `İ` is not a
  mark and lowercasing is what *manufactures* the U+0307 the strip removes,
  which is how `İZMİR` stops tokenizing to `zmi` without any Turkic
  tailoring. Not blanket NFKC — the alphanumeric-to-alphanumeric guard is what
  rejects `ﷺ` (So, 18 chars) and `﷼` (Sc, a delimiter that would become
  letters); CJK radicals invert that guard since they are themselves So.
  Cyrillic gets only a **loose** stress mark plus `ё→е`, because a blanket
  decompose-and-strip would turn `й` into `и`; ZWSP/ZWNJ/ZWJ are pinned as
  **not** stripped — ZWSP is Khmer's word delimiter and ZWJ is contrastive in
  Malayalam. Every fold's conflation is pinned by test: على/علي, كتابة/كتابه,
  Masse/Maße, πότε/ποτέ, все/всё),
  script-aware segmentation (`script.rs`: `Script` — Hebrew is
  `attaches_without_delimiter`, NOT `Other`: it writes with spaces but its
  clitics (`ה`/`ב`/`ל`/`ו`/`מ`/`ש`) attach with none, exactly as Arabic's do,
  and classed as delimiting it got an 8-character floor for 3-character stems
  while being excluded from `shares_a_stem` — measured, the only language in a
  15-language audit to admit **nothing at all**. A two-character subrun is a
  WORD, not a fragment, so `emit` flags n-grams only above length two: `גן`,
  `בן`, `יד` were exact matches before the reclassification and became
  unreachable after it. +
  `segment` — splitting on `!is_alphanumeric` finds no boundary in Han, Kana,
  Hangul, Bopomofo, Arabic, Khmer, Thai, Lao or Myanmar, so a clause became
  one token and a query for a word the drawer contains returned **nothing at
  all** — `search` drops a hit with no lexical evidence and a neutral cosine,
  so the observable was an empty result, not a bad ranking. Bigrams over
  maximal same-**script** subruns, plus unigrams only where a character is a
  word (`is_logographic` — Han only; unigrams in an alphabetic script make
  `قطار` match `المستشفى` on a shared alef and retire the relevance gate).
  A joining mark (combining class 7 or 9 — virama, nukta) is word-INTERNAL and
  continues a run, but **only in a delimiting script**: `नमस्ते` was `नमस`+`ते`,
  and the fragments matched unrelated words (`दिल` inside `दिल्ली`). Blanket-
  joining is wrong — in a non-delimiting script `emit` makes bigrams and a
  consonant+mark bigram is not injective, so Thai `เก่า`/`ก่อน` would share `ก่`.
  `Segmented.ngram` marks which tokens are n-grams from a non-delimiting,
  **non-logographic** script; the store refuses them the EXACT slot, because a
  shared two-character substring in an unvocalised abjad is not evidence —
  measured, bigram-to-bigram equality admitted **74.3%** of a real Arabic
  corpus on one query, against 6.9% for Greek. Whole-word containment
  (`shares_a_stem`, ≥3 chars) carries the clitics instead, into `lexical_morph`.
  Han is not flagged: there a character is a morpheme.
  Latin/digit subruns stay whole so a brand name inside CJK survives;
  delimiting scripts — Latin, Cyrillic, Greek, Georgian, Tibetan — are
  untouched, their defects being folding and morphology, which n-grams do not
  address. `segment` filters nothing — BM25 applies the historical `len() > 1`
  **byte** test, the embedder does not, because a one-letter word is signal
  there), hashed n-gram embedder identity (`embed.rs`: `HASH_EMBEDDER` =
  `undercroft-hash-v3` — v1 neither folded nor segmented, v2 shattered Brahmic
  conjuncts; the store migrates
  **every known predecessor** to v3 automatically at open via
  `KNOWN_EMBEDDER_UPGRADES` (both v1→v3 and v2→v3 — v2 shipped in no tag but
  existed on the branch, and without its row such a vault matches on name,
  returns early, and keeps vectors from a different token space silently), since a user
  who merely upgraded the binary did not choose a new vector space. Embeddings
  are not HMAC-covered, so a re-embed never touches a drawer tag or the audit
  chain — which is why this is not a rotation. The walk is batched, idempotent,
  and records the new identity **last**, so a crash mid-walk just repeats it;
  it also drops the PQ/IVF tables, whose codebook quantizes vectors that no
  longer exist. Unreadable rows are **skipped, not fatal** — a walk inside
  `open` that aborts leaves the vault unopenable for `verify` and `repair`
  too, which is worse than a stale vector on a row that already fails every
  read. `UNDERCROFT_FORCE_EMBEDDER=1` is checked **before** the migration
  branch or it would be dead code for the one transition that can fail, and
  `open_read_only` (used by `serve --read-only`) warns instead of writing.
  A swap to or from a *model* embedder stays manual —
  `UNDERCROFT_FORCE_EMBEDDER=1` + `repair`), grounding (`support.rs`:
  `Support`/`Span`/`Grounding` —
  spans as offsets, never copied text), temporal extraction (`temporal.rs`: in-text
  absolute + relative dates, resolved against the drawer's `content_date`,
  never guessed; a mention resolves to a **period** (`resolved` +
  `resolved_end`, `range()`) so "May 2023" and "last week" stay the month and
  the week instead of collapsing onto a first day; exact calendar
  arithmetic — `days_between`,
  `calendar_weeks_between` (boundaries crossed, not days/7),
  `calendar_months_between`, `hours_between` on absolute instants,
  `describe_interval` (years counted on the calendar, never days/365),
  `WeekStart::{Monday,Sunday,Saturday}` since first-day-of-week is locale
  data and it moves "last week"/"this Thursday" as well as the counts
  (`*_with` variants throughout); `Locale{language,week_start,date_order,
  calendar}` — FOUR read-time declarations, none of them inferred, because
  script is not evidence (Thai script writes Gregorian constantly) and a
  numeral system is not a calendar (`๒๐๒๖` is an ordinary Gregorian 2026 in
  Thai digits and reading the glyphs as an era claim resolved it to **1483**).
  `Calendar::{Gregorian,Buddhist,Minguo,Hijri,Jalali,Reiwa,Heisei,Showa,
  Taisho,Meiji}` — all but two are a renumbered year and convert by arithmetic;
  Hijri (**Umm al-Qura**, the Saudi
  civil calendar, NOT the tabular variant that is easy to write and wrong by a
  day or two) and Jalali are different calendars, so conversion is whole-date
  via `calendrical_calculations` (Apache-2.0, 3 transitive deps, pure algorithm,
  no data files, Unicode Consortium/ICU4X — attributed in NOTICE). A Japanese
  era is a renumbered year that is also **bounded** (`Calendar::japanese` →
  offset + first/last day): an era's first and last years are PARTIAL, so
  令和1年 is 1 May–31 Dec 2019 and reading it as the whole year would claim four
  months that were 平成31年 — wrong, not rounded. `ERA_MARKERS` +
  `era_beside` + `era_year_range`: a marker the writer typed beside a year
  (`พ.ศ.` `ค.ศ.` `هـ` `民國` `令和`, before/after/glued) **OUTRANKS** the declared
  calendar — the declaration is about a corpus, the marker about one date, and
  reading it is EVIDENCE. Markers that disagree on both sides settle nothing and
  leave the declaration standing. A **bare year** is a mention only where a
  marker names it (`2568` is a quantity, `พ.ศ. 2568` is 2025) — the same trade
  `month_name_is_deliberate` makes, and the only route by which 令和/民國 mean
  anything since those are written with a year and no month.
  `AR_ROOTS` × `AR_PATTERNS` → `ar_root_family`: Arabic is root-and-pattern, so
  144 roots poured into 20 templates generate 2859 forms once and two words meet
  only when ONE ROOT explains both. An ALLOWLIST — a form the table cannot
  generate matches nothing — which is why it succeeds where three subsequence
  families failed: `بيت`→`بيوت` and `يجب`→`يجيب` are the same string operation
  and no rule over shape separates them. Measured HALF the shipped skeleton
  rule's promiscuity (3.25 vs 6.67) while taking 5 of its 6 drops. Ours, of
  necessity: every mature Arabic resource is GPL, research-only or LDC-
  non-redistributable (CAMeL Tools' code is MIT, its database is not).
  `AMBIGUOUS_ERA_MARKERS` (bare `م`/`ه`) take TWO signals strongest-first, the
  `DateOrder` shape: `a_year_noun_governs` the number (reusing `AR_UNITS`'
  `Unit::Year` vocabulary through `ar_unit`, so every plural and article comes
  free — confirming evidence, never a blocklist), else
  `glued_to_what_precedes` — no separator at all, read from the RAW text since
  tokens are lowercased and NFC'd so `off + w.len()` is not where the previous
  token ended. `١٩٩٥م` is how Arabic writes a year, `١٥٠٠ م` how it writes a
  quantity, SI asks for that space. **The cost is a wrong reading and it is
  PINNED, not hidden**: `على ارتفاع ٢٥٠٠م` is an ordinary glued altitude and
  now resolves as the year 2500 — no string relation separates them and reading
  the number's SIZE would be inference; confined to four-digit quantities since
  the Gregorian gate wants four digits. Same trade as day-first: wrong-and-
  correctable beats silent. The era reaches the numeric readers and the bare
  year only — the
  month-name arms build Gregorian-only and always have, so a *declared* calendar
  never reached them either (recorded gap, both directions).
  `tokens()` breaks a run where a digit meets a letter from a script that
  `attaches_without_delimiter` (`push_run`/`breaks_before`): `1447هـ` and
  `令和6年` were single mixed tokens, so the digits were not a number and the
  marker was not a marker. Latin is deliberately excluded — it glues
  IDENTIFIERS (`covid19`, `mp3`, `5th`) and breaking those hands `count_of` a
  bare number that the `<n> <unit> ago` arm reads as a count, inventing a date
  from a product name. `-`/`/` stay opaque to the break or `٢٠٢٣-أيار-٠٧` would
  split at the month name and `named_date_token` would never see three fields;
  `.` is transparent so `ค.ศ.2023` breaks after the marker.
  `DateOrder` takes four signals strongest-first: declared; **demonstrated by
  the text** (`13/05` can only be day-first, so an unambiguous date states the
  writer's convention by example — EVIDENCE, not inference); implied by the
  language (CLDR gives `ar` as d/M/y in every Arabic territory, English splits
  US/Commonwealth and implies nothing, which is why `Locale::ARABIC` declares an
  order and `Locale::ENGLISH` does not); then day-first. There is no
  `GREGORIAN_MAX` any more — it bounded years at 2199 to stop Buddhist 2566
  reading as Gregorian 2566, and once a calendar could be declared it began
  discarding legitimate far-future dates (a novel, an astronomy note) to guard
  against an ambiguity a declaration settles; `Locale{language,week_start}` +
  `Language::{English,Arabic}` selects a **scanner, not a table** —
  Arabic puts the past marker before the count (قبل ثلاثة أيام), has a
  dual (يومين = two days as one word), puts period modifiers after the
  noun (الأسبوع الماضي), reads both Gregorian month-name systems
  (Levantine كانون الثاني + Roman يناير) and Arabic-Indic digits;
  the locale is a **read-time** parameter (`live_time_mentions_in`,
  `language` on `/v1/search` and `undercroft_search`) because the reading
  is live, so a corpus ingested under one locale answers correctly under
  another with no re-ingest;
  every shift is checked — hostile counts resolve to nothing, never a panic
  and never the unshifted anchor; local dates come from the offset the
  timestamp itself carries, never from
  the host clock, so a vault answers identically on every machine), hashed
  n-gram embedder (`embed.rs`: `Embedder` trait + `HashEmbedder`), reranker
  trait (`rerank.rs`: `Reranker`), late-interaction trait + MaxSim + int8
  token packing (`late.rs`: `LateInteraction`), conversation parsing, entities
- `crates/undercroft-vault` — security layer (keys.rs: master key + HKDF;
  seal.rs: AEAD + HMAC; lib.rs: VaultManager/Vault + manifest-as-rollback-
  anchor + pure chain arithmetic + key rotation primitives
  (rotation_candidate, byte-exact reseal_at_rest, two-phase
  vault.json.next staging, keycheck marker); bundle.rs:
  recipient-encrypted export bundles — **hybrid post-quantum since
  C3.4**: `keygen` = X25519 + ML-KEM-768 (`pq1` strings), v2 bundles
  derive the file key from BOTH shared secrets (HKDF ikm = DH ‖
  kem_shared, magic+eph+kem_ct all AAD), closing
  harvest-now-decrypt-later on the one asymmetric exchange in the
  codebase; legacy bare-hex X25519 identities still parse, still
  receive v1 bundles they can open, and a hybrid identity opens old v1
  backups with its curve half — but a hybrid recipient NEVER silently
  downgrades and an X25519-only secret gets a typed refusal on v2
  (downgrade-refusal pinned; docs/PQ.md is the posture page, incl. the
  honest boundary: quantum-resistant CRYPTOGRAPHY, never "quantum
  processing") + **signed manifests** (Ed25519 sender attestation
  beside the recipient flow — encryption says who may READ, the signature
  says who WROTE; scope/trust-claim/expiry/counts/provenance +
  unconditionally-checked payload digest; a sender-declared trust label is
  a CLAIM, never a boundary — docs/LABELS.md; legacy payloads import
  unattested-and-said-so); at-rest AAD domains: content, `/emb`, `/tok`
  token matrices, `/pq` index artifacts)
- `crates/undercroft-store` — per-vault SQLite storage, hybrid search (cosine +
  BM25 fusion; `SearchHit` carries **three** lexical channels — `lexical_exact`
  (the drawer said the word) and `lexical_morph` (it holds a word built on it —
  today only `contains_a_long_word`) both **admit** via `hits.retain`, kept
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
  poisons (`πολύ`/`πόλη` is why Snowball Greek was rejected). `-er` is
  German-only via `MorphLang` on `SearchOptions` (`suffixes_for`), fed by the
  request's existing `language` — ONE declaration, two consumers: the date
  scanner (en/ar) and morphology (en/de). For English `-er` admits
  `flow`/`flower`, `corn`/`corner`, `butt`/`butter`; declared German it takes
  `Kind`/`Kinder`, `Haus`/`Häuser`, `Buch`/`Bücher` and German goes 50%→**100%**,
  all on the lexical channel. Declared, never detected — the two share a script,
  so nothing in the bytes says which endings are legal, and the price is pinned:
  under German, `flow`/`flower` DOES meet. Note promiscuity
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
  opt-in `UNDERCROFT_SEARCH_TRACE=1` phase trace AFTER parallel
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
  is scope-resolved before candidates are drawn** (`scope_seqs` →
  `*_candidates_in`): `room` was a plain `WHERE` over globally generated
  candidates — the wing defect with no tier and no fallback — and the FTS
  prefilter shared the shape (both were recorded gaps, both closed
  2026-08-02). A scope that fits the hydration budget (`max(256,
  depth·32)`) drops the prefilter and is scanned exactly; a larger one
  gets membership-filtered candidates (PQ/wing-PQ/FDE filter during
  selection and widen when a probe under-delivers IN-SCOPE; FTS/HNSW
  filter their top-k and surrender to the bounded exact scan when the
  scope's share cannot fill the page), pools SIZED BY THE SCOPE
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
  HNSW (hnsw.rs, `hnsw` feature), transactional audit chain (`chain_meta` + `chain_append`),
  verify, knowledge graph (kg.rs — incl. the golden-values authority
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
  live in sealed blobs (`terms`, `name_rest`) covered by the fact's tag
  through a FOURTH canonical extension (0x1c), so nothing written earlier is
  re-tagged. `triple_id`/`entity_id` are keyed too, and that is not optional:
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
  extractor identity (which model claimed each distilled fact, inside the
  fact's HMAC via the third canonical extension — 0x1d, the
  support/authority precedent, so untouched facts keep byte-identical
  canonicals; a flipped attribution fails verification), receipted drawer
  supersession (`meta.supersedes` under the drawer HMAC + mirror column +
  keyed receipt over the superseded content's unkeyed fp in separate
  columns — the kg source_fp/receipt_tag shape one level up, re-keyed on
  rotation; five verdicts via `verify_supersessions`; superseding NEVER
  deletes), whole-palace export/import (typed records: drawers + KG
  entities/facts/tunnels; receipts re-key from the traveling fp at the
  destination; the manifest carries embedder identity and chain head as
  provenance, never as state),
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
  **`upsert_many` is the stated exception**: a batch owns its transaction,
  so it cannot call `write_drawer` and screens through its own
  `admission_divert` loop into `BulkOutcome{created, quarantined}` — the
  same decision reached by a SECOND implementation, which is the shape the
  `Screen` argument exists to prevent (ROADMAP R5: extract one
  screen-and-divert function both paths call; the telemetry half is
  already shared, both paths classifying through `admission::save_event`).
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
  cannot crowd or starve), `recent` — which is what `wake_up` and the
  closet index call, i.e. the two surfaces whose whole job is loading
  context at session start, exactly where injected text wants to be —
  and `list_drawers`. Naming the wing is how the reviewer opts back in,
  and MCP may not: `mcp.rs`'s **quarantine fence** refuses any tool whose
  arguments name the reserved wing or an `*id` resident in it, so the
  agent whose write was diverted can neither read the evidence back nor
  delete it; allow/deny chain-audited
  with the verdict inside the ruling tag; operator surfaces only, never
  MCP; default off = byte-identical write contract; **deny is receipted**
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
  parties verify the operator's Ed25519 signature),
  retention policies (retention.rs — C3.2 phase 2: per wing/room on the
  wing-trust pattern, operator-only + HMAC-tagged + audited, flip fails
  list AND sweep; enforcement is an **explicit sweep** through
  `forget_with_proof` — receipt per sweep, nothing automatic, quarantine
  wing refused; the clock is the HMAC-covered `meta.filed_at`,
  tag-verified per drawer, never the clear column — a flipped column can
  neither launder a deletion through a keyed sweep nor hide a drawer
  from its declared retention),
  management surface (manage.rs — incl. **deployment-assigned wing trust**:
  `TRUST_VOCAB` closed vocabulary assigned by the operator only, never over
  MCP; HMAC-tagged + audited, flip = integrity failure; consumed as a
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
  shared `resolve_search_policy`, applied per candidate off the
  HMAC-verified `meta.wing`. They were absent here until 2026-08-04, so an
  `index push` turned `--backend qdrant` into a route around admission
  control — the fix is a shared REQUIRED step, not a second copy. `index_push`
  still mirrors quarantined rows (an untrusted mirror can offer any id, so a
  push-side filter is not a boundary, and dropping them would empty the
  reviewer's own `--wing quarantine-pending` scope); the residue is stated —
  remotely the floor bounds what came BACK, not what was generated, i.e. an
  availability cost, never an integrity one. Telemetry is at parity too),
  read/egress auditing (the consultation-filed gap, closed 2026-08-04:
  **exports chain-audited unconditionally on every surface** —
  `audit_export`, one `egress/export` record binding surface + recipient
  + counts + the export's own manifest digest; read-only replicas warn
  and serve; **reads audited under `UNDERCROFT_READ_AUDIT=chain`** —
  `audit_read` at the search_inner + remote tails covers every path, one
  record per search with a KEYED query fingerprint (never text, pinned
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
  over preserved audit bytes, crash-reconciled at open), bulk ingest
  (`upsert_many`: one transaction + one manifest anchor per batch —
  advisory encode paths must never BEGIN or batching breaks)
- `crates/undercroft-net` — the outbound transport policy, in ONE place:
  **TLS or loopback, nothing else, no override** (refused at construction,
  before a byte moves) plus CA pinning, where a declared root REPLACES the
  public roots rather than adding to them and a file that pins nothing
  refuses instead of falling back. It is its own crate because it was
  implemented once in `undercroft-llm` for the embedder and LLM clients
  while the remote **index** backends had no transport policy at all
  (ROADMAP C8) — and every index push carries EMBEDDINGS, which are
  plaintext-derived, so the sealed-vault invariant's own reasoning applies
  one hop out. `is_loopback` delegates to the transport's own `url` parser
  rather than re-deriving the host, because a hand-rolled predicate
  inverted this gate twice (`http://127.0.0.1:8080@evil.com/` read as
  loopback)
- `crates/undercroft-obs` — observability shim: no-op + **zero deps** by default;
  under `--features telemetry` brings up `tracing` logs, Prometheus `/metrics`,
  OTLP traces (metadata-only spans), and the live SSE broker. Two contracts
  worth knowing: `chain_commit(records)` counts audit-chain **records**, not
  manifest anchors (a 256-drawer batch anchors once and advances it by 256;
  records appended without an anchor — read audits — are counted by the next
  one), and **a diversion is a `drawer-quarantined` frame decided by ONE
  classifier**: `admission::save_event` classifies by WHERE THE ROW LANDED,
  `write_drawer` emits at the choke point, and `upsert_many` — which owns
  its transaction and cannot reach the choke point — runs the same
  classifier over its batch. The frame carries the intended wing/room and
  the closed-vocabulary signal codes; codes ship even for a sealed vault
  since they are not names (a sealed frame suppresses the names), and
  offsets and content never travel. `monitor.html` dispatches on
  `drawer-quarantined`; `website/src/observability.md` documents it.
  **The counter travels with the frame since 2026-08-05 (C11/R5)**: both
  are emitted by ONE function (`PalaceStore::emit_write_event`) off ONE
  `save_event` classification, and `drawer_writes_total` gained a third
  label, `quarantined`. It used to be a hard-coded
  `WriteOutcome::Created` one line above the branch that decided the
  frame, on all five write arms, so the monitor showed
  `drawer-quarantined` while the counter climbed as `created` — a durable
  signal that was *wrong* rather than missing. Gated by a SOURCE count
  (`write_telemetry_has_exactly_one_emitter`), because the counter is a
  no-op without the telemetry feature and no test that merely drives a
  save could ever have seen it
- `crates/undercroft-index` — remote vector backends (Qdrant/Chroma/pgvector/
  Milvus/Weaviate) as untrusted accelerators; sealed content only, re-verified
- `crates/undercroft-llm` — local LLM runtimes (Ollama/OpenAI-compatible) for
  `refine` → KG extraction, **and `embed.rs`: `HttpEmbedder`**, an `Embedder`
  backed by a served model (`UNDERCROFT_EMBEDDER=http` + `UNDERCROFT_EMBED_URL`
  /`_MODEL`/`_API`/`_KEY`/`_DIM`). Both API shapes, dimension **probed** from
  the endpoint rather than assumed, identity `http:<model>` so the existing
  swap-refusal covers it. **Transport: TLS or loopback, nothing else** —
  cleartext http to a non-loopback host is REFUSED at construction with no
  override (operator decision 2026-08-03; the error names the fix), and
  `UNDERCROFT_EMBED_CA` declares a self-signed root as a **pin** (replaces
  the public roots; a garbage file refuses rather than falling back —
  un-pinning silently is the failure mode). The compose `embeddings-tls`
  Caddy terminator ships the required infra (deploy/embeddings-tls/) with
  its CA on the `undercroft-embed-tls` volume. Two hazards it still states
  rather than hides: the ENDPOINT reads drawer text in plaintext (warned
  at construction when the host is not loopback — TLS protects the wire,
  not the destination; sealing protects a vault at rest, not content
  handed to another process; in-process onnx/ort close it), and a failed
  embed cannot fail a write, so it degrades to a **counted** zero vector
  (lexically findable, semantically invisible until re-embedded).
  The same transport policy covers `LlmClient` itself (2026-08-04):
  refine and the admission advisor refuse cleartext beyond loopback,
  `UNDERCROFT_LLM_CA` pins a self-signed root, construction is fallible.
  No external API by default: nothing is contacted unless a URL is set
- `crates/undercroft-embed-onnx` — feature-gated ONNX embedder, cross-encoder
  reranker, **and** ColBERT late-interaction encoder (tract, pure Rust; two
  fixed-shape plans per ColBERT export — dynamic-axis exports carry ops tract
  rejects); built via the `onnx-build` compose service. Models are
  user-supplied; tract 0.22 runs BERT-family models, **not** DeBERTa rerankers
- `crates/undercroft-embed-ort` — opt-in ONNX Runtime backend (C++ dep;
  `ort-build` compose service): session-pool embedder + reranker + ColBERT
  encoder (late.rs — same exports/env as the tract one), ~2.5× tract per
  forward, int8 model support; pinned `ort = 2.0.0-rc.10`. Wired into the
  CLI via `--features ort` (`UNDERCROFT_EMBEDDER=ort`,
  `UNDERCROFT_RERANKER=ort|colbert-ort`; multi-tenant server shares one
  session pool across vaults)
- `crates/undercroft-cli` — `undercroft` binary (main.rs: CLI, plus `Posture`
  — `open_store_as` makes read-vs-write something a caller must STATE, so
  `serve-http --read-only` opens BOTH its stores read-only; the two opens
  had drifted apart, and which port path opened the vault decided whether
  a `--read-only` server re-embedded every drawer at start-up and appended
  a read-audit record per `/mcp` search; mcp.rs: MCP stdio — **33 tools, 12
  of them writes** — `WRITE_TOOLS`
  + the quarantine fence and the authority fence over raw arguments;
  parity.rs: the surface inventory the code is COUNTED AGAINST in both
  directions — a tool advertised without a line fails the build, a line
  naming a dead tool fails it too (that second half was written but never
  RUN: the check went `MCP_TOOLS → WRITE_TOOLS` only, so `WRITE_TOOLS` kept
  naming the removed authority tool and passed), and `OPERATOR_ONLY`
  (admission/trust/retention/forget/rotate/**authority** — promotion closes
  the previous canonical holder's window, so an agent that could write it
  could make its own fact the one answer `lookup_canonical` returns)
  asserts those never reach MCP,
  so a boundary is enforced by the same mechanism as the parity instead of
  living in a doc table that rots; search.rs: what a search DECLARES and
  what it OWES back, once for all three surfaces — `SearchOptions`, the
  read-time `Locale` and the honest-exclusion notes were rebuilt by hand
  per handler and each forgot a different piece (`week_start` reached only
  `/v1`, `room_cap` only `/v1`, `language` only MCP+`/v1`, `ranked_at`
  only MCP+`/v1`, the trust-floor exclusion count only CLI+`/v1`), and
  `DEFAULT_LIMIT` is now **5 everywhere** (it was 5 on CLI/MCP and 10 on
  `/v1`, so "the same search" answered differently per transport —
  unified DOWN, since every surface names its continuation);
  i18n.rs: result-string localization for nine languages
  (`UNDERCROFT_LANG` → `LANG`, primary subtag; errors, help and
  machine-oriented output stay English);
  refine.rs: the ONE LLM-distillation implementation both `undercroft refine`
  and `POST /v1/…/refine` drive — same `UNDERCROFT_LLM_*` config used to
  build two different vaults, the CLI's facts carrying no date resolved from
  the note's words, no grounding verdict and no searchable mirror;
  http.rs/tenant.rs: HTTP + multi-tenant `/v1` incl. the management and
  operator planes (drawers list/get/update/delete, taxonomy, stats +
  history, read-only kg browse + `kg/authority`, supersessions, trust,
  admission list/rule, retention set/list/sweep, forget, refine, verify,
  rotate, export/import). **`--read-only` is a posture on the whole
  process, decided once in FRONT of dispatch** (`mutates`), not a guard
  per mutating handler: there were thirteen guards for fourteen mutating
  routes and `POST …/kg/authority` never got one, so a read-only server
  rewrote HMAC-covered authority columns, superseded the previous
  canonical holder and appended to the chain while answering 200 — while
  the identical capability over `/mcp` in the same process refused. It
  fails CLOSED (anything not GET is a write unless named), and the two
  named exceptions are `POST …/search` and `POST …/verify` — both POST
  for cost, not for effect: search reads, and verify walks every record's
  HMAC and replays the chain. Verify is a read in the strict sense —
  `&self`, no mutating call — which also means it does **not** tighten the
  manifest anchor: only a store open does (`init_chain`), so the
  read-audit boundary's old "run writes or `verify`" advice was wrong on
  exactly the deployment it was written for, a server that caches its
  handle (A31). **The OPEN is a read too since 2026-08-05 (R4)** — this
  line used to record the opposite as a stated gap, and both halves of it
  are now closed: `open_read_only` takes a `SQLITE_OPEN_READ_ONLY`
  connection under `PRAGMA query_only=ON` (so a write we MISSED fails
  loudly rather than happening quietly), does not create the database,
  does not run `journal_mode=WAL`, creates and alters no table, seeds no
  `chain_meta`, fast-forwards no anchor, rebuilds no FTS index, and does
  not promote or delete a writer's `vault.json.next` — the operation
  A32 called evidence destruction on the incident runbook's own path. It
  reaches the UNLOCK as well (`unlock_as(Access::ReadOnly)`), because
  unlocking deletes a staging manifest it cannot authenticate and stating
  the posture one call later was already too late. Each of those is
  DETECTED and REPORTED instead, on `PalaceStats.unhealed` (all three
  surfaces) and as a warning at open. Two conditions refuse rather than
  report, both 409: an absent `palace.db` under a present manifest
  (`DatabaseMissing`, A33 — "empty" is not "absent", and it is an
  integrity verdict, so exit 2), and a schema a read-only role would have
  had to migrate (`ReadOnlyUnmigrated`, exit 1 — the vault is intact, the
  posture is simply wrong for it). A vault whose writer crashed
  mid-rotation still opens, which is the case that made reporting the
  right rule. The prefilter half (R1) was already closed: a tier loads an
  existing index and never builds one. Residue, stated: a read-only
  connection materialises SQLite's WAL scaffolding (`-shm`, and a
  zero-length `-wal`) when the directory is writable — no database
  content, reconstructible, and the price of reading a WAL database at
  all; where the directory is NOT writable the open escalates to
  `immutable=1` and says so, which is what makes a write-protected mount
  or a snapshot readable (R4's first item, settled by execution — the
  test blocks the `-shm` with a directory rather than with `chmod`,
  because the test container runs as root and permission bits do not bind
  root);
  ui.html: the vault admin console (incl. live MONITOR +
  KNOWLEDGE tabs), `include_str!`'d and served at `GET /ui` on every
  build; monitor.html: the Palace Monitor
  UI, `include_str!`'d and served at `GET /monitor` on telemetry builds);
  integration tests in `tests/cli.rs`
- `crates/undercroft-orchestrator` — `undercroft-orchestrator` binary: the
  optional multi-tenant control plane (docs/MULTI_TENANCY.md) — instance
  registry + tenant→vault map in its own SQLite (engine creds sealed,
  tokens stored as HMACs), `/t/*` routing proxy, `/admin/*` plane,
  count-verified migration, fleet console (ui.html at `GET /ui`),
  read replicas (`serve --read-replica`: RO state db, data plane only,
  `/healthz` mode+last_write lag surface).
  Pure `/v1` client; never linked by the engine
- `crates/undercroft-bench` — LongMemEval/LoCoMo/ConvoMem/MemBench/model-eval
  harnesses (`--features onnx` for model rows; `--skip`/`--limit` sharding),
  plus synthetic instruments: `synth`, `wingscale` (per-wing tier: scoped vs
  unscoped R@5 + steady-state ms/q, ONE ingest per corpus with `--floors`
  iterated in-process, per-pass warm-up reported separately — folding a
  one-time index build into a per-query average manufactured a 15× "effect"
  in this instrument's own first version), `scopescale` (scoped recall AT
  SCALE: a fixed 8192-drawer probe wing holding a fixed 512-row probe room,
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
  fixture must trip; deterministic, no vault, no model)
- `deploy/observability/` — Prometheus + Alertmanager + Loki + Tempo + Grafana
  stack (see its README.md + RUNBOOK.md)
- `architecture/` — illustrated architecture reference: eleven theme-aware
  SVG diagrams (`diagrams/`), the same as PDF (`pdf/`), and `index.html`
  which inlines them and documents every layer plus all **77**
  `UNDERCROFT_*` variables the engine honours — 62 written out in full
  across the env table's 58 rows, plus 15 siblings abbreviated to a
  suffix inside the row that owns them (`_TOKENIZER` three times, one
  per model role), which is why grepping the page for full names
  undercounts it. Count the truth, never a number in prose:
  `grep -rhoE '"UNDERCROFT_[A-Z0-9_]+"' crates/ | sort -u` over every
  crate except `undercroft-bench`, whose `UNDERCROFT_VS_*`/`UNDERCROFT_TEST_*`
  belong to the harness rather than the engine.
  **`diagrams/` is the only source; `pdf/` and
  the inlined copies are both DERIVED, and `build.sh` regenerates both
  — edit an SVG, re-run it, never hand-edit an inlined copy.** It also
  re-derives every `<h3>` id and the whole sidebar from the sections,
  and fails if a heading and a rail entry disagree: a hand-added
  heading otherwise gets no id and no rail entry and nothing complains
  (this happened once). librsvg
  has no CSS-variable support, so the PDF pass flattens each `var()` to
  its light fallback; it also needs `fonts-noto-core`/`-cjk` or Thai,
  Han, Kana and Devanagari render as tofu boxes — a defect the browser
  hides and only a rendered PDF page shows. The inline pass **strips
  each diagram's dark media query**: inlined, it sets `--d-*` on the
  `svg`, which beats the `:root` values, so the diagram would follow the
  SYSTEM theme while the page follows its manual toggle. `build.sh`
  fails if an inlined copy still carries one. The page shows **one
  section at a time** behind a sidebar, enabled by script (`body.paged`)
  so that with JS off every section stays visible and the document still
  reads end to end
- `website/` — GitHub Pages: `landing/index.html` (custom landing) + mdBook docs
  under `src/`
- `tests/e2e.sh`, `tests/e2e-backends.sh`, `tests/e2e-telemetry.sh`,
  `tests/e2e-orchestrator.sh` — end-to-end suites (run in Docker)
- `docs/AGENTS.md` — the scenario-driven agent implementation guide
  (published as docs/agents.html); its tool/route/env reference must be
  kept in sync when the MCP surface, `/v1` routes, or `UNDERCROFT_*`
  variables change
- `docs/AMB_REPLICATION.md` — how to run the Agent Memory Benchmark's
  own protocol against this engine with **Claude subagents in the two
  model roles and no external LLM API**. Deliberately carries **no AMB
  prompt text and no AMB code** — their clone ships no LICENSE, so it is
  all-rights-reserved by default and must never enter this repo or its
  history; the procedure asks the operator for their clone path and maps
  prompts, schemas and cached splits from there. Covers all five cached
  datasets and warns they are not interchangeable (`personamem` is MCQ
  with **no judge at all**, `beam` is a continuous rubric whose
  `build_judge_prompt` is never called, `locomo` alone skips a category).
  Its traps section is load-bearing: `task_type: "open"` needs a
  reasoning+answer schema, `query_timestamp` uses a LEXICOGRAPHIC
  session sort, LoCoMo's category ints are 1 single-hop / 3 multi-hop,
  and `k` defaults to **10** — at k=30 that was 34% of a whole
  conversation and the resulting 94.4% was uninterpretable
- `SECURITY.md` (disclosure policy; private vulnerability reporting is
  enabled on the repo), `NOTICE` (MemPalace MIT heritage attribution),
  `LICENSE` (BUSL 1.1 — see Conventions)
- `.github/workflows/release.yml` — on every `v*` tag: five binary
  targets (linux x86_64/arm64 native, macOS Intel cross-compiled on
  macos-latest + Apple Silicon, windows) uploaded to the release with
  sha256, and the multi-arch `ghcr.io/compufreq/undercroft` image
  (per-arch native builds merged into one manifest; index annotations
  carry the package description). Since the posture-configs unit also
  the **`ort` variant**, and since 2026-08-04 at FULL target parity
  with the default artifacts: a `…-ort` binary asset for all five
  targets (same matrix, Intel-macOS smoke under Rosetta, installed
  explicitly) and a `:tag-ort` multi-arch image (amd64+arm64 per-arch
  builds + their own manifest job; `republish-ort-image` dispatch
  carries the same shape so a republish produces exactly what the tag
  would have), each smoke-probed — `--help`, then
  `UNDERCROFT_EMBEDDER=ort` must fail on
  MODEL CONFIG ("loading ORT embedder"), never on a missing feature,
  which is what a default binary under the asset name would say. The
  binary smoke runs against the PACKAGED layout, not the build tree —
  a binary that secretly needs a shared library beside it fails at CI,
  not on a user's machine — and packaging carries any onnxruntime
  runtime library the build drops beside the binary (statically linked
  on every probed target, so normally nothing matches; the copy is the
  honest fallback, not the expectation). The Dockerfile features
  branch also
  builds the orchestrator (the runtime stage copies both binaries — a
  features-only build used to leave it missing)

The upstream Python implementation (the MemPalace project) is *not* in
this repo and no longer linked as a fork; its behavior is documented in
docs/PARITY.md. Never reintroduce Python code here.

## Build & test — Docker only

Build and test **inside containers**, not on the host (project policy):

```bash
docker compose run --rm test          # cargo unit + integration tests (641 run,
                                      # 4 #[ignore]d = 645 declared. Counted from
                                      # a battery run at the INTEGRATED tree,
                                      # never inherited and never from one
                                      # agent's own slice — a fleet member wrote
                                      # 556 here from its own worktree, which was
                                      # 551 plus the five tests it had added and
                                      # blind to the forty-five its seven
                                      # neighbours were adding in parallel. Sum
                                      # the `test result:` lines of a full run.
                                      # The 4 ignored are 3 measurements needing
                                      # testdata/*_50k.txt plus one in lib.rs; the
                                      # onnx crate's own ignored test is outside
                                      # default-members and never in this count)
docker compose run --rm lint          # rustfmt --check + clippy -D warnings
docker compose run --rm e2e           # e2e UI/UX suite against the release binary (238 checks)
docker compose run --rm orchestrator-e2e  # two engines + orchestrator (76 checks)
docker compose run --rm e2e-telemetry # telemetry build + /metrics gating (24 checks)
docker compose run --rm backends-e2e  # five live vector DBs over TLS (57 checks; weaviate
                                      # readiness gates on /v1/schema==200 — it
                                      # answers HTTP before its Raft leader exists)
docker compose run --rm onnx-build    # compile-check the ONNX embedder+reranker feature
docker compose run --rm ort-build    # compile-check CLI with --features onnx,ort
                                      # (CI clippy never sees non-default features —
                                      # clippy ort-gated code here explicitly)
docker compose run --rm site          # build the mdBook docs (mdbook pinned 0.5.4;
                                      # mermaid via vendored website/assets/mermaid.min.js)
docker build -t undercroft .           # runtime image

# A quantized text embedder on the compose network, CPU only — so a
# measurement is reproducible instead of depending on a desktop app on the
# host (which the bench container cannot reach anyway). Reached through
# the embeddings-tls terminator ONLY: the engine refuses cleartext http
# to any non-loopback host, no override. The client container mounts the
# terminator's CA volume and PINS the root:
docker compose up -d embeddings embeddings-tls
docker compose run --rm embed-pull    # one-time model fetch into a volume
#   then run cli/bench with (project-prefixed volume name — a bare
#   undercroft-embed-tls mounts a fresh empty volume silently):
#     -v undercroft_undercroft-embed-tls:/tls:ro
#     UNDERCROFT_EMBEDDER=http UNDERCROFT_EMBED_URL=https://embeddings-tls
#     UNDERCROFT_EMBED_CA=/tls/caddy/pki/authorities/local/root.crt
#     UNDERCROFT_EMBED_MODEL=nomic-embed-text
```

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

**`cargo build -p <crate>` does not compile that crate's integration tests.**
`tests/*.rs` needs `--tests`. Three unbalanced-brace defects survived several
"green" targeted builds this way and only surfaced in the compose battery, one
at a time, as different build targets reached each file.

**Union is the right conflict resolution for CHANGELOG bullets and the WRONG
one for code.** Applying it blindly across a 7-way merge spliced away closing
braces in three `.rs` files. Resolve code conflicts on their merits; reserve
union for additive prose.

**Before trusting any run of a freshly built binary, prove the binary is
fresh**: probe it for a symbol only the new code has (`--help | grep -c
<new-flag>`). A stale binary passes every old test by construction.

**Always pass `--build`.** The battery images COPY the source, they do not
mount it — `docker compose run --rm test` without `--build` silently
re-runs whatever was baked into the last image, so a "green" run can be
testing code you already changed. rustfmt cannot fix host files from those
images either; mount the repo instead:
`docker run --rm -v "<repo>:/src" -w /src rust:1.90-slim-bookworm sh -c "rustup component add rustfmt; cargo fmt --all"`

CI runs `cargo fmt --all --check` + `cargo clippy --all-targets -- -D warnings`
(no `--workspace`, so the excluded onnx crate is fmt'd but not clippy'd in CI).
Heavy cargo work: use the `undercroft-target` volume + `CARGO_TARGET_DIR=/build`
(host bind-mounted `target/` SIGBUSes under memory pressure).

## Invariants to preserve (inherited from MemPalace's mission + vault layer)

- Content is stored **verbatim** — never summarize, paraphrase, or lossy-
  compress user data on the write path. Retrieval returns the exact words.
- Local-first, zero external API by default: no phone-home; the default
  embedder is deterministic and offline. Observability is **opt-in** behind
  `--features telemetry` — default builds carry zero telemetry deps and emit
  nothing; when on, signals are **metadata/counts only** (never drawer content
  or keys) and nothing leaves the process unless an endpoint is set.
- Derived structure that is recomputable from content must **not** be
  persisted in clear beside it, and where it is recomputable at read it
  generally should not be persisted at all — `time_mentions` and `entities`
  are both read live (`live_time_mentions_in`, `live_entities`), which is
  also what makes a scanner fix and a language choice reach existing vaults
  with no migration.
- Drawer ids are deterministic over (wing, room, source, chunk_index,
  normalize_version); re-mining must stay idempotent and append-only — a crash
  mid-operation must leave the existing palace untouched. On the API save
  paths there is no source, so `chunk_index` carries a **unique append
  index** (`next_append_index`, backed by SQLite's AUTOINCREMENT sequence)
  rather than a position within a document: those saves are unique-per-call,
  not idempotent, and collapsing repeats is dedup's job. Never index an
  append with `count()` — it decreases on delete, and a reused index derives
  an id that already exists, silently overwriting an unrelated drawer.
- Sealed vaults must never persist plaintext or plaintext-derived data **in
  clear** on disk: FTS never exists for them; embeddings, PQ code rows/pages
  and codebooks, and ColBERT token matrices are AEAD-sealed under distinct
  AAD domains (search uses decrypt-once RAM caches; the opt-in PQ page tier
  decrypts lazily per probed list). Tests assert the at-rest bytes; new
  derived artifacts must follow the same pattern. **What a drawer costs is
  pinned too** — `one_drawer_costs_exactly_this_many_bytes` asserts each
  artifact's exact length against its formula (`40+6+dim` embedding = 430 B,
  `40+4+dim/8` PQ row = 92 B, `40+9+rows·(4+dim)` v1 tokens,
  `40+1+reps·2^ksim·dproj·4` raw FDE = 8,233 B; 40 = nonce+tag). **One
  `priced` table drives both the formulas and the inventory**, so a new
  artifact cannot be silenced by adding a name — the first version kept them
  separate and one added string literal made it green with nothing measured.
  The inventory is the **whole schema** (every table either priced
  per-drawer or justified as not) plus `drawers`' **column list**, because a
  name prefix is only a convention and a column is the cheapest unpriced
  per-drawer byte. Measured: 804 B of prose → 515 B sealed content, so the
  default vault's one derived artifact is **0.83×** the content and every
  tier at once is **22×**. Sealed is the strictest level, **not** the
  largest — hmac-only keeps plaintext and adds fts5 plus four shadow tables.
  Note the prefilters are an `else if` chain, FDE first: with the FDE tier
  on, `search` never builds the PQ index, and an FDE row is 8,233 B raw
  below `fde_pq_min` (256) but **301 B PQ'd above it**, so "8 KB/drawer" is
  a small-corpus figure.
  **`meta_json` is stored
  UNSEALED**, so nothing that copies words out of the content may live in it
  — `Drawer::meta_at_rest()` empties `time_mentions[].text` and `entities`
  before a row is written, keeping only resolutions (offsets + ISO dates,
  which are not content). What metadata still leaks is measured and pinned by
  `a_sealed_vault_exposes_metadata_but_never_content` — **twelve** fields,
  counted from the test's own list, not seven as this line said until
  2026-08-05: wing, room, source_file, added_by, hall, content_date,
  resolved dates, declared `kind`, the `supersedes` link, and the
  writer's `agent`/`channel`/`session` claims (plus the clear `filed_at`/
  `updated_at` columns and per-record ciphertext sizes, which the pricing
  test's column inventory covers). That test fails
  in **both** directions, so shrinking the exposure forces the inventory to
  be updated. Closing the rest = keyed blind index (truncated HMAC, as
  `fingerprint()` already does) for fields needing SQL equality, sealed blob
  + RAM cache for the rest.
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
- Every write must update the audit chain **atomically with its data**: the
  committed head lives in `chain_meta` and advances via `chain_append` inside
  the same SQLite transaction (the manifest holds a lagging rollback anchor,
  reconciled at open — crash ⇒ fast-forward, rollback ⇒ tamper). Every read
  must verify the record HMAC before returning data. **Anything that
  REPORTS the chain reads `chain_meta`** (`PalaceStore::chain_state`, behind
  `PalaceStats.writes`/`chain_head`), never `Vault::writes()` /
  `chain_head_hex()`: those are the handle's own manifest fields, written
  only by its own `anchor_manifest` and never reloaded, so in `serve-http`
  — two handles on one vault — the handle that did not write reported a
  frozen height beside a climbing live `drawers` count.
- Durability is pinned, not assumed: SQLite runs WAL + `synchronous=FULL`
  on both binaries, the manifest anchor is fsynced through an atomic
  rename (+ dir sync), and key material is fsynced at creation. The
  anchor must never run **ahead** of the database — that combination is
  what makes a power loss reconcile as a crash instead of a tamper alarm.
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
- **No compression unit may ever span two drawers' plaintext.** Content is
  zstd-3 framed *then* sealed (`compress_frame` → `content_at_rest`), so
  ciphertext length already reveals a drawer's compressibility on top of the
  length AEAD leaks. That is bounded only because every drawer is compressed
  in its **own independent frame with no shared dictionary** — an attacker
  who writes a drawer never shares a compression unit with a secret one.
  This was true by implementation rather than by policy until it was written
  down here. The at-rest attack class has a name (DBREACH, IEEE S&P 2023:
  plaintext extraction from engines that compress pages and encrypt at
  rest). Two consequences: a **shared zstd dictionary is forbidden**, and
  the **4096-row PQ pages must never be compressed** — sealed-but-uncompressed
  is deliberate, and that page geometry is already InnoDB's, so compressing
  it satisfies DBREACH's precondition in one commit. Prefer **fixed-rate**
  compression (quantization, whose output length is content-independent —
  embeddings are already int8 at `6 + dim` bytes) over entropy coding
  anywhere new.
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
  most worth counting), surfaced on `PalaceStats.codebooks`, `/v1/…/stats`
  (a hand-projected handler: adding a struct field does not reach the wire),
  and a gauge whose name must be in `undercroft_obs::GAUGE_NAMES` or it is
  silently dropped. A step means **re-quantization** for the three codebooks
  and **re-partitioning** for `pq-ivf`/`fde-ivf` (code bytes unchanged; the
  candidate set moves). A rebuild that reuses the stored codebook is not a new
  generation. The counter is outside HMAC coverage, so it is evidence about
  ambiguity, never about tampering.
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
  which a hand-maintained doc table cannot do. Deliberate absences are
  entries in `OPERATOR_ONLY` carrying their reason (an agent must not rule
  on the queue that exists to contain it, nor assign the trust class that
  decides what it may retrieve), asserted by the same test as the parity,
  so the two can never disagree about what MCP is allowed to reach.
- Cross-vault access must fail cryptographically (AAD binds vault id), not
  just logically.
- Vault/wing/room names go through `undercroft_core::validate_name` (path
  traversal guard).

## Definition of done — every unit, no exceptions

A unit is not done when the code works. It is done when all of this is true,
and this list exists because a session shipped work that passed every check it
had and was still bypassable on the surface most deployments use.

1. **Unit tests AND integration tests.** Both, every time, for every change —
   not "where it made sense". A unit test proves the function; an integration
   test proves the SURFACE. The 65-drift audit happened because capabilities
   were verified through one surface and assumed on the others. If a change
   touches behaviour a user can reach, an e2e check exercises it *through the
   surface a user actually drives*, and if it touches more than one surface it
   is exercised through each of them.
2. **A test that would have failed before the fix.** Assert the premise, so it
   cannot pass for the wrong reason. Several tests here carry an explicit
   counterfactual arm for exactly this.
3. **Drift check.** If the change touches a capability reachable from more
   than one of {CLI, MCP, `/v1`, orchestrator}, verify EVERY one of them —
   by reading the other surfaces' code, not by assuming symmetry. `cargo test`
   runs `parity.rs`, which counts the MCP tool surface against a written
   inventory in both directions and enforces the operator-only boundary; it
   catches an added or removed TOOL, and it cannot catch a capability that
   drifts in behaviour. That half is yours.
4. **Every governance surface updated in the same unit**: CHANGELOG, CLAUDE.md,
   ROADMAP, and whichever of docs/AGENTS.md, docs/THREAT_MODEL.md, README,
   architecture/index.html, website/ carry the claim you changed. A claim
   lives on every surface that states it.
5. **The full Docker battery** at the final tree, with raw exit codes:
   `test`, `lint`, `e2e`, `orchestrator-e2e`, `e2e-telemetry`, `backends-e2e`,
   `site`. `cargo build -p <crate>` does **not** compile integration tests —
   `--tests` does.

## Session-end hygiene — leave no debt, drift or stale

Run this before ending a session, and record the result. The rule from the
maintainer: *we don't leave debts or drifts or even stales anywhere in this
project.*

- **Docs vs code**: every number, tool table, route table and `UNDERCROFT_*`
  variable in README, CLAUDE.md, docs/*.md, architecture/index.html and
  website/ verified against the code — counted, not remembered. Landing-page
  stats and doc tables have gone generations stale before.
- **The published site**: `docker compose run --rm site` builds, and after a
  Pages deploy the live page is checked, not assumed.
- **The architecture reference**: if a diagram changed, `build.sh` re-run in
  Docker (diagrams/ is the only source; pdf/ and the inlined copies are
  derived, and the script fails if a heading and the rail disagree).
- **Open threads written down AS WORK**: every residual, gap and deferred
  decision recorded in ROADMAP with its reason, the shape of its fix, and a
  gate. A gap is a gap, never dressed up as a principled refusal — and
  **"accepted" is not a resting state**. Nothing broken or half-baked stays a
  gap; if it is genuinely not worth fixing, that is a decision with an
  argument, written down, not a line item that quietly never moves.
- **A handover** stating what is unmerged, unreleased, unrun and undecided.

## Conventions

- Rust 2021, workspace-level dependency versions, `thiserror` per-crate error
  enums, `anyhow` only in the CLI.
- Keys live in `SecretKey` (zeroize-on-drop); never `Debug`-print key material.
- Git identity for this repo: compufreq <compufreq@proton.me>.
- License: **BUSL-1.1** (source-available; rolling 4-year conversion to
  MPL 2.0; `NOTICE` carries the MemPalace MIT heritage attribution).
  Never reintroduce MIT as the project license or publish under it.
- **Drift check before every release**, not only when something feels off.
  The 65-drift audit found capabilities present on one surface and missing,
  weaker or silently ignored on another — 55 of them failing with no signal
  at all. Re-run it as a fan-out over the same seven dimensions (config
  wiring incl. every `UNDERCROFT_*` variable per surface, write path, search
  path, operational capabilities, error/status classes, audit-chain coverage,
  docs vs code) with an adversarial verifier per dimension. `parity.rs` holds
  the line between audits; the audit is what finds what a fixed inventory
  cannot express.
- Release flow: full Docker battery (always `--build`) → PR → CI green →
  explicit maintainer approval → merge → tag `vX.Y.Z` → `gh release
  create` (the tag also fires release.yml: binaries + GHCR image) →
  post-merge CI green → Pages live-verified. Version bumps touch
  workspace `Cargo.toml` + `Cargo.lock` (via a Docker `cargo update
  --workspace` — battery images COPY source and never update the host
  lock), `.claude-plugin/plugin.json`, CHANGELOG, ROADMAP, and the
  landing hero release button.
