# Undercroft — agent guide

Undercroft is a Rust conversion of MemPalace: hardened, local-first AI memory.
Verbatim drawers filed into wings/rooms, stored in isolated **vaults** with
per-vault HKDF-derived keys, XChaCha20-Poly1305 content sealing, and
HMAC-SHA256 integrity tags + a tamper-evident audit chain.

## Layout

- `Cargo.toml` — workspace root (11 crates; `undercroft-embed-onnx` and
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
  recipient-encrypted export bundles (X25519 ephemeral-static → HKDF →
  XChaCha20-Poly1305) + **signed manifests** (Ed25519 sender attestation
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
  `IRREGULAR` (~110 forms) admit on `lexical_morph`: SHAPE not length, which is
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
  gate-verified 131k→1M; scoped queries pay ~85 ms/q for it, flat). Rejected deliberately: retry-on-empty
  (masks legitimate empties) and post-ranking filters (spend the pool on
  excluded rows — the defect restated). `idx_drawers_room` serves
  room-only resolution; the composite index is leftmost-prefix. A wing's population is MORE
  homogeneous than the vault's, so its codebook fits better, and
  derived-structure scope matches the isolation unit (wing) rather than
  the crypto unit (vault) — a writer in one wing no longer shapes the
  codebook scoring another. Stated honestly: BM25's IDF stays global, so
  the wing isolates candidates, not scores; per-wing generation counters
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
  docs/LABELS.md for the label doctrine it instantiates),
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
  offsets never content; `UNDERCROFT_ADMISSION=quarantine` diverts flagged
  saves sealed into the reserved `quarantine-pending` wing, hard-excluded
  from retrieval except the reviewer's own scope; allow/deny chain-audited
  with the verdict inside the ruling tag; operator surfaces only, never
  MCP; default off = byte-identical write contract),
  provable forgetting (forget.rs — C3.2 phase 1: `forget`/
  `verify-forgetting`, chain-attested destruction with heads + tombstone
  interval + unkeyed content fps; vault-verifiable by keyed replay, third
  parties verify the operator's Ed25519 signature),
  management surface (manage.rs — incl. **deployment-assigned wing trust**:
  `TRUST_VOCAB` closed vocabulary assigned by the operator only, never over
  MCP; HMAC-tagged + audited, flip = integrity failure; consumed as a
  candidate-set floor (`min_trust`/`UNDERCROFT_TRUST_FLOOR`) through the
  scope machinery so a quarantined wing cannot crowd or starve a floored
  query; unassigned = `standard`, explicit wing scope bypasses the vault
  floor, never a request's own),
  remote-index integration (remote.rs — a mirror records the embedder it was
  pushed with; `search_with_index` refuses a mismatch rather than ranking a
  v2 query against v1 vectors, which returned an empty result with no error),
  in-place key rotation
  (rotate.rs: one-transaction re-seal of every artifact + chain re-key
  over preserved audit bytes, crash-reconciled at open), bulk ingest
  (`upsert_many`: one transaction + one manifest anchor per batch —
  advisory encode paths must never BEGIN or batching breaks)
- `crates/undercroft-obs` — observability shim: no-op + **zero deps** by default;
  under `--features telemetry` brings up `tracing` logs, Prometheus `/metrics`,
  OTLP traces (metadata-only spans), and the live SSE broker
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
- `crates/undercroft-cli` — `undercroft` binary (main.rs: CLI; mcp.rs: MCP stdio;
  http.rs/tenant.rs: HTTP + multi-tenant `/v1` incl. management routes
  (drawers list/get/update, taxonomy, verify, rotate, read-only kg
  browse); ui.html: the vault admin console (incl. live MONITOR +
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
  claim must cite), and `xlingual` (cross-lingual R@1/R@5 per language pair
  over operator-supplied TSV pairs — parallel corpora carry their own
  licenses and never enter the repo; the embedder env is the printed
  variable, hash being the measured-zero baseline; a verbatim-recovery
  sanity column guards the harness itself)
- `deploy/observability/` — Prometheus + Alertmanager + Loki + Tempo + Grafana
  stack (see its README.md + RUNBOOK.md)
- `architecture/` — illustrated architecture reference: ten theme-aware
  SVG diagrams (`diagrams/`), the same as PDF (`pdf/`), and `index.html`
  which inlines them and documents every layer plus all 70
  `UNDERCROFT_*` variables. **`diagrams/` is the only source; `pdf/` and
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
  carry the package description)

The upstream Python implementation (the MemPalace project) is *not* in
this repo and no longer linked as a fork; its behavior is documented in
docs/PARITY.md. Never reintroduce Python code here.

## Build & test — Docker only

Build and test **inside containers**, not on the host (project policy):

```bash
docker compose run --rm test          # cargo unit + integration tests (499)
docker compose run --rm lint          # rustfmt --check + clippy -D warnings
docker compose run --rm e2e           # e2e UI/UX suite against the release binary (181 checks)
docker compose run --rm orchestrator-e2e  # two engines + orchestrator (44 checks)
docker compose run --rm e2e-telemetry # telemetry build + /metrics gating (16 checks)
docker compose run --rm backends-e2e  # five live vector DBs (47 checks; weaviate
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
  `a_sealed_vault_exposes_metadata_but_never_content`: wing, room,
  source_file, added_by, hall, content_date, resolved dates. That test fails
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
  weight stays put. Reading dates *inside* the text is the
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
  must verify the record HMAC before returning data.
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
  `false_friends_stay_apart` (store lib.rs) runs 20 known false friends across
  en/de/ar/el end-to-end through `search` at realistic drawer length, asserting
  only the LEXICAL channels (a sem-only hit is the embedder's opinion, not a
  rule's) and failing in BOTH directions — `Verdict::Apart` must not gain a
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
  answer outside HMAC coverage. Codebook k-means is bounded only because
  vectors are L2-normalized before both training and encoding (`pq.rs`): on
  the unit sphere an attacker cannot buy influence with **magnitude**, only
  with **count**, which is what makes an unbounded breakdown point bounded at
  all — so that normalization is a security property, not only a
  distance-ordering one. It is **not** a small displacement bound (every
  centroid is a mean of in-ball points, so "at most the diameter" bounds
  nothing), and one channel stays open: a **NaN/Inf**
  vector from an `external:` embedder, which escapes it entirely. The
  **density** channel (owning fraction *f* bought ≈*f* of any uniform
  sample) is CLOSED at the draw (2026-08-03): `keyed_sample_capped`
  bounds any wing at `1/UNDERCROFT_TRAIN_SOURCE_CAP` (default 4) of every
  global training sample — within-quota corpora byte-identical, soft
  refill never shrinks the sample, deliberately inert below the sampling
  threshold where the per-wing codebook tier is the isolation instead;
  per-WING only, per-writer caps await admission-phase provenance.
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
- Cross-vault access must fail cryptographically (AAD binds vault id), not
  just logically.
- Vault/wing/room names go through `undercroft_core::validate_name` (path
  traversal guard).

## Conventions

- Rust 2021, workspace-level dependency versions, `thiserror` per-crate error
  enums, `anyhow` only in the CLI.
- Keys live in `SecretKey` (zeroize-on-drop); never `Debug`-print key material.
- Git identity for this repo: compufreq <compufreq@proton.me>.
- License: **BUSL-1.1** (source-available; rolling 4-year conversion to
  MPL 2.0; `NOTICE` carries the MemPalace MIT heritage attribution).
  Never reintroduce MIT as the project license or publish under it.
- Release flow: full Docker battery (always `--build`) → PR → CI green →
  explicit maintainer approval → merge → tag `vX.Y.Z` → `gh release
  create` (the tag also fires release.yml: binaries + GHCR image) →
  post-merge CI green → Pages live-verified. Version bumps touch
  workspace `Cargo.toml` + `Cargo.lock` (via a Docker `cargo update
  --workspace` — battery images COPY source and never update the host
  lock), `.claude-plugin/plugin.json`, CHANGELOG, ROADMAP, and the
  landing hero release button.
