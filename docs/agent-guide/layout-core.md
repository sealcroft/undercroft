# Agent guide — `crates/undercroft-core`

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the Layout entry for
`crates/undercroft-core`: normalization and the retrieval fold, script
segmentation, the hash embedder and its automatic migrations, grounding,
temporal extraction with its calendars, eras and locales, and the model-panic
boundary. Read it when your work touches that crate, or how text is folded,
segmented, embedded or dated.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12). PROPOSED with this split, for the maintainer's approval in its
pull request: this full text governs over any one-line statement of the same
rule in the core. In the moved text, "this file" and "here" mean the guide as
a whole — the core and its reference documents.

---

- `crates/undercroft-core` — domain model, chunking, ids, normalization
  (`normalize.rs`: `NormalizeMode::{Prose,Code}` + `mode_for_path` — code
  and fenced blocks keep indentation/trailing space/blank runs; both modes
  keep the safety floor; `match_key` = NFC **comparison keys only**, never
  applied to stored bytes — the promise is verbatim and NORMALIZE_VERSION is
  inside the drawer id, so folding on the write path would move every future
  id; used by `fingerprint()` — i.e. **dedup**, which is why folding cannot go
  here: `中國` and `中国` must not become one drawer. **No retrieval tokenizer
  folds with it any more** — they fold with `search_key`, whose first
  non-ASCII step is `match_key`, and the date scanner compares its tokens
  through it; neither moves it off NFC, because dedup keys on it), the
  retrieval fold (`search_key` — NFC,
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
  who merely upgraded the binary did not choose a new vector space. One known
  exception, stated in the code beside that table: the Hebrew reclassification
  above moved Hebrew's tokens inside v3 with no v4 row, so a vault already
  holding Hebrew keeps a stale cosine leg until `UNDERCROFT_FORCE_EMBEDDER=1` +
  `repair` — its lexical channels are read live and correct, and the fix is a
  v4 row at 45.9 µs/drawer, filed open as ROADMAP O166. Embeddings
  are not HMAC-covered, so a re-embed never touches a drawer tag or the audit
  chain — which is why this is not a rotation. The walk is batched, idempotent,
  and records the new identity **last**, so a crash mid-walk just repeats it;
  it also drops the PQ/IVF tables, whose codebook quantizes vectors that no
  longer exist. Unreadable rows are **skipped, not fatal** — a walk inside
  `open` that aborts leaves the vault unopenable for `verify` and `repair`
  too, which is worse than a stale vector on a row that already fails every
  read. `UNDERCROFT_FORCE_EMBEDDER=1` is checked **before** the migration
  branch or it would be dead code for the one transition that can fail, and
  `open_read_only` (used by `serve-mcp --read-only` and
  `serve-http --read-only`) warns instead of writing.
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
  token packing (`late.rs`: `LateInteraction`), conversation parsing, entities,
  and the model-panic boundary (`contain.rs`: `contain`, ROADMAP O150 — a
  `catch_unwind` that maps a panic to the caller's own error, truncating the
  payload to 256 bytes on a char boundary; deliberately no counter, since the
  count belongs to the role's degrade arm where `DEGRADE_ARMS` can see it, and
  no panic hook, since a hook is a process global)
