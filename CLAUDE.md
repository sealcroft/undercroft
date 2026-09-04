# Undercroft — agent guide

Undercroft is a Rust conversion of MemPalace: hardened, local-first AI memory.
Verbatim drawers filed into wings/rooms, stored in isolated **vaults** with
per-vault HKDF-derived keys, XChaCha20-Poly1305 content sealing, and
HMAC-SHA256 integrity tags + a tamper-evident audit chain.

Published by **Sealcroft** at `github.com/sealcroft/undercroft`, site at
`https://sealcroft.com/undercroft/`, house page at `https://sealcroft.com/`
(repo `sealcroft/sealcroft.github.io`). Current release **1.3.0** — a MINOR
over `1.2.2`, itself a PATCH over `1.2.1` and that a PATCH over `1.2.0`.
MINOR is right by this file's own test: it ADDS a field beside ones that stay
— `VerifyReport.policy_drift`, and a `policy_drift` key on
`POST /v1/…/verify` — and nothing documented stops being accepted. Two
security-relevant changes ride in it and both are worth knowing before an
upgrade. **`verify` gained a SEVENTH leg (O94)**: `wing_trust` and
`retention_policy` are keyed operator declarations that no drawer HMAC and no
chain step covered, so a flipped row failed closed on the retrieval path while
`verify` answered OK, and a DELETED row failed closed NOWHERE — the floor
simply stopped applying. A vault whose policy rows were edited outside the
engine now FAILS verify, and `backup create` gates on that verdict, which is
the point rather than a side effect. And **a request `min_trust` can no longer
lower a deployment's declared floor (O93)**: it won unconditionally, and
`trust_rank("quarantined") == 0` made `trust_clause` return no exclusion at
all, so one search argument lifted the floor corpus-wide from an agent
surface. Raising is untouched; an explicit `wing` scope still bypasses the
vault floor, because that confines the answer rather than lifting the floor.
`UPGRADING.md` carries the first; the second removes a capability nothing
should have relied on. **The tree carries
`1.3.0` only once the release PR merges; the TAG is a separate, explicit
step** — a build reporting a version it was never tagged as is worse
than one reporting the last release. `main` is branch
protected on both repos: force pushes and deletions blocked, admins exempt.
Forking cannot be disabled while the repos are public, and they must stay
public — GitHub Free will not serve Pages from a private repo.

## Who works on this project — the role every agent takes

**Every agent on this project — the session agent and every subagent it
spawns — works as an expert Senior Engineer holding three competencies at
once: Software Engineering, Agentic Memory Architecture and design, and
Security.** Not one of the three in turn, and not a generic coder. This is a
role statement, not a flourish: it is what the work has repeatedly needed and
what its absence has repeatedly cost.

- **Software Engineering** — the change compiles, is tested on both sides of
  its premise, is verified on every surface that reaches it, and leaves no
  second implementation of one decision.
- **Agentic Memory Architecture and design** — reason about **identity,
  lifetime, provenance and traceability BEFORE writing code.** A stored
  memory's value is that a reference to it still resolves later: across a key
  rotation, across a migration, across an export, and across an agent's own
  sessions. For any identifier or index key the question is one line: *what
  holds a reference to this, and what is that reference's lifetime?* The
  worked example is A10 — a rotating key used to derive identifiers, which
  would have orphaned every audit record, receipt and agent-held id at once.
- **Security** — assume the offline reader, the malicious writer and the
  injected drawer. Ask what a gate can **SEE**, not what it asserts: the two
  most expensive defects in this tree were gates measuring an observable the
  defect does not move (a substring scan against a hex digest; a column
  snapshot against a recipe that only moves when next derived).

Consequences that are binding, not advisory:

- **Verify by reading code. A heading, a doc claim, a CHANGELOG bullet and a
  test NAME are not verification** — headings here have been wrong
  repeatedly and are the most expensive artifact this project produces.
- **Report your own defects as your own**, never as discoveries. A fix that
  introduces a hole and reports it as a finding is worse than the hole.
- **Do the impact analysis first**: establish what a change touches and what
  could fail *silently*, plan it, prove it, then present the diff.
- **GROUND THE DECISION BEFORE ACTING — the doctrine is the first place to
  look, not the last.** The order is: read the architecture files and folders,
  read this doctrine, read the code. If they answer the question, **follow
  them** — that is not a decision to narrate, it is the standard, and asking
  about it wastes the maintainer's attention. If they do NOT answer it, do not
  fall back on your own judgement and report afterwards: **write the options
  out with their trade-offs and ask.** The failure this forbids is acting from
  taste and then informing — "I did X, here is why", which hands the
  maintainer a fait accompli dressed as a status update, and which they have
  had to correct.
  The corollary is that "I asked first" is not automatically compliance
  either: an option list assembled without reading the arch files and the code
  is a guess wearing a question mark, and it pushes the grounding work onto
  the person answering. Do the reading, THEN present options — and present
  them only where the reading genuinely ran out.
  Applied backwards, as a rule here must be: it CONFIRMS the drift-direction
  doctrine (provenance decides, and provenance lives in those files), the
  impact-analysis rule above, and O24, whose whole lesson was that reading the
  inventory the command already iterates was all it took. It RECLASSIFIES the
  M9/M10 scoping and the `tls-pins` repair, both of which were chosen and then
  reported rather than grounded and stated. It does not reclassify M6, which
  was put as an explicit option and ruled on — that one is the shape to copy.
- **A gap is a gap** — never dressed up as a principled refusal.
- **A RULE written into this file gets the same scrutiny as code, and the
  test is the same one: apply it backwards.** Before a doctrine lands here,
  run it over decisions the tree has already made and see what it
  reclassifies. If it changes nothing, it is describing what is already done
  — say that, or do not write it. If it changes a lot, the rule is probably
  wrong, and every past decision it overturns owes its own argument.
  This is not hypothetical. A versioning doctrine was written here as *"MAJOR
  carries anything that can stop a deployment which worked before"*, and it
  read as obviously correct. Applied backwards it would have made most of
  this project's past security fixes major releases, and none of them were —
  which is the signal that the RULE was wrong, not the history. The real test
  is a **documented contract** that changes; "a deployment could stop" is a
  different question with a different answer, and conflating them would have
  inflated every future hardening fix into a major. The maintainer caught it,
  not a gate.
  **"It changes nothing" has two meanings and they are opposite.** Either the
  rule describes what the tree already does — fine, say so — or there is no
  history to test it against, which is not validation at all. Applying the
  CORRECTED versioning test backwards returns the second: `1.0.0` is the only
  release under it and it was a version RESET, so nothing before it promised
  an upgrade path. The rule is therefore **untested by history and this
  release is its first real application**, which is a caveat that has to be
  written down rather than mistaken for a pass.
  So: a doctrine is a claim about the tree, and an unverified claim about the
  tree is exactly what the rule above forbids for code. **The reasoning that
  produces a rule fails in the same ways the code does, and it is harder to
  notice because prose does not fail to compile.**
- When fanning out subagents, they inherit this role and the read-only rule
  that goes with parallel work (a shared cargo target dir yields false
  greens; builds and the battery belong to the integrator).

## Layout

- `Cargo.toml` — workspace root (13 crates; `undercroft-embed-onnx` and
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
  scanner (en/ar) and morphology (en/de). For English `-er` admits
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
  2026-08-02). A scope that fits the hydration budget (`max(256,
  depth·32)`) drops the prefilter and is scanned exactly; a larger one
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
  `PalaceStore::accept_filtered_pool` is the one place both arms ask it.
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
  HNSW (hnsw.rs, `hnsw` feature), transactional audit chain (`chain_meta` + `chain_append`),
  verify (**`VerifyReport` is the whole verdict and it has SEVEN legs**: record
  HMACs, the chain replay, drawer supersession receipts, **KG fact
  receipts**, orphan graph labels, mirror drift, **declared-policy drift**.
  The rule that keeps growing
  it: *a keyed claim living in columns no drawer HMAC and no chain step
  covers must have a leg, or nothing sees it.* **The seventh is that rule
  applied one table over (O94)**: `wing_trust` and `retention_policy` are
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
  is the shape this file keeps recording. `PalaceStats` joined it the same
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
  — reported on `PalaceStats.unhealed`, marker withheld, retried. Readers
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
  via `verify_supersessions`; superseding NEVER deletes), whole-palace export/import (typed records: drawers + KG
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
  Two things that unit found and its filing had not: `validate_name(value,
  what)` **discarded `what`** at all 44 call sites, so no refusal anywhere
  in the tree could name its field — the gate was unreachable, not merely
  unmet — and `screen_and_divert`'s doc comment said "both write paths"
  while three callers existed. The reachable door was IMPORT, never save:
  the three save surfaces validate before they reach the store.
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
  parties verify the operator's Ed25519 signature. **The keyed replay has a
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
  inventory entry would),
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
  through. `PalaceStore::record_read` is the ONE place deciding whether a
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
  `audit_export`, one `egress/export` record binding surface + recipient
  + counts + the export's own manifest digest; read-only replicas warn
  and serve; **and `refine` is an egress too, since O79** —
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
  and now says so. The record lives in `refine.rs` — the one
  implementation both surfaces drive — not at each call site, which is
  why the read-only warn-and-serve reaches the CLI as well as `/v1`;
  **reads audited under `UNDERCROFT_READ_AUDIT=chain`** —
  `audit_read` at the search_inner + remote tails covers every path, one
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
  over preserved audit bytes, crash-reconciled at open), bulk ingest
  (`upsert_many`: one transaction + one manifest anchor per batch —
  advisory encode paths must never BEGIN or batching breaks)
- `crates/undercroft-config` — the declaration resolvers the engine and the
  control plane SHARE (`resolve_orch_key`, `resolve_admin_token`,
  `resolve_rate_limit`). Its own crate on `undercroft-net`'s precedent: a
  policy several crates need has one implementation, and when the crates that
  need it cannot link each other it gets a home neither owns. Six surfaces
  including the doctrine promised `undercroft config check` validates every
  `UNDERCROFT_*` declaration; three were not, because their parses sat inside
  `undercroft-orchestrator` — and the first fix attempt narrowed all six
  documents to match the code instead (ROADMAP O24, and **O24a keeps that
  draft**, because what separated right from wrong was not new evidence but
  reading the inventory the command already iterates). **The dependency list
  is the design** — `thiserror` and `hex`, nothing else: both consumers pay
  for whatever lands here, which is why this is not in `undercroft-core`
  (unicode normalization and a calendar library, for three string parses) and
  not in `undercroft-net`, whose domain is transport and which correctly
  keeps the two declaration resolvers that ARE transport (`declared_pin`,
  `declared_endpoint`)
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
  loopback).
  **A third instance landed in an AUDIT RECORD rather than in a gate (O92)**:
  `LlmClient::destination` hand-parsed the authority to strip userinfo,
  ending it at the first `/`, `?` or `#` — and for a special scheme the
  parser also ends it on a backslash, so the refine egress record named
  loopback while the corpus went to an attacker-chosen host, inside an HMAC'd
  canonical. So the rule is wider than a predicate: **anything that must know
  WHICH HOST a request reaches — to gate it, or to write it down — asks the
  parser the transport uses.** Note that the enumerating fix passes review
  easily, because a list of separators looks exhaustive until someone names
  the one missing from it; the durable test is a PROPERTY (this host equals
  the parser's host), never a longer table.
  **A FOURTH instance was the pgvector DSN (O90), and it adds the sharpest
  lesson of the three**: `dsn_is_loopback` scanned for a literal `host=`
  prefix and ended `saw_host || !d.is_empty()`, so a host spelled `hostaddr=`
  or `host = ` (whitespace libpq allows) read as LOOPBACK and skipped a
  cleartext refusal whose own text says *"There is no override"* — pushing
  plaintext-derived embeddings over the network. It had **no test at all**.
  The lesson is about the API you reason against: `postgres::Config` exposes
  `get_hosts()` and NO `get_hostaddrs()`, keeps its inner
  `tokio_postgres::Config` private, and the crate re-exports neither — so the
  key that defeats the guard is **invisible from the surface a guard author
  naturally reads**, and no amount of care with that surface would have found
  it. Ask which type the connector actually builds (`Client::connect` is
  `params.parse::<Config>()?.connect(tls)`) and parse with THAT, even when it
  costs a dependency edge.
  **The policy covers the DECLARATION as well as the client, and for two
  releases it only covered the client** (ROADMAP O82c). `agent_from_env` is
  documented as "the one constructor every hop that reads a `*_CA` variable
  should use" — but a hop that does not speak HTTP cannot use it, and
  pgvector is exactly that: `tokio_postgres_rustls`, which wants a
  `rustls::ClientConfig`. So it read `UNDERCROFT_INDEX_CA` with a bare
  `std::env::var`, and ONE declaration got **two answers across five
  backends** (the other four trim it and refuse a whitespace-only value
  through `declared_pin`) while **re-reading the PEM per construction**,
  which `pin_from_env` caches deliberately because re-reading per call is
  "silent un-pinning by another name" — on `index/status`, the one hop
  reachable per request. `rustls_config_from_env` is the door for a non-`ureq`
  hop; `Pin`'s field stays private, so the policy crate remains the only
  place a `ClientConfig` can be assembled. **Both existing transport gates
  were blind to it by construction**: one scans source for ureq's builder
  token, the other reads a dependency edge out of `Cargo.lock`, and a bare
  `env::var` moves neither — so the third gate matches the READ, which is the
  observable this class actually moves. Fourth instance of *ask what a gate
  can SEE*
- **The OTLP traces hop was the one outbound client that never obeyed any of
  this, and the gate could not see it (round-four #8).** `undercroft-obs`
  built its span exporter on `opentelemetry-otlp`'s `reqwest-blocking-client`
  feature, so it went through a second HTTP library `undercroft-net` knew
  nothing about — no cleartext refusal, no loopback check, no pin — while
  `UNDERCROFT_OTLP_HEADERS` is documented to carry a bearer token and spans
  carry vault ids and route labels. Worse, that feature set linked reqwest
  with **no TLS backend at all**, so `https://` could not work and the
  builder failure was swallowed by an `if let Ok(..)`: no traces, no error.
  The exporter now runs on the policed `ureq` agent through
  `opentelemetry-http`'s `HttpClient` trait, and `UNDERCROFT_OTLP_CA` pins
  its root. **The gate is the lesson**:
  `no_crate_but_undercroft_net_builds_its_own_http_client` scans source for
  ureq's builder token — the observable this defect does not move, since the
  client was somebody else's library. Its sibling
  `no_second_http_client_is_linked_into_the_workspace` reads the DEPENDENCY
  EDGE out of `Cargo.lock` instead, which is why dropping that feature (so
  reqwest leaves the lock entirely) is part of the fix rather than tidying.
  Third instance of *ask what a gate can SEE, not what it asserts.*
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
  the closed-vocabulary signal codes; **since M6 the names travel on every
  level too** — a frame only ever reaches a subscriber that proved per-vault
  authorization, and that same caller reads those names from `/v1/…/stats`,
  so blanking them blinded the owner and withheld nothing from anyone else.
  Offsets and content never travel, which is what the gates pin now. `monitor.html` dispatches on
  `drawer-quarantined`; `website/src/observability.md` documents it.
  **The counter travels with the frame since 2026-08-05 (C11/R5)**: both
  are emitted by ONE function (`PalaceStore::emit_write_event`) off ONE
  `save_event` classification, and `drawer_writes_total` gained a third VALUE on its one
  `outcome` label, `quarantined` (not a third label — the counter has
  exactly one). It used to be a hard-coded
  `WriteOutcome::Created` one line above the branch that decided the
  frame, on all five write arms, so the monitor showed
  `drawer-quarantined` while the counter climbed as `created` — a durable
  signal that was *wrong* rather than missing. Gated by a SOURCE count
  (`write_telemetry_has_exactly_one_emitter`), because the counter is a
  no-op without the telemetry feature and no test that merely drives a
  save could ever have seen it. **The exported series are an INVENTORY,
  and the whole of it is now counted (2026-08-09, ROADMAP O4)**:
  `GAUGE_NAMES` + `COUNTER_NAMES` + `HISTOGRAM_NAMES`, pinned to the emit
  sites by `the_series_inventory_matches_the_emit_sites` (both
  directions), and consumed by two gates that could not exist before it.
  `every_gauge_name_is_registered_and_every_registered_name_is_emitted`
  (in `undercroft-store`, where `CODEBOOK_ARTIFACTS` lives) covers all
  **ten** gauges — it covered the five codebook ones and the other five
  were bare literals in `tenant.rs` with nothing pinning them, i.e. the
  exact arrangement whose first instance shipped five dead names; a gauge
  outside `GAUGE_NAMES` is dropped with no error at any level.
  `every_series_the_deployment_configs_name_is_one_the_binary_exports`
  reads `deploy/observability/` (hence the Dockerfile's `COPY deploy`)
  and is deliberately ONE-directional: every series a config names must
  exist, never the reverse — an alert on a series the binary does not
  export stays `inactive` forever and a panel merely looks empty, and
  nothing in the stack reports either
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
  a read-audit record per `/mcp` search; mcp.rs: MCP stdio — **38 tools (incl. `undercroft_history`, the audit chain
  at `HistoryScope::Agent` — fenced by namespace and by the reserved review
  wing, so a diverted write cannot read its own evidence back), 12
  of them writes** (`index_status` was the thirteenth for one day: it ran
  `ensure`, which CREATES the collection it reports on, so it was never a
  read — and `VectorIndex::status` creates on none of the five backends, so
  it went back to `READ_TOOLS` when O83 closed. Non-creation is proved per
  backend by `backends-e2e`, which asks twice, rather than inferred from
  qdrant) — the read-only gate is `READ_TOOLS` and it FAILS
  CLOSED (`refused_when_read_only` = not-a-read), because
  `WRITE_TOOLS.contains(name)` served any tool nobody had classified yet and
  its compensating parity heuristic was blind to `_merge`, `_move`,
  `_import`, `_forget`, `_prune`, `_promote` and `_sweep`; `/v1`'s `mutates`
  decided the same question the safe way round and this copies it.
  `WRITE_TOOLS` survives `#[cfg(test)]` as the other half of the inventory,
  so an advertised tool in NEITHER list fails the build
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
  admission list/rule, retention set/list/sweep, forget,
  **verify-forgetting** (O14 — the plane could MINT an erasure receipt and
  check none, and on a multi-tenant deployment `/v1` is the only door an
  operator has; the verdict is a TYPED field because `verified` and
  `recorded` make different claims, and a document that does not describe
  this vault is 409 + `class: "integrity"`. It is on the orchestrator's
  `OPS_ROUTES` too, or the fleet operator it was filed for still could not
  reach it), refine, verify,
  rotate, export/import). **`--read-only` is a posture on the whole
  process, decided once in FRONT of dispatch** (`mutates`), not a guard
  per mutating handler: there were thirteen guards for fourteen mutating
  routes and `POST …/kg/authority` never got one, so a read-only server
  rewrote HMAC-covered authority columns, superseded the previous
  canonical holder and appended to the chain while answering 200 — while
  the identical capability over `/mcp` in the same process refused. It
  fails CLOSED (anything not GET is a write unless named), and the
  **three** named exceptions are `POST …/search`, `POST …/verify` and
  `POST …/verify-forgetting` — all POST for cost or for a caller-supplied
  document, never for effect: search reads, verify walks every record's
  HMAC and replays the chain, and verify-forgetting POSTs only because the
  attestation is the CALLER's and has to travel in a body. Failing closed
  means a new read must be NAMED, and the cost of forgetting is a
  read-only server refusing a pure read while the CLI performs it. Verify is a read in the strict sense —
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
  **Every one of those claims is about `open_read_only`, and O91 is what
  that scoping costs (2026-09-02): O81 added a `recorded_embedder` call
  ahead of the posture dispatch, so the FIRST thing `--read-only` did was
  open the database read-write — creating it where it was absent, and
  checkpointing away a crashed writer's hot `-wal` where it was present
  (measured, 41,232 bytes to 0, `palace.db` rewritten). Every sentence
  above stayed true and the posture was still violated, because the
  violation was in a call made BEFORE the function they describe. The only
  A33 test called `open_read_only` directly, so it was blind by
  construction and stayed green over the defect. **A posture is a property
  of the PATH, not of the function at the end of it** — ask what runs
  before the function whose contract you are quoting, and gate the path,
  which is why the ten O91 checks drive `open_store_as` and the two
  surfaces rather than the store call. It
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
  `/healthz` mode+last_write lag surface), and **its own
  `config check`** (`config_check.rs`, O21) — the engine's pre-flight runs
  the ENGINE's resolvers and cannot run another binary's at any price, so a
  fleet runs both. Two properties are load-bearing. Every arm calls the
  resolver `serve` calls, which is what forced `resolve_orch_key` (the hex
  decode was written out twice, in `Orch::open` AND `open_read_only`, neither
  reachable without opening a DATABASE) and `resolve_admin_token` (a length
  floor inline in the `serve` arm) into existence — and that floor was hiding
  a live defect: a trailing newline HAS LENGTH, so `$(cat …)` cleared 16
  characters and produced a control plane that started cleanly and refused
  every `/admin` request forever, HTTP having stripped the trailing
  whitespace from the header the client sent. And `ORCH_ENV_VARS` is counted
  against the CLI's `ENGINE_ENV_VARS` by **reading its source**, name and
  class, both directions — the only route two crates that deliberately do not
  link have. Note that gate's needle must be SPLIT (`concat!`): written
  contiguously it declares a variable called `UNDERCROFT_ORCH_`, the bare
  prefix, which the engine's own env-var inventory gate scans for and
  rejects. One gate's needle is another gate's input.
  **Telemetry since O20**, behind its own `telemetry` feature (a pure `/v1`
  client inherits nothing): four `undercroft_orch_*` counters and a histogram
  for the events no engine can see — a refused tenant token, the rate screen
  firing, a transport refusal that happens before a byte moves, and the
  one-write-becomes-two-calls amplification of the drawer probe. **No
  tenant-shaped label anywhere**, on the per-wing-codebook precedent: an
  identifier whose value set is created BY USE belongs on a query surface, and
  per-tenant figures are already on `/admin/tenants/{id}/stats`. The names are
  `undercroft_orch_`-prefixed because the shipped dashboard aggregates several
  engine series with no `job` filter and the route strings collide exactly.
  **`/metrics` is a SEPARATE listener** (`UNDERCROFT_ORCH_METRICS_ADDR`),
  which is a boundary rather than a drift from the engine: the engine's one
  listener can legitimately be loopback-only, the control plane's cannot be
  because tenants must reach it, so a `/metrics` path there would be
  network-exposed in every real fleet. Loopback needs no token; anything else
  refuses to start without `UNDERCROFT_ORCH_METRICS_TOKEN`.
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
  stack (see its README.md + RUNBOOK.md). **Every rule is aggregated `by
  (instance)` and that is load-bearing, not cosmetic**: Alertmanager's
  inhibition scopes itself with `equal:`, and a label absent from BOTH the
  source and the target counts as EQUAL — so equalling on a label no rule
  emits does not narrow the inhibition, it makes it global. The shipped
  config equalled on `vault`, which nothing emitted (every rule was a
  `sum()`, an `up{}` or a `sum by (le)`), so one critical
  `PalaceTamperDetected` silenced every warning in the fleet for as long
  as it fired, and the only symptom of that class is an alert that never
  arrives. Gated by the `obs-config` suite: `promtool test rules` over
  `alerts_test.yml` asserts the exact label set each rule emits — real
  PromQL evaluation, so it cannot agree with the rules by construction the
  way a second copy of the expressions would — and `tests/obs-config.sh`
  then requires every `equal:` label to be present in all of them, and
  every rule to have a test block. Adding a rule means adding a block
- `deploy/observability/Dockerfile.config-check` — the `obs-config` image:
  `promtool` and `amtool` lifted from the pinned Prometheus/Alertmanager
  images onto debian. Pinning matters — a check that runs a different
  version than the deployment is a check of something else
- `architecture/` — illustrated architecture reference: eleven theme-aware
  SVG diagrams (`diagrams/`), the same as PDF (`pdf/`), and `index.html`
  which inlines them and documents every layer plus **all 81**
  `UNDERCROFT_*` variables the engine honours — **64** written out in
  full across the env table's 60 rows, plus **17** siblings abbreviated
  to a suffix inside the row that owns them (`UNDERCROFT_ORCH_ADDR ·
  _DB · _KEY · _ADMIN_TOKEN · …` is one row; `_TOKENIZER` and `_NAME`
  appear once per model role), which is why grepping the page for full
  names undercounts it by exactly those 17.
  **This paragraph claimed "72 of the 81", "8 abbreviated" and "NINE
  absent" between 2026-08-14 and 2026-08-17, and all three were wrong**
  — ROADMAP **O43**. O38 rewrote a CORRECT line ("all 81", "17
  abbreviated") into a false one and asserted, confidently and in bold,
  that both halves of the original had been wrong. They had not. The
  page was never changed by O38 at all: `git log -- architecture/
  index.html` runs O24 → O20 → O14 → O30 → O32 and then straight to
  2026-08-17, so nothing about its coverage moved in round five.
  **What went wrong is a counting method that could not SEE what it was
  counting.** A bare `<code>_SUFFIX</code>` only tells you which
  variable it means once you attribute it to the ROW it sits in: `_NAME`
  in the ONNX row means `UNDERCROFT_ONNX_NAME` and says nothing about
  `UNDERCROFT_COLBERT_NAME`, which is abbreviated in its own row one
  line below. Count suffixes globally and you credit the wrong
  variables; count only full names and you miss all 17. O38 recognised
  eight of the abbreviations and read the other nine — the six
  `UNDERCROFT_ORCH_*` sharing one row, and the three `_NAME` — as
  absent, then wrote a scoping rationale explaining why they *ought* to
  be absent, which is the most expensive kind of wrong: a wrong
  measurement dressed in a reason. **This figure is now GATED** by the
  `prose figures` preflight, row-scoped, so it is counted rather than
  argued about.
  (77/62/58 until `UNDERCROFT_ORCH_ENGINE_CA` — the CA
  pin for the orchestrator→engine hop, which had no transport policy at
  all until the post-1.0.0 drift audit; 79/64/60 since
  `UNDERCROFT_OTLP_CA`, the pin for the traces hop, which had none
  either and whose exporter could not do TLS at all. Those historical
  figures are left as the record of what was believed at the time.)
  Count the truth,
  never a number in prose:
  `grep -rhoE '"UNDERCROFT_[A-Z0-9_]+"' crates/ | sort -u` over every
  crate except `undercroft-bench`, whose `UNDERCROFT_VS_*`/`UNDERCROFT_TEST_*`
  belong to the harness rather than the engine.
  **`diagrams/` is the only source; `pdf/` and
  the inlined copies are both DERIVED, and `build.sh` regenerates both
  — edit an SVG, re-run it, never hand-edit an inlined copy.** It also
  re-derives every `<h3>` id and the whole sidebar from the sections.
  **This sentence used to end "and fails if a heading and a rail entry
  disagree", and that was FALSE — measured, not argued (ROADMAP M14).**
  The old check stamped a fresh id onto every `<h3>`, collected those same
  ids, built the rail from them, substituted it in, and only THEN re-read
  the ids and the rail refs out of that same rewritten document. Both sides
  came from one list built in one pass, so it could not disagree; its
  protection was the regeneration silently fixing the problem, never the
  check. Proven by running the pre-M14 script's own bytes on a tree with a
  hand-added `<h3>`: **exit 0**, index.html silently rewritten, the heading
  stamped and given a manufactured rail entry. It also wrote the file
  BEFORE comparing, so a firing gate left it already mutated, and it had no
  premise probe — with zero sections both sets are empty and it passed
  having examined nothing.
  **`sh build.sh --check` is the verify half**: it derives everything in
  memory and fails if what is on disk differs, writing nothing at all. It
  runs as the `arch-check` compose service — a stock python image, no build,
  and a READ-ONLY mount so "writes nothing" is enforced rather than claimed
  — in the battery and as a CI matrix leg. Before M14 **nothing invoked this
  script**: no suite, no CI job, no compose service, every mention in the
  tree being prose telling a human to remember. Scope stated: `--check`
  verifies `index.html` and PDF COVERAGE in both directions, never PDF
  bytes, which are not a stable comparison target. librsvg
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
- `architecture/platform-views/` — an **illustrative parallel set** of twelve
  self-contained HTML diagrams (surfaces, crate map, write path, retrieval
  stack, containment/keys, admission, lifecycle, agent session, deployment,
  capability matrix, integrity chain) in the product's own dark palette,
  colour tokens taken from `website/landing/index.html` (verified 2026-08-30:
  same hex values under renamed variables). **The TYPOGRAPHY was never the
  product's**, and that is worth knowing because the sentence above implies
  otherwise: the set shipped on Geist + Instrument Serif from a Google Fonts
  CDN, faces that appear in NO other file in this tree — the landing page and
  the whole vendored set are IBM Plex + GFS Didot. So "vendor them, as O2 did"
  was the wrong repair; it would have added three families the product does
  not use, for an unpublished directory. They are **system stacks** now,
  matching the governed `architecture/index.html` beside them, which is the
  precedent that actually governs a file in this directory (ROADMAP O78).
  **`diagrams/` remains the authority** — this set is a second description of
  the same system. **Its published COUNTS are gated** since 2026-08-31 (ROADMAP
  O74, ruled *depend on the diagrams, they represent the facts we have now*):
  a `platform-views` block in the `prose figures` preflight joins MCP tools,
  MCP writes, `/v1` routes, CLI operations and the crate count to the tree,
  both arms probed. It lives in `tests/battery.sh` and NOT in `check.py`
  because `arch-check` mounts `./architecture` alone, read-only — that checker
  physically cannot see `crates/` and so cannot know what the truth is.
  **What is still bound by attention alone is PROSE**: a relational claim moves
  no count, so a figure gate cannot see it. That is not hypothetical — the
  deployment diagram's `<desc>` said `/ui` sat behind the palace bearer when
  `http.rs` serves it in FRONT of that gate, and the falsehood was in the text
  a screen-reader user gets while the visible label was correct. So a change to
  the engine must still move both sets or they disagree. `index.html` here is the entry point and
  `check.py` is the gate, run by the same `arch-check` service (one service,
  one CI leg): inventory counted in BOTH directions against `index.html`,
  the accessible-SVG contract, **offline assets with NO exception**, LF
  endings, a 9-node /
  2-accent budget, and the geometry rules a renderer would otherwise be needed
  to catch — no diagonal connector, none passing behind a non-endpoint box, no
  label mask painted over by a later node. It carries a **premise probe**: the
  geometry checks must fail on a known-bad fixture before any clean result is
  believed. **`rx` is the discriminator between a node and a zone** (6 vs 8) —
  a first version treated every large stroked rect as a node and reported 96
  breaches across a set whose exemplar had already been verified by eye, which
  is the calibration rule in one line: *a check that flags the artifact you
  confirmed with your own eyes is wrong about the check*
- `website/` — GitHub Pages: `landing/index.html` (custom landing) + mdBook docs
  under `src/`. **`build-site.sh` is the ONE assembly**, run by both
  `pages.yml` and `docker compose run --rm site`; the two used to carry
  their own `cp` lines, so the local preview could not exercise the
  deployed layout — which is the only place the cross-directory paths
  resolve at all. Landing goes to the root and the book to `/docs`, so
  the manual's skin reaches the fonts via `../../assets/fonts/` and the
  404's links resolve only under `book.toml`'s `site-url`
  (`/undercroft/docs/`; unset, mdBook built them as if the book were at
  the domain root, so the one page a lost visitor sees was the one page
  with no stylesheet). **The three font families are vendored**, under
  `landing/assets/fonts/` with their OFL texts — regenerate with
  `tools/vendor-fonts.sh`, which is run BY HAND and never by the build,
  since a build step that fetched fonts would defeat the point. It passes
  every `unicode-range` through unchanged rather than hand-authoring the
  `@font-face` blocks, which is how a vendoring pass silently drops a
  script. **Only the subsets rendered text uses are shipped** — `latin`,
  `greek`, `cyrillic`; the other four are 357 KB nothing needs — and that
  is MEASURED over rendered `.html` only, because a scan that includes the
  vendored scripts finds all seven (`mermaid.min.js` carries Unicode parser
  tables, `mark.min.js` a diacritic map: data inside a script, never glyphs
  a browser paints). `build-site.sh` fails if the assembled site references
  a font CDN at all, and fails if rendered text needs a dropped subset —
  that second check was born broken (a shell-built regex class, `sed` ate
  the backslashes, `2>/dev/null` ate perl's death) and reported a clean
  result having scanned nothing, which is why it now **probes itself
  against a range that must match before its zero-results are believed**.
  The probe then also caught that the site image carries `perl-base`, with
  neither `File::Find` nor `PerlIO`
- `tests/e2e.sh`, `tests/e2e-backends.sh`, `tests/e2e-telemetry.sh`,
  `tests/e2e-orchestrator.sh`, `tests/obs-config.sh` — end-to-end and
  config suites (run in Docker)
- `tests/tls-pins.sh` — every shipped CA pin is READABLE by the identity
  that pins it (ROADMAP M7/M9/M10). **Host-side, not in Docker**, because it
  DRIVES docker: it brings the real Caddy terminators up under throwaway
  compose projects and reads their volumes as the ENGINE's uid, taken from
  the `Dockerfile` so the two cannot drift. Two things it learned the hard
  way are encoded in it: a private project name does **not** scope a
  published PORT (hence `--no-deps`), and its first version ran `down -v` on
  the REAL projects and destroyed a live stack
- `docs/AGENTS.md` — the scenario-driven agent implementation guide
  (published as docs/agents.html); its tool/route/env reference must be
  kept in sync when the MCP surface, `/v1` routes, or `UNDERCROFT_*`
  variables change. **`/v1` is described by TWO documents** — this one's §10
  and `docs/remote-server.md` — and keeping only one is what O45 was: O14
  added a route, updated §10, and left the other reference claiming "All 35
  routes, counted against `route()` … rather than remembered". Both are
  gated now, as SETS in both directions rather than counts, because a count
  passes when one route is swapped for another.
  **The count is gated too, SEPARATELY, and the gap between those two
  sentences was real for as long as only the first existed.** Comparing sets
  is the right choice and its cost is that the SENTENCE introducing the list
  — *"All N routes, counted against `route()` … rather than remembered"* — is
  not part of what the set comparison examines. It said 36 while the list
  under it held 37, from M17 (which added `POST …/repair` to the list and not
  to the sentence) until 2026-08-21, and the gate was green throughout,
  correctly. Generalise it: **a number in prose beside a gated list is the
  un-gated part of a gated claim, and it is the part that rots** — when a
  gate deliberately measures something other than a count, ask what the count
  is doing while nobody watches it.
  **A full-name scan of any reference in this repo UNDERCOUNTS, and the
  undercount reads as a documentation gap.** Every reference here groups
  families into one row and abbreviates the siblings to a suffix —
  `` `undercroft_list_wings` / `_list_rooms` / `_get_taxonomy` `` in the tool
  table, `UNDERCROFT_ORCH_ADDR · _DB · _KEY` on the architecture page,
  "`_KEY` carries a bearer, `_DIM` overrides the dimension" in
  `docs/EMBEDDERS.md`. Three separate sweeps have now "found" phantom gaps
  this way, including O38, which shipped its miscount as a correction. Match
  the suffix form too, or you are measuring the notation rather than the
  coverage
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
- `SECURITY.md` (disclosure policy; private vulnerability reporting is
  enabled on the repo), `NOTICE` (MemPalace MIT heritage attribution),
  `LICENSE` (BUSL 1.1 — see Conventions)
- `.github/workflows/release.yml` — on every `v*` tag: five binary
  targets (linux x86_64/arm64 native, macOS Intel cross-compiled on
  macos-latest + Apple Silicon, windows) uploaded to the release with
  sha256, and the multi-arch `ghcr.io/sealcroft/undercroft` image
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
docker compose run --rm test          # cargo unit + integration tests (798 run,
                                      # 4 #[ignore]d = 802 compiled. Counted from
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
                                      # looked right last time. Pair each target
                                      # HEADER with the result that follows it —
                                      # 20 targets, 12 binaries + 8 doc-tests —
                                      # and treat an orphan as a PREMISE FAILURE,
                                      # since it is the only visible symptom of
                                      # the replay. **`tests/battery.sh` DOES
                                      # this now (O15, closed 2026-08-12)**: its
                                      # `test_summary` pairs headers with results
                                      # and prints a loud PREMISE FAILURE naming
                                      # the orphan count, so a replayed tail is
                                      # reported rather than absorbed. It stays
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
                                      # The 4 ignored are 3 measurements needing
                                      # testdata/*_50k.txt plus one in lib.rs. Run
                                      # them with `cargo test --release -- --ignored`:
                                      # 3 pass, and `measure_relation_promiscuity`
                                      # FAILS on missing data, not on logic — it
                                      # wants ar/el/he word lists and the tree
                                      # carries ar/de/en, so two are simply absent
                                      # (hermitdave/FrequencyWords, MIT, gitignored
                                      # corpora). Verified 2026-08-10. It is not a
                                      # measurement anyone can reproduce here until
                                      # those two lists are fetched; the
                                      # onnx crate's own ignored test is outside
                                      # default-members and never in this count)
docker compose run --rm lint          # rustfmt --check + clippy -D warnings, on the
                                      # default build AND the TELEMETRY build of
                                      # both feature-bearing binaries (O84).
                                      # `--all-targets` alone lints default
                                      # members with DEFAULT features, so
                                      # everything behind
                                      # `#[cfg(feature = "telemetry")]` was linted
                                      # by nothing and two dead wrappers survived
                                      # from O20 and O25. Publishes no check count
                                      # deliberately
docker compose run --rm e2e           # e2e UI/UX suite against the release binary (454 checks)
docker compose run --rm orchestrator-e2e  # two engines + orchestrator (127 checks)
docker compose run --rm e2e-telemetry # telemetry build + /metrics gating (53 checks)
docker compose run --rm backends-e2e  # five live vector DBs over TLS (82 checks; weaviate
                                      # readiness gates on /v1/schema==200 — it
                                      # answers HTTP before its Raft leader exists)
bash tests/tls-pins.sh                # CA pins readable + the stack starts (13 checks).
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
                                      # collision survives untouched
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
docker compose run --rm obs-config    # the observability CONFIG suite (10 checks):
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
docker compose run --rm onnx-build    # compile-check the ONNX embedder+reranker feature
docker compose run --rm ort-build    # compile-check CLI with --features onnx,ort
                                      # (CI clippy never sees non-default features —
                                      # clippy ort-gated code here explicitly)
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
**`bash tests/battery.sh --preflight-only` runs the fourteen host-side preflights
and no suite**, which is what CI invokes. **A count the battery cannot trust is never compared to a published figure, and there are TWO ways to earn that (O97/O103): the suite EXITED NON-ZERO — `cargo test` aborts at the first failing target, so a numeric, replay-free count arrives over a fraction of them — or the reader disowned it with a `PREMISE FAILURE` marker. `count_untrustworthy` is the one place that question is answered, because it used to be answered twice and differently: the cargo arm guarded on the marker, the shell arm stripped it with a trailing `.*`, and neither looked at the exit code. It fails either way — a gate that cannot measure must not report clean — and the verdict names WHICH cause, because the message was written for a replay and told the reader to re-run a failure that was deterministic. (This sentence said "seven" while
the tree ran eight, and nothing could say so — and then "ten" while the tree
ran eleven, which the gate caught inside the very unit that caused it.
It caught the twelfth the same way, in the unit that added it.
**It is gated now** — ROADMAP
**O42** — by the `prose figures` preflight, which counts this number and
seven other figures the doctrine states about the tree against what the tree
actually measures. It caught its own arrival: adding that preflight made the
count ten while this sentence still said nine.) The script is the one thing that
runs on the host rather than in a container, and it has to be: it *drives*
Docker, and the preflights read `ROADMAP.md`, the compose files, `ci.yml` and
`git ls-files --eol` over the WHOLE tree — none of which any image carries.
Everything a preflight cannot do with git, awk and grep belongs in a
container it launches, not in a host interpreter: a gate that needs Python on
the host is a gate that does not run on the next machine.

**`--no-preflight` is the mirror image and it is what CI's SUITE legs use**
(ROADMAP M13). Every matrix leg and the `tls-pins` job run
`bash tests/battery.sh --no-preflight <suite>` rather than
`docker compose run` directly, so CI and a local battery execute the SAME
code — including the post-run comparison of each suite's MEASURED check count
against the figure `CLAUDE.md` publishes for it. That comparison needs a RUN
and therefore cannot be a preflight, so until M13 it ran nowhere on a pull
request and a leg dropping from 370 checks to 3 was green. The flag skips the
fourteen preflights because the dedicated `preflight` job already runs them
once. **The shared readers — `test_summary`, `suite_summary`,
`declare_suite_counts`, `suite_count` — are deliberately defined OUTSIDE the
skipped block**, and that is not tidiness: with them inside, `--no-preflight`
printed `command not found` twice and the battery still exited 0, the
comparison examining nothing while reporting exactly what a clean tree
reports.

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
in BINARY mode on this repo.**

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

**Always pass `--build`.** The battery images COPY the source, they do not
mount it — `docker compose run --rm test` without `--build` silently
re-runs whatever was baked into the last image, so a "green" run can be
testing code you already changed. rustfmt cannot fix host files from those
images either; mount the repo instead:
`docker run --rm -v "<repo>:/src" -w /src rust:1.90-slim-bookworm sh -c "rustup component add rustfmt; cargo fmt --all"`

CI runs `cargo fmt --all --check` + `cargo clippy --all-targets -- -D warnings`
(no `--workspace`, so the excluded onnx crate is fmt'd but not clippy'd in CI),
**plus the same two telemetry-feature clippy runs the `lint` compose service
does** (O84).
**That job runs cargo DIRECTLY, not the compose service, and the two
definitions can disagree** — a fact worth knowing before adding a check to
either. It is not an oversight to route around: the job runs in a
`rust:1.90-slim-bookworm` container with no docker, so it cannot go through
`tests/battery.sh` the way M13 routed the suite legs. It bit immediately —
O84's first fix added the telemetry lint to the compose service alone, which
would have covered every local battery and NO pull request, i.e. exactly what
that entry's own gate requirement forbids. The `lint parity` preflight now
compares the two as SETS of clippy invocations, both directions, with a
premise arm on each extractor.
**Eight compose suites run as a `fail-fast: false` MATRIX** — eight since
`arch-check` joined (M14), and `tls-pins` is host-side and gets its own job
rather than a matrix leg, so CI runs ELEVEN jobs of which the matrix is one.
**The eleventh is `windows-check` (ROADMAP O102), and it exists because
NOTHING here compiled for Windows on a pull request.** `release.yml` builds
that target, and only on a TAG — so a Windows-only compile error was invisible
until the one moment it can no longer be fixed without a new version. `1.2.1`
shipped **16 assets instead of 20** that way: O90's fix named
`tokio_postgres::config::Host::Unix`, a variant that is `#[cfg(unix)]` and
does not exist off unix, and the ten-suite battery plus all seventeen other
CI checks were green because every one of them runs in a Linux container.
It is a `cargo check`, not a build: the class is code that does not COMPILE
for the target, and linking stays `release.yml`'s job. **A target you SHIP is
a target that must be compiled on a pull request** — the same rule as *ask
what a gate can SEE*, applied to the platform axis rather than to an
observable.
The tenth is **`house-figures`** (ROADMAP O65), and it is the ONLY check in
the tree that needs the INTERNET — which is exactly why it is a CI job and
not a `tests/battery.sh` preflight: the preflights run on every local battery
and a network arm there fails for anyone working offline. It reads the house
page's `<div class="n">` tiles and compares them to the tree, and it treats
an unreachable page as a FAILURE rather than a skip, because an unreachable
page and an accurate one must not produce the same verdict — this file's
oldest lesson, and the reason the check exists at all is that the same figure
sat stale for eleven days with nothing able to notice. Consequence, stated
rather than discovered: it can go red on a pull request that touched nothing,
because the house page is state this repo does not own. That is the signal,
not a defect in the gate.
This sentence said "one job each" while also saying the matrix is one job,
which cannot both be true: a matrix expands to one check RUN per leg under a
single job id, which is why adding a leg does not move `verdict`'s `needs:`
and adding a job does. Corrected 2026-08-20; the count was stale too. Two
properties are load-bearing: the legs are independent, so wall-clock is the
slowest suite rather than their sum; and **every suite runs even when one
fails**, where the old serial job stopped at the first failure and hid the
state of the five behind it — a fix then landed blind.
**The verdict is the `verdict` job, published as the context `CI verdict`, and
that is the one context a required status check is configured against.** It
`needs:` every job and inspects every entry of `toJSON(needs)`, so `skipped`
and `cancelled` fail it too; it asserts its own upstream COUNT, so a narrowed
`needs:` fails closed; and `tests/battery.sh`'s CI-inventory preflight counts
the workflow's jobs against that `needs:` in both directions, because a
workflow cannot enumerate its own jobs and the other direction — a new job
nobody wired in — is invisible from inside it.
**Three claims that stood here until 2026-08-10 were false, and the shape of
the error is the lesson.** (1) *"the aggregate is kept under the name `test`
because that is what a required status check resolves against"* — **no repo
had `required_status_checks` at all** (verified against the API on both), so
the rule protected a configuration that did not exist, and the published
context is a job's `name`, which was `Suites (aggregate)` and never `test`,
while the matrix leg published one literally called `test`. (2) *"needs:
suites"* left five jobs outside the verdict. (3) *"named from the same strings
`tests/battery.sh` uses so CI and a local battery cannot drift into different
sets"* — measured, the sets differ in BOTH directions and always have: the
matrix carries `onnx-build` and the battery does not, the battery carries
`lint` and `site` which CI runs as their own jobs, and `ort-build` is a
compose service **run by neither** while `release.yml` ships an `ort` binary
for five targets. Each survived because it was asserted in prose beside the
thing it described and nothing counted it — *a comment is not a gate*, which
is this file's own first rule applied to this file.
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
  **The same failure has a second form, and it cost round-four #7: never
  SUBSTITUTE A CONSTANT for one of the recipe's components.** The admission
  screen derived a diverted drawer's id as
  `drawer_id(QUARANTINE_WING, room, source, chunk)`, which collapses one of
  the four dimensions the recipe is injective over — so two diversions
  differing only in wing derived ONE id and `ON CONFLICT(id) DO UPDATE`
  replaced the first row wholesale, taking its content, its signal codes and
  the `intended_wing` that `admission allow` restores from. `mine ./docs
  --wing team-a` then `--wing team-b` is the ordinary operation that produces
  it. A second id space gets a DOMAIN TAG and keeps every component
  (`ids::quarantine_drawer_id`); the tag is load-bearing, because without it
  the diverted id would equal the id of the very drawer being screened and
  the diversion would overwrite the legitimate row. One shared recipe body
  (`id_over`) so the ordinary id cannot drift, pinned to an INDEPENDENTLY
  derived literal — the refactor's byte-identity was proved by
  re-implementing the recipe in Python and running it, not by observing that
  the tests still passed, which they would have either way. **No migration:
  existing quarantine ids are held by `audit.record_id` for the diversion
  write and by `admission/{id}/{verdict}` for every ruling, so moving a live
  one orphans both — A10 verbatim. The new recipe applies to new diversions
  only, and that is a decision with an argument, not a gap.**
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
- **A search cannot verify its own blind spot. If a sweep matched a pattern,
  a checker built on that same pattern proves nothing.** The 2026-08-08 rename
  replaced three Latin-script spellings of the former name. Three separate
  verifiers then reported the tree clean — because all three searched for
  those same three strings. They agreed with each other by construction, and
  four whole classes sat untouched beneath the agreement:
  1. **A different script.** The former name also existed in Greek capitals,
     which share no byte with the Latin form. It was the first text on the
     landing page, a constant raining the old brand down the hero canvas, and
     the monogram on every documentation page.
  2. **A truncated root.** An identifier used the first five letters as a
     stem. The sweep matched whole words, so it survived — and it named the
     class created inside a user's *live* Weaviate instance.
  3. **An encoding.** A pinned test certificate carried the name inside
     base64-encoded DER, while the comment directly above it asserted the new
     one. A doc claim is not verification, restated as bytes.
  4. **The identity without the spelling.** A mythological epithet named the
     old project precisely and contained none of its letters. No string search
     of any kind could see it.
  5. **The name that is in no file at all** (found 2026-08-10, and it is the
     one that had branded every build artifact for two days). `docker-compose
     .yml` declared no `name:` key, so Compose derived the project name from
     the **DIRECTORY the clone sits in** — still the former name — and
     prefixed every container, image, volume and network with it:
     `<former>-site`, `<former>-lint`, `<former>_default`. It appears in zero
     tracked bytes, so a content scan of all 367 files reports six clean
     classes and is *correct*, and useless. It also silently falsified a doc:
     this file's own volume-mount recipe named an `undercroft_`-prefixed
     volume that did not exist on the maintainer's machine, one sentence
     after warning that a wrong volume name mounts a fresh empty volume with
     no error. **A derived identifier is a name too.** Ask what the tooling
     computes from the environment — directory names, hostnames, image tags,
     registry paths, cache keys — not only what the files say. Gated by the
     compose-project-name preflight in `tests/battery.sh`, counted both ways.
  One layer down, the same shape: **17 historical PDF blobs passed a clean
  `grep`** while still carrying the name inside Flate-compressed content
  streams — invisible to a byte scan, plainly visible to git's own
  `astextplain` textconv and to anyone who opened the file. The maintainer
  found the Greek by *looking at the rendered page*, which is the check nobody
  had run.
  So: any claim that a string is gone must **decompress rather than grep**,
  must cover **non-Latin scripts and truncated roots**, must hunt the
  **identity** as well as the spelling, and must ask what the TOOLING DERIVES
  from the environment. `tests/no-trace/verify.py` covers the **seven** classes
  a file-content scan can reach and fails on any hit. It is **tracked and run by
  a preflight, in a container** since O10 — it was gitignored and hand-run
  before, so a fresh clone did not carry it and nothing invoked it, which is
  how a comment quoting the former name shipped under a green battery. Its
  needles are assembled from fragments so it scans ITSELF clean rather than
  being excluded by path, and a premise probe fires every pattern on a
  known-positive (and requires silence on clean control text) before any zero
  is believed. **The seventh class is a Flate-compressed PDF stream** (O26,
  closed 2026-08-13): the walk inflates every `stream`/`endstream` payload
  whose dictionary declares `/FlateDecode` and runs the same needles over the
  result, counts what it could NOT inflate, and treats a PDF that declares
  `FlateDecode` while yielding no readable stream as a premise failure rather
  than a clean file.
  **How that gap was described is the lesson, and it is this file's own first
  rule turned on a filed item.** O26, this guide, and the commit that created
  the scanner all said it *skipped* `.pdf` via `SKIP_BIN`. The hand-run
  original does. The tracked port dropped `pdf` from that list and nobody read
  the line — so all eleven tracked PDFs were opened in TEXT mode, scanned for
  needles that cannot survive DEFLATE, and **counted in `files scanned`**.
  That is worse than the skip it was filed as: an admitted skip is at least
  visible in the arithmetic, while false coverage reads as a clean result.
  Two general shapes follow. **A gap inherited from a filing is a claim about
  the code and gets the same verification as any other** — three surfaces
  agreed here and all three were describing a different file. And **a coverage
  count must count what was EXAMINED, not what was listed**: the same line
  reported `len(paths)`, skipped entries included, which over-reported by 80.
  Class 5 above is
  **outside its reach by construction** and needs a different mechanism —
  which is the compose preflight, not a wider regex. Do not "extend" the
  verifier to cover it; extend the QUESTION.
  The general rule outlives this rename: **a negative result is only
  as good as the widest question you thought to ask, so "none found" is a
  claim about the method, never about the tree.** Note that writing this
  lesson down is itself the trap — the first draft quoted every string it
  warned about and reintroduced the name into the guide. Describe the class,
  never the token.
- **A SCREEN'S SCOPE MUST MATCH THE SCOPE OF THE READ IT GUARDS, and a screen
  that names the fields it ignores reads as though it covered them.**
  `screen_kg_object` ran the detector on `object` alone and consumed
  `subject`/`predicate` only to build its error message — so the signature
  said "record" while the body said "field", and its doc comment claimed
  "this is the screen on it". The read it stands in front of is
  record-scoped: `kg_query_entity` returns `Triple` and serde serializes it
  WHOLE, so a poisoned subject reached the next session verbatim beside a
  clean object, with `validate_name` the only guard — and that admits any
  128-byte string free of control characters and path separators, which every
  `IMPERATIVE_MARKERS` phrase fits. The scope had been chosen by which field
  someone thought of as content. So: **ask what the READ returns, not what
  the writer considers content**, and make the covered set an INVENTORY
  checked in both directions — a table-driven test proving every listed field
  is screened, plus an assertion inside the screen proving no call site can
  name a field the inventory omits, which is the half a test cannot do
  (O17). **And then the inventory's own NAME chose a second scope, which is
  the same defect one level up (O29, 2026-08-13).** It was
  `KG_SCREENED_FIELDS`, so `tunnels.label` — agent-written through
  `undercroft_create_tunnel`, read back verbatim through
  `undercroft_list_tunnels` — was outside the question it asked, for as long
  as it existed. It is `admission::SCREENED_FIELDS` now, keyed by
  `(owner, field)`, because a key is what lets one inventory span tables and
  a graph-shaped name is what hid the gap. The rule for a row is **an agent
  can write it and an agent can read it back** — never "it is content", which
  is the judgement that scoped O17's own screen to `object`.
  **The sibling sweep is part of the fix, and its WORDING is load-bearing.**
  O29 asked "which other such fields exist *outside `drawers` and the
  graph*?" and the answer was partly INSIDE `drawers`: an agent-chosen WING
  name reaches `taxonomy`, `closets` and `stats` unscreened (filed O32,
  measured). A scoping phrase in a filed question decides what the answer can
  contain, exactly as a scoping phrase in a gate does.
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
  which a hand-maintained doc table cannot do.
  **"Against THE CODE" is the load-bearing half of that sentence, and two
  inventories agreeing with each other is not it** (ROADMAP O80). The
  audit-namespace gate iterated `MINTED` and `AGENT_FENCED_NAMESPACES` and
  compared them to one another while its own docstring claimed it *"counts
  the emitted prefixes"* — so it was both-directional, green, and
  structurally unable to see the one thing it existed for: a namespace the
  code mints and neither list names. Two lists are a closed system; they can
  be perfectly consistent and jointly wrong. Ask, of any inventory gate,
  *which side of this comparison is derived from the code* — and if the
  answer is neither, it is measuring agreement rather than truth. This is
  *ask what a gate can SEE* with the second list mistaken for the tree.
  Applied backwards it reclassifies exactly one gate, the one it was written
  for, and CONFIRMS the rest — `parity.rs` derives its universe from
  `MCP_TOOLS`, `SURFACE_ABSENCES` from `main.rs`'s dispatch, `ReadOp::ALL`
  from audit rows a driver really wrote, `GAUGE_NAMES` from the emit sites,
  `READ_SCHEMA` from the ADD COLUMN lists. One instance, and it is the
  existing rule being SHARPENED rather than a new one: the tree already said
  "against the code" and this is what the phrase costs when it is read
  loosely. Deliberate absences are
  entries in `OPERATOR_ONLY` carrying their reason (an agent must not rule
  on the queue that exists to contain it, nor assign the trust class that
  decides what it may retrieve), asserted by the same test as the parity,
  so the two can never disagree about what MCP is allowed to reach.
  **The CLI axis had no such inventory at all until M16**, so every CLI-only
  capability was an unrecorded gap by construction — measured, **74** CLI
  operations of which `parity.rs` named **17**. `SURFACE_ABSENCES` +
  `SURFACE_COMPLETE` now PARTITION it (62 rows over 59 anchors, plus 15
  reachable everywhere = 74 — this said **63** until 2026-08-30, and the 63rd
  `Absence::` is a COMMENT, which is the identical miscount O68 records having
  already caught one variant down: it corrected `Drift` 22 → 21 and left the
  TOTAL, one line up in the same sentence, still comment-inflated. The `= 74`
  was never wrong, because it derives from ANCHORS plus `SURFACE_COMPLETE` and
  not from rows — which is exactly why nothing noticed. Ungated: the `prose
  figures` preflight counts ten figures and this is not one of them), keyed on
  the `main.rs` dispatch anchor and on
  `(anchor, absent_from)` because a ruling differs per surface — `repair` is
  a boundary on MCP and a drift on `/v1`. **`Absence::Unruled` is a real
  verdict, not a smaller boundary**: where the absence is a PRODUCT decision
  the code does not settle, the row says nobody has decided and must cite the
  entry where it is filed, because an inventory whose reasons were guessed
  reads as ruled while being fiction — worse than none, since it stops the
  next reader looking. Scope, stated: the gate derives its universe from
  `main.rs`, so it is both-directional over the CLI axis only; an absence FROM
  the CLI of something present only on `/v1` (vault delete, the SSE stream) is
  filed in O66 rather than caught.
- **A drift has a DIRECTION, and it is decided by provenance — never by
  which side is cheaper to edit.** Finding that the code and the documents
  disagree is half the work; the other half is deciding which one is wrong,
  and that question has an answer rather than a preference. Ask the three
  places intent is recorded — `ROADMAP.md`, this file's doctrine, and
  `architecture/index.html` — **which one INTRODUCED the thing**:
  - **A new capability** (the ROADMAP files it, or the code adds something
    the documents never promised) → the **code leads**; update every surface
    that describes it, including the ones you did not grep for.
  - **A fix to something already promised** → the **documents lead**, and
    the code must be made to keep the promise. Narrowing a promise to match
    an implementation is how a gap silently becomes the design.
  **The discriminator is breadth, and it is nearly decisive: when a claim is
  consistent across every surface INCLUDING the doctrine, the prior is that
  the CODE is wrong.** Several documents do not independently invent the same
  promise. The worked example is O24 — six surfaces said
  `undercroft config check` validates every `UNDERCROFT_*` declaration, three
  of them were not validated, and the first fix narrowed all six. It was
  backwards, and three things in the tree said so: `ENGINE_ENV_VARS` already
  CONTAINS the six `UNDERCROFT_ORCH_*` entries, `UNDERCROFT_ORCH_ENGINE_CA`
  is already validated by that very command, and the three unvalidated parses
  are pure string→value — so *"never linked by the engine"*, which forbids a
  crate dependency, was used to license something it does not cover. Reading
  the inventory the command already iterates was all it took, and no gate
  caught it; the maintainer did.
  The converse case is real and has its own tell: a claim asserted in ONE
  place, recently, with nothing else agreeing, is a claim to TEST rather than
  a promise to keep — the versioning doctrine is that example, and history
  refuted it. Breadth plus the doctrine means keep; narrow and new means
  question.
  Applied backwards, as a new RULE here must be: it agrees with #40 (a
  detector shipped, the docs went stale, the code led), #54 and #55 (doc
  defects), #18 and O22 (the opaque-payload rule promised the refusal, the
  code was fixed to keep it) and round-four #8 (`undercroft-net`'s own doc
  claimed to be the only implementation; the code was made true). It
  reclassifies exactly one decision — O24's first draft — which is the one it
  was written for. Tested against roughly six decisions, all from this
  campaign; that is its whole history and it is stated rather than implied.
- **An IDENTIFIER is never derived from rotatable key material. Neither is
  a blind-index key. This is not a preference — it is the difference
  between a memory store and a pile of unreferenceable rows.**
  An id in this store is a durable reference held by the **audit chain**
  (`kg/{id}`, `kg-entity/{id}`, drawer ids — and rotation's contract is to
  re-key over PRESERVED audit bytes, so those references must still resolve
  afterwards), by **receipts** (`receipt_canonical` binds the triple id),
  by **supersession links**, by **exports**, and — the one easiest to
  forget — by **agents across sessions**: an agent that learned a fact id
  yesterday must be able to name it today. A moving id is not a rename. It
  silently breaks every one of those at once, and an audit trail whose
  references have moved is not an audit trail. **Traceability is the
  product**; an id is the promise that makes it possible.
  The **blind-index** key is long-lived for a second, independent reason:
  re-keying it means re-indexing the whole corpus, which is why searchable
  encryption separates the index key's lifecycle from the data key's in the
  first place. So: no HKDF-derived vault key (`Vault::tag`, the enc key,
  any of the four) may appear in an id recipe or a blind-index recipe.
  Where confidentiality demands keying — an unkeyed digest over content is
  a confirmation oracle — use a per-vault secret **stored sealed in
  `meta`**, which rotation RE-SEALS and never regenerates.
  The tree already said all of this and it is written here because a
  session did it wrong anyway (A10, 2026-08-05, caught before merge):
  `drawer_id` and the tunnel id are unkeyed deterministic digests;
  the two stored content fingerprints (`supersedes_fp`,
  `kg_triples.source_fp`) must **survive rotation unchanged**, which is
  why U12 keyed them with the STORED `kg_secret` rather than leaving them
  unkeyed (an unkeyed digest of content in a clear column is the oracle
  the sentence above forbids) and rather than with a vault key (which
  would move them). The recipe keys the DIGEST, not the content —
  `HMAC(k, sha256(m))` — so the at-rest migration re-wraps what is
  already stored and never needs the content back, which is what makes a
  legitimately-edited source migrate instead of forcing a choice between
  laundering a `SourceChanged` verdict and stranding the oracle forever.
  `forget.rs`'s attestation fingerprint stays unkeyed on purpose: it is
  signed and verified by a third party WITHOUT the vault key.
  `fingerprint()` is
  keyed but is a LOOKUP key that rotation recomputes, never an identifier;
  `sample_rank` is keyed and deliberately rotation-sensitive because it
  chooses a training sample and nothing holds a reference to it. Before
  changing how any identifier is derived, **enumerate what holds a
  reference to it and state that reference's lifetime** — the impact
  analysis, not the compiler, is what catches this.
  **It is a GATE now, because prose is what failed the first time**
  (`no_durable_reference_moves_on_a_key_rotation`, rotate.rs): every
  durable reference — ids, both blind columns, the content fingerprints,
  every `audit.record_id`, the KG secret's plaintext — snapshotted, rotated,
  required byte-identical, with the keyed lookup keys and receipts required
  to **change** so "nothing moved" cannot also pass for a rotation that did
  nothing. It needed **two arms and the first version had one**: a snapshot
  of the columns PASSED with the original defect reproduced verbatim,
  because rotation deliberately does not re-derive ids — **a moved recipe
  only appears the next time the id is DERIVED**, so the gate re-derives
  every reference after the rotation and requires it to land on the existing
  row. Same trap one level down from the ROADMAP's substring gate: measure
  the observable the defect actually moves, not the one nearby.
  **`audit.record_id` is a LABEL, not evidence, and the difference decides
  what a migration may touch.** The chain hashes `audit.tag` and nothing
  else (`chain_next_hex` takes the tag, `verify` replays tags, rotation
  preserves tags verbatim), so `record_id` sits outside the chain
  arithmetic and outside HMAC coverage. Consequence, learned the hard way in
  A10's own migration: when a re-derivation legitimately MOVES an id, the
  label must follow the row — leaving it both orphaned the audit trail and,
  because a pre-A10 id was an unkeyed digest of the words, **left the
  confirmation oracle in the file that the migration existed to remove**.
  Relabelling moves no evidence; not relabelling moved a reference. Any
  future migration that moves an identifier owes the same remap (one pass,
  inside the transaction, so it is inside the `VACUUM` too) — and note the
  audit table also holds **wing and room names** in clear
  (`trust/{wing}`, `retention/{wing}[/{room}]`, `retention-clear/…`), which
  is scope A10 unit 2 inherits and which its sizing did not list.
- **Rotation completeness is ENFORCED, not remembered.** *Every sealed column
  and every sealed meta value needs a line in `rotate.rs`* was prose and
  failed four times: `terms` (caught by e2e on `export`), then its neighbour
  `name_rest`, then `meta.kg_blind_secret`, then — worst — `wing_trust` and
  `retention_policy`, which were never re-TAGGED at all, so a routine
  rotation made `wing_trusts()` raise `Integrity` forever and took
  `trust_clause` and every floored search with it. Two gates now:
  `rotation_names_every_key_derived_artifact` (source-level, both directions:
  every at-rest AAD domain must be named in `rotate.rs`, every `tag`-carrying
  table must be both SELECTed and UPDATEd there, one justified exemption —
  `audit`, whose tags are preserved verbatim as historical evidence) and the
  `verified` arm of `no_durable_reference_moves_on_a_key_rotation`, which
  calls every reader whose contract is "tag-verified on the way out" after a
  rotation. **A forgotten re-tag is invisible to any snapshot of the
  columns** — the row is byte-identical and simply stops verifying — which is
  why the reader arm exists. Residual, stated: the source gate matches an AAD
  domain's static PREFIX, so it cannot see a wrong *variable* inside the
  domain; only reading rows back covers that. A key rotation also **records
  itself** in the chain now (was A19: the largest single mutation the engine
  performs left no evidence of itself).
- **A clear MIRROR column is safe for a narrowing filter and unsafe for an
  EXCLUSION — so a security decision reads the covered copy, never the
  mirror.** `wing`, `room`, `kind` and `supersedes` are indexed copies of
  values whose authoritative form is inside the HMAC-covered `meta_json`. The
  justification on file was that "the filter itself only ever narrows — a
  forged mirror can hide a row from a kind filter, never smuggle one in".
  True of `kind = 'x'`. **It inverts for `wing <> 'quarantine-pending'`**: one
  offline `UPDATE drawers SET wing = 'notes'` and diverted content stopped
  matching the exclusion, so it was back in `search`, in `recent` (which
  `wake_up` and the closet index call) and in `list_drawers`, while `verify`
  reported clean — the drawer's own HMAC covers `meta_json`, and nothing
  compared the two. The trust floor is a floor rather than a match and inverts
  the same way. This was A28, and it had a working exploit.
  The correct pattern was **already in the tree, twice**: `remote.rs` applies
  the policy off `drawer.meta.wing` after an HMAC-verified load and says why
  ("a mirror can offer any id it likes … so this is the boundary"), and
  `retention.rs` reads the covered `meta.filed_at` rather than the clear
  column. The local read path was the outlier. Now: `verified_meta_admits` is
  the boundary for all three reads (the SQL clause stays as the accelerator —
  it is what keeps poison out of the candidate pool, and "poison cannot crowd
  or starve" is a pre-candidate property), and `VerifyReport.mirror_drift`
  makes a flipped column DETECTED rather than merely ineffective.
  **`filed_at` is deliberately NOT a mirror in this sense** and the first
  version of that check got it wrong: the column takes the write path's own
  `now` while `meta.filed_at` was stamped when the `Drawer` was constructed,
  so they differ by a clock read in normal operation — checking it reported
  eight healthy vaults as tampered. The column is storage metadata; the
  covered field is the declared value, which is exactly why retention reads
  the covered one.
- **A migration's ADD COLUMN list and `READ_SCHEMA` are ONE inventory,
  counted both ways.** The read-only open decides "would I have to migrate
  this?" by checking `READ_SCHEMA`, so a column a writable open adds and that
  list does not name makes the refusal stop firing — the open proceeds and then
  fails on the first query naming the column. A10 did exactly that with
  `kg_triples.terms` and `kg_entities.name_rest`: a read-only open of any
  pre-A10 vault passed the gate and died on every KG read. The three ADD COLUMN
  lists are named constants the initialisers iterate, and
  `read_schema_covers_every_added_column` fails on a new column absent from
  `READ_SCHEMA` **and** on a `READ_SCHEMA` entry nothing adds. The old prose
  count ("twelve `ALTER TABLE`s", while the tree ran fourteen) is deleted in
  favour of naming the inventories.
- **An at-rest migration marks itself complete only when it IS complete.** The
  A10 marker went in with the rows while the `VACUUM` ran after the commit, so
  an interruption between them left "migrated" declared over words still in
  freed pages, and the early return meant nothing retried. A skipped row — one
  whose tag fails, which must not be re-tagged because that would launder it —
  did the same thing permanently. Rule: **write the marker last, only on a
  clean walk, and report what is still pending on `PalaceStats.unhealed`**
  (which is therefore no longer empty on a writable open — two comments said it
  was). Any future at-rest migration owes the same shape, plus the VACUUM and
  the byte-reading gate.
- **A struct is not a surface.** `/v1` serializes report structs whole, so a
  new field reaches the wire for free; the CLI prints named fields one by one
  and silently does not. This has bitten `PalaceStats` and then
  `RotationReport` — the second time inside the very unit that existed to fix
  forgotten sweeps. `parity.rs::HAND_PROJECTED` +
  `every_hand_projected_report_field_reaches_the_cli` now fails when a field
  has no projection, in both directions. Add a hand-projected report to that
  list when you create one.
- Cross-vault access must fail cryptographically (AAD binds vault id), not
  just logically.
- Vault/wing/room names go through `undercroft_core::validate_name` (path
  traversal guard).
- **A guard runs BEFORE any step that rewrites the field it guards, and a
  guard that cannot name the field it refused is half a guard.** Both halves
  are O30 (2026-08-13). The first: `validate_name` sat at the write choke
  point, which is where a guard belongs — but the admission screen ran in
  front of it, and a diversion MOVES the declared wing into `intended_wing`
  and writes the reserved constant in its place. So the guard ran, on a value
  the store had chosen, and reported success over a declaration nothing had
  checked. Placing a guard at the choke point is necessary and not sufficient:
  ask what has *already rewritten* the field by the time it runs. The second:
  `validate_name(value, what)` accepted a field label from all 44 call sites
  and discarded it, so no refusal in the tree could say WHICH name was bad —
  an operator with two declared names got one message for both, and the fix's
  own gate ("a refusal that names the field") was unreachable until the
  parameter was wired up. A parameter that is accepted and dropped is a
  promise the signature makes and the body breaks.
  Applied backwards, as a rule here must be: it **reclassifies exactly one**
  decision, the one it was written for. It **confirms three** that already got
  the order right — `import_stamp` re-stamps `added_by` before the screen
  reads it, `update_drawer` re-stamps for the same reason one level over, and
  `import_unwrap_screened` unwraps a reserved-wing claim before screening. It
  **does not touch A28**, which asks *which copy* a decision reads rather than
  *in what order*, and conflating the two would be the mistake the versioning
  doctrine above records. Four decisions is a thin history and this is the
  rule's first real application; that is stated rather than implied.

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
   **And a passing battery is not evidence a test is DETERMINISTIC — only
   repetition is.** A retrieval test asserting the whole ranked id list over
   1,200 near-identical drawers passed several consecutive batteries and then
   went red on CI; run twelve times it measured 4 failures in 6. The tail of
   that list is not a property of the system: the PQ codebook trains on a
   KEYED sample (`sample_rank`, off a master key that is random per vault),
   so which rows train it differs per run and the ADC ordering moves at the
   margin. **Never assert an exact order over content that ties**; assert the
   one answer the query decisively matches, or a membership the geometry
   cannot move. And when a test touches PQ, FDE, the codebook or any keyed
   draw, **run it in a loop before believing a green** — the battery runs
   each test once, which for a coin flip is not a measurement.
   **And counterfactual the FIX, not only the defect.** A filing makes TWO
   claims — what is broken, and what to do about it — and only the first ever
   gets re-verified, because a remedy that matches an accurate description
   reads as done. ROADMAP M3 is the instance: its description was exact, and
   its prescribed fix ("report the same pair the CLI does") would have made a
   server re-announce one healed anchor window on every later call, forever,
   because the field it names is set at open and never cleared while a server
   caches its handle for its lifetime. The arm that caught it asserts the
   behaviour the FIX would break, which nothing in the filing asks for.
   Stated as this file requires of a new rule: applied backwards it
   reclassifies nothing and confirms nothing — the past fixes it could have
   examined were structural (a required argument, an inventory row) and had
   no alternative shape to get wrong. **One instance, untested by history,
   and this is its first application.**
   **And when a counterfactual fires on only SOME of your checks, the ones
   that stayed green are the finding** — they passed with the defect present,
   so they are measuring something else, and on a clean tree they read
   exactly like coverage. O82a is the worked example: six checks on the SSE
   route's failure reply, of which four drove a request with no bearer — which
   never reaches that route's error arm at all, because the palace bearer gate
   answers it several hundred lines earlier through a helper M43 had already
   fixed. Restoring the defect passed four of six, and the correct reading was
   not "mostly covered" but "four of these test a different gate". The rebuilt
   block drives an unknown VAULT, which authenticates at the door and fails
   inside `authorize`; the challenge check is kept, relabelled and scoped to
   what it does cover, because deleting it would lose a real assertion at a
   call site. So: **a partial counterfactual is a diagnostic, not a partial
   pass** — read every green in it as a claim that needs its own reason. This
   sharpens item 2's existing "cannot pass for the wrong reason" rather than
   adding a rule; applied backwards it reclassifies nothing, because no
   earlier counterfactual in this tree was ever run and found to fire
   partially. One instance, and it is this one.
3. **Drift check.** If the change touches a capability reachable from more
   than one of {CLI, MCP, `/v1`, orchestrator}, verify EVERY one of them —
   by reading the other surfaces' code, not by assuming symmetry. `cargo test`
   runs `parity.rs`, which counts the MCP tool surface against a written
   inventory in both directions and enforces the operator-only boundary; it
   catches an added or removed TOOL, and it cannot catch a capability that
   drifts in behaviour. That half is yours.
4. **Every governance surface updated in the same unit**: CHANGELOG, CLAUDE.md,
   ROADMAP, **the three `.handover/` files** (ignored by git, governance
   nonetheless — see session-end hygiene), **the HOUSE PAGE at
   `sealcroft.com` when a figure it publishes moves**, and whichever of
   docs/AGENTS.md, docs/THREAT_MODEL.md, README, architecture/index.html,
   website/ carry the claim you changed. A claim lives on every surface that
   states it, and an UNCOMMITTED surface is the one nobody notices going
   stale.
   **The house page is the surface this rule keeps failing on, because it is
   in ANOTHER REPOSITORY** (`sealcroft/sealcroft.github.io`, no CI of its
   own) and so is invisible to every in-repo gate and to `git status`. It
   published `656 tests` against a tree running 689, went unfixed for eleven
   days, and had widened to 765 before anything noticed — its sibling defect,
   the house serving cleartext, is what ROADMAP O37 calls "the most severe
   process failure". **It is not optional and not a nice-to-have: it moves
   with the unit that moves the number, exactly like CHANGELOG does.**
   It publishes FOUR figures and only one of them moves often — the test
   count, on nearly every unit that adds a test. The other three (MCP tools,
   the benchmark headline, `0 bytes phoned home`) move rarely or never.
   Dropping the volatile tile to remove that friction was PROPOSED and
   REJECTED by the maintainer: the page is the org's front door, and a front
   door that is quietly wrong is worse than one that costs a commit to keep
   right.
   **Do it with `bash tests/house-figures.sh --update`**, which reads the
   truth from this tree, patches only the tiles that moved, and pushes. Run
   it in the same unit, then verify the LIVE page rather than the commit —
   Pages takes a minute or two, and `--update` waits for it.
   **And run it BEFORE the push, not after.** "Same unit" is not enough,
   because `house-figures` is a CI job that reads the LIVE page: any push
   moving a published figure is red from the moment it lands until the page
   catches up, so pushing first does not risk a red window, it GUARANTEES
   one. Recovery is `--update`, verify live, then `gh run rerun <id>
   --failed` — and check the re-run PER JOB, since `CI verdict` fails
   alongside whatever it was waiting on and a run conclusion alone will not
   tell you which of them was the real one.
   Applied backwards, as a rule here must be: it reclassifies **exactly one**
   decision — the `M37` push on 2026-08-23, which went red for precisely this
   reason — and confirms the obligation above by making it precise rather
   than changing it. Every other unit that day moved landing-page figures the
   house does not publish, so none of them would have been caught. **One
   instance is the whole history this rule has**, and that is stated rather
   than implied: it is a sequencing rule earned from a single observed
   failure, not a pattern established across many.
5. **The full Docker battery** at the final tree, with raw exit codes:
   `test`, `lint`, `obs-config`, `arch-check`, `e2e`, `orchestrator-e2e`,
   `e2e-telemetry`, `backends-e2e`, `site`, `tls-pins`. `cargo build -p <crate>` does **not** compile
   integration tests — `--tests` does. **Every time, never a subset** — and
   never piped: a pipeline's status is its LAST command's, so `| tail` reports
   success over a failing battery. Confirm it ran AFTER the last edit rather
   than assuming; `.battery/*.log` mtimes settle it in one line.
6. **Load a real corpus and drive the change through it.** A fixture proves
   logic and is structurally blind to cost, to schema ordering, and to
   anything that only appears at N > 3. Corpora on hand:
   `.handover/bench-data/` (LoCoMo, LongMemEval), `.handover/locomo_feed.txt`
   (minable), `crates/undercroft-store/testdata/*_50k.txt`,
   `benchmarks/model_eval/datasets/` (10 languages). Mining the LoCoMo feed
   into N wings gives a few thousand real drawers in seconds.
   **This is not belt-and-braces; it is the only thing that caught two
   defects on 2026-08-10, both written minutes earlier and both invisible to a
   green battery**: a `verify` leg issuing one query PER DRAWER against an
   unindexed column (fine on two rows, O(N) with an unindexed inner scan on a
   corpus), and a `CREATE INDEX` placed above its own `CREATE TABLE` in an
   ordered batch, which broke `init` outright — every command dead, and no
   unit test reached that path. Measure the thing you changed: `verify` went
   14→21 ms with deletions unindexed, 13→13 ms with the index.
7. **Count the renderers, not the surfaces.** The drift doctrine names four
   {CLI, MCP, `/v1`, orchestrator}, and that list is not the same as "everything
   that renders this struct". `ui.html` and the orchestrator console are
   `include_str!`'d `/v1` CLIENTS served at `GET /ui`: a new report field
   reaches their wire for free and stops dead. `VerifyReport` gained a leg on
   three gated surfaces and silently missed the fourth — and when `ui.html`
   was finally added to `parity.rs::HAND_PROJECTED`, the entry immediately
   found TWO legs it had never rendered (`orphan_labels`, `mirror_drift`),
   both of which drive the verdict tick it prints. Ask what else reads the
   struct before believing the gate covers it.
   **It happened again, to the struct this rule names first** (ROADMAP M5,
   2026-08-19). The `VerifyReport` row was added and the lesson stopped
   there, so `PalaceStats` — the struct listed above as the FIRST one this
   drift bit — still had no `ui.html` row, and adding one found FOUR fields
   the console had never read, including `unhealed` and `read_only`, the two
   an operator opens a console to find. So the rule is not "add the console
   when you notice"; it is **one row per (struct, renderer) pair, and adding
   a row for one struct says nothing about the next**.
   Two things a gate cannot do for you here. It cannot tell you the page is
   STALE: `ui.html` is compiled in, so a release binary built before the edit
   serves the old console while every gate reads the new source — prove the
   binary carries the markup, then LOOK at the page. And it cannot tell you a
   renderer should be exempt: a fleet OVERVIEW is a summary by construction,
   so demanding every field there would enforce the wrong shape. Write that
   decision down; do not leave it as a missing row.

## Session-end hygiene — leave no debt, drift or stale

Run this before ending a session, and record the result. The rule from the
maintainer: *we don't leave debts or drifts or even stales anywhere in this
project.*

**The working cycle, and the context-budget rule that bounds it.** Work is
**read → fix → test → commit**, one unit at a time, repeating until the queue
is done; the full Docker battery runs at every unit and a real corpus is
loaded at every unit (definition of done, items 5 and 6). **When the context
window reaches roughly 90%, STOP TAKING NEW UNITS and spend what is left
updating every governance surface**
— and **MEASURE that 90%, never estimate it: `bash
tests/context-check.sh`**. This rule was stated for weeks with no way to
evaluate it, so it was applied by feel and applied WRONG, repeatedly and in
one direction: on 2026-08-18 the agent announced it was near the budget at a
measured **54%**, having assumed a 200,000-token window when the real one is
**1,000,000** — every estimate out by ~2.7×, always toward stopping early and
handing over work that could have been finished. A threshold nobody can
measure is not a rule, it is a mood; this file's own first rule — *count the
truth, never a number in prose* — applies to the agent's own state as much as
to the tree. The reader takes the live session transcript's `usage` records
(`input + cache_creation + cache_read`), which is MEASURED; only the window
is declared, it is labelled as such in the output, and it fails loudly rather
than printing 0% when it cannot read a transcript, because a broken reader
and an empty context look identical downstream — CHANGELOG, ROADMAP, this file, whichever
docs carry the claim you changed, and the three `.handover/` files with the
marker re-pointed at `HEAD`.

That is not tidiness, it is arithmetic. A session that spends its last tokens
half-landing one more fix leaves the next session a tree it cannot trust and a
handover describing a different one; a session that spends them on the
handover leaves an accurate map and one clearly-stated next action. The second
is worth more than the fix, because the fix survives being deferred and the
map does not.

**Never half-land a change that alters a security verdict, an on-disk format,
or an id recipe.** File it instead — with its mechanism, the alternatives you
rejected and why, and its gate. ROADMAP `O13` is the worked example: round
four's second CRITICAL, analysed far enough to establish that the fix is a
THIRD verdict state rather than a corrected one, and deliberately left
unwritten because a half-correct verdict is worse than a known-wrong one.

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
- **The handover is a GOVERNANCE SURFACE that is deliberately NOT committed,
  and both halves of that are binding.**
  `.handover/` is gitignored on purpose (`.gitignore:44`, *"local only — never
  committed"*) and **must stay that way**: the directory holds 1.6 GB of
  working material including the 269 MB pre-rename history bundle, and none of
  it belongs in the repo. Do not "fix" this by un-ignoring it or by adding
  negation patterns.
  It is nonetheless a governance surface with the same standing as `ROADMAP`
  or `CHANGELOG`: **kept current in the same unit as the work, and
  drift-checked like everything else.** Three files carry that weight —
  `SESSION_START.md` (the prompt a new session is handed),
  `NEXT_SESSION.md` (project state) and `AUDIT_CONTINUATION.md` (audit
  state). A handover describing a tree that no longer exists is worse than
  none, because the next session acts on it.
  **This paragraph replaces one that said the opposite.** It read "it ships in
  the same commit as the work it describes" — a rule the repo forbids, written
  without checking whether it was satisfiable. The commit that introduced it
  (`a60b342`) is titled "handover: the session-start prompt…" and its diffstat
  is three files, none of them the handover: `git add -A` skips ignored paths
  SILENTLY, the output said "3 files changed", and nobody read which three.
  A doctrine that cannot be obeyed is not a high standard, it is a false
  claim — and this one was asserted in the same commit that added the
  verification doctrine. Gated now by the handover-freshness preflight in
  `tests/battery.sh`, because prose is what failed.
- **Every ROADMAP entry states its own status in its HEADING**, matching its
  body. `O2`'s heading read "the site loads three font families from Google"
  while its own body said CLOSED, and a handover was nearly written around an
  item that did not exist — the "a heading is the most expensive artifact this
  project produces" rule, on the file that plans the work. Gated in
  `tests/battery.sh`'s preflight, host-side beside the line-ending check,
  because no image carries `ROADMAP.md` so no `cargo test` can read it.

## Conventions

- Rust 2021, workspace-level dependency versions, `thiserror` per-crate error
  enums, `anyhow` only in the CLI.
- Keys live in `SecretKey` (zeroize-on-drop); never `Debug`-print key material.
- **Sealcroft is the HOUSE and never ships. Undercroft is this product.**
  Nothing is ever called bare `sealcroft` at the command line, in a crate, in
  an env var or in an MCP tool name — the product word carries the technical
  namespace, the house name carries only the org, the domain and the docs.
  The reason is mechanical, not aesthetic: `sealcroft-core` is ONE global
  crates.io name, so whichever product claims it locks the others out;
  `SEALCROFT_*` is ambiguous on a host running two of them; and **MCP tool
  namespaces are flat per agent**, so two Sealcroft servers collide by name in
  a client that has both. Binding for the planned sibling products (a security
  posture tool and an AI harness): each takes its own one-word namespace under
  `github.com/sealcroft`, exactly as `undercroft`/`UNDERCROFT_*`/
  `undercroft_*`/`undercroft-*` does here.
- **`compufreq` is a PERSON, not the org.** It stays in the LICENSE Licensor
  line, the NOTICE copyright, `Cargo.toml` authors, the git identity and the
  SECURITY contact. Only repository/registry/Pages URLs moved to `sealcroft`.
- Git identity for this repo: compufreq <compufreq@proton.me>.
- License: **BUSL-1.1** (source-available; rolling 4-year conversion to
  MPL 2.0; `NOTICE` carries the MemPalace MIT heritage attribution).
  Never reintroduce MIT as the project license or publish under it.
- **Semantic versioning, and the test for MAJOR is a DOCUMENTED CONTRACT
  that changes — not "a deployment could stop".** Those are different, and
  conflating them inflates a fix release into a major one. MAJOR is a removed
  or renamed surface, an on-disk format that will not open, a default that
  changes what is retrievable, a documented value that stops being accepted.
  MINOR is new capability, backward compatible. PATCH is a fix whose only
  observable change is that a defect is gone.
  **Tightening validation of input that was never documented as valid is a
  FIX, not a break.** A config value that was always a typo, an exit code
  that always contradicted the published doctrine, a refusal the policy
  always stated but enforced one step too late — closing those makes the code
  match the contract, and a deployment that "worked" on the old behaviour was
  running without the protection it declared. Say that plainly rather than
  reaching for a major.
  What such a fix DOES owe is warning: **anything that can stop a running
  deployment gets an `UPGRADING.md` entry in the same unit**, with symptom,
  cause and fix, and `undercroft config check` must be able to detect it
  before a restart. That is the obligation, and it is not the same as a
  version bump. ROADMAP is filed by target release.
- **A declared configuration is classified, and the class decides what a bad
  value does.** `architecture/index.html` states the doctrine — *"every
  default is the conservative choice"*, *"integrity is not a tier"*,
  *"outward paths are explicit"* — and it settles the question one call site
  at a time used to: where the default is already conservative and the
  declaration merely ADJUSTS it, garbage warns and keeps the default, because
  the operator loses tuning and nothing else. Where the DECLARATION is what
  turns a protection on, pins an outward path, or names which vector space a
  vault is in, the default is *off* and a silent fallback removes what was
  asked for — so garbage REFUSES to open. That is "integrity is not a tier"
  extended by one step: a protection an operator declared must not become a
  tier by typo. `parity.rs::ENGINE_ENV_VARS` carries
  `(name, ConfigClass, Parse)` and is counted against the code in both
  directions on BOTH axes, so a new variable does not compile until someone
  classifies it; `undercroft config check` runs every declaration through the
  resolver that will run at start-up, opening nothing, so an upgrade fails in
  a pipeline instead of at a restart.
  **The second axis exists because "I ran no parse" and "there is no parse to
  run" are different claims that READ IDENTICALLY (O52).** `check_one` falls
  to a catch-all rendering an unknown name as `Accepted` — printed as *"no
  parse to run; the consumer validates it"* — which is honest about a path or
  a bearer and a false claim about a knob whose arm somebody forgot. #9
  closed that for `Protects` with an exempt list counted both ways; O48 then
  WIDENED it for `Tunes`, teaching eleven resolvers to validate values the
  pre-flight still described as unvalidated. `Parse::{Checked,Opaque}` is
  declared per variable and counted both ways: a `Checked` one the command
  runs no parse for fails the build, an `Opaque` one that IS pre-flighted
  fails it too. What makes `Checked` affordable is `undercroft-store`'s
  `TUNED` table — every numeric knob's unset value and bounds stated ONCE,
  read by the engine's resolver AND by `check_declaration`, so the two cannot
  report different values. A knob whose unset depends on ANOTHER variable has
  no row and says why (`UNDERCROFT_LATE_TOP_N` falls through to
  `UNDERCROFT_RERANK_TOP_N`, valid or not, which is a compatibility promise).
  49 of the 81 are `Checked`, 32 `Opaque` — counted, not remembered.
  **The class is not the whole rule: a declaration is either a CLOSED
  VOCABULARY or OPAQUE PAYLOAD, and that decides what EMPTY means and whether
  the value may be TRIMMED.** A vocabulary variable (`UNDERCROFT_ADMISSION`)
  may legitimately read empty as a third spelling of its default, and is
  trimmed so a trailing newline from `$(cat …)` or a YAML block scalar cannot
  change its meaning. Payload — `UNDERCROFT_ASSERTION_SECRET`, a CA path, a
  token — has no vocabulary, so empty cannot express intent: it is always a
  failed interpolation and must REFUSE, and it must **not** be trimmed,
  because trimming changes the value itself and for a secret that means
  changing the KEY and silently invalidating every header already minted.
  Nothing encoded this, so each call site answered for itself, and
  `UNDERCROFT_ASSERTION_SECRET` was resolved by `!s.is_empty()` in two inline
  copies that DISAGREED: the minting side (`assert-header`) hard-errored on
  empty while the ENFORCING side read it as "assertions off" and answered 200
  to any bearer on every `/v1` route and `POST /mcp`. That one line also
  failed in **two opposite directions** — `""` turned the boundary off
  silently, and `" "` is not empty so it was accepted as a real one-byte key
  while the banner truthfully reported assertions required. A fix that only
  maps empty to absent closes the first and leaves the second.
  **The rule was written from one instance and there were at least two.**
  `UNDERCROFT_PASSPHRASE` carried the identical `.filter(|p| !p.is_empty())`
  for the whole time the doctrine sat in this file, on a higher-value secret:
  an empty declaration became "no passphrase" and the palace wrote a random
  `master.key` to DISK — the exact opposite of what declaring a passphrase
  asks for, granted silently, reachable through a compose recipe the docs
  shipped. So when a rule like this lands, **grep for the pattern it names
  rather than trusting that the instance which taught it was the only one**;
  `!is_empty()` over a declared secret is a two-minute search and it would
  have found this the same day. Note also the shape of the exemption that
  hid it: a later unit listed the passphrase as unpre-flightable because "a
  passphrase is a credential, not a syntax" — true of a WRONG one, false of
  an ABSENT one. Two questions, one answer, and the wrong one.
  **The sweep was finally run on 2026-08-12 and returned two more**, which is
  the doctrine paying for itself twice: `UNDERCROFT_MCP_HTTP_TOKEN` (a bearer
  gate removed on loopback) and `UNDERCROFT_OTLP_ENDPOINT` — the second inside
  the *previous commit's own* code, wrong in BOTH directions at once, the
  runtime reading empty as "off" while the pre-flight handed the empty string
  to the transport policy, which parses it, fails, and reports an unparseable
  URL as CLEARTEXT. Four instances, one pattern, and the only one anybody
  found by thinking about it was the first.
- **A declaration that CANNOT WORK is refused, never quietly adjusted into one
  that can — and "cannot work" is measured, not reasoned about.** Emptiness is
  not the only way a declared value fails to be one. A bearer ending in
  whitespace is a perfectly good string that **no client can ever present**:
  HTTP strips a header field value's trailing whitespace, so the token that
  arrives is always the trimmed one, and `UNDERCROFT_MCP_HTTP_TOKEN=$(cat
  /run/secrets/token)` over a file ending in a newline starts a healthy server
  that refuses every request forever — 401 naming no cause on one side,
  nothing in the log on the other. The tempting fix is to trim it; that is
  wrong, because it authenticates a key the operator did not declare, and a
  server whose key silently differs from the file it was configured from is
  the whole failure class restated.
  Two disciplines, both earned here. **Measure which spellings actually break
  before writing the guard**: leading and internal whitespace answer 200 and
  trailing whitespace answers 401, so the guard is `trim_end() != value` and
  not `trim() != value` — the wider version would refuse legitimate values in
  the name of a defect they do not have. And **a real corpus is how this class
  is found at all**: every unit test compares a resolver to itself, so no test
  in this tree could see it; the live `serve-http` over 1,360 mined drawers
  that the definition of done demands is what returned the 401. Ask of any
  declared value not only *"can this be empty?"* but *"is there a spelling of
  this that the surface consuming it cannot carry?"*
  Applied backwards, as this file requires of a new RULE: it reclassifies
  nothing and adds one case. The CA pin, the cleartext refusal and the two
  Argon2id/HMAC secrets all keep their current answers — a passphrase or an
  HMAC key with trailing whitespace WORKS, both sides using the same bytes, so
  the rule correctly declines to touch them. Only a value that must survive a
  transport it cannot survive is caught. That is the healthy outcome for a
  doctrine (mostly describes the tree, one genuine addition), and the addition
  is the only history it has: **untested against anything older than itself.**
- **Drift check before every release**, not only when something feels off.
  The 65-drift audit found capabilities present on one surface and missing,
  weaker or silently ignored on another — 55 of them failing with no signal
  at all. Re-run it as a fan-out over the same seven dimensions (config
  wiring incl. every `UNDERCROFT_*` variable per surface, write path, search
  path, operational capabilities, error/status classes, audit-chain coverage,
  docs vs code) with an adversarial verifier per dimension. `parity.rs` holds
  the line between audits; the audit is what finds what a fixed inventory
  cannot express.
- Release flow: full Docker battery (always `--build`) → **`UPGRADING.md`
  updated if anything can stop a running deployment, and `undercroft config
  check` able to detect it** → **set the CHANGELOG and ROADMAP release date
  to the date the tag will actually be cut, as the LAST edit before tagging**
  (it is written when the release is prepared and the tag is a separate,
  later step, so it drifts by exactly as long as the prep sits in review —
  `1.1.0` was prepared on 2026-08-14 and dated that, three days before it
  could be tagged, **and then drifted a second time while still unreleased**,
  which is the argument for making this a step rather than a number someone
  sets once and trusts. A release date is not a fact about the work; it is a
  fact about the tag, and the tag does not exist yet) → PR → CI green →
  explicit maintainer approval → merge → tag `vX.Y.Z` → `gh release
  create` (the tag also fires release.yml: binaries + GHCR image) →
  post-merge CI green → Pages live-verified → **the HOUSE PAGE
  (`sealcroft.com`, a different repo) refreshed and live-verified**, which is
  `bash tests/house-figures.sh --update` for the derivable tiles and a hand
  edit for the two release claims, since those follow the published TAG
  rather than this tree and so can only move after it exists. Its CI job goes
  red until they do, which is the intended order rather than a nuisance.
  Version bumps touch
  workspace `Cargo.toml` + `Cargo.lock` (via a Docker `cargo update
  --workspace` — battery images COPY source and never update the host
  lock), `.claude-plugin/plugin.json`, CHANGELOG, ROADMAP, `CLAUDE.md`'s
  own "Current release" sentence, the landing hero release button, and
  **`architecture/index.html`'s three `Engine v…` strings**.
  **That list is no longer the authority, and this is why.** The `1.0.0`
  release commit moved **five** version-identity strings across **three**
  files, and the list named only ONE of those three (the landing hero) —
  so the `1.1.0` release-prep commit bumped that one and left the other
  two behind, which is what a hand-recalled inventory always does: drift
  toward whatever the last person remembered, with nothing able to say
  so. (Counted from `git show 6976983`, not recalled — an earlier draft
  of this very paragraph said "eight surfaces, four omitted" and was
  wrong in both figures.) The
  authority is the **`version surfaces` preflight** in
  `tests/battery.sh`, which reads the workspace version out of
  `Cargo.toml` (never a literal of its own) and counts every version
  claim in the tree against it, in both directions: a surface that
  forgot to move fails, and a NEW surface with no inventory row fails
  too. Prose above, gate below — and the gate is the one to trust.
  Note it classifies claims, because they do not share a provenance: a
  `current` claim states the version the tree IS, while an **`as-of`**
  claim (`docs/PARITY.md`'s "updated for v…") states when something was
  last VERIFIED and is deliberately NOT bumped by a release — moving it
  would assert a re-verification nobody performed. Re-verify it, then
  move it.
