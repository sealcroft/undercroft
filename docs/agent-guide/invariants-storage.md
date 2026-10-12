# Agent guide — storage, crypto and integrity invariants

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the full text of the
invariants on drawer ids, sealed vaults at rest, the audit chain, durability,
compression, identifier and blind-index derivation, rotation completeness,
mirror columns, migrations, and guard ordering. Read it when your work touches
what is written to disk, an id or key derivation, the chain, a rotation, a
migration, or a guard on the write path.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12). PROPOSED with this split, for the maintainer's approval in its
pull request: this full text governs over any one-line statement of the same
rule in the core. In the moved text, "this file" and "here" mean the guide as
a whole — the core and its reference documents.

Where the moved text points outside this document: "the mistake the versioning
doctrine above records", in the last invariant, is in the core — the role
section's rule that a RULE written into the guide gets the same scrutiny as
code, whose worked example is that versioning doctrine, and the
semantic-versioning convention.

---

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
  `a_sealed_vault_exposes_metadata_but_never_content` — **sixteen** fields,
  counted from the test's own list, not seven as this line said until
  2026-08-05: wing, room, source_file, added_by, hall, content_date,
  resolved dates, declared `kind`, the `supersedes` link, the
  writer's `agent`/`channel`/`session` claims, and on a review-queue row the
  intended wing and room, the signal codes and offsets, and the keyed
  `queued_against` record. Those four were exposed long before the test
  could see them: its fixture never turned admission on, so no queue row
  existed to measure until O224 wrote two (plus the clear `filed_at`/
  `updated_at` columns and per-record ciphertext sizes, which the pricing
  test's column inventory covers). That test fails
  in **both** directions, so shrinking the exposure forces the inventory to
  be updated. Closing the rest = keyed blind index (truncated HMAC, as
  `fingerprint()` already does) for fields needing SQL equality, sealed blob
  + RAM cache for the rest.
- Every write must update the audit chain **atomically with its data**: the
  committed head lives in `chain_meta` and advances via `chain_append` inside
  the same SQLite transaction (the manifest holds a lagging rollback anchor,
  reconciled at open — crash ⇒ fast-forward, rollback ⇒ tamper). Every read
  must verify the record HMAC before returning data. **Anything that
  REPORTS the chain reads `chain_meta`** (`VaultStore::chain_state`, behind
  `VaultStats.writes`/`chain_head`), never `Vault::writes()` /
  `chain_head_hex()`: those are the handle's own manifest fields, written
  only by its own `anchor_manifest` and never reloaded, so in `serve-http`
  — which held **two handles on one vault** until O242 — the handle that did
  not write reported a frozen height beside a climbing live `drawers` count.
  That aliasing is gone (`serve-http` holds ONE handle, adopted into
  `Tenancy` and borrowed by both surfaces, because the second connection made
  every `/v1` commit look FOREIGN to the `/mcp` label guard and cost a full
  chain replay per search — **+89.5 ms measured, 42 → 131.5 ms**), and the
  rule outlives it: a handle's manifest fields describe what THAT handle
  wrote, so anything reporting the chain still reads `chain_meta`.
- Durability is pinned, not assumed: SQLite runs WAL + `synchronous=FULL`
  on both binaries, the manifest anchor is fsynced through an atomic
  rename (+ dir sync), and key material is fsynced at creation, under a
  temp name that a hard link publishes only once whole (O210). The
  anchor must never run **ahead** of the database — that combination is
  what makes a power loss reconcile as a crash instead of a tamper alarm.
  **And ONE door writes it (ROADMAP O254)**: `VaultStore::anchor()`, the only
  caller of `Vault::anchor_manifest`, takes no head; after the data COMMIT it
  holds SQLite's write lock, reads the committed head, height and keycheck,
  and hands them to a read-modify-write of the MAC-verified `vault.json`
  through a random-nonce `create_new` temp. Every anchor used to write the
  handle's CACHED manifest through one fixed `vault.json.tmp`, so two handles
  collided (a committed write reported failed, measured 27 times in eight
  seconds) and a handle opened before another's rotation wrote the retired
  salt back. A failed anchor never fails the write it follows: I/O is counted
  and covered by the next anchor; integrity (a manifest the handle's keys may
  not overwrite) RETIRES the handle, which then refuses every write at
  `chain_append`. Because the door holds the write lock across two fsyncs,
  the writable connection begins every transaction IMMEDIATE — a DEFERRED one
  that must upgrade is refused SQLITE_BUSY without waiting, and P2 measured
  a second writer failing every write that way.
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
  anywhere new. **And the decode buffer is sized from the frame header,
  never from the bound (O109, 2026-09-06)**: `decompress_frame` handed
  `zstd::bulk::decompress` the 16 MiB content bound as its CAPACITY, which
  that call pre-allocates before decoding a byte, and the store kept the Vec
  as the drawer's content `String` — so every hydrated framed candidate held
  a 16 MiB mapping for the life of the search. Resident memory stayed honest
  (untouched pages); the MAPPING COUNT did not, and a whole-corpus page at
  10⁶ sealed rows reached `vm.max_map_count` (262,145 measured against
  262,144, 8.2 TiB of address space over 5 GB resident) and killed the
  process with 46 GB free — one JSON `offset` from any authenticated caller.
  Found by O23's instrument, which was built to measure a COST and measured
  a crash instead; the lesson is the pqscale one again — a claim about 10⁶
  is settled at 10⁶, and this one had been argued from 10³.
  **The class was then swept tree-wide (O111, 2026-09-07), and a length
  check is a bound only while its arithmetic cannot WRAP**: both quantizer
  decoders checked `data.len() == 9 + m·K·dsub·4` unchecked, release builds
  carry no overflow checks, so a nine-byte blob whose header wrapped that
  product to zero passed the equality and reserved 24 GiB; the v2 token
  header's `dim` was compared with nothing and every caller reserved
  `rows·dim`; the FDE params blob had no ceiling on either side. All three
  are clear and untagged on an hmac-only vault. The doors now: checked
  arithmetic against the blob's own length, `dim == ProductQuantizer::dim`,
  `FdeParams::dim_for`. The same round gave every HTTP body ONE ceiling
  (`undercroft_net::MAX_BODY_BYTES`, 256 MiB): the engine had none and the
  orchestrator truncated to 256 MiB and forwarded the PREFIX, so a tenant
  import one byte over wrote part of its corpus at 200; refuse, never
  truncate, on both listeners, the proxy, and the six outbound reads. And
  O109's own surviving arm — a frame declaring no size — streams under the
  bound now instead of reserving it.
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
  any of the five) may appear in an id recipe or a blind-index recipe.
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
  **REVISED by ROADMAP O233 (2026-09-19), beside rather than in place of the
  paragraph above: a label IS evidence.** The paragraph was true of the chain
  arithmetic and false of the system: O11 (a label's absence is evidence),
  O13 (a recorded run compares labels), O94 and O230 (security verdicts found
  by label) and the forget attestation's mirror disclosure all DECIDE from
  `record_id`, and one relabel plus one deleted row lifted a quarantine floor
  with `verify` green. The version-2 chain step now folds every record's
  label and time, so on a switched chain an in-place `UPDATE audit` is
  exactly the tampering the replay catches, and **a migration that moves an
  identifier may not relabel in place** — it owes a recorded re-chain of its
  own, ruled when one is needed (the next blinding unit, which would move the
  wing names above, is the foreseeable case). A10's relabel was correct when
  made; the switch binds it as found. Applied backwards, the revision
  reclassifies exactly that one decision and confirms O205's standing
  constraint that existing `del/` record ids are never relabelled.
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
  clean walk, and report what is still pending on `VaultStats.unhealed`**
  (which is therefore no longer empty on a writable open — two comments said it
  was). Any future at-rest migration owes the same shape, plus the VACUUM and
  the byte-reading gate.
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
  Applied backwards, as a rule here must be — and **its first application
  was run over the wrong set** (ROADMAP O170, 2026-09-16). This paragraph
  said the rule "reclassifies exactly one decision" and "confirms three",
  having run it over the FIELD O30's filing named, the wing. The step it
  guards rewrites more than the wing: a diversion also replaces `drawer.id`,
  and an allow and an import unwrap re-derive one. Run over every field the
  rewrite touches, it reclassifies **three**: O30's own closure, which left
  the id-shape guard (`4a4ef2c`) and the non-finite guard (`3444da6`), both
  2026-08-05, behind the rewrite that `validate_declaration` (`bea1520`,
  2026-08-13) was added to precede, with the `filed_at` refusal beside them;
  the self-supersession guard, which reproduced O30's deny-only trap through
  a different field; and `import_unwrap_screened`, which confirms the rule
  for the wing and broke it for the id, re-deriving that before any guard
  looked. It still **confirms two** — `import_stamp` re-stamps `added_by`
  before the screen reads it, and `update_drawer` re-stamps for the same
  reason one level over — and still **does not touch A28**, which asks
  *which copy* a decision reads rather than *in what order*, and conflating
  the two would be the mistake the versioning doctrine above records. The
  lesson is the rule's own, one level up: **a backwards test is only as wide
  as the set it is run over, and that set is every field the rewriting step
  touches, never the field a filing names.** Two applications, O30 and O170,
  are its whole history, and the second corrected the first.
