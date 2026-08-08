# Consultation review — external architecture advice, checked against the code and the measurements

**What this is.** On 2026-07-31 an external AI consultation (Perplexity) reviewed
MemPalace and then proposed a target architecture for Undercroft: a typed
memory-object layer, a provenance graph, an authority ("golden values") tier,
intent-aware retrieval profiles, a Postgres engine mode, and signed portable
bundles. This document is that proposal checked, claim by claim, against what
the codebase actually contains, what this repo has already **measured**, and
the standing invariants. The actionable outcome lives in ROADMAP.md ("The
consultation-filtered track"); this file is the evidence behind it.

**Source quality, stated up front.** The consultation's citation list is
largely content-farm or hallucination-grade (an article announcing that a
film actress launched MemPalace; several domains that do not exist as
described). One substantive source drives nearly every claim. Several
criticisms target the **Python MemPalace** (ChromaDB, its benchmark
methodology, its lack of selective retrieval), not this engine. It knew
nothing of the PQ/FDE/per-wing tiers, the semantic admission gate, the
footprint pricing, receipts and grounding, or any measurement below. Treat it
as directional consultation; treat this document as the record of which
directions survived contact with evidence.

---

## 1. The gap table, verified against the code

The consultation's central table proposed six additions. Verified state
(2026-07-31, branch at the per-wing/pagination work). **This table is a
dated snapshot, deliberately left as it was** — it is the evidence the
adopted track in §7 was decided from, and rewriting it would erase the
reason those four items were chosen. Since then: **memory types**,
**temporal truth** and **golden values** are fully closed;
**provenance** closed on extractor identity, review state and trust class
but not on a multi-edge `derived_from` graph; **sovereign portability**
closed on sender attestation and the scope/trust/expiry manifest but not
on capability-scoped exchange, federation, or the meta-rows export gap;
**retrieval** profiles remain refused on measurement, not missing (§2).
§7 carries the per-item status.

| Area | What the code has (verified) | What is genuinely absent |
|---|---|---|
| Memory types | Drawers, KG triples, diaries, tunnels, hallways. `refine`'s fact-drawers are drawers by *convention* — no schema | No `kind` anywhere. No typed classes (decision, procedure, code_symbol, …) |
| Provenance | `kg_triples`: `confidence`, `source_drawer_id`, `source_fp`, `receipt_tag`, sealed `support` (grounding, with NULL ≠ unsupported) — a one-edge, cryptographically bound provenance link | Extractor identity not recorded; no `review_state`, no trust class, no multi-edge `derived_from` graph |
| Temporal truth | `kg_supersede`, validity windows, timeline — **KG only** | No supersession on drawers or any non-KG object; updates replace in place (audited, not queryable) |
| Retrieval | Hybrid + rerank + ColBERT + PQ/FDE + per-wing tier; declared per-request parameters (`language`, `calendar`, `date_order`, `wing`, `offset`, `ranked_at`, …) | No intent planner, no profiles |
| Sovereign portability | Bundles are recipient-**encrypted** (X25519→HKDF→XChaCha20). Zero signing code in bundle.rs — confidentiality, not sender authenticity | No signature/attestation, no scope/trust/expiry manifest, no capability-scoped exchange, no federation. Export copies no `meta` rows (recorded gap) |
| Golden values | `kg_query(subject, predicate)` is an exact lookup by key | No `authority_class`, no approval state, no canonical-key namespace, no promotion/demotion, no authority-first retrieval path |

Summary: the repo has the **hard substrate** (verbatim + crypto + receipts +
one supersession mechanism + one exact-lookup path + bundle crypto) and
essentially **none of the governance layer**. The substrate is the part that
cannot be retrofitted; the governance layer is additive schema and routes.

## 2. Recommendations this repo has measured — and refuted

Four of the consultation's recommendations have already been run here, with
numbers. They are rejected not on taste but on instruments:

- **Write gating / extraction-first memory.** Measured head-to-head on an
  identical LoCoMo corpus: mem0's extraction rubric (which discards content
  its prompt deems non-memorable) scored **66.9%** against this engine's
  verbatim **94.6%** — a −27.7pp cost paid at write time, unrecoverable at
  read time. Verbatim-first with dedup is the measured winner; extraction
  belongs **on top** (receipts), never **instead**.
- **Budgeted context packing / summarization.** The harness's byte-budget
  row (8,000 B, overlap charged once) measured **+0.3pp** turn all-gold.
  R3 pagination measured **+11.7pp delivered** (74.2% → 85.9% via four
  pages of ten, tiling contract-verified at 0 mismatches in 1,977 queries).
  On this engine, *iteration beats compression*. A packing layer may still
  earn a place someday — but it starts 11pp behind paging and must be
  measured against it.
- **Retrieval profiles that reweight channels by intent.** Every prior
  attempt to be clever with weights measured negative here: RRF fusion
  −7.3pp, `room_cap` diversification −5.6pp, per-query channel rescaling
  −9.4pp. Profiles are adoptable only as **declared** read-time parameters
  (the `language`/`Locale` pattern: one declaration, documented consumers,
  never detected) and only with per-recipe negative controls of the
  `false_friends_stay_apart` class.
- **`token_cost_estimate` as a stored field.** Conflicts with the invariant
  that recomputable derived data is read live, not persisted — the property
  that makes scanner fixes retroactive with no migration. Compute at read.

## 3. Posture decisions the consultation would make by default

Two proposals are not wrong so much as **decisions** — and this repo's
position on both is deliberate:

- **Postgres engine mode with RLS tenancy.** Cross-vault access here fails
  *cryptographically* (per-vault HKDF keys; AAD binds vault id) — an
  invariant, not an implementation detail. RLS is a policy check: exactly
  the logical isolation that invariant exists to reject. The scaling ceiling
  the consultation worries about is real and measured (~30 docs/s per
  sealed vault at 10⁶, fsync- and B-tree-bound), and the architecture's
  answer is horizontal: **the vault is the shard**, the orchestrator routes
  tenants, writes parallelize across vaults. If a shared-Postgres mode ever
  exists it is a *different, weaker trust tier* and must be named as such.
- **Forgetting/pruning policies.** "We don't get rid of data" is a product
  principle, and it survived — but the position moved, and the direction
  it moved in is worth recording. Expiry as **metadata** (a validity
  window that demotes authority at read time) was and is compatible. What
  this review rejected was *deletion workflows*; what C3.2 shipped instead
  is **attested** destruction: `forget` / `verify-forgetting` produce a
  chain-attested receipt (heads + tombstone interval + unkeyed content
  fingerprints) that the vault verifies by keyed replay and a third party
  verifies through the operator's Ed25519 signature. Retention policies
  exist too, per wing/room on the wing-trust pattern — operator-only,
  HMAC-tagged, audited — but enforcement is an **explicit sweep** through
  the same receipted path: nothing expires on a timer, every sweep leaves
  a receipt, and the quarantine wing is refused. The clock is the
  HMAC-covered `meta.filed_at`, tag-verified per drawer, never the clear
  column — otherwise flipping a column could launder a deletion through a
  keyed sweep. The principle that held is not "never delete"; it is
  **never delete silently**.

## 4. Trust granularity: what vault-level actually buys, and the poisoning question

The consultation's per-record `sensitivity`/scope tags prompted the sharpest
question of the review: *if a poisoned drawer is inside the vault, it is
reachable at vault level — does that hurt us?*

The precise answer, now recorded:

- **Sealing proves authenticity, not trustworthiness.** A poisoned drawer is
  authentically sealed poison. The vault boundary separates *principals*,
  not content quality within one principal's vault. The rule the design
  encodes — worth stating wherever vaults are explained — is **one vault =
  one trust domain**. Integrity and identity are already per-record (every
  artifact is its own AEAD unit, AAD-bound to record + domain + vault); only
  the *grant* (keys, access, rotation, revocation) is per-vault, which is
  correct within one trust domain and O(vault) when revoking (untested at
  10⁶ — a known number to get before any compliance claim).
- **What poison cannot do** (the poison-resistance invariant): win anything
  beyond its own slot. Scoring is per-item by design; it cannot re-score,
  suppress, or reorder other drawers, and cannot forge anything at rest.
- **What poison can do — three channels**: (1) win slots on its own merits;
  (2) **crowd** — many distinct poisoned drawers displace legitimate top-k
  entries, plus bounded vault-global IDF drift; (3) **reach the
  reader** — retrieval returns verbatim text into an agent's context, and
  prompt injection is the reader's vulnerability. The engine's contribution
  there is provenance good enough to gate on, which was the trust-class gap.
- **The density channel is closed at the draw (2026-08-03).** The named
  instrument this review recorded as unbuilt now exists:
  `keyed_sample_capped` bounds any single wing to
  `1/UNDERCROFT_TRAIN_SOURCE_CAP` (default 4) of every global codebook
  training sample, with a soft refill so the sample never shrinks, and
  within-quota corpora train byte-identically. It caps per **wing** (the
  adversarial bound, since a wing is a boundary a writer cannot cross by
  declaration) and additionally per **`meta.agent` claim** (the accident
  bound — a runaway agent flooding several wings). Claim-less rows are
  deliberately exempt: "no claim" must not collapse into one giant
  pseudo-agent. Below the sampling threshold the cap is inert, because
  there the per-wing codebook tier *is* the isolation. **Which** rows train
  is also no longer a stride: `stratified_keyed` draws one row per equal
  block of insertion order by a per-vault HKDF `sample` subkey —
  unguessable to a bulk writer, and immune to the periodic-corpus collapse
  a systematic sample suffers (measured R@5 83.0% vs 99.7% on a corpus
  whose period shared a factor with the stride).
- **What the per-wing tier changed (2026-07-31).** Wing-scoped queries now
  draw candidates from the wing's own index and codebook only. Poison in
  another wing can no longer crowd a scoped query's candidate set at all,
  nor shape the codebook that scores it. Pre-tier, wing scoping was a
  filter over globally generated candidates; post-tier, **the wing is an
  enforceable trust zone for scoped retrieval**. Unscoped queries remain
  exposed to crowding and IDF drift — inherent to "search everything".
- **Posture, now that the defense cluster has landed** (C3.3, 2026-08-04):
  differently-trusted principals still → different vaults, and untrusted
  *sources* within one principal's world still → designated wings queried
  scoped — but the wing is no longer only a convention. Trust classes are
  **deployment-assigned** on a closed vocabulary (operator only, never over
  MCP), HMAC-tagged and audited so a column flip fails verification, and
  consumed as a candidate-set *floor* resolved before candidates are drawn,
  so a low-trust wing can neither crowd nor starve a floored query.
  Write-path admission screening diverts flagged content into a reserved
  `quarantine-pending` wing that is hard-excluded from `search`, `recent`
  and `list_drawers`, and that MCP refuses to read or destroy at all — an
  agent must not rule on the queue that contains it. KG facts remain ahead
  of drawers: grounding already refuses a "fact" whose source does not
  contain its words, and receipt verification flags a changed source
  (pinned by test).

## 5. Where the repo already leads the consultation

Claims it made as market gaps that this repo already answers:

- **Benchmarking honesty** — the fairness contract in BENCHMARKS_VS, the
  configuration-beside-every-number rule, counterfactual-verified
  regression tests, retraction of findings that fail repeats. None of the
  systems the consultation compares publishes this discipline.
- **Source freshness revalidation** — exists cryptographically (receipt
  fingerprints flag changed sources); only a scheduled sweep is missing.
- **Retrieval gate vs action gate** — separated by construction: the engine
  retrieves and never acts; `serve-http --read-only` (a posture on the
  whole process, gated in front of dispatch and failing closed), MCP
  write-tool rejection, the MCP quarantine fence, and per-vault assertions
  are the engine-side enforcement points; action gating belongs to the
  agent harness.
- **The five-part memory model** maps nearly one-to-one: drawers =
  episodic/verbatim, KG = semantic, diaries = per-agent episodic, the
  wake-up L0 identity file = identity; working memory is the agent's
  context window, not a store's job. *Procedural* is the one unrepresented
  class — covered by the typed-`kind` adoption item.
- **File-level invalidation** — drawer ids are deterministic over
  (source, chunk_index), so re-mining a changed file replaces its drawers
  idempotently. Symbol-level is not built.
- **The SQLite multi-writer criticism dissolves**: it applies to several
  processes writing one file, a deployment shape this architecture never
  ships (one serving process per vault, sole-writer rotation contract,
  read replicas, orchestrator).

## 6. Gaps the consultation correctly identified (beyond the table)

Confirmed real, most already tracked, now with external confirmation:

- **Read-path auditing — CLOSED 2026-08-04.** The finding was correct: the
  chain covered writes, while reads and exports were observability events
  rather than tamper-evident records. Both halves now append chain records,
  and the split between them is the interesting part.
  **Exports are audited unconditionally, on every surface** (`audit_export`):
  one `egress/export` record binding the surface, the recipient, the record
  counts and the export's own manifest digest. Egress is rare and
  high-value, so it needs no declaration to be worth its cost.
  **Reads are audited under a declaration** (`UNDERCROFT_READ_AUDIT=chain`;
  unset = off): `audit_read` at the `search_inner` and remote tails covers
  every retrieval path with one record per search carrying a **keyed
  fingerprint of the query — never its text** (pinned by a db+WAL byte
  scan), the declared scope and the hit count. A chain append per query is
  a durability cost a sovereign deployment chooses, not one the default
  imposes; garbage in the declaration refuses to open rather than falling
  back, and a read-only open warns and disables (the replica precedent).
  The boundary is stated rather than hidden: read records run behind
  `&self` via `unchecked_transaction` and deliberately do **not** anchor
  the manifest, so they anchor at the next store open — until then a
  stripped unanchored tail is indistinguishable from a crash.
- **Entity resolution.** `kg_entities` is name-unique; no aliasing or merge.
  MemPalace of multi-hop quality.
- **Multi-hop retrieval depth.** Measured weakest category (AMB: multi-hop
  71.9% accuracy, 53.9% gold-recall). Already C2.5 on the roadmap.
- **Large artifacts.** Image *bytes* are a recorded gap (37.9% of LoCoMo
  gold-evidence turns carry captions; captions ingest, bytes do not).
  Posture question attached: sealed *references* + fingerprints to external
  artifacts fit the footprint invariant better than becoming a blob store.
- **Region policy / BYOK-HSM custody.** Orchestrator routes and migrates;
  region-as-policy and managed-cloud key custody are known commercial-track
  items. Confirmed, nothing new.
- **Coding-task memory as typed artifacts** (repo/branch/commit/symbol/API
  contract; commit-aware invalidation beyond file-level). The most
  product-shaped gap of the review; belongs to the queued "memory for
  coding agents" scenario, measure-first.

## 7. The adopted track

Four items survived every filter above. They were ordered so each proves
the pattern the next depends on, and each passes the existing governors
(the metadata-exposure test — every new clear-text field is a deliberate,
inventoried leak; footprint pricing; AGENTS.md surface sync). **All four
have now shipped**; the status line beside each is what the code says, not
what the plan said.

1. **Authority tier on KG facts — shipped.** `authority_class`,
   `review_state`, optional `canonical_key`, declared on closed
   vocabularies and covered by the fact's HMAC through a canonical
   extension on the `support` precedent, so untouched facts keep
   byte-identical canonicals and a column flip without the vault key fails
   verification. `lookup_canonical` is the indexed exact door (`/v1
   .../kg/canonical/{key}` + the MCP tool), at most one active approved
   fact per key, promotion superseding the previous holder under audit.
   Completed the long-queued predicate-lookup item and extended the
   poison-positive philosophy: declared, HMAC-covered truth outranking
   learned similarity.
2. **Extractor identity + generalized supersession — shipped.** Which
   model claimed each distilled fact now lives inside the fact's HMAC via
   a third canonical extension (0x1d, the same precedent), so a flipped
   attribution fails verification. Drawer supersession is receipted:
   `meta.supersedes` under the drawer HMAC, a mirror column, and a keyed
   receipt over the superseded content's unkeyed fingerprint in separate
   columns (the kg `source_fp`/`receipt_tag` shape one level up, re-keyed
   on rotation). Five verdicts via `verify_supersessions`, browsable at
   `GET /v1/vaults/{id}/supersessions` — and superseding never deletes.
3. **Bundle manifests — shipped; one half of the item is still open.**
   Ed25519 sender attestation now sits beside the recipient flow
   (encryption says who may READ, the signature says who WROTE), carrying
   scope, trust claim, expiry, counts and provenance plus an
   unconditionally-checked payload digest; legacy payloads import
   unattested and say so. A sender-declared trust label is a CLAIM, never
   a boundary (docs/LABELS.md). The recipient half went further than
   planned and is now **hybrid post-quantum** (X25519 + ML-KEM-768,
   docs/PQ.md). **Still open**: the meta-rows export gap — export/import
   is per-drawer and copies no `meta` rows, so a migrated vault reports
   codebook generation 0, which reads as "never trained" rather than
   "unknown".
4. **Typed `kind` — shipped**, on the closed vocabulary
   `undercroft_core::KIND_VOCAB`, validated at the single write choke point
   (rejected, never coerced) and absent by default, because absence is
   data and every pre-existing drawer is forever valid without one. It
   lives inside `meta_json` under the drawer HMAC, mirrors to an indexed
   column for the filter, and never enters the drawer id. Its value was
   **measured before it was claimed** (`undercroft-bench tagvalue`): on a
   corpus built to favour it the filter bought *no* recall lift — the
   measured value is latency (90.6 → 13.7 ms/q) and the guarantee class
   (starvation-free scoping, honest empties, a count of unlabeled rows the
   filter excluded). Recorded as the measurement it is rather than the
   recall lever it was assumed to be.

The poisoning-defense cluster (ingest-time trust labels → retrieval
filters, the per-source cap, quarantine-wing enforcement) landed as C3.3
and carries the R1 property from §4; the per-source cap is the density
instrument described there.

Retrieval profiles are **not** on the adopted track; they re-enter only as
declared parameters with per-recipe negative controls (§2).
