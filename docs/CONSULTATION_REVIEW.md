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
criticisms target the **Python upstream** (ChromaDB, its benchmark
methodology, its lack of selective retrieval), not this engine. It knew
nothing of the PQ/FDE/per-wing tiers, the semantic admission gate, the
footprint pricing, receipts and grounding, or any measurement below. Treat it
as directional consultation; treat this document as the record of which
directions survived contact with evidence.

---

## 1. The gap table, verified against the code

The consultation's central table proposed six additions. Verified state
(2026-07-31, branch at the per-wing/pagination work):

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
  principle. Expiry as **metadata** (a validity window that demotes
  authority at read time) is compatible; deletion workflows are not.
  Deletes exist, are explicit, and leave tombstones in the chain.

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
  entries, the open *density* channel whose named instrument (a per-source
  cap) is unbuilt, plus bounded vault-global IDF drift; (3) **reach the
  reader** — retrieval returns verbatim text into an agent's context, and
  prompt injection is the reader's vulnerability. The engine's contribution
  there is provenance good enough to gate on, which is the trust-class gap.
- **What the per-wing tier changed (2026-07-31).** Wing-scoped queries now
  draw candidates from the wing's own index and codebook only. Poison in
  another wing can no longer crowd a scoped query's candidate set at all,
  nor shape the codebook that scores it. Pre-tier, wing scoping was a
  filter over globally generated candidates; post-tier, **the wing is an
  enforceable trust zone for scoped retrieval**. Unscoped queries remain
  exposed to crowding and IDF drift — inherent to "search everything".
- **Posture until the defense cluster lands**: differently-trusted
  principals → different vaults; untrusted *sources* within one principal's
  world → designated wings, agents query scoped. KG facts are ahead of
  drawers: grounding already refuses a "fact" whose source does not contain
  its words, and receipt verification flags a changed source (pinned by
  test).

## 5. Where the repo already leads the consultation

Claims it made as market gaps that this repo already answers:

- **Benchmarking honesty** — the fairness contract in BENCHMARKS_VS, the
  configuration-beside-every-number rule, counterfactual-verified
  regression tests, retraction of findings that fail repeats. None of the
  systems the consultation compares publishes this discipline.
- **Source freshness revalidation** — exists cryptographically (receipt
  fingerprints flag changed sources); only a scheduled sweep is missing.
- **Retrieval gate vs action gate** — separated by construction: the engine
  retrieves and never acts; `serve --read-only`, MCP write-tool rejection
  and per-vault assertions are the engine-side enforcement points; action
  gating belongs to the agent harness.
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

- **Read-path auditing.** The chain covers writes; reads and exports are
  observability events, not tamper-evident records. A sovereign/compliance
  deployment would want chained read/export audit. New item.
- **Entity resolution.** `kg_entities` is name-unique; no aliasing or merge.
  Upstream of multi-hop quality.
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

Four items survived every filter above. They are ordered so each proves the
pattern the next depends on, and each passes the existing governors (the
metadata-exposure test — every new clear-text field is a deliberate,
inventoried leak; footprint pricing; AGENTS.md surface sync):

1. **Authority tier on KG facts** — `authority_class`, `review_state`,
   optional `canonical_key`; exact-authority route (`/v1` + MCP
   `lookup_canonical`) consulted before semantic recall for exact or
   high-risk asks. Completes the long-queued predicate-lookup item; extends
   the poison-positive philosophy (declared, HMAC-covered truth outranking
   learned similarity).
2. **Extractor identity + generalized supersession** — record which model
   extracted each fact (the embedder-identity pattern, one level up); a
   receipted `supersedes_id` on drawers so update/dedup chains become
   queryable rather than only audited.
3. **Bundle manifests** — sender signature (Ed25519 beside the existing
   X25519 recipient flow) plus a signed manifest carrying scope, trust
   class, expiry, and provenance summary; close the meta-rows export gap at
   the same time. Federation, if ever, starts here — it is meaningless
   without sender attestation.
4. **Typed `kind` + `review_state` on promoted records** — the widest
   schema surface, last, after 1–3 prove the pattern.

The poisoning-defense cluster (ingest-time trust labels → retrieval
filters, the per-source cap, quarantine-wing enforcement) is tracked with
C3.3 and now carries the R1 property from §4.

Retrieval profiles are **not** on the adopted track; they re-enter only as
declared parameters with per-recipe negative controls (§2).
