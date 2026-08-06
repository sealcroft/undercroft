# The labeling doctrine — how labels earn their place here

Written as the resolution of the open discussion pinned in ROADMAP on
2026-07-31 ("labeling as a reachability feature"), and shipped alongside its
first two instances: the golden-values authority tier (this work unit) and
scope-aware candidate generation (the starvation fix). Every future label —
`kind`, tags, trust classes — is designed against this document instead of
re-deriving it.

## The measured pattern, and the rule it implies

Labels used as **scopes, filters and exact keys** have all won here: wing
scoping, `content_date`, declared language, the poison-positive date-filter
design. Labels used as **score modifiers** have all lost: RRF −7.3pp,
`room_cap` −5.6pp, per-query channel rescaling −9.4pp (full rows in
ROADMAP's failed table). The rule:

> **A label may decide who competes. It may never adjust how they score.**

Within one query the order is fixed: the label filter constrains the
candidate set, then the existing calibrated fusion ranks within it,
untouched. "Filter after ranking" is refused — it spends the candidate pool
on rows the caller excluded, which is the starvation defect restated.

## Filters are not free: the starvation obligation

A filter combined with a prefilter inherits the scoped-starvation shape
(the corpus-wide top-k can exclude the scope entirely while the scope holds
the answer — pinned by test for wings, then found live in `room`). Any
label offered as a search filter MUST ride the scope-aware candidate
generation built for the fix: population resolved first through an index,
small scopes scanned exactly, large scopes membership-filtered with the
pool scaled to the scope's own population. A new filterable label is
therefore an index + a scope-resolution entry, never a bare SQL `WHERE`.

Two mechanisms are exempt because no candidate pool exists on their path:
**exact keys** (the `fp` blind index; `lookup_canonical`) — immune to every
crowding and starvation shape by construction — and full scans.

A filter must also declare its **unlabeled-rows policy**. A query filtering
on a label most rows never carried returns near-nothing, silently — the
"silence" the never-guess doctrine forbids. The honest surface reports what
the filter excluded (a count is enough), or the label's design states that
absence is meaningful (as with `wing`/`room`, which every drawer carries).

That obligation now has **two** instances and one implementation. `kind`
reports the in-scope drawers carrying no declared kind; `min_trust`
reports the wings below the floor; both report `None` rather than zero
when the caller set no filter, because "you set no floor" and "your floor
excluded nothing" are different statements. The implementation is shared
(`Exclusions` in the CLI crate, consumed by CLI, MCP and `/v1` alike)
because it was written twice and each copy dropped one leg — `/v1` and
the CLI disclosed the trust count and MCP did not. A policy this document
states once must be *implemented* once too, or the surfaces will disagree
about it.

## Cost is not trust: the two axes

- **Cost tiers, now measured** (`undercroft-bench tagcost`, LoCoMo corpus,
  2026-08-02): declared-by-caller ≈ zero (a field on the write);
  rule-derived = **0.38 µs/drawer — 0.4 s per million** (and read-live
  variants are free at write, which is also what makes scanner fixes
  retroactive); model-derived = **0.19 s/drawer on a served 1B CPU model —
  2.2 days per million, ~5·10⁵× the rule arm** — if it ever exists it is
  **asynchronous enrichment after the verbatim write, never a write gate**
  (write gating measured −27.7pp here, mem0's rubric).
- **Trust tiers are orthogonal.** A declared label is cheap but is still
  only a *claim* by its declarer. Self-scoping needs no trust: a caller
  filtering their own queries by their own labels harms only themselves.
  A label that **outranks other evidence** needs review — which is exactly
  what `review_state` on the authority tier is. A **self-declared label is
  never a trust boundary**: poison declares `kind=decision` as easily as
  anything else. Trust labeling belongs to deployment-assigned facts (which
  wing, which source, at ingest) — controlled by the principal, not by the
  content's author.
- Model-assigned labels are **extractor claims**: they require extractor
  identity and receipts (the KG's receipt pattern, one level up) before any
  surface may filter on them, and they may never feed a hard filter while
  unreviewed — extractor error would silently unreach content. The
  precondition SHIPPED: a KG fact records **which model claimed it**, and
  that identity lives inside the fact's own HMAC (a third canonical
  extension on the support/authority precedent, so untouched facts keep
  byte-identical canonicals), which means a flipped attribution fails
  verification rather than laundering a claim onto a better-trusted
  extractor. No surface filters on it yet; the requirement above is what
  a first one must satisfy.
- A label crossing a **trust boundary in transit** is still only a claim by
  its sender. A signed export bundle's manifest carries a sender-declared
  trust class beside the Ed25519 attestation: the signature proves *who
  wrote it*, never *what it deserves*. The receiving deployment's own
  operator assigns trust on arrival, exactly as at ingest — the same rule
  as below, one machine further away.

## The exposure rule on sealed vaults

A filterable label must be SQL-reachable, which on a sealed vault means one
of exactly two shapes:

1. **Closed-vocabulary enum in the clear** — a deliberate, low-entropy,
   inventoried leak (the `wing`/`room` precedent; the metadata-exposure and
   footprint tests fail until it is accounted for).
2. **Keyed blind index** — truncated HMAC, the *shape* `fingerprint()`
   uses: SQL equality with zero leak, no prefix/`LIKE`/range.

   **Copy the shape, NOT the key.** `fingerprint()` is keyed with the
   vault's rotatable MAC key, which is correct for what it is — a dedup
   LOOKUP key that rotation recomputes and nothing holds a reference to.
   A blind index is not that: re-keying one means re-indexing the corpus,
   and A10 unit 1 shipped a first version keyed with `Vault::tag` that
   would have moved every fact id on every rotation. Use a per-vault
   secret **stored sealed in `meta`**, which rotation re-seals and never
   regenerates (`kg.rs::kg_secret`), and see the CLAUDE.md invariant *an
   identifier is never derived from rotatable key material; neither is a
   blind-index key*. Two riders that unit paid for: any UNKEYED digest of
   the same value elsewhere (an id, a fingerprint) is a confirmation
   oracle that blinding the column does not close, and `audit.record_id`
   carries these values in clear too — it holds `trust/{wing}` and
   `retention/{wing}` today.

Free-form clear-text labels on sealed vaults are **not offerable**: a tag
like `password-rotation-policy` copies content-derived words into unsealed
metadata, which the verbatim-sealing invariant forbids. `canonical_key`
ships in the clear under rule 1's spirit — it is queryable structure like
subject/predicate (the trade the KG header records) and must be named like
an identifier, never with content words that should stay sealed.

## The authority tier, as the doctrine's first instance

`authority_class` + `review_state` + `canonical_key` on KG facts
(consultation adopted item 1) instantiate every rule above:

- All three are **declared** (closed vocabulary, validated, audited through
  the chain) and **HMAC-covered** — a column flip without the vault key
  fails verification, so poison cannot approve itself.
- `lookup_canonical` is the **exact-key door**: an indexed SQL equality,
  answered before semantic recall for exact or high-risk asks, returning at
  most one active approved fact per key or *nothing* — declared truth
  outranking learned similarity, and never a guess. Promotion onto an
  occupied key supersedes the previous holder (audited); history keeps the
  closed fact.
- The tier changes no score anywhere: it is a door beside retrieval, not a
  weight inside it.

## What shipped, and what still waits

- **`kind` on drawers** (consultation item 4) SHIPPED 2026-08-02, exactly
  as this document fixed it: declared closed vocabulary
  (`undercroft_core::KIND_VOCAB`, validated at the single write choke
  point, rejected never coerced), a clear-text inventoried column
  (exposure + footprint tests updated, both directions), the filter
  riding the gate-verified scope machinery (kind-starvation test with a
  raw premise), an unknown filter value erroring instead of silently
  emptying, and the unlabeled-rows count on `/v1`
  (`unlabeled_excluded`, beside `trust_excluded_wings`), MCP and CLI.
  Its **value instrument**
  (`undercroft-bench tagvalue`) shipped with it: R@1/R@5 + wrong-kind@1,
  unfiltered vs filtered, on a corpus built so every key's words live in
  two kinds — the number beside any claim the filter makes.
- **Trust labels** (ingest-time, deployment-assigned) SHIPPED 2026-08-03
  with the C3.3 defense cluster, on wing-as-trust-zone as designed and
  obeying every rule above. `TRUST_VOCAB` is a closed vocabulary
  (`quarantined | standard | trusted`) assigned by the **operator only**
  — CLI and `/v1`, deliberately never MCP, because the surface an agent
  drives must not set the class that decides what it may retrieve. The
  assignment is HMAC-tagged and chain-audited, so a column flip without
  the vault key fails verification and a floored search refuses rather
  than quietly ranking on a forged class. It is consumed as a
  **candidate-set floor** (`min_trust` per request, `UNDERCROFT_TRUST_FLOOR`
  per vault) resolved through the scope machinery before candidates are
  drawn — never a weight — so a quarantined wing can neither answer nor
  crowd a floored query, pinned by a starvation test with a raw premise.
  Unassigned means `standard`; naming a wing explicitly is self-scoping
  and bypasses the *vault* floor, never a request's own `min_trust`. The
  same clause reaches the remote-index path from the one shared policy
  function, so an attached backend is not a route around it.
  A self-declared `kind` remains ergonomics, never a trust boundary.
- The **quarantine wing** is this doctrine's hardest instance: a reserved
  clear-text wing value that *hard-excludes* from every read returning
  content unless the caller names it, and is refused outright on MCP.
  Note what makes that legitimate rather than a silent filter — it is
  operator-declared (`UNDERCROFT_ADMISSION`), the write that lands there
  says so on every surface, and the review queue is an operator surface
  with its own scope. An exclusion nobody can see or opt into would be
  exactly the silence this document forbids.
- **Free-form tags** wait for a product case, and ship blind-indexed if
  ever.
