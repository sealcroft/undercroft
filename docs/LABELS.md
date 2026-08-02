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
  unreviewed — extractor error would silently unreach content.

## The exposure rule on sealed vaults

A filterable label must be SQL-reachable, which on a sealed vault means one
of exactly two shapes:

1. **Closed-vocabulary enum in the clear** — a deliberate, low-entropy,
   inventoried leak (the `wing`/`room` precedent; the metadata-exposure and
   footprint tests fail until it is accounted for).
2. **Keyed blind index** — truncated HMAC like `fingerprint()`: SQL
   equality with zero leak, no prefix/`LIKE`/range.

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

## What waits, and on what

- **`kind` on drawers** (consultation item 4) waits for its instrument —
  no current benchmark carries kind annotations, and the queue's own rule
  is that the metric is designed before anything runs. Its design is
  already fixed by this document: declared, closed vocabulary, clear-text
  inventoried column, scope-aware filter, unlabeled-rows count in the
  response.
- **Free-form tags** wait for a product case, and ship blind-indexed if
  ever.
- **Trust labels** (ingest-time, deployment-assigned) belong to the C3.3
  defense cluster and build on wing-as-trust-zone.
