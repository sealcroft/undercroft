# Threat model — agent memory as an attack surface

This whitepaper formalizes what undercroft's code already implements: the
adversaries it defends against, the mechanism that defeats each one, and
— with equal precision — what it does **not** defend against. It is the
document a security reviewer should be handed alongside
[SECURITY.md](../SECURITY.md) (the disclosure policy and scope list),
the [security model](security.md) (the mechanism reference), and
[SECURITY_COMPARISON.md](SECURITY_COMPARISON.md) (the market context).
Nothing here is aspirational: every defensive claim names the shipping
mechanism, and planned work is labeled as planned.

## 1. Why a memory layer needs a threat model at all

Agent memory crossed from convenience to attack surface in the research
literature well before most memory products acknowledged it:

- **Query-only memory injection** — MINJA
  ([arXiv:2503.03704](https://arxiv.org/abs/2503.03704)) demonstrated
  >95% success poisoning an agent's memory bank using *nothing but
  ordinary queries*: no privileged access, no direct writes. The
  poisoned records then surface to *other users* of the shared memory.
- **Backdoored memory records** — AgentPoison showed optimized records
  planted in a memory store act as retrieval-triggered backdoors:
  specific future queries reliably retrieve the malicious record and
  steer the agent's behavior.
- **Forged reasoning and over-remembering** — 2026 work
  ([arXiv:2607.05029](https://arxiv.org/pdf/2607.05029),
  [arXiv:2607.06595](https://arxiv.org/pdf/2607.06595),
  [arXiv:2601.05504](https://arxiv.org/abs/2601.05504)) extends the
  attack family: forged agent reasoning traces stored as memory,
  poisoning through content an agent was merely *asked to process*, and
  systematic study of defenses. FragFuse
  ([arXiv:2606.15609](https://arxiv.org/pdf/2606.15609)) uses the memory
  layer to *bypass access control* by fragmenting a forbidden query
  across turns and letting memory fuse the answer.

Two properties make memory attacks worse than prompt attacks: they are
**persistent** (one successful poisoning misleads every future session
until discovered) and **transitive** (a store shared across users or
agents spreads the compromise). And the store itself concentrates risk
even absent an active attacker: it holds the most sensitive distillate
of a user's life or an organization's operations, usually — in the
current market — as plaintext with no integrity story.

A memory layer therefore has two distinct security jobs:

1. **Protect what it holds** — from disk theft, tampering, cross-tenant
   bleed, and exfiltration. This is where undercroft's shipped
   cryptography lives, and it is the subject of most of this document.
2. **Be honest about what it was told** — preserve exactly what was
   written, by whom, when, so that poisoning is attributable,
   auditable, and reversible rather than laundered into anonymous
   "facts." This is where verbatim storage is a security property, not
   a retrieval preference (§6), and where the write-path provenance and
   admission work (§8) extends the design.

## 2. System sketch

One machine, local-first, zero external calls by default. Memories are
stored **verbatim** in per-namespace **vaults**. Each vault derives its
own encryption/MAC/manifest keys via HKDF-SHA256 from a master key that
never leaves the machine. In a `sealed` vault (the default), content and
**every plaintext-derived artifact** — embeddings, PQ code rows and
pages, codebooks, ColBERT token matrices, FDE vectors, KG objects — are
encrypted with XChaCha20-Poly1305 before touching disk, each under an
AAD that binds the vault id and the artifact's identity. Every record
carries an HMAC-SHA256 tag verified **before** content is returned, and
every write advances a hash-chained audit log inside the same database
transaction as the data. The mechanism reference with diagrams is the
[security model](security.md); implementation lives in
`crates/undercroft-vault` (keys, sealing, chain arithmetic, export
bundles) and `crates/undercroft-store` (transactional chain, verify,
rotation).

## 3. Adversary classes and what defeats them

Each class states: capability, goal, shipped defense, and residual risk.

### A1 — Offline reader (stolen disk, backup, copied volume)

*Capability*: full read access to the palace directory at rest — every
database, manifest, and derived artifact. No keys, no passphrase.
*Goal*: read memories or anything content-derived.

**Defense (shipped)**: sealed vaults yield **record counts and sizes,
nothing else**. Content is zstd-then-AEAD; embeddings and all index
artifacts are sealed under their own AAD domains; sealed vaults build
no FTS index; duplicate-detection fingerprints are keyed HMACs that
reveal nothing offline. The at-rest bytes are asserted opaque by tests,
and every new derived artifact is required (project invariant) to
follow the same pattern.

**Residual**: at-rest sizes correlate weakly with content
compressibility (standard compress-then-encrypt caveat). Vaults created
as `hmac-only` store plaintext *by explicit operator choice* — the
level exists for grep-ability and is labeled, not a default.

### A2 — Offline tamperer (modify, truncate, or roll back the store)

*Capability*: read–write access to database and manifest at rest.
*Goal*: alter a memory, forge a record, delete evidence, or roll the
palace back to an earlier state without detection.

**Defense (shipped)**: tamper is **detected on read, not merely
resisted**. Any record, KG triple, or tunnel that fails its HMAC
surfaces immediately — a read returns an integrity error, never partial
data. `undercroft verify` audits everything. The audit chain advances
transactionally with each write (`chain_meta` + `chain_append` in the
same SQLite transaction), and the manifest holds a lagging, MAC'd
rollback anchor reconciled at every open: an anchor *behind* the
database head replays as a crash and heals silently; an anchor that is
not in the replayed chain at all is a **rollback alarm**
(`ManifestTampered`). Durability is pinned so the alarm cannot
false-fire: WAL + `synchronous=FULL` guarantee data+chain reach disk
before the anchor can, so power loss lands in the healed case by
construction. Deletions write keyed tombstones — absence is also
evidence.

**Residual (documented)**: an attacker with full disk control who
restores a **consistent old database + manifest pair together** rewinds
the palace to a state that was genuine at the time; the chain cannot
distinguish that from the machine having been off. The planned
mitigation is an external witness (publishing the chain head
off-machine); until then this is stated, not hidden.

### A3 — Cross-tenant adversary (one vault against another)

*Capability*: legitimate access to vault A on a multi-vault host —
including, in the worst case, the ability to move raw blobs between
vault directories.
*Goal*: read or influence vault B.

**Defense (shipped)**: isolation is **cryptographic, not logical**.
Vault keys are independent HKDF derivations; AAD binds the vault id
into every ciphertext, so a blob copied from vault A into vault B
**fails to decrypt** — it is not filtered out by a query predicate that
could have a bug, it is rejected by the cipher. Vault, wing, and room
names pass a path-traversal guard (`validate_name`). This is the
property that makes vault-per-customer multi-tenancy defensible; every
competitor surveyed in [SECURITY_COMPARISON.md](SECURITY_COMPARISON.md)
isolates tenants with a metadata filter.

### A4 — Network adversary (reaching the served surface)

*Capability*: network access to a served palace (HTTP `/v1`, MCP,
orchestrator `/t/*`).
*Goal*: read or write vaults without authorization.

**Defense (shipped)**: two independent layers. A palace-wide bearer is
mandatory for any non-loopback bind and gates every authenticated
route. Optionally (and always, in multi-tenant deployments), every
`/v1` request must additionally carry a per-vault assertion:
`HMAC-SHA256(secret, "<ts>|<vault_id>")` with the **vault id inside the
MAC** — an assertion for vault A cannot address vault B, timestamps
outside ±120 s are refused, comparison is constant-time, and failures
return a bare 401 with the reason only logged server-side (a detailed
error would leak vault existence or forgery proximity). The
orchestrator stores tenant tokens as HMACs and seals engine
credentials; token rotation invalidates the old token fleet-wide on the
next request.

`--read-only` is a **posture on the whole process**, not a filter on
one port. Both stores `serve-http` opens — the `/mcp` handle and every
`/v1` tenant vault — are opened read-only, so no embedder migration
runs and read auditing is force-disabled with a warning rather than
silently. The REST gate sits **in front of dispatch**, not at the top
of each mutating handler, and it **fails closed**: every non-GET is
refused unless it is on a two-entry allowlist (`POST …/search`, and
`POST …/verify` — which only fast-forwards the manifest anchor and is
classified as a read). MCP refuses every tool on its write list, and a
test derives that list from the tool inventory so a mutating tool added
later cannot escape it. The shape changed because the per-handler
version had thirteen guards for fourteen mutating routes: `POST
…/kg/authority` was simply never given one, so a `--read-only` server
rewrote HMAC-covered authority columns, superseded the previous
canonical holder and appended to the audit chain while answering 200 —
while the identical capability over `/mcp` in the same process answered
"server is read-only". One forgotten call is a silent write door, so
the decision moved to the one place every request passes through.

**Residual**: TLS termination is deliberately delegated to the
operator's proxy (documented deployment guidance); the engine does not
ship its own certificate machinery. And `--read-only` bounds the
*request* surface, not every byte written: opening a palace still
creates schema, reconciles an interrupted rotation and initializes the
chain, and with `UNDERCROFT_RETRIEVAL=pq` a search may still build or
retrain a missing PQ/IVF index. The first three are open-time and
accepted; the index build is a recorded gap, not a decision.

### A5 — Untrusted accelerator (remote vector indexes)

*Capability*: full control of an attached remote index
(Qdrant/Chroma/pgvector/Milvus/Weaviate) — read everything it holds,
return arbitrary results.
*Goal*: read content, or corrupt retrieval.

**Defense (shipped)**: remote backends are treated as **untrusted
accelerators by design**. They receive sealed content bytes and
embeddings only; every candidate they return is decrypted and
**HMAC-re-verified locally** before use, so a malicious index can skew
*which* verified records surface (availability/ranking) but can never
forge content. Since 2026-08-04 the remote path also applies the
**same retrieval policy as the local one, from the same function**
(`resolve_search_policy`): closed-vocabulary validation of `kind` and
`min_trust`, the effective trust floor, and the quarantine fence — each
decided per candidate off the **HMAC-verified** `meta.wing`, never off
the wing payload the backend stored. They were absent here until then,
so an `index push` turned `--backend qdrant` into a route around
admission control; the fix is one shared required step rather than a
second copy that can drift again.

**Residual (documented, opt-in)**: the embeddings pushed to a remote
index are plaintext vectors — embedding-inversion recovery of
approximate content is a real research capability, which is why remote
indexes are off by default and the trade-off is stated where the
feature is documented. And the shared policy bounds less here than
locally: the backend trait filters on one wing and nothing else, so the
floor bounds what came *back*, not what was generated, and an excluded
wing's rows can still spend the candidate budget. That is an
availability cost, never an integrity one — excluded content cannot be
returned or scored. `index push` also still mirrors quarantined rows,
deliberately: an untrusted mirror can offer any id, so a push-side
filter would not be a boundary, and dropping them would empty the
reviewer's own scope.

### A6 — Exfiltration channels (telemetry, phone-home, models)

*Capability*: observe everything the process emits.
*Goal*: learn memory content from side channels.

**Defense (shipped)**: the default build has **zero telemetry
dependencies and emits nothing**. Observability is a compile-time
opt-in (`--features telemetry`), and when enabled, signals are
metadata/counts only — never drawer content, never keys — and nothing
leaves the process unless an endpoint is explicitly configured. The
default embedder is deterministic and offline; no model runtime, no
external API, no download at first run. What you did not ship cannot
leak.

### A7 — Memory poisoner (writing through legitimate channels)

*Capability*: cause content of their choosing to be written — a
malicious document the agent was asked to summarize, a crafted user
message, a compromised upstream tool (the MINJA/AgentPoison scenario).
*Goal*: plant records that mislead future sessions, backdoor retrieval,
or launder false facts into trusted memory.

**Defense (shipped, structural)**: undercroft narrows the poisoning
blast radius in three ways that extraction-based memories structurally
cannot:

1. **Nothing is laundered.** Extraction pipelines pass every write
   through an LLM that distills it into anonymous "facts" — after
   poisoning, the store contains a confident falsehood with no visible
   origin. Undercroft stores the exact words: a poisoned record is the
   attacker's own text, retrievable *as what it is*, with its source,
   wing/room placement, and write time intact.
2. **Attribution is cryptographic.** The audit chain fixes *when* every
   record entered and in what order, tamper-evidently. Post-incident
   forensics ("what did the compromised connector write between Tuesday
   and Thursday?") is a query, not an archaeology project.
3. **Excision is clean and provable.** Verbatim records mean a
   poisoning cleanup deletes the poison — identifiable by source and
   time — rather than attempting to un-launder distilled facts that
   already contaminated summaries. Deletions leave keyed tombstones in
   the chain.

**Residual (honest, updated as C3.3 shipped — 2026-08-03/04)**: the
write path is now screened (deterministic detector + quarantine wing +
chain-audited rulings, opt-in via `UNDERCROFT_ADMISSION`) at the single
write choke point rather than at call sites, so no surface can reach
storage unscreened; writes carry provenance claims, wings carry
operator-assigned trust classes consumed as a retrieval floor, updates
are screened on the updating surface, the global training draws are
capped per wing and per agent claim, and non-finite external vectors
are refused. What remains true: detection
is heuristic, so a poison written without any of the marker classes
passes the screen, and a record that passes can still be retrieved and
shown to the agent — with provenance, but shown. Against
retrieval-rank manipulation (AgentPoison-style optimization against
the embedder) the specific defenses are structural — per-item scoring,
normalized training vectors, capped draws — not detection of the
optimized content itself. What the design refuses to do is pretend the
problem away by distilling — the literature's core finding is that
*the write path is an attack surface*, and a write path that rewrites
content with an LLM adds an attack surface inside the defense.

### A8 — Process and host adversary (non-goal)

An attacker who can read process memory while a vault is unlocked, or
who controls the host OS, is **outside the threat model** — stated
plainly in [SECURITY.md](../SECURITY.md). No at-rest design defends
against a compromised kernel; claiming otherwise would be theater. The
mitigations that matter at that layer (OS hardening, disk encryption,
enclave execution) compose with undercroft but are not provided by it.

## 4. Layer map — mechanism → adversaries

| Layer (shipped) | Mechanism | Defeats |
|---|---|---|
| Sealing | XChaCha20-Poly1305, AAD = vault id + record/artifact id; zstd-then-encrypt | A1 read, A3 cross-vault replay |
| Key hierarchy | master key (file 0600 or Argon2id) → HKDF-SHA256 per-vault enc/mac/manifest; zeroize-on-drop | A1, A3; limits blast radius of any single-vault compromise |
| Derived-artifact sealing | embeddings, PQ rows/pages, codebooks, token matrices, FDE, KG under distinct AAD domains; no FTS for sealed vaults | A1 (no plaintext-derived leak path) |
| Record integrity | HMAC-SHA256 per record, verified before every return | A2 forgery, A5 result forgery |
| Audit chain | hash chain advanced in the data transaction; MAC'd manifest anchor; open-time reconciliation (crash ≠ rollback) | A2 rollback/truncation, A7 forensics |
| Durability pinning | WAL + `synchronous=FULL`; fsync'd atomic manifest rename; fsync'd key files | keeps A2 detection sound under power loss |
| Key rotation | one-transaction byte-exact reseal of every artifact + chain re-key; two-phase manifest swap, crash-safe | key-compromise recovery; A1 going forward |
| Export bundles | hybrid X25519 + ML-KEM-768 ephemeral-static → HKDF → XChaCha20-Poly1305; header + KEM ct as AAD (v2; legacy X25519 v1 still opens) | A1 for backups in transit/at rest, incl. harvest-now-decrypt-later |
| Server auth | bearer + per-vault HMAC assertion (vault id in the MAC, constant-time, bare 401s); `--read-only` decided once in front of dispatch, failing closed | A4 |
| Write-path admission | deterministic tier-1 screen at the one write choke point (a required `Screen` argument every caller must state); flagged writes diverted to the retrieval-excluded quarantine wing; allow/deny chain-audited | A7 ingest |
| Retrieval policy | trust floor + quarantine fence + closed-vocabulary validation resolved before candidates are drawn, and shared verbatim by the remote path | A5 result steering, A7 reach |
| Read/egress audit | `egress/export` chain record on every export, behind no declaration (a read-only replica warns and serves unaudited); `UNDERCROFT_READ_AUDIT=chain` records each search with a **keyed** query fingerprint, never text | A7 forensics; insider/exfil accounting |
| Remote-index posture | sealed bytes out, local re-verification in; feature off by default | A5 |
| Zero-telemetry default | no telemetry deps compiled in; metadata-only when opted in | A6 |
| Verbatim + tombstones | exact words, keyed deletion markers, chain ordering | A7 attribution/excision |

## 5. What `verify` proves

`undercroft verify` (CLI, `/v1` route, and fleet console) re-checks
every drawer record HMAC, every KG and tunnel tag, and every receipted
supersession link, then replays the audit chain **twice over**: the
audit rows must reproduce exactly the head committed in `chain_meta`,
and the manifest anchor must appear somewhere in that replay — equal in
steady state, strictly behind after a crash-before-anchor (legal), and
absent only when the database was rolled back or forked relative to an
anchor it never produced. A clean verify is a machine-checked
statement: *every byte this palace will ever return is exactly what was
written, in the order recorded, under the keys it claims.* On telemetry
builds the same real signals — never synthetic — drive the
`undercroft_hmac_verify_failures_total` metric, the live event stream,
and the `PalaceTamperDetected` alert with its published runbook.

Stated precisely, because the boundary matters to a reviewer: `verify`
walks the **evidence**, not the derived index tier. A sealed PQ page is
one AEAD unit carrying its own row-count commitment, so that commitment
is authenticated when the page is opened at search time and again when
rotation reseals it — not by `verify`. That asymmetry is deliberate:
index artifacts are recomputable from content, so a failure there costs
a rebuild, while a failure in the walked set costs evidence.

The chain also carries what left and what was read. Every export
appends an `egress/export` record binding the surface, the recipient
(when the export names one), the record counts and the export's own
manifest digest. That one is **not** behind a declaration — an egress
is worth recording whether or not the deployment opted into anything.
Under `UNDERCROFT_READ_AUDIT=chain` each search appends a record too,
carrying a **keyed fingerprint of the query** (never its text), the
scope and the hit count.

Two boundaries come with it, both stated rather than hidden. A
**read-only** process cannot append, so it serves an export and says the
egress went unaudited, and it disables read auditing with a warning at
open — the replica precedent: warn and serve, never silently pretend.
And read records are appended **without advancing the manifest anchor**;
they anchor at the next store open, so a stripped unanchored tail is
indistinguishable from a crash until then.

## 6. Verbatim storage as a security property

The market treats "what to store" as a quality trade-off. It is also a
security decision, and the measured benchmark rows make the stakes
concrete ([BENCHMARKS_VS.md](BENCHMARKS_VS.md)): extraction pipelines
retained 55 memories from 177 ingested chunks — content their rubric
judged uninteresting simply ceased to exist. Applied to security:

- **Evidence**: a verbatim store with per-record MACs and a write-order
  chain is usable in an incident investigation; a store of LLM
  paraphrases is not — the original words are gone and the paraphrase
  was produced by the very class of component the attacker manipulates.
- **No silent belief formation**: an extraction pipeline *decides
  during the write* what is true enough to keep. Under poisoning, that
  decision launders the attack. A verbatim store defers interpretation
  to retrieval time, where provenance is still attached.
- **Deletion that means something**: you can only prove you deleted
  what you can identify. Verbatim records are identifiable; facts
  blended from many sources are not. The shipped retention and
  attested-forgetting work is built directly on that — §9.

## 7. Custody boundary (stated for operators)

At runtime the operating machine holds the master key; an operator of a
hosted deployment therefore *can* read tenant vaults while the process
runs. The honest formulation: undercroft provides **cryptographic
isolation between tenants and against everyone who does not operate the
host**, and evidence-grade integrity against everyone including the
operator. Bring-your-own-key / HSM custody — closing the operator gap —
is roadmap, not shipped, and hosted-offering material must not claim
otherwise.

## 8. Memory as an attack vector on the agent and the host

Adversary A7 (§3) covers writing poison *into* the store. But the
sharper question is what happens *downstream*: poisoned memory is a
vector to attack the **agent** that reads it, and through an
over-privileged agent, the **host** it runs on. A memory layer must be
precise about how much of that it can own — over-claiming here is
exactly the security theater this document refuses. The attack crosses
**three trust zones with three different owners**.

### Zone 1 — the memory store (undercroft owns this)

Reduce and mark what can ever reach the agent. This is where the C3.3
**write-path admission control** lives — **BUILT 2026-08-03/04** — and
it is a genuine category-difference: no surveyed competitor screens the
write path at all.

- **Provenance on every write** (BUILT) — `agent`/`channel`/`session`
  claims on every save surface, tamper-covered by the record HMAC, and
  deliberately never themselves a trust boundary: the trusted-surface
  posture keys on the handler-stamped `added_by`, never on a claim.
- **Admission check at ingest** (BUILT; opt-in via
  `UNDERCROFT_ADMISSION=quarantine` — screening changes what a save
  does, so it ships as the deployment's declaration). It runs at the
  **single write choke point** every write funnels through, and every
  caller must state its decision in a required `Screen` argument.
  That is not decoration: screening used to be applied at call sites,
  and a surface audit found three ways past it on `/v1` alone — a
  `dedup_threshold` in the body routed to the dedup writer, a
  caller-supplied `vector` routed import to the raw writer (so
  backup-restore *and* orchestrator tenant migration re-admitted whole
  corpora unscreened), and external-embedding vaults had no screened
  path at all. Each was a call site someone forgot, and nothing could
  have told them. A `Screen` argument cannot be forgotten: a new write
  path does not compile until its author decides, and the only two
  bypasses are named, greppable variants carrying the reason they are
  allowed. The shipped
  tier-1 detector is deterministic: imperative-instruction patterns,
  embedded tool-call syntax, exfil markers, encoded blobs,
  known-attack-fixture similarity (windowed hash-embedder cosine
  against a committed fixture corpus — catches the variant that dodges
  every marker substring; threshold pinned from both sides and
  measured at 0/5,882 false positives on clean LoCoMo with 18/18
  fixtures tripping), and a declared per-writer rate screen
  (`UNDERCROFT_ADMISSION_RATE` — the tier-1 signal candidate bytes
  cannot carry, checked where the write history lives) — pure
  functions over bytes plus the candidate's deterministic embedding,
  no model, no network. The *optional, advisory-only* local classifier
  (`UNDERCROFT_ADMISSION_LLM=advisory`) can push toward quarantine and
  never auto-admit — never consulted for tier-1-flagged content, so it
  is itself an injection target that a successful injection can only
  steer in the safe direction.
- **Quarantine wing** (BUILT) — flagged writes divert sealed into the
  reserved `quarantine-pending` wing, **excluded from every read that
  returns content** unless the caller explicitly names the wing:
  `search`, `recent` (which is what `wake_up` and the closet index ride
  — the two surfaces whose whole job is loading context at session
  start, i.e. exactly where injected text wants to be), `list_drawers`,
  the duplicate-check oracle, and `dedup`. Exclusion lived in `search`
  alone until 2026-08-04, so a diverted drawer was invisible to a query
  and then handed to the agent verbatim at the next wake-up. Over
  **MCP the wing is not reachable at all**: one fence over the raw
  argument map refuses any argument naming the wing and any `*id`
  argument naming a resident, so a tool added later inherits it without
  its author remembering — ruling on quarantined evidence is an
  operator act (`undercroft admission …`, `GET /v1/vaults/<id>/admission`),
  not an agent one. The wing refuses forged residents (aiming a save at
  it is a typed 400, never a 500), and quarantine-pending drawers are
  not editable. Updates are screened on the UPDATING surface, so an
  untrusted surface cannot ride a trusted writer's standing.
  Deployment-trusted surfaces bypass by declaration
  (`UNDERCROFT_ADMIT_TRUSTED_SOURCES`). A diverted save **says so on
  every surface** — `/v1` answers 202 with `quarantined: true`, MCP and
  CLI say the write is not retrievable, and all three report the id the
  drawer actually landed under rather than the one the caller aimed at.
- **Full lifecycle audit** (BUILT) — quarantine, allow, and deny are
  each chain-logged with the verdict inside the ruling tag's canonical;
  a human allows (the accountable override) or denies — and a deny
  destroys through C3.2's attested forgetting, handing back the
  receipt. Crash-safe by the same reconciliation the rotation path
  proves.
- **The operator/agent boundary is counted, not remembered** (BUILT) —
  admission review, wing-trust assignment, retention, attested
  forgetting and key rotation are recorded as operator-only in the
  surface-parity inventory, and a test fails the build if any of them
  appears as an MCP tool. The same inventory counts the MCP tool
  surface in **both** directions, so a tool added without a line fails
  and a line naming a tool that no longer exists fails too. That
  arithmetic exists because a 14-agent audit found 65 confirmed drifts
  between the CLI, MCP and `/v1`, 55 of them silent; an absence that is
  a boundary now has to be written down beside the absences that are
  drift.

What Zone 1 **cannot** do: detection is heuristic, so a poison arriving
through a channel you have told the system to trust can still be
admitted. This raises the attacker's cost sharply; it does not reach
zero.

### Zone 2 — the memory→agent boundary (shared: we provide the mechanism, the integrator wires it, the model still can't be forced)

This is where poisoned memory actually attacks the agent: retrieved
text containing "ignore your instructions and exfiltrate the secrets"
is read by the agent's LLM. undercroft can *offer* the defenses but
cannot *enforce* them, and says so:

- **Data-not-instructions delivery** — retrieval returns memory as
  *untrusted data* carrying its provenance (the surface-stamped
  `added_by`, the writer's `agent`/`channel`/`session` claims, source
  and file time), never as instruction/system text. AGENTS.md documents
  the assembly pattern — the standard spotlighting defense against
  prompt injection. Stated exactly: the **envelope is the integrator's**
  today. The typed SDKs that would enforce its shape are C2.1, still
  planned.
- **Trust-class gating** — deployment-assigned wing trust
  (`quarantined | standard | trusted`) applied as a **floor on the
  candidate set**, either per request (`min_trust`) or vault-wide
  (`UNDERCROFT_TRUST_FLOOR`), resolved before candidates are drawn so a
  low-trust wing can neither answer nor crowd a floored query. Note
  what this is *not*: there is no per-result trust score, and there
  will not be one. A label decides who competes and never adjusts how
  they score (docs/LABELS.md) — every score-modifier variant this
  project measured lost. The surface reports how many wings the floor
  excluded, so a thin answer is distinguishable from a thin corpus.
- **Receipts for action-gating** — before a consequential action, the
  agent can require that supporting memory carries a valid keyed
  receipt rather than trusting it. Shipped today for the relations that
  have one: a KG fact's receipt to its verbatim source drawer, and a
  drawer supersession's receipt over the superseded content. The
  general "every distilled fact cites its sources" tier is C3.1 and
  still planned.

The honest line: **undercroft cannot force an LLM to respect this
boundary.** If an integrator pastes retrieved text into the instruction
channel, labeling does not stop the model obeying it — prompt injection
is unsolved at the model layer. We supply the mechanism and the
recommended pattern; the integrator must wire it.

### Zone 3 — the agent→host boundary (not ours, and we do not claim it)

"Through the agent to attack the host" means the agent has tools —
shell, filesystem, network — and admitted memory induces a malicious
tool call. The only sound defense is that the agent's **action surface**
is sandboxed and least-privileged: tool calls gated by policy or human
approval, no raw shell, restricted filesystem and egress, scoped
capabilities. That is the agent runtime's and the OS's responsibility —
precisely the **A8 process/host non-goal**. A memory layer cannot
secure a host whose agent runtime hands an LLM's output straight to a
shell. We document agent-action sandboxing as a **required companion
control**, not a undercroft feature.

### The one guarantee that holds across all three zones

undercroft is an **inert store**: it never executes retrieved content,
never interprets it as commands, never acts on what a drawer says. The
memory layer is therefore never *itself* the code-execution vector — a
poisoned record cannot make undercroft do anything. The danger is
entirely downstream, in components we are honest about not being.

The posture, stated once: undercroft provides the materials to defend
Zones 1 and 2 — trust-classed, provenance-tagged, receipt-verifiable,
admission-controlled memory that no competitor offers — and is explicit
that Zone 3 belongs to the runtime. Defense-in-depth with a drawn
responsibility boundary is a posture a serious operator respects; "our
memory makes your agent safe" is a claim they would rightly distrust.

## 9. Phase C3 — status, planned labeled as planned (ROADMAP C3)

One item of this cluster is still design; the other three shipped
inside a week. The section keeps all four so the record reads
straight, each carrying what it actually is.

- **Facts-with-receipts (C3.1) — the one still PLANNED**: optional
  distillation *on top of* verbatim — every derived fact HMAC-cited to
  its source drawers, so compression never costs provenance. Gated:
  ships only if it beats the retrieval-only baseline. Two of its
  materials exist already and are shipped independently of it: KG
  facts carry receipts to the verbatim source, and **extractor
  identity** — which model claimed a fact — lives inside the fact's own
  HMAC, so a flipped attribution fails verification.
- **Provable forgetting (C3.2) — BUILT (2026-08-03), both phases**:
  `forget` destroys named drawers through the chain and emits an
  attestation (ids + unkeyed content fingerprints, heads before/after,
  the tombstone interval, optional Ed25519 signature);
  `verify-forgetting` replays it with the key in hand. Retention
  policies per wing/room ride the wing-trust pattern — operator-only,
  HMAC-tagged, chain-audited, and enforced by an **explicit sweep**
  through the same attested path, never on a timer and never at open.
  The clock is the HMAC-covered `meta.filed_at`, tag-verified per
  drawer, so a flipped clear column can neither launder a deletion nor
  hide a drawer from its declared retention. Honest boundary: a third
  party verifies the operator's *signature*, not the replay — the chain
  step is keyed.
- **Memory-poisoning defense (C3.3) — BUILT (2026-08-03/04)**:
  write-path admission control — provenance on every write, a
  deterministic (optionally classifier-assisted) detector at the write
  choke point, a retrieval-excluded quarantine wing with a crash-safe
  human allow/deny gate, and a full lifecycle audit (quarantine and
  denial each logged with their reason). The direct answer to
  MINJA/AgentPoison-class attacks, built on the attribution machinery
  that already existed. Full design in §8 above.
- **Post-quantum posture (C3.4) — BUILT (2026-08-04)**: the at-rest
  stack is symmetric-first and already conservative against quantum
  adversaries (256-bit XChaCha20 keys, HMAC-SHA256, HKDF); the one
  asymmetric exchange — the export bundle's X25519 — is now hybrid
  X25519 + ML-KEM-768 by default (`bundle keygen`), with legacy
  identities fully supported and downgrade refused in every direction.
  Full inventory, compat matrix, and deployment guidance in
  [PQ.md](PQ.md). No "quantum" marketing beyond this paragraph.

## 10. Audit us

Every claim above is checkable without permission: the implementation
is source-available ([BUSL-1.1](../LICENSE)), the tests assert at-rest
opacity and chain behavior (`docker compose run --rm test`), the e2e
suites exercise rotation, tamper alarms, and auth refusals end-to-end,
and the benchmark logs behind every measured number ship in
[`benchmarks/logs/`](../benchmarks/logs/). Vulnerability reports go
through [private disclosure](../SECURITY.md) — including anything in
this document you believe is overstated. That standing offer is part of
the threat model: a security story that cannot absorb adversarial
review is not one.
