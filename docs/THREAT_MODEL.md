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
   a retrieval preference (§6), and where the planned provenance work
   (§8) extends the design.

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
error would leak vault existence or forgery proximity). `--read-only`
strips every mutating tool. The orchestrator stores tenant tokens as
HMACs and seals engine credentials; token rotation invalidates the old
token fleet-wide on the next request.

**Residual**: TLS termination is deliberately delegated to the
operator's proxy (documented deployment guidance); the engine does not
ship its own certificate machinery.

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
forge content. **Residual (documented, opt-in)**: the embeddings pushed
to a remote index are plaintext vectors — embedding-inversion recovery
of approximate content is a real research capability, which is why
remote indexes are off by default and the trade-off is stated where the
feature is documented.

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
chain-audited rulings, opt-in via `UNDERCROFT_ADMISSION`), writes carry
provenance claims, wings carry operator-assigned trust classes consumed
as a retrieval floor, updates are screened on the updating surface, the
global training draws are capped per wing and per agent claim, and
non-finite external vectors are refused. What remains true: detection
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
| Server auth | bearer + per-vault HMAC assertion (vault id in the MAC, constant-time, bare 401s) | A4 |
| Remote-index posture | sealed bytes out, local re-verification in; feature off by default | A5 |
| Zero-telemetry default | no telemetry deps compiled in; metadata-only when opted in | A6 |
| Verbatim + tombstones | exact words, keyed deletion markers, chain ordering | A7 attribution/excision |

## 5. What `verify` proves

`undercroft verify` (CLI, `/v1` route, and fleet console) re-checks
every record HMAC, every KG and tunnel tag, the sealed index
commitments (including page-tier row counts), and replays the audit
chain against the manifest anchor. A clean verify is a machine-checked
statement: *every byte this palace will ever return is exactly what was
written, in the order recorded, under the keys it claims.* On telemetry
builds the same real signals — never synthetic — drive the
`undercroft_hmac_verify_failures_total` metric, the live event stream,
and the `PalaceTamperDetected` alert with its published runbook.

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
  blended from many sources are not. (The forthcoming retention work
  builds on this — §9.)

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
  does, so it ships as the deployment's declaration). The shipped
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
  reserved wing, `pending`, **excluded from all retrieval** except a
  reviewer's explicit scope; the wing refuses forged residents, and
  quarantine-pending drawers are not editable. Updates are screened on
  the UPDATING surface, so an untrusted surface cannot ride a trusted
  writer's standing. Deployment-trusted surfaces bypass by declaration
  (`UNDERCROFT_ADMIT_TRUSTED_SOURCES`).
- **Full lifecycle audit** (BUILT) — quarantine, allow, and deny are
  each chain-logged with the verdict inside the ruling tag's canonical;
  a human allows (the accountable override) or denies — and a deny
  destroys through C3.2's attested forgetting, handing back the
  receipt. Crash-safe by the same reconciliation the rotation path
  proves.

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
  clearly-delimited *untrusted data* carrying its provenance and trust
  score, never as instruction/system text. The SDKs (C2.1) can enforce
  the envelope shape and AGENTS.md documents the assembly pattern (the
  standard spotlighting defense against prompt injection).
- **Trust-threshold gating** — a per-result trust score the integrator
  thresholds before anything enters the agent's context.
- **Receipts for action-gating (C3.1)** — before a consequential
  action, the agent can require that the supporting memory carries a
  valid HMAC receipt chain to a trusted source: *verify the memory*
  rather than *trust the memory*.

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
Zones 1 and 2 — trust-scored, provenance-tagged, receipt-verifiable,
admission-controlled memory that no competitor offers — and is explicit
that Zone 3 belongs to the runtime. Defense-in-depth with a drawn
responsibility boundary is a posture a serious operator respects; "our
memory makes your agent safe" is a claim they would rightly distrust.

## 9. Planned extensions (labeled planned; ROADMAP C3)

- **Facts-with-receipts (C3.1)**: optional distillation *on top of*
  verbatim — every derived fact HMAC-cited to its source drawers, so
  compression never costs provenance. Gated: ships only if it beats
  the retrieval-only baseline.
- **Provable forgetting (C3.2)**: retention policies per wing/room and
  a deletion attestation derived from the audit chain — an auditable
  answer to right-to-be-forgotten requests.
- **Memory-poisoning defense (C3.3)**: write-path admission control —
  provenance on every write, a deterministic (optionally
  classifier-assisted) detector, a retrieval-excluded quarantine wing
  with a crash-safe human allow/deny gate, and a full lifecycle audit
  (quarantine and denial each logged with their reason). The direct
  answer to MINJA/AgentPoison-class attacks, built on the attribution
  machinery that already exists. Full design in §8 above.
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
