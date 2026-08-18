# Security Policy

Undercroft's whole premise is hardened memory — vulnerability reports are
taken seriously and handled privately.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub
issues.**

- Preferred: **[GitHub private vulnerability reporting](https://github.com/sealcroft/undercroft/security/advisories/new)**
  (Security → Report a vulnerability) — keeps the report, discussion, and
  fix coordination private until disclosure.
- Alternative: email **compufreq@proton.me** with subject
  `[SECURITY] undercroft: <short summary>`.

Include what you can: affected version/commit, vault level
(sealed / hmac-only), reproduction steps, and your impact assessment.

**Response expectations**: acknowledgment within 72 hours; an initial
assessment (accepted / needs-info / declined, with reasoning) within
7 days; accepted reports are fixed in a priority release with a GitHub
security advisory crediting the reporter (unless you prefer anonymity).
Please allow coordinated disclosure — up to 90 days before public
details; usually far faster.

## Supported versions

Only the **latest release** receives security fixes. Releases are
self-contained and migration is lossless (open the palace with the new
binary, or `export` / `import`) — please reproduce against the latest
version before reporting.

## Threat model

Undercroft's vault layer protects memories **at rest**: disk theft,
cross-vault bleed, and offline tampering of the database or manifest
(XChaCha20-Poly1305 AEAD, per-vault HKDF-SHA256 key derivation,
HMAC-SHA256 record tags plus a tamper-evident audit chain). It does **not**
defend against an attacker who can read process memory while a vault is
unlocked, nor against a compromised host OS.

Above that layer the served surfaces carry boundaries of their own, and
they are in scope too: the write-path admission screen (applied at the
single write choke point, so no surface reaches storage unscreened), the
quarantine wing's exclusion from every read that returns content, the
operator-only capabilities that must never appear over MCP, and
`--read-only` as a posture on the whole process rather than a filter on
one port. The whitepaper linked below states each mechanism and its
residual.

**Tamper is detected on read, not prevented.** Any record, KG triple, tunnel,
or manifest that fails its HMAC surfaces immediately: `undercroft verify` names
the record, and (on a `--features telemetry` build) the
`undercroft_hmac_verify_failures_total` metric, the live event stream, and the
Palace Monitor beacon all fire on the same real signal — never synthetically.
`deploy/observability/` ships a `PalaceTamperDetected` alert, and
`deploy/observability/RUNBOOK.md` (published at `/docs/runbook.html`) covers
how to confirm, mitigate, fix, and prevent it.

Details are documented in `crates/undercroft-vault/src/lib.rs` and the
[security model](https://sealcroft.com/undercroft/docs/security.html);
the formal adversary-class treatment — what each layer defeats and the
honest non-goals — is the
[threat-model whitepaper](https://sealcroft.com/undercroft/docs/threat-model.html)
(docs/THREAT_MODEL.md).

## Scope

In scope (examples, not a limit):

- Reading sealed content, embeddings, or derived artifacts (token
  matrices, PQ/FDE rows, codebooks) at rest without the vault's keys —
  AEAD/AAD bypass, nonce misuse, key-derivation flaws.
- Forging records, audit-chain entries, or manifests that `verify`
  accepts; making a **rollback** pass as a crash.
- Cross-vault access: any way blob or key material from one vault helps
  open another.
- HTTP-surface auth bypass: reaching `/v1` without the bearer,
  addressing a vault without a valid assertion, escaping the
  orchestrator's tenant→vault mapping or `/t/*` allowlist, forging or
  replaying tenant tokens.
- Plaintext or plaintext-derived data persisted to disk by a sealed
  vault (including via derived indexes, logs, or telemetry).
- Key material exposure through logs, errors, or telemetry.
- Opening an encrypted export bundle without its identity key, or
  making a hybrid (`pq1`) recipient silently accept a legacy X25519-only
  bundle — the downgrade refusal is a security property.
- Reaching stored content **without passing the admission screen** when
  a deployment declares `UNDERCROFT_ADMISSION=quarantine`: any write path
  that lands a drawer unscreened, or a save that reports success under
  the id the caller aimed at while the content sits in quarantine.
- Reading, editing, or destroying **quarantine-pending** content through
  any surface but the operator's own (`admission` on the CLI and `/v1`)
  — MCP in particular must refuse it — or reaching an **operator-only**
  capability from the agent surface. The full list is `OPERATOR_ONLY` in
  `crates/undercroft-cli/src/parity.rs`, enforced by a test rather than by
  this paragraph: admission rulings, wing-trust assignment, retention,
  attested forgetting, key rotation, knowledge-graph authority promotion,
  manifest-anchor tightening, **export**, **import**, and `refine`. The
  last three were missing here, and `export` is the one the inventory
  justifies with "an agent that could call it could exfiltrate a palace in
  one tool call" — so a reporter reading this list to decide whether a
  finding was in scope was reading a shorter list than the code enforces.
- A `--read-only` server or store changing state: any request that
  writes, any write on a read path — including a search that builds or
  retrains a missing prefilter index — and any write at **open**. Schema
  creation and migration, chain seeding, anchor fast-forward, FTS rebuild
  and promotion of a writer's staging manifest are all refused there now
  rather than merely avoided: the connection is opened `READ_ONLY` under
  `PRAGMA query_only=ON`, so a write nobody thought of fails loudly
  instead of happening quietly.

Out of scope (documented threat-model boundaries):

- Attacks requiring the master key, the passphrase, or process memory
  while a vault is unlocked; a compromised host OS.
- A consistent old database + manifest pair restored **together** by an
  attacker with full disk control (documented residual; external witness
  is the planned mitigation).
- **The knowledge-graph browse routes are not read-audited.** Under
  `UNDERCROFT_READ_AUDIT=chain` every content-returning DRAWER read appends
  one record (ROADMAP O50) — `search`, `get`, `recent`, `list`, diary,
  tunnel, closet, hallways, admission queue. The graph's own readers
  (`kg_query`, `kg_timeline`, `kg_entities`, `lookup_canonical`,
  `kg_receipts`) return distilled drawer words through a second funnel and
  do not yet record. Enumerated here as a limit rather than left implied,
  and filed as the remainder of round-four #23. Until O50 this list omitted
  the far larger gap — that `get` and every bulk read were unaudited
  entirely — which is why it is written out now.
- The **anchor lag on audited reads**. Under
  `UNDERCROFT_READ_AUDIT=chain` a read appends a chain record but
  deliberately does not fast-forward the manifest anchor, so a stripped
  *unanchored* tail is indistinguishable from a crash until the anchor
  next moves — at the next store open, or on demand through
  `undercroft vault anchor` / `POST /v1/vaults/{id}/anchor`, which exist
  because a long-lived server never re-opens. The lag itself is the
  documented boundary; a way to strip an **anchored** tail is very much
  in scope.
- The WAL scaffolding a read-only open materialises beside a vault when
  the directory is writable (an `-shm`, and a zero-length `-wal`). It
  carries no database content, is reconstructible, and is the price of
  reading a WAL database at all; where the directory is not writable the
  open escalates to `immutable=1` and says so.
- Denial of service against a server you operate, and resource
  exhaustion requiring authenticated access.
- Vulnerabilities exclusively in optional attached components (remote
  vector backends, local LLM runtimes, user-supplied ONNX models) —
  though sealed-content leakage *to* those components is very much in
  scope.
