# Security Policy

Undercroft's whole premise is hardened memory — vulnerability reports are
taken seriously and handled privately.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub
issues.**

- Preferred: **[GitHub private vulnerability reporting](https://github.com/compufreq/undercroft/security/advisories/new)**
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

**Tamper is detected on read, not prevented.** Any record, KG triple, tunnel,
or manifest that fails its HMAC surfaces immediately: `undercroft verify` names
the record, and (on a `--features telemetry` build) the
`undercroft_hmac_verify_failures_total` metric, the live event stream, and the
Palace Monitor beacon all fire on the same real signal — never synthetically.
`deploy/observability/` ships a `PalaceTamperDetected` alert, and
`deploy/observability/RUNBOOK.md` (published at `/docs/runbook.html`) covers
how to confirm, mitigate, fix, and prevent it.

Details are documented in `crates/undercroft-vault/src/lib.rs` and the
[security model](https://compufreq.github.io/undercroft/docs/security.html);
the formal adversary-class treatment — what each layer defeats and the
honest non-goals — is the
[threat-model whitepaper](https://compufreq.github.io/undercroft/docs/threat-model.html)
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
- Opening an encrypted export bundle without its identity key.

Out of scope (documented threat-model boundaries):

- Attacks requiring the master key, the passphrase, or process memory
  while a vault is unlocked; a compromised host OS.
- A consistent old database + manifest pair restored **together** by an
  attacker with full disk control (documented residual; external witness
  is the planned mitigation).
- Denial of service against a server you operate, and resource
  exhaustion requiring authenticated access.
- Vulnerabilities exclusively in optional attached components (remote
  vector backends, local LLM runtimes, user-supplied ONNX models) —
  though sealed-content leakage *to* those components is very much in
  scope.
