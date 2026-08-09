# Security comparison: undercroft vs the memory-layer market

The AI-memory market competes on retrieval convenience; this page
compares what each system does to **protect** the memory it holds. It
covers the *self-hosted/local artifacts* each vendor publishes — the
thing you actually run on your machine — not the compliance posture of
their hosted clouds (SOC 2 for a vendor's cloud says nothing about the
bytes your local deployment writes to disk).

Claims below are drawn from each project's public code and
documentation as of July 2026. The standard we apply to ourselves
applies here: if you represent one of these systems and a cell
misstates you, **open a PR with a source and we will correct it.**
Cells say *"not documented"* where we could not find the feature —
which is itself the finding: for most of this table, the competing
products don't claim these properties at all.

## The table

| Property | **undercroft** | mem0 / OpenMemory | Zep (Graphiti) | Letta | Cognee | Supermemory |
|---|---|---|---|---|---|---|
| Content encrypted at rest (application-level) | **Yes** — XChaCha20-Poly1305 per record, per-vault HKDF keys | not documented (plaintext in vector store + SQLite) | not documented | not documented | not documented | not documented |
| Derived artifacts encrypted (embeddings, index codes, token matrices) | **Yes** — AEAD-sealed under distinct AAD domains; tests assert the at-rest bytes | not documented (plaintext qdrant vectors) | not documented | not documented | not documented | not documented |
| Every read integrity-verified | **Yes** — HMAC-SHA256 per record, checked before content is returned | not documented | not documented | not documented | not documented | not documented |
| Tamper-evident audit chain | **Yes** — hash chain advanced transactionally with every write; manifest rollback anchor; `verify` command | not documented | not documented | not documented | not documented | not documented |
| Cross-tenant isolation is cryptographic | **Yes** — AAD binds the vault id; a blob moved across vaults *fails to decrypt*, it isn't just filtered | logical (`user_id` filter) | logical (session/group filters) | logical | logical (dataset scoping) | logical (`containerTag` filter) |
| In-place key rotation | **Yes** — one-transaction reseal of every artifact, crash-reconciled | not documented | not documented | not documented | not documented | not documented |
| Encrypted export/backup format | **Yes** — recipient-encrypted bundles (X25519 → HKDF → XChaCha20-Poly1305) | not documented | not documented | not documented | not documented | not documented |
| Runs with zero model runtime (no LLM/embedding server required) | **Yes** — deterministic offline embedder is the default | No — LLM + embedder required per write | No — LLM required for graph construction | No — LLM runtime is the product | No — LLM + embedder pipelines | No — model-dependent |
| Telemetry default | **None** — opt-in build feature; metadata-only when enabled | telemetry in OSS server (opt-out varies by component) | vendor-dependent | vendor-dependent | vendor-dependent | vendor-dependent |
| Verbatim storage (retrieval returns exact words, nothing silently discarded) | **Yes** — invariant | No — LLM-distilled facts (measured: [55 memories retained from 177 chunks](BENCHMARKS_VS.md#reading-the-mem0-row)) | No — graph facts | Partial — archival passages + distilled core memory | No — graph/derived representations | No — distilled facts/profiles |

## Why the empty column matters now

Agent memory is being actively discussed as an **attack surface**:
persistent memory poisoned once misleads every future session, and
memory stores hold the most sensitive distillate of a user's life or an
organization's operations. A memory layer that stores plaintext, can't
prove a record unaltered, and can't demonstrate that a deletion
happened is a liability that scales with adoption.

undercroft's answers are structural, not bolted on:

- **Sealed vaults**: content *and* every plaintext-derived artifact
  (embeddings, PQ codes/pages, ColBERT token matrices, KG objects) are
  AEAD-encrypted under per-vault keys derived via HKDF from a master
  key that never leaves the machine. An offline copy of the store yields
  **no word of the content**. It is not "nothing else": drawer
  *metadata* — wing and room names, the `source_file` path, `added_by`,
  the hall label, `content_date`, the dates resolved out of the content,
  the declared `kind`, the supersession link, the writer's
  `agent`/`channel`/`session` claims and the per-row timestamps — is
  stored in the clear, pinned by test and inventoried in
  [THREAT_MODEL.md](THREAT_MODEL.md) under adversary class A1. Do not
  put a secret in a wing
  or room name.
- **Evidence-grade integrity**: each record carries an HMAC verified on
  every read; every write advances a hash chain inside the same
  transaction; the chain head is anchored in the vault manifest so
  rollback of the whole database is detectable, not just row edits.
- **Cryptographic tenant boundaries**: the multi-tenant server and the
  orchestrator never rely on filters alone — AAD binding makes
  cross-vault access fail in the cipher, so an authorization bug
  downstream produces garbage, not a leak.
- **Zero external calls by default**: the default pipeline embeds
  deterministically offline. Nothing phones home; telemetry does not
  exist in default builds.

The one place these properties are visible in *performance* terms is
the [head-to-head benchmark](https://sealcroft.com/undercroft/docs/benchmarks-vs.html): the sealed,
audit-chained, zero-model configuration is not a premium tier we
benchmark around — it *is* the measured row.

## Scope and fairness notes

- Vendor clouds (Zep Cloud, mem0 Platform, Supermemory API) publish
  enterprise security programs (SOC 2 etc.). That is real and valuable
  — and orthogonal: it protects their infrastructure, not your
  self-hosted deployment, and requires shipping your memory to them.
  This page compares what runs on **your** machine.
- "Logical" isolation is not an accusation of a bug — filters can be
  implemented correctly. The distinction is what happens when the
  filter layer fails: cryptographic isolation fails closed.
- Disk-level encryption (LUKS/BitLocker/SQLCipher) can wrap any of
  these systems, ours included. The table is about what the
  *application* guarantees: per-record sealing, per-vault keys,
  integrity tags, and rotation are properties disk encryption cannot
  provide.
