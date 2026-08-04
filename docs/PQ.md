# Post-quantum posture

One page, three claims, each of them checkable against the code: what
is already quantum-resistant by construction, what was not and how it
was closed, and what this posture deliberately does not claim.

## The inventory: symmetric-first, so mostly done before it started

Undercroft's cryptography is symmetric wherever data rests. Grover's
algorithm halves effective symmetric security; Shor's breaks
elliptic-curve and RSA asymmetric cryptography outright. That
asymmetry-of-impact is the whole posture:

| mechanism | primitive | PQ status |
|---|---|---|
| content/artifact sealing | XChaCha20-Poly1305, 256-bit keys | ~128-bit effective under Grover — the accepted PQ bar |
| record tags, audit chain, tokens, attestation replay | HMAC-SHA256 | PQ-safe (no useful quantum speedup beyond Grover) |
| key derivation | HKDF-SHA256, Argon2id | PQ-safe |
| dedup fingerprints, blind indexes, audited read-query fingerprints | keyed HMAC (truncated) | PQ-safe |
| **export-bundle recipient encryption** | was X25519 alone | **the one vulnerable spot — closed, hybrid since C3.4** |
| bundle/attestation signatures | Ed25519 | quantum-forgeable *in the future*; not a harvest risk (see below) |

## The closed spot: hybrid X25519 + ML-KEM-768 bundles

An exported bundle is a file that leaves the machine, which makes it
the one place harvest-now-decrypt-later applies: an adversary who
records the file today decrypts it whenever a cryptographically
relevant quantum computer exists, because X25519 falls to Shor. Since
C3.4, `undercroft bundle keygen` produces a **hybrid identity** —
X25519 *and* ML-KEM-768 (FIPS 203 final, the RustCrypto `ml-kem`
implementation) — and a bundle sealed to it derives its file key from
**both** shared secrets:

```text
UNDERCROFT-BUNDLE-2 ‖ eph_x25519_pub (32) ‖ mlkem_ct (1088) ‖ nonce (24) ‖ ciphertext
file_key = HKDF-SHA256(salt = eph_pub ‖ recipient_x_pub,
                       ikm  = DH(eph, recipient_x) ‖ kem_shared,
                       info = "undercroft.v2/bundle")
```

Breaking the bundle requires breaking the curve **and** the lattice.
The magic, the ephemeral key and the KEM ciphertext are all bound as
AAD, so a spliced header, a swapped encapsulation, or a magic
rewritten to impersonate the other version fails to open — the
downgrade-refusal tests pin every direction.

Compatibility is total and explicit, never inferred:

| bundle | X25519-only identity (legacy, bare hex) | hybrid identity (`pq1…`) |
|---|---|---|
| v1 (`UNDERCROFT-BUNDLE-1`) | opens | opens (curve half) — upgrading an identity never orphans old backups |
| v2 (`UNDERCROFT-BUNDLE-2`) | typed refusal naming the hybrid format | opens |

A legacy bare-hex recipient still receives a v1 bundle it can actually
open; a hybrid recipient **always** receives v2 — a new identity has no
reason to be harvestable, and no silent downgrade exists.

## Deployment guidance: the wire is the proxy's job

The engine's own transport rule (TLS-or-loopback on every content
egress path, CA declarations as pins) says nothing about the TLS key
exchange, because that is terminated by your reverse proxy. To extend
the harvest-now posture to the wire, enable a **hybrid KEM group**
(`X25519MLKEM768`) at the terminator — current OpenSSL (3.5+),
BoringSSL, and the servers built on them (recent Caddy and nginx
builds) support it, and browsers already offer it by default. This
covers the `/v1` surface, the orchestrator, and the served-embedder
hop alike; nothing in undercroft needs to change for it.

## Signatures, stated honestly

Ed25519 signs bundle manifests and forgetting attestations. Shor
forges Ed25519 — but a signature is not a harvest target: recording a
signed manifest today does not let a future adversary alter what you
verified in the past, it lets them mint *new* forgeries once a CRQC
exists. That is a real but later problem, and the migration path
(ML-DSA alongside Ed25519, the same hybrid pattern) is recorded here
as future work rather than silently omitted.

Both signing paths are **optional and operator-held**, which bounds the
exposure: a bundle manifest is signed only when the exporter supplies
an identity, a forgetting attestation only when `forget --sign` is
given, and an unsigned document is imported or verified as
unattested-and-said-so rather than as trusted. The release path carries
no signing key at all — every binary asset ships beside a SHA-256
checksum (PQ-safe), and the workflow emits no build-provenance
attestation today, so there is nothing there to migrate and nothing
there to over-claim either.

## The honest boundary

This page describes quantum-resistant **cryptography**: mathematics
that resists a quantum adversary, running on ordinary hardware.
Nothing in undercroft processes anything on a quantum computer.
"Quantum retrieval", "quantum memory" and their marketing relatives
are vapor, and this project does not claim them — a search here is
BM25, cosine similarity and a reranker, exactly as documented, and it
would be exactly as fast on the day a quantum computer exists as it
was the day before.
