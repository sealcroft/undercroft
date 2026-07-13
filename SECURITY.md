# Security Policy

## Supported versions

Security fixes land on the current 0.x line.

## Threat model

Undercroft's vault layer protects memories **at rest**: disk theft,
cross-vault bleed, and offline tampering of the database or manifest
(XChaCha20-Poly1305 AEAD, per-vault HKDF-SHA256 key derivation,
HMAC-SHA256 record tags plus a tamper-evident audit chain). It does **not**
defend against an attacker who can read process memory while a vault is
unlocked, nor against a compromised host OS.

Details are documented in `crates/undercroft-vault/src/lib.rs`.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub
issues.** Use GitHub Private Vulnerability Reporting on this repository
(Security → Report a vulnerability). Include reproduction steps and the
commit hash. You can expect an acknowledgement within a week.
