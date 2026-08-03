//! Recipient-encrypted export bundles.
//!
//! `undercroft export --to <recipient>` seals the export so only the holder
//! of the matching identity key can read it — a backup or migration file
//! never has to exist in plaintext. Construction (age-style
//! ephemeral-static):
//!
//! * recipient identity = X25519 keypair (`keygen`); the secret stays in a
//!   0600 file, the public half is the shareable hex "recipient string";
//! * each bundle uses a **fresh ephemeral** X25519 keypair; the file key is
//!   `HKDF-SHA256(salt = eph_pub ‖ recipient_pub, ikm = DH(eph, recipient),
//!   info = "undercroft.v1/bundle")`;
//! * payload sealed with XChaCha20-Poly1305 (random 24-byte nonce), with
//!   the magic + ephemeral public key bound as AAD — a bundle spliced onto
//!   a different header fails to open;
//! * layout: `UNDERCROFT-BUNDLE-1` (18 bytes) ‖ eph_pub (32) ‖ nonce (24) ‖
//!   ciphertext.
//!
//! Compromise of a bundle file alone reveals nothing without the identity
//! key; compromise of the identity key does not affect the palace's own
//! at-rest keys (they are unrelated derivations).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Bundle file magic (also AAD, with the ephemeral key).
pub const BUNDLE_MAGIC: &[u8; 18] = b"UNDERCROFT-BUNDLE-1";

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("not a undercroft bundle (bad magic)")]
    BadMagic,
    #[error("bundle is truncated")]
    Truncated,
    #[error("recipient string is not a 32-byte hex public key")]
    BadRecipient,
    #[error("identity is not a 32-byte hex secret key")]
    BadIdentity,
    #[error("bundle failed to open — wrong identity key or corrupted file")]
    Open,
    #[error("signing key is not a 32-byte hex ed25519 secret")]
    BadSigner,
    #[error("manifest signature is missing or does not verify against its sender")]
    BadSignature,
    #[error("manifest is malformed: {0}")]
    BadManifest(String),
    #[error("bundle expired at {0}")]
    Expired(String),
}

/// Generate a recipient identity: `(secret_hex, recipient_hex)`. The secret
/// belongs in a private file; the recipient string is shareable.
pub fn keygen() -> (String, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (
        hex::encode(secret.as_bytes()),
        hex::encode(public.as_bytes()),
    )
}

/// The public recipient string for a stored identity secret.
pub fn recipient_of(secret_hex: &str) -> Result<String, BundleError> {
    let secret = parse_secret(secret_hex)?;
    Ok(hex::encode(PublicKey::from(&secret).as_bytes()))
}

/// True if `bytes` starts with the bundle magic.
pub fn is_bundle(bytes: &[u8]) -> bool {
    bytes.len() >= BUNDLE_MAGIC.len() && &bytes[..BUNDLE_MAGIC.len()] == BUNDLE_MAGIC
}

/// Seal `plaintext` so only `recipient_hex`'s identity can open it.
pub fn encrypt_for(recipient_hex: &str, plaintext: &[u8]) -> Result<Vec<u8>, BundleError> {
    let recipient = parse_public(recipient_hex).map_err(|_| BundleError::BadRecipient)?;
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&recipient);
    let key = file_key(eph_pub.as_bytes(), recipient.as_bytes(), shared.as_bytes());

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut aad = Vec::with_capacity(BUNDLE_MAGIC.len() + 32);
    aad.extend_from_slice(BUNDLE_MAGIC);
    aad.extend_from_slice(eph_pub.as_bytes());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| BundleError::Open)?;

    let mut out = Vec::with_capacity(BUNDLE_MAGIC.len() + 32 + NONCE_LEN + ct.len());
    out.extend_from_slice(BUNDLE_MAGIC);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a bundle with the identity secret that matches its recipient.
pub fn decrypt_with(secret_hex: &str, bundle: &[u8]) -> Result<Vec<u8>, BundleError> {
    if !is_bundle(bundle) {
        return Err(BundleError::BadMagic);
    }
    let rest = &bundle[BUNDLE_MAGIC.len()..];
    if rest.len() < 32 + NONCE_LEN + 16 {
        return Err(BundleError::Truncated);
    }
    let (eph_pub_bytes, rest) = rest.split_at(32);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let eph_pub_arr: [u8; 32] = eph_pub_bytes.try_into().expect("split_at(32)");
    let eph_pub = PublicKey::from(eph_pub_arr);

    let secret = parse_secret(secret_hex)?;
    let my_pub = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&eph_pub);
    let key = file_key(eph_pub.as_bytes(), my_pub.as_bytes(), shared.as_bytes());

    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut aad = Vec::with_capacity(BUNDLE_MAGIC.len() + 32);
    aad.extend_from_slice(BUNDLE_MAGIC);
    aad.extend_from_slice(eph_pub_bytes);
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| BundleError::Open)
}

// ---- signed manifests -------------------------------------------------
//
// The manifest is the first line of the (encrypted) payload: what a bundle
// claims to be — sender, scope, trust class, expiry, record counts and a
// provenance summary — signed as a whole with Ed25519 beside the X25519
// recipient flow. Recipient encryption says who may READ a bundle; the
// manifest signature says who WROTE it, which is the half federation is
// meaningless without. Legacy bundles (payloads with no manifest line)
// stay importable: absence of a manifest is a recorded fact, never an
// error, but a caller that demands a sender gets `BadSignature` rather
// than silence.

/// Record counts a manifest declares, verified against the payload at
/// import so a truncated or padded record stream is caught even when the
/// signature is not checked.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManifestCounts {
    pub drawers: u64,
    #[serde(default)]
    pub kg_entities: u64,
    #[serde(default)]
    pub kg_triples: u64,
    #[serde(default)]
    pub tunnels: u64,
}

/// The signed statement at the head of a bundle payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BundleManifest {
    /// Manifest format version (1).
    pub version: u32,
    /// Source vault id — scope, not routing: the importer chooses the
    /// destination vault and this records provenance only.
    pub vault: String,
    /// Source vault security level ("sealed" | "hmac-only").
    pub level: String,
    /// When the bundle was produced (RFC 3339).
    pub created_at: String,
    /// What the payload holds, by record type.
    pub counts: ManifestCounts,
    /// Provenance summary: the embedder identity the vectors (if any) were
    /// produced under, and the source vault's audit-chain head at export.
    /// Neither is importable state — the destination keeps its own — but
    /// both say where the records came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_head: Option<String>,
    /// Sender-declared trust class for the receiving deployment's policy —
    /// a CLAIM by the sender, never a trust boundary by itself (the
    /// docs/LABELS.md rule: labels a counterparty declares are ergonomics;
    /// trust is assigned by the receiving principal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    /// RFC 3339 instant after which the bundle must be refused at import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Ed25519 public key of the sender (hex), when signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// SHA-256 (hex) of the record bytes that follow the manifest line —
    /// inside the signature, so the attestation covers the whole payload.
    pub payload_sha256: String,
    /// Ed25519 signature (hex) over [`BundleManifest::canonical`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// The one JSON key a payload's first line uses to declare a manifest —
/// distinct from every record shape, so detection is unambiguous.
const MANIFEST_LINE_KEY: &str = "undercroft_manifest";

impl BundleManifest {
    /// Deterministic signing bytes: every declared field except the
    /// signature itself, `0x1f`-separated in fixed order (the vault
    /// `Manifest::canonical` precedent — never serde output, whose field
    /// order and whitespace are not a contract).
    pub fn canonical(&self) -> Vec<u8> {
        let counts = format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.counts.drawers,
            self.counts.kg_entities,
            self.counts.kg_triples,
            self.counts.tunnels
        );
        let fields = [
            self.version.to_string(),
            self.vault.clone(),
            self.level.clone(),
            self.created_at.clone(),
            counts,
            self.embedder.clone().unwrap_or_default(),
            self.chain_head.clone().unwrap_or_default(),
            self.trust.clone().unwrap_or_default(),
            self.expires.clone().unwrap_or_default(),
            self.sender.clone().unwrap_or_default(),
            self.payload_sha256.clone(),
        ];
        fields.join("\u{1f}").into_bytes()
    }

    /// Sign in place: sets `sender` from the signing key and `sig` over the
    /// canonical bytes.
    pub fn sign(&mut self, signing_secret_hex: &str) -> Result<(), BundleError> {
        let key = parse_signing(signing_secret_hex)?;
        self.sender = Some(hex::encode(key.verifying_key().as_bytes()));
        let sig: Signature = key.sign(&self.canonical());
        self.sig = Some(hex::encode(sig.to_bytes()));
        Ok(())
    }

    /// Verify the signature against the embedded sender key. An unsigned
    /// manifest fails — call this only when attestation is demanded; use
    /// [`BundleManifest::verify_against`] to also pin WHO the sender must be
    /// (an embedded key alone proves consistency, not identity).
    pub fn verify(&self) -> Result<(), BundleError> {
        let (Some(sender), Some(sig)) = (self.sender.as_deref(), self.sig.as_deref()) else {
            return Err(BundleError::BadSignature);
        };
        let key_bytes: [u8; 32] = hex::decode(sender)
            .map_err(|_| BundleError::BadSignature)?
            .try_into()
            .map_err(|_| BundleError::BadSignature)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| BundleError::BadSignature)?;
        let sig_bytes: [u8; 64] = hex::decode(sig)
            .map_err(|_| BundleError::BadSignature)?
            .try_into()
            .map_err(|_| BundleError::BadSignature)?;
        key.verify(&self.canonical(), &Signature::from_bytes(&sig_bytes))
            .map_err(|_| BundleError::BadSignature)
    }

    /// Verify the signature AND that the sender is exactly `expected_hex`.
    pub fn verify_against(&self, expected_hex: &str) -> Result<(), BundleError> {
        if self.sender.as_deref() != Some(expected_hex.trim()) {
            return Err(BundleError::BadSignature);
        }
        self.verify()
    }

    /// Whether the bundle has expired as of `now` (RFC 3339). A manifest
    /// with no expiry never expires; an unparseable expiry counts as
    /// expired — refusing is the safe reading of a malformed claim.
    pub fn expired_at(&self, now: &str) -> bool {
        use time::format_description::well_known::Rfc3339;
        use time::OffsetDateTime;
        let Some(exp) = self.expires.as_deref() else {
            return false;
        };
        let (Ok(exp), Ok(now)) = (
            OffsetDateTime::parse(exp, &Rfc3339),
            OffsetDateTime::parse(now, &Rfc3339),
        ) else {
            return true;
        };
        now >= exp
    }
}

/// Generate a signing identity: `(signing_secret_hex, sender_hex)`. The
/// secret belongs in a private file beside the recipient identity; the
/// sender string is what importers pin.
pub fn sign_keygen() -> (String, String) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    (
        hex::encode(key.to_bytes()),
        hex::encode(key.verifying_key().as_bytes()),
    )
}

/// The public sender string for a stored signing secret.
pub fn signer_of(signing_secret_hex: &str) -> Result<String, BundleError> {
    let key = parse_signing(signing_secret_hex)?;
    Ok(hex::encode(key.verifying_key().as_bytes()))
}

/// SHA-256 hex of the record bytes — what `payload_sha256` declares.
pub fn payload_digest(records: &[u8]) -> String {
    hex::encode(Sha256::digest(records))
}

/// Frame a payload: the manifest line, then the record bytes verbatim.
pub fn frame_payload(manifest: &BundleManifest, records: &[u8]) -> Vec<u8> {
    let line = serde_json::json!({ MANIFEST_LINE_KEY: manifest }).to_string();
    let mut out = Vec::with_capacity(line.len() + 1 + records.len());
    out.extend_from_slice(line.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(records);
    out
}

/// Split a payload into its manifest (when the first line declares one)
/// and the record bytes. A payload with no manifest line is a legacy
/// export: `(None, everything)` — importable, unattested, and said so.
pub fn split_payload(payload: &[u8]) -> Result<(Option<BundleManifest>, &[u8]), BundleError> {
    let first_len = payload
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(payload.len());
    let first = &payload[..first_len];
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(first) else {
        return Ok((None, payload));
    };
    let Some(m) = value.get(MANIFEST_LINE_KEY) else {
        return Ok((None, payload));
    };
    let manifest: BundleManifest =
        serde_json::from_value(m.clone()).map_err(|e| BundleError::BadManifest(e.to_string()))?;
    let rest = if first_len < payload.len() {
        &payload[first_len + 1..]
    } else {
        &payload[payload.len()..]
    };
    // The declared digest is checked here, unconditionally: even an
    // unsigned manifest must describe the bytes it travels with.
    if payload_digest(rest) != manifest.payload_sha256 {
        return Err(BundleError::BadManifest(
            "payload does not match the manifest's declared digest".into(),
        ));
    }
    Ok((Some(manifest), rest))
}

fn parse_signing(hex_str: &str) -> Result<SigningKey, BundleError> {
    let bytes: [u8; 32] = hex::decode(hex_str.trim())
        .map_err(|_| BundleError::BadSigner)?
        .try_into()
        .map_err(|_| BundleError::BadSigner)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn file_key(eph_pub: &[u8], recipient_pub: &[u8], shared: &[u8]) -> [u8; KEY_LEN] {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub);
    salt.extend_from_slice(recipient_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; KEY_LEN];
    hk.expand(b"undercroft.v1/bundle", &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn parse_secret(hex_str: &str) -> Result<StaticSecret, BundleError> {
    let bytes: [u8; 32] = hex::decode(hex_str.trim())
        .map_err(|_| BundleError::BadIdentity)?
        .try_into()
        .map_err(|_| BundleError::BadIdentity)?;
    Ok(StaticSecret::from(bytes))
}

fn parse_public(hex_str: &str) -> Result<PublicKey, BundleError> {
    let bytes: [u8; 32] = hex::decode(hex_str.trim())
        .map_err(|_| BundleError::BadRecipient)?
        .try_into()
        .map_err(|_| BundleError::BadRecipient)?;
    Ok(PublicKey::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let (secret, recipient) = keygen();
        let bundle = encrypt_for(&recipient, b"verbatim words survive").unwrap();
        assert!(is_bundle(&bundle));
        let plain = decrypt_with(&secret, &bundle).unwrap();
        assert_eq!(plain, b"verbatim words survive");
        assert_eq!(recipient_of(&secret).unwrap(), recipient);
    }

    #[test]
    fn wrong_identity_fails() {
        let (_, recipient) = keygen();
        let (other_secret, _) = keygen();
        let bundle = encrypt_for(&recipient, b"private").unwrap();
        assert!(matches!(
            decrypt_with(&other_secret, &bundle),
            Err(BundleError::Open)
        ));
    }

    #[test]
    fn tampered_bundle_fails() {
        let (secret, recipient) = keygen();
        let mut bundle = encrypt_for(&recipient, b"private").unwrap();
        let last = bundle.len() - 1;
        bundle[last] ^= 0x01;
        assert!(matches!(
            decrypt_with(&secret, &bundle),
            Err(BundleError::Open)
        ));
        // Splicing the ciphertext under a different header must fail too
        // (the ephemeral key is AAD).
        let mut spliced = encrypt_for(&recipient, b"other").unwrap();
        let tail = bundle[BUNDLE_MAGIC.len() + 32..].to_vec();
        spliced.truncate(BUNDLE_MAGIC.len() + 32);
        spliced.extend_from_slice(&tail);
        assert!(decrypt_with(&secret, &spliced).is_err());
    }

    #[test]
    fn ephemeral_keys_differ_per_bundle() {
        let (_, recipient) = keygen();
        let a = encrypt_for(&recipient, b"same words").unwrap();
        let b = encrypt_for(&recipient, b"same words").unwrap();
        assert_ne!(a, b, "fresh ephemeral key + nonce per bundle");
    }

    fn manifest(records: &[u8]) -> BundleManifest {
        BundleManifest {
            version: 1,
            vault: "v".into(),
            level: "sealed".into(),
            created_at: "2026-08-03T12:00:00Z".into(),
            counts: ManifestCounts {
                drawers: 2,
                ..Default::default()
            },
            embedder: Some("undercroft-hash-v3".into()),
            chain_head: None,
            trust: Some("partner".into()),
            expires: None,
            sender: None,
            payload_sha256: payload_digest(records),
            sig: None,
        }
    }

    #[test]
    fn signed_manifest_roundtrips_and_verifies() {
        let records = b"{\"drawer\":{}}\n{\"drawer\":{}}\n";
        let (signing, sender) = sign_keygen();
        let mut m = manifest(records);
        m.sign(&signing).unwrap();
        let payload = frame_payload(&m, records);
        let (got, rest) = split_payload(&payload).unwrap();
        let got = got.expect("manifest detected");
        assert_eq!(rest, records);
        got.verify().unwrap();
        got.verify_against(&sender).unwrap();
        assert_eq!(signer_of(&signing).unwrap(), sender);
        // A different sender pin is refused even though the sig verifies.
        let (_, other) = sign_keygen();
        assert!(matches!(
            got.verify_against(&other),
            Err(BundleError::BadSignature)
        ));
    }

    #[test]
    fn tampered_records_or_manifest_are_caught() {
        let records = b"{\"drawer\":{\"id\":\"a\"}}\n";
        let (signing, _) = sign_keygen();
        let mut m = manifest(records);
        m.sign(&signing).unwrap();
        // Records swapped under the manifest: the declared digest catches
        // it before any signature is even consulted.
        let payload = frame_payload(&m, b"{\"drawer\":{\"id\":\"b\"}}\n");
        assert!(matches!(
            split_payload(&payload),
            Err(BundleError::BadManifest(_))
        ));
        // A field edited after signing: digest matches, signature fails.
        let mut edited = m.clone();
        edited.trust = Some("core".into());
        assert!(matches!(edited.verify(), Err(BundleError::BadSignature)));
        // Unsigned manifests exist (legacy senders) but never claim to
        // verify.
        let unsigned = manifest(records);
        assert!(matches!(unsigned.verify(), Err(BundleError::BadSignature)));
    }

    #[test]
    fn expiry_is_enforced_and_malformed_expiry_refuses() {
        let records = b"";
        let mut m = manifest(records);
        assert!(
            !m.expired_at("2026-08-03T12:00:00Z"),
            "no expiry, no refusal"
        );
        m.expires = Some("2026-08-04T00:00:00Z".into());
        assert!(!m.expired_at("2026-08-03T23:59:59Z"));
        assert!(m.expired_at("2026-08-04T00:00:00Z"));
        m.expires = Some("not a date".into());
        assert!(
            m.expired_at("2026-08-03T12:00:00Z"),
            "malformed expiry refuses"
        );
    }

    #[test]
    fn legacy_payload_has_no_manifest_and_still_splits() {
        let legacy = b"{\"id\":\"drawer-1\",\"content\":\"words\"}\n";
        let (m, rest) = split_payload(legacy).unwrap();
        assert!(m.is_none());
        assert_eq!(rest, legacy);
    }

    #[test]
    fn junk_inputs_error_cleanly() {
        assert!(matches!(
            decrypt_with("00", b"UNDERCROFT-BUNDLE-1"),
            Err(BundleError::Truncated)
        ));
        assert!(matches!(
            decrypt_with("00", b"not a bundle at all"),
            Err(BundleError::BadMagic)
        ));
        assert!(matches!(
            encrypt_for("zz", b"x"),
            Err(BundleError::BadRecipient)
        ));
    }
}
