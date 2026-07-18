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
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
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
