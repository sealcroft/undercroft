//! Record sealing: XChaCha20-Poly1305 AEAD + HMAC-SHA256 integrity tags.
//!
//! Encryption gives confidentiality + authenticity of the content blob;
//! the separate HMAC (independent key) covers the *whole record* — id,
//! metadata, and at-rest content — so metadata tampering in the database
//! is detected even for records whose content is stored in plaintext
//! (`hmac-only` vaults). The AEAD associated data binds vault id and
//! record id, so a sealed blob cannot be replayed into another vault or
//! another record slot.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::keys::SecretKey;

pub const NONCE_LEN: usize = 24;
pub const HMAC_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("decryption failed: wrong key or tampered ciphertext")]
    Decrypt,
    #[error("sealed blob too short")]
    Truncated,
    #[error("integrity check failed: record HMAC does not match")]
    BadHmac,
    #[error("stored content is not valid UTF-8")]
    Utf8(#[from] std::string::FromUtf8Error),
}

fn aad(vault_id: &str, record_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + vault_id.len() + record_id.len());
    aad.extend_from_slice(b"undercroft.v1");
    aad.push(0x1f);
    aad.extend_from_slice(vault_id.as_bytes());
    aad.push(0x1f);
    aad.extend_from_slice(record_id.as_bytes());
    aad
}

/// Encrypt content for one record. Output layout: `nonce || ciphertext`.
pub fn seal_content(
    enc_key: &SecretKey,
    vault_id: &str,
    record_id: &str,
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(enc_key.as_bytes().into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad(vault_id, record_id),
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory buffers");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt a `nonce || ciphertext` blob produced by [`seal_content`].
pub fn open_content(
    enc_key: &SecretKey,
    vault_id: &str,
    record_id: &str,
    blob: &[u8],
) -> Result<Vec<u8>, SealError> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(SealError::Truncated);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(enc_key.as_bytes().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &aad(vault_id, record_id),
            },
        )
        .map_err(|_| SealError::Decrypt)
}

/// HMAC-SHA256 tag over a record's canonical bytes.
pub fn record_hmac(mac_key: &SecretKey, canonical: &[u8]) -> [u8; HMAC_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(canonical);
    mac.finalize().into_bytes().into()
}

/// Constant-time verification of a record HMAC.
pub fn verify_hmac(mac_key: &SecretKey, canonical: &[u8], tag: &[u8]) -> Result<(), SealError> {
    let expected = record_hmac(mac_key, canonical);
    if expected.ct_eq(tag).into() {
        Ok(())
    } else {
        Err(SealError::BadHmac)
    }
}

/// One link of the vault's tamper-evident audit chain:
/// `head_{i} = HMAC(mac_key, head_{i-1} || record_tag)`.
pub fn chain_next(mac_key: &SecretKey, prev_head: &[u8], record_tag: &[u8]) -> [u8; HMAC_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(prev_head);
    mac.update(record_tag);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{derive_vault_key, load_or_create_master, new_vault_salt};
    use tempfile::tempdir;

    fn keys() -> (SecretKey, SecretKey) {
        let dir = tempdir().unwrap();
        let master = load_or_create_master(dir.path(), None).unwrap();
        let salt = new_vault_salt();
        (
            derive_vault_key(&master, &salt, "v", "enc"),
            derive_vault_key(&master, &salt, "v", "mac"),
        )
    }

    #[test]
    fn seal_open_roundtrip() {
        let (enc, _) = keys();
        let blob = seal_content(&enc, "v", "r1", b"the exact original text");
        let out = open_content(&enc, "v", "r1", &blob).unwrap();
        assert_eq!(out, b"the exact original text");
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (enc, _) = keys();
        let mut blob = seal_content(&enc, "v", "r1", b"secret");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(
            open_content(&enc, "v", "r1", &blob),
            Err(SealError::Decrypt)
        ));
    }

    #[test]
    fn cross_record_replay_rejected() {
        let (enc, _) = keys();
        let blob = seal_content(&enc, "v", "r1", b"secret");
        // Same vault, different record id — AAD mismatch must fail.
        assert!(open_content(&enc, "v", "r2", &blob).is_err());
        // Different vault id — must also fail.
        assert!(open_content(&enc, "other", "r1", &blob).is_err());
    }

    #[test]
    fn hmac_detects_any_flip() {
        let (_, mac) = keys();
        let tag = record_hmac(&mac, b"canonical bytes");
        assert!(verify_hmac(&mac, b"canonical bytes", &tag).is_ok());
        assert!(verify_hmac(&mac, b"canonical bytez", &tag).is_err());
        let mut bad = tag;
        bad[0] ^= 0x80;
        assert!(verify_hmac(&mac, b"canonical bytes", &bad).is_err());
    }

    #[test]
    fn chain_is_order_sensitive() {
        let (_, mac) = keys();
        let t1 = record_hmac(&mac, b"one");
        let t2 = record_hmac(&mac, b"two");
        let genesis = [0u8; HMAC_LEN];
        let ab = chain_next(&mac, &chain_next(&mac, &genesis, &t1), &t2);
        let ba = chain_next(&mac, &chain_next(&mac, &genesis, &t2), &t1);
        assert_ne!(ab, ba);
    }
}
