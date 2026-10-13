//! Record sealing: XChaCha20-Poly1305 AEAD + HMAC-SHA256 integrity tags.
//!
//! Encryption gives confidentiality + authenticity of the content blob;
//! the separate HMAC (independent key) covers a row's id, metadata and
//! at-rest content, so metadata tampering in the database is detected even
//! for records whose content is stored in plaintext (`hmac-only` vaults).
//! The AEAD associated data binds vault id and record id, so a sealed blob
//! cannot be replayed into another vault or another record slot.
//!
//! **A tag proves a run of bytes, and only the encoding decides whether that
//! run has one reading** (ROADMAP O406). The version-1 row canonicals joined
//! their fields with a separator byte, no lengths and no table domain, under
//! one key — so a writer WITHOUT the key could move a field boundary to a
//! separator inside a field, or carry one table's row and tag onto another
//! table's row, and the tag still verified. This module said the HMAC
//! "covers the *whole record*" until O406, which was true of the bytes and
//! false of the fields. The version-2 row canonical ([`RowEncoder`]) is
//! unambiguous by construction: a per-table domain first, every required
//! field length-prefixed, every optional field a numbered TLV, under a key
//! of its own ([`RowFormat::V2`]).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::keys::SecretKey;

/// XChaCha20-Poly1305 nonce length in bytes; a nonce leads every sealed blob.
pub const NONCE_LEN: usize = 24;
/// Length of a record's HMAC-SHA256 tag in bytes.
pub const HMAC_LEN: usize = 32;

/// Everything opening a sealed record or checking a tag can refuse.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// AEAD open failed: wrong key, or tampered ciphertext.
    #[error("decryption failed: wrong key or tampered ciphertext")]
    Decrypt,
    /// The blob is shorter than a nonce plus a tag.
    #[error("sealed blob too short")]
    Truncated,
    /// The record's HMAC does not match — the integrity verdict.
    #[error("integrity check failed: record HMAC does not match")]
    BadHmac,
    // A `Utf8(#[from] FromUtf8Error)` variant stood here, documented as
    // "the opened content is not UTF-8", and nothing ever converted into
    // it: `open_content` returns bytes, and both store readers map a UTF-8
    // failure to their own verdicts. Deleted under ROADMAP O115 — its
    // `#[from]` is what the mint-site gate exempts, so this one was found
    // by reading, and the exemption is that gate's stated residue.
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

/// One link of the vault's tamper-evident audit chain, **version 1**:
/// `head_{i} = HMAC(mac_key, head_{i-1} || record_tag)`.
///
/// It folds the TAG alone, so an audit row's label and time sit outside it
/// (ROADMAP O233). Kept for the rows a vault wrote before its chain switched
/// to [`chain_next_v2`], and for the forget attestations minted over them.
pub fn chain_next(mac_key: &SecretKey, prev_head: &[u8], record_tag: &[u8]) -> [u8; HMAC_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(prev_head);
    mac.update(record_tag);
    mac.finalize().into_bytes().into()
}

/// The domain string every version-2 chain step begins with.
pub const CHAIN_V2_DOMAIN: &[u8] = b"undercroft.chain.v2";

/// One link of the audit chain, **version 2** (ROADMAP O233): the record's
/// label and time ride in the step with its tag.
///
/// `head_i = HMAC(chain_key, "undercroft.chain.v2" ‖ lp(head_{i-1}) ‖
/// lp(record_id) ‖ lp(record_tag) ‖ lp(at))`, where `lp` prefixes a field with
/// its length as a u64, little-endian.
///
/// **Every field is length-prefixed, the head included**, because a delimiter
/// is injective only while no field contains it and a prefix is injective by
/// construction — `Vault::sample_rank`'s argument. The head is 32 bytes on
/// every row this store writes, and is prefixed anyway: it arrives hex-decoded
/// from a column, and a field whose length is merely expected is not one whose
/// length is bound.
///
/// **Keyed with its own subkey** (label `chain`), never the record-tag key:
/// heads leave the vault on `/v1` and to the orchestrator, and the tree keeps a
/// keyed output that leaves the record-tag domain on a subkey of its own.
pub fn chain_next_v2(
    chain_key: &SecretKey,
    prev_head: &[u8],
    record_id: &str,
    record_tag: &[u8],
    at: &str,
) -> [u8; HMAC_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(chain_key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(CHAIN_V2_DOMAIN);
    for field in [prev_head, record_id.as_bytes(), record_tag, at.as_bytes()] {
        mac.update(&(field.len() as u64).to_le_bytes());
        mac.update(field);
    }
    mac.finalize().into_bytes().into()
}

/// The prefix of every version-2 row canonical's domain; the table's name
/// follows it (ROADMAP O406 item 1).
pub const ROW_V2_DOMAIN: &str = "undercroft.row.v2/";

/// Which row-canonical format a tag is computed in — the vault's TAG REGIME
/// (ROADMAP O406 item 4), decided by one commitment record in the audit
/// chain and never per row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowFormat {
    /// The separator-joined canonicals every vault wrote before O406, under
    /// the `mac` subkey. A vault keeps WRITING this until its walk commits,
    /// so no vault holds rows of both formats.
    V1,
    /// The length-prefixed, table-domained canonical, under the `row`
    /// subkey. A vault in this regime never accepts a version-1 tag.
    V2,
}

impl RowFormat {
    /// The manifest version a vault holding rows in this format must carry
    /// (ROADMAP O406 item 7): version 2 is what fences every older binary
    /// out of a walked vault — 1.6.1 and newer as age, 1.6.0 and older as a
    /// manifest whose MAC their canonical does not reproduce.
    pub fn manifest_version(self) -> u32 {
        match self {
            RowFormat::V1 => 1,
            RowFormat::V2 => 2,
        }
    }
}

/// A row's canonical bytes **and the format they were built in** — what
/// [`crate::Vault::row_tag`] takes, so the key a tag is computed under can
/// never be chosen apart from the encoding it covers. Built only by the
/// store's per-table builders (`rows.rs`, one module), never by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowCanonical {
    format: RowFormat,
    bytes: Vec<u8>,
}

impl RowCanonical {
    /// A version-1 canonical, built by the store's one module of version-1
    /// recipes — byte for byte what every tag before O406 covered.
    pub fn v1(bytes: Vec<u8>) -> Self {
        Self {
            format: RowFormat::V1,
            bytes,
        }
    }

    /// The format these bytes were built in.
    pub fn format(&self) -> RowFormat {
        self.format
    }

    /// The bytes the tag covers.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// **The version-2 row canonical** (ROADMAP O406 item 1): one byte string has
/// exactly one parse.
///
/// `lp(domain) ‖ lp(required)* ‖ (u16le(field) ‖ lp(value))*`, where `lp`
/// prefixes a value with its length as a u64, little-endian, and the domain
/// is [`ROW_V2_DOMAIN`] followed by the table. Required fields come in a
/// fixed order, EVERY one length-prefixed — fixed-width ones included, one
/// rule rather than a rule plus exceptions. Optional fields are TLV: a
/// field number, strictly ascending and never reused, then a length-prefixed
/// value; an absent field is OMITTED and a present empty one is written with
/// length 0, so absent is not empty, and a field added later leaves every
/// older row's bytes unchanged — the goal the version-1 extension convention
/// had, reached without the separator-inside-the-branch that made the fact
/// canonical non-injective.
///
/// Misuse — a required field after an optional one, a field number not
/// strictly above the last — panics: it is a defect in a builder, which the
/// per-table tests drive, and an ambiguous canonical must never be emitted.
#[derive(Debug)]
pub struct RowEncoder {
    bytes: Vec<u8>,
    last_field: Option<u16>,
}

impl RowEncoder {
    /// Begin a canonical for `table`.
    pub fn new(table: &str) -> Self {
        let mut bytes = Vec::with_capacity(64);
        let domain_len = ROW_V2_DOMAIN.len() + table.len();
        bytes.extend_from_slice(&(domain_len as u64).to_le_bytes());
        bytes.extend_from_slice(ROW_V2_DOMAIN.as_bytes());
        bytes.extend_from_slice(table.as_bytes());
        Self {
            bytes,
            last_field: None,
        }
    }

    fn lp(&mut self, v: &[u8]) {
        self.bytes
            .extend_from_slice(&(v.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(v);
    }

    /// The next required field.
    pub fn field(mut self, v: &[u8]) -> Self {
        assert!(
            self.last_field.is_none(),
            "a required field after an optional one makes the canonical ambiguous"
        );
        self.lp(v);
        self
    }

    /// An optional field: written as `number ‖ lp(value)` when present, and
    /// not at all when absent.
    pub fn optional(mut self, number: u16, v: Option<&[u8]>) -> Self {
        assert!(
            self.last_field.is_none_or(|last| number > last),
            "optional field numbers must be strictly ascending"
        );
        self.last_field = Some(number);
        if let Some(v) = v {
            self.bytes.extend_from_slice(&number.to_le_bytes());
            self.lp(v);
        }
        self
    }

    /// The finished canonical.
    pub fn finish(self) -> RowCanonical {
        RowCanonical {
            format: RowFormat::V2,
            bytes: self.bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{derive_vault_key, master_key, new_vault_salt};
    use tempfile::tempdir;

    fn keys() -> (SecretKey, SecretKey) {
        let dir = tempdir().unwrap();
        let master = master_key(dir.path(), None, crate::Access::ReadWrite)
            .unwrap()
            .key
            .unwrap();
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

    /// **ROADMAP O233: every field of a version-2 step moves the head**, and
    /// the encoding is injective across field boundaries. The version-1 step
    /// takes no label and no time at all, which is the defect.
    #[test]
    fn a_v2_step_covers_the_label_and_the_time_and_v1_does_not() {
        let (_, key) = keys();
        let tag = record_hmac(&key, b"one");
        let genesis = [0u8; HMAC_LEN];
        let base = chain_next_v2(&key, &genesis, "trust/secret", &tag, "2026-09-19T00:00:00Z");
        assert_ne!(
            base,
            chain_next_v2(&key, &genesis, "read/x", &tag, "2026-09-19T00:00:00Z"),
            "a relabel moves the head"
        );
        assert_ne!(
            base,
            chain_next_v2(&key, &genesis, "trust/secret", &tag, "2026-09-18T00:00:00Z"),
            "a re-timed record moves the head"
        );
        assert_ne!(
            base,
            chain_next_v2(
                &key,
                &genesis,
                "trust/secret",
                &record_hmac(&key, b"two"),
                "2026-09-19T00:00:00Z"
            ),
            "a changed tag moves the head"
        );
        let mut other = genesis;
        other[0] = 1;
        assert_ne!(
            base,
            chain_next_v2(&key, &other, "trust/secret", &tag, "2026-09-19T00:00:00Z"),
            "the previous head moves the head"
        );
        // Injective across a boundary: bytes moved from one field into its
        // neighbour are a different step, which a delimiter-free concatenation
        // would not guarantee.
        assert_ne!(
            chain_next_v2(&key, &genesis, "ab", b"c", "t"),
            chain_next_v2(&key, &genesis, "a", b"bc", "t"),
        );
        assert_ne!(
            chain_next_v2(&key, &genesis, "a", b"b", "ct"),
            chain_next_v2(&key, &genesis, "a", b"bc", "t"),
        );
        // Domain-separated from v1 even over the same key and the same tag.
        assert_ne!(&base[..], &chain_next(&key, &genesis, &tag)[..]);
    }

    /// ROADMAP O406 P15g, the encoder half: every byte value in every field,
    /// a boundary moved by any amount, absent against empty, and the table
    /// domain each give a different canonical — the properties the
    /// version-1 separator join lacked. The per-table builders are driven in
    /// the store's `rows.rs`.
    #[test]
    fn the_v2_row_encoder_has_one_parse() {
        let enc = |t: &str, a: &[u8], b: &[u8], o: Option<&[u8]>| {
            RowEncoder::new(t)
                .field(a)
                .field(b)
                .optional(1, o)
                .finish()
                .bytes()
                .to_vec()
        };
        // A boundary moved by one byte, for every byte value — including the
        // separators the version-1 canonicals used (0x1b–0x1f).
        for byte in 0u8..=255 {
            let whole = [b'a', byte, b'b'];
            for cut in 0..=whole.len() {
                for other in 0..=whole.len() {
                    if cut == other {
                        continue;
                    }
                    assert_ne!(
                        enc("t", &whole[..cut], &whole[cut..], None),
                        enc("t", &whole[..other], &whole[other..], None),
                        "a moved boundary over byte {byte:#04x} keeps the canonical"
                    );
                }
            }
        }
        // Absent is not empty, and an optional is not a required field.
        assert_ne!(enc("t", b"a", b"b", None), enc("t", b"a", b"b", Some(b"")));
        assert_ne!(enc("t", b"a", b"", Some(b"b")), enc("t", b"a", b"b", None));
        // The table domain separates two tables over identical fields.
        assert_ne!(
            enc("drawer", b"a", b"b", None),
            enc("fact", b"a", b"b", None)
        );
        // A field number moves the bytes even over the same value.
        assert_ne!(
            RowEncoder::new("t").optional(1, Some(b"x")).finish(),
            RowEncoder::new("t").optional(2, Some(b"x")).finish()
        );
        // A field added later leaves an older row's bytes as they were.
        assert_eq!(
            RowEncoder::new("t").field(b"a").finish(),
            RowEncoder::new("t").field(b"a").optional(9, None).finish()
        );
        assert_eq!(enc("t", b"a", b"b", None)[..8], 19u64.to_le_bytes());
    }

    #[test]
    #[should_panic(expected = "strictly ascending")]
    fn a_v2_field_number_out_of_order_is_refused() {
        let _ = RowEncoder::new("t")
            .optional(2, None)
            .optional(2, Some(b"x"));
    }

    #[test]
    #[should_panic(expected = "required field after an optional")]
    fn a_v2_required_field_after_an_optional_is_refused() {
        let _ = RowEncoder::new("t").optional(1, None).field(b"x");
    }
}
