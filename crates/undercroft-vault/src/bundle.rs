//! Recipient-encrypted export bundles.
//!
//! `undercroft export --to <recipient>` seals the export so only the holder
//! of the matching identity key can read it — a backup or migration file
//! never has to exist in plaintext. Two wire formats, one construction
//! family (age-style ephemeral-static):
//!
//! * **v2, the default since C3.4** — hybrid X25519 + ML-KEM-768. A
//!   recipient identity is an X25519 keypair AND an ML-KEM-768 keypair
//!   (`keygen`; strings carry the `pq1` prefix). Each bundle uses a fresh
//!   ephemeral X25519 keypair and a fresh ML-KEM encapsulation against the
//!   recipient's KEM key; the file key is `HKDF-SHA256(salt = eph_pub ‖
//!   recipient_x_pub, ikm = DH(eph, recipient_x) ‖ kem_shared, info =
//!   "undercroft.v2/bundle")` — an attacker must break BOTH the curve and
//!   the lattice, which is what closes harvest-now-decrypt-later against
//!   the one asymmetric exchange in the codebase (the ROADMAP C3.4
//!   inventory: everything else at rest is symmetric and already at the
//!   accepted PQ bar).
//!   Layout: `UNDERCROFT-BUNDLE-2` ‖ eph_pub (32) ‖ kem_ct (1088) ‖
//!   nonce (24) ‖ ciphertext, with magic + eph_pub + kem_ct all bound as
//!   AAD — a spliced header, a swapped encapsulation, or a magic rewritten
//!   to fake the other version all fail to open.
//! * **v1, still read and still writable to legacy recipients** — X25519
//!   only: `HKDF-SHA256(salt = eph_pub ‖ recipient_pub, ikm = DH(eph,
//!   recipient), info = "undercroft.v1/bundle")`, layout
//!   `UNDERCROFT-BUNDLE-1` ‖ eph_pub (32) ‖ nonce (24) ‖ ciphertext.
//!   A bare-hex recipient string selects it; a hybrid recipient NEVER
//!   silently downgrades to it (pinned by test).
//!
//! Payloads seal with XChaCha20-Poly1305 (random 24-byte nonce) in both.
//! Compromise of a bundle file alone reveals nothing without the identity
//! key; compromise of the identity key does not affect the palace's own
//! at-rest keys (they are unrelated derivations). Honest boundary, stated
//! once for the whole C3.4 posture: this is quantum-resistant
//! **cryptography** — nothing here processes anything on a quantum
//! computer, and no such claim exists anywhere in this project.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

type KemDk = ml_kem::kem::DecapsulationKey<MlKem768Params>;
type KemEk = ml_kem::kem::EncapsulationKey<MlKem768Params>;

/// What `open_header` recovers from a bundle's head: how many leading bytes
/// the header and nonce occupy, the AAD (which IS the header), the file key,
/// and the nonce.
type OpenedHeader = (usize, Vec<u8>, [u8; KEY_LEN], [u8; NONCE_LEN]);

/// v1 bundle file magic (also AAD, with the ephemeral key).
pub const BUNDLE_MAGIC: &[u8; 19] = b"UNDERCROFT-BUNDLE-1";
/// v2 (hybrid X25519 + ML-KEM-768) magic (also AAD, with the ephemeral
/// key and the KEM ciphertext).
pub const BUNDLE_MAGIC_V2: &[u8; 19] = b"UNDERCROFT-BUNDLE-2";

/// Prefix on hybrid identity/recipient strings. A bare 64-char hex string
/// remains a legacy X25519 key; the prefix is a declared format, not an
/// inference.
pub const HYBRID_PREFIX: &str = "pq1";

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
/// The Poly1305 tag the AEAD appends to every ciphertext. Named because
/// `encrypt_for_into` must reserve room for it before sealing in place.
const TAG_LEN: usize = 16;
/// ML-KEM-768 encoded sizes (FIPS 203).
const KEM_EK_LEN: usize = 1184;
const KEM_DK_LEN: usize = 2400;
const KEM_CT_LEN: usize = 1088;

/// Everything a bundle export or import can refuse.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// The file does not begin with a bundle magic.
    #[error("not a undercroft bundle (bad magic)")]
    BadMagic,
    /// The file ends before its declared contents do.
    #[error("bundle is truncated")]
    Truncated,
    /// The recipient string is neither a 32-byte hex X25519 key nor a `pq1` hybrid key.
    #[error("recipient string is neither a 32-byte hex X25519 key nor a pq1 hybrid key")]
    BadRecipient,
    /// The identity string is neither a 32-byte hex X25519 secret nor a `pq1` hybrid secret.
    #[error("identity is neither a 32-byte hex X25519 secret nor a pq1 hybrid secret")]
    BadIdentity,
    /// The bundle did not open: wrong identity key, or a corrupted file.
    #[error("bundle failed to open — wrong identity key or corrupted file")]
    Open,
    /// A v2 (hybrid) bundle offered to an X25519-only identity. Never silently downgraded.
    #[error(
        "this bundle uses the hybrid post-quantum format and the identity is X25519-only — \
         it was addressed to a pq1 hybrid recipient; use that identity's secret"
    )]
    NeedsHybrid,
    /// The signing key is not a 32-byte hex Ed25519 secret.
    #[error("signing key is not a 32-byte hex ed25519 secret")]
    BadSigner,
    /// The manifest carries no signature, or its signature does not verify against its sender.
    #[error("manifest signature is missing or does not verify against its sender")]
    BadSignature,
    /// The manifest could not be read as one; the message says what was wrong.
    #[error("manifest is malformed: {0}")]
    BadManifest(String),
    /// The bundle declared an expiry that has passed (the instant, RFC 3339).
    /// Raised by the two importers (`undercroft import`, `POST …/import`)
    /// after `BundleManifest::expired_at` — the check lives with the caller
    /// because the clock does.
    #[error("bundle expired at {0}")]
    Expired(String),
    /// Writing a sealed bundle to its sink failed.
    ///
    /// Only [`encrypt_for_into`] can raise this: it hands the caller's sink
    /// the bytes as they are produced instead of returning one buffer, so
    /// unlike every other variant here the failure can be the sink's rather
    /// than the format's.
    #[error("writing bundle: {0}")]
    Io(#[from] std::io::Error),
}

/// What [`BundleManifest::attest`] concluded about a payload's provenance.
///
/// A **result**, never a field: the key it replaces on the wire was
/// `signed`, computed from `sig.is_some()` — presence reported as though it
/// were verification. Nothing here is reachable without a signature check
/// having actually run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    /// No manifest at all — a legacy or hand-built payload.
    NoManifest,
    /// A manifest carrying neither sender nor signature.
    Unsigned,
    /// A signature that verified. `sender` is proven, not claimed.
    Verified {
        /// The sender whose signature verified over the manifest.
        sender: String,
    },
}

impl Attestation {
    /// The one-word status for a wire response or a terminal line.
    pub fn wire_status(&self) -> &'static str {
        match self {
            Attestation::NoManifest | Attestation::Unsigned => "unsigned",
            Attestation::Verified { .. } => "verified",
        }
    }

    /// The sender key, only when it was proven.
    pub fn verified_sender(&self) -> Option<&str> {
        match self {
            Attestation::Verified { sender } => Some(sender.as_str()),
            _ => None,
        }
    }
}

/// A parsed recipient: who a bundle can be addressed to.
enum Recipient {
    X25519(PublicKey),
    Hybrid(PublicKey, Box<KemEk>),
}

/// A parsed identity secret: who can open a bundle.
enum Identity {
    X25519(StaticSecret),
    Hybrid(StaticSecret, Box<KemDk>),
}

/// Generate a recipient identity: `(secret_hex, recipient_hex)` — **hybrid
/// X25519 + ML-KEM-768 since C3.4** (`pq1` prefix on both strings). The
/// secret belongs in a private file; the recipient string is shareable.
/// Legacy bare-hex X25519 identities remain accepted everywhere; only
/// generation moved, because a new identity has no reason to be
/// harvestable.
pub fn keygen() -> (String, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let mut secret_bytes = Vec::with_capacity(32 + KEM_DK_LEN);
    secret_bytes.extend_from_slice(secret.as_bytes());
    secret_bytes.extend_from_slice(&dk.as_bytes());
    let mut public_bytes = Vec::with_capacity(32 + KEM_EK_LEN);
    public_bytes.extend_from_slice(public.as_bytes());
    public_bytes.extend_from_slice(&ek.as_bytes());
    (
        format!("{HYBRID_PREFIX}{}", hex::encode(secret_bytes)),
        format!("{HYBRID_PREFIX}{}", hex::encode(public_bytes)),
    )
}

/// The public recipient string for a stored identity secret, in the same
/// format the secret uses (hybrid secret → hybrid recipient).
pub fn recipient_of(secret_hex: &str) -> Result<String, BundleError> {
    match parse_secret(secret_hex)? {
        Identity::X25519(secret) => Ok(hex::encode(PublicKey::from(&secret).as_bytes())),
        Identity::Hybrid(secret, dk) => {
            let mut out = Vec::with_capacity(32 + KEM_EK_LEN);
            out.extend_from_slice(PublicKey::from(&secret).as_bytes());
            // FIPS 203: the encapsulation key is embedded verbatim inside
            // the decapsulation key (dk = dk_pke ‖ ek ‖ H(ek) ‖ z).
            out.extend_from_slice(&dk.encapsulation_key().as_bytes());
            Ok(format!("{HYBRID_PREFIX}{}", hex::encode(out)))
        }
    }
}

/// True if `bytes` starts with either bundle magic.
pub fn is_bundle(bytes: &[u8]) -> bool {
    bytes.len() >= BUNDLE_MAGIC.len()
        && (&bytes[..BUNDLE_MAGIC.len()] == BUNDLE_MAGIC
            || &bytes[..BUNDLE_MAGIC_V2.len()] == BUNDLE_MAGIC_V2)
}

/// A bundle's header, which is also its AAD, paired with the file key it
/// was derived alongside: magic ‖ ephemeral public key, plus the KEM
/// ciphertext on v2.
///
/// One function because those are one decision. Every byte a reader needs
/// in order to re-derive the key is exactly the run of bytes the AEAD
/// authenticates, so producing them separately is producing two copies of
/// one fact. The recipient string selects the format: a hybrid (`pq1`)
/// recipient always produces a v2 header — never a silent downgrade — and
/// a legacy bare-hex recipient produces a v1 header it can actually open.
fn seal_header(recipient_hex: &str) -> Result<(Vec<u8>, [u8; KEY_LEN]), BundleError> {
    match parse_public(recipient_hex)? {
        Recipient::X25519(recipient) => {
            let eph = EphemeralSecret::random_from_rng(OsRng);
            let eph_pub = PublicKey::from(&eph);
            let shared = eph.diffie_hellman(&recipient);
            let key = file_key(eph_pub.as_bytes(), recipient.as_bytes(), shared.as_bytes());
            let mut header = Vec::with_capacity(BUNDLE_MAGIC.len() + 32);
            header.extend_from_slice(BUNDLE_MAGIC);
            header.extend_from_slice(eph_pub.as_bytes());
            Ok((header, key))
        }
        Recipient::Hybrid(recipient_x, ek) => {
            let eph = EphemeralSecret::random_from_rng(OsRng);
            let eph_pub = PublicKey::from(&eph);
            let x_shared = eph.diffie_hellman(&recipient_x);
            let (kem_ct, kem_shared) = ek
                .encapsulate(&mut OsRng)
                .map_err(|_| BundleError::BadRecipient)?;
            let key = hybrid_file_key(
                eph_pub.as_bytes(),
                recipient_x.as_bytes(),
                x_shared.as_bytes(),
                &kem_shared,
            );
            let mut header = Vec::with_capacity(BUNDLE_MAGIC_V2.len() + 32 + KEM_CT_LEN);
            header.extend_from_slice(BUNDLE_MAGIC_V2);
            header.extend_from_slice(eph_pub.as_bytes());
            header.extend_from_slice(&kem_ct);
            Ok((header, key))
        }
    }
}

/// Seal `plaintext` to `recipient_hex`, writing the bundle to `out` and
/// consuming the caller's buffer.
///
/// Byte-for-byte the bundle [`encrypt_for`] produces — **the format does
/// not move** (ROADMAP O138). What moves is the peak. The previous shape
/// asked for an owned ciphertext and then copied it into a second owned
/// buffer, so a sealed export held THREE whole-payload allocations at
/// once: the caller's plaintext, the ciphertext, and the assembled bundle.
/// Measured on a 361,779-drawer vault whose export is 467.7 MB, that was
/// **1,349 MB peak RSS (3.02x)** — worse than the unsealed peak O113 was
/// filed to fix, on a path neither O113 nor O137 ever measured.
///
/// Here the caller hands its buffer over, the tag is appended IN PLACE,
/// and the header reaches the sink ahead of it, so one allocation serves.
pub fn encrypt_for_into<W: std::io::Write>(
    recipient_hex: &str,
    mut plaintext: Vec<u8>,
    out: &mut W,
) -> Result<u64, BundleError> {
    let (header, key) = seal_header(recipient_hex)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    // Ask for the tag's room before the AEAD does. `encrypt_in_place`
    // appends TAG_LEN bytes, and a Vec that must grow for them reallocates
    // by DOUBLING — which on a 467 MB payload is this entire defect back
    // again, transiently, at the worst possible moment.
    plaintext.reserve(TAG_LEN);
    XChaCha20Poly1305::new((&key).into())
        .encrypt_in_place(XNonce::from_slice(&nonce), &header, &mut plaintext)
        .map_err(|_| BundleError::Open)?;
    out.write_all(&header)?;
    out.write_all(&nonce)?;
    out.write_all(&plaintext)?;
    Ok((header.len() + NONCE_LEN + plaintext.len()) as u64)
}

/// Seal `plaintext` so only `recipient_hex`'s identity can open it,
/// returning the whole bundle in one buffer.
///
/// Prefer [`encrypt_for_into`] for anything vault-sized: this has to copy
/// the caller's slice so the AEAD has a buffer it owns.
pub fn encrypt_for(recipient_hex: &str, plaintext: &[u8]) -> Result<Vec<u8>, BundleError> {
    // The v2 header is the larger of the two, so this over-reserves by
    // KEM_CT_LEN on a v1 bundle and never reallocates on either.
    let mut out = Vec::with_capacity(
        plaintext.len() + BUNDLE_MAGIC_V2.len() + 32 + KEM_CT_LEN + NONCE_LEN + TAG_LEN,
    );
    encrypt_for_into(recipient_hex, plaintext.to_vec(), &mut out)?;
    Ok(out)
}

/// Re-derive a bundle's file key from its header, and report how many
/// leading bytes that header and the nonce occupy.
///
/// The reading half of [`seal_header`], and it exists for the same reason:
/// the AAD and the key come out of one run of bytes, so one function
/// yields both and they cannot drift apart. The bundle's magic selects the
/// path — a v2 bundle demands the hybrid identity's KEM half (an
/// X25519-only secret gets [`BundleError::NeedsHybrid`], never a
/// downgraded attempt); a v1 bundle opens with the X25519 half of either
/// identity form, so upgrading an identity never orphans old backups.
fn open_header(secret_hex: &str, bundle: &[u8]) -> Result<OpenedHeader, BundleError> {
    if !is_bundle(bundle) {
        return Err(BundleError::BadMagic);
    }
    if &bundle[..BUNDLE_MAGIC_V2.len()] == BUNDLE_MAGIC_V2 {
        let rest = &bundle[BUNDLE_MAGIC_V2.len()..];
        if rest.len() < 32 + KEM_CT_LEN + NONCE_LEN + TAG_LEN {
            return Err(BundleError::Truncated);
        }
        let Identity::Hybrid(secret, dk) = parse_secret(secret_hex)? else {
            return Err(BundleError::NeedsHybrid);
        };
        let (eph_pub_bytes, after_eph) = rest.split_at(32);
        let (kem_ct_bytes, after_kem) = after_eph.split_at(KEM_CT_LEN);
        let (nonce_bytes, _) = after_kem.split_at(NONCE_LEN);
        let eph_pub_arr: [u8; 32] = eph_pub_bytes.try_into().expect("split_at(32)");
        let eph_pub = PublicKey::from(eph_pub_arr);
        let my_pub = PublicKey::from(&secret);
        let x_shared = secret.diffie_hellman(&eph_pub);
        let kem_ct = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct_bytes)
            .map_err(|_| BundleError::Truncated)?;
        // ML-KEM decapsulation is implicit-rejection: a forged ct yields
        // a wrong shared secret, and the AEAD open below fails.
        let kem_shared = dk.decapsulate(&kem_ct).map_err(|_| BundleError::Open)?;
        let key = hybrid_file_key(
            eph_pub.as_bytes(),
            my_pub.as_bytes(),
            x_shared.as_bytes(),
            &kem_shared,
        );
        let mut aad = Vec::with_capacity(BUNDLE_MAGIC_V2.len() + 32 + KEM_CT_LEN);
        aad.extend_from_slice(BUNDLE_MAGIC_V2);
        aad.extend_from_slice(eph_pub_bytes);
        aad.extend_from_slice(kem_ct_bytes);
        let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().expect("split_at(NONCE_LEN)");
        return Ok((
            BUNDLE_MAGIC_V2.len() + 32 + KEM_CT_LEN + NONCE_LEN,
            aad,
            key,
            nonce,
        ));
    }
    let rest = &bundle[BUNDLE_MAGIC.len()..];
    if rest.len() < 32 + NONCE_LEN + TAG_LEN {
        return Err(BundleError::Truncated);
    }
    let secret = match parse_secret(secret_hex)? {
        Identity::X25519(s) => s,
        Identity::Hybrid(s, _) => s,
    };
    let (eph_pub_bytes, after_eph) = rest.split_at(32);
    let (nonce_bytes, _) = after_eph.split_at(NONCE_LEN);
    let eph_pub_arr: [u8; 32] = eph_pub_bytes.try_into().expect("split_at(32)");
    let eph_pub = PublicKey::from(eph_pub_arr);
    let my_pub = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&eph_pub);
    let key = file_key(eph_pub.as_bytes(), my_pub.as_bytes(), shared.as_bytes());
    let mut aad = Vec::with_capacity(BUNDLE_MAGIC.len() + 32);
    aad.extend_from_slice(BUNDLE_MAGIC);
    aad.extend_from_slice(eph_pub_bytes);
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().expect("split_at(NONCE_LEN)");
    Ok((BUNDLE_MAGIC.len() + 32 + NONCE_LEN, aad, key, nonce))
}

/// Open a bundle with the identity secret that matches its recipient,
/// consuming the caller's buffer and returning the plaintext in it.
///
/// The one implementation; [`decrypt_with`] is a borrowing wrapper over
/// this. ROADMAP O138: the returning shape allocated the plaintext beside
/// a bundle the caller was still holding, which on the CLI's restore path
/// was two of the **2,002 MB peak RSS (4.49x)** measured for importing a
/// 467.7 MB bundle — the worst path in the export/import family, and one
/// nothing had ever measured.
pub fn decrypt_with_owned(secret_hex: &str, mut bundle: Vec<u8>) -> Result<Vec<u8>, BundleError> {
    let (prefix, aad, key, nonce) = open_header(secret_hex, &bundle)?;
    // The ciphertext moves down over the header rather than into a second
    // allocation: a memmove inside the buffer already in hand.
    bundle.drain(..prefix);
    XChaCha20Poly1305::new((&key).into())
        .decrypt_in_place(XNonce::from_slice(&nonce), &aad, &mut bundle)
        .map_err(|_| BundleError::Open)?;
    Ok(bundle)
}

/// Open a bundle held by reference.
///
/// Prefer [`decrypt_with_owned`] for anything vault-sized: this has to
/// copy the bundle so the AEAD has a buffer it owns.
pub fn decrypt_with(secret_hex: &str, bundle: &[u8]) -> Result<Vec<u8>, BundleError> {
    decrypt_with_owned(secret_hex, bundle.to_vec())
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

/// Record counts a manifest declares. Inside the signature and inside the
/// `egress/export` audit record; neither importer reads them — the
/// orchestrator's migration compares them to the destination's stats
/// after import. A truncated or padded record stream is caught by
/// `payload_sha256`, which is checked unconditionally.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManifestCounts {
    /// How many drawer records the payload holds.
    pub drawers: u64,
    /// How many knowledge-graph entity records the payload holds.
    #[serde(default)]
    pub kg_entities: u64,
    /// How many knowledge-graph fact records the payload holds.
    #[serde(default)]
    pub kg_triples: u64,
    /// How many tunnel records the payload holds.
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
    /// The source vault's audit-chain head at export — provenance, never importable state.
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

    /// The whole attestation decision an importer has to make, in one
    /// place, for every surface (ROADMAP C5).
    ///
    /// Three rules, and the differences between them are the point:
    ///
    /// * a manifest that CARRIES an attestation is verified
    ///   **unconditionally** — admitting a signature known not to verify
    ///   and calling it "unverified" is admitting evidence already found
    ///   false;
    /// * a `pinned` sender additionally pins WHO. An embedded key alone
    ///   proves the manifest is self-consistent, not that it came from
    ///   anyone in particular, so pinning is the only form of this that is
    ///   an authorization decision;
    /// * a pin with nothing to check is a **refusal**, never a shrug.
    ///
    /// It lives here because the two importers disagreed. `/v1` verified
    /// unconditionally; the CLI — the surface every operator backup restore
    /// uses — had no `else` branch and verified only when `--sender` was
    /// passed, printing `signed-by=<16 hex> (unverified …)` and importing.
    /// Since the payload digest IS checked unconditionally, an attacker
    /// swapping a signed bundle's payload had to break the signature but
    /// could keep the trusted sender's key, and the CLI then printed that
    /// sender's prefix beside attacker content: provenance-display
    /// laundering. A second per-surface guard would have been the same
    /// mistake one layer up; this is the choke point instead.
    pub fn attest(
        manifest: Option<&BundleManifest>,
        pinned: Option<&str>,
    ) -> Result<Attestation, BundleError> {
        let Some(m) = manifest else {
            if pinned.is_some() {
                return Err(BundleError::BadManifest(
                    "sender was pinned but the payload carries no manifest to verify".into(),
                ));
            }
            return Ok(Attestation::NoManifest);
        };
        // Half-signed counts as signed for this decision: a manifest with a
        // sender and no signature (or the reverse) is malformed, and
        // `verify` says so — reporting it as merely "unsigned" would
        // launder it.
        if m.sig.is_none() && m.sender.is_none() {
            if pinned.is_some() {
                return Err(BundleError::BadManifest(
                    "sender was pinned but the payload's manifest is unsigned".into(),
                ));
            }
            return Ok(Attestation::Unsigned);
        }
        // The pin is checked first and separately so the two failures stay
        // distinguishable: "signed by somebody else" is an authorization
        // answer, "the signature does not verify" is an integrity one, and
        // collapsing them into one `BadSignature` tells a caller which
        // question it asked but not which one failed.
        if let Some(expected) = pinned {
            if m.sender.as_deref() != Some(expected.trim()) {
                return Err(BundleError::BadManifest(
                    "the payload was signed by a key other than the pinned sender".into(),
                ));
            }
        }
        m.verify()?;
        Ok(Attestation::Verified {
            sender: m.sender.clone().unwrap_or_default(),
        })
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

/// Detached Ed25519 signature over arbitrary canonical bytes (hex) — the
/// forgetting attestation rides the same signing identity bundles use.
pub fn sign_detached(signing_secret_hex: &str, bytes: &[u8]) -> Result<String, BundleError> {
    let key = parse_signing(signing_secret_hex)?;
    let sig: Signature = key.sign(bytes);
    Ok(hex::encode(sig.to_bytes()))
}

/// Verify a detached signature against a sender string.
pub fn verify_detached(sender_hex: &str, bytes: &[u8], sig_hex: &str) -> Result<(), BundleError> {
    let key_bytes: [u8; 32] = hex::decode(sender_hex.trim())
        .map_err(|_| BundleError::BadSignature)?
        .try_into()
        .map_err(|_| BundleError::BadSignature)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| BundleError::BadSignature)?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex.trim())
        .map_err(|_| BundleError::BadSignature)?
        .try_into()
        .map_err(|_| BundleError::BadSignature)?;
    key.verify(bytes, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| BundleError::BadSignature)
}

/// Frame a payload: the manifest line, then the record bytes verbatim.
///
/// **Prefer [`frame_payload_into`]** where the caller owns `records` — this
/// allocates a second whole-payload buffer and copies into it, so both are
/// live at once. ROADMAP O113 measured that as the largest single contributor
/// to a 1,258 MB export peak, and the filing did not name it: it attributed
/// the cost to a store-side `Vec` that is not even on the path it measured.
pub fn frame_payload(manifest: &BundleManifest, records: &[u8]) -> Vec<u8> {
    let line = manifest_line(manifest);
    let mut out = Vec::with_capacity(line.len() + 1 + records.len());
    out.extend_from_slice(line.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(records);
    out
}

/// Frame in place: prepend the manifest line to a buffer the caller already
/// owns, so the payload exists ONCE (ROADMAP O113).
///
/// The insert shifts `records` rather than copying it into a second
/// allocation, and reserves first so the shift happens at most once. Output is
/// byte-identical to [`frame_payload`] — the format does not move, which is
/// the whole point: every reader, every shell suite and every third party
/// keeps working, and `BundleManifest.version` stays honestly 1.
pub fn frame_payload_into(manifest: &BundleManifest, records: &mut Vec<u8>) {
    let line = manifest_line(manifest);
    records.reserve(line.len() + 1);
    records.splice(
        0..0,
        line.into_bytes().into_iter().chain(std::iter::once(b'\n')),
    );
}

/// The manifest's own line, without the trailing newline. One spelling, so the
/// two framing functions cannot drift into different bytes.
fn manifest_line(manifest: &BundleManifest) -> String {
    serde_json::json!({ MANIFEST_LINE_KEY: manifest }).to_string()
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

/// The hybrid file key: both shared secrets concatenated as the HKDF ikm,
/// under a distinct info string. The KEM ciphertext itself is bound as
/// AAD rather than salted in here — either binding suffices and AAD keeps
/// the derivation's shape identical to v1's.
fn hybrid_file_key(
    eph_pub: &[u8],
    recipient_x_pub: &[u8],
    x_shared: &[u8],
    kem_shared: &[u8],
) -> [u8; KEY_LEN] {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub);
    salt.extend_from_slice(recipient_x_pub);
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(x_shared);
    ikm.extend_from_slice(kem_shared);
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut key = [0u8; KEY_LEN];
    hk.expand(b"undercroft.v2/bundle", &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn parse_secret(s: &str) -> Result<Identity, BundleError> {
    let s = s.trim();
    if let Some(hex_str) = s.strip_prefix(HYBRID_PREFIX) {
        let bytes = hex::decode(hex_str).map_err(|_| BundleError::BadIdentity)?;
        if bytes.len() != 32 + KEM_DK_LEN {
            return Err(BundleError::BadIdentity);
        }
        let x: [u8; 32] = bytes[..32].try_into().expect("checked length");
        let dk_bytes = ml_kem::Encoded::<KemDk>::try_from(&bytes[32..])
            .map_err(|_| BundleError::BadIdentity)?;
        let dk = KemDk::from_bytes(&dk_bytes);
        return Ok(Identity::Hybrid(StaticSecret::from(x), Box::new(dk)));
    }
    let bytes: [u8; 32] = hex::decode(s)
        .map_err(|_| BundleError::BadIdentity)?
        .try_into()
        .map_err(|_| BundleError::BadIdentity)?;
    Ok(Identity::X25519(StaticSecret::from(bytes)))
}

fn parse_public(s: &str) -> Result<Recipient, BundleError> {
    let s = s.trim();
    if let Some(hex_str) = s.strip_prefix(HYBRID_PREFIX) {
        let bytes = hex::decode(hex_str).map_err(|_| BundleError::BadRecipient)?;
        if bytes.len() != 32 + KEM_EK_LEN {
            return Err(BundleError::BadRecipient);
        }
        let x: [u8; 32] = bytes[..32].try_into().expect("checked length");
        let ek_bytes = ml_kem::Encoded::<KemEk>::try_from(&bytes[32..])
            .map_err(|_| BundleError::BadRecipient)?;
        let ek = KemEk::from_bytes(&ek_bytes);
        return Ok(Recipient::Hybrid(PublicKey::from(x), Box::new(ek)));
    }
    let bytes: [u8; 32] = hex::decode(s)
        .map_err(|_| BundleError::BadRecipient)?
        .try_into()
        .map_err(|_| BundleError::BadRecipient)?;
    Ok(Recipient::X25519(PublicKey::from(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A legacy X25519-only keypair, exactly what pre-C3.4 `keygen`
    /// produced — bare hex, no prefix.
    fn legacy_keygen() -> (String, String) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (
            hex::encode(secret.as_bytes()),
            hex::encode(public.as_bytes()),
        )
    }

    /// O138 changed HOW a bundle is assembled and must not have changed
    /// WHAT one is. A round trip through the current code cannot see that
    /// distinction, because both halves moved together — so this carries an
    /// INDEPENDENT implementation of the previous assembly (one-shot AEAD,
    /// ciphertext copied in behind the header) and requires today's reader
    /// to open it, which is the only claim an old backup cares about.
    #[test]
    fn a_bundle_assembled_the_previous_way_still_opens() {
        use chacha20poly1305::aead::{Aead, Payload};
        let (secret, recipient) = legacy_keygen();
        let Recipient::X25519(recipient_pub) = parse_public(&recipient).expect("recipient parses")
        else {
            panic!("legacy_keygen produces an X25519 recipient");
        };
        let plaintext = b"a manifest line\nand a drawer\n".to_vec();

        // --- the pre-O138 assembly, written out here rather than called ---
        let eph = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = PublicKey::from(&eph);
        let shared = eph.diffie_hellman(&recipient_pub);
        let key = file_key(
            eph_pub.as_bytes(),
            recipient_pub.as_bytes(),
            shared.as_bytes(),
        );
        let mut aad = Vec::new();
        aad.extend_from_slice(BUNDLE_MAGIC);
        aad.extend_from_slice(eph_pub.as_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ct = XChaCha20Poly1305::new((&key).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .expect("the previous seal");
        let mut old = Vec::new();
        old.extend_from_slice(BUNDLE_MAGIC);
        old.extend_from_slice(eph_pub.as_bytes());
        old.extend_from_slice(&nonce);
        old.extend_from_slice(&ct);

        assert_eq!(
            decrypt_with(&secret, &old).expect("a pre-O138 bundle still opens"),
            plaintext,
            "a bundle assembled the previous way no longer opens — the format moved"
        );

        // And what the current sealer emits has that same shape: every
        // field whose value is not random sits at the same offset, and the
        // length is the layout's own arithmetic.
        let new = encrypt_for(&recipient, &plaintext).expect("seal");
        assert_eq!(new.len(), old.len(), "the sealed length moved");
        assert_eq!(&new[..BUNDLE_MAGIC.len()], BUNDLE_MAGIC, "magic moved");
        assert_eq!(
            new.len(),
            BUNDLE_MAGIC.len() + 32 + NONCE_LEN + plaintext.len() + TAG_LEN,
            "the v1 layout is magic, ephemeral key, nonce, ciphertext+tag"
        );
    }

    /// The streaming sealer and the buffering one produce the same format,
    /// and the sink gets every byte. Without this, `encrypt_for_into` could
    /// write a bundle only it can read — the whole risk of the change.
    #[test]
    fn the_streaming_sealer_and_the_buffering_one_agree() {
        let (secret, recipient) = keygen();
        let plaintext = b"streamed".to_vec();
        let mut sink = Vec::new();
        let written =
            encrypt_for_into(&recipient, plaintext.clone(), &mut sink).expect("seal into a sink");
        assert_eq!(
            written as usize,
            sink.len(),
            "the reported byte count is not what reached the sink"
        );
        assert_eq!(
            decrypt_with(&secret, &sink).expect("open the streamed bundle"),
            plaintext,
            "the buffering reader cannot open the streaming sealer's bundle"
        );
        // The other direction, so neither half can drift alone.
        let buffered = encrypt_for(&recipient, &plaintext).expect("seal");
        assert_eq!(
            decrypt_with_owned(&secret, buffered).expect("open"),
            plaintext,
            "the consuming reader cannot open the buffering sealer's bundle"
        );
        assert_eq!(
            sink.len(),
            BUNDLE_MAGIC_V2.len() + 32 + KEM_CT_LEN + NONCE_LEN + plaintext.len() + TAG_LEN,
            "the v2 layout is magic, ephemeral key, KEM ciphertext, nonce, ciphertext+tag"
        );
    }

    #[test]
    fn roundtrip() {
        // `keygen` is hybrid since C3.4: both strings carry the prefix,
        // the bundle is v2, and the roundtrip is exact.
        let (secret, recipient) = keygen();
        assert!(secret.starts_with(HYBRID_PREFIX));
        assert!(recipient.starts_with(HYBRID_PREFIX));
        let bundle = encrypt_for(&recipient, b"verbatim words survive").unwrap();
        assert!(is_bundle(&bundle));
        assert_eq!(&bundle[..BUNDLE_MAGIC_V2.len()], BUNDLE_MAGIC_V2);
        let plain = decrypt_with(&secret, &bundle).unwrap();
        assert_eq!(plain, b"verbatim words survive");
        assert_eq!(recipient_of(&secret).unwrap(), recipient);
    }

    #[test]
    fn legacy_identities_still_work_both_ways() {
        // A bare-hex recipient gets a v1 bundle it can actually open —
        // "old format still importable" covers WRITING to old recipients
        // too, or upgrading one side would strand the other.
        let (secret, recipient) = legacy_keygen();
        let bundle = encrypt_for(&recipient, b"legacy words").unwrap();
        assert_eq!(&bundle[..BUNDLE_MAGIC.len()], BUNDLE_MAGIC);
        assert_eq!(decrypt_with(&secret, &bundle).unwrap(), b"legacy words");
        assert_eq!(recipient_of(&secret).unwrap(), recipient);
    }

    #[test]
    fn a_hybrid_identity_opens_v1_bundles_addressed_to_its_curve_half() {
        // Upgrading an identity never orphans old backups: a v1 bundle
        // addressed to the hybrid identity's X25519 component opens.
        let (secret, recipient) = keygen();
        let x_pub_hex = &recipient[HYBRID_PREFIX.len()..HYBRID_PREFIX.len() + 64];
        let bundle = encrypt_for(x_pub_hex, b"old backup").unwrap();
        assert_eq!(&bundle[..BUNDLE_MAGIC.len()], BUNDLE_MAGIC);
        assert_eq!(decrypt_with(&secret, &bundle).unwrap(), b"old backup");
    }

    /// The C3.4 gate's second sentence: no silent downgrade, in any
    /// direction an attacker or a stale tool could push.
    #[test]
    fn hybrid_never_downgrades() {
        let (secret, recipient) = keygen();
        // A hybrid recipient ALWAYS yields a v2 bundle.
        let bundle = encrypt_for(&recipient, b"post-quantum words").unwrap();
        assert_eq!(&bundle[..BUNDLE_MAGIC_V2.len()], BUNDLE_MAGIC_V2);
        // Rewriting the magic to v1 must not open anything: the magic is
        // AAD on both sides, and the v1 parse reads KEM bytes as nonce.
        let mut downgraded = bundle.clone();
        downgraded[..BUNDLE_MAGIC.len()].copy_from_slice(BUNDLE_MAGIC);
        assert!(decrypt_with(&secret, &downgraded).is_err());
        // An X25519-only identity handed a v2 bundle gets the typed
        // refusal, never a quiet curve-half attempt.
        let (legacy_secret, _) = legacy_keygen();
        assert!(matches!(
            decrypt_with(&legacy_secret, &bundle),
            Err(BundleError::NeedsHybrid)
        ));
        // A tampered KEM ciphertext fails (AAD-bound + the AEAD key moves
        // under ML-KEM's implicit rejection).
        let mut kem_tampered = bundle.clone();
        kem_tampered[BUNDLE_MAGIC_V2.len() + 32] ^= 0x01;
        assert!(matches!(
            decrypt_with(&secret, &kem_tampered),
            Err(BundleError::Open)
        ));
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
