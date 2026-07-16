//! Undercroft's hardened memory-management layer.
//!
//! A *palace* (data directory) holds many *vaults*. Each vault is an
//! isolation boundary for memories:
//!
//! * **Separate storage** — every vault gets its own directory and its own
//!   SQLite database file; there is no shared table space to leak across.
//! * **Separate keys** — per-vault encryption and MAC keys are derived from
//!   the palace master key with HKDF-SHA256 domain separation
//!   ([`keys::derive_vault_key`]); vault A's keys are useless against
//!   vault B's data.
//! * **Encryption** — in `sealed` vaults, drawer content (and its
//!   embedding) is encrypted with XChaCha20-Poly1305; the AAD binds vault
//!   id + record id so blobs cannot be replayed across vaults or slots.
//! * **HMAC integrity** — every record carries an HMAC-SHA256 tag over its
//!   canonical bytes (independent MAC key), and the vault manifest keeps a
//!   tamper-evident HMAC chain over all writes. `undercroft verify` walks
//!   both.
//!
//! Threat model: protects memories at rest against disk theft, cross-vault
//! bleed, and offline tampering of the database or manifest. It does not
//! defend against an attacker who can read process memory while a vault is
//! unlocked.

pub mod keys;
pub mod seal;

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use keys::{derive_vault_key, SecretKey, KEY_LEN};
use seal::{chain_next, record_hmac, verify_hmac, SealError, HMAC_LEN};

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("key error: {0}")]
    Key(#[from] keys::KeyError),
    #[error("seal error: {0}")]
    Seal(#[from] SealError),
    #[error("vault {0:?} not found (create it with `undercroft vault create {0}`)")]
    NotFound(String),
    #[error("vault {0:?} already exists")]
    AlreadyExists(String),
    #[error("vault manifest is corrupt: {0}")]
    CorruptManifest(String),
    #[error("vault manifest failed integrity verification — possible tampering")]
    ManifestTampered,
    #[error("invalid vault name: {0}")]
    BadName(#[from] undercroft_core::CoreError),
}

/// How much protection a vault applies to content at rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityLevel {
    /// Content + embeddings encrypted (AEAD) and HMAC-tagged. Search runs
    /// by decrypt-scan; nothing content-derived is indexed in plaintext.
    Sealed,
    /// Content stored in plaintext with full-text indexing, but every
    /// record still carries an HMAC integrity tag and joins the audit
    /// chain. For memories where searchability outweighs confidentiality.
    HmacOnly,
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityLevel::Sealed => f.write_str("sealed"),
            SecurityLevel::HmacOnly => f.write_str("hmac-only"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    version: u32,
    id: String,
    level: SecurityLevel,
    salt_hex: String,
    created_at: String,
    writes: u64,
    chain_head_hex: String,
    /// HMAC over the canonical manifest fields, keyed by the vault's
    /// manifest key — detects offline edits to the manifest itself
    /// (e.g. resetting the chain head or downgrading the level).
    manifest_mac_hex: String,
}

impl Manifest {
    fn canonical(&self) -> Vec<u8> {
        format!(
            "{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}\x1f{}",
            self.version,
            self.id,
            self.level,
            self.salt_hex,
            self.created_at,
            self.writes,
            self.chain_head_hex
        )
        .into_bytes()
    }
}

/// An unlocked vault: derived keys + manifest state.
pub struct Vault {
    id: String,
    dir: PathBuf,
    level: SecurityLevel,
    enc_key: SecretKey,
    mac_key: SecretKey,
    manifest_key: SecretKey,
    manifest: Manifest,
}

impl Vault {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path of this vault's SQLite database.
    pub fn db_path(&self) -> PathBuf {
        self.dir.join("palace.db")
    }

    pub fn level(&self) -> SecurityLevel {
        self.level
    }

    pub fn writes(&self) -> u64 {
        self.manifest.writes
    }

    pub fn chain_head_hex(&self) -> &str {
        &self.manifest.chain_head_hex
    }

    /// Prepare content for storage. Sealed vaults compress (zstd) then
    /// encrypt — that order matters: ciphertext has no redundancy left to
    /// compress. Compression is skipped when it doesn't pay (tiny or
    /// incompressible content). Hmac-only vaults keep raw plaintext so the
    /// database stays inspectable with standard tools.
    pub fn content_at_rest(&self, record_id: &str, plaintext: &[u8]) -> Vec<u8> {
        match self.level {
            SecurityLevel::Sealed => {
                let framed = compress_frame(plaintext);
                seal::seal_content(&self.enc_key, &self.id, record_id, &framed)
            }
            SecurityLevel::HmacOnly => plaintext.to_vec(),
        }
    }

    /// Recover plaintext content from its at-rest form.
    pub fn content_from_rest(&self, record_id: &str, blob: &[u8]) -> Result<Vec<u8>, VaultError> {
        match self.level {
            SecurityLevel::Sealed => {
                let framed = seal::open_content(&self.enc_key, &self.id, record_id, blob)?;
                decompress_frame(&framed)
            }
            SecurityLevel::HmacOnly => Ok(blob.to_vec()),
        }
    }

    /// Store an embedding: quantized to i8 (4x smaller than f32 — the
    /// vector is usually bigger than the text it embeds), then sealed in
    /// encrypted vaults (embeddings of plaintext leak content and must not
    /// be stored in clear).
    pub fn embedding_at_rest(&self, record_id: &str, embedding: &[f32]) -> Vec<u8> {
        let raw = quantize_embedding(embedding);
        match self.level {
            SecurityLevel::Sealed => {
                seal::seal_content(&self.enc_key, &self.id, &format!("{record_id}/emb"), &raw)
            }
            SecurityLevel::HmacOnly => raw,
        }
    }

    pub fn embedding_from_rest(
        &self,
        record_id: &str,
        blob: &[u8],
    ) -> Result<Vec<f32>, VaultError> {
        let raw = match self.level {
            SecurityLevel::Sealed => {
                seal::open_content(&self.enc_key, &self.id, &format!("{record_id}/emb"), blob)?
            }
            SecurityLevel::HmacOnly => blob.to_vec(),
        };
        Ok(dequantize_embedding(&raw))
    }

    /// Store a late-interaction token matrix (already quantized by the
    /// caller). Token embeddings are plaintext-derived like the sentence
    /// embedding, so sealed vaults seal them — under the `/tok` AAD domain,
    /// distinct from content and `/emb`, so at-rest blobs of one drawer can
    /// never be swapped for each other. This is the sealed tier's first
    /// encrypted-at-rest derived store: unlike the PQ/FTS *prefilters*
    /// (plaintext side-tables, hmac-only vaults only), a per-candidate
    /// rescore store can exist for sealed vaults because nothing derived
    /// ever touches disk in clear.
    pub fn tokens_at_rest(&self, record_id: &str, packed: &[u8]) -> Vec<u8> {
        match self.level {
            SecurityLevel::Sealed => {
                seal::seal_content(&self.enc_key, &self.id, &format!("{record_id}/tok"), packed)
            }
            SecurityLevel::HmacOnly => packed.to_vec(),
        }
    }

    /// Recover a token matrix blob from its at-rest form.
    pub fn tokens_from_rest(&self, record_id: &str, blob: &[u8]) -> Result<Vec<u8>, VaultError> {
        match self.level {
            SecurityLevel::Sealed => Ok(seal::open_content(
                &self.enc_key,
                &self.id,
                &format!("{record_id}/tok"),
                blob,
            )?),
            SecurityLevel::HmacOnly => Ok(blob.to_vec()),
        }
    }

    /// Store a retrieval-index artifact (PQ code row, codebook, IVF
    /// centroids — all plaintext-derived). Sealed vaults seal it under the
    /// `/pq` AAD domain; callers pass the owning drawer id for per-row
    /// artifacts or a stable synthetic id (e.g. `"pq/codebook"`) for
    /// index-wide ones. This closes the sealed-tier gap: sealed vaults can
    /// now persist an ANN index because none of it ever touches disk in
    /// clear — the search layer decrypts it once per open into a bounded
    /// RAM cache and scans there.
    pub fn index_at_rest(&self, record_id: &str, bytes: &[u8]) -> Vec<u8> {
        match self.level {
            SecurityLevel::Sealed => {
                seal::seal_content(&self.enc_key, &self.id, &format!("{record_id}/pq"), bytes)
            }
            SecurityLevel::HmacOnly => bytes.to_vec(),
        }
    }

    /// Recover a retrieval-index artifact from its at-rest form.
    pub fn index_from_rest(&self, record_id: &str, blob: &[u8]) -> Result<Vec<u8>, VaultError> {
        match self.level {
            SecurityLevel::Sealed => Ok(seal::open_content(
                &self.enc_key,
                &self.id,
                &format!("{record_id}/pq"),
                blob,
            )?),
            SecurityLevel::HmacOnly => Ok(blob.to_vec()),
        }
    }

    /// HMAC tag for a record's canonical bytes.
    pub fn tag(&self, canonical: &[u8]) -> [u8; HMAC_LEN] {
        record_hmac(&self.mac_key, canonical)
    }

    /// Verify a record tag (constant-time).
    pub fn verify_tag(&self, canonical: &[u8], tag: &[u8]) -> Result<(), VaultError> {
        Ok(verify_hmac(&self.mac_key, canonical, tag)?)
    }

    /// Advance the audit chain for one write and persist the manifest.
    pub fn commit_write(&mut self, record_tag: &[u8]) -> Result<(), VaultError> {
        let prev = hex::decode(&self.manifest.chain_head_hex)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        let next = chain_next(&self.mac_key, &prev, record_tag);
        self.manifest.chain_head_hex = hex::encode(next);
        self.manifest.writes += 1;
        self.save_manifest()?;
        undercroft_obs::chain_commit();
        undercroft_obs::event_chain_commit(self.id());
        Ok(())
    }

    /// Recompute the audit chain from an ordered list of record tags and
    /// compare with the stored head.
    pub fn verify_chain(&self, ordered_tags: &[Vec<u8>]) -> bool {
        let mut head = vec![0u8; HMAC_LEN];
        for tag in ordered_tags {
            head = chain_next(&self.mac_key, &head, tag).to_vec();
        }
        hex::encode(head) == self.manifest.chain_head_hex
    }

    fn save_manifest(&mut self) -> Result<(), VaultError> {
        self.manifest.manifest_mac_hex =
            hex::encode(record_hmac(&self.manifest_key, &self.manifest.canonical()));
        let json = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        let tmp = self.dir.join("vault.json.tmp");
        fs::write(&tmp, &json)?;
        fs::rename(&tmp, self.dir.join("vault.json"))?;
        Ok(())
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("id", &self.id)
            .field("level", &self.level)
            .field("writes", &self.manifest.writes)
            .finish_non_exhaustive()
    }
}

/// Factory for vaults under one palace directory.
pub struct VaultManager {
    root: PathBuf,
    master: SecretKey,
}

impl VaultManager {
    /// Open the palace at `root`, loading (or creating) the master key.
    /// `passphrase` switches to Argon2id passphrase derivation.
    pub fn open(root: &Path, passphrase: Option<&str>) -> Result<Self, VaultError> {
        let master = keys::load_or_create_master(root, passphrase)?;
        fs::create_dir_all(root.join("vaults"))?;
        Ok(Self {
            root: root.to_path_buf(),
            master,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn vault_dir(&self, id: &str) -> PathBuf {
        self.root.join("vaults").join(id)
    }

    pub fn list(&self) -> Result<Vec<String>, VaultError> {
        let mut out = Vec::new();
        let dir = self.root.join("vaults");
        if dir.exists() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if entry.path().join("vault.json").exists() {
                    out.push(entry.file_name().to_string_lossy().to_string());
                }
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn exists(&self, id: &str) -> bool {
        self.vault_dir(id).join("vault.json").exists()
    }

    /// Create a new vault. Fails if it already exists.
    pub fn create(&self, id: &str, level: SecurityLevel) -> Result<Vault, VaultError> {
        undercroft_core::validate_name(id, "vault")?;
        let dir = self.vault_dir(id);
        if self.exists(id) {
            return Err(VaultError::AlreadyExists(id.to_string()));
        }
        fs::create_dir_all(&dir)?;
        let salt = keys::new_vault_salt();
        let manifest = Manifest {
            version: 1,
            id: id.to_string(),
            level,
            salt_hex: hex::encode(salt),
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .expect("RFC3339 formatting of now() cannot fail"),
            writes: 0,
            chain_head_hex: hex::encode([0u8; HMAC_LEN]),
            manifest_mac_hex: String::new(),
        };
        let mut vault = self.assemble(dir, manifest)?;
        vault.save_manifest()?;
        Ok(vault)
    }

    /// Permanently delete a vault: its manifest, database, and directory.
    /// Returns `false` if the vault did not exist. Irreversible — the
    /// caller (e.g. an orchestrator migrating a tenant) is responsible for
    /// having exported/verified the contents first. Each vault is fully
    /// self-contained (its own dir + manifest), so removal touches nothing
    /// else in the palace.
    pub fn delete(&self, id: &str) -> Result<bool, VaultError> {
        undercroft_core::validate_name(id, "vault")?;
        if !self.exists(id) {
            return Ok(false);
        }
        fs::remove_dir_all(self.vault_dir(id))?;
        Ok(true)
    }

    /// Unlock an existing vault: derive its keys and verify the manifest MAC.
    pub fn unlock(&self, id: &str) -> Result<Vault, VaultError> {
        let dir = self.vault_dir(id);
        let manifest_path = dir.join("vault.json");
        if !manifest_path.exists() {
            return Err(VaultError::NotFound(id.to_string()));
        }
        let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        if manifest.id != id {
            return Err(VaultError::CorruptManifest("manifest id mismatch".into()));
        }
        let vault = self.assemble(dir, manifest)?;
        // Verify the manifest itself before trusting level / chain head.
        let expected = record_hmac(&vault.manifest_key, &vault.manifest.canonical());
        let stored = hex::decode(&vault.manifest.manifest_mac_hex)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        if verify_hmac(&vault.manifest_key, &vault.manifest.canonical(), &stored).is_err() {
            let _ = expected;
            undercroft_obs::hmac_verify_failed("manifest");
            undercroft_obs::event_hmac_fail(vault.id(), "manifest");
            return Err(VaultError::ManifestTampered);
        }
        Ok(vault)
    }

    fn assemble(&self, dir: PathBuf, manifest: Manifest) -> Result<Vault, VaultError> {
        let salt = hex::decode(&manifest.salt_hex)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        if salt.len() != keys::SALT_LEN {
            return Err(VaultError::CorruptManifest("bad salt length".into()));
        }
        let id = manifest.id.clone();
        Ok(Vault {
            enc_key: derive_vault_key(&self.master, &salt, &id, "enc"),
            mac_key: derive_vault_key(&self.master, &salt, &id, "mac"),
            manifest_key: derive_vault_key(&self.master, &salt, &id, "manifest"),
            level: manifest.level,
            id,
            dir,
            manifest,
        })
    }
}

impl std::fmt::Debug for VaultManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultManager")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Storage framing: compression (content) and quantization (embeddings)
// ---------------------------------------------------------------------------

/// Frame markers for compressed content. Legacy blobs (pre-compression)
/// contain normalized UTF-8 whose first byte is always >= 0x09, so 0x00 /
/// 0x01 are unambiguous.
const FRAME_RAW: u8 = 0x00;
const FRAME_ZSTD: u8 = 0x01;

/// zstd-compress with a marker frame; falls back to a raw frame when
/// compression doesn't pay.
fn compress_frame(plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() >= 64 {
        if let Ok(z) = zstd::bulk::compress(plaintext, 3) {
            if z.len() + 1 < plaintext.len() {
                let mut out = Vec::with_capacity(z.len() + 1);
                out.push(FRAME_ZSTD);
                out.extend_from_slice(&z);
                return out;
            }
        }
    }
    let mut out = Vec::with_capacity(plaintext.len() + 1);
    out.push(FRAME_RAW);
    out.extend_from_slice(plaintext);
    out
}

fn decompress_frame(framed: &[u8]) -> Result<Vec<u8>, VaultError> {
    match framed.first() {
        Some(&FRAME_RAW) => Ok(framed[1..].to_vec()),
        Some(&FRAME_ZSTD) => zstd::bulk::decompress(&framed[1..], 16 * 1024 * 1024)
            .map_err(|e| VaultError::CorruptManifest(format!("zstd: {e}"))),
        // Legacy record written before compression framing: the whole
        // buffer is the content (normalized UTF-8 never starts with 0x00/0x01).
        _ => Ok(framed.to_vec()),
    }
}

/// Quantized-embedding frame: `[0x02, 'Q', scale f32 LE, i8 * dim]`.
/// Standard embedder dims are multiples of 128, so the frame length
/// (6 + dim) is never divisible by 4 — legacy f32 blobs (4 * dim) can't
/// collide with it.
const EMB_MAGIC0: u8 = 0x02;
const EMB_MAGIC1: u8 = b'Q';

fn quantize_embedding(embedding: &[f32]) -> Vec<u8> {
    let max_abs = embedding.iter().fold(0f32, |m, v| m.max(v.abs()));
    let scale = if max_abs > 0.0 { max_abs / 127.0 } else { 1.0 };
    let mut out = Vec::with_capacity(6 + embedding.len());
    out.push(EMB_MAGIC0);
    out.push(EMB_MAGIC1);
    out.extend_from_slice(&scale.to_le_bytes());
    for v in embedding {
        out.push((v / scale).round().clamp(-127.0, 127.0) as i8 as u8);
    }
    out
}

fn dequantize_embedding(raw: &[u8]) -> Vec<f32> {
    if raw.len() > 6 && raw[0] == EMB_MAGIC0 && raw[1] == EMB_MAGIC1 && !raw.len().is_multiple_of(4)
    {
        let scale = f32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]);
        return raw[6..].iter().map(|&b| (b as i8) as f32 * scale).collect();
    }
    // Legacy f32 little-endian blob.
    raw.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

// Re-export for store-layer signatures.
pub use seal::HMAC_LEN as RECORD_TAG_LEN;
pub const MASTER_KEY_LEN: usize = KEY_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn create_unlock_roundtrip() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("personal", SecurityLevel::Sealed).unwrap();
        let v = mgr.unlock("personal").unwrap();
        assert_eq!(v.level(), SecurityLevel::Sealed);
        assert_eq!(mgr.list().unwrap(), vec!["personal".to_string()]);
    }

    #[test]
    fn seal_roundtrip_through_vault() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("a", SecurityLevel::Sealed).unwrap();
        let blob = v.content_at_rest("rec1", b"remember this verbatim");
        assert_ne!(blob, b"remember this verbatim"); // actually encrypted
        let back = v.content_from_rest("rec1", &blob).unwrap();
        assert_eq!(back, b"remember this verbatim");
    }

    #[test]
    fn vault_isolation_cross_vault_blob_fails() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let a = mgr.create("vault-a", SecurityLevel::Sealed).unwrap();
        let b = mgr.create("vault-b", SecurityLevel::Sealed).unwrap();
        let blob = a.content_at_rest("rec1", b"private to a");
        assert!(b.content_from_rest("rec1", &blob).is_err());
    }

    #[test]
    fn manifest_tampering_detected() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("t", SecurityLevel::Sealed).unwrap();
        // Downgrade the level behind the manager's back.
        let mpath = dir.path().join("vaults/t/vault.json");
        let text = std::fs::read_to_string(&mpath)
            .unwrap()
            .replace("sealed", "hmac-only");
        std::fs::write(&mpath, text).unwrap();
        assert!(matches!(mgr.unlock("t"), Err(VaultError::ManifestTampered)));
    }

    #[test]
    fn chain_tracks_writes_and_detects_reorder() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let mut v = mgr.create("c", SecurityLevel::HmacOnly).unwrap();
        let t1 = v.tag(b"record-one").to_vec();
        let t2 = v.tag(b"record-two").to_vec();
        v.commit_write(&t1).unwrap();
        v.commit_write(&t2).unwrap();
        assert!(v.verify_chain(&[t1.clone(), t2.clone()]));
        assert!(!v.verify_chain(&[t2, t1]));
        assert_eq!(v.writes(), 2);
    }

    #[test]
    fn sealed_content_is_compressed_before_encryption() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("z", SecurityLevel::Sealed).unwrap();
        // Highly repetitive 8 KB text must shrink dramatically at rest.
        let plaintext = "the quarterly report moved to friday. ".repeat(200);
        let blob = v.content_at_rest("r", plaintext.as_bytes());
        assert!(
            blob.len() < plaintext.len() / 4,
            "expected compression: {} at rest vs {} plaintext",
            blob.len(),
            plaintext.len()
        );
        let back = v.content_from_rest("r", &blob).unwrap();
        assert_eq!(back, plaintext.as_bytes());
    }

    #[test]
    fn legacy_uncompressed_content_still_decodes() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("legacy", SecurityLevel::Sealed).unwrap();
        // Simulate a pre-compression record: sealed raw plaintext, no frame.
        let legacy_blob =
            seal::seal_content(&v.enc_key, v.id(), "old", b"legacy verbatim memory text");
        let back = v.content_from_rest("old", &legacy_blob).unwrap();
        assert_eq!(back, b"legacy verbatim memory text");
    }

    #[test]
    fn embedding_quantization_shrinks_and_preserves_ranking() {
        let e = undercroft_core::HashEmbedder;
        use undercroft_core::embed::{cosine, Embedder};
        let v = e.embed("the deployment pipeline failed on friday");
        let q = super::quantize_embedding(&v);
        assert!(
            q.len() < v.len() * 4 / 3,
            "quantized {} vs f32 {}",
            q.len(),
            v.len() * 4
        );
        let back = super::dequantize_embedding(&q);
        assert_eq!(back.len(), v.len());
        assert!(
            cosine(&v, &back) > 0.999,
            "quantization must not disturb ranking: {}",
            cosine(&v, &back)
        );
        // Legacy f32 blobs still decode.
        let mut legacy = Vec::new();
        for x in &v {
            legacy.extend_from_slice(&x.to_le_bytes());
        }
        assert_eq!(super::dequantize_embedding(&legacy), v);
    }

    #[test]
    fn embedding_seal_roundtrip() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("e", SecurityLevel::Sealed).unwrap();
        let emb = vec![0.25f32, -1.5, 3.0];
        let blob = v.embedding_at_rest("r", &emb);
        let back = v.embedding_from_rest("r", &blob).unwrap();
        assert_eq!(back.len(), emb.len());
        for (a, b) in back.iter().zip(&emb) {
            assert!((a - b).abs() < 0.02, "quantized {a} vs {b}");
        }
    }
}
