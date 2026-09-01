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

pub mod bundle;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// What a caller intends to do with the vault it is unlocking.
///
/// Unlocking is not a passive act: it reconciles the filesystem side of a key
/// rotation, and it removes a `vault.json.next` it cannot authenticate. Both
/// are writes, and both used to happen whatever the caller's posture was —
/// so a replica started to *freeze* writes during incident response could
/// delete a writer's staging manifest on the way up (ROADMAP A32). Stating
/// the posture is how a read-only caller gets detection instead of healing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// The caller may write. Reconciliation heals, as it always has.
    ReadWrite,
    /// The caller must not write. Nothing on disk is touched; what would
    /// have been healed is recorded on [`Vault::unhealed`] instead.
    ReadOnly,
}

/// Something a read-only unlock found and deliberately did **not** repair.
///
/// A refusal would be worse than a report: a vault whose writer crashed
/// mid-rotation must stay openable for `verify` and `repair`, which is the
/// argument for reporting rather than refusing. So the vault opens, serves
/// reads, and says exactly what it left alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unhealed {
    /// A `vault.json.next` that is unreadable, belongs to another vault, or
    /// fails its MAC — a torn leftover a writable unlock deletes.
    TornStagingManifest,
    /// A rotation whose re-seal COMMITTED: its keys were adopted in memory
    /// so this process can read the database, but `vault.json.next` was not
    /// renamed over `vault.json`.
    RotationPromotionDeferred,
    /// A rotation that never committed: its staging file is still on disk.
    RotationDiscardDeferred,
}

impl std::fmt::Display for Unhealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unhealed::TornStagingManifest => f.write_str(
                "a torn vault.json.next was left in place (removing it is a write); \
                 a writable open will discard it",
            ),
            Unhealed::RotationPromotionDeferred => f.write_str(
                "a committed key rotation was adopted in memory only — vault.json.next \
                 was NOT promoted (the rename is a write); the manifest on disk still \
                 names the previous key generation until a writable open promotes it",
            ),
            Unhealed::RotationDiscardDeferred => f.write_str(
                "an uncommitted key rotation left vault.json.next on disk and it was \
                 kept (removing it is a write); a writable open will discard it",
            ),
        }
    }
}

/// What a staged rotation manifest means, decided against the database's
/// committed `keycheck` marker. Pure — deciding is not doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationVerdict {
    /// No staging manifest is attached; nothing to reconcile.
    Settled,
    /// The marker names the STAGED generation: the re-seal transaction
    /// committed and only the manifest rename was lost. Everything at rest
    /// is sealed under the staged keys, so a reader must adopt them.
    Committed,
    /// The marker still names the current generation: the rotation never
    /// committed and the staging file is a leftover.
    Abandoned,
}

/// An unlocked vault: derived keys + manifest state.
pub struct Vault {
    id: String,
    dir: PathBuf,
    level: SecurityLevel,
    enc_key: SecretKey,
    mac_key: SecretKey,
    manifest_key: SecretKey,
    /// Keys [`Vault::sample_rank`] — the draw that decides what a trained
    /// index artifact trains on. Separate from the MAC key on purpose: those
    /// ranks are published *by their effects* (which rows shaped a codebook)
    /// and must not share a key with record integrity.
    sample_key: SecretKey,
    manifest: Manifest,
    /// A pending key-rotation manifest (`vault.json.next`), attached at
    /// unlock when one exists so the store's open path can reconcile it
    /// against the database's keycheck: rotation committed ⇒ promote,
    /// not committed ⇒ discard.
    pending: Option<Box<Vault>>,
    /// Filesystem repairs this unlock declined to make because the caller
    /// declared [`Access::ReadOnly`]. Empty on every writable open.
    unhealed: Vec<Unhealed>,
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

    /// Whether this vault's database file is actually there.
    ///
    /// [`VaultManager::exists`] answers about `vault.json`, which is a
    /// different file: a half-copied backup, an interrupted `rsync` or a
    /// snapshot taken mid-write can carry the manifest and not the database.
    /// `Connection::open` then CREATES the database and the vault answers
    /// every read empty with no error at all (ROADMAP A33). A caller that
    /// must not write has to be able to tell "empty" from "absent" before it
    /// opens anything, and this is that question.
    pub fn database_exists(&self) -> bool {
        self.db_path().exists()
    }

    /// Filesystem repairs a read-only unlock found and declined to make.
    /// Empty on a writable open, which heals them instead.
    pub fn unhealed(&self) -> &[Unhealed] {
        &self.unhealed
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

    /// A keyed pseudorandom rank for one *choice* — not an integrity claim.
    ///
    /// The caller ranks candidates by this and takes the lowest; the result is
    /// a sample that is **reproducible for whoever holds the vault key and
    /// unguessable to everyone else**. Its reason for existing is the training
    /// sample of a trained index artifact (PQ codebooks, IVF centroids): a
    /// deterministic even stride over insertion order is reproducible *and*
    /// predictable, so a writer who can bulk-insert knows in advance which of
    /// their own rows will shape a codebook that every other drawer is then
    /// quantized against. k-means has an unbounded breakdown point, so that
    /// is a lever on other drawers' recall.
    ///
    /// Keyed on its own HKDF-derived subkey (label `sample`), not the MAC key:
    /// ranks are handed to code that decides what to train on, and nothing
    /// derived from them should ever be usable against a record tag. Key
    /// rotation re-derives it (fresh salt), so a *later* retrain draws a
    /// different sample — codes already on disk are re-sealed, never
    /// re-quantized, so that changes nothing already stored.
    /// The encoding is **length-prefixed, not delimited**: a separator is only
    /// injective while no label contains it, and this is a `pub` method, so
    /// `("a\x1fb", b"c")` and `("a", b"b\x1fc")` would have collided into one
    /// rank under a delimiter — two artifacts drawing the same sample while
    /// appearing not to.
    pub fn sample_rank(&self, label: &str, ident: &[u8]) -> u64 {
        let mut canonical = Vec::with_capacity(8 + label.len() + ident.len());
        canonical.extend((label.len() as u64).to_le_bytes());
        canonical.extend_from_slice(label.as_bytes());
        canonical.extend_from_slice(ident);
        let tag = record_hmac(&self.sample_key, &canonical);
        u64::from_le_bytes(tag[..8].try_into().expect("HMAC-SHA256 is 32 bytes"))
    }

    /// Advance the audit chain for one write and persist the manifest.
    /// One pure chain step over hex heads: `next = HMAC(prev ‖ tag)`. The
    /// store owns *where* the committed head lives (a `chain_meta` row that
    /// advances inside the same SQLite transaction as the data it covers —
    /// a crash can never separate a record from its chain entry); the vault
    /// owns the key. See [`anchor_manifest`](Self::anchor_manifest) for the
    /// out-of-database half.
    pub fn chain_next_hex(&self, prev_hex: &str, record_tag: &[u8]) -> Result<String, VaultError> {
        let prev = hex::decode(prev_hex).map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        Ok(hex::encode(chain_next(&self.mac_key, &prev, record_tag)))
    }

    /// The all-zero head every chain starts from.
    pub fn chain_genesis_hex() -> String {
        hex::encode([0u8; HMAC_LEN])
    }

    /// Re-anchor the manifest to the committed chain state, **after** the
    /// database transaction that produced it. The manifest is deliberately
    /// allowed to lag: a crash between commit and anchor leaves it *behind*
    /// the database, which open-time reconciliation distinguishes from a
    /// rollback (an anchor the database chain never produced) and heals by
    /// fast-forwarding — a power loss is not a tamper alarm, a restored old
    /// database still is.
    /// Returns how many chain RECORDS this anchor committed — the value the
    /// counter advances by. Returned so it can be asserted: it is otherwise
    /// only observable through a metric that is a no-op in a default build,
    /// which is why the two-handle over-count was invisible to every test.
    pub fn anchor_manifest(&mut self, head_hex: &str, writes: u64) -> Result<u64, VaultError> {
        // How many chain RECORDS this anchor commits. One anchor is not
        // one record: `upsert_many` appends per drawer inside one
        // transaction and anchors once at the end (256 records, one
        // anchor), and read-audit records append with no anchor at all
        // and are picked up by the next one. Counting anchors made the
        // same 1,000-drawer NDJSON read as 1,000 commits through
        // `/v1 …/import` and 4 through `undercroft import`, on a counter
        // whose own contract says "once per mutation" — so the counter
        // advances by the delta, which is exactly the chain's growth.
        //
        // **The subtrahend is read from DISK, not from this handle's cached
        // field.** `self.manifest.writes` is only ever written by this
        // handle's own `anchor_manifest`, so with two handles on one vault —
        // which is exactly what `serve-http` runs, and the reason
        // `audit_chain_height` was already moved off the cached manifest —
        // each one measured the OTHER's growth from its own stale baseline
        // and counted it again. Steady state was 2× with two handles, worse
        // with more: a durable signal that was wrong rather than missing.
        //
        // The on-disk manifest is the last anchor ANY handle committed, so
        // the delta against it is the chain's real growth since then. A crash
        // between commit and anchor leaves records unanchored and the next
        // anchor counts them — the behaviour this comment already claims for
        // read-audit records. Unreadable or unparseable falls back to the
        // cached field, i.e. the previous behaviour: a counter must never be
        // the reason a write fails.
        let committed = self.anchored_writes().unwrap_or(self.manifest.writes);
        let records = writes.saturating_sub(committed);
        self.manifest.chain_head_hex = head_hex.to_string();
        self.manifest.writes = writes;
        self.save_manifest()?;
        // Emitted only after the anchor is durable, as before — the
        // records it counts are already committed, so no rolled-back
        // write can be counted.
        undercroft_obs::chain_commit(records);
        undercroft_obs::event_chain_commit(self.id(), records);
        Ok(records)
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

    /// Value proving which key generation a database was last sealed under:
    /// a fixed-domain HMAC under the vault's mac key. The store keeps it in
    /// its `meta` table and flips it inside the rotation transaction — the
    /// committed marker that open-time reconciliation compares against.
    pub fn keycheck_hex(&self) -> String {
        hex::encode(record_hmac(&self.mac_key, b"undercroft.v1/keycheck"))
    }

    /// Re-seal one at-rest blob from this vault's keys to `next`'s, without
    /// interpreting the plaintext (byte-exact inner bytes — no
    /// decompress/requantize round trips). `full_record_id` is the seal-layer
    /// record id including any domain suffix (`{id}`, `{id}/emb`, `{id}/tok`,
    /// `pqrow/{seq}/pq`, `fde/{id}/tok`, …). Hmac-only vaults store these
    /// blobs in clear, so the blob passes through unchanged.
    pub fn reseal_at_rest(
        &self,
        next: &Vault,
        full_record_id: &str,
        blob: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        match self.level {
            SecurityLevel::Sealed => {
                let inner = seal::open_content(&self.enc_key, &self.id, full_record_id, blob)?;
                Ok(seal::seal_content(
                    &next.enc_key,
                    &next.id,
                    full_record_id,
                    &inner,
                ))
            }
            SecurityLevel::HmacOnly => Ok(blob.to_vec()),
        }
    }

    /// Take the pending rotation twin attached at unlock, if any.
    pub fn take_pending(&mut self) -> Option<Box<Vault>> {
        self.pending.take()
    }

    /// Whether a staging manifest from a key rotation is attached.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// What a staged rotation means, given the database's committed
    /// `keycheck` marker — **decided without doing anything**.
    ///
    /// Split out from the store's `reconcile_rotation` for the same reason
    /// [`chain_next_hex`](Self::chain_next_hex) is split from
    /// [`anchor_manifest`](Self::anchor_manifest): the arithmetic is pure and
    /// the effect is not, so a caller that must not write can still learn the
    /// verdict and report it.
    pub fn rotation_verdict(&self, db_keycheck: Option<&str>) -> RotationVerdict {
        match &self.pending {
            None => RotationVerdict::Settled,
            Some(pending) if db_keycheck == Some(pending.keycheck_hex().as_str()) => {
                RotationVerdict::Committed
            }
            Some(_) => RotationVerdict::Abandoned,
        }
    }

    /// Reconcile a staged rotation **without touching the filesystem**.
    ///
    /// The writable path promotes or discards `vault.json.next`; both are
    /// writes, and doing them from a read-only open is how the documented
    /// incident-response procedure — restart `--read-only` to freeze writes —
    /// could adopt a key generation or delete a writer's staging manifest
    /// (ROADMAP A32). Here the file is left exactly as found.
    ///
    /// A committed rotation still has to be *honoured in memory*: the
    /// database is already sealed under the staged keys, so a reader that
    /// kept the old ones would fail every AEAD open and read the vault as
    /// corrupt. Adopting them costs nothing on disk and is what keeps
    /// "detect and report" from meaning "serve garbage".
    pub fn reconcile_read_only(&mut self, db_keycheck: Option<&str>) -> RotationVerdict {
        let verdict = self.rotation_verdict(db_keycheck);
        match verdict {
            RotationVerdict::Settled => {}
            RotationVerdict::Committed => {
                let pending = self.pending.take().expect("verdict saw a pending twin");
                let notes = std::mem::take(&mut self.unhealed);
                *self = *pending;
                self.unhealed = notes;
                self.unhealed.push(Unhealed::RotationPromotionDeferred);
            }
            RotationVerdict::Abandoned => {
                self.pending = None;
                self.unhealed.push(Unhealed::RotationDiscardDeferred);
            }
        }
        verdict
    }

    fn pending_path(&self) -> PathBuf {
        self.dir.join("vault.json.next")
    }

    /// Fill this rotation candidate's chain state and durably stage it as
    /// `vault.json.next` (fsync + directory sync). Called by the store
    /// *before* the re-seal transaction commits; a crash before commit
    /// leaves a stale staging file that reconciliation discards.
    pub fn save_manifest_pending(&mut self, head_hex: &str, writes: u64) -> Result<(), VaultError> {
        self.manifest.chain_head_hex = head_hex.to_string();
        self.manifest.writes = writes;
        self.manifest.manifest_mac_hex =
            hex::encode(record_hmac(&self.manifest_key, &self.manifest.canonical()));
        let json = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        {
            use std::io::Write;
            let mut f = fs::File::create(self.pending_path())?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        keys::sync_dir(&self.dir)?;
        Ok(())
    }

    /// Promote a committed rotation: `vault.json.next` becomes the manifest.
    ///
    /// A **write** (rename + directory sync). A caller that promised not to
    /// write calls [`reconcile_read_only`](Self::reconcile_read_only) instead.
    pub fn promote_manifest(&self) -> Result<(), VaultError> {
        fs::rename(self.pending_path(), self.dir.join("vault.json"))?;
        keys::sync_dir(&self.dir)?;
        Ok(())
    }

    /// Remove a staging manifest from a rotation that never committed.
    ///
    /// A **write** (unlink + directory sync), and the one that destroys a
    /// concurrent writer's in-flight rotation if it runs from the wrong
    /// posture. See [`reconcile_read_only`](Self::reconcile_read_only).
    pub fn discard_pending_file(&self) -> Result<(), VaultError> {
        let p = self.pending_path();
        if p.exists() {
            fs::remove_file(&p)?;
            keys::sync_dir(&self.dir)?;
        }
        Ok(())
    }

    /// The chain head of the manifest currently ON DISK, **MAC-verified**.
    ///
    /// This is what a tamper decision must read. `chain_head_hex()` returns
    /// this handle's cached copy, written only by its own `anchor_manifest`
    /// and never reloaded — so on `serve-http`, which holds two handles on
    /// one vault, `reconcile_chain` and `verify` compared the database
    /// against an anchor a DIFFERENT handle had already moved, and neither
    /// could see a `vault.json` swapped on disk until a fresh open.
    /// `chain_state` was moved off the cached manifest for exactly this
    /// reason, and then the chain-commit counter was too — which left the
    /// least security-relevant consumer reading fresh while the two that
    /// decide `ManifestTampered` and `chain_ok` read stale.
    ///
    /// **MAC-verified, unlike [`anchored_writes`](Self::anchored_writes).**
    /// That one feeds a telemetry delta and a forged value can misreport a
    /// count and reach nothing else; this one decides whether a vault is
    /// declared tampered, so an unverifiable manifest is itself the verdict.
    /// A missing or unreadable file falls back to the cached head rather
    /// than inventing one — the anchor is allowed to lag, and a read failure
    /// is not evidence of tampering.
    pub fn anchored_head(&self) -> Result<String, VaultError> {
        let Ok(raw) = fs::read(self.dir.join("vault.json")) else {
            return Ok(self.manifest.chain_head_hex.clone());
        };
        let m: Manifest =
            serde_json::from_slice(&raw).map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        if m.id != self.id {
            return Err(VaultError::CorruptManifest("manifest id mismatch".into()));
        }
        let stored = hex::decode(&m.manifest_mac_hex)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        if verify_hmac(&self.manifest_key, &m.canonical(), &stored).is_err() {
            undercroft_obs::hmac_verify_failed("manifest");
            undercroft_obs::event_hmac_fail(
                self.id(),
                "manifest",
                undercroft_obs::TamperSite::default(),
            );
            return Err(VaultError::ManifestTampered);
        }
        Ok(m.chain_head_hex)
    }

    /// The `writes` height of the manifest currently ON DISK — the last
    /// anchor any handle on this vault committed.
    ///
    /// Deliberately unauthenticated and deliberately not fatal: its only
    /// consumer is the chain-commit counter's delta, which is telemetry. A
    /// forged value can misreport a count and can reach nothing else, so
    /// verifying the MAC here would trade a real failure mode (a write that
    /// cannot complete because a metrics subtrahend would not load) for a
    /// signal that is already outside HMAC coverage by construction.
    fn anchored_writes(&self) -> Option<u64> {
        let raw = fs::read(self.dir.join("vault.json")).ok()?;
        serde_json::from_slice::<Manifest>(&raw)
            .ok()
            .map(|m| m.writes)
    }

    fn save_manifest(&mut self) -> Result<(), VaultError> {
        self.manifest.manifest_mac_hex =
            hex::encode(record_hmac(&self.manifest_key, &self.manifest.canonical()));
        let json = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        // Durable atomic replace: fsync the bytes before the rename and the
        // directory entry after it, or a power loss can reorder the rename
        // ahead of the data and leave a torn anchor that reads as tamper.
        let tmp = self.dir.join("vault.json.tmp");
        {
            use std::io::Write;
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.dir.join("vault.json"))?;
        keys::sync_dir(&self.dir)?;
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
    ///
    /// Writable posture — the one every write role wants. A caller that must
    /// not write states so through [`unlock_as`](Self::unlock_as).
    pub fn unlock(&self, id: &str) -> Result<Vault, VaultError> {
        self.unlock_as(id, Access::ReadWrite)
    }

    /// [`unlock`](Self::unlock) with the caller's posture stated.
    ///
    /// Under [`Access::ReadOnly`] the one filesystem repair unlock performs —
    /// deleting a `vault.json.next` that does not authenticate — is skipped
    /// and recorded on [`Vault::unhealed`] instead. That file is unreadable
    /// *to us*; it is not necessarily garbage to the process that is writing
    /// it right now, and a replica is exactly the role most likely to meet
    /// one mid-rotation.
    pub fn unlock_as(&self, id: &str, access: Access) -> Result<Vault, VaultError> {
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
        let mut vault = self.assemble(dir, manifest)?;
        // Verify the manifest itself before trusting level / chain head.
        let expected = record_hmac(&vault.manifest_key, &vault.manifest.canonical());
        let stored = hex::decode(&vault.manifest.manifest_mac_hex)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        if verify_hmac(&vault.manifest_key, &vault.manifest.canonical(), &stored).is_err() {
            let _ = expected;
            undercroft_obs::hmac_verify_failed("manifest");
            undercroft_obs::event_hmac_fail(
                vault.id(),
                "manifest",
                undercroft_obs::TamperSite::default(),
            );
            return Err(VaultError::ManifestTampered);
        }
        // Attach a pending rotation manifest (vault.json.next) for the
        // store's open-time reconciliation. An unreadable, mismatched, or
        // MAC-invalid staging file is a torn leftover — remove it here.
        let pending_path = vault.pending_path();
        if pending_path.exists() {
            vault.pending = fs::read(&pending_path)
                .ok()
                .and_then(|raw| serde_json::from_slice::<Manifest>(&raw).ok())
                .filter(|pm| pm.id == vault.id)
                .and_then(|pm| self.assemble(vault.dir.clone(), pm).ok())
                .filter(|pv| {
                    hex::decode(&pv.manifest.manifest_mac_hex)
                        .map(|mac| {
                            verify_hmac(&pv.manifest_key, &pv.manifest.canonical(), &mac).is_ok()
                        })
                        .unwrap_or(false)
                })
                .map(Box::new);
            if vault.pending.is_none() {
                match access {
                    Access::ReadWrite => {
                        let _ = fs::remove_file(&pending_path);
                    }
                    Access::ReadOnly => vault.unhealed.push(Unhealed::TornStagingManifest),
                }
            }
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
            sample_key: derive_vault_key(&self.master, &salt, &id, "sample"),
            level: manifest.level,
            id,
            dir,
            manifest,
            pending: None,
            unhealed: Vec::new(),
        })
    }

    /// Build the next key generation for a vault: same identity, level, and
    /// history metadata, **fresh salt** ⇒ fresh enc/mac/manifest/sample keys.
    /// The fourth one moves the training-sample draw
    /// ([`Vault::sample_rank`]), so a *future* retrain in a rotated vault draws
    /// a different sample; rotation itself only re-seals, never re-quantizes,
    /// so nothing already on disk changes.
    /// Nothing is written here — the store's rotation stages the manifest
    /// once it has replayed the chain under the new keys.
    pub fn rotation_candidate(&self, id: &str) -> Result<Vault, VaultError> {
        let current = self.unlock(id)?;
        let mut manifest = current.manifest.clone();
        manifest.salt_hex = hex::encode(keys::new_vault_salt());
        self.assemble(current.dir.clone(), manifest)
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

    /// The training-sample draw must be reproducible for the key holder,
    /// independent per label, and *different* per vault — that last part is
    /// the whole point: a bulk writer who knows the algorithm still cannot
    /// know which of their rows will train a codebook.
    #[test]
    fn sample_rank_is_reproducible_per_vault_and_not_shared() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let a = mgr.create("vault-a", SecurityLevel::Sealed).unwrap();
        let b = mgr.create("vault-b", SecurityLevel::Sealed).unwrap();

        // Reproducible: same vault, same label, same ident.
        assert_eq!(a.sample_rank("pq", b"7"), a.sample_rank("pq", b"7"));
        // Survives a reopen — the key is derived, never stored.
        let a2 = mgr.unlock("vault-a").unwrap();
        assert_eq!(a.sample_rank("pq", b"7"), a2.sample_rank("pq", b"7"));

        // Independent across vaults, labels, and idents.
        assert_ne!(a.sample_rank("pq", b"7"), b.sample_rank("pq", b"7"));
        assert_ne!(a.sample_rank("pq", b"7"), a.sample_rank("ivf", b"7"));
        assert_ne!(a.sample_rank("pq", b"7"), a.sample_rank("pq", b"8"));
        // Length-prefixed, so no (label, ident) pair can be re-cut into
        // another: ("pq", "17") vs ("pq1", "7"), and — the case a delimiter
        // gets wrong — a label that contains the delimiter itself.
        assert_ne!(a.sample_rank("pq", b"17"), a.sample_rank("pq1", b"7"));
        assert_ne!(a.sample_rank("a\x1fb", b"c"), a.sample_rank("a", b"b\x1fc"));

        // Distinct from the record tag over the same bytes — different key.
        let tag = a.tag(b"pq\x1f7");
        assert_ne!(
            a.sample_rank("pq", b"7"),
            u64::from_le_bytes(tag[..8].try_into().unwrap()),
            "the sample draw must not be the MAC key under another name"
        );
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
        // The store advances heads transactionally via chain_next_hex and
        // anchors the manifest afterwards — same arithmetic, split API.
        let h1 = v.chain_next_hex(&Vault::chain_genesis_hex(), &t1).unwrap();
        let h2 = v.chain_next_hex(&h1, &t2).unwrap();
        v.anchor_manifest(&h2, 2).unwrap();
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

    /// R4/A33: a caller that must not write has to be able to tell an EMPTY
    /// vault from an ABSENT database before it opens anything — the store's
    /// `Connection::open` carries `SQLITE_OPEN_CREATE`, so by the time it has
    /// a connection the difference is gone and a half-copied backup answers
    /// every read empty with no error.
    /// **The chain-commit delta is measured against the vault, not against
    /// this handle's memory of it.**
    ///
    /// `records = writes - self.manifest.writes`, where the subtrahend was
    /// only ever written by this handle's own anchor. `serve-http` holds TWO
    /// handles on one vault, so each measured the other's growth from its
    /// own stale baseline and counted it again — steady state 2× with two
    /// handles. `audit_chain_height` was explicitly moved off the cached
    /// manifest for this exact reason; the commit DELTA was not.
    ///
    /// Invisible to every existing test because the only consumer is a
    /// counter that is a no-op without the telemetry feature, which is why
    /// `anchor_manifest` returns the number now.
    /// **The tamper decision reads the manifest on DISK, MAC-verified.**
    ///
    /// `chain_head_hex()` is this handle's cached copy, written only by its
    /// own anchor. With two handles on one vault — what `serve-http` runs —
    /// `reconcile_chain` and `verify` compared the database against an
    /// anchor a different handle had already moved, and neither could see a
    /// `vault.json` swapped underneath them until a fresh open.
    ///
    /// Both halves: it FOLLOWS another handle's anchor, and it REFUSES a
    /// manifest whose MAC does not verify — the second is what makes it a
    /// tamper decision rather than just a fresher read.
    #[test]
    fn the_anchored_head_is_read_from_disk_and_mac_verified() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("two-handles", SecurityLevel::Sealed).unwrap();
        let mut a = mgr.unlock("two-handles").unwrap();
        let b = mgr.unlock("two-handles").unwrap();

        // Handle A moves the anchor. B's cached copy is stale by
        // construction — that staleness is the defect.
        a.anchor_manifest("aa11", 5).unwrap();
        assert_eq!(
            b.chain_head_hex(),
            Vault::chain_genesis_hex(),
            "premise: B's cached head is stale"
        );
        assert_eq!(
            b.anchored_head().unwrap(),
            "aa11",
            "the decision must follow the anchor ANY handle committed"
        );

        // And a manifest edited offline is the verdict, not a fresher read.
        let path = dir.path().join("vaults/two-handles/vault.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("aa11"), "premise: the head is in the file");
        std::fs::write(&path, raw.replace("aa11", "bb22")).unwrap();
        assert!(
            matches!(b.anchored_head(), Err(VaultError::ManifestTampered)),
            "an offline edit must fail the MAC, not be adopted"
        );
    }

    #[test]
    fn the_chain_commit_delta_counts_each_record_once_across_handles() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("two-handles", SecurityLevel::Sealed).unwrap();
        let mut a = mgr.unlock("two-handles").unwrap();
        let mut b = mgr.unlock("two-handles").unwrap();

        // Handle A commits five records.
        assert_eq!(a.anchor_manifest("aa", 5).unwrap(), 5);
        // Handle B commits ONE more. Its own cached baseline is still 0, so
        // this is the line that used to answer 6.
        assert_eq!(
            b.anchor_manifest("bb", 6).unwrap(),
            1,
            "the delta is against the last anchor ANY handle committed, not \
             against this handle's memory of one"
        );
        // ...and back again, in both directions, because a fix that simply
        // moved the staleness to the other handle would pass a one-way test.
        assert_eq!(a.anchor_manifest("cc", 9).unwrap(), 3);
        assert_eq!(b.anchor_manifest("dd", 10).unwrap(), 1);

        // The total is the chain's real growth, which is the counter's
        // whole contract.
        let mut c = mgr.unlock("two-handles").unwrap();
        assert_eq!(c.anchor_manifest("ee", 11).unwrap(), 1);

        // A crash between commit and anchor leaves records unanchored; the
        // NEXT anchor counts them. That is the same rule read-audit records
        // already rely on, and it must survive this change.
        assert_eq!(c.anchor_manifest("ff", 14).unwrap(), 3);

        // Single-handle behaviour is untouched — the case every existing
        // deployment is in.
        let dir2 = tempdir().unwrap();
        let mgr2 = VaultManager::open(dir2.path(), None).unwrap();
        mgr2.create("one-handle", SecurityLevel::Sealed).unwrap();
        let mut only = mgr2.unlock("one-handle").unwrap();
        assert_eq!(only.anchor_manifest("11", 1).unwrap(), 1);
        assert_eq!(only.anchor_manifest("22", 257).unwrap(), 256);
    }

    #[test]
    fn a_missing_database_is_distinguishable_from_an_empty_one() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("half-copied", SecurityLevel::Sealed).unwrap();
        // The manifest is what `VaultManager::exists` tests, and it is there.
        assert!(mgr.exists("half-copied"));
        assert!(
            !v.database_exists(),
            "a freshly created vault has no database yet — this is the state a \
             half-copied backup is in, and it must be visible"
        );
        std::fs::write(v.db_path(), b"").unwrap();
        assert!(v.database_exists());
    }

    /// R4: unlocking is not passive. A staging manifest that does not
    /// authenticate is deleted by a writable unlock — correct there, and a
    /// filesystem write a read-only caller must not perform, because the file
    /// it cannot authenticate may be one a writer is in the middle of staging.
    ///
    /// Both arms run so the test cannot pass by the removal simply never
    /// happening.
    #[test]
    fn a_read_only_unlock_leaves_a_torn_staging_manifest_alone() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("t", SecurityLevel::Sealed).unwrap();
        let staging = dir.path().join("vaults/t/vault.json.next");

        std::fs::write(&staging, b"not a manifest").unwrap();
        let v = mgr.unlock_as("t", Access::ReadOnly).unwrap();
        assert!(
            staging.exists(),
            "a read-only unlock must not remove a staging manifest"
        );
        assert_eq!(v.unhealed(), [Unhealed::TornStagingManifest].as_slice());
        assert!(!v.has_pending());

        // Counterfactual: the writable posture still heals it.
        let v = mgr.unlock_as("t", Access::ReadWrite).unwrap();
        assert!(!staging.exists(), "a writable unlock discards a torn file");
        assert!(v.unhealed().is_empty());
        // ...and the default door is the writable one.
        assert!(mgr.unlock("t").unwrap().unhealed().is_empty());
    }

    /// A32: a rotation whose re-seal COMMITTED but whose manifest rename was
    /// lost. The writable path renames `vault.json.next` over `vault.json`; a
    /// read-only open must adopt the staged keys **in memory only** — it has
    /// to adopt them, because the database is already sealed under them, and
    /// it must not rename, because that adopts a key generation on the
    /// posture chosen to touch nothing.
    #[test]
    fn a_read_only_reconcile_adopts_committed_keys_without_touching_disk() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("r", SecurityLevel::Sealed).unwrap();
        let vdir = dir.path().join("vaults/r");
        let (live, staging) = (vdir.join("vault.json"), vdir.join("vault.json.next"));

        let mut next = mgr.rotation_candidate("r").unwrap();
        let next_keycheck = next.keycheck_hex();
        next.save_manifest_pending(&Vault::chain_genesis_hex(), 0)
            .unwrap();
        let before = std::fs::read(&live).unwrap();
        assert!(staging.exists(), "premise: a staging manifest is on disk");

        let mut v = mgr.unlock_as("r", Access::ReadOnly).unwrap();
        assert!(v.has_pending(), "premise: the staging twin attached");
        // The database's committed marker names the staged generation.
        assert_eq!(
            v.rotation_verdict(Some(&next_keycheck)),
            RotationVerdict::Committed
        );
        assert_eq!(
            v.reconcile_read_only(Some(&next_keycheck)),
            RotationVerdict::Committed
        );

        assert_eq!(
            v.keycheck_hex(),
            next_keycheck,
            "the staged keys must be adopted in memory or every sealed read fails"
        );
        assert!(staging.exists(), "vault.json.next must not be promoted");
        assert_eq!(
            std::fs::read(&live).unwrap(),
            before,
            "the live manifest must be byte-identical"
        );
        assert_eq!(
            v.unhealed(),
            [Unhealed::RotationPromotionDeferred].as_slice()
        );
    }

    /// The other verdict: a rotation that never committed. The writable path
    /// unlinks the staging file — which is precisely the operation that
    /// destroys a *concurrent* writer's in-flight rotation when it runs from
    /// a replica (A32). Read-only keeps the file and says so.
    #[test]
    fn a_read_only_reconcile_keeps_an_abandoned_rotations_staging_file() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let current = mgr.create("r", SecurityLevel::Sealed).unwrap();
        let current_keycheck = current.keycheck_hex();
        let staging = dir.path().join("vaults/r/vault.json.next");

        let mut next = mgr.rotation_candidate("r").unwrap();
        next.save_manifest_pending(&Vault::chain_genesis_hex(), 0)
            .unwrap();
        assert!(staging.exists(), "premise: a staging manifest is on disk");

        let mut v = mgr.unlock_as("r", Access::ReadOnly).unwrap();
        assert_eq!(
            v.reconcile_read_only(Some(&current_keycheck)),
            RotationVerdict::Abandoned
        );
        assert!(
            staging.exists(),
            "a read-only open must never unlink a writer's staging manifest"
        );
        assert_eq!(
            v.keycheck_hex(),
            current_keycheck,
            "an uncommitted rotation must not move the keys in use"
        );
        assert_eq!(v.unhealed(), [Unhealed::RotationDiscardDeferred].as_slice());

        // No staging manifest at all is the ordinary case and heals nothing.
        let mut v = mgr.unlock_as("r", Access::ReadOnly).unwrap();
        v.take_pending();
        assert_eq!(
            v.reconcile_read_only(Some(&current_keycheck)),
            RotationVerdict::Settled
        );
        assert!(v.unhealed().is_empty());
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
