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
//!   canonical bytes (independent MAC key); the store's `chain_meta` row
//!   carries the tamper-evident HMAC chain over all writes, and the vault
//!   manifest holds a MAC'd, lagging rollback anchor reconciled at open.
//!   `undercroft verify` walks both.
//!
//! Threat model: protects memories at rest against disk theft, cross-vault
//! bleed, and offline tampering of the database or manifest. It does not
//! defend against an attacker who can read process memory while a vault is
//! unlocked.
#![warn(missing_docs)]

pub mod backups;
pub mod bundle;
pub mod keys;
pub mod restores;
pub mod seal;

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use keys::{derive_vault_key, SecretKey, KEY_LEN};
use seal::{chain_next, record_hmac, verify_hmac, SealError, HMAC_LEN};

/// Everything the vault layer can refuse: I/O, key and seal failures, a vault that is missing or already present, a manifest that is corrupt or fails its MAC, and an invalid name.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// A filesystem operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Master-key or key-derivation failure.
    #[error("key error: {0}")]
    Key(#[from] keys::KeyError),
    /// Sealing or opening a record failed: wrong key, tampered bytes, or a truncated blob.
    #[error("seal error: {0}")]
    Seal(#[from] SealError),
    /// No vault of this id has a manifest under the palace.
    #[error("vault {0:?} not found (create it with `undercroft vault create {0}`)")]
    NotFound(String),
    /// A vault of this id already has a manifest.
    #[error("vault {0:?} already exists")]
    AlreadyExists(String),
    /// The manifest could not be read as one — or a sealed content frame
    /// could not be decoded (`decompress_frame` raises this variant for a
    /// frame past the content bound or a failed zstd decode) — or a chain
    /// head handed to `chain_step_hex` is not hex (the message names the
    /// manifest even then); the message says which. All are integrity
    /// verdicts on the CLI (exit 2).
    #[error("vault manifest is corrupt: {0}")]
    CorruptManifest(String),
    /// The manifest's HMAC does not verify under the vault's keys — evidence of tampering, and an integrity verdict on every surface.
    #[error("vault manifest failed integrity verification — possible tampering")]
    ManifestTampered,
    /// The vault id failed `validate_name`.
    #[error("invalid vault name: {0}")]
    BadName(#[from] undercroft_core::CoreError),
    /// A manager opened read-only was asked for something that writes, or
    /// for a key it never held (ROADMAP O204). Refused before any effect; a
    /// posture error, never an integrity verdict.
    #[error("refused under a read-only posture: {0}")]
    ReadOnly(&'static str),
    /// The manifest was written by a NEWER Undercroft than this build
    /// (ROADMAP O238). The vault is intact; this binary is simply too old
    /// for it, so this is a POSTURE refusal and never an integrity verdict —
    /// exit 1 on the CLI and a class-less 409 on `/v1`, like
    /// `ReadOnlyUnmigrated` and unlike `ManifestTampered`.
    ///
    /// **Read before the MAC is compared**, which is safe for one reason and
    /// only that reason: `version` is the FIRST field of
    /// [`Manifest::canonical`], so it is MAC-covered. Trusting it ahead of
    /// verification can therefore buy a refusal and never an acceptance — a
    /// forged bump makes this build refuse a vault it would otherwise have
    /// opened, which is the safe direction, and a forged DOWNGRADE cannot
    /// help an attacker because the MAC comparison that follows fails.
    #[error(
        "this vault's manifest is version {found}, and this build of Undercroft understands \
         up to version {supported} — upgrade Undercroft to open it (ROADMAP O238)"
    )]
    ManifestTooNew {
        /// The version the manifest on disk declares.
        found: u32,
        /// The newest version this build understands.
        supported: u32,
    },
    /// `create` found vault manifests in the installation and the master key
    /// verifies NONE of them (ROADMAP O204). A vault created now would be
    /// sealed under a key no existing vault uses — a split installation. An
    /// integrity verdict on every surface: it is the same finding a `search`
    /// of any of those vaults reports as tampering.
    #[error(
        "the master key opens none of the {manifests} vault manifest(s) here, so no vault was \
         created: it would be sealed under a key no existing vault uses. {} (ROADMAP O204)",
        key_opens_no_vault_reading(.declared)
    )]
    KeyOpensNoVault {
        /// Vault manifests found under `vaults/`.
        manifests: usize,
        /// The key source this process declared.
        declared: keys::KeySource,
    },
    /// A restore of this vault was interrupted between its two renames
    /// (ROADMAP O268): the vault it was replacing sits in the restore area and
    /// `vaults/<id>` may be empty. `create` and `backup restore` refuse until an
    /// operator puts it back, so an `init` after the crash cannot mint an empty
    /// vault over the one set aside. A posture refusal, never an integrity
    /// verdict: exit 1, and a 409 with no class.
    #[error(
        "a restore of vault {id:?} was interrupted: the vault it was replacing is kept at {} \
         and nothing was changed. Stop every process using the vault, then put it back with \
         `mv '{}' '{}'`, or remove it once the vault at that path is the one you want \
         (ROADMAP O268)",
        aside.display(),
        aside.display(),
        target.display()
    )]
    RestoreInterrupted {
        /// The vault the interrupted restore was replacing.
        id: String,
        /// Where that vault was set aside.
        aside: PathBuf,
        /// Where it goes back.
        target: PathBuf,
    },
}

fn key_opens_no_vault_reading(declared: &keys::KeySource) -> &'static str {
    match declared {
        keys::KeySource::Passphrase => {
            "Either UNDERCROFT_PASSPHRASE is not this installation's passphrase, or this installation was \
             set up without one and a stray kdf.salt is present (check both before changing \
             anything), or the manifests were tampered with"
        }
        keys::KeySource::KeyFile => {
            "Either this installation was set up with a passphrase and UNDERCROFT_PASSPHRASE is not \
             declared, or master.key is not this installation's key, or the manifests were tampered \
             with"
        }
    }
}

/// The installation directory holding one directory per vault.
pub const VAULTS_DIR: &str = "vaults";

/// The installation directory `undercroft backup create` copies vaults into. Each
/// copy carries its `vault.json`, which only this installation's master key opens,
/// so a backup refers to the key exactly as a vault does (ROADMAP O204).
pub const BACKUPS_DIR: &str = "backups";

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

/// The newest manifest format this build understands, and the version every
/// manifest it writes declares (ROADMAP O238).
///
/// **Bumping this is how a future on-disk change fences older binaries**, and
/// it is the ONLY thing that does. O233 had to fence 1.5.x out of a migrated
/// chain by freezing a database row that 1.5.x happens to compare; the next
/// format change may find no such row to freeze.
///
/// **A bump must ship in a release of its own, EARLIER than the change it
/// fences** (O241 ruling 4). A version bump alone is readable by an older
/// build — the canonical is unchanged in shape, so its MAC still verifies —
/// but a bump PLUS a new canonical field makes every older binary rebuild a
/// different canonical and answer `ManifestTampered` on an intact vault. The
/// fence has to be in the field before the format moves, or it reports
/// tampering instead of age.
pub const MANIFEST_VERSION: u32 = 1;

/// A vault's `vault.json` as read from disk: its exact bytes, verified under
/// the reading handle's manifest key, and the anchor they name (ROADMAP O256).
///
/// Minted only by [`Vault::verified_manifest`]; its bytes are written only by
/// [`backups::Stage::write_manifest`]. That is the pairing a backup needs —
/// the manifest archived beside the copied rows is the manifest those rows
/// were verified against, byte for byte, and never one this build composed.
pub struct VerifiedManifest {
    bytes: Vec<u8>,
    head: String,
    writes: u64,
    staged: bool,
}

impl VerifiedManifest {
    /// The chain head this manifest anchors.
    pub fn chain_head(&self) -> &str {
        &self.head
    }

    /// The chain height this manifest anchors.
    pub fn writes(&self) -> u64 {
        self.writes
    }

    /// Whether these are `vault.json.next`'s bytes: a committed key
    /// rotation's promote is deferred, and the staged manifest is the one the
    /// rows answer to (ROADMAP O266).
    pub fn is_staged(&self) -> bool {
        self.staged
    }
}

/// The manifest a handle's rows answer to, as read from disk (ROADMAP O266).
struct InForce {
    manifest: Manifest,
    /// Its exact bytes on disk.
    bytes: Vec<u8>,
    /// Whether it is `vault.json.next`'s — a deferred promote.
    staged: bool,
}

/// Why [`Vault::manifest_in_force`] found no manifest in force (ROADMAP
/// O266). Nothing is raised here; each reader decides what a miss means.
enum NotInForce {
    /// A manifest file could not be read — on a deferred handle, with
    /// `vault.json.next` still intact.
    Unreadable(std::io::Error),
    /// A manifest that does not parse, names another vault or is too new:
    /// today's verdict for each, as is.
    Refused(VaultError),
    /// A manifest failing this handle's MAC that is not the retired one the
    /// handle's adoption was licensed by: the one tamper verdict.
    Tampered,
    /// A deferred promote whose staged manifest is gone or changed, while
    /// `vault.json` does not verify under the handle's keys: the keys the
    /// database is sealed under are in no file.
    StagedLost(String),
}

impl std::fmt::Debug for VerifiedManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedManifest")
            .field("writes", &self.writes)
            .field("head", &self.head)
            .field("staged", &self.staged)
            .finish_non_exhaustive()
    }
}

impl Manifest {
    /// **The one door every manifest on disk is parsed through** (ROADMAP
    /// O238): deserialize, then refuse a version this build does not
    /// understand.
    ///
    /// The version gate sits HERE rather than at each call site because
    /// there are five of them — the open, the staging manifest, the fresh
    /// anchor read, O204's key survey and the telemetry delta — and a gate
    /// applied per call site is the arrangement that let three write paths
    /// past the admission screen.
    ///
    /// It runs BEFORE any MAC comparison, and that ordering is the ruling's
    /// (O241 ruling 4) rather than a convenience: see
    /// [`VaultError::ManifestTooNew`] for why reading a MAC-covered field
    /// ahead of its own verification is sound in this one direction.
    fn parse(raw: &[u8]) -> Result<Self, VaultError> {
        let manifest: Self =
            serde_json::from_slice(raw).map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        if manifest.version > MANIFEST_VERSION {
            return Err(VaultError::ManifestTooNew {
                found: manifest.version,
                supported: MANIFEST_VERSION,
            });
        }
        Ok(manifest)
    }

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
/// Opening a vault is not a passive act: the store reconciles the filesystem
/// side of a key rotation, and an unlock used to remove a `vault.json.next`
/// it could not authenticate. Both are writes, and both used to happen
/// whatever the caller's posture was — so a replica started to *freeze*
/// writes during incident response could delete a writer's staging manifest
/// on the way up (ROADMAP A32). Stating the posture is how a read-only caller
/// gets detection instead of healing. Since ROADMAP O257 no unlock deletes
/// anything on either posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// The caller may write. Reconciliation heals, as it always has.
    ReadWrite,
    /// The caller must not write. Nothing on disk is touched; what would
    /// have been healed is recorded on [`Vault::unhealed`] instead.
    ReadOnly,
}

/// Whose manifest an unlock is checking, which decides whether a MAC failure
/// raises the vault's tamper event (ROADMAP O268): a restore's staged copy of
/// an archive is not the live vault, and an alert naming the live vault for an
/// archive's fault would send an operator to the one thing that is intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tamper {
    LiveVault,
    Archive,
}

/// The per-vault database's filename since 1.5.0 (ROADMAP O7). It sits
/// beside `vault.json`, the manifest, and names the same thing that file
/// names: THIS vault. "The palace" is the whole installation and stays so.
pub const DB_FILE: &str = "vault.db";

/// The per-vault database's filename before 1.5.0. Still served wherever it
/// is found, and renamed to [`DB_FILE`] by the first writable open.
pub const LEGACY_DB_FILE: &str = "palace.db";

/// Which database file a vault directory holds (ROADMAP O7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbLayout {
    /// `vault.db` alone.
    Current,
    /// `palace.db` alone: a pre-1.5.0 vault no writable open has renamed.
    Legacy,
    /// Neither: a vault about to be created, or a manifest whose database
    /// is missing (A33) — `database_exists` is what tells those apart from
    /// a caller's point of view, and it says "absent" for both.
    Absent,
    /// Both: two databases claiming one manifest. Refused at open on every
    /// posture rather than guessed at, because whichever one the manifest's
    /// chain head anchors, the other is a stray copy an operator must judge.
    Ambiguous,
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
    /// fails its MAC. Reported on EVERY posture and never deleted (ROADMAP
    /// O257): a file this build cannot authenticate is inert, and it is either
    /// evidence (a planted file) or a torn pre-1.7 in-place write, which no
    /// reader can tell apart. The next key rotation stages over it.
    TornStagingManifest,
    /// A `vault.json.next` written by a NEWER build than this one (ROADMAP
    /// O238, O257): another build's rotation is pending, and this build may
    /// neither promote nor delete it. Reported on every posture.
    StagingManifestTooNew,
    /// A rotation whose re-seal COMMITTED: its keys were adopted in memory
    /// so this process can read the database, but `vault.json.next` was not
    /// renamed over `vault.json`.
    RotationPromotionDeferred,
    /// A rotation that never committed: its staging file is still on disk.
    RotationDiscardDeferred,
    /// The database is still under its pre-1.5.0 name, `palace.db`
    /// (ROADMAP O7). Renaming it is a write, and one that needs a WAL
    /// checkpoint first, so a read-only open serves it where it is and a
    /// writable open renames it.
    LegacyDatabaseName,
}

impl std::fmt::Display for Unhealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unhealed::LegacyDatabaseName => f.write_str(
                "the database is still named palace.db (renaming it is a write, and it \
                 needs a WAL checkpoint first); a writable open will rename it to vault.db",
            ),
            Unhealed::TornStagingManifest => f.write_str(
                "vault.json.next does not authenticate under this vault's keys and was left in \
                 place (ROADMAP O257): it is a torn write from a build before 1.7.0, or a file \
                 something other than Undercroft put there. Nothing reads it. The next \
                 `undercroft vault rotate` replaces it; to remove it by hand, first stop every \
                 process that has the vault open and check `undercroft verify` passes",
            ),
            Unhealed::StagingManifestTooNew => f.write_str(
                "vault.json.next was written by a NEWER build of Undercroft than this one: that \
                 build's key rotation is pending, and this build neither promotes nor deletes \
                 it (ROADMAP O238, O257). Open the vault with the newer build",
            ),
            Unhealed::RotationPromotionDeferred => f.write_str(
                "a committed key rotation was adopted in memory only — vault.json.next \
                 was NOT promoted over vault.json (that is a write), so vault.json still \
                 names the previous key generation. This open verified the vault against \
                 the staged manifest it read, which a writable open promotes. Do NOT \
                 delete vault.json.next: until then it is the only file holding the \
                 vault's current keys (ROADMAP O266)",
            ),
            Unhealed::RotationDiscardDeferred => f.write_str(
                "an uncommitted key rotation left vault.json.next on disk and it was \
                 kept (removing it is a write); a writable open will discard it",
            ),
        }
    }
}

/// Why a handle stopped writing (ROADMAP O254, O266). The kind decides the
/// class of the refusal every later write through the handle answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retirement {
    /// Its anchor found a manifest on disk its keys may not overwrite —
    /// another process rotated the vault, or the file was edited. An
    /// integrity finding.
    Integrity(String),
    /// Its own key rotation committed and the new manifest could not be
    /// written (ROADMAP O266): its keys ARE the vault's and
    /// `vault.json.next` holds them, so a reopen — whose writable open
    /// promotes it — is the whole remedy. Not an integrity finding.
    PromotionDeferred(String),
}

impl Retirement {
    /// The reason, whichever the kind.
    pub fn why(&self) -> &str {
        match self {
            Retirement::Integrity(why) | Retirement::PromotionDeferred(why) => why,
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
    /// The marker is present and names NEITHER this handle's generation nor
    /// the staged one (ROADMAP O257): another process rotated the vault after
    /// this unlock read it, or the manifest and the database disagree. What it
    /// means is decided by the store, which can read the rest of the evidence
    /// — this verdict only says the keycheck alone cannot settle it.
    Foreign,
}

/// Which audit-chain step a row takes (ROADMAP O233).
///
/// The store decides it per row, from one record: rows before the chain's
/// `migrate/chain-v2` commitment are `V1`, that record and every row after it
/// are `V2`. A forget attestation names its own through its `version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStep {
    /// `HMAC(mac_key, prev ‖ tag)`: the tag alone, as every chain before O233.
    V1,
    /// [`seal::chain_next_v2`]: the label, the tag and the time, under the
    /// `chain` subkey.
    V2,
}

/// One audit row as a chain step reads it: exactly the bytes the `audit`
/// table holds for it.
#[derive(Debug, Clone, Copy)]
pub struct ChainLink<'a> {
    /// `audit.record_id` — the label every reader finds the row by.
    pub record_id: &'a str,
    /// `audit.tag`.
    pub tag: &'a [u8],
    /// `audit.at`.
    pub at: &'a str,
}

/// The manifest's filename inside a vault directory.
pub const MANIFEST_FILE: &str = "vault.json";

/// A key rotation's staged manifest, promoted over [`MANIFEST_FILE`] once the
/// re-seal commits.
pub const STAGING_FILE: &str = "vault.json.next";

/// What separates a manifest file's name from the random nonce of the temp
/// file it is written through (ROADMAP O254): `vault.json.tmp.<32 hex>`.
///
/// **Never the bare `vault.json.tmp`**, which is what every anchor before
/// 1.7.0 wrote through — one fixed path, truncated by `File::create`, shared
/// by every handle and process on the vault, so one handle's `rename` moved
/// another's half-written file and a committed write reported failure. A
/// 1.6.x process still writes that name, so nothing here matches or removes
/// it.
const TEMP_INFIX: &str = ".tmp.";

/// What an anchor did when it succeeded (ROADMAP O254).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchored {
    /// The manifest on disk already named the committed head and height, so
    /// nothing was written.
    Current,
    /// A new manifest was written; `records` is how many chain records it
    /// committed that the manifest on disk did not yet cover.
    Written {
        /// Chain records committed by this anchor — the chain-commit counter's
        /// delta, measured against the MAC-verified manifest on disk.
        records: u64,
    },
}

/// Why an anchor wrote nothing (ROADMAP O254) — in two classes, because they
/// call for opposite responses and swapping them fails silently either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorFault {
    /// The filesystem refused a read or a write: a permission error, a full
    /// disk, a sharing violation, an fsync or rename failure. Transient, and
    /// harmless to defer — any later anchor covers everything committed
    /// before it, exactly as a crash between commit and anchor already does —
    /// so the write it follows is never refused on its account.
    Io(String),
    /// The manifest on disk is not one this handle may overwrite: missing,
    /// unparseable, a version newer than this build writes, a MAC that does
    /// not verify under this handle's key, a database keycheck that is not
    /// this handle's, or a height above the committed one. Every one of
    /// these is either another process having rotated this vault's keys or
    /// tampering, and in both a write from this handle would be sealed under
    /// keys the vault no longer answers to — so the handle stops writing.
    Integrity(String),
}

impl std::fmt::Display for AnchorFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorFault::Io(why) | AnchorFault::Integrity(why) => f.write_str(why),
        }
    }
}

/// A SHA-256 of a staged manifest's bytes — how a handle remembers WHICH
/// `vault.json.next` it staged or read (ROADMAP O257).
fn digest_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Write `bytes` durably as `<dir>/<name>`, the ONE way a manifest file is
/// written (ROADMAP O254): a temp file named with a random nonce and created
/// with `create_new`, fsync, rename over `name`, directory sync.
///
/// `create_new` refuses an existing path, so a symlink planted at the temp
/// name is refused rather than followed, and two containers sharing a volume
/// cannot collide on it — they would on a pid, since pid 1 is everyone's. The
/// fsync before the rename and the directory sync after it are the anchor's
/// durability contract, unchanged: a power loss must never reorder the rename
/// ahead of the data and leave a torn anchor that reads as tamper.
///
/// A failure after the temp file exists removes it, best effort. What a crash
/// leaves behind is swept by [`Vault::sweep_orphan_temps`], under the lock.
fn write_manifest_file(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    use rand::RngCore;
    use std::io::Write;
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let tmp = dir.join(format!("{name}{TEMP_INFIX}{}", hex::encode(nonce)));
    #[cfg(any(test, feature = "test-fixture"))]
    fixture::fire(fixture::Fault::CreateTemp)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let written = (|| {
        file.write_all(bytes)?;
        #[cfg(any(test, feature = "test-fixture"))]
        fixture::fire(fixture::Fault::Fsync)?;
        file.sync_all()?;
        drop(file);
        #[cfg(any(test, feature = "test-fixture"))]
        fixture::fire(fixture::Fault::Rename)?;
        fs::rename(&tmp, dir.join(name))
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    keys::sync_dir(dir)
}

/// Whether `name` is a temp file [`write_manifest_file`] creates — the bare
/// legacy `vault.json.tmp` is NOT one, deliberately.
fn is_nonce_temp(name: &str) -> bool {
    [STAGING_FILE, MANIFEST_FILE].iter().any(|base| {
        name.strip_prefix(base)
            .and_then(|rest| rest.strip_prefix(TEMP_INFIX))
            .is_some_and(|nonce| {
                nonce.len() == 32
                    && nonce
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
    })
}

/// Failure injection for the manifest writes (ROADMAP O254) — the seam the
/// O254 gate drives, because a temp file named with a random nonce cannot be
/// targeted from outside this crate. Compiled for this crate's own tests and
/// under the `test-fixture` feature, which `undercroft-store` enables through
/// a dev-dependency — the `cfg(any(test, …))` shape `undercroft-embed-onnx`'s
/// fixture set (ROADMAP O134a). No production build carries it.
#[cfg(any(test, feature = "test-fixture"))]
pub mod fixture {
    use std::cell::Cell;

    /// Which step of this thread's NEXT manifest read or write fails.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Fault {
        /// Reading `vault.json` fails with an I/O error other than "not found".
        Read,
        /// Creating the nonce temp file fails.
        CreateTemp,
        /// The temp file's fsync fails.
        Fsync,
        /// The rename over the manifest fails.
        Rename,
        /// A restore's rename of the live vault into the restore area fails
        /// (ROADMAP O268).
        SwapAside,
        /// A restore's rename of its verified stage into `vaults/<id>` fails.
        SwapIn,
        /// A restore's rename of the live vault BACK after a failed `SwapIn`
        /// fails, leaving both directories where the error says.
        SwapBack,
        /// Removing a promoted rotation's `vault.json.next` fails, AFTER the
        /// new `vault.json` was written (ROADMAP O266): a promote that is
        /// done, whose leftover the next writable open removes.
        RemoveStaged,
    }

    thread_local! {
        static ARMED: Cell<Option<Fault>> = const { Cell::new(None) };
        static REMAINING: Cell<u32> = const { Cell::new(0) };
        static THEN: Cell<Option<Fault>> = const { Cell::new(None) };
        static BETWEEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Run `hook` once, on this thread, between the two reads the manifest
    /// rule makes on a handle whose promote is deferred — `vault.json.next`,
    /// then `vault.json` (ROADMAP O266). How a test races a promote against
    /// them without an inline seam in the code under test.
    pub fn between_manifest_reads(hook: impl FnOnce() + 'static) {
        BETWEEN.with(|between| *between.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn run_between_manifest_reads() {
        if let Some(hook) = BETWEEN.with(|between| between.borrow_mut().take()) {
            hook();
        }
    }

    /// Arm `first` once, and `second` once after it fires — a restore's
    /// failed move-in followed by a failed move back (ROADMAP O268), the
    /// state a crash between its two renames leaves.
    pub fn fail_in_turn(first: Fault, second: Fault) {
        fail_times(first, 1);
        THEN.with(|then| then.set(Some(second)));
    }

    /// Arm `fault` for this thread's next manifest operation that reaches that
    /// step. Consumed when it fires; thread-local, so parallel tests cannot
    /// trip each other's.
    pub fn fail_next(fault: Fault) {
        fail_times(fault, 1);
    }

    /// Arm `fault` for this thread's next `times` manifest operations that
    /// reach that step — a rotation retries its promote (ROADMAP O257), and a
    /// test of the deferral must fail every attempt.
    pub fn fail_times(fault: Fault, times: u32) {
        ARMED.with(|armed| armed.set((times > 0).then_some(fault)));
        REMAINING.with(|left| left.set(times));
        THEN.with(|then| then.set(None));
    }

    /// Whether an armed fault is still waiting to fire.
    pub fn armed() -> Option<Fault> {
        ARMED.with(|armed| armed.get())
    }

    pub(crate) fn fire(step: Fault) -> std::io::Result<()> {
        ARMED.with(|armed| {
            if armed.get() != Some(step) {
                return Ok(());
            }
            let left = REMAINING.with(|left| {
                let n = left.get().saturating_sub(1);
                left.set(n);
                n
            });
            if left == 0 {
                let then = THEN.with(|then| then.take());
                armed.set(then);
                if then.is_some() {
                    REMAINING.with(|left| left.set(1));
                }
            }
            Err(std::io::Error::other(format!(
                "injected {step:?} failure (the ROADMAP O254 test fixture)"
            )))
        })
    }

    /// Write a manifest naming `head` and `writes`, MAC'd under `vault`'s key,
    /// through the one writer and past EVERY check the anchor makes. It is how
    /// a test lowers an anchor, plants a stale one, or restores a legacy
    /// chain's — the moves the anchor exists to refuse.
    pub fn write_anchor_unchecked(
        vault: &mut super::Vault,
        head: &str,
        writes: u64,
    ) -> Result<(), super::VaultError> {
        vault.manifest.chain_head_hex = head.to_string();
        vault.manifest.writes = writes;
        vault.save_manifest()
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
    /// Keys [`Vault::sample_rank`] — the draw that decides what a trained
    /// index artifact trains on. Separate from the MAC key on purpose: those
    /// ranks are published *by their effects* (which rows shaped a codebook)
    /// and must not share a key with record integrity.
    sample_key: SecretKey,
    /// Keys the version-2 audit-chain step (ROADMAP O233), whose heads leave
    /// the vault on `/v1` and to the orchestrator — kept off the record-tag
    /// key for the reason `sample_key` is. The version-1 step stays on
    /// `mac_key`, which is what every chain written before O233 used.
    chain_key: SecretKey,
    manifest: Manifest,
    /// A pending key-rotation manifest (`vault.json.next`), attached at
    /// unlock when one exists so the store's open path can reconcile it
    /// against the database's keycheck: rotation committed ⇒ promote,
    /// not committed ⇒ discard.
    pending: Option<Box<Vault>>,
    /// What this unlock found and did not repair: on a read-only posture every
    /// filesystem repair it declined, and on EITHER posture a staging manifest
    /// it could not authenticate (ROADMAP O257).
    unhealed: Vec<Unhealed>,
    /// Why this handle may no longer write (ROADMAP O254, O266): set when its
    /// anchor met an [`AnchorFault::Integrity`], or when its own rotation
    /// committed and could not promote its manifest. `None` on every unlock.
    retired: Option<Retirement>,
    /// A SHA-256 of the `vault.json` bytes this unlock MAC-verified — the
    /// buffer the check read, never a second read (ROADMAP O266). `None` on a
    /// handle no unlock minted.
    manifest_seen: Option<[u8; 32]>,
    /// **Set only while this handle's keys came from `vault.json.next`**
    /// (ROADMAP O266): the SHA-256 of the RETIRED generation's `vault.json`
    /// whose MAC was verified before those keys were adopted. See
    /// [`adopt_deferred_promotion`](Self::adopt_deferred_promotion).
    deferred_over: Option<[u8; 32]>,
    /// This generation's keycheck marker, computed once — the write door
    /// compares it on every audited write (ROADMAP O257).
    keycheck: String,
    /// What this handle last knew of `vault.json.next` (ROADMAP O257): a
    /// SHA-256 of the bytes the unlock READ (whether or not they
    /// authenticated), or of the bytes a rotation STAGED; `None` when there
    /// was no such file. A staged file is only ever promoted or removed when
    /// it is still exactly these bytes, and a file that changed since is how
    /// the store tells a rotation racing this open from tampering.
    staged_seen: Option<[u8; 32]>,
}

impl Vault {
    /// The vault's id: its directory name under `vaults/`, and the AAD every sealed record is bound to.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The vault's directory, holding `vault.json` and its database.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path of this vault's SQLite database: the file the directory HOLDS.
    ///
    /// `vault.db` for every vault created since 1.5.0 and for every older
    /// vault a writable open has renamed; `palace.db` for an older vault no
    /// writable open has touched yet (ROADMAP O7 — one word named both the
    /// installation and each vault's database, and the per-vault file is the
    /// one that moved). A pure function of the directory, so a read-only
    /// open serves whichever name is there and renames nothing; the rename
    /// itself lives in the store's writable open, because it needs a WAL
    /// checkpoint first and this crate does not speak SQLite.
    pub fn db_path(&self) -> PathBuf {
        match self.db_layout() {
            DbLayout::Legacy => self.legacy_db_path(),
            _ => self.current_db_path(),
        }
    }

    /// `<vault dir>/vault.db`, whether or not it exists yet.
    pub fn current_db_path(&self) -> PathBuf {
        self.dir.join(DB_FILE)
    }

    /// `<vault dir>/palace.db`, the pre-1.5.0 name, whether or not it exists.
    pub fn legacy_db_path(&self) -> PathBuf {
        self.dir.join(LEGACY_DB_FILE)
    }

    /// Which database file this vault's directory holds (ROADMAP O7).
    pub fn db_layout(&self) -> DbLayout {
        match (
            self.current_db_path().exists(),
            self.legacy_db_path().exists(),
        ) {
            (true, true) => DbLayout::Ambiguous,
            (true, false) => DbLayout::Current,
            (false, true) => DbLayout::Legacy,
            (false, false) => DbLayout::Absent,
        }
    }

    /// Whether this vault's database file is actually there, under either
    /// name.
    ///
    /// [`VaultManager::exists`] answers about `vault.json`, which is a
    /// different file: a half-copied backup, an interrupted `rsync` or a
    /// snapshot taken mid-write can carry the manifest and not the database.
    /// `Connection::open` then CREATES the database and the vault answers
    /// every read empty with no error at all (ROADMAP A33). A caller that
    /// must not write has to be able to tell "empty" from "absent" before it
    /// opens anything, and this is that question. A vault still carrying
    /// `palace.db` has its database — reading it as ABSENT would turn every
    /// pre-1.5.0 vault into an integrity verdict on the day of the upgrade,
    /// which is exactly the trap O7's own filing named.
    pub fn database_exists(&self) -> bool {
        !matches!(self.db_layout(), DbLayout::Absent)
    }

    /// What this unlock found and did not repair: a read-only unlock's
    /// declined repairs, and on either posture a staging manifest it could not
    /// authenticate or that a newer build wrote (ROADMAP O257).
    pub fn unhealed(&self) -> &[Unhealed] {
        &self.unhealed
    }

    /// Sealed (AEAD content plus HMAC) or HMAC-only (plaintext content, tagged).
    pub fn level(&self) -> SecurityLevel {
        self.level
    }

    /// The write count the manifest anchor held when THIS handle last anchored — not the live count, which `VaultStats.writes` reads from `chain_meta`.
    pub fn writes(&self) -> u64 {
        self.manifest.writes
    }

    /// The chain head the manifest anchor held when THIS handle last anchored — the rollback anchor, not the live head, which lives in `chain_meta`.
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

    /// Recover an embedding from its at-rest form: opened under the record's `/emb` AAD domain on a sealed vault, read as-is on hmac-only, then dequantized from int8.
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
    /// never be swapped for each other. This was the sealed tier's first
    /// encrypted-at-rest derived store. Only the FTS *prefilter* remains an
    /// hmac-only plaintext side-table; PQ artifacts are sealed through
    /// `index_at_rest` under `/pq`, and a per-candidate rescore store can
    /// exist for sealed vaults because nothing derived ever touches disk
    /// in clear.
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

    /// One pure chain step over hex heads, in the version the caller STATES.
    /// The store owns *where* the committed head lives (a `chain_meta` row
    /// that advances inside the same SQLite transaction as the data it covers
    /// — a crash can never separate a record from its chain entry) and which
    /// version a row takes; the vault owns the keys. See
    /// [`anchor_manifest`](Self::anchor_manifest) for the out-of-database half.
    ///
    /// **The version is a required argument** (ROADMAP O233), on the `Screen`
    /// and `Read` precedent: this replaced `chain_next_hex`, which folded the
    /// tag alone, so every caller had to be rewritten to say which step it
    /// takes and none can inherit the old one by default.
    pub fn chain_step_hex(
        &self,
        step: ChainStep,
        prev_hex: &str,
        link: ChainLink<'_>,
    ) -> Result<String, VaultError> {
        let prev = hex::decode(prev_hex).map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        Ok(hex::encode(match step {
            ChainStep::V1 => chain_next(&self.mac_key, &prev, link.tag),
            ChainStep::V2 => {
                seal::chain_next_v2(&self.chain_key, &prev, link.record_id, link.tag, link.at)
            }
        }))
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
    ///
    /// **Its one caller is the store's `anchor()` door (ROADMAP O254)**,
    /// which holds SQLite's write lock around this call and reads `head_hex`,
    /// `writes` and `db_keycheck` from the committed database under it. That
    /// lock is what serialises anchors between handles and processes: every
    /// anchor used to write the handle's whole CACHED manifest through one
    /// fixed `vault.json.tmp`, so two handles collided on the temp file — a
    /// committed write reported failure, measured 27 times in eight seconds
    /// — and a handle opened before another's key rotation wrote the retired
    /// salt back over the new one, measured, which leaves the vault unable to
    /// decrypt what the rotation sealed (O257).
    ///
    /// So this is a read-modify-write of the file ON DISK, never a write of
    /// the cache: the manifest is read, parsed and MAC-verified under this
    /// handle's key; the database keycheck must be this handle's; its height
    /// may not be above the committed one. Both key checks are needed — a
    /// keycheck test alone is defeated by an open that re-seeds the old
    /// keycheck, a MAC test alone by a promote that runs outside the lock.
    /// Anything that fails them is [`AnchorFault::Integrity`] and nothing is
    /// written; a filesystem refusal is [`AnchorFault::Io`].
    ///
    /// The chain-commit counter advances by the delta against the VERIFIED
    /// manifest on disk — the last anchor any handle committed — so two
    /// handles never count each other's records twice, and records a crash
    /// left unanchored are counted by the next anchor.
    pub fn anchor_manifest(
        &mut self,
        head_hex: &str,
        writes: u64,
        db_keycheck: Option<&str>,
    ) -> Result<Anchored, AnchorFault> {
        let own = self.keycheck_hex();
        if db_keycheck != Some(own.as_str()) {
            return Err(AnchorFault::Integrity(format!(
                "the database's key-generation marker is not this handle's (database {}, handle \
                 {}): another process rotated this vault's keys after this handle unlocked it",
                db_keycheck.map_or("absent", |k| &k[..k.len().min(12)]),
                &own[..12]
            )));
        }
        let on_disk = self.verified_disk_manifest()?;
        if on_disk.writes > writes {
            return Err(AnchorFault::Integrity(format!(
                "vault.json records {} chain record(s) and the database has committed {writes}: \
                 the manifest is AHEAD of the database, so it was not written by an anchor of \
                 this database",
                on_disk.writes
            )));
        }
        if on_disk.chain_head_hex == head_hex && on_disk.writes == writes {
            self.manifest = on_disk;
            return Ok(Anchored::Current);
        }
        let mut next = on_disk.clone();
        next.chain_head_hex = head_hex.to_string();
        next.writes = writes;
        next.manifest_mac_hex = hex::encode(record_hmac(&self.manifest_key, &next.canonical()));
        let json = serde_json::to_vec_pretty(&next)
            .map_err(|e| AnchorFault::Io(format!("serializing the manifest: {e}")))?;
        write_manifest_file(&self.dir, MANIFEST_FILE, &json)
            .map_err(|e| AnchorFault::Io(format!("writing vault.json: {e}")))?;
        let records = writes - on_disk.writes;
        self.manifest = next;
        // Emitted only after the anchor is durable — the records it counts
        // are already committed, so no rolled-back write can be counted.
        undercroft_obs::chain_commit(records);
        undercroft_obs::event_chain_commit(self.id(), records);
        Ok(Anchored::Written { records })
    }

    /// The manifest on disk, parsed and MAC-verified under this handle's key,
    /// or the anchor's verdict on why it cannot be overwritten.
    fn verified_disk_manifest(&self) -> Result<Manifest, AnchorFault> {
        self.verified_disk_read().map(|(manifest, _)| manifest)
    }

    /// [`verified_disk_manifest`](Self::verified_disk_manifest) with the
    /// SHA-256 of the very bytes whose MAC it verified (ROADMAP O266).
    fn verified_disk_read(&self) -> Result<(Manifest, [u8; 32]), AnchorFault> {
        #[cfg(any(test, feature = "test-fixture"))]
        fixture::fire(fixture::Fault::Read)
            .map_err(|e| AnchorFault::Io(format!("reading vault.json: {e}")))?;
        let raw = match fs::read(self.dir.join(MANIFEST_FILE)) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(AnchorFault::Integrity(
                    "vault.json is missing: this vault's manifest was removed beneath a live \
                     handle"
                        .into(),
                ))
            }
            Err(e) => return Err(AnchorFault::Io(format!("reading vault.json: {e}"))),
        };
        let manifest = Manifest::parse(&raw).map_err(|e| match e {
            VaultError::ManifestTooNew { .. } => AnchorFault::Integrity(format!(
                "{e} — a newer build is writing this vault, and every writer on one vault must \
                 run the same build"
            )),
            other => AnchorFault::Integrity(format!("vault.json does not parse: {other}")),
        })?;
        if manifest.id != self.id {
            return Err(AnchorFault::Integrity(format!(
                "vault.json names vault {:?}, not {:?}",
                manifest.id, self.id
            )));
        }
        let verifies = hex::decode(&manifest.manifest_mac_hex)
            .map(|mac| verify_hmac(&self.manifest_key, &manifest.canonical(), &mac).is_ok())
            .unwrap_or(false);
        if !verifies {
            return Err(AnchorFault::Integrity(
                "vault.json does not verify under this handle's key: another process rotated \
                 this vault's keys after this handle unlocked it, or the file was edited"
                    .into(),
            ));
        }
        Ok((manifest, digest_of(&raw)))
    }

    /// Stop this handle writing, as an integrity finding (ROADMAP O254): its
    /// anchor found a manifest on disk its keys may not overwrite. The first
    /// reason stands.
    pub fn retire(&mut self, why: String) {
        self.retired.get_or_insert(Retirement::Integrity(why));
    }

    /// Stop this handle writing because its OWN rotation committed and the
    /// new manifest could not be written (ROADMAP O266). Not an integrity
    /// finding: its keys are the vault's, `vault.json.next` holds them, and a
    /// reopen promotes it. The first reason stands.
    pub fn retire_until_reopened(&mut self, why: String) {
        self.retired
            .get_or_insert(Retirement::PromotionDeferred(why));
    }

    /// Why this handle may no longer write, whichever kind of retirement it
    /// is. `None` otherwise.
    pub fn retired(&self) -> Option<&str> {
        self.retired.as_ref().map(Retirement::why)
    }

    /// This handle's retirement, with its kind — what decides the class of
    /// the refusal every later write answers (ROADMAP O266).
    pub fn retirement(&self) -> Option<&Retirement> {
        self.retired.as_ref()
    }

    /// The chain height of the manifest this handle's rows answer to, read
    /// from disk — the last anchor ANY handle committed, or during a deferred
    /// promote the staged manifest's (ROADMAP O266). `None` when it cannot be
    /// read or does not verify; the lag it feeds is then unknown, and saying
    /// so is not the same as saying zero. Never raises the tamper event: a
    /// reported lag is not a verdict.
    pub fn anchored_writes(&self) -> Option<u64> {
        self.manifest_in_force().ok().map(|m| m.manifest.writes)
    }

    /// Remove temp files a crashed manifest write left behind (ROADMAP O254),
    /// returning how many were removed.
    ///
    /// The caller holds the database's write lock, which every manifest write
    /// runs under — so no writer on this vault is mid-write, and anything
    /// matching is an orphan. The age threshold is a second margin, not the
    /// first, and the bare legacy `vault.json.tmp` is never touched: a 1.6.x
    /// process still writes it, outside any lock.
    pub fn sweep_orphan_temps(&self, older_than: std::time::Duration) -> std::io::Result<usize> {
        let mut removed = 0;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if !name.to_str().is_some_and(is_nonce_temp) {
                continue;
            }
            let age = entry.metadata()?.modified()?.elapsed().unwrap_or_default();
            if age >= older_than {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    // A `verify_chain(&[tags]) -> bool` stood here, documented as the chain
    // verify, and no production code ever called it: it compared against
    // THIS HANDLE's cached manifest anchor, which a long-lived server never
    // reloads (the `anchored_head` doc records why), so the one answer it
    // could give was stale on exactly the deployment it would be reached
    // from. The store's `verify` replays the chain against `chain_meta`
    // through `chain_step_hex`. Deleted under ROADMAP O126 — a public door
    // with a contract nothing kept.

    /// Value proving which key generation a database was last sealed under:
    /// a fixed-domain HMAC under the vault's mac key. The store keeps it in
    /// its `meta` table and flips it inside the rotation transaction — the
    /// committed marker that open-time reconciliation compares against.
    pub fn keycheck_hex(&self) -> String {
        self.keycheck.clone()
    }

    /// [`keycheck_hex`](Self::keycheck_hex) without the copy — what the store's
    /// write door compares on every audited write (ROADMAP O257).
    pub fn keycheck(&self) -> &str {
        &self.keycheck
    }

    fn keycheck_of(mac_key: &SecretKey) -> String {
        hex::encode(record_hmac(mac_key, b"undercroft.v1/keycheck"))
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
    /// [`chain_step_hex`](Self::chain_step_hex) is split from
    /// [`anchor_manifest`](Self::anchor_manifest): the arithmetic is pure and
    /// the effect is not, so a caller that must not write can still learn the
    /// verdict and report it.
    ///
    /// A staged file naming the SAME generation as `vault.json` is what a
    /// promote leaves when it stops between writing the manifest and removing
    /// the staged file (ROADMAP O257): nothing is pending, and reading it as a
    /// deferred promotion would report one that already happened.
    pub fn rotation_verdict(&self, db_keycheck: Option<&str>) -> RotationVerdict {
        let own = self.keycheck.as_str();
        let settled_or_foreign = || match db_keycheck {
            None => RotationVerdict::Settled,
            Some(k) if k == own => RotationVerdict::Settled,
            Some(_) => RotationVerdict::Foreign,
        };
        match &self.pending {
            None => settled_or_foreign(),
            Some(p) if p.manifest.salt_hex == self.manifest.salt_hex => settled_or_foreign(),
            Some(p) if db_keycheck == Some(p.keycheck.as_str()) => RotationVerdict::Committed,
            Some(_) if db_keycheck.is_none() || db_keycheck == Some(own) => {
                RotationVerdict::Abandoned
            }
            Some(_) => RotationVerdict::Foreign,
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
    /// "detect and report" from meaning "serve garbage". A
    /// [`Foreign`](RotationVerdict::Foreign) verdict changes nothing here: the
    /// store reads the rest of the evidence and decides (ROADMAP O257).
    pub fn reconcile_read_only(&mut self, db_keycheck: Option<&str>) -> RotationVerdict {
        let verdict = self.rotation_verdict(db_keycheck);
        match verdict {
            RotationVerdict::Settled | RotationVerdict::Foreign => self.pending = None,
            RotationVerdict::Committed => {
                let pending = self.pending.take().expect("verdict saw a pending twin");
                let notes = std::mem::take(&mut self.unhealed);
                // Captured BEFORE the swap, which replaces every field: the
                // twin was assembled with defaults (ROADMAP O266).
                let retired = self.manifest_seen;
                *self = *pending;
                self.unhealed = notes;
                if let Some(retired) = retired {
                    self.adopt_deferred_promotion(retired);
                }
                self.unhealed.push(Unhealed::RotationPromotionDeferred);
            }
            RotationVerdict::Abandoned => {
                self.pending = None;
                self.unhealed.push(Unhealed::RotationDiscardDeferred);
            }
        }
        verdict
    }

    /// Record that this handle's keys came from `vault.json.next` while
    /// `vault.json` is still the retired generation's file, whose MAC was
    /// verified in the buffer `retired_manifest` digests (ROADMAP O266).
    ///
    /// Set in exactly two places: a read-only open that adopted a committed
    /// rotation in memory, and the rotating handle whose own promote failed
    /// every attempt. From then on the manifest the rows answer to is the
    /// STAGED one — the retired file's anchor is not a head a replay under
    /// these keys produces — but only while the disk still shows that state:
    /// see [`anchored_head`](Self::anchored_head). The strict readers
    /// ([`manifest_on_disk_is_mine`](Self::manifest_on_disk_is_mine), the
    /// anchor's own read, [`promote`](Self::promote)) are deliberately
    /// untouched: each asks about `vault.json` alone, and a lenient one would
    /// let a second rotation stage over the only file holding these keys, or
    /// a promote remove `.next` with nothing written.
    pub fn adopt_deferred_promotion(&mut self, retired_manifest: [u8; 32]) {
        self.deferred_over = Some(retired_manifest);
    }

    /// Whether this handle's keys came from a committed rotation whose
    /// manifest has not been promoted (ROADMAP O266).
    pub fn promotion_deferred(&self) -> bool {
        self.deferred_over.is_some()
    }

    fn pending_path(&self) -> PathBuf {
        self.dir.join(STAGING_FILE)
    }

    /// Fill this rotation candidate's chain state and durably stage it as
    /// `vault.json.next`. Called by the store *before* the re-seal
    /// transaction commits; a crash before commit leaves a stale staging file
    /// that reconciliation discards.
    ///
    /// Through the one manifest writer (ROADMAP O254) — a nonce temp, fsync,
    /// rename, directory sync — so a reader never meets a half-written
    /// staging file. It used to be written IN PLACE through `File::create`,
    /// which truncates: an unlock racing the write read a torn `.next` and a
    /// writable one deleted it as garbage. What was staged is remembered, so
    /// the promote removes that file and no other (ROADMAP O257).
    pub fn save_manifest_pending(&mut self, head_hex: &str, writes: u64) -> Result<(), VaultError> {
        self.manifest.chain_head_hex = head_hex.to_string();
        self.manifest.writes = writes;
        self.manifest.manifest_mac_hex =
            hex::encode(record_hmac(&self.manifest_key, &self.manifest.canonical()));
        let json = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        write_manifest_file(&self.dir, STAGING_FILE, &json)?;
        self.staged_seen = Some(digest_of(&json));
        Ok(())
    }

    /// Promote a committed rotation (ROADMAP O257): make `vault.json` this
    /// generation's manifest, then remove `vault.json.next` if it is still
    /// exactly the bytes this handle staged or read.
    ///
    /// **Written from memory, not renamed from the staged file**, so a
    /// rotation's promote no longer depends on `.next` surviving until it
    /// runs, and one implementation serves both callers — the rotation, with
    /// the generation it just committed, and the store's open, with the twin
    /// the unlock attached. **Idempotent and never lowering**: a `vault.json`
    /// that already verifies under this generation's key is left alone, since
    /// only a handle holding these keys can have written it and it may carry
    /// an anchor newer than the staged one. A too-new `vault.json` is refused
    /// rather than overwritten (ROADMAP O238).
    ///
    /// The CALLER authorises it: under the database's write lock, the
    /// committed keycheck must be this generation's. That is also what lets it
    /// heal a missing or corrupt `vault.json` — the database is the evidence
    /// of which generation the vault is in. A crash between the write and the
    /// removal leaves both files naming one generation, which
    /// [`rotation_verdict`](Self::rotation_verdict) reads as settled.
    pub fn promote(&self) -> Result<(), VaultError> {
        let current = match fs::read(self.dir.join(MANIFEST_FILE)) {
            Ok(raw) => match Manifest::parse(&raw) {
                Ok(m) => m.id == self.id && self.mac_verifies(&m),
                Err(e @ VaultError::ManifestTooNew { .. }) => return Err(e),
                Err(_) => false,
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        if !current {
            let json = serde_json::to_vec_pretty(&self.manifest)
                .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
            write_manifest_file(&self.dir, MANIFEST_FILE, &json)?;
        }
        self.remove_staged_if_unchanged()?;
        Ok(())
    }

    /// Remove `vault.json.next` if — and only if — it is still exactly the
    /// bytes this handle staged or its unlock read (ROADMAP O257). Returns
    /// whether it removed anything.
    ///
    /// A **write** (unlink + directory sync), made by the store under the
    /// database's write lock. Removing whatever file happened to be there was
    /// the defect: an open that attached one rotation's abandoned staging file
    /// could delete a LATER rotation's whose promote had failed, and the new
    /// salt was then in no file at all.
    pub fn remove_staged_if_unchanged(&self) -> Result<bool, VaultError> {
        let Some(seen) = self.staged_seen else {
            return Ok(false);
        };
        if self.staged_on_disk()? != Some(seen) {
            return Ok(false);
        }
        #[cfg(any(test, feature = "test-fixture"))]
        fixture::fire(fixture::Fault::RemoveStaged)?;
        match fs::remove_file(self.pending_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        keys::sync_dir(&self.dir)?;
        Ok(true)
    }

    /// A SHA-256 of `vault.json.next` as it is on disk NOW, `None` when there
    /// is no such file (ROADMAP O257).
    pub fn staged_on_disk(&self) -> Result<Option<[u8; 32]>, VaultError> {
        match fs::read(self.pending_path()) {
            Ok(raw) => Ok(Some(digest_of(&raw))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// What this handle last knew of `vault.json.next`: a SHA-256 of the
    /// bytes its unlock read or its rotation staged, `None` for no file.
    pub fn staged_seen(&self) -> Option<[u8; 32]> {
        self.staged_seen
    }

    /// Whether the manifest on disk verifies under THIS vault's key — the
    /// question a rotation asks when its promote failed, and the store asks
    /// of a foreign keycheck, to learn whether another process moved the
    /// manifest since this handle read it (ROADMAP O254, O257).
    ///
    /// **Strict, and deliberately NOT through the anchor rule** (ROADMAP
    /// O266): it asks about `vault.json` alone, so on a handle whose promote
    /// is deferred it answers `false` — which is what stops that handle
    /// rotating again over the only file holding its keys.
    pub fn manifest_on_disk_is_mine(&self) -> bool {
        self.verified_disk_manifest().is_ok()
    }

    /// [`manifest_on_disk_is_mine`](Self::manifest_on_disk_is_mine), with the
    /// SHA-256 of the bytes it verified when it is (ROADMAP O266) — how a
    /// rotation, under its exclusive hold, records the retired manifest its
    /// adoption of the next keys is licensed by if the promote is deferred.
    pub fn manifest_on_disk_digest(&self) -> Option<[u8; 32]> {
        self.verified_disk_read().ok().map(|(_, digest)| digest)
    }

    fn mac_verifies(&self, m: &Manifest) -> bool {
        hex::decode(&m.manifest_mac_hex)
            .map(|mac| verify_hmac(&self.manifest_key, &m.canonical(), &mac).is_ok())
            .unwrap_or(false)
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
    ///
    /// **While a committed rotation's promote is deferred it is the STAGED
    /// manifest's head** (ROADMAP O266): this handle's keys came from
    /// `vault.json.next`, the retired `vault.json` fails their MAC, and its
    /// anchor is not a head a replay under them produces — reading it here
    /// made every read-only open of such a vault refuse as tampering. The
    /// rule, and when it stops applying, is
    /// [`manifest_in_force`](Self::manifest_in_force)'s.
    pub fn anchored_head(&self) -> Result<String, VaultError> {
        match self.manifest_in_force() {
            Ok(m) => Ok(m.manifest.chain_head_hex),
            Err(NotInForce::Unreadable(_)) => Ok(self.manifest.chain_head_hex.clone()),
            Err(miss) => Err(self.refusal(miss)),
        }
    }

    /// **Which manifest this handle's rows answer to, read from disk**
    /// (ROADMAP O266) — the one rule [`anchored_head`](Self::anchored_head),
    /// [`anchored_writes`](Self::anchored_writes) and
    /// [`verified_manifest`](Self::verified_manifest) share. It emits
    /// nothing: each reader decides what a miss means for it.
    ///
    /// Ordinarily `vault.json`, verified under this handle's key. On a handle
    /// whose promote is deferred ([`adopt_deferred_promotion`]):
    ///
    /// 1. `vault.json.next` is read FIRST. A promote writes `vault.json` by
    ///    rename and only then removes `.next`, and nothing writes INTO
    ///    `.next`, so when the second read still finds the retired bytes,
    ///    `.next` was there when the first one read it — two reads, consistent
    ///    at the second, with no retry.
    /// 2. `vault.json` verifying under this handle's key means a promote has
    ///    happened since: it is read as always, and a later anchor is
    ///    followed. No latch — a rollback beneath a live handle is followed
    ///    down (O254 item 2).
    /// 3. `vault.json` byte-identical to the retired manifest the adoption
    ///    was licensed by AND `.next` byte-identical to what this handle read
    ///    or staged: still deferred, and the staged manifest is the one in
    ///    force — its bytes from disk, never re-serialised.
    /// 4. `.next` gone or changed while `vault.json` is not this generation's:
    ///    the keys the database is sealed under are in no file, which is what
    ///    a fresh open answers too (`settle_foreign_keycheck`, O257 item 5).
    ///    An integrity verdict, and NOT the tamper event — no MAC was forged.
    /// 5. Anything else failing this handle's MAC is the one tamper verdict.
    ///
    /// [`adopt_deferred_promotion`]: Self::adopt_deferred_promotion
    fn manifest_in_force(&self) -> Result<InForce, NotInForce> {
        // `None`: not deferred. `Some(None)`: deferred, and `.next` is gone
        // or no longer the bytes this handle read or staged.
        let staged: Option<Option<Vec<u8>>> = match self.deferred_over {
            None => None,
            Some(_) => {
                let read = match fs::read(self.pending_path()) {
                    Ok(raw) => Some(raw).filter(|raw| Some(digest_of(raw)) == self.staged_seen),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    // A read failure is not evidence (the fall-back's rule).
                    Err(e) => return Err(NotInForce::Unreadable(e)),
                };
                #[cfg(any(test, feature = "test-fixture"))]
                fixture::run_between_manifest_reads();
                Some(read)
            }
        };
        let lost = || {
            NotInForce::StagedLost(format!(
                "vault.json.next, which holds vault {:?}'s current key generation while its \
                 promote is deferred, is gone or has changed since this process read it, and \
                 vault.json does not verify under that generation's keys: the database is \
                 sealed under keys no manifest on disk now derives (ROADMAP O266, O257). \
                 Nothing was written. Restore the vault from a backup taken before this",
                self.id
            ))
        };
        let raw = match fs::read(self.dir.join(MANIFEST_FILE)) {
            Ok(raw) => raw,
            Err(_) if matches!(staged, Some(None)) => return Err(lost()),
            Err(e) => return Err(NotInForce::Unreadable(e)),
        };
        if let (Some(retired), Some(staged)) = (self.deferred_over, &staged) {
            if digest_of(&raw) == retired {
                return match staged {
                    Some(bytes) => Ok(InForce {
                        manifest: self.manifest.clone(),
                        bytes: bytes.clone(),
                        staged: true,
                    }),
                    None => Err(lost()),
                };
            }
        }
        let m = Manifest::parse(&raw).map_err(NotInForce::Refused)?;
        if m.id != self.id {
            return Err(NotInForce::Refused(VaultError::CorruptManifest(
                "manifest id mismatch".into(),
            )));
        }
        let stored = hex::decode(&m.manifest_mac_hex)
            .map_err(|e| NotInForce::Refused(VaultError::CorruptManifest(e.to_string())))?;
        if verify_hmac(&self.manifest_key, &m.canonical(), &stored).is_err() {
            return Err(if matches!(staged, Some(None)) {
                lost()
            } else {
                NotInForce::Tampered
            });
        }
        Ok(InForce {
            manifest: m,
            bytes: raw,
            staged: false,
        })
    }

    /// What a reader answers for a manifest [`manifest_in_force`] did not
    /// find — and the ONE place the manifest tamper event is raised.
    ///
    /// [`manifest_in_force`]: Self::manifest_in_force
    fn refusal(&self, miss: NotInForce) -> VaultError {
        match miss {
            NotInForce::Unreadable(e) => e.into(),
            NotInForce::Refused(e) => e,
            NotInForce::StagedLost(why) => VaultError::CorruptManifest(why),
            NotInForce::Tampered => {
                undercroft_obs::hmac_verify_failed("manifest");
                undercroft_obs::event_hmac_fail(
                    self.id(),
                    "manifest",
                    undercroft_obs::TamperSite::default(),
                );
                VaultError::ManifestTampered
            }
        }
    }

    /// **The manifest ON DISK, its exact bytes, MAC-verified — with NO
    /// fall-back** (ROADMAP O256).
    ///
    /// `backup create` reads it ONCE, before it pins the snapshot it verifies
    /// and copies: its head is the anchor that `verify` compares the rows
    /// with, and its bytes are what the archive carries, so the two cannot be
    /// different reads. [`anchored_head`](Self::anchored_head) falls back to
    /// the cached head when the file cannot be read, which is right for a
    /// tamper decision and wrong here — it would archive a manifest the vault
    /// never had. So a missing file is an integrity verdict and any other read
    /// error is an I/O refusal. The bytes leave this crate only through
    /// [`backups::Stage::write_manifest`].
    ///
    /// **During a deferred promote these are `vault.json.next`'s bytes**
    /// (ROADMAP O266, refining O256 item 3): the manifest the rows answer to,
    /// re-read from disk and required to be the bytes this handle read or
    /// staged — never re-serialised from memory. An archive carrying the
    /// retired `vault.json` instead is one a restore refuses as another key
    /// generation. [`VerifiedManifest::is_staged`] says which.
    pub fn verified_manifest(&self) -> Result<VerifiedManifest, VaultError> {
        match self.manifest_in_force() {
            Ok(m) => Ok(VerifiedManifest {
                head: m.manifest.chain_head_hex,
                writes: m.manifest.writes,
                bytes: m.bytes,
                staged: m.staged,
            }),
            Err(NotInForce::Unreadable(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(VaultError::CorruptManifest(format!(
                    "{MANIFEST_FILE} is missing from vault {:?}'s directory",
                    self.id
                )))
            }
            Err(miss) => Err(self.refusal(miss)),
        }
    }

    /// Write this handle's manifest as it stands, through the one writer.
    /// Reached by `create`, which has nothing on disk to check against, and
    /// by the test fixture; every anchor goes through
    /// [`anchor_manifest`](Self::anchor_manifest) and its checks instead.
    fn save_manifest(&mut self) -> Result<(), VaultError> {
        self.manifest.manifest_mac_hex =
            hex::encode(record_hmac(&self.manifest_key, &self.manifest.canonical()));
        let json = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| VaultError::CorruptManifest(e.to_string()))?;
        write_manifest_file(&self.dir, MANIFEST_FILE, &json)?;
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
    /// `None` only for a fresh palace opened read-only: there was no key to
    /// load and a read-only open creates none.
    master: Option<SecretKey>,
    declared: keys::KeySource,
    access: Access,
}

impl VaultManager {
    /// Open the palace at `root` for writing, loading (or, in a fresh
    /// installation, creating) the master key. `passphrase` switches to Argon2id
    /// passphrase derivation.
    pub fn open(root: &Path, passphrase: Option<&str>) -> Result<Self, VaultError> {
        Self::open_as(root, passphrase, Access::ReadWrite)
    }

    /// [`open`](Self::open) with the caller's posture stated (ROADMAP O204).
    ///
    /// The key is resolved by [`keys::master_key`], which refuses a
    /// declaration the installation contradicts and never creates key material
    /// where a vault or backup already refers to a key. Under
    /// [`Access::ReadOnly`] nothing is created at all — no key, no
    /// directory — and the manager itself refuses `create`, `delete` and
    /// `rotation_candidate`, and unlocks read-only whatever a caller asks:
    /// a posture decided one call later was already too late for a key file
    /// and a staging manifest (O175's ruling, applied to the manager).
    pub fn open_as(
        root: &Path,
        passphrase: Option<&str>,
        access: Access,
    ) -> Result<Self, VaultError> {
        let declared = keys::KeySource::declared(passphrase);
        let resolved = keys::master_key(root, passphrase, access)?;
        if resolved.both_present {
            undercroft_obs::diag_warn!("{}", keys::both_present_warning(declared));
        }
        if access == Access::ReadWrite {
            fs::create_dir_all(root.join(VAULTS_DIR))?;
        }
        Ok(Self {
            root: root.to_path_buf(),
            master: resolved.key,
            declared,
            access,
        })
    }

    /// The posture this manager was opened with.
    pub fn access(&self) -> Access {
        self.access
    }

    fn master(&self) -> Result<&SecretKey, VaultError> {
        self.master.as_ref().ok_or(VaultError::ReadOnly(
            "this data directory held no key material when it was opened read-only, so no vault key \
             can be derived",
        ))
    }

    fn writable(&self, what: &'static str) -> Result<(), VaultError> {
        match self.access {
            Access::ReadWrite => Ok(()),
            Access::ReadOnly => Err(VaultError::ReadOnly(what)),
        }
    }

    /// Refuse to mint a new reference to a key no existing vault uses.
    ///
    /// Reads each manifest's MAC directly — never through `unlock`, whose
    /// writable form deletes a torn staging manifest — and stops at the
    /// first that verifies. Enumeration errors propagate: a directory that
    /// cannot be read is not an empty one. A non-directory entry is not a
    /// vault, and a vault directory with no manifest has nothing to verify.
    fn key_opens_an_existing_vault(&self) -> Result<(), VaultError> {
        let dir = self.root.join(VAULTS_DIR);
        let entries = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let mut manifests = 0usize;
        for entry in entries {
            let path = entry?.path();
            if !fs::metadata(&path)?.is_dir() {
                continue;
            }
            let raw = match fs::read(path.join("vault.json")) {
                Ok(raw) => raw,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            manifests += 1;
            if self.manifest_verifies(path, &raw) {
                return Ok(());
            }
        }
        if manifests == 0 {
            return Ok(());
        }
        // One tamper signal for the refusal, not one per manifest probed.
        undercroft_obs::hmac_verify_failed("manifest");
        Err(VaultError::KeyOpensNoVault {
            manifests,
            declared: self.declared,
        })
    }

    fn manifest_verifies(&self, dir: PathBuf, raw: &[u8]) -> bool {
        // A manifest this build cannot read is one this key cannot be
        // shown to open, which is what this predicate answers.
        let Ok(manifest) = Manifest::parse(raw) else {
            return false;
        };
        let Ok(stored) = hex::decode(&manifest.manifest_mac_hex) else {
            return false;
        };
        let Ok(vault) = self.assemble(dir, manifest) else {
            return false;
        };
        verify_hmac(&vault.manifest_key, &vault.manifest.canonical(), &stored).is_ok()
    }

    /// The palace root: the data directory holding `vaults/` and the master
    /// key material (`master.key`, or `kdf.salt` under a passphrase).
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn vault_dir(&self, id: &str) -> PathBuf {
        self.root.join(VAULTS_DIR).join(id)
    }

    /// Every vault id under the palace that has a manifest, sorted.
    pub fn list(&self) -> Result<Vec<String>, VaultError> {
        let mut out = Vec::new();
        let dir = self.root.join(VAULTS_DIR);
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

    /// Whether a vault of this id has a manifest. Says nothing about its database — that is `Vault::database_exists`.
    pub fn exists(&self, id: &str) -> bool {
        self.vault_dir(id).join("vault.json").exists()
    }

    /// Create a new vault. Fails if it already exists.
    ///
    /// Refused under a read-only posture, and refused when the installation
    /// already holds vaults and its key opens none of them (ROADMAP O204):
    /// that is the door a split installation is minted through.
    pub fn create(&self, id: &str, level: SecurityLevel) -> Result<Vault, VaultError> {
        undercroft_core::validate_name(id, "vault")?;
        self.writable("creating a vault writes to the data directory")?;
        let dir = self.vault_dir(id);
        if self.exists(id) {
            return Err(VaultError::AlreadyExists(id.to_string()));
        }
        // A restore interrupted between its renames left the vault it was
        // replacing aside and `vaults/<id>` empty (ROADMAP O268): minting a new
        // vault there — `init` does, on the team-server recipe's every start —
        // would serve an empty one while the real vault sits in the restore area.
        restores::refuse_if_interrupted(&self.root, id)?;
        self.key_opens_an_existing_vault()?;
        fs::create_dir_all(&dir)?;
        let salt = keys::new_vault_salt();
        let manifest = Manifest {
            version: MANIFEST_VERSION,
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
        self.writable("deleting a vault writes to the data directory")?;
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
    /// An unlock writes nothing on either posture (ROADMAP O257). It used to
    /// delete a `vault.json.next` it could not authenticate when writable —
    /// the one filesystem repair it made, outside any lock — and now reports
    /// it on [`Vault::unhealed`] instead: that file is unreadable *to us*,
    /// which does not make it garbage to whoever wrote it.
    ///
    /// A manager opened read-only unlocks read-only whatever `access` says
    /// (ROADMAP O204): the posture belongs to the path, not to the call.
    pub fn unlock_as(&self, id: &str, access: Access) -> Result<Vault, VaultError> {
        self.unlock_dir(self.vault_dir(id), id, access, Tamper::LiveVault)
    }

    /// Unlock the COPY a restore staged, writable (ROADMAP O268) — the only way
    /// to unlock a vault anywhere but `vaults/<id>`.
    ///
    /// Keys derive from the master key, the manifest's salt and its id, never
    /// from the directory, so any directory holding a genuine manifest would
    /// unlock: taking only a [`restores::Stage`] this crate minted is what
    /// keeps `backups/<name>` from ever being opened writable. A stage whose
    /// manifest fails its MAC raises no tamper event under the vault's id — the
    /// live vault is untouched, and the restore's refusal names the archive.
    pub fn unlock_stage(&self, stage: &restores::Stage) -> Result<Vault, VaultError> {
        self.writable("restoring a backup replaces a vault")?;
        self.unlock_dir(
            stage.dir().to_path_buf(),
            stage.id(),
            Access::ReadWrite,
            Tamper::Archive,
        )
    }

    /// `unlock_as`'s whole body, for any directory: one implementation of the
    /// MAC check, the staged manifest, the version gate and the legacy name,
    /// whichever door asked (ROADMAP O268).
    fn unlock_dir(
        &self,
        dir: PathBuf,
        id: &str,
        access: Access,
        tamper: Tamper,
    ) -> Result<Vault, VaultError> {
        let access = match self.access {
            Access::ReadOnly => Access::ReadOnly,
            Access::ReadWrite => access,
        };
        let manifest_path = dir.join("vault.json");
        if !manifest_path.exists() {
            return Err(VaultError::NotFound(id.to_string()));
        }
        // Bound, digested, then parsed (ROADMAP O266): the digest must be of
        // the very buffer whose MAC is verified below, never of a second read.
        let raw = fs::read(&manifest_path)?;
        let raw_digest = digest_of(&raw);
        let manifest = Manifest::parse(&raw)?;
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
            if tamper == Tamper::LiveVault {
                undercroft_obs::hmac_verify_failed("manifest");
                undercroft_obs::event_hmac_fail(
                    vault.id(),
                    "manifest",
                    undercroft_obs::TamperSite::default(),
                );
            }
            return Err(VaultError::ManifestTampered);
        }
        vault.manifest_seen = Some(raw_digest);
        // Attach a pending rotation manifest (vault.json.next) for the
        // store's open-time reconciliation, and remember exactly which bytes
        // were read, authenticated or not: the store promotes or removes a
        // staged file only while it is still those bytes, and a file that
        // changed since is how it tells a rotation racing this open from
        // tampering (ROADMAP O257).
        //
        // **No unlock deletes it, on either posture** (ROADMAP O257). A
        // writable unlock used to remove every staging file it could not
        // authenticate, outside any lock — including a TOO-NEW one, because
        // `Manifest::parse(..).ok()` turned `ManifestTooNew` into "torn",
        // contrary to this comment's own claim and O238's record. A file this
        // build cannot authenticate is inert and is either evidence or a torn
        // pre-1.7 write, which no reader can tell apart; it is reported, and
        // the next rotation stages over it.
        let pending_path = vault.pending_path();
        match fs::read(&pending_path) {
            Ok(raw) => {
                vault.staged_seen = Some(digest_of(&raw));
                match Manifest::parse(&raw) {
                    Err(VaultError::ManifestTooNew { .. }) => {
                        vault.unhealed.push(Unhealed::StagingManifestTooNew)
                    }
                    parsed => {
                        vault.pending = parsed
                            .ok()
                            .filter(|pm| pm.id == vault.id)
                            .and_then(|pm| self.assemble(vault.dir.clone(), pm).ok())
                            .filter(|pv| pv.mac_verifies(&pv.manifest))
                            .map(|mut pv| {
                                pv.staged_seen = vault.staged_seen;
                                Box::new(pv)
                            });
                        if vault.pending.is_none() {
                            vault.unhealed.push(Unhealed::TornStagingManifest);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // ROADMAP O7: a database still under its pre-1.5.0 name. The rename
        // is the store's, at its writable open (it checkpoints the WAL
        // first); a read-only unlock reports it and serves the file as is.
        if matches!(access, Access::ReadOnly) && matches!(vault.db_layout(), DbLayout::Legacy) {
            vault.unhealed.push(Unhealed::LegacyDatabaseName);
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
        let master = self.master()?;
        let mac_key = derive_vault_key(master, &salt, &id, "mac");
        Ok(Vault {
            enc_key: derive_vault_key(master, &salt, &id, "enc"),
            keycheck: Vault::keycheck_of(&mac_key),
            mac_key,
            manifest_key: derive_vault_key(master, &salt, &id, "manifest"),
            sample_key: derive_vault_key(master, &salt, &id, "sample"),
            chain_key: derive_vault_key(master, &salt, &id, "chain"),
            level: manifest.level,
            id,
            dir,
            manifest,
            pending: None,
            unhealed: Vec::new(),
            retired: None,
            staged_seen: None,
            manifest_seen: None,
            deferred_over: None,
        })
    }

    /// Build the next key generation for a vault: same identity, level, and
    /// history metadata, **fresh salt** ⇒ fresh enc/mac/manifest/sample/chain
    /// keys. The chain key is why a rotation re-steps every version-2 audit
    /// row under the next generation. The sample key moves the training-sample draw
    /// ([`Vault::sample_rank`]), so a *future* retrain in a rotated vault draws
    /// a different sample; rotation itself only re-seals, never re-quantizes,
    /// so nothing already on disk changes.
    /// Nothing is staged here — the store's rotation stages the manifest
    /// once it has replayed the chain under the new keys, while it holds the
    /// vault exclusively (ROADMAP O257). A manager opened read-only refuses
    /// this before it unlocks anything (ROADMAP O204).
    pub fn rotation_candidate(&self, id: &str) -> Result<Vault, VaultError> {
        self.writable("rotating a vault's keys writes to the data directory")?;
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

/// The most one drawer's content may decompress to. A BOUND, enforced
/// against the size the frame header declares — never a pre-allocation.
///
/// It was the capacity handed to `zstd::bulk::decompress` for every framed
/// drawer, and that call does `Vec::with_capacity(capacity)` before it
/// decodes a byte, so each decode reserved 16 MiB, the store kept that Vec
/// as the drawer's content `String`, and every hydrated framed candidate
/// held a 16 MiB mapping for as long as the search held it. Resident memory
/// stayed honest (the pages were never touched); the MAPPING COUNT did not:
/// a whole-corpus page at 10⁶ sealed rows reached the kernel's
/// `vm.max_map_count` (262,144 — measured 262,145 at the abort, 8.2 TiB of
/// address space, 5 GB resident) and the process died in `handle_alloc_error`
/// with 46 GB free. Every framed read anywhere also paid an mmap/munmap
/// pair per row for the reservation (ROADMAP O109, found by O23's
/// instrument).
const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;

fn decompress_frame(framed: &[u8]) -> Result<Vec<u8>, VaultError> {
    match framed.first() {
        Some(&FRAME_RAW) => Ok(framed[1..].to_vec()),
        Some(&FRAME_ZSTD) => {
            let data = &framed[1..];
            // Size the buffer from the header `compress_frame`'s bulk
            // compressor always writes. A frame declaring more than the bound
            // is REFUSED here rather than decoded into a fixed buffer that
            // then overflows; a frame declaring nothing (no writer of ours
            // produces one) is streamed under the bound, so nothing that
            // opened before stops opening.
            let capacity = match zstd::zstd_safe::get_frame_content_size(data) {
                Ok(Some(n)) if n > MAX_CONTENT_BYTES as u64 => {
                    return Err(VaultError::CorruptManifest(format!(
                        "zstd: frame declares {n} bytes of content, above the \
                         {MAX_CONTENT_BYTES}-byte bound"
                    )));
                }
                Ok(Some(n)) => n as usize,
                Ok(None) => {
                    // A frame declaring no size is STREAMED under the bound
                    // rather than decoded into a bound-sized reservation —
                    // O109's mapping survived on this one arm (ROADMAP
                    // O111). No writer of ours produces such a frame (the
                    // bulk compressor always writes the size), so this is
                    // the arm a future streaming writer would silently take.
                    use std::io::Read;
                    let mut out = Vec::new();
                    zstd::stream::read::Decoder::new(data)
                        .map_err(|e| VaultError::CorruptManifest(format!("zstd: {e}")))?
                        .take(MAX_CONTENT_BYTES as u64 + 1)
                        .read_to_end(&mut out)
                        .map_err(|e| VaultError::CorruptManifest(format!("zstd: {e}")))?;
                    if out.len() > MAX_CONTENT_BYTES {
                        return Err(VaultError::CorruptManifest(format!(
                            "zstd: frame decodes past the {MAX_CONTENT_BYTES}-byte bound"
                        )));
                    }
                    return Ok(out);
                }
                Err(e) => {
                    return Err(VaultError::CorruptManifest(format!("zstd: {e:?}")));
                }
            };
            zstd::bulk::decompress(data, capacity)
                .map_err(|e| VaultError::CorruptManifest(format!("zstd: {e}")))
        }
        // Legacy record written before compression framing: the whole
        // buffer is the content (normalized UTF-8 never starts with 0x00/0x01).
        _ => Ok(framed.to_vec()),
    }
}

/// Quantized-embedding frame: `[0x02, 'Q', scale f32 LE, i8 * dim]`, told
/// from a legacy f32 blob (4 * dim bytes, always a multiple of four) by its
/// magic and by its length NOT being a multiple of four. That holds for every
/// dim except those ≡ 2 (mod 4), where 6 + dim IS a multiple of four and the
/// frame misreads as (6 + dim) / 4 floats with no error — pinned by
/// `a_dimension_two_mod_four_reads_back_as_the_wrong_vector` below, and
/// refused at the store's write choke point (ROADMAP O123).
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
/// Length of the palace master key in bytes.
pub const MASTER_KEY_LEN: usize = KEY_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// ROADMAP O123 — the WHY behind the store's refusal of a dimension
    /// 2 modulo 4: the quantized frame is told from a legacy f32 blob by
    /// its length not being a multiple of four, and `6 + dim` is one
    /// exactly then, so the frame reads back as `(6 + dim) / 4` garbage
    /// floats with no error. Pinned so the discriminator's premise is
    /// written down beside it; the refusal lives at the write choke point.
    #[test]
    fn a_dimension_two_mod_four_reads_back_as_the_wrong_vector() {
        let six = [1.0f32, -1.0, 0.5, -0.5, 0.25, -0.25];
        let back = dequantize_embedding(&quantize_embedding(&six));
        assert_eq!(back.len(), 3, "misread as three legacy f32s: {back:?}");
        let eight = [1.0f32, -1.0, 0.5, -0.5, 0.25, -0.25, 0.125, -0.125];
        let back = dequantize_embedding(&quantize_embedding(&eight));
        assert_eq!(back.len(), 8, "a dimension not 2 mod 4 round-trips");
    }

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

    /// ROADMAP O7: a new vault's database is `vault.db`, and until it exists
    /// the layout is `Absent` — which `database_exists` reports as absent,
    /// the A33 answer, rather than as a fresh vault to fabricate.
    #[test]
    fn a_new_vault_names_its_database_vault_db() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("a", SecurityLevel::Sealed).unwrap();
        assert_eq!(v.db_layout(), DbLayout::Absent);
        assert!(!v.database_exists());
        assert_eq!(v.db_path().file_name().unwrap(), DB_FILE);
        assert_ne!(DB_FILE, LEGACY_DB_FILE);
    }

    /// ROADMAP O7's gate, at this crate's level: a vault that still carries
    /// `palace.db` HAS its database — `db_path` answers with that file,
    /// `database_exists` says so (an integrity verdict on the day of the
    /// upgrade is the trap the entry named), a read-only unlock serves it
    /// and reports the pending rename, and a writable unlock reports
    /// nothing because the rename is the store's to make.
    #[test]
    fn a_legacy_named_database_is_served_and_reported_read_only() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("a", SecurityLevel::Sealed).unwrap();
        std::fs::write(v.legacy_db_path(), b"not really sqlite").unwrap();
        assert_eq!(v.db_layout(), DbLayout::Legacy);
        assert!(v.database_exists());
        assert_eq!(v.db_path(), v.legacy_db_path());
        let ro = mgr.unlock_as("a", Access::ReadOnly).unwrap();
        assert!(
            ro.unhealed().contains(&Unhealed::LegacyDatabaseName),
            "a read-only unlock must say the rename is pending: {:?}",
            ro.unhealed()
        );
        assert!(
            ro.legacy_db_path().exists(),
            "a read-only unlock renames nothing"
        );
        let rw = mgr.unlock_as("a", Access::ReadWrite).unwrap();
        assert!(rw.unhealed().is_empty());
        assert!(
            rw.legacy_db_path().exists(),
            "the unlock itself never renames — the store does"
        );
    }

    /// Two database files under one manifest are refused, not guessed at.
    #[test]
    fn two_database_files_are_an_ambiguous_layout() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("a", SecurityLevel::Sealed).unwrap();
        std::fs::write(v.current_db_path(), b"x").unwrap();
        std::fs::write(v.legacy_db_path(), b"y").unwrap();
        assert_eq!(v.db_layout(), DbLayout::Ambiguous);
        assert!(v.database_exists());
        assert_eq!(
            v.db_path(),
            v.current_db_path(),
            "the path names the current file; the store refuses"
        );
    }

    /// ROADMAP O109: a framed drawer decodes into a buffer of ITS OWN size,
    /// not into the 16 MiB bound. The observable is the returned Vec's
    /// capacity — the mapping each decode used to reserve — and the premise
    /// arm proves the content really was zstd-framed, because a raw frame
    /// would satisfy the assertion without exercising the decoder at all.
    #[test]
    fn a_framed_drawer_decodes_into_a_buffer_its_own_size() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("a", SecurityLevel::Sealed).unwrap();
        let text = "the quarterly budget review moved to thursday afternoon; "
            .repeat(20)
            .into_bytes();
        assert!(
            zstd::bulk::compress(&text, 3).unwrap().len() + 1 < text.len(),
            "premise: this content compresses, so compress_frame frames it"
        );
        let blob = v.content_at_rest("rec1", &text);
        let back = v.content_from_rest("rec1", &blob).unwrap();
        assert_eq!(back, text);
        assert_eq!(
            back.capacity(),
            text.len(),
            "the decode buffer must be sized from the frame header, not the bound"
        );
    }

    /// The bound stays a bound: a frame whose header declares more content
    /// than `MAX_CONTENT_BYTES` is refused before a byte is decoded.
    #[test]
    fn a_frame_declaring_more_than_the_bound_is_refused() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("a", SecurityLevel::Sealed).unwrap();
        let big = vec![b'a'; MAX_CONTENT_BYTES + 1];
        let blob = v.content_at_rest("rec1", &big);
        let err = v.content_from_rest("rec1", &blob).unwrap_err();
        assert!(
            err.to_string().contains("above the"),
            "an over-bound frame must be refused by the header, got: {err}"
        );
        // And the bound itself is still honoured: exactly MAX decodes.
        let max = vec![b'a'; MAX_CONTENT_BYTES];
        let blob = v.content_at_rest("rec1", &max);
        assert_eq!(
            v.content_from_rest("rec1", &blob).unwrap().len(),
            MAX_CONTENT_BYTES
        );
    }

    /// ROADMAP O111: a frame that declares no content size — the one arm
    /// O109 left reserving the whole bound — streams under the bound and is
    /// refused past it. The PREMISE arm proves the frame really carries no
    /// size, because a sized frame takes the other arm and would pass this
    /// test without touching the code it is for.
    #[test]
    fn a_frame_declaring_no_size_streams_under_the_bound() {
        let text = vec![b'x'; 200_000];
        let z = zstd::stream::encode_all(&text[..], 3).unwrap();
        assert!(
            zstd::zstd_safe::get_frame_content_size(&z)
                .unwrap()
                .is_none(),
            "PREMISE: a streaming encoder pledges no size, so the header carries none"
        );
        let mut framed = vec![FRAME_ZSTD];
        framed.extend_from_slice(&z);
        let out = decompress_frame(&framed).unwrap();
        assert_eq!(out, text);
        assert!(
            out.capacity() < MAX_CONTENT_BYTES / 4,
            "the buffer grew from the bytes decoded, not from the bound: {}",
            out.capacity()
        );
        let big = vec![b'x'; MAX_CONTENT_BYTES + 1];
        let z = zstd::stream::encode_all(&big[..], 3).unwrap();
        let mut framed = vec![FRAME_ZSTD];
        framed.extend_from_slice(&z);
        let err = decompress_frame(&framed).unwrap_err();
        assert!(err.to_string().contains("past the"), "{err}");
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

    /// **ROADMAP O238: a manifest a NEWER build wrote refuses, and says so
    /// as age rather than as tampering.**
    ///
    /// `version` was written by every build and read by none, so a future
    /// format change had nothing to fence an older binary with. O233 had to
    /// fence 1.5.x out of a migrated chain by freezing a database row that
    /// 1.5.x happens to compare; the next change may find no such row.
    ///
    /// **This is NOT the gate the entry proposed, and the difference is the
    /// whole point** (O241 ruling 4: "its entry's gate is also wrong — it
    /// drives the case that already refuses"). The entry said "a manifest
    /// with `version` one above the build's refuses to open". Hand-editing
    /// the number does that TODAY, because `version` is inside the canonical
    /// so the edit breaks the MAC — a green gate over an absent check. The
    /// arm below pins that, so nobody re-proposes it.
    ///
    /// What a FUTURE BINARY writes is a higher version with a VALID MAC over
    /// it, and that is what this build must refuse.
    #[test]
    fn a_manifest_from_a_newer_build_refuses_as_age_not_as_tampering() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("t", SecurityLevel::Sealed).unwrap();
        let path = dir.path().join("vaults/t/vault.json");

        // PREMISE: it opens now, and the version on disk is this build's.
        assert!(mgr.unlock("t").is_ok(), "premise: an ordinary vault opens");
        let mut m = Manifest::parse(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            m.version, MANIFEST_VERSION,
            "premise: written at this version"
        );

        // **What a future binary writes**: a higher version, MAC'd over it.
        // Re-keying the MAC is what separates this from the entry's gate —
        // without it the file is simply corrupt.
        m.version = MANIFEST_VERSION + 1;
        m.manifest_mac_hex = hex::encode(record_hmac(&v.manifest_key, &m.canonical()));
        fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();

        match mgr.unlock("t") {
            Err(VaultError::ManifestTooNew { found, supported }) => {
                assert_eq!((found, supported), (MANIFEST_VERSION + 1, MANIFEST_VERSION));
            }
            other => {
                panic!("a manifest from a newer build must refuse as ManifestTooNew, got {other:?}")
            }
        }
        // The message names BOTH versions, which is what makes it actionable
        // rather than merely a refusal.
        let msg = mgr.unlock("t").unwrap_err().to_string();
        assert!(
            msg.contains(&(MANIFEST_VERSION + 1).to_string())
                && msg.contains(&MANIFEST_VERSION.to_string()),
            "the refusal must name both versions: {msg}"
        );

        // **The ENTRY's gate, pinned as the wrong one.** Bump the number and
        // leave the MAC alone: that already refused before this unit, and it
        // refuses as TAMPERING, which is a different and misleading verdict.
        let mut forged = m.clone();
        forged.version = MANIFEST_VERSION + 1;
        forged.manifest_mac_hex = hex::encode(record_hmac(&v.manifest_key, &forged.canonical()));
        forged.version = MANIFEST_VERSION + 2; // MAC now describes a different version
        fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(
            matches!(mgr.unlock("t"), Err(VaultError::ManifestTooNew { .. })),
            "a forged bump refuses too — the version gate runs FIRST, and \
             refusing early is the safe direction because the field is inside \
             the canonical"
        );
    }

    /// O238: the fence does not fire on the version this build writes, and
    /// an OLDER version is not refused either — the gate is one-sided.
    ///
    /// Without this arm a `!=` comparison would pass every test above while
    /// refusing every vault an older release wrote, which is the opposite of
    /// what a compatibility fence is for.
    #[test]
    fn the_manifest_fence_refuses_only_what_is_newer() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("t", SecurityLevel::Sealed).unwrap();
        let path = dir.path().join("vaults/t/vault.json");
        assert!(mgr.unlock("t").is_ok(), "this build's own version opens");

        let mut m = Manifest::parse(&fs::read(&path).unwrap()).unwrap();
        m.version = 0; // an older format than this build
        m.manifest_mac_hex = hex::encode(record_hmac(&v.manifest_key, &m.canonical()));
        fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(
            mgr.unlock("t").is_ok(),
            "an OLDER manifest version must still open — the fence keeps new \
             formats out of old binaries, not old formats out of new ones"
        );
    }

    /// O238: the fresh anchor read refuses a too-new manifest too.
    ///
    /// `anchored_head` re-reads `vault.json` from DISK on every call rather
    /// than trusting this handle's cached copy, so a manifest swapped under
    /// a running process reaches it without any open — which is exactly the
    /// path that must not read a newer format as though it understood it.
    #[test]
    fn the_fresh_anchor_read_refuses_a_newer_manifest() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("t", SecurityLevel::Sealed).unwrap();
        let path = dir.path().join("vaults/t/vault.json");
        assert!(v.anchored_head().is_ok(), "premise: it reads now");

        let mut m = Manifest::parse(&fs::read(&path).unwrap()).unwrap();
        m.version = MANIFEST_VERSION + 1;
        m.manifest_mac_hex = hex::encode(record_hmac(&v.manifest_key, &m.canonical()));
        fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(
            matches!(v.anchored_head(), Err(VaultError::ManifestTooNew { .. })),
            "the anchor read goes through the same door as the open"
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
        fn link(tag: &[u8]) -> ChainLink<'_> {
            ChainLink {
                record_id: "r",
                tag,
                at: "2026-09-19T00:00:00Z",
            }
        }
        for step in [ChainStep::V1, ChainStep::V2] {
            // The store advances heads transactionally via chain_step_hex and
            // anchors the manifest afterwards — same arithmetic, split API.
            let h1 = v
                .chain_step_hex(step, &Vault::chain_genesis_hex(), link(&t1))
                .unwrap();
            let h2 = v.chain_step_hex(step, &h1, link(&t2)).unwrap();
            // Order matters: the same two tags the other way round replay to
            // a different head, in both versions.
            let swapped = v
                .chain_step_hex(
                    step,
                    &v.chain_step_hex(step, &Vault::chain_genesis_hex(), link(&t2))
                        .unwrap(),
                    link(&t1),
                )
                .unwrap();
            assert_ne!(swapped, h2, "{step:?}");
        }
        let h1 = v
            .chain_step_hex(ChainStep::V1, &Vault::chain_genesis_hex(), link(&t1))
            .unwrap();
        let h2 = v.chain_step_hex(ChainStep::V1, &h1, link(&t2)).unwrap();
        let kc = v.keycheck_hex();
        v.anchor_manifest(&h2, 2, Some(kc.as_str())).unwrap();
        assert_eq!(v.chain_head_hex(), h2, "the anchor is the replayed head");
        assert_eq!(v.writes(), 2);
    }

    /// **ROADMAP O233: the version-1 step is byte-identical to what every
    /// chain before it wrote, and version 2 is keyed apart.** Version 1 is
    /// pinned to the raw `HMAC(mac_key, prev ‖ tag)` a pre-O233 build
    /// computed, so no vault's history replays differently; version 2 must
    /// differ from it and must move when the label or the time does, and a
    /// rotation candidate — a fresh salt — must re-key it.
    #[test]
    fn chain_steps_are_pinned_and_a_rotation_rekeys_the_v2_step() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("k", SecurityLevel::Sealed).unwrap();
        let tag = v.tag(b"record").to_vec();
        let genesis = Vault::chain_genesis_hex();
        let link = |record_id: &'static str| ChainLink {
            record_id,
            tag: &tag,
            at: "2026-09-19T00:00:00Z",
        };
        let v1 = v
            .chain_step_hex(ChainStep::V1, &genesis, link("r"))
            .unwrap();
        assert_eq!(
            v1,
            hex::encode(chain_next(&v.mac_key, &[0u8; HMAC_LEN], &tag)),
            "version 1 is exactly the pre-O233 step"
        );
        assert_eq!(
            v1,
            v.chain_step_hex(ChainStep::V1, &genesis, link("relabelled"))
                .unwrap(),
            "premise: version 1 cannot see a label"
        );
        let v2 = v
            .chain_step_hex(ChainStep::V2, &genesis, link("r"))
            .unwrap();
        assert_ne!(v2, v1);
        assert_ne!(
            v2,
            v.chain_step_hex(ChainStep::V2, &genesis, link("relabelled"))
                .unwrap(),
            "version 2 sees the label"
        );
        drop(v);
        let next = mgr.rotation_candidate("k").unwrap();
        assert_ne!(
            v2,
            next.chain_step_hex(ChainStep::V2, &genesis, link("r"))
                .unwrap(),
            "a fresh salt re-keys the version-2 step"
        );
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
        let kc = a.keycheck_hex();
        a.anchor_manifest("aa11", 5, Some(kc.as_str())).unwrap();
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

    /// The records an anchor committed; a test's shorthand for the arm that
    /// wrote.
    fn records(anchored: Anchored) -> u64 {
        match anchored {
            Anchored::Written { records } => records,
            Anchored::Current => 0,
        }
    }

    fn manifest_bytes(dir: &Path, id: &str) -> Vec<u8> {
        std::fs::read(dir.join(VAULTS_DIR).join(id).join(MANIFEST_FILE)).unwrap()
    }

    /// **ROADMAP O254: an anchor refuses, as INTEGRITY, every manifest it may
    /// not overwrite — and leaves the file byte for byte as it found it.**
    /// Each arm is one line of the ruling's integrity class. The premise arm
    /// first: the same call with a healthy manifest writes.
    #[test]
    fn an_anchor_refuses_as_integrity_what_it_may_not_overwrite() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("v", SecurityLevel::Sealed).unwrap();
        let mut a = mgr.unlock("v").unwrap();
        let kc = a.keycheck_hex();
        assert_eq!(
            a.anchor_manifest("aa", 3, Some(kc.as_str())),
            Ok(Anchored::Written { records: 3 }),
            "premise: a healthy manifest is written"
        );
        let path = dir.path().join("vaults/v/vault.json");
        let healthy = std::fs::read(&path).unwrap();
        let refuses = |a: &mut Vault, head: &str, writes: u64, kc: Option<&str>, why: &str| {
            let before = std::fs::read(&path).ok();
            match a.anchor_manifest(head, writes, kc) {
                Err(AnchorFault::Integrity(_)) => {}
                other => panic!("{why}: expected an integrity refusal, got {other:?}"),
            }
            assert_eq!(std::fs::read(&path).ok(), before, "{why}: the file moved");
        };

        // A keycheck that is not this handle's: another process rotated.
        refuses(&mut a, "bb", 4, Some("00ff"), "foreign keycheck");
        refuses(&mut a, "bb", 4, None, "absent keycheck");
        // A height above the committed one: the manifest is ahead.
        refuses(
            &mut a,
            "bb",
            2,
            Some(kc.as_str()),
            "manifest ahead of the database",
        );
        // A MAC that does not verify under this handle's key.
        std::fs::write(
            &path,
            String::from_utf8(healthy.clone())
                .unwrap()
                .replace("\"aa\"", "\"ab\""),
        )
        .unwrap();
        refuses(&mut a, "bb", 4, Some(kc.as_str()), "an edited manifest");
        // Unparseable, and missing.
        std::fs::write(&path, b"{ not json").unwrap();
        refuses(
            &mut a,
            "bb",
            4,
            Some(kc.as_str()),
            "an unparseable manifest",
        );
        std::fs::remove_file(&path).unwrap();
        refuses(&mut a, "bb", 4, Some(kc.as_str()), "a missing manifest");
        // A version newer than this build writes.
        let newer = String::from_utf8(healthy.clone())
            .unwrap()
            .replace("\"version\": 1", "\"version\": 2");
        assert_ne!(
            newer.as_bytes(),
            healthy.as_slice(),
            "premise: the version moved"
        );
        std::fs::write(&path, newer).unwrap();
        refuses(
            &mut a,
            "bb",
            4,
            Some(kc.as_str()),
            "a newer manifest version",
        );

        // And the healthy manifest, restored, is written again: the refusals
        // above were about the FILE, not about this handle.
        std::fs::write(&path, &healthy).unwrap();
        assert_eq!(
            a.anchor_manifest("bb", 4, Some(kc.as_str())),
            Ok(Anchored::Written { records: 1 })
        );
        // A second anchor at the same head writes nothing.
        let written = std::fs::read(&path).unwrap();
        assert_eq!(
            a.anchor_manifest("bb", 4, Some(kc.as_str())),
            Ok(Anchored::Current)
        );
        assert_eq!(std::fs::read(&path).unwrap(), written);
    }

    /// **PROBE-254R at the vault level (ROADMAP O254, O257).** A handle
    /// unlocked before another's rotation used to write its whole cached
    /// manifest — the RETIRED salt — back over the rotated one, and the vault
    /// could then no longer decrypt what the rotation sealed. Both checks the
    /// ruling requires are driven: the keycheck the rotation committed, and
    /// the keycheck an open re-seeded back to the old value, where only the
    /// MAC stops it.
    #[test]
    fn a_handle_opened_before_a_rotation_cannot_write_the_retired_salt_back() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("v", SecurityLevel::Sealed).unwrap();
        let mut stale = mgr.unlock("v").unwrap();
        let old_kc = stale.keycheck_hex();
        let mut next = mgr.rotation_candidate("v").unwrap();
        next.save_manifest_pending("cc", 5).unwrap();

        // Between the rotation's commit and its promote, `vault.json` is still
        // the OLD manifest and its MAC verifies under the stale key: the
        // keycheck the database committed is the only thing that can refuse.
        let unpromoted = manifest_bytes(dir.path(), "v");
        let committed_kc = next.keycheck_hex();
        match stale.anchor_manifest("dd", 6, Some(committed_kc.as_str())) {
            Err(AnchorFault::Integrity(_)) => {}
            other => panic!("before the promote, the keycheck must refuse ({other:?})"),
        }
        assert_eq!(manifest_bytes(dir.path(), "v"), unpromoted);

        next.promote().unwrap();
        let rotated = manifest_bytes(dir.path(), "v");
        assert_ne!(
            next.keycheck_hex(),
            old_kc,
            "premise: the rotation moved the key generation"
        );

        for (kc, why) in [
            (next.keycheck_hex(), "the committed rotation's keycheck"),
            (old_kc.clone(), "an old keycheck re-seeded by a racing open"),
        ] {
            match stale.anchor_manifest("dd", 6, Some(kc.as_str())) {
                Err(AnchorFault::Integrity(_)) => {}
                other => panic!("{why}: the stale handle wrote ({other:?})"),
            }
            assert_eq!(
                manifest_bytes(dir.path(), "v"),
                rotated,
                "{why}: the rotated salt must survive"
            );
        }
        // The rotated handle itself still anchors.
        let kc = next.keycheck_hex();
        assert!(matches!(
            next.anchor_manifest("dd", 6, Some(kc.as_str())),
            Ok(Anchored::Written { records: 1 })
        ));
    }

    /// **The I/O class (ROADMAP O254)**: every filesystem step the anchor
    /// takes, failed through the fixture seam. Each is reported as I/O — never
    /// integrity, which would stop a healthy handle writing — the manifest is
    /// untouched, no temp file is left behind, and the NEXT anchor writes.
    #[test]
    fn an_anchor_reports_a_filesystem_failure_as_io_and_leaves_no_temp() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("v", SecurityLevel::HmacOnly).unwrap();
        let mut a = mgr.unlock("v").unwrap();
        let kc = a.keycheck_hex();
        let vdir = dir.path().join("vaults/v");
        let mut writes = 0;
        for fault in [
            fixture::Fault::Read,
            fixture::Fault::CreateTemp,
            fixture::Fault::Fsync,
            fixture::Fault::Rename,
        ] {
            writes += 1;
            let before = manifest_bytes(dir.path(), "v");
            fixture::fail_next(fault);
            match a.anchor_manifest(&format!("h{writes}"), writes, Some(kc.as_str())) {
                Err(AnchorFault::Io(_)) => {}
                other => panic!("{fault:?}: expected an I/O fault, got {other:?}"),
            }
            assert_eq!(fixture::armed(), None, "premise: the {fault:?} fault fired");
            assert_eq!(manifest_bytes(dir.path(), "v"), before, "{fault:?}");
            let temps: Vec<_> = std::fs::read_dir(&vdir)
                .unwrap()
                .filter_map(|e| e.unwrap().file_name().into_string().ok())
                .filter(|n| n.contains(".tmp"))
                .collect();
            assert!(temps.is_empty(), "{fault:?} left {temps:?}");
            assert!(
                matches!(
                    a.anchor_manifest(&format!("h{writes}"), writes, Some(kc.as_str())),
                    Ok(Anchored::Written { .. })
                ),
                "{fault:?}: the next anchor must write"
            );
        }
    }

    /// The sweep removes what a crashed write left, past its age, and NEVER
    /// the bare legacy `vault.json.tmp` a 1.6.x process still writes.
    #[test]
    fn the_orphan_sweep_takes_nonce_temps_and_never_the_legacy_name() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("v", SecurityLevel::HmacOnly).unwrap();
        let vdir = dir.path().join("vaults/v");
        let nonce = "0123456789abcdef0123456789abcdef";
        let orphans = [
            format!("vault.json.tmp.{nonce}"),
            format!("vault.json.next.tmp.{nonce}"),
        ];
        let kept = [
            "vault.json.tmp".to_string(),
            format!("vault.json.tmp.{}", &nonce[..31]),
            format!("vault.json.tmp.{}", nonce.to_uppercase()),
            format!("other.tmp.{nonce}"),
        ];
        for name in orphans.iter().chain(&kept) {
            std::fs::write(vdir.join(name), b"x").unwrap();
        }
        assert_eq!(
            v.sweep_orphan_temps(std::time::Duration::from_secs(3600))
                .unwrap(),
            0,
            "a young temp is not swept"
        );
        assert_eq!(
            v.sweep_orphan_temps(std::time::Duration::ZERO).unwrap(),
            orphans.len()
        );
        for name in &orphans {
            assert!(!vdir.join(name).exists(), "{name} survived");
        }
        for name in &kept {
            assert!(vdir.join(name).exists(), "{name} was swept");
        }
        assert!(vdir.join("vault.json").exists());
    }

    #[test]
    fn the_chain_commit_delta_counts_each_record_once_across_handles() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("two-handles", SecurityLevel::Sealed).unwrap();
        let mut a = mgr.unlock("two-handles").unwrap();
        let mut b = mgr.unlock("two-handles").unwrap();

        // Handle A commits five records.
        assert_eq!(
            records(
                a.anchor_manifest("aa", 5, Some(a.keycheck_hex()).as_deref())
                    .unwrap()
            ),
            5
        );
        // Handle B commits ONE more. Its own cached baseline is still 0, so
        // this is the line that used to answer 6.
        assert_eq!(
            records(
                b.anchor_manifest("bb", 6, Some(b.keycheck_hex()).as_deref())
                    .unwrap()
            ),
            1,
            "the delta is against the last anchor ANY handle committed, not \
             against this handle's memory of one"
        );
        // ...and back again, in both directions, because a fix that simply
        // moved the staleness to the other handle would pass a one-way test.
        assert_eq!(
            records(
                a.anchor_manifest("cc", 9, Some(a.keycheck_hex()).as_deref())
                    .unwrap()
            ),
            3
        );
        assert_eq!(
            records(
                b.anchor_manifest("dd", 10, Some(b.keycheck_hex()).as_deref())
                    .unwrap()
            ),
            1
        );

        // The total is the chain's real growth, which is the counter's
        // whole contract.
        let mut c = mgr.unlock("two-handles").unwrap();
        assert_eq!(
            records(
                c.anchor_manifest("ee", 11, Some(c.keycheck_hex()).as_deref())
                    .unwrap()
            ),
            1
        );

        // A crash between commit and anchor leaves records unanchored; the
        // NEXT anchor counts them. That is the same rule read-audit records
        // already rely on, and it must survive this change.
        assert_eq!(
            records(
                c.anchor_manifest("ff", 14, Some(c.keycheck_hex()).as_deref())
                    .unwrap()
            ),
            3
        );

        // Single-handle behaviour is untouched — the case every existing
        // deployment is in.
        let dir2 = tempdir().unwrap();
        let mgr2 = VaultManager::open(dir2.path(), None).unwrap();
        mgr2.create("one-handle", SecurityLevel::Sealed).unwrap();
        let mut only = mgr2.unlock("one-handle").unwrap();
        assert_eq!(
            records(
                only.anchor_manifest("11", 1, Some(only.keycheck_hex()).as_deref())
                    .unwrap()
            ),
            1
        );
        assert_eq!(
            records(
                only.anchor_manifest("22", 257, Some(only.keycheck_hex()).as_deref())
                    .unwrap()
            ),
            256
        );
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

    /// **ROADMAP O257, the promote.** Written from memory, idempotent, never
    /// lowering, and removing the staged file only while it is exactly the
    /// bytes this generation staged — plus the verdicts a leftover and a
    /// foreign keycheck read as.
    #[test]
    fn the_promote_is_idempotent_never_lowers_and_removes_only_its_own_staged_file() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        mgr.create("v", SecurityLevel::Sealed).unwrap();
        let vdir = dir.path().join("vaults/v");
        let staging = vdir.join(STAGING_FILE);
        let old = mgr.unlock("v").unwrap();
        let mut next = mgr.rotation_candidate("v").unwrap();
        next.save_manifest_pending(&Vault::chain_genesis_hex(), 3)
            .unwrap();
        assert!(staging.exists() && next.staged_seen().is_some(), "premise");

        // Promoted from memory even when the staged file is gone.
        fs::remove_file(&staging).unwrap();
        next.promote().unwrap();
        assert!(next.manifest_on_disk_is_mine(), "written from memory");
        assert!(!old.manifest_on_disk_is_mine());

        // Idempotent and never lowering: an anchor the new generation wrote
        // after the promote survives a second promote of the staged state.
        let kc = next.keycheck_hex();
        next.anchor_manifest("ab", 9, Some(kc.as_str())).unwrap();
        let anchored = fs::read(vdir.join(MANIFEST_FILE)).unwrap();
        next.promote().unwrap();
        assert_eq!(fs::read(vdir.join(MANIFEST_FILE)).unwrap(), anchored);

        // A staged file that is not the bytes this generation staged is left
        // where it is; the same bytes are removed.
        fs::write(&staging, b"some other rotation's staging file").unwrap();
        assert!(!next.remove_staged_if_unchanged().unwrap());
        assert!(staging.exists(), "another file must survive");
        let mut again = mgr.rotation_candidate("v").unwrap();
        again
            .save_manifest_pending(&Vault::chain_genesis_hex(), 9)
            .unwrap();
        assert!(!next.remove_staged_if_unchanged().unwrap());
        assert!(again.remove_staged_if_unchanged().unwrap());
        assert!(!staging.exists());

        // A too-new vault.json is refused, never overwritten (O238).
        let path = vdir.join(MANIFEST_FILE);
        let mut m = Manifest::parse(&fs::read(&path).unwrap()).unwrap();
        m.version = MANIFEST_VERSION + 1;
        m.manifest_mac_hex = hex::encode(record_hmac(&next.manifest_key, &m.canonical()));
        let too_new = serde_json::to_vec(&m).unwrap();
        fs::write(&path, &too_new).unwrap();
        assert!(matches!(
            again.promote(),
            Err(VaultError::ManifestTooNew { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), too_new);
        fs::write(&path, &anchored).unwrap();

        // Verdicts. A staged file naming vault.json's own generation — a crash
        // between the promote's write and its removal — is settled.
        fs::write(&staging, &anchored).unwrap();
        let u = mgr.unlock("v").unwrap();
        assert!(u.has_pending(), "premise: the leftover authenticates");
        assert_eq!(u.rotation_verdict(Some(&kc)), RotationVerdict::Settled);
        assert_eq!(
            u.rotation_verdict(Some(&old.keycheck_hex())),
            RotationVerdict::Foreign
        );
        fs::remove_file(&staging).unwrap();
        let u = mgr.unlock("v").unwrap();
        assert_eq!(u.rotation_verdict(None), RotationVerdict::Settled);
        assert_eq!(
            u.rotation_verdict(Some("0000")),
            RotationVerdict::Foreign,
            "a keycheck that is neither generation's"
        );
    }

    /// R4, then ROADMAP O257: no unlock deletes a staging manifest, on either
    /// posture. R4 stopped the READ-ONLY unlock deleting one it could not
    /// authenticate, because it may be one a writer is in the middle of
    /// staging; O257 stopped the WRITABLE unlock too — it deleted every such
    /// file outside any lock, a too-new one included (`parse(..).ok()` read
    /// `ManifestTooNew` as "torn", contrary to O238's record). The writable arm
    /// used to assert the deletion; it is inverted here, not removed, and the
    /// too-new arm is the counterfactual for the O238 defect.
    #[test]
    fn no_unlock_deletes_a_staging_manifest_it_cannot_authenticate() {
        let dir = tempdir().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let v = mgr.create("t", SecurityLevel::Sealed).unwrap();
        let staging = dir.path().join("vaults/t/vault.json.next");

        std::fs::write(&staging, b"not a manifest").unwrap();
        for access in [Access::ReadOnly, Access::ReadWrite] {
            let u = mgr.unlock_as("t", access).unwrap();
            assert!(staging.exists(), "{access:?}: the unlock removed it");
            assert_eq!(u.unhealed(), [Unhealed::TornStagingManifest].as_slice());
            assert!(!u.has_pending());
            assert!(u.staged_seen().is_some(), "{access:?}: the bytes it read");
        }
        mgr.rotation_candidate("t").unwrap();
        assert!(staging.exists(), "rotation_candidate removed it");

        // A too-new staging manifest: another build's rotation is pending.
        let mut m =
            Manifest::parse(&fs::read(dir.path().join("vaults/t/vault.json")).unwrap()).unwrap();
        m.version = MANIFEST_VERSION + 1;
        m.manifest_mac_hex = hex::encode(record_hmac(&v.manifest_key, &m.canonical()));
        let too_new = serde_json::to_vec(&m).unwrap();
        fs::write(&staging, &too_new).unwrap();
        for access in [Access::ReadOnly, Access::ReadWrite] {
            let u = mgr.unlock_as("t", access).unwrap();
            assert_eq!(fs::read(&staging).unwrap(), too_new, "{access:?}");
            assert_eq!(u.unhealed(), [Unhealed::StagingManifestTooNew].as_slice());
        }
        // With no staging file there is nothing to report.
        fs::remove_file(&staging).unwrap();
        let u = mgr.unlock("t").unwrap();
        assert!(u.unhealed().is_empty());
        assert!(u.staged_seen().is_none());
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

    /// ROADMAP O204 — a manager whose key opens none of the installation's vaults
    /// cannot mint a new one. Under 1.5.2 this is how one palace came to hold
    /// vaults under two keys (the ruling's probes P4 and P15): no single
    /// declaration opened them all afterwards.
    #[test]
    fn create_refuses_to_split_a_palace_across_two_keys() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let by_pass = VaultManager::open(root, Some("correct horse")).unwrap();
        by_pass.create("default", SecurityLevel::Sealed).unwrap();
        // The state an earlier release left behind: a key file beside the salt.
        std::fs::write(root.join(keys::MASTER_KEY_FILE), [9u8; KEY_LEN]).unwrap();

        // Both files present: the undeclared-passphrase open succeeds (the
        // declared source is used) and its create is refused.
        let by_file = VaultManager::open(root, None).unwrap();
        let err = by_file.create("other", SecurityLevel::Sealed).unwrap_err();
        assert!(
            matches!(
                err,
                VaultError::KeyOpensNoVault {
                    manifests: 1,
                    declared: keys::KeySource::KeyFile
                }
            ),
            "{err}"
        );
        assert!(
            !root.join(VAULTS_DIR).join("other").exists(),
            "nothing written"
        );

        // A wrong passphrase on the right source is the same split with no
        // stray file at all.
        let wrong = VaultManager::open(root, Some("wrong staple")).unwrap();
        assert!(matches!(
            wrong.create("other", SecurityLevel::Sealed),
            Err(VaultError::KeyOpensNoVault { .. })
        ));

        // Premise: the installation's own key still creates.
        by_pass.create("second", SecurityLevel::HmacOnly).unwrap();

        // One vault the key does not open among vaults it does is not a
        // split: the create proceeds, and that vault's own unlock is where
        // its verdict belongs. ("None", never "not all".)
        let vj = root.join(VAULTS_DIR).join("second").join("vault.json");
        let tampered = String::from_utf8(std::fs::read(&vj).unwrap())
            .unwrap()
            .replace("hmac-only", "sealed");
        std::fs::write(&vj, tampered).unwrap();
        assert!(matches!(
            by_pass.unlock("second"),
            Err(VaultError::ManifestTampered)
        ));
        by_pass.create("third", SecurityLevel::Sealed).unwrap();

        // Entries that are not vaults do not count, and do not block.
        let fresh = tempdir().unwrap();
        let mgr = VaultManager::open(fresh.path(), None).unwrap();
        std::fs::write(fresh.path().join(VAULTS_DIR).join("notes.txt"), b"x").unwrap();
        std::fs::create_dir_all(fresh.path().join(VAULTS_DIR).join("half")).unwrap();
        mgr.create("first", SecurityLevel::Sealed).unwrap();
    }

    /// ROADMAP O204 — the posture reaches the manager, so a read-only
    /// process performs none of its writes (probes P10 and P11): not a
    /// create, not a delete, and no rotation candidate. (The staging-manifest
    /// deletion `rotation_candidate`'s writable unlock used to perform is gone
    /// on every posture since ROADMAP O257.)
    #[test]
    fn a_read_only_manager_refuses_every_write_before_its_effect() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        VaultManager::open(root, None)
            .unwrap()
            .create("t", SecurityLevel::Sealed)
            .unwrap();
        let staging = root.join("vaults/t/vault.json.next");
        std::fs::write(&staging, b"not a manifest").unwrap();

        let ro = VaultManager::open_as(root, None, Access::ReadOnly).unwrap();
        assert_eq!(ro.access(), Access::ReadOnly);
        assert!(matches!(
            ro.create("u", SecurityLevel::Sealed),
            Err(VaultError::ReadOnly(_))
        ));
        assert!(!root.join("vaults/u").exists());
        assert!(matches!(ro.delete("t"), Err(VaultError::ReadOnly(_))));
        assert!(ro.exists("t"));
        assert!(matches!(
            ro.rotation_candidate("t"),
            Err(VaultError::ReadOnly(_))
        ));
        assert!(staging.exists(), "rotation_candidate must not unlock first");
        // A writable unlock REQUESTED of a read-only manager is read-only.
        let v = ro.unlock("t").unwrap();
        assert!(staging.exists(), "the manager's posture bounds the call's");
        assert_eq!(v.unhealed(), [Unhealed::TornStagingManifest].as_slice());

        // A writable manager's rotation_candidate succeeds — the refusal above
        // is the posture's — and, since ROADMAP O257, deletes nothing either.
        let rw = VaultManager::open(root, None).unwrap();
        rw.rotation_candidate("t").unwrap();
        assert!(staging.exists());
    }

    /// ROADMAP O204 (probe P5) — a read-only open of a directory that holds
    /// no installation creates nothing, lists nothing and can derive nothing.
    #[test]
    fn a_fresh_palace_opened_read_only_is_empty_and_untouched() {
        let parent = tempdir().unwrap();
        let root = parent.path().join("installation");
        for pw in [None, Some("correct horse")] {
            let ro = VaultManager::open_as(&root, pw, Access::ReadOnly).unwrap();
            assert!(ro.list().unwrap().is_empty());
            assert!(!ro.exists("default"));
            assert!(matches!(ro.unlock("default"), Err(VaultError::NotFound(_))));
            assert!(matches!(
                ro.create("default", SecurityLevel::Sealed),
                Err(VaultError::ReadOnly(_))
            ));
            assert!(!root.exists(), "no directory, no key, no vaults/");
        }
        // A vault that appears after a key-less read-only open cannot be
        // opened by that manager: it never had a key to derive from.
        let ro = VaultManager::open_as(&root, None, Access::ReadOnly).unwrap();
        VaultManager::open(&root, None)
            .unwrap()
            .create("late", SecurityLevel::Sealed)
            .unwrap();
        assert!(matches!(ro.unlock("late"), Err(VaultError::ReadOnly(_))));
    }

    /// ROADMAP O204 — a declaration the installation contradicts is refused at the
    /// open, wrapped as a key error, before anything is written.
    #[test]
    fn open_refuses_a_contradicting_declaration() {
        let dir = tempdir().unwrap();
        VaultManager::open(dir.path(), None)
            .unwrap()
            .create("default", SecurityLevel::Sealed)
            .unwrap();
        for access in [Access::ReadWrite, Access::ReadOnly] {
            let err = VaultManager::open_as(dir.path(), Some("correct horse"), access)
                .expect_err("refused");
            assert!(
                matches!(err, VaultError::Key(keys::KeyError::SourceMismatch { .. })),
                "{err}"
            );
        }
        assert!(!dir.path().join(keys::KDF_SALT_FILE).exists());
        assert!(VaultManager::open(dir.path(), None)
            .unwrap()
            .unlock("default")
            .is_ok());
    }

    /// **ROADMAP O266's source gate: one manifest rule, three readers, and
    /// every read of a manifest file named.**
    ///
    /// The defect was a reader reaching `vault.json` under the wrong rule, and
    /// the fix is ONE rule (`manifest_in_force`) three readers share while the
    /// strict readers stay strict: a lenient `manifest_on_disk_is_mine` lets a
    /// second rotation stage over the only file holding the keys, and a lenient
    /// `promote` removes `.next` with nothing written. The tamper event is
    /// raised in exactly three places — the unlock, the rule's refusal and
    /// O204's key-opens-no-vault refusal — never by the rule itself, so a
    /// healthy deferred vault never pages an operator. And every `fs::read` of a
    /// manifest file in this file is counted against a named list, so a new
    /// reader cannot skip the rule unseen. Scoped to this file: `backups.rs` and
    /// `restores.rs` read an ARCHIVE's or a STAGE's manifest, never a handle's
    /// anchor. Needles are split with `concat!` so this test's own text is not
    /// counted.
    #[test]
    fn the_manifest_rule_has_three_readers_and_every_manifest_read_is_named() {
        let src = include_str!("lib.rs");
        let cut = src
            .find(concat!("#[cfg(test)]\nmod ", "tests {"))
            .expect("premise: the tests module is where this gate expects it");
        let prod = &src[..cut];
        let fn_name = |line: &str| -> Option<String> {
            let t = line.trim_start();
            let t = t
                .strip_prefix("pub(crate) ")
                .or_else(|| t.strip_prefix("pub "))
                .unwrap_or(t);
            let t = t.strip_prefix("fn ")?;
            let end = t.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
            Some(t[..end].to_string())
        };
        let body = |name: &str| -> &str {
            let start = prod
                .find(&format!("fn {name}("))
                .unwrap_or_else(|| panic!("premise: no fn {name} in production code"));
            let rest = &prod[start + 3..];
            let end = [
                "\n    pub fn ",
                "\n    fn ",
                "\n    pub(crate) fn ",
                "\npub fn ",
                "\nfn ",
                "\npub(crate) fn ",
                "\nimpl ",
            ]
            .iter()
            .filter_map(|m| rest.find(m))
            .min()
            .unwrap_or(rest.len());
            &rest[..end]
        };

        let call = concat!("self.manifest_in", "_force()");
        assert_eq!(
            prod.matches(call).count(),
            3,
            "the manifest rule has exactly three readers"
        );
        for reader in ["anchored_head", "anchored_writes", "verified_manifest"] {
            assert!(
                body(reader).contains(call),
                "{reader} reads through the rule"
            );
        }
        for strict in [
            "manifest_on_disk_is_mine",
            "manifest_on_disk_digest",
            "verified_disk_manifest",
            "verified_disk_read",
            "anchor_manifest",
            "promote",
            "remove_staged_if_unchanged",
            "staged_on_disk",
        ] {
            assert!(
                !body(strict).contains(call),
                "{strict} asks about vault.json alone and must never take the rule"
            );
        }

        let emit = concat!("hmac_verify_failed(\"mani", "fest\")");
        assert_eq!(
            prod.matches(emit).count(),
            3,
            "the manifest tamper event is raised at the unlock, in the rule's refusal and in \
             O204's key-opens-no-vault refusal, and nowhere else"
        );
        for site in ["unlock_dir", "refusal", "key_opens_an_existing_vault"] {
            assert!(body(site).contains(emit), "{site} raises the tamper event");
        }
        for silent in ["manifest_in_force", "anchored_writes"] {
            assert!(
                !body(silent).contains(emit)
                    && !body(silent).contains(concat!("event_hmac", "_fail")),
                "{silent} must not raise the tamper event"
            );
        }

        let mut reads: Vec<String> = Vec::new();
        let mut current = String::new();
        for line in prod.lines() {
            if let Some(name) = fn_name(line) {
                current = name;
            }
            if line.contains(concat!("fs::re", "ad("))
                && [
                    "MANIFEST_FILE",
                    "\"vault.json\"",
                    "pending_path",
                    "STAGING_FILE",
                    "manifest_path",
                ]
                .iter()
                .any(|n| line.contains(n))
            {
                reads.push(current.clone());
            }
        }
        reads.sort();
        let mut expected = vec![
            "key_opens_an_existing_vault",
            "manifest_in_force",
            "manifest_in_force",
            "promote",
            "staged_on_disk",
            "unlock_dir",
            "unlock_dir",
            "verified_disk_read",
        ];
        expected.sort();
        assert_eq!(
            reads, expected,
            "every read of a manifest file is one of these; a new one must be ruled on \
             (ROADMAP O266)"
        );
    }
}
