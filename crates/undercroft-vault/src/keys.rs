//! Key material management.
//!
//! One master key per palace, from either a generated key file (default,
//! `master.key`, mode 0600 on Unix; not narrowed on Windows) or an
//! Argon2id-derived passphrase
//! (`UNDERCROFT_PASSPHRASE`). Per-vault keys are derived with HKDF-SHA256
//! using the vault id and a per-vault random salt as domain separation:
//!
//! ```text
//! enc_key    = HKDF(master, salt=vault_salt, info="undercroft.v1/vault/<id>/enc")
//! mac_key    = HKDF(master, salt=vault_salt, info="undercroft.v1/vault/<id>/mac")
//! sample_key = HKDF(master, salt=vault_salt, info="undercroft.v1/vault/<id>/sample")
//! ```
//!
//! (`manifest` is derived the same way; `sample` keys the training-sample draw
//! of trained index artifacts — see [`super::Vault::sample_rank`] — and is
//! separate from `mac` so a rank never shares a key with record integrity.)
//!
//! Vaults therefore never share working keys: leaking one vault's derived
//! keys does not expose siblings, and ciphertext cannot be transplanted
//! between vaults (the AEAD AAD additionally binds vault id + record id).
//!
//! **Key material is created only where nothing refers to a key** (ROADMAP
//! O204). The master key is never rotated — rotation moves a vault's salt —
//! so every `vault.json`, and every backup copy of one, refers to it for as
//! long as it exists. [`master_key`] therefore surveys the installation by stat
//! alone, classifies it with [`plan`], and only then reads, derives or
//! writes. It used to choose from the DECLARATION alone: a passphrase
//! declared on an installation keyed by `master.key` wrote a fresh `kdf.salt`,
//! derived a key no vault was sealed under, and the first unlock reported
//! tampering; `vault create` under that key then split the installation.

use crate::Access;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::fs;
use std::io;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The installation's random master key — the key source when no passphrase is
/// declared.
pub const MASTER_KEY_FILE: &str = "master.key";
/// The installation's Argon2id salt — the key source's persisted half when
/// `UNDERCROFT_PASSPHRASE` is declared.
pub const KDF_SALT_FILE: &str = "kdf.salt";

/// Length of every symmetric key and every X25519 / Ed25519 key this crate
/// handles, in bytes. The ML-KEM-768 halves of a hybrid bundle identity are
/// their own sizes (`bundle.rs`).
pub const KEY_LEN: usize = 32;
/// Length of a vault's key-derivation salt, in bytes.
pub const SALT_LEN: usize = 16;

/// Master-key file and key-derivation failures.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Reading or writing the key file failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// `master.key` is not exactly `KEY_LEN` bytes, or, under a passphrase,
    /// `kdf.salt` is not exactly `SALT_LEN` bytes.
    #[error("master key material is corrupt (expected a {KEY_LEN}-byte master.key or a {SALT_LEN}-byte kdf.salt)")]
    CorruptKeyFile,
    /// Argon2id refused; the message is the library's.
    #[error("argon2 failure: {0}")]
    Kdf(String),
    /// The declared source's file is absent and the OTHER source's file is
    /// present (ROADMAP O204). Refused before anything is derived or
    /// written. Not an integrity verdict: nothing has been verified, and the
    /// files alone cannot say which source keyed the installation.
    #[error("{}", source_mismatch_message(.declared, .references))]
    SourceMismatch {
        /// The key source this process declared.
        declared: KeySource,
        /// Entries under `vaults/` and `backups/` — what may refer to a key.
        references: usize,
    },
    /// Neither key file is present while the installation already holds vaults or
    /// backups (ROADMAP O204). A fresh key would open none of them, so none
    /// is created.
    #[error("{}", material_missing_message(.declared, .references))]
    MaterialMissing {
        /// The key source this process declared.
        declared: KeySource,
        /// Entries under `vaults/` and `backups/` — what may refer to a key.
        references: usize,
    },
}

/// Which key source a process declares: `UNDERCROFT_PASSPHRASE` set, or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// No passphrase: the random key in [`MASTER_KEY_FILE`].
    KeyFile,
    /// A passphrase: Argon2id over it and the salt in [`KDF_SALT_FILE`].
    Passphrase,
}

impl KeySource {
    /// The source a declaration names.
    pub fn declared(passphrase: Option<&str>) -> Self {
        if passphrase.is_some() {
            KeySource::Passphrase
        } else {
            KeySource::KeyFile
        }
    }

    /// The file this source keeps in the installation root.
    pub fn file(self) -> &'static str {
        match self {
            KeySource::KeyFile => MASTER_KEY_FILE,
            KeySource::Passphrase => KDF_SALT_FILE,
        }
    }

    fn other(self) -> Self {
        match self {
            KeySource::KeyFile => KeySource::Passphrase,
            KeySource::Passphrase => KeySource::KeyFile,
        }
    }
}

// The messages below give BOTH readings of what the operator is looking at
// and make every step conditional on how the installation was set up. They never
// tell anyone to unset the passphrase outright: the files are unauthenticated
// and an offline writer controls them, so "remove the declaration" said
// unconditionally would steer a passphrase deployment towards a key someone
// planted. They never name key bytes, a salt or a fingerprint, and never
// advise deleting a file — losing `kdf.salt` loses every passphrase vault as
// surely as losing `master.key` loses every key-file vault.

fn refers(references: usize) -> String {
    if references == 0 {
        "No vault or backup here refers to it yet".to_string()
    } else {
        format!(
            "{references} vault or backup entr{} here refer{} to the master key; do \
             not delete either file",
            if references == 1 { "y" } else { "ies" },
            if references == 1 { "s" } else { "" },
        )
    }
}

fn source_mismatch_message(declared: &KeySource, references: &usize) -> String {
    match declared {
        KeySource::Passphrase => format!(
            "UNDERCROFT_PASSPHRASE is declared, but this data directory holds {MASTER_KEY_FILE} and no \
             {KDF_SALT_FILE}, so nothing here pairs with the passphrase; nothing was written. If \
             the installation was set up WITHOUT a passphrase, it is keyed by {MASTER_KEY_FILE}: open \
             it without UNDERCROFT_PASSPHRASE, and move to a passphrase by exporting into a new \
             installation. If it was set up WITH one, {KDF_SALT_FILE} is missing: restore it, keep the \
             declaration, and treat {MASTER_KEY_FILE} as unexplained. {} (ROADMAP O204)",
            refers(*references)
        ),
        KeySource::KeyFile => format!(
            "UNDERCROFT_PASSPHRASE is not declared, but this data directory holds {KDF_SALT_FILE} and no \
             {MASTER_KEY_FILE}; nothing was written. If the installation was set up WITH a passphrase, \
             declare UNDERCROFT_PASSPHRASE. If it was set up without one, {MASTER_KEY_FILE} is \
             missing: restore it and treat {KDF_SALT_FILE} as unexplained. {} (ROADMAP O204)",
            refers(*references)
        ),
    }
}

fn material_missing_message(declared: &KeySource, references: &usize) -> String {
    let file = declared.file();
    let how = match declared {
        KeySource::KeyFile => format!(
            "Restore {MASTER_KEY_FILE} (or mount it where the installation expects it); if the installation \
             was set up with a passphrase, declare UNDERCROFT_PASSPHRASE and restore \
             {KDF_SALT_FILE} instead."
        ),
        KeySource::Passphrase => format!(
            "Restore {KDF_SALT_FILE}: the passphrase alone cannot re-derive the key without it. \
             If the installation was set up without a passphrase, restore {MASTER_KEY_FILE} instead."
        ),
    };
    format!(
        "{file} is missing, and this data directory already holds {references} vault or backup \
         entr{}. A new key would open none of them, so none was created and nothing was \
         written. {how} (ROADMAP O204)",
        if *references == 1 { "y" } else { "ies" },
    )
}

/// The warning every manager open prints while BOTH key files are present.
///
/// Exactly one of them keys any given vault; an earlier release wrote the
/// other (ROADMAP O204), or the installation was split by a create under the other
/// declaration. The engine uses the declared one and lets each vault's
/// manifest MAC decide, because the files are no evidence either way.
pub fn both_present_warning(declared: KeySource) -> String {
    format!(
        "this data directory holds both {MASTER_KEY_FILE} and {KDF_SALT_FILE}; using {} as declared. \
         Each vault opens under only one of them, so do not delete either until one \
         declaration opens every vault (ROADMAP O204)",
        declared.file()
    )
}

/// What an installation root holds, gathered by stat alone — no file is opened and
/// nothing is derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PalaceSurvey {
    /// A `master.key` entry exists (a symlink counts, dangling or not).
    pub master_key: bool,
    /// A `kdf.salt` entry exists.
    pub kdf_salt: bool,
    /// Entries under `vaults/` plus entries under `backups/`: everything that
    /// may refer to the master key. `vaults/` holding a directory with no
    /// manifest still counts — a directory with a database in it is not a
    /// fresh palace.
    pub references: usize,
}

impl PalaceSurvey {
    fn has(&self, source: KeySource) -> bool {
        match source {
            KeySource::KeyFile => self.master_key,
            KeySource::Passphrase => self.kdf_salt,
        }
    }
}

/// Stat the installation root. Every error except "not there" PROPAGATES: a
/// permission error read as absence is how a key gets created over an installation
/// that has one, which is this module's whole defect class.
pub fn survey(root: &Path) -> Result<PalaceSurvey, KeyError> {
    Ok(PalaceSurvey {
        master_key: entry_present(&root.join(MASTER_KEY_FILE))?,
        kdf_salt: entry_present(&root.join(KDF_SALT_FILE))?,
        references: entries(&root.join(crate::VAULTS_DIR))?
            + entries(&root.join(crate::BACKUPS_DIR))?,
    })
}

/// Whether a directory ENTRY exists. `symlink_metadata`, so a symlinked key
/// file (how container secrets are mounted) is present even while its
/// target is not, and is then never created over.
fn entry_present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn entries(dir: &Path) -> io::Result<usize> {
    match fs::read_dir(dir) {
        Ok(rd) => {
            let mut n = 0;
            for entry in rd {
                entry?;
                n += 1;
            }
            Ok(n)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

/// What [`master_key`] will do for an installation, decided before anything is
/// read, derived or written. `undercroft config check` asks the same
/// question through this function, so the pre-flight and the start cannot
/// answer differently.
#[derive(Debug)]
pub enum KeyPlan {
    /// Load the declared source's material.
    Load {
        /// The other source's file is present as well — warn, never choose.
        other_present: bool,
    },
    /// A fresh palace under a writable posture: create the declared source's
    /// material. The witness is what the private writer takes.
    Create(CreateWitness),
    /// A fresh palace under a read-only posture: hold no key and write
    /// nothing.
    NoKey,
}

/// Proof that [`plan`] classified an installation as fresh under a writable
/// posture. Its field is private, so nothing outside this module can make
/// one, and the one function that writes key material takes it.
#[derive(Debug)]
pub struct CreateWitness {
    source: KeySource,
}

/// Classify a surveyed installation for a declared source and posture.
pub fn plan(
    declared: KeySource,
    survey: &PalaceSurvey,
    access: Access,
) -> Result<KeyPlan, KeyError> {
    if survey.has(declared) {
        return Ok(KeyPlan::Load {
            other_present: survey.has(declared.other()),
        });
    }
    if survey.has(declared.other()) {
        // Refused even when nothing refers to the other file yet: creating
        // the declared one would leave two key sources in one palace, and
        // the next create under the other declaration would split it.
        return Err(KeyError::SourceMismatch {
            declared,
            references: survey.references,
        });
    }
    if survey.references > 0 {
        return Err(KeyError::MaterialMissing {
            declared,
            references: survey.references,
        });
    }
    Ok(match access {
        Access::ReadWrite => KeyPlan::Create(CreateWitness { source: declared }),
        Access::ReadOnly => KeyPlan::NoKey,
    })
}

/// The master key an open resolved to.
pub struct MasterKey {
    /// `None` only for a fresh palace opened read-only.
    pub key: Option<SecretKey>,
    /// Both key files are present; the declared one was used.
    pub both_present: bool,
}

/// Resolve the installation master key: survey, classify, then load or create.
///
/// With a passphrase the key is Argon2id (64 MiB, t=3, p=1) over the
/// passphrase and the palace-level salt in `<root>/kdf.salt`, and the secret never
/// touches disk; otherwise it is the random key in `<root>/master.key`. A
/// created file is owner-only on Unix (not narrowed on Windows). Argon2id
/// runs only after the classifier has accepted the installation.
pub fn master_key(
    root: &Path,
    passphrase: Option<&str>,
    access: Access,
) -> Result<MasterKey, KeyError> {
    let declared = KeySource::declared(passphrase);
    let mut retried = false;
    loop {
        match plan(declared, &survey(root)?, access)? {
            KeyPlan::Load { other_present } => {
                return Ok(MasterKey {
                    key: Some(load_master(root, passphrase)?),
                    both_present: other_present,
                })
            }
            KeyPlan::NoKey => {
                return Ok(MasterKey {
                    key: None,
                    both_present: false,
                })
            }
            KeyPlan::Create(witness) => match create_master(root, passphrase, witness) {
                // A concurrent first start created the file between our stat
                // and our exclusive create: classify again and load what it
                // wrote, never overwrite it.
                Err(KeyError::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists && !retried => {
                    retried = true;
                }
                created => {
                    return Ok(MasterKey {
                        key: Some(created?),
                        both_present: false,
                    })
                }
            },
        }
    }
}

/// Read the declared source's material and derive the master key. Never
/// writes.
fn load_master(root: &Path, passphrase: Option<&str>) -> Result<SecretKey, KeyError> {
    match passphrase {
        Some(pw) => {
            let salt = fs::read(root.join(KDF_SALT_FILE))?;
            if salt.len() != SALT_LEN {
                return Err(KeyError::CorruptKeyFile);
            }
            derive_from_passphrase(pw, &salt)
        }
        None => {
            let raw = fs::read(root.join(MASTER_KEY_FILE))?;
            let arr: [u8; KEY_LEN] = raw
                .as_slice()
                .try_into()
                .map_err(|_| KeyError::CorruptKeyFile)?;
            Ok(SecretKey(arr))
        }
    }
}

/// Create the declared source's material in an installation [`plan`] found fresh —
/// the ONE function that writes key material. It is private and takes the
/// classifier's witness, so its only caller is [`master_key`], which
/// surveyed THIS root first (`plan` is public for `config check`, and a
/// survey can be built by hand, so a public writer here would be a writer
/// without a check).
fn create_master(
    root: &Path,
    passphrase: Option<&str>,
    witness: CreateWitness,
) -> Result<SecretKey, KeyError> {
    if witness.source != KeySource::declared(passphrase) {
        return Err(KeyError::Io(io::Error::other(
            "a key-creation witness was issued for a different key source",
        )));
    }
    fs::create_dir_all(root)?;
    match passphrase {
        Some(pw) => {
            let mut salt = [0u8; SALT_LEN];
            rand::thread_rng().fill_bytes(&mut salt);
            write_new_private(&root.join(KDF_SALT_FILE), &salt)?;
            derive_from_passphrase(pw, &salt)
        }
        None => {
            let mut key = [0u8; KEY_LEN];
            rand::thread_rng().fill_bytes(&mut key);
            write_new_private(&root.join(MASTER_KEY_FILE), &key)?;
            Ok(SecretKey(key))
        }
    }
}

fn derive_from_passphrase(pw: &str, salt: &[u8]) -> Result<SecretKey, KeyError> {
    let params =
        Params::new(64 * 1024, 3, 1, Some(KEY_LEN)).map_err(|e| KeyError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(pw.as_bytes(), salt, &mut out)
        .map_err(|e| KeyError::Kdf(e.to_string()))?;
    Ok(SecretKey(out))
}

/// 32-byte secret, zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) [u8; KEY_LEN]);

impl SecretKey {
    /// The raw key bytes. Never logged and never `Debug`-printed.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Derive one labeled subkey for a vault from the master key.
pub fn derive_vault_key(
    master: &SecretKey,
    vault_salt: &[u8],
    vault_id: &str,
    label: &str,
) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(Some(vault_salt), master.as_bytes());
    let info = format!("undercroft.v1/vault/{vault_id}/{label}");
    let mut out = [0u8; KEY_LEN];
    hk.expand(info.as_bytes(), &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SecretKey(out)
}

/// Generate a fresh random vault salt.
pub fn new_vault_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Write a NEW key file: exclusive create, so an entry that appeared after
/// the survey — a concurrent first start, a planted symlink — fails with
/// `AlreadyExists` instead of being truncated or followed; owner-only from
/// the moment it exists on Unix, never narrowed after the bytes land.
///
/// Key material is written once and is unrecoverable if lost, so the file
/// and its directory entry are fsynced before this returns. A crash between
/// the create and the write still leaves a short file — ROADMAP O210.
fn write_new_private(path: &Path, data: &[u8]) -> io::Result<()> {
    {
        use std::io::Write;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// fsync a directory so a just-created or just-renamed entry inside it
/// survives power loss. Directories cannot be opened for sync on Windows;
/// there the rename itself is the strongest primitive available, so this
/// is a no-op.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn key(root: &Path, pw: Option<&str>) -> SecretKey {
        master_key(root, pw, Access::ReadWrite)
            .unwrap()
            .key
            .expect("a writable open always holds a key")
    }

    fn files(root: &Path) -> (bool, bool) {
        (
            root.join(MASTER_KEY_FILE).exists(),
            root.join(KDF_SALT_FILE).exists(),
        )
    }

    /// An installation that already refers to its key: one vault directory.
    fn with_a_vault(root: &Path) {
        fs::create_dir_all(root.join(crate::VAULTS_DIR).join("default")).unwrap();
    }

    #[test]
    fn master_key_persists_across_loads() {
        let dir = tempdir().unwrap();
        let a = key(dir.path(), None);
        let b = key(dir.path(), None);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn passphrase_derivation_is_stable_and_salted() {
        let dir = tempdir().unwrap();
        let a = key(dir.path(), Some("correct horse"));
        let b = key(dir.path(), Some("correct horse"));
        assert_eq!(a.as_bytes(), b.as_bytes());
        // A wrong passphrase on the RIGHT source still derives, to a
        // different key, which the manifest MAC then refuses (exit 2, the
        // stated cost). The classifier has nothing to say about it.
        let other = key(dir.path(), Some("wrong staple"));
        assert_ne!(a.as_bytes(), other.as_bytes());
        // A different palace (different salt) with the same passphrase gets a different key.
        let dir2 = tempdir().unwrap();
        let c = key(dir2.path(), Some("correct horse"));
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn vault_keys_are_domain_separated() {
        let dir = tempdir().unwrap();
        let master = key(dir.path(), None);
        let salt = new_vault_salt();
        let enc_a = derive_vault_key(&master, &salt, "vault-a", "enc");
        let mac_a = derive_vault_key(&master, &salt, "vault-a", "mac");
        let enc_b = derive_vault_key(&master, &salt, "vault-b", "enc");
        assert_ne!(enc_a.as_bytes(), mac_a.as_bytes());
        assert_ne!(enc_a.as_bytes(), enc_b.as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_owner_only_from_creation() {
        use std::os::unix::fs::PermissionsExt;
        for pw in [None, Some("correct horse")] {
            let dir = tempdir().unwrap();
            let _ = key(dir.path(), pw);
            let file = KeySource::declared(pw).file();
            let mode = fs::metadata(dir.path().join(file))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{file}");
        }
    }

    /// The whole decision, as a table: every combination of declared source,
    /// files present, references and posture (ROADMAP O204).
    #[test]
    fn the_classifier_decides_every_palace_state() {
        #[derive(Debug, PartialEq)]
        enum Want {
            Load { other: bool },
            Create,
            NoKey,
            Mismatch,
            Missing,
        }
        use Access::{ReadOnly as RO, ReadWrite as RW};
        use KeySource::{KeyFile as K, Passphrase as P};
        let s = |master_key, kdf_salt, references| PalaceSurvey {
            master_key,
            kdf_salt,
            references,
        };
        let rows: &[(KeySource, PalaceSurvey, Access, Want)] = &[
            // The declared file is there: load it, and flag the other.
            (K, s(true, false, 1), RW, Want::Load { other: false }),
            (P, s(false, true, 1), RO, Want::Load { other: false }),
            (K, s(true, true, 2), RW, Want::Load { other: true }),
            (P, s(true, true, 0), RO, Want::Load { other: true }),
            // The filed shape, both directions, with and without references.
            (P, s(true, false, 1), RW, Want::Mismatch),
            (K, s(false, true, 1), RW, Want::Mismatch),
            (P, s(true, false, 0), RW, Want::Mismatch),
            (K, s(false, true, 0), RO, Want::Mismatch),
            // Nothing there, but something refers to a key.
            (K, s(false, false, 1), RW, Want::Missing),
            (P, s(false, false, 3), RW, Want::Missing),
            (K, s(false, false, 1), RO, Want::Missing),
            // A fresh palace.
            (K, s(false, false, 0), RW, Want::Create),
            (P, s(false, false, 0), RW, Want::Create),
            (K, s(false, false, 0), RO, Want::NoKey),
            (P, s(false, false, 0), RO, Want::NoKey),
        ];
        for (declared, survey, access, want) in rows {
            let got = match plan(*declared, survey, *access) {
                Ok(KeyPlan::Load { other_present }) => Want::Load {
                    other: other_present,
                },
                Ok(KeyPlan::Create(w)) => {
                    assert_eq!(w.source, *declared, "witness for the declared source");
                    Want::Create
                }
                Ok(KeyPlan::NoKey) => Want::NoKey,
                Err(KeyError::SourceMismatch {
                    declared: d,
                    references,
                }) => {
                    assert_eq!((d, references), (*declared, survey.references));
                    Want::Mismatch
                }
                Err(KeyError::MaterialMissing {
                    declared: d,
                    references,
                }) => {
                    assert_eq!((d, references), (*declared, survey.references));
                    Want::Missing
                }
                Err(e) => panic!("unexpected {e}"),
            };
            assert_eq!(&got, want, "{declared:?} over {survey:?} under {access:?}");
        }
    }

    /// The filed case and its reverse, end to end: refused, and NOTHING
    /// written. The stray file was the defect's lasting damage.
    #[test]
    fn a_declaration_that_contradicts_the_palace_refuses_and_writes_nothing() {
        for (setup, then) in [(None, Some("correct horse")), (Some("correct horse"), None)] {
            let dir = tempdir().unwrap();
            let original = key(dir.path(), setup);
            with_a_vault(dir.path());
            let before = files(dir.path());
            // Premise: exactly the set-up source's file exists.
            assert_eq!(
                before,
                (setup.is_none(), setup.is_some()),
                "premise: one key file"
            );
            for access in [Access::ReadWrite, Access::ReadOnly] {
                let err = master_key(dir.path(), then, access)
                    .err()
                    .expect("a contradicting declaration must refuse");
                assert!(
                    matches!(err, KeyError::SourceMismatch { references: 1, .. }),
                    "{err}"
                );
                assert_eq!(files(dir.path()), before, "nothing may be written");
            }
            // Removing the contradicting declaration opens it as before.
            assert_eq!(key(dir.path(), setup).as_bytes(), original.as_bytes());
        }
    }

    #[test]
    fn missing_key_material_under_existing_vaults_is_never_replaced() {
        for (pw, file) in [
            (None, MASTER_KEY_FILE),
            (Some("correct horse"), KDF_SALT_FILE),
        ] {
            let dir = tempdir().unwrap();
            let _ = key(dir.path(), pw);
            with_a_vault(dir.path());
            fs::remove_file(dir.path().join(file)).unwrap();
            for access in [Access::ReadWrite, Access::ReadOnly] {
                let err = master_key(dir.path(), pw, access).err().expect("refuses");
                assert!(matches!(err, KeyError::MaterialMissing { .. }), "{err}");
                assert_eq!(files(dir.path()), (false, false), "no key was created");
            }
        }
        // A backup refers to the key just as a vault does.
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(crate::BACKUPS_DIR).join("default-x")).unwrap();
        let err = master_key(dir.path(), None, Access::ReadWrite)
            .err()
            .expect("a backup is a reference");
        assert!(matches!(err, KeyError::MaterialMissing { .. }), "{err}");
    }

    #[test]
    fn both_files_present_loads_the_declared_one_and_says_so() {
        let dir = tempdir().unwrap();
        let by_file = key(dir.path(), None);
        with_a_vault(dir.path());
        // The state earlier releases left behind: a salt beside the key file.
        fs::write(dir.path().join(KDF_SALT_FILE), [7u8; SALT_LEN]).unwrap();
        let m = master_key(dir.path(), None, Access::ReadOnly).unwrap();
        assert!(m.both_present);
        assert_eq!(m.key.unwrap().as_bytes(), by_file.as_bytes());
        let m = master_key(dir.path(), Some("pw"), Access::ReadWrite).unwrap();
        assert!(m.both_present);
        assert_ne!(
            m.key.unwrap().as_bytes(),
            by_file.as_bytes(),
            "the declared source is used; the manifest MAC decides"
        );
        assert!(both_present_warning(KeySource::Passphrase).contains(KDF_SALT_FILE));
    }

    #[test]
    fn a_fresh_palace_opened_read_only_holds_no_key_and_creates_nothing() {
        let parent = tempdir().unwrap();
        let root = parent.path().join("installation");
        for pw in [None, Some("correct horse")] {
            let m = master_key(&root, pw, Access::ReadOnly).unwrap();
            assert!(m.key.is_none() && !m.both_present);
            assert!(!root.exists(), "not even the directory");
        }
        // Premise: the same call under a writable posture does create.
        assert!(master_key(&root, None, Access::ReadWrite)
            .unwrap()
            .key
            .is_some());
        assert!(root.join(MASTER_KEY_FILE).exists());
    }

    /// A stat error is never read as "absent", which is how a key would be
    /// created over an installation that has one. Forced without `chmod` (the test
    /// container runs as root): a regular FILE where a directory must be.
    #[test]
    fn a_palace_that_cannot_be_surveyed_refuses() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(crate::VAULTS_DIR), b"not a directory").unwrap();
        let err = master_key(dir.path(), None, Access::ReadWrite)
            .err()
            .expect("an unreadable vaults/ must refuse");
        assert!(matches!(err, KeyError::Io(_)), "{err}");
        assert_eq!(files(dir.path()), (false, false));

        let file_root = dir.path().join("root-is-a-file");
        fs::write(&file_root, b"x").unwrap();
        assert!(matches!(
            master_key(&file_root, None, Access::ReadOnly),
            Err(KeyError::Io(_))
        ));
    }

    /// A key file mounted as a symlink is PRESENT even while its target is
    /// not, so it is loaded (and fails) rather than created over.
    #[cfg(unix)]
    #[test]
    fn a_dangling_key_symlink_is_never_created_over() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("secret-not-mounted-yet");
        std::os::unix::fs::symlink(&target, dir.path().join(MASTER_KEY_FILE)).unwrap();
        let err = master_key(dir.path(), None, Access::ReadWrite)
            .err()
            .expect("a dangling key link cannot load");
        assert!(matches!(err, KeyError::Io(_)), "{err}");
        assert!(!target.exists(), "the link was not followed into a create");
    }

    /// The exclusive create: an entry that appears between the survey and
    /// the write is loaded, never truncated.
    #[test]
    fn the_writer_never_replaces_an_existing_file() {
        let dir = tempdir().unwrap();
        let first = key(dir.path(), None);
        let witness = CreateWitness {
            source: KeySource::KeyFile,
        };
        let err = create_master(dir.path(), None, witness)
            .expect_err("create_new must refuse an existing file");
        assert!(
            matches!(&err, KeyError::Io(e) if e.kind() == io::ErrorKind::AlreadyExists),
            "{err}"
        );
        assert_eq!(key(dir.path(), None).as_bytes(), first.as_bytes());
        // A witness for the other source is refused before anything is written.
        let witness = CreateWitness {
            source: KeySource::Passphrase,
        };
        assert!(create_master(dir.path(), None, witness).is_err());
        assert!(!dir.path().join(KDF_SALT_FILE).exists());
    }

    /// Both readings, conditional remedies, and nothing an attacker can use.
    #[test]
    fn refusals_give_both_readings_and_never_advise_deleting_a_key() {
        let msgs = [
            KeyError::SourceMismatch {
                declared: KeySource::Passphrase,
                references: 2,
            }
            .to_string(),
            KeyError::SourceMismatch {
                declared: KeySource::KeyFile,
                references: 0,
            }
            .to_string(),
            KeyError::MaterialMissing {
                declared: KeySource::Passphrase,
                references: 1,
            }
            .to_string(),
            KeyError::MaterialMissing {
                declared: KeySource::KeyFile,
                references: 4,
            }
            .to_string(),
            both_present_warning(KeySource::KeyFile),
        ];
        for m in &msgs {
            assert!(m.contains("O204"), "{m}");
            let lower = m.to_lowercase();
            assert!(!lower.contains("unset"), "no unconditional downgrade: {m}");
            assert!(
                !lower.replace("do not delete", "").contains("delete"),
                "never advise deleting key material: {m}"
            );
        }
        // The downgrade step exists only behind its condition.
        assert!(
            msgs[0].contains("set up WITHOUT a passphrase"),
            "{}",
            msgs[0]
        );
        assert!(msgs[0].contains("If it was set up WITH one"), "{}", msgs[0]);
        assert!(msgs[0].contains("nothing was written"), "{}", msgs[0]);
        assert!(msgs[2].contains("none was created"), "{}", msgs[2]);
    }

    /// The one writer stays one (ROADMAP O204): a source count over this
    /// file, needles split so they do not match themselves.
    #[test]
    fn key_material_has_exactly_one_writer() {
        let src = include_str!("keys.rs");
        let end = src
            .find(concat!("#[cfg(test)]\nmod ", "tests"))
            .expect("premise: the test module marker");
        let body = &src[..end];
        let count = |needle: &str| body.matches(needle).count();
        assert_eq!(
            count(concat!("write_new_", "private(")),
            3,
            "definition + two calls"
        );
        assert_eq!(
            count(concat!("create_", "master(")),
            2,
            "definition + one call"
        );
        assert_eq!(
            count(concat!("pub fn create_", "master")),
            0,
            "the writer stays private"
        );
        assert_eq!(count(concat!("CreateWitness { source: ", "declared }")), 1);
        assert_eq!(
            count(concat!("File::", "create(")),
            0,
            "no truncating create"
        );
        assert_eq!(count(concat!("fs::", "write(")), 0);
    }
}
