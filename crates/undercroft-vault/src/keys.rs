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
//!
//! **A command derives a passphrase's key once** (ROADMAP O211), through a
//! [`KeyCache`] its process holds, across the opens a [`KeyHold`] spans. The
//! survey and the classification still run on every open, and the salt is
//! still read from disk on every open; only the Argon2id output is kept,
//! against a digest of the passphrase and the salt bytes that produced it,
//! because it is a pure function of exactly those two.
//!
//! **And a key file's name never holds fewer bytes than were written**
//! (ROADMAP O210). [`publish_new_secret`] writes the bytes to a temp file
//! named with a random nonce, fsyncs it, and only then gives it the final
//! name by a hard link, which fails if that name exists; a crash before the
//! link leaves no key file at all, so the next start creates a whole one. It
//! is also how `bundle keygen` and `bundle sign-keygen` write an identity
//! (ROADMAP O321).

use crate::Access;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Digest;
use sha2::Sha256;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
    /// `kdf.salt` is not exactly `SALT_LEN` bytes. The refusal names the file
    /// and its length (ROADMAP O210): a torn key file is never rewritten.
    #[error("{}", corrupt_key_file_message(.file, .len, .references))]
    CorruptKeyFile {
        /// The key file that is the wrong length.
        file: &'static str,
        /// Its length in bytes.
        len: usize,
        /// Entries under `vaults/` and `backups/` — what may refer to a key.
        references: usize,
    },
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

/// The refusal for a key file of the wrong length (ROADMAP O210). It names
/// the file and both lengths, says what leaves such a file, and — like
/// O204's refusals — never advises deleting it: whether anything refers to
/// the key is stated, and the operator decides.
fn corrupt_key_file_message(file: &str, len: &usize, references: &usize) -> String {
    let expected = if file == KDF_SALT_FILE {
        SALT_LEN
    } else {
        KEY_LEN
    };
    let refers = if *references == 0 {
        "No vault or backup here refers to a key yet.".to_string()
    } else {
        format!(
            "{references} vault or backup entr{} here refer{} to the master key: restore {file} \
             from a copy of this data directory.",
            if *references == 1 { "y" } else { "ies" },
            if *references == 1 { "s" } else { "" },
        )
    };
    format!(
        "{file} is {len} bytes where {expected} are expected, so no key can be loaded from it \
         and nothing was written. A crash while a release before 1.7.0 created it leaves a file \
         like this, and so does truncation; it is never rewritten in place. {refers} (ROADMAP \
         O210)"
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
/// one, and the one function that writes key material takes it — the
/// publisher beneath it is private too, and its only other door,
/// [`write_new_identity`], writes an identity (ROADMAP O210, O321).
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

/// The master key a process derived from its passphrase, held so the process
/// derives it ONCE (ROADMAP O211).
///
/// Argon2id is 64 MiB and three passes by design, and every manager open ran
/// it: `vault list` once for the list and once per vault it described,
/// `vault rotate` and a `serve-http` start twice. Nothing the derivation
/// produces changes between those opens — the master key is never rotated
/// (a rotation moves a vault's salt), and Argon2id is a pure function of the
/// passphrase and the salt — so the second run bought nothing.
///
/// **What is cached is the derivation, never the decision.** [`plan`] still
/// classifies the installation on every open, and `kdf.salt` is still read on
/// every open; a held key answers only when BOTH inputs equal the ones it was
/// derived from — the salt bytes, and a SHA-256 digest of the passphrase,
/// compared in constant time over fixed lengths, so the comparison says nothing
/// about the passphrase's length and the cache never keeps the passphrase
/// itself. A deleted salt is still refused, a replaced one derives again, and
/// a different passphrase never meets another passphrase's key. The key-file
/// source never reaches this: `master.key` is read on every open, as before.
///
/// **A key is kept only while a [`KeyHold`] is alive.** An open with no hold
/// derives, hands the key out and keeps nothing, so a command that opens once
/// — `serve-mcp`, `mine`, `refine` — holds the master key exactly as long as
/// its manager does, as before this cache existed. A command that opens more
/// than once takes a hold across those opens, and the last hold to drop
/// zeroizes the key. Forgetting a hold costs a derivation; it never keeps a
/// key.
///
/// One entry, because one installation has one salt; a second (passphrase,
/// salt) replaces the first. The held key is a [`SecretKey`], zeroized when it
/// is replaced, when the last hold drops, or when [`forget`](Self::forget)
/// drops it, and never written anywhere. `Debug` prints the count and nothing
/// else.
pub struct KeyCache {
    slot: Mutex<Option<Derived>>,
    runs: AtomicU64,
    holds: AtomicUsize,
}

/// One derivation: both of its inputs and its output.
struct Derived {
    passphrase_digest: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_LEN],
    key: SecretKey,
}

/// Keeps a [`KeyCache`]'s derived key across the opens made while it lives
/// (ROADMAP O211). Holds nest; the last one dropped zeroizes the key.
#[must_use = "a hold that is dropped at once keeps nothing"]
pub struct KeyHold<'a> {
    cache: &'a KeyCache,
}

impl Drop for KeyHold<'_> {
    fn drop(&mut self) {
        // The decrement comes before the slot's lock, and `derive` stores
        // only while it sees a hold under that same lock, so a key stored by
        // an open racing this drop is cleared here rather than left behind.
        if self.cache.holds.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.cache.forget();
        }
    }
}

impl KeyCache {
    /// An empty cache. `const`, so a binary can hold its one cache in a
    /// `static` — the process is the scope this cache is for.
    pub const fn new() -> Self {
        Self {
            slot: Mutex::new(None),
            runs: AtomicU64::new(0),
            holds: AtomicUsize::new(0),
        }
    }

    /// Keep the derived key across every open until the hold drops.
    pub fn hold(&self) -> KeyHold<'_> {
        self.holds.fetch_add(1, Ordering::AcqRel);
        KeyHold { cache: self }
    }

    /// How many times Argon2id has run through this cache.
    pub fn derivations(&self) -> u64 {
        self.runs.load(Ordering::Relaxed)
    }

    /// Whether a derived key is held right now.
    pub fn is_holding(&self) -> bool {
        self.slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Drop the held key (zeroized) and its inputs. The next passphrase open
    /// derives again.
    pub fn forget(&self) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// The master key for this passphrase and salt: the held one when both
    /// match, a fresh derivation otherwise, kept only while a hold is alive.
    /// The lock is held across the derivation, so two callers racing on a
    /// cold cache under one hold run Argon2id once.
    fn derive(&self, passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<SecretKey, KeyError> {
        let mut digest = Zeroizing::new([0u8; 32]);
        digest.copy_from_slice(&Sha256::digest(passphrase.as_bytes()));
        // A poisoned lock only means a holder panicked; the slot is replaced
        // whole or not at all, so what it holds is either a complete
        // derivation or nothing.
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = slot.as_ref() {
            // Both comparisons run over fixed lengths: a 16-byte salt and a
            // 32-byte digest.
            let same_salt: bool = held.salt[..].ct_eq(&salt[..]).into();
            let same_passphrase: bool = held.passphrase_digest[..].ct_eq(&digest[..]).into();
            if same_salt && same_passphrase {
                return Ok(held.key.duplicate());
            }
        }
        self.runs.fetch_add(1, Ordering::Relaxed);
        let key = derive_from_passphrase(passphrase, salt)?;
        *slot = if self.holds.load(Ordering::Acquire) > 0 {
            Some(Derived {
                passphrase_digest: digest,
                salt: *salt,
                key: key.duplicate(),
            })
        } else {
            None
        };
        Ok(key)
    }
}

impl Default for KeyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCache")
            .field("derivations", &self.derivations())
            .field("holds", &self.holds.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Resolve the installation master key: survey, classify, then load or create.
///
/// With a passphrase the key is Argon2id (64 MiB, t=3, p=1) over the
/// passphrase and the palace-level salt in `<root>/kdf.salt`, and the secret never
/// touches disk; otherwise it is the random key in `<root>/master.key`. A
/// created file is written through [`publish_new_secret`]: owner-only on Unix
/// from its open (not narrowed on Windows), and never visible under its name
/// holding fewer bytes than were written (ROADMAP O210). Argon2id runs only
/// after the classifier has accepted the installation.
///
/// Derives on every call. A process that opens more than once holds a
/// [`KeyCache`] and calls [`master_key_cached`] (ROADMAP O211).
pub fn master_key(
    root: &Path,
    passphrase: Option<&str>,
    access: Access,
) -> Result<MasterKey, KeyError> {
    master_key_cached(root, passphrase, access, &KeyCache::new())
}

/// [`master_key`], deriving a passphrase's key through `cache` (ROADMAP
/// O211). The survey, the classification and the read of the declared
/// source's file run on every call exactly as they do uncached; only
/// Argon2id is skipped, and only when a [`KeyHold`] on `cache` kept a key
/// whose passphrase and salt are the ones just declared and read.
pub fn master_key_cached(
    root: &Path,
    passphrase: Option<&str>,
    access: Access,
    cache: &KeyCache,
) -> Result<MasterKey, KeyError> {
    let declared = KeySource::declared(passphrase);
    let mut retried = false;
    loop {
        let surveyed = survey(root)?;
        match plan(declared, &surveyed, access)? {
            KeyPlan::Load { other_present } => {
                return Ok(MasterKey {
                    key: Some(load_master(root, passphrase, cache, surveyed.references)?),
                    both_present: other_present,
                })
            }
            KeyPlan::NoKey => {
                return Ok(MasterKey {
                    key: None,
                    both_present: false,
                })
            }
            KeyPlan::Create(witness) => match create_master(root, passphrase, witness, cache) {
                // A concurrent first start published the file between our
                // stat and our publish, which refuses an existing name: classify
                // again and load what it wrote, never overwrite it.
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
/// writes. The salt is read on every call, cached or not: it is half of what
/// the cache compares. `references` only words the refusal of a torn file.
fn load_master(
    root: &Path,
    passphrase: Option<&str>,
    cache: &KeyCache,
    references: usize,
) -> Result<SecretKey, KeyError> {
    match passphrase {
        Some(pw) => {
            let salt = fs::read(root.join(KDF_SALT_FILE))?;
            let salt: [u8; SALT_LEN] =
                salt.as_slice()
                    .try_into()
                    .map_err(|_| KeyError::CorruptKeyFile {
                        file: KDF_SALT_FILE,
                        len: salt.len(),
                        references,
                    })?;
            cache.derive(pw, &salt)
        }
        None => {
            let raw = fs::read(root.join(MASTER_KEY_FILE))?;
            let arr: [u8; KEY_LEN] =
                raw.as_slice()
                    .try_into()
                    .map_err(|_| KeyError::CorruptKeyFile {
                        file: MASTER_KEY_FILE,
                        len: raw.len(),
                        references,
                    })?;
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
    cache: &KeyCache,
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
            publish_new_secret(&root.join(KDF_SALT_FILE), &salt)?;
            cache.derive(pw, &salt)
        }
        None => {
            let mut key = [0u8; KEY_LEN];
            rand::thread_rng().fill_bytes(&mut key);
            publish_new_secret(&root.join(MASTER_KEY_FILE), &key)?;
            Ok(SecretKey(key))
        }
    }
}

/// Argon2id itself. Reached only through [`KeyCache::derive`], so every run is
/// counted.
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

    /// A second owned copy, itself zeroized on drop. Crate-private and never
    /// `Clone`: a copy is made only where a holder must keep one and hand one
    /// out (the [`KeyCache`]).
    pub(crate) fn duplicate(&self) -> SecretKey {
        SecretKey(self.0)
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

/// How a secret file got its final name (ROADMAP O210).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    /// A whole, fsynced temp file was hard-linked to the final name, so the
    /// name never held fewer bytes than were written.
    Linked,
    /// The filesystem has no hard links, so the final name was created
    /// exclusively and written in place — O204's writer, kept as the
    /// fallback until O412 is ruled. A crash inside that write leaves
    /// a torn file, which the next load refuses by name; a warning says so
    /// when this happens.
    InPlace,
}

/// The infix a secret's temp name carries between the final name and the
/// nonce — the manifest writer's (`lib.rs`), so one shape names both.
const SECRET_TEMP_INFIX: &str = ".tmp.";

/// Write a bundle identity NEW at `path` — the door `bundle keygen` and
/// `bundle sign-keygen` use (ROADMAP O321). It is the master key's publisher
/// (O210) without the classifier's witness, because an identity refers to
/// no installation and its path is the operator's: it refuses an existing
/// entry and nothing else, as `write_identity` never did either. The
/// installation's own key material is written by [`master_key`] alone,
/// through the private writer that takes [`plan`]'s witness (O204).
pub fn write_new_identity(path: &Path, data: &[u8]) -> io::Result<Published> {
    publish_new_secret(path, data)
}

/// Write `data` as a NEW secret file at `path`, and never anything else there
/// (ROADMAP O210, O321). Private: its doors are the witness-taking key
/// writer and [`write_new_identity`].
///
/// - **An existing entry is refused before a byte is written**, a link
///   included, dangling or not: `symlink_metadata`, then the publish below,
///   which refuses it again if it appeared since. `AlreadyExists` either way.
/// - **Owner-only from the open** on Unix (`0600`, masked by the umask, so
///   never wider), never narrowed after the bytes exist; Windows has no mode
///   to set here, as for every key file.
/// - **The name never holds fewer bytes than were written**: the bytes go to
///   `<name>.tmp.<32 hex digits>` in the same directory — created with
///   `create_new`, so a planted link at it is refused rather than followed —
///   which is fsynced and only then hard-linked to `path`. `link` fails if
///   `path` exists, so a concurrent writer's secret is never replaced and a
///   link planted there is never followed. The directory is fsynced, so the
///   name is durable before its temp twin is removed, and synced again. A
///   crash before the link leaves no file at `path`; after it, a whole one.
///   The temp name is 37 bytes longer than `path`'s, so a file name longer
///   than 218 bytes (on a 255-byte limit) is refused naming the temp.
/// - **Where the filesystem has no hard links** — and only there: the link
///   error must read as "unsupported" ([`links_unsupported`]) — it falls back
///   to O204's writer: `create_new` of `path` itself, mode at the open, the
///   bytes and an fsync, and it warns. Never a rename, which replaces an
///   existing file on Unix — a concurrent start's key, sealed under by then,
///   among them. Which writer a linkless filesystem SHOULD get is
///   O412's question; this one is what every release before 1.7.0
///   used. Its residual, stated: a crash inside the in-place write leaves a
///   torn file, which [`master_key`] refuses by name.
/// - **Any other link error refuses**, the temp kept: a full disk or an I/O
///   error on a filesystem that links never opens the torn-key window.
/// - **Once a name holds bytes, nothing here removes it**, and once the temp
///   is whole it is removed only after the secret is durable under its name
///   or the name is another writer's: a concurrent start may already have
///   loaded what a failing in-place write put there and sealed a vault under
///   it (O204's race), so a failure after that point keeps both files and
///   names both.
///
/// What a crash leaves besides: before the link, the temp file, holding
/// bytes nothing was ever sealed under; after it and before the temp name is
/// removed, a second name for the published secret, owner-only like it.
/// Nothing sweeps either (O204: never delete key material on a guess); that
/// nothing REPORTS them is O413.
fn publish_new_secret(path: &Path, data: &[u8]) -> io::Result<Published> {
    use std::io::Write;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} names no file", path.display()),
        )
    })?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if entry_present(path)? {
        return Err(already_exists(path));
    }
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut tmp_name = OsString::from(name);
    tmp_name.push(SECRET_TEMP_INFIX);
    tmp_name.push(hex::encode(nonce));
    let tmp = dir.join(tmp_name);

    let mut file = open_new_private(&tmp).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "{} was not written: creating its temp file {} failed ({e})",
                path.display(),
                tmp.display()
            ),
        )
    })?;
    #[cfg(any(test, feature = "test-fixture"))]
    {
        use crate::fixture::{secret_crash, SecretCrash};
        if let Some(crash) = secret_crash(SecretCrash::Created) {
            return Err(crash);
        }
        if let Some(crash) = secret_crash(SecretCrash::Torn) {
            file.write_all(&data[..data.len() / 2])?;
            return Err(crash);
        }
    }
    let staged = file.write_all(data).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = staged {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(any(test, feature = "test-fixture"))]
    if let Some(crash) = crate::fixture::secret_crash(crate::fixture::SecretCrash::Synced) {
        return Err(crash);
    }

    let published = match link_seam().and_then(|()| fs::hard_link(&tmp, path)) {
        Ok(()) => {
            #[cfg(any(test, feature = "test-fixture"))]
            if let Some(crash) =
                crate::fixture::secret_crash(crate::fixture::SecretCrash::Published)
            {
                return Err(crash);
            }
            Published::Linked
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // Another writer's name: these bytes were never published under
            // it nor returned, so nothing was sealed under them.
            let _ = fs::remove_file(&tmp);
            return Err(already_exists(path));
        }
        Err(link) if links_unsupported(&link) => match write_in_place(path, data) {
            Ok(()) => {
                undercroft_obs::diag_warn!(
                    "{}: this filesystem has no hard links ({link}), so the file was created \
                     in place; a crash while it was being written would have left a torn \
                     file, which the next start refuses by name (ROADMAP O210)",
                    path.display()
                );
                Published::InPlace
            }
            Err(InPlace::NameTaken) => {
                let _ = fs::remove_file(&tmp);
                return Err(already_exists(path));
            }
            Err(InPlace::NotCreated(e)) => {
                return Err(kept(
                    e,
                    format!(
                        "{} was not written: creating it in place failed",
                        path.display()
                    ),
                    &tmp,
                ))
            }
            Err(InPlace::Written(e)) => {
                return Err(kept(
                    e,
                    format!(
                        "{} was created in place and its write did not complete; it is kept, \
                         because another start may already have loaded it",
                        path.display()
                    ),
                    &tmp,
                ))
            }
        },
        Err(link) => {
            return Err(kept(
                link,
                format!(
                    "{} was not written: the hard link that publishes it failed with an error \
                     that does not mean this filesystem lacks links",
                    path.display()
                ),
                &tmp,
            ))
        }
    };
    // The name is durable BEFORE its temp twin goes, so no ordering of the
    // two directory updates on a power loss can lose both.
    sync_dir(dir).map_err(|e| {
        kept(
            e,
            format!(
                "{} was written and the directory sync after it failed",
                path.display()
            ),
            &tmp,
        )
    })?;
    if let Err(e) = fs::remove_file(&tmp) {
        undercroft_obs::diag_warn!(
            "{} was written, and its temp name {} could not be removed ({e}); it holds the \
             same secret, owner-only like it (ROADMAP O210)",
            path.display(),
            tmp.display()
        );
    }
    // Best effort: a removal this sync does not make durable leaves the temp
    // behind after a power loss, a leftover O413 names; the secret
    // is durable under its name either way.
    let _ = sync_dir(dir);
    Ok(published)
}

/// A failure after the temp file holds the whole secret: the temp is KEPT
/// and the error names it, beside the name that was being published.
fn kept(e: io::Error, what: String, tmp: &Path) -> io::Error {
    io::Error::new(
        e.kind(),
        format!(
            "{what} ({e}); the whole secret is kept at {}, which nothing removes (ROADMAP O210)",
            tmp.display()
        ),
    )
}

/// Whether a hard link failed because the filesystem has none (ROADMAP O210)
/// — the only failure the in-place fallback answers. Measured on Linux 6.6:
/// `EPERM` on vfat, the code the kernel's VFS returns for every filesystem
/// without a link operation (its exFAT driver among them), and `ENOSYS` on a
/// FUSE exFAT; an SMB3 mount of Samba links. `EOPNOTSUPP` is what BSD and
/// macOS document for a filesystem without links. Windows'
/// `ERROR_INVALID_FUNCTION` and `ERROR_NOT_SUPPORTED` are unmeasured. `EPERM`
/// is read as unsupported because the source is a regular file this process
/// created and owns a moment before, in the same directory.
fn links_unsupported(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::Unsupported
        || e.raw_os_error()
            .is_some_and(|code| LINKS_UNSUPPORTED.contains(&code))
}

/// `EPERM`, `ENOSYS`, `EOPNOTSUPP`.
#[cfg(any(target_os = "linux", target_os = "android"))]
const LINKS_UNSUPPORTED: &[i32] = &[1, 38, 95];
/// `EPERM`, `ENOTSUP`, `ENOSYS`, `EOPNOTSUPP`.
#[cfg(any(target_os = "macos", target_os = "ios"))]
const LINKS_UNSUPPORTED: &[i32] = &[1, 45, 78, 102];
/// `EPERM`, `EOPNOTSUPP`, `ENOSYS`.
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const LINKS_UNSUPPORTED: &[i32] = &[1, 45, 78];
/// `ERROR_INVALID_FUNCTION`, `ERROR_NOT_SUPPORTED`.
#[cfg(windows)]
const LINKS_UNSUPPORTED: &[i32] = &[1, 50];
/// Nothing classified: every link error refuses.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    windows
)))]
const LINKS_UNSUPPORTED: &[i32] = &[];

/// How the in-place fallback failed — which decides what is kept.
enum InPlace {
    /// The name exists: another writer's.
    NameTaken,
    /// Nothing was created at the name.
    NotCreated(io::Error),
    /// The name was created and its write or fsync failed: it may hold bytes
    /// a concurrent start has loaded, so it stays.
    Written(io::Error),
}

/// The fallback publish (ROADMAP O210): O204's exclusive in-place writer. It
/// removes nothing — O204's writer never did, and a name it created may
/// already have been loaded.
fn write_in_place(path: &Path, data: &[u8]) -> Result<(), InPlace> {
    use std::io::Write;
    let mut file = open_new_private(path).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => InPlace::NameTaken,
        _ => InPlace::NotCreated(e),
    })?;
    #[cfg(any(test, feature = "test-fixture"))]
    if let Some(crash) = crate::fixture::secret_crash(crate::fixture::SecretCrash::InPlaceTorn) {
        file.write_all(&data[..data.len() / 2])
            .map_err(InPlace::Written)?;
        return Err(InPlace::Written(crash));
    }
    file.write_all(data)
        .and_then(|()| in_place_sync_seam())
        .and_then(|()| file.sync_all())
        .map_err(InPlace::Written)
}

/// The fixture seams: before the hard link, an armed `SecretLink` fails it as
/// a filesystem without hard links does and `SecretLinkIo` as an ordinary
/// I/O error; before the in-place fsync, `SecretInPlaceSync` fails that
/// fsync. Nothing in production.
#[cfg(any(test, feature = "test-fixture"))]
fn link_seam() -> io::Result<()> {
    use crate::fixture::{fire, Fault};
    fire(Fault::SecretLink)
        .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e.to_string()))?;
    fire(Fault::SecretLinkIo)
}

#[cfg(not(any(test, feature = "test-fixture")))]
fn link_seam() -> io::Result<()> {
    Ok(())
}

#[cfg(any(test, feature = "test-fixture"))]
fn in_place_sync_seam() -> io::Result<()> {
    crate::fixture::fire(crate::fixture::Fault::SecretInPlaceSync)
}

#[cfg(not(any(test, feature = "test-fixture")))]
fn in_place_sync_seam() -> io::Result<()> {
    Ok(())
}

/// `create_new`, owner-only from the open on Unix.
fn open_new_private(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn already_exists(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "{} already exists (a link counts, followed or not); nothing was written",
            path.display()
        ),
    )
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
        let err = create_master(dir.path(), None, witness, &KeyCache::new())
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
        assert!(create_master(dir.path(), None, witness, &KeyCache::new()).is_err());
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
        // ROADMAP O210: a torn key file is refused by name, the same way.
        for (file, len, references) in [(MASTER_KEY_FILE, 0, 0), (KDF_SALT_FILE, 9, 3)] {
            let m = KeyError::CorruptKeyFile {
                file,
                len,
                references,
            }
            .to_string();
            assert!(m.contains("O210") && m.contains(file), "{m}");
            assert!(m.contains("nothing was written"), "{m}");
            assert!(
                !m.to_lowercase().contains("delete") && !m.contains("remove"),
                "never advise deleting key material: {m}"
            );
        }
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
        // ROADMAP O210: the one publisher, PRIVATE, called by the key
        // writer's two arms and the identity door (whose one caller, the
        // CLI's `write_identity`, is gated there).
        assert_eq!(
            count(concat!("publish_new_", "secret(")),
            4,
            "definition + two key-writer calls + the identity door"
        );
        assert_eq!(
            count(concat!("pub fn publish_new_", "secret")),
            0,
            "the publisher takes no witness, so it stays private"
        );
        assert_eq!(
            count(concat!("write_new_", "identity(")),
            1,
            "the identity door: its definition, and no caller in this file"
        );
        // A name the fallback created may already have been loaded, so it
        // removes nothing (the review of O210's first build).
        let in_place = &body[body
            .find(concat!("fn write_", "in_place("))
            .expect("premise: the fallback")..];
        let in_place = &in_place[..in_place.find("\n}\n").expect("premise: it closes")];
        assert!(
            !in_place.contains(concat!("remove_", "file(")),
            "the fallback removes nothing"
        );
        assert_eq!(count(concat!("write_new_", "private(")), 0, "retired");
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
        // ROADMAP O211: Argon2id has one caller, the cache, so every run is
        // counted and none can go around the held key.
        assert_eq!(
            count(concat!("derive_from_", "passphrase(")),
            2,
            "definition + the cache's one call"
        );
        assert_eq!(
            count(concat!("cache.", "derive(")),
            2,
            "the load and the create, both through the cache"
        );
        // Every file it creates is `create_new` with the mode at the open:
        // the temp, and the in-place fallback's final name.
        assert_eq!(
            count(concat!("open_new_", "private(")),
            3,
            "definition + the temp + the fallback"
        );
        assert_eq!(count(concat!(".create_", "new(true)")), 1, "one open");
        assert_eq!(count(concat!("fs::hard_", "link(")), 1, "one publish");
        assert_eq!(
            count(concat!("fs::", "rename(")),
            0,
            "a rename replaces an existing secret"
        );
        assert_eq!(
            count(concat!("set_", "permissions(")),
            0,
            "no mode narrowed after the bytes exist"
        );
    }

    /// The temp files a publish of `file` left in `dir`: exactly the
    /// `<file>.tmp.<32 lowercase hex>` shape.
    fn temps_of(dir: &Path, file: &str) -> Vec<std::path::PathBuf> {
        let prefix = format!("{file}{SECRET_TEMP_INFIX}");
        let mut found: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .and_then(|n| n.strip_prefix(&prefix))
                    .is_some_and(|nonce| {
                        nonce.len() == 32
                            && nonce
                                .bytes()
                                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                    })
            })
            .map(|e| e.path())
            .collect();
        found.sort();
        found
    }

    /// **ROADMAP O210's gate.** A process killed at each step of a key-file
    /// write, then started again: the next start loads a WHOLE key, and a
    /// short file is never published under the key's name. Each step is
    /// asserted REACHED — the temp file holds exactly the bytes that step
    /// leaves — so the crash cannot have fired somewhere else. The writer
    /// before O210 created `master.key` itself, so a crash after its create
    /// left a short `master.key` and every later start refused
    /// `CorruptKeyFile`.
    #[test]
    fn o210_a_crash_inside_a_key_write_never_publishes_a_short_key() {
        use crate::fixture::{crash_secret_write_at, SecretCrash};
        for pw in [None, Some("correct horse")] {
            let file = KeySource::declared(pw).file();
            let whole = if pw.is_some() { SALT_LEN } else { KEY_LEN };
            for (step, temp_len) in [
                (SecretCrash::Created, 0),
                (SecretCrash::Torn, whole / 2),
                (SecretCrash::Synced, whole),
                (SecretCrash::Published, whole),
            ] {
                let dir = tempdir().unwrap();
                let at = dir.path().join(file);
                crash_secret_write_at(step);
                let err = master_key(dir.path(), pw, Access::ReadWrite)
                    .err()
                    .expect("the armed crash fires");
                assert!(err.to_string().contains(&format!("{step:?}")), "{err}");
                // The property: the key's NAME never holds a short file —
                // absent before the link, whole after it.
                match fs::read(&at) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Ok(bytes) => assert_eq!(bytes.len(), whole, "{file} {step:?}: short"),
                    Err(e) => panic!("{e}"),
                }
                let temps = temps_of(dir.path(), file);
                assert_eq!(temps.len(), 1, "{file} {step:?}: one temp file");
                let temp = fs::read(&temps[0]).unwrap();
                assert_eq!(temp.len(), temp_len, "{file} {step:?}: REACHED");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(&temps[0]).unwrap().permissions().mode();
                    assert_eq!(mode & 0o777, 0o600, "{file} {step:?}: owner-only");
                }
                if step == SecretCrash::Published {
                    assert_eq!(fs::read(&at).unwrap(), temp, "the link published it");
                } else {
                    assert!(!entry_present(&at).unwrap(), "{file} {step:?}: unpublished");
                }
                // The next start: a whole file under the name, and the key
                // it holds is the key the start returned — after a crash past
                // the link, the very one that was published.
                let next = key(dir.path(), pw);
                let published = fs::read(&at).unwrap();
                assert_eq!(published.len(), whole, "{file} {step:?}: a whole file");
                let expected = match pw {
                    Some(pw) => derive_from_passphrase(pw, &published).unwrap(),
                    None => SecretKey(published.as_slice().try_into().unwrap()),
                };
                assert_eq!(next.as_bytes(), expected.as_bytes(), "{file} {step:?}");
                if step == SecretCrash::Published {
                    assert_eq!(published, temp, "the published key was kept");
                }
                // The crash's temp file is left, never swept: stated.
                assert_eq!(temps_of(dir.path(), file), temps, "{file} {step:?}");
            }
        }
    }

    /// The second arm of O210's gate: a short key file already there — left
    /// by a crash under an earlier release, or by the fallback below — is
    /// refused NAMING the file and its length, on both postures, and never
    /// rewritten.
    #[test]
    fn o210_a_short_key_file_is_refused_by_name_and_never_rewritten() {
        for (pw, file, whole) in [
            (None, MASTER_KEY_FILE, KEY_LEN),
            (Some("correct horse"), KDF_SALT_FILE, SALT_LEN),
        ] {
            for refs in [0, 1] {
                let dir = tempdir().unwrap();
                if refs == 1 {
                    with_a_vault(dir.path());
                }
                let short = vec![7u8; whole / 2];
                fs::write(dir.path().join(file), &short).unwrap();
                for access in [Access::ReadWrite, Access::ReadOnly] {
                    let err = master_key(dir.path(), pw, access)
                        .err()
                        .expect("a short key file refuses");
                    match &err {
                        KeyError::CorruptKeyFile {
                            file: f,
                            len,
                            references,
                        } => assert_eq!((*f, *len, *references), (file, whole / 2, refs)),
                        other => panic!("{other}"),
                    }
                    let m = err.to_string();
                    assert!(
                        m.contains(&format!("{file} is {} bytes where {whole}", whole / 2)),
                        "{m}"
                    );
                    assert_eq!(fs::read(dir.path().join(file)).unwrap(), short);
                    assert!(temps_of(dir.path(), file).is_empty(), "nothing was written");
                }
            }
        }
    }

    /// **The fallback** (ROADMAP O210): a filesystem that refuses the hard
    /// link gets O204's exclusive in-place writer, never a rename — still
    /// owner-only from the open, still refusing an existing name, the temp
    /// removed — and its residual, a crash inside the in-place write, leaves a
    /// torn key that the next start refuses by name.
    #[test]
    fn o210_without_hard_links_the_writer_falls_back_to_an_exclusive_in_place_write() {
        use crate::fixture::{crash_secret_write_at, fail_next, fail_times, Fault, SecretCrash};
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");
        fail_next(Fault::SecretLink);
        assert_eq!(
            publish_new_secret(&path, b"0123456789abcdef").unwrap(),
            Published::InPlace
        );
        assert_eq!(
            crate::fixture::armed(),
            None,
            "REACHED: the link was refused"
        );
        assert_eq!(fs::read(&path).unwrap(), b"0123456789abcdef");
        assert!(temps_of(dir.path(), "identity.key").is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Premise: without the fault the same call links.
        let linked = dir.path().join("linked.key");
        assert_eq!(
            publish_new_secret(&linked, b"x").unwrap(),
            Published::Linked
        );
        // Still exclusive: an existing name is refused and kept, the fault
        // never reached because the refusal comes first.
        fail_next(Fault::SecretLink);
        let err = publish_new_secret(&path, b"replacement").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert_eq!(fs::read(&path).unwrap(), b"0123456789abcdef");
        fail_times(Fault::SecretLink, 0);

        // The residual, through the key writer: torn in place, refused next.
        let root = tempdir().unwrap();
        fail_next(Fault::SecretLink);
        crash_secret_write_at(SecretCrash::InPlaceTorn);
        assert!(master_key(root.path(), None, Access::ReadWrite).is_err());
        assert_eq!(
            fs::metadata(root.path().join(MASTER_KEY_FILE))
                .unwrap()
                .len() as usize,
            KEY_LEN / 2,
            "REACHED: the in-place write was torn"
        );
        let err = master_key(root.path(), None, Access::ReadWrite)
            .err()
            .expect("the torn key refuses");
        assert!(
            matches!(
                err,
                KeyError::CorruptKeyFile {
                    file: MASTER_KEY_FILE,
                    len: 16,
                    references: 0
                }
            ),
            "{err}"
        );
    }

    /// **A failed in-place write keeps BOTH files** (the review of O210's
    /// first build). Without hard links the name is visible from its
    /// `create_new`, so a concurrent first start can load all 32 bytes and
    /// seal a vault while the fsync is still to come. The first build removed
    /// the name when that fsync failed and the caller then removed the
    /// fsynced temp, leaving no copy of a key a vault may be sealed under —
    /// every later start `MaterialMissing`. Now both stay and the error names
    /// both, and the next start loads the key the name holds.
    #[test]
    fn o210_a_failed_in_place_write_keeps_the_name_and_the_temp() {
        use crate::fixture::{fail_in_turn, Fault};
        let root = tempdir().unwrap();
        // The link fails as on vfat, then the in-place fsync fails.
        fail_in_turn(Fault::SecretLink, Fault::SecretInPlaceSync);
        let err = master_key(root.path(), None, Access::ReadWrite)
            .err()
            .expect("the in-place fsync fails");
        assert_eq!(crate::fixture::armed(), None, "REACHED: both faults fired");
        let at = root.path().join(MASTER_KEY_FILE);
        let named = fs::read(&at).expect("the name the fallback created is kept");
        assert_eq!(
            named.len(),
            KEY_LEN,
            "its whole write landed before the fsync"
        );
        let temps = temps_of(root.path(), MASTER_KEY_FILE);
        assert_eq!(temps.len(), 1, "the fsynced temp is kept");
        assert_eq!(fs::read(&temps[0]).unwrap(), named, "the same secret");
        let m = err.to_string();
        assert!(
            m.contains(&at.display().to_string()) && m.contains(&temps[0].display().to_string()),
            "the error names both: {m}"
        );
        // A start that came in the window, or after: the key under the name.
        assert_eq!(
            key(root.path(), None).as_bytes().as_slice(),
            named.as_slice()
        );
    }

    /// **The fallback answers only a filesystem without links** (the review
    /// of O210's first build): any other link error — a full disk, an I/O
    /// error, a vanished temp — refuses, nothing is written at the name, and
    /// the whole temp is kept and named. The first build fell back on every
    /// error but "exists", opening the torn-key window on filesystems that
    /// link. The next start, with the fault gone, links a whole key.
    #[test]
    fn o210_a_link_error_that_is_not_unsupported_refuses_and_keeps_the_temp() {
        use crate::fixture::{fail_next, Fault};
        let root = tempdir().unwrap();
        fail_next(Fault::SecretLinkIo);
        let err = master_key(root.path(), None, Access::ReadWrite)
            .err()
            .expect("an ordinary link error refuses");
        assert_eq!(crate::fixture::armed(), None, "REACHED: the link failed");
        assert!(
            !entry_present(&root.path().join(MASTER_KEY_FILE)).unwrap(),
            "nothing was written at the name: {err}"
        );
        let temps = temps_of(root.path(), MASTER_KEY_FILE);
        assert_eq!(temps.len(), 1, "the temp is kept");
        assert_eq!(fs::read(&temps[0]).unwrap().len(), KEY_LEN);
        assert!(
            err.to_string().contains(&temps[0].display().to_string()),
            "{err}"
        );
        let next = key(root.path(), None);
        assert_eq!(
            fs::read(root.path().join(MASTER_KEY_FILE)).unwrap(),
            next.as_bytes()
        );
    }

    /// Which link errors read as "this filesystem has no hard links": the
    /// codes measured (EPERM on vfat, ENOSYS on a FUSE exFAT) and the ones
    /// documented, and never an ordinary I/O error. On Linux the table's
    /// numbers are checked against the platform's own names for them.
    #[test]
    fn o210_only_an_unsupported_link_takes_the_fallback() {
        let raw = io::Error::from_raw_os_error;
        assert!(links_unsupported(&io::Error::new(
            io::ErrorKind::Unsupported,
            "x"
        )));
        for code in LINKS_UNSUPPORTED {
            assert!(links_unsupported(&raw(*code)), "{code}");
        }
        assert!(!links_unsupported(&io::Error::other("x")));
        assert!(!links_unsupported(&io::Error::new(
            io::ErrorKind::AlreadyExists,
            "x"
        )));
        #[cfg(target_os = "linux")]
        {
            for (code, name) in [
                (1, "Operation not permitted"),
                (38, "Function not implemented"),
                (95, "Operation not supported"),
            ] {
                assert!(
                    raw(code).to_string().contains(name),
                    "{code}: {}",
                    raw(code)
                );
            }
            // ENOENT, EIO, EACCES, ENOSPC, EROFS, EXDEV, EMLINK refuse.
            for code in [2, 5, 13, 28, 30, 18, 31] {
                assert!(!links_unsupported(&raw(code)), "{code}: {}", raw(code));
            }
        }
    }

    /// The temp name is 37 bytes longer than the target's, so on a 255-byte
    /// name limit a target name of 218 bytes publishes and one of 219 is
    /// refused, naming the temp it could not create and writing nothing.
    #[cfg(unix)]
    #[test]
    fn o210_a_name_too_long_for_its_temp_is_refused_naming_the_temp() {
        let dir = tempdir().unwrap();
        let fits = dir.path().join("k".repeat(218));
        assert_eq!(write_new_identity(&fits, b"x").unwrap(), Published::Linked);
        let long = dir.path().join("k".repeat(219));
        let err = write_new_identity(&long, b"x").unwrap_err();
        let m = err.to_string();
        assert!(m.contains("temp file") && m.contains(".tmp."), "{m}");
        assert!(!entry_present(&long).unwrap());
    }

    /// **ROADMAP O321, at the publisher.** A link at the name — dangling,
    /// or to a file that exists — is refused before a byte is written: the
    /// link's target is neither created nor changed, and no temp is left.
    #[cfg(unix)]
    #[test]
    fn o321_a_link_at_the_name_is_refused_and_never_followed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bundle.key");
        let target = dir.path().join("where-the-link-points");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let err = publish_new_secret(&path, b"secret").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert!(!target.exists(), "nothing was written through the link");
        fs::write(&target, b"someone else's").unwrap();
        let err = publish_new_secret(&path, b"secret").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert_eq!(fs::read(&target).unwrap(), b"someone else's");
        assert!(temps_of(dir.path(), "bundle.key").is_empty());
        // A link appearing after the check is refused by the link itself:
        // `hard_link` onto an existing name fails rather than replacing it.
        let late = dir.path().join("late.key");
        let tmp = dir.path().join("late.key.source");
        fs::write(&tmp, b"x").unwrap();
        std::os::unix::fs::symlink(&target, &late).unwrap();
        assert_eq!(
            fs::hard_link(&tmp, &late).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&target).unwrap(), b"someone else's");
    }

    /// Two first starts racing on a fresh installation get ONE key: the
    /// publish that loses the link re-classifies and loads the winner's.
    #[test]
    fn o210_racing_first_starts_hold_one_key() {
        for round in 0..20 {
            let dir = tempdir().unwrap();
            let root = dir.path().to_path_buf();
            let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
            let keys: Vec<[u8; KEY_LEN]> = (0..2)
                .map(|_| {
                    let (root, gate) = (root.clone(), gate.clone());
                    std::thread::spawn(move || {
                        gate.wait();
                        *key(&root, None).as_bytes()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect();
            assert_eq!(keys[0], keys[1], "round {round}");
            assert_eq!(fs::read(root.join(MASTER_KEY_FILE)).unwrap(), keys[0]);
            assert!(temps_of(&root, MASTER_KEY_FILE).is_empty(), "round {round}");
        }
    }

    // ---- ROADMAP O211: one derivation per process ---------------------------

    fn cached(root: &Path, pw: Option<&str>, access: Access, cache: &KeyCache) -> SecretKey {
        master_key_cached(root, pw, access, cache)
            .unwrap()
            .key
            .expect("an installation with key material holds a key")
    }

    /// The gate's shape: one cache, every open a command makes. `vault list`
    /// over three vaults opened the manager four times and `serve-http` twice;
    /// each open now classifies and reads the salt, and derives nothing after
    /// the first. The held key is the key a fresh derivation gives.
    #[test]
    fn a_cache_derives_a_passphrase_key_once_across_every_open() {
        let dir = tempdir().unwrap();
        let cache = KeyCache::new();
        let _held = cache.hold();
        // The create derives through the cache too: `init` then reopens.
        let created = cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache);
        assert_eq!(cache.derivations(), 1);
        with_a_vault(dir.path());
        for access in [
            Access::ReadWrite,
            Access::ReadOnly,
            Access::ReadWrite,
            Access::ReadWrite,
        ] {
            let k = cached(dir.path(), Some("correct horse"), access, &cache);
            assert_eq!(k.as_bytes(), created.as_bytes());
        }
        assert_eq!(cache.derivations(), 1, "one Argon2id run for five opens");
        // Premise: the uncached door derives every time and agrees.
        assert_eq!(
            key(dir.path(), Some("correct horse")).as_bytes(),
            created.as_bytes()
        );
    }

    /// The cache is keyed on BOTH inputs Argon2id takes. A held key never
    /// answers for another passphrase — a wrong one still derives its own
    /// wrong key, which the manifest MAC refuses — nor for a salt that changed
    /// on disk under it.
    #[test]
    fn a_held_key_never_answers_for_another_passphrase_or_salt() {
        let dir = tempdir().unwrap();
        let cache = KeyCache::new();
        let _held = cache.hold();
        let right = cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache);
        with_a_vault(dir.path());
        for (pw, runs) in [
            ("wrong staple", 2),
            ("correct hors", 3),
            ("correct horse ", 4),
        ] {
            let k = cached(dir.path(), Some(pw), Access::ReadWrite, &cache);
            assert_ne!(k.as_bytes(), right.as_bytes(), "{pw:?} met the held key");
            assert_eq!(cache.derivations(), runs, "{pw:?} derived its own");
        }
        // One entry: the right passphrase derives again, to the same key.
        let again = cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache);
        assert_eq!(again.as_bytes(), right.as_bytes());
        assert_eq!(cache.derivations(), 5);
        // A salt replaced on disk is a different input, so a different key.
        fs::remove_file(dir.path().join(KDF_SALT_FILE)).unwrap();
        let mut other = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join(KDF_SALT_FILE))
            .unwrap();
        std::io::Write::write_all(&mut other, &[0x5a; SALT_LEN]).unwrap();
        drop(other);
        let moved = cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache);
        assert_ne!(moved.as_bytes(), right.as_bytes());
        assert_eq!(cache.derivations(), 6);
    }

    /// **Only the derivation is cached, never the decision** (ROADMAP O204's
    /// classifier, under O211). With a key held, every open still surveys and
    /// classifies: a deleted salt is refused, a planted key file beside a
    /// missing salt is refused, and nothing is written — the held key is
    /// never served in place of the files the installation holds.
    #[test]
    fn the_classification_runs_on_every_open_while_a_key_is_held() {
        let dir = tempdir().unwrap();
        let cache = KeyCache::new();
        let _hold = cache.hold();
        let held = cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache);
        with_a_vault(dir.path());
        let salt = fs::read(dir.path().join(KDF_SALT_FILE)).unwrap();
        fs::remove_file(dir.path().join(KDF_SALT_FILE)).unwrap();
        for access in [Access::ReadWrite, Access::ReadOnly] {
            let err = master_key_cached(dir.path(), Some("correct horse"), access, &cache)
                .err()
                .expect("a deleted salt refuses with a key held");
            assert!(matches!(err, KeyError::MaterialMissing { .. }), "{err}");
            assert_eq!(files(dir.path()), (false, false), "nothing created");
        }
        // A key file planted where the salt was: the other source's file.
        let mut planted = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join(MASTER_KEY_FILE))
            .unwrap();
        std::io::Write::write_all(&mut planted, &[7u8; KEY_LEN]).unwrap();
        drop(planted);
        let err = master_key_cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache)
            .err()
            .expect("a contradicting installation refuses with a key held");
        assert!(matches!(err, KeyError::SourceMismatch { .. }), "{err}");
        assert_eq!(files(dir.path()), (true, false), "no salt written");
        // The salt put back beside the planted file: loaded, with the
        // both-present flag the classifier raises, from the held key.
        let mut back = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join(KDF_SALT_FILE))
            .unwrap();
        std::io::Write::write_all(&mut back, &salt).unwrap();
        drop(back);
        let m = master_key_cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache)
            .unwrap();
        assert!(m.both_present, "the classifier still ran");
        assert_eq!(m.key.unwrap().as_bytes(), held.as_bytes());
        assert_eq!(cache.derivations(), 1, "refusals derive nothing");
        // A corrupt salt is refused before the cache is asked.
        fs::remove_file(dir.path().join(KDF_SALT_FILE)).unwrap();
        let mut short = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join(KDF_SALT_FILE))
            .unwrap();
        std::io::Write::write_all(&mut short, &salt[..SALT_LEN - 1]).unwrap();
        drop(short);
        assert!(matches!(
            master_key_cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache),
            Err(KeyError::CorruptKeyFile { .. })
        ));
    }

    /// The key-file source never reaches the cache: `master.key` is read on
    /// every open, so a replaced file is what the next open loads.
    #[test]
    fn the_key_file_source_never_reaches_the_cache() {
        let dir = tempdir().unwrap();
        let cache = KeyCache::new();
        let _held = cache.hold();
        let first = cached(dir.path(), None, Access::ReadWrite, &cache);
        let _ = cached(dir.path(), None, Access::ReadOnly, &cache);
        assert_eq!(cache.derivations(), 0);
        fs::remove_file(dir.path().join(MASTER_KEY_FILE)).unwrap();
        let mut replaced = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join(MASTER_KEY_FILE))
            .unwrap();
        std::io::Write::write_all(&mut replaced, &[3u8; KEY_LEN]).unwrap();
        drop(replaced);
        let now = cached(dir.path(), None, Access::ReadWrite, &cache);
        assert_ne!(now.as_bytes(), first.as_bytes());
        assert_eq!(now.as_bytes(), &[3u8; KEY_LEN]);
        assert_eq!(cache.derivations(), 0);
        assert!(!cache.is_holding());
    }

    /// **A key is kept only while a hold is alive** (the independent review of
    /// O211's first build: a `serve-mcp`, `mine` or `refine` process kept the
    /// master key and a copy of the passphrase in the process cache for its
    /// whole life, where before the key went with the manager after its one
    /// open). An open with no hold keeps nothing; holds nest, and the last one
    /// dropped zeroizes the key.
    #[test]
    fn a_cache_keeps_nothing_outside_a_hold() {
        let dir = tempdir().unwrap();
        let cache = KeyCache::new();
        let k = cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache);
        assert!(!cache.is_holding(), "a one-open command keeps nothing");
        let again = cached(dir.path(), Some("correct horse"), Access::ReadOnly, &cache);
        assert_eq!(again.as_bytes(), k.as_bytes());
        assert_eq!(cache.derivations(), 2, "nothing was held to reuse");
        assert!(!cache.is_holding());

        let outer = cache.hold();
        let _ = cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache);
        assert!(cache.is_holding());
        {
            let _inner = cache.hold();
            let _ = cached(dir.path(), Some("correct horse"), Access::ReadOnly, &cache);
        }
        assert!(
            cache.is_holding(),
            "an inner hold leaves the outer one's key"
        );
        let _ = cached(dir.path(), Some("correct horse"), Access::ReadOnly, &cache);
        assert_eq!(cache.derivations(), 3, "one run for the three held opens");
        drop(outer);
        assert!(!cache.is_holding(), "the last hold zeroizes the key");
        let _ = cached(dir.path(), Some("correct horse"), Access::ReadOnly, &cache);
        assert_eq!(cache.derivations(), 4);
        assert!(!cache.is_holding());
    }

    /// `forget` drops the held key, so the next open derives again; `Debug`
    /// shows the counts and nothing else.
    #[test]
    fn a_forgotten_key_is_derived_again_and_debug_shows_only_the_count() {
        let dir = tempdir().unwrap();
        let cache = KeyCache::new();
        let _held = cache.hold();
        let k = cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache);
        let shown = format!("{cache:?}");
        assert!(shown.contains("derivations: 1"), "{shown}");
        assert!(shown.contains("holds: 1"), "{shown}");
        assert!(!shown.contains("correct horse"), "{shown}");
        assert!(!shown.contains(&hex::encode(k.as_bytes())), "{shown}");
        cache.forget();
        let again = cached(dir.path(), Some("correct horse"), Access::ReadWrite, &cache);
        assert_eq!(again.as_bytes(), k.as_bytes());
        assert_eq!(cache.derivations(), 2);
    }

    /// The lock is held across the derivation: opens racing on a cold cache
    /// run Argon2id once between them.
    #[test]
    fn racing_opens_on_a_cold_cache_derive_once() {
        let dir = tempdir().unwrap();
        let _ = key(dir.path(), Some("correct horse"));
        with_a_vault(dir.path());
        let cache = KeyCache::new();
        let _held = cache.hold();
        let keys: Vec<[u8; KEY_LEN]> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    s.spawn(|| {
                        *cached(dir.path(), Some("correct horse"), Access::ReadOnly, &cache)
                            .as_bytes()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(keys.windows(2).all(|w| w[0] == w[1]));
        assert_eq!(cache.derivations(), 1);
    }
}
