//! The filesystem side of `backup restore` (ROADMAP O268).
//!
//! A restore used to remove `vaults/<id>` and then copy an archive in, knowing
//! nothing about the archive but that it held a `vault.json` — whose id it had
//! not verified. Measured on `main` `4d0a658`: a manifest ahead of its rows, a
//! truncated database, another installation's archive and one flipped byte each
//! restored at exit 0 over a working vault that then refused to open.
//!
//! Now the archive is COPIED into a stage and proven there — unlocked, opened,
//! verified and checked by the store — before the live vault is touched, and
//! only then swapped in by two renames. This module owns everything on the
//! filesystem: where the stage lives, what is copied into it, and the swap.
//!
//! **Where**: one container directly under `vaults/`, [`RESTORE_ROOT`], whose
//! name is longer than any vault id may be — `validate_name` trims and then
//! refuses anything over 128 bytes — so no vault can ever be named it, and it
//! holds no `vault.json` of its own, so nothing that lists vaults sees it. It is
//! always on the live vault's filesystem, which is what lets a rename swap them.
//! Inside it: `stage-<32 hex>` directories (a copy of an archive, swept once an
//! hour old) and `aside-<sha256 of the id>` directories (the vault a restore was
//! replacing, NEVER swept and never removed on a failure path).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{
    write_manifest_file, Manifest, VaultError, DB_FILE, LEGACY_DB_FILE, MANIFEST_FILE,
    STAGING_FILE, VAULTS_DIR,
};

/// The directory under `vaults/` a restore stages in and sets a replaced vault
/// aside in. 129 bytes: one more than `validate_name` allows a name to measure
/// after trimming, and nothing to trim, so no vault id can equal it.
pub const RESTORE_ROOT: &str = ".undercroft-restore-area--a-name-longer-than-any-vault-id-may-be--so-that-no-vault-can-ever-be-given-it--see-ROADMAP-O268-restore";

/// A stage older than this belongs to a restore that crashed, and the next
/// restore sweeps it. A younger one may be another restore in progress.
pub const STALE_STAGE: Duration = Duration::from_secs(60 * 60);

const STAGE_PREFIX: &str = "stage-";
const ASIDE_PREFIX: &str = "aside-";

/// Every file besides the manifest a restore copies out of an archive: either
/// database name, each one's `-wal` — a 1.6.1 archive copied beside a writer can
/// hold committed frames only there — and a staged rotation manifest, which the
/// store promotes only when the database's own keycheck proves the rotation
/// committed. Never a `-shm` (rebuilt from the `-wal`) or a temp manifest.
const COPIED: [&str; 5] = [
    DB_FILE,
    LEGACY_DB_FILE,
    "vault.db-wal",
    "palace.db-wal",
    STAGING_FILE,
];

/// An archive under `backups/`, read once: its directory, the vault id its own
/// manifest names, the manifest's exact bytes, and what it holds.
///
/// The id is NOT verified here — nothing can be without the key, which the
/// manager holds. It is verified when the stage is unlocked, and the manifest's
/// MAC is keyed by that very id, so an archive planted to name another vault
/// fails there, before anything is removed.
#[derive(Debug)]
pub struct Archive {
    dir: PathBuf,
    id: String,
    manifest: Vec<u8>,
    salt: String,
    copied: Vec<String>,
    irregular: Vec<String>,
    skipped: Vec<String>,
}

impl Archive {
    /// Read the archive at `dir`: its manifest once, and every entry by
    /// `symlink_metadata`, never following a link.
    pub fn read(dir: &Path) -> Result<Archive, VaultError> {
        match fs::symlink_metadata(dir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(VaultError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "backup {} is not a directory (a link is never followed); nothing \
                         was restored",
                        dir.display()
                    ),
                )))
            }
            Err(e) => return Err(e.into()),
        }
        let mut copied = Vec::new();
        let mut irregular = Vec::new();
        let mut skipped = Vec::new();
        let mut manifest_regular = false;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let regular = fs::symlink_metadata(entry.path())?.is_file();
            if name == MANIFEST_FILE {
                manifest_regular = regular;
            } else if COPIED.contains(&name.as_str()) {
                if regular {
                    copied.push(name);
                } else {
                    irregular.push(name);
                }
            } else {
                skipped.push(name);
            }
        }
        if !manifest_regular {
            return Err(VaultError::CorruptManifest(format!(
                "the backup at {} holds no {MANIFEST_FILE} that is a regular file",
                dir.display()
            )));
        }
        copied.sort();
        irregular.sort();
        skipped.sort();
        let manifest = fs::read(dir.join(MANIFEST_FILE))?;
        let parsed = Manifest::parse(&manifest)?;
        undercroft_core::validate_name(&parsed.id, "vault")?;
        Ok(Archive {
            dir: dir.to_path_buf(),
            id: parsed.id,
            salt: parsed.salt_hex,
            manifest,
            copied,
            irregular,
            skipped,
        })
    }

    /// The vault id the archive's own manifest names (unverified until the
    /// stage is unlocked).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The archive's directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Entries a restore copies that are not regular files — a link or a
    /// directory under a database's or a manifest's name. The store refuses
    /// such an archive as an integrity finding: it is a property of the
    /// archive's bytes, which no retry changes.
    pub fn irregular(&self) -> &[String] {
        &self.irregular
    }

    /// Entries a restore does not copy, named on its report.
    pub fn skipped(&self) -> &[String] {
        &self.skipped
    }

    /// Whether the vault now at `vaults/<id>` belongs to another key generation
    /// than the archive — a rotation after the archive was taken, whose retired
    /// keys a restore brings back. `None` when there is no such vault or its
    /// manifest cannot be read as one.
    pub fn key_generation_differs(&self, root: &Path) -> Option<bool> {
        let raw = fs::read(root.join(VAULTS_DIR).join(&self.id).join(MANIFEST_FILE)).ok()?;
        let live = Manifest::parse(&raw).ok()?;
        (live.id == self.id).then(|| live.salt_hex != self.salt)
    }
}

/// Where a vault set aside by a restore of `id` sits — deterministic, so
/// [`VaultManager::create`](crate::VaultManager::create) can ask in one stat.
fn aside_path(vaults: &Path, id: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    vaults.join(RESTORE_ROOT).join(format!(
        "{ASIDE_PREFIX}{}",
        hex::encode(Sha256::digest(id.as_bytes()))
    ))
}

/// Refuse as [`VaultError::RestoreInterrupted`] when a restore of `id` left the
/// vault it was replacing aside under the palace at `root`.
pub fn refuse_if_interrupted(root: &Path, id: &str) -> Result<(), VaultError> {
    let vaults = root.join(VAULTS_DIR);
    let aside = aside_path(&vaults, id);
    match fs::symlink_metadata(&aside) {
        Ok(_) => Err(VaultError::RestoreInterrupted {
            id: id.to_string(),
            target: vaults.join(id),
            aside,
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// The restore area under `vaults`, made if absent — refused if something that
/// is not a plain directory sits at its name, since a link there would aim the
/// stage, the aside and the sweep somewhere else.
fn container(vaults: &Path) -> Result<PathBuf, VaultError> {
    let root = vaults.join(RESTORE_ROOT);
    for _ in 0..3 {
        match fs::symlink_metadata(&root) {
            Ok(m) if m.is_dir() => return Ok(root),
            Ok(_) => {
                return Err(VaultError::Io(io::Error::other(format!(
                    "{} is not a directory (a link is never followed); nothing was restored \
                     and the live vault was not changed (ROADMAP O268)",
                    root.display()
                ))))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::create_dir(&root) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            },
            Err(e) => return Err(e.into()),
        }
    }
    Err(VaultError::Io(io::Error::other(format!(
        "{} kept disappearing while a restore made it",
        root.display()
    ))))
}

fn nonce() -> String {
    use rand::RngCore;
    let mut n = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut n);
    hex::encode(n)
}

/// Remove the stages a crashed restore left: only `stage-<32 hex>` entries,
/// and only once they are older than [`STALE_STAGE`]. An aside is never touched.
fn sweep_stale(container: &Path) {
    let Ok(entries) = fs::read_dir(container) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let ours = name.strip_prefix(STAGE_PREFIX).is_some_and(|n| {
            n.len() == 32 && n.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        });
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > STALE_STAGE);
        if ours && stale {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// Copy one regular file durably: `create_new` at the destination, the bytes,
/// `sync_all`. The source was checked to be a regular file by
/// `symlink_metadata`; one swapped for a link between that check and this open
/// is read through it, and the stage's verify then judges what arrived.
fn copy_file(from: &Path, to: &Path) -> io::Result<()> {
    let mut src = fs::File::open(from)?;
    let mut dst = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)?;
    io::copy(&mut src, &mut dst)?;
    dst.sync_all()
}

/// A copy of an archive in the restore area, not yet proven: the store unlocks
/// it through [`VaultManager::unlock_stage`](crate::VaultManager::unlock_stage),
/// opens it, verifies it and checks it, and only then asks for the swap.
///
/// Dropped unswapped — any refusal before the swap — it removes itself; the
/// live vault was never touched.
#[derive(Debug)]
pub struct Stage {
    dir: PathBuf,
    container: PathBuf,
    vaults: PathBuf,
    id: String,
    swapped: bool,
    keep: bool,
}

impl Stage {
    /// Copy `archive` into a fresh stage under the palace at `root`: the
    /// manifest's exact bytes through the one manifest writer, every other
    /// file on the allowlist durably, the stage directory synced. Stale stages
    /// are swept first; an aside never is.
    pub fn copy(root: &Path, archive: &Archive) -> Result<Stage, VaultError> {
        let vaults = root.join(VAULTS_DIR);
        let mut last = None;
        // Another restore's Drop removes an EMPTY container behind itself,
        // which can land between making it and making the stage in it.
        let mut made = None;
        for _ in 0..3 {
            let container = container(&vaults)?;
            sweep_stale(&container);
            let dir = container.join(format!("{STAGE_PREFIX}{}", nonce()));
            match fs::create_dir(&dir) {
                Ok(()) => {
                    made = Some((container, dir));
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => last = Some(e),
                Err(e) => return Err(e.into()),
            }
        }
        let Some((container, dir)) = made else {
            return Err(last.expect("three attempts were made").into());
        };
        let stage = Stage {
            dir,
            container,
            vaults,
            id: archive.id.clone(),
            swapped: false,
            keep: false,
        };
        for name in &archive.copied {
            copy_file(&archive.dir.join(name), &stage.dir.join(name))?;
        }
        write_manifest_file(&stage.dir, MANIFEST_FILE, &archive.manifest)?;
        crate::keys::sync_dir(&stage.dir)?;
        Ok(stage)
    }

    /// The stage's directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The vault id the staged manifest names.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Remove a staged rotation manifest the stage's open neither promoted nor
    /// discarded — one that did not authenticate, or a newer build's — and say
    /// whether there was one. It is inert (nothing reads it), it stays in the
    /// archive, and it is not carried into the vault; the store's post-condition
    /// then requires exactly the database and the manifest.
    pub fn discard_unpromoted_staging(&self) -> io::Result<bool> {
        match fs::remove_file(self.dir.join(STAGING_FILE)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// What the stage holds, sorted.
    pub fn entries(&self) -> io::Result<Vec<String>> {
        let mut names: Vec<String> = fs::read_dir(&self.dir)?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<_>>()?;
        names.sort();
        Ok(names)
    }

    /// Swap the proven stage in for `vaults/<id>`, holding `hold` — O69's
    /// exclusive hold on the live vault, `None` when there is no live vault —
    /// across both renames, then removing the vault it replaced.
    ///
    /// In order: refuse if an aside for the id exists; rename the live vault
    /// aside; refuse if `vaults/<id>` is present again (`rename(2)` replaces
    /// an EMPTY directory silently); rename the stage in; sync `vaults/` and the
    /// restore area; drop the hold; require the manifest now at `vaults/<id>`
    /// to be byte-for-byte the stage's; remove the aside. A failed rename-in
    /// puts the live vault back; if that fails too, both paths are named and
    /// neither is removed. **An aside is never removed on a failure path.**
    pub fn swap<H>(mut self, hold: Option<H>) -> Result<Swapped, VaultError> {
        let target = self.vaults.join(&self.id);
        let aside = aside_path(&self.vaults, &self.id);
        refuse_if_interrupted(self.vaults.parent().unwrap_or(&self.vaults), &self.id)?;
        let expected = fs::read(self.dir.join(MANIFEST_FILE))?;
        let replaced = fs::symlink_metadata(&target).is_ok();
        if replaced {
            // The injected fault takes the rename's own error path, message
            // and all — a test that met a different path would prove nothing.
            seam(SwapStep::Aside)
                .and_then(|()| fs::rename(&target, &aside))
                .map_err(|e| {
                    VaultError::Io(io::Error::new(
                        e.kind(),
                        format!(
                        "moving the live vault {} aside failed ({e}); nothing was restored and \
                         the live vault was not changed",
                        target.display()
                    ),
                    ))
                })?;
        }
        if fs::symlink_metadata(&target).is_ok() {
            self.keep = true;
            return Err(VaultError::Io(io::Error::other(format!(
                "{} appeared while the restore ran, so the restored vault was not put there. \
                 The vault it was replacing is at {}, and the verified restore at {}; move one \
                 of them into place once nothing is using the vault (ROADMAP O268)",
                target.display(),
                aside.display(),
                self.dir.display()
            ))));
        }
        let moved_in = seam(SwapStep::In).and_then(|()| fs::rename(&self.dir, &target));
        if let Err(e) = moved_in {
            if !replaced {
                return Err(VaultError::Io(io::Error::new(
                    e.kind(),
                    format!(
                        "renaming the restored vault into place failed ({e}); nothing was changed"
                    ),
                )));
            }
            let back = seam(SwapStep::Back).and_then(|()| fs::rename(&aside, &target));
            return Err(VaultError::Io(match back {
                Ok(()) => io::Error::new(
                    e.kind(),
                    format!(
                        "renaming the restored vault into place failed ({e}); the live vault \
                         was put back unchanged"
                    ),
                ),
                Err(back) => {
                    self.keep = true;
                    io::Error::other(format!(
                        "renaming the restored vault into place failed ({e}), and putting the \
                         live vault back failed too ({back}). The vault that was live is at {}, \
                         the verified restore at {}; move one of them to {} once nothing is \
                         using the vault (ROADMAP O268)",
                        aside.display(),
                        self.dir.display(),
                        target.display()
                    ))
                }
            }));
        }
        self.swapped = true;
        let synced = crate::keys::sync_dir(&self.vaults)
            .and_then(|()| crate::keys::sync_dir(&self.container));
        drop(hold);
        if let Err(e) = synced {
            return Err(VaultError::Io(io::Error::new(
                e.kind(),
                format!(
                    "the restored vault is in place but its directory could not be synced ({e}); \
                     the vault it replaced is kept at {} until this is re-checked",
                    aside.display()
                ),
            )));
        }
        let now = fs::read(target.join(MANIFEST_FILE))?;
        if now != expected {
            return Err(VaultError::Io(io::Error::other(format!(
                "the manifest at {} changed after the restore renamed it in — something wrote \
                 to that vault while the restore ran (a `vault create`?). The vault it replaced \
                 is kept at {} (ROADMAP O268)",
                target.display(),
                aside.display()
            ))));
        }
        if replaced {
            fs::remove_dir_all(&aside).map_err(|e| {
                VaultError::Io(io::Error::new(
                    e.kind(),
                    format!(
                        "the restore is in place and verified, but the vault it replaced could \
                         not be removed from {} ({e}); remove it by hand, since a later restore \
                         or create of this vault refuses while it is there",
                        aside.display()
                    ),
                ))
            })?;
        }
        let _ = fs::remove_dir(&self.container);
        Ok(Swapped { replaced })
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if !self.swapped && !self.keep {
            let _ = fs::remove_dir_all(&self.dir);
            let _ = fs::remove_dir(&self.container);
        }
    }
}

/// Which of the swap's three renames the fixture seam may fail.
#[derive(Debug, Clone, Copy)]
enum SwapStep {
    Aside,
    In,
    Back,
}

/// The fixture seam before one of the swap's renames (ROADMAP O268): an
/// armed fault in a test build, so the injection takes the rename's own error
/// path; nothing in production.
#[cfg(any(test, feature = "test-fixture"))]
fn seam(step: SwapStep) -> io::Result<()> {
    crate::fixture::fire(match step {
        SwapStep::Aside => crate::fixture::Fault::SwapAside,
        SwapStep::In => crate::fixture::Fault::SwapIn,
        SwapStep::Back => crate::fixture::Fault::SwapBack,
    })
}

#[cfg(not(any(test, feature = "test-fixture")))]
fn seam(_: SwapStep) -> io::Result<()> {
    Ok(())
}

/// What a swap did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Swapped {
    /// Whether a vault stood at `vaults/<id>` and was replaced; `false` for a
    /// restore into an absent vault.
    pub replaced: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_vault_id_can_be_the_restore_area() {
        assert_eq!(
            RESTORE_ROOT.len(),
            129,
            "one byte past the 128 a name may measure"
        );
        assert!(
            undercroft_core::validate_name(RESTORE_ROOT, "vault").is_err(),
            "validate_name must refuse the restore area's name, or a vault could be called it"
        );
        assert_eq!(
            RESTORE_ROOT.trim(),
            RESTORE_ROOT,
            "nothing for a trim to remove"
        );
        assert!(RESTORE_ROOT.is_ascii());
    }

    #[test]
    fn an_aside_never_has_a_stage_s_shape() {
        let dir = tempfile::tempdir().unwrap();
        let vaults = dir.path().join(VAULTS_DIR);
        let aside = aside_path(&vaults, "default");
        let name = aside.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(ASIDE_PREFIX));
        assert!(!name.starts_with(STAGE_PREFIX));
        // An aside a year old survives the sweep.
        let container = container(&vaults).unwrap_or_else(|_| {
            fs::create_dir_all(&vaults).unwrap();
            container(&vaults).unwrap()
        });
        fs::create_dir(&aside).unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(365 * 24 * 3600);
        fs::File::open(&aside).unwrap().set_modified(old).ok();
        sweep_stale(&container);
        assert!(aside.exists(), "an aside is never swept");
    }
}
