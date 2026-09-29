//! The filesystem side of a vault delete (ROADMAP O291).
//!
//! A delete used to be `remove_dir_all(vaults/<id>)` with nothing held. Beside
//! another process's live handle that was a write acknowledged and lost — the
//! handle committed into the unlinked database and answered `Ok` — and a
//! replica that had read went on serving the deleted vault's content until it
//! restarted. It also answered `deleted: true` over content a link named, and
//! 404 over a directory holding a database and no manifest, which the
//! orchestrator reads as done.
//!
//! The store's door (`undercroft_store::delete_vault`) now decides everything
//! and takes O69's hold; this module owns the effects: what is at the path
//! ([`survey`]), the empty database a manifest-only vault is held on
//! ([`create_database`]), the ONE rename that takes the vault out of service
//! ([`set_aside`]), and the removal, judged by what is left ([`Aside::remove`],
//! [`finish_leftover`]). It decides no class and refuses nothing on its own:
//! it observes, and the door classifies.
//!
//! **Where**: a vault is set aside into the restore area (`restores.rs`'s
//! container, whose name no vault id can equal and which nothing lists) under
//! `deleting-<sha256 of the id>`. Not `aside-`: `create` refuses beside that
//! name and tells the operator to put the vault back, which for a delete would
//! bring an erased vault back. Not a nonce: an interrupted delete's leftover
//! must be findable by a retry, or the retry answers 404 over content. Every
//! such directory was set aside under a GRANTED hold, so no process holds it,
//! and removing one needs none.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::restores::{container, per_id};
use crate::{DbLayout, VaultError, DB_FILE, MANIFEST_FILE, VAULTS_DIR};

/// The name shape of a vault a delete set aside: `deleting-<64 hex>`.
pub const DELETING_PREFIX: &str = "deleting-";

/// Where a delete of `id` sets the vault aside under the palace at `root`.
pub fn deleting_path(root: &Path, id: &str) -> PathBuf {
    per_id(&root.join(VAULTS_DIR), DELETING_PREFIX, id)
}

/// What sits at `vaults/<id>`, read without following a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Nothing.
    Absent,
    /// A symbolic link, or anything that is not a directory; the text names it.
    NotADirectory(String),
    /// A directory.
    Directory,
}

/// What a delete found, observed only (ROADMAP O291). Every stat that fails
/// other than "not found" is an error, never read as absence: `Path::exists`
/// follows links and answers `false` on ANY error, which is how a vault with an
/// unreadable manifest read as no vault at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Survey {
    /// `vaults/<id>` as found.
    pub target: Target,
    /// The first entry inside the directory that is not a regular file — a
    /// link, a directory, a FIFO, a socket, a device — named with its kind.
    /// No build writes anything but regular files there.
    pub irregular: Option<String>,
    /// Which database the directory holds ([`DbLayout::of`]).
    pub layout: DbLayout,
    /// Whether it holds `vault.json`.
    pub manifest: bool,
    /// Whether a delete of this id left `deleting-<sha256 of the id>` behind.
    pub leftover: bool,
}

/// Survey `vaults/<id>` under the palace at `root`.
pub fn survey(root: &Path, id: &str) -> Result<Survey, VaultError> {
    let dir = root.join(VAULTS_DIR).join(id);
    let leftover = present(&deleting_path(root, id))?;
    let target = match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Target::Absent,
        Err(e) => return Err(e.into()),
        Ok(m) if m.file_type().is_dir() => Target::Directory,
        Ok(m) => Target::NotADirectory(format!("{} is {}", dir.display(), kind(&m))),
    };
    let mut irregular = None;
    let mut manifest = false;
    if target == Target::Directory {
        let mut names: Vec<(String, fs::Metadata)> = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            // `DirEntry::metadata` does not follow a link.
            let meta = entry.metadata()?;
            names.push((entry.file_name().to_string_lossy().into_owned(), meta));
        }
        names.sort_by(|a, b| a.0.cmp(&b.0));
        irregular = names
            .iter()
            .find(|(_, m)| !m.file_type().is_file())
            .map(|(name, m)| format!("{} is {}", dir.join(name).display(), kind(m)));
        manifest = names
            .iter()
            .any(|(name, m)| name == MANIFEST_FILE && m.file_type().is_file());
    }
    let layout = if target == Target::Directory {
        DbLayout::of(&dir)
    } else {
        DbLayout::Absent
    };
    Ok(Survey {
        target,
        irregular,
        layout,
        manifest,
        leftover,
    })
}

fn present(path: &Path) -> Result<bool, VaultError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn kind(meta: &fs::Metadata) -> &'static str {
    let t = meta.file_type();
    if t.is_symlink() {
        return "a symbolic link";
    }
    if t.is_dir() {
        return "a directory";
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if t.is_fifo() {
            return "a FIFO";
        }
        if t.is_socket() {
            return "a socket";
        }
        if t.is_block_device() || t.is_char_device() {
            return "a device";
        }
    }
    if t.is_file() {
        return "a regular file";
    }
    "not a regular file"
}

/// An empty `vault.db` a delete created in a directory holding no database, so
/// the hold has a file to lock (ROADMAP O291 ruling item 5). Owned only when
/// the delete's own exclusive create made it.
#[derive(Debug)]
pub struct OwnedDatabase {
    path: PathBuf,
}

/// Create `vaults/<id>/vault.db` exclusively: `Some` when this call made it,
/// `None` when a file is already there (a racer's, never owned).
pub fn create_database(root: &Path, id: &str) -> Result<Option<OwnedDatabase>, VaultError> {
    let path = root.join(VAULTS_DIR).join(id).join(DB_FILE);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(_) => Ok(Some(OwnedDatabase { path })),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
        Err(e) => Err(e.into()),
    }
}

impl OwnedDatabase {
    /// Remove the file this delete created, while it is still empty — the
    /// refusal that follows then changes nothing (ROADMAP O291). A file that
    /// grew is a racer's vault now and stays. Says whether it was removed.
    pub fn remove_if_empty(self) -> Result<bool, VaultError> {
        match fs::symlink_metadata(&self.path) {
            Ok(m) if m.file_type().is_file() && m.len() == 0 => {
                fs::remove_file(&self.path)?;
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

/// A vault taken out of service by [`set_aside`]: no open can reach it by a
/// vault path any more. Nothing removes it but [`Aside::remove`] — no `Drop`,
/// because an aside is kept on every failure path.
#[derive(Debug)]
#[must_use = "an aside holds the vault's content until it is removed"]
pub struct Aside {
    path: PathBuf,
    container: PathBuf,
}

/// Why [`set_aside`] failed, with the hold it was given still alive where it
/// still is — so the door can undo what it did under that hold before letting
/// go of it.
#[derive(Debug)]
pub struct SetAsideFailed<H> {
    /// What failed.
    pub error: VaultError,
    /// Whether the vault had already left `vaults/<id>` — only a failed sync
    /// after the rename. The error then names where its files are, and a retry
    /// of the delete finishes it; before, nothing was moved.
    pub moved: bool,
    /// The hold, unless it was released: for the retry off unix, or once the
    /// vault moved.
    pub hold: Option<H>,
}

/// Take `vaults/<id>` out of service by ONE rename into
/// `deleting-<sha256 of the id>`, holding `hold` — O69's hold on its database,
/// by value so the order is fixed here: rename, sync `vaults/` and the
/// container, release. A hold passed here is structure, not proof; the store's
/// source gate is what proves the door took one (ROADMAP O291 ruling item 4).
///
/// **Off unix, try first.** Rename under the hold; if the OS refuses — SQLite
/// opens without `FILE_SHARE_DELETE`, so it may refuse to move a directory
/// holding the file the hold has open — release the hold and try ONCE more.
/// Where the OS permits the first rename it ran under the hold, as on unix;
/// where it refuses, the retry is what "close the hold just before" would have
/// done. Unmeasured on Windows (ROADMAP O275).
pub fn set_aside<H>(root: &Path, id: &str, hold: H) -> Result<Aside, SetAsideFailed<H>> {
    let vaults = root.join(VAULTS_DIR);
    let target = vaults.join(id);
    let aside = deleting_path(root, id);
    // Taken for the one retry off unix; never on unix, where the rename runs
    // under the hold or not at all.
    #[cfg_attr(unix, allow(unused_mut))]
    let mut hold = Some(hold);
    let fail = |error: VaultError, hold: Option<H>| SetAsideFailed {
        error,
        moved: false,
        hold,
    };
    match present(&aside) {
        Ok(false) => {}
        Ok(true) => {
            return Err(fail(
                VaultError::Io(io::Error::other(format!(
                    "{} already exists — an earlier delete of this vault did not finish. \
                     Nothing was deleted; retry the delete, which removes it first",
                    aside.display()
                ))),
                hold,
            ))
        }
        Err(e) => return Err(fail(e, hold)),
    }
    // Another restore's `Drop` removes an EMPTY container behind itself, which
    // can land between making it and the rename (`Stage::copy`'s precedent).
    let mut moved = None;
    for _ in 0..3 {
        let area = match container(&vaults) {
            Ok(area) => area,
            Err(e) => {
                return Err(fail(
                    VaultError::Io(io::Error::other(format!(
                        "the restore area a delete sets a vault aside in could not be used \
                         ({e}); nothing was deleted"
                    ))),
                    hold,
                ))
            }
        };
        let rename = || seam().and_then(|()| fs::rename(&target, &aside));
        let attempt = rename();
        #[cfg(not(unix))]
        let attempt = match attempt {
            Err(_) if hold.is_some() => {
                drop(hold.take());
                rename()
            }
            other => other,
        };
        match attempt {
            Ok(()) => {
                moved = Some(area);
                break;
            }
            // The container vanished beneath the rename: try again — but only
            // while the hold is still held, so off unix the one unheld retry
            // stays one (ruling item 9).
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    && hold.is_some()
                    && present(&target).unwrap_or(false) =>
            {
                continue
            }
            Err(e) => {
                return Err(fail(
                    VaultError::Io(io::Error::new(
                        e.kind(),
                        format!(
                            "taking the vault {} out of service failed ({e}); nothing was \
                             deleted",
                            target.display()
                        ),
                    )),
                    hold,
                ))
            }
        }
    }
    let Some(area) = moved else {
        return Err(fail(
            VaultError::Io(io::Error::other(format!(
                "the restore area under {} kept disappearing while a delete used it; nothing \
                 was deleted",
                vaults.display()
            ))),
            hold,
        ));
    };
    let aside = Aside {
        path: aside,
        container: area,
    };
    let synced =
        crate::keys::sync_dir(&vaults).and_then(|()| crate::keys::sync_dir(&aside.container));
    drop(hold);
    match synced {
        Ok(()) => Ok(aside),
        Err(e) => Err(SetAsideFailed {
            error: aside.incomplete(e),
            moved: true,
            hold: None,
        }),
    }
}

impl Aside {
    /// Where the vault now sits.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the vault set aside, judged by the POST-CONDITION — nothing left
    /// at its path — never by the removal's own result; then sync the restore
    /// area and remove it if it is empty. A failure names the aside: the vault
    /// is out of service and its files are still on disk.
    pub fn remove(self) -> Result<(), VaultError> {
        remove_judged(&self.path).map_err(|e| self.incomplete(e))?;
        crate::keys::sync_dir(&self.container).map_err(|e| self.incomplete(e))?;
        let _ = fs::remove_dir(&self.container);
        Ok(())
    }

    fn incomplete(&self, e: io::Error) -> VaultError {
        VaultError::Io(io::Error::new(
            e.kind(),
            format!(
                "the vault is out of service, but the delete is NOT complete: its files are \
                 at {} ({e}). Retry the delete, which finishes it (ROADMAP O291)",
                self.path.display()
            ),
        ))
    }
}

/// Remove a delete's leftover for `id` — `deleting-<sha256 of the id>`, which
/// an earlier delete set aside under a granted hold and did not finish — and
/// say whether there was one. Judged by the post-condition.
pub fn finish_leftover(root: &Path, id: &str) -> Result<bool, VaultError> {
    let path = deleting_path(root, id);
    if !present(&path)? {
        return Ok(false);
    }
    remove_judged(&path).map_err(|e| {
        VaultError::Io(io::Error::new(
            e.kind(),
            format!(
                "an earlier delete of vault '{id}' left its files at {} and they could not all be \
                 removed ({e}); retry the delete, or remove that directory by hand (ROADMAP O291)",
                path.display()
            ),
        ))
    })?;
    // The unlinks synced before a delete answers `Removed` over them (ruling
    // item 14), as `Aside::remove` does.
    if let Some(area) = path.parent() {
        crate::keys::sync_dir(area)?;
    }
    Ok(true)
}

/// The module's one recursive removal. `remove_dir_all` removes what it can
/// and may meet a concurrent remover's `NotFound`; what decides is whether
/// anything is left.
fn remove_judged(path: &Path) -> io::Result<()> {
    let removed = seam_remove().and_then(|()| fs::remove_dir_all(path));
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(_) => Err(removed.err().unwrap_or_else(|| {
            io::Error::other("the directory is still there after its removal returned")
        })),
    }
}

/// The fixture seam before the set-aside rename: an armed fault in a test
/// build takes the rename's own error path; nothing in production.
#[cfg(any(test, feature = "test-fixture"))]
fn seam() -> io::Result<()> {
    crate::fixture::fire(crate::fixture::Fault::DeleteAside)
}

#[cfg(not(any(test, feature = "test-fixture")))]
fn seam() -> io::Result<()> {
    Ok(())
}

/// The fixture seam before the removal: an armed fault leaves the aside whole.
#[cfg(any(test, feature = "test-fixture"))]
fn seam_remove() -> io::Result<()> {
    crate::fixture::fire(crate::fixture::Fault::DeleteRemove)
}

#[cfg(not(any(test, feature = "test-fixture")))]
fn seam_remove() -> io::Result<()> {
    Ok(())
}
