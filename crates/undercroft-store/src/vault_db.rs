//! The one door through which this crate opens a vault's database by path
//! (ROADMAP O279).
//!
//! A connection takes its file descriptor at `Connection::open` and its first
//! lock at its first statement, and between the two it holds no lock at all —
//! so no fence sees it: O69's hold, which a `backup restore` takes before its
//! two renames, is GRANTED beside a connection that has only opened. A swap
//! landing there leaves the descriptor on the database the restore set aside,
//! while everything the connection or its store later opens by path — its
//! `-wal`, its `-shm`, the manifest beside it — names the restored vault.
//! Measured on a 2,000-drawer sealed vault: a writable open served the set-aside
//! vault and fast-forwarded the RESTORED manifest's anchor, after which the
//! restored vault refused to open as tampered; one ordinary save through it put
//! the set-aside file's pages into the restored `-wal` and the restored database
//! failed `integrity_check`; a read-only open served a vault that no longer
//! existed. Nothing reported any of it, and the restore answered `Restored`.
//!
//! So every such open goes through [`open_by_path`], in this order:
//!
//! 1. open, and turn checkpoint-on-close OFF at once, read back — every close
//!    before the check below is then inert on any VFS. SQLite's own moved-file
//!    guard skips a database it reads as empty (`databaseIsUnmoved`, `dbSize ==
//!    0`), and a close there would fold another opener's `-wal` into the file
//!    set aside and delete that `-wal` by path;
//! 2. the caller's first LOCKING statement — only once it has run does the
//!    connection hold a lock a restore's hold must see, so a check before it
//!    proves nothing about the moment after it;
//! 3. the identity check ([`identity`]), whatever that statement returned;
//! 4. a moved file is closed with `Connection::close()` — never by drop, whose
//!    result rusqlite discards (ROADMAP O278) — and the caller refuses; the
//!    same file gets checkpoint-on-close back, unless the caller keeps it off.
//!
//! **The identity check needs the tree's one `unsafe` block** (ruled by the
//! maintainer, 2026-09-27). Only SQLite knows which file its descriptor holds,
//! and it answers through `sqlite3_file_control(…, SQLITE_FCNTL_HAS_MOVED, …)`,
//! which rusqlite does not wrap. Every safe alternative measures a PATH and has
//! a measured hole: a path compared with itself before and after passes a path
//! that names A, then B at the open, then A again, while the descriptor reads B.
//! HAS_MOVED alone has one too — SQLite stats the path it RESOLVED, so across a
//! swap of a symlinked vault directory it answers "not moved" — which is why
//! the check also requires the resolved path and the path the open used to name
//! one file.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use undercroft_vault::VaultError;

use crate::open_pause::{self, Opener};
use crate::StoreError;

/// How [`open_by_path`] opens the file at its path.
#[derive(Clone, Copy)]
pub(crate) enum How {
    /// The path itself, with these flags.
    Plain(OpenFlags),
    /// The path's `immutable=1` URI, with these flags (plus `SQLITE_OPEN_URI`).
    Immutable(OpenFlags),
}

/// What [`open_by_path`] found.
pub(crate) enum Opened<T> {
    /// The descriptor is the file at the path; the first statement's value.
    Here(Connection, T),
    /// The file at the path is not the one the descriptor holds. The
    /// connection is already closed, without a checkpoint.
    Moved,
}

/// Whether a connection's descriptor holds the file at the path it opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Identity {
    /// It does.
    Same,
    /// It does not: the path names another file now, or no file, or the path
    /// SQLite resolved and the path the open used name different files.
    #[cfg_attr(not(unix), allow(dead_code))]
    Moved,
    /// This platform offers no check (SQLite's win32 VFS has no moved-file
    /// arm). A restore's rename is refused there while a descriptor is open,
    /// which is ROADMAP O275's question — never read as "same".
    #[cfg_attr(unix, allow(dead_code))]
    Unchecked,
}

/// Open the vault database at `path` (in the vault directory `dir`), run
/// `first` — the caller's first statement, which must take a lock — and prove
/// the descriptor's file is still the one at `path`. See the module doc.
///
/// `keep_no_checkpoint` leaves checkpoint-on-close off on the connection
/// returned (O69's hold, and a probe that must never be a vault's last closer).
/// An error from `first` on the same file is returned as it is; the connection
/// is dropped, inertly.
pub(crate) fn open_by_path<T>(
    dir: &Path,
    path: &Path,
    how: How,
    at: Opener,
    keep_no_checkpoint: bool,
    first: impl FnOnce(&mut Connection) -> Result<T, StoreError>,
) -> Result<Opened<T>, StoreError> {
    let mut conn = match how {
        How::Plain(flags) => Connection::open_with_flags(path, flags)?,
        How::Immutable(flags) => Connection::open_with_flags(
            crate::backup::immutable_uri(path),
            flags | OpenFlags::SQLITE_OPEN_URI,
        )?,
    };
    checkpoint_on_close(&conn, false, path)?;
    open_pause::fire(dir, at);
    let value = first(&mut conn);
    match identity(&conn, path) {
        Ok(Identity::Moved) => {
            close(conn, path)?;
            return Ok(Opened::Moved);
        }
        Ok(Identity::Same | Identity::Unchecked) => {}
        // A statement that failed says more than a check that could not run
        // after it; either way nothing proceeds on this connection, which is
        // dropped inertly.
        Err(e) => return Err(value.err().unwrap_or(e)),
    }
    let value = value?;
    if !keep_no_checkpoint {
        checkpoint_on_close(&conn, true, path)?;
    }
    Ok(Opened::Here(conn, value))
}

/// The refusal an open answers when its file moved: the reopen class, which
/// the CLI's `open_store_as` and `/v1`'s `store_for` retry once with a fresh
/// unlock.
pub(crate) fn moved(path: &Path) -> StoreError {
    undercroft_obs::diag_warn!(
        "{}: the database file this open reached is not the one at that path now (ROADMAP \
         O279); the connection was closed without a checkpoint and the open is refused",
        path.display()
    );
    StoreError::StaleUnlock(format!(
        "the database file this open reached is not the one at {} now — a backup restore \
         replaced the vault while this process was opening it, another process renamed \
         its pre-1.5.0 palace.db, or a vault delete removed it. It was closed without a \
         checkpoint; nothing was read from it or written through it. Reopen the vault \
         (ROADMAP O279, O291)",
        path.display()
    ))
}

/// Whether the vault directory `dir` is gone — a vault delete took it out of
/// service since this process unlocked it (ROADMAP O291). Only "not found"
/// counts; any other stat failure is not evidence of a delete.
pub(crate) fn vault_gone(dir: &Path) -> bool {
    matches!(std::fs::symlink_metadata(dir), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// The refusal an open answers when the vault was deleted beneath it: the
/// reopen class, whose retry answers "not found" (ROADMAP O291). It was a raw
/// SQLite "unable to open" on the writable posture and `DatabaseMissing`, an
/// integrity verdict, on the read-only one.
pub(crate) fn deleted(dir: &Path) -> StoreError {
    StoreError::StaleUnlock(format!(
        "the vault at {} was deleted while this process was opening it — its directory is \
         gone. Nothing was read or written. Reopen it, which finds no such vault (ROADMAP \
         O291)",
        dir.display()
    ))
}

/// Whether `conn`'s descriptor holds the file at `path` (unix): SQLite's own
/// moved-file check on the descriptor, AND the path SQLite resolved naming the
/// same `(dev, ino)` as `path`. Any stat that fails reads as moved.
#[cfg(unix)]
pub(crate) fn identity(conn: &Connection, path: &Path) -> Result<Identity, StoreError> {
    if descriptor_has_moved(conn, path)? {
        return Ok(Identity::Moved);
    }
    let resolved = resolved_filename(conn)?;
    Ok(match (file_id(&resolved), file_id(path)) {
        (Some(a), Some(b)) if a == b => Identity::Same,
        _ => Identity::Moved,
    })
}

/// No moved-file check exists off unix (ROADMAP O275).
#[cfg(not(unix))]
pub(crate) fn identity(_conn: &Connection, _path: &Path) -> Result<Identity, StoreError> {
    Ok(Identity::Unchecked)
}

/// SQLite's `SQLITE_FCNTL_HAS_MOVED` on the connection's main database: the
/// inode its descriptor had at the open against a fresh stat of the path SQLite
/// resolved, and "moved" when that path is gone. A file control that does not
/// answer is a refusal of its own class — "cannot tell" is never "same", and
/// never the reopen class a retry would meet again.
#[cfg(unix)]
#[allow(unsafe_code)]
fn descriptor_has_moved(conn: &Connection, path: &Path) -> Result<bool, StoreError> {
    let mut moved: std::os::raw::c_int = 0;
    // SAFETY: `conn.handle()` is the live `sqlite3*` this borrowed `Connection`
    // owns, valid for the whole call; `Connection` is `!Sync`, so no other
    // thread uses it meanwhile, and SQLite takes the connection's mutex inside
    // the call. `c"main"` is a static NUL-terminated schema name. The
    // out-parameter is a live, aligned stack `c_int`, and the unix VFS's
    // HAS_MOVED arm writes exactly one `int` through it and keeps no pointer.
    let rc = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            conn.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
            (&mut moved as *mut std::os::raw::c_int).cast(),
        )
    };
    if rc != rusqlite::ffi::SQLITE_OK {
        return Err(StoreError::Vault(VaultError::Io(std::io::Error::other(
            format!(
                "SQLite could not say whether the database file it opened is still the one at \
                 {} (its moved-file check answered {rc}); refusing rather than guessing \
                 (ROADMAP O279)",
                path.display()
            ),
        ))));
    }
    Ok(moved != 0)
}

/// The path SQLite resolved for the main database, read as BYTES: a vault
/// under a root that is not UTF-8 opens today, and `Connection::path()`
/// answers `None` there, which would refuse every open.
#[cfg(unix)]
fn resolved_filename(conn: &Connection) -> Result<std::path::PathBuf, StoreError> {
    use std::os::unix::ffi::OsStrExt;
    let unreadable = |why: String| {
        StoreError::Vault(VaultError::Io(std::io::Error::other(format!(
            "reading the database path SQLite resolved: {why} (ROADMAP O279)"
        ))))
    };
    let mut stmt = conn.prepare("PRAGMA database_list")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name = row
            .get_ref(1)?
            .as_bytes()
            .map_err(|e| unreadable(e.to_string()))?;
        if name == b"main" {
            let file = row
                .get_ref(2)?
                .as_bytes()
                .map_err(|e| unreadable(e.to_string()))?;
            return Ok(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(file)));
        }
    }
    Err(unreadable("no main database is attached".into()))
}

/// `(dev, ino)` of the file `p` names now, following links; `None` if it names
/// none.
#[cfg(unix)]
fn file_id(p: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
}

/// Set checkpoint-on-close ON (`on`) or OFF and read the result back: the
/// setting is the observable, not the call.
fn checkpoint_on_close(conn: &Connection, on: bool, path: &Path) -> Result<(), StoreError> {
    let no_ckpt = conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        !on,
    )?;
    if no_ckpt == on {
        return Err(StoreError::Vault(VaultError::Io(std::io::Error::other(
            format!(
                "could not turn checkpoint-on-close {} for {} (sqlite reports it {}); refusing \
                 rather than opening a connection whose close could rewrite a vault (ROADMAP \
                 O279)",
                if on { "back on" } else { "off" },
                path.display(),
                if no_ckpt { "off" } else { "on" }
            ),
        ))));
    }
    Ok(())
}

/// Close a connection whose file moved. A close that fails is not the reopen
/// class: its connection is dropped — inert, checkpoint-on-close being off —
/// and the error says this process should exit before it reopens the vault,
/// since a retry beside a connection still open on the set-aside file would put
/// two of SQLite's shared-memory nodes on one `-shm`.
fn close(conn: Connection, path: &Path) -> Result<(), StoreError> {
    conn.close().map_err(|(c, e)| {
        drop(c);
        StoreError::Vault(VaultError::Io(std::io::Error::other(format!(
            "the database file this open reached is not the one at {} now (a backup restore \
             replaced the vault), and closing the connection to it failed ({e}). Nothing was \
             written through it; exit this process before reopening the vault (ROADMAP O279)",
            path.display()
        ))))
    })
}
