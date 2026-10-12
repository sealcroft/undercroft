//! **The absent-database door** (ROADMAP O308 and O213, their rulings of
//! 2026-10-08): what an open may do with a vault directory that holds a
//! manifest and no database content.
//!
//! Before it, the writable open created the database whenever the layout was
//! absent (`SQLITE_OPEN_CREATE`), committed the schema batch, and only then
//! judged the empty trail `Headless::Erased` and refused `ManifestTampered` —
//! so the refusal manufactured the evidence its own verdict read, and every
//! later open on either posture answered tampering for what was a deleted
//! file. The read-only open answered A33's `DatabaseMissing` — the integrity
//! verdict, exit 2 — for every vault `init` had just created as well. So the
//! decision moves in FRONT of every opener: `recorded_embedder` (which runs
//! ahead of the posture dispatch on both surfaces, O91), the head of both
//! opens (before O7's legacy rename can open a file), and the writable
//! connect's ONE layout read, which is the only place `SQLITE_OPEN_CREATE` is
//! granted — on this door's *Fresh*-and-absent answer at that same
//! observation.

use std::path::{Path, PathBuf};

use undercroft_vault::{DbLayout, ManifestHistory, Vault, VaultError};

use crate::{vault_db, StoreError};

/// What a vault directory's database files are, read by ONE stat of each name
/// that FOLLOWS a link, as [`DbLayout::of`] and SQLite do (O279's gate G8
/// opens a linked database), with every error but not-found propagated —
/// never `Path::exists`, which reads a permission error as absence.
pub(crate) struct Survey {
    /// The layout these stats observed — the one a connect opens by.
    pub(crate) layout: DbLayout,
    /// Whether a database holds content: false for no main file at either
    /// name, or for the ONE main file a regular file of length 0 (ROADMAP O308
    /// item 3). A zero-page main file is no database SQLite made — enabling
    /// WAL writes page 1 — and holds no committed byte unless a `-wal` beside
    /// it does, which [`Self::wal`] answers.
    pub(crate) content: bool,
    /// A NON-EMPTY `-wal` of either name beside no content: it may hold
    /// committed frames, and SQLite's first lock on a zero-page main file
    /// DELETES the `-wal` beside it (`pagerOpenWalIfPresent`), read-only
    /// connections included. An empty `-wal` and a `-shm` are scaffolding.
    /// Read only where there is no content.
    pub(crate) wal: Option<PathBuf>,
}

/// One stat that follows a link: `None` only for not-found.
fn stat(path: &Path) -> Result<Option<std::fs::Metadata>, StoreError> {
    match std::fs::metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StoreError::Vault(VaultError::Io(e))),
    }
}

/// Survey the vault directory `dir` (ROADMAP O308 item 3). NOT inside
/// [`DbLayout::of`], which O291's delete asks while holding the zero-length
/// database it made itself.
pub(crate) fn survey(dir: &Path) -> Result<Survey, StoreError> {
    let current = stat(&dir.join(undercroft_vault::DB_FILE))?;
    let legacy = stat(&dir.join(undercroft_vault::LEGACY_DB_FILE))?;
    let empty = |meta: &std::fs::Metadata| meta.is_file() && meta.len() == 0;
    let (layout, content) = match (&current, &legacy) {
        (Some(_), Some(_)) => (DbLayout::Ambiguous, true),
        (Some(meta), None) => (DbLayout::Current, !empty(meta)),
        (None, Some(meta)) => (DbLayout::Legacy, !empty(meta)),
        (None, None) => (DbLayout::Absent, false),
    };
    let mut wal = None;
    if !content {
        for main in [undercroft_vault::DB_FILE, undercroft_vault::LEGACY_DB_FILE] {
            let path = dir.join(format!("{main}-wal"));
            // A `-wal` that is not a regular file is no scaffolding SQLite
            // made, and is named rather than ignored.
            if stat(&path)?.is_some_and(|meta| !meta.is_file() || meta.len() > 0) {
                wal = Some(path);
                break;
            }
        }
    }
    Ok(Survey {
        layout,
        content,
        wal,
    })
}

/// What the door decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Door {
    /// The directory holds database content in this layout: the open proceeds
    /// as it always has, and nothing about the manifest is asked here (O254's
    /// P1 — a busy writer anchors, so the manifest's bytes are no evidence
    /// beside a database).
    Content(DbLayout),
    /// No content beside a manifest that records no anchored write: the
    /// writable posture starts the vault in this layout; the read-only posture
    /// answers [`StoreError::ReadOnlyNoAnchoredWrite`] (ROADMAP O213).
    Fresh(DbLayout),
}

/// **The door, in the ruling's order** (ROADMAP O308 item 4): (a) the vault
/// directory gone — the reopen class (O291); (b) the unlock's values bound to
/// the directory, or the reopen class (item 2); (c) a non-empty `-wal` beside
/// no content — `DatabaseMissing` naming it, nothing opened; (d) a manifest
/// that records history — `DatabaseMissing`, nothing created; (e) a manifest no
/// build writes — `ManifestTampered`, as `adopt_empty_chain` answers it; (f) a
/// manifest that records no anchored write — [`Door::Fresh`].
pub(crate) fn door(vault: &Vault) -> Result<Door, StoreError> {
    let survey = survey(vault.dir())?;
    if survey.content {
        return Ok(Door::Content(survey.layout));
    }
    // (a) Deleted since the unlock: no missing database, a missing vault.
    if vault_db::vault_gone(vault.dir()) {
        return Err(vault_db::deleted(vault.dir()));
    }
    // (b) The unlock's values describe the directory only while `vault.json`
    // is the bytes it verified — after a delete and a `create` of the same id
    // between the unlock and here (O302), they describe a vault that is gone.
    if !vault.unlock_still_binds()? {
        undercroft_obs::diag_warn!(
            "vault {:?}: vault.json is not the file this open's unlock verified, and no \
             database is there to judge it by (ROADMAP O308); the open is refused and reopens",
            vault.id()
        );
        return Err(StoreError::StaleUnlock(format!(
            "vault.json at {} is not the file this open's unlock verified — the vault was \
             deleted and created again, or its manifest was rewritten, since the unlock — and \
             no database is there to judge it by. Nothing was created and nothing was read; \
             reopen the vault (ROADMAP O308)",
            vault.dir().display()
        )));
    }
    let path = |layout: DbLayout| match layout {
        DbLayout::Legacy => vault.legacy_db_path(),
        _ => vault.current_db_path(),
    };
    let missing = |wal: Option<&PathBuf>| StoreError::DatabaseMissing {
        id: vault.id().to_string(),
        path: path(survey.layout).display().to_string(),
        writes: vault.writes(),
        wal: wal.map(|w| w.display().to_string()),
        staged: vault.has_pending(),
    };
    // (c) Before the manifest is consulted: whatever it records, an open of a
    // zero-page database beside this file would delete it.
    if let Some(wal) = survey.wal.as_ref() {
        return Err(missing(Some(wal)));
    }
    match vault.manifest_history() {
        // (d)
        ManifestHistory::History => Err(missing(None)),
        // (e)
        ManifestHistory::Mixed => Err(StoreError::Vault(VaultError::ManifestTampered)),
        // (f)
        ManifestHistory::Fresh => Ok(Door::Fresh(survey.layout)),
    }
}
