//! Pause points inside `backup create`, for tests only (ROADMAP O256): a test
//! commits, anchors or rotates through another handle between the steps of a
//! backup. SQLite's progress handler cannot do it here — the page copy runs
//! no VM program, so a handler never fires inside it.
//!
//! A module of its own, with `fire` compiled in every build as a no-op
//! outside tests, on `rotate_pause.rs`'s precedent.

use std::path::Path;

/// Where a backup stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The manifest has been read; the snapshot is not yet pinned.
    ManifestRead,
    /// Inside the snapshot, its state pinned, nothing yet compared.
    Pinned,
    /// The snapshot verified; the page copy not yet taken.
    Verified,
    /// The page copy taken; the snapshot still open.
    Copied,
    /// The snapshot ended and the copy synced; the manifest not yet written.
    Synced,
    /// The manifest written into the stage; the archive not yet published.
    Staged,
}

/// Run whatever hook a test set for the vault in `dir`. A no-op outside
/// tests.
#[inline(always)]
pub(crate) fn fire(dir: &Path, phase: Phase) {
    #[cfg(test)]
    {
        let hook = hooks().lock().unwrap().get(dir).cloned();
        if let Some(hook) = hook {
            hook(phase);
        }
    }
    #[cfg(not(test))]
    let _ = (dir, phase);
}

#[cfg(test)]
type Hook = std::sync::Arc<dyn Fn(Phase) + Send + Sync>;

#[cfg(test)]
fn hooks() -> &'static std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Hook>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Hook>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(Default::default)
}

/// Run `hook` at every pause point of a backup of the vault in `dir`.
#[cfg(test)]
pub(crate) fn set(dir: &Path, hook: Hook) {
    hooks().lock().unwrap().insert(dir.to_path_buf(), hook);
}
