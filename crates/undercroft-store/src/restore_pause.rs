//! Pause points inside `backup restore`, for tests only (ROADMAP O268): a
//! test deletes the archive, commits to or holds the live vault, or plants a
//! file between the steps of a restore.
//!
//! A module of its own, with `fire` compiled in every build as a no-op
//! outside tests, on `backup_pause.rs`'s and `rotate_pause.rs`'s precedent.

use std::path::Path;

/// Where a restore stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The archive's manifest and entries have been read; nothing copied.
    ArchiveRead,
    /// The archive is copied into the stage; the stage not yet unlocked.
    Staged,
    /// The stage opened, verified and passed its storage check; its store is
    /// still open.
    Verified,
    /// The stage's store is closed and the post-condition held; the live
    /// vault not yet held.
    Closed,
    /// The live vault is held; the swap not yet begun.
    Held,
}

/// Run whatever hook a test set for the palace at `root`. A no-op outside
/// tests.
#[inline(always)]
pub(crate) fn fire(root: &Path, phase: Phase) {
    #[cfg(test)]
    {
        let hook = hooks().lock().unwrap().get(root).cloned();
        if let Some(hook) = hook {
            hook(phase);
        }
    }
    #[cfg(not(test))]
    let _ = (root, phase);
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

/// Run `hook` at every pause point of a restore into the palace at `root`.
#[cfg(test)]
pub(crate) fn set(root: &Path, hook: Hook) {
    hooks().lock().unwrap().insert(root.to_path_buf(), hook);
}
