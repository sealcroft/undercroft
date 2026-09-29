//! Pause points inside a vault delete, for tests only (ROADMAP O291): a test
//! opens a store, plants an entry or records which steps ran between the steps
//! of a delete — the last because a create-then-unlink and a rename-then-put-
//! back both END looking unchanged, and only a witness of the steps reached
//! tells a refusal from an effect that was undone.
//!
//! A module of its own, with `fire` compiled in every build as a no-op outside
//! tests, on `restore_pause.rs`'s precedent.

use std::path::Path;

/// Where a delete stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The vault was surveyed and passed the checks made before any effect;
    /// nothing created, nothing held.
    Surveyed,
    /// The hold is granted and the checks passed again under it; nothing moved.
    /// A conditional delete's check belongs here (ROADMAP O147).
    Held,
    /// The vault is out of service in the restore area and the hold released;
    /// its files are not yet removed.
    Aside,
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

/// Run `hook` at every pause point of a delete in the palace at `root`.
#[cfg(test)]
pub(crate) fn set(root: &Path, hook: Hook) {
    hooks().lock().unwrap().insert(root.to_path_buf(), hook);
}

/// Remove the hook for `root`.
#[cfg(test)]
pub(crate) fn clear(root: &Path) {
    hooks().lock().unwrap().remove(root);
}
