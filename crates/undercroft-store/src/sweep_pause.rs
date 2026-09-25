//! Pause points inside a retention sweep, for tests only (ROADMAP O255): a
//! test acts between the sweep's decision and the lock that destroys, which
//! is how the gate forces — and counts — the two branches a changed policy
//! takes: one re-decision outside the lock, then a decision inside it.
//!
//! A module of its own, with `fire` compiled in every build as a no-op
//! outside tests, on `rotate_pause.rs`'s precedent.

use std::path::Path;

/// Where a sweep stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// A decision made outside the lock, `attempt` 0 or 1, before the lock
    /// that re-validates it.
    Decided {
        /// Which outside decision this is.
        attempt: u32,
    },
    /// The policies changed after both outside decisions; the sweep now
    /// decides inside the lock. Fired before the lock is taken.
    DecidingInLock,
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

/// Run `hook` at every pause point of a sweep of the vault in `dir`.
#[cfg(test)]
pub(crate) fn set(dir: &Path, hook: Hook) {
    hooks().lock().unwrap().insert(dir.to_path_buf(), hook);
}
