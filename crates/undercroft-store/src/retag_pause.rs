//! Pause points inside the version-2 row-tag walk, for tests only (ROADMAP
//! O406): a test stops the walk after `vault.json` is raised and before the
//! re-tag commits — the crash state the raise-first order exists for — and
//! can keep a vault in the version-1 regime, which every vault written
//! before O406 is and no open of this build leaves a fresh one in.
//!
//! A module of its own, compiled in every build as a no-op outside tests, on
//! `rotate_pause.rs`'s precedent: an inline `#[cfg(test)]` hook in a file a
//! source gate reads cuts that gate's view.

use std::path::Path;

/// Where the walk stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// `vault.json` is version 2; nothing is re-tagged and the walk holds
    /// the vault exclusively.
    Raised,
    /// Every row is re-tagged and the commitment appended, uncommitted.
    Applied,
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

/// Whether a test has kept the vault in `dir` on the version-1 regime.
/// Always false outside tests.
#[inline(always)]
pub(crate) fn kept_on_v1(dir: &Path) -> bool {
    #[cfg(test)]
    {
        kept().lock().unwrap().contains(dir)
    }
    #[cfg(not(test))]
    {
        let _ = dir;
        false
    }
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

#[cfg(test)]
fn kept() -> &'static std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>> {
    static KEPT: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
    > = std::sync::OnceLock::new();
    KEPT.get_or_init(Default::default)
}

/// Run `hook` at every pause point of the walk on the vault in `dir`.
#[cfg(test)]
pub(crate) fn set(dir: &Path, hook: impl Fn(Phase) + Send + Sync + 'static) {
    hooks()
        .lock()
        .unwrap()
        .insert(dir.to_path_buf(), std::sync::Arc::new(hook));
}

/// Keep the vault in `dir` on the version-1 regime: its writable opens
/// withhold the walk, as a vault another process holds does.
#[cfg(test)]
pub(crate) fn keep_on_v1(dir: &Path) {
    kept().lock().unwrap().insert(dir.to_path_buf());
}

/// Let the vault in `dir` walk again.
#[cfg(test)]
pub(crate) fn release(dir: &Path) {
    kept().lock().unwrap().remove(dir);
    hooks().lock().unwrap().remove(dir);
}
