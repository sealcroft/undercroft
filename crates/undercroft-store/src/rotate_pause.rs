//! Pause points inside a key rotation, for tests only (ROADMAP O254's probe
//! P1): a test holds a rotation in one window while another handle acts —
//! the staging-to-commit window, where an open used to discard the staged
//! manifest, and the commit-to-promote window, where an open re-seeds the old
//! keycheck — and, since ROADMAP O276, one FAULT after it: the release proof
//! refused, so the handle replaces its connection.
//!
//! A module of its own, and `fire` compiled in every build as a no-op outside
//! tests, for a mechanical reason: `rotate.rs`'s completeness gate
//! (`rotation_names_every_key_derived_artifact`) reads that file's production
//! half as everything before its FIRST `#[cfg(test)]`, so a test hook written
//! inline there cut the gate's view to the file's first lines — which is how
//! this module came to exist, found by that gate failing.

use std::path::Path;

/// Where a rotation stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// `vault.json.next` is durable; the re-seal has not committed and the
    /// rotation holds the vault exclusively (ROADMAP O257).
    Staged,
    /// The re-seal committed; nothing is promoted, and the rotation STILL
    /// holds the vault exclusively — the lock survives the commit in
    /// exclusive locking mode (ROADMAP O257).
    Committed,
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

/// Whether a test has refused the release proof for the vault in `dir` —
/// the zero-timeout read another connection makes after an exclusive hold
/// (ROADMAP O257, O276). Always false outside tests.
///
/// It stands in for what no test on this platform can produce: a proof that
/// fails while nothing stops the handle opening a replacement. The one lock
/// that can fail the proof here is the handle's OWN — another connection
/// cannot hold the vault exclusively while this handle has it open (O257's
/// P3) — and that lock blocks the replacement too; on Windows the PENDING
/// byte a refused fence leaves (O257's D2) is the case this models.
#[inline(always)]
pub(crate) fn proof_refused(dir: &Path) -> bool {
    #[cfg(test)]
    {
        refused().lock().unwrap().contains(dir)
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
fn refused() -> &'static std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>> {
    static REFUSED: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
    > = std::sync::OnceLock::new();
    REFUSED.get_or_init(Default::default)
}

/// Run `hook` at every pause point of a rotation of the vault in `dir`.
#[cfg(test)]
pub(crate) fn set(dir: &Path, hook: Hook) {
    hooks().lock().unwrap().insert(dir.to_path_buf(), hook);
}

/// Refuse (or stop refusing) the release proof for the vault in `dir`.
#[cfg(test)]
pub(crate) fn refuse_proof(dir: &Path, on: bool) {
    let mut set = refused().lock().unwrap();
    if on {
        set.insert(dir.to_path_buf());
    } else {
        set.remove(dir);
    }
}
