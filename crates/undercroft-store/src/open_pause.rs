//! Pause points inside this crate's opens of a vault database, for tests only
//! (ROADMAP O279): a test swaps a restore in between a connection's
//! `Connection::open` — which takes the file descriptor — and its first
//! statement, which takes the first lock a fence can see.
//!
//! A module of its own, with [`fire`] compiled in every build as a no-op
//! outside tests, on `restore_pause.rs`'s precedent. The hooks are reachable
//! from other crates' tests through the `test-fixture` feature (the CLI's
//! `open_store_as` and `/v1`'s `store_for` are driven through a swap that way),
//! on the vault crate's `fixture` precedent; a production build carries none.

use std::path::Path;

/// Which open stops, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opener {
    /// `connect_writable`: the directory's layout is not yet read (ROADMAP
    /// O281 — the rename step can keep the legacy name, and another open finish
    /// the rename, before this reads it).
    WritableLayout,
    /// `connect_writable`: the descriptor is open; `journal_mode` has not run.
    Writable,
    /// `connect_read_only`: the descriptor is open; the probe has not run.
    ReadOnly,
    /// `connect_read_only`'s `immutable=1` arm: open; its probe has not run.
    Immutable,
    /// `hold_vault_exclusively`: the database was found; it is not yet opened.
    HoldLayout,
    /// `hold_vault_exclusively`: the descriptor is open; `BEGIN EXCLUSIVE` has
    /// not run.
    Hold,
    /// `recorded_embedder`: the descriptor is open; the meta read has not run.
    RecordedEmbedder,
    /// `migrate_db_filename`: the layout was read as legacy; the legacy
    /// database is not yet opened.
    LegacyLayout,
    /// `migrate_db_filename`: the legacy database is open; its hold — the first
    /// statement to take a lock — has not run.
    Legacy,
    /// `migrate_db_filename`: the legacy connection holds the file exclusively
    /// and is checkpointed; the directory is not yet read again and the rename
    /// has not run (ROADMAP O281 — the hold is still taken here).
    LegacyRename,
    /// `lock_released`: the proof connection is open; its read has not run.
    LockProbe,
}

/// Run whatever hook a test set for the vault directory `dir`. A no-op
/// outside tests.
#[inline(always)]
pub(crate) fn fire(dir: &Path, at: Opener) {
    #[cfg(any(test, feature = "test-fixture"))]
    {
        let hook = hooks().lock().unwrap().get(dir).cloned();
        if let Some(hook) = hook {
            hook(at);
        }
    }
    #[cfg(not(any(test, feature = "test-fixture")))]
    let _ = (dir, at);
}

/// A test's hook: called at every pause point of an open of one vault.
#[cfg(any(test, feature = "test-fixture"))]
pub type Hook = std::sync::Arc<dyn Fn(Opener) + Send + Sync>;

#[cfg(any(test, feature = "test-fixture"))]
fn hooks() -> &'static std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Hook>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, Hook>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(Default::default)
}

/// Run `hook` at every pause point of an open of the vault directory `dir`.
#[cfg(any(test, feature = "test-fixture"))]
pub fn set(dir: &Path, hook: Hook) {
    hooks().lock().unwrap().insert(dir.to_path_buf(), hook);
}

/// Remove the hook for `dir`.
#[cfg(any(test, feature = "test-fixture"))]
pub fn clear(dir: &Path) {
    hooks().lock().unwrap().remove(dir);
}
