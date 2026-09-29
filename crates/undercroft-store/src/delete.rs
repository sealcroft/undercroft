//! A vault delete, through one door (ROADMAP O291).
//!
//! `DELETE /v1/vaults/{id}` was `remove_dir_all(vaults/<id>)` with nothing
//! held. Measured on `main` `0667b76`: beside an idle writable handle in
//! another process the delete answered `Ok`, and that handle's next write
//! answered `Ok` too — committed into the unlinked database, then lost; a
//! replica that had read kept serving the deleted vault's content on every
//! later `get`; a symlinked vault or a symlinked database answered
//! `deleted: true` while the content it named survived (a hard link still
//! does: erasure scope is escalated); a directory
//! holding a database and no manifest, or a restore's aside holding the vault,
//! answered 404 — which the orchestrator reads as erased, and then drops the
//! only record of whose content it was.
//!
//! The ruling (ROADMAP O291, `#### RULED 2026-09-29`) follows O69, O257 and
//! O282: a vault directory is removed only under O69's hold, or not at all, by
//! ONE rename out of `vaults/` and a removal judged by what is left. The order
//! is the ruling's, step for step; every step before the rename changes
//! nothing but an empty `vault.db` the door made itself, which it removes on
//! any refusal after its hold was granted.

use undercroft_vault::deletes::{self, Target};
use undercroft_vault::{restores, Access, DbLayout, VaultError, VaultManager, VAULTS_DIR};

use crate::delete_pause::{self as pause, Phase};
use crate::{hold_vault_exclusively, HoldFor, StoreError};

/// What a delete did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deleted {
    /// The vault was removed — or an earlier delete of it, interrupted after
    /// the vault left `vaults/<id>`, was finished.
    Removed,
    /// There was nothing to delete.
    Absent,
}

/// **Delete the vault `id`, holding it** (ROADMAP O291).
///
/// Refused, changing nothing: under a read-only posture; for a bad name; while
/// a restore's aside holds the vault ([`VaultError::RestoreInterrupted`]); for
/// a vault path that is a link or not a directory, or holds any entry that is
/// not a regular file ([`StoreError::Invalid`] — a delete never follows a
/// link, and removing only the link would answer "deleted" over content that
/// survives); for two databases (the integrity class); and while another
/// connection holds the vault ([`StoreError::VaultHeld`]). A failure once the
/// vault has left `vaults/<id>` names where its files are, and a retry of the
/// delete finishes it — a retry never answers [`Deleted::Absent`] over them.
///
/// What [`Deleted::Removed`] promises, and does not, is the ruling's item 14:
/// the vault directory and every regular file in it are gone (synced first on
/// unix), and no connection held a SQLite lock on its database when it was
/// set aside — on a filesystem whose locks the processes share. Archives under
/// `backups/`, a remote mirror, another hard link to a file, an `immutable=1`
/// reader and freed blocks are outside it.
pub fn delete_vault(manager: &VaultManager, id: &str) -> Result<Deleted, StoreError> {
    // (a) the posture, then (b) the name, before anything is read.
    if manager.access() == Access::ReadOnly {
        return Err(StoreError::Vault(VaultError::ReadOnly(
            "deleting a vault removes it, so it is refused under --read-only; nothing was \
             deleted",
        )));
    }
    // `Invalid` (400), the class `/v1` gave a bad name when `vault_err`
    // classified the manager's own refusal; `store_err` has no arm for a
    // wrapped `BadName` and would have answered 500.
    undercroft_core::validate_name(id, "vault").map_err(|e| StoreError::Invalid(e.to_string()))?;
    let root = manager.root();
    let dir = root.join(VAULTS_DIR).join(id);
    // (c) a restore's aside holding the vault: neither 404 nor 200 over it.
    restores::refuse_if_interrupted(root, id)?;
    // (d) what is at the path, never following a link, errors propagated.
    let found = deletes::survey(root, id)?;
    match &found.target {
        Target::Absent => {
            return Ok(if deletes::finish_leftover(root, id)? {
                Deleted::Removed
            } else {
                Deleted::Absent
            })
        }
        Target::NotADirectory(what) => return Err(not_a_vault_file(id, what)),
        Target::Directory => {}
    }
    if let Some(what) = &found.irregular {
        return Err(not_a_vault_file(id, what));
    }
    // (e) two databases.
    if found.layout == DbLayout::Ambiguous {
        return Err(two_databases(id, &dir));
    }
    pause::fire(root, Phase::Surveyed);
    // (f) a directory holding no database gets an empty one to hold, made
    // exclusively: a file already there is a racer's and is never ours.
    let owned = if found.layout == DbLayout::Absent {
        deletes::create_database(root, id)?
    } else {
        None
    };
    // (g) O69's hold. Not granted, the door made no effect but the empty
    // file, which a racer may have adopted — it is left.
    let hold = match hold_vault_exclusively(&dir, HoldFor::Delete) {
        Ok(hold) => hold,
        Err(StoreError::Invalid(_)) if DbLayout::of(&dir) == DbLayout::Ambiguous => {
            return Err(two_databases(id, &dir))
        }
        Err(e) => return Err(e),
    };
    // (h) the checks again, under the hold, then (j) an earlier delete's
    // leftover removed: it must not exist at the rename. A refusal here undoes
    // the empty file under the hold, so a racer holding its descriptor fails
    // its identity check and reopens.
    let ready = recheck(root, id, &dir)
        .map(|()| pause::fire(root, Phase::Held))
        .and_then(|()| {
            deletes::finish_leftover(root, id)
                .map(|_| ())
                .map_err(Into::into)
        });
    if let Err(refused) = ready {
        let refused = undo(owned, refused);
        drop(hold);
        return Err(refused);
    }
    // (k)-(m) ONE rename out of `vaults/`, the directories synced, the hold
    // released — in that order, fixed by the vault crate.
    let aside = match deletes::set_aside(root, id, hold) {
        Ok(aside) => aside,
        Err(failed) => {
            let refused = if failed.moved {
                StoreError::Vault(failed.error)
            } else {
                undo(owned, StoreError::Vault(failed.error))
            };
            drop(failed.hold);
            return Err(refused);
        }
    };
    pause::fire(root, Phase::Aside);
    // (n) the removal, judged by what is left; never `Removed` on a failure.
    aside.remove()?;
    Ok(Deleted::Removed)
}

/// The checks of steps (c)–(e), made again under the hold.
fn recheck(root: &std::path::Path, id: &str, dir: &std::path::Path) -> Result<(), StoreError> {
    restores::refuse_if_interrupted(root, id)?;
    let again = deletes::survey(root, id)?;
    match &again.target {
        Target::Directory => {}
        Target::Absent => {
            return Err(StoreError::VaultHeld(format!(
                "the vault at {} was removed while this delete held it — another delete or a \
                 restore. Nothing was deleted; retry (ROADMAP O291)",
                dir.display()
            )))
        }
        Target::NotADirectory(what) => return Err(not_a_vault_file(id, what)),
    }
    if let Some(what) = &again.irregular {
        return Err(not_a_vault_file(id, what));
    }
    if again.layout == DbLayout::Ambiguous {
        return Err(two_databases(id, dir));
    }
    Ok(())
}

/// Remove the empty database this door made, before its refusal is returned.
/// A removal that fails is logged always, and appended to a `VaultHeld`
/// refusal's text; the other refusals keep their class and text unchanged.
fn undo(owned: Option<deletes::OwnedDatabase>, refused: StoreError) -> StoreError {
    let Some(owned) = owned else {
        return refused;
    };
    match owned.remove_if_empty() {
        Ok(_) => refused,
        Err(e) => {
            undercroft_obs::diag_warn!(
                "a refused vault delete could not remove the empty vault.db it had created: {e}"
            );
            match refused {
                StoreError::VaultHeld(why) => StoreError::VaultHeld(format!(
                    "{why} (and the empty vault.db this delete created could not be removed: \
                     {e})"
                )),
                other => other,
            }
        }
    }
}

fn not_a_vault_file(id: &str, what: &str) -> StoreError {
    StoreError::Invalid(format!(
        "vault '{id}' is not deleted: {what}. A delete removes only the regular files a vault \
         holds and never follows a link — removing a link alone would answer \"deleted\" while \
         what it names survives. Replace the link with what it names, or move the entry out, \
         then delete. Nothing was deleted (ROADMAP O291, extending O283)"
    ))
}

fn two_databases(id: &str, dir: &std::path::Path) -> StoreError {
    StoreError::IntegrityFinding(format!(
        "vault '{id}' holds two databases, {} and the pre-1.5.0 {}, in {}. A delete removes a \
         vault only when it can hold every database in it: move the one that is not this \
         vault's aside (verify each), then delete. Nothing was deleted (ROADMAP O291, O7)",
        undercroft_vault::DB_FILE,
        undercroft_vault::LEGACY_DB_FILE,
        dir.display()
    ))
}
