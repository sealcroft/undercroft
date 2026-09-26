//! `backup restore`: the archive is proven before the vault it replaces is
//! touched (ROADMAP O268).
//!
//! Both surfaces took O69's hold, REMOVED the vault and then copied the archive
//! in, checking only that the archive had a `vault.json` — whose id they did not
//! verify. Measured on `main` `4d0a658`: a manifest ahead of its rows, a
//! truncated database, another installation's archive and one flipped byte each
//! restored at exit 0 over a working vault, which then refused to open.
//!
//! Now ONE door both surfaces call, in this order: the archive copied into a
//! stage under `vaults/` (the vault crate's `restores.rs`); the stage unlocked
//! — its manifest's MAC, keyed by the very id it names — opened writable with
//! the surface's own embedder, so what is swapped in is the verified
//! post-migration state; `verify` over every leg and SQLite's `integrity_check`,
//! because `verify` never reads an index; the store closed and the stage
//! required to hold exactly the database and the manifest, at the verified head
//! and height. Only THEN is the live vault held, and swapped by two renames. A
//! refusal caused by the archive never reaches the live vault: it changes no
//! byte of it.

use std::path::Path;

use rusqlite::{Connection, ErrorCode, OpenFlags};
use serde::Serialize;
use undercroft_core::embed::Embedder;
use undercroft_vault::restores::{Archive, Stage};
use undercroft_vault::{Access, DbLayout, Vault, VaultError, VaultManager, DB_FILE, MANIFEST_FILE};

use crate::restore_pause::{self as pause, Phase};
use crate::{chain, StoreError, VaultStore, VerifyReport};

/// What `backup restore` put in place, and what it found on the way.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    /// The vault restored.
    pub vault: String,
    /// The archive's directory name under `backups/`.
    pub archive: String,
    /// The committed chain height the archive's database held, read before
    /// the stage's open appended anything. For an archive `backup create`
    /// wrote since 1.7.0 it EQUALS that report's `writes` — which is how an
    /// operator tells the archive they meant from an older one renamed to look
    /// like it. `None` for a schema that predates the chain table.
    pub archived_writes: Option<u64>,
    /// The committed chain head the archive's database held, as above.
    pub archived_chain_head: Option<String>,
    /// The committed chain height of the vault swapped in: the archive's, plus
    /// whatever the open's migrations appended (a version-2 switch appends one
    /// record).
    pub writes: u64,
    /// The committed chain head of the vault swapped in.
    pub chain_head: String,
    /// What the stage's open healed or left alone, in the operator's words —
    /// including a lagging manifest anchor it fast-forwarded (ROADMAP O246),
    /// which the restored vault's next open can no longer see.
    pub unhealed: Vec<String>,
    /// The embedder identity the stage's open re-recorded, `from -> to`: a
    /// known migration of the built-in embedder, or a declared
    /// `UNDERCROFT_FORCE_EMBEDDER=1`. `None` when it recorded nothing new.
    pub embedder_rerecorded: Option<String>,
    /// Whether the vault replaced was of ANOTHER key generation than the
    /// archive — a key rotation happened after the archive was taken, and a
    /// restore brings the retired keys back, so rotate again if that rotation
    /// answered a compromise. `None` when no vault was replaced or its
    /// manifest could not be read as one.
    pub key_generation_differs: Option<bool>,
    /// Whether a vault stood at `vaults/<id>` and was replaced.
    pub replaced: bool,
    /// Entries of the archive the restore did not copy, and a staged rotation
    /// manifest the open could not authenticate (left in the archive).
    pub skipped: Vec<String>,
}

/// What [`restore_archive`] did.
#[derive(Debug)]
pub enum RestoreOutcome {
    /// The archive verified, and it is now the vault.
    Restored(RestoreReport),
    /// The archive failed its own verification; nothing was restored and the
    /// live vault was not changed.
    Refused(Box<VerifyReport>),
}

/// How a surface builds the embedder a staged vault records: the CLI's and
/// `/v1`'s one factory, never a copy of it.
pub type EmbedderFor<'a> = &'a dyn Fn(&Vault) -> Result<Box<dyn Embedder + Send>, StoreError>;

/// Which step of proving the stage raised an error — it decides what one
/// ambiguous variant means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Read,
    Unlock,
    Open,
    Verify,
}

const UNCHANGED: &str = "nothing was restored and the live vault was not changed";

/// Class an error raised while proving the STAGE: anything that says the
/// archive's own bytes do not hold together is an integrity verdict about the
/// archive — including SQLite's corruption codes and a column that does not
/// decode, which are NOT integrity verdicts anywhere else in the tree (ROADMAP
/// O269). That is sound here and only here: the stage is a private copy this
/// process just wrote, so its corruption is the archive's.
fn archive_verdict(e: StoreError, archive: &str, step: Step) -> StoreError {
    let why = match &e {
        // `ManifestTampered` has two sources and they mean different things:
        // the unlock's MAC comparison, and the open's finding that the
        // manifest anchors a head the database does not reach.
        StoreError::Vault(VaultError::ManifestTampered) if step == Step::Unlock => Some(
            "its manifest fails its MAC under this installation's key — a torn archive taken \
             by 1.6.1 or earlier beside a writer, or one from another installation; the MAC \
             cannot tell them apart"
                .to_string(),
        ),
        StoreError::Vault(VaultError::ManifestTampered) => Some(
            "its manifest anchors a chain head its database does not reach — rows missing \
             beneath a genuine manifest, as in an archive copied as files beside a writer by \
             1.6.1 or earlier, or a database rolled back"
                .to_string(),
        ),
        StoreError::Vault(VaultError::CorruptManifest(_))
        | StoreError::Integrity(_)
        | StoreError::IntegrityFinding(_)
        | StoreError::Attestation(_)
        | StoreError::DatabaseMissing { .. }
        | StoreError::DatabaseAmbiguous { .. }
        | StoreError::CorruptRow { .. }
        | StoreError::Sqlite(rusqlite::Error::FromSqlConversionFailure(..)) => Some(e.to_string()),
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(f, _))
            if matches!(f.code, ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) =>
        {
            Some(e.to_string())
        }
        _ => None,
    };
    match why {
        Some(why) => StoreError::IntegrityFinding(format!(
            "backup {archive} does not verify, so {UNCHANGED}: {why}"
        )),
        None => e,
    }
}

/// The committed chain the stage's database holds before any open touches it
/// — through a plain read-only connection, which reads a `-wal` a 1.6.1
/// archive may carry (an `immutable` one would not). `None` for a schema with
/// no chain table, or one that does not read.
fn archived_state(vault: &Vault) -> Option<(String, u64)> {
    let conn =
        Connection::open_with_flags(vault.db_path(), OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    let head = chain::require_head(&conn).ok()?.head;
    let writes = chain::writes(&conn).ok()?;
    Some((head, writes))
}

impl VaultStore {
    /// SQLite's own check of the database's structure — every b-tree, every
    /// index against its table. `verify` walks tags and the chain and never an
    /// index: one flipped byte in an index page passed `verify` on four of seven
    /// pages tried while `integrity_check` named the missing rows, and
    /// `quick_check` passed all seven (ROADMAP O268, R3).
    fn storage_check(&self) -> Result<(), StoreError> {
        let mut stmt = self.conn.prepare("PRAGMA integrity_check")?;
        let found: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        if found == ["ok"] {
            return Ok(());
        }
        Err(StoreError::IntegrityFinding(format!(
            "SQLite's integrity_check fails: {}",
            found.iter().take(5).cloned().collect::<Vec<_>>().join("; ")
        )))
    }
}

/// **Restore the archive at `archive_dir` over its vault, proving it first**
/// (ROADMAP O268).
///
/// `expected` is the vault the caller addressed (`/v1` names one; the CLI
/// restores whichever vault the archive's manifest names), checked against the
/// archive before anything is copied and bound by the manifest's MAC when the
/// stage is unlocked. `force` allows replacing a vault that exists. `embedder`
/// is the surface's one factory.
///
/// Refused under a read-only posture before any effect. An archive that does
/// not verify answers [`RestoreOutcome::Refused`] or an integrity finding, and
/// changes no byte of the live vault; a vault another process holds answers
/// [`StoreError::VaultHeld`], also before any change.
pub fn restore_archive(
    manager: &VaultManager,
    archive_dir: &Path,
    expected: Option<&str>,
    force: bool,
    embedder: EmbedderFor<'_>,
) -> Result<RestoreOutcome, StoreError> {
    if manager.access() == Access::ReadOnly {
        return Err(StoreError::Vault(VaultError::ReadOnly(
            "restoring a backup replaces a vault, so it is refused under --read-only; nothing \
             was changed",
        )));
    }
    let name = archive_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let root = manager.root();
    let archive = Archive::read(archive_dir)
        .map_err(|e| archive_verdict(StoreError::Vault(e), &name, Step::Read))?;
    let id = archive.id().to_string();
    if let Some(want) = expected {
        if id != want {
            return Err(StoreError::Invalid(format!(
                "backup '{name}' holds vault '{id}', not '{want}'"
            )));
        }
    }
    undercroft_vault::restores::refuse_if_interrupted(root, &id)?;
    let target = root.join(undercroft_vault::VAULTS_DIR).join(&id);
    if std::fs::symlink_metadata(&target).is_ok() && !force {
        return Err(StoreError::Invalid(format!(
            "vault '{id}' exists; pass --force to overwrite it with the backup ({UNCHANGED})"
        )));
    }
    if !archive.irregular().is_empty() {
        return Err(StoreError::IntegrityFinding(format!(
            "backup {name} does not verify, so {UNCHANGED}: it holds {:?} as something other \
             than a regular file — a link or a directory — which no archive `backup create` \
             writes (ROADMAP O268)",
            archive.irregular()
        )));
    }
    pause::fire(root, Phase::ArchiveRead);
    let stage = Stage::copy(root, &archive)?;
    pause::fire(root, Phase::Staged);
    let vault = manager
        .unlock_stage(&stage)
        .map_err(|e| archive_verdict(StoreError::Vault(e), &name, Step::Unlock))?;
    // A writable open of a directory with no database CREATES one, which would
    // then fail verify as a broken chain — say what is actually wrong instead
    // (the O213 distinction: a manifest that records writes is missing data).
    if vault.db_layout() == DbLayout::Absent {
        return Err(if vault.writes() > 0 {
            StoreError::IntegrityFinding(format!(
                "backup {name} does not verify, so {UNCHANGED}: its manifest records {} write(s) \
                 and it holds no database",
                vault.writes()
            ))
        } else {
            StoreError::Invalid(format!("backup {name} holds no database; {UNCHANGED}"))
        });
    }
    let archived = archived_state(&vault);
    let recorded_before = VaultStore::recorded_embedder(&vault).ok().flatten();
    let embedder = embedder(&vault)?;
    let store = VaultStore::open_with_embedder(vault, embedder)
        .map_err(|e| archive_verdict(e, &name, Step::Open))?;
    let report = store
        .verify()
        .map_err(|e| archive_verdict(e, &name, Step::Verify))?;
    if !report.ok() {
        return Ok(RestoreOutcome::Refused(Box::new(report)));
    }
    store
        .storage_check()
        .map_err(|e| archive_verdict(e, &name, Step::Verify))?;
    pause::fire(root, Phase::Verified);
    let (chain_head, writes) = store.chain_state()?;
    let unhealed = store.unhealed().to_vec();
    let (now_name, now_dim) = (
        store.embedder.model_name().to_string(),
        store.embedder.dimension(),
    );
    let embedder_rerecorded = recorded_before.and_then(|(was, was_dim)| {
        let moved = was != now_name || (was_dim != 0 && was_dim != now_dim);
        moved.then(|| format!("{was}@{was_dim} -> {now_name}@{now_dim}"))
    });
    drop(store);
    // The post-condition. A staged rotation manifest the open could neither
    // promote nor discard did not authenticate: it is inert, stays in the
    // archive, and is not carried into the vault.
    let mut skipped: Vec<String> = archive.skipped().to_vec();
    if stage
        .discard_unpromoted_staging()
        .map_err(|e| StoreError::Vault(e.into()))?
    {
        skipped.push(format!(
            "{} (it did not authenticate; left in the archive)",
            undercroft_vault::STAGING_FILE
        ));
    }
    let held = stage.entries().map_err(|e| StoreError::Vault(e.into()))?;
    if held != [DB_FILE, MANIFEST_FILE] {
        return Err(StoreError::Vault(VaultError::Io(std::io::Error::other(
            format!(
            "the restored copy holds {held:?} after its store closed, not exactly {DB_FILE} and \
             {MANIFEST_FILE}; {UNCHANGED} (ROADMAP O268)"
        ),
        ))));
    }
    let (copied_head, copied_writes) = {
        let copy = crate::backup::open_immutable(&stage.dir().join(DB_FILE))?;
        (chain::require_head(&copy)?.head, chain::writes(&copy)?)
    };
    if (copied_head.as_str(), copied_writes) != (chain_head.as_str(), writes) {
        return Err(StoreError::Vault(VaultError::Io(std::io::Error::other(
            format!(
            "the restored copy holds chain height {copied_writes} after its store closed, not the \
             verified {writes}; {UNCHANGED} (ROADMAP O268)"
        ),
        ))));
    }
    pause::fire(root, Phase::Closed);
    let key_generation_differs = archive.key_generation_differs(root);
    // O69's hold, taken only now: every refusal the archive can cause has
    // already been made, so none of them reaches the live vault.
    let hold = if std::fs::symlink_metadata(&target).is_ok() {
        Some(crate::hold_vault_exclusively(&target).map_err(|e| match e {
            StoreError::Invalid(why) => StoreError::Invalid(format!(
                "{why}; {UNCHANGED} (a vault with no database is ROADMAP O270)"
            )),
            other => other,
        })?)
    } else {
        None
    };
    pause::fire(root, Phase::Held);
    let swapped = stage.swap(hold)?;
    Ok(RestoreOutcome::Restored(RestoreReport {
        vault: id,
        archive: name,
        archived_writes: archived.as_ref().map(|(_, w)| *w),
        archived_chain_head: archived.map(|(h, _)| h),
        writes,
        chain_head,
        unhealed,
        embedder_rerecorded,
        key_generation_differs,
        replaced: swapped.replaced,
        skipped,
    }))
}
