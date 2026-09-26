//! `backup create`: the archive IS the state `verify` judged (ROADMAP O256).
//!
//! Both surfaces used to verify through a store, DROP it, and copy the
//! vault's directory as plain files with no connection and no lock. Measured
//! beside a writer: 11 of 40 copies failed outright (a file `read_dir` listed
//! was gone before it was copied), 2 of the 29 written restored as
//! `ManifestTampered`, and 16 held a chain height the verify never saw. A
//! checkpoint between the main file and its `-wal` tore the database, and a
//! key rotation between the database and the manifest paired two key
//! generations — nothing held the vault, so O257's fence could not see it.
//!
//! Now ONE door, both surfaces: the manifest's exact bytes read once before
//! the snapshot is pinned; inside that one snapshot the key generation
//! compared, the verify, and SQLite's online backup API copying the pages of
//! exactly that state; the copy synced and its committed head and height
//! required to EQUAL the snapshot's; the manifest written beside it; one
//! rename to publish. The connection is held throughout, which is what
//! O257's fence sees.

use std::path::Path;

use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use undercroft_vault::backups::{self, Stage};

use crate::backup_pause::{self as pause, Phase};
use crate::{chain, StoreError, VaultStore, VerifyReport};

/// What `backup create` archived: the archive's name and the state it holds.
///
/// `writes` and `chain_head` are the archive's IDENTITY — the committed chain
/// the copied rows hold, which is the state the verify judged — and what a
/// runbook should record beside the name.
#[derive(Debug, Clone, Serialize)]
pub struct BackupReport {
    /// The archive's directory name under `backups/`.
    pub name: String,
    /// The vault it is a copy of.
    pub vault: String,
    /// The committed chain height the archived rows hold.
    pub writes: u64,
    /// The committed chain head the archived rows hold.
    pub chain_head: String,
    /// How many records the archived manifest's anchor lags those rows by.
    /// Zero in a quiet vault; above zero beside a writer or on a
    /// read-audited deployment, and a restore then heals the lag as a crash
    /// and says so (ROADMAP O246). Never healed INTO the archive: the anchor
    /// is carried as found, because on a vault whose anchor was lowered it is
    /// the one observable left (A2).
    pub anchor_behind_by: u64,
    /// Whether the archive's `vault.json` is the STAGED manifest of a
    /// committed key rotation whose promote was deferred (ROADMAP O266): the
    /// manifest the archived rows answer to, byte for byte `vault.json.next`,
    /// while the live `vault.json` still names the previous key generation. A
    /// restore opens the archive as an ordinary vault; this is its provenance.
    pub promote_deferred: bool,
    /// This vault's older archives removed to keep the newest ten.
    pub pruned: usize,
}

/// What [`VaultStore::backup`] did.
#[derive(Debug)]
pub enum BackupOutcome {
    /// The vault verified, and this archive of that state was published.
    Created(BackupReport),
    /// The vault failed its own verification, and nothing was archived.
    Refused(Box<VerifyReport>),
}

fn io(e: std::io::Error) -> StoreError {
    StoreError::Vault(undercroft_vault::VaultError::Io(e))
}

/// A connection to a copied database that writes NOTHING beside it — not the
/// `-shm` and `-wal` scaffolding an ordinary read-only open of a WAL-mode file
/// creates, which would put a third and fourth file in the stage.
pub(crate) fn open_immutable(path: &Path) -> Result<Connection, StoreError> {
    Ok(Connection::open_with_flags(
        immutable_uri(path),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?)
}

/// The `immutable=1` URI of a database file — the one builder both this door
/// and the read-only open's escalation use. `%` is escaped first, so a path
/// holding a literal `%3f` is not decoded into a `?`.
pub(crate) fn immutable_uri(path: &Path) -> String {
    format!(
        "file:{}?immutable=1",
        path.to_string_lossy()
            .replace('%', "%25")
            .replace('?', "%3f")
            .replace('#', "%23")
    )
}

impl VaultStore {
    /// **Archive this vault into `backups`, as exactly the state it verified**
    /// (ROADMAP O256).
    ///
    /// Refused as `Invalid` inside a snapshot this handle opened or inside a
    /// caller's transaction: nested, the manifest would be read after the
    /// pin, and inline, SQLite refuses to copy from a connection holding a
    /// write transaction. A failed verify archives nothing and answers
    /// [`BackupOutcome::Refused`]. Any failure after the verify passed — the
    /// copy, its sync, the post-condition, the publish — is an I/O-class
    /// error, never an integrity verdict: the live vault verified.
    ///
    /// It decides no posture: a read-only handle can take one (the page copy
    /// only reads), and whether `--read-only` SHOULD is ROADMAP O212's.
    pub fn backup(&self, backups_dir: &Path) -> Result<BackupOutcome, StoreError> {
        if self.owned_snapshots.get() > 0 || !self.conn.is_autocommit() {
            return Err(StoreError::Invalid(
                "a backup opens its own snapshot and cannot run inside a transaction or \
                 another snapshot (ROADMAP O256)"
                    .into(),
            ));
        }
        // What `verify` does first, for its reason: a first use of the graph
        // secret WRITES it, which the snapshot's `query_only` refuses.
        self.kg_secret()?;
        // ONCE, before the pin, with no fall-back: its head is the anchor the
        // rows are compared with, and its bytes are what the archive carries.
        // During a deferred promote that is `vault.json.next`'s manifest —
        // the one the rows answer to (ROADMAP O266, refining O256 item 3).
        let manifest = self.vault.verified_manifest()?;
        let vault_dir = self.vault.dir().to_path_buf();
        pause::fire(&vault_dir, Phase::ManifestRead);
        let stage = Stage::begin(backups_dir).map_err(io)?;
        // No journal and no fsync while the snapshot is pinned: a crash leaves
        // a torn STAGE, which is never an archive, and the copy is synced
        // once, after the snapshot ends. Never WAL: the copy's pages would
        // sit in a `-wal` the archive does not carry.
        let mut dst = Connection::open(stage.db_path())?;
        let mode: String = dst.query_row("PRAGMA journal_mode=OFF", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("off") {
            return Err(io(std::io::Error::other(format!(
                "the backup's destination refused journal_mode=OFF (it reads {mode})"
            ))));
        }
        dst.pragma_update(None, "synchronous", "OFF")?;
        let judged = self.snapshot(|snap| {
            pause::fire(&vault_dir, Phase::Pinned);
            // O257's fence already refuses a rotation while this connection is
            // open; this covers where locks do not work. The same refusal
            // the write door and the rotation give for the same condition.
            let db_keycheck: Option<String> = snap
                .conn()
                .query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
                    r.get(0)
                })
                .optional()?;
            if db_keycheck.as_deref() != Some(self.vault.keycheck()) {
                return Err(crate::stale_keys(db_keycheck.as_deref()));
            }
            let report = self.verify_in(snap, manifest.chain_head())?;
            if !report.ok() {
                return Ok(Err(report));
            }
            pause::fire(&vault_dir, Phase::Verified);
            // SQLite reuses the read transaction this connection holds, so
            // these are the pages `verify_in` just read. `step(-1)` answers
            // `Ok` for Busy, Locked and More as well as Done: anything but
            // Done is a copy that did not happen.
            let step = Backup::new(snap.conn(), &mut dst)?.step(-1)?;
            if step != StepResult::Done {
                return Err(io(std::io::Error::other(format!(
                    "the page copy did not complete ({step:?}); nothing was archived"
                ))));
            }
            pause::fire(&vault_dir, Phase::Copied);
            let head = chain::require_head(snap.conn())?.head;
            let writes = chain::writes(snap.conn())?;
            Ok(Ok((head, writes)))
        })?;
        let (chain_head, writes) = match judged {
            Ok(state) => state,
            Err(report) => return Ok(BackupOutcome::Refused(Box::new(report))),
        };
        drop(dst);
        std::fs::OpenOptions::new()
            .write(true)
            .open(stage.db_path())
            .and_then(|f| f.sync_all())
            .map_err(io)?;
        pause::fire(&vault_dir, Phase::Synced);
        // The post-condition: the COPY holds the state the snapshot held. Not
        // a second verify — the copy is that snapshot's pages — but it turns
        // a copy taken anywhere else (a refactor moving the step out of the
        // snapshot) into a refusal rather than a silently later archive.
        let (copied_head, copied_writes) = {
            let copy = open_immutable(&stage.db_path())?;
            (chain::require_head(&copy)?.head, chain::writes(&copy)?)
        };
        if (copied_head.as_str(), copied_writes) != (chain_head.as_str(), writes) {
            return Err(io(std::io::Error::other(format!(
                "the copied database holds chain height {copied_writes}, not the verified \
                 {writes}; nothing was archived (ROADMAP O256)"
            ))));
        }
        stage.write_manifest(&manifest).map_err(io)?;
        pause::fire(&vault_dir, Phase::Staged);
        let name =
            backups::archive_name(self.vault.id(), time::OffsetDateTime::now_utc()).map_err(io)?;
        stage.publish(&name).map_err(io)?;
        let pruned = backups::prune(backups_dir, self.vault.id(), backups::KEEP).map_err(io)?;
        Ok(BackupOutcome::Created(BackupReport {
            name,
            vault: self.vault.id().to_string(),
            anchor_behind_by: writes.saturating_sub(manifest.writes()),
            promote_deferred: manifest.is_staged(),
            writes,
            chain_head,
            pruned,
        }))
    }
}
