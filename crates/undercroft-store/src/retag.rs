//! **The version-2 row-tag walk** (ROADMAP O406 items 4–6).
//!
//! A vault's row tags are in ONE format, decided by ONE record: the
//! `migrate/tag-v2` commitment, read by exact label and `MIN(seq)` — O233's
//! shape, never a clear `meta` row an offline writer could delete. A vault
//! without it is in the version-1 regime and keeps WRITING version 1, so no
//! vault holds rows of both formats; a vault with it never accepts a
//! version-1 tag, so a row written back from before the switch fails its tag
//! with no per-row bookkeeping.
//!
//! The walk runs once, at a writable open, after A10, U12 and O233's switch
//! and withheld while any of them is pending; never while a
//! `vault.json.next` or a deferral is in force; and under O257's exclusive
//! hold, so no other process — a released binary included — holds the vault
//! while its format moves. Inside the hold it verifies first: any finding
//! [`crate::VerifyReport::walk_blockers`] names, or any ERROR from that
//! verify, withholds it entirely — nothing written, the reason on
//! `unhealed`, and never a failed open, because a walk inside `open` that
//! aborts would leave the vault unopenable for `verify` and `repair` (the
//! embedder walk's lesson). Otherwise, in this order: `vault.json` is
//! raised to version 2, then ONE transaction re-tags every row of every
//! tagged table — through the per-table re-tag a rotation uses — and appends
//! the commitment; COMMIT; anchor. The raise comes first so a crash between
//! the two leaves a version-2 manifest over version-1 rows (older binaries
//! fenced, this build retries), never a version-1 manifest over version-2
//! rows, which a released 1.6.1 would open, heal forward and write version-1
//! rows into.
//!
//! No VACUUM and no per-row record: a re-tag removes no confidential byte
//! (content and meta are not rewritten, and every version-1 tag already sits
//! verbatim in `audit.tag`), and one record per row would double `audit` and
//! every later label-guard replay for good.

use rusqlite::{params, Connection, OptionalExtension};
use undercroft_vault::RowFormat;

use crate::manage::Namespace;
use crate::rotate::Reseal;
use crate::{ExclusiveHold, StoreError, VaultStore};

/// The rest of the commitment's label, under [`Namespace::Migrate`].
pub(crate) const TAG_COMMITMENT_KIND: &str = "tag-v2";

/// The commitment's label: `migrate/tag-v2`.
pub(crate) fn commitment_label() -> String {
    Namespace::Migrate.record(TAG_COMMITMENT_KIND)
}

/// A vault's tag regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagRegime {
    /// No commitment: every row tag is version 1, and so is the next.
    V1,
    /// The commitment sits at `switch_seq`: every row tag is version 2.
    V2 {
        /// The commitment record's `seq`.
        switch_seq: i64,
    },
}

impl TagRegime {
    /// The row format this regime reads and writes.
    pub(crate) fn format(self) -> RowFormat {
        match self {
            TagRegime::V1 => RowFormat::V1,
            TagRegime::V2 { .. } => RowFormat::V2,
        }
    }
}

/// Read the tag regime: the FIRST row carrying the commitment's label — an
/// indexed equality on `record_id`. `MIN`, so a copy of the label appended
/// later moves nothing; the chain replay is what refuses such a copy.
pub(crate) fn tag_regime(conn: &Connection) -> Result<TagRegime, StoreError> {
    let switch: Option<i64> = conn.query_row(
        "SELECT MIN(seq) FROM audit WHERE record_id = ?1",
        params![commitment_label()],
        |r| r.get(0),
    )?;
    Ok(match switch {
        Some(switch_seq) => TagRegime::V2 { switch_seq },
        None => TagRegime::V1,
    })
}

/// What the walk did.
enum Walk {
    /// Every row re-tagged and the commitment appended.
    Walked,
    /// Another handle walked first.
    Already,
    /// Withheld, for the reason given.
    Withheld(String),
}

/// The withheld note's head, shared by every reason.
fn withheld(reason: &str) -> String {
    format!(
        "this vault's row tags are still in the version-1 format, whose fields a writer \
         WITHOUT the key can re-partition — or carry from one table to another — under a tag \
         that still verifies: the switch to the version-2 row canonical (ROADMAP O406) is \
         WITHHELD because {reason}. No row was re-tagged and no commitment appended; the \
         next writable open retries"
    )
}

impl VaultStore {
    /// The row-tag format this handle reads and writes (ROADMAP O406 item 4).
    pub(crate) fn row_format(&self) -> RowFormat {
        self.row_format.get()
    }

    /// Adopt the regime the database records — at assembly, and after this
    /// handle's own walk. The manifest version this handle's anchors write
    /// follows it, and never goes down.
    pub(crate) fn adopt_tag_regime(&mut self, regime: TagRegime) {
        let fmt = regime.format();
        self.row_format.set(fmt);
        self.vault.require_manifest_version(fmt.manifest_version());
    }

    /// **The manifest and the commitment, read together** (ROADMAP O406
    /// item 6), at every open before anything heals: a version-2 regime
    /// beside a version-1 manifest anchored AT or PAST the commitment's
    /// height is a state no writer of this design produces — the walk raises
    /// the manifest before its transaction — and so an integrity finding. One
    /// anchored BELOW the commitment is a stale manifest; the writable open
    /// heals it forward like any lag, and the anchor raises it.
    pub(crate) fn judge_tag_regime(&self) -> Result<(), StoreError> {
        let TagRegime::V2 { switch_seq } = tag_regime(&self.conn)? else {
            return Ok(());
        };
        let manifest = self.vault.verified_manifest()?;
        if manifest.version() >= RowFormat::V2.manifest_version() {
            return Ok(());
        }
        let height: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE seq <= ?1",
            params![switch_seq],
            |r| r.get(0),
        )?;
        if manifest.writes() >= height.max(0) as u64 {
            return Err(StoreError::IntegrityFinding(format!(
                "the database records the switch to the version-2 row tags (`{}` at audit seq \
                 {switch_seq}) and vault.json is a version-{} manifest anchored at height {}, \
                 at or past that switch: no writer of this build produces that pair — the walk \
                 raises the manifest BEFORE the transaction that records the switch. The \
                 manifest was rewritten, or the database is not the one this manifest anchors. \
                 {}; this open stops before it heals the anchor or re-tags a row. Run \
                 `undercroft verify` (ROADMAP O406)",
                commitment_label(),
                manifest.version(),
                manifest.writes(),
                crate::CHAIN_AS_FOUND
            )));
        }
        Ok(())
    }

    /// **The walk, at a writable open** (ROADMAP O406 item 5). Never fails
    /// the open for its own reasons: a withheld walk is a note on
    /// `unhealed`. It fails the open only when the exclusive hold it took
    /// cannot be proven released — the rotation's rule — because a handle
    /// that cannot let go of the vault must not be handed back as one that
    /// did.
    pub(crate) fn walk_tags_to_v2(&mut self) -> Result<(), StoreError> {
        if self.row_format() == RowFormat::V2 {
            return Ok(());
        }
        match self.walk_precondition() {
            Ok(None) => {}
            Ok(Some(reason)) => {
                self.note_walk(reason);
                return Ok(());
            }
            Err(e) => {
                self.note_walk(format!("its preconditions could not be read ({e})"));
                return Ok(());
            }
        }
        // Warmed outside the hold: on a vault that has none, its first use
        // writes one. A secret that does not open is a finding `verify`
        // names, and the walk's own reason to wait — never the open's
        // failure, or one byte flipped offline in `meta` would make every
        // writable open of an unwalked vault refuse (review of O406).
        if let Err(e) = self.kg_secret() {
            self.note_walk(format!(
                "the knowledge-graph secret could not be read ({e})"
            ));
            return Ok(());
        }
        let at = crate::manage::now_rfc3339();
        let walked = self.walk_held(&at);
        self.prove_released();
        if let Some(retirement) = self.vault.retirement() {
            return Err(crate::retired_handle(retirement));
        }
        match walked {
            Ok(Walk::Walked) => {
                self.adopt_tag_regime(tag_regime(&self.conn)?);
                // This connection's own commit moves no cookie, so a verdict
                // cached before it would outlive the chain it described.
                self.forget_label_verdict();
                self.anchor()?;
            }
            Ok(Walk::Already) => self.adopt_tag_regime(tag_regime(&self.conn)?),
            Ok(Walk::Withheld(reason)) => self.note_walk(reason),
            Err(StoreError::VaultHeld(_)) => self.note_walk(
                "another process has the vault open — a reader, a server, an older binary — \
                 and the switch must hold it alone"
                    .to_string(),
            ),
            Err(e) => self.note_walk(format!("the walk met an error ({e})")),
        }
        Ok(())
    }

    /// Why the walk cannot start, read before any lock: the three at-rest
    /// steps it follows, a staged manifest, a retired handle.
    fn walk_precondition(&self) -> Result<Option<String>, StoreError> {
        if let Some(why) = self.vault.retired() {
            return Ok(Some(format!("this handle no longer writes ({why})")));
        }
        if crate::retag_pause::kept_on_v1(self.vault.dir()) {
            return Ok(Some(
                "a test kept this vault on the version-1 regime".into(),
            ));
        }
        if !self.kg_blind_complete()? {
            return Ok(Some(
                "the knowledge-graph blinding migration (A10) has not completed, and it \
                 re-tags and relabels graph rows"
                    .into(),
            ));
        }
        if !self.content_fp_complete()? {
            return Ok(Some(
                "the content-fingerprint re-key (U12) has not completed, and it re-tags receipts"
                    .into(),
            ));
        }
        if crate::chain::regime(&self.conn)? == crate::chain::Regime::V1 {
            return Ok(Some(
                "the audit chain has not switched to its labelled step (ROADMAP O233), which \
                 the commitment this switch appends is stepped under"
                    .into(),
            ));
        }
        if self.vault.has_pending() || self.vault.staged_on_disk()?.is_some() {
            return Ok(Some(
                "a vault.json.next is present: a key rotation's staged manifest, or one this \
                 build could not authenticate, and the switch raises the manifest version"
                    .into(),
            ));
        }
        Ok(None)
    }

    /// The walk's work under the exclusive hold. Every `?` drops the hold,
    /// which rolls the transaction back.
    fn walk_held(&mut self, at: &str) -> Result<Walk, StoreError> {
        let mut hold = ExclusiveHold::take(&self.conn)?;
        if tag_regime(&self.conn)? != TagRegime::V1 {
            return Ok(Walk::Already);
        }
        // Verify first, in the hold's own transaction, the anchor read in
        // place: nothing else can even open the vault while it is held, so
        // the anchor and the rows are one state (O232, O253).
        let anchor = self.vault.anchored_head()?;
        let blockers = self.verify_in(&hold.snapshot()?, &anchor)?.walk_blockers();
        if !blockers.is_empty() {
            let n = blockers.len();
            let shown: Vec<&str> = blockers.iter().take(5).map(String::as_str).collect();
            return Ok(Walk::Withheld(format!(
                "`verify` has {n} finding(s) the switch would bind — re-tagging binds whatever \
                 partition the columns hold, and destroys the one authenticated recovery \
                 version 1 still allows: {}{}",
                shown.join("; "),
                if n > shown.len() { "; …" } else { "" }
            )));
        }
        // Every new tag computed IN MEMORY before anything is written, so a
        // refusal there — a mirror marker that does not verify, a row no read
        // takes — leaves both files as found rather than a raised manifest.
        let retagged = match self.retag_rows(&self.vault, RowFormat::V2, Reseal::No) {
            Ok(r) => r,
            Err(e) => {
                return Ok(Walk::Withheld(format!(
                    "a row could not be re-tagged ({e})"
                )))
            }
        };
        let keycheck: Option<String> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
                r.get(0)
            })
            .optional()?;
        // The raise FIRST of the writes, through the one manifest writer
        // (item 5): a crash after it leaves older binaries fenced and this
        // build retrying, never a version-1 manifest over version-2 rows.
        if let Err(fault) = self
            .vault
            .raise_manifest_version(RowFormat::V2.manifest_version(), keycheck.as_deref())
        {
            return Ok(Walk::Withheld(format!(
                "vault.json could not be raised to version 2 ({fault:?})"
            )));
        }
        crate::retag_pause::fire(self.vault.dir(), crate::retag_pause::Phase::Raised);
        self.apply_retagged(&self.conn, &retagged)?;
        Self::audit_migration(
            &self.conn,
            &self.vault,
            TAG_COMMITMENT_KIND,
            "v2",
            at,
            retagged.rows(),
            0,
        )?;
        crate::retag_pause::fire(self.vault.dir(), crate::retag_pause::Phase::Applied);
        hold.commit()?;
        Ok(Walk::Walked)
    }

    fn note_walk(&mut self, reason: String) {
        let note = withheld(&reason);
        undercroft_obs::diag_warn!("vault {:?}: {note}", self.vault.id());
        self.unhealed.push(note);
    }

    /// What a READ-ONLY open says about a vault still in the version-1
    /// regime: it verifies in the regime it finds and walks nothing.
    pub(crate) fn note_pending_walk(&mut self) {
        if self.row_format() == RowFormat::V1 {
            self.unhealed.push(
                "this vault's row tags are still in the version-1 format, whose fields a writer \
                 WITHOUT the key can re-partition — or carry from one table to another — under \
                 a tag that still verifies: a writable open of this build switches them to the \
                 version-2 row canonical (ROADMAP O406); a read-only open writes nothing"
                    .to_string(),
            );
        }
    }
}
