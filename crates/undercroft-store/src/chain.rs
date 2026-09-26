//! The audit chain's arithmetic and its committed head, in ONE place
//! (ROADMAP O233).
//!
//! **Why this module exists.** The chain used to fold each record's TAG alone
//! (`HMAC(mac_key, prev ‖ tag)`), so `audit.record_id` and `audit.at` sat
//! beside it unauthenticated — and every check that finds a record by its
//! label (O230's policy comparison, the orphan-label leg, a forget
//! attestation's recorded run, the mirror disclosure, the rotation count) was
//! one `UPDATE` deep. Measured: a quarantined wing's `trust/` record relabelled
//! and its row deleted read `VERIFY OK`, and a floored search returned the
//! quarantined drawer. The replay also lived in four hand-written loops.
//!
//! What it holds now:
//!
//! * **The regime**, decided from ONE record. A chain is version 1 until it
//!   carries a `migrate/chain-v2` commitment; that record and every row after
//!   it take the version-2 step, which folds the label and the time with the
//!   tag. The replay and every writer read the regime from that record alone —
//!   a clear pointer the replay did not consume would let an offline writer
//!   keep writers on version 1 silently.
//! * **The commitment.** Its TAG is an UNKEYED SHA-256 over every earlier row's
//!   label, tag and time, so the labels a vault held when it switched are bound
//!   too. Unkeyed on purpose: a rotation preserves audit tags verbatim, so a
//!   keyed digest could not be recomputed after one, while this one is
//!   authenticated by the keyed step it is folded into under whatever key is
//!   current.
//! * **The committed head, fenced against a downgrade.** Before the switch the
//!   live head is `chain_meta.head`; at the switch that row is FROZEN and the
//!   live head moves to `head_v2`. A 1.5.x binary compares its manifest anchor
//!   with `head`, finds them different, replays every row with the version-1
//!   step, cannot reproduce the frozen value, and refuses to open — before it
//!   can append a version-1 step to a version-2 chain or rotate one. The new
//!   key exists if and only if the commitment does; either alone is an
//!   integrity finding.
//! * **One replay** — `verify`, `reconcile_chain` (and so the writable open,
//!   the read-only report and `tighten_anchor`), a rotation's re-fold under the
//!   next keys, and the switch itself all run it.

use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use undercroft_vault::{ChainLink, ChainStep, Vault};

use crate::manage::Namespace;
use crate::StoreError;

/// The `chain_meta` key of the version-1 head: the live head before the
/// switch, FROZEN at it — what a 1.5.x binary reads, and cannot reproduce.
pub(crate) const FROZEN_HEAD: &str = "head";
/// The `chain_meta` key of the live head once the chain has switched.
pub(crate) const LIVE_HEAD: &str = "head_v2";
/// The rest of the commitment's label, under [`Namespace::Migrate`].
pub(crate) const COMMITMENT_KIND: &str = "chain-v2";
/// Domain string of the commitment digest.
const COMMITMENT_DOMAIN: &[u8] = b"undercroft.chain.v2/commitment";

/// The commitment's label: `migrate/chain-v2`.
pub(crate) fn commitment_label() -> String {
    Namespace::Migrate.record(COMMITMENT_KIND)
}

/// Which step each row of this chain takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Regime {
    /// No commitment: every row is version 1, and so is the next.
    V1,
    /// The commitment sits at `switch_seq`: rows before it are version 1, it
    /// and every row after it are version 2.
    V2 {
        /// The commitment record's `seq`.
        switch_seq: i64,
    },
}

impl Regime {
    /// The step the row at `seq` took.
    pub(crate) fn step_for(self, seq: i64) -> ChainStep {
        match self {
            Regime::V2 { switch_seq } if seq >= switch_seq => ChainStep::V2,
            _ => ChainStep::V1,
        }
    }

    /// The step the NEXT appended row takes.
    pub(crate) fn append_step(self) -> ChainStep {
        match self {
            Regime::V1 => ChainStep::V1,
            Regime::V2 { .. } => ChainStep::V2,
        }
    }

    /// Where the live head is kept.
    pub(crate) fn head_key(self) -> &'static str {
        match self {
            Regime::V1 => FROZEN_HEAD,
            Regime::V2 { .. } => LIVE_HEAD,
        }
    }
}

/// Read the regime off the chain: the first row carrying the commitment's
/// label. An indexed equality on `record_id`.
pub(crate) fn regime(conn: &Connection) -> Result<Regime, StoreError> {
    let switch: Option<i64> = conn.query_row(
        "SELECT MIN(seq) FROM audit WHERE record_id = ?1",
        params![commitment_label()],
        |r| r.get(0),
    )?;
    Ok(match switch {
        Some(switch_seq) => Regime::V2 { switch_seq },
        None => Regime::V1,
    })
}

/// The committed head and the regime it belongs to.
#[derive(Debug, Clone)]
pub(crate) struct Head {
    /// The chain's regime.
    pub regime: Regime,
    /// The live head, hex.
    pub head: String,
}

/// What `chain_meta` says, before it is judged.
#[derive(Clone)]
pub(crate) enum HeadState {
    /// No head at all: a database older than `chain_meta`, or a fresh one the
    /// open has not seeded yet.
    Unseeded,
    /// A head consistent with the regime.
    Seeded(Head),
    /// The regime and the head keys disagree — a commitment with no
    /// version-2 head, a version-2 head with no commitment, or a missing
    /// frozen head. Never produced by this store, whose switch writes the
    /// commitment and the head in one transaction; so it is an integrity
    /// finding.
    Inconsistent {
        /// What disagreed, in `verify`'s wording.
        finding: String,
    },
}

/// Read the committed head, judging the regime against the keys that hold it.
pub(crate) fn head_state(conn: &Connection) -> Result<HeadState, StoreError> {
    let regime = regime(conn)?;
    let get = |key: &str| -> Result<Option<String>, StoreError> {
        Ok(conn
            .query_row(
                "SELECT value FROM chain_meta WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()?)
    };
    let frozen = get(FROZEN_HEAD)?;
    let live = get(LIVE_HEAD)?;
    let inconsistent = |finding: &str| HeadState::Inconsistent {
        finding: finding.to_string(),
    };
    Ok(match (regime, frozen, live) {
        (Regime::V1, None, None) => HeadState::Unseeded,
        (Regime::V1, Some(head), None) => HeadState::Seeded(Head { regime, head }),
        (Regime::V1, _, Some(_)) => inconsistent(
            "audit chain: a version-2 head with no `migrate/chain-v2` commitment record",
        ),
        (Regime::V2 { .. }, Some(_), Some(head)) => HeadState::Seeded(Head { regime, head }),
        (Regime::V2 { .. }, _, None) => inconsistent(
            "audit chain: a `migrate/chain-v2` commitment record with no version-2 head",
        ),
        (Regime::V2 { .. }, None, Some(_)) => inconsistent(
            "audit chain: the frozen version-1 head is missing beside a version-2 head",
        ),
    })
}

/// The committed head, refusing an inconsistent pair as an integrity
/// finding. `None` when unseeded.
pub(crate) fn committed_head(conn: &Connection) -> Result<Option<Head>, StoreError> {
    head_state(conn)?.into_committed()
}

impl HeadState {
    /// The committed head, or the integrity finding a disagreeing regime is.
    ///
    /// Split out of [`committed_head`] by ROADMAP O251 so a caller that
    /// needs BOTH the judged head and the unjudged state — `reconcile_chain`
    /// does, once it hands its replay's verdict forward — can read
    /// `chain_meta` ONCE and derive both. Two reads would agree on every
    /// quiet vault and could straddle a concurrent commit on a busy one,
    /// which is one function disagreeing with itself about its own chain.
    ///
    /// **"Once" is three statements** ([`head_state`] reads the regime and
    /// two keys), so it is still three snapshots on a busy vault and can
    /// straddle another handle's version-2 switch (ROADMAP O253, corrected
    /// 2026-09-24). The fix is one read snapshot around the whole judgement.
    pub(crate) fn into_committed(self) -> Result<Option<Head>, StoreError> {
        match self {
            HeadState::Unseeded => Ok(None),
            HeadState::Seeded(h) => Ok(Some(h)),
            HeadState::Inconsistent { finding } => Err(StoreError::IntegrityFinding(finding)),
        }
    }
}

/// **The chain's two verdicts from one replay, in ONE place** (ROADMAP
/// O251): `(chain_ok, label_commitment)`, derived from a [`Replay`] and the
/// [`HeadState`] it should agree with.
///
/// It exists because two callers now make the same judgement —
/// [`crate::VaultStore::chain_verdict_in`], which replays for the label guard,
/// and `reconcile_chain`, which replays at the open and (when the open
/// appended nothing afterwards) hands its verdict forward so the guard need
/// not walk the same rows again. A second copy of this arithmetic would be a
/// second place for the chain's own verdict to be subtly wrong, which is the
/// defect class `reconcile_chain`'s own doc comment names one level up.
pub(crate) fn verdict(replayed: &Replay, head: &HeadState) -> (bool, crate::LabelCommitment) {
    let (db_head, heads_consistent) = match head {
        HeadState::Seeded(h) => (Some(h.head.as_str()), true),
        HeadState::Unseeded => (None, true),
        HeadState::Inconsistent { .. } => (None, false),
    };
    let malformed_at = |step| {
        replayed
            .malformed
            .iter()
            .any(|seq| replayed.regime.step_for(*seq) == step)
    };
    let chain_ok = heads_consistent
        && db_head == Some(replayed.head.as_str())
        && replayed.anchor_seen
        && !malformed_at(undercroft_vault::ChainStep::V2);
    let label_commitment = match replayed.regime {
        Regime::V1 => crate::LabelCommitment::Pending,
        Regime::V2 { .. }
            if replayed.commitment_intact == Some(true)
                && !malformed_at(undercroft_vault::ChainStep::V1) =>
        {
            crate::LabelCommitment::Intact
        }
        Regime::V2 { .. } => crate::LabelCommitment::Mismatch,
    };
    (chain_ok, label_commitment)
}

/// The committed head, which every caller that ADVANCES the chain needs to
/// exist. An unseeded chain here is the `chain_meta/head` row the old
/// `query_row` would have failed to find.
pub(crate) fn require_head(conn: &Connection) -> Result<Head, StoreError> {
    committed_head(conn)?.ok_or_else(|| StoreError::CorruptRow {
        id: "chain_meta/head".into(),
        reason: "the audit chain has no committed head".into(),
    })
}

/// Seed an unseeded chain from the manifest — a legacy database older than
/// `chain_meta`, or a fresh one. The head it writes is the version-1 head: a
/// chain switches only through [`switch`]'s commitment.
pub(crate) fn seed(conn: &Connection, head: &str, writes: u64) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO chain_meta (key, value) VALUES (?1, ?2), ('writes', ?3)",
        params![FROZEN_HEAD, head, writes.to_string()],
    )?;
    Ok(())
}

/// Advance the live head, inside the caller's transaction.
pub(crate) fn set_head(conn: &Connection, regime: Regime, head: &str) -> Result<(), StoreError> {
    conn.execute(
        "UPDATE chain_meta SET value = ?1 WHERE key = ?2",
        params![head, regime.head_key()],
    )?;
    Ok(())
}

/// The committed record count (`chain_meta.writes`).
pub(crate) fn writes(conn: &Connection) -> Result<u64, StoreError> {
    let v: String = conn.query_row(
        "SELECT value FROM chain_meta WHERE key = 'writes'",
        [],
        |r| r.get(0),
    )?;
    v.parse::<u64>().map_err(|e| StoreError::CorruptRow {
        id: "chain_meta/writes".into(),
        reason: e.to_string(),
    })
}

/// Set the committed record count, inside the caller's transaction.
pub(crate) fn set_writes(conn: &Connection, writes: u64) -> Result<(), StoreError> {
    conn.execute(
        "UPDATE chain_meta SET value = ?1 WHERE key = 'writes'",
        params![writes.to_string()],
    )?;
    Ok(())
}

/// The incremental commitment digest: `SHA-256(domain ‖ (lp(record_id) ‖
/// lp(tag) ‖ lp(at))* ‖ u64le(count))`, rows in `seq` order.
#[derive(Clone)]
pub(crate) struct CommitmentDigest {
    hasher: Sha256,
    count: u64,
}

impl CommitmentDigest {
    pub(crate) fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(COMMITMENT_DOMAIN);
        Self { hasher, count: 0 }
    }

    pub(crate) fn push(&mut self, record_id: &[u8], tag: &[u8], at: &[u8]) {
        for field in [record_id, tag, at] {
            self.hasher.update((field.len() as u64).to_le_bytes());
            self.hasher.update(field);
        }
        self.count += 1;
    }

    /// The digest over every row pushed so far — the commitment's TAG.
    pub(crate) fn finish(&self) -> [u8; 32] {
        let mut h = self.hasher.clone();
        h.update(self.count.to_le_bytes());
        h.finalize().into()
    }
}

/// What a replay found.
#[derive(Debug, Clone)]
pub(crate) struct Replay {
    /// The regime the chain's records declare.
    pub regime: Regime,
    /// The head the rows reproduce.
    pub head: String,
    /// Rows replayed.
    pub rows: usize,
    /// Whether `anchor` (when one was given) appeared among the heads, the
    /// genesis included.
    pub anchor_seen: bool,
    /// Rows after the last place the anchor appeared.
    pub behind_by: usize,
    /// `None` before the switch; otherwise whether the commitment record's
    /// tag equals the digest of every row before it.
    pub commitment_intact: Option<bool>,
    /// The digest over every row before the switch — over EVERY row on a
    /// version-1 chain, which is what the switch writes.
    pub digest: [u8; 32],
    /// Rows whose label or time is not stored as text, or whose tag is not
    /// a blob, by `seq`. SQLite compares a text value and a blob holding the
    /// same bytes as UNEQUAL, so a label rewritten as a blob hides from every
    /// `record_id = ?` lookup while stepping identically — each is a finding,
    /// on whichever side of the switch it sits.
    pub malformed: Vec<i64>,
}

fn bytes_of(v: ValueRef<'_>) -> (Vec<u8>, bool, bool) {
    // (bytes, is_text, is_blob)
    match v {
        ValueRef::Text(t) => (t.to_vec(), true, false),
        ValueRef::Blob(b) => (b.to_vec(), false, true),
        ValueRef::Integer(i) => (i.to_string().into_bytes(), false, false),
        ValueRef::Real(f) => (f.to_string().into_bytes(), false, false),
        ValueRef::Null => (Vec::new(), false, false),
    }
}

/// Replay the whole chain from genesis with `stepper`'s keys, streaming.
///
/// `stepper` is the handle's own vault for every check, and the NEXT key
/// generation for a rotation's re-fold. It never errors on what it finds in
/// the rows — a malformed row and a broken commitment are findings in the
/// returned [`Replay`], because a `verify` that returns an error instead of a
/// verdict is the failure `verify` exists to prevent.
///
/// **It REQUIRES a [`Snapshot`]** (ROADMAP O253): the regime it reads, the
/// rows it steps, and whatever head its caller compares the result with must
/// come from one state, or a legitimate commit between them reads as a broken
/// chain.
pub(crate) fn replay(
    snap: &Snapshot<'_>,
    stepper: &Vault,
    anchor: Option<&str>,
) -> Result<Replay, StoreError> {
    let conn = snap.conn();
    let regime = regime(conn)?;
    let genesis = Vault::chain_genesis_hex();
    let mut head = genesis.clone();
    let mut anchor_at: Option<usize> = anchor.filter(|a| *a == genesis).map(|_| 0);
    let mut digest = CommitmentDigest::new();
    let mut commitment_intact: Option<bool> = None;
    let mut malformed = Vec::new();
    let mut rows = 0usize;
    let mut stmt = conn.prepare("SELECT seq, record_id, tag, at FROM audit ORDER BY seq")?;
    let mut cursor = stmt.query([])?;
    while let Some(row) = cursor.next()? {
        let seq: i64 = row.get(0)?;
        let (record_id, rid_text, _) = bytes_of(row.get_ref(1)?);
        let (tag, _, tag_blob) = bytes_of(row.get_ref(2)?);
        let (at, at_text, _) = bytes_of(row.get_ref(3)?);
        if !(rid_text && tag_blob && at_text) {
            malformed.push(seq);
        }
        let step = regime.step_for(seq);
        if let Regime::V2 { switch_seq } = regime {
            if seq == switch_seq {
                commitment_intact = Some(tag[..] == digest.finish()[..]);
            }
        }
        if step == ChainStep::V1 {
            digest.push(&record_id, &tag, &at);
        }
        // A label or time that is not UTF-8 text cannot be a v2 link's
        // `&str`; such a row is already `malformed`, and its lossy form
        // steps to a head no genuine write produced.
        let rid = String::from_utf8_lossy(&record_id);
        let at = String::from_utf8_lossy(&at);
        head = stepper.chain_step_hex(
            step,
            &head,
            ChainLink {
                record_id: &rid,
                tag: &tag,
                at: &at,
            },
        )?;
        rows += 1;
        if anchor.is_some_and(|a| a == head) {
            anchor_at = Some(rows);
        }
    }
    Ok(Replay {
        regime,
        head,
        rows,
        anchor_seen: anchor_at.is_some(),
        behind_by: anchor_at.map(|at| rows - at).unwrap_or(0),
        commitment_intact,
        digest: digest.finish(),
        malformed,
    })
}

/// What a prefix scan folded (ROADMAP O245).
#[derive(Debug, Clone)]
pub(crate) struct Prefix {
    /// Every row in `audit`, whatever `at` asked for.
    pub rows: u64,
    /// The unkeyed digest over ALL rows.
    pub digest: [u8; 32],
    /// The digest after the first `at` rows, when `at` was given and the
    /// table holds at least that many; `None` otherwise.
    pub at_digest: Option<[u8; 32]>,
    /// The `seq` of the `at`-th row, on the same condition.
    pub at_seq: Option<i64>,
}

/// **An unkeyed, count-bound digest over the audit rows' preserved bytes,
/// in `seq` order** (ROADMAP O245): `CommitmentDigest`'s recipe over EVERY
/// row, whatever its regime, optionally snapshotted after the first `at`
/// rows in the same pass.
///
/// This is what an external witness binds, and the reason is O13's: a
/// rotation re-derives the keys both chain steps fold under and re-steps
/// every head (`rotate.rs`), so a witness carrying only a head is
/// unreachable after the first `vault rotate` — and the attacker A2 names
/// holds the key and can rotate. The row BYTES are what a rotation preserves
/// verbatim, so a digest over them survives it, and the count is folded so a
/// prefix and a longer chain cannot share one. Two things it does not
/// survive, stated: the A10 relabel (`kg.rs` rewrites `record_id` on a
/// sealed vault whose blinding walk has not completed — the emit refuses
/// while that is pending), and any rewrite of a witnessed row, which is the
/// point.
///
/// It REQUIRES a [`Snapshot`] for [`replay`]'s reason: a witness's `rows` and
/// `head` describe one state only if they were read in one (ROADMAP O253).
pub(crate) fn prefix(snap: &Snapshot<'_>, at: Option<u64>) -> Result<Prefix, StoreError> {
    let conn = snap.conn();
    let mut digest = CommitmentDigest::new();
    let mut rows = 0u64;
    let mut at_digest = None;
    let mut at_seq = None;
    let mut stmt = conn.prepare("SELECT seq, record_id, tag, at FROM audit ORDER BY seq")?;
    let mut cursor = stmt.query([])?;
    while let Some(row) = cursor.next()? {
        let seq: i64 = row.get(0)?;
        let (record_id, _, _) = bytes_of(row.get_ref(1)?);
        let (tag, _, _) = bytes_of(row.get_ref(2)?);
        let (at_bytes, _, _) = bytes_of(row.get_ref(3)?);
        digest.push(&record_id, &tag, &at_bytes);
        rows += 1;
        if at == Some(rows) {
            at_digest = Some(digest.finish());
            at_seq = Some(seq);
        }
    }
    Ok(Prefix {
        rows,
        digest: digest.finish(),
        at_digest,
        at_seq,
    })
}

/// What [`switch`] did.
pub(crate) enum SwitchOutcome {
    /// The commitment was appended; the caller commits and anchors — through
    /// the post-commit door, which reads the head it anchors from the
    /// committed database rather than taking one (ROADMAP O254).
    Switched,
    /// Another handle switched first — nothing to do.
    Already,
    /// The chain was left on version 1, for the reason given.
    Withheld(String),
}

/// Switch a version-1 chain to version 2 inside the caller's `BEGIN
/// IMMEDIATE` (ROADMAP O233): append the `migrate/chain-v2` commitment —
/// version-2 stepped, its tag the unkeyed digest of every earlier row — move
/// the live head to [`LIVE_HEAD`] and leave [`FROZEN_HEAD`] where it was.
///
/// **Verify first**, O232's shape: the version-1 rows must reproduce the
/// committed head and contain the manifest anchor, or the commitment would
/// bind labels on a chain that is already broken; such a chain is withheld
/// and says so. The regime is re-read inside the transaction, so two
/// handles opening at once write one commitment.
pub(crate) fn switch(
    locked: &Snapshot<'_>,
    vault: &Vault,
    anchor: &str,
    at: &str,
) -> Result<SwitchOutcome, StoreError> {
    // It writes, and it compares the anchor with the rows: both need the
    // write lock, under which nothing else commits (ROADMAP O253).
    if locked.origin() != Origin::WriteLocked {
        return Err(StoreError::Invalid(
            "the chain switch runs under the write lock (ROADMAP O233, O253)".into(),
        ));
    }
    let tx = locked.conn();
    let head = match head_state(tx)? {
        HeadState::Seeded(h) if h.regime == Regime::V1 => h,
        HeadState::Seeded(_) => return Ok(SwitchOutcome::Already),
        HeadState::Unseeded => {
            return Ok(SwitchOutcome::Withheld(
                "the audit chain has no committed head to switch from".into(),
            ))
        }
        HeadState::Inconsistent { finding, .. } => {
            return Err(StoreError::IntegrityFinding(finding))
        }
    };
    let replayed = replay(locked, vault, Some(anchor))?;
    if replayed.head != head.head || !replayed.anchor_seen || !replayed.malformed.is_empty() {
        return Ok(SwitchOutcome::Withheld(
            "the audit chain's labels are NOT chain-authenticated: the switch to the \
             labelled chain (ROADMAP O233) is withheld because the existing chain does \
             not replay cleanly to its committed head — run `undercroft verify`"
                .into(),
        ));
    }
    let label = commitment_label();
    let tag = replayed.digest;
    // The commitment is the first version-2 row by definition: it is what
    // makes the chain version 2.
    let next = vault.chain_step_hex(
        ChainStep::V2,
        &head.head,
        ChainLink {
            record_id: &label,
            tag: &tag,
            at,
        },
    )?;
    insert_record(tx, &label, &tag, at)?;
    tx.execute(
        "INSERT INTO chain_meta (key, value) VALUES (?1, ?2)",
        params![LIVE_HEAD, next],
    )?;
    let writes = writes(tx)? + 1;
    set_writes(tx, writes)?;
    Ok(SwitchOutcome::Switched)
}

/// The head after appending one row to `head`, with the step the chain's
/// regime assigns — the one decision both [`append`] and a rotation's own
/// record take, so no writer can choose its step from anything the replay
/// does not read.
pub(crate) fn next_head(
    stepper: &Vault,
    head: &Head,
    record_id: &str,
    tag: &[u8],
    at: &str,
) -> Result<String, StoreError> {
    Ok(stepper.chain_step_hex(
        head.regime.append_step(),
        &head.head,
        ChainLink { record_id, tag, at },
    )?)
}

/// Insert one `audit` row. The table's only two writers are [`append`] and a
/// rotation's own record, which computes its head before the row exists.
pub(crate) fn insert_record(
    conn: &Connection,
    record_id: &str,
    tag: &[u8],
    at: &str,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO audit (record_id, tag, at) VALUES (?1, ?2, ?3)",
        params![record_id, tag, at],
    )?;
    Ok(())
}

/// Append one audit row and advance the live head, inside the caller's open
/// transaction. Returns the new head.
pub(crate) fn append(
    conn: &Connection,
    stepper: &Vault,
    head: &Head,
    record_id: &str,
    tag: &[u8],
    at: &str,
) -> Result<String, StoreError> {
    insert_record(conn, record_id, tag, at)?;
    let next = next_head(stepper, head, record_id, tag, at)?;
    set_head(conn, head.regime, &next)?;
    Ok(next)
}

// ── What the chain says ABOUT one label ────────────────────────────────────
//
// The readers below answer "which record assigned this row, and when" — the
// question O230's policy decision asks of `wing_trust` and `retention_policy`
// and O234's asks of `drawers`, `kg_triples`, `kg_entities` and `tunnels`.
// One question, four tables, ONE implementation: they were written for the
// policy tables and live here now, because a second copy is a second place
// for the boundary arithmetic to be subtly wrong — and the boundary is what
// separates a replay from a rotation that legitimately re-tagged every row.

/// One audit record's place in the chain and its tag.
pub(crate) struct ChainRecord {
    /// Where it sits in the trail.
    pub(crate) seq: i64,
    /// The tag it recorded, as BYTES.
    pub(crate) tag: Vec<u8>,
}

/// The newest audit record carrying exactly this label — an indexed
/// equality on `record_id` (`idx_audit_record_id`), newest first.
pub(crate) fn newest_record(
    conn: &Connection,
    record_id: &str,
) -> Result<Option<ChainRecord>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT seq, tag FROM audit WHERE record_id = ?1 ORDER BY seq DESC LIMIT 1",
            params![record_id],
            |r| {
                // The tag's BYTES, whatever storage class holds them: a
                // tag rewritten as text made this read — and so the
                // whole `verify` — return an error instead of a verdict.
                // The chain replay reports the retype itself (ROADMAP
                // O233); here the bytes are what the comparison needs.
                let tag = match r.get_ref(1)? {
                    ValueRef::Blob(b) => b.to_vec(),
                    ValueRef::Text(t) => t.to_vec(),
                    _ => Vec::new(),
                };
                Ok(ChainRecord {
                    seq: r.get(0)?,
                    tag,
                })
            },
        )
        .optional()?)
}

/// The label a rotation under THIS key wrote — stated once, here, because
/// `rotate.rs` composes it at the write and this module reads it.
pub(crate) fn rotation_label(vault: &Vault) -> String {
    Namespace::Rotate.record(&vault.keycheck_hex()[..KEYCHECK_LABEL_LEN])
}

/// How much of the keycheck a `rotate/` label carries.
pub(crate) const KEYCHECK_LABEL_LEN: usize = 16;

/// **How many rotations the chain records after `seq`** — and this one is
/// deliberately NOT bound to the current key (ROADMAP O239).
///
/// The two questions differ and the difference is the reason both live here.
/// [`rotation_boundary`] asks *where is the rotation that installed the key I
/// hold*, which is one record under one keycheck. This asks *how many
/// rotations happened since*, which spans every key generation — so bounding
/// it by the current keycheck would answer at most one and silently undercount
/// a vault rotated twice. It corroborates a `Recorded` forget verdict and
/// never decides it (ROADMAP O13: a pre-A19 rotation appended no record, so
/// reading zero as "no rotation, therefore forged" recreates the defect), and
/// a planted `rotate/` label inflates it without changing any verdict.
pub(crate) fn rotations_since(conn: &Connection, seq: i64) -> Result<i64, StoreError> {
    let (clause, ps) = prefix_range(Namespace::Rotate).clause(2);
    let sql = format!("SELECT COUNT(*) FROM audit WHERE seq > ?1 AND {clause}");
    let mut args = vec![rusqlite::types::Value::Integer(seq)];
    args.extend(ps.into_iter().map(rusqlite::types::Value::Text));
    Ok(conn.query_row(&sql, rusqlite::params_from_iter(args), |r| r.get(0))?)
}

/// How a namespace's labels are SELECTED out of `audit` (ROADMAP O243).
///
/// Every prefixed namespace is a half-open range — `prefix` up to the same
/// string with its closing `/` replaced by the next byte, `0` — and the one
/// BARE namespace, `Namespace::Drawer`, whose prefix is empty, is not: its
/// labels are the ids that carry no `/` at all, which no range over
/// `record_id` can express. `prefix_range` used to compute the range for
/// every namespace and panicked on the bare one (`lo.len() - 1` underflows,
/// and the slice bound fails in both profiles); unreachable only because its
/// three callers happened to pass prefixed namespaces, which is a property
/// of the call sites and not of the function. A second variant, rather than
/// a refusal, because `chain_keys(Namespace::Drawer)` has an honest answer
/// — the bare labels — and a census over `Namespace::ALL` should get it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LabelRange {
    /// `record_id >= lo AND record_id < hi`.
    Prefixed {
        /// The namespace's prefix, `/` included.
        lo: String,
        /// The exclusive upper bound.
        hi: String,
    },
    /// The bare namespace: labels with no `/`.
    Bare,
}

impl LabelRange {
    /// The SQL predicate over `record_id`, its positional parameters numbered
    /// from `?{first}`, and those parameters in order. A caller appends it to
    /// its own `WHERE` and passes the parameters after its own.
    pub(crate) fn clause(&self, first: usize) -> (String, Vec<String>) {
        match self {
            LabelRange::Prefixed { lo, hi } => (
                format!("record_id >= ?{first} AND record_id < ?{}", first + 1),
                vec![lo.clone(), hi.clone()],
            ),
            LabelRange::Bare => ("instr(record_id, '/') = 0".to_string(), Vec::new()),
        }
    }
}

/// A namespace's label selection — see [`LabelRange`]. Never panics: the
/// bare namespace answers `Bare`, and every prefixed one's prefix ends in
/// the `/` the upper bound replaces, which the test over `Namespace::ALL`
/// pins.
pub(crate) fn prefix_range(ns: Namespace) -> LabelRange {
    let lo = ns.prefix();
    match lo.strip_suffix('/') {
        None => LabelRange::Bare,
        Some(stem) => LabelRange::Prefixed {
            lo: lo.to_string(),
            hi: format!("{stem}0"),
        },
    }
}

/// Every distinct label a namespace's records carry, by the same selection.
pub(crate) fn chain_keys(conn: &Connection, ns: Namespace) -> Result<Vec<String>, StoreError> {
    let (clause, ps) = prefix_range(ns).clause(1);
    let sql = format!("SELECT DISTINCT record_id FROM audit WHERE {clause} ORDER BY record_id");
    let mut stmt = conn.prepare(&sql)?;
    let keys = stmt
        .query_map(rusqlite::params_from_iter(ps.iter()), |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(keys)
}

// ── Are the chain's labels worth BELIEVING? (ROADMAP O237) ────────────────
//
// Everything above answers "what does the trail say about this label". This
// answers the question that has to come first, and did not until O237: **is
// the trail this handle is reading still the one the vault wrote.** Every
// reader above finds a record by its label and replays nothing, so one
// `UPDATE audit SET record_id = …` moved a quarantined wing's `trust/`
// record out of its own namespace, a `DELETE FROM wing_trust` took the row,
// and a `standard`-floored search returned the quarantined drawer — with
// `verify` failing on `chain_ok` ALONE, i.e. only once somebody ran it.
//
// Two mechanisms, because one process cannot afford either alone:
//
// * **ONE lazy full replay per handle, on the first guarded read.** Not at
//   open: measured on a real corpus, the open is FLAT in `audit` (36 ms at
//   102,001 rows, 35 ms at 1,002,001) while a replay is LINEAR in it (88 ms,
//   836 ms), and `audit` has no compaction anywhere in this tree — it grows
//   with every write, every read under `UNDERCROFT_READ_AUDIT=chain`, every
//   export and every push. A replay at open therefore charges every process
//   an unbounded cost for a protection that covers a long-lived server only
//   at boot (A31: such a server caches its handle and never re-opens). Not
//   per read either: 88 ms on a 36.84 ms/q baseline is +240%, far past
//   O234's measured read budget.
// * **A per-key APPEND-ONLY PREFIX invariant on every guarded read.** Not a
//   cached replay position — an incremental replay from a watermark is
//   UNSOUND here, because the attack rewrites rows BELOW any watermark.
//   `audit` is append-only in production (one `INSERT` and one `UPDATE`,
//   both source-gated; every `DELETE FROM audit` in the crate is
//   `#[cfg(test)]`), so for a label this handle has already looked at, a
//   record that VANISHES, a newest record that moves BACKWARDS, or a tag
//   that changes under a seq this handle already read is always tampering.
//   It costs O(keys) over rows the scan already fetches. **"Every guarded
//   read" means every read that looks a label up THROUGH this handle** —
//   the policy scans, the forget path and the `rotate/` boundary.
//   `refuse_replayed` finds a drawer's records in its own SQL and pins none
//   of them, so on the returning read the invariant covers the `rotate/`
//   label alone (ROADMAP O252, measured; corrected 2026-09-24).
//
// [`data_version`] is the ACCELERATOR between them and never the boundary
// (A28's shape one more time). It is measured sound for a writer that goes
// through SQLite — the handle's own commit does not move it, another
// connection does, another PROCESS does — and blind to one editing pages
// beneath SQLite. So it may short-circuit the expensive REPLAY, and it may
// never gate the prefix check.
//
// **What the pair does not see, stated rather than implied.** An APPEND is
// legitimate — it is the whole premise of the invariant — so a forged row
// appended by a writer editing pages beneath SQLite, which does not move
// the cookie either, is invisible to a handle that has already replayed,
// until it is re-opened or another connection commits. Only a replay can
// tell a forged append from a real one, because only the mac key can, and
// **no in-band structure changes that** — ROADMAP O241 ruled against the
// authenticated manifest census that was filed to, and a sentence here
// said it would close this residual, which was false in both directions.
// A census can only ever be ONE-directional (a key it names must be in the
// database), so it catches a key that VANISHES and never one that APPEARS,
// and appearing is the direction this residual runs; the anchor is also
// deliberately allowed to lag and read audits append with no anchor at
// all, so the unanchored tail a forged row hides in is legitimate and
// unbounded. The window is narrow — raw page writes under a live SQLite,
// with no recorded instance in this tree. **An out-of-band witness does
// NOT close it either**, and this paragraph said it did until ROADMAP
// O245's ruling (2026-09-23) read it against the check: a witness commits
// to a PREFIX of the rows, so it catches a rewind or an erasure at or
// below the witnessed height and sees any append above it — forged or
// not — as writes since the witness; and an offline check is itself
// "another connection replaying", which touches the serving handle's
// blindness not at all. What would close the append direction is a
// per-row out-of-band log under a credential that is not on the disk,
// which is not a copy of a chain fact and not this tree's.
//
// **And the window is wider than an APPEND, which the paragraph above
// undercounts — measured by ROADMAP O247's panel (2026-09-24), owned by
// O252.** Under an unmoved cookie the invariant sees three things only — a
// label that vanishes, a newest record that moves BACK, a tag that changes
// at a seq already read — and only for labels this handle has pinned. So a
// writer without the key re-points a label's newest record by any edit that
// moves it FORWARD or touches a label not yet pinned: an older record
// copied forward, a later record relabelled in (no height moves at all), a
// copied `rotate/` label (O247: `meta.keycheck` holds it in clear on every
// vault), the newest record of an unpinned label deleted. Measured: the
// replayed policy governs, the sweep destroys a drawer its declared policy
// keeps and reports `ok`, and a returning read serves a replayed drawer even
// after a relabel-out or a delete, because the drawer path pins nothing.
// Its gate is `o252_under_an_unmoved_cookie_an_edited_label_decides_a_policy_and_a_drawer`,
// pinned as a cost. O237 ruling 1 promised more than was built — "an older
// tag promoted to newest is ALWAYS a finding" — and the copy-forward is
// exactly that case. **"No in-band structure changes that" is too wide as
// well**: against a writer WITHOUT the key, in-band answers exist (O252
// names them — that promise kept, a tail fold under the handle's own key, a
// per-row MAC over position, deciding from an authenticated in-memory
// image); the out-of-band log above is the answer against a KEY-HOLDER. The
// whole guard defends against a writer who does not hold the key, and on a
// deployment that keeps `master.key` in a file beside the database, a
// writer who can edit the database can usually read that file too.
//
// **"Or another connection commits" got NARROWER on `serve-http`, and that
// is stated rather than absorbed** (ROADMAP O242). That process used to
// hold two handles on one vault, so every `/v1` commit handed the `/mcp`
// handle a free re-replay — and a free re-read and MAC check of the
// manifest with it, since the guard's replay begins at `anchored_head`. It now
// holds one, which is what every other deployment has always had, so
// neither happens until a genuinely FOREIGN commit arrives. The coverage
// that goes was an accident of that aliasing and never a mechanism: it
// never existed for an `/mcp`-only or `/v1`-only server, or for the CLI.
// What it incidentally shortened is the window here and O246's manifest
// rollback, and neither was ever designed to close on a sibling's write.
// This sentence said both "close on the same out-of-band witness" until
// O245's ruling: neither does. The window above is the append direction
// (previous paragraph), and O246's lowered anchor sits over an INTACT
// database, which a witness compares and finds extended — O246 closes on
// the writable open reporting the heal it performed, and on nothing else.

/// What a reader will DO with what the chain says about a label.
///
/// Required rather than inferred, on the [`crate::Read`] and
/// `admission::Screen` precedent: the two answers are opposite and the
/// difference is invisible at the call site, so the next caller to reach a
/// policy scan has to state which it is instead of inheriting whichever the
/// last one needed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LabelUse {
    /// The caller ACTS on the answer — a trust floor, a retention sweep, a
    /// destruction, a returning read. Refuses unless the chain authenticates
    /// its own labels, and holds the append-only invariant over every label
    /// it looks at.
    Decide,
    /// `verify` itself, gathering findings to REPORT. It never refuses: a
    /// `verify` that returns an ERROR instead of a verdict is the failure
    /// `verify` exists to prevent, and `backup create` and `/v1/verify` both
    /// read the verdict. It records nothing either — an observation taken
    /// while the trail is already suspect must not become the baseline a
    /// later decision is compared against.
    Report,
}

/// One label's newest record, as this handle last saw it.
struct Seen {
    seq: i64,
    tag: Vec<u8>,
}

/// What one handle has established about the chain, for the life of the
/// handle (ROADMAP O237).
#[derive(Default)]
pub(crate) struct LabelGuard {
    /// The last full replay's verdict, with the `data_version` it was taken
    /// at. Reused while that cookie has not moved, which is what makes the
    /// replay ONCE per handle on the deployment this was filed for.
    replayed: Option<Replayed>,
    /// The newest record seen for each label a guarded read looked up.
    newest: std::collections::HashMap<String, Seen>,
    /// The label SET seen for each namespace a guarded read enumerated. The
    /// exploit deletes the policy row AND relabels its record, so the key is
    /// in neither place afterwards and no per-key lookup is ever made for
    /// it: the set is the only thing that can miss it.
    keys: std::collections::HashMap<&'static str, std::collections::BTreeSet<String>>,
    /// How many full replays this handle has run. It has to be COUNTED
    /// rather than timed: "at most once per handle over N guarded reads" is
    /// O237's own gate, and a wall-clock proxy for it would pass on a corpus
    /// small enough that a replay is free — which is every fixture.
    ///
    /// **`#[cfg(test)]` until ROADMAP O250**, which is what that cost: O242
    /// was a +213% regression on the flagship deployment and it was found by
    /// a reviewer reading code, because the observable that would have shown
    /// it existed only in test builds. It now reaches
    /// `VaultStats.chain_replays` on every stats surface, and the
    /// `undercroft_chain_replays_total` counter beside it is the durable
    /// half for a served process whose stats nobody polls.
    replays: u64,
}

/// A replay's verdict, and the point it describes.
struct Replayed {
    data_version: i64,
    chain_ok: bool,
    labels: crate::LabelCommitment,
}

/// SQLite's `data_version` cookie: it changes when a connection OTHER than
/// this one commits, and not when this one does. Measured with a real second
/// process, behind a premise assertion — its first run reported "a process
/// does not move it" from a child that had run zero tests.
///
/// **Inside a read transaction it is CONSTANT and describes that
/// transaction's snapshot** (ROADMAP O253, P7), which is why a [`Snapshot`]
/// reads it once, as its first statement, and the guard compares that value.
pub(crate) fn data_version(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row("PRAGMA data_version", [], |r| r.get(0))?)
}

// ── ONE state per judgement (ROADMAP O253) ────────────────────────────────
//
// A judgement that compares two things it read — a replay against the
// committed head, a policy row against its newest record, a fetched drawer
// against the chain — is only a judgement when both were read from ONE
// database state. In autocommit every statement is its own WAL read
// snapshot, so a legitimate commit landing between two of them made the
// comparison disagree with itself: measured, 64 false tampering refusals and
// 41 `verify` runs reporting a broken chain in six seconds beside an ordinary
// `trust set` loop, with nothing tampered. The remedy the refusal names is to
// restore a backup, i.e. to throw away every write since it.
//
// So every judgement reads inside a [`Snapshot`], and the two readers the
// judgements rest on — [`replay`] and [`prefix`] — REQUIRE one: the tree's
// required-witness shape (`Screen`, `Read`, `LabelUse`), so a new walk that
// opened no snapshot does not compile. Only three things can mint one: the
// helper [`snapshot`], and the two write-lock guards (`WriteLock`, the
// rotation's `ExclusiveHold`), whose transactions are already one state.

/// Where a [`Snapshot`] came from — which decides whether the label guard may
/// REMEMBER what it read through it, and whether it may replay inside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Opened by [`snapshot`] in autocommit, or nested inside one this handle
    /// opened: a read transaction the handle owns and ends before any write.
    /// The only origin whose observations the guard keeps — a pin taken
    /// inside a transaction that later rolls back would name a `seq` that
    /// `AUTOINCREMENT` reuses, and the next read would refuse "a different
    /// tag at seq".
    Opened,
    /// A caller's transaction the helper found open and ran inside. Its reads
    /// are one state; whether anything else can commit meanwhile is unknown,
    /// so the manifest anchor cannot be compared inside it.
    Inline,
    /// A write-lock guard's transaction: nothing else commits while it is
    /// held, so the anchor read inside it is the anchor the rows answer to.
    WriteLocked,
}

/// **Proof that the reads made through it come from ONE database state**
/// (ROADMAP O253). Every statement run on [`conn`](Self::conn) while it lives
/// sees the same committed state, because the connection is inside one
/// transaction for the whole of its life.
pub(crate) struct Snapshot<'c> {
    conn: &'c Connection,
    origin: Origin,
    data_version: i64,
}

impl<'c> Snapshot<'c> {
    /// The connection, for the reads a judgement makes beside the replay —
    /// every one of them inside this snapshot.
    pub(crate) fn conn(&self) -> &'c Connection {
        self.conn
    }

    /// Where it came from.
    pub(crate) fn origin(&self) -> Origin {
        self.origin
    }

    /// The `data_version` of the state it reads (P7).
    pub(crate) fn data_version(&self) -> i64 {
        self.data_version
    }

    /// A snapshot over a transaction a WRITE-LOCK GUARD holds. Called by
    /// `WriteLock::snapshot` and `ExclusiveHold::snapshot` and nowhere else,
    /// which a source gate counts: a caller that passed a connection in
    /// autocommit here would be asserting a lock it does not hold.
    pub(crate) fn write_locked(conn: &'c Connection) -> Result<Self, StoreError> {
        if conn.is_autocommit() {
            return Err(StoreError::Invalid(
                "a write-locked snapshot was asked for on a connection holding no \
                 transaction (ROADMAP O253)"
                    .into(),
            ));
        }
        Ok(Self {
            conn,
            origin: Origin::WriteLocked,
            data_version: data_version(conn)?,
        })
    }
}

/// **Run `body` inside ONE read snapshot of `conn`** (ROADMAP O253).
///
/// In autocommit it sets `PRAGMA query_only = ON` (restoring the previous
/// value after, so a read-only handle stays on), begins a DEFERRED
/// transaction, reads `data_version` as its first statement — which pins the
/// snapshot and is the cookie the guard compares — runs `body`, and COMMITS
/// on Ok and on Err alike: a read transaction has nothing to keep or undo, so
/// the two are the same. `query_only` rather than a changed-rows tripwire with
/// a rollback, which was REFUTED as a silent-damage path of its own:
/// `kg_secret`'s first-use `INSERT` caches the secret before its write
/// commits, so a rollback would leave graph rows blinded with a key that
/// exists nowhere. Under `query_only` that write FAILS, before anything is
/// cached.
///
/// Inside a snapshot this handle already opened (`owned > 0`) it runs `body`
/// in that one. Inside any other transaction — a caller's write, a rotation —
/// it runs `body` INLINE, and the snapshot says so: those reads are one state
/// too, and the guard decides what it may do there.
///
/// `owned` is the handle's count of snapshots it opened, COUNTED rather than
/// inferred: `is_autocommit()` cannot tell this helper's transaction from a
/// caller's.
pub(crate) fn snapshot<T>(
    conn: &Connection,
    owned: &std::cell::Cell<u32>,
    body: impl FnOnce(&Snapshot<'_>) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    if owned.get() > 0 || !conn.is_autocommit() {
        let origin = if owned.get() > 0 {
            Origin::Opened
        } else {
            Origin::Inline
        };
        return body(&Snapshot {
            conn,
            origin,
            data_version: data_version(conn)?,
        });
    }
    let open = OpenSnapshot::begin(conn, owned)?;
    let out = data_version(conn).and_then(|data_version| {
        body(&Snapshot {
            conn,
            origin: Origin::Opened,
            data_version,
        })
    });
    let ended = open.end();
    // The body's own error outranks one from ending a read transaction.
    let value = out?;
    ended?;
    Ok(value)
}

/// The helper's read transaction, ended on every exit — a panic in `body`
/// included, or a long-lived handle would be left inside a transaction under
/// `query_only`, refusing every later write.
struct OpenSnapshot<'c> {
    conn: &'c Connection,
    owned: &'c std::cell::Cell<u32>,
    restore_query_only: bool,
    live: bool,
}

impl<'c> OpenSnapshot<'c> {
    fn begin(conn: &'c Connection, owned: &'c std::cell::Cell<u32>) -> Result<Self, StoreError> {
        let was_on: i64 = conn.query_row("PRAGMA query_only", [], |r| r.get(0))?;
        if was_on == 0 {
            conn.pragma_update(None, "query_only", "ON")?;
        }
        if let Err(e) = conn.execute_batch("BEGIN DEFERRED") {
            if was_on == 0 {
                let _ = conn.pragma_update(None, "query_only", "OFF");
            }
            return Err(e.into());
        }
        owned.set(owned.get() + 1);
        Ok(Self {
            conn,
            owned,
            restore_query_only: was_on == 0,
            live: true,
        })
    }

    fn end(mut self) -> Result<(), StoreError> {
        self.live = false;
        self.finish()
    }

    fn finish(&self) -> Result<(), StoreError> {
        self.owned.set(self.owned.get() - 1);
        let ended = self.conn.execute_batch("COMMIT").map_err(|e| {
            let _ = self.conn.execute_batch("ROLLBACK");
            StoreError::from(e)
        });
        let restored = if self.restore_query_only {
            self.conn
                .pragma_update(None, "query_only", "OFF")
                .map_err(StoreError::from)
        } else {
            Ok(())
        };
        ended.and(restored)
    }
}

impl Drop for OpenSnapshot<'_> {
    fn drop(&mut self) {
        if self.live {
            self.live = false;
            let _ = self.finish();
        }
    }
}

/// A cached or fresh verdict, refused unless it authenticates the labels.
fn refuse_unless_authentic(
    (chain_ok, labels): (bool, crate::LabelCommitment),
) -> Result<(), StoreError> {
    if chain_ok && labels != crate::LabelCommitment::Mismatch {
        return Ok(());
    }
    let why = if !chain_ok {
        "its records do not replay to the committed head"
    } else {
        "the labels it held when it switched no longer match their commitment"
    };
    Err(StoreError::IntegrityFinding(format!(
        "the audit chain does not authenticate its own labels ({why}), so what it \
         says about a record decides nothing — run `undercroft verify`, then \
         restore a backup that verifies"
    )))
}

impl crate::VaultStore {
    /// [`snapshot`] on this handle's connection, counted on this handle — the
    /// one way the store opens a read snapshot (ROADMAP O253).
    pub(crate) fn snapshot<T>(
        &self,
        body: impl FnOnce(&Snapshot<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        snapshot(&self.conn, &self.owned_snapshots, body)
    }

    /// The chain's two verdicts — `(chain_ok, label_commitment)` — from ONE
    /// replay inside `snap`, against the committed head read in the SAME
    /// snapshot (ROADMAP O233, O253). `anchor` is read by the caller BEFORE
    /// `snap` was opened, or under a write lock.
    ///
    /// `verify` reports them; the guard and the forget path's
    /// recorded-evidence verdict refuse without them. Besides a wrong head the
    /// replay can find a regime and a head key that disagree, and a row whose
    /// label, time or tag is not stored as the type every writer binds; each
    /// is sorted by which side of the switch it sits on (at or after it, the
    /// CHAIN's finding, which a rotation would re-step and so must refuse;
    /// before it, the label commitment's, which a rotation preserves
    /// verbatim — O232 ruling 1). The arithmetic is [`verdict`]'s, shared with
    /// the open's `reconcile_chain` (ROADMAP O251).
    ///
    /// It was five statements and a disk read in five snapshots — the regime
    /// read twice, once inside the replay and once inside `head_state`, so
    /// another handle's version-2 switch between them stepped the commitment
    /// row under version 1 and reported a broken chain.
    pub(crate) fn chain_verdict_in(
        &self,
        snap: &Snapshot<'_>,
        anchor: &str,
    ) -> Result<(bool, crate::LabelCommitment), StoreError> {
        let replayed = replay(snap, &self.vault, Some(anchor))?;
        let head = head_state(snap.conn())?;
        Ok(verdict(&replayed, &head))
    }

    /// **The door every reader that DECIDES from an audit label goes
    /// through** (ROADMAP O237): the chain must replay to its committed head
    /// under this handle's own keys, and its labels must still match the
    /// commitment that bound them.
    ///
    /// `Regime::V1` and [`crate::LabelCommitment::Pending`] MUST NOT refuse,
    /// and that is part of O237's ruling rather than an implementation
    /// choice: a clean legacy chain replays with `chain_ok = true` and its
    /// labels bound by nothing, so refusing on unbound labels would brick
    /// every pre-1.6.0 vault served `--read-only` (which cannot switch) — a
    /// documented contract change, i.e. MAJOR. Such a vault gets the
    /// append-only invariant and nothing more, which is stated rather than
    /// implied.
    ///
    /// **The DOOR (ROADMAP O253): run `body` inside one snapshot the guard
    /// has authenticated.** Every reader that decides from a label and every
    /// read that returns content goes through here, and `body` makes ALL of
    /// its reads — the rows it acts on and the chain evidence it compares them
    /// with — inside that snapshot. It used to be a check made BEFORE the
    /// reader's own statements, each its own snapshot, so a legitimate commit
    /// between two of them read as tampering, and a verdict taken in one state
    /// licensed rows read in another.
    ///
    /// Two attempts, by construction. The first opens a snapshot and reads
    /// its cookie inside it (P7: constant within the transaction, and so the
    /// version of exactly the rows the body reads — the ordering argument's
    /// goal met strictly, where reading it before the snapshot opened only
    /// met it probably). On a HIT it checks the cached verdict and runs the
    /// body in that same snapshot, which costs nothing but the cookie. On a
    /// MISS it ENDS the snapshot, reads the manifest anchor from disk, opens a
    /// second one and replays there; the second attempt never consults the
    /// cache. **The anchor is read BEFORE the snapshot, never inside it**: an
    /// anchor is written only after its commit, so one read first is never
    /// newer than the rows, while one read after the snapshot pinned can name
    /// a head a writer committed and anchored since — a false `chain_ok =
    /// false` over the whole replay window. All three lenses of the ruling
    /// found that independently; the brief had omitted it.
    ///
    /// Nested inside a snapshot this handle opened, or inside a caller's
    /// transaction, the snapshot is already pinned and the guard can only
    /// CHECK it: a hit runs the body; a miss replays only under a write lock
    /// ([`Origin::WriteLocked`]) and is otherwise an error naming the call
    /// site — the survey the ruling asked for found no such caller.
    #[track_caller]
    pub(crate) fn guarded<T>(
        &self,
        body: impl FnOnce(&Snapshot<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let site = std::panic::Location::caller();
        let mut body = Some(body);
        let mut run = |snap: &Snapshot<'_>| (body.take().expect("the body runs once"))(snap);
        if self.owned_snapshots.get() > 0 || !self.conn.is_autocommit() {
            return self.snapshot(|snap| {
                self.labels_authenticated_at(snap, site)?;
                run(snap)
            });
        }
        let first = self.snapshot(|snap| match self.cached_verdict(snap.data_version()) {
            Some(verdict) => {
                refuse_unless_authentic(verdict)?;
                run(snap).map(Some)
            }
            None => Ok(None),
        })?;
        if let Some(done) = first {
            return Ok(done);
        }
        let anchor = self.vault.anchored_head()?;
        self.snapshot(|snap| {
            let verdict = self.chain_verdict_in(snap, &anchor)?;
            self.remember_replay(snap, verdict);
            refuse_unless_authentic(verdict)?;
            run(snap)
        })
    }

    /// **The check a deciding reader makes inside the snapshot it was
    /// handed** (ROADMAP O253): the verdict the door established for exactly
    /// this state, or — under a write lock only — a replay made in place.
    /// Every `LabelUse::Decide` reader and every returning read's comparison
    /// calls it, so a reader handed a snapshot no guarded door authenticated
    /// fails loudly instead of deciding.
    #[track_caller]
    pub(crate) fn labels_authenticated(&self, snap: &Snapshot<'_>) -> Result<(), StoreError> {
        self.labels_authenticated_at(snap, std::panic::Location::caller())
    }

    fn labels_authenticated_at(
        &self,
        snap: &Snapshot<'_>,
        site: &std::panic::Location<'_>,
    ) -> Result<(), StoreError> {
        if let Some(verdict) = self.cached_verdict(snap.data_version()) {
            return refuse_unless_authentic(verdict);
        }
        match snap.origin() {
            // Nothing else commits under the lock, so the anchor read here is
            // the anchor these rows answer to. Counted — it walks the whole
            // table — and never cached: the lock's transaction may still roll
            // back.
            Origin::WriteLocked => {
                let anchor = self.vault.anchored_head()?;
                let verdict = self.chain_verdict_in(snap, &anchor)?;
                self.count_replay();
                refuse_unless_authentic(verdict)
            }
            Origin::Opened | Origin::Inline => Err(StoreError::Invalid(format!(
                "a label decision at {site} was reached inside a snapshot no guarded door \
                 authenticated (ROADMAP O253): it would compare the anchor with rows it did \
                 not read first. This is a defect in the caller, not in the vault"
            ))),
        }
    }

    /// The verdict cached for exactly this cookie, if any.
    fn cached_verdict(&self, data_version: i64) -> Option<(bool, crate::LabelCommitment)> {
        match &self.labels.borrow().replayed {
            Some(r) if r.data_version == data_version => Some((r.chain_ok, r.labels)),
            _ => None,
        }
    }

    /// Drop the cached replay verdict, so the next guarded read replays
    /// (ROADMAP O266). For a change of the chain this connection made itself —
    /// which moves no cookie — that the verdict does not describe: a key
    /// rotation re-steps every head. And for a change of CONNECTION (ROADMAP
    /// O276): the cookie the verdict is keyed by belongs to the connection
    /// that read it, and a fresh one restarts it. The append-only memory
    /// (`newest`, `keys`) is kept, because a rotation preserves every record's
    /// label and tag, and the rows it describes do not change with a
    /// connection.
    pub(crate) fn forget_label_verdict(&self) {
        self.labels.borrow_mut().replayed = None;
    }

    /// Keep a replay's verdict for the state it describes — only from a
    /// snapshot this handle opened, whose cookie IS that state (P7).
    fn remember_replay(
        &self,
        snap: &Snapshot<'_>,
        (chain_ok, labels): (bool, crate::LabelCommitment),
    ) {
        if snap.origin() == Origin::Opened {
            self.labels.borrow_mut().replayed = Some(Replayed {
                data_version: snap.data_version(),
                chain_ok,
                labels,
            });
        }
        self.count_replay();
    }

    fn count_replay(&self) {
        self.labels.borrow_mut().replays += 1;
        // The durable half (ROADMAP O250), OUTSIDE the borrow: nothing in
        // `undercroft-obs` reaches back into this store today, and the next
        // person to add a counter here should not have to prove that again.
        undercroft_obs::chain_replayed();
    }

    /// [`newest_record`] through the handle's append-only memory, read in
    /// `snap`. A `Decide` read is checked against every label this handle
    /// pinned, and pins what it found only from a snapshot the helper opened.
    pub(crate) fn newest_record(
        &self,
        snap: &Snapshot<'_>,
        record_id: &str,
        on: LabelUse,
    ) -> Result<Option<ChainRecord>, StoreError> {
        let found = newest_record(snap.conn(), record_id)?;
        if on == LabelUse::Decide {
            self.hold_append_only(snap, record_id, found.as_ref())?;
        }
        Ok(found)
    }

    /// [`chain_keys`] through the same memory: a label this handle saw in a
    /// namespace and no longer sees was taken out of it.
    pub(crate) fn chain_keys(
        &self,
        snap: &Snapshot<'_>,
        ns: Namespace,
        on: LabelUse,
    ) -> Result<Vec<String>, StoreError> {
        let found = chain_keys(snap.conn(), ns)?;
        if on == LabelUse::Decide {
            self.hold_keys_append_only(snap, ns, &found)?;
        }
        Ok(found)
    }

    /// **The rotation that installed the key this handle holds** — the
    /// boundary a tag comparison stops at, bound to the KEY rather than to
    /// the namespace (ROADMAP O239), and now through the same memory.
    ///
    /// It used to be `MAX(seq)` over the whole `rotate/` half-open range,
    /// which admits any label an offline writer spells. Measured: one
    /// statement — an `INSERT` of a forged `rotate/` row after the
    /// declaration to be ignored — put the boundary above every record, and
    /// O230's replay attack then went from `retention_policies()` REFUSING
    /// to answering `Ok(30 days)` with `policy_drift` EMPTY: the replayed
    /// policy governs and a sweep destroys under it. The same boundary feeds
    /// [`crate::VaultStore::version_boundary`], so that one statement
    /// disabled O234's arm 1 for every table and every key at once.
    ///
    /// `rotate.rs` writes `rotate/{keycheck_hex()[..16]}` under the NEXT
    /// key, and the vault holds that key once the rotation commits — so an
    /// indexed lookup of this handle's own keycheck names exactly the
    /// rotation that installed the key the comparison is made under. That is
    /// what the boundary always meant, and a planted label with a foreign
    /// keycheck is rejected in constant time. It can only make the boundary
    /// SMALLER or `None`, i.e. strictly more checking: a vault that never
    /// rotated, or that was rotated by a binary older than A19 (which
    /// appended no record at all), answers `None` exactly as before.
    ///
    /// **A COPY of this key's own label is not rejected** (ROADMAP O247).
    /// The label sits in clear — in `meta.keycheck` on every vault a writable
    /// open has touched, and in `audit.record_id` once the vault has rotated
    /// — so a row appended under it lifts the boundary to its seq, and a copy
    /// of the real rotation record carries a genuine tag. What refuses it is
    /// the replay, and only the replay: `a_copied_rotation_record_is_refused_by_the_replay_and_not_by_its_label`.
    /// Freezing the boundary at the last replay was ruled NOT to be built
    /// here, because every outcome it would prevent is reachable at equal
    /// cost by the edits ROADMAP O252 files; it is one component of that
    /// entry's fix.
    pub(crate) fn rotation_boundary(
        &self,
        snap: &Snapshot<'_>,
        on: LabelUse,
    ) -> Result<Option<i64>, StoreError> {
        let label = rotation_label(&self.vault);
        Ok(self.newest_record(snap, &label, on)?.map(|r| r.seq))
    }

    /// Install a verdict the OPEN's replay produced, so the first guarded
    /// read does not walk the same rows again (ROADMAP O251).
    ///
    /// **It does not count as a replay**, and that is deliberate rather than
    /// an oversight: `chain_replays` answers *how many times did this handle
    /// walk the whole `audit` table*, and the point of this unit is that the
    /// walk happened once. Counting it here would report the cost O251
    /// removes as though it were still being paid.
    ///
    /// The caller has already checked that the chain has not moved since the
    /// replay; this only records it.
    pub(crate) fn seed_label_verdict(
        &self,
        data_version: i64,
        chain_ok: bool,
        labels: crate::LabelCommitment,
    ) {
        self.labels.borrow_mut().replayed = Some(Replayed {
            data_version,
            chain_ok,
            labels,
        });
    }

    /// How many full replays this handle has run, for the life of the
    /// handle (ROADMAP O250).
    ///
    /// **The HANDLE's number, not the database's**, and that is structural
    /// rather than a choice: [`LabelGuard`] lives on the `VaultStore`, so
    /// there is nowhere else for it to live. It is O122's `embed_failures`
    /// contract one door over — on the CLI every command is its own handle
    /// and reads its own count; on `serve-http` it accumulates for as long
    /// as the handle is cached. A restart reads zero while the `audit` rows
    /// that made the replay expensive are all still there.
    pub(crate) fn replays(&self) -> u64 {
        self.labels.borrow().replays
    }

    /// The invariant for one label.
    ///
    /// Checked against every pin on any snapshot; a pin is RECORDED only from
    /// one the helper opened (ROADMAP O253): inside a caller's transaction the
    /// row read may yet roll back, and `AUTOINCREMENT` reuses its `seq`.
    fn hold_append_only(
        &self,
        snap: &Snapshot<'_>,
        record_id: &str,
        found: Option<&ChainRecord>,
    ) -> Result<(), StoreError> {
        let mut guard = self.labels.borrow_mut();
        let complaint = match (guard.newest.get(record_id), found) {
            (Some(seen), None) => Some(format!(
                "this handle read its record at seq {} and the chain now holds none",
                seen.seq
            )),
            (Some(seen), Some(now)) if now.seq < seen.seq => Some(format!(
                "its newest record moved back from seq {} to seq {}",
                seen.seq, now.seq
            )),
            (Some(seen), Some(now)) if now.seq == seen.seq && now.tag != seen.tag => Some(format!(
                "the record at seq {} now carries a different tag",
                seen.seq
            )),
            _ => None,
        };
        if let Some(what) = complaint {
            return Err(append_only_finding(record_id, &what));
        }
        if snap.origin() != Origin::Opened {
            return Ok(());
        }
        if let Some(now) = found {
            guard.newest.insert(
                record_id.to_string(),
                Seen {
                    seq: now.seq,
                    tag: now.tag.clone(),
                },
            );
        }
        Ok(())
    }

    /// The invariant for one namespace's label set.
    fn hold_keys_append_only(
        &self,
        snap: &Snapshot<'_>,
        ns: Namespace,
        found: &[String],
    ) -> Result<(), StoreError> {
        let mut guard = self.labels.borrow_mut();
        let seen = guard.keys.entry(ns.prefix()).or_default();
        if let Some(gone) = seen.iter().find(|k| !found.contains(k)) {
            let gone = gone.clone();
            return Err(append_only_finding(
                &gone,
                "this handle read it in the chain and the chain no longer carries it",
            ));
        }
        if snap.origin() == Origin::Opened {
            seen.extend(found.iter().cloned());
        }
        Ok(())
    }
}

/// One wording for both halves of the invariant, so the two cannot describe
/// the same mechanism differently.
fn append_only_finding(record_id: &str, what: &str) -> StoreError {
    StoreError::IntegrityFinding(format!(
        "{record_id}: {what} — the audit trail is append-only, so a record that moved \
         or vanished while this process held the vault open is tampering; run \
         `undercroft verify`, then restore a backup that verifies"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LabelCommitment, VaultStore};
    use tempfile::TempDir;
    use undercroft_core::{Drawer, HashEmbedder};
    use undercroft_vault::{Access, SecurityLevel, VaultManager};

    fn drawer(content: &str, idx: u32) -> Drawer {
        Drawer::new(
            "wing",
            "room",
            content.into(),
            Some("t.md".into()),
            idx,
            "t",
        )
    }

    fn fresh(level: SecurityLevel) -> (TempDir, VaultStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let store = VaultStore::open(mgr.create("r", level).unwrap()).unwrap();
        (dir, store)
    }

    fn reopen(dir: &TempDir) -> Result<VaultStore, StoreError> {
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        VaultStore::open(mgr.unlock("r").unwrap())
    }

    fn reopen_read_only(dir: &TempDir) -> VaultStore {
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        VaultStore::open_read_only(
            mgr.unlock_as("r", Access::ReadOnly).unwrap(),
            Box::new(HashEmbedder),
        )
        .unwrap()
    }

    fn rotate(dir: &TempDir, store: &mut VaultStore) -> Result<(), StoreError> {
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        store
            .rotate_keys(mgr.rotation_candidate("r").unwrap())
            .map(|_| ())
    }

    fn commitments(store: &VaultStore) -> i64 {
        store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE record_id = ?1",
                params![commitment_label()],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// **ROADMAP O243's gate: every `Namespace::ALL` variant is driven
    /// through `prefix_range`, and the bare one does not panic.** Before the
    /// fix the first variant, `Drawer`, panicked on `lo.len() - 1`. The
    /// prefixed arms pin the range's shape against each namespace's own
    /// spelling, and a seeded store shows the selections partition the
    /// table: `chain_keys(Drawer)` answers the bare drawer labels and no
    /// prefixed one, `chain_keys(Trust)` the `trust/` labels alone.
    #[test]
    fn every_namespace_selects_its_labels_and_the_bare_one_does_not_panic() {
        let mut bare = 0;
        for ns in Namespace::ALL.iter().copied() {
            let range = prefix_range(ns);
            let prefix = ns.prefix();
            match &range {
                LabelRange::Bare => {
                    assert!(prefix.is_empty(), "{ns:?}: only an empty prefix is bare");
                    bare += 1;
                }
                LabelRange::Prefixed { lo, hi } => {
                    assert_eq!(lo, prefix, "{ns:?}: the range starts at the prefix");
                    assert!(
                        prefix.ends_with('/'),
                        "{ns:?}: a prefix ends in the slash the bound replaces"
                    );
                    assert_eq!(
                        hi,
                        &format!("{}0", &prefix[..prefix.len() - 1]),
                        "{ns:?}: the bound is the prefix with its slash replaced by `0`"
                    );
                    assert!(lo < hi, "{ns:?}: the range is non-empty");
                }
            }
            // The clause is well-formed SQL for both shapes: prepare it.
            let (clause, ps) = range.clause(1);
            let (_d, s) = fresh(SecurityLevel::HmacOnly);
            let sql = format!("SELECT COUNT(*) FROM audit WHERE {clause}");
            let n: i64 = s
                .conn
                .query_row(&sql, rusqlite::params_from_iter(ps.iter()), |r| r.get(0))
                .unwrap_or_else(|e| panic!("{ns:?}: the clause does not prepare: {e}"));
            assert!(n >= 0);
        }
        assert_eq!(bare, 1, "exactly one namespace is bare: Drawer");

        // The selections partition a real table.
        let (_d, mut s) = fresh(SecurityLevel::HmacOnly);
        s.upsert(&drawer("first", 0)).unwrap();
        s.upsert(&drawer("second", 1)).unwrap();
        s.set_wing_trust("wing", "quarantined").unwrap();
        let drawers = chain_keys(&s.conn, Namespace::Drawer).unwrap();
        assert_eq!(drawers.len(), 2, "two bare drawer labels: {drawers:?}");
        assert!(drawers.iter().all(|k| !k.contains('/')), "{drawers:?}");
        let trust = chain_keys(&s.conn, Namespace::Trust).unwrap();
        assert_eq!(trust, vec!["trust/wing".to_string()]);
        let rotations = chain_keys(&s.conn, Namespace::Rotate).unwrap();
        assert!(rotations.is_empty(), "{rotations:?}");
        assert_eq!(rotations_since(&s.conn, 0).unwrap(), 0);
        // Every namespace's keys together cover every label exactly once.
        let total: usize = Namespace::ALL
            .iter()
            .map(|ns| chain_keys(&s.conn, *ns).unwrap().len())
            .sum();
        let distinct: i64 = s
            .conn
            .query_row("SELECT COUNT(DISTINCT record_id) FROM audit", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            total as i64, distinct,
            "the namespace selections partition the labels"
        );
    }

    /// The production prefix digest over the first `n` rows (ROADMAP O245),
    /// as the witness binds it.
    fn prefix_digest(store: &VaultStore, n: usize) -> [u8; 32] {
        store
            .snapshot(|s| prefix(s, Some(n as u64)))
            .unwrap()
            .at_digest
            .expect("the fixture holds at least n rows")
    }

    /// **ROADMAP O245, probes P1 and P4 — named by the ruling panel's
    /// refuter, run by the integrator, and now the pin under the witness
    /// the entry builds.** P1: a key rotation moves every
    /// intermediate chain head (both regimes step under a key the rotation
    /// re-derives), so a witness carrying only a head is unreachable after
    /// the first `vault rotate`; an unkeyed digest over the preserved
    /// `(record_id, tag, at)` bytes of the same prefix does not move. P4: a
    /// row that lands without moving `chain_meta.writes` is positioned by
    /// the replay's ROW count and not by `writes`, so a witness must carry
    /// rows, never `writes`, as its height.
    #[test]
    fn o245_probe_p1_p4_rotation_moves_heads_and_keeps_the_prefix_digest() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        for i in 0..3 {
            store.upsert(&drawer(&format!("fact {i}"), i)).unwrap();
        }
        let before = store.snapshot(|s| replay(s, &store.vault, None)).unwrap();
        let head_n = before.head.clone();
        let n = before.rows;
        let digest_n = prefix_digest(&store, n);
        // PREMISE: the head is a prefix point of its own chain before the
        // rotation, so a `!anchor_seen` afterwards is the rotation's doing.
        let seen = store
            .snapshot(|s| replay(s, &store.vault, Some(&head_n)))
            .unwrap();
        assert!(seen.anchor_seen, "premise: the head is on its own chain");
        assert_eq!(seen.behind_by, 0, "premise: it is the newest head");

        rotate(&dir, &mut store).unwrap();

        let after = store
            .snapshot(|s| replay(s, &store.vault, Some(&head_n)))
            .unwrap();
        assert_eq!(after.rows, n + 1, "the rotation appended its own record");
        assert!(
            !after.anchor_seen,
            "P1: a pre-rotation head is unreachable after a rotation (O13's shape)"
        );
        assert_eq!(
            prefix_digest(&store, n),
            digest_n,
            "P1: the unkeyed prefix digest is rotation-stable"
        );
        assert_ne!(
            prefix_digest(&store, n + 1),
            digest_n,
            "P1: the digest is count-bound — one more row is a different digest"
        );

        // P4: plant a row without moving `writes` (the retention fixture's
        // shape); the replay positions by rows and `writes` stays behind.
        let writes_before = writes(&store.conn).unwrap();
        store
            .conn
            .execute(
                "INSERT INTO audit (record_id, tag, at) \
                 VALUES ('probe/o245', X'00', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        let planted = store.snapshot(|s| replay(s, &store.vault, None)).unwrap();
        assert_eq!(planted.rows, n + 2, "P4: the replay counts the planted row");
        assert_eq!(
            writes(&store.conn).unwrap(),
            writes_before,
            "P4: `writes` did not move, so it is not the row height"
        );
    }

    /// **The switch happens once, at the first writable open, on every
    /// level** — including hmac-only, whose A10 marker is never written: a
    /// switch that waited for that marker alone (what every lens of the
    /// ruling proposed) would have left every hmac-only vault unswitched for
    /// ever, and this test is the one that says so.
    #[test]
    fn a_fresh_vault_switches_once_on_every_level() {
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let (dir, store) = fresh(level);
            assert!(
                matches!(regime(&store.conn).unwrap(), Regime::V2 { switch_seq: 1 }),
                "{level:?}: the commitment is the first record"
            );
            assert_eq!(commitments(&store), 1, "{level:?}");
            let report = store.verify().unwrap();
            assert!(report.ok(), "{level:?}: {report:?}");
            assert_eq!(
                report.label_commitment,
                LabelCommitment::Intact,
                "{level:?}"
            );
            drop(store);
            let again = reopen(&dir).unwrap();
            assert_eq!(commitments(&again), 1, "{level:?}: a reopen writes nothing");
        }
    }

    /// **P1r, the entry's own probe: a relabel plus a row deletion now fails
    /// `verify` and blocks a rotation.** Before O233 this read `VERIFY OK`
    /// and a `standard`-floored search returned the quarantined wing.
    #[test]
    fn a_relabel_after_the_switch_breaks_the_chain_and_blocks_a_rotation() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.set_wing_trust("secret", "quarantined").unwrap();
        assert!(store.verify().unwrap().ok(), "premise: clean");
        store
            .conn
            .execute(
                "UPDATE audit SET record_id = 'read/x' WHERE record_id = 'trust/secret'",
                [],
            )
            .unwrap();
        store.conn.execute("DELETE FROM wing_trust", []).unwrap();
        let report = store.verify().unwrap();
        assert!(
            report.policy_drift.is_empty(),
            "premise: the relabel hides the deletion from the policy leg, as O230 pinned"
        );
        assert!(
            !report.chain_ok,
            "the relabel breaks the replay: {report:?}"
        );
        assert!(!report.ok());
        assert!(
            matches!(
                rotate(&dir, &mut store),
                Err(StoreError::IntegrityFinding(_))
            ),
            "a rotation would re-step the forged label under the next key"
        );
    }

    /// Every field of an audit row after the switch is bound — the time,
    /// and the STORAGE TYPE of the label and the tag: SQLite compares a text
    /// value and a blob of the same bytes as unequal, so a label rewritten as
    /// a blob hides from every `record_id = ?` lookup while its bytes step
    /// the same.
    #[test]
    fn a_retimed_or_retyped_record_after_the_switch_breaks_the_chain() {
        type Tamper = fn(&Connection);
        let tampers: [(&str, Tamper); 3] = [
            ("re-timed", |c: &Connection| {
                c.execute(
                    "UPDATE audit SET at = '2000-01-01T00:00:00Z' \
                     WHERE record_id = 'trust/secret'",
                    [],
                )
                .unwrap();
            }),
            ("label retyped", |c: &Connection| {
                c.execute(
                    "UPDATE audit SET record_id = CAST(record_id AS BLOB) \
                     WHERE record_id = 'trust/secret'",
                    [],
                )
                .unwrap();
                let found: i64 = c
                    .query_row(
                        "SELECT COUNT(*) FROM audit WHERE record_id = 'trust/secret'",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(found, 0, "premise: the blob label hides from the lookup");
            }),
            ("tag retyped", |c: &Connection| {
                c.execute(
                    "UPDATE audit SET tag = CAST(tag AS TEXT) WHERE record_id = 'trust/secret'",
                    [],
                )
                .unwrap();
            }),
        ];
        for (name, tamper) in tampers {
            let (_dir, mut store) = fresh(SecurityLevel::Sealed);
            store.set_wing_trust("secret", "quarantined").unwrap();
            assert!(store.verify().unwrap().chain_ok, "{name}: premise");
            tamper(&store.conn);
            assert!(!store.verify().unwrap().chain_ok, "{name}");
        }
    }

    /// **A relabel BEFORE the switch is the commitment's finding, and a
    /// rotation neither refuses over it nor launders it** — the commitment is
    /// an unkeyed digest a rotation preserves verbatim with the rows it
    /// covers (O232 ruling 1: refuse only what a rotation would launder).
    #[test]
    fn a_relabel_before_the_switch_is_a_commitment_mismatch_a_rotation_preserves() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.unswitch_chain_for_test();
        store.set_wing_trust("secret", "quarantined").unwrap();
        let d = drawer("written before the switch", 0);
        store.upsert(&d).unwrap();
        assert_eq!(regime(&store.conn).unwrap(), Regime::V1, "premise: legacy");
        assert_eq!(
            store.verify().unwrap().label_commitment,
            LabelCommitment::Pending
        );
        drop(store);
        let mut store = reopen(&dir).unwrap();
        assert!(matches!(regime(&store.conn).unwrap(), Regime::V2 { .. }));
        let clean = store.verify().unwrap();
        assert!(
            clean.ok(),
            "the legacy history verifies after the switch: {clean:?}"
        );
        assert_eq!(clean.label_commitment, LabelCommitment::Intact);

        // The DRAWER's record, not the trust assignment's: relabelling
        // `trust/secret` is also a policy finding (a row with no record),
        // which blocks a rotation on its own — this isolates the commitment.
        store
            .conn
            .execute(
                "UPDATE audit SET record_id = 'read/x' WHERE record_id = ?1",
                params![d.id],
            )
            .unwrap();
        let report = store.verify().unwrap();
        assert!(
            report.chain_ok,
            "premise: a version-1 step never saw the label: {report:?}"
        );
        assert_eq!(report.label_commitment, LabelCommitment::Mismatch);
        assert!(!report.ok(), "and it fails the verdict");
        rotate(&dir, &mut store).expect("not a rotation blocker");
        let after = store.verify().unwrap();
        assert!(after.chain_ok, "{after:?}");
        assert_eq!(
            after.label_commitment,
            LabelCommitment::Mismatch,
            "the rotation preserved the evidence rather than laundering it"
        );
    }

    /// A crash between the switch's commit and its anchor leaves the
    /// manifest on the version-1 head; the next open finds it in the
    /// version-1 prefix and heals, with no new acceptance path.
    #[test]
    fn a_crash_between_the_switch_and_its_anchor_heals() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.unswitch_chain_for_test();
        store.upsert(&drawer("a legacy drawer", 0)).unwrap();
        let manifest = dir.path().join("vaults/r/vault.json");
        let before = std::fs::read(&manifest).unwrap();
        drop(store);
        let store = reopen(&dir).unwrap();
        assert!(matches!(regime(&store.conn).unwrap(), Regime::V2 { .. }));
        drop(store);
        // The anchor as it was before the switch committed: behind by one.
        std::fs::write(&manifest, &before).unwrap();
        let store = reopen(&dir).unwrap();
        assert!(
            matches!(
                store.anchor_at_open,
                crate::AnchorState::Healed { behind_by: 1 }
            ),
            "{:?}",
            store.anchor_at_open
        );
        assert!(store.verify().unwrap().ok());
    }

    /// **The downgrade fence's pair must agree**: a commitment with no
    /// version-2 head, a version-2 head with no commitment, or no frozen
    /// head, is an integrity finding — refused by a writable open, reported
    /// by a read-only one, and never a quiet fall back to version-1 writes.
    #[test]
    fn a_head_key_without_its_commitment_is_an_integrity_finding() {
        for (name, sql) in [
            (
                "no version-2 head",
                "DELETE FROM chain_meta WHERE key = 'head_v2'",
            ),
            (
                "no commitment",
                "DELETE FROM audit WHERE record_id = 'migrate/chain-v2'",
            ),
            (
                "no frozen head",
                "DELETE FROM chain_meta WHERE key = 'head'",
            ),
        ] {
            let (dir, store) = fresh(SecurityLevel::Sealed);
            store.conn.execute(sql, []).unwrap();
            drop(store);
            assert!(
                matches!(reopen(&dir), Err(StoreError::IntegrityFinding(_))),
                "{name}: a writable open refuses"
            );
            let ro = reopen_read_only(&dir);
            assert!(
                ro.unhealed().iter().any(|u| u.contains("audit chain:")),
                "{name}: a read-only open reports: {:?}",
                ro.unhealed()
            );
            assert!(!ro.verify().unwrap().chain_ok, "{name}");
        }
    }

    /// A read-only open never switches, and says the labels are not bound.
    #[test]
    fn a_read_only_open_reports_an_unswitched_chain_and_switches_nothing() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.unswitch_chain_for_test();
        drop(store);
        let ro = reopen_read_only(&dir);
        assert_eq!(regime(&ro.conn).unwrap(), Regime::V1);
        assert!(
            ro.unhealed()
                .iter()
                .any(|u| u.contains("not yet chain-authenticated")),
            "{:?}",
            ro.unhealed()
        );
        assert!(
            ro.verify().unwrap().ok(),
            "an unswitched chain still verifies"
        );
    }

    /// **A forget attestation names its step, and a version-2 one binds the
    /// labels and times of its tombstones.** A switched chain mints version
    /// 2; the same document relabelled as version 1 fails its keyed replay
    /// (the tamper verdict), and a version this build does not know is
    /// refused as unsupported — an input error, never "forged".
    #[test]
    fn a_switched_chain_mints_version_2_attestations_that_bind_their_labels() {
        use crate::forget::AttestationVerdict;
        let (_dir, mut store) = fresh(SecurityLevel::Sealed);
        let d = drawer("the ledger was signed", 0);
        store.upsert(&d).unwrap();
        let att = store
            .forget_with_proof(std::slice::from_ref(&d.id))
            .unwrap();
        assert_eq!(att.version, 2);
        assert_eq!(
            store.verify_forget_attestation(&att).unwrap(),
            AttestationVerdict::Verified
        );
        let mut as_v1 = att.clone();
        as_v1.version = 1;
        assert!(
            matches!(
                store.verify_forget_attestation(&as_v1),
                Err(StoreError::Attestation(_))
            ),
            "the version-1 step does not reproduce version-2 heads"
        );
        let mut retimed = att.clone();
        retimed.records[0].at = "2000-01-01T00:00:00Z".into();
        assert!(
            matches!(
                store.verify_forget_attestation(&retimed),
                Err(StoreError::Attestation(_))
            ),
            "a version-2 replay binds each tombstone's time"
        );
        let mut unknown = att;
        unknown.version = 3;
        assert!(
            matches!(
                store.verify_forget_attestation(&unknown),
                Err(StoreError::Invalid(_))
            ),
            "unsupported, not forged"
        );
    }

    /// An attestation minted on a legacy chain keeps verifying after the
    /// chain switches: its heads are version-1 heads, and the replay is
    /// self-contained over the document's own records.
    #[test]
    fn an_attestation_minted_before_the_switch_verifies_after_it() {
        use crate::forget::AttestationVerdict;
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.unswitch_chain_for_test();
        let d = drawer("destroyed before the upgrade", 0);
        store.upsert(&d).unwrap();
        let att = store
            .forget_with_proof(std::slice::from_ref(&d.id))
            .unwrap();
        assert_eq!(att.version, 1, "premise: minted on a version-1 chain");
        drop(store);
        let store = reopen(&dir).unwrap();
        assert!(matches!(regime(&store.conn).unwrap(), Regime::V2 { .. }));
        assert_eq!(
            store.verify_forget_attestation(&att).unwrap(),
            AttestationVerdict::Verified
        );
    }

    /// **The recorded verdict vouches only from a trail that verifies**, and
    /// finds its run by ORDER, not by `seq` arithmetic: an order-preserving
    /// renumber that opens a gap inside the run leaves a genuine document
    /// `Recorded` (the arithmetic form read it as forged), while a relabel
    /// after the switch makes the trail unauthenticated and refuses.
    #[test]
    fn the_recorded_verdict_needs_an_authenticated_trail_and_reads_it_by_order() {
        use crate::forget::AttestationVerdict;
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        let a = drawer("first destroyed", 0);
        let b = drawer("second destroyed", 1);
        let keep = drawer("kept", 2);
        for d in [&a, &b, &keep] {
            store.upsert(d).unwrap();
        }
        let att = store
            .forget_with_proof(&[a.id.clone(), b.id.clone()])
            .unwrap();
        rotate(&dir, &mut store).unwrap();
        assert!(
            matches!(
                store.verify_forget_attestation(&att).unwrap(),
                AttestationVerdict::Recorded { .. }
            ),
            "premise: after a rotation the keyed replay is unavailable"
        );

        // Open a gap inside the run, preserving order: the second tombstone
        // and everything after it move up by 1000. The chain folds order,
        // not numbers, so it still replays.
        let second: i64 = store
            .conn
            .query_row(
                "SELECT seq FROM audit WHERE record_id = ?1",
                params![format!("del/{}", b.id)],
                |r| r.get(0),
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE audit SET seq = -seq WHERE seq >= ?1",
                params![second],
            )
            .unwrap();
        store
            .conn
            .execute("UPDATE audit SET seq = 1000 - seq WHERE seq < 0", params![])
            .unwrap();
        assert!(store.verify().unwrap().chain_ok, "premise: order preserved");
        assert!(
            matches!(
                store.verify_forget_attestation(&att).unwrap(),
                AttestationVerdict::Recorded { rotations_since: 1 }
            ),
            "a renumbered run is still this vault's recorded evidence"
        );

        store
            .conn
            .execute(
                "UPDATE audit SET record_id = 'read/x' WHERE record_id = ?1",
                params![keep.id],
            )
            .unwrap();
        assert!(
            !store.verify().unwrap().chain_ok,
            "premise: the trail is broken"
        );
        assert!(
            matches!(
                store.verify_forget_attestation(&att),
                Err(StoreError::IntegrityFinding(_))
            ),
            "an unauthenticated trail cannot vouch for recorded tombstones"
        );
    }

    /// The files `lib.rs` declares as `#[cfg(test)] mod name;` — a WHOLE
    /// file of test code, which a split at `mod tests` cannot see. Derived
    /// from `lib.rs` rather than listed, so a new one is skipped the day it
    /// is declared (ROADMAP O253 added the second: its interleaving gate
    /// steps the chain itself, independently of the code it checks).
    fn test_only_files() -> std::collections::BTreeSet<String> {
        let lib = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
        )
        .unwrap();
        let mut out = std::collections::BTreeSet::new();
        let mut previous = "";
        for line in lib.lines() {
            let t = line.trim();
            if previous == "#[cfg(test)]" {
                if let Some(name) = t.strip_prefix("mod ").and_then(|r| r.strip_suffix(';')) {
                    out.insert(format!("{name}.rs"));
                }
            }
            if !t.is_empty() {
                previous = t;
            }
        }
        out
    }

    /// Every `.rs` file of this crate, cut at its test module, with comment
    /// lines dropped: prose naming a statement is not the statement. A file
    /// that IS a test module is skipped whole.
    fn production_lines() -> Vec<(String, usize, String)> {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let skip = test_only_files();
        // PREMISE: the reader finds the modules it exists to skip.
        assert!(
            skip.contains("anchor_tests.rs") && skip.contains("snapshot_tests.rs"),
            "premise: lib.rs declares its whole-file test modules: {skip:?}"
        );
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&src).expect("the crate's own sources are readable") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs")
                || skip.contains(&path.file_name().unwrap().to_string_lossy().to_string())
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let prod = text
                .split("#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or_default();
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            for (i, line) in prod.lines().enumerate() {
                if !line.trim_start().starts_with("//") {
                    out.push((file.clone(), i + 1, line.to_string()));
                }
            }
        }
        out
    }

    fn sites(lines: &[(String, usize, String)], needle: &str) -> Vec<String> {
        lines
            .iter()
            .filter(|(_, _, l)| l.contains(needle))
            .map(|(f, n, _)| format!("{f}:{n}"))
            .collect()
    }

    /// **ROADMAP O233's source gates: one owner for the chain.** Every head,
    /// every replay, every `audit` insert and every step go through this
    /// module, because each of those used to be written out by hand at
    /// several sites — four replay loops, nine `key = 'head'` reads — and a
    /// site left on the version-1 arithmetic is invisible until the first
    /// crash (a reconciliation still stepping v1 makes a switched vault
    /// unopenable). Needles are split with `concat!` so this test is not its
    /// own match.
    #[test]
    fn the_chain_has_one_owner_in_this_crate() {
        let lines = production_lines();
        assert!(
            lines.len() > 10_000 && !sites(&lines, "chain_meta").is_empty(),
            "premise: the scan read the crate's production source"
        );
        let head_reads = sites(&lines, concat!("key = ", "'head'"));
        assert!(
            head_reads.is_empty(),
            "the live head moved to `head_v2` at the switch; read it through \
             `chain::committed_head`: {head_reads:?}"
        );
        let tag_replays = sites(&lines, concat!("SELECT tag FROM audit ", "ORDER BY seq"));
        assert!(
            tag_replays.is_empty(),
            "a replay over tags alone cannot step a switched chain: {tag_replays:?}"
        );
        let inserts = sites(&lines, concat!("INSERT INTO ", "audit"));
        assert_eq!(
            inserts.len(),
            1,
            "`chain::insert_record` is the table's one writer: {inserts:?}"
        );
        assert!(inserts[0].starts_with("chain.rs:"), "{inserts:?}");
        let steps = sites(&lines, concat!(".chain_step", "_hex("));
        let files: std::collections::BTreeSet<&str> =
            steps.iter().map(|s| s.split(':').next().unwrap()).collect();
        assert_eq!(
            files.into_iter().collect::<Vec<_>>(),
            vec!["chain.rs", "forget.rs"],
            "a step is taken by the chain module, and by a forget attestation's \
             self-contained replay, which names its version: {steps:?}"
        );
        let relabels = sites(&lines, concat!("UPDATE ", "audit"));
        assert_eq!(
            relabels.len(),
            1,
            "A10's relabel is the only production rewrite of an audit row, and it \
             never runs on a switched chain: {relabels:?}"
        );
        assert!(relabels[0].starts_with("kg.rs:"), "{relabels:?}");
    }

    /// **A sealed vault whose A10 walk is incomplete stays on version 1**,
    /// because that walk relabels `audit` rows; an hmac-only vault, which
    /// never runs the walk, does not wait for it (the test above).
    #[test]
    fn the_switch_waits_for_a_sealed_vaults_blinding_walk() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.unswitch_chain_for_test();
        store
            .conn
            .execute("DELETE FROM meta WHERE key = 'kg_blind_version'", [])
            .unwrap();
        assert!(!store.kg_blind_complete().unwrap(), "premise");
        // An open would re-run A10 first, which on an empty graph completes
        // and writes the marker — so drive the switch directly to observe
        // the wait, then let a real open show the order.
        store.switch_chain_to_v2().unwrap();
        assert_eq!(regime(&store.conn).unwrap(), Regime::V1, "withheld");
        assert!(store
            .unhealed()
            .iter()
            .any(|u| u.contains("waits for the knowledge-graph blinding")));
        drop(store);
        let store = reopen(&dir).unwrap();
        assert!(
            matches!(regime(&store.conn).unwrap(), Regime::V2 { .. }),
            "once the walk completes, the same open switches"
        );
    }

    // ── ROADMAP O237: a read that DECIDES from a label asks first whether
    //    the labels are still this vault's ────────────────────────────────

    /// Relabel a wing's trust record and delete its row — the exploit P1r
    /// names, in one place so every arm below runs the same edit.
    fn lift_the_floor(conn: &Connection, wing: &str) {
        conn.execute(
            "UPDATE audit SET record_id = 'read/x' WHERE record_id = ?1",
            params![Namespace::Trust.record(wing)],
        )
        .unwrap();
        conn.execute("DELETE FROM wing_trust WHERE wing = ?1", params![wing])
            .unwrap();
    }

    /// **P1r, the gate this entry was filed on.** O233 made the relabel
    /// break `verify`; it left the reads that consult labels acting on one
    /// first, so the floored search returned the quarantined drawer until
    /// somebody ran `verify`. Now `wing_trusts()` — and so `trust_clause`,
    /// the floor, `recent` and `list_drawers` — refuses.
    ///
    /// The edit is made on the handle's OWN connection, which is the hard
    /// case on purpose: `PRAGMA data_version` does not move for it, so the
    /// cached replay verdict is reused and the APPEND-ONLY invariant is the
    /// only thing that can see it. A test that tampered from a second
    /// connection would pass on the replay alone and say nothing about half
    /// the mechanism.
    #[test]
    fn p1r_a_relabelled_trust_record_refuses_the_floored_read_before_any_verify() {
        let (_dir, mut store) = fresh(SecurityLevel::Sealed);
        store.set_wing_trust("secret", "quarantined").unwrap();
        assert_eq!(
            store.wing_trusts().unwrap(),
            vec![("secret".to_string(), "quarantined".to_string())],
            "premise: the floor reads the assignment"
        );
        let before = store.replays();
        lift_the_floor(&store.conn, "secret");
        let err = store.wing_trusts().unwrap_err();
        assert!(
            matches!(&err, StoreError::IntegrityFinding(m)
                     if m.contains("append-only") && m.contains("trust/secret")),
            "the floored read refuses, naming the record: {err}"
        );
        assert_eq!(
            store.replays(),
            before,
            "premise: no replay re-ran, so this was the append-only invariant"
        );
        // And the same refusal reaches the reads the floor rides.
        assert!(store.trust_clause("standard").is_err());
        // `verify` still REPORTS rather than refusing — it is the check an
        // operator runs next, and a `verify` that errors instead of
        // answering is the failure it exists to prevent.
        let report = store.verify().unwrap();
        assert!(!report.chain_ok && !report.ok(), "{report:?}");
    }

    /// The other side of the window: tampering done before this process ever
    /// opened the vault, which no per-key memory can have seen. The LAZY
    /// REPLAY is what catches it, and the two are told apart by the wording
    /// each produces.
    #[test]
    fn a_chain_tampered_before_the_handle_opened_refuses_on_the_first_guarded_read() {
        let dir = TempDir::new().unwrap();
        {
            let mgr = VaultManager::open(dir.path(), None).unwrap();
            let mut store =
                VaultStore::open(mgr.create("r", SecurityLevel::Sealed).unwrap()).unwrap();
            store.set_wing_trust("secret", "quarantined").unwrap();
            assert!(store.verify().unwrap().ok(), "premise: clean");
        }
        {
            let db = dir.path().join("vaults/r/vault.db");
            let conn = Connection::open(&db).unwrap();
            lift_the_floor(&conn, "secret");
        }
        let store = reopen(&dir).unwrap();
        assert_eq!(store.replays(), 0, "premise: nothing has replayed yet");
        let err = store.wing_trusts().unwrap_err();
        assert!(
            matches!(&err, StoreError::IntegrityFinding(m)
                     if m.contains("does not authenticate its own labels")),
            "the first guarded read replays and refuses: {err}"
        );
        assert_eq!(store.replays(), 1);
    }

    /// **The replay runs at most ONCE per handle over N guarded reads**, and
    /// `PRAGMA data_version` is what makes that true rather than a cache that
    /// never expires: a write from another connection moves the cookie and
    /// the next guarded read replays again.
    #[test]
    fn the_replay_runs_once_per_handle_and_again_only_when_another_writer_commits() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.set_wing_trust("secret", "quarantined").unwrap();
        store.set_retention("secret", None, 30).unwrap();
        store.upsert(&drawer("a harbour crane at dawn", 0)).unwrap();
        for _ in 0..5 {
            store.wing_trusts().unwrap();
            store.retention_policies().unwrap();
            store
                .recent(None, 5, crate::Read::Returned(crate::ReadOp::Recent))
                .unwrap();
        }
        assert_eq!(
            store.replays(),
            1,
            "fifteen guarded reads, one replay — the cost the ruling priced"
        );
        // A second handle on the same vault commits: the cookie moves and
        // the guard re-establishes the verdict rather than trusting a stale
        // one. Two handles on one vault is an ordinary deployment, so this
        // is also a false-alarm arm — it must not refuse.
        {
            let mut other = reopen(&dir).unwrap();
            other.set_wing_trust("second", "trusted").unwrap();
        }
        store.wing_trusts().unwrap();
        assert_eq!(store.replays(), 2, "the foreign commit is not trusted away");
        store.wing_trusts().unwrap();
        assert_eq!(store.replays(), 2, "and then it settles again");

        // **ROADMAP O250: and the number REACHES A SURFACE.** This is the
        // ruling's own gate — "with the guard's replay forced twice in one
        // handle, the promoted counter reads 2" — and it is asserted here
        // rather than in its own test because this is the only place in the
        // tree that forces exactly two replays on one handle, and a second
        // fixture reproducing it would be a second statement of what "a
        // foreign commit" means.
        //
        // Until O250 the count was `#[cfg(test)]`, so nothing outside a test
        // build could say whether the once-per-handle bound held — which is
        // how O242 ran at +213% on `serve-http` for a whole release and was
        // found by a reviewer reading code rather than by an observable.
        // A unit test cannot tell the promoted counter from the test-only
        // one (it compiles with `cfg(test)` on either way); `tests/e2e.sh`
        // drives the release binary for that half.
        assert_eq!(
            store.stats().unwrap().chain_replays,
            2,
            "the guard's own count reaches `VaultStats`, or it is an \
             accessor its tests alone read — which is the defect O122 named"
        );
    }

    /// **ROADMAP O251: an open that already replayed hands its verdict
    /// forward, so the first guarded read runs no SECOND replay.**
    ///
    /// `reconcile_chain` and the guard's `chain_verdict_in` make the same
    /// `chain::replay` call over the same rows, and until O251 the second one was computed
    /// from scratch. It costs nothing in the steady state, because
    /// `reconcile_chain` short-circuits when the anchor equals the committed
    /// head and never replays at all — and one whole replay (88 ms at
    /// 102,001 rows, 836 ms at 1,002,001) exactly when the open DID replay.
    ///
    /// **The lag is manufactured the way production makes it.**
    /// `UNDERCROFT_READ_AUDIT=chain` appends one chain record per
    /// content-returning read and deliberately does not anchor (A31/R3), so
    /// such a deployment ends every command with the anchor behind — and the
    /// next command's open replays to heal it, then replayed AGAIN on its
    /// first guarded read. Two full replays per command, on the one
    /// deployment whose whole purpose is reading.
    #[test]
    fn an_open_that_replayed_hands_its_verdict_to_the_first_guarded_read() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.set_wing_trust("secret", "quarantined").unwrap();
        store.upsert(&drawer("a harbour crane at dawn", 0)).unwrap();
        // Read audits advance `chain_meta` and never anchor, so the handle
        // closes with the manifest behind — which is what makes the NEXT
        // open replay rather than short-circuit.
        store.set_read_audit(true);
        for _ in 0..3 {
            store
                .recent(None, 5, crate::Read::Returned(crate::ReadOp::Recent))
                .unwrap();
        }
        drop(store);

        let reopened = reopen(&dir).unwrap();
        // PREMISE. Without this the test passes on a vault whose open took
        // the short-circuit, where there is no first replay to hand forward
        // and `replays() == 0` means only that nothing happened.
        assert!(
            matches!(reopened.anchor_at_open(), crate::AnchorState::Healed { .. }),
            "premise: the open must have REPLAYED to heal a lagging anchor, \
             got {:?}",
            reopened.anchor_at_open()
        );
        reopened.wing_trusts().unwrap();
        assert_eq!(
            reopened.replays(),
            0,
            "the open already replayed these rows; the guard must reuse that \
             verdict rather than walking them again"
        );
        // And the verdict handed forward is a real one, not a blank that
        // happens to let every read through: the same handle still refuses
        // when the chain stops authenticating its labels.
        let db = dir.path().join("vaults/r/vault.db");
        let other = Connection::open(&db).unwrap();
        lift_the_floor(&other, "secret");
        drop(other);
        let err = reopened.wing_trusts().unwrap_err();
        assert!(
            matches!(&err, StoreError::IntegrityFinding(m)
                     if m.contains("does not authenticate its own labels")),
            "a seeded verdict must not survive a foreign commit: {err}"
        );
        assert_eq!(
            reopened.replays(),
            1,
            "and the foreign commit costs exactly the one replay it should"
        );
    }

    /// **ROADMAP O251, the other half: an open that APPENDED may not hand a
    /// verdict forward**, because its own commits do not move
    /// `PRAGMA data_version` and a seeded verdict would go stale behind an
    /// unmoved cookie — O242 option (C)'s shape in miniature, and that
    /// option "would ship GREEN".
    ///
    /// The writable open appends after its replay in three places:
    /// `blind_existing_kg_rows` (A10), `rekey_content_fingerprints` (U12)
    /// and `switch_chain_to_v2` (O233), which also changes the REGIME and
    /// the live head — so a verdict computed before it would answer
    /// `LabelCommitment::Pending` for a vault that is now version 2.
    #[test]
    fn an_open_that_appended_after_its_replay_hands_nothing_forward() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.set_wing_trust("secret", "quarantined").unwrap();
        // Back to a legacy version-1 chain FIRST: `unswitch_chain_for_test`
        // re-anchors the manifest onto the version-1 head, so doing it after
        // the reads below would leave the anchor CURRENT and the next open
        // would short-circuit instead of replaying — a premise failure
        // dressed as a pass.
        store.unswitch_chain_for_test();
        // Now make the anchor lag, so the next open replays to heal it AND
        // appends its own `migrate/chain-v2` commitment afterwards.
        store.set_read_audit(true);
        for _ in 0..3 {
            store
                .recent(None, 5, crate::Read::Returned(crate::ReadOp::Recent))
                .unwrap();
        }
        drop(store);

        let reopened = reopen(&dir).unwrap();
        assert!(
            matches!(reopened.anchor_at_open(), crate::AnchorState::Healed { .. }),
            "premise: the open replayed, got {:?}",
            reopened.anchor_at_open()
        );
        // Through its own connection: `VaultStore::conn` is private to the
        // crate root, and every test here that needs the database reaches it
        // the same way.
        let db = dir.path().join("vaults/r/vault.db");
        let peek = Connection::open(&db).unwrap();
        assert!(
            matches!(regime(&peek).unwrap(), Regime::V2 { .. }),
            "premise: the open switched the chain, so it APPENDED after its \
             own replay — which is the case a seed must decline"
        );
        drop(peek);
        reopened.wing_trusts().unwrap();
        assert_eq!(
            reopened.replays(),
            1,
            "the open's verdict describes rows the open then added to, so the \
             guard must replay rather than trust it"
        );
    }

    /// A SECOND CONNECTION doing the exploit while this handle is open — the
    /// SQLite-mediated writer `data_version` is measured sound for. The
    /// replay re-runs and refuses; nothing was re-opened.
    #[test]
    fn a_second_connection_tampering_under_an_open_handle_is_refused() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.set_wing_trust("secret", "quarantined").unwrap();
        store.wing_trusts().unwrap();
        let db = dir.path().join("vaults/r/vault.db");
        let other = Connection::open(&db).unwrap();
        lift_the_floor(&other, "secret");
        drop(other);
        let err = store.wing_trusts().unwrap_err();
        assert!(
            matches!(&err, StoreError::IntegrityFinding(m)
                     if m.contains("does not authenticate its own labels")),
            "{err}"
        );
    }

    /// **The legacy carve-out, and what it still buys.** A version-1 chain
    /// replays clean with its labels bound by nothing, so refusing there
    /// would brick every pre-1.6.0 vault served `--read-only` — that
    /// exemption is the ruling's, not an implementation choice. The
    /// append-only invariant is NOT exempt, and on such a vault it is the
    /// only mechanism there is.
    #[test]
    fn a_legacy_chain_serves_its_readers_and_still_holds_the_append_only_rule() {
        let (_dir, mut store) = fresh(SecurityLevel::Sealed);
        store.set_wing_trust("secret", "quarantined").unwrap();
        store.unswitch_chain_for_test();
        assert_eq!(
            regime(&store.conn).unwrap(),
            Regime::V1,
            "premise: a legacy chain"
        );
        assert_eq!(
            store.verify().unwrap().label_commitment,
            crate::LabelCommitment::Pending,
            "premise: its labels are bound by nothing"
        );
        assert_eq!(
            store.wing_trusts().unwrap().len(),
            1,
            "unbound labels are not a refusal"
        );
        lift_the_floor(&store.conn, "secret");
        assert!(
            store.verify().unwrap().chain_ok,
            "premise: the version-1 replay cannot see a relabel at all"
        );
        let err = store.wing_trusts().unwrap_err();
        assert!(
            matches!(&err, StoreError::IntegrityFinding(m) if m.contains("append-only")),
            "the invariant is what a legacy vault gets: {err}"
        );
    }

    /// **A false-alarm sweep, expecting zero.** Every arm is an ordinary
    /// operation; a guard that fires on one of these is worse than none,
    /// because the remedy an operator is told to run (`verify`) reports
    /// nothing wrong.
    ///
    /// Two of the ruling's arms are deliberately not fabricated here and say
    /// why. O233's SWITCH is exercised by the legacy arm above, which
    /// unswitches and re-opens. A PRE-A19-rotated vault — rows re-tagged
    /// with no `rotate/` record — cannot be built any more without breaking
    /// the chain, because the chain now binds labels; such a vault arrives
    /// as a version-1 chain and is the legacy arm, one test up.
    #[test]
    fn ordinary_operations_do_not_trip_the_guard() {
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let (dir, mut store) = fresh(level);
            store.set_wing_trust("secret", "quarantined").unwrap();
            store.set_retention("notes", None, 30).unwrap();
            store.wing_trusts().unwrap();
            store.retention_policies().unwrap();

            // A rotation between two guarded reads: it re-tags every policy
            // row and appends its own record, and the boundary it writes is
            // the one the next read stops at.
            rotate(&dir, &mut store).unwrap();
            assert_eq!(store.wing_trusts().unwrap().len(), 1, "{level:?}");
            assert_eq!(store.retention_policies().unwrap().len(), 1, "{level:?}");

            // A legitimate clear, which deletes the row it declared.
            store.clear_retention("notes", None).unwrap();
            assert!(store.retention_policies().unwrap().is_empty(), "{level:?}");

            // A `trust set` from another handle while this one is open.
            {
                let mut other = reopen(&dir).unwrap();
                other.set_wing_trust("secret", "standard").unwrap();
            }
            assert_eq!(
                store.wing_trusts().unwrap(),
                vec![("secret".to_string(), "standard".to_string())],
                "{level:?}: a re-declaration is an append, not a move"
            );

            // And a returning read, which is the hottest guarded site.
            store.upsert(&drawer("a harbour crane at dawn", 0)).unwrap();
            assert_eq!(
                store
                    .recent(None, 5, crate::Read::Returned(crate::ReadOp::Recent))
                    .unwrap()
                    .len(),
                1,
                "{level:?}"
            );
            assert!(
                store.verify().unwrap().ok(),
                "{level:?}: and nothing is wrong"
            );
        }
    }

    /// **The `rotate/` lever's own counterfactual** (ROADMAP O239 measured
    /// it; O237 is the second answer to it). ONE forged `rotate/` row used
    /// to lift the boundary above every record and disable O230's comparison
    /// and O234's arm 1 at once. It is now dead twice: the boundary is an
    /// equality on THIS key's keycheck, so a foreign label moves nothing,
    /// and the forged row is an append to a labelled chain, so the guard
    /// refuses before the boundary is asked.
    ///
    /// The insert is made from a SECOND CONNECTION, which is both the
    /// realistic shape and the one the mechanism covers: an append does not
    /// violate the append-only invariant — that is what makes the invariant
    /// free of false alarms — so what sees it is the re-replay `PRAGMA
    /// data_version` triggers. A writer editing pages beneath SQLite could
    /// append without moving the cookie and would not be seen until the
    /// handle is re-opened; that residual is stated in this module's own
    /// documentation and in ROADMAP O237.
    #[test]
    fn a_forged_rotation_record_is_refused_by_the_guard_as_well() {
        let (dir, mut store) = fresh(SecurityLevel::Sealed);
        store.set_retention("notes", None, 30).unwrap();
        store.retention_policies().unwrap();
        let db = dir.path().join("vaults/r/vault.db");
        let other = Connection::open(&db).unwrap();
        other
            .execute(
                "INSERT INTO audit (record_id, tag, at) \
                 VALUES ('rotate/deadbeefdeadbeef', X'00', '2030-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        drop(other);
        assert_eq!(
            store
                .snapshot(|snap| store.rotation_boundary(snap, LabelUse::Report))
                .unwrap(),
            None,
            "ROADMAP O239: a foreign keycheck is not this handle's rotation"
        );
        let before = store.replays();
        let err = store.retention_policies().unwrap_err();
        assert!(
            matches!(&err, StoreError::IntegrityFinding(m)
                     if m.contains("does not authenticate its own labels")),
            "{err}"
        );
        // ROADMAP O247: and it is the RE-REPLAY that refused, named by count
        // as well as by wording — the arms below tell the two mechanisms
        // apart, and this one must say which it is too.
        assert_eq!(
            store.replays(),
            before + 1,
            "the foreign commit re-replayed"
        );
    }

    // ── ROADMAP O247 and O252: a COPIED `rotate/` label, and the class it is
    //    one spelling of ─────────────────────────────────────────────────

    /// The `rotate/` label an OFFLINE READER copies, read from the clear
    /// bytes it would read — `meta.keycheck`, which every writable open seeds
    /// (`reconcile_rotation`) — and never from the handle's own vault, which
    /// would prove nothing about what is on disk.
    fn rotation_label_on_disk(conn: &Connection) -> String {
        let keycheck: String = conn
            .query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
                r.get(0)
            })
            .unwrap();
        Namespace::Rotate.record(&keycheck[..KEYCHECK_LABEL_LEN])
    }

    /// A retention declaration's row, as O230's replay writes it back.
    type PolicyRow = (u32, Vec<u8>, String);

    fn policy_row(conn: &Connection, wing: &str) -> PolicyRow {
        conn.query_row(
            "SELECT max_age_days, tag, assigned_at FROM retention_policy WHERE wing = ?1",
            params![wing],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
    }

    fn write_policy_back(conn: &Connection, wing: &str, row: &PolicyRow) {
        let n = conn
            .execute(
                "UPDATE retention_policy SET max_age_days = ?1, tag = ?2, assigned_at = ?3 \
                 WHERE wing = ?4",
                params![row.0, row.1, row.2, wing],
            )
            .unwrap();
        assert_eq!(n, 1, "premise: the older policy row is written back");
    }

    /// `scratch` declared at 30 days and then at 365; returns the 30-day row
    /// an offline writer would write back.
    fn a_replayable_policy(store: &mut VaultStore) -> PolicyRow {
        store.set_retention("scratch", None, 30).unwrap();
        let old = policy_row(&store.conn, "scratch");
        store.set_retention("scratch", None, 365).unwrap();
        old
    }

    fn records_under(conn: &Connection, label: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE record_id = ?1",
            params![label],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// **ROADMAP O247's gate: a `rotate/` row carrying THIS handle's own
    /// keycheck.** O239's equality rejects a FOREIGN label and cannot reject
    /// a COPY of the real one, because the label sits in clear — in
    /// `audit.record_id` once the vault has rotated, and in `meta.keycheck` on
    /// every vault a writable open has touched. So the arm asserts first that
    /// the copy LIFTS the boundary, then which mechanism refuses: the full
    /// re-replay `PRAGMA data_version` triggers when another connection
    /// commits, named by its wording and by the replay count. On a rotated
    /// vault the copy is the REAL rotation record, label, tag and time,
    /// because a copy carries a genuine tag and only its position gives it
    /// away — which only a replay authenticates.
    ///
    /// `verify` fails on `chain_ok` ALONE here: its policy leg is blind above
    /// the lifted boundary. That is pinned as a cost, because a verdict that
    /// survives on one leg is the reason nobody notices the other going dark.
    #[test]
    fn a_copied_rotation_record_is_refused_by_the_replay_and_not_by_its_label() {
        for rotated in [false, true] {
            let (dir, mut store) = fresh(SecurityLevel::Sealed);
            if rotated {
                rotate(&dir, &mut store).unwrap();
            }
            let old = a_replayable_policy(&mut store);
            store.retention_policies().unwrap();
            let label = rotation_label_on_disk(&store.conn);
            assert_eq!(
                label,
                rotation_label(&store.vault),
                "premise: the label on disk IS this handle's own"
            );
            assert_eq!(
                records_under(&store.conn, &label),
                i64::from(rotated),
                "premise: a real rotation record exists exactly when the vault rotated"
            );
            let db = dir.path().join("vaults/r/vault.db");
            let other = Connection::open(&db).unwrap();
            if rotated {
                other
                    .execute(
                        "INSERT INTO audit (record_id, tag, at) \
                         SELECT record_id, tag, at FROM audit WHERE record_id = ?1",
                        params![label],
                    )
                    .unwrap();
            } else {
                other
                    .execute(
                        "INSERT INTO audit (record_id, tag, at) \
                         VALUES (?1, X'00', '2030-01-01T00:00:00Z')",
                        params![label],
                    )
                    .unwrap();
            }
            let planted = other.last_insert_rowid();
            write_policy_back(&other, "scratch", &old);
            drop(other);
            // PREMISES. Both declarations are still on the chain, so nothing
            // below is attributable to a record the plant removed; and the
            // copy IS the boundary now — without this the arm passes on a
            // mis-derived label too, since the replay refuses a foreign one
            // just the same.
            assert_eq!(records_under(&store.conn, "retention/scratch"), 2);
            assert_eq!(
                store
                    .snapshot(|snap| store.rotation_boundary(snap, LabelUse::Report))
                    .unwrap(),
                Some(planted),
                "rotated={rotated}: the equality accepts a copy"
            );
            let before = store.replays();
            let err = store.retention_policies().unwrap_err();
            assert!(
                matches!(&err, StoreError::IntegrityFinding(m)
                         if m.contains("do not replay to the committed head")
                            && !m.contains("append-only")
                            && !m.contains("not the newest declaration")),
                "rotated={rotated}: the refusal is the replay's: {err}"
            );
            assert_eq!(
                store.replays(),
                before + 1,
                "rotated={rotated}: and a replay ran to make it"
            );
            let report = store.verify().unwrap();
            assert!(!report.chain_ok && !report.ok(), "rotated={rotated}");
            assert!(
                report.policy_drift.is_empty(),
                "Verdict::Cost (ROADMAP O252) — rotated={rotated}: the policy leg is \
                 blind above the lifted boundary, so `verify` fails on `chain_ok` \
                 alone: {:?}",
                report.policy_drift
            );
        }
    }

    /// **The control: under an UNMOVED cookie a FOREIGN `rotate/` label is
    /// refused by O239's equality and by nothing else.** The plant is made on
    /// the handle's own connection, which is how this module stands in for a
    /// writer beneath SQLite (ROADMAP O237 `#### BUILT`): `PRAGMA
    /// data_version` does not move, so no replay re-runs, and the append-only
    /// invariant sees a legitimate append. It is the one arm in which the
    /// equality IS the mechanism, which is what makes "which mechanism
    /// refuses" mean something in the arm above.
    #[test]
    fn under_an_unmoved_cookie_the_equality_refuses_a_foreign_rotation_record() {
        for rotated in [false, true] {
            let (dir, mut store) = fresh(SecurityLevel::Sealed);
            if rotated {
                rotate(&dir, &mut store).unwrap();
            }
            let old = a_replayable_policy(&mut store);
            store.retention_policies().unwrap();
            let (replays, cookie) = (store.replays(), data_version(&store.conn).unwrap());
            let boundary = store
                .snapshot(|snap| store.rotation_boundary(snap, LabelUse::Report))
                .unwrap();
            store
                .conn
                .execute(
                    "INSERT INTO audit (record_id, tag, at) \
                     VALUES ('rotate/deadbeefdeadbeef', X'00', '2030-01-01T00:00:00Z')",
                    [],
                )
                .unwrap();
            write_policy_back(&store.conn, "scratch", &old);
            assert_eq!(
                data_version(&store.conn).unwrap(),
                cookie,
                "premise: the cookie did not move"
            );
            assert_eq!(
                store
                    .snapshot(|snap| store.rotation_boundary(snap, LabelUse::Report))
                    .unwrap(),
                boundary,
                "rotated={rotated}: a foreign label moves nothing"
            );
            let err = store.retention_policies().unwrap_err();
            assert!(
                matches!(&err, StoreError::IntegrityFinding(m)
                         if m.contains("not the newest declaration")),
                "rotated={rotated}: the policy comparison refuses: {err}"
            );
            assert_eq!(
                store.replays(),
                replays,
                "rotated={rotated}: no replay re-ran, so the equality refused it"
            );
        }
    }

    type DrawerRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

    fn drawer_row(conn: &Connection, id: &str) -> DrawerRow {
        conn.query_row(
            "SELECT meta_json, content, embedding, tag FROM drawers WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
    }

    fn write_drawer_back(conn: &Connection, id: &str, row: &DrawerRow) {
        let n = conn
            .execute(
                "UPDATE drawers SET meta_json = ?1, content = ?2, embedding = ?3, tag = ?4 \
                 WHERE id = ?5",
                params![row.0, row.1, row.2, row.3, id],
            )
            .unwrap();
        assert_eq!(n, 1, "premise: the older drawer row is written back");
    }

    /// **ROADMAP O252, pinned rather than absorbed: under an UNMOVED cookie a
    /// writer WITHOUT the key makes a replayed policy GOVERN, the sweep
    /// DESTROY with `ok: true`, and a replayed drawer SERVE — through any
    /// edit that re-points a label's newest record, most of which move no
    /// height and none of which needs a `rotate/` row.** O247 is one spelling
    /// of this; the others cost the same. Every arm is made on the handle's
    /// own connection (the cookie does not move, asserted), asserts the
    /// replayed VALUE rather than `is_ok()`, and ends with `verify` still
    /// seeing it — because a replay does, and none ran here.
    ///
    /// `Verdict::Cost`: a fix for O252 fails this test, and the fix must
    /// invert the arm it closes and say so, never delete it.
    #[test]
    fn o252_under_an_unmoved_cookie_an_edited_label_decides_a_policy_and_a_drawer() {
        let filed = (time::OffsetDateTime::now_utc() - time::Duration::days(100))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        for how in [
            "a copied rotate/ label",
            "an older record copied forward",
            "a later record relabelled in",
            "the newest record of an unpinned label deleted",
        ] {
            let (_dir, mut store) = fresh(SecurityLevel::Sealed);
            store.set_wing_trust("secret", "quarantined").unwrap();
            let old = a_replayable_policy(&mut store);
            let mut aged = Drawer::new(
                "scratch",
                "r",
                "a note filed a hundred days ago".into(),
                Some("t.md".into()),
                0,
                "t",
            );
            aged.meta.filed_at = filed.clone();
            store.upsert(&aged).unwrap();
            let later = drawer("an ordinary later write", 0);
            store.upsert(&later).unwrap();
            // The first replay — pinning `retention/scratch`, except in the
            // arm whose point is that it was never pinned.
            let unpinned = how.starts_with("the newest");
            if unpinned {
                store.wing_trusts().unwrap();
            } else {
                let preview = store.retention_sweep(true).unwrap();
                assert_eq!(
                    preview
                        .policies
                        .iter()
                        .map(|p| p.expired.len())
                        .sum::<usize>(),
                    0,
                    "premise: under the declared 365 days nothing expires"
                );
            }
            let (replays, cookie) = (store.replays(), data_version(&store.conn).unwrap());
            match how {
                "a copied rotate/ label" => {
                    let label = rotation_label_on_disk(&store.conn);
                    store
                        .conn
                        .execute(
                            "INSERT INTO audit (record_id, tag, at) \
                             VALUES (?1, X'00', '2030-01-01T00:00:00Z')",
                            params![label],
                        )
                        .unwrap();
                }
                "an older record copied forward" => {
                    store
                        .conn
                        .execute(
                            "INSERT INTO audit (record_id, tag, at) \
                             SELECT record_id, tag, at FROM audit \
                             WHERE record_id = 'retention/scratch' ORDER BY seq LIMIT 1",
                            [],
                        )
                        .unwrap();
                }
                "a later record relabelled in" => {
                    store
                        .conn
                        .execute(
                            "UPDATE audit SET record_id = 'retention/scratch', tag = ?1, at = ?2 \
                             WHERE seq = (SELECT MAX(seq) FROM audit WHERE record_id = ?3)",
                            params![old.1, old.2, later.id],
                        )
                        .unwrap();
                }
                _ => {
                    store
                        .conn
                        .execute(
                            "DELETE FROM audit WHERE seq = \
                             (SELECT MAX(seq) FROM audit WHERE record_id = 'retention/scratch')",
                            [],
                        )
                        .unwrap();
                }
            }
            write_policy_back(&store.conn, "scratch", &old);
            assert_eq!(
                data_version(&store.conn).unwrap(),
                cookie,
                "premise ({how}): the cookie did not move"
            );
            let governs: Vec<u32> = store
                .retention_policies()
                .unwrap()
                .iter()
                .map(|p| p.max_age_days)
                .collect();
            assert_eq!(
                governs,
                vec![30],
                "Verdict::Cost (ROADMAP O252) — {how}: the replayed policy governs"
            );
            let sweep = store.retention_sweep(false).unwrap();
            assert_eq!(
                (sweep.destroyed, sweep.ok),
                (1, true),
                "Verdict::Cost (ROADMAP O252) — {how}: the sweep destroys a drawer the \
                 declared policy keeps, and reports ok"
            );
            assert!(store
                .get(
                    &aged.id,
                    crate::Read::Internal(crate::InternalRead::Verification)
                )
                .unwrap()
                .is_none());
            assert_eq!(
                store.replays(),
                replays,
                "premise ({how}): no replay ran, which is the whole window"
            );
            assert!(
                !store.verify().unwrap().chain_ok,
                "{how}: and a replay does see it"
            );
        }

        // The returning read. `refuse_replayed` finds a drawer's records in
        // its own SQL and remembers nothing per label, so even an edit the
        // append-only invariant catches on a policy label is unseen here.
        for how in [
            "an older record copied forward",
            "the newest record relabelled out",
            "the newest record deleted",
        ] {
            let (_dir, mut store) = fresh(SecurityLevel::Sealed);
            let first = drawer("the account number is 1111", 0);
            store.upsert(&first).unwrap();
            let replayed = drawer_row(&store.conn, &first.id);
            store
                .upsert(&drawer("the account number is 2222 (corrected)", 0))
                .unwrap();
            assert!(store
                .get(&first.id, crate::Read::Returned(crate::ReadOp::Get))
                .unwrap()
                .expect("premise: the corrected drawer reads")
                .content
                .contains("2222"));
            let (replays, cookie) = (store.replays(), data_version(&store.conn).unwrap());
            let sql = match how {
                "an older record copied forward" => {
                    "INSERT INTO audit (record_id, tag, at) SELECT record_id, tag, at \
                     FROM audit WHERE record_id = ?1 ORDER BY seq LIMIT 1"
                }
                "the newest record relabelled out" => {
                    "UPDATE audit SET record_id = 'read/x' WHERE seq = \
                     (SELECT MAX(seq) FROM audit WHERE record_id = ?1)"
                }
                _ => {
                    "DELETE FROM audit WHERE seq = \
                     (SELECT MAX(seq) FROM audit WHERE record_id = ?1)"
                }
            };
            store.conn.execute(sql, params![first.id]).unwrap();
            write_drawer_back(&store.conn, &first.id, &replayed);
            assert_eq!(
                data_version(&store.conn).unwrap(),
                cookie,
                "premise ({how}): the cookie did not move"
            );
            let served = store
                .get(&first.id, crate::Read::Returned(crate::ReadOp::Get))
                .unwrap()
                .expect("the drawer reads");
            assert!(
                served.content.contains("1111"),
                "Verdict::Cost (ROADMAP O252) — {how}: a returning read serves the \
                 replayed drawer: {:?}",
                served.content
            );
            assert_eq!(store.replays(), replays, "premise ({how}): no replay ran");
            assert!(
                !store.verify().unwrap().chain_ok,
                "{how}: and a replay does see it"
            );
        }
    }

    /// **The guard is on the SCANS, so `verify` still reports.** The two
    /// legs that read policy evidence pass `Report`, and they must go on
    /// answering over a chain the guard refuses — which is the whole reason
    /// the witness is required rather than inferred.
    #[test]
    fn verify_reports_over_a_chain_the_guard_refuses() {
        let (_dir, mut store) = fresh(SecurityLevel::Sealed);
        store.set_wing_trust("secret", "quarantined").unwrap();
        store.wing_trusts().unwrap();
        lift_the_floor(&store.conn, "secret");
        assert!(store.wing_trusts().is_err(), "premise: the reader refuses");
        let report = store.verify().unwrap();
        assert!(!report.ok() && !report.chain_ok, "{report:?}");
    }

    /// **Every production call of the three label readers is inside this
    /// module or named here with its reason** — derived from the CODE, in
    /// both directions, because an inventory compared to another inventory
    /// is a closed system that can be consistent and jointly wrong (O80).
    #[test]
    fn every_label_reader_is_reached_through_the_guard() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        // (file, enclosing fn, why it may call the free reader directly).
        const ALLOWED: &[(&str, &str, &str)] = &[(
            "replay.rs",
            "newest_write_record",
            "O234's verify leg: it gathers evidence to REPORT, so it takes no \
             append-only observation — one made while the trail is already \
             suspect must not become the baseline a later decision is \
             compared against",
        )];
        let mut found: Vec<(String, String)> = Vec::new();
        for entry in std::fs::read_dir(&src).expect("the crate's own src is readable") {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") || name == "chain.rs" {
                continue;
            }
            for needle in [
                concat!("chain::", "newest_record("),
                concat!("chain::", "chain_keys("),
                concat!("chain::", "rotation_boundary("),
            ] {
                for f in production_sites(&name, needle) {
                    found.push((name.clone(), f));
                }
            }
        }
        found.sort();
        found.dedup();
        let expected: Vec<(String, String)> = ALLOWED
            .iter()
            .map(|(f, fun, _)| (f.to_string(), fun.to_string()))
            .collect();
        assert_eq!(
            found, expected,
            "a production call of a chain label reader that does not go through \
             `VaultStore::newest_record`/`chain_keys`/`rotation_boundary` is a \
             decision made with no guard in front of it"
        );
        // PREMISE, against ground truth rather than against itself: the
        // readers exist here and the scanner finds a needle it is pointed at.
        let here = std::fs::read_to_string(src.join("chain.rs")).unwrap();
        for f in [
            "pub(crate) fn newest_record(",
            "pub(crate) fn chain_keys(",
            "pub(crate) fn rotation_boundary(",
        ] {
            assert!(here.contains(f), "premise: chain.rs still defines {f:?}");
        }
        assert!(
            !production_sites("replay.rs", concat!("chain::", "newest_record(")).is_empty(),
            "premise: the scanner finds the one call the list names"
        );
    }

    /// **`audit` is append-only in production, which is the prefix
    /// invariant's premise** — so the statements that touch it are counted
    /// against the source, not remembered. A `DELETE` would make a record
    /// vanish legitimately and turn the invariant into a false alarm
    /// generator; a second `INSERT` or `UPDATE` would be a writer nobody
    /// ruled on (O80's lesson about a namespace nobody was forced to
    /// classify).
    #[test]
    fn the_audit_table_is_append_only_in_production() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut deletes: Vec<(String, String)> = Vec::new();
        let mut inserts: Vec<(String, String)> = Vec::new();
        let mut updates: Vec<(String, String)> = Vec::new();
        for entry in std::fs::read_dir(&src).expect("readable") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            for (needle, into) in [
                (concat!("DELETE FROM ", "audit"), &mut deletes),
                (concat!("INSERT INTO ", "audit"), &mut inserts),
                (concat!("UPDATE ", "audit SET"), &mut updates),
            ] {
                for f in production_sites(&name, needle) {
                    into.push((name.clone(), f));
                }
            }
        }
        for v in [&mut deletes, &mut inserts, &mut updates] {
            v.sort();
            v.dedup();
        }
        // PREMISE, both ways: the files skipped as test code are the ones
        // `lib.rs` compiles only under test, and never a production file.
        let skipped = test_only_files();
        assert!(
            skipped.contains("anchor_tests.rs"),
            "premise: a test-only file is recognised: {skipped:?}"
        );
        for f in ["chain.rs", "kg.rs", "lib.rs", "rotate.rs", "manage.rs"] {
            assert!(
                !skipped.contains(f),
                "premise: {f} is production and is scanned: {skipped:?}"
            );
        }
        assert!(
            deletes.is_empty(),
            "a production `DELETE FROM audit` breaks the append-only premise the \
             O237 prefix invariant rests on, and would make an ordinary operation \
             indistinguishable from the exploit: {deletes:?}"
        );
        assert_eq!(
            inserts,
            [("chain.rs".to_string(), "insert_record".to_string())],
            "the chain's one row writer"
        );
        assert_eq!(
            updates,
            [("kg.rs".to_string(), "blind_existing_kg_rows".to_string())],
            "the one label move in the tree: A10's blinding migration, which runs \
             inside a writable open before any guarded read and owes a recorded \
             re-chain if it is ever repeated (ROADMAP O233's revision)"
        );
    }

    /// Every PRODUCTION line of one of this crate's files that holds
    /// `needle`, named by the function enclosing it. The same reader
    /// `replay.rs`'s own source gate uses, plus the one thing that file did
    /// not need: an item annotated `#[cfg(test)]` OUTSIDE `mod tests` is
    /// test code too, and `unswitch_chain_for_test` is exactly that — a
    /// `DELETE FROM audit` that a split on `mod tests` alone would have
    /// reported as production. **And a whole FILE declared `#[cfg(test)]`
    /// is test code** (ROADMAP O276), through the same `test_only_files`
    /// `production_lines` has skipped since O253: this reader did not ask
    /// it, and counted `anchor_tests.rs` — whose functions carry no
    /// annotation of their own — as production the first time one of them
    /// held an `UPDATE audit`, a test simulating an offline edit, which is
    /// what such a file is for. Two readers in one module disagreed about
    /// what production is.
    fn production_sites(file: &str, needle: &str) -> Vec<String> {
        if test_only_files().contains(file) {
            return Vec::new();
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(file);
        let text = std::fs::read_to_string(&path).expect("the crate's own source is readable");
        let prod = text
            .split(concat!("#[cfg(test)]\n", "mod tests"))
            .next()
            .unwrap_or_default();
        let mut enclosing = String::new();
        let mut cfg_test_item = false;
        let mut previous = String::new();
        let mut out = Vec::new();
        for line in prod.lines() {
            let t = line.trim_start();
            // A free function at column 0 or a method at four spaces, never
            // a `fn` NESTED in a body. `replay.rs`'s reader takes four
            // spaces alone, because every site it tracks is a method; this
            // module's writers are free functions, and taking four alone
            // attributed `insert_record`'s statement to `CommitmentDigest::
            // finish` — the last method above it. The gate found that
            // itself, on its first run.
            let indent = line.len() - t.len();
            if indent == 0 || indent == 4 {
                if let Some(rest) = t
                    .strip_prefix("pub fn ")
                    .or_else(|| t.strip_prefix("pub(crate) fn "))
                    .or_else(|| t.strip_prefix("fn "))
                {
                    enclosing = rest
                        .split(['(', '<'])
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    cfg_test_item = previous.trim() == "#[cfg(test)]";
                }
            }
            if t.contains(needle) && !t.starts_with("//") && !cfg_test_item {
                out.push(enclosing.clone());
            }
            if !t.is_empty() {
                previous = t.to_string();
            }
        }
        out
    }
}
