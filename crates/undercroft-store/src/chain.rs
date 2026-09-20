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
    match head_state(conn)? {
        HeadState::Unseeded => Ok(None),
        HeadState::Seeded(h) => Ok(Some(h)),
        HeadState::Inconsistent { finding, .. } => Err(StoreError::IntegrityFinding(finding)),
    }
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
pub(crate) fn replay(
    conn: &Connection,
    stepper: &Vault,
    anchor: Option<&str>,
) -> Result<Replay, StoreError> {
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

/// What [`switch`] did.
pub(crate) enum SwitchOutcome {
    /// The commitment was appended; the caller commits and anchors.
    Switched {
        /// The new live head, which the manifest must now anchor.
        head: String,
        /// The committed record count, the commitment included.
        writes: u64,
    },
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
    tx: &Connection,
    vault: &Vault,
    anchor: &str,
    at: &str,
) -> Result<SwitchOutcome, StoreError> {
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
    let replayed = replay(tx, vault, Some(anchor))?;
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
    Ok(SwitchOutcome::Switched { head: next, writes })
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

/// The newest rotation's place in the chain — the boundary a tag comparison
/// stops at. A half-open range on `record_id` rather than a `LIKE`: SQLite's
/// `LIKE` is case-insensitive and cannot use the BINARY index, so it would
/// scan the whole trail on every floored search and could disagree with an
/// equality about `ROTATE/x`.
pub(crate) fn rotation_boundary(conn: &Connection) -> Result<Option<i64>, StoreError> {
    let (lo, hi) = prefix_range(Namespace::Rotate);
    Ok(conn.query_row(
        "SELECT MAX(seq) FROM audit WHERE record_id >= ?1 AND record_id < ?2",
        [lo.as_str(), hi.as_str()],
        |r| r.get(0),
    )?)
}

/// A namespace's labels as a half-open range: `prefix` up to the same string
/// with its closing `/` replaced by the next byte, `0`.
pub(crate) fn prefix_range(ns: Namespace) -> (String, String) {
    let lo = ns.prefix().to_string();
    let hi = format!("{}0", &lo[..lo.len() - 1]);
    (lo, hi)
}

/// Every distinct label a namespace's records carry, by the same range.
pub(crate) fn chain_keys(conn: &Connection, ns: Namespace) -> Result<Vec<String>, StoreError> {
    let (lo, hi) = prefix_range(ns);
    let mut stmt = conn.prepare(
        "SELECT DISTINCT record_id FROM audit \
         WHERE record_id >= ?1 AND record_id < ?2 ORDER BY record_id",
    )?;
    let keys = stmt
        .query_map([lo.as_str(), hi.as_str()], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(keys)
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

    /// Every `.rs` file of this crate, cut at its test module, with comment
    /// lines dropped: prose naming a statement is not the statement.
    fn production_lines() -> Vec<(String, usize, String)> {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&src).expect("the crate's own sources are readable") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
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
}
