//! The external witness (ROADMAP O245): a small document a vault EMITS about
//! its audit chain, kept somewhere an attacker with full disk control cannot
//! write, and CHECKED against the vault later.
//!
//! **What it closes, stated exactly.** The threat model's A2 residual: an
//! attacker who restores a genuine older `(vault.db, vault.json)` pair — or
//! the manifest alone first, then the database — rewinds the vault to a
//! state that was genuine at the time, and the chain cannot tell that from
//! the machine having been off. A witness taken before the rollback names
//! rows the rewound vault no longer holds, so the check reports it. It
//! closes the REWIND direction below the witnessed height and nothing else:
//! anything appended above the witness, forged or not, is "writes since the
//! witness", and a rollback to a point at or above it is inside the cadence.
//!
//! **What it binds, and why not the head.** Both chain steps are keyed
//! (`Vault::chain_step_hex`), a rotation re-derives those keys and re-steps
//! every head (`rotate.rs`), and A2 holds the key and can rotate — so a
//! witness carrying only the chain head reports "superseded" on exactly the
//! rollback it exists to catch, and the vault's own routine operation
//! launders it. That is O13's shape one document over. The binding is
//! therefore the ROW COUNT plus an unkeyed, count-bound digest over the
//! rows' preserved `(record_id, tag, at)` bytes ([`crate::chain::prefix`]),
//! which a rotation leaves untouched. The head travels as CORROBORATION:
//! valid until the first rotation after the witness, and reported as such,
//! never as the verdict.
//!
//! **Own door, always read-only, typed verdict.** Not a tenth `verify` leg:
//! `verify` takes no argument, and a leg present only when a file is
//! supplied would make `ok()` conditional on input. The CLI opens read-only
//! whatever the flags, because a writable open heals the anchor, relabels
//! and re-switches BEFORE anything reads (O91: gate the path) — none of that
//! destroys what the check compares, but a writable emit over a lowered
//! anchor would consume O246's evidence in silence. The verdict is a typed
//! enum on the `AttestationVerdict` precedent; a document naming another
//! vault is an integrity finding, because a re-created vault is an erasure
//! and must not read as a caller's typo.
//!
//! **Not offered over MCP**, by the maintainer's ruling of 2026-09-23: an
//! agent's memory IS this vault, so it cannot hold an off-machine witness,
//! and a check offered to the party whose rollback it would detect is no
//! witness.

use serde::{Deserialize, Serialize};

use crate::chain;
use crate::{StoreError, VaultStore};

/// The document format this build emits and understands.
pub const WITNESS_VERSION: u32 = 1;

/// What a vault says about its audit chain at one moment, for a reader who
/// keeps it out of the attacker's reach and brings it back later.
///
/// **Binding**: `vault`, `rows` and `prefix_digest`. **Corroboration**:
/// `head`, `regime`, `writes`, `anchored_head`, `emitted_at`, `unhealed` —
/// read for context, never decisive. `sender`/`sig` carry an optional
/// Ed25519 signature by the export/attestation identity
/// (`undercroft bundle sign-keygen`), which buys the witness STORE's
/// integrity — a writer to the store cannot substitute a witness blessing a
/// rolled-back state — and only if that key is kept off the vault's disk,
/// where it defaults to living.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainWitness {
    /// [`WITNESS_VERSION`].
    pub version: u32,
    /// The vault id this witness describes.
    pub vault: String,
    /// How many audit rows the digest covers — the replay's ROW count,
    /// never `chain_meta.writes`, which a planted row does not move.
    pub rows: u64,
    /// Hex of the unkeyed, count-bound digest over the first `rows` rows'
    /// preserved bytes ([`crate::chain::prefix`]).
    pub prefix_digest: String,
    /// The live chain head at emit — corroboration, key-generation-bound.
    pub head: String,
    /// `"v1"` or `"v2"`, so a check can NAME an un-switch rather than report
    /// a bare digest mismatch.
    pub regime: String,
    /// `chain_meta.writes` at emit — advisory.
    pub writes: u64,
    /// The manifest anchor ON DISK at emit, MAC-verified. An anchor never
    /// legitimately moves backwards, so a later check reading a lower one
    /// has O246's observable off-machine as well.
    pub anchored_head: String,
    /// When the emitter said it emitted this — the emitter's claim.
    pub emitted_at: String,
    /// What the emitting open found and declined to repair, so a witness
    /// taken over a lagging anchor says so on its face.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unhealed: Vec<String>,
    /// The Ed25519 public key (hex) the signature is checked against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// The detached Ed25519 signature (hex) over [`Self::canonical`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl ChainWitness {
    /// The bytes a signature covers: every field but the signature pair,
    /// `\x1f`-joined, with `unhealed` as an appended extension only when
    /// non-empty — the `ForgetAttestation` shape, for the same reason: a
    /// document written without the extension must canonicalise identically.
    pub fn canonical(&self) -> Vec<u8> {
        let mut parts = vec![
            format!("undercroft-witness/{}", self.version),
            self.vault.clone(),
            self.rows.to_string(),
            self.prefix_digest.clone(),
            self.head.clone(),
            self.regime.clone(),
            self.writes.to_string(),
            self.anchored_head.clone(),
            self.emitted_at.clone(),
        ];
        if !self.unhealed.is_empty() {
            parts.push(format!("unhealed\u{1e}{}", self.unhealed.join("\u{1e}")));
        }
        parts.join("\u{1f}").into_bytes()
    }

    /// Sign in place with a bundle signing identity (the secret's hex, as
    /// `undercroft bundle sign-keygen` writes it).
    pub fn sign(&mut self, signing_secret_hex: &str) -> Result<(), StoreError> {
        self.sender = Some(
            undercroft_vault::bundle::signer_of(signing_secret_hex)
                .map_err(|e| StoreError::Invalid(e.to_string()))?,
        );
        self.sig = Some(
            undercroft_vault::bundle::sign_detached(signing_secret_hex, &self.canonical())
                .map_err(|e| StoreError::Invalid(e.to_string()))?,
        );
        Ok(())
    }

    /// Whether this document carries a checkable signature: BOTH fields, on
    /// the attestation precedent — a signature with nobody to check it
    /// against is refused by the check, never counted as signed.
    pub fn signed(&self) -> bool {
        self.sender.is_some() && self.sig.is_some()
    }
}

/// What a check found. `#[must_use]` so a caller cannot take the `Ok` for
/// a clean verdict — half of this enum is the alarm.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessVerdict {
    /// The witnessed prefix is intact and the chain extends it (possibly by
    /// zero rows). The exit-0 verdict.
    Extends {
        /// Rows appended since the witness — every one of them "writes
        /// since the witness", forged or not; the witness cannot tell.
        rows_since: u64,
        /// Whether the witnessed head is still one of the chain's heads.
        /// `false` after a key rotation re-stepped it, which is corroboration
        /// lost and NOT a rollback — the binding above still holds.
        head_corroborated: bool,
        /// Key rotations the chain records after the witnessed row —
        /// corroboration for `head_corroborated == false`, never decisive.
        rotations_since: i64,
    },
    /// The chain no longer contains the witnessed prefix: it is shorter, or
    /// the rows below the witnessed height are not the ones witnessed. The
    /// integrity verdict — exit 2 on the CLI, 409 `class: "integrity"` on
    /// `/v1`.
    RolledBack {
        /// The height the witness named.
        rows_witnessed: u64,
        /// The height the chain has now.
        rows_now: u64,
        /// `true` when the chain is at least as tall as the witness and the
        /// prefix digest differs — a fork or an in-place rewrite below the
        /// witnessed height (O240's un-switch reads this way for a
        /// post-switch witness); `false` for a plain truncation.
        rewritten: bool,
    },
}

impl VaultStore {
    /// Emit a witness of this vault's audit chain as it stands.
    ///
    /// Refuses two things rather than witnessing them: a chain with no rows
    /// (a genesis witness is vacuous — every chain extends it), and a sealed
    /// vault whose A10 blinding walk is still pending, because that walk
    /// relabels audit rows on the next writable open and the digest would
    /// not survive it. Runs on either posture; the CLI opens read-only so
    /// the anchored pair is read as found.
    ///
    /// **One state per document** (ROADMAP O253): the manifest anchor first,
    /// then the rows, the digest, the head and the height in ONE snapshot. Read
    /// statement by statement, a commit landing during the walk produced a
    /// document whose `rows` named one state and whose `head` named the next
    /// — measured, 87 of 123 documents emitted beside a writer — which an
    /// external verifier replaying the witnessed prefix cannot reproduce.
    pub fn witness_emit(&self) -> Result<ChainWitness, StoreError> {
        let anchored_head = self.vault.anchored_head()?;
        let (prefix, head, writes) = self.snapshot(|snap| {
            let prefix = chain::prefix(snap, None)?;
            if prefix.rows == 0 {
                return Err(StoreError::Invalid(
                    "nothing to witness: the audit chain has no records yet, and a witness \
                     of the genesis head is one every chain extends"
                        .into(),
                ));
            }
            if !self.kg_blind_complete()? {
                return Err(StoreError::Invalid(
                    "refusing to witness: the knowledge-graph blinding migration (ROADMAP \
                     A10) has not completed on this vault and RELABELS audit rows when it \
                     does, so a digest taken now would not survive the next writable open — \
                     open the vault writable once, then witness"
                        .into(),
                ));
            }
            let head = chain::require_head(snap.conn())?;
            let writes = chain::writes(snap.conn())?;
            Ok((prefix, head, writes))
        })?;
        let regime = match head.regime {
            chain::Regime::V1 => "v1",
            chain::Regime::V2 { .. } => "v2",
        };
        Ok(ChainWitness {
            version: WITNESS_VERSION,
            vault: self.vault.id().to_string(),
            rows: prefix.rows,
            prefix_digest: hex::encode(prefix.digest),
            head: head.head,
            regime: regime.to_string(),
            writes,
            anchored_head,
            emitted_at: crate::manage::now_rfc3339(),
            unhealed: self.unhealed.clone(),
            sender: None,
            sig: None,
        })
    }

    /// Check a witness against this vault's audit chain.
    ///
    /// Two walks of `audit`: the unkeyed prefix scan that DECIDES, and the
    /// keyed replay that corroborates the head — both in ONE snapshot
    /// (ROADMAP O253), so the corroboration describes the rows the decision
    /// read. A document naming another
    /// vault, or carrying a signature that does not verify, is an error in
    /// the integrity family rather than a verdict — the caller's wrong file
    /// and a re-created vault are indistinguishable here, and the second is
    /// an erasure.
    pub fn witness_check(&self, w: &ChainWitness) -> Result<WitnessVerdict, StoreError> {
        if w.version > WITNESS_VERSION {
            return Err(StoreError::Invalid(format!(
                "witness version {} is newer than this build understands ({WITNESS_VERSION})",
                w.version
            )));
        }
        if w.vault != self.vault.id() {
            return Err(StoreError::IntegrityFinding(format!(
                "the witness names vault {:?} and this is {:?}: either the wrong file, or a \
                 vault destroyed and re-created under the same name — which is an erasure",
                w.vault,
                self.vault.id()
            )));
        }
        match (w.sender.as_deref(), w.sig.as_deref()) {
            (Some(sender), Some(sig)) => {
                undercroft_vault::bundle::verify_detached(sender, &w.canonical(), sig)
                    .map_err(|e| StoreError::Attestation(format!("witness signature: {e}")))?;
            }
            (None, None) => {}
            _ => {
                return Err(StoreError::Attestation(
                    "the witness carries a sender without a signature, or a signature \
                     without a sender: attributable to nobody, so refused rather than \
                     treated as unsigned"
                        .into(),
                ))
            }
        }
        if w.rows == 0 {
            return Err(StoreError::Invalid(
                "the witness names zero rows; a genesis witness is vacuous".into(),
            ));
        }
        self.snapshot(|snap| {
            let prefix = chain::prefix(snap, Some(w.rows))?;
            let Some(at_digest) = prefix.at_digest else {
                return Ok(WitnessVerdict::RolledBack {
                    rows_witnessed: w.rows,
                    rows_now: prefix.rows,
                    rewritten: false,
                });
            };
            if hex::encode(at_digest) != w.prefix_digest {
                return Ok(WitnessVerdict::RolledBack {
                    rows_witnessed: w.rows,
                    rows_now: prefix.rows,
                    rewritten: true,
                });
            }
            let replayed = chain::replay(snap, &self.vault, Some(&w.head))?;
            let rotations_since = match prefix.at_seq {
                Some(seq) => chain::rotations_since(snap.conn(), seq)?,
                None => 0,
            };
            Ok(WitnessVerdict::Extends {
                rows_since: prefix.rows - w.rows,
                head_corroborated: replayed.anchor_seen,
                rotations_since,
            })
        })
    }

    /// The `seq` of the newest audit row, for tests that plant rows.
    #[cfg(test)]
    pub(crate) fn newest_audit_seq(&self) -> Option<i64> {
        use rusqlite::OptionalExtension;
        self.conn
            .query_row("SELECT MAX(seq) FROM audit", [], |r| {
                r.get::<_, Option<i64>>(0)
            })
            .optional()
            .ok()
            .flatten()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use undercroft_core::Drawer;
    use undercroft_vault::{SecurityLevel, VaultManager};

    fn drawer(content: &str, idx: u32) -> Drawer {
        Drawer::new("w", "r", content.into(), Some("t.md".into()), idx, "t")
    }

    fn fresh(level: SecurityLevel) -> (TempDir, VaultStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let store = VaultStore::open(mgr.create("test", level).unwrap()).unwrap();
        (dir, store)
    }

    fn reopen(dir: &TempDir) -> VaultStore {
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        VaultStore::open(mgr.unlock("test").unwrap()).unwrap()
    }

    fn vault_dir(dir: &TempDir) -> std::path::PathBuf {
        dir.path().join("vaults/test")
    }

    fn rotate(dir: &TempDir, store: &mut VaultStore) {
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        store
            .rotate_keys(mgr.rotation_candidate("test").unwrap())
            .unwrap();
    }

    /// **The entry's gate, verbatim.** A2's rollback: the genuine earlier
    /// `(vault.db, vault.json)` pair restored together. PREMISE arms are the
    /// entry's counterfactual — `verify` is green and the open reports the
    /// anchor `Current`, so nothing in the vault can see it — and then the
    /// witness taken before the rollback reports `RolledBack`, while the
    /// witness taken AT the restored state reports `Extends { 0 }`.
    #[test]
    fn a_vault_rolled_back_to_a_genuine_earlier_state_is_reported_against_a_witness() {
        let (dir, mut s) = fresh(SecurityLevel::HmacOnly);
        s.upsert(&drawer("first", 0)).unwrap();
        s.upsert(&drawer("second", 1)).unwrap();
        let w2 = s.witness_emit().unwrap();
        // The genuine earlier pair is copied with the store CLOSED: a copy
        // taken under an open handle lacks whatever the WAL still holds,
        // which is a torn snapshot and not the state A2 restores.
        drop(s);
        let vd = vault_dir(&dir);
        let db = std::fs::read(vd.join("vault.db")).unwrap();
        let manifest = std::fs::read(vd.join("vault.json")).unwrap();
        let mut s = reopen(&dir);
        s.upsert(&drawer("third", 2)).unwrap();
        let w3 = s.witness_emit().unwrap();
        assert_eq!(w3.rows, w2.rows + 1);
        assert_ne!(w3.prefix_digest, w2.prefix_digest, "count-bound");
        drop(s);

        // The rollback: both files restored, the pair consistent. A WAL left
        // behind would carry the third write, so it goes too.
        std::fs::write(vd.join("vault.db"), &db).unwrap();
        std::fs::write(vd.join("vault.json"), &manifest).unwrap();
        let _ = std::fs::remove_file(vd.join("vault.db-wal"));
        let _ = std::fs::remove_file(vd.join("vault.db-shm"));

        let s = reopen(&dir);
        // PREMISE: the vault cannot see it.
        assert_eq!(s.anchor_at_open(), crate::AnchorState::Current);
        assert!(s.verify().unwrap().ok(), "verify is green by construction");
        assert_eq!(s.count().unwrap(), 2, "premise: the third drawer is gone");
        // GATE: the pre-rollback witness sees it.
        assert_eq!(
            s.witness_check(&w3).unwrap(),
            WitnessVerdict::RolledBack {
                rows_witnessed: w3.rows,
                rows_now: w2.rows,
                rewritten: false,
            }
        );
        // And the witness of the restored state itself is extended by nothing.
        assert_eq!(
            s.witness_check(&w2).unwrap(),
            WitnessVerdict::Extends {
                rows_since: 0,
                head_corroborated: true,
                rotations_since: 0,
            }
        );
    }

    /// A legitimate later state extends the witness, and a KEY-HOLDER's
    /// append after it is indistinguishable from one — pinned as a COST
    /// (ROADMAP O245's ruling, item 3), so nobody re-claims that a witness
    /// closes the append direction.
    #[test]
    fn a_later_state_extends_the_witness_and_a_forged_append_is_writes_since_it() {
        let (_dir, mut s) = fresh(SecurityLevel::Sealed);
        s.upsert(&drawer("first", 0)).unwrap();
        let w = s.witness_emit().unwrap();
        s.upsert(&drawer("second", 1)).unwrap();
        assert_eq!(
            s.witness_check(&w).unwrap(),
            WitnessVerdict::Extends {
                rows_since: 1,
                head_corroborated: true,
                rotations_since: 0,
            }
        );
        // The key-holder's forged row: appended with the real step, as an
        // attacker holding `master.key` can. The witness reads it as one more
        // write since itself. Verdict::Cost.
        let head = chain::require_head(&s.conn).unwrap();
        let link = undercroft_vault::ChainLink {
            record_id: "forged/row",
            tag: b"\x00",
            at: "2026-01-01T00:00:00Z",
        };
        let step = head.regime.step_for(s.newest_audit_seq().unwrap() + 1);
        let next = s.vault.chain_step_hex(step, &head.head, link).unwrap();
        chain::insert_record(&s.conn, "forged/row", b"\x00", "2026-01-01T00:00:00Z").unwrap();
        chain::set_head(&s.conn, head.regime, &next).unwrap();
        assert_eq!(
            s.witness_check(&w).unwrap(),
            WitnessVerdict::Extends {
                rows_since: 2,
                head_corroborated: true,
                rotations_since: 0,
            },
            "Verdict::Cost — a forged append above the witness is writes since it"
        );
    }

    /// **The O13 arm, and the reason the binding is a digest.** After a
    /// rotation the witnessed head is unreachable — corroboration lost — and
    /// the verdict is still `Extends`, NEVER `RolledBack`. A head-only design
    /// fails this test on exactly the routine operation A2 can force.
    #[test]
    fn a_rotation_loses_head_corroboration_and_never_reads_as_a_rollback() {
        let (dir, mut s) = fresh(SecurityLevel::Sealed);
        s.upsert(&drawer("first", 0)).unwrap();
        s.upsert(&drawer("second", 1)).unwrap();
        let w = s.witness_emit().unwrap();
        rotate(&dir, &mut s);
        // PREMISE: the head really did move.
        assert!(
            !s.snapshot(|snap| chain::replay(snap, &s.vault, Some(&w.head)))
                .unwrap()
                .anchor_seen,
            "premise: the rotation re-stepped the witnessed head"
        );
        assert_eq!(
            s.witness_check(&w).unwrap(),
            WitnessVerdict::Extends {
                rows_since: 1,
                head_corroborated: false,
                rotations_since: 1,
            }
        );
        // And a rollback AFTER the rotation is still caught by the digest:
        // truncate below the witness and the verdict flips.
        s.conn
            .execute("DELETE FROM audit WHERE seq > 1", [])
            .unwrap();
        assert!(matches!(
            s.witness_check(&w).unwrap(),
            WitnessVerdict::RolledBack {
                rows_witnessed,
                rows_now: 1,
                rewritten: false,
            } if rows_witnessed == w.rows
        ));
    }

    /// **O240's un-switch, caught by a POST-switch witness on both postures
    /// of the re-switch, and blind to a PRE-switch one** (pinned as a cost).
    #[test]
    fn the_unswitch_is_caught_by_a_post_switch_witness_and_not_a_pre_switch_one() {
        let (dir, mut s) = fresh(SecurityLevel::HmacOnly);
        s.upsert(&drawer("first", 0)).unwrap();
        s.upsert(&drawer("second", 1)).unwrap();
        let w_post = s.witness_emit().unwrap();
        assert_eq!(w_post.regime, "v2");
        // The attack: truncate to below the switch, drop the commitment,
        // restore the pre-switch manifest — `unswitch_chain_for_test` is
        // exactly that shape, and it re-anchors as the attacker would.
        s.unswitch_chain_for_test();
        assert_eq!(
            chain::regime(&s.conn).unwrap(),
            chain::Regime::V1,
            "premise: the chain reads as never switched"
        );
        assert!(matches!(
            s.witness_check(&w_post).unwrap(),
            WitnessVerdict::RolledBack {
                rewritten: false,
                ..
            }
        ));
        // A PRE-switch witness, taken on the un-switched chain.
        let w_pre = s.witness_emit().unwrap();
        assert_eq!(w_pre.regime, "v1");
        drop(s);
        // The next writable open re-switches and re-blesses the truncated
        // history (O240): the post-switch witness still sees it — the new
        // commitment is a different row in the witnessed position.
        let s = reopen(&dir);
        assert!(matches!(
            chain::regime(&s.conn).unwrap(),
            chain::Regime::V2 { .. }
        ));
        assert!(
            s.verify().unwrap().ok(),
            "premise: re-blessed, verify green"
        );
        assert!(matches!(
            s.witness_check(&w_post).unwrap(),
            WitnessVerdict::RolledBack {
                rewritten: true,
                ..
            }
        ));
        // Verdict::Cost — the pre-switch witness names rows the un-switch
        // left untouched; the re-switch's commitment is appended after them.
        assert!(matches!(
            s.witness_check(&w_pre).unwrap(),
            WitnessVerdict::Extends { rows_since: 1, .. }
        ));
    }

    /// A witness positions by ROWS: a row that lands without moving
    /// `chain_meta.writes` (the retention fixtures' shape) is counted.
    #[test]
    fn a_witness_positions_by_rows_never_by_writes() {
        let (_dir, mut s) = fresh(SecurityLevel::HmacOnly);
        s.upsert(&drawer("first", 0)).unwrap();
        let w = s.witness_emit().unwrap();
        let writes_before = chain::writes(&s.conn).unwrap();
        s.conn
            .execute(
                "INSERT INTO audit (record_id, tag, at) \
                 VALUES ('probe/o245', X'00', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        assert_eq!(chain::writes(&s.conn).unwrap(), writes_before, "premise");
        let again = s.witness_emit().unwrap();
        assert_eq!(again.rows, w.rows + 1, "rows counted the planted row");
        assert_eq!(again.writes, w.writes, "writes did not");
    }

    /// A witness of another vault is an integrity finding, not a caller
    /// error: a vault destroyed and re-created under the same name is an
    /// erasure and must not read as a typo.
    #[test]
    fn a_foreign_witness_is_an_integrity_finding() {
        let (_a, mut a) = fresh(SecurityLevel::HmacOnly);
        a.upsert(&drawer("first", 0)).unwrap();
        let w = a.witness_emit().unwrap();
        let dir_b = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir_b.path(), None).unwrap();
        let mut b =
            VaultStore::open(mgr.create("other", SecurityLevel::HmacOnly).unwrap()).unwrap();
        b.upsert(&drawer("first", 0)).unwrap();
        assert!(matches!(
            b.witness_check(&w),
            Err(StoreError::IntegrityFinding(_))
        ));
    }

    /// A genesis witness is refused at emit and at check.
    #[test]
    fn a_genesis_witness_is_refused() {
        let (_dir, s) = fresh(SecurityLevel::HmacOnly);
        // A fresh vault holds exactly its switch commitment, so the chain
        // is never truly empty on a current build; force the vacuous case.
        s.conn.execute("DELETE FROM audit", []).unwrap();
        assert!(matches!(s.witness_emit(), Err(StoreError::Invalid(_))));
        let w = ChainWitness {
            version: WITNESS_VERSION,
            vault: s.vault.id().to_string(),
            rows: 0,
            prefix_digest: String::new(),
            head: undercroft_vault::Vault::chain_genesis_hex(),
            regime: "v1".into(),
            writes: 0,
            anchored_head: String::new(),
            emitted_at: String::new(),
            unhealed: vec![],
            sender: None,
            sig: None,
        };
        assert!(matches!(s.witness_check(&w), Err(StoreError::Invalid(_))));
    }

    /// Signing: a signed witness verifies; a tampered one fails as an
    /// attestation error; a half-stripped one is refused, never "unsigned".
    #[test]
    fn a_signed_witness_verifies_and_a_tampered_or_half_stripped_one_is_refused() {
        let (_dir, mut s) = fresh(SecurityLevel::HmacOnly);
        s.upsert(&drawer("first", 0)).unwrap();
        let (secret, sender) = undercroft_vault::bundle::sign_keygen();
        let mut w = s.witness_emit().unwrap();
        w.sign(&secret).unwrap();
        assert_eq!(w.sender.as_deref(), Some(sender.as_str()));
        assert!(w.signed());
        assert!(matches!(
            s.witness_check(&w).unwrap(),
            WitnessVerdict::Extends { rows_since: 0, .. }
        ));
        let mut forged = w.clone();
        forged.rows += 1;
        assert!(matches!(
            s.witness_check(&forged),
            Err(StoreError::Attestation(_))
        ));
        let mut half = w.clone();
        half.sig = None;
        assert!(!half.signed());
        assert!(matches!(
            s.witness_check(&half),
            Err(StoreError::Attestation(_))
        ));
        // The document round-trips through JSON byte-for-byte on the
        // canonical, which is what a file on a shelf has to survive.
        let json = serde_json::to_string(&w).unwrap();
        let back: ChainWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(back.canonical(), w.canonical());
    }
}
