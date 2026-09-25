//! Retention policies (C3.2 phase 2): the operator declares how long a
//! wing (or one room in it) keeps drawers, and an **explicit sweep**
//! destroys what has aged out — through [`forget_with_proof`], so every
//! retention destruction carries the same chain-attested receipt as a
//! GDPR erasure request.
//!
//! Three postures, all deliberate:
//!
//! * **A policy is a declaration, enforcement is an act.** Nothing is
//!   destroyed at open, on a timer, or as a side effect of a write — a
//!   sweep runs when the operator runs it (`undercroft retention sweep`,
//!   `POST /v1/…/retention/sweep`). Automatic destruction reconciling
//!   against a restored backup, a skewed clock, or a crash window is a
//!   data-loss machine; an explicit sweep is auditable, schedulable by
//!   the deployment's own scheduler, and refusable.
//! * **Policies are the receiving principal's declarations** — assigned
//!   like wing trust (operator surfaces only, never MCP), validated,
//!   HMAC-tagged, chain-audited. An offline flip of `max_age_days` is
//!   an integrity failure on read, never a silently shorter retention.
//! * **The quarantine wing is not retention's to empty.** Its residents
//!   are pending human review; the doors out are `admission allow` and
//!   `admission deny` (the latter now receipted). A policy naming the
//!   reserved wing is refused.
//!
//! The retention clock is the **HMAC-covered** `meta.filed_at` — stamped
//! at drawer construction, which every API save path does server-side —
//! never `content_date` (the writer's claim about the content, which
//! would let a mis-dated drawer outlive or pre-die its residence), and
//! deliberately **not the clear-text `filed_at` column**: that column
//! sits outside HMAC coverage, and a destruction decision must rest only
//! on tag-verified bytes — an offline column flip must be able neither
//! to launder a deletion through a legitimate keyed sweep (flip older)
//! nor to hide a drawer from its declared retention (flip newer). The
//! same holds for SCOPE since ROADMAP O206: which wing and room a drawer
//! belongs to is read from the covered meta too, over one walk of every
//! drawer that tag-verifies each row before reading it — an
//! operator-command price, paid on purpose, and cheap because the tag
//! covers the at-rest bytes and nothing is decrypted. A sweep must never
//! destroy what it cannot date, and must never skip it silently either:
//! a covered member whose `filed_at` does not parse is WITHHELD and named
//! (it used to fail the whole sweep, which kept the rule at the price of
//! one legacy row stopping every policy), and a row whose tag fails is
//! named wherever it sits.

use rusqlite::params;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::admission::QUARANTINE_WING;
use crate::chain::{ChainRecord, LabelUse};
use crate::forget::ForgetAttestation;
use crate::{chain_append, Namespace, StoreError, VaultStore};

/// One declared policy, as listed back to the operator.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionPolicy {
    /// The wing the policy covers.
    pub wing: String,
    /// Empty = the whole wing.
    pub room: String,
    /// A drawer older than this many days, by its HMAC-covered `filed_at`, is past the policy.
    pub max_age_days: u32,
    /// When the policy was declared (RFC 3339).
    pub assigned_at: String,
}

/// One policy's share of a sweep.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionSweepEntry {
    /// The policy's wing.
    pub wing: String,
    /// The policy's room; empty for a whole-wing policy.
    pub room: String,
    /// The policy's age bound, in days.
    pub max_age_days: u32,
    /// Drawer ids past the policy's age at sweep time.
    pub expired: Vec<String>,
}

/// A drawer row the sweep could not decide (ROADMAP O206).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionUnverifiable {
    /// The row's id, as its unauthenticated column states it.
    pub id: String,
    /// Why it could not be decided.
    pub reason: String,
}

/// A drawer its policy covers and the sweep did not destroy, and why
/// (ROADMAP O206).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionWithheld {
    /// The drawer's id.
    pub id: String,
    /// Its wing, by the HMAC-covered meta.
    pub wing: String,
    /// Its room, by the HMAC-covered meta.
    pub room: String,
    /// Why it was withheld, naming the exit that works.
    pub reason: String,
}

/// What a sweep did (or, dry, would do).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionSweep {
    /// Whether nothing was destroyed.
    pub dry_run: bool,
    /// False when any of `unverifiable`, `withheld`, `mirror_drift` or
    /// `policy_drift` is non-empty. Serialized at the top level because a
    /// 200 carrying `"ok": false` is how an integrity verdict travels, and
    /// the orchestrator reads exactly that.
    pub ok: bool,
    /// Each policy's share of the sweep.
    pub policies: Vec<RetentionSweepEntry>,
    /// Distinct drawers destroyed (a wing policy and a room policy can
    /// name the same drawer; it dies once).
    pub destroyed: usize,
    /// Rows, anywhere in the vault, whose record HMAC fails or whose covered
    /// meta does not parse. Neither copy of such a row's scope is authentic,
    /// so none is destroyed and none is left out of this list.
    pub unverifiable: Vec<RetentionUnverifiable>,
    /// Drawers a policy covers, past its age, that were not destroyed.
    pub withheld: Vec<RetentionWithheld>,
    /// `verify`'s mirror-drift lines for the drawers this sweep destroyed or
    /// withheld — the one trace of an offline flip, kept in the report
    /// because destroying the drawer removes it from the vault.
    pub mirror_drift: Vec<String>,
    /// The retention half of `verify`'s policy-drift leg: a policy row that
    /// is gone while the chain still declares it, whose scope no sweep can
    /// enforce any more.
    pub policy_drift: Vec<String>,
    /// The chain-attested receipt for this sweep's destruction — absent
    /// on a dry run and on a sweep that found nothing expired: this
    /// store refuses to mint an attestation for no destruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<ForgetAttestation>,
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("rfc3339 now")
}

pub(crate) fn retention_canonical(wing: &str, room: &str, days: u32, at: &str) -> Vec<u8> {
    format!("retention\x1f{wing}\x1f{room}\x1f{days}\x1f{at}").into_bytes()
}

impl VaultStore {
    pub(crate) fn init_retention_schema(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS retention_policy (
                 wing         TEXT NOT NULL,
                 room         TEXT NOT NULL DEFAULT '',
                 max_age_days INTEGER NOT NULL,
                 tag          BLOB NOT NULL,
                 assigned_at  TEXT NOT NULL,
                 PRIMARY KEY (wing, room)
             );",
        )?;
        Ok(())
    }

    /// Declare (or re-declare) a retention policy for a wing, or for one
    /// room in it. Operator surfaces only — like wing trust, deliberately
    /// never an MCP tool: an agent must not shorten the life of the
    /// memory it writes or reads. Re-declaration overwrites and is
    /// audited again; history lives in the chain.
    pub fn set_retention(
        &mut self,
        wing: &str,
        room: Option<&str>,
        max_age_days: u32,
    ) -> Result<(), StoreError> {
        let room = room.unwrap_or("");
        // `Invalid`, not `CorruptRow`: a bad name is the caller's input
        // error and must reach `/v1` as 400 — the same name was already a
        // 400 on the save route and a 500 reading "corrupt row" here.
        undercroft_core::validate_name(wing, "wing")
            .map_err(|e| StoreError::Invalid(e.to_string()))?;
        if !room.is_empty() {
            undercroft_core::validate_name(room, "room")
                .map_err(|e| StoreError::Invalid(e.to_string()))?;
        }
        if wing == QUARANTINE_WING {
            return Err(StoreError::Invalid(format!(
                "no retention policy on {QUARANTINE_WING}: its residents are \
                 pending human review, and the doors out are `admission allow` \
                 and `admission deny`, not an age"
            )));
        }
        if max_age_days == 0 {
            return Err(StoreError::Invalid(
                "max_age_days must be at least 1 — to remove a policy, clear it \
                 explicitly"
                    .into(),
            ));
        }
        let now = now_rfc3339();
        let tag = self
            .vault
            .tag(retention_canonical(wing, room, max_age_days, &now).as_slice());
        let rest = if room.is_empty() {
            wing.to_string()
        } else {
            format!("{wing}/{room}")
        };
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO retention_policy (wing, room, max_age_days, tag, assigned_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(wing, room) DO UPDATE SET
                 max_age_days = excluded.max_age_days, tag = excluded.tag,
                 assigned_at = excluded.assigned_at",
            params![wing, room, max_age_days, tag.as_slice(), now],
        )?;
        chain_append(&tx, &self.vault, Namespace::Retention, &rest, &tag, &now)?;
        tx.commit()?;
        self.anchor()?;
        Ok(())
    }

    /// Remove a declared policy — an explicit, audited act (a policy that
    /// silently stopped applying would be indistinguishable from one that
    /// was never read).
    pub fn clear_retention(&mut self, wing: &str, room: Option<&str>) -> Result<(), StoreError> {
        let room = room.unwrap_or("");
        let removed = {
            let tx = self.conn.transaction()?;
            let n = tx.execute(
                "DELETE FROM retention_policy WHERE wing = ?1 AND room = ?2",
                params![wing, room],
            )?;
            if n > 0 {
                let now = now_rfc3339();
                let rest = if room.is_empty() {
                    wing.to_string()
                } else {
                    format!("{wing}/{room}")
                };
                let canonical = format!("retention-clear\x1f{wing}\x1f{room}\x1f{now}");
                let tag = self.vault.tag(canonical.as_bytes());
                chain_append(
                    &tx,
                    &self.vault,
                    Namespace::RetentionClear,
                    &rest,
                    &tag,
                    &now,
                )?;
                tx.commit()?;
                self.anchor()?;
            }
            n
        };
        if removed == 0 {
            return Err(StoreError::Invalid(format!(
                "no retention policy on wing {wing:?} room {room:?}"
            )));
        }
        Ok(())
    }

    /// Every declared policy, tag-verified on the way out — a flipped
    /// `max_age_days` is an integrity error here, never a silently
    /// different lifespan. **And checked against the chain (ROADMAP O230)**:
    /// an older, validly tagged row written back offline verifies too, so a
    /// row that is not its key's newest declaration, or that is present after
    /// a newer clear, refuses as well — the sweep and `retention list` with
    /// it, because a replayed lifespan is a tampered lifespan. A row DELETED
    /// behind the store stays report-only here (O206): there is no policy
    /// left to act on, and `verify` and the sweep's `policy_drift` name it.
    ///
    /// A guarded door (ROADMAP O253): the rows and the records they are
    /// judged against are read in ONE snapshot — read in two, a legitimate
    /// `retention set` between them made a row read "not the newest
    /// declaration" (measured, 59 in 248,408 reads).
    pub fn retention_policies(&self) -> Result<Vec<RetentionPolicy>, StoreError> {
        self.guarded(|snap| {
            let (rows, findings) = self.retention_policy_scan(snap, LabelUse::Decide)?;
            refuse_on_findings(&findings, |f| !f.gone)?;
            Ok(rows)
        })
    }

    /// Run (or preview) a sweep: every declared policy contributes the
    /// drawers older than its age, the distinct set is destroyed through the
    /// one attested destruction every forgetting path shares, and the
    /// attestation is the receipt. Dry runs and empty sweeps destroy nothing
    /// and attest nothing.
    ///
    /// **Membership is read from the HMAC-covered copy alone, over one walk
    /// of every drawer** (ROADMAP O206). The candidates used to come from the
    /// clear `wing`/`room` mirror, and every decision read the covered copy
    /// (O120) — so an offline `UPDATE drawers SET wing = …` that moved a
    /// drawer OUT of the mirror's scope kept it from ever being a candidate,
    /// and the sweep kept a drawer its policy says must be destroyed while
    /// reporting clean. That is A28 one more time: a mirror deciding an
    /// exclusion. The walk is [`VaultStore::walk_covered`], the same one
    /// `verify` rides; it checks each tag over the at-rest bytes, decrypts
    /// nothing, streams, and runs once per sweep with every policy matched
    /// in memory. No mirror prefilter — a SELECT on the clear columns is the
    /// defect, however it is described.
    ///
    /// What a sweep cannot decide it names and does not destroy, and it goes
    /// on with everything it could decide (`ok` is then false):
    /// * a row whose tag fails, or whose covered meta does not parse,
    ///   ANYWHERE in the vault — both copies of its scope are the offline
    ///   writer's, so a list scoped by either would reinstate the escape;
    /// * a covered member whose `filed_at` does not parse — it cannot be
    ///   dated. This arm used to FAIL the sweep, which kept "never destroy
    ///   what cannot be dated, never skip it silently" at the price of one
    ///   legacy row stopping every policy; naming it keeps both halves;
    /// * a covered member the pending-evidence fence refuses, which is a
    ///   drawer whose clear `wing` was flipped INTO the review queue: the
    ///   fence reads that column on purpose, and handing the row to the
    ///   destruction would refuse the whole call.
    ///
    /// A policy row that fails its own tag still refuses the whole sweep: a
    /// tampered lifespan must never drive a destruction.
    ///
    /// **It decides on ONE state and destroys only what the policy IN FORCE
    /// at the destruction expires** (ROADMAP O255). The decision — the
    /// policies, their drift and the walk — is one guarded snapshot, outside
    /// any lock, because the walk is O(corpus). The destruction takes ONE
    /// write lock, and inside it first compares the policy rows byte for byte
    /// (wing, room, age, tag, time) with the rows the decision used: every
    /// legitimate `set` and `clear` rewrites the tag and the time, so equal
    /// rows are the same declarations. Then each member is re-classified
    /// through the walk's own per-row decision and the fence, inside the lock:
    /// one that vanished, or that the policy no longer expires, is dropped;
    /// one whose tag now fails is unverifiable; one flipped into the review
    /// queue is withheld; the rest are destroyed, fingerprinted from what the
    /// lock read. It used to decide on four states and destroy on a fifth, so
    /// a `retention set 36500` committed meanwhile was ignored and the drawers
    /// it kept were destroyed (measured: 58 of 64 sweeps). When the rows
    /// differ, the lock commits nothing and the sweep decides again outside,
    /// ONCE; when they differ again, it decides inside the lock — the walk and
    /// an in-place replay under the write lock, a cost reached only by a
    /// policy re-declared inside two decision windows in a row. The report
    /// describes the state the destruction saw: `policies` are the
    /// declarations in force, and `destroyed` is the distinct union of the
    /// `expired` lists, which are the receipt's drawers. Stated residual:
    /// membership is as of the walk, so a drawer that crosses its age, or
    /// arrives with an old `filed_at`, after the walk waits for the next sweep.
    pub fn retention_sweep(&mut self, dry_run: bool) -> Result<RetentionSweep, StoreError> {
        let now = OffsetDateTime::now_utc();
        if dry_run {
            return self.guarded(|snap| {
                let decided = self.sweep_decide_in(snap, now)?;
                Ok(self.sweep_settle_in(snap, &decided, Settle::Preview)?.0)
            });
        }
        self.refuse_when_read_only("a retention sweep destroys drawers")?;
        for attempt in 0..2 {
            let decided = self.guarded(|snap| self.sweep_decide_in(snap, now))?;
            crate::sweep_pause::fire(
                self.vault.dir(),
                crate::sweep_pause::Phase::Decided { attempt },
            );
            let settled = self.under_destruction_lock(|s, snap| {
                if policy_rows(snap.conn())? != decided.rows {
                    // Declarations changed since the decision: nothing is
                    // destroyed under this lock, and the sweep decides again.
                    return Ok((None, Vec::new()));
                }
                let (sweep, destroyed) = s.sweep_settle_in(snap, &decided, Settle::Recheck)?;
                Ok((Some(sweep), destroyed))
            })?;
            if let Some(sweep) = settled {
                return Ok(sweep);
            }
        }
        crate::sweep_pause::fire(self.vault.dir(), crate::sweep_pause::Phase::DecidingInLock);
        self.under_destruction_lock(|s, snap| {
            let decided = s.sweep_decide_in(snap, now)?;
            s.sweep_settle_in(snap, &decided, Settle::AsDecided)
        })
    }

    /// A sweep's decision, on ONE state (ROADMAP O255): the policies and
    /// their drift through one `Decide` scan — which refuses a tampered
    /// lifespan — the rows as stored, and the walk. On a helper snapshot it
    /// is read outside any lock; on a write-locked one, inside it.
    fn sweep_decide_in(
        &self,
        snap: &crate::chain::Snapshot<'_>,
        now: OffsetDateTime,
    ) -> Result<SweepDecision, StoreError> {
        let (policies, findings) = self.retention_policy_scan(snap, LabelUse::Decide)?;
        refuse_on_findings(&findings, |f| !f.gone)?;
        let mut policy_drift: Vec<String> = findings.into_iter().map(|f| f.text).collect();
        policy_drift.sort();
        let rows = policy_rows(snap.conn())?;
        let cutoffs = cutoffs_of(&policies, now);
        let mut members = Vec::new();
        let mut unverifiable = Vec::new();
        let mut undatable = Vec::new();
        // No policy, no scope: nothing any row could be a member of, so the
        // walk would decide nothing.
        if !policies.is_empty() {
            // The walk reads through the handle's connection, which is inside
            // `snap`'s transaction: the same state as the policies.
            self.walk_covered(|row| {
                match classify(row, &policies, &cutoffs) {
                    Member::Outside => {}
                    Member::Unverifiable(u) => unverifiable.push(u),
                    Member::Undatable(w, drift) => undatable.push((w, drift)),
                    Member::Expired(m) => members.push(m),
                }
                Ok(())
            })?;
        }
        Ok(SweepDecision {
            rows,
            policies,
            policy_drift,
            cutoffs,
            members,
            unverifiable,
            undatable,
        })
    }

    /// Settle a decision: the fence, and — unless previewing — the attested
    /// destruction, inside the caller's lock. `Recheck` re-classifies every
    /// member from the row as the lock reads it; `AsDecided` trusts a
    /// decision made in this same state.
    fn sweep_settle_in(
        &self,
        snap: &crate::chain::Snapshot<'_>,
        decided: &SweepDecision,
        how: Settle,
    ) -> Result<(RetentionSweep, Vec<crate::manage::Destroyed>), StoreError> {
        let mut expired: Vec<Vec<String>> = vec![Vec::new(); decided.policies.len()];
        let mut unverifiable = decided.unverifiable.clone();
        let mut withheld = Vec::new();
        let mut mirror_drift = Vec::new();
        for (w, drift) in &decided.undatable {
            withheld.push(w.clone());
            mirror_drift.extend(drift.iter().cloned());
        }
        for m in &decided.members {
            let m = match how {
                Settle::Preview | Settle::AsDecided => m.clone(),
                Settle::Recheck => match self.covered_one(snap.conn(), &m.id)? {
                    // Destroyed by another handle since the walk.
                    None => continue,
                    Some(row) => match classify(row, &decided.policies, &decided.cutoffs) {
                        // Corrected out of scope, or kept by the policy.
                        Member::Outside => continue,
                        Member::Unverifiable(u) => {
                            if !unverifiable.iter().any(|v| v.id == u.id) {
                                unverifiable.push(u);
                            }
                            continue;
                        }
                        Member::Undatable(w, drift) => {
                            withheld.push(w);
                            mirror_drift.extend(drift);
                            continue;
                        }
                        Member::Expired(m) => m,
                    },
                },
            };
            // The pending-evidence fence decides here, through the function
            // the destruction itself calls — never a copy of it — so this
            // split cannot disagree with the refusal it exists to avoid.
            if self.is_quarantine_pending(&m.id)? {
                withheld.push(RetentionWithheld {
                    reason: format!(
                        "its clear `wing` column names the review queue ({QUARANTINE_WING}) \
                         while its HMAC-covered meta files it under {}; the \
                         pending-evidence fence reads that column, so no sweep can destroy \
                         it. Re-save its own content with `drawer update` and sweep again",
                        m.wing
                    ),
                    id: m.id.clone(),
                    wing: m.wing.clone(),
                    room: m.room.clone(),
                });
                mirror_drift.extend(m.drift.iter().cloned());
                continue;
            }
            for &i in &m.covers {
                expired[i].push(m.id.clone());
            }
            mirror_drift.extend(m.drift.iter().cloned());
        }
        let distinct =
            crate::forget::distinct(&expired.iter().flatten().cloned().collect::<Vec<String>>());
        let (attestation, destroyed) = if how == Settle::Preview || distinct.is_empty() {
            (None, Vec::new())
        } else {
            let (att, gone) = self.attest_in(
                snap,
                &distinct,
                crate::manage::PendingEvidence::Protect,
                &crate::forget::MirrorDelete::NotIssued,
            )?;
            (Some(att), gone)
        };
        let dry_run = how == Settle::Preview;
        let ok = unverifiable.is_empty()
            && withheld.is_empty()
            && mirror_drift.is_empty()
            && decided.policy_drift.is_empty();
        let policies = decided
            .policies
            .iter()
            .cloned()
            .zip(expired)
            .map(|(p, expired)| RetentionSweepEntry {
                wing: p.wing,
                room: p.room,
                max_age_days: p.max_age_days,
                expired,
            })
            .collect();
        Ok((
            RetentionSweep {
                dry_run,
                ok,
                policies,
                destroyed: if dry_run { 0 } else { distinct.len() },
                unverifiable,
                withheld,
                mirror_drift,
                policy_drift: decided.policy_drift.clone(),
                attestation,
            },
            destroyed,
        ))
    }

    /// The retention half of `verify`'s policy-drift leg (ROADMAP O94),
    /// sorted — ONE implementation, which `verify` and the sweep both call
    /// (ROADMAP O206), deciding through [`policy_finding`] (ROADMAP O230).
    /// The sweep needs a deleted row most: a policy row deleted offline is a
    /// scope nothing enforces any more, and a sweep that reads only the rows
    /// present answered clean beside it.
    pub(crate) fn retention_policy_drift(
        &self,
        snap: &crate::chain::Snapshot<'_>,
    ) -> Result<Vec<String>, StoreError> {
        let mut drift: Vec<String> = self
            .retention_policy_scan(snap, LabelUse::Report)?
            .1
            .into_iter()
            .map(|f| f.text)
            .collect();
        drift.sort();
        Ok(drift)
    }

    /// The trust half of the same leg, moved here from `verify` so both
    /// halves decide through [`policy_finding`] (ROADMAP O230), sorted.
    pub(crate) fn trust_policy_drift(
        &self,
        snap: &crate::chain::Snapshot<'_>,
    ) -> Result<Vec<String>, StoreError> {
        let mut drift: Vec<String> = self
            .trust_policy_scan(snap, LabelUse::Report)?
            .1
            .into_iter()
            .map(|f| f.text)
            .collect();
        drift.sort();
        Ok(drift)
    }

    /// Every `retention_policy` row with the evidence about it, and every
    /// finding — rows present and declarations whose row is gone. The ONE
    /// scan `verify`, the sweep and `retention_policies` share.
    ///
    /// **The guard is HERE, on the scan, not on the public wrapper**
    /// (ROADMAP O237): `verify` already reaches this function directly, so a
    /// guard on `retention_policies` alone would leave the next caller that
    /// does the same unguarded. `on` is required for the same reason — the
    /// two answers are opposite and neither is a safe default.
    ///
    /// **Everything it reads, it reads in `snap`** (ROADMAP O253): the rows,
    /// the boundary, every row's newest record and the label census. A
    /// `Decide` scan confirms the door authenticated that snapshot; a
    /// `Report` scan is `verify`'s, in `verify`'s one snapshot.
    pub(crate) fn retention_policy_scan(
        &self,
        snap: &crate::chain::Snapshot<'_>,
        on: LabelUse,
    ) -> Result<(Vec<RetentionPolicy>, Vec<PolicyFinding>), StoreError> {
        if on == LabelUse::Decide {
            self.labels_authenticated(snap)?;
        }
        let boundary = self.rotation_boundary(snap, on)?;
        let mut stmt = snap.conn().prepare(concat!(
            "SELECT wing, room, max_age_days, tag, assigned_at ",
            "FROM retention_policy ORDER BY wing, room",
        ))?;
        let rows: Vec<(String, String, u32, Vec<u8>, String)> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut kept = Vec::with_capacity(rows.len());
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (wing, room, days, tag, at) in rows {
            let rest = if room.is_empty() {
                wing.clone()
            } else {
                format!("{wing}/{room}")
            };
            let key = Namespace::Retention.record(&rest);
            let verifies = self
                .vault
                .verify_tag(
                    retention_canonical(&wing, &room, days, &at).as_slice(),
                    &tag,
                )
                .is_ok();
            let evidence = PolicyEvidence {
                newest: self.newest_record(snap, &key, on)?,
                newest_clear: self
                    .newest_record(snap, &Namespace::RetentionClear.record(&rest), on)?
                    .map(|r| r.seq),
                boundary,
            };
            let row = RowState {
                verifies,
                tag: &tag,
            };
            if let Some(f) = policy_finding(&key, PolicyNoun::Retention, Some(row), &evidence) {
                findings.push(f);
            }
            seen.insert(key);
            kept.push(RetentionPolicy {
                wing,
                room,
                max_age_days: days,
                assigned_at: at,
            });
        }
        for key in self.chain_keys(snap, Namespace::Retention, on)? {
            if seen.contains(&key) {
                continue;
            }
            let rest = &key[Namespace::Retention.prefix().len()..];
            let evidence = PolicyEvidence {
                newest: self.newest_record(snap, &key, on)?,
                newest_clear: self
                    .newest_record(snap, &Namespace::RetentionClear.record(rest), on)?
                    .map(|r| r.seq),
                boundary,
            };
            if let Some(f) = policy_finding(&key, PolicyNoun::Retention, None, &evidence) {
                findings.push(f);
            }
        }
        Ok((kept, findings))
    }

    /// The same scan for `wing_trust` (ROADMAP O230), shared by `verify` and
    /// [`VaultStore::wing_trusts`]. Trust has no clear: no
    /// `DELETE FROM wing_trust` exists in this crate, so a row that is gone
    /// has no legitimate path.
    ///
    /// Guarded on the SCAN, with `on` required, for the reason stated on
    /// [`VaultStore::retention_policy_scan`] (ROADMAP O237).
    pub(crate) fn trust_policy_scan(
        &self,
        snap: &crate::chain::Snapshot<'_>,
        on: LabelUse,
    ) -> Result<TrustScan, StoreError> {
        if on == LabelUse::Decide {
            self.labels_authenticated(snap)?;
        }
        let boundary = self.rotation_boundary(snap, on)?;
        let mut stmt = snap
            .conn()
            .prepare("SELECT wing, trust, tag, assigned_at FROM wing_trust ORDER BY wing")?;
        let rows: Vec<(String, String, Vec<u8>, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        let mut kept = Vec::with_capacity(rows.len());
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (wing, trust, tag, at) in rows {
            let key = Namespace::Trust.record(&wing);
            let verifies = self
                .vault
                .verify_tag(
                    crate::manage::wing_trust_canonical(&wing, &trust, &at).as_slice(),
                    &tag,
                )
                .is_ok();
            let evidence = PolicyEvidence {
                newest: self.newest_record(snap, &key, on)?,
                newest_clear: None,
                boundary,
            };
            let row = RowState {
                verifies,
                tag: &tag,
            };
            if let Some(f) = policy_finding(&key, PolicyNoun::Trust, Some(row), &evidence) {
                findings.push(f);
            }
            seen.insert(key);
            kept.push((wing, trust));
        }
        for key in self.chain_keys(snap, Namespace::Trust, on)? {
            if seen.contains(&key) {
                continue;
            }
            let evidence = PolicyEvidence {
                newest: self.newest_record(snap, &key, on)?,
                newest_clear: None,
                boundary,
            };
            if let Some(f) = policy_finding(&key, PolicyNoun::Trust, None, &evidence) {
                findings.push(f);
            }
        }
        Ok((kept, findings))
    }
}

/// A policy row as stored — the tag and the time included, because every
/// legitimate `set` and `clear` rewrites them (ROADMAP O255).
type PolicyRow = (String, String, u32, Vec<u8>, String);

/// The policy table as stored, in one order, on `conn`.
fn policy_rows(conn: &rusqlite::Connection) -> Result<Vec<PolicyRow>, StoreError> {
    let mut stmt = conn.prepare(concat!(
        "SELECT wing, room, max_age_days, tag, assigned_at ",
        "FROM retention_policy ORDER BY wing, room",
    ))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

fn cutoffs_of(policies: &[RetentionPolicy], now: OffsetDateTime) -> Vec<OffsetDateTime> {
    policies
        .iter()
        .map(|p| now - Duration::days(i64::from(p.max_age_days)))
        .collect()
}

/// What a sweep decided, on one state (ROADMAP O255).
struct SweepDecision {
    /// The policy rows as stored, compared inside the destroying lock.
    rows: Vec<PolicyRow>,
    policies: Vec<RetentionPolicy>,
    policy_drift: Vec<String>,
    cutoffs: Vec<OffsetDateTime>,
    /// Covered members past a policy's age, in walk order.
    members: Vec<ExpiredMember>,
    /// Rows the walk could not decide, anywhere in the vault.
    unverifiable: Vec<RetentionUnverifiable>,
    /// Covered members that cannot be dated, with their drift.
    undatable: Vec<(RetentionWithheld, Vec<String>)>,
}

/// A covered member past at least one policy's age.
#[derive(Clone)]
struct ExpiredMember {
    id: String,
    wing: String,
    room: String,
    drift: Vec<String>,
    /// The policies it is past, by index.
    covers: Vec<usize>,
}

/// One row's standing under a set of policies.
enum Member {
    Outside,
    Unverifiable(RetentionUnverifiable),
    Undatable(RetentionWithheld, Vec<String>),
    Expired(ExpiredMember),
}

/// How a decision is settled.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Settle {
    /// A dry run: nothing is destroyed and no lock is taken.
    Preview,
    /// Inside the destroying lock, every member re-read and re-classified.
    Recheck,
    /// Inside the lock the decision itself was made in.
    AsDecided,
}

/// The ONE per-row membership decision the walk and the in-lock re-check
/// share (ROADMAP O206, O255): the covered scope, the covered clock.
fn classify(
    row: crate::CoveredRow,
    policies: &[RetentionPolicy],
    cutoffs: &[OffsetDateTime],
) -> Member {
    let (id, meta, drift) = match row {
        crate::CoveredRow::TagFailed { id } => {
            return Member::Unverifiable(RetentionUnverifiable {
                id,
                reason: "its record HMAC does not verify, so neither copy of its scope or its \
                         clock is authentic; `verify` names it"
                    .into(),
            });
        }
        crate::CoveredRow::MetaUnparseable { id } => {
            return Member::Unverifiable(RetentionUnverifiable {
                id,
                reason: "its HMAC-covered meta does not parse".into(),
            });
        }
        crate::CoveredRow::Verified { id, meta, drift } => (id, meta, drift),
    };
    let covers: Vec<usize> = policies
        .iter()
        .enumerate()
        .filter(|(_, p)| meta.wing == p.wing && (p.room.is_empty() || meta.room == p.room))
        .map(|(i, _)| i)
        .collect();
    if covers.is_empty() {
        return Member::Outside;
    }
    let filed = match OffsetDateTime::parse(&meta.filed_at, &Rfc3339) {
        Ok(t) => t,
        Err(e) => {
            let reason = format!(
                "its HMAC-covered filed_at {:?} is not RFC 3339 ({e}), so it cannot be dated; \
                 destroy it with `forget` if its policy applies",
                meta.filed_at
            );
            return Member::Undatable(
                RetentionWithheld {
                    id,
                    wing: meta.wing,
                    room: meta.room,
                    reason,
                },
                drift,
            );
        }
    };
    let past: Vec<usize> = covers.into_iter().filter(|&i| filed < cutoffs[i]).collect();
    if past.is_empty() {
        return Member::Outside;
    }
    Member::Expired(ExpiredMember {
        id,
        wing: meta.wing,
        room: meta.room,
        drift,
        covers: past,
    })
}

/// How a READER of a policy table refuses (ROADMAP O230): a failed tag keeps
/// its HMAC-mismatch verdict, naming the key as before; any other finding
/// the reader acts on is an integrity verdict that states itself.
pub(crate) fn refuse_on_findings(
    findings: &[PolicyFinding],
    acts_on: impl Fn(&PolicyFinding) -> bool,
) -> Result<(), StoreError> {
    if let Some(f) = findings.iter().find(|f| f.tag_fails) {
        let key = f.text.split(':').next().unwrap_or_default();
        return Err(StoreError::Integrity(key.to_string()));
    }
    let named: Vec<&str> = findings
        .iter()
        .filter(|f| acts_on(f))
        .map(|f| f.text.as_str())
        .collect();
    if named.is_empty() {
        return Ok(());
    }
    Err(StoreError::IntegrityFinding(format!(
        "{} — the policy tables disagree with the audit chain that recorded them; \
         run `undercroft verify`, then re-declare the policy (`trust set`, \
         `retention set` or `retention clear`) to write a fresh matching record",
        named.join("; ")
    )))
}

/// Every `wing_trust` row as `(wing, trust)`, and every finding.
pub(crate) type TrustScan = (Vec<(String, String)>, Vec<PolicyFinding>);

/// What the chain holds about one policy key, gathered by the one gatherer.
pub(crate) struct PolicyEvidence {
    /// The newest assignment (`trust/…`) or declaration (`retention/…`).
    newest: Option<ChainRecord>,
    /// The newest `retention-clear/…` for the same key, by seq.
    newest_clear: Option<i64>,
    /// The newest rotation's seq; records before it predate the key epoch.
    boundary: Option<i64>,
}

/// A policy row as the decision sees it.
pub(crate) struct RowState<'a> {
    verifies: bool,
    tag: &'a [u8],
}

/// Which table a key belongs to: the finding names it in that table's words.
#[derive(Clone, Copy)]
pub(crate) enum PolicyNoun {
    Trust,
    Retention,
}

/// A policy finding, and whether it is a failed tag (an HMAC mismatch) or a
/// row that verifies and still disagrees with the chain.
pub(crate) struct PolicyFinding {
    /// The row fails its tag under the current key.
    pub(crate) tag_fails: bool,
    /// The row is gone while the chain still declares it.
    pub(crate) gone: bool,
    /// `verify`'s line for it.
    pub(crate) text: String,
}

/// **The one policy decision** (ROADMAP O230): `verify`'s policy leg, the
/// trust floor and the retention sweep all ask it, so they cannot disagree.
///
/// A row that verifies under the current key is not enough, and was all the
/// leg checked: a row copied out of the file earlier and written back
/// verifies too, and its record id exists. So a row must also be the one its
/// NEWEST chain record assigned — its tag equal to that record's tag, which
/// is the row's own tag at the moment it was written — whenever that record
/// is NEWER than the last rotation. Older than the boundary, the row was
/// re-tagged by that rotation and nothing in the chain carries its new tag;
/// since O232 every rotation verifies before it re-tags, so such a row is the
/// checked latest assignment re-tagged, and rows an earlier binary's rotation
/// laundered are the stated residual. A row present after a NEWER
/// `retention-clear/` is a cleared policy written back, at any seq. The
/// comparison is O94's, which that entry dropped because it alarmed on every
/// rotated vault; bounded by the rotation it no longer does.
///
/// **What a lookup by label can still miss (ROADMAP O233)**: every lookup
/// finds a record by its label, so relabelling the newer record, or a later
/// one as `rotate/`, still hides a replay FROM THIS FUNCTION. It was a stated
/// cost until O233's labelled chain step made the relabel itself break the
/// replay on a switched chain, where `verify` fails on `chain_ok` (after the
/// switch) or `label_commitment` (before it). The readers that call this act
/// before any replay runs, which is ROADMAP O237.
pub(crate) fn policy_finding(
    key: &str,
    noun: PolicyNoun,
    row: Option<RowState<'_>>,
    evidence: &PolicyEvidence,
) -> Option<PolicyFinding> {
    let (verb, noun_word) = match noun {
        PolicyNoun::Trust => ("assigned", "assignment"),
        PolicyNoun::Retention => ("declared", "declaration"),
    };
    let cleared_after = match (&evidence.newest, evidence.newest_clear) {
        (Some(a), Some(c)) => c > a.seq,
        (None, Some(_)) => true,
        _ => false,
    };
    let finding = |text: String, tag_fails: bool, gone: bool| {
        Some(PolicyFinding {
            tag_fails,
            gone,
            text,
        })
    };
    match row {
        Some(r) if !r.verifies => finding(format!("{key}: row does not verify"), true, false),
        Some(_) if cleared_after => finding(
            format!("{key}: row present, cleared later in the chain"),
            false,
            false,
        ),
        Some(r) => match &evidence.newest {
            None => finding(format!("{key}: {verb} in no chain record"), false, false),
            Some(a) if evidence.boundary.is_none_or(|b| a.seq > b) && a.tag != r.tag => finding(
                format!("{key}: row is not the newest {noun_word} in the chain"),
                false,
                false,
            ),
            Some(_) => None,
        },
        None => match &evidence.newest {
            Some(_) if !cleared_after => finding(
                format!("{key}: {verb} in the chain, row is gone"),
                false,
                true,
            ),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::LabelUse;
    use crate::{InternalRead, Read, StoreError, VaultStore};
    use rusqlite::params;
    use tempfile::TempDir;
    use undercroft_core::Drawer;
    use undercroft_vault::{SecurityLevel, VaultManager};

    /// ROADMAP O120 (A28 one table over): a sweep destroys only what the
    /// HMAC-covered `meta.wing`/`meta.room` places in scope. The candidate
    /// SELECT rides the clear mirror columns, and until this fix so did the
    /// decision, so one offline `UPDATE drawers SET wing = …` moved a drawer
    /// INTO a retention scope and a keyed sweep destroyed it — the mirror
    /// was the whole membership test. The PREMISE arm proves the same
    /// drawer IS swept when its covered scope really is the policy's.
    #[test]
    fn a_flipped_wing_mirror_cannot_move_a_drawer_into_a_retention_scope() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("r", SecurityLevel::Sealed).unwrap();
        let mut store = VaultStore::open(vault).unwrap();
        // An old drawer filed under `archive`, which has no retention.
        let mut kept = Drawer::new(
            "archive",
            "r",
            "an old memory the archive keeps".into(),
            Some("t.md".into()),
            0,
            "t",
        );
        kept.meta.filed_at = "2020-01-01T00:00:00Z".into();
        // And an old drawer genuinely filed under `scratch`, which expires.
        let mut swept = Drawer::new(
            "scratch",
            "r",
            "an old note scratch forgets".into(),
            Some("t.md".into()),
            1,
            "t",
        );
        swept.meta.filed_at = "2020-01-01T00:00:00Z".into();
        store.upsert(&kept).unwrap();
        store.upsert(&swept).unwrap();
        store.set_retention("scratch", None, 30).unwrap();
        // The offline writer: flip `kept`'s clear mirror into the scope.
        store
            .conn
            .execute(
                "UPDATE drawers SET wing = 'scratch' WHERE id = ?1",
                [&kept.id],
            )
            .unwrap();
        let sweep = store.retention_sweep(false).unwrap();
        // PREMISE: the sweep ran and destroyed the drawer whose covered
        // scope really is `scratch`.
        assert_eq!(sweep.destroyed, 1, "{sweep:?}");
        assert_eq!(sweep.policies[0].expired, vec![swept.id.clone()]);
        assert!(store
            .get(&swept.id, Read::Internal(InternalRead::Verification))
            .unwrap()
            .is_none());
        // The flipped drawer survives: its covered wing is `archive`.
        assert!(
            store
                .get(&kept.id, Read::Internal(InternalRead::Verification))
                .unwrap()
                .is_some(),
            "a clear mirror flip must not put a drawer inside a sweep"
        );
        // And the flip is what `verify` reports. The sweep does not: the
        // flipped drawer is no member of any scope, so its drift is
        // `verify`'s to name, and the sweep's report stays about what it
        // destroyed or withheld (O206).
        assert!(!store.verify().unwrap().mirror_drift.is_empty());
        assert!(sweep.mirror_drift.is_empty() && sweep.ok, "{sweep:?}");
    }

    fn sealed_store() -> (TempDir, VaultStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("r", SecurityLevel::Sealed).unwrap();
        (dir, VaultStore::open(vault).unwrap())
    }

    /// An old drawer, past any policy this module declares.
    fn old(wing: &str, room: &str, text: &str, chunk: u32) -> Drawer {
        let mut d = Drawer::new(wing, room, text.into(), Some("t.md".into()), chunk, "t");
        d.meta.filed_at = "2020-01-01T00:00:00Z".into();
        d
    }

    fn present(store: &VaultStore, id: &str) -> bool {
        store
            .conn
            .query_row("SELECT COUNT(*) FROM drawers WHERE id = ?1", [id], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
            == 1
    }

    /// ROADMAP O206's gate. The candidates came from the clear mirror, so an
    /// offline `UPDATE drawers SET wing = …` (or `room`) that moved a drawer
    /// OUT of its policy's scope kept it from ever being a candidate: the
    /// sweep destroyed the rest, reported clean, and kept a drawer its
    /// declared retention says must go. Membership is the covered copy now,
    /// over one walk, so the flipped drawers are destroyed — and the report
    /// carries the drift, because destroying them removes the one trace of
    /// the flip from the vault. The dry run walks the same path and says the
    /// same, destroying nothing.
    #[test]
    fn a_mirror_flipped_out_of_a_retention_scope_is_still_swept() {
        let (_d, mut store) = sealed_store();
        let wing_flip = old("w1", "r", "an old note the offline writer wants kept", 0);
        let kept_clean = old("w1", "r", "an old note with its mirror intact", 1);
        let room_flip = old("v", "keep", "an old note in a room-scoped policy", 2);
        let other = old("other", "r", "an old note no policy covers", 3);
        for d in [&wing_flip, &kept_clean, &room_flip, &other] {
            store.upsert(d).unwrap();
        }
        store.set_retention("w1", None, 30).unwrap();
        store.set_retention("v", Some("keep"), 30).unwrap();
        // The offline writer moves one drawer's WING and another's ROOM out
        // of their policies' scopes.
        store
            .conn
            .execute(
                "UPDATE drawers SET wing = 'elsewhere' WHERE id = ?1",
                [&wing_flip.id],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE drawers SET room = 'other' WHERE id = ?1",
                [&room_flip.id],
            )
            .unwrap();

        let dry = store.retention_sweep(true).unwrap();
        assert_eq!(dry.destroyed, 0);
        assert!(dry.attestation.is_none());
        assert_eq!(
            dry.policies[0].expired,
            vec![room_flip.id.clone()],
            "{dry:?}"
        );
        assert_eq!(
            dry.policies[1].expired,
            vec![wing_flip.id.clone(), kept_clean.id.clone()],
            "{dry:?}"
        );
        assert!(
            !dry.ok,
            "a dry run over drift must say so before anything is destroyed"
        );
        assert!(present(&store, &wing_flip.id) && present(&store, &room_flip.id));

        let sweep = store.retention_sweep(false).unwrap();
        assert_eq!(sweep.destroyed, 3, "{sweep:?}");
        let att = sweep
            .attestation
            .as_ref()
            .expect("a destroying sweep attests");
        let attested: Vec<&str> = att.drawers.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(
            attested,
            vec![
                room_flip.id.as_str(),
                wing_flip.id.as_str(),
                kept_clean.id.as_str()
            ]
        );
        assert!(
            !present(&store, &wing_flip.id),
            "the wing flip escaped the sweep"
        );
        assert!(
            !present(&store, &room_flip.id),
            "the room flip escaped the sweep"
        );
        assert!(!present(&store, &kept_clean.id));
        assert!(present(&store, &other.id));
        // The drift is in the report, because the vault no longer holds it.
        assert_eq!(sweep.mirror_drift.len(), 2, "{sweep:?}");
        assert!(sweep.mirror_drift[0].starts_with(&wing_flip.id));
        assert!(sweep.mirror_drift[0].contains("column wing=\"elsewhere\""));
        assert!(sweep.mirror_drift[1].starts_with(&room_flip.id));
        assert!(sweep.mirror_drift[1].contains("column room=\"other\""));
        assert!(!sweep.ok);
        assert!(sweep.unverifiable.is_empty() && sweep.withheld.is_empty());
        // Nothing drifted is left, so `verify` is green, and the next sweep
        // is clean.
        assert!(store.verify().unwrap().ok());
        let again = store.retention_sweep(false).unwrap();
        assert!(again.ok && again.destroyed == 0, "{again:?}");
    }

    /// A row the walk cannot verify is named wherever it sits and destroyed
    /// nowhere, and every row the sweep could decide is still destroyed.
    /// Two shapes: a zeroed tag in a wing no policy covers — which today's
    /// sweep never looked at — and a DOUBLE flip, the clear `wing` and the
    /// covered `meta_json` both moved out of the scope, which breaks the tag
    /// and leaves no copy that places the row anywhere authentic. A list
    /// scoped by either copy would miss both.
    #[test]
    fn a_row_the_sweep_cannot_verify_is_named_from_anywhere_and_the_rest_is_swept() {
        let (_d, mut store) = sealed_store();
        let a = old("w1", "r", "an old note that expires", 0);
        let double = old("w1", "r", "an old note flipped in both copies", 1);
        let elsewhere = old("unrelated", "r", "an old note in a wing with no policy", 2);
        for d in [&a, &double, &elsewhere] {
            store.upsert(d).unwrap();
        }
        store.set_retention("w1", None, 30).unwrap();
        store
            .conn
            .execute(
                "UPDATE drawers SET tag = zeroblob(32) WHERE id = ?1",
                [&elsewhere.id],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE drawers SET wing = 'gone', \
                 meta_json = replace(meta_json, '\"wing\":\"w1\"', '\"wing\":\"gone\"') \
                 WHERE id = ?1",
                [&double.id],
            )
            .unwrap();
        let sweep = store.retention_sweep(false).unwrap();
        assert_eq!(sweep.destroyed, 1, "{sweep:?}");
        assert!(!present(&store, &a.id));
        let named: Vec<&str> = sweep.unverifiable.iter().map(|u| u.id.as_str()).collect();
        assert_eq!(named, vec![double.id.as_str(), elsewhere.id.as_str()]);
        assert!(sweep.unverifiable[0].reason.contains("does not verify"));
        assert!(present(&store, &double.id) && present(&store, &elsewhere.id));
        assert!(!sweep.ok);
        // `verify` names the same two rows.
        let report = store.verify().unwrap();
        assert_eq!(report.bad_records.len(), 2, "{report:?}");
    }

    /// A drawer its covered copy files under a policy, whose clear `wing`
    /// was flipped INTO the review queue. The walk makes it a member; the
    /// pending-evidence fence reads the clear column and refuses it, and
    /// handed to `forget_with_proof` it would refuse the WHOLE sweep. So it
    /// is withheld and named with the exit that works, the rest is swept,
    /// and after `drawer update` re-saves its own content the mirror is
    /// healed, its covered `filed_at` is unchanged, and the next sweep
    /// destroys it.
    #[test]
    fn a_member_flipped_into_the_review_queue_is_withheld_and_the_rest_is_swept() {
        let (_d, mut store) = sealed_store();
        let flipped = old("w1", "r", "an old note parked in the review queue", 0);
        let clean = old("w1", "r", "an old note that expires", 1);
        for d in [&flipped, &clean] {
            store.upsert(d).unwrap();
        }
        store.set_retention("w1", None, 30).unwrap();
        store
            .conn
            .execute(
                "UPDATE drawers SET wing = ?1 WHERE id = ?2",
                [crate::admission::QUARANTINE_WING, flipped.id.as_str()],
            )
            .unwrap();
        // PREMISE: the fence refuses this row on the destruction path.
        assert!(store.is_quarantine_pending(&flipped.id).unwrap());
        assert!(store
            .forget_with_proof(std::slice::from_ref(&flipped.id))
            .is_err());

        let sweep = store.retention_sweep(false).unwrap();
        assert_eq!(sweep.destroyed, 1, "{sweep:?}");
        assert!(!present(&store, &clean.id));
        assert!(present(&store, &flipped.id));
        assert_eq!(sweep.withheld.len(), 1, "{sweep:?}");
        let w = &sweep.withheld[0];
        assert_eq!(
            (w.id.as_str(), w.wing.as_str()),
            (flipped.id.as_str(), "w1")
        );
        assert!(w.reason.contains("drawer update"), "{}", w.reason);
        assert!(!sweep.policies[0].expired.contains(&flipped.id));
        assert!(sweep.mirror_drift[0].starts_with(&flipped.id));
        assert!(!sweep.ok);

        // The exit the reason names.
        let outcome = store
            .update_drawer(&flipped.id, &flipped.content, "cli")
            .unwrap();
        assert!(
            matches!(outcome, crate::manage::UpdateOutcome::Updated),
            "{outcome:?}"
        );
        assert!(!store.is_quarantine_pending(&flipped.id).unwrap());
        let healed = store
            .get(&flipped.id, Read::Internal(InternalRead::Verification))
            .unwrap()
            .unwrap();
        assert_eq!(healed.meta.filed_at, "2020-01-01T00:00:00Z");
        let again = store.retention_sweep(false).unwrap();
        assert_eq!(again.destroyed, 1, "{again:?}");
        assert!(again.ok, "{again:?}");
        assert!(!present(&store, &flipped.id));
    }

    /// A member whose covered `filed_at` does not parse cannot be dated. The
    /// write path refuses such a value, so the row is a legacy one, built
    /// here with a tag the vault's own key recomputes. It FAILED the whole
    /// sweep; now it is withheld and named, and the rest is swept.
    #[test]
    fn a_member_that_cannot_be_dated_is_withheld_and_the_rest_is_swept() {
        let (_d, mut store) = sealed_store();
        let legacy = old("w1", "r", "a legacy note with a broken clock", 0);
        let clean = old("w1", "r", "an old note that expires", 1);
        for d in [&legacy, &clean] {
            store.upsert(d).unwrap();
        }
        store.set_retention("w1", None, 30).unwrap();
        let (meta, content): (String, Vec<u8>) = store
            .conn
            .query_row(
                "SELECT meta_json, content FROM drawers WHERE id = ?1",
                [&legacy.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let meta = meta.replace("2020-01-01T00:00:00Z", "last spring");
        assert!(
            meta.contains("last spring"),
            "PREMISE: the clock was rewritten"
        );
        let tag = store
            .vault
            .tag(&crate::canonical(&legacy.id, meta.as_bytes(), &content));
        store
            .conn
            .execute(
                "UPDATE drawers SET meta_json = ?1, tag = ?2 WHERE id = ?3",
                rusqlite::params![meta, tag.as_slice(), legacy.id],
            )
            .unwrap();
        assert!(
            store.verify().unwrap().bad_records.is_empty(),
            "PREMISE: it verifies"
        );

        let sweep = store.retention_sweep(false).unwrap();
        assert_eq!(sweep.destroyed, 1, "{sweep:?}");
        assert!(!present(&store, &clean.id));
        assert!(present(&store, &legacy.id));
        assert_eq!(sweep.withheld.len(), 1);
        assert_eq!(sweep.withheld[0].id, legacy.id);
        assert!(sweep.withheld[0].reason.contains("cannot be dated"));
        assert!(!sweep.ok);
    }

    /// A policy row deleted offline is a scope nothing enforces any more.
    /// The sweep read only the rows present and answered clean beside it;
    /// it reads the retention half of `verify`'s policy leg now. A clear is
    /// the legitimate absence and stays clean.
    #[test]
    fn a_policy_row_deleted_offline_is_named_by_the_sweep() {
        let (_d, mut store) = sealed_store();
        store.upsert(&old("w1", "r", "an old note", 0)).unwrap();
        store.set_retention("w1", None, 30).unwrap();
        store.set_retention("w2", None, 30).unwrap();
        store.clear_retention("w2", None).unwrap();
        let clean = store.retention_sweep(true).unwrap();
        assert!(clean.ok && clean.policy_drift.is_empty(), "{clean:?}");
        store
            .conn
            .execute("DELETE FROM retention_policy WHERE wing = 'w1'", [])
            .unwrap();
        let sweep = store.retention_sweep(false).unwrap();
        assert!(sweep.policies.is_empty());
        assert_eq!(sweep.destroyed, 0);
        assert_eq!(
            sweep.policy_drift,
            vec!["retention/w1: declared in the chain, row is gone".to_string()]
        );
        assert!(!sweep.ok);
        // The same line `verify` reports.
        assert!(store
            .verify()
            .unwrap()
            .policy_drift
            .contains(&sweep.policy_drift[0]));
    }

    /// **ROADMAP O239: a planted `rotate/` label no longer lifts the
    /// boundary.**
    ///
    /// Measured before the fix, on O230's own replay attack: one statement —
    /// `UPDATE audit SET record_id='rotate/deadbeefdeadbeef' WHERE
    /// seq=(SELECT MAX(seq) FROM audit)` — took `retention_policies()` from
    /// REFUSING to answering `Ok(30 days)` with `policy_drift` EMPTY, so the
    /// replayed policy governed and a sweep would have destroyed under it.
    /// The same boundary feeds O234's arm 1, so one statement disabled the
    /// newest-version comparison for every table and every key at once.
    ///
    /// Both arms are asserted, because a test that only plants the label
    /// cannot tell a working bound from a comparison that stopped working.
    #[test]
    fn a_planted_rotate_label_does_not_lift_the_policy_boundary() {
        for plant in [false, true] {
            let (_d, mut s) = sealed_store();
            s.set_retention("scratch", None, 30).unwrap();
            let old: (u32, Vec<u8>, String) = s
                .conn
                .query_row(
                    "SELECT max_age_days, tag, assigned_at FROM retention_policy \
                     WHERE wing = 'scratch'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            s.set_retention("scratch", None, 365).unwrap();

            if plant {
                // An INSERT, not a relabel. Appending a forged `rotate/` row
                // AFTER the newer declaration leaves that declaration in the
                // chain and simply puts the boundary above it, so the
                // comparison is skipped while every record the gatherer needs
                // is still there. Strictly easier than a relabel — it destroys
                // nothing — and it is the shape O230 ruling 5 pinned.
                let n = s
                    .conn
                    .execute(
                        "INSERT INTO audit (record_id, tag, at) \
                         VALUES ('rotate/deadbeefdeadbeef', X'00', '2026-01-01T00:00:00Z')",
                        [],
                    )
                    .unwrap();
                assert_eq!(n, 1, "premise: the forged rotation is appended");
                // PREMISE: the newer declaration is still on the chain, so a
                // finding here is attributable to the boundary and not to a
                // record the plant removed.
                let newest: i64 = s
                    .conn
                    .query_row(
                        "SELECT COUNT(*) FROM audit WHERE record_id = 'retention/scratch'",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(newest, 2, "premise: both declarations still recorded");
            }

            // The replay: write the older, validly tagged row back.
            s.conn
                .execute(
                    "UPDATE retention_policy SET max_age_days = ?1, tag = ?2, \
                     assigned_at = ?3 WHERE wing = 'scratch'",
                    params![old.0, old.1, old.2],
                )
                .unwrap();

            let err = s.retention_policies().unwrap_err();
            assert!(
                matches!(err, StoreError::IntegrityFinding(_)),
                "plant={plant}: the replayed policy must not govern — {err:?}"
            );
            let drift = s.verify().unwrap().policy_drift;
            assert_eq!(drift.len(), 1, "plant={plant}: {drift:?}");
            assert!(drift[0].contains("not the newest declaration"));
        }
    }

    /// **A REAL rotation still moves the boundary**, which is the half a
    /// keycheck bound could silently break: bind it to the wrong generation
    /// and every rotated vault alarms on rows the rotation legitimately
    /// re-tagged — the false alarm O94 dropped the comparison for.
    #[test]
    fn a_real_rotation_still_bounds_the_comparison() {
        let (dir, mut s) = sealed_store();
        s.set_retention("scratch", None, 30).unwrap();
        s.set_wing_trust("w", "trusted").unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        s.rotate_keys(mgr.rotation_candidate("r").unwrap()).unwrap();

        // PREMISE: the rotation wrote a record under the key the vault now
        // holds, and the boundary finds it.
        let boundary = s
            .snapshot(|snap| s.rotation_boundary(snap, LabelUse::Report))
            .unwrap();
        assert!(boundary.is_some(), "a rotation must move the boundary");
        assert!(s.verify().unwrap().ok(), "a rotated vault verifies");
        assert_eq!(s.retention_policies().unwrap().len(), 1);
        assert_eq!(s.wing_trusts().unwrap().len(), 1);

        // And a SECOND rotation moves it again — the newest generation wins,
        // so the bound is "the rotation that installed the key I hold" rather
        // than "the first rotation ever".
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        s.rotate_keys(mgr.rotation_candidate("r").unwrap()).unwrap();
        let later = s
            .snapshot(|snap| s.rotation_boundary(snap, LabelUse::Report))
            .unwrap();
        assert!(
            later > boundary,
            "{later:?} must be newer than {boundary:?}"
        );
        assert!(s.verify().unwrap().ok());
    }

    /// **A vault that never rotated answers `None`**, exactly as the range
    /// scan did — the bound can only make the boundary smaller, never
    /// manufacture one.
    #[test]
    fn an_unrotated_vault_has_no_rotation_boundary() {
        let (_d, s) = sealed_store();
        assert_eq!(
            s.snapshot(|snap| s.rotation_boundary(snap, LabelUse::Report))
                .unwrap(),
            None
        );
        // And a planted label of a FOREIGN keycheck does not manufacture one.
        s.conn
            .execute(
                "INSERT INTO audit (record_id, tag, at) \
                 VALUES ('rotate/deadbeefdeadbeef', X'00', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        assert_eq!(
            s.snapshot(|snap| s.rotation_boundary(snap, LabelUse::Report))
                .unwrap(),
            None,
            "a foreign keycheck is not this vault's rotation"
        );
    }

    /// **The rotation COUNT is a different question and keeps the range**
    /// (ROADMAP O239). Bound to the current keycheck it would answer at most
    /// one and silently undercount a vault rotated twice, which is the
    /// corroboration O13's `Recorded` verdict reads.
    #[test]
    fn the_rotation_count_spans_every_key_generation() {
        let (dir, mut s) = sealed_store();
        for _ in 0..2 {
            let mgr = VaultManager::open(dir.path(), None).unwrap();
            s.rotate_keys(mgr.rotation_candidate("r").unwrap()).unwrap();
        }
        assert_eq!(
            crate::chain::rotations_since(&s.conn, 0).unwrap(),
            2,
            "both rotations counted, across two key generations"
        );
        // The boundary, by contrast, names exactly one.
        let b = s
            .snapshot(|snap| s.rotation_boundary(snap, LabelUse::Report))
            .unwrap()
            .expect("the current key's rotation");
        assert_eq!(crate::chain::rotations_since(&s.conn, b).unwrap(), 0);
    }
}
