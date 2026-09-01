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
//! sweep therefore hydrates and tag-verifies every drawer in scope
//! before dating it — an operator-command price, paid on purpose. A
//! drawer whose covered `filed_at` fails to parse is a corrupt row and
//! FAILS the sweep loudly; a sweep must never destroy what it cannot
//! date, and must never skip it silently either.

use rusqlite::params;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::admission::QUARANTINE_WING;
use crate::forget::ForgetAttestation;
use crate::{chain_append, Namespace, PalaceStore, StoreError};

/// One declared policy, as listed back to the operator.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionPolicy {
    pub wing: String,
    /// Empty = the whole wing.
    pub room: String,
    pub max_age_days: u32,
    pub assigned_at: String,
}

/// One policy's share of a sweep.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionSweepEntry {
    pub wing: String,
    pub room: String,
    pub max_age_days: u32,
    /// Drawer ids past the policy's age at sweep time.
    pub expired: Vec<String>,
}

/// What a sweep did (or, dry, would do).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionSweep {
    pub dry_run: bool,
    pub policies: Vec<RetentionSweepEntry>,
    /// Distinct drawers destroyed (a wing policy and a room policy can
    /// name the same drawer; it dies once).
    pub destroyed: usize,
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

impl PalaceStore {
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
        let (head, writes) =
            chain_append(&tx, &self.vault, Namespace::Retention, &rest, &tag, &now)?;
        tx.commit()?;
        self.vault.anchor_manifest(&head, writes)?;
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
                let (head, writes) = chain_append(
                    &tx,
                    &self.vault,
                    Namespace::RetentionClear,
                    &rest,
                    &tag,
                    &now,
                )?;
                tx.commit()?;
                self.vault.anchor_manifest(&head, writes)?;
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
    /// different lifespan.
    pub fn retention_policies(&self) -> Result<Vec<RetentionPolicy>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT wing, room, max_age_days, tag, assigned_at
             FROM retention_policy ORDER BY wing, room",
        )?;
        let rows: Vec<(String, String, u32, Vec<u8>, String)> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (wing, room, days, tag, at) in rows {
            self.vault
                .verify_tag(
                    retention_canonical(&wing, &room, days, &at).as_slice(),
                    &tag,
                )
                .map_err(|_| StoreError::Integrity(format!("retention/{wing}/{room}")))?;
            out.push(RetentionPolicy {
                wing,
                room,
                max_age_days: days,
                assigned_at: at,
            });
        }
        Ok(out)
    }

    /// Run (or preview) a sweep: every declared policy contributes the
    /// drawers older than its age, the distinct set is destroyed through
    /// [`PalaceStore::forget_with_proof`], and the attestation is the
    /// receipt. Dry runs and empty sweeps destroy nothing and attest
    /// nothing.
    pub fn retention_sweep(&mut self, dry_run: bool) -> Result<RetentionSweep, StoreError> {
        let now = OffsetDateTime::now_utc();
        let policies = self.retention_policies()?;
        let mut entries = Vec::with_capacity(policies.len());
        let mut distinct: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for p in policies {
            let cutoff = now - Duration::days(i64::from(p.max_age_days));
            let expired = self.expired_in(&p.wing, &p.room, cutoff)?;
            for id in &expired {
                if seen.insert(id.clone()) {
                    distinct.push(id.clone());
                }
            }
            entries.push(RetentionSweepEntry {
                wing: p.wing,
                room: p.room,
                max_age_days: p.max_age_days,
                expired,
            });
        }
        let attestation = if dry_run || distinct.is_empty() {
            None
        } else {
            Some(self.forget_with_proof(&distinct)?)
        };
        Ok(RetentionSweep {
            dry_run,
            policies: entries,
            destroyed: if dry_run { 0 } else { distinct.len() },
            attestation,
        })
    }

    /// Drawer ids in scope whose **tag-verified** `meta.filed_at` is
    /// strictly before `cutoff`, oldest first. Ids come from the scope
    /// columns, but every dating decision reads the hydrated drawer —
    /// [`PalaceStore::get`] verifies the record HMAC — so a clear-text
    /// column flip can neither accelerate nor evade a sweep (module
    /// header). An unparseable covered `filed_at` fails the sweep: a
    /// sweep must neither destroy what it cannot date nor skip it
    /// silently.
    fn expired_in(
        &self,
        wing: &str,
        room: &str,
        cutoff: OffsetDateTime,
    ) -> Result<Vec<String>, StoreError> {
        let (sql, binds): (&str, Vec<&str>) = if room.is_empty() {
            (
                "SELECT id FROM drawers WHERE wing = ?1 ORDER BY seq",
                vec![wing],
            )
        } else {
            (
                "SELECT id FROM drawers WHERE wing = ?1 AND room = ?2 ORDER BY seq",
                vec![wing, room],
            )
        };
        let mut stmt = self.conn.prepare(sql)?;
        let ids: Vec<String> = stmt
            .query_map(rusqlite::params_from_iter(binds), |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::new();
        for id in ids {
            let Some(d) = self.get(
                &id,
                crate::Read::Internal(crate::InternalRead::Verification),
            )?
            else {
                continue;
            };
            let filed_at = &d.meta.filed_at;
            let filed =
                OffsetDateTime::parse(filed_at, &Rfc3339).map_err(|e| StoreError::CorruptRow {
                    id: id.clone(),
                    reason: format!("covered filed_at {filed_at:?} is not RFC3339: {e}"),
                })?;
            if filed < cutoff {
                out.push(id);
            }
        }
        Ok(out)
    }
}
