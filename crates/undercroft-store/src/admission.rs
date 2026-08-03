//! Write-path admission control (C3.3 phase 2): screen memory at ingest,
//! quarantine what trips the deterministic tier-1 detector, and keep the
//! whole lifecycle chain-audited. See `undercroft_core::admission` for the
//! detector and its honest boundaries, and THREAT_MODEL.md §8 for the
//! design this implements.
//!
//! **Default OFF** (`UNDERCROFT_ADMISSION=quarantine` opts in): admission
//! changes what a save DOES, and a behavior change on the write contract
//! ships as the deployment's declaration, never as a surprise. When on:
//!
//! * a flagged save is DIVERTED — re-filed sealed into the reserved
//!   [`QUARANTINE_WING`] with its signal codes and intended destination
//!   in metadata (codes and offsets only; nothing content-derived) —
//!   never rejected and never silently dropped;
//! * quarantined drawers are excluded from every search that does not
//!   explicitly scope to the quarantine wing (the reviewer's own view),
//!   enforced through the same pre-candidate machinery as the trust
//!   floor, so a quarantined drawer can neither answer nor crowd;
//! * `admission allow` re-files the drawer where it was headed and
//!   removes the quarantined copy; `admission deny` deletes it (keyed
//!   tombstone). Both append a DECISION record to the audit chain with
//!   the verdict inside the tag's canonical, so the review trail is as
//!   tamper-evident as the data. A crash between the two steps of an
//!   allow leaves both copies present and the pending entry intact —
//!   re-running the allow converges (same deterministic ids), the
//!   append-only crash posture everywhere else in this store.

use undercroft_core::Drawer;
use rusqlite::params;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{chain_append, PalaceStore, StoreError};

/// The reserved wing flagged writes land in. Reserved by convention and
/// guarded at the save surfaces: a caller cannot aim a save here
/// directly, so presence in this wing always means "the screen put it
/// here and no one has ruled yet".
pub const QUARANTINE_WING: &str = "quarantine-pending";

/// One pending admission review.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingAdmission {
    pub id: String,
    pub intended_wing: String,
    pub intended_room: String,
    pub signals: Vec<undercroft_core::admission::AdmissionSignal>,
    pub filed_at: String,
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("rfc3339 now")
}

impl PalaceStore {
    /// Whether admission screening diverts flagged writes on this store.
    pub fn admission_on(&self) -> bool {
        self.admission_quarantine
    }

    /// Turn admission screening on or off programmatically (the env
    /// `UNDERCROFT_ADMISSION` resolved at open is the deployment's way).
    pub fn set_admission(&mut self, on: bool) {
        self.admission_quarantine = on;
    }

    /// Declare the trusted-surface posture programmatically (the env
    /// `UNDERCROFT_ADMIT_TRUSTED_SOURCES` resolved at open is the
    /// deployment's way).
    pub fn set_admit_trusted_sources(&mut self, sources: Vec<String>) {
        self.admit_trusted_sources = sources;
    }

    /// Screen one candidate drawer; `Some(diverted)` when it must land in
    /// quarantine instead of where it was headed. The diverted drawer
    /// keeps the verbatim content (sealed like any other), records the
    /// signal codes + offsets and the intended destination, and derives
    /// its id in the quarantine wing — deterministic, so a crashed and
    /// retried save converges on one row.
    pub(crate) fn admission_divert(&self, drawer: &Drawer) -> Option<Drawer> {
        if !self.admission_quarantine {
            return None;
        }
        // Never re-screen what is already quarantined (the allow path
        // re-files through the normal save, and screening the reviewer's
        // own decision would trap drawers forever).
        if drawer.meta.wing == QUARANTINE_WING {
            return None;
        }
        // The provenance-driven posture: writes from a deployment-trusted
        // SURFACE auto-admit. Keyed on `added_by`, which handlers stamp
        // and a caller cannot set — keying on the writer-declared
        // `channel` claim would let poison admit itself by declaration.
        if self
            .admit_trusted_sources
            .iter()
            .any(|s| s == &drawer.meta.added_by)
        {
            return None;
        }
        let signals = undercroft_core::admission::screen(&drawer.content);
        if signals.is_empty() {
            return None;
        }
        let mut d = drawer.clone();
        d.meta.intended_wing = Some(d.meta.wing.clone());
        d.meta.intended_room = Some(d.meta.room.clone());
        d.meta.admission_signals = signals;
        d.meta.wing = QUARANTINE_WING.to_string();
        let source = d.meta.source_file.as_deref().unwrap_or("(direct)");
        d.id = undercroft_core::ids::drawer_id(
            QUARANTINE_WING,
            &d.meta.room,
            source,
            d.meta.chunk_index,
        );
        Some(d)
    }

    /// Every drawer awaiting an admission ruling, oldest first.
    pub fn admission_pending(&self) -> Result<Vec<PendingAdmission>, StoreError> {
        let ids: Vec<String> = self
            .conn
            .prepare("SELECT id FROM drawers WHERE wing = ?1 ORDER BY seq")?
            .query_map(params![QUARANTINE_WING], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(d) = self.get(&id)? else { continue };
            out.push(PendingAdmission {
                id: d.id.clone(),
                intended_wing: d.meta.intended_wing.clone().unwrap_or_default(),
                intended_room: d.meta.intended_room.clone().unwrap_or_default(),
                signals: d.meta.admission_signals.clone(),
                filed_at: d.meta.filed_at.clone(),
            });
        }
        Ok(out)
    }

    /// Allow a quarantined drawer: re-file it where it was headed (the
    /// signals and intended-destination metadata come off — the ruling is
    /// in the chain, not on the record), then remove the quarantined
    /// copy. Returns the re-filed drawer's id.
    pub fn admission_allow(&mut self, id: &str) -> Result<String, StoreError> {
        let d = self.quarantined(id)?;
        let wing = d.meta.intended_wing.clone().unwrap_or_default();
        let room = d.meta.intended_room.clone().unwrap_or_default();
        if wing.is_empty() || room.is_empty() {
            return Err(StoreError::Invalid(format!(
                "{id} carries no intended destination — not a quarantined drawer"
            )));
        }
        let mut restored = d.clone();
        restored.meta.wing = wing.clone();
        restored.meta.room = room;
        restored.meta.intended_wing = None;
        restored.meta.intended_room = None;
        restored.meta.admission_signals = Vec::new();
        let source = restored.meta.source_file.as_deref().unwrap_or("(direct)");
        restored.id = undercroft_core::ids::drawer_id(
            &restored.meta.wing,
            &restored.meta.room,
            source,
            restored.meta.chunk_index,
        );
        let restored_id = restored.id.clone();
        // Straight to the write path, NOT through `upsert`: the content
        // still trips the screen (that is why it was here), and the
        // human ruling IS the override — re-screening would trap every
        // allowed drawer forever.
        let embedding = self.embedder.embed(&restored.content);
        self.write_drawer(&restored, embedding)?;
        self.admission_ruling(id, "allowed", Some(&restored_id))?;
        self.delete_drawer(id)?;
        Ok(restored_id)
    }

    /// Deny a quarantined drawer: the ruling is recorded, then the content
    /// is destroyed **through the attested-forgetting path** (C3.2), so a
    /// deny hands back the same chain-attested receipt as a `forget` —
    /// the ruling record sits just before the attested interval, and the
    /// interval holds exactly this drawer's tombstone. What remains
    /// afterwards is the audit trail — signals, ruling, tombstone, and a
    /// verifiable attestation — and no content.
    pub fn admission_deny(
        &mut self,
        id: &str,
    ) -> Result<crate::forget::ForgetAttestation, StoreError> {
        // Verifies it exists and is actually quarantined before ruling.
        self.quarantined(id)?;
        self.admission_ruling(id, "denied", None)?;
        self.forget_with_proof(&[id.to_string()])
    }

    /// Fetch + verify a drawer and require it to be quarantine-resident.
    fn quarantined(&self, id: &str) -> Result<Drawer, StoreError> {
        let d = self
            .get(id)?
            .ok_or_else(|| StoreError::Invalid(format!("no drawer {id}")))?;
        if d.meta.wing != QUARANTINE_WING {
            return Err(StoreError::Invalid(format!(
                "{id} is not in the quarantine wing"
            )));
        }
        Ok(d)
    }

    /// One chain-audited ruling record. The verdict (and the re-filed id,
    /// when allowing) is inside the tag's canonical, so a review trail
    /// cannot be rewritten offline without failing the chain.
    fn admission_ruling(
        &mut self,
        id: &str,
        verdict: &str,
        restored_id: Option<&str>,
    ) -> Result<(), StoreError> {
        let now = now_rfc3339();
        let canonical = format!(
            "admission\x1f{id}\x1f{verdict}\x1f{}\x1f{now}",
            restored_id.unwrap_or("")
        );
        let tag = self.vault.tag(canonical.as_bytes());
        let tx = self.conn.transaction()?;
        let (head, writes) = chain_append(
            &tx,
            &self.vault,
            &format!("admission/{id}/{verdict}"),
            &tag,
            &now,
        )?;
        tx.commit()?;
        self.vault.anchor_manifest(&head, writes)?;
        Ok(())
    }
}
