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

use rusqlite::params;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use undercroft_core::Drawer;

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

/// What one just-written drawer means on the live event feed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SaveEvent<'a> {
    /// Filed where it was headed.
    Saved,
    /// The admission screen diverted it. Carries where it was HEADED
    /// (it is in [`QUARANTINE_WING`] now) and the tier-1 signal codes —
    /// a closed vocabulary, so they are metadata a live feed may carry;
    /// the offsets beside them are not published.
    Quarantined {
        intended_wing: &'a str,
        codes: Vec<&'a str>,
    },
}

/// Did this row land in the review queue?
///
/// The one predicate [`save_event`] keys on, named so the write choke point
/// can ask it without restating the comparison. Two copies of "is this
/// quarantined" that can drift is the shape this module spends its time
/// removing.
pub(crate) fn landed_in_quarantine(drawer: &Drawer) -> bool {
    drawer.meta.wing == QUARANTINE_WING
}

/// Classify a written drawer by WHERE IT LANDED, not by which call site
/// wrote it.
///
/// Exact rather than heuristic: the single write choke point refuses
/// [`QUARANTINE_WING`] to any drawer without admission signals, so a row
/// in that wing was put there by the screen. Deciding this per call site
/// is what produced the split the monitor showed — the single-save paths
/// returned before emitting anything (silence for MCP, `/v1` and CLI
/// `remember`), while the bulk paths emitted an ordinary `drawer-saved`
/// whose only tell was a wing named `quarantine-pending`.
pub(crate) fn save_event(drawer: &Drawer) -> SaveEvent<'_> {
    if !landed_in_quarantine(drawer) {
        return SaveEvent::Saved;
    }
    SaveEvent::Quarantined {
        // A diverted drawer always records where it was going; fall back
        // to the wing itself rather than inventing a destination.
        intended_wing: drawer
            .meta
            .intended_wing
            .as_deref()
            .unwrap_or(&drawer.meta.wing),
        codes: drawer
            .meta
            .admission_signals
            .iter()
            .map(|s| s.code.as_str())
            .collect(),
    }
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

    /// Declare the per-writer rate screen programmatically (the env
    /// `UNDERCROFT_ADMISSION_RATE` resolved at open is the deployment's
    /// way). `Some((count, seconds))`: at least `count` committed writes
    /// by the same writer identity inside the trailing window diverts
    /// the next one.
    pub fn set_admission_rate(&mut self, rate: Option<(u32, u32)>) {
        self.admission_rate = rate;
    }

    /// Wire the optional tier-2 advisor (the binary's job, like the
    /// reranker — `UNDERCROFT_ADMISSION_LLM=advisory` resolves to this).
    /// Consulted only when screening is on, only for candidates the
    /// deterministic tier passed, only toward quarantine.
    pub fn set_admission_advisor(
        &mut self,
        advisor: Option<Box<dyn undercroft_core::admission::AdmissionAdvisor + Send + Sync>>,
    ) {
        self.admission_advisor = advisor;
    }

    /// The screen-and-divert step, in the ONE place both write paths call.
    ///
    /// `write_drawer` calls it in front of its transaction; `upsert_many`
    /// calls it inside its batch loop, because a batch owns its transaction
    /// and so cannot route through the choke point at all. Until 2026-08-05
    /// those were two implementations of one security decision — the shape
    /// every drift in the surface audit had — and they did not even guard on
    /// the same condition: the choke point tested the required [`Screen`]
    /// argument while the bulk path tested `admission_quarantine` directly,
    /// so the argument that exists to force a caller to decide never reached
    /// the bulk path at all. Now both state a `Screen` and one function
    /// reads it.
    ///
    /// [`Self::admission_divert`] is private to this module and has exactly
    /// one caller — enforced by Rust's own visibility and pinned by
    /// `admission_divert_has_exactly_one_caller`, so a third write path
    /// cannot grow a third copy of the decision.
    ///
    /// [`Screen`]: crate::Screen
    pub(crate) fn screen_and_divert(
        &self,
        drawer: &Drawer,
        screen: crate::Screen,
    ) -> Option<Drawer> {
        match screen {
            // A bypass is a decision already made somewhere a reviewer can
            // grep for; the reason it carries is that justification.
            crate::Screen::Bypass(_) => None,
            crate::Screen::Apply => self.admission_divert(drawer),
        }
    }

    /// Screen one candidate drawer; `Some(diverted)` when it must land in
    /// quarantine instead of where it was headed. The diverted drawer
    /// keeps the verbatim content (sealed like any other), records the
    /// signal codes + offsets and the intended destination, and derives
    /// its id in the quarantine wing — deterministic, so a crashed and
    /// retried save converges on one row.
    ///
    /// **Private to this module on purpose** (R5): reachable only through
    /// [`Self::screen_and_divert`], so the screening decision exists once
    /// and a new write path cannot re-implement it the way the bulk path
    /// once did.
    fn admission_divert(&self, drawer: &Drawer) -> Option<Drawer> {
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
        let mut signals = undercroft_core::admission::screen(&drawer.content);
        // The declared rate screen (the tier-1 signal candidate bytes
        // cannot carry): checked beside the content screen, so a
        // reviewer sees both kinds of evidence when both fired.
        if self.rate_flagged(drawer) {
            signals.push(undercroft_core::admission::AdmissionSignal {
                code: undercroft_core::admission::RATE_ANOMALY_CODE.to_string(),
                offset: 0,
            });
        }
        if signals.is_empty() {
            // Tier 2, advisory-only (C3.3): a wired model may push a
            // candidate the deterministic tier passed toward quarantine —
            // never the other way around (a tier-1-flagged candidate is
            // never shown to the model, so talking the classifier into
            // "clean" bypasses nothing), and a failed or unparseable
            // answer is a non-event, never a blocked write.
            match self.admission_advisor.as_ref()?.assess(&drawer.content) {
                Some(true) => signals.push(undercroft_core::admission::AdmissionSignal {
                    code: undercroft_core::admission::LLM_ADVISORY_CODE.to_string(),
                    offset: 0,
                }),
                Some(false) | None => return None,
            }
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

    /// Whether the declared rate screen flags this write: the writer
    /// identity already has ≥ `count` COMMITTED rows filed inside the
    /// trailing window. Identity is the `agent` claim when the write
    /// carries one (the accident bound: a runaway agent loops with its
    /// own claim attached — the same grouping as the training-draw cap),
    /// else the surface-stamped `added_by` among claim-less rows — so a
    /// claim-less flood through one surface is still bounded, and the
    /// two groupings never mix (a claim is not a surface).
    ///
    /// Honest boundaries, stated rather than hidden:
    /// * the clock is the CLEAR `filed_at` column, not the HMAC-covered
    ///   `meta.filed_at` retention uses — a rate screen diverts
    ///   (recoverable, reviewed), never destroys, so it sits with the
    ///   other clear columns that shape candidate behavior while every
    ///   integrity claim rides the HMAC;
    /// * an `agent` claim is the writer's own statement — a deliberate
    ///   attacker rotates claims to evade the per-claim bound, exactly
    ///   as documented for the training-draw cap; the surface grouping
    ///   is the floor under that;
    /// * rows land only at commit, so one bulk `upsert_many` batch is
    ///   screened against the history BEFORE the batch — the burst the
    ///   screen bounds is repeated committed writes, which is the shape
    ///   a runaway agent actually has (trusted surfaces bypass the
    ///   screen entirely for deliberate bulk ingest);
    /// * timestamps compare lexicographically (one writer, one format);
    ///   at the window's edge sub-second fractions can slip a row by
    ///   under a second — noise at any declarable window.
    fn rate_flagged(&self, drawer: &Drawer) -> bool {
        let Some((count, secs)) = self.admission_rate else {
            return false;
        };
        let cutoff = (OffsetDateTime::now_utc() - time::Duration::seconds(i64::from(secs)))
            .format(&Rfc3339)
            .expect("rfc3339 cutoff");
        let counted: Result<i64, _> = if let Some(agent) = &drawer.meta.agent {
            self.conn.query_row(
                "SELECT COUNT(*) FROM drawers WHERE filed_at >= ?1 \
                 AND json_extract(meta_json, '$.agent') = ?2",
                params![cutoff, agent],
                |r| r.get(0),
            )
        } else {
            self.conn.query_row(
                "SELECT COUNT(*) FROM drawers WHERE filed_at >= ?1 \
                 AND json_extract(meta_json, '$.agent') IS NULL \
                 AND json_extract(meta_json, '$.added_by') = ?2",
                params![cutoff, &drawer.meta.added_by],
                |r| r.get(0),
            )
        };
        match counted {
            Ok(n) => n >= i64::from(count),
            Err(e) => {
                // A screen must never fail a write; a rate query that
                // cannot run degrades to not-flagged, loudly.
                undercroft_obs::diag_warn!("admission rate query failed ({e}); write not screened");
                false
            }
        }
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
        // The human ruling IS the override — stated, not implied.
        self.write_drawer(
            &restored,
            embedding,
            crate::Screen::Bypass(crate::BypassReason::OperatorRuling),
        )?;
        self.admission_ruling(id, "allowed", Some(&restored_id))?;
        // `Ruled`: the verdict is already in the chain one line above, which
        // is exactly what the plain delete path refuses to proceed without.
        self.delete_drawer_ruled(id, crate::manage::PendingEvidence::Ruled)?;
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
        // `Ruled`: the deny verdict is committed; the attested destruction
        // is the effect of a ruling, not an ordinary forget.
        self.forget_with_proof_ruled(&[id.to_string()], crate::manage::PendingEvidence::Ruled)
    }

    /// Append a ruling record without acting on it — the crash-window
    /// tests' way of reproducing "the ruling committed, the effect did
    /// not", which is exactly the partial state a crash mid-deny leaves.
    #[cfg(test)]
    pub(crate) fn admission_ruling_for_test(
        &mut self,
        id: &str,
        verdict: &str,
    ) -> Result<(), StoreError> {
        self.admission_ruling(id, verdict, None)
    }

    /// Fetch + verify a drawer and require it to be quarantine-resident.
    fn quarantined(&self, id: &str) -> Result<Drawer, StoreError> {
        let d = self
            .get(id)?
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
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
