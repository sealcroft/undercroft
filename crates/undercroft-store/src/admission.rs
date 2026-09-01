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

use crate::{chain_append, Namespace, PalaceStore, StoreError};

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

/// The destination a write DECLARES, through the one path-traversal guard.
///
/// It exists because the order was wrong (ROADMAP O30). `write_drawer_stmts`
/// validates `meta.wing`/`meta.room` at the write choke point, which is where
/// CLAUDE.md puts it so no write path can forget — but the admission screen
/// runs BEFORE that, and the screen is the step that **rewrites the fields
/// validation reads**: [`PalaceStore::admission_divert`] moves the declared
/// wing into `intended_wing` and writes the reserved constant into
/// `meta.wing`. So a write declaring an invalid wing was not refused at the
/// door; it was screened, and if the content tripped the detector it was
/// DIVERTED — after which the choke point validated the reserved constant,
/// which is always valid, and the row landed in the review queue carrying an
/// invalid declaration nothing had ever checked.
///
/// Both write paths had it: `write_drawer` screens at the choke point,
/// `upsert_many` screens in its own batch loop because it owns its
/// transaction. Validating here — inside the shared screening step, in front
/// of the rewrite — is one implementation for both, and is the reason this
/// is not two call sites.
pub(crate) fn validate_declaration(meta: &undercroft_core::DrawerMeta) -> Result<(), StoreError> {
    undercroft_core::validate_name(&meta.wing, "wing")
        .map_err(|e| StoreError::Invalid(e.to_string()))?;
    undercroft_core::validate_name(&meta.room, "room")
        .map_err(|e| StoreError::Invalid(e.to_string()))?;
    Ok(())
}

/// Every agent-writable field that another agent reads back verbatim, and
/// which is therefore screened. **One inventory, spanning tables** — the
/// `(owner, field)` key is what lets it, and what lets the both-directions
/// gate dispatch to the right call site.
///
/// It was `KG_SCREENED_FIELDS` and it was scoped to the graph (O17). A field
/// in another table was outside the question it asked, so `tunnels.label`
/// went unscreened for as long as it existed: written by an agent through
/// `undercroft_create_tunnel`, read back verbatim by another through
/// `undercroft_list_tunnels` and `undercroft_follow_tunnel` (ROADMAP O29).
/// A second list would have been a second thing to forget; keying by owner
/// keeps it one.
///
/// The rule for adding a row: a field belongs here when an AGENT can write
/// it and an AGENT can read it back. Not "when it is content" — that is the
/// judgement that scoped O17's own screen to `object` and left `subject` and
/// `predicate` open.
///
/// Why each `fact` row is here, carried over from the inventory this
/// replaces: `kg_query_entity` returns `Triple` and `serde` serializes it
/// WHOLE, so every field reaches a later session verbatim, and `subject` /
/// `predicate` were guarded only by `validate_name`. `canonical_key` and
/// `extractor` are import-only — they arrive off the wire from another
/// vault, are serialized straight back by `kg_query`, and have no author
/// this vault ever screened. `entity` / `entity_type` belong to
/// `kg_import_entity`, which screened nothing at all. `tunnel`/`label` is
/// the same argument one table over.
///
/// Gated by `a_flagged_string_in_any_screened_field_is_refused`, which is
/// table-driven over this list and dispatches on the owner — so a row added
/// here without a call site screening it fails the build's tests rather than
/// passing quietly.
pub(crate) const SCREENED_FIELDS: &[(&str, &str)] = &[
    ("fact", "subject"),
    ("fact", "predicate"),
    ("fact", "object"),
    ("fact", "canonical_key"),
    ("fact", "extractor"),
    ("fact", "entity"),
    ("fact", "entity_type"),
    ("tunnel", "label"),
];

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

    /// The screen-and-divert step, in the ONE place every caller reaches it.
    ///
    /// `write_drawer` calls it in front of its transaction; `upsert_many`
    /// calls it inside its batch loop, because a batch owns its transaction
    /// and so cannot route through the choke point at all; and `dedup`'s
    /// **dry run** calls it to preview whether the survivor would divert,
    /// which is a read (`&self`) rather than a write. That third caller is
    /// named here because this comment said "both write paths" and there
    /// were three call sites — the compiler found it when this function
    /// became fallible, and a doc comment that undercounts its own callers
    /// is the same class of artifact as a heading that is wrong.
    ///
    /// Until 2026-08-05
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
    ) -> Result<Option<Drawer>, StoreError> {
        match screen {
            // A bypass is a decision already made somewhere a reviewer can
            // grep for; the reason it carries is that justification.
            //
            // It does NOT re-validate, and that is deliberate rather than an
            // omission. `AlreadyDiverted` carries this function's own output,
            // whose declaration was validated one frame up on the `Apply`
            // arm; `OperatorRuling` carries what [`Self::admission_allow`]
            // restored, which that function validates itself and with a far
            // better message — it is the one caller that knows the value came
            // out of a queue row rather than off a request. Validating a
            // second time here would only replace that message with a worse
            // one, and the write choke point is still behind both.
            crate::Screen::Bypass(_) => Ok(None),
            // The declaration is validated HERE, in front of the rewrite,
            // because this arm is the rewrite: `admission_divert` moves
            // `meta.wing` into `intended_wing` and puts the reserved constant
            // in its place, so everything downstream validates a system value
            // and the caller's own declaration is never seen again. That is
            // ROADMAP O30, and it compounded — the row landed in the review
            // queue and `admission_allow` was then refused on the way back
            // out, so it could be denied but never allowed.
            crate::Screen::Apply => {
                validate_declaration(&drawer.meta)?;
                Ok(self.admission_divert(drawer))
            }
        }
    }

    /// Screen agent-written text that another agent reads back verbatim,
    /// against [`SCREENED_FIELDS`]. A flagged value is **REFUSED** and the
    /// refusal names which field tripped.
    ///
    /// Refused rather than diverted, and that is the decision rather than an
    /// omission: a diversion needs somewhere to divert TO. A drawer has the
    /// reserved wing, `admission list` and the allow/deny rulings; neither a
    /// fact nor a tunnel has any of it, and inventing a state nothing reads
    /// and no surface reviews would be a silent drop wearing a queue's
    /// clothes. So the write fails loudly and leaves the caller the verbatim
    /// route: file the text as a drawer, where a flagged write IS quarantined
    /// for a reviewer. `Invalid`, not `CorruptRow` — caller input owes a 400.
    ///
    /// Tier 2 deliberately does not reach here, for the reason O17 recorded:
    /// with no queue to push toward, an advisory opinion would become the
    /// sole reason a write hard-fails.
    ///
    /// `owner` is the inventory key AND the noun in the message, so the two
    /// cannot drift into disagreeing about what has no queue.
    pub(crate) fn screen_agent_text(
        &self,
        locator: &str,
        owner: &str,
        fields: &[(&str, &str)],
    ) -> Result<(), StoreError> {
        // **The inventory is checked in BOTH directions, and this is the half
        // a test cannot do.** The table-driven gate proves every row in
        // `SCREENED_FIELDS` is screened somewhere; this proves the reverse — a
        // call site cannot invent an (owner, field) pair absent from the
        // inventory, which is how a new agent-readable column would otherwise
        // get screened without ever being listed as covered. `debug_assert`
        // because it is a programming error, not caller input: the names are
        // literals in this crate.
        debug_assert!(
            fields
                .iter()
                .all(|(name, _)| SCREENED_FIELDS.contains(&(owner, name))),
            "a screen call names a field outside SCREENED_FIELDS: {owner}/{:?}",
            fields.iter().map(|(n, _)| *n).collect::<Vec<_>>()
        );
        if !self.admission_quarantine {
            return Ok(());
        }
        for (name, value) in fields {
            let signals = undercroft_core::admission::screen(value);
            if signals.is_empty() {
                continue;
            }
            let codes: Vec<&str> = signals.iter().map(|s| s.code.as_str()).collect();
            return Err(StoreError::Invalid(format!(
                "{locator}: the {name} trips the admission screen ({}) and a \
                 {owner} has no review queue to divert it to — file the text as \
                 a drawer, where a flagged write is quarantined for review",
                codes.join(", ")
            )));
        }
        Ok(())
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
        // The DECLARED DESTINATION, screened beside the content (ROADMAP
        // O32). A wing name is agent-chosen and another agent reads it back
        // through `taxonomy`, the closet index, `list_wings` and — for a
        // diary — `list_agents`, which resolves `wing = agent-{agent}`. Both
        // existing guards fired on that path and neither saw it:
        // `validate_name` admits any 128-byte string free of control
        // characters and path separators, and this screen had only ever been
        // pointed at `drawer.content`. Measured before the fix: clean content
        // into a poisoned wing was accepted and the string reached all three
        // read surfaces.
        //
        // DIVERTED, not refused, and this is where the graph and the tunnel
        // precedent stops applying. Those refuse because a fact and a tunnel
        // have nowhere to divert TO. A drawer has the reserved wing,
        // `admission list` and the rulings — so the write is kept, the wing
        // is never created (the row lands in the reserved wing instead, so
        // nothing adds the poisoned name to the taxonomy), and the name
        // survives on `intended_wing`, which only the operator's review queue
        // shows. Refusing would discard a legitimate drawer over its label
        // and break the contract that a flagged write is never lost.
        //
        // It lives HERE rather than in `validate_declaration` — which is what
        // this unit's own filing predicted — because that function is called
        // from the door AND from the write choke point, and at the choke
        // point a diverted row's wing is already the reserved constant, so
        // screening there would screen a value the store chose. This function
        // is door-only by construction, which makes the split the filing
        // worried about unnecessary rather than solved.
        if self.destination_flagged(drawer) {
            signals.push(undercroft_core::admission::AdmissionSignal {
                code: undercroft_core::admission::DESTINATION_ANOMALY_CODE.to_string(),
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
        // The wing the write was AIMED at, captured BEFORE any mutation and
        // held in a local. Deliberately not read back out of
        // `d.meta.intended_wing` with a fallback: a future reordering of the
        // mutations below would then quietly fall back to the reserved
        // constant and restore the collision with every test still green.
        let origin_wing = drawer.meta.wing.clone();
        let mut d = drawer.clone();
        d.meta.intended_wing = Some(d.meta.wing.clone());
        d.meta.intended_room = Some(d.meta.room.clone());
        d.meta.admission_signals = signals;
        d.meta.wing = QUARANTINE_WING.to_string();
        let source = d.meta.source_file.as_deref().unwrap_or("(direct)");
        // Keyed on the ORIGIN wing, in its own id space. Passing
        // `QUARANTINE_WING` here substituted a constant for one of the four
        // components the recipe is injective over, so two diversions
        // differing only in wing became one row.
        d.id = undercroft_core::ids::quarantine_drawer_id(
            &origin_wing,
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

    /// Does the caller's declared destination trip the tier-1 screen?
    ///
    /// The wing and the room, separately — a signal in either is a signal,
    /// and screening the two CONCATENATED would let a marker split across the
    /// boundary read as one string that neither field contains.
    ///
    /// `&self` and no history: unlike the rate screen this is a pure function
    /// of the candidate's own metadata, so it costs two `screen` calls over
    /// at most 256 bytes, and runs only when screening is declared — the
    /// caller has already returned for an unscreened vault.
    fn destination_flagged(&self, drawer: &Drawer) -> bool {
        !undercroft_core::admission::screen(&drawer.meta.wing).is_empty()
            || !undercroft_core::admission::screen(&drawer.meta.room).is_empty()
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
            let Some(d) = self.get(&id, crate::Read::Internal(crate::InternalRead::BulkMember))?
            else {
                continue;
            };
            out.push(PendingAdmission {
                id: d.id.clone(),
                intended_wing: d.meta.intended_wing.clone().unwrap_or_default(),
                intended_room: d.meta.intended_room.clone().unwrap_or_default(),
                signals: d.meta.admission_signals.clone(),
                filed_at: d.meta.filed_at.clone(),
            });
        }
        // ROADMAP O50: one record for this door, through the one recording
        // door — `record_read` owns the "does this get written" decision.
        self.record_read(
            crate::Read::Returned(crate::ReadOp::AdmissionList),
            "",
            crate::ReadScope::none(),
            out.len(),
        )?;
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
        // Non-empty was the ONLY check, and it is not the check the restore
        // needs: `write_drawer_stmts` validates what it is handed, so a row
        // whose intended destination is invalid was refused there — with a
        // message naming neither the field, nor the row, nor the fact that
        // the value came out of the queue rather than off this request. The
        // operator saw a generic write error and the row stayed pending.
        // It could be DENIED, i.e. destroyed, and never allowed.
        //
        // The ordering fix above means no new row reaches the queue this
        // way. This arm is what a row written by an older binary meets, and
        // it is the half worth having on its own (ROADMAP O30): it turns a
        // permanent trap into a refusal that says what to do about it.
        for (what, value) in [
            ("intended wing", wing.as_str()),
            ("intended room", room.as_str()),
        ] {
            undercroft_core::validate_name(value, what).map_err(|e| {
                StoreError::Invalid(format!(
                    "{id} cannot be allowed: {e}. Its destination was recorded \
                     before the screen validated one, so re-filing it as \
                     declared is refused — read the drawer back naming the \
                     {QUARANTINE_WING} wing, save it to a valid destination, \
                     then deny this row"
                ))
            })?;
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
        self.forget_with_proof_ruled(
            &[id.to_string()],
            crate::manage::PendingEvidence::Ruled,
            crate::forget::MirrorDelete::NotIssued,
        )
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
            .get(id, crate::Read::Internal(crate::InternalRead::PolicyFence))?
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
            Namespace::Admission,
            &format!("{id}/{verdict}"),
            &tag,
            &now,
        )?;
        tx.commit()?;
        self.vault.anchor_manifest(&head, writes)?;
        Ok(())
    }
}
