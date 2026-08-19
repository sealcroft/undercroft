//! Provable forgetting (C3.2 phase 1): `forget --prove` destroys named
//! drawers **through the audit chain** and emits an attestation that the
//! named content was destroyed and nothing else changed in the same
//! breath.
//!
//! **What the attestation is, honestly.** The chain step is KEYED
//! (`next = HMAC(mac_key, prev ‖ tag)`), so replaying heads requires the
//! vault key. Two verification postures follow, and both are real:
//!
//! * **vault-verifiable** — [`PalaceStore::verify_forget_attestation`]
//!   replays the recorded segment with the key in hand and checks four
//!   things: the heads chain exactly through the recorded tombstones;
//!   every record IS a tombstone for a named drawer (nothing else
//!   happened between the heads); each tombstone's tag verifies as this
//!   vault's own `del` tag; and the drawers are gone now.
//!
//!   **That posture has a lifetime, and it is shorter than the
//!   attestation's.** The key it needs is destroyed by the next key
//!   rotation, so it answers [`AttestationVerdict::Recorded`] rather than
//!   [`AttestationVerdict::Verified`] from then on — a reduced claim, read
//!   off the preserved audit trail, and NOT a tamper verdict. Read that
//!   type before changing anything here: reporting the reduced case as
//!   forged is ROADMAP O13, and it is what this module did until it was
//!   fixed.
//! * **operator-signed** — the attestation's canonical bytes carry an
//!   Ed25519 signature (the bundle signing identity), which is what a
//!   third party (the data subject, an auditor) trusts. They trust the
//!   SIGNATURE, not replay: full third-party replay would need an
//!   unkeyed public chain, a design change this unit does not smuggle
//!   in. The heads still bind the operator — a later history shown for
//!   the same interval that disagrees is two conflicting signed claims.
//!
//! What "destroyed" means here is what `delete_drawer` ships: row +
//! derived artifacts gone, keyed tombstone chained atomically. A crash
//! mid-batch leaves already-deleted drawers tombstoned and chained (the
//! append-only posture) and NO attestation — re-run to completion, then
//! attest. Retention policies and admission-deny-with-receipt build on
//! this in their own units.

use rusqlite::params;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{PalaceStore, StoreError};

/// Whether this destruction also issued a delete to a remote mirror.
///
/// A stated argument rather than a defaulted flag, on the `Screen`,
/// `Posture` and `PlaintextPush` precedent: an attestation is a signed claim
/// handed to a third party, and what it says about a mirror must be decided
/// by the caller that knows, not inferred by the function that does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorDelete {
    /// A delete was issued to the named backend.
    Issued(String),
    /// None was. Every surface that has no index handle — `retention sweep`,
    /// `admission deny`, plain `forget` — says this, and the attestation
    /// warns when the vault was ever pushed.
    NotIssued,
}

/// What this vault can say about an attestation it is handed.
///
/// **Three outcomes, because two of them were one.** The keyed replay needs
/// the MAC key that MADE the tombstones, and [`PalaceStore::rotate_keys`]
/// destroys that key — that is what a rotation IS. So after any rotation
/// every tombstone tag failed `verify_tag` and the recorded heads no longer
/// corresponded to the re-keyed chain, and a genuine attestation was reported
/// **forged**, with this CLI's tamper exit code, the first time an operator
/// did the thing the security model tells them to do routinely (ROADMAP O13).
///
/// The honest answer is a third state rather than a corrected verdict —
/// `stated`/`background`/`unevaluated` and `Unreceipted`-vs-`Dangling` are
/// the same move already made twice in this tree: "we did not look" and "we
/// looked and found nothing" are different claims and must not share a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "the two verdicts make DIFFERENT claims — treating `Recorded` as \
              `Verified` is exactly the conflation this enum exists to stop"]
pub enum AttestationVerdict {
    /// The keyed replay ran and passed: every tombstone tag verifies as this
    /// vault's own, and the recorded heads chain exactly through them.
    Verified,
    /// **The keyed replay is unavailable, and the evidence is real.**
    ///
    /// The tags do not verify under this vault's current MAC key, and this
    /// vault's own `audit` trail — which rotation preserves byte for byte —
    /// holds exactly these records, as a CONTIGUOUS run, in this order, and
    /// the named drawers are gone.
    ///
    /// What that proves: the document names evidence this vault actually
    /// recorded, and nothing else happened *between* the attested records.
    ///
    /// **What it does not prove, stated rather than implied.** (a) That the
    /// tag bytes are genuine MACs — the key that would settle it no longer
    /// exists, which is a property of rotation and not of this check. (b)
    /// The interval's ENDPOINTS: `head_before`/`head_after` are unverifiable
    /// strings on this path, so "nothing else changed" narrows to "nothing
    /// else happened between the first and last attested record".
    ///
    /// **The residual that follows from (a), named rather than left for a
    /// reader to derive.** This verdict cannot separate a preserved genuine
    /// tag from a preserved forged one, so an offline writer who inserted a
    /// tombstone-shaped `audit` row and destroyed the drawer would reach
    /// `Recorded` where the old code said forged. It is narrow and it is not
    /// unwitnessed: on an unrotated vault that row breaks the chain replay,
    /// which is `verify`'s second leg and the CLI names it in this verdict;
    /// on a rotated one the operator's own rotation re-keyed the chain over
    /// it, which no check here or anywhere else can undo. The alternative —
    /// keep calling every rotated vault's genuine receipt forged — trades a
    /// narrow ambiguity for a certain false alarm on the routine path.
    ///
    /// The third-party posture is untouched either way: `verify_detached`
    /// checks the operator's Ed25519 signature and touches no vault key, so
    /// a data subject holding the signed document verifies it across any
    /// number of rotations.
    Recorded {
        /// Key rotations this vault RECORDED after the attested interval.
        ///
        /// Corroboration only — it never decides the verdict, and `0` is not
        /// evidence of absence: a rotation before ROADMAP A19 appended no
        /// record at all, so a legacy vault legitimately reports zero. A
        /// check that read it the other way would call those vaults forged,
        /// which is the defect this whole type exists to remove.
        rotations_since: usize,
    },
}

/// One destroyed drawer, as the attestation names it: the id and the
/// **unkeyed** content fingerprint — a commitment to WHAT was destroyed that
/// survives rotation and never reveals the words.
///
/// **Deliberately the one place that stayed unkeyed when U12 keyed the two
/// stored fingerprint columns**, and it is not an oversight: this value is
/// signed and handed to a third party — the data subject, an auditor — whose
/// whole verification posture (see this module's header) is checking a
/// commitment against content they already hold, WITHOUT the vault key.
/// Keying it destroys the property the attestation exists to provide.
///
/// The two situations are opposites. `kg_triples.source_fp` sat at rest in a
/// stolen file, offering an oracle over content the vault still holds, to
/// nobody in particular. This is a deliberate disclosure, to a named party,
/// about content the vault no longer holds at all.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForgottenDrawer {
    pub id: String,
    pub content_fp: String,
}

/// One chained record inside the attested interval.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttestedRecord {
    pub record_id: String,
    pub tag: String,
    pub at: String,
}

/// The attestation `forget --prove` emits.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForgetAttestation {
    pub version: u32,
    pub vault: String,
    pub created_at: String,
    pub drawers: Vec<ForgottenDrawer>,
    pub head_before: String,
    pub head_after: String,
    pub records: Vec<AttestedRecord>,
    /// **What this destruction did NOT reach: a remote mirror.**
    ///
    /// `index push` hands the whole corpus — at-rest blobs and embeddings,
    /// and on an hmac-only vault that blob is the PLAINTEXT — to a
    /// third-party accelerator in another trust domain. `VectorIndex::delete`
    /// was declared, implemented by all five backends, and called by nothing,
    /// so a signed attestation said "destroyed" over content that was still
    /// sitting in someone's Qdrant. The `egress/index-push` record sharpens
    /// it further: the chain now explicitly says the corpus left on date X,
    /// beside an attestation claiming it is gone.
    ///
    /// So the attestation states the boundary itself rather than leaving it
    /// to a document. Present only when this vault was ever pushed; its value
    /// is what this operation DID — "delete issued to <backend>" — or that it
    /// issued none. Never a claim about the remote's own state: this process
    /// cannot verify a third party's storage, and an attestation that
    /// asserted it would be the kind of unverifiable claim the rest of this
    /// module refuses to mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl ForgetAttestation {
    /// Deterministic signing bytes: every field except the signature,
    /// `0x1f`-separated in fixed order (the manifest precedent).
    pub fn canonical(&self) -> Vec<u8> {
        let mut parts: Vec<String> = vec![
            self.version.to_string(),
            self.vault.clone(),
            self.created_at.clone(),
            self.head_before.clone(),
            self.head_after.clone(),
            self.sender.clone().unwrap_or_default(),
        ];
        for d in &self.drawers {
            parts.push(format!("{}\u{1e}{}", d.id, d.content_fp));
        }
        for r in &self.records {
            parts.push(format!("{}\u{1e}{}\u{1e}{}", r.record_id, r.tag, r.at));
        }
        // **A canonical EXTENSION, appended and only when present** — the
        // shape `authority_ext` / `extractor_ext` / `terms_ext` already use
        // on the knowledge-graph canonicals, and for the identical reason:
        // an attestation written before this field existed must produce
        // byte-identical canonical bytes, or every signature already handed
        // to a data subject or an auditor stops verifying. Adding it to the
        // fixed prefix — even as an empty string, the way `sender` is
        // handled — would have done exactly that.
        //
        // It IS signed when present, which is the point: a mirror note the
        // recipient could strip without breaking the signature would be a
        // disclosure an operator could quietly remove.
        if let Some(m) = &self.mirror {
            parts.push(format!("mirror\u{1e}{m}"));
        }
        parts.join("\u{1f}").into_bytes()
    }

    /// Sign in place with a bundle signing identity.
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
}

impl PalaceStore {
    /// Destroy the named drawers and attest it. Every id must exist —
    /// attesting the destruction of what was never there is a claim this
    /// store refuses to mint.
    ///
    /// Quarantine-pending drawers are refused here too (the delete choke
    /// point enforces it): a `forget` receipt attests destruction but says
    /// nothing about a review, so forgetting pending evidence would still
    /// leave the admission trail with a hole. `admission deny` is the door
    /// — it records the verdict and then destroys through *this* path, so
    /// the operator loses no receipt by going the long way round.
    pub fn forget_with_proof(&mut self, ids: &[String]) -> Result<ForgetAttestation, StoreError> {
        self.forget_with_proof_ruled(
            ids,
            crate::manage::PendingEvidence::Protect,
            MirrorDelete::NotIssued,
        )
    }

    /// Destroy the named drawers **and delete them from a remote mirror**,
    /// then attest both.
    ///
    /// `VectorIndex::delete` existed, was implemented by all five backends,
    /// and had zero callers — so this is the door it was written for. The
    /// remote delete goes FIRST, deliberately: if it fails, nothing local has
    /// been destroyed and the operator can retry with the vault intact. The
    /// other order leaves a signed attestation of destruction beside a
    /// third-party copy that is still there, which is the exact claim this
    /// unit exists to stop minting. A remote delete that succeeds while the
    /// local destruction then fails leaves the mirror missing rows the vault
    /// still holds — an availability cost on an untrusted accelerator, fixed
    /// by re-pushing, and the honest direction to fail in.
    pub fn forget_with_proof_mirrored(
        &mut self,
        ids: &[String],
        index: &mut dyn undercroft_index::VectorIndex,
    ) -> Result<ForgetAttestation, StoreError> {
        // **Every refusal the ruled path makes has to be made HERE too, or
        // the remote delete outruns it.** The ruled path checks existence
        // and the pending-evidence fence before it destroys anything —
        // which is worthless on this path, because by then the mirror row
        // is already gone. A quarantine-pending drawer is review evidence
        // that `forget` deliberately refuses to destroy; deleting the
        // mirror's copy and then refusing locally would let an agent whose
        // write was diverted strip half the evidence with a command that
        // reports an error. So: refuse first, delete second.
        //
        // Duplicated deliberately rather than hoisted, and it is not a
        // second implementation of the rule: the ruled path still owns the
        // decision and still enforces it, and this is a pre-flight that
        // must be a subset of it. If the two ever disagree the local walk
        // wins and nothing is destroyed — the safe direction.
        // **The empty case FIRST, before anything reaches a backend.** The
        // ruled path's first refusal is `ids.is_empty()`, and a pre-flight
        // that skipped it issued `index.delete(collection, &[])` before the
        // local refusal fired — and an empty id list is not uniformly a
        // no-op: Chroma receives `{"ids": []}` with no `where`, which is its
        // delete-EVERYTHING shape. Not reachable from the CLI (`ids` is
        // `required`), and this function is `pub`.
        if ids.is_empty() {
            return Err(StoreError::Invalid("nothing to forget".into()));
        }
        for id in ids {
            if self
                .get(id, crate::Read::Internal(crate::InternalRead::Verification))?
                .is_none()
            {
                return Err(StoreError::NotFound(id.clone()));
            }
            if self.is_quarantine_pending(id)? {
                return Err(StoreError::Invalid(format!(
                    "{id} is quarantine-pending — rule on it with `admission allow`/`deny`; \
                     pending review evidence is not deletable, on the mirror either"
                )));
            }
        }
        let collection = self.index_collection();
        let backend = index.name().to_string();
        // `ensure` FIRST, exactly as `index_push` does. It is not decoration:
        // `ChromaIndex` resolves a collection NAME to the backend's opaque id
        // inside `ensure` and caches it per process, so `delete` without it
        // returns "ensure() not called" — `undercroft forget --backend chroma`
        // was a 100% failure. The fake index in the unit tests makes `ensure`
        // a no-op and never consults it, so only a live backend can see this.
        index.ensure(&collection, self.embedder_dimension())?;
        index.delete(&collection, ids)?;
        self.forget_with_proof_ruled(
            ids,
            crate::manage::PendingEvidence::Protect,
            MirrorDelete::Issued(backend),
        )
    }

    /// `forget_with_proof` with the pending-evidence decision stated —
    /// `admission deny` is the one caller allowed to pass `Ruled`.
    pub(crate) fn forget_with_proof_ruled(
        &mut self,
        ids: &[String],
        evidence: crate::manage::PendingEvidence,
        mirror: MirrorDelete,
    ) -> Result<ForgetAttestation, StoreError> {
        if ids.is_empty() {
            return Err(StoreError::Invalid("nothing to forget".into()));
        }
        // Existence + fingerprints first, so a bad id aborts before any
        // deletion. The pending-evidence fence is checked here too, for the
        // same reason: the choke point would catch it, but only after the
        // ids before it in the list were already gone.
        let mut drawers = Vec::with_capacity(ids.len());
        for id in ids {
            let d = self
                .get(id, crate::Read::Internal(crate::InternalRead::Verification))?
                // NotFound, not Invalid: one status class for "not here"
                // across every route (cluster: write-validation).
                .ok_or_else(|| StoreError::NotFound(id.clone()))?;
            // ...and pending review evidence is not deletable through the
            // forgetting path either (cluster: ops-boundaries).
            if evidence == crate::manage::PendingEvidence::Protect
                && self.is_quarantine_pending(id)?
            {
                return Err(StoreError::Invalid(format!(
                    "{id} is quarantine-pending — rule on it with `admission allow`/`deny`; pending review evidence is not deletable"
                )));
            }
            drawers.push(ForgottenDrawer {
                id: id.clone(),
                content_fp: hex::encode(crate::kg::content_fp(&d.content)),
            });
        }
        let head_before: String = self.chain_head()?;
        let seq_before: i64 =
            self.conn
                .query_row("SELECT COALESCE(MAX(seq), 0) FROM audit", [], |r| r.get(0))?;
        for id in ids {
            self.delete_drawer_ruled(id, evidence)?;
        }
        let head_after: String = self.chain_head()?;
        let mut stmt = self
            .conn
            .prepare("SELECT record_id, tag, at FROM audit WHERE seq > ?1 ORDER BY seq")?;
        let records: Vec<AttestedRecord> = stmt
            .query_map(params![seq_before], |r| {
                Ok(AttestedRecord {
                    record_id: r.get(0)?,
                    tag: hex::encode(r.get::<_, Vec<u8>>(1)?),
                    at: r.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(ForgetAttestation {
            version: 1,
            vault: self.vault.id().to_string(),
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .expect("rfc3339 now"),
            drawers,
            head_before,
            head_after,
            records,
            // Stamped HERE, at the one function every destruction path runs
            // through — `forget`, `retention sweep` and `admission deny` all
            // land on it — rather than at a surface. A boundary that has to
            // be remembered per call site is the class of defect this tree
            // spends its time closing.
            mirror: self.mirror_note(&mirror),
            sender: None,
            sig: None,
        })
    }

    /// What to say about a remote mirror in an attestation, if anything.
    ///
    /// `None` for the overwhelming majority of vaults, which were never
    /// pushed: nothing is claimed, and the canonical is byte-identical to
    /// what every build before this one produced.
    fn mirror_note(&self, mirror: &MirrorDelete) -> Option<String> {
        // **Decided off the CHAIN, not off the `meta` row.**
        //
        // The first version asked `pushed_embedder()`, which reads an
        // untagged, unsealed `INSERT INTO meta`. One offline
        // `DELETE FROM meta WHERE key='index_pushed_embedder'` and every
        // later attestation silently drops the disclosure — and still
        // verifies, because the signature covers bytes that never contained
        // it. That is the suppress-BEFORE twin of the strip-after attack the
        // canonical extension was written to stop, three paragraphs up, and
        // the covered evidence was sitting one table over: `index_push`
        // records `egress/index-push` on the tamper-evident chain
        // unconditionally. A28's rule, on a decision this unit introduced.
        //
        // `meta` is still consulted, for the embedder NAME only — a label in
        // a warning, not the decision.
        let pushed: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM audit WHERE record_id = 'egress/index-push')",
                [],
                |r| r.get(0),
            )
            .unwrap_or(false)
            || self.pushed_embedder().is_some();
        if !pushed {
            return None;
        }
        let embedder = self
            .pushed_embedder()
            .unwrap_or_else(|| "unrecorded".to_string());
        Some(match mirror {
            MirrorDelete::Issued(backend) => format!(
                "this vault was pushed to a remote index (embedding space {embedder}); a delete \
                 for the named drawers was issued to {backend} by this operation. Whether the \
                 backend honoured it is not something this vault can verify"
            ),
            MirrorDelete::NotIssued => format!(
                "WARNING: this vault was pushed to a remote index (embedding space {embedder}) \
                 and NO delete was issued by this operation. The at-rest blob for these drawers \
                 may still exist on that third-party mirror — on an hmac-only vault that blob is \
                 the plaintext. Re-run with a backend named, or delete the collection there"
            ),
        })
    }

    /// Verify a forgetting attestation against THIS vault, with the key in
    /// hand. Errors name what failed and are the tamper verdict; the two
    /// `Ok` verdicts are documented on [`AttestationVerdict`] and make
    /// DIFFERENT claims — [`AttestationVerdict::Verified`] means the keyed
    /// replay ran and passed, [`AttestationVerdict::Recorded`] means the key
    /// that made these tombstones was destroyed by a rotation and the
    /// vault's own preserved audit trail holds them verbatim.
    pub fn verify_forget_attestation(
        &self,
        att: &ForgetAttestation,
    ) -> Result<AttestationVerdict, StoreError> {
        // A typed verdict, not a generic input error: every branch below is
        // "this document does not describe what this vault did", which the
        // CLI reports with its integrity exit code (see
        // [`StoreError::Attestation`]).
        let fail = StoreError::Attestation;
        if att.vault != self.vault.id() {
            return Err(fail(format!(
                "attests vault {:?}, this is {:?}",
                att.vault,
                self.vault.id()
            )));
        }
        // Signature first when present: a forged document should fail
        // before any flattering partial checks.
        match (att.sender.as_deref(), att.sig.as_deref()) {
            (Some(sender), Some(sig)) => {
                undercroft_vault::bundle::verify_detached(sender, &att.canonical(), sig)
                    .map_err(|e| fail(format!("signature: {e}")))?;
            }
            // **A signature with nobody to check it against is REFUSED, not
            // skipped.** [`ForgetAttestation::sign`] writes both fields, so
            // no genuine document reaches this arm — but a hand-edited one
            // does, and the `if let` this replaces simply performed no
            // verification for it while the CLI printed "sender signature
            // verified" on `sig.is_some()` alone. A claim the code had not
            // established, on the one surface whose entire third-party
            // posture IS that signature, and `sender` is the public key: a
            // document with `sender` stripped is precisely one nobody can
            // attribute. Tightening a shape `sign()` never produced is a
            // fix, not a contract change.
            (None, Some(_)) => {
                return Err(fail(
                    "carries a signature but names no sender to verify it against".into(),
                ));
            }
            // Unsigned, or a sender named with no signature. Both are
            // reported as unsigned and neither asserts provenance, so
            // neither is refused — a `sender` alone is a label, and the
            // verdict says "unsigned" about it, which is true.
            (_, None) => {}
        }
        let named: std::collections::HashSet<&str> =
            att.drawers.iter().map(|d| d.id.as_str()).collect();
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        // **The structural walk first, and it is key-independent on purpose.**
        // Every record must be a tombstone for a drawer this document names,
        // and its tag must decode. Neither claim needs a key, so both are
        // checked identically on both postures below — a rotation must not
        // buy a forger a weaker structural check.
        let mut tags: Vec<Vec<u8>> = Vec::with_capacity(att.records.len());
        for r in &att.records {
            let tag = hex::decode(&r.tag).map_err(|e| fail(format!("tag hex: {e}")))?;
            let Some(id) = r.record_id.strip_prefix("del/") else {
                return Err(fail(format!(
                    "record {:?} is not a tombstone — something else \
                     happened inside the attested interval",
                    r.record_id
                )));
            };
            if !named.contains(id) {
                return Err(fail(format!("tombstone for unnamed drawer {id}")));
            }
            seen.insert(
                att.drawers
                    .iter()
                    .find(|d| d.id == id)
                    .map(|d| d.id.as_str())
                    .expect("named checked above"),
            );
            tags.push(tag);
        }

        // Which posture can this vault take? The keyed replay needs the MAC
        // key that MADE these tombstones, and `rotate_keys` destroys it by
        // design. An attestation that spans a rotation cannot exist — one
        // `forget` is one transaction under one key — so this is all-or-
        // nothing: any tag that will not verify takes the WHOLE document to
        // the recorded-evidence path.
        //
        // Not because that path is stricter — it is not, and neither posture
        // dominates the other: the keyed one proves the tags are genuine and
        // the interval's endpoints, the recorded one proves the trail holds
        // them contiguously. It is all-or-nothing because a mixed document
        // cannot be replayed at all (the head chain needs every tag), so the
        // alternative is a per-record verdict nobody could act on, and
        // falling to the NARROWER claim is the safe direction to fall.
        let replayable = att.records.iter().zip(&tags).all(|(r, tag)| {
            let id = r.record_id.strip_prefix("del/").expect("checked above");
            self.vault
                .verify_tag(format!("del\x1f{id}").as_bytes(), tag)
                .is_ok()
        });
        let verdict = if replayable {
            let mut head = att.head_before.clone();
            for tag in &tags {
                head = self
                    .vault
                    .chain_next_hex(&head, tag)
                    .map_err(|e| fail(format!("chain step: {e}")))?;
            }
            if head != att.head_after {
                return Err(fail(
                    "heads do not chain through the recorded tombstones".into(),
                ));
            }
            AttestationVerdict::Verified
        } else {
            AttestationVerdict::Recorded {
                rotations_since: self.attested_run_in_audit(att, &tags)?,
            }
        };

        // Required by BOTH verdicts: this vault named a tombstone for every
        // drawer the document claims, and every one of them is gone NOW.
        // That second check is a live query, so it is the one part of the
        // attestation a rotation cannot weaken.
        for d in &att.drawers {
            if !seen.contains(d.id.as_str()) {
                return Err(fail(format!("no tombstone recorded for {}", d.id)));
            }
            if self
                .get(
                    &d.id,
                    crate::Read::Internal(crate::InternalRead::Verification),
                )?
                .is_some()
            {
                return Err(fail(format!("{} still exists", d.id)));
            }
        }
        Ok(verdict)
    }

    /// Locate the attested records as a **contiguous run** of this vault's
    /// own `audit` trail, and report how many key rotations it recorded
    /// afterwards. The error is the tamper verdict: a document whose
    /// tombstones this vault never wrote is forged whether or not a rotation
    /// has happened.
    ///
    /// **Contiguity is what survives of "nothing else changed".** The keyed
    /// path gets that from the head replay; here the heads are unverifiable
    /// strings, so the equivalent structural claim is that the attested
    /// records sit at consecutive `seq` values with nothing interleaved.
    /// That holds by construction — `forget_with_proof_ruled` takes
    /// `MAX(seq)` before destroying anything and selects `seq > that`
    /// afterwards, and `audit` is append-only (`AUTOINCREMENT`, and no
    /// production statement deletes from it). Without this the check would
    /// admit a document that quietly omitted a record from the middle of its
    /// own interval, which is precisely the claim it exists to support.
    ///
    /// Several rows can legitimately match one attested record: a drawer id
    /// is deterministic, so a drawer may be mined, destroyed, re-mined and
    /// destroyed again, and both tombstones carry the same `record_id` and
    /// the same tag bytes. Hence a candidate walk rather than a lookup.
    fn attested_run_in_audit(
        &self,
        att: &ForgetAttestation,
        tags: &[Vec<u8>],
    ) -> Result<usize, StoreError> {
        let fail = StoreError::Attestation;
        let n = att.records.len();
        if n == 0 {
            // Unreachable from `verify_forget_attestation` (an empty record
            // list is vacuously replayable and goes the keyed way), and
            // guarded rather than indexed blindly because the next caller
            // will not know that.
            return Ok(0);
        }
        let first = &att.records[0];
        let candidates: Vec<i64> = {
            let mut stmt = self.conn.prepare(
                "SELECT seq FROM audit WHERE record_id = ?1 AND tag = ?2 AND at = ?3 \
                 ORDER BY seq",
            )?;
            let rows = stmt
                .query_map(params![first.record_id, tags[0], first.at], |r| r.get(0))?
                .collect::<Result<Vec<i64>, _>>()?;
            rows
        };
        if candidates.is_empty() {
            let id = first
                .record_id
                .strip_prefix("del/")
                .unwrap_or(&first.record_id);
            return Err(fail(format!(
                "tombstone tag for {id} is not this vault's, and no record in \
                 this vault's audit trail holds those bytes"
            )));
        }
        for start in candidates {
            if self.audit_run_matches(start, att, tags)? {
                let end = start + n as i64 - 1;
                let rotations: i64 = self.conn.query_row(
                    "SELECT COUNT(*) FROM audit WHERE seq > ?1 AND record_id LIKE 'rotate/%'",
                    params![end],
                    |r| r.get(0),
                )?;
                return Ok(rotations as usize);
            }
        }
        // Deliberately names BOTH causes rather than the interesting one: a
        // forged tag on any record after the first lands here too, and a
        // message blaming an interleaved record for it would send an
        // operator looking for the wrong thing.
        Err(fail(
            "the attested records do not match a contiguous run of this \
             vault's audit trail — a tag this vault never wrote, or something \
             else inside the attested interval"
                .into(),
        ))
    }

    /// Do the `n` audit rows starting at `start` equal the attested records,
    /// field for field and in order? Every column is compared, `at`
    /// included: the row this vault wrote is the evidence, not a subset of
    /// it that happens to match.
    fn audit_run_matches(
        &self,
        start: i64,
        att: &ForgetAttestation,
        tags: &[Vec<u8>],
    ) -> Result<bool, StoreError> {
        let end = start + att.records.len() as i64 - 1;
        let mut stmt = self.conn.prepare(
            "SELECT record_id, tag, at FROM audit WHERE seq BETWEEN ?1 AND ?2 ORDER BY seq",
        )?;
        let rows: Vec<(String, Vec<u8>, String)> = stmt
            .query_map(params![start, end], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<Result<_, _>>()?;
        if rows.len() != att.records.len() {
            return Ok(false);
        }
        Ok(rows
            .iter()
            .zip(att.records.iter().zip(tags))
            .all(|((rid, tag, at), (r, want))| rid == &r.record_id && tag == want && at == &r.at))
    }

    fn chain_head(&self) -> Result<String, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM chain_meta WHERE key = 'head'", [], |r| {
                r.get(0)
            })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn att(mirror: Option<&str>) -> ForgetAttestation {
        ForgetAttestation {
            version: 1,
            vault: "v".into(),
            created_at: "2026-08-09T00:00:00Z".into(),
            drawers: vec![ForgottenDrawer {
                id: "abc".into(),
                content_fp: "ff".into(),
            }],
            head_before: "aa".into(),
            head_after: "bb".into(),
            records: vec![AttestedRecord {
                record_id: "del/abc".into(),
                tag: "cc".into(),
                at: "2026-08-09T00:00:00Z".into(),
            }],
            mirror: mirror.map(str::to_string),
            sender: None,
            sig: None,
        }
    }

    /// **Adding the mirror note must not invalidate a signature already in
    /// a third party's hands.**
    ///
    /// The attestation's whole third-party posture is an Ed25519 signature
    /// over `canonical()`. A field folded into the fixed prefix — even as an
    /// empty string, the way `sender` is — changes those bytes for every
    /// document ever signed, so a data subject holding last year's
    /// attestation would find it no longer verifies and have no way to tell
    /// that from a forgery. Hence a canonical EXTENSION: present only when
    /// set, appended last.
    ///
    /// Both directions. Absent must reproduce the pre-field bytes EXACTLY —
    /// spelled out here as a literal rather than derived from the code, so
    /// the gate cannot agree with a future refactor by construction — and
    /// present must change them, or the note would be strippable without
    /// breaking the signature.
    #[test]
    fn the_mirror_note_is_a_canonical_extension_and_does_not_move_old_bytes() {
        let pre_field = [
            "1",
            "v",
            "2026-08-09T00:00:00Z",
            "aa",
            "bb",
            "",
            "abc\u{1e}ff",
            "del/abc\u{1e}cc\u{1e}2026-08-09T00:00:00Z",
        ]
        .join("\u{1f}");
        assert_eq!(
            att(None).canonical(),
            pre_field.as_bytes(),
            "an attestation with no mirror note must be byte-identical to what every \
             build before the field produced — otherwise every signature already issued \
             stops verifying"
        );
        let with = att(Some("pushed to qdrant"));
        assert_ne!(
            with.canonical(),
            att(None).canonical(),
            "the note must be INSIDE the signed bytes, or an operator could strip a \
             disclosure without breaking the signature"
        );
        assert!(with
            .canonical()
            .ends_with("mirror\u{1e}pushed to qdrant".as_bytes()));
    }

    fn drawer(content: &str, idx: u32) -> undercroft_core::Drawer {
        undercroft_core::Drawer::new(
            "wing",
            "room",
            content.into(),
            Some("t.md".into()),
            idx,
            "t",
        )
    }

    /// **ROADMAP O13.** A genuine attestation reported FORGED, with this
    /// project's tamper exit code, the first time an operator rotated their
    /// keys — the thing the security model tells them to do routinely.
    ///
    /// The cause is not a bug in either component. `verify_forget_attestation`
    /// re-checks tombstone tags with `verify_tag` and replays heads with
    /// `chain_next_hex`, both under the CURRENT mac key; `rotate_keys`
    /// destroys the old key, which is what a rotation IS. So the keyed replay
    /// is genuinely unavailable afterwards and no key swap can restore it.
    /// The fix is a third verdict, and this test is the reason it cannot be
    /// two: **every arm below distinguishes a state the old code conflated.**
    ///
    /// Arms, in the order they run: the PREMISE (before any rotation the
    /// keyed replay runs and PASSES — without it `Recorded` could be what
    /// this vault answers to everything); a forgery refused before the
    /// rotation; then the three ROADMAP gate arms — the genuine document
    /// across a rotation, a tag forged AFTER it, and the third-party
    /// signature path — plus contiguity, plus the rotation count read from
    /// the trail rather than assumed.
    #[test]
    fn a_key_rotation_makes_the_replay_unavailable_never_the_attestation_forged() {
        use undercroft_vault::{SecurityLevel, VaultManager};

        let dir = tempfile::TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("r", SecurityLevel::Sealed).unwrap();
        let mut store = PalaceStore::open(vault).unwrap();

        // THREE destroyed together, so the attested interval has a middle
        // to omit, and one kept so "nothing else changed" has something to
        // be true about.
        let a = drawer("the first note the subject asked us to erase", 0);
        let b = drawer("the second note the subject asked us to erase", 1);
        let c = drawer("the third note the subject asked us to erase", 2);
        let keep = drawer("an unrelated note that must survive all of this", 3);
        for d in [&a, &b, &c, &keep] {
            store.upsert(d).unwrap();
        }
        let mut att = store
            .forget_with_proof(&[a.id.clone(), b.id.clone(), c.id.clone()])
            .unwrap();
        let (secret, _) = undercroft_vault::bundle::sign_keygen();
        att.sign(&secret).unwrap();
        assert_eq!(att.records.len(), 3, "premise: three tombstones attested");

        // PREMISE. Before any rotation this is the keyed verdict.
        assert_eq!(
            store.verify_forget_attestation(&att).unwrap(),
            AttestationVerdict::Verified,
            "premise: an unrotated vault replays its own attestation"
        );

        // A document that quietly omits a record from the MIDDLE of its own
        // interval — "we destroyed a and c and nothing else happened", while
        // b was destroyed between them. Re-signed, so what refuses it is the
        // claim and not a stale signature. Refused on the keyed path today
        // (the heads cannot chain); the arm after the rotation is what
        // proves the fallback did not quietly drop the interval claim.
        let mut dropped = att.clone();
        dropped.records.remove(1);
        dropped.drawers.remove(1);
        dropped.sign(&secret).unwrap();
        assert!(
            matches!(
                store.verify_forget_attestation(&dropped),
                Err(StoreError::Attestation(_))
            ),
            "premise: an omitted record is refused BEFORE the rotation too"
        );

        // ---- the rotation the security model asks for ----
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let candidate = mgr.rotation_candidate("r").unwrap();
        store.rotate_keys(candidate).unwrap();

        // ARM 1 — the whole point. Not forged, not an error, and therefore
        // not exit 2.
        assert_eq!(
            store.verify_forget_attestation(&att).unwrap(),
            AttestationVerdict::Recorded { rotations_since: 1 },
            "a genuine attestation across a key rotation must report the \
             replay unavailable, NEVER forged"
        );

        // ARM 2 — a tag forged after the rotation is still the tamper
        // verdict. Re-signed for the same reason as above: unsigned, this
        // would fail on the signature and the arm would pass without ever
        // reaching the check it exists to exercise.
        let mut forged = att.clone();
        forged.records[0].tag = "00".repeat(32);
        forged.sign(&secret).unwrap();
        match store.verify_forget_attestation(&forged) {
            Err(StoreError::Attestation(why)) => assert!(
                why.contains("no record in this vault's audit trail"),
                "a forged tag must be refused for being absent from the \
                 trail, not incidentally: {why}"
            ),
            other => panic!("a tag forged after a rotation must fail: {other:?}"),
        }

        // ARM 3 — the third-party posture is untouched. `verify_detached`
        // takes no vault key, so a data subject holding the signed document
        // verifies it across any number of rotations. This is the boundary
        // that makes O13 a false alarm rather than a lost proof.
        undercroft_vault::bundle::verify_detached(
            att.sender.as_deref().expect("signed above"),
            &att.canonical(),
            att.sig.as_deref().expect("signed above"),
        )
        .expect("the operator's signature must verify across a rotation");

        // ARM 4 — contiguity. The heads are unverifiable strings on this
        // path, so the interval claim rests on the attested records being a
        // contiguous run of the trail. Without this the fallback would admit
        // the omission the pre-rotation arm above refuses.
        match store.verify_forget_attestation(&dropped) {
            Err(StoreError::Attestation(why)) => assert!(
                why.contains("contiguous"),
                "an omitted record must be refused for breaking the run: {why}"
            ),
            other => panic!("an omitted record must fail after rotation too: {other:?}"),
        }

        // The count is READ from the trail, not assumed. A second rotation
        // moves it; a hard-coded 1 would survive arm 1 and die here.
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let candidate = mgr.rotation_candidate("r").unwrap();
        store.rotate_keys(candidate).unwrap();
        assert_eq!(
            store.verify_forget_attestation(&att).unwrap(),
            AttestationVerdict::Recorded { rotations_since: 2 },
            "the rotation count comes from the vault's own audit trail"
        );

        // And the live half a rotation cannot weaken: the named drawers are
        // still gone and the unrelated one is still here.
        assert!(store
            .get(
                &a.id,
                crate::Read::Internal(crate::InternalRead::Verification)
            )
            .unwrap()
            .is_none());
        assert!(store
            .get(
                &keep.id,
                crate::Read::Internal(crate::InternalRead::Verification)
            )
            .unwrap()
            .is_some());
        assert!(store.verify().unwrap().ok(), "the chain stays green");
    }

    /// **A signature with nobody to check it against is REFUSED, not
    /// skipped** — and this is the arm that used to pass silently.
    ///
    /// [`ForgetAttestation::sign`] writes `sender` and `sig` together, so a
    /// genuine document carries both. Verification, though, ran only when
    /// both were present, and `Command::VerifyForgetting` printed
    /// "sender signature verified" on `sig.is_some()` ALONE. `sender` is the
    /// public key the signature is checked against, so a document with it
    /// stripped is attributable to nobody — and the one surface whose entire
    /// third-party posture is that signature said it was verified.
    ///
    /// COUNTERFACTUAL, run: with the `if let (Some(..), Some(..))` this
    /// replaced, arm 2 returns `Ok(Verified)` for a document nothing
    /// authenticated, and the CLI prints the sentence over it.
    #[test]
    fn a_signature_with_no_sender_is_refused_rather_than_silently_unchecked() {
        use undercroft_vault::{SecurityLevel, VaultManager};

        let dir = tempfile::TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("s", SecurityLevel::Sealed).unwrap();
        let mut store = PalaceStore::open(vault).unwrap();

        let gone = drawer("a note the subject asked us to erase", 0);
        let keep = drawer("an unrelated note that must survive", 1);
        for d in [&gone, &keep] {
            store.upsert(d).unwrap();
        }
        let mut att = store
            .forget_with_proof(std::slice::from_ref(&gone.id))
            .unwrap();
        let (secret, _) = undercroft_vault::bundle::sign_keygen();
        att.sign(&secret).unwrap();

        // ARM 1 — PREMISE. Signed and complete, this verifies; without it
        // the refusal below could be any other defect in the document.
        assert!(
            att.sender.is_some() && att.sig.is_some(),
            "premise: sign() writes BOTH fields, which is what makes the \
             stripped shape detectable at all"
        );
        assert_eq!(
            store.verify_forget_attestation(&att).unwrap(),
            AttestationVerdict::Verified,
            "premise: the intact signed document verifies"
        );

        // ARM 2 — the defect. `sig` kept, `sender` stripped: nothing can
        // check it, so claiming it was checked is the lie.
        let mut stripped = att.clone();
        stripped.sender = None;
        match store.verify_forget_attestation(&stripped) {
            Err(StoreError::Attestation(why)) => assert!(
                why.contains("names no sender"),
                "must be refused FOR that reason, not incidentally: {why}"
            ),
            other => panic!(
                "a signature with no sender must be refused, not skipped: \
                 {other:?}"
            ),
        }

        // ARM 3 — the other direction is NOT an error, and saying so keeps
        // the refusal narrow. A `sender` with no signature asserts nothing
        // cryptographically and is reported as unsigned, which is true.
        let mut unsigned = att.clone();
        unsigned.sig = None;
        assert_eq!(
            store.verify_forget_attestation(&unsigned).unwrap(),
            AttestationVerdict::Verified,
            "a sender named without a signature is unsigned, not forged"
        );

        // ARM 4 — and a wholly unsigned document still verifies, so the new
        // arm has not made signing mandatory by accident.
        let mut bare = att.clone();
        bare.sender = None;
        bare.sig = None;
        assert_eq!(
            store.verify_forget_attestation(&bare).unwrap(),
            AttestationVerdict::Verified,
            "an unsigned attestation is still a valid vault-verifiable one"
        );
        assert!(store
            .get(
                &keep.id,
                crate::Read::Internal(crate::InternalRead::Verification)
            )
            .unwrap()
            .is_some());
    }
}
