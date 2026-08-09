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
            if self.get(id)?.is_none() {
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
                .get(id)?
                // NotFound, not Invalid: one status class for "not here"
                // across every route (cluster: write-validation).
                .ok_or_else(|| StoreError::NotFound(id.clone()))?;
            // ...and pending review evidence is not deletable through the
            // forgetting path either (cluster: ops-boundaries).
            if evidence == crate::manage::PendingEvidence::Protect
                && self.is_quarantine_pending(id)?
            {
                return Err(StoreError::Invalid(format!(
                    "{id} is quarantine-pending — rule on it with `admission                      allow`/`deny`; pending review evidence is not deletable"
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

    /// Verify a forgetting attestation against THIS vault, with the key
    /// in hand. Errors name what failed; `Ok(())` means: the heads chain
    /// exactly through the recorded tombstones, every record is a `del`
    /// tombstone for a named drawer with this vault's own tag, nothing
    /// else happened in the interval, and the drawers are gone.
    pub fn verify_forget_attestation(&self, att: &ForgetAttestation) -> Result<(), StoreError> {
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
        if let (Some(sender), Some(sig)) = (att.sender.as_deref(), att.sig.as_deref()) {
            undercroft_vault::bundle::verify_detached(sender, &att.canonical(), sig)
                .map_err(|e| fail(format!("signature: {e}")))?;
        }
        let named: std::collections::HashSet<&str> =
            att.drawers.iter().map(|d| d.id.as_str()).collect();
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut head = att.head_before.clone();
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
            self.vault
                .verify_tag(format!("del\x1f{id}").as_bytes(), &tag)
                .map_err(|_| fail(format!("tombstone tag for {id} is not this vault's")))?;
            seen.insert(
                att.drawers
                    .iter()
                    .find(|d| d.id == id)
                    .map(|d| d.id.as_str())
                    .expect("named checked above"),
            );
            head = self
                .vault
                .chain_next_hex(&head, &tag)
                .map_err(|e| fail(format!("chain step: {e}")))?;
        }
        if head != att.head_after {
            return Err(fail(
                "heads do not chain through the recorded tombstones".into(),
            ));
        }
        for d in &att.drawers {
            if !seen.contains(d.id.as_str()) {
                return Err(fail(format!("no tombstone recorded for {}", d.id)));
            }
            if self.get(&d.id)?.is_some() {
                return Err(fail(format!("{} still exists", d.id)));
            }
        }
        Ok(())
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
}
