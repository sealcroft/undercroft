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

/// One destroyed drawer, as the attestation names it: the id and the
/// unkeyed content fingerprint (the kg `source_fp` precedent — a
/// commitment to WHAT was destroyed that survives rotation and never
/// reveals the words).
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
        self.forget_with_proof_ruled(ids, crate::manage::PendingEvidence::Protect)
    }

    /// `forget_with_proof` with the pending-evidence decision stated —
    /// `admission deny` is the one caller allowed to pass `Ruled`.
    pub(crate) fn forget_with_proof_ruled(
        &mut self,
        ids: &[String],
        evidence: crate::manage::PendingEvidence,
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
            sender: None,
            sig: None,
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
