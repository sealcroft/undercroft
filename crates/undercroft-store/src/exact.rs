//! **ROADMAP O406 item 8: the exact legs** — what `verify` can see of a
//! field boundary moved, or a tag moved between tables, by a writer without
//! the key.
//!
//! A row tag proves a run of bytes, never where each field in it ends, and
//! until the version-2 row canonical every tag in the tree joined its fields
//! with a separator and no lengths, under one key and no table domain. So a
//! re-partition of a row's own bytes, or another table's row carrying them,
//! verifies. A tag check cannot see that by construction; these legs read
//! what a moved boundary DOES move:
//!
//! * **(a) fact identity** — a fact's id is a digest over its subject,
//!   predicate, object and `valid_from`, and is its canonical's first field,
//!   so every move a reader can construct changes something the id covers.
//!   In `kg.rs` ([`crate::kg::fact_id_holds`]), the one decision `verify`
//!   and the fact read doors take.
//! * **(b) shapes** — fields whose every write has one shape: a drawer id is
//!   32 lowercase hex, a receipt's citation and a supersession's target are
//!   drawer ids, an entity's `created_at` is RFC 3339, a `canonical_key`
//!   passes `validate_name`, a fact's dates and extractor hold no control
//!   byte, and an hmac-only vault seals no graph words.
//! * **(c) cross-table identity** — a drawer whose id is a fact's or an
//!   entity's, or a fact whose id is an entity's. All three are 128-bit
//!   digests, so a collision between legitimate rows is not a case; and the
//!   drawer→fact transplant (P15i) is the one that SERVES: an hmac-only
//!   fact's subject is a word an agent chose, a `DrawerMeta` JSON parses,
//!   and the forged drawer was returned by `get` and `recent` under `VERIFY
//!   OK`, with no audit record of its write (measured, `transplant_tests`).
//! * **(d)** a sealed fact or entity field that does not open under its own
//!   AAD goes through ROADMAP O269's arm, `BadReason::Undecodable`.
//!
//! **None of them blocks a rotation** (O232's criterion: a rotation that
//! keeps the framing leaves each exactly as detectable) and **every one
//! withholds the version-2 walk**, which would bind the moved partition.

use std::collections::HashSet;

use crate::chain::Snapshot;
use crate::{is_drawer_id, text_of, BadRecord, StoreError, VaultStore};

/// What the graph walk found: the records it could not take, and the exact
/// legs' findings over the ones it could.
pub(crate) struct KgVerdict {
    /// `bad_records` entries: a failed tag, an undecodable column, a sealed
    /// field that does not open (O406 item 8(d)).
    pub(crate) bad: Vec<BadRecord>,
    /// Item 8(a): facts whose id their decoded words do not derive.
    pub(crate) identity: Vec<String>,
    /// Item 8(b), over the graph's rows.
    pub(crate) shapes: Vec<String>,
}

impl VaultStore {
    /// Item 8(b) over `drawers`: an id that is not 32 lowercase hex, and a
    /// receipted supersession whose target is not a drawer id. Rows a walk
    /// already named (`named`) are left to that finding.
    pub(crate) fn drawer_shapes_in(
        &self,
        snap: &Snapshot<'_>,
        named: &HashSet<String>,
    ) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        let mut stmt = snap
            .conn()
            .prepare("SELECT id, supersedes, supersedes_receipt FROM drawers ORDER BY seq")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            // An id that does not decode is O269's finding, by `seq`.
            let Some(id) = text_of(&r.get_ref(0)?) else {
                continue;
            };
            if named.contains(id) {
                continue;
            }
            if !is_drawer_id(id) {
                out.push(format!(
                    "{id}: the drawer's id is not a derived drawer id (32 lowercase hex), which \
                     every write of a drawer produces"
                ));
            }
            let receipted = !matches!(r.get_ref(2)?, rusqlite::types::ValueRef::Null);
            if receipted && !text_of(&r.get_ref(1)?).is_some_and(is_drawer_id) {
                out.push(format!(
                    "{id}: column supersedes, which its receipt binds, is not a drawer id"
                ));
            }
        }
        Ok(out)
    }

    /// Item 8(c): one id in two tables. Indexed on both sides of every join
    /// (`drawers.id` and `kg_triples.id` are UNIQUE, `kg_entities.id` the
    /// PRIMARY KEY).
    pub(crate) fn cross_table_ids_in(
        &self,
        snap: &Snapshot<'_>,
    ) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        for (sql, what) in [
            (
                "SELECT d.id FROM drawers d JOIN kg_triples t ON t.id = d.id ORDER BY d.id",
                "a drawer and a fact",
            ),
            (
                "SELECT d.id FROM drawers d JOIN kg_entities e ON e.id = d.id ORDER BY d.id",
                "a drawer and an entity",
            ),
            (
                "SELECT t.id FROM kg_triples t JOIN kg_entities e ON e.id = t.id ORDER BY t.id",
                "a fact and an entity",
            ),
        ] {
            let mut stmt = snap.conn().prepare(sql)?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let id = match text_of(&r.get_ref(0)?) {
                    Some(id) => id.to_string(),
                    None => continue,
                };
                out.push(format!(
                    "{id}: one id names {what} — ids are 128-bit digests no two legitimate \
                     rows share, so one of them carries the other's bytes and tag"
                ));
            }
        }
        Ok(out)
    }
}
