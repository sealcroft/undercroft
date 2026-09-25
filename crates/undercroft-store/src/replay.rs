//! **An older version of a row, written back offline** (ROADMAP O234).
//!
//! Every table whose rows carry an HMAC tag appends that tag to the audit
//! chain when the row is written: a drawer write records the drawer id, a
//! fact records `kg/{id}` (and `kg/{id}/authority` for an authority change),
//! an entity records `kg-entity/{id}`, a tunnel records `tunnel/{id}`. The
//! row's tag is then recomputed IN PLACE on every later write, and until this
//! module no leg compared the two. So a row copied out of the file and
//! written back later carried a tag the vault's key still recomputes, over a
//! record id that still exists — and `verify` answered OK.
//!
//! Measured on `d938e62`, through the CLI: after `drawer update` corrected
//! "the account number is 1111" to "… 2222 (corrected)", the earlier row's
//! `meta_json`, `content`, `embedding` and `tag` written back with sqlite3
//! read "1111" again, with `hmac failures: 0`, `audit chain: ok`, `VERIFY
//! OK`. The same restores an ended or demoted canonical fact, and a drawer
//! `forget` destroyed, written back, is served again beside its own
//! tombstone.
//!
//! **This is O230's policy comparison, extended to the tables that hold the
//! corpus** — the same question ([`crate::chain::newest_record`] answers it
//! for both), with the boundaries the panel settled:
//!
//! * **Arm 1** — the row's key has a newer record than the row's tag, above
//!   `max(the last rotation, the chain switch)`. The rotation bound is
//!   O230's: a rotation re-tags every row and records nothing per row, so
//!   below it the chain simply cannot carry the current tag. The SWITCH
//!   bound is O234's own, and it is what the entry's filing missed — the
//!   rotations from `cc0e1c7` to `55af8d1` re-tagged drawers, facts and
//!   entities with NO `rotate/` record at all, so a bound on `rotate/` alone
//!   false-alarms on every vault those binaries rotated. Only a vault whose
//!   chain has switched (ROADMAP O233) has a seq above which every rotation
//!   is recorded, so this arm runs there and nowhere else.
//! * **Arm 2** — the row's tag IS in the chain, and not in the newest record.
//!   Unbounded, and it is what finds a replay made before the upgrade, which
//!   arm 1 structurally cannot see. It cannot false-alarm on a rotation or on
//!   A10's blinding walk, because a tag either of those produced appears in
//!   no record at all.
//! * **Arm 3** — the row is present although a DESTRUCTION record for it is
//!   newer than any write of it. Which records destroy is
//!   [`Namespace::is_destruction`], exhaustive, rather than a
//!   `strip_prefix("del/")` here: O205 has a second destruction namespace
//!   filed, and a check that spells the prefix inline would simply not see
//!   it. Destroy-then-re-mine is ordinary and records a write above the
//!   tombstone, so it is not a finding.
//!
//! Findings fail `verify` and join [`crate::VerifyReport::rotation_blockers`]
//! — a rotation recomputes every tag from the row's current columns, so it
//! would turn the replayed version into the authentic one and take the
//! evidence with it (ROADMAP O232's criterion).
//!
//! **What this does not see**, stated rather than implied: a replay made
//! before a rotation, whose re-tag leaves the restored content carrying a tag
//! no record holds. O232 refuses to rotate over a standing finding, so the
//! window is a vault rotated by a binary older than that fix — the same
//! residual O230 records one table over.

use crate::chain::{self, ChainRecord, LabelUse};
use crate::manage::Namespace;
use crate::{StoreError, VaultStore};

/// One table whose rows carry a tag the audit chain records.
///
/// A table, not a trait: the four differ only in how a row's labels are
/// spelled and in which arms can apply to them, and stating that as data
/// keeps the decision below a pure function of one row's evidence.
struct Tagged {
    /// The table and its id column (`id` on all four).
    table: &'static str,
    /// What a finding calls a row of it.
    noun: &'static str,
    /// The labels a WRITE of one row appends: a namespace and a suffix, with
    /// the row's id between them.
    writes: &'static [(Namespace, &'static str)],
    /// What sits between a destruction namespace's prefix and the row's id —
    /// `None` where no path destroys such a row, which turns arm 3 off.
    ///
    /// It is not uniform: a drawer's tombstone is `del/{id}` and a tunnel's
    /// `del/tunnel/{id}`, so the infix is what keeps one drawer's tombstone
    /// from ever being read as a tunnel's.
    destruction_infix: Option<&'static str>,
    /// Whether a row of this table is ever rewritten in place. A tunnel is
    /// not — `create_tunnel` inserts or does nothing — so arms 1 and 2 have
    /// nothing to compare there and only arm 3 applies.
    versioned: bool,
}

/// How many consulted ids one refusal statement names. Under the 999-variable
/// limit an older SQLite is compiled with, not the 32,766 this one reports:
/// the bound that matters is the smallest a build may carry.
const REFUSAL_BATCH: usize = 900;

/// The four tables, and the one place the set is stated.
const TAGGED: &[Tagged] = &[
    Tagged {
        table: "drawers",
        noun: "drawer",
        // The one bare namespace: a drawer's record id is the drawer id.
        writes: &[(Namespace::Drawer, "")],
        destruction_infix: Some(""),
        versioned: true,
    },
    Tagged {
        table: "kg_triples",
        noun: "fact",
        // A fact's tag moves on an ordinary write, on a validity window
        // closing and on an authority change — and the last records itself
        // under a DIFFERENT label, so the newest record is the newest across
        // both or the check reads an authority promotion as a replay.
        writes: &[(Namespace::Kg, ""), (Namespace::Kg, "/authority")],
        // Nothing in this crate deletes from `kg_triples`: invalidation
        // closes a validity window, it does not remove the row.
        destruction_infix: None,
        versioned: true,
    },
    Tagged {
        table: "kg_entities",
        noun: "entity",
        writes: &[(Namespace::KgEntity, "")],
        // As above for `kg_entities`.
        destruction_infix: None,
        versioned: true,
    },
    Tagged {
        table: "tunnels",
        noun: "tunnel",
        writes: &[(Namespace::Tunnel, "")],
        destruction_infix: Some("tunnel/"),
        versioned: false,
    },
];

/// What the chain holds about one row, gathered before the decision.
pub(crate) struct RowEvidence<'a> {
    /// The row's current tag.
    pub(crate) tag: &'a [u8],
    /// The newest record across every label a write of this row appends.
    pub(crate) newest: Option<&'a ChainRecord>,
    /// Whether ANY of those records carries the row's current tag.
    pub(crate) tag_recorded: bool,
    /// `max(the last rotation, the chain switch)`; `None` turns arm 1 off,
    /// which is what an unswitched chain does.
    pub(crate) boundary: Option<i64>,
    /// The newest destruction record naming this row, if any.
    pub(crate) destroyed_at: Option<i64>,
}

/// Which way a row disagrees with the chain that recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayVerdict {
    /// An older version of the row, written back over the current one.
    Superseded,
    /// A row present although the chain records its destruction.
    Resurrected,
}

/// **The one version decision** (ROADMAP O234), a pure function of one row's
/// evidence — so `verify` and any reader that consults it cannot disagree
/// about whether a row is the version the chain last recorded.
///
/// `versioned` is the table's, not the row's: where a row is never rewritten
/// in place, arms 1 and 2 have no newer version to find and asking them would
/// turn `create_tunnel`'s no-op append (ROADMAP O236) into an alarm.
pub(crate) fn replay_finding(row: &RowEvidence<'_>, versioned: bool) -> Option<ReplayVerdict> {
    // Arm 3 first, and it is the stronger claim: the chain says this row was
    // destroyed and it is here. A destruction below the newest write is
    // ordinary — destroy, then re-mine or restore.
    if let Some(dead) = row.destroyed_at {
        if row.newest.is_none_or(|n| dead > n.seq) {
            return Some(ReplayVerdict::Resurrected);
        }
    }
    if !versioned {
        return None;
    }
    let newest = row.newest?;
    if newest.tag == row.tag {
        return None;
    }
    // Arm 1: a recorded newer version, above the boundary below which a
    // rotation may legitimately have re-tagged the row with nothing to say
    // so. Arm 2: the row's own tag sits in an older record, which is a
    // version this vault really wrote and then superseded — no bound needed,
    // because neither a rotation nor A10 produces a tag any record holds.
    let above_boundary = row.boundary.is_some_and(|b| newest.seq > b);
    if above_boundary || row.tag_recorded {
        Some(ReplayVerdict::Superseded)
    } else {
        None
    }
}

/// Which table a returning read consulted, for [`VaultStore::refuse_replayed`].
///
/// A closed set rather than a table name: a door names what it read, and the
/// spec — the labels, the arms — comes from [`TAGGED`], the one place they
/// are stated.
#[derive(Clone, Copy)]
pub(crate) enum Consulted {
    /// `drawers`, from `get`, `recent` and a search's hydrated candidates.
    Drawers,
    /// `kg_triples`, from `decode_triple` and `lookup_canonical`'s candidates.
    Facts,
}

impl Consulted {
    fn spec(self) -> &'static Tagged {
        let table = match self {
            Consulted::Drawers => "drawers",
            Consulted::Facts => "kg_triples",
        };
        TAGGED
            .iter()
            .find(|t| t.table == table)
            .expect("every consulted table is one of the tagged ones")
    }
}

/// The label expressions for one row's writes, as SQL over `t.id` with the
/// prefixes and suffixes bound as parameters — never formatted into the
/// statement, and never spelled inline: the prefix is
/// [`Namespace::prefix`]'s, once.
fn write_label_sql(spec: &Tagged, first_param: usize) -> (String, Vec<String>) {
    let mut exprs = Vec::with_capacity(spec.writes.len());
    let mut params = Vec::with_capacity(spec.writes.len() * 2);
    for (ns, suffix) in spec.writes {
        let p = first_param + params.len();
        exprs.push(format!("?{} || t.id || ?{}", p, p + 1));
        params.push(ns.prefix().to_string());
        params.push((*suffix).to_string());
    }
    (exprs.join(", "), params)
}

/// The same for the labels that DESTROY one row. A table with no destruction
/// path gets an expression that can match nothing — the empty string prefixed
/// by a namespace never equals a real label — so the statement's shape stays
/// one shape and its plan does not depend on the table.
fn destruction_label_sql(spec: &Tagged, first_param: usize) -> (String, Vec<String>) {
    let Some(infix) = spec.destruction_infix else {
        return ("NULL".to_string(), Vec::new());
    };
    let mut exprs = Vec::new();
    let mut params = Vec::new();
    for ns in Namespace::ALL
        .iter()
        .copied()
        .filter(|n| n.is_destruction())
    {
        let p = first_param + params.len();
        exprs.push(format!("?{p} || t.id"));
        params.push(ns.record(infix));
    }
    (exprs.join(", "), params)
}

impl VaultStore {
    /// Every row that is not the version the chain last recorded — the ninth
    /// verify leg (ROADMAP O234), sorted.
    pub(crate) fn version_replay_drift(
        &self,
        snap: &chain::Snapshot<'_>,
    ) -> Result<Vec<String>, StoreError> {
        let boundary = self.version_boundary(snap, LabelUse::Report)?;
        let mut out = Vec::new();
        for spec in TAGGED {
            if spec.versioned {
                out.extend(self.superseded_rows(snap, spec, boundary)?);
            }
            if spec.destruction_infix.is_some() {
                out.extend(self.resurrected_rows(snap, spec)?);
            }
        }
        out.sort();
        Ok(out)
    }

    /// `max(the last rotation, the chain switch)`, or `None` on a chain that
    /// has not switched — see arm 1 in this module's own documentation for
    /// why the switch is half of it.
    fn version_boundary(
        &self,
        snap: &chain::Snapshot<'_>,
        on: LabelUse,
    ) -> Result<Option<i64>, StoreError> {
        let switch = match chain::regime(snap.conn())? {
            chain::Regime::V1 => return Ok(None),
            chain::Regime::V2 { switch_seq } => switch_seq,
        };
        let rotate = self.rotation_boundary(snap, on)?.unwrap_or(switch);
        Ok(Some(switch.max(rotate)))
    }

    /// Arms 1 and 2, as ONE statement per table that returns only the rows
    /// that disagree.
    ///
    /// **The first clause is what makes it affordable and the ordering is
    /// deliberate.** A clean row's newest record carries its tag, so the
    /// leading subquery settles it with ONE indexed probe of
    /// `idx_audit_record_id` and `AND` short-circuits the rest; the two
    /// behind it run only for a row that already differs. Measured before
    /// this was written (ROADMAP O233's panel): one such probe is ~10 µs
    /// alone and ~281 ms set-based over 102,000 drawers, against a `verify`
    /// of 0.33 s — which is the shape this is, and not a probe loop in Rust,
    /// which would be that 10 µs once per row.
    ///
    /// `CAST(a.tag AS BLOB)` rather than a bare comparison: SQLite reads a
    /// TEXT and a BLOB holding the same bytes as unequal, so a tag an offline
    /// writer retyped would otherwise read as a version replay here. It is a
    /// finding either way — O233's replay reports the retype itself — and
    /// naming it twice, once wrongly, is the thing to avoid.
    fn superseded_rows(
        &self,
        snap: &chain::Snapshot<'_>,
        spec: &Tagged,
        boundary: Option<i64>,
    ) -> Result<Vec<String>, StoreError> {
        let (labels, label_params) = write_label_sql(spec, 1);
        // Arm 1 is off on an unswitched chain: `0` rather than a branch, so
        // the statement's shape — and its plan — do not depend on the vault.
        let arm1 = match boundary {
            Some(b) => {
                format!("(SELECT MAX(a.seq) FROM audit a WHERE a.record_id IN ({labels})) > {b}")
            }
            None => "0".to_string(),
        };
        let sql = format!(
            "SELECT t.id FROM {table} t \
              WHERE (SELECT CAST(a.tag AS BLOB) FROM audit a \
                      WHERE a.record_id IN ({labels}) ORDER BY a.seq DESC LIMIT 1) <> t.tag \
                AND ({arm1} \
                     OR EXISTS (SELECT 1 FROM audit a WHERE a.record_id IN ({labels}) \
                                 AND CAST(a.tag AS BLOB) = t.tag)) \
              ORDER BY t.id",
            table = spec.table,
        );
        let mut stmt = snap.conn().prepare(&sql)?;
        let ids: Vec<String> = stmt
            .query_map(rusqlite::params_from_iter(label_params.iter()), |r| {
                r.get(0)
            })?
            .collect::<Result<_, _>>()?;
        Ok(ids
            .into_iter()
            .map(|id| {
                format!(
                    "{id}: the {} row is not the newest version in the chain",
                    spec.noun
                )
            })
            .collect())
    }

    /// Arm 3, driven from the DESTRUCTION records rather than from the table.
    ///
    /// A tombstone exists per destroyed row, and destruction is rare next to
    /// writing, so this costs two indexed probes per destroyed thing instead
    /// of one per row of the corpus. The labels come from every namespace
    /// [`Namespace::is_destruction`] admits, so a second destruction
    /// namespace is covered the day it is classified.
    fn resurrected_rows(
        &self,
        snap: &chain::Snapshot<'_>,
        spec: &Tagged,
    ) -> Result<Vec<String>, StoreError> {
        let infix = spec
            .destruction_infix
            .expect("only a table with a destruction path reaches here");
        let mut out = Vec::new();
        for ns in Namespace::ALL
            .iter()
            .copied()
            .filter(|n| n.is_destruction())
        {
            // The namespace's own selection (ROADMAP O243): a range for a
            // prefixed namespace, the no-slash predicate for the bare one —
            // so a destruction namespace classified later is scanned
            // whatever its prefix is, and never panics this leg.
            let (clause, ps) = chain::prefix_range(ns).clause(1);
            let sql =
                format!("SELECT record_id, MAX(seq) FROM audit WHERE {clause} GROUP BY record_id");
            let mut stmt = snap.conn().prepare(&sql)?;
            let dead: Vec<(String, i64)> = stmt
                .query_map(rusqlite::params_from_iter(ps.iter()), |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?
                .collect::<Result<_, _>>()?;
            drop(stmt);
            let head = format!("{}{infix}", ns.prefix());
            for (label, dead_at) in dead {
                // `del/tunnel/{id}` is not a drawer's tombstone and
                // `del/{drawer}` is not a tunnel's: the infix separates them,
                // and a rest that does not carry it belongs to another table.
                let Some(id) = label.strip_prefix(&head) else {
                    continue;
                };
                if id.is_empty() || !Self::row_exists(snap, spec.table, id)? {
                    continue;
                }
                let newest = Self::newest_write_record(snap, spec, id)?;
                let evidence = RowEvidence {
                    // Arm 3 does not read the tag; the row's presence is the
                    // whole claim.
                    tag: &[],
                    newest: newest.as_ref(),
                    tag_recorded: false,
                    boundary: None,
                    destroyed_at: Some(dead_at),
                };
                if replay_finding(&evidence, false) == Some(ReplayVerdict::Resurrected) {
                    out.push(format!(
                        "{id}: the {} row is present after its destruction was recorded",
                        spec.noun
                    ));
                }
            }
        }
        Ok(out)
    }

    /// **The read half** (ROADMAP O234): refuse a read that RETURNS content
    /// when any row it consulted is not the version the chain last recorded.
    ///
    /// Three things the ruling settled, each the opposite of what one lens
    /// proposed.
    ///
    /// * **Internal lookups never refuse.** The remedy for a replayed row is
    ///   a WRITE — `import_verdict` replaces a row whose content differs or
    ///   whose HMAC fails (ROADMAP O215) — so refusing inside the engine's
    ///   own reads would block the restore that fixes it. The witness is
    ///   what separates the two, and it is required at every door already
    ///   (ROADMAP O50).
    /// * **The whole CONSULTED set, not the returned hits** (O230 ruling 4).
    ///   A search's rank is a function of every candidate it hydrated, so a
    ///   replayed row that merely displaced a real one has changed the
    ///   answer without appearing in it; and `lookup_canonical` filters on
    ///   clear columns before it decodes, so a replayed row can HIDE the
    ///   current holder rather than be returned in its place.
    /// * **Never partial.** Either every returning door asks, or none does.
    ///
    /// One statement, stopping at the first finding. A clean row costs one
    /// indexed probe for its newest record and one that MISSES for a
    /// tombstone — the `EXISTS` is what keeps the second cheap, because with
    /// no destruction record its inner comparison never runs.
    ///
    /// `ids` is what the door consulted; `None` means the whole table, which
    /// is what a graph door that rides `all_triples` really looks at. That
    /// distinction is deliberate rather than an optimisation: naming the ids
    /// of a walk that decoded every row would under-report the same way
    /// recording a door's count on a shared helper over-reports (ROADMAP
    /// O51).
    ///
    /// **The comparison only; the guard is the DOOR's** (ROADMAP O253). It
    /// takes the door's snapshot, and the door fetches the rows it returns in
    /// that same snapshot, so the rows and the records they are compared with
    /// are one state — every chunk of a large consulted set included. It was
    /// its own statements after the door's fetch, and a legitimate correction
    /// landing between them made it compare the corrected row while the read
    /// returned the replayed one. A door that returns nothing to a caller
    /// never calls it: the engine's own lookups decide nothing from it.
    pub(crate) fn refuse_replayed(
        &self,
        snap: &chain::Snapshot<'_>,
        from: Consulted,
        ids: Option<&[String]>,
    ) -> Result<(), StoreError> {
        if ids.is_some_and(<[String]>::is_empty) {
            return Ok(());
        }
        // **This comparison is only as good as the labels it rests on**
        // (ROADMAP O237): every arm below finds a record BY ITS LABEL, so an
        // `UPDATE audit SET record_id = …` on the newest write record makes a
        // replayed row look like the current one, and a forged `rotate/` row
        // lifts the boundary arm 1 stops at. This is the hottest label
        // decision in the tree, so it is where the door belongs — one full
        // replay per handle, then a per-key append-only check.
        //
        // **The per-key half reaches only the `rotate/` label here**
        // (corrected 2026-09-24, ROADMAP O252): `version_boundary` looks that
        // one up through the guard, and every drawer record below is found
        // by this function's own SQL and pinned by nothing. So under an
        // unmoved cookie a relabel-out or a delete of a drawer's newest write
        // record — which the invariant refuses on a pinned policy label — is
        // unseen here, and the replayed drawer is served. Measured, and
        // pinned as a cost in `chain.rs`.
        //
        // The DOOR authenticated this snapshot; this confirms the comparison
        // was handed one that was, so it can never decide under an unguarded
        // state (ROADMAP O253).
        self.labels_authenticated(snap)?;
        // **A consulted set is not bounded by anything the caller controls,
        // and one `IN` list is.** An unscoped search on a vault with no
        // prefilter tier hydrates the WHOLE corpus, so this arrived as a 500
        // on the first real 102,000-drawer run: SQLite refuses a statement
        // past `?32766`, and a smaller build refuses at `?999`. Batched, the
        // work is the same probes in more round trips, and the batch is well
        // under the oldest limit rather than under the current one.
        match ids {
            Some(ids) if ids.len() > REFUSAL_BATCH => {
                for chunk in ids.chunks(REFUSAL_BATCH) {
                    self.refuse_replayed(snap, from, Some(chunk))?;
                }
                return Ok(());
            }
            _ => {}
        }
        let spec = from.spec();
        let boundary = self.version_boundary(snap, LabelUse::Decide)?;
        let (labels, mut binds) = write_label_sql(spec, 1);
        let dead = destruction_label_sql(spec, 1 + binds.len());
        binds.extend(dead.1);
        let arm1 = match boundary {
            Some(b) => {
                format!("(SELECT MAX(a.seq) FROM audit a WHERE a.record_id IN ({labels})) > {b}")
            }
            None => "0".to_string(),
        };
        let scope = match ids {
            None => "1".to_string(),
            Some(ids) => {
                let first = 1 + binds.len();
                let holes: Vec<String> =
                    (0..ids.len()).map(|i| format!("?{}", first + i)).collect();
                binds.extend(ids.iter().cloned());
                format!("t.id IN ({})", holes.join(", "))
            }
        };
        let sql = format!(
            "SELECT t.id FROM {table} t WHERE {scope} AND ( \
               ((SELECT CAST(a.tag AS BLOB) FROM audit a \
                  WHERE a.record_id IN ({labels}) ORDER BY a.seq DESC LIMIT 1) <> t.tag \
                AND ({arm1} \
                     OR EXISTS (SELECT 1 FROM audit a WHERE a.record_id IN ({labels}) \
                                 AND CAST(a.tag AS BLOB) = t.tag))) \
               OR EXISTS (SELECT 1 FROM audit x WHERE x.record_id IN ({dead_labels}) \
                           AND x.seq > COALESCE((SELECT MAX(a.seq) FROM audit a \
                                                  WHERE a.record_id IN ({labels})), -1)) \
             ) LIMIT 1",
            table = spec.table,
            dead_labels = dead.0,
        );
        let mut stmt = snap.conn().prepare(&sql)?;
        let found: Option<String> = stmt
            .query_map(rusqlite::params_from_iter(binds.iter()), |r| r.get(0))?
            .next()
            .transpose()?;
        match found {
            None => Ok(()),
            Some(id) => Err(StoreError::IntegrityFinding(format!(
                "{id}: the {} row is not the version the audit chain last recorded — \
                 this read consulted it; run `undercroft verify`, then restore a \
                 backup that verifies",
                spec.noun
            ))),
        }
    }

    /// Whether the table still holds this id.
    fn row_exists(snap: &chain::Snapshot<'_>, table: &str, id: &str) -> Result<bool, StoreError> {
        let n: i64 = snap.conn().query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE id = ?1"),
            rusqlite::params![id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// The newest record across every label a write of this row appends —
    /// [`chain::newest_record`] per label, which is the one reader of what
    /// the trail says about a label.
    fn newest_write_record(
        snap: &chain::Snapshot<'_>,
        spec: &Tagged,
        id: &str,
    ) -> Result<Option<ChainRecord>, StoreError> {
        let mut best: Option<ChainRecord> = None;
        for (ns, suffix) in spec.writes {
            let label = ns.record(&format!("{id}{suffix}"));
            if let Some(rec) = chain::newest_record(snap.conn(), &label)? {
                if best.as_ref().is_none_or(|b| rec.seq > b.seq) {
                    best = Some(rec);
                }
            }
        }
        Ok(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InternalRead, Read};
    use rusqlite::params;
    use tempfile::TempDir;
    use undercroft_core::Drawer;
    use undercroft_vault::{SecurityLevel, VaultManager};

    fn drawer(content: &str, idx: u32) -> Drawer {
        Drawer::new(
            "wing",
            "room",
            content.into(),
            Some("t.md".into()),
            idx,
            "t",
        )
    }

    fn fresh(level: SecurityLevel) -> (TempDir, VaultStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let store = VaultStore::open(mgr.create("r", level).unwrap()).unwrap();
        (dir, store)
    }

    fn rotate(dir: &TempDir, store: &mut VaultStore) {
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        store
            .rotate_keys(mgr.rotation_candidate("r").unwrap())
            .expect("a clean vault rotates");
    }

    /// The four columns a drawer replay restores — exactly the ones the
    /// measurement on `d938e62` moved with sqlite3.
    type DrawerRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

    fn snapshot_drawer(store: &VaultStore, id: &str) -> DrawerRow {
        store
            .conn
            .query_row(
                "SELECT meta_json, content, embedding, tag FROM drawers WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap()
    }

    fn restore_drawer(store: &VaultStore, id: &str, row: &DrawerRow) {
        store
            .conn
            .execute(
                "UPDATE drawers SET meta_json = ?1, content = ?2, embedding = ?3, tag = ?4 \
                 WHERE id = ?5",
                params![row.0, row.1, row.2, row.3, id],
            )
            .unwrap();
    }

    fn tag_of(store: &VaultStore, table: &str, id: &str) -> Vec<u8> {
        store
            .conn
            .query_row(
                &format!("SELECT tag FROM {table} WHERE id = ?1"),
                params![id],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// **O234a, the measured defect: an older drawer written back.**
    ///
    /// The counterfactual is the previous behaviour, asserted rather than
    /// remembered: every OTHER leg passes over this tampering, so the verdict
    /// is attributable to this one. That is exactly what made it invisible —
    /// the tag verifies under the current key and the record id exists, which
    /// is all `verify` compared.
    #[test]
    fn an_older_drawer_written_back_fails_verify() {
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let (_d, mut s) = fresh(level);
            let first = drawer("the account number is 1111", 0);
            s.upsert(&first).unwrap();
            let before = snapshot_drawer(&s, &first.id);
            // The same filing, corrected: the id is deterministic over
            // (wing, room, source, chunk), so this rewrites the SAME row.
            let fixed = drawer("the account number is 2222 (corrected)", 0);
            assert_eq!(fixed.id, first.id, "premise: one row, two versions");
            s.upsert(&fixed).unwrap();
            assert!(s.verify().unwrap().ok(), "premise: a clean vault verifies");

            restore_drawer(&s, &first.id, &before);
            let back = s
                .get(&first.id, Read::Internal(InternalRead::Verification))
                .unwrap()
                .expect("the restored row reads back verified");
            assert!(
                back.content.contains("1111"),
                "premise: the replay serves the old content again"
            );

            let r = s.verify().unwrap();
            // The counterfactual, as assertions: every other leg is clean, so
            // only the new one can be failing the verdict.
            assert!(r.bad_records.is_empty(), "{:?}", r.bad_records);
            assert!(
                r.chain_ok,
                "the chain still replays — nothing moved in `audit`"
            );
            assert!(r.orphan_labels.is_empty() && r.mirror_drift.is_empty());
            assert!(r.policy_drift.is_empty());
            assert_eq!(r.version_replay.len(), 1, "{:?}", r.version_replay);
            assert!(r.version_replay[0].contains(&first.id));
            assert!(r.version_replay[0].contains("not the newest version"));
            assert!(!r.ok(), "a replayed version fails the verdict");
            // And a rotation must not launder it (ROADMAP O232's criterion).
            assert!(r
                .rotation_blockers()
                .iter()
                .any(|b| b.starts_with("version ")));
        }
    }

    /// **O234b: a drawer `forget` destroyed, written back.** Arm 3, and the
    /// one arm that compares no tag at all — the chain says the row is gone
    /// and it is here.
    #[test]
    fn a_drawer_restored_after_its_destruction_fails_verify() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        let d = drawer("a memory an operator erased", 0);
        s.upsert(&d).unwrap();
        let row = snapshot_drawer(&s, &d.id);
        assert!(s.delete_drawer(&d.id).unwrap(), "premise: it was destroyed");
        assert!(s.verify().unwrap().ok(), "premise: a destruction verifies");

        s.conn
            .execute(
                "INSERT INTO drawers (id, wing, room, meta_json, content, embedding, tag, \
                 filed_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                params![
                    d.id,
                    d.meta.wing,
                    d.meta.room,
                    row.0,
                    row.1,
                    row.2,
                    row.3,
                    d.meta.filed_at
                ],
            )
            .unwrap();
        assert!(
            s.get(&d.id, Read::Internal(InternalRead::Verification))
                .unwrap()
                .is_some(),
            "premise: the erased drawer is served again"
        );

        let r = s.verify().unwrap();
        assert!(r.bad_records.is_empty() && r.chain_ok && r.orphan_labels.is_empty());
        assert_eq!(r.version_replay.len(), 1, "{:?}", r.version_replay);
        assert!(r.version_replay[0].contains("present after its destruction"));
        assert!(!r.ok());
    }

    /// **Destroy, then re-mine, is ordinary** — the false alarm arm 3 would
    /// raise if it asked only whether a tombstone exists. A write above the
    /// tombstone is what separates the two, and nothing else does.
    #[test]
    fn destroying_a_drawer_and_re_mining_it_is_not_a_resurrection() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        let d = drawer("a note mined twice", 0);
        s.upsert(&d).unwrap();
        assert!(s.delete_drawer(&d.id).unwrap());
        s.upsert(&d).unwrap();
        let r = s.verify().unwrap();
        assert!(r.version_replay.is_empty(), "{:?}", r.version_replay);
        assert!(r.ok());
    }

    /// **O234c: an invalidated fact written back reads active again.**
    #[test]
    fn an_invalidated_fact_written_back_fails_verify() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        let id = s
            .kg_add("alice", "works_at", "acme", None, None, 0.9, None)
            .unwrap();
        // Every column `kg_invalidate` rewrites, so the restored row is the
        // one this vault really wrote — which is the whole premise: it
        // verifies under the current key.
        type Active = (
            Option<Vec<u8>>,
            Option<String>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let active: Active = s
            .conn
            .query_row(
                "SELECT object, valid_to, tag, support, terms FROM kg_triples WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(s.kg_invalidate("alice", "works_at", None, None).unwrap(), 1);
        assert!(
            s.verify().unwrap().ok(),
            "premise: an invalidation verifies"
        );

        s.conn
            .execute(
                "UPDATE kg_triples SET object = ?1, valid_to = ?2, tag = ?3, support = ?4, \
                 terms = ?5 WHERE id = ?6",
                params![active.0, active.1, active.2, active.3, active.4, id],
            )
            .unwrap();
        let r = s.verify().unwrap();
        assert!(r.bad_records.is_empty(), "{:?}", r.bad_records);
        assert_eq!(r.version_replay.len(), 1, "{:?}", r.version_replay);
        assert!(r.version_replay[0].contains(&id));
        assert!(r.version_replay[0].contains("the fact row"));
        assert!(!r.ok());
    }

    /// **An authority change records itself under a DIFFERENT label**, so a
    /// fact's newest record is the newest across `kg/{id}` AND
    /// `kg/{id}/authority`. Reading only the first makes every promotion look
    /// like a replay; reading only the second makes a demotion invisible.
    /// Both directions are asserted, which is why the promotion arm here is
    /// more than a premise.
    #[test]
    fn a_promoted_fact_is_not_a_replay_and_a_demoted_one_written_back_is() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        let id = s
            .kg_add("acme", "ceo", "dana", None, None, 0.9, None)
            .unwrap();
        s.kg_set_authority(&id, "canonical", "approved", Some("acme-ceo"))
            .unwrap();
        let promoted = tag_of(&s, "kg_triples", &id);
        let r = s.verify().unwrap();
        assert!(
            r.version_replay.is_empty() && r.ok(),
            "a promotion is a write, not a replay: {:?}",
            r.version_replay
        );

        // Demote it, then write the promoted row back.
        s.kg_set_authority(&id, "stated", "unreviewed", None)
            .unwrap();
        s.conn
            .execute(
                "UPDATE kg_triples SET authority_class = 'canonical', review_state = 'approved', \
                 canonical_key = 'acme-ceo', tag = ?1 WHERE id = ?2",
                params![promoted, id],
            )
            .unwrap();
        let r = s.verify().unwrap();
        assert_eq!(r.version_replay.len(), 1, "{:?}", r.version_replay);
        assert!(!r.ok());
    }

    /// **A tunnel is never rewritten in place**, so arms 1 and 2 have nothing
    /// to compare there and only arm 3 applies. `create_tunnel` appends a
    /// record for a create that wrote nothing (ROADMAP O236), which arms 1
    /// and 2 would read as a version that never landed — this pins that they
    /// do not run, and that a deleted tunnel written back is still found.
    #[test]
    fn a_repeated_tunnel_create_is_clean_and_a_restored_one_is_not() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        let id = s.create_tunnel("wing", "other", "see also").unwrap();
        let again = s.create_tunnel("wing", "other", "see also").unwrap();
        assert_eq!(id, again, "premise: the same tunnel, appended twice");
        let r = s.verify().unwrap();
        assert!(
            r.version_replay.is_empty() && r.ok(),
            "{:?}",
            r.version_replay
        );

        let row: (String, String, String, Vec<u8>, String) = s
            .conn
            .query_row(
                "SELECT from_wing, to_wing, label, tag, created_at FROM tunnels WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert!(s.delete_tunnel(&id).unwrap());
        assert!(s.verify().unwrap().ok(), "premise: a deletion verifies");
        s.conn
            .execute(
                "INSERT INTO tunnels (id, from_wing, to_wing, label, tag, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, row.0, row.1, row.2, row.3, row.4],
            )
            .unwrap();
        let r = s.verify().unwrap();
        assert_eq!(r.version_replay.len(), 1, "{:?}", r.version_replay);
        assert!(r.version_replay[0].contains("the tunnel row"));
        assert!(!r.ok());
    }

    /// **The false-alarm sweep** (the ruling's second probe, as a test): every
    /// ordinary write surface, before and after a key rotation, expecting
    /// nothing. The rotation is the case that matters — it re-tags every row
    /// and records NOTHING per row, so a comparison with no boundary reads a
    /// whole rotated corpus as replayed.
    #[test]
    fn ordinary_writes_and_a_rotation_leave_no_version_finding() {
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let (dir, mut s) = fresh(level);
            for i in 0..4u32 {
                s.upsert(&drawer(&format!("an ordinary memory number {i}"), i))
                    .unwrap();
            }
            // An update in place, a destruction and a re-mine.
            s.upsert(&drawer("an ordinary memory number 0, corrected", 0))
                .unwrap();
            let gone = drawer("an ordinary memory number 3", 3);
            assert!(s.delete_drawer(&gone.id).unwrap());
            s.upsert(&gone).unwrap();
            // The graph: a repeated add, an authority promotion, an
            // invalidation, and a tunnel created twice.
            let id = s
                .kg_add("alice", "lives_in", "berlin", None, None, 0.8, None)
                .unwrap();
            assert_eq!(
                s.kg_add("alice", "lives_in", "berlin", None, None, 0.8, None)
                    .unwrap(),
                id,
                "premise: a deterministic id, written twice"
            );
            s.kg_invalidate("alice", "lives_in", None, None).unwrap();
            // A promotion, on a fact of its own: the authority tier refuses
            // to let the exact-authority door be emptied, so a holder cannot
            // also be the invalidation above.
            let held = s
                .kg_add("acme", "ceo", "dana", None, None, 0.9, None)
                .unwrap();
            s.kg_set_authority(&held, "canonical", "approved", Some("acme-ceo"))
                .unwrap();
            s.create_tunnel("wing", "other", "see also").unwrap();
            s.create_tunnel("wing", "other", "see also").unwrap();

            let before = s.verify().unwrap();
            assert!(
                before.version_replay.is_empty() && before.ok(),
                "{level:?} before a rotation: {:?}",
                before.version_replay
            );

            rotate(&dir, &mut s);
            let after = s.verify().unwrap();
            assert!(
                after.version_replay.is_empty() && after.ok(),
                "{level:?} after a rotation — every row is re-tagged and no \
                 record says so, which is what the boundary is for: {:?}",
                after.version_replay
            );
        }
    }

    /// **A replay made BEFORE the chain switched is found by arm 2**, the half
    /// of the decision that needs no boundary. Arm 1 cannot see it — there is
    /// no switch to bound it — and a check built on arm 1 alone would hide
    /// every replay made before the upgrade, which is the correction the
    /// panel made to this entry's own filing.
    #[test]
    fn a_replay_made_before_the_switch_is_found_by_the_unbounded_arm() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        // A legacy chain: no commitment, so no switch seq exists.
        s.unswitch_chain_for_test();
        let first = drawer("the account number is 1111", 0);
        s.upsert(&first).unwrap();
        let before = snapshot_drawer(&s, &first.id);
        s.upsert(&drawer("the account number is 2222 (corrected)", 0))
            .unwrap();
        restore_drawer(&s, &first.id, &before);

        // PREMISE: arm 1 is off, because there is no switch to bound it.
        assert_eq!(
            s.snapshot(|snap| s.version_boundary(snap, LabelUse::Report))
                .unwrap(),
            None
        );
        let r = s.verify().unwrap();
        assert_eq!(r.version_replay.len(), 1, "{:?}", r.version_replay);
        assert!(!r.ok());
    }

    /// **The pure decision, arm by arm**, including the two shapes that must
    /// NOT fire: a tag no record holds below the boundary (a rotation, or
    /// A10's blinding walk), and a destruction older than the newest write.
    #[test]
    fn the_version_decision_answers_each_arm_on_its_own() {
        fn run(
            tag: &[u8],
            newest: Option<(i64, &[u8])>,
            tag_recorded: bool,
            boundary: Option<i64>,
            destroyed_at: Option<i64>,
            versioned: bool,
        ) -> Option<ReplayVerdict> {
            let newest = newest.map(|(seq, t)| ChainRecord {
                seq,
                tag: t.to_vec(),
            });
            replay_finding(
                &RowEvidence {
                    tag,
                    newest: newest.as_ref(),
                    tag_recorded,
                    boundary,
                    destroyed_at,
                },
                versioned,
            )
        }

        // Clean: the newest record carries the row's tag.
        assert_eq!(run(b"A", Some((9, b"A")), true, Some(1), None, true), None);
        // Arm 1: a recorded newer version, above the boundary.
        assert_eq!(
            run(b"A", Some((9, b"B")), false, Some(1), None, true),
            Some(ReplayVerdict::Superseded)
        );
        // The same evidence BELOW the boundary is a rotation, not a replay:
        // the row was re-tagged and no record could say so.
        assert_eq!(
            run(b"A", Some((9, b"B")), false, Some(20), None, true),
            None
        );
        // Arm 2: the row's own tag sits in an older record — no boundary
        // needed, which is what finds a replay made before the switch.
        assert_eq!(
            run(b"A", Some((9, b"B")), true, None, None, true),
            Some(ReplayVerdict::Superseded)
        );
        // Arm 3: a destruction newer than the newest write.
        assert_eq!(
            run(b"A", Some((3, b"A")), true, None, Some(7), true),
            Some(ReplayVerdict::Resurrected)
        );
        // …and older than it is destroy-then-re-mine.
        assert_eq!(run(b"A", Some((9, b"A")), true, None, Some(7), true), None);
        // A table whose rows are never rewritten takes arm 3 alone.
        assert_eq!(run(b"A", Some((9, b"B")), true, Some(1), None, false), None);
        assert_eq!(
            run(b"A", Some((3, b"A")), false, None, Some(7), false),
            Some(ReplayVerdict::Resurrected)
        );
        // A row with no record at all is not this leg's finding: an offline
        // INSERT cannot produce a tag that verifies, and one that fails is
        // already `bad_records`.
        assert_eq!(run(b"A", None, false, Some(1), None, true), None);
    }

    /// **Which namespaces destroy is ruled once, exhaustively.** A second
    /// destruction namespace (ROADMAP O205 has one filed) must be classified
    /// on the enum or arm 3 simply stops seeing it — the defect O80 closed for
    /// the agent fence, on the same enum, by the same mechanism.
    #[test]
    fn exactly_one_namespace_destroys_and_every_table_composes_from_it() {
        let destroying: Vec<&str> = Namespace::ALL
            .iter()
            .filter(|n| n.is_destruction())
            .map(|n| n.prefix())
            .collect();
        assert_eq!(destroying, vec!["del/"], "{destroying:?}");
        for spec in TAGGED {
            if let Some(infix) = spec.destruction_infix {
                assert!(
                    Namespace::Del.record(infix).starts_with("del/"),
                    "{}",
                    spec.table
                );
            }
        }
        // And every table states its write labels through the vocabulary, so
        // a namespace that is renamed moves them with it.
        for spec in TAGGED {
            for (ns, suffix) in spec.writes {
                assert!(ns.record(&format!("x{suffix}")).ends_with(suffix));
            }
        }
    }

    /// **A returning read refuses; the engine's own lookups do not.**
    ///
    /// Both halves are load-bearing and the second is the one a lens got
    /// wrong: the remedy for a replayed row is a WRITE — `import_verdict`
    /// replaces a row whose content differs (ROADMAP O215) — and it reads
    /// the row first, through `get`, to decide. A refusal there would block
    /// the restore that fixes the vault, so the witness decides and nothing
    /// else does.
    #[test]
    fn a_returning_read_refuses_a_replayed_drawer_and_an_internal_one_serves_it() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        let first = drawer("the account number is 1111", 0);
        s.upsert(&first).unwrap();
        let before = snapshot_drawer(&s, &first.id);
        s.upsert(&drawer("the account number is 2222 (corrected)", 0))
            .unwrap();
        restore_drawer(&s, &first.id, &before);

        let err = s
            .get(&first.id, Read::Returned(crate::ReadOp::Get))
            .unwrap_err();
        assert!(
            matches!(err, StoreError::IntegrityFinding(_)),
            "a returned read refuses: {err:?}"
        );
        assert!(err.to_string().contains(&first.id));

        // The counterfactual for the OTHER half: the same row, read
        // internally, is served — which is what the restore path needs.
        let served = s
            .get(&first.id, Read::Internal(InternalRead::Verification))
            .unwrap()
            .expect("an internal lookup still reads the row");
        assert!(served.content.contains("1111"));

        // And `recent`, which is what `wake_up` and the closet index call.
        let err = s
            .recent(None, 10, Read::Returned(crate::ReadOp::Recent))
            .unwrap_err();
        assert!(matches!(err, StoreError::IntegrityFinding(_)), "{err:?}");
        assert!(s
            .recent(None, 10, Read::Internal(InternalRead::BulkMember))
            .is_ok());
    }

    /// **A search refuses on its CONSULTED set, not on its hits.** The
    /// replayed drawer here does not match the query, so it cannot appear in
    /// the answer — and it was hydrated, which means it competed for the
    /// page. A check scoped to the returned hits reads that as clean.
    #[test]
    fn a_search_refuses_on_a_replayed_candidate_it_would_not_have_returned() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        for i in 0..6u32 {
            s.upsert(&drawer(
                &format!("a note about harbour cranes and containers {i}"),
                i,
            ))
            .unwrap();
        }
        let first = drawer("the account number is 1111", 40);
        s.upsert(&first).unwrap();
        let before = snapshot_drawer(&s, &first.id);
        s.upsert(&drawer("the account number is 2222 (corrected)", 40))
            .unwrap();
        // PREMISE: this query does not match the replayed drawer.
        let hits = s.search("harbour cranes", &Default::default()).unwrap();
        assert!(
            !hits.iter().any(|h| h.drawer.id == first.id),
            "premise: the replayed drawer is no hit for this query"
        );

        restore_drawer(&s, &first.id, &before);
        let err = s.search("harbour cranes", &Default::default()).unwrap_err();
        assert!(
            matches!(err, StoreError::IntegrityFinding(_)),
            "a search refuses on what it consulted: {err:?}"
        );
    }

    /// **`lookup_canonical`'s consulted set is wider than its answer**, and
    /// this is the door where that matters most: its filter rides CLEAR
    /// columns, so a replayed row can HIDE the current holder instead of
    /// being returned in its place — and a check on the returned row would
    /// then have nothing to look at.
    #[test]
    fn the_authority_door_refuses_when_a_replayed_row_sits_on_its_key() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        let id = s
            .kg_add("acme", "ceo", "dana", None, None, 0.9, None)
            .unwrap();
        s.kg_set_authority(&id, "canonical", "approved", Some("acme-ceo"))
            .unwrap();
        let promoted = tag_of(&s, "kg_triples", &id);
        assert!(s
            .lookup_canonical("acme-ceo", Read::Returned(crate::ReadOp::KgCanonical))
            .unwrap()
            .is_some());

        // Demote it — the door now answers `None` — then write the promoted
        // row back. It is served again, and the door refuses instead.
        s.kg_set_authority(&id, "stated", "unreviewed", None)
            .unwrap();
        s.conn
            .execute(
                "UPDATE kg_triples SET authority_class = 'canonical', review_state = 'approved', \
                 canonical_key = 'acme-ceo', tag = ?1 WHERE id = ?2",
                params![promoted, id],
            )
            .unwrap();
        let err = s
            .lookup_canonical("acme-ceo", Read::Returned(crate::ReadOp::KgCanonical))
            .unwrap_err();
        assert!(matches!(err, StoreError::IntegrityFinding(_)), "{err:?}");
        assert!(err.to_string().contains(&id));
    }

    /// **A graph door rides `all_triples`, which decodes every fact**, so the
    /// set it consulted is the table. The replayed fact here is about a
    /// different entity than the one asked for, and the door still refuses —
    /// which is the same claim the search test makes one table over.
    #[test]
    fn a_graph_door_refuses_on_a_replayed_fact_it_would_not_have_returned() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        s.kg_add("bob", "lives_in", "lisbon", None, None, 0.9, None)
            .unwrap();
        let id = s
            .kg_add("alice", "works_at", "acme", None, None, 0.9, None)
            .unwrap();
        type Active = (
            Option<Vec<u8>>,
            Option<String>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let active: Active = s
            .conn
            .query_row(
                "SELECT object, valid_to, tag, support, terms FROM kg_triples WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(s.kg_invalidate("alice", "works_at", None, None).unwrap(), 1);
        // PREMISE: the door answers about `bob`, and is clean before.
        assert_eq!(
            s.kg_query_entity("bob", None, "both", Read::Returned(crate::ReadOp::KgQuery))
                .unwrap()
                .len(),
            1
        );
        s.conn
            .execute(
                "UPDATE kg_triples SET object = ?1, valid_to = ?2, tag = ?3, support = ?4, \
                 terms = ?5 WHERE id = ?6",
                params![active.0, active.1, active.2, active.3, active.4, id],
            )
            .unwrap();
        let err = s
            .kg_query_entity("bob", None, "both", Read::Returned(crate::ReadOp::KgQuery))
            .unwrap_err();
        assert!(matches!(err, StoreError::IntegrityFinding(_)), "{err:?}");
    }

    /// **A clean vault's returning reads are untouched** — the premise every
    /// refusal above rests on, and the one a gate that only ever asserted
    /// refusals could not state.
    #[test]
    fn a_clean_vault_returns_from_every_door_the_check_guards() {
        let (_d, mut s) = fresh(SecurityLevel::Sealed);
        let d = drawer("a harbour crane lifts a container", 0);
        s.upsert(&d).unwrap();
        let id = s
            .kg_add("acme", "ceo", "dana", None, None, 0.9, None)
            .unwrap();
        s.kg_set_authority(&id, "canonical", "approved", Some("acme-ceo"))
            .unwrap();
        assert!(s
            .get(&d.id, Read::Returned(crate::ReadOp::Get))
            .unwrap()
            .is_some());
        assert_eq!(
            s.recent(None, 10, Read::Returned(crate::ReadOp::Recent))
                .unwrap()
                .len(),
            1
        );
        assert!(!s
            .search("harbour crane", &Default::default())
            .unwrap()
            .is_empty());
        assert!(s
            .lookup_canonical("acme-ceo", Read::Returned(crate::ReadOp::KgCanonical))
            .unwrap()
            .is_some());
        assert_eq!(
            s.kg_query_entity("acme", None, "both", Read::Returned(crate::ReadOp::KgQuery))
                .unwrap()
                .len(),
            1
        );
        assert!(s.verify().unwrap().ok());
    }

    /// Every PRODUCTION line of one of this crate's files that holds `needle`,
    /// named by the function enclosing it — the shape `chain.rs`'s own source
    /// gate uses, one question over.
    fn production_sites(file: &str, needle: &str) -> Vec<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(file);
        let text = std::fs::read_to_string(&path).expect("the crate's own source is readable");
        let prod = text
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or_default();
        let mut enclosing = String::new();
        let mut out = Vec::new();
        for line in prod.lines() {
            let t = line.trim_start();
            // A method of the `impl`, at exactly four spaces — never a `fn`
            // NESTED in a body. The gate found that distinction itself: the
            // tracker first attributed `walk_covered`'s verify site to the
            // inner `fn typed` eight spaces in, and reported a door with no
            // reason where there is one.
            let top_level = line.len() - t.len() == 4;
            if top_level {
                if let Some(rest) = t
                    .strip_prefix("pub fn ")
                    .or_else(|| t.strip_prefix("pub(crate) fn "))
                    .or_else(|| t.strip_prefix("fn "))
                {
                    enclosing = rest
                        .split(['(', '<'])
                        .next()
                        .unwrap_or_default()
                        .to_string();
                }
            }
            if t.contains(needle) && !t.starts_with("//") {
                out.push(enclosing.clone());
            }
        }
        out
    }

    /// **Never partial** — the ruling's own word for the read half: every door
    /// that RETURNS content asks the version check, and the sites that do not
    /// are named here with the reason.
    ///
    /// A count would not do. The failure this guards is a door somebody adds
    /// or moves, and a list of NAMES is what makes a diff say so — the
    /// argument `parity.rs` makes for the surface inventory and O80 makes for
    /// a namespace nobody was forced to classify.
    #[test]
    fn every_returning_door_asks_and_the_rest_say_why() {
        let mut asked = production_sites("lib.rs", "self.refuse_replayed(");
        asked.extend(production_sites("kg.rs", "self.refuse_replayed("));
        asked.sort();
        let expected: Vec<String> = [
            // The drawer doors.
            "get",
            // The graph, riding `all_triples`: what each of these consults is
            // the whole table.
            "kg_query_entity",
            "kg_query_relationship",
            "kg_timeline",
            // The authority door, whose consulted set is every row on the key
            // — wider than the one row it can return, because its filter
            // rides clear columns.
            "lookup_canonical",
            // `recent`'s reads, inside its guarded snapshot (ROADMAP O253).
            "recent_in",
            "search_inner",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            asked, expected,
            "a returning door that does not ask is a door a replayed row is \
             served through"
        );

        // PREMISE: the scan reads real source and its needle is findable —
        // an empty result and a clean tree must not look the same.
        let verifies = production_sites("lib.rs", "verify_tag(&canonical(");
        assert_eq!(
            verifies.len(),
            6,
            "the six drawer verify sites the ruling names: {verifies:?}"
        );
        let mut silent: Vec<String> = verifies
            .into_iter()
            .filter(|f| !asked.contains(f))
            .collect();
        silent.sort();
        assert_eq!(
            silent,
            [
                // The export paths carry no caller-supplied witness because
                // they are `InternalRead::ExportAudited`: an unconditional
                // `egress/` record covers them, and `backup create` gates on
                // the verdict this unit adds a leg to.
                "export_each",
                "export_each_with_vectors",
                // `get`'s row read (ROADMAP O253). `get` itself compares on a
                // returning read, in the same guarded snapshot; the engine's
                // own lookups reach it with no caller to return content to.
                "fetch_verified",
                // The verify and sweep walk. It IS the leg — refusing here
                // would leave the check unable to report what it found.
                "walk_covered",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
            "a drawer verify site that neither asks nor has a reason"
        );
    }
}
