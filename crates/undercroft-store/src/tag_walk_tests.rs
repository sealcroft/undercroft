//! ROADMAP O406: the version-2 row-tag walk — the probes its ruling names
//! that a store test can drive (P15k, P15l, the crash state of P15e), and
//! the regime's own rules (items 4, 6, 9, 10, 12).

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use undercroft_core::Drawer;
use undercroft_vault::{Access, RowFormat, SecurityLevel, VaultManager};

use undercroft_core::HashEmbedder;

use crate::{InternalRead, Read, ReadOp, SearchOptions, StoreError, VaultStore};

const VAULT: &str = "o406";

fn mgr(root: &Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn open(root: &Path) -> VaultStore {
    VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap()
}

fn open_ro(root: &Path) -> Result<VaultStore, StoreError> {
    VaultStore::open_read_only(
        VaultManager::open_as(root, None, Access::ReadOnly)
            .unwrap()
            .unlock_as(VAULT, Access::ReadOnly)
            .unwrap(),
        Box::new(HashEmbedder),
    )
}

fn drawer(wing: &str, content: &str, idx: u32) -> Drawer {
    Drawer::new(
        wing,
        "room",
        content.into(),
        Some("o406.md".into()),
        idx,
        "test",
    )
}

fn manifest_version(root: &Path) -> u64 {
    let raw = std::fs::read(vdir(root).join("vault.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    v["version"].as_u64().unwrap()
}

fn commitments(s: &VaultStore) -> i64 {
    s.conn
        .query_row(
            "SELECT COUNT(*) FROM audit WHERE record_id = 'migrate/tag-v2'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// A vault on the version-1 regime — every vault a release before O406
/// wrote — holding one of every tagged row: drawers, a supersession, a
/// receipted fact, an approved canonical fact, an entity, a tunnel, a trust
/// class and a retention policy, all written after O233's switch.
fn legacy(level: SecurityLevel) -> TempDir {
    let dir = TempDir::new().unwrap();
    let vault = mgr(dir.path()).create(VAULT, level).unwrap();
    crate::retag_pause::keep_on_v1(vault.dir());
    let mut s = VaultStore::open(vault).unwrap();
    assert_eq!(s.row_format(), RowFormat::V1, "premise: version 1");
    let src = drawer("w1", "the harbour ledger names cargo and its pier", 0);
    s.upsert(&src).unwrap();
    s.upsert(&drawer("w2", "a quarantined wing's note", 1))
        .unwrap();
    let mut newer = drawer("w1", "a note that supersedes the first one", 2);
    newer.meta.supersedes = Some(src.id.clone());
    s.upsert(&newer).unwrap();
    s.kg_add_receipted(
        "harbour",
        "ships",
        "cargo",
        Some("2026-01-01"),
        None,
        0.9,
        (&src.id, &src.content),
        None,
    )
    .unwrap();
    let canon = s
        .kg_add("ada", "employer", "acme", None, None, 1.0, None)
        .unwrap();
    s.kg_set_authority(&canon, "canonical", "approved", Some("ada-employer"))
        .unwrap();
    assert!(
        s.create_tunnel("w1", "w2", "shared ledger")
            .unwrap()
            .created
    );
    s.set_wing_trust("w2", "quarantined").unwrap();
    s.set_retention("w1", None, 3650).unwrap();
    assert!(s.verify().unwrap().ok(), "premise: clean");
    drop(s);
    crate::retag_pause::release(&vdir(dir.path()));
    dir
}

/// **P15k**: after the walk every row verifies under version 2, the
/// version arms and the policy scans see nothing — the trust and retention
/// rows' newest records hold version-1 tags BELOW the commitment — and the
/// readers that decide from them answer: `wing_trusts()`, a floored search,
/// `get`, `lookup_canonical`. On both levels, on a never-rotated vault and
/// on one rotated on version 1 whose policies were assigned AFTER that
/// rotation — the two shapes item 9's boundary has to serve.
#[test]
fn p15k_every_row_and_every_policy_reads_after_the_walk() {
    for (level, rotated) in [
        (SecurityLevel::Sealed, false),
        (SecurityLevel::HmacOnly, false),
        (SecurityLevel::Sealed, true),
        (SecurityLevel::HmacOnly, true),
    ] {
        let dir = legacy(level);
        let root = dir.path();
        if rotated {
            crate::retag_pause::keep_on_v1(&vdir(root));
            let m = mgr(root);
            let mut w = VaultStore::open(m.unlock(VAULT).unwrap()).unwrap();
            w.rotate_keys(m.rotation_candidate(VAULT).unwrap()).unwrap();
            drop(w);
            let mut w = open(root);
            assert_eq!(
                w.row_format(),
                RowFormat::V1,
                "premise: rotated on version 1"
            );
            w.set_wing_trust("w2", "quarantined").unwrap();
            w.set_retention("w1", None, 3650).unwrap();
            assert!(
                w.verify().unwrap().ok(),
                "premise: clean after the rotation"
            );
            drop(w);
            crate::retag_pause::release(&vdir(root));
        }
        assert_eq!(
            manifest_version(root),
            2,
            "premise: create writes version 2"
        );
        let s = open(root);
        assert_eq!(s.row_format(), RowFormat::V2, "{level:?} {rotated}: walked");
        assert_eq!(commitments(&s), 1, "{level:?}: one commitment");
        assert_eq!(manifest_version(root), 2);
        let r = s.verify().unwrap();
        assert!(r.ok(), "{level:?} {rotated}: {r:?}");
        assert!(r.version_replay.is_empty() && r.policy_drift.is_empty());
        assert_eq!(
            s.wing_trusts().unwrap(),
            vec![("w2".to_string(), "quarantined".to_string())]
        );
        assert_eq!(s.retention_policies().unwrap().len(), 1);
        let opts = SearchOptions {
            limit: 10,
            min_trust: Some("standard".into()),
            ..Default::default()
        };
        let hits = s.search("harbour ledger cargo", &opts).unwrap();
        assert!(
            hits.iter().all(|h| h.drawer.meta.wing != "w2"),
            "{level:?}: the floor still excludes the quarantined wing"
        );
        assert!(!hits.is_empty(), "{level:?}: and serves the rest");
        let id = drawer("w1", "the harbour ledger names cargo and its pier", 0).id;
        assert!(s.get(&id, Read::Returned(ReadOp::Get)).unwrap().is_some());
        assert_eq!(
            s.lookup_canonical("ada-employer", Read::Returned(ReadOp::KgCanonical))
                .unwrap()
                .map(|t| t.object),
            Some("acme".to_string())
        );
        // A write after the walk takes version 2 and its record, and the
        // version arms compare above the commitment.
        let mut s = s;
        s.upsert(&drawer("w1", "a later note", 9)).unwrap();
        s.set_wing_trust("w1", "trusted").unwrap();
        assert!(s.verify().unwrap().ok(), "{level:?}");
    }
}

/// **The walk never runs beside another holder** — every process on one
/// vault must agree on its format — and says so. A read-only replica
/// holding the vault keeps it on version 1; once it lets go, the next
/// writable open walks.
#[test]
fn the_walk_is_withheld_while_another_connection_holds_the_vault() {
    let dir = legacy(SecurityLevel::Sealed);
    let root = dir.path();
    let replica = open_ro(root).unwrap();
    assert_eq!(replica.row_format(), RowFormat::V1);
    assert!(
        replica
            .unhealed()
            .iter()
            .any(|n| n.contains("version-1 format") && n.contains("read-only")),
        "a read-only open reports the pending walk: {:?}",
        replica.unhealed()
    );
    // It holds the vault once it has read it.
    assert!(replica.verify().unwrap().ok());
    let s = open(root);
    assert_eq!(s.row_format(), RowFormat::V1, "withheld beside the replica");
    assert!(
        s.unhealed()
            .iter()
            .any(|n| n.contains("WITHHELD") && n.contains("another process")),
        "{:?}",
        s.unhealed()
    );
    assert_eq!(commitments(&s), 0);
    assert!(s.verify().unwrap().ok(), "and the vault works on version 1");
    drop(s);
    drop(replica);
    let s = open(root);
    assert_eq!(s.row_format(), RowFormat::V2);
}

/// **P15e's crash state, in the store** (ROADMAP O406 item 5): the raise
/// comes BEFORE the transaction, so a crash between them leaves a version-2
/// manifest over version-1 rows — older binaries fenced, this build reading
/// the version-1 regime and retrying — and never the reverse.
#[test]
fn a_crash_after_the_raise_leaves_the_vault_on_version_1_and_retrying() {
    let dir = legacy(SecurityLevel::HmacOnly);
    let root = dir.path();
    // A legacy manifest is version 1; lower it, so the raise is visible.
    {
        let mut s = {
            crate::retag_pause::keep_on_v1(&vdir(root));
            open(root)
        };
        undercroft_vault::fixture::set_manifest_version(&mut s.vault, 1);
        let head = crate::chain::require_head(&s.conn).unwrap().head;
        let writes = crate::chain::writes(&s.conn).unwrap();
        undercroft_vault::fixture::write_anchor_unchecked(&mut s.vault, &head, writes).unwrap();
        crate::retag_pause::release(&vdir(root));
    }
    assert_eq!(
        manifest_version(root),
        1,
        "premise: a released vault's manifest"
    );
    crate::retag_pause::set(&vdir(root), |p| {
        if p == crate::retag_pause::Phase::Raised {
            panic!("crash after the raise");
        }
    });
    let crashed = std::panic::catch_unwind(|| open(root));
    assert!(crashed.is_err(), "premise: the walk reached the raise");
    crate::retag_pause::release(&vdir(root));
    assert_eq!(manifest_version(root), 2, "the raise is durable");
    // This build reads the version-1 regime and verifies it.
    let ro = open_ro(root).unwrap();
    assert_eq!(ro.row_format(), RowFormat::V1);
    assert!(ro.verify().unwrap().ok());
    assert_eq!(commitments(&ro), 0, "nothing of the transaction landed");
    drop(ro);
    // And the next writable open retries.
    let s = open(root);
    assert_eq!(s.row_format(), RowFormat::V2);
    assert!(s.verify().unwrap().ok());
}

/// **ROADMAP O406 item 6: the manifest and the commitment, read together.**
/// The commitment beside a version-1 manifest anchored at or past it is no
/// state this design writes — an integrity finding, refused at open on both
/// postures. One anchored BELOW it is a stale manifest, healed forward and
/// raised.
#[test]
fn a_version_1_manifest_beside_the_commitment_is_judged_by_its_height() {
    let dir = legacy(SecurityLevel::Sealed);
    let root = dir.path();
    let (pre_head, pre_writes) = {
        let s = {
            crate::retag_pause::keep_on_v1(&vdir(root));
            open(root)
        };
        let h = (
            crate::chain::require_head(&s.conn).unwrap().head,
            crate::chain::writes(&s.conn).unwrap(),
        );
        crate::retag_pause::release(&vdir(root));
        h
    };
    let mut s = open(root);
    assert_eq!(s.row_format(), RowFormat::V2, "premise: walked");
    // At the committed head: the pair no writer produces.
    let head = crate::chain::require_head(&s.conn).unwrap().head;
    let writes = crate::chain::writes(&s.conn).unwrap();
    undercroft_vault::fixture::set_manifest_version(&mut s.vault, 1);
    undercroft_vault::fixture::write_anchor_unchecked(&mut s.vault, &head, writes).unwrap();
    drop(s);
    for got in [
        VaultStore::open(mgr(root).unlock(VAULT).unwrap()).map(|_| ()),
        open_ro(root).map(|_| ()),
    ] {
        assert!(
            matches!(got, Err(StoreError::IntegrityFinding(ref m)) if m.contains("version-1 manifest")),
            "{got:?}"
        );
    }
    // Below the commitment: a lag, healed forward and raised.
    let mut v = mgr(root).unlock(VAULT).unwrap();
    undercroft_vault::fixture::set_manifest_version(&mut v, 1);
    undercroft_vault::fixture::write_anchor_unchecked(&mut v, &pre_head, pre_writes).unwrap();
    assert_eq!(manifest_version(root), 1);
    let s = open(root);
    assert!(matches!(
        s.anchor_at_open(),
        crate::AnchorState::Healed { .. }
    ));
    assert_eq!(manifest_version(root), 2, "the heal raised the version");
    assert!(s.verify().unwrap().ok());
}

/// **P15l**: the walk only appends, and it moves no record's tag — so an
/// erasure receipt minted before it still answers `Verified` (its keyed
/// replay is under the `mac` subkey, which the walk leaves alone: ROADMAP
/// O406 item 2's reason for a separate key), and a witness emitted before it
/// still answers `Extends`.
#[test]
fn p15l_a_receipt_and_a_witness_from_before_the_walk_still_hold() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let vault = mgr(root).create(VAULT, SecurityLevel::Sealed).unwrap();
    crate::retag_pause::keep_on_v1(vault.dir());
    let mut s = VaultStore::open(vault).unwrap();
    let gone = drawer("w1", "a note to be forgotten", 0);
    s.upsert(&gone).unwrap();
    s.upsert(&drawer("w1", "a note that stays", 1)).unwrap();
    let att = s.forget_with_proof(std::slice::from_ref(&gone.id)).unwrap();
    let witness = s.witness_emit().unwrap();
    assert_eq!(
        s.verify_forget_attestation(&att).unwrap(),
        crate::AttestationVerdict::Verified,
        "premise"
    );
    drop(s);
    crate::retag_pause::release(&vdir(root));
    let s = open(root);
    assert_eq!(s.row_format(), RowFormat::V2, "premise: walked");
    assert_eq!(
        s.verify_forget_attestation(&att).unwrap(),
        crate::AttestationVerdict::Verified
    );
    assert!(matches!(
        s.witness_check(&witness).unwrap(),
        crate::WitnessVerdict::Extends { rows_since: 1, .. }
    ));
}

/// **P15k's second half**: the walk withholds over every row it would bind
/// — a drawer whose meta does not parse (O231), a fact re-partitioned under
/// its tag, a tag carried from a fact onto a drawer — writes nothing, and
/// names why; deleting one row leaves it withheld on the others.
#[test]
fn p15k_the_walk_withholds_over_each_moved_row_and_names_it() {
    let dir = legacy(SecurityLevel::HmacOnly);
    let root = dir.path();
    crate::retag_pause::keep_on_v1(&vdir(root));
    let mut s = open(root);
    // (1) an O231 row: the meta/content boundary moved to a 0x1f in content.
    let victim = drawer("w1", "alpha\u{1f}omega", 5);
    s.upsert(&victim).unwrap();
    let moved = s
        .conn
        .execute(
            "UPDATE drawers SET \
               meta_json = meta_json || char(31) || \
                 CAST(substr(content, 1, instr(content, x'1f') - 1) AS TEXT), \
               content = substr(content, instr(content, x'1f') + 1) \
             WHERE id = ?1",
            [&victim.id],
        )
        .unwrap();
    assert_eq!(moved, 1);
    // (2) an E7 split: an agent's object carries the support separator, and
    // a keyless writer strips it into `support` — the fact's id moves.
    let fid = s
        .kg_add(
            "rhea",
            "said",
            "x\u{1f}{\"spans\":[]}",
            None,
            None,
            0.5,
            None,
        )
        .unwrap();
    s.conn
        .execute(
            "UPDATE kg_triples SET object = CAST('x' AS BLOB), support = CAST('{\"spans\":[]}' AS BLOB) \
             WHERE id = ?1",
            [&fid],
        )
        .unwrap();
    let r = s.verify().unwrap();
    assert!(
        r.identity
            .iter()
            .any(|i| i.starts_with(&format!("kg/{fid}:"))),
        "premise: the split is an identity finding: {r:?}"
    );
    assert!(
        !r.bad_records
            .iter()
            .any(|b| b.record == format!("kg/{fid}")),
        "premise: and its version-1 tag still verifies: {r:?}"
    );
    drop(s);
    crate::retag_pause::release(&vdir(root));
    let before = std::fs::read(vdir(root).join("vault.json")).unwrap();
    let s = open(root);
    assert_eq!(s.row_format(), RowFormat::V1, "withheld");
    assert_eq!(commitments(&s), 0, "and nothing appended");
    assert_eq!(
        std::fs::read(vdir(root).join("vault.json")).unwrap(),
        before,
        "nor the manifest raised"
    );
    let note = s
        .unhealed()
        .iter()
        .find(|n| n.contains("WITHHELD"))
        .cloned()
        .expect("it says why");
    assert!(note.contains(&victim.id) && note.contains(&fid), "{note}");
    let mut s = s;
    s.delete_drawer(&victim.id).unwrap();
    drop(s);
    let s = open(root);
    assert_eq!(s.row_format(), RowFormat::V1, "still withheld on the fact");
    assert!(
        s.unhealed()
            .iter()
            .any(|n| n.contains("WITHHELD") && n.contains(&fid)),
        "{:?}",
        s.unhealed()
    );
    // The fact read door refuses the moved fact, the decision `verify` takes.
    assert!(matches!(
        s.kg_query_entity("rhea", None, "both", Read::Returned(ReadOp::KgQuery)),
        Err(StoreError::IntegrityFinding(_))
    ));
}

/// **The walk never fails the open** (review of O406): a `kg_blind_secret`
/// flipped offline in `meta` made the walk's warm-up return `CorruptRow`
/// through EVERY writable open of an unwalked vault. It withholds, says why,
/// and the vault opens on version 1, where `verify` can name the damage.
#[test]
fn a_secret_that_does_not_open_withholds_the_walk_and_never_fails_the_open() {
    let dir = legacy(SecurityLevel::Sealed);
    let root = dir.path();
    {
        let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
        let n = c
            .execute(
                "UPDATE meta SET value = CASE WHEN substr(value, 1, 1) = '0' THEN '1' ELSE '0' \
                 END || substr(value, 2) WHERE key = 'kg_blind_secret'",
                [],
            )
            .unwrap();
        assert_eq!(n, 1, "premise: the vault holds a secret");
    }
    let s = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).expect("the open is not refused");
    assert_eq!(s.row_format(), RowFormat::V1);
    assert!(
        s.unhealed()
            .iter()
            .any(|n| n.contains("WITHHELD") && n.contains("knowledge-graph secret")),
        "{:?}",
        s.unhealed()
    );
    assert_eq!(commitments(&s), 0, "nothing appended");
}

/// **ROADMAP O419**: a `-0.0` confidence is stored as the `+0.0` the
/// database reads back, and tagged as stored, at both write doors — so on a
/// vault still on version 1, whose tags must stay the released bytes, the
/// fact verifies, and a rotation completes. It failed its own tag there, and
/// an MCP agent could keep a vault's walk withheld with one such fact.
#[test]
fn o419_a_negative_zero_confidence_is_stored_as_read_and_verifies() {
    let dir = TempDir::new().unwrap();
    let vault = mgr(dir.path())
        .create(VAULT, SecurityLevel::HmacOnly)
        .unwrap();
    crate::retag_pause::keep_on_v1(vault.dir());
    let mut s = VaultStore::open(vault).unwrap();
    assert_eq!(s.row_format(), RowFormat::V1, "premise: version 1");
    let id = s.kg_add("s", "p", "o", None, None, -0.0, None).unwrap();
    let mut exp = s
        .kg_export(Read::Internal(InternalRead::ExportAudited))
        .unwrap()
        .into_iter()
        .find(|e| e.triple.id == id)
        .unwrap();
    let r = s.verify().unwrap();
    assert!(r.ok(), "the add: {r:?}");
    // The import door, over the same row: its upsert stores the payload's.
    exp.triple.confidence = -0.0;
    assert_eq!(s.kg_import(&exp).unwrap(), id);
    {
        let fact = &id;
        let q: String = s
            .conn
            .query_row(
                "SELECT quote(confidence) FROM kg_triples WHERE id = ?1",
                [fact],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(q, "0.0", "stored as it reads back");
    }
    let r = s.verify().unwrap();
    assert!(r.ok(), "{r:?}");
    let m = mgr(dir.path());
    s.rotate_keys(m.rotation_candidate(VAULT).unwrap())
        .expect("a rotation completes");
}

/// **ROADMAP O406 item 10**: an empty date, or one holding a control
/// character, is refused at the graph's one write path, on both bounds; an
/// absent one is an open window; and a re-add that spells a stored date
/// differently keeps the row its tag covers (item 1: the upsert's SET list
/// carries `valid_from`).
#[test]
fn an_empty_or_control_date_is_refused_and_a_re_add_keeps_its_own_tag() {
    let dir = TempDir::new().unwrap();
    let mut s = VaultStore::open(
        mgr(dir.path())
            .create(VAULT, SecurityLevel::HmacOnly)
            .unwrap(),
    )
    .unwrap();
    for (vf, vt) in [
        (Some(""), None),
        (None, Some("")),
        (Some("2026-01-01\n"), None),
        (None, Some("2026\u{1f}")),
    ] {
        assert!(
            matches!(
                s.kg_add("s", "p", "o", vf, vt, 0.5, None),
                Err(StoreError::Invalid(ref m)) if m.contains("empty or holds a control")
            ),
            "{vf:?} {vt:?}"
        );
    }
    let id = s.kg_add("s", "p", "o", None, None, 0.5, None).unwrap();
    // An import spelling the absent bound as '' lands on the same id and
    // keeps what it stored under the tag it computed.
    let mut exp = s
        .kg_export(Read::Internal(InternalRead::ExportAudited))
        .unwrap()
        .into_iter()
        .find(|e| e.triple.id == id)
        .unwrap();
    exp.triple.valid_from = Some(String::new());
    assert_eq!(s.kg_import(&exp).unwrap(), id);
    let vf: Option<String> = s
        .conn
        .query_row(
            "SELECT valid_from FROM kg_triples WHERE id = ?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(vf.as_deref(), Some(""), "the row holds what the tag covers");
    assert!(s.verify().unwrap().ok(), "and verifies");
}

/// **Turn a walked vault back into the version-1 shape every release before
/// ROADMAP O406 wrote** — row tags in version 1, the audit records holding
/// those tags, no tag commitment, a version-1 manifest. A test fixture, here
/// rather than in `lib.rs` because it rewrites `audit.tag`, which no
/// production path does (`the_chain_has_one_owner_in_this_crate`).
/// `VaultStore::unswitch_chain_for_test` calls it before it re-steps the chain.
pub(crate) fn unwalk_for_test(s: &mut VaultStore) {
    if s.row_format() != RowFormat::V2 {
        return;
    }
    // Every tag-bearing column, in one stable order, so the version-2
    // tags the audit records hold can be put back to the version-1
    // ones a legacy vault's records hold — a record and its row agree
    // on a legacy vault, and the version leg compares the two.
    let tags = |conn: &rusqlite::Connection| -> Vec<Option<Vec<u8>>> {
        let mut out = Vec::new();
        for sql in [
            "SELECT tag FROM drawers ORDER BY seq",
            "SELECT supersedes_receipt FROM drawers ORDER BY seq",
            "SELECT tag FROM kg_triples ORDER BY seq",
            "SELECT receipt_tag FROM kg_triples ORDER BY seq",
            "SELECT tag FROM kg_entities ORDER BY rowid",
            "SELECT tag FROM tunnels ORDER BY seq",
            "SELECT tag FROM wing_trust ORDER BY rowid",
            "SELECT tag FROM retention_policy ORDER BY rowid",
        ] {
            let mut stmt = conn.prepare(sql).unwrap();
            let rows = stmt
                .query_map([], |r| r.get::<_, Option<Vec<u8>>>(0))
                .unwrap();
            out.extend(rows.map(Result::unwrap));
        }
        out
    };
    let v2 = tags(&s.conn);
    let back = s
        .retag_rows(
            &s.vault,
            undercroft_vault::RowFormat::V1,
            crate::rotate::Reseal::No,
        )
        .unwrap();
    s.apply_retagged(&s.conn, &back).unwrap();
    for (old, new) in v2.iter().zip(tags(&s.conn)) {
        if let (Some(old), Some(new)) = (old, new) {
            s.conn
                .execute(
                    "UPDATE audit SET tag = ?1 WHERE tag = ?2",
                    rusqlite::params![new, old],
                )
                .unwrap();
        }
    }
    s.conn
        .execute(
            "DELETE FROM audit WHERE record_id = ?1",
            rusqlite::params![crate::retag::commitment_label()],
        )
        .unwrap();
    s.row_format.set(undercroft_vault::RowFormat::V1);
    undercroft_vault::fixture::set_manifest_version(&mut s.vault, 1);
}
