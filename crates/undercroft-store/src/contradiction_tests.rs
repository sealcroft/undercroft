//! ROADMAP O296: a writable open judges the audit chain before any rotation
//! effect, and a database that contradicts its manifest is refused with
//! nothing written.
//!
//! `reconcile_rotation` decided the rotation verdict from the database's clear
//! `meta.keycheck` and ACTED on it — removed `vault.json.next`, wrote the
//! staged manifest over the retired one, seeded or re-seeded the marker — and
//! committed, and only then did `init_chain` find that the rows answered to
//! neither generation and refuse. Every contradicting state below did that on
//! `main`, at both security levels; the refusal CLASS was already the one it
//! is now, so every arm asserts the files' bytes, the marker, `chain_meta` and
//! the `audit` row count over two writable opens and a read-only one. Only
//! those tell the fix from the defect.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::OptionalExtension;
use tempfile::TempDir;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{fixture, Access, SecurityLevel, VaultError, VaultManager};

use crate::rotate_pause as pause;
use crate::{StoreError, VaultStore};

const VAULT: &str = "o296";
const LEVELS: [SecurityLevel; 2] = [SecurityLevel::HmacOnly, SecurityLevel::Sealed];

fn mgr(root: &Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn manifest(root: &Path) -> PathBuf {
    vdir(root).join("vault.json")
}

fn staging(root: &Path) -> PathBuf {
    vdir(root).join("vault.json.next")
}

fn drawer(tag: &str, i: u32) -> Drawer {
    Drawer::new(
        "w1",
        "r",
        format!("{tag} {i}: the harbour ledger names cargo {i} for the eastern quay"),
        Some(format!("{tag}.md")),
        i,
        "test",
    )
}

fn db(root: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap()
}

/// Everything a rotation reconcile could write, read with no store.
#[derive(Debug, PartialEq, Eq)]
struct Disk {
    manifest: Option<Vec<u8>>,
    staged: Option<Vec<u8>>,
    keycheck: Option<String>,
    chain_meta: Option<Vec<(String, String)>>,
    audit_rows: i64,
}

fn disk(root: &Path) -> Disk {
    let c = rusqlite::Connection::open_with_flags(
        vdir(root).join("vault.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let chain_meta = c
        .prepare("SELECT key, value FROM chain_meta ORDER BY key")
        .ok()
        .map(|mut st| {
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        });
    Disk {
        manifest: std::fs::read(manifest(root)).ok(),
        staged: std::fs::read(staging(root)).ok(),
        keycheck: c
            .query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
                r.get(0)
            })
            .optional()
            .unwrap(),
        chain_meta,
        audit_rows: c
            .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
            .unwrap(),
    }
}

fn keycheck(root: &Path) -> Option<String> {
    disk(root).keycheck
}

fn set_keycheck(root: &Path, kc: Option<&str>) {
    let c = db(root);
    match kc {
        None => {
            assert_eq!(
                c.execute("DELETE FROM meta WHERE key = 'keycheck'", [])
                    .unwrap(),
                1,
                "premise: a marker to delete"
            );
        }
        Some(v) => {
            c.execute(
                "INSERT INTO meta (key, value) VALUES ('keycheck', ?1) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [v],
            )
            .unwrap();
        }
    }
}

fn head_in(p: &Path) -> String {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    v["chain_head_hex"].as_str().unwrap().to_string()
}

/// Set `chain_meta`'s LIVE head — a clear, unauthenticated value — to `head`.
fn forge_head(root: &Path, head: &str) {
    assert_eq!(
        db(root)
            .execute(
                "UPDATE chain_meta SET value = ?1 WHERE key = 'head_v2'",
                [head]
            )
            .unwrap(),
        1,
        "premise: a version-2 head to forge"
    );
}

/// Delete the chain's committed heads and its version-2 commitment, so it
/// reads as unseeded; `all` deletes every `chain_meta` row, `writes` included.
fn unseed(root: &Path, all: bool) {
    let c = db(root);
    let sql = if all {
        "DELETE FROM chain_meta"
    } else {
        "DELETE FROM chain_meta WHERE key IN ('head', 'head_v2')"
    };
    assert!(c.execute(sql, []).unwrap() >= 1, "premise: heads");
    assert_eq!(
        c.execute(
            "DELETE FROM audit WHERE record_id = ?1",
            [crate::chain::commitment_label()]
        )
        .unwrap(),
        1,
        "premise: the version-2 commitment"
    );
}

fn plain(root: &Path, level: SecurityLevel, n: u32) {
    let mut w = VaultStore::open(mgr(root).create(VAULT, level).unwrap()).unwrap();
    w.upsert_many(&(0..n).map(|i| drawer("note", i)).collect::<Vec<_>>())
        .unwrap();
}

fn writable(root: &Path) -> Result<VaultStore, StoreError> {
    VaultStore::open(mgr(root).unlock(VAULT)?)
}

fn read_only(root: &Path) -> Result<VaultStore, StoreError> {
    let m = VaultManager::open_as(root, None, Access::ReadOnly)?;
    VaultStore::open_read_only(
        m.unlock_as(VAULT, Access::ReadOnly)?,
        Box::new(HashEmbedder),
    )
}

fn write_some(root: &Path, from: u32, n: u32) {
    let mut s = writable(root).unwrap();
    for i in 0..n {
        s.upsert(&drawer("more", from + i)).unwrap();
    }
}

fn copy_db(root: &Path) {
    db(root)
        .execute("VACUUM INTO ?1", [root.join("copy.db").to_str().unwrap()])
        .unwrap();
}

fn restore_db(root: &Path) {
    for f in ["vault.db", "vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(vdir(root).join(f));
    }
    std::fs::copy(root.join("copy.db"), vdir(root).join("vault.db")).unwrap();
}

/// A rotation that commits and fails every promote attempt, through the fault
/// seam: `vault.json` the retired bytes R, `.next` the staged manifest S, the
/// marker the staged generation's.
fn rotate_deferred(root: &Path) {
    let m = mgr(root);
    let mut w = writable(root).unwrap();
    pause::set(
        &vdir(root),
        Arc::new(|phase| {
            if phase == pause::Phase::Committed {
                fixture::fail_times(fixture::Fault::Rename, crate::rotate::PROMOTE_ATTEMPTS);
            }
        }),
    );
    let rep = w.rotate_keys(m.rotation_candidate(VAULT).unwrap()).unwrap();
    pause::set(&vdir(root), Arc::new(|_| {}));
    assert!(rep.promote_deferred.is_some(), "premise: deferred");
    assert!(staging(root).exists(), "premise: staged");
}

/// A rotation that stages and aborts before its commit: an abandoned `.next`
/// beside the vault's own `vault.json`, the marker this generation's.
fn rotate_aborted(root: &Path) {
    let m = mgr(root);
    let mut w = writable(root).unwrap();
    pause::set(
        &vdir(root),
        Arc::new(|phase| {
            if phase == pause::Phase::Staged {
                panic!("abort the rotation before its commit");
            }
        }),
    );
    let cand = m.rotation_candidate(VAULT).unwrap();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| w.rotate_keys(cand)));
    pause::set(&vdir(root), Arc::new(|_| {}));
    assert!(r.is_err(), "premise: the rotation aborted");
    assert!(staging(root).exists(), "premise: its stage stayed");
}

fn rotate_plain(root: &Path) {
    let m = mgr(root);
    let mut w = writable(root).unwrap();
    w.rotate_keys(m.rotation_candidate(VAULT).unwrap()).unwrap();
}

/// What a refusal must be — its VARIANT and a fragment of its text: three
/// integrity variants exit 2, so a class alone passes on `main`.
#[derive(Clone, Copy, Debug)]
enum Want {
    /// `Integrity("audit-chain head")`: a head the rows do not reproduce.
    Head,
    /// `ManifestTampered`: an anchor the rows never reach.
    Tampered,
    /// `IntegrityFinding` whose text carries this fragment.
    Finding(&'static str),
    /// `CorruptManifest` whose text carries this fragment.
    Corrupt(&'static str),
}

fn is(e: &StoreError, want: Want) -> bool {
    match (want, e) {
        (Want::Head, StoreError::Integrity(m)) => m == "audit-chain head",
        (Want::Tampered, StoreError::Vault(VaultError::ManifestTampered)) => true,
        (Want::Finding(t), StoreError::IntegrityFinding(m)) => m.contains(t),
        (Want::Corrupt(t), StoreError::Vault(VaultError::CorruptManifest(m))) => m.contains(t),
        _ => false,
    }
}

/// What the read-only open answers the same state with: it writes nothing on
/// any of them, and on the forged-head and unseeded rows it SERVES where the
/// writable open refuses — the divergence O296's ruling states.
#[derive(Clone, Copy, Debug)]
enum ReadOnly {
    Refuses(Want),
    Serves,
    /// `ReadOnlyUnmigrated`: a schema the posture may not create — with no
    /// `chain_meta` table the read-only open cannot read the chain at all.
    Declines,
}

/// Two writable opens refuse as `want` and write NOTHING; the read-only open
/// answers as `ro` and writes nothing either.
fn refused(label: &str, root: &Path, want: Want, ro: ReadOnly) {
    let before = disk(root);
    for n in 1..=2 {
        match writable(root) {
            Ok(s) => panic!(
                "{label}: writable open #{n} served, height {:?}, notes {:?}",
                s.chain_state().map(|c| c.1),
                s.unhealed()
            ),
            Err(e) => assert!(is(&e, want), "{label}: writable open #{n}: {e}"),
        }
        assert_eq!(
            disk(root),
            before,
            "{label}: writable open #{n} wrote before it refused"
        );
    }
    match (ro, read_only(root)) {
        (ReadOnly::Refuses(w), Err(e)) => assert!(is(&e, w), "{label}: read-only: {e}"),
        (ReadOnly::Declines, Err(StoreError::ReadOnlyUnmigrated { .. })) => {}
        (ReadOnly::Serves, Ok(_)) => {}
        (ro, other) => panic!(
            "{label}: read-only expected {ro:?}, got {:?}",
            other.as_ref().err()
        ),
    }
    assert_eq!(disk(root), before, "{label}: the read-only open");
}

/// **The filing's first route**: during a deferral the keycheck row deleted.
/// The open read `Abandoned`, deleted `.next` — the only copy of the staged
/// generation's salt — seeded the retired generation's marker over a database
/// sealed under the new one, and only then refused. The chain answers to the
/// staged keys, and O296 still refuses (option B): no build writes this state,
/// and a heal on the chain's evidence would trust what a transplant can copy.
#[test]
fn o296_a_deleted_marker_during_a_deferral_is_refused_and_writes_nothing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        rotate_deferred(root);
        set_keycheck(root, None);
        refused(
            &format!("{level:?} kc_absent"),
            root,
            Want::Head,
            ReadOnly::Refuses(Want::Head),
        );
        assert!(staging(root).exists(), "{level:?}: the staged salt kept");
    }
}

/// The retired generation's marker PLANTED during a deferral (a clear value,
/// copied from any older copy of the database): `Abandoned` again, and `.next`
/// was deleted before the refusal.
#[test]
fn o296_a_planted_old_marker_during_a_deferral_is_refused_and_writes_nothing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        let g0 = keycheck(root).unwrap();
        rotate_deferred(root);
        assert_ne!(keycheck(root).as_deref(), Some(g0.as_str()), "premise");
        set_keycheck(root, Some(&g0));
        refused(
            &format!("{level:?} g0marker"),
            root,
            Want::Head,
            ReadOnly::Refuses(Want::Head),
        );
    }
}

/// **The filing's second route**: a pre-rotation database copy two writes
/// behind the retired manifest's anchor, restored during a deferral. Its chain
/// answers to the handle's keys — the anchor-blind check this replaced said so
/// — and never reaches the anchor: a rollback, `ManifestTampered`, and `.next`
/// was deleted before it.
#[test]
fn o296_a_pre_rotation_database_behind_the_anchor_is_refused_and_writes_nothing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 18);
        copy_db(root);
        write_some(root, 18, 2);
        rotate_deferred(root);
        restore_db(root);
        refused(
            &format!("{level:?} predb_behind"),
            root,
            Want::Tampered,
            ReadOnly::Refuses(Want::Tampered),
        );
    }
}

/// **The `Committed` arm, which the filing did not name**: a pre-rotation
/// database restored during a deferral with the live staged-generation marker
/// copied onto it. The licence's files were exactly what the unlock read, so
/// the open wrote the staged manifest OVER the retired one — the only manifest
/// that database answers to — removed `.next`, and then refused. The judgement
/// under the staged keys now refuses first: both manifests are kept.
#[test]
fn o296_a_copied_marker_over_an_old_database_never_promotes_over_its_manifest() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        copy_db(root);
        rotate_deferred(root);
        let g1 = keycheck(root).unwrap();
        restore_db(root);
        set_keycheck(root, Some(&g1));
        let retired = std::fs::read(manifest(root)).unwrap();
        refused(
            &format!("{level:?} committed_g0db"),
            root,
            Want::Head,
            ReadOnly::Refuses(Want::Head),
        );
        assert_eq!(
            std::fs::read(manifest(root)).unwrap(),
            retired,
            "{level:?}: the retired manifest, which the database answers to, kept"
        );
    }
}

/// **The `Foreign` heal over a rollback**: a database two writes behind its
/// anchor, beside a foreign marker. The anchor-blind check passed it, the
/// marker was re-seeded over the edit, and then the open refused. The foreign
/// judgement reaches the anchor now: `ManifestTampered` first, and the planted
/// marker stays as evidence.
#[test]
fn o296_a_foreign_marker_over_a_rollback_is_tampering_before_any_reseed() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 18);
        copy_db(root);
        write_some(root, 18, 2);
        restore_db(root);
        set_keycheck(root, Some(&"ab".repeat(32)));
        refused(
            &format!("{level:?} foreign_behind"),
            root,
            Want::Tampered,
            ReadOnly::Refuses(Want::Tampered),
        );
        assert_eq!(keycheck(root), Some("ab".repeat(32)), "{level:?}");
    }
}

/// **The `Settled` arm's absent-marker seed**: an older generation's
/// `vault.json` put back over a rotated vault, the marker deleted. The open
/// seeded the old generation's marker over a database sealed under the new
/// one, then refused; it now judges first.
#[test]
fn o296_an_old_manifest_over_a_rotated_database_seeds_nothing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        let r = std::fs::read(manifest(root)).unwrap();
        rotate_plain(root);
        std::fs::write(manifest(root), &r).unwrap();
        set_keycheck(root, None);
        refused(
            &format!("{level:?} settled_oldmanifest"),
            root,
            Want::Head,
            ReadOnly::Refuses(Want::Head),
        );
        assert_eq!(keycheck(root), None, "{level:?}: nothing seeded");
    }
}

/// **The replay is FORCED before an effect.** With `chain_meta`'s clear head
/// also set to the anchor in the manifest, the ordinary open's short-circuit
/// reads `Current` without replaying: on `main` the open deleted `.next`, or
/// wrote the staged manifest over the retired one, and then OPENED Ok. The
/// keyed replay reproduces neither head. The read-only open still serves these
/// (its check keeps the short-circuit, and it writes nothing) — the divergence
/// the ruling states.
#[test]
fn o296_a_forged_head_cannot_license_a_rotation_effect() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        rotate_deferred(root);
        set_keycheck(root, None);
        forge_head(root, &head_in(&manifest(root)));
        refused(
            &format!("{level:?} kc_absent + head forged to R"),
            root,
            Want::Head,
            ReadOnly::Serves,
        );

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        copy_db(root);
        rotate_deferred(root);
        let g1 = keycheck(root).unwrap();
        let s_head = head_in(&staging(root));
        restore_db(root);
        set_keycheck(root, Some(&g1));
        forge_head(root, &s_head);
        refused(
            &format!("{level:?} committed_g0db + head forged to S"),
            root,
            Want::Head,
            ReadOnly::Serves,
        );
    }
}

/// **The foreign heal keeps its full replay** (the refuter's P-D): a foreign
/// marker beside a rollback whose head is forged to the anchor. The check this
/// replaced replayed in full and refused; a judgement that short-circuited
/// would read `Current` and heal. O257's text is kept.
#[test]
fn o296_a_foreign_marker_over_a_forged_rollback_is_still_refused() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 18);
        copy_db(root);
        write_some(root, 18, 2);
        restore_db(root);
        set_keycheck(root, Some(&"ab".repeat(32)));
        forge_head(root, &head_in(&manifest(root)));
        let generations = Want::Finding("from different key generations");
        refused(
            &format!("{level:?} pd"),
            root,
            generations,
            ReadOnly::Refuses(generations),
        );
    }
}

/// **No committed head beside a stage**: the heads and the version-2
/// commitment deleted (a partial deletion, `writes` left, which answered a raw
/// `UNIQUE` error — a 500 — after deleting `.next`), or every `chain_meta` row
/// (which OPENED Ok after deleting `.next`), or the whole table dropped. No
/// build writes any of them beside a stage; each refuses with nothing written.
#[test]
fn o296_no_committed_head_beside_a_stage_is_refused_and_writes_nothing() {
    let unseeded = Want::Finding("no committed audit-chain head");
    for level in LEVELS {
        for all in [false, true] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            plain(root, level, 18);
            copy_db(root);
            write_some(root, 18, 2);
            rotate_deferred(root);
            restore_db(root);
            unseed(root, all);
            refused(
                &format!("{level:?} unseeded (all={all}) beside an abandoned twin"),
                root,
                unseeded,
                ReadOnly::Serves,
            );

            let dir = TempDir::new().unwrap();
            let root = dir.path();
            plain(root, level, 20);
            copy_db(root);
            rotate_deferred(root);
            let g1 = keycheck(root).unwrap();
            restore_db(root);
            set_keycheck(root, Some(&g1));
            unseed(root, all);
            let retired = std::fs::read(manifest(root)).unwrap();
            refused(
                &format!("{level:?} unseeded (all={all}) beside a committed twin"),
                root,
                unseeded,
                ReadOnly::Serves,
            );
            assert_eq!(std::fs::read(manifest(root)).unwrap(), retired);
        }
        // A FOREIGN marker beside no committed head, no stage at all: on
        // `main` the anchor-blind check read it as answering, re-seeded the
        // marker and let `init_chain` adopt `chain_meta` from the manifest — Ok,
        // or a raw `UNIQUE` error with `writes` left. Refused on both postures
        // now, O257's foreign judgement having nothing to judge by.
        for all in [false, true] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            plain(root, level, 20);
            set_keycheck(root, Some(&"ab".repeat(32)));
            unseed(root, all);
            let foreign = Want::Finding("no committed audit-chain head to judge which generation");
            refused(
                &format!("{level:?} unseeded (all={all}) beside a foreign marker"),
                root,
                foreign,
                ReadOnly::Refuses(foreign),
            );
            assert_eq!(keycheck(root), Some("ab".repeat(32)), "{level:?}");
        }
        // The table dropped outright, the commitment still in `audit`: the
        // regime says version 2 and nothing holds its head.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        rotate_deferred(root);
        db(root).execute_batch("DROP TABLE chain_meta").unwrap();
        refused(
            &format!("{level:?} chain_meta dropped beside a committed twin"),
            root,
            Want::Finding("no `chain_meta` table"),
            ReadOnly::Declines,
        );
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        rotate_aborted(root);
        db(root).execute_batch("DROP TABLE chain_meta").unwrap();
        refused(
            &format!("{level:?} chain_meta dropped beside an abandoned twin"),
            root,
            Want::Finding("no `chain_meta` table"),
            ReadOnly::Declines,
        );
    }
}

/// **The window after a held unlock**: an abandoned stage with the marker
/// absent, and `vault.json` deleted between the unlock and the open. O290's
/// guard kept the stage, but the absent marker was still SEEDED before
/// `init_chain` refused. The anchor's read now refuses before any effect.
#[test]
fn o296_a_held_unlock_whose_manifest_went_seeds_nothing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        rotate_aborted(root);
        set_keycheck(root, None);
        let held = mgr(root).unlock(VAULT).unwrap();
        assert!(held.has_pending(), "premise: the stage is attached");
        std::fs::remove_file(manifest(root)).unwrap();
        let before = disk(root);
        match VaultStore::open(held) {
            Err(e) => assert!(
                is(&e, Want::Corrupt("vault.json is missing from")),
                "{level:?}: {e}"
            ),
            Ok(_) => panic!("{level:?}: served with vault.json gone"),
        }
        assert_eq!(
            disk(root),
            before,
            "{level:?}: nothing seeded, nothing removed"
        );
        assert_eq!(keycheck(root), None, "{level:?}");
    }
}

/// **The states each arm must still settle**, unchanged: a deferral promoted
/// (and one whose `vault.json` is an older file of the retired generation); an
/// abandoned stage beside anchors, and beside an anchor two records behind
/// (the lag healed and said); a promote's leftover; O257's foreign heal and its
/// note; a legacy absent marker; a fresh vault; an absent marker beside a stage
/// the chain says was abandoned.
#[test]
fn o296_every_legitimate_state_still_settles() {
    for level in LEVELS {
        let settled = |label: &str, root: &Path, note: Option<&str>| -> VaultStore {
            let s = writable(root).unwrap_or_else(|e| panic!("{level:?} {label}: {e}"));
            assert!(s.verify().unwrap().ok(), "{level:?} {label}: verify");
            match note {
                Some(n) => assert!(
                    s.unhealed().iter().any(|u| u.contains(n)),
                    "{level:?} {label}: note {n:?} in {:?}",
                    s.unhealed()
                ),
                None => assert!(
                    s.unhealed().is_empty(),
                    "{level:?} {label}: {:?}",
                    s.unhealed()
                ),
            }
            assert!(!staging(root).exists(), "{level:?} {label}: .next settled");
            s
        };

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        rotate_deferred(root);
        let s_bytes = std::fs::read(staging(root)).unwrap();
        drop(settled("deferral", root, None));
        assert_eq!(std::fs::read(manifest(root)).unwrap(), s_bytes);

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        let r0 = std::fs::read(manifest(root)).unwrap();
        write_some(root, 20, 2);
        rotate_deferred(root);
        std::fs::write(manifest(root), &r0).unwrap();
        drop(settled("deferral over an older vault.json", root, None));

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        rotate_aborted(root);
        let stage = std::fs::read(staging(root)).unwrap();
        write_some(root, 20, 3);
        std::fs::write(staging(root), &stage).unwrap();
        let kc = keycheck(root);
        drop(settled("an abandoned stage beside anchors", root, None));
        assert_eq!(keycheck(root), kc);

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        let r0 = std::fs::read(manifest(root)).unwrap();
        write_some(root, 20, 2);
        rotate_aborted(root);
        std::fs::write(manifest(root), &r0).unwrap();
        drop(settled(
            "an abandoned stage beside a lagging anchor",
            root,
            Some("record(s) behind"),
        ));

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        rotate_plain(root);
        std::fs::copy(manifest(root), staging(root)).unwrap();
        drop(settled("a promote's leftover", root, None));

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        let own = keycheck(root);
        set_keycheck(root, Some(&"ab".repeat(32)));
        drop(settled(
            "O257's foreign heal",
            root,
            Some("named another generation"),
        ));
        assert_eq!(keycheck(root), own, "{level:?}: re-seeded");

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        let own = keycheck(root);
        set_keycheck(root, None);
        drop(settled("a legacy absent marker", root, None));
        assert_eq!(keycheck(root), own, "{level:?}: seeded");

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        mgr(root).create(VAULT, level).unwrap();
        let s = settled("a fresh vault", root, None);
        assert_eq!(s.chain_state().unwrap().1, 1);
        assert!(keycheck(root).is_some(), "{level:?}: seeded");

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        let own = keycheck(root);
        rotate_aborted(root);
        set_keycheck(root, None);
        drop(settled(
            "an absent marker beside a stage the chain says was abandoned",
            root,
            None,
        ));
        assert_eq!(keycheck(root), own, "{level:?}: seeded");
    }
}

/// **The costs the ruling pins, each as `main` answers it.** Every value the
/// reconcile consults can be COPIED or TRUNCATED into agreement: a transplant
/// of the staged generation's `rotate/` row, `chain_meta` rows and marker onto
/// a pre-rotation database (rotation preserves audit tags and re-steps only
/// heads, so the staged keys replay it to the staged anchor), and a truncation
/// of the new database back to the retired anchor. The effect then runs and the
/// open answers Ok; `verify` and the first read fail — what deleting the salt
/// file achieves, which the same writer can do directly. A pre-rotation
/// database restored AT the anchor is a crash before the commit to every value
/// there is (A2's). And with no stage at all, a forged head or an emptied
/// `chain_meta` opens Ok (the O(1) open's residual, and O303).
#[test]
fn o296_what_the_judgement_cannot_see_is_pinned() {
    for level in LEVELS {
        // The transplant.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        copy_db(root);
        rotate_deferred(root);
        let s_bytes = std::fs::read(staging(root)).unwrap();
        {
            let live = db(root);
            let copy = rusqlite::Connection::open(root.join("copy.db")).unwrap();
            let max: i64 = copy
                .query_row("SELECT MAX(seq) FROM audit", [], |r| r.get(0))
                .unwrap();
            let mut st = live
                .prepare("SELECT seq, record_id, tag, at FROM audit WHERE seq > ?1")
                .unwrap();
            let rows: Vec<(i64, String, Vec<u8>, String)> = st
                .query_map([max], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(rows.len(), 1, "premise: the rotation's one row");
            for (seq, rid, tag, at) in &rows {
                copy.execute(
                    "INSERT INTO audit (seq, record_id, tag, at) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![seq, rid, tag, at],
                )
                .unwrap();
            }
            let mut st = live.prepare("SELECT key, value FROM chain_meta").unwrap();
            for kv in st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .unwrap()
            {
                let (k, v) = kv.unwrap();
                copy.execute("UPDATE chain_meta SET value = ?2 WHERE key = ?1", [&k, &v])
                    .unwrap();
            }
            let kc: String = live
                .query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            copy.execute("UPDATE meta SET value = ?1 WHERE key = 'keycheck'", [&kc])
                .unwrap();
        }
        restore_db(root);
        let s = writable(root).expect("COST: the transplant is promoted");
        assert!(!s.verify().map(|v| v.ok()).unwrap_or(false), "{level:?}");
        assert_eq!(std::fs::read(manifest(root)).unwrap(), s_bytes, "{level:?}");
        assert!(!staging(root).exists(), "{level:?}");

        // The truncation.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        let g0 = keycheck(root).unwrap();
        rotate_deferred(root);
        let r: serde_json::Value =
            serde_json::from_slice(&std::fs::read(manifest(root)).unwrap()).unwrap();
        {
            let c = db(root);
            assert_eq!(
                c.execute("DELETE FROM audit WHERE record_id LIKE 'rotate/%'", [])
                    .unwrap(),
                1
            );
            c.execute(
                "UPDATE chain_meta SET value = ?1 WHERE key = 'head_v2'",
                [r["chain_head_hex"].as_str().unwrap()],
            )
            .unwrap();
            c.execute(
                "UPDATE chain_meta SET value = ?1 WHERE key = 'writes'",
                [r["writes"].to_string()],
            )
            .unwrap();
        }
        set_keycheck(root, Some(&g0));
        let s = writable(root).expect("COST: the truncation is discarded");
        assert!(!s.verify().map(|v| v.ok()).unwrap_or(false), "{level:?}");
        assert!(!staging(root).exists(), "{level:?}");

        // A pre-rotation database restored at the anchor.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        copy_db(root);
        rotate_deferred(root);
        restore_db(root);
        let s = writable(root).expect("COST: read as a crash before the commit");
        assert!(s.verify().unwrap().ok(), "{level:?}");
        assert!(!staging(root).exists(), "{level:?}");

        // No stage: a forged head, and an emptied `chain_meta` (O303).
        for emptied in [false, true] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            plain(root, level, 18);
            copy_db(root);
            write_some(root, 18, 2);
            restore_db(root);
            if emptied {
                unseed(root, true);
            } else {
                forge_head(root, &head_in(&manifest(root)));
            }
            let s = writable(root).expect("COST: the O(1) open's residual, and O303");
            assert!(!s.verify().unwrap().ok(), "{level:?} emptied={emptied}");
        }
    }
}

/// **O290's guard stays in front of each removal.** The anchor's read FALLS
/// BACK to the handle's cached head over a `vault.json` it cannot read, so the
/// judgement answers; the guard's strict read does not fall back, and an
/// abandoned stage beside a manifest this open could not read is kept. The
/// fault seam stands in for an unreadable file, which permissions cannot make
/// for a test running as root.
#[test]
fn o296_the_judgement_does_not_replace_the_removal_guard() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        rotate_aborted(root);
        let stage = std::fs::read(staging(root)).unwrap();
        let held = mgr(root).unlock(VAULT).unwrap();
        assert!(held.has_pending(), "premise: the stage is attached");
        // Control: the anchor's read alone fails, the judgement answers on the
        // cached head, and the stage is removed — the guard's read succeeded.
        {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            plain(root, level, 20);
            rotate_aborted(root);
            let held = mgr(root).unlock(VAULT).unwrap();
            fixture::fail_next(fixture::Fault::RuleRead);
            let opened = VaultStore::open(held);
            assert_eq!(
                fixture::armed(),
                None,
                "{level:?}: premise: the rule's read failed"
            );
            opened.unwrap_or_else(|e| panic!("{level:?} control: {e}"));
            assert!(
                !staging(root).exists(),
                "{level:?} control: the judgement answered over the fallen-back anchor"
            );
        }
        fixture::fail_in_turn(fixture::Fault::RuleRead, fixture::Fault::Read);
        let opened = VaultStore::open(held);
        assert_eq!(
            fixture::armed(),
            None,
            "{level:?}: premise: both reads failed"
        );
        opened.unwrap_or_else(|e| panic!("{level:?}: {e}"));
        assert_eq!(
            std::fs::read(staging(root)).ok(),
            Some(stage),
            "{level:?}: the stage kept beside a manifest the open could not read"
        );
    }
}

fn flip_mac(p: &Path) {
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    let mac = v["manifest_mac_hex"].as_str().unwrap().to_string();
    let first = if mac.starts_with('0') { "1" } else { "0" };
    v["manifest_mac_hex"] = serde_json::Value::String(format!("{first}{}", &mac[1..]));
    std::fs::write(p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

/// **The licence is acted on one forced replay after it is asked — a cost this
/// unit widened, PINNED and filed as ROADMAP O304.** On the staged branch the
/// licence reads `.next` and `vault.json` and decides to write; the judgement
/// then replays the chain under the write lock (about 90 ms at 10^5 audit rows,
/// 836 ms at 10^6); the promote writes on the earlier answer. On `main` the ask
/// and the write were back to back. No legitimate writer can land in the window
/// — an anchor needs the lock, a rotation the fence, a restore or a delete O69's
/// hold — so only an offline edit does, and what it costs is a forged
/// `vault.json` overwritten by the staged manifest the database answers to, with
/// no tamper page: no key and no row is lost. The hook stands where the edit
/// would land.
#[test]
fn o296_the_licence_is_acted_on_after_the_judgement_pinned() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        rotate_deferred(root);
        let staged = std::fs::read(staging(root)).unwrap();
        let held = mgr(root).unlock(VAULT).unwrap();
        let json = manifest(root);
        fixture::between_licence_and_promote(move || flip_mac(&json));
        let s = VaultStore::open(held).expect("COST (O304): the forged manifest is overwritten");
        assert!(s.verify().unwrap().ok(), "{level:?}");
        assert_eq!(
            std::fs::read(manifest(root)).unwrap(),
            staged,
            "{level:?}: the staged manifest written over the forged one"
        );
        assert!(!staging(root).exists(), "{level:?}");
    }
}
