//! ROADMAP O303: an open adopts only an EMPTY head-less chain, and refuses
//! every other with nothing written.
//!
//! `init_chain` seeded a `chain_meta` with no committed head FROM THE
//! MANIFEST, replaying nothing. So a database rolled back beneath its anchor,
//! with `chain_meta` and the version-2 commitment deleted, opened Ok on the
//! writable posture, took writes, and its first write moved the anchor over the
//! only evidence of the rollback; with the height left behind it answered a raw
//! `UNIQUE` error, and with only the height deleted every write answered a raw
//! "Query returned no rows" while `verify` said OK. Every arm below asserts the
//! manifest's bytes, the marker, `chain_meta` (or its absence) and the `audit`
//! row count across two writable opens and a read-only one, at both security
//! levels: the classes alone do not tell the fix from the defect.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use rusqlite::OptionalExtension;
use tempfile::TempDir;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{fixture, Access, SecurityLevel, Vault, VaultError, VaultManager};

use crate::open_pause::{self, Opener};
use crate::{AnchorState, StoreError, VaultStore};

const VAULT: &str = "o303";
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

/// Everything an open could write before it refused, read with no store.
/// `chain_meta` is `None` when the TABLE is absent.
#[derive(Debug, PartialEq, Eq)]
struct Disk {
    manifest: Vec<u8>,
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
        manifest: std::fs::read(manifest(root)).unwrap(),
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

/// A database two records behind the manifest's anchor.
fn rolled_back(root: &Path, level: SecurityLevel) {
    plain(root, level, 18);
    copy_db(root);
    write_some(root, 18, 2);
    restore_db(root);
}

/// Delete the chain's heads — and, with `height`, its height — and the
/// version-2 commitment, so no head is left.
fn behead(root: &Path, height: bool) {
    let c = db(root);
    let sql = if height {
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

/// A version-1 chain — every vault written before O233 — anchored at its head.
fn to_v1(root: &Path) {
    writable(root).unwrap().unswitch_chain_for_test();
}

fn delete_marker(root: &Path) {
    assert_eq!(
        db(root)
            .execute("DELETE FROM meta WHERE key = 'keycheck'", [])
            .unwrap(),
        1,
        "premise: a marker to delete"
    );
}

/// A fresh vault's EMPTY chain as a crash between the table's creation and
/// its seed leaves it: the database's schema, no `audit` row, `chain_meta`
/// empty (or, with `table` false, absent) and the manifest at genesis and
/// height 0 — made by opening the vault once and putting back the manifest
/// its `create` wrote, since no fault seam stops an open there.
fn empty_chain(root: &Path, level: SecurityLevel, table: bool) {
    mgr(root).create(VAULT, level).unwrap();
    let genesis = std::fs::read(manifest(root)).unwrap();
    drop(writable(root).unwrap());
    let c = db(root);
    if table {
        c.execute("DELETE FROM chain_meta", []).unwrap();
    } else {
        c.execute_batch("DROP TABLE chain_meta").unwrap();
    }
    c.execute("DELETE FROM audit", []).unwrap();
    drop(c);
    std::fs::write(manifest(root), &genesis).unwrap();
    let d = disk(root);
    assert_eq!(d.audit_rows, 0, "premise: no record");
    assert_eq!(
        d.chain_meta.map(|m| m.len()),
        if table { Some(0) } else { None },
        "premise: no head and no height"
    );
}

/// What a refusal must be — its VARIANT and a fragment of its text.
#[derive(Clone, Copy, Debug)]
enum Want {
    /// `ManifestTampered`: an anchor the rows never reach.
    Tampered,
    /// `IntegrityFinding` whose text carries this fragment.
    Finding(&'static str),
}

fn is(e: &StoreError, want: Want) -> bool {
    match (want, e) {
        (Want::Tampered, StoreError::Vault(VaultError::ManifestTampered)) => true,
        (Want::Finding(t), StoreError::IntegrityFinding(m)) => m.contains(t),
        _ => false,
    }
}

/// What the read-only open answers the same state with. It writes nothing.
#[derive(Clone, Copy, Debug)]
enum ReadOnly {
    /// Refused at the open.
    Refuses(Want),
    /// Opened, the finding REPORTED on `unhealed` (O233 item 3) — and the
    /// chain's height, `stats`' source, is the same finding, never a raw
    /// error or a `CorruptRow` (a 500).
    Reports(&'static str),
}

const RECORDS: &str = "holds no committed head while `audit` holds records";
const HEIGHT: &str = "holds no committed head while `chain_meta` holds a committed height";
const NO_HEIGHT: &str = "a committed head with no committed height";

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
        (ReadOnly::Reports(t), Ok(s)) => {
            assert!(
                s.unhealed().iter().any(|n| n.contains(t)),
                "{label}: read-only reports it: {:?}",
                s.unhealed()
            );
            match s.chain_state() {
                Err(StoreError::IntegrityFinding(_)) => {}
                other => panic!("{label}: read-only height: {:?}", other.map(|c| c.1)),
            }
        }
        (ro, other) => panic!(
            "{label}: read-only expected {ro:?}, got {:?}",
            other.as_ref().err()
        ),
    }
    assert_eq!(disk(root), before, "{label}: the read-only open");
}

/// **The filing's route, and its neighbours**: a database two records behind
/// its anchor with every `chain_meta` row and the version-2 commitment deleted
/// OPENED at the manifest's height, took a write, and that write moved the
/// anchor over the rollback. The same with no rollback at all, with the marker
/// deleted too (the rotation reconcile's lock path then seeded a marker first),
/// and on a never-switched version-1 chain. Each is refused with nothing
/// written; the read-only open reports it and serves, as it reports any chain
/// a writable open refuses.
#[test]
fn o303_a_headless_chain_with_records_is_refused_and_writes_nothing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        rolled_back(root, level);
        behead(root, true);
        refused(
            &format!("{level:?} rollback, chain_meta emptied"),
            root,
            Want::Finding(RECORDS),
            ReadOnly::Reports(RECORDS),
        );

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        rolled_back(root, level);
        behead(root, true);
        delete_marker(root);
        refused(
            &format!("{level:?} rollback, chain_meta and the marker deleted"),
            root,
            Want::Finding(RECORDS),
            ReadOnly::Reports(RECORDS),
        );
        assert_eq!(keycheck_of(root), None, "{level:?}: no marker seeded");

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        behead(root, true);
        refused(
            &format!("{level:?} no rollback, chain_meta emptied"),
            root,
            Want::Finding(RECORDS),
            ReadOnly::Reports(RECORDS),
        );

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        to_v1(root);
        {
            let c = db(root);
            c.execute(
                "DELETE FROM audit WHERE seq IN (SELECT seq FROM audit ORDER BY seq DESC LIMIT 2)",
                [],
            )
            .unwrap();
            c.execute("DELETE FROM chain_meta", []).unwrap();
        }
        refused(
            &format!("{level:?} version-1 rollback, chain_meta emptied"),
            root,
            Want::Finding(RECORDS),
            ReadOnly::Reports(RECORDS),
        );
    }
}

fn keycheck_of(root: &Path) -> Option<String> {
    disk(root).keycheck
}

/// **The partial deletions**: the heads deleted and the height left answered a
/// raw `UNIQUE constraint failed: chain_meta.key` (a 500); the height alone,
/// every record gone, is the same state with no rows; the height deleted and
/// the heads left OPENED on both postures, served reads and answered `verify`
/// OK while every write and `stats` answered a raw "Query returned no rows".
#[test]
fn o303_a_partial_chain_meta_is_an_integrity_finding_never_a_raw_error() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        rolled_back(root, level);
        behead(root, false);
        refused(
            &format!("{level:?} heads deleted, height left"),
            root,
            Want::Finding(RECORDS),
            ReadOnly::Reports(RECORDS),
        );

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        {
            let c = db(root);
            c.execute(
                "DELETE FROM chain_meta WHERE key IN ('head', 'head_v2')",
                [],
            )
            .unwrap();
            c.execute("DELETE FROM audit", []).unwrap();
        }
        refused(
            &format!("{level:?} the height alone"),
            root,
            Want::Finding(HEIGHT),
            ReadOnly::Reports(HEIGHT),
        );

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        assert_eq!(
            db(root)
                .execute("DELETE FROM chain_meta WHERE key = 'writes'", [])
                .unwrap(),
            1,
            "premise: a height to delete"
        );
        refused(
            &format!("{level:?} the height deleted, the heads left"),
            root,
            Want::Finding(NO_HEIGHT),
            ReadOnly::Reports(NO_HEIGHT),
        );
        // And beneath a handle already open: a write refuses in the same
        // class rather than a raw SQLite error.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 5);
        let mut s = writable(root).unwrap();
        db(root)
            .execute("DELETE FROM chain_meta WHERE key = 'writes'", [])
            .unwrap();
        match s.upsert(&drawer("late", 0)) {
            Err(StoreError::IntegrityFinding(m)) => assert!(m.contains(NO_HEIGHT), "{m}"),
            other => panic!("{level:?}: a write beneath the edit: {:?}", other.err()),
        }
        // And the witness over the same chain, which reads the height too.
        match s.witness_emit() {
            Err(StoreError::IntegrityFinding(_)) => {}
            other => panic!("{level:?}: the witness beneath the edit: {:?}", other.err()),
        }
        // A height that is not a number is the same edit: it was a
        // `CorruptRow`, a 500.
        db(root)
            .execute(
                "INSERT INTO chain_meta (key, value) VALUES ('writes', 'many')",
                [],
            )
            .unwrap();
        match s.upsert(&drawer("later", 0)) {
            Err(StoreError::IntegrityFinding(m)) => assert!(m.contains("not a number"), "{m}"),
            other => panic!("{level:?}: a garbled height: {:?}", other.err()),
        }
    }
}

/// **An erased trail**: every `audit` row and every `chain_meta` row deleted
/// beside a manifest past genesis OPENED at height 21 over zero rows. It is the
/// rollback the anchor exists to catch, on both postures.
#[test]
fn o303_an_erased_trail_is_tampering_on_both_postures() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        {
            let c = db(root);
            c.execute("DELETE FROM chain_meta", []).unwrap();
            c.execute("DELETE FROM audit", []).unwrap();
        }
        refused(
            &format!("{level:?} erased trail"),
            root,
            Want::Tampered,
            ReadOnly::Refuses(Want::Tampered),
        );
    }
}

/// **The filing's own remedy is refused too — it is an oracle.** On a
/// version-1 chain, one row appended by a writer without the key and
/// `chain_meta` emptied: seeding the REPLAYED head (the filing's shape) had the
/// store compute the keyed head over the forged row, heal the anchor over it
/// and bind its label at the version-2 switch — measured, `chain_ok` true and
/// the labels `Intact`. Refused here, the forged row still unbound.
#[test]
fn o303_a_forged_tail_on_an_emptied_chain_is_refused_not_laundered() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        to_v1(root);
        {
            let c = db(root);
            c.execute(
                "INSERT INTO audit (record_id, tag, at) VALUES ('trust/w1', ?1, \
                 '2026-01-01T00:00:00Z')",
                [vec![0x5au8; 32]],
            )
            .unwrap();
            c.execute("DELETE FROM chain_meta", []).unwrap();
        }
        refused(
            &format!("{level:?} forged tail"),
            root,
            Want::Finding(RECORDS),
            ReadOnly::Reports(RECORDS),
        );
    }
}

/// **A database with no `chain_meta` table and records** — the shape a source
/// build of this repository older than 0.19.0 writes, which `main` adopted from
/// the manifest (measured: it opened and verified). No release since 1.0.0
/// writes it, and 1.0.0 declared nothing before it needs to open: refused, the
/// table never created. On the read-only posture it is refused as well, where
/// the schema check answered "unmigrated" and named a writable open as the
/// remedy — an open that now refuses.
#[test]
fn o303_a_database_with_records_and_no_chain_meta_table_is_refused() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level, 20);
        to_v1(root);
        db(root).execute_batch("DROP TABLE chain_meta").unwrap();
        refused(
            &format!("{level:?} records, no chain_meta table"),
            root,
            Want::Finding(RECORDS),
            ReadOnly::Refuses(Want::Finding(RECORDS)),
        );
        assert_eq!(
            disk(root).chain_meta,
            None,
            "{level:?}: the table not created"
        );
    }
}

/// **The one head-less chain adopted: a fresh vault's, EMPTY** — no record, no
/// height, the manifest at genesis and height 0 — with the table absent (the
/// first open has not reached it) or present and empty (a crash between its
/// creation and the seed). Seeded with the constants, switched, verified, and
/// open to writes; the read-only open, which may not seed, answers the
/// absent-table class for both. A genesis head beside a nonzero height is a
/// manifest only a key holder writes, and is refused.
#[test]
fn o303_only_the_empty_chain_is_adopted() {
    for level in LEVELS {
        // A fresh vault: no database at all.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        mgr(root).create(VAULT, level).unwrap();
        let mut s = writable(root).unwrap();
        assert_eq!(s.anchor_at_open(), AnchorState::Unseeded, "{level:?}");
        s.upsert(&drawer("first", 0)).unwrap();
        assert!(s.verify().unwrap().ok(), "{level:?}");
        drop(s);
        assert_eq!(writable(root).unwrap().chain_state().unwrap().1, 2);

        for table in [false, true] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            empty_chain(root, level, table);
            match read_only(root) {
                Err(StoreError::ReadOnlyUnmigrated { missing }) => {
                    assert!(missing.contains("chain_meta"), "{level:?}: {missing}")
                }
                other => panic!("{level:?} table={table}: read-only {:?}", other.err()),
            }
            let mut s = writable(root)
                .unwrap_or_else(|e| panic!("{level:?} table={table}: not adopted: {e}"));
            assert_eq!(s.anchor_at_open(), AnchorState::Unseeded);
            let genesis = Vault::chain_genesis_hex();
            let meta = disk(root).chain_meta.expect("the table created");
            assert!(
                meta.contains(&("head".to_string(), genesis.clone())),
                "{level:?} table={table}: the constant seeded: {meta:?}"
            );
            s.upsert(&drawer("first", 0)).unwrap();
            assert!(s.verify().unwrap().ok(), "{level:?} table={table}");
            drop(s);
            let s = writable(root).unwrap();
            assert_eq!(s.anchor_at_open(), AnchorState::Current);
            assert!(s.verify().unwrap().ok());
        }

        // Genesis beside a nonzero height.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        empty_chain(root, level, true);
        let mut v = mgr(root).unlock(VAULT).unwrap();
        fixture::write_anchor_unchecked(&mut v, &Vault::chain_genesis_hex(), 5).unwrap();
        drop(v);
        let before = disk(root);
        match writable(root) {
            Err(StoreError::Vault(VaultError::ManifestTampered)) => {}
            other => panic!("{level:?}: genesis at height 5: {:?}", other.err()),
        }
        assert_eq!(disk(root), before, "{level:?}: nothing seeded");
    }
}

/// **Two first opens of one fresh vault seed ONE chain.** The seed took no
/// lock, so both judged the chain empty and both inserted; measured across two
/// processes, one run in 200 answered a raw `UNIQUE constraint failed:
/// chain_meta.key`. The first open is held between its judgement and its lock
/// while the second opens completely; both open, one seed and one version-2
/// commitment are written.
#[test]
fn o303_two_first_opens_seed_one_chain() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        mgr(&root).create(VAULT, level).unwrap();
        let (reached_tx, reached_rx) = mpsc::channel::<()>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let go_rx = Arc::new(Mutex::new(go_rx));
        let reached_tx = Arc::new(Mutex::new(reached_tx));
        let fired = Arc::new(AtomicUsize::new(0));
        {
            let fired = fired.clone();
            open_pause::set(
                &vdir(&root),
                Arc::new(move |at| {
                    if at == Opener::Adopting && fired.fetch_add(1, Ordering::SeqCst) == 0 {
                        reached_tx.lock().unwrap().send(()).unwrap();
                        go_rx.lock().unwrap().recv().unwrap();
                    }
                }),
            );
        }
        let first = {
            let root = root.clone();
            std::thread::spawn(move || writable(&root).map(|_| ()))
        };
        reached_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("premise: the first open reached its adoption");
        let second = writable(&root);
        go_tx.send(()).unwrap();
        let first = first.join().unwrap();
        open_pause::clear(&vdir(&root));
        assert_eq!(
            fired.load(Ordering::SeqCst),
            2,
            "premise: both opens adopted"
        );
        second.unwrap_or_else(|e| panic!("{level:?}: the second open: {e}"));
        first.unwrap_or_else(|e| panic!("{level:?}: the first open: {e}"));
        let d = disk(&root);
        assert_eq!(d.audit_rows, 1, "{level:?}: one commitment, not two");
        assert_eq!(
            d.chain_meta.map(|m| m.len()),
            Some(3),
            "{level:?}: one seed (head, head_v2, writes)"
        );
        assert!(writable(&root).unwrap().verify().unwrap().ok());
    }
}

/// **The same race, one step narrower: a seed committed between this open's
/// judgement and its lock, and NOT yet anchored** — the moment another first
/// open has seeded and not reached its switch. The manifest is still at
/// genesis and height 0 there, so nothing but the judgement made again under
/// the lock can see the chain is seeded; without it the open inserted and met
/// a raw `UNIQUE constraint failed`. The arm above cannot see that: its second
/// open anchors before the first resumes, so the manifest's height alone
/// refuses the seed — measured, a counterfactual dropping the locked
/// judgement passed it.
#[test]
fn o303_a_seed_landing_before_the_lock_is_judged_not_inserted_over() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        mgr(&root).create(VAULT, level).unwrap();
        let fired = Arc::new(AtomicUsize::new(0));
        {
            let fired = fired.clone();
            let root = root.clone();
            open_pause::set(
                &vdir(&root),
                Arc::new(move |at| {
                    if at == Opener::Adopting && fired.fetch_add(1, Ordering::SeqCst) == 0 {
                        // What a concurrent first open commits at its seed.
                        let c = db(&root);
                        c.execute_batch(
                            "CREATE TABLE IF NOT EXISTS chain_meta (
                                 key   TEXT PRIMARY KEY,
                                 value TEXT NOT NULL
                             );",
                        )
                        .unwrap();
                        c.execute(
                            "INSERT INTO chain_meta (key, value) VALUES ('head', ?1), ('writes', '0')",
                            [Vault::chain_genesis_hex()],
                        )
                        .unwrap();
                    }
                }),
            );
        }
        let before = std::fs::read(manifest(&root)).unwrap();
        let opened = writable(&root);
        open_pause::clear(&vdir(&root));
        assert_eq!(fired.load(Ordering::SeqCst), 1, "premise: the open adopted");
        let s = opened.unwrap_or_else(|e| panic!("{level:?}: {e}"));
        assert_eq!(
            s.anchor_at_open(),
            AnchorState::Current,
            "{level:?}: judged what the other open seeded"
        );
        assert!(s.verify().unwrap().ok(), "{level:?}");
        drop(s);
        assert_ne!(
            std::fs::read(manifest(&root)).unwrap(),
            before,
            "premise: the switch anchored"
        );
    }
}

/// **Seeded by another open and emptied again before this open's second
/// judgement**: the adoption found the chain seeded and handed it back to the
/// ordinary reconcile, which met no head again and would have returned a handle
/// with none. It is an edit racing the open, refused; nothing is seeded.
#[test]
fn o303_a_chain_emptied_after_another_open_seeded_it_is_refused() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        mgr(&root).create(VAULT, level).unwrap();
        let before = std::fs::read(manifest(&root)).unwrap();
        let fired = Arc::new(Mutex::new(Vec::new()));
        {
            let fired = fired.clone();
            let root = root.clone();
            open_pause::set(
                &vdir(&root),
                Arc::new(move |at| {
                    fired.lock().unwrap().push(at);
                    let c = db(&root);
                    match at {
                        Opener::Adopting => {
                            c.execute_batch(
                                "CREATE TABLE IF NOT EXISTS chain_meta (
                                     key   TEXT PRIMARY KEY,
                                     value TEXT NOT NULL
                                 );",
                            )
                            .unwrap();
                            c.execute(
                                "INSERT INTO chain_meta (key, value) VALUES ('head', ?1), \
                                 ('writes', '0')",
                                [Vault::chain_genesis_hex()],
                            )
                            .unwrap();
                        }
                        Opener::Readopting => {
                            c.execute("DELETE FROM chain_meta", []).unwrap();
                        }
                        _ => {}
                    }
                }),
            );
        }
        let opened = writable(&root);
        open_pause::clear(&vdir(&root));
        let fired = fired.lock().unwrap().clone();
        assert!(
            fired.contains(&Opener::Adopting) && fired.contains(&Opener::Readopting),
            "premise: both pause points reached: {fired:?}"
        );
        match opened {
            Err(StoreError::IntegrityFinding(m)) => {
                assert!(m.contains("emptied again"), "{level:?}: {m}")
            }
            other => panic!("{level:?}: {:?}", other.err()),
        }
        assert_eq!(std::fs::read(manifest(&root)).unwrap(), before, "{level:?}");
        assert_eq!(
            disk(&root).chain_meta.map(|m| m.len()),
            Some(0),
            "{level:?}"
        );
    }
}

/// **`vault anchor` beneath a handle whose `chain_meta` was emptied answered
/// "nothing to anchor"** — and `/v1 …/anchor` a 500, `chain_state` then
/// answering `CorruptRow`. The trail erased with it is the rollback the anchor
/// catches; with the manifest put back at genesis too, the empty chain an open
/// would seed is still refused beneath an open handle, whose open seeded one.
/// Nothing is anchored and nothing seeded — that would heal the edit.
#[test]
fn o303_tighten_anchor_refuses_a_chain_emptied_beneath_it() {
    for level in LEVELS {
        for genesis in [false, true] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            mgr(root).create(VAULT, level).unwrap();
            let created = std::fs::read(manifest(root)).unwrap();
            let mut s = writable(root).unwrap();
            {
                let c = db(root);
                c.execute("DELETE FROM chain_meta", []).unwrap();
                c.execute("DELETE FROM audit", []).unwrap();
            }
            if genesis {
                std::fs::write(manifest(root), &created).unwrap();
            }
            let before = std::fs::read(manifest(root)).unwrap();
            match (genesis, s.tighten_anchor()) {
                (false, Err(StoreError::Vault(VaultError::ManifestTampered))) => {}
                (true, Err(StoreError::IntegrityFinding(m))) => {
                    assert!(m.contains("beneath this open handle"), "{m}")
                }
                (g, other) => panic!("{level:?} genesis={g}: {other:?}"),
            }
            assert!(matches!(
                s.chain_state(),
                Err(StoreError::IntegrityFinding(_))
            ));
            // The witness: an erased trail past genesis is the finding (it said
            // "no records yet"); at genesis there is nothing to witness.
            match (genesis, s.witness_emit()) {
                (false, Err(StoreError::IntegrityFinding(m))) => {
                    assert!(m.contains("the trail was erased"), "{m}")
                }
                (true, Err(StoreError::Invalid(m))) => assert!(m.contains("nothing to witness")),
                (g, other) => panic!("{level:?} genesis={g}: the witness: {:?}", other.err()),
            }
            assert_eq!(std::fs::read(manifest(root)).unwrap(), before);
            assert_eq!(disk(root).chain_meta.map(|m| m.len()), Some(0));
        }
    }
}

/// The exact extent of the first `fn name(` in `text`, up to its own closing
/// brace — `close` is `"\n    }\n"` for a method, `"\n}\n"` for a free fn.
fn fn_body<'a>(text: &'a str, name: &str, close: &str) -> &'a str {
    let at = text
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("no fn {name}"));
    let rest = &text[at..];
    let end = rest.find(close).expect("the fn's closing brace") + close.len();
    &rest[..end]
}

const METHOD: &str = "\n    }\n";

/// **Source gates** (ROADMAP O303). The seed takes no value at all, so no
/// manifest field can reach it; it has ONE production caller, the adoption,
/// under the write lock and after the table's creation there; `init_chain`
/// reads no manifest field and creates no table before the judgement; the
/// head-less judgement replays nothing and asks `EXISTS`, never a count; and
/// `head_state` reads the height.
#[test]
fn o303_source_gates() {
    let lib = include_str!("lib.rs");
    let chain = include_str!("chain.rs");
    // Every production source of this crate: the `*_tests.rs` files skipped,
    // and each file cut at its first INLINE test module (`#[cfg(test)]` then
    // `mod name {`), since `lib.rs` carries two.
    let production: Vec<(String, String)> = {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let mut cut = text.len();
            for (at, _) in text.match_indices("#[cfg(test)]\nmod ") {
                let line_end = text[at..].find('{').map(|b| at + b);
                let semi = text[at..].find(';').map(|b| at + b);
                if let (Some(brace), s) = (line_end, semi) {
                    if s.is_none_or(|s| brace < s) {
                        cut = at;
                        break;
                    }
                }
            }
            out.push((name, text[..cut].to_string()));
        }
        out
    };
    assert!(
        production.len() > 20 && production.iter().any(|(n, _)| n == "chain.rs"),
        "premise: the crate's sources were read"
    );
    assert!(
        chain.contains("pub(crate) fn seed_empty(conn: &Connection) -> Result<(), StoreError>"),
        "the seed takes the connection and nothing else"
    );
    assert!(
        !chain.contains("pub(crate) fn seed("),
        "the seed that took the manifest's head"
    );
    let seed = "chain::seed_empty(";
    let seeds: usize = production
        .iter()
        .map(|(_, t)| t.matches("seed_empty(").count())
        .sum();
    assert_eq!(
        seeds, 2,
        "the definition and ONE production call, in any source file"
    );
    let lib_prod = &production.iter().find(|(n, _)| n == "lib.rs").unwrap().1;
    assert_eq!(lib_prod.matches(seed).count(), 1, "the call is the store's");
    let adopt = fn_body(lib, "adopt_empty_chain", METHOD);
    let at = adopt.find(seed).expect("the adoption seeds");
    let lock = adopt
        .find("WriteLock::begin(")
        .expect("under the write lock");
    let table = adopt
        .find("CREATE TABLE IF NOT EXISTS chain_meta")
        .expect("the table created in the lock");
    let manifest = adopt
        .find("self.vault.verified_manifest()?")
        .expect("the manifest read strictly");
    let judged = adopt.find("Self::judge_chain(").expect("judged again");
    let commit = adopt.find("lock.commit()?").expect("committed");
    assert!(
        lock < table && table < manifest && manifest < judged && judged < at && at < commit,
        "lock, table, manifest, judgement, seed, commit"
    );
    let init = fn_body(lib, "init_chain", METHOD);
    for banned in [
        "chain_head_hex()",
        ".writes()",
        "CREATE TABLE",
        "chain::seed",
    ] {
        assert!(!init.contains(banned), "init_chain: {banned}");
    }
    let headless = fn_body(lib, "judge_headless", METHOD);
    assert!(
        !headless.contains(concat!("chain::re", "play(")),
        "no replay"
    );
    assert!(headless.contains("SELECT EXISTS (SELECT 1 FROM audit)"));
    assert!(!headless.contains("count("), "EXISTS, never a count");
    let judge = fn_body(lib, "judge_chain", METHOD);
    assert_eq!(judge.matches("Self::judge_headless(").count(), 2);
    let head_state = fn_body(chain, "head_state", "\n}\n");
    assert!(
        head_state.contains("get(WRITES_KEY)?"),
        "head_state reads the height"
    );
}
