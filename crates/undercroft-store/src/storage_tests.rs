//! ROADMAP O269: `verify` is blind to storage corruption, and exits 1 on the
//! corruption it trips over.
//!
//! Every damaged vault here is damaged the way the filing measured — bytes
//! flipped in its pages, a file cut short, a column retyped by a writer without
//! the key — and every verdict is read through the store's own doors: the
//! open, `verify`, `backup create`, a rotation and `repair`. The surfaces'
//! projections are the CLI's and `/v1`'s own tests and the e2e suite.

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{Access, SecurityLevel, VaultManager};

use crate::{BackupOutcome, BadReason, RestoreOutcome, StoreError, VaultStore, VerifyReport};

const VAULT: &str = "o269";

fn drawer(wing: &str, content: &str, idx: u32) -> Drawer {
    Drawer::new(
        wing,
        &format!("room{}", idx % 3),
        content.into(),
        Some("o269.md".into()),
        idx,
        "test",
    )
}

fn mgr(root: &Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn db(root: &Path) -> PathBuf {
    vdir(root).join("vault.db")
}

fn open_rw(root: &Path) -> Result<VaultStore, StoreError> {
    VaultStore::open(mgr(root).unlock(VAULT).unwrap())
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

/// A closed vault of `n` drawers in two wings, holding one of every tagged
/// row a `verify` leg walks — a supersession link, a fact citing a drawer, an
/// approved canonical fact, an entity, a tunnel, a trust class and a
/// retention policy — its WAL folded into the main file, verified clean.
fn corpus(level: SecurityLevel, n: usize) -> TempDir {
    let dir = TempDir::new().unwrap();
    corpus_into(&dir, level, n);
    dir
}

/// [`corpus`] into a directory a test prepared — one kept on the version-1
/// row-tag regime, say (ROADMAP O406).
fn corpus_into(dir: &TempDir, level: SecurityLevel, n: usize) {
    let mut s = VaultStore::open(mgr(dir.path()).create(VAULT, level).unwrap()).unwrap();
    let batch: Vec<Drawer> = (0..n)
        .map(|i| {
            drawer(
                if i % 2 == 0 { "w1" } else { "w2" },
                &format!("note {i}: the harbour ledger names cargo {i} and its pier"),
                i as u32,
            )
        })
        .collect();
    s.upsert_many(&batch).unwrap();
    let mut newer = drawer("w1", "a note that supersedes the first one", 9000);
    newer.meta.supersedes = Some(batch[0].id.clone());
    s.upsert(&newer).unwrap();
    s.kg_add(
        "harbour",
        "ships",
        "cargo",
        Some("2026-01-01"),
        None,
        0.9,
        Some(&batch[1].id),
    )
    .unwrap();
    let canonical = s
        .kg_add("pier", "opens at", "six", None, None, 1.0, None)
        .unwrap();
    s.kg_set_authority(&canonical, "canonical", "approved", Some("pier-hours"))
        .unwrap();
    assert!(
        s.create_tunnel("w1", "w2", "shared ledger")
            .unwrap()
            .created,
        "premise: the tunnel was written"
    );
    s.set_wing_trust("w1", "standard").unwrap();
    s.set_retention("w2", None, 3650).unwrap();
    let r = s.verify().unwrap();
    assert!(r.ok(), "premise: clean ({r:?})");
    drop(s);
    assert!(
        !vdir(dir.path()).join("vault.db-wal").exists(),
        "premise: the close folded the WAL"
    );
}

/// A copy of the whole installation at `src` (key file and vault), for damaging.
fn clone_root(src: &Path) -> TempDir {
    fn copy(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                copy(&p, &to.join(e.file_name()));
            } else {
                std::fs::copy(&p, to.join(e.file_name())).unwrap();
            }
        }
    }
    let dir = TempDir::new().unwrap();
    copy(src, dir.path());
    dir
}

/// The one embedder factory a restore opens its stage with.
fn hash(
    _: &undercroft_vault::Vault,
) -> Result<Box<dyn undercroft_core::embed::Embedder + Send>, StoreError> {
    Ok(Box::new(HashEmbedder))
}

/// Open `root`'s vault read-only with the `immutable=1` escalation FORCED, as
/// O213's gate forces it (`absent_tests.rs`): at the ordinary read-only
/// connection's pause a directory stands where its `-wal` would be, so its
/// probe cannot read the database the ordinary way and the open escalates; at
/// the escalation's pause the directory is gone. The main file must hold every
/// commit — a `-wal` with frames would leave the handle blind, which is O213's
/// question and not this one.
fn open_immutable(root: &Path) -> Result<VaultStore, StoreError> {
    use crate::open_pause::{self, Opener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let wal = vdir(root).join("vault.db-wal");
    assert!(
        std::fs::metadata(&wal)
            .map(|m| m.len() == 0)
            .unwrap_or(true),
        "premise: no -wal frames beside the main file"
    );
    let _ = std::fs::remove_file(&wal);
    let escalated = Arc::new(AtomicUsize::new(0));
    {
        let (wal, escalated) = (wal.clone(), escalated.clone());
        open_pause::set(
            &vdir(root),
            Arc::new(move |here| match here {
                Opener::ReadOnly => {
                    let _ = std::fs::create_dir(&wal);
                }
                Opener::Immutable => {
                    let _ = std::fs::remove_dir(&wal);
                    escalated.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }),
        );
    }
    let s = open_ro(root);
    open_pause::clear(&vdir(root));
    assert_eq!(
        escalated.load(Ordering::SeqCst),
        1,
        "premise: the open escalated to immutable=1"
    );
    s
}

/// A raw connection that is not the store's, the way an offline writer or a
/// damaged disk reaches the file.
fn raw(root: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(db(root)).unwrap()
}

fn page_size(root: &Path) -> usize {
    raw(root)
        .query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))
        .unwrap() as usize
}

fn root_page(root: &Path, name: &str) -> usize {
    raw(root)
        .query_row(
            "SELECT rootpage FROM sqlite_schema WHERE name = ?1",
            [name],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as usize
}

fn integrity_check(root: &Path) -> Vec<String> {
    let c = raw(root);
    let mut st = c.prepare("PRAGMA integrity_check").unwrap();
    let rows: Vec<String> = st
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    rows
}

/// Every leg but the storage leg clean: the vault `verify` called clean
/// before ROADMAP O269.
fn rows_clean(r: &VerifyReport) -> bool {
    VerifyReport {
        storage: Vec::new(),
        ..r.clone()
    }
    .ok()
}

/// **R3 on a LIVE vault**: the installation cloned from `src` with one byte flipped
/// in the page of `index`, chosen by measurement so that SQLite's
/// `integrity_check` fails and the report `verify` returns satisfies `want`.
/// `None` if no such byte is found.
fn r3_flip(src: &Path, index: &str, want: impl Fn(&VerifyReport) -> bool) -> Option<TempDir> {
    let ps = page_size(src);
    let page = root_page(src, index);
    // Inside the page's cell content area, where the index's keys are — read
    // from the b-tree page header (offset 5, "start of cell content area").
    let start = {
        let b = std::fs::read(db(src)).unwrap();
        let at = (page - 1) * ps + 5;
        usize::from(u16::from_be_bytes([b[at], b[at + 1]]))
    };
    for off in (start.max(8)..ps).step_by(3) {
        let cand = clone_root(src);
        let mut bytes = std::fs::read(db(cand.path())).unwrap();
        bytes[(page - 1) * ps + off] ^= 0x01;
        std::fs::write(db(cand.path()), &bytes).unwrap();
        if integrity_check(cand.path()) == ["ok"] {
            continue;
        }
        let premise = open_rw(cand.path())
            .ok()
            .and_then(|s| s.verify().ok())
            .is_some_and(|r| want(&r));
        if premise {
            return Some(cand);
        }
    }
    None
}

/// **P-O269f's placement, asserted** (ROADMAP O269, the maintainer's option
/// B). A truncated `vault.db` and a zeroed header surface at the open's FIRST
/// statement on both postures — measured before the build — and are now the
/// integrity class, `StorageCorrupt`, naming that door; the read-only open no
/// longer escalates them onto `immutable=1` (item 8), whose own probe answered
/// the same raw code. Counterfactual: `StoreError::Sqlite(DatabaseCorrupt)` /
/// `(NotADatabase)` on both, exit 1.
#[test]
fn o269_a_file_that_does_not_hold_together_refuses_at_the_open_as_storage_damage() {
    for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
        type Damage = (&'static str, fn(&mut Vec<u8>));
        let cases: &[Damage] = &[
            ("truncated on a page boundary", |b| {
                let page = u16::from_be_bytes([b[16], b[17]]) as usize;
                let keep = (b.len() / 2 / page) * page;
                b.truncate(keep);
            }),
            ("truncated mid-page", |b| {
                let keep = b.len() / 2 + 123;
                b.truncate(keep);
            }),
            ("its header magic zeroed", |b| b[0] = 0),
        ];
        for (name, damage) in cases {
            let dir = corpus(level, 120);
            let root = dir.path();
            let mut bytes = std::fs::read(db(root)).unwrap();
            damage(&mut bytes);
            std::fs::write(db(root), &bytes).unwrap();
            for (posture, opened) in [("read-only", open_ro(root)), ("writable", open_rw(root))] {
                match opened {
                    Err(StoreError::StorageCorrupt(why)) => assert!(
                        why.contains(&format!("the {posture} open's first statement")),
                        "{level:?} {name} {posture}: the door is named: {why}"
                    ),
                    Err(e) => panic!("{level:?} {name} {posture}: not the storage verdict: {e:?}"),
                    Ok(_) => panic!("{level:?} {name} {posture}: a damaged file opened"),
                }
            }
        }
    }
}

/// **The read-only open's first content read is a named door too** (option
/// B), and a damaged page past `sqlite_schema` reaches it: the `meta` table's
/// own root page, whose type byte no b-tree has. The writable open does not
/// read that page at any of ITS named doors — it meets it partway, in the
/// rotation reconcile — so it keeps the run-failure class there, the residual
/// the ruling states ("the next `verify` gives the verdict").
#[test]
fn o269_the_read_only_first_content_read_is_a_named_door() {
    let dir = corpus(SecurityLevel::Sealed, 30);
    let root = dir.path();
    let (ps, page) = (page_size(root), root_page(root, "meta"));
    let mut bytes = std::fs::read(db(root)).unwrap();
    bytes[(page - 1) * ps] = 0x00;
    std::fs::write(db(root), &bytes).unwrap();
    match open_ro(root) {
        Err(StoreError::StorageCorrupt(why)) => assert!(
            why.contains("the read-only open's first content read"),
            "{why}"
        ),
        Err(e) => panic!("not the storage verdict: {e:?}"),
        Ok(_) => panic!("a damaged meta page opened read-only"),
    }
    match open_rw(root) {
        Err(StoreError::Sqlite(e)) => assert!(crate::is_storage_corrupt(&e), "{e:?}"),
        Err(e) => panic!("the stated residual moved — record it under O269: {e:?}"),
        Ok(_) => panic!("a damaged meta page opened writable"),
    }
}

/// **R3, the filing's measurement, on the LIVE vault, both levels** (ROADMAP
/// O269 items 1, 4, 5 and 11, and the review of its first build). A byte
/// flipped in `idx_drawers_room`'s page that every row leg passes: the storage
/// leg names the index, `ok()` is false, `backup create` refuses it and a
/// rotation refuses it before any work — its files byte-identical. **`repair`
/// does not mend it, and must not**: its closing VACUUM copies each index's
/// cells as they stand and rebuilds none (SQLite's transfer optimization), and
/// the REINDEX this build first added would conform the index to its table —
/// which, after a TABLE-side flip, reads exactly like this damage (item 7's
/// laundering). The remedy is a restore: an archive taken before the damage
/// restores and `verify` answers OK. The premise IS the counterfactual:
/// `rows_clean` is exactly the report `verify` returned before.
#[test]
fn o269_r3_an_index_flip_fails_verify_backup_and_rotation_and_a_restore_mends_it() {
    for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
        let src = corpus(level, 40);
        // The archive the remedy restores, taken while the vault was intact;
        // `r3_flip` clones the installation, `backups/` included.
        let archive = match open_rw(src.path())
            .unwrap()
            .backup(&src.path().join("backups"))
            .unwrap()
        {
            BackupOutcome::Created(r) => r.name,
            BackupOutcome::Refused(r) => panic!("premise ({level:?}): an intact archive: {r:?}"),
        };
        // The state `verify` answered OK over: every row leg clean.
        let live = r3_flip(src.path(), "idx_drawers_room", |r| {
            rows_clean(r) && !r.storage.is_empty()
        })
        .unwrap_or_else(|| panic!("premise ({level:?}): an R3 flip verify used to pass"));
        let root = live.path();
        let s = open_rw(root).unwrap();
        let r = s.verify().unwrap();
        assert!(!r.ok(), "{level:?}: {r:?}");
        assert!(
            r.storage.iter().all(|f| f.starts_with("integrity_check: "))
                && r.storage.iter().any(|f| f.contains("idx_drawers_room")),
            "{level:?}: the storage leg names the index: {:?}",
            r.storage
        );
        assert!(
            r.rotation_blockers()
                .iter()
                .any(|b| b.starts_with("storage ")),
            "{level:?}: a rotation blocker: {:?}",
            r.rotation_blockers()
        );
        match s.backup(&root.join("backups")).unwrap() {
            BackupOutcome::Refused(r) => assert!(!r.storage.is_empty(), "{r:?}"),
            BackupOutcome::Created(r) => panic!("{level:?}: archived a damaged vault: {r:?}"),
        }
        drop(s);
        let before = std::fs::read(db(root)).unwrap();
        let mut s = open_rw(root).unwrap();
        let next = mgr(root).rotation_candidate(VAULT).unwrap();
        match s.rotate_keys(next) {
            Err(StoreError::IntegrityFinding(why)) => {
                assert!(why.contains("storage integrity_check"), "{why}")
            }
            other => panic!("{level:?}: the rotation was not refused: {other:?}"),
        }
        drop(s);
        assert_eq!(
            std::fs::read(db(root)).unwrap(),
            before,
            "{level:?}: refused before any work"
        );
        let mut s = open_rw(root).unwrap();
        let (r, _) = s.repair("test").unwrap();
        assert!(
            !r.ok() && r.storage.iter().any(|f| f.contains("idx_drawers_room")),
            "{level:?}: repair rebuilds no index, so the finding stands: {r:?}"
        );
        drop(s);
        assert_ne!(
            integrity_check(root),
            ["ok"],
            "{level:?}: SQLite's own check agrees"
        );
        match crate::restore_archive(
            &mgr(root),
            &root.join("backups").join(&archive),
            None,
            true,
            &hash,
        ) {
            Ok(RestoreOutcome::Restored(r)) => assert!(r.replaced, "{level:?}: {r:?}"),
            other => panic!("{level:?}: the archive did not restore: {other:?}"),
        }
        assert!(open_rw(root).unwrap().verify().unwrap().ok(), "{level:?}");
        assert_eq!(integrity_check(root), ["ok"], "{level:?}");
    }
}

/// **A damaged freelist page and a damaged table page are findings, never
/// errors** (O269 items 1 and 3). The freelist is what only a full check
/// reads; the table page is what a later leg trips over, and is folded into
/// the storage leg naming the leg it stopped — `verify` returned SQLite's
/// error for it, exit 1.
#[test]
fn o269_a_freelist_or_table_page_flip_is_a_storage_finding_never_an_error() {
    // The freelist: free pages from deleted drawers, its trunk's leaf count
    // made larger than a page can hold.
    let dir = corpus(SecurityLevel::Sealed, 200);
    let root = dir.path();
    {
        let mut s = open_rw(root).unwrap();
        // Contiguous rows, so whole pages fall free.
        let ids: Vec<String> = s
            .conn
            .prepare("SELECT id FROM drawers ORDER BY seq LIMIT 150")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for id in ids {
            s.delete_drawer(&id).unwrap();
        }
    }
    let trunk = {
        let b = std::fs::read(db(root)).unwrap();
        u32::from_be_bytes([b[32], b[33], b[34], b[35]]) as usize
    };
    assert!(trunk > 0, "premise: the deletes left a freelist");
    let ps = page_size(root);
    let mut bytes = std::fs::read(db(root)).unwrap();
    let at = (trunk - 1) * ps + 4;
    bytes[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    std::fs::write(db(root), &bytes).unwrap();
    assert_ne!(integrity_check(root), ["ok"], "premise: SQLite sees it");
    let r = open_rw(root)
        .unwrap()
        .verify()
        .expect("a verdict, never an error");
    assert!(!r.ok() && !r.storage.is_empty(), "{r:?}");

    // A table page: the `drawers` b-tree's root, its page type made one no
    // b-tree has. The drawer walk trips over it.
    let dir = corpus(SecurityLevel::HmacOnly, 200);
    let root = dir.path();
    let (ps, page) = (page_size(root), root_page(root, "drawers"));
    let mut bytes = std::fs::read(db(root)).unwrap();
    bytes[(page - 1) * ps] = 0x00;
    std::fs::write(db(root), &bytes).unwrap();
    let r = open_ro(root)
        .unwrap()
        .verify()
        .expect("a verdict, never an error");
    assert!(!r.ok(), "{r:?}");
    assert!(
        r.storage
            .iter()
            .any(|f| f.starts_with("the drawer walk not run: ")),
        "the leg it stopped is named: {:?}",
        r.storage
    );
    assert_eq!(
        (r.records_checked > 0, r.bad_records.is_empty()),
        (true, true),
        "the walk took its empty value; the graph and tunnel walks still ran: {r:?}"
    );
}

/// The same byte damage inside the audit table stops the chain replay, and a
/// replay that did not run claims nothing: `chain_ok` false (O269 item 3).
#[test]
fn o269_a_replay_that_could_not_run_claims_no_chain() {
    let dir = corpus(SecurityLevel::Sealed, 60);
    let root = dir.path();
    let (ps, page) = (page_size(root), root_page(root, "audit"));
    let mut bytes = std::fs::read(db(root)).unwrap();
    bytes[(page - 1) * ps] = 0x00;
    std::fs::write(db(root), &bytes).unwrap();
    // The open itself replays nothing on a current anchor and reads no audit
    // page; the read-only open is the one that reaches `verify`.
    let r = open_ro(root).unwrap().verify().expect("a verdict");
    assert!(!r.chain_ok, "{r:?}");
    assert!(
        r.storage
            .iter()
            .any(|f| f.starts_with("the chain replay not run: ")),
        "{:?}",
        r.storage
    );
}

/// **A value no read takes is named, and every other leg still reports**
/// (ROADMAP O269 item 2). A writer without the key retypes columns: `verify`
/// read each with a typed `get` and returned that read's error — exit 1, a
/// 500, and nothing else it found. Now each is a finding in the leg that owns
/// the read, named by its id, or by its place in its table where the id does
/// not decode; the tag is checked over the bytes, so a retype whose bytes are
/// intact is `Undecodable` and a byte that changed is `TagFailed`; and an
/// ordinary finding beside them is still there.
#[test]
fn o269_a_value_no_read_takes_is_named_and_every_other_leg_still_reports() {
    for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
        let dir = corpus(level, 30);
        let root = dir.path();
        let c = raw(root);
        let ids: Vec<(i64, String)> = c
            .prepare("SELECT seq, id FROM drawers WHERE supersedes IS NULL ORDER BY seq LIMIT 6")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let set = |sql: &str, id: &str| {
            assert_eq!(c.execute(sql, [id]).unwrap(), 1, "premise: {sql}");
        };
        // A meta_json retyped, bytes intact: Undecodable, by id.
        set(
            "UPDATE drawers SET meta_json = CAST(meta_json AS BLOB) WHERE id = ?1",
            &ids[0].1,
        );
        // A mirror retyped: drift.
        set(
            "UPDATE drawers SET wing = CAST(wing AS BLOB) WHERE id = ?1",
            &ids[1].1,
        );
        // An id retyped: named by seq — and its label now names no drawer.
        set(
            "UPDATE drawers SET id = CAST(id AS BLOB) WHERE id = ?1",
            &ids[2].1,
        );
        // A byte that breaks UTF-8: the bytes changed, so the tag fails.
        set(
            "UPDATE drawers SET meta_json = CAST(x'ff' || CAST(meta_json AS BLOB) AS TEXT) \
             WHERE id = ?1",
            &ids[3].1,
        );
        // A bare drawer label in `audit` retyped.
        assert_eq!(
            c.execute(
                "UPDATE audit SET record_id = CAST(record_id AS BLOB) \
                 WHERE seq = (SELECT MIN(seq) FROM audit WHERE record_id = ?1)",
                [&ids[4].1],
            )
            .unwrap(),
            1
        );
        // An ordinary finding beside them: a mirror edited.
        set(
            "UPDATE drawers SET room = 'elsewhere' WHERE id = ?1",
            &ids[5].1,
        );
        // A fact's object retyped (a BLOB column as TEXT), and a policy row's
        // tag retyped.
        assert_eq!(
            c.execute(
                "UPDATE kg_triples SET object = CAST(object AS TEXT) \
                 WHERE seq = (SELECT MIN(seq) FROM kg_triples)",
                [],
            )
            .unwrap(),
            1
        );
        assert_eq!(
            c.execute("UPDATE wing_trust SET tag = CAST(tag AS TEXT)", [])
                .unwrap(),
            1
        );
        drop(c);
        let s = open_rw(root).unwrap();
        let r = s.verify().expect("a verdict, never a conversion error");
        let line = |b: &crate::BadRecord| b.to_string();
        let bad: Vec<String> = r.bad_records.iter().map(line).collect();
        let has = |want: &str| bad.iter().any(|b| b.starts_with(want));
        assert!(
            r.bad_records.iter().any(|b| b.record == ids[0].1
                && b.reason == BadReason::Undecodable
                && b.detail == "column meta_json holds a BLOB"),
            "{level:?}: {bad:?}"
        );
        assert!(
            has(&format!("drawers seq {}: column id holds a BLOB", ids[2].0)),
            "{level:?}: named by seq: {bad:?}"
        );
        assert!(
            r.bad_records
                .iter()
                .any(|b| b.record == ids[3].1 && b.reason == BadReason::TagFailed),
            "{level:?}: {bad:?}"
        );
        assert!(
            r.bad_records.iter().any(|b| b.record.starts_with("kg/")
                && b.reason == BadReason::Undecodable
                && b.detail.starts_with("column object holds TEXT")),
            "{level:?}: {bad:?}"
        );
        assert!(
            r.mirror_drift
                .iter()
                .any(|m| m.starts_with(&format!("{}: column wing holds a BLOB", ids[1].1))),
            "{level:?}: {:?}",
            r.mirror_drift
        );
        assert!(
            r.mirror_drift
                .iter()
                .any(|m| m.starts_with(&format!("{}: column room=", ids[5].1))),
            "{level:?}: the ordinary finding still reports: {:?}",
            r.mirror_drift
        );
        assert!(
            r.orphan_labels
                .iter()
                .any(|l| l.starts_with("audit seq ") && l.contains("holds a BLOB")),
            "{level:?}: {:?}",
            r.orphan_labels
        );
        assert!(
            r.policy_drift
                .iter()
                .any(|p| p.starts_with("trust/w1: column tag holds TEXT")),
            "{level:?}: {:?}",
            r.policy_drift
        );
        // Each retype is a rotation blocker, by item 2.
        let blockers = r.rotation_blockers();
        assert!(
            blockers
                .iter()
                .any(|b| b.contains(&ids[0].1) && b.contains("meta_json")),
            "{level:?}: {blockers:?}"
        );
        // And the storage leg is clean: SQLite admits a BLOB in a TEXT column
        // of a table that is not STRICT, which is why this is item 2's arm and
        // not item 1's.
        assert!(r.storage.is_empty(), "{level:?}: {:?}", r.storage);
    }
}

/// **The property gate** (ROADMAP O269's gate): every TEXT column of every
/// table, as `table_xinfo` lists it (O80: counted against the file, never a
/// list), retyped to a BLOB and to TEXT that is not UTF-8, one at a time —
/// `verify` returns a report every time, never an error.
///
/// One table is out, and not by choice: `chain_meta`, whose value retyped
/// refuses BOTH opens with a conversion error before any `verify` can run —
/// the open's own typed reads, filed as O433. A retyped `meta.value`
/// refuses the writable open the same way, so this opens read-only where the
/// writable open refuses. The FTS tables are FTS5's own, which the storage
/// leg's `integrity_check` reads.
#[test]
fn o269_no_column_of_the_wrong_class_makes_verify_return_an_error() {
    for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
        let src = corpus(level, 12);
        let c = raw(src.path());
        let tables: Vec<String> = c
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'drawers_fts%' \
                 AND name <> 'chain_meta' \
                 ORDER BY name",
            )
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut cases = Vec::new();
        for t in &tables {
            let cols: Vec<(String, String)> = c
                .prepare(&format!("PRAGMA table_xinfo({t})"))
                .unwrap()
                .query_map([], |r| Ok((r.get(1)?, r.get(2)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            for (col, ty) in cols {
                if ty.eq_ignore_ascii_case("TEXT") {
                    cases.push((t.clone(), col));
                }
            }
        }
        drop(c);
        assert!(
            cases.len() >= 30,
            "premise: the TEXT columns were read from the file: {cases:?}"
        );
        for (table, col) in &cases {
            for (mode, expr) in [
                ("a BLOB", format!("CAST({col} AS BLOB)")),
                (
                    "TEXT that is not UTF-8",
                    format!("CAST(x'ff' || CAST({col} AS BLOB) AS TEXT)"),
                ),
            ] {
                let copy = clone_root(src.path());
                let changed = raw(copy.path())
                    .execute(
                        &format!(
                            "UPDATE {table} SET {col} = {expr} WHERE rowid = \
                             (SELECT MIN(rowid) FROM {table} WHERE {col} IS NOT NULL)"
                        ),
                        [],
                    )
                    .unwrap();
                if changed == 0 {
                    continue;
                }
                let s = open_rw(copy.path())
                    .or_else(|_| open_ro(copy.path()))
                    .unwrap_or_else(|e| {
                        panic!("{level:?} {table}.{col} as {mode}: no open: {e:?}")
                    });
                if let Err(e) = s.verify() {
                    panic!("{level:?} {table}.{col} as {mode}: verify errored: {e:?}");
                }
            }
        }
    }
}

/// **A lost autoindex entry is refused before any re-key** (ROADMAP O269's
/// P-O269e, item 4). An entity's entry in `kg_entities`' autoindex is damaged
/// so the table holds a row its index does not: the rotation re-keys entities
/// by `WHERE id = ?`, which goes through that index, so before the build it
/// changed ZERO rows and left the entity tagged under the retired key. The
/// storage leg refuses it now, before the rotation's first write.
#[test]
fn o269_a_rotation_over_a_lost_autoindex_entry_is_refused_before_any_work() {
    let src = corpus(SecurityLevel::Sealed, 20);
    let entities: i64 = raw(src.path())
        .query_row("SELECT COUNT(*) FROM kg_entities", [], |r| r.get(0))
        .unwrap();
    assert!(entities > 0, "premise: the corpus holds entities");
    // An entry of `kg_entities`' id autoindex damaged: the storage leg names
    // it. The orphan-label leg may see it too — a label's lookup goes through
    // the same index — and is no rotation blocker, which is why the rotation
    // before this build went on to re-key that entity in zero rows.
    let live = r3_flip(src.path(), "sqlite_autoindex_kg_entities_1", |r| {
        r.storage
            .iter()
            .any(|f| f.contains("sqlite_autoindex_kg_entities_1"))
            && r.bad_records.is_empty()
            && r.chain_ok
    })
    .expect("premise: a flip in the entities' id autoindex the storage leg names");
    let root = live.path();
    let before = std::fs::read(db(root)).unwrap();
    let mut s = open_rw(root).unwrap();
    let next = mgr(root).rotation_candidate(VAULT).unwrap();
    match s.rotate_keys(next) {
        Err(StoreError::IntegrityFinding(why)) => assert!(why.contains("storage "), "{why}"),
        other => panic!("not refused: {other:?}"),
    }
    drop(s);
    assert_eq!(std::fs::read(db(root)).unwrap(), before);
}

/// The phase-3 assertion itself (O269 item 4): one row is the only count a
/// re-key may change; anything else refuses in the integrity class.
#[test]
fn o269_a_re_key_that_changes_other_than_one_row_refuses() {
    assert!(crate::rotate::one_row(1, "kg_entities id", "x").is_ok());
    for n in [0, 2] {
        match crate::rotate::one_row(n, "kg_entities id", "x") {
            Err(StoreError::IntegrityFinding(why)) => {
                assert!(why.contains(&format!("changed {n} row(s)")), "{why}")
            }
            other => panic!("{n}: {other:?}"),
        }
    }
}

/// **A committed head or height moves exactly one row** (ROADMAP O269's
/// review, item 4's assertion applied to the two values every write moves).
/// `set_head` and `set_writes` changed whatever their UPDATE matched and
/// answered `Ok`, so a `chain_meta` whose key no longer finds its row let a
/// write's rows commit while the head or the height silently did not move.
/// Now any other count refuses in the integrity class, naming the key, and
/// the caller's transaction rolls back. Counterfactual: `Ok(())` over zero
/// rows.
#[test]
fn o269_a_head_or_height_that_moves_no_row_refuses() {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch("CREATE TABLE chain_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
        .unwrap();
    let head = || crate::chain::set_head(&c, crate::chain::Regime::V1, "00ff");
    let height = || crate::chain::set_writes(&c, 7);
    for (what, key, r) in [
        ("head", "\"head\"", head()),
        ("height", "\"writes\"", height()),
    ] {
        match r {
            Err(StoreError::IntegrityFinding(why)) => assert!(
                why.contains("changed 0 row(s)") && why.contains(key),
                "{what}: {why}"
            ),
            other => panic!("{what}: an UPDATE of no row answered {other:?}"),
        }
    }
    c.execute_batch("INSERT INTO chain_meta VALUES ('head', 'x'), ('writes', '1');")
        .unwrap();
    head().unwrap();
    height().unwrap();
    let read = |k: &str| -> String {
        c.query_row("SELECT value FROM chain_meta WHERE key = ?1", [k], |r| {
            r.get(0)
        })
        .unwrap()
    };
    assert_eq!((read("head"), read("writes")), ("00ff".into(), "7".into()));
}

/// **A corrupt FTS5 table read first does not cancel the check of the rest**
/// (ROADMAP O269's review). The storage leg reads each FTS5 table before the
/// pragma (the stale-cache fix); a corruption code met there was handed to
/// the pragma's error arm, which made the WHOLE leg one line and skipped
/// `integrity_check` — so an index flip elsewhere in the file went unnamed
/// beside it. Now the read is its own finding and the check still runs.
/// Counterfactual: one line, the FTS read's, and no `idx_drawers_room`
/// (O269's first build).
#[test]
fn o269_a_corrupt_fts_table_read_first_does_not_cancel_the_check() {
    let src = corpus(SecurityLevel::HmacOnly, 40);
    let live = r3_flip(src.path(), "idx_drawers_room", |r| {
        rows_clean(r) && !r.storage.is_empty()
    })
    .expect("premise: an R3 flip");
    let root = live.path();
    // The FTS5 table's content b-tree, its root page's type byte set to one
    // no page has: the table scan the read makes meets it first.
    let (ps, page) = (page_size(root), root_page(root, "drawers_fts_content"));
    let mut bytes = std::fs::read(db(root)).unwrap();
    bytes[(page - 1) * ps] = 0x00;
    std::fs::write(db(root), &bytes).unwrap();
    let premise = raw(root)
        .query_row("SELECT rowid FROM drawers_fts LIMIT 1", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap_err();
    assert!(crate::is_storage_corrupt(&premise), "premise: {premise}");
    // Read-only: the writable open's FTS work meets the page past its named
    // doors, the residual O269 states.
    let r = open_ro(root).unwrap().verify().unwrap();
    assert!(
        r.storage
            .iter()
            .any(|f| f.starts_with("\"drawers_fts\" could not be read: ")),
        "the read is its own finding: {:?}",
        r.storage
    );
    assert!(
        r.storage
            .iter()
            .any(|f| f.starts_with("integrity_check: ") && f.contains("idx_drawers_room")),
        "and the check of the rest still ran: {:?}",
        r.storage
    );
}

/// **O427's gate, met by O269's ruling** (ROADMAP O427, closed by this build).
/// O221's review measured it: `content` rewritten as TEXT and `meta_json`
/// stored as a BLOB made `verify` and every retention sweep fail with the
/// conversion error, one such row anywhere in the vault failing every sweep.
/// Now `verify` names each with its reason — the TEXT content changed the
/// bytes, so its tag fails over them; the BLOB meta kept them, so it is
/// `Undecodable` — and a sweep names each unverifiable, destroys neither, and
/// destroys the other expired members. Counterfactual: O221's walk, the
/// conversion error from both.
#[test]
fn o427_two_retyped_rows_are_named_by_verify_and_held_by_the_sweep() {
    for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let mut s = VaultStore::open(mgr(root).create(VAULT, level).unwrap()).unwrap();
        let old: Vec<Drawer> = (0..6)
            .map(|i| {
                let mut d = drawer("old", &format!("an expired note {i} about the weir"), i);
                d.meta.filed_at = "2020-01-01T00:00:00Z".into();
                d
            })
            .collect();
        s.upsert_many(&old).unwrap();
        s.set_retention("old", None, 30).unwrap();
        drop(s);
        let c = raw(root);
        assert_eq!(
            c.execute(
                "UPDATE drawers SET content = 'x' WHERE id = ?1",
                [&old[0].id]
            )
            .unwrap(),
            1
        );
        assert_eq!(
            c.execute(
                "UPDATE drawers SET meta_json = CAST(meta_json AS BLOB) WHERE id = ?1",
                [&old[1].id],
            )
            .unwrap(),
            1
        );
        drop(c);
        let mut s = open_rw(root).unwrap();
        let r = s.verify().expect("a verdict, never a conversion error");
        assert!(!r.ok(), "{level:?}");
        assert!(
            r.bad_records
                .iter()
                .any(|b| b.record == old[0].id && b.reason == BadReason::TagFailed),
            "{level:?}: {:?}",
            r.bad_records
        );
        assert!(
            r.bad_records.iter().any(|b| b.record == old[1].id
                && b.reason == BadReason::Undecodable
                && b.detail == "column meta_json holds a BLOB"),
            "{level:?}: {:?}",
            r.bad_records
        );
        let sw = s
            .retention_sweep(false)
            .expect("a sweep, never a conversion error");
        let held: Vec<&str> = sw.unverifiable.iter().map(|u| u.id.as_str()).collect();
        assert!(
            held.contains(&old[0].id.as_str()) && held.contains(&old[1].id.as_str()),
            "{level:?}: {sw:?}"
        );
        assert_eq!(sw.destroyed, 4, "{level:?}: the rest destroyed: {sw:?}");
        assert!(!sw.ok, "{level:?}");
        let left: Vec<String> = raw(root)
            .prepare("SELECT id FROM drawers ORDER BY seq")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            left,
            vec![old[0].id.clone(), old[1].id.clone()],
            "{level:?}"
        );
    }
}

/// **The canonical builders moved onto bytes and their output did not**
/// (O269 item 2). Pinned against the `format!` strings they replaced, written
/// out here by hand — a round trip through the builder itself passes on any
/// format (O406's warning).
#[test]
fn o269_the_byte_level_builders_are_byte_for_byte_the_old_ones() {
    // The version-1 recipes, which every row written before ROADMAP O406's
    // walk is still verified under.
    const V1: undercroft_vault::RowFormat = undercroft_vault::RowFormat::V1;
    assert_eq!(
        crate::rows::wing_trust(V1, "w1", "standard", "2026-01-01T00:00:00Z")
            .bytes()
            .to_vec(),
        b"wingtrust\x1fw1\x1fstandard\x1f2026-01-01T00:00:00Z".to_vec()
    );
    assert_eq!(
        crate::rows::tunnel(V1, "id", "a", "b", "lab el", "t")
            .bytes()
            .to_vec(),
        b"tunnel\x1fid\x1fa\x1fb\x1flab el\x1ft".to_vec()
    );
    assert_eq!(
        crate::rows::retention(V1, "w", "", 30, "t")
            .bytes()
            .to_vec(),
        b"retention\x1fw\x1f\x1f30\x1ft".to_vec()
    );
    assert_eq!(
        crate::rows::entity(V1, "id", "n", "unknown", "t", None)
            .bytes()
            .to_vec(),
        b"id\x1fn\x1funknown\x1ft".to_vec()
    );
    assert_eq!(
        crate::rows::entity(V1, "id", "n", "e", "t", Some(b"R".as_slice()))
            .bytes()
            .to_vec(),
        b"id\x1fn\x1fe\x1ft\x1bR".to_vec()
    );
    let mut fact = b"i\x1fs\x1fp\x1ff\x1f\x1f".to_vec();
    fact.extend_from_slice(&0.5f64.to_le_bytes());
    fact.extend_from_slice(b"\x1fOBJ\x1fSUP\x1e\x1fa\x1fr\x1fk\x1d\x1fx\x1cT");
    assert_eq!(
        crate::rows::fact(
            V1,
            &crate::rows::FactFields {
                id: b"i",
                subject: b"s",
                predicate: b"p",
                object: b"OBJ",
                valid_from: Some(b"f"),
                valid_to: None,
                confidence: 0.5,
                support: Some(b"SUP"),
                authority_class: Some(b"a"),
                review_state: Some(b"r"),
                canonical_key: Some(b"k"),
                extractor: Some(b"x"),
                terms: Some(b"T"),
            },
        )
        .bytes()
        .to_vec(),
        fact
    );
    assert_eq!(
        crate::rows::drawer(V1, "id", b"{}", b"c").bytes().to_vec(),
        b"id\x1f{}\x1fc".to_vec()
    );
}

/// **P-L2d** (ROADMAP O269 items 1 and 5): ten backups of an R3-flipped vault.
/// Before the build each answered `Created` — the damaged state archived as
/// clean ten times, and the prune, which keeps ten by count, evicted the one
/// archive taken before the damage, the last a restore would accept. Now each
/// is refused and the good archive stays.
#[test]
fn o269_ten_backups_of_a_damaged_vault_are_each_refused_and_the_good_one_stays() {
    let src = corpus(SecurityLevel::Sealed, 40);
    let good = match open_rw(src.path())
        .unwrap()
        .backup(&src.path().join("backups"))
        .unwrap()
    {
        BackupOutcome::Created(r) => r.name,
        BackupOutcome::Refused(r) => panic!("premise: a clean vault archives ({r:?})"),
    };
    let live = r3_flip(src.path(), "idx_drawers_room", |r| {
        rows_clean(r) && !r.storage.is_empty()
    })
    .expect("premise: an R3 flip verify used to pass");
    let root = live.path();
    let s = open_rw(root).unwrap();
    for i in 0..10 {
        match s.backup(&root.join("backups")).unwrap() {
            BackupOutcome::Refused(r) => assert!(!r.storage.is_empty(), "{i}: {r:?}"),
            BackupOutcome::Created(r) => panic!("{i}: archived a damaged vault: {r:?}"),
        }
    }
    let names: Vec<String> = std::fs::read_dir(root.join("backups"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    assert_eq!(
        names,
        vec![good],
        "the archive taken before the damage stays"
    );
}

/// **P-L2c, the index-hidden replay** (ROADMAP O269 item 4, its first
/// mechanism). An offline writer writes back an OLDER `wing_trust` row and
/// damages the `idx_audit_record_id` entry of the record that superseded it:
/// the policy leg finds a row's newest record by an indexed equality on its
/// label, so it is handed the older record and reports nothing, while the
/// chain replay — a scan in `seq` order — stays green. `verify` answered OK
/// over it and a rotation laundered it for good. The storage leg names the
/// index; `verify` fails and the rotation refuses.
#[test]
fn o269_an_index_hidden_policy_replay_fails_verify_and_the_rotation_refuses() {
    let dir = corpus(SecurityLevel::Sealed, 30);
    let root = dir.path();
    // The older assignment's row, kept; then a newer one.
    let old: (String, Vec<u8>, String) = raw(root)
        .query_row(
            "SELECT trust, tag, assigned_at FROM wing_trust WHERE wing = 'w1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    open_rw(root)
        .unwrap()
        .set_wing_trust("w1", "quarantined")
        .unwrap();
    // Written back, keyless: the older row over the newer one.
    assert_eq!(
        raw(root)
            .execute(
                "UPDATE wing_trust SET trust = ?1, tag = ?2, assigned_at = ?3 WHERE wing = 'w1'",
                rusqlite::params![old.0, old.1, old.2],
            )
            .unwrap(),
        1
    );
    let before = open_rw(root).unwrap().verify().unwrap();
    assert!(
        before
            .policy_drift
            .iter()
            .any(|p| p.starts_with("trust/w1:")),
        "premise: with the index intact the replay is a policy finding: {before:?}"
    );
    // The newer record's index entry damaged: its rowid made the older
    // record's, in the index's page only — so a lookup by the label meets the
    // older record twice and the newer one never, and no phantom label
    // appears (a flipped LABEL byte would surface as a key with no row).
    let seqs: Vec<i64> = raw(root)
        .prepare("SELECT seq FROM audit WHERE record_id = 'trust/w1' ORDER BY seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        seqs.len() == 2 && seqs[1] < 128,
        "premise: two assignments, each seq one byte in the index record: {seqs:?}"
    );
    let (ps, page) = (page_size(root), root_page(root, "idx_audit_record_id"));
    let mut bytes = std::fs::read(db(root)).unwrap();
    let pg = (page - 1) * ps;
    let hits: Vec<usize> = bytes[pg..pg + ps]
        .windows(b"trust/w1".len())
        .enumerate()
        .filter(|(_, w)| *w == b"trust/w1")
        .map(|(i, _)| pg + i)
        .collect();
    assert_eq!(
        hits.len(),
        2,
        "premise: both assignments' entries are in the index page"
    );
    // Each entry's one-byte rowid sits right after its label; the cells lie in
    // the page in insertion order, not key order, so the newer record's is
    // found by its value.
    let at = hits
        .iter()
        .map(|h| h + b"trust/w1".len())
        .find(|&at| i64::from(bytes[at]) == seqs[1])
        .expect("premise: the newer record's rowid byte follows one of the labels");
    bytes[at] = seqs[0] as u8;
    std::fs::write(db(root), &bytes).unwrap();
    let r = open_rw(root).unwrap().verify().unwrap();
    assert!(
        r.policy_drift.is_empty() && rows_clean(&r),
        "premise, the hole: every row leg is clean over the replay — what `verify` answered: {r:?}"
    );
    assert!(
        r.storage.iter().any(|f| f.contains("idx_audit_record_id")),
        "the storage leg names the index: {:?}",
        r.storage
    );
    assert!(!r.ok());
    let before = std::fs::read(db(root)).unwrap();
    let mut s = open_rw(root).unwrap();
    let next = mgr(root).rotation_candidate(VAULT).unwrap();
    match s.rotate_keys(next) {
        Err(StoreError::IntegrityFinding(why)) => {
            assert!(why.contains("idx_audit_record_id"), "{why}")
        }
        other => panic!("the replay was not refused: {other:?}"),
    }
    drop(s);
    assert_eq!(
        std::fs::read(db(root)).unwrap(),
        before,
        "nothing was re-keyed"
    );
}

/// **O406's later-0x1f move, named** (ROADMAP O269 item 2, the arm O406's
/// ruling hands here). A sealed drawer's meta/content boundary moved, with no
/// key, to a 0x1f LATER in its ciphertext: the canonical's bytes are
/// unchanged, so the tag verifies, and `meta_json` is not UTF-8 — `verify` and
/// `backup create` answered a conversion error naming nothing. It is
/// `Undecodable` now, named, and a rotation blocker, which O231's
/// `MetaUnparseable` is not: the rotation reads `meta_json` by its type and
/// could not re-tag the row at all.
///
/// **And on a vault ROADMAP O406's walk has reached, the move fails its
/// tag**: the version-2 drawer canonical length-prefixes the meta and the
/// content, so moving bytes between them changes the canonical. Both arms
/// are run: the version-1 one is every vault the walk has not reached.
#[test]
fn o269_o406s_later_separator_move_is_named_and_blocks_a_rotation() {
    for fmt in [
        undercroft_vault::RowFormat::V1,
        undercroft_vault::RowFormat::V2,
    ] {
        let dir = TempDir::new().unwrap();
        if fmt == undercroft_vault::RowFormat::V1 {
            crate::retag_pause::keep_on_v1(&vdir(dir.path()));
        }
        corpus_into(&dir, SecurityLevel::Sealed, 60);
        let root = dir.path();
        let c = raw(root);
        // A drawer whose ciphertext holds a 0x1f whose prefix is not UTF-8.
        let rows: Vec<(String, String, Vec<u8>)> = c
            .prepare("SELECT id, meta_json, content FROM drawers ORDER BY seq")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let (id, meta, content, at) = rows
            .into_iter()
            .find_map(|(id, meta, content)| {
                let at = content
                    .iter()
                    .enumerate()
                    .skip(1)
                    .filter(|(_, b)| **b == 0x1f)
                    .map(|(i, _)| i)
                    .find(|&i| std::str::from_utf8(&content[..i]).is_err())?;
                Some((id, meta, content, at))
            })
            .expect("premise: a sealed drawer holds a later 0x1f behind non-UTF-8 bytes");
        let mut new_meta = meta.into_bytes();
        new_meta.push(0x1f);
        new_meta.extend_from_slice(&content[..at]);
        assert_eq!(
            c.execute(
                "UPDATE drawers SET meta_json = CAST(?1 AS TEXT), content = ?2 WHERE id = ?3",
                rusqlite::params![new_meta, &content[at + 1..], id],
            )
            .unwrap(),
            1
        );
        drop(c);
        let s = open_rw(root).unwrap();
        assert_eq!(s.row_format(), fmt, "premise: the regime the arm is about");
        let r = s.verify().expect("a verdict, never a conversion error");
        let want = match fmt {
            undercroft_vault::RowFormat::V1 => crate::BadRecord::undecodable(
                id.clone(),
                "column meta_json holds TEXT that is not UTF-8",
            ),
            undercroft_vault::RowFormat::V2 => crate::BadRecord::tag_failed(id.clone()),
        };
        assert_eq!(r.bad_records, vec![want], "{fmt:?}: {r:?}");
        assert!(
            r.rotation_blockers().iter().any(|b| b.contains(&id)),
            "{:?}",
            r.rotation_blockers()
        );
        match s.backup(&root.join("backups")).unwrap() {
            BackupOutcome::Refused(_) => {}
            BackupOutcome::Created(r) => panic!("archived it: {r:?}"),
        }
    }
}

/// **An `immutable=1` handle's storage findings are no verdict** (ROADMAP
/// O269, the review of its first build). Such a handle reads the main file with
/// no lock and no WAL, so beside a process still writing the vault a read can
/// tear — P-O269g measured 721 of 61,742 bare reads answering `SQLITE_CORRUPT`
/// on an intact vault — and SQLite's answer then says nothing about the file.
/// The open's named doors excluded such a handle (option B); `verify`'s own
/// leg did not: it put the pragma's rows and the codes a later leg met into
/// the report, and the CLI exited 2 on them. Now `verify` on such a handle
/// answers `StorageUnverifiable` — exit 1, 409 with no class — naming why,
/// while the same file opened the ordinary way still gets the verdict, and an
/// intact vault through the same posture still verifies. The damage is real
/// here only so the outcome is deterministic: the handle cannot tell it from a
/// torn read, which is the point (the race through a store handle is
/// `p_o269g_verify_through_an_immutable_handle_beside_a_writer`, measured).
/// Counterfactual: `Ok(report)` carrying the storage leg's finding.
#[test]
fn o269_an_immutable_handle_reports_the_storage_leg_not_verifiable() {
    // An intact vault through the posture: a report, and a clean one.
    let clean = corpus(SecurityLevel::Sealed, 40);
    let r = open_immutable(clean.path()).unwrap().verify().unwrap();
    assert!(
        r.ok(),
        "an intact vault verifies on an immutable handle: {r:?}"
    );
    let live = r3_flip(clean.path(), "idx_drawers_room", |r| {
        rows_clean(r) && !r.storage.is_empty()
    })
    .expect("premise: an R3 flip");
    let root = live.path();
    let r = open_ro(root).unwrap().verify().unwrap();
    assert!(
        !r.ok() && r.storage.iter().any(|f| f.contains("idx_drawers_room")),
        "control: the ordinary read-only handle gives the verdict: {r:?}"
    );
    match open_immutable(root).unwrap().verify() {
        Err(StoreError::StorageUnverifiable(why)) => assert!(
            why.contains("immutable=1")
                && why.contains("idx_drawers_room")
                && why.contains("Nothing was concluded"),
            "{why}"
        ),
        other => panic!("an immutable handle gave a verdict: {other:?}"),
    }
}

/// What [`immutable_beside_a_writer`] counted.
#[derive(Debug, Default)]
struct BesideAWriter {
    /// `verify` calls made.
    verifies: u64,
    /// Answers that were `StorageUnverifiable`: a torn read met and no verdict.
    unverifiable: u64,
    /// Reports whose storage leg held a finding — each an integrity verdict on
    /// an intact vault.
    storage_verdicts: Vec<String>,
    /// Reports with a finding in another leg only (O435's).
    other_legs: u64,
    /// Errors, by text: each is exit 1, never a verdict.
    errors: Vec<String>,
    /// The writer's saves.
    saves: u32,
    /// The fewest and the most records a report checked: whether the handle
    /// saw the writer's rows at all.
    checked: (u64, u64),
}

/// The P-O269g run through the store: `verify` on an `immutable=1` handle with
/// an eight-page cache beside a writer, for `budget`.
fn immutable_beside_a_writer(budget: std::time::Duration) -> BesideAWriter {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let dir = corpus(SecurityLevel::Sealed, 300);
    let root = dir.path().to_path_buf();
    let s = open_immutable(&root).unwrap();
    s.conn.execute_batch("PRAGMA cache_size = 8").unwrap();
    assert!(s.verify().unwrap().ok(), "premise: clean before the writer");
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (root, stop) = (root.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut w = open_rw(&root).unwrap();
            let mut i = 0u32;
            // Large saves, so pages split and the WAL checkpoints into the
            // main file — the bytes an immutable reader reads — often.
            let body = "the harbour ledger names cargo and its pier ".repeat(60);
            while !stop.load(Ordering::Relaxed) {
                i += 1;
                w.upsert(&drawer("wg", &format!("{body} {i}"), 100_000 + i))
                    .unwrap();
                if i.is_multiple_of(4) {
                    let _ = w.conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)");
                }
            }
            i
        })
    };
    let mut run = BesideAWriter {
        checked: (u64::MAX, 0),
        ..Default::default()
    };
    let until = std::time::Instant::now() + budget;
    while std::time::Instant::now() < until {
        run.verifies += 1;
        let answer = s.verify();
        if let Ok(r) = &answer {
            run.checked = (
                run.checked.0.min(r.records_checked),
                run.checked.1.max(r.records_checked),
            );
        }
        match answer {
            Err(StoreError::StorageUnverifiable(_)) => run.unverifiable += 1,
            Ok(r) if !r.storage.is_empty() => run.storage_verdicts.push(r.storage.join("; ")),
            Ok(r) if !r.ok() => run.other_legs += 1,
            Ok(_) => {}
            Err(e) => {
                if run.errors.len() < 5 {
                    run.errors.push(e.to_string());
                }
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    run.saves = writer.join().unwrap();
    println!("immutable verify beside a writer: {run:?}");
    run
}

/// **P-O269g's setup, through the store** (ROADMAP O269, the review of its
/// first build): an `immutable=1` handle opened over an intact vault, then a
/// writer saving large drawers and checkpointing into the main file beside it,
/// and `verify` run on the handle for `O269G_SECS`. Printed, never asserted:
/// it is a measurement of whether the bare-connection race P-O269g measured
/// reaches a store handle's `verify`, and every answer it can give is counted
/// — `StorageUnverifiable` (a torn read met, no verdict), a storage finding
/// (the verdict this build's review closed), a finding in another leg, an
/// error, and the range of records the reports checked.
///
/// **Measured 2026-10-12 at O269's review**: with the default cache, 38,363
/// verifies beside 4,857 saves; with the cache cut to eight pages, 16,773
/// beside 1,920 and 7,416 beside 884. Not one torn read, and the last run's
/// reports each checked exactly 306 records (the first's printed reports read
/// the same): a long-lived `immutable=1` handle here never read the writer's
/// rows at all. What it answered instead, on all but the
/// first few verifies, was a report failing the CHAIN leg — the handle's rows
/// replayed against an anchor the writer moved on disk — which is an
/// integrity verdict on an intact vault, filed as O435. The race this
/// build's review named is therefore pinned by
/// `o269_an_immutable_handle_reports_the_storage_leg_not_verifiable`, whose
/// damage is real only so its outcome is deterministic.
#[test]
#[ignore = "P-O269g through the store; run by name with --ignored (O269G_SECS)"]
fn p_o269g_verify_through_an_immutable_handle_beside_a_writer() {
    let secs: u64 = std::env::var("O269G_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let run = immutable_beside_a_writer(std::time::Duration::from_secs(secs));
    println!(
        "P-O269g (store): {} verifies, {} unverifiable, {} storage verdicts, {} other-leg \
         findings, errors {:?}",
        run.verifies,
        run.unverifiable,
        run.storage_verdicts.len(),
        run.other_legs,
        run.errors
    );
}

/// **P-O269g** (ROADMAP O269, the maintainer's ruling of 2026-10-08): does an
/// `immutable=1` reader beside a live writer ever raise `SQLITE_CORRUPT` or
/// `SQLITE_NOTADB` on an INTACT vault? Option B mints the integrity verdict
/// only on a handle that is not `immutable=1` because the answer could be yes;
/// option A stays the alternative only if it never is, which a probe can
/// support and never prove. Looped; the counts are printed.
#[test]
#[ignore = "P-O269g; run by name with --ignored (O269G_SECS)"]
fn p_o269g_an_immutable_reader_beside_a_writer() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let secs: u64 = std::env::var("O269G_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let dir = corpus(SecurityLevel::Sealed, 300);
    let root = dir.path().to_path_buf();
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (root, stop) = (root.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut w = open_rw(&root).unwrap();
            let mut i = 0u32;
            // Large saves, so pages split and the WAL checkpoints into the
            // main file — the bytes an immutable reader reads — often.
            let body = "the harbour ledger names cargo and its pier ".repeat(60);
            while !stop.load(Ordering::Relaxed) {
                i += 1;
                w.upsert(&drawer("wg", &format!("{body} {i}"), 100_000 + i))
                    .unwrap();
                if i.is_multiple_of(4) {
                    let _ = w.conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)");
                }
            }
            i
        })
    };
    let (mut ok, mut corrupt, mut notadb, mut other) = (0u64, 0u64, 0u64, 0u64);
    let mut others: Vec<String> = Vec::new();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut reads = 0u64;
    while std::time::Instant::now() < until {
        reads += 1;
        let r = (|| -> Result<(), rusqlite::Error> {
            let c = rusqlite::Connection::open_with_flags(
                crate::backup::immutable_uri(&db(&root)),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
            )?;
            c.query_row(
                "SELECT count(*), sum(length(content)), sum(length(meta_json)) FROM drawers",
                [],
                |r| r.get::<_, i64>(0),
            )?;
            c.query_row("SELECT count(*) FROM audit", [], |r| r.get::<_, i64>(0))?;
            Ok(())
        })();
        match r {
            Ok(()) => ok += 1,
            Err(rusqlite::Error::SqliteFailure(f, _))
                if f.code == rusqlite::ErrorCode::DatabaseCorrupt =>
            {
                corrupt += 1
            }
            Err(rusqlite::Error::SqliteFailure(f, _))
                if f.code == rusqlite::ErrorCode::NotADatabase =>
            {
                notadb += 1
            }
            Err(e) => {
                other += 1;
                if others.len() < 5 {
                    others.push(e.to_string());
                }
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    let saves = writer.join().unwrap();
    println!(
        "P-O269g: {reads} immutable reads beside {saves} saves: ok {ok}, SQLITE_CORRUPT {corrupt}, \
         SQLITE_NOTADB {notadb}, other {other} {others:?}"
    );
}

/// **P-O269d** (ROADMAP O269's ruling): one byte flipped in a `drawers_fts_data`
/// page of an hmac-only vault. `integrity_check` reaches it through FTS5's own
/// integrity pass; the probe settles whether the lexical prefilter
/// under-returns meanwhile. Printed, never asserted.
#[test]
#[ignore = "P-O269d; run by name with --ignored"]
fn p_o269d_a_flipped_fts_page() {
    let src = corpus(SecurityLevel::HmacOnly, 200);
    let query = "harbour ledger cargo 117";
    let before: Vec<String> = open_rw(src.path())
        .unwrap()
        .search(
            query,
            &crate::SearchOptions {
                limit: 10,
                ..Default::default()
            },
        )
        .unwrap()
        .into_iter()
        .map(|h| h.drawer.id)
        .collect();
    let ps = page_size(src.path());
    let page = root_page(src.path(), "drawers_fts_data");
    let pages = std::fs::metadata(db(src.path())).unwrap().len() as usize / ps;
    let mut tried = 0;
    let mut seen = 0;
    for p in page..=pages {
        for off in (100..ps - 8).step_by(211) {
            let cand = clone_root(src.path());
            let mut bytes = std::fs::read(db(cand.path())).unwrap();
            bytes[(p - 1) * ps + off] ^= 0x01;
            std::fs::write(db(cand.path()), &bytes).unwrap();
            // A flip that breaks the schema itself refuses even this read.
            let ic = match std::panic::catch_unwind(|| integrity_check(cand.path())) {
                Ok(ic) => ic,
                Err(_) => continue,
            };
            tried += 1;
            if ic == ["ok"]
                || !ic
                    .iter()
                    .any(|l| l.contains("fts5") || l.contains("drawers_fts"))
            {
                continue;
            }
            seen += 1;
            let s = match open_rw(cand.path()) {
                Ok(s) => s,
                Err(e) => {
                    println!("P-O269d page {p} off {off}: open refused: {e}");
                    continue;
                }
            };
            let v = s.verify().map(|r| (r.ok(), r.storage.len()));
            let after = s
                .search(
                    query,
                    &crate::SearchOptions {
                        limit: 10,
                        ..Default::default()
                    },
                )
                .map(|h| h.into_iter().map(|h| h.drawer.id).collect::<Vec<_>>());
            println!(
                "P-O269d page {p} off {off}: integrity_check {:?}; verify (ok, storage rows) {v:?}; \
                 search same as before: {:?}",
                ic.iter().take(2).collect::<Vec<_>>(),
                after.as_ref().map(|a| *a == before).map_err(|e| e.to_string())
            );
            if seen >= 6 {
                println!("P-O269d: {tried} flips tried");
                return;
            }
        }
    }
    println!("P-O269d: {tried} flips tried, {seen} reached FTS5's check");
}

/// **P-O269b / P-O269h, the storage leg's cost at scale** (ROADMAP O269 item
/// 9). A vault of `O269_DRAWERS` LoCoMo-feed chunks (five turns each) in
/// eight wings, at `O269_LEVEL` (`sealed` or `hmac`), with the PQ tier and
/// every wing's PQ tier built; then, three rounds each: `verify` whole, the
/// check alone in a snapshot, the backup's pinned span beside a writer saving
/// every 10 ms (O256's line), and one rotation's whole hold. The corpus is
/// built once into `O269_CORPUS`. Printed, never asserted: the ruling records
/// the cost and never narrows the check for it.
#[test]
#[ignore = "ROADMAP O269 cost; run by name with --ignored (O269_DRAWERS, O269_LEVEL, O269_FEED, O269_CORPUS)"]
fn p_o269b_cost_of_the_storage_leg_at_scale() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let n: usize = env("O269_DRAWERS", "102000").parse().unwrap();
    let level_name = env("O269_LEVEL", "sealed");
    let level = match level_name.as_str() {
        "hmac" => SecurityLevel::HmacOnly,
        _ => SecurityLevel::Sealed,
    };
    let corpus_dir = PathBuf::from(env(
        "O269_CORPUS",
        &format!("/build/o269-corpus-{level_name}-{n}"),
    ));
    let feed = std::fs::read_to_string(env("O269_FEED", "/feed/locomo_feed.txt")).unwrap();
    let lines: Vec<&str> = feed.lines().filter(|l| !l.trim().is_empty()).collect();
    let ms = |t: Instant| t.elapsed().as_secs_f64() * 1e3;
    if !db(&corpus_dir).exists() {
        let t = Instant::now();
        std::fs::create_dir_all(&corpus_dir).unwrap();
        let mut s = VaultStore::open(mgr(&corpus_dir).create(VAULT, level).unwrap()).unwrap();
        for chunk in (0..n).collect::<Vec<_>>().chunks(2000) {
            let batch: Vec<Drawer> = chunk
                .iter()
                .map(|&i| {
                    let text: Vec<&str> =
                        (0..5).map(|k| lines[(i * 5 + k) % lines.len()]).collect();
                    let mut d = drawer(
                        &format!("w{}", i % 8),
                        &format!("{} [{i}]", text.join("\n")),
                        i as u32,
                    );
                    d.meta.room = format!("r{}", i % 13);
                    d
                })
                .collect();
            s.upsert_many(&batch).unwrap();
        }
        s.set_pq(true);
        s.search(
            "support group painting",
            &crate::SearchOptions {
                limit: 5,
                ..Default::default()
            },
        )
        .unwrap();
        for w in 0..8 {
            s.search(
                "support group painting",
                &crate::SearchOptions {
                    wing: Some(format!("w{w}")),
                    limit: 5,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        println!(
            "O269_COST corpus: {n} drawers, {level_name}, built in {:.0} s",
            t.elapsed().as_secs_f64()
        );
    }
    let work = clone_root(&corpus_dir);
    let root = work.path().to_path_buf();
    let size = std::fs::metadata(db(&root)).unwrap().len();
    let audit: i64 = raw(&root)
        .query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))
        .unwrap();
    let tables: i64 = raw(&root)
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    println!("O269_COST vault: {n} drawers, {audit} audit rows, {tables} tables, {size} bytes");
    let s = open_rw(&root).unwrap();
    for round in 0..3 {
        let t = Instant::now();
        let r = s.verify().unwrap();
        let whole = ms(t);
        assert!(r.ok(), "{r:?}");
        let t = Instant::now();
        let found = s.snapshot(|snap| s.storage_check_in(snap)).unwrap();
        let check = ms(t);
        assert!(found.is_empty());
        println!(
            "O269_COST round {round}: verify {whole:.0} ms (storage leg alone {check:.0} ms, the \
             other legs ~{:.0} ms)",
            whole - check
        );
    }
    // The backup's pin beside a writer saving every 10 ms (O256's P-C line).
    let stop = Arc::new(AtomicBool::new(false));
    let lat = Arc::new(Mutex::new(Vec::<f64>::new()));
    let writer = {
        let (root, stop, lat) = (root.clone(), stop.clone(), lat.clone());
        std::thread::spawn(move || {
            let mut w = open_rw(&root).unwrap();
            let mut i = 0u32;
            while !stop.load(Ordering::Relaxed) {
                i += 1;
                let t = Instant::now();
                w.upsert(&drawer("wsaves", &format!("a later save {i}"), 900_000 + i))
                    .expect("never refused beside a backup");
                lat.lock().unwrap().push(t.elapsed().as_secs_f64() * 1e3);
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };
    std::thread::sleep(Duration::from_millis(500));
    let marks: Arc<Mutex<Vec<(crate::backup_pause::Phase, Instant)>>> =
        Arc::new(Mutex::new(Vec::new()));
    {
        let marks = marks.clone();
        crate::backup_pause::set(
            &vdir(&root),
            Arc::new(move |p| marks.lock().unwrap().push((p, Instant::now()))),
        );
    }
    for round in 0..3 {
        marks.lock().unwrap().clear();
        let t = Instant::now();
        match s.backup(&root.join("backups")).unwrap() {
            BackupOutcome::Created(_) => {}
            BackupOutcome::Refused(r) => panic!("{r:?}"),
        }
        let total = ms(t);
        let m = marks.lock().unwrap().clone();
        let at = |p: crate::backup_pause::Phase| m.iter().find(|(q, _)| *q == p).unwrap().1;
        let pinned = at(crate::backup_pause::Phase::Copied)
            .duration_since(at(crate::backup_pause::Phase::Pinned))
            .as_secs_f64()
            * 1e3;
        let verified = at(crate::backup_pause::Phase::Verified)
            .duration_since(at(crate::backup_pause::Phase::Pinned))
            .as_secs_f64()
            * 1e3;
        println!(
            "O269_COST backup round {round}: {total:.0} ms, pinned {pinned:.0} ms (verify inside \
             the pin {verified:.0} ms)"
        );
    }
    crate::backup_pause::set(&vdir(&root), Arc::new(|_| {}));
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    let mut l = lat.lock().unwrap().clone();
    l.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "O269_COST writer beside the backups: {} saves, p50 {:.1} ms, p99 {:.1} ms, max {:.1} ms",
        l.len(),
        l[l.len() / 2],
        l[l.len() * 99 / 100],
        l[l.len() - 1]
    );
    drop(s);
    // One rotation's whole hold: its verify (the storage leg inside) and the
    // re-key, from the fence to the promote.
    let mut s = open_rw(&root).unwrap();
    let next = mgr(&root).rotation_candidate(VAULT).unwrap();
    let t = Instant::now();
    s.rotate_keys(next).unwrap();
    println!("O269_COST rotation: {:.0} ms, the hold whole", ms(t));
}

/// **A legitimate writer beside a long-lived handle is never storage damage**
/// (found by P-O269b on its first hmac-only run). FTS5 caches its index
/// structure on a connection and its integrity pass reused the cache, so a
/// server's handle whose last FTS read predated another connection's FTS write
/// reported `malformed inverted index for FTS5 table main.drawers_fts` on an
/// intact vault — every `verify` and `backup create` beside a writer failed.
/// The storage leg reads each FTS5 table in its snapshot first. The premise
/// arm runs the bare pragma on the same stale handle and must see the false
/// finding, or this test proves nothing.
#[test]
fn o269_a_writer_beside_a_long_lived_handle_is_no_storage_finding() {
    let dir = corpus(SecurityLevel::HmacOnly, 300);
    let root = dir.path().to_path_buf();
    let a = open_rw(&root).unwrap();
    assert!(
        a.verify().unwrap().ok(),
        "premise: clean, and the handle's FTS cache warm"
    );
    let mut b = open_rw(&root).unwrap();
    for i in 0..5u32 {
        b.upsert(&drawer(
            "wb",
            &format!("a later save number {i} about ledgers"),
            50_000 + i,
        ))
        .unwrap();
    }
    // The premise, on a handle made stale the same way: the bare pragma in a
    // fresh snapshot reports the FTS5 table malformed.
    let stale = open_rw(&root).unwrap();
    assert!(
        stale.verify().unwrap().ok(),
        "premise: warm the second handle too"
    );
    b.upsert(&drawer("wb", "one more save about ledgers", 60_000))
        .unwrap();
    let bare: Vec<String> = stale
        .snapshot(|snap| {
            let mut st = snap.conn().prepare("PRAGMA integrity_check")?;
            let v: Vec<String> = st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
            Ok(v)
        })
        .unwrap();
    assert!(
        bare.iter()
            .any(|l| l.contains("malformed inverted index for FTS5")),
        "premise: the stale cache misleads the bare check: {bare:?}"
    );
    let r = a.verify().unwrap();
    assert!(r.ok(), "a legitimate writer is not damage: {r:?}");
    let r = stale.verify().unwrap();
    assert!(r.ok(), "{r:?}");
}
