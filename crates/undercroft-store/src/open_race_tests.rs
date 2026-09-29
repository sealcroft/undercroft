//! ROADMAP O279 (and O280, O282, O283): every open of a vault's database by
//! path proves, after its first locking statement, that its descriptor is the
//! file at the path — so an open that raced a `backup restore` swap is refused
//! and reopened, instead of serving the vault set aside and writing into the
//! restored one.
//!
//! Every race is a REAL `restore_archive` swapped in at a pause point between
//! an opener's `Connection::open` and its first statement, over a multi-page
//! sealed vault. The restored directory is compared with the stage the restore
//! swapped in, hashed at `Phase::Held` — never while this process has a
//! connection open on those files, since reading a database's file with a
//! second descriptor and closing it drops the process's POSIX locks on it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use tempfile::TempDir;
use undercroft_core::embed::Embedder;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::restores::RESTORE_ROOT;
use undercroft_vault::{Access, SecurityLevel, Vault, VaultError, VaultManager};

use crate::open_pause::{self, Opener};
use crate::restore_pause::{self, Phase};
use crate::{
    hold_vault_exclusively, restore_archive, BackupOutcome, BackupReport, RestoreOutcome,
    RestoreReport, StoreError, VaultStore,
};

const VAULT: &str = "o279";

/// A stage's files, captured by a restore pause hook.
type Staged = Arc<Mutex<Option<BTreeMap<String, Vec<u8>>>>>;

fn hash(_: &Vault) -> Result<Box<dyn Embedder + Send>, StoreError> {
    Ok(Box::new(HashEmbedder))
}

fn mgr(root: &Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn ro_mgr(root: &Path) -> VaultManager {
    VaultManager::open_as(root, None, Access::ReadOnly).unwrap()
}

fn open_at(root: &Path) -> VaultStore {
    VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap()
}

fn open_ro(root: &Path) -> Result<VaultStore, StoreError> {
    VaultStore::open_read_only(ro_mgr(root).unlock(VAULT).unwrap(), Box::new(HashEmbedder))
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn drawer(wing: &str, content: String, idx: u32) -> Drawer {
    Drawer::new(
        wing,
        "r",
        content,
        Some(format!("o279-{wing}.md")),
        idx,
        "test",
    )
}

/// A sealed vault of `n` drawers, in a fresh palace under `parent` (the
/// system temp directory when `None`).
fn corpus_in(parent: Option<&Path>, n: usize) -> TempDir {
    let dir = match parent {
        Some(p) => TempDir::new_in(p).unwrap(),
        None => TempDir::new().unwrap(),
    };
    let mut s = VaultStore::open(
        mgr(dir.path())
            .create(VAULT, SecurityLevel::Sealed)
            .unwrap(),
    )
    .unwrap();
    let batch: Vec<Drawer> = (0..n)
        .map(|i| {
            drawer(
                "w1",
                format!(
                    "note {i}: the harbour ledger names cargo {i}, bound for the eastern quay \
                     with a manifest of {} crates and a pilot named for the tide",
                    i * 7
                ),
                i as u32,
            )
        })
        .collect();
    s.upsert_many(&batch).unwrap();
    dir
}

fn corpus(n: usize) -> TempDir {
    corpus_in(None, n)
}

/// `n` saves after the archive, so the vault a restore replaces has moved on.
fn later(root: &Path, n: u32) {
    let mut s = open_at(root);
    for i in 0..n {
        s.upsert(&drawer(
            "w2",
            format!("a later save {i}, long enough to move a page or two"),
            i,
        ))
        .unwrap();
    }
}

fn archive(root: &Path) -> (PathBuf, BackupReport) {
    let s = open_at(root);
    let r = match s.backup(&root.join("backups")).unwrap() {
        BackupOutcome::Created(r) => r,
        BackupOutcome::Refused(r) => panic!("premise: the vault verifies ({r:?})"),
    };
    (root.join("backups").join(&r.name), r)
}

fn restore(root: &Path, arch: &Path) -> RestoreReport {
    match restore_archive(&mgr(root), arch, None, true, &hash) {
        Ok(RestoreOutcome::Restored(r)) => r,
        Ok(RestoreOutcome::Refused(r)) => panic!("premise: the archive verifies ({r:?})"),
        Err(e) => panic!("premise: the restore runs ({e})"),
    }
}

/// Every regular file directly in `dir`, by name, with its bytes.
fn files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                out.insert(
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                );
            }
        }
    }
    out
}

/// The stage a restore under `root` is about to swap in, hashed at
/// `Phase::Held` (its store is closed; the hold is on the LIVE vault).
fn stage_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let area = root.join("vaults").join(RESTORE_ROOT);
    let stage = std::fs::read_dir(&area)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("stage-"))
        })
        .expect("premise: a stage exists at Phase::Held");
    files(&stage)
}

/// The restored vault is what the restore put in place: its database and
/// manifest byte-identical to the stage, any `-wal` holding no frame, the
/// `-shm` exempt (reconstructible scaffolding, R4's residue), no other file;
/// `integrity_check` ok; and a fresh open verifying at the report's head,
/// height and count.
fn assert_restored_untouched(
    root: &Path,
    staged: &BTreeMap<String, Vec<u8>>,
    report: &RestoreReport,
    count: u64,
    label: &str,
) {
    let now = files(&vdir(root));
    for f in ["vault.db", "vault.json"] {
        assert!(
            staged.contains_key(f),
            "{label}: premise: the stage held {f}"
        );
        assert!(
            now.get(f) == staged.get(f),
            "{label}: {f} is byte-identical to what the restore swapped in"
        );
    }
    for (name, bytes) in &now {
        match name.as_str() {
            "vault.db" | "vault.json" | "vault.db-shm" => {}
            "vault.db-wal" => assert!(
                bytes.is_empty(),
                "{label}: the restored -wal holds {} bytes of frames",
                bytes.len()
            ),
            other => panic!("{label}: the restored directory gained {other}"),
        }
    }
    {
        let c = Connection::open_with_flags(
            vdir(root).join("vault.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let ok: String = c
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ok, "ok", "{label}: integrity_check");
    }
    let s = open_at(root);
    assert!(
        s.verify().unwrap().ok(),
        "{label}: the restored vault verifies"
    );
    let (head, writes) = s.chain_state().unwrap();
    assert_eq!(
        (head.as_str(), writes),
        (report.chain_head.as_str(), report.writes),
        "{label}: the restored vault holds exactly the reported state"
    );
    assert_eq!(s.count().unwrap(), count, "{label}: the archive's rows");
}

/// The O279 refusal, by variant AND wording, so O257's race arm or a
/// `VaultHeld` cannot pass for it.
fn is_moved(e: &StoreError) -> bool {
    matches!(e, StoreError::StaleUnlock(m)
        if m.contains("is not the one at") && m.contains("ROADMAP O279"))
}

/// A restore swapped in when `at` first fires for the vault under `root`,
/// entirely inside the window; the stage is hashed at `Phase::Held`.
struct Race {
    dir: PathBuf,
    report: Arc<Mutex<Option<RestoreReport>>>,
    staged: Staged,
}

impl Race {
    fn at(root: &Path, at: Opener, arch: &Path) -> Race {
        let (report, staged) = (Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)));
        {
            let (r, staged) = (root.to_path_buf(), staged.clone());
            restore_pause::set(
                root,
                Arc::new(move |p| {
                    if p == Phase::Held {
                        *staged.lock().unwrap() = Some(stage_files(&r));
                    }
                }),
            );
        }
        let armed = Arc::new(AtomicBool::new(true));
        let (r, arch, report2) = (root.to_path_buf(), arch.to_path_buf(), report.clone());
        open_pause::set(
            &vdir(root),
            Arc::new(move |here| {
                if here == at && armed.swap(false, Ordering::SeqCst) {
                    *report2.lock().unwrap() = Some(restore(&r, &arch));
                }
            }),
        );
        Race {
            dir: vdir(root),
            report,
            staged,
        }
    }

    fn finish(self) -> (RestoreReport, BTreeMap<String, Vec<u8>>) {
        open_pause::clear(&self.dir);
        let report = self
            .report
            .lock()
            .unwrap()
            .take()
            .expect("premise: the window was reached and the restore ran in it");
        let staged = self.staged.lock().unwrap().take().expect("premise: staged");
        (report, staged)
    }
}

// ---------------------------------------------------------------------------
// Each opener, raced
// ---------------------------------------------------------------------------

/// **G1 — P1 inverted.** A writable open whose descriptor was taken before a
/// restore's swap is refused with the reopen class; the restored vault is
/// exactly what the restore put in place, and the reopen serves it. Before
/// O279 this open answered Ok, served the 2,050 rows set aside, and healed the
/// restored manifest forward — the restored vault then refused to open as
/// tampered, and one save through the racer corrupted it.
#[test]
fn o279_a_writable_open_that_raced_a_swap_is_refused_and_the_restored_vault_is_untouched() {
    let dir = corpus(2000);
    let root = dir.path().to_path_buf();
    let (arch, created) = archive(&root);
    later(&root, 50);
    let race = Race::at(&root, Opener::Writable, &arch);
    let racer = VaultStore::open(mgr(&root).unlock(VAULT).unwrap());
    let (report, staged) = race.finish();
    match racer {
        Err(e) => assert!(is_moved(&e), "the racer answers the reopen class: {e:?}"),
        Ok(s) => panic!(
            "the racer opened and serves {:?} rows of the vault set aside",
            s.count()
        ),
    }
    assert_eq!(
        report.writes, created.writes,
        "premise: the archive's state"
    );
    assert_restored_untouched(&root, &staged, &report, 2000, "writable");
}

/// **G2 — P1b inverted.** The realistic interleaving: the restore takes its
/// hold inside the window, the racer's first statement arrives while it is held
/// and waits it out, and the swap runs on its own thread.
#[test]
fn o279_an_open_whose_first_statement_waited_out_the_hold_is_refused() {
    let dir = corpus(2000);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    later(&root, 50);
    let (held_tx, held_rx) = mpsc::channel::<()>();
    let held_tx = Mutex::new(Some(held_tx));
    let staged: Staged = Default::default();
    {
        let (r, staged) = (root.clone(), staged.clone());
        restore_pause::set(
            &root,
            Arc::new(move |p| {
                if p == Phase::Held {
                    *staged.lock().unwrap() = Some(stage_files(&r));
                    if let Some(tx) = held_tx.lock().unwrap().take() {
                        tx.send(()).unwrap();
                        std::thread::sleep(Duration::from_millis(300));
                    }
                }
            }),
        );
    }
    let worker: Arc<Mutex<Option<std::thread::JoinHandle<RestoreReport>>>> = Default::default();
    let armed = Arc::new(AtomicBool::new(true));
    {
        let (r, arch, worker, armed) = (root.clone(), arch.clone(), worker.clone(), armed.clone());
        let held_rx = Mutex::new(held_rx);
        open_pause::set(
            &vdir(&root),
            Arc::new(move |here| {
                if here == Opener::Writable && armed.swap(false, Ordering::SeqCst) {
                    let (r, arch) = (r.clone(), arch.clone());
                    *worker.lock().unwrap() = Some(std::thread::spawn(move || restore(&r, &arch)));
                    held_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(60))
                        .expect("premise: the restore took its hold");
                }
            }),
        );
    }
    let t = Instant::now();
    let racer = VaultStore::open(mgr(&root).unlock(VAULT).unwrap());
    let waited = t.elapsed();
    open_pause::clear(&vdir(&root));
    let report = worker
        .lock()
        .unwrap()
        .take()
        .expect("premise: the window was reached")
        .join()
        .unwrap();
    assert!(
        waited >= Duration::from_millis(250),
        "premise: the first statement waited out the hold ({waited:?})"
    );
    match racer {
        Err(e) => assert!(is_moved(&e), "{e:?}"),
        Ok(_) => panic!("the racer opened on the vault set aside"),
    }
    let staged = staged.lock().unwrap().take().unwrap();
    assert_restored_untouched(&root, &staged, &report, 2000, "waited out the hold");
}

/// **G3 — P2 inverted, and the two-rename gap.** A read-only open that raced
/// the swap is refused rather than serving the vault that no longer exists;
/// and a probe that fails because it ran in the gap between the swap's renames
/// is refused too — never reopened `immutable=1` onto whatever the path names
/// next (its seam must not fire).
#[test]
fn o279_a_read_only_open_that_raced_a_swap_is_refused_and_never_escalates() {
    let dir = corpus(2000);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    later(&root, 50);
    let race = Race::at(&root, Opener::ReadOnly, &arch);
    let racer = open_ro(&root);
    let (report, staged) = race.finish();
    match racer {
        Err(e) => assert!(is_moved(&e), "{e:?}"),
        Ok(s) => panic!("the read-only racer serves {:?} rows set aside", s.count()),
    }
    assert_restored_untouched(&root, &staged, &report, 2000, "read-only");

    // The gap: the directory renamed away inside the window and put back only
    // after the open answered.
    let vd = vdir(&root);
    let gap = root.join("vaults").join("o279-in-the-gap");
    let escalated = Arc::new(AtomicBool::new(false));
    {
        let (vd2, gap2, escalated) = (vd.clone(), gap.clone(), escalated.clone());
        let armed = AtomicBool::new(true);
        open_pause::set(
            &vd,
            Arc::new(move |here| match here {
                Opener::ReadOnly if armed.swap(false, Ordering::SeqCst) => {
                    std::fs::rename(&vd2, &gap2).unwrap();
                }
                Opener::Immutable => escalated.store(true, Ordering::SeqCst),
                _ => {}
            }),
        );
    }
    let v = ro_mgr(&root).unlock(VAULT).unwrap();
    let in_gap = VaultStore::open_read_only(v, Box::new(HashEmbedder));
    open_pause::clear(&vd);
    std::fs::rename(&gap, &vd).unwrap();
    match in_gap {
        Err(e) => assert!(is_moved(&e), "a probe that failed in the gap: {e:?}"),
        Ok(_) => panic!("an open in the gap served something"),
    }
    assert!(
        !escalated.load(Ordering::SeqCst),
        "a moved file was reopened immutable=1"
    );
    assert!(open_at(&root).verify().unwrap().ok());
}

/// **G4 — the `immutable=1` arm proves its file too.** The ordinary read-only
/// open is made to fail inside its window — a directory where its `-wal` goes,
/// which SQLite cannot open (`CANTOPEN`, not busy) — so it escalates; the
/// blocker is gone once the escalation's window opens. A restore swapped in
/// there is refused. The control: with no swap the escalation serves. (A `-shm`
/// blocked by a directory is NOT enough on this build: a read-only connection
/// then reads its `-wal` without a wal-index and serves the ordinary way, so
/// `a_vault_whose_wal_index_cannot_be_created_is_read_as_an_immutable_snapshot`
/// may not reach the escalation its name claims — it asserts only that reads
/// are served.)
#[test]
fn o279_the_immutable_escalation_proves_its_file() {
    let dir = corpus(200);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    let fired = Arc::new(AtomicUsize::new(0));
    let restored: Arc<Mutex<Option<RestoreReport>>> = Default::default();
    // Block the ordinary arm, unblock at the escalation, and there restore
    // `arch` when one is given.
    let escalate = |root: &Path, then: Option<PathBuf>| {
        let (vd, fired, restored) = (vdir(root), fired.clone(), restored.clone());
        let (r, wal) = (root.to_path_buf(), vdir(root).join("vault.db-wal"));
        let armed = AtomicBool::new(true);
        open_pause::set(
            &vd,
            Arc::new(move |here| match here {
                Opener::ReadOnly => {
                    let _ = std::fs::remove_file(&wal);
                    std::fs::create_dir(&wal).unwrap();
                }
                Opener::Immutable if armed.swap(false, Ordering::SeqCst) => {
                    fired.fetch_add(1, Ordering::SeqCst);
                    std::fs::remove_dir(&wal).unwrap();
                    if let Some(arch) = &then {
                        *restored.lock().unwrap() = Some(restore(&r, arch));
                    }
                }
                _ => {}
            }),
        );
    };
    escalate(&root, None);
    let control = open_ro(&root);
    open_pause::clear(&vdir(&root));
    let control = control.expect("control: the escalation serves");
    assert_eq!(fired.load(Ordering::SeqCst), 1, "premise: it escalated");
    assert_eq!(control.count().unwrap(), 200);
    drop(control);

    let staged: Staged = Default::default();
    {
        let (r, staged) = (root.clone(), staged.clone());
        restore_pause::set(
            &root,
            Arc::new(move |p| {
                if p == Phase::Held {
                    *staged.lock().unwrap() = Some(stage_files(&r));
                }
            }),
        );
    }
    escalate(&root, Some(arch.clone()));
    let racer = open_ro(&root);
    open_pause::clear(&vdir(&root));
    assert_eq!(
        fired.load(Ordering::SeqCst),
        2,
        "premise: it escalated again"
    );
    match racer {
        Err(e) => assert!(is_moved(&e), "{e:?}"),
        Ok(_) => panic!("the immutable racer served the vault set aside"),
    }
    let report = restored.lock().unwrap().take().expect("premise: restored");
    let staged = staged.lock().unwrap().take().expect("premise: staged");
    assert_restored_untouched(&root, &staged, &report, 200, "immutable");
}

/// **G5 — P3 inverted.** O69's own hold, opened before ANOTHER restore's swap,
/// is refused as `VaultHeld` with its own wording — never granted on the file
/// that restore set aside while a live store holds the one in place — and the
/// live store keeps serving the file at the path.
#[test]
fn o279_a_hold_opened_before_another_restores_swap_is_refused() {
    let dir = corpus(200);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    let live: Arc<Mutex<Option<VaultStore>>> = Default::default();
    {
        let (r, arch, live) = (root.clone(), arch.clone(), live.clone());
        let armed = AtomicBool::new(true);
        open_pause::set(
            &vdir(&root),
            Arc::new(move |here| {
                if here == Opener::Hold && armed.swap(false, Ordering::SeqCst) {
                    restore(&r, &arch);
                    *live.lock().unwrap() = Some(open_at(&r));
                }
            }),
        );
    }
    let second = hold_vault_exclusively(&vdir(&root), crate::HoldFor::Restore);
    open_pause::clear(&vdir(&root));
    match second {
        Err(StoreError::VaultHeld(m)) => assert!(
            m.contains("was replaced by another restore") && m.contains("ROADMAP O279"),
            "{m}"
        ),
        Err(e) => panic!("the wrong refusal: {e:?}"),
        Ok(_) => panic!("the hold was granted on the file the first restore set aside"),
    }
    let mut live = live.lock().unwrap().take().expect("premise: the window");
    live.upsert(&drawer("w3", "written by the live store".into(), 1))
        .unwrap();
    assert_eq!(live.count().unwrap(), 201, "the live store still serves");
    match hold_vault_exclusively(&vdir(&root), crate::HoldFor::Restore) {
        Err(StoreError::VaultHeld(m)) => {
            assert!(m.contains("open in another process"), "{m}")
        }
        other => panic!("a fresh hold beside the live store: {:?}", other.err()),
    }
    drop(live);
    assert!(hold_vault_exclusively(&vdir(&root), crate::HoldFor::Restore).is_ok());
}

/// **G5b — PR6.** A database that vanished between the hold's existence check
/// and its open is refused as replaced — never CREATED empty and locked, which
/// a CREATE-bearing open did and then granted the hold on a file that matters
/// to nobody.
#[test]
fn o279_a_hold_whose_database_vanished_creates_nothing() {
    let dir = corpus(20);
    let root = dir.path().to_path_buf();
    let vd = vdir(&root);
    let (db, away) = (vd.join("vault.db"), vd.join("vault.db.away"));
    {
        let (db, away) = (db.clone(), away.clone());
        let armed = AtomicBool::new(true);
        open_pause::set(
            &vd,
            Arc::new(move |here| {
                if here == Opener::HoldLayout && armed.swap(false, Ordering::SeqCst) {
                    std::fs::rename(&db, &away).unwrap();
                }
            }),
        );
    }
    let held = hold_vault_exclusively(&vd, crate::HoldFor::Restore);
    open_pause::clear(&vd);
    let created = db.exists();
    std::fs::rename(&away, &db).unwrap();
    match held {
        Err(StoreError::VaultHeld(m)) => assert!(m.contains("ROADMAP O279"), "{m}"),
        other => panic!("{:?}", other.err()),
    }
    assert!(!created, "the hold created an empty database");
}

/// **G6 — P4, P11, the moved legacy file and the rename's ENOENT (ROADMAP
/// O279, O280), and the step's hold (O281).** A legacy `palace.db` vault's
/// rename step never creates or overwrites a database, and nothing opens the
/// file while it renames: arm (d) here used to run a second Undercroft open to
/// completion between the checkpoint and the rename, which the hold now makes
/// impossible — (f) is that interleaving now.
#[test]
fn o280_the_legacy_rename_never_creates_or_overwrites_a_database() {
    // (a) P4: a restore swaps a `vault.db` in after the layout was read.
    let dir = corpus(200);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    make_legacy(&root);
    let race = Race::at(&root, Opener::LegacyLayout, &arch);
    let racer = VaultStore::open(mgr(&root).unlock(VAULT).unwrap());
    let (report, _) = race.finish();
    let racer = racer.expect("the open proceeds on the restored vault.db");
    assert_eq!(
        racer.count().unwrap(),
        200,
        "the restored rows, not an empty file"
    );
    drop(racer);
    let s = open_at(&root);
    assert!(s.verify().unwrap().ok());
    assert_eq!(s.chain_state().unwrap().1, report.writes);
    assert!(!vdir(&root).join("palace.db").exists());
    drop(s);

    // (b) P11: another writable open migrates inside this one's window, and
    // stays open as a server would.
    let dir = corpus(500);
    let root = dir.path().to_path_buf();
    make_legacy(&root);
    let second = second_open_at(&root, Opener::LegacyLayout);
    let first = VaultStore::open(mgr(&root).unlock(VAULT).unwrap()).expect("the first open");
    open_pause::clear(&vdir(&root));
    let second = second.lock().unwrap().take().expect("premise: the window");
    assert_eq!(
        first.count().unwrap(),
        500,
        "the first open serves the rows"
    );
    assert_eq!(second.count().unwrap(), 500, "and so does the second");
    drop((first, second));
    let s = open_at(&root);
    assert!(s.verify().unwrap().ok());
    assert_eq!(s.count().unwrap(), 500, "nothing was emptied");
    drop(s);

    // (c) The legacy file moved between its open and its first read: refused
    // before the checkpoint; the legacy sidecars that read left by path are
    // swept by the reopen.
    let dir = corpus(200);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    make_legacy(&root);
    let race = Race::at(&root, Opener::Legacy, &arch);
    let racer = VaultStore::open(mgr(&root).unlock(VAULT).unwrap());
    let (report, staged) = race.finish();
    match racer {
        Err(e) => assert!(is_moved(&e), "{e:?}"),
        Ok(_) => panic!("the legacy step proceeded on the file set aside"),
    }
    let now = files(&vdir(&root));
    for f in ["vault.db", "vault.json"] {
        assert!(now.get(f) == staged.get(f), "legacy: {f} untouched");
    }
    for leftover in ["palace.db-wal", "palace.db-shm"] {
        if let Some(bytes) = now.get(leftover) {
            if leftover.ends_with("-wal") {
                assert!(bytes.is_empty(), "the refused legacy read left frames");
            }
        }
    }
    assert!(!now.contains_key("palace.db"), "no legacy database created");
    let s = open_at(&root);
    assert!(s.verify().unwrap().ok());
    assert_eq!(s.chain_state().unwrap().1, report.writes);
    drop(s);
    let after = files(&vdir(&root));
    assert!(
        !after.keys().any(|k| k.starts_with("palace.db")),
        "the reopen swept the legacy sidecars: {:?}",
        after.keys().collect::<Vec<_>>()
    );

    // (d) Something that is not Undercroft renamed the legacy file between
    // this one's checkpoint and its rename (no Undercroft open can: the step
    // holds the file exclusively there, ROADMAP O281): the directory read at
    // the rename says so, and the open proceeds on `vault.db`.
    let dir = corpus(300);
    let root = dir.path().to_path_buf();
    make_legacy(&root);
    let vd = vdir(&root);
    at_rename(&vd, |vd| {
        std::fs::rename(vd.join("palace.db"), vd.join("vault.db")).unwrap()
    });
    let first = VaultStore::open(mgr(&root).unlock(VAULT).unwrap()).expect("the first open");
    open_pause::clear(&vd);
    assert_eq!(first.count().unwrap(), 300);
    drop(first);
    let s = open_at(&root);
    assert!(s.verify().unwrap().ok());
    assert_eq!(s.count().unwrap(), 300);
    drop(s);

    // (e) A `vault.db` appeared beside the legacy file there: O7's two-files
    // verdict, and `rename(2)` never replaces it.
    let dir = corpus(300);
    let root = dir.path().to_path_buf();
    make_legacy(&root);
    let vd = vdir(&root);
    at_rename(&vd, |vd| {
        std::fs::write(vd.join("vault.db"), b"a stray").unwrap()
    });
    let opened = VaultStore::open(mgr(&root).unlock(VAULT).unwrap());
    open_pause::clear(&vd);
    assert!(
        matches!(opened, Err(StoreError::DatabaseAmbiguous { .. })),
        "{:?}",
        opened.err()
    );
    assert_eq!(
        std::fs::read(vd.join("vault.db")).unwrap(),
        b"a stray",
        "the stray was not renamed over"
    );
    assert!(
        vd.join("palace.db").exists(),
        "and the vault is where it was"
    );

    // (f) Undercroft opens that race the step's hold, started between its
    // checkpoint and its rename: neither renames, reads or writes the file —
    // each waits on the lock and answers the reopen class once the rename
    // lands — and a retry serves the renamed vault.
    let dir = corpus(300);
    let root = dir.path().to_path_buf();
    make_legacy(&root);
    let vd = vdir(&root);
    type Racers = Arc<Mutex<Vec<std::thread::JoinHandle<Result<u64, StoreError>>>>>;
    let racers: Racers = Default::default();
    {
        let (r, racers) = (root.clone(), racers.clone());
        at_rename(&vd, move |_| {
            let (w, ro) = (r.clone(), r.clone());
            let mut racers = racers.lock().unwrap();
            racers.push(std::thread::spawn(move || {
                VaultStore::open(mgr(&w).unlock(VAULT).unwrap())?.count()
            }));
            racers.push(std::thread::spawn(move || {
                let m = VaultManager::open_as(&ro, None, Access::ReadOnly).unwrap();
                VaultStore::open_read_only(m.unlock(VAULT).unwrap(), Box::new(HashEmbedder))?
                    .count()
            }));
            std::thread::sleep(std::time::Duration::from_millis(300));
        });
    }
    let first = VaultStore::open(mgr(&root).unlock(VAULT).unwrap()).expect("the first open");
    open_pause::clear(&vd);
    let racers: Vec<_> = std::mem::take(&mut *racers.lock().unwrap());
    assert_eq!(
        racers.len(),
        2,
        "premise: both racers started inside the hold"
    );
    for (racer, what) in racers.into_iter().zip(["writable", "read-only"]) {
        match racer.join().unwrap() {
            Err(e) => assert!(is_moved(&e), "the {what} racer: {e:?}"),
            Ok(n) => panic!("the {what} racer read {n} drawers through the hold"),
        }
    }
    assert_eq!(first.count().unwrap(), 300);
    drop(first);
    let s = open_at(&root);
    assert_eq!(
        s.count().unwrap(),
        300,
        "the retry serves the renamed vault"
    );
    assert!(s.verify().unwrap().ok());
    assert!(vd.join("vault.db").exists() && !vd.join("palace.db").exists());
}

/// Run `f` once, the first time the legacy step reaches its rename for the
/// vault in `vd` — inside its exclusive hold (ROADMAP O281).
fn at_rename(vd: &Path, f: impl Fn(&Path) + Send + Sync + 'static) {
    let armed = AtomicBool::new(true);
    let at = vd.to_path_buf();
    open_pause::set(
        vd,
        Arc::new(move |here| {
            if here == Opener::LegacyRename && armed.swap(false, Ordering::SeqCst) {
                f(&at)
            }
        }),
    );
}

/// A second writable open, run to completion (it migrates a legacy vault) when
/// `at` first fires for the vault under `root`, and kept open.
fn second_open_at(root: &Path, at: Opener) -> Arc<Mutex<Option<VaultStore>>> {
    let slot: Arc<Mutex<Option<VaultStore>>> = Default::default();
    let (r, slot2) = (root.to_path_buf(), slot.clone());
    let armed = AtomicBool::new(true);
    open_pause::set(
        &vdir(root),
        Arc::new(move |here| {
            if here == at && armed.swap(false, Ordering::SeqCst) {
                *slot2.lock().unwrap() = Some(open_at(&r));
            }
        }),
    );
    slot
}

/// The live vault as a pre-1.5.0 one left it: its database named `palace.db`.
fn make_legacy(root: &Path) {
    {
        let s = open_at(root);
        s.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap();
    }
    let vd = vdir(root);
    for f in ["vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(vd.join(f));
    }
    std::fs::rename(vd.join("vault.db"), vd.join("palace.db")).unwrap();
}

/// **G7, the store's half.** `recorded_embedder`, which both surfaces run
/// before the open, is refused when its file moved — whatever its reads
/// returned — and leaves the restored vault as the restore put it.
#[test]
fn o279_recorded_embedder_that_raced_a_swap_is_refused() {
    let dir = corpus(2000);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    later(&root, 50);
    let v = mgr(&root).unlock(VAULT).unwrap();
    let race = Race::at(&root, Opener::RecordedEmbedder, &arch);
    let read = VaultStore::recorded_embedder(&v);
    let (report, staged) = race.finish();
    match read {
        Err(e) => assert!(is_moved(&e), "{e:?}"),
        Ok(r) => panic!("the identity of the vault set aside was read: {r:?}"),
    }
    drop(v);
    assert_restored_untouched(&root, &staged, &report, 2000, "recorded_embedder");
}

/// **P8 inverted — the race across PROCESSES.** Another process's writable
/// open takes its descriptor; this process's restore takes its hold, the
/// child's first statement waits it out, the swap runs. The child is refused
/// and its reopen serves the restored vault.
#[test]
fn o279_an_open_in_another_process_that_raced_a_swap_is_refused() {
    let dir = corpus(2000);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    later(&root, 50);
    let sync = TempDir::new().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "open_race_tests::o279_racing_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("O279_ROOT", &root)
        .env("O279_SYNC", sync.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    wait_for(&sync.path().join("opened"));
    let staged: Staged = Default::default();
    {
        let (r, staged, go) = (root.clone(), staged.clone(), sync.path().join("go"));
        restore_pause::set(
            &root,
            Arc::new(move |p| {
                if p == Phase::Held {
                    *staged.lock().unwrap() = Some(stage_files(&r));
                    std::fs::write(&go, b"").unwrap();
                    std::thread::sleep(Duration::from_millis(300));
                }
            }),
        );
    }
    let report = restore(&root, &arch);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "the child failed: {:?}", out.status);
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find_map(|l| l.find("O279_CHILD ").map(|at| l[at..].to_string()))
        .unwrap_or_else(|| panic!("the child reported nothing:\n{text}"));
    assert!(line.contains("refused=true"), "{line}");
    assert!(line.contains("reopened=2000"), "{line}");
    let staged = staged.lock().unwrap().take().expect("premise: staged");
    assert_restored_untouched(&root, &staged, &report, 2000, "another process");
}

fn wait_for(p: &Path) {
    let t = Instant::now();
    while !p.exists() {
        assert!(
            t.elapsed() < Duration::from_secs(60),
            "timed out waiting for {}",
            p.display()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Not a test: the child of the cross-process race. A real writable open whose
/// pause hook signals the parent and waits for its hold, then a reopen.
#[test]
#[ignore = "child-process entry point for ROADMAP O279's cross-process race; driven by it, never on its own"]
fn o279_racing_child() {
    let Ok(root) = std::env::var("O279_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let sync = PathBuf::from(std::env::var("O279_SYNC").unwrap());
    let armed = Arc::new(AtomicBool::new(true));
    {
        let (armed, sync) = (armed.clone(), sync.clone());
        open_pause::set(
            &vdir(&root),
            Arc::new(move |here| {
                if here == Opener::Writable && armed.swap(false, Ordering::SeqCst) {
                    std::fs::write(sync.join("opened"), b"").unwrap();
                    wait_for(&sync.join("go"));
                }
            }),
        );
    }
    let refused = match VaultStore::open(mgr(&root).unlock(VAULT).unwrap()) {
        Err(e) => is_moved(&e),
        Ok(_) => false,
    };
    let reopened = open_at(&root).count().unwrap();
    println!("O279_CHILD refused={refused} reopened={reopened}");
}

// ---------------------------------------------------------------------------
// What the check can see
// ---------------------------------------------------------------------------

/// **G8 — no false positive.** Ten ordinary opens of every opener with a pause
/// hook that does nothing are served; and a restore that lands BEFORE the open
/// (between the unlock and the open) is not a race — the descriptor IS the
/// restored file — so the open serves the restored vault. A pre-open/post-lock
/// stat of the path would refuse that one.
#[test]
fn o279_no_open_is_refused_without_a_swap() {
    let dir = corpus(100);
    let root = dir.path().to_path_buf();
    let fired: Arc<Mutex<BTreeMap<String, usize>>> = Default::default();
    {
        let fired = fired.clone();
        open_pause::set(
            &vdir(&root),
            Arc::new(move |here| {
                *fired
                    .lock()
                    .unwrap()
                    .entry(format!("{here:?}"))
                    .or_default() += 1;
            }),
        );
    }
    for _ in 0..10 {
        let v = mgr(&root).unlock(VAULT).unwrap();
        assert!(VaultStore::recorded_embedder(&v).unwrap().is_some());
        assert_eq!(VaultStore::open(v).unwrap().count().unwrap(), 100);
        assert_eq!(open_ro(&root).unwrap().count().unwrap(), 100);
        drop(hold_vault_exclusively(&vdir(&root), crate::HoldFor::Restore).unwrap());
    }
    open_pause::clear(&vdir(&root));
    let fired = fired.lock().unwrap().clone();
    for opener in [
        "RecordedEmbedder",
        "Writable",
        "ReadOnly",
        "HoldLayout",
        "Hold",
    ] {
        assert!(
            fired.get(opener).copied().unwrap_or(0) >= 10,
            "premise: {opener} ran through the door: {fired:?}"
        );
    }

    // P7: the swap before the open.
    let (arch, _) = archive(&root);
    later(&root, 5);
    let v = mgr(&root).unlock(VAULT).unwrap();
    let report = restore(&root, &arch);
    let s = VaultStore::open(v).expect("a restore before the open is not a race");
    assert_eq!(s.count().unwrap(), 100, "it serves the restored vault");
    assert_eq!(s.chain_state().unwrap().1, report.writes);
}

/// **G8 — what the identity check sees, shape by shape.** Each arm is a swap
/// made by hand inside the writable open's window, so each can be told apart
/// from a check that sees less: a path that names A, then B at the open, then A
/// again (a check comparing only paths reads "not moved" while the descriptor
/// holds B); a symlinked vault directory and a symlinked database swapped (the
/// descriptor's own file never moved, so SQLite's HAS_MOVED alone reads "not
/// moved"); and a palace root that is not UTF-8, where
/// `Connection::path()` answers `None` and a check built on it would refuse
/// every open.
#[cfg(unix)]
#[test]
fn o279_the_identity_check_sees_the_descriptor_and_the_path() {
    use std::os::unix::ffi::OsStrExt;
    let vaults = |root: &Path| root.join("vaults");
    // The vault is unlocked BEFORE anything is moved: the unlock reads the
    // manifest of the vault the open means, as a real open does.
    let expect_moved = |v: Vault, root: &Path, label: &str| {
        let r = VaultStore::open(v);
        open_pause::clear(&vdir(root));
        match r {
            Err(e) => assert!(is_moved(&e), "{label}: {e:?}"),
            Ok(_) => panic!("{label}: served a file that is not the one at the path"),
        }
    };
    // Put `other` (a whole vault directory) at `vdir(root)` when the writable
    // open's window opens, moving what was there to `aside`.
    let swap_in = |root: &Path, other: PathBuf, aside: PathBuf| {
        let vd = vdir(root);
        let armed = AtomicBool::new(true);
        let vd2 = vd.clone();
        open_pause::set(
            &vd,
            Arc::new(move |here| {
                if here == Opener::Writable && armed.swap(false, Ordering::SeqCst) {
                    std::fs::rename(&vd2, &aside).unwrap();
                    std::fs::rename(&other, &vd2).unwrap();
                }
            }),
        );
    };

    // ABA: B in place at the open, A back before the first statement.
    let a = corpus(50);
    let b = corpus(60);
    let root = a.path();
    let v = mgr(root).unlock(VAULT).unwrap();
    std::fs::rename(vdir(root), vaults(root).join("a-aside")).unwrap();
    std::fs::rename(vdir(b.path()), vdir(root)).unwrap();
    swap_in(
        root,
        vaults(root).join("a-aside"),
        vaults(root).join("b-aside"),
    );
    expect_moved(v, root, "A, B at the open, A again");
    assert_eq!(open_at(root).count().unwrap(), 50, "A is in place again");

    // A symlinked vault directory, the link swapped for another vault.
    let a = corpus(50);
    let b = corpus(60);
    let root = a.path();
    let elsewhere = TempDir::new().unwrap();
    let real = elsewhere.path().join("real");
    std::fs::rename(vdir(root), &real).unwrap();
    std::os::unix::fs::symlink(&real, vdir(root)).unwrap();
    assert_eq!(
        open_at(root).count().unwrap(),
        50,
        "premise: a linked vault opens"
    );
    let v = mgr(root).unlock(VAULT).unwrap();
    swap_in(root, vdir(b.path()), vaults(root).join("the-link"));
    expect_moved(v, root, "a symlinked directory");

    // A symlinked database inside a real directory, the directory swapped.
    let a = corpus(50);
    let b = corpus(60);
    let root = a.path();
    {
        let s = open_at(root);
        s.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap();
    }
    let elsewhere = TempDir::new().unwrap();
    let real_db = elsewhere.path().join("real.db");
    std::fs::rename(vdir(root).join("vault.db"), &real_db).unwrap();
    for f in ["vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(vdir(root).join(f));
    }
    std::os::unix::fs::symlink(&real_db, vdir(root).join("vault.db")).unwrap();
    assert_eq!(
        open_at(root).count().unwrap(),
        50,
        "premise: a linked database opens"
    );
    let v = mgr(root).unlock(VAULT).unwrap();
    swap_in(root, vdir(b.path()), vaults(root).join("with-the-link"));
    expect_moved(v, root, "a symlinked database");

    // A root that is not UTF-8: every opener serves.
    let base = TempDir::new().unwrap();
    let odd = base.path().join(std::ffi::OsStr::from_bytes(b"root-\xff"));
    std::fs::create_dir(&odd).unwrap();
    let dir = corpus_in(Some(&odd), 20);
    let root = dir.path();
    let v = mgr(root).unlock(VAULT).unwrap();
    assert!(VaultStore::recorded_embedder(&v).unwrap().is_some());
    assert_eq!(VaultStore::open(v).unwrap().count().unwrap(), 20);
    assert_eq!(open_ro(root).unwrap().count().unwrap(), 20);
    drop(hold_vault_exclusively(&vdir(root), crate::HoldFor::Restore).unwrap());
}

/// **G10 — checkpoint-on-close is back on an ordinary connection**, and kept
/// off on the hold's. Left off, every close would leave a `-wal` beside the
/// database and O268's two-file post-condition would refuse every restore.
#[test]
fn o279_checkpoint_on_close_is_back_on_and_the_hold_keeps_it_off() {
    let dir = corpus(20);
    let root = dir.path().to_path_buf();
    let no_ckpt = |c: &Connection| {
        c.db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)
            .unwrap()
    };
    let s = open_at(&root);
    assert!(!no_ckpt(&s.conn), "a writable store checkpoints at close");
    let r = open_ro(&root).unwrap();
    assert!(!no_ckpt(&r.conn), "a read-only store has it back too");
    // The read-only one first: a read-only connection cannot checkpoint, so
    // the writable one must be the last to close.
    drop(r);
    drop(s);
    let left: Vec<String> = files(&vdir(&root)).into_keys().collect();
    assert_eq!(
        left,
        ["vault.db", "vault.json"],
        "the last close left two files"
    );
    let hold = hold_vault_exclusively(&vdir(&root), crate::HoldFor::Restore).unwrap();
    assert!(
        no_ckpt(&hold.0),
        "the hold's close must touch nothing (O268)"
    );
}

// ---------------------------------------------------------------------------
// The restore door's siblings
// ---------------------------------------------------------------------------

/// **P13 inverted.** `key_generation_differs` names the vault actually
/// replaced: a rotation committed as the restore's post-condition finished and
/// promoted inside the hold's busy wait made the report say `Some(false)` for a
/// vault that had just been rotated. Computed under the hold, it says true.
#[test]
fn o279_the_report_names_the_key_generation_of_the_vault_it_replaced() {
    let dir = corpus(100);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    let worker: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Default::default();
    {
        let (r, worker) = (root.clone(), worker.clone());
        restore_pause::set(
            &root,
            Arc::new(move |p| {
                if p != Phase::Closed {
                    return;
                }
                let (tx, rx) = mpsc::channel::<()>();
                let r2 = r.clone();
                *worker.lock().unwrap() = Some(std::thread::spawn(move || {
                    let tx = Mutex::new(Some(tx));
                    crate::rotate_pause::set(
                        &vdir(&r2),
                        Arc::new(move |rp| {
                            if rp == crate::rotate_pause::Phase::Committed {
                                if let Some(tx) = tx.lock().unwrap().take() {
                                    tx.send(()).unwrap();
                                    std::thread::sleep(Duration::from_millis(150));
                                }
                            }
                        }),
                    );
                    let mut s = open_at(&r2);
                    s.rotate_keys(mgr(&r2).rotation_candidate(VAULT).unwrap())
                        .unwrap();
                }));
                rx.recv_timeout(Duration::from_secs(60))
                    .expect("premise: the rotation committed");
            }),
        );
    }
    let report = restore(&root, &arch);
    worker
        .lock()
        .unwrap()
        .take()
        .expect("premise: the rotation ran")
        .join()
        .unwrap();
    assert_eq!(
        report.key_generation_differs,
        Some(true),
        "the replaced vault had just been rotated"
    );
}

/// **ROADMAP O282, P14 inverted.** A restore into an ABSENT vault takes no
/// hold; a vault created and written at the target before the swap is not
/// renamed aside unheld and removed — the restore refuses and changes nothing,
/// and the store serving that vault keeps serving the file at the path.
#[test]
fn o282_a_vault_that_appears_at_an_absent_restore_target_is_not_replaced() {
    let dir = corpus(50);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    crate::delete_vault(&mgr(&root), VAULT).unwrap();
    assert!(!vdir(&root).exists(), "premise: the target is absent");
    let live: Arc<Mutex<Option<VaultStore>>> = Default::default();
    {
        let (r, live) = (root.clone(), live.clone());
        restore_pause::set(
            &root,
            Arc::new(move |p| {
                if p != Phase::Held {
                    return;
                }
                let mut s = VaultStore::open(mgr(&r).create(VAULT, SecurityLevel::Sealed).unwrap())
                    .unwrap();
                for i in 0..3 {
                    s.upsert(&drawer("created", format!("written meanwhile {i}"), i))
                        .unwrap();
                }
                *live.lock().unwrap() = Some(s);
            }),
        );
    }
    let outcome = restore_archive(&mgr(&root), &arch, None, false, &hash);
    match outcome {
        Err(StoreError::Vault(VaultError::Io(e))) => {
            assert!(e.to_string().contains("ROADMAP O282"), "{e}")
        }
        Err(e) => panic!("the wrong refusal: {e}"),
        Ok(_) => panic!("the vault that appeared was replaced with nothing holding it"),
    }
    let live = live.lock().unwrap().take().expect("premise: the window");
    assert_eq!(
        live.count().unwrap(),
        3,
        "the vault that appeared still serves"
    );
    drop(live);
    assert_eq!(open_at(&root).count().unwrap(), 3, "and it is at the path");
    let area = root.join("vaults").join(RESTORE_ROOT);
    assert!(
        std::fs::read_dir(&area)
            .map(|rd| rd.count() == 0)
            .unwrap_or(true),
        "no stage or aside left"
    );
}

/// **ROADMAP O283, ruled by the maintainer 2026-09-27: "restore refuses
/// symlinks".** A symlinked vault directory, and a real directory whose
/// database is a link, are refused before anything is staged, with the link,
/// the directory it names and every file byte-identical; a link that appears
/// after the door looked is refused by the swap. A real directory restores.
#[cfg(unix)]
#[test]
fn o283_a_restore_over_a_symlinked_vault_is_refused_and_changes_nothing() {
    let refused_invalid = |root: &Path, arch: &Path, label: &str| {
        match restore_archive(&mgr(root), arch, None, true, &hash) {
            Err(StoreError::Invalid(m)) => {
                assert!(
                    m.contains("ROADMAP O283") && m.contains("symbolic link"),
                    "{label}: {m}"
                )
            }
            Err(e) => panic!("{label}: the wrong refusal: {e}"),
            Ok(_) => panic!("{label}: restored over a link"),
        }
        let area = root.join("vaults").join(RESTORE_ROOT);
        assert!(
            std::fs::read_dir(&area)
                .map(|rd| rd.count() == 0)
                .unwrap_or(true),
            "{label}: nothing staged"
        );
    };

    // A linked directory.
    let dir = corpus(40);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    let elsewhere = TempDir::new().unwrap();
    let real = elsewhere.path().join("real");
    std::fs::rename(vdir(&root), &real).unwrap();
    std::os::unix::fs::symlink(&real, vdir(&root)).unwrap();
    let before = files(&real);
    refused_invalid(&root, &arch, "a linked directory");
    assert!(std::fs::symlink_metadata(vdir(&root))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        files(&real),
        before,
        "the directory the link names is untouched"
    );

    // A linked database inside a real directory.
    let dir = corpus(40);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    {
        let s = open_at(&root);
        s.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap();
    }
    let elsewhere = TempDir::new().unwrap();
    let real_db = elsewhere.path().join("real.db");
    std::fs::rename(vdir(&root).join("vault.db"), &real_db).unwrap();
    for f in ["vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(vdir(&root).join(f));
    }
    std::os::unix::fs::symlink(&real_db, vdir(&root).join("vault.db")).unwrap();
    let db_before = std::fs::read(&real_db).unwrap();
    refused_invalid(&root, &arch, "a linked database");
    assert_eq!(std::fs::read(&real_db).unwrap(), db_before);

    // A link that appears at an absent target after the door looked: the
    // swap refuses it.
    let dir = corpus(40);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    crate::delete_vault(&mgr(&root), VAULT).unwrap();
    let elsewhere = TempDir::new().unwrap();
    let target_of_link = elsewhere.path().join("somewhere");
    std::fs::create_dir(&target_of_link).unwrap();
    {
        let (r, t) = (root.clone(), target_of_link.clone());
        restore_pause::set(
            &root,
            Arc::new(move |p| {
                if p == Phase::Held {
                    std::os::unix::fs::symlink(&t, vdir(&r)).unwrap();
                }
            }),
        );
    }
    match restore_archive(&mgr(&root), &arch, None, false, &hash) {
        Err(StoreError::Vault(VaultError::Io(e))) => {
            assert!(e.to_string().contains("ROADMAP O283"), "{e}")
        }
        other => panic!("a link at the swap: {:?}", other.err()),
    }
    assert!(std::fs::symlink_metadata(vdir(&root))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(target_of_link.read_dir().unwrap().next().is_none());

    // The control: a real directory restores.
    let dir = corpus(40);
    let root = dir.path().to_path_buf();
    let (arch, _) = archive(&root);
    later(&root, 3);
    restore(&root, &arch);
    assert_eq!(open_at(&root).count().unwrap(), 40);
}

// ---------------------------------------------------------------------------
// The source gates
// ---------------------------------------------------------------------------

/// A store source file's production text: everything before its `mod tests`.
fn production(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap();
    match text.find("\n#[cfg(test)]\nmod tests") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

/// The body of `fn <name>` in `text`, up to the next item at its level.
fn body_of<'a>(text: &'a str, name: &str) -> &'a str {
    let at = text
        .find(&format!("fn {name}("))
        .or_else(|| text.find(&format!("fn {name}<")))
        .unwrap_or_else(|| panic!("no fn {name}"));
    let rest = &text[at..];
    let end = rest[1..]
        .find("\n    fn ")
        .or_else(|| rest[1..].find("\n    pub fn "))
        .or_else(|| rest[1..].find("\n    pub(crate) fn "))
        .or_else(|| rest[1..].find("\nfn "))
        .or_else(|| rest[1..].find("\npub fn "))
        .or_else(|| rest[1..].find("\npub(crate) fn "))
        .or_else(|| rest[1..].find("\n#[cfg"))
        .map_or(rest.len(), |e| e + 1);
    &rest[..end]
}

/// Occurrences of `needle` in the non-comment part of every line of `text`.
fn count_code(text: &str, needle: &str) -> usize {
    text.lines()
        .map(|l| match l.find("//") {
            Some(c) => &l[..c],
            None => l,
        })
        .map(|l| l.matches(needle).count())
        .sum()
}

/// Every production source of the store: `*_tests.rs` files are whole test
/// modules, and every other file is cut at its `mod tests`.
fn store_sources() -> Vec<(String, String)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut out: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .filter(|p| !p.to_string_lossy().ends_with("_tests.rs"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                production(&p),
            )
        })
        .collect();
    out.sort();
    out
}

/// **G11 — every open of a database in the store's production code is the
/// door, or a reasoned allowlist entry; nothing else opens one.** The three
/// spellings a connection is opened by are counted over every production
/// source, and each must sit in the function the allowlist names, both ways:
/// a new opener anywhere fails, and one moved into an allowlisted function
/// fails too. The counter is proved on planted text first.
#[test]
fn o279_every_open_of_a_vault_database_goes_through_the_one_door() {
    const OPENERS: [&str; 3] = ["Connection::open(", "open_with_flags(", "open_in_memory("];
    let planted = "let c = Connection::open(&p)?;\n\
                   let d = Connection::open_with_flags(&p, f)?;\n\
                   // Connection::open(&p) in a comment\n\
                   /// Connection::open_in_memory() in a doc\n\
                   let e = Connection::open_in_memory()?;\n";
    let n: usize = OPENERS.iter().map(|o| count_code(planted, o)).sum();
    assert_eq!(n, 3, "premise: the counter sees code and neither comment");

    // (file, fn, opens): where every open may be, and how many.
    let allowed: [(&str, &str, usize); 5] = [
        // The door: the plain path and the immutable URI.
        ("vault_db.rs", "open_by_path", 2),
        // A schema-less placeholder in memory, never a file (ROADMAP O278).
        ("lib.rs", "replace_connection", 1),
        // Stage and archive copies this process wrote (backup, restore).
        ("backup.rs", "open_immutable", 1),
        // The backup's own stage destination, a nonce path nothing swaps.
        ("backup.rs", "backup", 1),
        // The restore's stage, read before its open.
        ("restore.rs", "archived_state", 1),
    ];
    let sources = store_sources();
    assert!(sources.len() > 20, "premise: the store's sources were read");
    let total: usize = sources
        .iter()
        .map(|(_, t)| OPENERS.iter().map(|o| count_code(t, o)).sum::<usize>())
        .sum();
    let mut expected = 0;
    for (file, func, opens) in allowed {
        let text = &sources
            .iter()
            .find(|(f, _)| f == file)
            .unwrap_or_else(|| panic!("no {file}"))
            .1;
        let found: usize = OPENERS
            .iter()
            .map(|o| count_code(body_of(text, func), o))
            .sum();
        assert_eq!(
            found, opens,
            "{file}::{func} opens {found}, allowed {opens}"
        );
        expected += opens;
    }
    assert_eq!(
        total, expected,
        "an open of a database outside the door and its allowlist"
    );

    // Every connector goes through the door.
    let lib = &sources.iter().find(|(f, _)| f == "lib.rs").unwrap().1;
    for (func, doors) in [
        ("hold_vault_exclusively", 1),
        ("migrate_db_filename", 1),
        ("connect_writable", 1),
        ("connect_read_only", 2),
        ("recorded_embedder", 1),
        ("lock_released", 1),
    ] {
        assert_eq!(
            count_code(body_of(lib, func), "vault_db::open_by_path("),
            doors,
            "{func} goes through the door"
        );
    }

    // CREATE only where the directory holds no database.
    let creates: usize = sources
        .iter()
        .map(|(_, t)| count_code(t, "SQLITE_OPEN_CREATE"))
        .sum();
    assert_eq!(creates, 1, "SQLITE_OPEN_CREATE appears once in production");
    let writable = body_of(lib, "connect_writable");
    let absent = writable.find("DbLayout::Absent").expect("the Absent arm");
    assert!(
        writable[absent..].contains("SQLITE_OPEN_CREATE"),
        "and only in connect_writable's Absent arm"
    );
}

/// **G11 — the door's order, and its close.** Checkpoint-on-close goes off
/// before the pause seam and the first statement, the identity is asked after
/// the first statement, a moved file is closed with `close` (never dropped),
/// and the unix identity check needs both legs.
#[test]
fn o279_the_door_checks_after_the_first_statement_and_closes_a_moved_file() {
    let door = production(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/vault_db.rs"
    )));
    let body = body_of(&door, "open_by_path");
    let at = |needle: &str| {
        body.find(needle)
            .unwrap_or_else(|| panic!("the door names {needle}"))
    };
    let order = [
        "open_with_flags(",
        "checkpoint_on_close(&conn, false",
        "open_pause::fire(",
        "first(&mut conn)",
        "identity(&conn",
        "checkpoint_on_close(&conn, true",
    ];
    for pair in order.windows(2) {
        assert!(at(pair[0]) < at(pair[1]), "{} before {}", pair[0], pair[1]);
    }
    let moved = &body[at("Identity::Moved")..];
    assert!(moved
        .find("close(conn")
        .is_some_and(|c| c < moved.find("return").unwrap()));
    assert_eq!(count_code(body, "drop("), 0, "the door drops no connection");
    let identity = body_of(&door, "identity");
    assert!(identity.contains("descriptor_has_moved(") && identity.contains("resolved_filename("));
    assert!(
        !door.contains(".path()"),
        "the resolved path is read as bytes, never through Connection::path()"
    );
}

/// **G11 — the tree's one `unsafe` block** (ROADMAP O279, ruled by the
/// maintainer 2026-09-27): counted over every production source of every
/// crate, it is in `vault_db::descriptor_has_moved`, under a `// SAFETY:`
/// comment, and the store denies `unsafe` everywhere else.
#[test]
fn o279_the_tree_holds_exactly_one_unsafe_block() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                if !p.ends_with("target") {
                    walk(&p, out);
                }
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let crates = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
    let mut files = Vec::new();
    walk(crates, &mut files);
    assert!(
        files.len() > 60,
        "premise: the workspace's sources were read"
    );
    let planted = "let rc = unsafe { f() };\n// unsafe { in a comment }\nlet s = \"unsafe\";\n";
    assert_eq!(count_code(planted, "unsafe {"), 1, "premise: the counter");
    let mut found = Vec::new();
    for f in &files {
        let name = f.to_string_lossy();
        if name.ends_with("_tests.rs") || name.contains("/tests/") || name.contains("\\tests\\") {
            continue;
        }
        let text = production(f);
        for needle in ["unsafe {", "unsafe fn ", "unsafe impl ", "unsafe extern"] {
            for _ in 0..count_code(&text, needle) {
                found.push(format!("{} ({needle})", f.display()));
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "exactly one unsafe block in production: {found:?}"
    );
    assert!(found[0].contains("vault_db.rs"), "{found:?}");
    let door = std::fs::read_to_string(crates.join("undercroft-store/src/vault_db.rs")).unwrap();
    let block = body_of(&door, "descriptor_has_moved");
    let safety = block.find("// SAFETY:").expect("a SAFETY comment");
    assert!(safety < block.find("unsafe {").unwrap());
    let lib = std::fs::read_to_string(crates.join("undercroft-store/src/lib.rs")).unwrap();
    assert!(lib.contains("#![deny(unsafe_code)]"));
    assert_eq!(count_code(&door, "#[allow(unsafe_code)]"), 1);
}
