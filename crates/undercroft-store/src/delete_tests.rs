//! ROADMAP O291: a vault delete removes a vault only under O69's hold, by one
//! rename out of `vaults/` and a removal judged by what is left — or refuses,
//! changing nothing.
//!
//! The holders the refusal is FOR are real processes — this test binary
//! re-entered through [`o291_holder_child`] — because SQLite's locks belong to
//! the process: an in-process connection is seen through SQLite's own inode
//! table, a different mechanism, and proves nothing about another process.
//! Every refusal is asserted with its variant, the directory's bytes, and the
//! delete's pause witnesses — which steps RAN — because a create-then-unlink
//! and a rename-then-put-back both end looking unchanged.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{deletes, restores, Access, SecurityLevel, VaultError, VaultManager};

use crate::delete_pause::{self, Phase};
use crate::open_pause::{self, Opener};
use crate::{delete_vault, Deleted, Read, ReadOp, StoreError, VaultStore};

const VAULT: &str = "o291";
const LEVELS: [SecurityLevel; 2] = [SecurityLevel::Sealed, SecurityLevel::HmacOnly];

fn mgr(root: &Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn area(root: &Path) -> PathBuf {
    root.join("vaults").join(restores::RESTORE_ROOT)
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

/// A vault of three drawers, its store closed.
fn seeded(level: SecurityLevel) -> TempDir {
    let dir = TempDir::new().unwrap();
    let mut s = VaultStore::open(mgr(dir.path()).create(VAULT, level).unwrap()).unwrap();
    for i in 0..3 {
        s.upsert(&drawer("seed", i)).unwrap();
    }
    dir
}

/// What `vault create` leaves before any store opens it: a manifest alone.
fn manifest_only() -> TempDir {
    let dir = TempDir::new().unwrap();
    drop(
        mgr(dir.path())
            .create(VAULT, SecurityLevel::Sealed)
            .unwrap(),
    );
    dir
}

/// Every entry of `dir` by name, kind, length and — for a regular file — its
/// SHA-256. Read only where no connection of THIS process holds the files:
/// closing a descriptor drops the process's POSIX locks on the file.
fn snapshot(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return vec![format!("<{} absent>", dir.display())];
    };
    let mut out: Vec<String> = rd
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let m = std::fs::symlink_metadata(e.path()).unwrap();
            if m.file_type().is_file() {
                let digest = hex::encode(Sha256::digest(std::fs::read(e.path()).unwrap()));
                format!("{name} file {} {digest}", m.len())
            } else {
                format!("{name} {:?}", m.file_type())
            }
        })
        .collect();
    out.sort();
    out
}

/// Record which of the delete's pause points it reached.
fn witness(root: &Path) -> Arc<Mutex<Vec<Phase>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    delete_pause::set(root, Arc::new(move |p| s2.lock().unwrap().push(p)));
    seen
}

/// [`witness`], then `hook` at each pause point — one hook per root, so a
/// test that acts at a pause point records through the same one.
fn witness_with(
    root: &Path,
    hook: impl Fn(Phase) + Send + Sync + 'static,
) -> Arc<Mutex<Vec<Phase>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    delete_pause::set(
        root,
        Arc::new(move |p| {
            s2.lock().unwrap().push(p);
            hook(p);
        }),
    );
    seen
}

fn phases(seen: &Arc<Mutex<Vec<Phase>>>) -> Vec<Phase> {
    seen.lock().unwrap().clone()
}

fn no_leftover(root: &Path) {
    assert!(
        std::fs::symlink_metadata(deletes::deleting_path(root, VAULT)).is_err(),
        "a delete's aside is left behind"
    );
}

fn assert_held(e: &StoreError) {
    match e {
        StoreError::VaultHeld(why) => {
            assert!(why.contains("Nothing was deleted"), "{why}");
            assert!(why.contains("ROADMAP O291"), "{why}");
            assert!(
                !why.contains("restore"),
                "a delete's refusal names a restore: {why}"
            );
        }
        other => panic!("expected VaultHeld, got {other:?}"),
    }
}

fn wait_for(p: &Path, what: &str) {
    let t = Instant::now();
    while !p.exists() {
        assert!(
            t.elapsed() < Duration::from_secs(60),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn holder(role: &str, root: &Path, sync: &Path) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "delete_tests::o291_holder_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("O291_HOLDER_ROLE", role)
        .env("O291_HOLDER_ROOT", root)
        .env("O291_HOLDER_SYNC", sync)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

fn report(child: Child) -> Vec<(String, String)> {
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "the holder failed: {:?}", out.status);
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find_map(|l| l.find("O291_HOLDER ").map(|at| l[at + 12..].to_string()))
        .unwrap_or_else(|| panic!("the holder reported nothing: {text}"));
    line.split_whitespace()
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn get<'a>(r: &'a [(String, String)], k: &str) -> &'a str {
    r.iter()
        .find(|(key, _)| key == k)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("no {k} in {r:?}"))
}

/// The idle holders, each in its own process, each having READ (so its label
/// guard is warm — a cold handle refuses a deleted vault on its own, and an
/// arm driven by one would pass with the defect present).
/// `rw`: a writable store — one read, idle until told, then one write and a
/// read of what it wrote. `ro`: a read-only store — one read, idle until told,
/// then the same read again. `create`: a writable store opened on a
/// manifest-only vault — it CREATES the database — with one write, then the
/// same idle and the same write as `rw`.
#[test]
#[ignore = "child-process entry point for ROADMAP O291's cross-process gates"]
fn o291_holder_child() {
    let Ok(role) = std::env::var("O291_HOLDER_ROLE") else {
        return;
    };
    let root = PathBuf::from(std::env::var("O291_HOLDER_ROOT").unwrap());
    let sync = PathBuf::from(std::env::var("O291_HOLDER_SYNC").unwrap());
    let seed = drawer("seed", 0);
    match role.as_str() {
        "rw" | "create" => {
            let mut s = VaultStore::open(mgr(&root).unlock(VAULT).unwrap()).unwrap();
            if role == "create" {
                s.upsert(&drawer("created", 0)).unwrap();
            }
            let warm = if role == "create" {
                drawer("created", 0)
            } else {
                seed.clone()
            };
            let before = s
                .get(&warm.id, Read::Returned(ReadOp::Get))
                .unwrap()
                .is_some();
            std::fs::write(sync.join("held"), b"").unwrap();
            wait_for(&sync.join("go"), "go");
            let x = drawer("held", 7);
            let wrote = s.upsert(&x).is_ok();
            let read = s
                .get(&x.id, Read::Returned(ReadOp::Get))
                .map(|o| o.is_some())
                .unwrap_or(false);
            println!(
                "O291_HOLDER before={before} wrote={wrote} read={read} anchor_failures={}",
                s.anchor_failures()
            );
        }
        "ro" => {
            let ro = VaultManager::open_as(&root, None, Access::ReadOnly).unwrap();
            let s = VaultStore::open_read_only(ro.unlock(VAULT).unwrap(), Box::new(HashEmbedder))
                .unwrap();
            let before = s
                .get(&seed.id, Read::Returned(ReadOp::Get))
                .unwrap()
                .is_some();
            std::fs::write(sync.join("held"), b"").unwrap();
            wait_for(&sync.join("go"), "go");
            let after = s
                .get(&seed.id, Read::Returned(ReadOp::Get))
                .map(|o| o.is_some())
                .unwrap_or(false);
            println!("O291_HOLDER before={before} after={after}");
        }
        other => panic!("unknown holder role {other}"),
    }
}

/// **P1 and P2, inverted, across processes.** An idle writable handle and an
/// idle read-only replica, each in another process, make a delete refuse with
/// nothing changed: the directory's bytes identical, the hold's step reached
/// and nothing after it, the vault still openable — and the holder's next
/// write lands and is read back by a fresh open. Before the fix the write
/// answered `Ok` into an unlinked file and the replica served a deleted vault.
#[test]
fn o291_a_delete_beside_a_holder_in_another_process_refuses_and_changes_nothing() {
    for level in LEVELS {
        for role in ["rw", "ro"] {
            for round in 0..5 {
                let dir = seeded(level);
                let root = dir.path();
                let sync = TempDir::new().unwrap();
                let child = holder(role, root, sync.path());
                wait_for(&sync.path().join("held"), "the holder");
                let before = snapshot(&vdir(root));
                let seen = witness(root);
                let refused = delete_vault(&mgr(root), VAULT).expect_err("a held vault is deleted");
                delete_pause::clear(root);
                assert_held(&refused);
                assert_eq!(
                    phases(&seen),
                    vec![Phase::Surveyed],
                    "{level:?} {role} #{round}: a step past the hold ran"
                );
                assert_eq!(snapshot(&vdir(root)), before, "{level:?} {role} #{round}");
                assert!(
                    std::fs::symlink_metadata(area(root)).is_err(),
                    "the refusal made the restore area"
                );
                std::fs::write(sync.path().join("go"), b"").unwrap();
                let r = report(child);
                assert_eq!(get(&r, "before"), "true", "premise: the holder read");
                let s = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
                if role == "rw" {
                    assert_eq!(get(&r, "wrote"), "true", "{r:?}");
                    assert_eq!(get(&r, "read"), "true", "{r:?}");
                    assert_eq!(get(&r, "anchor_failures"), "0", "{r:?}");
                    assert!(
                        s.get(&drawer("held", 7).id, Read::Returned(ReadOp::Get))
                            .unwrap()
                            .is_some(),
                        "{level:?}: the holder's write after the refusal is lost"
                    );
                } else {
                    assert_eq!(get(&r, "after"), "true", "{r:?}");
                }
                assert!(s.verify().unwrap().ok(), "{level:?} {role}");
            }
        }
    }
}

/// With nothing holding it, a delete removes the vault — current, legacy and
/// manifest-only, at both levels — through every step, leaving no aside and no
/// restore area, and the id can be created again as a new vault.
#[test]
fn o291_a_delete_with_no_holder_removes_the_vault() {
    for level in LEVELS {
        for layout in ["current", "legacy", "manifest-only"] {
            let dir = if layout == "manifest-only" {
                let d = TempDir::new().unwrap();
                drop(mgr(d.path()).create(VAULT, level).unwrap());
                d
            } else {
                seeded(level)
            };
            let root = dir.path();
            if layout == "legacy" {
                let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
                let _: i64 = c
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
                    .unwrap();
                c.close().unwrap();
                for f in ["vault.db-wal", "vault.db-shm"] {
                    let _ = std::fs::remove_file(vdir(root).join(f));
                }
                std::fs::rename(vdir(root).join("vault.db"), vdir(root).join("palace.db")).unwrap();
            }
            let seen = witness(root);
            assert_eq!(
                delete_vault(&mgr(root), VAULT).unwrap(),
                Deleted::Removed,
                "{level:?} {layout}"
            );
            delete_pause::clear(root);
            assert_eq!(
                phases(&seen),
                vec![Phase::Surveyed, Phase::Held, Phase::Aside],
                "{level:?} {layout}"
            );
            assert!(
                std::fs::symlink_metadata(vdir(root)).is_err(),
                "{level:?} {layout}"
            );
            no_leftover(root);
            assert!(
                std::fs::symlink_metadata(area(root)).is_err(),
                "an empty restore area is left"
            );
            assert!(matches!(
                mgr(root).unlock(VAULT),
                Err(VaultError::NotFound(_))
            ));
            assert_eq!(delete_vault(&mgr(root), VAULT).unwrap(), Deleted::Absent);
            let mut s = VaultStore::open(mgr(root).create(VAULT, level).unwrap()).unwrap();
            assert!(s
                .get(&drawer("seed", 0).id, Read::Returned(ReadOp::Get))
                .unwrap()
                .is_none());
            s.upsert(&drawer("new", 0)).unwrap();
        }
    }
}

/// An open whose unlock predates a delete answers the reopen class — never a
/// raw SQLite "unable to open" (the writable posture, `/v1`'s 500) and never
/// `DatabaseMissing` (the read-only posture's integrity verdict, exit 2) — and
/// its retry finds no vault. `recorded_embedder`, which the surfaces call
/// first, answers the same.
#[test]
fn o291_an_open_racing_a_delete_answers_the_reopen_class() {
    let deleted = |e: &StoreError| matches!(e, StoreError::StaleUnlock(why) if why.contains("was deleted while this process was opening it"));
    for level in LEVELS {
        // Unlocked, then deleted, then opened.
        let dir = seeded(level);
        let root = dir.path();
        let (w, r, e) = (
            mgr(root).unlock(VAULT).unwrap(),
            mgr(root).unlock_as(VAULT, Access::ReadOnly).unwrap(),
            mgr(root).unlock(VAULT).unwrap(),
        );
        assert_eq!(delete_vault(&mgr(root), VAULT).unwrap(), Deleted::Removed);
        let w = VaultStore::open(w).map(|_| ()).unwrap_err();
        assert!(deleted(&w), "{level:?} writable: {w:?}");
        let r = VaultStore::open_read_only(r, Box::new(HashEmbedder))
            .map(|_| ())
            .unwrap_err();
        assert!(deleted(&r), "{level:?} read-only: {r:?}");
        // Asked AFTER the delete it finds no database and records nothing —
        // the open that follows answers the reopen class above.
        assert!(
            matches!(VaultStore::recorded_embedder(&e), Ok(None)),
            "{level:?} recorded_embedder"
        );
        assert!(matches!(
            mgr(root).unlock(VAULT),
            Err(VaultError::NotFound(_))
        ));
        assert!(
            std::fs::symlink_metadata(vdir(root)).is_err(),
            "an open created the vault"
        );

        // A delete landing inside `recorded_embedder`, which the surfaces call
        // before their open: its descriptor was open, so it is the reopen class.
        let dir2 = seeded(level);
        let root2 = dir2.path().to_path_buf();
        let fired = Arc::new(AtomicBool::new(false));
        {
            let (r2, fired) = (root2.clone(), fired.clone());
            open_pause::set(
                &vdir(&root2),
                Arc::new(move |here| {
                    if here == Opener::RecordedEmbedder && !fired.swap(true, Ordering::SeqCst) {
                        assert_eq!(delete_vault(&mgr(&r2), VAULT).unwrap(), Deleted::Removed);
                    }
                }),
            );
        }
        let recorded = VaultStore::recorded_embedder(&mgr(&root2).unlock(VAULT).unwrap());
        open_pause::clear(&vdir(&root2));
        assert!(fired.load(Ordering::SeqCst), "premise: the delete ran");
        assert!(
            matches!(recorded, Err(StoreError::StaleUnlock(_))),
            "{level:?} recorded_embedder: {recorded:?}"
        );

        // A delete landing inside an open, at each pause point.
        for (writable, at) in [
            (true, Opener::WritableLayout),
            (true, Opener::Writable),
            (false, Opener::ReadOnlyLayout),
            (false, Opener::ReadOnly),
        ] {
            let dir = seeded(level);
            let root = dir.path().to_path_buf();
            let fired = Arc::new(AtomicBool::new(false));
            {
                let (r2, fired) = (root.clone(), fired.clone());
                open_pause::set(
                    &vdir(&root),
                    Arc::new(move |here| {
                        if here == at && !fired.swap(true, Ordering::SeqCst) {
                            assert_eq!(delete_vault(&mgr(&r2), VAULT).unwrap(), Deleted::Removed);
                        }
                    }),
                );
            }
            let answer = if writable {
                VaultStore::open(mgr(&root).unlock(VAULT).unwrap()).map(|_| ())
            } else {
                VaultStore::open_read_only(
                    mgr(&root).unlock_as(VAULT, Access::ReadOnly).unwrap(),
                    Box::new(HashEmbedder),
                )
                .map(|_| ())
            };
            open_pause::clear(&vdir(&root));
            assert!(
                fired.load(Ordering::SeqCst),
                "premise: the delete ran at {at:?}"
            );
            let e = answer.unwrap_err();
            assert!(
                matches!(e, StoreError::StaleUnlock(_)),
                "{level:?} at {at:?}: {e:?}"
            );
            assert!(matches!(
                mgr(&root).unlock(VAULT),
                Err(VaultError::NotFound(_))
            ));
            assert!(
                std::fs::symlink_metadata(vdir(&root)).is_err(),
                "{level:?} at {at:?}: an open created the vault's directory"
            );
        }
    }
}

/// An open arriving while the delete holds the vault is told a delete is
/// running (`OPEN_HELD` names it and keeps its prefix).
#[test]
fn o291_an_open_under_the_hold_is_told_a_delete_is_running() {
    let dir = seeded(SecurityLevel::Sealed);
    let root = dir.path().to_path_buf();
    let told = Arc::new(Mutex::new(None));
    {
        let (r2, told) = (root.clone(), told.clone());
        delete_pause::set(
            &root,
            Arc::new(move |p| {
                if p == Phase::Held {
                    let ro = VaultStore::open_read_only(
                        mgr(&r2).unlock_as(VAULT, Access::ReadOnly).unwrap(),
                        Box::new(HashEmbedder),
                    )
                    .map(|_| ());
                    *told.lock().unwrap() = Some(ro);
                }
            }),
        );
    }
    assert_eq!(delete_vault(&mgr(&root), VAULT).unwrap(), Deleted::Removed);
    delete_pause::clear(&root);
    let answer = told.lock().unwrap().take();
    match answer {
        Some(Err(StoreError::VaultHeld(why))) => {
            assert!(
                why.starts_with("another process holds this vault exclusively"),
                "{why}"
            );
            assert!(why.contains("a vault delete"), "{why}");
        }
        other => panic!("expected OPEN_HELD, got {other:?}"),
    }
}

/// **The manifest-only vault, with an ACTIVE holder** (ruling item 5). A
/// writable store in another process opens a manifest-only vault — creating
/// its database — and writes, after the delete surveyed it: the delete's
/// exclusive create finds the file (not its own), the hold is refused, nothing
/// is moved, and the holder's reads and writes stay ordinary. Rename-then-look
/// moved such a vault with nothing holding it: the holder served a false
/// integrity verdict and was retired (measured, O291's probe).
#[test]
fn o291_a_manifest_only_vault_that_gains_a_writer_is_never_moved_beneath_it() {
    let dir = manifest_only();
    let root = dir.path().to_path_buf();
    let sync = TempDir::new().unwrap();
    let child = Arc::new(Mutex::new(None));
    let seen = {
        let (r2, s2, child) = (root.clone(), sync.path().to_path_buf(), child.clone());
        witness_with(&root, move |p| {
            if p == Phase::Surveyed {
                let c = holder("create", &r2, &s2);
                wait_for(&s2.join("held"), "the creating holder");
                *child.lock().unwrap() = Some(c);
            }
        })
    };
    let refused = delete_vault(&mgr(&root), VAULT).expect_err("moved beneath a writer");
    delete_pause::clear(&root);
    assert_held(&refused);
    assert_eq!(phases(&seen), vec![Phase::Surveyed]);
    std::fs::write(sync.path().join("go"), b"").unwrap();
    let r = report(
        child
            .lock()
            .unwrap()
            .take()
            .expect("premise: the holder ran"),
    );
    assert_eq!(get(&r, "wrote"), "true", "{r:?}");
    assert_eq!(get(&r, "read"), "true", "{r:?}");
    assert_eq!(get(&r, "anchor_failures"), "0", "{r:?}");
    let s = VaultStore::open(mgr(&root).unlock(VAULT).unwrap()).unwrap();
    for x in [drawer("created", 0), drawer("held", 7)] {
        assert!(s.get(&x.id, Read::Returned(ReadOp::Get)).unwrap().is_some());
    }
    assert!(s.verify().unwrap().ok());
}

/// The racing open's thread, handed out of a pause hook.
type Racer = Arc<Mutex<Option<std::thread::JoinHandle<Result<(), StoreError>>>>>;

/// **The empty database the door made is undone** (ruling item 5): a rename
/// that fails after the hold was granted on a manifest-only vault leaves the
/// directory byte-identical to before. With a racer — an open that unlocked
/// the vault and took its descriptor on the door's empty file while the hold
/// was held — the racer answers the reopen class once it proceeds, and its
/// retry opens the vault normally.
#[test]
fn o291_a_refusal_after_the_hold_undoes_the_database_the_delete_made() {
    for with_racer in [false, true] {
        let dir = manifest_only();
        let root = dir.path().to_path_buf();
        let before = snapshot(&vdir(&root));
        let racer: Racer = Arc::new(Mutex::new(None));
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let go_rx = Arc::new(Mutex::new(Some(go_rx)));
        let seen = {
            let (r2, racer2, go_rx) = (root.clone(), racer.clone(), go_rx.clone());
            witness_with(&root, move |p| {
                if !with_racer || p != Phase::Held {
                    return;
                }
                let (opened_tx, opened_rx) = std::sync::mpsc::channel::<()>();
                let go = go_rx.lock().unwrap().take().unwrap();
                let (opened_tx, go) = (Mutex::new(opened_tx), Mutex::new(go));
                let fired = AtomicBool::new(false);
                open_pause::set(
                    &vdir(&r2),
                    Arc::new(move |here| {
                        if here == Opener::Writable && !fired.swap(true, Ordering::SeqCst) {
                            opened_tx.lock().unwrap().send(()).unwrap();
                            go.lock()
                                .unwrap()
                                .recv_timeout(Duration::from_secs(60))
                                .unwrap();
                        }
                    }),
                );
                let v = mgr(&r2).unlock(VAULT).unwrap();
                *racer2.lock().unwrap() =
                    Some(std::thread::spawn(move || VaultStore::open(v).map(|_| ())));
                opened_rx
                    .recv_timeout(Duration::from_secs(60))
                    .expect("premise: the racer took its descriptor");
            })
        };
        undercroft_vault::fixture::fail_next(undercroft_vault::fixture::Fault::DeleteAside);
        let refused = delete_vault(&mgr(&root), VAULT).expect_err("the rename was failed");
        delete_pause::clear(&root);
        match &refused {
            StoreError::Vault(VaultError::Io(e)) => {
                assert!(e.to_string().contains("nothing was deleted"), "{e}")
            }
            other => panic!("expected the rename's Io, got {other:?}"),
        }
        assert_eq!(phases(&seen), vec![Phase::Surveyed, Phase::Held]);
        if let Some(racer) = racer.lock().unwrap().take() {
            go_tx.send(()).unwrap();
            let answer = racer.join().unwrap();
            open_pause::clear(&vdir(&root));
            assert!(
                matches!(answer, Err(StoreError::StaleUnlock(_))),
                "the racer on the undone file: {answer:?}"
            );
        } else {
            assert!(!with_racer, "premise: the racer ran");
        }
        assert_eq!(
            snapshot(&vdir(&root)),
            before,
            "the refusal changed the directory"
        );
        no_leftover(&root);
        let s = VaultStore::open(mgr(&root).unlock(VAULT).unwrap()).unwrap();
        assert_eq!(s.count().unwrap(), 0);
    }
}

/// A link, or any entry that is not a regular file, refuses before any
/// effect — nothing surveyed past, nothing created, the link and what it
/// names byte-identical — where the old delete answered `deleted` and left
/// what the link named (P6). A delete never follows a link.
#[cfg(unix)]
#[test]
fn o291_a_link_or_a_non_file_entry_refuses_and_changes_nothing() {
    use std::os::unix::fs::symlink;
    for case in [
        "dir-link",
        "db-link",
        "wal-link",
        "manifest-link",
        "fifo",
        "subdir",
    ] {
        let dir = seeded(SecurityLevel::Sealed);
        let root = dir.path();
        let elsewhere = TempDir::new().unwrap();
        match case {
            "dir-link" => {
                let real = elsewhere.path().join("real");
                std::fs::rename(vdir(root), &real).unwrap();
                symlink(&real, vdir(root)).unwrap();
            }
            "db-link" | "manifest-link" => {
                let name = if case == "db-link" {
                    "vault.db"
                } else {
                    "vault.json"
                };
                if case == "db-link" {
                    for f in ["vault.db-wal", "vault.db-shm"] {
                        let _ = std::fs::remove_file(vdir(root).join(f));
                    }
                }
                let real = elsewhere.path().join(name);
                std::fs::rename(vdir(root).join(name), &real).unwrap();
                symlink(&real, vdir(root).join(name)).unwrap();
            }
            "wal-link" => {
                let real = elsewhere.path().join("frames");
                std::fs::write(&real, b"committed frames kept elsewhere").unwrap();
                let _ = std::fs::remove_file(vdir(root).join("vault.db-wal"));
                symlink(&real, vdir(root).join("vault.db-wal")).unwrap();
            }
            "fifo" => {
                let st = Command::new("mkfifo")
                    .arg(vdir(root).join("stray"))
                    .status()
                    .unwrap();
                assert!(st.success(), "premise: mkfifo");
            }
            _ => std::fs::create_dir(vdir(root).join("stray")).unwrap(),
        }
        let before = (snapshot(&vdir(root)), snapshot(elsewhere.path()));
        let seen = witness(root);
        let refused = delete_vault(&mgr(root), VAULT).expect_err(case);
        delete_pause::clear(root);
        match &refused {
            StoreError::Invalid(why) => {
                assert!(why.contains("never follows a link"), "{case}: {why}");
                assert!(why.contains("Nothing was deleted"), "{case}: {why}");
            }
            other => panic!("{case}: expected Invalid, got {other:?}"),
        }
        assert!(phases(&seen).is_empty(), "{case}: {:?}", phases(&seen));
        assert_eq!(
            (snapshot(&vdir(root)), snapshot(elsewhere.path())),
            before,
            "{case}"
        );
        assert!(std::fs::symlink_metadata(area(root)).is_err(), "{case}");
    }
}

/// **The checks are made again UNDER the hold** (ruling item 3h): a link
/// planted after the survey — here at the survey's pause point, before the
/// hold — refuses the delete with nothing moved, and the step after the hold
/// is never reached.
#[cfg(unix)]
#[test]
fn o291_the_survey_is_made_again_under_the_hold() {
    let dir = seeded(SecurityLevel::Sealed);
    let root = dir.path().to_path_buf();
    let elsewhere = TempDir::new().unwrap();
    let target = elsewhere.path().join("elsewhere");
    std::fs::write(&target, b"content a link names").unwrap();
    let seen = {
        let (v, t) = (vdir(&root), target.clone());
        witness_with(&root, move |p| {
            if p == Phase::Surveyed {
                std::os::unix::fs::symlink(&t, v.join("planted")).unwrap();
            }
        })
    };
    let refused = delete_vault(&mgr(&root), VAULT).expect_err("a link planted after the survey");
    delete_pause::clear(&root);
    assert!(
        matches!(&refused, StoreError::Invalid(why) if why.contains("never follows a link")),
        "{refused:?}"
    );
    assert_eq!(
        phases(&seen),
        vec![Phase::Surveyed],
        "a step past the hold ran"
    );
    assert!(vdir(&root).join("vault.db").exists() && vdir(&root).join("vault.json").exists());
    assert_eq!(std::fs::read(&target).unwrap(), b"content a link names");
    no_leftover(&root);
}

/// Two databases refuse in the integrity class, worded for a delete, with
/// nothing changed.
#[test]
fn o291_two_databases_refuse_as_integrity() {
    let dir = seeded(SecurityLevel::Sealed);
    let root = dir.path();
    std::fs::copy(vdir(root).join("vault.db"), vdir(root).join("palace.db")).unwrap();
    let before = snapshot(&vdir(root));
    let seen = witness(root);
    let refused = delete_vault(&mgr(root), VAULT).unwrap_err();
    delete_pause::clear(root);
    match &refused {
        StoreError::IntegrityFinding(why) => {
            assert!(
                why.contains("two databases") && why.contains("Nothing was deleted"),
                "{why}"
            )
        }
        other => panic!("expected IntegrityFinding, got {other:?}"),
    }
    assert!(phases(&seen).is_empty());
    assert_eq!(snapshot(&vdir(root)), before);
}

/// A restore's aside holding the vault refuses the delete — with the vault
/// directory present or absent — where the old delete answered 200 or 404
/// and left the aside (P11).
#[test]
fn o291_a_restore_aside_refuses_the_delete() {
    for with_target in [true, false] {
        let dir = seeded(SecurityLevel::Sealed);
        let root = dir.path();
        std::fs::create_dir_all(area(root)).unwrap();
        let aside = area(root).join(format!(
            "aside-{}",
            hex::encode(Sha256::digest(VAULT.as_bytes()))
        ));
        std::fs::create_dir(&aside).unwrap();
        for f in ["vault.db", "vault.json"] {
            std::fs::copy(vdir(root).join(f), aside.join(f)).unwrap();
        }
        if !with_target {
            std::fs::remove_dir_all(vdir(root)).unwrap();
        }
        let before = (snapshot(&vdir(root)), snapshot(&aside));
        let refused = delete_vault(&mgr(root), VAULT).unwrap_err();
        assert!(
            matches!(
                refused,
                StoreError::Vault(VaultError::RestoreInterrupted { .. })
            ),
            "with the target {with_target}: {refused:?}"
        );
        assert_eq!((snapshot(&vdir(root)), snapshot(&aside)), before);
    }
}

/// A removal that fails leaves the vault out of service and SAYS so — never
/// `Removed` — and a retry finishes it; a leftover of a crashed delete is
/// finished the same way, with the vault directory absent or present.
#[test]
fn o291_an_interrupted_delete_is_finished_by_the_next_and_never_answers_absent() {
    let dir = seeded(SecurityLevel::Sealed);
    let root = dir.path();
    undercroft_vault::fixture::fail_next(undercroft_vault::fixture::Fault::DeleteRemove);
    let e = delete_vault(&mgr(root), VAULT).unwrap_err();
    match &e {
        StoreError::Vault(VaultError::Io(io)) => {
            let text = io.to_string();
            assert!(
                text.contains("NOT complete") && text.contains("deleting-"),
                "{text}"
            );
        }
        other => panic!("expected the removal's Io, got {other:?}"),
    }
    assert!(std::fs::symlink_metadata(vdir(root)).is_err());
    let leftover = deletes::deleting_path(root, VAULT);
    assert!(
        leftover.join("vault.db").exists(),
        "premise: the aside is whole"
    );
    // A create of the id is not refused beside the leftover (O300 files
    // whether it should finish it).
    drop(mgr(root).create(VAULT, SecurityLevel::Sealed).unwrap());
    assert_eq!(delete_vault(&mgr(root), VAULT).unwrap(), Deleted::Removed);
    no_leftover(root);
    // A crashed delete's leftover with no vault directory: finished, `Removed`.
    let dir = seeded(SecurityLevel::Sealed);
    let root = dir.path();
    std::fs::create_dir_all(area(root)).unwrap();
    std::fs::rename(vdir(root), deletes::deleting_path(root, VAULT)).unwrap();
    assert_eq!(delete_vault(&mgr(root), VAULT).unwrap(), Deleted::Removed);
    no_leftover(root);
    assert_eq!(delete_vault(&mgr(root), VAULT).unwrap(), Deleted::Absent);
}

/// A directory holding a database and no manifest is deleted under the hold,
/// where the old delete answered 404 and kept it (P10, O292's state).
#[test]
fn o291_a_database_with_no_manifest_is_deleted() {
    let dir = seeded(SecurityLevel::Sealed);
    let root = dir.path();
    std::fs::remove_file(vdir(root).join("vault.json")).unwrap();
    let seen = witness(root);
    assert_eq!(delete_vault(&mgr(root), VAULT).unwrap(), Deleted::Removed);
    delete_pause::clear(root);
    assert_eq!(
        phases(&seen),
        vec![Phase::Surveyed, Phase::Held, Phase::Aside]
    );
    assert!(std::fs::symlink_metadata(vdir(root)).is_err());
}

/// Refused before any effect: a read-only manager and a bad name.
#[test]
fn o291_a_read_only_manager_and_a_bad_name_refuse_before_any_effect() {
    let dir = seeded(SecurityLevel::Sealed);
    let root = dir.path();
    let before = snapshot(&vdir(root));
    let ro = VaultManager::open_as(root, None, Access::ReadOnly).unwrap();
    assert!(matches!(
        delete_vault(&ro, VAULT),
        Err(StoreError::Vault(VaultError::ReadOnly(_)))
    ));
    assert!(matches!(
        delete_vault(&mgr(root), "../escape"),
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(snapshot(&vdir(root)), before);
}

/// **A pinned residual, escalated (ROADMAP O291, E1).** A hard link to the
/// database outside the vault survives a delete, which answers `Removed`:
/// "deleted" covers the vault DIRECTORY until the maintainer rules on erasure
/// scope. This fails in both directions — a delete that starts refusing or
/// reaching hard links must be recorded, not absorbed.
#[cfg(unix)]
#[test]
fn o291_a_hard_link_outside_the_vault_survives_a_delete_as_a_stated_residual() {
    let dir = seeded(SecurityLevel::Sealed);
    let root = dir.path();
    let elsewhere = TempDir::new().unwrap();
    let copy = elsewhere.path().join("hard");
    std::fs::hard_link(vdir(root).join("vault.db"), &copy).unwrap();
    let bytes = std::fs::read(&copy).unwrap();
    assert_eq!(delete_vault(&mgr(root), VAULT).unwrap(), Deleted::Removed);
    assert_eq!(std::fs::read(&copy).unwrap(), bytes, "the residual moved");
}

/// A `deleting-` leftover is not a restore's aside: `create` is not refused
/// beside it and no restore sweeps it (ruling items 3 and 7).
#[test]
fn o291_a_delete_leftover_is_neither_an_aside_nor_a_stage() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let m = mgr(root);
    std::fs::create_dir_all(deletes::deleting_path(root, VAULT)).unwrap();
    assert!(restores::refuse_if_interrupted(root, VAULT).is_ok());
    let name = deletes::deleting_path(root, VAULT)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(name.starts_with(deletes::DELETING_PREFIX) && !name.starts_with("aside-"));
    assert!(!name.starts_with("stage-"));
    drop(m.create(VAULT, SecurityLevel::Sealed).unwrap());
}
