//! ROADMAP O281: a pre-1.5.0 `palace.db` is renamed only when no other
//! connection has the vault open — across processes, which is where the
//! defect was measured.
//!
//! The rename step used to leave the name alone when its TRUNCATE checkpoint
//! reported busy, and busy sees only a reader in the middle of a read. An IDLE
//! holder in another process was renamed beneath: a read-only replica then
//! served stale rows and a false `verify` failure (P-IDLE), and a writable
//! holder's later commits each answered OK and were lost with the `-wal` the
//! step unlinked (P2). The holders here are real processes — this test binary
//! re-entered through [`o281_holder_child`] — because SQLite's locks belong to
//! the process and an in-process holder proves nothing about another one.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags};
use tempfile::TempDir;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{Access, SecurityLevel, VaultManager};

use crate::open_pause::{self, Opener};
use crate::{StoreError, VaultStore};

const VAULT: &str = "o281";

fn mgr(root: &Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn drawers(n: usize, tag: &str) -> Vec<Drawer> {
    (0..n)
        .map(|i| {
            Drawer::new(
                "w1",
                "r",
                format!("{tag} {i}: the harbour ledger names cargo {i} for the eastern quay"),
                Some(format!("{tag}.md")),
                i as u32,
                "test",
            )
        })
        .collect()
}

/// A sealed vault of `n` drawers as a pre-1.5.0 build left it: its database
/// named `palace.db`, checkpointed, no sidecars. `probe_table` adds a table the
/// raw writable holder can write to without a vault key.
fn legacy_vault(n: usize, probe_table: bool) -> TempDir {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    {
        let m = mgr(root);
        let mut s = VaultStore::open(m.create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
        s.upsert_many(&drawers(n, "note")).unwrap();
    }
    let vd = vdir(root);
    {
        let c = Connection::open(vd.join("vault.db")).unwrap();
        if probe_table {
            c.execute_batch("CREATE TABLE o281_holder(x INTEGER)")
                .unwrap();
        }
        c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
        c.close().unwrap();
    }
    for f in ["vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(vd.join(f));
    }
    std::fs::rename(vd.join("vault.db"), vd.join("palace.db")).unwrap();
    dir
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
            "legacy_rename_tests::o281_holder_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("O281_HOLDER_ROLE", role)
        .env("O281_HOLDER_ROOT", root)
        .env("O281_HOLDER_SYNC", sync)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

/// The holder's one report line, parsed into `key=value` pairs.
fn report(child: Child) -> Vec<(String, String)> {
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "the holder failed: {:?}", out.status);
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find_map(|l| l.find("O281_HOLDER ").map(|at| l[at + 12..].to_string()))
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

/// The idle holders, each in its own process. `ro`: a read-only store — one
/// read, idle until told, then a read and `verify`. `rw`: a raw writable
/// connection on `palace.db`, which is what an older build or a writable
/// handle that kept the legacy name is — one read, idle until told, then ten
/// inserts and a normal close.
#[test]
#[ignore = "child-process entry point for ROADMAP O281's cross-process gates"]
fn o281_holder_child() {
    let Ok(role) = std::env::var("O281_HOLDER_ROLE") else {
        return;
    };
    let root = PathBuf::from(std::env::var("O281_HOLDER_ROOT").unwrap());
    let sync = PathBuf::from(std::env::var("O281_HOLDER_SYNC").unwrap());
    match role.as_str() {
        "ro" => {
            let ro = VaultManager::open_as(&root, None, Access::ReadOnly).unwrap();
            let s = VaultStore::open_read_only(ro.unlock(VAULT).unwrap(), Box::new(HashEmbedder))
                .unwrap();
            let before = s.count().unwrap();
            std::fs::write(sync.join("held"), b"").unwrap();
            wait_for(&sync.join("go"), "go");
            let after = s.count().unwrap();
            let v = s.verify().unwrap();
            println!(
                "O281_HOLDER before={before} after={after} verify_ok={} chain_ok={}",
                v.ok(),
                v.chain_ok
            );
        }
        "rw" => {
            let c = Connection::open_with_flags(
                vdir(&root).join("palace.db"),
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .unwrap();
            let before: i64 = c
                .query_row("SELECT count(*) FROM drawers", [], |r| r.get(0))
                .unwrap();
            std::fs::write(sync.join("held"), b"").unwrap();
            wait_for(&sync.join("go"), "go");
            for i in 0..10 {
                c.execute("INSERT INTO o281_holder(x) VALUES (?1)", [i])
                    .unwrap();
            }
            let seen: i64 = c
                .query_row("SELECT count(*) FROM drawers", [], |r| r.get(0))
                .unwrap();
            c.close().map_err(|(_, e)| e).unwrap();
            println!("O281_HOLDER before={before} after={seen} inserted=10");
        }
        other => panic!("unknown holder role {other}"),
    }
}

/// **P-IDLE, inverted.** A read-only replica in another process holds a legacy
/// vault idle; a writable open keeps the legacy name beside it, says so, and
/// writes into the file the replica shares — so the replica reads the writes
/// and verifies. Once the replica has gone, the next writable open renames.
#[test]
fn o281_a_writable_open_keeps_the_legacy_name_beside_an_idle_replica() {
    let dir = legacy_vault(300, false);
    let root = dir.path();
    let vd = vdir(root);
    let sync = TempDir::new().unwrap();
    let replica = holder("ro", root, sync.path());
    wait_for(&sync.path().join("held"), "the replica");
    let mut w = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).expect("the writable open");
    assert!(
        vd.join("palace.db").exists() && !vd.join("vault.db").exists(),
        "renamed beneath an idle replica in another process"
    );
    assert!(
        w.unhealed().iter().any(|n| n.contains("ROADMAP O281")),
        "{:?}",
        w.unhealed()
    );
    w.upsert_many(&drawers(40, "after")).unwrap();
    assert_eq!(w.count().unwrap(), 340);
    std::fs::write(sync.path().join("go"), b"").unwrap();
    let r = report(replica);
    assert_eq!(
        get(&r, "before"),
        "300",
        "premise: the replica read the vault"
    );
    assert_eq!(
        get(&r, "after"),
        "340",
        "the replica reads the writer's rows"
    );
    assert_eq!(get(&r, "verify_ok"), "true", "and verifies: {r:?}");
    assert_eq!(get(&r, "chain_ok"), "true", "{r:?}");
    drop(w);
    let s = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
    assert!(
        vd.join("vault.db").exists() && !vd.join("palace.db").exists(),
        "renamed once the replica has gone"
    );
    assert!(!s.unhealed().iter().any(|n| n.contains("ROADMAP O281")));
    assert_eq!(s.count().unwrap(), 340);
    assert!(s.verify().unwrap().ok());
}

/// **P2, inverted.** A WRITABLE holder in another process keeps its commits:
/// the rename used to unlink the `-wal` it had open, and every commit it made
/// afterwards answered OK and was gone. Now the name is kept, both write into
/// one file, and every row of both is there after both close.
#[test]
fn o281_a_writable_idle_holder_in_another_process_loses_nothing() {
    let dir = legacy_vault(300, true);
    let root = dir.path();
    let vd = vdir(root);
    let sync = TempDir::new().unwrap();
    let writer = holder("rw", root, sync.path());
    wait_for(&sync.path().join("held"), "the writable holder");
    let mut w = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).expect("the writable open");
    assert!(
        vd.join("palace.db").exists() && !vd.join("vault.db").exists(),
        "renamed beneath an idle writable holder in another process"
    );
    w.upsert_many(&drawers(40, "after")).unwrap();
    std::fs::write(sync.path().join("go"), b"").unwrap();
    let r = report(writer);
    assert_eq!(
        get(&r, "before"),
        "300",
        "premise: the holder read the vault"
    );
    assert_eq!(
        get(&r, "after"),
        "340",
        "the holder shares the writer's file"
    );
    let theirs: i64 = w
        .conn
        .query_row("SELECT count(*) FROM o281_holder", [], |r| r.get(0))
        .unwrap();
    assert_eq!(theirs, 10, "the holder's commits reach the writer's file");
    drop(w);
    let s = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
    assert!(vd.join("vault.db").exists() && !vd.join("palace.db").exists());
    let kept: i64 = s
        .conn
        .query_row("SELECT count(*) FROM o281_holder", [], |r| r.get(0))
        .unwrap();
    assert_eq!(kept, 10, "every commit the holder made survived the rename");
    assert_eq!(s.count().unwrap(), 340);
    let integrity: String = s
        .conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    assert!(s.verify().unwrap().ok());
}

/// **The note describes the handle** — found by the review of O281's first
/// build. A writable open whose rename step KEPT the legacy name, because
/// another open held the file, and which then found `vault.db`, because that
/// other open finished the rename before this one read the directory, is a
/// handle on `vault.db`: it carries no note saying the vault is still
/// `palace.db`. The first build put the note on it, where a server would have
/// shown it on every stats surface for its whole life.
#[test]
fn o281_an_open_that_ends_on_vault_db_carries_no_legacy_note() {
    type Second = Arc<Mutex<Option<std::thread::JoinHandle<Result<VaultStore, StoreError>>>>>;
    let dir = legacy_vault(200, false);
    let root = dir.path().to_path_buf();
    let vd = vdir(&root);
    let (arrived_tx, arrived_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (arrived_tx, arrived_rx) = (Mutex::new(arrived_tx), Mutex::new(arrived_rx));
    let release_rx = Mutex::new(release_rx);
    let holds = Arc::new(AtomicUsize::new(0));
    let second: Second = Default::default();
    {
        let (r, second, holds) = (root.clone(), second.clone(), holds.clone());
        let (spawned, paused) = (AtomicBool::new(false), AtomicBool::new(false));
        open_pause::set(
            &vd,
            Arc::new(move |here| match here {
                Opener::Legacy => {
                    holds.fetch_add(1, Ordering::SeqCst);
                }
                // Inside the first open's hold: start a second, and wait until
                // its rename step has kept the name and reached its connect.
                Opener::LegacyRename if !spawned.swap(true, Ordering::SeqCst) => {
                    let r = r.clone();
                    *second.lock().unwrap() = Some(std::thread::spawn(move || {
                        VaultStore::open(mgr(&r).unlock(VAULT).unwrap())
                    }));
                    arrived_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(30))
                        .expect("the second open reached its connect");
                }
                // The second open, the first to get here: the first open still
                // holds the file. It reads the directory once released.
                Opener::WritableLayout if !paused.swap(true, Ordering::SeqCst) => {
                    arrived_tx.lock().unwrap().send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(30))
                        .expect("released");
                }
                _ => {}
            }),
        );
    }
    let first = VaultStore::open(mgr(&root).unlock(VAULT).unwrap()).expect("the first open");
    release_tx.send(()).unwrap();
    let b = second
        .lock()
        .unwrap()
        .take()
        .expect("premise: the second open ran inside the first's hold");
    let b = b.join().unwrap().expect("the second open ends on vault.db");
    open_pause::clear(&vd);
    assert_eq!(
        holds.load(Ordering::SeqCst),
        2,
        "premise: both opens reached the rename step's hold"
    );
    assert!(
        vd.join("vault.db").exists() && !vd.join("palace.db").exists(),
        "the first open renamed"
    );
    assert!(
        !b.unhealed().iter().any(|n| n.contains("ROADMAP O281")),
        "a handle on vault.db says the vault is still palace.db: {:?}",
        b.unhealed()
    );
    assert!(!first.unhealed().iter().any(|n| n.contains("ROADMAP O281")));
    assert_eq!(b.count().unwrap(), 200);
}

/// A stray `vault.db` that appears between the rename step keeping the name
/// and the connect is O7's two-files verdict there too — never opened as the
/// vault, and never renamed over. Only something that is not Undercroft can
/// put it there.
#[test]
fn o281_a_stray_vault_db_at_the_connect_is_the_two_files_verdict() {
    let dir = legacy_vault(20, false);
    let root = dir.path().to_path_buf();
    let vd = vdir(&root);
    let holder = Connection::open(vd.join("palace.db")).unwrap();
    let read: i64 = holder
        .query_row("SELECT count(*) FROM drawers", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        read, 20,
        "premise: the holder has read the file, so the name is kept"
    );
    {
        let at = vd.clone();
        let armed = AtomicBool::new(true);
        open_pause::set(
            &vd,
            Arc::new(move |here| {
                if here == Opener::WritableLayout && armed.swap(false, Ordering::SeqCst) {
                    std::fs::write(at.join("vault.db"), b"a stray").unwrap();
                }
            }),
        );
    }
    let opened = VaultStore::open(mgr(&root).unlock(VAULT).unwrap());
    open_pause::clear(&vd);
    assert!(
        matches!(opened, Err(StoreError::DatabaseAmbiguous { .. })),
        "{:?}",
        opened.err()
    );
    assert_eq!(std::fs::read(vd.join("vault.db")).unwrap(), b"a stray");
    assert!(
        vd.join("palace.db").exists(),
        "and the vault is where it was"
    );
    drop(holder);
}
