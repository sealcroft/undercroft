//! ROADMAP O256: `backup create` archives exactly the state its verify judged.
//!
//! Every archive here is checked the way an operator meets it — through the
//! restore's copy into a FRESH root that holds only the master key, opened
//! writable and read-only, never through the handle that took it — and its
//! committed head and height must EQUAL the report's. "Inside the verified
//! window" is not accepted: O256's probe found eleven archives there that
//! proved nothing.
//!
//! The page copy runs no VM program, so SQLite's progress handler never fires
//! inside it; the interleavings are driven from `backup_pause.rs`'s points.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use undercroft_core::Drawer;
use undercroft_vault::{Access, SecurityLevel, VaultManager};

use crate::backup_pause::{self as pause, Phase};
use crate::{BackupOutcome, BackupReport, StoreError, VaultStore};

const VAULT: &str = "o256";

const PHASES: [Phase; 6] = [
    Phase::ManifestRead,
    Phase::Pinned,
    Phase::Verified,
    Phase::Copied,
    Phase::Synced,
    Phase::Staged,
];

fn drawer(content: &str, idx: u32) -> Drawer {
    Drawer::new(
        "w1",
        "r",
        content.into(),
        Some("o256.md".into()),
        idx,
        "test",
    )
}

fn open_at(root: &Path) -> VaultStore {
    let mgr = VaultManager::open(root, None).unwrap();
    VaultStore::open(mgr.unlock(VAULT).unwrap()).unwrap()
}

fn open_read_only_at(root: &Path) -> VaultStore {
    let mgr = VaultManager::open_as(root, None, Access::ReadOnly).unwrap();
    let v = mgr.unlock_as(VAULT, Access::ReadOnly).unwrap();
    VaultStore::open_read_only(v, Box::new(undercroft_core::HashEmbedder)).unwrap()
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn backups(root: &Path) -> PathBuf {
    root.join("backups")
}

/// A vault with `n` drawers, a trust class, a retention policy and facts.
fn corpus(level: SecurityLevel, n: usize) -> TempDir {
    let dir = TempDir::new().unwrap();
    let mgr = VaultManager::open(dir.path(), None).unwrap();
    let mut s = VaultStore::open(mgr.create(VAULT, level).unwrap()).unwrap();
    for chunk in (0..n).collect::<Vec<_>>().chunks(500) {
        let batch: Vec<Drawer> = chunk
            .iter()
            .map(|i| {
                drawer(
                    &format!("note {i}: the harbour ledger names cargo {i}"),
                    *i as u32,
                )
            })
            .collect();
        s.upsert_many(&batch).unwrap();
    }
    s.set_wing_trust("w1", "standard").unwrap();
    s.set_retention("w1", None, 3650).unwrap();
    for i in 0..3 {
        s.kg_add(
            "harbour",
            "ships",
            &format!("cargo {i}"),
            None,
            None,
            1.0,
            None,
        )
        .unwrap();
    }
    dir
}

fn save(w: &mut VaultStore, i: u64) -> Result<(), StoreError> {
    w.upsert(&Drawer::new(
        "w2",
        "r",
        format!("an unrelated save {i}"),
        Some("o256-writer.md".into()),
        i as u32,
        "test",
    ))
    .map(|_| ())
}

fn created(outcome: BackupOutcome) -> BackupReport {
    match outcome {
        BackupOutcome::Created(r) => r,
        BackupOutcome::Refused(r) => {
            panic!("the vault verifies, yet the backup was refused: {r:?}")
        }
    }
}

/// The restore's copy: the archive's files into a fresh root's
/// `vaults/<id>`, beside the same master key and nothing else.
fn restore(root: &Path, archive: &Path) -> TempDir {
    let r2 = TempDir::new().unwrap();
    std::fs::copy(root.join("master.key"), r2.path().join("master.key")).unwrap();
    let to = vdir(r2.path());
    std::fs::create_dir_all(&to).unwrap();
    for entry in std::fs::read_dir(archive).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
    r2
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// The archive IS the state the report names: exactly two files, a WAL-mode
/// header, `integrity_check` ok, and a restore that verifies and holds a
/// committed head and height EQUAL to the report's — writable and read-only.
fn assert_is_the_reported_state(root: &Path, report: &BackupReport, label: &str) {
    let archive = backups(root).join(&report.name);
    assert_eq!(
        files_in(&archive),
        ["vault.db", "vault.json"],
        "{label}: contents"
    );
    let db = std::fs::read(archive.join("vault.db")).unwrap();
    assert_eq!(
        (db[18], db[19]),
        (2, 2),
        "{label}: the archive keeps the WAL-mode header, so a restored vault is WAL and \
         O69's -shm detection still sees its holders"
    );
    {
        let c = crate::backup::open_immutable(&archive.join("vault.db")).unwrap();
        let ok: String = c
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ok, "ok", "{label}: integrity_check");
    }
    assert_eq!(
        files_in(&archive),
        ["vault.db", "vault.json"],
        "{label}: reading the archive wrote nothing beside it"
    );
    let r = restore(root, &archive);
    let s = open_at(r.path());
    assert!(
        s.verify().unwrap().ok(),
        "{label}: the restored archive verifies"
    );
    let (head, writes) = s.chain_state().unwrap();
    assert_eq!(
        (head.as_str(), writes),
        (report.chain_head.as_str(), report.writes),
        "{label}: the restored vault holds EXACTLY the reported state"
    );
    drop(s);
    let r = restore(root, &archive);
    let s = open_read_only_at(r.path());
    assert!(s.verify().unwrap().ok(), "{label}: read-only too");
    let (head, writes) = s.chain_state().unwrap();
    assert_eq!(
        (head.as_str(), writes),
        (report.chain_head.as_str(), report.writes),
        "{label}: read-only"
    );
}

/// **A commit — and its anchor — landing at any point of a backup is either
/// wholly in the archive or wholly outside it**, the archive restores and
/// verifies, and its manifest is byte-for-byte the one read before the pin.
///
/// A commit before the pin is in the archive, and the manifest read before it
/// lags by exactly that commit, which the report says; one after the pin is
/// not in the archive at all.
#[test]
fn o256_a_commit_at_any_pause_point_is_wholly_in_the_archive_or_wholly_out() {
    for phase in PHASES {
        let dir = corpus(SecurityLevel::Sealed, 200);
        let root = dir.path();
        let writer = Arc::new(Mutex::new(open_at(root)));
        let seen: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let committed = Arc::new(AtomicU64::new(0));
        {
            let (writer, seen, committed) = (writer.clone(), seen.clone(), committed.clone());
            let manifest = vdir(root).join("vault.json");
            pause::set(
                &vdir(root),
                Arc::new(move |p| {
                    if p == Phase::ManifestRead {
                        *seen.lock().unwrap() = Some(std::fs::read(&manifest).unwrap());
                    }
                    if p == phase {
                        save(&mut writer.lock().unwrap(), 1).unwrap();
                        committed.fetch_add(1, Ordering::SeqCst);
                    }
                }),
            );
        }
        let s = open_at(root);
        let (_, before) = s.chain_state().unwrap();
        let report = created(s.backup(&backups(root)).unwrap());
        pause::set(&vdir(root), Arc::new(|_| {}));
        let (_, live) = s.chain_state().unwrap();
        assert_eq!(
            committed.load(Ordering::SeqCst),
            1,
            "premise: {phase:?} committed"
        );
        assert!(
            live > before,
            "premise: the commit moved the chain ({phase:?})"
        );
        if phase == Phase::ManifestRead {
            assert_eq!(
                report.writes, live,
                "{phase:?}: before the pin, so archived"
            );
            assert_eq!(
                report.anchor_behind_by,
                live - before,
                "{phase:?}: the lag is said"
            );
        } else {
            assert_eq!(
                report.writes, before,
                "{phase:?}: after the pin, so not archived"
            );
            assert_eq!(report.anchor_behind_by, 0, "{phase:?}");
        }
        assert_eq!(
            std::fs::read(backups(root).join(&report.name).join("vault.json")).unwrap(),
            seen.lock()
                .unwrap()
                .clone()
                .expect("premise: the manifest read was seen"),
            "{phase:?}: the archived manifest is the bytes read before the pin"
        );
        assert_is_the_reported_state(root, &report, &format!("{phase:?}"));
    }
}

/// **A key rotation attempted at any point of a backup is refused**, because
/// the backup holds its connection throughout — which is what O257's fence
/// sees. The old copy held none, and a rotation between its files paired two
/// key generations (O256's probe R).
#[test]
fn o256_a_rotation_at_any_pause_point_is_refused_and_the_archive_restores() {
    for phase in PHASES {
        let dir = corpus(SecurityLevel::Sealed, 100);
        let root = dir.path().to_path_buf();
        let refused = Arc::new(Mutex::new(None::<String>));
        {
            let (root, refused) = (root.clone(), refused.clone());
            pause::set(
                &vdir(&root.clone()),
                Arc::new(move |p| {
                    if p == phase {
                        let mgr = VaultManager::open(&root, None).unwrap();
                        let candidate = mgr.rotation_candidate(VAULT).unwrap();
                        let mut r = open_at(&root);
                        *refused.lock().unwrap() = Some(match r.rotate_keys(candidate) {
                            Err(StoreError::VaultHeld(_)) => "held".into(),
                            other => format!("{:?}", other.map(|_| ())),
                        });
                    }
                }),
            );
        }
        let s = open_at(&root);
        let report = created(s.backup(&backups(&root)).unwrap());
        pause::set(&vdir(&root), Arc::new(|_| {}));
        assert_eq!(
            refused.lock().unwrap().as_deref(),
            Some("held"),
            "{phase:?}: the rotation must be refused VaultHeld"
        );
        assert_is_the_reported_state(&root, &report, &format!("rotation at {phase:?}"));
    }
}

/// **A backup that fails at any point leaves nothing a reader could take for
/// an archive** — no published name, no stage — and the handle backs up
/// cleanly afterwards (its snapshot ended with the failure).
#[test]
fn o256_a_backup_failing_at_any_point_leaves_nothing_behind() {
    for phase in PHASES {
        let dir = corpus(SecurityLevel::Sealed, 50);
        let root = dir.path();
        pause::set(
            &vdir(root),
            Arc::new(move |p| {
                if p == phase {
                    panic!("an injected failure at {p:?} (ROADMAP O256)");
                }
            }),
        );
        let s = open_at(root);
        let b = backups(root);
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.backup(&b)));
        pause::set(&vdir(root), Arc::new(|_| {}));
        assert!(failed.is_err(), "premise: {phase:?} failed");
        assert!(
            undercroft_vault::backups::list_entries(&b)
                .unwrap()
                .is_empty(),
            "{phase:?}: nothing listed"
        );
        assert!(!b.join(".staging").exists(), "{phase:?}: no stage left");
        let report = created(s.backup(&b).unwrap());
        assert_is_the_reported_state(root, &report, &format!("after a failure at {phase:?}"));
    }
}

/// A vault that fails its own verification is never archived, and the
/// refusal leaves nothing behind either.
#[test]
fn o256_a_vault_that_fails_verify_is_refused_and_nothing_is_archived() {
    let dir = corpus(SecurityLevel::Sealed, 20);
    let root = dir.path();
    {
        let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
        c.execute(
            "UPDATE drawers SET tag = zeroblob(32) WHERE seq = (SELECT min(seq) FROM drawers)",
            [],
        )
        .unwrap();
    }
    let s = open_at(root);
    match s.backup(&backups(root)).unwrap() {
        BackupOutcome::Refused(r) => assert!(!r.ok()),
        BackupOutcome::Created(r) => panic!("a tampered vault was archived: {r:?}"),
    }
    assert!(undercroft_vault::backups::list_entries(&backups(root))
        .unwrap()
        .is_empty());
}

/// The door opens its own snapshot: nested inside one, it refuses rather than
/// read the manifest after the pin.
#[test]
fn o256_the_door_refuses_inside_a_snapshot() {
    let dir = corpus(SecurityLevel::Sealed, 5);
    let root = dir.path();
    let s = open_at(root);
    s.snapshot(|_| {
        assert!(matches!(
            s.backup(&backups(root)),
            Err(StoreError::Invalid(_))
        ));
        Ok(())
    })
    .unwrap();
    assert!(!backups(root).join(".staging").exists());
}

/// A read-only handle can take a backup — the page copy only reads — and a
/// lagging anchor travels as found and is reported, never healed into the
/// archive. Whether `--read-only` SHOULD back up is ROADMAP O212's.
#[test]
fn o256_a_read_only_handle_archives_the_state_it_verified_and_reports_the_lag() {
    let dir = corpus(SecurityLevel::HmacOnly, 30);
    let root = dir.path();
    // A lagging anchor, the shape a crash between a commit and its anchor
    // leaves: the manifest as it stood, then one more commit, then that
    // manifest back. A read-only open reports the lag and never heals it.
    let manifest = vdir(root).join("vault.json");
    let earlier = std::fs::read(&manifest).unwrap();
    save(&mut open_at(root), 7).unwrap();
    std::fs::write(&manifest, &earlier).unwrap();
    let s = open_read_only_at(root);
    let report = created(s.backup(&backups(root)).unwrap());
    assert!(
        report.anchor_behind_by >= 1,
        "premise: the anchor lags, and the archive carries it as found: {report:?}"
    );
    assert_is_the_reported_state(root, &report, "read-only");
}

/// Beside a writer committing as fast as it can, a whole run of backups is
/// each EXACTLY the verified state — and, in the same run, the old shape (a
/// verify, then the directory copied as files) fails, which is the premise
/// that the writer was fast enough to matter. Run by name, looped.
#[test]
#[ignore = "ROADMAP O256 soak; run by name with --ignored (O256_DRAWERS, O256_ROUNDS)"]
fn o256_soak_beside_a_writer_every_archive_is_the_verified_state() {
    let n = std::env::var("O256_DRAWERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);
    let rounds = std::env::var("O256_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40u64);
    let dir = corpus(SecurityLevel::Sealed, n);
    let root = dir.path().to_path_buf();
    let stop = Arc::new(AtomicBool::new(false));
    let commits = Arc::new(AtomicU64::new(0));
    let writer = {
        let (root, stop, commits) = (root.clone(), stop.clone(), commits.clone());
        std::thread::spawn(move || {
            let mut w = open_at(&root);
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) {
                i += 1;
                if save(&mut w, i).is_ok() {
                    commits.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    let s = open_at(&root);
    let mut door = Vec::new();
    let mut quiet = 0;
    for _ in 0..rounds {
        let c0 = commits.load(Ordering::Relaxed);
        let t = Instant::now();
        let report = created(s.backup(&backups(&root)).unwrap());
        let ms = t.elapsed().as_secs_f64() * 1e3;
        if commits.load(Ordering::Relaxed) == c0 {
            quiet += 1;
        }
        door.push((report, ms));
        // Beyond ten, prune removes the oldest; check each archive at once.
        let (report, _) = door.last().unwrap();
        assert_is_the_reported_state(&root, report, &report.name);
    }
    // The old shape, same writer, same run: the positive control.
    let old_dir = root.join("old-shape");
    let (mut failed_copy, mut refused, mut off_state) = (0, 0, 0);
    for r in 0..rounds {
        let (_, lo) = s.chain_state().unwrap();
        assert!(s.verify().unwrap().ok());
        let (_, hi) = s.chain_state().unwrap();
        let dst = old_dir.join(format!("r{r}"));
        std::fs::create_dir_all(&dst).unwrap();
        let copied = std::fs::read_dir(vdir(&root)).unwrap().try_for_each(|e| {
            let e = e?;
            std::fs::copy(e.path(), dst.join(e.file_name())).map(|_| ())
        });
        if copied.is_err() {
            failed_copy += 1;
            continue;
        }
        let r2 = restore(&root, &dst);
        let opened = VaultManager::open(r2.path(), None)
            .map_err(StoreError::from)
            .and_then(|m| m.unlock(VAULT).map_err(StoreError::from))
            .and_then(VaultStore::open);
        match opened {
            Err(_) => refused += 1,
            Ok(o) => {
                let (_, h) = o.chain_state().unwrap();
                if h < lo || h > hi {
                    off_state += 1;
                }
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    let mut ms: Vec<f64> = door.iter().map(|(_, ms)| *ms).collect();
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "O256_SOAK n={n} rounds={rounds}: door {} archives, every one the reported state, \
         {quiet} with no writer commit during the call, median {:.0} ms; old shape: {failed_copy} \
         copies failed, {refused} restores refused, {off_state} off the verified window; writer \
         {} commits",
        door.len(),
        ms[ms.len() / 2],
        commits.load(Ordering::Relaxed)
    );
    assert!(
        quiet * 10 <= rounds,
        "premise: the writer committed during nearly every backup ({quiet} of {rounds} quiet)"
    );
    assert!(
        failed_copy + refused + off_state > 0,
        "positive control: the old shape must fail beside this writer, or the soak proved nothing"
    );
}

/// ROADMAP O256 P-C: the ruled hold — the verify and the page copy in ONE
/// snapshot on the store's own connection — at ~10^5, beside a writer saving
/// every 10 ms: the backup's time, the pinned span, the `-wal` high-water, and
/// the writer's save latency. The corpus is built once into `O256_CORPUS`.
#[test]
#[ignore = "ROADMAP O256 cost at ~10^5; run by name with --ignored (O256_CORPUS, O256_DRAWERS)"]
fn o256_cost_of_the_held_snapshot_at_scale() {
    let corpus_dir =
        PathBuf::from(std::env::var("O256_CORPUS").unwrap_or_else(|_| "/build/o256-corpus".into()));
    let drawers: usize = std::env::var("O256_DRAWERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(102_000);
    if !vdir(&corpus_dir).join("vault.db").exists() {
        std::fs::create_dir_all(&corpus_dir).unwrap();
        let mgr = VaultManager::open(&corpus_dir, None).unwrap();
        let mut s = VaultStore::open(mgr.create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
        for chunk in (0..drawers).collect::<Vec<_>>().chunks(2000) {
            let batch: Vec<Drawer> = chunk
                .iter()
                .map(|i| {
                    drawer(
                        &format!("note {i}: the harbour ledger names cargo {i}"),
                        *i as u32,
                    )
                })
                .collect();
            s.upsert_many(&batch).unwrap();
        }
    }
    let work = TempDir::new().unwrap();
    for sub in ["vaults", "master.key"] {
        let from = corpus_dir.join(sub);
        if from.is_dir() {
            copy_tree(&from, &work.path().join(sub));
        } else {
            std::fs::copy(&from, work.path().join(sub)).unwrap();
        }
    }
    let root = work.path().to_path_buf();
    let wal = vdir(&root).join("vault.db-wal");
    let stop = Arc::new(AtomicBool::new(false));
    let lat = Arc::new(Mutex::new(Vec::<f64>::new()));
    let writer = {
        let (root, stop, lat) = (root.clone(), stop.clone(), lat.clone());
        std::thread::spawn(move || {
            let mut w = open_at(&root);
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) {
                i += 1;
                let t = Instant::now();
                save(&mut w, i).expect("the writer is never refused beside a backup");
                lat.lock().unwrap().push(t.elapsed().as_secs_f64() * 1e3);
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };
    std::thread::sleep(Duration::from_millis(500));
    let s = open_at(&root);
    let marks: Arc<Mutex<Vec<(Phase, Instant, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let (marks, wal) = (marks.clone(), wal.clone());
        pause::set(
            &vdir(&root),
            Arc::new(move |p| {
                let size = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
                marks.lock().unwrap().push((p, Instant::now(), size));
            }),
        );
    }
    for round in 0..3 {
        marks.lock().unwrap().clear();
        let t = Instant::now();
        let report = created(s.backup(&backups(&root)).unwrap());
        let total = t.elapsed().as_secs_f64() * 1e3;
        let m = marks.lock().unwrap().clone();
        let at = |p: Phase| {
            m.iter()
                .find(|(q, _, _)| *q == p)
                .map(|(_, t, w)| (*t, *w))
                .unwrap()
        };
        let (pinned, wal0) = at(Phase::Pinned);
        let (copied, wal1) = at(Phase::Copied);
        println!(
            "O256_COST round {round}: backup {total:.0} ms, snapshot pinned {:.0} ms (verify + \
             copy), -wal {wal0} → {wal1} B across the pin, archive height {}",
            copied.duration_since(pinned).as_secs_f64() * 1e3,
            report.writes
        );
    }
    pause::set(&vdir(&root), Arc::new(|_| {}));
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    let mut l = lat.lock().unwrap().clone();
    l.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "O256_COST writer: {} saves, p50 {:.1} ms, p99 {:.1} ms, max {:.1} ms, none refused",
        l.len(),
        l[l.len() / 2],
        l[l.len() * 99 / 100],
        l[l.len() - 1]
    );
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

/// The manifest is read with NO fall-back: with `vault.json` gone after the
/// open, the backup refuses as an integrity verdict and archives nothing —
/// where `anchored_head`'s fall-back to the cached head would have archived
/// a manifest the vault never had, or none at all.
#[test]
fn o256_a_missing_manifest_refuses_and_nothing_is_archived() {
    let dir = corpus(SecurityLevel::Sealed, 10);
    let root = dir.path();
    let s = open_at(root);
    std::fs::remove_file(vdir(root).join("vault.json")).unwrap();
    match s.backup(&backups(root)) {
        Err(StoreError::Vault(undercroft_vault::VaultError::CorruptManifest(_))) => {}
        other => panic!("expected the integrity refusal, got {other:?}"),
    }
    assert!(undercroft_vault::backups::list_entries(&backups(root))
        .unwrap()
        .is_empty());
}

/// Where locks do not work, O257's fence cannot see a rotation; the key
/// generation compared inside the snapshot still can. A marker naming another
/// generation — rows still intact under this handle's keys, so the verify
/// alone passes — refuses as the write door and the rotation refuse it.
#[test]
fn o256_a_foreign_key_generation_marker_refuses_inside_the_snapshot() {
    let dir = corpus(SecurityLevel::Sealed, 10);
    let root = dir.path();
    let s = open_at(root);
    {
        let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
        c.execute(
            "UPDATE meta SET value = 'another-generation' WHERE key = 'keycheck'",
            [],
        )
        .unwrap();
    }
    match s.backup(&backups(root)) {
        Err(StoreError::IntegrityFinding(why)) => assert!(why.contains("O257"), "{why}"),
        other => panic!("expected the stale-keys refusal, got {other:?}"),
    }
    assert!(undercroft_vault::backups::list_entries(&backups(root))
        .unwrap()
        .is_empty());
}
