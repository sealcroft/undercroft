//! ROADMAP O288: a handle never carries a rotation verdict its unlock derived
//! from files that no longer say so.
//!
//! The unlock reads `vault.json.next` and `vault.json` by path before any
//! database connection exists, and the read-only open decides the rotation
//! verdict — and mints `RotationPromotionDeferred` ("Do NOT delete
//! vault.json.next") or `RotationDiscardDeferred` — from those reads. Three
//! things moved under it: the unlock read `vault.json` FIRST, so an anchor and
//! a deferred rotation between its two reads made a read-only open answer a
//! false `ManifestTampered`; and a promote, a discard or a restore between the
//! unlock and the open left the note on a vault that no longer had the file.
//! The unlock now reads `.next` first, and the read-only open asks, on the
//! verdict its reconcile returned, whether the files still say so.
//!
//! Every refusal is asserted by its WORDING as well as its variant: the unlock's
//! order answers R1 through O257's race arm, O288's check answers the rest, and
//! with both in place a variant alone cannot tell which mechanism refused.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use undercroft_core::embed::Embedder;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{
    fixture, Access, RotationVerdict, SecurityLevel, Unhealed, Vault, VaultError, VaultManager,
};

use crate::rotate_pause as pause;
use crate::{restore_archive, BackupOutcome, RestoreOutcome, StoreError, VaultStore};

const VAULT: &str = "o288";
const LEVELS: [SecurityLevel; 2] = [SecurityLevel::HmacOnly, SecurityLevel::Sealed];

fn hash(_: &Vault) -> Result<Box<dyn Embedder + Send>, StoreError> {
    Ok(Box::new(HashEmbedder))
}

fn mgr(root: &Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn staging(root: &Path) -> PathBuf {
    vdir(root).join("vault.json.next")
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

/// A vault of `n` drawers at `level`, no handle left open.
fn vault(level: SecurityLevel, n: u32) -> TempDir {
    let dir = TempDir::new().unwrap();
    let mut s = VaultStore::open(mgr(dir.path()).create(VAULT, level).unwrap()).unwrap();
    s.upsert_many(&(0..n).map(|i| drawer("note", i)).collect::<Vec<_>>())
        .unwrap();
    dir
}

fn unlock(root: &Path, read_only: bool) -> Vault {
    if read_only {
        VaultManager::open_as(root, None, Access::ReadOnly)
            .unwrap()
            .unlock(VAULT)
            .unwrap()
    } else {
        mgr(root).unlock(VAULT).unwrap()
    }
}

fn open(v: Vault, read_only: bool) -> Result<VaultStore, StoreError> {
    if read_only {
        VaultStore::open_read_only(v, Box::new(HashEmbedder))
    } else {
        VaultStore::open(v)
    }
}

/// A key rotation through a writable handle; `defer` fails every promote
/// attempt through the vault crate's fault seam, so it COMMITS and leaves
/// `vault.json` on the retired generation beside `vault.json.next`.
fn rotate(root: &Path, defer: bool) {
    let m = mgr(root);
    let mut s = VaultStore::open(m.unlock(VAULT).unwrap()).unwrap();
    if defer {
        pause::set(
            &vdir(root),
            Arc::new(|phase| {
                if phase == pause::Phase::Committed {
                    fixture::fail_times(fixture::Fault::Rename, crate::rotate::PROMOTE_ATTEMPTS);
                }
            }),
        );
    }
    let report = s.rotate_keys(m.rotation_candidate(VAULT).unwrap()).unwrap();
    pause::set(&vdir(root), Arc::new(|_| {}));
    assert_eq!(
        report.promote_deferred.is_some(),
        defer,
        "premise: the rotation's promote was deferred exactly when asked"
    );
}

/// Another process's writable open, which promotes a deferred rotation; with
/// `removal_fails` its removal of `.next` fails AFTER the new `vault.json` is
/// written (O266's fault), the state O257 names as legitimate.
fn promote(root: &Path, removal_fails: bool) {
    if removal_fails {
        fixture::fail_next(fixture::Fault::RemoveStaged);
    }
    let opened = VaultStore::open(mgr(root).unlock(VAULT).unwrap());
    assert_eq!(
        opened.is_ok(),
        !removal_fails,
        "premise: the promoting open ({:?})",
        opened.as_ref().err()
    );
}

/// A read-only backup, which over a deferral archives the staged bytes as its
/// `vault.json` (O266 item 4).
fn backup(root: &Path) -> PathBuf {
    let s = open(unlock(root, true), true).unwrap();
    match s.backup(&root.join("backups")).unwrap() {
        BackupOutcome::Created(r) => root.join("backups").join(r.name),
        BackupOutcome::Refused(r) => panic!("premise: the vault verifies ({r:?})"),
    }
}

fn restore(root: &Path, arch: &Path) {
    match restore_archive(&mgr(root), arch, None, true, &hash) {
        Ok(RestoreOutcome::Restored(_)) => {}
        other => panic!("premise: the restore ran ({:?})", other.err()),
    }
}

/// An abandoned rotation's staging file: a valid next-generation manifest
/// that no re-seal ever committed.
fn abandon_a_stage(root: &Path) {
    let current = mgr(root).unlock(VAULT).unwrap();
    let (head, writes) = (current.chain_head_hex().to_string(), current.writes());
    let mut next = mgr(root).rotation_candidate(VAULT).unwrap();
    next.save_manifest_pending(&head, writes).unwrap();
    assert!(staging(root).exists(), "premise: the stage is on disk");
}

fn keycheck(root: &Path) -> String {
    let c = rusqlite::Connection::open_with_flags(
        vdir(root).join("vault.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    c.query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
        r.get(0)
    })
    .unwrap()
}

fn has(notes: &[String], note: Unhealed) -> bool {
    notes.iter().any(|n| *n == note.to_string())
}

/// O288's refusal, by variant AND wording.
fn refused_by_o288(opened: Result<VaultStore, StoreError>, what: &str) {
    match opened {
        Err(StoreError::StaleUnlock(m)) => assert!(
            m.contains("ROADMAP O288") && m.contains("key rotation state changed"),
            "{what}: {m}"
        ),
        Err(e) => panic!("{what}: refused otherwise: {e:?}"),
        Ok(s) => panic!(
            "{what}: served, carrying {:?} (promotion deferred: {})",
            s.unhealed(),
            s.vault.promotion_deferred()
        ),
    }
}

/// A fresh open serves the vault with neither deferral note and no staged
/// manifest in force, and it verifies.
fn served_clean(root: &Path, read_only: bool, what: &str) {
    let s = open(unlock(root, read_only), read_only).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(
        !has(s.unhealed(), Unhealed::RotationPromotionDeferred)
            && !has(s.unhealed(), Unhealed::RotationDiscardDeferred),
        "{what}: {:?}",
        s.unhealed()
    );
    assert!(!s.vault.promotion_deferred(), "{what}: deferred_over set");
    assert!(s.verify().unwrap().ok(), "{what}: verify");
}

/// **R1 — the unlock reads `.next` first.** An old-generation writer anchors
/// and a rotation commits and fails its promote, both between the unlock's two
/// reads: the unlock finds no staging file (it read before the rotation staged),
/// so the open's verdict is `Foreign` and O257's race arm answers the reopen
/// class — never `ManifestTampered`, which read in the old order it answered on
/// the read-only posture, with the manifest tamper event. The retry serves.
#[test]
fn o288_an_anchor_and_a_deferred_rotation_inside_the_unlock_are_a_race_not_tampering() {
    for level in LEVELS {
        for read_only in [true, false] {
            let what = format!("{level:?} read_only={read_only}");
            let dir = vault(level, 20);
            let root = dir.path().to_path_buf();
            let writer = VaultStore::open(mgr(&root).unlock(VAULT).unwrap()).unwrap();
            let fired = Rc::new(Cell::new(false));
            let (f, r) = (fired.clone(), root.clone());
            fixture::between_unlock_reads(move || {
                f.set(true);
                let mut writer = writer;
                writer.upsert(&drawer("late", 99)).unwrap();
                drop(writer);
                rotate(&r, true);
            });
            let v = unlock(&root, read_only);
            assert!(
                fired.get(),
                "{what}: premise: the hook ran inside the unlock"
            );
            assert!(
                !v.has_pending(),
                "{what}: premise: the staging file was read before the rotation staged it"
            );
            assert!(
                staging(&root).exists(),
                "{what}: premise: the deferral is on disk"
            );
            match open(v, read_only) {
                Err(StoreError::StaleUnlock(m)) => assert!(
                    m.contains("ROADMAP O257") && !m.contains("ROADMAP O288"),
                    "{what}: O257's race arm answers it: {m}"
                ),
                Err(e) => panic!("{what}: {e:?}"),
                Ok(_) => panic!("{what}: served a handle whose keys the database does not hold"),
            }
            let s = open(unlock(&root, read_only), read_only).unwrap();
            assert_eq!(
                has(s.unhealed(), Unhealed::RotationPromotionDeferred),
                read_only,
                "{what}: the retry says what is true: {:?}",
                s.unhealed()
            );
            assert!(s.verify().unwrap().ok(), "{what}");
        }
    }
}

/// **R1 at the vault, where O288's store check cannot mask it**: the same
/// interleaving, then the read-only reconcile against the database's keycheck,
/// then the anchor read. In the old order the unlock attached the staged file
/// with `manifest_seen` naming the pre-anchor bytes, and the anchor read
/// answered `ManifestTampered`.
#[test]
fn o288_the_vault_reads_the_retired_manifest_the_rotation_left_not_an_older_one() {
    for level in LEVELS {
        let dir = vault(level, 20);
        let root = dir.path().to_path_buf();
        let writer = VaultStore::open(mgr(&root).unlock(VAULT).unwrap()).unwrap();
        let r = root.clone();
        fixture::between_unlock_reads(move || {
            let mut writer = writer;
            writer.upsert(&drawer("late", 99)).unwrap();
            drop(writer);
            rotate(&r, true);
        });
        let mut v = unlock(&root, true);
        let kc = keycheck(&root);
        let verdict = v.reconcile_read_only(Some(kc.as_str()));
        // The anchor read FIRST, so the old order fails on the false verdict
        // itself rather than on how the new one got there.
        v.anchored_head()
            .unwrap_or_else(|e| panic!("{level:?}: the anchor read refused ({verdict:?}): {e:?}"));
        assert_eq!(
            verdict,
            RotationVerdict::Foreign,
            "{level:?}: the unlock recorded the generation it read, with no stage"
        );
    }
}

/// **A promote between the unlock's two reads is served on the FIRST open**:
/// the staged file read first and the promoted `vault.json` read second name
/// one generation, which is `Settled`. In the old order the unlock read the
/// retired manifest and no staging file, and the open was a retry.
#[test]
fn o288_a_promote_between_the_unlock_reads_is_served_on_the_first_open() {
    for level in LEVELS {
        for read_only in [true, false] {
            let what = format!("{level:?} read_only={read_only}");
            let dir = vault(level, 20);
            let root = dir.path().to_path_buf();
            rotate(&root, true);
            let r = root.clone();
            fixture::between_unlock_reads(move || promote(&r, false));
            let v = unlock(&root, read_only);
            assert!(
                v.has_pending(),
                "{what}: premise: the staged file was read before the promote"
            );
            assert!(!staging(&root).exists(), "{what}: premise: promoted");
            let s = open(v, read_only).unwrap_or_else(|e| panic!("{what}: {e:?}"));
            assert!(
                !has(s.unhealed(), Unhealed::RotationPromotionDeferred),
                "{what}: {:?}",
                s.unhealed()
            );
            assert!(!s.vault.promotion_deferred(), "{what}");
            assert!(s.verify().unwrap().ok(), "{what}");
        }
    }
}

/// **R2 — a promote after the unlock.** The held read-only open is refused with
/// O288's reopen class whether the promoter's removal of `.next` failed or
/// succeeded — before O288 both served `RotationPromotionDeferred`, the second
/// over a vault with no `.next` at all — and a fresh open serves clean. The
/// writable posture re-decides under its write lock and is served.
#[test]
fn o288_a_promote_after_the_unlock_refuses_the_read_only_deferral_note() {
    for level in LEVELS {
        for removal_fails in [true, false] {
            for read_only in [true, false] {
                let what = format!("{level:?} removal_fails={removal_fails} ro={read_only}");
                let dir = vault(level, 20);
                let root = dir.path();
                rotate(root, true);
                let v = unlock(root, read_only);
                assert!(v.has_pending(), "{what}: premise: the unlock attached it");
                let retired = std::fs::read(manifest(root)).unwrap();
                promote(root, removal_fails);
                assert_ne!(
                    std::fs::read(manifest(root)).unwrap(),
                    retired,
                    "{what}: premise: vault.json was promoted"
                );
                assert_eq!(staging(root).exists(), removal_fails, "{what}: premise");
                if read_only {
                    refused_by_o288(open(v, true), &what);
                } else {
                    let s = open(v, false).unwrap_or_else(|e| panic!("{what}: {e:?}"));
                    assert!(s.unhealed().is_empty(), "{what}: {:?}", s.unhealed());
                }
                served_clean(root, read_only, &what);
            }
        }
    }
}

/// **The ordinary route to R2, with no fault anywhere**: a read-only unlock
/// inside a rotation's hold, which then commits and promotes. A read-only
/// connect WAITS at the fence rather than answering `VaultHeld` (measured,
/// ~430 ms), so an open started during the hold, as well as one made after it,
/// used to serve the rotation's staged file as a deferral that never happened.
#[test]
fn o288_an_ordinary_rotation_beneath_a_read_only_open_is_not_a_deferral() {
    for (level, during) in LEVELS.iter().flat_map(|l| [(*l, false), (*l, true)]) {
        let what = format!("{level:?} during={during}");
        let dir = vault(level, 20);
        let root = dir.path().to_path_buf();
        let retired = std::fs::read(manifest(&root)).unwrap();
        let (at_tx, at_rx) = std::sync::mpsc::channel::<()>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let go_rx = std::sync::Mutex::new(go_rx);
        pause::set(
            &vdir(&root),
            Arc::new(move |p| {
                if p == pause::Phase::Staged {
                    at_tx.send(()).unwrap();
                    go_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(30))
                        .expect("bounded: the test signals go");
                }
            }),
        );
        let rotating = {
            let root = root.clone();
            std::thread::spawn(move || {
                let m = mgr(&root);
                let mut s = VaultStore::open(m.unlock(VAULT).unwrap()).unwrap();
                s.rotate_keys(m.rotation_candidate(VAULT).unwrap())
                    .map(|r| r.promote_deferred.is_some())
            })
        };
        at_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the rotation reaches its staged window");
        let v = unlock(&root, true);
        assert!(
            v.has_pending(),
            "{what}: premise: the unlock read the stage"
        );
        let held = if during {
            let opening = std::thread::spawn(move || open(v, true).map(|s| s.unhealed().to_vec()));
            std::thread::sleep(Duration::from_millis(300));
            assert!(
                !opening.is_finished(),
                "{what}: premise: the open waits at the rotation's fence"
            );
            go_tx.send(()).unwrap();
            assert!(!rotating.join().unwrap().unwrap(), "{what}: promoted");
            opening.join().unwrap()
        } else {
            go_tx.send(()).unwrap();
            assert!(!rotating.join().unwrap().unwrap(), "{what}: promoted");
            open(v, true).map(|s| s.unhealed().to_vec())
        };
        pause::set(&vdir(&root), Arc::new(|_| {}));
        assert!(
            !staging(&root).exists(),
            "{what}: premise: the promote removed it"
        );
        assert_ne!(
            std::fs::read(manifest(&root)).unwrap(),
            retired,
            "{what}: premise: vault.json was promoted after the unlock read it"
        );
        match held {
            Err(StoreError::StaleUnlock(m)) => assert!(m.contains("ROADMAP O288"), "{what}: {m}"),
            other => panic!("{what}: {other:?}"),
        }
        served_clean(&root, true, &what);
    }
}

/// **R3 — a restore after the unlock sets aside a vault whose staging file
/// was VALID** (O284 compares only one it could not authenticate). An archive
/// older than the rotation made the read-only open say an uncommitted rotation
/// was kept on disk; a read-only backup of the deferral made it say the
/// promotion was deferred; the restored vault holds no staging file either way.
#[test]
fn o288_a_restore_after_the_unlock_refuses_the_set_aside_rotation() {
    for level in LEVELS {
        for older_archive in [true, false] {
            for read_only in [true, false] {
                let what = format!("{level:?} older_archive={older_archive} ro={read_only}");
                let dir = vault(level, 20);
                let root = dir.path();
                let arch = if older_archive {
                    let a = backup(root);
                    rotate(root, true);
                    a
                } else {
                    rotate(root, true);
                    backup(root)
                };
                let v = unlock(root, read_only);
                assert!(v.has_pending(), "{what}: premise: the unlock attached it");
                restore(root, &arch);
                assert!(!staging(root).exists(), "{what}: premise: none restored");
                if read_only {
                    refused_by_o288(open(v, true), &what);
                } else {
                    let s = open(v, false).unwrap_or_else(|e| panic!("{what}: {e:?}"));
                    assert!(s.unhealed().is_empty(), "{what}: {:?}", s.unhealed());
                }
                served_clean(root, read_only, &what);
            }
        }
    }
}

/// **R2′ — another open discards an abandoned stage after the unlock read it**:
/// the read-only open said an uncommitted rotation was kept on disk, after the
/// file was gone.
#[test]
fn o288_a_discard_after_the_unlock_refuses_the_kept_stage_note() {
    for level in LEVELS {
        let dir = vault(level, 20);
        let root = dir.path();
        abandon_a_stage(root);
        let v = unlock(root, true);
        assert!(
            v.has_pending(),
            "{level:?}: premise: the unlock attached it"
        );
        drop(VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap());
        assert!(!staging(root).exists(), "{level:?}: premise: discarded");
        refused_by_o288(open(v, true), &format!("{level:?}"));
        served_clean(root, true, &format!("{level:?}"));
    }
}

/// **A second full rotation between the unlock's two reads** (the refuter's
/// case the swap creates): the first rotation's staged file read first, the
/// second's promoted `vault.json` read second — `Abandoned`, over a staging
/// file that is gone.
#[test]
fn o288_a_second_rotation_between_the_unlock_reads_is_refused() {
    for level in LEVELS {
        let what = format!("{level:?} second rotation");
        let dir = vault(level, 20);
        let root = dir.path().to_path_buf();
        rotate(&root, true);
        let r = root.clone();
        fixture::between_unlock_reads(move || {
            promote(&r, false);
            rotate(&r, false);
        });
        let v = unlock(&root, true);
        assert!(v.has_pending(), "{what}: premise: the first stage was read");
        assert!(
            !staging(&root).exists(),
            "{what}: premise: the second promoted"
        );
        refused_by_o288(open(v, true), &what);
        served_clean(&root, true, &what);
    }
}

/// **A restore between the unlock's two reads** (the refuter's other case):
/// the set-aside vault's staged file read first, the restored `vault.json`
/// second.
#[test]
fn o288_a_restore_between_the_unlock_reads_is_refused() {
    for level in LEVELS {
        let what = format!("{level:?} restore between the reads");
        let dir = vault(level, 20);
        let root = dir.path().to_path_buf();
        let arch = backup(&root);
        rotate(&root, true);
        let (r, a) = (root.clone(), arch.clone());
        fixture::between_unlock_reads(move || restore(&r, &a));
        let v = unlock(&root, true);
        assert!(
            v.has_pending(),
            "{what}: premise: the set-aside stage was read"
        );
        assert!(!staging(&root).exists(), "{what}: premise: none restored");
        refused_by_o288(open(v, true), &what);
        served_clean(&root, true, &what);
    }
}

/// **Negative control: a genuine deferral is served, with its note, every
/// time** — the check asks the rule's staged branch, which a steady deferral
/// answers.
#[test]
fn o288_a_steady_deferral_is_served_with_its_note() {
    for level in LEVELS {
        let dir = vault(level, 20);
        let root = dir.path();
        rotate(root, true);
        for i in 0..5 {
            let s = open(unlock(root, true), true)
                .unwrap_or_else(|e| panic!("{level:?} open {i}: {e:?}"));
            assert!(has(s.unhealed(), Unhealed::RotationPromotionDeferred));
            assert!(s.vault.promotion_deferred());
            assert!(s.verify().unwrap().ok(), "{level:?} open {i}");
        }
    }
}

/// **Negative control: a busy writer beside an abandoned stage refuses no
/// read-only open.** The writer opened before the stage existed, so its open
/// took the no-lock path and it anchors freely, and `Abandoned` compares
/// `.next` alone. The premise is OVERLAP, measured per open — `vault.json`
/// different just after the open from just before its unlock — and at least
/// three such opens are required, so a comparison of `vault.json` there would
/// refuse at least three times rather than only by chance. Every wait is
/// bounded, and a writer that dies fails the test instead of hanging it.
#[test]
fn o288_opens_beside_a_writer_anchoring_by_an_abandoned_stage_are_never_refused() {
    for level in LEVELS {
        let dir = vault(level, 30);
        let root = dir.path().to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let written = Arc::new(AtomicU32::new(0));
        let (opened_tx, opened_rx) = std::sync::mpsc::channel::<()>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let writer = {
            let (r, stop, written) = (root.clone(), stop.clone(), written.clone());
            std::thread::spawn(move || {
                let mut s = VaultStore::open(mgr(&r).unlock(VAULT).unwrap()).unwrap();
                opened_tx.send(()).unwrap();
                go_rx.recv_timeout(Duration::from_secs(30)).unwrap();
                let mut i = 0u32;
                while !stop.load(Ordering::SeqCst) {
                    s.upsert(&drawer("busy", 1000 + i)).unwrap();
                    i += 1;
                    written.store(i, Ordering::SeqCst);
                }
                i
            })
        };
        opened_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the writer opens before the stage exists");
        abandon_a_stage(&root);
        go_tx.send(()).unwrap();
        let started = Instant::now();
        while written.load(Ordering::SeqCst) == 0 {
            assert!(
                !writer.is_finished() && started.elapsed() < Duration::from_secs(30),
                "{level:?}: the writer never wrote"
            );
            std::thread::yield_now();
        }
        let (mut refused, mut opens, mut overlapped) = (Vec::new(), 0, 0);
        while opens < 50 || overlapped < 3 {
            assert!(
                !writer.is_finished() && started.elapsed() < Duration::from_secs(90),
                "{level:?}: {overlapped} of {opens} opens overlapped an anchor"
            );
            let before = std::fs::read(manifest(&root)).unwrap();
            match open(unlock(&root, true), true) {
                Ok(s) => assert!(
                    has(s.unhealed(), Unhealed::RotationDiscardDeferred),
                    "{level:?}: premise: every open read the abandoned stage: {:?}",
                    s.unhealed()
                ),
                Err(StoreError::StaleUnlock(m)) => refused.push(m),
                Err(e) => panic!("{level:?}: an open beside the writer failed otherwise: {e}"),
            }
            if std::fs::read(manifest(&root)).unwrap() != before {
                overlapped += 1;
            }
            opens += 1;
        }
        stop.store(true, Ordering::SeqCst);
        assert!(writer.join().unwrap() > 0);
        assert!(
            staging(&root).exists(),
            "{level:?}: premise: the stage stayed"
        );
        assert!(
            refused.is_empty(),
            "{level:?}: {} of {opens} refused ({overlapped} overlapped): {:?}",
            refused.len(),
            refused.first()
        );
    }
}

/// **A read that fails is its own error, never the reopen class**: a staging
/// file, then a `vault.json`, that cannot be read once the unlock has read it
/// answers `Io` — a retry would read nothing better.
#[test]
fn o288_an_unreadable_file_after_the_unlock_is_an_error_not_a_retry() {
    for (level, target) in LEVELS
        .iter()
        .flat_map(|l| [(*l, "vault.json.next"), (*l, "vault.json")])
    {
        let dir = vault(level, 10);
        let root = dir.path();
        rotate(root, true);
        let v = unlock(root, true);
        let path = vdir(root).join(target);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        match open(v, true) {
            Err(StoreError::Vault(VaultError::Io(_))) => {}
            other => panic!("{target}: {:?}", other.err()),
        }
    }
}

/// **The check has ONE call site, on the read-only open, between the reconcile
/// and the handle's assembly**, and asks the vault's rule nowhere else — before
/// the reconcile there is no verdict to ask about, and after the assembly a note
/// has already been copied and the chain checked.
#[test]
fn o288_the_rotation_check_runs_once_on_the_read_only_open_before_any_note() {
    let src = include_str!("lib.rs");
    let prod = &src[..src
        .find(concat!("#[cfg(test)]\nmod ", "tests {"))
        .expect("premise: the tests module is where this gate expects it")];
    let body = |name: &str| -> &str {
        let start = prod
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("premise: no fn {name}"));
        let rest = &prod[start..];
        let end = ["\n    fn ", "\n    pub fn ", "\n    pub(crate) fn "]
            .iter()
            .filter_map(|m| rest[3..].find(m))
            .min()
            .map_or(rest.len(), |e| e + 3);
        &rest[..end]
    };
    let call = concat!("Self::adopted_rotation", "_holds(");
    assert_eq!(prod.matches(call).count(), 1, "one call site");
    let ro = body("open_inner_read_only");
    let (reconcile, check, assemble) = (
        ro.find(".reconcile_read_only(").expect("the reconcile"),
        ro.find(call).expect("the check is on the read-only open"),
        ro.find("Self::assemble(").expect("the assembly"),
    );
    assert!(
        reconcile < check && check < assemble,
        "after the reconcile, before the assembly"
    );
    assert!(
        !body("open_inner").contains(call),
        "never on the writable open"
    );
    let rule = concat!(".deferral_in", "_force(");
    assert_eq!(prod.matches(rule).count(), 1, "the rule asked once");
    assert!(body("adopted_rotation_holds").contains(rule));
}
