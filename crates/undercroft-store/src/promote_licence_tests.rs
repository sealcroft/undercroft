//! ROADMAP O290: a writable open promotes a staged rotation only while the
//! files still license it.
//!
//! The unlock reads `vault.json.next` and `vault.json` by path before any
//! database connection exists; the writable open's reconcile then acts, under
//! the write lock, on what it read. Its promote used to write the staged twin's
//! manifest from memory over whatever `vault.json` had become — deleted, torn,
//! forged — so a database rolled back beneath the open, with `vault.json`
//! deleted, opened as a crash lag and verified clean, and a forged manifest was
//! overwritten with no tamper event. It now asks the manifest rule, once, under
//! the lock: the staged branch writes, a promote since skips the write, and
//! anything else is the rule's own refusal with nothing written. A leftover or
//! an abandoned stage is removed only while `vault.json` verifies under the
//! handle's key.
//!
//! Every refusal asserts its VARIANT and the files' bytes: three integrity
//! variants exit 2, and the defect in the settled case was a deletion beside a
//! refusal today's code already made.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::OptionalExtension;
use tempfile::TempDir;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{fixture, Access, SecurityLevel, Vault, VaultError, VaultManager};

use crate::rotate_pause as pause;
use crate::{StoreError, VaultStore};

const VAULT: &str = "o290";
const LEVELS: [SecurityLevel; 2] = [SecurityLevel::HmacOnly, SecurityLevel::Sealed];
const HEAL: &str = "record(s) behind";

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

/// What is at a manifest path: its bytes, `None` for nothing, and a directory
/// told apart from both.
#[derive(Debug, PartialEq, Eq)]
enum At {
    Bytes(Vec<u8>),
    Nothing,
    Dir,
}

fn at(p: &Path) -> At {
    if p.is_dir() {
        At::Dir
    } else {
        std::fs::read(p).map_or(At::Nothing, At::Bytes)
    }
}

/// The database's committed height and keycheck, read with no store.
fn db_state(root: &Path) -> (Option<String>, Option<String>) {
    let c = rusqlite::Connection::open_with_flags(
        vdir(root).join("vault.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let get =
        |sql: &str| -> Option<String> { c.query_row(sql, [], |r| r.get(0)).optional().unwrap() };
    (
        get("SELECT value FROM chain_meta WHERE key = 'writes'"),
        get("SELECT value FROM meta WHERE key = 'keycheck'"),
    )
}

fn head_of(bytes: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    v["chain_head_hex"].as_str().unwrap().to_string()
}

fn flip_mac(p: &Path) {
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    let mac = v["manifest_mac_hex"].as_str().unwrap().to_string();
    let first = if mac.starts_with('0') { "1" } else { "0" };
    v["manifest_mac_hex"] = serde_json::Value::String(format!("{first}{}", &mac[1..]));
    std::fs::write(p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

fn writable(root: &Path) -> VaultStore {
    VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap()
}

fn read_only(root: &Path) -> Result<VaultStore, StoreError> {
    let m = VaultManager::open_as(root, None, Access::ReadOnly)?;
    VaultStore::open_read_only(
        m.unlock_as(VAULT, Access::ReadOnly)?,
        Box::new(HashEmbedder),
    )
}

fn plain(root: &Path, level: SecurityLevel) {
    let mut w = VaultStore::open(mgr(root).create(VAULT, level).unwrap()).unwrap();
    w.upsert_many(&(0..20).map(|i| drawer("note", i)).collect::<Vec<_>>())
        .unwrap();
}

/// A rotation that commits and fails every promote attempt, through the fault
/// seam: `vault.json` the retired bytes R, `.next` the staged manifest S.
/// Returns (R, S).
fn deferral(root: &Path, level: SecurityLevel) -> (Vec<u8>, Vec<u8>) {
    plain(root, level);
    let m = mgr(root);
    let mut w = writable(root);
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
    (
        std::fs::read(manifest(root)).unwrap(),
        std::fs::read(staging(root)).unwrap(),
    )
}

/// A rotation that stages and aborts before its commit (a panicking pause
/// hook): an abandoned `.next` beside the vault's own `vault.json`.
fn abandoned_stage(root: &Path) {
    let m = mgr(root);
    let mut w = writable(root);
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

fn held(root: &Path) -> Vault {
    let v = mgr(root).unlock(VAULT).unwrap();
    assert!(
        v.has_pending(),
        "premise: the held unlock attached the stage"
    );
    v
}

/// Another writable open promotes the deferral and writes `before`, the
/// database is copied, then `after` more. Returns (height at copy, final).
fn promote_and_write(root: &Path, before: u32, after: u32) -> (u64, u64) {
    let mut s = writable(root);
    for i in 0..before {
        s.upsert(&drawer("after", 100 + i)).unwrap();
    }
    let at_copy = s.chain_state().unwrap().1;
    let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
    c.execute("VACUUM INTO ?1", [root.join("copy.db").to_str().unwrap()])
        .unwrap();
    for i in 0..after {
        s.upsert(&drawer("after", 200 + i)).unwrap();
    }
    (at_copy, s.chain_state().unwrap().1)
}

fn restore_db(root: &Path) {
    for f in ["vault.db", "vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(vdir(root).join(f));
    }
    std::fs::copy(root.join("copy.db"), vdir(root).join("vault.db")).unwrap();
}

fn corrupt(r: &Result<VaultStore, StoreError>) -> String {
    match r {
        Err(StoreError::Vault(VaultError::CorruptManifest(m))) => m.clone(),
        other => panic!("expected CorruptManifest, got {:?}", other.as_ref().err()),
    }
}

/// **P-W, the filing (ROADMAP O290)**: a held writable unlock over a deferral;
/// another open promotes and writes to 27; the database is restored to a copy
/// at 24 and `vault.json` deleted. The held open answered Ok at height 24 with
/// a crash-lag note and `verify` OK, and every later open saw a clean vault. It
/// now refuses as a live handle refuses an absent manifest, writes nothing, and
/// leaves a fresh open's answer — `NotFound` — as it was.
#[test]
fn o290_a_rollback_beneath_a_held_writable_unlock_is_refused_and_writes_nothing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let (retired, _) = deferral(root, level);
        let v = held(root);
        let (copied, last) = promote_and_write(root, 2, 3);
        assert!(copied < last, "premise: the copy is behind");
        assert_eq!(at(&staging(root)), At::Nothing, "premise: promoted");
        assert_ne!(
            at(&manifest(root)),
            At::Bytes(retired),
            "premise: the promote wrote vault.json"
        );
        std::fs::remove_file(manifest(root)).unwrap();
        restore_db(root);
        let before = db_state(root);
        let msg = corrupt(&VaultStore::open(v));
        assert!(
            msg.contains("vault.json is missing from"),
            "{level:?}: {msg}"
        );
        assert_eq!(
            at(&manifest(root)),
            At::Nothing,
            "{level:?}: nothing written"
        );
        assert_eq!(at(&staging(root)), At::Nothing, "{level:?}");
        assert_eq!(db_state(root), before, "{level:?}: height and keycheck");
        assert_eq!(before.0.as_deref(), Some(copied.to_string().as_str()));
        assert!(matches!(
            mgr(root).unlock(VAULT),
            Err(VaultError::NotFound(_))
        ));
        assert!(matches!(
            read_only(root),
            Err(StoreError::Vault(VaultError::NotFound(_)))
        ));
    }
}

/// **P-W′**: the same rollback with the RETIRED bytes written back instead of
/// deleting `vault.json`. "The bytes the unlock read" — the filed candidate's
/// licence — accepts it; the rule's staged branch does not, because `.next` is
/// gone: the lost-staging verdict, R byte-identical, and a fresh open's
/// integrity finding unchanged.
#[test]
fn o290_the_retired_bytes_put_back_beneath_a_held_unlock_are_refused_as_lost_keys() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let (retired, _) = deferral(root, level);
        let v = held(root);
        promote_and_write(root, 2, 3);
        restore_db(root);
        std::fs::write(manifest(root), &retired).unwrap();
        let before = db_state(root);
        let msg = corrupt(&VaultStore::open(v));
        assert!(
            msg.contains("vault.json.next, which holds"),
            "{level:?}: {msg}"
        );
        assert_eq!(at(&manifest(root)), At::Bytes(retired), "{level:?}");
        assert_eq!(at(&staging(root)), At::Nothing, "{level:?}");
        assert_eq!(db_state(root), before, "{level:?}: nothing committed");
        assert!(
            matches!(
                mgr(root).unlock(VAULT).map(VaultStore::open),
                Ok(Err(StoreError::IntegrityFinding(_)))
            ),
            "{level:?}: a fresh open's verdict"
        );
    }
}

/// **The heal O257 item 5 made, refused** (ROADMAP O290): `vault.json`
/// deleted, torn, forged, a directory or too new between a held unlock and its
/// open, with no rollback. Each is refused in the rule's own class, with the
/// files exactly as found — the forged file above all, which every fresh open
/// pages on and the heal overwrote.
#[test]
fn o290_a_manifest_edited_in_the_window_is_refused_in_the_rules_class_and_kept() {
    for level in LEVELS {
        for edit in ["deleted", "torn", "forged", "directory", "too-new"] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            let (retired, staged) = deferral(root, level);
            let v = held(root);
            let p = manifest(root);
            match edit {
                "deleted" => std::fs::remove_file(&p).unwrap(),
                "torn" => std::fs::write(&p, &retired[..retired.len() / 2]).unwrap(),
                "forged" => flip_mac(&p),
                "directory" => {
                    std::fs::remove_file(&p).unwrap();
                    std::fs::create_dir(&p).unwrap();
                }
                _ => {
                    let mut m: serde_json::Value = serde_json::from_slice(&retired).unwrap();
                    m["version"] = serde_json::json!(undercroft_vault::MANIFEST_VERSION + 1);
                    std::fs::write(&p, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
                }
            }
            let found = at(&p);
            let before = db_state(root);
            let opened = VaultStore::open(v);
            let label = format!("{level:?} {edit}");
            match (edit, &opened) {
                ("deleted", Err(StoreError::Vault(VaultError::CorruptManifest(m)))) => {
                    assert!(m.contains("vault.json is missing from"), "{label}: {m}");
                    assert!(
                        m.contains("vault.json.next is intact beside it"),
                        "{label}: the verdict names the file holding the keys: {m}"
                    );
                }
                ("torn", Err(StoreError::Vault(VaultError::CorruptManifest(_)))) => {}
                ("forged", Err(StoreError::Vault(VaultError::ManifestTampered))) => {}
                ("directory", Err(StoreError::Vault(VaultError::CorruptManifest(m)))) => {
                    assert!(m.contains("is not a manifest file in"), "{label}: {m}")
                }
                ("too-new", Err(StoreError::Vault(VaultError::ManifestTooNew { .. }))) => {}
                _ => panic!("{label}: {:?}", opened.as_ref().err()),
            }
            assert_eq!(at(&p), found, "{label}: vault.json as found");
            assert_eq!(at(&staging(root)), At::Bytes(staged), "{label}: .next kept");
            assert_eq!(db_state(root), before, "{label}: nothing committed");
            if edit == "deleted" {
                // What a fresh open answers, unchanged by the refused one.
                assert!(
                    matches!(mgr(root).unlock(VAULT), Err(VaultError::NotFound(_))),
                    "{label}: fresh writable"
                );
                assert!(
                    matches!(
                        read_only(root),
                        Err(StoreError::Vault(VaultError::NotFound(_)))
                    ),
                    "{label}: fresh read-only"
                );
            }
        }
    }
}

/// A FIFO at `vault.json` in the window answers within a bound: the licence's
/// guarded read classes it as no manifest file before anything could open it.
/// The heal's bare read blocked on it while the open held the write lock.
#[cfg(unix)]
#[test]
fn o290_a_fifo_at_the_manifest_in_the_window_answers_within_a_bound() {
    use std::os::unix::fs::FileTypeExt;
    use std::sync::mpsc;
    use std::time::Duration;
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let (_, staged) = deferral(&root, level);
        let v = held(&root);
        std::fs::remove_file(manifest(&root)).unwrap();
        let ok = std::process::Command::new("mkfifo")
            .arg(manifest(&root))
            .status()
            .expect("premise: mkfifo runs")
            .success();
        assert!(ok, "premise: the FIFO was made");
        let before = db_state(&root);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(
                VaultStore::open(v)
                    .err()
                    .map(|e| matches!(e, StoreError::Vault(VaultError::CorruptManifest(_)))),
            );
        });
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(answer) => assert_eq!(answer, Some(true), "{level:?}: the absent verdict"),
            Err(_) => {
                // Read-write: releases a reader blocked opening it, never waits.
                drop(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(manifest(&root)),
                );
                let _ = rx.recv_timeout(Duration::from_secs(10));
                panic!("{level:?}: the writable open BLOCKED on a FIFO at vault.json");
            }
        }
        assert!(
            std::fs::symlink_metadata(manifest(&root))
                .unwrap()
                .file_type()
                .is_fifo(),
            "{level:?}: the FIFO left where it was"
        );
        assert_eq!(
            at(&staging(&root)),
            At::Bytes(staged),
            "{level:?}: .next kept"
        );
        assert_eq!(db_state(&root), before, "{level:?}: nothing committed");
    }
}

/// A `vault.json` that is there and cannot be read, at the licence (the
/// fixture fault on the rule's read): the read error, and nothing written.
#[test]
fn o290_a_read_fault_at_the_licence_is_io_and_writes_nothing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let (retired, staged) = deferral(root, level);
        let v = held(root);
        let before = db_state(root);
        fixture::fail_next(fixture::Fault::RuleRead);
        let opened = VaultStore::open(v);
        assert!(
            fixture::armed().is_none(),
            "{level:?}: premise: the fault fired"
        );
        assert!(
            matches!(opened, Err(StoreError::Vault(VaultError::Io(_)))),
            "{level:?}: {:?}",
            opened.err()
        );
        assert_eq!(at(&manifest(root)), At::Bytes(retired), "{level:?}");
        assert_eq!(at(&staging(root)), At::Bytes(staged), "{level:?}");
        assert_eq!(db_state(root), before, "{level:?}: nothing committed");
    }
}

/// **The recovery the heal existed for stays**: a steady deferral — the files
/// the unlock read, untouched — is promoted by the next writable open. The
/// handle it leaves carries no deferral (the licence's retired digest is
/// cleared), and the promoted manifest is the staged one.
#[test]
fn o290_a_steady_deferral_is_still_promoted_under_its_licence() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let (_, staged) = deferral(root, level);
        let s = VaultStore::open(held(root)).unwrap();
        assert!(!s.vault.promotion_deferred(), "{level:?}: no deferral kept");
        assert!(
            !s.unhealed().iter().any(|n| n.contains(HEAL)),
            "{level:?}: {:?}",
            s.unhealed()
        );
        assert_eq!(at(&staging(root)), At::Nothing, "{level:?}: .next removed");
        let At::Bytes(written) = at(&manifest(root)) else {
            panic!("{level:?}: no vault.json");
        };
        assert_eq!(head_of(&written), head_of(&staged), "{level:?}: S's head");
        assert!(s.verify().unwrap().ok(), "{level:?}");
        drop(s);
        let r = read_only(root).unwrap();
        assert!(!r.vault.promotion_deferred(), "{level:?}: settled");
    }
}

/// **The discriminator a kept retired digest would pass**: with the deferral
/// promoted under its licence, the RETIRED pair put back beneath the live
/// writable handle is a forged manifest to it, as to any ordinary handle —
/// never "the deferral again".
#[test]
fn o290_the_retired_pair_put_back_beneath_the_promoted_handle_pages() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let (retired, staged) = deferral(root, level);
        let s = VaultStore::open(held(root)).unwrap();
        std::fs::write(manifest(root), &retired).unwrap();
        std::fs::write(staging(root), &staged).unwrap();
        assert!(
            matches!(
                s.verify(),
                Err(StoreError::Vault(VaultError::ManifestTampered))
            ),
            "{level:?}"
        );
    }
}

/// **A promote since is followed, never rewritten** (O254's P1, from the
/// licence's side): another open promotes after the held unlock — its `.next`
/// removal succeeding or failing, and with anchors after it — and the held open
/// serves the vault with `vault.json` exactly as the promote left it, no heal
/// note, and a leftover `.next` removed.
#[test]
fn o290_a_promote_since_the_unlock_is_followed_and_never_rewritten() {
    for level in LEVELS {
        for how in ["removed", "removal-failed", "anchored"] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            let (_, staged) = deferral(root, level);
            let v = held(root);
            match how {
                "removal-failed" => {
                    fixture::fail_next(fixture::Fault::RemoveStaged);
                    assert!(VaultStore::open(mgr(root).unlock(VAULT).unwrap()).is_err());
                    assert_eq!(
                        at(&staging(root)),
                        At::Bytes(staged.clone()),
                        "premise: the leftover"
                    );
                }
                "anchored" => {
                    let mut s = writable(root);
                    for i in 0..3 {
                        s.upsert(&drawer("after", 300 + i)).unwrap();
                    }
                }
                _ => drop(writable(root)),
            }
            let label = format!("{level:?} {how}");
            let promoted = at(&manifest(root));
            let s = VaultStore::open(v).unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(
                at(&manifest(root)),
                promoted,
                "{label}: vault.json untouched"
            );
            assert_eq!(at(&staging(root)), At::Nothing, "{label}");
            assert!(
                !s.unhealed().iter().any(|n| n.contains(HEAL)),
                "{label}: {:?}",
                s.unhealed()
            );
            assert!(!s.vault.promotion_deferred(), "{label}");
            assert!(s.verify().unwrap().ok(), "{label}");
        }
    }
}

/// A second rotation that stages and aborts after the promote: the held open
/// is licensed by the promote (it skips the write), and the aborted stage — not
/// the bytes the unlock read — survives.
#[test]
fn o290_a_second_rotations_aborted_stage_survives_the_held_open() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        deferral(root, level);
        let v = held(root);
        drop(writable(root));
        abandoned_stage(root);
        let second = at(&staging(root));
        let s = VaultStore::open(v).unwrap();
        assert_eq!(
            at(&staging(root)),
            second,
            "{level:?}: the aborted stage kept"
        );
        assert!(s.verify().unwrap().ok(), "{level:?}");
    }
}

/// **The promote decides on the licence's answer, never a second read**: a
/// hook between the licence (a promote since: skip the write) and the promote
/// deletes `vault.json`. Nothing is written, and the open refuses the absent
/// manifest. Deciding on a second read, it wrote the staged manifest — the
/// anchor the unlock read — over the gap. And where the promoter's removal had
/// failed, the leftover `.next` it left is not removed on the licence's earlier
/// answer: with `vault.json` gone it is the last copy of the keys (found by
/// O290's review; the leftover rule of O290 item 3, applied in `promote_as`).
#[test]
fn o290_the_licence_decides_and_the_promote_never_reads_again() {
    for level in LEVELS {
        for leftover in [false, true] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            let (_, staged) = deferral(root, level);
            let v = held(root);
            if leftover {
                fixture::fail_next(fixture::Fault::RemoveStaged);
                assert!(VaultStore::open(mgr(root).unlock(VAULT).unwrap()).is_err());
                assert_eq!(
                    at(&staging(root)),
                    At::Bytes(staged.clone()),
                    "premise: the promoter's leftover"
                );
            } else {
                drop(writable(root));
                assert_eq!(at(&staging(root)), At::Nothing, "premise: removed");
            }
            let label = format!("{level:?} leftover={leftover}");
            let r = root.to_path_buf();
            let fired = std::rc::Rc::new(std::cell::Cell::new(false));
            let f = fired.clone();
            fixture::between_licence_and_promote(move || {
                f.set(true);
                std::fs::remove_file(manifest(&r)).unwrap();
            });
            let before = db_state(root);
            let kept = at(&staging(root));
            let opened = VaultStore::open(v);
            assert!(fired.get(), "{label}: premise: the hook fired");
            let msg = corrupt(&opened);
            assert!(msg.contains("vault.json is missing from"), "{label}: {msg}");
            assert_eq!(at(&manifest(root)), At::Nothing, "{label}: nothing written");
            assert_eq!(at(&staging(root)), kept, "{label}: .next as found");
            assert_eq!(db_state(root), before, "{label}: nothing committed");
        }
    }
}

/// **A leftover or an abandoned stage outlives a `vault.json` that went**
/// (ROADMAP O290): removed only while `vault.json` verifies under the handle's
/// key. A settled leftover beside a deleted `vault.json` was the last copy of
/// the keys, and the open deleted it and then refused. With `vault.json`
/// intact both are still removed — the controls.
#[test]
fn o290_a_leftover_or_an_abandoned_stage_outlives_a_manifest_that_went() {
    for level in LEVELS {
        for (kind, edit) in [
            ("settled", "deleted"),
            ("settled", "forged"),
            ("settled", "intact"),
            ("abandoned", "deleted"),
            ("abandoned", "forged"),
            ("abandoned", "intact"),
        ] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            plain(root, level);
            if kind == "settled" {
                let m = mgr(root);
                writable(root)
                    .rotate_keys(m.rotation_candidate(VAULT).unwrap())
                    .unwrap();
                std::fs::copy(manifest(root), staging(root)).unwrap();
            } else {
                abandoned_stage(root);
            }
            let stage = at(&staging(root));
            let v = held(root);
            match edit {
                "deleted" => std::fs::remove_file(manifest(root)).unwrap(),
                "forged" => flip_mac(&manifest(root)),
                _ => {}
            }
            let label = format!("{level:?} {kind} {edit}");
            let found = at(&manifest(root));
            let before = db_state(root);
            let opened = VaultStore::open(v);
            match (edit, &opened) {
                ("deleted", Err(StoreError::Vault(VaultError::CorruptManifest(m)))) => {
                    assert!(m.contains("vault.json is missing from"), "{label}: {m}")
                }
                ("forged", Err(StoreError::Vault(VaultError::ManifestTampered))) => {}
                ("intact", Ok(_)) => {}
                _ => panic!("{label}: {:?}", opened.as_ref().err()),
            }
            if edit == "intact" {
                assert_eq!(at(&staging(root)), At::Nothing, "{label}: removed");
            } else {
                assert_eq!(at(&staging(root)), stage, "{label}: .next kept");
                assert_eq!(at(&manifest(root)), found, "{label}: vault.json as found");
                assert_eq!(db_state(root), before, "{label}: nothing committed");
            }
        }
    }
}

/// The read-only posture of the same window: a held read-only unlock over the
/// deferral, the rollback and the deletion — the integrity verdict, never the
/// reopen class (ROADMAP O290, revising O289 item 3a's `Io`).
#[test]
fn o290_the_read_only_window_answers_an_absent_manifest_as_integrity() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        deferral(root, level);
        let v = VaultManager::open_as(root, None, Access::ReadOnly)
            .unwrap()
            .unlock_as(VAULT, Access::ReadOnly)
            .unwrap();
        assert!(v.has_pending(), "premise");
        promote_and_write(root, 2, 3);
        std::fs::remove_file(manifest(root)).unwrap();
        restore_db(root);
        let before = db_state(root);
        let opened = VaultStore::open_read_only(v, Box::new(HashEmbedder));
        assert!(
            !matches!(opened, Err(StoreError::StaleUnlock(_))),
            "{level:?}: never a reopen"
        );
        let msg = corrupt(&opened);
        assert!(
            msg.contains("vault.json is missing from"),
            "{level:?}: {msg}"
        );
        assert_eq!(at(&manifest(root)), At::Nothing, "{level:?}");
        assert_eq!(at(&staging(root)), At::Nothing, "{level:?}");
        assert_eq!(db_state(root), before, "{level:?}");
    }
}

/// **What the licence does not see, pinned** — each a cost the ruling states,
/// whose disappearance is news to record. The promoted manifest KEPT beside the
/// rolled-back database: the anchor refuses it, held and fresh alike. The same
/// rollback with NO deferral, `vault.json` deleted: the absent-manifest verdict
/// held, "no such vault" fresh — the licence never runs there. The database AND
/// `vault.json` rolled back together, and the retired pair put back beside the
/// rolled-back database (P-W‴): accepted by the held open and by a fresh open,
/// the second with the lag note — A2, which only the witness sees (ROADMAP
/// O245).
#[test]
fn o290_what_the_licence_cannot_see_is_pinned() {
    for level in LEVELS {
        // The promoted manifest kept.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        deferral(root, level);
        let v = held(root);
        promote_and_write(root, 2, 3);
        restore_db(root);
        let (found, before) = (at(&manifest(root)), db_state(root));
        assert!(matches!(
            VaultStore::open(v),
            Err(StoreError::Vault(VaultError::ManifestTampered))
        ));
        assert_eq!(at(&manifest(root)), found, "{level:?}: kept, as found");
        assert_eq!(db_state(root), before, "{level:?}: kept: nothing committed");
        assert!(
            matches!(
                mgr(root).unlock(VAULT).map(VaultStore::open),
                Ok(Err(StoreError::Vault(VaultError::ManifestTampered)))
            ),
            "{level:?}: kept: a fresh open alike"
        );
        // No deferral: an ordinary held unlock, the rollback, `vault.json` gone.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        plain(root, level);
        let v = mgr(root).unlock(VAULT).unwrap();
        assert!(!v.has_pending(), "premise: no deferral");
        promote_and_write(root, 2, 3);
        std::fs::remove_file(manifest(root)).unwrap();
        restore_db(root);
        let msg = corrupt(&VaultStore::open(v));
        assert!(
            msg.contains("vault.json is missing from"),
            "{level:?}: {msg}"
        );
        assert!(matches!(
            mgr(root).unlock(VAULT),
            Err(VaultError::NotFound(_))
        ));
        // The pair rolled back.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        deferral(root, level);
        let v = held(root);
        let mut s = writable(root);
        for i in 0..2 {
            s.upsert(&drawer("after", 100 + i)).unwrap();
        }
        let pair_height = s.chain_state().unwrap().1;
        let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
        c.execute("VACUUM INTO ?1", [root.join("copy.db").to_str().unwrap()])
            .unwrap();
        let pair_manifest = std::fs::read(manifest(root)).unwrap();
        for i in 0..3 {
            s.upsert(&drawer("after", 200 + i)).unwrap();
        }
        drop((s, c));
        restore_db(root);
        std::fs::write(manifest(root), &pair_manifest).unwrap();
        let s = VaultStore::open(v).unwrap();
        assert_eq!(s.chain_state().unwrap().1, pair_height, "{level:?}: PAIR");
        assert!(s.verify().unwrap().ok(), "{level:?}: PAIR verifies");
        // The retired pair put back beside the rolled-back database.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let (retired, staged) = deferral(root, level);
        let v = held(root);
        let (copied, _) = promote_and_write(root, 2, 3);
        let put_back = |root: &Path| {
            restore_db(root);
            std::fs::write(manifest(root), &retired).unwrap();
            std::fs::write(staging(root), &staged).unwrap();
        };
        put_back(root);
        let s = VaultStore::open(v).unwrap();
        assert_eq!(s.chain_state().unwrap().1, copied, "{level:?}: P-W3 held");
        assert!(s.unhealed().iter().any(|n| n.contains(HEAL)), "{level:?}");
        drop(s);
        put_back(root);
        let s = writable(root);
        assert_eq!(s.chain_state().unwrap().1, copied, "{level:?}: P-W3 fresh");
        assert!(s.unhealed().iter().any(|n| n.contains(HEAL)), "{level:?}");
    }
}
