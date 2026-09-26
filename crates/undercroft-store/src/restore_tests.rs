//! ROADMAP O268: `backup restore` proves an archive before it touches the
//! vault it replaces.
//!
//! Every refusal the ARCHIVE causes is checked against the live vault's bytes —
//! every file's name and contents read as files, never through an open, since
//! an open heals — on a quiescent vault and on one whose writer left committed
//! frames in its `-wal` (a leaked connection: the frames stay, as a SIGKILLed
//! server's do). Every restored vault is checked through a fresh open, which
//! must verify at exactly the height and head the report names.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;
use undercroft_core::embed::Embedder;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::restores::RESTORE_ROOT;
use undercroft_vault::{fixture, Access, SecurityLevel, Vault, VaultError, VaultManager};

use crate::restore_pause::{self as pause, Phase};
use crate::{
    restore_archive, BackupOutcome, BackupReport, RestoreOutcome, RestoreReport, StoreError,
    VaultStore,
};

const VAULT: &str = "o268";

fn hash(_: &Vault) -> Result<Box<dyn Embedder + Send>, StoreError> {
    Ok(Box::new(HashEmbedder))
}

fn drawer(content: &str, idx: u32) -> Drawer {
    Drawer::new(
        "w1",
        "r",
        content.into(),
        Some("o268.md".into()),
        idx,
        "test",
    )
}

fn mgr(root: &Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn open_at(root: &Path) -> VaultStore {
    VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap()
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn backups(root: &Path) -> PathBuf {
    root.join("backups")
}

/// A vault of `n` drawers with a trust class, a retention policy and facts.
fn corpus(n: usize) -> TempDir {
    let dir = TempDir::new().unwrap();
    let m = mgr(dir.path());
    let mut s = VaultStore::open(m.create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
    let batch: Vec<Drawer> = (0..n)
        .map(|i| {
            drawer(
                &format!("note {i}: the harbour ledger names cargo {i}"),
                i as u32,
            )
        })
        .collect();
    s.upsert_many(&batch).unwrap();
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

fn save(s: &mut VaultStore, i: u32) {
    s.upsert(&Drawer::new(
        "w2",
        "r",
        format!("a later save {i}"),
        Some("o268-later.md".into()),
        i,
        "test",
    ))
    .unwrap();
}

/// An archive of the vault through O256's door, and its report.
fn archive(root: &Path) -> (PathBuf, BackupReport) {
    let s = open_at(root);
    let report = match s.backup(&backups(root)).unwrap() {
        BackupOutcome::Created(r) => r,
        BackupOutcome::Refused(r) => panic!("premise: the vault verifies ({r:?})"),
    };
    (backups(root).join(&report.name), report)
}

/// A copy of `archive` beside it, under another name, for damaging.
fn copy_archive(archive: &Path, name: &str) -> PathBuf {
    let to = archive.parent().unwrap().join(name);
    std::fs::create_dir(&to).unwrap();
    for e in std::fs::read_dir(archive).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
    to
}

/// Every file under `dir`, by relative path, with its bytes — read as files.
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            if m.is_dir() {
                out.insert(format!("{rel}/"), Vec::new());
                walk(base, &p, out);
            } else {
                out.insert(rel, std::fs::read(&p).unwrap_or_default());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn restored(outcome: Result<RestoreOutcome, StoreError>) -> RestoreReport {
    match outcome {
        Ok(RestoreOutcome::Restored(r)) => r,
        Ok(RestoreOutcome::Refused(r)) => panic!("the archive verifies, yet it was refused: {r:?}"),
        Err(e) => panic!("the restore failed: {e}"),
    }
}

/// The restored vault, through a fresh open: verifies, and holds exactly the
/// reported state.
fn assert_is_the_reported_state(root: &Path, report: &RestoreReport, label: &str) {
    let s = open_at(root);
    assert!(
        s.verify().unwrap().ok(),
        "{label}: the restored vault verifies"
    );
    let (head, writes) = s.chain_state().unwrap();
    assert_eq!(
        (head.as_str(), writes),
        (report.chain_head.as_str(), report.writes),
        "{label}: the restored vault holds EXACTLY the reported state"
    );
}

/// No restore area left behind a refusal, and nothing that lists vaults sees one.
fn assert_no_stage(root: &Path, label: &str) {
    let area = root.join("vaults").join(RESTORE_ROOT);
    let left: Vec<_> = std::fs::read_dir(&area)
        .map(|rd| rd.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "{label}: the restore area holds {left:?}");
    assert!(
        !mgr(root).list().unwrap().iter().any(|v| v == RESTORE_ROOT),
        "{label}: the restore area is never a vault"
    );
}

fn is_integrity(e: &StoreError) -> bool {
    matches!(e, StoreError::IntegrityFinding(_))
}

/// A live vault whose writer's committed frames sit in its `-wal` and which
/// nothing holds — a SIGKILLed server's state: the writer's connection closes
/// with checkpoint-on-close off, so its frames stay where they were.
fn heat(root: &Path) {
    let mut s = open_at(root);
    save(&mut s, 900);
    save(&mut s, 901);
    s.conn
        .set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .unwrap();
    drop(s);
    let wal = vdir(root).join("vault.db-wal");
    assert!(
        std::fs::metadata(&wal)
            .map(|m| m.len() > 0)
            .unwrap_or(false),
        "premise: a hot -wal"
    );
}

/// **A good archive restores over a vault that moved on, and the result is
/// exactly the archive**: the report's `archived_*` equal O256's create report,
/// a fresh open verifies at the reported state, no restore area is left, and the
/// replaced vault's later writes are gone.
#[test]
fn o268_a_good_archive_restores_and_is_exactly_the_archive() {
    let dir = corpus(200);
    let root = dir.path();
    let (arch, created) = archive(root);
    {
        let mut s = open_at(root);
        for i in 0..5 {
            save(&mut s, i);
        }
    }
    let report = restored(restore_archive(&mgr(root), &arch, None, true, &hash));
    assert_eq!(report.vault, VAULT);
    assert!(report.replaced);
    assert_eq!(report.archived_writes, Some(created.writes));
    assert_eq!(
        report.archived_chain_head.as_deref(),
        Some(created.chain_head.as_str())
    );
    assert_eq!(
        (report.writes, report.chain_head.as_str()),
        (created.writes, created.chain_head.as_str()),
        "a current archive's open appends nothing"
    );
    assert_eq!(report.key_generation_differs, Some(false));
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    assert_is_the_reported_state(root, &report, "good");
    assert_no_stage(root, "good");
    assert_eq!(
        open_at(root).count().unwrap(),
        200,
        "the later saves are gone"
    );
    // The archive itself was read, never written.
    let (again, _) = archive(root);
    assert_ne!(again, arch);
}

/// **Every refusal the archive causes leaves the live vault byte-identical**,
/// quiescent or with committed frames in its `-wal`, and is an integrity
/// verdict. Each damaged archive is first shown to be one today's restore would
/// have taken: it does not open and verify in a scratch root.
#[test]
fn o268_a_damaged_archive_is_refused_and_the_live_vault_is_unchanged() {
    for hot in [false, true] {
        let dir = corpus(40);
        let root = dir.path();
        let (arch, _) = archive(root);
        {
            let mut s = open_at(root);
            save(&mut s, 1);
        }
        // T1: a newer manifest beside the older database.
        let t1 = copy_archive(&arch, "o268-t1");
        std::fs::copy(vdir(root).join("vault.json"), t1.join("vault.json")).unwrap();
        // T2: a truncated database.
        let t2 = copy_archive(&arch, "o268-t2");
        let db = std::fs::read(t2.join("vault.db")).unwrap();
        std::fs::write(t2.join("vault.db"), &db[..db.len() / 2]).unwrap();
        // T3: another installation's archive of a vault with the same id.
        let other = corpus(10);
        let (foreign, _) = archive(other.path());
        let t3 = copy_archive(&foreign, "o268-t3");
        // T4: one flipped byte near the end of the database.
        let t4 = copy_archive(&arch, "o268-t4");
        let mut db = std::fs::read(t4.join("vault.db")).unwrap();
        let at = db.len() - 700;
        db[at] ^= 0xff;
        std::fs::write(t4.join("vault.db"), &db).unwrap();
        // T5: a database that is a link — something no archive holds.
        let t5 = copy_archive(&arch, "o268-t5");
        #[cfg(unix)]
        {
            std::fs::remove_file(t5.join("vault.db")).unwrap();
            std::os::unix::fs::symlink(arch.join("vault.db"), t5.join("vault.db")).unwrap();
        }
        if hot {
            heat(root);
        }
        let live = tree(&vdir(root));
        for (label, damaged) in [
            ("T1", &t1),
            ("T2", &t2),
            ("T3", &t3),
            ("T4", &t4),
            ("T5", &t5),
        ] {
            if label == "T5" && cfg!(not(unix)) {
                continue;
            }
            let label = format!("{label} hot={hot}");
            let outcome = restore_archive(&mgr(root), damaged, None, true, &hash);
            match &outcome {
                Err(e) => assert!(is_integrity(e), "{label}: an integrity verdict, got {e}"),
                Ok(RestoreOutcome::Refused(_)) => {}
                Ok(RestoreOutcome::Restored(r)) => panic!("{label}: restored {r:?}"),
            }
            if let Err(e) = &outcome {
                let said = e.to_string();
                assert!(
                    said.contains("the live vault was not changed"),
                    "{label}: the refusal says the live vault is intact: {said}"
                );
                // Each names its own cause: the two sources of one variant are
                // not the same finding.
                let cause = match &label[..2] {
                    "T1" => "does not reach",
                    "T3" => "fails its MAC",
                    "T5" => "regular file",
                    _ => "",
                };
                assert!(said.contains(cause), "{label}: names {cause:?}: {said}");
            }
            assert_eq!(
                tree(&vdir(root)),
                live,
                "{label}: the live vault is byte-identical"
            );
            assert_no_stage(root, &label);
        }
    }
}

/// **The planted id**: an archive whose manifest is edited to name another
/// vault — what a writer without the key can make — is refused, and the vault it
/// names is untouched. Today's restore removed `vaults/<that id>` on `--force`.
#[test]
fn o268_an_archive_naming_another_vault_cannot_replace_it() {
    let dir = corpus(20);
    let root = dir.path();
    let (arch, _) = archive(root);
    {
        let m = mgr(root);
        let mut v = VaultStore::open(m.create("victim", SecurityLevel::Sealed).unwrap()).unwrap();
        v.upsert(&Drawer::new(
            "w",
            "r",
            "the victim's own drawer".into(),
            None,
            0,
            "t",
        ))
        .unwrap();
    }
    let planted = copy_archive(&arch, "victim-2026-01-01T00-00-00Z");
    let raw = std::fs::read_to_string(planted.join("vault.json")).unwrap();
    let edited = raw.replace(&format!("\"id\": \"{VAULT}\""), "\"id\": \"victim\"");
    assert_ne!(raw, edited, "premise: the manifest's id was edited");
    std::fs::write(planted.join("vault.json"), edited).unwrap();
    let victim = tree(&root.join("vaults").join("victim"));
    let e = match restore_archive(&mgr(root), &planted, None, true, &hash) {
        Err(e) => e,
        Ok(o) => panic!("a planted id was restored: {o:?}"),
    };
    assert!(is_integrity(&e), "{e}");
    assert_eq!(tree(&root.join("vaults").join("victim")), victim);
    // And `/v1`'s addressed-vault check refuses it before anything is copied.
    let e = restore_archive(&mgr(root), &planted, Some(VAULT), true, &hash).unwrap_err();
    assert!(matches!(e, StoreError::Invalid(_)), "{e}");
    assert_no_stage(root, "planted");
}

/// **`verify` is blind to an index; the restore is not.** A byte flipped in an
/// index page is found by measurement to pass `verify` in a scratch root (the
/// premise — `verify` reads no index) and fail `integrity_check`; the restore
/// refuses it as an integrity verdict.
#[test]
fn o268_a_corrupt_index_passes_verify_and_is_still_refused() {
    let dir = corpus(40);
    let root = dir.path();
    let (arch, _) = archive(root);
    let (page, page_size): (i64, i64) = {
        let c = crate::backup::open_immutable(&arch.join("vault.db")).unwrap();
        (
            c.query_row(
                "SELECT rootpage FROM sqlite_master WHERE name = 'idx_drawers_room'",
                [],
                |r| r.get(0),
            )
            .unwrap(),
            c.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap(),
        )
    };
    let mut found = None;
    for back in (100..page_size - 100).step_by(37) {
        let cand = copy_archive(&arch, &format!("o268-index-{back}"));
        let mut db = std::fs::read(cand.join("vault.db")).unwrap();
        db[((page - 1) * page_size + page_size - back) as usize] ^= 0x01;
        std::fs::write(cand.join("vault.db"), &db).unwrap();
        let bad_check = {
            let c = crate::backup::open_immutable(&cand.join("vault.db")).unwrap();
            let r: String = c
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))
                .unwrap();
            r != "ok"
        };
        let verifies = bad_check && {
            let scratch = TempDir::new().unwrap();
            std::fs::copy(root.join("master.key"), scratch.path().join("master.key")).unwrap();
            let to = vdir(scratch.path());
            std::fs::create_dir_all(&to).unwrap();
            for f in ["vault.db", "vault.json"] {
                std::fs::copy(cand.join(f), to.join(f)).unwrap();
            }
            VaultStore::open(mgr(scratch.path()).unlock(VAULT).unwrap())
                .ok()
                .and_then(|s| s.verify().ok())
                .is_some_and(|r| r.ok())
        };
        if verifies {
            found = Some(cand);
            break;
        }
        std::fs::remove_dir_all(&cand).unwrap();
    }
    let cand =
        found.expect("premise: a flipped index byte that verify passes and integrity_check fails");
    let live = tree(&vdir(root));
    let e = match restore_archive(&mgr(root), &cand, None, true, &hash) {
        Err(e) => e,
        Ok(o) => panic!("a corrupt index was restored: {o:?}"),
    };
    assert!(
        is_integrity(&e) && e.to_string().contains("integrity_check"),
        "{e}"
    );
    assert_eq!(tree(&vdir(root)), live);
    assert_no_stage(root, "index");
}

/// **A 1.6.1-shaped archive** — the directory copied as files while a writer
/// held the vault, so its committed frames are in the `-wal` — restores whole
/// (P1b's shape), and names the `-shm` it did not copy. The same archive
/// without its `-wal` is refused: the manifest is ahead of the rows.
#[test]
fn o268_a_legacy_archive_restores_with_the_frames_in_its_wal() {
    let dir = corpus(30);
    let root = dir.path();
    heat(root);
    let (height, head) = {
        // A second handle reads the hot state through the WAL.
        let s = VaultStore::open_read_only(
            VaultManager::open_as(root, None, Access::ReadOnly)
                .unwrap()
                .unlock_as(VAULT, Access::ReadOnly)
                .unwrap(),
            Box::new(HashEmbedder),
        )
        .unwrap();
        let (h, w) = s.chain_state().unwrap();
        (w, h)
    };
    let legacy = backups(root).join(format!("{VAULT}-2026-01-01T00-00-00Z"));
    std::fs::create_dir_all(&legacy).unwrap();
    for e in std::fs::read_dir(vdir(root)).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), legacy.join(e.file_name())).unwrap();
    }
    assert!(
        legacy.join("vault.db-wal").exists(),
        "premise: the archive carries a -wal"
    );
    let short = copy_archive(&legacy, "o268-no-wal");
    std::fs::remove_file(short.join("vault.db-wal")).unwrap();
    let _ = std::fs::remove_file(short.join("vault.db-shm"));

    // Into a fresh root holding the same key (the live one is held by the
    // leaked writer, which the hold would rightly refuse).
    let fresh = TempDir::new().unwrap();
    std::fs::copy(root.join("master.key"), fresh.path().join("master.key")).unwrap();
    let report = restored(restore_archive(
        &mgr(fresh.path()),
        &legacy,
        None,
        false,
        &hash,
    ));
    assert!(!report.replaced);
    assert_eq!(
        (report.writes, report.chain_head.as_str()),
        (height, head.as_str())
    );
    assert!(
        report.skipped.iter().any(|s| s == "vault.db-shm"),
        "the -shm is named, not copied: {:?}",
        report.skipped
    );
    assert_is_the_reported_state(fresh.path(), &report, "legacy -wal");

    let fresh2 = TempDir::new().unwrap();
    std::fs::copy(root.join("master.key"), fresh2.path().join("master.key")).unwrap();
    match restore_archive(&mgr(fresh2.path()), &short, None, false, &hash) {
        Err(e) => assert!(is_integrity(&e), "{e}"),
        Ok(RestoreOutcome::Refused(_)) => {}
        Ok(RestoreOutcome::Restored(r)) => panic!("an archive short of its -wal restored: {r:?}"),
    }
    assert!(!vdir(fresh2.path()).exists(), "nothing was restored");
}

/// **A committed rotation that was never promoted** — `vault.json` on the old
/// generation, `vault.json.next` on the new, the database's keycheck naming the
/// new — restores: the stage's open promotes, because the database proves the
/// rotation committed (O256 item 6's reason, refuted for restore). Without the
/// staged manifest the same archive is refused as another key generation.
#[test]
fn o268_an_archive_of_a_deferred_promote_restores_by_promoting_it() {
    let dir = corpus(20);
    let root = dir.path();
    {
        let m = mgr(root);
        let mut s = VaultStore::open(m.unlock(VAULT).unwrap()).unwrap();
        crate::rotate_pause::set(
            &vdir(root),
            Arc::new(|phase| {
                if phase == crate::rotate_pause::Phase::Committed {
                    fixture::fail_times(fixture::Fault::Rename, crate::rotate::PROMOTE_ATTEMPTS);
                }
            }),
        );
        let report = s.rotate_keys(m.rotation_candidate(VAULT).unwrap()).unwrap();
        assert!(
            report.promote_deferred.is_some(),
            "premise: the promote was deferred"
        );
    }
    assert!(
        vdir(root).join("vault.json.next").exists(),
        "premise: a staged manifest"
    );
    let arch = backups(root).join(format!("{VAULT}-2026-01-01T00-00-00Z"));
    std::fs::create_dir_all(&arch).unwrap();
    for f in ["vault.db", "vault.json", "vault.json.next"] {
        std::fs::copy(vdir(root).join(f), arch.join(f)).unwrap();
    }
    let without = copy_archive(&arch, "o268-no-next");
    std::fs::remove_file(without.join("vault.json.next")).unwrap();

    let fresh = TempDir::new().unwrap();
    std::fs::copy(root.join("master.key"), fresh.path().join("master.key")).unwrap();
    let report = restored(restore_archive(
        &mgr(fresh.path()),
        &arch,
        None,
        false,
        &hash,
    ));
    assert_is_the_reported_state(fresh.path(), &report, "deferred promote");
    assert!(
        !vdir(fresh.path()).join("vault.json.next").exists(),
        "promoted"
    );

    let fresh2 = TempDir::new().unwrap();
    std::fs::copy(root.join("master.key"), fresh2.path().join("master.key")).unwrap();
    match restore_archive(&mgr(fresh2.path()), &without, None, false, &hash) {
        Err(e) => assert!(is_integrity(&e), "{e}"),
        Ok(o) => panic!("an archive without its staged generation restored: {o:?}"),
    }
}

/// **A pre-1.5.0 database name** restores, renamed to `vault.db` by the stage's
/// open.
#[test]
fn o268_a_palace_db_archive_restores_under_the_current_name() {
    let dir = corpus(20);
    let root = dir.path();
    let (arch, created) = archive(root);
    let legacy = copy_archive(&arch, "o268-legacy-name");
    std::fs::rename(legacy.join("vault.db"), legacy.join("palace.db")).unwrap();
    let report = restored(restore_archive(&mgr(root), &legacy, None, true, &hash));
    assert_eq!(report.writes, created.writes);
    assert!(vdir(root).join("vault.db").exists() && !vdir(root).join("palace.db").exists());
    assert_is_the_reported_state(root, &report, "palace.db");
}

/// **A known migration of the built-in embedder is reported**, never silent:
/// the archive records `undercroft-hash-v2`, the stage's open migrates it.
#[test]
fn o268_a_re_recorded_embedder_is_reported() {
    let dir = corpus(20);
    let root = dir.path();
    let (arch, _) = archive(root);
    let old = copy_archive(&arch, "o268-hash-v2");
    {
        let c = rusqlite::Connection::open(old.join("vault.db")).unwrap();
        c.execute(
            "UPDATE meta SET value = 'undercroft-hash-v2' WHERE key = 'embedder_name'",
            [],
        )
        .unwrap();
    }
    let report = restored(restore_archive(&mgr(root), &old, None, true, &hash));
    assert_eq!(
        report.embedder_rerecorded.as_deref(),
        Some("undercroft-hash-v2@384 -> undercroft-hash-v3@384")
    );
    assert_is_the_reported_state(root, &report, "re-recorded");
}

/// **An archive older than a rotation brings the retired keys back, and says
/// so.**
#[test]
fn o268_restoring_across_a_rotation_reports_the_key_generation() {
    let dir = corpus(20);
    let root = dir.path();
    let (arch, _) = archive(root);
    {
        let m = mgr(root);
        let mut s = VaultStore::open(m.unlock(VAULT).unwrap()).unwrap();
        s.rotate_keys(m.rotation_candidate(VAULT).unwrap()).unwrap();
    }
    let report = restored(restore_archive(&mgr(root), &arch, None, true, &hash));
    assert_eq!(report.key_generation_differs, Some(true));
    assert_is_the_reported_state(root, &report, "across a rotation");
}

/// **`--read-only` refuses before any effect**: not a byte of the data directory moves,
/// and no step of the restore is reached — the stage's `Drop` would remove a
/// stage made by a refusal decided too late, so the end state alone cannot
/// tell "never made" from "made and cleaned up" (the counterfactual that moved
/// the check after the copy passed a tree comparison).
#[test]
fn o268_a_read_only_manager_refuses_and_writes_nothing() {
    let dir = corpus(20);
    let root = dir.path();
    let (arch, _) = archive(root);
    let before = tree(root);
    let reached: Arc<std::sync::Mutex<Vec<Phase>>> = Arc::default();
    let seen = reached.clone();
    pause::set(
        root,
        Arc::new(move |phase| seen.lock().unwrap().push(phase)),
    );
    let ro = VaultManager::open_as(root, None, Access::ReadOnly).unwrap();
    let e = restore_archive(&ro, &arch, None, true, &hash).unwrap_err();
    pause::set(root, Arc::new(|_| {}));
    assert!(
        matches!(e, StoreError::Vault(VaultError::ReadOnly(_))),
        "{e}"
    );
    assert_eq!(
        *reached.lock().unwrap(),
        Vec::<Phase>::new(),
        "no step was reached"
    );
    assert_eq!(tree(root), before);
}

/// **A vault another handle holds is refused after the archive verifies**, with
/// nothing changed and no restore area left; an existing vault is never
/// replaced without `force`; and a commit landing while the archive is staged is
/// simply replaced — a restore restores.
#[test]
fn o268_a_held_vault_is_refused_and_a_commit_during_staging_is_replaced() {
    let dir = corpus(20);
    let root = dir.path();
    let (arch, created) = archive(root);
    let e = restore_archive(&mgr(root), &arch, None, false, &hash).unwrap_err();
    assert!(
        matches!(e, StoreError::Invalid(ref m) if m.contains("--force")),
        "{e}"
    );

    let holder = open_at(root);
    let live = tree(&vdir(root));
    let e = restore_archive(&mgr(root), &arch, None, true, &hash).unwrap_err();
    assert!(matches!(e, StoreError::VaultHeld(_)), "{e}");
    assert_eq!(
        tree(&vdir(root)),
        live,
        "held: the live vault is byte-identical"
    );
    assert_no_stage(root, "held");
    drop(holder);

    let r = root.to_path_buf();
    pause::set(
        root,
        Arc::new(move |phase| {
            if phase == Phase::Staged {
                let mut s = open_at(&r);
                save(&mut s, 77);
            }
        }),
    );
    let report = restored(restore_archive(&mgr(root), &arch, None, true, &hash));
    pause::set(root, Arc::new(|_| {}));
    assert_eq!(
        report.writes, created.writes,
        "the staged-time commit is replaced"
    );
    assert_is_the_reported_state(root, &report, "commit during staging");
}

/// **The prune race**: an archive removed while the restore reads it fails the
/// copy — an ordinary failure, not a verdict — with the live vault unchanged and
/// no restore area left.
#[test]
fn o268_an_archive_pruned_mid_restore_changes_nothing() {
    let dir = corpus(20);
    let root = dir.path();
    let (arch, _) = archive(root);
    let live = tree(&vdir(root));
    let gone = arch.clone();
    pause::set(
        root,
        Arc::new(move |phase| {
            if phase == Phase::ArchiveRead {
                let _ = std::fs::remove_dir_all(&gone);
            }
        }),
    );
    let e = restore_archive(&mgr(root), &arch, None, true, &hash).unwrap_err();
    pause::set(root, Arc::new(|_| {}));
    assert!(!is_integrity(&e), "a race is not a verdict: {e}");
    assert_eq!(tree(&vdir(root)), live);
    assert_no_stage(root, "pruned");
}

/// **A failed move aside, or a failed move-in that puts the live vault back,
/// leaves it as it was** — quiescent, and with a dead writer's committed
/// frames in its `-wal`, where only the hold's checkpoint-on-close being off
/// keeps its close from folding them into `vault.db` (ROADMAP O268, R1). The
/// one trace a quiescent vault keeps is the empty `-wal` the hold's own open
/// made, stated as a residual.
#[test]
fn o268_a_failed_move_leaves_the_live_vault_as_it_was() {
    for hot in [false, true] {
        for fault in [fixture::Fault::SwapAside, fixture::Fault::SwapIn] {
            let label = format!("{fault:?} hot={hot}");
            let dir = corpus(20);
            let root = dir.path();
            let (arch, _) = archive(root);
            {
                let mut s = open_at(root);
                save(&mut s, 5);
            }
            if hot {
                heat(root);
            }
            let files = |root: &Path| {
                let mut t = tree(&vdir(root));
                if !hot && t.get("vault.db-wal").is_some_and(|b| b.is_empty()) {
                    t.remove("vault.db-wal");
                }
                t
            };
            let live = files(root);
            pause::set(
                root,
                Arc::new(move |phase| {
                    if phase == Phase::Held {
                        fixture::fail_next(fault);
                    }
                }),
            );
            let e = restore_archive(&mgr(root), &arch, None, true, &hash).unwrap_err();
            pause::set(root, Arc::new(|_| {}));
            assert!(!is_integrity(&e), "{label}: {e}");
            assert!(
                e.to_string().contains("nothing was restored")
                    || e.to_string().contains("put back unchanged"),
                "{label}: the error says the live vault is intact: {e}"
            );
            assert_eq!(
                files(root),
                live,
                "{label}: the live vault is byte-identical"
            );
            assert_no_stage(root, &label);
        }
    }
}

/// **A swap that fails is legible and never loses a vault.** When the move-in
/// fails and putting the live vault back fails too — the state a crash between
/// the renames leaves —
/// the error names both directories, `create`, `init` and another restore all
/// refuse while the aside exists, nothing that lists vaults sees the restore
/// area, and moving the aside back yields the original vault.
#[test]
fn o268_a_failed_swap_never_loses_a_vault() {
    let dir = corpus(20);
    let root = dir.path();
    let (arch, _) = archive(root);
    {
        let mut s = open_at(root);
        save(&mut s, 5);
    }
    let original = open_at(root).chain_state().unwrap();

    // The move-in fails AND the move back fails: the state a crash between the
    // two renames leaves — the live vault aside, the verified stage beside it,
    // `vaults/<id>` vacant. Both are kept and both are named.
    pause::set(
        root,
        Arc::new(|phase| {
            if phase == Phase::Held {
                fixture::fail_in_turn(fixture::Fault::SwapIn, fixture::Fault::SwapBack);
            }
        }),
    );
    let e = restore_archive(&mgr(root), &arch, None, true, &hash).unwrap_err();
    pause::set(root, Arc::new(|_| {}));
    let area = root.join("vaults").join(RESTORE_ROOT);
    let aside = {
        use sha2::{Digest, Sha256};
        area.join(format!(
            "aside-{}",
            hex::encode(Sha256::digest(VAULT.as_bytes()))
        ))
    };
    let said = e.to_string();
    assert!(!is_integrity(&e), "{said}");
    assert!(
        said.contains(&aside.display().to_string()) && said.contains("stage-"),
        "the error names both directories: {said}"
    );
    assert!(aside.exists(), "the vault that was live is kept");
    assert!(
        !vdir(root).exists(),
        "premise: the crash state, `vaults/<id>` vacant"
    );
    let e = mgr(root).create(VAULT, SecurityLevel::Sealed).unwrap_err();
    assert!(
        matches!(e, VaultError::RestoreInterrupted { .. }),
        "create: {e}"
    );
    assert!(
        e.to_string().contains("mv "),
        "the refusal names the fix: {e}"
    );
    let e = restore_archive(&mgr(root), &arch, None, true, &hash).unwrap_err();
    assert!(
        matches!(e, StoreError::Vault(VaultError::RestoreInterrupted { .. })),
        "restore: {e}"
    );
    assert!(
        mgr(root).list().unwrap().is_empty(),
        "no vault, and never the restore area"
    );
    std::fs::rename(&aside, vdir(root)).unwrap();
    assert_eq!(
        open_at(root).chain_state().unwrap(),
        original,
        "the aside is the original"
    );
    assert!(open_at(root).verify().unwrap().ok());
}

/// **What a restore costs at ~10^5** (ROADMAP O268's gate): the time in each
/// step — the copy into the stage, the stage's unlock + open + verify +
/// `integrity_check`, the close and post-condition, the hold, the swap — and
/// the disk it needs beside the live vault. Run by name; it builds (or reuses)
/// O256's 102,000-drawer sealed corpus in the target volume.
#[test]
#[ignore = "ROADMAP O268 cost at ~10^5; run by name with --ignored (O268_CORPUS, O268_VAULT)"]
fn o268_cost_of_a_restore_at_scale() {
    let corpus_dir =
        PathBuf::from(std::env::var("O268_CORPUS").unwrap_or_else(|_| "/build/o256-corpus".into()));
    let id = std::env::var("O268_VAULT").unwrap_or_else(|_| "o256".into());
    let drawers: usize = std::env::var("O268_DRAWERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(102_000);
    let live = |root: &Path| root.join("vaults").join(&id);
    if !live(&corpus_dir).join("vault.db").exists() {
        std::fs::create_dir_all(&corpus_dir).unwrap();
        let m = mgr(&corpus_dir);
        let mut s = VaultStore::open(m.create(&id, SecurityLevel::Sealed).unwrap()).unwrap();
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
    let root = work.path().to_path_buf();
    std::fs::create_dir_all(live(&root)).unwrap();
    std::fs::copy(corpus_dir.join("master.key"), root.join("master.key")).unwrap();
    for f in ["vault.db", "vault.json"] {
        std::fs::copy(live(&corpus_dir).join(f), live(&root).join(f)).unwrap();
    }
    let s = VaultStore::open(mgr(&root).unlock(&id).unwrap()).unwrap();
    let t = std::time::Instant::now();
    assert!(s.verify().unwrap().ok());
    let verify_ms = t.elapsed().as_secs_f64() * 1e3;
    let report = match s.backup(&backups(&root)).unwrap() {
        BackupOutcome::Created(r) => r,
        BackupOutcome::Refused(r) => panic!("premise: the corpus verifies ({r:?})"),
    };
    drop(s);
    let arch = backups(&root).join(&report.name);
    let archive_bytes: u64 = std::fs::read_dir(&arch)
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .sum();
    let check_ms = {
        let c = crate::backup::open_immutable(&arch.join("vault.db")).unwrap();
        let t = std::time::Instant::now();
        let r: String = c
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(r, "ok");
        t.elapsed().as_secs_f64() * 1e3
    };
    let area = root.join("vaults").join(RESTORE_ROOT);
    let marks: Arc<std::sync::Mutex<Vec<(Phase, std::time::Instant, u64)>>> = Arc::default();
    {
        let (marks, area) = (marks.clone(), area.clone());
        pause::set(
            &root,
            Arc::new(move |p| {
                let staged: u64 = walk_size(&area);
                marks
                    .lock()
                    .unwrap()
                    .push((p, std::time::Instant::now(), staged));
            }),
        );
    }
    for round in 0..3 {
        marks.lock().unwrap().clear();
        let t = std::time::Instant::now();
        let r = restored(restore_archive(&mgr(&root), &arch, None, true, &hash));
        let end = std::time::Instant::now();
        let total = t.elapsed().as_secs_f64() * 1e3;
        let m = marks.lock().unwrap().clone();
        let at = |p: Phase| {
            m.iter()
                .find(|(q, _, _)| *q == p)
                .map(|(_, t, s)| (*t, *s))
                .unwrap()
        };
        let ms =
            |a: std::time::Instant, b: std::time::Instant| b.duration_since(a).as_secs_f64() * 1e3;
        let (read, _) = at(Phase::ArchiveRead);
        let (staged, stage_bytes) = at(Phase::Staged);
        let (verified, peak) = at(Phase::Verified);
        let (closed, _) = at(Phase::Closed);
        let (held, _) = at(Phase::Held);
        println!(
            "O268_COST round {round}: restore {total:.0} ms — copy {:.0}, unlock+open+verify+check \
             {:.0}, close+post-condition {:.0}, hold {:.0}, swap {:.0}; stage {} B after the \
             copy, {} B at its peak; restored height {}",
            ms(read, staged),
            ms(staged, verified),
            ms(verified, closed),
            ms(closed, held),
            ms(held, end),
            stage_bytes,
            peak,
            r.writes
        );
    }
    pause::set(&root, Arc::new(|_| {}));
    println!(
        "O268_COST corpus: {drawers} drawers, archive {archive_bytes} B; verify alone \
         {verify_ms:.0} ms, integrity_check alone {check_ms:.0} ms"
    );
}

fn walk_size(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| {
            let m = e.metadata().unwrap();
            if m.is_dir() {
                walk_size(&e.path())
            } else {
                m.len()
            }
        })
        .sum()
}
