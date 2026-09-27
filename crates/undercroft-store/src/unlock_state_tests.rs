//! ROADMAP O284: a handle never carries unlock-era state about a vault
//! directory other than the one its open proved.
//!
//! The unlock reads `vault.json.next` by path before any connection exists,
//! and a `backup restore` landing between the unlock and the open left a
//! handle on the RESTORED database carrying the SET-ASIDE vault's notes. The
//! store's open now compares the digest of what the unlock read with the file
//! there, after O279's door has proved the database, and derives the read-only
//! legacy-name note from the file its connector opened.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use tempfile::TempDir;
use undercroft_core::embed::Embedder;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{Access, SecurityLevel, Unhealed, Vault, VaultManager};

use crate::{restore_archive, BackupOutcome, RestoreOutcome, StoreError, VaultStore};

const VAULT: &str = "o284";

fn hash(_: &Vault) -> Result<Box<dyn Embedder + Send>, StoreError> {
    Ok(Box::new(HashEmbedder))
}

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

/// A sealed vault of `n` drawers and its archive, taken before anything else.
fn vault_with_archive(n: usize) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    {
        let mut s =
            VaultStore::open(mgr(root).create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
        s.upsert_many(&drawers(n, "note")).unwrap();
    }
    let s = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
    let arch = match s.backup(&root.join("backups")).unwrap() {
        BackupOutcome::Created(r) => root.join("backups").join(r.name),
        BackupOutcome::Refused(r) => panic!("premise: the vault verifies ({r:?})"),
    };
    (dir, arch)
}

fn restore(root: &Path, arch: &Path) {
    match restore_archive(&mgr(root), arch, None, true, &hash) {
        Ok(RestoreOutcome::Restored(_)) => {}
        other => panic!("premise: the restore ran ({:?})", other.err()),
    }
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

fn torn_note(notes: &[String]) -> bool {
    notes.iter().any(|n| n.contains("vault.json.next"))
}

/// **G1 — P12b, inverted, on both postures.** A torn `vault.json.next` in the
/// live vault, an archive taken before it, a restore between the unlock and
/// the open: the open is refused with the reopen class, and a fresh open
/// serves the restored rows carrying no note about the `.next` the vault set
/// aside held.
#[test]
fn o284_a_restore_after_the_unlock_leaves_no_note_about_the_vault_set_aside() {
    for read_only in [false, true] {
        let (dir, arch) = vault_with_archive(100);
        let root = dir.path();
        std::fs::write(vdir(root).join("vault.json.next"), b"{ torn").unwrap();
        let v = unlock(root, read_only);
        assert!(
            v.unhealed().contains(&Unhealed::TornStagingManifest),
            "premise: the unlock found the torn file (read_only={read_only})"
        );
        restore(root, &arch);
        assert!(
            !vdir(root).join("vault.json.next").exists(),
            "premise: the restored vault holds no .next"
        );
        match open(v, read_only) {
            Err(StoreError::StaleUnlock(m)) => assert!(m.contains("ROADMAP O284"), "{m}"),
            Err(e) => panic!("read_only={read_only}: the wrong refusal: {e}"),
            Ok(s) => panic!(
                "read_only={read_only}: served with the unlock's notes {:?}",
                s.unhealed()
            ),
        }
        let s = open(unlock(root, read_only), read_only).expect("the reopen");
        assert_eq!(s.count().unwrap(), 100, "the restored rows");
        assert!(!torn_note(s.unhealed()), "{:?}", s.unhealed());
    }
}

/// **G2 — the negative control.** A restore with no `.next` on either side,
/// between the unlock and the open, is served at once: equal digests (`None`
/// and `None`) are the same inputs, so the notes are true of the restored
/// vault and there is nothing to refuse.
#[test]
fn o284_a_restore_with_no_staging_file_on_either_side_is_served_at_once() {
    for read_only in [false, true] {
        let (dir, arch) = vault_with_archive(60);
        let root = dir.path();
        {
            let mut s = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
            s.upsert_many(&drawers(10, "later")).unwrap();
        }
        let v = unlock(root, read_only);
        restore(root, &arch);
        let s = open(v, read_only).expect("served on the first attempt");
        assert_eq!(
            s.count().unwrap(),
            60,
            "the restored rows, not the 70 replaced"
        );
        assert!(s.verify().unwrap().ok());
    }
}

/// **G3 — the read-only legacy-name note follows the file the connector
/// opened.** The one note the `.next` comparison cannot reach: a pre-1.5.0
/// vault unlocked read-only, then restored from an archive under the current
/// name, is served from `vault.db` and says nothing about `palace.db`.
#[test]
fn o284_the_read_only_legacy_note_describes_the_file_it_opened() {
    let (dir, arch) = vault_with_archive(40);
    let root = dir.path();
    let vd = vdir(root);
    {
        let c = rusqlite::Connection::open(vd.join("vault.db")).unwrap();
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
    let v = unlock(root, true);
    assert!(
        v.unhealed().contains(&Unhealed::LegacyDatabaseName),
        "premise: the unlock saw the legacy name"
    );
    restore(root, &arch);
    assert!(vd.join("vault.db").exists() && !vd.join("palace.db").exists());
    let s = open(v, true).expect("served: no staging file changed");
    assert_eq!(s.count().unwrap(), 40);
    assert!(
        !s.unhealed()
            .iter()
            .any(|n| n.contains("still named palace.db")),
        "a handle on vault.db says the vault is still palace.db: {:?}",
        s.unhealed()
    );
    // And a read-only open that really opens `palace.db` still says so.
    drop(s);
    std::fs::rename(vd.join("vault.db"), vd.join("palace.db")).unwrap();
    for f in ["vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(vd.join(f));
    }
    let s = open(unlock(root, true), true).unwrap();
    assert!(
        s.unhealed()
            .iter()
            .any(|n| n.contains("still named palace.db")),
        "{:?}",
        s.unhealed()
    );
}

/// **G4 — a busy writer never trips it.** Fifty read-only opens beside a
/// writer anchoring in a loop, with a torn `.next` in the directory the whole
/// time: an anchor rewrites `vault.json`, never `.next`, so none is refused.
#[test]
fn o284_opens_beside_a_writer_anchoring_in_a_loop_are_never_refused() {
    let (dir, _) = vault_with_archive(30);
    let root = dir.path().to_path_buf();
    std::fs::write(vdir(&root).join("vault.json.next"), b"{ torn").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let written = Arc::new(AtomicU32::new(0));
    let writer = {
        let (r, stop, written) = (root.clone(), stop.clone(), written.clone());
        std::thread::spawn(move || {
            let mut s = VaultStore::open(mgr(&r).unlock(VAULT).unwrap()).unwrap();
            let mut i = 0u32;
            while !stop.load(Ordering::SeqCst) {
                s.upsert(&Drawer::new(
                    "w9",
                    "r",
                    format!("a write beside the opens {i}"),
                    Some("busy.md".into()),
                    i,
                    "t",
                ))
                .unwrap();
                i += 1;
                written.store(i, Ordering::SeqCst);
            }
            i
        })
    };
    while written.load(Ordering::SeqCst) == 0 {
        std::thread::yield_now();
    }
    let before = written.load(Ordering::SeqCst);
    let mut refused = Vec::new();
    // At least fifty opens, and until the writer has anchored at least three
    // times WHILE they ran — a fixed fifty finished inside one write on a
    // quiet machine and proved no overlap at all. Bounded.
    let started = std::time::Instant::now();
    let mut opens = 0;
    while opens < 50 || written.load(Ordering::SeqCst) - before < 3 {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "the writer made {} writes in 60 s of opens",
            written.load(Ordering::SeqCst) - before
        );
        match open(unlock(&root, true), true) {
            Ok(_) => {}
            Err(StoreError::StaleUnlock(m)) => refused.push(m),
            Err(e) => panic!("an open beside the writer failed otherwise: {e}"),
        }
        opens += 1;
    }
    let during = written.load(Ordering::SeqCst) - before;
    stop.store(true, Ordering::SeqCst);
    let writes = writer.join().unwrap();
    assert!(writes > 0);
    assert!(
        during > 0,
        "premise: the writer anchored WHILE the opens ran ({during} writes then)"
    );
    assert!(
        refused.is_empty(),
        "{} of {opens} refused: {:?}",
        refused.len(),
        refused.first()
    );
}

/// **G5 — a staging file gone between the unlock and the open with no restore
/// at all** is refused the same way: the unlock's note described a file that
/// is gone. No open removes a torn `.next` (O257); a person or another tool
/// does, and a rotation's promote or discard settles a valid one the same way.
#[test]
fn o284_a_staging_file_removed_after_the_unlock_is_refused_and_reopens() {
    let (dir, _) = vault_with_archive(20);
    let root = dir.path();
    std::fs::write(vdir(root).join("vault.json.next"), b"{ torn").unwrap();
    let v = unlock(root, true);
    assert!(v.unhealed().contains(&Unhealed::TornStagingManifest));
    std::fs::remove_file(vdir(root).join("vault.json.next")).unwrap();
    assert!(matches!(open(v, true), Err(StoreError::StaleUnlock(_))));
    let s = open(unlock(root, true), true).unwrap();
    assert!(!torn_note(s.unhealed()));
}
