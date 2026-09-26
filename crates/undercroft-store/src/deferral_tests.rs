//! ROADMAP O266: a handle whose keys came from `vault.json.next` — a read-only
//! open that adopted a committed rotation in memory, or the rotating handle
//! after its own promote failed every attempt — verifies against the STAGED
//! manifest while the disk still shows that state, and answers exactly what a
//! fresh open over the same files answers once it does not. The rotating
//! handle stops writing, with the reopen class, before anything commits.
//!
//! Every read arm is driven from a label-guard MISS: a cached verdict serves
//! a read without asking the manifest anything, so an arm that hit the cache
//! would pass on the unfixed tree.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;
use undercroft_core::embed::Embedder;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{fixture, Access, SecurityLevel, Vault, VaultError, VaultManager};

use crate::forget::{AttestationVerdict, ForgetAttestation};
use crate::rotate_pause as pause;
use crate::{
    restore_archive, BackupOutcome, Read, ReadOp, RestoreOutcome, SearchOptions, StoreError,
    VaultStore,
};

const VAULT: &str = "o266";
const LEVELS: [SecurityLevel; 2] = [SecurityLevel::HmacOnly, SecurityLevel::Sealed];
const KEPT: &str = "the harbour keeper logs the lighthouse lamp at dusk";
const QUERY: &str = "harbour keeper lighthouse";

fn drawer(content: &str, idx: u32) -> Drawer {
    Drawer::new(
        "w",
        "r",
        content.into(),
        Some("o266.md".into()),
        idx,
        "test",
    )
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

fn bytes(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

fn hash(_: &Vault) -> Result<Box<dyn Embedder + Send>, StoreError> {
    Ok(Box::new(HashEmbedder))
}

fn read_only(root: &Path) -> Result<VaultStore, StoreError> {
    let m = VaultManager::open_as(root, None, Access::ReadOnly)?;
    VaultStore::open_read_only(
        m.unlock_as(VAULT, Access::ReadOnly)?,
        Box::new(HashEmbedder),
    )
}

fn writable(root: &Path) -> VaultStore {
    VaultStore::open(
        VaultManager::open(root, None)
            .unwrap()
            .unlock(VAULT)
            .unwrap(),
    )
    .unwrap()
}

/// The class a surface would give a refusal, which is what the arms compare:
/// `ManifestTampered` and the integrity class BOTH exit 2, so a refusal
/// asserted without its class passes for the wrong verdict.
fn class(e: &StoreError) -> &'static str {
    match e {
        StoreError::Vault(VaultError::ManifestTampered) => "tampered",
        StoreError::Vault(VaultError::CorruptManifest(_)) | StoreError::IntegrityFinding(_) => {
            "integrity"
        }
        StoreError::Vault(VaultError::NotFound(_)) => "not-found",
        _ => "other",
    }
}

/// A vault whose rotation COMMITTED and whose promote failed every attempt,
/// through the vault crate's fault seam — the rotating handle still open, and
/// an erasure receipt minted before the rotation.
struct Deferred {
    dir: TempDir,
    rotating: VaultStore,
    receipt: ForgetAttestation,
    kept: String,
}

fn deferred(level: SecurityLevel, warm: bool) -> Deferred {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let m = VaultManager::open(root, None).unwrap();
    let mut s = VaultStore::open(m.create(VAULT, level).unwrap()).unwrap();
    let kept = drawer(KEPT, 0);
    s.upsert(&kept).unwrap();
    for i in 1..5 {
        s.upsert(&drawer(
            &format!("harbour ledger entry {i}: cargo landed"),
            i,
        ))
        .unwrap();
    }
    let doomed = drawer("a note the subject asked us to erase", 9);
    s.upsert(&doomed).unwrap();
    let mut receipt = s
        .forget_with_proof(std::slice::from_ref(&doomed.id))
        .unwrap();
    let (secret, _) = undercroft_vault::bundle::sign_keygen();
    receipt.sign(&secret).unwrap();
    if warm {
        s.search(QUERY, &SearchOptions::default()).unwrap();
        assert!(s.replays() >= 1, "premise: the label guard is warm");
    }
    pause::set(
        &vdir(root),
        Arc::new(|phase| {
            if phase == pause::Phase::Committed {
                fixture::fail_times(fixture::Fault::Rename, crate::rotate::PROMOTE_ATTEMPTS);
            }
        }),
    );
    let report = s.rotate_keys(m.rotation_candidate(VAULT).unwrap()).unwrap();
    pause::set(&vdir(root), Arc::new(|_| {}));
    assert!(
        report.promote_deferred.is_some(),
        "premise: the promote was deferred"
    );
    assert!(staging(root).exists(), "premise: vault.json.next is staged");
    assert!(
        !s.vault.manifest_on_disk_is_mine(),
        "premise: vault.json is still the retired generation's"
    );
    Deferred {
        dir,
        rotating: s,
        receipt,
        kept: kept.id,
    }
}

/// **The filing's gate.** A read-only open over a deferred promote opens,
/// names the deferral, serves reads verbatim, verifies, emits a witness whose
/// anchor is the staged manifest's — which is the committed head — reports no
/// lag, answers a receipt minted before the rotation as `Recorded`, and
/// leaves every file as it found it. Before O266 it refused `ManifestTampered`
/// at open (exit 2).
#[test]
fn o266_a_read_only_open_over_a_deferred_promote_verifies_against_the_staged_manifest() {
    for level in LEVELS {
        let Deferred {
            dir,
            rotating,
            receipt,
            kept,
        } = deferred(level, false);
        let root = dir.path();
        let (head, writes) = rotating.chain_state().unwrap();
        drop(rotating);
        let files = || {
            (
                bytes(&manifest(root)),
                bytes(&staging(root)),
                bytes(&vdir(root).join("vault.db")),
            )
        };
        let before = files();
        let r = read_only(root).unwrap_or_else(|e| {
            panic!("{level:?}: a read-only open over a deferred promote must open: {e}")
        });
        assert!(
            r.unhealed()
                .iter()
                .any(|n| n.contains("O266") && n.contains("staged manifest")),
            "{level:?}: the deferral is named: {:?}",
            r.unhealed()
        );
        assert_eq!(
            r.replays(),
            0,
            "premise: the open replayed nothing — the staged anchor is current"
        );
        let hits = r.search(QUERY, &SearchOptions::default()).unwrap();
        assert_eq!(
            r.replays(),
            1,
            "{level:?}: the first guarded read missed and replayed against the staged anchor"
        );
        assert!(
            hits.iter().any(|h| h.drawer.content == KEPT),
            "{level:?}: verbatim"
        );
        let got = r
            .get(&kept, Read::Returned(ReadOp::Get))
            .unwrap()
            .expect("the drawer");
        assert_eq!(got.content, KEPT);
        let report = r.verify().unwrap();
        assert!(report.ok(), "{level:?}: {report:?}");
        let witness = r.witness_emit().unwrap();
        assert_eq!(witness.anchored_head, head, "{level:?}: the staged anchor");
        assert_eq!(witness.head, head);
        let stats = r.stats().unwrap();
        assert_eq!(stats.anchor_lag, Some(0), "{level:?}");
        assert_eq!(stats.writes, writes);
        assert_eq!(
            r.verify_forget_attestation(&receipt).unwrap(),
            AttestationVerdict::Recorded { rotations_since: 1 },
            "{level:?}: a receipt minted before the rotation"
        );
        drop(r);
        assert_eq!(files(), before, "{level:?}: the open touched nothing");
    }
}

/// **Mid-life, from a miss.** A long-lived read-only handle whose cache a
/// foreign commit invalidates replays against the staged anchor and serves.
#[test]
fn o266_a_long_lived_read_only_handle_serves_after_a_foreign_commit_forces_a_miss() {
    let d = deferred(SecurityLevel::Sealed, false);
    let root = d.dir.path();
    drop(d.rotating);
    let r = read_only(root).unwrap();
    r.search(QUERY, &SearchOptions::default()).unwrap();
    let n = r.replays();
    let raw = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
    raw.execute(
        "INSERT INTO meta (key, value) VALUES ('o266-foreign', 'x')",
        [],
    )
    .unwrap();
    drop(raw);
    let hits = r.search(QUERY, &SearchOptions::default()).unwrap();
    assert_eq!(
        r.replays(),
        n + 1,
        "premise: the foreign commit forced a miss"
    );
    assert!(hits.iter().any(|h| h.drawer.content == KEPT));
    assert!(r.verify().unwrap().ok());
}

#[derive(Debug, Clone, Copy)]
enum Break {
    FlipManifest,
    DropStaged,
    EditStaged,
    DropBoth,
}

/// Change one hex digit of a manifest's MAC, keeping it valid JSON.
fn flip_mac(path: &Path) {
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mac = v["manifest_mac_hex"].as_str().unwrap().to_string();
    let first = if mac.starts_with('0') { '1' } else { '0' };
    v["manifest_mac_hex"] = format!("{first}{}", &mac[1..]).into();
    std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

fn apply(root: &Path, how: Break) {
    match how {
        Break::FlipManifest => flip_mac(&manifest(root)),
        Break::DropStaged => std::fs::remove_file(staging(root)).unwrap(),
        Break::EditStaged => flip_mac(&staging(root)),
        Break::DropBoth => {
            std::fs::remove_file(staging(root)).unwrap();
            std::fs::remove_file(manifest(root)).unwrap();
        }
    }
}

/// **The refusals, on a LIVE handle and on a FRESH open, classes compared.**
/// A `vault.json` no generation's MAC verifies is the tamper verdict on both.
/// A lost or edited `.next` beside the retired `vault.json` is the integrity
/// verdict with no tamper event — what a fresh open answers through
/// `settle_foreign_keycheck`. With both files gone the live handle answers
/// integrity and a fresh open `NotFound` (stated in the ruling).
#[test]
fn o266_a_broken_deferral_refuses_as_a_fresh_open_would_on_a_live_handle() {
    for (how, live, fresh) in [
        (Break::FlipManifest, "tampered", "tampered"),
        (Break::DropStaged, "integrity", "integrity"),
        (Break::EditStaged, "integrity", "integrity"),
        (Break::DropBoth, "integrity", "not-found"),
    ] {
        for level in LEVELS {
            let d = deferred(level, false);
            let root = d.dir.path();
            drop(d.rotating);
            let r = read_only(root).unwrap();
            assert!(r.verify().unwrap().ok(), "premise: {how:?} {level:?}");
            apply(root, how);
            let e = r.verify().expect_err("a broken deferral must refuse");
            assert_eq!(class(&e), live, "{how:?} {level:?}, live: {e}");
            let e = r
                .witness_emit()
                .expect_err("the witness reads the same anchor");
            assert_eq!(class(&e), live, "{how:?} {level:?}, live witness: {e}");
            drop(r);
            match read_only(root) {
                Ok(_) => panic!("{how:?} {level:?}: a fresh open served a broken deferral"),
                Err(e) => assert_eq!(class(&e), fresh, "{how:?} {level:?}, fresh: {e}"),
            }
        }
    }
}

/// **A promote racing the rule's two reads is followed, never refused.** The
/// hook runs between `.next`'s read and `vault.json`'s, and a writable open
/// promotes there; then another handle writes and anchors, and the long-lived
/// read-only handle follows that anchor. Read the other way round, the second
/// read would find `.next` gone beside a `vault.json` it had already judged
/// retired — a false integrity verdict beside a legitimate promote.
#[test]
fn o266_a_promote_racing_the_two_reads_is_followed_not_refused() {
    let d = deferred(SecurityLevel::Sealed, false);
    let root = d.dir.path().to_path_buf();
    drop(d.rotating);
    let r = read_only(&root).unwrap();
    let promoter = root.clone();
    fixture::between_manifest_reads(move || drop(writable(&promoter)));
    let report = r.verify().unwrap();
    assert!(report.ok(), "{report:?}");
    assert!(
        !staging(&root).exists(),
        "premise: the promote landed between the two reads"
    );
    writable(&root)
        .upsert(&drawer("written after the promote", 20))
        .unwrap();
    let (head, _) = r.chain_state().unwrap();
    assert!(r.verify().unwrap().ok());
    assert_eq!(r.witness_emit().unwrap().anchored_head, head);
    assert_eq!(r.stats().unwrap().anchor_lag, Some(0));
}

/// **No latch** (O254 item 2): the exact retired `vault.json` and the old
/// `.next`, put back after a promote and a write, are served by the live
/// handle as a fresh open serves them — with the lag reported, not refused.
#[test]
fn o266_no_latch_a_restored_deferred_pair_is_served_with_its_lag() {
    let d = deferred(SecurityLevel::Sealed, false);
    let root = d.dir.path();
    drop(d.rotating);
    let (retired, staged) = (
        bytes(&manifest(root)).unwrap(),
        bytes(&staging(root)).unwrap(),
    );
    let r = read_only(root).unwrap();
    assert!(r.verify().unwrap().ok());
    writable(root)
        .upsert(&drawer("written after the promote", 21))
        .unwrap();
    assert!(!staging(root).exists(), "premise: promoted");
    assert!(
        r.verify().unwrap().ok(),
        "premise: the promoted manifest is followed"
    );
    std::fs::write(manifest(root), &retired).unwrap();
    std::fs::write(staging(root), &staged).unwrap();
    let report = r.verify().unwrap();
    assert!(report.ok(), "{report:?}");
    assert_eq!(r.stats().unwrap().anchor_lag, Some(1));
    let fresh = read_only(root).unwrap();
    assert!(fresh.verify().unwrap().ok());
    assert_eq!(fresh.stats().unwrap().anchor_lag, Some(1));
    assert!(
        fresh.unhealed().iter().any(|n| n.contains("behind")),
        "{:?}",
        fresh.unhealed()
    );
}

/// **The rotating handle**, its label guard WARMED before the rotation: its
/// first read afterwards misses (the rotation reset the verdict it cached),
/// it serves and verifies against the staged manifest, and every write door
/// refuses with the reopen class before anything commits — where its first
/// write used to commit past the staged anchor and then retire the handle as
/// an integrity finding. A later writable open promotes, with no heal.
#[test]
fn o266_the_rotating_handle_reads_the_staged_manifest_and_stops_writing_before_a_commit() {
    for level in LEVELS {
        let d = deferred(level, true);
        let root = d.dir.path();
        let mut s = d.rotating;
        let n = s.replays();
        let hits = s.search(QUERY, &SearchOptions::default()).unwrap();
        assert_eq!(
            s.replays(),
            n + 1,
            "{level:?}: the rotation's reset made the next read a miss"
        );
        assert!(hits.iter().any(|h| h.drawer.content == KEPT));
        assert!(s.verify().unwrap().ok(), "{level:?}");
        assert_eq!(s.stats().unwrap().anchor_lag, Some(0));
        let chain = s.chain_state().unwrap();
        let keycheck = |s: &VaultStore| -> String {
            s.conn
                .query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
                    r.get(0)
                })
                .unwrap()
        };
        let marker = keycheck(&s);
        let on_disk = (bytes(&manifest(root)), bytes(&staging(root)));
        match s.upsert(&drawer("a write after the deferral", 30)) {
            Err(StoreError::StaleUnlock(m)) => assert!(m.contains("O266"), "{m}"),
            other => panic!("{level:?}: a write after the deferral: {other:?}"),
        }
        assert_eq!(
            s.chain_state().unwrap(),
            chain,
            "{level:?}: nothing committed"
        );
        assert_eq!(keycheck(&s), marker);
        match s.tighten_anchor() {
            Err(StoreError::StaleUnlock(_)) => {}
            other => panic!("{level:?}: tighten_anchor on a deferred handle: {other:?}"),
        }
        let m = VaultManager::open(root, None).unwrap();
        match s.rotate_keys(m.rotation_candidate(VAULT).unwrap()) {
            Err(StoreError::StaleUnlock(_)) => {}
            other => panic!("{level:?}: a second rotation on a deferred handle: {other:?}"),
        }
        assert_eq!(
            (bytes(&manifest(root)), bytes(&staging(root))),
            on_disk,
            "{level:?}: nothing moved on disk"
        );
        drop(s);
        let w = writable(root);
        assert!(
            !staging(root).exists(),
            "the next writable open promoted it"
        );
        assert!(w.verify().unwrap().ok());
        assert!(
            !w.unhealed().iter().any(|n| n.contains("behind")),
            "{level:?}: no row committed past the staged anchor: {:?}",
            w.unhealed()
        );
    }
}

/// **A backup of a deferral carries the manifest its rows answer to**
/// (O256 item 3, refined): exactly two files, the archive's `vault.json`
/// byte-identical to `.next`, and it restores into a fresh root that
/// verifies. With `.next` lost the backup refuses and publishes nothing.
#[test]
fn o266_a_read_only_backup_of_a_deferral_archives_the_staged_manifest_and_restores() {
    let d = deferred(SecurityLevel::Sealed, false);
    let root = d.dir.path();
    drop(d.rotating);
    let r = read_only(root).unwrap();
    let staged = bytes(&staging(root)).unwrap();
    let backups = root.join("backups");
    let report = match r.backup(&backups).unwrap() {
        BackupOutcome::Created(report) => report,
        BackupOutcome::Refused(v) => panic!("a verified deferral was refused: {v:?}"),
    };
    assert!(report.promote_deferred);
    assert_eq!(report.anchor_behind_by, 0);
    let archive = backups.join(&report.name);
    let mut names: Vec<String> = std::fs::read_dir(&archive)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["vault.db", "vault.json"]);
    assert_eq!(
        std::fs::read(archive.join("vault.json")).unwrap(),
        staged,
        "the archive's manifest IS the staged bytes"
    );
    let fresh = TempDir::new().unwrap();
    std::fs::copy(root.join("master.key"), fresh.path().join("master.key")).unwrap();
    match restore_archive(
        &VaultManager::open(fresh.path(), None).unwrap(),
        &archive,
        None,
        false,
        &hash,
    )
    .unwrap()
    {
        RestoreOutcome::Restored(_) => {}
        RestoreOutcome::Refused(v) => panic!("the archive of a deferral did not restore: {v:?}"),
    }
    assert!(writable(fresh.path()).verify().unwrap().ok());

    let archives = || {
        std::fs::read_dir(&backups)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name() != ".staging")
            .count()
    };
    let published = archives();
    std::fs::remove_file(staging(root)).unwrap();
    match r.backup(&backups) {
        Err(e) => assert_eq!(class(&e), "integrity", "{e}"),
        Ok(o) => panic!("a backup with the staged manifest lost: {o:?}"),
    }
    assert_eq!(archives(), published, "nothing was published");
}

/// **A promote that wrote the manifest is not deferred** when only the
/// staged file's removal fails: the rotation reported DEFERRED, and a note
/// that the manifest "could not be written", over a `vault.json` already on
/// the new generation. The handle keeps writing; the next writable open
/// removes the leftover.
#[test]
fn o266_a_promote_that_wrote_the_manifest_is_not_deferred_when_only_the_removal_fails() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let m = VaultManager::open(root, None).unwrap();
    let mut s = VaultStore::open(m.create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
    s.upsert(&drawer("a memory the rotation seals", 0)).unwrap();
    pause::set(
        &vdir(root),
        Arc::new(|phase| {
            if phase == pause::Phase::Committed {
                fixture::fail_times(
                    fixture::Fault::RemoveStaged,
                    crate::rotate::PROMOTE_ATTEMPTS,
                );
            }
        }),
    );
    let report = s.rotate_keys(m.rotation_candidate(VAULT).unwrap()).unwrap();
    pause::set(&vdir(root), Arc::new(|_| {}));
    assert_eq!(fixture::armed(), None, "premise: every removal failed");
    assert!(
        report.promote_deferred.is_none(),
        "{:?}",
        report.promote_deferred
    );
    assert!(
        s.vault.manifest_on_disk_is_mine(),
        "the new manifest is on disk"
    );
    assert!(staging(root).exists(), "premise: the leftover");
    assert!(
        s.unhealed()
            .iter()
            .any(|n| n.contains("could not be removed")),
        "{:?}",
        s.unhealed()
    );
    assert!(s.vault.retired().is_none());
    s.upsert(&drawer("the rotated handle writes", 1)).unwrap();
    drop(s);
    let w = writable(root);
    assert!(!staging(root).exists(), "the next writable open removed it");
    assert!(w.verify().unwrap().ok());
}
