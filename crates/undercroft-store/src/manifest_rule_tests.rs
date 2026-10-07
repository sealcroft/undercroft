//! ROADMAP O289 and O277: what the manifest rule answers when `vault.json`
//! fails a handle's MAC or is not there to read — on every handle, before and
//! after a promote.
//!
//! A read-only handle opened over a deferred promote keeps `deferred_over` for
//! its life (no latch, O254 item 2), and the rule answered a later forged
//! `vault.json` beside a gone `.next` as a LOST `.next` — the integrity class,
//! with no tamper event — where an ordinary handle and a fresh unlock page an
//! operator. The rule also returned at once on a `.next` read error, so a
//! directory planted there turned a forged or keyless vault into `VERIFY OK`;
//! and an ordinary handle fell back over a `vault.json` that was gone (O277),
//! answering `VERIFY OK` over a vault no open could reopen. A FIFO at either
//! path blocked every reader.
//!
//! Every arm asserts the VARIANT: `ManifestTampered` and the integrity class
//! both exit 2, so a refusal asserted without its class passes for the wrong
//! verdict. Every `search` arm is driven from a label-guard MISS — a foreign
//! commit after the handle's last read — with the replay counter as its
//! premise: a cached verdict answers without asking the manifest anything.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{fixture, Access, SecurityLevel, VaultError, VaultManager};

use crate::rotate_pause as pause;
use crate::{BackupOutcome, SearchOptions, StoreError, VaultStore};

const VAULT: &str = "o289";
const LEVELS: [SecurityLevel; 2] = [SecurityLevel::HmacOnly, SecurityLevel::Sealed];
const QUERY: &str = "harbour ledger cargo";

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
        "w",
        "r",
        format!("{tag} {i}: the harbour ledger names cargo {i} for the eastern quay"),
        Some(format!("{tag}.md")),
        i,
        "test",
    )
}

fn read_only(root: &Path) -> Result<VaultStore, StoreError> {
    let m = VaultManager::open_as(root, None, Access::ReadOnly)?;
    VaultStore::open_read_only(
        m.unlock_as(VAULT, Access::ReadOnly)?,
        Box::new(HashEmbedder),
    )
}

fn writable(root: &Path) -> VaultStore {
    VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap()
}

/// The answer's variant — what the arms compare. The two integrity variants
/// are kept apart: the manifest rule answers `CorruptManifest`, and an
/// `IntegrityFinding` (a guard's refusal, a fresh open's foreign keycheck) is a
/// different mechanism that must not pass for it.
fn class<T>(r: &Result<T, StoreError>) -> &'static str {
    match r {
        Ok(_) => "served",
        Err(StoreError::Vault(VaultError::ManifestTampered)) => "tampered",
        Err(StoreError::Vault(VaultError::CorruptManifest(_))) => "integrity",
        Err(StoreError::IntegrityFinding(_)) => "finding",
        Err(StoreError::Vault(VaultError::Io(_))) => "io",
        Err(StoreError::Vault(VaultError::NotFound(_))) => "not-found",
        Err(_) => "other",
    }
}

/// `verify` served AND passing, or its refusal's class.
fn verify_class(s: &VaultStore) -> &'static str {
    match s.verify() {
        Ok(report) if report.ok() => "served",
        Ok(_) => "failed-verify",
        refused => class(&refused),
    }
}

/// The backup door's class. On a read-only handle the door refuses before it
/// reads anything (ROADMAP O212), so the refusal is asserted and what is
/// compared is the STRICT manifest read the door makes on every other
/// handle — `verified_manifest`, the rule's one reader with no fall-back,
/// which an archive written outside the data directory (O320) would reach under
/// either posture. Asked of the handle that read the manifest, so the rule's
/// answer on a read-only adopted handle stays pinned, as O289 made it.
fn backup_class(s: &VaultStore, root: &Path) -> &'static str {
    let dir = root.join("o289-backups");
    std::fs::create_dir_all(&dir).unwrap();
    if s.is_read_only() {
        assert!(
            matches!(
                s.backup(&dir),
                Err(StoreError::Vault(VaultError::ReadOnly(_)))
            ),
            "a read-only backup refuses before any effect (O212)"
        );
        return class(&s.vault.verified_manifest().map_err(StoreError::Vault));
    }
    match s.backup(&dir) {
        Ok(BackupOutcome::Created(_)) => "served",
        Ok(BackupOutcome::Refused(_)) => "failed-verify",
        refused => class(&refused),
    }
}

/// A foreign commit, so every handle's next guarded read misses its cached
/// verdict and asks the manifest.
fn foreign_commit(root: &Path) {
    let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
    c.execute(
        "INSERT INTO meta (key, value) VALUES ('o289-foreign', 'x') \
         ON CONFLICT(key) DO UPDATE SET value = value || 'x'",
        [],
    )
    .unwrap();
}

/// `search`'s class, from a MISS: the premise is that the guard replayed.
fn search_class(s: &VaultStore) -> &'static str {
    let before = s.replays();
    let got = s.search(QUERY, &SearchOptions::default());
    let answer = class(&got);
    if answer == "served" {
        assert!(
            s.replays() > before,
            "premise: the search missed the guard's cached verdict and replayed"
        );
    }
    answer
}

/// Every door a manifest reaches, on one handle: `verify`, a guarded search,
/// the witness and a backup (on a read-only handle, the backup's strict
/// manifest read, behind its refusal — [`backup_class`]).
fn doors(s: &VaultStore, root: &Path) -> [&'static str; 4] {
    [
        verify_class(s),
        search_class(s),
        class(&s.witness_emit()),
        backup_class(s, root),
    ]
}

/// Change one hex digit of a manifest's MAC, keeping it valid JSON and
/// leaving the salt alone — a flip in the salt would derive other keys and
/// test something else.
fn flip_mac(path: &Path) {
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let salt = v["salt_hex"].clone();
    let mac = v["manifest_mac_hex"].as_str().unwrap().to_string();
    let first = if mac.starts_with('0') { '1' } else { '0' };
    v["manifest_mac_hex"] = format!("{first}{}", &mac[1..]).into();
    std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        after["salt_hex"], salt,
        "premise: the flip left the salt alone"
    );
}

/// A vault whose rotation COMMITTED and whose promote failed every attempt,
/// through the fault seam: the rotating handle, a read-only handle opened over
/// the deferral (HELD), the retired `vault.json`'s bytes, and a genuine older
/// generation-0 manifest that is NOT them.
struct Deferred {
    dir: TempDir,
    rotating: VaultStore,
    held: VaultStore,
    retired: Vec<u8>,
    older: Vec<u8>,
}

fn deferred(level: SecurityLevel) -> Deferred {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let m = mgr(root);
    let mut s = VaultStore::open(m.create(VAULT, level).unwrap()).unwrap();
    for i in 0..4 {
        s.upsert(&drawer("note", i)).unwrap();
    }
    let older = std::fs::read(manifest(root)).unwrap();
    for i in 4..12 {
        s.upsert(&drawer("note", i)).unwrap();
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
    let retired = std::fs::read(manifest(root)).unwrap();
    assert_ne!(
        retired, older,
        "premise: the older manifest is not the retired one"
    );
    let held = read_only(root).unwrap();
    assert!(
        held.vault.promotion_deferred(),
        "premise: the held handle is deferred"
    );
    held.search(QUERY, &SearchOptions::default()).unwrap();
    Deferred {
        dir,
        rotating: s,
        held,
        retired,
        older,
    }
}

/// A writable open promotes the deferral beneath the held handles; returns
/// the CONTROL, an ordinary read-only handle opened after it.
fn promote_beneath(root: &Path, retired: &[u8]) -> VaultStore {
    drop(writable(root));
    assert!(!staging(root).exists(), "premise: promoted, .next removed");
    assert_ne!(
        std::fs::read(manifest(root)).unwrap(),
        retired,
        "premise: vault.json is the new generation's"
    );
    let control = read_only(root).unwrap();
    assert!(
        !control.vault.promotion_deferred(),
        "premise: the control is an ordinary handle"
    );
    control.search(QUERY, &SearchOptions::default()).unwrap();
    control
}

fn fresh_unlock(root: &Path) -> &'static str {
    match VaultManager::open_as(root, None, Access::ReadOnly)
        .unwrap()
        .unlock_as(VAULT, Access::ReadOnly)
    {
        Ok(_) => "served",
        Err(e) => class(&Err::<(), _>(StoreError::Vault(e))),
    }
}

/// **The filing's gate, P-S5 inverted.** After a promote beneath a held
/// read-only handle, a forged `vault.json` is the tamper verdict on every door
/// of the held and rotating handles — what the control and a fresh unlock
/// answer. Before O289 the deferred handles answered a lost `.next`: integrity,
/// with no event, and a message telling the operator to restore from a backup.
#[test]
fn o289_a_forged_manifest_after_a_promote_is_the_tamper_verdict_on_every_door() {
    for level in LEVELS {
        let d = deferred(level);
        let root = d.dir.path();
        let control = promote_beneath(root, &d.retired);
        flip_mac(&manifest(root));
        assert_ne!(std::fs::read(manifest(root)).unwrap(), d.retired, "premise");
        foreign_commit(root);
        for (who, s) in [
            ("held", &d.held),
            ("rotating", &d.rotating),
            ("control", &control),
        ] {
            assert_eq!(doors(s, root), ["tampered"; 4], "{level:?} {who}");
        }
        assert_eq!(fresh_unlock(root), "tampered", "{level:?} fresh");
    }
}

/// **A `.next` that cannot be read is never served over**: the rule held the
/// read and answered from it at once, so a directory planted at `.next` made
/// `anchored_head` fall back — `VERIFY OK` beside a forged `vault.json`, and
/// beside the retired one with the keys in no readable file. Now the MAC
/// verdict comes first, and beside the retired bytes the read error is the
/// answer. Beside a promoted `vault.json` the ordinary answer stands.
#[test]
fn o289_a_staging_file_that_cannot_be_read_is_never_served_over() {
    for level in LEVELS {
        for (promote, flip, expected) in [
            (false, false, ["io"; 4]),
            (false, true, ["tampered"; 4]),
            (true, false, ["served"; 4]),
            (true, true, ["tampered"; 4]),
        ] {
            let d = deferred(level);
            let root = d.dir.path();
            let _control = promote.then(|| promote_beneath(root, &d.retired));
            if !promote {
                std::fs::remove_file(staging(root)).unwrap();
            }
            std::fs::create_dir(staging(root)).unwrap();
            if flip {
                flip_mac(&manifest(root));
            }
            assert_eq!(
                std::fs::read(manifest(root)).unwrap() == d.retired,
                !promote && !flip,
                "premise: vault.json is the retired bytes exactly when nothing moved it"
            );
            foreign_commit(root);
            assert_eq!(
                doors(&d.held, root),
                expected,
                "{level:?} promote={promote} flip={flip}"
            );
        }
    }
}

/// **The retired bytes are the one thing the held handle knows**: put back
/// after a promote with `.next` gone, they are the keys in no file — the
/// integrity verdict, no event, where a fresh open answers the integrity
/// finding too. A GENUINE older generation-0 manifest is not them, and the held
/// handle cannot tell it from a forgery: it pages, as the control does, where a
/// fresh open answers integrity — a pinned cost (O266's residual, now on both
/// sides of the promote).
#[test]
fn o289_the_retired_bytes_after_a_promote_are_lost_keys_and_an_older_manifest_pages() {
    for level in LEVELS {
        for (bytes, held, control_expect) in [
            ("retired", "integrity", "tampered"),
            ("older", "tampered", "tampered"),
        ] {
            let d = deferred(level);
            let root = d.dir.path();
            let control = promote_beneath(root, &d.retired);
            let put = if bytes == "retired" {
                &d.retired
            } else {
                &d.older
            };
            std::fs::write(manifest(root), put).unwrap();
            foreign_commit(root);
            assert_eq!(doors(&d.held, root), [held; 4], "{level:?} {bytes} held");
            assert_eq!(
                doors(&control, root),
                [control_expect; 4],
                "{level:?} {bytes} control"
            );
            assert_eq!(
                fresh_unlock(root),
                "served",
                "premise: a genuine manifest unlocks"
            );
            assert_eq!(
                class(&read_only(root)),
                "finding",
                "{level:?} {bytes}: a fresh open meets another key generation"
            );
        }
    }
}

/// **O277: a `vault.json` that is GONE is the integrity verdict on every
/// handle** — missing, a directory in its place, or the vault's directory
/// itself removed or replaced by a file. An ordinary handle fell back and
/// answered `VERIFY OK`, the witness and a guarded read over a vault no open
/// could reopen; the directory case was "other I/O" under the filed
/// `NotFound`-only split, so it is here by name.
#[test]
fn o277_an_absent_manifest_is_the_integrity_verdict_on_every_handle() {
    #[derive(Debug, Clone, Copy)]
    enum Gone {
        Deleted,
        Directory,
        VaultDirRemoved,
        VaultDirIsAFile,
    }
    let gone = |root: &Path, how: Gone| match how {
        Gone::Deleted => std::fs::remove_file(manifest(root)).unwrap(),
        Gone::Directory => {
            std::fs::remove_file(manifest(root)).unwrap();
            std::fs::create_dir(manifest(root)).unwrap();
        }
        Gone::VaultDirRemoved => {
            std::fs::rename(vdir(root), root.join("set-aside")).unwrap();
        }
        Gone::VaultDirIsAFile => {
            std::fs::rename(vdir(root), root.join("set-aside")).unwrap();
            std::fs::write(vdir(root), b"not a directory").unwrap();
        }
    };
    for level in LEVELS {
        for how in [
            Gone::Deleted,
            Gone::Directory,
            Gone::VaultDirRemoved,
            Gone::VaultDirIsAFile,
        ] {
            // Ordinary handles, both postures.
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            {
                let mut s = VaultStore::open(mgr(root).create(VAULT, level).unwrap()).unwrap();
                for i in 0..6 {
                    s.upsert(&drawer("note", i)).unwrap();
                }
            }
            let w = writable(root);
            let r = read_only(root).unwrap();
            w.search(QUERY, &SearchOptions::default()).unwrap();
            r.search(QUERY, &SearchOptions::default()).unwrap();
            foreign_commit(root);
            gone(root, how);
            for (who, s) in [("writable", &w), ("read-only", &r)] {
                assert_eq!(doors(s, root), ["integrity"; 4], "{level:?} {how:?} {who}");
                if matches!(how, Gone::Deleted | Gone::Directory) {
                    assert_eq!(
                        s.stats().unwrap().anchor_lag,
                        None,
                        "{level:?} {how:?} {who}: the lag is unknown, never zero"
                    );
                }
            }
            // Deferred handles: `.next` intact (before a promote) and gone
            // (after one).
            for promote in [false, true] {
                let d = deferred(level);
                let root = d.dir.path();
                let _control = promote.then(|| promote_beneath(root, &d.retired));
                foreign_commit(root);
                gone(root, how);
                assert_eq!(
                    doors(&d.held, root),
                    ["integrity"; 4],
                    "{level:?} {how:?} deferred, promoted={promote}"
                );
            }
        }
    }
}

/// **A present `vault.json` that cannot be READ is a read failure, never
/// evidence** — through the fixture fault on the rule's read, since a test
/// running as root cannot make one with permissions. The fall-back stands
/// where it cannot stand in for keys no file holds: an ordinary handle, and a
/// deferred one whose `.next` is intact. After a promote the held handle's
/// `.next` is gone, and the read error is the answer. A backup never falls
/// back. At the read-only open's check it is `Io`, never a reopen (O288 item
/// 2): the exception O288 stated there is gone with the arm that made it. A
/// `vault.json` ABSENT at that check is the integrity verdict (ROADMAP O290).
#[test]
fn o289_a_manifest_that_cannot_be_read_falls_back_only_where_the_keys_are_on_disk() {
    for level in LEVELS {
        // Ordinary, and deferred with `.next` intact: the fall-back.
        let d = deferred(level);
        let root = d.dir.path();
        let r = read_only(root).unwrap();
        for (who, s) in [
            ("held, .next intact", &d.held),
            ("a second deferred open", &r),
        ] {
            fixture::fail_next(fixture::Fault::RuleRead);
            assert_eq!(verify_class(s), "served", "{level:?} {who}");
            assert!(fixture::armed().is_none(), "premise: the fault fired");
            fixture::fail_next(fixture::Fault::RuleRead);
            assert_eq!(backup_class(s, root), "io", "{level:?} {who}: no fall-back");
            assert!(fixture::armed().is_none(), "premise: the fault fired");
        }
        drop(r);
        // After a promote: `.next` is gone on the held handle.
        let control = promote_beneath(root, &d.retired);
        for (who, s, expect) in [
            ("held, .next gone", &d.held, "io"),
            ("control", &control, "served"),
        ] {
            fixture::fail_next(fixture::Fault::RuleRead);
            assert_eq!(verify_class(s), expect, "{level:?} {who}");
            assert!(fixture::armed().is_none(), "premise: the fault fired");
        }
        // The read-only open's check: the read error, not a reopen.
        let d = deferred(level);
        let root = d.dir.path();
        let v = VaultManager::open_as(root, None, Access::ReadOnly)
            .unwrap()
            .unlock_as(VAULT, Access::ReadOnly)
            .unwrap();
        fixture::fail_next(fixture::Fault::RuleRead);
        assert_eq!(
            class(&VaultStore::open_read_only(v, Box::new(HashEmbedder))),
            "io",
            "{level:?}: the open's check answers the read error in its own class"
        );
        assert!(
            fixture::armed().is_none(),
            "premise: the fault fired at the check"
        );
        // The case O289 moved: `.next` gone after the unlock read it, and then
        // `vault.json` unreadable, or absent. The rule answered a lost `.next`
        // and the check a REOPEN (O288's stated exception). Unreadable, it is
        // the read error, as every other read failure at the check is; ABSENT,
        // it is the integrity verdict every other handle answers for a missing
        // manifest (ROADMAP O290, revising O289 item 3a, which answered it `Io`
        // here). Never a reopen, either way.
        for absent in [false, true] {
            let d = deferred(level);
            let root = d.dir.path();
            let v = VaultManager::open_as(root, None, Access::ReadOnly)
                .unwrap()
                .unlock_as(VAULT, Access::ReadOnly)
                .unwrap();
            assert!(
                v.has_pending(),
                "premise: the unlock attached the staged rotation"
            );
            std::fs::remove_file(staging(root)).unwrap();
            if absent {
                std::fs::remove_file(manifest(root)).unwrap();
            } else {
                fixture::fail_next(fixture::Fault::RuleRead);
            }
            let opened = VaultStore::open_read_only(v, Box::new(HashEmbedder));
            assert!(
                !matches!(opened, Err(StoreError::StaleUnlock(_))),
                "{level:?} absent={absent}: never a reopen"
            );
            assert_eq!(
                class(&opened),
                if absent { "integrity" } else { "io" },
                "{level:?} absent={absent}"
            );
            assert!(fixture::armed().is_none(), "premise: nothing left armed");
        }
    }
}

/// **A FIFO at a manifest path answers, within a bound** — it blocked every
/// reader: the rule's two reads (so `verify`, the witness and `stats`), the
/// anchor's strict read (a writer holding the write lock), and the unlock's
/// `vault.json` read (O288 guarded only its `.next` read). Each door runs on its
/// own thread and must answer within five seconds. One that does not is
/// released by opening the FIFO read-write — which never blocks on Linux, where
/// opening it write-only would itself wait for a reader — so a regression fails
/// here instead of hanging the battery.
#[cfg(unix)]
#[test]
fn o289_a_fifo_at_a_manifest_path_answers_within_a_bound() {
    use std::sync::mpsc;
    use std::time::Duration;
    let mkfifo = |p: &Path| {
        let _ = std::fs::remove_file(p);
        let ok = std::process::Command::new("mkfifo")
            .arg(p)
            .status()
            .expect("premise: mkfifo runs")
            .success();
        assert!(ok, "premise: the FIFO was made");
    };
    /// Run `door` on a thread; what it answered within the bound.
    fn bounded<T: Send + 'static, R: Send + 'static>(
        subject: T,
        fifo: PathBuf,
        door: impl FnOnce(T) -> R + Send + 'static,
    ) -> R {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(door(subject));
        });
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(answer) => answer,
            Err(_) => {
                // Read-write: a reader blocked opening the FIFO is released,
                // and this open never waits for one.
                let released = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&fifo);
                drop(released);
                let _ = rx.recv_timeout(Duration::from_secs(10));
                panic!("a manifest read BLOCKED on a FIFO at {}", fifo.display());
            }
        }
    }
    let vault = |root: &Path| {
        let mut s =
            VaultStore::open(mgr(root).create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
        s.upsert(&drawer("note", 0)).unwrap();
    };
    // `vault.json` beneath an ordinary live read-only handle: `verify` and
    // `stats` (whose lag reads the rule) answer.
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    vault(&root);
    let r = read_only(&root).unwrap();
    mkfifo(&manifest(&root));
    let (r, verified) = bounded(r, manifest(&root), |s| {
        let v = verify_class(&s);
        (s, v)
    });
    assert_eq!(verified, "integrity");
    let lag = bounded(r, manifest(&root), |s| s.stats().map(|st| st.anchor_lag));
    assert_eq!(lag.unwrap(), None, "stats answers, the lag unknown");
    // The unlock's own `vault.json` read.
    let at = root.clone();
    assert_eq!(bounded(at, manifest(&root), |p| fresh_unlock(&p)), "io");
    // The anchor's strict read, under the write lock: a writable handle's
    // write commits, its anchor finds no manifest it may overwrite, and the
    // handle stops writing — it hung here, holding the lock.
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    vault(&root);
    let w = writable(&root);
    let before = w.chain_state().unwrap().1;
    mkfifo(&manifest(&root));
    let w = bounded(w, manifest(&root), |mut s| {
        s.upsert(&drawer("after", 7)).unwrap();
        s
    });
    assert_eq!(
        w.chain_state().unwrap().1,
        before + 1,
        "the write committed"
    );
    assert!(
        w.vault
            .retired()
            .is_some_and(|why| why.contains("replaced beneath a live handle")),
        "the anchor retired the handle: {:?}",
        w.vault.retired()
    );
    // `.next` beneath a held deferred handle: the read error, beside the
    // retired bytes.
    let d = deferred(SecurityLevel::Sealed);
    let root = d.dir.path().to_path_buf();
    mkfifo(&staging(&root));
    let Deferred {
        held, dir: _keep, ..
    } = d;
    assert_eq!(bounded(held, staging(&root), |s| verify_class(&s)), "io");
}

/// **A writable handle whose `vault.json` is replaced by something that is not
/// a manifest stops writing** (ROADMAP O289, refining O254 item 3). The anchor's
/// strict read answered a directory as an I/O fault — counted, the handle kept
/// writing, each anchor failing — and a FIFO hung it; both are now the
/// integrity class, as a missing manifest already was: the write in flight
/// commits (O254 item 3), and the next is refused.
#[test]
fn o289_a_writable_handle_whose_manifest_is_not_a_file_stops_writing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let mut s = VaultStore::open(mgr(root).create(VAULT, level).unwrap()).unwrap();
        s.upsert(&drawer("note", 0)).unwrap();
        let before = s.chain_state().unwrap().1;
        std::fs::remove_file(manifest(root)).unwrap();
        std::fs::create_dir(manifest(root)).unwrap();
        s.upsert(&drawer("after", 1)).unwrap();
        assert_eq!(
            s.chain_state().unwrap().1,
            before + 1,
            "{level:?}: committed"
        );
        assert!(
            s.vault
                .retired()
                .is_some_and(|why| why.contains("replaced beneath a live handle")),
            "{level:?}: retired as an integrity finding: {:?}",
            s.vault.retired()
        );
        assert!(
            matches!(
                s.upsert(&drawer("after", 2)),
                Err(StoreError::IntegrityFinding(_))
            ),
            "{level:?}: the next write is refused"
        );
        assert_eq!(s.chain_state().unwrap().1, before + 1, "{level:?}");
    }
}

/// **P6, O277's measurement, re-run and pinned as it lands.** A live writable
/// handle whose `vault.json` is deleted: `verify` and the witness now answer
/// the integrity verdict (they answered `VERIFY OK` and emitted a witness).
/// The next write still COMMITS, then retires the handle at its anchor — O254
/// item 3's ruled behaviour, which this unit does not change (the refuter
/// predicted a refusal before the commit; the write path reads no anchor
/// before it commits) — and the one after it is refused.
#[test]
fn o277_p6_a_live_writable_handle_over_a_deleted_manifest() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let mut s = VaultStore::open(mgr(root).create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
    for i in 0..5 {
        s.upsert(&drawer("note", i)).unwrap();
    }
    let before = s.chain_state().unwrap().1;
    std::fs::remove_file(manifest(root)).unwrap();
    assert_eq!(verify_class(&s), "integrity");
    assert_eq!(class(&s.witness_emit()), "integrity");
    assert!(s.vault.retired().is_none(), "premise: not retired yet");
    s.upsert(&drawer("after", 50)).unwrap();
    assert_eq!(
        s.chain_state().unwrap().1,
        before + 1,
        "the write committed"
    );
    assert!(
        s.vault
            .retired()
            .is_some_and(|why| why.contains("vault.json is missing")),
        "the anchor retired the handle"
    );
    assert!(matches!(
        s.upsert(&drawer("after", 51)),
        Err(StoreError::IntegrityFinding(_))
    ));
    assert_eq!(
        s.chain_state().unwrap().1,
        before + 1,
        "nothing more committed"
    );
}
