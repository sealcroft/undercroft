//! ROADMAP O304: the writable open asks the manifest rule AGAIN before it
//! writes a staged rotation's manifest, and that ask can only refuse or
//! withhold the write.
//!
//! O296 put the store's forced judgement of the audit chain between the
//! licence's reads of `vault.json.next` and `vault.json` and the promote's
//! write, so that window is one forced replay long — 80–96 ms at 10^5 audit
//! rows, measured. No legitimate writer of either file can land in it; an
//! offline edit can, and on `main` it was answered by writing the staged
//! manifest over whatever was there: a forged `vault.json` with no tamper page,
//! a deleted one healed, a lost `.next` healed — opened Ok. Two rows failed
//! instead, with a raw I/O error: a directory at `vault.json` (the write's
//! rename, nothing written) and a directory at `.next` (after the staged
//! manifest was written). Every arm here makes its edit in the window through
//! the vault crate's `between_licence_and_promote` hook, and asserts the
//! variant, the bytes at both paths and the database's state: the classes the
//! rows refuse in now are the ones a fresh open gives, so the bytes are what
//! tell the fix from today.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use rusqlite::OptionalExtension;
use tempfile::TempDir;
use undercroft_core::Drawer;
use undercroft_vault::{fixture, SecurityLevel, Vault, VaultError, VaultManager};

use crate::rotate_pause as pause;
use crate::{StoreError, VaultStore};

const VAULT: &str = "o304";
const LEVELS: [SecurityLevel; 2] = [SecurityLevel::HmacOnly, SecurityLevel::Sealed];

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

/// What is at a manifest path: its bytes, nothing, or a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Everything in the database a promote's reconcile could write: the marker,
/// the `chain_meta` rows (head, height) and the `audit` count.
#[derive(Debug, PartialEq, Eq)]
struct Db {
    keycheck: Option<String>,
    chain_meta: Vec<(String, String)>,
    audit_rows: i64,
}

fn db(root: &Path) -> Db {
    let c = rusqlite::Connection::open_with_flags(
        vdir(root).join("vault.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut st = c
        .prepare("SELECT key, value FROM chain_meta ORDER BY key")
        .unwrap();
    let chain_meta = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    Db {
        keycheck: c
            .query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
                r.get(0)
            })
            .optional()
            .unwrap(),
        chain_meta,
        audit_rows: c
            .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
            .unwrap(),
    }
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap()
}

fn flip_mac(p: &Path) {
    let mut v = json(&std::fs::read(p).unwrap());
    let mac = v["manifest_mac_hex"].as_str().unwrap().to_string();
    let first = if mac.starts_with('0') { "1" } else { "0" };
    v["manifest_mac_hex"] = serde_json::Value::String(format!("{first}{}", &mac[1..]));
    std::fs::write(p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

fn writable(root: &Path) -> Result<VaultStore, StoreError> {
    VaultStore::open(mgr(root).unlock(VAULT)?)
}

fn write_some(root: &Path, tag: &str, n: u32) {
    let mut s = writable(root).unwrap();
    for i in 0..n {
        s.upsert(&drawer(tag, i)).unwrap();
    }
}

/// The manifests a deferral leaves, and one from before it.
struct Deferral {
    /// `vault.json` at the deferral: the retired generation's bytes.
    r: Vec<u8>,
    /// `vault.json.next`: the staged manifest.
    s: Vec<u8>,
    /// An OLDER `vault.json` of the retired generation, at a lower height.
    older: Vec<u8>,
}

/// Ten drawers, an older manifest kept, five more, then a rotation that
/// commits and fails every promote attempt: `vault.json` the retired bytes R,
/// `.next` the staged manifest S, the marker the staged generation's.
fn deferral(root: &Path, level: SecurityLevel) -> Deferral {
    let mut w = VaultStore::open(mgr(root).create(VAULT, level).unwrap()).unwrap();
    w.upsert_many(&(0..10).map(|i| drawer("note", i)).collect::<Vec<_>>())
        .unwrap();
    drop(w);
    let older = std::fs::read(manifest(root)).unwrap();
    write_some(root, "later", 5);
    let m = mgr(root);
    let mut w = writable(root).unwrap();
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
    Deferral {
        r: std::fs::read(manifest(root)).unwrap(),
        s: std::fs::read(staging(root)).unwrap(),
        older,
    }
}

fn held(root: &Path) -> Vault {
    let v = mgr(root).unlock(VAULT).unwrap();
    assert!(
        v.has_pending(),
        "premise: the unlock attached the staged twin"
    );
    v
}

/// Make `edit` in the licence-to-promote window of a writable open of `held`,
/// and return the open's answer with what the edit left at both paths.
fn open_with_edit(
    root: &Path,
    held: Vault,
    edit: impl FnOnce(&Path) + 'static,
) -> (Result<VaultStore, StoreError>, Option<(At, At)>) {
    let left: Rc<RefCell<Option<(At, At)>>> = Rc::new(RefCell::new(None));
    {
        let (root, left) = (root.to_path_buf(), left.clone());
        fixture::between_licence_and_promote(move || {
            edit(&root);
            *left.borrow_mut() = Some((at(&manifest(&root)), at(&staging(&root))));
        });
    }
    let opened = VaultStore::open(held);
    let left = left.borrow_mut().take();
    (opened, left)
}

/// What a refusal must be, with a fragment of its text where one tells it
/// apart.
#[derive(Clone, Copy)]
enum Want {
    Tampered,
    Corrupt(&'static [&'static str]),
    Io(&'static str),
    TooNew,
}

fn is(e: &StoreError, want: Want) -> bool {
    match (e, want) {
        (StoreError::Vault(VaultError::ManifestTampered), Want::Tampered) => true,
        (StoreError::Vault(VaultError::CorruptManifest(m)), Want::Corrupt(frags)) => {
            frags.iter().all(|f| m.contains(f))
        }
        (StoreError::Vault(VaultError::Io(io)), Want::Io(frag)) => io.to_string().contains(frag),
        (StoreError::Vault(VaultError::ManifestTooNew { .. }), Want::TooNew) => true,
        _ => false,
    }
}

type Edit = fn(&Path, &Deferral) -> Box<dyn FnOnce(&Path)>;

/// **Every edit the rule refuses at the ask is refused in the window, in the
/// rule's own class, with nothing written and both files as the edit left
/// them** — and a fresh open of what is left refuses too, where that is the
/// state's answer: not for the fault seam's injected read, nor a directory at
/// `.next`, nor an older retired-generation manifest (each row says why).
#[test]
fn o304_an_edit_in_the_window_is_answered_as_the_rule_answers_it() {
    let rows: [(&str, Want, bool, Edit); 10] = [
        ("vault.json's MAC flipped", Want::Tampered, true, |_, _| {
            Box::new(|r: &Path| flip_mac(&manifest(r)))
        }),
        (
            "vault.json deleted",
            Want::Corrupt(&["vault.json is missing from", "do NOT delete it"]),
            true,
            |_, _| Box::new(|r: &Path| std::fs::remove_file(manifest(r)).unwrap()),
        ),
        (
            "an older manifest of the retired generation put back",
            Want::Tampered,
            // A fresh unlock reads this file AS the retired manifest and its
            // licence takes the staged branch — O290's C″, ruled: only a handle
            // that verified R can tell another retired-generation file from it.
            false,
            |_, d| {
                let older = d.older.clone();
                Box::new(move |r: &Path| std::fs::write(manifest(r), &older).unwrap())
            },
        ),
        (
            "a directory at vault.json",
            Want::Corrupt(&["vault.json is not a manifest file"]),
            true,
            |_, _| {
                Box::new(|r: &Path| {
                    std::fs::remove_file(manifest(r)).unwrap();
                    std::fs::create_dir(manifest(r)).unwrap();
                })
            },
        ),
        (
            "vault.json torn",
            Want::Corrupt(&["EOF while parsing"]),
            true,
            |_, d| {
                let torn = d.r[..d.r.len() / 2].to_vec();
                Box::new(move |r: &Path| std::fs::write(manifest(r), &torn).unwrap())
            },
        ),
        ("vault.json too new", Want::TooNew, true, |_, d| {
            let mut v = json(&d.r);
            v["version"] = serde_json::Value::from(999u64);
            let bytes = serde_json::to_vec_pretty(&v).unwrap();
            Box::new(move |r: &Path| std::fs::write(manifest(r), &bytes).unwrap())
        }),
        (
            "vault.json unreadable (the fault seam)",
            Want::Io("injected RuleRead"),
            false,
            |_, _| Box::new(|_: &Path| fixture::fail_next(fixture::Fault::RuleRead)),
        ),
        (
            ".next deleted",
            Want::Corrupt(&["is gone or has changed"]),
            true,
            |_, _| Box::new(|r: &Path| std::fs::remove_file(staging(r)).unwrap()),
        ),
        (
            ".next overwritten",
            Want::Corrupt(&["is gone or has changed"]),
            true,
            |_, d| {
                let older = d.older.clone();
                Box::new(move |r: &Path| std::fs::write(staging(r), &older).unwrap())
            },
        ),
        (
            "a directory at .next",
            Want::Io("not a regular file"),
            false,
            |_, _| {
                Box::new(|r: &Path| {
                    std::fs::remove_file(staging(r)).unwrap();
                    std::fs::create_dir(staging(r)).unwrap();
                })
            },
        ),
    ];
    for level in LEVELS {
        for (label, want, fresh_refuses, edit) in rows {
            let dir = TempDir::new().unwrap();
            let root = dir.path().to_path_buf();
            let d = deferral(&root, level);
            let before = db(&root);
            let held = held(&root);
            let (opened, left) = open_with_edit(&root, held, edit(&root, &d));
            let (json_left, next_left) = left.expect("premise: the window was reached");
            match opened {
                Err(e) => assert!(is(&e, want), "{level:?} {label}: wrong refusal {e:?}"),
                Ok(_) => panic!("{level:?} {label}: served"),
            }
            assert_eq!(fixture::armed(), None, "{level:?} {label}: premise");
            assert_eq!(
                at(&manifest(&root)),
                json_left,
                "{level:?} {label}: vault.json as the edit left it"
            );
            assert_eq!(
                at(&staging(&root)),
                next_left,
                "{level:?} {label}: .next as the edit left it"
            );
            assert_eq!(db(&root), before, "{level:?} {label}: nothing committed");
            if fresh_refuses {
                assert!(
                    writable(&root).is_err(),
                    "{level:?} {label}: a fresh open refuses the same state"
                );
                assert_eq!(at(&manifest(&root)), json_left, "{level:?} {label}");
                assert_eq!(at(&staging(&root)), next_left, "{level:?} {label}");
            }
        }
    }
}

/// A FIFO at `vault.json` in the window answers within a bound: the re-ask's
/// guarded read classes it as no manifest file before anything opens it.
#[cfg(unix)]
#[test]
fn o304_a_fifo_at_the_manifest_in_the_window_answers_within_a_bound() {
    use std::os::unix::fs::FileTypeExt;
    use std::sync::mpsc;
    use std::time::Duration;
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let d = deferral(&root, level);
        let before = db(&root);
        let v = held(&root);
        let (tx, rx) = mpsc::channel();
        {
            let root = root.clone();
            std::thread::spawn(move || {
                fixture::between_licence_and_promote(move || {
                    std::fs::remove_file(manifest(&root)).unwrap();
                    let ok = std::process::Command::new("mkfifo")
                        .arg(manifest(&root))
                        .status()
                        .expect("premise: mkfifo runs")
                        .success();
                    assert!(ok, "premise: the FIFO was made");
                });
                let _ = tx.send(VaultStore::open(v).err().map(|e| {
                    matches!(e, StoreError::Vault(VaultError::CorruptManifest(m))
                        if m.contains("vault.json is not a manifest file"))
                }));
            });
        }
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
        assert_eq!(at(&staging(&root)), At::Bytes(d.s), "{level:?}: .next kept");
        assert_eq!(db(&root), before, "{level:?}: nothing committed");
    }
}

/// **The staged manifest put in place by hand in the window — re-serialised,
/// or `.next` moved — is FOLLOWED, with the write withheld.** The re-ask reads
/// `vault.json` verifying under the new key at exactly the head and height the
/// judgement saw: the promote runs as a promote since, nothing is written, and
/// `.next`, a duplicate, is removed under its guard. The REFORMATTED copy is
/// what tells a withheld write from a made one — the staged bytes byte for
/// byte would look the same either way.
#[test]
fn o304_the_staged_manifest_put_in_place_by_hand_is_followed_with_the_write_withheld() {
    for level in LEVELS {
        for how in ["re-serialised", "moved"] {
            let dir = TempDir::new().unwrap();
            let root = dir.path().to_path_buf();
            let d = deferral(&root, level);
            let compact = serde_json::to_vec(&json(&d.s)).unwrap();
            assert_ne!(
                compact, d.s,
                "premise: the copy's bytes differ from .next's"
            );
            let expect = if how == "moved" {
                d.s.clone()
            } else {
                compact.clone()
            };
            let before = db(&root);
            let held = held(&root);
            let (opened, left) = open_with_edit(&root, held, move |r| {
                if how == "moved" {
                    std::fs::rename(staging(r), manifest(r)).unwrap();
                } else {
                    std::fs::write(manifest(r), &compact).unwrap();
                }
            });
            assert!(left.is_some(), "premise: the window was reached");
            let s = opened.unwrap_or_else(|e| panic!("{level:?} {how}: {e:?}"));
            assert!(s.verify().unwrap().ok(), "{level:?} {how}");
            assert!(!s.vault().promotion_deferred(), "{level:?} {how}");
            drop(s);
            assert_eq!(
                at(&manifest(&root)),
                At::Bytes(expect),
                "{level:?} {how}: {}",
                if how == "moved" {
                    "the staged bytes in place (a write of the same bytes looks the same — the \
                     re-serialised copy is the arm that tells them apart)"
                } else {
                    "the copy kept — no write was made over it"
                }
            );
            assert_eq!(at(&staging(&root)), At::Nothing, "{level:?} {how}");
            assert_eq!(
                db(&root).keycheck,
                before.keycheck,
                "{level:?} {how}: the staged generation's marker"
            );
            assert!(writable(&root).is_ok(), "{level:?} {how}: a fresh open");
        }
    }
}

/// A deferral whose staged manifest S another open promoted, and wrote past,
/// to H; then R and S put back (A2's) with the database at H or rolled back
/// below it. Returns (S, H).
fn another_head(root: &Path, level: SecurityLevel, rolled_back: bool) -> (Vec<u8>, Vec<u8>) {
    let d = deferral(root, level);
    write_some(root, "since", 1);
    let mid = root.join("mid.db");
    rusqlite::Connection::open(vdir(root).join("vault.db"))
        .unwrap()
        .execute("VACUUM INTO ?1", [mid.to_str().unwrap()])
        .unwrap();
    write_some(root, "since-more", 2);
    let h = std::fs::read(manifest(root)).unwrap();
    assert_ne!(
        json(&h)["writes"],
        json(&d.s)["writes"],
        "premise: H is past the staged head"
    );
    std::fs::write(manifest(root), &d.r).unwrap();
    std::fs::write(staging(root), &d.s).unwrap();
    if rolled_back {
        for f in ["vault.db", "vault.db-wal", "vault.db-shm"] {
            let _ = std::fs::remove_file(vdir(root).join(f));
        }
        std::fs::copy(&mid, vdir(root).join("vault.db")).unwrap();
    }
    (d.s, h)
}

/// **A manifest of the new generation at ANOTHER head in the window is the
/// reopen class** — no judgement saw that head — and the reopen judges it:
/// over the database at that head a fresh open serves it with `verify` OK;
/// over a database rolled back below it, the fresh open answers
/// `ManifestTampered`. Never written over, never followed, never an integrity
/// verdict. A genuine manifest of that generation is reachable without the key
/// (the vault's own `backups/`, or one captured after an earlier promote), so
/// following it would have served the rolled-back database.
#[test]
fn o304_a_manifest_at_another_head_in_the_window_is_reopened_and_judged() {
    for level in LEVELS {
        for rolled_back in [false, true] {
            let label = format!("{level:?} rolled_back={rolled_back}");
            let dir = TempDir::new().unwrap();
            let root = dir.path().to_path_buf();
            let (s_bytes, h) = another_head(&root, level, rolled_back);
            let before = db(&root);
            let held = held(&root);
            let h2 = h.clone();
            let (opened, left) = open_with_edit(&root, held, move |r| {
                std::fs::write(manifest(r), &h2).unwrap()
            });
            assert!(left.is_some(), "{label}: premise: the window was reached");
            match opened {
                Err(StoreError::StaleUnlock(m)) => assert!(
                    m.contains("changed beneath this open's write lock") && m.contains("O304"),
                    "{label}: {m}"
                ),
                Err(e) => panic!("{label}: not the reopen class: {e:?}"),
                Ok(_) => panic!("{label}: served"),
            }
            assert_eq!(at(&manifest(&root)), At::Bytes(h.clone()), "{label}");
            assert_eq!(at(&staging(&root)), At::Bytes(s_bytes.clone()), "{label}");
            assert_eq!(db(&root), before, "{label}: nothing committed");
            // The reopen.
            match writable(&root) {
                Ok(s) if !rolled_back => {
                    assert!(s.verify().unwrap().ok(), "{label}");
                    assert_eq!(
                        s.chain_state().unwrap().1,
                        json(&h)["writes"].as_u64().unwrap(),
                        "{label}: served at H"
                    );
                    drop(s);
                    assert_eq!(
                        at(&staging(&root)),
                        At::Nothing,
                        "{label}: leftover removed"
                    );
                }
                Err(StoreError::Vault(VaultError::ManifestTampered)) if rolled_back => {
                    assert_eq!(at(&manifest(&root)), At::Bytes(h), "{label}");
                    assert_eq!(at(&staging(&root)), At::Bytes(s_bytes), "{label}");
                }
                other => panic!("{label}: the reopen answered {:?}", other.err()),
            }
        }
    }
}

/// **A promote since is never asked again.** R and S put back in the `Skip`
/// window (after another open promoted and wrote) are left as found, and the
/// open's own reconcile of the anchor answers the tamper verdict — a re-ask
/// there would read the pair as the staged branch and weaken the page.
#[test]
fn o304_the_retired_pair_put_back_in_the_skip_window_is_the_tamper_verdict() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let d = deferral(&root, level);
        let held = held(&root);
        write_some(&root, "since", 1);
        assert_eq!(at(&staging(&root)), At::Nothing, "premise: promoted since");
        let before = db(&root);
        let (r, s) = (d.r.clone(), d.s.clone());
        let (opened, left) = open_with_edit(&root, held, move |root| {
            std::fs::write(manifest(root), &r).unwrap();
            std::fs::write(staging(root), &s).unwrap();
        });
        assert!(left.is_some(), "{level:?}: premise: the window was reached");
        assert!(
            matches!(
                opened.err(),
                Some(StoreError::Vault(VaultError::ManifestTampered))
            ),
            "{level:?}: the tamper verdict"
        );
        assert_eq!(at(&manifest(&root)), At::Bytes(d.r), "{level:?}");
        assert_eq!(at(&staging(&root)), At::Bytes(d.s), "{level:?}");
        assert_eq!(db(&root), before, "{level:?}: nothing committed");
        // A fresh open ACCEPTS the pair put back, with the lag healed — A2's,
        // O290's P-W‴: only a handle that saw the promote since can tell.
        let fresh = writable(&root).unwrap_or_else(|e| panic!("{level:?}: {e:?}"));
        assert!(fresh.verify().unwrap().ok(), "{level:?}");
    }
}

/// **The residual, PINNED as a cost**: an edit landing between the re-ask and
/// the write's rename — about one fsync, measured 7.5–11.7 ms, not growing with
/// the corpus — is overwritten by the staged manifest the database answers to,
/// with no page. Nothing is laundered (the anchor was judged), and it takes
/// the capability that could delete `.next` outright.
#[test]
fn o304_the_reask_to_write_residual_is_pinned() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let d = deferral(&root, level);
        let held = held(&root);
        let reached = Rc::new(RefCell::new(false));
        {
            let (root, reached) = (root.clone(), reached.clone());
            fixture::between_reask_and_write(move || {
                flip_mac(&manifest(&root));
                *reached.borrow_mut() = true;
            });
        }
        let s = VaultStore::open(held).expect("COST (O304): overwritten in the residual");
        assert!(
            *reached.borrow(),
            "{level:?}: premise: the residual was reached"
        );
        assert!(s.verify().unwrap().ok(), "{level:?}");
        drop(s);
        assert_eq!(
            at(&manifest(&root)),
            At::Bytes(d.s),
            "{level:?}: the staged manifest written over the edit"
        );
        assert_eq!(at(&staging(&root)), At::Nothing, "{level:?}");
    }
}

/// The steady deferral still promotes, with both hooks reached.
#[test]
fn o304_the_steady_deferral_promotes_through_the_reask() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let d = deferral(&root, level);
        let held = held(&root);
        let reached = Rc::new(RefCell::new(0));
        {
            let reached = reached.clone();
            fixture::between_reask_and_write(move || *reached.borrow_mut() += 1);
        }
        // Armed inside the window, so only a read of the rule AFTER the licence
        // — the re-ask's — can fire it: the residual's hook runs whether or not
        // a re-ask was made (the review's finding, under cf1).
        let read_again = Rc::new(RefCell::new(false));
        let flag = read_again.clone();
        let (opened, left) = open_with_edit(&root, held, move |_| {
            fixture::between_manifest_reads(move || *flag.borrow_mut() = true)
        });
        assert_eq!(
            left,
            Some((At::Bytes(d.r.clone()), At::Bytes(d.s.clone()))),
            "{level:?}: premise: the window was reached on the deferral"
        );
        assert!(*read_again.borrow(), "{level:?}: the re-ask read the rule");
        assert_eq!(
            *reached.borrow(),
            1,
            "{level:?}: the residual's hook was reached"
        );
        let s = opened.unwrap_or_else(|e| panic!("{level:?}: {e:?}"));
        assert!(s.verify().unwrap().ok(), "{level:?}");
        assert!(!s.vault().promotion_deferred(), "{level:?}");
        drop(s);
        assert_eq!(at(&manifest(&root)), At::Bytes(d.s), "{level:?}");
        assert_eq!(at(&staging(&root)), At::Nothing, "{level:?}");
    }
}
