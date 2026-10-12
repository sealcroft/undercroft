//! ROADMAP O308, O213 and O322 (their rulings of 2026-10-08): what an open
//! does with a vault directory that holds a manifest and no database
//! content, what a read-only open answers for a vault whose manifest records
//! no anchored write, and what an open-path refusal may claim it left alone.
//!
//! Every arm asserts the vault directory's FILES — names and bytes — across
//! the refusal, and which steps the open reached, because every class here was
//! already a refusal before the fix: the writable open CREATED `vault.db`, ran
//! its schema batch and only then refused, and a class alone passes over that.
//! Each open runs the PATH a surface runs — `recorded_embedder`, then the open
//! (O91) — so a door asked inside one open only would not pass.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{fixture, Access, SecurityLevel, Vault, VaultError, VaultManager};

use crate::open_pause::{self, Opener};
use crate::rotate_pause as pause;
use crate::{StoreError, VaultStore, CHAIN_AS_FOUND};

const VAULT: &str = "o308";
const LEVELS: [SecurityLevel; 2] = [SecurityLevel::HmacOnly, SecurityLevel::Sealed];

fn mgr(root: &Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn at(root: &Path, name: &str) -> PathBuf {
    vdir(root).join(name)
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

/// Every entry in the vault directory, by name, with a regular file's bytes —
/// what a refusal must leave exactly as found.
fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(vdir(root))
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let bytes = if e.file_type().unwrap().is_file() {
                std::fs::read(e.path()).unwrap()
            } else {
                b"<not a regular file>".to_vec()
            };
            (e.file_name().to_string_lossy().into_owned(), bytes)
        })
        .collect()
}

/// [`files`] without the WAL scaffolding a read-only connection materialises
/// beside a WAL database it opens — a `-shm` and an empty `-wal` (CLAUDE.md,
/// R4's stated residue) — for the arms where a database IS there to open.
fn files_but_scaffolding(root: &Path) -> BTreeMap<String, Vec<u8>> {
    files(root)
        .into_iter()
        .filter(|(name, bytes)| {
            !(name.ends_with("-shm") || (name.ends_with("-wal") && bytes.is_empty()))
        })
        .collect()
}

/// A vault with `n` drawers written: its manifest records history.
fn written(root: &Path, level: SecurityLevel, n: u32) {
    let mut w = VaultStore::open(mgr(root).create(VAULT, level).unwrap()).unwrap();
    w.upsert_many(&(0..n).map(|i| drawer("note", i)).collect::<Vec<_>>())
        .unwrap();
}

/// The writable PATH a surface runs: the unlock, `recorded_embedder`, the open.
fn writable(root: &Path) -> Result<VaultStore, StoreError> {
    let v = mgr(root).unlock(VAULT)?;
    VaultStore::recorded_embedder(&v)?;
    VaultStore::open(v)
}

/// The read-only PATH a surface runs.
fn read_only(root: &Path) -> Result<VaultStore, StoreError> {
    let m = VaultManager::open_as(root, None, Access::ReadOnly)?;
    let v = m.unlock_as(VAULT, Access::ReadOnly)?;
    VaultStore::recorded_embedder(&v)?;
    VaultStore::open_read_only(v, Box::new(HashEmbedder))
}

fn remove_db(root: &Path) {
    for f in ["vault.db", "vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(at(root, f));
    }
}

fn missing(e: &StoreError) -> Option<(u64, Option<&str>, bool)> {
    match e {
        StoreError::DatabaseMissing {
            writes,
            wal,
            staged,
            ..
        } => Some((*writes, wal.as_deref(), *staged)),
        _ => None,
    }
}

fn err<T>(r: Result<T, StoreError>, label: &str) -> StoreError {
    match r {
        Ok(_) => panic!("{label}: opened"),
        Err(e) => e,
    }
}

/// Both postures refuse `state`, twice on the writable one, and leave every
/// file exactly as found; `check` judges each refusal.
fn refused_everywhere(label: &str, root: &Path, check: impl Fn(&str, &StoreError)) {
    let before = files(root);
    let seen = witness(root);
    for n in 0..2 {
        let e = err(writable(root), label);
        check(&format!("{label}: writable #{n}"), &e);
        assert_eq!(files(root), before, "{label}: writable #{n} changed a file");
    }
    let e = err(read_only(root), label);
    check(&format!("{label}: read-only"), &e);
    assert_eq!(files(root), before, "{label}: read-only changed a file");
    open_pause::clear(&vdir(root));
    no_descriptor(label, &seen);
}

/// The pause points at which an open HOLDS a descriptor on the vault's
/// database: reaching one is reaching a connect, so a refusal that reached one
/// opened the file — and a create-then-remove passes every end-state check.
const DESCRIPTORS: [Opener; 6] = [
    Opener::Writable,
    Opener::ReadOnly,
    Opener::Immutable,
    Opener::RecordedEmbedder,
    Opener::Legacy,
    Opener::Hold,
];

/// Record every pause point the vault's opens reach.
fn witness(root: &Path) -> Arc<Mutex<Vec<Opener>>> {
    let seen: Arc<Mutex<Vec<Opener>>> = Default::default();
    let push = seen.clone();
    open_pause::set(
        &vdir(root),
        Arc::new(move |at| push.lock().unwrap().push(at)),
    );
    seen
}

/// No refusal reached a descriptor: every one was decided before a connect.
fn no_descriptor(label: &str, seen: &Arc<Mutex<Vec<Opener>>>) {
    let seen = seen.lock().unwrap();
    assert!(
        !seen.iter().any(|at| DESCRIPTORS.contains(at)),
        "{label}: an open reached a descriptor on the database: {seen:?}"
    );
}

fn is_missing_history(label: &str, e: &StoreError) {
    let (writes, wal, staged) = missing(e).unwrap_or_else(|| panic!("{label}: {e:?}"));
    assert!(writes > 0, "{label}: the recorded height is named");
    assert_eq!((wal, staged), (None, false), "{label}");
    let text = e.to_string();
    assert!(
        text.contains(&format!("chain height of {writes}")),
        "{text}"
    );
    assert!(text.contains("nothing was created"), "{text}");
    assert!(
        !text.contains("writable process") && !text.to_lowercase().contains("delete the"),
        "{label}: the text is posture-neutral and advises deleting nothing: {text}"
    );
}

fn is_tampered(label: &str, e: &StoreError) {
    assert!(
        matches!(e, StoreError::Vault(VaultError::ManifestTampered)),
        "{label}: {e:?}"
    );
}

/// **P-NOFILE: a deleted `vault.db` beside a manifest that records history.**
/// The writable open CREATED the database, ran its schema batch, judged the
/// empty trail `Erased` and refused `ManifestTampered` — leaving the file, so
/// every later open on both postures answered tampering for a missing file.
/// Now both postures answer A33's `DatabaseMissing`, naming the recorded
/// height, and no file appears.
#[test]
fn o308_a_deleted_database_beside_a_recorded_history_creates_nothing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        written(root, level, 20);
        remove_db(root);
        refused_everywhere(&format!("{level:?}"), root, is_missing_history);
        assert!(!at(root, "vault.db").exists(), "{level:?}: no vault.db");
    }
}

/// **P-ZERO: a zero-length `vault.db` is no content.** SQLite reads a zero-page
/// file as an empty database, so the writable open ran its schema batch into it
/// and refused `ManifestTampered`; the read-only open answered
/// `ReadOnlyUnmigrated`. Both refuse as the deleted file does now, and the file
/// stays zero bytes.
#[test]
fn o308_a_zero_length_database_is_no_content() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        written(root, level, 12);
        remove_db(root);
        std::fs::File::create(at(root, "vault.db")).unwrap();
        refused_everywhere(&format!("{level:?} zero"), root, is_missing_history);
        assert_eq!(std::fs::metadata(at(root, "vault.db")).unwrap().len(), 0);
    }
}

/// **P-WAL and P-ZERO-WAL: a non-empty `-wal` beside no content is named and
/// kept.** SQLite's first lock on a zero-page main file DELETES the `-wal`
/// beside it, read-only connections included: through `recorded_embedder` on
/// the read-only path, through the CREATE on the writable one. Now the door
/// refuses having opened nothing, naming the file, whatever the manifest
/// records — a fresh one included, since this arm runs before the manifest is
/// consulted. An EMPTY `-wal` is scaffolding and decides nothing.
#[test]
fn o308_a_non_empty_wal_beside_no_content_is_named_and_kept() {
    const FRAMES: &[u8] = b"frames the door must never let SQLite discard";
    for level in LEVELS {
        for (shape, main, wal) in [
            ("no main file", None, "vault.db-wal"),
            ("zero-length main file", Some("vault.db"), "vault.db-wal"),
            ("legacy name", Some("palace.db"), "palace.db-wal"),
        ] {
            for fresh in [false, true] {
                let dir = TempDir::new().unwrap();
                let root = dir.path();
                if fresh {
                    mgr(root).create(VAULT, level).unwrap();
                } else {
                    written(root, level, 6);
                    remove_db(root);
                }
                if let Some(main) = main {
                    std::fs::File::create(at(root, main)).unwrap();
                }
                std::fs::write(at(root, wal), FRAMES).unwrap();
                let label = format!("{level:?} {shape} fresh={fresh}");
                refused_everywhere(&label, root, |label, e| {
                    let (_, named, _) = missing(e).unwrap_or_else(|| panic!("{label}: {e:?}"));
                    assert!(named.is_some_and(|n| n.ends_with(wal)), "{label}: {e}");
                    assert!(e.to_string().contains("do NOT delete it"), "{label}: {e}");
                });
                assert_eq!(std::fs::read(at(root, wal)).unwrap(), FRAMES, "{label}");
            }
        }
        // An EMPTY `-wal` is scaffolding: a fresh vault's read-only open is
        // the posture refusal, and its writable open starts the vault.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        mgr(root).create(VAULT, level).unwrap();
        std::fs::File::create(at(root, "vault.db-wal")).unwrap();
        assert!(matches!(
            read_only(root),
            Err(StoreError::ReadOnlyNoAnchoredWrite { .. })
        ));
        writable(root).unwrap_or_else(|e| panic!("{level:?}: an empty -wal blocked: {e}"));
    }
}

/// **A manifest no build writes — a genesis head beside a nonzero height, or a
/// later head at height 0 — beside no content is `ManifestTampered` on both
/// postures** (O308 item 4(e)), as `adopt_empty_chain` answers it; the read-only
/// open answered the genesis one A33's `DatabaseMissing`, the later one too.
#[test]
fn o308_a_mixed_manifest_beside_no_content_is_tampering_on_both_postures() {
    for level in LEVELS {
        for (head, writes) in [(Vault::chain_genesis_hex(), 5), ("11".repeat(32), 0)] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            mgr(root).create(VAULT, level).unwrap();
            let mut v = mgr(root).unlock(VAULT).unwrap();
            fixture::write_anchor_unchecked(&mut v, &head, writes).unwrap();
            drop(v);
            refused_everywhere(&format!("{level:?} {writes}"), root, is_tampered);
            assert!(!at(root, "vault.db").exists());
        }
    }
}

/// A rotation that commits and fails every promote attempt: `vault.json` the
/// retired bytes, `.next` the AUTHENTICATED staged manifest.
fn rotate_deferred(root: &Path) {
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
    assert!(at(root, "vault.json.next").exists(), "premise: staged");
}

/// **A staging file decides by its MAC, never by its presence** (O308 item 1,
/// O257). An unauthenticated `vault.json.next` beside a fresh vault is inert:
/// the read-only open answers the posture refusal and the writable one starts
/// the vault, leaving the file. An authenticated one makes the manifest record
/// history, and `DatabaseMissing` names it with "do NOT delete it".
#[test]
fn o308_a_staging_file_decides_by_its_mac_never_by_its_presence() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        mgr(root).create(VAULT, level).unwrap();
        std::fs::write(at(root, "vault.json.next"), b"{\"half-written\":").unwrap();
        assert!(matches!(
            read_only(root),
            Err(StoreError::ReadOnlyNoAnchoredWrite { .. })
        ));
        assert!(!at(root, "vault.db").exists());
        writable(root).unwrap_or_else(|e| panic!("{level:?}: a torn .next decided: {e}"));
        assert_eq!(
            std::fs::read(at(root, "vault.json.next")).unwrap(),
            b"{\"half-written\":",
            "{level:?}: the torn file is kept (O257)"
        );

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        written(root, level, 8);
        rotate_deferred(root);
        remove_db(root);
        let staged = std::fs::read(at(root, "vault.json.next")).unwrap();
        refused_everywhere(&format!("{level:?} staged"), root, |label, e| {
            let (_, wal, staged) = missing(e).unwrap_or_else(|| panic!("{label}: {e:?}"));
            assert_eq!((wal, staged), (None, true), "{label}");
            let text = e.to_string();
            assert!(
                text.contains("vault.json.next") && text.contains("do NOT delete it"),
                "{label}: {text}"
            );
        });
        assert_eq!(std::fs::read(at(root, "vault.json.next")).unwrap(), staged);
    }
}

/// Set a hook on the vault's opens that runs `act` at `when`, the first time.
/// ... and record every pause point reached, the witness that a refusal came
/// before any descriptor.
fn at_first(
    root: &Path,
    when: Opener,
    act: impl Fn() + Send + Sync + 'static,
) -> (Arc<AtomicUsize>, Arc<Mutex<Vec<Opener>>>) {
    let fired = Arc::new(AtomicUsize::new(0));
    let reached: Arc<Mutex<Vec<Opener>>> = Default::default();
    let (count, push) = (fired.clone(), reached.clone());
    open_pause::set(
        &vdir(root),
        Arc::new(move |at| {
            push.lock().unwrap().push(at);
            if at == when && count.fetch_add(1, Ordering::SeqCst) == 0 {
                act();
            }
        }),
    );
    (fired, reached)
}

/// **The connect's own layout read is the door too** (O308 item 5): a
/// database deleted between the open's head and the connect — the head's door
/// passed, the database was there — is refused before anything is created. The
/// CREATE grant read the layout alone, and created the file.
#[test]
fn o308_a_database_deleted_in_the_connects_window_creates_nothing() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        written(&root, level, 10);
        let r = root.clone();
        let (fired, reached) = at_first(&root, Opener::WritableLayout, move || remove_db(&r));
        let e = err(writable(&root), "window");
        open_pause::clear(&vdir(&root));
        // `recorded_embedder` opened the database while it was there; the
        // CONNECT, after the deletion, must reach no descriptor.
        {
            let reached = reached.lock().unwrap();
            assert!(
                reached.contains(&Opener::WritableLayout) && !reached.contains(&Opener::Writable),
                "{level:?} window: the connect reached a descriptor: {reached:?}"
            );
        }
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "premise: the window reached"
        );
        is_missing_history(&format!("{level:?} window"), &e);
        assert!(
            !at(&root, "vault.db").exists(),
            "{level:?}: created in the window"
        );
    }
}

/// **P-O302-ABSENT: a vault deleted and created again between the unlock and
/// the door is the reopen class, never a tamper page** (O308 item 2): the
/// unlock's values describe a vault that is gone, and a strict MAC re-read of
/// the new `vault.json` would fail and raise the manifest tamper event. The
/// retry starts the new vault (writable) or answers its posture refusal
/// (read-only). A vault deleted and NOT created again answers O291's "deleted"
/// first (item 4(a) before the binding).
#[test]
fn o308_a_vault_replaced_beneath_the_open_is_the_reopen_class() {
    for level in LEVELS {
        // Writable, in the connect's window.
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        mgr(&root).create(VAULT, level).unwrap();
        let r = root.clone();
        let (fired, reached) = at_first(&root, Opener::WritableLayout, move || {
            std::fs::remove_dir_all(vdir(&r)).unwrap();
            mgr(&r).create(VAULT, level).unwrap();
        });
        let e = err(writable(&root), "replaced");
        open_pause::clear(&vdir(&root));
        no_descriptor(&format!("{level:?} replaced"), &reached);
        assert!(
            reached.lock().unwrap().contains(&Opener::WritableLayout),
            "{level:?} replaced: premise, the connect's layout read was reached"
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "premise: the window reached"
        );
        assert!(
            matches!(&e, StoreError::StaleUnlock(t) if t.contains("O308")),
            "{level:?}: {e:?}"
        );
        assert!(
            !at(&root, "vault.db").exists(),
            "{level:?}: nothing created"
        );
        writable(&root).unwrap_or_else(|e| panic!("{level:?}: the retry: {e}"));
        assert!(
            at(&root, "vault.db").exists(),
            "the retry starts the new vault"
        );

        // Read-only, between the unlock and the open.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        mgr(root).create(VAULT, level).unwrap();
        let m = VaultManager::open_as(root, None, Access::ReadOnly).unwrap();
        let v = m.unlock_as(VAULT, Access::ReadOnly).unwrap();
        std::fs::remove_dir_all(vdir(root)).unwrap();
        mgr(root).create(VAULT, level).unwrap();
        let e = err(VaultStore::open_read_only(v, Box::new(HashEmbedder)), "ro");
        assert!(
            matches!(&e, StoreError::StaleUnlock(t) if t.contains("O308")),
            "{level:?}: {e:?}"
        );
        assert!(matches!(
            read_only(root),
            Err(StoreError::ReadOnlyNoAnchoredWrite { .. })
        ));
        assert!(!at(root, "vault.db").exists());

        // Deleted and not created again: O291's answer, on both postures.
        for writable_posture in [true, false] {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            mgr(root).create(VAULT, level).unwrap();
            let v = mgr(root).unlock(VAULT).unwrap();
            std::fs::remove_dir_all(vdir(root)).unwrap();
            let e = if writable_posture {
                err(VaultStore::open(v), "deleted")
            } else {
                err(
                    VaultStore::open_read_only(v, Box::new(HashEmbedder)),
                    "deleted",
                )
            };
            assert!(
                matches!(&e, StoreError::StaleUnlock(t) if t.contains("was deleted")),
                "{level:?} writable={writable_posture}: {e:?}"
            );
            assert!(!vdir(root).exists(), "nothing recreated the directory");
        }
    }
}

/// **The survey FOLLOWS a link** (O308 item 3), as `DbLayout` and SQLite do: a
/// dangling link at `vault.db` beside a manifest that records history is no
/// content and refused before the connect could CREATE through it — a survey
/// by `symlink_metadata` reads the link as content, and the connect then saw
/// `Absent` and created the link's target. Beside a FRESH manifest the
/// writable open still creates that target, outside the vault directory: P-LINK,
/// measured, its ruling owed by a new entry (ROADMAP O430), pinned here as a COST
/// whose disappearance is news to record, never to absorb.
#[cfg(unix)]
#[test]
fn o308_a_dangling_link_at_the_database_name() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let target = root.join("outside.db");
        written(root, level, 4);
        remove_db(root);
        std::os::unix::fs::symlink(&target, at(root, "vault.db")).unwrap();
        refused_everywhere(&format!("{level:?} link"), root, is_missing_history);
        assert!(!target.exists(), "{level:?}: created through the link");

        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let target = root.join("outside.db");
        mgr(root).create(VAULT, level).unwrap();
        std::os::unix::fs::symlink(&target, at(root, "vault.db")).unwrap();
        writable(root).unwrap_or_else(|e| panic!("{level:?}: the fresh link: {e}"));
        assert!(
            target.exists(),
            "{level:?}: P-LINK's cost moved — the writable open no longer creates a dangling \
             link's target; record it in ROADMAP O430"
        );
    }
}

/// A one-page database with no table at all: what a `PRAGMA` write leaves.
fn schema_less(path: &Path) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch("PRAGMA user_version = 7").unwrap();
    let tables: i64 = c
        .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
        .unwrap();
    assert_eq!(tables, 0, "premise: no table");
    drop(c);
    assert!(
        std::fs::metadata(path).unwrap().len() > 0,
        "premise: a page"
    );
}

/// **One never-anchored vault answers one variant wherever the read-only open
/// can see nothing was migrated** (O213 item 3): no database, a zero-length
/// one, one holding none of the read schema's tables, and an EMPTY chain all
/// answer `ReadOnlyNoAnchoredWrite` — they answered `DatabaseMissing` (exit 2)
/// and `ReadOnlyUnmigrated` (exit 1) by how far a first writable open got. A
/// database holding PART of a schema keeps `ReadOnlyUnmigrated`.
#[test]
fn o213_one_never_anchored_vault_answers_one_variant() {
    /// A named way to leave a fresh vault's directory.
    type Shape = (&'static str, fn(&Path));
    for level in LEVELS {
        let shapes: [Shape; 5] = [
            ("no database", |_| {}),
            ("zero-length", |root| {
                std::fs::File::create(at(root, "vault.db")).unwrap();
            }),
            ("no table", |root| schema_less(&at(root, "vault.db"))),
            ("empty chain", |root| {
                let genesis = std::fs::read(at(root, "vault.json")).unwrap();
                drop(writable(root).unwrap());
                let c = rusqlite::Connection::open(at(root, "vault.db")).unwrap();
                c.execute_batch("DELETE FROM chain_meta; DELETE FROM audit;")
                    .unwrap();
                drop(c);
                std::fs::write(at(root, "vault.json"), genesis).unwrap();
            }),
            // Its absent-table twin: O303's "one state, one class".
            ("empty chain, no chain_meta table", |root| {
                let genesis = std::fs::read(at(root, "vault.json")).unwrap();
                drop(writable(root).unwrap());
                let c = rusqlite::Connection::open(at(root, "vault.db")).unwrap();
                c.execute_batch("DROP TABLE chain_meta; DELETE FROM audit;")
                    .unwrap();
                drop(c);
                std::fs::write(at(root, "vault.json"), genesis).unwrap();
            }),
        ];
        for (shape, make) in shapes {
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            mgr(root).create(VAULT, level).unwrap();
            make(root);
            let before = files_but_scaffolding(root);
            match read_only(root) {
                Err(StoreError::ReadOnlyNoAnchoredWrite { id }) => assert_eq!(id, VAULT),
                other => panic!("{level:?} {shape}: {:?}", other.err()),
            }
            assert_eq!(
                files_but_scaffolding(root),
                before,
                "{level:?} {shape}: a file changed"
            );
        }
        // PART of a schema: an interrupted first batch, or an older build.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        mgr(root).create(VAULT, level).unwrap();
        let c = rusqlite::Connection::open(at(root, "vault.db")).unwrap();
        c.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .unwrap();
        drop(c);
        assert!(matches!(
            read_only(root),
            Err(StoreError::ReadOnlyUnmigrated { .. })
        ));
    }
}

/// **A database with no `audit` table beside a manifest that records
/// something is the erased trail on the read-only posture too** (O213 items 4
/// and 5): it returned early there, and the schema check answered
/// `ReadOnlyUnmigrated`, exit 1, while the writable open answers
/// `ManifestTampered`. An empty chain beside a manifest no build writes is the
/// same verdict.
#[test]
fn o213_a_schema_less_database_beside_a_recording_manifest_is_tampering_on_both() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        written(root, level, 5);
        remove_db(root);
        schema_less(&at(root, "vault.db"));
        let before = files_but_scaffolding(root);
        is_tampered("read-only", &err(read_only(root), "ro"));
        assert_eq!(
            files_but_scaffolding(root),
            before,
            "{level:?}: read-only changed a file"
        );
        // The writable open runs its schema batch first (O308's stated
        // residual: a non-empty schema-less file), and answers the same.
        is_tampered("writable", &err(writable(root), "rw"));

        // An empty chain beside a genesis head at height 5.
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        mgr(root).create(VAULT, level).unwrap();
        drop(writable(root).unwrap());
        let c = rusqlite::Connection::open(at(root, "vault.db")).unwrap();
        c.execute_batch("DELETE FROM chain_meta; DELETE FROM audit;")
            .unwrap();
        drop(c);
        let mut v = mgr(root).unlock(VAULT).unwrap();
        fixture::write_anchor_unchecked(&mut v, &Vault::chain_genesis_hex(), 5).unwrap();
        drop(v);
        is_tampered("empty chain, mixed", &err(read_only(root), "ro"));
        is_tampered("empty chain, mixed", &err(writable(root), "rw"));
    }
}

/// **A tamper verdict needs evidence the handle can SEE** (O213's
/// independent review, measured): a young vault whose writer was killed
/// before any checkpoint holds every table in its `-wal` and none in a one-page
/// main file; with its `-shm` gone on a read-only mount the open escalates to
/// `immutable=1`, which reads no `-wal`, and item 5's arm called the trail it
/// could not see erased — `ManifestTampered`, exit 2, on a vault nothing had
/// touched. On such a BLIND handle the arm answers the schema refusal it
/// answered before O213, `ReadOnlyUnmigrated`, and the `-wal` is left exactly
/// as found. The escalation is forced as O279's gate forces it: a directory
/// stands at the `-wal` while the ordinary connection probes, and the real
/// file is back before the immutable one opens.
#[cfg(unix)]
#[test]
fn o213_a_blind_handle_never_reads_a_hot_wal_as_an_erased_trail() {
    for level in LEVELS {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        mgr(root).create(VAULT, level).unwrap();
        let mut w = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
        for i in 0..3 {
            w.upsert(&drawer("young", i)).unwrap();
        }
        // The writer still holds the vault, so nothing has checkpointed: copy
        // what a kill leaves — the main file, the hot `-wal`, no `-shm`.
        let copy = TempDir::new().unwrap();
        let croot = copy.path();
        std::fs::create_dir_all(vdir(croot)).unwrap();
        std::fs::copy(root.join("master.key"), croot.join("master.key")).unwrap();
        for f in ["vault.json", "vault.db", "vault.db-wal"] {
            std::fs::copy(at(root, f), at(croot, f)).unwrap();
        }
        drop(w);
        let main_tables: i64 = rusqlite::Connection::open_with_flags(
            format!("file:{}?immutable=1", at(croot, "vault.db").display()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .unwrap()
        .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
        .unwrap();
        assert_eq!(
            main_tables, 0,
            "{level:?} premise: the main file holds no table"
        );
        let frames = std::fs::read(at(croot, "vault.db-wal")).unwrap();
        assert!(!frames.is_empty(), "{level:?} premise: a hot -wal");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(at(croot, "vault.json")).unwrap()).unwrap();
        assert!(
            manifest["writes"].as_u64().unwrap() > 0,
            "{level:?} premise: the manifest records history"
        );

        let escalated = Arc::new(AtomicUsize::new(0));
        {
            let (wal, aside, escalated) = (
                at(croot, "vault.db-wal"),
                croot.join("wal.aside"),
                escalated.clone(),
            );
            open_pause::set(
                &vdir(croot),
                Arc::new(move |here| match here {
                    Opener::ReadOnly => {
                        std::fs::rename(&wal, &aside).unwrap();
                        std::fs::create_dir(&wal).unwrap();
                    }
                    Opener::Immutable => {
                        std::fs::remove_dir(&wal).unwrap();
                        std::fs::rename(&aside, &wal).unwrap();
                        escalated.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }),
            );
        }
        let e = err(read_only(croot), "blind");
        open_pause::clear(&vdir(croot));
        assert_eq!(
            escalated.load(Ordering::SeqCst),
            1,
            "{level:?} premise: the open escalated to immutable=1"
        );
        assert!(
            matches!(&e, StoreError::ReadOnlyUnmigrated { missing } if missing.contains("audit")),
            "{level:?}: a blind handle raised {e:?}"
        );
        assert_eq!(
            std::fs::read(at(croot, "vault.db-wal")).unwrap(),
            frames,
            "{level:?}: the -wal as found"
        );
    }
}

// ---------------------------------------------------------------------------
// ROADMAP O322: what an open-path refusal claims it left as found
// ---------------------------------------------------------------------------

/// Everything the O322 texts claim, read with no store: the manifest, the
/// staging file, the marker, `chain_meta` (or its absence) and every `audit`
/// row's label and tag. Read from whichever database name the directory holds.
#[derive(Debug, PartialEq, Eq)]
struct Claimed {
    manifest: Vec<u8>,
    staged: Option<Vec<u8>>,
    keycheck: Option<String>,
    chain_meta: Option<Vec<(String, String)>>,
    audit: Vec<(String, Vec<u8>)>,
}

fn claimed(root: &Path) -> Claimed {
    use rusqlite::OptionalExtension;
    let db = ["vault.db", "palace.db"]
        .into_iter()
        .map(|n| at(root, n))
        .find(|p| p.exists())
        .unwrap();
    let c = rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    let audit: Vec<(String, Vec<u8>)> = c
        .prepare("SELECT record_id, tag FROM audit ORDER BY seq")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    Claimed {
        audit,
        manifest: std::fs::read(at(root, "vault.json")).unwrap(),
        staged: std::fs::read(at(root, "vault.json.next")).ok(),
        keycheck: c
            .query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
                r.get(0)
            })
            .optional()
            .unwrap(),
        chain_meta: c
            .prepare("SELECT key, value FROM chain_meta ORDER BY key")
            .ok()
            .map(|mut st| {
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                    .unwrap()
                    .map(Result::unwrap)
                    .collect()
            }),
    }
}

fn index_exists(root: &Path, name: &str) -> bool {
    let db = ["vault.db", "palace.db"]
        .into_iter()
        .map(|n| at(root, n))
        .find(|p| p.exists())
        .unwrap();
    let c = rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    c.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type = 'index' AND name = ?1",
        [name],
        |r| r.get::<_, i64>(0),
    )
    .unwrap()
        == 1
}

/// A pre-1.5.0-shaped database with records and no `chain_meta`: a version-1
/// chain, its file renamed `palace.db`, the indexes `drop` names gone, the
/// marker deleted when `marker` is false, and a NON-EMPTY `palace.db-wal`
/// carrying the edits (checkpoint-on-close off), so the open's legacy rename
/// has frames to fold in.
fn orphaned_legacy(root: &Path, level: SecurityLevel, marker: bool, drop: &[&str]) {
    written(root, level, 15);
    {
        let mut w = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
        w.unswitch_chain_for_test();
    }
    let c = rusqlite::Connection::open(at(root, "vault.db")).unwrap();
    assert!(!c
        .set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true
        )
        .map(|on| !on)
        .unwrap());
    if !marker {
        c.execute("DELETE FROM meta WHERE key = 'keycheck'", [])
            .unwrap();
    }
    c.execute_batch("DROP TABLE chain_meta").unwrap();
    for index in drop {
        c.execute_batch(&format!("DROP INDEX {index}")).unwrap();
    }
    drop_conn(c);
    std::fs::rename(at(root, "vault.db"), at(root, "palace.db")).unwrap();
    std::fs::rename(at(root, "vault.db-wal"), at(root, "palace.db-wal")).unwrap();
    let _ = std::fs::remove_file(at(root, "vault.db-shm"));
    assert!(
        std::fs::metadata(at(root, "palace.db-wal")).unwrap().len() > 0,
        "premise: a non-empty -wal"
    );
}

fn drop_conn(c: rusqlite::Connection) {
    c.close().map_err(|(_, e)| e).unwrap();
}

/// **The two O322 fixtures, each at its own site with a pause witness**: the
/// rotation reconcile's LOCK path (marker deleted, so the open takes the lock)
/// and the `init_chain` FAST path (marker kept). Each refusal used to say
/// "Nothing was written" after O7's rename and the schema batch had run. It now
/// says what it guarantees — `CHAIN_AS_FOUND` — and that claim is checked: the
/// manifest, the staging file, the marker, `chain_meta` and every `audit` row
/// and tag as found. The rename and the recreated indexes are pinned as effects
/// the text does not deny. On the read-only posture there is no rename and the
/// text is the same, and true.
#[test]
fn o322_an_open_path_refusal_says_what_it_leaves_as_found() {
    for level in LEVELS {
        for (site, marker, drop, witness) in [
            (
                "lock path",
                false,
                &["idx_drawers_room", "idx_audit_record_id"][..],
                Opener::RotationLock,
            ),
            (
                "init_chain",
                true,
                &["idx_audit_record_id"][..],
                Opener::InitChain,
            ),
        ] {
            let label = format!("{level:?} {site}");
            let dir = TempDir::new().unwrap();
            let root = dir.path();
            orphaned_legacy(root, level, marker, drop);

            // Read-only first: it renames nothing, and its text is the same.
            let before = claimed(root);
            let e = err(read_only(root), &label);
            let text = e.to_string();
            assert!(
                matches!(e, StoreError::IntegrityFinding(_)),
                "{label}: {e:?}"
            );
            assert!(text.contains(CHAIN_AS_FOUND), "{label}: {text}");
            assert!(
                !text.to_lowercase().contains("nothing was written"),
                "{text}"
            );
            assert!(at(root, "palace.db").exists(), "{label}: read-only renamed");
            assert_eq!(claimed(root), before, "{label}: read-only");

            let fired = Arc::new(AtomicUsize::new(0));
            let seen = fired.clone();
            open_pause::set(
                &vdir(root),
                Arc::new(move |at| {
                    if at == witness {
                        seen.fetch_add(1, Ordering::SeqCst);
                    }
                }),
            );
            let e = err(writable(root), &label);
            open_pause::clear(&vdir(root));
            assert_eq!(
                fired.load(Ordering::SeqCst),
                1,
                "{label}: the site's witness"
            );
            let text = e.to_string();
            assert!(
                matches!(e, StoreError::IntegrityFinding(_)),
                "{label}: {e:?}"
            );
            assert!(text.contains(CHAIN_AS_FOUND), "{label}: {text}");
            assert!(
                !text.to_lowercase().contains("nothing was written"),
                "{label}: {text}"
            );
            assert!(
                text.contains("source build older than 0.19.0")
                    && text.contains("restore it from a backup that verifies"),
                "{label}: both readings named: {text}"
            );
            // What the text claims.
            assert_eq!(claimed(root), before, "{label}: the claim is false");
            // What it does not deny: the rename, and the indexes the schema
            // batch made.
            assert!(
                at(root, "vault.db").exists() && !at(root, "palace.db").exists(),
                "{label}: premise — the rename ran before the refusal"
            );
            for index in drop {
                assert!(index_exists(root, index), "{label}: {index} recreated");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The source gates
// ---------------------------------------------------------------------------

/// A source file's production text: everything before its `mod tests`.
fn production(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap();
    match text.find("\n#[cfg(test)]\nmod tests") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

/// `text` with every comment cut from its line, then every string
/// continuation (`\` + newline + indent) joined, as Rust joins it — so a
/// phrase wrapped across two lines of a literal is one phrase.
fn literal_text(text: &str) -> String {
    let code: Vec<&str> = text
        .lines()
        .map(|l| match l.find("//") {
            Some(c) => &l[..c],
            None => l,
        })
        .collect();
    let joined = code.join("\n");
    let mut out = String::with_capacity(joined.len());
    let mut rest = joined.as_str();
    while let Some(i) = rest.find("\\\n") {
        out.push_str(&rest[..i]);
        rest = rest[i + 2..].trim_start_matches([' ', '\t']);
    }
    out.push_str(rest);
    out
}

/// The `fn` whose body holds byte `at`: the last `fn <name>` before it.
fn enclosing_fn(text: &str, at: usize) -> String {
    let head = &text[..at];
    let start = head.rfind("fn ").expect("inside a fn") + 3;
    head[start..]
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// **O322 item 5: every "nothing was written" literal in the store's and the
/// vault's production code is classified** — counted against the code, per
/// `(file, fn)`, both ways, so a site neither ruling run found is a failure
/// rather than a miss. Every site that remains is one whose refusal comes
/// before any write of its own path, or inside a transaction that rolls back.
#[test]
fn o322_every_nothing_was_written_literal_is_classified() {
    const NEEDLE: &str = "nothing was written";
    // The counter, proved on planted text first: a wrapped literal counts, a
    // comment does not.
    // The continuation's indent is built, not typed: a literal holding the run
    // is what the CLI's collapsed-space gate refuses.
    let indent = " ".repeat(13);
    let planted = format!(
        "fn site() {{\n    let a = \"Nothing was \\\n{indent}written here\";\n    // nothing was \
         written in a comment\n}}\n"
    );
    let joined = literal_text(&planted);
    assert_eq!(joined.to_lowercase().matches(NEEDLE).count(), 1, "{joined}");
    assert_eq!(
        enclosing_fn(&joined, joined.find("Nothing").unwrap()),
        "site"
    );

    // (crate dir, file, fn, count, why the claim holds there)
    let allowed: &[(&str, &str, &str, usize, &str)] = &[
        (
            "undercroft-store",
            "backup.rs",
            "backup",
            1,
            "refused under --read-only as the door's FIRST statement (O212)",
        ),
        (
            "undercroft-store",
            "chain.rs",
            "require_head",
            1,
            "beneath an open handle, by a read or inside a write's transaction that rolls \
             back; never on the open path",
        ),
        (
            "undercroft-store",
            "lib.rs",
            "retired_handle",
            2,
            "a retired handle refuses before its write begins (O254, O266)",
        ),
        (
            "undercroft-store",
            "lib.rs",
            "stale_keys",
            1,
            "chain_append refuses inside the write's transaction, which rolls back (O257)",
        ),
        (
            "undercroft-store",
            "lib.rs",
            "anchor",
            1,
            "a note scoped to vault.json, which the failed anchor did not write (O254)",
        ),
        (
            "undercroft-store",
            "lib.rs",
            "write_drawer_stmts",
            1,
            "an allow's destination check, inside its transaction, which rolls back (O224)",
        ),
        (
            "undercroft-store",
            "vault_db.rs",
            "close",
            1,
            "scoped to the moved file's connection, whose first statement only took a lock \
             (O279): \"nothing was written through it\"",
        ),
        (
            "undercroft-vault",
            "keys.rs",
            "material_missing_message",
            1,
            "the stat-only key classifier refuses before any key is read or written (O204)",
        ),
        // Merged from `main` after O322's build (2026-10-12), each read where
        // it is raised and true there.
        (
            "undercroft-store",
            "admission.rs",
            "allow_in",
            1,
            "an allow's decision re-asked inside its own lock, before its effect (O224's door)",
        ),
        (
            "undercroft-vault",
            "keys.rs",
            "already_exists",
            1,
            "a create-new key or identity write refused before a byte is written (O210, O321)",
        ),
        (
            "undercroft-vault",
            "keys.rs",
            "corrupt_key_file_message",
            1,
            "a short key file refused by the classifier, never rewritten in place (O210)",
        ),
        (
            "undercroft-vault",
            "keys.rs",
            "source_mismatch_message",
            2,
            "the stat-only key classifier refuses before any key is read or written (O204)",
        ),
    ];
    let crates = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
    let mut found: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for krate in ["undercroft-store", "undercroft-vault"] {
        let src = crates.join(krate).join("src");
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
                continue;
            }
            let text = literal_text(&production(&path));
            let lower = text.to_lowercase();
            for (at, _) in lower.match_indices(NEEDLE) {
                *found
                    .entry((krate.to_string(), name.clone(), enclosing_fn(&text, at)))
                    .or_default() += 1;
            }
        }
    }
    let want: BTreeMap<(String, String, String), usize> = allowed
        .iter()
        .map(|(k, f, func, n, _)| ((k.to_string(), f.to_string(), func.to_string()), *n))
        .collect();
    assert_eq!(
        found, want,
        "a \"nothing was written\" literal moved: classify it in this table with why its \
         claim holds where it is raised, or say what the site does guarantee (ROADMAP O322)"
    );
}

/// **O308 items 1 and 5: one CREATE grant, one predicate, and the door before
/// every opener.** `SQLITE_OPEN_CREATE` is spelled once in the store's
/// production code, inside `connect_writable`, after the door; no
/// `writes() == 0` / `writes() > 0` / `writes() != 0` spelling stands in for
/// the predicate; and the door is asked in the four places the ruling names,
/// each before its first opener — `recorded_embedder` and `migrate_db_filename`
/// opening a no-content file first is what defeated it.
#[test]
fn o308_one_create_grant_one_predicate_and_the_door_first() {
    let src = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
            sources.push((name, literal_text(&production(&path))));
        }
    }
    let count = |needle: &str| -> Vec<(String, String)> {
        sources
            .iter()
            .flat_map(|(name, text)| {
                text.match_indices(needle)
                    .map(|(at, _)| (name.clone(), enclosing_fn(text, at)))
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    // Every spelling that carries CREATE, each proved on planted text first:
    // the flag itself (`open_with_flags` with it, or a flags variable built
    // from it), `Connection::open` (rusqlite's default flags carry it) and
    // `OpenFlags::default()` (the same default, spelled out).
    const CREATES: [&str; 3] = [
        "SQLITE_OPEN_CREATE",
        "Connection::open(",
        "OpenFlags::default()",
    ];
    for spelling in CREATES {
        let planted = format!(
            "fn planted() {{\n    let c = {spelling};\n    // {spelling} in a comment\n}}\n"
        );
        let text = literal_text(&planted);
        let hits: Vec<_> = text.match_indices(spelling).collect();
        assert_eq!(
            hits.len(),
            1,
            "premise: the counter sees {spelling} in code alone"
        );
        assert_eq!(enclosing_fn(&text, hits[0].0), "planted");
    }
    let mut creates: Vec<(String, String, &str)> = CREATES
        .iter()
        .flat_map(|spelling| {
            count(spelling)
                .into_iter()
                .map(move |(file, func)| (file, func, *spelling))
        })
        .collect();
    creates.sort();
    assert_eq!(
        creates,
        vec![
            // The archive's own stage, a nonce path under `backups/.staging`
            // this process made; never a vault directory (O256).
            (
                "backup.rs".to_string(),
                "backup".to_string(),
                "Connection::open("
            ),
            // The one grant on a vault's database (O308 item 5).
            (
                "lib.rs".to_string(),
                "connect_writable".to_string(),
                "SQLITE_OPEN_CREATE"
            ),
        ],
        "every open that can CREATE a file, by spelling"
    );
    for spelling in ["writes() == 0", "writes() > 0", "writes() != 0"] {
        assert_eq!(
            count(spelling),
            vec![],
            "{spelling} stands in for the predicate"
        );
    }
    let mut doors = count("absent::door(");
    doors.sort();
    assert_eq!(
        doors,
        vec![
            ("lib.rs".to_string(), "connect_writable".to_string()),
            ("lib.rs".to_string(), "open_inner".to_string()),
            ("lib.rs".to_string(), "open_inner_read_only".to_string()),
            ("lib.rs".to_string(), "recorded_embedder".to_string()),
        ],
        "the door's four sites"
    );
    let lib = &sources.iter().find(|(n, _)| n == "lib.rs").unwrap().1;
    let body = |name: &str| -> &str {
        let at = lib.find(&format!("fn {name}(")).unwrap();
        let rest = &lib[at..];
        let end = rest[3..].find("\n    fn ").map_or(rest.len(), |e| e + 3);
        &rest[..end]
    };
    for (func, opener) in [
        ("open_inner", "migrate_db_filename("),
        ("open_inner_read_only", "connect_read_only("),
        ("recorded_embedder", "open_by_path("),
        ("connect_writable", "open_by_path("),
    ] {
        let b = body(func);
        let door = b.find("absent::door(").unwrap();
        let open = b
            .find(opener)
            .unwrap_or_else(|| panic!("{func} names {opener}"));
        assert!(door < open, "{func}: the door before {opener}");
    }
    let connect = body("connect_writable");
    assert!(
        connect.find("absent::door(").unwrap() < connect.find("SQLITE_OPEN_CREATE").unwrap(),
        "the CREATE grant reads the door's observation"
    );
    // O253's order on the read-only arms (O213's review): the manifest is read
    // BEFORE the arms read the database, and an arm reads it again only for
    // the class of a miss.
    let ro = body("open_inner_read_only");
    let first = ro
        .find("manifest_history_in_force()")
        .expect("the read-only open reads the manifest for its arms");
    for arm in [
        "refuse_headless_without_table(",
        "check_read_schema(",
        "check_chain_read_only(",
    ] {
        let at = ro
            .find(arm)
            .unwrap_or_else(|| panic!("the read-only open runs {arm}"));
        assert!(first < at, "the manifest is read before {arm}");
    }
    let again = body("history_read_first");
    assert!(
        again.find("return Ok(history)").unwrap() < again.find("verified_manifest()").unwrap(),
        "a manifest read before the database is used; a strict read only follows a miss"
    );
}
