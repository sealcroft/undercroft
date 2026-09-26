//! ROADMAP O254: the post-commit anchor door, its two failure classes, the
//! stale handle it stops, and the concurrency it exists for — driven across
//! real PROCESSES, because the defect was two processes sharing one temp file
//! and a lock taken inside one process proves nothing about another. And
//! ROADMAP O257: the key rotation's exclusive fence, the write door, and how
//! an open reads a keycheck another generation left — across processes for
//! the same reason.
//!
//! Child processes are this same test binary re-invoked on
//! [`o254_child_entry`], an `#[ignore]`d test that does nothing unless the
//! parent's environment names a role.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use undercroft_core::Drawer;
use undercroft_vault::{fixture, Access, SecurityLevel, VaultManager};

use crate::rotate_pause as pause;
use crate::{AnchorOutcome, StoreError, VaultStore, WriteLock};

const VAULT: &str = "o254";

fn fresh(level: SecurityLevel) -> (TempDir, VaultStore) {
    let dir = TempDir::new().unwrap();
    let mgr = VaultManager::open(dir.path(), None).unwrap();
    let vault = mgr.create(VAULT, level).unwrap();
    (dir, VaultStore::open(vault).unwrap())
}

fn reopen(root: &Path) -> VaultStore {
    let mgr = VaultManager::open(root, None).unwrap();
    VaultStore::open(mgr.unlock(VAULT).unwrap()).unwrap()
}

fn drawer(content: &str, idx: u32) -> Drawer {
    Drawer::new(
        "w",
        "r",
        content.into(),
        Some("o254.md".into()),
        idx,
        "test",
    )
}

fn vdir(root: &Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn manifest(root: &Path) -> Vec<u8> {
    std::fs::read(vdir(root).join("vault.json")).unwrap()
}

/// The door refuses to run inside a transaction — a typed error, since a
/// `debug_assert!` would not fire in suites run `--release` — and anchors
/// once the transaction has ended.
#[test]
fn the_door_refuses_inside_a_transaction_and_anchors_after_it() {
    let (_dir, mut s) = fresh(SecurityLevel::HmacOnly);
    s.upsert(&drawer("one fact", 0)).unwrap();
    s.conn.execute_batch("BEGIN").unwrap();
    match s.anchor() {
        Err(StoreError::Invalid(m)) => assert!(m.contains("O254"), "{m}"),
        other => panic!("inside a transaction the door must refuse, got {other:?}"),
    }
    s.conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(s.anchor().unwrap(), AnchorOutcome::Anchored);
    assert_eq!(s.anchor_failures(), 0);
}

/// **The I/O class, through a real write.** A rename that fails after the
/// COMMIT leaves the write STORED and answers Ok — an error would invite a
/// retry, and API saves are unique-per-call, so the retry would duplicate the
/// memory — counted, the lag visible, the handle still writing; the next
/// anchor covers the record this one could not.
#[test]
fn a_committed_write_whose_anchor_fails_on_io_is_ok_counted_and_covered_next() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    s.upsert(&drawer("the first memory", 0)).unwrap();
    assert_eq!(s.stats().unwrap().anchor_lag, Some(0), "premise: anchored");
    let before = manifest(dir.path());

    fixture::fail_next(fixture::Fault::Rename);
    let records = s.count().unwrap();
    s.upsert(&drawer("the second memory", 1))
        .expect("a committed write must not report its anchor's failure");
    assert_eq!(fixture::armed(), None, "premise: the injected rename fired");
    assert_eq!(s.count().unwrap(), records + 1, "the write is stored");
    assert_eq!(manifest(dir.path()), before, "nothing was anchored");
    let stats = s.stats().unwrap();
    assert_eq!(stats.anchor_failures, 1);
    assert_eq!(
        stats.anchor_lag,
        Some(1),
        "the unanchored record is visible"
    );
    assert!(
        s.vault.retired().is_none(),
        "an I/O failure retires nothing"
    );
    assert!(stats.unhealed.is_empty(), "{:?}", stats.unhealed);

    s.upsert(&drawer("the third memory", 2)).unwrap();
    let stats = s.stats().unwrap();
    assert_eq!(stats.anchor_lag, Some(0), "the next anchor covers both");
    assert_eq!(stats.anchor_failures, 1);
    drop(s);
    let s = reopen(dir.path());
    assert!(s.verify().unwrap().chain_ok);
}

/// The other half of the I/O class: a write lock still busy past its timeout
/// defers the anchor rather than failing anything.
#[test]
fn a_busy_write_lock_defers_the_anchor() {
    let (dir, mut s) = fresh(SecurityLevel::HmacOnly);
    s.upsert(&drawer("a memory", 0)).unwrap();
    s.conn.busy_timeout(Duration::from_millis(100)).unwrap();
    let other = rusqlite::Connection::open(vdir(dir.path()).join("vault.db")).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    match s.anchor().unwrap() {
        AnchorOutcome::Deferred(why) => assert!(why.contains("write lock"), "{why}"),
        other => panic!("a busy lock must defer the anchor, got {other:?}"),
    }
    assert_eq!(s.anchor_failures(), 1);
    other.execute_batch("ROLLBACK").unwrap();
    assert_eq!(s.anchor().unwrap(), AnchorOutcome::Anchored);
}

/// The database's committed keycheck, read through a connection of its own
/// that is closed before this returns — a connection held open would itself
/// be a holder the rotation's fence refuses beside.
fn keycheck_of(root: &Path) -> Option<String> {
    use rusqlite::OptionalExtension;
    let conn = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
    conn.query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
        r.get(0)
    })
    .optional()
    .unwrap()
}

/// What another key generation's commit, or an offline edit, leaves in the
/// marker. `None` deletes it.
fn set_keycheck(root: &Path, keycheck: Option<&str>) {
    let conn = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
    match keycheck {
        Some(k) => conn
            .execute(
                "INSERT INTO meta (key, value) VALUES ('keycheck', ?1) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [k],
            )
            .unwrap(),
        None => conn
            .execute("DELETE FROM meta WHERE key = 'keycheck'", [])
            .unwrap(),
    };
}

fn rotate_rows(s: &VaultStore) -> i64 {
    s.conn
        .query_row(
            "SELECT count(*) FROM audit WHERE record_id LIKE 'rotate/%'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

fn staging(root: &Path) -> PathBuf {
    vdir(root).join("vault.json.next")
}

/// Copy an installation — its key and every vault — with every store on it
/// dropped, so the database's WAL has been checkpointed into the file (a copy
/// taken under an open handle is a torn snapshot).
fn copy_installation(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy_installation(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Another PROCESS holding the vault open in `role` (`idle`, `ro-idle`,
/// `reader-txn`), returned once it says it holds it.
fn hold_from_another_process(
    root: &Path,
    role: &str,
    tag: &str,
) -> (Child, BufReader<std::process::ChildStdout>) {
    let mut child = spawn_child(role, &child_env(root, 0, tag));
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut ready = false;
    for _ in 0..16 {
        let mut line = String::new();
        if out.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line.contains("O254_READY") {
            ready = true;
            break;
        }
    }
    assert!(ready, "premise: the {role} process holds the vault open");
    (child, out)
}

fn let_go(
    root: &Path,
    tag: &str,
    (mut child, mut out): (Child, BufReader<std::process::ChildStdout>),
) {
    std::fs::write(root.join(format!("release-{tag}")), b"").unwrap();
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
    assert!(child.wait().unwrap().success(), "{tag}: {rest}");
}

/// Another PROCESS opens the vault and writes, within a bound — the only
/// proof that this process holds nothing on it (ROADMAP O257, O278).
fn another_process_writes(root: &Path, tag: &str) {
    let started = Instant::now();
    let mut env = child_env(root, 1, tag);
    env.push(("O254_BUSY_MS", "1000".into()));
    let report = child_report(spawn_child("writer", &env));
    assert_eq!(report["err"], "0", "{tag}: another process could not write");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{tag}: the other process waited {:?} to open",
        started.elapsed()
    );
}

/// **The release, proven the only way it can be (ROADMAP O257)**: another
/// PROCESS opens the vault and writes, within a bound, and this handle did not
/// have to replace its own connection to let it. Reading `locking_mode` back
/// would prove nothing, and a reconnect would hide a restore that failed.
fn assert_released(root: &Path, s: &VaultStore, tag: &str) {
    another_process_writes(root, tag);
    assert_eq!(
        s.lock_reconnects(),
        0,
        "{tag}: the hold was released only by replacing the connection"
    );
}

/// **ROADMAP O257, the fence, in one process.** O254's version of this test
/// rotated through one handle while a second, opened before it, stayed live,
/// and pinned that the stale handle RETIRED at its next anchor — after its
/// first write had already committed under the retired keys. The rotation now
/// refuses outright: a second handle in the same process holds the vault, so
/// the rotation answers `VaultHeld` and changes nothing, both handles keep
/// writing, and the same rotation succeeds once the other handle is dropped.
/// O254's retire arm survives, through the one route left to it, in
/// [`a_manifest_another_key_generation_wrote_retires_the_handle`].
#[test]
fn a_second_handle_in_the_process_refuses_the_rotation_until_it_is_dropped() {
    let (dir, mut other) = fresh(SecurityLevel::Sealed);
    other.upsert(&drawer("before the rotation", 0)).unwrap();
    let root = dir.path();
    let mgr = VaultManager::open(root, None).unwrap();
    let mut rotator = VaultStore::open(mgr.unlock(VAULT).unwrap()).unwrap();
    // The fence's wait is the connection's own busy timeout; shortened here
    // only so the refusal does not cost the suite five seconds.
    rotator
        .conn
        .busy_timeout(Duration::from_millis(300))
        .unwrap();
    let (salt, kc) = (manifest(root), keycheck_of(root));
    let (height, rows) = (
        crate::chain::writes(&rotator.conn).unwrap(),
        rotate_rows(&rotator),
    );
    match rotator.rotate_keys(mgr.rotation_candidate(VAULT).unwrap()) {
        Err(StoreError::VaultHeld(m)) => assert!(m.contains("O257"), "{m}"),
        other => panic!("the fence must refuse beside a live handle, got {other:?}"),
    }
    assert_eq!(
        manifest(root),
        salt,
        "a refused rotation moved the manifest"
    );
    assert_eq!(keycheck_of(root), kc);
    assert_eq!(crate::chain::writes(&rotator.conn).unwrap(), height);
    assert_eq!(
        rotate_rows(&rotator),
        rows,
        "a refused rotation left a record"
    );
    assert!(
        !staging(root).exists(),
        "a refused rotation staged a manifest"
    );
    assert_eq!(rotator.lock_reconnects(), 0);
    other.upsert(&drawer("the other handle writes", 1)).unwrap();
    rotator.upsert(&drawer("the rotator writes", 2)).unwrap();
    assert_eq!(other.anchor_failures() + rotator.anchor_failures(), 0);
    assert!(other.vault.retired().is_none() && rotator.vault.retired().is_none());

    drop(other);
    rotator
        .rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
        .expect("once nothing else holds the vault, the rotation runs");
    assert_ne!(manifest(root), salt, "premise: the rotation ran");
    assert_eq!(rotator.lock_reconnects(), 0);
    rotator.upsert(&drawer("after the rotation", 3)).unwrap();
    assert_eq!(rotator.anchor_failures(), 0);
    drop(rotator);
    let s = reopen(root);
    assert!(s.verify().unwrap().ok());
    assert_eq!(s.count().unwrap(), 4);
}

/// **O254's retire arm, kept (ROADMAP O254, O257).** A handle whose anchor
/// meets a `vault.json` its keys do not verify stops writing: the write before
/// it is committed, nothing reaches the manifest, and every later write — a
/// save, an audited write, a rotation — refuses. No rotation of this build can
/// run beside a live handle any more, so the manifest is PLANTED: the vault is
/// copied to a second installation holding the same master key, rotated there,
/// and that manifest written over this one — what a rotation by a build
/// without the fence, or on a filesystem whose locks do not work, leaves
/// beside a live handle.
#[test]
fn a_manifest_another_key_generation_wrote_retires_the_handle() {
    let (dir, s) = fresh(SecurityLevel::Sealed);
    drop(s);
    let root = dir.path();
    let elsewhere = TempDir::new().unwrap();
    copy_installation(root, elsewhere.path());
    let mut stale = reopen(root);
    stale.upsert(&drawer("before the rotation", 0)).unwrap();
    let there = VaultManager::open(elsewhere.path(), None).unwrap();
    let mut rotated = VaultStore::open(there.unlock(VAULT).unwrap()).unwrap();
    rotated
        .rotate_keys(there.rotation_candidate(VAULT).unwrap())
        .unwrap();
    drop(rotated);
    let foreign = manifest(elsewhere.path());
    std::fs::write(vdir(root).join("vault.json"), &foreign).unwrap();

    stale
        .audit_migration_standalone("o254-probe", "1", 0, 0)
        .expect("the write before the anchor is committed and answers Ok");
    assert!(
        stale.vault.retired().is_some(),
        "the stale handle must retire"
    );
    assert_eq!(stale.anchor_failures(), 1);
    assert_eq!(manifest(root), foreign, "the planted manifest must survive");
    assert!(stale
        .stats()
        .unwrap()
        .unhealed
        .iter()
        .any(|n| n.contains("stopped writing")));
    let mgr = VaultManager::open(root, None).unwrap();
    let height = crate::chain::writes(&stale.conn).unwrap();
    for (what, refused) in [
        (
            "an audited write",
            stale
                .audit_migration_standalone("o254-probe", "2", 0, 0)
                .err(),
        ),
        (
            "a drawer save",
            stale.upsert(&drawer("after the rotation", 1)).err(),
        ),
        (
            "a rotation",
            stale
                .rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
                .err(),
        ),
    ] {
        match refused {
            Some(StoreError::IntegrityFinding(m)) => assert!(m.contains("O254"), "{what}: {m}"),
            other => panic!("{what}: a retired handle must refuse, got {other:?}"),
        }
    }
    assert_eq!(crate::chain::writes(&stale.conn).unwrap(), height);
    assert_eq!(manifest(root), foreign);
}

/// **P1's discard window (ROADMAP O254), re-shaped by O257.** An open that met
/// a rotation's staged file between its staging and its commit used to read the
/// OLD keycheck and delete it. O254 moved that decision under the write lock;
/// O257's fence now stops such an open before it reaches the decision at all —
/// it waits at its FIRST statement until the rotation has committed AND
/// promoted, then adopts the promoted generation. The `is_finished` arm is
/// what separates "held by the fence" from "reached reconcile and waited
/// there", which this test's O254 form could not tell apart.
#[test]
fn p1_an_open_inside_the_staging_window_waits_and_promotes_rather_than_discards() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    s.upsert(&drawer("a memory the rotation seals", 0)).unwrap();
    drop(s);
    let root = dir.path().to_path_buf();
    let (staged_tx, staged_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let go_rx = std::sync::Mutex::new(go_rx);
    pause::set(
        &vdir(&root),
        std::sync::Arc::new(move |phase| {
            if phase == pause::Phase::Staged {
                staged_tx.send(()).unwrap();
                go_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(20))
                    .expect("bounded: the test signals go");
            }
        }),
    );
    let rotating = {
        let root = root.clone();
        std::thread::spawn(move || {
            let mgr = VaultManager::open(&root, None).unwrap();
            let mut s = VaultStore::open(mgr.unlock(VAULT).unwrap()).unwrap();
            s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
                .map(|_| s)
        })
    };
    staged_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the rotation reaches its staged window");
    assert!(
        staging(&root).exists(),
        "premise: the staged manifest is on disk"
    );
    let opening = {
        let root = root.clone();
        std::thread::spawn(move || reopen(&root))
    };
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        !opening.is_finished(),
        "the open must be held by the fence, not finished beside the rotation"
    );
    assert!(
        staging(&root).exists(),
        "the open must not have discarded the staged manifest"
    );
    go_tx.send(()).unwrap();
    let mut rotated = rotating.join().unwrap().expect("the rotation succeeds");
    let mut opened = opening.join().unwrap();
    rotated.upsert(&drawer("the rotator writes", 1)).unwrap();
    opened.upsert(&drawer("the opener writes", 2)).unwrap();
    assert_eq!(rotated.anchor_failures() + opened.anchor_failures(), 0);
    assert!(
        !staging(&root).exists(),
        "the promote removed its staged file"
    );
    drop((rotated, opened));
    let s = reopen(&root);
    assert!(s.verify().unwrap().chain_ok);
    assert_eq!(s.count().unwrap(), 3);
}

/// **P1's re-seed window, INVERTED (ROADMAP O254 pinned it as a cost, O257
/// closes it).** An open that unlocked BEFORE a rotation staged and reconciled
/// after its commit used to write the OLD keycheck back — in autocommit, after
/// its lock had gone — and only then fail; the rotating handle's next anchor
/// read that keycheck and retired. Now the open is held by the fence until the
/// rotation has promoted, then finds `vault.json` no longer verifying under
/// the keys it unlocked: a race, refused for a reopen, writing nothing. The
/// keycheck is untouched and the rotating handle does NOT retire.
#[test]
fn p1_an_open_that_read_the_vault_before_a_rotation_is_told_to_reopen_and_writes_nothing() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    s.upsert(&drawer("a memory the rotation seals", 0)).unwrap();
    drop(s);
    let root = dir.path().to_path_buf();
    let mgr = VaultManager::open(&root, None).unwrap();
    // Unlocked before the rotation stages: this handle never sees `.next`.
    let early = mgr.unlock(VAULT).unwrap();
    let (committed_tx, committed_rx) = std::sync::mpsc::channel::<()>();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let go_rx = std::sync::Mutex::new(go_rx);
    pause::set(
        &vdir(&root),
        std::sync::Arc::new(move |phase| {
            if phase == pause::Phase::Committed {
                committed_tx.send(()).unwrap();
                go_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(20))
                    .expect("bounded: the test signals go");
            }
        }),
    );
    let rotating = {
        let root = root.clone();
        std::thread::spawn(move || {
            let mgr = VaultManager::open(&root, None).unwrap();
            let mut s = VaultStore::open(mgr.unlock(VAULT).unwrap()).unwrap();
            s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
                .map(|_| s)
        })
    };
    committed_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the rotation commits");
    let opening = std::thread::spawn(move || VaultStore::open(early));
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        !opening.is_finished(),
        "the early open must be held by the fence"
    );
    go_tx.send(()).unwrap();
    let mut rotated = rotating.join().unwrap().expect("the rotation succeeds");
    let rotated_kc = keycheck_of(&root);
    match opening.join().unwrap() {
        Err(StoreError::StaleUnlock(m)) => assert!(m.contains("reopen"), "{m}"),
        other => panic!(
            "the early open must be told to reopen, got {:?}",
            other.err()
        ),
    }
    assert_eq!(
        keycheck_of(&root),
        rotated_kc,
        "the early open re-seeded (O257)"
    );
    rotated.upsert(&drawer("after the promote", 1)).unwrap();
    assert!(
        rotated.vault.retired().is_none(),
        "INVERTED from O254's pinned cost: the rotating handle keeps writing"
    );
    assert_eq!(rotated.anchor_failures(), 0);
    drop(rotated);
    let s = reopen(&root);
    assert!(s.verify().unwrap().chain_ok);
}

/// **P4 (ROADMAP O254): a thread holding a write transaction on one
/// connection and writing through another.** The ruling asked whether the
/// door now stalls such a thread at the anchor. It does not add a stall: the
/// second handle's DATA write needs the same lock and stops there, before
/// any commit, exactly as it did before this door existed — so nothing is
/// committed, nothing is anchored and nothing is counted. No production path
/// holds two handles on one vault on one thread (`serve-http` shares one
/// since O242; the CLI opens one per command).
#[test]
fn p4_a_second_handle_on_a_locked_thread_stops_at_its_data_write_not_the_anchor() {
    let (dir, a) = fresh(SecurityLevel::HmacOnly);
    let mut b = reopen(dir.path());
    b.conn.busy_timeout(Duration::from_millis(200)).unwrap();
    let before = crate::chain::writes(&b.conn).unwrap();
    let held = WriteLock::begin(&a.conn).unwrap();
    let started = Instant::now();
    let refused = b.upsert(&drawer("blocked", 0));
    let waited = started.elapsed();
    drop(held);
    assert!(refused.is_err(), "the data write needs the held lock");
    assert!(
        waited < Duration::from_secs(2),
        "one busy timeout, {waited:?}"
    );
    assert_eq!(b.anchor_failures(), 0, "the anchor was never reached");
    assert_eq!(crate::chain::writes(&b.conn).unwrap(), before);
}

// ---------------------------------------------------------------------------
// Across processes
// ---------------------------------------------------------------------------

/// A child of the multi-process tests: this test binary, re-run on
/// [`o254_child_entry`] with a role in its environment.
fn spawn_child(role: &str, envs: &[(&str, String)]) -> Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "anchor_tests::o254_child_entry",
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .env("O254_ROLE", role)
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.spawn().unwrap()
}

/// One line a child reports, `O254_CHILD key=value …`, as a map.
fn child_report(child: Child) -> std::collections::HashMap<String, String> {
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "a child failed: {:?}", out.status);
    let text = String::from_utf8_lossy(&out.stdout);
    // libtest prints `test <name> ... ` with no newline before the test's
    // own output, so the report is found anywhere in a line, not at its start.
    let line = text
        .lines()
        .find_map(|l| l.find("O254_CHILD ").map(|at| &l[at..]))
        .unwrap_or_else(|| panic!("the child reported nothing:\n{text}"));
    line.split_whitespace()
        .skip(1)
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn child_env(root: &Path, n: usize, tag: &str) -> Vec<(&'static str, String)> {
    vec![
        ("O254_ROOT", root.display().to_string()),
        ("O254_N", n.to_string()),
        ("O254_TAG", tag.to_string()),
    ]
}

/// Not a test: the entry point the multi-process tests re-invoke this binary
/// on. Every role is bounded, and a role it does not know fails.
#[test]
#[ignore = "child-process entry point for the ROADMAP O254 multi-process gate; driven by it, never on its own"]
fn o254_child_entry() {
    let Ok(role) = std::env::var("O254_ROLE") else {
        return;
    };
    let root = PathBuf::from(std::env::var("O254_ROOT").unwrap());
    let n: usize = std::env::var("O254_N").unwrap().parse().unwrap();
    let tag = std::env::var("O254_TAG").unwrap();
    match role.as_str() {
        "writer" => {
            let mut s = reopen(&root);
            // The gate asks for a long busy timeout: it tests the ANCHOR, and
            // SQLite's sleep-based busy handler starves a waiter past the
            // production 5 s under sustained contention whether or not the
            // anchor holds the lock — measured in the lockless baseline too.
            // P2 runs on the production default and reports what it costs.
            if let Ok(ms) = std::env::var("O254_BUSY_MS") {
                s.conn
                    .busy_timeout(Duration::from_millis(ms.parse().unwrap()))
                    .unwrap();
            }
            let (mut ok, mut err) = (0u64, 0u64);
            let mut micros = Vec::with_capacity(n);
            for i in 0..n {
                let started = Instant::now();
                // A source per child: the drawer id is derived from the
                // source and chunk, so two children must not share one.
                let d = Drawer::new(
                    "w",
                    "r",
                    format!("child {tag} write {i}"),
                    Some(format!("child-{tag}.md")),
                    i as u32,
                    "test",
                );
                // `append` is the smallest committed write there is — one
                // audit record and its anchor — through a DEFERRED
                // transaction, the shape P2 measures beside a real save.
                let wrote = if std::env::var("O254_MODE").as_deref() == Ok("append") {
                    s.audit_migration_standalone("o254-gate", &format!("{tag}-{i}"), 0, 0)
                        .map(|_| true)
                } else {
                    s.upsert(&d)
                };
                match wrote {
                    Ok(_) => ok += 1,
                    Err(e) => {
                        err += 1;
                        eprintln!("O254 child {tag}: write {i} failed: {e}");
                    }
                }
                micros.push(started.elapsed().as_micros() as u64);
            }
            micros.sort_unstable();
            let pct = |p: f64| micros[((micros.len() - 1) as f64 * p) as usize];
            println!(
                "O254_CHILD ok={ok} err={err} anchor_failures={} p50_us={} p99_us={} max_us={}",
                s.anchor_failures(),
                pct(0.50),
                pct(0.99),
                micros.last().unwrap()
            );
        }
        // Opens the vault writably `n` times while writers commit — the open's
        // heal anchors through the door too. The ruling requires this probe
        // clean of I/O errors, and since ROADMAP O253 clean of errors of ANY
        // kind: the two it used to report and not judge — `constraint failed`
        // and `database is locked` — were the FTS judgement read in two
        // snapshots and its rebuild racing a writer in autocommit. A heal the
        // lock deferred is not an error and is counted apart (`busy_heal`).
        "opener" => {
            let (mut ok, mut io, mut busy, mut other, mut deferred, mut held) =
                (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
            let mut busy_heal = 0u64;
            for i in 0..n {
                let mgr = VaultManager::open(&root, None).unwrap();
                match mgr
                    .unlock(VAULT)
                    .map_err(StoreError::from)
                    .and_then(VaultStore::open)
                {
                    Ok(s) => {
                        ok += 1;
                        // A heal the lock deferred past the busy timeout is
                        // the I/O class the ruling calls harmless; any other
                        // deferred or refused heal is a manifest failure,
                        // which is what the gate exists to see. The open's
                        // own note says which.
                        let heal_was_busy = s.unhealed().iter().any(|n| {
                            n.contains("could NOT fast-forward") && n.contains("write lock")
                        });
                        if heal_was_busy {
                            busy_heal += 1;
                        } else {
                            deferred += s.anchor_failures();
                        }
                    }
                    Err(e) => {
                        // Three classes, kept apart: the manifest's own I/O
                        // error is the filed defect ("vault error: io error:
                        // No such file or directory"); SQLite's busy is a
                        // DEFERRED transaction that read and could not
                        // upgrade, which the busy handler never waits for;
                        // anything else is reported whole.
                        let text = e.to_string();
                        if matches!(e, StoreError::VaultHeld(_)) {
                            // ROADMAP O257: an open while a rotation holds the
                            // vault says so, typed.
                            held += 1;
                        } else if text.contains("database is locked") {
                            busy += 1;
                        } else if text.contains("io error") {
                            io += 1;
                        } else {
                            other += 1;
                        }
                        eprintln!("O254 opener {tag}: open {i} failed: {text}");
                    }
                }
            }
            println!(
                "O254_CHILD opened={ok} io_err={io} busy_err={busy} other_err={other} \
                 anchor_failures={deferred} held_err={held} busy_heal={busy_heal}"
            );
        }
        // One read-only open (the `--read-only` server's path), reporting
        // whether it opened and how long it took.
        "ro-opener" => {
            let t = Instant::now();
            let mgr = VaultManager::open(&root, None).unwrap();
            let outcome = mgr
                .unlock_as(VAULT, Access::ReadOnly)
                .map_err(StoreError::from)
                .and_then(|v| {
                    VaultStore::open_read_only(v, Box::new(undercroft_core::HashEmbedder))
                });
            let (opened, drawers, held) = match &outcome {
                Ok(s) => (1, s.count().unwrap_or(0), 0),
                Err(e) => {
                    eprintln!("O257 ro-opener {tag}: {e}");
                    (0, 0, u8::from(matches!(e, StoreError::VaultHeld(_))))
                }
            };
            println!(
                "O254_CHILD ro_opened={opened} drawers={drawers} held_err={held} ms={}",
                t.elapsed().as_millis()
            );
        }
        // Holds a connection (and, for `reader-txn`, an open read transaction)
        // until the parent drops a release file — P3's other process.
        "idle" | "reader-txn" | "ro-idle" | "immutable-idle" => {
            let db = vdir(&root).join("vault.db");
            let conn = match role.as_str() {
                // A `--read-only` server's connection shape (`connect_read_only`).
                "ro-idle" => rusqlite::Connection::open_with_flags(
                    &db,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .unwrap(),
                // The escalation a read-only open takes on a write-protected
                // mount: `immutable=1`, which takes no locks at all.
                "immutable-idle" => rusqlite::Connection::open_with_flags(
                    format!("file:{}?immutable=1", db.display()),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_URI
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .unwrap(),
                _ => rusqlite::Connection::open(&db).unwrap(),
            };
            // `sqlite_master`, not `meta`: an immutable reader ignores the
            // WAL, where a schema not yet checkpointed may still live.
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap();
            if role == "reader-txn" {
                conn.execute_batch("BEGIN").unwrap();
                conn.query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0))
                    .unwrap();
            }
            println!("O254_READY");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            let release = root.join(format!("release-{tag}"));
            let deadline = Instant::now() + Duration::from_secs(30);
            while !release.exists() {
                assert!(Instant::now() < deadline, "bounded: never released");
                std::thread::sleep(Duration::from_millis(20));
            }
            println!("O254_CHILD released=1");
        }
        other => panic!("unknown O254 child role {other:?}"),
    }
}

/// Run `writers` child processes of `n` saves each against the vault in
/// `root` while this thread reads `vault.json` in a loop, parsing and
/// MAC-verifying every read. Returns the children's reports and what the
/// reader saw: reads that did not verify, and whether the anchored height
/// ever moved backwards.
fn contend(
    root: &Path,
    writers: usize,
    n: usize,
    openers: usize,
    mode: &str,
    busy_ms: Option<u64>,
    round: &str,
) -> (
    Vec<std::collections::HashMap<String, String>>,
    u64,
    u64,
    bool,
) {
    let mgr = VaultManager::open(root, None).unwrap();
    let reader = mgr.unlock_as(VAULT, Access::ReadOnly).unwrap();
    // Writers in `mode` — `append` for the gate, a real `save` for P2 — and
    // openers making a fifth as many opens.
    let children: Vec<Child> = (0..writers)
        .map(|w| {
            let mut env = child_env(root, n, &format!("{round}-{w}"));
            env.push(("O254_MODE", mode.to_string()));
            if let Some(ms) = busy_ms {
                env.push(("O254_BUSY_MS", ms.to_string()));
            }
            spawn_child("writer", &env)
        })
        .chain((0..openers).map(|o| {
            spawn_child(
                "opener",
                &child_env(root, n / 5, &format!("{round}-open-{o}")),
            )
        }))
        .collect();
    let (mut reads, mut bad, mut last, mut backwards) = (0u64, 0u64, 0u64, false);
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut children: Vec<Option<Child>> = children.into_iter().map(Some).collect();
    let mut reports = Vec::new();
    loop {
        match reader.anchored_writes() {
            Some(w) => {
                backwards |= w < last;
                last = last.max(w);
            }
            None => bad += 1,
        }
        reads += 1;
        for slot in children.iter_mut() {
            if slot
                .as_mut()
                .is_some_and(|c| c.try_wait().unwrap().is_some())
            {
                reports.push(child_report(slot.take().unwrap()));
            }
        }
        if children.iter().all(Option::is_none) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bounded: the writers never finished"
        );
    }
    (reports, reads, bad, backwards)
}

/// **The O254 gate: two PROCESSES anchoring in a loop while a third parses
/// and MAC-verifies `vault.json` on every iteration.** Zero failed writes,
/// zero unparseable or unverifiable reads, a height that never moves down,
/// and the manifest current at the end — across a forced digit crossing of
/// the height at 99→100 and 999→1000, the shape that left trailing bytes
/// after a shorter JSON when two handles wrote one temp file through
/// separate descriptors.
///
/// Counterfactual, measured by the filing on the old writer: 53 of 456
/// opens and 27 committed writes failed in eight seconds.
#[test]
fn two_processes_anchoring_while_a_third_reads_never_fail_or_tear_the_manifest() {
    let (dir, mut s) = fresh(SecurityLevel::HmacOnly);
    let root = dir.path().to_path_buf();
    for (target, round) in [(90u64, "a"), (990, "b")] {
        // Seed the height to just below the crossing, in one batch.
        let height = crate::chain::writes(&s.conn).unwrap();
        let seed: Vec<Drawer> = (height..target)
            .map(|i| drawer(&format!("seed {round} {i}"), 10_000 + i as u32))
            .collect();
        s.upsert_many(&seed).unwrap();
        let below = crate::chain::writes(&s.conn).unwrap();
        assert!(below < target + 5, "premise: seeded below the crossing");
        let (reports, reads, bad, backwards) =
            contend(&root, 2, 200, 1, "save", Some(60_000), round);
        let crossing = if round == "a" { 100 } else { 1000 };
        let after = crate::chain::writes(&s.conn).unwrap();
        assert!(
            below < crossing && after >= crossing,
            "premise: the height crossed {crossing} ({below} → {after})"
        );
        assert!(reads > 10, "premise: the reader read ({reads})");
        let (mut wrote, mut opened) = (0, 0);
        for r in &reports {
            if r.contains_key("opened") {
                opened += 1;
                assert_eq!(r["io_err"], "0", "an open failed on I/O: {r:?}");
                // ROADMAP O253's FOUND note, closed: no open fails at all.
                assert_eq!(r["other_err"], "0", "an open failed: {r:?}");
                assert_eq!(r["busy_err"], "0", "an open failed busy: {r:?}");
                assert_eq!(r["anchor_failures"], "0", "an open's heal failed: {r:?}");
                eprintln!("O254 gate round {round}: opener {r:?}");
            } else {
                wrote += 1;
                assert_eq!(r["err"], "0", "a write failed: {r:?}");
                assert_eq!(r["anchor_failures"], "0", "an anchor failed: {r:?}");
            }
        }
        assert_eq!((wrote, opened), (2, 1), "premise: every child reported");
        assert_eq!(bad, 0, "{bad} of {reads} reads did not parse and verify");
        assert!(!backwards, "the anchored height moved down");
        assert_eq!(
            s.stats().unwrap().anchor_lag,
            Some(0),
            "the last anchor names the committed head"
        );
    }
    drop(s);
    assert!(reopen(&root).verify().unwrap().chain_ok);
}

/// **P3 (ROADMAP O254, for O257's fence).** Does `locking_mode=EXCLUSIVE`
/// plus `BEGIN EXCLUSIVE`, taken on an ALREADY-OPEN WAL connection, see a
/// connection another PROCESS holds open? O257's exclusive rotation posture
/// would rest on the answer, and O69's hold opens a fresh connection, so its
/// answer does not carry over. Pinned as measured, both arms.
#[test]
fn p3_an_exclusive_lock_on_an_open_wal_connection_against_another_process() {
    let (dir, s) = fresh(SecurityLevel::HmacOnly);
    let root = dir.path().to_path_buf();
    let mut observed = Vec::new();
    // `none` is the control: with no other process, the same sequence must
    // take the lock, or a `busy` below would measure something else.
    for role in ["none", "idle", "reader-txn"] {
        let mut child = (role != "none").then(|| {
            let mut child = spawn_child(role, &child_env(&root, 0, role));
            let mut out = BufReader::new(child.stdout.take().unwrap());
            // libtest prints its own lines first; read until the child says
            // it holds the connection, bounded by the child's own exit.
            let mut ready = false;
            for _ in 0..16 {
                let mut line = String::new();
                if out.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                if line.contains("O254_READY") {
                    ready = true;
                    break;
                }
            }
            assert!(ready, "premise: the other process holds the database open");
            (child, out)
        });
        s.conn.busy_timeout(Duration::from_millis(300)).unwrap();
        s.conn
            .query_row("PRAGMA locking_mode=EXCLUSIVE", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap();
        let took = s.conn.execute_batch("BEGIN EXCLUSIVE");
        if took.is_ok() {
            // A write inside it, so the exclusive lock is really exercised.
            let wrote = s.conn.execute_batch("INSERT INTO meta (key, value) VALUES ('o254-p3', 'x') ON CONFLICT(key) DO UPDATE SET value = 'y'");
            let _ = s.conn.execute_batch("ROLLBACK");
            observed.push((role, "exclusive taken", wrote.is_ok()));
        } else {
            observed.push((role, "busy", false));
        }
        s.conn
            .query_row("PRAGMA locking_mode=NORMAL", [], |r| r.get::<_, String>(0))
            .unwrap();
        // NORMAL takes effect at the next lock release; touch the file once.
        s.conn
            .query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0))
            .unwrap();
        if let Some((mut child, mut out)) = child.take() {
            std::fs::write(root.join(format!("release-{role}")), b"").unwrap();
            let mut rest = String::new();
            std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
            assert!(child.wait().unwrap().success(), "{role}: {rest}");
        }
    }
    eprintln!("O254 P3 observed: {observed:?}");
    assert_eq!(
        observed,
        P3_MEASURED.to_vec(),
        "SQLite's answer moved — re-read O257's fence before relying on it"
    );
}

/// What P3 measured (2026-09-24, SQLite bundled by rusqlite 0.32), pinned so
/// O257 can build on a fact rather than a guess: the exclusive lock is
/// REFUSED while another process merely holds the database open — idle, no
/// transaction — as well as while it reads, and taken when nothing else
/// does. So an exclusive rotation posture would refuse beside a live server
/// rather than proceed past it.
const P3_MEASURED: &[(&str, &str, bool)] = &[
    ("none", "exclusive taken", true),
    ("idle", "busy", false),
    ("reader-txn", "busy", false),
];

/// **P2 (ROADMAP O254): save latency and failed writes with 1, 2 and 4
/// writer PROCESSES.** A measurement, not a gate — run it by name with
/// `--ignored` and read the table it prints.
#[test]
#[ignore = "P2 measurement for ROADMAP O254; run by name with --ignored and read its table"]
fn p2_measure_save_latency_and_busy_with_1_2_and_4_writers() {
    let per_writer: usize = std::env::var("O254_P2_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    // `save` is a drawer save (`write_drawer`, `BEGIN IMMEDIATE`); `append`
    // is an audited write through a DEFERRED transaction, which SQLite fails
    // at once with SQLITE_BUSY when its read must upgrade while another
    // connection holds the write lock — the busy handler never runs for it.
    let mode = std::env::var("O254_P2_MODE").unwrap_or_else(|_| "save".into());
    for writers in [1usize, 2, 4] {
        let (dir, s) = fresh(SecurityLevel::Sealed);
        drop(s);
        let started = Instant::now();
        let (reports, reads, bad, backwards) = contend(
            dir.path(),
            writers,
            per_writer,
            0,
            &mode,
            None,
            &format!("p2-{writers}"),
        );
        let wall = started.elapsed();
        let worst = |k: &str| {
            reports
                .iter()
                .map(|r| r[k].parse::<u64>().unwrap())
                .max()
                .unwrap()
        };
        let sum = |k: &str| {
            reports
                .iter()
                .map(|r| r[k].parse::<u64>().unwrap())
                .sum::<u64>()
        };
        eprintln!(
            "O254 P2 mode={mode} writers={writers} writes={} wall_ms={} p50_us(worst writer)={} \
             p99_us(worst writer)={} max_us={} failed_writes={} deferred_anchors={} \
             reads={reads} bad_reads={bad} backwards={backwards}",
            writers * per_writer,
            wall.as_millis(),
            worst("p50_us"),
            worst("p99_us"),
            worst("max_us"),
            sum("err"),
            sum("anchor_failures"),
        );
    }
}

/// **O257 probes (a measurement, not a gate)**: what the exclusive rotation
/// posture O254's P3 pointed at does once it is HELD rather than merely
/// taken. Run by name with `--ignored` and read the lines it prints.
#[test]
#[ignore = "O257 probe; run by name with --ignored and read what it prints"]
fn o257_probe_exclusive_posture_held_across_a_commit() {
    let (dir, mut s) = fresh(SecurityLevel::HmacOnly);
    s.upsert(&drawer("seed", 0)).unwrap();
    let root = dir.path().to_path_buf();
    let db = vdir(&root).join("vault.db");
    let exclusive = |c: &rusqlite::Connection| -> String {
        c.query_row("PRAGMA locking_mode=EXCLUSIVE", [], |r| r.get(0))
            .unwrap()
    };
    let normal = |c: &rusqlite::Connection| {
        let m: String = c
            .query_row("PRAGMA locking_mode=NORMAL", [], |r| r.get(0))
            .unwrap();
        c.query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0))
            .unwrap();
        m
    };
    let opener = |tag: &str| {
        let t = Instant::now();
        let r = child_report(spawn_child("opener", &child_env(&root, 1, tag)));
        (r, t.elapsed())
    };

    // PA: taken, a write, COMMIT — is the lock still held after the commit?
    eprintln!("O257 PA mode set: {}", exclusive(&s.conn));
    s.conn.execute_batch("BEGIN EXCLUSIVE").unwrap();
    s.conn
        .execute_batch("INSERT INTO meta (key, value) VALUES ('o257-pa', '1') ON CONFLICT(key) DO UPDATE SET value = '2'")
        .unwrap();
    s.conn.execute_batch("COMMIT").unwrap();
    let (r, took) = opener("pa-held");
    eprintln!("O257 PA other-process open AFTER COMMIT, still EXCLUSIVE: {r:?} in {took:?}");
    eprintln!("O257 PA restore: {}", normal(&s.conn));
    let (r, took) = opener("pa-released");
    eprintln!("O257 PA other-process open after NORMAL + one read: {r:?} in {took:?}");

    // PB: an idle second connection in the SAME process.
    let other = rusqlite::Connection::open(&db).unwrap();
    other
        .query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0))
        .unwrap();
    s.conn.busy_timeout(Duration::from_millis(300)).unwrap();
    exclusive(&s.conn);
    let took = s.conn.execute_batch("BEGIN EXCLUSIVE");
    eprintln!("O257 PB same-process idle connection: BEGIN EXCLUSIVE -> {took:?}");
    if took.is_ok() {
        s.conn.execute_batch("ROLLBACK").unwrap();
    }
    normal(&s.conn);
    drop(other);
    // PB2: a second VaultStore in the same process.
    let s2 = reopen(&root);
    exclusive(&s.conn);
    let took = s.conn.execute_batch("BEGIN EXCLUSIVE");
    eprintln!("O257 PB2 same-process second VaultStore: BEGIN EXCLUSIVE -> {took:?}");
    if took.is_ok() {
        s.conn.execute_batch("ROLLBACK").unwrap();
    }
    normal(&s.conn);
    drop(s2);
    s.conn.busy_timeout(Duration::from_secs(5)).unwrap();

    // PC: an opener in another process while the lock is held for 1.5 s,
    // under the production 5 s busy timeout — does it wait and then open?
    for hold in [1500u64, 7000] {
        exclusive(&s.conn);
        s.conn.execute_batch("BEGIN EXCLUSIVE").unwrap();
        s.conn.execute_batch("COMMIT").unwrap();
        let t = Instant::now();
        let child = spawn_child("opener", &child_env(&root, 1, &format!("pc-{hold}")));
        std::thread::sleep(Duration::from_millis(hold));
        normal(&s.conn);
        let r = child_report(child);
        eprintln!(
            "O257 PC opener while the lock was held {hold} ms: {r:?} in {:?}",
            t.elapsed()
        );
    }
    // PD: a store left open after all of it still writes, and so does
    // another process.
    s.upsert(&drawer("after the probes", 1)).unwrap();
    let (r, took) = opener("pd");
    eprintln!("O257 PD after the probes: {r:?} in {took:?}");

    // P6: a read-only holder and an `immutable=1` holder in another process.
    s.conn.busy_timeout(Duration::from_millis(300)).unwrap();
    for role in ["ro-idle", "immutable-idle"] {
        let mut child = spawn_child(role, &child_env(&root, 0, role));
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut ready = false;
        for _ in 0..16 {
            let mut line = String::new();
            if out.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.contains("O254_READY") {
                ready = true;
                break;
            }
        }
        assert!(ready, "premise: {role} holds the database open");
        exclusive(&s.conn);
        let took = s.conn.execute_batch("BEGIN EXCLUSIVE");
        eprintln!("O257 P6 {role}: BEGIN EXCLUSIVE -> {took:?}");
        if took.is_ok() {
            s.conn.execute_batch("ROLLBACK").unwrap();
        }
        normal(&s.conn);
        std::fs::write(root.join(format!("release-{role}")), b"").unwrap();
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
        assert!(child.wait().unwrap().success(), "{role}: {rest}");
    }
    // P6b: a refused fence leaves the handle writable and another process
    // writing (the mode restored).
    let holder = rusqlite::Connection::open(&db).unwrap();
    holder
        .query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0))
        .unwrap();
    exclusive(&s.conn);
    let refused = s.conn.execute_batch("BEGIN EXCLUSIVE");
    eprintln!("O257 P6b fence beside a holder: {refused:?}");
    let restored = normal(&s.conn);
    drop(holder);
    s.upsert(&drawer("after a refused fence", 2)).unwrap();
    let (r, took) = opener("p6b");
    eprintln!("O257 P6b after a refused fence (mode {restored}): {r:?} in {took:?}");

    // P-RO: a read-only open in another process while the hold lasts 7 s,
    // after a write the WAL still holds — does it refuse, or read a frozen
    // main file through `immutable=1` (D1)?
    s.conn.busy_timeout(Duration::from_secs(5)).unwrap();
    s.upsert(&drawer("only in the WAL", 3)).unwrap();
    let live = s.count().unwrap();
    exclusive(&s.conn);
    s.conn.execute_batch("BEGIN EXCLUSIVE").unwrap();
    s.conn.execute_batch("COMMIT").unwrap();
    let child = spawn_child("ro-opener", &child_env(&root, 0, "p-ro"));
    std::thread::sleep(Duration::from_millis(7000));
    normal(&s.conn);
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find_map(|l| l.find("O254_CHILD ").map(|at| &l[at..]))
        .unwrap_or("(no report)");
    eprintln!("O257 P-RO read-only open during a 7 s hold (live drawers {live}): {line}");
}

/// **O257 P8 (a measurement)**: how long a rotation holds the vault — the
/// window in which every other open waits its busy timeout. Sealed drawers,
/// `O257_P8_N` of them (default 5,000). Run by name with `--ignored`.
#[test]
#[ignore = "O257 P8 measurement; run by name with --ignored"]
fn o257_probe_rotation_hold_time() {
    let n: u32 = std::env::var("O257_P8_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000);
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    for chunk in (0..n).collect::<Vec<_>>().chunks(500) {
        let batch: Vec<Drawer> = chunk
            .iter()
            .map(|i| {
                drawer(
                    &format!("memory {i}: the tide table for the north quay, read at dawn"),
                    *i,
                )
            })
            .collect();
        s.upsert_many(&batch).unwrap();
    }
    let mgr = VaultManager::open(dir.path(), None).unwrap();
    let started = Instant::now();
    let report = s
        .rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
        .unwrap();
    eprintln!(
        "O257 P8 drawers={} rotation_ms={}",
        report.drawers,
        started.elapsed().as_millis()
    );
}

// ---------------------------------------------------------------------------
// ROADMAP O257: the rotation's fence, and what it leaves behind
// ---------------------------------------------------------------------------

/// **The O257 gate, across processes.** A rotation beside another PROCESS
/// holding the vault — idle, or a `--read-only` connection — is refused as
/// `VaultHeld` and changes nothing; and after EVERY exit — each refusal, a
/// verify blocker, an injected staging fault, a panicking pause hook, a
/// deferred promote, a success — another process opens and writes, and this
/// handle did not have to reconnect to let it. The counterfactuals that must
/// fail here: no fence; no NORMAL restore; `SELECT 1` as the release.
#[test]
fn a_rotation_beside_another_process_is_refused_and_every_exit_releases_the_vault() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    for i in 0..3 {
        s.upsert(&drawer(&format!("memory {i}"), i)).unwrap();
    }
    let root = dir.path();
    let mgr = VaultManager::open(root, None).unwrap();
    s.conn.busy_timeout(Duration::from_millis(300)).unwrap();

    for role in ["idle", "ro-idle"] {
        let holder = hold_from_another_process(root, role, role);
        let (salt, kc) = (manifest(root), keycheck_of(root));
        let (height, rows) = (crate::chain::writes(&s.conn).unwrap(), rotate_rows(&s));
        match s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap()) {
            Err(StoreError::VaultHeld(m)) => assert!(m.contains("O257"), "{role}: {m}"),
            other => panic!("{role}: the fence must refuse beside a holder, got {other:?}"),
        }
        assert_eq!(manifest(root), salt, "{role}: the salt moved");
        assert_eq!(keycheck_of(root), kc, "{role}");
        assert_eq!(crate::chain::writes(&s.conn).unwrap(), height, "{role}");
        assert_eq!(rotate_rows(&s), rows, "{role}");
        assert!(
            !staging(root).exists(),
            "{role}: a staged manifest was left"
        );
        // Released even while the holder is still there.
        assert_released(root, &s, &format!("refused-{role}"));
        let_go(root, role, holder);
    }

    // A verify blocker: an integrity finding, refused inside the fence.
    let tag: Vec<u8> = s
        .conn
        .query_row("SELECT tag FROM drawers ORDER BY seq LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    s.conn
        .execute(
            "UPDATE drawers SET tag = zeroblob(32) WHERE seq = (SELECT min(seq) FROM drawers)",
            [],
        )
        .unwrap();
    match s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap()) {
        Err(StoreError::IntegrityFinding(m)) => assert!(m.contains("refused"), "{m}"),
        other => panic!("a tampered row must block the rotation, got {other:?}"),
    }
    assert_released(root, &s, "blocker");
    s.conn
        .execute(
            "UPDATE drawers SET tag = ?1 WHERE seq = (SELECT min(seq) FROM drawers)",
            rusqlite::params![tag],
        )
        .unwrap();

    // An injected fault at the staging write — the rotation's first manifest
    // write — fails the rotation before its commit.
    fixture::fail_next(fixture::Fault::Rename);
    assert!(s
        .rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
        .is_err());
    assert_eq!(fixture::armed(), None, "premise: the injected fault fired");
    assert_released(root, &s, "staging-fault");

    // A pause hook that panics inside the fence.
    pause::set(
        &vdir(root),
        std::sync::Arc::new(|phase| {
            if phase == pause::Phase::Staged {
                panic!("an injected panic inside the fence (ROADMAP O257)");
            }
        }),
    );
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
    }));
    assert!(panicked.is_err(), "premise: the hook panicked");
    assert_released(root, &s, "panic");

    // A promote that fails every attempt: the rotation COMMITTED, answers Ok,
    // and says the deferral on the report and on `unhealed`.
    pause::set(
        &vdir(root),
        std::sync::Arc::new(|phase| {
            if phase == pause::Phase::Committed {
                fixture::fail_times(fixture::Fault::Rename, crate::rotate::PROMOTE_ATTEMPTS);
            }
        }),
    );
    let before = manifest(root);
    let report = s
        .rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
        .expect("a committed rotation answers Ok (O254 ruling item 3)");
    assert!(
        report.promote_deferred.is_some(),
        "the deferral is reported"
    );
    assert_eq!(manifest(root), before, "premise: nothing was promoted");
    assert!(staging(root).exists(), "the staged manifest is intact");
    assert!(s
        .stats()
        .unwrap()
        .unhealed
        .iter()
        .any(|n| n.contains("do NOT delete it")));
    // The other process's open promotes it, and writes.
    assert_released(root, &s, "deferred-promote");
    assert!(
        !staging(root).exists(),
        "the next writable open promoted it"
    );

    pause::set(&vdir(root), std::sync::Arc::new(|_| {}));
    // ROADMAP O266: the handle whose promote was deferred retired AT the
    // deferral, with the reopen class, so it rotates nothing more — even once
    // another process has promoted — and the refusal changes nothing. This
    // arm used to rotate that same handle again; re-shaped, not deleted.
    let before = manifest(root);
    match s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap()) {
        Err(StoreError::StaleUnlock(m)) => assert!(m.contains("O266"), "{m}"),
        other => panic!("a handle whose promote was deferred rotated again: {other:?}"),
    }
    assert_eq!(
        manifest(root),
        before,
        "the refused rotation changed nothing"
    );
    assert!(!staging(root).exists());
    assert_released(root, &s, "retired-after-deferral");
    // Reopened, it rotates.
    drop(s);
    let mut s = reopen(root);
    s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
        .expect("with nothing holding the vault, the rotation runs");
    assert_ne!(manifest(root), before);
    assert_released(root, &s, "success");
    s.upsert(&drawer("the rotated handle writes", 9)).unwrap();
    assert_eq!(s.anchor_failures(), 0);
    drop(s);
    assert!(reopen(root).verify().unwrap().ok());
}

/// **The fence is HELD from staging through the promote (ROADMAP O257)**:
/// paused at Staged and at Committed, a writable open AND a read-only open in
/// another process are both refused as `VaultHeld` — never served, and the
/// read-only one never through `immutable=1`, which read the main file without
/// the WAL and refused with a false "schema predates this build" (probe P-RO,
/// D1).
#[test]
fn the_fence_holds_at_both_pauses_against_writable_and_read_only_opens() {
    for phase in [pause::Phase::Staged, pause::Phase::Committed] {
        let (dir, mut s) = fresh(SecurityLevel::Sealed);
        s.upsert(&drawer("a memory the rotation seals", 0)).unwrap();
        drop(s);
        let root = dir.path().to_path_buf();
        let (at_tx, at_rx) = std::sync::mpsc::channel::<()>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let go_rx = std::sync::Mutex::new(go_rx);
        pause::set(
            &vdir(&root),
            std::sync::Arc::new(move |p| {
                if p == phase {
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
                let mgr = VaultManager::open(&root, None).unwrap();
                let mut s = VaultStore::open(mgr.unlock(VAULT).unwrap()).unwrap();
                s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
                    .map(|_| s)
            })
        };
        at_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the rotation reaches its pause");
        let tag = format!("{phase:?}");
        let writable = spawn_child("opener", &child_env(&root, 1, &format!("w-{tag}")));
        let read_only = spawn_child("ro-opener", &child_env(&root, 0, &format!("r-{tag}")));
        let (w, r) = (child_report(writable), child_report(read_only));
        assert_eq!(
            w["held_err"], "1",
            "{tag}: a writable open was not held: {w:?}"
        );
        assert_eq!(w["opened"], "0", "{tag}: {w:?}");
        assert_eq!(
            r["held_err"], "1",
            "{tag}: a read-only open was not held: {r:?}"
        );
        assert_eq!(r["ro_opened"], "0", "{tag}: {r:?}");
        go_tx.send(()).unwrap();
        let s = rotating.join().unwrap().expect("the rotation succeeds");
        assert_released(&root, &s, &format!("after-{tag}"));
    }
}

/// **The write door (ROADMAP O257).** O254 stopped a stale handle at its
/// ANCHOR, after its first write had committed under the retired keys — the
/// write that made the next open refuse the vault (pinned in e2e as O254's
/// cost). The keycheck is now read inside every audited write's own
/// transaction: a handle whose marker the database no longer holds — another
/// build's rotation beside it, or an edited marker — commits nothing, the
/// read-audit append included, and an absent marker is refused as the anchor
/// refuses it. Nothing latches: once the marker is this handle's again, it
/// writes.
#[test]
fn a_handle_whose_keys_the_database_no_longer_holds_writes_nothing() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    s.upsert(&drawer("the memory before", 0)).unwrap();
    let root = dir.path();
    let own = keycheck_of(root).expect("premise: the open seeded the marker");
    s.set_read_audit(true);
    for (arm, marker) in [("foreign", Some("00".repeat(32))), ("absent", None)] {
        set_keycheck(root, marker.as_deref());
        let (count, height) = (s.count().unwrap(), crate::chain::writes(&s.conn).unwrap());
        for (what, refused) in [
            ("a save", s.upsert(&drawer("after", 1)).err()),
            (
                "an audited write",
                s.audit_migration_standalone("o257-door", arm, 0, 0).err(),
            ),
            (
                "a read under read-audit",
                s.search("memory", &crate::SearchOptions::default()).err(),
            ),
        ] {
            match refused {
                Some(StoreError::IntegrityFinding(m)) => {
                    assert!(m.contains("O257"), "{arm} marker, {what}: {m}")
                }
                other => panic!("{arm} marker, {what}: must refuse, got {other:?}"),
            }
        }
        assert_eq!(s.count().unwrap(), count, "{arm}: a row was committed");
        assert_eq!(crate::chain::writes(&s.conn).unwrap(), height, "{arm}");
    }
    set_keycheck(root, Some(&own));
    s.upsert(&drawer("the marker is this handle's again", 2))
        .expect("no latch: the door is re-evaluated per write");
    assert!(s.vault.retired().is_none());
    drop(s);
    assert!(reopen(root).verify().unwrap().ok());
}

/// **A present foreign keycheck, decided by the evidence around it (ROADMAP
/// O257).** Three states, and the refuter's point is the middle one: the
/// state a pre-1.7 re-seed LEFT — rotated manifest, rotated data, the OLD
/// marker — is an intact vault that 1.6.x heals, and a build that refused it
/// as tampering would be a MAJOR change. So: the chain replays under the
/// manifest's keys ⇒ re-seeded with a note (read-only: served, noted,
/// untouched); a manifest restored from BEFORE a rotation ⇒ an integrity
/// verdict that rewrites nothing, on both postures; and an unchanged torn
/// staging file beside that restored manifest is STILL an integrity verdict,
/// never a race — comparing with what the unlock attached would have made it a
/// reopen on every retry.
#[test]
fn a_foreign_keycheck_heals_refuses_as_integrity_or_reads_as_a_race_by_the_evidence() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    s.upsert(&drawer("a memory that outlives two rotations", 0))
        .unwrap();
    let root = dir.path();
    let mgr = VaultManager::open(root, None).unwrap();
    let old_manifest = manifest(root);
    let old_kc = keycheck_of(root).unwrap();
    s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
        .unwrap();
    drop(s);
    let new_kc = keycheck_of(root).unwrap();
    assert_ne!(old_kc, new_kc, "premise: the rotation moved the marker");

    // The pre-1.7 re-seed's leftover: rotated manifest and data, OLD marker.
    set_keycheck(root, Some(&old_kc));
    let ro = VaultStore::open_read_only(
        mgr.unlock_as(VAULT, Access::ReadOnly).unwrap(),
        Box::new(undercroft_core::HashEmbedder),
    )
    .expect("a read-only open serves the intact vault");
    assert!(ro
        .unhealed()
        .iter()
        .any(|n| n.contains("a writable open re-seeds it")));
    assert_eq!(ro.count().unwrap(), 1);
    drop(ro);
    assert_eq!(keycheck_of(root).unwrap(), old_kc, "a read-only open wrote");
    let s = reopen(root);
    assert_eq!(
        keycheck_of(root).unwrap(),
        new_kc,
        "re-seeded to this generation"
    );
    assert!(s
        .unhealed()
        .iter()
        .any(|n| n.contains("re-seeded to this generation")));
    assert!(s.verify().unwrap().ok());
    drop(s);

    // A manifest restored from before the rotation: integrity, both postures.
    std::fs::write(vdir(root).join("vault.json"), &old_manifest).unwrap();
    for torn in [false, true] {
        if torn {
            std::fs::write(staging(root), b"{\"half-written\":").unwrap();
        }
        match VaultStore::open(mgr.unlock(VAULT).unwrap()) {
            Err(StoreError::IntegrityFinding(m)) => {
                assert!(m.contains("different key generations"), "torn={torn}: {m}")
            }
            other => panic!(
                "torn={torn}: must be an integrity verdict, got {:?}",
                other.err()
            ),
        }
        match VaultStore::open_read_only(
            mgr.unlock_as(VAULT, Access::ReadOnly).unwrap(),
            Box::new(undercroft_core::HashEmbedder),
        ) {
            Err(StoreError::IntegrityFinding(_)) => {}
            other => panic!(
                "torn={torn}: read-only must refuse too, got {:?}",
                other.err()
            ),
        }
        assert_eq!(keycheck_of(root).unwrap(), new_kc, "torn={torn}: rewritten");
    }
}

/// **The discard's identity (ROADMAP O257, the R1/R2 sequence).** An open
/// attached one rotation's ABANDONED staging file (R1) and connected only after
/// a LATER rotation (R2) committed and failed to promote. Its discard used to
/// remove whatever `.next` was on disk — R2's, the only copy of the new salt —
/// and its re-seed wrote the old keycheck: the vault's data sealed under keys
/// no file could derive. Now the staged file changed since that open read it,
/// so the open is told to reopen and removes nothing, and the reopen promotes
/// R2's generation.
#[test]
fn an_open_that_attached_an_older_staging_file_never_deletes_a_newer_one() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    s.upsert(&drawer("a memory R2 seals", 0)).unwrap();
    drop(s);
    let root = dir.path();
    let mgr = VaultManager::open(root, None).unwrap();
    // R1: a rotation that staged and never committed.
    let mut r1 = mgr.rotation_candidate(VAULT).unwrap();
    r1.save_manifest_pending(&undercroft_vault::Vault::chain_genesis_hex(), 1)
        .unwrap();
    let p1 = std::fs::read(staging(root)).unwrap();
    // U reads the vault now, attaching R1's file, and connects later.
    let early = mgr.unlock(VAULT).unwrap();
    assert!(early.has_pending(), "premise: R1's file attached");
    // R2: its own open discards R1's file (unchanged since it read it), then
    // it rotates, and its promote fails every attempt.
    let mut s = reopen(root);
    assert!(
        !staging(root).exists(),
        "the open discarded R1's abandoned file"
    );
    pause::set(
        &vdir(root),
        std::sync::Arc::new(|phase| {
            if phase == pause::Phase::Committed {
                fixture::fail_times(fixture::Fault::Rename, crate::rotate::PROMOTE_ATTEMPTS);
            }
        }),
    );
    let report = s
        .rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
        .unwrap();
    assert!(
        report.promote_deferred.is_some(),
        "premise: R2's promote failed"
    );
    let p2 = std::fs::read(staging(root)).unwrap();
    assert_ne!(p1, p2);
    let r2_kc = keycheck_of(root);
    drop(s);

    match VaultStore::open(early) {
        Err(StoreError::StaleUnlock(_)) => {}
        other => panic!("U must be told to reopen, got {:?}", other.err()),
    }
    assert_eq!(
        std::fs::read(staging(root)).unwrap(),
        p2,
        "R2's staged manifest — the only copy of its salt — must survive"
    );
    assert_eq!(keycheck_of(root), r2_kc, "U re-seeded the marker");
    let s = reopen(root);
    assert!(
        !staging(root).exists(),
        "the reopen promoted R2's generation"
    );
    assert!(s.verify().unwrap().ok());
    assert_eq!(s.count().unwrap(), 1);
}

/// **A staged file naming the CURRENT generation never lowers the anchor
/// (ROADMAP O257).** It is what a promote leaves when it stops between writing
/// the manifest and removing the staged file — or an older copy of this
/// generation's manifest planted as one. Before O257 it read as a committed
/// rotation and was RENAMED over `vault.json`, moving the anchor down (and the
/// next heal wrote a note that read as a restored manifest). Now it is settled:
/// removed when it is still the bytes the unlock read, `vault.json` untouched.
#[test]
fn a_staged_file_of_the_current_generation_is_removed_and_never_lowers_the_anchor() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    s.upsert(&drawer("first", 0)).unwrap();
    let root = dir.path();
    let earlier = manifest(root);
    s.upsert(&drawer("second", 1)).unwrap();
    s.upsert(&drawer("third", 2)).unwrap();
    let later = manifest(root);
    assert_ne!(earlier, later, "premise: the anchor moved");
    drop(s);
    std::fs::write(staging(root), &earlier).unwrap();
    let s = reopen(root);
    assert_eq!(manifest(root), later, "the anchor was moved down");
    assert!(!staging(root).exists(), "the leftover is removed");
    assert!(s.unhealed().is_empty(), "{:?}", s.unhealed());
    assert_eq!(s.stats().unwrap().anchor_lag, Some(0));
}

// ---------------------------------------------------------------------------
// ROADMAP O276, O278: a handle that lets go of the vault
// ---------------------------------------------------------------------------

type DrawerRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

fn drawer_row(conn: &rusqlite::Connection, id: &str) -> DrawerRow {
    conn.query_row(
        "SELECT meta_json, content, embedding, tag FROM drawers WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .unwrap()
}

/// O252's replay attack, made by whatever connection runs it: the record of
/// the drawer's correction relabelled out of its namespace, and the row the
/// correction replaced written back.
fn replay_the_correction(conn: &rusqlite::Connection, id: &str, older: &DrawerRow) {
    let relabelled = conn
        .execute(
            "UPDATE audit SET record_id = 'read/x' WHERE seq = \
             (SELECT MAX(seq) FROM audit WHERE record_id = ?1)",
            [id],
        )
        .unwrap();
    assert_eq!(
        relabelled, 1,
        "premise: the correction's record is relabelled"
    );
    let n = conn
        .execute(
            "UPDATE drawers SET meta_json = ?1, content = ?2, embedding = ?3, tag = ?4 \
             WHERE id = ?5",
            rusqlite::params![older.0, older.1, older.2, older.3, id],
        )
        .unwrap();
    assert_eq!(n, 1, "premise: the older drawer row is written back");
}

/// Whether another connection can read the vault right now.
fn another_connection_reads(root: &Path) -> bool {
    let probe = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
    probe.busy_timeout(Duration::ZERO).unwrap();
    probe
        .query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0))
        .is_ok()
}

/// The state the release fallback exists for (O278's M1): this handle's OWN
/// connection left holding the vault exclusively — what a failed return to
/// NORMAL leaves, and by reading what Windows' PENDING byte after a refused
/// fence leaves (O257's D2). Real, never the proof-refusal seam: the seam
/// fails a proof that nothing holds, which the old fallback passed too.
fn hold_the_vault_with_its_own_connection(s: &VaultStore, root: &Path) {
    let mode: String = s
        .conn
        .query_row("PRAGMA locking_mode = EXCLUSIVE", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        mode, "exclusive",
        "premise: the handle's connection is exclusive"
    );
    s.conn.execute_batch("BEGIN EXCLUSIVE; COMMIT").unwrap();
    assert!(
        !another_connection_reads(root),
        "premise: the handle's own connection holds the vault"
    );
}

/// The reopen class (ROADMAP O278): what a handle that let go of the vault
/// answers — `StaleUnlock` from the store's doors, `HandleReleased` from a
/// manifest read. Asserted by VARIANT: an `is_err()` would pass the tamper
/// verdict this exists to rule out.
fn assert_reopen_class<T: std::fmt::Debug>(what: &str, r: Result<T, StoreError>) {
    match r {
        Err(StoreError::StaleUnlock(m)) => assert!(m.contains("O278"), "{what}: {m}"),
        Err(StoreError::Vault(undercroft_vault::VaultError::HandleReleased(m))) => {
            assert!(m.contains("closed its database connection"), "{what}: {m}")
        }
        other => panic!("{what}: a released handle must answer the reopen class, got {other:?}"),
    }
}

/// A door the retirement does not reach first (O278 ruling item 3): it meets
/// the placeholder and is refused — loudly, never Ok with vault data, and
/// never a verdict about the vault.
fn assert_refused_without_a_verdict<T: std::fmt::Debug>(what: &str, r: Result<T, StoreError>) {
    use undercroft_vault::VaultError as V;
    match r {
        Ok(v) => panic!("{what}: a released handle answered Ok: {v:?}"),
        Err(
            e @ (StoreError::Integrity(_)
            | StoreError::IntegrityFinding(_)
            | StoreError::Vault(V::ManifestTampered)
            | StoreError::Vault(V::CorruptManifest(_))),
        ) => panic!("{what}: a released handle answered a verdict: {e:?}"),
        Err(_) => {}
    }
}

fn is_released(s: &VaultStore) -> bool {
    matches!(
        s.vault.retirement(),
        Some(undercroft_vault::Retirement::Released(_))
    )
}

fn hash_embedder(
    _: &undercroft_vault::Vault,
) -> Result<Box<dyn undercroft_core::embed::Embedder + Send>, StoreError> {
    Ok(Box::new(undercroft_core::HashEmbedder))
}

/// **ROADMAP O276, re-shaped by O278 — never deleted.** It pinned that a
/// connection the handle REPLACED took nothing the old one cached: the label
/// guard keys its replay verdict by `PRAGMA data_version`, which a fresh
/// connection restarts (O266's P5), so a correction another connection rolled
/// back was served as the OLD account number after the swap. Since O278 the
/// fallback replaces the connection with a placeholder and reattaches nothing,
/// so the handle serves NOTHING — a stronger answer than a replay. The
/// forgotten verdict is still the helper's, and its source gate below pins
/// it; its behavioural counterfactual no longer bites here, because nothing
/// reads through the placeholder. The rollback itself is refused by a fresh
/// open's first guarded read.
///
/// The fence is refused by an idle connection holding the vault open, and
/// the release proof through the test fault, which stands in for the PENDING
/// byte such a refusal leaves on Windows (O257's D2).
#[test]
fn a_replaced_connection_forgets_the_label_verdict_the_old_one_cached() {
    use crate::{Read, ReadOp};
    for level in [SecurityLevel::HmacOnly, SecurityLevel::Sealed] {
        let (dir, mut s) = fresh(level);
        let root = dir.path();
        let first = drawer("the account number is 1111", 0);
        s.upsert(&first).unwrap();
        let older = drawer_row(&s.conn, &first.id);
        s.upsert(&drawer("the account number is 2222 (corrected)", 0))
            .unwrap();
        let read = s
            .get(&first.id, Read::Returned(ReadOp::Get))
            .unwrap()
            .expect("premise: the corrected drawer reads");
        assert!(read.content.contains("2222"), "{level:?}: premise");
        assert!(
            s.replays() >= 1,
            "{level:?}: premise: the guard replayed and cached its verdict"
        );

        // Another connection rolls the correction back, and stays OPEN.
        let other = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
        replay_the_correction(&other, &first.id, &older);

        // The fence's wait is the connection's own busy timeout; shortened
        // only so the refusal does not cost the suite five seconds.
        s.conn.busy_timeout(Duration::from_millis(300)).unwrap();
        pause::refuse_proof(&vdir(root), true);
        let mgr = VaultManager::open(root, None).unwrap();
        let refused = s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap());
        pause::refuse_proof(&vdir(root), false);
        match refused {
            Err(StoreError::VaultHeld(m)) => assert!(m.contains("O257"), "{m}"),
            other => panic!("{level:?}: the fence must refuse beside the other, got {other:?}"),
        }
        assert_eq!(
            s.lock_reconnects(),
            1,
            "{level:?}: premise: the fallback was taken"
        );
        assert!(is_released(&s), "{level:?}: the handle let go of the vault");
        assert_reopen_class(
            &format!("{level:?} get"),
            s.get(&first.id, Read::Returned(ReadOp::Get)),
        );
        drop(other);
        drop(s);
        match reopen(root).get(&first.id, Read::Returned(ReadOp::Get)) {
            Err(StoreError::IntegrityFinding(m)) => assert!(m.contains("verify"), "{m}"),
            other => panic!("{level:?}: a fresh open must refuse the rollback, got {other:?}"),
        }
    }
}

/// **ROADMAP O278, the pinned cost INVERTED** — it was
/// `o278_the_fallback_cannot_replace_a_connection_whose_own_lock_blocks_the_replacement`,
/// which measured the fallback opening its replacement beside the lock it was
/// to release: 5.01 s of busy wait, the vault still held, the counter reading
/// one. Now the fallback CLOSES the connection and reattaches nothing: the
/// vault is released at once, another process writes, and every door the
/// release reaches answers the reopen class. Driven by the real own-lock.
#[test]
fn o278_the_fallback_releases_a_connection_whose_own_lock_held_the_vault() {
    use crate::{Read, ReadOp};
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    let kept = drawer("a memory the released handle must not serve", 0);
    s.upsert(&kept).unwrap();
    let root = dir.path();
    hold_the_vault_with_its_own_connection(&s, root);
    let started = Instant::now();
    s.prove_released();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the release waited {:?} — it opened something beside the lock it was to release",
        started.elapsed()
    );
    assert_eq!(
        s.lock_reconnects(),
        1,
        "the fallback was taken, and counted"
    );
    assert!(is_released(&s), "{:?}", s.vault.retirement());
    assert!(
        s.unhealed().iter().any(|n| n.contains("O278")),
        "the release is said: {:?}",
        s.unhealed()
    );
    assert!(another_connection_reads(root), "the vault is released");
    another_process_writes(root, "o278-released");
    assert_reopen_class("get", s.get(&kept.id, Read::Returned(ReadOp::Get)));
    assert_reopen_class("verify", s.verify());
    assert_reopen_class("witness_emit", s.witness_emit());
    // The snapshot door itself (the ruling's item 2). Every door above reads
    // the manifest anchor before or inside its snapshot (O253's order), where
    // the resolver refuses first — so none of them sees this door, and the
    // counterfactual that removed its check stayed green until this line.
    assert_reopen_class("snapshot", s.snapshot(|_| Ok(())));
    assert_refused_without_a_verdict(
        "upsert",
        s.upsert(&drawer("a write through the released handle", 1)),
    );
    assert_refused_without_a_verdict("count", s.count());
    drop(s);
    let s = reopen(root);
    assert!(s.verify().unwrap().ok());
    assert_eq!(
        s.count().unwrap(),
        2,
        "the other process's write landed, and nothing of the released handle's"
    );
}

/// **ROADMAP O278: a released handle reads no manifest.** After another
/// process rotated the vault, a manifest read under this handle's keys fails
/// its MAC — the tamper verdict, false, and paging an operator. `verify`, the
/// witness, a backup and an erasure receipt's check read the manifest by path
/// BEFORE they touch the database, so the refusal lives in the vault crate's
/// one resolver. The graph secret is warmed first: cold, `verify` would fail
/// on the placeholder before it read the manifest and the arm would pass
/// without the fix.
#[test]
fn o278_a_released_handle_reads_no_manifest_after_another_process_rotates() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    let root = dir.path().to_path_buf();
    s.upsert(&drawer("a memory the rotation seals", 0)).unwrap();
    let doomed = drawer("a note the subject asked us to erase", 1);
    s.upsert(&doomed).unwrap();
    let receipt = s
        .forget_with_proof(std::slice::from_ref(&doomed.id))
        .unwrap();
    assert!(
        s.verify().unwrap().ok(),
        "premise: verify ran, which warms the graph secret"
    );
    hold_the_vault_with_its_own_connection(&s, &root);
    s.prove_released();
    assert!(is_released(&s));
    // The release is what lets another handle take the fence at all.
    let mgr = VaultManager::open(&root, None).unwrap();
    let mut other = reopen(&root);
    other
        .rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
        .expect("with the vault released, another handle rotates it");
    drop(other);
    assert_reopen_class("verify", s.verify());
    assert_reopen_class("witness_emit", s.witness_emit());
    assert_reopen_class("backup", s.backup(&root.join("backups")));
    // A receipt this handle's own keys minted replays by computation alone —
    // the manifest is read only on the path for a receipt they cannot replay
    // (`forget.rs`, the recorded-evidence arm) — and the check that the
    // drawers are gone then meets the placeholder: refused, never a verdict.
    assert_refused_without_a_verdict(
        "verify_forget_attestation",
        s.verify_forget_attestation(&receipt),
    );
    drop(s);
    assert!(
        reopen(&root).verify().unwrap().ok(),
        "a fresh open answers to the rotated keys"
    );
}

/// **ROADMAP O278: a released handle lets a restore run, and does not
/// re-enter the vault after it.** A reopen by path here would have read the
/// file the restore set aside and written into the restored directory's
/// `-wal` (the ruling's PF); the released handle holds nothing, so O69's hold
/// is taken, and nothing the handle is asked afterwards touches the restored
/// directory.
#[test]
fn o278_a_released_handle_lets_a_restore_run_and_does_not_re_enter_the_vault() {
    use crate::{Read, ReadOp};
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    let root = dir.path().to_path_buf();
    let kept = drawer("a memory the archive keeps", 0);
    s.upsert(&kept).unwrap();
    let backups = root.join("backups");
    let archive = match s.backup(&backups).unwrap() {
        crate::BackupOutcome::Created(report) => backups.join(&report.name),
        crate::BackupOutcome::Refused(v) => panic!("premise: the backup is taken: {v:?}"),
    };
    s.upsert(&drawer("written after the backup", 1)).unwrap();
    hold_the_vault_with_its_own_connection(&s, &root);
    s.prove_released();
    assert!(is_released(&s));
    let mgr = VaultManager::open(&root, None).unwrap();
    match crate::restore_archive(&mgr, &archive, None, true, &hash_embedder).unwrap() {
        crate::RestoreOutcome::Restored(_) => {}
        crate::RestoreOutcome::Refused(v) => {
            panic!("with the vault released, the restore runs: {v:?}")
        }
    }
    let files = || {
        let mut v: Vec<String> = std::fs::read_dir(vdir(&root))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    let before = files();
    assert_reopen_class("get", s.get(&kept.id, Read::Returned(ReadOp::Get)));
    assert_reopen_class("verify", s.verify());
    assert_refused_without_a_verdict("count", s.count());
    assert_eq!(
        files(),
        before,
        "the released handle made nothing in the restored directory"
    );
    drop(s);
    let r = reopen(&root);
    assert!(r.verify().unwrap().ok());
    assert_eq!(r.count().unwrap(), 1, "the restored vault is the archive's");
}

/// **ROADMAP O278: a release OUTRANKS a deferred promote.** A handle whose
/// promote was deferred serves reads against the staged manifest (O266); a
/// released one has nothing behind it, so the release must replace the
/// deferral — "the first reason stands" would keep the handle serving reads
/// that fall through to the placeholder. The deferral's own warning stays
/// said.
#[test]
fn o278_a_release_outranks_a_deferred_promote() {
    use crate::{Read, ReadOp};
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    let root = dir.path();
    let kept = drawer("a memory the rotation seals", 0);
    s.upsert(&kept).unwrap();
    pause::set(
        &vdir(root),
        std::sync::Arc::new(|phase| {
            if phase == pause::Phase::Committed {
                fixture::fail_times(fixture::Fault::Rename, crate::rotate::PROMOTE_ATTEMPTS);
            }
        }),
    );
    pause::refuse_proof(&vdir(root), true);
    let mgr = VaultManager::open(root, None).unwrap();
    let report = s.rotate_keys(mgr.rotation_candidate(VAULT).unwrap());
    pause::refuse_proof(&vdir(root), false);
    pause::set(&vdir(root), std::sync::Arc::new(|_| {}));
    let report = report.expect("a committed rotation answers Ok (O254 ruling item 3)");
    assert!(
        report.promote_deferred.is_some(),
        "premise: the promote was deferred"
    );
    assert!(
        is_released(&s),
        "the release outranks the deferral: {:?}",
        s.vault.retirement()
    );
    assert!(
        s.unhealed().iter().any(|n| n.contains("do NOT delete")),
        "the deferral's warning is still said: {:?}",
        s.unhealed()
    );
    assert_reopen_class("get", s.get(&kept.id, Read::Returned(ReadOp::Get)));
    drop(s);
    let r = reopen(root);
    assert!(
        !staging(root).exists(),
        "the next writable open promoted it"
    );
    assert!(r.verify().unwrap().ok());
}

/// **ROADMAP O278: the rotation's report carries the head it committed**,
/// read inside its hold — what both surfaces print, so neither reads through
/// a handle that may have let go of the vault on its way out.
#[test]
fn o278_the_rotation_report_carries_the_committed_head() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    let root = dir.path();
    s.upsert(&drawer("a memory the rotation seals", 0)).unwrap();
    let mgr = VaultManager::open(root, None).unwrap();
    let report = s
        .rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
        .unwrap();
    assert_eq!(s.lock_reconnects(), 0, "premise: an ordinary release");
    drop(s);
    let (head, writes) = reopen(root).chain_state().unwrap();
    assert_eq!(report.chain_head, head);
    assert_eq!(report.writes, writes);
}

/// **ROADMAP O278: a read-only handle is refused a rotation BEFORE the
/// fence.** It answered a raw `SQLITE_READONLY` at `BEGIN EXCLUSIVE`, and a
/// refused release proof — a write-protected mount can fail one — would then
/// have let go of a vault it was only reading. The proof is refused here to
/// show the refusal comes first.
#[test]
fn o278_a_read_only_handle_is_refused_a_rotation_before_the_fence() {
    let (dir, mut s) = fresh(SecurityLevel::Sealed);
    let root = dir.path();
    s.upsert(&drawer("a memory", 0)).unwrap();
    drop(s);
    let m = VaultManager::open_as(root, None, Access::ReadOnly).unwrap();
    let mut ro = VaultStore::open_read_only(
        m.unlock_as(VAULT, Access::ReadOnly).unwrap(),
        Box::new(undercroft_core::HashEmbedder),
    )
    .unwrap();
    let before = manifest(root);
    pause::refuse_proof(&vdir(root), true);
    let mgr = VaultManager::open(root, None).unwrap();
    let got = ro.rotate_keys(mgr.rotation_candidate(VAULT).unwrap());
    pause::refuse_proof(&vdir(root), false);
    match got {
        Err(StoreError::Invalid(m)) => assert!(m.contains("read-only"), "{m}"),
        other => panic!("a read-only handle must be refused a rotation, got {other:?}"),
    }
    assert_eq!(ro.lock_reconnects(), 0, "the fallback was never reached");
    assert!(ro.vault.retirement().is_none());
    assert!(!staging(root).exists(), "nothing was staged");
    assert_eq!(manifest(root), before);
    let q: i64 = ro
        .conn
        .query_row("PRAGMA query_only", [], |r| r.get(0))
        .unwrap();
    assert_eq!(q, 1, "the connection is still the read-only one");
}

// ---------------------------------------------------------------------------
// The source gate
// ---------------------------------------------------------------------------

/// A file's production text: everything before its `mod tests`.
fn production(path: &str) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    match text.find("\n#[cfg(test)]\nmod tests") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

fn sources(dir: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .filter(|p| !p.ends_with("anchor_tests.rs"))
        .map(|p| {
            let p = p.display().to_string();
            (p.clone(), production(&p))
        })
        .collect();
    out.sort();
    out
}

/// The body of `fn <name>` in `text`, up to the next top-level item.
fn body_of<'a>(text: &'a str, name: &str) -> &'a str {
    let at = text
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("no fn {name}"));
    let rest = &text[at..];
    let end = rest[1..]
        .find("\n    fn ")
        .or_else(|| rest[1..].find("\nfn "))
        .map_or(rest.len(), |e| e + 1);
    &rest[..end]
}

/// **ROADMAP O276, re-pointed by O278: a handle's connection is replaced in
/// ONE place — by a placeholder, the vault's connection CLOSED — and that
/// place forgets the label guard's cached verdict, and nothing it or the
/// fallback runs opens the vault again.** Counted over every store source,
/// in each form a connection can be replaced: an assignment to a `.conn`
/// field, or a `mem::replace`, `mem::swap` or `mem::take` of one. Every one
/// must sit in `replace_connection`; the helper must close the old connection
/// explicitly (rusqlite's drop discards a failed close); and neither the
/// helper nor `prove_released` may name a connector — a count alone would
/// pass an open written back into either. The counter is proved on a planted
/// text first, which must find an assignment and a replace and neither a
/// comparison nor a comment.
#[test]
fn a_connection_is_replaced_in_one_place_and_that_place_forgets_the_verdict() {
    fn replacements(text: &str) -> usize {
        text.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| {
                let assigned = l
                    .match_indices(".conn =")
                    .any(|(at, m)| !l[at + m.len()..].starts_with('='));
                let moved = ["mem::replace(&mut ", "mem::swap(&mut ", "mem::take(&mut "]
                    .iter()
                    .any(|m| l.contains(m) && l.contains(".conn"));
                assigned || moved
            })
            .count()
    }
    let planted = "fn a(&mut self) { self.conn = c; }\n\
                   fn b(&mut self) { let _ = std::mem::replace(&mut self.conn, c); }\n\
                   fn c(&self) -> bool { self.conn == d }\n\
                   // self.conn = e;\n";
    assert_eq!(
        replacements(planted),
        2,
        "premise: the counter sees an assignment and a replace, and neither a comparison \
         nor a comment"
    );
    let store = sources(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    assert!(store.len() > 10, "premise: sources read");
    let lib = &store.iter().find(|(p, _)| p.ends_with("lib.rs")).unwrap().1;
    let helper = body_of(lib, "replace_connection");
    let fallback = body_of(lib, "prove_released");
    let total: usize = store.iter().map(|(_, t)| replacements(t)).sum();
    assert!(
        replacements(helper) > 0,
        "premise: the helper replaces the connection"
    );
    assert_eq!(
        total,
        replacements(helper),
        "a connection is replaced outside the one helper"
    );
    assert!(
        helper.contains("std::mem::replace(&mut self.conn"),
        "the helper swaps a placeholder in"
    );
    assert!(
        helper.contains(".close()"),
        "and closes the vault's connection explicitly"
    );
    assert!(
        helper.contains("self.forget_label_verdict()"),
        "and forgets the cached verdict"
    );
    for (name, body) in [("replace_connection", helper), ("prove_released", fallback)] {
        for connector in [
            "connect_writable(",
            "connect_read_only(",
            "Connection::open(",
            "open_with_flags(",
        ] {
            assert!(
                !body.contains(connector),
                "{name} opens the vault again through {connector} (ROADMAP O278: nothing \
                 reattaches)"
            );
        }
    }
    assert!(
        fallback.contains("self.replace_connection()") && fallback.contains("self.vault.release("),
        "the fallback releases through the helper and marks the handle released"
    );
}

/// **ROADMAP O278: no surface reads through the handle after a rotation.**
/// A handle whose release could not be proven let go of the vault on its way
/// out and answers the reopen class, so a `chain_state()` after
/// `rotate_keys` turned a COMMITTED rotation into an error — which invites a
/// second rotation. Both surfaces print the head from the rotation's report.
#[test]
fn no_surface_reads_the_handle_after_a_rotation() {
    let crates = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let main = production(&format!("{crates}/undercroft-cli/src/main.rs"));
    let tenant = production(&format!("{crates}/undercroft-cli/src/tenant.rs"));
    let arm = {
        let at = main
            .find("VaultAction::Rotate { name } =>")
            .expect("premise: the CLI's rotate arm");
        let rest = &main[at..];
        let end = rest[1..]
            .find("VaultAction::")
            .map_or(rest.len(), |e| e + 1);
        &rest[..end]
    };
    for (surface, body) in [("the CLI", arm), ("/v1", body_of(&tenant, "rotate"))] {
        let (_, after) = body
            .split_once(".rotate_keys(")
            .unwrap_or_else(|| panic!("premise: {surface} rotates"));
        assert!(
            !after.contains("chain_state("),
            "{surface} reads the chain through the handle after a rotation"
        );
        assert!(
            after.contains("report.chain_head"),
            "premise: {surface} prints the head from the report"
        );
    }
}

/// **Every writer of `vault.json` and `vault.json.next`, and every caller of
/// `anchor_manifest`, counted across the crates (ROADMAP O254).** The ruling
/// names the silent failures: a `vault.json` writer that survives outside the
/// door, and an anchor "optimised" back into a caller's own hands. So:
/// `anchor_manifest` has ONE production caller, the door's; the vault crate
/// renames in exactly one place — the one writer, which the promote now goes
/// through (ROADMAP O257) — deletes only files it can name as its own and
/// never in an unlock, and creates a file only through `create_new`; each
/// promote and staged-file removal in the store runs under the write lock or
/// inside the rotation's fence; the one writer
/// keeps the anchor's durability at one file fsync and one directory sync;
/// and no other crate writes the manifest. The CLI's `copy_dir` — restore
/// into `vaults/` under O69's exclusive hold, which refuses while any handle
/// has the vault open — is the one whole-directory writer, pinned by its call
/// sites so a new one is ruled; backup create copies the verified snapshot
/// through the store since ROADMAP O256, and its archive's manifest goes
/// through the one writer.
#[test]
fn every_manifest_writer_and_anchor_caller_is_the_one_the_ruling_names() {
    let crates = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let store = sources(&format!("{crates}/undercroft-store/src"));
    let vault = production(&format!("{crates}/undercroft-vault/src/lib.rs"));
    let cli = sources(&format!("{crates}/undercroft-cli/src"));
    let orch = sources(&format!("{crates}/undercroft-orchestrator/src"));
    assert!(
        store.len() > 10 && !cli.is_empty() && !orch.is_empty(),
        "premise: sources read"
    );

    // One production caller of `anchor_manifest`, and it is the door's.
    let callers: Vec<&String> = store
        .iter()
        .chain(&cli)
        .chain(&orch)
        .filter(|(_, t)| t.contains(".anchor_manifest("))
        .map(|(p, _)| p)
        .collect();
    let total: usize = store
        .iter()
        .chain(&cli)
        .chain(&orch)
        .map(|(_, t)| t.matches(".anchor_manifest(").count())
        .sum();
    assert_eq!(total, 1, "anchor_manifest callers: {callers:?}");
    let lib = &store.iter().find(|(p, _)| p.ends_with("lib.rs")).unwrap().1;
    assert!(body_of(lib, "anchor_under_lock").contains(".anchor_manifest("));
    assert!(body_of(lib, "anchor_under_lock").contains("WriteLock::begin("));

    // The vault crate: ONE rename — the one writer's — since the promote
    // writes the new manifest from memory through it rather than renaming the
    // staged file (ROADMAP O257, a refinement of O254 ruling item 4); one
    // `create_new`; no truncating create.
    assert_eq!(vault.matches("fs::rename(").count(), 1, "vault renames");
    assert!(body_of(&vault, "write_manifest_file").contains("fs::rename("));
    assert!(body_of(&vault, "promote").contains("write_manifest_file("));
    assert_eq!(vault.matches(".create_new(true)").count(), 1);
    assert_eq!(
        vault.matches("File::create(").count(),
        0,
        "a truncating create"
    );
    assert_eq!(
        vault.matches("write_manifest_file(").count(),
        5,
        "one def + four writers: create, staging, anchor, promote"
    );
    // Three deletions, each of a file the vault crate can name as its own: a
    // failed write's own temp, an orphan temp under the lock, and a staged
    // manifest still exactly the bytes this handle staged or read. None in an
    // unlock, on either posture (ROADMAP O257).
    assert_eq!(
        vault.matches("fs::remove_file(").count(),
        3,
        "vault deletions"
    );
    assert!(body_of(&vault, "write_manifest_file").contains("fs::remove_file("));
    assert!(body_of(&vault, "sweep_orphan_temps").contains("fs::remove_file("));
    assert!(body_of(&vault, "remove_staged_if_unchanged").contains("fs::remove_file("));
    // `unlock_as` is one line since ROADMAP O268: its body is `unlock_dir`,
    // which the stage's unlock shares, so the check reads THAT body — asserting
    // it of a one-line wrapper would pass with the deletion back in.
    assert!(
        body_of(&vault, "unlock_as").contains("self.unlock_dir("),
        "premise: unlock_as delegates to the shared body"
    );
    let shared = body_of(&vault, "unlock_dir");
    assert!(
        shared.contains("verify_hmac(") && shared.contains("pending_path()"),
        "premise: the shared body is the unlock"
    );
    assert!(
        !shared.contains("remove_file"),
        "an unlock deletes nothing (ROADMAP O257)"
    );
    let writer = body_of(&vault, "write_manifest_file");
    assert_eq!(writer.matches(".sync_all()").count(), 1, "one file fsync");
    assert_eq!(writer.matches("sync_dir(").count(), 1, "one directory sync");
    assert!(
        !vault.contains("\"vault.json.tmp\""),
        "the legacy fixed temp name"
    );

    // The ARCHIVE (ROADMAP O256): the sixth manifest writer, and the one
    // other place the crate renames or removes. Its manifest goes through the
    // one writer — the exact bytes the backup verified against — and its
    // rename is the publish of a stage; it removes only a stage of its own
    // (a failed backup's, or one a crash abandoned) and archives `prune`
    // keeps no longer.
    let archive = production(&format!("{crates}/undercroft-vault/src/backups.rs"));
    assert_eq!(
        archive.matches("write_manifest_file(").count(),
        1,
        "the archive writes its manifest once, through the one writer"
    );
    assert!(body_of(&archive, "write_manifest").contains("write_manifest_file("));
    assert_eq!(archive.matches("fs::rename(").count(), 1, "archive renames");
    assert!(body_of(&archive, "publish").contains("fs::rename("));
    assert_eq!(
        archive.matches("fs::remove_dir_all(").count(),
        3,
        "archive removals: an unpublished stage, an abandoned stage, a pruned archive"
    );
    assert!(body_of(&archive, "drop").contains("fs::remove_dir_all("));
    assert!(body_of(&archive, "sweep_stale").contains("fs::remove_dir_all("));
    assert!(body_of(&archive, "prune").contains("fs::remove_dir_all("));
    for w in [
        "fs::remove_file(",
        "File::create(",
        "fs::write(",
        "fs::copy(",
    ] {
        assert_eq!(
            archive.matches(w).count(),
            0,
            "the archive module calls {w}"
        );
    }

    // Each promote and staged-file removal in the store runs where no other
    // writer can interleave: inside `reconcile_rotation`, whose whole body is
    // under the write lock, or inside the rotation's fence BEFORE the hold is
    // dropped (ROADMAP O254, O257). Counted per call site, so a new caller
    // anywhere else fails here.
    let rotate = &store
        .iter()
        .find(|(p, _)| p.ends_with("rotate.rs"))
        .unwrap()
        .1;
    let reconcile = body_of(lib, "reconcile_rotation");
    let fenced = body_of(rotate, "rotate_keys_fenced");
    assert!(
        reconcile.contains("WriteLock::begin("),
        "premise: reconcile locks"
    );
    let (take, drop_at) = (
        fenced
            .find("ExclusiveHold::take(")
            .expect("the fence is taken"),
        fenced.find("drop(hold)").expect("the fence is dropped"),
    );
    for call in [".promote()", ".remove_staged_if_unchanged()"] {
        let total: usize = store.iter().map(|(_, t)| t.matches(call).count()).sum();
        let locked = reconcile.matches(call).count();
        let in_fence = fenced
            .match_indices(call)
            .filter(|(at, _)| *at > take && *at < drop_at)
            .count();
        assert_eq!(
            total,
            locked + in_fence,
            "{call}: a call site outside the write lock and the fence"
        );
        assert!(locked >= 1, "premise: {call} is reached from reconcile");
    }
    assert_eq!(
        fenced.matches(".promote()").count(),
        2,
        "premise: the retried promote"
    );

    // No other crate writes a manifest, and the directory writer is pinned.
    // The STORE is scanned too (ROADMAP O256's refuter: a store-crate writer
    // passed unseen), its test files aside — a test may plant a manifest.
    for (path, text) in store
        .iter()
        .filter(|(p, _)| !p.ends_with("_tests.rs"))
        .chain(&cli)
        .chain(&orch)
    {
        for line in text.lines().filter(|l| l.contains("vault.json")) {
            let code = line.split("//").next().unwrap();
            assert!(
                !["fs::write", "fs::rename", "File::create", "fs::copy"]
                    .iter()
                    .any(|w| code.contains(w)),
                "{path} writes a manifest outside the door: {line}"
            );
        }
    }
    // `copy_dir` is RETIRED (ROADMAP O268): it followed links and recursed,
    // and both restores ran it after removing the vault. Restore copies through
    // the vault crate's allowlist now, and nothing may bring the helper back.
    let copy_dir_calls: usize = cli
        .iter()
        .chain(&store)
        .map(|(_, t)| t.matches("copy_dir(").count())
        .sum();
    assert_eq!(
        copy_dir_calls, 0,
        "`copy_dir` is back: restore through the one door"
    );

    // The RESTORE (ROADMAP O268): its module writes the stage's manifest once
    // through the one writer, renames exactly three times — the live vault
    // aside, the stage in, the live vault back — all inside the swap, removes
    // only a stage (dropped or stale) and an aside after a SUCCESSFUL swap, and
    // deletes one file: an unpromoted staged manifest in its own stage.
    let restores = production(&format!("{crates}/undercroft-vault/src/restores.rs"));
    assert_eq!(
        restores.matches("write_manifest_file(").count(),
        1,
        "the stage's manifest is written once, through the one writer"
    );
    assert!(body_of(&restores, "copy").contains("write_manifest_file("));
    assert_eq!(
        restores.matches("fs::rename(").count(),
        3,
        "restore renames"
    );
    assert_eq!(
        body_of(&restores, "swap<H>").matches("fs::rename(").count(),
        3,
        "every restore rename is the swap's"
    );
    assert_eq!(
        restores.matches("fs::remove_dir_all(").count(),
        3,
        "restore removals: a stale stage, an aside after a completed swap, a dropped stage"
    );
    assert!(body_of(&restores, "sweep_stale").contains("fs::remove_dir_all("));
    assert!(body_of(&restores, "drop").contains("fs::remove_dir_all("));
    let swap = body_of(&restores, "swap<H>");
    let removed_at = swap
        .find("fs::remove_dir_all(&aside)")
        .expect("the aside is removed");
    assert!(
        swap[..removed_at].rfind("self.swapped = true").is_some()
            && swap[..removed_at].contains("now != expected"),
        "an aside is removed only after the swap completed and its manifest was re-read"
    );
    assert_eq!(restores.matches("fs::remove_file(").count(), 1);
    assert!(body_of(&restores, "discard_unpromoted_staging").contains("fs::remove_file("));
    for w in ["File::create(", "fs::write(", "fs::copy("] {
        assert_eq!(
            restores.matches(w).count(),
            0,
            "the restore module calls {w}"
        );
    }
    // One door takes the hold and swaps: the stage is swapped in nowhere else,
    // and only after the hold, which is taken only after the stage verified.
    let door = &store
        .iter()
        .find(|(p, _)| p.ends_with("restore.rs") && !p.ends_with("_tests.rs"))
        .expect("the restore door")
        .1;
    let swaps: usize = store
        .iter()
        .filter(|(p, _)| !p.ends_with("_tests.rs"))
        .chain(&cli)
        .chain(&orch)
        .map(|(_, t)| t.matches(".swap(hold)").count())
        .sum();
    assert_eq!(swaps, 1, "one swap");
    let (verified, held, swapped) = (
        door.find("storage_check()").expect("the storage check"),
        door.find("hold_vault_exclusively(").expect("the hold"),
        door.find(".swap(hold)").expect("the swap"),
    );
    assert!(
        verified < held && held < swapped,
        "verify, then hold, then swap"
    );
    let holds: usize = cli
        .iter()
        .chain(&orch)
        .map(|(_, t)| t.matches("hold_vault_exclusively(").count())
        .sum();
    assert_eq!(holds, 0, "no surface takes O69's hold itself any more");
    let unlocks: usize = store
        .iter()
        .chain(&cli)
        .chain(&orch)
        .map(|(_, t)| t.matches(".unlock_stage(").count())
        .sum();
    assert_eq!(unlocks, 1, "the stage is unlocked by the door alone");
}
