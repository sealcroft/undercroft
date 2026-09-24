//! ROADMAP O254: the post-commit anchor door, its two failure classes, the
//! stale handle it stops, and the concurrency it exists for — driven across
//! real PROCESSES, because the defect was two processes sharing one temp file
//! and a lock taken inside one process proves nothing about another.
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

/// **PROBE-254R in one process (ROADMAP O254 P1's in-process arm).** A
/// handle opened before another handle's key rotation used to write the
/// RETIRED salt back on its next anchor, and the vault could no longer
/// decrypt what the rotation sealed. Now its anchor reads the rotation's
/// keycheck under the lock and the handle RETIRES: the write before it is
/// committed, nothing reaches `vault.json`, and every later write refuses.
///
/// The stale handle's committed row is sealed under keys the vault no longer
/// answers to — O257's third route, not this entry's, and it is left to
/// that entry.
#[test]
fn a_handle_opened_before_a_rotation_retires_and_the_rotated_salt_survives() {
    let (dir, mut stale) = fresh(SecurityLevel::Sealed);
    stale.upsert(&drawer("before the rotation", 0)).unwrap();
    let mgr = VaultManager::open(dir.path(), None).unwrap();
    let mut rotator = VaultStore::open(mgr.unlock(VAULT).unwrap()).unwrap();
    rotator
        .rotate_keys(mgr.rotation_candidate(VAULT).unwrap())
        .unwrap();
    let rotated = manifest(dir.path());

    stale
        .audit_migration_standalone("o254-probe", "1", 0, 0)
        .expect("the write before the anchor is committed and answers Ok");
    assert!(
        stale.vault.retired().is_some(),
        "the stale handle must retire"
    );
    assert_eq!(stale.anchor_failures(), 1);
    assert_eq!(
        manifest(dir.path()),
        rotated,
        "the rotated salt must survive the stale handle's anchor"
    );
    assert!(stale
        .stats()
        .unwrap()
        .unhealed
        .iter()
        .any(|n| n.contains("stopped writing")));

    // Every later write refuses, as an integrity verdict, and writes nothing.
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
    assert_eq!(manifest(dir.path()), rotated);

    // The rotated handle is untouched and still anchors.
    rotator.upsert(&drawer("after the rotation", 2)).unwrap();
    assert_eq!(rotator.anchor_failures(), 0);
    assert!(rotator.vault.retired().is_none());
    drop((stale, rotator));
    reopen(dir.path());
}

/// **P1's discard window (ROADMAP O254, O257).** An open that met a
/// rotation's staged file between its staging and its commit used to read
/// the OLD keycheck and delete the file, and the rotation then committed with
/// no manifest to promote — the new salt gone. The comparison now runs under
/// the write lock the rotation holds from before it stages until it commits,
/// so the open waits for the commit and then promotes.
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
        vdir(&root).join("vault.json.next").exists(),
        "premise: the staged manifest is on disk"
    );
    let opening = {
        let root = root.clone();
        std::thread::spawn(move || reopen(&root))
    };
    // Long enough for the open to reach its reconcile and block on the lock.
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        vdir(&root).join("vault.json.next").exists(),
        "the open must not have discarded the staged manifest"
    );
    go_tx.send(()).unwrap();
    let mut rotated = rotating.join().unwrap().expect("the rotation succeeds");
    let mut opened = opening.join().unwrap();
    // Both handles answer to the new keys, and both still write.
    rotated.upsert(&drawer("the rotator writes", 1)).unwrap();
    opened.upsert(&drawer("the opener writes", 2)).unwrap();
    assert_eq!(rotated.anchor_failures() + opened.anchor_failures(), 0);
    drop((rotated, opened));
    let s = reopen(&root);
    assert!(s.verify().unwrap().chain_ok);
    assert_eq!(s.count().unwrap(), 3);
}

/// **P1's re-seed window (ROADMAP O254 probe; O257 owns the fix).** An open
/// that unlocked BEFORE a rotation staged, and reconciles between the
/// rotation's commit and its promote, still writes the OLD keycheck back —
/// `reconcile_rotation`'s re-seed, which O257 is filed to refuse. What O254
/// changes is that the salt SURVIVES it: the promote runs under the lock, and
/// the rotating handle's next anchor, reading a keycheck that is not its own,
/// retires that handle instead of writing. A pinned COST: when O257 lands,
/// the re-seed is refused and this test's retire arm inverts.
#[test]
fn p1_a_reseed_inside_the_promote_window_costs_a_retired_handle_never_the_salt() {
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
    let conn = rusqlite::Connection::open(vdir(&root).join("vault.db")).unwrap();
    let keycheck = |c: &rusqlite::Connection| -> String {
        c.query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
            r.get(0)
        })
        .unwrap()
    };
    let rotated_kc = keycheck(&conn);
    assert_ne!(
        rotated_kc,
        early.keycheck_hex(),
        "premise: the rotation committed"
    );
    // The early handle's open re-seeds the OLD keycheck and then fails on
    // the re-keyed chain, which its keys cannot replay.
    assert!(VaultStore::open(early).is_err());
    assert_ne!(
        keycheck(&conn),
        rotated_kc,
        "premise: the re-seed happened (O257)"
    );
    go_tx.send(()).unwrap();
    let mut rotated = rotating.join().unwrap().expect("the rotation succeeds");
    let promoted = manifest(&root);
    // The rotating handle's next write commits, and its anchor reads a
    // keycheck that is not its own: it retires rather than writes.
    rotated.upsert(&drawer("after the promote", 1)).unwrap();
    assert!(
        rotated.vault.retired().is_some(),
        "COST pinned (O257 inverts it): the re-seed retires the rotating handle"
    );
    assert_eq!(manifest(&root), promoted, "the rotated salt survives");
    drop(rotated);
    // A fresh open re-seeds the keycheck from the promoted manifest and the
    // vault answers to the rotated keys.
    let s = reopen(&root);
    assert_eq!(keycheck(&conn), rotated_kc);
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
        // clean of I/O errors; an integrity refusal here is O253's (the open
        // reads the head and replays in two snapshots), reported, not judged.
        "opener" => {
            let (mut ok, mut io, mut busy, mut other, mut deferred) =
                (0u64, 0u64, 0u64, 0u64, 0u64);
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
                        let busy_heal = s.unhealed().iter().any(|n| {
                            n.contains("could NOT fast-forward") && n.contains("write lock")
                        });
                        if busy_heal {
                            busy += 1;
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
                        if text.contains("database is locked") {
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
                 anchor_failures={deferred}"
            );
        }
        // Holds a connection (and, for `reader-txn`, an open read transaction)
        // until the parent drops a release file — P3's other process.
        "idle" | "reader-txn" => {
            let conn = rusqlite::Connection::open(vdir(&root).join("vault.db")).unwrap();
            conn.query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0))
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

/// **Every writer of `vault.json` and `vault.json.next`, and every caller of
/// `anchor_manifest`, counted across the crates (ROADMAP O254).** The ruling
/// names the silent failures: a `vault.json` writer that survives outside the
/// door, and an anchor "optimised" back into a caller's own hands. So:
/// `anchor_manifest` has ONE production caller, the door's; the vault crate
/// renames in exactly two places — the one writer and the promote — and
/// creates a file only through `create_new`; each promote and discard in the
/// store runs within a few lines of taking the write lock; the one writer
/// keeps the anchor's durability at one file fsync and one directory sync;
/// and no other crate writes the manifest. The CLI's `copy_dir` — backup
/// create into `backups/`, restore back into `vaults/` under O69's exclusive
/// hold, which refuses while any handle has the vault open — is the one
/// whole-directory writer, pinned by its call sites so a new one is ruled.
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

    // The vault crate: two renames, one `create_new`, no truncating create.
    assert_eq!(vault.matches("fs::rename(").count(), 2, "vault renames");
    assert!(body_of(&vault, "write_manifest_file").contains("fs::rename("));
    assert!(body_of(&vault, "promote_manifest").contains("fs::rename("));
    assert_eq!(vault.matches(".create_new(true)").count(), 1);
    assert_eq!(
        vault.matches("File::create(").count(),
        0,
        "a truncating create"
    );
    assert_eq!(
        vault.matches("write_manifest_file(").count(),
        4,
        "one def + three writers"
    );
    let writer = body_of(&vault, "write_manifest_file");
    assert_eq!(writer.matches(".sync_all()").count(), 1, "one file fsync");
    assert_eq!(writer.matches("sync_dir(").count(), 1, "one directory sync");
    assert!(
        !vault.contains("\"vault.json.tmp\""),
        "the legacy fixed temp name"
    );

    // Each promote and discard in the store runs under the write lock.
    for call in [".promote_manifest()", ".discard_pending_file()"] {
        let mut sites = 0;
        for (path, text) in &store {
            for (at, _) in text.match_indices(call) {
                sites += 1;
                let window: String = text[..at].lines().rev().take(20).collect();
                assert!(
                    window.contains("WriteLock::begin(") || window.contains("RotationTx::begin("),
                    "{path}: {call} outside the write lock"
                );
            }
        }
        assert!(sites >= 1, "premise: {call} has call sites");
    }

    // No other crate writes a manifest, and the directory writer is pinned.
    for (path, text) in cli.iter().chain(&orch) {
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
    let copy_dir_calls: usize = cli
        .iter()
        .map(|(_, t)| t.matches("copy_dir(").count())
        .sum();
    assert_eq!(
        copy_dir_calls, 6,
        "`copy_dir` call sites moved (one definition, one recursion, backup create and \
         restore on the CLI and on /v1): rule the new one against O69's hold"
    );
}
