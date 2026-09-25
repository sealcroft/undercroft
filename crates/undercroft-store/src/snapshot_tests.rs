//! ROADMAP O253: every judgement that compares what it reads reads it from
//! ONE database state — driven with a second handle committing at every VM
//! step of a door, so a judgement split across two snapshots is caught at the
//! step that splits it rather than by the luck of a timing loop.
//!
//! The mechanism is SQLite's progress handler (rusqlite's `hooks` feature, a
//! DEV-dependency of this crate, so production code carries no interleave
//! hook). The handler is installed on the store's own connection and, at its
//! Nth callback, makes one LEGITIMATE commit through a second `VaultStore` on
//! the same vault — an ordinary `trust set`, `retention set`, drawer
//! correction, save, fact or audited read. Nothing here tampers, except the
//! masking arm, which tampers deliberately and says so.
//!
//! The doors are driven through their public APIs only, so the same sweep
//! measures a tree that reads in two snapshots and one that reads in one.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use undercroft_core::Drawer;
use undercroft_vault::{SecurityLevel, VaultManager};

use crate::witness::{ChainWitness, WitnessVerdict};
use crate::{Read, ReadOp, SearchOptions, StoreError, VaultStore};

const VAULT: &str = "o253";

fn drawer(content: &str, idx: u32) -> Drawer {
    Drawer::new(
        "w1",
        "r",
        content.into(),
        Some("o253.md".into()),
        idx,
        "test",
    )
}

fn open_at(root: &std::path::Path) -> VaultStore {
    let mgr = VaultManager::open(root, None).unwrap();
    VaultStore::open(mgr.unlock(VAULT).unwrap()).unwrap()
}

/// A vault with `n` drawers in one wing, a trust class and a retention
/// policy on it, and a handful of facts — every table a guarded door reads.
fn corpus(level: SecurityLevel, n: usize) -> (TempDir, VaultStore) {
    let dir = TempDir::new().unwrap();
    let mgr = VaultManager::open(dir.path(), None).unwrap();
    let mut s = VaultStore::open(mgr.create(VAULT, level).unwrap()).unwrap();
    for chunk in (0..n).collect::<Vec<_>>().chunks(500) {
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
    s.set_wing_trust("w1", "standard").unwrap();
    s.set_retention("w1", None, 3650).unwrap();
    for i in 0..4 {
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
    (dir, s)
}

/// One legitimate commit a second handle makes.
#[derive(Clone, Copy, Debug)]
enum Commit {
    Trust,
    Retention,
    Correct,
    Save,
    Fact,
    /// An audited read: a commit that moves the head WITHOUT an anchor, which
    /// is what makes an open (and `vault anchor`) replay.
    AuditedRead,
}

const ROUND_ROBIN: [Commit; 5] = [
    Commit::Trust,
    Commit::Retention,
    Commit::Correct,
    Commit::Save,
    Commit::Fact,
];

/// The id every correction rewrites and every by-id door reads.
fn target_id(s: &VaultStore) -> String {
    let r = s
        .recent(
            Some("w1"),
            1,
            Read::Internal(crate::InternalRead::Verification),
        )
        .unwrap();
    r[0].id.clone()
}

fn commit(w: &mut VaultStore, kind: Commit, i: u64, target: &str) -> Result<(), StoreError> {
    match kind {
        Commit::Trust => w.set_wing_trust(
            "w1",
            if i.is_multiple_of(2) {
                "trusted"
            } else {
                "standard"
            },
        ),
        Commit::Retention => w.set_retention("w1", None, 3650 + (i % 7) as u32),
        Commit::Correct => w
            .update_drawer(
                target,
                &format!("note corrected {i}: the harbour ledger"),
                "test",
            )
            .map(|_| ()),
        Commit::Save => w
            .upsert(&Drawer::new(
                "w2",
                "r",
                format!("an unrelated save {i}"),
                Some("o253-writer.md".into()),
                i as u32,
                "test",
            ))
            .map(|_| ()),
        Commit::Fact => w
            .kg_add(
                "harbour",
                "ships",
                &format!("late cargo {i}"),
                None,
                None,
                1.0,
                None,
            )
            .map(|_| ()),
        Commit::AuditedRead => w.get(target, Read::Returned(ReadOp::Get)).map(|_| ()),
    }
}

/// What the writer did from inside the handler. A panic in a progress
/// handler is swallowed by rusqlite, so every outcome is recorded instead.
#[derive(Default)]
struct Fired {
    inside: u64,
    writer_errors: Vec<String>,
}

/// Arm the handler on EVERY VM step (SQLite restarts the progress count per
/// statement, so a coarser handler never fires inside a short one); at the
/// `at`-th step, commit once through `writer`.
fn arm(
    s: &VaultStore,
    at: u64,
    writer: Arc<Mutex<VaultStore>>,
    kind: Commit,
    i: u64,
    target: String,
    log: Arc<Mutex<Fired>>,
) {
    let mut n = 0u64;
    s.conn.progress_handler(
        1,
        Some(move || {
            n += 1;
            if n == at {
                let mut w = writer.lock().unwrap();
                let r = commit(&mut w, kind, i, &target);
                let mut l = log.lock().unwrap();
                match r {
                    Ok(()) => l.inside += 1,
                    Err(e) => l.writer_errors.push(format!("{kind:?}: {e}")),
                }
            }
            false
        }),
    );
}

fn disarm(s: &VaultStore) {
    s.conn.progress_handler(0, None::<fn() -> bool>);
}

/// How many callbacks at `every = 1` one run of `door` takes.
fn ops_of(s: &mut VaultStore, door: &Door) -> u64 {
    let n = Arc::new(Mutex::new(0u64));
    let m = n.clone();
    s.conn.progress_handler(
        1,
        Some(move || {
            *m.lock().unwrap() += 1;
            false
        }),
    );
    let r = door(s);
    disarm(s);
    r.unwrap_or_else(|e| panic!("premise: the door answers when nothing interleaves: {e}"));
    let v = *n.lock().unwrap();
    v
}

type Door = dyn Fn(&mut VaultStore) -> Result<(), String>;

/// What one sweep of one door measured.
#[derive(Debug, Default)]
struct Sweep {
    runs: u64,
    fired_inside: u64,
    refusals: Vec<(u64, String)>,
    writer_errors: Vec<String>,
    /// Callbacks of one run whose cookie had moved (a replay) and one whose
    /// had not, at `every = 1`: their difference is the replay's own steps.
    miss_ops: u64,
    hit_ops: u64,
    replays_before: u64,
    replays_after: u64,
}

/// Sweep `door` across every step of itself, a legitimate commit landing at
/// each, round-robin over `kinds`. Every run starts with the cookie moved, so
/// the door replays — the window the defect lives in.
fn sweep(
    root: &std::path::Path,
    s: &mut VaultStore,
    door: &Door,
    kinds: &[Commit],
    target_runs: u64,
) -> Sweep {
    let target = target_id(s);
    let writer = Arc::new(Mutex::new(open_at(root)));
    let mut out = Sweep::default();
    // A commit with no handler moves the cookie: the next run replays.
    let nudge = |i: u64| {
        let mut w = writer.lock().unwrap();
        commit(&mut w, Commit::Save, 1_000_000 + i, &target).unwrap();
    };
    door(s).unwrap_or_else(|e| panic!("premise: the door answers on a quiet vault: {e}"));
    nudge(0);
    out.miss_ops = ops_of(s, door);
    out.hit_ops = ops_of(s, door);
    // The handler fires at EVERY step and the target step is strided, never
    // the other way round: SQLite restarts the progress count per statement,
    // so `every > 1` never fires inside a statement shorter than `every` —
    // and the statements between a replay and the head it is compared with
    // are exactly the short ones. The first version strided `every` and
    // under-sampled them.
    let stride = (out.miss_ops / target_runs).max(1);
    out.replays_before = s.replays();
    for at in (1..=out.miss_ops + 2 * stride).step_by(stride as usize) {
        nudge(at);
        let log = Arc::new(Mutex::new(Fired::default()));
        let kind = kinds[(at as usize) % kinds.len()];
        arm(s, at, writer.clone(), kind, at, target.clone(), log.clone());
        let r = door(s);
        disarm(s);
        out.runs += 1;
        let l = log.lock().unwrap();
        out.fired_inside += l.inside;
        out.writer_errors.extend(l.writer_errors.iter().cloned());
        if let Err(e) = r {
            out.refusals.push((at, e));
        }
    }
    out.replays_after = s.replays();
    out
}

fn verdict_door(s: &mut VaultStore) -> Result<(), String> {
    let r = s.verify().map_err(|e| e.to_string())?;
    if r.ok() {
        Ok(())
    } else {
        Err(format!(
            "verify: chain_ok={} labels={:?} policy_drift={:?} version_replay={:?} bad={:?}",
            r.chain_ok, r.label_commitment, r.policy_drift, r.version_replay, r.bad_records
        ))
    }
}

fn doors() -> Vec<(&'static str, Box<Door>)> {
    vec![
        (
            "wing_trusts",
            Box::new(|s: &mut VaultStore| s.wing_trusts().map(|_| ()).map_err(|e| e.to_string())),
        ),
        (
            "retention_policies",
            Box::new(|s: &mut VaultStore| {
                s.retention_policies()
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        ),
        ("verify", Box::new(verdict_door)),
        (
            "get",
            Box::new(|s: &mut VaultStore| {
                let id = target_id(s);
                s.get(&id, Read::Returned(ReadOp::Get))
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        ),
        (
            "recent",
            Box::new(|s: &mut VaultStore| {
                s.recent(None, 20, Read::Returned(ReadOp::Recent))
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        ),
        (
            "search",
            Box::new(|s: &mut VaultStore| {
                let opts = SearchOptions {
                    limit: 5,
                    ..Default::default()
                };
                s.search("harbour ledger cargo", &opts)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        ),
        (
            "kg_query_entity",
            Box::new(|s: &mut VaultStore| {
                s.kg_query_entity("harbour", None, "outgoing", Read::Returned(ReadOp::KgQuery))
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }),
        ),
    ]
}

/// **The gate, over the seven deciding doors**: a legitimate commit at every
/// step of each, and no refusal of any kind.
///
/// Counterfactual, measured on `1b9746e` before the fix: see ROADMAP O253's
/// BUILT record for the per-door counts.
#[test]
fn o253_a_legitimate_commit_at_any_step_of_a_deciding_door_is_never_a_refusal() {
    let (dir, mut s) = corpus(SecurityLevel::Sealed, 120);
    let mut failed = Vec::new();
    // Two knobs for a focused counterfactual — a denser sweep of one door —
    // never set by the suite: `O253_RUNS` (target runs per door) and
    // `O253_DOOR` (one door by name).
    let runs = env_or("O253_RUNS", 120);
    let only = std::env::var("O253_DOOR").ok();
    for (name, door) in doors() {
        if only.as_deref().is_some_and(|d| d != name) {
            continue;
        }
        let sw = sweep(dir.path(), &mut s, door.as_ref(), &ROUND_ROBIN, runs);
        eprintln!(
            "O253 sweep {name}: runs={} fired_inside={} refusals={} miss_ops={} hit_ops={} \
             replays {}→{}",
            sw.runs,
            sw.fired_inside,
            sw.refusals.len(),
            sw.miss_ops,
            sw.hit_ops,
            sw.replays_before,
            sw.replays_after
        );
        assert!(
            sw.writer_errors.is_empty(),
            "{name}: the writer failed: {:?}",
            sw.writer_errors
        );
        // Premises: the commits landed INSIDE the door, and every run replayed
        // (the window the defect lives in) — a sweep that fired after the door
        // returned, or whose door never replayed, measured nothing.
        assert!(
            sw.fired_inside * 10 >= sw.runs * 8,
            "{name}: premise: most commits landed inside the door ({} of {})",
            sw.fired_inside,
            sw.runs
        );
        if name != "verify" {
            assert!(
                sw.miss_ops > sw.hit_ops,
                "{name}: premise: a run whose cookie moved does more work (the replay)"
            );
            assert!(
                sw.replays_after - sw.replays_before >= sw.runs,
                "{name}: premise: every run replayed ({} → {} over {} runs)",
                sw.replays_before,
                sw.replays_after,
                sw.runs
            );
        }
        for (at, e) in &sw.refusals {
            failed.push(format!("{name} at step {at}: {e}"));
        }
    }
    assert!(
        failed.is_empty(),
        "{} refusal(s) under a legitimate writer:\n{}",
        failed.len(),
        failed.join("\n")
    );
}

/// `vault anchor` — `reconcile_chain`, the open's judgement — while a second
/// handle makes audited reads, the commits that leave the anchor behind.
#[test]
fn o253_reconciling_the_anchor_beside_a_writer_never_reads_a_broken_head() {
    let (dir, mut s) = corpus(SecurityLevel::Sealed, 120);
    let door = |s: &mut VaultStore| s.tighten_anchor().map(|_| ()).map_err(|e| e.to_string());
    // The writer here must NOT anchor, or the anchor never lags and the
    // judgement never replays: an audited read appends and does not anchor.
    let target = target_id(&s);
    let writer = Arc::new(Mutex::new(open_at(dir.path())));
    writer.lock().unwrap().read_audit = true;
    let lag = |i: u64| {
        commit(&mut writer.lock().unwrap(), Commit::AuditedRead, i, &target).unwrap();
    };
    lag(0);
    let miss_ops = ops_of(&mut s, &door);
    let stride = (miss_ops / 120).max(1);
    let (mut runs, mut fired, mut refusals) = (0u64, 0u64, Vec::new());
    for at in (1..=miss_ops + 2 * stride).step_by(stride as usize) {
        lag(at);
        let log = Arc::new(Mutex::new(Fired::default()));
        arm(
            &s,
            at,
            writer.clone(),
            Commit::AuditedRead,
            at,
            target.clone(),
            log.clone(),
        );
        let r = door(&mut s);
        disarm(&s);
        runs += 1;
        let l = log.lock().unwrap();
        assert!(l.writer_errors.is_empty(), "{:?}", l.writer_errors);
        fired += l.inside;
        if let Err(e) = r {
            refusals.push(format!("step {at}: {e}"));
        }
    }
    eprintln!(
        "O253 reconcile sweep: runs={runs} fired_inside={fired} refusals={}",
        refusals.len()
    );
    assert!(
        fired * 10 >= runs * 8,
        "premise: the commits landed inside ({fired}/{runs})"
    );
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
    assert!(s.verify().unwrap().ok(), "and the vault verifies");
}

/// Witness emit and check beside a writer: the check extends, and the emitted
/// document's `rows`, `head` and `writes` describe ONE state.
#[test]
fn o253_a_witness_beside_a_writer_describes_one_state_and_still_extends() {
    let (dir, mut s) = corpus(SecurityLevel::Sealed, 120);
    let w0 = s.witness_emit().unwrap();
    let check = move |s: &mut VaultStore| match s.witness_check(&w0) {
        Ok(WitnessVerdict::Extends { .. }) => Ok(()),
        Ok(v) => Err(format!("{v:?}")),
        Err(e) => Err(e.to_string()),
    };
    let sw = sweep(dir.path(), &mut s, &check, &ROUND_ROBIN, 120);
    assert!(sw.refusals.is_empty(), "witness check: {:?}", sw.refusals);
    // The emit: a document is consistent when its head is the chain's head
    // after exactly `rows` rows — which a replay anchored on that head
    // reports as `behind_by = total - rows`.
    let consistent = |s: &mut VaultStore| -> Result<(), String> {
        let w: ChainWitness = s.witness_emit().map_err(|e| e.to_string())?;
        let (total, seen, behind) = s.chain_position_of(&w.head);
        if !seen || behind != total - w.rows {
            return Err(format!(
                "rows={} writes={} but its head sits {behind} behind a {total}-row chain \
                 (seen={seen})",
                w.rows, w.writes
            ));
        }
        if w.writes < w.rows {
            return Err(format!("writes {} below rows {}", w.writes, w.rows));
        }
        Ok(())
    };
    let sw = sweep(dir.path(), &mut s, &consistent, &ROUND_ROBIN, 120);
    assert!(sw.refusals.is_empty(), "witness emit: {:?}", sw.refusals);
}

/// **The masking arm (ROADMAP O253 item 6, the hydration gap folded).** A
/// drawer's older version written back — a replay O234 refuses — and then, at
/// step N of a returning read, a LEGITIMATE correction of that same drawer. A
/// read that fetched the row in one snapshot and compared it in another
/// served the replayed words; a read that does both in one either refuses the
/// replay or serves the correction, and never the replay.
#[test]
fn o253_a_correction_landing_mid_read_never_launders_a_replayed_drawer() {
    let (dir, mut s) = corpus(SecurityLevel::Sealed, 60);
    let target = target_id(&s);
    let old = s.drawer_row_for_test(&target);
    let old_content = s
        .get(&target, Read::Internal(crate::InternalRead::Verification))
        .unwrap()
        .unwrap()
        .content;
    let writer = Arc::new(Mutex::new(open_at(dir.path())));
    let doors: Vec<(&str, Box<Door>)> = vec![
        (
            "get",
            Box::new({
                let target = target.clone();
                let old_content = old_content.clone();
                move |s: &mut VaultStore| match s.get(&target, Read::Returned(ReadOp::Get)) {
                    Ok(Some(d)) if d.content == old_content => Err("SERVED THE REPLAY".into()),
                    Ok(_) => Ok(()),
                    Err(e) => Err(format!("refused: {e}")),
                }
            }),
        ),
        (
            "search",
            Box::new({
                let old_content = old_content.clone();
                move |s: &mut VaultStore| {
                    let opts = SearchOptions {
                        limit: 60,
                        ..Default::default()
                    };
                    match s.search("harbour ledger", &opts) {
                        Ok(hits) if hits.iter().any(|h| h.drawer.content == old_content) => {
                            Err("SERVED THE REPLAY".into())
                        }
                        Ok(_) => Ok(()),
                        Err(e) => Err(format!("refused: {e}")),
                    }
                }
            }),
        ),
    ];
    let mut laundered = Vec::new();
    for (name, door) in doors {
        // Establish the correction the replay rolls back.
        commit(&mut writer.lock().unwrap(), Commit::Correct, 0, &target).unwrap();
        s.put_drawer_row_for_test(&target, &old);
        let ops = ops_of_or_refusal(&mut s, door.as_ref());
        let stride = (ops / 150).max(1);
        let (mut served, mut refused, mut corrected, mut fired) = (0u64, 0u64, 0u64, 0u64);
        for at in (1..=ops + 2 * stride).step_by(stride as usize) {
            // Every run starts from the replayed row.
            s.put_drawer_row_for_test(&target, &old);
            let log = Arc::new(Mutex::new(Fired::default()));
            arm(
                &s,
                at,
                writer.clone(),
                Commit::Correct,
                at,
                target.clone(),
                log.clone(),
            );
            let r = door(&mut s);
            disarm(&s);
            fired += log.lock().unwrap().inside;
            match r {
                Err(e) if e == "SERVED THE REPLAY" => served += 1,
                Err(_) => refused += 1,
                Ok(()) => corrected += 1,
            }
        }
        eprintln!(
            "O253 masking {name}: served_replay={served} refused={refused} \
             served_correction={corrected} fired_inside={fired}"
        );
        assert!(
            fired > 0,
            "{name}: premise: corrections landed inside the read"
        );
        assert!(
            refused > 0,
            "{name}: premise: the replay is refused when nothing interleaves"
        );
        if served > 0 {
            laundered.push(format!(
                "{name}: served the replayed drawer {served} time(s)"
            ));
        }
    }
    assert!(laundered.is_empty(), "{laundered:?}");
}

// ---------------------------------------------------------------------------
// The helper, the witness and the guard's arms
// ---------------------------------------------------------------------------

/// **P7, pinned**: inside a snapshot the helper opened, `data_version` is
/// constant and the reads do not see a commit another connection makes —
/// the observable the whole design rests on. Its premise is that the same
/// commit DOES move the cookie outside.
#[test]
fn o253_p7_a_snapshot_reads_one_state_and_its_cookie_names_it() {
    let (dir, s) = corpus(SecurityLevel::HmacOnly, 10);
    let mut other = open_at(dir.path());
    let before = crate::chain::data_version(&s.conn).unwrap();
    let rows = |c: &rusqlite::Connection| -> i64 {
        c.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))
            .unwrap()
    };
    let (inside, cookie_first, cookie_last, rows_first, rows_last) = s
        .snapshot(|snap| {
            let first = snap.data_version();
            let n0 = rows(snap.conn());
            commit(&mut other, Commit::Save, 1, "").unwrap();
            let last = crate::chain::data_version(snap.conn())?;
            Ok((snap.origin(), first, last, n0, rows(snap.conn())))
        })
        .unwrap();
    assert_eq!(inside, crate::chain::Origin::Opened);
    assert_eq!(
        cookie_first, cookie_last,
        "P7: the cookie is constant inside"
    );
    assert_eq!(
        rows_first, rows_last,
        "one state: the commit is not visible inside"
    );
    let after = crate::chain::data_version(&s.conn).unwrap();
    assert_ne!(
        before, after,
        "premise: that commit moves the cookie outside"
    );
    assert_eq!(
        rows(&s.conn),
        rows_first + 1,
        "premise: and it committed a row"
    );
}

/// The helper ENDS its transaction and restores `query_only` on every exit
/// — Ok, Err and a panic — and nests inside itself as one snapshot. A
/// long-lived handle left inside a read transaction under `query_only`
/// would refuse every later write.
#[test]
fn o253_the_helper_always_ends_its_snapshot_and_restores_the_posture() {
    let (_dir, mut s) = corpus(SecurityLevel::Sealed, 4);
    let query_only = |s: &VaultStore| -> i64 {
        s.conn
            .query_row("PRAGMA query_only", [], |r| r.get(0))
            .unwrap()
    };
    let settled = |s: &VaultStore, what: &str| {
        assert!(s.conn.is_autocommit(), "{what}: the transaction ended");
        assert_eq!(query_only(s), 0, "{what}: query_only restored");
        assert_eq!(
            s.owned_snapshots.get(),
            0,
            "{what}: the count returned to zero"
        );
    };
    let nested = s
        .snapshot(|outer| {
            assert_eq!(query_only(&s), 1, "query_only holds inside");
            s.snapshot(|inner| Ok((outer.data_version(), inner.data_version(), inner.origin())))
        })
        .unwrap();
    assert_eq!(nested.0, nested.1, "a nested snapshot is the outer one");
    assert_eq!(nested.2, crate::chain::Origin::Opened);
    settled(&s, "ok");
    let refused = s.snapshot(|snap| {
        snap.conn()
            .execute("INSERT INTO meta (key, value) VALUES ('o253', 'x')", [])?;
        Ok(())
    });
    assert!(
        refused.is_err(),
        "a write inside a snapshot is refused (query_only)"
    );
    settled(&s, "err");
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = s.snapshot(|_| -> Result<(), StoreError> { panic!("inside a snapshot") });
    }));
    assert!(panicked.is_err(), "premise: the body panicked");
    settled(&s, "panic");
    // And the handle still writes.
    s.upsert(&drawer("after the snapshots", 999)).unwrap();
}

/// The guard inside a CALLER's transaction: a hit decides, a miss is an error
/// naming the call site (never a replay that would compare the anchor with
/// rows it did not read first) — and under a write lock the miss replays in
/// place, caching nothing.
#[test]
fn o253_inside_a_callers_transaction_the_guard_checks_and_never_guesses() {
    let (dir, s) = corpus(SecurityLevel::Sealed, 8);
    // A hit: the cache names the current state.
    s.wing_trusts().unwrap();
    let tx = s.conn.unchecked_transaction().unwrap();
    s.wing_trusts()
        .expect("a hit decides inside a caller's transaction");
    drop(tx);
    // A miss: another handle commits, so the cookie moved.
    commit(&mut open_at(dir.path()), Commit::Save, 1, "").unwrap();
    let tx = s.conn.unchecked_transaction().unwrap();
    let err = s.wing_trusts().unwrap_err().to_string();
    drop(tx);
    assert!(
        err.contains("no guarded door authenticated") && err.contains("manage.rs"),
        "a miss inside a caller's transaction names the call site: {err}"
    );
    // Under a write lock the miss replays in place and caches nothing.
    let replays = s.replays();
    {
        let lock = crate::WriteLock::begin(&s.conn).unwrap();
        let snap = lock.snapshot().unwrap();
        assert_eq!(snap.origin(), crate::chain::Origin::WriteLocked);
        s.labels_authenticated(&snap)
            .expect("a write-locked miss replays in place");
    }
    assert_eq!(s.replays(), replays + 1, "counted");
    s.wing_trusts().unwrap();
    assert_eq!(
        s.replays(),
        replays + 2,
        "and not cached: the door replays again"
    );
}

/// **`verify` on a writable vault with no graph secret, beside a writer**
/// (the ruling's gate): two legs read the secret, whose first use WRITES it.
/// Without the warm-up the snapshot's `query_only` refuses that write LOUDLY
/// — never a rollback that leaves a cached secret stored nowhere; with it,
/// `verify` answers and the snapshot changes nothing.
///
/// The state is CONSTRUCTED, and that is a correction of the ruling's
/// premise rather than a shortcut: it asked for a "fresh writable vault with
/// no graph secret", and there is none — every writable open runs the two
/// at-rest migrations, and both call `kg_secret()` and store it. The
/// first-use write inside `verify` is reachable only when the row is absent
/// after the migrations have marked themselves done, so that is the state
/// built here.
#[test]
fn o253_verify_warms_the_graph_secret_before_its_snapshot() {
    let dir = TempDir::new().unwrap();
    let mgr = VaultManager::open(dir.path(), None).unwrap();
    let mut s = VaultStore::open(mgr.create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
    s.upsert(&drawer("one drawer, no facts", 1)).unwrap();
    let premise: i64 = s
        .conn
        .query_row(
            "SELECT COUNT(*) FROM meta WHERE key = 'kg_blind_secret'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        premise, 1,
        "premise: a writable open already stored the secret"
    );
    s.conn
        .execute("DELETE FROM meta WHERE key = 'kg_blind_secret'", [])
        .unwrap();
    *s.kg_secret.borrow_mut() = None;
    let stored = |s: &VaultStore| -> i64 {
        s.conn
            .query_row(
                "SELECT COUNT(*) FROM meta WHERE key = 'kg_blind_secret'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(stored(&s), 0, "premise: no graph secret yet");
    // Without the warm-up: the legs inside one snapshot, as `verify` would
    // run them had it not warmed first.
    let anchor = s.vault.anchored_head().unwrap();
    let loud = s.snapshot(|snap| s.verify_in(snap, &anchor));
    assert!(
        loud.is_err(),
        "the first-use write is refused inside the snapshot"
    );
    assert!(
        s.kg_secret.borrow().is_none(),
        "and refused BEFORE the secret was cached — nothing is stored nowhere"
    );
    assert_eq!(stored(&s), 0);
    // With it: the warm-up is this handle's own write, before the snapshot.
    let changes = s.conn.total_changes();
    let report = s.verify().unwrap();
    assert!(report.ok(), "{report:?}");
    assert_eq!(stored(&s), 1, "the warm-up stored the secret");
    let warmed = s.conn.total_changes();
    assert!(warmed > changes, "premise: the warm-up was a write");
    // And beside a writer, the snapshot itself writes nothing.
    commit(&mut open_at(dir.path()), Commit::Save, 2, "").unwrap();
    let anchor = s.vault.anchored_head().unwrap();
    let report = s.snapshot(|snap| s.verify_in(snap, &anchor)).unwrap();
    assert!(report.ok(), "{report:?}");
    assert_eq!(
        s.conn.total_changes(),
        warmed,
        "the snapshot itself wrote nothing"
    );
}

/// **Only the helper and the two write-lock guards mint a snapshot.** A
/// source gate, because the type system stops a walk with no snapshot but
/// not a caller that asserts a write lock it does not hold.
#[test]
fn o253_only_the_two_write_lock_guards_assert_a_write_locked_snapshot() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name == "snapshot_tests.rs" || path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if !t.starts_with("//") && t.contains(concat!("Snapshot::", "write_locked(")) {
                found.push(format!("{name}:{}", i + 1));
            }
        }
    }
    assert_eq!(
        found.len(),
        2,
        "WriteLock::snapshot and ExclusiveHold::snapshot: {found:?}"
    );
    assert!(found.iter().all(|f| f.starts_with("lib.rs:")), "{found:?}");
    // And the struct is built nowhere but chain.rs.
    let literal = concat!("Snapshot", " {");
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name == "chain.rs" || name == "snapshot_tests.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(!text.contains(literal), "{name} builds a Snapshot by hand");
    }
}

/// **The FOUND note's open failure, at its cause**: an hmac-only vault whose
/// index is short is rebuilt at the next open — under the write lock — and
/// an open that finds it current takes no lock at all.
#[test]
fn o253_a_short_fts_index_is_rebuilt_at_open_under_the_lock() {
    let (dir, s) = corpus(SecurityLevel::HmacOnly, 30);
    let count = |s: &VaultStore, t: &str| -> i64 {
        s.conn
            .query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(
        count(&s, "drawers_fts"),
        count(&s, "drawers"),
        "premise: complete"
    );
    s.conn
        .execute(
            "DELETE FROM drawers_fts WHERE rowid = (SELECT MAX(rowid) FROM drawers_fts)",
            [],
        )
        .unwrap();
    drop(s);
    // A second connection holding a READ transaction does not block the
    // rebuild (WAL), which is the point: only writers queue behind it.
    let reader =
        rusqlite::Connection::open(dir.path().join("vaults").join(VAULT).join("vault.db")).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    reader
        .query_row("SELECT COUNT(*) FROM drawers", [], |r| r.get::<_, i64>(0))
        .unwrap();
    let s = open_at(dir.path());
    assert!(s.fts, "the prefilter is on");
    assert_eq!(count(&s, "drawers_fts"), count(&s, "drawers"), "rebuilt");
    reader.execute_batch("COMMIT").unwrap();
    // A writer holding the lock past the timeout: the open serves WITHOUT the
    // prefilter rather than failing, and rather than serving a short index.
    s.conn
        .execute(
            "DELETE FROM drawers_fts WHERE rowid = (SELECT MAX(rowid) FROM drawers_fts)",
            [],
        )
        .unwrap();
    drop(s);
    let holder =
        rusqlite::Connection::open(dir.path().join("vaults").join(VAULT).join("vault.db")).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mgr = VaultManager::open(dir.path(), None).unwrap();
    let mut vault_conn_timeout = VaultStore::open(mgr.unlock(VAULT).unwrap());
    // The open either waits out the busy timeout and degrades, or — if an
    // earlier step of the open needs the lock — says the vault is held; it
    // never fails on the index and never serves it short.
    match &mut vault_conn_timeout {
        Ok(s) => {
            assert!(
                !s.fts,
                "a short index the lock kept from rebuilding is not served"
            );
        }
        Err(e) => panic!("the open failed over an accelerator: {e}"),
    }
    holder.execute_batch("ROLLBACK").unwrap();
}

/// `ops_of` for a door that REFUSES on a quiet vault — the masking arm's.
fn ops_of_or_refusal(s: &mut VaultStore, door: &Door) -> u64 {
    let n = Arc::new(Mutex::new(0u64));
    let m = n.clone();
    s.conn.progress_handler(
        1,
        Some(move || {
            *m.lock().unwrap() += 1;
            false
        }),
    );
    let _ = door(s);
    disarm(s);
    let v = *n.lock().unwrap();
    v
}

/// The four columns a drawer replay restores (the O234 measurement's).
type DrawerRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);

impl VaultStore {
    /// Where `head` sits in this vault's chain: `(rows, seen, behind_by)`,
    /// stepped HERE rather than through `chain::replay`, so the check is
    /// independent of the code it checks.
    fn chain_position_of(&self, head: &str) -> (u64, bool, u64) {
        let regime = crate::chain::regime(&self.conn).unwrap();
        let mut at = undercroft_vault::Vault::chain_genesis_hex();
        let mut seen_at = (at == head).then_some(0u64);
        let mut rows = 0u64;
        let mut stmt = self
            .conn
            .prepare("SELECT seq, record_id, tag, at FROM audit ORDER BY seq")
            .unwrap();
        let mut cur = stmt.query([]).unwrap();
        while let Some(r) = cur.next().unwrap() {
            let seq: i64 = r.get(0).unwrap();
            let rid: String = r.get(1).unwrap();
            let tag: Vec<u8> = r.get(2).unwrap();
            let when: String = r.get(3).unwrap();
            at = self
                .vault
                .chain_step_hex(
                    regime.step_for(seq),
                    &at,
                    undercroft_vault::ChainLink {
                        record_id: &rid,
                        tag: &tag,
                        at: &when,
                    },
                )
                .unwrap();
            rows += 1;
            if at == head {
                seen_at = Some(rows);
            }
        }
        (rows, seen_at.is_some(), seen_at.map_or(0, |s| rows - s))
    }

    fn drawer_row_for_test(&self, id: &str) -> DrawerRow {
        self.conn
            .query_row(
                "SELECT meta_json, content, embedding, tag FROM drawers WHERE id = ?1",
                rusqlite::params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap()
    }

    /// Write an older version of a drawer back — the O234 replay, made on
    /// this handle's own connection so it moves no cookie.
    fn put_drawer_row_for_test(&self, id: &str, row: &DrawerRow) {
        self.conn
            .execute(
                "UPDATE drawers SET meta_json = ?1, content = ?2, embedding = ?3, tag = ?4 \
                 WHERE id = ?5",
                rusqlite::params![row.0, row.1, row.2, row.3, id],
            )
            .unwrap();
    }
}

// ---------------------------------------------------------------------------
// Soaks — each door ALONE, read-audit on, a writer thread committing for the
// whole window. Measurements run by name; the sweep above is the gate.
// ---------------------------------------------------------------------------

fn env_or(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The one error wording this soak counts instead of failing on: ROADMAP
/// O258's busy tail. With read-audit on, a returning read WRITES its record
/// after the snapshot, so beside a writer committing in a tight loop it
/// waits on the write lock and can be starved past the busy timeout. That is
/// a refused write with nothing stored — O258's filed defect, measured here
/// and reported there, on O254's precedent (its gate reported O253's open
/// failures and asserted neither). Every OTHER error still fails the soak,
/// an unknown wording included.
const O258_BUSY: &str = "sqlite error: database is locked";

#[test]
#[ignore = "ROADMAP O253 soak; run by name with --ignored (O253_DRAWERS, O253_SECS, O253_LOOPS, O253_READ_AUDIT)"]
fn o253_soak_each_door_alone_beside_a_writer() {
    let drawers = env_or("O253_DRAWERS", 4000) as usize;
    let secs = env_or("O253_SECS", 6);
    let loops = env_or("O253_LOOPS", 10);
    let built = Instant::now();
    let (dir, mut s) = corpus(SecurityLevel::Sealed, drawers);
    eprintln!(
        "O253 soak: {drawers} drawers built in {:.1}s",
        built.elapsed().as_secs_f64()
    );
    // Read-audit ON, as ruled; `O253_READ_AUDIT=0` is the ablation that shows
    // which errors the read record causes.
    s.read_audit = std::env::var("O253_READ_AUDIT").as_deref() != Ok("0");
    let target = target_id(&s);
    let mut table = Vec::new();
    for (name, door) in doors() {
        let (mut ok, mut errs, mut commits, mut replays) = (0u64, Vec::new(), 0u64, 0u64);
        let mut busy = 0u64;
        for _ in 0..loops {
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let root = dir.path().to_path_buf();
            let flag = stop.clone();
            let t = target.clone();
            let writer = std::thread::spawn(move || {
                let mut w = open_at(&root);
                let (mut n, mut failed) = (0u64, Vec::new());
                let deadline = Instant::now() + Duration::from_secs(600);
                while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                    assert!(Instant::now() < deadline, "bounded: never stopped");
                    let kind = ROUND_ROBIN[(n as usize) % ROUND_ROBIN.len()];
                    if let Err(e) = commit(&mut w, kind, n, &t) {
                        failed.push(format!("{kind:?}: {e}"));
                    }
                    n += 1;
                }
                (n, failed)
            });
            let before = s.replays();
            let until = Instant::now() + Duration::from_secs(secs);
            while Instant::now() < until {
                match door(&mut s) {
                    Ok(()) => ok += 1,
                    Err(e) if e == O258_BUSY => busy += 1,
                    Err(e) => errs.push(e),
                }
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let (n, failed) = writer.join().unwrap();
            assert!(failed.is_empty(), "{name}: the writer failed: {failed:?}");
            commits += n;
            replays += s.replays() - before;
        }
        eprintln!(
            "O253 soak {name}: reads_ok={ok} errors={} o258_busy={busy} writer_commits={commits} \
             replays={replays} read_audit={}",
            errs.len(),
            s.read_audit
        );
        for e in errs.iter().take(5) {
            eprintln!("    {e}");
        }
        assert!(commits > 0, "{name}: premise: the writer committed");
        if name != "verify" {
            assert!(
                replays > loops,
                "{name}: premise: the replays rose ({replays})"
            );
        }
        table.push((name, ok, errs.len()));
    }
    let failed: Vec<_> = table.iter().filter(|(_, _, e)| *e > 0).collect();
    assert!(
        failed.is_empty(),
        "errors under a legitimate writer: {failed:?}"
    );
}

// ---------------------------------------------------------------------------
// Cost at ~10^5 — O234's instrument at its own size. Run by name, once per
// binary per round, the two binaries alternating: the corpus is built ONCE
// into `O253_CORPUS` and every run measures a fresh COPY of it, so both read
// the same bytes and neither measures the other's writes.
// ---------------------------------------------------------------------------

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

#[test]
#[ignore = "ROADMAP O253 cost at ~10^5; run by name with --ignored (O253_CORPUS, O253_DRAWERS)"]
fn o253_cost_at_scale() {
    let corpus_dir = std::path::PathBuf::from(
        std::env::var("O253_CORPUS").unwrap_or_else(|_| "/build/o253-corpus".into()),
    );
    let drawers = env_or("O253_DRAWERS", 102_000) as usize;
    if !corpus_dir
        .join("vaults")
        .join(VAULT)
        .join("vault.db")
        .exists()
    {
        let t = Instant::now();
        std::fs::create_dir_all(&corpus_dir).unwrap();
        let mgr = VaultManager::open(&corpus_dir, None).unwrap();
        let mut s = VaultStore::open(mgr.create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
        for chunk in (0..drawers).collect::<Vec<_>>().chunks(2000) {
            let batch: Vec<Drawer> = chunk
                .iter()
                .map(|i| {
                    drawer(
                        &format!(
                            "note {i}: the harbour ledger names cargo {i} in wing {}",
                            i % 7
                        ),
                        *i as u32,
                    )
                })
                .collect();
            s.upsert_many(&batch).unwrap();
        }
        s.set_wing_trust("w1", "standard").unwrap();
        s.set_retention("w1", None, 3650).unwrap();
        eprintln!(
            "O253_COST corpus: {drawers} drawers built in {:.1}s",
            t.elapsed().as_secs_f64()
        );
    }
    let work = TempDir::new().unwrap();
    copy_tree(&corpus_dir, work.path());
    let t = Instant::now();
    let s = open_at(work.path());
    let open_ms = t.elapsed().as_secs_f64() * 1e3;
    // The first guarded read of a handle: the one replay it pays.
    let t = Instant::now();
    s.wing_trusts().unwrap();
    let first_ms = t.elapsed().as_secs_f64() * 1e3;
    let target = target_id(&s);
    let opts = SearchOptions {
        limit: 5,
        ..Default::default()
    };
    // Warm-up, untimed: the PQ tier's build and caches.
    for _ in 0..3 {
        s.search("harbour ledger cargo 4711", &opts).unwrap();
    }
    let mut search = Vec::new();
    for i in 0..25 {
        let t = Instant::now();
        s.search(&format!("harbour ledger cargo {}", 1000 + i * 37), &opts)
            .unwrap();
        search.push(t.elapsed().as_secs_f64() * 1e3);
    }
    let mut get = Vec::new();
    let mut trusts = Vec::new();
    for _ in 0..200 {
        let t = Instant::now();
        s.get(&target, Read::Returned(ReadOp::Get)).unwrap();
        get.push(t.elapsed().as_secs_f64() * 1e6);
        let t = Instant::now();
        s.wing_trusts().unwrap();
        trusts.push(t.elapsed().as_secs_f64() * 1e6);
    }
    println!(
        "O253_COST open_ms={open_ms:.1} first_guarded_ms={first_ms:.1} search_ms={:.2} \
         get_us={:.0} wing_trusts_us={:.0} replays={}",
        median(search),
        median(get),
        median(trusts),
        s.replays()
    );
}

/// **The `-wal` while `verify` holds one snapshot beside a steady writer**:
/// a reader's snapshot keeps a checkpoint from passing it, so the log grows
/// for as long as the snapshot is held — not a per-read constant, which is
/// why the ruling asked for it measured.
#[test]
#[ignore = "ROADMAP O253 -wal growth under verify; run by name with --ignored (O253_CORPUS, O253_SECS)"]
fn o253_wal_growth_while_verify_holds_its_snapshot() {
    let corpus_dir = std::path::PathBuf::from(
        std::env::var("O253_CORPUS").unwrap_or_else(|_| "/build/o253-corpus".into()),
    );
    assert!(
        corpus_dir
            .join("vaults")
            .join(VAULT)
            .join("vault.db")
            .exists(),
        "premise: build the corpus with o253_cost_at_scale first"
    );
    let work = TempDir::new().unwrap();
    copy_tree(&corpus_dir, work.path());
    let s = open_at(work.path());
    let wal = work.path().join("vaults").join(VAULT).join("vault.db-wal");
    let size = || std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let root = work.path().to_path_buf();
    let flag = stop.clone();
    let writer = std::thread::spawn(move || {
        let mut w = open_at(&root);
        let mut n = 0u64;
        let deadline = Instant::now() + Duration::from_secs(600);
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            assert!(Instant::now() < deadline, "bounded");
            commit(&mut w, Commit::Save, n, "").unwrap();
            n += 1;
        }
        n
    });
    let (mut runs, mut max_wal, mut verify_ms) = (0u64, 0u64, Vec::new());
    let until = Instant::now() + Duration::from_secs(env_or("O253_SECS", 20));
    while Instant::now() < until {
        let t = Instant::now();
        let r = s.verify().unwrap();
        verify_ms.push(t.elapsed().as_secs_f64() * 1e3);
        assert!(r.ok(), "{r:?}");
        max_wal = max_wal.max(size());
        runs += 1;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let commits = writer.join().unwrap();
    println!(
        "O253_WAL verify_runs={runs} writer_commits={commits} verify_ms={:.0} \
         max_wal_bytes={max_wal} final_wal_bytes={}",
        median(verify_ms),
        size()
    );
    assert!(commits > 0, "premise: the writer committed");
}
