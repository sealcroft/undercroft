//! ROADMAP O279 through the surfaces: the CLI's `open_store_as` — which
//! `serve-mcp` and `serve-http`'s `/mcp` open through as well — and `/v1`'s
//! `store_for`, each driven through a real `backup restore` swapped in between
//! an open's `Connection::open` and its first statement. The store refuses such
//! an open with the reopen class; these prove each surface REOPENS once onto
//! the restored vault, says a second race in a row rather than chasing it, and
//! that `/v1`'s embedder factory — which reads the vault's recorded identity
//! through the store before the open — answers the store's classes instead of
//! a 500.

use super::*;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use undercroft_store::open_pause::{self, Opener};
use undercroft_store::{BackupOutcome, RestoreOutcome, StoreError};

const VAULT: &str = "o279s";
const NOW: i64 = 1_790_000_000;

fn mgr(root: &std::path::Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn vdir(root: &std::path::Path) -> PathBuf {
    root.join("vaults").join(VAULT)
}

fn hash(
    _: &Vault,
) -> std::result::Result<Box<dyn undercroft_core::embed::Embedder + Send>, StoreError> {
    Ok(Box::new(undercroft_core::HashEmbedder))
}

/// A sealed vault of `n` drawers, its archive, and `later` saves after it.
fn vault_with_archive(n: usize, later: u32) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    {
        let mut s =
            VaultStore::open(mgr(root).create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
        let batch: Vec<Drawer> = (0..n)
            .map(|i| {
                Drawer::new(
                    "w1",
                    "r",
                    format!("note {i}: the harbour ledger names cargo {i}"),
                    Some("o279s.md".into()),
                    i as u32,
                    "test",
                )
            })
            .collect();
        s.upsert_many(&batch).unwrap();
    }
    let arch = {
        let s = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
        match s.backup(&root.join("backups")).unwrap() {
            BackupOutcome::Created(r) => root.join("backups").join(r.name),
            BackupOutcome::Refused(r) => panic!("premise: the vault verifies ({r:?})"),
        }
    };
    {
        let mut s = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
        for i in 0..later {
            s.upsert(&Drawer::new(
                "w2",
                "r",
                format!("a later save {i}"),
                Some("later.md".into()),
                i,
                "test",
            ))
            .unwrap();
        }
    }
    (dir, arch)
}

/// Swap `arch` in, by a real restore, each of the first `times` times `at`
/// fires for the vault under `root`; returns how many ran.
fn race(
    root: &std::path::Path,
    at: Opener,
    arch: &std::path::Path,
    times: usize,
) -> Arc<AtomicUsize> {
    let ran = Arc::new(AtomicUsize::new(0));
    let (r, arch, ran2) = (root.to_path_buf(), arch.to_path_buf(), ran.clone());
    open_pause::set(
        &vdir(root),
        Arc::new(move |here| {
            if here == at && ran2.load(Ordering::SeqCst) < times {
                ran2.fetch_add(1, Ordering::SeqCst);
                match undercroft_store::restore_archive(&mgr(&r), &arch, None, true, &hash) {
                    Ok(RestoreOutcome::Restored(_)) => {}
                    other => panic!("premise: the restore ran ({:?})", other.err()),
                }
            }
        }),
    );
    ran
}

fn is_reopen_class(e: &anyhow::Error) -> bool {
    e.chain().any(|l| {
        matches!(
            l.downcast_ref::<StoreError>(),
            Some(StoreError::StaleUnlock(m)) if m.contains("ROADMAP O279")
        )
    })
}

/// **The CLI (and MCP) reopen once onto the restored vault**, on both
/// postures, for a swap at the embedder read `open_store_once` makes first and
/// at the store's own open: the first attempt is refused, the retry serves the
/// restored vault's 200 rows — never the 220 the restore replaced.
#[test]
fn o279_open_store_as_reopens_onto_the_restored_vault() {
    for (at, posture, label) in [
        (Opener::RecordedEmbedder, Posture::ReadWrite, "writable"),
        (Opener::Writable, Posture::ReadWrite, "writable"),
        (Opener::RecordedEmbedder, Posture::ReadOnly, "read-only"),
        (Opener::ReadOnly, Posture::ReadOnly, "read-only"),
    ] {
        let (dir, arch) = vault_with_archive(200, 20);
        let root = dir.path();
        let ran = race(root, at, &arch, 1);
        let opened = open_store_as(root, VAULT, posture);
        open_pause::clear(&vdir(root));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "{at:?}: premise: the window was reached"
        );
        let store = opened.unwrap_or_else(|e| panic!("{at:?} {label}: {e:#}"));
        assert_eq!(
            store.count().unwrap(),
            200,
            "{at:?} {label}: the reopen serves the restored vault"
        );
    }
}

/// **A second race in a row is said, not chased** (O257 item 4's one retry):
/// both attempts refused, the reopen class reaches the caller — exit 1, never a
/// vault served from a file the path no longer names.
#[test]
fn o279_open_store_as_says_a_second_race_in_a_row() {
    let (dir, arch) = vault_with_archive(100, 5);
    let root = dir.path();
    let ran = race(root, Opener::Writable, &arch, 2);
    let opened = open_store_as(root, VAULT, Posture::ReadWrite);
    open_pause::clear(&vdir(root));
    assert_eq!(
        ran.load(Ordering::SeqCst),
        2,
        "premise: both attempts raced"
    );
    match opened {
        Err(e) => assert!(is_reopen_class(&e), "{e:#}"),
        Ok(_) => panic!("a second race was served"),
    }
}

/// One `/v1` request answered by `tenancy`: status and body.
fn call(tenancy: &mut tenant::Tenancy, path: &str) -> (u16, String) {
    call_method(tenancy, "GET", path)
}

/// [`call`] with the method stated — `DELETE /v1/vaults/{id}` (ROADMAP O291).
fn call_method(tenancy: &mut tenant::Tenancy, method: &str, path: &str) -> (u16, String) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().expect("tcp listener");
    let raw = format!("{method} {path} HTTP/1.0\r\n\r\n");
    let client = std::thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        resp
    });
    let req = server.recv().unwrap();
    tenancy.handle(req, NOW);
    let resp = client.join().unwrap();
    let code: u16 = resp
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {resp:?}"));
    (
        code,
        resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    )
}

/// **`/v1` reopens once too**, for a swap at its embedder factory's read of
/// the recorded identity and at the store's open: 200, and the restored
/// vault's rows. The factory's refusal used to be a 500 outside the retry.
#[test]
fn o279_v1_reopens_onto_the_restored_vault() {
    for at in [Opener::RecordedEmbedder, Opener::Writable] {
        let (dir, arch) = vault_with_archive(200, 20);
        let root = dir.path();
        let mut tenancy =
            tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
        let ran = race(root, at, &arch, 1);
        let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
        open_pause::clear(&vdir(root));
        assert_eq!(ran.load(Ordering::SeqCst), 1, "{at:?}: premise: the window");
        assert_eq!(code, 200, "{at:?}: {body}");
        assert!(
            body.contains("\"drawers\":200"),
            "{at:?}: the restored rows: {body}"
        );
    }
}

/// **A second race in a row on `/v1`** answers the reopen class: 409 with no
/// integrity class, never a 500 and never a served vault.
#[test]
fn o279_v1_says_a_second_race_in_a_row() {
    let (dir, arch) = vault_with_archive(100, 5);
    let root = dir.path();
    let mut tenancy =
        tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
    let ran = race(root, Opener::RecordedEmbedder, &arch, 2);
    let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    open_pause::clear(&vdir(root));
    assert_eq!(
        ran.load(Ordering::SeqCst),
        2,
        "premise: both attempts raced"
    );
    assert_eq!(code, 409, "{body}");
    assert!(!body.contains("\"class\""), "no integrity class: {body}");
    assert!(body.contains("ROADMAP O279"), "{body}");
}

/// **ROADMAP O257 items 1 and 7 on `/v1`'s factory path**: a `VaultHeld` the
/// factory's `recorded_embedder` raises is 409 with no class — this route
/// answered every factory error 500, outside the retry — while a factory
/// failure that is not the store's stays a 500.
#[test]
fn o279_v1_answers_the_factory_s_store_refusals_in_the_store_s_classes() {
    let (dir, _) = vault_with_archive(10, 0);
    let root = dir.path();
    let held: tenant::EmbedderFactory = Box::new(|_| {
        Err(anyhow::Error::from(StoreError::VaultHeld(
            "another process holds this vault exclusively".into(),
        )))
    });
    let mut tenancy = tenant::Tenancy::new(mgr(root), held, false).expect("no secret declared");
    let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    assert_eq!(code, 409, "{body}");
    assert!(!body.contains("\"class\""), "no integrity class: {body}");

    let broken: tenant::EmbedderFactory =
        Box::new(|_| Err(anyhow::anyhow!("the model file is not there")));
    let mut tenancy = tenant::Tenancy::new(mgr(root), broken, false).expect("no secret declared");
    let (code, _) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    assert_eq!(code, 500, "a factory failure that is not the store's");

    let calls = Arc::new(Mutex::new(0));
    let stale: tenant::EmbedderFactory = {
        let calls = calls.clone();
        Box::new(move |_| {
            *calls.lock().unwrap() += 1;
            Err(anyhow::Error::from(StoreError::StaleUnlock(
                "a file that moved (ROADMAP O279)".into(),
            )))
        })
    };
    let mut tenancy = tenant::Tenancy::new(mgr(root), stale, false).expect("no secret declared");
    let (code, _) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    assert_eq!(code, 409);
    assert_eq!(
        *calls.lock().unwrap(),
        2,
        "the reopen class is retried exactly once"
    );
}

/// **ROADMAP O284 through `open_store_as`, both postures.** A torn
/// `vault.json.next` in the live vault and a restore landing after the unlock
/// and before the database open: the first attempt is refused with the reopen
/// class, and the retry serves the restored vault's 200 rows with no note
/// about the `.next` the vault set aside held.
#[test]
fn o284_open_store_as_drops_the_set_aside_vaults_unlock_notes() {
    for (at, posture) in [
        (Opener::WritableLayout, Posture::ReadWrite),
        (Opener::ReadOnlyLayout, Posture::ReadOnly),
    ] {
        let (dir, arch) = vault_with_archive(200, 20);
        let root = dir.path();
        std::fs::write(vdir(root).join("vault.json.next"), b"{ torn").unwrap();
        let ran = race(root, at, &arch, 1);
        let opened = open_store_as(root, VAULT, posture);
        open_pause::clear(&vdir(root));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "{at:?}: premise: the window was reached"
        );
        let store = opened.unwrap_or_else(|e| panic!("{at:?}: {e:#}"));
        assert_eq!(store.count().unwrap(), 200, "{at:?}: the restored vault");
        assert!(
            !store
                .unhealed()
                .iter()
                .any(|n| n.contains("vault.json.next")),
            "{at:?}: the set-aside vault's note: {:?}",
            store.unhealed()
        );
    }
}

const DEFERRAL: &str = "adopted in memory only";

/// A sealed vault of `n` drawers, no handle left open.
fn fresh_vault(root: &std::path::Path, n: u32) {
    let mut s = VaultStore::open(mgr(root).create(VAULT, SecurityLevel::Sealed).unwrap()).unwrap();
    let batch: Vec<Drawer> = (0..n)
        .map(|i| {
            Drawer::new(
                "w1",
                "r",
                format!("note {i}: the harbour ledger names cargo {i}"),
                Some("o288s.md".into()),
                i,
                "test",
            )
        })
        .collect();
    s.upsert_many(&batch).unwrap();
}

/// A committed rotation whose promote was deferred, by O266's hand recipe:
/// rotate, move the new `vault.json` to `vault.json.next`, put the retired
/// bytes back.
fn defer_by_hand(root: &std::path::Path) {
    let retired = std::fs::read(vdir(root).join("vault.json")).unwrap();
    {
        let m = mgr(root);
        let mut s = VaultStore::open(m.unlock(VAULT).unwrap()).unwrap();
        s.rotate_keys(m.rotation_candidate(VAULT).unwrap()).unwrap();
    }
    std::fs::rename(
        vdir(root).join("vault.json"),
        vdir(root).join("vault.json.next"),
    )
    .unwrap();
    std::fs::write(vdir(root).join("vault.json"), &retired).unwrap();
}

/// At the read-only open's layout pause, once, another open promotes the
/// deferral — after the unlock read it, before the database open.
fn promote_at_the_read_only_layout(root: &std::path::Path) -> Arc<AtomicUsize> {
    let ran = Arc::new(AtomicUsize::new(0));
    let (r, ran2) = (root.to_path_buf(), ran.clone());
    open_pause::set(
        &vdir(root),
        Arc::new(move |here| {
            if here == Opener::ReadOnlyLayout && ran2.load(Ordering::SeqCst) == 0 {
                ran2.fetch_add(1, Ordering::SeqCst);
                drop(VaultStore::open(mgr(&r).unlock(VAULT).unwrap()).unwrap());
            }
        }),
    );
    ran
}

/// **ROADMAP O288 through `open_store_as`, read-only.** A deferral, and another
/// open PROMOTING it after the unlock and before the database open: the first
/// attempt is refused with the reopen class and the retry serves the promoted
/// vault. Before O288 the first attempt served it, saying the promotion was
/// deferred and not to delete a staging file the promote had already removed.
#[test]
fn o288_open_store_as_drops_a_deferral_promoted_after_the_unlock() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 20);
    defer_by_hand(root);
    assert!(
        open_store_as(root, VAULT, Posture::ReadOnly)
            .unwrap()
            .unhealed()
            .iter()
            .any(|n| n.contains(DEFERRAL)),
        "premise: the hand recipe made a deferral a read-only open reports"
    );
    let ran = promote_at_the_read_only_layout(root);
    let opened = open_store_as(root, VAULT, Posture::ReadOnly);
    open_pause::clear(&vdir(root));
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "premise: the window was reached"
    );
    assert!(
        !vdir(root).join("vault.json.next").exists(),
        "premise: the other open promoted it"
    );
    let store = opened.unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        !store.unhealed().iter().any(|n| n.contains(DEFERRAL)),
        "a note about a deferral the promote had ended: {:?}",
        store.unhealed()
    );
    assert_eq!(store.count().unwrap(), 20);
}

/// **ROADMAP O288's R1 through `open_store_as`, read-only.** An anchor, then a
/// rotation that commits and whose promote is deferred, both between the
/// unlock's two manifest reads: the unlock read no staging file (it reads
/// `vault.json.next` first), O257's race arm refuses the first attempt, and the
/// retry serves the deferral with its TRUE note. Read the old way round with
/// nothing after it, the first attempt answered `ManifestTampered` — exit 2,
/// never retried. This arm guards the SURFACE outcome and cannot tell the two
/// mechanisms apart: with the open's rotation check in place, the old order
/// also ends in one retry (measured, O288's counterfactuals), so the order
/// itself is gated in the store (the O257 wording) and at the vault (the
/// anchor read), and this arm fails only when both are gone.
#[test]
fn o288_open_store_as_serves_a_rotation_inside_the_unlock_after_one_retry() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 20);
    let writer = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
    let fired = Arc::new(AtomicUsize::new(0));
    let (r, f) = (root.to_path_buf(), fired.clone());
    undercroft_vault::fixture::between_unlock_reads(move || {
        f.fetch_add(1, Ordering::SeqCst);
        let mut writer = writer;
        writer
            .upsert(&Drawer::new(
                "w1",
                "r",
                "a late write the rotation retires".into(),
                Some("o288s.md".into()),
                99,
                "test",
            ))
            .unwrap();
        drop(writer);
        defer_by_hand(&r);
    });
    let opened = open_store_as(root, VAULT, Posture::ReadOnly);
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "premise: the hook ran inside the first unlock"
    );
    let store = opened.unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        store.unhealed().iter().any(|n| n.contains(DEFERRAL)),
        "the retry reports the deferral that is really there: {:?}",
        store.unhealed()
    );
    assert_eq!(store.count().unwrap(), 21);
    assert!(store.verify().unwrap().ok());
}

/// At the writable open's layout pause, once — after its unlock read the
/// deferral, before its database open — `edit` runs: the P-W rollback (another
/// open promotes and writes, the database is restored to a copy two writes
/// behind, `vault.json` deleted) or a forged `vault.json`.
fn edit_at_the_writable_layout(root: &std::path::Path, edit: &'static str) -> Arc<AtomicUsize> {
    let ran = Arc::new(AtomicUsize::new(0));
    let (r, ran2) = (root.to_path_buf(), ran.clone());
    open_pause::set(
        &vdir(root),
        Arc::new(move |here| {
            if here != Opener::WritableLayout || ran2.fetch_add(1, Ordering::SeqCst) != 0 {
                return;
            }
            let json = vdir(&r).join("vault.json");
            if edit == "forged" {
                let mut v: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
                let mac = v["manifest_mac_hex"].as_str().unwrap().to_string();
                let first = if mac.starts_with('0') { "1" } else { "0" };
                v["manifest_mac_hex"] = serde_json::Value::String(format!("{first}{}", &mac[1..]));
                std::fs::write(&json, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
                return;
            }
            let copy = r.join("copy.db");
            {
                let mut s = VaultStore::open(mgr(&r).unlock(VAULT).unwrap()).unwrap();
                let save = |s: &mut VaultStore, i: u32| {
                    s.upsert(&Drawer::new(
                        "w1",
                        "r",
                        format!("after the promote {i}"),
                        Some("o290s.md".into()),
                        i,
                        "test",
                    ))
                    .unwrap();
                };
                save(&mut s, 0);
                save(&mut s, 1);
                let c = rusqlite::Connection::open(vdir(&r).join("vault.db")).unwrap();
                c.execute("VACUUM INTO ?1", [copy.to_str().unwrap()])
                    .unwrap();
                drop(c);
                for i in 2..5 {
                    save(&mut s, i);
                }
            }
            assert!(
                !vdir(&r).join("vault.json.next").exists(),
                "premise: the other open promoted the deferral"
            );
            std::fs::remove_file(&json).unwrap();
            for f in ["vault.db", "vault.db-wal", "vault.db-shm"] {
                let _ = std::fs::remove_file(vdir(&r).join(f));
            }
            std::fs::copy(&copy, vdir(&r).join("vault.db")).unwrap();
        }),
    );
    ran
}

/// **ROADMAP O290 through `open_store_as`, writable.** A deferral, and the P-W
/// rollback landed between the open's unlock and its database open: the open
/// refuses with the integrity verdict for the absent manifest — exit 2 — and is
/// NOT retried, so the answer is not the fresh unlock's `NotFound`. Before O290
/// it served the rolled-back vault, `verify` clean, with a crash-lag note.
#[test]
fn o290_open_store_as_refuses_a_rollback_in_the_writable_window_without_a_retry() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 20);
    defer_by_hand(root);
    let ran = edit_at_the_writable_layout(root, "rollback");
    let opened = open_store_as(root, VAULT, Posture::ReadWrite);
    open_pause::clear(&vdir(root));
    assert!(
        ran.load(Ordering::SeqCst) >= 1,
        "premise: the window was reached"
    );
    let e = match opened {
        Err(e) => e,
        Ok(s) => panic!(
            "served the rolled-back vault at height {:?}: {:?}",
            s.chain_state().map(|c| c.1),
            s.unhealed()
        ),
    };
    assert!(
        e.chain().any(|l| matches!(
            l.downcast_ref::<StoreError>(),
            Some(StoreError::Vault(undercroft_vault::VaultError::CorruptManifest(m)))
                if m.contains("vault.json is missing from")
        )),
        "the absent manifest's verdict, never a retry's NotFound: {e:#}"
    );
    assert!(integrity_verdict(&e), "exit 2: {e:#}");
    assert!(
        !vdir(root).join("vault.json").exists(),
        "nothing written over the gap"
    );
}

/// **ROADMAP O290 through `open_store_as`, writable: a forged manifest in the
/// window pages.** The heal overwrote it with the staged manifest and served,
/// with no tamper event; it is now the tamper verdict, and the forged file is
/// left for the operator.
#[test]
fn o290_open_store_as_refuses_a_forged_manifest_in_the_writable_window() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 20);
    defer_by_hand(root);
    let ran = edit_at_the_writable_layout(root, "forged");
    let opened = open_store_as(root, VAULT, Posture::ReadWrite);
    open_pause::clear(&vdir(root));
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "premise: the window was reached"
    );
    let e = opened.err().expect("a forged vault.json was served");
    assert!(
        format!("{e:#}").contains("possible tampering"),
        "the tamper verdict: {e:#}"
    );
    assert!(integrity_verdict(&e), "exit 2: {e:#}");
    assert!(
        vdir(root).join("vault.json.next").exists(),
        "the staged manifest is left beside the forged one"
    );
}

/// **ROADMAP O290 on `/v1`, writable**: `store_for` answers the P-W rollback in
/// the window with 409 and the integrity class. It answered 200.
#[test]
fn o290_v1_writable_refuses_a_rollback_in_the_window_as_integrity() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 20);
    defer_by_hand(root);
    let mut tenancy =
        tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
    let ran = edit_at_the_writable_layout(root, "rollback");
    let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    open_pause::clear(&vdir(root));
    assert!(
        ran.load(Ordering::SeqCst) >= 1,
        "premise: the window was reached"
    );
    assert_eq!(code, 409, "{body}");
    assert!(body.contains("\"class\":\"integrity\""), "{body}");
    assert!(body.contains("vault.json is missing from"), "{body}");
}

/// **ROADMAP O290 on `/v1`, writable: a forged manifest in the window is the
/// tamper verdict**, 409 with the integrity class; it was overwritten and
/// served. Like the CLI's forged arm this guards the surface OUTCOME — a reopen's
/// fresh unlock would page too (measured under O290's cf3) — and the store's
/// arm pins the mechanism.
#[test]
fn o290_v1_writable_refuses_a_forged_manifest_in_the_window() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 20);
    defer_by_hand(root);
    let mut tenancy =
        tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
    let ran = edit_at_the_writable_layout(root, "forged");
    let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    open_pause::clear(&vdir(root));
    assert!(
        ran.load(Ordering::SeqCst) >= 1,
        "premise: the window was reached"
    );
    assert_eq!(code, 409, "{body}");
    assert!(body.contains("\"class\":\"integrity\""), "{body}");
    assert!(body.contains("possible tampering"), "{body}");
    assert!(
        vdir(root).join("vault.json.next").exists(),
        "the staged manifest is left beside the forged one"
    );
}

/// **ROADMAP O288 on `/v1`, read-only**: `store_for` answers the same race
/// with one reopen, and serves the promoted vault with no deferral note.
#[test]
fn o288_v1_read_only_drops_a_deferral_promoted_after_the_unlock() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 20);
    defer_by_hand(root);
    let ro = VaultManager::open_as(root, None, undercroft_vault::Access::ReadOnly).unwrap();
    let mut tenancy =
        tenant::Tenancy::new(ro, embedder_factory(), true).expect("no secret declared");
    let ran = promote_at_the_read_only_layout(root);
    let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    open_pause::clear(&vdir(root));
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "premise: the window was reached"
    );
    assert!(
        !vdir(root).join("vault.json.next").exists(),
        "premise: the other open promoted it"
    );
    assert_eq!(code, 200, "{body}");
    assert!(body.contains("\"drawers\":20"), "{body}");
    assert!(!body.contains(DEFERRAL), "{body}");
}

/// **ROADMAP O291 through the CLI's open**: a vault deleted between
/// `open_store_as`'s unlock and its connect — at the writable and read-only
/// layouts, and inside the recorded-embedder read the surface makes first —
/// reaches the operator as "no such vault" (exit 1) through the reopen class
/// and its one retry. It was a raw SQLite "unable to open" on the writable
/// posture and `DatabaseMissing`, the integrity verdict (exit 2), on the
/// read-only one; and no open creates the directory back.
#[test]
fn o291_open_store_as_meets_a_delete_in_its_window_as_no_such_vault() {
    for (posture, at) in [
        (Posture::ReadWrite, Opener::WritableLayout),
        (Posture::ReadOnly, Opener::ReadOnlyLayout),
        (Posture::ReadWrite, Opener::RecordedEmbedder),
    ] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        fresh_vault(root, 5);
        let ran = Arc::new(AtomicUsize::new(0));
        {
            let (r, ran) = (root.to_path_buf(), ran.clone());
            open_pause::set(
                &vdir(root),
                Arc::new(move |here| {
                    if here == at && ran.fetch_add(1, Ordering::SeqCst) == 0 {
                        assert_eq!(
                            undercroft_store::delete_vault(&mgr(&r), VAULT).unwrap(),
                            undercroft_store::Deleted::Removed
                        );
                    }
                }),
            );
        }
        let opened = open_store_as(root, VAULT, posture);
        open_pause::clear(&vdir(root));
        assert!(
            ran.load(Ordering::SeqCst) >= 1,
            "premise: {at:?} was reached"
        );
        let e = match opened {
            Err(e) => e,
            Ok(_) => panic!("{at:?}: served a deleted vault"),
        };
        assert!(
            e.chain().any(|l| matches!(
                l.downcast_ref::<StoreError>(),
                Some(StoreError::Vault(undercroft_vault::VaultError::NotFound(_)))
            ) || matches!(
                l.downcast_ref::<undercroft_vault::VaultError>(),
                Some(undercroft_vault::VaultError::NotFound(_))
            )),
            "{at:?}: the retry finds no vault: {e:#}"
        );
        assert!(
            !integrity_verdict(&e),
            "{at:?}: a delete is not tampering: {e:#}"
        );
        assert!(
            !vdir(root).exists(),
            "{at:?}: an open created the vault back"
        );
    }
}

/// **ROADMAP O291 through `/v1`'s open**: the same window answers 404, never a
/// 500 or the integrity class.
#[test]
fn o291_v1_meets_a_delete_in_its_window_as_404() {
    for at in [Opener::WritableLayout, Opener::RecordedEmbedder] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        fresh_vault(root, 5);
        let mut tenancy =
            tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
        let ran = Arc::new(AtomicUsize::new(0));
        {
            let (r, ran) = (root.to_path_buf(), ran.clone());
            open_pause::set(
                &vdir(root),
                Arc::new(move |here| {
                    if here == at && ran.fetch_add(1, Ordering::SeqCst) == 0 {
                        undercroft_store::delete_vault(&mgr(&r), VAULT).unwrap();
                    }
                }),
            );
        }
        let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
        open_pause::clear(&vdir(root));
        assert!(
            ran.load(Ordering::SeqCst) >= 1,
            "premise: {at:?} was reached"
        );
        assert_eq!(code, 404, "{at:?}: {body}");
        assert!(!body.contains("\"class\""), "{at:?}: {body}");
    }
}

/// **ROADMAP O291, the `/v1` route**: `DELETE /v1/vaults/{id}` evicts this
/// server's own handle and deletes (200, then 404); beside another connection
/// holding the vault it answers 409 with NO class, names a delete, and changes
/// nothing — where it answered 200 and removed the vault beneath the holder.
#[test]
fn o291_v1_delete_evicts_its_own_handle_and_refuses_beside_a_holder() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 5);
    let mut tenancy =
        tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
    // A holder: another connection that has read.
    let holder = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
    assert_eq!(holder.count().unwrap(), 5, "premise: the holder read");
    let (code, _) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    assert_eq!(code, 200, "premise: /v1 cached its own handle");
    let (code, body) = call_method(&mut tenancy, "DELETE", &format!("/v1/vaults/{VAULT}"));
    assert_eq!(code, 409, "{body}");
    assert!(!body.contains("\"class\""), "{body}");
    assert!(
        body.contains("Nothing was deleted") && !body.contains("restore"),
        "{body}"
    );
    assert!(vdir(root).join("vault.json").exists() && vdir(root).join("vault.db").exists());
    assert_eq!(
        holder.count().unwrap(),
        5,
        "the holder serves a vault that still exists"
    );
    drop(holder);
    // Its own handle (re-opened by this stats call) is evicted by the route.
    let (code, _) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    assert_eq!(code, 200);
    let (code, body) = call_method(&mut tenancy, "DELETE", &format!("/v1/vaults/{VAULT}"));
    assert_eq!(code, 200, "{body}");
    assert!(body.contains("\"deleted\":true"), "{body}");
    assert!(!vdir(root).exists());
    let (code, _) = call_method(&mut tenancy, "DELETE", &format!("/v1/vaults/{VAULT}"));
    assert_eq!(code, 404);
}
