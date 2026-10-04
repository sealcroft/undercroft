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

/// The files and marker a rotation reconcile could write (ROADMAP O296).
fn o296_disk(root: &std::path::Path) -> (Vec<u8>, Option<Vec<u8>>, Option<String>) {
    let c = rusqlite::Connection::open_with_flags(
        vdir(root).join("vault.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    (
        std::fs::read(vdir(root).join("vault.json")).unwrap(),
        std::fs::read(vdir(root).join("vault.json.next")).ok(),
        rusqlite::OptionalExtension::optional(c.query_row(
            "SELECT value FROM meta WHERE key = 'keycheck'",
            [],
            |r| r.get(0),
        ))
        .unwrap(),
    )
}

/// ROADMAP O296's two surface routes, built by O266's hand recipe: `deleted`,
/// the marker row deleted beside the deferral; otherwise a pre-rotation copy of
/// the database restored with the live staged-generation marker copied onto it.
fn o296_contradiction(root: &std::path::Path, deleted: bool) {
    fresh_vault(root, 20);
    let copy = root.join("copy.db");
    rusqlite::Connection::open(vdir(root).join("vault.db"))
        .unwrap()
        .execute("VACUUM INTO ?1", [copy.to_str().unwrap()])
        .unwrap();
    defer_by_hand(root);
    let db = vdir(root).join("vault.db");
    if deleted {
        let n = rusqlite::Connection::open(&db)
            .unwrap()
            .execute("DELETE FROM meta WHERE key = 'keycheck'", [])
            .unwrap();
        assert_eq!(n, 1, "premise: a marker to delete");
        return;
    }
    let (_, _, g1) = o296_disk(root);
    for f in ["vault.db", "vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(vdir(root).join(f));
    }
    std::fs::copy(&copy, &db).unwrap();
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute(
            "UPDATE meta SET value = ?1 WHERE key = 'keycheck'",
            [g1.expect("premise: the staged generation's marker")],
        )
        .unwrap();
}

/// **ROADMAP O296 through `open_store_as`, writable**: a database that
/// contradicts its manifest — the marker deleted during a deferral, or an old
/// database carrying the staged generation's marker — is the integrity verdict
/// (exit 2) with `vault.json`, `vault.json.next` and the marker exactly as
/// found. It used to delete `.next` — or write the staged manifest over the
/// retired one — and seed the marker, and only then refuse in the same class.
#[test]
fn o296_open_store_as_refuses_a_contradicting_database_and_writes_nothing() {
    for deleted in [true, false] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        o296_contradiction(root, deleted);
        let before = o296_disk(root);
        assert!(before.1.is_some(), "premise: the stage is on disk");
        let e = match open_store_as(root, VAULT, Posture::ReadWrite) {
            Err(e) => e,
            Ok(_) => panic!("deleted={deleted}: served a contradicting database"),
        };
        assert!(
            e.chain().any(|l| matches!(
                l.downcast_ref::<StoreError>(),
                Some(StoreError::Integrity(m)) if m == "audit-chain head"
            )),
            "deleted={deleted}: {e:#}"
        );
        assert!(integrity_verdict(&e), "exit 2: {e:#}");
        assert_eq!(
            o296_disk(root),
            before,
            "deleted={deleted}: nothing written"
        );
    }
}

/// **ROADMAP O296 on `/v1`, writable**: `store_for` answers the same two states
/// 409 with the integrity class, and writes nothing.
#[test]
fn o296_v1_refuses_a_contradicting_database_and_writes_nothing() {
    for deleted in [true, false] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        o296_contradiction(root, deleted);
        let before = o296_disk(root);
        let mut tenancy =
            tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
        let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
        assert_eq!(code, 409, "deleted={deleted}: {body}");
        assert!(body.contains("\"class\":\"integrity\""), "{body}");
        assert!(body.contains("audit-chain head"), "{body}");
        assert_eq!(
            o296_disk(root),
            before,
            "deleted={deleted}: nothing written"
        );
    }
}

/// What an open over a head-less chain could write (ROADMAP O303): the
/// manifest's bytes, the marker, `chain_meta` and the `audit` row count.
type O303Disk = (Vec<u8>, Option<String>, Vec<(String, String)>, i64);

fn o303_disk(root: &std::path::Path) -> O303Disk {
    let c = rusqlite::Connection::open_with_flags(
        vdir(root).join("vault.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let chain_meta = c
        .prepare("SELECT key, value FROM chain_meta ORDER BY key")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    (
        std::fs::read(vdir(root).join("vault.json")).unwrap(),
        rusqlite::OptionalExtension::optional(c.query_row(
            "SELECT value FROM meta WHERE key = 'keycheck'",
            [],
            |r| r.get(0),
        ))
        .unwrap(),
        chain_meta,
        c.query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
            .unwrap(),
    )
}

/// ROADMAP O303's two surface states: `headless`, every `chain_meta` row and
/// the version-2 commitment deleted (records, no head — `main` opened it at the
/// manifest's height and took writes); otherwise the height alone deleted
/// (`main` served reads and answered every write a raw 500).
fn o303_state(root: &std::path::Path, headless: bool) -> &'static str {
    fresh_vault(root, 20);
    let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
    if headless {
        assert!(c.execute("DELETE FROM chain_meta", []).unwrap() >= 1);
        assert_eq!(
            c.execute("DELETE FROM audit WHERE record_id = 'migrate/chain-v2'", [])
                .unwrap(),
            1,
            "premise: the version-2 commitment"
        );
        "holds no committed head while `audit` holds records"
    } else {
        assert_eq!(
            c.execute("DELETE FROM chain_meta WHERE key = 'writes'", [])
                .unwrap(),
            1,
            "premise: a height to delete"
        );
        "a committed head with no committed height"
    }
}

/// **ROADMAP O303 through `open_store_as`, writable**: a head-less chain with
/// records, and a head with no height, are the integrity verdict (exit 2) with
/// the manifest, the marker, `chain_meta` and `audit` exactly as found.
#[test]
fn o303_open_store_as_refuses_a_headless_chain_and_writes_nothing() {
    for headless in [true, false] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let fragment = o303_state(root, headless);
        let before = o303_disk(root);
        let e = match open_store_as(root, VAULT, Posture::ReadWrite) {
            Err(e) => e,
            Ok(_) => panic!("headless={headless}: served"),
        };
        assert!(
            e.chain().any(|l| matches!(
                l.downcast_ref::<StoreError>(),
                Some(StoreError::IntegrityFinding(m)) if m.contains(fragment)
            )),
            "headless={headless}: {e:#}"
        );
        assert!(integrity_verdict(&e), "exit 2: {e:#}");
        assert_eq!(
            o303_disk(root),
            before,
            "headless={headless}: nothing written"
        );
    }
}

/// **ROADMAP O303, the two other answers through the surfaces**: an erased
/// audit trail beside a manifest past genesis is the tamper verdict through
/// `open_store_as` (exit 2), nothing written — `main` opened it as an empty
/// vault at the manifest's height and took writes; and a READ-ONLY server over
/// a fresh vault's empty chain answers 409 with NO integrity class, the posture
/// error its absent-table twin answers.
#[test]
fn o303_surfaces_answer_an_erased_trail_and_the_empty_chain() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 20);
    {
        let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
        c.execute("DELETE FROM chain_meta", []).unwrap();
        c.execute("DELETE FROM audit", []).unwrap();
    }
    let before = o303_disk(root);
    let e = match open_store_as(root, VAULT, Posture::ReadWrite) {
        Err(e) => e,
        Ok(_) => panic!("served an erased trail"),
    };
    assert!(
        e.chain().any(|l| matches!(
            l.downcast_ref::<StoreError>(),
            Some(StoreError::Vault(
                undercroft_vault::VaultError::ManifestTampered
            ))
        )),
        "{e:#}"
    );
    assert!(integrity_verdict(&e), "exit 2: {e:#}");
    assert_eq!(o303_disk(root), before, "nothing written");

    let dir = TempDir::new().unwrap();
    let root = dir.path();
    mgr(root).create(VAULT, SecurityLevel::Sealed).unwrap();
    let created = std::fs::read(vdir(root).join("vault.json")).unwrap();
    drop(open_store_as(root, VAULT, Posture::ReadWrite).unwrap());
    {
        let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
        c.execute("DELETE FROM chain_meta", []).unwrap();
        c.execute("DELETE FROM audit", []).unwrap();
    }
    std::fs::write(vdir(root).join("vault.json"), &created).unwrap();
    let ro = VaultManager::open_as(root, None, undercroft_vault::Access::ReadOnly).unwrap();
    let mut tenancy =
        tenant::Tenancy::new(ro, embedder_factory(), true).expect("no secret declared");
    let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    assert_eq!(code, 409, "{body}");
    assert!(
        !body.contains("\"class\""),
        "a posture error, not a verdict: {body}"
    );
    assert!(body.contains("chain_meta"), "{body}");
}

/// **ROADMAP O303 on `/v1`**: `store_for` answers both states 409 with the
/// integrity class and writes nothing; a READ-ONLY server serves them with the
/// finding reported, and its `stats` — whose height read answered a
/// `CorruptRow` or a raw "Query returned no rows", a 500 — answers 409 too.
#[test]
fn o303_v1_refuses_a_headless_chain_and_never_answers_500() {
    for headless in [true, false] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let fragment = o303_state(root, headless);
        let before = o303_disk(root);
        let mut tenancy =
            tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
        let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
        assert_eq!(code, 409, "headless={headless}: {body}");
        assert!(body.contains("\"class\":\"integrity\""), "{body}");
        assert!(body.contains(fragment), "{body}");
        assert_eq!(
            o303_disk(root),
            before,
            "headless={headless}: nothing written"
        );

        let ro = VaultManager::open_as(root, None, undercroft_vault::Access::ReadOnly).unwrap();
        let mut tenancy =
            tenant::Tenancy::new(ro, embedder_factory(), true).expect("no secret declared");
        let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
        assert_eq!(code, 409, "read-only headless={headless}: {body}");
        assert!(body.contains("\"class\":\"integrity\""), "{body}");
        assert_eq!(o303_disk(root), before, "read-only headless={headless}");
    }
}

/// **ROADMAP O303, `POST …/anchor` beneath a cached handle**: `chain_meta`
/// emptied while the server holds the vault. `main` answered 500 — the reconcile
/// read "unseeded", then `chain_state` answered `CorruptRow`. It is 409 with the
/// integrity class, and nothing is anchored or seeded.
#[test]
fn o303_v1_anchor_beneath_a_cached_handle_refuses() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 5);
    let mut tenancy =
        tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
    let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    assert_eq!(code, 200, "premise: the handle is open and cached: {body}");
    assert!(
        rusqlite::Connection::open(vdir(root).join("vault.db"))
            .unwrap()
            .execute("DELETE FROM chain_meta", [])
            .unwrap()
            >= 1
    );
    let before = o303_disk(root);
    let (code, body) = call_method(&mut tenancy, "POST", &format!("/v1/vaults/{VAULT}/anchor"));
    assert_eq!(code, 409, "{body}");
    assert!(body.contains("\"class\":\"integrity\""), "{body}");
    assert_eq!(o303_disk(root), before, "nothing anchored or seeded");
}

/// **ROADMAP O303, read-only, the EMPTY chain** — a fresh vault's, left by a
/// crash between the table's creation and its seed: the read-only open, which
/// may not seed it, answers the class its absent-table twin already answers —
/// `ReadOnlyUnmigrated`, exit 1, never the tamper verdict — and a writable open
/// adopts it.
#[test]
fn o303_open_store_as_read_only_declines_the_empty_chain() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    mgr(root).create(VAULT, SecurityLevel::Sealed).unwrap();
    let created = std::fs::read(vdir(root).join("vault.json")).unwrap();
    drop(open_store_as(root, VAULT, Posture::ReadWrite).unwrap());
    {
        let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
        c.execute("DELETE FROM chain_meta", []).unwrap();
        c.execute("DELETE FROM audit", []).unwrap();
    }
    std::fs::write(vdir(root).join("vault.json"), &created).unwrap();
    let e = match open_store_as(root, VAULT, Posture::ReadOnly) {
        Err(e) => e,
        Ok(_) => panic!("served an unseeded chain read-only"),
    };
    assert!(
        e.chain().any(|l| matches!(
            l.downcast_ref::<StoreError>(),
            Some(StoreError::ReadOnlyUnmigrated { .. })
        )),
        "{e:#}"
    );
    assert!(
        !integrity_verdict(&e),
        "exit 1, not the tamper verdict: {e:#}"
    );
    let s = open_store_as(root, VAULT, Posture::ReadWrite).expect("adopted");
    assert!(s.verify().unwrap().ok());
}

/// A deferral by hand; another open promotes it and writes past it, to a head
/// H; then the retired `vault.json` and the staged `.next` are put back (A2's),
/// with the database at H or rolled back below it. Returns H's bytes.
fn o304_another_head(root: &std::path::Path, rolled_back: bool) -> Vec<u8> {
    defer_by_hand(root);
    let (r, s) = (
        std::fs::read(vdir(root).join("vault.json")).unwrap(),
        std::fs::read(vdir(root).join("vault.json.next")).unwrap(),
    );
    let save = |n: u32, copy: Option<&std::path::Path>| {
        let mut st = VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap();
        for i in 0..n {
            st.upsert(&Drawer::new(
                "w1",
                "r",
                format!("o304 since the promote {i}"),
                Some("o304s.md".into()),
                i,
                "test",
            ))
            .unwrap();
        }
        if let Some(copy) = copy {
            let c = rusqlite::Connection::open(vdir(root).join("vault.db")).unwrap();
            c.execute("VACUUM INTO ?1", [copy.to_str().unwrap()])
                .unwrap();
        }
    };
    let mid = root.join("mid.db");
    save(1, Some(&mid));
    save(2, None);
    let h = std::fs::read(vdir(root).join("vault.json")).unwrap();
    std::fs::write(vdir(root).join("vault.json"), &r).unwrap();
    std::fs::write(vdir(root).join("vault.json.next"), &s).unwrap();
    if rolled_back {
        for f in ["vault.db", "vault.db-wal", "vault.db-shm"] {
            let _ = std::fs::remove_file(vdir(root).join(f));
        }
        std::fs::copy(&mid, vdir(root).join("vault.db")).unwrap();
    }
    h
}

/// Put `edit` in the writable open's licence-to-promote window, once.
fn o304_in_the_licence_window(
    root: &std::path::Path,
    edit: impl FnOnce(&std::path::Path) + 'static,
) -> Arc<AtomicUsize> {
    let ran = Arc::new(AtomicUsize::new(0));
    let (r, ran2) = (root.to_path_buf(), ran.clone());
    undercroft_vault::fixture::between_licence_and_promote(move || {
        ran2.fetch_add(1, Ordering::SeqCst);
        edit(&r);
    });
    ran
}

fn o304_flipped(bytes: &[u8]) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let mac = v["manifest_mac_hex"].as_str().unwrap().to_string();
    let first = if mac.starts_with('0') { "1" } else { "0" };
    v["manifest_mac_hex"] = serde_json::Value::String(format!("{first}{}", &mac[1..]));
    serde_json::to_vec_pretty(&v).unwrap()
}

fn o304_forge(root: &std::path::Path) {
    let json = vdir(root).join("vault.json");
    std::fs::write(&json, o304_flipped(&std::fs::read(&json).unwrap())).unwrap();
}

/// The database's `chain_meta` rows and `audit` count, read with no store.
fn o304_db(root: &std::path::Path) -> (Vec<(String, String)>, i64) {
    let c = rusqlite::Connection::open_with_flags(
        vdir(root).join("vault.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut st = c
        .prepare("SELECT key, value FROM chain_meta ORDER BY key")
        .unwrap();
    let rows = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let n = c
        .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
        .unwrap();
    (rows, n)
}

/// Count the writable opens that reach the layout pause: one, or a retry.
fn o304_count_writable_opens(root: &std::path::Path) -> Arc<AtomicUsize> {
    let opens = Arc::new(AtomicUsize::new(0));
    let o = opens.clone();
    open_pause::set(
        &vdir(root),
        Arc::new(move |here| {
            if here == Opener::WritableLayout {
                o.fetch_add(1, Ordering::SeqCst);
            }
        }),
    );
    opens
}

/// **ROADMAP O304 through `open_store_as`, writable.** A `vault.json` forged in
/// the licence-to-promote window — the one forced replay O296 put between the
/// licence's reads and the write — is the tamper verdict, exit 2, the forged
/// file and the staged `.next` left for the operator. It was overwritten by the
/// staged manifest and served.
#[test]
fn o304_open_store_as_refuses_a_manifest_forged_after_the_licence() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 20);
    defer_by_hand(root);
    let staged = std::fs::read(vdir(root).join("vault.json.next")).unwrap();
    let forged = o304_flipped(&std::fs::read(vdir(root).join("vault.json")).unwrap());
    let before = o304_db(root);
    let opens = o304_count_writable_opens(root);
    let ran = o304_in_the_licence_window(root, o304_forge);
    let opened = open_store_as(root, VAULT, Posture::ReadWrite);
    open_pause::clear(&vdir(root));
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "premise: the window was reached"
    );
    assert_eq!(opens.load(Ordering::SeqCst), 1, "not retried");
    assert_eq!(o304_db(root), before, "nothing committed");
    assert_eq!(
        std::fs::read(vdir(root).join("vault.json")).unwrap(),
        forged,
        "the forged bytes kept"
    );
    let e = opened
        .err()
        .expect("O304: a forged vault.json was overwritten and served");
    assert!(
        format!("{e:#}").contains("possible tampering"),
        "the tamper verdict: {e:#}"
    );
    assert!(integrity_verdict(&e), "exit 2: {e:#}");
    assert_eq!(
        std::fs::read(vdir(root).join("vault.json.next")).unwrap(),
        staged,
        "the staged manifest kept"
    );
    assert_ne!(
        std::fs::read(vdir(root).join("vault.json")).unwrap(),
        staged,
        "the forged file kept, not overwritten"
    );
}

/// **ROADMAP O304 on `/v1`, writable**: the same forged manifest is 409 with
/// the integrity class.
#[test]
fn o304_v1_refuses_a_manifest_forged_after_the_licence() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fresh_vault(root, 20);
    defer_by_hand(root);
    let mut tenancy =
        tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
    let forged = o304_flipped(&std::fs::read(vdir(root).join("vault.json")).unwrap());
    let before = o304_db(root);
    let opens = o304_count_writable_opens(root);
    let ran = o304_in_the_licence_window(root, o304_forge);
    let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
    open_pause::clear(&vdir(root));
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "premise: the window was reached"
    );
    assert_eq!(opens.load(Ordering::SeqCst), 1, "not retried: {body}");
    assert_eq!(o304_db(root), before, "nothing committed");
    assert_eq!(
        std::fs::read(vdir(root).join("vault.json")).unwrap(),
        forged,
        "the forged bytes kept"
    );
    assert_eq!(code, 409, "{body}");
    assert!(body.contains("\"class\":\"integrity\""), "{body}");
    assert!(body.contains("possible tampering"), "{body}");
    assert!(vdir(root).join("vault.json.next").exists(), "{body}");
}

/// **ROADMAP O304 through `open_store_as`: a manifest of the new generation at
/// another head in the window is reopened, once, and the reopen judges it.**
/// Over the database at that head it is served at that head; over a database
/// rolled back below it the reopen answers the tamper verdict — where `main`
/// wrote the staged manifest over it and healed the anchor DOWN to the
/// rolled-back database. Were the refusal not the reopen class, neither would
/// be retried and both would answer the refusal's own text.
#[test]
fn o304_open_store_as_reopens_over_another_head_after_the_licence() {
    for rolled_back in [false, true] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        fresh_vault(root, 20);
        let h = o304_another_head(root, rolled_back);
        let staged = std::fs::read(vdir(root).join("vault.json.next")).unwrap();
        let h2 = h.clone();
        let ran = o304_in_the_licence_window(root, move |r| {
            std::fs::write(vdir(r).join("vault.json"), &h2).unwrap()
        });
        let opened = open_store_as(root, VAULT, Posture::ReadWrite);
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "rolled_back={rolled_back}: premise: the window was reached"
        );
        let h_writes = serde_json::from_slice::<serde_json::Value>(&h).unwrap()["writes"]
            .as_u64()
            .unwrap();
        match opened {
            Ok(s) if !rolled_back => {
                assert_eq!(s.chain_state().unwrap().1, h_writes, "served at H");
                assert!(s.verify().unwrap().ok());
            }
            Err(e) if rolled_back => {
                let text = format!("{e:#}");
                assert!(text.contains("possible tampering"), "{text}");
                assert!(
                    !text.contains("changed beneath this open's write lock"),
                    "{text}"
                );
                assert!(integrity_verdict(&e), "exit 2: {text}");
                assert_eq!(std::fs::read(vdir(root).join("vault.json")).unwrap(), h);
                // Followed rather than reopened, the promote since's guard
                // would have removed it before `init_chain` refused (P3).
                assert_eq!(
                    std::fs::read(vdir(root).join("vault.json.next")).unwrap(),
                    staged,
                    ".next kept"
                );
            }
            Ok(s) => panic!(
                "rolled back: served at height {:?}",
                s.chain_state().map(|c| c.1)
            ),
            Err(e) => panic!("at H: refused {e:#}"),
        }
    }
}

/// **ROADMAP O304 on `/v1`**: `store_for` reopens over another head in the
/// window, once — 200 over the database at that head, 409 with the integrity
/// class over one rolled back below it.
#[test]
fn o304_v1_reopens_over_another_head_after_the_licence() {
    for rolled_back in [false, true] {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        fresh_vault(root, 20);
        let h = o304_another_head(root, rolled_back);
        let staged = std::fs::read(vdir(root).join("vault.json.next")).unwrap();
        let mut tenancy =
            tenant::Tenancy::new(mgr(root), embedder_factory(), false).expect("no secret declared");
        let ran = o304_in_the_licence_window(root, move |r| {
            std::fs::write(vdir(r).join("vault.json"), &h).unwrap()
        });
        let (code, body) = call(&mut tenancy, &format!("/v1/vaults/{VAULT}/stats"));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "rolled_back={rolled_back}: premise: the window was reached"
        );
        if rolled_back {
            assert_eq!(code, 409, "{body}");
            assert!(body.contains("\"class\":\"integrity\""), "{body}");
            assert!(body.contains("possible tampering"), "{body}");
            assert_eq!(
                std::fs::read(vdir(root).join("vault.json.next")).unwrap(),
                staged,
                ".next kept"
            );
        } else {
            assert_eq!(code, 200, "{body}");
        }
    }
}
