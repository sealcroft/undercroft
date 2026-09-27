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
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().expect("tcp listener");
    let raw = format!("GET {path} HTTP/1.0\r\n\r\n");
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
