//! Integration tests: drive the real `undercroft` binary end-to-end.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn cmd(home: &TempDir) -> Command {
    let mut c = Command::cargo_bin("undercroft").unwrap();
    c.env("UNDERCROFT_HOME", home.path());
    c.env_remove("UNDERCROFT_PASSPHRASE");
    c
}

#[test]
fn init_creates_palace_and_default_vault() {
    let home = TempDir::new().unwrap();
    cmd(&home)
        .args(["init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Palace initialized"))
        .stdout(predicate::str::contains("vault 'default'"))
        .stdout(predicate::str::contains("sealed"));
    assert!(home.path().join("master.key").exists());
    assert!(home.path().join("vaults/default/vault.json").exists());
    // Second init is a friendly no-op.
    cmd(&home)
        .args(["init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already initialized"));
}

#[test]
fn remember_search_wakeup_flow() {
    let home = TempDir::new().unwrap();
    cmd(&home).args(["init"]).assert().success();
    cmd(&home)
        .args([
            "remember",
            "We chose GraphQL over REST because the mobile app needed fewer round trips",
            "--wing",
            "backend",
            "--room",
            "decisions",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Filed drawer"));
    cmd(&home)
        .args([
            "remember",
            "The cat prefers the sunny windowsill",
            "--wing",
            "home",
        ])
        .assert()
        .success();

    cmd(&home)
        .args(["search", "why did we choose graphql"])
        .assert()
        .success()
        .stdout(predicate::str::contains("backend/decisions"));

    // Wing scoping excludes other wings.
    cmd(&home)
        .args(["search", "graphql", "--wing", "home"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No memories matched"));

    cmd(&home)
        .args(["wake-up"])
        .assert()
        .success()
        .stdout(predicate::str::contains("L0 — IDENTITY"))
        .stdout(predicate::str::contains("L1 — ESSENTIAL STORY"))
        .stdout(predicate::str::contains("GraphQL"));
}

#[test]
fn vault_isolation_between_namespaces() {
    let home = TempDir::new().unwrap();
    cmd(&home).args(["init"]).assert().success();
    cmd(&home)
        .args(["vault", "create", "work"])
        .assert()
        .success();
    cmd(&home)
        .args([
            "remember",
            "quarterly revenue target is confidential",
            "--vault",
            "work",
        ])
        .assert()
        .success();
    // The default vault must not see the work vault's memories.
    cmd(&home)
        .args(["search", "quarterly revenue target"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No memories matched"));
    // Separate DB files on disk.
    assert!(home.path().join("vaults/work/palace.db").exists());
    assert!(home.path().join("vaults/default/palace.db").exists());
}

#[test]
fn mine_and_export_roundtrip() {
    let home = TempDir::new().unwrap();
    let src = TempDir::new().unwrap();
    std::fs::write(
        src.path().join("meeting-notes.md"),
        "# Standup\n\nAlice is refactoring the auth flow.\n\nBob ships the billing fix Friday.",
    )
    .unwrap();
    cmd(&home).args(["init"]).assert().success();
    cmd(&home)
        .args(["mine", src.path().to_str().unwrap(), "--wing", "team"])
        .assert()
        .success()
        .stdout(predicate::str::contains("drawer(s) filed"));

    let out = cmd(&home).args(["export"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("auth flow"));
    // Line 1 is the manifest (unsigned here), records follow — each typed.
    let mut lines = stdout.lines();
    let manifest: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    let m = &manifest["undercroft_manifest"];
    assert_eq!(m["version"], 1);
    assert!(m["counts"]["drawers"].as_u64().unwrap() >= 1);
    assert!(m["sig"].is_null(), "unsigned without --sign");
    let first: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(first["drawer"]["meta"]["wing"], "team");
    assert_eq!(first["drawer"]["meta"]["room"], "meeting-notes");
}

/// The whole sealed + signed bundle flow, across two palaces: recipient
/// encryption (who may read), sender attestation (who wrote), and the
/// closed meta-rows gap (KG facts travel and re-key). Pinned end to end
/// because no CLI test exercised `export --to` / `import --identity` at
/// all before the manifest existed.
#[test]
fn signed_bundle_migrates_a_palace_with_its_knowledge_graph() {
    let src_home = TempDir::new().unwrap();
    let dst_home = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    cmd(&src_home).args(["init"]).assert().success();
    cmd(&dst_home).args(["init"]).assert().success();
    cmd(&src_home)
        .args(["remember", "the deploy window moved to Tuesday mornings"])
        .assert()
        .success();
    cmd(&src_home)
        .args(["kg", "add", "team", "deploy_window", "tuesday-mornings"])
        .assert()
        .success();

    // Destination identity (who may read) + source signing key (who wrote).
    let id_path = work.path().join("dst.key");
    let out = cmd(&dst_home)
        .args(["bundle", "keygen", "--out", id_path.to_str().unwrap()])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let recipient = stdout
        .lines()
        .find_map(|l| l.strip_prefix("Recipient (shareable): "))
        .expect("recipient printed")
        .to_string();
    let sign_path = work.path().join("src-sign.key");
    let out = cmd(&src_home)
        .args([
            "bundle",
            "sign-keygen",
            "--out",
            sign_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let sender = stdout
        .lines()
        .find_map(|l| l.strip_prefix("Sender (importers pin this): "))
        .expect("sender printed")
        .to_string();

    let bundle_path = work.path().join("palace.bundle");
    cmd(&src_home)
        .args([
            "export",
            "--to",
            &recipient,
            "--out",
            bundle_path.to_str().unwrap(),
            "--sign",
            sign_path.to_str().unwrap(),
            "--trust",
            "partner",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("sender-signed"));

    // Import with the sender pinned: attestation is enforced, the KG rides.
    cmd(&dst_home)
        .args([
            "import",
            bundle_path.to_str().unwrap(),
            "--identity",
            id_path.to_str().unwrap(),
            "--sender",
            &sender,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(verified)"))
        .stdout(predicate::str::contains("1 fact(s)"));

    // The fact answers in the destination palace, and integrity holds.
    cmd(&dst_home)
        .args(["kg", "query", "team"])
        .assert()
        .success()
        .stdout(predicate::str::contains("tuesday-mornings"));
    cmd(&dst_home).args(["verify"]).assert().success();

    // A wrong pinned sender refuses the import outright.
    let (_, wrong_sender) = {
        let out = cmd(&dst_home)
            .args([
                "bundle",
                "sign-keygen",
                "--out",
                work.path().join("other.key").to_str().unwrap(),
            ])
            .assert()
            .success();
        let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
        let s = stdout
            .lines()
            .find_map(|l| l.strip_prefix("Sender (importers pin this): "))
            .unwrap()
            .to_string();
        ((), s)
    };
    cmd(&dst_home)
        .args([
            "import",
            bundle_path.to_str().unwrap(),
            "--identity",
            id_path.to_str().unwrap(),
            "--sender",
            &wrong_sender,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("attestation failed"));
}

#[test]
fn verify_passes_clean_and_fails_after_tampering() {
    let home = TempDir::new().unwrap();
    cmd(&home)
        .args(["init", "--level", "hmac-only"])
        .assert()
        .success();
    cmd(&home)
        .args(["remember", "the true untampered memory"])
        .assert()
        .success();
    cmd(&home)
        .args(["verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("VERIFY OK"));

    // Forge the record directly in SQLite, bypassing the vault layer.
    let db = home.path().join("vaults/default/palace.db");
    let conn = rusqlite_open(&db);
    conn.execute("UPDATE drawers SET content = X'666f72676564'", [])
        .unwrap(); // 'forged'
    drop(conn);

    cmd(&home)
        .args(["verify"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("TAMPERED"))
        .stdout(predicate::str::contains("VERIFY FAILED"));
}

#[test]
fn sealed_vault_leaves_no_plaintext_in_db() {
    let home = TempDir::new().unwrap();
    cmd(&home).args(["init"]).assert().success();
    cmd(&home)
        .args(["remember", "zebra-passport-9331 is the recovery phrase"])
        .assert()
        .success();
    let db = std::fs::read(home.path().join("vaults/default/palace.db")).unwrap();
    let needle = b"zebra-passport-9331";
    assert!(!db.windows(needle.len()).any(|w| w == needle));
    // But search still finds it (decrypt-scan).
    cmd(&home)
        .args(["search", "recovery phrase zebra"])
        .assert()
        .success()
        .stdout(predicate::str::contains("zebra-passport-9331"));
}

#[test]
fn wrong_passphrase_cannot_read_sealed_vault() {
    let home = TempDir::new().unwrap();
    let mut c = Command::cargo_bin("undercroft").unwrap();
    c.env("UNDERCROFT_HOME", home.path())
        .env("UNDERCROFT_PASSPHRASE", "correct horse");
    c.args(["init"]).assert().success();
    let mut c = Command::cargo_bin("undercroft").unwrap();
    c.env("UNDERCROFT_HOME", home.path())
        .env("UNDERCROFT_PASSPHRASE", "correct horse");
    c.args(["remember", "sealed under the right passphrase"])
        .assert()
        .success();

    // Wrong passphrase: manifest MAC check fails before any data is served.
    let mut c = Command::cargo_bin("undercroft").unwrap();
    c.env("UNDERCROFT_HOME", home.path())
        .env("UNDERCROFT_PASSPHRASE", "wrong staple");
    c.args(["search", "sealed"]).assert().failure();
}

#[test]
fn help_and_version_ux() {
    let home = TempDir::new().unwrap();
    cmd(&home)
        .args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hardened local-first AI memory"))
        .stdout(predicate::str::contains("remember"))
        .stdout(predicate::str::contains("search"))
        .stdout(predicate::str::contains("verify"));
    cmd(&home).args(["--version"]).assert().success();
    // Unknown command exits nonzero with guidance on stderr.
    cmd(&home)
        .args(["frobnicate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn rejects_path_traversal_names() {
    let home = TempDir::new().unwrap();
    cmd(&home).args(["init"]).assert().success();
    cmd(&home)
        .args(["vault", "create", "../escape"])
        .assert()
        .failure();
    cmd(&home)
        .args(["remember", "x", "--wing", "a/b"])
        .assert()
        .failure();
}

#[test]
fn kg_cli_supersede_and_time_travel() {
    let home = TempDir::new().unwrap();
    cmd(&home).args(["init"]).assert().success();
    cmd(&home)
        .args([
            "kg",
            "add",
            "alice",
            "works_at",
            "acme",
            "--from",
            "2024-01-01",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added fact"));
    cmd(&home)
        .args([
            "kg",
            "supersede",
            "alice",
            "works_at",
            "globex",
            "--at",
            "2025-06-01",
        ])
        .assert()
        .success();
    cmd(&home)
        .args(["kg", "query", "alice"])
        .assert()
        .success()
        .stdout(predicate::str::contains("globex"))
        .stdout(predicate::str::contains("acme").not());
    cmd(&home)
        .args(["kg", "query", "alice", "--as-of", "2024-06-15"])
        .assert()
        .success()
        .stdout(predicate::str::contains("acme"));
}

#[test]
fn convo_mine_and_sweep_idempotent() {
    let home = TempDir::new().unwrap();
    let convos = TempDir::new().unwrap();
    std::fs::write(
        convos.path().join("sess.jsonl"),
        r#"{"type":"user","message":{"role":"user","content":"what timezone does the cron run in?"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"All crons run in UTC to avoid DST bugs."}]}}"#,
    )
    .unwrap();
    cmd(&home).args(["init"]).assert().success();
    cmd(&home)
        .args([
            "mine",
            convos.path().to_str().unwrap(),
            "--mode",
            "convos",
            "--wing",
            "cc",
        ])
        .assert()
        .success();
    cmd(&home)
        .args(["search", "cron timezone", "--wing", "cc"])
        .assert()
        .success()
        .stdout(predicate::str::contains("UTC"));
    // Sweep files per-message drawers; second sweep is a no-op.
    cmd(&home)
        .args(["sweep", convos.path().to_str().unwrap(), "--wing", "swept"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 message drawer(s) filed"));
    cmd(&home)
        .args(["sweep", convos.path().to_str().unwrap(), "--wing", "swept"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 message drawer(s) filed"));
}

#[test]
fn diary_and_tunnel_flow() {
    let home = TempDir::new().unwrap();
    cmd(&home).args(["init"]).assert().success();
    cmd(&home)
        .args(["diary", "write", "scout", "note one"])
        .assert()
        .success();
    cmd(&home)
        .args(["diary", "agents"])
        .assert()
        .success()
        .stdout(predicate::str::contains("scout"));
    cmd(&home)
        .args(["remember", "target wing memory", "--wing", "b"])
        .assert()
        .success();
    cmd(&home)
        .args(["tunnel", "create", "a", "b"])
        .assert()
        .success();
    cmd(&home)
        .args(["tunnel", "traverse", "a"])
        .assert()
        .success()
        .stdout(predicate::str::contains("b"));
    cmd(&home)
        .args(["verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("VERIFY OK"));
}

// Tiny local shim so this test file does not depend on rusqlite directly
// through the workspace: reuse the store crate's re-exported connection.
fn rusqlite_open(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}

#[test]
fn content_date_is_recorded_and_anchors_relative_dates_in_the_text() {
    let home = TempDir::new().unwrap();
    cmd(&home).args(["init"]).assert().success();

    // The content happened on 8 May; it is being filed now. "yesterday" is
    // only interpretable against the former.
    cmd(&home)
        .args([
            "remember",
            "I went to the support group yesterday",
            "--wing",
            "caroline",
            "--content-date",
            "2023-05-08T13:56:00+00:00",
        ])
        .assert()
        .success();

    // Round-trips out of the sealed store, and the drawer records the
    // resolved date rather than only the raw phrase.
    let out = cmd(&home)
        .args(["export"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("2023-05-08T13:56:00+00:00"),
        "content_date must survive the write path: {text}"
    );
    assert!(
        text.contains("2023-05-07"),
        "\"yesterday\" must resolve against the anchor: {text}"
    );
    assert!(
        text.contains("I went to the support group yesterday"),
        "the text itself stays verbatim: {text}"
    );
}

/// `remember` derives its drawer id from a unique append slot, never from
/// `count()`.
///
/// `COUNT(*)` goes *down* after a delete, so a `count()`-derived index is
/// handed back out while it is still in use: the id collides and
/// `ON CONFLICT(id) DO UPDATE` overwrites the unrelated drawer holding it,
/// destroying a record by writing a different one. The `/v1` and MCP save
/// paths were already safe; this pins the CLI path end-to-end through the
/// real binary, which is where the regression would actually reach a user.
#[test]
fn remember_after_a_delete_must_not_overwrite_an_unrelated_drawer() {
    fn filed_id(out: Vec<u8>) -> String {
        let text = String::from_utf8(out).unwrap();
        // "Filed drawer {id} in {wing}/{room} (vault '{vault}')"
        text.split("Filed drawer ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or_else(|| panic!("no drawer id in output: {text}"))
            .to_string()
    }
    fn remember(home: &TempDir, content: &str) -> String {
        filed_id(
            cmd(home)
                .args(["remember", content, "--wing", "w", "--room", "r"])
                .assert()
                .success()
                .get_output()
                .stdout
                .clone(),
        )
    }

    let home = TempDir::new().unwrap();
    cmd(&home).args(["init"]).assert().success();

    let a = remember(&home, "first note about harbours");
    let b = remember(&home, "second note about lighthouses");
    assert_ne!(a, b, "two saves must not share an id");

    cmd(&home)
        .args(["drawer", "delete", &a])
        .assert()
        .success()
        .stdout(predicate::str::contains("Deleted drawer"));

    let c = remember(&home, "third note about tides");
    assert_ne!(
        c, b,
        "a save after a delete must not land on a surviving drawer's id"
    );

    // The unrelated drawer is intact, verbatim, and still readable.
    cmd(&home)
        .args(["drawer", "get", &b])
        .assert()
        .success()
        .stdout(predicate::str::contains("second note about lighthouses"));
    // And the new content really was stored, not silently folded into b.
    cmd(&home)
        .args(["drawer", "get", &c])
        .assert()
        .success()
        .stdout(predicate::str::contains("third note about tides"));
}
