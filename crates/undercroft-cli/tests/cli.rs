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
        .args(["remember", "The cat prefers the sunny windowsill", "--wing", "home"])
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
    cmd(&home).args(["vault", "create", "work"]).assert().success();
    cmd(&home)
        .args(["remember", "quarterly revenue target is confidential", "--vault", "work"])
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
    let first: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
    assert_eq!(first["meta"]["wing"], "team");
    assert_eq!(first["meta"]["room"], "meeting-notes");
}

#[test]
fn verify_passes_clean_and_fails_after_tampering() {
    let home = TempDir::new().unwrap();
    cmd(&home).args(["init", "--level", "hmac-only"]).assert().success();
    cmd(&home).args(["remember", "the true untampered memory"]).assert().success();
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
    c.env("UNDERCROFT_HOME", home.path()).env("UNDERCROFT_PASSPHRASE", "correct horse");
    c.args(["init"]).assert().success();
    let mut c = Command::cargo_bin("undercroft").unwrap();
    c.env("UNDERCROFT_HOME", home.path()).env("UNDERCROFT_PASSPHRASE", "correct horse");
    c.args(["remember", "sealed under the right passphrase"]).assert().success();

    // Wrong passphrase: manifest MAC check fails before any data is served.
    let mut c = Command::cargo_bin("undercroft").unwrap();
    c.env("UNDERCROFT_HOME", home.path()).env("UNDERCROFT_PASSPHRASE", "wrong staple");
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

// Tiny local shim so this test file does not depend on rusqlite directly
// through the workspace: reuse the store crate's re-exported connection.
fn rusqlite_open(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}
