//! ROADMAP O231: a drawer whose HMAC verifies and whose covered `meta_json`
//! does not parse is a `verify` finding.
//!
//! `walk_covered` yielded `CoveredRow::MetaUnparseable` for such a row and
//! `verify` counted it and reported it in no leg, so it answered OK over a
//! drawer every read refuses — and `backup create` and `backup restore` gate
//! on that verdict. The row is reached two ways, and both are driven here:
//! with the vault's own key (a legacy or defect-written row, the shape the
//! entry filed), and WITHOUT it, by moving the 0x1f separator the drawer
//! canonical joins id, meta and content with — which the entry said could not
//! be done.
//!
//! Every report is checked as a verdict (`ok()`), by name and reason, on the
//! wire it travels as, and against the rotation's blockers, which O232's
//! ruling keeps it out of ("never on … an O231 row").

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use undercroft_core::embed::Embedder;
use undercroft_core::{Drawer, HashEmbedder};
use undercroft_vault::{SecurityLevel, Vault, VaultManager};

use crate::{
    canonical, restore_archive, BackupOutcome, BadReason, BadRecord, InternalRead, Read,
    RestoreOutcome, StoreError, VaultStore,
};

const VAULT: &str = "o231";

fn drawer(content: &str, idx: u32) -> Drawer {
    Drawer::new(
        "w1",
        "r",
        content.into(),
        Some("o231.md".into()),
        idx,
        "test",
    )
}

fn mgr(root: &Path) -> VaultManager {
    VaultManager::open(root, None).unwrap()
}

fn open_at(root: &Path) -> VaultStore {
    VaultStore::open(mgr(root).unlock(VAULT).unwrap()).unwrap()
}

fn backups(root: &Path) -> PathBuf {
    root.join("backups")
}

fn hash(_: &Vault) -> Result<Box<dyn Embedder + Send>, StoreError> {
    Ok(Box::new(HashEmbedder))
}

/// A vault of `victim` and one untouched neighbour, verified clean.
fn vault_with(level: SecurityLevel, victim: &Drawer) -> (TempDir, VaultStore) {
    let dir = TempDir::new().unwrap();
    let mut s = VaultStore::open(mgr(dir.path()).create(VAULT, level).unwrap()).unwrap();
    s.upsert(victim).unwrap();
    s.upsert(&drawer("an untouched neighbour about the harbour", 99))
        .unwrap();
    assert!(s.verify().unwrap().ok(), "premise: clean before");
    (dir, s)
}

fn columns(s: &VaultStore, id: &str) -> (String, Vec<u8>, Vec<u8>) {
    s.conn
        .query_row(
            "SELECT meta_json, content, tag FROM drawers WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}

/// The legacy / defect-written shape: `meta` written over the row WITH the
/// vault's key, the content untouched, and the new tag recorded in the chain
/// in the same transaction — as the write that made such a row recorded it.
/// Without that record the row would be a version replay too (O234's leg),
/// and the verdict would not be this finding's.
fn retag_over(s: &VaultStore, id: &str, meta: &str) {
    let (_, content, _) = columns(s, id);
    let tag = s.vault.tag(&canonical(id, meta.as_bytes(), &content));
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let tx = s.conn.unchecked_transaction().unwrap();
    assert_eq!(
        tx.execute(
            "UPDATE drawers SET meta_json = ?1, tag = ?2 WHERE id = ?3",
            rusqlite::params![meta, tag.as_slice(), id],
        )
        .unwrap(),
        1,
        "premise: the row was rewritten"
    );
    crate::chain_append(&tx, &s.vault, crate::Namespace::Drawer, id, &tag, &now).unwrap();
    tx.commit().unwrap();
}

/// The keyless shape, on any connection to a vault database: the meta/content
/// boundary moved to the first 0x1f in the content, with SQLite's own
/// `instr`/`substr` over the stored bytes. The tag column is never written.
fn move_the_separator(conn: &rusqlite::Connection, id: &str) {
    let moved = conn
        .execute(
            "UPDATE drawers SET \
               meta_json = meta_json || char(31) || \
                 CAST(substr(content, 1, instr(content, x'1f') - 1) AS TEXT), \
               content = substr(content, instr(content, x'1f') + 1) \
             WHERE id = ?1 AND instr(content, x'1f') > 0",
            [id],
        )
        .unwrap();
    assert_eq!(moved, 1, "premise: the boundary moved");
}

/// The premises every arm shares: the row's HMAC VERIFIES over the columns it
/// now holds, its covered meta does NOT parse, and every read refuses it —
/// the state `verify` used to answer OK over.
fn assert_an_o231_row(s: &VaultStore, id: &str) {
    let (meta, content, tag) = columns(s, id);
    assert!(
        s.vault
            .verify_tag(&canonical(id, meta.as_bytes(), &content), &tag)
            .is_ok(),
        "premise: the row's HMAC verifies"
    );
    assert!(
        serde_json::from_str::<undercroft_core::DrawerMeta>(&meta).is_err(),
        "premise: its covered meta does not parse"
    );
    assert!(
        matches!(
            s.get(id, Read::Internal(InternalRead::Verification)),
            Err(StoreError::CorruptRow { id: ref got, .. }) if got == id
        ),
        "premise: every read refuses it"
    );
}

/// The report names the row once, with its own reason, fails the verdict, and
/// blocks no rotation.
fn assert_named(s: &VaultStore, id: &str) -> crate::VerifyReport {
    let report = s.verify().unwrap();
    assert!(!report.ok(), "{report:?}");
    assert_eq!(
        report.bad_records,
        vec![BadRecord {
            record: id.to_string(),
            reason: BadReason::MetaUnparseable,
            detail: String::new(),
        }],
        "{report:?}"
    );
    // The row is still counted, as it always was.
    assert_eq!(report.records_checked, 2, "{report:?}");
    // Every other leg is clean, so the verdict is THIS finding's.
    assert!(
        report.chain_ok && report.orphan_labels.is_empty(),
        "{report:?}"
    );
    assert!(report.mirror_drift.is_empty() && report.policy_drift.is_empty());
    assert!(report.version_replay.is_empty(), "{report:?}");
    // O232's ruling: never a rotation blocker.
    assert!(
        report.rotation_blockers().is_empty(),
        "{:?}",
        report.rotation_blockers()
    );
    report
}

/// **The entry's gate**: a drawer re-tagged over an unparseable `meta_json`
/// makes `verify` fail and names it — on the report, on the line every
/// renderer prints, and on the `/v1` wire.
#[test]
fn o231_a_drawer_tagged_over_unparseable_meta_fails_verify_and_is_named() {
    let victim = drawer("a note whose meta a defective build rewrote", 0);
    let (_d, s) = vault_with(SecurityLevel::Sealed, &victim);
    // Valid JSON, and not a drawer's meta: every required field is missing.
    retag_over(&s, &victim.id, r#"{"wing":"w1"}"#);
    assert_an_o231_row(&s, &victim.id);

    let report = assert_named(&s, &victim.id);
    let line = report.bad_records[0].to_string();
    assert!(
        line.starts_with(&format!("{}: ", victim.id))
            && line.contains("HMAC verifies")
            && line.contains("does not parse"),
        "{line}"
    );
    // The wire: one string per record, the reason travelling with it, and a
    // failed HMAC still a bare id — byte for byte what it was before O231.
    let wire = serde_json::to_value(&report).unwrap();
    assert_eq!(wire["bad_records"], serde_json::json!([line]));
    assert_eq!(
        serde_json::to_value(BadRecord::tag_failed("kg/abc")).unwrap(),
        serde_json::json!("kg/abc")
    );
}

/// **It needs no key.** The canonical is `id 0x1f meta 0x1f content`, and a
/// serialised meta never holds a raw 0x1f while content may, so moving the
/// meta/content boundary to a 0x1f inside the content leaves the canonical —
/// and so the tag — byte for byte the same. The entry said such a row "needs
/// the vault key to reach"; this one is made with SQL alone, and the tag
/// column is never written.
#[test]
fn o231_a_writer_without_the_key_makes_one_by_moving_the_separator() {
    // Content at rest is the plaintext on an hmac-only vault. The store takes
    // what it is handed: the save surfaces strip control characters before
    // it, `Drawer::new` and `upsert` do not.
    let victim = drawer("alpha\u{1f}omega", 0);
    let (_d, s) = vault_with(SecurityLevel::HmacOnly, &victim);
    let (_, _, tag_before) = columns(&s, &victim.id);
    move_the_separator(&s.conn, &victim.id);
    let (meta, content, tag) = columns(&s, &victim.id);
    assert_eq!(tag, tag_before, "premise: the tag was never written");
    assert_eq!(content, b"omega");
    assert!(meta.ends_with("\u{1f}alpha"), "{meta:?}");
    assert_an_o231_row(&s, &victim.id);
    assert_named(&s, &victim.id);
}

/// **`backup create` refuses it, and a rotation does not** — the two gates
/// that read this verdict, each on its own rule. The backup gates on `ok()`;
/// the rotation on `rotation_blockers()`, which O232's ruling keeps this row
/// out of because a rotation re-tags the same bytes without parsing them —
/// and the row is exactly as detectable afterwards, which is the reason.
#[test]
fn o231_backup_create_refuses_it_and_a_rotation_leaves_it_detectable() {
    let victim = drawer("a note a defective build re-filed", 0);
    let (dir, s) = vault_with(SecurityLevel::Sealed, &victim);
    let root = dir.path();
    retag_over(&s, &victim.id, r#"{"not":"a drawer's meta"}"#);
    assert_an_o231_row(&s, &victim.id);

    match s.backup(&backups(root)).unwrap() {
        BackupOutcome::Refused(r) => assert_eq!(
            r.bad_records,
            vec![BadRecord {
                record: victim.id.clone(),
                reason: BadReason::MetaUnparseable,
                detail: String::new(),
            }]
        ),
        BackupOutcome::Created(r) => panic!("an O231 row was archived as clean: {r:?}"),
    }
    let archived = std::fs::read_dir(backups(root))
        .map(|rd| rd.flatten().filter(|e| e.file_name() != ".staging").count())
        .unwrap_or(0);
    assert_eq!(archived, 0, "a refused backup publishes no archive");

    // The rotation proceeds over it (O232: never on an O231 row) …
    let mut s = s;
    let rotated = s
        .rotate_keys(mgr(root).rotation_candidate(VAULT).unwrap())
        .expect("a rotation is never refused over an O231 row");
    assert_eq!(rotated.drawers, 2, "{rotated:?}");
    drop(s);
    // … and the row is exactly as detectable under the next key.
    let s = open_at(root);
    assert_an_o231_row(&s, &victim.id);
    assert_named(&s, &victim.id);
}

/// **An archive an older release took over such a row now refuses to
/// restore** — the restore's stage runs the same `verify`. Made inside a good
/// archive with no key, by the separator move, because no archive holding one
/// can be taken any more.
#[test]
fn o231_an_archive_holding_one_refuses_to_restore() {
    let victim = drawer("archived before 1.7.0\u{1f}and moved", 0);
    let (dir, s) = vault_with(SecurityLevel::HmacOnly, &victim);
    let root = dir.path();
    let created = match s.backup(&backups(root)).unwrap() {
        BackupOutcome::Created(r) => r,
        BackupOutcome::Refused(r) => panic!("premise: the vault verifies ({r:?})"),
    };
    drop(s);
    let archive = backups(root).join(&created.name);
    {
        let a = rusqlite::Connection::open(archive.join("vault.db")).unwrap();
        move_the_separator(&a, &victim.id);
        // Fold the write into the database file, as an archive holds it.
        a.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
    }
    let live_before = std::fs::read(root.join("vaults").join(VAULT).join("vault.db")).unwrap();
    match restore_archive(&mgr(root), &archive, None, true, &hash) {
        Ok(RestoreOutcome::Refused(r)) => assert_eq!(
            r.bad_records,
            vec![BadRecord {
                record: victim.id.clone(),
                reason: BadReason::MetaUnparseable,
                detail: String::new(),
            }],
            "{r:?}"
        ),
        Ok(RestoreOutcome::Restored(r)) => panic!("restored an O231 row: {r:?}"),
        Err(e) => panic!("refused, but not as a verdict naming the row: {e}"),
    }
    assert_eq!(
        std::fs::read(root.join("vaults").join(VAULT).join("vault.db")).unwrap(),
        live_before,
        "the live vault is untouched"
    );
}

/// **A link citing the row answers a VERDICT, never OK** (ROADMAP O269 item
/// 2, "no row aborts `verify`"). A supersession link cites the O231 row: `get`
/// refuses it as `CorruptRow`, and `verify` used to answer that error — exit
/// 1, a 500 — which this test pinned as O269's residual. Now the drawer walk
/// names the row and the ONE link citing it is left out of its leg, the
/// receipt having verified: never a swallowed leg, so a TAMPERED receipt on
/// the same link — decided before the read — is still reported and still
/// blocks a rotation, the hazard the old swallow's condition guarded.
#[test]
fn o231_a_link_citing_the_row_answers_a_verdict_never_ok() {
    let old = drawer("the original note a later one supersedes", 0);
    let (_dir, mut s) = vault_with(SecurityLevel::Sealed, &old);
    let mut newer = drawer("the note that supersedes it", 1);
    newer.meta.supersedes = Some(old.id.clone());
    s.upsert(&newer).unwrap();
    assert!(s.verify().unwrap().ok(), "premise: the link verifies");
    retag_over(&s, &old.id, r#"{"wing":"w1"}"#);
    assert_an_o231_row(&s, &old.id);
    let r = s
        .verify()
        .expect("a verdict, never the cited drawer's error");
    assert!(!r.ok(), "{r:?}");
    assert_eq!(
        r.bad_records,
        vec![BadRecord::meta_unparseable(old.id.clone())],
        "{r:?}"
    );
    assert!(
        r.supersessions.is_empty(),
        "the link whose verdict needs the unreadable drawer is left out: {r:?}"
    );
    // The receipt itself forged: decided before the read, so reported, and a
    // blocker the rotation sees.
    assert_eq!(
        s.conn
            .execute(
                "UPDATE drawers SET supersedes_receipt = zeroblob(32) WHERE id = ?1",
                [&newer.id],
            )
            .unwrap(),
        1
    );
    let r = s.verify().expect("a verdict");
    assert_eq!(r.tampered_supersessions(), 1, "{r:?}");
    assert!(
        r.rotation_blockers()
            .iter()
            .any(|b| b.starts_with("supersession ")),
        "{:?}",
        r.rotation_blockers()
    );
}
