//! ROADMAP O406, probe P15i: **a tag moved from one table to another, with
//! no key, verifies.**
//!
//! Every row tag in the tree used to be a bare HMAC under ONE key over fields
//! joined by 0x1f, with no table domain and no lengths. A drawer's canonical
//! is `id 1f meta 1f content` and a fact's `id 1f subject 1f predicate 1f
//! from 1f to 1f confidence(8) 1f object …`; both ids are 32 lowercase hex.
//! So a keyless writer who INSERTs a drawer whose id is a fact's id, whose
//! `meta_json` is the fact's subject and whose content is the rest of the
//! fact's canonical, and copies the fact's tag, has written a drawer whose
//! tag verifies — and on an hmac-only vault the subject is a word an MCP
//! agent chose, so it can be a `DrawerMeta` JSON naming any wing and any
//! `added_by`. Nothing appends an audit record for that write. The same holds
//! for an entity (`id 1f name 1f etype 1f created_at`).
//!
//! The fixture is the store's own API plus the documented offline column
//! edit, on both security levels, and every verdict is asserted by NAME.

use tempfile::TempDir;
use undercroft_core::Drawer;
use undercroft_vault::{RowFormat, SecurityLevel, VaultManager};

use crate::{BadReason, Read, VaultStore};

const VAULT: &str = "p15i";

/// The subject an agent writes over `undercroft_kg_add`: a `DrawerMeta` JSON
/// that `validate_name` admits (no control byte, no path separator, under
/// 128 bytes), naming a wing and an `added_by` the agent chose.
const META: &str = r#"{"wing":"w","room":"r","chunk_index":0,"added_by":"mine","filed_at":"x","normalize_version":2,"id_recipe":"v"}"#;

fn open_new(level: SecurityLevel, fmt: RowFormat) -> (TempDir, VaultStore) {
    let dir = TempDir::new().unwrap();
    let mgr = VaultManager::open(dir.path(), None).unwrap();
    let vault = mgr.create(VAULT, level).unwrap();
    if fmt == RowFormat::V1 {
        // Every vault written before O406 is in this regime; a fresh one is
        // walked at its first writable open unless the walk is withheld.
        crate::retag_pause::keep_on_v1(vault.dir());
    }
    let mut s = VaultStore::open(vault).unwrap();
    assert_eq!(s.row_format(), fmt, "premise: the regime the arm is about");
    // A real drawer beside the transplant, whose embedding the forged row
    // borrows: the offline writer needs some bytes in a NOT NULL column.
    s.upsert(&Drawer::new(
        "w",
        "r",
        "an ordinary note about the harbour".into(),
        Some("p15i.md".into()),
        0,
        "test",
    ))
    .unwrap();
    assert!(s.verify().unwrap().ok(), "premise: clean before");
    (dir, s)
}

/// The fact as stored: id, tag, object at rest.
fn fact_row(s: &VaultStore, id: &str) -> (Vec<u8>, Vec<u8>, String) {
    s.conn
        .query_row(
            "SELECT tag, object, subject FROM kg_triples WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}

/// The keyless move: INSERT a drawer under `id` whose `meta_json` and
/// content are `meta` and `content`, carrying `tag` — copied, never
/// computed. Every other NOT NULL column gets bytes from the real drawer.
fn insert_drawer(s: &VaultStore, id: &str, meta: &[u8], content: &[u8], tag: &[u8]) {
    let embedding: Vec<u8> = s
        .conn
        .query_row("SELECT embedding FROM drawers LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let n = s
        .conn
        .execute(
            "INSERT INTO drawers (id, wing, room, meta_json, content, embedding, tag, \
                                  filed_at, updated_at) \
             VALUES (?1, 'w', 'r', CAST(?2 AS TEXT), ?3, ?4, ?5, 'x', 'x')",
            rusqlite::params![id, meta, content, embedding, tag],
        )
        .unwrap();
    assert_eq!(n, 1, "premise: the drawer row was written");
}

/// The rest of a version-1 fact canonical after its subject's separator:
/// `predicate 1f valid_from 1f valid_to 1f confidence(8) 1f object`.
fn fact_tail(predicate: &str, confidence: f64, object: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(predicate.as_bytes());
    out.extend_from_slice(&[0x1f, 0x1f, 0x1f]);
    out.extend_from_slice(&confidence.to_le_bytes());
    out.push(0x1f);
    out.extend_from_slice(object);
    out
}

/// The verdict on the forged drawer, by regime.
///
/// **Version 2** (every vault this build has walked): the drawer's tag does
/// not verify — the canonical is table-domained under the `row` key, so a
/// fact's tag cannot cover a drawer row — and the identity leg names the id
/// shared by two tables.
///
/// **Version 1** (a vault the walk has not reached): the tag STILL verifies
/// — no key is needed, the premise this probe exists for — and the identity
/// leg is what names it, which also withholds the walk that would bind it.
fn assert_named(s: &VaultStore, id: &str, fmt: RowFormat) {
    let report = s.verify().unwrap();
    assert!(
        !report.ok(),
        "a tag transplanted from another table with no key must fail verify; the report \
         was {report:?}"
    );
    let tag_failed = report
        .bad_records
        .iter()
        .any(|b| b.record == id && b.reason == BadReason::TagFailed);
    assert_eq!(
        tag_failed,
        fmt == RowFormat::V2,
        "version 2 names the transplanted drawer as a record whose HMAC does not verify; \
         version 1 cannot, because the bytes ARE the fact's: {report:?}"
    );
    assert!(
        report
            .identity
            .iter()
            .any(|i| i.starts_with(&format!("{id}: one id names a drawer"))),
        "the identity leg names the id two tables share: {report:?}"
    );
    assert!(
        report
            .rotation_blockers()
            .iter()
            .all(|b| !b.contains("identity")),
        "the identity leg blocks no rotation (O232's criterion)"
    );
    assert!(
        report
            .walk_blockers()
            .iter()
            .any(|b| b.starts_with("identity ")),
        "and it withholds the walk"
    );
}

/// A fact's tag on a drawer row, hmac-only: the subject is a `DrawerMeta`
/// JSON an agent chose, so the drawer PARSES — wing, room, `added_by` all the
/// writer's. Measured before O406: served by `get` and `recent` (what
/// `wake_up` reads) under `VERIFY OK`, with no audit record of its write.
#[test]
fn p15i_a_fact_transplanted_into_drawers_fails_verify_on_hmac_only() {
    for fmt in [RowFormat::V1, RowFormat::V2] {
        let (_d, mut s) = open_new(SecurityLevel::HmacOnly, fmt);
        let id = s
            .kg_add(META, "p", "INJECTED", None, None, 0.0, None)
            .unwrap();
        let (tag, object, subject) = fact_row(&s, &id);
        assert_eq!(subject, META, "premise: hmac-only stores the words");
        assert_eq!(id.len(), 32, "premise: a fact id has a drawer id's shape");
        insert_drawer(
            &s,
            &id,
            META.as_bytes(),
            &fact_tail("p", 0.0, &object),
            &tag,
        );
        assert_named(&s, &id, fmt);
        let served = s.get(&id, Read::Returned(crate::ReadOp::Get));
        match fmt {
            // The residual of a vault still on version 1, PINNED: a read
            // checks the tag, and the tag verifies; the identity leg is what
            // names it, and the walk is withheld until it is resolved.
            RowFormat::V1 => assert!(
                served.unwrap().is_some_and(|d| d.meta.added_by == "mine"),
                "version 1 still serves it — the cost the walk closes"
            ),
            RowFormat::V2 => {
                assert!(served.is_err(), "version 2 refuses it at every read");
                let recent = s.recent(None, 10, Read::Returned(crate::ReadOp::Recent));
                assert!(
                    recent.is_err() || recent.unwrap().iter().all(|d| d.id != id),
                    "and no listing returns it — `wake_up` reads through `recent`"
                );
            }
        }
    }
}

/// An entity's tag on a drawer row, hmac-only: `id 1f name 1f etype 1f
/// created_at` reads as `id 1f meta 1f content` with the name as the meta.
#[test]
fn p15i_an_entity_transplanted_into_drawers_fails_verify_on_hmac_only() {
    for fmt in [RowFormat::V1, RowFormat::V2] {
        let (_d, mut s) = open_new(SecurityLevel::HmacOnly, fmt);
        s.kg_add(META, "p", "o", None, None, 0.5, None).unwrap();
        let (eid, tag, etype, created): (String, Vec<u8>, String, String) = s
            .conn
            .query_row(
                "SELECT id, tag, etype, created_at FROM kg_entities WHERE name = ?1",
                [META],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            eid.len(),
            32,
            "premise: an entity id has a drawer id's shape"
        );
        let mut content = etype.into_bytes();
        content.push(0x1f);
        content.extend_from_slice(created.as_bytes());
        insert_drawer(&s, &eid, META.as_bytes(), &content, &tag);
        assert_named(&s, &eid, fmt);
    }
}

/// The same transplant on a sealed vault. The subject column holds a blind
/// index there, so the forged meta does not parse; the verdict still names
/// the row by the id it shares, and — on version 2 — as a record whose tag
/// does not verify, not merely as unreadable.
#[test]
fn p15i_on_a_sealed_vault_the_transplant_fails_verify_too() {
    for fmt in [RowFormat::V1, RowFormat::V2] {
        let (_d, mut s) = open_new(SecurityLevel::Sealed, fmt);
        let id = s
            .kg_add(META, "p", "INJECTED", None, None, 0.0, None)
            .unwrap();
        let (tag, object, subject_at_rest) = fact_row(&s, &id);
        assert_ne!(
            subject_at_rest, META,
            "premise: sealed stores a blind index"
        );
        let predicate_at_rest: String = s
            .conn
            .query_row(
                "SELECT predicate FROM kg_triples WHERE id = ?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        // The sealed fact's version-1 canonical carries its terms extension
        // too; the move keeps every byte after the subject's separator.
        let terms: Vec<u8> = s
            .conn
            .query_row("SELECT terms FROM kg_triples WHERE id = ?1", [&id], |r| {
                r.get(0)
            })
            .unwrap();
        let mut content = fact_tail(&predicate_at_rest, 0.0, &object);
        content.push(0x1c);
        content.extend_from_slice(&terms);
        insert_drawer(&s, &id, subject_at_rest.as_bytes(), &content, &tag);
        assert_named(&s, &id, fmt);
    }
}
