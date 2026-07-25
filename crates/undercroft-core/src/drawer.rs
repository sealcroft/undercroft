//! The drawer record — one verbatim chunk filed in the palace.
//!
//! Field names mirror mempalace's drawer metadata (`_build_drawer_metadata`
//! in miner.py) so exported palaces remain recognizable: wing, room,
//! source_file, chunk_index, added_by, filed_at, normalize_version,
//! id_recipe, line_start/line_end, content_date, hall, entities.

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DrawerMeta {
    pub wing: String,
    pub room: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    pub chunk_index: u32,
    pub added_by: String,
    /// RFC 3339 timestamp of when the drawer was filed.
    pub filed_at: String,
    pub normalize_version: u32,
    pub id_recipe: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_start: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_end: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_date: Option<String>,
    /// Dates and times written into the content itself, preserved verbatim
    /// and resolved against `content_date` where that is possible. Derived
    /// structure, like `entities` — the text is never altered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub time_mentions: Vec<crate::temporal::TimeMention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hall: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Drawer {
    pub id: String,
    /// Verbatim content. Encrypted at rest in sealed vaults.
    pub content: String,
    pub meta: DrawerMeta,
}

impl Drawer {
    /// Build a drawer from normalized content with a deterministic id.
    pub fn new(
        wing: &str,
        room: &str,
        content: String,
        source_file: Option<String>,
        chunk_index: u32,
        added_by: &str,
    ) -> Self {
        let source = source_file.as_deref().unwrap_or("(direct)");
        let id = crate::ids::drawer_id(wing, room, source, chunk_index);
        let filed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("RFC3339 formatting of now() cannot fail");
        // Scanned here rather than at each call site so no write path can
        // forget: every drawer that enters the palace, by any route, keeps
        // the times written into it. Resolution needs an anchor and so waits
        // for `with_content_date`.
        let time_mentions = crate::temporal::extract_time_mentions(&content, None);
        // Likewise the entities named in the content. `manage.rs` already
        // re-derived these on demand for co-occurrence; recording them on the
        // drawer means the structure travels with an export and does not have
        // to be recomputed to be read.
        let entities = crate::entity::extract_entities(&content);
        Drawer {
            id,
            content,
            meta: DrawerMeta {
                wing: wing.to_string(),
                room: room.to_string(),
                source_file,
                chunk_index,
                added_by: added_by.to_string(),
                filed_at,
                normalize_version: crate::normalize::NORMALIZE_VERSION,
                id_recipe: crate::ids::ID_RECIPE.to_string(),
                line_start: None,
                line_end: None,
                content_date: None,
                time_mentions,
                hall: None,
                entities,
            },
        }
    }

    /// Record when the *content* happened, as distinct from `filed_at`,
    /// which records when we wrote it down. Ingesting a year-old
    /// conversation today makes those two dates a year apart, and text like
    /// "I went yesterday" is only interpretable against the former.
    ///
    /// Does not affect the drawer id — identity stays (wing, room, source,
    /// chunk_index, normalize_version), so re-mining an existing corpus with
    /// dates now available stays idempotent instead of duplicating it.
    /// Supplying the anchor also resolves the relative mentions already
    /// scanned from the content — "yesterday" only becomes a date here.
    #[must_use]
    pub fn with_content_date(mut self, content_date: Option<String>) -> Self {
        let anchor = content_date
            .as_deref()
            .and_then(crate::temporal::parse_anchor);
        if anchor.is_some() {
            self.meta.time_mentions = crate::temporal::extract_time_mentions(&self.content, anchor);
        }
        self.meta.content_date = content_date;
        self
    }

    /// Canonical bytes covered by the integrity HMAC: id, meta (canonical
    /// JSON), and content, separated by 0x1f so fields cannot bleed into
    /// each other.
    pub fn canonical_bytes(&self, content_at_rest: &[u8]) -> Vec<u8> {
        let meta_json = serde_json::to_vec(&self.meta).expect("meta serializes");
        let mut out =
            Vec::with_capacity(self.id.len() + meta_json.len() + content_at_rest.len() + 2);
        out.extend_from_slice(self.id.as_bytes());
        out.push(0x1f);
        out.extend_from_slice(&meta_json);
        out.push(0x1f);
        out.extend_from_slice(content_at_rest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_id_same_slot() {
        let a = Drawer::new("w", "r", "one".into(), Some("f.md".into()), 0, "test");
        let b = Drawer::new("w", "r", "two".into(), Some("f.md".into()), 0, "test");
        assert_eq!(a.id, b.id); // same slot => same id (idempotent re-mine)
    }

    #[test]
    fn canonical_bytes_change_with_meta() {
        let mut a = Drawer::new("w", "r", "c".into(), None, 0, "test");
        let before = a.canonical_bytes(b"c");
        a.meta.room = "other".into();
        let after = a.canonical_bytes(b"c");
        assert_ne!(before, after);
    }

    #[test]
    fn entities_are_recorded_on_every_drawer() {
        // Sentence-initial words are deliberately excluded as noise by
        // extract_entities, so the names under test sit mid-sentence.
        let d = Drawer::new(
            "w",
            "r",
            "we met Alice and Blue Heron in Berlin.".into(),
            None,
            0,
            "test",
        );
        for want in ["alice", "blue heron", "berlin"] {
            assert!(
                d.meta.entities.contains(&want.to_string()),
                "missing {want}: {:?}",
                d.meta.entities
            );
        }
    }

    #[test]
    fn entities_survive_the_meta_roundtrip() {
        let d = Drawer::new("w", "r", "Alice went to Berlin.".into(), None, 0, "test");
        let back: DrawerMeta =
            serde_json::from_str(&serde_json::to_string(&d.meta).unwrap()).unwrap();
        assert_eq!(back.entities, d.meta.entities);
        assert!(!back.entities.is_empty());
    }

    #[test]
    fn entityless_content_stays_empty_and_is_omitted_from_json() {
        let d = Drawer::new(
            "w",
            "r",
            "just some lowercase words".into(),
            None,
            0,
            "test",
        );
        assert!(d.meta.entities.is_empty(), "{:?}", d.meta.entities);
        // skip_serializing_if keeps existing rows byte-identical.
        assert!(!serde_json::to_string(&d.meta).unwrap().contains("entities"));
    }

    #[test]
    fn meta_roundtrips_json() {
        let d = Drawer::new(
            "wing",
            "room",
            "content".into(),
            Some("s.md".into()),
            3,
            "cli",
        );
        let j = serde_json::to_string(&d.meta).unwrap();
        let back: DrawerMeta = serde_json::from_str(&j).unwrap();
        assert_eq!(back, d.meta);
    }
}
