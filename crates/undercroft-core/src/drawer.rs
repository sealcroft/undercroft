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
                hall: None,
                entities: Vec::new(),
            },
        }
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
