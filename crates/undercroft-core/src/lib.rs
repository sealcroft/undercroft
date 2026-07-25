//! Undercroft core domain model.
//!
//! Ported from MemPalace (Python): a *palace* holds *wings* (people /
//! projects), wings hold *rooms* (topics), rooms hold *drawers* — verbatim
//! chunks of original text. Nothing is summarized or paraphrased on the way
//! in; retrieval returns the exact bytes that were stored.

pub mod chunk;
pub mod convo;
pub mod drawer;
pub mod embed;
pub mod entity;
pub mod fde;
pub mod ids;
pub mod late;
pub mod normalize;
pub mod rerank;
pub mod support;
pub mod temporal;

pub use chunk::{chunk_text, ChunkOptions};
pub use drawer::{Drawer, DrawerMeta};
pub use embed::{parse_external_spec, ExternalEmbedder, HashEmbedder, EMBED_DIM};
pub use ids::drawer_id;
pub use normalize::{normalize_content, normalize_wing_name, NORMALIZE_VERSION};
pub use rerank::Reranker;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid name {0:?}: {1}")]
    InvalidName(String, &'static str),
    #[error("content too large: {0} bytes (max {1})")]
    ContentTooLarge(usize, usize),
}

/// Validate a wing / room / vault name: 1..=128 chars, no path separators,
/// no control characters, not "." or "..". Mirrors mempalace's
/// `sanitize_name` contract so mined palaces stay compatible.
pub fn validate_name(value: &str, what: &'static str) -> Result<(), CoreError> {
    let v = value.trim();
    if v.is_empty() || v.len() > 128 {
        return Err(CoreError::InvalidName(
            value.into(),
            "must be 1..=128 chars",
        ));
    }
    if v == "." || v == ".." {
        return Err(CoreError::InvalidName(value.into(), "reserved name"));
    }
    if v.chars()
        .any(|c| c.is_control() || c == '/' || c == '\\' || c == '\0')
    {
        let _ = what;
        return Err(CoreError::InvalidName(
            value.into(),
            "control chars and path separators are not allowed",
        ));
    }
    Ok(())
}

pub const MAX_CONTENT_BYTES: usize = 100_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_rejects_traversal() {
        assert!(validate_name("..", "wing").is_err());
        assert!(validate_name("a/b", "wing").is_err());
        assert!(validate_name("a\\b", "wing").is_err());
        assert!(validate_name("ok-name_1", "wing").is_ok());
    }

    #[test]
    fn validate_name_rejects_empty_and_huge() {
        assert!(validate_name("", "room").is_err());
        assert!(validate_name(&"x".repeat(200), "room").is_err());
    }
}
