//! Undercroft core domain model.
//!
//! Ported from MemPalace (Python): a *palace* holds *wings* (people /
//! projects), wings hold *rooms* (topics), rooms hold *drawers* — verbatim
//! chunks of original text. Nothing is summarized or paraphrased on the way
//! in; retrieval returns the exact bytes that were stored.

pub mod admission;
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
pub mod script;
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

/// The closed vocabulary a declared drawer `kind` must come from — the
/// exposure rule in docs/LABELS.md: a filterable label on a sealed vault
/// is a small closed vocabulary in the clear (a deliberate, low-entropy,
/// inventoried leak) or a blind index; free text is not offerable there.
/// Extending this list is a deliberate schema-level decision, not a
/// call-site convenience.
pub const KIND_VOCAB: &[&str] = &[
    "question",
    "preference",
    "decision",
    "event",
    "procedure",
    "statement",
];

/// Validate a declared kind against [`KIND_VOCAB`]. Unknown values are
/// rejected, never coerced — a typo silently becoming an unreachable
/// label is the silence the never-guess contract forbids.
pub fn validate_kind(value: &str) -> Result<(), CoreError> {
    if KIND_VOCAB.contains(&value) {
        Ok(())
    } else {
        Err(CoreError::InvalidName(
            value.into(),
            "not in the closed kind vocabulary (question|preference|decision|event|procedure|statement)",
        ))
    }
}

/// The closed vocabulary of deployment-assigned wing trust classes,
/// ordered lowest to highest. Trust is assigned by the RECEIVING
/// PRINCIPAL (operator surfaces only — CLI and `/v1`, deliberately never
/// MCP: an agent that writes content must not be able to raise its own
/// standing; docs/LABELS.md, "a self-declared label is never a trust
/// boundary"). A wing with no assignment reads as `standard` — a total
/// default, so a trust filter can never silently empty against an
/// unlabeled palace.
pub const TRUST_VOCAB: &[&str] = &["quarantined", "standard", "trusted"];

/// Validate a trust class against [`TRUST_VOCAB`] — rejected, never
/// coerced.
pub fn validate_trust(value: &str) -> Result<(), CoreError> {
    if TRUST_VOCAB.contains(&value) {
        Ok(())
    } else {
        Err(CoreError::InvalidName(
            value.into(),
            "not in the closed trust vocabulary (quarantined|standard|trusted)",
        ))
    }
}

/// Rank of a trust class within [`TRUST_VOCAB`] (0 = lowest). Callers
/// must have validated first; an unknown class ranks lowest rather than
/// panicking.
pub fn trust_rank(value: &str) -> usize {
    TRUST_VOCAB.iter().position(|t| *t == value).unwrap_or(0)
}

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
