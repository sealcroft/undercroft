//! Deterministic drawer ids.
//!
//! Mempalace derives drawer ids from a stable recipe over (wing, room,
//! source, chunk_index, normalize_version) so re-mining the same content is
//! idempotent. We keep that property with SHA-256.

use sha2::{Digest, Sha256};

/// Recipe tag stored in drawer metadata (mempalace's `id_recipe`).
pub const ID_RECIPE: &str = "sha256/wing|room|source|chunk|v1";

/// Deterministic drawer id: `sha256(wing \x1f room \x1f source \x1f chunk \x1f v)`
/// hex-truncated to 32 chars (128 bits — collision-safe at palace scale).
pub fn drawer_id(wing: &str, room: &str, source: &str, chunk_index: u32) -> String {
    let mut h = Sha256::new();
    for part in [wing, room, source] {
        h.update(part.as_bytes());
        h.update([0x1f]);
    }
    h.update(chunk_index.to_le_bytes());
    h.update([0x1f]);
    h.update(crate::normalize::NORMALIZE_VERSION.to_le_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_distinct() {
        let a = drawer_id("w", "r", "s.md", 0);
        let b = drawer_id("w", "r", "s.md", 0);
        let c = drawer_id("w", "r", "s.md", 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn delimiter_prevents_ambiguity() {
        // "ab"+"c" must not collide with "a"+"bc"
        assert_ne!(drawer_id("ab", "c", "s", 0), drawer_id("a", "bc", "s", 0));
    }
}
