//! Deterministic drawer ids.
//!
//! Mempalace derives drawer ids from a stable recipe over (wing, room,
//! source, chunk_index, normalize_version) so re-mining the same content is
//! idempotent. We keep that property with SHA-256.

use sha2::{Digest, Sha256};

/// Recipe tag stored in drawer metadata (mempalace's `id_recipe`).
pub const ID_RECIPE: &str = "sha256/wing|room|source|chunk|v1";

/// Domain tag separating the quarantine id space from the ordinary one.
///
/// Load-bearing, not decoration. Without it
/// `quarantine_drawer_id(wing, room, source, chunk)` would hash exactly what
/// `drawer_id` hashes and return the SAME id — so diverting a drawer would
/// derive the id of the very drawer it was screening, and
/// `ON CONFLICT(id) DO UPDATE` would overwrite a legitimate row with the
/// quarantined copy. The two spaces must not meet.
const QUARANTINE_DOMAIN: &str = "quarantine";

/// The one implementation of the recipe. `domain` is prefixed when present
/// and contributes NOTHING when absent, so [`drawer_id`] is byte-identical
/// to what it hashed before this parameter existed — a drawer id is a
/// durable reference held by the audit chain, by receipts, by supersession
/// links, by exports and by agents across sessions, and moving one is not a
/// rename (see `CLAUDE.md`'s identifier invariant). Pinned by
/// `the_ordinary_recipe_has_not_moved`.
fn id_over(domain: Option<&str>, wing: &str, room: &str, source: &str, chunk_index: u32) -> String {
    let mut h = Sha256::new();
    if let Some(d) = domain {
        h.update(d.as_bytes());
        h.update([0x1f]);
    }
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

/// Deterministic drawer id: `sha256(wing \x1f room \x1f source \x1f chunk \x1f v)`
/// hex-truncated to 32 chars (128 bits — collision-safe at palace scale).
pub fn drawer_id(wing: &str, room: &str, source: &str, chunk_index: u32) -> String {
    id_over(None, wing, room, source, chunk_index)
}

/// Deterministic id for a drawer the admission screen diverted.
///
/// **NOT `drawer_id(QUARANTINE_WING, room, source, chunk)`.** That is what
/// this used to be, and substituting a constant for the wing collapses one
/// of the four components [`drawer_id`] is injective over: two drawers
/// differing only in wing derived ONE quarantine id, and the write path's
/// `ON CONFLICT(id) DO UPDATE` replaced the first row wholesale — content,
/// signal codes, `intended_wing` and all. `mine ./docs --wing team-a` then
/// `--wing team-b` is the ordinary operation that produces it, because
/// `room_for_file` and the chunk index are both functions of the file and
/// the wing is the only knob. The same failure `next_append_index` exists to
/// prevent one level up, in its constant-substitution form.
///
/// The queue slot is therefore keyed on the wing the write was AIMED at —
/// which is also the component `admission_allow` restores from, so the
/// inverse derivation is unchanged.
pub fn quarantine_drawer_id(
    intended_wing: &str,
    room: &str,
    source: &str,
    chunk_index: u32,
) -> String {
    id_over(
        Some(QUARANTINE_DOMAIN),
        intended_wing,
        room,
        source,
        chunk_index,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A drawer id is a durable reference — the audit chain, receipts,
    /// supersession links, exports and agents across sessions all hold one.
    /// Refactoring the recipe into `id_over` must therefore be a no-op on
    /// the bytes, and "the tests still pass" cannot show that: every other
    /// test here compares the function to ITSELF. This one pins the output.
    /// Both literals were derived INDEPENDENTLY — re-implemented in Python
    /// from the recipe as committed and run, rather than copied out of this
    /// function's own output, which would have agreed with any change by
    /// construction.
    #[test]
    fn the_ordinary_recipe_has_not_moved() {
        assert_eq!(
            drawer_id("w", "r", "s.md", 0),
            "f95019f45b6f49ad9e1f42c4864f7ce6",
            "the ordinary drawer id recipe MOVED — every existing vault's ids \
             and every audit record naming one would be orphaned"
        );
        assert_eq!(
            quarantine_drawer_id("w", "r", "s.md", 0),
            "1a0966403243e062e0fc5786b8773eed",
            "the quarantine id space MOVED — every row already awaiting \
             review, and the audit records naming it, would be orphaned"
        );
    }

    /// The domain tag, from both sides. Without it a diverted drawer would
    /// derive the id of the drawer it was screening and overwrite it; and
    /// the id must also differ from the OLD recipe's output, or the fix
    /// would silently agree with the defect.
    #[test]
    fn a_quarantine_id_shares_no_space_with_an_ordinary_one() {
        assert_ne!(
            quarantine_drawer_id("inbox", "r", "s.md", 0),
            drawer_id("inbox", "r", "s.md", 0),
            "a diversion would derive the id of the row it screened"
        );
        assert_ne!(
            quarantine_drawer_id("inbox", "r", "s.md", 0),
            drawer_id("quarantine-pending", "r", "s.md", 0),
            "the new recipe must not reproduce the constant-substitution one"
        );
    }

    /// The counterfactual for round-four #7, at the recipe. Two diversions
    /// differing ONLY in the wing they were aimed at are two ids. Under the
    /// old recipe both sides of this were `drawer_id(QUARANTINE_WING, …)`
    /// and it was an equality.
    #[test]
    fn a_quarantine_id_keeps_the_wing_it_was_aimed_at() {
        assert_ne!(
            quarantine_drawer_id("team-a", "docs", "guide.md", 3),
            quarantine_drawer_id("team-b", "docs", "guide.md", 3),
            "two diversions differing only in wing must be two queue slots"
        );
        // Still deterministic and still injective over the other three.
        assert_eq!(
            quarantine_drawer_id("team-a", "docs", "guide.md", 3),
            quarantine_drawer_id("team-a", "docs", "guide.md", 3)
        );
        assert_ne!(
            quarantine_drawer_id("team-a", "docs", "guide.md", 3),
            quarantine_drawer_id("team-a", "docs", "guide.md", 4)
        );
        assert_eq!(
            quarantine_drawer_id("team-a", "docs", "guide.md", 3).len(),
            32
        );
    }

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
