//! Declaration parsing shared by every crate that reads a `Tunes` knob.
//!
//! ROADMAP O48 (round-four #25). `ConfigClass::Tunes` is documented — in
//! `parity.rs`, in `CLAUDE.md` and on the architecture page — as *"garbage
//! warns and keeps that default"*. Three resolvers honoured it. Eleven in the
//! store's `assemble` did not: they were `v.parse().unwrap_or(DEFAULT)`, which
//! swallows the failure in silence, so an operator who typed
//! `UNDERCROFT_POOL_DIV=64x` got the default and no signal that their
//! declaration had not taken effect.
//!
//! **Why the helper lives in `undercroft-core` and returns its message rather
//! than logging it.** Core is the only crate every consumer shares:
//! `undercroft-embed-ort` and `undercroft-orchestrator` do not depend on
//! `undercroft-store`, so a helper there would be copied. Core has no
//! `undercroft-obs` dependency and must not gain one for three string parses,
//! so [`Fallback`] carries the operator-facing message **and** the value to
//! fall back to, and the caller warns in whatever way it already warns. The
//! error carrying the fallback is load-bearing: it makes it structurally
//! impossible for a pre-flight to report one value while the engine picks
//! another.
//!
//! **The contract, and it is stronger than the doctrine asked for: a
//! declaration that cannot be read behaves exactly as if it were ABSENT.**
//! The plan for this fix said to special-case `UNDERCROFT_FDE_IVF_MIN`, whose
//! garbage fallback enabled a tier that is default-off "because the operator
//! makes that call" — garbage being *less* conservative than saying nothing.
//! Special-casing one knob leaves the next one to be remembered. Falling back
//! to the UNSET value instead makes every knob conservative by construction,
//! and turns that defect into an impossible state rather than a fixed one.

use std::fmt;

/// A declaration that could not be read: what to use instead, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fallback<T> {
    /// The value to use — always what an ABSENT declaration would give.
    pub value: T,
    /// Operator-facing, and it must name the variable, the bad value and the
    /// consequence. A warning that does not say what happened instead is a
    /// warning an operator cannot act on.
    pub why: String,
}

impl<T> fmt::Display for Fallback<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.why)
    }
}

/// `off | <usize>` — the shape eight store knobs use, where `off` disables a
/// tier and a number sets its threshold.
///
/// `unset` is what an absent declaration gives, and is therefore also what an
/// UNREADABLE one gives. `min` rejects degenerate values: `UNDERCROFT_POOL_DIV=0`
/// parses fine and every consumer then guards it with `.max(1)`, so a zero
/// silently means "pool = the whole live corpus" — a declaration that reads as
/// a tuning value and behaves as a switch.
pub fn off_or_usize(
    name: &str,
    raw: Option<&str>,
    unset: usize,
    min: usize,
) -> Result<usize, Fallback<usize>> {
    let Some(v) = raw else { return Ok(unset) };
    let t = v.trim();
    if t.eq_ignore_ascii_case("off") {
        return Ok(usize::MAX);
    }
    bounded(name, v, t, unset, min)
}

/// A bare integer knob, with no `off` spelling.
pub fn bounded_usize(
    name: &str,
    raw: Option<&str>,
    unset: usize,
    min: usize,
) -> Result<usize, Fallback<usize>> {
    let Some(v) = raw else { return Ok(unset) };
    bounded(name, v, v.trim(), unset, min)
}

fn bounded(
    name: &str,
    raw: &str,
    trimmed: &str,
    unset: usize,
    min: usize,
) -> Result<usize, Fallback<usize>> {
    match trimmed.parse::<usize>() {
        Ok(n) if n >= min => Ok(n),
        Ok(n) => Err(Fallback {
            value: unset,
            why: format!(
                "{name}={raw:?} is below the minimum of {min} (got {n}); \
                 ignoring the declaration and behaving as if it were unset"
            ),
        }),
        Err(_) => Err(Fallback {
            value: unset,
            why: format!(
                "{name}={raw:?} is not a number; ignoring the declaration and \
                 behaving as if it were unset"
            ),
        }),
    }
}

/// A closed vocabulary. Returns the matched spelling, lowercased.
pub fn one_of(
    name: &str,
    raw: Option<&str>,
    allowed: &[&str],
    unset: &'static str,
) -> Result<String, Fallback<String>> {
    let Some(v) = raw else {
        return Ok(unset.to_string());
    };
    let t = v.trim().to_ascii_lowercase();
    if allowed.iter().any(|a| *a == t) {
        return Ok(t);
    }
    Err(Fallback {
        value: unset.to_string(),
        why: format!(
            "{name}={raw:?} is not one of [{}]; ignoring the declaration and \
             behaving as if it were unset",
            allowed.join(", ")
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreadable_declaration_behaves_exactly_as_an_absent_one() {
        // This is the whole contract, and the reason O48 does not need a
        // special case for the one knob whose garbage was less conservative
        // than its absence.
        for unset in [0usize, 4096, usize::MAX] {
            let absent = off_or_usize("X", None, unset, 1).unwrap();
            let garbage = off_or_usize("X", Some("not-a-number"), unset, 1).unwrap_err();
            assert_eq!(absent, unset);
            assert_eq!(
                garbage.value, unset,
                "garbage must land exactly where absence lands"
            );
            assert!(garbage.why.contains('X'), "the warning must name the knob");
        }
    }

    #[test]
    fn off_disables_and_a_number_is_taken() {
        assert_eq!(off_or_usize("X", Some("off"), 7, 1).unwrap(), usize::MAX);
        assert_eq!(off_or_usize("X", Some(" OFF "), 7, 1).unwrap(), usize::MAX);
        assert_eq!(off_or_usize("X", Some("64"), 7, 1).unwrap(), 64);
        assert_eq!(bounded_usize("X", Some(" 12 "), 7, 0).unwrap(), 12);
    }

    #[test]
    fn a_degenerate_divisor_is_refused_rather_than_silently_meaning_one() {
        // UNDERCROFT_POOL_DIV=0 parses, and every consumer guards with
        // `.max(1)`, so it silently means "the pool is the whole corpus".
        let e = off_or_usize("UNDERCROFT_POOL_DIV", Some("0"), 64, 1).unwrap_err();
        assert_eq!(e.value, 64);
        assert!(e.why.contains("minimum"), "{}", e.why);
        // A threshold whose 0 is meaningful is unaffected: min = 0.
        assert_eq!(bounded_usize("X", Some("0"), 9, 0).unwrap(), 0);
    }

    #[test]
    fn a_closed_vocabulary_refuses_an_unknown_spelling() {
        let ok = one_of("X", Some("Legacy"), &["bm25", "legacy"], "bm25").unwrap();
        assert_eq!(ok, "legacy");
        let e = one_of("X", Some("legcy"), &["bm25", "legacy"], "bm25").unwrap_err();
        assert_eq!(e.value, "bm25");
        assert!(e.why.contains("bm25, legacy"), "{}", e.why);
    }
}
