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

/// [`bounded_usize`] for the knobs whose natural width is 64 bits — an RNG
/// seed and a millisecond interval. Kept as its own entry point rather than
/// making the numeric helper generic, because generic bounds here would buy
/// one line and cost the readability of the message this returns.
pub fn bounded_u64(
    name: &str,
    raw: Option<&str>,
    unset: u64,
    min: u64,
) -> Result<u64, Fallback<u64>> {
    let Some(v) = raw else { return Ok(unset) };
    let t = v.trim();
    match t.parse::<u64>() {
        Ok(n) if n >= min => Ok(n),
        Ok(n) => Err(Fallback {
            value: unset,
            why: format!(
                "{name}={v:?} is below the minimum of {min} (got {n}); \
                 ignoring the declaration and behaving as if it were unset"
            ),
        }),
        Err(_) => Err(Fallback {
            value: unset,
            why: format!(
                "{name}={v:?} is not a number; ignoring the declaration and \
                 behaving as if it were unset"
            ),
        }),
    }
}

/// A bare integer with a real upper bound as well as a lower one.
///
/// `UNDERCROFT_FDE_KSIM` was `parse().ok().unwrap_or(d).clamp(1, 16)`, so a
/// declared 32 was silently taken as 16 — the swallow O48 closed, wearing a
/// clamp instead of an `unwrap_or`. A range the construction enforces has to
/// be part of the DECLARATION's parse, or the pre-flight and the engine
/// disagree about the same value.
pub fn in_range_usize(
    name: &str,
    raw: Option<&str>,
    unset: usize,
    min: usize,
    max: usize,
) -> Result<usize, Fallback<usize>> {
    let v = bounded_usize(name, raw, unset, min)?;
    if v > max {
        return Err(Fallback {
            value: unset,
            why: format!(
                "{name}={v} is above the maximum of {max}; ignoring the \
                 declaration and behaving as if it were unset"
            ),
        });
    }
    Ok(v)
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

/// A knob whose absence means "derive it" rather than "use this constant":
/// a session-pool size derived from the core count, an embedding dimension
/// probed from the endpoint. `None` is what absence gives, and therefore what
/// an unreadable declaration gives.
///
/// ROADMAP O52. Both of its callers were
/// `.ok().and_then(|v| v.parse().ok()).filter(|&n| n >= 1)`, which swallows a
/// typo in silence and then, for the embedder, PROBES the endpoint instead of
/// using the dimension the operator declared — a declaration that reads as a
/// pin and behaves as a suggestion.
pub fn positive_usize(
    name: &str,
    raw: Option<&str>,
) -> Result<Option<usize>, Fallback<Option<usize>>> {
    let Some(v) = raw else { return Ok(None) };
    match bounded_usize(name, Some(v), 0, 1) {
        Ok(n) => Ok(Some(n)),
        Err(f) => Err(Fallback {
            value: None,
            why: f.why,
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

/// The warning an undeclared model identity owes its operator.
///
/// ROADMAP O49 (round-four #27). `UNDERCROFT_ONNX_NAME` and its five siblings
/// default to a shared LITERAL — `"onnx-sentence"`, `"onnx-reranker"`,
/// `"colbert"` — so two different model files, loaded on two different days,
/// record **one** vector-space identity. The store's whole defence against a
/// silent model swap is that identity: `EmbedderMismatch` refuses to search
/// across one, because doing so degrades recall invisibly. A constant default
/// disarms exactly that check for every deployment that never set the name,
/// and the ColBERT case is the same one level down — its token matrices are
/// stored per drawer.
///
/// **Why this warns rather than deriving an identity from the model file.**
/// Deriving one would be correct and is filed for `2.0.0`: every existing
/// vault has `"onnx-sentence"` recorded, so a derived identity turns the next
/// start-up into `EmbedderMismatch` and demands an explicit
/// `UNDERCROFT_FORCE_EMBEDDER=1` plus `repair` from deployments that changed
/// nothing. That is *"a default that changes what is retrievable"* — MAJOR by
/// this project's own test — and shipping it in a patch would be exactly the
/// silent breakage this entry is about, pointed the other way.
///
/// So the defect's SILENCE is what gets fixed here: 67 of round four's 70
/// findings produced no signal at all, and that is the property being closed.
/// The identity an ONNX-family embedder records when nobody declares one.
///
/// **One constant, because it was two** (ROADMAP M22, round-four `#27`).
/// `undercroft-embed-onnx` and `undercroft-embed-ort` each wrote
/// `"onnx-sentence"` out twice — once in the warning and once as the value —
/// so the same decision lived in four places across two crates that never
/// link each other. Changing one and not the others would make two backends
/// record DIFFERENT identities for the SAME model, which is the mismatch
/// guard firing on a vault that never changed vector space: the defect
/// `#27` describes, pointed the other way.
///
/// **The value is deliberately unchanged.** It is recorded in existing
/// vaults and gates `EmbedderMismatch`, so moving it is *"a documented value
/// that stops being accepted"* — MAJOR by this file's own test. What `#27`
/// actually asks for — an identity DERIVED from the model rather than from a
/// constant — is filed for 2.0.0 with that argument, and `CLAUDE.md` forbids
/// half-landing a change to an id recipe. This closes the duplication and
/// says plainly that it does not close the cause.
pub const SHARED_MODEL_IDENTITY: &str = "onnx-sentence";

/// Likewise for the reranker and the ColBERT encoder, which share the same
/// shape and the same hazard one role over.
pub const SHARED_RERANKER_IDENTITY: &str = "onnx-reranker";
/// The ColBERT late-interaction encoder's undeclared identity.
pub const SHARED_COLBERT_IDENTITY: &str = "colbert";

pub fn undeclared_model_identity(var: &str, shared_default: &str, model_path: &str) -> String {
    format!(
        "{var} is not set, so this model records the shared identity \
         {shared_default:?} (loaded from {model_path:?}). A DIFFERENT model \
         loaded later without {var} records the SAME identity, and the store \
         cannot then tell the vector space changed — searches would silently \
         rank new queries against vectors from the old model. Set {var} to \
         something that names this model, and change it whenever the model \
         file changes."
    )
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
    fn the_undeclared_identity_warning_names_the_variable_the_value_and_the_risk() {
        let w = undeclared_model_identity("UNDERCROFT_ONNX_NAME", "onnx-sentence", "/m/a.onnx");
        // An operator must be able to act on it: which knob, what was
        // recorded, where it came from, and what goes wrong later.
        for needle in [
            "UNDERCROFT_ONNX_NAME",
            "onnx-sentence",
            "/m/a.onnx",
            "SAME identity",
        ] {
            assert!(w.contains(needle), "warning must name {needle}: {w}");
        }
    }

    /// ROADMAP M22 (round-four `#27`). The shared identities live in ONE
    /// place, and the two embedder crates must not write them out again.
    ///
    /// They each carried the literal twice — once in the warning, once as the
    /// value — so one decision sat in four places across two crates that
    /// deliberately never link. Changing one and not the others makes two
    /// backends record DIFFERENT identities for the SAME model, which fires
    /// the mismatch guard on a vault whose vector space never changed: `#27`
    /// pointed the other way.
    ///
    /// Reads the other crates' SOURCE, which is the only route two crates
    /// that do not link have — the same idiom
    /// `the_orchestrator_and_the_engine_agree_on_every_orch_variable` uses.
    #[test]
    fn no_embedder_crate_writes_a_shared_identity_out_again() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
        let files = [
            "undercroft-embed-onnx/src/lib.rs",
            "undercroft-embed-onnx/src/rerank.rs",
            "undercroft-embed-onnx/src/late.rs",
            "undercroft-embed-ort/src/lib.rs",
            "undercroft-embed-ort/src/late.rs",
        ];
        // The needles are ASSEMBLED so this test does not match its own
        // source — the "a gate whose own text is part of what it measures"
        // trap, which this tree records more often than any other.
        let needles = [
            format!("\"{}-{}\"", "onnx", "sentence"),
            format!("\"{}-{}\"", "onnx", "reranker"),
            format!("\"{}\"", "colbert"),
        ];
        let mut scanned = 0usize;
        let mut offenders: Vec<String> = Vec::new();
        for f in files {
            let path = format!("{root}/{f}");
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
            // PREMISE, per file. A path that moved would read as a crate with
            // no duplicated literals, which is exactly what a clean crate
            // reads as — the failure this whole family is about.
            assert!(
                src.contains("SHARED_") && src.len() > 500,
                "premise: {f} does not look like a loader that uses the shared \
                 identities — this scan examined the wrong file"
            );
            scanned += 1;
            for n in &needles {
                if src.contains(n.as_str()) {
                    offenders.push(format!("{f} still writes {n}"));
                }
            }
        }
        assert_eq!(scanned, 5, "premise: every loader source was read");
        assert!(
            offenders.is_empty(),
            "a shared model identity is written out again instead of using the \
             constant in undercroft_core::config: {offenders:#?}"
        );
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
