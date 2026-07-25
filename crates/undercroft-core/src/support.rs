//! Where a distilled fact rests: on the writer's own words, or on the
//! extractor's background knowledge.
//!
//! A knowledge graph is *derived structure* by definition, so calling one
//! subset of it "derived" distinguishes nothing. What does distinguish is
//! whether the note a fact came from actually says it. "Ana works as a
//! radiologist" is in the note. "Leeds is in the United Kingdom" is not —
//! and it is still the edge that answers which country Ana works in. Both
//! belong in the graph. Only one of them rests on the user.
//!
//! This is a **provenance kind, not a quality grade**. Background facts are
//! what make a graph worth having over a pile of drawers: they connect
//! entities across notes that never mention each other. Nothing here ranks
//! them, and nothing here should ever filter them out by default.
//!
//! The distinction is established the way a temporal claim is
//! ([`crate::temporal::resolve_claimed_span`]): the extractor **quotes**, and
//! this module **checks** the quote against the note. A label a model applies
//! to itself is worth nothing. A substring test is worth exactly what it says.
//!
//! Spans are recorded as offsets into the source drawer, never as copied
//! text. The words are already stored once, verbatim; copying them into a
//! second place is more plaintext to seal and another thing to keep in step.

use serde::{Deserialize, Serialize};

/// A byte range of the source drawer's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub offset: u32,
    pub len: u32,
}

/// The outcome of *evaluating* a fact against its note.
///
/// Constructing one of these means the check was run. An empty `spans` is a
/// real result — "looked, found nothing" — and is not the same as never
/// having looked, which is represented by the absence of a `Support`
/// altogether. See [`Grounding`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Support {
    /// Every quoted span that was found in the note, ordered by position and
    /// deduplicated so the same evaluation always yields the same bytes —
    /// these get sealed and tamper-tagged, so determinism is not optional.
    #[serde(default)]
    pub spans: Vec<Span>,
}

/// How a fact stands relative to the note it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grounding {
    /// The note contains words supporting this fact, at the recorded spans.
    Stated,
    /// The check ran and the note supports none of it: the fact rests on the
    /// extractor's background knowledge. Not a demerit — see the module docs.
    Background,
    /// The check never ran. Every fact distilled before grounding existed is
    /// here, as is any fact from an extractor that was not asked to quote.
    /// Distinct from `Background` on purpose: "we did not look" and "we
    /// looked and found nothing" are different claims, and defaulting the
    /// first to the second would assert something about facts nobody checked.
    Unevaluated,
}

impl Support {
    /// Check each quoted span against `text`, keeping the ones that are
    /// really there.
    ///
    /// A quote the note does not contain contributes nothing — it does not
    /// fail, it simply is not evidence. A fact whose every quote is invented
    /// therefore lands on `Background`, which is the honest reading: nothing
    /// in the note supports it.
    pub fn evaluate<S: AsRef<str>>(text: &str, quotes: &[S]) -> Self {
        let mut spans: Vec<Span> = quotes
            .iter()
            .filter_map(|q| locate(text, q.as_ref()))
            .collect();
        spans.sort_by_key(|s| (s.offset, s.len));
        spans.dedup();
        Support { spans }
    }

    pub fn is_stated(&self) -> bool {
        !self.spans.is_empty()
    }

    /// Classify an *optional* support — the absent case is the whole reason
    /// this takes an `Option`.
    pub fn grounding(support: Option<&Support>) -> Grounding {
        match support {
            None => Grounding::Unevaluated,
            Some(s) if s.is_stated() => Grounding::Stated,
            Some(_) => Grounding::Background,
        }
    }
}

/// Byte range of `quote` within `text`, if it is literally there.
///
/// No minimum length is imposed. A one-word quote is legitimate evidence and
/// a threshold would be an invented constant; `len` is carried precisely so a
/// reader can see how much was actually quoted and judge for itself. The
/// weakness this leaves is real: an extractor that quotes a single common
/// word gets `Stated` for a fact the note does not support. The span makes
/// that visible rather than hiding it behind a flag.
pub fn locate(text: &str, quote: &str) -> Option<Span> {
    let quote = quote.trim();
    if quote.is_empty() {
        return None;
    }
    let at = text.find(quote)?;
    Some(Span {
        offset: u32::try_from(at).ok()?,
        len: u32::try_from(quote.len()).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOTE: &str = "Ana works as a radiologist at St. Mary's hospital in Leeds.";

    #[test]
    fn a_quote_the_note_contains_is_located() {
        let s = locate(NOTE, "works as a radiologist").unwrap();
        assert_eq!(s.offset as usize, NOTE.find("works").unwrap());
        assert_eq!(s.len as usize, "works as a radiologist".len());
    }

    #[test]
    fn a_quote_the_note_does_not_contain_is_not_evidence() {
        for q in ["is a surgeon", "United Kingdom", "", "   "] {
            assert!(locate(NOTE, q).is_none(), "{q:?}");
        }
    }

    /// The three states are the point: never looked, looked and found
    /// nothing, looked and found something.
    #[test]
    fn the_three_states_are_distinct() {
        assert_eq!(Support::grounding(None), Grounding::Unevaluated);

        let background = Support::evaluate(NOTE, &["United Kingdom"]);
        assert!(!background.is_stated());
        assert_eq!(
            Support::grounding(Some(&background)),
            Grounding::Background,
            "an invented quote leaves the fact resting on background knowledge"
        );

        let stated = Support::evaluate(NOTE, &["works as a radiologist"]);
        assert!(stated.is_stated());
        assert_eq!(Support::grounding(Some(&stated)), Grounding::Stated);
    }

    #[test]
    fn several_disjoint_spans_are_all_kept() {
        let s = Support::evaluate(NOTE, &["Ana", "St. Mary's hospital"]);
        assert_eq!(s.spans.len(), 2);
        assert!(
            s.spans[0].offset < s.spans[1].offset,
            "ordered by position: {:?}",
            s.spans
        );
    }

    /// These bytes get sealed and tamper-tagged, so the same evaluation has
    /// to produce the same bytes however the quotes arrive.
    #[test]
    fn evaluation_is_order_independent_and_deduplicated() {
        let a = Support::evaluate(NOTE, &["Ana", "Leeds", "Ana"]);
        let b = Support::evaluate(NOTE, &["Leeds", "Ana"]);
        assert_eq!(a, b);
        assert_eq!(a.spans.len(), 2, "the repeat collapses: {:?}", a.spans);
    }

    #[test]
    fn a_mix_keeps_only_what_is_really_there() {
        let s = Support::evaluate(NOTE, &["works as a radiologist", "was born in 1984"]);
        assert_eq!(s.spans.len(), 1);
        assert!(s.is_stated(), "one real quote is still support");
    }
}
