//! LLM distillation — **one** implementation, driven by both surfaces.
//!
//! `undercroft refine` and `POST /v1/vaults/{id}/refine` are the same
//! capability under the same `UNDERCROFT_LLM_*` configuration, and they
//! used to produce materially different vaults. The CLI called
//! `kg_add_receipted` with no validity window, no grounding argument and
//! no searchable mirror, then spent a second LLM call per drawer
//! extracting entities it only counted and threw away; `/v1` resolved the
//! fact's date from the note's own words, recorded a `Support` verdict,
//! and mirrored every new fact into a `facts` room so distillation
//! reached retrieval at all. Same command name, same endpoint, four
//! divergences, and both surfaces printed a success summary that named
//! none of them.
//!
//! So the behaviour lives here and the surfaces only parse arguments and
//! render the report. A future change to what distillation *does* cannot
//! land on one surface again without landing on the other.

use undercroft_core::Drawer;
use undercroft_llm::LlmClient;
use undercroft_store::{PalaceStore, StoreError};

/// What to distil and where the mirrored facts land.
pub(crate) struct RefineOptions<'a> {
    /// Scope the verbatim drawers that are read.
    pub wing: Option<&'a str>,
    /// Restrict to one room; `None` = every room except `fact_room`.
    pub room: Option<&'a str>,
    /// Room the searchable fact-drawers land in, inside their **source
    /// drawer's** wing (so per-wing isolation is preserved). Never read
    /// back as a source, or a second run would compound its own output.
    pub fact_room: &'a str,
    /// Read at most this many drawers.
    pub limit: usize,
    /// Extract and count, write nothing. The graph and the mirror are
    /// both skipped — a dry run must not be half a refinement.
    pub dry_run: bool,
}

/// Counts only — the caller decides how to render them.
#[derive(Default)]
pub(crate) struct RefineReport {
    pub sources: usize,
    pub facts: u32,
    /// Facts already mirrored in this run: the graph collapses a repeated
    /// triple onto one row, and the retrieval surface has to match or one
    /// fact restated across chunks occupies several slots of one top-k.
    pub duplicates: u32,
    /// Triples whose subject/predicate failed `validate_name`.
    pub skipped: u32,
    /// Drawers whose extraction call failed. Never fatal: a refinement is
    /// resumable and one unreachable answer must not discard the rest.
    pub failed: u32,
    /// Facts dated by words in the note rather than by the note's own
    /// date — the only visible measure of whether the extractor is
    /// pointing at real spans.
    pub dated_from_text: u32,
    /// Facts the note's own words support (the rest rest on the model's
    /// background knowledge; both are wanted, the difference is recorded).
    pub stated: u32,
    /// `(subject, predicate, object)` for a dry run, in extraction order.
    /// Empty otherwise.
    pub preview: Vec<(String, String, String)>,
}

/// Distil `store`'s verbatim drawers into receipted, grounded KG facts and
/// mirror each new fact as a searchable drawer. The verbatim drawers are
/// never modified.
pub(crate) fn refine(
    store: &mut PalaceStore,
    llm: &LlmClient,
    opts: &RefineOptions<'_>,
) -> Result<RefineReport, StoreError> {
    // Read the verbatim side only: never re-distil fact-drawers, or a
    // second call would compound its own output into the graph.
    let sources: Vec<Drawer> = store
        .recent(opts.wing, opts.limit)?
        .into_iter()
        .filter(|d| d.meta.room != opts.fact_room)
        .filter(|d| opts.room.is_none_or(|r| d.meta.room == r))
        .collect();

    // Keyed on the triple id the graph itself returns, so the graph's
    // notion of identity and the mirror's cannot drift.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut rep = RefineReport {
        sources: sources.len(),
        ..Default::default()
    };
    for d in &sources {
        let anchor = d
            .meta
            .content_date
            .as_deref()
            .and_then(undercroft_core::temporal::parse_anchor);
        let triples = match llm.extract_triples(&d.content) {
            Ok(t) => t,
            Err(e) => {
                undercroft_obs::diag_error!("refine: triples failed for {}: {e}", d.id);
                rep.failed += 1;
                continue;
            }
        };
        for t in triples {
            let subject = t.subject.to_lowercase();
            let predicate = t.predicate.to_lowercase();
            if undercroft_core::validate_name(&subject, "subject").is_err()
                || undercroft_core::validate_name(&predicate, "predicate").is_err()
            {
                rep.skipped += 1;
                continue;
            }
            if opts.dry_run {
                rep.preview
                    .push((t.subject.clone(), t.predicate.clone(), t.object.clone()));
                rep.facts += 1;
                continue;
            }
            // When the fact was established, which is not the same as when
            // the note was written: "I quit smoking three months ago" is a
            // fact about February in a note dated May. The extractor is
            // asked to point at the words that say so and is not permitted
            // to supply a date — `resolve_claimed_span` rejects any span
            // the note does not literally contain and resolves the rest
            // deterministically. Anything unverified falls back to the
            // note's own date, which is what every fact used to get.
            let dated = t.when.as_deref().and_then(|claim| {
                undercroft_core::temporal::resolve_claimed_span(&d.content, claim, anchor)
            });
            if dated.is_some() {
                rep.dated_from_text += 1;
            }
            let fact_date = dated
                .as_ref()
                .and_then(|m| m.resolved.clone())
                .or_else(|| d.meta.content_date.clone());
            // Where the fact rests. The quote is checked against the note
            // the same way the `when` span is; what the note does not
            // contain is not evidence. A fact with no quotable support is
            // NOT thereby wrong — "Leeds is in the United Kingdom" is the
            // edge that answers which country Ana works in, and the graph
            // wants it. This records which of the two it is, so a caller
            // that needs the user's own words can ask for them. Passing
            // `None` here (what the CLI did) means something else
            // entirely: "no such check was run".
            let support = undercroft_core::support::Support::evaluate(
                &d.content,
                t.quote
                    .as_deref()
                    .map(|q| [q])
                    .unwrap_or_default()
                    .as_slice(),
            );
            if support.is_stated() {
                rep.stated += 1;
            }
            // The receipt is an HMAC-covered citation back to the verbatim
            // drawer this fact came from — checkable later via `kg
            // receipts` / `GET …/kg/receipts`. `valid_to` stays open even
            // when the span named a period: a period says when the event
            // *happened*, not that the fact stopped holding, and "in May
            // 2023" must not be read as "expired on the 31st".
            let triple_id = store.kg_add_grounded(
                &subject,
                &predicate,
                &t.object,
                fact_date.as_deref(),
                None,
                0.8, // model-extracted: below human-asserted confidence
                (&d.id, &d.content),
                Some(&support),
                // Which model claimed the fact — provenance, HMAC-covered.
                Some(llm.model()),
            )?;
            // Restating a known fact still re-cites it in the graph — the
            // receipt above is refreshed either way — but it must not add
            // a second copy to the retrieval surface.
            if !seen.insert(triple_id) {
                rep.duplicates += 1;
                continue;
            }
            // A unique append slot from the store's own sequence. The
            // per-call fact counter that used to sit here is exactly the
            // `count()`-as-index hazard the id contract forbids: wing,
            // room and source are all fixed for a mirror drawer, so a
            // second refine run re-derived ids starting at 0 again and
            // silently overwrote the first run's fact-drawers.
            let idx = store.next_append_index()? as u32;
            store.upsert(
                &Drawer::new(
                    &d.meta.wing,
                    opts.fact_room,
                    format!("{} {} {}", t.subject, t.predicate, t.object),
                    None,
                    idx,
                    "distill",
                )
                .with_content_date(fact_date),
            )?;
            rep.facts += 1;
        }
    }
    Ok(rep)
}
