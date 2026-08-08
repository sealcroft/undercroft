//! What a search DECLARES, and what it OWES the caller back — once, for every
//! surface.
//!
//! CLI, MCP and `/v1` each built the same `SearchOptions`, the same read-time
//! `Locale`, and the same honest-exclusion notes by hand, and each of them
//! forgot a different piece: `week_start` reached only `/v1`, `room_cap` only
//! `/v1`, the declared morphology `language` only MCP and `/v1`, `ranked_at`
//! only MCP and `/v1`, and the trust-floor exclusion count only the CLI and
//! `/v1`. Five independent omissions across three handlers, none of them
//! stated anywhere as deliberate.
//!
//! Patching five holes leaves the sixth. The parse lives here instead, so a
//! surface reaches a declaration by CALLING for it rather than by remembering
//! to re-implement it — and the ones that read JSON (`/v1` bodies and MCP tool
//! arguments use the same key names) share the identical function.

use serde_json::Value;
use undercroft_store::{PalaceStore, SearchHit, SearchOptions, StoreError};

/// How many hits a search returns when the caller does not say.
///
/// One number for all three surfaces. It was 5 on the CLI and MCP and 10 on
/// `/v1`, so "the same search" answered with a different page size depending
/// on the transport — which quietly moves any recall comparison a user makes
/// between them. Unified DOWN rather than up: every surface now names its
/// continuation, so a caller who wants ten asks for ten or takes a second
/// page, while a page of full drawer text is charged to an agent's context on
/// every call. `/v1` callers relying on the old default of 10 must pass
/// `limit` explicitly (stated in docs/AGENTS.md and the changelog).
pub const DEFAULT_LIMIT: usize = 5;

/// The locale a request asks its temporal text to be read in.
///
/// `language` selects a scanner — Arabic puts the past marker before the count
/// and has a dual, so it is grammar rather than vocabulary — and `week_start`
/// selects the week convention, which moves "last week" and every week count.
/// Arabic defaults to Saturday weeks, the convention across most of the region,
/// because getting the language right and leaving the week European produces
/// answers that are subtly rather than obviously wrong.
///
/// All four fields are read from the same key names on `/v1` bodies and MCP
/// tool arguments, which is why one function serves both.
pub fn locale_from(body: &Value) -> undercroft_core::temporal::Locale {
    use undercroft_core::temporal::{Calendar, DateOrder, Locale, WeekStart};
    let mut locale = match body.get("language").and_then(Value::as_str) {
        Some("ar") | Some("arabic") => Locale::ARABIC,
        _ => Locale::ENGLISH,
    };
    if let Some(ws) = body.get("week_start").and_then(Value::as_str) {
        locale = locale.with_week_start(match ws {
            "sunday" | "sun" => WeekStart::Sunday,
            "saturday" | "sat" => WeekStart::Saturday,
            _ => WeekStart::Monday,
        });
    }
    // Which field a bare numeric date puts first. Declared, because it cannot be
    // derived: US English is month-first and Commonwealth English day-first, and
    // both are `Language::English`. An unrecognised value leaves whatever the
    // LANGUAGE implied standing rather than erasing it — overwriting Arabic's
    // CLDR day-first with `Undeclared` because a caller typo'd the value would
    // discard evidence to honour a non-declaration. Never an error either: a
    // reading convention is not worth a 400.
    if let Some(order) = body.get("date_order").and_then(Value::as_str) {
        locale = match order {
            "month_first" | "mdy" | "us" => locale.with_date_order(DateOrder::MonthFirst),
            "day_first" | "dmy" => locale.with_date_order(DateOrder::DayFirst),
            _ => locale,
        };
    }
    // Which calendar counted the year. Never inferred — see `Calendar`. This is
    // the corpus-wide default only: an era marker in a drawer's own words
    // (พ.ศ., هـ, 民國, 令和) outranks whatever is declared here.
    if let Some(cal) = body.get("calendar").and_then(Value::as_str) {
        locale = match cal {
            "buddhist" | "be" | "thai" => locale.with_calendar(Calendar::Buddhist),
            "minguo" | "roc" | "taiwan" => locale.with_calendar(Calendar::Minguo),
            "hijri" | "islamic" | "umalqura" => locale.with_calendar(Calendar::Hijri),
            "jalali" | "persian" | "solar_hijri" => locale.with_calendar(Calendar::Jalali),
            "reiwa" => locale.with_calendar(Calendar::Reiwa),
            "heisei" => locale.with_calendar(Calendar::Heisei),
            "showa" => locale.with_calendar(Calendar::Showa),
            "taisho" => locale.with_calendar(Calendar::Taisho),
            "meiji" => locale.with_calendar(Calendar::Meiji),
            _ => locale,
        };
    }
    locale
}

/// Whose inflection applies to the query, from the request's `language`.
///
/// Read-time and declared, exactly like `calendar` and `date_order`: German and
/// English share a script, so nothing in the bytes says which endings are legal.
/// The vocabulary itself lives on [`undercroft_store::MorphLang::CODES`] so the
/// tool schema that advertises it cannot fall behind the parser.
pub fn morph_lang_from(body: &Value) -> undercroft_store::MorphLang {
    undercroft_store::MorphLang::declared(body.get("language").and_then(Value::as_str))
}

/// One line of prose per declarable value, for a tool schema or `--help`.
pub fn language_codes() -> String {
    undercroft_store::MorphLang::CODES.join(", ")
}

/// Why this hit is here, in the channels that decided it.
///
/// `/v1` has returned `semantic`, `lexical`, `lexical_exact` and
/// `lexical_morph` per hit since the channels were split apart; the CLI and
/// MCP returned one blended `score` and nothing else. The store keeps the
/// channels separate precisely so a caller can tell "the drawer said your
/// word" from "the drawer holds a word built on yours" from "the vectors
/// agreed" — i.e. so a surprising hit, or a surprising miss, is
/// *reproducible* rather than a matter of opinion. Two of the three surfaces
/// could not see the evidence that reproduces it.
///
/// All four channels, not the three the residual named: rendering three would
/// leave `/v1` reporting one field its neighbours do not, which is this
/// residual's own complaint one field over. `lexical` is the one that RANKS
/// (approximate evidence at half weight, capped per query slot); the other
/// two are the ones that ADMIT, and a hit carrying neither of them was
/// admitted by the cosine alone — which is exactly the reading a reproduction
/// needs and which `score` cannot show.
///
/// Printed unconditionally rather than behind a verbosity flag. Evidence a
/// caller has to know to ask for reproduces the asymmetry this closes, and
/// four fixed-width numbers are a rounding error beside the page of verbatim
/// drawer text both surfaces already print.
pub fn evidence(hit: &SearchHit) -> String {
    format!(
        "evidence: exact {:.3} · morph {:.3} · lexical {:.3} · semantic {:.3}",
        hit.lexical_exact, hit.lexical_morph, hit.lexical, hit.semantic
    )
}

/// What a filter kept OUT of the competition, counted.
///
/// Both filters that narrow the candidate set before scoring owe the caller
/// this: a thin answer under a `kind` filter or a `min_trust` floor is
/// otherwise indistinguishable from a thin corpus, and the caller has no way
/// to ask. The policy is docs/LABELS.md's and it was implemented twice, each
/// time missing one leg — `/v1` and the CLI reported the trust count and MCP
/// did not; nothing reported it unless the caller had set the filter, which is
/// right, and nothing said so anywhere as a decision, which is not.
pub struct Exclusions {
    /// In-scope drawers carrying no declared kind, while a `kind` filter is set.
    pub unlabeled: Option<u64>,
    /// Wings below the declared floor, while `min_trust` is set.
    pub trust_excluded: Option<u64>,
}

impl Exclusions {
    /// Count what this request's own filters excluded. Absent filter ⇒ `None`,
    /// never `Some(0)`: "you set no floor" and "your floor excluded nothing"
    /// are different statements and the surfaces render them differently.
    pub fn measure(store: &PalaceStore, opts: &SearchOptions) -> Result<Self, StoreError> {
        let unlabeled = match opts.kind {
            Some(_) => Some(store.unkinded_in_scope(opts.wing.as_deref(), opts.room.as_deref())?),
            None => None,
        };
        let trust_excluded = match opts.min_trust.as_deref() {
            Some(floor) => Some(store.trust_excluded_wing_count(floor)?),
            None => None,
        };
        Ok(Exclusions {
            unlabeled,
            trust_excluded,
        })
    }

    /// The same counts as prose, for the two surfaces that answer in text.
    /// A count of zero says nothing — there is nothing to disclose.
    pub fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(n) = self.unlabeled.filter(|n| *n > 0) {
            out.push(format!(
                "({n} in-scope drawers carry no declared kind and were not considered)"
            ));
        }
        if let Some(n) = self.trust_excluded.filter(|n| *n > 0) {
            out.push(format!(
                "({n} wing(s) below the trust floor were not considered)"
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use undercroft_core::temporal::{Calendar, DateOrder, Language, WeekStart};

    /// `locale_from` is the whole of the read-time convention surface, and it
    /// had no test at all — so a renamed field or a typo in a value would have
    /// shipped silently while `docs/AGENTS.md` promised it worked.
    #[test]
    fn the_request_declares_its_reading_conventions() {
        let l = locale_from(&serde_json::json!({}));
        assert_eq!(l.language, Language::English);
        assert_eq!(l.week_start, WeekStart::Monday);
        assert_eq!(
            l.date_order,
            DateOrder::Undeclared,
            "English implies no order"
        );
        assert_eq!(l.calendar, Calendar::Gregorian);

        // Arabic brings Saturday weeks and day-first with it: CLDR gives `ar` as
        // d/M/y in every Arabic territory, so both follow from the language.
        let l = locale_from(&serde_json::json!({"language": "ar"}));
        assert_eq!(l.language, Language::Arabic);
        assert_eq!(l.week_start, WeekStart::Saturday);
        assert_eq!(l.date_order, DateOrder::DayFirst);

        // Each convention is independently declarable, with the aliases a caller
        // would actually reach for.
        for (v, want) in [
            ("month_first", DateOrder::MonthFirst),
            ("mdy", DateOrder::MonthFirst),
            ("us", DateOrder::MonthFirst),
            ("day_first", DateOrder::DayFirst),
            ("dmy", DateOrder::DayFirst),
        ] {
            let l = locale_from(&serde_json::json!({"date_order": v}));
            assert_eq!(l.date_order, want, "date_order {v:?}");
        }
        for (v, want) in [
            ("buddhist", Calendar::Buddhist),
            ("thai", Calendar::Buddhist),
            ("be", Calendar::Buddhist),
            ("minguo", Calendar::Minguo),
            ("roc", Calendar::Minguo),
            ("hijri", Calendar::Hijri),
            ("umalqura", Calendar::Hijri),
            ("jalali", Calendar::Jalali),
            ("persian", Calendar::Jalali),
            ("reiwa", Calendar::Reiwa),
            ("heisei", Calendar::Heisei),
            ("showa", Calendar::Showa),
            ("taisho", Calendar::Taisho),
            ("meiji", Calendar::Meiji),
        ] {
            let l = locale_from(&serde_json::json!({"calendar": v}));
            assert_eq!(l.calendar, want, "calendar {v:?}");
        }

        // Every week convention is declarable, on both key spellings. Sunday is
        // the one no language implies, so before this parser was shared it was
        // unreachable over MCP by any route at all.
        for (v, want) in [
            ("monday", WeekStart::Monday),
            ("sunday", WeekStart::Sunday),
            ("sun", WeekStart::Sunday),
            ("saturday", WeekStart::Saturday),
            ("sat", WeekStart::Saturday),
        ] {
            let l = locale_from(&serde_json::json!({"week_start": v}));
            assert_eq!(l.week_start, want, "week_start {v:?}");
        }
        // Declared beats implied, in both directions: an Arabic corpus read on
        // Monday weeks, an English one on Saturday weeks.
        let l = locale_from(&serde_json::json!({"language": "ar", "week_start": "monday"}));
        assert_eq!(l.week_start, WeekStart::Monday);

        // An unrecognised value falls back rather than failing: a reading
        // convention is not worth a 400.
        let l = locale_from(&serde_json::json!({"calendar": "mayan", "date_order": "sideways"}));
        assert_eq!(l.calendar, Calendar::Gregorian);
        assert_eq!(l.date_order, DateOrder::Undeclared);
        // And it does not ERASE what the language implied — the typo is the
        // caller declaring nothing, not the caller declaring "no convention".
        let l = locale_from(&serde_json::json!({"language": "ar", "date_order": "sideways"}));
        assert_eq!(l.date_order, DateOrder::DayFirst, "still from the language");

        // And they compose.
        let l = locale_from(
            &serde_json::json!({"language": "ar", "calendar": "hijri", "week_start": "sunday"}),
        );
        assert_eq!(l.language, Language::Arabic);
        assert_eq!(l.calendar, Calendar::Hijri);
        assert_eq!(l.week_start, WeekStart::Sunday);
        assert_eq!(l.date_order, DateOrder::DayFirst, "still from the language");
    }

    /// One `language` declaration, two consumers — the date scanner and
    /// morphology — reading the same key off the same request.
    #[test]
    fn one_language_declaration_feeds_both_consumers() {
        use undercroft_store::MorphLang;
        let body = serde_json::json!({"language": "de"});
        assert_eq!(morph_lang_from(&body), MorphLang::German);
        // German declares no date scanner of its own, so the temporal reading
        // stays English — each consumer falls back independently rather than
        // one of them guessing on the other's behalf.
        assert_eq!(locale_from(&body).language, Language::English);

        let body = serde_json::json!({"language": "ar"});
        assert_eq!(locale_from(&body).language, Language::Arabic);
        assert_eq!(
            morph_lang_from(&body),
            MorphLang::Undeclared,
            "Arabic morphology is root-and-pattern, not a suffix table"
        );

        assert_eq!(
            morph_lang_from(&serde_json::json!({})),
            MorphLang::Undeclared
        );
        // The advertised vocabulary is the parser's own, so a schema built from
        // it cannot promise a language the handler drops.
        for code in undercroft_store::MorphLang::CODES {
            let body = serde_json::json!({ "language": code });
            assert_ne!(
                morph_lang_from(&body),
                MorphLang::Undeclared,
                "advertised code {code:?} must parse"
            );
            assert!(language_codes().contains(code));
        }
    }

    /// Every channel is rendered, in its own place, with its own value.
    ///
    /// Four distinct values, because a "contains 0.000" assertion passes just
    /// as happily on a rendering that transposed two fields — and transposing
    /// `lexical_exact` with `lexical_morph` is the one mistake that would make
    /// the evidence say the opposite of what happened.
    #[test]
    fn the_evidence_line_names_every_channel_and_keeps_them_apart() {
        let hit = SearchHit {
            drawer: undercroft_core::Drawer::new("w", "r", "text".into(), None, 0, "test"),
            score: 0.5,
            semantic: 0.61,
            lexical: 0.77,
            lexical_exact: 0.82,
            lexical_morph: 0.25,
        };
        assert_eq!(
            evidence(&hit),
            "evidence: exact 0.820 · morph 0.250 · lexical 0.770 · semantic 0.610"
        );
    }

    /// Both text surfaces render the channels through the ONE function above.
    ///
    /// The same mechanism `parity.rs` uses, for the same reason: this whole
    /// module exists because three handlers each built the declaration by hand
    /// and each forgot a different piece. A second hand-rolled rendering is
    /// how the fourth omission gets born, and a `format!` in a handler is
    /// invisible to every test that only checks the helper.
    #[test]
    fn every_text_surface_renders_the_channels_through_one_function() {
        for (surface, src) in [
            ("the CLI", include_str!("main.rs")),
            ("MCP", include_str!("mcp.rs")),
        ] {
            assert!(
                src.contains("search::evidence("),
                "{surface} renders search hits without calling search::evidence — \
                 the lexical channels were `/v1`-only once already"
            );
        }
    }

    /// A filter that narrows the candidate set says what it kept out, and says
    /// nothing at all when it was never set — the two are different claims.
    #[test]
    fn exclusion_notes_speak_only_for_filters_the_caller_set() {
        let none = Exclusions {
            unlabeled: None,
            trust_excluded: None,
        };
        assert!(none.notes().is_empty(), "no filter, nothing to disclose");

        let zero = Exclusions {
            unlabeled: Some(0),
            trust_excluded: Some(0),
        };
        assert!(
            zero.notes().is_empty(),
            "a filter that excluded nothing has nothing to disclose"
        );

        let some = Exclusions {
            unlabeled: Some(3),
            trust_excluded: Some(2),
        };
        let notes = some.notes();
        assert_eq!(notes.len(), 2, "both filters excluded something: {notes:?}");
        assert!(notes[0].contains("3 in-scope drawers"), "{notes:?}");
        assert!(notes[1].contains("2 wing(s)"), "{notes:?}");
    }
}
