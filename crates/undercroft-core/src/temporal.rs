//! Temporal mentions found *inside* drawer content.
//!
//! A drawer carries two kinds of time. `content_date` says when the content
//! happened — metadata the writer supplies. This module covers the other
//! kind: dates and times written into the text itself, which are just as
//! much user data and must not be silently lost because they arrived as
//! prose rather than as a field.
//!
//! Two shapes appear in real text:
//!
//! * **Absolute** — "2023-05-07", "7 May 2023", "May 2023". Self-contained.
//! * **Relative** — "yesterday", "last Tuesday", "three weeks ago". These
//!   carry no meaning on their own; they are interpretable only against an
//!   anchor. That anchor is the drawer's `content_date`.
//!
//! Rules inherited from the mission:
//!
//! * **The text is never modified.** A mention records the exact span as
//!   written, plus a resolution when one is derivable. Extraction only adds
//!   derived structure, like `entities`.
//! * **Deterministic and offline.** A hand-rolled scanner, no model and no
//!   network, so the same input always yields the same mentions.
//! * **Never guess.** With no anchor, a relative mention is still recorded
//!   but left unresolved. An unresolved mention is honest; an invented date
//!   is the failure mode we are trying to eliminate.

use serde::{Deserialize, Serialize};
use time::{Date, Duration, Month, Weekday};

/// Whether a mention stands on its own or needs an anchor to interpret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeKind {
    /// Fully specified in the text ("7 May 2023").
    Absolute,
    /// Meaningful only relative to an anchor ("yesterday").
    Relative,
}

/// One temporal expression found in drawer content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeMention {
    /// The span exactly as written, preserved verbatim.
    pub text: String,
    pub kind: TimeKind,
    /// `YYYY-MM-DD` when derivable — directly for absolute mentions, or
    /// against the anchor for relative ones. `None` means "recorded, not
    /// resolvable", never "assumed".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    /// Byte offset of the span in the content, so a caller can highlight or
    /// re-read it without re-scanning.
    pub offset: u32,
}

const MONTHS: [(&str, Month); 12] = [
    ("january", Month::January),
    ("february", Month::February),
    ("march", Month::March),
    ("april", Month::April),
    ("may", Month::May),
    ("june", Month::June),
    ("july", Month::July),
    ("august", Month::August),
    ("september", Month::September),
    ("october", Month::October),
    ("november", Month::November),
    ("december", Month::December),
];

const WEEKDAYS: [(&str, Weekday); 7] = [
    ("monday", Weekday::Monday),
    ("tuesday", Weekday::Tuesday),
    ("wednesday", Weekday::Wednesday),
    ("thursday", Weekday::Thursday),
    ("friday", Weekday::Friday),
    ("saturday", Weekday::Saturday),
    ("sunday", Weekday::Sunday),
];

const NUMBER_WORDS: [(&str, i64); 12] = [
    ("a", 1),
    ("an", 1),
    ("one", 1),
    ("two", 2),
    ("three", 3),
    ("four", 4),
    ("five", 5),
    ("six", 6),
    ("seven", 7),
    ("eight", 8),
    ("nine", 9),
    ("ten", 10),
];

/// Match a month name or its three-letter abbreviation.
fn month_of(word: &str) -> Option<Month> {
    let w = word.trim_end_matches('.');
    MONTHS
        .iter()
        .find(|(name, _)| *name == w || (w.len() == 3 && name.starts_with(w)))
        .map(|(_, m)| *m)
}

fn weekday_of(word: &str) -> Option<Weekday> {
    let w = word.trim_end_matches('.');
    WEEKDAYS
        .iter()
        .find(|(name, _)| *name == w || (w.len() >= 3 && name.starts_with(w)))
        .map(|(_, d)| *d)
}

fn count_of(word: &str) -> Option<i64> {
    word.parse::<i64>().ok().filter(|n| *n > 0).or_else(|| {
        NUMBER_WORDS
            .iter()
            .find(|(w, _)| *w == word)
            .map(|(_, n)| *n)
    })
}

/// Parse the leading `YYYY-MM-DD` of an RFC3339 timestamp or bare date.
/// Anything else is not an anchor — callers get `None` and leave relative
/// mentions unresolved rather than inventing one.
pub fn parse_anchor(s: &str) -> Option<Date> {
    let d = s.get(..10)?;
    let mut it = d.split('-');
    let y: i32 = it.next()?.parse().ok()?;
    let m: u8 = it.next()?.parse().ok()?;
    let day: u8 = it.next()?.parse().ok()?;
    Date::from_calendar_date(y, Month::try_from(m).ok()?, day).ok()
}

/// Whole days from `from` to `to` — negative when `to` precedes `from`.
///
/// Exact calendar arithmetic: month lengths and leap years are the `time`
/// crate's problem, not a caller's and certainly not a language model's.
/// Both arguments accept an RFC 3339 timestamp or a bare `YYYY-MM-DD`;
/// anything unparseable yields `None` rather than a guess.
pub fn days_between(from: &str, to: &str) -> Option<i64> {
    let a = parse_anchor(from)?;
    let b = parse_anchor(to)?;
    Some((b - a).whole_days())
}

/// Monday that begins the ISO-8601 week containing `d`.
///
/// Monday because ISO 8601 says so. A locale that starts its weeks on Sunday
/// would shift every boundary, which is why the convention is stated here
/// instead of left implicit in an arithmetic expression.
fn week_start(d: Date) -> Date {
    d - Duration::days(d.weekday().number_days_from_monday() as i64)
}

/// Calendar weeks crossed between two dates: how many week boundaries lie
/// between them, not how many 7-day spans fit inside.
///
/// Those are different questions, and "how many weeks since X" is the
/// calendar one. Thursday 2023-01-19 to Wednesday 2023-05-03 is 104 days —
/// fourteen 7-day spans, but **fifteen** week boundaries crossed (the week
/// of Jan 16 through the week of May 1). Dividing days by 7 silently answers
/// the question nobody asked.
///
/// Derived from week starts rather than ISO week numbers, because those reset
/// each year and subtracting them breaks across a year boundary.
pub fn calendar_weeks_between(from: &str, to: &str) -> Option<i64> {
    let a = week_start(parse_anchor(from)?);
    let b = week_start(parse_anchor(to)?);
    Some((b - a).whole_days() / 7)
}

/// Calendar months crossed: January to May is 4, whatever the day of the
/// month and however many days those months held. Not `days / 30`, which is
/// a duration approximation and drifts.
pub fn calendar_months_between(from: &str, to: &str) -> Option<i64> {
    let a = parse_anchor(from)?;
    let b = parse_anchor(to)?;
    let key = |d: Date| d.year() as i64 * 12 + (d.month() as u8 as i64);
    Some(key(b) - key(a))
}

/// The interval between two dates phrased for a human or a prompt, in
/// calendar units so it agrees with how the question would be asked.
///
/// Days below a fortnight, because "13 days" tells you more than "1 week".
/// Then calendar weeks out to about half a year, then calendar months, then
/// years. Direction is explicit; identical dates read "same day".
///
/// Always offered *alongside* the exact counts, never instead of them.
pub fn describe_interval(from: &str, to: &str) -> Option<String> {
    let days = days_between(from, to)?;
    if days == 0 {
        return Some("same day".to_string());
    }
    let dir = if days < 0 { "before" } else { "after" };
    let n = days.abs();
    let (v, unit) = if n < 14 {
        (n, "day")
    } else if n < 180 {
        (calendar_weeks_between(from, to)?.abs(), "week")
    } else if n < 730 {
        (calendar_months_between(from, to)?.abs(), "month")
    } else {
        (n / 365, "year")
    };
    Some(format!("{v} {unit}{} {dir}", if v == 1 { "" } else { "s" }))
}

fn fmt(d: Date) -> String {
    format!("{:04}-{:02}-{:02}", d.year(), d.month() as u8, d.day())
}

/// Most recent occurrence of `wd` strictly before `from`.
fn previous_weekday(from: Date, wd: Weekday) -> Date {
    let mut d = from - Duration::days(1);
    while d.weekday() != wd {
        d -= Duration::days(1);
    }
    d
}

/// Next occurrence of `wd` strictly after `from`.
fn next_weekday(from: Date, wd: Weekday) -> Date {
    let mut d = from + Duration::days(1);
    while d.weekday() != wd {
        d += Duration::days(1);
    }
    d
}

/// Shift `d` by `n` whole months, clamping the day into the target month.
fn shift_months(d: Date, n: i64) -> Date {
    let total = d.year() as i64 * 12 + (d.month() as i64 - 1) + n;
    let (y, m) = (total.div_euclid(12) as i32, total.rem_euclid(12) as u8 + 1);
    let month = Month::try_from(m).unwrap_or(Month::January);
    let mut day = d.day();
    while day > 28 {
        if let Ok(ok) = Date::from_calendar_date(y, month, day) {
            return ok;
        }
        day -= 1;
    }
    Date::from_calendar_date(y, month, day).unwrap_or(d)
}

/// Split into lowercase word tokens with their byte offsets, keeping digits
/// and hyphens together so "2023-05-07" survives as one token.
fn tokens(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, ch) in text.char_indices() {
        let keep = ch.is_alphanumeric() || ch == '-' || ch == '/' || ch == '.';
        match (keep, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push((s, text[s..i].to_lowercase()));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, text[s..].to_lowercase()));
    }
    out
}

/// Parse a bare `YYYY-MM-DD` (or `YYYY/MM/DD`) token.
fn iso_token(tok: &str) -> Option<Date> {
    let t = tok.replace('/', "-");
    let mut it = t.split('-');
    let y: i32 = it.next()?.parse().ok()?;
    if !(1000..=9999).contains(&y) {
        return None;
    }
    let m: u8 = it.next()?.parse().ok()?;
    let d: u8 = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Date::from_calendar_date(y, Month::try_from(m).ok()?, d).ok()
}

/// Find every temporal expression in `text`, resolving what the `anchor`
/// allows. Absolute mentions resolve with or without an anchor; relative
/// ones resolve only with it.
///
/// The scan is linear and allocation-light: real drawers run this on every
/// write, so it must stay cheap enough to never be worth skipping.
pub fn extract_time_mentions(text: &str, anchor: Option<Date>) -> Vec<TimeMention> {
    let toks = tokens(text);
    let mut out: Vec<TimeMention> = Vec::new();
    let mut i = 0usize;

    // Raw slice for the verbatim span: tokens are lowercased, the record
    // must not be.
    let span = |from: usize, to_tok: usize| -> String {
        let end = toks
            .get(to_tok)
            .map(|(o, w)| o + w.len())
            .unwrap_or(text.len());
        text[from..end.min(text.len())].to_string()
    };

    while i < toks.len() {
        let (off, ref w) = toks[i];
        let mut consumed = 0usize;
        let mut mention: Option<(TimeKind, Option<Date>)> = None;

        if let Some(d) = iso_token(w) {
            mention = Some((TimeKind::Absolute, Some(d)));
        } else if let Some(month) = month_of(w) {
            // "May 7, 2023" / "May 2023" / "May 7"
            let day = toks.get(i + 1).and_then(|(_, t)| t.parse::<u8>().ok());
            let year_at = if day.is_some() { i + 2 } else { i + 1 };
            let year = toks
                .get(year_at)
                .and_then(|(_, t)| t.parse::<i32>().ok())
                .filter(|y| (1000..=9999).contains(y));
            consumed = match (day.is_some(), year.is_some()) {
                (true, true) => 2,
                (true, false) | (false, true) => 1,
                (false, false) => 0,
            };
            let resolved =
                year.and_then(|y| Date::from_calendar_date(y, month, day.unwrap_or(1)).ok());
            // A bare month with no year is a real mention but not a date.
            mention = Some((TimeKind::Absolute, resolved));
        } else if let (Some(day), Some(month)) = (
            // "7 May 2023" — only when a month actually follows. A bare
            // number must fall through to the relative arm, or "2 days ago"
            // is swallowed here as a day-of-month and never resolved.
            w.parse::<u8>().ok().filter(|d| (1..=31).contains(d)),
            toks.get(i + 1).and_then(|(_, t)| month_of(t)),
        ) {
            let year = toks
                .get(i + 2)
                .and_then(|(_, t)| t.parse::<i32>().ok())
                .filter(|y| (1000..=9999).contains(y));
            consumed = if year.is_some() { 2 } else { 1 };
            mention = Some((
                TimeKind::Absolute,
                year.and_then(|y| Date::from_calendar_date(y, month, day).ok()),
            ));
        } else {
            match w.as_str() {
                "yesterday" => {
                    mention = Some((TimeKind::Relative, anchor.map(|a| a - Duration::days(1))))
                }
                "today" | "tonight" => mention = Some((TimeKind::Relative, anchor)),
                "tomorrow" => {
                    mention = Some((TimeKind::Relative, anchor.map(|a| a + Duration::days(1))))
                }
                "last" | "next" | "this" => {
                    let back = w == "last";
                    if let Some((_, unit)) = toks.get(i + 1) {
                        consumed = 1;
                        let resolved = anchor.and_then(|a| match unit.as_str() {
                            "night" => Some(a - Duration::days(1)),
                            "week" => Some(if back {
                                a - Duration::days(7)
                            } else if w == "this" {
                                a
                            } else {
                                a + Duration::days(7)
                            }),
                            "month" => Some(shift_months(
                                a,
                                if w == "this" {
                                    0
                                } else if back {
                                    -1
                                } else {
                                    1
                                },
                            )),
                            "year" => Some(shift_months(
                                a,
                                if w == "this" {
                                    0
                                } else if back {
                                    -12
                                } else {
                                    12
                                },
                            )),
                            "morning" | "evening" | "afternoon" => Some(a),
                            _ => weekday_of(unit).map(|wd| {
                                if back {
                                    previous_weekday(a, wd)
                                } else {
                                    next_weekday(a, wd)
                                }
                            }),
                        });
                        let is_temporal = matches!(
                            unit.as_str(),
                            "night"
                                | "week"
                                | "month"
                                | "year"
                                | "morning"
                                | "evening"
                                | "afternoon"
                        ) || weekday_of(unit).is_some();
                        if is_temporal {
                            mention = Some((TimeKind::Relative, resolved));
                        } else {
                            consumed = 0;
                        }
                    }
                }
                _ => {
                    // "<n> <unit> ago"
                    if let Some(n) = count_of(w) {
                        let unit = toks.get(i + 1).map(|(_, t)| t.as_str()).unwrap_or("");
                        let ago = toks.get(i + 2).map(|(_, t)| t.as_str()) == Some("ago");
                        if ago {
                            let resolved = anchor.and_then(|a| match unit.trim_end_matches('s') {
                                "day" => Some(a - Duration::days(n)),
                                "week" => Some(a - Duration::days(7 * n)),
                                "month" => Some(shift_months(a, -n)),
                                "year" => Some(shift_months(a, -12 * n)),
                                _ => None,
                            });
                            if matches!(
                                unit.trim_end_matches('s'),
                                "day" | "week" | "month" | "year"
                            ) {
                                consumed = 2;
                                mention = Some((TimeKind::Relative, resolved));
                            }
                        }
                    }
                }
            }
        }

        if let Some((kind, resolved)) = mention {
            out.push(TimeMention {
                text: span(off, i + consumed),
                kind,
                resolved: resolved.map(fmt),
                offset: off as u32,
            });
            i += consumed + 1;
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor() -> Option<Date> {
        parse_anchor("2023-05-08T13:56:00+00:00")
    }

    #[test]
    fn resolves_yesterday_against_the_anchor() {
        let m = extract_time_mentions("I went to a support group yesterday", anchor());
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].text, "yesterday");
        assert_eq!(m[0].kind, TimeKind::Relative);
        assert_eq!(m[0].resolved.as_deref(), Some("2023-05-07"));
    }

    #[test]
    fn records_but_never_invents_without_an_anchor() {
        let m = extract_time_mentions("we met yesterday", None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].text, "yesterday");
        assert!(m[0].resolved.is_none(), "must not guess a date");
    }

    #[test]
    fn absolute_dates_resolve_without_an_anchor() {
        for (text, want) in [
            ("filed on 2023-05-07 sharp", "2023-05-07"),
            ("filed on 7 May 2023 sharp", "2023-05-07"),
            ("filed on May 7, 2023 sharp", "2023-05-07"),
        ] {
            let m = extract_time_mentions(text, None);
            assert_eq!(m.len(), 1, "{text}");
            assert_eq!(m[0].kind, TimeKind::Absolute);
            assert_eq!(m[0].resolved.as_deref(), Some(want), "{text}");
        }
    }

    #[test]
    fn keeps_the_span_verbatim_not_lowercased() {
        let m = extract_time_mentions("see you on 7 May 2023", None);
        assert_eq!(m[0].text, "7 May 2023");
    }

    #[test]
    fn last_weekday_walks_back_from_the_anchor() {
        // 2023-05-08 is a Monday; "last Tuesday" is 2023-05-02.
        let m = extract_time_mentions("I joined last Tuesday", anchor());
        assert_eq!(m[0].resolved.as_deref(), Some("2023-05-02"));
    }

    #[test]
    fn counted_units_ago() {
        for (text, want) in [
            ("three weeks ago", "2023-04-17"),
            ("2 days ago", "2023-05-06"),
            ("a month ago", "2023-04-08"),
        ] {
            let m = extract_time_mentions(text, anchor());
            assert_eq!(m.len(), 1, "{text}");
            assert_eq!(m[0].resolved.as_deref(), Some(want), "{text}");
        }
    }

    #[test]
    fn month_without_a_year_is_recorded_unresolved() {
        let m = extract_time_mentions("sometime in May we talked", None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, TimeKind::Absolute);
        assert!(m[0].resolved.is_none());
    }

    #[test]
    fn ordinary_prose_yields_nothing() {
        let m = extract_time_mentions("the last person to leave locks up", anchor());
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn month_end_clamps_when_shifting() {
        let a = parse_anchor("2023-03-31");
        let m = extract_time_mentions("a month ago", a);
        assert_eq!(m[0].resolved.as_deref(), Some("2023-02-28"));
    }

    #[test]
    fn finds_several_mentions_in_one_drawer() {
        let m = extract_time_mentions("met yesterday, meeting again next Friday", anchor());
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].resolved.as_deref(), Some("2023-05-07"));
        assert_eq!(m[1].resolved.as_deref(), Some("2023-05-12"));
    }

    // ---- exact interval arithmetic ----------------------------------------

    #[test]
    fn days_between_is_exact_across_month_lengths() {
        // Feb 2023 has 28 days; a naive 30-day month would be wrong here.
        assert_eq!(days_between("2023-01-31", "2023-03-01"), Some(29));
        assert_eq!(days_between("2023-05-08", "2023-05-07"), Some(-1));
        assert_eq!(days_between("2023-05-08", "2023-05-08"), Some(0));
    }

    #[test]
    fn days_between_handles_leap_years() {
        // 2024 is a leap year, 2023 is not.
        assert_eq!(days_between("2024-02-28", "2024-03-01"), Some(2));
        assert_eq!(days_between("2023-02-28", "2023-03-01"), Some(1));
        assert_eq!(days_between("2023-01-01", "2024-01-01"), Some(365));
        assert_eq!(days_between("2024-01-01", "2025-01-01"), Some(366));
    }

    #[test]
    fn days_between_accepts_rfc3339_and_bare_dates() {
        assert_eq!(
            days_between("2023-01-19T08:00:00+00:00", "2023-05-03"),
            Some(104)
        );
    }

    #[test]
    fn days_between_refuses_garbage_rather_than_guessing() {
        assert_eq!(days_between("not a date", "2023-05-08"), None);
        assert_eq!(days_between("2023-05-08", ""), None);
    }

    /// The failure this exists to remove, and the correction that followed.
    /// Asked for the gap between a flu recovery and a jog, a generator
    /// answered "11.7 weeks". The truth is 104 days — and the answer to
    /// "how many weeks" is **15**, the number of week boundaries crossed.
    /// `days / 7` gives 14, which answers a different question.
    #[test]
    fn weeks_means_calendar_weeks_not_seven_day_spans() {
        let (a, b) = ("2023-01-19", "2023-05-03");
        assert_eq!(days_between(a, b), Some(104));
        assert_eq!(104 / 7, 14, "the duration reading");
        assert_eq!(
            calendar_weeks_between(a, b),
            Some(15),
            "the calendar reading"
        );
        assert_eq!(calendar_months_between(a, b), Some(4));
        assert_eq!(describe_interval(a, b).unwrap(), "15 weeks after");
    }

    #[test]
    fn calendar_weeks_count_boundaries_not_elapsed_time() {
        // Sunday to the following Monday: one day, but a boundary is crossed.
        assert_eq!(days_between("2023-01-15", "2023-01-16"), Some(1));
        assert_eq!(calendar_weeks_between("2023-01-15", "2023-01-16"), Some(1));
        // Monday to Sunday of the same week: six days, no boundary.
        assert_eq!(days_between("2023-01-16", "2023-01-22"), Some(6));
        assert_eq!(calendar_weeks_between("2023-01-16", "2023-01-22"), Some(0));
    }

    #[test]
    fn calendar_weeks_survive_the_year_boundary() {
        // ISO week numbers reset in January, so subtracting them would be
        // wrong here. Week starts are not.
        assert_eq!(calendar_weeks_between("2022-12-26", "2023-01-02"), Some(1));
        assert_eq!(calendar_weeks_between("2022-12-20", "2023-01-10"), Some(3));
    }

    #[test]
    fn calendar_months_ignore_month_length() {
        assert_eq!(calendar_months_between("2023-01-31", "2023-02-01"), Some(1));
        assert_eq!(calendar_months_between("2023-01-01", "2023-01-31"), Some(0));
        assert_eq!(calendar_months_between("2023-11-15", "2024-02-01"), Some(3));
    }

    #[test]
    fn intervals_are_directional() {
        assert_eq!(
            describe_interval("2023-05-03", "2023-01-19").unwrap(),
            "15 weeks before"
        );
        assert_eq!(
            describe_interval("2023-05-03", "2023-05-03").unwrap(),
            "same day"
        );
        assert_eq!(
            calendar_weeks_between("2023-05-03", "2023-01-19"),
            Some(-15)
        );
    }

    #[test]
    fn short_intervals_count_days() {
        assert_eq!(
            describe_interval("2023-05-01", "2023-05-02").unwrap(),
            "1 day after"
        );
        assert_eq!(
            describe_interval("2023-05-01", "2023-05-13").unwrap(),
            "12 days after"
        );
    }

    #[test]
    fn weeks_keep_resolution_past_two_months() {
        // Calling this "2 months" would discard precision a memory should keep.
        assert_eq!(
            describe_interval("2023-01-01", "2023-03-12").unwrap(),
            "10 weeks after"
        );
        // Past half a year, months read better than thirty-odd weeks.
        assert_eq!(
            describe_interval("2023-01-01", "2023-07-01").unwrap(),
            "6 months after"
        );
    }

    #[test]
    fn describe_interval_refuses_garbage() {
        assert!(describe_interval("nope", "2023-05-03").is_none());
    }
}
