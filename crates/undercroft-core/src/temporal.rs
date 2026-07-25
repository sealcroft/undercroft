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
//! Either shape may name a **day** or a **period**. "7 May 2023" is a day;
//! "May 2023", "last week" and "last year" are periods, and a mention records
//! which it was rather than flattening a month onto its first morning.
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
//! * **Never panic.** Drawer content is arbitrary user text and this runs on
//!   every write, so "999999999 years ago" must yield an unresolved mention.
//!   Every shift is checked; out of range resolves to nothing.
//!
//! # Known gaps
//!
//! Limits of the scanner as it stands. Listed so they are visible, not
//! because any of them is a position worth defending.
//!
//! * **Two-digit years.** "5/7/23" is not read: the century is not in the
//!   token and this does not try to supply one.
//! * **A bare month with no year.** "in March" is recorded but unresolved.
//!   Which March is not in the text; narrowing it would take tense, which
//!   this does not read.
//! * **A lowercase bare month is not recorded at all** — see
//!   `month_name_is_deliberate`. Capitalization is the only available signal
//!   and it is weak, so this misses real months in all-lowercase text and
//!   wherever a sentence happens to begin with one.
//! * **Times of day.** "an hour ago" is not recorded. Resolving it needs the
//!   anchor's time, and the anchor is a `Date` — `parse_anchor` reduces the
//!   timestamp to its local day.
//! * **Non-English text.** Month names, weekday names, "ago" and the number
//!   words are English only, so a non-English drawer yields no mentions.
//!   Non-Gregorian calendars are not represented.
//! * **"Next Friday" said on a Wednesday** resolves to the coming Friday.
//!   Speakers who mean the following week's get a wrong date, and nothing in
//!   the text separates them.
//! * **Ambiguous numeric dates.** "05/07/2023" is recorded unresolved,
//!   because May 7th and the 5th of July are both real readings of it. Where
//!   only one reading is a date — "13/05/2023", "05/13/2023" — it resolves.

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
    ///
    /// The **first** day of what the text names. For a mention that names a
    /// single day that is the day; for one that names a period see
    /// [`resolved_end`](Self::resolved_end).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    /// Inclusive **last** day, present only when the text named a period
    /// wider than one day: "May 2023" ends on the 31st, "last week" on its
    /// final day, "last year" on December 31st.
    ///
    /// This distinction is not cosmetic. Collapsing a period to its first day
    /// asserts a precision the writer did not offer — it makes "May 2023"
    /// indistinguishable from "1 May 2023", which is the same class of
    /// invention this module exists to prevent. Omitted for single-day
    /// mentions so the common case serializes exactly as it always did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_end: Option<String>,
    /// Byte offset of the span in the content, so a caller can highlight or
    /// re-read it without re-scanning.
    pub offset: u32,
}

impl TimeMention {
    /// Inclusive `(first, last)` day pair of what the text named, when it
    /// resolved at all. A single-day mention yields the same date twice, so a
    /// caller can treat every mention as a range without special-casing.
    pub fn range(&self) -> Option<(&str, &str)> {
        let start = self.resolved.as_deref()?;
        Some((start, self.resolved_end.as_deref().unwrap_or(start)))
    }

    /// Whether the text named a period wider than a single day.
    pub fn is_period(&self) -> bool {
        self.resolved_end.is_some()
    }
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

/// The **local calendar date** an RFC 3339 timestamp names, in the offset the
/// timestamp itself carries — or a bare `YYYY-MM-DD` as given. Anything else
/// is not an anchor: callers get `None` and leave relative mentions
/// unresolved rather than inventing one.
///
/// Taking the leading 10 characters is not a shortcut, it is the definition.
/// `2023-05-08T23:30:00-07:00` names May 8th *for the person who wrote it*,
/// and "yesterday" in their sentence means their May 7th regardless of what
/// UTC or the reading machine thinks. The actor's frame travels with the
/// data; the host's timezone is never consulted, so the same vault answers
/// identically on every machine.
///
/// Storing the offset rather than a zone name is deliberate: historical
/// records need no IANA database, and a later change to DST rules cannot
/// retroactively alter what was recorded.
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

/// The UTC offset an RFC 3339 timestamp declares, in whole minutes. `None`
/// for a bare date, which names a day without committing to a frame.
///
/// Exposed so a caller can tell whether two timestamps are even comparable
/// in the same frame before trusting a day count between them.
pub fn offset_minutes(s: &str) -> Option<i32> {
    let t = s.get(10..)?;
    // The offset sits at the END of the time part: "T23:30:00Z" or
    // "T23:30:00-07:00". Zulu is UTC by definition.
    if t.ends_with('Z') || t.ends_with('z') {
        return Some(0);
    }
    // ...THH:MM:SS±HH:MM — find the sign that introduces the offset.
    let idx = t.rfind(['+', '-'])?;
    let sign = if t.as_bytes()[idx] == b'-' { -1 } else { 1 };
    let rest = &t[idx + 1..];
    let (h, m) = rest.split_once(':')?;
    Some(sign * (h.parse::<i32>().ok()? * 60 + m.parse::<i32>().ok()?))
}

/// Whether two timestamps are expressed in the same UTC offset.
///
/// When they are not, a local-date difference and an absolute-instant
/// difference can disagree — occasionally even in sign — so a caller
/// comparing across frames should know it is doing so rather than be handed
/// one answer as if it were the only one.
pub fn same_frame(a: &str, b: &str) -> bool {
    match (offset_minutes(a), offset_minutes(b)) {
        (Some(x), Some(y)) => x == y,
        // A bare date makes no claim, so it cannot conflict.
        _ => true,
    }
}

/// Absolute hours between two RFC 3339 instants, honouring both offsets.
///
/// The counterpart to [`days_between`], which works in local calendar days.
/// Use this when physical ordering matters — did A really happen before B —
/// and that when human day-counting matters. They are different questions:
/// an evening in Los Angeles and the next morning in Tokyo is +1 local day
/// but −7.5 absolute hours.
pub fn hours_between(from: &str, to: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let a = time::OffsetDateTime::parse(from, &Rfc3339).ok()?;
    let b = time::OffsetDateTime::parse(to, &Rfc3339).ok()?;
    Some((b - a).whole_hours())
}

/// Which day a week begins on. Not a formatting preference: it moves every
/// week boundary, so it changes the answer to "how many weeks since".
///
/// ISO 8601 says Monday, and that is the default. The United States, Canada,
/// Japan and Israel count from Sunday, and a reader there is not wrong — so
/// the convention is a parameter rather than a hardcoded assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WeekStart {
    #[default]
    Monday,
    Sunday,
}

impl WeekStart {
    /// Days to subtract from `d` to reach the start of its week.
    fn back_from(self, d: Date) -> i64 {
        let from_monday = d.weekday().number_days_from_monday() as i64;
        match self {
            WeekStart::Monday => from_monday,
            // Sunday is the day before Monday, so shift the cycle by one.
            WeekStart::Sunday => (from_monday + 1) % 7,
        }
    }
}

/// Days beyond which no calendar date can exist — the `time` crate's year
/// range is roughly ±9999, so a count larger than this cannot land on a real
/// date and is refused before it can overflow anything.
///
/// Drawer content is arbitrary user text: "999999999 days ago" is a string
/// somebody can write, and it must produce an unresolved mention, not a
/// panic on the write path and not a silently wrong date.
const MAX_DAY_SHIFT: i64 = 4_000_000;

/// Shift `d` by `n` days, or `None` if that leaves the representable range.
fn shift_days(d: Date, n: i64) -> Option<Date> {
    if !(-MAX_DAY_SHIFT..=MAX_DAY_SHIFT).contains(&n) {
        return None;
    }
    d.checked_add(Duration::days(n))
}

/// First day of the week containing `d`, under `ws`.
fn week_start_of(d: Date, ws: WeekStart) -> Option<Date> {
    shift_days(d, -ws.back_from(d))
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
    calendar_weeks_between_with(from, to, WeekStart::default())
}

/// As [`calendar_weeks_between`], under an explicit week-start convention.
/// A caller that knows its user's locale should say so; the two conventions
/// genuinely disagree for dates that fall on a Sunday.
pub fn calendar_weeks_between_with(from: &str, to: &str, ws: WeekStart) -> Option<i64> {
    let a = week_start_of(parse_anchor(from)?, ws)?;
    let b = week_start_of(parse_anchor(to)?, ws)?;
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
    describe_interval_with(from, to, WeekStart::default())
}

/// As [`describe_interval`], under an explicit week-start convention — the
/// weeks band phrases a boundary count, and that count is locale-dependent.
pub fn describe_interval_with(from: &str, to: &str, ws: WeekStart) -> Option<String> {
    let days = days_between(from, to)?;
    if days == 0 {
        return Some("same day".to_string());
    }
    let dir = if days < 0 { "before" } else { "after" };
    let n = days.abs();
    let (v, unit) = if n < 14 {
        (n, "day")
    } else if n < 180 {
        (calendar_weeks_between_with(from, to, ws)?.abs(), "week")
    } else if n < 730 {
        (calendar_months_between(from, to)?.abs(), "month")
    } else {
        // Calendar years, not `days / 365`. A span containing a leap day is
        // longer than 365 days per year, so dividing rounds *up* into a year
        // that has not finished — 2023-01-01 to 2024-12-31 is 730 days and
        // one year, not two. Every other band floors; this one must too.
        (calendar_months_between(from, to)?.abs() / 12, "year")
    };
    Some(format!("{v} {unit}{} {dir}", if v == 1 { "" } else { "s" }))
}

fn fmt(d: Date) -> String {
    format!("{:04}-{:02}-{:02}", d.year(), d.month() as u8, d.day())
}

/// Days from `wd` back to the most recent occurrence strictly before `from`.
fn days_back_to(from: Date, wd: Weekday) -> i64 {
    let (a, b) = (
        from.weekday().number_days_from_monday() as i64,
        wd.number_days_from_monday() as i64,
    );
    (a - b + 6).rem_euclid(7) + 1
}

/// Most recent occurrence of `wd` strictly before `from`.
fn previous_weekday(from: Date, wd: Weekday) -> Option<Date> {
    shift_days(from, -days_back_to(from, wd))
}

/// Next occurrence of `wd` strictly after `from`.
fn next_weekday(from: Date, wd: Weekday) -> Option<Date> {
    let (a, b) = (
        from.weekday().number_days_from_monday() as i64,
        wd.number_days_from_monday() as i64,
    );
    shift_days(from, (b - a + 6).rem_euclid(7) + 1)
}

/// The occurrence of `wd` inside the week that contains `from`, under `ws`.
///
/// "this Friday" and "next Friday" must not resolve to the same day. Walking
/// forward from the anchor makes them identical whenever the weekday is still
/// ahead, which reads every "this" as a "next" — so "this" is anchored to the
/// current week instead, which is what the word says.
///
/// The week in question is the locale's, hence `ws`: on a Sunday, "this
/// Monday" is tomorrow under ISO weeks and six days ago under Sunday-first
/// ones. Both readings are correct for their reader; neither is universal.
fn weekday_in_week(from: Date, wd: Weekday, ws: WeekStart) -> Option<Date> {
    let start = week_start_of(from, ws)?;
    let (a, b) = (
        start.weekday().number_days_from_monday() as i64,
        wd.number_days_from_monday() as i64,
    );
    shift_days(start, (b - a).rem_euclid(7))
}

/// Shift `d` by `n` whole months, clamping the day into the target month
/// (Jan 31 minus one month is Feb 28, or Feb 29 in a leap year).
///
/// `None` when the result leaves the representable range. Returning the
/// *unshifted* date there — as this once did — reports the anchor as though
/// it were the answer, which is a wrong date wearing the costume of a right
/// one. An unresolved mention is the honest outcome.
fn shift_months(d: Date, n: i64) -> Option<Date> {
    let total = (d.year() as i64)
        .checked_mul(12)?
        .checked_add(d.month() as i64 - 1)?
        .checked_add(n)?;
    let y = i32::try_from(total.div_euclid(12)).ok()?;
    let month = Month::try_from(u8::try_from(total.rem_euclid(12) + 1).ok()?).ok()?;
    let mut day = d.day();
    while day > 28 {
        if let Ok(ok) = Date::from_calendar_date(y, month, day) {
            return Some(ok);
        }
        day -= 1;
    }
    Date::from_calendar_date(y, month, day).ok()
}

/// A single day, expressed as the degenerate period that starts and ends on
/// it, so every mention can be handled as a range.
fn point(d: Date) -> (Date, Date) {
    (d, d)
}

/// First and last day of the calendar month containing `d`.
fn month_range(d: Date) -> Option<(Date, Date)> {
    let start = Date::from_calendar_date(d.year(), d.month(), 1).ok()?;
    let end = shift_days(shift_months(start, 1)?, -1)?;
    Some((start, end))
}

/// First and last day of the calendar year containing `d`.
fn year_range(d: Date) -> Option<(Date, Date)> {
    Some((
        Date::from_calendar_date(d.year(), Month::January, 1).ok()?,
        Date::from_calendar_date(d.year(), Month::December, 31).ok()?,
    ))
}

/// First and last day of the week containing `d`, under `ws`.
fn week_range(d: Date, ws: WeekStart) -> Option<(Date, Date)> {
    let start = week_start_of(d, ws)?;
    Some((start, shift_days(start, 6)?))
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

/// Whether a month name written at byte offset `off` is being used as a month
/// rather than as an ordinary English word — "in May" against "it may rain",
/// "last March" against "march forward".
///
/// Only consulted where the expression carries no year and so cannot resolve
/// to a date anyway; anything resolvable is kept whatever its case, because
/// "7 may 2023" is unambiguously a date.
///
/// The one cheap signal is capitalization, and it only means something where
/// the writer had a choice. At the start of the text, of a line, or of a
/// sentence, capitalization is forced and says nothing — so there we decline
/// rather than guess, which costs a caller nothing it could have used and
/// keeps every "may", "march" and "august" out of the record.
fn month_name_is_deliberate(text: &str, off: usize) -> bool {
    if !text[off..].chars().next().is_some_and(char::is_uppercase) {
        return false;
    }
    let before = text[..off].trim_end_matches([' ', '\t']);
    !(before.is_empty() || before.ends_with(['.', '!', '?', '\n', '\r']))
}

/// Resolve a span that some *other* component claims dates something in
/// `text` — an extraction model reading the note, most usefully.
///
/// The claim is not trusted. It is checked against the text first: a span
/// that is not literally there is rejected, so a proposer that invents "in
/// June 2019" for a note which never said it gets nothing back. What survives
/// that check is resolved by the same deterministic scanner every drawer goes
/// through, against the same anchor, and only a claim that *resolves* is
/// returned.
///
/// This is the whole contract that lets an approximate component help without
/// being trusted: **it may point at words, it may not supply a date.** Only
/// this module turns words into a `resolved` value, so a claim that cannot be
/// verified degrades to no answer rather than to a wrong one — which keeps
/// "never guess" true of the system, not merely of the scanner.
///
/// The returned mention's `offset` is relative to `text`, not to the claim.
pub fn resolve_claimed_span(text: &str, claim: &str, anchor: Option<Date>) -> Option<TimeMention> {
    resolve_claimed_span_with(text, claim, anchor, WeekStart::default())
}

/// As [`resolve_claimed_span`], under an explicit week-start convention.
pub fn resolve_claimed_span_with(
    text: &str,
    claim: &str,
    anchor: Option<Date>,
    ws: WeekStart,
) -> Option<TimeMention> {
    let claim = claim.trim();
    if claim.is_empty() {
        return None;
    }
    // Verbatim or nothing. The words have to be the writer's.
    let at = text.find(claim)?;
    let mut m = extract_time_mentions_with(claim, anchor, ws)
        .into_iter()
        .find(|m| m.resolved.is_some())?;
    m.offset = u32::try_from(at)
        .unwrap_or(u32::MAX)
        .saturating_add(m.offset);
    Some(m)
}

/// Parse a numeric date whose **year comes last** — "13/05/2023",
/// "05-13-2023", "13.5.2023".
///
/// Day-first and month-first orders are both in wide use and the token does
/// not say which it is. It does not have to: only one order yields a real
/// date whenever either number exceeds twelve, which covers most of the
/// calendar. So this returns
///
/// * `Some(Some(date))` — one reading is a date and the other is not,
/// * `Some(None)` — both are dates, so the token names a day we cannot
///   identify. It is still a date expression and the caller records it
///   unresolved rather than dropping it,
/// * `None` — neither reading is a date, so this is not one.
///
/// Two-digit years are not read at all; the century is not in the token.
fn dmy_token(tok: &str) -> Option<Option<Date>> {
    let norm = tok.replace(['/', '.'], "-");
    let parts: Vec<&str> = norm.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: i32 = parts[2]
        .parse()
        .ok()
        .filter(|y| (1000..=9999).contains(y))?;
    let (a, b): (u8, u8) = (parts[0].parse().ok()?, parts[1].parse().ok()?);
    // `Month::try_from` rejects anything over twelve, which is exactly the
    // test that decides the order.
    let day_first = Month::try_from(b)
        .ok()
        .and_then(|m| Date::from_calendar_date(year, m, a).ok());
    let month_first = Month::try_from(a)
        .ok()
        .and_then(|m| Date::from_calendar_date(year, m, b).ok());
    match (day_first, month_first) {
        (Some(d), None) | (None, Some(d)) => Some(Some(d)),
        (Some(_), Some(_)) => Some(None),
        (None, None) => None,
    }
}

/// Find every temporal expression in `text`, resolving what the `anchor`
/// allows. Absolute mentions resolve with or without an anchor; relative
/// ones resolve only with it.
///
/// The scan is linear and allocation-light: real drawers run this on every
/// write, so it must stay cheap enough to never be worth skipping.
pub fn extract_time_mentions(text: &str, anchor: Option<Date>) -> Vec<TimeMention> {
    extract_time_mentions_with(text, anchor, WeekStart::default())
}

/// As [`extract_time_mentions`], under an explicit week-start convention.
///
/// The convention is not decoration here: "last week" names a different seven
/// days depending on where the week begins, and so does "this Thursday". A
/// caller that knows its user's locale should say so.
pub fn extract_time_mentions_with(
    text: &str,
    anchor: Option<Date>,
    ws: WeekStart,
) -> Vec<TimeMention> {
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
        // The period the text names, as an inclusive first/last day pair.
        // A single day is the pair repeated; `None` is "recorded, not
        // resolvable", which stays distinct from "resolved to one day".
        let mut mention: Option<(TimeKind, Option<(Date, Date)>)> = None;

        if let Some(d) = iso_token(w) {
            mention = Some((TimeKind::Absolute, Some(point(d))));
        } else if let Some(resolved) = dmy_token(w) {
            mention = Some((TimeKind::Absolute, resolved.map(point)));
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
            let period = match (day, year) {
                (Some(d), Some(y)) => Date::from_calendar_date(y, month, d).ok().map(point),
                // "May 2023" names the month, not its first day.
                (None, Some(y)) => Date::from_calendar_date(y, month, 1)
                    .ok()
                    .and_then(month_range),
                // A day without a year, or a bare month, is a real mention
                // but not a date: which year is not knowable from the text.
                _ => None,
            };
            // A bare month name is also an ordinary word; without a day or a
            // year to disambiguate it, take it only where the writer's
            // capitalization actually chose.
            if day.is_some() || year.is_some() || month_name_is_deliberate(text, off) {
                mention = Some((TimeKind::Absolute, period));
            }
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
            // Same guard, same reason: "chapter 7 may be wrong" is not a date,
            // and without a year there is nothing else to tell them apart.
            if year.is_some() || month_name_is_deliberate(text, toks[i + 1].0) {
                mention = Some((
                    TimeKind::Absolute,
                    year.and_then(|y| Date::from_calendar_date(y, month, day).ok())
                        .map(point),
                ));
            }
        } else {
            match w.as_str() {
                "yesterday" => {
                    mention = Some((
                        TimeKind::Relative,
                        anchor.and_then(|a| shift_days(a, -1)).map(point),
                    ))
                }
                "today" | "tonight" => mention = Some((TimeKind::Relative, anchor.map(point))),
                "tomorrow" => {
                    mention = Some((
                        TimeKind::Relative,
                        anchor.and_then(|a| shift_days(a, 1)).map(point),
                    ))
                }
                "last" | "next" | "this" => {
                    // How far the phrase moves, in units of whatever follows.
                    let step: i64 = match w.as_str() {
                        "last" => -1,
                        "this" => 0,
                        _ => 1,
                    };
                    if let Some((_, unit)) = toks.get(i + 1) {
                        let period = anchor.and_then(|a| match unit.as_str() {
                            // Parts of a day name a day, and which day is
                            // exactly what "last"/"this"/"next" is saying:
                            // "last evening" is yesterday's.
                            "night" | "morning" | "evening" | "afternoon" => {
                                shift_days(a, step).map(point)
                            }
                            // Named calendar periods, not anchor ± an offset.
                            // "last month" is the whole of the previous month;
                            // reading it as "the same day-of-month, one month
                            // back" answers a question nobody asked.
                            "week" => shift_days(week_start_of(a, ws)?, 7 * step)
                                .and_then(|d| week_range(d, ws)),
                            "month" => shift_months(a, step).and_then(month_range),
                            "year" => shift_months(a, 12 * step).and_then(year_range),
                            _ => weekday_of(unit)
                                .and_then(|wd| match step {
                                    -1 => previous_weekday(a, wd),
                                    0 => weekday_in_week(a, wd, ws),
                                    _ => next_weekday(a, wd),
                                })
                                .map(point),
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
                            consumed = 1;
                            mention = Some((TimeKind::Relative, period));
                        }
                    }
                }
                _ => {
                    // "<n> <unit> ago" — displacement arithmetic on the
                    // anchor, so it names a day rather than a calendar
                    // period: "three weeks ago" is the day three weeks back,
                    // where "last week" is a week.
                    if let Some(n) = count_of(w) {
                        let unit = toks.get(i + 1).map(|(_, t)| t.as_str()).unwrap_or("");
                        let ago = toks.get(i + 2).map(|(_, t)| t.as_str()) == Some("ago");
                        if ago {
                            let period = anchor
                                .and_then(|a| match unit.trim_end_matches('s') {
                                    "day" => shift_days(a, -n),
                                    "week" => n.checked_mul(7).and_then(|d| shift_days(a, -d)),
                                    "month" => shift_months(a, -n),
                                    "year" => n.checked_mul(12).and_then(|m| shift_months(a, -m)),
                                    _ => None,
                                })
                                .map(point);
                            if matches!(
                                unit.trim_end_matches('s'),
                                "day" | "week" | "month" | "year"
                            ) {
                                consumed = 2;
                                mention = Some((TimeKind::Relative, period));
                            }
                        }
                    }
                }
            }
        }

        if let Some((kind, period)) = mention {
            let (start, end) = match period {
                Some((s, e)) => (Some(fmt(s)), Some(fmt(e))),
                None => (None, None),
            };
            out.push(TimeMention {
                text: span(off, i + consumed),
                kind,
                // A single day writes one date, exactly as before; only a
                // genuine period carries the second.
                resolved_end: match (&start, &end) {
                    (Some(s), Some(e)) if s != e => end,
                    _ => None,
                },
                resolved: start,
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

    // ---- a claim is checked, not believed --------------------------------

    /// The contract that lets an approximate proposer help without being
    /// trusted: it points at words, and this module turns words into dates.
    #[test]
    fn a_claimed_span_resolves_only_when_the_text_really_says_it() {
        let note = "I quit smoking three months ago and feel better";
        let m = resolve_claimed_span(note, "three months ago", anchor()).unwrap();
        assert_eq!(m.resolved.as_deref(), Some("2023-02-08"));
        // Offsets are reported against the note, not the fragment.
        assert_eq!(m.offset as usize, note.find("three").unwrap());
    }

    /// A span the note does not contain is refused outright — the failure
    /// mode this check exists for is a model inventing a plausible date.
    #[test]
    fn an_invented_span_is_refused() {
        let note = "I quit smoking three months ago";
        for claim in [
            "in June 2019",   // never appears
            "two months ago", // plausible, still not what was written
            "2023-02-08",     // the right answer, but not the note's words
            "",
            "   ",
        ] {
            assert!(
                resolve_claimed_span(note, claim, anchor()).is_none(),
                "accepted {claim:?}"
            );
        }
    }

    /// Present in the note but not a time expression, or not resolvable
    /// against the anchor — either way the caller gets nothing and falls
    /// back, rather than getting something wrong.
    #[test]
    fn a_real_span_that_is_not_a_date_resolves_to_nothing() {
        let note = "I quit smoking after the move to Berlin, sometime in March";
        assert!(resolve_claimed_span(note, "after the move", anchor()).is_none());
        // "March" is in the note, but no year is, and this never guesses one.
        assert!(resolve_claimed_span(note, "March", anchor()).is_none());
    }

    #[test]
    fn a_claimed_span_may_name_a_period() {
        let note = "we signed the lease in May 2023 after a long search";
        let m = resolve_claimed_span(note, "May 2023", None).unwrap();
        assert_eq!(m.range(), Some(("2023-05-01", "2023-05-31")));
        assert!(m.is_period());
    }

    /// Relative claims need the note's anchor, exactly like the scanner.
    #[test]
    fn a_relative_claim_without_an_anchor_stays_unresolved() {
        let note = "I quit smoking three months ago";
        assert!(resolve_claimed_span(note, "three months ago", None).is_none());
    }

    // ---- numeric dates with the year last --------------------------------

    /// Day-first and month-first are both in use, but only one of them yields
    /// a real date whenever either number exceeds twelve.
    #[test]
    fn numeric_dates_resolve_wherever_the_order_is_decidable() {
        for (text, want) in [
            ("on 13/05/2023 we met", "2023-05-13"),
            ("on 05/13/2023 we met", "2023-05-13"),
            ("on 13-05-2023 we met", "2023-05-13"),
            ("on 13.5.2023 we met", "2023-05-13"),
            ("on 31/01/2023 we met", "2023-01-31"),
        ] {
            let m = extract_time_mentions(text, None);
            assert_eq!(m.len(), 1, "{text} -> {m:?}");
            assert_eq!(m[0].resolved.as_deref(), Some(want), "{text}");
        }
    }

    /// When both readings are real dates the token does not say which day it
    /// names. Recording it unresolved keeps the fact that a date is there;
    /// picking one would be a coin flip reported as a fact.
    #[test]
    fn ambiguous_numeric_dates_are_recorded_but_not_resolved() {
        let m = extract_time_mentions("dated 05/07/2023 exactly", None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].text, "05/07/2023");
        assert_eq!(m[0].kind, TimeKind::Absolute);
        assert!(m[0].resolved.is_none(), "{m:?}");
    }

    #[test]
    fn numeric_non_dates_are_not_dates() {
        for text in [
            "score 31/02/2023 here", // no such day in February
            "version 1/2/23 here",   // two-digit year, century unknown
            "ratio 40/50/2023 here", // neither number can be a month
            "build 2023-05-07 fine", // year-first stays the ISO path
        ] {
            let m = extract_time_mentions(text, None);
            let numeric: Vec<_> = m.iter().filter(|x| x.text.contains('/')).collect();
            assert!(numeric.is_empty(), "{text} -> {numeric:?}");
        }
    }

    // ---- periods are not their first day ---------------------------------

    /// "May 2023" names a month. Resolving it to the 1st makes it
    /// indistinguishable from "1 May 2023" — precision the writer never
    /// offered, which is the invention this module exists to prevent.
    #[test]
    fn a_month_and_year_names_the_whole_month() {
        let m = extract_time_mentions("we shipped it in May 2023 eventually", None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].text, "May 2023");
        assert_eq!(m[0].range(), Some(("2023-05-01", "2023-05-31")));
        assert!(m[0].is_period());
        // February is shorter, and shorter still outside a leap year.
        let feb = extract_time_mentions("February 2024 was busy", None);
        assert_eq!(feb[0].range(), Some(("2024-02-01", "2024-02-29")));
        let feb23 = extract_time_mentions("February 2023 was busy", None);
        assert_eq!(feb23[0].range(), Some(("2023-02-01", "2023-02-28")));
    }

    #[test]
    fn a_single_day_carries_no_end_and_serializes_as_before() {
        let m = extract_time_mentions("on 2023-05-07 we met", None);
        assert_eq!(m[0].range(), Some(("2023-05-07", "2023-05-07")));
        assert!(!m[0].is_period());
        assert!(
            m[0].resolved_end.is_none(),
            "a point must not write a second date"
        );
        let json = serde_json::to_string(&m[0]).unwrap();
        assert!(!json.contains("resolved_end"), "{json}");
    }

    #[test]
    fn last_week_is_a_week_not_a_day_seven_days_back() {
        // 2023-05-08 is a Monday, so the ISO week before it is May 1–7.
        let m = extract_time_mentions("we discussed it last week", anchor());
        assert_eq!(m[0].range(), Some(("2023-05-01", "2023-05-07")));
        let this = extract_time_mentions("we discussed it this week", anchor());
        assert_eq!(this[0].range(), Some(("2023-05-08", "2023-05-14")));
        let next = extract_time_mentions("we discuss it next week", anchor());
        assert_eq!(next[0].range(), Some(("2023-05-15", "2023-05-21")));
    }

    #[test]
    fn last_month_is_a_month_not_the_same_day_one_month_back() {
        let m = extract_time_mentions("I quit last month", anchor());
        assert_eq!(m[0].range(), Some(("2023-04-01", "2023-04-30")));
        let this = extract_time_mentions("I quit this month", anchor());
        assert_eq!(this[0].range(), Some(("2023-05-01", "2023-05-31")));
    }

    #[test]
    fn last_year_is_a_year() {
        let m = extract_time_mentions("we moved last year", anchor());
        assert_eq!(m[0].range(), Some(("2022-01-01", "2022-12-31")));
        let next = extract_time_mentions("we move next year", anchor());
        assert_eq!(next[0].range(), Some(("2024-01-01", "2024-12-31")));
    }

    /// "N units ago" is displacement arithmetic on the anchor, so it names a
    /// day. That is a different shape from "last week", which names a period,
    /// and the two must not be flattened together.
    #[test]
    fn counted_units_ago_stay_points() {
        for text in ["three weeks ago", "2 days ago", "a month ago"] {
            let m = extract_time_mentions(text, anchor());
            assert!(!m[0].is_period(), "{text} should name a day");
        }
    }

    // ---- "this" and "next" are different words ---------------------------

    /// Walking forward from the anchor made "this Friday" and "next Friday"
    /// the same date whenever the weekday was still ahead — reading every
    /// "this" as a "next". "This" belongs to the current week.
    #[test]
    fn this_weekday_and_next_weekday_differ() {
        // Anchor is Monday 2023-05-08; that week runs May 8–14 under ISO.
        let this = extract_time_mentions("meeting this Friday", anchor());
        let next = extract_time_mentions("meeting next Friday", anchor());
        assert_eq!(this[0].resolved.as_deref(), Some("2023-05-12"));
        assert_eq!(next[0].resolved.as_deref(), Some("2023-05-12"));
        // On a Saturday the two readings separate: "this Friday" is the one
        // inside the current week, already past.
        let sat = parse_anchor("2023-05-13");
        let this = extract_time_mentions("meeting this Friday", sat);
        let next = extract_time_mentions("meeting next Friday", sat);
        assert_eq!(this[0].resolved.as_deref(), Some("2023-05-12"));
        assert_eq!(next[0].resolved.as_deref(), Some("2023-05-19"));
        assert_ne!(this[0].resolved, next[0].resolved);
    }

    #[test]
    fn this_weekday_follows_the_week_start_convention() {
        // Sunday 2023-05-14. Under ISO it closes the week that began Monday
        // the 8th, so "this Monday" is the 8th. Under a Sunday-first locale
        // it opens the week, so "this Monday" is tomorrow, the 15th.
        let sun = parse_anchor("2023-05-14");
        let iso = extract_time_mentions_with("this Monday", sun, WeekStart::Monday);
        let us = extract_time_mentions_with("this Monday", sun, WeekStart::Sunday);
        assert_eq!(iso[0].resolved.as_deref(), Some("2023-05-08"));
        assert_eq!(us[0].resolved.as_deref(), Some("2023-05-15"));
    }

    #[test]
    fn last_week_follows_the_week_start_convention() {
        let sun = parse_anchor("2023-05-14");
        let iso = extract_time_mentions_with("last week", sun, WeekStart::Monday);
        let us = extract_time_mentions_with("last week", sun, WeekStart::Sunday);
        assert_eq!(iso[0].range(), Some(("2023-05-01", "2023-05-07")));
        assert_eq!(us[0].range(), Some(("2023-05-07", "2023-05-13")));
    }

    /// Day parts belong to the day the qualifier names: "last evening" is
    /// yesterday's, not today's.
    #[test]
    fn day_parts_take_the_day_their_qualifier_names() {
        for (text, want) in [
            ("last night", "2023-05-07"),
            ("last evening", "2023-05-07"),
            ("this morning", "2023-05-08"),
            ("tonight", "2023-05-08"),
            ("next morning", "2023-05-09"),
        ] {
            let m = extract_time_mentions(text, anchor());
            assert_eq!(m.len(), 1, "{text}");
            assert_eq!(m[0].resolved.as_deref(), Some(want), "{text}");
        }
    }

    // ---- month names are also ordinary words -----------------------------

    /// "may", "march" and "august" are English words. A bare one carries no
    /// date, so recording it buys nothing and costs a false mention on every
    /// drawer that uses the verb.
    #[test]
    fn a_bare_lowercase_month_is_not_a_month() {
        for text in [
            "it may rain tomorrow",
            "we march forward",
            "an august occasion",
            "chapter 7 may be wrong",
        ] {
            let m = extract_time_mentions(text, None);
            assert!(
                m.iter().all(|x| x.text.to_lowercase() != "may"
                    && x.text.to_lowercase() != "march"
                    && x.text.to_lowercase() != "august"
                    && !x.text.to_lowercase().starts_with("7 may")),
                "{text} -> {m:?}"
            );
        }
    }

    #[test]
    fn a_capitalized_bare_month_is_still_recorded() {
        let m = extract_time_mentions("we met in March and again later", None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].text, "March");
        assert!(m[0].resolved.is_none(), "no year, so no date");
    }

    /// At the start of a sentence every word is capitalized, so the signal
    /// is not the writer's choice and cannot be read as one.
    #[test]
    fn sentence_initial_capitalization_is_not_evidence() {
        let m = extract_time_mentions("It rained. May was hard.", None);
        assert!(m.is_empty(), "{m:?}");
    }

    /// Case is only consulted where nothing else can decide. A year, or a
    /// day, makes the expression a date whatever its case.
    #[test]
    fn case_never_overrides_an_unambiguous_date() {
        for (text, want) in [
            ("filed 7 may 2023", "2023-05-07"),
            ("filed may 7, 2023", "2023-05-07"),
            ("filed may 2023", "2023-05-01"),
        ] {
            let m = extract_time_mentions(text, None);
            assert_eq!(m.len(), 1, "{text} -> {m:?}");
            assert_eq!(m[0].resolved.as_deref(), Some(want), "{text}");
        }
    }

    // ---- hostile input must not panic or lie -----------------------------

    /// Drawer content is arbitrary user text and this runs on every write.
    /// A count no calendar can hold has to come back unresolved — not as a
    /// panic, and not as the anchor date wearing the answer's costume.
    #[test]
    fn absurd_counts_resolve_to_nothing_rather_than_panicking() {
        for text in [
            "999999999 days ago",
            "9223372036854775807 days ago",
            "9223372036854775807 weeks ago",
            "9223372036854775807 months ago",
            "9223372036854775807 years ago",
            "4000001 days ago",
        ] {
            let m = extract_time_mentions(text, anchor());
            assert_eq!(m.len(), 1, "{text} is still a mention");
            assert!(
                m[0].resolved.is_none(),
                "{text} resolved to {:?}",
                m[0].resolved
            );
        }
    }

    #[test]
    fn shifting_out_of_range_yields_nothing_not_the_anchor() {
        let a = parse_anchor("9999-12-31").unwrap();
        assert_eq!(shift_months(a, 1), None);
        assert_eq!(shift_days(a, 1), None);
        assert_eq!(shift_months(a, i64::MAX), None);
        assert_eq!(shift_months(a, i64::MIN), None);
        // And a shift that stays in range still works.
        assert_eq!(shift_months(a, -1).map(fmt), Some("9999-11-30".to_string()));
    }

    #[test]
    fn extraction_never_panics_on_extreme_anchors() {
        for anchor_str in ["0001-01-01", "9999-12-31"] {
            let a = parse_anchor(anchor_str);
            let m = extract_time_mentions(
                "yesterday, tomorrow, last week, next year, this month, 5 years ago",
                a,
            );
            assert!(!m.is_empty(), "{anchor_str}");
        }
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
    // ---- frames: whose clock is this? ------------------------------------

    #[test]
    fn the_local_date_is_the_actors_date_not_utcs() {
        // 23:30 in Los Angeles is already the next day in UTC. The sentence
        // "I went yesterday" written then means the writer's yesterday.
        let ts = "2023-05-08T23:30:00-07:00";
        assert_eq!(fmt(parse_anchor(ts).unwrap()), "2023-05-08");
        let m = extract_time_mentions("I went yesterday", parse_anchor(ts));
        assert_eq!(m[0].resolved.as_deref(), Some("2023-05-07"));
    }

    #[test]
    fn offsets_are_read_not_discarded() {
        assert_eq!(offset_minutes("2023-05-08T23:30:00-07:00"), Some(-420));
        assert_eq!(offset_minutes("2023-05-08T23:30:00+09:00"), Some(540));
        assert_eq!(offset_minutes("2023-05-08T23:30:00Z"), Some(0));
        assert_eq!(
            offset_minutes("2023-05-08"),
            None,
            "a bare date claims no frame"
        );
    }

    #[test]
    fn same_frame_detects_incomparable_timestamps() {
        assert!(same_frame(
            "2023-05-08T10:00:00+09:00",
            "2023-05-09T10:00:00+09:00"
        ));
        assert!(!same_frame(
            "2023-05-08T23:30:00-07:00",
            "2023-05-09T08:00:00+09:00"
        ));
        // A bare date makes no claim, so it never conflicts.
        assert!(same_frame("2023-05-08", "2023-05-09T08:00:00+09:00"));
    }

    /// The case that motivates keeping both notions: across frames, local-day
    /// counting and absolute-instant counting can disagree in SIGN. Neither
    /// is wrong; they answer different questions, so the engine reports both
    /// rather than silently picking one.
    #[test]
    fn local_days_and_absolute_hours_can_disagree_in_sign() {
        let a = "2023-05-08T23:30:00-07:00"; // evening in Los Angeles
        let b = "2023-05-09T08:00:00+09:00"; // next morning in Tokyo
        assert_eq!(days_between(a, b), Some(1), "one local day later");
        assert_eq!(
            hours_between(a, b),
            Some(-7),
            "but earlier in absolute time"
        );
        assert!(!same_frame(a, b), "and the caller can tell why");
    }

    #[test]
    fn hours_between_honours_both_offsets() {
        assert_eq!(
            hours_between("2023-05-08T23:30:00+09:00", "2023-05-08T23:30:00-07:00"),
            Some(16)
        );
        assert_eq!(
            hours_between("2023-05-08", "2023-05-09"),
            None,
            "needs instants"
        );
    }

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
    fn week_start_convention_changes_the_count_and_both_are_right() {
        // 2023-01-15 is a Sunday. Under ISO it closes the week beginning
        // Jan 9; under a Sunday-first locale it OPENS the next one — so the
        // gap to the following Wednesday spans a different number of weeks.
        let (sun, wed) = ("2023-01-15", "2023-01-18");
        assert_eq!(
            calendar_weeks_between_with(sun, wed, WeekStart::Monday),
            Some(1),
            "ISO: Sunday ends the previous week, so a boundary is crossed"
        );
        assert_eq!(
            calendar_weeks_between_with(sun, wed, WeekStart::Sunday),
            Some(0),
            "Sunday-first: both dates sit inside one week"
        );
        // The default stays ISO, unchanged for existing callers.
        assert_eq!(calendar_weeks_between(sun, wed), Some(1));
        assert_eq!(WeekStart::default(), WeekStart::Monday);
    }

    #[test]
    fn sunday_first_weeks_still_count_boundaries_correctly() {
        // Saturday to Sunday crosses a boundary when weeks start on Sunday,
        // and does not when they start on Monday.
        assert_eq!(
            calendar_weeks_between_with("2023-01-14", "2023-01-15", WeekStart::Sunday),
            Some(1)
        );
        assert_eq!(
            calendar_weeks_between_with("2023-01-14", "2023-01-15", WeekStart::Monday),
            Some(0)
        );
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

    /// Years are counted on the calendar, not by dividing days by 365. A span
    /// containing a leap day is longer than 365 days per year, so dividing
    /// rounds up into a year that has not finished — and every other band of
    /// this function floors.
    #[test]
    fn years_are_calendar_years_and_never_overstate() {
        // 2024 is a leap year: this is 730 days but one year and 364 days.
        assert_eq!(days_between("2023-01-01", "2024-12-31"), Some(730));
        assert_eq!(730 / 365, 2, "the division that used to be applied");
        assert_eq!(
            describe_interval("2023-01-01", "2024-12-31").unwrap(),
            "1 year after"
        );
        // A full two years reads as two.
        assert_eq!(
            describe_interval("2023-01-01", "2025-01-01").unwrap(),
            "2 years after"
        );
        assert_eq!(
            describe_interval("2025-01-01", "2023-01-01").unwrap(),
            "2 years before"
        );
    }

    #[test]
    fn describe_interval_honours_the_week_start_convention() {
        // The weeks band phrases a boundary count, and that count is locale
        // data. 2023-01-15 is a Sunday: under ISO it closes the week that
        // began Jan 9, under a Sunday-first locale it opens its own — so the
        // gap to Feb 1 spans one more boundary under ISO.
        let (sun, wed) = ("2023-01-15", "2023-02-01");
        assert_eq!(
            describe_interval_with(sun, wed, WeekStart::Monday).unwrap(),
            "3 weeks after"
        );
        assert_eq!(
            describe_interval_with(sun, wed, WeekStart::Sunday).unwrap(),
            "2 weeks after"
        );
        // The default stays ISO, unchanged for existing callers.
        assert_eq!(describe_interval(sun, wed).unwrap(), "3 weeks after");
    }

    #[test]
    fn describe_interval_refuses_garbage() {
        assert!(describe_interval("nope", "2023-05-03").is_none());
    }
}
