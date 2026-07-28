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
//!   words are English only, so a non-English drawer yields no mentions
//!   unless `Locale::ARABIC` is asked for.
//! * **Ambiguous numeric dates resolve by convention, not by evidence.**
//!   `05/07/2023` is 5 July or 7 May and the token does not say. Four signals
//!   are consulted in order: a `date_order` declared on `Locale`; an
//!   unambiguous date elsewhere in the same text, which is the writer stating
//!   their convention by example; the language, where it implies one (CLDR
//!   gives `ar` as `d/M/y` in every Arabic territory, while English splits
//!   US/Commonwealth and implies nothing); and failing all three, day-first.
//!   The last is a reading asserted where the text is silent — a US corpus
//!   that never declares `MonthFirst` reads `07/05` as 7 May — taken because a
//!   date the reader can see and correct beats one they cannot use.
//! * **A month NAME joined by hyphens is not read at all.** `-` is a token
//!   character, which is what makes `2023-05-07` a single token — so
//!   `٢٠٢٣-أيار-٠٧` arrives as ONE token carrying a month name: the numeric
//!   readers decline it for not being all digits, and the month-name arm
//!   never sees `أيار` alone. Isolated against both variables — separator and
//!   field order — the separator is what does it, and it does it in **both**
//!   languages:
//!
//!   ```text
//!   ٧ أيار ٢٠٢٣     -> 2023-05-07      07-May-2023 -> nothing
//!   ٠٧-أيار-٢٠٢٣    -> nothing         2023-May-07 -> nothing
//!   ```
//!
//!   Closing it means splitting a mixed token, which is a tokenizer change
//!   and moves every offset in both scanners.
//! * **A month name written year-first strands its numbers.** Separate and
//!   milder than the hyphen case, and found by isolating it: with spaces,
//!   `٢٠٢٣ أيار ٠٧` records `أيار` as a bare month and leaves it
//!   **unresolved** rather than yielding nothing. The month-name arm looks
//!   for the day before the name and the year after — the shape
//!   `٧ أيار ٢٠٢٣` has — so a year-first ordering is seen but not assembled.
//!   Visible to a caller as an unresolved mention, which is the honest
//!   failure, but it is a failure.
//! * **Non-Gregorian calendars are declared, not detected.** `Locale` carries
//!   a [`Calendar`]; Buddhist, Minguo, Hijri (Umm al-Qura) and Jalali all
//!   convert. Nothing is inferred from the text: script is not evidence
//!   (Thai script writes Gregorian constantly) and neither is the numeral
//!   system (`๒๐๒๖` is an ordinary Gregorian 2026 in Thai digits, and reading
//!   the glyphs as an era claim resolved it to 1483). An undeclared corpus
//!   reads years as written, so a Thai date reads 543 years high until someone
//!   says the calendar — visible and correctable, where a dropped date is
//!   neither.
//! * **Era markers written in the text are not read yet** — `พ.ศ.`, `ค.ศ.`,
//!   `هـ`, `م`, 令和, 民國. These would outrank a declared calendar, being the
//!   writer's own statement about a specific date rather than the caller's
//!   about a corpus. Attached forms (`1447هـ`, `令和7年`, `2568พ.ศ.`) arrive as
//!   ONE token because `tokens` keeps alphanumerics together, so reading them
//!   needs the same tokenizer split as the hyphen-joined month name above.
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
/// Japan and Israel count from Sunday. Egypt, Saudi Arabia, the UAE and
/// neighbours count from **Saturday**, because Friday is the holy day. None of
/// those readers is wrong, so the convention is a parameter rather than a
/// hardcoded assumption. CLDR is the authority every platform reads for this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WeekStart {
    #[default]
    Monday,
    Sunday,
    Saturday,
}

impl WeekStart {
    /// Days to subtract from `d` to reach the start of its week.
    fn back_from(self, d: Date) -> i64 {
        let from_monday = d.weekday().number_days_from_monday() as i64;
        match self {
            WeekStart::Monday => from_monday,
            // Sunday is one day before Monday, Saturday two, so shift the
            // cycle by that much and wrap.
            WeekStart::Sunday => (from_monday + 1) % 7,
            WeekStart::Saturday => (from_monday + 2) % 7,
        }
    }
}

/// Which language's temporal vocabulary and grammar to read, together with
/// the week convention that goes with it.
///
/// Bundled rather than passed separately because they travel together: a
/// caller reading Arabic almost always wants Saturday weeks, and getting one
/// right while leaving the other at a European default produces answers that
/// are subtly wrong rather than obviously wrong.
///
/// The language is **configured, not detected.** Detection would have to
/// guess, and guessing costs more than it saves: matching every language's
/// vocabulary at once makes French *mars* collide with English *Mars* and
/// English *may* with a month in four languages. A caller knows its corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Locale {
    pub language: Language,
    pub week_start: WeekStart,
    /// Which field a bare numeric date puts first. `07/05/2023` is 7 May or
    /// 5 July depending on the writer's convention, and no amount of reading
    /// the text settles it — so it is declared, exactly as `week_start` is.
    pub date_order: DateOrder,
    /// Which calendar counted the years. Declared, never inferred: `2566` may
    /// be Buddhist Era 2566 or the Gregorian year 2566 in a novel.
    pub calendar: Calendar,
}

/// Which field a numeric date puts first.
///
/// This cannot be derived from `language`: US English is month-first, British
/// and Commonwealth English is day-first, and both are `Language::English`.
/// The same is true of `week_start`, which is why that is already its own
/// field rather than a property of the language.
///
/// `Undeclared` means the caller did not say, not that the engine gives up. It
/// falls through to what the text demonstrates about itself, and failing that
/// to **day-first** — `d/M/y` is the majority convention worldwide and CLDR's
/// most common pattern, so it is the reading most likely to be right when
/// nothing else is known.
///
/// The cost is explicit: a US corpus that never declares `MonthFirst` reads
/// `07/05` as 7 May. That is a real error for those users, taken deliberately
/// because a resolved date they can see and correct beats an unresolved one
/// they cannot use — and because an unambiguous date anywhere in the same
/// drawer overrides the default before it ever applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DateOrder {
    #[default]
    Undeclared,
    /// `d/M/y` — most of the world, per CLDR.
    DayFirst,
    /// `M/d/y` — the United States.
    MonthFirst,
}

/// Which calendar counted a year.
///
/// Declared by the caller at read time, never inferred from the text. Script
/// is not evidence — Thai script writes Gregorian dates constantly — and the
/// numeral system is not evidence either: `๒๐๒๖` is an ordinary Gregorian 2026
/// typed in Thai digits, and treating the glyphs as an era claim resolved it
/// to 1483.
///
/// Only the calendars whose conversion is exact arithmetic are here. A
/// renumbered year is all Buddhist and Minguo are: same months, same lengths,
/// same leap rule, a different count. Hijri is lunar and drifts about eleven
/// days a year, and Jalali turns at the vernal equinox with different month
/// lengths — neither is reachable by subtracting a constant, so neither is
/// offered rather than being offered wrongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Calendar {
    /// Read years as written.
    #[default]
    Gregorian,
    /// Thai solar Buddhist Era: `y - 543`. Constant from 1941, when Thailand
    /// moved new year to 1 January; January-to-March dates before that carry
    /// 542, which matters for a historical corpus and not for a memory.
    Buddhist,
    /// Republic of China / Taiwan: `y + 1911`.
    Minguo,
    /// Islamic Hijri, Umm al-Qura — the Saudi CIVIL calendar, the one printed
    /// on documents. Lunar: a year is about eleven days shorter than a solar
    /// one, so no offset reaches it and the whole date must be converted.
    /// Deliberately this variant and not the tabular one, which is the easy
    /// implementation and diverges from what real documents say.
    Hijri,
    /// Solar Hijri / Jalali, as used in Iran and Afghanistan. Solar, but the
    /// year turns at the vernal equinox and the month lengths differ, so again
    /// the whole date converts rather than the year shifting.
    Jalali,
}

/// A day number from `calendrical_calculations` as a `time::Date`.
///
/// `RataDie` counts days from 1 January 1 CE, so the bridge is one known
/// anchor and no magic constant: RataDie 1 IS that day.
fn date_from_rata_die(rd: calendrical_calculations::rata_die::RataDie) -> Option<Date> {
    let epoch = Date::from_calendar_date(1, Month::January, 1)
        .ok()?
        .to_julian_day();
    let jd = i32::try_from(rd.to_i64_date().checked_sub(1)?)
        .ok()?
        .checked_add(epoch)?;
    Date::from_julian_day(jd).ok()
}

impl Calendar {
    /// The Gregorian date that `(y, m, d)` names in this calendar.
    ///
    /// A whole date, not a year: Buddhist and Minguo only renumber the year and
    /// could have been an offset, but Hijri and Jalali have different month
    /// lengths, so converting the year and keeping the Gregorian month would
    /// produce a date neither calendar contains.
    fn to_gregorian(self, y: i32, m: u8, d: u8) -> Option<Date> {
        use calendrical_calculations::{islamic, persian};
        let shifted = |y: i32| Date::from_calendar_date(y, Month::try_from(m).ok()?, d).ok();
        let date = match self {
            Calendar::Gregorian => shifted(y)?,
            Calendar::Buddhist => shifted(y.checked_sub(543)?)?,
            Calendar::Minguo => shifted(y.checked_add(1911)?)?,
            Calendar::Hijri => {
                if !(1..=12).contains(&m) || !(1..=30).contains(&d) {
                    return None;
                }
                date_from_rata_die(islamic::fixed_from_saudi_islamic(y, m, d))?
            }
            Calendar::Jalali => {
                if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
                    return None;
                }
                date_from_rata_die(persian::fixed_from_fast_persian(y, m, d))?
            }
        };
        // A date is a date. `time::Date` spans +/-9999 and a memory may hold
        // a year in a novel, an astronomy note or a century-scale plan, so the
        // only bound here is what the type can represent.
        (1..=9999).contains(&date.year()).then_some(date)
    }
}

/// Read `(y, m, d)` in the declared calendar, with the module's three answers:
/// resolved, recorded-but-undecided, or not a date.
fn read_date(cal: Calendar, y: i32, m: u8, d: u8) -> Option<Option<Date>> {
    // A DECLARED calendar numbers its own years, and the four-digit test is a
    // Gregorian assumption: Minguo 114 is 2025 in three digits and Japanese era
    // years are one or two. Bound those only by the converted result, which
    // `to_gregorian` checks. This regressed once when the Gregorian horizon was
    // retired and the guard was left in front of every calendar.
    if cal == Calendar::Gregorian {
        if !(1000..=9999).contains(&y) {
            return None; // a two-digit year names no century; this does not guess one
        }
    } else if y < 1 {
        return None;
    }
    Some(cal.to_gregorian(y, m, d))
}

/// Languages whose temporal expressions this module can read.
///
/// Adding one is not a table swap. English puts the marker *after* the count
/// ("three days ago") where Arabic puts it before ("قبل ثلاثة أيام"), and
/// Arabic has a dual number — يومين is "two days" as one inflected word, not
/// a numeral beside a plural. Grammar per language, not vocabulary per
/// language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    #[default]
    English,
    Arabic,
}

impl Locale {
    pub const ENGLISH: Locale = Locale {
        language: Language::English,
        week_start: WeekStart::Monday,
        date_order: DateOrder::Undeclared,
        calendar: Calendar::Gregorian,
    };
    /// Arabic with Saturday weeks and day-first dates — the conventions
    /// across most of the region.
    ///
    /// `date_order` is `DayFirst` here and `Undeclared` for English, and the
    /// asymmetry is a fact rather than a preference: CLDR gives `ar` as
    /// `d/M/y` in every Arabic territory, so day-first follows from the
    /// language. English splits — US month-first, Commonwealth day-first, both
    /// `Language::English` — so nothing follows from it and the caller has to
    /// say. Defaulting English either way would resolve half the world's dates
    /// wrong instead of recording them.
    pub const ARABIC: Locale = Locale {
        language: Language::Arabic,
        week_start: WeekStart::Saturday,
        date_order: DateOrder::DayFirst,
        calendar: Calendar::Gregorian,
    };

    pub fn with_week_start(self, week_start: WeekStart) -> Self {
        Self { week_start, ..self }
    }

    pub fn with_date_order(self, date_order: DateOrder) -> Self {
        Self { date_order, ..self }
    }

    pub fn with_calendar(self, calendar: Calendar) -> Self {
        Self { calendar, ..self }
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
fn iso_token(tok: &str, cal: Calendar) -> Option<Option<Date>> {
    let t = tok.replace('/', "-");
    let mut it = t.split('-');
    let y: i32 = ascii_digits(it.next()?)?.parse().ok()?;
    let m: u8 = ascii_digits(it.next()?)?.parse().ok()?;
    let d: u8 = ascii_digits(it.next()?)?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    read_date(cal, y, m, d)
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

// --- Arabic ---------------------------------------------------------------
//
// Sources for the vocabulary below: the two Gregorian month-name systems in
// Arabic are the Levantine/Mashriqi set inherited from the Aramaic Babylonian
// calendar (Iraq, Syria, Jordan, Lebanon, Palestine) and the Latin-derived set
// used in Egypt, Sudan and the Gulf. Both are current, neither is a dialect of
// the other, and a corpus can mix them — so both are matched.

/// Arabic-Indic (U+0660..U+0669, ٠-٩) and Extended Arabic-Indic
/// (U+06F0..U+06F9, ۰-۹, used for Persian and Urdu) digits rewritten as ASCII.
///
/// Returns `None` unless every character is a digit in one of the three sets,
/// so this never half-converts a mixed token. Without it `"٣ أيام"` is
/// invisible: `str::parse` accepts ASCII only, so a perfectly ordinary Arabic
/// count silently fails to be a count.
/// The field order a text demonstrates about itself.
///
/// A numeric date whose day exceeds twelve can only be read one way, and that
/// reading is the writer's convention stated by example. `13/05/2023` is
/// day-first because 13 is not a month; a drawer containing it tells us how to
/// read `07/05/2023` two sentences later.
///
/// This is EVIDENCE, not inference. Nothing is assumed about the writer's
/// region, script or software — an instance they wrote is read, in the same
/// text, where only one parse exists. It is the same class of signal as
/// `month_name_is_deliberate` using capitalisation, and it fails closed: a
/// text with no unambiguous date yields nothing and the ambiguous ones stay
/// recorded-and-unresolved.
///
/// Contradictory evidence yields nothing rather than a majority vote. A drawer
/// holding both `13/05/2023` and `05/13/2023` was written by someone
/// inconsistent or is quoting two sources, and guessing which convention won
/// is exactly what this module does not do.
fn order_demonstrated_by(text: &str) -> DateOrder {
    let (mut day_first, mut month_first) = (false, false);
    for (_, w) in tokens(text) {
        let norm = w.replace(['/', '.'], "-");
        let parts: Vec<&str> = norm.split('-').collect();
        if parts.len() != 3 {
            continue;
        }
        let read = |p: &str| -> Option<u8> { ascii_digits(p)?.parse().ok() };
        let (Some(a), Some(b)) = (read(parts[0]), read(parts[1])) else {
            continue;
        };
        // Only a field that cannot be a month is evidence.
        if a > 12 && (1..=31).contains(&a) && (1..=12).contains(&b) {
            day_first = true;
        } else if b > 12 && (1..=31).contains(&b) && (1..=12).contains(&a) {
            month_first = true;
        }
    }
    match (day_first, month_first) {
        (true, false) => DateOrder::DayFirst,
        (false, true) => DateOrder::MonthFirst,
        // None, or both — say nothing.
        _ => DateOrder::Undeclared,
    }
}

/// A token's digits rewritten as ASCII, or `None` if it is not all digits.
///
/// The digit system is a NUMERAL SYSTEM and nothing more. An earlier version of
/// this carried an "era offset" keyed on the Thai block, on the reasoning that
/// Thai numerals mean the Buddhist Era — and `๒๐๒๖`, which is simply how a Thai
/// writer types the Gregorian year 2026, resolved to 1483. Which calendar
/// counted a year is declared on [`Locale`], never read off the glyphs.
///
/// Every entry was checked for the ten-code-point property AND for what follows
/// the run, so a neighbouring non-digit cannot be admitted: U+0660 is followed
/// by U+066A, U+0966 by U+0970, U+0E50 by U+0E5A. Ethiopic is deliberately
/// absent — U+1369 is ONE, not zero, and the system is not positional. CJK
/// ideographic and Roman numerals likewise.
fn ascii_digits(tok: &str) -> Option<String> {
    const DIGIT_ZEROS: [u32; 7] = [
        '0' as u32, 0x0660, // Arabic-Indic
        0x06F0, // Extended Arabic-Indic (Persian, Urdu)
        0x0966, // Devanagari
        0x09E6, // Bengali
        0x0E50, // Thai
        0xFF10, // Fullwidth
    ];
    let mut out = String::with_capacity(tok.len());
    for c in tok.chars() {
        let cp = c as u32;
        let n = DIGIT_ZEROS
            .iter()
            .find_map(|&zero| cp.checked_sub(zero).filter(|n| *n < 10))?;
        out.push(char::from(b'0' + n as u8));
    }
    (!out.is_empty()).then_some(out)
}

/// A calendar unit named by a relative expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    Day,
    Week,
    Month,
    Year,
}

/// Levantine / Mashriqi month names, from the Aramaic Babylonian calendar.
const AR_MONTHS_LEVANT: [(&str, Month); 12] = [
    ("كانون الثاني", Month::January),
    ("شباط", Month::February),
    ("آذار", Month::March),
    ("نيسان", Month::April),
    ("أيار", Month::May),
    ("حزيران", Month::June),
    ("تموز", Month::July),
    ("آب", Month::August),
    ("أيلول", Month::September),
    ("تشرين الأول", Month::October),
    ("تشرين الثاني", Month::November),
    ("كانون الأول", Month::December),
];

/// Latin-derived month names, standard in Egypt, Sudan and the Gulf.
const AR_MONTHS_ROMAN: [(&str, Month); 12] = [
    ("يناير", Month::January),
    ("فبراير", Month::February),
    ("مارس", Month::March),
    ("أبريل", Month::April),
    ("مايو", Month::May),
    ("يونيو", Month::June),
    ("يوليو", Month::July),
    ("أغسطس", Month::August),
    ("سبتمبر", Month::September),
    ("أكتوبر", Month::October),
    ("نوفمبر", Month::November),
    ("ديسمبر", Month::December),
];

const AR_WEEKDAYS: [(&str, Weekday); 7] = [
    ("الاثنين", Weekday::Monday),
    ("الثلاثاء", Weekday::Tuesday),
    ("الأربعاء", Weekday::Wednesday),
    ("الخميس", Weekday::Thursday),
    ("الجمعة", Weekday::Friday),
    ("السبت", Weekday::Saturday),
    ("الأحد", Weekday::Sunday),
];

/// Counting words three to ten, in both genders. Arabic numerals agree in
/// gender with the counted noun *inversely*, so both forms appear in ordinary
/// text and both have to be read: ثلاثة أيام but ثلاث سنوات.
const AR_NUMBERS: [(&str, i64); 18] = [
    ("ثلاثة", 3),
    ("ثلاث", 3),
    ("أربعة", 4),
    ("أربع", 4),
    ("خمسة", 5),
    ("خمس", 5),
    ("ستة", 6),
    ("ست", 6),
    ("سبعة", 7),
    ("سبع", 7),
    ("ثمانية", 8),
    ("ثماني", 8),
    ("تسعة", 9),
    ("تسع", 9),
    ("عشرة", 10),
    ("عشر", 10),
    ("واحد", 1),
    ("واحدة", 1),
];

/// Singular and plural unit nouns. `شهور` and `أشهر` are both plurals of
/// شهر; `سنة` and `عام` are separate words for the same year.
const AR_UNITS: [(&str, Unit); 16] = [
    ("يوم", Unit::Day),
    ("أيام", Unit::Day),
    ("يوما", Unit::Day),
    ("أسبوع", Unit::Week),
    ("أسابيع", Unit::Week),
    ("أسبوعا", Unit::Week),
    ("شهر", Unit::Month),
    ("أشهر", Unit::Month),
    ("شهور", Unit::Month),
    ("شهرا", Unit::Month),
    ("سنة", Unit::Year),
    ("سنوات", Unit::Year),
    ("سنين", Unit::Year),
    ("عام", Unit::Year),
    ("أعوام", Unit::Year),
    ("عاما", Unit::Year),
];

/// The dual: one inflected word meaning exactly two of something. Not a
/// numeral beside a plural, which is why the count cannot be parsed out of it
/// and the whole word has to be recognised.
const AR_DUALS: [(&str, Unit); 6] = [
    ("يومين", Unit::Day),
    ("أسبوعين", Unit::Week),
    ("شهرين", Unit::Month),
    ("سنتين", Unit::Year),
    ("عامين", Unit::Year),
    ("يومان", Unit::Day),
];

/// A date joined by hyphens or slashes whose middle field is a month NAME —
/// `2023-May-07`, `07-May-2023`, `٢٠٢٣-أيار-٠٧`, `١٣/أيار/٢٠٢٣`.
///
/// These read as nothing at all before this existed, in **both** languages,
/// because `-` is a token character — which is what makes `2023-05-07` a
/// single token — so the whole thing arrives as ONE token carrying a month
/// name: the all-digit readers decline it, and the month-name arms never see
/// the name on its own. A fully specified, unambiguous date produced silence.
///
/// Order is decided the same way `dmy_token` decides it, by what can only be
/// one thing: a four-digit field is the year, and the remaining field is the
/// day. Where both outer fields could be years nothing is returned, since
/// guessing is what this module exists not to do.
fn named_date_token(
    tok: &str,
    month: impl Fn(&str) -> Option<Month>,
    cal: Calendar,
) -> Option<Option<Date>> {
    let parts: Vec<&str> = tok.split(['-', '/']).collect();
    if parts.len() != 3 {
        return None;
    }
    let m = month(parts[1])?;
    // Read both outer fields RAW. The era belongs to the year alone — applying
    // it to whichever field happens to share the numerals turns a day of 13
    // into -530. `iso_token` gets this right by parsing month and day
    // separately; the same discipline has to hold here.
    let outer = |p: &str| -> Option<(i32, i32)> {
        let digits = ascii_digits(p)?;
        Some((digits.parse::<i32>().ok()?, digits.chars().count() as i32))
    };
    let (a, alen) = outer(parts[0])?;
    let (c, clen) = outer(parts[2])?;
    let year_first = alen == 4;
    let year_last = clen == 4;
    // Subtract the era only from the field chosen as the year.
    let (raw_y, d) = match (year_first, year_last) {
        (true, false) => (a, c),
        (false, true) => (c, a),
        // Two four-digit fields, or neither: not decidable, so not decided.
        _ => return None,
    };
    read_date(cal, raw_y, m as u8, u8::try_from(d).ok()?)
}

/// Whether an [`AR_AGO`] marker at byte offset `off` is putting what follows
/// into the past, or is the ordinary preposition it also is.
///
/// قبل, منذ and مند are temporal and nothing else, so they are taken as read.
/// من is different in kind: it is one of the commonest words in the language
/// and its everyday job is partitive or comparative — الخامس من الشهر is "the
/// fifth OF THE MONTH", أكثر من ثلاثة أيام is "more THAN three days". A unit
/// noun follows in both, so "a unit follows" is no evidence at all, and taking
/// it as evidence invents a date out of a sentence that named none. That is
/// the failure this module exists to prevent, and here it fires on ordinary
/// prose rather than on some edge case.
///
/// من is still genuine — من ثلاثة أيام is "three days ago" in several
/// registers — so it is guarded rather than dropped, and the guard asks for
/// **confirming evidence** instead of listing the words that would rule it
/// out. A blocklist of quantifiers, comparatives and ordinals fabricates on
/// the first one nobody thought of; an allowlist fails by staying quiet, and a
/// mention never recorded is a gap where an invented date is a lie. Three
/// things have to hold together:
///
/// * **it opens a clause.** A partitive من always has in front of it the thing
///   it partitions — the ordinal, the comparative, the counted noun. Cheap and
///   under-inclusive on purpose, the same trade `month_name_is_deliberate`
///   makes for English: this misses a mid-sentence كان الاجتماع من ثلاثة أيام;
/// * **a count reaches a unit** — من ثلاثة أيام, من يومين. Never the bare
///   من شهر: "from a month" is not "a month ago", and it is exactly the
///   implied-one reading that قبل شهر deserves which made من الشهر resolve;
/// * **no range marker closes it.** من X إلى Y is the one competing
///   construction with the same clause-initial shape, and it names a span of
///   durations rather than a point in the past.
fn ar_ago_is_temporal(
    text: &str,
    marker: &str,
    off: usize,
    next: &str,
    after: &str,
    third: &str,
) -> bool {
    // The other markers mean nothing but "ago".
    if marker != "من" {
        return true;
    }
    let before = text[..off].trim_end_matches([' ', '\t']);
    // Arabic punctuation closes a clause in an Arabic drawer exactly as its
    // Latin counterpart does in an English one: U+060C ، U+061B ؛ U+061F ؟.
    let opens_clause = before.is_empty()
        || before.ends_with([
            '.', '!', '?', '\n', '\r', ':', ';', ',', '\u{060C}', '\u{061B}', '\u{061F}',
        ]);
    let counted = if ar_dual(next).is_some() {
        !AR_RANGE_TO.contains(&after)
    } else if ar_count(next).is_some() && ar_unit(after).is_some() {
        !AR_RANGE_TO.contains(&third)
    } else {
        false
    };
    opens_clause && counted
}

/// Range markers: من ثلاثة أيام إلى خمسة أيام is a span of durations, not a
/// point in the past. Listed because this is the one other construction that
/// puts a count and a unit directly after a clause-initial من.
const AR_RANGE_TO: [&str; 4] = ["إلى", "الى", "حتى", "لغاية"];

/// Markers that put what follows in the past. They **precede** the count,
/// which is the structural difference from English.
///
/// The first three mean nothing else. The fourth is an ordinary preposition as
/// well, and [`ar_ago_is_temporal`] is what keeps it from turning prose into
/// dates.
const AR_AGO: [&str; 4] = ["قبل", "منذ", "مند", "من"];

/// Modifiers that follow a unit noun: الأسبوع الماضي is "the week the past".
const AR_PAST: [&str; 6] = [
    "الماضي",
    "الماضية",
    "المنصرم",
    "المنصرمة",
    "الفائت",
    "السابق",
];
const AR_NEXT: [&str; 6] = [
    "القادم",
    "القادمة",
    "المقبل",
    "المقبلة",
    "التالي",
    "التالية",
];
const AR_THIS: [&str; 4] = ["هذا", "هذه", "الحالي", "الجاري"];

/// Strip the definite article, which attaches to the noun: الأسبوع is
/// "the week". Only when something remains, so ال alone is untouched.
fn ar_bare(w: &str) -> &str {
    w.strip_prefix("ال").filter(|r| !r.is_empty()).unwrap_or(w)
}

fn ar_unit(w: &str) -> Option<Unit> {
    let b = ar_bare(w);
    AR_UNITS
        .iter()
        .find(|(n, _)| *n == b)
        .map(|(_, u)| *u)
        .or_else(|| AR_DUALS.iter().find(|(n, _)| *n == b).map(|(_, u)| *u))
}

fn ar_dual(w: &str) -> Option<Unit> {
    AR_DUALS
        .iter()
        .find(|(n, _)| *n == ar_bare(w))
        .map(|(_, u)| *u)
}

/// How far a period modifier moves its noun: الماضي back one, القادم forward
/// one, هذا none. `None` when the word is not a modifier at all.
///
/// Kept separate because a unit noun only names a period when one of these
/// follows it. اليوم is both "the day" and "today", and without this check the
/// unit reading claims the token and then finds nothing to do with it — which
/// is exactly how "today" went missing.
fn ar_period_step(w: &str) -> Option<i64> {
    if AR_PAST.contains(&w) {
        Some(-1)
    } else if AR_NEXT.contains(&w) {
        Some(1)
    } else if AR_THIS.contains(&w) {
        Some(0)
    } else {
        None
    }
}

fn ar_count(w: &str) -> Option<i64> {
    if let Some(d) = ascii_digits(w) {
        return d.parse::<i64>().ok().filter(|n| *n > 0);
    }
    AR_NUMBERS
        .iter()
        .find(|(n, _)| *n == ar_bare(w))
        .map(|(_, v)| *v)
}

fn ar_month(w: &str) -> Option<Month> {
    AR_MONTHS_ROMAN
        .iter()
        .chain(AR_MONTHS_LEVANT.iter())
        .find(|(n, _)| *n == w)
        .map(|(_, m)| *m)
}

fn ar_weekday(w: &str) -> Option<Weekday> {
    let with_article = format!("ال{}", ar_bare(w));
    AR_WEEKDAYS
        .iter()
        .find(|(n, _)| *n == w || *n == with_article)
        .map(|(_, d)| *d)
}

/// Shift `a` backwards or forwards by `n` of `unit`, returning the period the
/// expression names. A displaced day stays a day; a named calendar period
/// stays a period.
fn shift_unit(a: Date, unit: Unit, n: i64, ws: WeekStart, period: bool) -> Option<(Date, Date)> {
    match unit {
        Unit::Day => shift_days(a, n).map(point),
        Unit::Week if period => {
            shift_days(week_start_of(a, ws)?, 7 * n).and_then(|d| week_range(d, ws))
        }
        Unit::Week => n.checked_mul(7).and_then(|d| shift_days(a, d)).map(point),
        Unit::Month if period => shift_months(a, n).and_then(month_range),
        Unit::Month => shift_months(a, n).map(point),
        Unit::Year if period => shift_months(a, 12 * n).and_then(year_range),
        Unit::Year => n
            .checked_mul(12)
            .and_then(|m| shift_months(a, m))
            .map(point),
    }
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
fn dmy_token(tok: &str, cal: Calendar, order: DateOrder) -> Option<Option<Date>> {
    let norm = tok.replace(['/', '.'], "-");
    let parts: Vec<&str> = norm.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: i32 = ascii_digits(parts[2])?.parse().ok()?;
    let (a, b): (u8, u8) = (
        ascii_digits(parts[0])?.parse().ok()?,
        ascii_digits(parts[1])?.parse().ok()?,
    );
    // A year with no era declared is recorded unresolved whatever the field
    // order — the order cannot rescue a year we cannot place.
    if matches!(read_date(cal, year, 1, 1), Some(None)) {
        return (1..=31).contains(&a).then_some(None);
    }
    // Read both orders through the DECLARED calendar, so a Hijri or Jalali
    // corpus gets its own month lengths rather than Gregorian ones.
    // `Month::try_from` rejecting anything over twelve is what decides the
    // order when only one reading is a date.
    let day_first = read_date(cal, year, b, a).flatten();
    let month_first = read_date(cal, year, a, b).flatten();
    match (day_first, month_first) {
        (Some(d), None) | (None, Some(d)) => Some(Some(d)),
        // Both readings are real dates. A DECLARED order settles it — the
        // caller has already told us the convention, and refusing to use it
        // discards information they supplied. Undeclared stays recorded and
        // unresolved: `07/05/2023` is 7 May or 5 July and the text does not say.
        (Some(df), Some(mf)) => Some(Some(match order {
            DateOrder::MonthFirst => mf,
            // The scanners never pass `Undeclared` — they resolve it to the
            // demonstrated order or to day-first before calling. Reading it as
            // day-first here keeps a direct caller consistent with them rather
            // than silently refusing.
            DateOrder::DayFirst | DateOrder::Undeclared => df,
        })),
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
    extract_time_mentions_in(text, anchor, Locale::ENGLISH.with_week_start(ws))
}

/// As [`extract_time_mentions`], in a given language and week convention.
///
/// The language selects a scanner, not a table: see [`Language`].
pub fn extract_time_mentions_in(
    text: &str,
    anchor: Option<Date>,
    locale: Locale,
) -> Vec<TimeMention> {
    match locale.language {
        Language::English => scan_english(text, anchor, locale),
        Language::Arabic => scan_arabic(text, anchor, locale),
    }
}

/// Read Arabic temporal expressions.
///
/// A separate scanner rather than the English one with different words,
/// because the grammar differs in three ways that the English patterns cannot
/// express:
///
/// * the past marker **precedes** the count — قبل ثلاثة أيام, not "three days
///   قبل";
/// * the **dual** is one word — قبل يومين is "two days ago" in two tokens, and
///   there is no numeral to read;
/// * a period modifier **follows** its noun — الأسبوع الماضي is "the week the
///   past", the reverse of "last week".
///
/// Tokens are compared in canonical form, so أ written as one code point or as
/// alef plus a combining hamza both match. Offsets stay relative to the
/// original text.
fn scan_arabic(text: &str, anchor: Option<Date>, loc: Locale) -> Vec<TimeMention> {
    let ws = loc.week_start;
    // Precedence: what the caller declared, else what the text demonstrates
    // about itself, else the world's majority convention.
    let order = match loc.date_order {
        DateOrder::Undeclared => match order_demonstrated_by(text) {
            DateOrder::Undeclared => DateOrder::DayFirst,
            demonstrated => demonstrated,
        },
        declared => declared,
    };
    let raw = tokens(text);
    // Compare canonically; report offsets from the untouched text.
    let toks: Vec<(usize, String)> = raw
        .iter()
        .map(|(o, w)| (*o, crate::normalize::match_key(w).into_owned()))
        .collect();
    let mut out: Vec<TimeMention> = Vec::new();
    let mut i = 0usize;

    let span = |from: usize, to_tok: usize| -> String {
        let end = toks
            .get(to_tok)
            .map(|(o, w)| o + w.len())
            .unwrap_or(text.len());
        text[from..end.min(text.len())].to_string()
    };
    let at = |k: usize| -> &str { toks.get(k).map(|(_, w)| w.as_str()).unwrap_or("") };

    while i < toks.len() {
        let (off, ref w) = toks[i];
        let mut consumed = 0usize;
        let mut mention: Option<(TimeKind, Option<(Date, Date)>)> = None;

        // Language-neutral numeric forms first — a date written 2023-05-07 is
        // the same date in any prose around it.
        if let Some(d) = named_date_token(w, ar_month, loc.calendar) {
            mention = Some((TimeKind::Absolute, d.map(point)));
        } else if let Some(d) = iso_token(w, loc.calendar) {
            mention = Some((TimeKind::Absolute, d.map(point)));
        } else if let Some(resolved) = dmy_token(w, loc.calendar, order) {
            mention = Some((TimeKind::Absolute, resolved.map(point)));
        } else if let Some(month) = ar_month(w).or_else(|| {
            // Two-word Levantine names: كانون الثاني, تشرين الأول.
            ar_month(&format!("{w} {}", at(i + 1)))
        }) {
            // Either the bare name matched or the two-word form did.
            let two_word = ar_month(w).is_none();
            let base = if two_word { i + 1 } else { i };
            let year_tok = at(base + 1);
            let year = ascii_digits(year_tok)
                .and_then(|d| d.parse::<i32>().ok())
                .filter(|y| (1000..=9999).contains(y));
            // A day may precede the month: ٧ مايو ٢٠١٩.
            let day_before = (i > 0)
                .then(|| ascii_digits(at(i - 1)))
                .flatten()
                .and_then(|d| d.parse::<u8>().ok())
                .filter(|d| (1..=31).contains(d));
            consumed = (base - i) + usize::from(year.is_some());
            let period = match (day_before, year) {
                (Some(d), Some(y)) => Date::from_calendar_date(y, month, d).ok().map(point),
                // A month and year name the month, not its first morning.
                (None, Some(y)) => Date::from_calendar_date(y, month, 1)
                    .ok()
                    .and_then(month_range),
                _ => None,
            };
            if let (Some(d), true) = (day_before, period.is_some()) {
                // Absorb the preceding day into the recorded span.
                let _ = d;
                let start = raw[i - 1].0;
                out.push(TimeMention {
                    text: span(start, i + consumed),
                    kind: TimeKind::Absolute,
                    resolved: period.map(|(s, _)| fmt(s)),
                    resolved_end: None,
                    offset: start as u32,
                });
                i += consumed + 1;
                continue;
            }
            mention = Some((TimeKind::Absolute, period));
        } else if AR_AGO.contains(&w.as_str())
            && ar_ago_is_temporal(text, w.as_str(), off, at(i + 1), at(i + 2), at(i + 3))
        {
            // قبل / منذ + (dual | count + unit)
            if let Some(unit) = ar_dual(at(i + 1)) {
                consumed = 1;
                mention = Some((
                    TimeKind::Relative,
                    anchor.and_then(|a| shift_unit(a, unit, -2, ws, false)),
                ));
            } else if let (Some(n), Some(unit)) = (ar_count(at(i + 1)), ar_unit(at(i + 2))) {
                consumed = 2;
                mention = Some((
                    TimeKind::Relative,
                    anchor.and_then(|a| shift_unit(a, unit, -n, ws, false)),
                ));
            } else if let Some(unit) = ar_unit(at(i + 1)).filter(|_| {
                // ...but قبل الشهر الماضي is "before LAST month", not "a month
                // ago". The noun belongs to the modifier behind it: taking it
                // here resolves one unit back AND strands الماضي, so when the
                // token after the noun is a modifier, leave the whole phrase to
                // the period branch on the next pass. English already reads
                // "before last month" this way — the period is recorded, the
                // preposition is not.
                ar_period_step(at(i + 2)).is_none()
            }) {
                // قبل شهر — "a month ago", the count implied as one.
                consumed = 1;
                mention = Some((
                    TimeKind::Relative,
                    anchor.and_then(|a| shift_unit(a, unit, -1, ws, false)),
                ));
            }
        } else if AR_THIS.contains(&w.as_str()) {
            // هذا الأسبوع — the marker precedes here.
            if let Some(unit) = ar_unit(at(i + 1)) {
                consumed = 1;
                mention = Some((
                    TimeKind::Relative,
                    anchor.and_then(|a| shift_unit(a, unit, 0, ws, true)),
                ));
            }
        } else if let Some((unit, step)) =
            // الأسبوع الماضي / الشهر القادم — the modifier follows the noun,
            // and a unit only names a period when one actually does. Requiring
            // it here is what leaves اليوم free to mean "today" below.
            ar_unit(w).and_then(|u| ar_period_step(at(i + 1)).map(|s| (u, s)))
        {
            consumed = 1;
            mention = Some((
                TimeKind::Relative,
                anchor.and_then(|a| shift_unit(a, unit, step, ws, true)),
            ));
        } else if let Some((wd, step)) =
            // السبت الماضي / الخميس القادم — a named day, so a point.
            ar_weekday(w).and_then(|d| ar_period_step(at(i + 1)).map(|s| (d, s)))
        {
            consumed = 1;
            let resolved = anchor.and_then(|a| match step {
                -1 => previous_weekday(a, wd),
                0 => weekday_in_week(a, wd, ws),
                _ => next_weekday(a, wd),
            });
            mention = Some((TimeKind::Relative, resolved.map(point)));
        } else {
            let days = match w.as_str() {
                "أمس" | "امس" | "البارحة" | "امبارح" | "مبارح" => Some(-1),
                "اليوم" => Some(0),
                "غدا" | "غدًا" | "الغد" | "بكرة" | "بكره" => Some(1),
                _ => None,
            };
            if let Some(d) = days {
                mention = Some((
                    TimeKind::Relative,
                    anchor.and_then(|a| shift_days(a, d)).map(point),
                ));
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

fn scan_english(text: &str, anchor: Option<Date>, loc: Locale) -> Vec<TimeMention> {
    let ws = loc.week_start;
    // Precedence: what the caller declared, else what the text demonstrates
    // about itself, else the world's majority convention.
    let order = match loc.date_order {
        DateOrder::Undeclared => match order_demonstrated_by(text) {
            DateOrder::Undeclared => DateOrder::DayFirst,
            demonstrated => demonstrated,
        },
        declared => declared,
    };
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

        if let Some(d) = named_date_token(w, month_of, loc.calendar) {
            mention = Some((TimeKind::Absolute, d.map(point)));
        } else if let Some(d) = iso_token(w, loc.calendar) {
            mention = Some((TimeKind::Absolute, d.map(point)));
        } else if let Some(resolved) = dmy_token(w, loc.calendar, order) {
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

    // ---- Arabic ----------------------------------------------------------

    /// 2023-05-08 is a Monday. Under Saturday-first weeks — the convention
    /// across Egypt, Saudi Arabia and the UAE — its week runs Sat 6 to Fri 12.
    fn ar(text: &str) -> Vec<TimeMention> {
        extract_time_mentions_in(text, parse_anchor("2023-05-08"), Locale::ARABIC)
    }

    /// `من` is one of the commonest words in Arabic and its everyday job is
    /// partitive or comparative. Taking a following unit as evidence that it
    /// means "ago" invented dates out of sentences that named none — the
    /// failure this module exists to prevent, firing on ordinary prose.
    ///
    /// Every row asserts `len()` explicitly: `all(is_none())` is vacuously
    /// true on an empty vector, so without the count a row proves nothing.
    /// And the last block is what separates GUARDING `من` from DELETING it —
    /// with the word simply removed from `AR_AGO` those reads would go silent
    /// too, and this test would pass over a different, worse fix.
    #[test]
    fn min_reads_as_ago_only_where_the_sentence_confirms_it() {
        // Partitive: "the fifth OF THE MONTH" names no elapsed time.
        let m = ar("الخامس من الشهر كان يوم عطلة");
        assert!(
            m.iter()
                .all(|x| x.resolved.as_deref() != Some("2023-04-08")),
            "partitive من fabricated a month-ago date: {:?}",
            m.iter().map(|x| (&x.text, &x.resolved)).collect::<Vec<_>>()
        );

        // Comparative: "more THAN three days" is a quantity, not a date.
        let m = ar("استغرق الأمر أكثر من ثلاثة أيام");
        assert!(
            m.iter()
                .all(|x| x.resolved.as_deref() != Some("2023-05-05")),
            "comparative من fabricated a three-days-ago date: {:?}",
            m.iter().map(|x| (&x.text, &x.resolved)).collect::<Vec<_>>()
        );

        // A bare unit with no count: "from a month" is not "a month ago".
        // This is the implied-one reading قبل شهر deserves and من does not.
        let m = ar("من شهر بدأنا العمل");
        assert!(
            m.iter()
                .all(|x| x.resolved.as_deref() != Some("2023-04-08")),
            "bare من شهر took the implied-one reading: {:?}",
            m.iter().map(|x| (&x.text, &x.resolved)).collect::<Vec<_>>()
        );

        // ...and the reads that must SURVIVE. Without these the test cannot
        // tell a guard from a deletion.
        let m = ar("من ثلاثة أيام وصلت الرسالة");
        assert_eq!(
            m.len(),
            1,
            "clause-initial من + count + unit must read: {m:?}"
        );
        assert_eq!(m[0].resolved.as_deref(), Some("2023-05-05"));
        let m = ar("من يومين وصلت الرسالة");
        assert_eq!(m.len(), 1, "من + dual must read: {m:?}");
        assert_eq!(m[0].resolved.as_deref(), Some("2023-05-06"));

        // The unambiguous markers are untouched by the guard.
        let m = ar("قبل ثلاثة أيام وصلت الرسالة");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].resolved.as_deref(), Some("2023-05-05"));
    }

    /// `قبل الشهر الماضي` is "before LAST month". Taking the noun for the
    /// implied-one reading resolved one unit back AND stranded الماضي.
    #[test]
    fn a_past_marker_does_not_swallow_the_noun_of_a_period_phrase() {
        let m = ar("قبل الشهر الماضي انتهى المشروع");
        assert_eq!(m.len(), 1, "expected the period, got {m:?}");
        assert_eq!(m[0].text, "الشهر الماضي");
        // The unpatched code returned a POINT one month back; the period is
        // what a reader sees, so assert the range rather than the start.
        assert_eq!(m[0].resolved.as_deref(), Some("2023-04-01"));
        assert_eq!(m[0].resolved_end.as_deref(), Some("2023-04-30"));

        // Unmodified nouns keep the implied-one reading.
        let m = ar("قبل شهر انتهى المشروع");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].resolved.as_deref(), Some("2023-04-08"));
    }

    /// A numeric date is a date in any digit system — and the digit system is
    /// what says which era counted the year.
    ///
    /// `iso_token` used `str::parse`, which is ASCII-only, so a date written
    /// in Arabic-Indic numerals was unread *even under* `Language::Arabic` —
    /// the numeric channel was closed to exactly the languages whose
    /// word-forms this module also cannot read.
    #[test]
    fn a_numeric_date_reads_in_any_digit_system() {
        // Arabic-Indic and Persian: Gregorian, no era shift.
        assert_eq!(
            iso_token("٢٠٢٣-٠٥-٠٧", Calendar::Gregorian),
            Some(Date::from_calendar_date(2023, Month::May, 7).ok())
        );
        assert_eq!(
            iso_token("۲۰۲۳-۰۵-۰۷", Calendar::Gregorian),
            Some(Date::from_calendar_date(2023, Month::May, 7).ok())
        );
        // Devanagari and fullwidth.
        assert_eq!(
            iso_token("२०२३-०५-०७", Calendar::Gregorian),
            Some(Date::from_calendar_date(2023, Month::May, 7).ok())
        );
        assert_eq!(
            iso_token("２０２３-０５-０７", Calendar::Gregorian),
            Some(Date::from_calendar_date(2023, Month::May, 7).ok())
        );
        // ASCII is unchanged.
        assert_eq!(
            iso_token("2023-05-07", Calendar::Gregorian),
            Some(Date::from_calendar_date(2023, Month::May, 7).ok())
        );
        // Day-first forms too. 13 cannot be a month, which is what decides
        // the order — so this one resolves.
        assert_eq!(
            dmy_token("١٣/٠٥/٢٠٢٣", Calendar::Gregorian, DateOrder::Undeclared),
            Some(Date::from_calendar_date(2023, Month::May, 13).ok())
        );
        // ٠٧/٠٥ reads as 7 May or 5 July. A direct caller passing `Undeclared`
        // gets day-first, matching what the scanners resolve it to — see
        // `DateOrder`. Declaring `MonthFirst` is how the other reading is had.
        assert_eq!(
            dmy_token("٠٧/٠٥/٢٠٢٣", Calendar::Gregorian, DateOrder::Undeclared),
            Some(Some(Date::from_calendar_date(2023, Month::May, 7).unwrap()))
        );
        assert_eq!(
            dmy_token("٠٧/٠٥/٢٠٢٣", Calendar::Gregorian, DateOrder::MonthFirst),
            Some(Some(
                Date::from_calendar_date(2023, Month::July, 5).unwrap()
            ))
        );
        // `iso_token` reads all-digit tokens only, so a hyphen-joined month
        // NAME is not its business. Recording it here because the scanner as a
        // whole does not read that form either — measured: ٢٠٢٣-أيار-٠٧ yields
        // NOTHING, while ٧ أيار ٢٠٢٣ resolves. `-` is a token character (which
        // is what makes 2023-05-07 one token), so the hyphenated form arrives
        // as a single token carrying a month name and no arm claims it. That
        // is a GAP, listed in the module's Known gaps — not a statement that
        // the form is not a date.
        assert_eq!(iso_token("٢٠٢٣-أيار-٠٧", Calendar::Gregorian), None);
        assert!(
            extract_time_mentions_in("٧ أيار ٢٠٢٣", parse_anchor("2023-05-08"), Locale::ARABIC)
                .iter()
                .any(|m| m.resolved.as_deref() == Some("2023-05-07")),
            "the space-separated month-name form must still read"
        );
    }

    /// A far-future year resolves as written. A memory holds the dates in
    /// someone's fiction, an astronomy note or a century-scale plan.
    ///
    /// This bound was 2199 for a while, to stop Thai Buddhist Era 2566 reading
    /// as the Gregorian year 2566 — the right defence when nothing could tell
    /// the engine which calendar counted a year. Once [`Calendar`] became a
    /// declaration it started causing the harm it was built to prevent, so it
    /// is gone: an undeclared corpus reads years as written, and a Thai corpus
    /// says so and converts.
    #[test]
    fn a_far_future_year_resolves_as_written() {
        let d = |y, m, day| Date::from_calendar_date(y, m, day).ok();
        // Ordinary dates, unaffected — the thing that must not regress.
        assert_eq!(
            iso_token("2023-05-07", Calendar::Gregorian),
            Some(d(2023, Month::May, 7))
        );
        assert_eq!(
            iso_token("١٩٩٩-١٢-٣١", Calendar::Gregorian),
            Some(d(1999, Month::December, 31))
        );
        // The novelist's date: resolved, not dropped and not shifted.
        assert_eq!(
            iso_token("2566-05-13", Calendar::Gregorian),
            Some(d(2566, Month::May, 13))
        );
        assert_eq!(
            iso_token("๒๕๖๖-๐๕-๑๓", Calendar::Gregorian),
            Some(d(2566, Month::May, 13))
        );
        // A Gregorian year in Thai numerals is still not shifted.
        assert_eq!(
            iso_token("๒๐๒๖-๐๕-๐๗", Calendar::Gregorian),
            Some(d(2026, Month::May, 7))
        );
        // Not a date at all is still None — the distinction a caller needs.
        assert_eq!(iso_token("hello-world-now", Calendar::Gregorian), None);
        assert_eq!(
            iso_token("99-05-13", Calendar::Gregorian),
            None,
            "two-digit years unread"
        );
    }

    /// A far-future date reaches the caller resolved, not as a bare mention.
    #[test]
    fn a_far_future_date_reaches_the_caller_resolved() {
        let m = extract_time_mentions(
            "the colony was founded 2566-05-13 exactly",
            parse_anchor("2023-05-08"),
        );
        assert_eq!(m.len(), 1, "the date must be recorded: {m:?}");
        assert_eq!(m[0].text, "2566-05-13", "verbatim, as written");
        assert_eq!(m[0].resolved.as_deref(), Some("2566-05-13"), "and resolved");
    }

    /// Every year reading must agree with every other.
    ///
    /// Three sites gated years at 2199 and three at 9999, so
    /// `iso_token("2566-05-13")` refused while `May 13, 2566` — the same date,
    /// one screen away — resolved. The constant is gone now; what this pins is
    /// the invariant that outlived it, since the readers drifting apart is the
    /// defect, not the particular bound they drifted around.
    #[test]
    fn every_reader_agrees_about_the_same_date() {
        let a = parse_anchor("2023-05-08");
        let want = Some("2566-05-13");
        for text in [
            "2566-05-13",
            "May 13, 2566",
            "13 May 2566",
            "2566-May-13",
            "13/05/2566",
        ] {
            let m = extract_time_mentions(text, a);
            assert_eq!(m.len(), 1, "{text:?} produced {m:?}");
            assert_eq!(
                m[0].resolved.as_deref(),
                want,
                "{text:?} disagreed with the others"
            );
        }
        // ...and in Arabic, through its own month-name arm.
        let m = extract_time_mentions_in("١٣ أيار ٢٥٦٦", a, Locale::ARABIC);
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].resolved.as_deref(), want);
    }

    /// `07/05/2023` is 7 May or 5 July. Four signals can settle it, and the
    /// engine takes them in order of how much they rest on.
    #[test]
    fn the_four_signals_that_settle_a_numeric_date_order() {
        let a = parse_anchor("2023-05-08");
        let one = |text: &str, loc: Locale| -> Option<String> {
            let m = extract_time_mentions_in(text, a, loc);
            assert_eq!(m.len(), 1, "expected one mention in {text:?}: {m:?}");
            m[0].resolved.clone()
        };

        // 1 — DECLARED on the Locale. The caller's assertion, honoured.
        let us = Locale::ENGLISH.with_date_order(DateOrder::MonthFirst);
        let gb = Locale::ENGLISH.with_date_order(DateOrder::DayFirst);
        assert_eq!(one("we met 07/05/2023", us).as_deref(), Some("2023-07-05"));
        assert_eq!(one("we met 07/05/2023", gb).as_deref(), Some("2023-05-07"));

        // 2 — IMPLIED BY LANGUAGE. CLDR gives `ar` as d/M/y in every Arabic
        // territory, so day-first follows from the language rather than from a
        // preference. English splits US/Commonwealth and cannot imply either.
        assert_eq!(
            one("التقينا ٠٧/٠٥/٢٠٢٣", Locale::ARABIC).as_deref(),
            Some("2023-05-07")
        );

        // 3 — DEMONSTRATED BY THE TEXT. 13 cannot be a month, so the writer
        // has stated their convention by example, in this drawer.
        assert_eq!(
            one("first 13/05/2023", Locale::ENGLISH).as_deref(),
            Some("2023-05-13"),
            "an unambiguous date resolves on its own"
        );
        let m = extract_time_mentions_in("met 13/05/2023 and again 07/05/2023", a, Locale::ENGLISH);
        assert_eq!(m.len(), 2, "{m:?}");
        assert_eq!(
            m[1].resolved.as_deref(),
            Some("2023-05-07"),
            "carried by the writer's own example"
        );
        // ...and the same text with month-first evidence reads the other way.
        let m = extract_time_mentions_in("met 05/13/2023 and again 07/05/2023", a, Locale::ENGLISH);
        assert_eq!(m.len(), 2, "{m:?}");
        assert_eq!(m[1].resolved.as_deref(), Some("2023-07-05"));

        // 4 — THE MAJORITY CONVENTION. Nothing declared, nothing demonstrated:
        // day-first, because `d/M/y` is what most of the world writes.
        assert_eq!(
            one("we met 07/05/2023", Locale::ENGLISH).as_deref(),
            Some("2023-05-07")
        );
        // The cost of that default, pinned so it is visible in the suite and
        // not only in a comment: a US corpus reads 7 May unless it declares.
        // Layer 2 rescues any drawer containing one unambiguous date.
        assert_eq!(
            one("we met 07/05/2023", us).as_deref(),
            Some("2023-07-05"),
            "declaring MonthFirst is how a US corpus corrects it"
        );

        // Contradictory evidence says nothing rather than voting. A drawer
        // holding both orders was written inconsistently or quotes two sources.
        assert_eq!(
            order_demonstrated_by("13/05/2023 and 05/13/2023"),
            DateOrder::Undeclared
        );
        assert_eq!(order_demonstrated_by("13/05/2023"), DateOrder::DayFirst);
        assert_eq!(order_demonstrated_by("05/13/2023"), DateOrder::MonthFirst);
        assert_eq!(order_demonstrated_by("07/05/2023"), DateOrder::Undeclared);
    }

    /// A declared calendar resolves an era the text cannot settle — and is
    /// honoured even where the raw year would have read as Gregorian, because
    /// it is the caller's assertion about their own corpus, not an inference.
    #[test]
    fn a_declared_calendar_resolves_the_era() {
        let a = parse_anchor("2023-05-08");
        let th = Locale::ENGLISH.with_calendar(Calendar::Buddhist);
        let tw = Locale::ENGLISH.with_calendar(Calendar::Minguo);

        assert_eq!(
            iso_token("2566-05-13", Calendar::Buddhist),
            Some(Date::from_calendar_date(2023, Month::May, 13).ok())
        );
        assert_eq!(
            iso_token("0114-01-01", Calendar::Minguo),
            Some(Date::from_calendar_date(2025, Month::January, 1).ok())
        );
        // The declaration applies to every year, including ones that would
        // have read as Gregorian. The caller said Buddhist; that is the answer.
        assert_eq!(
            iso_token("2026-05-07", Calendar::Buddhist),
            Some(Date::from_calendar_date(1483, Month::May, 7).ok())
        );
        // Without a declaration the year reads as written — 2566 CE, which is
        // right for a novel and 543 years high for an undeclared Thai corpus.
        // Visible and correctable either way; the declaration is the fix.
        assert_eq!(
            iso_token("2566-05-13", Calendar::Gregorian),
            Some(Date::from_calendar_date(2566, Month::May, 13).ok())
        );

        let m = extract_time_mentions_in("founded 2566-05-13", a, th);
        assert_eq!(m[0].resolved.as_deref(), Some("2023-05-13"));
        let m = extract_time_mentions_in("founded 0114-01-01", a, tw);
        assert_eq!(m[0].resolved.as_deref(), Some("2025-01-01"));
    }

    /// Hijri and Jalali are not renumbered Gregorian years, so they convert as
    /// whole dates through `calendrical_calculations` rather than by an offset.
    ///
    /// Nowruz is the load-bearing assertion. Jalali year 1 begins at the vernal
    /// equinox, so `1404-01-01` must land on 20 or 21 March 2025 — an error in
    /// the equinox anchor shows up here immediately, where a mid-year date
    /// would absorb an off-by-one silently.
    #[test]
    fn the_calendars_that_need_real_calendar_math() {
        // --- Jalali / Solar Hijri: Nowruz 1404.
        let nowruz = iso_token("1404-01-01", Calendar::Jalali)
            .flatten()
            .expect("Jalali 1404-01-01 must convert");
        assert_eq!(nowruz.year(), 2025, "Nowruz 1404 falls in 2025: {nowruz}");
        assert_eq!(
            nowruz.month(),
            Month::March,
            "at the vernal equinox: {nowruz}"
        );
        assert!(
            (20..=21).contains(&nowruz.day()),
            "Nowruz is 20 or 21 March, got {nowruz}"
        );
        // A month beyond twelve is not a Jalali date.
        assert_eq!(iso_token("1404-13-01", Calendar::Jalali), Some(None));

        // --- Hijri, Umm al-Qura (the Saudi CIVIL calendar, not the tabular
        // approximation, which is the easy implementation and diverges from
        // what real documents say).
        let hijri = iso_token("1447-01-01", Calendar::Hijri)
            .flatten()
            .expect("Hijri 1447-01-01 must convert");
        // 1 Muharram 1447 falls in mid-2025. A lunar year is ~11 days shorter
        // than a solar one, so no constant offset reaches this — which is the
        // whole reason the conversion is delegated.
        assert_eq!(hijri.year(), 2025, "got {hijri}");
        // A lunar month never exceeds 30 days.
        assert_eq!(iso_token("1447-01-31", Calendar::Hijri), Some(None));
        assert_eq!(iso_token("1447-13-01", Calendar::Hijri), Some(None));

        // Both are reachable end to end through a declared Locale.
        let fa = Locale::ENGLISH.with_calendar(Calendar::Jalali);
        let m = extract_time_mentions_in("written 1404-01-01", parse_anchor("2025-03-21"), fa);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(m[0]
            .resolved
            .as_deref()
            .is_some_and(|r| r.starts_with("2025-03-2")));

        // And the arithmetic calendars still take the cheap path — no
        // dependency is consulted for a renumbered year.
        assert_eq!(
            iso_token("2566-05-13", Calendar::Buddhist),
            Some(Date::from_calendar_date(2023, Month::May, 13).ok())
        );
        assert_eq!(
            iso_token("0114-01-01", Calendar::Minguo),
            Some(Date::from_calendar_date(2025, Month::January, 1).ok())
        );
    }

    #[test]
    fn arabic_indic_digits_are_digits() {
        assert_eq!(ascii_digits("٣").as_deref(), Some("3"));
        assert_eq!(ascii_digits("٢٠٢٣").as_deref(), Some("2023"));
        // Extended Arabic-Indic, used for Persian and Urdu.
        assert_eq!(ascii_digits("۱۴۴۵").as_deref(), Some("1445"));
        assert_eq!(ascii_digits("2023").as_deref(), Some("2023"));
        // Never half-converts a mixed token.
        assert_eq!(ascii_digits("٣أيام"), None);
        assert_eq!(ascii_digits("أيام"), None);
        assert_eq!(ascii_digits(""), None);
    }

    /// The marker precedes the count, which is the pattern English cannot
    /// express: "قبل ثلاثة أيام" is three days ago.
    #[test]
    fn the_past_marker_precedes_the_count() {
        for text in ["قبل ثلاثة أيام", "منذ ثلاثة أيام", "قبل ٣ أيام"]
        {
            let m = ar(text);
            assert_eq!(m.len(), 1, "{text} -> {m:?}");
            assert_eq!(m[0].resolved.as_deref(), Some("2023-05-05"), "{text}");
        }
    }

    /// Numerals agree in gender inversely with the counted noun, so both
    /// forms occur in ordinary prose and both must read.
    #[test]
    fn both_genders_of_a_numeral_count() {
        assert_eq!(
            ar("قبل ثلاث سنوات")[0].resolved.as_deref(),
            Some("2020-05-08")
        );
        assert_eq!(
            ar("قبل ثلاثة أشهر")[0].resolved.as_deref(),
            Some("2023-02-08")
        );
    }

    /// The dual is one inflected word meaning exactly two — there is no
    /// numeral in "قبل يومين" to parse out.
    #[test]
    fn the_dual_means_two_without_a_numeral() {
        assert_eq!(ar("قبل يومين")[0].resolved.as_deref(), Some("2023-05-06"));
        assert_eq!(ar("قبل أسبوعين")[0].resolved.as_deref(), Some("2023-04-24"));
        assert_eq!(ar("منذ شهرين")[0].resolved.as_deref(), Some("2023-03-08"));
        assert_eq!(ar("قبل سنتين")[0].resolved.as_deref(), Some("2021-05-08"));
        assert_eq!(ar("منذ عامين")[0].resolved.as_deref(), Some("2021-05-08"));
    }

    #[test]
    fn a_bare_unit_after_the_marker_counts_as_one() {
        assert_eq!(ar("قبل شهر")[0].resolved.as_deref(), Some("2023-04-08"));
        assert_eq!(ar("قبل يوم")[0].resolved.as_deref(), Some("2023-05-07"));
    }

    #[test]
    fn relative_days() {
        for (text, want) in [
            ("أمس", "2023-05-07"),
            ("البارحة", "2023-05-07"),
            ("اليوم", "2023-05-08"),
            ("غدا", "2023-05-09"),
            ("الغد", "2023-05-09"),
        ] {
            let m = ar(text);
            assert_eq!(m.len(), 1, "{text} -> {m:?}");
            assert_eq!(m[0].resolved.as_deref(), Some(want), "{text}");
        }
    }

    /// A period modifier follows its noun — الأسبوع الماضي is "the week the
    /// past" — and it names a period, not a day seven back.
    #[test]
    fn the_modifier_follows_the_noun_and_names_a_period() {
        // Saturday-first: the anchor's week is May 6..12, so the one before
        // it is April 29 .. May 5.
        let m = ar("الأسبوع الماضي");
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].range(), Some(("2023-04-29", "2023-05-05")));
        assert!(m[0].is_period());

        assert_eq!(
            ar("الشهر الماضي")[0].range(),
            Some(("2023-04-01", "2023-04-30"))
        );
        assert_eq!(
            ar("السنة الماضية")[0].range(),
            Some(("2022-01-01", "2022-12-31"))
        );
        assert_eq!(
            ar("الشهر القادم")[0].range(),
            Some(("2023-06-01", "2023-06-30"))
        );
    }

    #[test]
    fn this_precedes_its_noun() {
        assert_eq!(
            ar("هذا الأسبوع")[0].range(),
            Some(("2023-05-06", "2023-05-12")),
            "Saturday-first week containing Monday the 8th"
        );
        assert_eq!(
            ar("هذا الشهر")[0].range(),
            Some(("2023-05-01", "2023-05-31"))
        );
    }

    #[test]
    fn week_start_moves_the_arabic_week_too() {
        let iso = extract_time_mentions_in(
            "الأسبوع الماضي",
            parse_anchor("2023-05-08"),
            Locale::ARABIC.with_week_start(WeekStart::Monday),
        );
        // Monday-first: the previous week is May 1..7, not April 29..May 5.
        assert_eq!(iso[0].range(), Some(("2023-05-01", "2023-05-07")));
    }

    /// Both month-name systems are current and a corpus can mix them.
    #[test]
    fn both_month_systems_resolve() {
        // Latin-derived, standard in Egypt and the Gulf.
        assert_eq!(ar("٧ مايو ٢٠١٩")[0].resolved.as_deref(), Some("2019-05-07"));
        // Levantine, from the Aramaic Babylonian calendar — two words.
        assert_eq!(ar("٧ أيار ٢٠١٩")[0].resolved.as_deref(), Some("2019-05-07"));
        assert_eq!(
            ar("٧ كانون الثاني ٢٠٢٠")[0].resolved.as_deref(),
            Some("2020-01-07")
        );
        assert_eq!(
            ar("١٥ تشرين الأول ٢٠٢١")[0].resolved.as_deref(),
            Some("2021-10-15")
        );
    }

    /// A month with a year names the month, exactly as in English.
    #[test]
    fn an_arabic_month_and_year_is_a_period() {
        let m = ar("في مايو ٢٠٢٣");
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].range(), Some(("2023-05-01", "2023-05-31")));
    }

    #[test]
    fn arabic_weekdays_resolve_against_the_anchor() {
        // Anchor Monday 2023-05-08.
        assert_eq!(
            ar("الخميس الماضي")[0].resolved.as_deref(),
            Some("2023-05-04")
        );
        assert_eq!(
            ar("الخميس القادم")[0].resolved.as_deref(),
            Some("2023-05-11")
        );
    }

    /// Canonically equivalent spellings must read the same: أ is one code
    /// point or alef plus a combining hamza.
    #[test]
    fn arabic_reads_either_encoding_of_the_same_word() {
        let composed = ar("الأسبوع الماضي");
        let decomposed = ar("ال\u{0627}\u{0654}سبوع الماضي");
        assert_eq!(composed.len(), 1);
        assert_eq!(decomposed.len(), 1, "{decomposed:?}");
        assert_eq!(composed[0].resolved, decomposed[0].resolved);
    }

    #[test]
    fn arabic_still_reads_iso_dates() {
        assert_eq!(
            ar("اجتمعنا في 2023-05-07")[0].resolved.as_deref(),
            Some("2023-05-07")
        );
    }

    #[test]
    fn arabic_without_an_anchor_records_but_does_not_guess() {
        let m = extract_time_mentions_in("قبل ثلاثة أيام", None, Locale::ARABIC);
        assert_eq!(m.len(), 1);
        assert!(m[0].resolved.is_none(), "no anchor, no date");
    }

    #[test]
    fn ordinary_arabic_prose_yields_nothing() {
        let m = ar("كان الاجتماع مفيدا وناقشنا الخطة");
        assert!(m.is_empty(), "{m:?}");
    }

    /// The English scanner must not have moved, and must not read Arabic.
    #[test]
    fn the_locales_stay_independent() {
        let en = extract_time_mentions("three days ago", parse_anchor("2023-05-08"));
        assert_eq!(en[0].resolved.as_deref(), Some("2023-05-05"));
        let en_on_arabic = extract_time_mentions("قبل ثلاثة أيام", parse_anchor("2023-05-08"));
        assert!(en_on_arabic.is_empty(), "{en_on_arabic:?}");
        assert_eq!(Locale::default(), Locale::ENGLISH);
    }

    #[test]
    fn saturday_weeks_count_boundaries_correctly() {
        // 2023-05-05 is a Friday, 2023-05-06 a Saturday: a boundary under
        // Saturday-first weeks, none under Monday-first.
        assert_eq!(
            calendar_weeks_between_with("2023-05-05", "2023-05-06", WeekStart::Saturday),
            Some(1)
        );
        assert_eq!(
            calendar_weeks_between_with("2023-05-05", "2023-05-06", WeekStart::Monday),
            Some(0)
        );
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
    /// names, so something outside the token has to.
    ///
    /// This test used to assert the opposite — that such a date is recorded and
    /// left unresolved, because "picking one would be a coin flip reported as a
    /// fact". That was a considered position and it is now reversed
    /// deliberately: a memory that returns no date is unusable, and `d/M/y` is
    /// not a coin flip but the majority convention worldwide and CLDR's most
    /// common pattern. It is still a reading asserted where the text is silent,
    /// which is why the two stronger signals come first — a declaration on
    /// `Locale`, and any unambiguous date in the same drawer.
    #[test]
    fn an_ambiguous_numeric_date_takes_the_majority_convention() {
        let m = extract_time_mentions("dated 05/07/2023 exactly", None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].text, "05/07/2023");
        assert_eq!(m[0].kind, TimeKind::Absolute);
        assert_eq!(m[0].resolved.as_deref(), Some("2023-07-05"), "day-first");
        // ...and either stronger signal overrides it.
        let m = extract_time_mentions_in(
            "dated 05/07/2023 exactly",
            None,
            Locale::ENGLISH.with_date_order(DateOrder::MonthFirst),
        );
        assert_eq!(
            m[0].resolved.as_deref(),
            Some("2023-05-07"),
            "declared wins"
        );
        let m = extract_time_mentions("on 05/13/2023 and 05/07/2023", None);
        assert_eq!(
            m[1].resolved.as_deref(),
            Some("2023-05-07"),
            "the writer's own unambiguous date wins"
        );
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
