//! The drawer record — one verbatim chunk filed in the palace.
//!
//! Field names mirror mempalace's drawer metadata (`_build_drawer_metadata`
//! in miner.py) so exported palaces remain recognizable: wing, room,
//! source_file, chunk_index, added_by, filed_at, normalize_version,
//! id_recipe, line_start/line_end, content_date, hall, entities. `occurrences`
//! is ours: dedup collapses identical text, and the days that text appeared on
//! survive the collapse.

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// One time this exact content was recorded.
///
/// The same words written on two different days are two events, not one
/// record and one mistake. Collapsing the text is fine — it is the same text
/// — but the *when* of each appearance is data, and losing it would undo the
/// thing `content_date` exists to establish.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Occurrence {
    /// When the content happened, if the writer knew. Ordered first so a
    /// sort over occurrences is chronological by the date that matters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_date: Option<String>,
    /// When this appearance was filed.
    pub filed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DrawerMeta {
    pub wing: String,
    pub room: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// Position of this chunk within `source_file` — **when there is one.**
    ///
    /// A save that arrives through an API has no source to be the fourth
    /// chunk of, but its id still has to be unique, and this is the only
    /// field left to carry that. Those paths put a monotonic append index
    /// here instead (`PalaceStore::next_append_index`). So it orders chunks
    /// within a document, and orders nothing at all across API saves — read
    /// it together with `source_file` or not at all.
    pub chunk_index: u32,
    pub added_by: String,
    /// RFC 3339 timestamp of when the drawer was filed.
    pub filed_at: String,
    pub normalize_version: u32,
    pub id_recipe: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_start: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_end: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_date: Option<String>,
    /// Dates and times written into the content itself, preserved verbatim
    /// and resolved against `content_date` where that is possible. Derived
    /// structure, like `entities` — the text is never altered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub time_mentions: Vec<crate::temporal::TimeMention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hall: Option<String>,
    /// The declared record kind — one of [`crate::KIND_VOCAB`], or absent
    /// (which is how every drawer written before the label existed reads,
    /// and a perfectly good permanent state: absence is data, never
    /// guessed over). DECLARED by the writer, validated against the
    /// closed vocabulary at every write surface, and never inferred from
    /// content — the doctrine in docs/LABELS.md. Serialized only when
    /// present, so existing rows stay byte-identical and keep verifying;
    /// inside `meta_json`, so it is covered by the drawer's HMAC, and
    /// mirrored to an indexed column for the search filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The id of the drawer this record supersedes — an update/dedup chain
    /// link, DECLARED by the writer and never inferred. The superseded
    /// drawer is untouched: content is never deleted or hidden by a
    /// supersession, the chain just becomes queryable instead of only
    /// audited. Serialized only when present (old rows byte-identical);
    /// inside `meta_json`, so the link itself is under the drawer's HMAC.
    /// The store binds it further with a keyed receipt over the superseded
    /// drawer's content fingerprint — the KG receipt pattern one level up —
    /// stored beside the row and re-keyed on rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// Tier-1 admission signals tripped at ingest (C3.3): signal CODES
    /// and byte offsets only — structure, never content, so they may sit
    /// in unsealed metadata beside the sealed text. Present only on
    /// quarantined drawers; empty for everything admitted normally.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admission_signals: Vec<crate::admission::AdmissionSignal>,
    /// Where a quarantined drawer was HEADED when the screen diverted it
    /// — what `admission allow` re-files it into. Present only while
    /// quarantined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_wing: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_room: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<String>,
    /// **Further** times this same content was recorded, beyond the drawer's
    /// own `content_date`/`filed_at`.
    ///
    /// Populated only by deduplication: when identical text is collapsed, the
    /// text goes but the dates stay, so the record keeps the chronology of
    /// when it appeared. Empty for a drawer seen once, which is almost all of
    /// them — and empty serializes to nothing, so existing rows stay
    /// byte-identical and keep verifying.
    ///
    /// Use [`Drawer::all_occurrences`] to read the complete history; this
    /// field alone omits the first one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub occurrences: Vec<Occurrence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Drawer {
    pub id: String,
    /// Verbatim content. Encrypted at rest in sealed vaults.
    pub content: String,
    pub meta: DrawerMeta,
}

impl Drawer {
    /// Build a drawer from normalized content with a deterministic id.
    pub fn new(
        wing: &str,
        room: &str,
        content: String,
        source_file: Option<String>,
        chunk_index: u32,
        added_by: &str,
    ) -> Self {
        let source = source_file.as_deref().unwrap_or("(direct)");
        let id = crate::ids::drawer_id(wing, room, source, chunk_index);
        let filed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("RFC3339 formatting of now() cannot fail");
        // Scanned here rather than at each call site so no write path can
        // forget: every drawer that enters the palace, by any route, keeps
        // the times written into it. Resolution needs an anchor and so waits
        // for `with_content_date`.
        let time_mentions = crate::temporal::extract_time_mentions(&content, None);
        // Likewise the entities named in the content. `manage.rs` already
        // re-derived these on demand for co-occurrence; recording them on the
        // drawer means the structure travels with an export and does not have
        // to be recomputed to be read.
        let entities = crate::entity::extract_entities(&content);
        Drawer {
            id,
            content,
            meta: DrawerMeta {
                wing: wing.to_string(),
                room: room.to_string(),
                source_file,
                chunk_index,
                added_by: added_by.to_string(),
                filed_at,
                normalize_version: crate::normalize::NORMALIZE_VERSION,
                id_recipe: crate::ids::ID_RECIPE.to_string(),
                line_start: None,
                line_end: None,
                content_date: None,
                time_mentions,
                hall: None,
                kind: None,
                supersedes: None,
                admission_signals: Vec::new(),
                intended_wing: None,
                intended_room: None,
                entities,
                occurrences: Vec::new(),
            },
        }
    }

    /// Declare this drawer's kind (validated against the closed vocabulary
    /// by the store's write path, not here — a `Drawer` is plain data).
    /// The kind never enters the drawer id: re-declaring it must not move
    /// the record.
    #[must_use]
    pub fn with_kind(mut self, kind: Option<String>) -> Self {
        self.meta.kind = kind;
        self
    }

    /// Declare that this drawer supersedes an earlier one. The link is a
    /// claim until the store's write path receipts it against the
    /// superseded drawer's content; a link to a drawer that does not exist
    /// is recorded and later reported as dangling, never silently dropped.
    /// Superseding never deletes: the old drawer stays retrievable.
    #[must_use]
    pub fn with_supersedes(mut self, supersedes: Option<String>) -> Self {
        self.meta.supersedes = supersedes;
        self
    }

    /// Every time this content is known to have been recorded, earliest
    /// first: the drawer's own appearance plus any folded in by dedup.
    ///
    /// Always at least one entry, so a caller never has to special-case the
    /// ordinary drawer that was seen exactly once.
    pub fn all_occurrences(&self) -> Vec<Occurrence> {
        let mut out = Vec::with_capacity(self.meta.occurrences.len() + 1);
        out.push(Occurrence {
            content_date: self.meta.content_date.clone(),
            filed_at: self.meta.filed_at.clone(),
        });
        out.extend(self.meta.occurrences.iter().cloned());
        // Undated appearances sort first; `Option::None` orders below `Some`.
        out.sort();
        out.dedup_by(|a, b| a.content_date == b.content_date);
        out
    }

    /// This drawer's metadata with every field that copies words out of the
    /// content emptied — what a store may write beside sealed ciphertext.
    ///
    /// `meta_json` is not sealed. That is fine for wing, room, dates and
    /// counts, which are structure rather than content, and it is the same
    /// trade-off plaintext wing/room names already make. It is **not** fine
    /// for `time_mentions[].text`, which holds the exact date expression as
    /// written, or for `entities`, which holds the names. A sealed vault that
    /// encrypts the sentence and writes its dates and names in the clear
    /// beside the ciphertext has not sealed the sentence.
    ///
    /// Nothing is lost by dropping them. Both are derived structure,
    /// recomputable from content the reader has already decrypted, and the
    /// read path recomputes mentions live in any case
    /// ([`live_time_mentions`](Self::live_time_mentions)). What survives here
    /// is the *resolutions* — offsets and ISO dates — which are not content
    /// and which keep the stored reading comparable with the live one.
    ///
    /// Applied at both security levels: an hmac-only vault stores its content
    /// in the clear anyway, so stripping costs it nothing and keeps one
    /// storage contract instead of two.
    #[must_use]
    pub fn meta_at_rest(&self) -> DrawerMeta {
        let mut meta = self.meta.clone();
        for m in &mut meta.time_mentions {
            m.text.clear();
        }
        meta.entities.clear();
        meta
    }

    /// Record that this same content was also seen as `other`, keeping the
    /// dates that collapsing the text would otherwise destroy.
    ///
    /// Deduplicated by `content_date`: re-ingesting the same corpus five
    /// times is one appearance filed five ways, not five appearances. A
    /// genuinely different day is a genuinely different entry.
    pub fn absorb_occurrences_of(&mut self, other: &Drawer) {
        let mut merged = self.all_occurrences();
        merged.extend(other.all_occurrences());
        merged.sort();
        merged.dedup_by(|a, b| a.content_date == b.content_date);
        // The drawer's own appearance stays in `content_date`/`filed_at`;
        // this field carries only the rest.
        merged.retain(|o| o.content_date != self.meta.content_date);
        self.meta.occurrences = merged;
    }

    /// Record when the *content* happened, as distinct from `filed_at`,
    /// which records when we wrote it down. Ingesting a year-old
    /// conversation today makes those two dates a year apart, and text like
    /// "I went yesterday" is only interpretable against the former.
    ///
    /// Does not affect the drawer id — identity stays (wing, room, source,
    /// chunk_index, normalize_version), so re-mining an existing corpus with
    /// dates now available stays idempotent instead of duplicating it.
    /// Supplying the anchor also resolves the relative mentions already
    /// scanned from the content — "yesterday" only becomes a date here.
    #[must_use]
    pub fn with_content_date(mut self, content_date: Option<String>) -> Self {
        let anchor = content_date
            .as_deref()
            .and_then(crate::temporal::parse_anchor);
        if anchor.is_some() {
            self.meta.time_mentions = crate::temporal::extract_time_mentions(&self.content, anchor);
        }
        self.meta.content_date = content_date;
        self
    }

    /// The times written into this drawer's text, as **this build** reads it.
    ///
    /// `meta.time_mentions` is the reading taken when the drawer was written
    /// and sealed then. But a mention is derived from two things the drawer
    /// stores permanently and immutably — its own text and its
    /// `content_date` — so the resolution is recomputable at any moment, and
    /// storing it only freezes it at whatever the writing binary understood.
    ///
    /// That freeze has teeth. A drawer written before "last month" was read
    /// as a month still carries it as a single day. The words are fine; the
    /// engine's reading of them is out of date, and re-reading is the only
    /// way to benefit from a fix without rewriting the drawer.
    ///
    /// So read surfaces answer from here and the sealed copy stays as the
    /// record of what was understood at the time. Deliberately the same call
    /// [`with_content_date`](Self::with_content_date) makes, so the two
    /// readings cannot drift apart by construction.
    pub fn live_time_mentions(&self) -> Vec<crate::temporal::TimeMention> {
        self.live_time_mentions_in(crate::temporal::Locale::default())
    }

    /// As [`live_time_mentions`](Self::live_time_mentions), reading a given
    /// language and week convention.
    ///
    /// Because the reading is live, **the locale is a read-time question.**
    /// An Arabic corpus ingested while the engine was reading English carries
    /// nothing useful in its sealed mentions — and gets the correct ones the
    /// moment a reader asks in Arabic, with no re-ingest and no rewrite. That
    /// is not a workaround for late configuration; it is the reason the
    /// reading was moved to read time.
    pub fn live_time_mentions_in(
        &self,
        locale: crate::temporal::Locale,
    ) -> Vec<crate::temporal::TimeMention> {
        let anchor = self
            .meta
            .content_date
            .as_deref()
            .and_then(crate::temporal::parse_anchor);
        crate::temporal::extract_time_mentions_in(&self.content, anchor, locale)
    }

    /// The names in this drawer's content, as this build reads them.
    ///
    /// Derived rather than stored for the same reason the times are read
    /// live: a name is a word out of the content, and
    /// [`meta_at_rest`](Self::meta_at_rest) keeps those out of unsealed
    /// metadata. The reader has the content already, so nothing is lost.
    pub fn live_entities(&self) -> Vec<String> {
        crate::entity::extract_entities(&self.content)
    }

    /// Whether this build reads the drawer's times differently from the
    /// reading sealed onto it.
    ///
    /// True means the drawer was written by an older understanding of the
    /// language, not that anything is corrupt. Surfaced rather than resolved
    /// silently: a caller comparing an export against a live answer deserves
    /// to know which of the two it is looking at.
    ///
    /// Compared on the *resolutions* — the stored copy carries no verbatim
    /// span, by design, so comparing the text would report every drawer as
    /// disagreeing and say nothing at all.
    pub fn time_mentions_differ(&self) -> bool {
        let strip = |v: Vec<crate::temporal::TimeMention>| {
            v.into_iter()
                .map(|mut m| {
                    m.text.clear();
                    m
                })
                .collect::<Vec<_>>()
        };
        strip(self.live_time_mentions()) != strip(self.meta.time_mentions.clone())
    }

    /// Canonical bytes covered by the integrity HMAC: id, meta (canonical
    /// JSON), and content, separated by 0x1f so fields cannot bleed into
    /// each other.
    pub fn canonical_bytes(&self, content_at_rest: &[u8]) -> Vec<u8> {
        let meta_json = serde_json::to_vec(&self.meta).expect("meta serializes");
        let mut out =
            Vec::with_capacity(self.id.len() + meta_json.len() + content_at_rest.len() + 2);
        out.extend_from_slice(self.id.as_bytes());
        out.push(0x1f);
        out.extend_from_slice(&meta_json);
        out.push(0x1f);
        out.extend_from_slice(content_at_rest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_id_same_slot() {
        let a = Drawer::new("w", "r", "one".into(), Some("f.md".into()), 0, "test");
        let b = Drawer::new("w", "r", "two".into(), Some("f.md".into()), 0, "test");
        assert_eq!(a.id, b.id); // same slot => same id (idempotent re-mine)
    }

    // ---- collapsing text must not collapse chronology --------------------

    fn dated(text: &str, date: &str) -> Drawer {
        Drawer::new("w", "r", text.into(), None, 0, "test").with_content_date(Some(date.into()))
    }

    /// A drawer seen once still answers the question, so no caller has to
    /// special-case the ordinary drawer.
    #[test]
    fn a_drawer_seen_once_has_one_occurrence() {
        let d = dated("the standup notes", "2023-05-08");
        let all = d.all_occurrences();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].content_date.as_deref(), Some("2023-05-08"));
        assert!(
            d.meta.occurrences.is_empty(),
            "nothing extra to store for the common case"
        );
    }

    /// The same words on two different days are two things that happened.
    /// Collapsing the text is fine; losing a date is not.
    #[test]
    fn absorbing_a_duplicate_keeps_both_days() {
        let mut keep = dated("the standup notes", "2023-04-10");
        let gone = dated("the standup notes", "2023-06-26");
        keep.absorb_occurrences_of(&gone);

        let days: Vec<_> = keep
            .all_occurrences()
            .into_iter()
            .filter_map(|o| o.content_date)
            .collect();
        assert_eq!(
            days,
            ["2023-04-10", "2023-06-26"],
            "chronological, both kept"
        );
        assert_eq!(
            keep.meta.content_date.as_deref(),
            Some("2023-04-10"),
            "the survivor's own date is unchanged"
        );
        assert_eq!(keep.content, "the standup notes", "one copy of the text");
    }

    /// Re-ingesting the same corpus is one appearance filed twice, not two
    /// appearances — otherwise every re-run inflates the history.
    #[test]
    fn refiling_the_same_day_does_not_invent_an_appearance() {
        let mut keep = dated("the standup notes", "2023-04-10");
        let again = dated("the standup notes", "2023-04-10");
        keep.absorb_occurrences_of(&again);
        assert_eq!(keep.all_occurrences().len(), 1);
        assert!(keep.meta.occurrences.is_empty());
    }

    #[test]
    fn absorbing_is_order_independent_and_accumulates() {
        let mut a = dated("same words", "2023-03-01");
        a.absorb_occurrences_of(&dated("same words", "2023-05-01"));
        a.absorb_occurrences_of(&dated("same words", "2023-04-01"));
        let days: Vec<_> = a
            .all_occurrences()
            .into_iter()
            .filter_map(|o| o.content_date)
            .collect();
        assert_eq!(days, ["2023-03-01", "2023-04-01", "2023-05-01"]);
    }

    /// Undated text has no chronological position to record, so it collapses
    /// to a single appearance rather than accumulating filing timestamps.
    #[test]
    fn undated_duplicates_collapse_to_one_appearance() {
        let mut a = Drawer::new("w", "r", "no date here".into(), None, 0, "test");
        let b = Drawer::new("w", "r", "no date here".into(), None, 0, "test");
        a.absorb_occurrences_of(&b);
        assert_eq!(a.all_occurrences().len(), 1);
    }

    /// Empty occurrences must serialize to nothing, so every drawer written
    /// before this existed keeps its exact bytes and keeps verifying.
    #[test]
    fn no_occurrences_adds_nothing_to_the_stored_bytes() {
        let d = dated("plain", "2023-05-08");
        let json = serde_json::to_string(&d.meta).unwrap();
        assert!(!json.contains("occurrences"), "{json}");
    }

    // ---- the reading is live; the seal is the record --------------------

    /// The point of reading live: a drawer sealed by an older build carries
    /// an older understanding of its own words, and re-reading upgrades it
    /// without rewriting a single byte. Here the sealed copy says "last
    /// month" is one day — the pre-fix reading — while this build reads the
    /// month it names.
    #[test]
    fn a_stale_sealed_reading_is_superseded_without_touching_the_drawer() {
        let mut d = Drawer::new("w", "r", "I quit last month".into(), None, 0, "test")
            .with_content_date(Some("2023-05-08".into()));
        let sealed_before = d.meta.time_mentions.clone();
        let content_before = d.content.clone();

        // Simulate what an older binary sealed: the same span, resolved to a
        // single day instead of the month it names.
        d.meta.time_mentions[0].resolved = Some("2023-04-08".into());
        d.meta.time_mentions[0].resolved_end = None;

        assert!(d.time_mentions_differ(), "this build reads it differently");
        let live = d.live_time_mentions();
        assert_eq!(live[0].range(), Some(("2023-04-01", "2023-04-30")));
        assert_eq!(live, sealed_before, "live matches what this build writes");
        assert_eq!(d.content, content_before, "the words are never touched");
    }

    #[test]
    fn an_up_to_date_drawer_reports_no_disagreement() {
        let d = Drawer::new("w", "r", "we met yesterday".into(), None, 0, "test")
            .with_content_date(Some("2023-05-08".into()));
        assert!(!d.time_mentions_differ());
        assert_eq!(d.live_time_mentions(), d.meta.time_mentions);
    }

    /// Live reading uses the drawer's own anchor, so a drawer with no
    /// `content_date` resolves nothing — the same refusal the write path
    /// makes, not a different one.
    #[test]
    fn live_reading_never_invents_an_anchor() {
        let d = Drawer::new("w", "r", "we met yesterday".into(), None, 0, "test");
        let live = d.live_time_mentions();
        assert_eq!(live.len(), 1);
        assert!(live[0].resolved.is_none(), "no anchor, no date");
        assert!(!d.time_mentions_differ());
    }

    #[test]
    fn canonical_bytes_change_with_meta() {
        let mut a = Drawer::new("w", "r", "c".into(), None, 0, "test");
        let before = a.canonical_bytes(b"c");
        a.meta.room = "other".into();
        let after = a.canonical_bytes(b"c");
        assert_ne!(before, after);
    }

    #[test]
    fn entities_are_recorded_on_every_drawer() {
        // Sentence-initial words are deliberately excluded as noise by
        // extract_entities, so the names under test sit mid-sentence.
        let d = Drawer::new(
            "w",
            "r",
            "we met Alice and Blue Heron in Berlin.".into(),
            None,
            0,
            "test",
        );
        for want in ["alice", "blue heron", "berlin"] {
            assert!(
                d.meta.entities.contains(&want.to_string()),
                "missing {want}: {:?}",
                d.meta.entities
            );
        }
    }

    #[test]
    fn entities_survive_the_meta_roundtrip() {
        let d = Drawer::new("w", "r", "Alice went to Berlin.".into(), None, 0, "test");
        let back: DrawerMeta =
            serde_json::from_str(&serde_json::to_string(&d.meta).unwrap()).unwrap();
        assert_eq!(back.entities, d.meta.entities);
        assert!(!back.entities.is_empty());
    }

    #[test]
    fn entityless_content_stays_empty_and_is_omitted_from_json() {
        let d = Drawer::new(
            "w",
            "r",
            "just some lowercase words".into(),
            None,
            0,
            "test",
        );
        assert!(d.meta.entities.is_empty(), "{:?}", d.meta.entities);
        // skip_serializing_if keeps existing rows byte-identical.
        assert!(!serde_json::to_string(&d.meta).unwrap().contains("entities"));
    }

    #[test]
    fn meta_roundtrips_json() {
        let d = Drawer::new(
            "wing",
            "room",
            "content".into(),
            Some("s.md".into()),
            3,
            "cli",
        );
        let j = serde_json::to_string(&d.meta).unwrap();
        let back: DrawerMeta = serde_json::from_str(&j).unwrap();
        assert_eq!(back, d.meta);
    }
}
