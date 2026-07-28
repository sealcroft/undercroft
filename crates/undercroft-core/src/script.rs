//! Script-aware segmentation for comparison keys.
//!
//! Splitting on `!char::is_alphanumeric()` finds word boundaries only in
//! scripts that mark them. It does not in Han, Kana, Hangul, Bopomofo,
//! Arabic, Khmer, Thai, Lao or Myanmar — there a whole clause collapses into
//! a single token, and a query for a word the drawer visibly contains matches
//! nothing at all:
//!
//! ```text
//! doc   我昨天去了北京参加会议  -> ["我昨天去了北京参加会议"]
//! query 北京                  -> ["北京"]          0 / 1 matched
//! ```
//!
//! That is not a ranking problem. `search` drops any hit with no lexical
//! evidence and a merely neutral cosine, so the observable is an empty result
//! set that reads as an empty vault.
//!
//! Note this is *not* the same failure everywhere. Han and Kana produce one
//! stable mega-token, so at least both sides agree. Khmer, Thai and Myanmar
//! carry marks that are combining but **not** `Other_Alphabetic` (Khmer COENG
//! U+17D2, Thai tone marks U+0E48..U+0E4C, Myanmar ASAT U+103A), which *do*
//! split — into fragments that start and end mid-word, positioned by whatever
//! word happens to follow. Query and document then disagree, which is
//! strictly worse: the same Thai word matches when it ends the document and
//! misses when it begins it.
//!
//! The fix is to segment such runs into character bigrams (Lucene's
//! `CJKBigramFilter` shape), symmetrically on both sides — plus unigrams, but
//! **only where a character is a word**. That distinction is load-bearing in
//! both directions. Without Han unigrams, `好` in `他说：「好。」` is a working
//! token today that the change would delete. With unigrams everywhere,
//! `قطار` matches `المستشفى` on a shared alef, and since a hit is admitted on
//! `lexical > 0.0`, that does not just add noise — it retires the relevance
//! gate for every query in the script.
//!
//! Two boundaries this deliberately does not cross:
//!
//! * **Runs are split by script first.** `我们用Kubernetes部署` bigrammed
//!   whole would emit `wi, in, nd, do, ow, ws` and destroy an exact brand-name
//!   match that works today. Latin and digit subruns are left whole.
//! * **Delimiting scripts are untouched.** Georgian, Greek, Cyrillic, Latin
//!   and Tibetan (which delimits on the tsheg U+0F0B) mark their boundaries;
//!   their remaining defects are folding and morphology, not segmentation, and
//!   n-grams are the wrong tool for those.
//!
//! ## Known gaps, recorded rather than discovered
//!
//! * **Hebrew and Yiddish get nothing.** `script_of` returns `Script::Other`
//!   for `U+0590..U+05FF`, so there are no bigrams, and `search_key` is the
//!   identity on Hebrew — no niqqud strip. Measured: `בְּרֵאשִׁית` and `בראשית`
//!   share no token, no n-gram at any n, no embedder trigram, and score
//!   exactly 0.5000, so pointed Hebrew cannot find its own unpointed spelling.
//!   Hebrew also attaches its clitics at the *front* (ה ו ב ל כ מ ש), so a
//!   prefix rule is structurally the wrong shape for it. Separately
//!   `ספר`/`ספרים` — a three-letter root and its plural, i.e. the common case —
//!   has zero evidence on every channel and would not be fixed by a fold.
//! * **Brahmic conjuncts shatter.** The virama is not `Other_Alphabetic`
//!   (Devanagari `U+094D`, and the same in Bengali, Gurmukhi, Gujarati, Oriya,
//!   Tamil, Telugu, Kannada, Malayalam, Sinhala), so `नमस्ते` splits at the
//!   conjunct into `नमस` + `ते` — the Khmer-COENG failure this module was
//!   written to fix, in a script family it does not cover.
//! * **A one-syllable Korean noun cannot find itself inflected.** `집` emits
//!   `["집"]` while `집에서` emits `["집에","에서","집에서"]`: intersection empty,
//!   and `fuzzy_eq` is excluded by its own two-character minimum. Note this
//!   gap does *not* exist on `Fusion::Legacy` or the remote path, where
//!   `lower.contains("집")` is true — so it is configuration-dependent, which
//!   is itself worth knowing.

/// The scripts this module treats specially, plus `Other` for everything that
/// already marks its own word boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    Han,
    Hiragana,
    Katakana,
    Hangul,
    Bopomofo,
    Arabic,
    /// Hebrew. It writes spaces between words, which is why it sat in `Other`
    /// and was therefore treated as delimiting — but its clitics (`ה` the,
    /// `ב` in, `ל` to, `ו` and, `מ` from, `ש` that) attach with **no**
    /// delimiter, exactly as Arabic's do, and Hebrew stems are three or four
    /// characters. Classed as delimiting it got `contains_a_long_word`'s
    /// eight-character floor and was excluded from `shares_a_stem`, so every
    /// route was closed at once: measured over 8 real pairs at both drawer
    /// lengths, Hebrew admitted **0**, the only language in the audit to score
    /// nothing at all. Whole-word containment reaches 7 of those 8.
    Hebrew,
    Khmer,
    Thai,
    Lao,
    Myanmar,
    /// Any script that delimits its words — Latin, Cyrillic, Greek, Georgian,
    /// Tibetan, Devanagari, digits, and everything else.
    Other,
}

impl Script {
    /// True when the script attaches words or morphology without a delimiter,
    /// so a boundary split cannot find word edges inside it.
    ///
    /// Arabic and Hebrew are included even though they space their words: in
    /// both, the definite article and the conjunction/preposition proclitics
    /// attach with no delimiter, so `كتاب` cannot reach `الكتاب` and `ספר`
    /// cannot reach `הספר` by any split. This predicate is about morphology,
    /// not about whether the orthography happens to use a space.
    pub fn attaches_without_delimiter(self) -> bool {
        !matches!(self, Script::Other)
    }

    /// True when a single character is itself a unit of meaning, so emitting
    /// it alone is evidence rather than noise.
    ///
    /// This is what separates Han from the rest. `好` and `猫` are words; a
    /// lone Arabic `ا`, Thai consonant or Korean syllable is not. Emitting
    /// unigrams for the alphabetic scripts makes any two texts in the script
    /// share a token — `قطار` would "match" `المستشفى` on the alef — and
    /// since `search` admits a hit on `lexical > 0.0`, that does not merely
    /// add noise to the ranking, it defeats the relevance gate entirely.
    pub fn is_logographic(self) -> bool {
        matches!(self, Script::Han)
    }
}

/// Classify a character by script.
///
/// Explicit ranges rather than a Unicode Script table dependency: the set we
/// treat specially is small, fixed, and each range below is the reason it is
/// here. Everything unlisted is `Other`, which is the safe answer — it means
/// "leave this alone".
pub fn script_of(c: char) -> Script {
    match c as u32 {
        // Han. Includes the CJK iteration mark 々 (U+3005), which repeats the
        // preceding ideograph and so belongs to its run.
        0x3005 | 0x303B => Script::Han,
        0x3400..=0x4DBF        // Extension A
        | 0x4E00..=0x9FFF      // Unified Ideographs
        | 0xF900..=0xFAFF      // Compatibility Ideographs
        | 0x20000..=0x2A6DF    // Extension B
        | 0x2A700..=0x2EBEF    // Extensions C-F
        | 0x2F800..=0x2FA1F => Script::Han,

        0x3040..=0x309F => Script::Hiragana,
        // Katakana, phonetic extensions, and halfwidth forms. The prolonged
        // sound mark ー (U+30FC) lives in this block and belongs to its run.
        0x30A0..=0x30FF | 0x31F0..=0x31FF | 0xFF66..=0xFF9F => Script::Katakana,

        0x1100..=0x11FF        // Jamo
        | 0x3130..=0x318F      // Compatibility Jamo
        | 0xA960..=0xA97F      // Jamo Extended-A
        | 0xAC00..=0xD7A3      // Syllables
        | 0xD7B0..=0xD7FF => Script::Hangul,

        0x3105..=0x312F | 0x31A0..=0x31BF => Script::Bopomofo,

        0x0600..=0x06FF        // Arabic
        | 0x0750..=0x077F      // Supplement
        | 0x08A0..=0x08FF      // Extended-A
        | 0xFB50..=0xFDFF      // Presentation Forms-A
        | 0xFE70..=0xFEFF => Script::Arabic,

        // Hebrew, plus the presentation forms. The points (niqqud) live inside
        // this block and the fold strips them, so they never reach a run.
        0x0590..=0x05FF | 0xFB1D..=0xFB4F => Script::Hebrew,

        0x1780..=0x17FF | 0x19E0..=0x19FF => Script::Khmer,
        0x0E00..=0x0E7F => Script::Thai,
        0x0E80..=0x0EFF => Script::Lao,
        0x1000..=0x109F | 0xA9E0..=0xA9FF | 0xAA60..=0xAA7F => Script::Myanmar,

        _ => Script::Other,
    }
}

/// The result of segmenting a text into comparison tokens.
pub struct Segmented {
    /// Tokens for term matching. Both the query and the document side go
    /// through this, so matching stays symmetric.
    /// Every token, **unfiltered**. Callers apply their own minimum-length
    /// rule: BM25 keeps the historical `len() > 1` *byte* test, while the
    /// hash embedder has always indexed one-letter words and must keep doing
    /// so or `vitamin C` stops being distinguishable from `vitamin D`.
    pub tokens: Vec<String>,
    /// Parallel to `tokens`: true where the token is a character n-gram from a
    /// script that attaches without a delimiter and is **not** logographic —
    /// Arabic, Kana, Hangul, Khmer, Thai, Lao, Myanmar, Bopomofo.
    ///
    /// The caller needs this because such an n-gram is not a word and must not
    /// be treated as one. Measured on a real 50k-word Arabic corpus, matching
    /// bigram-to-bigram by literal equality admitted **74.3%** of a 120-drawer
    /// vault on a single query, against 6.9% for Greek through the same code —
    /// a shared two-character substring in an unvocalised abjad is not
    /// evidence that a drawer is about the query. It is the failure
    /// `is_logographic` documents for unigrams, one n-gram order lower.
    ///
    /// Han is deliberately excluded: there a character *is* a morpheme, so its
    /// unigrams and bigrams are words and are marked `false`.
    pub ngram: Vec<bool>,
    /// Content units, counting a segmented run **once per character** rather
    /// than once per emitted n-gram.
    ///
    /// BM25 divides by document length. Without this, segmenting a run into
    /// unigrams plus bigrams would roughly triple the measured length of
    /// exactly the documents the segmentation exists to serve, and length
    /// normalization would take back most of the gain.
    pub len: usize,
}

/// Segment `text` into comparison tokens.
///
/// `text` is expected to be already canonicalized and lowercased by the
/// caller — this function decides boundaries, not encoding.
/// A mark that is orthographically *inside* a word even though
/// `is_alphanumeric` says otherwise.
///
/// Canonical combining class 9 is the virama family (all 69 of them) and 7 is
/// the nukta family; both join consonants into a cluster. `is_alphanumeric` is
/// the derived Alphabetic property, and these are not `Other_Alphabetic`, so
/// they read as word *boundaries* — `नमस्ते` split into `नमस` + `ते`, which is
/// the Khmer-COENG failure this module was written to fix, in a script family
/// it did not cover.
///
/// The extra codepoints are Devanagari/Bengali/Oriya/Malayalam signs in the
/// same position that fall outside those two classes.
fn is_joining_mark(c: char) -> bool {
    use unicode_normalization::char::canonical_combining_class;
    matches!(canonical_combining_class(c), 7 | 9)
        || matches!(c as u32, 0x0951..=0x0954 | 0x09FE | 0x0B55 | 0x0D3B..=0x0D3C)
}

/// Maximal word runs, treating a joining mark as word-internal — but **only in
/// a delimiting script**.
///
/// The scoping is the whole safety argument. In a delimiting script the token
/// *is* the word, so gluing two fragments back into their true spelling cannot
/// make two different words equal — it is injective, and it removes spurious
/// matches rather than creating them (`दिल` stops matching `दिल्ली`, `मन` stops
/// matching `मन्दिर`).
///
/// In a non-delimiting script `emit` produces character bigrams, and there a
/// mark is *not* injective: allowing Thai tone marks to join would make
/// `เก่า`(old) and `ก่อน`(before) share the bigram `ก่`, and `ရန်ကုန်`(Yangon)
/// share `န်` with `မြန်မာ` — near-contentless high-frequency tokens in the
/// exact channel, which is precisely the hole that forced unigrams to be
/// Han-only. So Khmer COENG, Myanmar ASAT and the Thai marks keep splitting,
/// and those scripts are bit-identical to before.
///
/// A joining mark never *opens* a run, so a stray leading virama stays a
/// delimiter.
fn runs(text: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let mut start: Option<usize> = None;
    let mut prev: Option<char> = None;
    for (i, c) in text.char_indices() {
        let inside = if c.is_alphanumeric() {
            true
        } else if is_joining_mark(c) {
            start.is_some() && prev.is_some_and(|p| script_of(p) == Script::Other)
        } else {
            false
        };
        match (inside, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push(&text[s..i]);
                start = None;
            }
            _ => {}
        }
        prev = Some(c);
    }
    if let Some(s) = start {
        out.push(&text[s..]);
    }
    out
}

pub fn segment(text: &str) -> Segmented {
    let mut out = Segmented {
        tokens: Vec::new(),
        ngram: Vec::new(),
        len: 0,
    };
    for run in runs(text) {
        if run.is_empty() {
            continue;
        }
        let mut start = 0usize;
        let mut current: Option<Script> = None;
        for (offset, ch) in run.char_indices() {
            let script = script_of(ch);
            match current {
                None => {
                    current = Some(script);
                    start = offset;
                }
                Some(prev) if prev == script => {}
                Some(prev) => {
                    emit(&mut out, &run[start..offset], prev);
                    current = Some(script);
                    start = offset;
                }
            }
        }
        if let Some(prev) = current {
            emit(&mut out, &run[start..], prev);
        }
    }
    out
}

/// Emit one same-script subrun.
fn emit(out: &mut Segmented, sub: &str, script: Script) {
    if sub.is_empty() {
        return;
    }
    if !script.attaches_without_delimiter() {
        out.len += 1;
        out.tokens.push(sub.to_string());
        out.ngram.push(false);
        return;
    }
    let chars: Vec<char> = sub.chars().collect();
    // A joining mark is not a content unit — it glues two consonants into one
    // cluster. Counting it would inflate BM25's document length. Defensive
    // here: `runs` only lets one join inside a delimiting subrun, which takes
    // the branch above.
    out.len += chars.iter().filter(|c| !is_joining_mark(**c)).count();
    // Unigrams only where a character is a word (see `is_logographic`).
    if script.is_logographic() {
        for ch in &chars {
            out.tokens.push(ch.to_string());
            out.ngram.push(false);
        }
    }
    if chars.len() < 2 {
        // A one-character subrun bounded by delimiters is a real token in any
        // script, and was one before this change — a lone Arabic letter is
        // 2 bytes and cleared the old byte filter.
        if !script.is_logographic() {
            out.tokens.push(sub.to_string());
            out.ngram.push(false);
        }
        return;
    }
    // An n-gram is a FRAGMENT of a word. At exactly two characters the bigram
    // *is* the whole subrun, so flagging it would deny a real word the exact
    // slot — and nothing else is emitted at that length, because the
    // whole-subrun push below is guarded on `> 2`. Hebrew regressed into this
    // when it left the delimiting class: `גן`, `בן`, `יד`, `עץ`, `שם` were
    // exact matches as `Script::Other` and became unreachable, measured
    // DROPPED at realistic drawer length on every channel. Arabic, Korean and
    // Thai had the same hole latently and never had the exact match to lose.
    //
    // This does not re-open the 74.3% defect: a two-character run *inside* a
    // longer word is still emitted from that word's own subrun with the flag
    // set, so a fragment never fills the exact slot. Only a subrun that the
    // delimiters themselves bound reaches here unflagged.
    let is_ngram = !script.is_logographic() && chars.len() > 2;
    for pair in chars.windows(2) {
        out.tokens.push(format!("{}{}", pair[0], pair[1]));
        out.ngram.push(is_ngram);
    }
    // The whole unit, when it is longer than the bigrams already emitted. For
    // Arabic this is the word itself and carries the strongest signal; for a
    // CJK run it is the clause, which is what the old tokenizer produced, so
    // nothing that matched before stops matching.
    if chars.len() > 2 {
        // The whole subrun is the word, whatever the script.
        out.tokens.push(sub.to_string());
        out.ngram.push(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors `undercroft_store::tokenize` exactly: the retrieval fold, then
    /// segmentation, then the historical byte filter. Using bare
    /// `to_lowercase` here instead would let these tests pass while the
    /// product behaved differently.
    fn toks(s: &str) -> Vec<String> {
        segment(&crate::normalize::search_key(s))
            .tokens
            .into_iter()
            .filter(|t| t.len() > 1)
            .collect()
    }

    /// How many of the query's tokens the document supplies. Zero is the
    /// failure this module exists to remove.
    fn matched(query: &str, doc: &str) -> usize {
        let d = toks(doc);
        toks(query).iter().filter(|t| d.contains(t)).count()
    }

    #[test]
    fn a_chinese_clause_is_no_longer_one_token() {
        let t = toks("我昨天去了北京参加会议");
        assert!(t.contains(&"北京".to_string()), "{t:?}");
        assert!(t.contains(&"北".to_string()));
        // The old whole-clause token survives, so nothing that matched before stops.
        assert!(t.contains(&"我昨天去了北京参加会议".to_string()));
    }

    #[test]
    fn the_city_in_the_sentence_is_findable() {
        assert_eq!(matched("北京", "我昨天去了北京参加会议"), 3); // 北, 京, 北京
        assert_eq!(matched("東京", "昨日は東京で会議に参加しました"), 3);
    }

    /// The failure that is worse than Chinese: fragments positioned by the
    /// following word, so the same word matches at one end and not the other.
    #[test]
    fn a_thai_word_matches_wherever_it_sits() {
        assert!(matched("ประชุม", "ประชุมทีมงานที่กรุงเทพ") > 0);
        assert!(matched("กรุงเทพ", "ประชุมทีมงานที่กรุงเทพ") > 0);
        assert!(matched("ประชุม", "ฉันไปกรุงเทพเมื่อวานนี้เพื่อเข้าร่วมประชุม") > 0);
    }

    #[test]
    fn khmer_coeng_no_longer_shatters_the_word() {
        let doc = "ខ្ញុំបានទៅភ្នំពេញកាលពីម្សិលមិញដើម្បីចូលរួមប្រជុំ";
        assert!(matched("ភ្នំពេញ", doc) > 0);
        assert!(matched("ចូលរួម", doc) > 0);
    }

    /// Arabic spaces its words; what attaches with no delimiter is the
    /// definite article and the proclitics.
    #[test]
    fn arabic_reaches_through_the_definite_article() {
        assert!(matched("كتاب", "قرأت الكتاب أمس") > 0);
        assert!(matched("مكتبة", "ذهبت إلى المكتبة") > 0);
        // A three-letter root, which the hash embedder cannot reach at all.
        assert!(matched("بيت", "دخلت البيت") > 0);
    }

    /// Different words must stay different, or the fix is just noise.
    ///
    /// The Arabic pair is the one that caught it: with unigrams in every
    /// script, these two share the alef and the drawer clears the relevance
    /// gate on a single letter.
    #[test]
    fn unrelated_terms_still_do_not_match() {
        assert_eq!(matched("قطار", "ذهبت إلى المستشفى"), 0);
        assert_eq!(matched("東京", "私は大阪に住んでいます"), 0);
        assert_eq!(matched("ประชุม", "ฉันชอบอาหารไทย"), 0);
    }

    /// No alphabetic non-delimiting script may emit a bare character.
    #[test]
    fn only_logographic_scripts_emit_single_characters() {
        assert!(toks("الكتاب").iter().all(|t| t.chars().count() > 1));
        assert!(toks("한국어는").iter().all(|t| t.chars().count() > 1));
        assert!(toks("กรุงเทพ").iter().all(|t| t.chars().count() > 1));
        // Han does, because there a character is a word.
        assert!(toks("北京参加会议").contains(&"北".to_string()));
    }

    #[test]
    fn korean_reaches_through_its_particles() {
        assert!(matched("한국어", "한국어는 어렵다") > 0);
        assert!(matched("서울", "어제 서울에서 회의에 참석했습니다") > 0);
    }

    /// A Latin brand name inside CJK must not be shredded into bigrams.
    #[test]
    fn latin_subruns_are_left_whole() {
        let t = toks("我们用Kubernetes部署");
        assert!(t.contains(&"kubernetes".to_string()), "{t:?}");
        assert!(!t.contains(&"wi".to_string()), "{t:?}");
        assert!(t.contains(&"部署".to_string()));
    }

    /// Japanese splits kanji from kana, so grammatical particles do not glue
    /// themselves to content words.
    #[test]
    fn japanese_splits_at_script_boundaries() {
        let t = toks("東京タワー");
        assert!(t.contains(&"東京".to_string()), "{t:?}");
        assert!(t.contains(&"タワー".to_string()), "{t:?}");
        // The two scripts must not produce a bigram straddling the boundary.
        assert!(!t.contains(&"京タ".to_string()), "{t:?}");
    }

    /// A single ideograph is a real word and must survive.
    #[test]
    fn a_lone_ideograph_is_a_token() {
        assert!(toks("他说：「好。」").contains(&"好".to_string()));
        assert!(matched("好", "他说：「好。」") > 0);
    }

    #[test]
    fn latin_cyrillic_and_georgian_tokenize_exactly_as_before() {
        // The regression guard: English, Russian and Georgian must stay
        // byte-identical to the old split-on-non-alphanumeric behaviour.
        // Note the single-letter Cyrillic words: the historical filter is a
        // *byte* test, so `я` and `в` (2 bytes each) always survived it while
        // a one-letter English word does not. That asymmetry is preserved
        // here deliberately — changing it would silently drop tokens from
        // every existing vault.
        //
        // Greek is deliberately gone from this list: its tonos folds now, so
        // `Αθήνα` yields `αθηνα`. These three rows carry no ё, no loose acute
        // and rely on Mkhedruli being caseless, which makes the test a
        // tripwire for any *future* Cyrillic or Georgian fold.
        let cases = [
            (
                "I went to Beijing yesterday",
                vec!["went", "to", "beijing", "yesterday"],
            ),
            ("Я поехал в Москву", vec!["я", "поехал", "в", "москву"]),
            ("წიგნი მაგიდაზე", vec!["წიგნი", "მაგიდაზე"]),
        ];
        for (input, want) in cases {
            let got = toks(input);
            let want: Vec<String> = want.into_iter().map(str::to_string).collect();
            assert_eq!(got, want, "input: {input}");
        }
    }

    /// A conjunct is one word. The virama is not `Other_Alphabetic`, so it read
    /// as a boundary and shattered every Brahmic word at its clusters.
    #[test]
    fn a_brahmic_conjunct_is_one_word() {
        assert_eq!(toks("नमस्ते"), vec!["नमस्ते".to_string()]);
        assert_eq!(segment("नमस्ते").len, 1, "one word, not two");
        assert_eq!(toks("संस्कृत"), vec!["संस्कृत".to_string()]);
        assert_eq!(toks("தமிழ்"), vec!["தமிழ்".to_string()]);
        assert_eq!(toks("বাংলায়"), vec!["বাংলায়".to_string()]);
        assert_eq!(toks("മലയാളം"), vec!["മലയാളം".to_string()]);
    }

    /// The gain is precision, not just recall: the fragments were matching
    /// unrelated words. `दिल`(heart) matched `दिल्ली`(Delhi) on `दिल`.
    #[test]
    fn conjunct_fragments_stop_colliding() {
        for (query, doc) in [
            ("दिल", "मैं दिल्ली में रहता हूँ"),
            ("मन", "मन्दिर गया"),
            ("धन", "धन्यवाद"),
            ("लोक", "यह संस्कृत का श्लोक है"),
        ] {
            let d = toks(doc);
            let shared = toks(query).iter().filter(|t| d.contains(t)).count();
            assert_eq!(shared, 0, "{query} still collides inside {doc}");
        }
    }

    /// A joining mark never opens a run, so a stray one stays a delimiter.
    #[test]
    fn a_leading_joining_mark_is_still_a_delimiter() {
        assert_eq!(toks("\u{094D}नमस"), vec!["नमस".to_string()]);
    }

    /// The scoping is the safety argument. Letting marks join in a
    /// non-delimiting script would make consonant+mark BIGRAMS, which are not
    /// injective: `เก่า`(old) and `ก่อน`(before) would share `ก่`, and
    /// `ရန်ကုန်`(Yangon) would share `န်` with `မြန်မာ` — contentless
    /// high-frequency tokens in the admitting channel.
    #[test]
    fn non_delimiting_scripts_are_untouched() {
        let cases = [
            "ฉันไปกรุงเทพเมื่อวานนี้",
            "เก่า",
            "ก่อน",
            "ខ្ញុំបានទៅភ្នំពេញ",
            "ရန်ကုန်",
            "မြန်မာ",
            "قَرَأتُ الكِتَابَ",
            "한국어는 어렵다",
            "我昨天去了北京参加会议",
            "昨日は東京で会議に参加しました",
            "בְּרֵאשִׁית",
            "کتاب‌ها",
            "٢٠٢٣",
            "İZMİR",
            "мо́жет",
            "vitamin c",
            "https://example.com/a?b=1",
        ];
        for input in cases {
            let before: Vec<String> = crate::normalize::search_key(input)
                .split(|c: char| !c.is_alphanumeric())
                .filter(|r| !r.is_empty())
                .flat_map(|r| {
                    let mut s = Segmented {
                        tokens: Vec::new(),
                        ngram: Vec::new(),
                        len: 0,
                    };
                    let mut st = 0usize;
                    let mut cur: Option<Script> = None;
                    for (off, ch) in r.char_indices() {
                        let sc = script_of(ch);
                        match cur {
                            None => {
                                cur = Some(sc);
                                st = off;
                            }
                            Some(p) if p == sc => {}
                            Some(p) => {
                                emit(&mut s, &r[st..off], p);
                                cur = Some(sc);
                                st = off;
                            }
                        }
                    }
                    if let Some(p) = cur {
                        emit(&mut s, &r[st..], p);
                    }
                    s.tokens
                })
                .collect();
            let after = segment(&crate::normalize::search_key(input)).tokens;
            assert_eq!(after, before, "{input:?} changed");
        }
    }

    /// The case suffix stays out of reach, and that is a gap, not a fix.
    #[test]
    fn brahmic_case_suffixes_are_still_unreachable() {
        let d = toks("घरमें बैठा हूँ");
        assert_eq!(toks("घर").iter().filter(|t| d.contains(t)).count(), 0);
    }

    /// Tibetan delimits on the tsheg, so it needs no segmentation and must
    /// not get any.
    #[test]
    fn tibetan_is_left_alone() {
        assert_eq!(script_of('\u{0F40}'), Script::Other);
    }

    /// Every token carries a flag, and they stay in step.
    #[test]
    fn the_ngram_flags_line_up_with_the_tokens() {
        for input in [
            "قرأت الكتاب أمس",
            "我昨天去了北京参加会议",
            "한국어는 어렵다",
            "ฉันไปกรุงเทพ",
            "i went to beijing",
            "नमस्ते",
        ] {
            let s = segment(&crate::normalize::search_key(input));
            assert_eq!(s.tokens.len(), s.ngram.len(), "{input:?}");
        }
    }

    /// An Arabic bigram is not a word. A Han bigram is.
    #[test]
    fn only_non_logographic_ngrams_are_flagged() {
        let ar = segment(&crate::normalize::search_key("كتاب"));
        for (t, ng) in ar.tokens.iter().zip(&ar.ngram) {
            // The whole word is not an n-gram; its bigrams are.
            assert_eq!(*ng, t.chars().count() < 4, "{t}");
        }
        // Han: a character is a morpheme, so nothing is flagged.
        let zh = segment(&crate::normalize::search_key("北京参加"));
        assert!(zh.ngram.iter().all(|f| !f), "Han must not be flagged");
        // Delimiting scripts emit whole words only.
        let en = segment(&crate::normalize::search_key("beijing"));
        assert!(en.ngram.iter().all(|f| !f));
    }

    /// `segment` itself filters nothing — a one-letter word reaches the
    /// caller, and only BM25 drops it. The hash embedder needs it.
    #[test]
    fn one_letter_words_reach_the_caller() {
        let all = segment("vitamin c").tokens;
        assert!(all.contains(&"c".to_string()), "{all:?}");
        // ...and BM25's byte filter is what removes it, as it always has.
        assert!(!toks("vitamin c").contains(&"c".to_string()));
    }

    /// Length must count content, not the n-gram expansion, or BM25's length
    /// normalization penalises exactly the documents this serves.
    #[test]
    fn length_counts_characters_not_ngrams() {
        let s = segment("北京");
        assert_eq!(s.len, 2);
        assert!(s.tokens.len() > 2, "{:?}", s.tokens);

        // An 11-character clause counts as 11, comparable to 11 words.
        assert_eq!(segment("我昨天去了北京参加会议").len, 11);
        // Latin is unchanged: one unit per word.
        assert_eq!(segment("i went to beijing").len, 4);
    }

    /// Was a documented gap, now closed: Turkish dotted capital İ lowercases
    /// to `i` + U+0307, which is combining but not Other_Alphabetic, so it
    /// split the word and the byte filter ate the fragments — `İZMİR` gave
    /// `["zmi"]`. `search_key` strips the mark after lowercasing, which needs
    /// no Turkic tailoring and so keeps Turkish ı/i minimal pairs.
    #[test]
    fn turkish_dotted_capital_folds_to_izmir() {
        assert_eq!(toks("İZMİR"), vec!["izmir".to_string()]);
        assert_eq!(toks("İzmir"), toks("izmir"));
    }
}
