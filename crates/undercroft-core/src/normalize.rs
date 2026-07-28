//! Content normalization, mirroring mempalace's `normalize.py` contract:
//! deterministic cleanup applied before hashing so drawer ids are stable
//! across re-mines of the same source.

/// Bumped whenever normalization output changes; stored in drawer metadata
/// (mempalace's `normalize_version`) so a re-mine can detect stale drawers.
///
/// v2: whitespace tidying no longer applies inside fenced code blocks, and
/// [`NormalizeMode::Code`] skips it entirely. Indentation and blank runs are
/// content in a script, not formatting noise.
pub const NORMALIZE_VERSION: u32 = 2;

/// The key two texts must share to count as the same text.
///
/// Unicode lets one visible string be written several ways. "é" is one code
/// point or two. Arabic أ is either U+0623 or bare alef plus a combining
/// hamza — and that class covers أحمد, إبراهيم, مؤمن, رئيس, so it is the
/// common case, not an exotic one. Byte comparison calls those different, so
/// a fingerprint misses the duplicate and a lexical query misses the drawer,
/// silently, and only for non-ASCII text — exactly the text least likely to
/// be noticed failing.
///
/// This composes to NFC, which is *canonical* equivalence only: the result
/// renders identically by Unicode's own definition. Compatibility folding
/// (NFKC) is deliberately not applied — it rewrites ﬁ to fi and ① to 1, which
/// changes content rather than encoding.
///
/// What it therefore does **not** fix: tatweel (ـ) is a real character, not a
/// decomposition, and Arabic presentation forms are compatibility mappings —
/// both survive NFC and would need their own decision about whether removing
/// them is normalization or editing.
///
/// **Comparison only.** Stored content keeps the writer's exact bytes: the
/// promise is verbatim, and normalizing on the way in would quietly edit
/// text to make our indexes tidier. It would also change
/// [`NORMALIZE_VERSION`], which is inside the drawer id, so every future id
/// would move. Deriving the key at comparison time costs one scan and no
/// migration.
pub fn match_key(s: &str) -> std::borrow::Cow<'_, str> {
    use unicode_normalization::{is_nfc_quick, IsNormalized, UnicodeNormalization};
    // Almost all real input is already NFC; the quick check keeps this a scan
    // rather than a rebuild on the hot path.
    match is_nfc_quick(s.chars()) {
        IsNormalized::Yes => std::borrow::Cow::Borrowed(s),
        _ => std::borrow::Cow::Owned(s.nfc().collect()),
    }
}

/// The retrieval key: [`match_key`] plus the folds that decide whether two
/// spellings of one word can meet in an index.
///
/// [`match_key`] answers "is this the same text?" and is deliberately strict —
/// it is what `fingerprint()` compares, so folding there would make `中國` and
/// `中国` the same *drawer* for dedup, and it pins `ﬁ != fi`, `① != 1` and
/// surviving tatweel because rewriting those is editing, not normalizing.
///
/// This answers a different question: "would a person looking for one expect
/// the other?" A drawer written `قَرَأتُ الكِتَابَ` shares no whole-word token
/// with a query for `الكتاب`; `İzmir` tokenizes to `zmi`; `Straße` never meets
/// `strasse`; `٢٠٢٣` never meets `2023`; a PDF's `ﬁnal conﬁguration` never
/// meets `final configuration`. None of those are ranking problems — `search`
/// admits a hit on lexical evidence or a clearly positive cosine, so with the
/// default embedder the observable is an empty result set.
///
/// **Every fold here loses something, and the losses are real**: `ß→ss` merges
/// German `Masse`/`Maße`; the Arabic yeh fold merges `على` (upon) with `علي`
/// (a name); teh marbuta merges every feminine `-ة` noun with the masculine
/// `-ه` possessive (`كتابة` writing / `كتابه` his book); stripping Greek tonos
/// merges `πότε` (when) with `ποτέ` (never); `ё→е` merges `все` with `всё`.
/// They are taken because the unmarked spelling is the *default register* in
/// each of those orthographies — the corpus has already made the merge, and
/// keeping the marks does not preserve a distinction anyone maintains, it only
/// stops the marked minority from ever matching the unmarked majority. What is
/// lost is provenance, and it is lost only in the comparison key.
///
/// **A recorded over-merge, in the exact channel.** Stripping Greek accents
/// folds `πότε` (when) onto `ποτέ` (never), and `καλά` (well) onto `κάλα`.
/// Those become one token, so they meet by literal equality and are admitted
/// as though the drawer said the queried word — measured, at rank 1. This is
/// not a bug to revert: the accent strip is what lets an all-caps or
/// carelessly-typed Greek query find anything at all, and it is what makes our
/// fold comparable to Lucene's own accent-stripped Greek analysis. It is a
/// cost, it lands in the channel that admits, and it is written here because
/// five rounds of review looked straight past it.
///
/// **Comparison only**, exactly like [`match_key`]: stored bytes are verbatim,
/// drawer ids and [`NORMALIZE_VERSION`] do not move, and dedup keeps
/// [`match_key`].
pub fn search_key(s: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    // S0 — the ASCII path, which is most real input. No rule below has an
    // ASCII source codepoint, so lowercasing is the whole transform here.
    // `search_key_matches_the_fast_path_over_ascii` pins that invariant, and
    // any future table entry keyed on ASCII will fail it.
    if s.is_ascii() {
        return if s.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(s.to_ascii_lowercase())
        } else {
            Cow::Borrowed(s)
        };
    }
    let nfc = match_key(s);
    if !may_fold(&nfc) {
        return nfc;
    }
    Cow::Owned(fold(&nfc))
}

/// Cheap rejection: does this text contain anything any rule could touch?
///
/// A Cyrillic or Georgian corpus with no stress marks folds to itself, and
/// this is what keeps it from being rebuilt per candidate on every query.
fn may_fold(s: &str) -> bool {
    s.chars().any(|c| {
        c.is_uppercase()
            || matches!(c as u32,
                0x00AD | 0x00B5
                | 0x00C0..=0x024F
                | 0x0300..=0x036F
                | 0x0374..=0x03FF
                // Cyrillic is NOT a blanket range: only ё folds, and a loose
                // stress mark is caught by 0x0300..=0x036F above. Including
                // the block would rebuild every Russian drawer per candidate
                // to produce an identical string.
                | 0x0401 | 0x0451
                // Hebrew: only the points fold, and they all live here.
                | 0x0591..=0x05C7
                | 0x0600..=0x08FF
                | 0x115F | 0x1160
                | 0x180B..=0x180F
                | 0x1E00..=0x1FFF
                | 0x2E80..=0x2FD5
                // Only the ideographic numerals and the two loose voicing
                // marks — not the kana blocks, which fold to nothing.
                | 0x3007 | 0x3038..=0x303A | 0x3099..=0x309A | 0x3164 | 0x3192..=0x3195
                | 0xFB00..=0xFDFF
                | 0xFE00..=0xFFDC
                | 0xE0100..=0xE01EF)
    })
}

/// True for the Latin and Greek blocks whose diacritics fold (S5a).
fn latin_or_greek(c: char) -> bool {
    matches!(c as u32, 0x0041..=0x024F | 0x1E00..=0x1EFF | 0x0370..=0x03FF | 0x1F00..=0x1FFF)
}

fn cyrillic(c: char) -> bool {
    matches!(c as u32, 0x0400..=0x052F)
}

/// A mark or invisible that carries no lexical weight in the scripts we fold.
fn is_stripped(c: char) -> bool {
    matches!(c as u32,
        // S5d — invisibles that split a word today. ZWSP/ZWNJ/ZWJ are NOT
        // here on purpose: ZWSP is Khmer's word delimiter, ZWNJ splitting
        // `کتاب‌ها` yields an exact whole-word hit on the stem, and ZWJ is
        // contrastive in Malayalam and Sinhala. They must keep splitting.
        0x00AD | 0xFEFF | 0x034F | 0x180B..=0x180D | 0x180F
        | 0xFE00..=0xFE0F | 0xE0100..=0xE01EF
        // S5c — Arabic marks. Excluded deliberately: U+06DD (END OF AYAH),
        // U+06DE, U+06E9, U+08E2 are verse *separators* and stripping them
        // glues two ayahs into one word; U+06E5/U+06E6 are Lm vowel letters;
        // U+08D4..U+08DF and U+08E3..U+08E9 are Ajami tone marks that are
        // contrastive within one orthography.
        // U+0674 HIGH HAMZA is deliberately absent: the spec listed it as a
        // functional mark, but Unicode gives it category Lo — a base letter,
        // and a hamza carrier in Kazakh and Uyghur orthography. Lucene does
        // not strip it either. The guard test caught this.
        | 0x0640 | 0x0610..=0x061A | 0x064B..=0x065F | 0x0670
        | 0x06D6..=0x06DC | 0x06DF..=0x06E4 | 0x06E7 | 0x06E8 | 0x06EA..=0x06ED
        | 0x08CA..=0x08D3 | 0x08E0..=0x08E1 | 0x08EA..=0x08EF
        // S5e — Hebrew points (niqqud, and the cantillation marks above them).
        // Same argument as the Arabic harakat directly above: they are vowel
        // and chant notation, normally absent, and a vocalised drawer must
        // still answer an unvocalised query. Deliberately excluded: U+05BE
        // MAQAF is a hyphen, U+05C0 PASEQ and U+05C3 SOF PASUQ are verse
        // punctuation, and U+05C6 NUN HAFUKHA is an editorial mark — all four
        // are delimiters, and stripping them would glue two words into one.
        | 0x0591..=0x05BD | 0x05BF | 0x05C1..=0x05C2 | 0x05C4..=0x05C5 | 0x05C7
        // S3 residue — a voicing mark that failed to compose onto a
        // non-voicable base. Mn, and it would split the katakana run at
        // exactly the place S2 exists to repair.
        | 0x3099 | 0x309A
        // Hangul fillers: Lo, so they join a run and corrupt its bigrams.
        | 0x115F | 0x1160 | 0x3164)
}

/// S6 — letters that no decomposition can reach.
fn map_letter(c: char) -> Option<&'static str> {
    Some(match c as u32 {
        // Latin ligatures and long s. PDF extraction emits these constantly.
        0xFB00 => "ff",
        0xFB01 => "fi",
        0xFB02 => "fl",
        0xFB03 => "ffi",
        0xFB04 => "ffl",
        0xFB05 | 0xFB06 => "st",
        0x017F => "s",
        0x0133 => "ij",
        // Departs from the standard fold, which keeps a modifier letter no
        // user will type. Both sources are deprecated and vanishingly rare.
        0x0149 => "n",
        0x1E9A => "a",
        0x00DF => "ss",
        // No canonical decomposition exists for these, so NFD provably
        // cannot reach them: `Łódź` would otherwise fold to `łodz`.
        0x00E6 => "ae",
        0x00F8 => "o",
        0x0111 => "d",
        0x0140 | 0x0142 => "l",
        0x0153 => "oe",
        0x0167 => "t",
        0x0192 => "f",
        0x01C6 => "dz",
        0x01C9 => "lj",
        0x01CC => "nj",
        0x01F3 => "dz",
        0x0237 => "j",
        // We lowercase with the default algorithm, under which Turkish
        // capital I becomes `i`. Without this, `IĞDIR` and `Iğdır` are two
        // tokens for one word inside one document.
        0x0131 => "i",
        // Rust's Final_Sigma correctly does not fire before a case-ignorable
        // character, so Greek elision and the ano teleia split `μας`/`μασ`.
        0x03C2 | 0x03F2 => "\u{03C3}",
        0x03D0 => "\u{03B2}",
        0x00B5 => "\u{03BC}",
        // Russian orthography treats ё as optional and omits it by default.
        0x0451 => "\u{0435}",
        // Arabic alef, yeh, teh marbuta, heh, kaf: the unmarked spellings are
        // the majority convention, and Persian/Urdu keyboards emit different
        // codepoints for the same letters.
        0x0622 | 0x0623 | 0x0625 | 0x0671 | 0x0672 | 0x0673 | 0x0675 => "\u{0627}",
        0x0649 | 0x06CC => "\u{064A}",
        0x0629 | 0x06C3 => "\u{0647}",
        0x06C0..=0x06C2 => "\u{0647}",
        0x06A9 => "\u{0643}",
        // Arabic-Indic and Persian digits. Recall fix and precision fix in
        // one rule: `٢٠٢٣` currently *bigrams* as ٢٠/٠٢/٢٣, and ٢٠ occurs in
        // every year of this century, so digit bigrams are near-contentless
        // tokens that clear the relevance gate on their own. Folded, the run
        // leaves the Arabic script class and is emitted whole as `2023`.
        0x0660..=0x0669 => return ASCII_DIGITS.get(c as usize - 0x0660).copied(),
        0x06F0..=0x06F9 => return ASCII_DIGITS.get(c as usize - 0x06F0).copied(),
        _ => return None,
    })
}

const ASCII_DIGITS: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];

/// S2 — compatibility expansion, scoped to two block families.
///
/// Returns `None` when nothing fired, so S3's recomposition pass is skipped.
///
/// The guard is what keeps this from becoming blanket NFKC: `ﷺ` (18 chars,
/// category So) would inject a whole phrase into every religious drawer's term
/// frequency, and `﷼` (Sc) would turn a delimiter into letters and manufacture
/// cross-word bigrams. Only alphanumeric-to-alphanumeric expansions are taken.
fn expand_compat(s: &str) -> Option<String> {
    use unicode_normalization::char::decompose_compatible;
    if !s.chars().any(|c| {
        matches!(c as u32,
            0xFB50..=0xFDFF | 0xFE70..=0xFEFF | 0xFF01..=0xFFDC
            | 0x2E80..=0x2EF3 | 0x2F00..=0x2FD5 | 0x3038..=0x303A | 0x3192..=0x3195)
    }) {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut fired = false;
    for c in s.chars() {
        // Two explicit entries the range guard cannot express: the halfwidth
        // voicing marks, which S3 then composes onto the preceding kana.
        let explicit = match c as u32 {
            0xFF9E => Some('\u{3099}'),
            0xFF9F => Some('\u{309A}'),
            _ => None,
        };
        if let Some(m) = explicit {
            out.push(m);
            fired = true;
            continue;
        }
        let wide = matches!(c as u32, 0xFB50..=0xFDFF | 0xFE70..=0xFEFF | 0xFF01..=0xFFDC);
        let cjk = matches!(c as u32,
            0x2E80..=0x2EF3 | 0x2F00..=0x2FD5 | 0x3038..=0x303A | 0x3192..=0x3195);
        // The source-must-be-alphanumeric guard applies to the Arabic and
        // width forms only — it is what rejects `ﷺ` (So, 18 chars) and `﷼`
        // (Sc, a delimiter that would become letters). CJK radicals are
        // themselves So, so requiring it there would skip all 214 of them:
        // this is the one place a delimiter deliberately becomes a letter.
        if !(wide || cjk) || (wide && !c.is_alphanumeric()) {
            out.push(c);
            continue;
        }
        let mut d = String::new();
        decompose_compatible(c, |x| d.push(x));
        let n = d.chars().count();
        let ok = if cjk {
            n == 1 && d.chars().all(char::is_alphanumeric)
        } else {
            (1..=4).contains(&n) && d.chars().all(char::is_alphanumeric)
        };
        if ok && d != c.to_string() {
            out.push_str(&d);
            fired = true;
        } else {
            out.push(c);
        }
    }
    fired.then_some(out)
}

/// S2–S6 over text already known to need work.
fn fold(input: &str) -> String {
    use unicode_normalization::char::decompose_canonical;
    use unicode_normalization::UnicodeNormalization;

    // S2, then S3 — recompose only if S2 fired, or this is a second whole-
    // string normalization pass per candidate document. Composition is what
    // turns halfwidth ｶ + ﾞ into ガ rather than leaving a loose mark.
    let expanded = expand_compat(input);
    let recomposed: Option<String> = expanded.as_deref().map(|e| e.nfc().collect());
    let base: &str = recomposed.as_deref().unwrap_or(input);

    // S4 — must precede S5, because U+0130 İ is not a mark and S5 cannot see
    // it: lowercasing manufactures the U+0307 that S5 then removes. It must
    // also precede S6 so every table above is keyed on lowercase only.
    let lowered = base.to_lowercase();

    // S5 — marks and invisibles.
    let mut stripped = String::with_capacity(lowered.len());
    for c in lowered.chars() {
        if is_stripped(c) {
            continue;
        }
        // A loose combining mark: after NFC anything still standing alone is
        // decoration on the previous letter. On Cyrillic that can only be a
        // pedagogical stress mark (`мо́жет`), never part of ё/й/ѐ — those all
        // recompose — which is why Cyrillic gets this and nothing else.
        if matches!(c as u32, 0x0300..=0x036F) {
            match stripped.chars().last() {
                Some(p) if latin_or_greek(p) => continue,
                Some(p) if cyrillic(p) && matches!(c as u32, 0x0300 | 0x0301) => continue,
                _ => {}
            }
        }
        // S5a — a precomposed Latin or Greek letter with diacritics folds to
        // its base. The alphabetic-base test is load-bearing: eleven
        // codepoints in U+1F00..U+1FFF decompose to a non-letter base
        // (U+00A8, U+1FBF, U+1FFE, U+0060, U+00B4) and must be left alone.
        // A Cyrillic base is never taken here, so й stays й and ё is left to
        // the explicit map.
        let mut d = String::new();
        decompose_canonical(c, |x| d.push(x));
        let mut it = d.chars();
        match it.next() {
            Some(b) if d.chars().count() > 1 && b.is_alphabetic() && latin_or_greek(b) => {
                stripped.push(b);
                for rest in it {
                    if !matches!(rest as u32, 0x0300..=0x036F) {
                        stripped.push(rest);
                    }
                }
            }
            _ => stripped.push(c),
        }
    }

    // S6 — letters keyed on bare lowercase forms.
    let mut out = String::with_capacity(stripped.len());
    for c in stripped.chars() {
        match map_letter(c) {
            Some(m) => out.push_str(m),
            None => out.push(c),
        }
    }
    out
}

/// How much tidying the content can survive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NormalizeMode {
    /// Prose: tidy trailing whitespace and runs of blank lines, but never
    /// inside a fenced code block.
    #[default]
    Prose,
    /// Code and scripts: apply only the safety rules. Every byte of
    /// indentation and every blank line is preserved, because in a Python
    /// file leading whitespace *is* the semantics and a diff over trailing
    /// whitespace is a real change.
    Code,
}

/// The safety floor, applied in every mode: NUL and lone control characters
/// are removed (they corrupt terminals, logs, and C-string boundaries) and
/// CRLF/CR become LF so a hash is stable across platforms. `\n` and `\t`
/// always survive.
fn make_safe(input: &str) -> String {
    let unified = input.replace("\r\n", "\n").replace('\r', "\n");
    unified
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
        .collect()
}

/// True for a line that opens or closes a fenced code block (``` or ~~~).
fn is_fence(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("```") || t.starts_with("~~~")
}

/// Normalize verbatim content for storage. Strips NUL and lone control
/// characters and normalizes CRLF to LF in every mode; in
/// [`NormalizeMode::Prose`] it additionally trims trailing whitespace per
/// line and collapses 3+ blank lines to 2 — but not inside fenced code
/// blocks. The text is otherwise preserved byte-for-byte: Undercroft stores
/// verbatim, not summaries.
pub fn normalize_content_mode(input: &str, mode: NormalizeMode) -> String {
    let cleaned = make_safe(input);
    if mode == NormalizeMode::Code {
        // Safety only. Trim the outer blank lines so an id does not depend
        // on stray leading/trailing newlines, and change nothing within.
        return cleaned.trim_matches('\n').to_string();
    }
    let mut out = String::with_capacity(cleaned.len());
    let mut blank_run = 0usize;
    let mut in_fence = false;
    for line in cleaned.split('\n') {
        if is_fence(line) {
            in_fence = !in_fence;
            blank_run = 0;
        }
        if in_fence || is_fence(line) {
            // Inside a fence the line is content: no trimming, no collapsing.
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let line = line.trim_end();
        if line.is_empty() {
            blank_run += 1;
            if blank_run > 2 {
                continue;
            }
        } else {
            blank_run = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim_matches('\n').to_string()
}

/// Normalize prose content. Equivalent to
/// `normalize_content_mode(input, NormalizeMode::Prose)`.
pub fn normalize_content(input: &str) -> String {
    normalize_content_mode(input, NormalizeMode::Prose)
}

/// File extensions whose contents are code, scripts, or
/// whitespace-significant data. For these, leading indentation carries
/// meaning, a trailing space can be a real diff, and a run of blank lines is
/// how the author separated blocks — so they normalize in
/// [`NormalizeMode::Code`].
///
/// Kept explicit rather than "anything that is not .md/.txt": guessing wrong
/// towards Code is harmless (we simply preserve more), but guessing wrong
/// towards Prose silently edits a script, so the list only grows by
/// deliberate addition.
const CODE_EXTENSIONS: &[&str] = &[
    "asm",
    "bash",
    "bat",
    "c",
    "cc",
    "cfg",
    "clj",
    "conf",
    "cpp",
    "cs",
    "css",
    "csv",
    "cxx",
    "dart",
    "diff",
    "dockerfile",
    "ex",
    "exs",
    "f90",
    "fish",
    "go",
    "gradle",
    "graphql",
    "groovy",
    "h",
    "hpp",
    "hs",
    "html",
    "ini",
    "java",
    "jl",
    "js",
    "json",
    "jsonl",
    "jsx",
    "kt",
    "kts",
    "lisp",
    "lock",
    "lua",
    "m",
    "make",
    "mk",
    "ml",
    "nim",
    "nix",
    "patch",
    "php",
    "pl",
    "properties",
    "proto",
    "ps1",
    "psm1",
    "py",
    "pyi",
    "r",
    "rb",
    "rs",
    "sbt",
    "scala",
    "scm",
    "sh",
    "sql",
    "svg",
    "swift",
    "tf",
    "tfvars",
    "toml",
    "ts",
    "tsv",
    "tsx",
    "vb",
    "vim",
    "xml",
    "yaml",
    "yml",
    "zig",
    "zsh",
];

/// Filenames that are code or config even though they carry no extension.
const CODE_FILENAMES: &[&str] = &[
    "dockerfile",
    "makefile",
    "rakefile",
    "gemfile",
    "justfile",
    "procfile",
    "cmakelists.txt",
    ".gitignore",
    ".dockerignore",
    ".editorconfig",
    ".env",
];

/// Pick the normalization mode for a file path. Unknown and extensionless
/// files stay [`NormalizeMode::Prose`], the documented default; the choice
/// depends only on the path, so re-mining the same file always normalizes it
/// the same way.
pub fn mode_for_path(path: &std::path::Path) -> NormalizeMode {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if CODE_FILENAMES.contains(&name.as_str()) {
        return NormalizeMode::Code;
    }
    let ext = path
        .extension()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if CODE_EXTENSIONS.contains(&ext.as_str()) {
        NormalizeMode::Code
    } else {
        NormalizeMode::Prose
    }
}

/// Normalization exactly as v1 performed it. Retained as the reference the
/// regression tests check [`NormalizeMode::Prose`] against: prose without a
/// fenced block must still normalize byte-for-byte the way it always did, so
/// the v2 bump cannot quietly change existing behaviour.
#[cfg_attr(not(test), allow(dead_code))]
fn legacy_normalize_content(input: &str) -> String {
    let unified = input.replace("\r\n", "\n").replace('\r', "\n");
    let cleaned: String = unified
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
        .collect();
    let mut out = String::with_capacity(cleaned.len());
    let mut blank_run = 0usize;
    for line in cleaned.split('\n') {
        let line = line.trim_end();
        if line.is_empty() {
            blank_run += 1;
            if blank_run > 2 {
                continue;
            }
        } else {
            blank_run = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    // Drop the trailing newline we always append, then trim outer blank lines.
    out.trim_matches('\n').to_string()
}

/// Normalize a wing name the way mempalace does: lowercase, spaces to
/// hyphens, strip anything that is not alphanumeric, hyphen or underscore.
pub fn normalize_wing_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.trim().to_lowercase().chars() {
        match c {
            ' ' => out.push('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => out.push(c),
            _ => {}
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_nul_and_controls_keeps_tabs_newlines() {
        let s = "a\0b\x07c\td\ne";
        assert_eq!(normalize_content(s), "abc\td\ne");
    }

    #[test]
    fn collapses_blank_runs_and_crlf() {
        // 3 blank lines collapse to 2; CRLF is unified to LF.
        let s = "a\r\n\r\n\r\n\r\nb";
        assert_eq!(normalize_content(s), "a\n\n\nb");
        // 1 blank line is preserved as-is.
        assert_eq!(normalize_content("a\n\nb"), "a\n\nb");
    }

    #[test]
    fn wing_names() {
        assert_eq!(normalize_wing_name("My Project!"), "my-project");
        assert_eq!(normalize_wing_name("  Alice B  "), "alice-b");
    }

    // ---- v2: code-mode preservation -------------------------------------

    const PY: &str = "def f():\n    x = 1   \n\n\n\n    return x\n";

    #[test]
    fn code_mode_preserves_trailing_space_and_blank_runs() {
        let out = normalize_content_mode(PY, NormalizeMode::Code);
        assert!(
            out.contains("x = 1   "),
            "trailing space is a real diff: {out:?}"
        );
        assert!(
            out.contains("\n\n\n\n"),
            "blank runs are the author's blocks: {out:?}"
        );
    }

    #[test]
    fn code_mode_still_applies_the_safety_floor() {
        let out = normalize_content_mode("a\u{0}b\r\nc\u{7}d", NormalizeMode::Code);
        assert_eq!(out, "ab\ncd", "NUL/control must go in every mode");
    }

    #[test]
    fn code_mode_preserves_leading_indentation_exactly() {
        let src = "\tif True:\n\t\tpass\n";
        assert!(normalize_content_mode(src, NormalizeMode::Code).contains("\t\tpass"));
    }

    #[test]
    fn prose_mode_still_tidies_ordinary_text() {
        let out = normalize_content_mode("a   \n\n\n\nb", NormalizeMode::Prose);
        assert_eq!(out, "a\n\n\nb");
    }

    #[test]
    fn prose_mode_leaves_fenced_blocks_alone() {
        let src = "intro   \n\n```py\ndef f():\n    x = 1   \n\n\n\n    return x\n```\n\nafter   ";
        let out = normalize_content_mode(src, NormalizeMode::Prose);
        assert!(
            out.contains("x = 1   "),
            "fenced code keeps trailing space: {out:?}"
        );
        assert!(
            out.contains("\n\n\n\n"),
            "fenced code keeps blank runs: {out:?}"
        );
        assert!(
            out.starts_with("intro\n"),
            "prose outside the fence still tidies"
        );
        assert!(
            out.ends_with("after"),
            "prose after the fence still tidies: {out:?}"
        );
    }

    #[test]
    fn tilde_fences_count_too() {
        let out = normalize_content_mode("~~~\na   \n~~~", NormalizeMode::Prose);
        assert!(out.contains("a   "));
    }

    // ---- v2: regression against v1 --------------------------------------

    /// Prose containing no fence must normalize byte-for-byte the way v1
    /// did. This is the guarantee the NORMALIZE_VERSION bump rests on: v2
    /// changes behaviour *only* inside fences and *only* in Code mode.
    #[test]
    fn prose_without_fences_matches_v1_exactly() {
        for case in [
            "",
            "plain",
            "a   \nb\t\n",
            "trailing   ",
            "a\n\n\n\n\n\nb",
            "\n\n\nlead and trail\n\n\n",
            "a\u{0}b\r\nc",
            "line\twith\ttabs   \n\n\nnext",
            "unicode — em dash and  double  spaces   \n\n\n\nend",
            "mixed\r\nline\rendings\n",
        ] {
            assert_eq!(
                normalize_content(case),
                legacy_normalize_content(case),
                "v2 prose diverged from v1 on {case:?}",
            );
        }
    }

    #[test]
    fn normalize_content_defaults_to_prose() {
        let s = "a   \n\n\n\nb";
        assert_eq!(
            normalize_content(s),
            normalize_content_mode(s, NormalizeMode::Prose)
        );
        assert_eq!(NormalizeMode::default(), NormalizeMode::Prose);
    }

    #[test]
    fn normalization_is_idempotent_in_both_modes() {
        for mode in [NormalizeMode::Prose, NormalizeMode::Code] {
            let once = normalize_content_mode(PY, mode);
            assert_eq!(
                normalize_content_mode(&once, mode),
                once,
                "{mode:?} not idempotent"
            );
        }
    }

    // ---- v2: mode selection ---------------------------------------------

    #[test]
    fn code_paths_select_code_mode() {
        for p in [
            "a.py",
            "a.rs",
            "a.ts",
            "a.sh",
            "a.yaml",
            "a.json",
            "a.sql",
            "a.toml",
            "Makefile",
            "Dockerfile",
            "src/deep/mod.rs",
            "A.PY",
            ".gitignore",
        ] {
            assert_eq!(
                mode_for_path(std::path::Path::new(p)),
                NormalizeMode::Code,
                "{p} should be Code",
            );
        }
    }

    #[test]
    fn prose_paths_stay_prose() {
        for p in [
            "notes.md",
            "README.txt",
            "letter",
            "a.docx",
            "photo.png",
            "notes.markdown",
        ] {
            assert_eq!(
                mode_for_path(std::path::Path::new(p)),
                NormalizeMode::Prose,
                "{p} should be Prose",
            );
        }
    }

    #[test]
    fn a_mined_python_file_survives_round_trip() {
        // The regression this whole change exists for: mining a script must
        // not silently reformat it.
        let src = "import os\n\n\n\ndef main():\n    args = []   \n    return args\n";
        let mode = mode_for_path(std::path::Path::new("tool.py"));
        assert_eq!(normalize_content_mode(src, mode), src.trim_matches('\n'));
    }

    // ---- comparison keys, not content ------------------------------------

    /// Arabic أ is either one code point or alef plus a combining hamza. The
    /// two render identically and mean the same thing, so a fingerprint taken
    /// over raw bytes would call them different content and miss the
    /// duplicate — silently, since nothing on screen distinguishes them.
    #[test]
    fn canonically_equal_arabic_shares_one_key() {
        let composed = "أحمد";
        let decomposed = "\u{0627}\u{0654}\u{062D}\u{0645}\u{062F}";
        assert_ne!(
            composed.as_bytes(),
            decomposed.as_bytes(),
            "different bytes"
        );
        assert_eq!(match_key(composed), match_key(decomposed), "same text");
    }

    #[test]
    fn canonically_equal_latin_shares_one_key() {
        let composed = "caf\u{00E9}";
        let decomposed = "cafe\u{0301}";
        assert_ne!(composed, decomposed);
        assert_eq!(match_key(composed), match_key(decomposed));
    }

    /// Compatibility folding would make these equal. It is not applied,
    /// because rewriting ﬁ to fi changes the content rather than its encoding.
    #[test]
    fn compatibility_variants_stay_distinct() {
        assert_ne!(match_key("\u{FB01}le"), match_key("file"));
        assert_ne!(match_key("\u{2460}"), match_key("1"));
    }

    /// Tatweel is a character the writer typed, not a decomposition — folding
    /// it away here would be editing, so it survives here. `search_key` is
    /// where the retrieval consequence is dealt with; see its twin below.
    #[test]
    fn tatweel_is_not_removed() {
        assert_ne!(match_key("مـحـمد"), match_key("محمد"));
    }

    // ------------------------------------------------------------------
    // search_key — the retrieval fold
    // ------------------------------------------------------------------

    /// The two contracts, pinned against each other so neither drifts.
    #[test]
    fn search_key_folds_what_match_key_deliberately_keeps() {
        assert_eq!(search_key("مـحـمد"), search_key("محمد"), "tatweel");
        assert_eq!(search_key("\u{FB01}le"), "file", "fi ligature");
        // ...but the compatibility line is still drawn: a circled digit is
        // not a digit, exactly as match_key has it.
        assert_ne!(search_key("\u{2460}"), search_key("1"));
    }

    #[test]
    fn arabic_marks_and_letter_variants_fold() {
        assert_eq!(search_key("قَرَأتُ الكِتَابَ"), search_key("قرأت الكتاب"));
        // Alef, yeh, teh marbuta, and the Persian/Urdu keyboard letters.
        assert_eq!(search_key("أحمد"), search_key("احمد"));
        assert_eq!(search_key("مصطفى"), search_key("مصطفي"));
        assert_eq!(search_key("مدرسة"), search_key("مدرسه"));
        assert_eq!(search_key("کتاب"), search_key("كتاب"), "Persian kaf");
        // Arabic-Indic and Persian digits become digits.
        assert_eq!(search_key("٢٠٢٣"), "2023");
        assert_eq!(search_key("۲۰۲۳"), "2023");
    }

    /// The conflations this buys are real and are the accepted price. Pinned
    /// so nobody has to rediscover them from a bug report.
    #[test]
    fn the_folds_conflate_these_and_we_accept_it() {
        assert_eq!(search_key("على"), search_key("علي"), "upon / a name");
        assert_eq!(
            search_key("كتابة"),
            search_key("كتابه"),
            "writing / his book"
        );
        assert_eq!(
            search_key("Masse"),
            search_key("Maße"),
            "mass / measurements"
        );
        assert_eq!(search_key("πότε"), search_key("ποτέ"), "when / never");
        assert_eq!(search_key("все"), search_key("всё"), "all / everything");
    }

    /// The accent strip's own cost, pinned so it stays a known quantity
    /// rather than a surprise. These are distinct Greek words that the fold
    /// makes one token — and one token means the EXACT channel, which admits.
    #[test]
    fn stripping_greek_accents_merges_these_and_we_accept_it() {
        assert_eq!(search_key("πότε"), search_key("ποτέ"), "when / never");
        assert_eq!(search_key("καλά"), search_key("κάλα"));
        // Not everything collapses: the fold is accents, not letters.
        assert_ne!(search_key("κατάσταση"), search_key("κατάστημα"));
    }

    #[test]
    fn greek_tonos_and_final_sigma_fold() {
        assert_eq!(search_key("ΑΘΗΝΑ"), search_key("Αθήνα"));
        assert_eq!(search_key("ΟΔΟΣ"), search_key("οδός"));
        // Polytonic collapses through NFC plus the mark strip, no table.
        assert_eq!(search_key("ἀγαθός"), search_key("αγαθος"));
    }

    /// The İ case: lowercase manufactures a combining dot that the mark strip
    /// then removes, so no Turkic tailoring is needed and Turkish minimal
    /// pairs on ı/i are the only cost.
    #[test]
    fn turkish_dotted_capital_folds() {
        assert_eq!(search_key("İZMİR"), "izmir");
        assert_eq!(search_key("İzmir"), "izmir");
    }

    /// Letters with no canonical decomposition — NFD provably cannot reach
    /// these, which is why the explicit map exists.
    #[test]
    fn letters_nfd_cannot_reach_still_fold() {
        assert_eq!(search_key("ŁÓDŹ"), "lodz");
        assert_eq!(search_key("Straße"), "strasse");
        assert_eq!(search_key("Ø"), "o");
        assert_eq!(search_key("æon"), "aeon");
    }

    #[test]
    fn width_and_presentation_forms_fold() {
        assert_eq!(search_key("ＡＰＩ"), "api");
        assert_eq!(search_key("２０２４"), "2024");
        // Halfwidth kana composes onto its voicing mark rather than leaving
        // a loose one that would split the run.
        assert_eq!(search_key("ｶﾞ"), "ガ");
        assert!(!search_key("ﾝﾞ").contains('\u{3099}'));
        // A Kangxi radical is the same ideograph as far as retrieval goes.
        assert_eq!(search_key("\u{2F00}"), "\u{4E00}");
    }

    /// Cyrillic is the script where a blanket "decompose and strip marks"
    /// would have done damage: й decomposes to и + breve and ё to е + diaeresis.
    /// Only a *loose* stress mark folds, plus ё by explicit map.
    #[test]
    fn cyrillic_keeps_its_letters() {
        assert_eq!(search_key("йод"), "йод", "й must not become и");
        assert_eq!(search_key("мо́жет"), "может", "stress mark only");
        // Ukrainian і/ї and Belarusian ў are letters, not accented Russian.
        assert_eq!(search_key("їжак"), "їжак");
    }

    /// The whole change rests on this: a corpus with nothing to fold must not
    /// be rebuilt once per candidate on every query.
    #[test]
    fn text_with_nothing_to_fold_is_borrowed() {
        for s in ["привет мир", "იყო ერთი", "hello world", "こんにちは"]
        {
            assert!(
                matches!(search_key(s), std::borrow::Cow::Borrowed(_)),
                "{s:?} was rebuilt"
            );
        }
    }

    /// No rule may have an ASCII source codepoint, or the fast path lies.
    #[test]
    fn search_key_matches_the_fast_path_over_ascii() {
        for cp in 0u32..0x80 {
            let c = char::from_u32(cp).unwrap();
            let s = c.to_string();
            let fast = search_key(&s).into_owned();
            let full = fold(&s);
            assert_eq!(fast, full.to_lowercase(), "U+{cp:04X} diverges");
        }
    }

    /// Folding twice must equal folding once, or any index built on the key
    /// disagrees with a query folded on the way in.
    #[test]
    fn search_key_is_idempotent() {
        for cp in 0u32..0x11000 {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            let once = search_key(&c.to_string()).into_owned();
            let twice = search_key(&once).into_owned();
            assert_eq!(once, twice, "U+{cp:04X} is not idempotent");
        }
    }

    /// A toolchain Unicode bump must not silently start eating a letter
    /// inside a range we strip. Rust exposes no general-category API, so this
    /// allowlist is the only backstop.
    #[test]
    fn stripped_arabic_marks_are_never_letters() {
        const ALLOWED_ALPHABETIC: &[std::ops::RangeInclusive<u32>] = &[
            // Tatweel is Lm — a letter by category, elongation by function.
            // Stripping it is the deliberate difference from `match_key`.
            0x0640..=0x0640,
            0x0610..=0x061A,
            0x064B..=0x065F,
            0x0670..=0x0670,
            0x06D6..=0x06DC,
            0x06E1..=0x06E4,
            0x06E7..=0x06E8,
            0x06ED..=0x06ED,
        ];
        for cp in 0x0600u32..0x0900 {
            let c = char::from_u32(cp).unwrap();
            if !is_stripped(c) || !c.is_alphanumeric() {
                continue;
            }
            assert!(
                ALLOWED_ALPHABETIC.iter().any(|r| r.contains(&cp)),
                "U+{cp:04X} is alphanumeric and stripped but not on the allowlist"
            );
        }
    }

    /// Verse separators must keep splitting, or the last word of one ayah
    /// glues to the first of the next.
    #[test]
    fn quranic_separators_and_vowel_letters_survive() {
        for cp in [0x06DDu32, 0x06DE, 0x06E9, 0x08E2, 0x06E5, 0x06E6] {
            let c = char::from_u32(cp).unwrap();
            assert!(!is_stripped(c), "U+{cp:04X} must not be stripped");
        }
    }

    /// ZWSP is Khmer's word delimiter; ZWNJ splitting `کتاب‌ها` gives an exact
    /// whole-word hit on the stem; ZWJ is contrastive in Malayalam. All three
    /// split today and must keep splitting. Pinned so a future "strip the
    /// invisibles" cleanup cannot take them.
    #[test]
    fn zero_width_joiners_are_not_stripped() {
        for cp in [0x200Bu32, 0x200C, 0x200D] {
            let c = char::from_u32(cp).unwrap();
            assert!(!is_stripped(c), "U+{cp:04X} must not be stripped");
        }
    }

    /// The hot path is every fingerprint and every token, and almost all real
    /// input is already NFC, so the common case must not allocate.
    #[test]
    fn already_canonical_text_is_borrowed_not_rebuilt() {
        assert!(matches!(
            match_key("plain ascii and محمد alike"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    /// Comparison keys must never leak into what we store.
    #[test]
    fn normalization_does_not_compose_stored_content() {
        let decomposed = "cafe\u{0301}";
        assert_eq!(
            normalize_content(decomposed),
            decomposed,
            "stored bytes stay exactly as written"
        );
    }
}
