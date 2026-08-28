//! Local, deterministic hashed n-gram embedder.
//!
//! Mempalace's default embedder is a downloaded sentence-transformer model.
//! For the Rust port we ship a zero-dependency feature-hashing embedder:
//! unigrams + bigrams + character trigrams over `script::segment`'s units,
//! hashed into a fixed-width vector and L2-normalized. It is deterministic,
//! needs no network, and gives useful lexical-semantic recall; a model-backed
//! `Embedder` (ONNX) can be plugged in behind the same trait later.
//!
//! It is feature hashing over **surface forms**, so it matches on shared
//! literal units and nothing else: `car` and `automobile` do not match, and
//! neither does a translation pair. Cross-lingual retrieval needs a real
//! multilingual model. What segmentation buys is the *within-language* case
//! that was silently broken — a Chinese or Khmer query sharing no feature at
//! all with a document that visibly contains it.

use sha2::{Digest, Sha256};

pub const EMBED_DIM: usize = 384;

pub trait Embedder {
    fn model_name(&self) -> &str;
    fn dimension(&self) -> usize;
    fn embed(&self, text: &str) -> Vec<f32>;

    /// The `semantic` score above which this vector space may admit a drawer
    /// on cosine evidence alone, or `None` for a space whose floor is not
    /// knowable here — in which case admission rests on the lexical channels
    /// and nothing else.
    ///
    /// **This is a property of the vector space, not of the search code**,
    /// which is the whole reason it lives on the trait. The gate was a single
    /// `const` calibrated to [`HashEmbedder`], whose unrelated-pair floor is
    /// almost exactly zero; feature hashing over surface forms puts texts that
    /// share no token at cosine ~0. A model embedder does not. E5- and
    /// BGE-family encoders put *unrelated* pairs near 0.75 in this same
    /// `semantic` space, so a gate of 0.56 is below their floor, the disjunct
    /// is vacuously true for every hit, and the store's relevance gate is
    /// retired for every query in every language — silently, by configuration
    /// rather than by code.
    ///
    /// The default implementation **measures** the embedder in hand
    /// ([`calibrate_admission_gate`]) rather than guessing from its name.
    /// Reading what a model actually does to known-unrelated text is evidence;
    /// deriving a gate from the string `bge-m3` would be inference, and this
    /// project does not infer. An implementation that knows its own floor
    /// should override and say so.
    fn semantic_admission_gate(&self) -> Option<f32> {
        calibrate_admission_gate(self)
    }

    /// Whether [`Self::semantic_admission_gate`] MEASURED this vector space or
    /// returned a constant the implementation declares (ROADMAP O72).
    ///
    /// The distinction is invisible from the value alone and an operator
    /// cannot otherwise recover it: the default implementation probes, while
    /// [`HashEmbedder`] deliberately declares its gate so the default vault
    /// pays no forward passes at open. Reported on `PalaceStats`, because "my
    /// semantic channel contributes nothing" and "my semantic channel was
    /// never measured" are different situations with different remedies.
    fn semantic_gate_is_measured(&self) -> bool {
        true
    }

    /// The raw cosine this vector space gives known-unrelated text — the
    /// zero point the store's cosine→`semantic` map is calibrated against —
    /// or `None` for a space whose floor is not knowable here (the store
    /// then keeps the floor-0 map, which is the shipped hash map).
    ///
    /// **Why the map needs this and a gate alone is not enough** (found by
    /// the first real xlingual run): the shipped map `(cos+1)/2` sends
    /// cosine 0 to `semantic` 0.5 — correct for [`HashEmbedder`], whose
    /// unrelated floor IS ~0. A served model puts unrelated text near
    /// cosine 0.5, so its whole semantic range compresses into the top
    /// quarter of the scale while BM25's lexical channel spans all of it —
    /// and same-language function-word overlap out-scores a cross-lingual
    /// translation gold at every fusion weight. The same
    /// one-constant-for-every-embedder defect class as the gate, one
    /// channel over. Calibrated, the map sends the measured floor to 0.5
    /// and 1.0 to 1.0, restoring the channel's dynamic range without
    /// moving the hash vault by a byte (floor 0 reproduces the shipped map
    /// exactly).
    ///
    /// The default implementation measures the same probe pairs the gate
    /// uses; a zero-vector probe is an inference failure and refuses, for
    /// the reasons documented on [`calibrate_admission_gate`].
    fn semantic_floor(&self) -> Option<f32> {
        calibrate_semantic_floor(self)
    }
}

/// Pairs of texts that share no subject, used to find where a vector space
/// puts things that have nothing to do with each other.
///
/// Ours, written for this purpose: ordinary sentences about ordinary things,
/// quoted from nothing.
///
/// **Half are same-language on purpose.** A cross-lingual probe set alone
/// measures the wrong floor: two unrelated sentences in *one* language share
/// function words, register and syntax, and a model scores them well above an
/// unrelated pair that also happens to cross a script boundary. Calibrating on
/// cross-lingual pairs only would therefore under-estimate the floor and leave
/// the gate partly retired — the exact failure this is here to close. The
/// cross-lingual half is kept because a multilingual model's floor is also a
/// cross-lingual property, and the four English-anchored pairs are the ones
/// `the_semantic_gate_is_calibrated_to_the_default_embedder` already pins.
const UNRELATED_PROBES: [(&str, &str); 14] = [
    // Cross-lingual.
    ("the quarterly revenue report", "私は昨日公園へ行きました"),
    ("kubernetes cluster autoscaling", "ذهبت إلى المستشفى أمس"),
    (
        "my cat sleeps on the windowsill",
        "πήγα στην Αθήνα το καλοκαίρι",
    ),
    (
        "database migration rollback",
        "그는 어제 서울에서 회의에 참석했습니다",
    ),
    ("она читает книгу по вечерам", "the bridge was repainted"),
    ("der Zug fährt um sieben Uhr ab", "海の水はとても冷たかった"),
    ("मैंने कल एक नई किताब खरीदी", "the servers rebooted overnight"),
    // Same-language, and these are the ones that set the floor.
    (
        "the compiler emitted three warnings",
        "she planted tulips along the fence",
    ),
    (
        "اشترى سيارة جديدة الأسبوع الماضي",
        "الطبخ يحتاج إلى صبر طويل",
    ),
    (
        "поезд опоздал на двадцать минут",
        "она изучает историю искусства",
    ),
    (
        "der Drucker ist schon wieder kaputt",
        "im Sommer schwimmen wir im See",
    ),
    (
        "το ψωμί τελείωσε νωρίς το πρωί",
        "ο υπολογιστής χρειάζεται επισκευή",
    ),
    ("会議は三時に始まります", "この靴は少し小さいです"),
    ("他昨天修好了自行车", "这份报告需要重新排版"),
];

/// Headroom between the measured floor and the gate, in `semantic` space.
///
/// 0.06, which is not a new number: the hand-derived [`HASH_ADMISSION_GATE`]
/// is 0.56 against a floor of ~0.50, so this is that gate's own headroom
/// carried across rather than re-invented. It is the one part of the
/// calibration that is a convention rather than a measurement, and it is
/// stated here so it can be argued with.
const ADMISSION_MARGIN: f32 = 0.06;

/// Cosine 0 in `semantic` space — two vectors with nothing in common.
const NEUTRAL: f32 = 0.5;

/// Measure where an embedder puts known-unrelated text, and return a gate a
/// margin above the worst case.
///
/// `None` means "do not admit on semantic evidence alone". That is returned
/// when any probe embeds to the zero vector, because a zero vector is exactly
/// how both model backends report an *inference failure*
/// (`embed_inner(..).unwrap_or_else(|_| vec![0.0; dim])`). Calibrating through
/// one would measure the failure rather than the model and hand back a
/// hash-shaped gate near 0.56 — which a later *successful* inference would
/// sail straight over, reintroducing the retired-gate bug through the back
/// door. It is also what makes an [`ExternalEmbedder`] fall out correctly, its
/// `embed` being all-zeros by construction, though that one overrides
/// explicitly rather than relying on the accident.
///
/// **The estimator is max-of-14 and that is crude.** It is conservative in the
/// direction that matters — the gate clears every unrelated pair observed —
/// but 14 pairs cannot describe a distribution, and a model whose floor is
/// genuinely higher than anything here will still admit too much. An operator
/// who has measured their own corpus should declare the result rather than
/// trust this (`UNDERCROFT_SEMANTIC_GATE`).
pub fn calibrate_admission_gate<E: Embedder + ?Sized>(e: &E) -> Option<f32> {
    // The store's cosine→semantic map is calibrated to this same measured
    // floor (`semantic_floor`), which by construction lands every measured
    // embedder's unrelated worst case at NEUTRAL in `semantic` space — so
    // the gate is simply the margin above neutral, the exact headroom the
    // hand-derived hash gate always had. Measuring the floor is still what
    // decides whether a gate exists at all: a zero-vector probe refuses.
    calibrate_semantic_floor(e).map(|_| (NEUTRAL + ADMISSION_MARGIN).clamp(NEUTRAL, 1.0))
}

/// Measure the raw cosine an embedder gives its worst known-unrelated
/// probe pair — the calibration zero for the cosine→`semantic` map.
/// `None` when any probe embeds to the zero vector (inference failure;
/// see [`calibrate_admission_gate`]). Clamped short of 1.0 so the map's
/// denominator can never vanish: a space that puts unrelated text at
/// cosine ~1 has no usable semantic channel and the clamp keeps the
/// arithmetic honest while the gate (unclearable at 1.0) says so.
pub fn calibrate_semantic_floor<E: Embedder + ?Sized>(e: &E) -> Option<f32> {
    let mut floor = 0.0f32;
    for (a, b) in UNRELATED_PROBES {
        let (va, vb) = (e.embed(a), e.embed(b));
        if va.iter().all(|x| *x == 0.0) || vb.iter().all(|x| *x == 0.0) {
            return None;
        }
        let c = cosine(&va, &vb);
        if c > floor {
            floor = c;
        }
    }
    Some(floor.clamp(0.0, 0.98))
}

#[derive(Debug, Default, Clone)]
pub struct HashEmbedder;

impl HashEmbedder {
    fn bucket(token: &str) -> (usize, f32) {
        let digest = Sha256::digest(token.as_bytes());
        let idx =
            u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) as usize % EMBED_DIM;
        // Sign bit from an independent digest byte reduces hash-collision bias.
        let sign = if digest[4] & 1 == 0 { 1.0 } else { -1.0 };
        (idx, sign)
    }

    /// Feature units for one text.
    ///
    /// Canonicalized and segmented by exactly the same rules the store's
    /// tokenizer uses. Both were previously `split(|c| !c.is_alphanumeric())`
    /// written out twice, in two crates, and they had drifted apart in two
    /// ways that mattered:
    ///
    /// * No `match_key`, so NFC and NFD spellings of the same word produced
    ///   different buckets. Composed `أحمد` and its decomposed twin shared
    ///   one feature of three; `ёлка`, `οδός` and `más` shared **none**. The
    ///   store folded, this did not, and on a sealed vault this is the only
    ///   retrieval signal there is.
    /// * No segmentation, so a Chinese clause hashed as a single feature and
    ///   the character-trigram family — the one thing that might have
    ///   rescued it — never fired, because its gate is `chars.len() > 3` and
    ///   a two-character query like `北京` never reached it.
    fn tokens(text: &str) -> Vec<String> {
        let key = crate::normalize::search_key(text);
        // Unfiltered on purpose: one-letter words carry meaning here
        // (`vitamin C`), even though BM25 drops them.
        let words = crate::script::segment(&key).tokens;
        let mut toks: Vec<String> = Vec::with_capacity(words.len() * 3);
        for w in &words {
            toks.push(format!("u:{w}"));
        }
        for pair in words.windows(2) {
            toks.push(format!("b:{} {}", pair[0], pair[1]));
        }
        for w in &words {
            let chars: Vec<char> = w.chars().collect();
            // A three-character word emits NO subword feature at all. That is
            // why `run` cannot meet `running` on the cosine leg: `running`
            // contributes `t:run`, `run` contributes nothing, and the pair
            // scores exactly 0.0000 — an open gap, recorded here because the
            // gate is where someone will come looking for it.
            //
            // Lowering it to `> 2` was measured and rejected. It does close the
            // bare pair (cosine 0.0000 -> 0.1361, semantic 0.5680 against a
            // 0.5600 gate) but with 0.0080 of headroom that does not survive a
            // real drawer — at 10-40 words of context it admits 2-4 times in 20
            // against 1-2 before. The cost is permanent and corpus-wide,
            // because a whole-word trigram shares a bucket with the same
            // trigram interior to longer words: `t:the` went 770 -> 5,074 on
            // this repo's prose, function-word trigram mass 1.86% -> 4.80%, and
            // cosine-arm admissions +18.7% over twelve realistic queries. The
            // two effects are inseparable — the bucket collision that lets
            // whole-word `run` meet interior `run` in `running` is the same one
            // that makes `the` collide with `there`, `other` and `theme`. And
            // it would cost a v4 identity: a re-embed per vault, PQ dropped,
            // every remote mirror `IndexStale`.
            if chars.len() > 3 {
                for tri in chars.windows(3) {
                    toks.push(format!("t:{}{}{}", tri[0], tri[1], tri[2]));
                }
            }
        }
        toks
    }
}

/// Identity of the default embedder.
///
/// `v2` canonicalizes with `match_key` and segments with `script::segment`,
/// so it puts different vectors in the index than `v1` did for the same text.
/// The name is the thing that makes that visible: a vault records it, and an
/// open that finds a different one is a migration, not a silent swap. See
/// `PalaceStore::open_with_embedder`.
/// v1: no fold, no segmentation. v2: `search_key` + `script::segment`.
/// v3: Brahmic conjuncts are one word rather than fragments.
///
/// v2 was never released — no tag carries it and `origin/main` still holds v1 —
/// so it could have been redefined in place a second time, and the research
/// recommended exactly that to avoid a permanent migration row for a version
/// nobody ran. Minting v3 anyway, because the argument cuts the other way once
/// the token set changes twice on one branch: anyone who built a vault from an
/// intermediate commit holds v2 vectors that a redefinition would leave stale
/// and unmigrated, with the identity matching and therefore no warning and no
/// `UNDERCROFT_FORCE_EMBEDDER` escape. Silently stale vectors are the failure
/// class this whole series exists to remove; one extra tuple is cheaper than
/// making an exception to it.
pub const HASH_EMBEDDER_V1: &str = "undercroft-hash-v1";
pub const HASH_EMBEDDER_V2: &str = "undercroft-hash-v2";
pub const HASH_EMBEDDER: &str = "undercroft-hash-v3";

/// The `semantic` score above which [`HashEmbedder`] admits on cosine alone.
///
/// Declared rather than calibrated, and deliberately so: this is the
/// hand-derived number the store shipped, measured against this embedder, and
/// re-deriving it at open would move it by a hundredth and shift which pairs
/// admit across a battery that pins several of them at "a hair over the gate".
/// `semantic` is `(cosine + 1) / 2`, so 0.56 is a raw cosine of 0.12 — chosen
/// because feature hashing over surface forms puts unrelated text at almost
/// exactly zero. `the_semantic_gate_is_calibrated_to_the_default_embedder` is
/// the acceptance test.
///
/// It is also length-sensitive in a way nothing else records: measured, a typo
/// pair and a false friend both admit on a bare pair (0.85, 0.78) and stop
/// admitting past ~40 words, while a true morphological pair (`книга`/`книге`)
/// stops admitting at 20. Admission on this leg tracks drawer length as much
/// as relatedness, which is why lexical evidence is what the gate should
/// mostly rest on.
pub const HASH_ADMISSION_GATE: f32 = 0.56;

impl Embedder for HashEmbedder {
    fn model_name(&self) -> &str {
        HASH_EMBEDDER
    }

    fn dimension(&self) -> usize {
        EMBED_DIM
    }

    fn semantic_admission_gate(&self) -> Option<f32> {
        Some(HASH_ADMISSION_GATE)
    }

    /// DECLARED, not measured — see [`Self::semantic_floor`] below for why.
    fn semantic_gate_is_measured(&self) -> bool {
        false
    }

    /// DECLARED zero, not measured: feature hashing over surface forms
    /// puts texts sharing no token at cosine ~0, and the shipped
    /// `(cos+1)/2` map IS the floor-0 calibration — declaring it keeps
    /// the default vault byte-identical and pays no probe embeds at open.
    fn semantic_floor(&self) -> Option<f32> {
        Some(0.0)
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0f32; EMBED_DIM];
        for tok in Self::tokens(text) {
            let (idx, sign) = Self::bucket(&tok);
            v[idx] += sign;
        }
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut v {
                *x /= norm;
            }
        }
        v
    }
}

/// Identity for a vault whose embeddings are supplied by the caller rather
/// than computed locally. Some platforms already own an embedding space
/// (they embed through their own model gateway for spend attribution and
/// share one space across ingest, sync, and migration); such a vault stores
/// caller-provided vectors and never runs a local model.
///
/// The recorded identity is `external:<name>@<dim>` — `model_name()` is
/// `external:<name>` and `dimension()` is `<dim>`, so it enforces exactly
/// like any other embedder identity (a silent model/dimension swap is
/// still refused). `embed()` is never reached: the store requires a vector
/// on every write to an external vault and refuses auto-embedding here.
#[derive(Debug, Clone)]
pub struct ExternalEmbedder {
    name: String,
    dim: usize,
}

impl ExternalEmbedder {
    /// `name` is the bare model name (no `external:` prefix); it is stored
    /// prefixed so the recorded identity is self-describing.
    pub fn new(name: &str, dim: usize) -> Self {
        Self {
            name: format!("external:{name}"),
            dim,
        }
    }
}

impl Embedder for ExternalEmbedder {
    fn model_name(&self) -> &str {
        &self.name
    }

    fn dimension(&self) -> usize {
        self.dim
    }

    fn embed(&self, _text: &str) -> Vec<f32> {
        // Unreachable in normal operation — external vaults are written and
        // searched with caller-supplied vectors. A zero vector is a safe
        // degradation (cosine 0) rather than a panic if some path slips
        // through the store's guards.
        vec![0.0; self.dim.max(1)]
    }

    /// Unknown, and unknowable from here.
    ///
    /// There is no local model to measure: `embed` above is never reached, and
    /// `search_with_vector` scores a caller-supplied query vector against
    /// caller-supplied drawer vectors, so every `semantic` on this path is a
    /// real cosine from a real model this process has never seen. Before this
    /// was a per-embedder property such a vault was gated at 0.56, i.e. at
    /// [`HashEmbedder`]'s floor — which for the gateway-hosted encoders these
    /// vaults actually use is well *below* their unrelated floor, so a query
    /// with no good match returned whatever ranked highest instead of nothing.
    ///
    /// Refusing is the only honest answer and it errs in the safe direction:
    /// it can narrow admission, never widen it. The remedy is a declaration —
    /// `UNDERCROFT_SEMANTIC_GATE=<measured value>` — not a guess made here.
    fn semantic_admission_gate(&self) -> Option<f32> {
        None
    }

    /// Nothing was measured: the vectors come from a model this process has
    /// never seen, so there was no probe to run.
    fn semantic_gate_is_measured(&self) -> bool {
        false
    }

    /// `None` for the same reason as the gate: the vectors come from a
    /// model this process has never seen, so there is no floor to measure
    /// — the store keeps the floor-0 map and the caller may declare one
    /// (`UNDERCROFT_SEMANTIC_FLOOR`) from their own measurement.
    fn semantic_floor(&self) -> Option<f32> {
        None
    }
}

/// Parse an `external:<name>@<dim>` embedder spec into `(name, dim)` with
/// the `external:` prefix stripped. Returns `None` if it is not an external
/// spec or the dimension is missing / unparseable.
pub fn parse_external_spec(spec: &str) -> Option<(String, usize)> {
    let rest = spec.strip_prefix("external:")?;
    let (name, dim) = rest.rsplit_once('@')?;
    let dim: usize = dim.parse().ok()?;
    if name.is_empty() || dim == 0 {
        return None;
    }
    Some((name.to_string(), dim))
}

/// Cosine similarity between two same-width vectors.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let e = HashEmbedder;
        assert_eq!(e.embed("hello world"), e.embed("hello world"));
    }

    /// The store folded encodings before comparing and this did not, so on a
    /// sealed vault — where cosine is the only retrieval signal there is —
    /// the same word written two legal ways landed in different buckets.
    #[test]
    fn one_word_in_two_encodings_is_one_vector() {
        let e = HashEmbedder;
        for (composed, decomposed) in [
            (
                "\u{0623}\u{062D}\u{0645}\u{062F}",
                "\u{0627}\u{0654}\u{062D}\u{0645}\u{062F}",
            ),
            (
                "\u{0451}\u{043B}\u{043A}\u{0430}",
                "\u{0435}\u{0308}\u{043B}\u{043A}\u{0430}",
            ),
            ("caf\u{00E9}", "cafe\u{0301}"),
        ] {
            assert_ne!(composed, decomposed, "the test inputs must differ as bytes");
            assert_eq!(
                e.embed(composed),
                e.embed(decomposed),
                "{composed:?} vs {decomposed:?}"
            );
        }
    }

    /// The cosine leg folds too. On a sealed vault it is the only retrieval
    /// signal, so if it disagreed with the tokenizer about what a word is,
    /// there would be nothing to fall back to.
    #[test]
    fn the_embedder_folds_like_the_tokenizer() {
        let e = HashEmbedder;
        assert_eq!(e.embed("كِتَاب"), e.embed("كتاب"), "harakat");
        assert_eq!(e.embed("İZMİR"), e.embed("izmir"), "Turkish dotted capital");
        assert_eq!(e.embed("Straße"), e.embed("strasse"), "sharp s");
        assert_eq!(e.embed("٢٠٢٣"), e.embed("2023"), "Arabic-Indic digits");
        assert_eq!(e.embed("ΑΘΗΝΑ"), e.embed("Αθήνα"), "Greek tonos");
    }

    /// A two-character CJK query never reached the trigram family — its gate
    /// is `chars.len() > 3` — so it shared no feature at all with a document
    /// that hashed a whole clause into one bucket.
    #[test]
    fn a_short_cjk_query_shares_features_with_its_document() {
        let e = HashEmbedder;
        let q = e.embed("北京");
        let doc = e.embed("我昨天去了北京参加会议");
        let other = e.embed("今天天气很好适合散步");
        assert!(cosine(&q, &doc) > 0.0, "no shared feature at all");
        assert!(cosine(&q, &doc) > cosine(&q, &other));
    }

    /// One-letter words are meaningful here even though BM25 drops them.
    #[test]
    fn single_letter_words_still_count() {
        let e = HashEmbedder;
        assert_ne!(e.embed("vitamin c"), e.embed("vitamin d"));
    }

    #[test]
    fn related_text_scores_higher_than_unrelated() {
        let e = HashEmbedder;
        let q = e.embed("why did we switch to graphql");
        let related = e.embed("we decided to switch to graphql because rest was too chatty");
        let unrelated = e.embed("the cat sat on the windowsill in the sun");
        assert!(cosine(&q, &related) > cosine(&q, &unrelated));
    }

    #[test]
    fn normalized() {
        let e = HashEmbedder;
        let v = e.embed("some text to embed");
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
    }
}
