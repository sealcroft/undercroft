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

impl Embedder for HashEmbedder {
    fn model_name(&self) -> &str {
        HASH_EMBEDDER
    }

    fn dimension(&self) -> usize {
        EMBED_DIM
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
