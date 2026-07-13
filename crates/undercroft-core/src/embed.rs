//! Local, deterministic hashed n-gram embedder.
//!
//! Mempalace's default embedder is a downloaded sentence-transformer model.
//! For the Rust port we ship a zero-dependency feature-hashing embedder:
//! word unigrams + bigrams + character trigrams hashed into a fixed-width
//! vector, L2-normalized. It is deterministic, needs no network, and gives
//! useful lexical-semantic recall; a model-backed `Embedder` (ONNX) can be
//! plugged in behind the same trait later.

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
        let idx = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) as usize
            % EMBED_DIM;
        // Sign bit from an independent digest byte reduces hash-collision bias.
        let sign = if digest[4] & 1 == 0 { 1.0 } else { -1.0 };
        (idx, sign)
    }

    fn tokens(text: &str) -> Vec<String> {
        let lower = text.to_lowercase();
        let words: Vec<&str> = lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect();
        let mut toks: Vec<String> = Vec::with_capacity(words.len() * 3);
        for w in &words {
            toks.push(format!("u:{w}"));
        }
        for pair in words.windows(2) {
            toks.push(format!("b:{} {}", pair[0], pair[1]));
        }
        for w in &words {
            let chars: Vec<char> = w.chars().collect();
            if chars.len() > 3 {
                for tri in chars.windows(3) {
                    toks.push(format!("t:{}{}{}", tri[0], tri[1], tri[2]));
                }
            }
        }
        toks
    }
}

impl Embedder for HashEmbedder {
    fn model_name(&self) -> &str {
        "undercroft-hash-v1"
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
