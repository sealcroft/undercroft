//! Heuristic entity detection, ported from mempalace's `entity_detector.py`
//! spirit: no models, no network — capitalized-token heuristics good enough
//! to tag drawers and build co-occurrence hallways.

use std::collections::BTreeSet;

const STOPWORDS: &[&str] = &[
    "the",
    "this",
    "that",
    "these",
    "those",
    "a",
    "an",
    "i",
    "we",
    "you",
    "he",
    "she",
    "it",
    "they",
    "my",
    "our",
    "your",
    "their",
    "if",
    "when",
    "then",
    "and",
    "or",
    "but",
    "so",
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "today",
    "tomorrow",
    "yesterday",
    "ok",
    "yes",
    "no",
    "hi",
    "hello",
];

/// Extract likely entity names: capitalized words and capitalized multi-word
/// runs ("Alice", "Blue Heron"), excluding sentence-initial noise via a
/// stopword list. Returned lowercase, deduplicated, sorted.
pub fn extract_entities(text: &str) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for sentence in text.split(|c: char| ".!?\n".contains(c)) {
        let words: Vec<&str> = sentence.split_whitespace().collect();
        let mut run: Vec<String> = Vec::new();
        for (i, raw) in words.iter().enumerate() {
            let word: String = raw
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '\'')
                .collect();
            let is_cap = word
                .chars()
                .next()
                .map(|c| c.is_uppercase())
                .unwrap_or(false)
                && word.chars().skip(1).any(|c| c.is_lowercase());
            if is_cap && !STOPWORDS.contains(&word.to_lowercase().as_str()) {
                // Sentence-initial single capitals are usually just grammar;
                // only count them if they re-appear mid-sentence elsewhere,
                // which the multi-pass below approximates by requiring
                // position > 0 unless part of a multi-word run.
                run.push(word);
                let _ = i;
            } else {
                flush_run(&mut run, &mut out, i);
            }
        }
        flush_run(&mut run, &mut out, words.len());
    }
    out.into_iter().collect()
}

fn flush_run(run: &mut Vec<String>, out: &mut BTreeSet<String>, end_index: usize) {
    if run.is_empty() {
        return;
    }
    let start_index = end_index - run.len();
    if run.len() >= 2 {
        out.insert(run.join(" ").to_lowercase());
    } else if start_index > 0 {
        // Single capitalized word not at sentence start.
        out.insert(run[0].to_lowercase());
    }
    run.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_names_and_multiword() {
        let ents = extract_entities("Yesterday Alice met Bob Smith at the Acme office.");
        assert!(ents.contains(&"alice".to_string()));
        assert!(ents.contains(&"bob smith".to_string()));
        assert!(ents.contains(&"acme".to_string()));
    }

    #[test]
    fn skips_sentence_initial_grammar_words() {
        let ents = extract_entities("The meeting went fine. This is good.");
        assert!(ents.is_empty());
    }
}
