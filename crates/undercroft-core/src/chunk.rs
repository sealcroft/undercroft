//! Text chunking, mirroring mempalace's miner defaults:
//! 800-char chunks, 100-char overlap, 50-char minimum, split on paragraph
//! boundaries where possible so drawers stay readable.

#[derive(Debug, Clone, Copy)]
pub struct ChunkOptions {
    pub chunk_size: usize,
    pub overlap: usize,
    pub min_chunk: usize,
}

impl Default for ChunkOptions {
    fn default() -> Self {
        Self {
            chunk_size: 800,
            overlap: 100,
            min_chunk: 50,
        }
    }
}

/// Split normalized text into chunks. Prefers paragraph boundaries
/// (`\n\n`), falls back to a sliding window with overlap for oversized
/// paragraphs. Never splits inside a UTF-8 code point.
pub fn chunk_text(text: &str, opts: ChunkOptions) -> Vec<String> {
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }
    if text.len() <= opts.chunk_size {
        return vec![text.to_string()];
    }

    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();

    for para in text.split("\n\n") {
        let para = para.trim();
        if para.is_empty() {
            continue;
        }
        if current.len() + para.len() + 2 <= opts.chunk_size {
            if !current.is_empty() {
                current.push_str("\n\n");
            }
            current.push_str(para);
            continue;
        }
        if !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
        }
        if para.len() <= opts.chunk_size {
            current = para.to_string();
        } else {
            // Sliding window over an oversized paragraph.
            let bytes = para.as_bytes();
            let mut start = 0usize;
            while start < bytes.len() {
                let mut end = (start + opts.chunk_size).min(bytes.len());
                while end < bytes.len() && !para.is_char_boundary(end) {
                    end += 1;
                }
                while !para.is_char_boundary(start) {
                    start += 1;
                }
                chunks.push(para[start..end].to_string());
                if end == bytes.len() {
                    break;
                }
                let next = end.saturating_sub(opts.overlap);
                start = if next > start { next } else { end };
            }
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }

    // Merge a trailing runt into its predecessor.
    if chunks.len() >= 2 && chunks.last().map(|c| c.len() < opts.min_chunk) == Some(true) {
        let runt = chunks.pop().unwrap();
        let prev = chunks.last_mut().unwrap();
        prev.push_str("\n\n");
        prev.push_str(&runt);
    }
    chunks.retain(|c| !c.trim().is_empty());
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_single_chunk() {
        let out = chunk_text("hello world", ChunkOptions::default());
        assert_eq!(out, vec!["hello world"]);
    }

    #[test]
    fn paragraphs_grouped_under_limit() {
        let text = format!("{}\n\n{}", "a".repeat(300), "b".repeat(300));
        let out = chunk_text(&text, ChunkOptions::default());
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn oversized_paragraph_windows_with_overlap() {
        let text = "x".repeat(2000);
        let out = chunk_text(&text, ChunkOptions::default());
        assert!(out.len() >= 2);
        assert!(out.iter().all(|c| c.len() <= 800));
        let total: usize = out.iter().map(|c| c.len()).sum();
        assert!(total >= 2000); // overlap duplicates some bytes
    }

    #[test]
    fn utf8_boundaries_respected() {
        let text = "é".repeat(1200);
        let out = chunk_text(&text, ChunkOptions::default());
        assert!(out.iter().all(|c| c.chars().all(|ch| ch == 'é')));
    }
}
