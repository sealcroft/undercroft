//! Content normalization, mirroring mempalace's `normalize.py` contract:
//! deterministic cleanup applied before hashing so drawer ids are stable
//! across re-mines of the same source.

/// Bumped whenever normalization output changes; stored in drawer metadata
/// (mempalace's `normalize_version`) so a re-mine can detect stale drawers.
pub const NORMALIZE_VERSION: u32 = 1;

/// Normalize verbatim content: strip NUL bytes and lone control characters
/// (except \n and \t), normalize CRLF to LF, trim trailing whitespace per
/// line, and collapse 3+ blank lines to 2. The text itself is otherwise
/// preserved byte-for-byte — Undercroft stores verbatim, not summaries.
pub fn normalize_content(input: &str) -> String {
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
}
