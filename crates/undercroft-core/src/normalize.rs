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
}
