//! The binaries' two output streams, and what their fate does to the exit
//! status (ROADMAP O287).
//!
//! Rust ignores `SIGPIPE`, so a write to a pipe whose reader has gone returns
//! `EPIPE`, and `println!` PANICS on it: exit 101, a status no document
//! defines, and a panic text on stderr. Worse, the panic skips whatever the
//! command does after the print, and most verdicts here are printed before
//! they are decided — `verify | head` over a tampered vault answered 101
//! where the doctrine promises 2.
//!
//! So every stdout write the code of `undercroft` and
//! `undercroft-orchestrator` makes goes through ONE door — the one write that
//! does not is the telemetry build's `UNDERCROFT_LOG_FORMAT=json` log layer,
//! which tracing points at stdout (ROADMAP O333) — and the door never panics,
//! never returns an error and never
//! exits. On `BrokenPipe` it LATCHES — it records that the reader left and
//! discards everything written after — and the command runs on to its own
//! verdict. Any other stdout error (`ENOSPC`, `EIO`) is a run failure. The
//! binary's `main` flushes the door explicitly ([`finish`]) and folds the
//! result into its exit status in one place ([`exit_status`]): an integrity
//! verdict 2, then a run failure 1, then the reader leaving 141, then 0.
//!
//! **Reader-left comes from this latch and from nothing else.** An
//! `io::ErrorKind::BrokenPipe` found in an error chain is never read as one:
//! an outbound socket raises the same kind, and a refine whose model endpoint
//! hung up is a failed run, not a closed stdout.
//!
//! Its home is this crate because both binaries already link it, it has no
//! dependency by default, and it already owns the diagnostic path to stderr —
//! one implementation of the decision rather than one per binary.
//!
//! The stderr half is `errln!`: a best-effort line that cannot panic, for
//! the lines a binary prints on its exit path, or `cmd 2>&1 | reader` still
//! turns an exit 2 into 101 at the final error print. It latches nothing — a
//! closed stderr changes no exit status. The default build's diagnostic
//! macros (`diag_*!`) write through it too (ROADMAP O328).
//!
//! The source gates at the end of this file count every print in both
//! binaries' sources and in every crate's production code, cfg-gated code
//! included, because no lint leg compiles the model features (ROADMAP O153).
//! They read text: a library that writes to a stream on its own is outside
//! them, which is how O333's log layer stood beside the first of them.

use std::fmt;
use std::io::{self, Write};
use std::sync::{Mutex, PoisonError};

/// Exit 0 — the command ran, and no write to its stdout failed. Not a proof
/// of delivery: output that fits in a pipe's buffer is accepted in full by
/// the pipe, so a reader that dies after the last write leaves the run at 0.
/// Only an export's payload digest, checked at import, sees that.
pub const EXIT_SUCCESS: u8 = 0;
/// Exit 1 — the run itself failed: bad arguments, a missing file, an
/// unreadable vault, or a standard output that could not be written for any
/// reason other than its reader leaving. A script may retry it.
pub const EXIT_FAILURE: u8 = 1;
/// Exit 2 — an INTEGRITY VERDICT: stored evidence does not verify. Reserved
/// for that and nothing else, and it outranks every other class.
pub const EXIT_INTEGRITY: u8 = 2;
/// Exit 141 — the reader of standard output went away before the output was
/// complete. The command ran to its own end, and found no integrity verdict
/// and no failure; what it printed after the reader left was discarded. Not
/// a failed run to retry — a retry of a write that committed files it again —
/// and not a verdict. 141 is 128 + `SIGPIPE`, the status a POSIX shell
/// reports for this event; the binaries return it as an ordinary exit code,
/// so it is the same number on Windows, which has no `SIGPIPE`.
pub const EXIT_READER_LEFT: u8 = 141;

/// What became of everything the process wrote to its standard output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// No write failed, the explicit flush included (see [`EXIT_SUCCESS`] for
    /// what that does not prove).
    Delivered,
    /// The reader went away; everything written after was discarded.
    ReaderLeft,
    /// A write failed for another reason (`ENOSPC`, `EIO`): a run failure.
    /// Carries the error's text for the one line `main` prints about it.
    Failed(String),
}

/// How the command itself ended, as its binary classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Run {
    /// The command reached its end with no error.
    Completed,
    /// The command failed: a run failure.
    Failed,
    /// The command reached an integrity verdict.
    Integrity,
}

/// The exit status, folded in the one order the doctrine allows: an
/// integrity verdict, then a run failure (a stdout that failed for any reason
/// but its reader leaving is one), then the reader leaving, then success.
pub fn exit_status(run: Run, delivery: &Delivery) -> u8 {
    match (run, delivery) {
        (Run::Integrity, _) => EXIT_INTEGRITY,
        (Run::Failed, _) | (_, Delivery::Failed(_)) => EXIT_FAILURE,
        (Run::Completed, Delivery::ReaderLeft) => EXIT_READER_LEFT,
        (Run::Completed, Delivery::Delivered) => EXIT_SUCCESS,
    }
}

/// The fate of one MCP frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame {
    /// Written and flushed.
    Sent,
    /// The client closed its end: the session is over, as at stdin EOF. This
    /// does NOT latch the door — `serve-mcp` ends with exit 0 on a closed
    /// client, the status it already gives the same client leaving by EOF.
    ClientLeft,
    /// Any other error: recorded as a run failure, and the session is over.
    Failed,
}

/// The latch itself, over whatever a write does — a pure state machine, so
/// the tests drive it with writers that fail on demand.
#[derive(Debug)]
struct Latch {
    state: Delivery,
}

impl Latch {
    const fn new() -> Self {
        Latch {
            state: Delivery::Delivered,
        }
    }

    /// Run one write unless the stream is already lost, and classify its
    /// failure. Returns whether the write was ATTEMPTED.
    fn attempt(&mut self, op: impl FnOnce() -> io::Result<()>) -> bool {
        if self.state != Delivery::Delivered {
            return false;
        }
        if let Err(e) = op() {
            self.lose(&e);
        }
        true
    }

    /// Record the first loss; a later one changes nothing.
    fn lose(&mut self, e: &io::Error) {
        if self.state == Delivery::Delivered {
            self.state = if e.kind() == io::ErrorKind::BrokenPipe {
                Delivery::ReaderLeft
            } else {
                Delivery::Failed(e.to_string())
            };
        }
    }

    /// One MCP frame: a client leaving ends the session without latching.
    fn frame(&mut self, op: impl FnOnce() -> io::Result<()>) -> Frame {
        match &self.state {
            Delivery::Delivered => {}
            Delivery::ReaderLeft => return Frame::ClientLeft,
            Delivery::Failed(_) => return Frame::Failed,
        }
        match op() {
            Ok(()) => Frame::Sent,
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Frame::ClientLeft,
            Err(e) => {
                self.lose(&e);
                Frame::Failed
            }
        }
    }
}

/// The process's one door onto stdout.
static DOOR: Mutex<Latch> = Mutex::new(Latch::new());

fn door<T>(f: impl FnOnce(&mut Latch) -> T) -> T {
    // A panic inside a caller's `Display` impl poisons nothing that matters:
    // the latch's state is a plain enum, valid at every point.
    let mut latch = DOOR.lock().unwrap_or_else(PoisonError::into_inner);
    f(&mut latch)
}

/// Backing function for `outln!`: one line to stdout through the door.
///
/// The line is formatted BEFORE the door is taken, so a `Display` impl that
/// itself printed could never re-enter the door's (non-reentrant) lock.
#[doc(hidden)]
pub fn _out_line(args: fmt::Arguments<'_>) {
    let mut line = args.to_string();
    line.push('\n');
    write_bytes(line.as_bytes());
}

/// Bytes to stdout through the door, as they are — `export`'s payload.
pub fn write_bytes(bytes: &[u8]) {
    door(|latch| {
        latch.attempt(|| io::stdout().lock().write_all(bytes));
    });
}

/// A write a library makes to stdout itself — clap's help and version text
/// (`clap::Error::print`), which picks its own colouring — classified by the
/// door like any other: skipped once the stream is lost, latched on
/// `BrokenPipe`, a run failure on anything else.
pub fn write_with(op: impl FnOnce() -> io::Result<()>) {
    door(|latch| {
        latch.attempt(op);
    });
}

/// One MCP frame — written and flushed, because the client is waiting on it.
pub fn send_frame(bytes: &[u8]) -> Frame {
    door(|latch| {
        latch.frame(|| {
            let mut out = io::stdout().lock();
            out.write_all(bytes)?;
            out.flush()
        })
    })
}

/// Flush stdout explicitly and report what became of everything written.
///
/// Called once, by `main`, before the exit status is decided — never left to
/// the flush at process exit, whose error std discards.
pub fn finish() -> Delivery {
    door(|latch| {
        latch.attempt(|| io::stdout().lock().flush());
        latch.state.clone()
    })
}

/// Backing function for `errln!`: one best-effort line to stderr. It cannot
/// panic and latches nothing; a line that cannot be written is lost.
#[doc(hidden)]
pub fn _err_line(args: fmt::Arguments<'_>) {
    let _ = writeln!(io::stderr().lock(), "{args}");
}

/// Print one line to stdout through the door (ROADMAP O287). The binaries'
/// only way to stdout: `println!` panics on a closed pipe, and a lint plus a
/// source count keep it out of both of them.
#[macro_export]
macro_rules! outln {
    () => {
        $crate::stdio::_out_line(::core::format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::stdio::_out_line(::core::format_args!($($arg)*))
    };
}

/// Print one best-effort line to stderr (ROADMAP O287): it cannot panic, so a
/// closed or full stderr never turns a verdict's exit status into 101.
#[macro_export]
macro_rules! errln {
    () => {
        $crate::stdio::_err_line(::core::format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::stdio::_err_line(::core::format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn broken() -> io::Error {
        io::Error::from(io::ErrorKind::BrokenPipe)
    }

    fn full() -> io::Error {
        // ENOSPC's kind; the text is what `main` prints.
        io::Error::new(io::ErrorKind::StorageFull, "No space left on device")
    }

    /// The latch, step by step, asserting which writes were REACHED: a test
    /// of the end state alone would pass a door that kept writing into a
    /// closed pipe and merely forgot the errors.
    #[test]
    fn a_closed_reader_latches_and_every_later_write_is_discarded() {
        let mut latch = Latch::new();
        let mut reached = 0;
        assert!(latch.attempt(|| {
            reached += 1;
            Ok(())
        }));
        assert_eq!(latch.state, Delivery::Delivered, "premise: a clean write");
        assert!(latch.attempt(|| {
            reached += 1;
            Err(broken())
        }));
        assert_eq!(latch.state, Delivery::ReaderLeft);
        // Discarded: the write after the latch is never attempted.
        assert!(!latch.attempt(|| {
            reached += 1;
            Ok(())
        }));
        assert_eq!(reached, 2, "the write after the reader left was reached");
        assert_eq!(latch.state, Delivery::ReaderLeft);
    }

    #[test]
    fn any_other_stdout_error_is_a_run_failure_and_the_first_loss_wins() {
        let mut latch = Latch::new();
        latch.attempt(|| Err(full()));
        assert_eq!(
            latch.state,
            Delivery::Failed("No space left on device".into())
        );
        // A later broken pipe cannot downgrade a failure to reader-left.
        latch.lose(&broken());
        assert!(matches!(latch.state, Delivery::Failed(_)));
        // And the other way: a failure after the reader left changes nothing.
        let mut latch = Latch::new();
        latch.attempt(|| Err(broken()));
        latch.lose(&full());
        assert_eq!(latch.state, Delivery::ReaderLeft);
    }

    /// The fold, every cell. Its counterfactual is the filed shape — a quiet
    /// exit 0 for the reader leaving — which fails the middle row.
    #[test]
    fn the_fold_is_integrity_then_failure_then_reader_left_then_success() {
        let delivered = Delivery::Delivered;
        let left = Delivery::ReaderLeft;
        let failed = Delivery::Failed("EIO".into());
        let table = [
            (Run::Integrity, &delivered, 2),
            (Run::Integrity, &left, 2),
            (Run::Integrity, &failed, 2),
            (Run::Failed, &delivered, 1),
            (Run::Failed, &left, 1),
            (Run::Failed, &failed, 1),
            (Run::Completed, &failed, 1),
            (Run::Completed, &left, 141),
            (Run::Completed, &delivered, 0),
        ];
        for (run, delivery, want) in table {
            assert_eq!(
                exit_status(run, delivery),
                want,
                "{run:?} with {delivery:?}"
            );
        }
        assert_eq!(EXIT_READER_LEFT, 141);
        // Four distinct classes: a reader leaving is none of the other three.
        let mut codes = [EXIT_SUCCESS, EXIT_FAILURE, EXIT_INTEGRITY, EXIT_READER_LEFT];
        codes.sort_unstable();
        assert_eq!(codes, [0, 1, 2, 141]);
    }

    #[test]
    fn a_client_leaving_ends_a_session_without_latching_the_door() {
        let mut latch = Latch::new();
        assert_eq!(latch.frame(|| Ok(())), Frame::Sent);
        assert_eq!(latch.frame(|| Err(broken())), Frame::ClientLeft);
        assert_eq!(
            latch.state,
            Delivery::Delivered,
            "serve-mcp's closed client is exit 0, so the frame must not latch"
        );
        assert_eq!(latch.frame(|| Err(full())), Frame::Failed);
        assert!(matches!(latch.state, Delivery::Failed(_)));
        let mut reached = false;
        assert_eq!(
            latch.frame(|| {
                reached = true;
                Ok(())
            }),
            Frame::Failed
        );
        assert!(!reached, "a frame after a failure was attempted");
    }

    // -----------------------------------------------------------------------
    // The source gates: no print escapes the door in either binary, and no
    // production code anywhere writes a line that can panic.
    // -----------------------------------------------------------------------

    /// The code of a Rust source with every comment removed and the CONTENTS
    /// of every string and character literal blanked — `//` inside a string
    /// (a URL) ends nothing, and a needle spelled inside a literal is not a
    /// call. Line breaks are kept. Handles `//`, nested `/* */`, `"…"` with
    /// escapes, raw strings `r"…"`/`r#"…"#` (a raw identifier `r#name` is
    /// left alone) and char literals; a lifetime is left alone.
    fn code_only(text: &str) -> String {
        let c: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < c.len() {
            let ch = c[i];
            let next = c.get(i + 1).copied();
            if ch == '/' && next == Some('/') {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            if ch == '/' && next == Some('*') {
                let mut depth = 0;
                while i < c.len() {
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                        continue;
                    }
                    if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                        continue;
                    }
                    if c[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
                continue;
            }
            if ch == 'r' && matches!(next, Some('"') | Some('#')) {
                let mut j = i + 1;
                let mut hashes = 0;
                while c.get(j) == Some(&'#') {
                    hashes += 1;
                    j += 1;
                }
                if c.get(j) == Some(&'"') {
                    j += 1;
                    while j < c.len() {
                        if c[j] == '"' && (0..hashes).all(|k| c.get(j + 1 + k) == Some(&'#')) {
                            j += 1 + hashes;
                            break;
                        }
                        if c[j] == '\n' {
                            out.push('\n');
                        }
                        j += 1;
                    }
                    out.push_str("\"\"");
                    i = j;
                    continue;
                }
            }
            if ch == '"' {
                i += 1;
                while i < c.len() {
                    if c[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if c[i] == '"' {
                        i += 1;
                        break;
                    }
                    if c[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
                out.push_str("\"\"");
                continue;
            }
            if ch == '\'' {
                if next == Some('\\') {
                    let mut j = i + 2;
                    while j < c.len() && c[j] != '\'' {
                        j += 1;
                    }
                    out.push_str("' '");
                    i = j + 1;
                    continue;
                }
                if c.get(i + 2) == Some(&'\'') {
                    out.push_str("' '");
                    i += 3;
                    continue;
                }
            }
            out.push(ch);
            i += 1;
        }
        out
    }

    /// Occurrences of `needle` as a whole token in `code_only(text)`: the
    /// character before it is not part of an identifier, so `eprintln!` is
    /// not a `println!` and `outln!` is not a `ln!`.
    fn count_token(text: &str, needle: &str) -> usize {
        let code = code_only(text);
        code.match_indices(needle)
            .filter(|(i, _)| {
                code[..*i]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
            })
            .count()
    }

    /// Every `.rs` file under `dir`, recursively, in a stable order.
    fn sources(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("{}: {e}", d.display())) {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        out.sort();
        out
    }

    /// A crate source's PRODUCTION text: a `*_tests.rs` file is a whole test
    /// module and has none; any other file is cut at its column-0
    /// `#[cfg(test)]` followed — after any comment and attribute lines — by
    /// `mod tests`. Other inline `#[cfg(test)]` modules stay counted.
    fn production(path: &Path) -> String {
        if path.to_string_lossy().ends_with("_tests.rs") {
            return String::new();
        }
        let text = std::fs::read_to_string(path).unwrap();
        let mut from = 0;
        while let Some(rel) = text[from..].find("\n#[cfg(test)]\n") {
            let at = from + rel;
            let after = text[at + "\n#[cfg(test)]\n".len()..]
                .lines()
                .find(|l| {
                    let t = l.trim_start();
                    !(t.starts_with("//") || t.starts_with("#["))
                })
                .unwrap_or("");
            if after.starts_with("mod tests") {
                return text[..at].to_string();
            }
            from = at + 1;
        }
        text
    }

    /// The print macros, which panic on a closed or full stream.
    const MACROS: [&str; 5] = ["println!", "print!", "eprintln!", "eprint!", "dbg!"];

    /// The writes that bypass the door: the print macros and the raw handles,
    /// which bypass the latch.
    const ESCAPES: [&str; 9] = [
        "println!",
        "print!",
        "eprintln!",
        "eprint!",
        "dbg!",
        "stdout()",
        "stderr()",
        "io::stdout",
        "io::stderr",
    ];

    /// Premise for both gates: the counter, on planted text — a print after a
    /// URL in a string is found, and a needle in a comment, a string or a raw
    /// string is not.
    #[test]
    fn the_print_counter_reads_code_not_comments_or_literals() {
        let planted = "println!(\"x\");\neprintln!(\"y\");\n// println!(\"z\")\n\
                       let o = std::io::stdout();\noutln!(\"ok\");\nprint!(\"p\");\n\
                       let u = \"http://x\"; println!(\"after a url\");\n\
                       let s = \"println!\"; let r = r#\"eprintln!(\"q\")\"#;\n\
                       /* dbg!(1) /* nested */ dbg!(2) */ let c = '\"'; dbg!(3);\n";
        let hits: Vec<(&str, usize)> = ESCAPES
            .iter()
            .map(|n| (*n, count_token(planted, n)))
            .filter(|(_, k)| *k > 0)
            .collect();
        assert_eq!(
            hits,
            vec![
                ("println!", 2),
                ("print!", 1),
                ("eprintln!", 1),
                ("dbg!", 1),
                ("stdout()", 1),
                ("io::stdout", 1)
            ],
            "premise: the counter finds exactly what was planted"
        );
    }

    /// **Every print of both binaries goes through the door** (ROADMAP O287):
    /// counted over every source file under `undercroft-cli/src` and
    /// `undercroft-orchestrator/src`, recursively, test modules and
    /// cfg-gated code included — the `#![deny(clippy::print_stdout,
    /// clippy::print_stderr)]` at each root is the lint, and no lint leg
    /// compiles the model features (O153). Outside this text count: a
    /// library a binary calls that writes on its own (clap's help, which the
    /// door classifies; tracing's writer — ROADMAP O333).
    #[test]
    fn no_print_in_either_binary_escapes_the_door() {
        let crates = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let mut found = Vec::new();
        let mut scanned = 0;
        let mut door_writes = 0;
        for krate in ["undercroft-cli", "undercroft-orchestrator"] {
            for f in sources(&crates.join(krate).join("src")) {
                scanned += 1;
                let text = std::fs::read_to_string(&f).unwrap();
                door_writes += count_token(&text, "outln!");
                for needle in ESCAPES {
                    for _ in 0..count_token(&text, needle) {
                        found.push(format!("{} ({needle})", f.display()));
                    }
                }
            }
        }
        assert!(
            scanned >= 15,
            "premise: both binaries' sources were read ({scanned})"
        );
        assert!(
            door_writes > 250,
            "premise: the binaries print through the door ({door_writes} outln!)"
        );
        assert!(found.is_empty(), "a print escapes the door: {found:?}");
        // The binaries' roots carry the lint.
        for root in [
            "undercroft-cli/src/main.rs",
            "undercroft-orchestrator/src/main.rs",
        ] {
            let text = std::fs::read_to_string(crates.join(root)).unwrap();
            assert!(
                text.contains("#![deny(clippy::print_stdout, clippy::print_stderr)]"),
                "{root} has lost its print lint"
            );
        }
    }

    /// **No production code in the workspace writes a line that can panic**
    /// (ROADMAP O328): no print macro in the production text of any crate
    /// but the bench harness — every `src/` file, recursively, cut at its
    /// `mod tests`, `*_tests.rs` excluded — so a server whose log reader
    /// went away cannot die at a diagnostic, and a command cannot lose its
    /// verdict to one. The raw handles live in this crate alone: stdout in
    /// the door, stderr in the door and the telemetry build's log writer.
    #[test]
    fn no_production_code_prints_a_line_that_can_panic() {
        let crates = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let mut found = Vec::new();
        let mut handles = Vec::new();
        let mut crates_read = 0;
        let mut diag_sites = 0;
        for entry in std::fs::read_dir(crates).unwrap() {
            let dir = entry.unwrap().path();
            let name = dir.file_name().unwrap().to_string_lossy().into_owned();
            if !dir.join("src").is_dir() || name == "undercroft-bench" {
                continue;
            }
            crates_read += 1;
            for f in sources(&dir.join("src")) {
                let text = production(&f);
                diag_sites += count_token(&text, "diag_warn!");
                for needle in MACROS {
                    for _ in 0..count_token(&text, needle) {
                        found.push(format!("{} ({needle})", f.display()));
                    }
                }
                for needle in ["stdout()", "io::stdout", "stderr()", "io::stderr"] {
                    for _ in 0..count_token(&text, needle) {
                        handles.push((f.display().to_string(), needle));
                    }
                }
            }
        }
        assert!(
            crates_read >= 12,
            "premise: every workspace crate was read ({crates_read})"
        );
        assert!(
            diag_sites > 30,
            "premise: production text was read, diagnostics included ({diag_sites})"
        );
        assert!(
            found.is_empty(),
            "production code prints a line that can panic: {found:?}"
        );
        let stray: Vec<_> = handles
            .iter()
            .filter(|(f, n)| {
                let door = f.ends_with("stdio.rs");
                let log_writer = f.ends_with("imp.rs") && n.contains("stderr");
                !(door || log_writer)
            })
            .collect();
        assert!(
            handles.iter().any(|(f, _)| f.ends_with("stdio.rs")) && stray.is_empty(),
            "a raw stdout/stderr handle outside undercroft-obs: {stray:?}"
        );
    }
}
