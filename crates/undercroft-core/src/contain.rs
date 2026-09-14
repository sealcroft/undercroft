//! A panic inside one model forward, turned into an error the caller already
//! handles (ROADMAP O150).
//!
//! Every model role's hot path is infallible by contract: a failed embed
//! degrades to a counted zero vector, a failed score to a counted `0.0`, a
//! failed encode to a counted empty matrix. A PANIC went past all of that. An
//! embedding id past the table panics inside tract's `Gather` kernel on every
//! tract role, and a panic unwinds out of the single-threaded `/v1` and MCP
//! loops and ends the process — on the late stage AFTER the drawer committed,
//! so a client's retry files a duplicate.
//!
//! [`contain`] is the one boundary. Each backend wraps a role's WHOLE inner
//! body in it, so a tokenizer panic, a runtime panic and a shape panic after
//! the runtime returns are all inside, and maps the caught panic to its own
//! `Panicked` error, which reaches the counted degrade that role already has.
//! Deliberately NOT here:
//!
//! * **a counter** — the count belongs to the role's own degrade arm, where
//!   `parity.rs`' `DEGRADE_ARMS` can see it. A second count that only tests
//!   read is the silent shape ROADMAP O122 closed;
//! * **a panic hook** — a library that installs one changes a process global
//!   under every other crate. The default hook prints one `panicked at` line
//!   beside the counted degrade line, and that is the documented cost.
//!
//! **Unwinding is required.** Under `panic = "abort"` there is nothing to
//! catch, so both model crates refuse to compile in that configuration.
//!
//! **`AssertUnwindSafe` is a claim about the callers, and it is the
//! residual.** It holds by reading, not by the type system: the wrapped bodies
//! touch only call-local values after the runtime returns, the tokenizer's
//! only shared encode-path state is a cache behind `try_read`/`try_write`,
//! tract 0.22.3 builds a fresh plan state per call, and ORT's session mutex is
//! recovered from poisoning rather than trusted to stay clean. Interior
//! mutability added to a model struct later is not covered by this function
//! and must be argued again.

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The most bytes of a panic payload [`contain`] keeps. A payload is runtime
/// text of any length, and it lands in one degrade line on stderr.
pub const PAYLOAD_LIMIT: usize = 256;

/// What [`contain`] reports for a payload that is neither a `String` nor a
/// `&'static str` — a `panic_any` of some other type.
pub const OPAQUE_PAYLOAD: &str = "<non-string panic payload>";

/// Run `f`, turning a panic inside it into `Err(panicked(message))`.
///
/// `f`'s own `Ok` and `Err` pass through untouched, so a body that already
/// returns typed errors keeps them and only an unwind is converted. `message`
/// is the panic payload's text, truncated to [`PAYLOAD_LIMIT`] bytes on a
/// character boundary.
pub fn contain<T, E>(
    f: impl FnOnce() -> Result<T, E>,
    panicked: impl FnOnce(String) -> E,
) -> Result<T, E> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(payload) => Err(panicked(describe(&*payload))),
    }
}

/// The text of a panic payload, bounded.
fn describe(payload: &(dyn Any + Send)) -> String {
    let text = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&'static str>().copied())
        .unwrap_or(OPAQUE_PAYLOAD);
    let mut end = text.len().min(PAYLOAD_LIMIT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::panic_any;

    #[test]
    fn an_ok_and_a_typed_err_pass_through_untouched() {
        assert_eq!(contain(|| Ok::<u8, String>(7), |m| m), Ok(7));
        assert_eq!(
            contain(
                || Err::<u8, String>("typed".to_string()),
                |m| format!("panicked: {m}")
            ),
            Err("typed".to_string()),
            "a typed error must not be reported as a panic"
        );
    }

    #[test]
    fn a_panic_becomes_the_callers_error_whatever_the_payload_type() {
        let owned = contain(
            || -> Result<u8, String> { panic_any(String::from("owned message")) },
            |m| format!("panicked: {m}"),
        );
        assert_eq!(owned, Err("panicked: owned message".to_string()));

        let borrowed = contain(
            || -> Result<u8, String> { panic_any("static message") },
            |m| format!("panicked: {m}"),
        );
        assert_eq!(borrowed, Err("panicked: static message".to_string()));

        let formatted = contain(
            || -> Result<u8, String> { panic!("index {} out of range", 4096) },
            |m| m,
        );
        assert_eq!(formatted, Err("index 4096 out of range".to_string()));

        let opaque = contain(|| -> Result<u8, String> { panic_any(42u32) }, |m| m);
        assert_eq!(opaque, Err(OPAQUE_PAYLOAD.to_string()));
    }

    #[test]
    fn a_long_payload_is_cut_on_a_character_boundary() {
        // One ASCII byte then two-byte characters: every boundary past the
        // first byte is ODD, so the limit (256, even) falls inside a character
        // and a byte slice there would not be a string at all.
        let long = format!("a{}", "\u{e9}".repeat(300));
        let got = contain(|| -> Result<u8, String> { panic_any(long) }, |m| m)
            .expect_err("a panic must be reported");
        assert_eq!(
            got.len(),
            PAYLOAD_LIMIT - 1,
            "cut at the boundary below the limit"
        );
        assert!(got.starts_with('a') && got.ends_with('\u{e9}'));

        let short = contain(|| -> Result<u8, String> { panic_any("short") }, |m| m);
        assert_eq!(
            short,
            Err("short".to_string()),
            "a short payload is not cut"
        );
    }

    #[test]
    fn a_panic_inside_does_not_stop_the_next_call() {
        let mut seen = Vec::new();
        for i in 0..3u8 {
            seen.push(contain(
                || -> Result<u8, String> {
                    if i == 1 {
                        panic!("the middle call panics");
                    }
                    Ok(i)
                },
                |m| m,
            ));
        }
        assert_eq!(
            seen,
            vec![Ok(0), Err("the middle call panics".to_string()), Ok(2)]
        );
    }
}
