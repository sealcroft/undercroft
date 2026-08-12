//! Declaration resolvers shared by the engine and the control plane.
//!
//! **Why this is its own crate**, on the precedent `undercroft-net` set: a
//! policy that several crates need has exactly one implementation, and when
//! the crates that need it cannot link each other, that implementation gets a
//! home neither of them owns. `undercroft-net` was carved out because the
//! transport policy lived in `undercroft-llm` while the index backends had
//! none at all. This is the same shape one layer over: three
//! `UNDERCROFT_ORCH_*` declarations are read by `undercroft-orchestrator` and
//! must ALSO be pre-flighted by `undercroft config check`, and the engine
//! deliberately never links the control plane (`CLAUDE.md`: *"Pure `/v1`
//! client; never linked by the engine"*).
//!
//! **What it fixes (ROADMAP O24).** Six surfaces — `UPGRADING.md`, `ROADMAP`,
//! `README`, `docs/AGENTS.md`, `CLAUDE.md` and `architecture/index.html`'s
//! doctrine paragraph — promise that `undercroft config check` validates
//! every `UNDERCROFT_*` declaration. Three were not validated: their parses
//! lived inside the orchestrator, where the engine could not reach them. The
//! first attempt at this narrowed all six documents to match the code, which
//! was backwards — several documents do not independently invent the same
//! promise, and the engine's own inventory already CONTAINED those three.
//!
//! **The dependency list is the design.** `thiserror` and `hex`, nothing
//! else. Both consumers pay for whatever lands here, and a control plane has
//! no use for a domain model — which is why these did not go into
//! `undercroft-core` (unicode normalization and a calendar library for three
//! string parses) nor into `undercroft-net`, whose domain is transport and
//! which correctly owns the two declaration resolvers that ARE transport
//! (`declared_pin`, `declared_endpoint`).
//!
//! **Nothing here opens anything.** Every function is a pure string→value
//! parse, which is what lets a pre-flight run the same code a start-up runs
//! without a database, a socket or a port.

/// A declaration that does not resolve.
///
/// One variant with the message inside it rather than a taxonomy: every
/// caller here renders the text and nothing branches on the kind. The
/// consumers map it to their own error types at the boundary — `StateError`
/// in the orchestrator, a `String` in the engine's `check_declaration` —
/// which keeps this crate free of both.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

fn refuse<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

/// `UNDERCROFT_ORCH_KEY` — the 32-byte key sealing engine credentials and
/// MAC-ing tenant tokens.
///
/// Unset and empty refuse separately, because the fixes differ: one means
/// *generate one with `keygen`*, the other means *your `${VAR}` did not
/// interpolate*. The single message they used to share said neither.
///
/// **Trimmed, and that is an exception with an argument.** Hex carries no
/// whitespace, so trimming cannot change which key was named — it can only
/// remove the newline `$(cat orch.key)` leaves. Contrast
/// [`resolve_admin_token`], where trimming would change the KEY itself and is
/// refused instead. The two answers differ because the questions do.
pub fn resolve_orch_key(declared: Option<&str>) -> Result<[u8; 32], ConfigError> {
    let Some(raw) = declared else {
        return refuse("UNDERCROFT_ORCH_KEY is not set (generate one with `keygen`)");
    };
    let v = raw.trim();
    if v.is_empty() {
        return refuse(
            "UNDERCROFT_ORCH_KEY is set but names no key (it is empty or only whitespace). It \
             is most often an unset shell variable interpolated into a compose file or a \
             systemd unit. Generate one with `keygen`",
        );
    }
    let Ok(bytes) = hex::decode(v) else {
        return refuse("UNDERCROFT_ORCH_KEY is not hex");
    };
    match <[u8; 32]>::try_from(bytes) {
        Ok(k) => Ok(k),
        Err(_) => refuse("UNDERCROFT_ORCH_KEY must be 32 bytes (64 hex)"),
    }
}

/// `UNDERCROFT_ORCH_ADMIN_TOKEN` — the bearer for the `/admin` plane.
///
/// **Trailing whitespace refuses**, and that is the defect this function was
/// written for. HTTP strips a header field value's trailing whitespace, so
/// the bearer that ARRIVES is always the trimmed one and never equals the
/// declaration. `$(cat /run/secrets/token)` over a file ending in a newline
/// **clears the 16-character floor** — a newline has length — so the control
/// plane started cleanly and refused every request forever: a 401 naming no
/// cause on one side, nothing in the log on the other.
///
/// Not trimmed for the operator: that authenticates a key they did not
/// declare. Leading and internal whitespace ARE presentable — measured on the
/// engine's identical path, both answer 200 — so they stay values and the
/// refusal is exactly as wide as the defect.
///
/// The order of the three guards is load-bearing and pinned by test: empty
/// must not be diagnosed as short, and a trailing newline must not be
/// diagnosed as either.
pub fn resolve_admin_token(declared: Option<&str>) -> Result<String, ConfigError> {
    let Some(raw) = declared else {
        return refuse("UNDERCROFT_ORCH_ADMIN_TOKEN is not set");
    };
    if raw.trim().is_empty() {
        return refuse(
            "UNDERCROFT_ORCH_ADMIN_TOKEN is set but names no token (it is empty or only \
             whitespace). It is most often an unset shell variable interpolated into a compose \
             file or a systemd unit",
        );
    }
    if raw.trim_end() != raw {
        return refuse(
            "UNDERCROFT_ORCH_ADMIN_TOKEN ends in whitespace, and no client could ever present \
             it: HTTP strips a header value's trailing whitespace, so the bearer that arrives \
             is always the trimmed one and every /admin request is refused — a 401 that names \
             no cause, from a control plane that started cleanly. It is most often \
             `$(cat /run/secrets/token)` over a file ending in a newline, which clears the \
             16-character floor because a newline has length. Strip it at the source \
             (`tr -d '\\n'`). It is not trimmed here on purpose: that would authenticate a key \
             you did not declare",
        );
    }
    if raw.len() < 16 {
        return refuse("UNDERCROFT_ORCH_ADMIN_TOKEN must be at least 16 characters");
    }
    Ok(raw.to_string())
}

/// `UNDERCROFT_ORCH_RATE_LIMIT` — requests per minute per tenant, or `0`/`off`.
///
/// A **closed vocabulary**, so empty legitimately means the default — the
/// opposite answer from the two secrets above, and the distinction is
/// `CLAUDE.md`'s payload-vs-vocabulary rule. Pinned by test so a future sweep
/// for `is_empty()` over a declaration does not "fix" it into a refusal.
pub fn resolve_rate_limit(declared: Option<&str>) -> Result<u64, ConfigError> {
    let Some(raw) = declared else { return Ok(0) };
    let v = raw.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("off") {
        return Ok(0);
    }
    match v.parse::<u64>() {
        Ok(n) => Ok(n),
        Err(_) => refuse(format!(
            "UNDERCROFT_ORCH_RATE_LIMIT={v:?} — expected requests per minute as a plain \
             positive integer (e.g. 600), or 0/off; refusing to start with an unreadable \
             rate-limit declaration"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key resolves without opening anything — the property that makes a
    /// pre-flight possible at all, and the reason this left `Orch::open`'s
    /// body, where it was written out TWICE.
    #[test]
    fn the_orchestrator_key_resolves_without_opening_anything() {
        let good = "a".repeat(64);
        assert_eq!(resolve_orch_key(Some(&good)).unwrap().len(), 32);
        // Hex carries no whitespace, so trimming names the same key.
        assert_eq!(
            resolve_orch_key(Some(&format!("{good}\n"))).unwrap(),
            resolve_orch_key(Some(&good)).unwrap()
        );
        assert!(resolve_orch_key(None)
            .unwrap_err()
            .to_string()
            .contains("not set"));
        for empty in ["", "  ", "\n"] {
            assert!(resolve_orch_key(Some(empty))
                .unwrap_err()
                .to_string()
                .contains("names no key"));
        }
        assert!(resolve_orch_key(Some("zz"))
            .unwrap_err()
            .to_string()
            .contains("not hex"));
        assert!(resolve_orch_key(Some("aabb"))
            .unwrap_err()
            .to_string()
            .contains("32 bytes"));
    }

    /// The admin token's three refusals and the values that are not
    /// refusals. **The counterfactual is the LENGTH FLOOR**:
    /// `"0123456789abcdef\n"` is 17 characters, so the floor that was once
    /// the only check passed it, and a test asserting merely "a short token
    /// is refused" would have passed against the defect.
    #[test]
    fn an_admin_token_that_cannot_be_presented_is_refused() {
        assert!(resolve_admin_token(None).is_err());
        for empty in ["", " ", "\n", "   \t "] {
            let e = resolve_admin_token(Some(empty)).unwrap_err().to_string();
            assert!(e.contains("names no token"), "{e}");
        }
        for tailed in [
            "0123456789abcdef\n",
            "0123456789abcdef ",
            "0123456789abcdef\t",
        ] {
            assert!(
                tailed.len() >= 16,
                "premise: this value must CLEAR the length floor, or the test proves nothing"
            );
            let e = resolve_admin_token(Some(tailed)).unwrap_err().to_string();
            assert!(e.contains("ends in whitespace"), "{e}");
            assert!(!e.contains("at least 16"), "wrong diagnosis: {e}");
        }
        let e = resolve_admin_token(Some("short")).unwrap_err().to_string();
        assert!(e.contains("at least 16"), "{e}");
        // Presentable whitespace is a value, not a typo — leading and
        // internal both answer 200 over HTTP, measured against a live server.
        for real in [" 0123456789abcdef", "0123 456789 abcdef"] {
            assert_eq!(resolve_admin_token(Some(real)).unwrap(), real);
        }
    }

    /// A closed vocabulary: empty is the default, not a failed interpolation.
    /// The opposite answer from the two secrets above, deliberately.
    #[test]
    fn an_empty_rate_limit_is_the_default_and_not_a_refusal() {
        assert_eq!(resolve_rate_limit(None).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some("")).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some("off")).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some("OFF")).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some(" 600 ")).unwrap(), 600);
        assert!(resolve_rate_limit(Some("lots")).is_err());
    }
}
