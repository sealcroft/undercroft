//! Per-vault request assertions for the multi-tenant HTTP server.
//!
//! A multi-tenant host (one vault per customer) can't rely on a single
//! palace-wide bearer token: whoever holds it can address every vault. So
//! alongside that bearer, each vault-addressing request carries a short-
//! lived HMAC assertion proving the caller is authorized *for that specific
//! vault*.
//!
//! Header: `X-Vault-Assertion: <ts>:<hex hmac>` where
//! `hmac = HMAC-SHA256(secret, "<ts>|<vault_id>")` and `ts` is unix
//! seconds. The signing secret comes from `UNDERCROFT_ASSERTION_SECRET`.
//!
//! The caller platform authorizes its user, then mints an assertion. The
//! engine verifies it independently, so a compromised caller component that
//! lacks the secret gets nothing. An assertion minted for vault A cannot
//! authorize vault B (the vault id is inside the MAC), a stale timestamp is
//! refused (±window seconds), and comparison is constant-time.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Accepted clock skew, in seconds, between the caller minting an assertion
/// and the engine verifying it.
pub const DEFAULT_WINDOW_SECS: i64 = 120;

/// Why an assertion was rejected. All variants map to HTTP 401; the reason
/// is for server-side logging, never returned to the caller (it would leak
/// whether a vault exists or how close a forgery got).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionError {
    /// No `X-Vault-Assertion` header on a request that needs one.
    Missing,
    /// Header present but not `<ts>:<hex>` with a parseable timestamp.
    Malformed,
    /// Timestamp outside the accepted window (clock skew / replay).
    Expired,
    /// MAC did not match — wrong vault, wrong secret, or forgery.
    BadMac,
}

impl std::fmt::Display for AssertionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AssertionError::Missing => "missing X-Vault-Assertion header",
            AssertionError::Malformed => "malformed X-Vault-Assertion header",
            AssertionError::Expired => "X-Vault-Assertion timestamp outside window",
            AssertionError::BadMac => "X-Vault-Assertion MAC mismatch",
        })
    }
}

/// The canonical message signed by an assertion: `"<ts>|<vault_id>"`.
fn signed_message(ts: i64, vault_id: &str) -> String {
    format!("{ts}|{vault_id}")
}

/// Compute the hex HMAC an authorized caller would send for
/// `(vault_id, ts)`. Used by the verifier and by tests to mint assertions;
/// the caller platform reimplements this same one-liner in its own stack.
pub fn sign(secret: &[u8], vault_id: &str, ts: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signed_message(ts, vault_id).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Format a full `X-Vault-Assertion` header value for `(vault_id, ts)`.
pub fn header_value(secret: &[u8], vault_id: &str, ts: i64) -> String {
    format!("{ts}:{}", sign(secret, vault_id, ts))
}

/// Verify a header value authorizes `vault_id` at wall-clock `now`, within
/// `±window` seconds. The vault id is bound into the MAC, so an assertion
/// minted for one vault never verifies against another.
pub fn verify(
    secret: &[u8],
    vault_id: &str,
    header: Option<&str>,
    now: i64,
    window: i64,
) -> Result<(), AssertionError> {
    let header = header.ok_or(AssertionError::Missing)?;
    let (ts_str, mac_hex) = header.split_once(':').ok_or(AssertionError::Malformed)?;
    let ts: i64 = ts_str
        .trim()
        .parse()
        .map_err(|_| AssertionError::Malformed)?;
    let presented = hex::decode(mac_hex.trim()).map_err(|_| AssertionError::Malformed)?;

    // Timestamp window before doing MAC work — cheap replay rejection.
    if (now - ts).abs() > window {
        return Err(AssertionError::Expired);
    }

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signed_message(ts, vault_id).as_bytes());
    let expected = mac.finalize().into_bytes();

    // Length guard first (ct_eq requires equal length), then constant-time.
    if presented.len() != expected.len() {
        return Err(AssertionError::BadMac);
    }
    if bool::from(presented.as_slice().ct_eq(expected.as_slice())) {
        Ok(())
    } else {
        Err(AssertionError::BadMac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"orchestrator-shared-secret-32bytes!!";
    const NOW: i64 = 1_800_000_000;

    #[test]
    fn valid_assertion_passes() {
        let h = header_value(SECRET, "tenant-acme", NOW);
        assert!(verify(SECRET, "tenant-acme", Some(&h), NOW, DEFAULT_WINDOW_SECS).is_ok());
    }

    #[test]
    fn assertion_for_vault_a_never_authorizes_vault_b() {
        // The core multi-tenant guarantee.
        let h = header_value(SECRET, "tenant-acme", NOW);
        assert_eq!(
            verify(SECRET, "tenant-globex", Some(&h), NOW, DEFAULT_WINDOW_SECS),
            Err(AssertionError::BadMac)
        );
    }

    #[test]
    fn stale_timestamp_is_refused() {
        let old = NOW - DEFAULT_WINDOW_SECS - 1;
        let h = header_value(SECRET, "tenant-acme", old);
        assert_eq!(
            verify(SECRET, "tenant-acme", Some(&h), NOW, DEFAULT_WINDOW_SECS),
            Err(AssertionError::Expired)
        );
        // Symmetric: a timestamp too far in the future is also refused.
        let future = NOW + DEFAULT_WINDOW_SECS + 1;
        let h2 = header_value(SECRET, "tenant-acme", future);
        assert_eq!(
            verify(SECRET, "tenant-acme", Some(&h2), NOW, DEFAULT_WINDOW_SECS),
            Err(AssertionError::Expired)
        );
    }

    #[test]
    fn just_inside_window_passes() {
        let edge = NOW - DEFAULT_WINDOW_SECS;
        let h = header_value(SECRET, "tenant-acme", edge);
        assert!(verify(SECRET, "tenant-acme", Some(&h), NOW, DEFAULT_WINDOW_SECS).is_ok());
    }

    #[test]
    fn wrong_secret_is_refused() {
        let h = header_value(b"a-different-secret", "tenant-acme", NOW);
        assert_eq!(
            verify(SECRET, "tenant-acme", Some(&h), NOW, DEFAULT_WINDOW_SECS),
            Err(AssertionError::BadMac)
        );
    }

    #[test]
    fn missing_header_is_missing() {
        assert_eq!(
            verify(SECRET, "tenant-acme", None, NOW, DEFAULT_WINDOW_SECS),
            Err(AssertionError::Missing)
        );
    }

    #[test]
    fn garbled_headers_are_malformed() {
        for bad in [
            "",
            "no-colon-here",
            "notanumber:deadbeef",
            "1800000000:nothex!!",
            ":deadbeef",
        ] {
            assert_eq!(
                verify(SECRET, "tenant-acme", Some(bad), NOW, DEFAULT_WINDOW_SECS),
                Err(AssertionError::Malformed),
                "expected malformed for {bad:?}"
            );
        }
    }

    #[test]
    fn present_but_empty_mac_is_bad_not_malformed() {
        // A valid timestamp with an empty MAC field parses fine but fails
        // the length-guarded compare.
        assert_eq!(
            verify(
                SECRET,
                "tenant-acme",
                Some("1800000000:"),
                NOW,
                DEFAULT_WINDOW_SECS
            ),
            Err(AssertionError::BadMac)
        );
    }

    #[test]
    fn truncated_mac_is_bad_not_a_panic() {
        // A correct-prefix but wrong-length MAC must be rejected without
        // panicking in the constant-time compare.
        let full = sign(SECRET, "tenant-acme", NOW);
        let h = format!("{NOW}:{}", &full[..full.len() - 2]);
        assert_eq!(
            verify(SECRET, "tenant-acme", Some(&h), NOW, DEFAULT_WINDOW_SECS),
            Err(AssertionError::BadMac)
        );
    }
}
