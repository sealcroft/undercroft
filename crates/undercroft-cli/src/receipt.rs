//! A destruction's receipt, delivered whatever fails after the drawers are
//! gone (ROADMAP O262).
//!
//! `forget`, `admission deny` and `retention sweep` destroy drawers and hand
//! back a [`ForgetAttestation`]: the chain-attested receipt naming every
//! destroyed drawer by an UNKEYED fingerprint of its content, which a data
//! subject or an auditor checks against content they already hold. That
//! fingerprint is stored nowhere — keeping it would keep a commitment to
//! erased content — so once the store has committed, the receipt in this
//! process's memory is the only copy that will ever exist.
//!
//! The three commands read their `--sign` identity and wrote `--out` only
//! AFTER that commit, each through `?`. A mistyped signing path, a file that
//! is not a signing identity, or an output path that could not be written
//! exited non-zero over drawers already gone, and the receipt went with the
//! process. Two rules close it, in the order a command meets them:
//!
//! 1. [`signing_identity`] reads and checks `--sign` BEFORE the vault is
//!    opened, so a bad identity refuses with nothing opened, sent or
//!    destroyed. Its type is the proof: a [`SigningIdentity`] exists only
//!    once `signer_of` has parsed the bytes it holds.
//! 2. After the destruction nothing ends the command before the receipt is
//!    delivered. [`sign`] reports a signing failure without touching the
//!    receipt — unreachable once rule 1 passed, since signing parses the same
//!    bytes the same way, and handled anyway because this is the side of the
//!    commit where "unreachable" must not be what the receipt rests on — and
//!    [`deliver`] puts the JSON on stdout, where it goes without `--out`,
//!    whenever `--out` cannot be written or the receipt is unsigned, and only
//!    then fails the command, saying the drawers are destroyed.
//!
//! `--out` is NOT checked ahead (the filing's shape, followed): a probe of
//! the path would be a write before the destruction — an empty file left
//! behind by a refused or read-only run, the effect O212 removed from every
//! read-only door — and a path that was writable when probed can still fail
//! when written, so the fallback is needed either way.
//!
//! What this does not cover, stated: a process killed between the commit and
//! the delivery (O255's residual), and a stdout that cannot be written either
//! — then the error says the receipt is lost rather than implying it was
//! delivered.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use undercroft_store::ForgetAttestation;

/// A `--sign` identity read and checked before anything was destroyed. Only
/// [`signing_identity`] makes one, so holding one is the proof the check ran.
pub(crate) struct SigningIdentity(String);

/// Read and check a `--sign` identity. Run it FIRST — before the vault is
/// opened — in every command that destroys: a missing file or one that is
/// not a signing identity then refuses with nothing changed, where it used to
/// refuse over drawers already destroyed.
pub(crate) fn signing_identity(path: Option<&Path>) -> Result<Option<SigningIdentity>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let secret = std::fs::read_to_string(path)
        .with_context(|| format!("reading signing identity {}", path.display()))?;
    undercroft_vault::bundle::signer_of(&secret).with_context(|| {
        format!(
            "{} is not a signing identity (`undercroft bundle sign-keygen` writes one)",
            path.display()
        )
    })?;
    Ok(Some(SigningIdentity(secret)))
}

/// Sign a receipt with an identity [`signing_identity`] checked. On failure
/// the receipt is left as the store minted it — whole and unsigned — and the
/// error goes to [`deliver`], which hands the receipt over before failing.
/// Never `?` this: the drawers are already gone.
pub(crate) fn sign(att: &mut ForgetAttestation, identity: Option<&SigningIdentity>) -> Result<()> {
    let Some(SigningIdentity(secret)) = identity else {
        return Ok(());
    };
    att.sign(secret).context("signing the receipt")
}

/// Where [`deliver`] put a receipt.
pub(crate) enum Delivered<'a> {
    /// Written to the `--out` path.
    File(&'a Path),
    /// Printed on stdout, because no `--out` was named.
    Stdout,
}

/// Hand a destruction's receipt over: to `out` when one is named, else on
/// `stdout`. `signed` is [`sign`]'s answer.
///
/// Every failure here comes AFTER the drawers were destroyed, so each one
/// prints the receipt on `stdout` — the bytes the file would have held,
/// where the receipt goes without `--out` — before returning the error. An
/// unsigned receipt is never written where a signed one was asked for.
pub(crate) fn deliver<'a>(
    json: &str,
    out: Option<&'a Path>,
    signed: Result<()>,
    stdout: &mut dyn Write,
) -> Result<Delivered<'a>> {
    if let Err(e) = signed {
        return Err(fallback(
            json,
            stdout,
            e.context("the receipt is UNSIGNED: signing it failed"),
        ));
    }
    let Some(path) = out else {
        print(json, stdout).map_err(|e| {
            anyhow::Error::from(e).context(
                "the drawers ARE destroyed and printing their receipt failed: the receipt is lost",
            )
        })?;
        return Ok(Delivered::Stdout);
    };
    match std::fs::write(path, json) {
        Ok(()) => Ok(Delivered::File(path)),
        Err(e) => Err(fallback(
            json,
            stdout,
            anyhow::Error::from(e)
                .context(format!("writing the receipt to {} failed", path.display())),
        )),
    }
}

/// Print the receipt on `stdout` after `why` stopped its delivery, keeping
/// `why` as the cause, and say which happened: printed, or — when stdout
/// cannot be written either — lost, rather than implying it was printed.
fn fallback(json: &str, stdout: &mut dyn Write, why: anyhow::Error) -> anyhow::Error {
    match print(json, stdout) {
        Ok(()) => why.context(
            "the drawers ARE destroyed, so their receipt is printed on stdout instead: save \
             it, because it can never be minted again",
        ),
        Err(also) => why.context(format!(
            "the drawers ARE destroyed and printing their receipt on stdout failed too \
             ({also}): the receipt is lost"
        )),
    }
}

fn print(json: &str, stdout: &mut dyn Write) -> std::io::Result<()> {
    writeln!(stdout, "{json}")?;
    stdout.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use undercroft_store::forget::ForgottenDrawer;

    fn minted() -> ForgetAttestation {
        ForgetAttestation {
            version: 2,
            vault: "default".into(),
            created_at: "2026-10-08T00:00:00Z".into(),
            drawers: vec![ForgottenDrawer {
                id: "d1".into(),
                content_fp: "f1".into(),
            }],
            head_before: "aa".into(),
            head_after: "bb".into(),
            records: vec![],
            mirror: None,
            sender: None,
            sig: None,
        }
    }

    /// Rule 1: the identity is read and parsed before anything runs, and the
    /// two ways it can be wrong both refuse with their own words.
    #[test]
    fn a_signing_identity_is_read_and_checked_before_it_is_needed() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(signing_identity(None).unwrap().is_none());
        let absent = dir.path().join("absent.key");
        let err = signing_identity(Some(&absent))
            .err()
            .expect("a missing file refuses");
        assert!(
            format!("{err:#}").contains("reading signing identity"),
            "{err:#}"
        );
        let garbage = dir.path().join("garbage.key");
        std::fs::write(&garbage, "not a key\n").unwrap();
        let err = signing_identity(Some(&garbage))
            .err()
            .expect("a non-key refuses");
        assert!(
            format!("{err:#}").contains("is not a signing identity"),
            "{err:#}"
        );
        let good = dir.path().join("sign.key");
        std::fs::write(&good, undercroft_vault::bundle::sign_keygen().0).unwrap();
        assert!(signing_identity(Some(&good)).unwrap().is_some());
    }

    /// Rule 2, `--out`: a path that cannot be written — a directory, which
    /// refuses root too — puts the exact JSON on stdout and fails naming the
    /// path; a writable one gets the JSON and stdout gets nothing; no `--out`
    /// prints it.
    #[test]
    fn a_receipt_whose_out_cannot_be_written_is_printed_before_the_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let json = "{\n  \"version\": 2\n}";
        let mut stdout = Vec::new();
        let err = deliver(json, Some(dir.path()), Ok(()), &mut stdout)
            .err()
            .expect("a directory cannot be written as a file");
        assert_eq!(
            stdout,
            format!("{json}\n").into_bytes(),
            "the receipt was lost"
        );
        let said = format!("{err:#}");
        assert!(said.contains("ARE destroyed"), "{said}");
        assert!(said.contains(&dir.path().display().to_string()), "{said}");

        let file = dir.path().join("receipt.json");
        let mut stdout = Vec::new();
        let d = deliver(json, Some(&file), Ok(()), &mut stdout).unwrap();
        assert!(matches!(d, Delivered::File(p) if p == file));
        assert!(stdout.is_empty(), "a written receipt is not also printed");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), json);

        let mut stdout = Vec::new();
        let d = deliver(json, None, Ok(()), &mut stdout).unwrap();
        assert!(matches!(d, Delivered::Stdout));
        assert_eq!(stdout, format!("{json}\n").into_bytes());
    }

    /// Rule 2, signing: a failure leaves the receipt whole and unsigned, never
    /// writes it where a signed one was asked for, and still prints it. The
    /// identity is built here past [`signing_identity`]'s check on purpose —
    /// that check is what makes this unreachable from the binary.
    #[test]
    fn a_receipt_that_could_not_be_signed_is_printed_whole_and_unsigned() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut att = minted();
        let canonical = att.canonical();
        let signed = sign(&mut att, Some(&SigningIdentity("not a key".into())));
        assert!(signed.is_err(), "premise: a garbage identity cannot sign");
        assert!(
            att.sender.is_none() && att.sig.is_none(),
            "never half-signed"
        );
        assert_eq!(
            att.canonical(),
            canonical,
            "the receipt is otherwise untouched"
        );

        let json = serde_json::to_string_pretty(&att).unwrap();
        let file = dir.path().join("receipt.json");
        let mut stdout = Vec::new();
        let err = deliver(&json, Some(&file), signed, &mut stdout)
            .err()
            .expect("an unsigned receipt fails the command");
        assert!(
            !file.exists(),
            "an unsigned receipt was written where a signed one was asked for"
        );
        assert_eq!(
            stdout,
            format!("{json}\n").into_bytes(),
            "the receipt was lost"
        );
        assert!(format!("{err:#}").contains("UNSIGNED"), "{err:#}");

        let (secret, sender) = undercroft_vault::bundle::sign_keygen();
        sign(&mut att, Some(&SigningIdentity(secret))).unwrap();
        assert_eq!(att.sender.as_deref(), Some(sender.as_str()));
        assert!(att.sig.is_some());
    }

    /// The last fallback: a stdout that cannot be written either. The error
    /// says the receipt is lost instead of implying it was printed.
    #[test]
    fn a_receipt_that_cannot_be_printed_either_is_called_lost() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let dir = tempfile::TempDir::new().unwrap();
        let err = deliver("{}", Some(dir.path()), Ok(()), &mut Closed)
            .err()
            .expect("both deliveries failed");
        let said = format!("{err:#}");
        assert!(said.contains("the receipt is lost"), "{said}");
        let err = deliver("{}", None, Ok(()), &mut Closed)
            .err()
            .expect("stdout failed");
        assert!(format!("{err:#}").contains("the receipt is lost"));
    }
}
