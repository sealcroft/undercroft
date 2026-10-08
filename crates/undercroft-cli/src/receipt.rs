//! A destruction's receipt, delivered — or said to be lost — whatever fails
//! after the drawers are gone (ROADMAP O262).
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
//! process. Three rules close it, in the order a command meets them:
//!
//! 1. [`signing_identity`] reads and checks `--sign` BEFORE the vault is
//!    opened, so a bad identity refuses with nothing opened, sent or
//!    destroyed. Its type is the proof: a [`SigningIdentity`] exists only
//!    once `signer_of` has parsed the bytes it holds.
//! 2. After the destruction, the receipt's delivery is attempted before
//!    anything else is written: `--out` FIRST, durably ([`write_durably`]:
//!    synced, renamed into place, its directory synced), so the file exists on
//!    disk before the command reports anything, as the drawers' absence does.
//!    [`sign`] reports a signing failure without touching the receipt —
//!    unreachable once rule 1 passed, since signing parses the same bytes the
//!    same way, and handled anyway because this is the side of the commit
//!    where "unreachable" must not be what the receipt rests on.
//! 3. A delivery that fails says where the receipt went. [`deliver`] puts the
//!    JSON on stdout — where it goes without `--out` — whenever `--out` cannot
//!    be written or the receipt is unsigned, through the stdout door's FLUSHED
//!    write (ROADMAP O287), and asks the door what became of it: printed, or —
//!    when the reader has gone or stdout fails — LOST, and it says so rather
//!    than claim a copy went out. Without `--out`, stdout is the destination;
//!    a receipt lost there is said on stderr, and the door's own fold decides
//!    the exit status (141 for a reader that left, 1 for any other failure).
//!
//! `--out` is NOT checked ahead (the filing's shape, followed): a probe of
//! the path would be a write before the destruction — an empty file left
//! behind by a refused or read-only run, the effect O212 removed from every
//! read-only door — and a path that was writable when probed can still fail
//! when written, so the fallback is needed either way.
//!
//! What this does not cover, stated: a process killed between the commit and
//! the delivery (O255's residual); a receipt lost because stdout could not
//! take it either, which is said, not prevented; and a stdout write that was
//! accepted by a pipe whose reader then died unread, which no writer can see.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use undercroft_obs::errln;
use undercroft_obs::stdio::Delivery;
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
    /// Written, durably, to the `--out` path.
    File(&'a Path),
    /// Printed on stdout, because no `--out` was named.
    Stdout,
    /// No `--out` was named and stdout could not take it: the receipt is
    /// lost, stderr says so, and the stdout door's fold decides the exit.
    Lost,
}

impl<'a> Delivered<'a> {
    /// The `--out` path the receipt was written to, if it was.
    pub(crate) fn file(self) -> Option<&'a Path> {
        match self {
            Delivered::File(path) => Some(path),
            Delivered::Stdout | Delivered::Lost => None,
        }
    }
}

/// The production stdout of a delivery: the bytes through the stdout door,
/// flushed, and what became of them (ROADMAP O287).
pub(crate) fn door(bytes: &[u8]) -> Delivery {
    undercroft_obs::stdio::write_bytes_flushed(bytes)
}

/// Hand a destruction's receipt over: to `out` when one is named, else on
/// stdout. `signed` is [`sign`]'s answer; `stdout` writes bytes, flushed, and
/// says what became of them — [`door`] in production.
///
/// Every failure here comes AFTER the drawers were destroyed, so each one
/// prints the receipt on stdout — the bytes the file would have held — before
/// returning the error, and the error says whether that copy went out or the
/// receipt is lost. An unsigned receipt is never written where a signed one
/// was asked for.
pub(crate) fn deliver<'a>(
    json: &str,
    out: Option<&'a Path>,
    signed: Result<()>,
    mut stdout: impl FnMut(&[u8]) -> Delivery,
) -> Result<Delivered<'a>> {
    if let Err(e) = signed {
        return Err(fallback(
            json,
            &mut stdout,
            e.context("the receipt is UNSIGNED: signing it failed"),
        ));
    }
    let Some(path) = out else {
        return Ok(match stdout(line(json).as_bytes()) {
            Delivery::Delivered => Delivered::Stdout,
            lost => {
                errln!(
                    "Error: the drawers ARE destroyed and their receipt could not be printed \
                     ({}): the receipt is lost",
                    why(&lost)
                );
                Delivered::Lost
            }
        });
    };
    match write_durably(path, json.as_bytes()) {
        Ok(()) => Ok(Delivered::File(path)),
        Err(e) => Err(fallback(
            json,
            &mut stdout,
            anyhow::Error::from(e)
                .context(format!("writing the receipt to {} failed", path.display())),
        )),
    }
}

/// Print the receipt on stdout after `why` stopped its delivery, keeping
/// `why` as the cause, and say which happened: printed, or — when the door
/// has latched (its reader gone, or a write failed) — lost, rather than
/// claiming a copy went out.
fn fallback(
    json: &str,
    stdout: &mut impl FnMut(&[u8]) -> Delivery,
    cause: anyhow::Error,
) -> anyhow::Error {
    match stdout(line(json).as_bytes()) {
        Delivery::Delivered => cause.context(
            "the drawers ARE destroyed, so their receipt is printed on stdout instead: save \
             it, because it can never be minted again",
        ),
        lost => cause.context(format!(
            "the drawers ARE destroyed and their receipt could not be printed on stdout either \
             ({}): the receipt is lost",
            why(&lost)
        )),
    }
}

fn line(json: &str) -> String {
    format!("{json}\n")
}

fn why(lost: &Delivery) -> String {
    match lost {
        Delivery::ReaderLeft => "the reader of standard output went away".to_string(),
        Delivery::Failed(e) => e.clone(),
        Delivery::Delivered => "nothing failed".to_string(),
    }
}

/// Write `bytes` to `path` so the file is on disk before the caller reports
/// it: a destruction is committed with `synchronous=FULL`, so a receipt left
/// in the page cache could be empty after a power loss while the drawers are
/// durably gone.
///
/// A regular file (or no file yet) is written to a temporary beside it, opened
/// `create_new`, synced, renamed over the path, and the directory synced — so
/// an existing file at the path, perhaps an earlier receipt, is replaced only
/// by a complete one and never truncated by a write that then fails. Anything
/// else at the path — a symbolic link, a FIFO, a device such as `/dev/stdout`
/// — is written through as before, and synced only if it opens as a regular
/// file, since a rename would replace the link or the device itself.
pub(crate) fn write_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let in_place = match std::fs::symlink_metadata(path) {
        Ok(m) => !m.file_type().is_file(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    if in_place {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
        if f.metadata()?.is_file() {
            f.sync_all()?;
        }
        return Ok(());
    }
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("the --out path names no file"))?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(
        ".{}.{}-{nonce}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let written = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    // The temporary is this call's own (`create_new`), so removing it on a
    // failure removes nothing anyone else wrote.
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(dir)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    // A directory cannot be opened as a file here; NTFS journals the rename.
    Ok(())
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

    /// What a recording stdout was handed.
    type Seen = std::rc::Rc<std::cell::RefCell<Vec<u8>>>;

    /// A stdout that records what it was handed and answers `fate`.
    fn recording(fate: Delivery) -> (Seen, impl FnMut(&[u8]) -> Delivery) {
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let sink = seen.clone();
        (seen, move |b: &[u8]| {
            sink.borrow_mut().extend_from_slice(b);
            fate.clone()
        })
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

    /// Rule 2 and 3, `--out`: a path that cannot be written — a directory,
    /// which refuses root too — puts the exact JSON on stdout and fails naming
    /// the path; a writable one gets the JSON and stdout gets nothing; no
    /// `--out` prints it.
    #[test]
    fn a_receipt_whose_out_cannot_be_written_is_printed_before_the_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let json = "{\n  \"version\": 2\n}";
        let (seen, sink) = recording(Delivery::Delivered);
        let err = deliver(json, Some(dir.path()), Ok(()), sink)
            .err()
            .expect("a directory cannot be written as a file");
        assert_eq!(
            *seen.borrow(),
            format!("{json}\n").into_bytes(),
            "the receipt was lost"
        );
        let said = format!("{err:#}");
        assert!(said.contains("printed on stdout instead"), "{said}");
        assert!(said.contains(&dir.path().display().to_string()), "{said}");

        let file = dir.path().join("receipt.json");
        let (seen, sink) = recording(Delivery::Delivered);
        let d = deliver(json, Some(&file), Ok(()), sink).unwrap();
        assert!(matches!(d, Delivered::File(p) if p == file));
        assert!(
            seen.borrow().is_empty(),
            "a written receipt is not also printed"
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), json);

        let (seen, sink) = recording(Delivery::Delivered);
        let d = deliver(json, None, Ok(()), sink).unwrap();
        assert!(matches!(d, Delivered::Stdout));
        assert_eq!(*seen.borrow(), format!("{json}\n").into_bytes());
    }

    /// Rule 3 against the door's latch: when stdout did not take the fallback
    /// — its reader gone, or a write failed — the error says the receipt is
    /// LOST and never that it was printed; without `--out` the receipt is
    /// reported lost rather than delivered.
    #[test]
    fn a_receipt_the_door_did_not_take_is_called_lost_not_printed() {
        let dir = tempfile::TempDir::new().unwrap();
        for fate in [
            Delivery::ReaderLeft,
            Delivery::Failed("No space left on device".into()),
        ] {
            let (seen, sink) = recording(fate.clone());
            let err = deliver("{}", Some(dir.path()), Ok(()), sink)
                .err()
                .expect("both deliveries failed");
            let said = format!("{err:#}");
            assert!(said.contains("the receipt is lost"), "{fate:?}: {said}");
            assert!(
                !said.contains("printed on stdout instead"),
                "{fate:?}: claims a copy went out: {said}"
            );
            assert!(
                !seen.borrow().is_empty(),
                "premise: the fallback was attempted"
            );
            let (_, sink) = recording(fate.clone());
            let d = deliver("{}", None, Ok(()), sink).unwrap();
            assert!(matches!(d, Delivered::Lost), "{fate:?}");
        }
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
        let (seen, sink) = recording(Delivery::Delivered);
        let err = deliver(&json, Some(&file), signed, sink)
            .err()
            .expect("an unsigned receipt fails the command");
        assert!(
            !file.exists(),
            "an unsigned receipt was written where a signed one was asked for"
        );
        assert_eq!(
            *seen.borrow(),
            format!("{json}\n").into_bytes(),
            "the receipt was lost"
        );
        assert!(format!("{err:#}").contains("UNSIGNED"), "{err:#}");

        let (secret, sender) = undercroft_vault::bundle::sign_keygen();
        sign(&mut att, Some(&SigningIdentity(secret))).unwrap();
        assert_eq!(att.sender.as_deref(), Some(sender.as_str()));
        assert!(att.sig.is_some());
    }

    /// `write_durably`: a new file, a replaced regular file, and a failure
    /// that leaves the earlier file whole and no temporary behind.
    #[test]
    fn a_receipt_file_is_replaced_whole_or_not_at_all() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("receipt.json");
        write_durably(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        write_durably(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let leftovers = || {
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".tmp")
                })
                .count()
        };
        assert_eq!(leftovers(), 0, "a temporary was left behind");
        // A path whose directory does not exist fails, and writes nothing.
        let missing = dir.path().join("no-such-dir").join("receipt.json");
        assert!(write_durably(&missing, b"x").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"second", "untouched");
        assert_eq!(leftovers(), 0);
    }
}
