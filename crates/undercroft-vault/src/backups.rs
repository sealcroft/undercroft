//! The archive side of `backup create` (ROADMAP O256, O265).
//!
//! An archive is BUILT in a stage inside `backups/` and PUBLISHED by one
//! rename, so nothing that reads `backups/` by name — `backup list`, the `/v1`
//! listing, `prune`, `restore`, an off-site sync — ever meets a half-written
//! one. The store fills the stage (the copied database, from inside the
//! snapshot it verified) and this module owns everything else: where the stage
//! is, the manifest written into it, the publish, and which archives belong to
//! which vault.
//!
//! **Which vault an archive belongs to is decided by its OWN manifest, never
//! by a name prefix** (ROADMAP O68, O265). `prune_backups` kept ten archives
//! by `starts_with("{vault}-")`, and a prefix cannot tell vault `p` from
//! `p-2024` or `p-archive`: measured, backing up `p` deleted one of `p-2024`'s
//! archives beside ten of them, and its own new archive beside ten of
//! `p-archive`'s, while printing "Backup created".

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{write_manifest_file, VerifiedManifest, DB_FILE, MANIFEST_FILE};

/// The directory under `backups/` every archive is built in before it is
/// published. It is never an archive: never listed, pruned or restorable.
pub const STAGING_DIR: &str = ".staging";

/// How many archives of one vault `backup create` keeps.
pub const KEEP: usize = 10;

/// A stage older than this belongs to a backup that crashed, and the next
/// create sweeps it. A younger one may be another process's backup in
/// progress and is never touched.
pub const STALE_STAGE: Duration = Duration::from_secs(60 * 60);

/// An archive being built: `backups/.staging/<nonce>/`.
///
/// Dropped unpublished — any refusal or error after [`Stage::begin`] — it
/// removes itself, so a failed backup leaves nothing a reader could take for
/// an archive. Its location and its random name are what prove it is a
/// backup's own, which is why sweeping an abandoned one is sound where
/// deleting an unauthenticated staged manifest was not (ROADMAP O257).
pub struct Stage {
    dir: PathBuf,
    backups: PathBuf,
    published: bool,
}

impl Stage {
    /// Create a fresh stage under `backups`, sweeping stages a crash left
    /// behind. `create_dir`, never `create_dir_all`, for the stage itself: a
    /// path planted at its name is refused rather than written into.
    pub fn begin(backups: &Path) -> io::Result<Stage> {
        let root = backups.join(STAGING_DIR);
        sweep_stale(&root);
        let mut last = None;
        // A concurrent publish removes an EMPTY `.staging` behind itself, which
        // can land between the two creates below; a second attempt meets it.
        for _ in 0..3 {
            fs::create_dir_all(&root)?;
            let dir = root.join(nonce());
            match fs::create_dir(&dir) {
                Ok(()) => {
                    return Ok(Stage {
                        dir,
                        backups: backups.to_path_buf(),
                        published: false,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.expect("three attempts were made"))
    }

    /// Where the copied database goes.
    pub fn db_path(&self) -> PathBuf {
        self.dir.join(DB_FILE)
    }

    /// Write the manifest the copied rows were verified against — its exact
    /// bytes — through the ONE manifest writer (ROADMAP O254): a nonce temp,
    /// fsync, rename, directory sync.
    pub fn write_manifest(&self, manifest: &VerifiedManifest) -> io::Result<()> {
        write_manifest_file(&self.dir, MANIFEST_FILE, &manifest.bytes)
    }

    /// Publish the stage as `backups/<name>`: it must hold EXACTLY the
    /// database and the manifest, and `name` must not exist — `rename(2)`
    /// silently replaces an EMPTY directory, so an existing entry is refused
    /// first. Then `backups/` is synced, so the archive's name is as durable
    /// as its contents.
    pub fn publish(mut self, name: &str) -> io::Result<PathBuf> {
        undercroft_core::validate_name(name, "backup")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut held: Vec<String> = fs::read_dir(&self.dir)?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<_>>()?;
        held.sort();
        if held != [DB_FILE, MANIFEST_FILE] {
            return Err(io::Error::other(format!(
                "the staged archive holds {held:?}, not exactly {DB_FILE} and {MANIFEST_FILE}; \
                 nothing was published (ROADMAP O256)"
            )));
        }
        let target = self.backups.join(name);
        if fs::symlink_metadata(&target).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("a backup named {name} already exists; nothing was published"),
            ));
        }
        crate::keys::sync_dir(&self.dir)?;
        fs::rename(&self.dir, &target)?;
        self.published = true;
        crate::keys::sync_dir(&self.backups)?;
        let _ = fs::remove_dir(self.backups.join(STAGING_DIR));
        Ok(target)
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.dir);
            let _ = fs::remove_dir(self.backups.join(STAGING_DIR));
        }
    }
}

fn nonce() -> String {
    use rand::RngCore;
    let mut n = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut n);
    hex::encode(n)
}

/// Remove the stages a crashed backup left: only entries named like a stage
/// this module creates, and only once they are older than [`STALE_STAGE`].
fn sweep_stale(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let ours = name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit());
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > STALE_STAGE);
        if ours && stale {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// The name `backup create` publishes an archive of `vault` under at `now`:
/// `{vault}-{RFC 3339 stamp, ':' and '.' replaced by '-'}`.
pub fn archive_name(vault: &str, now: time::OffsetDateTime) -> io::Result<String> {
    let stamp = now
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(io::Error::other)?
        .replace([':', '.'], "-");
    Ok(format!("{vault}-{stamp}"))
}

/// The vault an archive belongs to, read from the archive's OWN manifest —
/// the authority ROADMAP O68 ruled, since a directory name is not one.
pub fn archive_vault_id(dir: &Path) -> Result<String, crate::VaultError> {
    let raw = fs::read(dir.join(MANIFEST_FILE))?;
    let v: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| crate::VaultError::CorruptManifest(e.to_string()))?;
    let id = v
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if id.is_empty() {
        return Err(crate::VaultError::CorruptManifest(format!(
            "backup at {} has no vault id in its manifest",
            dir.display()
        )));
    }
    undercroft_core::validate_name(id, "vault")?;
    Ok(id.to_string())
}

/// The sort key of a `{vault}-` name's remainder when it is exactly a stamp
/// [`archive_name`] writes — `YYYY-MM-DDTHH-MM-SS`, then `Z`, or `-` and one
/// to nine fraction digits and `Z` — as the seconds and the nanoseconds.
///
/// The name is not sorted as a string: `…03Z` sorts after `…03-5Z` although
/// it is the earlier instant.
fn stamp_key(rest: &str) -> Option<(&str, u32)> {
    let b = rest.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let shape = digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b'-'
        && digits(14..16)
        && b[16] == b'-'
        && digits(17..19);
    if !shape {
        return None;
    }
    let (secs, tail) = rest.split_at(19);
    let frac = match tail.as_bytes() {
        [b'Z'] => "",
        [b'-', f @ .., b'Z'] if (1..=9).contains(&f.len()) && f.iter().all(u8::is_ascii_digit) => {
            &tail[1..tail.len() - 1]
        }
        _ => return None,
    };
    let nanos = format!("{frac:0<9}").parse().ok()?;
    Some((secs, nanos))
}

/// The archives `backup create` published for `vault`, OLDEST first: every
/// entry named `{vault}-{stamp}` in exactly [`archive_name`]'s shape whose own
/// manifest names `vault`. Never the stage, never another vault's archive,
/// never a directory without a manifest.
pub fn archives_of(backups: &Path, vault: &str) -> io::Result<Vec<String>> {
    let entries = match fs::read_dir(backups) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let prefix = format!("{vault}-");
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(key) = name.strip_prefix(&prefix).and_then(stamp_key) else {
            continue;
        };
        let key = (key.0.to_string(), key.1);
        if archive_vault_id(&entry.path()).ok().as_deref() == Some(vault) {
            found.push((key, name));
        }
    }
    found.sort();
    Ok(found.into_iter().map(|(_, name)| name).collect())
}

/// Keep `vault`'s newest `keep` archives and remove the rest; the number
/// removed. An archive another process removed first is not a failure.
pub fn prune(backups: &Path, vault: &str, keep: usize) -> io::Result<usize> {
    let names = archives_of(backups, vault)?;
    let mut removed = 0;
    for name in names.iter().take(names.len().saturating_sub(keep)) {
        match fs::remove_dir_all(backups.join(name)) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

/// Every entry of `backups/` a person listing it should see — all of them but
/// the stage, sorted by name. The CLI lists the whole palace; the `/v1`
/// listing is per vault and reads each entry's manifest instead.
pub fn list_entries(backups: &Path) -> io::Result<Vec<String>> {
    let mut names: Vec<String> = match fs::read_dir(backups) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != STAGING_DIR)
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(backups: &Path, name: &str, id: &str) {
        let d = backups.join(name);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join(MANIFEST_FILE), format!("{{\"id\":\"{id}\"}}")).unwrap();
    }

    /// **ROADMAP O265.** Backing up `p` beside `p-2024` and `p-archive`
    /// removes none of theirs and keeps `p`'s newest ten. Today's prefix prune
    /// deleted one of `p-2024`'s (`-` sorts before `0`) and `p`'s own newest
    /// beside `p-archive` (`a` sorts after `2`) — both measured.
    #[test]
    fn prune_keeps_each_vaults_own_newest_and_never_a_neighbours() {
        for neighbour in ["p-2024", "p-archive"] {
            let dir = tempfile::TempDir::new().unwrap();
            let b = dir.path();
            for d in 1..=10 {
                archive(
                    b,
                    &format!("{neighbour}-2026-09-{d:02}T00-00-00Z"),
                    neighbour,
                );
            }
            for d in 1..=11 {
                archive(b, &format!("p-2026-09-{d:02}T12-00-00Z"), "p");
            }
            assert_eq!(prune(b, "p", KEEP).unwrap(), 1, "{neighbour}");
            let left = list_entries(b).unwrap();
            assert_eq!(
                left.iter()
                    .filter(|n| n.starts_with(&format!("{neighbour}-")))
                    .count(),
                10,
                "a neighbour's archive was pruned ({neighbour})"
            );
            assert!(
                !left.contains(&"p-2026-09-01T12-00-00Z".to_string()),
                "the oldest goes"
            );
            assert!(
                left.contains(&"p-2026-09-11T12-00-00Z".to_string()),
                "the newest stays"
            );
            assert_eq!(archives_of(b, "p").unwrap().len(), KEEP);
        }
    }

    /// The manifest decides, and the shape decides: an entry named like `p`'s
    /// archive whose manifest names another vault, one with no manifest, and
    /// the stage are never `p`'s.
    #[test]
    fn only_published_archives_whose_manifest_names_the_vault_count() {
        let dir = tempfile::TempDir::new().unwrap();
        let b = dir.path();
        archive(b, "p-2026-09-01T00-00-00Z", "p");
        archive(b, "p-2026-09-02T00-00-00Z", "q");
        fs::create_dir_all(b.join("p-2026-09-03T00-00-00Z")).unwrap();
        archive(b, "p-copy", "p");
        fs::create_dir_all(b.join(STAGING_DIR).join("0".repeat(32))).unwrap();
        assert_eq!(archives_of(b, "p").unwrap(), ["p-2026-09-01T00-00-00Z"]);
        assert!(!list_entries(b).unwrap().contains(&STAGING_DIR.to_string()));
    }

    /// Stamps sort as instants, not strings: a whole second before its own
    /// fractions, and fractions by value.
    #[test]
    fn archives_sort_by_the_instant_their_stamp_names() {
        let dir = tempfile::TempDir::new().unwrap();
        let b = dir.path();
        for s in ["03-5Z", "03Z", "03-56Z", "03-123456789Z", "04Z"] {
            archive(b, &format!("p-2026-09-01T00-00-{s}"), "p");
        }
        let order: Vec<String> = archives_of(b, "p")
            .unwrap()
            .into_iter()
            .map(|n| n.trim_start_matches("p-2026-09-01T00-00-").to_string())
            .collect();
        assert_eq!(order, ["03Z", "03-123456789Z", "03-5Z", "03-56Z", "04Z"]);
        let now = time::OffsetDateTime::now_utc();
        let name = archive_name("p", now).unwrap();
        assert!(
            stamp_key(name.strip_prefix("p-").unwrap()).is_some(),
            "archive_name writes the shape archives_of reads: {name}"
        );
    }

    /// A stage is removed when dropped unpublished, publishes only exactly two
    /// files, refuses an existing target — an EMPTY one included, which
    /// `rename(2)` would replace in silence — and leaves no `.staging` behind.
    #[test]
    fn a_stage_publishes_exactly_two_files_or_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let b = dir.path();
        let stage = Stage::begin(b).unwrap();
        let staged = stage.dir.clone();
        drop(stage);
        assert!(!staged.exists() && !b.join(STAGING_DIR).exists());

        let stage = Stage::begin(b).unwrap();
        fs::write(stage.db_path(), b"db").unwrap();
        assert!(stage.publish("p-x").is_err(), "one file is not an archive");
        assert!(!b.join("p-x").exists() && !b.join(STAGING_DIR).exists());

        fs::create_dir_all(b.join("p-y")).unwrap();
        let stage = Stage::begin(b).unwrap();
        fs::write(stage.db_path(), b"db").unwrap();
        fs::write(stage.dir.join(MANIFEST_FILE), b"{}").unwrap();
        let err = stage.publish("p-y").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_dir(b.join("p-y")).unwrap().count(), 0, "untouched");

        let stage = Stage::begin(b).unwrap();
        fs::write(stage.db_path(), b"db").unwrap();
        fs::write(stage.dir.join(MANIFEST_FILE), b"{}").unwrap();
        let at = stage.publish("p-z").unwrap();
        assert_eq!(at, b.join("p-z"));
        assert!(at.join(DB_FILE).exists() && !b.join(STAGING_DIR).exists());
    }

    /// Only a stage OLDER than the threshold is swept, and only one named
    /// like a stage this module creates.
    #[test]
    fn only_an_abandoned_stage_is_swept() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join(STAGING_DIR);
        let fresh = root.join("a".repeat(32));
        let foreign = root.join("not-a-stage");
        fs::create_dir_all(&fresh).unwrap();
        fs::create_dir_all(&foreign).unwrap();
        sweep_stale(&root);
        assert!(fresh.exists(), "a fresh stage may be a backup in progress");
        assert!(foreign.exists());
    }
}
