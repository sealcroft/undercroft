//! Key material management.
//!
//! One master key per palace, from either a generated key file (default,
//! `master.key`, mode 0600) or an Argon2id-derived passphrase
//! (`UNDERCROFT_PASSPHRASE`). Per-vault keys are derived with HKDF-SHA256
//! using the vault id and a per-vault random salt as domain separation:
//!
//! ```text
//! enc_key = HKDF(master, salt=vault_salt, info="undercroft.v1/vault/<id>/enc")
//! mac_key = HKDF(master, salt=vault_salt, info="undercroft.v1/vault/<id>/mac")
//! ```
//!
//! Vaults therefore never share working keys: leaking one vault's derived
//! keys does not expose siblings, and ciphertext cannot be transplanted
//! between vaults (the AEAD AAD additionally binds vault id + record id).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::fs;
use std::io;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("master key file is corrupt (expected {KEY_LEN} bytes)")]
    CorruptKeyFile,
    #[error("argon2 failure: {0}")]
    Kdf(String),
}

/// 32-byte secret, zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) [u8; KEY_LEN]);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Load the palace master key, creating it on first use.
///
/// If `passphrase` is provided, the key is derived with Argon2id (64 MiB,
/// t=3, p=1) from the passphrase and a palace-level salt persisted at
/// `<dir>/kdf.salt`; no key material touches disk. Otherwise a random key
/// is generated once at `<dir>/master.key` with permissions 0600.
pub fn load_or_create_master(dir: &Path, passphrase: Option<&str>) -> Result<SecretKey, KeyError> {
    fs::create_dir_all(dir)?;
    match passphrase {
        Some(pw) => {
            let salt_path = dir.join("kdf.salt");
            let salt = if salt_path.exists() {
                let raw = fs::read(&salt_path)?;
                if raw.len() != SALT_LEN {
                    return Err(KeyError::CorruptKeyFile);
                }
                raw
            } else {
                let mut salt = vec![0u8; SALT_LEN];
                rand::thread_rng().fill_bytes(&mut salt);
                write_private(&salt_path, &salt)?;
                salt
            };
            let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
                .map_err(|e| KeyError::Kdf(e.to_string()))?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut out = [0u8; KEY_LEN];
            argon
                .hash_password_into(pw.as_bytes(), &salt, &mut out)
                .map_err(|e| KeyError::Kdf(e.to_string()))?;
            Ok(SecretKey(out))
        }
        None => {
            let key_path = dir.join("master.key");
            if key_path.exists() {
                let raw = fs::read(&key_path)?;
                let arr: [u8; KEY_LEN] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeyError::CorruptKeyFile)?;
                Ok(SecretKey(arr))
            } else {
                let mut key = [0u8; KEY_LEN];
                rand::thread_rng().fill_bytes(&mut key);
                write_private(&key_path, &key)?;
                Ok(SecretKey(key))
            }
        }
    }
}

/// Derive one labeled subkey for a vault from the master key.
pub fn derive_vault_key(
    master: &SecretKey,
    vault_salt: &[u8],
    vault_id: &str,
    label: &str,
) -> SecretKey {
    let hk = Hkdf::<Sha256>::new(Some(vault_salt), master.as_bytes());
    let info = format!("undercroft.v1/vault/{vault_id}/{label}");
    let mut out = [0u8; KEY_LEN];
    hk.expand(info.as_bytes(), &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SecretKey(out)
}

/// Generate a fresh random vault salt.
pub fn new_vault_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    // Key material is written once and is unrecoverable if lost — fsync the
    // file and its directory entry so creation survives power loss.
    {
        use std::io::Write;
        let mut f = fs::File::create(path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// fsync a directory so a just-created or just-renamed entry inside it
/// survives power loss. Directories cannot be opened for sync on Windows;
/// there the rename itself is the strongest primitive available, so this
/// is a no-op.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn master_key_persists_across_loads() {
        let dir = tempdir().unwrap();
        let a = load_or_create_master(dir.path(), None).unwrap();
        let b = load_or_create_master(dir.path(), None).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn passphrase_derivation_is_stable_and_salted() {
        let dir = tempdir().unwrap();
        let a = load_or_create_master(dir.path(), Some("correct horse")).unwrap();
        let b = load_or_create_master(dir.path(), Some("correct horse")).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let other = load_or_create_master(dir.path(), Some("wrong staple")).unwrap();
        assert_ne!(a.as_bytes(), other.as_bytes());
        // A different palace (different salt) with the same passphrase gets a different key.
        let dir2 = tempdir().unwrap();
        let c = load_or_create_master(dir2.path(), Some("correct horse")).unwrap();
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn vault_keys_are_domain_separated() {
        let dir = tempdir().unwrap();
        let master = load_or_create_master(dir.path(), None).unwrap();
        let salt = new_vault_salt();
        let enc_a = derive_vault_key(&master, &salt, "vault-a", "enc");
        let mac_a = derive_vault_key(&master, &salt, "vault-a", "mac");
        let enc_b = derive_vault_key(&master, &salt, "vault-b", "enc");
        assert_ne!(enc_a.as_bytes(), mac_a.as_bytes());
        assert_ne!(enc_a.as_bytes(), enc_b.as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let _ = load_or_create_master(dir.path(), None).unwrap();
        let mode = std::fs::metadata(dir.path().join("master.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
