//! Orchestrator control-plane state: instance registry + tenant→vault map.
//!
//! Lives in its **own** SQLite file, entirely outside any palace — the
//! engine stays tree-blind. The state is credential-bearing (engine
//! bearers, assertion secrets, tenant tokens), so it is hardened the same
//! way the engine hardens its own secrets:
//!
//! * **Engine credentials are sealed at rest** — XChaCha20-Poly1305 under
//!   the orchestrator key (`UNDERCROFT_ORCH_KEY`, 32 bytes hex), AAD-bound
//!   to the instance name (a blob copied onto another instance row fails
//!   to open, mirroring the vault-id AAD binding in the engine).
//! * **Tenant tokens are never stored** — only a domain-separated
//!   HMAC-SHA256 under the same key. A stolen state file yields no token
//!   that authorizes anything; verification recomputes the MAC.
//!
//! The orchestrator key is the root of this trust domain exactly like the
//! palace master key is the engine's; losing it means re-registering
//! instances and re-minting tenant tokens (tenant *data* lives in the
//! engine vaults and is untouched).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("{0}")]
    Invalid(String),
    #[error("credential blob failed to open (wrong UNDERCROFT_ORCH_KEY, or tampered state)")]
    Unsealable,
}

/// One registered engine instance (credentials stay sealed until asked for).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Instance {
    pub name: String,
    pub url: String,
    pub tenants: u64,
}

/// Decrypted engine credentials for one instance.
pub struct InstanceCreds {
    pub url: String,
    pub bearer: Zeroizing<String>,
    pub assertion_secret: Zeroizing<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub instance: String,
    pub vault: String,
    pub created_at: String,
}

pub struct Orch {
    conn: Connection,
    key: Zeroizing<[u8; 32]>,
    read_only: bool,
}

fn now_rfc3339() -> String {
    // Coarse wall-clock stamp; the orchestrator has no time dependency
    // beyond display, so seconds-resolution unix time keeps deps lean.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

impl Orch {
    /// Open (or create) the state database. `key_hex` is the 64-char hex
    /// orchestrator key (`UNDERCROFT_ORCH_KEY`).
    pub fn open(path: &std::path::Path, key_hex: &str) -> Result<Self, StateError> {
        let bytes = hex::decode(key_hex.trim())
            .map_err(|_| StateError::Invalid("UNDERCROFT_ORCH_KEY is not hex".into()))?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| {
            StateError::Invalid("UNDERCROFT_ORCH_KEY must be 32 bytes (64 hex)".into())
        })?;
        let conn = Connection::open(path)?;
        // Control-plane state must survive power loss: a token shown once at
        // create/rotate is gone forever if the row that recorded its HMAC is
        // lost, and a half-durable migration flip would leave routing wrong.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS instances (
                 name TEXT PRIMARY KEY,
                 url  TEXT NOT NULL,
                 cred BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tenants (
                 id         TEXT PRIMARY KEY,
                 name       TEXT NOT NULL,
                 instance   TEXT NOT NULL,
                 vault      TEXT NOT NULL,
                 token_mac  BLOB NOT NULL UNIQUE,
                 created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS meta (
                 k TEXT PRIMARY KEY,
                 v TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            conn,
            key: Zeroizing::new(key),
            read_only: false,
        })
    }

    /// Open an existing state database strictly read-only — the replica
    /// serve mode. No pragma writes, no schema creation; every mutating
    /// method refuses before SQLite would. WAL databases read fine here:
    /// on a shared volume the writer maintains the `-shm` file, and a
    /// replicated snapshot is a checkpointed plain file.
    pub fn open_read_only(path: &std::path::Path, key_hex: &str) -> Result<Self, StateError> {
        let bytes = hex::decode(key_hex.trim())
            .map_err(|_| StateError::Invalid("UNDERCROFT_ORCH_KEY is not hex".into()))?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| {
            StateError::Invalid("UNDERCROFT_ORCH_KEY must be 32 bytes (64 hex)".into())
        })?;
        if !path.exists() {
            return Err(StateError::Invalid(format!(
                "state database {path:?} does not exist (a read replica never creates one)"
            )));
        }
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        // Belt over the read-only fd: refuse writes at the connection level
        // too, so a future code path can't accidentally mutate through it.
        conn.pragma_update(None, "query_only", "ON")?;
        Ok(Self {
            conn,
            key: Zeroizing::new(key),
            read_only: true,
        })
    }

    fn require_writable(&self) -> Result<(), StateError> {
        if self.read_only {
            return Err(StateError::Invalid(
                "state database is open read-only (read replica) — mutations belong to the writer"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Stamp the moment of the last successful mutation (unix seconds) into
    /// the `meta` table. Surfaced on `/healthz` so an operator can compare
    /// a replica's view against the writer's and read the replication lag.
    fn touch_last_write(&self) -> Result<(), StateError> {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (k, v) VALUES ('last_write', ?1)",
            params![secs.to_string()],
        )?;
        Ok(())
    }

    /// The unix-seconds stamp of the last mutation this database has seen,
    /// if any. Tolerates databases from before the `meta` table existed.
    pub fn last_write(&self) -> Result<Option<u64>, StateError> {
        let has_meta: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
            [],
            |r| r.get(0),
        )?;
        if has_meta == 0 {
            return Ok(None);
        }
        let v: Option<String> = self
            .conn
            .query_row("SELECT v FROM meta WHERE k = 'last_write'", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(v.and_then(|s| s.parse().ok()))
    }

    // -- sealing -----------------------------------------------------------

    fn seal(&self, aad: &str, plain: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut out = nonce.to_vec();
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: aad.as_bytes(),
                },
            )
            .expect("xchacha20 encrypt is infallible for in-memory data");
        out.extend(ct);
        out
    }

    fn open_sealed(&self, aad: &str, blob: &[u8]) -> Result<Vec<u8>, StateError> {
        if blob.len() < 25 {
            return Err(StateError::Unsealable);
        }
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        cipher
            .decrypt(
                XNonce::from_slice(&blob[..24]),
                Payload {
                    msg: &blob[24..],
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| StateError::Unsealable)
    }

    fn token_mac(&self, token: &str) -> Vec<u8> {
        // Fully-qualified: `KeyInit` (aead) and `Mac` both define
        // `new_from_slice` and both traits are in scope here.
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.key).expect("hmac key");
        mac.update(b"orch-token\x1f");
        mac.update(token.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    // -- instances ---------------------------------------------------------

    pub fn instance_add(
        &self,
        name: &str,
        url: &str,
        bearer: &str,
        assertion_secret: &str,
    ) -> Result<(), StateError> {
        self.require_writable()?;
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(StateError::Invalid(
                "instance name must be non-empty alphanumeric/dash".into(),
            ));
        }
        let cred = serde_json::json!({ "bearer": bearer, "assertion_secret": assertion_secret });
        let blob = self.seal(
            &format!("orch/instance/{name}"),
            cred.to_string().as_bytes(),
        );
        self.conn.execute(
            "INSERT OR REPLACE INTO instances (name, url, cred) VALUES (?1, ?2, ?3)",
            params![name, url.trim_end_matches('/'), blob],
        )?;
        self.touch_last_write()
    }

    pub fn instance_list(&self) -> Result<Vec<Instance>, StateError> {
        let mut stmt = self.conn.prepare(
            "SELECT i.name, i.url,
                    (SELECT COUNT(*) FROM tenants t WHERE t.instance = i.name)
             FROM instances i ORDER BY i.name",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Instance {
                    name: r.get(0)?,
                    url: r.get(1)?,
                    tenants: r.get::<_, i64>(2)? as u64,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    pub fn instance_creds(&self, name: &str) -> Result<InstanceCreds, StateError> {
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT url, cred FROM instances WHERE name = ?1",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((url, blob)) = row else {
            return Err(StateError::Invalid(format!("unknown instance {name:?}")));
        };
        let plain = self.open_sealed(&format!("orch/instance/{name}"), &blob)?;
        let v: serde_json::Value =
            serde_json::from_slice(&plain).map_err(|_| StateError::Unsealable)?;
        let get = |k: &str| {
            v.get(k)
                .and_then(serde_json::Value::as_str)
                .map(|s| Zeroizing::new(s.to_string()))
                .ok_or(StateError::Unsealable)
        };
        Ok(InstanceCreds {
            url,
            bearer: get("bearer")?,
            assertion_secret: get("assertion_secret")?,
        })
    }

    /// Remove an instance. Refused while tenants still map to it — losing
    /// the mapping would strand their vaults.
    pub fn instance_remove(&self, name: &str) -> Result<bool, StateError> {
        self.require_writable()?;
        let tenants: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM tenants WHERE instance = ?1",
            params![name],
            |r| r.get(0),
        )?;
        if tenants > 0 {
            return Err(StateError::Invalid(format!(
                "instance {name:?} still hosts {tenants} tenant(s) — migrate them first"
            )));
        }
        let removed = self
            .conn
            .execute("DELETE FROM instances WHERE name = ?1", params![name])?
            > 0;
        if removed {
            self.touch_last_write()?;
        }
        Ok(removed)
    }

    /// The registered instance with the fewest tenants (placement default).
    pub fn instance_least_loaded(&self) -> Result<Option<String>, StateError> {
        Ok(self
            .conn
            .query_row(
                "SELECT i.name FROM instances i
                 ORDER BY (SELECT COUNT(*) FROM tenants t WHERE t.instance = i.name), i.name
                 LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?)
    }

    // -- tenants -----------------------------------------------------------

    /// Create the tenant row and mint its token (returned exactly once —
    /// only the MAC is stored). The caller creates the engine vault first;
    /// this only records the mapping.
    pub fn tenant_create(
        &self,
        name: &str,
        instance: &str,
    ) -> Result<(Tenant, String), StateError> {
        self.require_writable()?;
        let mut id_bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        let id = hex::encode(id_bytes);
        let vault = format!("tenant-{id}");
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);
        let t = Tenant {
            id: id.clone(),
            name: name.to_string(),
            instance: instance.to_string(),
            vault,
            created_at: now_rfc3339(),
        };
        self.conn.execute(
            "INSERT INTO tenants (id, name, instance, vault, token_mac, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                t.id,
                t.name,
                t.instance,
                t.vault,
                self.token_mac(&token),
                t.created_at
            ],
        )?;
        self.touch_last_write()?;
        Ok((t, token))
    }

    /// Resolve a presented tenant token to its tenant, or `None`. Lookup is
    /// by recomputed MAC — the token itself never touches disk.
    pub fn tenant_by_token(&self, token: &str) -> Result<Option<Tenant>, StateError> {
        let mac = self.token_mac(token);
        Ok(self
            .conn
            .query_row(
                "SELECT id, name, instance, vault, created_at FROM tenants WHERE token_mac = ?1",
                params![mac],
                |r| {
                    Ok(Tenant {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        instance: r.get(2)?,
                        vault: r.get(3)?,
                        created_at: r.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn tenant_get(&self, id: &str) -> Result<Option<Tenant>, StateError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, name, instance, vault, created_at FROM tenants WHERE id = ?1",
                params![id],
                |r| {
                    Ok(Tenant {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        instance: r.get(2)?,
                        vault: r.get(3)?,
                        created_at: r.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn tenant_list(&self) -> Result<Vec<Tenant>, StateError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, instance, vault, created_at FROM tenants ORDER BY created_at, id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Tenant {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    instance: r.get(2)?,
                    vault: r.get(3)?,
                    created_at: r.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// Rotate a tenant's token: mint a fresh one, replace the stored MAC.
    /// The old token stops resolving in the same statement — there is no
    /// grace window (rotation is the revocation primitive). Returned once,
    /// like at create.
    pub fn tenant_rotate_token(&self, id: &str) -> Result<String, StateError> {
        self.require_writable()?;
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);
        let n = self.conn.execute(
            "UPDATE tenants SET token_mac = ?1 WHERE id = ?2",
            params![self.token_mac(&token), id],
        )?;
        if n == 0 {
            return Err(StateError::Invalid(format!("unknown tenant {id:?}")));
        }
        self.touch_last_write()?;
        Ok(token)
    }

    pub fn tenant_set_instance(&self, id: &str, instance: &str) -> Result<(), StateError> {
        self.require_writable()?;
        let n = self.conn.execute(
            "UPDATE tenants SET instance = ?1 WHERE id = ?2",
            params![instance, id],
        )?;
        if n == 0 {
            return Err(StateError::Invalid(format!("unknown tenant {id:?}")));
        }
        self.touch_last_write()
    }

    pub fn tenant_delete(&self, id: &str) -> Result<bool, StateError> {
        self.require_writable()?;
        let deleted = self
            .conn
            .execute("DELETE FROM tenants WHERE id = ?1", params![id])?
            > 0;
        if deleted {
            self.touch_last_write()?;
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn orch() -> (tempfile::TempDir, Orch) {
        let dir = tempfile::TempDir::new().unwrap();
        let o = Orch::open(&dir.path().join("orch.db"), KEY).unwrap();
        (dir, o)
    }

    /// Durability contract: the control-plane db runs WAL + synchronous=FULL
    /// — a minted token's HMAC row and a migration flip must survive power
    /// loss the moment they are acknowledged.
    #[test]
    fn state_db_pins_wal_and_full_synchronous() {
        let (_d, o) = orch();
        let journal: String = o
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(journal.to_ascii_lowercase(), "wal");
        let sync: i64 = o
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 2, "synchronous must be FULL");
    }

    #[test]
    fn credentials_seal_and_open_with_aad_binding() {
        let (_d, o) = orch();
        o.instance_add("alpha", "http://a:8800/", "bearer-a", "secret-a")
            .unwrap();
        let c = o.instance_creds("alpha").unwrap();
        assert_eq!(c.url, "http://a:8800");
        assert_eq!(&*c.bearer, "bearer-a");
        assert_eq!(&*c.assertion_secret, "secret-a");
        // A blob copied onto another instance row must fail to open (AAD
        // binds the instance name, mirroring the engine's vault-id AAD).
        let blob: Vec<u8> = o
            .conn
            .query_row("SELECT cred FROM instances WHERE name = 'alpha'", [], |r| {
                r.get(0)
            })
            .unwrap();
        o.conn
            .execute(
                "INSERT INTO instances (name, url, cred) VALUES ('beta', 'http://b', ?1)",
                params![blob],
            )
            .unwrap();
        assert!(matches!(
            o.instance_creds("beta"),
            Err(StateError::Unsealable)
        ));
    }

    #[test]
    fn wrong_key_cannot_open_credentials() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("orch.db");
        Orch::open(&path, KEY)
            .unwrap()
            .instance_add("alpha", "http://a", "b", "s")
            .unwrap();
        let other = Orch::open(
            &path,
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        )
        .unwrap();
        assert!(matches!(
            other.instance_creds("alpha"),
            Err(StateError::Unsealable)
        ));
    }

    #[test]
    fn tokens_resolve_by_mac_and_never_store_plaintext() {
        let (_d, o) = orch();
        o.instance_add("alpha", "http://a", "b", "s").unwrap();
        let (t, token) = o.tenant_create("acme", "alpha").unwrap();
        assert_eq!(t.vault, format!("tenant-{}", t.id));
        let hit = o.tenant_by_token(&token).unwrap().expect("token resolves");
        assert_eq!(hit.id, t.id);
        assert!(o.tenant_by_token("not-a-token").unwrap().is_none());
        // The plaintext token appears nowhere in the database file.
        let count: i64 = o
            .conn
            .query_row(
                "SELECT COUNT(*) FROM tenants WHERE instr(hex(token_mac), ?1) > 0",
                params![token.to_uppercase()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn token_rotation_revokes_the_old_token_immediately() {
        let (_d, o) = orch();
        o.instance_add("alpha", "http://a", "b", "s").unwrap();
        let (t, old) = o.tenant_create("acme", "alpha").unwrap();
        let new = o.tenant_rotate_token(&t.id).unwrap();
        assert_ne!(old, new);
        assert!(o.tenant_by_token(&old).unwrap().is_none(), "old token dead");
        assert_eq!(o.tenant_by_token(&new).unwrap().unwrap().id, t.id);
        assert!(o.tenant_rotate_token("nope").is_err());
    }

    /// The read-replica contract at the state layer: a read-only handle on
    /// the writer's live database resolves tokens and opens sealed creds,
    /// refuses every mutation with a clear error, and observes the writer's
    /// changes (here: a rotation) immediately — shared-volume convergence.
    #[test]
    fn read_only_handle_serves_lookups_and_refuses_mutations() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("orch.db");
        let writer = Orch::open(&path, KEY).unwrap();
        writer.instance_add("alpha", "http://a", "b", "s").unwrap();
        let (t, token) = writer.tenant_create("acme", "alpha").unwrap();

        let replica = Orch::open_read_only(&path, KEY).unwrap();
        assert_eq!(replica.tenant_by_token(&token).unwrap().unwrap().id, t.id);
        assert_eq!(&*replica.instance_creds("alpha").unwrap().bearer, "b");
        assert!(replica.last_write().unwrap().is_some());
        for err in [
            replica.instance_add("x", "http://x", "b", "s").unwrap_err(),
            replica.tenant_create("x", "alpha").map(|_| ()).unwrap_err(),
            replica.tenant_rotate_token(&t.id).map(|_| ()).unwrap_err(),
            replica.tenant_delete(&t.id).map(|_| ()).unwrap_err(),
            replica.instance_remove("alpha").map(|_| ()).unwrap_err(),
            replica.tenant_set_instance(&t.id, "alpha").unwrap_err(),
        ] {
            assert!(err.to_string().contains("read-only"), "got: {err}");
        }
        // The writer rotates; the replica's very next lookup converges.
        let fresh = writer.tenant_rotate_token(&t.id).unwrap();
        assert!(replica.tenant_by_token(&token).unwrap().is_none());
        assert_eq!(replica.tenant_by_token(&fresh).unwrap().unwrap().id, t.id);
        // A replica never creates state.
        assert!(Orch::open_read_only(&dir.path().join("absent.db"), KEY).is_err());
    }

    #[test]
    fn least_loaded_placement_and_remove_guard() {
        let (_d, o) = orch();
        o.instance_add("alpha", "http://a", "b", "s").unwrap();
        o.instance_add("beta", "http://b", "b", "s").unwrap();
        assert_eq!(o.instance_least_loaded().unwrap().as_deref(), Some("alpha"));
        let (t1, _) = o.tenant_create("one", "alpha").unwrap();
        assert_eq!(o.instance_least_loaded().unwrap().as_deref(), Some("beta"));
        // An instance hosting tenants refuses removal.
        assert!(o.instance_remove("alpha").is_err());
        o.tenant_set_instance(&t1.id, "beta").unwrap();
        assert!(o.instance_remove("alpha").unwrap());
    }
}
