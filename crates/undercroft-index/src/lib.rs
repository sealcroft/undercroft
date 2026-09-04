//! Remote vector indexes for Undercroft — Qdrant, Chroma, and pgvector.
//!
//! Design differs deliberately from MemPalace, which shipped
//! plaintext documents to these servers. Here a remote backend is an
//! **untrusted search accelerator**:
//!
//! * the *at-rest* content blob (base64 of the vault's AEAD output) is what
//!   gets uploaded — a compromised server reads ciphertext. For an
//!   `hmac-only` vault that blob IS the plaintext, and the store refuses
//!   the push unless the caller says otherwise (ROADMAP C8);
//! * embeddings are uploaded in the clear TO THE BACKEND because
//!   server-side ANN cannot work otherwise — the documented trade-off of
//!   remote search (embedding inversion can leak content gist; use local
//!   search if that is unacceptable). They are **not** in the clear on the
//!   WIRE: since 2026-08-05 this crate applies the same transport policy as
//!   the embedder and LLM clients — TLS or loopback, no override, with
//!   `UNDERCROFT_INDEX_CA` pinning a self-signed root — because an embedding
//!   is plaintext-derived data and the sealed-vault invariant seals vectors
//!   at rest for exactly that reason;
//! * wing/room labels ride along as filterable payload, matching the
//!   visibility they already have inside a sealed vault;
//! * queries return candidate ids only — the caller re-loads records from
//!   the local palace, where HMAC verification and decryption happen. A
//!   lying index can hide results, but cannot forge or alter them.

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("http error: {0}")]
    Http(String),
    #[error("postgres error: {0}")]
    Pg(String),
    #[error("unexpected response from backend: {0}")]
    BadResponse(String),
    /// The transport policy refused this endpoint, or a declared CA pin
    /// did not resolve. Construction-time, before a byte moves.
    #[error("{0}")]
    Transport(String),
    #[error("unknown backend {0:?} (expected: qdrant, chroma, pgvector, milvus, weaviate)")]
    UnknownBackend(String),
    #[error("backend {0} is not configured: set {1}")]
    NotConfigured(&'static str, &'static str),
}

/// One record pushed to a remote index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexRecord {
    pub id: String,
    /// Base64 of the drawer's **at-rest** content blob.
    ///
    /// This said "Never plaintext" and that was a claim the code did not
    /// enforce: `content_at_rest` returns the plaintext for an `HmacOnly`
    /// vault, and the push base64'd the raw column with no level gate
    /// (ROADMAP C8). It is sealed for a `Sealed` vault — the default and
    /// the only level this field's name describes — and the store now
    /// REFUSES to push an hmac-only vault unless the caller states that
    /// plaintext leaving the machine is intended.
    pub sealed_b64: String,
    pub wing: String,
    pub room: String,
    pub embedding: Vec<f32>,
}

/// A candidate hit from a remote query: id + backend-reported score.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: String,
    pub score: f32,
}

pub trait VectorIndex {
    fn name(&self) -> &'static str;
    /// Create/ensure the collection for a (vault, dimension) pair.
    fn ensure(&mut self, collection: &str, dim: usize) -> Result<(), IndexError>;
    fn upsert(&mut self, collection: &str, records: &[IndexRecord]) -> Result<(), IndexError>;
    fn query(
        &mut self,
        collection: &str,
        embedding: &[f32],
        wing: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Candidate>, IndexError>;
    fn count(&mut self, collection: &str) -> Result<u64, IndexError>;
    fn delete(&mut self, collection: &str, ids: &[String]) -> Result<(), IndexError>;

    /// **How many rows the mirror holds, or `None` when there is no mirror —
    /// WITHOUT creating one** (ROADMAP O83).
    ///
    /// `index_status` used to be `ensure()` followed by `count()`, and
    /// `ensure` CREATES: `PUT /collections` on qdrant, a `CREATE EXTENSION`
    /// and `CREATE TABLE` pair on pgvector, `POST /collections` on chroma,
    /// milvus and weaviate. Harmless while the only caller was an operator's own CLI;
    /// O68 then exposed it as a GET on `/v1`, an MCP read tool and a tenant
    /// data-plane route, so a READ issued DDL against operator
    /// infrastructure — from a `--read-only` server and from a tenant
    /// bearer.
    ///
    /// **`Option<u64>` is the other half.** With `ensure` running first,
    /// "no mirror exists" and "the mirror is empty" both answered `0`, so
    /// the route could not answer the question its own documentation said it
    /// existed for.
    ///
    /// Implementors must not create, and must not report ABSENT for a
    /// backend they merely could not reach — see [`get_or_absent`], which
    /// keeps those two apart. Every implementation here was probed against
    /// the live backend rather than inferred from its neighbour, because
    /// the five APIs disagree about this in ways documentation does not
    /// advertise: chroma's collection path takes the NAME (an id 404s) while
    /// its `/count` needs the ID, and milvus has an explicit
    /// `collections/has` where the others rely on a 404.
    fn status(&mut self, collection: &str) -> Result<Option<u64>, IndexError>;
}

/// The declared trust root for a self-signed backend terminator, as a PIN:
/// it REPLACES the public roots rather than adding to them, exactly as
/// `UNDERCROFT_EMBED_CA` and `UNDERCROFT_LLM_CA` do. A garbage file refuses to
/// open rather than falling back — un-pinning silently is the failure mode.
pub const CA_VAR: &str = "UNDERCROFT_INDEX_CA";

/// A policy-bound HTTP agent for a backend, 30-second timeout.
///
/// **TLS or loopback, nothing else, no override** — the same rule the
/// embedder and LLM clients have enforced since 2026-08-03, applied here
/// because every push carries embeddings and an embedding is
/// plaintext-DERIVED data (ROADMAP C8). A sealed vault's content blob is
/// ciphertext on the wire; its VECTOR was not, and the sealed-vault
/// invariant seals vectors at rest for precisely that reason.
pub(crate) fn backend_agent(base_url: &str) -> Result<ureq::Agent, IndexError> {
    backend_agent_with(base_url, std::time::Duration::from_secs(30))
}

/// A GET whose **404 means ABSENT** and whose every other failure is still a
/// failure (ROADMAP O83).
///
/// The distinction is the whole point of [`VectorIndex::status`]. *"There is
/// no mirror"* and *"I could not reach the backend"* are different answers,
/// and the existing `ensure` implementations conflate them deliberately —
/// qdrant's is `if exists.is_ok() { return }` and weaviate's the same shape,
/// so a network blip reads as "absent" and the next line CREATES. That is
/// harmless when the next step is to create and dishonest when the next step
/// is to REPORT: it would tell an operator their mirror is gone because a
/// TLS handshake failed.
///
/// Shared because all three HTTP backends have byte-identical `call` error
/// mapping, and a second copy of this decision is how the two would drift.
pub(crate) fn get_or_absent(
    agent: &ureq::Agent,
    url: &str,
) -> Result<Option<serde_json::Value>, IndexError> {
    match agent.get(url).call() {
        Ok(r) => Ok(Some(r.into_json().unwrap_or(serde_json::Value::Null))),
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(ureq::Error::Status(code, r)) => Err(IndexError::Http(format!(
            "GET {url} -> {code}: {}",
            r.into_string().unwrap_or_default()
        ))),
        Err(e) => Err(IndexError::Http(e.to_string())),
    }
}

pub(crate) fn backend_agent_with(
    base_url: &str,
    timeout: std::time::Duration,
) -> Result<ureq::Agent, IndexError> {
    // Resolved ONCE per process, not per call — the shape declared a defect
    // on the orchestrator hop (a bad pin binds the port and then fails every
    // request) and present here too, with the same consequence one layer
    // down: a push re-read and re-parsed the PEM for every batch, and the
    // pin was mutable at runtime by anything that could rewrite the file.
    // `agent_from_env` is also where the four `*_CA` variables agree about
    // what an empty declaration means.
    undercroft_net::agent_from_env("the remote index", base_url, CA_VAR, timeout)
        .map_err(|e| IndexError::Transport(e.to_string()))
}

/// Construct a backend by name from environment configuration
/// (`UNDERCROFT_QDRANT_URL`, `UNDERCROFT_CHROMA_URL`, `UNDERCROFT_PGVECTOR_DSN`).
pub fn from_env(backend: &str) -> Result<Box<dyn VectorIndex>, IndexError> {
    match backend {
        "qdrant" => {
            let url = std::env::var("UNDERCROFT_QDRANT_URL")
                .map_err(|_| IndexError::NotConfigured("qdrant", "UNDERCROFT_QDRANT_URL"))?;
            Ok(Box::new(qdrant::QdrantIndex::new(&url)?))
        }
        "chroma" => {
            let url = std::env::var("UNDERCROFT_CHROMA_URL")
                .map_err(|_| IndexError::NotConfigured("chroma", "UNDERCROFT_CHROMA_URL"))?;
            Ok(Box::new(chroma::ChromaIndex::new(&url)?))
        }
        "pgvector" => {
            let dsn = std::env::var("UNDERCROFT_PGVECTOR_DSN")
                .map_err(|_| IndexError::NotConfigured("pgvector", "UNDERCROFT_PGVECTOR_DSN"))?;
            Ok(Box::new(pgvector::PgVectorIndex::new(&dsn)?))
        }
        "milvus" => {
            let url = std::env::var("UNDERCROFT_MILVUS_URL")
                .map_err(|_| IndexError::NotConfigured("milvus", "UNDERCROFT_MILVUS_URL"))?;
            Ok(Box::new(milvus::MilvusIndex::new(&url)?))
        }
        "weaviate" => {
            let url = std::env::var("UNDERCROFT_WEAVIATE_URL")
                .map_err(|_| IndexError::NotConfigured("weaviate", "UNDERCROFT_WEAVIATE_URL"))?;
            Ok(Box::new(weaviate::WeaviateIndex::new(&url)?))
        }
        other => Err(IndexError::UnknownBackend(other.into())),
    }
}

pub mod qdrant {
    use super::*;
    use serde_json::{json, Value};

    pub struct QdrantIndex {
        base: String,
        agent: ureq::Agent,
    }

    impl QdrantIndex {
        pub fn new(base_url: &str) -> Result<Self, IndexError> {
            Ok(Self {
                base: base_url.trim_end_matches('/').to_string(),
                agent: super::backend_agent(base_url)?,
            })
        }

        fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, IndexError> {
            let url = format!("{}{}", self.base, path);
            let req = self.agent.request(method, &url);
            let resp = match body {
                Some(b) => req.send_json(b),
                None => req.call(),
            };
            match resp {
                Ok(r) => r
                    .into_json()
                    .map_err(|e| IndexError::BadResponse(e.to_string())),
                Err(ureq::Error::Status(code, r)) => Err(IndexError::Http(format!(
                    "{method} {url} -> {code}: {}",
                    r.into_string().unwrap_or_default()
                ))),
                Err(e) => Err(IndexError::Http(e.to_string())),
            }
        }

        /// Qdrant point ids must be UUIDs or unsigned ints; derive a stable
        /// UUID-shaped id from our hex record id.
        fn point_id(id: &str) -> String {
            let h = format!("{:0<32}", id.chars().take(32).collect::<String>());
            format!(
                "{}-{}-{}-{}-{}",
                &h[0..8],
                &h[8..12],
                &h[12..16],
                &h[16..20],
                &h[20..32]
            )
        }

        /// Exposed so the unit test can exercise `point_id` ITSELF, for the
        /// same reason as `PgVectorIndex::table_for_test`: the test used to
        /// assert against a hand-copied duplicate of this body kept at crate
        /// root, so `point_id` could change shape with the test still green.
        #[doc(hidden)]
        pub fn point_id_for_test(id: &str) -> String {
            Self::point_id(id)
        }
    }

    impl VectorIndex for QdrantIndex {
        fn name(&self) -> &'static str {
            "qdrant"
        }

        fn ensure(&mut self, collection: &str, dim: usize) -> Result<(), IndexError> {
            let exists = self.call("GET", &format!("/collections/{collection}"), None);
            if exists.is_ok() {
                return Ok(());
            }
            self.call(
                "PUT",
                &format!("/collections/{collection}"),
                Some(json!({ "vectors": { "size": dim, "distance": "Cosine" } })),
            )?;
            Ok(())
        }

        fn upsert(&mut self, collection: &str, records: &[IndexRecord]) -> Result<(), IndexError> {
            let points: Vec<Value> = records
                .iter()
                .map(|r| {
                    json!({
                        "id": Self::point_id(&r.id),
                        "vector": r.embedding,
                        "payload": {
                            "record_id": r.id,
                            "sealed_b64": r.sealed_b64,
                            "wing": r.wing,
                            "room": r.room
                        }
                    })
                })
                .collect();
            self.call(
                "PUT",
                &format!("/collections/{collection}/points?wait=true"),
                Some(json!({ "points": points })),
            )?;
            Ok(())
        }

        fn query(
            &mut self,
            collection: &str,
            embedding: &[f32],
            wing: Option<&str>,
            limit: usize,
        ) -> Result<Vec<Candidate>, IndexError> {
            let mut body = json!({
                "vector": embedding,
                "limit": limit,
                "with_payload": ["record_id"]
            });
            if let Some(w) = wing {
                body["filter"] = json!({ "must": [ { "key": "wing", "match": { "value": w } } ] });
            }
            let resp = self.call(
                "POST",
                &format!("/collections/{collection}/points/search"),
                Some(body),
            )?;
            let hits = resp
                .get("result")
                .and_then(Value::as_array)
                .ok_or_else(|| IndexError::BadResponse("missing result array".into()))?;
            Ok(hits
                .iter()
                .filter_map(|h| {
                    Some(Candidate {
                        id: h.pointer("/payload/record_id")?.as_str()?.to_string(),
                        score: h.get("score")?.as_f64()? as f32,
                    })
                })
                .collect())
        }

        /// Probed against qdrant 1.x: absent -> 404, present -> 200.
        fn status(&mut self, collection: &str) -> Result<Option<u64>, IndexError> {
            let url = format!("{}/collections/{collection}", self.base);
            if super::get_or_absent(&self.agent, &url)?.is_none() {
                return Ok(None);
            }
            self.count(collection).map(Some)
        }

        fn count(&mut self, collection: &str) -> Result<u64, IndexError> {
            let resp = self.call(
                "POST",
                &format!("/collections/{collection}/points/count"),
                Some(json!({ "exact": true })),
            )?;
            resp.pointer("/result/count")
                .and_then(Value::as_u64)
                .ok_or_else(|| IndexError::BadResponse("missing count".into()))
        }

        fn delete(&mut self, collection: &str, ids: &[String]) -> Result<(), IndexError> {
            let points: Vec<String> = ids.iter().map(|i| Self::point_id(i)).collect();
            self.call(
                "POST",
                &format!("/collections/{collection}/points/delete?wait=true"),
                Some(json!({ "points": points })),
            )?;
            Ok(())
        }
    }
}

pub mod chroma {
    use super::*;
    use serde_json::{json, Value};

    /// Chroma server (REST v2 API). Collection ids are resolved by name and
    /// cached per process.
    pub struct ChromaIndex {
        base: String,
        agent: ureq::Agent,
        ids: std::collections::HashMap<String, String>,
    }

    impl ChromaIndex {
        pub fn new(base_url: &str) -> Result<Self, IndexError> {
            Ok(Self {
                base: format!(
                    "{}/api/v2/tenants/default_tenant/databases/default_database",
                    base_url.trim_end_matches('/')
                ),
                agent: super::backend_agent(base_url)?,
                ids: Default::default(),
            })
        }

        fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, IndexError> {
            let url = format!("{}{}", self.base, path);
            let req = self.agent.request(method, &url);
            let resp = match body {
                Some(b) => req.send_json(b),
                None => req.call(),
            };
            match resp {
                Ok(r) => Ok(r.into_json().unwrap_or(Value::Null)),
                Err(ureq::Error::Status(code, r)) => Err(IndexError::Http(format!(
                    "{method} {url} -> {code}: {}",
                    r.into_string().unwrap_or_default()
                ))),
                Err(e) => Err(IndexError::Http(e.to_string())),
            }
        }

        fn collection_id(&mut self, name: &str, dim: usize) -> Result<String, IndexError> {
            if let Some(id) = self.ids.get(name) {
                return Ok(id.clone());
            }
            let resp = self.call(
                "POST",
                "/collections",
                Some(json!({
                    "name": name,
                    "get_or_create": true,
                    "configuration": { "hnsw": { "space": "cosine" } },
                    "metadata": { "dimension": dim }
                })),
            )?;
            let id = resp
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| IndexError::BadResponse("collection create returned no id".into()))?
                .to_string();
            self.ids.insert(name.to_string(), id.clone());
            Ok(id)
        }
    }

    impl VectorIndex for ChromaIndex {
        fn name(&self) -> &'static str {
            "chroma"
        }

        fn ensure(&mut self, collection: &str, dim: usize) -> Result<(), IndexError> {
            self.collection_id(collection, dim).map(|_| ())
        }

        fn upsert(&mut self, collection: &str, records: &[IndexRecord]) -> Result<(), IndexError> {
            let cid = self
                .ids
                .get(collection)
                .cloned()
                .ok_or_else(|| IndexError::BadResponse("ensure() not called".into()))?;
            let body = json!({
                "ids": records.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
                "embeddings": records.iter().map(|r| r.embedding.clone()).collect::<Vec<_>>(),
                // Documents carry only sealed bytes; metadata carries structure.
                "documents": records.iter().map(|r| r.sealed_b64.clone()).collect::<Vec<_>>(),
                "metadatas": records
                    .iter()
                    .map(|r| json!({ "wing": r.wing, "room": r.room }))
                    .collect::<Vec<_>>(),
            });
            self.call("POST", &format!("/collections/{cid}/upsert"), Some(body))?;
            Ok(())
        }

        fn query(
            &mut self,
            collection: &str,
            embedding: &[f32],
            wing: Option<&str>,
            limit: usize,
        ) -> Result<Vec<Candidate>, IndexError> {
            let cid = self
                .ids
                .get(collection)
                .cloned()
                .ok_or_else(|| IndexError::BadResponse("ensure() not called".into()))?;
            let mut body = json!({
                "query_embeddings": [embedding],
                "n_results": limit,
                "include": ["distances"]
            });
            if let Some(w) = wing {
                body["where"] = json!({ "wing": w });
            }
            let resp = self.call("POST", &format!("/collections/{cid}/query"), Some(body))?;
            let ids = resp
                .pointer("/ids/0")
                .and_then(Value::as_array)
                .ok_or_else(|| IndexError::BadResponse("missing ids".into()))?;
            let dists = resp.pointer("/distances/0").and_then(Value::as_array);
            Ok(ids
                .iter()
                .enumerate()
                .filter_map(|(i, id)| {
                    let d = dists
                        .and_then(|ds| ds.get(i))
                        .and_then(Value::as_f64)
                        .unwrap_or(1.0) as f32;
                    Some(Candidate {
                        id: id.as_str()?.to_string(),
                        score: 1.0 - d,
                    })
                })
                .collect())
        }

        /// **Probed, because reasoning gets this one backwards.** In chroma
        /// v2 the collection path segment is the NAME — `GET
        /// /collections/{name}` answers 200 with the id, and the same path
        /// with an ID answers 404 — while `/count` needs the ID and rejects
        /// a name with `400 Collection ID is not a valid UUIDv4`. So this is
        /// two calls, and neither is `POST /collections` with
        /// `get_or_create: true`, which is what `collection_id` does and
        /// what made a status call CREATE.
        fn status(&mut self, collection: &str) -> Result<Option<u64>, IndexError> {
            let url = format!("{}/collections/{collection}", self.base);
            let Some(found) = super::get_or_absent(&self.agent, &url)? else {
                return Ok(None);
            };
            let id = found
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| IndexError::BadResponse("collection lookup returned no id".into()))?
                .to_string();
            // Cache it: this resolved the same thing `collection_id` would
            // have, without creating, so a later call need not ask again.
            self.ids.insert(collection.to_string(), id.clone());
            let resp = self.call("GET", &format!("/collections/{id}/count"), None)?;
            resp.as_u64()
                .map(Some)
                .ok_or_else(|| IndexError::BadResponse("count not a number".into()))
        }

        fn count(&mut self, collection: &str) -> Result<u64, IndexError> {
            let cid = self
                .ids
                .get(collection)
                .cloned()
                .ok_or_else(|| IndexError::BadResponse("ensure() not called".into()))?;
            let resp = self.call("GET", &format!("/collections/{cid}/count"), None)?;
            resp.as_u64()
                .ok_or_else(|| IndexError::BadResponse("count not a number".into()))
        }

        fn delete(&mut self, collection: &str, ids: &[String]) -> Result<(), IndexError> {
            let cid = self
                .ids
                .get(collection)
                .cloned()
                .ok_or_else(|| IndexError::BadResponse("ensure() not called".into()))?;
            self.call(
                "POST",
                &format!("/collections/{cid}/delete"),
                Some(json!({ "ids": ids })),
            )?;
            Ok(())
        }
    }
}

pub mod pgvector {
    use super::*;
    use postgres::{Client, NoTls};

    /// Postgres + pgvector. One table per collection:
    /// `undercroft_<collection>(id text pk, sealed_b64 text, wing text,
    /// room text, embedding vector(dim))`.
    pub struct PgVectorIndex {
        client: Client,
    }

    /// Is this DSN pointed at this machine?
    ///
    /// **Asks the parser the CONNECTOR uses, and does not read the string by
    /// hand (ROADMAP O90).** `postgres::Client::connect` is literally
    /// `params.parse::<Config>()?.connect(tls)`, and `postgres::Config`'s
    /// `FromStr` delegates to `tokio_postgres::Config` — the type parsed
    /// here. Both DSN spellings, URL and key/value, go through it, so this
    /// predicate cannot disagree with where the connection actually goes.
    ///
    /// **It used to fail OPEN, and the gate it guards has no override.** The
    /// old body scanned whitespace-split fields for a literal `host=` prefix
    /// and ended `saw_host || !d.is_empty()`, which conflates *"there is no
    /// host"* with *"I did not parse the host that is there"*. Every DSN
    /// whose host is spelled another way therefore read as loopback and
    /// skipped the cleartext refusal, sending plaintext-derived embeddings
    /// across the network:
    ///
    /// | DSN | old | now |
    /// |---|---|---|
    /// | `host=10.0.0.5 dbname=x` | refuses | refuses |
    /// | `hostaddr=10.0.0.5 dbname=x` | **loopback** | refuses |
    /// | `host = 10.0.0.5 dbname=x` | **loopback** | refuses |
    ///
    /// Both bypasses reach the connector — verified by reading its parser,
    /// which the filing had left open: `parameter()` runs
    /// `skip_ws()`/`eat('=')`/`skip_ws()`, so whitespace around `=` is legal,
    /// and `hostaddr` is a recognised key that `host` does not cover.
    ///
    /// `hostaddr` is what the connection actually dials when both are
    /// present (`host` then serves verification), so **every** host and every
    /// hostaddr must be loopback — a comma list is a list, and one remote
    /// entry is enough to refuse. A DSN that does not parse is NOT loopback,
    /// which is the direction the old doc claimed and the old body did not.
    pub(crate) fn dsn_is_loopback(dsn: &str) -> bool {
        let d = dsn.trim();
        // An empty DSN is a failed interpolation, not a declaration that the
        // database is local. Refusing keeps the pre-O90 answer for this case.
        if d.is_empty() {
            return false;
        }
        let Ok(cfg) = d.parse::<tokio_postgres::Config>() else {
            return false;
        };
        let hosts = cfg.get_hosts();
        let addrs = cfg.get_hostaddrs();
        // Neither key given: libpq's default really is the local socket.
        if hosts.is_empty() && addrs.is_empty() {
            return true;
        }
        addrs.iter().all(|ip| ip.is_loopback())
            && hosts.iter().all(|h| match h {
                // A unix socket never leaves the machine.
                //
                // `#[cfg(unix)]` because the VARIANT is: `Host::Unix` does not
                // exist off unix, so naming it unconditionally does not compile
                // for `x86_64-pc-windows-msvc` — which is a target this project
                // ships a binary for, and which nothing but `release.yml`
                // builds. The `Tcp` arm below already handles the non-unix
                // case, where a socket path arrives as an unresolvable name.
                #[cfg(unix)]
                tokio_postgres::config::Host::Unix(_) => true,
                tokio_postgres::config::Host::Tcp(name) => {
                    name == "localhost"
                        || name
                            .parse::<std::net::IpAddr>()
                            .map(|ip| ip.is_loopback())
                            .unwrap_or(false)
                        // `Config::host` only maps a leading `/` to `Unix`
                        // under `cfg(unix)`; off it, a socket path arrives
                        // here as a `Tcp` name that can never resolve.
                        || name.starts_with('/')
                }
            })
    }

    /// Does this DSN ask for TLS?
    ///
    /// `sslmode` is the only thing in a DSN that can. `require` is accepted
    /// and `disable`/`allow`/`prefer` are not, because `prefer` silently
    /// falls back to cleartext — exactly the silent-downgrade shape this
    /// policy exists to refuse.
    ///
    /// **`require` here is not libpq's `require`.** In libpq that mode
    /// encrypts without verifying anything. The connector this crate hands
    /// `postgres` is rustls, which always verifies the chain and the
    /// hostname against its configured roots, so `require` behaves as
    /// `verify-full` does elsewhere. `verify-ca`/`verify-full` are matched
    /// too because an operator may well write them, but `tokio-postgres`
    /// itself only parses `disable`/`prefer`/`require` — spelling one of
    /// the stronger modes in the DSN makes the connection string
    /// unparseable, so the accepted spelling is `require` and the
    /// verification comes from the connector.
    pub(crate) fn dsn_demands_tls(dsn: &str) -> bool {
        let lower = dsn.to_ascii_lowercase();
        [
            "sslmode=require",
            "sslmode=verify-ca",
            "sslmode=verify-full",
        ]
        .iter()
        .any(|m| lower.contains(m))
    }

    impl PgVectorIndex {
        pub fn new(dsn: &str) -> Result<Self, IndexError> {
            // The same rule as every other client, spelled for libpq:
            // cleartext beyond loopback is refused at construction, before
            // a byte moves (ROADMAP C8). This backend was wired `NoTls`
            // with no check at all, so for pgvector **no TLS-compliant
            // configuration existed** — the refusal below would have been
            // unsatisfiable, which is why the connector had to come with it.
            if !dsn_is_loopback(dsn) && !dsn_demands_tls(dsn) {
                return Err(IndexError::Transport(format!(
                    "the pgvector DSN points at a non-loopback host without TLS. Embeddings are plaintext-derived and would cross the network in the clear. Add `sslmode=require` to {} — the connector is rustls, so it verifies the chain and the hostname, which libpq's `require` does not — and declare the server's root with {} if it is self-signed. There is no override.",
                    "UNDERCROFT_PGVECTOR_DSN", CA_VAR
                )));
            }
            // **Resolved UNCONDITIONALLY, above the branch, which is the
            // whole of ROADMAP O96.** O82c moved this read into the policy
            // crate and left it inside `if dsn_demands_tls(dsn)`, so one
            // `UNDERCROFT_INDEX_CA` got TWO answers: the four HTTP backends
            // reach `agent_from_env`, which calls `pin_from_env`
            // unconditionally after its transport check, and refuse a
            // whitespace-only value — while pgvector on a loopback or
            // non-TLS DSN started silently with the declaration ignored.
            // `undercroft config check` validates that variable, so a
            // pre-flight called it FATAL while the run ignored it, which is
            // the one property both config-check modules exist to provide.
            //
            // Not a new class: `parity.rs` records it verbatim for
            // `undercroft-llm` — *"applied a declared pin only `if tls`, so a
            // loopback-http base never validated the CA file while the shared
            // path did"*. O82c fixed the mechanism and kept the guard.
            //
            // The ORDER is `agent_from_env`'s, deliberately: the transport
            // refusal above comes first because it is the one an operator
            // cannot fix by editing a file, and the resolution is discarded
            // on the `NoTls` arm rather than skipped — a declared pin that
            // does not parse is a refusal on every path, not only the paths
            // that would have used it.
            let declared_ca = undercroft_net::rustls_config_from_env("the remote index", CA_VAR)
                .map_err(|e| IndexError::Transport(e.to_string()))?;
            let client = if dsn_demands_tls(dsn) {
                let tls = tokio_postgres_rustls::MakeRustlsConnect::new((*declared_ca).clone());
                Client::connect(dsn, tls).map_err(|e| IndexError::Pg(e.to_string()))?
            } else {
                Client::connect(dsn, NoTls).map_err(|e| IndexError::Pg(e.to_string()))?
            };
            Ok(Self { client })
        }

        fn table(collection: &str) -> String {
            // Collection names are vault ids (validate_name'd), but quote
            // defensively into a fixed alphabet anyway.
            let safe: String = collection
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
            format!("undercroft_{safe}")
        }

        /// Exposed so the unit test can exercise `table` ITSELF. The test
        /// used to carry a hand-copied duplicate of that body in its own
        /// module and assert against the copy, so it could not observe a
        /// change to the real function in either direction — a gate
        /// measuring an observable the defect does not move. This name
        /// remains the only way in from outside the module.
        #[doc(hidden)]
        pub fn table_for_test(collection: &str) -> String {
            Self::table(collection)
        }

        fn vec_literal(embedding: &[f32]) -> String {
            let inner: Vec<String> = embedding.iter().map(|v| v.to_string()).collect();
            format!("[{}]", inner.join(","))
        }
    }

    impl VectorIndex for PgVectorIndex {
        fn name(&self) -> &'static str {
            "pgvector"
        }

        fn ensure(&mut self, collection: &str, dim: usize) -> Result<(), IndexError> {
            let table = Self::table(collection);
            self.client
                .batch_execute(&format!(
                    "CREATE EXTENSION IF NOT EXISTS vector;
                     CREATE TABLE IF NOT EXISTS {table} (
                         id TEXT PRIMARY KEY,
                         sealed_b64 TEXT NOT NULL,
                         wing TEXT NOT NULL,
                         room TEXT NOT NULL,
                         embedding vector({dim}) NOT NULL
                     );"
                ))
                .map_err(|e| IndexError::Pg(e.to_string()))
        }

        fn upsert(&mut self, collection: &str, records: &[IndexRecord]) -> Result<(), IndexError> {
            let table = Self::table(collection);
            let mut tx = self
                .client
                .transaction()
                .map_err(|e| IndexError::Pg(e.to_string()))?;
            for r in records {
                tx.execute(
                    &format!(
                        "INSERT INTO {table} (id, sealed_b64, wing, room, embedding)
                         VALUES ($1, $2, $3, $4, $5::text::vector)
                         ON CONFLICT (id) DO UPDATE SET
                             sealed_b64 = EXCLUDED.sealed_b64,
                             wing = EXCLUDED.wing,
                             room = EXCLUDED.room,
                             embedding = EXCLUDED.embedding"
                    ),
                    &[
                        &r.id,
                        &r.sealed_b64,
                        &r.wing,
                        &r.room,
                        &Self::vec_literal(&r.embedding),
                    ],
                )
                .map_err(|e| IndexError::Pg(e.to_string()))?;
            }
            tx.commit().map_err(|e| IndexError::Pg(e.to_string()))
        }

        fn query(
            &mut self,
            collection: &str,
            embedding: &[f32],
            wing: Option<&str>,
            limit: usize,
        ) -> Result<Vec<Candidate>, IndexError> {
            let table = Self::table(collection);
            let lit = Self::vec_literal(embedding);
            let rows = match wing {
                Some(w) => self
                    .client
                    .query(
                        &format!(
                            "SELECT id, 1 - (embedding <=> $1::text::vector) AS score
                             FROM {table} WHERE wing = $2
                             ORDER BY embedding <=> $1::text::vector LIMIT {limit}"
                        ),
                        &[&lit, &w],
                    )
                    .map_err(|e| IndexError::Pg(e.to_string()))?,
                None => self
                    .client
                    .query(
                        &format!(
                            "SELECT id, 1 - (embedding <=> $1::text::vector) AS score
                             FROM {table}
                             ORDER BY embedding <=> $1::text::vector LIMIT {limit}"
                        ),
                        &[&lit],
                    )
                    .map_err(|e| IndexError::Pg(e.to_string()))?,
            };
            Ok(rows
                .iter()
                .map(|row| Candidate {
                    id: row.get::<_, String>(0),
                    score: row.get::<_, f64>(1) as f32,
                })
                .collect())
        }

        /// `to_regclass` is core postgres and answers NULL for an absent
        /// relation — no `CREATE EXTENSION`, no `CREATE TABLE`. Probed both
        /// directions against the live server.
        fn status(&mut self, collection: &str) -> Result<Option<u64>, IndexError> {
            let table = Self::table(collection);
            let row = self
                .client
                .query_one(
                    "SELECT to_regclass($1) IS NOT NULL",
                    &[&format!("public.{table}")],
                )
                .map_err(|e| IndexError::Pg(e.to_string()))?;
            if !row.get::<_, bool>(0) {
                return Ok(None);
            }
            self.count(collection).map(Some)
        }

        fn count(&mut self, collection: &str) -> Result<u64, IndexError> {
            let table = Self::table(collection);
            let row = self
                .client
                .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
                .map_err(|e| IndexError::Pg(e.to_string()))?;
            Ok(row.get::<_, i64>(0) as u64)
        }

        fn delete(&mut self, collection: &str, ids: &[String]) -> Result<(), IndexError> {
            let table = Self::table(collection);
            self.client
                .execute(&format!("DELETE FROM {table} WHERE id = ANY($1)"), &[&ids])
                .map_err(|e| IndexError::Pg(e.to_string()))?;
            Ok(())
        }
    }
}

pub mod milvus {
    use super::*;
    use serde_json::{json, Value};

    /// Milvus standalone via the RESTful v2 API (proxy port 19530).
    /// Collections are quick-created with a VarChar primary key and dynamic
    /// fields for the sealed payload + wing/room labels.
    pub struct MilvusIndex {
        base: String,
        agent: ureq::Agent,
    }

    impl MilvusIndex {
        pub fn new(base_url: &str) -> Result<Self, IndexError> {
            Ok(Self {
                base: base_url.trim_end_matches('/').to_string(),
                agent: super::backend_agent_with(base_url, std::time::Duration::from_secs(60))?,
            })
        }

        fn call(&self, path: &str, body: Value) -> Result<Value, IndexError> {
            let url = format!("{}/v2/vectordb{}", self.base, path);
            let resp = self
                .agent
                .post(&url)
                .send_json(body)
                .map_err(|e| IndexError::Http(format!("POST {url}: {e}")))?;
            let v: Value = resp
                .into_json()
                .map_err(|e| IndexError::BadResponse(e.to_string()))?;
            let code = v.get("code").and_then(Value::as_i64).unwrap_or(0);
            if code != 0 && code != 200 {
                return Err(IndexError::BadResponse(format!("milvus code {code}: {v}")));
            }
            Ok(v)
        }
    }

    impl VectorIndex for MilvusIndex {
        fn name(&self) -> &'static str {
            "milvus"
        }

        fn ensure(&mut self, collection: &str, dim: usize) -> Result<(), IndexError> {
            self.call(
                "/collections/create",
                json!({
                    "collectionName": collection,
                    "dimension": dim,
                    "metricType": "COSINE",
                    "idType": "VarChar",
                    "primaryFieldName": "id",
                    "vectorFieldName": "vector",
                    "params": { "max_length": "64" }
                }),
            )?;
            Ok(())
        }

        fn upsert(&mut self, collection: &str, records: &[IndexRecord]) -> Result<(), IndexError> {
            let data: Vec<Value> = records
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "vector": r.embedding,
                        "sealed_b64": r.sealed_b64,
                        "wing": r.wing,
                        "room": r.room
                    })
                })
                .collect();
            self.call(
                "/entities/upsert",
                json!({ "collectionName": collection, "data": data }),
            )?;
            Ok(())
        }

        fn query(
            &mut self,
            collection: &str,
            embedding: &[f32],
            wing: Option<&str>,
            limit: usize,
        ) -> Result<Vec<Candidate>, IndexError> {
            let mut body = json!({
                "collectionName": collection,
                "data": [embedding],
                "limit": limit,
                "outputFields": ["id"],
                // Freshly-upserted entities must be visible.
                "consistencyLevel": "Strong"
            });
            if let Some(w) = wing {
                body["filter"] = json!(format!("wing == \"{}\"", w.replace('"', "")));
            }
            let resp = self.call("/entities/search", body)?;
            let hits = resp
                .get("data")
                .and_then(Value::as_array)
                .ok_or_else(|| IndexError::BadResponse("missing data array".into()))?;
            Ok(hits
                .iter()
                .filter_map(|h| {
                    Some(Candidate {
                        id: h.get("id")?.as_str()?.to_string(),
                        score: h.get("distance")?.as_f64()? as f32,
                    })
                })
                .collect())
        }

        /// Milvus is the one backend with an EXPLICIT existence call, probed
        /// live: `POST /v2/vectordb/collections/has` answers
        /// `{"code":0,"data":{"has":false}}` for an absent name. No 404 to
        /// interpret, and no create.
        fn status(&mut self, collection: &str) -> Result<Option<u64>, IndexError> {
            let resp = self.call("/collections/has", json!({ "collectionName": collection }))?;
            let has = resp
                .pointer("/data/has")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    IndexError::BadResponse("collections/has returned no `has`".into())
                })?;
            if !has {
                return Ok(None);
            }
            self.count(collection).map(Some)
        }

        fn count(&mut self, collection: &str) -> Result<u64, IndexError> {
            let resp = self.call(
                "/entities/query",
                json!({
                    "collectionName": collection,
                    "filter": "",
                    "outputFields": ["count(*)"],
                    "consistencyLevel": "Strong"
                }),
            )?;
            resp.pointer("/data/0/count(*)")
                .and_then(Value::as_u64)
                .ok_or_else(|| IndexError::BadResponse("missing count(*)".into()))
        }

        fn delete(&mut self, collection: &str, ids: &[String]) -> Result<(), IndexError> {
            let list = ids
                .iter()
                .map(|i| format!("\"{}\"", i.replace('"', "")))
                .collect::<Vec<_>>()
                .join(",");
            self.call(
                "/entities/delete",
                json!({ "collectionName": collection, "filter": format!("id in [{list}]") }),
            )?;
            Ok(())
        }
    }
}

pub mod weaviate {
    use super::*;
    use serde_json::{json, Value};

    /// Weaviate (REST v1 + GraphQL). Classes are created with
    /// `vectorizer: none` — vectors always come from the client, and the
    /// stored document is the sealed blob, never plaintext.
    pub struct WeaviateIndex {
        base: String,
        agent: ureq::Agent,
    }

    impl WeaviateIndex {
        pub fn new(base_url: &str) -> Result<Self, IndexError> {
            Ok(Self {
                base: base_url.trim_end_matches('/').to_string(),
                agent: super::backend_agent(base_url)?,
            })
        }

        /// Weaviate class names must be /[A-Z][A-Za-z0-9]*/.
        fn class_name(collection: &str) -> String {
            let safe: String = collection
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            format!("Undercroft{safe}")
        }

        /// Weaviate object ids must be UUIDs; derive one from the record id.
        fn object_id(id: &str) -> String {
            let h = format!("{:0<32}", id.chars().take(32).collect::<String>());
            format!(
                "{}-{}-{}-{}-{}",
                &h[0..8],
                &h[8..12],
                &h[12..16],
                &h[16..20],
                &h[20..32]
            )
        }

        fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, IndexError> {
            let url = format!("{}{}", self.base, path);
            let req = self.agent.request(method, &url);
            let resp = match body {
                Some(b) => req.send_json(b),
                None => req.call(),
            };
            match resp {
                Ok(r) => Ok(r.into_json().unwrap_or(Value::Null)),
                Err(ureq::Error::Status(code, r)) => Err(IndexError::Http(format!(
                    "{method} {url} -> {code}: {}",
                    r.into_string().unwrap_or_default()
                ))),
                Err(e) => Err(IndexError::Http(e.to_string())),
            }
        }
    }

    impl VectorIndex for WeaviateIndex {
        fn name(&self) -> &'static str {
            "weaviate"
        }

        fn ensure(&mut self, collection: &str, _dim: usize) -> Result<(), IndexError> {
            let class = Self::class_name(collection);
            if self
                .call("GET", &format!("/v1/schema/{class}"), None)
                .is_ok()
            {
                return Ok(());
            }
            self.call(
                "POST",
                "/v1/schema",
                Some(json!({
                    "class": class,
                    "vectorizer": "none",
                    "vectorIndexConfig": { "distance": "cosine" },
                    "properties": [
                        { "name": "record_id", "dataType": ["text"] },
                        { "name": "sealed_b64", "dataType": ["text"] },
                        { "name": "wing", "dataType": ["text"] },
                        { "name": "room", "dataType": ["text"] }
                    ]
                })),
            )?;
            Ok(())
        }

        fn upsert(&mut self, collection: &str, records: &[IndexRecord]) -> Result<(), IndexError> {
            let class = Self::class_name(collection);
            for r in records {
                let body = json!({
                    "class": class,
                    "id": Self::object_id(&r.id),
                    "vector": r.embedding,
                    "properties": {
                        "record_id": r.id,
                        "sealed_b64": r.sealed_b64,
                        "wing": r.wing,
                        "room": r.room
                    }
                });
                // PUT replaces an existing object; a new id needs POST.
                let path = format!("/v1/objects/{class}/{}", Self::object_id(&r.id));
                match self.call("PUT", &path, Some(body.clone())) {
                    Ok(_) => {}
                    Err(IndexError::Http(msg)) if msg.contains("no object with id") => {
                        self.call("POST", "/v1/objects", Some(body))?;
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }

        fn query(
            &mut self,
            collection: &str,
            embedding: &[f32],
            wing: Option<&str>,
            limit: usize,
        ) -> Result<Vec<Candidate>, IndexError> {
            let class = Self::class_name(collection);
            let vec_json = serde_json::to_string(embedding)
                .map_err(|e| IndexError::BadResponse(e.to_string()))?;
            let where_clause = match wing {
                Some(w) => format!(
                    ", where: {{ path: [\"wing\"], operator: Equal, valueText: \"{}\" }}",
                    w.replace('"', "")
                ),
                None => String::new(),
            };
            let gql = format!(
                "{{ Get {{ {class}(nearVector: {{ vector: {vec_json} }}, limit: {limit}{where_clause}) \
                 {{ record_id _additional {{ certainty }} }} }} }}"
            );
            let resp = self.call("POST", "/v1/graphql", Some(json!({ "query": gql })))?;
            if let Some(errs) = resp.get("errors") {
                if errs.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
                    return Err(IndexError::BadResponse(format!("graphql errors: {errs}")));
                }
            }
            let hits = resp
                .pointer(&format!("/data/Get/{class}"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Ok(hits
                .iter()
                .filter_map(|h| {
                    Some(Candidate {
                        id: h.get("record_id")?.as_str()?.to_string(),
                        score: h
                            .pointer("/_additional/certainty")
                            .and_then(Value::as_f64)
                            .unwrap_or(0.5) as f32,
                    })
                })
                .collect())
        }

        /// Probed live: `GET /v1/schema/{class}` answers 404 for an absent
        /// class. `ensure` already asks this question and then throws the
        /// answer away by treating ANY error as absent; this one keeps the
        /// distinction.
        fn status(&mut self, collection: &str) -> Result<Option<u64>, IndexError> {
            let class = Self::class_name(collection);
            let url = format!("{}/v1/schema/{class}", self.base);
            if super::get_or_absent(&self.agent, &url)?.is_none() {
                return Ok(None);
            }
            self.count(collection).map(Some)
        }

        fn count(&mut self, collection: &str) -> Result<u64, IndexError> {
            let class = Self::class_name(collection);
            let gql = format!("{{ Aggregate {{ {class} {{ meta {{ count }} }} }} }}");
            let resp = self.call("POST", "/v1/graphql", Some(json!({ "query": gql })))?;
            resp.pointer(&format!("/data/Aggregate/{class}/0/meta/count"))
                .and_then(Value::as_u64)
                .ok_or_else(|| IndexError::BadResponse("missing aggregate count".into()))
        }

        fn delete(&mut self, collection: &str, ids: &[String]) -> Result<(), IndexError> {
            let class = Self::class_name(collection);
            for id in ids {
                let _ = self.call(
                    "DELETE",
                    &format!("/v1/objects/{class}/{}", Self::object_id(id)),
                    None,
                );
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The pgvector DSN predicate must fail CLOSED (ROADMAP O90).**
    ///
    /// It had no test at all, which is how it shipped failing open: the old
    /// body looked for a literal `host=` prefix in whitespace-split fields
    /// and ended `saw_host || !d.is_empty()`, so *"I found no `host=`
    /// token"* and *"there is no host"* were the same answer. Any DSN whose
    /// host is spelled another way read as loopback and skipped a cleartext
    /// refusal that says, in its own words, *"There is no override"* —
    /// sending plaintext-derived embeddings across the network.
    ///
    /// Both bypass rows are reachable at the CONNECTOR, not just at this
    /// predicate: `tokio_postgres`'s key/value parser runs
    /// `skip_ws()`/`eat('=')`/`skip_ws()`, so whitespace around `=` is legal,
    /// and `hostaddr` is a key of its own that `host` never covers.
    ///
    /// The `true` rows are load-bearing: without them a predicate that
    /// simply refused everything would pass.
    #[test]
    fn a_dsn_is_loopback_only_when_every_host_in_it_is() {
        // (dsn, is_loopback, what it pins)
        let cases: &[(&str, bool, &str)] = &[
            ("host=localhost dbname=x", true, "the ordinary local DSN"),
            ("host=127.0.0.1 dbname=x", true, "a loopback literal"),
            ("host=::1 dbname=x", true, "the v6 loopback literal"),
            (
                "dbname=x user=u",
                true,
                "no host key: libpq's default IS the local socket",
            ),
            (
                "host=/var/run/postgresql dbname=x",
                true,
                "a unix socket never leaves the machine",
            ),
            (
                "postgres://localhost/x",
                true,
                "the URL spelling of the same thing",
            ),
            (
                "hostaddr=127.0.0.1 dbname=x",
                true,
                "hostaddr may legitimately BE loopback",
            ),
            (
                "host=10.0.0.5 dbname=x",
                false,
                "the one spelling the old code caught",
            ),
            (
                "hostaddr=10.0.0.5 dbname=x",
                false,
                "O90: a standard libpq key the old scan did not know — read as LOOPBACK",
            ),
            (
                "host = 10.0.0.5 dbname=x",
                false,
                "O90: libpq allows whitespace around `=`, and so does the connector",
            ),
            (
                "host=db.internal dbname=x",
                false,
                "a name we cannot resolve is not loopback",
            ),
            (
                "postgres://10.0.0.5/x",
                false,
                "the URL spelling of a remote host",
            ),
            (
                "host=localhost,10.0.0.5 dbname=x",
                false,
                "a comma list is a LIST: one remote entry is enough to refuse",
            ),
            (
                "host=localhost hostaddr=10.0.0.5 dbname=x",
                false,
                "hostaddr is what gets dialed when both are given",
            ),
            (
                "",
                false,
                "an empty DSN is a failed interpolation, not a local database",
            ),
        ];
        // Premise: the table must exercise BOTH answers, or a constant
        // predicate passes it.
        assert!(
            cases.iter().any(|c| c.1) && cases.iter().any(|c| !c.1),
            "premise: the fixture set is degenerate"
        );
        for (dsn, want, why) in cases {
            assert_eq!(pgvector::dsn_is_loopback(dsn), *want, "{dsn:?}: {why}");
        }
    }

    /// A DSN the connector cannot parse is NOT loopback.
    ///
    /// Separate from the table because it is a different claim, and because
    /// the fixture has to be verified to be unparseable rather than assumed
    /// — a string that quietly parses would make this assert nothing.
    #[test]
    fn an_unparseable_dsn_is_not_loopback() {
        // `"="` looks unparseable and is NOT — it reads as an empty key with
        // an empty value — which the premise arm below caught. Every fixture
        // here is one the connector really rejects.
        for dsn in ["host", "host=localhost bogus", "host=localhost '"] {
            assert!(
                dsn.parse::<tokio_postgres::Config>().is_err(),
                "premise: {dsn:?} must actually fail to parse"
            );
            assert!(
                !pgvector::dsn_is_loopback(dsn),
                "an unparseable DSN must take the safe direction: {dsn:?}"
            );
        }
    }

    #[test]
    fn qdrant_point_id_shape() {
        let id = qdrant::QdrantIndex::point_id_for_test("a1b2c3d4e5f60718293a4b5c6d7e8f90");
        assert_eq!(id.len(), 36);
        assert_eq!(id.matches('-').count(), 4);
        // Deterministic
        assert_eq!(
            id,
            qdrant::QdrantIndex::point_id_for_test("a1b2c3d4e5f60718293a4b5c6d7e8f90")
        );
    }

    #[test]
    fn pg_table_name_sanitized() {
        // Ensured indirectly: names map to a fixed alphabet.
        // (Construction requires a live server; only the pure helpers are
        // unit-tested. Live-server coverage is in tests/backends.rs, gated
        // on the backend URL variables the compose suite sets.)
        //
        // This calls the PRODUCTION function. It used to call a duplicate
        // of the body kept in this test module, which meant the assertion
        // held no matter what `table` did.
        let t = pgvector::PgVectorIndex::table_for_test("my-vault");
        assert_eq!(t, "undercroft_my_vault");
    }

    #[test]
    fn unknown_backend_rejected() {
        assert!(matches!(
            from_env("nope"),
            Err(IndexError::UnknownBackend(_))
        ));
    }
}
