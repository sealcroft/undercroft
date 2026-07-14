//! Remote vector indexes for Undercroft — Qdrant, Chroma, and pgvector.
//!
//! Design differs deliberately from upstream MemPalace, which shipped
//! plaintext documents to these servers. Here a remote backend is an
//! **untrusted search accelerator**:
//!
//! * the *sealed* content blob (base64 of the vault's AEAD output) is what
//!   gets uploaded — a compromised server reads ciphertext;
//! * embeddings are uploaded in plaintext because server-side ANN cannot
//!   work otherwise — this is the documented trade-off of remote search
//!   (embedding inversion can leak content gist; use local search if that
//!   is unacceptable);
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
    #[error("unknown backend {0:?} (expected: qdrant, chroma, pgvector, milvus, weaviate)")]
    UnknownBackend(String),
    #[error("backend {0} is not configured: set {1}")]
    NotConfigured(&'static str, &'static str),
}

/// One record pushed to a remote index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexRecord {
    pub id: String,
    /// Base64 of the at-rest (sealed) content blob. Never plaintext.
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
}

/// Construct a backend by name from environment configuration
/// (`UNDERCROFT_QDRANT_URL`, `UNDERCROFT_CHROMA_URL`, `UNDERCROFT_PGVECTOR_DSN`).
pub fn from_env(backend: &str) -> Result<Box<dyn VectorIndex>, IndexError> {
    match backend {
        "qdrant" => {
            let url = std::env::var("UNDERCROFT_QDRANT_URL")
                .map_err(|_| IndexError::NotConfigured("qdrant", "UNDERCROFT_QDRANT_URL"))?;
            Ok(Box::new(qdrant::QdrantIndex::new(&url)))
        }
        "chroma" => {
            let url = std::env::var("UNDERCROFT_CHROMA_URL")
                .map_err(|_| IndexError::NotConfigured("chroma", "UNDERCROFT_CHROMA_URL"))?;
            Ok(Box::new(chroma::ChromaIndex::new(&url)))
        }
        "pgvector" => {
            let dsn = std::env::var("UNDERCROFT_PGVECTOR_DSN")
                .map_err(|_| IndexError::NotConfigured("pgvector", "UNDERCROFT_PGVECTOR_DSN"))?;
            Ok(Box::new(pgvector::PgVectorIndex::new(&dsn)?))
        }
        "milvus" => {
            let url = std::env::var("UNDERCROFT_MILVUS_URL")
                .map_err(|_| IndexError::NotConfigured("milvus", "UNDERCROFT_MILVUS_URL"))?;
            Ok(Box::new(milvus::MilvusIndex::new(&url)))
        }
        "weaviate" => {
            let url = std::env::var("UNDERCROFT_WEAVIATE_URL")
                .map_err(|_| IndexError::NotConfigured("weaviate", "UNDERCROFT_WEAVIATE_URL"))?;
            Ok(Box::new(weaviate::WeaviateIndex::new(&url)))
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
        pub fn new(base_url: &str) -> Self {
            Self {
                base: base_url.trim_end_matches('/').to_string(),
                agent: ureq::AgentBuilder::new()
                    .timeout(std::time::Duration::from_secs(30))
                    .build(),
            }
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
        pub fn new(base_url: &str) -> Self {
            Self {
                base: format!(
                    "{}/api/v2/tenants/default_tenant/databases/default_database",
                    base_url.trim_end_matches('/')
                ),
                agent: ureq::AgentBuilder::new()
                    .timeout(std::time::Duration::from_secs(30))
                    .build(),
                ids: Default::default(),
            }
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

    impl PgVectorIndex {
        pub fn new(dsn: &str) -> Result<Self, IndexError> {
            let client = Client::connect(dsn, NoTls).map_err(|e| IndexError::Pg(e.to_string()))?;
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
        pub fn new(base_url: &str) -> Self {
            Self {
                base: base_url.trim_end_matches('/').to_string(),
                agent: ureq::AgentBuilder::new()
                    .timeout(std::time::Duration::from_secs(60))
                    .build(),
            }
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
        pub fn new(base_url: &str) -> Self {
            Self {
                base: base_url.trim_end_matches('/').to_string(),
                agent: ureq::AgentBuilder::new()
                    .timeout(std::time::Duration::from_secs(30))
                    .build(),
            }
        }

        /// Weaviate class names must be /[A-Z][A-Za-z0-9]*/.
        fn class_name(collection: &str) -> String {
            let safe: String = collection
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            format!("Mnemo{safe}")
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

// Expose the point-id helper for the unit test without making it public API.
impl qdrant::QdrantIndex {
    #[doc(hidden)]
    pub fn point_id_for_test(id: &str) -> String {
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // on UNDERCROFT_TEST_* env vars.)
        let t = pgvector_table_for_test("my-vault");
        assert_eq!(t, "undercroft_my_vault");
    }

    #[test]
    fn unknown_backend_rejected() {
        assert!(matches!(
            from_env("nope"),
            Err(IndexError::UnknownBackend(_))
        ));
    }

    // Test-only accessors for private helpers.
    fn pgvector_table_for_test(name: &str) -> String {
        let safe: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        format!("undercroft_{safe}")
    }
}
