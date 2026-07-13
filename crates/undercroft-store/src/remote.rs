//! Remote vector-index integration.
//!
//! A remote backend (Qdrant / Chroma / pgvector) is an *untrusted search
//! accelerator*, never the system of record:
//!
//! * `index_push` uploads each drawer's **sealed** content blob (base64 of
//!   the AEAD output — ciphertext for sealed vaults) plus its embedding and
//!   wing/room labels;
//! * `search_with_index` asks the remote for candidate ids only, then
//!   re-loads every candidate from the local palace where the HMAC is
//!   verified and content decrypted. A compromised index can *omit*
//!   results, but cannot forge, alter, or inject them;
//! * final ranking is recomputed locally (semantic + lexical + recency),
//!   so remote score manipulation cannot smuggle a bad record to the top.

use base64::Engine;
use undercroft_index::{IndexRecord, VectorIndex};

use crate::{PalaceStore, SearchHit, SearchOptions, StoreError};

impl PalaceStore {
    /// Collection name for this vault on remote backends.
    pub fn index_collection(&self) -> String {
        format!("undercroft_{}", self.vault.id())
    }

    /// Push every drawer to a remote index (sealed content + embeddings).
    /// Returns the number of records uploaded.
    pub fn index_push(&self, index: &mut dyn VectorIndex) -> Result<u64, StoreError> {
        let collection = self.index_collection();
        index.ensure(&collection, self.embedder_dimension())?;
        let mut stmt = self
            .conn
            .prepare("SELECT id, wing, room, content, embedding FROM drawers ORDER BY seq")?;
        let rows: Vec<(String, String, String, Vec<u8>, Vec<u8>)> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut batch = Vec::with_capacity(64);
        let mut pushed = 0u64;
        for (id, wing, room, content_rest, emb_rest) in rows {
            let embedding = self
                .vault
                .embedding_from_rest(&id, &emb_rest)
                .map_err(|e| StoreError::CorruptRow {
                    id: id.clone(),
                    reason: e.to_string(),
                })?;
            batch.push(IndexRecord {
                sealed_b64: b64.encode(&content_rest),
                id,
                wing,
                room,
                embedding,
            });
            if batch.len() >= 64 {
                index.upsert(&collection, &batch)?;
                pushed += batch.len() as u64;
                batch.clear();
            }
        }
        if !batch.is_empty() {
            index.upsert(&collection, &batch)?;
            pushed += batch.len() as u64;
        }
        Ok(pushed)
    }

    /// Search using a remote index for candidate retrieval. Candidates are
    /// re-verified and re-ranked locally before being returned.
    pub fn search_with_index(
        &self,
        index: &mut dyn VectorIndex,
        query: &str,
        opts: &SearchOptions,
    ) -> Result<Vec<SearchHit>, StoreError> {
        let limit = if opts.limit == 0 { 10 } else { opts.limit };
        let collection = self.index_collection();
        index.ensure(&collection, self.embedder_dimension())?;
        let qvec = self.embedder_embed(query);
        // Over-fetch so local re-ranking + relevance gating has material.
        let candidates = index.query(
            &collection,
            &qvec,
            opts.wing.as_deref(),
            (limit * 4).max(20),
        )?;
        let mut hits = Vec::new();
        for c in candidates {
            // Local load = HMAC verify + decrypt. Unknown ids (index drift
            // after deletes) are skipped, not trusted.
            let Some(drawer) = self.get(&c.id)? else {
                continue;
            };
            if let Some(room) = &opts.room {
                if &drawer.meta.room != room {
                    continue;
                }
            }
            if let Some(wing) = &opts.wing {
                if &drawer.meta.wing != wing {
                    continue;
                }
            }
            hits.push(self.score_drawer(drawer, query, &qvec));
        }
        hits.retain(|h| h.lexical > 0.0 || h.semantic > 0.56);
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hits.truncate(limit);
        Ok(hits)
    }

    /// Remote index status: name + record count for this vault's collection.
    pub fn index_status(&self, index: &mut dyn VectorIndex) -> Result<(String, u64), StoreError> {
        let collection = self.index_collection();
        index.ensure(&collection, self.embedder_dimension())?;
        Ok((index.name().to_string(), index.count(&collection)?))
    }

    pub(crate) fn embedder_dimension(&self) -> usize {
        self.embedder.dimension()
    }

    pub(crate) fn embedder_embed(&self, text: &str) -> Vec<f32> {
        self.embedder.embed(text)
    }
}
