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
use rusqlite::{params, OptionalExtension};

use crate::{PalaceStore, SearchHit, SearchOptions, StoreError};

/// Raw index-push row: (id, wing, room, content, embedding).
type PushRow = (String, String, String, Vec<u8>, Vec<u8>);

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
        let rows: Vec<PushRow> = stmt
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
        self.record_pushed_embedder()?;
        Ok(pushed)
    }

    /// Remember which embedding space the mirror was built in.
    ///
    /// The collection name is derived from the vault id alone, so nothing
    /// about a remote mirror records what its vectors mean. That is fine
    /// while the embedder never changes and silently wrong the moment it
    /// does: the query is embedded locally by the *current* embedder and
    /// matched against whatever the remote still holds.
    fn record_pushed_embedder(&self) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('index_pushed_embedder', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![self.embedder.model_name()],
        )?;
        Ok(())
    }

    /// The embedder the remote mirror was pushed with, if it was ever pushed
    /// from a build that recorded one.
    fn pushed_embedder(&self) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'index_pushed_embedder'",
                [],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
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
        // Rank to the page's far edge, slice at the end — the same page
        // semantics as the local path, so a caller iterating over a mirror
        // sees the same contract as one iterating locally.
        let depth = opts.offset.saturating_add(limit);
        // A mirror built in a different embedding space cannot rank: the
        // query is embedded here and compared there, so the candidates come
        // back effectively at random and local re-scoring then drops them —
        // an empty result from a vault that holds the answer. Refuse, and say
        // what to run, rather than return that quietly.
        if let Some(pushed) = self.pushed_embedder() {
            let current = self.embedder.model_name();
            if pushed != current {
                return Err(StoreError::IndexStale {
                    pushed,
                    current: current.to_string(),
                });
            }
        }
        let collection = self.index_collection();
        index.ensure(&collection, self.embedder_dimension())?;
        let qvec = self.embedder_embed(query);
        // Over-fetch so local re-ranking + relevance gating has material.
        let candidates = index.query(
            &collection,
            &qvec,
            opts.wing.as_deref(),
            depth.saturating_mul(4).max(20),
        )?;
        // One clock for every page of an iteration, exactly as locally.
        let now = opts.ranked_at.unwrap_or_else(time::OffsetDateTime::now_utc);
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
            // The kind filter reads the VERIFIED meta — the HMAC-covered
            // copy, not the mirror column — because on this path every
            // candidate is already decrypted and checked.
            if let Some(kind) = &opts.kind {
                if drawer.meta.kind.as_deref() != Some(kind.as_str()) {
                    continue;
                }
            }
            hits.push(self.score_drawer(drawer, query, &qvec, now));
        }
        // The exact channel, for the same reason as the local gate: an
        // approximate match should reorder a result set, never populate one.
        // The cosine leg comes from the embedder's own calibration, exactly as
        // it does locally — a mirror is an accelerator, not a different vector
        // space, and gating it differently would make the same query admit
        // differently depending on which path answered it.
        let gate = self.semantic_gate;
        hits.retain(|h| {
            h.lexical_exact > 0.0 || h.lexical_morph > 0.0 || gate.is_some_and(|g| h.semantic > g)
        });
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hits.truncate(depth);
        if opts.offset > 0 {
            hits.drain(..opts.offset.min(hits.len()));
        }
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
