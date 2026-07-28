//! Palace management, ported from mempalace's drawer-management, diary,
//! tunnel, hallway, dedup, and stats surfaces.
//!
//! Everything here rides the vault security layer: content stays sealed,
//! every mutation is HMAC-tagged and appended to the audit chain (including
//! deletions, which log a keyed tombstone tag), and duplicate detection
//! uses a *keyed* fingerprint — HMAC of the plaintext, truncated — so the
//! stored fingerprint reveals nothing about content to an offline attacker.

use rusqlite::{params, OptionalExtension};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use undercroft_core::{entity::extract_entities, Drawer};

use crate::{chain_append, PalaceStore, StoreError};

#[derive(Debug, Clone, serde::Serialize)]
pub struct DrawerSummary {
    pub id: String,
    pub wing: String,
    pub room: String,
    pub preview: String,
    pub filed_at: String,
    pub source_file: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PalaceStats {
    pub records: u64,
    pub wings: Vec<(String, u64)>,
    pub rooms: u64,
    pub kg: crate::KgStats,
    pub tunnels: u64,
    pub writes: u64,
    pub level: String,
    pub db_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DedupReport {
    pub duplicate_groups: u64,
    pub removed: Vec<String>,
    pub applied: bool,
    /// How many distinct appearance dates were carried onto survivors rather
    /// than deleted with their rows. Reported because it is the difference
    /// between collapsing text and losing history.
    pub dates_kept: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Tunnel {
    pub id: String,
    pub from_wing: String,
    pub to_wing: String,
    pub label: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Hallway {
    pub entity_a: String,
    pub entity_b: String,
    pub strength: u64,
}

/// Raw tunnel row: (id, from_wing, to_wing, label, tag, created_at).
type TunnelRow = (String, String, String, String, Vec<u8>, String);

/// One wing's rooms with drawer counts.
pub type WingRooms = (String, Vec<(String, u64)>);

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("rfc3339 now")
}

pub(crate) fn tunnel_canonical(
    id: &str,
    from: &str,
    to: &str,
    label: &str,
    created: &str,
) -> Vec<u8> {
    format!("tunnel\x1f{id}\x1f{from}\x1f{to}\x1f{label}\x1f{created}").into_bytes()
}

impl PalaceStore {
    pub(crate) fn init_manage_schema(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tunnels (
                 seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                 id         TEXT NOT NULL UNIQUE,
                 from_wing  TEXT NOT NULL,
                 to_wing    TEXT NOT NULL,
                 label      TEXT NOT NULL,
                 tag        BLOB NOT NULL,
                 created_at TEXT NOT NULL
             );",
        )?;
        // Keyed content fingerprint for duplicate detection (nullable on
        // rows written before this column existed; backfilled by repair).
        let cols: Vec<String> = self
            .conn
            .prepare("PRAGMA table_info(drawers)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<Result<_, _>>()?;
        if !cols.iter().any(|c| c == "fp") {
            self.conn
                .execute("ALTER TABLE drawers ADD COLUMN fp BLOB", [])?;
        }
        Ok(())
    }

    /// Keyed content fingerprint: HMAC(mac_key, "fp" || content), truncated.
    /// Deterministic for equality lookups, useless without the vault key.
    ///
    /// Taken over the canonical form, not the raw bytes: two strings that
    /// render identically are the same content, and a duplicate written with
    /// composed accents or Arabic harakat encoded differently is still a
    /// duplicate. The stored text is untouched — only the key we compare by
    /// is folded.
    pub(crate) fn fingerprint(&self, content: &str) -> Vec<u8> {
        let key = undercroft_core::normalize::match_key(content);
        let mut buf = Vec::with_capacity(key.len() + 3);
        buf.extend_from_slice(b"fp\x1f");
        buf.extend_from_slice(key.as_bytes());
        self.vault.tag(&buf)[..16].to_vec()
    }

    /// Exact-duplicate lookup by content. Returns the existing drawer id.
    pub fn check_duplicate(&self, content: &str) -> Result<Option<String>, StoreError> {
        let fp = self.fingerprint(content);
        Ok(self
            .conn
            .query_row(
                "SELECT id FROM drawers WHERE fp = ?1 LIMIT 1",
                params![fp],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Page through drawer summaries, optionally scoped.
    pub fn list_drawers(
        &self,
        wing: Option<&str>,
        room: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<DrawerSummary>, StoreError> {
        let mut sql = String::from("SELECT id, meta_json, content, tag FROM drawers");
        let mut clauses = Vec::new();
        let mut binds: Vec<String> = Vec::new();
        if let Some(w) = wing {
            binds.push(w.to_string());
            clauses.push(format!("wing = ?{}", binds.len()));
        }
        if let Some(r) = room {
            binds.push(r.to_string());
            clauses.push(format!("room = ?{}", binds.len()));
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(&format!(" ORDER BY seq LIMIT {limit} OFFSET {offset}"));
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = stmt
            .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, meta_json, content_rest, tag) in rows {
            let drawer = self.verify_and_decode(&id, &meta_json, &content_rest, &tag)?;
            out.push(DrawerSummary {
                preview: drawer.content.chars().take(120).collect(),
                id: drawer.id,
                wing: drawer.meta.wing,
                room: drawer.meta.room,
                filed_at: drawer.meta.filed_at,
                source_file: drawer.meta.source_file,
            });
        }
        Ok(out)
    }

    /// Delete one drawer. Logs a keyed tombstone in the audit chain so the
    /// deletion itself is tamper-evident. Returns whether the id existed.
    pub fn delete_drawer(&mut self, id: &str) -> Result<bool, StoreError> {
        // Purge the PQ code first (needs the live seq): the ADC scan reads
        // codes without joining drawers, so orphans would linger as wasted
        // candidate slots until the next rebuild. Tail rows delete; a code
        // inside a sealed page is counted out of the page commitment
        // instead (pqidx::pq_purge_row). Advisory either way.
        self.pq_purge_row(id);
        // Both levels also hold the codes in a RAM cache — drop it wholesale
        // (deletes are rare; the next search reloads once).
        self.pq_cache.borrow_mut().take();
        self.late_purge_row(id);
        // Delete + tombstone + chain advance are one transaction: a crash
        // can't leave a deletion the audit chain never heard about.
        let tag = self.vault.tag(format!("del\x1f{id}").as_bytes());
        // Resolved before the transaction, removed inside it: the FTS index
        // must never end up shorter than the table, because under-returning
        // is what cuts a drawer out of the scan entirely.
        let fts_seq = self.fts_seq_of(id);
        let tx = self.conn.transaction()?;
        let n = tx.execute("DELETE FROM drawers WHERE id = ?1", params![id])?;
        if let Some(seq) = fts_seq {
            let _ = tx.execute("DELETE FROM drawers_fts WHERE rowid = ?1", params![seq]);
        }
        let anchor = if n > 0 {
            Some(chain_append(
                &tx,
                &self.vault,
                &format!("del/{id}"),
                &tag,
                &now_rfc3339(),
            )?)
        } else {
            None
        };
        tx.commit()?;
        if let Some((head, writes)) = anchor {
            self.vault.anchor_manifest(&head, writes)?;
            if let Some(cache) = self.emb_cache.borrow_mut().as_mut() {
                cache.remove(id);
            }
            // Drop the stale ANN index; rebuilt on the next search.
            #[cfg(feature = "hnsw")]
            self.hnsw.borrow_mut().take();
            undercroft_obs::drawer_delete();
            undercroft_obs::event_drawer_deleted(self.vault.id());
        }
        Ok(n > 0)
    }

    /// Delete every drawer mined from one source file. Returns the count.
    pub fn delete_by_source(&mut self, source_file: &str) -> Result<u64, StoreError> {
        let ids: Vec<String> = self
            .conn
            .prepare("SELECT id FROM drawers WHERE json_extract(meta_json, '$.source_file') = ?1")?
            .query_map(params![source_file], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let mut count = 0u64;
        for id in ids {
            if self.delete_drawer(&id)? {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Replace a drawer's content in place (same id/slot), re-sealed,
    /// re-embedded, re-tagged, chained.
    pub fn update_drawer(&mut self, id: &str, new_content: &str) -> Result<bool, StoreError> {
        let Some(mut drawer) = self.get(id)? else {
            return Ok(false);
        };
        drawer.content = undercroft_core::normalize_content(new_content);
        self.upsert(&drawer)?;
        Ok(true)
    }

    /// Rooms and drawer counts within one wing.
    pub fn rooms(&self, wing: &str) -> Result<Vec<(String, u64)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT room, COUNT(*) FROM drawers WHERE wing = ?1 GROUP BY room ORDER BY room",
        )?;
        let rows = stmt
            .query_map(params![wing], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// The palace's full wing → rooms tree (mempalace's taxonomy).
    pub fn taxonomy(&self) -> Result<Vec<WingRooms>, StoreError> {
        let mut out = Vec::new();
        for (wing, _) in self.wings()? {
            let rooms = self.rooms(&wing)?;
            out.push((wing, rooms));
        }
        Ok(out)
    }

    // ------------------------------------------------------------------
    // Agent diaries
    // ------------------------------------------------------------------

    /// Append a diary entry for an agent (each agent gets its own wing).
    pub fn diary_write(&mut self, agent: &str, entry: &str) -> Result<String, StoreError> {
        undercroft_core::validate_name(agent, "agent").map_err(|e| StoreError::CorruptRow {
            id: agent.into(),
            reason: e.to_string(),
        })?;
        let wing = format!("agent-{agent}");
        let normalized = undercroft_core::normalize_content(entry);
        let idx: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM drawers WHERE wing = ?1 AND room = 'diary'",
            params![wing],
            |r| r.get(0),
        )?;
        let drawer = Drawer::new(&wing, "diary", normalized, None, idx as u32, agent);
        self.upsert(&drawer)?;
        Ok(drawer.id)
    }

    /// Most recent diary entries for an agent.
    pub fn diary_read(&self, agent: &str, limit: usize) -> Result<Vec<Drawer>, StoreError> {
        let wing = format!("agent-{agent}");
        let mut entries = self.recent(Some(&wing), limit)?;
        entries.retain(|d| d.meta.room == "diary");
        Ok(entries)
    }

    /// Agents discovered from diary wings (mempalace_list_agents).
    pub fn list_agents(&self) -> Result<Vec<String>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT wing FROM drawers WHERE wing LIKE 'agent-%' ORDER BY wing")?;
        let rows: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        Ok(rows
            .into_iter()
            .map(|w| w.trim_start_matches("agent-").to_string())
            .collect())
    }

    // ------------------------------------------------------------------
    // Stats / dedup
    // ------------------------------------------------------------------

    pub fn stats(&self) -> Result<PalaceStats, StoreError> {
        let rooms: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM (SELECT DISTINCT wing, room FROM drawers)",
            [],
            |r| r.get(0),
        )?;
        let db_bytes = std::fs::metadata(self.vault.db_path())
            .map(|m| m.len())
            .unwrap_or(0);
        Ok(PalaceStats {
            records: self.count()?,
            wings: self.wings()?,
            rooms: rooms as u64,
            kg: self.kg_stats()?,
            tunnels: self.tunnel_count()?,
            writes: self.vault.writes(),
            level: self.vault.level().to_string(),
            db_bytes,
        })
    }

    /// Find exact-duplicate drawers (same keyed fingerprint). With `apply`,
    /// keep the earliest of each group and delete the rest — **carrying every
    /// deleted record's dates onto the survivor first**.
    ///
    /// The fingerprint covers content only, so a group is "the same words",
    /// not "the same event". The same words written on two different days are
    /// two things that happened, and deleting one used to destroy a date
    /// nothing could recover. Collapsing the *text* is right — it is the same
    /// text — but the chronology of when it appeared is data, so it moves to
    /// the survivor's `occurrences` before the row goes.
    pub fn dedup(&mut self, apply: bool) -> Result<DedupReport, StoreError> {
        let groups: Vec<(Vec<u8>, i64)> = self
            .conn
            .prepare(
                "SELECT fp, COUNT(*) FROM drawers WHERE fp IS NOT NULL
                 GROUP BY fp HAVING COUNT(*) > 1",
            )?
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut removed = Vec::new();
        let mut dates_kept = 0u64;
        for (fp, _) in &groups {
            let ids: Vec<String> = self
                .conn
                .prepare("SELECT id FROM drawers WHERE fp = ?1 ORDER BY seq")?
                .query_map(params![fp], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let Some((keep_id, drop_ids)) = ids.split_first() else {
                continue;
            };
            // Gather first, so a report without `apply` still says truthfully
            // how many appearances the survivor would end up holding.
            let mut survivor = self.get(keep_id)?;
            let before = survivor.as_ref().map(|d| d.all_occurrences().len());
            for id in drop_ids {
                if let (Some(keep), Some(gone)) = (survivor.as_mut(), self.get(id)?) {
                    keep.absorb_occurrences_of(&gone);
                }
                removed.push(id.clone());
            }
            if let (Some(keep), Some(before)) = (survivor.as_ref(), before) {
                let gained = keep.all_occurrences().len().saturating_sub(before);
                dates_kept += gained as u64;
                if apply && gained > 0 {
                    // Rewrite the survivor before removing the rows it now
                    // speaks for, so a crash between the two leaves the dates
                    // recorded rather than lost.
                    self.upsert(keep)?;
                }
            }
            if apply {
                for id in drop_ids {
                    self.delete_drawer(id)?;
                }
            }
        }
        Ok(DedupReport {
            duplicate_groups: groups.len() as u64,
            removed,
            applied: apply,
            dates_kept,
        })
    }

    /// Repair pass: re-fingerprint rows missing `fp`, re-embed every drawer
    /// with the current embedder (recording its identity — this is the
    /// second half of a forced model swap), vacuum, and re-verify.
    /// Returns (report, rows_backfilled).
    pub fn repair(&mut self) -> Result<(crate::VerifyReport, u64), StoreError> {
        // Re-embedding below bypasses upsert; drop any warmed cache.
        *self.emb_cache.borrow_mut() = None;
        let missing: Vec<String> = self
            .conn
            .prepare("SELECT id FROM drawers WHERE fp IS NULL")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let mut fixed = 0u64;
        for id in missing {
            if let Some(d) = self.get(&id)? {
                let fp = self.fingerprint(&d.content);
                self.conn
                    .execute("UPDATE drawers SET fp = ?1 WHERE id = ?2", params![fp, id])?;
                fixed += 1;
            }
        }
        // Re-embed everything with the current embedder. Embeddings are not
        // HMAC-covered (they are derived data), so no retagging is needed.
        let ids: Vec<String> = self
            .conn
            .prepare("SELECT id FROM drawers ORDER BY seq")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        for id in ids {
            if let Some(d) = self.get(&id)? {
                let emb = self.embedder_embed(&d.content);
                let emb_rest = self.vault.embedding_at_rest(&id, &emb);
                self.conn.execute(
                    "UPDATE drawers SET embedding = ?1 WHERE id = ?2",
                    params![emb_rest, id],
                )?;
            }
        }
        // The PQ/IVF index quantizes the vectors we just replaced; a stale
        // codebook does not fail loudly, it returns the wrong candidates.
        self.invalidate_embedding_space()?;
        self.record_embedder_identity()?;
        self.conn.execute_batch("VACUUM;")?;
        Ok((self.verify()?, fixed))
    }

    // ------------------------------------------------------------------
    // Tunnels — cross-wing connections
    // ------------------------------------------------------------------

    pub fn create_tunnel(
        &mut self,
        from_wing: &str,
        to_wing: &str,
        label: &str,
    ) -> Result<String, StoreError> {
        let id = hex::encode(
            &sha2::Sha256::digest(format!("{from_wing}\x1f{to_wing}\x1f{label}").as_bytes())[..12],
        );
        let created = now_rfc3339();
        let tag = self
            .vault
            .tag(&tunnel_canonical(&id, from_wing, to_wing, label, &created));
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO tunnels (id, from_wing, to_wing, label, tag, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO NOTHING",
            params![id, from_wing, to_wing, label, tag.as_slice(), created],
        )?;
        let (head, writes) =
            chain_append(&tx, &self.vault, &format!("tunnel/{id}"), &tag, &created)?;
        tx.commit()?;
        self.vault.anchor_manifest(&head, writes)?;
        Ok(id)
    }

    pub fn list_tunnels(&self, wing: Option<&str>) -> Result<Vec<Tunnel>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, from_wing, to_wing, label, tag, created_at FROM tunnels ORDER BY seq",
        )?;
        let rows: Vec<TunnelRow> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::new();
        for (id, from, to, label, tag, created) in rows {
            self.vault
                .verify_tag(&tunnel_canonical(&id, &from, &to, &label, &created), &tag)
                .map_err(|_| {
                    undercroft_obs::hmac_verify_failed("tunnel");
                    undercroft_obs::event_hmac_fail(self.vault.id(), "tunnel");
                    StoreError::Integrity(format!("tunnel/{id}"))
                })?;
            if wing.map(|w| from == w || to == w).unwrap_or(true) {
                out.push(Tunnel {
                    id,
                    from_wing: from,
                    to_wing: to,
                    label,
                    created_at: created,
                });
            }
        }
        Ok(out)
    }

    pub fn delete_tunnel(&mut self, id: &str) -> Result<bool, StoreError> {
        let tag = self.vault.tag(format!("del\x1ftunnel/{id}").as_bytes());
        let tx = self.conn.transaction()?;
        let n = tx.execute("DELETE FROM tunnels WHERE id = ?1", params![id])?;
        let anchor = if n > 0 {
            Some(chain_append(
                &tx,
                &self.vault,
                &format!("del/tunnel/{id}"),
                &tag,
                &now_rfc3339(),
            )?)
        } else {
            None
        };
        tx.commit()?;
        if let Some((head, writes)) = anchor {
            self.vault.anchor_manifest(&head, writes)?;
        }
        Ok(n > 0)
    }

    /// Follow a tunnel: recent drawers from the destination wing.
    pub fn follow_tunnel(&self, id: &str, limit: usize) -> Result<Vec<Drawer>, StoreError> {
        let to: Option<String> = self
            .conn
            .query_row(
                "SELECT to_wing FROM tunnels WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        match to {
            Some(wing) => self.recent(Some(&wing), limit),
            None => Ok(Vec::new()),
        }
    }

    /// BFS over tunnels from a starting wing (mempalace_traverse).
    pub fn traverse(
        &self,
        start: &str,
        max_depth: usize,
    ) -> Result<Vec<(String, usize)>, StoreError> {
        let tunnels = self.list_tunnels(None)?;
        let mut seen = vec![(start.to_string(), 0usize)];
        let mut frontier = vec![start.to_string()];
        for depth in 1..=max_depth {
            let mut next = Vec::new();
            for t in &tunnels {
                for (from, to) in [(&t.from_wing, &t.to_wing), (&t.to_wing, &t.from_wing)] {
                    if frontier.contains(from) && !seen.iter().any(|(w, _)| w == to) {
                        seen.push((to.clone(), depth));
                        next.push(to.clone());
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        Ok(seen)
    }

    pub(crate) fn tunnel_count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM tunnels", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub(crate) fn tunnels_verify(&self) -> Result<Vec<String>, StoreError> {
        let mut bad = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT id, from_wing, to_wing, label, tag, created_at FROM tunnels ORDER BY seq",
        )?;
        let rows: Vec<TunnelRow> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        for (id, from, to, label, tag, created) in rows {
            if self
                .vault
                .verify_tag(&tunnel_canonical(&id, &from, &to, &label, &created), &tag)
                .is_err()
            {
                bad.push(format!("tunnel/{id}"));
            }
        }
        Ok(bad)
    }

    // ------------------------------------------------------------------
    // Hallways — within-wing entity co-occurrence (computed on demand)
    // ------------------------------------------------------------------

    /// Entity pairs that travel together across a wing's drawers, ranked by
    /// co-occurrence count. Computed live from decrypted content — nothing
    /// entity-derived is persisted (sealed vaults leak nothing).
    pub fn hallways(&self, wing: &str, top: usize) -> Result<Vec<Hallway>, StoreError> {
        use std::collections::HashMap;
        let drawers = self.recent(Some(wing), 10_000)?;
        let mut pairs: HashMap<(String, String), u64> = HashMap::new();
        for d in &drawers {
            let ents = extract_entities(&d.content);
            for i in 0..ents.len() {
                for j in (i + 1)..ents.len() {
                    let key = (ents[i].clone(), ents[j].clone());
                    *pairs.entry(key).or_insert(0) += 1;
                }
            }
        }
        let mut out: Vec<Hallway> = pairs
            .into_iter()
            .filter(|(_, n)| *n >= 2)
            .map(|((a, b), n)| Hallway {
                entity_a: a,
                entity_b: b,
                strength: n,
            })
            .collect();
        out.sort_by(|x, y| {
            y.strength
                .cmp(&x.strength)
                .then(x.entity_a.cmp(&y.entity_a))
        });
        out.truncate(top);
        Ok(out)
    }

    // ------------------------------------------------------------------
    // Closets — compact LLM-scannable index (port of the AAAK idea)
    // ------------------------------------------------------------------

    /// Compact index lines an LLM can scan to decide which drawers to open
    /// — the Rust port of mempalace's AAAK/closet concept, deterministic
    /// (no LLM required to build). One line per room:
    ///
    /// `wing/room n=COUNT span=FIRST..LAST keys=entity,entity,… ids=ID,ID,…`
    ///
    /// Computed on demand from decrypted content; nothing is persisted, so
    /// sealed vaults leak nothing.
    pub fn closet_index(&self, wing: Option<&str>) -> Result<Vec<String>, StoreError> {
        use std::collections::BTreeMap;
        let drawers = self.recent(wing, 100_000)?;
        let mut rooms: BTreeMap<(String, String), Vec<&Drawer>> = BTreeMap::new();
        for d in &drawers {
            rooms
                .entry((d.meta.wing.clone(), d.meta.room.clone()))
                .or_default()
                .push(d);
        }
        let mut out = Vec::with_capacity(rooms.len());
        for ((w, r), ds) in rooms {
            let mut dates: Vec<&str> = ds.iter().map(|d| d.meta.filed_at.as_str()).collect();
            dates.sort();
            let span = match (dates.first(), dates.last()) {
                (Some(a), Some(b)) => {
                    format!("{}..{}", &a[..10.min(a.len())], &b[..10.min(b.len())])
                }
                _ => String::new(),
            };
            // Top entities by frequency across the room's drawers.
            let mut freq: std::collections::HashMap<String, u32> = Default::default();
            for d in &ds {
                for e in extract_entities(&d.content) {
                    *freq.entry(e).or_insert(0) += 1;
                }
            }
            let mut keys: Vec<(String, u32)> = freq.into_iter().collect();
            keys.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let keys: Vec<String> = keys.into_iter().take(6).map(|(k, _)| k).collect();
            let ids: Vec<&str> = ds.iter().take(4).map(|d| d.id.as_str()).collect();
            out.push(format!(
                "{w}/{r} n={} span={span} keys={} ids={}",
                ds.len(),
                keys.join(","),
                ids.join(",")
            ));
        }
        Ok(out)
    }

    /// Shared verify-and-decode used by list paths.
    fn verify_and_decode(
        &self,
        id: &str,
        meta_json: &str,
        content_rest: &[u8],
        tag: &[u8],
    ) -> Result<Drawer, StoreError> {
        self.vault
            .verify_tag(
                &crate::canonical(id, meta_json.as_bytes(), content_rest),
                tag,
            )
            .map_err(|_| {
                undercroft_obs::hmac_verify_failed("drawer");
                undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                StoreError::Integrity(id.to_string())
            })?;
        self.decode(id, meta_json, content_rest)
    }
}

use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;
    use undercroft_vault::{SecurityLevel, VaultManager};
    use tempfile::TempDir;

    fn store() -> (TempDir, PalaceStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("m", SecurityLevel::Sealed).unwrap();
        (dir, PalaceStore::open(vault).unwrap())
    }

    fn drawer(wing: &str, room: &str, content: &str, idx: u32) -> Drawer {
        Drawer::new(wing, room, content.into(), Some("s.md".into()), idx, "test")
    }

    #[test]
    fn drawer_lifecycle_list_update_delete() {
        let (_d, mut s) = store();
        let dr = drawer("w", "r", "original text", 0);
        s.upsert(&dr).unwrap();
        assert_eq!(s.list_drawers(Some("w"), None, 10, 0).unwrap().len(), 1);
        assert!(s.update_drawer(&dr.id, "updated text").unwrap());
        assert_eq!(s.get(&dr.id).unwrap().unwrap().content, "updated text");
        assert!(s.delete_drawer(&dr.id).unwrap());
        assert!(s.get(&dr.id).unwrap().is_none());
        // Deletion is chained — verify still passes.
        assert!(s.verify().unwrap().ok());
    }

    /// The sweep deletes rows. Before this, it deleted their dates with
    /// them: the same words recorded on two days became one record and the
    /// second day stopped having happened, unrecoverably. The text is one
    /// record; the chronology is all of them.
    #[test]
    fn dedup_collapses_the_text_and_keeps_every_date() {
        let (_d, mut s) = store();
        let first =
            drawer("w", "r", "the standup notes", 0).with_content_date(Some("2023-04-10".into()));
        let later =
            drawer("w", "r2", "the standup notes", 0).with_content_date(Some("2023-06-26".into()));
        s.upsert(&first).unwrap();
        s.upsert(&later).unwrap();

        let report = s.dedup(true).unwrap();
        assert_eq!(report.removed.len(), 1, "one row collapses");
        assert_eq!(report.dates_kept, 1, "and its date is carried, not dropped");

        let kept = s.get(&first.id).unwrap().unwrap();
        let days: Vec<_> = kept
            .all_occurrences()
            .into_iter()
            .filter_map(|o| o.content_date)
            .collect();
        assert_eq!(days, ["2023-04-10", "2023-06-26"]);
        assert!(
            s.get(&later.id).unwrap().is_none(),
            "the duplicate row is gone"
        );
        assert!(s.verify().unwrap().ok(), "chain and HMACs still verify");
    }

    /// A dry run must report the same history it would preserve, or the
    /// preview is not a preview of what happens.
    #[test]
    fn a_dry_run_reports_the_dates_it_would_keep_and_deletes_nothing() {
        let (_d, mut s) = store();
        let a = drawer("w", "r", "same words", 0).with_content_date(Some("2023-01-01".into()));
        let b = drawer("w", "r2", "same words", 0).with_content_date(Some("2023-02-02".into()));
        s.upsert(&a).unwrap();
        s.upsert(&b).unwrap();

        let report = s.dedup(false).unwrap();
        assert!(!report.applied);
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.dates_kept, 1);
        assert!(s.get(&b.id).unwrap().is_some(), "dry run deletes nothing");
        assert!(
            s.get(&a.id).unwrap().unwrap().meta.occurrences.is_empty(),
            "and writes nothing"
        );
    }

    /// Same words, same day, filed twice is one appearance — otherwise
    /// re-ingesting a corpus inflates its history every run.
    #[test]
    fn dedup_of_the_same_day_records_no_extra_appearance() {
        let (_d, mut s) = store();
        let a = drawer("w", "r", "same words", 0).with_content_date(Some("2023-01-01".into()));
        let b = drawer("w", "r2", "same words", 0).with_content_date(Some("2023-01-01".into()));
        s.upsert(&a).unwrap();
        s.upsert(&b).unwrap();
        let report = s.dedup(true).unwrap();
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.dates_kept, 0, "nothing new happened");
        assert_eq!(s.get(&a.id).unwrap().unwrap().all_occurrences().len(), 1);
    }

    /// The duplicate a byte comparison cannot see: the same Arabic name
    /// written with a composed hamza in one drawer and a combining one in
    /// the other. Identical on screen, identical in meaning, and previously
    /// two separate records that dedup would never pair.
    #[test]
    fn canonically_equal_text_is_one_duplicate() {
        let (_d, mut s) = store();
        let composed = "قابلت أحمد أمس";
        let decomposed = "قابلت \u{0627}\u{0654}حمد أمس";
        assert_ne!(composed, decomposed, "the bytes really do differ");

        s.upsert(&drawer("w", "r", composed, 0)).unwrap();
        assert!(
            s.check_duplicate(decomposed).unwrap().is_some(),
            "the other encoding must be recognised as the same content"
        );

        s.upsert(&drawer("w", "r2", decomposed, 0)).unwrap();
        let report = s.dedup(true).unwrap();
        assert_eq!(report.removed.len(), 1, "and dedup must pair them");
    }

    #[test]
    fn duplicate_detection_and_dedup() {
        let (_d, mut s) = store();
        s.upsert(&drawer("w", "r", "same content", 0)).unwrap();
        s.upsert(&drawer("w", "r", "same content", 1)).unwrap();
        s.upsert(&drawer("w", "r", "unique content", 2)).unwrap();
        assert!(s.check_duplicate("same content").unwrap().is_some());
        assert!(s.check_duplicate("never stored").unwrap().is_none());
        let report = s.dedup(true).unwrap();
        assert_eq!(report.duplicate_groups, 1);
        assert_eq!(report.removed.len(), 1);
        assert_eq!(s.count().unwrap(), 2);
        assert!(s.verify().unwrap().ok());
    }

    #[test]
    fn diaries_per_agent() {
        let (_d, mut s) = store();
        s.diary_write("scout", "explored the auth module today")
            .unwrap();
        s.diary_write("scout", "found the race condition").unwrap();
        s.diary_write("builder", "shipped the fix").unwrap();
        assert_eq!(s.list_agents().unwrap(), vec!["builder", "scout"]);
        let entries = s.diary_read("scout", 10).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(s.diary_read("nobody", 10).unwrap().is_empty());
    }

    #[test]
    fn delete_by_source_scopes_correctly() {
        let (_d, mut s) = store();
        s.upsert(&drawer("w", "r", "a", 0)).unwrap();
        s.upsert(&drawer("w", "r", "b", 1)).unwrap();
        let mut other = drawer("w", "r", "c", 2);
        other.meta.source_file = Some("other.md".into());
        other.id = undercroft_core::drawer_id("w", "r", "other.md", 2);
        s.upsert(&other).unwrap();
        assert_eq!(s.delete_by_source("s.md").unwrap(), 2);
        assert_eq!(s.count().unwrap(), 1);
    }

    #[test]
    fn tunnels_create_follow_traverse() {
        let (_d, mut s) = store();
        s.upsert(&drawer("wing-b", "r", "destination memory", 0))
            .unwrap();
        let id = s.create_tunnel("wing-a", "wing-b", "related work").unwrap();
        assert_eq!(s.list_tunnels(Some("wing-a")).unwrap().len(), 1);
        let dest = s.follow_tunnel(&id, 5).unwrap();
        assert_eq!(dest.len(), 1);
        s.create_tunnel("wing-b", "wing-c", "next hop").unwrap();
        let reach = s.traverse("wing-a", 3).unwrap();
        assert!(reach.iter().any(|(w, d)| w == "wing-c" && *d == 2));
        assert!(s.delete_tunnel(&id).unwrap());
        assert!(s.verify().unwrap().ok());
    }

    #[test]
    fn hallways_from_cooccurrence() {
        let (_d, mut s) = store();
        for i in 0..3 {
            s.upsert(&drawer(
                "team",
                "notes",
                &format!("Meeting {i}: yesterday Alice and Bob discussed the Herald launch"),
                i,
            ))
            .unwrap();
        }
        let halls = s.hallways("team", 10).unwrap();
        assert!(halls
            .iter()
            .any(|h| (h.entity_a == "alice" && h.entity_b == "bob") && h.strength >= 2));
    }

    #[test]
    fn stats_and_taxonomy() {
        let (_d, mut s) = store();
        s.upsert(&drawer("w1", "r1", "x", 0)).unwrap();
        s.upsert(&drawer("w1", "r2", "y", 1)).unwrap();
        s.upsert(&drawer("w2", "r1", "z", 2)).unwrap();
        s.kg_add("alice", "works_at", "acme", None, None, 1.0, None)
            .unwrap();
        let st = s.stats().unwrap();
        assert_eq!(st.records, 3);
        assert_eq!(st.rooms, 3);
        assert_eq!(st.kg.triples, 1);
        assert_eq!(st.level, "sealed");
        let tax = s.taxonomy().unwrap();
        assert_eq!(tax.len(), 2);
        assert_eq!(tax[0].1.len(), 2);
    }

    #[test]
    fn repair_backfills_and_passes() {
        let (_d, mut s) = store();
        s.upsert(&drawer("w", "r", "content", 0)).unwrap();
        s.conn.execute("UPDATE drawers SET fp = NULL", []).unwrap();
        let (report, fixed) = s.repair().unwrap();
        assert!(report.ok());
        assert_eq!(fixed, 1);
        assert!(s.check_duplicate("content").unwrap().is_some());
    }
}
