//! On-disk PQ candidate prefilter — bounded-RAM retrieval for both vault
//! levels.
//!
//! The semantic analogue of the FTS5 BM25 prefilter. PQ codes are
//! plaintext-derived, so the two security levels store them differently
//! under the same invariant (*sealed vaults never persist plaintext-derived
//! data in clear*):
//!
//! * **hmac-only** — plain codes on disk (content is already plaintext;
//!   mirrors FTS5).
//! * **sealed** — every code row is AEAD-sealed (`list ‖ code`, bound to its
//!   seq under the `/pq` AAD domain; the plaintext `list` column stays `-1`
//!   because a clear list id would leak semantic clustering), and the
//!   codebook + IVF centroids in `pq_meta` are sealed likewise; an offline
//!   attacker sees only fixed-size sealed blobs, i.e. the drawer count it
//!   already knows.
//!
//! **Both levels ADC-scan the same load-once RAM cache** (~52 B/drawer —
//! 2.6 MB at N=50k, bounded): sealed vaults decrypt their rows into it once
//! per open, hmac-only vaults load the plain rows the same way. The cache
//! started as the sealed tier's workaround for opaque on-disk rows; a
//! controlled before/after at N=20–50k measured the hmac switch as
//! **performance parity within run-to-run noise** (an earlier loaded-host
//! run had suggested a win), so it is kept as the single scan path for the
//! simpler reason: one code path, no per-query SQLite iteration, identical
//! recall.
//!
//! Each drawer's embedding is product-quantized to a few dozen bytes
//! ([`crate::pq`]) and stored in a `drawer_pq` table; the trained codebook
//! (~hundreds of KB) is persisted once in `pq_meta` and cached in RAM.
//! Resident memory is the codebook + tables + code cache, **not** O(corpus)
//! f32 vectors, unlike the in-memory HNSW prototype.
//!
//! **IVF inverted lists** make the scan sub-linear above `ivf_min` drawers:
//! a coarse quantizer ([`crate::pq::CoarseQuantizer`], `nlist ≈ √N` centroids)
//! partitions the corpus, the code table is physically clustered by list
//! (`WITHOUT ROWID`, PK `(list, seq)` — each probed list is one sequential
//! range scan), and a search ADC-scans only the `nprobe` lists nearest the
//! query instead of every row. Non-residual: codes are identical with or
//! without IVF. Below `ivf_min` — or whenever a probe returns fewer than `k`
//! rows — the flat full-code scan runs instead, so IVF can narrow the
//! candidate set but never empty it.
//!
//! Coherence is **event-driven**: `write_drawer` encodes (and list-assigns)
//! each new/updated row incrementally with the persisted codebook — a
//! successful encode keeps the index coherent by construction — and the
//! O(corpus) verification (matched-count join, rebuild on drift) runs only on
//! the first search after open or after a write that couldn't encode, never
//! per query (measured at N=50k, the per-search join cost more than the
//! probed scan it guarded). The IVF partitions are additionally retrained
//! when the corpus **doubles** past their training size (centroids trained on
//! a small corpus mis-partition a large one), and dropped by any rebuild that
//! finds the corpus below `ivf_min`. `delete_drawer` purges its code row;
//! an orphan surviving a crash window merely wastes a candidate slot (the
//! hydration query filters against live drawers) until the next rebuild.

use undercroft_vault::SecurityLevel;
use rusqlite::{params, OptionalExtension};

use crate::pq::{CoarseQuantizer, ProductQuantizer};
use crate::{PalaceStore, StoreError};

/// k-means iterations and training-sample cap: PQ codebooks tolerate sampling
/// well, and training is a one-time cost we keep to seconds.
const PQ_TRAIN_ITERS: usize = 12;
const PQ_TRAIN_SAMPLE: usize = 4096;

/// IVF partitioning kicks in above this corpus size by default — below it the
/// flat ADC scan is already a few milliseconds and partitions would only add
/// recall risk. Tunable: `UNDERCROFT_IVF_MIN` (`off` disables IVF, keeping the
/// flat PQ scan) / [`PalaceStore::set_ivf`].
pub(crate) const IVF_MIN_DEFAULT: usize = 8192;
const IVF_TRAIN_ITERS: usize = 10;

impl PalaceStore {
    /// Enable (or disable) the on-disk PQ ANN prefilter — both security
    /// levels. hmac-only vaults store plain codes; **sealed vaults store
    /// every row, the codebook, and the IVF centroids AEAD-sealed** (`/pq`
    /// AAD domain, rows bound to their seq) — the
    /// no-plaintext-derived-data-in-clear invariant holds at both levels.
    /// Search ADC-scans a bounded RAM cache loaded (sealed: decrypted) once
    /// per open, at either level.
    pub fn set_pq(&mut self, on: bool) {
        self.pq_enabled = on;
    }

    fn pq_sealed(&self) -> bool {
        matches!(self.vault.level(), SecurityLevel::Sealed)
    }

    /// Pack a sealed row's plaintext: `list:i32le ++ code`. The IVF list id
    /// lives *inside* the sealed blob — a plaintext list column would leak
    /// which drawers are semantically similar.
    fn pq_row_pack(list: i64, code: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + code.len());
        out.extend((list as i32).to_le_bytes());
        out.extend_from_slice(code);
        out
    }

    fn pq_row_unpack(plain: &[u8]) -> Option<(i64, Vec<u8>)> {
        if plain.len() < 5 {
            return None;
        }
        let list = i32::from_le_bytes(plain[..4].try_into().ok()?) as i64;
        Some((list, plain[4..].to_vec()))
    }

    /// Tune the IVF layer of the PQ prefilter: `min` is the corpus size at
    /// which partitioning kicks in (`usize::MAX` ⇒ never — flat scan only),
    /// `nprobe` the number of inverted lists a query scans (`None` ⇒ the
    /// default `max(8, nlist/4)` — a quarter of the corpus; recall tracks
    /// the probed *fraction*). Defaults come from `UNDERCROFT_IVF_MIN` /
    /// `UNDERCROFT_IVF_NPROBE` at open.
    pub fn set_ivf(&mut self, min: usize, nprobe: Option<usize>) {
        self.ivf_min = min;
        self.ivf_nprobe = nprobe;
    }

    fn pq_schema(&self) -> Result<(), StoreError> {
        // The code table is **physically clustered by inverted list**
        // (`WITHOUT ROWID`, PK `(list, seq)`): a probe reads each list as a
        // sequential B-tree range scan instead of one random row fetch per
        // secondary-index hit — measured, the random-access layout made a
        // 23%-fraction probe *slower* than the flat full scan. Rows without a
        // partition (IVF off or not yet trained) sit in list -1; the flat
        // scan reads the whole table regardless.
        //
        // Pre-IVF (v0.14.0) tables used `seq INTEGER PRIMARY KEY` — drop them
        // and let the matched-count self-heal rebuild in the new layout.
        let legacy: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'drawer_pq' \
             AND sql NOT LIKE '%WITHOUT ROWID%'",
            [],
            |r| r.get(0),
        )?;
        if legacy > 0 {
            self.conn.execute("DROP TABLE drawer_pq", [])?;
        }
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS drawer_pq (
                 list INTEGER NOT NULL,
                 seq  INTEGER NOT NULL,
                 code BLOB NOT NULL,
                 PRIMARY KEY (list, seq)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS drawer_pq_seq ON drawer_pq(seq);
             CREATE TABLE IF NOT EXISTS pq_meta (
                 key   TEXT PRIMARY KEY,
                 value BLOB NOT NULL
             );",
        )?;
        Ok(())
    }

    /// Vector top-`k` candidate `seq`s by streaming ADC over the on-disk
    /// codes — only the probed inverted lists when IVF is active, every code
    /// row otherwise. `None` ⇒ no usable index (empty corpus, or a dimension
    /// PQ can't split); the caller falls back to the full scan.
    pub(crate) fn pq_candidates(
        &self,
        qvec: &[f32],
        k: usize,
    ) -> Result<Option<Vec<i64>>, StoreError> {
        // Coherence is **event-driven**, not per-query: the O(corpus)
        // verification (schema + matched-count join) runs on the first
        // search after open and after any write that could have broken the
        // index (an encode that found no cached codebook, or one that
        // errored — a *successful* incremental encode keeps the index
        // coherent by construction and stays on the fast path). Measured at
        // N=50k, the per-search join was costing more than the probed ADC
        // scan it was guarding.
        let mut just_verified = false;
        if !self.pq_verified.get() || self.pq.borrow().is_none() {
            just_verified = true;
            self.pq_schema()?;
            let drawers: i64 = self
                .conn
                .query_row("SELECT COUNT(*) FROM drawers", [], |r| r.get(0))?;
            if drawers == 0 {
                return Ok(None);
            }
            // Self-heal: every live drawer must have a code row (orphans
            // from deletes are excluded by the join and are harmless), and —
            // when the corpus is IVF-sized — the partitions must exist and
            // not be outgrown (2× their training size).
            let matched: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM drawer_pq p JOIN drawers d ON d.seq = p.seq",
                [],
                |r| r.get(0),
            )?;
            let want_ivf = (drawers as usize) >= self.ivf_min;
            let ivf_stale = want_ivf && {
                if self.ivf.borrow().is_none() {
                    self.ivf_load()?;
                }
                match self.ivf.borrow().as_ref() {
                    None => true,
                    Some(cq) => drawers as u64 > cq.trained_n().saturating_mul(2),
                }
            };
            if (self.pq.borrow().is_none() || matched != drawers || ivf_stale)
                && !self.pq_build()?
            {
                return Ok(None);
            }
            self.pq_live.set(drawers);
            self.pq_verified.set(true);
        }
        let live = self.pq_live.get();
        if live == 0 {
            return Ok(None);
        }
        // Growth re-check on the fast path (cheap, cached counters): a
        // corpus that crossed the IVF threshold, or doubled past the
        // partitions' training size, re-verifies once so they (re)train
        // rather than silently degrading recall. Skipped when this call
        // just verified — whatever state the verify pass left (including
        // "no partitions trainable") is trusted, which bounds the recursion
        // at one level.
        let want_ivf = (live as usize) >= self.ivf_min;
        if want_ivf && !just_verified {
            let outgrown = match self.ivf.borrow().as_ref() {
                None => true,
                Some(cq) => live as u64 > cq.trained_n().saturating_mul(2),
            };
            if outgrown {
                self.pq_verified.set(false);
                return self.pq_candidates(qvec, k);
            }
        }
        let pq_ref = self.pq.borrow();
        let Some(pq) = pq_ref.as_ref() else {
            return Ok(None);
        };
        let tables = pq.distance_tables(qvec);

        // Probed IVF lists for this query, when partitions are live.
        let probe: Option<Vec<i64>> = if want_ivf {
            self.ivf.borrow().as_ref().and_then(|cq| {
                // Default nprobe is a **fraction** (a quarter of the lists),
                // not a fixed count: recall tracks the probed fraction of the
                // corpus, so a count that ignores nlist collapses recall as N
                // grows. Measured on synth: 23% of lists = flat-scan recall.
                let nprobe = self.ivf_nprobe.unwrap_or_else(|| (cq.nlist() / 4).max(8));
                let lists = cq.probe(qvec, nprobe);
                if lists.is_empty() {
                    None
                } else {
                    // List -1 (rows written before the partitions existed)
                    // rides along in every probe.
                    let mut l: Vec<i64> = lists.into_iter().map(i64::from).collect();
                    l.push(-1);
                    Some(l)
                }
            })
        } else {
            None
        };

        // Both levels ADC-scan the load-once RAM cache (sealed rows decrypt
        // into it; plain rows load as stored — measured before/after at
        // N=20–50k: parity with the old per-query SQLite streaming, kept
        // for the single code path). No `JOIN drawers` here: delete-orphans
        // are purged by
        // `delete_drawer`, and any crash-window survivor merely wastes a
        // candidate slot downstream — the hydration query filters
        // `seq IN (...)` against live drawers — until the next rebuild.
        // Probes filter the cache in RAM; if the probed lists hold fewer
        // than `k` rows (skewed partitions, tiny corpus), widen to the full
        // scan rather than starve the fusion stage.
        self.pq_cache_ensure()?;
        let cache_ref = self.pq_cache.borrow();
        let Some(cache) = cache_ref.as_ref() else {
            return Ok(None);
        };
        let mut scored: Option<Vec<(f32, i64)>> = None;
        if let Some(lists) = &probe {
            let probed: Vec<(f32, i64)> = cache
                .iter()
                .filter(|(_, list, _)| lists.contains(list))
                .map(|(seq, _, code)| (pq.adc(&tables, code), *seq))
                .collect();
            if probed.len() >= k {
                scored = Some(probed);
            }
        }
        if scored.is_none() {
            scored = Some(
                cache
                    .iter()
                    .map(|(seq, _, code)| (pq.adc(&tables, code), *seq))
                    .collect(),
            );
        }
        let mut scored = scored.unwrap_or_default();
        if scored.len() > k {
            scored.select_nth_unstable_by(k - 1, |a, b| {
                a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
            });
            scored.truncate(k);
        }
        Ok(Some(scored.into_iter().map(|(_, seq)| seq).collect()))
    }

    /// Build the RAM code cache (no-op if already cached): one pass over
    /// `drawer_pq` per open. Sealed vaults open each row's AEAD blob under
    /// its seq-bound AAD; hmac-only rows load as stored. Sealed rows that
    /// fail to open are skipped — the matched-count verify catches real
    /// drift; a skipped row only costs its candidate slot.
    fn pq_cache_ensure(&self) -> Result<(), StoreError> {
        if self.pq_cache.borrow().is_some() {
            return Ok(());
        }
        let cache = if self.pq_sealed() {
            let mut stmt = self.conn.prepare("SELECT seq, code FROM drawer_pq")?;
            let rows: Vec<(i64, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            let mut cache = Vec::with_capacity(rows.len());
            for (seq, blob) in rows {
                let Ok(plain) = self.vault.index_from_rest(&format!("pqrow/{seq}"), &blob) else {
                    continue;
                };
                let Some((list, code)) = Self::pq_row_unpack(&plain) else {
                    continue;
                };
                cache.push((seq, list, code));
            }
            cache
        } else {
            let mut stmt = self.conn.prepare("SELECT seq, list, code FROM drawer_pq")?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        *self.pq_cache.borrow_mut() = Some(cache);
        Ok(())
    }

    /// Read a pq_meta value through the vault's index sealing (identity on
    /// hmac-only vaults).
    fn pq_meta_get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT value FROM pq_meta WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(stored.and_then(|b| self.vault.index_from_rest(&format!("pq/{key}"), &b).ok()))
    }

    fn pq_meta_put(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        let blob = self.vault.index_at_rest(&format!("pq/{key}"), value);
        self.conn.execute(
            "INSERT OR REPLACE INTO pq_meta (key, value) VALUES (?1, ?2)",
            params![key, blob],
        )?;
        Ok(())
    }

    /// Fill the RAM cache from the persisted IVF centroids, if any.
    fn ivf_load(&self) -> Result<(), StoreError> {
        let stored = self.pq_meta_get("ivf")?;
        *self.ivf.borrow_mut() = stored.and_then(|b| CoarseQuantizer::from_bytes(&b));
        Ok(())
    }

    /// Load-or-train the codebook and (re)encode every drawer; train (or
    /// retrain) the IVF partitions when the corpus warrants them, drop them
    /// when it doesn't. Returns `false` when the corpus can't be quantized
    /// (empty, or dimension not divisible into subspaces) — the caller falls
    /// back to the full scan.
    fn pq_build(&self) -> Result<bool, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, id, embedding FROM drawers")?;
        let rows: Vec<(i64, String, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        if rows.is_empty() {
            return Ok(false);
        }
        let mut items = Vec::with_capacity(rows.len());
        for (seq, id, rest) in rows {
            let emb =
                self.vault
                    .embedding_from_rest(&id, &rest)
                    .map_err(|e| StoreError::CorruptRow {
                        id: id.clone(),
                        reason: e.to_string(),
                    })?;
            items.push((seq, emb));
        }

        let stored = self.pq_meta_get("codebook")?;
        let pq = match stored.and_then(|b| ProductQuantizer::from_bytes(&b)) {
            Some(pq) => pq,
            None => {
                // Subspaces of 8 dims (fall back to 4) — every common
                // embedding dim (384/512/768/1024) divides by 8.
                let dim = items[0].1.len();
                let Some(m) = [8usize, 4]
                    .iter()
                    .find(|&&dsub| dim % dsub == 0)
                    .map(|&dsub| dim / dsub)
                else {
                    return Ok(false);
                };
                // Train on an even sample; codebooks tolerate sampling well.
                let stride = items.len().div_ceil(PQ_TRAIN_SAMPLE).max(1);
                let sample: Vec<Vec<f32>> = items
                    .iter()
                    .step_by(stride)
                    .map(|(_, v)| v.clone())
                    .collect();
                let Some(pq) = ProductQuantizer::train(&sample, m, PQ_TRAIN_ITERS) else {
                    return Ok(false);
                };
                self.pq_meta_put("codebook", &pq.to_bytes())?;
                pq
            }
        };

        // IVF partitions: (re)train whenever the corpus is IVF-sized and the
        // cached centroids are absent or outgrown; drop them below the
        // threshold so they can't silently go stale.
        let n = items.len();
        if n >= self.ivf_min {
            let fresh = matches!(
                self.ivf.borrow().as_ref(),
                Some(cq) if n as u64 <= cq.trained_n().saturating_mul(2)
            );
            if !fresh {
                let nlist = (n as f64).sqrt() as usize;
                let nlist = nlist.clamp(16, 1024);
                let stride = n.div_ceil(PQ_TRAIN_SAMPLE).max(1);
                let sample: Vec<Vec<f32>> = items
                    .iter()
                    .step_by(stride)
                    .map(|(_, v)| v.clone())
                    .collect();
                match CoarseQuantizer::train(&sample, nlist, IVF_TRAIN_ITERS, n as u64) {
                    Some(cq) => {
                        self.pq_meta_put("ivf", &cq.to_bytes())?;
                        *self.ivf.borrow_mut() = Some(cq);
                    }
                    None => {
                        self.conn
                            .execute("DELETE FROM pq_meta WHERE key = 'ivf'", [])?;
                        *self.ivf.borrow_mut() = None;
                    }
                }
            }
        } else {
            self.conn
                .execute("DELETE FROM pq_meta WHERE key = 'ivf'", [])?;
            *self.ivf.borrow_mut() = None;
        }

        self.conn.execute("DELETE FROM drawer_pq", [])?;
        let mut ins = self
            .conn
            .prepare("INSERT OR REPLACE INTO drawer_pq (list, seq, code) VALUES (?1, ?2, ?3)")?;
        let sealed = self.pq_sealed();
        let ivf_ref = self.ivf.borrow();
        let mut cache = Vec::with_capacity(items.len());
        for (seq, vec) in &items {
            let list: i64 = ivf_ref.as_ref().map_or(-1, |cq| cq.assign(vec) as i64);
            let code = pq.encode(vec);
            if sealed {
                // Sealed row: list id + code AEAD-sealed together, bound to
                // this seq; the plaintext list column stays -1 (a clear list
                // id would leak semantic clustering).
                let blob = self
                    .vault
                    .index_at_rest(&format!("pqrow/{seq}"), &Self::pq_row_pack(list, &code));
                ins.execute(params![-1i64, seq, blob])?;
            } else {
                ins.execute(params![list, seq, code])?;
            }
            // Either level's RAM cache is populated from the plaintext
            // already in hand — no re-read, no re-decrypt.
            cache.push((*seq, list, code));
        }
        drop(ivf_ref);
        *self.pq_cache.borrow_mut() = Some(cache);
        *self.pq.borrow_mut() = Some(pq);
        Ok(true)
    }

    /// Incrementally encode one written drawer with the cached codebook
    /// (called from `write_drawer` after commit), list-assigning it when IVF
    /// partitions are live. A successful encode keeps the index coherent by
    /// construction; a failure (or a write before any codebook exists) arms
    /// the next search's full verification instead — nothing is ever lost,
    /// only re-checked.
    pub(crate) fn pq_encode_row(&self, id: &str, embedding: &[f32], created: bool) {
        if !self.pq_enabled {
            return;
        }
        let code = match self.pq.borrow().as_ref() {
            Some(pq) => pq.encode(embedding),
            // No codebook yet ⇒ no index to keep coherent; the verify
            // condition (`pq.is_none()`) already forces the first search to
            // build from scratch.
            None => return,
        };
        let list: i64 = self
            .ivf
            .borrow()
            .as_ref()
            .map_or(-1, |cq| cq.assign(embedding) as i64);
        // Both the sealed AAD binding and the RAM-cache update need the
        // row's seq, so resolve it first. Updates keep their `seq` (drawers
        // upsert is ON CONFLICT DO UPDATE), so a re-embedded drawer may move
        // lists — drop the old row or it would live on as a stale
        // (list, seq) duplicate.
        let outcome = self
            .conn
            .query_row("SELECT seq FROM drawers WHERE id = ?1", params![id], |r| {
                r.get::<_, i64>(0)
            })
            .and_then(|seq| {
                self.conn
                    .execute("DELETE FROM drawer_pq WHERE seq = ?1", params![seq])?;
                if self.pq_sealed() {
                    let blob = self
                        .vault
                        .index_at_rest(&format!("pqrow/{seq}"), &Self::pq_row_pack(list, &code));
                    self.conn.execute(
                        "INSERT OR REPLACE INTO drawer_pq (list, seq, code) VALUES (-1, ?1, ?2)",
                        params![seq, blob],
                    )?;
                } else {
                    self.conn.execute(
                        "INSERT OR REPLACE INTO drawer_pq (list, seq, code) VALUES (?1, ?2, ?3)",
                        params![list, seq, code],
                    )?;
                }
                Ok(seq)
            });
        match outcome {
            Ok(seq) => {
                // Keep the RAM cache coherent with the plaintext in hand.
                if let Some(cache) = self.pq_cache.borrow_mut().as_mut() {
                    cache.retain(|(s, _, _)| *s != seq);
                    cache.push((seq, list, code));
                }
                if created {
                    self.pq_live.set(self.pq_live.get() + 1);
                }
            }
            // The index may now be missing this row — re-verify on the next
            // search rather than serve from a silently stale index.
            Err(_) => self.pq_verified.set(false),
        }
    }
}
