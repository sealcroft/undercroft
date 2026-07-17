//! MUVERA FDE candidate generation — token-aware retrieval through a
//! single-vector index (arXiv:2405.19504; design in
//! docs/RETRIEVAL_SCALING.md "Beyond MaxSim").
//!
//! Every drawer's stored ColBERT token matrix compresses into one
//! **fixed-dimensional encoding** ([`undercroft_core::fde`]) whose dot
//! product with a query FDE approximates MaxSim. Search then generates
//! candidates by scanning FDEs instead of relying on the fusion signals —
//! the candidate stage becomes token-aware with **no transformer and no
//! per-token work in the hot path** (one query forward total, shared with
//! the MaxSim rescore that still runs over the top pool).
//!
//! Storage mirrors the token store it derives from: FDE rows live in
//! `drawer_fde` keyed by drawer id + model, AEAD-sealed on sealed vaults
//! under the `/tok` domain with `fde/{id}` labels (an FDE is
//! plaintext-derived exactly like the matrix it summarizes; hmac-only
//! vaults store it plain like their other on-disk indexes). The encoder's
//! parameters + seed persist sealed in `fde_meta` — query-side and
//! doc-side encoders must agree bit-for-bit, and a palace restored from
//! backup keeps scoring identically.
//!
//! Coherence is event-driven like the PQ index: writes with the encoder
//! attached store their FDE from the matrix already in hand; the first
//! FDE search backfills any drawer that has a token matrix but no FDE —
//! **pure arithmetic from the stored matrix, no transformer forwards** —
//! and loads the `(seq, fde)` cache once per open. Drawers with no token
//! matrix at all have no FDE and are simply invisible to FDE candidate
//! generation (they keep appearing through full-scan search until token
//! backfill covers them — same advisory posture as the rescore stage).
//!
//! RAM: the cache holds `dim×4` bytes per drawer (default 2048-dim FDEs →
//! 8 KB/drawer, ~400 MB at N=50k). Honest note: this v1 is the *quality*
//! tier — PQ-compressing FDE rows (the codes-not-vectors trick the
//! retrieval PQ already uses) is the designed follow-up if the measured
//! quality warrants it.

use undercroft_core::fde::{fde_dot, FdeEncoder, FdeParams};
use undercroft_core::late::dequantize_tokens;
use rusqlite::{params, OptionalExtension};

use crate::{PalaceStore, StoreError};

fn f32s_to_bytes(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for x in v {
        out.extend(x.to_le_bytes());
    }
    out
}

fn bytes_to_f32s(b: &[u8]) -> Option<Vec<f32>> {
    if !b.len().is_multiple_of(4) {
        return None;
    }
    Some(
        b.chunks_exact(4)
            .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
            .collect(),
    )
}

/// Pack `(params, token_dim)`:
/// `[1][reps:u32][ksim:u32][dproj:u32][seed:u64][tokdim:u32]`.
fn params_pack(p: FdeParams, tokdim: usize) -> Vec<u8> {
    let mut out = vec![1u8];
    out.extend((p.reps as u32).to_le_bytes());
    out.extend((p.ksim as u32).to_le_bytes());
    out.extend((p.dproj as u32).to_le_bytes());
    out.extend(p.seed.to_le_bytes());
    out.extend((tokdim as u32).to_le_bytes());
    out
}

fn params_unpack(b: &[u8]) -> Option<(FdeParams, usize)> {
    if b.len() != 25 || b[0] != 1 {
        return None;
    }
    let u32at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
    Some((
        FdeParams {
            reps: u32at(1),
            ksim: u32at(5),
            dproj: u32at(9),
            seed: u64::from_le_bytes(b[13..21].try_into().unwrap()),
        },
        u32at(21),
    ))
}

/// First-build parameters: defaults, overridable via `UNDERCROFT_FDE_REPS` /
/// `_KSIM` / `_DPROJ` / `_SEED`. Only consulted the first time a palace
/// builds its FDE index — afterwards the persisted copy wins (stored FDEs
/// and future query FDEs must come from the same construction).
fn params_from_env() -> FdeParams {
    let get = |k: &str, d: usize| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(d)
    };
    let d = FdeParams::default();
    FdeParams {
        reps: get("UNDERCROFT_FDE_REPS", d.reps).max(1),
        ksim: get("UNDERCROFT_FDE_KSIM", d.ksim).clamp(1, 16),
        dproj: get("UNDERCROFT_FDE_DPROJ", d.dproj).max(1),
        seed: std::env::var("UNDERCROFT_FDE_SEED")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(d.seed),
    }
}

impl PalaceStore {
    /// Enable (or disable) MUVERA FDE candidate generation
    /// (`UNDERCROFT_RETRIEVAL=fde`). Requires the late-interaction encoder
    /// for the query side; without one, searches fall back to the full
    /// fusion scan.
    pub fn set_fde(&mut self, on: bool) {
        self.fde_enabled = on;
    }

    fn fde_schema(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS drawer_fde (
                 id    TEXT PRIMARY KEY,
                 model TEXT NOT NULL,
                 fde   BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS fde_meta (
                 key   TEXT PRIMARY KEY,
                 value BLOB NOT NULL
             );",
        )?;
        Ok(())
    }

    /// Load-or-create the encoder for token dim `tokdim` (once per session).
    /// Persisted params win over env; a token-dim change (different late
    /// model) drops every stored FDE — mixing constructions would score
    /// garbage silently.
    fn fde_encoder_ensure(&self, tokdim: usize) -> Result<bool, StoreError> {
        if let Some(enc) = self.fde_encoder.borrow().as_ref() {
            return Ok(enc.token_dim() == tokdim);
        }
        self.fde_schema()?;
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT value FROM fde_meta WHERE key = 'params'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let stored = stored
            .and_then(|b| self.vault.tokens_from_rest("fde/params", &b).ok())
            .and_then(|b| params_unpack(&b));
        let params = match stored {
            Some((p, d)) if d == tokdim => p,
            other => {
                if other.is_some() {
                    // Token dim changed (new late model): stored FDEs are
                    // unscorable — drop them and re-persist.
                    self.conn.execute("DELETE FROM drawer_fde", [])?;
                    self.fde_cache.borrow_mut().take();
                }
                let p = params_from_env();
                let blob = self
                    .vault
                    .tokens_at_rest("fde/params", &params_pack(p, tokdim));
                self.conn.execute(
                    "INSERT OR REPLACE INTO fde_meta (key, value) VALUES ('params', ?1)",
                    params![blob],
                )?;
                p
            }
        };
        *self.fde_encoder.borrow_mut() = Some(FdeEncoder::new(tokdim, params));
        Ok(true)
    }

    /// Store one drawer's FDE from the token matrix already in hand (called
    /// from the token write/backfill paths — no extra forwards, no re-read).
    /// Advisory like every derived artifact: failure leaves the drawer
    /// FDE-less, which candidate generation treats as invisible and the
    /// next build pass repairs.
    pub(crate) fn fde_encode_row(&self, id: &str, model: &str, matrix: &[f32], tokdim: usize) {
        if !self.fde_enabled || matrix.is_empty() {
            return;
        }
        if !matches!(self.fde_encoder_ensure(tokdim), Ok(true)) {
            return;
        }
        let enc_ref = self.fde_encoder.borrow();
        let Some(enc) = enc_ref.as_ref() else {
            return;
        };
        let fde = enc.encode_doc(matrix);
        let blob = self
            .vault
            .tokens_at_rest(&format!("fde/{id}"), &f32s_to_bytes(&fde));
        let ok = self
            .conn
            .execute(
                "INSERT OR REPLACE INTO drawer_fde (id, model, fde) VALUES (?1, ?2, ?3)",
                params![id, model, blob],
            )
            .is_ok();
        if ok {
            let seq: Option<i64> = self
                .conn
                .query_row("SELECT seq FROM drawers WHERE id = ?1", params![id], |r| {
                    r.get(0)
                })
                .optional()
                .ok()
                .flatten();
            if let (Some(seq), Some(cache)) = (seq, self.fde_cache.borrow_mut().as_mut()) {
                cache.retain(|(s, _)| *s != seq);
                cache.push((seq, fde));
            }
        }
    }

    /// Purge a deleted drawer's FDE row (called beside the token purge; the
    /// cache drops wholesale — deletes are rare, the next search reloads).
    pub(crate) fn fde_purge_row(&self, id: &str) {
        let _ = self
            .conn
            .execute("DELETE FROM drawer_fde WHERE id = ?1", params![id]);
        self.fde_cache.borrow_mut().take();
    }

    /// Backfill FDEs for every drawer that has a stored token matrix under
    /// `model` but no FDE row — pure arithmetic over the stored matrices
    /// (v1 rows dequantize; v2 rows decode through the token codebook), no
    /// transformer anywhere.
    fn fde_backfill(&self, model: &str) -> Result<(), StoreError> {
        let missing: Vec<(String, Vec<u8>)> = self
            .conn
            .prepare(
                "SELECT t.id, t.tok FROM drawer_tok t
                 LEFT JOIN drawer_fde f ON f.id = t.id AND f.model = t.model
                 WHERE t.model = ?1 AND f.id IS NULL",
            )?
            .query_map(params![model], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        if missing.is_empty() {
            return Ok(());
        }
        self.tok_pq_ensure(model);
        let tok_pq = self.tok_pq.borrow();
        for (id, blob) in missing {
            let Ok(packed) = self.vault.tokens_from_rest(&id, &blob) else {
                continue;
            };
            let matrix: Option<(Vec<f32>, usize)> = match packed.first() {
                Some(2) => tok_pq.as_ref().and_then(|pq| {
                    crate::latestage::unpack_v2(&packed, pq.code_len()).map(
                        |(dim, _rows, codes)| {
                            let mut m = Vec::with_capacity(codes.len() / pq.code_len() * dim);
                            for code in codes.chunks_exact(pq.code_len()) {
                                m.extend(pq.decode(code));
                            }
                            (m, dim)
                        },
                    )
                }),
                _ => dequantize_tokens(&packed),
            };
            let Some((matrix, tokdim)) = matrix else {
                continue;
            };
            if !matches!(self.fde_encoder_ensure(tokdim), Ok(true)) {
                continue;
            }
            let enc_ref = self.fde_encoder.borrow();
            let Some(enc) = enc_ref.as_ref() else {
                continue;
            };
            let fde = enc.encode_doc(&matrix);
            let blob = self
                .vault
                .tokens_at_rest(&format!("fde/{id}"), &f32s_to_bytes(&fde));
            drop(enc_ref);
            let _ = self.conn.execute(
                "INSERT OR REPLACE INTO drawer_fde (id, model, fde) VALUES (?1, ?2, ?3)",
                params![id, model, blob],
            );
        }
        Ok(())
    }

    /// Load the `(seq, fde)` cache (no-op if present): one pass per open,
    /// sealed rows decrypt through the vault. Rows that fail to open or
    /// parse are skipped — they only cost their candidate slot.
    fn fde_cache_ensure(&self, model: &str) -> Result<(), StoreError> {
        if self.fde_cache.borrow().is_some() {
            return Ok(());
        }
        let rows: Vec<(String, i64, Vec<u8>)> = self
            .conn
            .prepare(
                "SELECT f.id, d.seq, f.fde FROM drawer_fde f
                 JOIN drawers d ON d.id = f.id WHERE f.model = ?1",
            )?
            .query_map(params![model], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        let mut cache = Vec::with_capacity(rows.len());
        for (id, seq, blob) in rows {
            let Ok(plain) = self.vault.tokens_from_rest(&format!("fde/{id}"), &blob) else {
                continue;
            };
            let Some(fde) = bytes_to_f32s(&plain) else {
                continue;
            };
            cache.push((seq, fde));
        }
        *self.fde_cache.borrow_mut() = Some(cache);
        Ok(())
    }

    /// Top-`k` candidate seqs by FDE dot product, or `None` when FDE
    /// retrieval can't serve this query (no late encoder, no FDE rows, or
    /// an empty query encode) — the caller falls back to the fusion scan.
    pub(crate) fn fde_candidates(
        &self,
        query: &str,
        k: usize,
    ) -> Result<Option<Vec<i64>>, StoreError> {
        let Some(late) = &self.late else {
            return Ok(None);
        };
        let model = late.model_name().to_string();
        if !matches!(self.fde_encoder_ensure(late.dim()), Ok(true)) {
            return Ok(None);
        }
        if !self.fde_checked.get() {
            self.fde_checked.set(true);
            self.fde_backfill(&model)?;
            self.fde_cache.borrow_mut().take(); // rebuild below with new rows
        }
        self.fde_cache_ensure(&model)?;
        let qmatrix = late.encode_query(query);
        if qmatrix.is_empty() {
            return Ok(None);
        }
        // Stash the encoded query for the MaxSim rescore stage: the forward
        // is the expensive part of both stages, and one search pays it once.
        *self.qmatrix_cache.borrow_mut() = Some((query.to_string(), qmatrix.clone()));
        let enc_ref = self.fde_encoder.borrow();
        let Some(enc) = enc_ref.as_ref() else {
            return Ok(None);
        };
        let qfde = enc.encode_query(&qmatrix);
        let cache_ref = self.fde_cache.borrow();
        let cache = match cache_ref.as_ref() {
            Some(c) if !c.is_empty() => c,
            _ => return Ok(None),
        };
        let mut scored: Vec<(f32, i64)> = cache
            .iter()
            .map(|(seq, fde)| (fde_dot(&qfde, fde), *seq))
            .collect();
        if scored.len() > k {
            scored.select_nth_unstable_by(k - 1, |a, b| {
                b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal)
            });
            scored.truncate(k);
        }
        Ok(Some(scored.into_iter().map(|(_, seq)| seq).collect()))
    }
}
