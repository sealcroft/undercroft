//! MUVERA FDE candidate generation — token-aware retrieval through a
//! single-vector index (arXiv:2405.19504; design + measurements in
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
//! **Two storage tiers, upgraded event-driven** (the token store's PQ
//! pattern, applied to FDEs):
//!
//! * **v1 (raw)** — `[1][f32le…]`: exact FDEs, 4 B/dim (8 KB at the
//!   default 2048). What small palaces keep. (Headerless v0.23.0 rows are
//!   recognized by length and read as v1.)
//! * **v2 (PQ codes)** — `[2][list:i32le][code…]`: once at least
//!   `UNDERCROFT_FDE_PQ_MIN` rows exist, a product-quantizer codebook
//!   trains from the palace's own FDEs (persisted sealed in `fde_meta`),
//!   every row repacks to `dim/8` bytes (**32×**), and the scan switches
//!   to per-query dot-product LUTs.
//!
//! **The inverted tier** activates past `UNDERCROFT_FDE_IVF_MIN` coded
//! rows: coarse centroids (`nlist ≈ √N`, clamp 16..=4096) train over the
//! palace's own decoded FDEs, each row's `list` field (reserved as -1
//! since v0.24.0 — no migration) rewrites in place, and the RAM cache
//! groups into per-list **slabs** so a probe scans only its lists
//! contiguously. The naive attempt (flat cache + per-row membership
//! filter) measured net-negative at N≤200k — containment dropped to
//! 0.84–0.99 and the O(N·nprobe) filter cost more than the flat ADC scan
//! — which is why the threshold defaults high and the flat scan remains
//! the small-N path. The list id rides *inside* the sealed blob because a
//! plaintext list column would leak which drawers are semantically
//! similar.
//!
//! Storage mirrors the token store it derives from: rows live in
//! `drawer_fde` keyed by drawer id + model, AEAD-sealed on sealed vaults
//! under the `/tok` domain with `fde/{id}` labels. The encoder's
//! parameters + seed persist sealed in `fde_meta` — query-side and
//! doc-side encoders must agree bit-for-bit, and a palace restored from
//! backup keeps scoring identically.
//!
//! Coherence is event-driven like the PQ index: writes with the encoder
//! attached store their FDE from the matrix already in hand; the first
//! FDE search backfills any drawer that has a token matrix but no FDE —
//! **pure arithmetic from the stored matrix, no transformer forwards** —
//! and loads the cache once per open. A row that fails to open during the
//! v2 repack is deleted, which turns it back into "missing" for the next
//! backfill; nothing is ever silently mixed across formats or models.

use rusqlite::{params, OptionalExtension};
use undercroft_core::fde::{fde_dot, FdeEncoder, FdeParams};
use undercroft_core::late::dequantize_tokens;

use crate::pq::{CoarseQuantizer, ProductQuantizer};
use crate::{PalaceStore, StoreError, CODEBOOK_FDE, CODEBOOK_FDE_IVF};

/// Stored-FDE count at which the FDE codebook trains (v2 packing).
pub(crate) const FDE_PQ_MIN_DEFAULT: usize = 256;
/// Sampling cap and k-means iterations for FDE-codebook training.
const FDE_PQ_SAMPLE: usize = 4096;
const FDE_PQ_ITERS: usize = 10;
/// Suggested coded-row count for opting the inverted tier in
/// (`UNDERCROFT_FDE_IVF_MIN` set without a parseable number falls back
/// here). The tier is **off by default**: the containment gate measured
/// probed containment below flat's at every fraction (0.960 quarter /
/// 0.993 half at N=500k vs flat 1.000), so activating it is an explicit
/// operator trade of a small exact-top-10 tail for scan time.
pub(crate) const FDE_IVF_MIN_DEFAULT: usize = 500_000;
const FDE_IVF_ITERS: usize = 10;

/// The FDE RAM cache: raw vectors below the codebook threshold, PQ codes
/// above it. One variant at a time — the train pass repacks every row in
/// one sweep, so formats never mix.
pub(crate) enum FdeCache {
    /// `(seq, fde)` — exact vectors, dot-product scan.
    Raw(Vec<(i64, Vec<f32>)>),
    /// Slab-grouped codes: `list → (seqs, contiguous codes)`. A probe
    /// scans only its lists' slabs — no per-row membership test, which is
    /// the O(N·nprobe) cost that sank the naive inverted attempt. All rows
    /// sit in list -1 until the inverted tier trains; -1 also rides along
    /// in every probe afterwards (rows written before partitions existed).
    Coded {
        code_len: usize,
        slabs: std::collections::HashMap<i64, (Vec<i64>, Vec<u8>)>,
    },
}

impl FdeCache {
    fn coded_rows(&self) -> usize {
        match self {
            FdeCache::Raw(_) => 0,
            FdeCache::Coded { slabs, .. } => slabs.values().map(|(s, _)| s.len()).sum(),
        }
    }
}

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

/// One parsed FDE row payload.
enum FdeRow {
    Raw(Vec<f32>),
    Coded(i64, Vec<u8>),
}

fn fde_row_pack_raw(fde: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + fde.len() * 4);
    out.push(1u8);
    out.extend(f32s_to_bytes(fde));
    out
}

fn fde_row_pack_coded(list: i64, code: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + code.len());
    out.push(2u8);
    out.extend((list as i32).to_le_bytes());
    out.extend_from_slice(code);
    out
}

/// Parse a row payload. `fde_dim` recognizes legacy (v0.23.0) headerless
/// f32 rows by exact length; `code_len` validates v2 rows.
fn fde_row_unpack(plain: &[u8], fde_dim: usize, code_len: usize) -> Option<FdeRow> {
    match plain.first() {
        Some(1) if (plain.len() - 1).is_multiple_of(4) => {
            bytes_to_f32s(&plain[1..]).map(FdeRow::Raw)
        }
        Some(2) if code_len > 0 && plain.len() == 5 + code_len => {
            let list = i32::from_le_bytes(plain[1..5].try_into().ok()?) as i64;
            Some(FdeRow::Coded(list, plain[5..].to_vec()))
        }
        _ if plain.len() == fde_dim * 4 => bytes_to_f32s(plain).map(FdeRow::Raw),
        _ => None,
    }
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

    pub(crate) fn fde_schema(&self) -> Result<(), StoreError> {
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

    fn fde_meta_get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT value FROM fde_meta WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(stored.and_then(|b| self.vault.tokens_from_rest(&format!("fde/{key}"), &b).ok()))
    }

    fn fde_meta_put(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        let blob = self.vault.tokens_at_rest(&format!("fde/{key}"), value);
        self.conn.execute(
            "INSERT OR REPLACE INTO fde_meta (key, value) VALUES (?1, ?2)",
            params![key, blob],
        )?;
        Ok(())
    }

    /// Load-or-create the encoder for token dim `tokdim` (once per session).
    /// Persisted params win over env; a token-dim change (different late
    /// model) drops every stored FDE and the codebook — mixing
    /// constructions would score garbage silently.
    fn fde_encoder_ensure(&self, tokdim: usize) -> Result<bool, StoreError> {
        if let Some(enc) = self.fde_encoder.borrow().as_ref() {
            return Ok(enc.token_dim() == tokdim);
        }
        // R1: a read-only store loads the encoder's persisted params and
        // never mints them. Creating the schema, dropping mismatched rows
        // and writing a fresh `params` blob are all writes — and the last is
        // the worst of them, because it would pin a REPLICA's env-derived
        // parameters onto a vault its writer never chose them for.
        if !self.may_build_indexes() {
            if !self.table_exists("fde_meta")? {
                self.ro_prefilter_fallback("FDE");
                return Ok(false);
            }
            let Some((p, d)) = self.fde_meta_get("params")?.and_then(|b| params_unpack(&b)) else {
                self.ro_prefilter_fallback("FDE");
                return Ok(false);
            };
            if d != tokdim {
                self.ro_prefilter_fallback("FDE");
                return Ok(false);
            }
            *self.fde_encoder.borrow_mut() = Some(FdeEncoder::new(tokdim, p));
            return Ok(true);
        }
        self.fde_schema()?;
        let stored = self.fde_meta_get("params")?.and_then(|b| params_unpack(&b));
        let params = match stored {
            Some((p, d)) if d == tokdim => p,
            other => {
                if other.is_some() {
                    self.conn.execute("DELETE FROM drawer_fde", [])?;
                    self.conn
                        .execute("DELETE FROM fde_meta WHERE key != 'params'", [])?;
                    self.fde_cache.borrow_mut().take();
                    *self.fde_pq.borrow_mut() = None;
                }
                let p = params_from_env();
                self.fde_meta_put("params", &params_pack(p, tokdim))?;
                p
            }
        };
        *self.fde_encoder.borrow_mut() = Some(FdeEncoder::new(tokdim, params));
        Ok(true)
    }

    /// Pack an FDE in the best live format (v2 codes when the codebook is
    /// cached, v1 raw otherwise) and upsert the row; keeps the RAM cache
    /// coherent from the plaintext in hand. Advisory like every derived
    /// artifact: failure leaves the drawer FDE-less, repaired by the next
    /// backfill pass.
    fn fde_store_row(&self, id: &str, model: &str, fde: &[f32]) {
        let (payload, cache_row) = match self.fde_pq.borrow().as_ref() {
            Some(pq) => {
                // List-assign against the live centroids; -1 until the
                // inverted tier has trained (it rides in every probe).
                let list = self
                    .fde_ivf
                    .borrow()
                    .as_ref()
                    .map_or(-1, |cq| cq.assign(fde) as i64);
                let code = pq.encode(fde);
                (fde_row_pack_coded(list, &code), Some((list, code)))
            }
            None => (fde_row_pack_raw(fde), None),
        };
        let blob = self.vault.tokens_at_rest(&format!("fde/{id}"), &payload);
        let ok = self
            .conn
            .execute(
                "INSERT OR REPLACE INTO drawer_fde (id, model, fde) VALUES (?1, ?2, ?3)",
                params![id, model, blob],
            )
            .is_ok();
        if !ok {
            return;
        }
        let seq: Option<i64> = self
            .conn
            .query_row("SELECT seq FROM drawers WHERE id = ?1", params![id], |r| {
                r.get(0)
            })
            .optional()
            .ok()
            .flatten();
        let Some(seq) = seq else { return };
        let mut cache = self.fde_cache.borrow_mut();
        match (cache.as_mut(), cache_row) {
            (Some(FdeCache::Raw(rows)), None) => {
                rows.retain(|(s, _)| *s != seq);
                rows.push((seq, fde.to_vec()));
            }
            (Some(FdeCache::Coded { code_len, slabs }), Some((list, code)))
                if *code_len == code.len() =>
            {
                // Drop any previous position first — a re-embedded drawer
                // may have moved lists.
                let cl = *code_len;
                for (seqs, codes) in slabs.values_mut() {
                    if let Some(i) = seqs.iter().position(|s| *s == seq) {
                        seqs.remove(i);
                        codes.drain(i * cl..(i + 1) * cl);
                        break;
                    }
                }
                let (seqs, codes) = slabs.entry(list).or_default();
                seqs.push(seq);
                codes.extend_from_slice(&code);
            }
            (Some(_), _) => {
                // Format transition mid-write (shouldn't happen — the train
                // pass rebuilds the cache) — drop and reload lazily.
                *cache = None;
            }
            (None, _) => {}
        }
    }

    /// Store one drawer's FDE from the token matrix already in hand (called
    /// from the token write/backfill paths — no extra forwards, no re-read).
    pub(crate) fn fde_encode_row(&self, id: &str, model: &str, matrix: &[f32], tokdim: usize) {
        if !self.fde_enabled || matrix.is_empty() {
            return;
        }
        if !matches!(self.fde_encoder_ensure(tokdim), Ok(true)) {
            return;
        }
        let fde = {
            let enc_ref = self.fde_encoder.borrow();
            let Some(enc) = enc_ref.as_ref() else {
                return;
            };
            enc.encode_doc(matrix)
        };
        self.fde_store_row(id, model, &fde);
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
        // One transaction for the whole backfill (ROADMAP A20): every row was
        // its own autocommit `INSERT` under `synchronous=FULL`, i.e. one fsync
        // per drawer, and an interruption left a half-backfilled table whose
        // remainder only the next pass would notice.
        let filled = self.one_rewrite(|| {
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
                let fde = {
                    let enc_ref = self.fde_encoder.borrow();
                    let Some(enc) = enc_ref.as_ref() else {
                        continue;
                    };
                    enc.encode_doc(&matrix)
                };
                self.fde_store_row(&id, model, &fde);
            }
            Ok(())
        });
        if let Err(e) = filled {
            // Advisory, as everywhere on this tier: the rows that would have
            // been written are simply still missing, and the next pass finds
            // them again. A search must not fail because a backfill did.
            undercroft_obs::diag_warn!("FDE backfill rolled back ({e}); rows stay missing");
        }
        Ok(())
    }

    /// Load-or-train the FDE codebook once per session. Training fires when
    /// at least `fde_pq_min` rows exist: every raw row repacks to v2 codes
    /// (**32× smaller**) in one pass — pure re-encoding. A stored codebook
    /// trained for another model is dropped with the rows (see
    /// `fde_encoder_ensure`).
    fn fde_pq_ensure(&self, model: &str, fde_dim: usize) -> Result<(), StoreError> {
        if self.fde_pq.borrow().is_some() || self.fde_pq_checked.get() {
            return Ok(());
        }
        self.fde_pq_checked.set(true);
        // Stored codebook?
        if let Some(pq) = self
            .fde_meta_get("codebook")?
            .and_then(|b| ProductQuantizer::from_bytes(&b))
        {
            *self.fde_pq.borrow_mut() = Some(pq);
            return Ok(());
        }
        // No stored codebook, and training one (plus repacking every row to
        // v2) is a write — a read-only store keeps the raw v1 rows it has
        // (R1). Not a fallback to the exact scan: the flat raw-FDE path is
        // the tier's own default below `fde_pq_min` and still serves.
        if !self.may_build_indexes() {
            return Ok(());
        }
        let rows: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM drawer_fde WHERE model = ?1",
            params![model],
            |r| r.get(0),
        )?;
        if (rows as usize) < self.fde_pq_min {
            return Ok(());
        }
        // Collect the raw FDEs (v1/legacy rows) for training + repack.
        let all: Vec<(String, Vec<u8>)> = self
            .conn
            .prepare("SELECT id, fde FROM drawer_fde WHERE model = ?1")?
            .query_map(params![model], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut raw: Vec<(String, Vec<f32>)> = Vec::with_capacity(all.len());
        for (id, blob) in all {
            let parsed = self
                .vault
                .tokens_from_rest(&format!("fde/{id}"), &blob)
                .ok()
                .and_then(|p| fde_row_unpack(&p, fde_dim, 0));
            match parsed {
                Some(FdeRow::Raw(f)) if f.len() == fde_dim => raw.push((id, f)),
                _ => {
                    // Unreadable or mis-shaped: delete → "missing" → the
                    // next backfill recreates it (as v2, post-train).
                    let _ = self
                        .conn
                        .execute("DELETE FROM drawer_fde WHERE id = ?1", params![id]);
                }
            }
        }
        if raw.len() < self.fde_pq_min {
            return Ok(());
        }
        // Keyed draw, not an even stride over insertion order — see
        // `pqidx::stratified_keyed` — and capped per wing + per agent
        // claim like the PQ codebook's: the density channel is the same
        // on this tier.
        let source_of = self.source_by_drawer_id()?;
        let sample: Vec<Vec<f32>> = self
            .keyed_sample_capped(
                CODEBOOK_FDE,
                &raw,
                FDE_PQ_SAMPLE,
                |(id, _)| id.as_bytes().to_vec(),
                |(id, _)| source_of.get(id.as_str()).cloned().unwrap_or_default(),
            )
            .into_iter()
            .map(|i| raw[i].1.clone())
            .collect();
        let Some(m) = [8usize, 4]
            .iter()
            .find(|&&d| fde_dim.is_multiple_of(d))
            .map(|&d| fde_dim / d)
        else {
            return Ok(());
        };
        let Some(pq) = ProductQuantizer::train(&sample, m, FDE_PQ_ITERS) else {
            return Ok(());
        };
        if raw.len() > FDE_PQ_SAMPLE {
            let probe: Vec<Vec<f32>> = self
                .keyed_sample(
                    "fde-fit-probe",
                    &raw,
                    crate::pqidx::PQ_FIT_PROBE,
                    |(id, _)| id.as_bytes().to_vec(),
                )
                .into_iter()
                .map(|i| raw[i].1.clone())
                .collect();
            self.warn_unrepresentative(CODEBOOK_FDE, &pq, &sample, &probe);
        }
        // Codebook + the rows it recodes commit together (ROADMAP A20). The
        // codebook was persisted before this loop and each repacked row
        // autocommitted, so an interruption left a v2 codebook over rows
        // still packed raw — readable only because `fde_row_unpack` accepts
        // both, which is luck rather than design — at one fsync per row.
        // Advisory tier: a failed rewrite rolls back whole and leaves the raw
        // rows the reader already understands. It must not fail the search
        // that happened to trigger it.
        let repack = self.one_rewrite(|| {
            self.fde_meta_put("codebook", &pq.to_bytes())?;
            self.codebook_generation_bump(CODEBOOK_FDE);
            // Repack every raw row to v2 with the codebook in hand (list -1 —
            // reserved, see the module docs).
            for (id, fde) in &raw {
                let payload = fde_row_pack_coded(-1, &pq.encode(fde));
                let blob = self.vault.tokens_at_rest(&format!("fde/{id}"), &payload);
                self.conn.execute(
                    "UPDATE drawer_fde SET fde = ?1 WHERE id = ?2",
                    params![blob, id],
                )?;
            }
            Ok(())
        });
        if let Err(e) = repack {
            undercroft_obs::diag_warn!(
                "FDE codebook + repack rolled back ({e}); the raw rows stand and \
                 the flat scan serves — a later search retries"
            );
            return Ok(());
        }
        *self.fde_pq.borrow_mut() = Some(pq);
        self.fde_cache.borrow_mut().take(); // rebuild coded
        Ok(())
    }

    /// Load the FDE cache (no-op if present): one pass per open, sealed
    /// rows decrypt through the vault. Rows that fail to open or parse are
    /// skipped — they only cost their candidate slot.
    fn fde_cache_ensure(&self, model: &str, fde_dim: usize) -> Result<(), StoreError> {
        if self.fde_cache.borrow().is_some() {
            return Ok(());
        }
        let code_len = self.fde_pq.borrow().as_ref().map_or(0, |pq| pq.code_len());
        let rows: Vec<(String, i64, Vec<u8>)> = self
            .conn
            .prepare(
                "SELECT f.id, d.seq, f.fde FROM drawer_fde f
                 JOIN drawers d ON d.id = f.id WHERE f.model = ?1",
            )?
            .query_map(params![model], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        let mut raw = Vec::new();
        let mut slabs: std::collections::HashMap<i64, (Vec<i64>, Vec<u8>)> =
            std::collections::HashMap::new();
        let mut coded_n = 0usize;
        for (id, seq, blob) in rows {
            let Ok(plain) = self.vault.tokens_from_rest(&format!("fde/{id}"), &blob) else {
                continue;
            };
            match fde_row_unpack(&plain, fde_dim, code_len) {
                Some(FdeRow::Raw(f)) => raw.push((seq, f)),
                Some(FdeRow::Coded(list, code)) => {
                    let (seqs, codes) = slabs.entry(list).or_default();
                    seqs.push(seq);
                    codes.extend_from_slice(&code);
                    coded_n += 1;
                }
                None => {}
            }
        }
        // One variant at a time (the train pass repacks wholesale); if both
        // somehow appear, the coded majority wins and stragglers cost their
        // candidate slot until the next backfill sweep.
        *self.fde_cache.borrow_mut() = Some(if coded_n >= raw.len() {
            FdeCache::Coded { code_len, slabs }
        } else {
            FdeCache::Raw(raw)
        });
        Ok(())
    }

    /// Load-or-train the inverted tier once per session. Past `fde_ivf_min`
    /// coded rows, coarse centroids (`nlist ≈ √N`, clamp 16..=4096) train
    /// over the palace's own decoded FDEs, every row's reserved list field
    /// rewrites in place (the v2 pack anticipated this — no migration), and
    /// the cache regroups. Centroids retrain when the corpus doubles past
    /// their training size. Advisory like every derived artifact.
    ///
    /// It must never `BEGIN` **inside a caller's transaction** — the rule that
    /// keeps `upsert_many`'s batch working, and the reason this rewrite was
    /// left un-transacted for so long. [`PalaceStore::one_rewrite`] states the
    /// rule instead of avoiding it: a transaction at the top level, nothing at
    /// all when one is already open.
    fn fde_ivf_ensure(&self, model: &str) -> Result<(), StoreError> {
        if self.fde_ivf_checked.get() {
            return Ok(());
        }
        self.fde_ivf_checked.set(true);
        if self.fde_ivf.borrow().is_none() {
            if let Some(cq) = self
                .fde_meta_get("ivf")?
                .and_then(|b| CoarseQuantizer::from_bytes(&b))
            {
                *self.fde_ivf.borrow_mut() = Some(cq);
            }
        }
        // Training or retraining the inverted tier's centroids — and
        // re-assigning every coded row to a list — is a write (R1). A
        // read-only store uses the centroids it loaded above, or none, and
        // the flat ADC scan serves either way.
        if !self.may_build_indexes() {
            return Ok(());
        }
        let n = self
            .fde_cache
            .borrow()
            .as_ref()
            .map_or(0, |c| c.coded_rows());
        // Same freshness rule as the embedding-space IVF (1.5×, see
        // `pqidx::ivf_fresh` for why the 2× doubling rule was retired).
        let fresh = matches!(
            self.fde_ivf.borrow().as_ref(),
            Some(cq) if crate::pqidx::ivf_fresh(n as u64, cq.trained_n())
        );
        if n < self.fde_ivf_min || fresh {
            return Ok(());
        }
        // Decode every cached code back to FDE space for training +
        // assignment (one pass, RAM only — the codes are already in hand).
        let mut rows: Vec<(i64, Vec<u8>, Vec<f32>)> = Vec::with_capacity(n);
        {
            let cache_ref = self.fde_cache.borrow();
            let Some(FdeCache::Coded { code_len, slabs }) = cache_ref.as_ref() else {
                return Ok(());
            };
            let pq_ref = self.fde_pq.borrow();
            let Some(pq) = pq_ref.as_ref() else {
                return Ok(());
            };
            let cl = *code_len;
            if cl == 0 {
                return Ok(());
            }
            for (seqs, codes) in slabs.values() {
                for (i, seq) in seqs.iter().enumerate() {
                    let code = &codes[i * cl..(i + 1) * cl];
                    rows.push((*seq, code.to_vec(), pq.decode(code)));
                }
            }
        }
        let source_of_seq = self.source_by_seq()?;
        let sample: Vec<Vec<f32>> = self
            .keyed_sample_capped(
                CODEBOOK_FDE_IVF,
                &rows,
                FDE_PQ_SAMPLE,
                |(seq, _, _)| seq.to_le_bytes().to_vec(),
                |(seq, _, _)| source_of_seq.get(seq).cloned().unwrap_or_default(),
            )
            .into_iter()
            .map(|i| rows[i].2.clone())
            .collect();
        let nlist = ((n as f64).sqrt() as usize).clamp(16, 4096);
        let Some(cq) = CoarseQuantizer::train(&sample, nlist, FDE_IVF_ITERS, n as u64) else {
            return Ok(());
        };
        let id_of: std::collections::HashMap<i64, String> = self
            .conn
            .prepare(
                "SELECT d.seq, f.id FROM drawer_fde f
                 JOIN drawers d ON d.id = f.id WHERE f.model = ?1",
            )?
            .query_map(params![model], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        // Centroids + every row's re-assigned list field in ONE transaction
        // (ROADMAP A20). Both halves describe the same partitioning: stored
        // centroids over rows still carrying the previous assignment send
        // every probe to the wrong slab, and the per-row autocommit made that
        // the state any interruption left behind — at one fsync per row.
        let mut slabs: std::collections::HashMap<i64, (Vec<i64>, Vec<u8>)> =
            std::collections::HashMap::new();
        let mut code_len = 0usize;
        let repartition = self.one_rewrite(|| {
            self.fde_meta_put("ivf", &cq.to_bytes())?;
            self.codebook_generation_bump(CODEBOOK_FDE_IVF);
            for (seq, code, fde) in rows {
                let list = cq.assign(&fde) as i64;
                if let Some(id) = id_of.get(&seq) {
                    let payload = fde_row_pack_coded(list, &code);
                    let blob = self.vault.tokens_at_rest(&format!("fde/{id}"), &payload);
                    self.conn.execute(
                        "UPDATE drawer_fde SET fde = ?1 WHERE id = ?2",
                        params![blob, id],
                    )?;
                }
                code_len = code.len();
                let (seqs, codes) = slabs.entry(list).or_default();
                seqs.push(seq);
                codes.extend_from_slice(&code);
            }
            Ok(())
        });
        if let Err(e) = repartition {
            // Advisory: the previous partitioning (or none) survives whole,
            // and the flat ADC scan serves either way.
            undercroft_obs::diag_warn!(
                "FDE inverted tier rolled back ({e}); the previous partitioning stands"
            );
            return Ok(());
        }
        // Regroup the cache from the assignments in hand.
        *self.fde_cache.borrow_mut() = Some(FdeCache::Coded { code_len, slabs });
        *self.fde_ivf.borrow_mut() = Some(cq);
        Ok(())
    }

    /// Top-`k` candidate seqs by FDE similarity, or `None` when FDE
    /// retrieval can't serve this query (no late encoder, no FDE rows, or
    /// an empty query encode) — the caller falls back to the fusion scan.
    /// Test surface: the production path always resolves a scope first and
    /// calls [`Self::fde_candidates_in`].
    #[cfg(test)]
    pub(crate) fn fde_candidates(
        &self,
        query: &str,
        k: usize,
    ) -> Result<Option<Vec<i64>>, StoreError> {
        self.fde_candidates_in(query, k, None)
    }

    /// [`Self::fde_candidates`] restricted to a declared scope's seq set:
    /// the FDE index is scope-blind (wing and room alike), so every
    /// candidate is membership-filtered before the cut, and the inverted
    /// tier's probe must find `k` rows INSIDE the scope before it is
    /// trusted over the full scan.
    pub(crate) fn fde_candidates_in(
        &self,
        query: &str,
        k: usize,
        scope: Option<&crate::SeqFilter>,
    ) -> Result<Option<Vec<i64>>, StoreError> {
        let Some(late) = &self.late else {
            return Ok(None);
        };
        let model = late.model_name().to_string();
        if !matches!(self.fde_encoder_ensure(late.dim()), Ok(true)) {
            return Ok(None);
        }
        let fde_dim = self
            .fde_encoder
            .borrow()
            .as_ref()
            .map_or(0, |enc| enc.dim());
        // The backfill writes a row per drawer that has a token matrix and
        // no FDE — a build, not a read, so a read-only store skips it (R1)
        // and answers from whatever rows its writer already stored.
        if !self.fde_checked.get() && self.may_build_indexes() {
            self.fde_checked.set(true);
            self.fde_backfill(&model)?;
            self.fde_cache.borrow_mut().take(); // rebuild below with new rows
        }
        self.fde_pq_ensure(&model, fde_dim)?;
        self.fde_cache_ensure(&model, fde_dim)?;
        self.fde_ivf_ensure(&model)?;
        let qmatrix = late.encode_query(query);
        if qmatrix.is_empty() {
            return Ok(None);
        }
        // Stash the encoded query for the MaxSim rescore stage: the forward
        // is the expensive part of both stages, and one search pays it once.
        *self.qmatrix_cache.borrow_mut() = Some((query.to_string(), qmatrix.clone()));
        let qfde = {
            let enc_ref = self.fde_encoder.borrow();
            let Some(enc) = enc_ref.as_ref() else {
                return Ok(None);
            };
            enc.encode_query(&qmatrix)
        };
        let cache_ref = self.fde_cache.borrow();
        let mut scored: Vec<(f32, i64)> = match cache_ref.as_ref() {
            Some(FdeCache::Raw(rows)) if !rows.is_empty() => rows
                .iter()
                .map(|(seq, fde)| (fde_dot(&qfde, fde), *seq))
                .collect(),
            Some(FdeCache::Coded { code_len, slabs }) if !slabs.is_empty() && *code_len > 0 => {
                // ADC over the codes: per-query dot LUTs, 16 table adds per
                // doc. With live centroids only the probed lists' slabs are
                // scanned (plus -1); skewed partitions that return fewer
                // than `k` rows widen to the full scan rather than starve
                // the candidate pool.
                let pq_ref = self.fde_pq.borrow();
                let Some(pq) = pq_ref.as_ref() else {
                    return Ok(None);
                };
                let Some(tables) = pq.dot_tables(&qfde) else {
                    return Ok(None);
                };
                let cl = *code_len;
                let scan = |lists: Option<&[i64]>| -> Vec<(f32, i64)> {
                    let mut out = Vec::new();
                    let mut slab = |seqs: &Vec<i64>, codes: &Vec<u8>| {
                        for (i, seq) in seqs.iter().enumerate() {
                            out.push((pq.adc_dot(&tables, &codes[i * cl..(i + 1) * cl]), *seq));
                        }
                    };
                    match lists {
                        Some(ls) => {
                            for l in ls {
                                if let Some((seqs, codes)) = slabs.get(l) {
                                    slab(seqs, codes);
                                }
                            }
                        }
                        None => {
                            for (seqs, codes) in slabs.values() {
                                slab(seqs, codes);
                            }
                        }
                    }
                    out
                };
                let ivf_ref = self.fde_ivf.borrow();
                match ivf_ref.as_ref() {
                    Some(cq) => {
                        let nprobe = self.fde_nprobe.unwrap_or_else(|| (cq.nlist() / 4).max(8));
                        let mut lists: Vec<i64> =
                            cq.probe(&qfde, nprobe).into_iter().map(i64::from).collect();
                        lists.push(-1);
                        let probed = scan(Some(&lists));
                        let enough = match scope {
                            Some(s) => probed.iter().filter(|(_, q)| s.admits(q)).count() >= k,
                            None => probed.len() >= k,
                        };
                        if enough {
                            probed
                        } else {
                            scan(None)
                        }
                    }
                    None => scan(None),
                }
            }
            _ => return Ok(None),
        };
        if let Some(s) = scope {
            scored.retain(|(_, seq)| s.admits(seq));
        }
        if scored.len() > k {
            scored.select_nth_unstable_by(k - 1, |a, b| {
                b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal)
            });
            scored.truncate(k);
        }
        Ok(Some(scored.into_iter().map(|(_, seq)| seq).collect()))
    }
}
