//! SQLite-backed palace storage, one database per vault.
//!
//! Mirrors mempalace's `sqlite_exact` backend shape (documents +
//! metadata_json + embedding blob + FTS5 when available) with the vault
//! security layer threaded through every read and write:
//!
//! * content / embeddings pass through [`Vault::content_at_rest`] — sealed
//!   vaults store only ciphertext, and nothing content-derived (including
//!   the FTS index) is persisted in plaintext;
//! * every row carries an HMAC tag over `id \x1f meta_json \x1f content`,
//!   verified on read and re-walkable via [`PalaceStore::verify`];
//! * an append-only `audit` table records the tag of every write in order,
//!   which must replay to the manifest's HMAC chain head.

mod fdeidx;
#[cfg(feature = "hnsw")]
mod hnsw;
pub mod kg;
mod latestage;
pub mod manage;
pub mod pq;
mod pqidx;
pub mod remote;
mod rotate;

pub use kg::{KgStats, ReceiptStatus, ReceiptVerdict, Triple};
pub use manage::{DedupReport, DrawerSummary, Hallway, PalaceStats, Tunnel};
pub use rotate::RotationReport;

use rusqlite::{params, Connection, OptionalExtension};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use undercroft_core::embed::{cosine, Embedder};
use undercroft_core::{Drawer, DrawerMeta, HashEmbedder, Reranker};
use undercroft_vault::{SecurityLevel, Vault, VaultError};

/// Drawer count at which the BM25 prefilter engages for hmac-only vaults.
/// Below this a full decrypt-free scan is cheap and keeps semantic-only
/// recall exact; above it the FTS5 candidate cut dominates search cost.
const DEFAULT_FTS_PREFILTER_MIN: usize = 2048;

/// The cosine above which a drawer is admitted on semantic evidence alone.
///
/// **Calibrated to `HashEmbedder`, and must be re-derived for any other
/// embedder.** `semantic` is `(cosine + 1) / 2`, so this is a raw cosine of
/// 0.12 — chosen because feature hashing over surface forms puts unrelated
/// text at almost exactly zero. A model embedder does not: its unrelated-pair
/// floor is typically well above 0.12, and swapping one in without re-deriving
/// this number makes the disjunct vacuously true and retires the relevance
/// gate for every query in every language, by configuration rather than by
/// code. `the_semantic_gate_is_calibrated_to_the_default_embedder` is the
/// acceptance test for that.
///
/// It is also length-sensitive in a way nothing else records: measured, a
/// typo pair and a false friend both admit on a bare pair (0.85, 0.78) and
/// stop admitting past ~40 words, while a true morphological pair
/// (`книга`/`книге`) stops admitting at 20. Admission on this leg tracks
/// drawer length as much as relatedness, which is why lexical evidence is
/// what the gate should mostly rest on.
const SEMANTIC_ADMISSION_GATE: f32 = 0.56;

/// Bumped whenever `search_key` changes what the FTS index holds, so an
/// existing vault rebuilds instead of serving a stale token set. `v1` is the
/// first folded index; a vault written before it has no marker at all and the
/// external-content triggers are dropped on the way past.
const FTS_KEY_VERSION: &str = "v1";

/// Embedder identity changes this build performs on its own.
///
/// Only the built-in hash embedder appears here. It is deterministic, local
/// and cheap, so re-embedding a vault is a walk rather than a model run — and
/// because it ships inside the binary, a user who merely upgraded did not
/// choose a new embedding space and should not have to repair one by hand.
///
/// A swap to or from a model-backed embedder is never automatic: that is
/// potentially hours of inference and a deliberate decision, so it keeps the
/// explicit `UNDERCROFT_FORCE_EMBEDDER` + `repair` path.
const KNOWN_EMBEDDER_UPGRADES: &[(&str, &str)] = &[
    (
        undercroft_core::embed::HASH_EMBEDDER_V1,
        undercroft_core::embed::HASH_EMBEDDER,
    ),
    // v2 never shipped in a tag, but it existed on the branch long enough for
    // a vault to be built from it. Without this row such a vault matches on
    // name, returns early, and keeps vectors from a different token space with
    // no warning and no override that helps.
    (
        undercroft_core::embed::HASH_EMBEDDER_V2,
        undercroft_core::embed::HASH_EMBEDDER,
    ),
];

// KNOWN GAP, deliberately accepted — no v4.
//
// Moving Hebrew out of the delimiting script class changed its token space:
// `segment` now emits character bigrams for Hebrew where it emitted one word,
// and the fold strips the points. Every other script's tokens are byte-
// identical, so the blast radius is Hebrew alone — much narrower than v1→v2
// (fold + segmentation) or v2→v3 (Brahmic conjuncts), both of which moved
// tokens for whole script families and therefore bumped.
//
// The consequence is real and is not fixed here: a vault that already holds
// Hebrew content keeps `undercroft-hash-v3` vectors built from the old token
// space, so its Hebrew *cosine* leg stays stale until someone runs
// `UNDERCROFT_FORCE_EMBEDDER=1` + `repair`. The lexical channels — which are
// what this change was for, and what carries Hebrew from 0% to 87.5% — are
// recomputed at read and are correct immediately.
//
// This is a judgement that a whole-fleet re-embed is not worth one script's
// cosine leg, not a claim that nothing changed. If Hebrew corpora become a
// real workload, the fix is a v4 row above and it costs 45.9 µs/drawer.
/// Default number of fusion-ranked candidates a reranker re-scores per search
/// (override with `UNDERCROFT_RERANK_TOP_N`). One cross-encoder forward pass
/// runs per candidate, so this bounds the added latency.
const DEFAULT_RERANK_TOP_N: usize = 50;

/// Append an audit entry **and** advance the committed chain head, inside
/// the caller's open transaction (a [`rusqlite::Transaction`] derefs to
/// `Connection`, so both work). Returns `(new_head_hex, writes)` for the
/// post-commit [`Vault::anchor_manifest`] call. Every mutation site pairs
/// its data statements with exactly one `chain_append` in one transaction —
/// the invariant that makes a crash unable to separate a record from its
/// chain entry.
pub(crate) fn chain_append(
    conn: &rusqlite::Connection,
    vault: &Vault,
    record_id: &str,
    tag: &[u8],
    at: &str,
) -> Result<(String, u64), StoreError> {
    conn.execute(
        "INSERT INTO audit (record_id, tag, at) VALUES (?1, ?2, ?3)",
        params![record_id, tag, at],
    )?;
    let head: String =
        conn.query_row("SELECT value FROM chain_meta WHERE key = 'head'", [], |r| {
            r.get(0)
        })?;
    let next = vault.chain_next_hex(&head, tag)?;
    let writes: u64 =
        conn.query_row(
            "SELECT value FROM chain_meta WHERE key = 'writes'",
            [],
            |r| r.get::<_, String>(0),
        )?
        .parse::<u64>()
        .map_err(|e| StoreError::CorruptRow {
            id: "chain_meta/writes".into(),
            reason: e.to_string(),
        })? + 1;
    conn.execute(
        "UPDATE chain_meta SET value = ?1 WHERE key = 'head'",
        params![next],
    )?;
    conn.execute(
        "UPDATE chain_meta SET value = ?1 WHERE key = 'writes'",
        params![writes.to_string()],
    )?;
    Ok((next, writes))
}

pub(crate) fn rerank_top_n() -> usize {
    std::env::var("UNDERCROFT_RERANK_TOP_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_RERANK_TOP_N)
}

/// How the semantic and lexical signals are combined at rank time.
///
/// `Bm25` (the default) blends cosine with a real Okapi BM25 lexical score
/// (IDF-weighted, length-normalized) computed over the decrypted candidate
/// set, plus recency. `Legacy` is the older behavior: the lexical term is a
/// flat term-overlap fraction that weights every matched query term equally
/// — measurably worse (see benchmarks/RESULTS.md; BM25 lifts LongMemEval-S
/// R@5 from 90.4% to 95.0% with the hash embedder, almost entirely on
/// paraphrase-heavy preference questions). `Rrf` fuses the cosine and BM25
/// rankings with reciprocal-rank fusion — scale-free, but it discards score
/// magnitude and benchmarked below `Bm25`. All three verify HMACs
/// identically; fusion only reorders already-trusted candidates.
///
/// Override at open with `UNDERCROFT_FUSION` (`bm25` / `legacy` / `rrf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fusion {
    Legacy,
    Bm25,
    Rrf,
}

impl Fusion {
    fn from_env() -> Self {
        match std::env::var("UNDERCROFT_FUSION").ok().as_deref() {
            Some(v) if v.eq_ignore_ascii_case("legacy") => Fusion::Legacy,
            Some(v) if v.eq_ignore_ascii_case("rrf") => Fusion::Rrf,
            _ => Fusion::Bm25,
        }
    }
}

// Okapi BM25 constants (the standard defaults).
const BM25_K1: f32 = 1.2;
const BM25_B: f32 = 0.75;
// Reciprocal-rank-fusion damping — the canonical value from the original
// RRF paper; larger flattens the contribution of top ranks.
const RRF_K: f32 = 60.0;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("corrupt row {id}: {reason}")]
    CorruptRow { id: String, reason: String },
    #[error("integrity failure on record {0} — HMAC mismatch")]
    Integrity(String),
    #[error(
        "vault was embedded with {stored:?} ({stored_dim}d) but the current embedder is \
         {current:?} ({current_dim}d); searching across a model swap silently degrades recall. \
         Set UNDERCROFT_FORCE_EMBEDDER=1 to record the new identity, then run `undercroft repair` \
         to re-embed."
    )]
    EmbedderMismatch {
        stored: String,
        stored_dim: usize,
        current: String,
        current_dim: usize,
    },
    #[error("remote index error: {0}")]
    Index(#[from] undercroft_index::IndexError),
    #[error(
        "the remote index was built with embedder {pushed:?} but this vault now uses \
         {current:?}; vectors from two embedding spaces cannot be compared, so its candidates \
         would be meaningless. Run `undercroft index push` to rebuild it."
    )]
    IndexStale { pushed: String, current: String },
    #[error("this vault uses external embeddings; writes must supply a vector")]
    ExternalVault,
    #[error("this vault computes its own embeddings; a vector may not be supplied")]
    NotExternalVault,
    #[error("embedding dimension mismatch: vault expects {expected}, got {got}")]
    EmbeddingDim { expected: usize, got: usize },
    #[error("invalid operation: {0}")]
    Invalid(String),
}

/// Raw drawer row as read for search: (id, meta_json, content, embedding, tag).
type SearchRow = (String, String, Vec<u8>, Vec<u8>, Vec<u8>);

/// Take `limit` hits from `hits` (already best-first) allowing at most `cap`
/// per room, then refill any slots the cap left empty in score order.
///
/// Order within the result stays score-descending, so a caller that ignores
/// rooms sees nothing surprising. Single pass plus a small counter map: no
/// re-scoring, no extra decryption, no allocation per candidate.
fn diversify_by_room(hits: Vec<SearchHit>, limit: usize, cap: usize) -> Vec<SearchHit> {
    let mut per_room: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let mut taken = vec![false; hits.len()];
    let mut chosen = 0usize;
    for (i, h) in hits.iter().enumerate() {
        if chosen == limit {
            break;
        }
        let n = per_room.entry(h.drawer.meta.room.as_str()).or_insert(0);
        if *n < cap {
            *n += 1;
            taken[i] = true;
            chosen += 1;
        }
    }
    // Refill: the cap is a spreading preference, not a quota to enforce at
    // the cost of returning fewer memories than asked for.
    if chosen < limit {
        for (i, slot) in taken.iter_mut().enumerate() {
            if chosen == limit {
                break;
            }
            if !*slot {
                *slot = true;
                chosen += 1;
            }
            let _ = i;
        }
    }
    hits.into_iter()
        .zip(taken)
        .filter_map(|(h, keep)| keep.then_some(h))
        .collect()
}

pub(crate) fn canonical(id: &str, meta_json: &[u8], content_at_rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(id.len() + meta_json.len() + content_at_rest.len() + 2);
    out.extend_from_slice(id.as_bytes());
    out.push(0x1f);
    out.extend_from_slice(meta_json);
    out.push(0x1f);
    out.extend_from_slice(content_at_rest);
    out
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub drawer: Drawer,
    pub score: f32,
    pub semantic: f32,
    /// Lexical evidence for ranking: exact term matches plus approximate ones
    /// (folds, one-edit tolerance, morphological families) at reduced weight.
    pub lexical: f32,
    /// Lexical evidence that the drawer literally contains a query term.
    ///
    /// This is what decides admission. Approximate evidence is a guess, and a
    /// guess should move a drawer within a result set rather than put it
    /// there: `lexical` alone would let one forgiven edit return a drawer as
    /// if it had said the word.
    pub lexical_exact: f32,
    /// Lexical evidence that the drawer holds a *morphological relative* of a
    /// query term rather than the term itself — today, and only, a whole word
    /// contained inside a longer one (`Dampfschiff` in
    /// `Donaudampfschifffahrt`).
    ///
    /// This admits, like `lexical_exact`, and unlike the approximate channel.
    /// The reason it is a separate field rather than folded into either is
    /// auditability: a caller can tell "your word is in here" from "something
    /// built on your word is in here", so a report of a surprising hit — or a
    /// surprising miss — is reproducible instead of a matter of opinion.
    ///
    /// It exists because the alternative was worse in both directions. Left in
    /// the approximate channel, containment could not admit, and measured, a
    /// compound drawer past ~80 words has neither exact lexical evidence nor a
    /// passing cosine, so it was dropped rather than mis-ranked. Promoted into
    /// `lexical_exact`, it would have become indistinguishable from the drawer
    /// having said the word — and `lexical_score`'s substring leg already makes
    /// that claim on `Fusion::Legacy` and every remote search, which is the
    /// inconsistency this resolves.
    pub lexical_morph: f32,
}

/// Result of [`PalaceStore::save_with_dedup`]: the drawer id that now holds
/// the content, whether it was a fresh insert, and whether an existing
/// near-duplicate was refreshed in place.
#[derive(Debug, Clone)]
pub struct SaveOutcome {
    pub id: String,
    pub created: bool,
    pub deduped: bool,
}

#[derive(Debug, Default, Clone)]
pub struct SearchOptions {
    pub wing: Option<String>,
    pub room: Option<String>,
    pub limit: usize,
    /// Soft cap on how many of the returned hits may come from any single
    /// room. `None` (the default) keeps pure score order.
    ///
    /// A room is a real structural unit — one session, ticket or meeting —
    /// and a question whose answer spans several of them is starved when a
    /// flat top-k fills up with the most verbose one. The cap is *soft*:
    /// once every room has had its share, leftover slots are refilled in
    /// score order, so a genuinely single-room question still gets its
    /// evidence and recall is never traded away.
    pub room_cap: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyReport {
    pub records_checked: u64,
    pub bad_records: Vec<String>,
    pub chain_ok: bool,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.bad_records.is_empty() && self.chain_ok
    }
}

pub struct PalaceStore {
    conn: Connection,
    vault: Vault,
    embedder: Box<dyn Embedder + Send>,
    /// Optional second-stage cross-encoder reranker. When present, the
    /// fusion-ranked top-N candidates are re-scored by `(query, content)`
    /// pairs before the final `limit` cut. `None` ⇒ first-pass ranking only.
    reranker: Option<Box<dyn Reranker + Send + Sync>>,
    /// Optional late-interaction (ColBERT) second stage: writes store
    /// per-token matrices, searches MaxSim-rescore the fusion top-N in one
    /// query forward. The cross-encoder wins when both are set. See
    /// `latestage`.
    late: Option<Box<dyn undercroft_core::late::LateInteraction + Send + Sync>>,
    /// In-process decrypted-embedding cache for long-running servers
    /// (serve-mcp / serve-http / daemon): sealed vaults pay AEAD decryption
    /// of every embedding once instead of on every search. Never persisted
    /// — this is the in-memory role embedded ChromaDB's index played
    /// upstream, without writing plaintext-derived data to disk.
    emb_cache: std::cell::RefCell<Option<std::collections::HashMap<String, Vec<f32>>>>,
    /// Whether the FTS5 BM25 prefilter index exists. Only ever true for
    /// hmac-only vaults — sealed vaults must not persist anything
    /// plaintext-derived, an FTS index included.
    fts: bool,
    /// Drawer count at which the prefilter engages; `None` disables it.
    fts_min: Option<usize>,
    /// How semantic and lexical signals are combined at rank time.
    fusion: Fusion,
    /// `Some(dim)` when this vault's embeddings are supplied by the caller
    /// (embedder identity `external:<name>@<dim>`): writes must carry a
    /// vector of exactly `dim`, and the store never computes an embedding.
    external_dim: Option<usize>,
    /// When true, search uses the local in-memory HNSW ANN prefilter instead
    /// of the full cosine scan. Opt-in; requires the `hnsw` build feature.
    hnsw_enabled: bool,
    /// Lazily-built in-memory HNSW index (RAM only, never persisted). Dropped
    /// on any write and rebuilt on the next search.
    #[cfg(feature = "hnsw")]
    hnsw: std::cell::RefCell<Option<hnsw::HnswIndex>>,
    /// When true (hmac-only vaults only), search prefilters candidates via the
    /// on-disk PQ codes — bounded RAM at any corpus size. See `pqidx`.
    pq_enabled: bool,
    /// The cached PQ codebook (the on-disk copy in `pq_meta` is authoritative).
    pq: std::cell::RefCell<Option<pq::ProductQuantizer>>,
    /// The cached IVF coarse quantizer (on-disk copy in `pq_meta`, key `ivf`).
    ivf: std::cell::RefCell<Option<pq::CoarseQuantizer>>,
    /// Both levels: PQ code rows loaded (sealed: decrypted) once per open
    /// (~52 B per drawer — bounded), slab-grouped by IVF list so a probe
    /// scans only its lists contiguously. See `pqidx`.
    pq_cache: std::cell::RefCell<Option<pqidx::PqCache>>,
    /// Token-matrix product quantizer (v2 pack format) — trained from the
    /// vault's own stored matrices once they cross `tok_pq_min`, cached
    /// here, persisted sealed in `tok_meta`. See `latestage`.
    tok_pq: std::cell::RefCell<Option<pq::ProductQuantizer>>,
    /// Whether this session already tried to load/train the token codebook.
    tok_pq_checked: std::cell::Cell<bool>,
    /// Stored-matrix count at which the token codebook trains
    /// (`UNDERCROFT_TOK_PQ_MIN`, `off` ⇒ never — v1 int8 packing only).
    tok_pq_min: usize,
    /// Whether the PQ index passed its coherence check since the last event
    /// that could break it (open, or a write that failed to encode). While
    /// true, searches skip the O(corpus) verification entirely. See `pqidx`.
    pq_verified: std::cell::Cell<bool>,
    /// Live drawer count as of the last verification, maintained on writes —
    /// drives the IVF thresholds without per-search `COUNT(*)`.
    pq_live: std::cell::Cell<i64>,
    /// Corpus size at which the PQ prefilter partitions into IVF inverted
    /// lists (`usize::MAX` ⇒ never). See `pqidx`.
    ivf_min: usize,
    /// Inverted lists probed per query (`None` ⇒ `max(8, nlist/4)`).
    ivf_nprobe: Option<usize>,
    /// Sealed vaults: corpus size at which PQ codes keep to one AEAD page
    /// per IVF list instead of per-row seals (`usize::MAX` ⇒ never — the
    /// default; the page tier is opt-in until the RAM trigger fires).
    /// `UNDERCROFT_PQ_PAGE_MIN` / [`PalaceStore::set_pq_pages`]. See `pqidx`.
    pq_page_min: usize,
    /// When true, search generates candidates by MUVERA FDE dot product
    /// (`UNDERCROFT_RETRIEVAL=fde`; needs the late encoder). See `fdeidx`.
    fde_enabled: bool,
    /// The deterministic FDE encoder (params persisted sealed in `fde_meta`).
    fde_encoder: std::cell::RefCell<Option<undercroft_core::fde::FdeEncoder>>,
    /// FDE rows loaded once per open (sealed rows decrypt): raw vectors
    /// below the codebook threshold, PQ codes above it. See `fdeidx`.
    fde_cache: std::cell::RefCell<Option<fdeidx::FdeCache>>,
    /// Whether this session already ran the FDE backfill pass.
    fde_checked: std::cell::Cell<bool>,
    /// The FDE codebook (v2 packing; persisted sealed in `fde_meta`).
    fde_pq: std::cell::RefCell<Option<pq::ProductQuantizer>>,
    /// Whether this session already tried to load/train the FDE codebook.
    fde_pq_checked: std::cell::Cell<bool>,
    /// Stored-FDE count at which the codebook trains
    /// (`UNDERCROFT_FDE_PQ_MIN`, `off` ⇒ never — raw v1 rows only).
    fde_pq_min: usize,
    /// Inverted-tier coarse centroids over FDE space, trained event-driven
    /// past `fde_ivf_min` coded rows (persisted sealed in `fde_meta`).
    fde_ivf: std::cell::RefCell<Option<pq::CoarseQuantizer>>,
    fde_ivf_checked: std::cell::Cell<bool>,
    /// (`UNDERCROFT_FDE_IVF_MIN`, `off` ⇒ never.) Below this the flat ADC
    /// scan stays — it was the measured winner at every small-N scale.
    fde_ivf_min: usize,
    /// `UNDERCROFT_FDE_NPROBE` (default `max(8, nlist/4)` — recall tracks
    /// the probed fraction, mirroring the embedding-space PQ/IVF tier).
    fde_nprobe: Option<usize>,
    /// The current query's token matrix, stashed by FDE candidate
    /// generation and consumed by the MaxSim rescore — the query forward is
    /// the expensive part of both stages, and one search must pay it once.
    qmatrix_cache: std::cell::RefCell<Option<EncodedQuery>>,
}

/// A query's encoded token matrix, keyed by the query text it encodes.
type EncodedQuery = (String, Vec<f32>);

impl PalaceStore {
    /// Open with the default deterministic hashed n-gram embedder.
    pub fn open(vault: Vault) -> Result<Self, StoreError> {
        Self::open_with_embedder(vault, Box::new(HashEmbedder))
    }

    /// Open with an explicit embedder. The embedder's identity (model name
    /// and dimension) is recorded on first use and enforced afterwards:
    /// searching across a silent model swap degrades recall, so a mismatch
    /// is an error unless `UNDERCROFT_FORCE_EMBEDDER=1` re-records it
    /// (follow with `repair` to re-embed).
    pub fn open_with_embedder(
        vault: Vault,
        embedder: Box<dyn Embedder + Send>,
    ) -> Result<Self, StoreError> {
        let mut store = Self::open_inner(vault, embedder)?;
        store.enforce_embedder_identity(true)?;
        Ok(store)
    }

    /// Open for a role that must not write.
    ///
    /// A read-only replica still has to serve reads across an embedder
    /// upgrade, so a mismatch here neither migrates nor refuses: it warns and
    /// leaves the old vectors in place. The semantic leg is then comparing
    /// vectors from two different spaces and is not trustworthy, which the
    /// warning says — the lexical leg is unaffected, and `search` already
    /// admits a hit on lexical evidence alone.
    pub fn open_read_only(
        vault: Vault,
        embedder: Box<dyn Embedder + Send>,
    ) -> Result<Self, StoreError> {
        let mut store = Self::open_inner(vault, embedder)?;
        store.enforce_embedder_identity(false)?;
        Ok(store)
    }

    fn enforce_embedder_identity(&mut self, may_migrate: bool) -> Result<(), StoreError> {
        let stored_name: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'embedder_name'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let stored_dim: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'embedder_dim'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let current_name = self.embedder.model_name().to_string();
        let current_dim = self.embedder.dimension();
        match (stored_name, stored_dim) {
            (Some(name), Some(dim)) => {
                let dim: usize = dim.parse().unwrap_or(0);
                if name == current_name && (dim == 0 || dim == current_dim) {
                    return Ok(());
                }
                // The documented override comes first, so it dominates every
                // identity path. Putting it after the migration branch would
                // make it dead code for the one transition that actually does
                // fallible work, leaving an operator whose migration cannot
                // complete with no way in.
                if std::env::var("UNDERCROFT_FORCE_EMBEDDER").ok().as_deref() == Some("1") {
                    // A read-only role must not write, and recording the
                    // identity is a write. An operator setting the override to
                    // get a replica past `EmbedderMismatch` would otherwise
                    // get a replica that claims the new identity, keeps the
                    // old vectors, and serves a semantic leg spanning two
                    // embedding spaces — with nothing on disk saying so.
                    if !may_migrate {
                        undercroft_obs::diag_warn!(
                            "UNDERCROFT_FORCE_EMBEDDER=1 on a read-only open: serving {name} \
                             vectors with the {current_name} embedder, and recording nothing. \
                             The semantic ranking spans two embedding spaces and is not \
                             meaningful; the lexical leg is unaffected"
                        );
                        return Ok(());
                    }
                    self.record_embedder_identity()?;
                    return Ok(());
                }
                // A known, dimension-preserving upgrade of the built-in
                // embedder is a migration we know how to run, not a mismatch
                // to refuse. `dim == 0` means the stored dimension is
                // unparseable, which is not evidence that it matches — treat
                // it as a mismatch rather than migrating on an assumption.
                let known = KNOWN_EMBEDDER_UPGRADES
                    .iter()
                    .any(|(from, to)| *from == name && *to == current_name);
                if known && dim == current_dim {
                    if !may_migrate {
                        undercroft_obs::diag_warn!(
                            "vault holds {name} embeddings but this build uses {current_name}; \
                             opened read-only so they are left as they are — the semantic \
                             ranking is not meaningful until a writable open migrates them"
                        );
                        return Ok(());
                    }
                    return self.migrate_embedding_space();
                }
                Err(StoreError::EmbedderMismatch {
                    stored: name,
                    stored_dim: dim,
                    current: current_name,
                    current_dim,
                })
            }
            _ => self.record_embedder_identity(),
        }
    }

    /// Re-embed every drawer after a known upgrade of the built-in embedder.
    ///
    /// **Safe to interrupt.** Embeddings are derived data and are not covered
    /// by the record HMAC, so nothing here touches a drawer tag or the audit
    /// chain — which is exactly why a re-embed is not a rotation. Re-embedding
    /// is idempotent (same content, same embedder, same vector), and the new
    /// identity is written only after the last row lands, so a crash mid-walk
    /// leaves the old identity in place and the next open repeats the whole
    /// walk to the same result.
    ///
    /// Every drawer is read through `get`, so the pass verifies each record's
    /// HMAC on the way past. A tampered vault fails the migration rather than
    /// quietly re-embedding corrupt content.
    fn migrate_embedding_space(&mut self) -> Result<(), StoreError> {
        let ids: Vec<String> = self
            .conn
            .prepare("SELECT id FROM drawers ORDER BY seq")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        // This runs inside `open`, so on a large vault it must say what it is
        // doing rather than look like a hang. Counts and identities only —
        // never content.
        if !ids.is_empty() {
            undercroft_obs::diag_info!(
                "migrating {} drawers to embedder {} (one-time, resumable)",
                ids.len(),
                undercroft_core::embed::HASH_EMBEDDER
            );
        }
        // Batched rather than one transaction: a vault with 100k drawers
        // should not hold a single write lock for the length of the walk, and
        // idempotency plus the deferred identity write make batching safe.
        let mut damaged = 0u64;
        for chunk in ids.chunks(512) {
            let mut rows: Vec<(String, Vec<u8>)> = Vec::with_capacity(chunk.len());
            for id in chunk {
                // A drawer that cannot be read is skipped, not fatal. `get`
                // verifies the record HMAC, so a corrupt or tampered row
                // errors here — and aborting would turn a vault that was
                // damaged-but-mostly-readable into one that opens for nothing
                // at all, including `verify`, which is the only tool that can
                // name the damage. Its old vector stays; a row that fails
                // every read does not have a recall problem.
                match self.get(id) {
                    Ok(Some(d)) => {
                        let emb = self.embedder_embed(&d.content);
                        rows.push((id.clone(), self.vault.embedding_at_rest(id, &emb)));
                    }
                    Ok(None) => {}
                    Err(_) => {
                        damaged += 1;
                        undercroft_obs::diag_warn!(
                            "drawer {id} could not be read during re-embed and was left \
                             untouched; run `verify`"
                        );
                    }
                }
            }
            let tx = self.conn.transaction()?;
            {
                let mut up = tx.prepare("UPDATE drawers SET embedding = ?1 WHERE id = ?2")?;
                for (id, blob) in &rows {
                    up.execute(params![blob, id])?;
                }
            }
            tx.commit()?;
        }
        if damaged > 0 {
            undercroft_obs::diag_warn!(
                "{damaged} drawer(s) could not be re-embedded; the vault is open and the rest \
                 migrated — run `verify` to see which"
            );
        }
        self.invalidate_embedding_space()?;
        // Recorded even when rows were skipped. Withholding it would make
        // every future open repeat the whole walk for damage that only
        // `repair` can clear — and on the multi-tenant server that is once
        // per request.
        self.record_embedder_identity()
    }

    /// Discard everything derived from the *previous* embedding vectors.
    ///
    /// The PQ/IVF index quantizes the vector space: its codes, pages and
    /// codebook all describe embeddings that no longer exist, and a stale
    /// codebook does not fail loudly — it silently returns the wrong
    /// candidates. Dropping the tables lets the existing self-heal rebuild
    /// them.
    ///
    /// ColBERT token matrices (`drawer_tok`) and the FDE index are built from
    /// the late-interaction model rather than this one, so they are correct
    /// across an embedder change and are deliberately left in place.
    pub(crate) fn invalidate_embedding_space(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "DROP TABLE IF EXISTS drawer_pq;
             DROP TABLE IF EXISTS pq_page;
             DROP TABLE IF EXISTS pq_meta;",
        )?;
        self.drop_derived_caches();
        Ok(())
    }

    fn record_embedder_identity(&self) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('embedder_name', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![self.embedder.model_name()],
        )?;
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('embedder_dim', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![self.embedder.dimension().to_string()],
        )?;
        Ok(())
    }

    /// Reconcile a pending key rotation (`vault.json.next`) against the
    /// database's `keycheck` marker, and keep that marker seeded. The
    /// keycheck flips inside the rotation transaction, so it says exactly
    /// whether the re-seal committed: match ⇒ the crash happened after
    /// commit, promote the staged manifest and adopt the new keys;
    /// mismatch ⇒ before commit, discard the staging file and stay on the
    /// current keys. Runs before any read so a crashed rotation can never
    /// masquerade as tamper.
    fn reconcile_rotation(conn: &Connection, mut vault: Vault) -> Result<Vault, StoreError> {
        let db_kc: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = 'keycheck'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(pending) = vault.take_pending() {
            if db_kc.as_deref() == Some(pending.keycheck_hex().as_str()) {
                pending.promote_manifest()?;
                vault = *pending;
            } else {
                vault.discard_pending_file()?;
            }
        }
        let want = vault.keycheck_hex();
        if db_kc.as_deref() != Some(want.as_str()) {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('keycheck', ?1) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![want],
            )?;
        }
        Ok(vault)
    }

    fn open_inner(vault: Vault, embedder: Box<dyn Embedder + Send>) -> Result<Self, StoreError> {
        let conn = Connection::open(vault.db_path())?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // Pinned explicitly rather than left to the compile-time default: the
        // manifest anchor is written *after* the transaction that produced a
        // chain head, and open-time reconciliation treats an anchor the
        // database chain never produced as tamper. FULL guarantees the
        // data+chain commit reaches disk before its anchor possibly can, so a
        // power loss always leaves the anchor equal or *behind* (the healed
        // crash case) — never ahead (the alarm case).
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS drawers (
                 seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                 id         TEXT NOT NULL UNIQUE,
                 wing       TEXT NOT NULL,
                 room       TEXT NOT NULL,
                 meta_json  TEXT NOT NULL,
                 content    BLOB NOT NULL,
                 embedding  BLOB NOT NULL,
                 tag        BLOB NOT NULL,
                 filed_at   TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_drawers_wing_room ON drawers(wing, room);
             CREATE TABLE IF NOT EXISTS audit (
                 seq       INTEGER PRIMARY KEY AUTOINCREMENT,
                 record_id TEXT NOT NULL,
                 tag       BLOB NOT NULL,
                 at        TEXT NOT NULL
             );",
        )?;
        let vault = Self::reconcile_rotation(&conn, vault)?;
        let fts_min = match std::env::var("UNDERCROFT_FTS_PREFILTER_MIN") {
            Ok(v) if v.eq_ignore_ascii_case("off") => None,
            Ok(v) => Some(v.parse().unwrap_or(DEFAULT_FTS_PREFILTER_MIN)),
            Err(_) => Some(DEFAULT_FTS_PREFILTER_MIN),
        };
        let external_dim = embedder
            .model_name()
            .starts_with("external:")
            .then(|| embedder.dimension());
        let mut store = Self {
            conn,
            vault,
            embedder,
            reranker: None,
            late: None,
            emb_cache: std::cell::RefCell::new(None),
            fts: false,
            fts_min,
            fusion: Fusion::from_env(),
            external_dim,
            hnsw_enabled: false,
            #[cfg(feature = "hnsw")]
            hnsw: std::cell::RefCell::new(None),
            pq_enabled: false,
            pq: std::cell::RefCell::new(None),
            ivf: std::cell::RefCell::new(None),
            pq_cache: std::cell::RefCell::new(None),
            tok_pq: std::cell::RefCell::new(None),
            tok_pq_checked: std::cell::Cell::new(false),
            tok_pq_min: match std::env::var("UNDERCROFT_TOK_PQ_MIN") {
                Ok(v) if v.eq_ignore_ascii_case("off") => usize::MAX,
                Ok(v) => v.parse().unwrap_or(latestage::TOK_PQ_MIN_DEFAULT),
                Err(_) => latestage::TOK_PQ_MIN_DEFAULT,
            },
            pq_verified: std::cell::Cell::new(false),
            pq_live: std::cell::Cell::new(0),
            ivf_min: match std::env::var("UNDERCROFT_IVF_MIN") {
                Ok(v) if v.eq_ignore_ascii_case("off") => usize::MAX,
                Ok(v) => v.parse().unwrap_or(pqidx::IVF_MIN_DEFAULT),
                Err(_) => pqidx::IVF_MIN_DEFAULT,
            },
            ivf_nprobe: std::env::var("UNDERCROFT_IVF_NPROBE")
                .ok()
                .and_then(|v| v.parse().ok()),
            pq_page_min: match std::env::var("UNDERCROFT_PQ_PAGE_MIN") {
                Ok(v) if v.eq_ignore_ascii_case("off") => usize::MAX,
                Ok(v) => v.parse().unwrap_or(usize::MAX),
                Err(_) => usize::MAX,
            },
            fde_enabled: false,
            fde_encoder: std::cell::RefCell::new(None),
            fde_cache: std::cell::RefCell::new(None),
            fde_checked: std::cell::Cell::new(false),
            fde_pq: std::cell::RefCell::new(None),
            fde_pq_checked: std::cell::Cell::new(false),
            fde_pq_min: match std::env::var("UNDERCROFT_FDE_PQ_MIN") {
                Ok(v) if v.eq_ignore_ascii_case("off") => usize::MAX,
                Ok(v) => v.parse().unwrap_or(fdeidx::FDE_PQ_MIN_DEFAULT),
                Err(_) => fdeidx::FDE_PQ_MIN_DEFAULT,
            },
            fde_ivf: std::cell::RefCell::new(None),
            fde_ivf_checked: std::cell::Cell::new(false),
            // Default OFF: the containment gate measured probed containment
            // below flat's at every fraction (0.96 quarter / 0.993 half at
            // 500k vs flat 1.000) — opting in trades a small tail of exact
            // top-10 members for scan time; the operator makes that call.
            fde_ivf_min: match std::env::var("UNDERCROFT_FDE_IVF_MIN") {
                Ok(v) if v.eq_ignore_ascii_case("off") => usize::MAX,
                Ok(v) => v.parse().unwrap_or(fdeidx::FDE_IVF_MIN_DEFAULT),
                Err(_) => usize::MAX,
            },
            fde_nprobe: std::env::var("UNDERCROFT_FDE_NPROBE")
                .ok()
                .and_then(|v| v.parse().ok()),
            qmatrix_cache: std::cell::RefCell::new(None),
        };
        store.fts = store.init_fts_schema()?;
        store.init_kg_schema()?;
        store.init_manage_schema()?;
        store.init_chain()?;
        Ok(store)
    }

    /// Initialize (or reconcile) the transactional chain head.
    ///
    /// The committed head lives in `chain_meta` and advances **inside the
    /// same SQLite transaction** as the data + audit row it covers, so a
    /// crash can never separate a record from its chain entry. The manifest
    /// keeps a MAC'd copy as an *out-of-database rollback anchor*, written
    /// after each commit — which means a crash between commit and anchor
    /// legitimately leaves the manifest **behind**. Reconciliation:
    ///
    /// * manifest head == database head → nothing to do;
    /// * manifest head appears in the chain the audit rows reproduce
    ///   (strictly behind) → crash artifact → fast-forward the anchor;
    /// * anything else → the database was rolled back or forked relative to
    ///   an anchor it never produced → `ManifestTampered`.
    ///
    /// A power loss is not a tamper alarm; a restored old database still is.
    fn init_chain(&mut self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chain_meta (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );",
        )?;
        let db_head: Option<String> = self
            .conn
            .query_row("SELECT value FROM chain_meta WHERE key = 'head'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let Some(db_head) = db_head else {
            // Legacy adoption (pre-chain_meta database) or a fresh vault:
            // seed from the manifest, which was authoritative until now.
            self.conn.execute(
                "INSERT INTO chain_meta (key, value) VALUES ('head', ?1), ('writes', ?2)",
                params![self.vault.chain_head_hex(), self.vault.writes().to_string()],
            )?;
            return Ok(());
        };
        let anchor = self.vault.chain_head_hex().to_string();
        if anchor == db_head {
            return Ok(());
        }
        // Heads differ: replay the audit rows and decide crash vs rollback.
        let mut stmt = self.conn.prepare("SELECT tag FROM audit ORDER BY seq")?;
        let tags: Vec<Vec<u8>> = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<Result<_, _>>()?;
        drop(stmt);
        let mut head = undercroft_vault::Vault::chain_genesis_hex();
        let mut anchor_seen = head == anchor;
        for tag in &tags {
            head = self.vault.chain_next_hex(&head, tag)?;
            if head == anchor {
                anchor_seen = true;
            }
        }
        if head != db_head {
            // The committed head doesn't match its own audit rows — this is
            // in-database corruption, not an anchoring artifact.
            return Err(StoreError::Integrity("audit-chain head".into()));
        }
        if !anchor_seen {
            return Err(StoreError::Vault(
                undercroft_vault::VaultError::ManifestTampered,
            ));
        }
        // Crash artifact: the anchor is a strict ancestor. Fast-forward it.
        let writes: u64 = self
            .conn
            .query_row(
                "SELECT value FROM chain_meta WHERE key = 'writes'",
                [],
                |r| r.get::<_, String>(0),
            )?
            .parse()
            .unwrap_or(tags.len() as u64);
        self.vault.anchor_manifest(&db_head, writes)?;
        Ok(())
    }

    /// hmac-only vaults keep a plaintext FTS5 index over drawer content as
    /// a BM25 prefilter (triggers keep it coherent through every insert /
    /// content update / delete). Sealed vaults never get one. Returns
    /// whether the index is usable; `false` (e.g. an SQLite build without
    /// the fts5 module) means search falls back to the full scan.
    fn init_fts_schema(&self) -> Result<bool, StoreError> {
        if !matches!(self.vault.level(), SecurityLevel::HmacOnly) {
            return Ok(false);
        }
        // A *standalone* fts5 table over folded text, not external-content
        // over raw `drawers.content`.
        //
        // The external-content form indexed raw bytes under unicode61, which
        // folds Latin diacritics and ς→σ and nothing else. Our query terms are
        // now `search_key`-folded, so the two disagree on ß, ё, Turkish İ and
        // every Arabic mark — and the prefilter is only safe when it finds
        // *nothing*: a non-empty wrong answer becomes `seq IN (...)` and cuts
        // the right drawer out of the scan and out of the cosine path with it.
        // Query `izmir` against a drawer saying `İzmir` was exactly that.
        //
        // Folding the index instead makes unicode61's token set a superset of
        // ours over the same text, so it can over-return (the scan filters
        // that) but never under-return, which was the fatal direction.
        //
        // Note the query-side predicate everyone reaches for is dead code:
        // `needs_full_scan` sees the output of `tokenize`, so every term it
        // gets is already folded and `search_key(t) != t` is identically false.
        if self
            .conn
            .execute_batch("CREATE VIRTUAL TABLE IF NOT EXISTS drawers_fts USING fts5(text);")
            .is_err()
        {
            return Ok(false);
        }
        // Storing folded text in clear leaks nothing new: this table only ever
        // exists for HmacOnly vaults, whose content is already readable.
        // Sealed vaults never reach here.
        let stored: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'fts_key_version'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let n_drawers: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM drawers", [], |r| r.get(0))?;
        let n_fts: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM drawers_fts", [], |r| r.get(0))?;
        // Rebuild when the fold changed (a vault indexed by an older build,
        // including the external-content shape) or when the counts disagree.
        if stored.as_deref() != Some(FTS_KEY_VERSION) || n_fts != n_drawers {
            self.rebuild_fts()?;
        }
        Ok(true)
    }

    /// Drop and repopulate `drawers_fts` from folded content, in one
    /// transaction. Also removes the external-content triggers an older build
    /// installed, which would otherwise keep writing raw text into it.
    fn rebuild_fts(&self) -> Result<(), StoreError> {
        let rows: Vec<(i64, Vec<u8>, String)> = self
            .conn
            .prepare("SELECT seq, content, id FROM drawers ORDER BY seq")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        self.conn.execute_batch(
            "DROP TRIGGER IF EXISTS drawers_fts_ai;
             DROP TRIGGER IF EXISTS drawers_fts_ad;
             DROP TRIGGER IF EXISTS drawers_fts_au;
             DROP TABLE IF EXISTS drawers_fts;
             CREATE VIRTUAL TABLE drawers_fts USING fts5(text);",
        )?;
        {
            let mut ins = self
                .conn
                .prepare("INSERT INTO drawers_fts(rowid, text) VALUES (?1, ?2)")?;
            for (seq, blob, id) in &rows {
                // An unreadable row is skipped, not fatal: the prefilter is an
                // accelerator, and `verify` is what reports damage.
                let Ok(plain) = self.vault.content_from_rest(id, blob) else {
                    continue;
                };
                let Ok(text) = std::str::from_utf8(&plain) else {
                    continue;
                };
                ins.execute(params![seq, &*undercroft_core::normalize::search_key(text)])?;
            }
        }
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('fts_key_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![FTS_KEY_VERSION],
        )?;
        Ok(())
    }

    /// Keep `drawers_fts` in step with a written row.
    ///
    /// Called from the write path rather than a trigger, because the fold is
    /// Rust and SQL cannot express it. Advisory: a failure here costs the
    /// prefilter an entry (the scan still finds the drawer), never the write.
    pub(crate) fn fts_index(&self, id: &str, content: &str) {
        if !self.fts {
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
        let _ = self
            .conn
            .execute("DELETE FROM drawers_fts WHERE rowid = ?1", params![seq]);
        let _ = self.conn.execute(
            "INSERT INTO drawers_fts(rowid, text) VALUES (?1, ?2)",
            params![seq, &*undercroft_core::normalize::search_key(content)],
        );
    }

    /// The `seq` a drawer occupies, for removing its index entry inside the
    /// same transaction that removes the row — dropping it beforehand would
    /// leave the index short of the table if that transaction rolled back,
    /// and under-returning is the one direction the prefilter must never do.
    pub(crate) fn fts_seq_of(&self, id: &str) -> Option<i64> {
        if !self.fts {
            return None;
        }
        self.conn
            .query_row("SELECT seq FROM drawers WHERE id = ?1", params![id], |r| {
                r.get(0)
            })
            .optional()
            .ok()
            .flatten()
    }

    /// Tune when the BM25 prefilter engages on hmac-only vaults: it runs
    /// once the palace holds at least `min` drawers; `None` disables it
    /// entirely. Also settable at open via `UNDERCROFT_FTS_PREFILTER_MIN`
    /// (a number, or `off`).
    pub fn set_fts_prefilter_min(&mut self, min: Option<usize>) {
        self.fts_min = min;
    }

    /// Select the rank-time fusion strategy. Defaults to the value of
    /// `UNDERCROFT_FUSION` at open (`legacy` / `bm25` / `rrf`, legacy
    /// otherwise). See [`Fusion`].
    pub fn set_fusion(&mut self, fusion: Fusion) {
        self.fusion = fusion;
    }

    /// Attach (or clear) a second-stage cross-encoder reranker. With one set,
    /// `search` re-scores the fusion-ranked top-N candidates by the full
    /// `(query, content)` pair before the final `limit` cut. Idempotent and
    /// additive — leaving it unset preserves first-pass ranking exactly.
    pub fn set_reranker(&mut self, reranker: Option<Box<dyn Reranker + Send + Sync>>) {
        self.reranker = reranker;
    }

    /// Enable (or disable) the local in-memory HNSW ANN prefilter. When on,
    /// search cuts candidates to the vector top-K via an O(log n) graph walk
    /// instead of the O(n) full cosine scan. The index is built lazily on the
    /// first search, held in RAM only, and rebuilt after any write. Requires
    /// the `hnsw` build feature; a no-op flag otherwise (falls back to scan).
    pub fn set_hnsw(&mut self, on: bool) {
        self.hnsw_enabled = on;
    }

    /// Vector top-`k` candidate `seq`s via the HNSW index, building it lazily
    /// from the (decrypted) corpus on first use. `None` ⇒ empty corpus, so the
    /// caller falls back to a full scan (which also yields nothing).
    #[cfg(feature = "hnsw")]
    fn hnsw_candidates(&self, qvec: &[f32], k: usize) -> Result<Option<Vec<i64>>, StoreError> {
        if self.hnsw.borrow().is_none() {
            let mut stmt = self
                .conn
                .prepare("SELECT seq, id, embedding FROM drawers")?;
            let rows: Vec<(i64, String, Vec<u8>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?;
            if rows.is_empty() {
                return Ok(None);
            }
            let mut items = Vec::with_capacity(rows.len());
            for (seq, id, emb_rest) in rows {
                let emb = self
                    .vault
                    .embedding_from_rest(&id, &emb_rest)
                    .map_err(|e| StoreError::CorruptRow {
                        id: id.clone(),
                        reason: e.to_string(),
                    })?;
                items.push((seq, emb));
            }
            *self.hnsw.borrow_mut() = Some(hnsw::HnswIndex::build(items));
        }
        Ok(Some(self.hnsw.borrow().as_ref().unwrap().query(qvec, k)))
    }

    /// Decrypt every drawer embedding into an in-memory map so subsequent
    /// searches skip per-row AEAD work. Kept coherent by `upsert` /
    /// `delete_drawer`. Returns the number of cached vectors.
    pub fn warm_embedding_cache(&self) -> Result<usize, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id, embedding FROM drawers")?;
        let rows: Vec<(String, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut map = std::collections::HashMap::with_capacity(rows.len());
        for (id, emb_rest) in rows {
            let emb = self
                .vault
                .embedding_from_rest(&id, &emb_rest)
                .map_err(|e| StoreError::CorruptRow {
                    id: id.clone(),
                    reason: e.to_string(),
                })?;
            map.insert(id, emb);
        }
        let n = map.len();
        *self.emb_cache.borrow_mut() = Some(map);
        Ok(n)
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Whether this vault seals content at rest. Used to suppress wing/room
    /// names in live telemetry events for sealed vaults.
    fn is_sealed(&self) -> bool {
        matches!(self.vault.level(), SecurityLevel::Sealed)
    }

    pub fn count(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM drawers", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// An index no drawer in this vault has ever been given.
    ///
    /// For callers that need a unique *slot* rather than a chunk's position
    /// within a source: a note saved through an API has no source to be the
    /// fourth chunk of, but its id still has to be unique, and `chunk_index`
    /// is the only field left to carry that.
    ///
    /// [`count`](Self::count) cannot serve, and the difference is a data-loss
    /// bug rather than a nicety. `COUNT(*)` goes *down* when a drawer is
    /// deleted, so the next save is handed an index that is still in use, the
    /// derived id collides, and `ON CONFLICT(id) DO UPDATE` overwrites the
    /// unrelated drawer holding it — a record destroyed by writing a
    /// different one. SQLite's `AUTOINCREMENT` sequence never reuses a rowid,
    /// so it only ever moves forward.
    ///
    /// Identical to `count()` for any vault that has never deleted, so
    /// existing ids are unaffected.
    pub fn next_append_index(&self) -> Result<u64, StoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'drawers'), 0)",
            [],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    /// Whether this vault stores caller-supplied embeddings
    /// (`external:<name>@<dim>` identity). Such vaults reject
    /// [`upsert`](Self::upsert) — use [`upsert_external`](Self::upsert_external).
    pub fn is_external(&self) -> bool {
        self.external_dim.is_some()
    }

    /// Read a vault's recorded embedder identity `(name, dim)` without
    /// opening a full store — lets a caller (e.g. the multi-tenant server)
    /// pick the right embedder before opening. `None` if nothing is
    /// recorded yet (a fresh, never-written vault).
    pub fn recorded_embedder(vault: &Vault) -> Result<Option<(String, usize)>, StoreError> {
        let conn = Connection::open(vault.db_path())?;
        let name: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'embedder_name'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        let dim: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'embedder_dim'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        Ok(match (name, dim) {
            (Some(n), Some(d)) => Some((n, d.parse().unwrap_or(0))),
            _ => None,
        })
    }

    /// Insert or replace a drawer, computing its embedding with the vault's
    /// embedder. Returns `true` if the id was new. Refused on external
    /// vaults, which must supply a vector via
    /// [`upsert_external`](Self::upsert_external).
    pub fn upsert(&mut self, drawer: &Drawer) -> Result<bool, StoreError> {
        let _span = undercroft_obs::scope("save", self.vault.id());
        if self.external_dim.is_some() {
            return Err(StoreError::ExternalVault);
        }
        let embedding = self.embedder.embed(&drawer.content);
        let created = self.write_drawer(drawer, embedding)?;
        undercroft_obs::drawer_write(undercroft_obs::WriteOutcome::Created);
        undercroft_obs::event_drawer_saved(
            self.vault.id(),
            &drawer.meta.wing,
            &drawer.meta.room,
            false,
            self.is_sealed(),
        );
        Ok(created)
    }

    /// Insert or replace a drawer on an external-embedding vault using the
    /// caller-supplied `vector`, which must match the recorded dimension
    /// exactly. Returns `true` if the id was new. Errors on a non-external
    /// vault or a dimension mismatch.
    pub fn upsert_external(
        &mut self,
        drawer: &Drawer,
        vector: Vec<f32>,
    ) -> Result<bool, StoreError> {
        let _span = undercroft_obs::scope("save", self.vault.id());
        match self.external_dim {
            None => Err(StoreError::NotExternalVault),
            Some(dim) if vector.len() != dim => Err(StoreError::EmbeddingDim {
                expected: dim,
                got: vector.len(),
            }),
            Some(_) => {
                let created = self.write_drawer(drawer, vector)?;
                undercroft_obs::drawer_write(undercroft_obs::WriteOutcome::Created);
                undercroft_obs::event_drawer_saved(
                    self.vault.id(),
                    &drawer.meta.wing,
                    &drawer.meta.room,
                    false,
                    self.is_sealed(),
                );
                Ok(created)
            }
        }
    }

    /// Seal + tag + persist a drawer with an already-computed `embedding`,
    /// advancing the audit chain and keeping the warm cache coherent. The
    /// embedding source (local embedder or caller-supplied) is the caller's
    /// concern; the at-rest sealing and integrity handling are identical.
    fn write_drawer(&mut self, drawer: &Drawer, embedding: Vec<f32>) -> Result<bool, StoreError> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let (is_new, head, writes) = match self.write_drawer_stmts(drawer, &embedding) {
            Ok(v) => v,
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        };
        if let Err(e) = self.conn.execute_batch("COMMIT") {
            let _ = self.conn.execute_batch("ROLLBACK");
            return Err(e.into());
        }
        self.vault.anchor_manifest(&head, writes)?;
        self.post_write(drawer, embedding, is_new);
        Ok(is_new)
    }

    /// The row + audit-chain statements of one drawer write, executed on
    /// the connection's **current transaction** (the caller owns
    /// BEGIN/COMMIT). Returns `(is_new, chain_head, writes)` for the
    /// caller to anchor after its commit.
    fn write_drawer_stmts(
        &mut self,
        drawer: &Drawer,
        embedding: &[f32],
    ) -> Result<(bool, String, u64), StoreError> {
        // meta_json is stored unsealed, so it must not carry words copied out
        // of the content — the date expressions and names that derivation
        // lifts verbatim. `meta_at_rest` empties exactly those and keeps the
        // resolutions, which are offsets and ISO dates rather than content.
        // The tag below covers what is actually written, so verify stays
        // consistent with storage.
        let meta_json =
            serde_json::to_string(&drawer.meta_at_rest()).map_err(|e| StoreError::CorruptRow {
                id: drawer.id.clone(),
                reason: e.to_string(),
            })?;
        let content_rest = self
            .vault
            .content_at_rest(&drawer.id, drawer.content.as_bytes());
        let emb_rest = self.vault.embedding_at_rest(&drawer.id, embedding);
        let tag = self
            .vault
            .tag(&canonical(&drawer.id, meta_json.as_bytes(), &content_rest));
        let fp = self.fingerprint(&drawer.content);
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("rfc3339 now");

        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT seq FROM drawers WHERE id = ?1",
                params![drawer.id],
                |r| r.get(0),
            )
            .optional()?;
        self.conn.execute(
            "INSERT INTO drawers (id, wing, room, meta_json, content, embedding, tag, fp, filed_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT(id) DO UPDATE SET
                 wing = excluded.wing,
                 room = excluded.room,
                 meta_json = excluded.meta_json,
                 content = excluded.content,
                 embedding = excluded.embedding,
                 tag = excluded.tag,
                 fp = excluded.fp,
                 updated_at = excluded.updated_at",
            params![
                drawer.id,
                drawer.meta.wing,
                drawer.meta.room,
                meta_json,
                content_rest,
                emb_rest,
                tag.as_slice(),
                fp,
                now,
            ],
        )?;
        let (head, writes) = chain_append(&self.conn, &self.vault, &drawer.id, &tag, &now)?;
        Ok((existing.is_none(), head, writes))
    }

    /// Post-commit bookkeeping for one written drawer: derived indexes and
    /// RAM caches. In a batch these statements join the caller's open
    /// transaction instead of each paying their own WAL sync.
    fn post_write(&mut self, drawer: &Drawer, embedding: Vec<f32>, is_new: bool) {
        // Keep the on-disk PQ codes coherent (advisory; self-heals on search).
        self.pq_encode_row(&drawer.id, &embedding, is_new);
        // Store the late-interaction token matrix (advisory; a drawer
        // without one keeps its fusion rank at rescore time).
        self.late_encode_row(&drawer.id, &drawer.content);
        // And the folded FTS entry (hmac-only vaults; a no-op otherwise).
        self.fts_index(&drawer.id, &drawer.content);
        if let Some(cache) = self.emb_cache.borrow_mut().as_mut() {
            cache.insert(drawer.id.clone(), embedding);
        }
        // The ANN index is now stale; drop it so the next search rebuilds.
        #[cfg(feature = "hnsw")]
        self.hnsw.borrow_mut().take();
    }

    /// Insert or replace a batch of drawers in **one transaction**: rows,
    /// audit-chain advances, and derived-index writes all commit together
    /// with a single WAL sync, and the manifest anchors once at the end —
    /// under `synchronous=FULL` this is the difference between several disk
    /// syncs per drawer and one per batch. A mid-batch failure rolls the
    /// whole batch back (the existing palace is untouched — the append-only
    /// crash invariant), and the anchor never runs ahead because it is
    /// written only after the commit it describes. Returns how many ids
    /// were new. Refused on external vaults.
    pub fn upsert_many(&mut self, drawers: &[Drawer]) -> Result<usize, StoreError> {
        if self.external_dim.is_some() {
            return Err(StoreError::ExternalVault);
        }
        if drawers.is_empty() {
            return Ok(0);
        }
        let _span = undercroft_obs::scope("save", self.vault.id());
        // Embedding is CPU work — do it before taking the write lock.
        let embeddings: Vec<Vec<f32>> = drawers
            .iter()
            .map(|d| self.embedder.embed(&d.content))
            .collect();
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let mut created = 0usize;
        let mut anchor: Option<(String, u64)> = None;
        for (drawer, embedding) in drawers.iter().zip(embeddings) {
            let (is_new, head, writes) = match self.write_drawer_stmts(drawer, &embedding) {
                Ok(v) => v,
                Err(e) => {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
            };
            if is_new {
                created += 1;
            }
            anchor = Some((head, writes));
            self.post_write(drawer, embedding, is_new);
        }
        if let Err(e) = self.conn.execute_batch("COMMIT") {
            let _ = self.conn.execute_batch("ROLLBACK");
            return Err(e.into());
        }
        if let Some((head, writes)) = anchor {
            self.vault.anchor_manifest(&head, writes)?;
        }
        // Page-tier batch boundary: fold the tail rows this batch wrote
        // into their lists' pages — one reseal per touched list per batch,
        // the write-amplification bound the format was designed around.
        // Runs after COMMIT (it manages its own writes); advisory.
        if self.pq_enabled && self.is_sealed() {
            match self.pq_pages_present() {
                Ok(true) => {
                    if self.pq_compact_tail().is_err() {
                        self.pq_verified.set(false);
                    }
                }
                Ok(false) => {}
                Err(_) => {}
            }
        }
        for drawer in drawers {
            undercroft_obs::drawer_write(undercroft_obs::WriteOutcome::Created);
            undercroft_obs::event_drawer_saved(
                self.vault.id(),
                &drawer.meta.wing,
                &drawer.meta.room,
                false,
                self.is_sealed(),
            );
        }
        Ok(created)
    }

    /// Save a drawer, collapsing near-duplicates. If some existing drawer
    /// in the SAME wing+room has embedding cosine `>= threshold` against the
    /// incoming one, that drawer is refreshed in place — its text, metadata,
    /// and recency updated while its id is kept — and the outcome reports
    /// `deduped`. Otherwise it is a normal insert/update. Makes re-ingesting
    /// an updated corpus idempotent: unchanged facts refresh instead of
    /// piling up as near-copies. The refresh is an ordinary audited update
    /// (re-tagged, chain advanced), never a silent overwrite. Refused on
    /// external vaults — use [`save_with_dedup_vec`](Self::save_with_dedup_vec).
    pub fn save_with_dedup(
        &mut self,
        drawer: &Drawer,
        threshold: f32,
    ) -> Result<SaveOutcome, StoreError> {
        if self.external_dim.is_some() {
            return Err(StoreError::ExternalVault);
        }
        let embedding = self.embedder.embed(&drawer.content);
        self.save_with_dedup_vec(drawer, embedding, threshold)
    }

    /// [`save_with_dedup`](Self::save_with_dedup) with a caller-supplied
    /// embedding — the external-vault path (dimension-checked there).
    pub fn save_with_dedup_vec(
        &mut self,
        drawer: &Drawer,
        embedding: Vec<f32>,
        threshold: f32,
    ) -> Result<SaveOutcome, StoreError> {
        let _span = undercroft_obs::scope("save", self.vault.id());
        if let Some(dim) = self.external_dim {
            if embedding.len() != dim {
                return Err(StoreError::EmbeddingDim {
                    expected: dim,
                    got: embedding.len(),
                });
            }
        }
        // Scan the same wing+room for the closest existing drawer. Scope
        // the statement so its borrow of `self.conn` is released before the
        // `&mut self` write below.
        let rows: Vec<(String, Vec<u8>)> = {
            let mut stmt = self
                .conn
                .prepare("SELECT id, embedding FROM drawers WHERE wing = ?1 AND room = ?2")?;
            let rows = stmt
                .query_map(params![drawer.meta.wing, drawer.meta.room], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?
                .collect::<Result<_, _>>()?;
            rows
        };
        let mut best: Option<(String, f32)> = None;
        for (id, emb_rest) in rows {
            let emb = self
                .vault
                .embedding_from_rest(&id, &emb_rest)
                .map_err(|e| StoreError::CorruptRow {
                    id: id.clone(),
                    reason: e.to_string(),
                })?;
            let sim = cosine(&embedding, &emb);
            if sim >= threshold && best.as_ref().map(|(_, s)| sim > *s).unwrap_or(true) {
                best = Some((id, sim));
            }
        }

        if let Some((match_id, _)) = best {
            // Refresh the matched drawer in place: keep its id, take the
            // incoming content/metadata and a fresh recency.
            let mut refreshed = Drawer {
                id: match_id.clone(),
                content: drawer.content.clone(),
                meta: drawer.meta.clone(),
            };
            // Taking the incoming metadata wholesale used to discard the
            // matched drawer's dates with it: the same text recorded on an
            // earlier day simply stopped having happened. The text collapses,
            // the chronology does not.
            if let Some(existing) = self.get(&match_id)? {
                refreshed.absorb_occurrences_of(&existing);
            }
            self.write_drawer(&refreshed, embedding)?;
            undercroft_obs::drawer_write(undercroft_obs::WriteOutcome::Deduped);
            undercroft_obs::event_drawer_saved(
                self.vault.id(),
                &drawer.meta.wing,
                &drawer.meta.room,
                true,
                self.is_sealed(),
            );
            Ok(SaveOutcome {
                id: match_id,
                created: false,
                deduped: true,
            })
        } else {
            let created = self.write_drawer(drawer, embedding)?;
            undercroft_obs::drawer_write(undercroft_obs::WriteOutcome::Created);
            undercroft_obs::event_drawer_saved(
                self.vault.id(),
                &drawer.meta.wing,
                &drawer.meta.room,
                false,
                self.is_sealed(),
            );
            Ok(SaveOutcome {
                id: drawer.id.clone(),
                created,
                deduped: false,
            })
        }
    }

    /// Decrypted export of every drawer together with its embedding vector,
    /// for lossless migration (verified import elsewhere, then drop the
    /// source). Ordered by insertion. Unlike [`export_all`](Self::export_all)
    /// this carries the vector so an external-embedding vault round-trips
    /// without a model.
    pub fn export_all_with_vectors(&self) -> Result<Vec<(Drawer, Vec<f32>)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, meta_json, content, embedding, tag FROM drawers ORDER BY seq")?;
        let rows: Vec<SearchRow> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, meta_json, content_rest, emb_rest, tag) in rows {
            self.vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .map_err(|_| {
                    undercroft_obs::hmac_verify_failed("drawer");
                    undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                    StoreError::Integrity(id.clone())
                })?;
            let drawer = self.decode(&id, &meta_json, &content_rest)?;
            let emb = self
                .vault
                .embedding_from_rest(&id, &emb_rest)
                .map_err(|e| StoreError::CorruptRow {
                    id: id.clone(),
                    reason: e.to_string(),
                })?;
            out.push((drawer, emb));
        }
        Ok(out)
    }

    /// Import one drawer, the inverse of a migration export. On an external
    /// vault a `vector` is required (dimension-checked). On a normal vault a
    /// matching-dimension `vector` is preserved verbatim; otherwise the
    /// drawer is re-embedded with the vault's own embedder. Returns whether
    /// the id was new.
    pub fn import_record(
        &mut self,
        drawer: &Drawer,
        vector: Option<Vec<f32>>,
    ) -> Result<bool, StoreError> {
        match self.external_dim {
            Some(dim) => {
                let v = vector.ok_or(StoreError::ExternalVault)?;
                if v.len() != dim {
                    return Err(StoreError::EmbeddingDim {
                        expected: dim,
                        got: v.len(),
                    });
                }
                self.write_drawer(drawer, v)
            }
            None => match vector {
                Some(v) if v.len() == self.embedder.dimension() => self.write_drawer(drawer, v),
                _ => self.upsert(drawer),
            },
        }
    }

    /// Fetch one drawer by id, verifying its HMAC and decrypting content.
    pub fn get(&self, id: &str) -> Result<Option<Drawer>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, meta_json, content, tag FROM drawers WHERE id = ?1",
                params![id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((id, meta_json, content_rest, tag)) => {
                self.vault
                    .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                    .map_err(|_| {
                        undercroft_obs::hmac_verify_failed("drawer");
                        undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                        StoreError::Integrity(id.clone())
                    })?;
                Ok(Some(self.decode(&id, &meta_json, &content_rest)?))
            }
        }
    }

    fn decode(&self, id: &str, meta_json: &str, content_rest: &[u8]) -> Result<Drawer, StoreError> {
        let meta: DrawerMeta =
            serde_json::from_str(meta_json).map_err(|e| StoreError::CorruptRow {
                id: id.into(),
                reason: e.to_string(),
            })?;
        let plain = self
            .vault
            .content_from_rest(id, content_rest)
            .map_err(|e| StoreError::CorruptRow {
                id: id.into(),
                reason: e.to_string(),
            })?;
        let content = String::from_utf8(plain).map_err(|e| StoreError::CorruptRow {
            id: id.into(),
            reason: e.to_string(),
        })?;
        Ok(Drawer {
            id: id.to_string(),
            content,
            meta,
        })
    }

    /// Most recently filed drawers (optionally scoped to a wing) — the
    /// palace's "essential story" feed used by wake-up.
    pub fn recent(&self, wing: Option<&str>, limit: usize) -> Result<Vec<Drawer>, StoreError> {
        let mut sql = String::from("SELECT id, meta_json, content, tag FROM drawers");
        if wing.is_some() {
            sql.push_str(" WHERE wing = ?1");
        }
        sql.push_str(" ORDER BY updated_at DESC, seq DESC LIMIT ");
        sql.push_str(&limit.to_string());
        let mut stmt = self.conn.prepare(&sql)?;
        let map = |r: &rusqlite::Row<'_>| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        };
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = match wing {
            Some(w) => stmt.query_map(params![w], map)?.collect::<Result<_, _>>()?,
            None => stmt.query_map([], map)?.collect::<Result<_, _>>()?,
        };
        let mut out = Vec::with_capacity(rows.len());
        for (id, meta_json, content_rest, tag) in rows {
            self.vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .map_err(|_| {
                    undercroft_obs::hmac_verify_failed("drawer");
                    undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                    StoreError::Integrity(id.clone())
                })?;
            out.push(self.decode(&id, &meta_json, &content_rest)?);
        }
        Ok(out)
    }

    /// Hybrid search: hashed-embedding cosine + lexical term overlap +
    /// recency decay. Sealed vaults decrypt-scan; nothing derived from
    /// plaintext is read from disk indexes. hmac-only vaults above the
    /// prefilter threshold first cut candidates to the FTS5 BM25 top-K
    /// (final scoring is unchanged — the index only narrows the scan).
    pub fn search(&self, query: &str, opts: &SearchOptions) -> Result<Vec<SearchHit>, StoreError> {
        if self.external_dim.is_some() {
            return Err(StoreError::ExternalVault);
        }
        let qvec = self.embedder.embed(query);
        self.search_inner(query, qvec, opts)
    }

    /// Search an external-embedding vault with a caller-supplied query
    /// vector (same embedding space as the stored drawers); `query` still
    /// drives the lexical/BM25 half. The vector must match the recorded
    /// dimension. Errors on a non-external vault or a dimension mismatch.
    pub fn search_with_vector(
        &self,
        query: &str,
        qvec: Vec<f32>,
        opts: &SearchOptions,
    ) -> Result<Vec<SearchHit>, StoreError> {
        match self.external_dim {
            None => Err(StoreError::NotExternalVault),
            Some(dim) if qvec.len() != dim => Err(StoreError::EmbeddingDim {
                expected: dim,
                got: qvec.len(),
            }),
            Some(_) => self.search_inner(query, qvec, opts),
        }
    }

    fn search_inner(
        &self,
        query: &str,
        qvec: Vec<f32>,
        opts: &SearchOptions,
    ) -> Result<Vec<SearchHit>, StoreError> {
        let _span = undercroft_obs::scope("search", self.vault.id());
        let obs_start = std::time::Instant::now();
        let limit = if opts.limit == 0 { 10 } else { opts.limit };
        let qterms: Vec<String> = tokenize(query);

        let candidates = if self.fde_enabled {
            // MUVERA FDE candidates: token-aware single-vector ranking over
            // the load-once FDE cache (falls back to the fusion scan when no
            // late encoder / no FDE rows exist). Over-fetch generously so
            // BM25 fusion still has material.
            self.fde_candidates(query, std::cmp::max(256, limit * 32))?
        } else if self.pq_enabled {
            // On-disk PQ prefilter: ADC over the RAM code cache, bounded at
            // any corpus size. Over-fetch generously so BM25 fusion still
            // has material.
            self.pq_candidates(&qvec, std::cmp::max(256, limit * 32))?
        } else if self.hnsw_enabled {
            // Semantic ANN prefilter: cut to the vector top-K before verify +
            // fusion. Over-fetch generously so BM25 fusion still has material.
            #[cfg(feature = "hnsw")]
            {
                self.hnsw_candidates(&qvec, std::cmp::max(256, limit * 32))?
            }
            #[cfg(not(feature = "hnsw"))]
            {
                None
            }
        } else {
            match self.fts_min {
                Some(min)
                    if self.fts
                        && !qterms.is_empty()
                        && !needs_full_scan(&qterms)
                        && self.count()? >= min as u64 =>
                {
                    self.fts_candidates(&qterms, std::cmp::max(256, limit * 32))
                }
                _ => None,
            }
        };
        let obs_prefiltered = candidates.is_some();

        let mut sql = String::from("SELECT id, meta_json, content, embedding, tag FROM drawers");
        let mut clauses: Vec<String> = Vec::new();
        let mut binds: Vec<String> = Vec::new();
        if let Some(seqs) = &candidates {
            let list: Vec<String> = seqs.iter().map(i64::to_string).collect();
            clauses.push(format!("seq IN ({})", list.join(",")));
        }
        if let Some(w) = &opts.wing {
            binds.push(w.clone());
            clauses.push(format!("wing = ?{}", binds.len()));
        }
        if let Some(r) = &opts.room {
            binds.push(r.clone());
            clauses.push(format!("room = ?{}", binds.len()));
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: Vec<SearchRow> = stmt
            .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;

        // Pass 1: verify + decrypt every candidate, and gather the signals
        // that don't need corpus statistics (cosine, recency). Content
        // tokens are kept only when a BM25-based fusion needs them.
        let now = OffsetDateTime::now_utc();
        let mut cands: Vec<Candidate> = Vec::with_capacity(rows.len());
        for (id, meta_json, content_rest, emb_rest, tag) in rows {
            self.vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .map_err(|_| {
                    undercroft_obs::hmac_verify_failed("drawer");
                    undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                    StoreError::Integrity(id.clone())
                })?;
            let drawer = self.decode(&id, &meta_json, &content_rest)?;
            let cached = self
                .emb_cache
                .borrow()
                .as_ref()
                .and_then(|c| c.get(&id).cloned());
            let emb = match cached {
                Some(e) => e,
                None => self
                    .vault
                    .embedding_from_rest(&id, &emb_rest)
                    .map_err(|e| StoreError::CorruptRow {
                        id: id.clone(),
                        reason: e.to_string(),
                    })?,
            };
            let semantic = ((cosine(&qvec, &emb) + 1.0) / 2.0).clamp(0.0, 1.0);
            let recency = recency_boost(&drawer.meta.filed_at, now);
            let (tokens, ngram, units) = if self.fusion == Fusion::Legacy {
                (Vec::new(), Vec::new(), 0.0)
            } else {
                let s = segment(&drawer.content);
                let units = s.len as f32;
                // Same minimum-length rule the query side applies, so term
                // matching stays symmetric rather than relying on a one-byte
                // token happening never to match anything. The n-gram flags
                // are filtered in step with the tokens they describe.
                let (tokens, ngram): (Vec<String>, Vec<bool>) = s
                    .tokens
                    .into_iter()
                    .zip(s.ngram)
                    .filter(|(t, _)| t.len() > 1)
                    .unzip();
                (tokens, ngram, units)
            };
            cands.push(Candidate {
                drawer,
                semantic,
                recency,
                tokens,
                ngram,
                units,
            });
        }

        // Pass 2: derive the lexical signal (per fusion mode) and combine.
        let mut hits = match self.fusion {
            Fusion::Legacy => cands
                .into_iter()
                .map(|c| {
                    let (lexical, lexical_exact) = lexical_score(&qterms, query, &c.drawer.content);
                    let score = 0.55 * c.semantic + 0.35 * lexical + 0.10 * c.recency;
                    SearchHit {
                        drawer: c.drawer,
                        score,
                        semantic: c.semantic,
                        lexical,
                        lexical_exact,
                        // `lexical_score`'s exact leg is unrestricted substring
                        // containment, so on this path the relation the morph
                        // channel carries elsewhere is already counted as exact.
                        // Left at zero rather than double-counted.
                        lexical_morph: 0.0,
                    }
                })
                .collect::<Vec<_>>(),
            Fusion::Bm25 => {
                let bm25 = bm25_scores(&qterms, &cands);
                cands
                    .into_iter()
                    .zip(bm25)
                    .map(|(c, (lexical, lexical_exact, lexical_morph))| {
                        let score = 0.55 * c.semantic + 0.35 * lexical + 0.10 * c.recency;
                        SearchHit {
                            drawer: c.drawer,
                            score,
                            semantic: c.semantic,
                            lexical,
                            lexical_exact,
                            lexical_morph,
                        }
                    })
                    .collect::<Vec<_>>()
            }
            Fusion::Rrf => rrf_fuse(&qterms, cands),
        };

        // Relevance gate: an unrelated record still scores ~0.35 from the
        // neutral cosine midpoint + recency alone. Require actual evidence —
        // the drawer literally contains a query term, or the cosine is
        // clearly positive.
        //
        // Deliberately the *exact* channel. Approximate evidence — a fold
        // that made two spellings one token, a forgiven edit, a shared word
        // family — is a guess, and a guess should reorder a result set rather
        // than populate one. Gating on the blended channel would mean every
        // fold widens admission, which is how `قطار` came to match
        // `المستشفى` on a shared alef.
        hits.retain(|h| {
            h.lexical_exact > 0.0 || h.lexical_morph > 0.0 || h.semantic > SEMANTIC_ADMISSION_GATE
        });
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Optional second stage: a cross-encoder re-scores the top-N
        // fusion-ranked candidates using the full (query, content) pair — the
        // interaction a bi-encoder can't capture — then we re-sort. `score` is
        // overwritten with the reranker score; `semantic`/`lexical` are kept
        // for transparency. Bounded to `rerank_top_n()` forward passes.
        if let Some(reranker) = &self.reranker {
            // Rerank only the top `top_n` fusion candidates — a true latency
            // cap, since each candidate costs one cross-encoder forward pass.
            // Candidates below `top_n` keep their fusion rank, so a small
            // `top_n` never drops results, it only leaves the tail unreranked.
            // `score_batch` is the whole-pool interface: each backend
            // parallelizes it as it best can (the tract backend fans the
            // independent passes across cores with rayon; an ORT backend runs
            // one batched forward). 16.6s → ~0.7s measured with tract on 24
            // cores at top_n=20.
            let pool = hits.len().min(rerank_top_n());
            let passages: Vec<&str> = hits[..pool]
                .iter()
                .map(|h| h.drawer.content.as_str())
                .collect();
            let scores = reranker.score_batch(query, &passages);
            for (h, s) in hits[..pool].iter_mut().zip(scores) {
                h.score = s;
            }
            hits[..pool].sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        } else {
            // Late-interaction alternative: MaxSim over ingest-time token
            // matrices, one query-encode forward total (no-op when unset).
            self.late_rescore(query, &mut hits);
        }
        match opts.room_cap {
            Some(cap) if cap > 0 && hits.len() > limit => {
                hits = diversify_by_room(std::mem::take(&mut hits), limit, cap)
            }
            _ => hits.truncate(limit),
        }

        let fusion_label = match self.fusion {
            Fusion::Legacy => "legacy",
            Fusion::Bm25 => "bm25",
            Fusion::Rrf => "rrf",
        };
        undercroft_obs::search_completed(
            obs_start.elapsed(),
            hits.len(),
            fusion_label,
            obs_prefiltered,
        );
        undercroft_obs::event_search(
            self.vault.id(),
            opts.wing.as_deref(),
            opts.room.as_deref(),
            hits.len(),
            self.is_sealed(),
        );
        Ok(hits)
    }

    /// BM25 top-`k` candidate seqs from the FTS5 index. `None` means "no
    /// usable cut" — nothing matched, or the query produced no tokens —
    /// and the caller falls back to the full scan, which preserves
    /// semantic-only recall when the query shares no term with any drawer.
    fn fts_candidates(&self, qterms: &[String], k: usize) -> Option<Vec<i64>> {
        let mut parts: Vec<String> = Vec::with_capacity(qterms.len() * 2);
        for t in qterms {
            parts.push(format!("\"{t}\""));
            // The scorer tolerates one typo in terms of 5+ chars; a 4-char
            // prefix match keeps most such variants in the candidate pool.
            if t.chars().count() >= 5 {
                let prefix: String = t.chars().take(4).collect();
                parts.push(format!("\"{prefix}\"*"));
            }
        }
        if parts.is_empty() {
            return None;
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT rowid FROM drawers_fts WHERE drawers_fts MATCH ?1
                 ORDER BY rank LIMIT ?2",
            )
            .ok()?;
        let seqs: Vec<i64> = stmt
            .query_map(params![parts.join(" OR "), k as i64], |r| r.get(0))
            .ok()?
            .collect::<Result<_, _>>()
            .ok()?;
        if seqs.is_empty() {
            None
        } else {
            Some(seqs)
        }
    }

    /// Score one already-decrypted drawer against a query (used by the
    /// remote-index path, where the embedding is recomputed locally from
    /// the verified plaintext rather than trusted from the server).
    pub(crate) fn score_drawer(
        &self,
        drawer: undercroft_core::Drawer,
        query: &str,
        qvec: &[f32],
    ) -> SearchHit {
        let qterms: Vec<String> = tokenize(query);
        let emb = self.embedder.embed(&drawer.content);
        let semantic = ((cosine(qvec, &emb) + 1.0) / 2.0).clamp(0.0, 1.0);
        let (lexical, lexical_exact) = lexical_score(&qterms, query, &drawer.content);
        let recency = recency_boost(&drawer.meta.filed_at, OffsetDateTime::now_utc());
        let score = 0.55 * semantic + 0.35 * lexical + 0.10 * recency;
        SearchHit {
            drawer,
            score,
            semantic,
            lexical,
            lexical_exact,
            lexical_morph: 0.0,
        }
    }

    /// Walk every record verifying its HMAC, then replay the audit chain
    /// against the manifest head.
    pub fn verify(&self) -> Result<VerifyReport, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, meta_json, content, tag FROM drawers ORDER BY seq")?;
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        let mut bad = Vec::new();
        let mut checked = 0u64;
        for (id, meta_json, content_rest, tag) in rows {
            checked += 1;
            if self
                .vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .is_err()
            {
                bad.push(id);
            }
        }
        // Knowledge-graph and tunnel rows are integrity-tagged too.
        checked += self.kg_count()?;
        bad.extend(self.kg_verify()?);
        checked += self.tunnel_count()?;
        bad.extend(self.tunnels_verify()?);
        let mut stmt = self.conn.prepare("SELECT tag FROM audit ORDER BY seq")?;
        let tags: Vec<Vec<u8>> = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<Result<_, _>>()?;
        drop(stmt);
        // Two-part chain check. (1) The audit rows must reproduce exactly
        // the committed head in chain_meta — they advanced in the same
        // transactions, so any mismatch is corruption, not timing. (2) The
        // manifest anchor must appear somewhere in that chain: equal in
        // steady state, strictly behind after a crash-before-anchor (legal),
        // and absent only when the database was rolled back or forked
        // relative to an anchor it never produced.
        let anchor = self.vault.chain_head_hex().to_string();
        let mut head = Vault::chain_genesis_hex();
        let mut anchor_seen = head == anchor;
        for tag in &tags {
            head = self.vault.chain_next_hex(&head, tag)?;
            if head == anchor {
                anchor_seen = true;
            }
        }
        let db_head: Option<String> = self
            .conn
            .query_row("SELECT value FROM chain_meta WHERE key = 'head'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let chain_ok = db_head.as_deref() == Some(head.as_str()) && anchor_seen;
        Ok(VerifyReport {
            records_checked: checked,
            bad_records: bad,
            chain_ok,
        })
    }

    /// Decrypted export of every drawer (for backup / migration).
    pub fn export_all(&self) -> Result<Vec<Drawer>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, meta_json, content, tag FROM drawers ORDER BY seq")?;
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, meta_json, content_rest, tag) in rows {
            self.vault
                .verify_tag(&canonical(&id, meta_json.as_bytes(), &content_rest), &tag)
                .map_err(|_| {
                    undercroft_obs::hmac_verify_failed("drawer");
                    undercroft_obs::event_hmac_fail(self.vault.id(), "drawer");
                    StoreError::Integrity(id.clone())
                })?;
            out.push(self.decode(&id, &meta_json, &content_rest)?);
        }
        Ok(out)
    }

    /// Distinct wings and per-wing drawer counts.
    pub fn wings(&self) -> Result<Vec<(String, u64)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT wing, COUNT(*) FROM drawers GROUP BY wing ORDER BY wing")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }
}

/// One verified, decrypted candidate carried between search's two passes:
/// the signals computable per-document up front (cosine, recency) plus the
/// content tokens BM25 needs once corpus statistics are known. `tokens` is
/// left empty under `Fusion::Legacy`, which never inspects them.
struct Candidate {
    drawer: Drawer,
    semantic: f32,
    recency: f32,
    tokens: Vec<String>,
    /// Parallel to `tokens` — see `script::Segmented::ngram`.
    ngram: Vec<bool>,
    /// Content units — see `script::Segmented::len`. Not `tokens.len()`,
    /// which counts the n-gram expansion.
    units: f32,
}

/// Lowercase comparison tokens — the same tokenization the query goes
/// through, so BM25 term matching is symmetric with the query.
///
/// Canonicalized first: what byte comparison misses is the *same* word written
/// with a different but canonically equivalent encoding, which would put the
/// query and the drawer in different buckets for no reason a reader could
/// see. Both sides run through here, so the fold stays symmetric.
///
/// Boundaries then come from `script::segment`. `is_alphanumeric` is
/// Unicode-aware, but being aware of a character is not the same as knowing
/// where its words end: in Han, Kana, Hangul, Arabic, Khmer, Thai, Lao and
/// Myanmar it finds no boundary the writer intended, and a whole clause
/// became one token. See that module for what each script actually does.
fn tokenize(content: &str) -> Vec<String> {
    // The historical minimum-length rule, kept exactly: it is a *byte* test,
    // so it only ever drops single ASCII letters — every non-Latin character
    // is 2+ bytes and always survived it. Changing it to characters would
    // silently delete every one-letter Cyrillic, Greek and Arabic token from
    // every existing vault, so it stays as it is.
    segment(content)
        .tokens
        .into_iter()
        .filter(|t| t.len() > 1)
        .collect()
}

/// `tokenize`, keeping the content-unit count that BM25 needs for length
/// normalization. Segmented runs emit unigrams and bigrams, so `tokens.len()`
/// is no longer a measure of how much a drawer says.
fn segment(content: &str) -> undercroft_core::script::Segmented {
    // `search_key`, not `match_key`: this is the retrieval key, and it also
    // lowercases. Both `tokenize` (the query side) and the per-candidate
    // document side flow through here, so symmetry is structural rather than
    // something two call sites have to remember.
    undercroft_core::script::segment(&undercroft_core::normalize::search_key(content))
}

/// Whether a query term matches a document token, tolerating one edit.
///
/// The tolerance is a port of mempalace's spellcheck extra and it is gated by
/// length, because a single edit is a large fraction of a short word. That
/// gate is in **bytes**, so it opens at three characters of Cyrillic and at
/// *two* of anything CJK — where a one-character substitution is not a typo
/// but a different word: 北京/東京 are two cities, 中国/美国 two countries,
/// 한국/중국 likewise, and each pair is one substitution apart.
///
/// So for terms written entirely in a script that attaches without a
/// delimiter, allow insertion and deletion — a particle or clitic arriving —
/// and never substitution. Elsewhere the historical byte gate stands.
///
/// Note this is deliberately *not* "make the gate character-based". Korean
/// query terms are two to four syllables and would all fall under a five-
/// character threshold, losing the tolerance that is the only reason Korean
/// retrieved anything before segmentation existed.
fn fuzzy_eq(q: &str, tok: &str) -> bool {
    if q.chars()
        .all(|c| undercroft_core::script::script_of(c).attaches_without_delimiter())
    {
        let (qn, tn) = (q.chars().count(), tok.chars().count());
        // Both sides must be at least two characters. A one-character query
        // term is one insertion away from *every* bigram containing it, so
        // `北` would claim 北, 东北 and 北虎 in one drawer and score a
        // Siberian-tiger note as three occurrences of the query. Korean
        // particles (한국어/한국어는) and 北京/北京市 are unaffected.
        return qn.min(tn) >= 2 && qn.abs_diff(tn) == 1 && within_one_edit(q, tok);
    }
    // Never forgive an edit inside a number. `١٠٠٠٠٠` used to be all-Arabic
    // and took the strict branch above; folded to ASCII `100000` it reaches
    // here, clears the byte gate, and matches `200000`, `100001` and
    // `190000`. A digit substitution is not a typo worth forgiving in a
    // retrieval index, and this closes the same latent hole for numbers that
    // were always Latin-typed.
    if !q.chars().any(|c| !c.is_numeric()) {
        return false;
    }
    if q.len() >= 5 && within_one_edit(q, tok) {
        return true;
    }
    same_word_family(q, tok) || contains_a_long_word(q, tok)
}

/// One word is a whole substring of the other, at any offset.
///
/// This is the half of compounding a prefix rule structurally cannot see:
/// `Dampfschiff` is a *suffix* of `Donaudampfschifffahrt` and `Ausbildung` sits
/// interior to `Bundesausbildungsförderungsgesetz`, so `same_word_family`
/// reaches neither — the shared prefix is zero.
///
/// It is also a consistency fix. `lexical_score` has always scored this
/// relation, through `lower.contains(t)`, so `Fusion::Legacy` and every
/// remote-index search already had it; only the default BM25 path, which
/// compares tokens rather than substrings, did not. Measured, that mattered
/// more than it looks: the cosine leg carries `Dampfschiff` /
/// `Donaudampfschifffahrt` at 0.8182 on a bare pair but only 0.5058 once the
/// drawer reaches ~80 words, so at real chunk length `lexical_exact` was 0,
/// `semantic` was below the gate, and the drawer was dropped rather than
/// mis-ranked.
///
/// **Eight characters on the shorter side**, chosen by measurement over this
/// repo's own prose (73 files, 6,710 distinct alphabetic words): 644 linked
/// pairs, 0.017% of eligible pairs, 214 of them beyond `same_word_family`'s
/// reach, per-word degree p90 = 1 and max = 8. At seven the `-ability` family
/// alone links fourteen words to `ability`, and `article`/`particle`,
/// `mission`/`admission` and `allowed`/`swallowed` arrive — 401 extra pairs.
///
/// Deliberately short of `run` / `running`, whose shorter side is 3: short
/// stems are a different gap and this is not a workaround for it.
///
/// The residue it does create is real morphology far more often than noise —
/// `unresolved`/`resolved`, `incompatible`/`compatible`,
/// `autoincrement`/`increment` — with `counting`/`accounting` and
/// `knowledge`/`acknowledged` as the sharpest genuine false pairs. All of it
/// lands in the approximate channel, so none of it can admit a drawer.
/// Critically, it creates none of gap (a)'s false friends: containment is
/// false for `город`/`горох`, `книга`/`книге` and `positive`/`position`.
/// One word contains the other, in a script that attaches without a delimiter
/// and is not logographic.
///
/// This is `contains_a_long_word`'s counterpart for Arabic, Kana, Hangul,
/// Khmer, Thai, Lao and Myanmar. It is what carries `كتاب` to `الكتاب` and
/// `مكتبة` to `بالمكتبة` once bigram-to-bigram equality stops being exact
/// evidence: the whole-subrun tokens still contain one another, which is a
/// contiguous chain over the stem rather than one shared fragment.
///
/// Three characters on the shorter side, not eight. The delimiting rule can
/// afford eight because a Latin word carries its own boundaries; an Arabic
/// stem is commonly three letters and there is no shorter honest floor. The
/// cost is measured and real: at three characters this relation runs at 0.519
/// morphological precision, against 0.820 at four and 0.911 at five. It routes
/// to `tf_morph`, so it is labelled and discounted — but it does admit, and
/// that number is the reason the channel exists.
fn shares_a_stem(q: &str, tok: &str) -> bool {
    let non_delimiting_word = |s: &str| {
        s.chars().all(|c| {
            let sc = undercroft_core::script::script_of(c);
            sc.attaches_without_delimiter() && !sc.is_logographic()
        })
    };
    if !non_delimiting_word(q) || !non_delimiting_word(tok) {
        return false;
    }
    const MIN_CHARS: usize = 3;
    let (qn, tn) = (q.chars().count(), tok.chars().count());
    if qn.min(tn) < MIN_CHARS {
        return false;
    }
    if qn <= tn {
        tok.contains(q)
    } else {
        q.contains(tok)
    }
}

fn contains_a_long_word(q: &str, tok: &str) -> bool {
    // Delimiting scripts only — a bigram token from Han, Arabic or Thai must
    // never reach a substring rule.
    if !q
        .chars()
        .all(|c| !undercroft_core::script::script_of(c).attaches_without_delimiter())
    {
        return false;
    }
    const MIN_CHARS: usize = 8;
    let (qn, tn) = (q.chars().count(), tok.chars().count());
    if qn.min(tn) < MIN_CHARS {
        return false;
    }
    if qn <= tn {
        tok.contains(q)
    } else {
        q.contains(tok)
    }
}

/// One word is nearly a prefix of the other — the reachable half of
/// morphology, without needing to know anyone's language.
///
/// This connects suffix and agglutinative inflection: `documentation` to
/// `document`/`documented`/`documents`/`documenting`, `encryption` to
/// `encrypt`, Georgian `ბიბლიოთეკა` to `ბიბლიოთეკაში`, German
/// `Konfiguration` to `Konfigurationen`.
///
/// The two thresholds are both load-bearing and both were chosen by what they
/// reject. A prefix of **7** is what excludes the systematic English
/// `-tive`/`-tion` class, which sits at exactly 6 and is length-symmetric so a
/// length-difference bound would not catch it: `positive`/`position`,
/// `relative`/`relation`, `creative`/`creation`, `transfer`/`transform`,
/// `personal`/`personnel`. It also rejects the Slavic and Greek false friends
/// a 6 would admit — `сообщение` (message) / `сообщество` (community),
/// `κατάσταση` (situation) / `κατάστημα` (shop). Bounding the divergent tail
/// on the **shorter** side rejects `представление` (idea) /
/// `представитель` (representative), which shares 8.
///
/// Three false pairs survive and are the accepted cost: `conversation` /
/// `conversion`, `processor` / `procession`, `internal` / `international`.
/// They feed the **approximate** channel only, so none of them can admit a
/// drawer **on the lexical channel** — they can only move one inside a result
/// set that already cleared the exact gate. That containment is why the
/// channel split had to land first.
///
/// The qualifier is not pedantry. The gate is a disjunction, and its other arm
/// is `semantic > SEMANTIC_ADMISSION_GATE`, which is undiscounted and
/// uncapped: measured, `internal` / `international` clears it at every drawer
/// length tested and `conversation` / `conversion` at three lengths of four.
/// So these pairs *can* be admitted — by the cosine leg, not by this rule.
/// Reading this containment as absolute overstates what the split buys.
///
/// One asymmetry worth knowing before reading the next paragraph as absolute:
/// `lexical_score`'s exact leg is unrestricted substring containment with **no
/// length gate**, so on `Fusion::Legacy` and on every remote-index search a
/// query `run` against a drawer saying `i was running daily` already yields
/// `lexical_exact = 1.0` and is admitted. It is the default BM25 path, which
/// compares whole tokens, that does not. So the short-stem gap is *directional*
/// (it bites when the query is the shorter form) and holds on one of three
/// fusion modes — the same shipped inconsistency `contains_a_long_word` was
/// added to reduce.
///
/// What this does not reach, and no prefix rule can: Russian nominal case
/// (`книга`/`книге` share 4, and so do `город`/`горох`), Greek `πόλη`/`πόλεων`
/// (3), English short stems (`running`/`run` — `run` is 3 characters), and
/// German compounds, where `Dampfschiff` is a *suffix* of
/// `Donaudampfschifffahrt` (the embedder's character trigrams already carry
/// that one on the cosine leg). Stem-rewriting morphology — Arabic broken
/// plurals, Korean conjugation — shares no contiguous surface at all.
/// The per-script morphological rules — the "right tool per language" made
/// explicit, with every value carrying the promiscuity that chose it.
///
/// Promiscuity = how many of a real 50k vocabulary one query links to
/// (hermitdave/FrequencyWords 2018, top-500 queries against the full list).
/// It is the instrument that produced the 74.3% figure, and it needs no
/// relatedness labels: a relation that reaches a large slice of the lexicon is
/// unsafe whether or not any single pair is defensible.
struct MorphRule {
    /// Minimum characters on the shorter side for whole-word containment.
    floor: usize,
    /// Consonantal-skeleton equality, and the weak letters it removes.
    /// Equality, never subsequence: measured, skeleton-subsequence on Arabic
    /// reaches mean 64.81 words — **worse than the 49.44 of the containment
    /// rule already shipped** — while equality reaches 6.67.
    skeleton: Option<fn(char) -> bool>,
    /// Whether a >=7 shared prefix admits (Greek only — see `greek_word_family`).
    prefix_family: bool,
}

/// Arabic weak letters: alef, waw, yeh.
fn ar_weak(c: char) -> bool {
    matches!(c as u32, 0x0627 | 0x0648 | 0x064A)
}
/// Hebrew matres lectionis: alef, waw, yod. `ה` is deliberately absent — it is
/// the definite article and a frequent radical, so stripping it would merge a
/// clitic into the stem it attaches to.
fn he_weak(c: char) -> bool {
    matches!(c as u32, 0x05D0 | 0x05D5 | 0x05D9)
}

/// Minimum consonants left after the weak letters go. Measured on Arabic, the
/// class size by skeleton length is 75.3 / 38.2 / 14.3 / 6.4 for lengths
/// 1/2/3/4 — so a floor of 3 keeps the strong triliteral roots and refuses the
/// collapse. It is a floor on the SKELETON, not on the word: that distinction
/// is what lets `كتاب`/`كتب` through while refusing `بيت`→`بت`.
const SKELETON_FLOOR: usize = 3;

fn skeleton_with(w: &str, weak: fn(char) -> bool) -> String {
    w.chars().filter(|c| !weak(*c)).collect()
}

/// Which rule applies to this word, by the script of its characters.
///
/// Returns `None` for mixed-script words and for Han, where a character is
/// already a morpheme and no stem relation applies.
fn morph_rule_for(w: &str) -> Option<MorphRule> {
    let mut chars = w.chars();
    let first = chars.next()?;
    let sc = undercroft_core::script::script_of(first);
    if !w
        .chars()
        .all(|c| undercroft_core::script::script_of(c) == sc)
    {
        return None;
    }
    use undercroft_core::script::Script;
    Some(match sc {
        // Semitic root-and-pattern. Arabic and Hebrew are the same family and
        // take the same tool; only the weak-letter set differs.
        Script::Arabic => MorphRule {
            floor: 3,
            skeleton: Some(ar_weak),
            prefix_family: false,
        },
        Script::Hebrew => MorphRule {
            floor: 3,
            skeleton: Some(he_weak),
            prefix_family: false,
        },
        // Han: a character is a morpheme, so unigrams already carry it.
        Script::Han => return None,
        // The other non-delimiting scripts keep the >=3 whole-word rule.
        s if s.attaches_without_delimiter() => MorphRule {
            floor: 3,
            skeleton: None,
            prefix_family: false,
        },
        // Delimiting scripts keep the floor of 8.
        //
        // I lowered this to 5 and it was wrong. The justification was a
        // promiscuity measurement — how many words of a real 50k vocabulary a
        // query links to — which read 3.03 for English at 5 and looked safe.
        // That instrument counts links; it cannot see whether a link is
        // CORRECT, and there were no negative controls. Measured against the
        // real engine afterwards, floor 5 admitted `other`/`mother`,
        // `count`/`accounting`, `press`/`depression`, `stand`/`understand`,
        // `cover`/`discovery` and `article`/`particle` — every one a false
        // admission that did not exist before.
        //
        // The 8 is not arbitrary and was not chosen by counting: see
        // `contains_a_long_word`, which names the 401 extra pairs that taking
        // 7 instead would have admitted. A precision-justified constant must
        // not be replaced by a recall-justified one.
        //
        // What this costs, and it is real: Turkish is purely additive with
        // stems of 2-5 characters, so containment is true on every pair and
        // the floor refuses all of it. Turkish, Hindi, Spanish and English
        // regress to their prior numbers. Reaching them needs a per-LANGUAGE
        // floor, which needs a language input, because Turkish and English
        // share a script and disagree about the right value.
        //
        // (retained for the record) The measurement at floor 5 read: Greek
        // 3.41, English 3.03, Russian 3.20, Turkish 9.35, German 12.44; at 3,
        // 45.68 / 33.33 / 27.49 / 65.55 / 68.47, German peaking at 1,996
        // links for one query because German compounds.
        _ => MorphRule {
            floor: 8,
            skeleton: None,
            prefix_family: true,
        },
    })
}

/// Does a morphological relation hold — the admitting half of the morph
/// channel, dispatched per script.
fn morph_relation(q: &str, tok: &str) -> bool {
    let Some(rule) = morph_rule_for(q) else {
        return false;
    };
    // Both sides must be the same script, or a rule chosen for one language
    // decides a pair from another.
    if morph_rule_for(tok).is_none()
        || undercroft_core::script::script_of(tok.chars().next().unwrap_or(' '))
            != undercroft_core::script::script_of(q.chars().next().unwrap_or(' '))
    {
        return false;
    }
    // Never relate one number to another. `fuzzy_eq` has refused this since
    // the Arabic digit fold landed — "a digit substitution is not a typo worth
    // forgiving in a retrieval index" — but that guard sits in the channel
    // that RANKS. This one is evaluated first and lands in the channel that
    // ADMITS, so without its own guard it was strictly worse: measured,
    // `45678` admitted a drawer saying `456789`, `100000` admitted `1000000`,
    // and `2023` admitted `20231`. Every invoice number, order id and account
    // number in a vault was one containment away from a wrong drawer.
    if !q.chars().any(|c| !c.is_numeric()) || !tok.chars().any(|c| !c.is_numeric()) {
        return false;
    }
    // The shipped >=3 whole-word rule, unchanged. It self-guards on script, so
    // it is a no-op for the delimiting branch.
    if shares_a_stem(q, tok) {
        return true;
    }
    let (qn, tn) = (q.chars().count(), tok.chars().count());
    if qn.min(tn) >= rule.floor
        && (if qn <= tn {
            tok.contains(q)
        } else {
            q.contains(tok)
        })
    {
        return true;
    }
    if let Some(weak) = rule.skeleton {
        let a = skeleton_with(q, weak);
        if a.chars().count() >= SKELETON_FLOOR && a == skeleton_with(tok, weak) {
            return true;
        }
    }
    // Greek only, and `greek_word_family` is what enforces that: measured,
    // this rule links a mean of 0.16 English words and 0.58 Russian ones, so
    // it is not the promiscuity that keeps it off Latin — it is that Latin's
    // false pairs (`conversation`/`conversion`) are the named, documented cost
    // of the rule, and Greek's beneficiaries are nine real paradigm forms.
    rule.prefix_family && greek_word_family(q, tok)
}

/// `same_word_family`, but admitting — and only for Greek.
///
/// Greek inflection **substitutes** its endings rather than appending them, so
/// containment reaches almost none of it. Measured over 49 real paradigm pairs
/// at realistic drawer length: endings that merely append admitted 12 of 15,
/// endings that replace admitted **1 of 20**. Of the 33 pairs dropped,
/// `same_word_family` already fires on 9 — every form of `άνθρωπος`, three of
/// `εργαζόμενος`, `πληροφορίες`, `πληροφοριών`, `εφημερίδες` — but it was
/// routed to the approximate channel, which ranks and never admits, so those
/// drawers were **dropped rather than mis-ranked**.
///
/// Scoped to the Greek script deliberately, because that is exactly what
/// separates the benefit from the cost. The three Latin pairs this rule's own
/// documentation names as the accepted price — `conversation`/`conversion`,
/// `processor`/`procession`, `internal`/`international` — all measure a
/// 7-prefix and all would admit. They are Latin; the nine beneficiaries are
/// Greek. Conditioning on script takes the one and not the other.
///
/// Measured Greek cost: `παράδειγμα`/`παράδεισος` (example/paradise), which
/// shares 7 and diverges by 3. Note what does *not* fire — `πολύ`/`πόλη`, the
/// frequency argument that killed Snowball Greek, shares only 3 characters. A
/// stemmer builds an equivalence class that one false friend poisons; a
/// pairwise predicate answers about two strings and creates no class, which is
/// why this survives an argument a stemmer did not.
fn greek_word_family(q: &str, tok: &str) -> bool {
    let greek = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| matches!(c as u32, 0x0370..=0x03FF | 0x1F00..=0x1FFF))
    };
    greek(q) && greek(tok) && same_word_family(q, tok)
}

fn same_word_family(q: &str, tok: &str) -> bool {
    // Delimiting scripts only. A bigram token from Han, Arabic or Thai must
    // never reach a character-prefix rule.
    if !q
        .chars()
        .all(|c| !undercroft_core::script::script_of(c).attaches_without_delimiter())
    {
        return false;
    }
    let (qn, tn) = (q.chars().count(), tok.chars().count());
    let shared = q
        .chars()
        .zip(tok.chars())
        .take_while(|(a, b)| a == b)
        .count();
    shared >= 7 && qn.min(tn) - shared <= 3
}

/// True when a query cannot be served by the FTS5 prefilter.
///
/// `drawers_fts` is a standalone fts5 table over `search_key(content)` — see
/// `init_fts_schema`, which explains why it is no longer external-content over
/// raw bytes. Folding the index fixed the *fold* disagreement; it does not fix
/// the *segmentation* one, and that is what this predicate is still for: our
/// tokens for Han, Kana, Hangul, Arabic, Khmer, Thai, Lao and Myanmar are
/// character bigrams, and unicode61 does not bigram anything.
///
/// The prefilter is only safe when it finds nothing: `fts_candidates` returns
/// `None` on an empty result and search falls back to a full scan. A
/// *non-empty* wrong answer becomes `seq IN (...)` and cuts the right drawer
/// out of the scan entirely — and out of the cosine path with it. Bypassing
/// keeps the full scan, which is correct and merely slower.
fn needs_full_scan(qterms: &[String]) -> bool {
    qterms.iter().any(|t| {
        t.chars()
            .any(|c| undercroft_core::script::script_of(c).attaches_without_delimiter())
    })
}

/// Raw Okapi BM25 per candidate over the candidate set as the corpus, plus
/// `k_sat` — the mean IDF of query terms that actually occur, used as the
/// saturation constant when squashing raw scores into [0,1]. Term matching
/// carries the same one-typo tolerance (5+ char terms) as lexical search,
/// so a misspelled query still contributes.
/// BM25 over a candidate set, kept in two channels.
///
/// `raw` is for ranking and blends both kinds of evidence. `exact` counts
/// only tokens that literally equal a query term, and it is what decides
/// *admission* — see the relevance gate in `search`. The distinction matters
/// because approximate evidence is a guess: a fold makes two spellings one
/// token, and `fuzzy_eq` forgives an edit. Under a single channel each of
/// those is a membership decision, so a drawer whose only relationship to the
/// query is a typo away gets returned as if it had said the word.
struct Bm25 {
    raw: Vec<f32>,
    exact: Vec<f32>,
    morph: Vec<f32>,
    k_sat: f32,
}

/// Approximate evidence counts, but never as much as saying the word.
const APPROX_WEIGHT: f32 = 0.5;

fn bm25_raw(qterms: &[String], cands: &[Candidate]) -> Bm25 {
    let n = cands.len();
    if n == 0 || qterms.is_empty() {
        return Bm25 {
            raw: vec![0.0; n],
            exact: vec![0.0; n],
            morph: vec![0.0; n],
            k_sat: 0.0,
        };
    }
    // tf[doc][term] = occurrences of qterms[term] in the doc's tokens.
    let mut tf = vec![vec![0u32; qterms.len()]; n];
    let mut tf_approx = vec![vec![0u32; qterms.len()]; n];
    let mut tf_morph = vec![vec![0u32; qterms.len()]; n];
    let mut lengths = vec![0f32; n];
    for (i, c) in cands.iter().enumerate() {
        // Content units, not emitted tokens: a segmented run expands into
        // unigrams plus bigrams, and charging that to document length would
        // penalise precisely the drawers segmentation exists to reach.
        lengths[i] = c.units;
        for (ti, tok) in c.tokens.iter().enumerate() {
            // An n-gram is a fragment, not a word. Letting one fill the exact
            // slot by literal equality is what let a single shared
            // two-character substring admit a drawer: measured, 74.3% of a
            // real Arabic corpus on one query, against 6.9% for Greek through
            // the same code. Han is not flagged, because there a character is
            // a morpheme.
            let is_ngram = c.ngram.get(ti).copied().unwrap_or(false);
            // A token fills at most one query-term slot, and an *exact* match
            // outranks a fuzzy one wherever the two compete. Taking the first
            // match of either kind let an earlier fuzzy term steal a token
            // that exactly equals a later one: for query `دفتر دفاتر`, a
            // document saying `دفاتر` scored as evidence for `دفتر` while
            // `دفاتر` — literally present — kept df = 0 and therefore maximal
            // IDF for a term that occurs. The document was scored as if it
            // contained a different word.
            if !is_ngram {
                if let Some(j) = qterms.iter().position(|q| q == tok) {
                    tf[i][j] += 1;
                    continue;
                }
            }
            // Checked before the general fuzzy scan so containment lands in
            // its own channel rather than being absorbed as approximate.
            if let Some(j) = qterms.iter().position(|q| morph_relation(q, tok)) {
                tf_morph[i][j] = 1;
                continue;
            }
            // A bigram meeting the same bigram is the weakest evidence there
            // is — real, but the same grade that makes كريم (a name) surface
            // كرم (generosity) at rank 1. It ranks; it does not admit.
            if is_ngram {
                if let Some(j) = qterms.iter().position(|q| q == tok) {
                    tf_approx[i][j] = 1;
                    continue;
                }
            }
            if let Some(j) = qterms.iter().position(|q| fuzzy_eq(q, tok)) {
                // Capped at one per slot. Uncapped, a drawer saying
                // `document documents documented documenting` reaches tf = 4
                // on a query for `documentation` while a drawer that says
                // `documentation` once reaches tf = 1 — the approximate
                // channel would outscore the exact one.
                tf_approx[i][j] = 1;
            }
        }
    }
    let avgdl = (lengths.iter().sum::<f32>() / n as f32).max(1.0);
    let mut idf = vec![0f32; qterms.len()];
    let mut present_idf_sum = 0f32;
    let mut present_cnt = 0f32;
    for (j, idf_j) in idf.iter_mut().enumerate() {
        // Rarity counts a term as present on either channel — IDF describes
        // the corpus, not the confidence of one match.
        let df = (0..n)
            .filter(|&i| tf[i][j] > 0 || tf_morph[i][j] > 0 || tf_approx[i][j] > 0)
            .count() as f32;
        // Okapi probabilistic IDF, +1 inside the log to stay non-negative.
        *idf_j = (1.0 + (n as f32 - df + 0.5) / (df + 0.5)).ln();
        if df > 0.0 {
            present_idf_sum += *idf_j;
            present_cnt += 1.0;
        }
    }
    let k_sat = if present_cnt > 0.0 {
        present_idf_sum / present_cnt
    } else {
        0.0
    };
    let mut raw = vec![0f32; n];
    let mut exact = vec![0f32; n];
    let mut morph = vec![0f32; n];
    for i in 0..n {
        let len_norm = 1.0 - BM25_B + BM25_B * lengths[i] / avgdl;
        let saturate = |f: f32, idf: f32| idf * (f * (BM25_K1 + 1.0)) / (f + BM25_K1 * len_norm);
        let (mut s, mut e, mut m) = (0f32, 0f32, 0f32);
        for (j, idf_j) in idf.iter().enumerate() {
            let f_exact = tf[i][j] as f32;
            let f_morph = tf_morph[i][j] as f32;
            // Morphological evidence is discounted exactly like approximate
            // evidence for RANKING; the difference is only that it admits.
            let f = f_exact + APPROX_WEIGHT * (f_morph + tf_approx[i][j] as f32);
            if f > 0.0 {
                s += saturate(f, *idf_j);
            }
            if f_exact > 0.0 {
                e += saturate(f_exact, *idf_j);
            }
            if f_morph > 0.0 {
                m += saturate(f_morph, *idf_j);
            }
        }
        raw[i] = s;
        exact[i] = e;
        morph[i] = m;
    }
    Bm25 {
        raw,
        exact,
        morph,
        k_sat,
    }
}

/// BM25 squashed into [0,1] for the linear blend: `raw / (raw + k_sat)`,
/// so one strong term match sits near 0.5 and additional evidence climbs
/// toward 1 without ever forcing a top candidate to exactly 1.0.
fn bm25_scores(qterms: &[String], cands: &[Candidate]) -> Vec<(f32, f32, f32)> {
    let b = bm25_raw(qterms, cands);
    if b.k_sat <= 0.0 {
        return vec![(0.0, 0.0, 0.0); cands.len()];
    }
    let squash = |r: f32| if r > 0.0 { r / (r + b.k_sat) } else { 0.0 };
    (0..cands.len())
        .map(|i| (squash(b.raw[i]), squash(b.exact[i]), squash(b.morph[i])))
        .collect()
}

/// 1-based ranks by descending value, ties broken by original index.
fn ranks_desc(vals: &[f32]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..vals.len()).collect();
    idx.sort_by(|&a, &b| {
        vals[b]
            .partial_cmp(&vals[a])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.cmp(&b))
    });
    let mut rank = vec![0usize; vals.len()];
    for (r, &i) in idx.iter().enumerate() {
        rank[i] = r + 1;
    }
    rank
}

/// Like [`ranks_desc`] but only entries with a positive value are ranked;
/// the rest get `None` so they contribute nothing to the RRF sum (a zero
/// BM25 must not earn rank credit just for existing).
fn ranks_desc_positive(vals: &[f32]) -> Vec<Option<usize>> {
    let mut idx: Vec<usize> = (0..vals.len()).filter(|&i| vals[i] > 0.0).collect();
    idx.sort_by(|&a, &b| {
        vals[b]
            .partial_cmp(&vals[a])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.cmp(&b))
    });
    let mut rank = vec![None; vals.len()];
    for (r, &i) in idx.iter().enumerate() {
        rank[i] = Some(r + 1);
    }
    rank
}

/// Reciprocal-rank fusion of the cosine ranking and the BM25 ranking, with
/// recency as a lightly-weighted third ranker (0.10, matching the linear
/// blend's recency weight). Scale-free: no semantic/lexical weight to tune,
/// only rank positions. `lexical` is reported as the squashed BM25 so the
/// caller's relevance gate treats it exactly like the BM25 blend.
fn rrf_fuse(qterms: &[String], cands: Vec<Candidate>) -> Vec<SearchHit> {
    let b = bm25_raw(qterms, &cands);
    let (raw, k_sat) = (b.raw, b.k_sat);
    let sem: Vec<f32> = cands.iter().map(|c| c.semantic).collect();
    let rec: Vec<f32> = cands.iter().map(|c| c.recency).collect();
    let sem_rank = ranks_desc(&sem);
    let rec_rank = ranks_desc(&rec);
    let bm_rank = ranks_desc_positive(&raw);
    cands
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            let mut score = 1.0 / (RRF_K + sem_rank[i] as f32);
            if let Some(r) = bm_rank[i] {
                score += 1.0 / (RRF_K + r as f32);
            }
            score += 0.10 * (1.0 / (RRF_K + rec_rank[i] as f32));
            let squash = |r: f32| {
                if k_sat > 0.0 && r > 0.0 {
                    r / (r + k_sat)
                } else {
                    0.0
                }
            };
            SearchHit {
                drawer: c.drawer,
                score,
                semantic: c.semantic,
                lexical: squash(raw[i]),
                lexical_exact: squash(b.exact[i]),
                lexical_morph: squash(b.morph[i]),
            }
        })
        .collect()
}

/// Fraction of query terms present in the content, with a phrase bonus.
/// Terms of 5+ chars also match with one typo (edit distance 1) — the
/// port of mempalace's spellcheck extra, done at query time instead of
/// with a dictionary.
///
/// Returns `(lexical, lexical_exact)` on the same split as `bm25_raw`: the
/// substring leg is exact evidence, the one-edit leg is not.
fn lexical_score(qterms: &[String], raw_query: &str, content: &str) -> (f32, f32) {
    if qterms.is_empty() {
        return (0.0, 0.0);
    }
    // Same canonical fold the query terms went through, or a drawer written
    // with a different but equivalent encoding cannot match its own words.
    // Both legs of this function must fold, or the substring leg desynchronises
    // from the term leg: a folded query term cannot be found in an unfolded
    // haystack, and under the relevance gate that *drops* the drawer.
    let lower = undercroft_core::normalize::search_key(content);
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let (mut exact, mut approx) = (0f32, 0f32);
    for t in qterms {
        if lower.contains(t.as_str()) {
            exact += 1.0;
        } else if words.iter().any(|w| fuzzy_eq(t, w)) {
            approx += 1.0;
        }
    }
    let n = qterms.len() as f32;
    let mut score = (exact + APPROX_WEIGHT * approx) / n;
    let mut score_exact = exact / n;
    let phrase = undercroft_core::normalize::search_key(raw_query.trim());
    if phrase.len() > 3 && lower.contains(&*phrase) {
        // A literal phrase hit is exact evidence on both channels.
        score = (score + 0.5).min(1.0);
        score_exact = (score_exact + 0.5).min(1.0);
    }
    (score, score_exact)
}

/// True when `a` and `b` are within Levenshtein distance 1 (single
/// substitution, insertion, or deletion). O(len) — no DP table.
fn within_one_edit(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (la, lb) = (a.len(), b.len());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    let (short, long) = if la <= lb { (&a, &b) } else { (&b, &a) };
    let mut i = 0;
    let mut j = 0;
    let mut edits = 0;
    while i < short.len() && j < long.len() {
        if short[i] == long[j] {
            i += 1;
            j += 1;
            continue;
        }
        edits += 1;
        if edits > 1 {
            return false;
        }
        if short.len() == long.len() {
            i += 1; // substitution
        }
        j += 1; // skip in the longer (insertion/deletion)
    }
    edits + (long.len() - j) + (short.len() - i) <= 1
}

/// Exponential recency decay with a 30-day half-life.
fn recency_boost(filed_at: &str, now: OffsetDateTime) -> f32 {
    match OffsetDateTime::parse(filed_at, &Rfc3339) {
        Ok(t) => {
            let days = (now - t).whole_seconds().max(0) as f32 / 86_400.0;
            (0.5f32).powf(days / 30.0)
        }
        Err(_) => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use undercroft_vault::{SecurityLevel, VaultManager};
    use tempfile::TempDir;

    fn store(level: SecurityLevel) -> (TempDir, PalaceStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", level).unwrap();
        (dir, PalaceStore::open(vault).unwrap())
    }

    /// Build a hit with a known room and score — enough for the pure
    /// selection helper, which never looks at content or embeddings.
    fn hit(room: &str, score: f32, idx: u32) -> SearchHit {
        SearchHit {
            drawer: drawer("w", room, &format!("c{idx}"), idx),
            score,
            semantic: score,
            lexical: score,
            lexical_exact: score,
            lexical_morph: 0.0,
        }
    }

    #[test]
    fn room_cap_spreads_selection_across_rooms() {
        // One verbose room dominates by score; evidence in other rooms sits
        // lower. Without a cap the answer never sees rooms b or c.
        let hits = vec![
            hit("a", 0.99, 0),
            hit("a", 0.98, 1),
            hit("a", 0.97, 2),
            hit("a", 0.96, 3),
            hit("b", 0.50, 4),
            hit("c", 0.40, 5),
        ];
        let out = diversify_by_room(hits, 4, 2);
        let rooms: Vec<&str> = out.iter().map(|h| h.drawer.meta.room.as_str()).collect();
        assert_eq!(rooms, vec!["a", "a", "b", "c"], "{rooms:?}");
        // Score order is preserved within the result.
        assert!(out.windows(2).all(|w| w[0].score >= w[1].score));
    }

    #[test]
    fn room_cap_is_soft_and_never_returns_fewer_than_asked() {
        // Everything is in one room: the cap must not starve the caller.
        let hits: Vec<SearchHit> = (0..6)
            .map(|i| hit("solo", 0.9 - i as f32 * 0.01, i))
            .collect();
        let out = diversify_by_room(hits, 4, 2);
        assert_eq!(out.len(), 4, "soft cap must refill to the limit");
        assert!(out.iter().all(|h| h.drawer.meta.room == "solo"));
    }

    #[test]
    fn room_cap_refill_keeps_the_best_leftovers_in_order() {
        let hits = vec![
            hit("a", 0.99, 0),
            hit("a", 0.98, 1),
            hit("a", 0.97, 2),
            hit("b", 0.60, 3),
        ];
        // cap 1: a gets one, b gets one, then refill takes a's next best.
        let out = diversify_by_room(hits, 3, 1);
        let ids: Vec<u32> = out.iter().map(|h| h.drawer.meta.chunk_index).collect();
        assert_eq!(ids, vec![0, 1, 3], "{ids:?}");
    }

    #[test]
    fn search_without_room_cap_is_unchanged() {
        let (_dir, mut s) = store(SecurityLevel::Sealed);
        for i in 0..6u32 {
            s.upsert(&drawer(
                "w",
                if i < 4 { "loud" } else { "quiet" },
                "zebra lockfile note",
                i,
            ))
            .unwrap();
        }
        let flat = s
            .search(
                "zebra lockfile note",
                &SearchOptions {
                    limit: 3,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(flat.len(), 3);
        let capped = s
            .search(
                "zebra lockfile note",
                &SearchOptions {
                    limit: 3,
                    room_cap: Some(1),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(capped.len(), 3, "capped search still fills the limit");
        // The cap can only change WHICH rooms appear, never how many hits.
        assert!(capped.iter().any(|h| h.drawer.meta.room == "quiet"));
    }

    /// Exactly what `POST /v1/vaults/{id}/drawers` does: index the new
    /// drawer by the store's current row count.
    fn rest_save(s: &mut PalaceStore, wing: &str, room: &str, text: &str) -> String {
        let idx = s.next_append_index().unwrap() as u32;
        let d = Drawer::new(wing, room, text.into(), None, idx, "rest");
        s.upsert(&d).unwrap();
        d.id
    }

    /// `count()` is `SELECT COUNT(*)`, so it goes DOWN when a drawer is
    /// deleted — and it is the drawer id's uniquifier on the REST write path.
    /// After a delete, the next save reuses an index that is still in use,
    /// and `ON CONFLICT(id) DO UPDATE` overwrites the drawer holding it.
    /// An unrelated record is destroyed by writing a new one.
    #[test]
    fn a_rest_save_after_a_delete_must_not_overwrite_an_unrelated_drawer() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let a = rest_save(&mut s, "w", "r", "first note");
        let b = rest_save(&mut s, "w", "r", "second note");
        assert_ne!(a, b);

        assert!(s.delete_drawer(&a).unwrap());
        let c = rest_save(&mut s, "w", "r", "third note");

        assert_ne!(c, b, "a new save must not land on an existing drawer's id");
        assert_eq!(
            s.get(&b).unwrap().map(|d| d.content),
            Some("second note".to_string()),
            "the unrelated drawer must survive"
        );
        assert_eq!(s.count().unwrap(), 2, "two drawers remain");
    }

    fn drawer(wing: &str, room: &str, content: &str, idx: u32) -> Drawer {
        Drawer::new(
            wing,
            room,
            content.into(),
            Some("test.md".into()),
            idx,
            "test",
        )
    }

    /// Durability contract: WAL + synchronous=FULL, pinned — not left to the
    /// compile-time default — so the data+chain commit is always on disk
    /// before its manifest anchor can be (anchor never runs ahead).
    #[test]
    fn connection_pins_wal_and_full_synchronous() {
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let (_dir, store) = store(level);
            let journal: String = store
                .conn
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .unwrap();
            assert_eq!(journal.to_ascii_lowercase(), "wal");
            let sync: i64 = store
                .conn
                .query_row("PRAGMA synchronous", [], |r| r.get(0))
                .unwrap();
            assert_eq!(sync, 2, "synchronous must be FULL");
        }
    }

    /// A manifest anchor write must never leave its temp file behind — the
    /// durable-replace path renames it into place every time.
    #[test]
    fn manifest_anchor_leaves_no_temp_file() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::Sealed).unwrap();
        let vault_dir = dir.path().join("vaults/test");
        let mut store = PalaceStore::open(vault).unwrap();
        store.upsert(&drawer("w", "r", "durable words", 0)).unwrap();
        assert!(vault_dir.join("vault.json").exists());
        assert!(
            !vault_dir.join("vault.json.tmp").exists(),
            "anchor temp file must be renamed away"
        );
    }

    fn external_store(level: SecurityLevel, dim: usize) -> (TempDir, PalaceStore) {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", level).unwrap();
        let emb = Box::new(undercroft_core::ExternalEmbedder::new("acme-embed", dim));
        (dir, PalaceStore::open_with_embedder(vault, emb).unwrap())
    }

    /// Bulk path: the whole batch commits in one transaction, the chain
    /// advances per drawer, and the anchor written after the commit
    /// matches the database head at a cold reopen (no divergence window).
    #[test]
    fn upsert_many_batches_atomically() {
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let (dir, mut store) = store(level);
            let batch: Vec<Drawer> = (0..10u32)
                .map(|i| drawer("w", "r", &format!("bulk drawer number {i}"), i))
                .collect();
            assert_eq!(store.upsert_many(&batch).unwrap(), 10);
            assert_eq!(store.count().unwrap(), 10);
            assert!(store.verify().unwrap().ok());
            // Re-upserting the same batch updates in place — nothing new —
            // and every update still advances the audit chain.
            assert_eq!(store.upsert_many(&batch).unwrap(), 0);
            assert!(store.verify().unwrap().ok());
            let hits = store
                .search(
                    "bulk drawer number",
                    &SearchOptions {
                        wing: None,
                        room: None,
                        limit: 5,
                        room_cap: None,
                    },
                )
                .unwrap();
            assert!(!hits.is_empty());
            drop(store);
            let mgr = VaultManager::open(dir.path(), None).unwrap();
            let store2 = PalaceStore::open(mgr.unlock("test").unwrap()).unwrap();
            assert!(store2.verify().unwrap().ok());
            assert_eq!(store2.count().unwrap(), 10);
        }
    }

    /// A deterministic reranker that scores purely by passage length — used to
    /// prove the rerank pass actually re-orders results independently of the
    /// first-pass fusion score.
    struct LenReranker;
    impl Reranker for LenReranker {
        fn model_name(&self) -> &str {
            "len-mock"
        }
        fn score(&self, _query: &str, passage: &str) -> f32 {
            passage.chars().count() as f32
        }
    }

    /// A deterministic late-interaction encoder: one "token" per word,
    /// each a unit one-hot picked by a word hash. MaxSim then counts
    /// (normalized) query-word coverage — enough to prove ordering flows
    /// from the stored matrices.
    struct WordLate;
    impl undercroft_core::late::LateInteraction for WordLate {
        fn model_name(&self) -> &str {
            "word-mock"
        }
        fn dim(&self) -> usize {
            16
        }
        fn encode_doc(&self, text: &str) -> Vec<f32> {
            let mut m = Vec::new();
            for w in text.split_whitespace() {
                let mut row = vec![0f32; 16];
                let h = w.bytes().fold(0usize, |a, b| (a * 31 + b as usize) % 16);
                row[h] = 1.0;
                m.extend(row);
            }
            m
        }
        fn encode_query(&self, text: &str) -> Vec<f32> {
            self.encode_doc(text)
        }
    }

    #[test]
    fn late_interaction_rescore_orders_by_stored_matrices() {
        for level in [SecurityLevel::HmacOnly, SecurityLevel::Sealed] {
            let (_d, mut s) = store(level);
            s.set_late(Some(Box::new(WordLate)));
            // Both mention the query word once; the second covers more of
            // the query's words, so MaxSim must rank it first even though
            // both fuse similarly.
            s.upsert(&drawer("w", "r", "kafka pipeline notes", 0))
                .unwrap();
            s.upsert(&drawer("w", "r", "kafka stream backlog rework", 1))
                .unwrap();
            let hits = s
                .search(
                    "kafka stream backlog",
                    &SearchOptions {
                        wing: None,
                        room: None,
                        limit: 2,
                        room_cap: None,
                    },
                )
                .unwrap();
            assert_eq!(hits.len(), 2);
            assert!(
                hits[0].drawer.content.contains("backlog"),
                "MaxSim coverage must lead at level {level:?}: got {:?}",
                hits[0].drawer.content
            );

            // The token store exists and, on sealed vaults, never holds the
            // plaintext-derived matrix in clear: our mock rows are one-hot
            // (byte 0x7F after int8 quantization at scale 1/127 appears
            // per word) — a sealed blob must not equal the plain packing.
            let (blob, plain): (Vec<u8>, Vec<u8>) = {
                let b: Vec<u8> = s
                    .conn
                    .query_row(
                        "SELECT tok FROM drawer_tok WHERE id = (SELECT id FROM drawers LIMIT 1)",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                let m = undercroft_core::late::LateInteraction::encode_doc(
                    &WordLate,
                    "kafka pipeline notes",
                );
                (b, undercroft_core::late::quantize_tokens(&m, 16))
            };
            match level {
                SecurityLevel::HmacOnly => assert_eq!(blob, plain),
                SecurityLevel::Sealed => assert_ne!(
                    blob, plain,
                    "sealed vault must not store plaintext-derived tokens in clear"
                ),
            }

            // Deleting purges the token row.
            let id = hits[0].drawer.id.clone();
            s.delete_drawer(&id).unwrap();
            let left: i64 = s
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM drawer_tok WHERE id = ?1",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(left, 0, "delete must purge the token matrix");
        }
    }

    #[test]
    fn fde_candidates_rank_the_target_and_seal_at_rest() {
        for level in [SecurityLevel::HmacOnly, SecurityLevel::Sealed] {
            let (_d, mut s) = store(level);
            s.set_late(Some(Box::new(WordLate)));
            s.set_fde(true);
            for i in 0..30 {
                s.upsert(&drawer("w", "r", &format!("routine filler note {i}"), i))
                    .unwrap();
            }
            let target = drawer("w", "r", "kafka stream backlog rework", 100);
            s.upsert(&target).unwrap();

            // FDE candidate generation must place the covering doc in its
            // head (call the generator directly — end-to-end search also
            // fuses BM25, which would mask a broken FDE ranking).
            let cands = s
                .fde_candidates("kafka stream backlog", 5)
                .unwrap()
                .expect("FDE index must serve");
            let target_seq: i64 = s
                .conn
                .query_row("SELECT seq FROM drawers WHERE id = ?1", [&target.id], |r| {
                    r.get(0)
                })
                .unwrap();
            assert!(
                cands.contains(&target_seq),
                "target must be an FDE top-5 candidate at level {level:?}"
            );

            // Every token-bearing drawer got an FDE row, written from the
            // matrix in hand (no backfill was needed).
            let rows: i64 = s
                .conn
                .query_row("SELECT COUNT(*) FROM drawer_fde", [], |r| r.get(0))
                .unwrap();
            assert_eq!(rows, 31, "every drawer must carry an FDE");

            // At rest: the sealed blob must not be the plain v1 packing.
            let expected_plain: Vec<u8> = {
                let enc = undercroft_core::fde::FdeEncoder::new(
                    16,
                    undercroft_core::fde::FdeParams::default(),
                );
                let m = undercroft_core::late::LateInteraction::encode_doc(
                    &WordLate,
                    "kafka stream backlog rework",
                );
                std::iter::once(1u8)
                    .chain(enc.encode_doc(&m).iter().flat_map(|v| v.to_le_bytes()))
                    .collect()
            };
            let blob: Vec<u8> = s
                .conn
                .query_row(
                    "SELECT fde FROM drawer_fde WHERE id = ?1",
                    [&target.id],
                    |r| r.get(0),
                )
                .unwrap();
            match level {
                SecurityLevel::HmacOnly => assert_eq!(blob, expected_plain),
                SecurityLevel::Sealed => assert_ne!(
                    blob, expected_plain,
                    "sealed vault must not store plaintext-derived FDEs in clear"
                ),
            }

            // Reopen semantics: a fresh cache reproduces the candidates.
            s.fde_cache.borrow_mut().take();
            let again = s
                .fde_candidates("kafka stream backlog", 5)
                .unwrap()
                .expect("cache rebuild");
            assert_eq!(cands, again, "cache rebuild must reproduce candidates");

            // Delete purges the FDE row beside the token row.
            s.delete_drawer(&target.id).unwrap();
            let left: i64 = s
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM drawer_fde WHERE id = ?1",
                    [&target.id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(left, 0, "delete must purge the FDE row");
        }
    }

    #[test]
    fn fde_codebook_trains_repacks_and_candidates_agree() {
        for level in [SecurityLevel::HmacOnly, SecurityLevel::Sealed] {
            let (_d, mut s) = store(level);
            s.set_late(Some(Box::new(WordLate)));
            s.set_fde(true);
            s.fde_pq_min = 8; // train immediately at test scale
            for i in 0..30 {
                s.upsert(&drawer("w", "r", &format!("routine filler note {i}"), i))
                    .unwrap();
            }
            let target = drawer("w", "r", "kafka stream backlog rework", 100);
            s.upsert(&target).unwrap();

            let cands = s
                .fde_candidates("kafka stream backlog", 5)
                .unwrap()
                .expect("FDE index must serve");
            let target_seq: i64 = s
                .conn
                .query_row("SELECT seq FROM drawers WHERE id = ?1", [&target.id], |r| {
                    r.get(0)
                })
                .unwrap();
            assert!(
                cands.contains(&target_seq),
                "target must survive the PQ-coded head at level {level:?}"
            );

            // The codebook trained and every row repacked to v2 codes:
            // hmac-only rows are plain (version byte 2, dim/8 + 5 bytes);
            // sealed rows must be opaque (AEAD ≠ the plain packing size).
            let meta: i64 = s
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM fde_meta WHERE key = 'codebook'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(meta, 1, "codebook must persist");
            let fde_dim = s.fde_encoder.borrow().as_ref().unwrap().dim();
            let blob: Vec<u8> = s
                .conn
                .query_row(
                    "SELECT fde FROM drawer_fde WHERE id = ?1",
                    [&target.id],
                    |r| r.get(0),
                )
                .unwrap();
            let plain_v2_len = 5 + fde_dim / 8;
            match level {
                SecurityLevel::HmacOnly => {
                    assert_eq!(blob.first(), Some(&2u8), "row must be v2 codes");
                    assert_eq!(blob.len(), plain_v2_len, "32× packing expected");
                }
                SecurityLevel::Sealed => {
                    assert_ne!(
                        blob.len(),
                        plain_v2_len,
                        "sealed row must not be the plain packing"
                    );
                    assert_ne!(
                        blob.len(),
                        1 + fde_dim * 4,
                        "sealed row must not be the raw packing either"
                    );
                }
            }

            // Cache rebuild parity first (before any further writes — an
            // extra row could legitimately reshuffle a top-5 tie).
            s.fde_cache.borrow_mut().take();
            let again = s
                .fde_candidates("kafka stream backlog", 5)
                .unwrap()
                .expect("cache rebuild");
            assert_eq!(
                cands, again,
                "coded cache rebuild must reproduce candidates"
            );

            // A write AFTER the codebook exists stores v2 directly and
            // stays findable.
            s.upsert(&drawer("w", "api", "zookeeper quorum flapped again", 200))
                .unwrap();
            let hits = s
                .fde_candidates("zookeeper quorum flapped", 5)
                .unwrap()
                .expect("post-train writes must serve");
            let zk_seq: i64 = s
                .conn
                .query_row("SELECT seq FROM drawers WHERE room = 'api'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert!(hits.contains(&zk_seq));
        }
    }

    #[test]
    fn fde_inverted_tier_partitions_and_agrees() {
        for level in [SecurityLevel::HmacOnly, SecurityLevel::Sealed] {
            let (_d, mut s) = store(level);
            s.set_late(Some(Box::new(WordLate)));
            s.set_fde(true);
            s.fde_pq_min = 8; // train immediately at test scale
            s.fde_ivf_min = 16; // invert immediately at test scale
            for i in 0..80 {
                s.upsert(&drawer("w", "r", &format!("routine filler note {i}"), i))
                    .unwrap();
            }
            let target = drawer("w", "r", "kafka stream backlog rework", 100);
            s.upsert(&target).unwrap();
            let target_seq: i64 = s
                .conn
                .query_row("SELECT seq FROM drawers WHERE id = ?1", [&target.id], |r| {
                    r.get(0)
                })
                .unwrap();

            let cands = s
                .fde_candidates("kafka stream backlog", 5)
                .unwrap()
                .expect("FDE index must serve");
            assert!(
                cands.contains(&target_seq),
                "target must survive the probed head at level {level:?}"
            );

            // Centroids trained + persisted; every cached row carries a
            // real list (nothing left in -1 after the in-place rewrite).
            assert!(s.fde_ivf.borrow().is_some(), "inverted tier must train");
            let meta: i64 = s
                .conn
                .query_row("SELECT COUNT(*) FROM fde_meta WHERE key = 'ivf'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(meta, 1, "centroids must persist");
            match s.fde_cache.borrow().as_ref() {
                Some(fdeidx::FdeCache::Coded { slabs, .. }) => {
                    assert!(
                        slabs.keys().all(|l| *l >= 0),
                        "every row must be list-assigned after inversion"
                    );
                }
                _ => panic!("cache must be coded"),
            }

            // Rows rewrote in place — sealed rows stay opaque.
            let fde_dim = s.fde_encoder.borrow().as_ref().unwrap().dim();
            let blob: Vec<u8> = s
                .conn
                .query_row(
                    "SELECT fde FROM drawer_fde WHERE id = ?1",
                    [&target.id],
                    |r| r.get(0),
                )
                .unwrap();
            match level {
                SecurityLevel::HmacOnly => {
                    assert_eq!(blob.first(), Some(&2u8), "row must stay v2 codes");
                    let list = i32::from_le_bytes(blob[1..5].try_into().unwrap());
                    assert!(list >= 0, "row must carry a real list id");
                }
                SecurityLevel::Sealed => {
                    assert_ne!(
                        blob.len(),
                        5 + fde_dim / 8,
                        "sealed row must not be the plain packing"
                    );
                }
            }

            // Cold rebuild reproduces the probed candidates (lists persist
            // inside the sealed rows).
            s.fde_cache.borrow_mut().take();
            let again = s
                .fde_candidates("kafka stream backlog", 5)
                .unwrap()
                .expect("slab rebuild");
            assert_eq!(cands, again, "slab rebuild must reproduce candidates");

            // The unit-scale containment gate: the full slab scan (probe
            // disabled) must agree on the target.
            *s.fde_ivf.borrow_mut() = None;
            let full = s
                .fde_candidates("kafka stream backlog", 5)
                .unwrap()
                .expect("full scan");
            assert!(full.contains(&target_seq), "probe must not beat full scan");

            // Centroids reload from sealed meta; a post-invert write gets a
            // real list and stays findable.
            s.fde_ivf_checked.set(false);
            s.upsert(&drawer("w", "api", "zookeeper quorum flapped again", 200))
                .unwrap();
            let hits = s
                .fde_candidates("zookeeper quorum flapped", 5)
                .unwrap()
                .expect("post-invert writes must serve");
            let zk_seq: i64 = s
                .conn
                .query_row("SELECT seq FROM drawers WHERE room = 'api'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert!(hits.contains(&zk_seq));
            assert!(
                s.fde_ivf.borrow().is_some(),
                "centroids must reload from meta"
            );
        }
    }

    #[test]
    fn fde_backfill_covers_pre_enable_writes() {
        // Tokens ingested while FDE generation was off: the first FDE search
        // must backfill every FDE from the stored matrices — pure
        // arithmetic, no encoder forwards (WordLate is cheap, but the seam
        // under test is the drawer_tok → drawer_fde path).
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.set_late(Some(Box::new(WordLate)));
        for i in 0..10 {
            s.upsert(&drawer("w", "r", &format!("routine filler note {i}"), i))
                .unwrap();
        }
        let target = drawer("w", "r", "kafka stream backlog rework", 100);
        s.upsert(&target).unwrap();
        let before: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_fde", [], |r| r.get(0))
            .unwrap_or(0);
        assert_eq!(before, 0, "FDE off ⇒ no rows written at ingest");

        s.set_fde(true);
        let cands = s
            .fde_candidates("kafka stream backlog", 5)
            .unwrap()
            .expect("backfill must produce a servable index");
        let target_seq: i64 = s
            .conn
            .query_row("SELECT seq FROM drawers WHERE id = ?1", [&target.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(cands.contains(&target_seq));
        let after: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_fde", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, 11, "backfill must cover every token-bearing drawer");
    }

    /// A LateInteraction encoder that panics on doc encodes — proves a
    /// restore path never re-runs the expensive per-drawer forward.
    struct QueryOnlyLate;
    impl undercroft_core::late::LateInteraction for QueryOnlyLate {
        fn model_name(&self) -> &str {
            "word-mock" // must match WordLate so imported artifacts are used
        }
        fn dim(&self) -> usize {
            16
        }
        fn encode_doc(&self, _text: &str) -> Vec<f32> {
            panic!("restore must not re-encode documents");
        }
        fn encode_query(&self, text: &str) -> Vec<f32> {
            WordLate.encode_doc(text)
        }
    }

    #[test]
    fn token_artifacts_round_trip_without_reencoding() {
        // Source vault: sealed, encoder attached, matrices stored at write.
        let (_d1, mut src) = store(SecurityLevel::Sealed);
        src.set_late(Some(Box::new(WordLate)));
        src.upsert(&drawer("w", "r", "kafka pipeline notes", 0))
            .unwrap();
        src.upsert(&drawer("w", "r", "kafka stream backlog rework", 1))
            .unwrap();

        // Export drawers + vectors + artifacts (artifacts come out as
        // plaintext packing regardless of the source's sealing).
        let records = src.export_all_with_vectors().unwrap();
        let artifacts: Vec<Option<(String, Vec<u8>)>> = records
            .iter()
            .map(|(d, _)| src.token_artifact(&d.id).unwrap())
            .collect();
        assert!(artifacts.iter().all(Option::is_some));

        // Destination vault (also sealed, different keys): import WITHOUT
        // any encoder — then attach a query-only encoder that panics on any
        // doc encode. Rescoring must work purely from imported artifacts.
        let (_d2, mut dst) = store(SecurityLevel::Sealed);
        for ((d, v), tok) in records.iter().zip(&artifacts) {
            dst.import_record(d, Some(v.clone())).unwrap();
            let (model, packed) = tok.as_ref().unwrap();
            dst.import_token_artifact(&d.id, model, packed).unwrap();
        }
        dst.set_late(Some(Box::new(QueryOnlyLate)));
        let hits = dst
            .search("kafka stream backlog", &SearchOptions::default())
            .unwrap();
        assert!(
            hits[0].drawer.content.contains("backlog"),
            "imported matrices must drive MaxSim order: {:?}",
            hits[0].drawer.content
        );

        // The destination's at-rest blob must be re-sealed under ITS key —
        // not the source's bytes, not plaintext.
        let (src_blob, dst_blob): (Vec<u8>, Vec<u8>) = {
            let get = |s: &PalaceStore, id: &str| -> Vec<u8> {
                s.conn
                    .query_row(
                        "SELECT tok FROM drawer_tok WHERE id = ?1",
                        params![id],
                        |r| r.get(0),
                    )
                    .unwrap()
            };
            let id = &records[0].0.id;
            (get(&src, id), get(&dst, id))
        };
        let plain = &artifacts[0].as_ref().unwrap().1;
        assert_ne!(
            &dst_blob, plain,
            "sealed destination must not store plaintext"
        );
        assert_ne!(dst_blob, src_blob, "artifact must be re-sealed, not copied");

        // Garbage artifacts are rejected up front.
        assert!(dst
            .import_token_artifact("some-id", "word-mock", &[9, 9, 9])
            .is_err());
    }

    #[test]
    fn late_rescore_leaves_unencoded_rows_at_fusion_rank() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        // Written BEFORE the encoder is attached — no stored matrix.
        s.upsert(&drawer("w", "r", "kafka stream backlog rework", 0))
            .unwrap();
        s.set_late(Some(Box::new(WordLate)));
        let hits = s
            .search("kafka stream backlog", &SearchOptions::default())
            .unwrap();
        // The drawer is still found with its fusion score intact (not sunk).
        assert!(!hits.is_empty());
        assert!(hits[0].score > 0.0);
    }

    #[test]
    fn token_pq_trains_repacks_and_scores_with_luts() {
        for level in [SecurityLevel::HmacOnly, SecurityLevel::Sealed] {
            let (_d, mut s) = store(level);
            s.tok_pq_min = 4; // train immediately for the test
            s.set_late(Some(Box::new(WordLate)));
            for i in 0..6 {
                s.upsert(&drawer("w", "r", &format!("filler note number {i}"), i))
                    .unwrap();
            }
            s.upsert(&drawer("w", "r", "kafka stream backlog rework", 50))
                .unwrap();
            s.upsert(&drawer("w", "r", "kafka pipeline notes", 51))
                .unwrap();

            // First search trains the codebook, repacks every row to v2,
            // and MaxSim ordering still holds through the LUT path.
            let hits = s
                .search("kafka stream backlog", &SearchOptions::default())
                .unwrap();
            assert!(hits[0].drawer.content.contains("backlog"), "at {level:?}");
            assert!(s.tok_pq.borrow().is_some(), "codebook trained");
            let v2: i64 = {
                let blobs: Vec<(String, Vec<u8>)> = s
                    .conn
                    .prepare("SELECT id, tok FROM drawer_tok")
                    .unwrap()
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();
                blobs
                    .iter()
                    .filter(|(id, b)| s.vault.tokens_from_rest(id, b).unwrap().first() == Some(&2))
                    .count() as i64
            };
            assert_eq!(v2, 8, "every stored matrix repacked to v2 at {level:?}");

            // New writes pack v2 directly, and remain findable via LUTs.
            s.upsert(&drawer("w", "r", "zebra migration ledger", 60))
                .unwrap();
            let blob: Vec<u8> = s
                .conn
                .query_row(
                    "SELECT tok FROM drawer_tok WHERE id = (SELECT id FROM drawers WHERE seq = (SELECT MAX(seq) FROM drawers))",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let last_id: String = s
                .conn
                .query_row(
                    "SELECT id FROM drawers WHERE seq = (SELECT MAX(seq) FROM drawers)",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                s.vault.tokens_from_rest(&last_id, &blob).unwrap().first(),
                Some(&2)
            );
            let hits = s
                .search("zebra migration ledger", &SearchOptions::default())
                .unwrap();
            assert!(hits[0].drawer.content.contains("zebra"));

            // Artifacts still travel as universal v1 (importable anywhere).
            let (_, packed) = s.token_artifact(&last_id).unwrap().unwrap();
            assert_eq!(packed.first(), Some(&1), "artifact must be v1");
            assert!(undercroft_core::late::dequantize_tokens(&packed).is_some());
        }
    }

    #[test]
    fn late_backfill_encodes_missing_matrices_in_bounded_passes() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        // Three drawers ingested with no encoder → zero matrices.
        for (i, text) in ["alpha fact", "beta fact", "gamma fact"].iter().enumerate() {
            s.upsert(&drawer("w", "r", text, i as u32)).unwrap();
        }
        // Without an encoder, backfill refuses clearly.
        assert!(s.late_backfill(10).is_err());

        s.set_late(Some(Box::new(WordLate)));
        let (encoded, remaining) = s.late_backfill(2).unwrap();
        assert_eq!((encoded, remaining), (2, 1), "bounded pass");
        let (encoded, remaining) = s.late_backfill(2).unwrap();
        assert_eq!((encoded, remaining), (1, 0), "second pass completes");
        let (encoded, remaining) = s.late_backfill(2).unwrap();
        assert_eq!((encoded, remaining), (0, 0), "idempotent when covered");

        let rows: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_tok", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 3, "every drawer carries a matrix after backfill");
    }

    #[test]
    fn reranker_reorders_top_k() {
        let (_d, mut store) = store(SecurityLevel::HmacOnly);
        // Three candidates that all match the query term, of increasing length.
        store.upsert(&drawer("w", "r", "graphql", 0)).unwrap();
        store
            .upsert(&drawer("w", "r", "graphql over rest for the mobile api", 1))
            .unwrap();
        store
            .upsert(&drawer(
                "w",
                "r",
                "graphql was chosen because the mobile app needed far fewer round \
                 trips and one flexible endpoint instead of many rest calls",
                2,
            ))
            .unwrap();
        let opts = SearchOptions {
            wing: None,
            room: None,
            limit: 3,
            room_cap: None,
        };

        // Baseline (no reranker) returns all three, fusion-ordered.
        let base = store.search("graphql", &opts).unwrap();
        assert_eq!(base.len(), 3);

        // With the length reranker attached, the longest passage must be first
        // — proving the rerank score drives the final order.
        store.set_reranker(Some(Box::new(LenReranker)));
        let reranked = store.search("graphql", &opts).unwrap();
        let longest = reranked
            .iter()
            .max_by_key(|h| h.drawer.content.chars().count())
            .unwrap()
            .drawer
            .content
            .clone();
        assert_eq!(
            reranked[0].drawer.content, longest,
            "reranker should rank the longest passage first"
        );

        // Clearing the reranker restores first-pass behaviour.
        store.set_reranker(None);
        let after = store.search("graphql", &opts).unwrap();
        assert_eq!(after[0].drawer.content, base[0].drawer.content);
    }

    #[test]
    fn external_vault_enforces_vector_and_dimension() {
        let (_d, mut s) = external_store(SecurityLevel::Sealed, 4);
        assert!(s.is_external());
        let dr = drawer("w", "r", "customer prefers dark mode", 0);
        // Auto-embedding paths are refused.
        assert!(matches!(s.upsert(&dr), Err(StoreError::ExternalVault)));
        assert!(matches!(
            s.search("dark mode", &SearchOptions::default()),
            Err(StoreError::ExternalVault)
        ));
        // Wrong dimension is refused on write and on search.
        assert!(matches!(
            s.upsert_external(&dr, vec![0.1, 0.2]),
            Err(StoreError::EmbeddingDim {
                expected: 4,
                got: 2
            })
        ));
        // Correct dimension round-trips, and search uses the supplied vector.
        s.upsert_external(&dr, vec![1.0, 0.0, 0.0, 0.0]).unwrap();
        let hits = s
            .search_with_vector(
                "dark mode",
                vec![1.0, 0.0, 0.0, 0.0],
                &SearchOptions::default(),
            )
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].drawer.content, "customer prefers dark mode");
        assert!(matches!(
            s.search_with_vector("x", vec![1.0, 0.0], &SearchOptions::default()),
            Err(StoreError::EmbeddingDim {
                expected: 4,
                got: 2
            })
        ));
    }

    #[test]
    fn external_identity_recorded_and_reenforced() {
        let (dir, mut s) = external_store(SecurityLevel::Sealed, 8);
        s.upsert_external(&drawer("w", "r", "note", 0), vec![0.5; 8])
            .unwrap();
        drop(s);
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.unlock("test").unwrap();
        assert_eq!(
            PalaceStore::recorded_embedder(&vault).unwrap(),
            Some(("external:acme-embed".to_string(), 8))
        );
        // Opening the external vault with the plain hash embedder must be
        // refused — a silent embedder swap degrades recall.
        assert!(matches!(
            PalaceStore::open(mgr.unlock("test").unwrap()),
            Err(StoreError::EmbedderMismatch { .. })
        ));
    }

    #[test]
    fn external_vault_seals_supplied_vector() {
        let (dir, mut s) = external_store(SecurityLevel::Sealed, 3);
        s.upsert_external(
            &drawer("w", "r", "top-secret preference", 0),
            vec![0.11, 0.22, 0.33],
        )
        .unwrap();
        drop(s);
        let db = std::fs::read(dir.path().join("vaults/test/palace.db")).unwrap();
        assert!(
            !db.windows(9).any(|w| w == b"top-secre"),
            "external sealed vault leaked plaintext content"
        );
    }

    #[test]
    fn dedup_refresh_is_idempotent_and_audited() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let d1 = drawer("team", "facts", "the deploy target is us-east-1", 0);
        let o1 = s.save_with_dedup(&d1, 0.95).unwrap();
        assert!(o1.created && !o1.deduped);
        // Same corpus re-ingested with a fresh id: a near-duplicate refresh,
        // not a new record.
        let d2 = drawer("team", "facts", "the deploy target is us-east-1", 99);
        assert_ne!(d1.id, d2.id);
        let o2 = s.save_with_dedup(&d2, 0.95).unwrap();
        assert!(o2.deduped && !o2.created);
        assert_eq!(o2.id, d1.id, "refresh keeps the original id");
        assert_eq!(s.count().unwrap(), 1, "no near-duplicate piled up");
        // A genuinely different fact in the same room is not deduped.
        let o3 = s
            .save_with_dedup(
                &drawer("team", "facts", "the on-call rotation is weekly", 1),
                0.95,
            )
            .unwrap();
        assert!(o3.created && !o3.deduped);
        assert_eq!(s.count().unwrap(), 2);
        // The refresh was an audited update, so the chain still verifies.
        assert!(s.verify().unwrap().ok());
    }

    #[test]
    fn dedup_refresh_updates_text_in_place() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.save_with_dedup(&drawer("w", "r", "alice works at acme corporation", 0), 0.9)
            .unwrap();
        // Near-duplicate with updated wording refreshes the existing drawer.
        let o = s
            .save_with_dedup(
                &drawer("w", "r", "alice works at acme corporation now", 1),
                0.9,
            )
            .unwrap();
        assert!(o.deduped);
        let back = s.get(&o.id).unwrap().unwrap();
        assert_eq!(back.content, "alice works at acme corporation now");
    }

    #[test]
    fn crash_before_anchor_heals_without_alarm() {
        let (dir, mut s) = store(SecurityLevel::HmacOnly);
        s.upsert(&drawer("w", "r", "first fact", 0)).unwrap();
        let old_head = s.vault.chain_head_hex().to_string();
        s.upsert(&drawer("w", "r", "second fact", 1)).unwrap();
        s.upsert(&drawer("w", "r", "third fact", 2)).unwrap();

        // Simulate a crash between transaction commit and manifest anchor:
        // the database holds three chained writes, the manifest only saw
        // the first. A power loss must NOT read as tampering.
        s.vault.anchor_manifest(&old_head, 1).unwrap();
        assert!(
            s.verify().unwrap().chain_ok,
            "a behind-anchor (crash artifact) must not fail verification"
        );
        drop(s);

        // Reopen: reconciliation fast-forwards the anchor to the committed
        // head and the palace is fully healthy again.
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let s = PalaceStore::open(mgr.unlock("test").unwrap()).unwrap();
        assert_eq!(s.vault.writes(), 3, "anchor fast-forwarded");
        let db_head: String = s
            .conn
            .query_row("SELECT value FROM chain_meta WHERE key = 'head'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(s.vault.chain_head_hex(), db_head);
        assert!(s.verify().unwrap().chain_ok);
    }

    #[test]
    fn database_rollback_is_detected_at_open() {
        let (dir, mut s) = store(SecurityLevel::HmacOnly);
        s.upsert(&drawer("w", "r", "first fact", 0)).unwrap();
        s.upsert(&drawer("w", "r", "second fact", 1)).unwrap();
        let h2 = s.vault.chain_head_hex().to_string();
        s.upsert(&drawer("w", "r", "third fact", 2)).unwrap();
        drop(s);

        // Restore-an-old-database attack in miniature: erase the third
        // write from the db (data + audit + committed head) while the
        // manifest anchor still points at a head this database never
        // produces. Internally the rolled-back db is self-consistent — only
        // the out-of-database anchor exposes it.
        let db = rusqlite::Connection::open(dir.path().join("vaults/test/palace.db")).unwrap();
        db.execute(
            "DELETE FROM audit WHERE seq = (SELECT MAX(seq) FROM audit)",
            [],
        )
        .unwrap();
        db.execute(
            "DELETE FROM drawers WHERE seq = (SELECT MAX(seq) FROM drawers)",
            [],
        )
        .unwrap();
        db.execute(
            "UPDATE chain_meta SET value = ?1 WHERE key = 'head'",
            params![h2],
        )
        .unwrap();
        db.execute("UPDATE chain_meta SET value = '2' WHERE key = 'writes'", [])
            .unwrap();
        drop(db);

        let mgr = VaultManager::open(dir.path(), None).unwrap();
        match PalaceStore::open(mgr.unlock("test").unwrap()) {
            Err(StoreError::Vault(VaultError::ManifestTampered)) => {}
            Err(e) => panic!("rollback must map to ManifestTampered, got: {e}"),
            Ok(_) => panic!("rollback must be detected at open"),
        }
    }

    #[test]
    fn import_roundtrip_preserves_records() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "first memory", 0)).unwrap();
        s.upsert(&drawer("w", "r", "second memory", 1)).unwrap();
        let exported = s.export_all_with_vectors().unwrap();
        assert_eq!(exported.len(), 2);
        // Import into a fresh vault, mirroring a migration.
        let (_d2, mut s2) = store(SecurityLevel::Sealed);
        let mut n = 0u64;
        for (dr, vec) in &exported {
            if s2.import_record(dr, Some(vec.clone())).unwrap() {
                n += 1;
            }
        }
        assert_eq!(n, 2);
        assert_eq!(s2.count().unwrap(), 2);
        assert!(s2.verify().unwrap().ok());
        let hits = s2
            .search("second memory", &SearchOptions::default())
            .unwrap();
        assert!(hits.iter().any(|h| h.drawer.content == "second memory"));
    }

    #[test]
    fn external_import_requires_vector() {
        let (_d, mut s) = external_store(SecurityLevel::Sealed, 4);
        let dr = drawer("w", "r", "x", 0);
        assert!(matches!(
            s.import_record(&dr, None),
            Err(StoreError::ExternalVault)
        ));
        assert!(s.import_record(&dr, Some(vec![0.0; 4])).unwrap());
    }

    #[test]
    fn upsert_get_roundtrip_sealed() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        let dr = drawer(
            "work",
            "decisions",
            "we chose graphql over rest for the api",
            0,
        );
        assert!(s.upsert(&dr).unwrap());
        let back = s.get(&dr.id).unwrap().unwrap();
        assert_eq!(back.content, dr.content);
        assert_eq!(back.meta.wing, "work");
        // Re-upsert same slot is an update, not a new record.
        assert!(!s.upsert(&dr).unwrap());
        assert_eq!(s.count().unwrap(), 1);
    }

    #[test]
    fn sealed_content_is_not_plaintext_on_disk() {
        let (dir, mut s) = store(SecurityLevel::Sealed);
        let secret = "the launch code is very-secret-phrase-42";
        s.upsert(&drawer("w", "r", secret, 0)).unwrap();
        drop(s);
        let db = std::fs::read(dir.path().join("vaults/test/palace.db")).unwrap();
        let needle = b"very-secret-phrase-42";
        assert!(
            !db.windows(needle.len()).any(|w| w == needle),
            "plaintext leaked into sealed vault database"
        );
    }

    /// The existing at-rest test uses a secret containing no date expression
    /// and no name, so it cannot see this: *derived* structure is stored in
    /// `meta_json`, which is not sealed, and two of those fields hold spans
    /// copied verbatim out of the content. A sealed vault that encrypts the
    /// sentence and writes fragments of it in the clear beside the ciphertext
    /// has not sealed the sentence.
    #[test]
    fn sealed_vault_leaks_no_derived_fragment_of_its_content() {
        let (dir, mut s) = store(SecurityLevel::Sealed);
        // "Zerlinda" is a name the entity extractor takes; "three weeks ago"
        // is a span the temporal scanner records verbatim.
        let secret = "the passphrase came from Zerlinda three weeks ago";
        s.upsert(&drawer("w", "r", secret, 0).with_content_date(Some("2023-05-08".into())))
            .unwrap();
        drop(s);
        let db = std::fs::read(dir.path().join("vaults/test/palace.db")).unwrap();
        let leaked: Vec<&str> = ["Zerlinda", "zerlinda", "three weeks ago", "passphrase"]
            .into_iter()
            .filter(|n| db.windows(n.len()).any(|w| w == n.as_bytes()))
            .collect();
        assert!(
            leaked.is_empty(),
            "sealed vault wrote content fragments in the clear: {leaked:?}"
        );
    }

    /// What a stolen sealed-vault file reveals — asserted, so a change in
    /// either direction trips it.
    ///
    /// Content is sealed and must stay sealed; that half is the guarantee.
    /// The other half is an honest inventory of what metadata is still
    /// readable, because `meta_json` is stored unsealed and pretending
    /// otherwise would be worse than the exposure. An attacker holding the
    /// file learns the wing and room names — which in practice are topics,
    /// people, cases — the source path, when the content happened, and the
    /// dates resolved out of it. They do not learn a word of the content.
    ///
    /// This list is not an endorsement. It is the thing to shrink, and this
    /// test is what will notice when it does.
    #[test]
    fn a_sealed_vault_exposes_metadata_but_never_content() {
        let (dir, mut s) = store(SecurityLevel::Sealed);
        let mut d = Drawer::new(
            "wingsecretmerger",
            "roomdivorcecase",
            "Zerlinda signed the acquisition three weeks ago in Geneva.".into(),
            Some("/home/alice/projects/acquisition-secret/notes.md".into()),
            7,
            "addedbyprobe",
        )
        .with_content_date(Some("2023-05-08".into()));
        d.meta.hall = Some("hallsecretlabel".into());
        s.upsert(&d).unwrap();
        drop(s);
        let db = std::fs::read(dir.path().join("vaults/test/palace.db")).unwrap();
        let has = |n: &str| db.windows(n.len()).any(|w| w == n.as_bytes());

        // The guarantee: not one word of the content, nor anything derived
        // from it that copies its words.
        for secret in ["Zerlinda", "zerlinda", "Geneva", "three weeks ago"] {
            assert!(!has(secret), "content leaked into a sealed vault: {secret}");
        }

        // The inventory: readable today, and each one is a thing to fix.
        for (what, needle) in [
            ("wing name", "wingsecretmerger"),
            ("room name", "roomdivorcecase"),
            ("source path", "/home/alice/projects/acquisition-secret"),
            ("added_by", "addedbyprobe"),
            ("hall label", "hallsecretlabel"),
            ("content_date", "2023-05-08"),
            ("a date resolved out of the content", "2023-04-17"),
        ] {
            assert!(
                has(needle),
                "{what} is no longer readable — good, but update this inventory"
            );
        }
    }

    #[test]
    fn hmac_only_content_is_plaintext_but_tagged() {
        let (dir, mut s) = store(SecurityLevel::HmacOnly);
        s.upsert(&drawer("w", "r", "findable plaintext content", 0))
            .unwrap();
        drop(s);
        let db = std::fs::read(dir.path().join("vaults/test/palace.db")).unwrap();
        assert!(db.windows(8).any(|w| w == b"findable"));
    }

    #[test]
    fn search_ranks_relevant_first() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer(
            "work",
            "api",
            "we switched to graphql because rest was chatty",
            0,
        ))
        .unwrap();
        s.upsert(&drawer("home", "pets", "the cat likes the windowsill", 1))
            .unwrap();
        s.upsert(&drawer(
            "work",
            "infra",
            "postgres migration completed friday",
            2,
        ))
        .unwrap();
        let hits = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(hits[0].drawer.meta.room, "api");
        assert!(hits[0].score > hits.last().unwrap().score);
    }

    #[test]
    fn search_scopes_to_wing() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("a", "r", "shared topic alpha content", 0))
            .unwrap();
        s.upsert(&drawer("b", "r", "shared topic alpha content", 1))
            .unwrap();
        let hits = s
            .search(
                "alpha",
                &SearchOptions {
                    wing: Some("a".into()),
                    room: None,
                    limit: 10,
                    room_cap: None,
                },
            )
            .unwrap();
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|h| h.drawer.meta.wing == "a"));
    }

    #[test]
    fn verify_clean_store_passes() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        for i in 0..5 {
            s.upsert(&drawer("w", "r", &format!("memory number {i}"), i))
                .unwrap();
        }
        let report = s.verify().unwrap();
        assert!(report.ok());
        assert_eq!(report.records_checked, 5);
    }

    #[test]
    fn verify_detects_row_tampering() {
        let (dir, mut s) = store(SecurityLevel::HmacOnly);
        let dr = drawer("w", "r", "original truthful memory", 0);
        s.upsert(&dr).unwrap();
        drop(s);
        // Tamper with the row directly, bypassing the store.
        let conn = Connection::open(dir.path().join("vaults/test/palace.db")).unwrap();
        conn.execute(
            "UPDATE drawers SET content = ?1 WHERE id = ?2",
            params![b"forged memory".as_slice(), dr.id],
        )
        .unwrap();
        drop(conn);
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let s = PalaceStore::open(mgr.unlock("test").unwrap()).unwrap();
        let report = s.verify().unwrap();
        assert!(!report.ok());
        assert_eq!(report.bad_records, vec![dr.id.clone()]);
        // Reads of the tampered record must refuse, not return forged data.
        assert!(matches!(s.get(&dr.id), Err(StoreError::Integrity(_))));
    }

    #[test]
    fn verify_detects_audit_chain_tampering() {
        let (dir, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "one", 0)).unwrap();
        s.upsert(&drawer("w", "r", "two", 1)).unwrap();
        drop(s);
        // Delete an audit row (hide a write).
        let conn = Connection::open(dir.path().join("vaults/test/palace.db")).unwrap();
        conn.execute("DELETE FROM audit WHERE seq = 1", []).unwrap();
        drop(conn);
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let s = PalaceStore::open(mgr.unlock("test").unwrap()).unwrap();
        assert!(!s.verify().unwrap().chain_ok);
    }

    #[test]
    fn embedding_cache_stays_coherent() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer(
            "w",
            "r",
            "the original cached memory about databases",
            0,
        ))
        .unwrap();
        assert_eq!(s.warm_embedding_cache().unwrap(), 1);
        // Search via cache finds it.
        let hits = s
            .search("cached memory databases", &SearchOptions::default())
            .unwrap();
        assert_eq!(hits.len(), 1);
        // New upsert while warm must be searchable (cache updated).
        s.upsert(&drawer(
            "w",
            "r",
            "a second note about kubernetes upgrades",
            1,
        ))
        .unwrap();
        let hits = s
            .search("kubernetes upgrades", &SearchOptions::default())
            .unwrap();
        assert!(hits.iter().any(|h| h.drawer.content.contains("kubernetes")));
        // Delete while warm removes it from results.
        let id = hits[0].drawer.id.clone();
        s.delete_drawer(&id).unwrap();
        let hits = s
            .search("kubernetes upgrades", &SearchOptions::default())
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn fuzzy_search_tolerates_one_typo() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer(
            "w",
            "r",
            "the kubernetes cluster upgrade finished",
            0,
        ))
        .unwrap();
        // "kubernets" (missing e) and "clutser" (transposed = 2 edits, won't
        // match) — the single-typo term still anchors the hit.
        let hits = s
            .search("kubernets upgrade", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty());
        assert!(hits[0].drawer.content.contains("kubernetes"));
    }

    #[test]
    fn within_one_edit_cases() {
        assert!(within_one_edit("kubernetes", "kubernets")); // deletion
        assert!(within_one_edit("color", "colour")); // insertion
        assert!(within_one_edit("grafana", "grafena")); // substitution
        assert!(!within_one_edit("cluster", "clutser")); // transposition = 2 edits
        assert!(!within_one_edit("abc", "xyz"));
    }

    #[test]
    fn closet_index_lines() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        for i in 0..3 {
            s.upsert(&drawer(
                "team",
                "standups",
                &format!("Update {i}: Alice shipped the Billing Portal migration"),
                i,
            ))
            .unwrap();
        }
        let lines = s.closet_index(Some("team")).unwrap();
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert!(line.starts_with("team/standups n=3"));
        assert!(line.contains("alice"));
        assert!(line.contains("ids="));
    }

    #[test]
    fn fts_index_exists_only_in_hmac_only_vaults() {
        let count_fts = |s: &PalaceStore| -> i64 {
            s.conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'drawers_fts%'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        s.upsert(&drawer("w", "r", "indexed plaintext", 0)).unwrap();
        assert!(s.fts);
        assert!(count_fts(&s) > 0);
        // Sealed vaults must not persist a plaintext-derived index.
        let (_d2, s2) = store(SecurityLevel::Sealed);
        assert!(!s2.fts);
        assert_eq!(count_fts(&s2), 0);
    }

    #[test]
    fn fts_prefilter_agrees_with_full_scan() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        for i in 0..30 {
            s.upsert(&drawer("w", "r", &format!("routine note number {i}"), i))
                .unwrap();
        }
        s.upsert(&drawer(
            "w",
            "api",
            "we switched to graphql because rest was chatty",
            100,
        ))
        .unwrap();
        s.set_fts_prefilter_min(None);
        let full = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        s.set_fts_prefilter_min(Some(0));
        let pre = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(pre[0].drawer.id, full[0].drawer.id);
        assert!(pre[0].drawer.content.contains("graphql"));
    }

    #[test]
    fn fts_stays_coherent_through_update_and_delete() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        // Assert against the index itself — the full-scan fallback in
        // search() would mask a stale index.
        let fts_matches = |s: &PalaceStore, term: &str| -> i64 {
            s.conn
                .query_row(
                    "SELECT COUNT(*) FROM drawers_fts WHERE drawers_fts MATCH ?1",
                    params![term],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let mut dr = drawer("w", "r", "the elephant walked to the river", 0);
        s.upsert(&dr).unwrap();
        assert_eq!(fts_matches(&s, "elephant"), 1);
        // Same id, new content: the old term must leave the index.
        dr.content = "the giraffe reached the savanna".into();
        s.upsert(&dr).unwrap();
        assert_eq!(fts_matches(&s, "elephant"), 0);
        assert_eq!(fts_matches(&s, "giraffe"), 1);
        s.delete_drawer(&dr.id).unwrap();
        assert_eq!(fts_matches(&s, "giraffe"), 0);
        // And the prefiltered search path agrees.
        s.set_fts_prefilter_min(Some(0));
        let hits = s
            .search("giraffe savanna", &SearchOptions::default())
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn pq_prefilter_agrees_with_full_scan() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        for i in 0..30 {
            s.upsert(&drawer("w", "r", &format!("routine note number {i}"), i))
                .unwrap();
        }
        s.upsert(&drawer(
            "w",
            "api",
            "we switched to graphql because rest was chatty",
            100,
        ))
        .unwrap();
        let full = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        s.set_pq(true);
        let pre = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(pre[0].drawer.id, full[0].drawer.id);
        // The index must actually exist (not the full-scan fallback).
        let coded: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq", [], |r| r.get(0))
            .unwrap();
        assert_eq!(coded, 31, "every drawer must be PQ-coded");
        // Incremental coherence: a drawer written after the build is found.
        s.upsert(&drawer(
            "w",
            "api",
            "kafka handles the event stream backlog now",
            200,
        ))
        .unwrap();
        let hits = s
            .search("kafka event stream backlog", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("kafka"));
        // Reopen semantics: a fresh RAM cache (load-on-open path) reproduces
        // the same candidates — hmac-only scans the cache too now.
        s.pq_cache.borrow_mut().take();
        s.pq_verified.set(false);
        let again = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(again[0].drawer.id, full[0].drawer.id);
    }

    #[test]
    fn ivf_partitions_agree_with_flat_pq_and_self_heal() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        for i in 0..120 {
            s.upsert(&drawer("w", "r", &format!("routine note number {i}"), i))
                .unwrap();
        }
        s.upsert(&drawer(
            "w",
            "api",
            "we switched to graphql because rest was chatty",
            500,
        ))
        .unwrap();
        s.set_pq(true);

        // Flat PQ baseline (IVF off).
        s.set_ivf(usize::MAX, None);
        let flat = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();

        // IVF on, generous probe: same result, and the rows are partitioned.
        s.set_ivf(32, Some(4));
        let ivf = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(ivf[0].drawer.id, flat[0].drawer.id);
        let listed: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq WHERE list >= 0", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(listed, 121, "every code row must carry a list id");
        let stored_ivf: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM pq_meta WHERE key = 'ivf'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stored_ivf, 1, "IVF centroids must persist");

        // Incremental write gets a list id and stays findable through the
        // probed path.
        s.upsert(&drawer(
            "w",
            "api",
            "kafka handles the event stream backlog now",
            600,
        ))
        .unwrap();
        let unlisted: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM drawer_pq p JOIN drawers d ON d.seq = p.seq \
                 WHERE p.list = -1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(unlisted, 0, "incremental writes must be list-assigned");
        let hits = s
            .search("kafka event stream backlog", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("kafka"));

        // Outgrown partitions retrain: tripling the corpus past 2× the
        // trained size must bump trained_n on the persisted centroids.
        let before = s
            .conn
            .query_row("SELECT value FROM pq_meta WHERE key = 'ivf'", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map(|b| pq::CoarseQuantizer::from_bytes(&b).unwrap().trained_n())
            .unwrap();
        for i in 0..400 {
            s.upsert(&drawer(
                "w",
                "grow",
                &format!("expansion fact {i}"),
                1000 + i,
            ))
            .unwrap();
        }
        let _ = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        let after = s
            .conn
            .query_row("SELECT value FROM pq_meta WHERE key = 'ivf'", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map(|b| pq::CoarseQuantizer::from_bytes(&b).unwrap().trained_n())
            .unwrap();
        assert!(
            after > before * 2,
            "outgrown IVF must retrain (trained_n {before} -> {after})"
        );

        // Below the threshold a rebuild drops the partitions, not leaves
        // them stale. Model a crash that lost a code row: the row vanishes
        // AND the next open starts unverified (coherence is checked on the
        // first search after open, not per query).
        s.set_ivf(usize::MAX, None);
        s.conn
            .execute(
                "DELETE FROM drawer_pq WHERE seq IN (SELECT seq FROM drawer_pq LIMIT 1)",
                [],
            )
            .unwrap();
        s.pq_verified.set(false);
        let _ = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        let stored_ivf: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM pq_meta WHERE key = 'ivf'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stored_ivf, 0, "sub-threshold rebuild must drop IVF");
    }

    #[test]
    fn ivf_probe_finds_the_target_in_a_strict_subset() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        let target = drawer("w", "r", "topic 3 detail number 13", 13);
        for i in 0..200 {
            s.upsert(&drawer(
                "w",
                "r",
                &format!("topic {} detail number {i}", i % 10),
                i,
            ))
            .unwrap();
        }
        s.set_pq(true);
        s.set_ivf(64, Some(2));
        // Small k so the probed lists satisfy it and the early-return branch
        // (not the full-scan fallback) is what's under test.
        let qvec = s.embedder.embed("topic 3 detail number 13");
        let cands = s.pq_candidates(&qvec, 20).unwrap().expect("PQ index");
        assert_eq!(cands.len(), 20);
        let target_seq: i64 = s
            .conn
            .query_row("SELECT seq FROM drawers WHERE id = ?1", [&target.id], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(
            cands.contains(&target_seq),
            "the query's own drawer must survive a 2-list probe"
        );
        // And the probe really is a strict subset: no two lists cover the
        // whole corpus (nlist = 16 at N=200).
        let max_two_lists: i64 = s
            .conn
            .query_row(
                "SELECT COALESCE(SUM(c), 0) FROM (SELECT COUNT(*) c FROM drawer_pq \
                 GROUP BY list ORDER BY c DESC LIMIT 2)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            max_two_lists < 200,
            "a 2-list probe must scan a strict subset ({max_two_lists}/200)"
        );
    }

    #[test]
    fn pq_legacy_layout_migrates_and_updates_leave_no_duplicates() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        // A pre-IVF (v0.14.0) drawer_pq: seq-keyed rowid table.
        s.conn
            .execute_batch(
                "CREATE TABLE drawer_pq (seq INTEGER PRIMARY KEY, code BLOB NOT NULL);
                 INSERT INTO drawer_pq VALUES (1, x'00');",
            )
            .unwrap();
        for i in 0..40 {
            s.upsert(&drawer("w", "r", &format!("migration note {i}"), i))
                .unwrap();
        }
        s.set_pq(true);
        let hits = s
            .search("migration note 7", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("note 7"));
        // The legacy table must have been replaced by the clustered layout
        // and fully re-encoded.
        let (sql, rows): (String, i64) = (
            s.conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE name = 'drawer_pq'",
                    [],
                    |r| r.get(0),
                )
                .unwrap(),
            s.conn
                .query_row("SELECT COUNT(*) FROM drawer_pq", [], |r| r.get(0))
                .unwrap(),
        );
        assert!(sql.contains("WITHOUT ROWID"), "must migrate: {sql}");
        assert_eq!(rows, 40);

        // Updating a drawer (same id ⇒ same seq, embedding changes) must not
        // leave a stale row in the old list.
        let mut updated = drawer("w", "r", "migration note 3", 3);
        updated.content = "completely different content about zebras".into();
        s.upsert(&updated).unwrap();
        let dup: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) - COUNT(DISTINCT seq) FROM drawer_pq",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dup, 0, "an updated drawer must occupy exactly one list");

        // Deleting a drawer purges its code row (the scan doesn't join
        // drawers, so orphans would linger as dead candidate slots).
        let victim = drawer("w", "r", "migration note 5", 5);
        assert!(s.delete_drawer(&victim.id).unwrap());
        let orphans: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM drawer_pq WHERE seq NOT IN (SELECT seq FROM drawers)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0, "delete must purge the PQ code row");
    }

    /// The opt-in sealed page tier end to end: pages at rest with an empty
    /// tail, sealed row-count commitment, lazy per-probe decryption,
    /// single writes riding the tail until a batch folds them, updates and
    /// deletes balancing through the sealed counters without rebuilds, and
    /// event-driven format migration in both directions.
    #[test]
    fn sealed_pq_page_tier_agrees_folds_and_migrates() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.set_pq(true);
        s.set_ivf(8, None);
        s.set_pq_pages(1);
        for i in 0..40 {
            s.upsert(&drawer("w", "r", &format!("page tier note number {i}"), i))
                .unwrap();
        }
        s.upsert(&drawer(
            "w",
            "r",
            "the flux capacitor needs a gigawatt of power",
            99,
        ))
        .unwrap();
        let hits = s
            .search("flux capacitor power", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("flux"));
        let page_count = |s: &PalaceStore| -> i64 {
            s.conn
                .query_row("SELECT COUNT(*) FROM pq_page", [], |r| r.get(0))
                .unwrap()
        };
        let tail_count = |s: &PalaceStore| -> i64 {
            s.conn
                .query_row("SELECT COUNT(*) FROM drawer_pq", [], |r| r.get(0))
                .unwrap()
        };
        assert!(page_count(&s) > 0, "codes live in sealed pages");
        assert_eq!(tail_count(&s), 0, "a fresh build leaves no tail");
        assert_eq!(s.pq_count_get("rowcount").unwrap(), 41);
        // No page blob may contain a plaintext-packed code.
        {
            let pq_ref = s.pq.borrow();
            let pq = pq_ref.as_ref().expect("codebook cached");
            let code = pq.encode(&s.embedder.embed("page tier note number 7"));
            let blobs: Vec<Vec<u8>> = s
                .conn
                .prepare("SELECT blob FROM pq_page")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(
                blobs
                    .iter()
                    .all(|b| !b.windows(code.len()).any(|w| w == code.as_slice())),
                "sealed pages must be opaque"
            );
        }
        // Lazy mode: a fresh cache decrypts only the probed lists' pages
        // (nprobe = max(8, nlist/4) = 8, plus the -1 rider).
        s.pq_cache.borrow_mut().take();
        let q = s.embedder.embed("page tier note number 7");
        let got = s.pq_candidates(&q, 1).unwrap().expect("index usable");
        assert!(!got.is_empty());
        let loaded = s.pq_cache.borrow().as_ref().unwrap().loaded_count();
        assert!(
            matches!(loaded, Some(n) if (1..=9).contains(&n)),
            "probe must stay lazy (loaded {loaded:?})"
        );

        // A single write rides the tail — searchable immediately.
        s.upsert(&drawer("w", "r", "tail rider about quantum tunneling", 200))
            .unwrap();
        assert_eq!(tail_count(&s), 1);
        let hits = s
            .search("quantum tunneling", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("quantum"));
        // The next batch folds the tail into pages.
        let batch: Vec<Drawer> = (300..332)
            .map(|i| drawer("w", "r", &format!("batch fold note {i}"), i))
            .collect();
        s.upsert_many(&batch).unwrap();
        assert_eq!(tail_count(&s), 0, "batch boundary folds the tail");
        assert_eq!(s.pq_count_get("rowcount").unwrap(), 74);

        // Update a paged drawer: its stale page copy is counted out of the
        // commitment; delete another: same. No page is rewritten and the
        // next verify must NOT rebuild.
        let mut upd = drawer("w", "r", "page tier note number 3", 3);
        upd.content = "entirely new content about zeppelins".into();
        s.upsert(&upd).unwrap();
        assert_eq!(s.pq_count_get("deleted").unwrap(), 1);
        let victim = drawer("w", "r", "page tier note number 5", 5);
        assert!(s.delete_drawer(&victim.id).unwrap());
        assert_eq!(s.pq_count_get("deleted").unwrap(), 2);
        let pages_before = page_count(&s);
        s.pq_verified.set(false);
        let hits = s.search("zeppelins", &SearchOptions::default()).unwrap();
        assert!(hits[0].drawer.content.contains("zeppelins"));
        assert_eq!(
            page_count(&s),
            pages_before,
            "balanced counters must not trigger a rebuild"
        );

        // Event-driven migration OFF: pages unpack back into sealed rows.
        s.set_pq_pages(usize::MAX);
        s.pq_verified.set(false);
        let hits = s
            .search("flux capacitor power", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("flux"));
        assert_eq!(page_count(&s), 0, "pages cleared on downgrade");
        assert!(tail_count(&s) > 0, "rows restored");
        assert_eq!(s.pq_count_get("rowcount").unwrap(), 0);
        // …and back ON: rows repack into pages (orphans stay out).
        s.set_pq_pages(1);
        s.pq_verified.set(false);
        let hits = s
            .search("batch fold note 310", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("batch fold"));
        assert!(page_count(&s) > 0, "pages restored on upgrade");
        assert_eq!(tail_count(&s), 0);
        assert_eq!(s.pq_count_get("rowcount").unwrap(), 73);
        // Cold reopen sanity: everything reloads from the sealed pages.
        s.pq_cache.borrow_mut().take();
        s.pq_verified.set(false);
        let hits = s
            .search("quantum tunneling", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("quantum"));
    }

    #[test]
    fn sealed_pq_stores_nothing_plaintext_derived_in_clear() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        for i in 0..30 {
            s.upsert(&drawer("w", "r", &format!("routine note number {i}"), i))
                .unwrap();
        }
        s.upsert(&drawer(
            "w",
            "api",
            "we switched to graphql because rest was chatty",
            100,
        ))
        .unwrap();

        // Sealed baseline (decrypt-scan), then the sealed PQ path: results
        // must agree.
        let full = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        s.set_pq(true);
        let pre = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(pre[0].drawer.id, full[0].drawer.id);

        // The index exists — but nothing on disk is in clear.
        // (1) Every row's blob must differ from the plain (list ‖ code)
        //     packing of its embedding, and the list column must carry no
        //     information.
        let coded: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq", [], |r| r.get(0))
            .unwrap();
        assert_eq!(coded, 31, "sealed vaults get the PQ index too");
        let clear_lists: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq WHERE list != -1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(clear_lists, 0, "list ids must never be stored in clear");
        {
            let pq_ref = s.pq.borrow();
            let pq = pq_ref.as_ref().expect("codebook cached");
            let emb = s
                .embedder
                .embed("we switched to graphql because rest was chatty");
            let plain_code = pq.encode(&emb);
            let blobs: Vec<Vec<u8>> = s
                .conn
                .prepare("SELECT code FROM drawer_pq")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(
                blobs.iter().all(|b| !b
                    .windows(plain_code.len())
                    .any(|w| w == plain_code.as_slice())),
                "no sealed row may contain a plain code"
            );
        }
        // (2) The codebook/IVF metadata must not decode as plaintext.
        let meta: Vec<u8> = s
            .conn
            .query_row(
                "SELECT value FROM pq_meta WHERE key = 'codebook'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            pq::ProductQuantizer::from_bytes(&meta).is_none(),
            "sealed codebook must not be readable without the vault key"
        );

        // Incremental sealed write stays findable (cache kept coherent).
        s.upsert(&drawer(
            "w",
            "api",
            "kafka handles the event stream backlog now",
            200,
        ))
        .unwrap();
        let hits = s
            .search("kafka event stream backlog", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("kafka"));

        // Reopen semantics: a fresh cache (decrypt-on-open path) reproduces
        // the same candidates.
        s.pq_cache.borrow_mut().take();
        s.pq_verified.set(false);
        let again = s
            .search("why did we switch to graphql", &SearchOptions::default())
            .unwrap();
        assert_eq!(again[0].drawer.id, full[0].drawer.id);
    }

    #[test]
    fn fts_prefilter_keeps_one_typo_matches() {
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        s.set_fts_prefilter_min(Some(0));
        s.upsert(&drawer(
            "w",
            "r",
            "the kubernetes cluster upgrade finished",
            0,
        ))
        .unwrap();
        // "kubernets" shares the 4-char prefix, so the prefilter keeps the
        // row and the fuzzy scorer still anchors the hit.
        let hits = s
            .search("kubernets upgrade", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty());
        assert!(hits[0].drawer.content.contains("kubernetes"));
    }

    #[test]
    fn fts_backfills_missing_index_on_open() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::HmacOnly).unwrap();
        let mut s = PalaceStore::open(vault).unwrap();
        s.upsert(&drawer("w", "r", "memory written before the index", 0))
            .unwrap();
        drop(s);
        // Simulate a vault predating the feature (or a dropped index). The
        // external-content triggers an older build installed are gone now, so
        // dropping the table is the whole simulation.
        let conn = Connection::open(dir.path().join("vaults/test/palace.db")).unwrap();
        conn.execute_batch("DROP TABLE drawers_fts;").unwrap();
        drop(conn);
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let mut s = PalaceStore::open(mgr.unlock("test").unwrap()).unwrap();
        s.set_fts_prefilter_min(Some(0));
        let hits = s
            .search("memory written before", &SearchOptions::default())
            .unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn bm25_ranks_rare_term_over_common_term() {
        // A term that appears in almost every drawer (IDF≈0) should lose to
        // a rare, discriminating term — something the legacy term-overlap
        // fraction, which weights every matched term equally, cannot do.
        let (_d, mut s) = store(SecurityLevel::Sealed);
        for i in 0..12 {
            s.upsert(&drawer(
                "w",
                "r",
                &format!("the system logged an event {i}"),
                i,
            ))
            .unwrap();
        }
        // One drawer additionally mentions a rare term.
        s.upsert(&drawer(
            "w",
            "r",
            "the system logged an event about xylophone calibration",
            99,
        ))
        .unwrap();
        s.set_fusion(Fusion::Bm25);
        let hits = s
            .search("system xylophone", &SearchOptions::default())
            .unwrap();
        assert!(hits[0].drawer.content.contains("xylophone"));
    }

    #[test]
    fn bm25_and_rrf_still_find_relevant_first() {
        // Both fusion modes must preserve the basic ranking contract.
        for mode in [Fusion::Bm25, Fusion::Rrf] {
            let (_d, mut s) = store(SecurityLevel::Sealed);
            s.upsert(&drawer(
                "work",
                "api",
                "we switched to graphql because rest was chatty",
                0,
            ))
            .unwrap();
            s.upsert(&drawer("home", "pets", "the cat likes the windowsill", 1))
                .unwrap();
            s.upsert(&drawer(
                "work",
                "infra",
                "postgres migration completed friday",
                2,
            ))
            .unwrap();
            s.set_fusion(mode);
            let hits = s
                .search("why did we switch to graphql", &SearchOptions::default())
                .unwrap();
            assert_eq!(hits[0].drawer.meta.room, "api", "mode {mode:?}");
        }
    }

    #[test]
    fn bm25_fusion_tolerates_one_typo() {
        // The typo tolerance carries into BM25 term matching.
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer(
            "w",
            "r",
            "the kubernetes cluster upgrade finished",
            0,
        ))
        .unwrap();
        s.upsert(&drawer("w", "r", "unrelated note about the weather", 1))
            .unwrap();
        s.set_fusion(Fusion::Bm25);
        let hits = s
            .search("kubernets upgrade", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty());
        assert!(hits[0].drawer.content.contains("kubernetes"));
    }

    /// The headline. Before segmentation these queries returned an **empty
    /// vector**, not a bad ranking: the clause was one token so BM25 scored
    /// zero, the hash embedder shared no feature so cosine was 0.0 and
    /// `semantic` exactly 0.500, and the relevance gate
    /// (`lexical > 0.0 || semantic > 0.56`) then dropped the only drawer that
    /// contained the answer. An empty result reads as an empty vault.
    ///
    /// So the assertion that matters is "did anything come back at all".
    #[test]
    fn a_query_finds_the_drawer_that_contains_it() {
        let cases = [
            ("北京", "我昨天去了北京参加会议"),
            ("東京", "昨日は東京で会議に参加しました"),
            ("한국어", "한국어는 어렵다"),
            ("ភ្នំពេញ", "ខ្ញុំបានទៅភ្នំពេញកាលពីម្សិលមិញ"),
            ("ประชุม", "ประชุมทีมงานที่กรุงเทพ"),
            // Arabic: the word is present, wearing its definite article.
            ("كتاب", "قرأت الكتاب أمس"),
        ];
        for (query, content) in cases {
            let (_d, mut s) = store(SecurityLevel::Sealed);
            s.upsert(&drawer("w", "r", content, 0)).unwrap();
            s.upsert(&drawer("w", "r", "an unrelated note about the weather", 1))
                .unwrap();
            let hits = s.search(query, &SearchOptions::default()).unwrap();
            assert!(!hits.is_empty(), "query {query:?} returned nothing");
            assert_eq!(hits[0].drawer.content, content, "query {query:?}");
            assert!(hits[0].lexical > 0.0, "query {query:?} matched no term");
        }
    }

    /// Segmentation must not turn every short CJK term into a wildcard. The
    /// byte-gated tolerance opened at two characters, where one substitution
    /// is a different city, not a typo.
    #[test]
    fn a_substitution_in_cjk_is_a_different_word_not_a_typo() {
        assert!(!fuzzy_eq("北京", "東京"));
        assert!(!fuzzy_eq("中国", "美国"));
        assert!(!fuzzy_eq("한국", "중국"));
        // Insertion and deletion still pass — that is a particle arriving.
        assert!(fuzzy_eq("한국어", "한국어는"));
        assert!(fuzzy_eq("北京", "北京市"));
        // And the Latin tolerance is untouched.
        assert!(fuzzy_eq("kubernetes", "kubernets"));
        assert!(!fuzzy_eq("cat", "bat"), "below the byte gate, as before");
    }

    #[test]
    fn the_right_city_outranks_the_one_sharing_a_character() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "我昨天去了北京参加会议", 0))
            .unwrap();
        s.upsert(&drawer("w", "r", "東京タワーに行きました", 1))
            .unwrap();
        let hits = s.search("北京", &SearchOptions::default()).unwrap();
        assert!(!hits.is_empty());
        assert!(
            hits[0].drawer.content.contains("北京"),
            "got {:?}",
            hits[0].drawer.content
        );
    }

    /// `drawers_fts` indexes raw content under unicode61, which cannot agree
    /// with segmented query terms. The prefilter only fails safe when it
    /// matches *nothing*; a non-empty wrong answer cuts the right drawer out
    /// of the scan and out of the cosine path with it.
    #[test]
    fn the_fts_prefilter_is_bypassed_for_segmented_scripts() {
        assert!(needs_full_scan(&["北京".to_string()]));
        assert!(needs_full_scan(&["كتاب".to_string()]));
        assert!(!needs_full_scan(&["beijing".to_string()]));
        assert!(!needs_full_scan(&["москва".to_string()]));

        // And end to end, with the prefilter forced on.
        let (_d, mut s) = store(SecurityLevel::HmacOnly);
        assert!(s.fts, "hmac-only vaults index for FTS");
        s.set_fts_prefilter_min(Some(1));
        s.upsert(&drawer("w", "r", "我昨天去了北京参加会议", 0))
            .unwrap();
        for i in 1..5 {
            s.upsert(&drawer("w", "r", &format!("filler note {i}"), i))
                .unwrap();
        }
        let hits = s.search("北京", &SearchOptions::default()).unwrap();
        assert!(!hits.is_empty(), "prefilter cut the only matching drawer");
        assert!(hits[0].drawer.content.contains("北京"));
    }

    /// The regression guard. Latin-script retrieval must be untouched — the
    /// segmenter only claims scripts that do not delimit their own words.
    #[test]
    fn latin_retrieval_is_unchanged() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer(
            "w",
            "r",
            "the kubernetes cluster upgrade finished",
            0,
        ))
        .unwrap();
        s.upsert(&drawer("w", "r", "unrelated note about the weather", 1))
            .unwrap();
        for mode in [Fusion::Bm25, Fusion::Rrf, Fusion::Legacy] {
            s.set_fusion(mode);
            let hits = s
                .search("kubernetes upgrade", &SearchOptions::default())
                .unwrap();
            assert!(!hits.is_empty(), "mode {mode:?}");
            assert!(
                hits[0].drawer.content.contains("kubernetes"),
                "mode {mode:?}"
            );
        }
    }

    /// A long segmented clause must not be buried by BM25 length
    /// normalization just because it expanded into n-grams.
    #[test]
    fn ngram_expansion_does_not_inflate_document_length() {
        let long = "我昨天去了北京参加会议然后回到上海继续工作并且写了一份很长的报告";
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", long, 0)).unwrap();
        s.upsert(&drawer("w", "r", "今天天气很好", 1)).unwrap();
        let hits = s.search("北京", &SearchOptions::default()).unwrap();
        assert!(!hits.is_empty());
        assert_eq!(hits[0].drawer.content, long);
    }

    // ------------------------------------------------------------------
    // Embedder identity migration
    // ------------------------------------------------------------------

    /// Environment variables are process-global and `cargo test` runs threads
    /// in parallel, so two tests toggling `UNDERCROFT_FORCE_EMBEDDER` race and
    /// one of them reads the other's value. Every such test takes this first.
    /// (`unwrap_or_else(into_inner)` because a panic inside one holder must not
    /// poison the rest into failing for the wrong reason.)
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Put a vault back into the state a v1 build left it in: the old
    /// identity recorded, and embeddings that are not what v2 would produce.
    /// Junk vectors are the point — if the migration does not actually run,
    /// the drawer stays unfindable and the test says so.
    fn make_it_look_like_v1(s: &PalaceStore) {
        s.conn
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'embedder_name'",
                params![undercroft_core::embed::HASH_EMBEDDER_V1],
            )
            .unwrap();
        let junk = vec![0.0f32; undercroft_core::embed::EMBED_DIM];
        let ids: Vec<String> = s
            .conn
            .prepare("SELECT id FROM drawers")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for id in ids {
            let blob = s.vault.embedding_at_rest(&id, &junk);
            s.conn
                .execute(
                    "UPDATE drawers SET embedding = ?1 WHERE id = ?2",
                    params![blob, id],
                )
                .unwrap();
        }
    }

    fn reopen_vault(dir: &TempDir) -> Result<PalaceStore, StoreError> {
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        PalaceStore::open(mgr.unlock("test").unwrap())
    }

    /// Every known predecessor migrates, not just the oldest. v2 shipped in no
    /// tag but existed on the branch, and a vault built from it holds vectors
    /// from a different token space.
    #[test]
    fn every_known_predecessor_identity_migrates() {
        for from in [
            undercroft_core::embed::HASH_EMBEDDER_V1,
            undercroft_core::embed::HASH_EMBEDDER_V2,
        ] {
            let dir = TempDir::new().unwrap();
            let mgr = VaultManager::open(dir.path(), None).unwrap();
            let vault = mgr.create("test", SecurityLevel::Sealed).unwrap();
            {
                let mut s = PalaceStore::open(vault).unwrap();
                s.upsert(&drawer("w", "r", "the heron files verbatim drawers", 0))
                    .unwrap();
                make_it_look_like_v1(&s);
                s.conn
                    .execute(
                        "UPDATE meta SET value = ?1 WHERE key = 'embedder_name'",
                        params![from],
                    )
                    .unwrap();
            }
            let s = reopen_vault(&dir).unwrap_or_else(|_| panic!("{from} must migrate"));
            let stored: String = s
                .conn
                .query_row(
                    "SELECT value FROM meta WHERE key='embedder_name'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(stored, undercroft_core::embed::HASH_EMBEDDER, "from {from}");
            let hits = s
                .search("heron verbatim", &SearchOptions::default())
                .unwrap();
            assert!(!hits.is_empty(), "from {from}");
        }
    }

    /// Upgrading the binary must not hand the user a broken vault, and must
    /// not require them to know an env var exists.
    #[test]
    fn a_v1_vault_migrates_itself_on_open() {
        for level in [SecurityLevel::Sealed, SecurityLevel::HmacOnly] {
            let dir = TempDir::new().unwrap();
            let mgr = VaultManager::open(dir.path(), None).unwrap();
            let vault = mgr.create("test", level).unwrap();
            {
                let mut s = PalaceStore::open(vault).unwrap();
                s.upsert(&drawer("w", "r", "the heron files verbatim drawers", 0))
                    .unwrap();
                s.upsert(&drawer("w", "r", "unrelated note about rain", 1))
                    .unwrap();
                make_it_look_like_v1(&s);
            }

            let s = reopen_vault(&dir).expect("a known upgrade must not refuse to open");

            let stored: String = s
                .conn
                .query_row(
                    "SELECT value FROM meta WHERE key='embedder_name'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(stored, undercroft_core::embed::HASH_EMBEDDER, "{level:?}");

            // The vectors were actually rewritten, not just the label.
            let hits = s
                .search("heron verbatim", &SearchOptions::default())
                .unwrap();
            assert!(!hits.is_empty(), "{level:?}");
            assert!(hits[0].drawer.content.contains("heron"), "{level:?}");
            assert!(hits[0].semantic > 0.5, "{level:?} — still the junk vector");
        }
    }

    /// The migration writes the new identity last, so an interrupted walk
    /// leaves the vault claiming v1 and the next open simply does it again.
    /// Re-embedding is idempotent, so repeating it is free of consequence.
    #[test]
    fn an_interrupted_migration_is_retried_and_idempotent() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::Sealed).unwrap();
        {
            let mut s = PalaceStore::open(vault).unwrap();
            s.upsert(&drawer("w", "r", "the heron files verbatim drawers", 0))
                .unwrap();
            make_it_look_like_v1(&s);
        }
        let read_vector = |s: &PalaceStore| -> Vec<f32> {
            let (id, blob): (String, Vec<u8>) = s
                .conn
                .query_row("SELECT id, embedding FROM drawers", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .unwrap();
            s.vault.embedding_from_rest(&id, &blob).unwrap()
        };
        let first = {
            let s = reopen_vault(&dir).unwrap();
            read_vector(&s)
        };
        // Pretend the identity write never landed, and run it again.
        {
            let s = reopen_vault(&dir).unwrap();
            s.conn
                .execute(
                    "UPDATE meta SET value = ?1 WHERE key = 'embedder_name'",
                    params![undercroft_core::embed::HASH_EMBEDDER_V1],
                )
                .unwrap();
        }
        let s = reopen_vault(&dir).unwrap();
        // Sealed embeddings carry a random nonce, so the ciphertext differs
        // between runs while the vector underneath must not.
        assert_eq!(first, read_vector(&s), "re-running the walk moved a vector");
        let hits = s
            .search("heron verbatim", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty());
    }

    /// One damaged drawer must not cost the user the other fifty thousand —
    /// especially since `verify`, the only tool that can name the damage,
    /// needs an open store to run.
    #[test]
    fn one_unreadable_drawer_does_not_make_the_vault_unopenable() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::Sealed).unwrap();
        let victim: String;
        {
            let mut s = PalaceStore::open(vault).unwrap();
            s.upsert(&drawer("w", "r", "the heron files verbatim drawers", 0))
                .unwrap();
            s.upsert(&drawer("w", "r", "a second intact drawer about rain", 1))
                .unwrap();
            victim = s
                .conn
                .query_row("SELECT id FROM drawers ORDER BY seq LIMIT 1", [], |r| {
                    r.get(0)
                })
                .unwrap();
            // Corrupt the tag so `get` fails its HMAC check on this row only.
            s.conn
                .execute(
                    "UPDATE drawers SET tag = ?1 WHERE id = ?2",
                    params![vec![0u8; 32], victim],
                )
                .unwrap();
            make_it_look_like_v1(&s);
        }
        let s = reopen_vault(&dir).expect("one bad drawer must not lock the vault");

        // The walk continued past the damaged row: the intact drawer now
        // holds the vector v2 produces for its content.
        let (intact_id, blob, content): (String, Vec<u8>, Vec<u8>) = s
            .conn
            .query_row(
                "SELECT id, embedding, content FROM drawers WHERE id != ?1",
                params![victim],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let stored = s.vault.embedding_from_rest(&intact_id, &blob).unwrap();
        let plain = s.vault.content_from_rest(&intact_id, &content).unwrap();
        let expected = HashEmbedder.embed(std::str::from_utf8(&plain).unwrap());
        assert_eq!(stored.len(), expected.len());
        assert!(
            undercroft_core::embed::cosine(&stored, &expected) > 0.99,
            "the intact drawer was not re-embedded"
        );

        // And `verify` — the only tool that can name the damage — is now
        // reachable, which it would not be if open had failed.
        let report = s.verify().unwrap();
        assert!(
            report.bad_records.contains(&victim),
            "verify should still name the damaged drawer"
        );
        // Note: `search` remains intolerant of a corrupt row (the candidate
        // loader propagates the HMAC failure). That predates this change and
        // is not addressed here — what the tolerant walk buys is that `open`,
        // and therefore `verify` and `repair`, still work.
    }

    /// The override must not turn a read-only open into a write either.
    #[test]
    fn force_embedder_writes_nothing_on_a_read_only_open() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::Sealed).unwrap();
        {
            let mut s = PalaceStore::open(vault).unwrap();
            s.upsert(&drawer("w", "r", "the heron files verbatim drawers", 0))
                .unwrap();
            // An identity this build does not know how to migrate.
            s.conn
                .execute(
                    "UPDATE meta SET value = 'some-onnx-model' WHERE key = 'embedder_name'",
                    [],
                )
                .unwrap();
        }
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("UNDERCROFT_FORCE_EMBEDDER", "1");
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let opened =
            PalaceStore::open_read_only(mgr.unlock("test").unwrap(), Box::new(HashEmbedder));
        std::env::remove_var("UNDERCROFT_FORCE_EMBEDDER");
        let s = opened.expect("the override should still let a read-only open through");
        let stored: String = s
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key='embedder_name'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            stored, "some-onnx-model",
            "a read-only open recorded a new identity"
        );
    }

    /// A read-only role serves reads across the upgrade; it does not rewrite
    /// the vault it was told not to write to.
    #[test]
    fn a_read_only_open_does_not_migrate() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::Sealed).unwrap();
        {
            let mut s = PalaceStore::open(vault).unwrap();
            s.upsert(&drawer("w", "r", "the heron files verbatim drawers", 0))
                .unwrap();
            make_it_look_like_v1(&s);
        }
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let s = PalaceStore::open_read_only(mgr.unlock("test").unwrap(), Box::new(HashEmbedder))
            .expect("a read-only open must still succeed");
        let stored: String = s
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key='embedder_name'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            stored,
            undercroft_core::embed::HASH_EMBEDDER_V1,
            "a read-only open rewrote the vault"
        );
        // The lexical leg still works, which is the point of degrading
        // rather than refusing.
        let hits = s
            .search("heron verbatim", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty());
    }

    /// The documented override has to dominate every identity path, including
    /// the one that now does fallible work.
    #[test]
    fn force_embedder_still_overrides_a_known_upgrade() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::Sealed).unwrap();
        {
            let mut s = PalaceStore::open(vault).unwrap();
            s.upsert(&drawer("w", "r", "the heron files verbatim drawers", 0))
                .unwrap();
            make_it_look_like_v1(&s);
        }
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("UNDERCROFT_FORCE_EMBEDDER", "1");
        let s = reopen_vault(&dir).unwrap();
        // Identity recorded, but no walk ran — the junk vector is still there.
        let hits = s
            .search("heron verbatim", &SearchOptions::default())
            .unwrap();
        let migrated = hits.first().map(|h| h.semantic > 0.5).unwrap_or(false);
        std::env::remove_var("UNDERCROFT_FORCE_EMBEDDER");
        assert!(!migrated, "the override should have skipped the migration");
    }

    /// The reachable half of morphology, and the boundary of it.
    #[test]
    fn a_word_family_is_matched_but_a_false_friend_is_not() {
        for (a, b) in [
            ("documentation", "document"),
            ("documentation", "documented"),
            ("documentation", "documents"),
            ("encryption", "encrypt"),
            ("konfiguration", "konfigurationen"),
            ("ბიბლიოთეკა", "ბიბლიოთეკაში"),
        ] {
            assert!(same_word_family(a, b), "{a} / {b} should be a family");
        }
        // Rejected: the systematic English -tive/-tion class sits at a shared
        // prefix of exactly 6, and is length-symmetric.
        for (a, b) in [
            ("positive", "position"),
            ("relative", "relation"),
            ("creative", "creation"),
            ("transfer", "transform"),
            ("personal", "personnel"),
            ("сообщение", "сообщество"),
            ("κατάσταση", "κατάστημα"),
            ("представление", "представитель"),
        ] {
            assert!(!same_word_family(a, b), "{a} / {b} must not be a family");
        }
        // Out of reach, and honestly so: these share too little.
        for (a, b) in [("книга", "книге"), ("running", "run"), ("πόλη", "πόλεων")]
        {
            assert!(!same_word_family(a, b), "{a} / {b}");
        }
        // A bigram token from a segmented script must never reach this rule.
        assert!(!same_word_family("北京", "北京市"));
    }

    /// Compounding's other half: a suffix or interior relation, which no
    /// prefix rule can see.
    #[test]
    fn a_contained_word_is_found_at_any_offset() {
        for (a, b) in [
            ("dampfschiff", "donaudampfschifffahrt"),
            ("ausbildung", "bundesausbildungsfoerderungsgesetz"),
            ("konfiguration", "systemkonfiguration"),
        ] {
            assert!(contains_a_long_word(a, b), "{a} in {b}");
            assert!(contains_a_long_word(b, a), "and symmetrically");
        }
        // Below the eight-character floor: short stems are a different gap and
        // this must not pretend to solve them.
        assert!(!contains_a_long_word("run", "running"));
        assert!(!contains_a_long_word("ability", "vulnerability"), "7 chars");
        // The decisive safety property: none of gap (a)'s false friends.
        for (a, b) in [
            ("город", "горох"),
            ("книга", "книге"),
            ("positive", "position"),
        ] {
            assert!(!contains_a_long_word(a, b), "{a} / {b}");
        }
        // A bigram token from a segmented script must never reach this rule.
        assert!(!contains_a_long_word("北京", "北京市"));
    }

    /// The accepted cost, pinned so it is a recorded decision rather than a
    /// surprise in a bug report. All of it is approximate-channel only.
    #[test]
    fn containment_admits_these_false_pairs_and_we_accept_it() {
        assert!(contains_a_long_word("counting", "accounting"));
        assert!(contains_a_long_word("knowledge", "acknowledged"));
        // Derivational prefixes: morphologically related, semantically
        // opposite. Correct as evidence, wrong as a synonym — which is exactly
        // what a capped, half-weighted approximate channel is for.
        assert!(contains_a_long_word("compatible", "incompatible"));
        assert!(contains_a_long_word("resolved", "unresolved"));
    }

    /// Containment is now *admitting* evidence, in its own channel.
    ///
    /// It stays out of `lexical_exact`, because the drawer did not say the
    /// word — it said something built on it — and a caller asking "why did
    /// this come back" is entitled to that distinction. But it clears the
    /// gate, which it could not do while it sat in the approximate channel.
    #[test]
    fn containment_admits_in_its_own_channel() {
        let cand = |content: &'static str| {
            let s = segment(content);
            let units = s.len as f32;
            let (tokens, ngram): (Vec<String>, Vec<bool>) = s
                .tokens
                .into_iter()
                .zip(s.ngram)
                .filter(|(t, _)| t.len() > 1)
                .unzip();
            Candidate {
                drawer: drawer("w", "r", content, 0),
                semantic: 0.0,
                recency: 0.0,
                units,
                tokens,
                ngram,
            }
        };
        let qterms = tokenize("dampfschifffahrt");
        let cands = vec![
            cand("die donaudampfschifffahrtsgesellschaft tagt heute"),
            cand("ein bericht ueber ganz andere dinge"),
        ];
        let b = bm25_raw(&qterms, &cands);
        assert_eq!(b.exact[0], 0.0, "the drawer did not say the word");
        assert!(b.morph[0] > 0.0, "but it holds a word built on it");
        assert!(b.raw[0] > 0.0, "and it ranks");
        assert_eq!(b.morph[1], 0.0, "the unrelated drawer gets nothing");
        // Discounted for ranking exactly like approximate evidence: an exact
        // match on the same term must still outrank it.
        let exact_cands = vec![cand("dampfschifffahrt ist das thema")];
        let e = bm25_raw(&qterms, &exact_cands);
        assert!(e.exact[0] > 0.0);
    }

    /// The failure D1 was decided to close. Measured, the cosine leg carries
    /// `Dampfschiff`/`Donaudampfschifffahrt` at 0.82 on a bare pair and 0.51
    /// past ~80 words, so before the morph channel a compound drawer at real
    /// chunk length had neither exact lexical evidence nor a passing cosine
    /// and was dropped rather than mis-ranked.
    #[test]
    fn a_compound_is_found_at_chunk_length() {
        let filler = " das ist ein sehr langer text mit vielen weiteren woertern darin";
        let content = format!(
            "die Donaudampfschifffahrtsgesellschaft{}{}{}{}",
            filler, filler, filler, filler
        );
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", &content, 0)).unwrap();
        s.upsert(&drawer("w", "r", "an unrelated note about the weather", 1))
            .unwrap();
        let hits = s
            .search("dampfschifffahrt", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty(), "the compound drawer was dropped");
        let h = &hits[0];
        assert!(h.drawer.content.starts_with("die Donau"));
        assert_eq!(h.lexical_exact, 0.0, "it never claimed to be exact");
        assert!(
            h.lexical_morph > 0.0,
            "it was admitted on the morph channel"
        );
    }

    /// The gate is a raw cosine of 0.12, and it only means anything because
    /// feature hashing puts unrelated text at ~0. This is the acceptance test
    /// for any future embedder: a model whose unrelated-pair floor exceeds it
    /// makes the semantic disjunct vacuously true and retires the relevance
    /// gate for every query in every language, by configuration alone.
    #[test]
    fn the_semantic_gate_is_calibrated_to_the_default_embedder() {
        let e = HashEmbedder;
        let ceiling = 2.0 * SEMANTIC_ADMISSION_GATE - 1.0;
        let unrelated = [
            ("the quarterly revenue report", "私は昨日公園へ行きました"),
            ("kubernetes cluster autoscaling", "ذهبت إلى المستشفى أمس"),
            (
                "my cat sleeps on the windowsill",
                "πήγα στην Αθήνα το καλοκαίρι",
            ),
            (
                "database migration rollback",
                "그는 어제 서울에서 회의에 참석했습니다",
            ),
        ];
        for (a, b) in unrelated {
            let c = undercroft_core::embed::cosine(&e.embed(a), &e.embed(b));
            assert!(
                c < ceiling,
                "unrelated pair scored {c}, at or above the gate's {ceiling}"
            );
        }
    }

    /// A family match must never *admit* a drawer — only reorder one already
    /// admitted. This is the containment the channel split exists to provide.
    #[test]
    fn a_family_match_is_approximate_evidence_only() {
        let cand = |content: &'static str| {
            let s = segment(content);
            let units = s.len as f32;
            let (tokens, ngram): (Vec<String>, Vec<bool>) = s
                .tokens
                .into_iter()
                .zip(s.ngram)
                .filter(|(t, _)| t.len() > 1)
                .unzip();
            Candidate {
                drawer: drawer("w", "r", content, 0),
                semantic: 0.0,
                recency: 0.0,
                units,
                tokens,
                ngram,
            }
        };
        let qterms = tokenize("documentation");
        let cands = vec![
            cand("the document was filed"),
            cand("read the documentation"),
        ];
        let b = bm25_raw(&qterms, &cands);
        assert_eq!(b.exact[0], 0.0, "a family match is not exact evidence");
        assert!(b.raw[0] > 0.0, "but it does contribute to ranking");
        assert!(b.exact[1] > 0.0, "the literal term is exact evidence");
        assert!(b.raw[1] > b.raw[0], "exact must outrank family");
    }

    /// End to end, through the real gate: a query typed the plain way must
    /// find a drawer written the marked way, in each script the fold covers.
    #[test]
    fn a_folded_query_finds_the_unfolded_drawer() {
        let cases = [
            ("izmir", "the meeting in İzmir was short"),
            ("strasse", "sie wohnt in der Hauptstraße"),
            ("lodz", "a postcard from Łódź"),
            ("2023", "التقرير عن سنة ٢٠٢٣"),
            ("الكتاب", "قَرَأتُ الكِتَابَ أمس"),
            ("kitab", "قرأت الكتاب أمس"),  // control: must NOT match
            ("athina", "Πήγα στην Αθήνα"), // control: must NOT match
        ];
        for (query, content) in cases {
            let (_d, mut s) = store(SecurityLevel::Sealed);
            s.upsert(&drawer("w", "r", content, 0)).unwrap();
            let hits = s.search(query, &SearchOptions::default()).unwrap();
            let found = hits.iter().any(|h| h.drawer.content == content);
            // The two controls are transliterations, not folds — the fold is a
            // comparison key, never a romanizer, and nothing here should
            // suggest otherwise.
            let expect = !matches!(query, "kitab" | "athina");
            assert_eq!(found, expect, "query {query:?} against {content:?}");
        }
    }

    /// Greek within its own script, which the fold does cover.
    #[test]
    fn an_unaccented_greek_query_finds_its_drawer() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "Πήγα στην Αθήνα το καλοκαίρι", 0))
            .unwrap();
        let hits = s.search("ΑΘΗΝΑ", &SearchOptions::default()).unwrap();
        assert!(!hits.is_empty(), "all-caps Greek found nothing");
    }

    /// The prefilter used to hold raw content under unicode61, which folds
    /// Latin diacritics and nothing else. It returned a non-empty *wrong* set
    /// for `izmir` and cut the right drawer out of the scan. The index is
    /// folded now, so its token set is a superset of ours over the same text:
    /// it can over-return, which the scan filters, but never under-return.
    #[test]
    fn the_folded_fts_index_finds_folded_queries() {
        // Unchanged: a pure-Latin query still uses the prefilter.
        assert!(!needs_full_scan(&["strasse".to_string()]));

        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::HmacOnly).unwrap();
        let mut s = PalaceStore::open(vault).unwrap();
        assert!(s.fts);
        s.set_fts_prefilter_min(Some(1));
        s.upsert(&drawer("w", "r", "das Büro in der Hauptstraße", 0))
            .unwrap();
        s.upsert(&drawer("w", "r", "the meeting in İzmir was short", 1))
            .unwrap();
        for i in 2..8 {
            s.upsert(&drawer("w", "r", &format!("filler note {i}"), i))
                .unwrap();
        }
        for (query, want) in [("strasse", "Hauptstraße"), ("izmir", "İzmir")] {
            let hits = s.search(query, &SearchOptions::default()).unwrap();
            assert!(
                hits.iter().any(|h| h.drawer.content.contains(want)),
                "prefilter cut the drawer for {query:?}"
            );
        }
    }

    /// The defect this closes: a shared two-character substring was literal
    /// equality, so it filled the EXACT slot and admitted. Measured on a real
    /// 50k-word Arabic corpus, one content word admitted **74.3%** of a
    /// 120-drawer vault — against 6.9% for Greek through the same code, a
    /// 10.8x difference produced by one line in `script.rs`.
    #[test]
    fn an_arabic_bigram_alone_does_not_admit() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        // None of these is about a book. Each shares at most a bigram with the
        // query, which is exactly the evidence that used to admit.
        let unrelated = [
            "ذهبت إلى المستشفى أمس",
            "الطقس جميل اليوم في المدينة",
            "اشتريت قطارا صغيرا لابني",
            "كريم رجل كريم مع أصدقائه",
            "مصرف كبير في وسط البلد",
        ];
        for (i, c) in unrelated.iter().enumerate() {
            s.upsert(&drawer("w", "r", c, i as u32)).unwrap();
        }
        s.upsert(&drawer("w", "r", "قرأت الكتاب أمس في البيت", 99))
            .unwrap();

        let hits = s.search("الكتاب", &SearchOptions::default()).unwrap();
        assert!(!hits.is_empty(), "the drawer that says it must come back");
        assert!(hits[0].drawer.content.contains("الكتاب"));
        // The whole point: the rest of the vault is no longer admitted on a
        // shared fragment. Before this change every one of these cleared the
        // gate in the exact channel.
        assert!(
            hits.len() <= 2,
            "admitted {} of 6 drawers on one query: {:?}",
            hits.len(),
            hits.iter().map(|h| &h.drawer.content).collect::<Vec<_>>()
        );
    }

    /// ...and the clitic cases it must not cost. These are carried by
    /// whole-word containment, not by bigram equality.
    #[test]
    fn arabic_clitics_survive_the_tightening() {
        for (query, content) in [
            ("كتاب", "قرأت الكتاب أمس"),
            ("مكتبة", "ذهبت إلى بالمكتبة صباحا"),
            ("معلم", "حضر المعلمون الاجتماع"),
        ] {
            let (_d, mut s) = store(SecurityLevel::Sealed);
            s.upsert(&drawer("w", "r", content, 0)).unwrap();
            s.upsert(&drawer("w", "r", "الطقس جميل اليوم", 1)).unwrap();
            let hits = s.search(query, &SearchOptions::default()).unwrap();
            assert!(
                hits.iter().any(|h| h.drawer.content == content),
                "{query} lost {content}"
            );
        }
        // The relation is morphological, not exact — it says so.
        assert!(shares_a_stem("كتاب", "الكتاب"));
        assert!(!shares_a_stem("كتاب", "كت"), "a bigram is below the floor");
        // A name and a common noun sharing one bigram is not a stem relation.
        assert!(!shares_a_stem("كريم", "كرم"));
        // Delimiting scripts are untouched by this rule.
        assert!(!shares_a_stem("running", "run"));
    }

    /// Hebrew scored **0 of 8** — the only language in the audit to admit
    /// nothing at all, at either drawer length — because it writes with spaces
    /// and was therefore classed as delimiting, which handed it the
    /// eight-character floor and excluded it from `shares_a_stem`. Its clitics
    /// attach at the front with no delimiter, exactly like Arabic's.
    #[test]
    fn hebrew_clitics_reach_their_stem() {
        for (query, content) in [
            ("ספר", "קראתי את הספר אתמול בערב"),
            ("ספר", "כתבתי בספר הזה הרבה"),
            ("ספר", "קניתי ספרים חדשים בחנות"),
            ("ילד", "הילדים שיחקו בגינה"),
        ] {
            let (_d, mut s) = store(SecurityLevel::Sealed);
            s.upsert(&drawer("w", "r", content, 0)).unwrap();
            s.upsert(&drawer("w", "r", "מזג האוויר היה נעים", 1))
                .unwrap();
            let hits = s.search(query, &SearchOptions::default()).unwrap();
            assert!(
                hits.iter().any(|h| h.drawer.content == content),
                "{query} lost {content}"
            );
        }
        assert!(shares_a_stem("ספר", "הספר"), "the front clitic must carry");
        // ...and the floor still rejects a fragment, exactly as for Arabic.
        assert!(!shares_a_stem("ספר", "סו"));
    }

    /// Vocalised Hebrew must answer an unvocalised query — the same promise
    /// the Arabic harakat strip already makes.
    #[test]
    fn hebrew_points_do_not_split_a_word() {
        use undercroft_core::normalize::search_key;
        assert_eq!(search_key("סֵפֶר"), search_key("ספר"));
        assert_eq!(search_key("שָׁלוֹם"), search_key("שלום"));
        // The maqaf is a hyphen and must keep splitting: stripping it would
        // glue two words into one token.
        assert_ne!(search_key("בית־ספר"), search_key("ביתספר"));
    }

    /// Greek endings substitute rather than append, so containment reaches
    /// almost none of them. This is the pair class that was dropped — not
    /// mis-ranked — before `greek_word_family` admitted.
    #[test]
    fn greek_inflection_admits_and_latin_is_untouched() {
        for (query, content) in [
            ("άνθρωπος", "Το δικαίωμα του ανθρώπου είναι θεμελιώδες"),
            ("άνθρωπος", "Οι άνθρωποι περίμεναν στην ουρά"),
            ("πληροφορία", "Ζήτησα πληροφορίες για το δρομολόγιο"),
        ] {
            let (_d, mut s) = store(SecurityLevel::Sealed);
            s.upsert(&drawer("w", "r", content, 0)).unwrap();
            s.upsert(&drawer("w", "r", "Ο καιρός ήταν ζεστός χθες", 1))
                .unwrap();
            let hits = s.search(query, &SearchOptions::default()).unwrap();
            assert!(
                hits.iter().any(|h| h.drawer.content == content),
                "{query} lost {content}"
            );
        }
        assert!(greek_word_family("ανθρωπος", "ανθρωπου"));
        // The frequency argument that killed Snowball Greek does not reach a
        // pairwise rule: πολύ/πόλη share three characters, not seven.
        assert!(!greek_word_family("πολυ", "πολη"));
        assert!(!greek_word_family("κατασταση", "καταστημα"));
        // The measured cost, pinned so it stays a known quantity.
        assert!(
            greek_word_family("παραδειγμα", "παραδεισος"),
            "example/paradise is this rule's accepted false pair"
        );
        // Latin keeps the rule OFF the admitting channel — this is the whole
        // reason the predicate is script-scoped.
        assert!(same_word_family("conversation", "conversion"));
        assert!(!greek_word_family("conversation", "conversion"));
        assert!(!greek_word_family("internal", "international"));
    }

    // ---- TEMPORARY promiscuity measurement, delete after reading ----------
    //
    // How much of a REAL vocabulary does one query link to under each
    // relation? That is the instrument that produced the 74.3% Arabic figure,
    // so these numbers land on a comparable scale. It needs no relatedness
    // labels: a relation that links a query to a large fraction of the
    // lexicon is unsafe whether or not any individual pair is defensible.
    //
    // Corpus: hermitdave/FrequencyWords 2018 (OpenSubtitles-derived), MIT,
    // 50,000 words with counts, top-N by frequency used as queries.

    fn load_words(path: &str, script_ok: fn(char) -> bool) -> Vec<String> {
        let raw = std::fs::read_to_string(path).expect("word list");
        raw.lines()
            .filter_map(|l| l.split_whitespace().next())
            .map(|w| undercroft_core::normalize::search_key(w).to_string())
            .filter(|w| w.chars().count() >= 2 && w.chars().all(script_ok))
            .collect()
    }

    fn arabic_char(c: char) -> bool {
        matches!(c as u32, 0x0620..=0x064A | 0x0671..=0x06D3)
    }
    fn greek_char(c: char) -> bool {
        matches!(c as u32, 0x0370..=0x03FF | 0x1F00..=0x1FFF)
    }

    fn skeleton_of(s: &str) -> String {
        s.chars()
            .filter(|c| !matches!(*c as u32, 0x0627 | 0x0648 | 0x064A))
            .collect()
    }

    /// Report the distribution of "how many vocabulary words does this query
    /// link to", over the top `qn` queries against the whole vocabulary.
    fn report(label: &str, queries: &[String], vocab: &[String], rel: impl Fn(&str, &str) -> bool) {
        let mut counts: Vec<usize> = queries
            .iter()
            .map(|q| {
                vocab
                    .iter()
                    .filter(|w| w.as_str() != q && rel(q, w))
                    .count()
            })
            .collect();
        counts.sort_unstable();
        let n = counts.len().max(1);
        let total: usize = counts.iter().sum();
        let mean = total as f64 / n as f64;
        let median = counts[n / 2];
        let p95 = counts[(n * 95 / 100).min(n - 1)];
        let max = *counts.last().unwrap_or(&0);
        let zero = counts.iter().filter(|c| **c == 0).count();
        println!(
            "  {label:<34} mean {mean:>8.2}  median {median:>5}  p95 {p95:>6}  max {max:>6}  \
             links-nothing {:>4.1}%  of-vocab {:>6.3}%",
            100.0 * zero as f64 / n as f64,
            100.0 * mean / vocab.len() as f64
        );
    }

    fn latin_char(c: char) -> bool {
        c.is_alphabetic() && (c as u32) < 0x0250
    }
    fn cyrillic_char(c: char) -> bool {
        matches!(c as u32, 0x0400..=0x04FF)
    }
    fn hebrew_char(c: char) -> bool {
        matches!(c as u32, 0x05D0..=0x05EA)
    }

    /// Hebrew matres lectionis. `ה` is deliberately NOT stripped: it is the
    /// definite article and a frequent real consonant, so removing it would
    /// merge the clitic with the stem it attaches to.
    fn he_skeleton(s: &str) -> String {
        s.chars()
            .filter(|c| !matches!(*c as u32, 0x05D0 | 0x05D5 | 0x05D9))
            .collect()
    }

    fn floors(label: &str, qs: &[String], v: &[String], fl: &[usize]) {
        for &f in fl {
            report(&format!("{label} floor {f}"), qs, v, move |q, w| {
                let (qn, tn) = (q.chars().count(), w.chars().count());
                qn.min(tn) >= f
                    && if qn <= tn {
                        w.contains(q)
                    } else {
                        q.contains(w)
                    }
            });
        }
    }

    #[test]
    #[ignore = "measurement, needs testdata/*_50k.txt"]
    fn measure_relation_promiscuity() {
        const QN: usize = 500;
        let load = |f: &str, ok: fn(char) -> bool| {
            let v = load_words(&format!("testdata/{f}_50k.txt"), ok);
            let q: Vec<String> = v.iter().take(QN).cloned().collect();
            (v, q)
        };
        let (ar, arq) = load("ar", arabic_char);
        let (el, elq) = load("el", greek_char);
        let (he, heq) = load("he", hebrew_char);
        let (en, enq) = load("en", latin_char);
        let (de, deq) = load("de", latin_char);
        let (tr, trq) = load("tr", latin_char);
        let (ru, ruq) = load("ru", cyrillic_char);

        println!(
            "
=== ARABIC (vocab {}) ===",
            ar.len()
        );
        report("SHIPPED shares_a_stem >=3", &arq, &ar, |q, w| {
            shares_a_stem(q, w)
        });
        report("skeleton equality >=3", &arq, &ar, |q, w| {
            let (a, b) = (skeleton_of(q), skeleton_of(w));
            a.chars().count() >= 3 && a == b
        });
        report("skeleton SUBSEQ >=3", &arq, &ar, |q, w| {
            let (a, b) = (skeleton_of(q), skeleton_of(w));
            if a.chars().count() < 3 {
                return false;
            }
            let mut it = b.chars();
            a.chars().all(|c| it.any(|x| x == c))
        });

        println!(
            "
=== HEBREW (vocab {}) ===",
            he.len()
        );
        report("SHIPPED shares_a_stem >=3", &heq, &he, |q, w| {
            shares_a_stem(q, w)
        });
        report("he-skeleton equality >=3", &heq, &he, |q, w| {
            let (a, b) = (he_skeleton(q), he_skeleton(w));
            a.chars().count() >= 3 && a == b
        });

        println!(
            "
=== GREEK (vocab {}) ===",
            el.len()
        );
        report("SHIPPED greek_word_family", &elq, &el, |q, w| {
            greek_word_family(q, w)
        });
        floors("contains", &elq, &el, &[3, 4, 5, 6, 8]);

        println!(
            "
=== ENGLISH (vocab {}) ===",
            en.len()
        );
        floors("contains", &enq, &en, &[3, 4, 5, 6, 8]);
        report("same_word_family >=7", &enq, &en, |q, w| {
            same_word_family(q, w)
        });

        println!(
            "
=== GERMAN (vocab {}) ===",
            de.len()
        );
        floors("contains", &deq, &de, &[3, 4, 5, 6, 8]);

        println!(
            "
=== TURKISH (vocab {}) ===",
            tr.len()
        );
        floors("contains", &trq, &tr, &[3, 4, 5, 6, 8]);

        println!(
            "
=== RUSSIAN (vocab {}) ===",
            ru.len()
        );
        floors("contains", &ruq, &ru, &[3, 4, 5, 6, 8]);
        report("same_word_family >=7", &ruq, &ru, |q, w| {
            same_word_family(q, w)
        });
    }

    /// Regression: a two-character word in a non-delimiting script.
    ///
    /// At exactly two characters the bigram IS the word, and flagging it as an
    /// n-gram denied it the exact slot while the whole-subrun push was guarded
    /// on `> 2` — so nothing unflagged was emitted at all. Hebrew fell into
    /// this when it left the delimiting class.
    ///
    /// Pinned at REALISTIC drawer length on purpose. On a one-sentence drawer
    /// every one of these was admitted by the semantic gate at 0.56-0.58, i.e.
    /// a hair over `SEMANTIC_ADMISSION_GATE`, so a short-drawer test reports
    /// "found" while the lexical channels are empty and passes with the fix
    /// reverted.
    #[test]
    fn a_two_character_word_is_a_word_not_a_fragment() {
        const PAD: &str = " מזג האוויר אתמול היה חם ושמשי מאוד קניתי ירקות טריים \
             בשוק המרכזי הרכבת איחרה בשעתיים בגלל תקלה אכלנו במסעדה קרובה עם \
             חברים טובים הים היה שקט והשמש שקעה מוקדם";
        for (query, content) in [
            ("גן", "יש גן גדול ליד הבית שלנו"),
            ("בן", "הוא בן טוב מאוד למשפחה שלו"),
            ("יד", "הוא הרים את יד ימין באוויר"),
            ("עץ", "יש עץ גבוה מאוד בחצר האחורית"),
        ] {
            let (_d, mut s) = store(SecurityLevel::Sealed);
            let target = format!("{content}{PAD}");
            s.upsert(&drawer("w", "r", &target, 0)).unwrap();
            for (i, f) in ["מזג האוויר נעים", "הרכבת איחרה", "אכלנו במסעדה"]
                .iter()
                .enumerate()
            {
                s.upsert(&drawer("w", "r", &format!("{f}{PAD}"), i as u32 + 1))
                    .unwrap();
            }
            let hits = s.search(query, &SearchOptions::default()).unwrap();
            let hit = hits
                .iter()
                .find(|h| h.drawer.content.starts_with(content))
                .unwrap_or_else(|| panic!("{query} lost its drawer at realistic length"));
            assert!(
                hit.lexical_exact > 0.0,
                "{query}: admitted on {:?}, not the exact channel — the cosine \
                 gate is carrying it and the fix is not working",
                hit.semantic
            );
        }
        // A two-character run INSIDE a longer word stays a fragment.
        let seg = undercroft_core::script::segment(&undercroft_core::normalize::search_key("הגן"));
        let whole = seg.tokens.iter().position(|t| t == "הגן").unwrap();
        assert!(!seg.ngram[whole], "the whole word is not an n-gram");
        for (i, t) in seg.tokens.iter().enumerate() {
            if t.chars().count() == 2 {
                assert!(
                    seg.ngram[i],
                    "{t} is a fragment of הגן and must stay flagged"
                );
            }
        }
    }

    /// Regression: the morph channel must never relate one number to another.
    /// `fuzzy_eq` has always refused this, but it ranks; this one admits.
    #[test]
    fn a_number_is_never_a_morphological_relative() {
        for (query, content) in [
            ("45678", "invoice 456789 was paid last week"),
            ("100000", "the total came to 1000000 exactly"),
            ("2023", "in 20231 the record was filed"),
        ] {
            let (_d, mut s) = store(SecurityLevel::Sealed);
            s.upsert(&drawer("w", "r", content, 0)).unwrap();
            s.upsert(&drawer("w", "r", "the weather was warm today", 1))
                .unwrap();
            let hits = s.search(query, &SearchOptions::default()).unwrap();
            // The morph channel must be empty. The drawer may still surface on
            // the semantic gate, which this fix does not touch — asserting on
            // absence would test the cosine, not the guard.
            if let Some(h) = hits.iter().find(|h| h.drawer.content == content) {
                assert_eq!(
                    h.lexical_morph, 0.0,
                    "{query} claimed a morphological relation to {content:?} —                      a digit edit is not morphology"
                );
                assert_eq!(h.lexical_exact, 0.0, "{query} claimed exact evidence");
            }
        }
        assert!(!morph_relation("45678", "456789"));
        assert!(
            morph_relation("document", "documentation"),
            "words still relate"
        );
    }

    /// Regression: the delimiting floor is 8, and these are the pairs that
    /// justify it. Lowering it to 5 promoted every one of them from ranking
    /// into admission — a precision loss bought with a recall-only measurement.
    #[test]
    fn the_delimiting_floor_still_refuses_its_named_false_pairs() {
        for (query, content) in [
            ("other", "my mother called me yesterday"),
            ("count", "the accounting team reviewed it"),
            ("press", "he suffers from depression sometimes"),
            ("stand", "I cannot understand this at all"),
            ("cover", "the discovery changed everything"),
            ("article", "every particle was measured"),
        ] {
            let (_d, mut s) = store(SecurityLevel::Sealed);
            s.upsert(&drawer("w", "r", content, 0)).unwrap();
            s.upsert(&drawer("w", "r", "the train arrived late", 1))
                .unwrap();
            let hits = s.search(query, &SearchOptions::default()).unwrap();
            if let Some(h) = hits.iter().find(|h| h.drawer.content == content) {
                assert_eq!(
                    h.lexical_morph, 0.0,
                    "{query} claimed a morphological relation to {content:?}"
                );
            }
        }
        // The relation the floor exists to keep: eight characters, genuine.
        assert!(morph_relation("document", "documentation"));
        assert!(!morph_relation("other", "mother"));
    }

    /// A single ideograph is one insertion from every bigram containing it.
    #[test]
    fn a_one_character_query_is_not_a_wildcard() {
        // And a number is never a typo: after the digit fold `١٠٠٠٠٠` is
        // ASCII and would otherwise clear the byte gate and match `200000`.
        assert!(!fuzzy_eq("100000", "200000"));
        assert!(!fuzzy_eq("100000", "100001"));
        assert!(
            fuzzy_eq("kubernetes", "kubernets"),
            "words still forgive one"
        );
    }

    #[test]
    fn a_one_character_cjk_query_is_not_a_wildcard() {
        assert!(!fuzzy_eq("北", "东北"));
        assert!(!fuzzy_eq("北", "北虎"));
        // Two-character terms keep the particle/suffix tolerance.
        assert!(fuzzy_eq("한국어", "한국어는"));
        assert!(fuzzy_eq("北京", "北京市"));
    }

    /// A real model swap is a decision, not something to do behind the
    /// user's back — hours of inference and a different vector space.
    #[test]
    fn an_unknown_embedder_swap_still_refuses() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::Sealed).unwrap();
        {
            let mut s = PalaceStore::open(vault).unwrap();
            s.upsert(&drawer("w", "r", "a note", 0)).unwrap();
            s.conn
                .execute(
                    "UPDATE meta SET value = 'some-onnx-model' WHERE key = 'embedder_name'",
                    [],
                )
                .unwrap();
        }
        match reopen_vault(&dir) {
            Err(StoreError::EmbedderMismatch { .. }) => {}
            Err(e) => panic!("wrong error: {e:?}"),
            Ok(_) => panic!("a model swap must never happen behind the user's back"),
        }
    }

    /// PQ codes quantize the old vector space. A stale codebook does not
    /// fail loudly — it returns the wrong candidates.
    #[test]
    fn migration_discards_the_quantized_index() {
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::Sealed).unwrap();
        {
            let mut s = PalaceStore::open(vault).unwrap();
            s.upsert(&drawer("w", "r", "the heron files drawers", 0))
                .unwrap();
            s.pq_schema().unwrap();
            s.conn
                .execute(
                    "INSERT INTO pq_meta (key, value) VALUES ('codebook', x'00')",
                    [],
                )
                .unwrap();
            make_it_look_like_v1(&s);
        }
        let s = reopen_vault(&dir).unwrap();
        let stale: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'pq_meta'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stale, 0, "the old codebook outlived the vectors it encoded");
    }

    /// The migration runs inside `open`, so its cost is a user-visible pause.
    /// Not part of the normal suite — run explicitly:
    /// `cargo test --release -p undercroft-store -- --ignored migration_at_scale --nocapture`
    #[test]
    #[ignore]
    fn migration_at_scale() {
        const N: usize = 20_000;
        let dir = TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::Sealed).unwrap();
        {
            let mut s = PalaceStore::open(vault).unwrap();
            let batch: Vec<Drawer> = (0..N)
                .map(|i| {
                    drawer(
                        "w",
                        "r",
                        &format!(
                            "drawer {i}: the heron files verbatim drawers into wings and rooms, \
                             and this sentence exists to give the embedder realistic work to do"
                        ),
                        i as u32,
                    )
                })
                .collect();
            s.upsert_many(&batch).unwrap();
            make_it_look_like_v1(&s);
        }
        let t0 = std::time::Instant::now();
        let s = reopen_vault(&dir).unwrap();
        let elapsed = t0.elapsed();
        eprintln!(
            "migrated {N} drawers in {:?} ({:.1} µs/drawer)",
            elapsed,
            elapsed.as_secs_f64() * 1e6 / N as f64
        );
        let hits = s
            .search("heron verbatim", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty());
    }

    /// A document containing the query term verbatim must be scored as
    /// containing it, not as containing a term it merely resembles.
    #[test]
    fn an_exact_match_outranks_a_fuzzy_one_for_the_same_token() {
        // The discriminating case is a drawer holding BOTH surface forms.
        // Old behaviour: the exact token `kubernets` is claimed by query term
        // 0, and `kubernetes` is *also* claimed by term 0 (one edit away),
        // giving tf = [2, 0] — one term, saturated by k1. New behaviour: each
        // token fills its own exact slot, tf = [1, 1] — two terms, neither
        // saturated, which scores strictly higher. Anything that ranks on a
        // cosine tie instead would pass with the fix reverted.
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "kubernets kubernetes both forms here", 0))
            .unwrap();
        s.upsert(&drawer("w", "r", "kubernets kubernets twice the typo", 1))
            .unwrap();
        s.set_fusion(Fusion::Bm25);
        let hits = s
            .search("kubernets kubernetes", &SearchOptions::default())
            .unwrap();
        assert!(!hits.is_empty());
        assert!(
            hits[0].drawer.content.contains("both forms"),
            "got {:?}",
            hits[0].drawer.content
        );
        // And directly, on the channels: a drawer holding both surface forms
        // fills two exact slots, and the blended channel can only ever be at
        // least the exact one.
        let cand = |content: &'static str| {
            let s = segment(content);
            let units = s.len as f32;
            let (tokens, ngram): (Vec<String>, Vec<bool>) = s
                .tokens
                .into_iter()
                .zip(s.ngram)
                .filter(|(t, _)| t.len() > 1)
                .unzip();
            Candidate {
                drawer: drawer("w", "r", content, 0),
                semantic: 0.0,
                recency: 0.0,
                units,
                tokens,
                ngram,
            }
        };
        let qterms = tokenize("kubernets kubernetes");
        let cands = vec![
            cand("kubernets kubernetes both forms here"),
            cand("kubernets kubernets twice the typo"),
        ];
        let b = bm25_raw(&qterms, &cands);
        assert!(b.exact[0] > 0.0, "both forms are literally present");
        assert!(b.raw[0] >= b.exact[0], "blended is never below exact");
        assert!(
            b.raw[0] > b.raw[1],
            "two exact terms must outscore one term seen twice: {:?} vs {:?}",
            b.raw[0],
            b.raw[1]
        );
    }

    /// The whole point of the split: approximate evidence alone must not
    /// admit a drawer, only reorder ones already admitted.
    #[test]
    fn approximate_evidence_alone_does_not_admit_a_drawer() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        // `kubernets` is one edit from `kubernetes`, so the drawer is
        // approximate evidence and nothing more.
        s.upsert(&drawer("w", "r", "the kubernets cluster note", 0))
            .unwrap();
        s.set_fusion(Fusion::Bm25);
        let hits = s.search("kubernetes", &SearchOptions::default()).unwrap();
        for h in &hits {
            assert!(
                h.lexical_exact > 0.0 || h.semantic > SEMANTIC_ADMISSION_GATE,
                "admitted on approximate evidence alone: exact={} sem={}",
                h.lexical_exact,
                h.semantic
            );
        }
        // And when it *is* admitted (the hash embedder shares trigrams here),
        // the approximate channel still shows up in ranking.
        if let Some(h) = hits.first() {
            assert!(h.lexical >= h.lexical_exact);
        }
    }

    #[test]
    fn export_roundtrips_all_records() {
        let (_d, mut s) = store(SecurityLevel::Sealed);
        s.upsert(&drawer("w", "r", "alpha", 0)).unwrap();
        s.upsert(&drawer("w", "r", "beta", 1)).unwrap();
        let all = s.export_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].content, "alpha");
    }
}
