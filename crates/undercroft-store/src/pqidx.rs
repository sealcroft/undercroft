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
//! recall. Since v0.41.0 the cache is **slab-grouped by IVF list**
//! ([`PqCache`]): a probe scans its lists' contiguous slabs instead of
//! filtering every row through a membership test — the page-level spike
//! measured that flat filter at 0.3–1.4 s/q at 10⁷ versus 10–36 ms/q for
//! the grouped layout, with zero at-rest change
//! (`benchmarks/logs/pqpage_spike.log`; docs/RETRIEVAL_SCALING.md).
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

use rusqlite::{params, OptionalExtension};
use undercroft_vault::SecurityLevel;

use crate::pq::{CoarseQuantizer, ProductQuantizer};
use crate::{PalaceStore, StoreError, CODEBOOK_PQ, CODEBOOK_PQ_IVF};

/// The PQ RAM code cache, slab-grouped by IVF list: `list → (seqs,
/// contiguous codes)`. A probe scans only its lists' slabs — no per-row
/// membership test, which is the O(N·nprobe) filter the page-level spike
/// measured at 0.3–1.4 s/q at 10⁷ (`benchmarks/logs/pqpage_spike.log`; the
/// grouped layout recovered 10–36 ms/q with zero at-rest change). Rows
/// sit in list -1 until IVF partitions train; -1 also rides along in
/// every probe afterwards. Mirrors `fdeidx::FdeCache::Coded`.
pub(crate) struct PqCache {
    code_len: usize,
    slabs: std::collections::HashMap<i64, (Vec<i64>, Vec<u8>)>,
    /// Page-tier bookkeeping: which lists' pages have been decrypted into
    /// `slabs` so far. `None` ⇒ everything is resident (per-row mode, or a
    /// completed full load) — the pre-page behavior.
    loaded: Option<std::collections::HashSet<i64>>,
}

/// One wing's private PQ state: its own codebook, its own optional IVF
/// partitions, and a fully-resident RAM code cache over its own rows.
///
/// This exists because the wing is the retrieval unit a caller actually
/// scopes to, and the global prefilter is wing-blind twice over: its
/// candidate set is drawn from the whole corpus (so a scoped query's cost is
/// corpus-sized, ~913 s/query at 10⁶ measured 0.91 ms/drawer), and its
/// top-k can starve a wing entirely (the intersection of global candidates
/// with `WHERE wing = ?` can be empty while the wing holds the answer).
/// A per-wing index bounds a scoped query by the wing's size and makes its
/// recall a property of the wing, not of what the rest of the corpus looks
/// like.
///
/// The codebook is per wing deliberately — a wing's population is *more*
/// homogeneous than the vault's, so its codebook quantizes it better, and
/// derived-structure scope then matches the isolation unit (the wing)
/// rather than the crypto unit (the vault): a writer in one wing no longer
/// shapes the codebook that scores another. What stays global, stated
/// honestly: BM25's IDF — the wing is an isolation unit for *candidates*,
/// not for scores.
pub(crate) struct WingPq {
    pq: ProductQuantizer,
    ivf: Option<CoarseQuantizer>,
    cache: PqCache,
    live: i64,
}

/// What a rebuild owes `pq_meta` once its rows commit.
///
/// **Why this exists.** Both PQ tiers wrote a trained codebook and trained
/// IVF centroids the moment they existed — an autocommit `INSERT` under
/// `synchronous=FULL`, i.e. one fsync landing *ahead* of the rows those
/// artifacts describe. A crash in that window left a codebook no stored code
/// was encoded against, or centroids no stored row was partitioned by. The
/// load path reads that split state as coherent (`matched == count &&
/// ivf_ok`) and probes the wrong lists; `widen` does not fire, because the
/// wrong lists still hold ≥ k rows. Silent partial recall loss, invisible to
/// `verify` — derived indexes sit outside HMAC coverage by design — and
/// invisible to the generation counter too, which is the counter's whole
/// job: the global tier self-heals at the next writable open, the per-wing
/// tier never does, and a read-only replica heals neither.
///
/// [`PalaceStore::one_rewrite`]'s doc states this rule generally and FDE
/// (`fdeidx.rs`) and the token codebook (`latestage.rs`) already follow it.
/// PQ did not; this is PQ catching up.
///
/// **Buffered rather than wrapped**, deliberately: wrapping the whole build
/// would hold the write lock across k-means, which is the trade
/// [`PalaceStore::one_rewrite`]'s doc already argues against. Training stays
/// outside the transaction and only its *decision* travels in.
enum PendingMeta {
    /// The stored artifact is reused as-is. A rebuild is not a retrain and
    /// must not advance a generation — pinned by
    /// `training_a_codebook_advances_a_visible_generation`.
    Keep,
    /// Freshly trained: write these bytes and step the generation, both
    /// inside the rebuild's transaction.
    Put(Vec<u8>),
    /// Untrainable, or the corpus fell below the tier's threshold: remove it
    /// with the rows, so it cannot silently go stale.
    Drop,
}

impl PqCache {
    fn new(code_len: usize) -> Self {
        Self {
            code_len,
            slabs: std::collections::HashMap::new(),
            loaded: None,
        }
    }

    /// A paged cache starts empty (tail rows aside) and fills lazily,
    /// list by probed list.
    fn new_paged(code_len: usize) -> Self {
        Self {
            code_len,
            slabs: std::collections::HashMap::new(),
            loaded: Some(std::collections::HashSet::new()),
        }
    }

    fn push(&mut self, seq: i64, list: i64, code: &[u8]) {
        // A wrong-length code would corrupt its slab's stride — skip it;
        // like a sealed row that fails to open, it only costs a candidate
        // slot until the matched-count verify rebuilds.
        if code.len() != self.code_len {
            return;
        }
        let (seqs, codes) = self.slabs.entry(list).or_default();
        seqs.push(seq);
        codes.extend_from_slice(code);
    }

    /// Drop `seq` wherever it lives (a re-embedded drawer may move lists).
    fn remove_seq(&mut self, seq: i64) {
        let code_len = self.code_len;
        self.slabs.retain(|_, (seqs, codes)| {
            if let Some(pos) = seqs.iter().position(|s| *s == seq) {
                seqs.remove(pos);
                codes.drain(pos * code_len..(pos + 1) * code_len);
            }
            !seqs.is_empty()
        });
    }

    #[cfg(test)]
    fn rows(&self) -> usize {
        self.slabs.values().map(|(s, _)| s.len()).sum()
    }

    /// Test visibility into lazy mode: `Some(n)` = paged, `n` lists loaded
    /// so far; `None` = fully resident.
    #[cfg(test)]
    pub(crate) fn loaded_count(&self) -> Option<usize> {
        self.loaded.as_ref().map(|s| s.len())
    }

    /// Rows across the given lists only (the widen-when-<k check).
    fn rows_in(&self, lists: &[i64]) -> usize {
        lists
            .iter()
            .filter_map(|l| self.slabs.get(l))
            .map(|(s, _)| s.len())
            .sum()
    }

    /// ADC-score every row of the given lists (or all lists when `None`)
    /// into `out`.
    fn scan(
        &self,
        pq: &ProductQuantizer,
        tables: &[f32],
        lists: Option<&[i64]>,
        out: &mut Vec<(f32, i64)>,
    ) {
        let mut scan_slab = |seqs: &Vec<i64>, codes: &Vec<u8>| {
            for (i, seq) in seqs.iter().enumerate() {
                let code = &codes[i * self.code_len..(i + 1) * self.code_len];
                out.push((pq.adc(tables, code), *seq));
            }
        };
        match lists {
            Some(lists) => {
                for l in lists {
                    if let Some((seqs, codes)) = self.slabs.get(l) {
                        scan_slab(seqs, codes);
                    }
                }
            }
            None => {
                for (seqs, codes) in self.slabs.values() {
                    scan_slab(seqs, codes);
                }
            }
        }
    }
}

/// k-means iterations and training-sample cap: PQ codebooks tolerate sampling
/// well, and training is a one-time cost we keep to seconds.
const PQ_TRAIN_ITERS: usize = 12;
const PQ_TRAIN_SAMPLE: usize = 4096;
/// Vectors drawn — by a second keyed label, so they are not the training
/// sample — to check a fresh codebook against the corpus it will encode.
pub(crate) const PQ_FIT_PROBE: usize = 512;

/// `want` training-sample indices, ascending — **stratified by position and
/// keyed within each stratum**.
///
/// Every codebook and centroid set in this crate trains on a *sample* of the
/// corpus, and that sample used to be an even stride over insertion order:
/// reproducible, and equally reproducible to a writer who never held the vault
/// key. k-means has an unbounded breakdown point, so knowing which rows train
/// the quantizer every other row is then encoded against is a lever on
/// unrelated drawers' recall — the one cross-drawer coupling the codebooks
/// already carry (see the poison-resistance invariant in CLAUDE.md).
///
/// **The stride was also a latent recall landmine, and that is measured.** A
/// fixed interval over a corpus whose insertion order is *periodic* samples one
/// residue class: if the interval shares a factor with the period, the sample
/// is homogeneous and the codebook trains on a slice of the space. On
/// `synth --n 16384` with `UNDERCROFT_RETRIEVAL=pq` — where `⌈n/4096⌉ = 4` meets
/// a corpus built from `FACT_TEMPLATES[i % 4]` — the stride scores **R@5 83.0%
/// / R@1 82.5%**, failing that harness's own ≥95% regression gate, while this
/// draw scores **99.7% / 98.9%**. At `n = 20000` the interval is 5, coprime
/// with the period, and the stride is a perfectly balanced systematic sample
/// (99.8% / 99.2%) against this draw's 99.4% / 97.9% — so the stride's apparent
/// edge is alignment luck between two measured points, and its collapse sits
/// between them. Periodic insertion order is not exotic: round-robin ingest
/// per source, alternating speakers, one session per day all produce it.
///
/// **Why stratify rather than take the `want` lowest ranks.** Blocks preserve
/// the one property the stride had that was worth keeping — coverage across the
/// corpus — while the keyed choice *inside* each block breaks the residue
/// alignment that made it fragile. Measured, the two keyed variants are within
/// noise of each other (uniform 97.8/99.4, stratified 97.9/99.4 at n=20000), so
/// this is chosen for the reasoning it supports, not a recall win.
///
/// What it costs an attacker: under the stride a writer knew exactly which seqs
/// would train (`seq ≡ 0 mod stride`), so **one** crafted row placed on a
/// sampled position entered the training set. Now they know their block
/// contributes one row but not which, so certainty costs them every row in the
/// block, and a single crafted row is a `1/blocksize` chance.
///
/// Below the cap every index is returned, exactly as the stride did at
/// `stride == 1` — so nothing changes for a corpus smaller than the sample.
pub(crate) fn stratified_keyed(n: usize, want: usize, rank: impl Fn(usize) -> u64) -> Vec<usize> {
    if want == 0 {
        return Vec::new();
    }
    if want >= n {
        return (0..n).collect();
    }
    let mut chosen = Vec::with_capacity(want);
    for b in 0..want {
        let lo = b * n / want;
        let hi = (((b + 1) * n / want).max(lo + 1)).min(n);
        let mut best = lo;
        let mut best_rank = u64::MAX;
        for i in lo..hi {
            let r = rank(i);
            // `<` keeps the first on a tie, so the draw is total-ordered.
            if r < best_rank {
                best_rank = r;
                best = i;
            }
        }
        chosen.push(best);
    }
    chosen
}

/// IVF partitioning kicks in above this corpus size by default — below it the
/// flat ADC scan is already a few milliseconds and partitions would only add
/// recall risk. Tunable: `UNDERCROFT_IVF_MIN` (`off` disables IVF, keeping the
/// flat PQ scan) / [`PalaceStore::set_ivf`].
pub(crate) const IVF_MIN_DEFAULT: usize = 8192;
const IVF_TRAIN_ITERS: usize = 10;

/// Rows per sealed page. Caps the read-modify-reseal cost of folding a
/// tail batch into a list (~200 KB at 48-B codes) — the write-amplification
/// bound the page-level spike priced (`(list, pageno)` caps).
const PQ_PAGE_CAP: usize = 4096;

/// Tail rows accumulated before a search's verify pass folds them into
/// pages. `upsert_many` folds at its batch boundary regardless; this bound
/// only limits how long a trickle of single writes rides in per-row form
/// (they are fully searchable either way).
const PQ_TAIL_FOLD: usize = 256;

/// A wing earns its own PQ index at this many drawers. Below the floor a
/// scoped query skips the prefilter and full-scans its wing — the `WHERE
/// wing` clause bounds that scan by the wing's size, so the floor is also
/// the worst-case row count a scoped query ever pays without an index.
///
/// The floor exists for two measured reasons, not taste: k-means with 256
/// centroids per subspace on a few hundred vectors produces duplicate
/// centroids (a codebook must be *earned* by population), and a codebook is
/// ~hundreds of KB — a thousand tiny wings would pay 100× more in codebooks
/// than in the 92 B/drawer codes they index. 4096 aligns with
/// `PQ_TRAIN_SAMPLE`: the smallest per-wing codebook trains on a full-size
/// sample. Tunable: `UNDERCROFT_WING_PQ_MIN` (`off` disables the per-wing
/// tier — scoped queries then intersect the global candidates, the
/// pre-tier behavior) / [`PalaceStore::set_wing_pq_min`].
pub const WING_PQ_MIN_DEFAULT: usize = 4096;

/// Corpus-scaled stage-1 candidate pool divisor: the semantic prefilters
/// fetch at least `live_rows / POOL_DIV` ADC candidates, which the exact
/// second stage (`refine_by_exact_cosine`) then cuts back to hydration
/// size using the true vectors. The pool is the only place recall can
/// leak — everything downstream re-scores exactly — and it is measured,
/// not chosen: a fixed 256-candidate pool leaked unscoped R@5 from 100.0%
/// to 96.8% between 131k and 1M (constant per-vector quantization error,
/// linearly growing competitors), /512 recovered 524k and 1M but left
/// residual misses at 262k even with a fresh codebook, and /64 is the
/// deeper net the refine stage makes affordable: stage-2 pays
/// microseconds per embedding instead of ~0.09 ms per hydration, so a
/// 16k-candidate pool at 1M costs embedding decrypts, not row loads.
pub(crate) const POOL_DIV_DEFAULT: usize = 64;

/// Whether IVF partitions trained on `trained` rows are still fresh for a
/// corpus of `live` rows. The factor is 1.5×, down from the original
/// strictly-greater 2×, for two measured reasons: the doubling rule was
/// priced when a retrain cost 73 minutes (the per-row-fsync rebuild bug —
/// post-fix a 524k rebuild is ~13 s, so freshness is nearly free), and the
/// strict boundary let a corpus sit at *exactly* double its training size
/// without ever retraining — measured at 262k riding 131k-trained
/// partitions, where staleness sank one query's gold beyond a 2048
/// candidate pool.
pub(crate) fn ivf_fresh(live: u64, trained: u64) -> bool {
    live <= trained.saturating_mul(3) / 2
}

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

    /// Declare the cosine→`semantic` calibration zero programmatically
    /// (the env `UNDERCROFT_SEMANTIC_FLOOR` resolved at open is the
    /// deployment's way; the embedder's own measurement is the default).
    /// 0 is the shipped hash map. Out-of-range values are rejected.
    pub fn set_sem_floor(&mut self, floor: f32) -> Result<(), StoreError> {
        if !floor.is_finite() || !(0.0..=0.98).contains(&floor) {
            return Err(StoreError::Invalid(format!(
                "semantic floor {floor} is not a cosine in [0.0, 0.98]"
            )));
        }
        self.sem_floor = floor;
        Ok(())
    }

    /// Declare the vault-level trust floor programmatically (the env
    /// `UNDERCROFT_TRUST_FLOOR` resolved at open is the deployment's way).
    /// `None` = no floor. An invalid class is rejected, never coerced.
    /// The vault's declared trust floor, if any.
    ///
    /// A surface needs this to tell "this vault is empty" from "nothing in
    /// it meets the floor you declared". Since the floor began governing
    /// `recent` and `list_drawers`, an `Allow([])` clause -- a floor above
    /// `standard` with no wing yet assigned that class, which is an ordinary
    /// state -- empties those reads, and `wake_up` said "Palace is empty"
    /// over an intact corpus. An exclusion nobody can see is the silence
    /// this project's own label doctrine forbids.
    pub fn trust_floor(&self) -> Option<&str> {
        self.trust_floor.as_deref()
    }

    pub fn set_trust_floor(&mut self, floor: Option<String>) -> Result<(), StoreError> {
        if let Some(f) = floor.as_deref() {
            undercroft_core::validate_trust(f).map_err(|e| StoreError::Invalid(e.to_string()))?;
        }
        self.trust_floor = floor;
        Ok(())
    }

    /// Tune the per-wing PQ floor: wings holding at least `min` drawers get
    /// their own codebook, IVF partitions and code rows, and a wing-scoped
    /// search probes those instead of intersecting corpus-wide candidates.
    /// `usize::MAX` ⇒ tier off (scoped queries keep the global-candidate
    /// behavior exactly). Default from `UNDERCROFT_WING_PQ_MIN` at open
    /// (`off` ⇒ never).
    pub fn set_wing_pq_min(&mut self, min: usize) {
        self.wing_pq_min = min;
        self.wing_pq.borrow_mut().clear();
    }

    /// Tune the corpus-scaled candidate pool (candidates ≥ live/div;
    /// `usize::MAX` ⇒ fixed floor only, the measured-leaky pre-fix
    /// behavior). Default from `UNDERCROFT_POOL_DIV` at open (`off` ⇒
    /// scaling off). See [`POOL_DIV_DEFAULT`] for why 512.
    pub fn set_pool_div(&mut self, div: usize) {
        self.pool_div = div.max(1);
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

    // -- sealed page tier (opt-in, `UNDERCROFT_PQ_PAGE_MIN`) -----------------

    /// Whether the page tier applies at this corpus size: sealed vaults
    /// only (hmac-only rows are plaintext — pages would only add seal
    /// overhead they don't carry today).
    fn pq_pages_on(&self, rows: usize) -> bool {
        self.pq_sealed() && rows >= self.pq_page_min
    }

    /// Sealed-page plaintext: `count:u32le ‖ (seq:i64le ‖ code)*`. The
    /// count is the row-count commitment — the page is one AEAD unit, so
    /// intra-page splicing or selective row deletion cannot happen without
    /// the key (stronger than per-row seals against that class).
    fn pq_page_pack(rows: &[(i64, Vec<u8>)]) -> Vec<u8> {
        let code_len = rows.first().map_or(0, |(_, c)| c.len());
        let mut out = Vec::with_capacity(4 + rows.len() * (8 + code_len));
        out.extend((rows.len() as u32).to_le_bytes());
        for (seq, code) in rows {
            out.extend(seq.to_le_bytes());
            out.extend_from_slice(code);
        }
        out
    }

    /// Inverse of [`Self::pq_page_pack`]; `None` on any structural
    /// mismatch (wrong count, truncated rows, stride disagreement).
    fn pq_page_unpack(plain: &[u8], code_len: usize) -> Option<Vec<(i64, Vec<u8>)>> {
        if plain.len() < 4 || code_len == 0 {
            return None;
        }
        let count = u32::from_le_bytes(plain[..4].try_into().ok()?) as usize;
        let stride = 8 + code_len;
        if plain.len() != 4 + count * stride {
            return None;
        }
        let mut rows = Vec::with_capacity(count);
        for i in 0..count {
            let at = 4 + i * stride;
            let seq = i64::from_le_bytes(plain[at..at + 8].try_into().ok()?);
            rows.push((seq, plain[at + 8..at + stride].to_vec()));
        }
        Some(rows)
    }

    /// Sealed u64 counters in `pq_meta` (`rowcount` = live rows committed
    /// to pages, `deleted` = paged rows since orphaned by delete/update).
    /// Written through the same sealing as every other pq_meta artifact.
    pub(crate) fn pq_count_get(&self, key: &str) -> Result<u64, StoreError> {
        Ok(self
            .pq_meta_get(key)?
            .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0))
    }

    fn pq_count_put(&self, key: &str, v: u64) -> Result<(), StoreError> {
        self.pq_meta_put(key, &v.to_le_bytes())
    }

    /// Whether any sealed pages exist (the "paged mode" probe used by the
    /// verify pass, the write path, the delete path, and the batch fold).
    pub(crate) fn pq_pages_present(&self) -> Result<bool, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM pq_page", [], |r| r.get(0))?;
        Ok(n > 0)
    }

    /// Write `rows` (already grouped however the caller likes) into sealed
    /// pages, appending after each list's current last page and respecting
    /// the per-page cap. Advances `rowcount` by the number of rows written.
    fn pq_page_append(
        &self,
        mut by_list: std::collections::HashMap<i64, Vec<(i64, Vec<u8>)>>,
    ) -> Result<(), StoreError> {
        let mut written = 0u64;
        for (list, mut rows) in by_list.drain() {
            written += rows.len() as u64;
            // The list's last page may still have room — fold into it.
            let last: Option<(i64, Vec<u8>)> = self
                .conn
                .query_row(
                    "SELECT pageno, blob FROM pq_page WHERE list = ?1 \
                     ORDER BY pageno DESC LIMIT 1",
                    params![list],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let mut pageno = match last {
                Some((no, blob)) => {
                    let plain = self
                        .vault
                        .index_from_rest(&format!("pqpage/{list}/{no}"), &blob)
                        .ok();
                    let code_len = rows.first().map_or(0, |(_, c)| c.len());
                    match plain.and_then(|p| Self::pq_page_unpack(&p, code_len)) {
                        Some(mut existing) if existing.len() < PQ_PAGE_CAP => {
                            // Rewrite this page with the fold appended.
                            existing.append(&mut rows);
                            rows = existing;
                            no
                        }
                        // Full (or unreadable — the verify equation will
                        // catch real drift): start the next page.
                        _ => no + 1,
                    }
                }
                None => 0,
            };
            for chunk in rows.chunks(PQ_PAGE_CAP) {
                let blob = self.vault.index_at_rest(
                    &format!("pqpage/{list}/{pageno}"),
                    &Self::pq_page_pack(chunk),
                );
                self.conn.execute(
                    "INSERT OR REPLACE INTO pq_page (list, pageno, blob) VALUES (?1, ?2, ?3)",
                    params![list, pageno, blob],
                )?;
                pageno += 1;
            }
        }
        let rowcount = self.pq_count_get("rowcount")?;
        self.pq_count_put("rowcount", rowcount + written)
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

    /// Tune the sealed page tier: `min` is the corpus size at which PQ
    /// codes keep to one AEAD page per IVF list instead of per-row seals
    /// (`usize::MAX` ⇒ never — the default). Takes effect event-driven: the
    /// next search's verify pass repacks in either direction. Default from
    /// `UNDERCROFT_PQ_PAGE_MIN` at open (`off` ⇒ never).
    pub fn set_pq_pages(&mut self, min: usize) {
        self.pq_page_min = min;
    }

    pub(crate) fn pq_schema(&self) -> Result<(), StoreError> {
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
             );
             -- Sealed page tier (opt-in): one AEAD blob per (list, pageno).
             -- The plaintext (list, pageno) key is what lets a probe fetch
             -- its lists without decrypting the world; blob lengths reveal
             -- the cluster-size histogram, never membership (spike-accepted).
             CREATE TABLE IF NOT EXISTS pq_page (
                 list   INTEGER NOT NULL,
                 pageno INTEGER NOT NULL,
                 blob   BLOB NOT NULL,
                 PRIMARY KEY (list, pageno)
             ) WITHOUT ROWID;
             -- Per-wing PQ rows (the wing-as-retrieval-unit tier): same
             -- clustered layout as drawer_pq, one dimension up. The wing
             -- name is plaintext because `drawers.wing` already is — the
             -- sealed-metadata exposure test pins that — and the sealed
             -- list id stays inside the blob for the same reason as the
             -- global rows. Rows exist only for wings past the floor.
             CREATE TABLE IF NOT EXISTS drawer_pq_wing (
                 wing TEXT NOT NULL,
                 list INTEGER NOT NULL,
                 seq  INTEGER NOT NULL,
                 code BLOB NOT NULL,
                 PRIMARY KEY (wing, list, seq)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS drawer_pq_wing_seq ON drawer_pq_wing(seq);
             -- A scoped query's first step is 'how big is this wing' — make
             -- that a range scan, not a table scan.
             CREATE INDEX IF NOT EXISTS drawers_wing ON drawers(wing);",
        )?;
        Ok(())
    }

    /// Vector top-`k` candidate `seq`s by streaming ADC over the on-disk
    /// codes — only the probed inverted lists when IVF is active, every code
    /// row otherwise. `None` ⇒ no usable index (empty corpus, or a dimension
    /// PQ can't split); the caller falls back to the full scan.
    /// Test surface: the production path always resolves a scope first and
    /// calls [`Self::pq_candidates_in`].
    #[cfg(test)]
    pub(crate) fn pq_candidates(
        &self,
        qvec: &[f32],
        k: usize,
    ) -> Result<Option<Vec<i64>>, StoreError> {
        self.pq_candidates_in(qvec, k, None)
    }

    /// [`Self::pq_candidates`] restricted to a declared scope's seq set:
    /// every returned candidate is a member, so a scoped query's pool can
    /// never be crowded out by rows the caller excluded. The caller passes
    /// `k` already scaled to the scope's population — the global live count
    /// must not inflate it back.
    pub(crate) fn pq_candidates_in(
        &self,
        qvec: &[f32],
        k: usize,
        scope: Option<&crate::SeqFilter>,
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
        // R1: a read-only store LOADS an index and never builds one. The
        // verification below is not a read — `pq_schema` creates tables and
        // drops others, `pq_build` trains and re-encodes every row, and the
        // repack/compact arms rewrite the on-disk format — so on a replica
        // the first search after open silently wrote to the vault the flag
        // promised it would not touch. `just_verified` is set so the growth
        // re-check below cannot recurse into a retrain either: whatever the
        // load found is what this store has.
        if self.read_only {
            let stale = !self.pq_verified.get() || self.pq.borrow().is_none();
            if stale && !self.pq_load_only()? {
                self.ro_prefilter_fallback("PQ");
                return Ok(None);
            }
            just_verified = true;
        } else if !self.pq_verified.get() || self.pq.borrow().is_none() {
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
            // not be outgrown (2× their training size). On the page tier
            // the equation extends: matched = tail rows (joined against
            // live drawers, as always) + the sealed page commitment
            // (`rowcount` − `deleted`) — pages can't be joined without
            // decrypting the world, which is exactly what lazy mode avoids.
            let tail_matched: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM drawer_pq p JOIN drawers d ON d.seq = p.seq",
                [],
                |r| r.get(0),
            )?;
            let pages = self.pq_pages_present()?;
            let matched = if pages {
                let live = self
                    .pq_count_get("rowcount")?
                    .saturating_sub(self.pq_count_get("deleted")?);
                tail_matched + live as i64
            } else {
                tail_matched
            };
            let want_ivf = (drawers as usize) >= self.ivf_min;
            let ivf_stale = want_ivf && {
                if self.ivf.borrow().is_none() {
                    self.ivf_load()?;
                }
                match self.ivf.borrow().as_ref() {
                    None => true,
                    Some(cq) => !ivf_fresh(drawers as u64, cq.trained_n()),
                }
            };
            if self.pq.borrow().is_none() || matched != drawers || ivf_stale {
                if !self.pq_build()? {
                    return Ok(None);
                }
            } else {
                // Coherent index — reconcile the *format* with the page
                // setting (event-driven migration, both directions), and
                // fold an accumulated single-write tail into its pages.
                let want_pages = self.pq_pages_on(drawers as usize);
                if want_pages && !pages {
                    self.pq_repack_rows_to_pages()?;
                } else if !want_pages && pages {
                    self.pq_repack_pages_to_rows()?;
                } else if pages {
                    let tails: i64 =
                        self.conn
                            .query_row("SELECT COUNT(*) FROM drawer_pq", [], |r| r.get(0))?;
                    if tails as usize >= PQ_TAIL_FOLD {
                        self.pq_compact_tail()?;
                    }
                }
            }
            self.pq_live.set(drawers);
            self.pq_verified.set(true);
        }
        let live = self.pq_live.get();
        if live == 0 {
            return Ok(None);
        }
        // Corpus-scaled pool, applied against the verified live count: a
        // fixed floor is the measured recall-leak defect (R@5 100 → 96.8
        // over 131k → 1M at 256 candidates; 100.0% restored at live/512).
        // A NARROWED call arrives already scaled to its scope's population.
        // An exclusion has been scaled by nothing and must keep the corpus
        // divisor: gating on `is_some()` let one quarantined row pin stage
        // 1 at the caller's fixed floor, which is the measured recall leak
        // this divisor exists to close.
        let k = if scope.is_some_and(|f| f.narrows()) {
            k
        } else {
            k.max(live as usize / self.pool_div.max(1))
        };
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
                Some(cq) => !ivf_fresh(live as u64, cq.trained_n()),
            };
            if outgrown {
                self.pq_verified.set(false);
                return self.pq_candidates_in(qvec, k, scope);
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
        // A probe scans only its lists' slabs (the flat cache's per-row
        // membership filter was the O(N·nprobe) cost the page-level spike
        // measured at 0.3–1.4 s/q at 10⁷); if the probed lists hold fewer
        // than `k` rows (skewed partitions, tiny corpus), widen to the full
        // scan rather than starve the fusion stage. On the sealed page
        // tier, only the scanned lists' pages are ever decrypted — that
        // lazy load is the open-time/RAM win the spike measured.
        self.pq_cache_ensure(pq.code_len())?;
        match &probe {
            Some(lists) => self.pq_cache_load_lists(lists)?,
            None => self.pq_cache_load_all()?,
        }
        let widen = match &probe {
            Some(lists) => self
                .pq_cache
                .borrow()
                .as_ref()
                .is_none_or(|c| c.rows_in(lists) < k),
            None => true,
        };
        if widen {
            self.pq_cache_load_all()?;
        }
        let mut scored: Vec<(f32, i64)> = Vec::new();
        {
            let cache_ref = self.pq_cache.borrow();
            let Some(cache) = cache_ref.as_ref() else {
                return Ok(None);
            };
            match &probe {
                Some(lists) if !widen => cache.scan(pq, &tables, Some(lists), &mut scored),
                _ => cache.scan(pq, &tables, None, &mut scored),
            }
        }
        if let Some(s) = scope {
            scored.retain(|(_, seq)| s.admits(seq));
            // A probe that under-delivers INSIDE the scope widens to the
            // full scan: the scope's rows may sit in lists the probe
            // skipped, and starving a scoped query on partition luck is
            // the shape this parameter exists to close.
            if scored.len() < k && probe.is_some() && !widen {
                self.pq_cache_load_all()?;
                let cache_ref = self.pq_cache.borrow();
                let Some(cache) = cache_ref.as_ref() else {
                    return Ok(None);
                };
                scored.clear();
                cache.scan(pq, &tables, None, &mut scored);
                scored.retain(|(_, seq)| s.admits(seq));
            }
        }
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
    fn pq_cache_ensure(&self, code_len: usize) -> Result<(), StoreError> {
        if self.pq_cache.borrow().is_some() {
            return Ok(());
        }
        // Per-row rows load eagerly (in paged mode these are the tail —
        // the recent single writes); pages decrypt lazily per probed list.
        let rows = if self.pq_sealed() {
            self.pq_rows_sealed()?
        } else {
            self.pq_rows_plain()?
        };
        let stride = if code_len > 0 {
            code_len
        } else {
            rows.first().map_or(0, |(_, _, c)| c.len())
        };
        let paged = self.pq_sealed() && self.pq_pages_present()?;
        let mut cache = if paged {
            PqCache::new_paged(stride)
        } else {
            PqCache::new(stride)
        };
        for (seq, list, code) in &rows {
            cache.push(*seq, *list, code);
        }
        *self.pq_cache.borrow_mut() = Some(cache);
        Ok(())
    }

    /// The sealed per-row load: decrypt each `drawer_pq` blob under its
    /// seq-bound AAD. Rows that fail to open are skipped — the verify
    /// equation catches real drift; a skipped row costs a candidate slot.
    fn pq_rows_sealed(&self) -> Result<Vec<(i64, i64, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT seq, code FROM drawer_pq")?;
        let sealed: Vec<(i64, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok(sealed
            .into_iter()
            .filter_map(|(seq, blob)| {
                let plain = self
                    .vault
                    .index_from_rest(&format!("pqrow/{seq}"), &blob)
                    .ok()?;
                let (list, code) = Self::pq_row_unpack(&plain)?;
                Some((seq, list, code))
            })
            .collect())
    }

    /// Decrypt the given lists' pages into the cache. No-op for lists
    /// already loaded, and for non-paged caches (`loaded == None`).
    fn pq_cache_load_lists(&self, lists: &[i64]) -> Result<(), StoreError> {
        let mut cache_ref = self.pq_cache.borrow_mut();
        let Some(cache) = cache_ref.as_mut() else {
            return Ok(());
        };
        let Some(loaded) = &cache.loaded else {
            return Ok(());
        };
        let missing: Vec<i64> = lists
            .iter()
            .copied()
            .filter(|l| !loaded.contains(l))
            .collect();
        for list in missing {
            let mut stmt = self
                .conn
                .prepare("SELECT pageno, blob FROM pq_page WHERE list = ?1")?;
            let pages: Vec<(i64, Vec<u8>)> = stmt
                .query_map(params![list], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            for (pageno, blob) in pages {
                let Ok(plain) = self
                    .vault
                    .index_from_rest(&format!("pqpage/{list}/{pageno}"), &blob)
                else {
                    continue;
                };
                let Some(rows) = Self::pq_page_unpack(&plain, cache.code_len) else {
                    continue;
                };
                for (seq, code) in rows {
                    cache.push(seq, list, &code);
                }
            }
            cache
                .loaded
                .as_mut()
                .expect("paged cache checked above")
                .insert(list);
        }
        Ok(())
    }

    /// Decrypt every remaining page (flat scans, or a probe that came up
    /// short and widened). Afterwards the cache is fully resident.
    fn pq_cache_load_all(&self) -> Result<(), StoreError> {
        {
            let cache_ref = self.pq_cache.borrow();
            match cache_ref.as_ref() {
                Some(c) if c.loaded.is_some() => {}
                _ => return Ok(()),
            }
        }
        let mut stmt = self.conn.prepare("SELECT DISTINCT list FROM pq_page")?;
        let lists: Vec<i64> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        drop(stmt);
        self.pq_cache_load_lists(&lists)?;
        if let Some(cache) = self.pq_cache.borrow_mut().as_mut() {
            cache.loaded = None;
        }
        Ok(())
    }

    /// The hmac-only cache load: plain `(seq, list, code)` rows as stored.
    fn pq_rows_plain(&self) -> Result<Vec<(i64, i64, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT seq, list, code FROM drawer_pq")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
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

    /// Apply a buffered [`PendingMeta`] decision.
    ///
    /// Called from INSIDE a rebuild's transaction, never beside the training
    /// call that produced it — that placement is the whole point (see
    /// [`PendingMeta`]). `artifact` is the generation key, which for the
    /// per-wing tier is a dynamic `<wing>/<name>` string.
    ///
    /// One residue, stated: the DURABLE counter (the `meta` row every
    /// surface reports) rolls back with the transaction, but
    /// `codebook_generation_bump` also sets a live telemetry gauge eagerly,
    /// and a rollback leaves that gauge one ahead until the next bump. It is
    /// a count of training events, not integrity evidence, and the same
    /// residue every `one_rewrite` caller already carries.
    fn pq_meta_apply(
        &self,
        key: &str,
        artifact: &str,
        pending: &PendingMeta,
    ) -> Result<(), StoreError> {
        match pending {
            PendingMeta::Keep => {}
            PendingMeta::Put(bytes) => {
                self.pq_meta_put(key, bytes)?;
                self.codebook_generation_bump(artifact);
            }
            PendingMeta::Drop => {
                self.conn
                    .execute("DELETE FROM pq_meta WHERE key = ?1", params![key])?;
            }
        }
        Ok(())
    }

    /// Warn when a freshly trained codebook fits its own training sample much
    /// better than the corpus it will encode.
    ///
    /// The failure this catches is measured, not hypothetical: a sample drawn
    /// by an even stride over a corpus with periodic insertion order took one
    /// repeating slice, and `synth --n 16384` scored R@5 83.0% against 99.7%.
    /// Nothing in the codebook's bytes says that happened and its error on its
    /// own sample looks fine — only the gap to unseen vectors shows it. The
    /// draw that caused it is gone, but a codebook can still be handed an
    /// unrepresentative corpus (one enormous near-duplicate cluster, an
    /// `external:` embedder with a degenerate space), and a vault trained by
    /// an older build keeps its codebook until something forces a retrain.
    ///
    /// Advisory: it never fails a training pass. The probe is a second keyed
    /// draw, so it overlaps the sample only by chance and only slightly.
    pub(crate) fn warn_unrepresentative(
        &self,
        artifact: &str,
        pq: &ProductQuantizer,
        sample: &[Vec<f32>],
        probe: &[Vec<f32>],
    ) {
        if probe.is_empty() {
            return;
        }
        let fit = pq.fit_report(sample, probe);
        if fit.looks_unrepresentative() {
            undercroft_obs::diag_warn!(
                "codebook {artifact}: trained sample reconstructs at {:.5} but \
                 unseen vectors at {:.5} ({:.1}x). The training sample does not \
                 represent this corpus, so approximate distances will be worse \
                 than they should be for everything outside it. Two known \
                 causes: a codebook trained by a pre-keyed-draw build (an even \
                 stride over a periodic ingest — re-train the index), or a \
                 corpus whose rows each carry unique content the sample cap \
                 cannot represent (ids, keys, codes — a larger corpus makes \
                 the gap wider, not wrong; check retrieval recall before \
                 acting).",
                fit.sample_error,
                fit.probe_error,
                fit.ratio()
            );
        }
    }

    /// Run one derived-index rewrite as a single durable unit.
    ///
    /// Two defects share this shape and both are closed here (ROADMAP A20).
    /// **Cost**: under `synchronous=FULL` an autocommit `UPDATE` per row is
    /// one fsync per row — measured at 7.8–8.3 ms/row when `pq_build` had it,
    /// i.e. ~95% of a "build cost" that was disk syncs rather than
    /// computation. **Correctness**: a codebook is written *before* the rows
    /// it recodes, so an interruption between them leaves a v2 codebook
    /// beside v1 rows; that survived only because the readers accept both
    /// formats, which is luck, not design. One transaction makes the pair
    /// atomic and a crash roll back to the previous coherent state.
    ///
    /// `pq_build` takes the transaction directly. These paths cannot, because
    /// they are also reachable from inside a caller's transaction — the
    /// advisory-encode rule ("never BEGIN, or batching breaks": `upsert_many`
    /// owns one transaction across a whole batch and calls into the encode
    /// paths). `is_autocommit` is what lets one function honour both: at the
    /// top level it opens a transaction, inside someone else's it does
    /// nothing and the writes are atomic with the enclosing one anyway.
    /// A `BEGIN` there would fail outright, which is why the un-transacted
    /// loops could not simply be wrapped.
    ///
    /// The trade is stated, not hidden: a rebuild now holds the write lock
    /// for its whole duration, encode arithmetic included, where before it
    /// released between rows. `pq_build` made the same trade first and for
    /// the same reason — the alternative is a partial table, and a rebuild
    /// that fsyncs per row is slow enough to hold the lock roughly as long
    /// anyway. Where a rewrite is genuinely full-corpus and concurrent
    /// readers must keep serving (`rebuild_fts`), the answer is a shadow
    /// table and a swap, not a longer lock.
    pub(crate) fn one_rewrite<T>(
        &self,
        f: impl FnOnce() -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        if !self.conn.is_autocommit() {
            return f();
        }
        // `unchecked_transaction` because these run behind `&self` on the
        // search path, exactly as `pq_build`'s does.
        let tx = self.conn.unchecked_transaction()?;
        let out = f()?;
        tx.commit()?;
        Ok(out)
    }

    /// Indices of the keyed training sample over `items`, each identified by
    /// `ident` — the draw described on [`stratified_keyed`]. `label` separates
    /// one artifact's draw from another's, so two codebooks trained from the
    /// same corpus do not train on the same rows.
    pub(crate) fn keyed_sample<T>(
        &self,
        label: &str,
        items: &[T],
        want: usize,
        ident: impl Fn(&T) -> Vec<u8>,
    ) -> Vec<usize> {
        stratified_keyed(items.len(), want, |i| {
            self.vault.sample_rank(label, &ident(&items[i]))
        })
    }

    /// Source attribution maps — (wing, agent claim) — for the capped
    /// draws whose row sets don't carry them themselves (the FDE tier's).
    /// The agent claim reads from the unsealed `meta_json` (it is
    /// metadata by design, the `added_by` trade extended).
    #[allow(clippy::type_complexity)]
    pub(crate) fn source_by_drawer_id(
        &self,
    ) -> Result<std::collections::HashMap<String, (String, Option<String>)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, wing, json_extract(meta_json, '$.agent') FROM drawers")?;
        let map = stmt
            .query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?
            .collect::<Result<_, _>>()?;
        Ok(map)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn source_by_seq(
        &self,
    ) -> Result<std::collections::HashMap<i64, (String, Option<String>)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, wing, json_extract(meta_json, '$.agent') FROM drawers")?;
        let map = stmt
            .query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?
            .collect::<Result<_, _>>()?;
        Ok(map)
    }

    /// [`Self::keyed_sample`] with a SOFT per-source cap — C3.3's density
    /// channel closed at the training draw: owning fraction *f* of a
    /// corpus used to buy ≈*f* of any uniform sample, so a bulk writer
    /// could shape the codebook that scores every other wing. Two
    /// groupings bound the draw, each at `want / cap_div`:
    ///
    /// - **the wing** — the isolation unit, the adversarial bound: wing
    ///   assignment belongs to the deployment, not the writer;
    /// - **the agent CLAIM** (`meta.agent`, when present) — the
    ///   **accident** bound: one runaway agent flooding across several
    ///   wings no longer buys the combined share. A claim is the
    ///   writer's own statement, so an adversary defeats this grouping
    ///   by omitting or varying it — which is why it bounds accidents,
    ///   never adversaries, and why the wing grouping stays the security
    ///   claim. Rows with NO agent claim are deliberately exempt from
    ///   the agent grouping: most corpora carry no claims, and treating
    ///   "unclaimed" as one giant pseudo-agent would cap every ordinary
    ///   vault at a fraction of its own sample.
    ///
    /// Mechanics, chosen for two properties that are pinned by test:
    /// - **Every group within quota ⇒ EXACTLY the uncapped draw.** The
    ///   base draw is [`stratified_keyed`] unchanged; the cap only
    ///   truncates a group that exceeded its quota (dropping its
    ///   highest-ranked picks) and refills from unpicked rows in
    ///   keyed-rank order. A single-wing claim-less vault is always a
    ///   no-op, and a corpus whose wings and agents sit inside their
    ///   quotas keeps byte-identical codebooks.
    /// - **Soft, never starving.** When honest rows cannot fill the
    ///   freed slots, the capped groups' own next rows refill last — the
    ///   sample never shrinks, because a smaller training sample is a
    ///   quality cost every wing pays.
    pub(crate) fn keyed_sample_capped<T>(
        &self,
        label: &str,
        items: &[T],
        want: usize,
        ident: impl Fn(&T) -> Vec<u8>,
        source: impl Fn(&T) -> (String, Option<String>),
    ) -> Vec<usize> {
        let base = self.keyed_sample(label, items, want, &ident);
        let cap_div = self.train_source_cap;
        if cap_div == usize::MAX || base.len() < 2 {
            return base;
        }
        // The whole corpus fits the sample: there is no DRAW to bias, and
        // truncating would shrink the training set with nothing left to
        // refill from. The cap bounds the sampling channel; below the
        // sampling threshold a flooding wing's k-means mass is bounded by
        // the per-wing codebook isolation instead (its own tier), not
        // here — recorded, not hidden.
        if base.len() >= items.len() {
            return base;
        }
        let mut wings: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut agents: std::collections::HashSet<String> = std::collections::HashSet::new();
        for it in items {
            let (w, a) = source(it);
            wings.insert(w);
            if let Some(a) = a {
                agents.insert(a);
            }
        }
        // Fewer groups than the divisor: quota is an even split — with
        // one wing (or no claims at all) that grouping is a no-op.
        let wing_cap = want.div_ceil(cap_div.min(wings.len().max(1)));
        let agent_cap = (!agents.is_empty()).then(|| want.div_ceil(cap_div.min(agents.len())));
        let mut per_w: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut per_a: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for &i in &base {
            let (w, a) = source(&items[i]);
            *per_w.entry(w).or_default() += 1;
            if let Some(a) = a {
                *per_a.entry(a).or_default() += 1;
            }
        }
        let within = per_w.values().all(|&n| n <= wing_cap)
            && agent_cap.is_none_or(|c| per_a.values().all(|&n| n <= c));
        if within {
            return base;
        }
        let rank = |i: usize| self.vault.sample_rank(label, &ident(&items[i]));
        // Admission under both quotas at once; `soft` waives them on the
        // final refill pass so the sample never shrinks.
        let mut cw: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut ca: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut admit = |i: usize, soft: bool| -> bool {
            let (w, a) = source(&items[i]);
            let ok_w = soft || cw.get(&w).copied().unwrap_or(0) < wing_cap;
            let ok_a = soft
                || match (&a, agent_cap) {
                    (Some(name), Some(cap)) => ca.get(name).copied().unwrap_or(0) < cap,
                    _ => true,
                };
            if ok_w && ok_a {
                *cw.entry(w).or_default() += 1;
                if let Some(a) = a {
                    *ca.entry(a).or_default() += 1;
                }
                true
            } else {
                false
            }
        };
        // Keep each group's lowest-ranked picks; drop the excess.
        let mut by_rank: Vec<usize> = base.clone();
        by_rank.sort_by_key(|&i| rank(i));
        let mut kept: Vec<usize> = Vec::with_capacity(base.len());
        for &i in &by_rank {
            if admit(i, false) {
                kept.push(i);
            }
        }
        // Refill the freed slots from unpicked rows, keyed-rank order,
        // respecting the quotas first and softening only when nothing
        // else remains.
        let picked: std::collections::HashSet<usize> = base.iter().copied().collect();
        let mut rest: Vec<usize> = (0..items.len()).filter(|i| !picked.contains(i)).collect();
        rest.sort_by_key(|&i| rank(i));
        let mut in_kept: std::collections::HashSet<usize> = kept.iter().copied().collect();
        for pass_soft in [false, true] {
            for &i in &rest {
                if kept.len() >= base.len() {
                    break;
                }
                if in_kept.contains(&i) {
                    continue;
                }
                if admit(i, pass_soft) {
                    in_kept.insert(i);
                    kept.push(i);
                }
            }
        }
        kept
    }

    /// Fill the RAM cache from the persisted IVF centroids, if any.
    fn ivf_load(&self) -> Result<(), StoreError> {
        let stored = self.pq_meta_get("ivf")?;
        *self.ivf.borrow_mut() = stored.and_then(|b| CoarseQuantizer::from_bytes(&b));
        Ok(())
    }

    /// Load an existing PQ index into the session caches, building nothing —
    /// the read-only posture (R1). `false` means there is nothing usable to
    /// load and the caller must fall back to the exact scan.
    ///
    /// Deliberately does NOT call `pq_schema()`: creating those tables is a
    /// write, and their absence is precisely the answer "this vault has no
    /// index". Deliberately does not repack or compact either — both rewrite
    /// the on-disk format, and a replica must leave the format its writer
    /// chose exactly as it found it.
    fn pq_load_only(&self) -> Result<bool, StoreError> {
        if !self.table_exists("drawer_pq")? || !self.table_exists("pq_meta")? {
            return Ok(false);
        }
        if self.pq.borrow().is_none() {
            let Some(pq) = self
                .pq_meta_get("codebook")?
                .and_then(|b| ProductQuantizer::from_bytes(&b))
            else {
                return Ok(false);
            };
            *self.pq.borrow_mut() = Some(pq);
        }
        if self.ivf.borrow().is_none() {
            self.ivf_load()?;
        }
        let drawers: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM drawers", [], |r| r.get(0))?;
        if drawers == 0 {
            return Ok(false);
        }
        // The coverage boundary, stated rather than hidden: a writable open
        // self-heals a short index by rebuilding it, and this one cannot, so
        // drawers written after the index was last built are invisible to
        // the prefilter. That is a RECALL cost, never a wrong answer — the
        // candidates it does return are hydrated and scored exactly as
        // always — but it is the kind of degradation a replica operator has
        // to be told about rather than discover in a recall number.
        let tail_matched: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM drawer_pq p JOIN drawers d ON d.seq = p.seq",
            [],
            |r| r.get(0),
        )?;
        let matched = if self.pq_pages_present()? {
            let live = self
                .pq_count_get("rowcount")?
                .saturating_sub(self.pq_count_get("deleted")?);
            tail_matched + live as i64
        } else {
            tail_matched
        };
        if matched != drawers {
            undercroft_obs::diag_warn!(
                "read-only open: the PQ index covers {matched} of {drawers} drawers and \
                 cannot be rebuilt here; the uncovered rows are not offered as candidates \
                 until a writable open heals it"
            );
        }
        self.pq_live.set(drawers);
        self.pq_verified.set(true);
        Ok(true)
    }

    /// Whether a table exists, without creating it — the read-only tiers ask
    /// before they read, because the `CREATE TABLE IF NOT EXISTS` they would
    /// otherwise ride on is a write.
    pub(crate) fn table_exists(&self, name: &str) -> Result<bool, StoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![name],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Load-or-train the codebook and (re)encode every drawer; train (or
    /// retrain) the IVF partitions when the corpus warrants them, drop them
    /// when it doesn't. Returns `false` when the corpus can't be quantized
    /// (empty, or dimension not divisible into subspaces) — the caller falls
    /// back to the full scan.
    ///
    /// Writes throughout, so a read-only store never reaches it — see
    /// [`Self::pq_load_only`], which is what that posture calls instead.
    fn pq_build(&self) -> Result<bool, StoreError> {
        // (seq, id, sealed embedding, wing, agent claim)
        type EmbeddingRow = (i64, String, Vec<u8>, String, Option<String>);
        let mut stmt = self.conn.prepare(
            "SELECT seq, id, embedding, wing, json_extract(meta_json, '$.agent') FROM drawers",
        )?;
        let rows: Vec<EmbeddingRow> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<_, _>>()?;
        if rows.is_empty() {
            return Ok(false);
        }
        let mut items = Vec::with_capacity(rows.len());
        for (seq, id, rest, wing, agent) in rows {
            let emb =
                self.vault
                    .embedding_from_rest(&id, &rest)
                    .map_err(|e| StoreError::CorruptRow {
                        id: id.clone(),
                        reason: e.to_string(),
                    })?;
            items.push((seq, emb, wing, agent));
        }

        let stored = self.pq_meta_get("codebook")?;
        // A freshly trained codebook is BUFFERED, not written here — see
        // [`PendingMeta`]. `Keep` is the reuse arm: a rebuild through the
        // `Some(codebook)` branch re-encodes every row against the stored
        // artifact and must not step its generation.
        let mut codebook_write = PendingMeta::Keep;
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
                // Train on a keyed sample — per-wing-capped, so a bulk
                // writer's density buys at most a bounded share of the
                // codebook. Codebooks tolerate sampling well.
                let sample: Vec<Vec<f32>> = self
                    .keyed_sample_capped(
                        CODEBOOK_PQ,
                        &items,
                        PQ_TRAIN_SAMPLE,
                        |(seq, _, _, _)| seq.to_le_bytes().to_vec(),
                        |(_, _, wing, agent)| (wing.clone(), agent.clone()),
                    )
                    .into_iter()
                    .map(|i| items[i].1.clone())
                    .collect();
                let Some(pq) = ProductQuantizer::train(&sample, m, PQ_TRAIN_ITERS) else {
                    return Ok(false);
                };
                codebook_write = PendingMeta::Put(pq.to_bytes());
                // Only meaningful when a sample was actually drawn: below the
                // cap the sample *is* the corpus and the probe is inside it.
                if items.len() > PQ_TRAIN_SAMPLE {
                    // The probe stays UNCAPPED on purpose: it represents
                    // the corpus as it is, so a capped sample facing a
                    // heavily skewed corpus can legitimately warn — that
                    // skew being visible is information, not noise.
                    let probe: Vec<Vec<f32>> = self
                        .keyed_sample("pq-fit-probe", &items, PQ_FIT_PROBE, |(seq, _, _, _)| {
                            seq.to_le_bytes().to_vec()
                        })
                        .into_iter()
                        .map(|i| items[i].1.clone())
                        .collect();
                    self.warn_unrepresentative(CODEBOOK_PQ, &pq, &sample, &probe);
                }
                pq
            }
        };

        // IVF partitions: (re)train whenever the corpus is IVF-sized and the
        // cached centroids are absent or outgrown; drop them below the
        // threshold so they can't silently go stale. Buffered like the
        // codebook — and `self.ivf` is TAKEN rather than borrowed, so the
        // handle is re-pointed only after the commit. Assigning lists from a
        // RAM copy the transaction then rolled back is the same split state
        // one level up: the next verify pass reads those centroids as fresh,
        // skips the retrain, and commits rows partitioned by centroids no
        // reader can load. Left empty by a failure it is harmless — the
        // verify path calls `ivf_load` whenever it is `None`.
        let n = items.len();
        let mut ivf_write = PendingMeta::Keep;
        let mut ivf = self.ivf.borrow_mut().take();
        if n >= self.ivf_min {
            let fresh = matches!(ivf.as_ref(), Some(cq) if ivf_fresh(n as u64, cq.trained_n()));
            if !fresh {
                // √N lists, clamped. The upper clamp sat at 1024 until the
                // page-level spike showed √N must keep tracking N past 10⁶
                // (a 10⁷ corpus at 1024 lists puts ~10k rows in every probe
                // slab); 4096 covers √N up to ~16M drawers and matches the
                // inverted-FDE tier's clamp.
                let nlist = (n as f64).sqrt() as usize;
                let nlist = nlist.clamp(16, 4096);
                // A separate label from the codebook's: two independent draws
                // rather than the identical stride both used to take.
                let sample: Vec<Vec<f32>> = self
                    .keyed_sample_capped(
                        CODEBOOK_PQ_IVF,
                        &items,
                        PQ_TRAIN_SAMPLE,
                        |(seq, _, _, _)| seq.to_le_bytes().to_vec(),
                        |(_, _, wing, agent)| (wing.clone(), agent.clone()),
                    )
                    .into_iter()
                    .map(|i| items[i].1.clone())
                    .collect();
                match CoarseQuantizer::train(&sample, nlist, IVF_TRAIN_ITERS, n as u64) {
                    Some(cq) => {
                        ivf_write = PendingMeta::Put(cq.to_bytes());
                        ivf = Some(cq);
                    }
                    None => {
                        ivf_write = PendingMeta::Drop;
                        ivf = None;
                    }
                }
            }
        } else {
            ivf_write = PendingMeta::Drop;
            ivf = None;
        }

        // A rebuild always writes the target format from scratch — it is
        // also the migration path of last resort (any drift lands here).
        //
        // ONE transaction for the whole rewrite. This loop used to run each
        // row as an autocommit INSERT, which under `synchronous=FULL` is one
        // fsync per row — measured at 7.8–8.3 ms/row, i.e. 17 minutes at
        // 131k and 73 minutes at 524k of a "build cost" that was ~95% disk
        // syncs, not computation. `unchecked_transaction` because this runs
        // behind `&self` on the search path; it never nests inside a write
        // transaction (build is only ever entered from the verify pass).
        // A crash mid-rebuild rolls back to the pre-rebuild state, which the
        // matched-count self-heal already handles — strictly better than
        // the partial table an interrupted per-row loop left behind.
        //
        // That last sentence was FALSE until the buffered writes below: the
        // rows rolled back and the codebook/centroids did not, so the crash
        // landed in the one state the self-heal cannot see (M2, [`PendingMeta`]).
        let tx = self.conn.unchecked_transaction()?;
        self.pq_meta_apply("codebook", CODEBOOK_PQ, &codebook_write)?;
        self.pq_meta_apply("ivf", CODEBOOK_PQ_IVF, &ivf_write)?;
        self.conn.execute("DELETE FROM drawer_pq", [])?;
        self.conn.execute("DELETE FROM pq_page", [])?;
        self.conn.execute(
            "DELETE FROM pq_meta WHERE key IN ('rowcount', 'deleted')",
            [],
        )?;
        let mut ins = self
            .conn
            .prepare("INSERT OR REPLACE INTO drawer_pq (list, seq, code) VALUES (?1, ?2, ?3)")?;
        let sealed = self.pq_sealed();
        let paged = self.pq_pages_on(items.len());
        let mut cache = PqCache::new(pq.code_len());
        let mut by_list: std::collections::HashMap<i64, Vec<(i64, Vec<u8>)>> =
            std::collections::HashMap::new();
        // Encode + IVF-assign are pure math over shared read-only
        // codebooks — the CPU residual left after the transaction fix, and
        // it parallelizes cleanly (bounded by rayon's pool). Sealing and
        // the SQLite writes stay serial below: one connection, and the
        // AEAD seal is microseconds per 52-byte row.
        let coded: Vec<(i64, i64, Vec<u8>)> = {
            use rayon::prelude::*;
            let cq = ivf.as_ref();
            items
                .par_iter()
                .map(|(seq, vec, _, _)| {
                    let list: i64 = cq.map_or(-1, |c| c.assign(vec) as i64);
                    (*seq, list, pq.encode(vec))
                })
                .collect()
        };
        for (seq, list, code) in &coded {
            let (seq, list) = (*seq, *list);
            if paged {
                by_list.entry(list).or_default().push((seq, code.clone()));
            } else if sealed {
                // Sealed row: list id + code AEAD-sealed together, bound to
                // this seq; the plaintext list column stays -1 (a clear list
                // id would leak semantic clustering).
                let blob = self
                    .vault
                    .index_at_rest(&format!("pqrow/{seq}"), &Self::pq_row_pack(list, code));
                ins.execute(params![-1i64, seq, blob])?;
            } else {
                ins.execute(params![list, seq, code])?;
            }
            // Either level's RAM cache is populated from the plaintext
            // already in hand — no re-read, no re-decrypt. After a paged
            // build the cache is fully resident (`loaded = None`).
            cache.push(seq, list, code);
        }
        drop(ins);
        if paged {
            self.pq_page_append(by_list)?;
        }
        tx.commit()?;
        // RAM follows the commit, never precedes it.
        *self.ivf.borrow_mut() = ivf;
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
        // The wing tier first: it has its own codebook and its own coherence
        // story, and must not be skipped by the global early-returns below.
        self.wing_pq_encode_row(id, embedding, created);
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
        // (list, seq) duplicate. On the page tier a single write always
        // lands as a *tail* row (today's per-row form) — never a page
        // reseal; the fold happens per batch / per verify pass.
        let outcome = self
            .conn
            .query_row("SELECT seq FROM drawers WHERE id = ?1", params![id], |r| {
                r.get::<_, i64>(0)
            })
            .and_then(|seq| {
                let tail_dropped = self
                    .conn
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
                Ok((seq, tail_dropped))
            });
        match outcome {
            Ok((seq, tail_dropped)) => {
                // An updated drawer whose previous code lives inside a page
                // leaves it there as a stale copy (rewriting the page per
                // single write is the amplification the tail exists to
                // avoid). Count it out of the sealed commitment so the
                // verify equation stays balanced; the copy wastes one
                // candidate slot until the next rebuild repacks.
                if !created && tail_dropped == 0 {
                    if let Ok(true) = self.pq_pages_present() {
                        let bumped = self
                            .pq_count_get("deleted")
                            .and_then(|d| self.pq_count_put("deleted", d + 1));
                        if bumped.is_err() {
                            self.pq_verified.set(false);
                        }
                    }
                }
                // Keep the RAM cache coherent with the plaintext in hand.
                if let Some(cache) = self.pq_cache.borrow_mut().as_mut() {
                    cache.remove_seq(seq);
                    cache.push(seq, list, &code);
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

    /// Purge one drawer's code on delete (called by `delete_drawer` with
    /// the drawer row still live). Tail rows delete directly; a code inside
    /// a sealed page is instead counted out of the commitment (`deleted`) —
    /// the page itself is rewritten only by fold/rebuild, never per delete.
    /// Advisory: any failure arms the next search's verification.
    pub(crate) fn pq_purge_row(&self, id: &str) {
        let outcome: Result<(), StoreError> = (|| {
            let row: Option<(i64, String)> = self
                .conn
                .query_row(
                    "SELECT seq, wing FROM drawers WHERE id = ?1",
                    params![id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((seq, wing)) = row else {
                return Ok(());
            };
            let tail = self
                .conn
                .execute("DELETE FROM drawer_pq WHERE seq = ?1", params![seq])?;
            if tail == 0 && self.pq_pages_present()? {
                let d = self.pq_count_get("deleted")?;
                self.pq_count_put("deleted", d + 1)?;
            }
            // The wing tier mirrors the tail: per-row deletes, no page
            // tier, and the wing's RAM cache is updated surgically (both
            // sides of its matched-count equation lose one row).
            let _ = self
                .conn
                .execute("DELETE FROM drawer_pq_wing WHERE seq = ?1", params![seq]);
            if let Some(Some(st)) = self.wing_pq.borrow_mut().get_mut(&wing) {
                st.cache.remove_seq(seq);
                st.live -= 1;
            }
            Ok(())
        })();
        if outcome.is_err() {
            self.pq_verified.set(false);
            self.wing_pq.borrow_mut().clear();
        }
    }

    /// Vector top-`k` candidate seqs for one wing, from that wing's own
    /// index. `None` ⇒ the wing has no usable index (below the floor, or a
    /// dimension PQ can't split) — the caller falls back to the full scan,
    /// which the `WHERE wing` clause bounds by the wing's size. That
    /// fallback is a *recall* choice as much as a cost one: intersecting
    /// corpus-wide candidates with a wing can starve it entirely, while a
    /// full scan of a below-floor wing is exact and floor-bounded.
    ///
    /// Verification is per wing and event-driven, mirroring the global
    /// tier: the first scoped query after open (or after a write this
    /// session couldn't index) runs the wing's matched-count check and
    /// rebuilds on drift; a verified wing stays on the fast path.
    /// Test surface: the production path always resolves a scope first and
    /// calls [`Self::wing_pq_candidates_in`].
    #[cfg(test)]
    pub(crate) fn wing_pq_candidates(
        &self,
        wing: &str,
        qvec: &[f32],
        k: usize,
    ) -> Result<Option<Vec<i64>>, StoreError> {
        self.wing_pq_candidates_in(wing, qvec, k, None)
    }

    /// [`Self::wing_pq_candidates`] restricted to a declared scope's seq
    /// set — a `room` inside the wing. The wing's own index honors the wing
    /// filter by construction; the scope carries what it cannot see.
    pub(crate) fn wing_pq_candidates_in(
        &self,
        wing: &str,
        qvec: &[f32],
        k: usize,
        scope: Option<&crate::SeqFilter>,
    ) -> Result<Option<Vec<i64>>, StoreError> {
        if !self.wing_pq.borrow().contains_key(wing) {
            let built = self.wing_pq_build(wing)?;
            self.wing_pq.borrow_mut().insert(wing.to_string(), built);
        }
        // Growth re-check on the fast path (cheap, in-RAM counters): a wing
        // that crossed the IVF threshold, or doubled past its partitions'
        // training size, rebuilds once rather than silently degrading.
        // A read-only store may not rebuild (R1) — it keeps the index its
        // writer left, which is a recall cost and not a wrong answer.
        let outgrown = self.may_build_indexes()
            && match self.wing_pq.borrow().get(wing) {
                Some(Some(st)) => match st.ivf.as_ref() {
                    Some(cq) => !ivf_fresh(st.live as u64, cq.trained_n()),
                    None => st.live as usize >= self.ivf_min,
                },
                _ => false,
            };
        if outgrown {
            let rebuilt = self.wing_pq_build(wing)?;
            self.wing_pq.borrow_mut().insert(wing.to_string(), rebuilt);
        }
        let map = self.wing_pq.borrow();
        let Some(Some(st)) = map.get(wing) else {
            return Ok(None);
        };
        // Same corpus-scaled pool as the global path, against the wing's
        // own live count — a wing large enough to leak gets the same cure.
        // A NARROWED call arrives already scaled to its scope's population.
        // An exclusion has been scaled by nothing and must keep the corpus
        // divisor: gating on `is_some()` let one quarantined row pin stage
        // 1 at the caller's fixed floor, which is the measured recall leak
        // this divisor exists to close.
        let k = if scope.is_some_and(|f| f.narrows()) {
            k
        } else {
            k.max(st.live as usize / self.pool_div.max(1))
        };
        let tables = st.pq.distance_tables(qvec);
        let probe: Option<Vec<i64>> = st.ivf.as_ref().and_then(|cq| {
            let nprobe = self.ivf_nprobe.unwrap_or_else(|| (cq.nlist() / 4).max(8));
            let lists = cq.probe(qvec, nprobe);
            if lists.is_empty() {
                None
            } else {
                let mut l: Vec<i64> = lists.into_iter().map(i64::from).collect();
                l.push(-1);
                Some(l)
            }
        });
        let widen = match &probe {
            Some(lists) => st.cache.rows_in(lists) < k,
            None => true,
        };
        let mut scored: Vec<(f32, i64)> = Vec::new();
        match &probe {
            Some(lists) if !widen => st.cache.scan(&st.pq, &tables, Some(lists), &mut scored),
            _ => st.cache.scan(&st.pq, &tables, None, &mut scored),
        }
        if let Some(s) = scope {
            scored.retain(|(_, seq)| s.admits(seq));
            // Under-delivery inside the scope widens to the whole wing —
            // the wing cache is fully resident, so this is one more scan,
            // not a load.
            if scored.len() < k && probe.is_some() && !widen {
                scored.clear();
                st.cache.scan(&st.pq, &tables, None, &mut scored);
                scored.retain(|(_, seq)| s.admits(seq));
            }
        }
        if scored.len() > k {
            scored.select_nth_unstable_by(k - 1, |a, b| {
                a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
            });
            scored.truncate(k);
        }
        undercroft_obs::search_wings_probed(1);
        Ok(Some(scored.into_iter().map(|(_, seq)| seq).collect()))
    }

    /// Verify-or-build one wing's index. `Ok(None)` means the wing earns no
    /// index (below the floor, or unquantizable) and the caller should
    /// full-scan; the `None` is cached in the session map so the check runs
    /// once, invalidated by any write to that wing.
    fn wing_pq_build(&self, wing: &str) -> Result<Option<WingPq>, StoreError> {
        // R1: on a read-only store this function may only take its
        // coherent-LOAD path below. Creating the schema is a write, and the
        // tables' absence already means "no index here".
        if self.may_build_indexes() {
            self.pq_schema()?;
        } else if !self.table_exists("drawer_pq_wing")? || !self.table_exists("pq_meta")? {
            self.ro_prefilter_fallback("per-wing PQ");
            return Ok(None);
        }
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM drawers WHERE wing = ?1",
            params![wing],
            |r| r.get(0),
        )?;
        if (count as usize) < self.wing_pq_min {
            // A wing that shrank below the floor sheds its artifacts —
            // a stale codebook silently kept is the exact failure class the
            // generation counters exist to make visible elsewhere. Shedding
            // is a write, so a read-only store leaves the stale artifacts
            // alone and simply declines the tier: the wing full-scans, which
            // is what a below-floor wing does anyway.
            if self.may_build_indexes() {
                self.conn
                    .execute("DELETE FROM drawer_pq_wing WHERE wing = ?1", params![wing])?;
                self.conn.execute(
                    "DELETE FROM pq_meta WHERE key IN (?1, ?2)",
                    params![format!("codebook/{wing}"), format!("ivf/{wing}")],
                )?;
            }
            return Ok(None);
        }

        // The wing's vectors, decrypted once for whichever path runs.
        let mut stmt = self
            .conn
            .prepare("SELECT seq, id, embedding FROM drawers WHERE wing = ?1")?;
        let rows: Vec<(i64, String, Vec<u8>)> = stmt
            .query_map(params![wing], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        drop(stmt);
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
        if items.is_empty() {
            return Ok(None);
        }

        let codebook_key = format!("codebook/{wing}");
        let ivf_key = format!("ivf/{wing}");
        let stored = self
            .pq_meta_get(&codebook_key)?
            .and_then(|b| ProductQuantizer::from_bytes(&b));
        let want_ivf = (count as usize) >= self.ivf_min;

        // Coherent-load path: stored codebook, every live wing drawer has a
        // row (orphans are excluded by the join and are harmless), and the
        // partitions are neither missing-when-wanted nor outgrown.
        if let Some(pq) = &stored {
            let matched: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM drawer_pq_wing p JOIN drawers d \
                 ON d.seq = p.seq AND d.wing = p.wing WHERE p.wing = ?1",
                params![wing],
                |r| r.get(0),
            )?;
            let ivf = self
                .pq_meta_get(&ivf_key)?
                .and_then(|b| CoarseQuantizer::from_bytes(&b));
            let ivf_ok = if want_ivf {
                ivf.as_ref()
                    .is_some_and(|cq| ivf_fresh(count as u64, cq.trained_n()))
            } else {
                true
            };
            if matched == count && ivf_ok {
                let mut cache = PqCache::new(pq.code_len());
                let sealed = self.pq_sealed();
                let mut stmt = self
                    .conn
                    .prepare("SELECT seq, list, code FROM drawer_pq_wing WHERE wing = ?1")?;
                let stored_rows: Vec<(i64, i64, Vec<u8>)> = stmt
                    .query_map(params![wing], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<_, _>>()?;
                for (seq, list, blob) in stored_rows {
                    if sealed {
                        // A row that fails to open is skipped, not fatal —
                        // it costs its candidate slot until a rebuild, the
                        // same trade the global cache makes.
                        if let Ok(plain) = self
                            .vault
                            .index_from_rest(&format!("pqrow/{wing}/{seq}"), &blob)
                        {
                            if let Some((list, code)) = Self::pq_row_unpack(&plain) {
                                cache.push(seq, list, &code);
                            }
                        }
                    } else {
                        cache.push(seq, list, &blob);
                    }
                }
                return Ok(Some(WingPq {
                    pq: pq.clone(),
                    ivf: if want_ivf { ivf } else { None },
                    cache,
                    live: count,
                }));
            }
        }

        // Everything below rebuilds, and a read-only store may not (R1):
        // the wing's scoped query rides the exact scan instead, which is the
        // same path a wing below the tier floor already takes — bounded,
        // exact, and starvation-free.
        if !self.may_build_indexes() {
            self.ro_prefilter_fallback("per-wing PQ");
            return Ok(None);
        }
        // One string in two roles (draw label + generation key), same as the
        // global five — hoisted because the generation bump now happens down
        // in the transaction rather than beside the training call.
        let codebook_artifact = format!("{wing}/{CODEBOOK_PQ}");
        let ivf_artifact = format!("{wing}/{CODEBOOK_PQ_IVF}");

        // Rebuild. The codebook is reused when stored (a rebuild is not a
        // retrain and must not advance the generation); trained fresh
        // otherwise, on a keyed sample whose label carries the wing — every
        // wing draws independently. What a fresh training decides is
        // BUFFERED and applied inside the transaction below ([`PendingMeta`]):
        // this tier is the one that never self-heals, so a codebook landing
        // an fsync ahead of its rows here is permanent, not transient.
        let mut codebook_write = PendingMeta::Keep;
        let pq = match stored {
            Some(pq) => pq,
            None => {
                let dim = items[0].1.len();
                let Some(m) = [8usize, 4]
                    .iter()
                    .find(|&&dsub| dim % dsub == 0)
                    .map(|&dsub| dim / dsub)
                else {
                    return Ok(None);
                };
                let sample: Vec<Vec<f32>> = self
                    .keyed_sample(&codebook_artifact, &items, PQ_TRAIN_SAMPLE, |(seq, _)| {
                        seq.to_le_bytes().to_vec()
                    })
                    .into_iter()
                    .map(|i| items[i].1.clone())
                    .collect();
                let Some(pq) = ProductQuantizer::train(&sample, m, PQ_TRAIN_ITERS) else {
                    return Ok(None);
                };
                codebook_write = PendingMeta::Put(pq.to_bytes());
                if items.len() > PQ_TRAIN_SAMPLE {
                    let probe: Vec<Vec<f32>> = self
                        .keyed_sample(
                            &format!("{wing}/pq-fit-probe"),
                            &items,
                            PQ_FIT_PROBE,
                            |(seq, _)| seq.to_le_bytes().to_vec(),
                        )
                        .into_iter()
                        .map(|i| items[i].1.clone())
                        .collect();
                    self.warn_unrepresentative(&codebook_artifact, &pq, &sample, &probe);
                }
                pq
            }
        };

        let mut ivf_write = PendingMeta::Keep;
        let ivf = if want_ivf {
            let fresh = self
                .pq_meta_get(&ivf_key)?
                .and_then(|b| CoarseQuantizer::from_bytes(&b))
                .filter(|cq| ivf_fresh(count as u64, cq.trained_n()));
            match fresh {
                Some(cq) => Some(cq),
                None => {
                    let nlist = ((count as f64).sqrt() as usize).clamp(16, 4096);
                    let sample: Vec<Vec<f32>> = self
                        .keyed_sample(&ivf_artifact, &items, PQ_TRAIN_SAMPLE, |(seq, _)| {
                            seq.to_le_bytes().to_vec()
                        })
                        .into_iter()
                        .map(|i| items[i].1.clone())
                        .collect();
                    match CoarseQuantizer::train(&sample, nlist, IVF_TRAIN_ITERS, count as u64) {
                        Some(cq) => {
                            ivf_write = PendingMeta::Put(cq.to_bytes());
                            Some(cq)
                        }
                        // Untrainable: `Keep`, not `Drop` — this arm has
                        // always left a stored centroid set in place while
                        // encoding every row at list -1. Benign (a probe's
                        // list set always carries -1, so the scan still sees
                        // every row) and left exactly as it was: this unit
                        // moves WHEN a write happens, never WHETHER.
                        None => None,
                    }
                }
            }
        } else {
            ivf_write = PendingMeta::Drop;
            None
        };

        // Rebuild always writes from scratch — also the migration path of
        // last resort for this wing, exactly like the global rebuild. One
        // transaction for the same reason as there: per-row autocommit was
        // one fsync per row (measured 3.8 ms/row — the wing "build cost"
        // was disk syncs, not encoding) — and, since M2, the codebook and
        // the centroids ride it too.
        let tx = self.conn.unchecked_transaction()?;
        self.pq_meta_apply(&codebook_key, &codebook_artifact, &codebook_write)?;
        self.pq_meta_apply(&ivf_key, &ivf_artifact, &ivf_write)?;
        self.conn
            .execute("DELETE FROM drawer_pq_wing WHERE wing = ?1", params![wing])?;
        let mut ins = self.conn.prepare(
            "INSERT OR REPLACE INTO drawer_pq_wing (wing, list, seq, code) \
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        let sealed = self.pq_sealed();
        let mut cache = PqCache::new(pq.code_len());
        // Same split as the global rebuild: parallel encode+assign (pure
        // math, shared read-only codebooks), serial seal+write.
        let coded: Vec<(i64, i64, Vec<u8>)> = {
            use rayon::prelude::*;
            let cq = ivf.as_ref();
            items
                .par_iter()
                .map(|(seq, vec)| {
                    let list: i64 = cq.map_or(-1, |c| c.assign(vec) as i64);
                    (*seq, list, pq.encode(vec))
                })
                .collect()
        };
        for (seq, list, code) in &coded {
            let (seq, list) = (*seq, *list);
            if sealed {
                let blob = self.vault.index_at_rest(
                    &format!("pqrow/{wing}/{seq}"),
                    &Self::pq_row_pack(list, code),
                );
                ins.execute(params![wing, -1i64, seq, blob])?;
            } else {
                ins.execute(params![wing, list, seq, code])?;
            }
            cache.push(seq, list, code);
        }
        drop(ins);
        tx.commit()?;
        Ok(Some(WingPq {
            pq,
            ivf,
            cache,
            live: count,
        }))
    }

    /// Keep the written drawer's wing index coherent (advisory, mirrors the
    /// global incremental encode): a wing verified this session gets the row
    /// encoded in place; a wing checked-and-skipped gets its verdict
    /// invalidated on growth so the next scoped query re-checks the floor;
    /// a wing never consulted needs nothing — its first scoped query runs
    /// the matched-count verify anyway.
    fn wing_pq_encode_row(&self, id: &str, embedding: &[f32], created: bool) {
        if self.wing_pq_min == usize::MAX {
            return;
        }
        let Ok((seq, wing)) = self.conn.query_row(
            "SELECT seq, wing FROM drawers WHERE id = ?1",
            params![id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        ) else {
            return;
        };
        let invalidate = {
            let mut map = self.wing_pq.borrow_mut();
            match map.get_mut(&wing) {
                Some(Some(st)) => {
                    let code = st.pq.encode(embedding);
                    let list: i64 = st.ivf.as_ref().map_or(-1, |cq| cq.assign(embedding) as i64);
                    let outcome: Result<(), rusqlite::Error> = (|| {
                        self.conn
                            .execute("DELETE FROM drawer_pq_wing WHERE seq = ?1", params![seq])?;
                        if self.pq_sealed() {
                            let blob = self.vault.index_at_rest(
                                &format!("pqrow/{wing}/{seq}"),
                                &Self::pq_row_pack(list, &code),
                            );
                            self.conn.execute(
                                "INSERT OR REPLACE INTO drawer_pq_wing (wing, list, seq, code) \
                                 VALUES (?1, -1, ?2, ?3)",
                                params![wing, seq, blob],
                            )?;
                        } else {
                            self.conn.execute(
                                "INSERT OR REPLACE INTO drawer_pq_wing (wing, list, seq, code) \
                                 VALUES (?1, ?2, ?3, ?4)",
                                params![wing, list, seq, code],
                            )?;
                        }
                        Ok(())
                    })();
                    match outcome {
                        Ok(()) => {
                            st.cache.remove_seq(seq);
                            st.cache.push(seq, list, &code);
                            if created {
                                st.live += 1;
                            }
                            false
                        }
                        // A write the index couldn't absorb arms the wing's
                        // re-verify instead of leaving a silent hole.
                        Err(_) => true,
                    }
                }
                // The wing may have just crossed the floor.
                Some(None) if created => true,
                _ => false,
            }
        };
        if invalidate {
            self.wing_pq.borrow_mut().remove(&wing);
        }
    }

    /// Fold the accumulated tail into its lists' pages (the batch-boundary
    /// compaction `upsert_many` triggers, and the verify pass once the
    /// tail passes [`PQ_TAIL_FOLD`]). The cache reloads on next use — the
    /// folded rows would otherwise double once their lists lazily load.
    pub(crate) fn pq_compact_tail(&self) -> Result<(), StoreError> {
        let rows = self.pq_rows_sealed()?;
        if rows.is_empty() {
            return Ok(());
        }
        // Fold only rows for live drawers: committing an orphan (crash
        // window) into `rowcount` would unbalance the verify equation and
        // force a needless full rebuild.
        let live = self.pq_live_seqs()?;
        let mut by_list: std::collections::HashMap<i64, Vec<(i64, Vec<u8>)>> =
            std::collections::HashMap::new();
        for (seq, list, code) in rows {
            if live.contains(&seq) {
                by_list.entry(list).or_default().push((seq, code));
            }
        }
        self.pq_page_append(by_list)?;
        self.conn.execute("DELETE FROM drawer_pq", [])?;
        self.pq_cache.borrow_mut().take();
        Ok(())
    }

    fn pq_live_seqs(&self) -> Result<std::collections::HashSet<i64>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT seq FROM drawers")?;
        let live: std::collections::HashSet<i64> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        Ok(live)
    }

    /// Event-driven migration, per-row → pages: regroup the existing sealed
    /// rows without touching embeddings or the codebook. Runs from the
    /// verify pass when the page setting turns on over a coherent index.
    fn pq_repack_rows_to_pages(&self) -> Result<(), StoreError> {
        let rows = self.pq_rows_sealed()?;
        if rows.is_empty() {
            return Ok(());
        }
        // Orphans (rows whose drawer is gone) stay out of the commitment —
        // packing them in would immediately re-trigger a full rebuild.
        let live = self.pq_live_seqs()?;
        self.pq_count_put("rowcount", 0)?;
        self.pq_count_put("deleted", 0)?;
        let mut by_list: std::collections::HashMap<i64, Vec<(i64, Vec<u8>)>> =
            std::collections::HashMap::new();
        for (seq, list, code) in rows {
            if live.contains(&seq) {
                by_list.entry(list).or_default().push((seq, code));
            }
        }
        self.pq_page_append(by_list)?;
        self.conn.execute("DELETE FROM drawer_pq", [])?;
        self.pq_cache.borrow_mut().take();
        Ok(())
    }

    /// Event-driven migration, pages → per-row: unpack every page back
    /// into sealed rows (tail rows win over their stale page copies) and
    /// clear the page tier. Runs when the setting turns off.
    fn pq_repack_pages_to_rows(&self) -> Result<(), StoreError> {
        let Some(code_len) = self.pq.borrow().as_ref().map(|p| p.code_len()) else {
            return Ok(());
        };
        let mut tail_stmt = self.conn.prepare("SELECT seq FROM drawer_pq")?;
        let tail_seqs: std::collections::HashSet<i64> = tail_stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        drop(tail_stmt);
        let mut page_stmt = self
            .conn
            .prepare("SELECT list, pageno, blob FROM pq_page")?;
        let pages: Vec<(i64, i64, Vec<u8>)> = page_stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        drop(page_stmt);
        let mut ins = self
            .conn
            .prepare("INSERT OR REPLACE INTO drawer_pq (list, seq, code) VALUES (-1, ?1, ?2)")?;
        for (list, pageno, blob) in pages {
            let Ok(plain) = self
                .vault
                .index_from_rest(&format!("pqpage/{list}/{pageno}"), &blob)
            else {
                continue;
            };
            let Some(rows) = Self::pq_page_unpack(&plain, code_len) else {
                continue;
            };
            for (seq, code) in rows {
                if tail_seqs.contains(&seq) {
                    continue;
                }
                let sealed = self
                    .vault
                    .index_at_rest(&format!("pqrow/{seq}"), &Self::pq_row_pack(list, &code));
                ins.execute(params![seq, sealed])?;
            }
        }
        drop(ins);
        self.conn.execute("DELETE FROM pq_page", [])?;
        self.conn.execute(
            "DELETE FROM pq_meta WHERE key IN ('rowcount', 'deleted')",
            [],
        )?;
        self.pq_cache.borrow_mut().take();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{stratified_keyed, PqCache};
    use crate::{PalaceStore, StoreError, CODEBOOK_PQ, CODEBOOK_PQ_IVF};
    use undercroft_core::Drawer;
    use undercroft_vault::{SecurityLevel, VaultManager};

    fn store() -> (tempfile::TempDir, PalaceStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = VaultManager::open(dir.path(), None).unwrap();
        let vault = mgr.create("test", SecurityLevel::HmacOnly).unwrap();
        (dir, PalaceStore::open(vault).unwrap())
    }

    /// A store holding `n` drawers in one wing, with both PQ tiers tuned so
    /// that a corpus this small still trains a codebook AND a centroid set —
    /// the two artifacts M2 is about.
    fn filled(n: u32) -> (tempfile::TempDir, PalaceStore) {
        let (dir, mut s) = store();
        for i in 0..n {
            s.upsert(&Drawer::new(
                "w",
                "r",
                format!("routine filler note {i}"),
                Some("t.md".into()),
                i,
                "test",
            ))
            .unwrap();
        }
        s.set_ivf(16, None);
        s.set_wing_pq_min(8);
        s.pq_schema().unwrap();
        (dir, s)
    }

    fn meta_rows(s: &PalaceStore, key: &str) -> i64 {
        s.conn
            .query_row("SELECT COUNT(*) FROM pq_meta WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .unwrap()
    }

    /// The interruption, made deterministic: the next row this rebuild
    /// writes aborts, exactly where a power loss would land — after the
    /// artifacts were trained, before the codes they describe exist.
    fn interrupt_inserts_into(s: &PalaceStore, table: &str) {
        s.conn
            .execute(
                &format!(
                    "CREATE TRIGGER interrupt BEFORE INSERT ON {table} \
                     BEGIN SELECT RAISE(ABORT, 'power loss'); END"
                ),
                [],
            )
            .unwrap();
    }

    /// M2. A codebook (and a centroid set) must reach disk with the rows it
    /// describes, on BOTH PQ tiers.
    ///
    /// Trained artifacts used to be written the moment they existed — an
    /// autocommit `INSERT` under `synchronous=FULL`, one fsync ahead of the
    /// rows encoded against them. An interruption in that window left an
    /// artifact no stored code matched, which the load path reads as coherent
    /// (`matched == count && ivf_ok`) and probes the wrong lists with, and
    /// which the generation counter reports as a real retrain — the one
    /// artifact that counter exists to make visible, arriving invisibly.
    ///
    /// Both arms assert their own premise: arm one proves a clean build
    /// really does persist both artifacts and step both generations, so the
    /// zeroes in arm two mean "rolled back" rather than "never got there".
    #[test]
    fn an_interrupted_pq_rebuild_leaves_no_codebook_behind() {
        // ── Global tier, clean: the premise.
        let (_d, s) = filled(30);
        assert!(s.pq_build().unwrap(), "premise: a build ran to completion");
        assert_eq!(meta_rows(&s, "codebook"), 1);
        assert_eq!(meta_rows(&s, "ivf"), 1, "30 ≥ ivf_min 16, so IVF trains");
        assert_eq!(s.codebook_generation(CODEBOOK_PQ), 1);
        assert_eq!(s.codebook_generation(CODEBOOK_PQ_IVF), 1);
        let rows: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 30, "one code row per drawer");

        // ── Global tier, interrupted. Before the fix the two `pq_meta`
        // writes had already autocommitted by the time the first row insert
        // ran, so the rollback took the rows and left the artifacts.
        let (_d, s) = filled(30);
        interrupt_inserts_into(&s, "drawer_pq");
        let err = s.pq_build().unwrap_err();
        assert!(
            err.to_string().contains("power loss"),
            "the interruption must be the trigger's, i.e. after training: {err}"
        );
        assert_eq!(
            meta_rows(&s, "codebook"),
            0,
            "a codebook that no stored code was encoded against must not \
             survive the rollback"
        );
        assert_eq!(
            meta_rows(&s, "ivf"),
            0,
            "nor centroids no row is partitioned by"
        );
        assert_eq!(
            s.codebook_generation(CODEBOOK_PQ),
            0,
            "and the generation counter must not claim a retrain that rolled back"
        );
        assert_eq!(s.codebook_generation(CODEBOOK_PQ_IVF), 0);
        let rows: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "premise: the rows rolled back too");

        // ── Per-wing tier, clean: the premise, under its own dynamic
        // artifact names.
        let wing_pq = format!("w/{CODEBOOK_PQ}");
        let wing_ivf = format!("w/{CODEBOOK_PQ_IVF}");
        let (_d, s) = filled(30);
        assert!(
            s.wing_pq_build("w").unwrap().is_some(),
            "premise: the wing is past the floor and earns an index"
        );
        assert_eq!(meta_rows(&s, "codebook/w"), 1);
        assert_eq!(meta_rows(&s, "ivf/w"), 1);
        assert_eq!(s.codebook_generation(&wing_pq), 1);
        assert_eq!(s.codebook_generation(&wing_ivf), 1);

        // ── Per-wing tier, interrupted. This tier is the one that never
        // self-heals: the global rebuild re-runs at the next writable open,
        // a wing's split state simply stands.
        let (_d, s) = filled(30);
        interrupt_inserts_into(&s, "drawer_pq_wing");
        // `WingPq` is not `Debug`, so match rather than `unwrap_err` — and
        // the Ok arm is a real assertion: a rebuild that "succeeds" through
        // an aborted insert would be the defect wearing a green tick.
        let err = match s.wing_pq_build("w") {
            Err(e) => e,
            Ok(_) => panic!("an interrupted wing rebuild must fail, not report an index"),
        };
        assert!(
            err.to_string().contains("power loss"),
            "the interruption must be the trigger's: {err}"
        );
        assert_eq!(
            meta_rows(&s, "codebook/w"),
            0,
            "the wing's codebook must roll back with the wing's rows"
        );
        assert_eq!(meta_rows(&s, "ivf/w"), 0, "and so must its centroids");
        assert_eq!(
            s.codebook_generation(&wing_pq),
            0,
            "no generation may be claimed for an artifact that never landed"
        );
        assert_eq!(s.codebook_generation(&wing_ivf), 0);
        let rows: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM drawer_pq_wing", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "premise: the wing's rows rolled back too");
    }

    /// A20. `one_rewrite` exists because the derived-index rebuild loops
    /// could not simply take a transaction: they are reachable both from the
    /// top of the search path and from inside a caller's transaction, where a
    /// `BEGIN` fails outright (the advisory-encode rule `upsert_many` rests
    /// on). All three behaviours are asserted, because a helper that quietly
    /// did nothing would pass a test for any one of them.
    #[test]
    fn one_rewrite_opens_a_transaction_only_at_the_top_level() {
        let (_d, s) = store();
        s.conn
            .execute("CREATE TABLE t (k INTEGER PRIMARY KEY)", [])
            .unwrap();
        let count = || -> i64 {
            s.conn
                .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
                .unwrap()
        };

        // Premise: at the top level the connection is in autocommit, which
        // is exactly the state the un-transacted loops ran every row in.
        assert!(s.conn.is_autocommit());
        s.one_rewrite(|| {
            assert!(
                !s.conn.is_autocommit(),
                "the rewrite must run inside a transaction"
            );
            s.conn.execute("INSERT INTO t (k) VALUES (1)", [])?;
            Ok(())
        })
        .unwrap();
        assert_eq!(count(), 1);

        // An error rolls the WHOLE rewrite back — the property the codebook
        // and the rows it recodes need, and the one per-row autocommit could
        // not provide at any price.
        let failed = s.one_rewrite(|| {
            s.conn.execute("INSERT INTO t (k) VALUES (2)", [])?;
            s.conn.execute("INSERT INTO t (k) VALUES (3)", [])?;
            Err::<(), _>(StoreError::CorruptRow {
                id: "-".into(),
                reason: "interrupted".into(),
            })
        });
        assert!(failed.is_err());
        assert_eq!(count(), 1, "a failed rewrite must leave nothing behind");

        // Inside a caller's transaction it must NOT begin one: a nested
        // BEGIN is an error, so this call failing at all is the regression.
        let outer = s.conn.unchecked_transaction().unwrap();
        s.one_rewrite(|| {
            assert!(!s.conn.is_autocommit());
            s.conn.execute("INSERT INTO t (k) VALUES (4)", [])?;
            Ok(())
        })
        .expect("must not BEGIN inside a caller's transaction");
        assert_eq!(count(), 2, "the write is visible inside the outer tx");
        outer.rollback().unwrap();
        assert_eq!(
            count(),
            1,
            "and it is atomic WITH the outer tx, not committed behind its back"
        );
    }

    /// The selection half of the keyed draw, and both of its properties: the
    /// **strata** (measured worth 1.4pp of R@1 on `synth --n 20000`) and the
    /// **unpredictability inside them** (the reason for the change at all).
    #[test]
    fn stratified_keyed_keeps_the_strata_and_randomises_within_them() {
        // Below the cap, everything trains — exactly what stride 1 did.
        let id = |i: usize| i as u64;
        assert_eq!(stratified_keyed(10, 10, id), (0..10).collect::<Vec<_>>());
        assert_eq!(stratified_keyed(10, 99, id), (0..10).collect::<Vec<_>>());
        assert!(stratified_keyed(10, 0, id).is_empty());

        // One pick per block: [0,2) [2,4) [4,6) — the lowest rank in each.
        let ranks = [50u64, 3, 90, 1, 70, 2];
        assert_eq!(stratified_keyed(6, 3, |i| ranks[i]), vec![1, 3, 5]);

        // PRF-shaped ranks over 1000 items, 50 wanted.
        let prf: Vec<u64> = (0..1000u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15))
            .collect();
        let chosen = stratified_keyed(1000, 50, |i| prf[i]);
        assert_eq!(chosen.len(), 50, "exactly `want`, never fewer");
        assert!(
            chosen.windows(2).all(|w| w[0] < w[1]),
            "ascending, no dupes"
        );

        // STRATIFIED: exactly one pick from each equal block, so the sample
        // spans the corpus the way the stride did — the half that carries the
        // recall.
        for (b, &i) in chosen.iter().enumerate() {
            let lo = b * 1000 / 50;
            let hi = (b + 1) * 1000 / 50;
            assert!(
                (lo..hi).contains(&i),
                "block {b} picked {i}, outside {lo}..{hi}"
            );
        }

        // KEYED: not the stride's first-of-block, which is what a bulk writer
        // could predict. Either property alone is the bug.
        let stride: Vec<usize> = (0..1000).step_by(1000 / 50).collect();
        assert_ne!(chosen, stride, "a keyed draw must not reproduce the stride");

        // Deterministic for the same ranks — the vault key is what makes the
        // ranks themselves reproducible (see `Vault::sample_rank`).
        assert_eq!(chosen, stratified_keyed(1000, 50, |i| prf[i]));

        // A degenerate rank function degrades to exactly the old stride
        // rather than to something arbitrary.
        assert_eq!(stratified_keyed(1000, 50, |_| 7), stride);
    }

    /// The slab contract: rows group by list with a fixed stride, probe
    /// scans see exactly their lists' rows, removal keeps strides intact
    /// (and a re-push may land in a different list — the re-embed case),
    /// and wrong-length codes are refused rather than corrupting a slab.
    #[test]
    fn slab_cache_groups_removes_and_guards_stride() {
        let mut c = PqCache::new(2);
        c.push(1, 0, &[1, 1]);
        c.push(2, 0, &[2, 2]);
        c.push(3, 1, &[3, 3]);
        c.push(4, -1, &[4, 4]);
        c.push(5, 1, &[9, 9, 9]); // wrong stride: refused
        assert_eq!(c.rows(), 4);
        assert_eq!(c.rows_in(&[0, -1]), 3);
        assert_eq!(c.rows_in(&[7]), 0);
        // Remove from the middle of list 0, then re-home seq 3 to list 0.
        c.remove_seq(1);
        c.remove_seq(3);
        c.push(3, 0, &[5, 5]);
        assert_eq!(c.rows(), 3);
        assert_eq!(c.rows_in(&[0]), 2);
        assert_eq!(c.rows_in(&[1]), 0, "emptied slab is dropped");
        let (seqs, codes) = &c.slabs[&0];
        assert_eq!(seqs, &vec![2, 3]);
        assert_eq!(codes, &vec![2, 2, 5, 5], "stride intact after removal");
    }
}
