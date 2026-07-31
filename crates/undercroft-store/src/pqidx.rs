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

use undercroft_vault::SecurityLevel;
use rusqlite::{params, OptionalExtension};

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
                    Some(cq) => drawers as u64 > cq.trained_n().saturating_mul(2),
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
        let cache_ref = self.pq_cache.borrow();
        let Some(cache) = cache_ref.as_ref() else {
            return Ok(None);
        };
        let mut scored: Vec<(f32, i64)> = Vec::new();
        match &probe {
            Some(lists) if !widen => cache.scan(pq, &tables, Some(lists), &mut scored),
            _ => cache.scan(pq, &tables, None, &mut scored),
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
                // Train on a keyed sample; codebooks tolerate sampling well.
                let sample: Vec<Vec<f32>> = self
                    .keyed_sample(CODEBOOK_PQ, &items, PQ_TRAIN_SAMPLE, |(seq, _)| {
                        seq.to_le_bytes().to_vec()
                    })
                    .into_iter()
                    .map(|i| items[i].1.clone())
                    .collect();
                let Some(pq) = ProductQuantizer::train(&sample, m, PQ_TRAIN_ITERS) else {
                    return Ok(false);
                };
                self.pq_meta_put("codebook", &pq.to_bytes())?;
                self.codebook_generation_bump(CODEBOOK_PQ);
                // Only meaningful when a sample was actually drawn: below the
                // cap the sample *is* the corpus and the probe is inside it.
                if items.len() > PQ_TRAIN_SAMPLE {
                    let probe: Vec<Vec<f32>> = self
                        .keyed_sample("pq-fit-probe", &items, PQ_FIT_PROBE, |(seq, _)| {
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
        // threshold so they can't silently go stale.
        let n = items.len();
        if n >= self.ivf_min {
            let fresh = matches!(
                self.ivf.borrow().as_ref(),
                Some(cq) if n as u64 <= cq.trained_n().saturating_mul(2)
            );
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
                    .keyed_sample(CODEBOOK_PQ_IVF, &items, PQ_TRAIN_SAMPLE, |(seq, _)| {
                        seq.to_le_bytes().to_vec()
                    })
                    .into_iter()
                    .map(|i| items[i].1.clone())
                    .collect();
                match CoarseQuantizer::train(&sample, nlist, IVF_TRAIN_ITERS, n as u64) {
                    Some(cq) => {
                        self.pq_meta_put("ivf", &cq.to_bytes())?;
                        self.codebook_generation_bump(CODEBOOK_PQ_IVF);
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

        // A rebuild always writes the target format from scratch — it is
        // also the migration path of last resort (any drift lands here).
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
        let ivf_ref = self.ivf.borrow();
        let mut cache = PqCache::new(pq.code_len());
        let mut by_list: std::collections::HashMap<i64, Vec<(i64, Vec<u8>)>> =
            std::collections::HashMap::new();
        for (seq, vec) in &items {
            let list: i64 = ivf_ref.as_ref().map_or(-1, |cq| cq.assign(vec) as i64);
            let code = pq.encode(vec);
            if paged {
                by_list.entry(list).or_default().push((*seq, code.clone()));
            } else if sealed {
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
            // already in hand — no re-read, no re-decrypt. After a paged
            // build the cache is fully resident (`loaded = None`).
            cache.push(*seq, list, &code);
        }
        drop(ivf_ref);
        drop(ins);
        if paged {
            self.pq_page_append(by_list)?;
        }
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
    pub(crate) fn wing_pq_candidates(
        &self,
        wing: &str,
        qvec: &[f32],
        k: usize,
    ) -> Result<Option<Vec<i64>>, StoreError> {
        if !self.wing_pq.borrow().contains_key(wing) {
            let built = self.wing_pq_build(wing)?;
            self.wing_pq.borrow_mut().insert(wing.to_string(), built);
        }
        // Growth re-check on the fast path (cheap, in-RAM counters): a wing
        // that crossed the IVF threshold, or doubled past its partitions'
        // training size, rebuilds once rather than silently degrading.
        let outgrown = match self.wing_pq.borrow().get(wing) {
            Some(Some(st)) => match st.ivf.as_ref() {
                Some(cq) => st.live as u64 > cq.trained_n().saturating_mul(2),
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
        self.pq_schema()?;
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM drawers WHERE wing = ?1",
            params![wing],
            |r| r.get(0),
        )?;
        if (count as usize) < self.wing_pq_min {
            // A wing that shrank below the floor sheds its artifacts —
            // a stale codebook silently kept is the exact failure class the
            // generation counters exist to make visible elsewhere.
            self.conn
                .execute("DELETE FROM drawer_pq_wing WHERE wing = ?1", params![wing])?;
            self.conn.execute(
                "DELETE FROM pq_meta WHERE key IN (?1, ?2)",
                params![format!("codebook/{wing}"), format!("ivf/{wing}")],
            )?;
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
                    .is_some_and(|cq| count as u64 <= cq.trained_n().saturating_mul(2))
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

        // Rebuild. The codebook is reused when stored (a rebuild is not a
        // retrain and must not advance the generation); trained fresh
        // otherwise, on a keyed sample whose label carries the wing — every
        // wing draws independently, and the artifact string is one string
        // in two roles (draw label + generation key), same as the global
        // five.
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
                let artifact = format!("{wing}/{CODEBOOK_PQ}");
                let sample: Vec<Vec<f32>> = self
                    .keyed_sample(&artifact, &items, PQ_TRAIN_SAMPLE, |(seq, _)| {
                        seq.to_le_bytes().to_vec()
                    })
                    .into_iter()
                    .map(|i| items[i].1.clone())
                    .collect();
                let Some(pq) = ProductQuantizer::train(&sample, m, PQ_TRAIN_ITERS) else {
                    return Ok(None);
                };
                self.pq_meta_put(&codebook_key, &pq.to_bytes())?;
                self.codebook_generation_bump(&artifact);
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
                    self.warn_unrepresentative(&artifact, &pq, &sample, &probe);
                }
                pq
            }
        };

        let ivf = if want_ivf {
            let fresh = self
                .pq_meta_get(&ivf_key)?
                .and_then(|b| CoarseQuantizer::from_bytes(&b))
                .filter(|cq| count as u64 <= cq.trained_n().saturating_mul(2));
            match fresh {
                Some(cq) => Some(cq),
                None => {
                    let nlist = ((count as f64).sqrt() as usize).clamp(16, 4096);
                    let artifact = format!("{wing}/{CODEBOOK_PQ_IVF}");
                    let sample: Vec<Vec<f32>> = self
                        .keyed_sample(&artifact, &items, PQ_TRAIN_SAMPLE, |(seq, _)| {
                            seq.to_le_bytes().to_vec()
                        })
                        .into_iter()
                        .map(|i| items[i].1.clone())
                        .collect();
                    match CoarseQuantizer::train(&sample, nlist, IVF_TRAIN_ITERS, count as u64) {
                        Some(cq) => {
                            self.pq_meta_put(&ivf_key, &cq.to_bytes())?;
                            self.codebook_generation_bump(&artifact);
                            Some(cq)
                        }
                        None => None,
                    }
                }
            }
        } else {
            self.conn
                .execute("DELETE FROM pq_meta WHERE key = ?1", params![ivf_key])?;
            None
        };

        // Rebuild always writes from scratch — also the migration path of
        // last resort for this wing, exactly like the global rebuild.
        self.conn
            .execute("DELETE FROM drawer_pq_wing WHERE wing = ?1", params![wing])?;
        let mut ins = self.conn.prepare(
            "INSERT OR REPLACE INTO drawer_pq_wing (wing, list, seq, code) \
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        let sealed = self.pq_sealed();
        let mut cache = PqCache::new(pq.code_len());
        for (seq, vec) in &items {
            let list: i64 = ivf.as_ref().map_or(-1, |cq| cq.assign(vec) as i64);
            let code = pq.encode(vec);
            if sealed {
                let blob = self.vault.index_at_rest(
                    &format!("pqrow/{wing}/{seq}"),
                    &Self::pq_row_pack(list, &code),
                );
                ins.execute(params![wing, -1i64, seq, blob])?;
            } else {
                ins.execute(params![wing, list, seq, code])?;
            }
            cache.push(*seq, list, &code);
        }
        drop(ins);
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
