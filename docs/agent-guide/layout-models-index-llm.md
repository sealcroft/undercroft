# Agent guide — index, LLM and model crates

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the Layout entries for
`crates/undercroft-index` (remote vector backends as untrusted accelerators),
`crates/undercroft-llm` (refine and the served `HttpEmbedder`, with the
degrade counters of all three model roles), `crates/undercroft-embed-onnx` and
`crates/undercroft-embed-ort`. Read it when your work touches a remote index,
a served or in-process model, an embedder, a reranker or a late-interaction
encoder.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12), and it governs over any one-line statement of the same rule in
the core. In the moved text, "this file" and "here" mean the guide as a whole
— the core and its reference documents.

---

- `crates/undercroft-index` — remote vector backends (Qdrant/Chroma/pgvector/
  Milvus/Weaviate) as untrusted accelerators. `index push` (CLI only) uploads
  each drawer's at-rest content blob with its embedding and wing/room labels:
  ciphertext on a sealed vault, while on an hmac-only vault that blob IS the
  plaintext, so the push is refused unless `index push --allow-plaintext`
  declares it (C8). Remote results are candidate ids only, re-loaded and
  HMAC-verified locally — deduplicated first and capped at the distinct ids
  asked for, because a mirror is untrusted for the SHAPE of its answer too
  (O186); a search asks `VectorIndex::exists` and never `ensure`, the CREATE,
  so a vault with no mirror is refused rather than given one (O185) — and
  every push appends one `egress/index-push` chain
  record — a failed push too, once any batch had already left. **On a
  read-only open the store refuses the push, and `forget --backend`, before
  either touches the mirror (O175)**: `query_only` refuses a write INTO the
  database, but a remote effect ran first and SQLite was asked afterwards, so
  a function with an effect outside the database decides its posture itself,
  held there by a source gate over every store `fn` that takes a `VectorIndex`
- `crates/undercroft-llm` — local LLM runtimes (Ollama/OpenAI-compatible) for
  `refine` → KG extraction, **and `embed.rs`: `HttpEmbedder`**, an `Embedder`
  backed by a served model (`UNDERCROFT_EMBEDDER=http` + `UNDERCROFT_EMBED_URL`
  /`_MODEL`/`_API`/`_KEY`/`_DIM`). Both API shapes, dimension **probed** from
  the endpoint rather than assumed, identity `http:<model>` so the existing
  swap-refusal covers it. **Transport: TLS or loopback, nothing else** —
  cleartext http to a non-loopback host is REFUSED at construction with no
  override (operator decision 2026-08-03; the error names the fix), and
  `UNDERCROFT_EMBED_CA` declares a self-signed root as a **pin** (replaces
  the public roots; a garbage file refuses rather than falling back —
  un-pinning silently is the failure mode). The compose `embeddings-tls`
  Caddy terminator ships the required infra (deploy/embeddings-tls/) with
  its CA on the `undercroft-embed-tls` volume. Two hazards it still states
  rather than hides: the ENDPOINT reads drawer text in plaintext (warned
  at construction when the host is not loopback — TLS protects the wire,
  not the destination; sealing protects a vault at rest, not content
  handed to another process; in-process onnx/ort close it), and a failed
  embed cannot fail a write, so it degrades to a **counted** zero vector
  (lexically findable, semantically invisible until re-embedded).
  **"Counted" reached no surface for two releases, and two of the three
  degrading backends counted nothing (ROADMAP O122, 2026-09-08)**:
  `HttpEmbedder::failures()` was read by its own tests alone, while `onnx`
  and `ort` degraded through a bare `.unwrap_or_else(|_| zeros)` — so a
  corpus of holes reported a clean vector space everywhere. Now
  `Embedder::embed_failures` is a REQUIRED trait method (a default of zero
  is exactly the silent shape it closes; the compiler enumerated eleven
  impls), all three backends count and say so, `VaultStats.embed_failures`
  reads it LIVE on all four renderers, and
  `undercroft_embed_failures_total{backend}` is the durable series with an
  `EmbedFailures` alert. It is the EMBEDDER's number for the life of the
  process, never the database's: on the CLI each command's own open, on a
  server accumulating, and under `ort` process-wide across every vault
  because the multi-tenant server shares one session pool. The durable
  question — how many rows at rest carry a zero vector — has no cheap
  answer on a sealed vault and is not faked; O122 stated it as a residual
  and it is filed open as ROADMAP O174.
  **The same shape held for the OTHER two model roles and cost more (O131,
  2026-09-08)**: both rerankers scored a failed pass `0.0` and both ColBERT
  encoders returned an empty matrix, each through a bare `unwrap_or`, none
  counted. The reranker is the worst of the three because of WHERE the
  number lands — `search` overwrites the candidate's fusion score with it
  and re-sorts, so a failed pass does not merely lose a candidate, it SINKS
  it, and `0.0` is what a genuinely irrelevant passage scores too. A failed
  embed at least leaves a zero vector `repair` can find; a failed score
  leaves no artifact at all. `Reranker::score_failures` and
  `LateInteraction::encode_failures` are required the same way,
  `VaultStats` gains `rerank_failures`/`late_failures`, and the counters
  are `undercroft_rerank_failures_total{backend}` +
  `undercroft_late_failures_total{backend,side}` — three series rather than
  one `stage` label, ruled by the maintainer 2026-09-08 while the embed
  series was still unreleased and free to rename. `side` is load-bearing:
  a `doc` failure is a durable hole in the token space, a `query` failure
  retires the late stage for one search. **The residual this entry carried
  — that the gates covered the trait-to-surface plumbing and NOT the real
  degrade sites — is CLOSED by O134a**, and it had undercounted itself: the
  sites are NINE reachable counted arms across six backends, not four, plus a
  TENTH that was unreachable and is now gone. They live in the two model
  crates and need weights the battery has not got, so a fixture GENERATED
  in-test (a ~2 KB ONNX graph + a WordLevel tokenizer, no committed bytes)
  drives all nine through the real trait methods on the real types. Route R
  measured a divergence between two SHIPPED backends nobody had run: an id
  past the embedding table made tract PANIC — on all five doors, not only the
  embedder — and ORT report a counted degrade. **O150 CONTAINS it**: one
  `undercroft_core::contain::contain` around each role's WHOLE inner body on
  both backends (eight bodies, `CONTAINED_FNS` in `parity.rs`, which also
  requires every tokenizer encode, tract plan run and ORT batch run to be
  CALLED from inside one), a `Panicked` variant flowing into the degrade arm
  that role already counts — so `DEGRADE_ARMS` stays nine — ORT's poisoned
  session lock recovered rather than `expect`ed, and `compile_error!` on
  `panic = "abort"` in both crates, since nothing else can see an abort
  build.
  The same transport policy covers `LlmClient` itself (2026-08-04):
  refine and the admission advisor refuse cleartext beyond loopback,
  `UNDERCROFT_LLM_CA` pins a self-signed root, construction is fallible.
  No external API by default: nothing is contacted unless a URL is set
- `crates/undercroft-embed-onnx` — feature-gated ONNX embedder, cross-encoder
  reranker, **and** ColBERT late-interaction encoder (tract, pure Rust; two
  fixed-shape plans per ColBERT export — dynamic-axis exports carry ops tract
  rejects); built AND TESTED via the `onnx-build` compose service. Models are
  user-supplied; tract 0.22 runs BERT-family models, **not** DeBERTa rerankers.
  **`fixture.rs` is where the tests get a model** (O134a): a ~2 KB ONNX graph
  plus a WordLevel tokenizer GENERATED in-test, behind
  `#[cfg(any(test, feature = "test-fixture"))]`, so nothing binary is
  committed and the premise of every counterfactual stays readable in a diff.
  `undercroft-embed-ort` takes it as a dev-dependency with that feature — ONE
  generator for both backends, as a real Cargo EDGE rather than `#[path]`,
  which would hide it from every gate that reads edges. The CLI's `model_e2e`
  target reaches it the OTHER way (O157) — the feature named in its
  `required-features`, over the CLI's existing optional dependency — because
  the CLI is a default member, and a dev-dependency there measured +265 s on
  every default test build and four ML crates in `windows-check`. The graph is two
  `Gather`s into an `Add`: gathering the MASK through a two-row table removes
  the `Cast` and the `Unsqueeze` whose ONNX signature moved at opset 13, so
  one file compiles at seq 256 and at 32 in BOTH runtimes
- `crates/undercroft-embed-ort` — opt-in ONNX Runtime backend (C++ dep;
  `ort-build` compose service): session-pool embedder + reranker + ColBERT
  encoder (late.rs — same exports/env as the tract one), ~2.5× tract per
  forward, int8 model support; pinned `ort = 2.0.0-rc.10`. Wired into the
  CLI via `--features ort` (`UNDERCROFT_EMBEDDER=ort`,
  `UNDERCROFT_RERANKER=ort|colbert-ort`; multi-tenant server shares one
  session pool across vaults). **`OrtReranker::score` goes straight to
  `score_one` since O134a**: routing one passage through `score_batch_inner`
  gave it a counted arm nothing could reach, because that function returns
  `Err` or a one-element `Vec` for a single passage. Restructured rather than
  deleted — `v[0]` makes it a panic and `unwrap_or(0.0)` puts back the
  uncounted degrade O131 closed — with the pool-slot expression preserved
  verbatim, which is result-preserving and NOT scheduling-preserving.
  `score_batch` still collapses the WHOLE window on one failing pair where
  tract degrades per passage; that divergence is PINNED as a named cost and
  ruled in O151. **ORT is contained too (O150)** although it refuses an
  out-of-table id with a typed error: its tokenizer runs before the session
  lock and its pooling indexes after it. Its three session locks RECOVER from
  poisoning (`PoisonError::into_inner`) — `expect` turned one contained panic
  into a panic on every later call, on the pool every tenant shares — which is
  sound because ort 2.0.0-rc.10's run is one FFI call and the only Rust it
  calls back into is an `extern "system"` logger, where a panic aborts rather
  than unwinds; a claim that rests on that exact pin
