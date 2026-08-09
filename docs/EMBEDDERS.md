# Choosing an embedder posture

Every undercroft vault embeds text to power the semantic half of hybrid
retrieval. Which *process* runs the model is a security decision first
and a quality decision second — so the engine ships four postures, each
a ready configuration, each with its trade stated rather than hidden.

One fact frames all four: **the model is the quality lever, the runtime
is not.** Measured on LoCoMo, the jump from the default hash embedder to
*any* modern model is +3.2–4.2pp turn all-gold, while four modern models
span ≤1.0pp among themselves — and the same model produces the same
vectors in every runtime. Pick a posture for its security and
operational shape; pick a model for its quality.

## The four postures

| posture | text leaves the process? | setup | speed | when |
|---|---|---|---|---|
| `hash` (default) | never | none | fastest | zero-egress default; single-language vaults |
| `http` (served) | **yes — to the endpoint, in plaintext** | one compose command | one HTTP call per write/query (11–29× ingest, +20–57% search) | benchmarks, experimentation, deployments that consciously accept the endpoint trade |
| `onnx` (in-process, tract) | never | ONNX export + `--features onnx` build | baseline | pure-Rust constraint, no C++ deps |
| `ort` (in-process, ONNX Runtime) | never | ONNX export + `--features ort` build | ~2.5× tract per forward, int8 support | production vaults with sensitive memories; throughput |

There is also `external:<name>@<dim>` — you supply vectors yourself and
the engine never embeds; its own doctrine (measured gates refuse
semantic-only admission, non-finite vectors are refused at the door) is
documented in the architecture reference.

## `hash` — the zero-egress default

```sh
# nothing to configure — this is what a fresh vault runs
```

Deterministic feature hashing over surface forms: offline, zero
dependencies, no model files, byte-reproducible. Its honest limit:
**single-language**. Two texts match only on shared literal tokens or
trigrams — `car` and `automobile` do not match, and cross-lingual pairs
score noise.

## `http` — a served model, TLS or loopback only

```sh
docker compose up -d embeddings embeddings-tls
# Once: fetch the model. `embed-pull` reads the SAME variable the client
# does (default nomic-embed-text) — asking the client for a model nobody
# pulled is the way this recipe fails.
UNDERCROFT_EMBED_MODEL=bge-m3 docker compose run --rm embed-pull
# then run cli/bench with (project-prefixed volume name — a bare
# `undercroft-embed-tls` mounts a fresh empty volume silently):
#   -v undercroft_undercroft-embed-tls:/tls:ro
UNDERCROFT_EMBEDDER=http
UNDERCROFT_EMBED_URL=https://embeddings-tls
UNDERCROFT_EMBED_CA=/tls/caddy/pki/authorities/local/root.crt
UNDERCROFT_EMBED_MODEL=bge-m3
```

Optional: `UNDERCROFT_EMBED_API` picks the endpoint shape when probing
cannot, `_KEY` carries a bearer, `_DIM` overrides the dimension the
engine otherwise **probes from the endpoint** rather than assuming.

The convenience tier: no export, no feature build, any Ollama /
llama.cpp / LM Studio / vLLM / TEI endpoint. Two rules are enforced, not
suggested:

* **Cleartext http to a non-loopback host refuses at construction — no
  override exists.** The compose `embeddings-tls` Caddy terminator ships
  the required TLS infra; `UNDERCROFT_EMBED_CA` pins its self-signed root
  (a pin, not an addition — public roots are out, and a garbage file
  refuses rather than silently un-pinning).
* **The endpoint still reads your text in plaintext.** TLS protects the
  wire, not the destination — construction says so at warning level.
  If that trade is unacceptable, use an in-process posture.

A failed embed can never fail a write: it degrades to a counted zero
vector (lexically findable, semantically invisible until re-embedded).

## `onnx` / `ort` — in-process, nothing leaves

For `ort`, no build is required: every release ships `…-<target>-ort`
binary assets for all five targets and a multi-arch
`ghcr.io/sealcroft/undercroft:<tag>-ort` image (amd64 + arm64), each
smoke-probed at build for the compiled feature. Building yourself:

```sh
# build once with the feature compiled in
cargo build --release -p undercroft-cli --features onnx   # tract, pure Rust
cargo build --release -p undercroft-cli --features onnx,ort  # + ONNX Runtime

UNDERCROFT_EMBEDDER=ort        # or onnx
UNDERCROFT_ONNX_MODEL=/models/model.onnx
UNDERCROFT_ONNX_TOKENIZER=/models/tokenizer.json
UNDERCROFT_ONNX_NAME=bge-m3    # recorded as the vault's embedder identity
```

The posture that matches the sealed-vault promise in full: the model
runs inside the undercroft process, text never crosses a process
boundary, and there is no warning to print because there is no trade to
accept. Costs: a one-time model export, a feature-compiled binary
(`onnx` is pure Rust; `ort` links ONNX Runtime's C++ library, runs
~2.5× faster per forward, and supports int8 quantized models), and the
model's RAM inside the engine process.

Honest boundaries: tract runs **BERT-family** models (DeBERTa rerankers
are out; ColBERT exports need fixed-shape plans); the compose
`onnx-build` / `ort-build` services compile-check both features in CI.

## Exporting a model (out of repo, on purpose)

Model weights never enter this repository — like benchmark corpora, they
carry their own licenses and stay on your disk. The standard export uses
Hugging Face Optimum, one time, on any machine:

```sh
pip install "optimum[exporters]"
optimum-cli export onnx --model BAAI/bge-m3 --task feature-extraction ./bge-m3-onnx
# produces model.onnx + tokenizer.json — point UNDERCROFT_ONNX_MODEL/_TOKENIZER at them
```

For `ort`, int8 quantization (optional, ~4× smaller, CPU-friendlier):

```sh
optimum-cli onnxruntime quantize --onnx_model ./bge-m3-onnx --avx512 -o ./bge-m3-int8
```

Check the model's own license before use; the engine records the name
you declare (`UNDERCROFT_ONNX_NAME`) as the vault's embedder identity and
refuses a silent swap.

## What a vault remembers about its embedder

A vault records the identity of the space its vectors live in, and a
mismatch is refused rather than ranked. (A remote mirror records the
identity it was pushed with for the same reason: ranking a v2 query
against v1 vectors returned an empty result with no error at all.) Two
consequences, both of which bite when you *change* a posture rather than
when you pick one:

* **A model swap is manual, in both directions.** `hash` is
  `undercroft-hash-v3`; `onnx`/`ort` record `UNDERCROFT_ONNX_NAME`; `http`
  records `http:<model>`, so the same refusal covers a served model too.
  Changing any of them means `UNDERCROFT_FORCE_EMBEDDER=1` + `repair` —
  potentially hours of inference, so it stays a decision you make out
  loud.
* **The one automatic migration is hash-to-hash.** A user who merely
  upgraded the binary did not choose a new vector space, so a vault on a
  known predecessor of the built-in hash embedder (`v1` or `v2`) is
  walked to `v3` at open: batched, idempotent, recording the new identity
  last so a crash just repeats it, dropping the PQ/IVF tables whose
  codebook quantizes vectors that no longer exist, and skipping
  unreadable rows rather than aborting an open that `verify` and `repair`
  also need. Embeddings are not HMAC-covered, so a re-embed touches no
  drawer tag and no audit chain — which is exactly why this is not a
  rotation. A read-only open warns instead of writing.

## The gate and the floor move with the model — and they are measured

Two constants used to be baked in for every embedder, and installing a
modern model silently retired both. They are now properties of the vector
space in hand:

* **The semantic admission gate** — the cosine below which a hit with no
  lexical evidence is dropped — is `Embedder::semantic_admission_gate`,
  measured from 14 known-unrelated probe pairs (worst + a 0.06 margin),
  half of them same-language on purpose, because a cross-lingual-only
  probe set under-estimates the floor. `HashEmbedder` declares the
  shipped 0.56 rather than re-deriving it, so the default vault does not
  move; `ExternalEmbedder` refuses semantic-only admission outright,
  since its vectors come from a model this process has never seen; a
  probe that embeds to zero is an inference *failure*, not a floor, and
  also refuses. Resolved once per open, never per hit — a calibrating
  embedder costs forward passes.
* **The semantic floor** — where unrelated text actually sits in this
  space — calibrates the cosine→score map. The shipped `(cos+1)/2` sends
  cosine 0 to 0.5, correct for hash, whose unrelated floor *is* ~0. A
  served model puts unrelated text near cosine 0.5, so its whole semantic
  range compressed into the top quarter of the scale while BM25 spanned
  all of it — measured, that made same-language function-word overlap
  beat a cross-lingual gold at every fusion weight. Calibrated, the
  measured floor becomes the map's neutral; hash declares floor 0 and
  reproduces the shipped expression bit-for-bit.

`UNDERCROFT_SEMANTIC_GATE` declares the gate (a cosine in `[0.0, 1.0]`;
`off` refuses semantic-only admission outright, i.e. lexical channels
only) and `UNDERCROFT_SEMANTIC_FLOOR` the floor (a cosine in `[0.0, 0.98]`;
`off` = 0, the shipped hash map). Both are for an operator who has
measured their own corpus, which beats a 14-pair probe set. Garbage in the GATE now **refuses
to open**: falling back is not the safe direction — a declared `off` that
silently becomes the embedder's own gate re-admits semantic-only matches
on a deployment that measured its corpus and decided against them. The
FLOOR still warns and defers, because it moves a calibration rather than
an admission boundary. Both `.trim()`, which the gate did not: `off`
carrying the trailing newline a `$(cat …)` or a YAML block scalar
produces used to revert the declaration silently.

## Cross-lingual honesty, in one paragraph

A multilingual embedder is the one condition for cross-lingual
retrieval — **including cross-script**, since the script-disjoint fusion
reweight: a query/candidate pair sharing no letter script (where no
lettered token can possibly match) takes the fusion blend at the weight
ceiling automatically, read from the pair's own bytes, never from
language detection. Measured on FLORES-200: cross-script pairs at
**95–100% R@5 at the default weight** (36–44% before the reweight),
same-script pairs untouched, and a declared
`UNDERCROFT_FUSION_WEIGHT=0.70` still composes. Full per-pair tables and
the reproduction recipe live in the CHANGELOG.
