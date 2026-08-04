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
docker compose run --rm embed-pull            # once: fetch the model
# then run cli/bench with (project-prefixed volume name):
#   -v undercroft_undercroft-embed-tls:/tls:ro
UNDERCROFT_EMBEDDER=http
UNDERCROFT_EMBED_URL=https://embeddings-tls
UNDERCROFT_EMBED_CA=/tls/caddy/pki/authorities/local/root.crt
UNDERCROFT_EMBED_MODEL=bge-m3
```

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

## Cross-lingual honesty, in one paragraph

A multilingual embedder is **necessary but not sufficient** for
cross-script retrieval: at the default fusion weight, pairs sharing no
script (Arabic/Thai/Chinese ↔ English) measure 36–44% R@5 on FLORES-200
because same-language lexical noise outvotes the gold's semantic score.
The honest cross-lingual configuration is the multilingual embedder
**plus a declared `UNDERCROFT_FUSION_WEIGHT=0.70`**, which measures
97.5–100% R@5 on every pair. Full per-pair tables and the reproduction
recipe live in the CHANGELOG.
