# Agents implementation guide

**Audience: an AI agent (or the human pairing with one) that needs to give
itself — or a product it is building — a hardened, local-first memory.**
This document is scenario-driven: find the scenario that matches your
situation, follow its steps verbatim, then verify with the checklist at the
end. Everything here is the real surface of the current release — tool
names, routes, and environment variables are copied from the code, not
paraphrased.

Links are absolute so this page reads correctly anywhere:
repository <https://github.com/compufreq/undercroft>, rendered docs
<https://compufreq.github.io/undercroft/docs/>.

---

## 0. Ground rules (invariants you must not violate)

Undercroft stores memories **verbatim** in *drawers*, filed into
*wings/rooms*, inside isolated *vaults* (own SQLite database, own
HKDF-derived keys). When you build on it:

1. **Never summarize, paraphrase, or compress content on the write path.**
   Store the exact words; retrieval returns the exact words. Summarize at
   read time in your own context if you must.
2. **Local-first, zero external calls by default.** The default embedder is
   deterministic and offline. Never add a phone-home. Telemetry exists but
   is opt-in at build time and metadata-only.
3. **Sealed vaults keep nothing plaintext-derived on disk.** Do not write
   sidecar files, caches, or logs containing drawer content next to a
   sealed vault. **Know precisely what this does and does not cover.**
   Content, embeddings, PQ codes, ColBERT matrices and grounding spans are
   sealed. Drawer *metadata* is not: an attacker holding the database file
   reads the wing and room names — which in practice are topics, people or
   case identifiers — the `source_file` path, `added_by`, the hall label,
   `content_date`, and the dates resolved out of the content. They read no
   word of the content itself. If a wing name, a room name or a file path
   would be sensitive in your deployment, **do not put the secret in the
   name** — treat those as public labels until this is closed. The exposure
   is pinned by a test so it cannot widen unnoticed.
4. **Drawer ids are deterministic** over (wing, room, source, chunk_index),
   but what that buys you depends on the path. Ingest *from a source* —
   `mine`, `sweep`, `import` — is idempotent: the source path and the chunk's
   position within it are the id, so processing the same file twice updates
   in place. Rely on that instead of inventing your own dedup on top.
   **A save through an API is not.** `POST /v1/drawers`, `undercroft_save`
   and `undercroft_add_drawer` have no source to be a chunk of, so
   `chunk_index` carries a unique append index instead and every call
   creates a new drawer — posting identical text twice gives you two.
   That is deliberate: the same words on a different day are a different
   event. To collapse repeats, pass `dedup_threshold` on save or run
   `undercroft_dedup`; both keep every date the text appeared on.
5. **Integrity is enforced, not assumed.** Every read verifies an HMAC;
   every write advances a tamper-evident audit chain in the same
   transaction. If `verify` fails, treat it as an incident (see the
   [tamper runbook](https://compufreq.github.io/undercroft/docs/runbook.html)),
   not as noise.
6. **Names are validated.** Vault/wing/room names go through a
   path-traversal guard — expect errors on `../`-style input rather than
   trying to sanitize yourself.

---

## 1. Choose your scenario

| Your situation | Scenario | Deployment shape |
|---|---|---|
| One agent, one machine, persistent memory across sessions | **A** | CLI + MCP stdio server |
| Several agents / teammates sharing one memory | **B** | `serve-http` with a bearer token |
| Your product needs per-customer isolated memory | **C** | Multi-tenant `/v1` REST engine |
| Fleets of engines, tenants placed/migrated between them | **D** | The `undercroft-orchestrator` control plane |
| You need better recall or lower latency than defaults | **E** | Retrieval/model tier selection |
| You operate any of the above | **F** | Security operations (verify/rotate/backup/bundles) |
| You need dashboards/alerts | **G** | Opt-in telemetry build |

All scenarios start the same way:

```bash
docker pull ghcr.io/compufreq/undercroft:latest   # published image
# or: prebuilt binaries on every GitHub release (linux/macos/windows, sha256)
# or: git clone https://github.com/compufreq/undercroft && docker build -t undercroft .
# or: cargo build --release
undercroft init                     # palace at ~/.undercroft (override: UNDERCROFT_HOME)
```

`init` creates the master key (`master.key`, 0600 — or derive it from
`UNDERCROFT_PASSPHRASE` instead) and a `default` vault at the `sealed`
level. Use `--level hmac-only` only when you explicitly want a
plaintext-inspectable database with integrity tags.

---

## 2. Scenario A — a single agent that remembers

The shape: your agent runs the MCP stdio server as a subprocess and uses
its tools; hooks auto-save the session transcript so nothing is lost even
when the agent forgets to save.

**A1. Register the MCP server** (Claude Code `.mcp.json`, Claude Desktop
`claude_desktop_config.json`, or any MCP client):

```json
{ "mcpServers": { "undercroft": { "command": "undercroft", "args": ["serve-mcp"] } } }
```

Add `"--vault", "work"` to scope the server to a non-default vault, and
set `UNDERCROFT_HOME` in the server's env if the palace lives elsewhere.

**A2. Install the auto-save hook** (Claude Code):

```bash
undercroft hooks claude-code
```

This prints a `settings.json` fragment wiring **Stop** and **PreCompact**
events to `undercroft sweep ~/.claude/projects --wing claude-code` — one
verbatim drawer per prose message, idempotent, so re-sweeps are no-ops.

**A3. Use the tools.** Session start: call `undercroft_wake_up` (recent
essential memories; the CLI `wake-up` additionally prints an L0 identity
section from `<data-dir>/identity.txt` — create that file to give the
agent a durable self-description). During work: `undercroft_save` for
decisions worth keeping, `undercroft_search` before re-deriving anything,
`undercroft_kg_add`/`undercroft_kg_query` for temporal facts ("alice
works_at acme *since* 2024-01"). The full 32-tool surface is in §8.

**A4. Bulk history**: `undercroft mine <dir>` chunks documents;
`undercroft mine <dir> --mode convos` and `undercroft sweep <dir>` ingest
agent transcripts; `undercroft daemon run --watch <dir>` keeps sweeping in
the background. Ingest is batched — hundreds of drawers commit as single
transactions.

---

## 3. Scenario B — a shared team memory

One `serve-http` process serves both MCP-over-HTTP (`POST /mcp`) and the
REST surface. Auth is layered:

```bash
export UNDERCROFT_MCP_HTTP_TOKEN=$(openssl rand -hex 24)   # palace bearer
undercroft serve-http --host 0.0.0.0 --port 8800
```

- The server **refuses to start** on a non-loopback bind without the
  bearer. Every request (MCP and `/v1`) must send
  `Authorization: Bearer <token>`.
- `--read-only` strips all 12 mutating MCP tools and returns 403 on
  mutating `/v1` routes — run a second read-only instance for consumers
  that should never write. It is a posture on the whole process, not a
  route filter: **both** stores the server opens (the `/mcp` one and each
  `/v1` tenant one) are opened read-only, so the vault gets no embedder
  migration (an embedder upgrade warns and serves the old vectors instead
  of re-embedding, and instead of refusing to start), no `embedder_name`
  stamp, and no read-audit records even with
  `UNDERCROFT_READ_AUDIT=chain` — that variable's trail is empty on a
  read-only server, by design and with a warning at open. On `/v1` the
  refusal is decided in front of dispatch and **fails closed**: anything
  that is not a `GET` is refused except `POST .../search` and
  `POST .../verify`, so a route added later is refused until it is
  deliberately classified.
- `POST /v1/vaults/{id}/rotate` and `DELETE /v1/vaults/{id}` answer
  **409** for the vault named by `--vault`, because this same process
  also holds that vault open behind `/mcp` and key rotation needs the
  only handle (see §9). Every other tenant vault rotates normally.
- `GET /healthz` is the only unauthenticated route.
- Put TLS in front with a reverse proxy; the server itself speaks HTTP.

Point every teammate's MCP client at it, or use the REST routes in §9
directly.

---

## 4. Scenario C — a multi-tenant memory engine inside your product

Give each customer their own vault, and require a **per-vault assertion**
on every request so holding the palace bearer alone is not enough:

```bash
export UNDERCROFT_MCP_HTTP_TOKEN=...        # reaching the server
export UNDERCROFT_ASSERTION_SECRET=...      # addressing a tenant
undercroft serve-http --host 0.0.0.0 --port 8800
```

Every `/v1` request must then carry
`X-Vault-Assertion: <unix-ts>:<hex HMAC-SHA256(secret, "<ts>|<vault_id>")>`
for the exact vault it addresses (±120 s window; the vault id is inside
the MAC, so an assertion for tenant A can never address tenant B). Mint
one for testing with `undercroft assert-header <vault>`.

Per-tenant flow (full route table in §9):

```text
POST   /v1/vaults                      {"id":"acme","level":"sealed"}       # create
POST   /v1/vaults/acme/drawers         {"text":"...","wing":"notes"}        # save
POST   /v1/vaults/acme/search          {"query":"...","limit":8}            # search
GET    /v1/vaults/acme/export                                              # lossless NDJSON
POST   /v1/vaults/acme/import                                              # count-verified restore
```

Two options worth knowing:

- **External embeddings**: create the vault with
  `"embedder":"external:<name>@<dim>"` and supply a `vector` with every
  save and search — your product's embedding model, undercroft's sealing
  and integrity. Dimension is enforced exactly.
- **Dedup-refresh**: pass `"dedup_threshold":0.9` on save to refresh a
  near-duplicate in place (audited update) instead of piling up copies. The
  refreshed drawer takes the incoming text and date, and keeps the one it
  displaced in `occurrences`, so collapsing a repeat never erases the day it
  first appeared. Search hits carry the full chronology.

Export lines carry vectors and ColBERT token artifacts, so
export→import is a **lossless migration primitive** — restore is a copy,
not a re-embed.

---

## 5. Scenario D — a fleet with the orchestrator

When one engine is not enough, `undercroft-orchestrator` (separate binary,
same repo) is the control plane: instance registry, tenant→vault mapping,
token minting, routing, and live migration. It is a pure client of `/v1` —
engines never know it exists. Full docs:
[MULTI_TENANCY.md](https://github.com/compufreq/undercroft/blob/main/docs/MULTI_TENANCY.md).

```bash
export UNDERCROFT_ORCH_KEY=$(undercroft-orchestrator keygen)   # seals engine creds
export UNDERCROFT_ORCH_ADMIN_TOKEN=...                        # /admin bearer (≥16 chars)
undercroft-orchestrator serve                                 # 127.0.0.1:8900 (UNDERCROFT_ORCH_ADDR)

# register engines, create tenants (token shown ONCE), migrate:
undercroft-orchestrator instance-add engine-a http://a:8800 <bearer> <assertion-secret>
undercroft-orchestrator tenant-create acme
undercroft-orchestrator migrate acme engine-b     # export→import→count-verify→flip→delete

# scale read routing: replicas serve /t/* from a read-only state db
# (shared volume or replicated snapshot); /admin and /ui stay on the writer
undercroft-orchestrator serve --read-replica --addr 0.0.0.0:8901
```

Tenants call `/t/<subpath>` with their own bearer; the orchestrator
resolves the token (stored only as an HMAC), forwards to
`/v1/vaults/{their-vault}/<subpath>` with the engine bearer + a fresh
assertion. The subpath allowlist is `drawers | search | stats | export |
import` — vault lifecycle is deliberately unreachable with a tenant token.
Optional per-tenant rate limiting: `UNDERCROFT_ORCH_RATE_LIMIT=<req/min>`
(a plain integer; a declaration it cannot read refuses to start rather
than serving unlimited in silence).
Rotate a tenant token with `tenant-rotate` (the old one dies in the same
statement — immediately on the writer, within the replication window on
replicas). `GET /healthz` reports `mode` and `last_write` on writer and
replicas so lag is observable. Deploy TLS on both hops; back up the
orchestrator's SQLite.

---

## 6. Scenario E — choosing retrieval quality and latency

Everything composes through environment variables; identity is recorded
per vault on first write, and a model swap is refused unless you set
`UNDERCROFT_FORCE_EMBEDDER=1` and re-embed with `undercroft repair`.

**Embedder tiers** (`UNDERCROFT_EMBEDDER`; the full posture guide with
setup recipes, the model-export procedure, and the security trades is
[docs/EMBEDDERS.md](EMBEDDERS.md) — published as the "Choosing an
embedder posture" chapter. Since the posture-configs unit, releases ship
the `ort` posture ready-made: a `…-x86_64-unknown-linux-gnu-ort.tar.gz`
binary asset and a `ghcr.io/compufreq/undercroft:<tag>-ort` image, both
smoke-probed for the compiled feature at build):

| Value | What | When |
|---|---|---|
| `hash` (default) | deterministic hashed n-grams, offline, zero deps | correct default; measured LoCoMo R@10 92.7% with hybrid search. **Single-language only** — see below |
| `http` | a model served over HTTPS (or loopback) — Ollama, llama.cpp server, LM Studio, vLLM, TEI. `UNDERCROFT_EMBED_URL` + `_MODEL` (+ optional `_API`, `_KEY`, `_DIM`, `_CA`); dimension is probed from the endpoint. **Cleartext http to a non-loopback host is refused at construction, no override** — front the endpoint with TLS (the compose `embeddings-tls` terminator ships ready) and pin a self-signed root with `UNDERCROFT_EMBED_CA` | **the recommended configuration when the endpoint is loopback or a TLS-fronted private service** — the largest measured lever on retrieval quality (**+3.2 to +4.2pp** turn all-gold over `hash` across four models, which span only 1.0pp between them; each figure is n=1, so no specific model is recommended until repeat runs separate them), and no ONNX export needed. Stays opt-in rather than default because **the endpoint reads drawer text in plaintext** (TLS protects the wire, not the destination) — the default must remain zero-egress, and that posture is the product's, not a tuning knob. Costs one request per drawer at ingest (11–29×) and +20–57% search |
| `onnx` | user-supplied MiniLM-class ONNX via tract (pure Rust); needs `UNDERCROFT_ONNX_MODEL`/`_TOKENIZER`, build `--features onnx` | best recall, pure-Rust constraint |
| `ort` | same models via ONNX Runtime (C++ dep, build `--features ort`); ~2.5× faster/forward, int8 support, ~4–5× faster ingest | throughput matters; same env vars, switching is one env change |

**Cross-lingual retrieval needs a multilingual embedder — the default
cannot do it, and will not tell you so.** `hash` is feature hashing over
surface forms: word unigrams, word bigrams and character trigrams, each
SHA-256'd into a bucket. Two texts score close only when they share literal
tokens or trigrams. An English query and an Arabic note share none, so the
score is noise — measured, a translation pair scored *lower* than an
unrelated sentence. The same limit applies within one language: `car` and
`automobile` do not match either. The trigrams buy morphology
(`run`/`running`), not meaning.

So a vault holding several languages, or queried in a language other than
the one it was written in, needs `onnx`/`ort`/`http` with a **multilingual**
model (bge-m3, LaBSE, multilingual-e5, nomic-embed-text-v2-moe) — or an
external vault, where you supply vectors yourself and the engine never
embeds. Either way the vectors are sealed at rest exactly like the default
ones, so this costs nothing in confidentiality.

**And the default weight now serves cross-script pairs honestly** (the
script-disjoint fusion reweight, 2026-08-04): a (query, candidate) pair
sharing **no letter script** — where no lettered token can possibly
match — takes the fusion blend at the weight ceiling automatically,
read from the pair's own bytes (never language detection; en↔de share a
script and are untouched). Measured on FLORES-200 (bge-m3, sealed, full
tables in CHANGELOG): cross-script pairs went **36–44% → 95–100% R@5 at
the default weight**, same-script pairs digit-identical, and a declared
`UNDERCROFT_FUSION_WEIGHT=0.70` still composes (digit-identical at the
ceiling). One condition remains: the multilingual embedder itself.

Note the two axes are independent. **Retrieval** across languages is the
embedder's job. **Reading dates inside the text** is the scanner's, selected
per request with `language` (`en`, `ar`), and it works regardless of which
embedder found the drawer.

### Reading conventions are declared, not detected

Four read-time fields decide how a drawer's dates are read. All are per request,
all default to prior behaviour, and because mentions are re-read live an
already-ingested corpus answers correctly the moment you declare its conventions
— no re-ingest, no re-embed.

| field | values | default | what it decides |
|---|---|---|---|
| `language` | dates: `en`, `ar` · morphology: `en`, `de`, `nl`, `it`, `es`, `fr`, `pt`, `tr`, `ru`, `el`, `hi`, `ka`, `ko` | inferred per drawer | **two consumers, one declaration.** Which scanner reads the *dates*, and whose inflection *retrieval* uses. Each falls back rather than guessing. **Morphology no longer needs it** — see below |
| `week_start` | `monday`, `sunday`, `saturday` | `monday` (`saturday` for `ar`) | which day begins a week — moves "last week" and every week count |
| `date_order` | `day_first`, `month_first` | see below | which field a bare numeric date puts first |
| `calendar` | `gregorian`, `buddhist`, `minguo`, `hijri`, `jalali`, `reiwa`, `heisei`, `showa`, `taisho`, `meiji` | `gregorian` | which calendar counted the year, **unless a drawer names its own era** |

All four are accepted on `POST /v1/vaults/{id}/search` and on `undercroft_search`
— the same key names, parsed by the same code. The CLI takes the one of them it
has a consumer for, `undercroft search --language <code>`, which selects the
retrieval morphology; CLI search prints no in-text dates, so the three
date-reading conventions have nothing to act on there.

**`date_order`** — `07/05/2023` is 7 May or 5 July and the token does not say.
Four signals are consulted, strongest first:

1. what you declared on the request;
2. what the text demonstrates about itself — `13/05` can only be day-first, so
   an unambiguous date anywhere in the same drawer states the writer's
   convention by example. This is evidence, not inference, and it overrides the
   default without any configuration;
3. what the language implies — CLDR gives `ar` as `d/M/y` in every Arabic
   territory, so Arabic declares day-first. English splits US/Commonwealth and
   implies nothing, which is why it does not;
4. failing all three, **day-first** — the majority convention worldwide.

The cost of that last step is explicit: a US corpus that never declares
`month_first` reads `07/05` as 7 May. Declare it once and the whole corpus reads
correctly, retroactively.

### Morphology: 19 languages, and you do not have to declare any of them

Retrieval reaches a word's other forms — `running` from `run`, `Kinder` from
`Kind`, `libri` from `libro`, `бумаги` from `бумага`, `مكتوب` from `كتب`.
Measured end to end at realistic drawer length over 191 paradigm pairs in 19
languages: **100% on the lexical channel, declared or not**, with nothing left
to the embedder.

Which language applies is resolved three ways, strongest first:

1. **What you declared** on the request. A statement about your corpus, and it
   wins.
2. **What the script settles.** Greek, Georgian and Hangul are used by one
   language apiece, so a Greek `-ος` ending can only ever match a Greek word.
   (Cyrillic and Devanagari get the majority language's table — Russian and
   Hindi — whose endings the family largely shares. Approximate, and labelled.)
3. **What the drawer says it is.** A text carrying `der`, `die`, `und`, `nicht`
   is German. Only closed-class function words vote, and only decisively — three
   hits and twice the runner-up — because `is` votes for English and Dutch
   alike. Where they disagree the drawer says nothing.

This is reading, not guessing. Nothing is derived from the *shape* of a word;
the writer's own commonest words are read, exactly as an era marker is.

**Declare `language` anyway when you know it.** It is stronger than either
fallback, and for a short or code-heavy drawer the function words may not carry.

**What it costs, per language, pinned by test.** Morphology admits, so every
rule has a price and none of them is hidden:

| declaring | also merges |
|---|---|
| `de` | `flow`/`flower` — German needs `-er`, English cannot have it |
| `nl` | `kop`/`kopen`, `man`/`manen` — Dutch `-en` |
| `it` | `pesca`/`pesce` — `a→e` carries the feminine plural |
| `tr` | `kar`/`kara` |
| `en` | `champion`/`champ` is *lost*, not merged — `-ion` needs a six-character stem to keep `question`/`quest` apart |
| (always) | Arabic `سيارة`/`أسرة` — the consonantal skeleton rule, which predates this |

Cross-lingual retrieval is a different axis and remains **impossible** with the
default embedder: `HashEmbedder` is feature hashing over surface forms, so an
EN/AR translation pair scores *below* an unrelated sentence. Every figure above
is within-language. Use an `onnx`/`ort` multilingual model for that.

**`calendar`** — nothing is inferred here, ever. Script is not evidence (Thai
script writes Gregorian dates constantly) and neither is the numeral system
(`๒๐๒๖` is an ordinary Gregorian 2026 typed in Thai digits). An undeclared
corpus reads years as written, so a Thai date reads 543 years high until you say
`buddhist` — visible and correctable, where a silently dropped date is neither.
Buddhist, Minguo and the five Japanese eras are renumbered Gregorian years and
convert by arithmetic; Hijri (**Umm al-Qura**, the Saudi civil calendar) and
Jalali are different calendars — lunar drift, an equinox-anchored new year,
different month lengths — so they convert as whole dates. A Japanese era is
**bounded**: 令和 begins on 1 May 2019, so 令和1年 is that May to December and
not the whole of a year four months of which were 平成31年.

**An era marker in the drawer's own words outranks what you declared.** `พ.ศ.`,
`ค.ศ.`, `พุทธศักราช`, `คริสต์ศักราช`, `هـ`, `هجري`, `ميلادي`, `民國`, `公元`,
`西暦`, `令和`, `平成`, `昭和`, `大正`, `明治` are read wherever they stand beside
a year — before it, after it, or glued to it (`1447هـ`, `2568พ.ศ.`, `ค.ศ.2023`,
`令和6年`). Your declaration is a statement about a corpus; the marker is the
writer's statement about one date, so the more specific evidence wins. This is
still reading, never inference — the era is written down. Markers on both sides
that disagree settle nothing and leave your declaration standing.

A **bare year** is recorded only where a marker names it: `2568` alone is a
quantity, `พ.ศ. 2568` is the year 2025. It resolves to the whole year as a
period (`resolved` + `resolved_end`).

**Bare `م` and `ه` are read where the writing confirms them.** They abbreviate
ميلادي and هجري, but `م` is also *metres* and `ه` a list letter, so the word
alone settles nothing — which is the point Arabic makes about itself: it reads
in context, and the context is on the page. Two signals, strongest first:

1. **a year noun governs the number** — `سنة ٢٠٢٣م`, `عام ١٩٩٥ م`,
   `في العام ٢٠٠٠م`. The sentence states the reading, spaced or glued.
2. **the marker is glued to the year**, no separator at all — `١٩٩٥م`. That is
   how Arabic writes a year; `١٥٠٠ م` with the space is how it writes a
   quantity, and SI asks for that space. The default, in the same sense as
   day-first: the answer where nothing stronger was written.

A spaced marker with no year noun stays unread — `جريت ١٥٠٠ م` names no date.

**The cost of signal 2 is real and pinned by test.** Arabic geography writes
`على ارتفاع ٢٥٠٠م` — an altitude — glued, and it now reads as the year 2500.
Nothing in the string separates the two, and reading the number's *size* would
be the inference this module refuses. The collision is confined to four-digit
quantities written without their space, since the Gregorian gate wants four
digits and `٥٠٠م` has three. Same trade as day-first: a wrong year is in the
record and correctable, where silence is neither.

Two gaps, stated rather than glossed:

* **month-name arms are Gregorian-only.** `٧ مايو ٢٠٢٣` and `May 2023` build
  their dates without consulting a calendar at all — a *declared* calendar has
  never reached them either — so a marker beside one is not read.
* **CJK numeric dates** (`2023年5月7日`) are still not parsed; only the era-plus-
  year form is.

**Second stage** (`UNDERCROFT_RERANKER`): `onnx`/`ort` = cross-encoder
re-scoring of the top `UNDERCROFT_RERANK_TOP_N` (default 50) — measured
LoCoMo R@10 94.6→97.7%; `colbert`/`colbert-ort` = late interaction: encode
once at ingest, **one** query forward + MaxSim at search — ~96.5–96.8% at
a flat ~93 ms/q (tract) or ~70 ms/q (ort), independent of core count.
Model paths via `UNDERCROFT_RERANK_*` / `UNDERCROFT_COLBERT_*`. BERT-family
models only (tract cannot run DeBERTa rerankers).

**The two stages have separate depths, and this matters.**
`UNDERCROFT_RERANK_TOP_N` (50) is a *latency cap* — one transformer forward
per candidate. `UNDERCROFT_LATE_TOP_N` (**200**) is a *rescore depth* — MaxSim
is arithmetic over matrices built at ingest, so depth is far cheaper per
candidate. They were one constant until the split, which meant late
interaction inherited a budget it never spent.

What the depth is worth, stated with the configuration it was measured in:
**+2.1pp** of turn-level evidence delivery on LoCoMo **with the token codebook
disabled** (exact int8), which is the only configuration where two runs are
comparable. In the shipped configuration for a corpus past `TOK_PQ_MIN` — v2
PQ-ADC — the same 50→200 step measured +1.7pp and +0.0pp on two runs, so its
default-configuration value is **not established**; both sit inside the
per-vault training draw's own spread. 200 is a judgement (enough depth to take
the measured gain without unbounded rescore), **not** a measured optimum: 400
was higher in two of three sweeps and lower by one question in the third.

Note the depth applies to the un-truncated candidate list, so on a sealed
vault with no prefilter it reaches the whole corpus. Setting only
`UNDERCROFT_RERANK_TOP_N` still drives both stages, so a pinned deployment
keeps the behaviour it pinned.

**Candidate generation** (`UNDERCROFT_RETRIEVAL`): unset = full scan with
FTS prefilter (fine to ~10⁴ drawers); `pq` = bounded-RAM PQ/IVF prefilter
(recall flat in corpus size, works on sealed vaults via a decrypt-once RAM
cache); `fde` = MUVERA fixed-dimensional encodings for the ColBERT stage —
measured recall identical to fusion at −25% latency, rows PQ-compress 32×.
Export recipes and all measured tables:
[RETRIEVAL_SCALING.md](https://github.com/compufreq/undercroft/blob/main/docs/RETRIEVAL_SCALING.md).

**Remote vector DBs** (Qdrant/Chroma/pgvector/Milvus/Weaviate via
`undercroft index push` + `search --backend`) are **untrusted
accelerators**: they hold sealed bytes, every candidate is re-verified and
decrypted locally. They pay off only at very large corpora — measure
before adopting. After a key rotation, re-run `index push`.

A mirror-served query answers under the **same retrieval policy** as
`--backend local`: the closed vocabularies (`--kind`, `--min-trust`) are
validated the same way, the trust floor — the request's and the vault's —
is applied, and admission-quarantined drawers are excluded unless you
name the quarantine wing yourself. The push mirrors every drawer,
quarantined rows included, because an untrusted mirror can offer any id
it likes: the fence is applied where the bytes are decrypted, not where
they are uploaded. Cost of the accelerator, stated: locally the floor
bounds candidate *generation*, remotely it can only bound what came back,
so an excluded wing's rows still spend part of the candidate budget.
An external-embedding vault is refused on this path exactly as it is on
`search` — the query vector has to come from the caller.

---

## 7. Scenario F — operating it securely

Daily/CI:

```bash
undercroft verify           # HMAC every record + replay the audit chain
                           # + check every supersession receipt; exit 2 on failure
undercroft backup create    # verified snapshot, keeps last 10
```

**Exit 2 means an integrity verdict**, on every command that can reach one:
`verify` (a bad record, a broken chain or a tampered supersession link),
`repair` (same, after backfilling), `backup create` (it refuses to archive a
palace that failed verification) and `verify-forgetting` (the attestation does
not describe what this vault did — a forged signature, a tombstone tag that is
not this vault's, or something other than a tombstone inside the attested
interval). Exit 1 stays what it always was: the run itself failed — bad
arguments, a missing file, an unreadable vault. A compliance script may retry
exit 1; retrying exit 2 only re-detects the tampering.

- A **crash is never a tamper alarm** (open-time reconciliation
  fast-forwards a lagging manifest anchor); a **rollback or forged record
  always is**. On `VERIFY FAILED`, follow the
  [runbook](https://compufreq.github.io/undercroft/docs/runbook.html).
- **Key rotation** — `undercroft vault rotate <name>`: fresh derived keys,
  every sealed blob re-encrypted and every tag re-keyed in one
  transaction, crash-safe at any instant. Do it on key-exposure suspicion
  or on schedule. Not while another process serves the vault.
- **Encrypted backups** — a backup file should never exist in plaintext:

```bash
undercroft bundle keygen --out ops.key            # prints the shareable recipient once
undercroft bundle sign-keygen --out sign.key      # prints the pinnable sender once
undercroft export --to <recipient> --out palace.bundle --sign sign.key
undercroft import palace.bundle --identity ops.key --sender <sender-hex>
```

  An export now leads with a **signed-able manifest** (sender, scope,
  trust claim, expiry, record counts, provenance summary) and carries the
  **whole palace**: drawers, KG entities, facts (receipts re-keyed at the
  destination; grounding, authority tier and extractor identity intact)
  and tunnels — the meta-rows gap is closed. Recipient encryption says who
  may *read* a bundle; the manifest signature says who *wrote* it. Pin the
  sender with `--sender` to enforce attestation; `--trust` is the sender's
  claim for your policy, never a trust boundary by itself; an expired
  bundle is refused at import. Legacy exports (no manifest) still import.
  Since C3.4, `bundle keygen` produces a **hybrid post-quantum identity**
  (X25519 + ML-KEM-768, `pq1`-prefixed strings) and seals v2 bundles that
  close harvest-now-decrypt-later; legacy bare-hex X25519 identities keep
  working in both directions, and nothing downgrades silently — the full
  posture and compat matrix live in [PQ.md](PQ.md).

- Durability is real: SQLite runs WAL + `synchronous=FULL`, the manifest
  anchor and key files are fsynced — an acknowledged write is on disk.

---

## 8. Reference — MCP tools (34)

Write tools (marked **W**) are refused when the server runs `--read-only`.

| Tool | W | Does |
|---|---|---|
| `undercroft_save` | W | save one memory verbatim |
| `undercroft_search` | | hybrid semantic+lexical search. All four reading conventions are accepted here exactly as on `/v1` — `language`, `week_start`, `date_order`, `calendar` (see §5) — so `language: "ar"` reads the stored text as Arabic and `language: "de"` reaches German word forms, while `week_start` decides what "last week" inside a drawer resolves to. Pass `as_of` and each hit reports how long before it the content happened ("15 weeks before"), computed by the engine — do not subtract dates yourself. Hits also carry the dates written *inside* the text, resolved against that drawer's own anchor, the further days the same text was recorded on, and the drawer **id** every follow-up tool takes (`_get_drawer`, `_update_drawer`, `_delete_drawer`, `supersedes` on a save). `room_cap` soft-caps how many hits may come from any one room, so an answer spanning several sessions is not starved by the most verbose one. Default `limit` is **5** on every surface. A full page ends with the exact continuation to go deeper — repeat the search with the stated `offset` and `ranked_at` instead of re-asking the same question; a short page means the ranking is exhausted |
| `undercroft_wake_up` | | recent essential memories for session start |
| `undercroft_verify` | | verify HMACs + audit chain |
| `undercroft_status` | | palace statistics |
| `undercroft_get_drawer` | | fetch one drawer verbatim |
| `undercroft_add_drawer` | W | file a drawer with explicit wing/room |
| `undercroft_update_drawer` | W | replace content in place (re-sealed, audited; screened like a save when admission is on — a flagged update quarantines and the reply says so, the drawer keeps its previous content) |
| `undercroft_delete_drawer` | W | delete + tamper-evident tombstone |
| `undercroft_list_drawers` | | page drawer summaries |
| `undercroft_delete_by_source` | W | delete everything mined from a source |
| `undercroft_check_duplicate` | | is this exact content already filed? |
| `undercroft_list_wings` / `_list_rooms` / `_get_taxonomy` | | palace shape |
| `undercroft_create_tunnel` / `_delete_tunnel` | W | connect/disconnect wings |
| `undercroft_list_tunnels` / `_follow_tunnel` / `_traverse` | | navigate tunnels |
| `undercroft_list_hallways` | | entity co-occurrence within a wing |
| `undercroft_get_closet_index` | | compact LLM-scannable index |
| `undercroft_save` / `_add_drawer` also take `kind` | W | declared record kind (closed vocabulary: `question`\|`preference`\|`decision`\|`event`\|`procedure`\|`statement`; rejected if unknown — omit rather than guess). `undercroft_search` filters by it; while filtering, the reply says how many in-scope drawers carry no declared kind |
| `undercroft_save` / `_add_drawer` also take `supersedes` | W | id of the drawer the new record replaces: a receipted update link (the KG receipt pattern one level up — bound to the superseded content's fingerprint under a keyed tag, re-keyed on rotation). The old drawer is **never** deleted or hidden; `undercroft_verify` reports every link's verdict (`verified`\|`source-changed`\|`dangling`\|`unreceipted`\|`tampered`, the last failing the verify) |
| `undercroft_search` also takes `min_trust` | | minimum deployment-assigned wing trust for the query (`quarantined`\|`standard`\|`trusted`): wings the operator assigned below it never enter the candidate competition; unassigned wings count as `standard`. While the floor is set the reply says how many wings it kept out, so a thin answer is never mistaken for a thin corpus. Reading with a floor is self-protection and always allowed — ASSIGNING trust is an operator action (`/v1` + CLI) and deliberately not an MCP tool: an agent that writes content must not be able to raise its own standing |
| `undercroft_kg_add` / `_kg_invalidate` / `_kg_supersede` | W | temporal facts: assert/close/replace |
| `undercroft_kg_query` / `_kg_timeline` / `_kg_stats` | | query facts (incl. `--as-of`) |
| `undercroft_lookup_canonical` | | the exact-authority door: the one active, approved, canonical fact for a key. Consult BEFORE semantic recall for exact or high-risk asks; an empty answer means no declared truth exists — never guess on the key's behalf |
| `undercroft_kg_set_authority` | W | place a fact on the authority tier (closed vocabulary: `stated`\|`canonical` × `unreviewed`\|`approved`\|`rejected`; `canonical_key` required for canonical). Audited; the state is inside the fact's HMAC, so a column flip without the vault key fails verification |
| `undercroft_diary_write` | W | per-agent diary entry |
| `undercroft_diary_read` / `_list_agents` | | read diaries |
| `undercroft_dedup` | W | report/remove exact duplicates. Collapses the *text* only — the days each copy was recorded on are folded onto the survivor's `occurrences` before its row goes, and the report's `dates_kept` counts them. The same words on two different days are two things that happened |

## 9. Reference — HTTP surface

Engine (`serve-http`; bearer always; `X-Vault-Assertion` when
`UNDERCROFT_ASSERTION_SECRET` is set; in read-only everything below that is
not a `GET`, `POST .../search` or `POST .../verify` answers 403):
`UNDERCROFT_ASSERTION_SECRET` is set — on `/v1` **and** on `POST /mcp`, which
asserts for the `--vault` vault; mutating routes 403 in read-only):

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | liveness (no auth) |
| POST | `/mcp` | MCP over HTTP |
| POST | `/v1/vaults` | create vault (`level`, optional `embedder`) |
| GET | `/v1/vaults` | list vaults (403 when assertions are enabled) |
| DELETE | `/v1/vaults/{id}` | delete vault |
| GET | `/v1/vaults/{id}/stats` | stats: records, level, writes, chain head, wings/rooms/kg/tunnels/db_bytes, plus `codebooks` — `[artifact, generation]` per trained index artifact (a generation that moved means every row encoded against its predecessor was re-quantized) |
| GET | `/v1/vaults/{id}/stats/history` | the recent stats sample ring buffer (aggregate counts only, `?window=N` ≤ 300) so a fresh stream client can backfill its chart. **`telemetry` builds only** — a default build answers 501 |
| POST | `/v1/vaults/{id}/drawers` | save (`text`, `wing`, `room`, opt `kind` — closed vocabulary, 400 if unknown — opt `supersedes` — a receipted update link to the drawer this save replaces; the old drawer stays — opt `vector`, `dedup_threshold`) |
| POST | `/v1/vaults/{id}/drawers` | save (`text` — **max 100,000 bytes**, the engine's bound, enforced at the store write choke point on every surface since 2026-08-04; `wing`/`room` go through the same name guard on every write path including import — opt `kind` — closed vocabulary, 400 if unknown — opt `supersedes` — a receipted update link to the drawer this save replaces; the old drawer stays — opt `vector`, `dedup_threshold`) |
| GET | `/v1/vaults/{id}/drawers` | paged summaries (`wing`, `room`, `limit`, `offset`) |
| GET | `/v1/vaults/{id}/drawers/{drawer_id}` | one full drawer, verbatim. `drawer` is byte-faithful to what is stored, so a fetch and an export never disagree about the record; when this build reads its times differently from the sealed reading, `live_time_mentions` and `mentions_restated: true` are added alongside |
| PUT | `/v1/vaults/{id}/drawers/{drawer_id}` | replace content (`text`); screened like a save when admission is on — a flagged update answers 202 `{quarantined: true}` and the drawer keeps its previous content |
| POST | `/v1/vaults/{id}/search` | search (`query`, `limit`, opt `vector`; opt `kind` to filter by declared record kind — while set, the response's `unlabeled_excluded` counts in-scope drawers with no declared kind, so thin labeling is never mistaken for a thin corpus; opt `offset` + `ranked_at` to page — the response returns `next_offset` and the `ranked_at` it ranked at, and repeating both continues the same ranking instead of re-asking it) |
| DELETE | `/v1/vaults/{id}/drawers/{drawer_id}` | delete drawer. **404 when the id is not here** — it answered 200 `{"deleted": false}` until 2026-08-04, so a client checking only the status was told a typo'd or stale id had been deleted. "That record is not here" is 404 on every route now, including `forget` and `admission`, which used to raise it as 400 |
| POST | `/v1/vaults/{id}/search` | search (`query`, `limit` — **default 5**, one page size for every surface; it was 10 here until v0.47.0, so a client relying on ten hits must now say `limit: 10` — opt `vector`; opt `kind` to filter by declared record kind — while set, the response's `unlabeled_excluded` counts in-scope drawers with no declared kind, so thin labeling is never mistaken for a thin corpus; opt `offset` + `ranked_at` to page — the response returns `next_offset` and the `ranked_at` it ranked at, and repeating both continues the same ranking instead of re-asking it) |
| DELETE | `/v1/vaults/{id}/drawers/{drawer_id}` | delete drawer |
| GET | `/v1/vaults/{id}/taxonomy` | wing → room tree with counts |
| GET | `/v1/vaults/{id}/kg/stats` | entity/triple/active/closed counts |
| GET | `/v1/vaults/{id}/kg/entities` | paged entity summaries (`limit`, `offset`) |
| GET | `/v1/vaults/{id}/kg/query` | facts about an entity (`entity`, `direction`, `as_of`, `grounding`) |
| GET | `/v1/vaults/{id}/kg/timeline` | temporal fact timeline (opt `entity`, `grounding`) |
| GET | `/v1/vaults/{id}/kg/canonical/{key}` | the exact-authority door: the one active, approved, canonical fact for the key, or 404 — consult before semantic recall for exact/high-risk asks |
| POST | `/v1/vaults/{id}/kg/authority` | place a fact on the authority tier (`triple_id`, `authority_class`, `review_state`, opt `canonical_key`); audited, HMAC-covered. A value outside the closed vocabulary, or a `triple_id` that names no fact, is **400** |
| GET | `/v1/vaults/{id}/kg/receipts` | every distilled fact's receipt verdict against its cited verbatim source (`verified`\|`source_changed`\|`dangling`\|`tampered`) + summary counts — the KG half of "alert on `tampered` without walking the list"; `GET …/supersessions` below is the drawer-level analogue |

Every fact returned by `kg/query` and `kg/timeline` carries `grounding`:
`stated` (the source note's own words support it — `support.spans` gives the
byte ranges in the cited drawer), `background` (checked, and the note supports
none of it — world knowledge the extractor brought, which is what lets the
graph answer across notes), or `unevaluated` (never checked; every fact
distilled before grounding existed). `?grounding=` narrows to one of those and
is **opt-in only** — the default returns all three, because filtering out
background facts breaks exactly the multi-hop questions the graph is for.
| POST | `/v1/vaults/{id}/refine` | distil verbatim drawers into receipted KG facts + searchable fact-drawers (needs `UNDERCROFT_LLM_URL`). A fact is dated by the words in its note ("three months ago"), not by the note's own date: the extractor returns the span verbatim, the engine rejects any span the note does not contain and resolves the rest deterministically, falling back to `content_date`. The response reports `dated_from_text`. Every distilled fact records its **extractor identity** (the model that claimed it) inside the fact's HMAC — provenance an offline attacker cannot rewrite; facts added by hand carry none. **`undercroft refine` is the same code path** (`--wing`/`--room`/`--fact-room`/`--limit`/`--dry-run`), so the two surfaces build the same vault from the same `UNDERCROFT_LLM_*` configuration; before v0.47.0 the CLI wrote no fact date, no grounding verdict and no searchable mirror |
| POST | `/v1/vaults/{id}/search` | body also accepts `room_cap` (soft per-room cap on selection; absent = pure score order) and `as_of` (RFC 3339 reference date). Hits carry `content_date`, `filed_at`, `time_mentions`, `entities`, and — when `as_of` is given — `elapsed_days`, `elapsed_weeks`, `elapsed_months`, `elapsed`, `same_frame`. Each entry in `time_mentions` carries `resolved` plus `resolved_end` when the text named a period ("May 2023", "last week") rather than a day, and — with `as_of` — its **own** `elapsed_days`/`elapsed` (`elapsed_days_end` for a period). Those answer a different question from the hit's: the drawer's `content_date` is when it was written, a mention is when the thing it describes happened. `time_mentions` is **read live**, not from the seal — it is derived from the drawer's own text and `content_date`, both immutable, so every improvement to the scanner applies to existing vaults with no migration. `mentions_restated: true` appears only when this build reads the drawer differently from the reading sealed onto it |
| POST | `/v1/vaults/{id}/verify` | integrity verdict: HMAC every record, replay the audit chain, and check every drawer supersession receipt. `ok` covers all three legs — the same verdict CLI `verify` exits 2 on and MCP prints as VERIFY FAILED — plus `records_checked`, `bad_records`, `chain_ok`, a `supersessions` count breakdown and `bad_supersessions` (links whose receipt failed its HMAC) |
| GET | `/v1/vaults/{id}/supersessions` | every drawer supersession link's verdict (`verified`\|`source_changed`\|`dangling`\|`unreceipted`\|`tampered`) + summary counts — alert on `tampered` without walking the list |
| POST | `/v1/vaults/{id}/forget` | destroy the named drawers through the audit chain and return the attestation (`{ids}` in; heads + tombstone interval + content fingerprints out, unsigned — sign via CLI `forget --sign`). Verify with CLI `verify-forgetting` |
| GET | `/v1/vaults/{id}/admission` | drawers awaiting an admission ruling (signal codes + offsets, intended destination) plus whether screening is on |
| POST | `/v1/vaults/{id}/admission` | rule on a quarantined drawer (`drawer_id`, `verdict` ∈ `allow`\|`deny`; chain-audited — a deny destroys through the attested-forgetting path and the response carries the receipt). Operator surface, never MCP — an agent whose write was quarantined must not rule on it |
| GET | `/v1/vaults/{id}/retention` | every declared retention policy, tag-verified |
| POST | `/v1/vaults/{id}/retention` | declare (`{wing, room?, days}`) or clear (`{wing, room?, clear: true}`) a retention policy; audited. Operator surface, never MCP — an agent must not shorten the life of the memory it writes or reads |
| POST | `/v1/vaults/{id}/retention/sweep` | destroy what aged out through the attested-forgetting path (`{dry_run: true}` previews); the response carries the sweep report + receipt. Nothing runs automatically — a sweep happens when the operator asks |
| POST | `/v1/vaults/{id}/trust` | assign a wing's trust class (`wing`, `trust` ∈ `quarantined`\|`standard`\|`trusted`; 400 if unknown). The receiving principal's declaration — an OPERATOR surface, deliberately absent from MCP; audited, tamper-evident |
| GET | `/v1/vaults/{id}/trust` | every assigned wing trust class (absent wings read as `standard`) |
| POST | `/v1/vaults/{id}/rotate` | rotate the vault onto fresh keys (sole-writer contract — **409** for the vault this same process also serves over `/mcp`, i.e. the one named by `--vault`: rotating retires the keys under that second live handle, which then reports every read as TAMPERED and re-anchors the manifest from its stale cache. Stop the server and run `undercroft vault rotate <name>`, which holds the only handle) |
| GET | `/v1/vaults/{id}/export` | lossless NDJSON: a manifest first line (counts, provenance, unsigned on this surface), then drawers (vectors + token artifacts), KG entities, facts (receipts travel and re-key at import) and tunnels — the whole palace |
| POST | `/v1/vaults/{id}/import` | parse-before-write import; accepts manifest-era typed records and legacy drawer-only NDJSON; enforces the manifest's payload digest and expiry when present. The response carries `quarantined` beside `imported` — how many records the admission screen diverted (0 while screening is off). Every imported record's `added_by` is **re-stamped `import`**, overwriting whatever the payload claimed: that field is the key the trusted-source auto-admit rides, so a bundle claiming `added_by: "cli"` must not inherit a save surface's standing. Declare `UNDERCROFT_ADMIT_TRUSTED_SOURCES=import` to trust the import act itself |
| GET | `/ui` | vault admin console (static page; every build) |
| GET | `/metrics`, `/monitor`, `/v1/…/stream` | telemetry builds only |

Orchestrator: tenant data plane `/t/<drawers|search|stats|export|import>`
with the tenant bearer; admin plane `/admin/instances[…]`,
`/admin/tenants[…]` (+ `/rotate`, `/migrate`, `/stats` — metadata-only
relay) with `UNDERCROFT_ORCH_ADMIN_TOKEN`; `GET /ui` serves the fleet
console (static page, no auth to load — the admin token is entered in
the page; live 10 s health + stats sweep). `GET /healthz` reports
`mode` (`writer`/`read-replica`) + `last_write`; on a read replica
(`serve --read-replica`) only `/healthz` and `/t/*` serve — `/admin/*`
and `/ui` answer 403.

## 10. Reference — environment variables

Core: `UNDERCROFT_HOME` (palace dir, default `~/.undercroft`) ·
`UNDERCROFT_PASSPHRASE` (Argon2id master key instead of key file) ·
`UNDERCROFT_LANG` (CLI language, 9 supported).

Models: `UNDERCROFT_EMBEDDER` (`hash`|`onnx`|`ort`|`http`) ·
`UNDERCROFT_EMBED_URL`/`_MODEL`/`_API`/`_KEY`/`_DIM`/`_CA` (served
embedder; TLS or loopback only, `_CA` pins a self-signed root) ·
`UNDERCROFT_ONNX_MODEL`/`_TOKENIZER`/`_NAME` ·
`UNDERCROFT_RERANKER` (`onnx`|`ort`|`colbert`|`colbert-ort`; the two
ColBERT values are **single-vault only** — `serve-http` refuses them,
same shape as `UNDERCROFT_RETRIEVAL=hnsw`) ·
`UNDERCROFT_RERANK_MODEL`/`_TOKENIZER`/`_NAME`/`_TOP_N` (50) ·
`UNDERCROFT_COLBERT_MODEL`/`_QUERY_MODEL`/`_TOKENIZER`/`_NAME` ·
`UNDERCROFT_ORT_POOL` (session pool, default = cores) ·
`UNDERCROFT_FORCE_EMBEDDER` (allow identity swap, then `repair`).

Retrieval: `UNDERCROFT_RETRIEVAL` (`pq`|`fde`|`hnsw` — `hnsw` is an
in-process index and **single-vault only**: `serve-http` refuses it and
names the fix, so choose `pq` or `fde` for a multi-tenant server) ·
`UNDERCROFT_SEARCH_TRACE` (unset — any value prints a per-phase timing
trace of each search to stderr, the instrument that found this project's
own search hotspot. **Presence-triggered**: `0` and `off` turn it ON
too; unset it to turn it off) · `UNDERCROFT_FUSION`
(`bm25` default |`legacy`; `rrf` removed — measured −7.3pp, warns and falls
back to `bm25`) · `UNDERCROFT_FUSION_WEIGHT` (0.55 — the blend's semantic
weight `w` in `w·semantic + (0.90−w)·lexical + 0.10·recency`; declared,
clamped to 0.20–0.70 so no configuration can retire a channel, one global
value never per-query) · `UNDERCROFT_TRUST_FLOOR` (unset — vault-level
minimum wing trust, `quarantined`|`standard`|`trusted`: unscoped searches
exclude wings the operator assigned below it, resolved before candidates
are drawn; an explicitly named wing scope bypasses the vault floor,
a request's own `min_trust` never is; garbage warns and stays off) ·
`UNDERCROFT_ADMIT_TRUSTED_SOURCES` (empty — comma list of surfaces whose
writes bypass the admission screen, matched against the handler-stamped
`added_by`, never against writer-declared provenance claims: a claim
must not admit itself) ·
`UNDERCROFT_ADMISSION` (off — `quarantine` screens every save with the
deterministic tier-1 detector and diverts flagged writes, sealed with
their signal codes and intended destination, into the reserved
`quarantine-pending` wing: hard-excluded from retrieval except a
reviewer's explicit wing scope, and reviewed via CLI
`admission list|allow|deny` or `/v1` GET/POST `…/admission` — operator
surfaces, deliberately never MCP. **MCP cannot reach the wing at all**:
any tool argument naming `quarantine-pending`, or any `id`/`*_id`
argument naming a drawer resident there, is refused — the review queue
is an operator surface for reading as well as for ruling. And on EVERY
surface, a quarantine-pending drawer cannot be deleted or forgotten:
`admission allow`/`deny` are the doors, because a plain delete leaves
only a `del/<id>` tombstone that no one can tell from housekeeping.
Heuristic, quarantine-not-reject; the
default leaves the write contract byte-identical) ·
`UNDERCROFT_ADMISSION_LLM` (unset — `advisory` wires the
`UNDERCROFT_LLM_*` runtime as the screen's tier-2 classifier: consulted
only for candidates the deterministic tier passed, only toward
quarantine (the `llm-advisory` signal code) — never auto-admit, because
the model is itself an injection target; a failed or unparseable answer
is a non-event, and a declared-but-unusable advisor refuses to open.
TLS or loopback only) ·
`UNDERCROFT_ADMISSION_RATE` (unset — `<count>/<seconds>` declares the
per-writer rate screen: a writer identity (the `agent` claim when the
write carries one, else the surface-stamped `added_by` among claim-less
rows) that already has ≥ count committed writes inside the trailing
window diverts to quarantine with the `rate-anomaly` signal. The
threshold is deployment-shaped, so it is declared, never defaulted; an
unreadable declaration refuses to open rather than silently running
unscreened; consulted only when `UNDERCROFT_ADMISSION=quarantine`) ·
`UNDERCROFT_READ_AUDIT` (unset — `chain` appends one audit-chain record
per search: a keyed fingerprint of the query (never its text), the
declared scope, and the hit count, on every search path. A per-query
chain append is a real durability cost, so it is declared; garbage
refuses to open; a read-only open warns and serves unaudited. Exports
are chain-audited unconditionally — one `egress/export` record binding
the export's own manifest digest — with no variable to set) ·
`UNDERCROFT_TRAIN_SOURCE_CAP` (4 — per-wing cap divisor on global
codebook training draws: no single wing supplies more than 1/N of a
training sample while others can fill it; within-quota corpora draw
byte-identical samples; `off` = uncapped) ·
`UNDERCROFT_FTS_PREFILTER_MIN` (2048) ·
`UNDERCROFT_SEMANTIC_GATE` (the embedder's own calibration; a number in
`0.0..=1.0` declares the `semantic` score above which a drawer is admitted
on cosine evidence alone, `off` refuses semantic-only admission entirely.
Set it only if you have measured your own corpus — the default is measured
from the embedder in hand, and an external vault refuses until you declare) ·
`UNDERCROFT_SEMANTIC_FLOOR` (the embedder's own — the raw cosine the vector
space gives unrelated text, the calibration zero of the cosine→`semantic`
map: the measured floor lands at 0.5 and 1.0 stays 1.0, so a served
model's semantic channel keeps its full range in fusion. Hash declares 0,
which reproduces the shipped map to the bit; declare this only for an
external vault you have measured yourself; garbage warns and defers) ·
`UNDERCROFT_IVF_MIN` (8192) · `UNDERCROFT_IVF_NPROBE` ·
`UNDERCROFT_WING_PQ_MIN` (4096 — wings at least this large carry their own
PQ codebook and code rows, so a wing-scoped search probes the wing's index
instead of intersecting corpus-wide candidates; smaller wings full-scan
themselves, bounded and exact; `off` disables the per-wing tier only —
every declared scope, wing or room, is resolved before candidates are
drawn, so no scoped query can be starved by the corpus top-k) ·
`UNDERCROFT_POOL_DIV` (64 — semantic prefilters fetch at least `live/div`
stage-1 ADC candidates, and an exact-cosine second stage over just those
candidates' embeddings cuts back to hydration size, so recall follows the
wide pool while hydration stays fixed; measured: fixed 256 leaked R@5
100→96.8% by 1M drawers; `off` = fixed floor, the measured-leaky
behavior) ·
`UNDERCROFT_PQ_PAGE_MIN` (off by default — sealed page tier: one AEAD
page per IVF list, lazy per-probe decrypt) ·
`UNDERCROFT_TOK_PQ_MIN` (256) · `UNDERCROFT_FDE_PQ_MIN` (256) ·
`UNDERCROFT_FDE_IVF_MIN` (off by default — opt-in inverted tier) ·
`UNDERCROFT_FDE_NPROBE` (max(8, nlist/4)) ·
`UNDERCROFT_FDE_REPS`/`_KSIM`/`_DPROJ`/`_SEED` (first build only, then
persisted per vault) · remote backends:
`UNDERCROFT_QDRANT_URL`/`_CHROMA_URL`/`_PGVECTOR_DSN`/`_MILVUS_URL`/`_WEAVIATE_URL`.

Server: `UNDERCROFT_MCP_HTTP_TOKEN` (bearer; mandatory non-loopback) ·
`UNDERCROFT_ASSERTION_SECRET` (enables per-vault assertions) ·
`UNDERCROFT_METRICS=1` (+ bearer) · `UNDERCROFT_SAMPLE_INTERVAL_MS` (2000).

LLM (optional, for `refine` and the admission advisor):
`UNDERCROFT_LLM_URL` (**TLS or loopback only** — cleartext http to a
non-loopback host refuses at construction, no override: refine sends
drawer text verbatim and the advisor sends candidates, and that content
must never cross a readable wire) · `UNDERCROFT_LLM_MODEL`
(`llama3.2`) · `UNDERCROFT_LLM_API` (`ollama`|`openai`) ·
`UNDERCROFT_LLM_CA` (PEM whose certificates become the ONLY trust roots
for the LLM connection — the `UNDERCROFT_EMBED_CA` pin one client over;
garbage refuses, never falls back) ·
`UNDERCROFT_LLM_KEY` (bearer credential; **unset by default** — local
runtimes take none, and an empty key sends no header at all. Set it only
to reach a runtime behind an authenticating gateway, which unlike the
local default means drawer text leaves the machine).

Telemetry builds: `UNDERCROFT_LOG` · `UNDERCROFT_LOG_FORMAT` (`json`) ·
`UNDERCROFT_OTLP_ENDPOINT` (unset ⇒ nothing leaves the process) ·
`UNDERCROFT_OTLP_HEADERS` (comma-separated `key=value` export headers,
e.g. `authorization=Bearer <token>` for authenticated collectors) ·
`UNDERCROFT_SERVICE_NAME`.

Orchestrator: `UNDERCROFT_ORCH_DB` · `UNDERCROFT_ORCH_KEY` (required) ·
`UNDERCROFT_ORCH_ADMIN_TOKEN` (required on the writer, ≥16 chars; unused
by `serve --read-replica`) · `UNDERCROFT_ORCH_ADDR` (127.0.0.1:8900) ·
`UNDERCROFT_ORCH_RATE_LIMIT` (req/min per tenant; unset/`0`/`off` = off;
per-process — each replica enforces its own windows. A value that is not
one of those **refuses to start**, the engine's posture for a declaration
it cannot read: `100/min` and `1_000` used to parse as "off" and serve
unlimited in silence).

## 11. Verify your implementation

Whatever scenario you built, prove it before calling it done:

```bash
undercroft verify                          # exit 0, "VERIFY OK", chain ok
undercroft stats                           # records/wings match what you ingested
undercroft search "<something you stored>" # returns the exact words
undercroft backup create && undercroft backup list
```

Server scenarios: `curl -fsS http://host:port/healthz`; a request
**without** the bearer must 401; with assertions enabled, a request signed
for vault A against vault B must 401; `--read-only` must refuse a save.
Orchestrator: a tenant token must reach only its own vault, and
`/t/<anything-not-allowlisted>` must 404. If any of these checks
surprises you, stop and read the matching scenario again — the system is
designed so that the insecure configuration is the one that takes extra
work.
