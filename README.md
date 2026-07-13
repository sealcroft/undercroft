<div align="center">

# Undercroft

**Hardened, local-first AI memory — a Rust conversion of [MemPalace](https://github.com/MemPalace/mempalace) with encrypted, integrity-verified memory vaults.**

</div>

---

## Why "Undercroft"?

In Greek mythology, **Undercroft** (νη-MOZ-ih-nee) is the Titaness of memory and
remembrance, daughter of Uranus and Gaia, and the mother of the nine Muses.
Before writing existed, the Greeks held that all knowledge — every epic, every
lineage, every law — survived only through her: memory was not a convenience
but the *guardian of everything worth keeping*. Orators drank from her spring;
in the underworld, initiates were told to pass the river Lethe (forgetting)
and drink instead from the pool of Undercroft to retain what they knew across
the crossing.

That is precisely this project's job description:

| Undercroft (myth) | undercroft (this project) |
|---|---|
| Guardian of memory before writing existed | Guards your AI's memory outside any single session |
| Mother of the Muses — memory begets creation | Retrieved context begets better answers, code, and writing |
| Her pool preserves knowledge across the crossing into the underworld | Memories survive the "crossing" between sessions, context compressions, and machines |
| Sacred, protected spring — not an open river | Memories live in **sealed vaults**: encrypted, isolated, tamper-evident |

The ancient *method of loci* — the "memory palace" technique MemPalace is named
for — was itself attributed to Undercroft's gift. Undercroft keeps the palace and
adds what the myth implies: the palace has **locks**.

## What it is

Undercroft stores conversation history and project knowledge as **verbatim
text** (never summarized on the way in) and retrieves it with hybrid
semantic + lexical + recency search. The index keeps MemPalace's structure —
people and projects are *wings*, topics are *rooms*, original content lives in
*drawers* — and adds a security-first **memory management layer**:

### The vault layer (new in this fork)

Every memory namespace is a **vault** — a hard isolation boundary:

- **Separation** — each vault has its own directory and its own SQLite
  database. There is no shared table space to leak across, and vault names are
  validated against path traversal.
- **Key isolation** — per-vault encryption and MAC keys are derived from one
  palace master key via **HKDF-SHA256 domain separation**. Vault A's keys are
  cryptographically useless against vault B's data. The master key is either a
  `0600` key file or derived from a passphrase with **Argon2id** (64 MiB, t=3);
  keys are zeroized in memory on drop.
- **Encryption** — in `sealed` vaults (the default), drawer content *and its
  embedding* are encrypted with **XChaCha20-Poly1305**. The AEAD associated
  data binds vault id + record id, so ciphertext cannot be replayed into
  another vault or another record slot. Nothing content-derived is written to
  disk in plaintext — search runs by decrypt-scan.
- **HMAC integrity** — every record carries an **HMAC-SHA256** tag (independent
  MAC key) over its id, metadata, and at-rest content; reads verify before
  returning data. An append-only audit table feeds a **tamper-evident HMAC
  chain** whose head lives in the vault manifest — and the manifest itself is
  MAC'd, so offline edits (chain resets, security-level downgrades) are caught
  at unlock. `undercroft verify` walks all of it.
- **Choice of level** — `sealed` (encrypt everything) or `hmac-only`
  (plaintext + full-text indexing, but still integrity-tagged and chained) for
  memories where searchability outweighs confidentiality.

**Threat model:** protects memories at rest against disk theft, cross-vault
bleed, and offline tampering of the database or manifest. It does *not* defend
against an attacker who can read process memory while a vault is unlocked.

Nothing leaves your machine. The embedder is a deterministic local
hashed n-gram model — no downloads, no API calls, no network at all.

## Quickstart (Docker — recommended)

Everything persists under `/data`, so mount a volume there:

```bash
docker build -t undercroft .

docker run --rm -v undercroft-data:/data undercroft init
docker run --rm -v undercroft-data:/data undercroft remember \
  "We chose GraphQL over REST for the mobile API" --wing backend --room decisions
docker run --rm -v undercroft-data:/data undercroft search "why graphql"
docker run --rm -v undercroft-data:/data undercroft verify
docker run -i --rm -v undercroft-data:/data undercroft serve-mcp   # MCP stdio server
```

Wire it into an MCP client (e.g. Claude Code):

```json
{
  "mcpServers": {
    "undercroft": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-v", "undercroft-data:/data", "undercroft", "serve-mcp"]
    }
  }
}
```

Or build natively: `cargo build --release` → `target/release/undercroft`.

## CLI

```text
undercroft init                       # master key + 'default' sealed vault
undercroft vault create work          # new isolated vault (own keys, own DB)
undercroft vault list | status <name>
undercroft remember <text> [--vault --wing --room]
undercroft mine <dir> [--vault --wing]    # chunk + file text/markdown files
undercroft search <query> [--vault --wing --room -n N]
undercroft wake-up [--vault --wing]       # L0 identity + L1 essential story
undercroft verify [--vault]               # HMAC every record + replay audit chain
undercroft export [--vault]               # decrypted JSONL to stdout
undercroft serve-mcp [--vault]            # MCP tools: save/search/wake_up/verify
```

Palace location: `$UNDERCROFT_HOME` (default `~/.undercroft`; `/data` in Docker).
Passphrase mode: set `UNDERCROFT_PASSPHRASE` before `init` and every command.

## MCP tools

| Tool | Purpose |
|---|---|
| `undercroft_save` | File one verbatim memory (encrypted + tagged at rest) |
| `undercroft_search` | Hybrid search over the vault |
| `undercroft_wake_up` | Recent essential memories for session start |
| `undercroft_verify` | HMAC + audit-chain integrity check |

## Testing (all in Docker)

```bash
docker compose run --rm test   # unit + integration tests (cargo, 40+ tests)
docker compose run --rm e2e    # end-to-end UI/UX suite against the real binary
```

The e2e suite drives the actual CLI the way a user would — help text, happy
paths, exit codes, vault isolation, plaintext-leak checks against the raw DB
file, deliberate on-disk tampering (must be detected), and a scripted MCP
JSON-RPC session.

## Architecture

```
crates/
  undercroft-core/    domain model: drawers, chunking, ids, normalization,
                     deterministic hashed n-gram embedder
  undercroft-vault/   security layer: VaultManager, HKDF key derivation,
                     XChaCha20-Poly1305 sealing, HMAC tags + audit chain
  undercroft-store/   SQLite per-vault storage + hybrid search
  undercroft-cli/     `undercroft` binary: CLI + MCP stdio server
```

Drawer metadata (wing, room, source_file, chunk_index, added_by, filed_at,
normalize_version, id_recipe, …) mirrors MemPalace's schema, and drawer ids
use the same deterministic-recipe idea (idempotent re-mining).

## Relationship to MemPalace

Undercroft is a fork of [MemPalace](https://github.com/MemPalace/mempalace)
(MIT). The Python implementation is retained in-tree (`mempalace/`,
`Dockerfile.python`, `docker-compose.python.yml`) as the reference during the
conversion; the Rust workspace is the primary implementation going forward.
Not yet ported: the Chroma/Qdrant/Milvus/pgvector server backends, the
conversation/format miners, knowledge graph, and the model-based embedder —
see [ROADMAP](ROADMAP.md).

## License

BUSL-1.1 — see [LICENSE](LICENSE). Original work © MemPalace contributors.
