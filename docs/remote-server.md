# Remote team server

Share one palace with a team over MCP HTTP:

```bash
cp deploy/server.env.example deploy/.env    # set UNDERCROFT_MCP_HTTP_TOKEN
docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env up -d
```

Clients:

```bash
claude mcp add --transport http undercroft http://HOST:8765/mcp \
  --header "Authorization: Bearer $UNDERCROFT_MCP_HTTP_TOKEN"
```

- The server refuses non-loopback binds without the token.
- `--read-only` exposes recall without write access (see the compose file).
- `/healthz` is unauthenticated for probes.
- Plain HTTP: terminate TLS in a reverse proxy for anything beyond a
  trusted network.
- Backing store: the palace volume is the system of record; Qdrant only
  ever receives sealed content + embeddings.

Systemd alternative: `deploy/undercroft-server.service`.

## Multi-tenant REST surface (`/v1`)

`serve-http` also exposes a versioned REST API in the same process, behind
the same bearer, for programmatic (non-MCP) callers and for orchestration
platforms that use one **vault per tenant**. One palace per process stays
the model — tenancy is vaults, not palaces.

```text
POST   /v1/vaults                      {id, level?, embedder?}   create vault
DELETE /v1/vaults/{id}                                           delete vault
GET    /v1/vaults/{id}/stats            (records, level, writes, chain head,
                                         wings, rooms, kg, tunnels, db_bytes,
                                         codebooks)
POST   /v1/vaults/{id}/drawers         {text, wing?, room?, vector?, dedup_threshold?}
GET    /v1/vaults/{id}/drawers          ?wing=&room=&limit=&offset=  paged summaries
GET    /v1/vaults/{id}/drawers/{drawer_id}                       one full drawer
PUT    /v1/vaults/{id}/drawers/{drawer_id}  {text}               replace content
POST   /v1/vaults/{id}/search          {query, wing?, room?, limit?, vector?}
DELETE /v1/vaults/{id}/drawers/{drawer_id}
GET    /v1/vaults/{id}/taxonomy         (wing → room tree with counts)
GET    /v1/vaults/{id}/kg/stats         (entity/triple/active/closed counts)
GET    /v1/vaults/{id}/kg/entities      ?limit=&offset=              paged entities
GET    /v1/vaults/{id}/kg/query         ?entity=&direction=&as_of=   facts about one entity
GET    /v1/vaults/{id}/kg/timeline      ?entity=                     temporal fact timeline
POST   /v1/vaults/{id}/verify           (HMAC + audit-chain report)
POST   /v1/vaults/{id}/rotate           (re-key the vault; sole-writer contract)
GET    /v1/vaults/{id}/export           (decrypted NDJSON: {drawer, vector} per line)
POST   /v1/vaults/{id}/import           (NDJSON body; returns {imported: N})
GET    /ui                              (vault admin console; unauthenticated static page)
GET    /healthz                         (unauthenticated)
```

The **admin console** at `/ui` drives this whole surface from a browser:
vault lifecycle, stats, verification, key rotation, drawer browsing with
verbatim view/edit/delete, search, and export/import. The page itself
carries no secrets — the bearer (and the assertion secret, under per-vault
isolation) are entered in the page and never leave the tab; assertions are
minted in-browser with WebCrypto. Destructive operations require typing the
target's name.

Vault lifecycle over HTTP lets an orchestrator auto-provision a dedicated
memory instance per tenant and migrate a vault between instances:
`export → verified import → drop`. Import returns the exact record count so
the caller can verify before dropping the source.

`level` is `sealed` (default) or `hmac-only`. `embedder` is `hash`
(default) or `external:<name>@<dim>` (see below). Under `--read-only`, only
reads (stats, search, export) are served; every mutation returns 403.

## Per-vault request authorization

The palace-wide bearer proves the caller reached the right *server*; it does
not distinguish *tenants*. Set `UNDERCROFT_ASSERTION_SECRET` and every `/v1`
request must additionally carry a short-lived assertion for the exact vault
it addresses — and so must `POST /mcp`, for the vault the server was started
with (`--vault`). Both transports are gated, or the one the MCP handler
serves would stay open to a bare bearer:

```text
X-Vault-Assertion: <unix_ts>:<hex>
    hex = HMAC-SHA256(secret, "<unix_ts>|<vault_id>")
```

The caller platform authorizes its user, then mints the assertion; the
engine verifies it independently, so a compromised caller component that
lacks the secret gets nothing. An assertion minted for vault A never
authorizes vault B (the vault id is inside the MAC), a timestamp outside
±120s is refused, and comparison is constant-time. Any failure is a bare
401 — the reason is logged server-side, never returned.

Mint one for testing or from a shell with `undercroft assert-header <vault>`
(reads `UNDERCROFT_ASSERTION_SECRET`); production callers reimplement the
same one-line HMAC in their own stack.

```bash
export UNDERCROFT_ASSERTION_SECRET=…
H=$(undercroft assert-header acme)
curl -s http://HOST:8765/v1/vaults/acme/search \
  -H "Authorization: Bearer $UNDERCROFT_MCP_HTTP_TOKEN" \
  -H "X-Vault-Assertion: $H" \
  -d '{"query":"which database for billing"}'
```

## Externally-supplied embeddings

A vault created with `embedder: "external:<name>@<dim>"` stores
caller-provided vectors and never runs a local model — for platforms that
already own an embedding space (embedding through their own model gateway
for spend attribution, shared across ingest, sync, and migration). Such a
vault requires a `vector` of exactly `<dim>` floats on every drawer write
and on every search, refuses writes without one, and enforces the recorded
dimension exactly like any other embedder identity. Sealed vaults seal
these vectors the same way as internally-computed ones.

## Semantic dedup-refresh on save

Pass `dedup_threshold` on a drawer write to collapse near-duplicates: if an
existing drawer in the same wing+room has embedding cosine `>= threshold`,
it is refreshed in place (text/metadata/recency updated, id kept) and the
response reports `{"deduped": true, "id": …}`. This makes bulk
re-ingestion of an updated corpus idempotent — re-running an importer
refreshes unchanged facts instead of piling up near-copies. A refresh is an
ordinary audited update (re-tagged, chain advanced), never a silent
overwrite.

## Orchestrated deployment (one instance per tenant)

The master key is injected at start; `init` runs headless with no prompts
and never logs key material. A container orchestrator can stamp out one
Undercroft per tenant:

```yaml
services:
  undercroft:
    image: undercroft:latest
    command: ["serve-http", "--host", "0.0.0.0", "--port", "8765"]
    environment:
      # Master key material — inject from your secret store, never bake in.
      UNDERCROFT_PASSPHRASE: ${TENANT_PASSPHRASE}
      UNDERCROFT_MCP_HTTP_TOKEN: ${PALACE_BEARER}
      UNDERCROFT_ASSERTION_SECRET: ${ASSERTION_SECRET}
    volumes:
      - tenant-data:/data          # palace: vaults, keys, audit chain
    # Front with a TLS-terminating reverse proxy; /healthz for probes.
volumes:
  tenant-data:
```

Bootstrap is non-interactive: with `UNDERCROFT_PASSPHRASE` set, `undercroft
init` (or the first `serve-http`, which opens the default vault) derives the
master key via Argon2id and writes it under `/data` with `0600` permissions
— no TTY, no prompt, and the key is never emitted to logs. Provision each
tenant's vaults over `/v1/vaults` once the instance is up.
