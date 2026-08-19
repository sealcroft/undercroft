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
- It also refuses a token that is **empty** or ends in **whitespace**. The
  second is the one that bites: `UNDERCROFT_MCP_HTTP_TOKEN=$(cat
  /run/secrets/token)` over a file ending in a newline used to start a server
  that refused every client forever, because HTTP strips a header value's
  trailing whitespace so the declared token could never be presented. Strip it
  at the source — `$(tr -d '\n' < /run/secrets/token)`. Leading and internal
  whitespace are fine; they are presentable.
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

**All 36 routes**, counted against `route()` in
`crates/undercroft-cli/src/tenant.rs` rather than remembered — and the count
is GATED now (ROADMAP O45), because "rather than remembered" was exactly what
happened: this list said 35 and omitted
`POST /v1/vaults/{id}/verify-forgetting` from the day O14 added it, while
`docs/AGENTS.md` §10 carried it correctly. One route added, two route
references, one updated. It also listed 18 of them until 2026-08-05,
omitting the whole operator plane
(trust, admission review, retention, forgetting) plus the golden-values
tier. Everything under *operator plane* is deliberately absent from MCP:
an agent must not rule on the queue that exists to contain it, nor assign
the trust class that decides what it may retrieve.

```text
── lifecycle ────────────────────────────────────────────────────────────
POST   /v1/vaults                      {id, level?, embedder?}   create vault
GET    /v1/vaults                                                list vault ids
DELETE /v1/vaults/{id}                                           delete vault

── read / write ─────────────────────────────────────────────────────────
GET    /v1/vaults/{id}/stats            (records AND drawers — one drawer
                                         count under both names, from one
                                         read; quarantined — the part of it
                                         in the reserved review wing, which
                                         wings/rooms exclude, so the three
                                         reconcile; level; the chain height as
                                         writes AND chain_records — same
                                         number, `writes` deprecated since
                                         it counts exports and audited
                                         reads too; chain head,
                                         wings, rooms, kg, tunnels, db_bytes,
                                         read_only, unhealed, codebooks)
GET    /v1/vaults/{id}/stats/history    ?window=N   sample ring buffer
                                         (501 without --features telemetry)
POST   /v1/vaults/{id}/drawers         {text, wing?, room?, vector?, dedup_threshold?}
                                         202 + {quarantined:true} if diverted
GET    /v1/vaults/{id}/drawers          ?wing=&room=&limit=&offset=  paged summaries
GET    /v1/vaults/{id}/drawers/{drawer_id}                       one full drawer
PUT    /v1/vaults/{id}/drawers/{drawer_id}  {text}               replace content
DELETE /v1/vaults/{id}/drawers/{drawer_id}
POST   /v1/vaults/{id}/search          {query, wing?, room?, limit?, vector?, …}
GET    /v1/vaults/{id}/taxonomy         (wing → room tree with counts)

── knowledge graph (read-only browse, plus the authority tier) ───────────
GET    /v1/vaults/{id}/kg/stats         (entity/triple/active/closed counts)
GET    /v1/vaults/{id}/kg/entities      ?limit=&offset=              paged entities
GET    /v1/vaults/{id}/kg/query         ?entity=&direction=&as_of=   facts about one entity
GET    /v1/vaults/{id}/kg/timeline      ?entity=                     temporal fact timeline
GET    /v1/vaults/{id}/kg/receipts      receipt verdicts per fact
                                         (verified|source_changed|dangling|tampered)
GET    /v1/vaults/{id}/kg/canonical/{key}   the one active approved fact
POST   /v1/vaults/{id}/kg/authority     declare authority_class / review_state
GET    /v1/vaults/{id}/supersessions    drawer supersession links + verdicts

── operator plane (never on MCP) ────────────────────────────────────────
GET    /v1/vaults/{id}/history          audit chain (subject?, limit?, offset?)
GET    /v1/vaults/{id}/trust            wing trust assignments
POST   /v1/vaults/{id}/trust            assign one (closed vocabulary)
GET    /v1/vaults/{id}/admission        the pending review queue
POST   /v1/vaults/{id}/admission        rule allow | deny (deny is receipted)
GET    /v1/vaults/{id}/retention        policies per wing/room
POST   /v1/vaults/{id}/retention        set one
POST   /v1/vaults/{id}/retention/sweep  enforce; returns a proof receipt
POST   /v1/vaults/{id}/forget           provable destruction + attestation
POST   /v1/vaults/{id}/verify-forgetting  check an attestation this vault
                                        issued: Verified, or Recorded when a
                                        key rotation has destroyed the replay
                                        key (exit 0 either way); 409 if the
                                        document does not describe this vault

── maintenance / portability ────────────────────────────────────────────
POST   /v1/vaults/{id}/refine           LLM distillation → KG
POST   /v1/vaults/{id}/verify           (HMAC + audit-chain report)
POST   /v1/vaults/{id}/anchor           (tighten the manifest rollback anchor; a write)
POST   /v1/vaults/{id}/rotate           (re-key the vault; sole-writer contract)
GET    /v1/vaults/{id}/export           (decrypted NDJSON: {drawer, vector} per line)
POST   /v1/vaults/{id}/import           (NDJSON body; returns {imported, quarantined})

── not under /v1 ────────────────────────────────────────────────────────
GET    /ui                              (vault admin console; unauthenticated static page)
GET    /healthz                         (unauthenticated)
```

**The console at `/ui` is a `/v1` CLIENT, not a fourth surface.** It has no
capability of its own and no code path the REST API does not expose, so the
drift rule (CLI / MCP / `/v1` / orchestrator) does not add a column for it —
but a fix that lands on `/v1` and not on the page is still a defect the user
meets, which is how a success toast came to be shown for a `202
{"quarantined": true}`. Stated because several boundaries in these documents
rest on it and none of them said so (ROADMAP C14).

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
(default) or `external:<name>@<dim>` (see below).

**`--read-only`, precisely.** It is a posture on the whole process, not a
filter on one port, and the gate sits **in front of dispatch** rather than
at the top of each mutating handler — because the per-handler version had
thirteen guards for fourteen mutating routes and `POST …/kg/authority`
never got one. It **fails closed**: every `GET` is served, and every
non-GET is refused with 403 *unless it is one of two named reads* —
`POST …/search` and `POST …/verify` (both POST for cost, not for effect).
A route added later is refused until someone deliberately names it. This
paragraph used to say "only reads (stats, search, export) are served",
which under-listed the reads and omitted `verify` entirely.

**The open is covered too, since 1.0.0.** This paragraph used to name it
as the thing `--read-only` did not cover — opening a store created schema,
initialised the chain, and ran a rotation reconcile that could promote or
delete a staged `vault.json.next`, all lazily on the first request against a
cold handle. The connection is now `SQLITE_OPEN_READ_ONLY` under `PRAGMA
query_only=ON`; the schema is checked rather than created, a lagging manifest
anchor is reported rather than healed, and a staged rotation is honoured in
memory with its file untouched. Whatever the open declined to repair appears
as `unhealed` on `GET /v1/vaults/{id}/stats` beside `read_only`. Two
conditions refuse with **409** instead: a manifest whose `palace.db` is
absent, and a schema this build would have had to migrate.

What is still not a claim: a read-only connection materialises SQLite's WAL
scaffolding (`-shm`, and a zero-length `-wal`) where the directory is
writable — no database content, and where the directory is not writable the
open escalates to `immutable=1` and warns. If you need a genuinely
byte-frozen vault, stop the server rather than restarting it read-only.

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
      # Same interpolation hazard as the assertion secret below, and the
      # consequence is worse: an empty value used to mean "no passphrase",
      # so the palace wrote a random master.key to DISK — the opposite of
      # what declaring a passphrase asks for. Since 1.1.0 it REFUSES. The
      # `:?` form fails in compose before the container ever starts.
      UNDERCROFT_PASSPHRASE: ${TENANT_PASSPHRASE:?set TENANT_PASSPHRASE}
      UNDERCROFT_MCP_HTTP_TOKEN: ${PALACE_BEARER}
      # Compose interpolates an UNSET shell variable to the empty string, and
      # the variable is then SET in the container. Since 1.1.0 an empty (or
      # whitespace-only) assertion secret REFUSES to start rather than
      # silently running with per-vault assertions disabled — which is what
      # this recipe used to produce. Use `${ASSERTION_SECRET:?set it}` to
      # fail in compose instead, or unset the line entirely to run without
      # assertions deliberately. `undercroft config check` catches it too.
      UNDERCROFT_ASSERTION_SECRET: ${ASSERTION_SECRET:?set ASSERTION_SECRET}
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
