# Remote team server

Share one palace with a team over MCP HTTP:

```bash
cp deploy/server.env.example deploy/.env    # set UNDERCROFT_MCP_HTTP_TOKEN
docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env up -d
```

The first start runs `undercroft init` before it serves, which sets up the
master key and creates a **sealed** `default` vault on the `undercroft-data`
volume; later starts find that vault and serve it. Until 1.6.0 the recipe
served without `init`, so a fresh volume exited `vault "default" not found` and
restarted forever. For another level, create the vault before the first `up`:

```bash
docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env \
  run --rm --no-deps --entrypoint undercroft undercroft init --level hmac-only
```

`UNDERCROFT_PASSPHRASE` in `deploy/.env` derives the master key instead of
writing a key file. Set it before the first start and keep it set. Until 1.6.0
the recipe did not pass it to the container, so a declared passphrase was
ignored. A passphrase declared later, over a volume first started without one,
is refused before anything is written (exit 1, naming both key files; ROADMAP
O204) — move such a volume to a passphrase by exporting into a new one.

Check the running server's declarations:

```bash
docker compose -f deploy/docker-compose.server.yml exec undercroft undercroft config check
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
  Start the server writable once first: `init` writes only the vault's
  manifest, and a read-only server refuses a vault whose database the first
  writable open has not created yet.
- `/healthz` is unauthenticated for probes.
- Plain HTTP: terminate TLS in a reverse proxy for anything beyond a
  trusted network.
- Backing store: the `undercroft-data` volume is the system of record. MCP and
  `/v1` recall search the vault directly and never consult Qdrant.

Systemd alternative: `deploy/undercroft-server.service`. It does not run
`init` yet, so run it once before enabling the unit, as the unit's user, with
the unit's data directory and environment file — otherwise `init` creates a
different installation, or one keyed differently from the one the unit opens:

```bash
sudo systemd-run --wait --pipe --uid=undercroft --gid=undercroft \
  -p EnvironmentFile=/etc/undercroft/server.env \
  -E UNDERCROFT_HOME=/var/lib/undercroft \
  /usr/local/bin/undercroft init
```

`systemd-run` reads the environment file as root, as the unit does; the file
is root-owned `0600`, so `sudo -u undercroft` could not source it.

ROADMAP O200 tracks running it from the unit.

## The optional Qdrant mirror

The recipe also runs Qdrant, behind its own TLS terminator (`qdrant-tls`).
Nothing is sent to it until an operator pushes, and only
`undercroft search --backend qdrant` reads it:

```bash
docker compose -f deploy/docker-compose.server.yml exec undercroft undercroft index push qdrant
docker compose -f deploy/docker-compose.server.yml exec undercroft undercroft index status qdrant
docker compose -f deploy/docker-compose.server.yml exec undercroft undercroft search "query" --backend qdrant
```

- **What Qdrant receives:** each drawer's id and at-rest content (sealed on a
  sealed vault), its decrypted embedding, and its wing and room labels in the
  clear. An embedding is derived from the plaintext. An hmac-only vault's
  push is refused unless `index push --allow-plaintext`, because its at-rest
  content is the plaintext.
- **What comes back:** candidate ids only. Each one is re-loaded from the
  vault, HMAC-verified and filtered by the vault's own retrieval policy before
  it is returned.
- **Every push appends an `egress/index-push` audit record**, a partly failed
  one included.
- **It is a snapshot.** A later save is not mirrored until the next push, and
  a delete reaches Qdrant only through `forget` naming a backend.
- **Transport:** the engine refuses cleartext http to any non-loopback host,
  with no override, because the embeddings are plaintext-derived. So it
  reaches Qdrant at `https://qdrant-tls` and pins the terminator's internal CA
  with `UNDERCROFT_INDEX_CA`. The `qdrant-tls-export` one-shot copies that
  public root to `/tls/root.crt`, where the engine's uid can read it; the CA
  private key stays where it is. Until 1.6.0 the recipe declared
  `http://qdrant:6333`, which the engine refused on every index call.
- **Residuals:** the hop from `qdrant-tls` to `qdrant` is cleartext on the
  compose network; Qdrant accepts unauthenticated requests from anything on
  that network; and the engine reads the pin once per process, so a pin that
  becomes unreadable is not noticed until a restart. `/healthz` answers 200
  either way, because serving builds no index.

## Multi-tenant REST surface (`/v1`)

`serve-http` also exposes a versioned REST API in the same process, behind
the same bearer, for programmatic (non-MCP) callers and for orchestration
platforms that use one **vault per tenant**. One palace per process stays
the model — tenancy is vaults, not palaces.

**All 58 routes**, counted against `route()` in
`crates/undercroft-cli/src/tenant.rs` rather than remembered — and the LIST is
GATED now (ROADMAP O45), because "rather than remembered" was exactly what
happened: this list said 35 and omitted
`POST /v1/vaults/{id}/verify-forgetting` from the day O14 added it, while
`docs/AGENTS.md` §10 carried it correctly. One route added, two route
references, one updated.

**And this number said 36 while the list beside it held 37**, from M17 until
2026-08-21 — `POST …/repair` was added to the list and not to the sentence
above it. The O45 gate compares the two references to `route()` as SETS in
both directions, deliberately, *because a count passes when one route is
swapped for another* — so it was green over a wrong count, correctly and by
design. A number in prose next to a gated list is the un-gated part of a
gated claim, and it is the part that rots. It also listed 18 of them until 2026-08-05,
omitting the whole operator plane
(trust, admission review, retention, forgetting) plus the golden-values
tier. Everything under *operator plane* is deliberately absent from MCP —
an agent must not rule on the queue that exists to contain it, nor assign
the trust class that decides what it may retrieve — **with one exception
since 1.2.0**: `verify-forgetting` is reachable as
`undercroft_check_erasure_receipt`. ROADMAP O68 ruled it a DRIFT rather
than a boundary, because it checks a CALLER-SUPPLIED document and mutates
nothing, so the operator-only reasoning never explained its absence. (MCP's
`undercroft_history` is not a second exception: it is a different,
agent-scoped view of the audit chain with the operator namespaces fenced
out, not the operator-scope `history` route below.)

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
                                         read_only, unhealed, codebooks,
                                         embed_failures — zero vectors this
                                         server's embedder degraded to since
                                         it opened the vault, O122;
                                         rerank_failures + late_failures —
                                         the same for the cross-encoder and
                                         the ColBERT encoder, 0 when the
                                         stage is not attached, O131;
                                         chain_ceiling + chain_over_ceiling —
                                         the height this vault is declared to
                                         stay under (UNDERCROFT_AUDIT_CEILING,
                                         null when undeclared) and the
                                         engine's verdict on it: it REPORTS,
                                         never deletes and never refuses;
                                         chain_replays — full audit-chain
                                         replays by this handle's label
                                         guard, O250;
                                         anchor_lag — committed records the
                                         MAC-verified manifest on disk
                                         trails the database by, null when
                                         it does not verify, alarms on
                                         nothing; anchor_failures — this
                                         handle's post-commit anchors that
                                         failed, either class, O254)
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
POST   /v1/vaults/{id}/drawers/check-duplicate  {text} -> {duplicate, id}
DELETE /v1/vaults/{id}/drawers          ?source=  every drawer from one file
POST   /v1/vaults/{id}/dedup            {apply?} — DRY RUN unless apply:true

── knowledge graph (read-only browse, plus the authority tier) ───────────
GET    /v1/vaults/{id}/kg/stats         (entity/triple/active/closed counts)
GET    /v1/vaults/{id}/kg/entities      ?limit=&offset=              paged entities
GET    /v1/vaults/{id}/kg/query         ?entity=&direction=&as_of=   facts about one entity
GET    /v1/vaults/{id}/kg/timeline      ?entity=                     temporal fact timeline
GET    /v1/vaults/{id}/kg/receipts      receipt verdicts per fact
                                         (verified|source_changed|dangling|tampered);
                                         ?integrity_only=1 answers {ok, checked}
                                         alone — one HMAC per fact and no
                                         drawer reads (8.6 us/fact -> 0.7)
GET    /v1/vaults/{id}/kg/canonical/{key}   the one active approved fact
POST   /v1/vaults/{id}/kg/authority     declare authority_class / review_state
GET    /v1/vaults/{id}/supersessions    drawer supersession links + verdicts
GET    /v1/vaults/{id}/kg/rel            facts by PREDICATE (predicate, as_of?)
GET    /v1/vaults/{id}/index/status      remote mirror vs local counts. A read:
                                        creates nothing, and remote_records is
                                        null when NO mirror exists — which is
                                        not the same as a mirror holding zero
POST   /v1/vaults/{id}/tunnels          connect two wings {from,to,label}
GET    /v1/vaults/{id}/tunnels          list tunnels (wing?)
GET    /v1/vaults/{id}/tunnels/traverse wings reachable from start (start, depth?)
DELETE /v1/vaults/{id}/tunnels/{tid}    remove one tunnel (404 if absent)
GET    /v1/vaults/{id}/tunnels/{tid}/drawers  drawers from the far wing (limit?)

── session context and agent diaries ────────────────────────────────────
GET    /v1/vaults/{id}/wake-up          recent drawers for session start (wing?)
                                         NO identity layer — see AGENTS.md §10
POST   /v1/vaults/{id}/diary            {agent, entry}; 202 if screened away
GET    /v1/vaults/{id}/diary            one agent's entries (agent, limit?)
GET    /v1/vaults/{id}/diary/agents     who has written a diary
GET    /v1/vaults/{id}/closets          the closet index (wing?)
GET    /v1/vaults/{id}/hallways         entity co-occurrence (wing, top?)

── operator plane (mostly never on MCP — verify-forgetting is the one
   exception since 1.2.0/O68, as undercroft_check_erasure_receipt; the
   witness routes are off MCP by the maintainer's ruling, O245) ─────────
POST   /v1/vaults/{id}/backups          snapshot this vault (409 if it fails verify)
GET    /v1/vaults/{id}/backups          this vault's snapshots
POST   /v1/vaults/{id}/backups/restore  {name}; 400 if the backup holds another
                                        vault, 409 while the vault is in use
GET    /v1/vaults/{id}/history          audit chain (subject?, limit?, offset?)
GET    /v1/vaults/{id}/trust            wing trust assignments
POST   /v1/vaults/{id}/trust            assign one (closed vocabulary)
GET    /v1/vaults/{id}/admission        the pending review queue
POST   /v1/vaults/{id}/admission        rule allow | deny (deny is receipted)
GET    /v1/vaults/{id}/retention        policies per wing/room
POST   /v1/vaults/{id}/retention        set one
POST   /v1/vaults/{id}/retention/sweep  enforce; returns a proof receipt
POST   /v1/vaults/{id}/forget           provable destruction + attestation
GET    /v1/vaults/{id}/witness          emit a witness of the audit chain (O245):
                                        rows + an unkeyed digest over their
                                        preserved bytes as the binding, head +
                                        anchor as corroboration; keep it OFF
                                        this machine
POST   /v1/vaults/{id}/witness          check a witness (body) against this
                                        vault: 200 {verdict:"extends", rows_since,
                                        head_corroborated, rotations_since}, or
                                        409 class integrity when rolled back
                                        or naming another vault; a read
POST   /v1/vaults/{id}/verify-forgetting  check an attestation this vault
                                        issued: Verified, or Recorded when a
                                        key rotation has destroyed the replay
                                        key (exit 0 either way); 409 if the
                                        document does not describe this vault

── maintenance / portability ────────────────────────────────────────────
POST   /v1/vaults/{id}/refine           LLM distillation → KG
POST   /v1/vaults/{id}/verify           (HMAC + audit-chain report)
POST   /v1/vaults/{id}/repair           (the REMEDIATION half of verify; a write)
POST   /v1/vaults/{id}/anchor           (tighten the manifest rollback anchor; a write)
POST   /v1/vaults/{id}/rotate           (re-key the vault; sole-writer contract)
GET    /v1/vaults/{id}/export           (decrypted NDJSON: {drawer, vector} per line)
POST   /v1/vaults/{id}/import           (NDJSON body, at most 256 MiB — 413 above, never a prefix; returns {imported, quarantined, new, replaced, unchanged}; 400 on a record naming a row awaiting an admission ruling, 409 if that row fails its HMAC)

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
`export → verified import → drop`. Verify against what the destination
HOLDS, not against the import reply: `imported` counts records PROCESSED,
and the write is an upsert, so two records landing on one row count two.
Before dropping the source, compare the destination's `GET …/stats`
`records` with the drawer count the export's leading manifest line declares
(`undercroft_manifest.counts.drawers`), and with the source's own `records`
while nothing writes to it — the judgement `undercroft-orchestrator
migrate` makes (ROADMAP O140).

`level` is `sealed` (default) or `hmac-only`. `embedder` is `hash`
(default) or `external:<name>@<dim>` (see below).

**`--read-only`, precisely.** It is a posture on the whole process, not a
filter on one port, and the gate sits **in front of dispatch** rather than
at the top of each mutating handler — because the per-handler version had
thirteen guards for fourteen mutating routes and `POST …/kg/authority`
never got one. It **fails closed**: every `GET` is served, and every
non-GET is refused with 403 *unless it is one of four named reads* —
`POST …/search`, `POST …/verify`, `POST …/verify-forgetting` and
`POST …/witness` (POST for cost or for a caller-supplied document, never
for effect; the fourth arrived with O245).
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
as `unhealed` on `GET /v1/vaults/{id}/stats` beside `read_only` — and since
1.7.0 (ROADMAP O246) a writable server's open reports there, in the past
tense, the anchor heal it performed and how far behind the anchor was. Two
conditions refuse with **409** instead: a manifest whose `vault.db` is
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

**The shape of every 401**, on both binaries: `{"error":"unauthorized"}` with
`Content-Type: application/json` and `WWW-Authenticate: Bearer`. The body
carries no reason and no `class`, which is the contract above; the challenge
header is RFC 9110 §11.6.1's MUST and tells a client only the scheme it
already used. Match on the status, or parse the JSON and read `error` — the
transport gate answered `text/plain` before 1.2.0, so one endpoint used to
return two content types depending on which layer refused you. The
orchestrator's dedicated metrics listener is the one exception and stays
`text/plain`: an error should match the success format of the endpoint being
called, and that one serves Prometheus text.

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
    # `init` first: `serve-http` alone does not create the default vault, and
    # on a fresh volume it exits `vault "default" not found`. `init` exits 0
    # once the vault exists, and `&&` stops on any other failure.
    entrypoint: ["/bin/sh", "-c"]
    command: ["undercroft init && exec undercroft serve-http --host 0.0.0.0 --port 8765"]
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
init`, which the command above runs on every start, derives the
master key via Argon2id (64 MiB, t=3) from the passphrase and a random salt
it persists at `/data/kdf.salt` (`0600`). No key material is written, so the
passphrase must be supplied on every start — no TTY, no prompt, and the key
is never emitted to logs. Provision each tenant's vaults over `/v1/vaults`
once the instance is up.
