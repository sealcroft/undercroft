# Security model

## Goals

Protect memories **at rest** against disk theft, cross-vault bleed, and
offline tampering of the database or manifest. Detect (not just resist)
modification: every read verifies, `verify` audits everything.

## Mechanisms

- **Master key**: 32-byte key file (0600) or Argon2id(passphrase, salt),
  64 MiB / t=3. Keys zeroized on drop; never logged.
- **Per-vault keys**: `HKDF-SHA256(master, vault_salt, "undercroft.v1/vault/<id>/<label>")`
  for enc / mac / manifest / sample labels. The fourth keys the PQ
  training-sample rank and is deliberately rotation-sensitive, because
  nothing holds a durable reference to it. Vaults never share working keys.
- **Compression**: sealed content is zstd-compressed *before* encryption
  (compress-then-encrypt; the reverse leaks nothing but gains nothing).
  Note the standard caveat: at-rest sizes correlate weakly with content
  compressibility.
- **Sealing**: XChaCha20-Poly1305, random 24-byte nonce, AAD binds
  `vault_id + record_id` — ciphertext cannot be replayed across vaults or
  record slots. Sealed vaults encrypt content *and* embeddings; nothing
  content-derived is written to disk in plaintext (no FTS index either).
  hmac-only vaults — which store plaintext by choice — keep an FTS5 BM25
  prefilter index. Like embeddings, it is derived data outside the HMAC
  envelope: tampering with it can hide records from *search* (an
  availability attack, self-healed by an index rebuild) but can never
  forge a record, since every returned row still verifies its HMAC.
- **Integrity**: HMAC-SHA256 per record (independent key) over
  id + metadata + at-rest content; append-only audit table; chain head
  `h_i = HMAC(mac, h_{i-1} || tag_i)` stored in a MAC'd manifest. Deletions
  log keyed tombstones. KG triples and tunnels carry tags too.
- **Duplicate detection** uses keyed fingerprints (truncated HMAC), so
  stored fingerprints reveal nothing offline.

What one record goes through, at rest and on read:

```mermaid
flowchart LR
    subgraph write["write (sealed vault)"]
        c["content"] --> z["zstd compress<br/><i>own frame, no shared dictionary</i>"] --> e["XChaCha20-Poly1305<br/><i>AAD: vault id + record id</i>"]
        e --> h["HMAC-SHA256 tag<br/><i>id ␟ meta_at_rest ␟ sealed bytes</i>"]
        e --> row["SQLite row"]
        h --> row
        row --> chain["audit row + chain head<br/><i>same transaction</i>"]
    end
    subgraph read["read"]
        row2["row"] --> v{"HMAC verifies?"}
        v -- yes --> d["decrypt → verbatim content"]
        v -- no --> alarm["Integrity error<br/><i>never partial data</i>"]
    end
```

The audit chain reconciles at every open — a crash is never a false
alarm, a rollback always is one:

```mermaid
stateDiagram-v2
    [*] --> Compare: open — verify the manifest MAC,<br/>compare its anchor vs the chain_meta head
    Compare --> Unseeded: no chain_meta head yet<br/>(first open) — seeded, then Current
    Compare --> Current: anchor == db head<br/>(no replay needed)
    Compare --> Replay: anchor ≠ db head —<br/>replay every audit tag
    Replay --> Healed: anchor appears earlier<br/>in the replayed chain
    Replay --> ChainBroken: replayed chain ≠ db head —<br/>audit rows were edited
    Replay --> Tampered: anchor never appears<br/>in the replayed chain
    Healed --> Current: crash artifact — reported as<br/>anchor_at_open, re-anchored on a writable open
    Unseeded --> Current
    ChainBroken --> [*]: Integrity("audit-chain head")
    Tampered --> [*]: ManifestTampered —<br/>rollback or fork detected
    Current --> [*]
```
- **Durability backs the reconciliation story**: the store pins SQLite to
  WAL + `synchronous=FULL`, so a data+chain commit is on disk before its
  manifest anchor can be — a power loss leaves the anchor equal or behind
  (the healed crash case), never ahead (the alarm case). The anchor itself
  is written durably (fsync before the atomic rename, directory synced
  after), and key material is fsynced at creation.
- **Key rotation** (`undercroft vault rotate <name>`): the vault gets a
  fresh salt ⇒ fresh enc/mac/manifest keys; every sealed blob is
  re-encrypted byte-exact at the seal layer (AAD domains preserved) and
  every integrity tag, keyed fingerprint, and the audit chain re-keyed —
  all in **one transaction**, with a two-phase manifest swap
  (`vault.json.next` staged durably, promoted only after the commit; a
  `keycheck` marker in the database tells a crashed rotation's reopen
  which side committed). A crash at any moment leaves the vault openable
  under exactly one key generation. Audit tags of superseded content are
  preserved verbatim (their plaintext is gone by design); the chain over
  them is what rotates. Remote-index copies hold old-key ciphertext
  afterwards — re-run `index push`.
- **Encrypted export bundles** (`undercroft export --to <recipient>`): a
  backup or migration file never exists in plaintext. Since C3.4 the
  recipient identity is **hybrid post-quantum** — X25519 **and**
  ML-KEM-768, both halves in one `pq1`-prefixed string from `bundle
  keygen`. A v2 bundle derives its file key from **both** shared secrets
  (HKDF ikm = `DH(eph, recipient_x) ‖ kem_shared`, with the magic, the
  ephemeral key and the KEM ciphertext all bound as AAD), which is what
  closes harvest-now-decrypt-later on the one asymmetric exchange in the
  codebase. Legacy bare-hex X25519 identities still parse and still
  receive v1 bundles (age-style ephemeral-static ECDH → HKDF-SHA256 →
  XChaCha20-Poly1305, header as AAD), and a hybrid identity opens an old
  v1 backup with its curve half — but **nothing downgrades silently**: a
  hybrid recipient never gets a v1 bundle, and an X25519-only secret
  handed a v2 bundle gets a typed refusal, pinned by test. A bundle alone
  reveals nothing without the identity key, and the identity key is
  unrelated to the palace's own at-rest keys. `import --identity
  <keyfile>` opens it. Full posture and compatibility matrix: [PQ.md](https://sealcroft.com/undercroft/docs/pq.html).
- **Signed manifests** beside the recipient flow: encryption says who may
  *read* a bundle, an Ed25519 sender attestation (`bundle sign-keygen`,
  `export --sign`) says who *wrote* it — scope, trust claim, expiry,
  counts, provenance, and a payload digest that is checked
  unconditionally. Pin the sender with `import --sender <hex>`. A
  sender-declared trust label is a **claim, never a boundary**
  ([LABELS.md](https://sealcroft.com/undercroft/docs/labels.html)); legacy payloads import unattested and say so.
- **Remote indexes** receive sealed bytes + plaintext embeddings only;
  results are re-verified locally. See the trade-off note in the README.
- **HTTP server**: refuses non-loopback binds without a bearer token.
  `--read-only` is a **posture on the whole process**, and it refuses at
  the **call**, not in the catalogue — `tools/list` still advertises every
  tool, and a mutating one answers `server is read-only: <name> is not
  allowed`. (This line used to say it "strips all mutating tools"; it does
  not, and a client that filters its own UI off the catalogue would show
  buttons that cannot fire.) On `/v1` the gate sits in front of dispatch
  and **fails closed**: every non-GET is refused unless named, and the two
  named reads are `POST …/search` and `POST …/verify`. **The open is
  covered too since 1.0.0** (ROADMAP R4): this line used to say the open
  itself writes — schema creation, chain init, and a rotation reconcile
  that could promote or delete a staged `vault.json.next`. The connection
  is now `SQLITE_OPEN_READ_ONLY` under `PRAGMA query_only=ON`, the schema
  is checked rather than created, a lagging anchor is reported rather than
  healed, and a staged rotation is left on disk; what was declined is
  readable as `unhealed` on every stats surface. An absent `palace.db`
  under a present manifest and an unmigrated schema both refuse with 409
  rather than being papered over. Residue: SQLite's WAL scaffolding
  (`-shm`, a zero-length `-wal`) is still materialised where the directory
  is writable, so if you need a byte-frozen vault, stop the server rather
  than restarting it read-only, and take the incident runbook's step-1 copy.

## Server auth model (two layers)

The HTTP server distinguishes *reaching the server* from *addressing a
tenant*:

1. **Palace-wide bearer** (`UNDERCROFT_MCP_HTTP_TOKEN`) — mandatory for any
   non-loopback bind, gates every authenticated route (MCP and REST).
   Proves the caller reached the right server; it does not distinguish
   vaults, so on its own whoever holds it can address every vault.
   Since 1.1.0 a declaration that **names no token** refuses to start rather
   than silently serving without a gate (which on a loopback bind meant every
   process on the host), and so does one ending in **whitespace** — HTTP
   strips a header value's trailing whitespace, so such a token can never be
   presented and the server would refuse every client forever with an
   unexplained 401. Neither is trimmed for you: that would authenticate a key
   you did not declare.
2. **Per-vault assertion** (`UNDERCROFT_ASSERTION_SECRET`, optional — but a
   declaration that names no secret **refuses to start** since 1.1.0, rather
   than silently disabling this whole layer; unset it to decline it) — when
   set, every `/v1` request **and every `POST /mcp` call** must carry
   `X-Vault-Assertion: <ts>:<HMAC-SHA256(secret, "<ts>|<vault_id>")>` for
   the exact vault it addresses. The vault id is bound into the MAC, so an
   assertion for vault A cannot authorize vault B; timestamps outside ±120s
   are refused; comparison is constant-time. The caller platform authorizes
   its user and mints the assertion, and the engine verifies independently
   — a compromised caller component without the secret gets nothing. This
   is what makes a multi-tenant host (vault = customer) safe: the engine,
   not the caller, enforces per-tenant access on every request. Failures
   return a bare 401; the reason is logged server-side, never returned (it
   would leak vault existence or how close a forgery got).

```mermaid
flowchart TB
    req["request to /v1/vaults/{id}/…"] --> t{"UNDERCROFT_MCP_HTTP_TOKEN<br/>declared?"}
    t -- "no — loopback only;<br/>any other bind refuses to start" --> a
    t -- yes --> b{"palace bearer<br/>matches, constant-time?"}
    b -- no --> r401a["401"]
    b -- yes --> a{"assertion secret<br/>configured?"}
    a -- no --> serve["serve<br/><i>single-operator mode</i>"]
    a -- yes --> m{"X-Vault-Assertion:<br/>ts within ±120 s AND<br/>HMAC(secret, ts pipe vault-id)<br/>matches, constant-time?"}
    m -- no --> r401b["401 — bare, reason<br/>only logged server-side"]
    m -- yes --> serve2["serve <b>this vault only</b><br/><i>the id is inside the MAC</i>"]
```

Fusion and external-embedding vaults do not change any of this: search only
re-ranks already-HMAC-verified candidates, and caller-supplied vectors are
sealed exactly like internally-computed ones.

## Non-goals

An attacker reading process memory while a vault is unlocked; a compromised
host OS; traffic analysis of remote-index queries; embedding-inversion
resistance for vectors pushed to remote indexes (documented, opt-in).

## Levels

`sealed` (default): everything above. `hmac-only`: plaintext content with
full integrity tagging + chain — for vaults where grep-ability outweighs
confidentiality.
