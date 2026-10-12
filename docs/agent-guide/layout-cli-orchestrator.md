# Agent guide — the two binaries

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the Layout entries for
`crates/undercroft-cli` (posture, the MCP tools and their read-only gate,
`parity.rs`, `search.rs`, i18n, refine, `/v1` and its management planes,
`--read-only`, the consoles) and `crates/undercroft-orchestrator`. Read it
when your work touches either binary, a surface (CLI, MCP, `/v1`, the
orchestrator, a console), or the parity inventories.

It was moved here unchanged when the guide was split (ROADMAP O433,
2026-10-12), and it governs over any one-line statement of the same rule in
the core. In the moved text, "this file" and "here" mean the guide as a whole
— the core and its reference documents.

The MCP tool count in it is read by the `prose figures` preflight in
`tests/battery.sh`; reword that sentence only together with its row.

---

- `crates/undercroft-cli` — `undercroft` binary (main.rs: CLI, plus `Posture`
  — `open_store_as` makes read-vs-write something a caller must STATE, so
  `serve-http --read-only` opens BOTH its stores read-only; the two opens
  had drifted apart, and which port path opened the vault decided whether
  a `--read-only` server re-embedded every drawer at start-up and appended
  a read-audit record per `/mcp` search; mcp.rs: MCP stdio — **38 tools (incl. `undercroft_history`, the audit chain
  at `HistoryScope::Agent` — fenced by namespace and by the reserved review
  wing, so a diverted write cannot read its own evidence back), 12
  of them writes** (`index_status` was the thirteenth for one day: it ran
  `ensure`, which CREATES the collection it reports on, so it was never a
  read — and `VectorIndex::status` creates on none of the five backends, so
  it went back to `READ_TOOLS` when O83 closed. Non-creation is proved per
  backend by `backends-e2e`, which asks twice, rather than inferred from
  qdrant) — the read-only gate is `READ_TOOLS` and it FAILS
  CLOSED (`refused_when_read_only` = not-a-read), because
  `WRITE_TOOLS.contains(name)` served any tool nobody had classified yet and
  its compensating parity heuristic was blind to `_merge`, `_move`,
  `_import`, `_forget`, `_prune`, `_promote` and `_sweep`; `/v1`'s `mutates`
  decided the same question the safe way round and this copies it.
  `WRITE_TOOLS` survives `#[cfg(test)]` as the other half of the inventory,
  so an advertised tool in NEITHER list fails the build
  + the quarantine fence and the authority fence over raw arguments;
  parity.rs: the surface inventory the code is COUNTED AGAINST in both
  directions — a tool advertised without a line fails the build, a line
  naming a dead tool fails it too; **and every `pub enum *Error` variant
  is counted against its mint sites (O115)**, because `BundleError::Expired`
  was declared, documented under the `missing_docs` lint, and constructed
  nowhere — a lint that requires a sentence about a behaviour cannot tell
  whether the behaviour exists, and the by-eye read that found it finds
  what it happens to look at (that second half was written but never
  RUN: the check went `MCP_TOOLS → WRITE_TOOLS` only, so `WRITE_TOOLS` kept
  naming the removed authority tool and passed), and `OPERATOR_ONLY`
  (admission/trust/retention/forget/rotate/**authority**/anchor/export/
  import/refine — authority because promotion closes
  the previous canonical holder's window, so an agent that could write it
  could make its own fact the one answer `lookup_canonical` returns)
  asserts those never reach MCP,
  so a boundary is enforced by the same mechanism as the parity instead of
  living in a doc table that rots; search.rs: what a search DECLARES and
  what it OWES back, once for all three surfaces — `SearchOptions`, the
  read-time `Locale` and the honest-exclusion notes were rebuilt by hand
  per handler and each forgot a different piece (`week_start` reached only
  `/v1`, `room_cap` only `/v1`, `language` only MCP+`/v1`, `ranked_at`
  only MCP+`/v1`, the trust-floor exclusion count only CLI+`/v1`), and
  `DEFAULT_LIMIT` is now **5 everywhere** (it was 5 on CLI/MCP and 10 on
  `/v1`, so "the same search" answered differently per transport —
  unified DOWN, since every surface names its continuation). **A search can
  take a DATE WINDOW since O108 (2026-09-06)**, three declarations parsed
  once for all three surfaces: `when` narrows to drawers whose covered
  `content_date` falls inside it (a positive narrowing like `room`, undated
  drawers outside every window, a non-date REFUSED), `when_slack_days` widens
  it, and `when_from_query` reads the question through the temporal scanner
  and, where it resolves a day or period, tops the candidate pool up with the
  drawers dated inside it — fenced by the same scope, trust clause and
  `admits` as the pool — and adds a fixed 0.15 term for every candidate whose
  `content_date` or resolved mention falls inside. Off by default and
  byte-identical without a window; the reply says which window ran, from
  the ONE resolver the store applied (`resolve_window`). Measured on LoCoMo
  it covers the two ids it was filed on, reaches 23 never-covered questions
  and loses one. The bench stamps each session's date on its chunks for it;
  before that the harness ingested no dates at all, so no date channel could
  have been measured there;
  i18n.rs: result-string localization for nine languages
  (`UNDERCROFT_LANG` → `LANG`, primary subtag; errors, help and
  machine-oriented output stay English);
  receipt.rs: the ONE place `forget`, `admission deny` and `retention sweep`
  deliver a destruction's receipt (ROADMAP O262) — `--sign` read and parsed
  before the vault is opened, and once the drawers are gone the receipt's
  delivery is attempted before anything else is written: `--out` first and
  durably, stdout through the door's flushed write (O287) as its fallback, and
  a delivery that fails says where the receipt went or that it is lost, because
  its fingerprints are stored nowhere and it can never be minted again;
  refine.rs: the ONE LLM-distillation implementation both `undercroft refine`
  and `POST /v1/…/refine` drive — same `UNDERCROFT_LLM_*` config used to
  build two different vaults, the CLI's facts carrying no date resolved from
  the note's words, no grounding verdict and no searchable mirror;
  http.rs/tenant.rs: HTTP + multi-tenant `/v1` incl. the management and
  operator planes (drawers list/get/update/delete, taxonomy, stats +
  history, read-only kg browse + `kg/authority`, supersessions, trust,
  admission list/rule, retention set/list/sweep, forget,
  **verify-forgetting** (O14 — the plane could MINT an erasure receipt and
  check none, and on a multi-tenant deployment `/v1` is the only door an
  operator has; the verdict is a TYPED field because `verified` and
  `recorded` make different claims, and a document that does not describe
  this vault is 409 + `class: "integrity"`. It is on the orchestrator's
  `OPS_ROUTES` too, or the fleet operator it was filed for still could not
  reach it), refine, verify,
  rotate, export/import). **`--read-only` is a posture on the whole
  process, decided once in FRONT of dispatch** (`mutates`), not a guard
  per mutating handler: there were thirteen guards for fourteen mutating
  routes and `POST …/kg/authority` never got one, so a read-only server
  rewrote HMAC-covered authority columns, superseded the previous
  canonical holder and appended to the chain while answering 200 — while
  the identical capability over `/mcp` in the same process refused. It
  fails CLOSED (anything not GET is a write unless named), and the
  **four** named exceptions are `POST …/search`, `POST …/verify`, `POST …/witness` (ROADMAP O245, the caller's witness travels in a body) and
  `POST …/verify-forgetting` — all POST for cost or for a caller-supplied
  document, never for effect: search reads, verify walks every record's
  HMAC and replays the chain, and verify-forgetting POSTs only because the
  attestation is the CALLER's and has to travel in a body. Failing closed
  means a new read must be NAMED, and the cost of forgetting is a
  read-only server refusing a pure read while the CLI performs it. Verify is a read in the strict sense —
  `&self`, no mutating call — which also means it does **not** tighten the
  manifest anchor: only a store open does (`init_chain`), so the
  read-audit boundary's old "run writes or `verify`" advice was wrong on
  exactly the deployment it was written for, a server that caches its
  handle (A31). **The OPEN is a read too since 2026-08-05 (R4)** — this
  line used to record the opposite as a stated gap, and both halves of it
  are now closed: `open_read_only` takes a `SQLITE_OPEN_READ_ONLY`
  connection under `PRAGMA query_only=ON` (so a write we MISSED fails
  loudly rather than happening quietly), does not create the database,
  does not run `journal_mode=WAL`, creates and alters no table, seeds no
  `chain_meta`, fast-forwards no anchor, rebuilds no FTS index, and does
  not promote or delete a writer's `vault.json.next` — the operation
  A32 called evidence destruction on the incident runbook's own path. It
  **Every one of those claims is about `open_read_only`, and O91 is what
  that scoping costs (2026-09-02): O81 added a `recorded_embedder` call
  ahead of the posture dispatch, so the FIRST thing `--read-only` did was
  open the database read-write — creating it where it was absent, and
  checkpointing away a crashed writer's hot `-wal` where it was present
  (measured, 41,232 bytes to 0, `palace.db` rewritten). Every sentence
  above stayed true and the posture was still violated, because the
  violation was in a call made BEFORE the function they describe. The only
  A33 test called `open_read_only` directly, so it was blind by
  construction and stayed green over the defect. **A posture is a property
  of the PATH, not of the function at the end of it** — ask what runs
  before the function whose contract you are quoting, and gate the path,
  which is why the ten O91 checks drive `open_store_as` and the two
  surfaces rather than the store call. It
  reaches the UNLOCK as well (`unlock_as(Access::ReadOnly)`), because
  unlocking deletes a staging manifest it cannot authenticate and stating
  the posture one call later was already too late. Each of those is
  DETECTED and REPORTED instead, on `VaultStats.unhealed` (all three
  surfaces) and as a warning at open. Two conditions refuse rather than
  report, all 409: an absent `vault.db` under a manifest that records
  history (`DatabaseMissing`, A33 — "empty" is not "absent", and it is an
  integrity verdict, so exit 2, on the writable posture too since O308), a
  manifest that records NO anchored write — what `init` leaves
  (`ReadOnlyNoAnchoredWrite`, exit 1, O213: it was A33's exit 2 on every
  fresh volume) — and a schema a read-only role would have had to migrate
  (`ReadOnlyUnmigrated`, exit 1 — the vault is intact, the posture is simply
  wrong for it). A vault whose writer crashed
  mid-rotation still opens, which is the case that made reporting the
  right rule — **and since O266 it verifies too**: the open adopts the
  staged keys in memory and compares the rows with the STAGED manifest.
  From 1.1.0 (`30c560f`) until O266 it refused as tampering, because
  `anchored_head` MAC-checked the retired `vault.json` under the adopted
  key, and nothing saw it: the A32 test drove the vault and never a store
  open, O91's lesson exactly. The prefilter half (R1) was already closed: a tier loads an
  existing index and never builds one. Residue, stated: a read-only
  connection materialises SQLite's WAL scaffolding (`-shm`, and a
  zero-length `-wal`) when the directory is writable — no database
  content, reconstructible, and the price of reading a WAL database at
  all; where the directory is NOT writable the open escalates to
  `immutable=1` and says so, which is what makes a write-protected mount
  or a snapshot readable (R4's first item, said to be settled by execution —
  the test blocks the `-shm` with a directory rather than with `chmod`,
  because the test container runs as root and permission bits do not bind
  root. **That test does not reach the escalation** (ROADMAP O286, measured by
  O279: a read-only connection whose `-shm` cannot be mapped reads its `-wal`
  without one and serves the ordinary way), so what a write-protected mount
  does is unmeasured; O279's gate forces the escalation another way);
  ui.html: the vault admin console (incl. live MONITOR +
  KNOWLEDGE tabs), `include_str!`'d and served at `GET /ui` on every
  build; monitor.html: the Palace Monitor
  UI, `include_str!`'d and served at `GET /monitor` on telemetry builds);
  integration tests in `tests/cli.rs`, and `tests/model_e2e.rs` — the
  model-backend join (ROADMAP O157), a `required-features` target run BY NAME
  from the `ort-build` leg and nowhere else
- `crates/undercroft-orchestrator` — `undercroft-orchestrator` binary: the
  optional multi-tenant control plane (docs/MULTI_TENANCY.md) — instance
  registry + tenant→vault map in its own SQLite (engine creds sealed,
  tokens stored as HMACs), `/t/*` routing proxy, `/admin/*` plane,
  migration judged against the source vault's own audit-chain snapshot and
  against what the destination HOLDS (O140 — a count is not a version, and
  `imported` counts records processed, not rows kept), **`PATCH
  /admin/tenants/{id}` + `tenant-repoint`** — the re-point O136's refusal and
  `UPGRADING.md` had named since 1.5.2 while it existed on no surface (O149);
  it moves a MAPPING and never data, so the destination is asked whether it
  holds the vault and refused if it cannot answer, fleet console
  (ui.html at `GET /ui`),
  read replicas (`serve --read-replica`: RO state db, data plane only,
  `/healthz` mode+last_write lag surface), and **its own
  `config check`** (`config_check.rs`, O21) — the engine's pre-flight runs
  the ENGINE's resolvers and cannot run another binary's at any price, so a
  fleet runs both. Two properties are load-bearing. Every arm calls the
  resolver `serve` calls, which is what forced `resolve_orch_key` (the hex
  decode was written out twice, in `Orch::open` AND `open_read_only`, neither
  reachable without opening a DATABASE) and `resolve_admin_token` (a length
  floor inline in the `serve` arm) into existence — and that floor was hiding
  a live defect: a trailing newline HAS LENGTH, so `$(cat …)` cleared 16
  characters and produced a control plane that started cleanly and refused
  every `/admin` request forever, HTTP having stripped the trailing
  whitespace from the header the client sent. And `ORCH_ENV_VARS` is counted
  against the CLI's `ENGINE_ENV_VARS` by **reading its source**, name and
  class, both directions — the only route two crates that deliberately do not
  link have. Note that gate's needle must be SPLIT (`concat!`): written
  contiguously it declares a variable called `UNDERCROFT_ORCH_`, the bare
  prefix, which the engine's own env-var inventory gate scans for and
  rejects. One gate's needle is another gate's input.
  **Telemetry since O20**, behind its own `telemetry` feature (a pure `/v1`
  client inherits nothing): four `undercroft_orch_*` counters and a histogram
  for the events no engine can see — a refused tenant token, the rate screen
  firing, a transport refusal that happens before a byte moves, and the
  one-write-becomes-two-calls amplification of the drawer probe. **No
  tenant-shaped label anywhere**, on the per-wing-codebook precedent: an
  identifier whose value set is created BY USE belongs on a query surface, and
  per-tenant figures are already on `/admin/tenants/{id}/stats`. The names are
  `undercroft_orch_`-prefixed because the shipped dashboard aggregates several
  engine series with no `job` filter and the route strings collide exactly.
  **`/metrics` is a SEPARATE listener** (`UNDERCROFT_ORCH_METRICS_ADDR`),
  which is a boundary rather than a drift from the engine: the engine's one
  listener can legitimately be loopback-only, the control plane's cannot be
  because tenants must reach it, so a `/metrics` path there would be
  network-exposed in every real fleet. Loopback needs no token; anything else
  refuses to start without `UNDERCROFT_ORCH_METRICS_TOKEN`.
  Pure `/v1` client; never linked by the engine
