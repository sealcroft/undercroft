# Upgrading Undercroft

Every change that can stop a deployment which worked before is listed here,
with its symptom, its cause and its fix. Nothing else is: an entry in this
file means *this can prevent your process from starting or your script from
succeeding*, so a short file is the honest one.

## Check before you upgrade

```bash
undercroft config check
```

It runs every `UNDERCROFT_*` declaration in the current environment through
the resolver that runs at start-up, and **opens nothing** — no vault, no
database, no socket, no outbound call. Exit 1 means this environment would
refuse to start; exit 0 means it starts.

**Three declarations do not yet keep that promise**, and it is a gap rather
than the design (ROADMAP **O24**): `UNDERCROFT_ORCH_ADMIN_TOKEN`,
`UNDERCROFT_ORCH_KEY` and `UNDERCROFT_ORCH_RATE_LIMIT` are read by the
control-plane binary and are pre-flighted today by its own command instead.

Run it in a pipeline against the deployment's real environment. That is the
difference between finding out in CI and finding out during a rolling
restart, one node at a time.

**A fleet runs TWO commands, and this one covers the engine.** The control
plane has its own:

```bash
undercroft-orchestrator config check
```

It runs the four `UNDERCROFT_ORCH_*` declarations that binary reads through
the same resolvers its `serve` path runs, opens no state database and binds no
port, and uses the same exit codes. What must not drift is the CLASSIFICATION
of each variable, and that is counted across the two inventories, in both
directions, by a test rather than by anyone remembering.

**Run it because it pre-flights the control plane standalone — not because
the engine's command is supposed to skip those three.** It is not: three of
them are a coverage gap in the engine's command (O24), and closing it does not
retire this one.

Everything that can refuse is pre-flighted by one of the two. Until 1.1.0 the
orchestrator's declarations had no pre-flight at all, and this paragraph said
so (ROADMAP O21).

**There used to be a second limit here and it was too broad**: *"it cannot
check a credential — any string is a well-formed passphrase or token."* That
is true of a WRONG credential and false of an ABSENT or UNUSABLE one, which
are different questions with different answers. A credential's **correctness**
is still uncheckable without decrypting a vault or being refused by a peer.
Its **emptiness** is checkable and is always a failed interpolation; and for a
bearer, so is whether it could ever be presented at all. Both are checked now,
and no variable is exempt from this command for being a credential.

It reports **validated** and **accepted** separately, and the distinction
matters: only some variables have a parse to run. A path, a URL, a token or a
model name is validated by the thing that consumes it, and this command says
so rather than implying it checked them.

---

## 1.1.0

**These are fixes, not contract changes**, and the distinction is worth
stating because it decides what you have to do. None of them removes a
documented value, a route or a surface. Each closes a case where input that
was NEVER valid was accepted and silently ignored — so a deployment that
"worked" was running without a protection it had declared.

What they can do is stop a **misconfigured** deployment at start-up, which is
why every one is listed here and detectable in advance by
`undercroft config check`. If that command exits 0 against your environment,
none of this affects you.

### The OTLP traces endpoint obeys the transport policy — cleartext to a non-loopback collector is refused

**Affects:** `UNDERCROFT_OTLP_ENDPOINT`, on `--features telemetry` builds
only. **This one can stop a deployment that was genuinely working**, so read
it even if the rest of this section does not apply to you.

**Symptom:** the process exits 1 at start-up with
`the OTLP collector is configured with cleartext http to a non-loopback host
(…). Drawer-derived data would cross the network in the clear. … There is no
override.`

**Cause:** the OTLP span exporter was the one outbound client in the
workspace that never went through `undercroft-net`, so it obeyed neither the
cleartext refusal nor CA pinning — while `UNDERCROFT_OTLP_HEADERS` is
documented to carry a bearer token and spans carry vault ids and route
labels. It also had **no TLS backend linked at all**, so an `https://`
collector could not work even if you declared one, and the failure was
swallowed inside the span processor: no traces, no error. Both are fixed
together, which is why the refusal appears now — before, there was no secure
configuration to move to.

**Fix, in order of preference:**

1. Terminate TLS in front of the collector and declare it:
   `UNDERCROFT_OTLP_ENDPOINT=https://collector` plus
   `UNDERCROFT_OTLP_CA=/path/to/root.crt` if it uses a private CA. A declared
   root **replaces** the public roots — that is what pinning means.
   `deploy/observability/tempo-tls/` is a working example, and the shipped
   observability stack was converted to it in this release.
2. Bind the collector to loopback and point at `http://127.0.0.1:4318`.
   Loopback cleartext is allowed, unchanged.
3. Unset `UNDERCROFT_OTLP_ENDPOINT`. Traces stop; metrics and logs are
   unaffected.

**Detectable in advance:** yes. `undercroft config check` runs the same
transport policy the process runs, and now reports this variable as fatal
rather than as an unparsed string. `config check` itself is deliberately
exempt from the start-up refusal — a command whose job is diagnosing an
environment that will not start has to run in one.

**If you ran the shipped observability stack**, `docker compose pull` and
bring it up again: it now includes a `tempo-tls` terminator and the engine
pins its CA. No data migration, no volume change beyond the new
`tempo-tls-data`.

**Why there is no warn-first release, since this is the one entry here that
can stop a deployment that was genuinely working.** Considered and rejected,
with the reasons, so this reads as a ruling rather than an oversight. A
release that warns instead of refusing is a release where the bearer token
this exporter is documented to carry still crosses the network in the clear —
the warning names the harm while continuing to do it, for everyone who does
not read start-up logs. That is worse than a refusal, not gentler. It also
contradicts the configuration doctrine this project already applies
everywhere else: where a declaration turns a protection on, a silent fallback
removes exactly what the operator asked for, so garbage refuses rather than
degrades. And the substitute for a deprecation window already exists and is
better than one — `undercroft config check` runs the same policy the process
runs, opens nothing, and belongs in a pipeline, so the failure lands in CI
rather than one node at a time during a rolling restart.

### An empty `UNDERCROFT_PASSPHRASE` refuses instead of writing a key to disk

**Affects:** `UNDERCROFT_PASSPHRASE`, when it is declared but resolves to an
empty or whitespace-only value.

**Symptom:** the process exits 1 with `UNDERCROFT_PASSPHRASE is set but names
no passphrase …`.

**Cause:** the value was resolved with `.filter(|p| !p.is_empty())`, so an
empty declaration became *no declaration* and the palace fell back to a random
`master.key` on disk. Declaring a passphrase is exactly the request that **no
key material be written to disk**, so the fallback granted the opposite of what
was asked — and said nothing. `vault status` printed the `master.key` path, and
that only reads as wrong if you already suspected it.

The path is not hypothetical: `docs/remote-server.md` shipped
`UNDERCROFT_PASSPHRASE: ${TENANT_PASSPHRASE}`, and Compose interpolates an
unset shell variable to the empty string and then *sets* it in the container.
That recipe now uses the `:?` form so it fails in Compose instead.

**Fix:** set a real passphrase, or unset the variable to use the on-disk master
key deliberately. Whitespace-only is refused too, for the same reason.

**A vault created under the fallback still opens** — it has a real
`master.key` and nothing about it changed. What changes is that the ambiguity
is now refused at start-up rather than resolved silently in the wrong
direction. If that is your deployment, unset the variable and you keep exactly
the behaviour you have.

**The value is not trimmed.** Whitespace decides only whether a passphrase was
*named*; a passphrase that legitimately contains leading or trailing spaces
still reaches Argon2id byte-for-byte, because trimming would change the key and
silently make an existing vault underivable.

**Detectable in advance:** yes — `undercroft config check` now runs this
resolver. It previously could not: the variable was exempt from the pre-flight
on the argument that a passphrase is a credential rather than a syntax, which
is true of a *wrong* passphrase and false of an *absent* one.

### A `UNDERCROFT_ORCH_ADMIN_TOKEN` ending in whitespace refuses instead of 401-ing every admin request

**Affects:** `undercroft-orchestrator serve`, when the admin token has a
trailing space, tab or newline. `$(cat /run/secrets/token)` produces one.

**Symptom:** the process exits 1 with `UNDERCROFT_ORCH_ADMIN_TOKEN ends in
whitespace, and no client could ever present it …`.

**Cause:** the same as the engine's bearer, and it survived here for a
specific reason worth knowing — the only validation was a **16-character
floor**, and a newline has length, so `$(cat …)` cleared it at 27 characters.
The control plane then started cleanly and refused every `/admin` request
forever, because HTTP strips a header value's trailing whitespace and the
bearer that arrives is never the declared one.

**Fix:** `$(tr -d '\n' < /run/secrets/token)`, or a token without trailing
whitespace. Not trimmed for you, for the same reason as the engine's.

**Empty is refused too**, with its own message. It was already refused by the
length floor; what changes is that it says which problem it is.

**Detectable in advance:** yes — `undercroft-orchestrator config check`, which
did not exist before 1.1.0.

### An empty `UNDERCROFT_MCP_HTTP_TOKEN` refuses instead of removing the bearer gate

**Affects:** `UNDERCROFT_MCP_HTTP_TOKEN`, when it is declared but resolves to
an empty or whitespace-only value, on `serve-http`.

**Symptom:** the process exits 1 with `UNDERCROFT_MCP_HTTP_TOKEN is set but
names no token …`.

**Cause:** the same `.filter(|t| !t.is_empty())` as the passphrase above, on a
narrower boundary — which is why it is a separate entry rather than a line in
that one. A **non-loopback** bind with no token already refused outright, so
the network-exposed case was never open. What an empty declaration silently
produced was a **loopback** server on which the operator asked for a bearer
and got none: `/mcp` and `/v1` served any process on the host.

**Fix:** set a real token, or unset the variable to run without one
deliberately. The refusal only fires where a declaration exists.

**If you bind non-loopback, nothing changes for you** except the wording of a
refusal you were already getting. `deploy/docker-compose.server.yml` uses
Compose's `:?` form and fails before the container starts, as before.

**Detectable in advance:** yes.

### A `UNDERCROFT_MCP_HTTP_TOKEN` ending in whitespace refuses instead of 401-ing every client

**Affects:** `UNDERCROFT_MCP_HTTP_TOKEN` with a trailing space, tab or
newline. `UNDERCROFT_MCP_HTTP_TOKEN=$(cat /run/secrets/token)` over a file
ending in a newline is the ordinary way to produce one.

**Symptom:** the process exits 1 with `UNDERCROFT_MCP_HTTP_TOKEN ends in
whitespace, and no client could ever present it …`.

**Cause:** HTTP strips a header field value's trailing whitespace, so the
bearer that ARRIVES is always the trimmed one and never equals the declared
token. The server started cleanly and refused every request forever, with a
401 naming no cause on one side and nothing in the log on the other. Measured
against a live server: leading and internal whitespace answer 200, a trailing
space or newline answers 401.

**Fix:** strip it at the source — `$(tr -d '\n' < /run/secrets/token)` — or
use a token without trailing whitespace. **It is deliberately not trimmed for
you**: that would authenticate a key you did not declare, and a server whose
key silently differs from the file it was configured from is the failure this
whole class is about.

**Leading and internal whitespace are still accepted**, because they are
presentable and therefore values rather than typos. The refusal is exactly as
wide as the defect.

**If your token has no trailing whitespace, nothing changes for you.** If it
does, your server was already unreachable — this tells you why.

**Detectable in advance:** yes.

### An empty `UNDERCROFT_OTLP_ENDPOINT` refuses instead of silently exporting nothing

**Affects:** `UNDERCROFT_OTLP_ENDPOINT` on `--features telemetry` builds, when
it is declared but resolves to an empty or whitespace-only value.

**Symptom:** the process exits 1 with `the OTLP collector is set but names no
endpoint …`.

**Cause:** the exporter read the value through a helper that maps empty to
unset, so a declared collector produced **no traces and no message**. That is
the failure the transport fix in this same release exists to prevent, one case
further along. `undercroft config check` meanwhile handed the empty string
straight to the transport policy, which parses it, fails, and reports an
unparseable URL as CLEARTEXT — so the pre-flight refused the environment while
the process started, and told the operator to configure https for a value that
names no host. Both halves are closed by one resolver both callers now hold.

**Fix:** set a real endpoint, or unset the variable to export nothing
deliberately.

**Detectable in advance:** yes, and with the right diagnosis now rather than a
cleartext one.

### A declaration that turns a protection on now refuses when it does not parse

**Affects:** `UNDERCROFT_TRUST_FLOOR`, `UNDERCROFT_ADMISSION`,
`UNDERCROFT_SEMANTIC_GATE`.

**Symptom:** the process exits at start-up, naming the variable and the legal
values. On `serve-http` this happens before the port is bound.

**Cause:** these used to warn once on stderr and fall back to their default.
The default is *off* for all three, so the fallback removed exactly what was
declared — a below-floor wing answering every query, the write-path screen
not running, semantic-only admission restored on a corpus that had measured
it away.

**Fix:** correct the value, or decline explicitly. Declining is declarable:

```bash
UNDERCROFT_TRUST_FLOOR=off        # or quarantined | standard | trusted
UNDERCROFT_ADMISSION=off          # or quarantine
UNDERCROFT_SEMANTIC_GATE=off      # or a number in 0.0..=1.0
```

Values are trimmed now, so a trailing newline from `$(cat …)` or a YAML block
scalar no longer changes the meaning. That silent case is part of what this
change closes.

### An assertion secret that names no secret is refused

**Affects:** `UNDERCROFT_ASSERTION_SECRET` on `undercroft serve-http` and
`undercroft assert-header`; the `assertion_secret` argument to
`undercroft-orchestrator instance-add` and `POST /admin/instances`.

**Symptom:** the process exits at start-up naming the variable, or the
registration answers HTTP 400. On `serve-http` this happens before the port
is bound. `undercroft config check` reports it too, which it previously did
not.

**Cause:** the value was resolved with `!s.is_empty()`, which failed in two
opposite directions from one line. An **empty** value became "no secret
declared", so every `/v1` assertion gate and the `POST /mcp` transport gate
turned into a no-op — silently, because the start-up banner does not say
"assertions off", it merely omits the clause saying they are on. A
**whitespace-only** value is not empty, so it was accepted as a real secret:
assertions enforced, banner truthfully saying so, key one guessable byte.

The empty case is reachable from the compose recipe in
`docs/remote-server.md`, which ships `UNDERCROFT_ASSERTION_SECRET:
${ASSERTION_SECRET}` — an unset shell variable interpolates to the empty
string, and the variable IS then set in the container.

**Fix:** set a real secret, or **unset the variable** to run without
assertions. Unset is still not a declaration and still means assertions off,
so a single-tenant deployment that never declared one is unaffected.

```bash
UNDERCROFT_ASSERTION_SECRET=<a real secret>   # or unset it entirely
```

**The value is deliberately not trimmed.** Unlike the closed-vocabulary
variables above, a secret is opaque payload: trimming would change the key
and silently invalidate every header already minted. Only a value that is
*entirely* whitespace is refused.

### A cleartext engine URL is refused at registration

**Affects:** `undercroft-orchestrator instance-add`, `POST /admin/instances`.

**Symptom:** HTTP 400, or a non-zero exit, with the transport policy's
message.

**Cause:** registration is the moment this crate is allowed to refuse. It
used to accept the URL and refuse at the first outbound request instead —
which arrives on a tenant's behalf, long after the operator who typed it has
gone.

**Fix:** use `https://`, or bind the engine to loopback. Instance rows stored
before the upgrade keep routing (nothing re-checks stored rows), but
re-registering one — which is how you update an instance's URL or
credentials, since `instance-add` is an upsert — will fail until the URL is
corrected.

### `instance-remove` of an unknown name exits non-zero

**Affects:** `undercroft-orchestrator instance-remove <name>`.

**Symptom:** exit 1 with `no instance "<name>"` where it previously printed
`not found` and exited 0.

**Cause:** `DELETE /admin/instances/{name}` already answered 404. Two doors
gave opposite answers to one call, and a decommission script reading the exit
code saw a no-op as done.

**Fix:** if your script removes unconditionally, tolerate the failure:

```bash
undercroft-orchestrator instance-remove old-engine || true
```

### Usage errors now exit 1 rather than 2

**Affects:** both binaries, any invalid command line.

**Symptom:** a typo or a renamed flag exits 1 where it previously exited 2.

**Cause:** exit 2 is this project's integrity verdict, on every command. A
usage error sharing that code meant a typo reached a compliance script as a
tamper verdict. `--help` and `--version` still exit 0.

**Fix:** none needed unless a script treated exit 2 as "bad arguments" — that
distinction now works the way the documentation always said it did.

---

## Anything not listed here

A release changes no documented contract without a major version. Stricter
validation of input that was never valid is a fix and appears above, in the
same unit as the change, with a way to detect it before you restart —
that obligation is what this file exists for.
