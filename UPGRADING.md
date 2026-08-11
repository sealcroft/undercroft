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

Run it in a pipeline against the deployment's real environment. That is the
difference between finding out in CI and finding out during a rolling
restart, one node at a time.

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
