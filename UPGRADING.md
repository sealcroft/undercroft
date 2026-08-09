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
