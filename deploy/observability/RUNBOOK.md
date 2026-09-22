# Tamper runbook (operator quick-reference)

Full version, published: **https://sealcroft.com/undercroft/docs/runbook.html**
(this is what the `PalaceTamperDetected` alert's `runbook_url` links to).

`PalaceTamperDetected` fired (or `undercroft verify` shows `hmac failures > 0`, or
the Palace Monitor beacon lit) → a stored record failed its HMAC on read. Treat
as on-disk tampering until proven otherwise.

**1. Where** — the alert's `surface` label (`drawer`/`kg`/`tunnel`/`manifest`)
says which artifact class failed, and its `instance` label says which process.
Grafana “Tamper by surface” + Logs panels show the same.

There is **no `vault` label on this alert**: the integrity counter is emitted
with `surface` alone. (`AuditChainHeightHigh` does carry one — it is an
unaggregated gauge, and gauges have always been per-vault. This sentence read
"or any other" until ROADMAP O250 added that rule.) This page told a responder to
localize by one, which is the same belief that produced the fleet-wide
inhibition defect — `alertmanager.yml` scoped its silencing with
`equal: ["vault"]`, and a label absent from both sides counts as equal, so
one tamper alert muted every warning in the fleet. The configs were fixed;
this sentence was not. To localize by vault, use the live event stream (telemetry
builds) — the Palace Monitor at `/monitor`, or `GET /v1/vaults/{id}/stream`: its `hmac-fail`
frame names the vault and the failing row's CLAIMED id, wing and room, marked
`unverified` because they are what the altered row says about itself. The
stream is live only, so it names a failure only to a subscriber connected when
it happened. Otherwise run step 2's `verify` per vault (or
`POST /v1/vaults/{id}/verify`). Neither the integrity log line nor the per-vault
gauges help: the log names only the surface, and the gauges carry counts rather
than failures and are hidden from `/metrics` when per-vault assertions are
declared.

**2. Confirm** — name the exact record:
```bash
undercroft verify --vault <vault>      # -> "TAMPERED: <id>", "audit chain: ok" (content edits do not move the chain)
```

**3. Mitigate** — freeze writes and preserve evidence before touching anything:
```bash
undercroft serve-http --read-only …
cp -a "$UNDERCROFT_HOME/vaults/<vault>" "/tmp/<vault>.evidence.$(date +%s)"
```

**4. Fix** — verbatim restore from a known-good backup, then re-verify:
```bash
undercroft backup list
undercroft backup restore <backup-name>   # one positional; --force to overwrite
undercroft verify --vault <vault>      # must be 0 failures, chain ok
undercroft repair --vault <vault>      # backfill fingerprints, re-embed every drawer + drop PQ/IVF (a served embedder receives the corpus), vacuum, re-verify
```

**5. Prevent** — scheduled `backup`s, `0700` on the vault directory, `0600` on `master.key`,
OS file-integrity monitoring on the vault dir, keep alerting on, per-vault
assertions for multi-tenant.

The alarm only ever fires on a real HMAC-verify failure — there are no synthetic
tamper alarms anywhere in the system.
