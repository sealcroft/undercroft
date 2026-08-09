# Tamper runbook (operator quick-reference)

Full version, published: **https://sealcroft.com/undercroft/docs/runbook.html**
(this is what the `PalaceTamperDetected` alert's `runbook_url` links to).

`PalaceTamperDetected` fired (or `undercroft verify` shows `hmac failures > 0`, or
the Palace Monitor beacon lit) → a stored record failed its HMAC on read. Treat
as on-disk tampering until proven otherwise.

**1. Where** — the alert's `surface` label (`drawer`/`kg`/`tunnel`/`manifest`)
says which artifact class failed, and its `instance` label says which process.
Grafana “Tamper by surface” + Logs panels show the same.

There is **no `vault` label**, on this alert or any other: the integrity
counter is emitted with `surface` alone. This page told a responder to
localize by one, which is the same belief that produced the fleet-wide
inhibition defect — `alertmanager.yml` scoped its silencing with
`equal: ["vault"]`, and a label absent from both sides counts as equal, so
one tamper alert muted every warning in the fleet. The configs were fixed;
this sentence was not. To localize by vault, read the `undercroft_drawers`
or `undercroft_audit_chain_height` gauges, which are per-vault, or the
structured logs.

**2. Confirm** — name the exact record:
```bash
undercroft verify --vault <vault>      # -> "TAMPERED: <id>", "audit chain: BROKEN"
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
undercroft repair --vault <vault>      # backfill fingerprints, vacuum, re-verify
```

**5. Prevent** — scheduled `backup`s, `0600` on the vault dir + `master.key`,
OS file-integrity monitoring on the vault dir, keep alerting on, per-vault
assertions for multi-tenant.

The alarm only ever fires on a real HMAC-verify failure — there are no synthetic
tamper alarms anywhere in the system.
