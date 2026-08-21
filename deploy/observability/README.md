# Undercroft observability stack (metrics · logs · traces · alerting)

A self-contained local stack that runs a telemetry-enabled Undercroft server
and gives it the full operability picture: **metrics** (Prometheus), **logs**
(Loki), **distributed traces** (Tempo), and **alerting** (Alertmanager) — all
rendered in **Grafana**, with server-side PNG export via a Grafana image
renderer. Everything Undercroft emits is **metadata and counts only** — never
drawer content or key material.

```bash
cd deploy/observability
docker compose -f docker-compose.observability.yml up --build
```

Grafana is at `http://localhost:3000` (anonymous viewer; the **Undercroft —
Palace** dashboard, uid `undercroft-palace`, is provisioned), Prometheus at
`:9090`, Alertmanager at `:9093`, Loki at `:3100`, Tempo at `:3200` and the
engine at `:8765`.

**If any of those ports is already taken** — a second observability stack on
the same host is common — remap with an override file rather than editing
this one, and note that Compose **merges** `ports:` lists, so a plain
override *appends* and the collision survives silently:

```yaml
# ports.override.yml — `!override` replaces; without it, both bindings exist
services:
  grafana:    { ports: !override ["13000:3000"] }
  prometheus: { ports: !override ["19090:9090"] }
```

**Two headline panels are blank on an idle deployment, by design.**
`undercroft_drawers` and `undercroft_audit_chain_height` are set by the
sampler, which runs only for vaults with an active stream subscriber, and by
`GET /v1/vaults/{id}/stats`. Touch either and they populate; until then
Prometheus has no series for them and those panels render empty. That costs
nothing when no dashboard is connected, which is the point — but it reads as
a broken dashboard the first time you see it.

**Why there is a `tls-export` service.** The engine pins Caddy's CA for the
OTLP hop, and Caddy writes its whole PKI as root (cert `0600`, directories
`0700`) because that tree holds the CA private key. The engine runs as uid
10001, so a pin aimed inside that tree is unreadable and the engine **refuses
to start** — it never falls back to the public roots, since a pin that
silently un-pins is the failure mode. `tls-export` copies the PUBLIC root to
`/tls/root.crt` at `0644` and the engine pins that; the private key never
moves. It also waits for the file, which closes a race `depends_on` alone
does not: that only waits for the container to start, not for Caddy to have
generated anything.

```
undercroft (telemetry) ──/metrics──▶ Prometheus ──rules──▶ Alertmanager ──▶ alert-sink
          │  │                          │                                    (webhook)
          │  └──JSON logs──▶ promtail ──▶ Loki ──┐
          └──OTLP traces────────────────▶ Tempo ─┤
                                                 └──▶ Grafana (+ image-renderer)
```

| Service | URL | What |
|---|---|---|
| **Grafana** | http://localhost:3000 | Dashboard **“Undercroft — Palace”** (metrics + logs + traces + active alerts). Anonymous viewer is on; admin is `admin`/`admin` unless you set `GRAFANA_ADMIN_PASSWORD`. Embedding is enabled (`GF_SECURITY_ALLOW_EMBEDDING`) so the engine’s vault admin console (`GET /ui` → GRAFANA tab) can iframe the dashboard directly, and the anonymous viewer may open Explore (`GF_USERS_VIEWERS_CAN_EDIT`) so trace/log drill-downs from the panels work without logging in. |
| **Prometheus** | http://localhost:9090 | Metrics + the **Alerts** tab (rule state). |
| **Alertmanager** | http://localhost:9093 | Routed/firing alerts. |
| **Loki** | http://localhost:3100 | Log store (query via Grafana). |
| **Tempo** | http://localhost:3200 | Trace store (query via Grafana). |
| **Palace Monitor** | http://localhost:8765/monitor | The pixel-art live view — enter the demo token, pick a vault, watch it work. |

## How it fits together

- The `undercroft` image is built with the `telemetry` feature
  (`UNDERCROFT_FEATURES=telemetry`) and started with `UNDERCROFT_METRICS=1`
  (`/metrics` on), `UNDERCROFT_LOG_FORMAT=json` (structured logs promtail ships
  to Loki), and `UNDERCROFT_OTLP_ENDPOINT=https://tempo-tls` (traces to Tempo
  through the bundled TLS terminator — the engine refuses cleartext http to a
  non-loopback host, with no override, and pins Caddy's internal CA root via
  `UNDERCROFT_OTLP_CA` off the shared `tempo-tls-data` volume).
- `/metrics` is bearer-gated; Prometheus authenticates with the same token
  (`prometheus.yml`).
- Prometheus evaluates `alerts.yml` and pushes firing alerts to Alertmanager,
  which routes them to **`alert-sink`** — a tiny webhook receiver that logs
  every delivered alert to stdout (`docker compose logs -f alert-sink`), so the
  whole path is visible without external creds. Swap in Slack/email in
  `alertmanager/alertmanager.yml`.

## Alerts

Defined in `alerts.yml`:

| Alert | Severity | Fires when |
|---|---|---|
| **PalaceTamperDetected** | critical | any `undercroft_hmac_verify_failures_total` increase — a record/KG/tunnel/manifest failed its integrity tag on read. The `surface` label says where. |
| **AuditChainStalled** | warning | writes are landing but the audit chain isn't advancing (10m). |
| **UndercroftDown** | critical | the `/metrics` target is unscrapable (1m). |
| **HighSearchLatencyP95** | warning | search p95 > 500ms (10m). |
| **HttpServerErrors** | warning | any HTTP 5xx (5m). |
| **AuthRejectionsSpike** | warning | elevated bearer/assertion rejections (10m). |

A firing tamper alert links to the [**runbook**](RUNBOOK.md) (published at
`/docs/runbook.html`) — where it happened, and how to confirm, mitigate, fix,
and prevent it.

**Every rule is aggregated `by (instance)`, and the inhibition depends on it.**
Alertmanager silences warnings while a critical is firing on the *same*
instance, scoping that with `equal: ["instance"]`. A label absent from both the
source and the target counts as **equal**, so an `equal:` naming a label no
rule emits does not narrow the inhibition — it makes it global. This config
equalled on `vault`, which nothing emitted, so one PalaceTamperDetected
anywhere muted every warning in the fleet, and the only symptom was an alert
that never arrived. If you add a rule, keep `instance` (a bare `sum()` drops
it) and give it a block in `alerts_test.yml`; `docker compose run --rm
obs-config` runs `promtool test rules` over that file, asserts the exact label
set each rule emits, and fails if the `equal:` labels are not among them.

## Generating some data

```bash
TOKEN=undercroft-observability-demo-token
# create a vault + save a drawer over the /v1 REST surface
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"id":"demo","level":"hmac-only"}' http://localhost:8765/v1/vaults
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"text":"We chose XChaCha20 for sealing","wing":"security","room":"decisions"}' \
  http://localhost:8765/v1/vaults/demo/drawers
```

## Demonstrating a tamper alert

Corrupt one drawer's bytes on disk, then read it — the HMAC check fails, the
metric increments, and `PalaceTamperDetected` fires within a scrape interval:

```bash
# rewrite a drawer's content column directly in the vault DB (bypassing the HMAC)
docker compose exec undercroft sh -c \
  "sqlite3 /data/vaults/demo/palace.db \"UPDATE drawers SET content=x'00' WHERE 1 LIMIT 1\"" \
  || echo "(install sqlite3 in the image, or use the python one-liner in RUNBOOK.md)"
# now search so the record is read + verified → hmac-fail
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"xchacha","limit":5}' http://localhost:8765/v1/vaults/demo/search
# watch it arrive:
docker compose logs -f alert-sink
```

## Security note

`UNDERCROFT_MCP_HTTP_TOKEN` (compose) and the Prometheus scrape credential
(`prometheus.yml`) share **one fixed demo token** for turnkey local use — not a
secret. Loki, Tempo, Alertmanager, and the renderer are unauthenticated, and
promtail mounts the Docker socket read-only. Keep this stack on localhost; for
anything shared, set real secrets, disable Grafana anonymous access, drop the
socket mount for a different log path, and front it all with TLS.
