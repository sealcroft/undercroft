# Undercroft observability stack (Prometheus + Grafana)

A self-contained local stack that runs a telemetry-enabled Undercroft
server, scrapes its `/metrics` endpoint with Prometheus, and renders a
pre-provisioned Grafana dashboard.

```bash
cd deploy/observability
docker compose -f docker-compose.observability.yml up --build
```

- **Grafana** → http://localhost:3000 — dashboard **“Undercroft — Palace”**
  (anonymous viewer access is enabled for convenience; admin login is
  `admin` / `admin` unless you set `GRAFANA_ADMIN_PASSWORD`).
- **Prometheus** → http://localhost:9090
- **Palace Monitor** → http://localhost:8765/monitor — the pixel-art live
  view; enter the bearer token (the demo token below), pick a vault, and
  watch the archivist file drawers in real time.

The dashboard shows request rate by route, search rate and p95/p50
latency, drawer writes by outcome (created vs deduped), audit-chain commit
rate, and — front and center — **HMAC verify failures**, the tamper
signal, which turns the stat panel red the moment it goes non-zero.

## How it fits together

- The `undercroft` image is built with the `telemetry` feature via the
  `UNDERCROFT_FEATURES=telemetry` build arg, and started with
  `UNDERCROFT_METRICS=1`, so `/metrics` is live.
- `/metrics` is bearer-gated. Prometheus authenticates with the same token
  (`prometheus.yml` → `authorization.credentials`).

## Generating some data

```bash
TOKEN=undercroft-observability-demo-token
# a search over the single-vault MCP surface
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"undercroft_save","arguments":{"content":"first memory"}}}' \
  http://localhost:8765/mcp
```

## Security note

`UNDERCROFT_MCP_HTTP_TOKEN` (compose) and the Prometheus scrape credential
(`prometheus.yml`) share **one fixed demo token** for turnkey local use.
It is not a secret. For anything beyond localhost: change both to a real
secret (or use Prometheus `authorization.credentials_file`), disable
Grafana anonymous access, and front the whole thing with TLS.
