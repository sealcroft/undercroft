# Remote team server

Share one palace with a team over MCP HTTP:

```bash
cp deploy/server.env.example deploy/.env    # set UNDERCROFT_MCP_HTTP_TOKEN
docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env up -d
```

Clients:

```bash
claude mcp add --transport http undercroft http://HOST:8765/mcp \
  --header "Authorization: Bearer $UNDERCROFT_MCP_HTTP_TOKEN"
```

- The server refuses non-loopback binds without the token.
- `--read-only` exposes recall without write access (see the compose file).
- `/healthz` is unauthenticated for probes.
- Plain HTTP: terminate TLS in a reverse proxy for anything beyond a
  trusted network.
- Backing store: the palace volume is the system of record; Qdrant only
  ever receives sealed content + embeddings.

Systemd alternative: `deploy/undercroft-server.service`.
