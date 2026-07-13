# Deploying Undercroft

- `docker-compose.server.yml` — shared team memory server: MCP over HTTP
  (bearer-token auth) backed by Qdrant. Content is sealed client-side inside
  the undercroft container before it ever reaches Qdrant.
- `undercroft-server.service` — the same server as a hardened systemd unit.
- `undercroft-daemon.service` — per-user auto-save daemon (periodic
  `undercroft daemon run` sweep of `~/.claude/projects`).
- `server.env.example` — environment template; copy to `.env` / 
  `/etc/undercroft/server.env` and set the bearer token.

The server refuses a non-loopback bind without `UNDERCROFT_MCP_HTTP_TOKEN`.
Use `--read-only` to expose recall without write access. Always terminate
TLS in front of it for anything beyond a trusted private network.
