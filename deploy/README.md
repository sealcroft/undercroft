# Deploying Undercroft

- `docker-compose.server.yml` — shared team memory server: MCP over HTTP
  (bearer-token auth). The first start runs `undercroft init`, which creates
  a sealed `default` vault on the `undercroft-data` volume, and that volume is
  the system of record. It also runs an OPTIONAL Qdrant mirror that nothing
  reads until an operator runs `index push qdrant`; MCP and `/v1` recall
  never consult it. A push sends each drawer's at-rest content (sealed on a
  sealed vault) with its plaintext-derived embedding and its wing and room
  labels, and is recorded in the vault's audit chain. The engine reaches
  Qdrant only over TLS, through `qdrant-tls/`.
- `qdrant-tls/` — the Caddy terminator in front of that Qdrant. The recipe's
  `qdrant-tls-export` one-shot copies Caddy's public CA root to a path the
  engine can read, and the engine pins it with `UNDERCROFT_INDEX_CA`.
- `undercroft-server.service` — the same server as a hardened systemd unit.
  Every start runs `undercroft init` first (`ExecStartPre`), as the unit's
  user with its data directory and environment file, so the first start
  creates a sealed `default` vault and a failed init stops the start with its
  own error in the journal. `RequiresMountsFor=/var/lib/undercroft` keeps that
  init from running before the data directory's mount, which would mint a
  second installation beneath the mount point. For another level, create the
  vault before the first start in that same identity and environment
  (`docs/remote-server.md` has the command).
- `undercroft-daemon.service` — per-user auto-save daemon (periodic
  `undercroft daemon run` sweep of `~/.claude/projects`).
- `server.env.example` — environment template; copy to `.env` / 
  `/etc/undercroft/server.env` and set the bearer token.

The server refuses a non-loopback bind without `UNDERCROFT_MCP_HTTP_TOKEN`.
Use `--read-only` to expose recall without write access, after one writable
start has created the vault's database. Always terminate TLS in front of it
for anything beyond a trusted private network.

`docs/remote-server.md` has the full team-server walkthrough, including what
the Qdrant mirror holds and the residuals of its transport.
