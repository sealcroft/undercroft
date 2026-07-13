# Integrations

- `shared/recall-protocol.md` — the contract all integrations follow.
- Claude Code: install the plugin in `.claude-plugin/` (commands, MCP
  server, auto-save hooks, skills), or wire `hooks/` manually.
- Cursor: copy `rules/undercroft-recall.mdc` into your project rules.
- Any MCP client: `mcp.json` at the repo root shows the stdio server
  config; `deploy/` shows the shared HTTP team server.
