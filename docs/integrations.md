# Integrations

## Claude Code

MCP server: `claude mcp add undercroft -- undercroft serve-mcp`
Auto-save hooks: `undercroft hooks claude-code` prints settings; or install
the plugin from `.claude-plugin/` (commands, hooks, skills, MCP).
Backfill history: `undercroft mine ~/.claude/projects --mode convos`, then
per-message recall with `undercroft sweep ~/.claude/projects`.

## Cursor

Copy `rules/undercroft-recall.mdc` into `.cursor/rules/`; wire the MCP server
in Cursor's MCP settings with command `undercroft serve-mcp`.

## Gemini CLI / Codex / any MCP client

Stdio config (see `mcp.json`):

```json
{ "mcpServers": { "undercroft": { "command": "undercroft", "args": ["serve-mcp"] } } }
```

## Background auto-save without hooks

`undercroft daemon run --watch <transcript-dir> --interval 300` — or the
systemd user unit in `deploy/undercroft-daemon.service`.

## Team server

See [remote-server.md](remote-server.md).
