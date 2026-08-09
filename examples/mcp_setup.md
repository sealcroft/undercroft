# MCP setup

## Claude Code

```bash
claude mcp add undercroft -- undercroft serve-mcp

# Recall only — every write tool refused, and the vault opened read-only:
claude mcp add undercroft -- undercroft serve-mcp --read-only
```

Docker variant:

```bash
claude mcp add undercroft -- docker run -i --rm -v undercroft-data:/data undercroft serve-mcp
```

## Any stdio MCP client

```json
{ "mcpServers": { "undercroft": { "command": "undercroft", "args": ["serve-mcp"] } } }
```

## Remote (HTTP) server

See [docs/remote-server.md](../docs/remote-server.md).

34 tools are exposed; ask the client to list them, or see the README table.
