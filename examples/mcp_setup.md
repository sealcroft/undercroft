# MCP setup

## Claude Code

```bash
claude mcp add undercroft -- undercroft serve-mcp
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

30 tools are exposed; ask the client to list them, or see the README table.
