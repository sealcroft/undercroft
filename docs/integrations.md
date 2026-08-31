# Integrations

> The [agents implementation guide](https://sealcroft.com/undercroft/docs/agents.html)
> covers each of these surfaces as a step-by-step scenario, with the full
> MCP tool, REST route, and environment-variable reference.

Every integration reaches the same engine through one of three surfaces —
interactive MCP, HTTP, or background ingestion — and they all end at the
same vault-sealed store:

```mermaid
flowchart LR
    subgraph clients["Clients"]
        cc["Claude Code<br/><i>MCP + hooks/plugin</i>"]
        cur["Cursor<br/><i>rules + MCP</i>"]
        gem["Gemini CLI / Codex /<br/>any MCP client"]
        team["Team callers<br/><i>REST /v1</i>"]
    end
    subgraph ingest["Background ingestion"]
        mine["mine / sweep<br/><i>transcript backfill</i>"]
        daemon["daemon --watch<br/><i>systemd unit</i>"]
    end
    cc --> mcp["MCP stdio<br/><i>serve-mcp, 38 tools</i>"]
    cur --> mcp
    gem --> mcp
    cc -. "shared server" .-> http["HTTP<br/><i>serve-http: MCP /mcp +<br/>REST /v1, bearer + assertions</i>"]
    team --> http
    mcp --> store["palace store<br/><i>sealed vaults, audit chain</i>"]
    http --> store
    mine --> store
    daemon --> store
    store -. "sealed content only,<br/>re-verified locally" .-> remote["remote vector indexes<br/><i>Qdrant / Chroma / pgvector /<br/>Milvus / Weaviate — untrusted<br/>accelerators</i>"]
    llmx["local LLM<br/><i>Ollama / OpenAI-compatible</i>"] -. "refine → KG<br/>(opt-in, local)" .-> store
```

## Claude Code

MCP server: `claude mcp add undercroft -- undercroft serve-mcp`

Add `--read-only` to serve recall without write access: every write tool
is refused, and the posture reaches the OPEN too — a read-only stdio
server does not migrate the embedder or append a read-audit record per
read. The gate fails closed: a tool it has not classified as a read is
refused.
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
