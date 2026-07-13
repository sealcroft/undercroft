# Examples

Library examples (run with cargo):

```bash
cargo run -p undercroft-cli --example basic_mining
cargo run -p undercroft-cli --example convo_import
```

- `basic_mining.rs` — create a palace, file drawers, search, verify — the
  whole lifecycle against the library API.
- `convo_import.rs` — parse a Claude Code JSONL transcript and file one
  drawer per message.

Setup guides:

- [mcp_setup.md](mcp_setup.md) — wire the MCP server into Claude Code and
  other clients.
- [gemini_cli_setup.md](gemini_cli_setup.md) — Gemini CLI configuration.
- CLI walkthrough: see [docs/getting-started.md](../docs/getting-started.md).
