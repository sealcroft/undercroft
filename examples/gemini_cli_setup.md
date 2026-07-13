# Gemini CLI setup

Add to `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "undercroft": { "command": "undercroft", "args": ["serve-mcp"] }
  }
}
```

Gemini CLI will discover the `undercroft_*` tools (save, search, wake_up,
kg_*, diary_*, …). Start sessions by calling `undercroft_wake_up`, and store
decisions verbatim with `undercroft_save`.

For automatic transcript capture, run the sweep daemon against Gemini CLI's
session directory:

```bash
undercroft daemon run --watch ~/.gemini/tmp --interval 300 --wing gemini
```
