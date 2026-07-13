# Auto-save hooks

Shell hooks that sweep agent transcripts into the palace so nothing is lost
to context compaction. All hooks call `undercroft sweep`, which is idempotent
— re-running never duplicates a memory — and they run in the background so
no tokens or time are spent in the chat window.

## Claude Code

Either install the plugin (`.claude-plugin/`), or print ready-to-paste
settings with:

```bash
undercroft hooks claude-code
```

or wire these scripts manually into `~/.claude/settings.json` under the
`Stop`, `PreCompact`, and `SessionEnd` hook events.

## Other agents (Cursor, Codex, Gemini CLI, ...)

Any agent that writes JSONL transcripts works: point the daemon at the
transcript directory —

```bash
undercroft daemon run --watch <transcript-dir> --interval 300
```

or see `deploy/undercroft-daemon.service` for a systemd user unit.
