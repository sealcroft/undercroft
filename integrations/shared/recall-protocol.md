# Shared recall protocol

The contract every Undercroft integration (Claude Code plugin, Cursor rules,
Codex hooks, custom agents) follows:

1. **Wake-up first.** Begin sessions with `undercroft wake-up` (or the
   `undercroft_wake_up` MCP tool) to load identity + recent essentials.
2. **Search before asking.** When the user references something from the
   past, search the palace before saying "I don't know":
   `undercroft search "<question>" [--wing <project>]`.
3. **Verbatim in, verbatim out.** Save exact words; quote retrieved drawers
   exactly. Summarize only in your own commentary around them.
4. **Facts go to the graph.** Durable facts with a time dimension belong in
   the knowledge graph (`kg add` / `kg supersede`), not only in prose.
5. **Trust the vault, check the chain.** On any integrity error, stop and
   surface it — run `undercroft verify` and show the result. Never present
   data that failed its HMAC.
6. **Diaries for agents.** Long-running specialist agents write session
   notes with `undercroft diary write <agent> "<entry>"` and re-orient with
   `undercroft diary read <agent>`.
