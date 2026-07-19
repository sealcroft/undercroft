# Getting started

> Implementing with (or as) an AI agent? The
> [agents implementation guide](https://compufreq.github.io/undercroft/docs/agents.html)
> is the scenario-driven version of this page: pick a deployment shape
> (single agent, team server, multi-tenant engine, fleet), follow its
> steps, and verify with the checklist.

## Install

Docker (recommended — nothing touches the host):

```bash
docker build -t undercroft .
alias undercroft='docker run --rm -v undercroft-data:/data undercroft'
```

Or native: `cargo build --release` → `target/release/undercroft`.

## First palace

```bash
undercroft init                                   # master key + sealed 'default' vault
undercroft remember "We chose GraphQL for the mobile API" --wing backend --room decisions
undercroft mine ~/notes --wing personal           # documents
undercroft mine ~/.claude/projects --mode convos  # Claude Code sessions
undercroft search "why graphql"
undercroft wake-up                                # session-start context
undercroft verify                                 # HMAC + audit chain check
```

Palace location: `$UNDERCROFT_HOME` (default `~/.undercroft`). Passphrase
mode: export `UNDERCROFT_PASSPHRASE` before `init` and every command.

## Wire into Claude Code

```bash
claude mcp add undercroft -- undercroft serve-mcp
undercroft hooks claude-code   # auto-save hook settings to paste
```

Continue with [integrations](integrations.md), [architecture](architecture.md),
[security model](security.md), and [remote team server](remote-server.md).
