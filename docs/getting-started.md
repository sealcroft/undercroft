# Getting started

> Implementing with (or as) an AI agent? The
> [agents implementation guide](https://sealcroft.com/undercroft/docs/agents.html)
> is the scenario-driven version of this page: pick a deployment shape
> (single agent, team server, multi-tenant engine, fleet), follow its
> steps, and verify with the checklist.

## Install

Docker (recommended — nothing touches the host):

```bash
docker pull ghcr.io/sealcroft/undercroft:latest    # or: docker build -t undercroft .
alias undercroft='docker run --rm -v undercroft-data:/data ghcr.io/sealcroft/undercroft:latest'
```

The alias mounts only the palace volume and forwards no host environment
variable, so under Docker `mine` needs its folder bind-mounted and
`UNDERCROFT_PASSPHRASE` needs `-e`. A shell alias also never reaches a
program that launches `undercroft` itself, which is why Claude Code gets the
full `docker run -i` command below.

Prebuilt binaries (Linux x86_64/arm64, macOS Intel/Apple Silicon, Windows) are
attached to every [release](https://github.com/sealcroft/undercroft/releases/latest),
with SHA-256 checksums. Or native: `cargo build --release` →
`target/release/undercroft`.

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

Under Docker the two `mine` lines need their folders mounted. Read-only is
enough, and the image runs as uid 10001, which must be able to read them:

```bash
docker run --rm -v undercroft-data:/data -v ~/notes:/notes:ro \
  ghcr.io/sealcroft/undercroft:latest mine /notes --wing personal
docker run --rm -v undercroft-data:/data -v ~/.claude/projects:/convos:ro \
  ghcr.io/sealcroft/undercroft:latest mine /convos --mode convos
```

Palace location: `$UNDERCROFT_HOME` (default `~/.undercroft`; `/data` in the
image). Passphrase mode: export `UNDERCROFT_PASSPHRASE` before `init` and
every command, and under Docker add `-e UNDERCROFT_PASSPHRASE` to every
`docker run`, the alias included. A passphrase declared over an installation created
without one is refused, and so is the reverse; back up `kdf.salt` as carefully
as `master.key`, since the passphrase cannot re-derive the key without it.

## Wire into Claude Code

```bash
claude mcp add undercroft -- undercroft serve-mcp

# ...or under Docker: stdio needs -i, and the alias above does not apply here
claude mcp add undercroft -- docker run -i --rm -v undercroft-data:/data \
  ghcr.io/sealcroft/undercroft:latest serve-mcp

# ...or recall only, with every write tool refused:
claude mcp add undercroft -- undercroft serve-mcp --read-only
undercroft hooks claude-code   # auto-save hook settings to paste
```

Continue with [integrations](integrations.md), [architecture](architecture.md),
[security model](security.md), and [remote team server](remote-server.md).
