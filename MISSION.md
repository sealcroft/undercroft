# Undercroft: The Mission

Memory is identity. When an AI forgets everything between conversations, it
cannot build real understanding — of you, your work, your people, your life.
And when memory *is* kept, it becomes the most sensitive file on your disk:
months of conversations, decisions, names, and half-formed ideas, all in one
place.

Undercroft exists to solve both problems at once. It is a memory system that
**remembers everything and guards what it remembers**.

## What we believe

**Verbatim always.** Memory that paraphrases is memory that lies. Undercroft
stores your exact words and returns your exact words — no summarization, no
extraction, no lossy compression on the write path. If you said it, the
palace holds precisely what you said.

**A palace, not a warehouse.** Most memory systems are flat dumps behind a
similarity search. Undercroft keeps the memory-palace structure that gave its
ancestor, MemPalace, its name: *wings* for people and projects, *rooms* for
topics, *drawers* for the verbatim content — connected by *tunnels* and
*hallways* so things can be found from any angle, not just the one they were
filed under. You should be able to ask "remember when we talked about that
idea…" in vague terms and get the exact moment back.

**Memory deserves locks.** This is where Undercroft departs from every memory
system we know of. A store of everything you've told an AI must be treated
like a password vault, not a cache:

- memories live in **isolated vaults** with cryptographically separated keys
  — one compromised vault exposes nothing about its siblings;
- content is **encrypted at rest** (XChaCha20-Poly1305), bound to its vault
  and record so ciphertext cannot be replayed elsewhere;
- every record carries an **HMAC integrity tag** and every write joins a
  **tamper-evident audit chain** — if anything on disk is altered, added,
  or silently deleted, `verify` says so;
- even remote search accelerators only ever receive **sealed bytes**, and
  their answers are re-verified locally before you see them.

**Local-first, zero external dependency.** Everything — chunking, embedding,
search, the knowledge graph — runs on your machine with no API key, no
model download, and no telemetry. The default embedder is deterministic and
offline. Remote vector databases and model-based embedders exist as explicit,
opt-in choices, never defaults and never silent fallbacks.

**Honest engineering.** Trade-offs are documented where they live: what
sealed vaults still reveal (structure labels, embeddings pushed to remote
indexes), what the threat model does and does not cover, and what has not
been ported yet. A security feature that overstates itself is a
vulnerability with good marketing.

## What we will not accept

Summarization of user content on the write path. Cloud storage or sync as a
default. Telemetry of any kind. Features that require an API key for core
memory. Shortcuts that bypass verbatim storage, the vault layer, or the
audit chain.

## The name

Undercroft is the Greek Titaness of memory, mother of the nine Muses. Her
pool — unlike the river Lethe beside it — let souls keep what they knew
across the crossing. That is the whole mission in one image: memory that
survives the crossing between sessions, and a spring that is guarded, not
an open river.
