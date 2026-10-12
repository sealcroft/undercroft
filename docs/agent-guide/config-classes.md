# Agent guide — configuration classes

A reference document of the agent guide. `CLAUDE.md`, at the repository root,
is the guide's core — read by every agent on every turn — and its last section
indexes this document. This one holds, VERBATIM, the doctrine for declared
configuration — `Protects` and `Tunes`, `Checked` and `Opaque`, closed
vocabulary versus opaque payload, mandatory operands — and declarations that
cannot work. Read it when your work adds or changes an `UNDERCROFT_*`
variable, a resolver, or `undercroft config check`.

It was moved here unchanged when the guide was split (ROADMAP O436,
2026-10-12), and it governs over any one-line statement of the same rule in
the core. In the moved text, "this file" and "here" mean the guide as a whole
— the core and its reference documents.

The `Checked`, `Opaque`, `Protects` and `Tunes` figures in it are read by the
`prose figures` preflight in `tests/battery.sh`; reword that sentence only
together with its rows.

---

- **A declared configuration is classified, and the class decides what a bad
  value does.** `architecture/index.html` states the doctrine — *"every
  default is the conservative choice"*, *"integrity is not a tier"*,
  *"outward paths are explicit"* — and it settles the question one call site
  at a time used to: where the default is already conservative and the
  declaration merely ADJUSTS it, garbage warns and keeps the default, because
  the operator loses tuning and nothing else. Where the DECLARATION is what
  turns a protection on, pins an outward path, or names which vector space a
  vault is in, the default is *off* and a silent fallback removes what was
  asked for — so garbage REFUSES to open. That is "integrity is not a tier"
  extended by one step: a protection an operator declared must not become a
  tier by typo.
  **And a MANDATORY OPERAND inherits its selector's class (O155, 2026-09-12).**
  The three clauses above describe a declaration that acts; they had no answer
  for the one it acts THROUGH — the model file `UNDERCROFT_EMBEDDER=onnx` will
  load, the endpoint `=http` will reach, the URL `index push --backend qdrant`
  needs. Those were `Tunes` while their selectors were `Protects`, and a bad
  value in either refuses at the same `?`, so the class contradicted itself in
  one line. Fourteen rows move: four backend URLs, a DSN, two served-runtime
  URLs and seven model paths. The discriminator is **a default to keep**, and
  it is what stops the rule running away — `UNDERCROFT_EMBED_MODEL`
  (`nomic-embed-text`), `_LLM_MODEL` (`llama3.2`) and `_ORCH_DB`
  (`orchestrator.db`) look identical and stay `Tunes` because each has one.
  Applied backwards it reclassifies nothing else and CONFIRMS the rest: every
  `_NAME` row, `_EMBED_DIM`, `_EMBED_API`, `_LLM_API` and both `_KEY`s are
  optional operands with real defaults, and every `_CA` was already `Protects`.
  **One application, and that is stated rather than implied.**
  **What the rule COST is the part worth keeping**: making fourteen rows
  `Protects` forced `PREFLIGHT_EXEMPT` to answer *why can this not be
  pre-flighted?* for each, and for seven the answer was that it CAN be and was
  not — `config check` exited 0 on a cleartext backend URL that its own client
  refuses at construction. A taxonomy change that could not alter behaviour
  found a live hole because the class is what decides which rows a gate LOOKS
  at. `parity.rs::ENGINE_ENV_VARS` carries
  `(name, ConfigClass, Parse)` and is counted against the code in both
  directions on BOTH axes, so a new variable does not compile until someone
  classifies it; `undercroft config check` runs every declaration through the
  resolver that will run at start-up, opening nothing, so an upgrade fails in
  a pipeline instead of at a restart. Since O204 it also stats a DECLARED data
  directory through the key classifier a start runs — only a declared one,
  because a CI runner's own home is a verdict about nothing — and since O279
  opens one of its vaults' `vault.json` read-only to ask whether that
  filesystem keeps a file's identity, the observable every open's moved-file
  check compares.
  **The second axis exists because "I ran no parse" and "there is no parse to
  run" are different claims that READ IDENTICALLY (O52).** `check_one` falls
  to a catch-all rendering an unknown name as `Accepted` — printed as *"no
  parse to run; the consumer validates it"* — which is honest about a path or
  a bearer and a false claim about a knob whose arm somebody forgot. #9
  closed that for `Protects` with an exempt list counted both ways; O48 then
  WIDENED it for `Tunes`, teaching eleven resolvers to validate values the
  pre-flight still described as unvalidated. `Parse::{Checked,Opaque}` is
  declared per variable and counted both ways: a `Checked` one the command
  runs no parse for fails the build, an `Opaque` one that IS pre-flighted
  fails it too. What makes `Checked` affordable is `undercroft-store`'s
  `TUNED` table — every numeric knob's unset value and bounds stated ONCE,
  read by the engine's resolver AND by `check_declaration`, so the two cannot
  report different values. A knob whose unset depends on ANOTHER variable has
  no row and says why (`UNDERCROFT_LATE_TOP_N` falls through to
  `UNDERCROFT_RERANK_TOP_N`, valid or not, which is a compatibility promise).
  58 of the 82 are `Checked`, 24 `Opaque`, and 40 `Protects` against 42
  `Tunes` — counted by the `prose figures` preflight, not remembered. The
  class figures had rotted before it existed: O121 moved
  `UNDERCROFT_RERANKER` to `Protects` and the platform-views decision tree
  went on publishing the old split for five days, which is what O155 gated.
  **The two axes are declared independently, but the second decides whether
  the first can be OBSERVED: for an `Opaque` row the class is DOCUMENTATION
  rather than a gate (O155).** `check_one` answers `Accepted`
  before the class is read, so nothing an operator observes moves when an
  `Opaque` row is reclassified and no test in that crate can falsify the
  claim; its consequence lives at the consumer — a model that loads, an
  endpoint that answers — which this command reaches deliberately never. Say
  that plainly rather than leaving an unfalsifiable claim to rot. The class
  still earns its place on those rows: it is what tells a READER the failure
  mode, and it is what decides which rows `PREFLIGHT_EXEMPT` must account
  for — which is how a taxonomy change that could not alter behaviour turned
  up seven rows that were pre-flightable and unchecked.
  **The class is not the whole rule: a declaration is either a CLOSED
  VOCABULARY or OPAQUE PAYLOAD, and that decides what EMPTY means and whether
  the value may be TRIMMED.** A vocabulary variable (`UNDERCROFT_ADMISSION`)
  may legitimately read empty as a third spelling of its default, and is
  trimmed so a trailing newline from `$(cat …)` or a YAML block scalar cannot
  change its meaning. Payload — `UNDERCROFT_ASSERTION_SECRET`, a CA path, a
  token — has no vocabulary, so empty cannot express intent: it is always a
  failed interpolation and must REFUSE, and it must **not** be trimmed,
  because trimming changes the value itself and for a secret that means
  changing the KEY and silently invalidating every header already minted.
  Nothing encoded this, so each call site answered for itself, and
  `UNDERCROFT_ASSERTION_SECRET` was resolved by `!s.is_empty()` in two inline
  copies that DISAGREED: the minting side (`assert-header`) hard-errored on
  empty while the ENFORCING side read it as "assertions off" and answered 200
  to any bearer on every `/v1` route and `POST /mcp`. That one line also
  failed in **two opposite directions** — `""` turned the boundary off
  silently, and `" "` is not empty so it was accepted as a real one-byte key
  while the banner truthfully reported assertions required. A fix that only
  maps empty to absent closes the first and leaves the second.
  **The rule was written from one instance and there were at least two.**
  `UNDERCROFT_PASSPHRASE` carried the identical `.filter(|p| !p.is_empty())`
  for the whole time the doctrine sat in this file, on a higher-value secret:
  an empty declaration became "no passphrase" and the palace wrote a random
  `master.key` to DISK — the exact opposite of what declaring a passphrase
  asks for, granted silently, reachable through a compose recipe the docs
  shipped. So when a rule like this lands, **grep for the pattern it names
  rather than trusting that the instance which taught it was the only one**;
  `!is_empty()` over a declared secret is a two-minute search and it would
  have found this the same day. Note also the shape of the exemption that
  hid it: a later unit listed the passphrase as unpre-flightable because "a
  passphrase is a credential, not a syntax" — true of a WRONG one, false of
  an ABSENT one. Two questions, one answer, and the wrong one.
  **The sweep was finally run on 2026-08-12 and returned two more**, which is
  the doctrine paying for itself twice: `UNDERCROFT_MCP_HTTP_TOKEN` (a bearer
  gate removed on loopback) and `UNDERCROFT_OTLP_ENDPOINT` — the second inside
  the *previous commit's own* code, wrong in BOTH directions at once, the
  runtime reading empty as "off" while the pre-flight handed the empty string
  to the transport policy, which parses it, fails, and reports an unparseable
  URL as CLEARTEXT. Four instances, one pattern, and the only one anybody
  found by thinking about it was the first.
- **A declaration that CANNOT WORK is refused, never quietly adjusted into one
  that can — and "cannot work" is measured, not reasoned about.** Emptiness is
  not the only way a declared value fails to be one. A bearer ending in
  whitespace is a perfectly good string that **no client can ever present**:
  HTTP strips a header field value's trailing whitespace, so the token that
  arrives is always the trimmed one, and `UNDERCROFT_MCP_HTTP_TOKEN=$(cat
  /run/secrets/token)` over a file ending in a newline starts a healthy server
  that refuses every request forever — 401 naming no cause on one side,
  nothing in the log on the other. The tempting fix is to trim it; that is
  wrong, because it authenticates a key the operator did not declare, and a
  server whose key silently differs from the file it was configured from is
  the whole failure class restated.
  Two disciplines, both earned here. **Measure which spellings actually break
  before writing the guard**: leading and internal whitespace answer 200 and
  trailing whitespace answers 401, so the guard is `trim_end() != value` and
  not `trim() != value` — the wider version would refuse legitimate values in
  the name of a defect they do not have. And **a real corpus is how this class
  is found at all**: every unit test compares a resolver to itself, so no test
  in this tree could see it; the live `serve-http` over 1,360 mined drawers
  that the definition of done demands is what returned the 401. Ask of any
  declared value not only *"can this be empty?"* but *"is there a spelling of
  this that the surface consuming it cannot carry?"*
  Applied backwards, as this file requires of a new RULE: it reclassifies
  nothing and adds one case. The CA pin, the cleartext refusal and the two
  Argon2id/HMAC secrets all keep their current answers — a passphrase or an
  HMAC key with trailing whitespace WORKS, both sides using the same bytes, so
  the rule correctly declines to touch them. Only a value that must survive a
  transport it cannot survive is caught. That is the healthy outcome for a
  doctrine (mostly describes the tree, one genuine addition), and the addition
  is the only history it has: **untested against anything older than itself.**
