//! `undercroft config check` — validate every declaration WITHOUT opening a
//! vault or binding a port.
//!
//! **Why this exists.** Undercroft's configuration doctrine is that a
//! declaration which turns a protection on must REFUSE when it does not
//! parse (`parity::ConfigClass::Protects`): silently running without what
//! the operator declared is the failure mode. That is the right behaviour
//! and it has a cost — the refusal arrives when the process starts, which on
//! a fleet is during a rolling upgrade, one node at a time.
//!
//! So the same resolvers are reachable ahead of time. This command reads the
//! environment, runs every declaration through the code that will run at
//! start-up, and reports what would happen — with an exit code a pipeline
//! can gate on. It opens nothing: no vault, no database, no socket, no
//! outbound call. A CI job can run it against the deployment's real
//! environment and fail there rather than at restart.
//!
//! **The classification is the inventory's, not a second copy.**
//! `ENGINE_ENV_VARS` carries `(name, ConfigClass, Parse)` and is counted
//! against the code in both directions on both axes, so a variable this
//! command does not know about cannot exist, and a `Checked` one it runs
//! no parse for cannot either.

use crate::parity::{ConfigClass, ENGINE_ENV_VARS};

/// What checking one declaration found.
enum Finding {
    /// Declared and it resolves.
    Ok(String),
    /// Declared, and there is no parse to run — this command has not
    /// validated it and says so rather than implying it has.
    Accepted,
    /// Declared, does not resolve, and its class REFUSES — this stops a
    /// start-up.
    Fatal(String),
    /// Declared, does not resolve, and its class falls back to the
    /// conservative default.
    Warn(String),
}

/// Run every declaration present in the environment through its real
/// resolver. Returns (fatal, warned, validated, accepted).
///
/// `validated` and `accepted` are reported apart on purpose. Only some
/// variables have a parse to run; the rest are paths, URLs, tokens and model
/// names whose only real validation is the thing that consumes them. Folding
/// the two together would let this command imply it had checked all of them,
/// and "none found" is a claim about the method, never about the tree.
///
/// **Since O52 the split is DECLARED rather than emergent.** `accepted` is
/// exactly the `Parse::Opaque` half of `ENGINE_ENV_VARS`, counted against
/// this code in both directions — so the number an operator reads as "not
/// checked" cannot quietly grow when someone adds a knob and forgets its arm.
pub fn run(verbose: bool) -> (usize, usize, usize, usize) {
    let mut fatal = 0usize;
    let mut warned = 0usize;
    let mut validated = 0usize;
    let mut accepted = 0usize;

    for (name, _, _) in ENGINE_ENV_VARS {
        let Ok(raw) = std::env::var(name) else {
            continue; // Undeclared is not a finding.
        };
        let finding = check_one(name, &raw);
        match finding {
            Finding::Ok(what) => {
                validated += 1;
                if verbose {
                    println!("  ok      {name}={raw:?} — {what}");
                }
            }
            Finding::Accepted => {
                accepted += 1;
                if verbose {
                    // Says WHICH kind of unchecked it is. Before O52 this
                    // read the same for a path with genuinely nothing to
                    // parse and for a knob whose parse nobody had wired up,
                    // so the honest half of the message was carrying the
                    // dishonest half.
                    println!(
                        "  seen    {name}={raw:?} — declared Opaque: no parse exists, so its \
                         consumer is the only real validation"
                    );
                }
            }
            Finding::Warn(why) => {
                validated += 1;
                warned += 1;
                println!("  warn    {name}={raw:?} — {why}");
            }
            Finding::Fatal(why) => {
                // A refusal IS a validation — running the parse is how we
                // know it refuses. Counting it only as fatal made the two
                // totals fail to add up for the operator reading them.
                validated += 1;
                fatal += 1;
                println!("  REFUSES {name}={raw:?} — {why}");
            }
        }
    }
    (fatal, warned, validated, accepted)
}

/// One declaration, through the resolver that will run at start-up.
///
/// Every arm here calls the SAME function the engine calls — never a second
/// copy of the parse. A validator that agreed with its own reimplementation
/// rather than with the code would be the exact class of defect this tree
/// spends its time closing.
fn check_one(name: &str, raw: &str) -> Finding {
    let class = ENGINE_ENV_VARS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, c, _)| *c)
        .unwrap_or(ConfigClass::Tunes);
    // **Declarations this crate owns are checked here, not in the store.**
    // `check_declaration` lives in `undercroft-store`, which cannot reach a
    // parse that lives in the CLI or in `undercroft-llm` — so those fell
    // through its catch-all and this command printed "no parse to run; the
    // consumer validates it" about values that stop start-up. Measured
    // against the binary: `config check` exited 0 while the same environment
    // failed to run, for all three below (round-four #9).
    //
    // Each arm calls the SAME function the engine calls. None of them
    // constructs anything — this command opens nothing and makes no outbound
    // call, so a model is never loaded to find out whether its name is legal.
    let owned: Option<Result<String, String>> = match name {
        "UNDERCROFT_EMBEDDER" => Some(
            crate::check_embedder(raw).map(|()| "selects the vector space for this vault".into()),
        ),
        "UNDERCROFT_RETRIEVAL" => {
            Some(crate::check_retrieval(raw).map(|()| "selects the candidate generator".into()))
        }
        "UNDERCROFT_RERANKER" => {
            Some(crate::check_reranker(raw).map(|()| "attaches the second retrieval stage".into()))
        }
        "UNDERCROFT_ADMISSION_LLM" => Some(
            undercroft_llm::advisor::check_mode(raw)
                .map(|()| "tier-2 advisory screen, toward quarantine only".into())
                .map_err(|e| e.to_string()),
        ),
        // Its CORRECTNESS is uncheckable — any non-empty string is a
        // well-formed token and only a client can say whether it is the right
        // one. Its EMPTINESS is not, and that was the whole of ROADMAP O22:
        // an empty declaration served /mcp and /v1 to any caller on the
        // loopback host while the operator's configuration said a bearer was
        // required. Two different questions, and the exemption this replaces
        // answered both with "a credential, not a syntax".
        "UNDERCROFT_MCP_HTTP_TOKEN" => Some(
            crate::http::resolve_mcp_token(Some(raw))
                .map(|_| "bearer required on /mcp and /v1".into()),
        ),
        // ROADMAP O52. Four declarations whose parses live in this crate,
        // `undercroft-llm` and `undercroft-embed-ort`. The last is the reason
        // its parse sits in `undercroft-core`: `--features ort` is not a
        // default build, so an arm calling the ort crate would be unreachable
        // from the binary an operator actually pre-flights with.
        "UNDERCROFT_METRICS" => Some(crate::http::resolve_metrics(Some(raw)).map(|on| {
            if on {
                "/metrics is served".into()
            } else {
                "/metrics is off".into()
            }
        })),
        "UNDERCROFT_SAMPLE_INTERVAL_MS" => Some(
            crate::http::resolve_sample_interval_ms(Some(raw))
                .map(|ms| format!("the telemetry sampler ticks every {ms} ms")),
        ),
        "UNDERCROFT_LLM_API" | "UNDERCROFT_EMBED_API" => Some(
            undercroft_llm::check_api_kind(name, Some(raw))
                .map(|k| format!("the served runtime speaks {k:?}")),
        ),
        // The dimension goes through `embed_dim`, the embedder's own parse,
        // so a declared 2-modulo-4 width is reported here and not first at
        // the write choke point (ROADMAP O123).
        "UNDERCROFT_EMBED_DIM" => Some(
            undercroft_core::config::embed_dim(name, Some(raw))
                .map(|n| match n {
                    Some(n) => format!("declared as {n}"),
                    None => "derived at start-up".into(),
                })
                .map_err(|f| f.why),
        ),
        "UNDERCROFT_ORT_POOL" => Some(
            undercroft_core::config::positive_usize(name, Some(raw))
                .map(|n| match n {
                    Some(n) => format!("declared as {n}"),
                    None => "derived at start-up".into(),
                })
                .map_err(|f| f.why),
        ),
        // **The seven outward paths, ROADMAP O155.** Reclassifying these
        // `Protects` asked the question the class forces — *why can this not
        // be pre-flighted?* — and for these seven the honest answer was that
        // it CAN be, and was not. `config check` printed *"declared Opaque:
        // no parse exists"* and exited 0 for
        // `UNDERCROFT_QDRANT_URL=http://qdrant.internal:6333`, which
        // `index push` refuses at construction; same for the other three
        // backends, for the embedder and for the LLM runtime. That is
        // round-four #9's defect verbatim — exit 0 for an environment that
        // does not start — surviving on seven rows because the class that
        // makes the gate look at them said `Tunes`.
        //
        // Every arm calls the SAME policy the client calls, with the SAME
        // `what` string, so the refusal an operator reads here is word for
        // word the one they would have met at start-up. `declared_endpoint`
        // is the pre-flight entry point to `require_secure_transport`, which
        // is what `agent_from_env` runs inside each of these constructors;
        // it adds the empty case, and empty refuses at the consumer too (an
        // unparseable URL is cleartext and not loopback, the safe direction).
        // Nothing here opens a socket, resolves a name or reads a file.
        //
        // What it still does NOT check is whether anything ANSWERS at that
        // URL. That is the consumer's, deliberately.
        "UNDERCROFT_QDRANT_URL"
        | "UNDERCROFT_CHROMA_URL"
        | "UNDERCROFT_MILVUS_URL"
        | "UNDERCROFT_WEAVIATE_URL" => Some(
            undercroft_net::declared_endpoint("the remote index", Some(raw))
                .map(|_| "the remote index is reached over a permitted transport".into())
                .map_err(|e| e.to_string()),
        ),
        "UNDERCROFT_EMBED_URL" => Some(
            undercroft_net::declared_endpoint("the embedder", Some(raw))
                .map(|_| "the embeddings endpoint is reached over a permitted transport".into())
                .map_err(|e| e.to_string()),
        ),
        "UNDERCROFT_LLM_URL" => Some(
            undercroft_net::declared_endpoint("the LLM endpoint", Some(raw))
                .map(|_| "the LLM runtime is reached over a permitted transport".into())
                .map_err(|e| e.to_string()),
        ),
        // The DSN is not a URL, so it gets libpq's parser rather than the
        // URL one — `check_dsn_transport` is the function `PgVectorIndex::new`
        // itself calls, lifted out of that constructor for this arm (O155)
        // rather than restated here. O90 is why asking the connector's own
        // parser is the only acceptable shape: a hand-read of the string let
        // `hostaddr=` and `host = ` pass as loopback.
        "UNDERCROFT_PGVECTOR_DSN" => Some(
            undercroft_index::pgvector::check_dsn_transport(raw)
                .map(|()| "the pgvector database is reached over a permitted transport".into())
                .map_err(|e| e.to_string()),
        ),
        _ => None,
    };
    if let Some(result) = owned {
        return match result {
            Ok(what) => Finding::Ok(what),
            Err(why) => match class {
                ConfigClass::Protects => Finding::Fatal(why),
                ConfigClass::Tunes => Finding::Warn(format!(
                    "{why}; this one keeps the conservative default rather than refusing"
                )),
            },
        };
    }
    match undercroft_store::check_declaration(name, raw) {
        Ok(Some(what)) => Finding::Ok(what),
        Ok(None) => Finding::Accepted,
        Err(why) => match class {
            ConfigClass::Protects => Finding::Fatal(why),
            ConfigClass::Tunes => Finding::Warn(format!(
                "{why}; this one keeps the conservative default rather than refusing"
            )),
        },
    }
}

/// `Protects` variables this command legitimately cannot pre-flight, each
/// with the reason it is exempt rather than forgotten.
///
/// A `Protects` variable is one whose refusal is FATAL, so an operator is
/// told to trust `config check`'s exit code — `UPGRADING.md` says in as many
/// words that if it exits 0, none of its entries affect you. Anything on this
/// list is a place where that promise is narrower than it sounds, so the list
/// is short, argued, and counted against the code in THREE directions by
/// [`tests::every_protects_variable_is_pre_flighted_or_exempt`]: a `Protects`
/// row with neither an arm nor an entry fails, an entry for a row that IS
/// pre-flighted fails, and — since O155 — an entry naming anything that is
/// not a `Protects` row of `ENGINE_ENV_VARS` fails.
///
/// **That third direction was missing while the doc said "both", and O155 was
/// about to multiply what it could not see from two entries to nine.** The
/// gate's loop `continue`s on every row that is not `Protects`, so the exempt
/// list's own universe was never examined: an entry for a `Tunes` variable,
/// for a name reclassified after it was written, or for a variable deleted
/// from the engine entirely would sit here reading like an argued decision
/// and be visited by nothing. That is the shape this command exists to close,
/// one list over — an inventory whose staleness nothing can report.
///
/// `#[cfg(test)]` because it is inventory, not behaviour — the same shape as
/// `mcp::WRITE_TOOLS`, which survives as the other half of a count and is
/// referenced by nothing at run time.
#[cfg(test)]
const PREFLIGHT_EXEMPT: &[(&str, &str)] = &[
    // `UNDERCROFT_PASSPHRASE` was here, and then `UNDERCROFT_MCP_HTTP_TOKEN`
    // was, and both were too broad in the same way: a credential's
    // CORRECTNESS is uncheckable without decrypting a vault or being refused
    // by a peer, but its EMPTINESS is checkable here and is always a failed
    // interpolation. Listing the variable answered both questions with
    // "cannot" — and the silent halves were key material written to disk and
    // a bearer gate removed from a loopback server. Each has an arm now, and
    // the both-directions half of the gate below is what forced these entries
    // to be deleted rather than left to rot.
    //
    // Nothing is exempt for being a credential any more. If a future one is,
    // say which of the two questions is unanswerable and why.
    //
    // **The three `UNDERCROFT_ORCH_*` entries are GONE (ROADMAP O24).** They
    // said the declarations were owned by a different binary and therefore
    // unreachable "at any price", and that was wrong twice over: this
    // command's own `ENGINE_ENV_VARS` already contained the names, and
    // `UNDERCROFT_ORCH_ENGINE_CA` was already validated by the CA-pin arm.
    // The doctrine forbids the engine LINKING the control-plane crate; it
    // never forbade validating three string-to-value parses.
    //
    // They live in `undercroft-config` now — a leaf crate both binaries link
    // and neither owns, carved out on the precedent `undercroft-net` set —
    // so `check_declaration` runs the SAME code the control plane runs.
    //
    // The deletion was FORCED rather than remembered: the both-directions
    // gate below fails on an entry that turns out to be pre-flighted.
    // Flags, not vocabularies: any value that is not the enabling one leaves
    // the conservative default in place, so there is nothing that can fail
    // to parse. Verified against the binary — a garbage value runs.
    (
        "UNDERCROFT_FORCE_EMBEDDER",
        "a flag; no value can fail to parse",
    ),
    (
        "UNDERCROFT_ADMIT_TRUSTED_SOURCES",
        "a flag; no value can fail to parse",
    ),
    // **The seven model paths (ROADMAP O155).** These became `Protects` with
    // the other mandatory operands, and unlike the seven outward paths that
    // moved with them — which turned out to be pre-flightable and now are —
    // these seven genuinely are not. Two reasons they share, stated once so
    // per-row lines can say what is true of each one alone:
    //
    // **The value's meaning is whether it LOADS, and loading is what this
    // command does not do.** Every other arm in `check_one` is a string-to-
    // value parse; a model path's only real question is answered by compiling
    // a graph or building a tokenizer, which costs seconds, allocates, and
    // needs the weights to be present on the machine running the check.
    //
    // **Existence is the wrong question and would be a worse answer than
    // none.** `Path::exists` runs no I/O worth the name and could be added in
    // a line, and it would make this command report a green path that the
    // runtime then refuses — the `Accepted`-is-a-lie defect wearing a tick
    // instead of a shrug. It is also measured on the wrong machine: a CI job
    // pre-flights the deployment's ENVIRONMENT, not its filesystem, and the
    // host that will open the file is usually not the one running the check.
    //
    // Worth knowing, though not the reason on its own: both loaders live
    // behind `--features onnx` / `ort`, so an arm calling them would be
    // unreachable from the default binary an operator actually pre-flights
    // with. That is the same argument O52 made for `UNDERCROFT_ORT_POOL`,
    // which is why that row's parse sits in `undercroft-core` instead — a
    // move no model FILE can make.
    (
        "UNDERCROFT_ONNX_MODEL",
        "an ONNX graph tract must compile into a fixed-shape plan; a readable \
         file can still carry ops the runtime rejects, which only loading shows",
    ),
    (
        "UNDERCROFT_ONNX_TOKENIZER",
        "a tokenizers JSON whose vocabulary must match the model's embedding \
         table; mismatch is invisible per-file and is what O150 measured — an \
         id past the table panics tract and degrades ORT",
    ),
    (
        "UNDERCROFT_RERANK_MODEL",
        "a cross-encoder export, and the file that loads may still be an \
         EMBEDDER: what makes it a reranker is the output shape of a forward \
         pass, which this command does not run",
    ),
    (
        "UNDERCROFT_RERANK_TOKENIZER",
        "tokenizes query/passage PAIRS, so the same file that is correct for \
         the embedder can be wrong here — a distinction no property of the \
         path carries",
    ),
    (
        "UNDERCROFT_COLBERT_MODEL",
        "the doc-length export, correct only RELATIVE to the query export it \
         is paired with (their dimensions must agree), so no per-row check of \
         this value can be the check that matters",
    ),
    (
        "UNDERCROFT_COLBERT_QUERY_MODEL",
        "the query-length export; the loader probes only this one, so an \
         always-failing doc model still loads — a pre-flight cannot honestly \
         be stricter about the pair than the loader is",
    ),
    (
        "UNDERCROFT_COLBERT_TOKENIZER",
        "shared by both plans, and exercised by neither at load: the ColBERT \
         probes bypass it with hard-coded ids, so even the real loader does \
         not learn whether this file is usable",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-four #9's gate. **Every `Protects` variable is either
    /// pre-flighted or on the exempt list, and the list cannot go stale
    /// because it is counted in both directions.**
    ///
    /// The defect this closes is not "three arms were missing" — it is that
    /// nothing could tell. `check_declaration`'s catch-all renders an
    /// unknown name as `Accepted`, printed as *"no parse to run; the
    /// consumer validates it"*, which is indistinguishable from a variable
    /// that genuinely has no parse. Measured against the binary,
    /// `config check` exited 0 for `UNDERCROFT_RETRIEVAL`,
    /// `UNDERCROFT_EMBEDDER` and `UNDERCROFT_ADMISSION_LLM` while the same
    /// environment failed to start — and `UPGRADING.md` tells operators that
    /// exit 0 means none of its entries affect them.
    #[test]
    fn every_protects_variable_is_pre_flighted_or_exempt() {
        let exempt: std::collections::BTreeMap<&str, &str> =
            PREFLIGHT_EXEMPT.iter().copied().collect();
        let mut unchecked = Vec::new();
        let mut protects = 0usize;
        for (name, class, _) in ENGINE_ENV_VARS {
            if *class != ConfigClass::Protects {
                continue;
            }
            protects += 1;
            // A value no vocabulary can contain. `Accepted` here means this
            // command ran no parse at all for a variable whose refusal is
            // fatal.
            let accepted = matches!(check_one(name, "\u{1}not-a-legal-value"), Finding::Accepted);
            match (accepted, exempt.contains_key(name)) {
                (true, false) => unchecked.push(format!(
                    "  {name} — Protects, but this command runs no parse for it. \
                     Give it an arm, or add it to PREFLIGHT_EXEMPT with a reason."
                )),
                (false, true) => unchecked.push(format!(
                    "  {name} — listed in PREFLIGHT_EXEMPT but IS pre-flighted now. \
                     Good news: delete the exemption."
                )),
                _ => {}
            }
        }
        // **The third direction (ROADMAP O155): the exempt list's own
        // universe.** The loop above `continue`s on every non-`Protects` row,
        // so it can never visit an entry naming one — or naming nothing at
        // all. Without this, an exemption left behind by a reclassification
        // reads like an argued decision and is checked by no one, which is
        // precisely the staleness this command exists to report one list over.
        let known: std::collections::BTreeMap<&str, ConfigClass> =
            ENGINE_ENV_VARS.iter().map(|(n, c, _)| (*n, *c)).collect();
        let mut exemptions_seen = 0usize;
        for (name, _) in PREFLIGHT_EXEMPT {
            exemptions_seen += 1;
            match known.get(name) {
                None => unchecked.push(format!(
                    "  {name} — exempt from a pre-flight, but no such variable is in \
                     ENGINE_ENV_VARS. Either the engine stopped honouring it (delete the \
                     exemption) or the name is misspelt, which exempts nothing."
                )),
                Some(ConfigClass::Tunes) => unchecked.push(format!(
                    "  {name} — exempt from a pre-flight, but it is classed Tunes, and \
                     only a Protects row needs an exemption. Its reason is now unread: \
                     delete it, or restore the class it was written for."
                )),
                Some(ConfigClass::Protects) => {}
            }
        }
        // PREMISE. A filter that matched nothing would report a clean tree.
        assert!(
            protects >= 20,
            "premise failed: only {protects} Protects variables found — the \
             inventory is not being read"
        );
        // PREMISE for the direction above. It counts what the LOOP visited,
        // not what the const holds: `PREFLIGHT_EXEMPT.is_empty()` is folded at
        // compile time (clippy says so), so an assertion on it is dead code
        // wearing a premise probe's clothes — this file's own trap, one gate
        // over.
        assert!(
            exemptions_seen > 0,
            "premise failed: the exempt-list direction visited no entry"
        );
        assert!(
            unchecked.is_empty(),
            "`config check` and the Protects class disagree:\n{}",
            unchecked.join("\n")
        );
    }

    /// **ROADMAP O52's gate: the `Parse` axis is counted against the code in
    /// both directions.**
    ///
    /// The defect is not "some arms were missing" — it is that nothing could
    /// tell. `check_one`'s catch-all renders any unknown name as `Accepted`,
    /// printed as *"no parse to run; the consumer validates it"*, which reads
    /// identically for a path with genuinely nothing to parse and for a knob
    /// whose parse somebody forgot. Round-four #9 closed that for `Protects`;
    /// this closes it for every class, which matters because O48 had just
    /// taught eleven `Tunes` resolvers to validate values the pre-flight was
    /// still describing as unvalidated.
    ///
    /// Both directions, because only the second keeps the inventory honest as
    /// the code grows: a `Checked` entry the pre-flight runs no parse for is a
    /// false claim to an operator, and an `Opaque` entry that IS pre-flighted
    /// is good news that has to be recorded rather than left to rot.
    #[test]
    fn every_checked_variable_is_pre_flighted_and_every_opaque_one_is_not() {
        use crate::parity::Parse;
        let mut wrong = Vec::new();
        let (mut checked, mut opaque) = (0usize, 0usize);
        for (name, _, parse) in ENGINE_ENV_VARS {
            // A value no vocabulary contains and no number parses. `Accepted`
            // for this means the command ran no parse at all.
            let ran_a_parse =
                !matches!(check_one(name, "\u{1}not-a-legal-value"), Finding::Accepted);
            match parse {
                Parse::Checked => {
                    checked += 1;
                    if !ran_a_parse {
                        wrong.push(format!(
                            "  {name} — declared Checked, but this command runs no parse for \
                             it. Wire an arm that calls the resolver the engine calls, or \
                             reclassify it Opaque."
                        ));
                    }
                }
                Parse::Opaque => {
                    opaque += 1;
                    if ran_a_parse {
                        wrong.push(format!(
                            "  {name} — declared Opaque, but IS pre-flighted now. Good news: \
                             reclassify it Checked."
                        ));
                    }
                }
            }
        }
        // PREMISE, both halves. A filter that matched nothing, or an axis
        // where every entry landed on one value, would report a clean tree.
        assert!(
            checked >= 40 && opaque >= 20,
            "premise failed: {checked} checked / {opaque} opaque — the axis is not populated"
        );
        assert!(
            wrong.is_empty(),
            "the Parse axis and `config check` disagree:\n{}",
            wrong.join("\n")
        );
    }

    /// The pre-flight's own arithmetic: `validated + accepted` must equal the
    /// number of declarations it looked at, and `accepted` must be exactly the
    /// `Opaque` ones. An operator reads those two totals as "checked" and "not
    /// checked", so they have to mean that.
    #[test]
    fn the_two_totals_an_operator_reads_are_the_two_halves_of_the_axis() {
        use crate::parity::Parse;
        let opaque: Vec<&str> = ENGINE_ENV_VARS
            .iter()
            .filter(|(_, _, p)| *p == Parse::Opaque)
            .map(|(n, _, _)| *n)
            .collect();
        assert!(!opaque.is_empty(), "premise: no Opaque entries");
        for name in &opaque {
            assert!(
                matches!(check_one(name, "anything-at-all"), Finding::Accepted),
                "{name} is Opaque, so it must report as unchecked rather than as \
                 checked-and-fine"
            );
        }
    }

    /// **The validator calls the engine's own resolvers, and this is the
    /// test that would notice if it ever stopped.**
    ///
    /// A pre-flight that reimplemented the parse would agree with itself and
    /// not with the code — worse than no pre-flight, because an operator
    /// would trust it. So the assertions here are that each verdict matches
    /// what the resolver returns, not that some string appears.
    #[test]
    fn every_checked_declaration_agrees_with_the_resolver_that_runs() {
        // Accepted by the resolver.
        for (name, good) in [
            ("UNDERCROFT_ADMISSION", "quarantine"),
            ("UNDERCROFT_ADMISSION", "off"),
            ("UNDERCROFT_TRUST_FLOOR", "trusted"),
            ("UNDERCROFT_TRUST_FLOOR", "off"),
            ("UNDERCROFT_READ_AUDIT", "chain"),
            ("UNDERCROFT_SEMANTIC_GATE", "0.7"),
            ("UNDERCROFT_SEMANTIC_GATE", "off"),
            ("UNDERCROFT_ADMISSION_RATE", "120/60"),
            // The seven outward paths (ROADMAP O155). TLS to a named host,
            // and — for the DSN — libpq's own default of the local socket.
            ("UNDERCROFT_QDRANT_URL", "https://q.example"),
            ("UNDERCROFT_CHROMA_URL", "https://c.example"),
            ("UNDERCROFT_MILVUS_URL", "https://m.example"),
            ("UNDERCROFT_WEAVIATE_URL", "https://w.example"),
            ("UNDERCROFT_EMBED_URL", "https://e.example"),
            ("UNDERCROFT_LLM_URL", "http://127.0.0.1:11434"),
            ("UNDERCROFT_PGVECTOR_DSN", "dbname=x"),
            ("UNDERCROFT_PGVECTOR_DSN", "host=db.example sslmode=require"),
        ] {
            assert!(
                matches!(check_one(name, good), Finding::Ok(_)),
                "{name}={good:?} is accepted by its resolver and must be accepted here"
            );
        }
        // Refused by the resolver, and every one of these is a `Protects`
        // variable, so the pre-flight must call it FATAL rather than warn.
        for (name, bad) in [
            ("UNDERCROFT_ADMISSION", "quarantien"),
            ("UNDERCROFT_TRUST_FLOOR", "trusetd"),
            ("UNDERCROFT_READ_AUDIT", "yes"),
            ("UNDERCROFT_SEMANTIC_GATE", "1.5"),
            ("UNDERCROFT_ADMISSION_RATE", "120"),
            ("UNDERCROFT_EMBED_CA", ""),
            ("UNDERCROFT_ORCH_ENGINE_CA", "   "),
            // **The defect O155's reclassification exposed.** Every row here
            // used to answer `Accepted` — `config check` exited 0 and said
            // *"declared Opaque: no parse exists"* — while the client refuses
            // each of them at construction, before a byte moves. That is
            // round-four #9's "exit 0 for an environment that does not start",
            // surviving on seven rows because the class that makes the gate
            // look at them said `Tunes`.
            ("UNDERCROFT_QDRANT_URL", "http://qdrant.internal:6333"),
            ("UNDERCROFT_CHROMA_URL", "http://chroma.internal:8000"),
            ("UNDERCROFT_MILVUS_URL", "http://milvus.internal:19530"),
            ("UNDERCROFT_WEAVIATE_URL", "http://weaviate.internal:8080"),
            ("UNDERCROFT_EMBED_URL", "http://embeddings.internal"),
            ("UNDERCROFT_LLM_URL", "http://ollama.internal:11434"),
            // Cleartext to a non-loopback database, and O90's two spellings
            // that a hand-read of the string let through as loopback.
            ("UNDERCROFT_PGVECTOR_DSN", "host=10.0.0.5 dbname=x"),
            ("UNDERCROFT_PGVECTOR_DSN", "hostaddr=10.0.0.5 dbname=x"),
            // Empty is a failed interpolation, never a declaration, and it
            // refuses at the consumer too: an unparseable URL is cleartext
            // and is not loopback, which is the safe direction.
            ("UNDERCROFT_QDRANT_URL", ""),
            ("UNDERCROFT_EMBED_URL", "   "),
        ] {
            assert!(
                matches!(check_one(name, bad), Finding::Fatal(_)),
                "{name}={bad:?} is refused by its resolver and must be FATAL here"
            );
        }
        // A variable with no parse is reported as unchecked, never as
        // checked-and-fine. `UNDERCROFT_HOME` is `Tunes, Opaque` — a path
        // with a real default — and stays the example here; the row that
        // used to sit beside it was `UNDERCROFT_QDRANT_URL`, which had no
        // parse and now has one, so it moved up into both lists above.
        assert!(matches!(
            check_one("UNDERCROFT_HOME", "/anything"),
            Finding::Accepted
        ));
    }

    /// A `Tunes` variable that fails to parse warns rather than refusing —
    /// the other half of the doctrine, and the half a one-sided test would
    /// miss. `ENGINE_ENV_VARS` classifies every name, so this asserts the
    /// classification is actually consulted.
    #[test]
    fn the_class_decides_whether_a_refusal_is_fatal() {
        use crate::parity::{ConfigClass, ENGINE_ENV_VARS};
        let protects = ENGINE_ENV_VARS
            .iter()
            .filter(|(_, c, _)| *c == ConfigClass::Protects)
            .count();
        let tunes = ENGINE_ENV_VARS
            .iter()
            .filter(|(_, c, _)| *c == ConfigClass::Tunes)
            .count();
        assert!(
            protects > 5 && tunes > 5,
            "premise: both classes are populated ({protects} protects, {tunes} tunes)"
        );
        // **The hand-written list of nine names that used to live here is
        // GONE** (ROADMAP O155). Its comment promised that "every name the
        // validator can refuse must be classified", but the list of names
        // that CAN refuse was maintained by hand — so a variable that gained
        // a refusal was never added to it, and the converse (a `Tunes`
        // variable that actually refuses) was not asked at all. Two lists
        // agreeing with each other, which is O80's rule one axis over:
        // neither side came from the code.
        //
        // `every_checked_declaration_answers_garbage_the_way_its_class_says`
        // replaces it and strictly contains it: the universe is
        // `ENGINE_ENV_VARS`, the verdict comes from the real resolver, and
        // it runs in BOTH directions over all 49 `Checked` declarations.
        // Keeping the list as well would be a second implementation of one
        // decision — and the weaker one.
    }

    /// **The class is a claim about CONSEQUENCE, and until O155 nothing
    /// checked it against one.**
    ///
    /// The test above asserts that NINE names somebody remembered are
    /// `Protects`. Its own comment says *"every name the validator can
    /// refuse must be classified"* — but the list of names that can refuse
    /// is hand-maintained, so a variable that GAINS a refusal is never added
    /// to it, and the converse (a `Tunes` variable that actually refuses) is
    /// not asked at all. Two lists agreeing with each other, which is O80's
    /// rule one axis over: neither side was derived from the code.
    ///
    /// This derives its universe from `ENGINE_ENV_VARS` and its verdict from
    /// the REAL resolver, by feeding every `Checked` declaration a value no
    /// parse can accept and requiring the Finding to match the class:
    /// `Protects` must be `Fatal`, `Tunes` must be `Warn`.
    ///
    /// Two other outcomes are failures with their own meaning. `Ok` means a
    /// resolver accepted deliberate garbage, so its "parse" validates
    /// nothing. `Accepted` means no parse ran at all, which is the `Checked`
    /// axis lying — the defect O52 closed for `Protects` and O48 widened to
    /// `Tunes`, now checked for both from one place.
    ///
    /// Not a duplicate of
    /// `every_checked_declaration_agrees_with_the_resolver_that_runs`, and
    /// the division of labour is worth stating so a later reader does not
    /// delete the wrong one: that test drives HAND-CHOSEN values — including
    /// VALID ones, which this cannot — over a named sample, and is the only
    /// thing asserting that a good value is still accepted. This one drives
    /// only unacceptable values, but over EVERY `Checked` row, with the
    /// universe taken from the inventory rather than from a list.
    ///
    /// Blind spot, stated because it is where this class actually drifted:
    /// an `Opaque` declaration has no parse, so it CANNOT be driven here and
    /// its `ConfigClass` decides nothing — `check_one` returns `Accepted`
    /// before the class is ever consulted. For those rows the class is
    /// documentation rather than a gate, and that is exactly why the
    /// model-path operands sat misclassified (ROADMAP O155).
    #[test]
    fn every_checked_declaration_answers_garbage_the_way_its_class_says() {
        use crate::parity::{ConfigClass, Parse, ENGINE_ENV_VARS};
        // Rejected by a number parser, a closed vocabulary, a path that must
        // open, an address, a duration and a rate alike.
        const GARBAGE: &str = "!!undercroft-not-a-valid-value!!";

        // **TWO unacceptable values, because "invalid" has two shapes** and
        // driving only one misreads five variables. A closed vocabulary, a
        // number, a path or an address rejects an arbitrary string; an
        // OPAQUE PAYLOAD — a passphrase, a bearer — has no vocabulary, so an
        // arbitrary string is a perfectly good value for it and the only
        // thing it cannot be is EMPTY. That is the tree's own
        // vocabulary-versus-payload rule, and the first version of this gate
        // reported all five secrets as defects for want of it.
        //
        // So a declaration passes if SOME unacceptable value produces the
        // outcome its class promises, and fails if ANY produces the opposite
        // one — a `Protects` variable must never merely warn, and a `Tunes`
        // knob must never refuse.
        let unacceptable = [GARBAGE, ""];
        let mut wrong: Vec<String> = Vec::new();
        let mut driven = 0usize;
        for (name, class, parse) in ENGINE_ENV_VARS {
            if *parse != Parse::Checked {
                continue;
            }
            driven += 1;
            let found: Vec<Finding> = unacceptable.iter().map(|v| check_one(name, v)).collect();
            let promised = found.iter().any(|f| {
                matches!(
                    (f, class),
                    (Finding::Fatal(_), ConfigClass::Protects)
                        | (Finding::Warn(_), ConfigClass::Tunes)
                )
            });
            let contradicted = found.iter().any(|f| {
                matches!(
                    (f, class),
                    (Finding::Warn(_), ConfigClass::Protects)
                        | (Finding::Fatal(_), ConfigClass::Tunes)
                )
            });
            if contradicted {
                wrong.push(format!(
                    "  {name}: declared {class:?}, but an unacceptable value produced the OPPOSITE verdict"
                ));
            } else if !promised {
                let got = if found.iter().any(|f| matches!(f, Finding::Accepted)) {
                    "Accepted — no parse ran, so `Checked` is not true of it"
                } else {
                    "Ok for every unacceptable value — its parse validates nothing"
                };
                wrong.push(format!("  {name}: declared {class:?}, but {got}"));
            }
        }

        // PREMISE PROBE. A loop that drove nothing reports exactly what a
        // clean inventory reports.
        assert!(
            driven > 40,
            "premise: only {driven} Checked declaration(s) were driven"
        );
        assert!(
            wrong.is_empty(),
            "the ConfigClass claim disagrees with what the resolver actually does:\n{}",
            wrong.join("\n")
        );
    }
}
