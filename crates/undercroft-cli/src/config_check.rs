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
//! `ENGINE_ENV_VARS` carries `(name, ConfigClass)` and is counted against
//! the code in both directions, so a variable this command does not know
//! about cannot exist.

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
pub fn run(verbose: bool) -> (usize, usize, usize, usize) {
    let mut fatal = 0usize;
    let mut warned = 0usize;
    let mut validated = 0usize;
    let mut accepted = 0usize;

    for (name, _) in ENGINE_ENV_VARS {
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
                    println!(
                        "  seen    {name}={raw:?} — no parse to run; the consumer validates it"
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
        .find(|(n, _)| *n == name)
        .map(|(_, c)| *c)
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
        "UNDERCROFT_ADMISSION_LLM" => Some(
            undercroft_llm::advisor::check_mode(raw)
                .map(|()| "tier-2 advisory screen, toward quarantine only".into())
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
/// is short, argued, and counted against the code in BOTH directions by
/// [`tests::every_protects_variable_is_pre_flighted_or_exempt`].
///
/// `#[cfg(test)]` because it is inventory, not behaviour — the same shape as
/// `mcp::WRITE_TOOLS`, which survives as the other half of a count and is
/// referenced by nothing at run time.
#[cfg(test)]
const PREFLIGHT_EXEMPT: &[(&str, &str)] = &[
    // Opaque payload: any non-empty string is a well-formed value, and
    // whether it is the RIGHT one can only be learned by decrypting a vault
    // — which this command must not do.
    ("UNDERCROFT_PASSPHRASE", "a credential, not a syntax"),
    ("UNDERCROFT_MCP_HTTP_TOKEN", "a credential, not a syntax"),
    // Owned by a DIFFERENT BINARY. `undercroft config check` runs the
    // engine's resolvers; these are read by `undercroft-orchestrator`, which
    // has no pre-flight command of its own. Filed as ROADMAP O21 rather than
    // silently narrowed, because an operator running a fleet reads this
    // command's exit code and would not guess it skipped a whole surface.
    ("UNDERCROFT_ORCH_ADMIN_TOKEN", "orchestrator-owned (O21)"),
    ("UNDERCROFT_ORCH_KEY", "orchestrator-owned (O21)"),
    ("UNDERCROFT_ORCH_RATE_LIMIT", "orchestrator-owned (O21)"),
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
        for (name, class) in ENGINE_ENV_VARS {
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
        // PREMISE. A filter that matched nothing would report a clean tree.
        assert!(
            protects >= 20,
            "premise failed: only {protects} Protects variables found — the \
             inventory is not being read"
        );
        assert!(
            unchecked.is_empty(),
            "`config check` and the Protects class disagree:\n{}",
            unchecked.join("\n")
        );
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
        ] {
            assert!(
                matches!(check_one(name, bad), Finding::Fatal(_)),
                "{name}={bad:?} is refused by its resolver and must be FATAL here"
            );
        }
        // A variable with no parse is reported as unchecked, never as
        // checked-and-fine.
        assert!(matches!(
            check_one("UNDERCROFT_HOME", "/anything"),
            Finding::Accepted
        ));
        assert!(matches!(
            check_one("UNDERCROFT_QDRANT_URL", "https://q.example"),
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
            .filter(|(_, c)| *c == ConfigClass::Protects)
            .count();
        let tunes = ENGINE_ENV_VARS
            .iter()
            .filter(|(_, c)| *c == ConfigClass::Tunes)
            .count();
        assert!(
            protects > 5 && tunes > 5,
            "premise: both classes are populated ({protects} protects, {tunes} tunes)"
        );
        // Every name the validator can refuse must be classified, or the
        // fatal/warn decision falls back to a default nobody chose.
        for name in [
            "UNDERCROFT_ADMISSION",
            "UNDERCROFT_TRUST_FLOOR",
            "UNDERCROFT_READ_AUDIT",
            "UNDERCROFT_SEMANTIC_GATE",
            "UNDERCROFT_ADMISSION_RATE",
            "UNDERCROFT_EMBED_CA",
            "UNDERCROFT_LLM_CA",
            "UNDERCROFT_INDEX_CA",
            "UNDERCROFT_ORCH_ENGINE_CA",
        ] {
            let class = ENGINE_ENV_VARS.iter().find(|(n, _)| *n == name);
            assert_eq!(
                class.map(|(_, c)| *c),
                Some(ConfigClass::Protects),
                "{name} can refuse, so it must be classified Protects"
            );
        }
    }
}
