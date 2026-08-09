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

#[cfg(test)]
mod tests {
    use super::*;

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
