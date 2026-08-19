//! `undercroft-orchestrator config check` — validate every declaration
//! WITHOUT opening the state database or binding a port.
//!
//! **Why this exists (ROADMAP O21).** `undercroft config check` runs the
//! ENGINE's resolvers. Four `UNDERCROFT_ORCH_*` declarations are read by this
//! binary instead, and it had no pre-flight command at all — so three of them
//! sat on the engine's `PREFLIGHT_EXEMPT` list with "orchestrator-owned" as
//! the reason. `UPGRADING.md` tells an operator that if `config check` exits
//! 0, none of its entries affect them; for a fleet running the control plane
//! that promise was narrower than it read, and nothing on either surface said
//! so.
//!
//! Every arm calls the **same resolver the serve path calls**, never a second
//! copy of a parse. A validator that agreed with its own reimplementation
//! rather than with the code would be the defect class this exists to close.
//! Two of those resolvers had to be extracted to make that possible, and that
//! extraction is most of the value: the orchestrator key was decoded inline
//! in `Orch::open` AND `Orch::open_read_only`, and the admin token's length
//! floor was an `if` in the `serve` arm — none of them reachable without
//! opening a database or binding a port.

use undercroft_config::{
    resolve_admin_token, resolve_metrics_addr, resolve_metrics_token, resolve_orch_key,
    resolve_rate_limit,
};

/// What a bad value does, per `CLAUDE.md`'s configuration doctrine.
///
/// Deliberately a second, tiny copy of the engine's enum rather than a shared
/// crate: the orchestrator is a pure `/v1` client and **must not link the
/// engine's CLI** (nor the engine this one). What must not drift is the
/// CLASSIFICATION, and that is counted across the two crates by
/// [`tests::the_orchestrator_and_the_engine_agree_on_every_orch_variable`],
/// which reads the engine's inventory as SOURCE — the only route two crates
/// that cannot see each other have.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ConfigClass {
    /// Garbage refuses: the declaration is what turns a protection on, so a
    /// silent fallback removes what was asked for.
    Protects,
    /// Garbage warns and keeps the conservative default already in place.
    Tunes,
}

use ConfigClass::{Protects, Tunes};

/// Whether this command runs a real parse for a declaration — the engine's
/// `parity::Parse`, duplicated deliberately.
///
/// ROADMAP O58. The engine gained this axis in O52 and **this binary, whose
/// inventory is counted against the engine's in both directions, did not** —
/// so one of two sibling pre-flights learned to say which declarations it had
/// actually checked and the other kept printing *"no parse to run; the
/// consumer validates it"* about all of them. That drift was introduced by
/// O52 itself, in this session, and is reported as mine.
///
/// Duplicated rather than imported because the control plane deliberately
/// never links the engine — the same reason `ConfigClass` is duplicated ten
/// lines above. The cross-inventory gate below now compares this axis too, by
/// reading the engine's source, so the two copies cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Parse {
    /// This command runs the real resolver for the declaration.
    Checked,
    /// There is no parse to run: a listen address this command must not bind,
    /// a database path it must not open. Saying so is honest; saying
    /// "checked" would not be.
    Opaque,
}

use Parse::{Checked, Opaque};

/// Every declaration THIS binary reads, with what a bad value does.
///
/// Counted against the engine's `ENGINE_ENV_VARS` in both directions, so a
/// variable added to one and not the other fails the build.
pub(crate) const ORCH_ENV_VARS: &[(&str, ConfigClass, Parse)] = &[
    ("UNDERCROFT_ORCH_ADDR", Tunes, Opaque),
    ("UNDERCROFT_ORCH_ADMIN_TOKEN", Protects, Checked),
    ("UNDERCROFT_ORCH_DB", Tunes, Opaque),
    ("UNDERCROFT_ORCH_ENGINE_CA", Protects, Checked),
    ("UNDERCROFT_ORCH_KEY", Protects, Checked),
    ("UNDERCROFT_ORCH_METRICS_ADDR", Protects, Checked),
    ("UNDERCROFT_ORCH_METRICS_TOKEN", Protects, Checked),
    ("UNDERCROFT_ORCH_RATE_LIMIT", Protects, Checked),
];

/// What checking one declaration found.
enum Finding {
    Ok(String),
    Accepted,
    Fatal(String),
    Warn(String),
}

/// One declaration, through the resolver that will run at start-up.
fn check_one(name: &str, raw: &str) -> Finding {
    let class = ORCH_ENV_VARS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, c, _)| *c)
        .unwrap_or(Tunes);
    let result: Option<Result<String, String>> = match name {
        "UNDERCROFT_ORCH_KEY" => Some(
            resolve_orch_key(Some(raw))
                .map(|_| "seals instance credentials and MACs tenant tokens".into())
                .map_err(|e| e.to_string()),
        ),
        "UNDERCROFT_ORCH_ADMIN_TOKEN" => Some(
            resolve_admin_token(Some(raw))
                .map(|_| "bearer required on the /admin plane".into())
                .map_err(|e| e.to_string()),
        ),
        "UNDERCROFT_ORCH_METRICS_ADDR" => Some(
            resolve_metrics_addr(Some(raw))
                .and_then(|a| match a {
                    Some(a) => {
                        // **The ADDRESS arm checks the TOKEN too**, and that is not
                        // redundancy. `config check` only iterates declarations that
                        // are SET, so a non-loopback address with no token declared
                        // was invisible to it — the pre-flight exited 0 for an
                        // environment that refuses to start, which is the exact
                        // promise it exists to keep. Found by a premise probe on the
                        // corpus run, not by a test.
                        resolve_metrics_token(
                            &a,
                            std::env::var("UNDERCROFT_ORCH_METRICS_TOKEN")
                                .ok()
                                .as_deref(),
                        )
                        .map(|t| match t {
                            Some(_) => format!("metrics listener on {a}, behind a token"),
                            None => format!("metrics listener on {a} (loopback, no token)"),
                        })
                    }
                    None => Ok("no metrics listener".into()),
                })
                .map_err(|e| e.to_string()),
        ),
        // Checked against the address it guards, because "is a token
        // required" is a question about the ADDRESS: loopback needs none and
        // anything else does. Reading it alone would validate the string and
        // miss the only rule that matters.
        "UNDERCROFT_ORCH_METRICS_TOKEN" => Some(
            resolve_metrics_token(
                &std::env::var("UNDERCROFT_ORCH_METRICS_ADDR").unwrap_or_default(),
                Some(raw),
            )
            .map(|_| "bearer required on the metrics listener".into())
            .map_err(|e| e.to_string()),
        ),
        "UNDERCROFT_ORCH_RATE_LIMIT" => Some(
            resolve_rate_limit(Some(raw))
                .map(|n| match n {
                    0 => "no rate screen".to_string(),
                    n => format!("{n} requests/minute per tenant"),
                })
                .map_err(|e| e.to_string()),
        ),
        // The CA pin goes through `undercroft-net`'s own resolver — the same
        // one the engine's pre-flight runs for the other four pins, so the
        // two commands cannot disagree about what pins a hop. It does read
        // the PEM off disk, which is a file read and not an outbound call or
        // a database: the pin has to load or the hop is un-pinned, and
        // learning that at start-up is the whole point of this command.
        "UNDERCROFT_ORCH_ENGINE_CA" => Some(
            undercroft_net::declared_pin("the engine hop", Some(raw))
                .map(|p| match p {
                    Some(_) => "engine hop pinned to this root (public roots replaced)".into(),
                    None => "no pin".to_string(),
                })
                .map_err(|e| e.to_string()),
        ),
        // A listen address and a database path have no parse this command can
        // run without binding or opening. Reported as seen, never as checked.
        _ => None,
    };
    match result {
        None => Finding::Accepted,
        Some(Ok(what)) => Finding::Ok(what),
        Some(Err(why)) => match class {
            Protects => Finding::Fatal(why),
            Tunes => Finding::Warn(format!(
                "{why}; this one keeps the conservative default rather than refusing"
            )),
        },
    }
}

/// Run every declaration present in the environment through its real
/// resolver. Returns (fatal, warned, validated, accepted).
pub(crate) fn run(verbose: bool) -> (usize, usize, usize, usize) {
    let (mut fatal, mut warned, mut validated, mut accepted) = (0, 0, 0, 0);
    for (name, _, _) in ORCH_ENV_VARS {
        let Ok(raw) = std::env::var(name) else {
            continue; // Undeclared is not a finding.
        };
        match check_one(name, &raw) {
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
                        "  seen    {name}={raw:?} — declared Opaque: no parse exists, so its consumer is the only real validation"
                    );
                }
            }
            Finding::Warn(why) => {
                validated += 1;
                warned += 1;
                println!("  warn    {name}={raw:?} — {why}");
            }
            Finding::Fatal(why) => {
                validated += 1;
                fatal += 1;
                println!("  REFUSES {name}={raw:?} — {why}");
            }
        }
    }
    (fatal, warned, validated, accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every `Protects` declaration this binary reads is pre-flighted.**
    ///
    /// There is deliberately no exempt list here. The engine needed one and
    /// argued each entry; this binary reads four `Protects` variables and can
    /// check all four, so an exemption would be a place for a gap to hide
    /// rather than a boundary with a reason. If one is ever genuinely
    /// unpre-flightable, add the list back — and say which of *"is it
    /// absent"* and *"is it correct"* cannot be answered, because that
    /// distinction is what made the engine's first two exemptions too broad.
    #[test]
    fn every_protects_variable_is_pre_flighted() {
        let mut unchecked = Vec::new();
        let mut protects = 0usize;
        for (name, class, _) in ORCH_ENV_VARS {
            if *class != Protects {
                continue;
            }
            protects += 1;
            // A value no vocabulary and no encoding can contain.
            if matches!(check_one(name, "\u{1}not-a-legal-value"), Finding::Accepted) {
                unchecked.push(*name);
            }
        }
        // PREMISE. A filter that matched nothing would report a clean tree.
        assert_eq!(
            protects, 6,
            "premise failed: expected 6 Protects variables, found {protects} — the \
             inventory is not being read"
        );
        assert!(
            unchecked.is_empty(),
            "these Protects declarations have no parse in `config check`: {unchecked:?}"
        );
    }

    /// ROADMAP O58. **The engine's O52 gate, on this binary** — every
    /// `Checked` declaration is pre-flighted and every `Opaque` one is not,
    /// counted in both directions.
    ///
    /// O52 gave the ENGINE's pre-flight a `Parse` axis so it could say which
    /// declarations it had actually run a parse for, instead of printing "no
    /// parse to run" whether or not one existed. This binary — whose
    /// inventory is counted against the engine's in both directions by the
    /// test below — kept the undifferentiated message. One of two sibling
    /// commands learned to tell the truth about its own coverage; that is
    /// the 65-drift shape, created by the fix rather than found by it.
    #[test]
    fn every_checked_variable_is_pre_flighted_and_every_opaque_one_is_not() {
        let mut wrong = Vec::new();
        let (mut checked, mut opaque) = (0usize, 0usize);
        for (name, _, parse) in ORCH_ENV_VARS {
            let ran_a_parse =
                !matches!(check_one(name, "\u{1}not-a-legal-value"), Finding::Accepted);
            match parse {
                Checked => {
                    checked += 1;
                    if !ran_a_parse {
                        wrong.push(format!(
                            "  {name} — declared Checked, but this command runs no parse for \
                             it. Wire an arm calling the resolver `serve` calls, or \
                             reclassify it Opaque."
                        ));
                    }
                }
                Opaque => {
                    opaque += 1;
                    if ran_a_parse {
                        wrong.push(format!(
                            "  {name} — declared Opaque, but IS pre-flighted now. Good news: \
                             reclassify it Checked, and the engine's inventory with it."
                        ));
                    }
                }
            }
        }
        // PREMISE, both halves: an axis where every entry landed on one value
        // would report a clean tree.
        assert!(
            checked >= 5 && opaque >= 1,
            "premise failed: {checked} checked / {opaque} opaque — the axis is not populated"
        );
        assert!(
            wrong.is_empty(),
            "the Parse axis and this pre-flight disagree:\n{}",
            wrong.join("\n")
        );
    }

    /// The two crates cannot link each other — the engine is tree-blind and
    /// this binary is a pure `/v1` client — so the inventories are counted
    /// across the SOURCE, in both directions, name and class.
    ///
    /// Without it, `ENGINE_ENV_VARS` and [`ORCH_ENV_VARS`] are two hand-kept
    /// lists of the same six variables, which is the arrangement whose first
    /// instance in this tree shipped five dead gauge names.
    #[test]
    fn the_orchestrator_and_the_engine_agree_on_every_orch_variable() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../undercroft-cli/src/parity.rs"
        );
        let src = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read the engine inventory at {path}: {e}"));

        // Matching `("UNDER…CROFT_ORCH_X", Protects),`. The needle is SPLIT,
        // and not for tidiness: the engine's own inventory gate scans every
        // `.rs` file under `crates/` for a quoted `UNDER…CROFT_` literal and
        // requires each one to be a variable it knows. Written contiguously,
        // this line declares a variable called `UNDERCROFT_ORCH_` — the bare
        // prefix — and fails that gate. It did, on the first battery. One
        // gate's needle is another gate's input.
        let mut engine: Vec<(String, ConfigClass, Parse)> = Vec::new();
        for line in src.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix(concat!('(', '"', "UNDER", "CROFT_ORCH_")) else {
                continue;
            };
            let Some((name_tail, class_part)) = rest.split_once("\", ") else {
                continue;
            };
            let class = if class_part.starts_with("Protects") {
                Protects
            } else if class_part.starts_with("Tunes") {
                Tunes
            } else {
                panic!("unrecognised class on engine inventory line: {line}");
            };
            // The engine's third field, since O58. Reading it here is what
            // keeps the two duplicated `Parse` enums from meaning different
            // things — the same reason this gate reads the class.
            let parse = if class_part.contains("Checked") {
                Checked
            } else if class_part.contains("Opaque") {
                Opaque
            } else {
                panic!(
                    "no Parse axis on engine inventory line: {line}. The engine gained \
                     `parity::Parse` in O52; if it is gone, remove it here too."
                );
            };
            engine.push((format!("UNDERCROFT_ORCH_{name_tail}"), class, parse));
        }

        // PREMISE. A parser that matched nothing reports two agreeing empty
        // sets, which reads exactly like a clean tree — the failure mode this
        // file's own doctrine names.
        assert!(
            engine.len() >= 6,
            "premise failed: parsed {} ORCH entries out of {path} — the scan found \
             nothing to compare, which is not the same as agreement",
            engine.len()
        );

        let mine: std::collections::BTreeMap<&str, (ConfigClass, Parse)> = ORCH_ENV_VARS
            .iter()
            .map(|(n, c, p)| (*n, (*c, *p)))
            .collect();
        let theirs: std::collections::BTreeMap<&str, (ConfigClass, Parse)> = engine
            .iter()
            .map(|(n, c, p)| (n.as_str(), (*c, *p)))
            .collect();

        for (name, (class, parse)) in &theirs {
            match mine.get(name) {
                None => panic!(
                    "{name} is in the engine's ENGINE_ENV_VARS and not in ORCH_ENV_VARS — \
                     this binary reads it and its pre-flight does not know it exists"
                ),
                Some((c, _)) if c != class => panic!(
                    "{name} is {class:?} to the engine and {c:?} here — one of them decides \
                     whether a bad value refuses or warns, and they must not disagree"
                ),
                // The axis, since O58. Two pre-flights telling an operator
                // different things about whether the SAME declaration was
                // checked is the drift this join exists to prevent.
                Some((_, p)) if p != parse => panic!(
                    "{name} is {parse:?} to the engine and {p:?} here — one of these two \
                     commands is telling an operator it checked a declaration the other \
                     says has no parse to run"
                ),
                _ => {}
            }
        }
        for name in mine.keys() {
            assert!(
                theirs.contains_key(name),
                "{name} is in ORCH_ENV_VARS and not in the engine's ENGINE_ENV_VARS — that \
                 inventory is what `architecture/index.html` and the env-count gate gate"
            );
        }
    }

    /// The admin token's three refusals, and the one value that is not a
    /// refusal. The trailing-whitespace arm is the live defect O22 found on
    /// the engine's identical path and left here on purpose, because a bare
    /// guard beside the length floor would have been a second implementation.
    ///
    /// The counterfactual is the LENGTH FLOOR: `"0123456789abcdef\n"` is 17
    /// characters, so the floor that was the only check here passed it, and a
    /// test asserting merely "a short token is refused" would have passed
    /// against the defect.
    #[test]
    fn an_admin_token_that_cannot_be_presented_is_refused() {
        assert!(resolve_admin_token(None).is_err());
        for empty in ["", " ", "\n", "   \t "] {
            let e = resolve_admin_token(Some(empty)).unwrap_err().to_string();
            assert!(e.contains("names no token"), "{e}");
        }
        for tailed in [
            "0123456789abcdef\n",
            "0123456789abcdef ",
            "0123456789abcdef\t",
        ] {
            assert!(
                tailed.len() >= 16,
                "premise: this value must CLEAR the length floor, or the test proves nothing"
            );
            let e = resolve_admin_token(Some(tailed)).unwrap_err().to_string();
            assert!(e.contains("ends in whitespace"), "{e}");
            assert!(!e.contains("at least 16"), "wrong diagnosis: {e}");
        }
        // Too short still refuses, and says so.
        let e = resolve_admin_token(Some("short")).unwrap_err().to_string();
        assert!(e.contains("at least 16"), "{e}");
        // Presentable whitespace is a value, not a typo — leading and
        // internal both answer 200 over HTTP, measured on the engine's path.
        for real in [" 0123456789abcdef", "0123 456789 abcdef"] {
            assert_eq!(resolve_admin_token(Some(real)).unwrap(), real);
        }
    }

    /// The key resolver refuses what the two `Orch::open`s used to refuse,
    /// plus the empty case neither said anything useful about, and it does it
    /// WITHOUT a database — which is the property that makes a pre-flight
    /// possible at all.
    #[test]
    fn the_orchestrator_key_resolves_without_opening_anything() {
        let good = "a".repeat(64);
        assert_eq!(resolve_orch_key(Some(&good)).unwrap().len(), 32);
        // Hex carries no whitespace, so trimming cannot change which key was
        // named — only remove the newline `$(cat orch.key)` leaves.
        assert_eq!(
            resolve_orch_key(Some(&format!("{good}\n"))).unwrap(),
            resolve_orch_key(Some(&good)).unwrap()
        );
        assert!(resolve_orch_key(None)
            .unwrap_err()
            .to_string()
            .contains("not set"));
        for empty in ["", "  ", "\n"] {
            assert!(resolve_orch_key(Some(empty))
                .unwrap_err()
                .to_string()
                .contains("names no key"));
        }
        assert!(resolve_orch_key(Some("zz"))
            .unwrap_err()
            .to_string()
            .contains("not hex"));
        assert!(resolve_orch_key(Some("aabb"))
            .unwrap_err()
            .to_string()
            .contains("32 bytes"));
    }

    /// The rate limit is a **closed vocabulary**, so empty legitimately means
    /// the default — the opposite answer from the secrets above, and the
    /// distinction is the whole of `CLAUDE.md`'s payload-vs-vocabulary rule.
    /// Pinned so a future sweep for `is_empty()` does not "fix" it.
    #[test]
    fn an_empty_rate_limit_is_the_default_and_not_a_refusal() {
        assert_eq!(resolve_rate_limit(None).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some("")).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some("off")).unwrap(), 0);
        assert_eq!(resolve_rate_limit(Some(" 600 ")).unwrap(), 600);
        assert!(resolve_rate_limit(Some("lots")).is_err());
    }
}
