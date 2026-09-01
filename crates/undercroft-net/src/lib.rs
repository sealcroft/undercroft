//! Outbound transport policy, in one place.
//!
//! Every Undercroft client that leaves this machine obeys the same two
//! rules, and this crate is the only implementation of them:
//!
//! * **TLS or loopback, nothing else, no override.** Cleartext `http` to a
//!   non-loopback host is refused at CONSTRUCTION, before a byte moves,
//!   and the error names the fix.
//! * **A declared CA is a PIN.** `pinned_roots` makes the PEM's
//!   certificates the *only* trust roots — the bundled public roots are
//!   deliberately absent, because a declaration that merely *adds* a root
//!   is not a pin. A garbage file refuses; it never falls back.
//!
//! It exists as its own crate because it was implemented once, in
//! `undercroft-llm`, for the embedder and the LLM client — and the remote
//! **index** backends had no transport policy at all (closed as ROADMAP
//! C8 — a breadcrumb into the CHANGELOG, not a live entry). Every
//! push carries embeddings, and an embedding is plaintext-DERIVED data:
//! the sealed-vault invariant seals them at rest for exactly that reason,
//! so shipping them in clear over a network is the same exposure one layer
//! out. Two copies of that rule would be two places for it to drift, which
//! is the defect class this branch spends its time closing.
//!
//! What this crate does NOT claim: TLS protects the wire, not the
//! destination. A remote endpoint still receives whatever you send it.

use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error(
        "{what} is configured with cleartext http to a non-loopback host ({url}). Drawer-derived \
         data would cross the network in the clear. Use https (terminate TLS in front of the \
         service — see deploy/embeddings-tls/ for a working example), or bind the service to \
         loopback. There is no override."
    )]
    Cleartext { what: &'static str, url: String },
    #[error("{what}: the declared trust root {path} {reason}")]
    BadPin {
        what: &'static str,
        path: String,
        reason: String,
    },
    #[error("{what}: {reason}")]
    Config { what: &'static str, reason: String },
}

/// Whether a base URL points at this machine.
///
/// Deliberately conservative: an unparseable or unusual host counts as NOT
/// loopback, so the refusal errs toward telling the operator their data is
/// leaving.
///
/// It asks the SAME parser the transport will use rather than re-deriving
/// the host by hand. Hand-parsing this string is how the predicate came to
/// disagree with ureq twice:
///
/// * `http://127.0.0.1:8080@evil.com/v1` — splitting the authority on `:`
///   returned the USERNAME `127.0.0.1`;
/// * `http://evil.com\@127.0.0.1/v1` — for a special scheme the WHATWG
///   parser treats `\` as a path separator, so the host is `evil.com`
///   while an `@`-split reads `127.0.0.1`.
///
/// Each time the gate INVERTED: "TLS or loopback, nothing else" passed, and
/// data went cleartext to an attacker-chosen host. The first fix enumerated
/// the spellings, which tests the enumeration; this one cannot disagree
/// with the transport, because it is the transport's own parser.
pub fn is_loopback(base: &str) -> bool {
    let Ok(parsed) = url::Url::parse(base) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(d)) => d == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Whether a base URL is cleartext (`http`, not `https`).
///
/// An unparseable URL is treated as cleartext for the same reason
/// [`is_loopback`] treats it as remote: the safe direction.
pub fn is_cleartext(base: &str) -> bool {
    match url::Url::parse(base) {
        Ok(u) => u.scheme() != "https",
        Err(_) => true,
    }
}

/// The policy itself: refuse cleartext beyond loopback.
///
/// `what` names the client in the error, because an operator with three
/// endpoints configured needs to know which one refused.
pub fn require_secure_transport(what: &'static str, base: &str) -> Result<(), NetError> {
    if is_cleartext(base) && !is_loopback(base) {
        return Err(NetError::Cleartext {
            what,
            url: base.to_string(),
        });
    }
    Ok(())
}

/// Build the pinned TLS configuration a declared CA file resolves to.
///
/// The PEM's certificates become the ONLY trust roots. Errors (empty file,
/// no parseable certificate, a root rustls rejects) are construction
/// refusals at the caller, never fallbacks — un-pinning silently is the
/// failure mode this exists to prevent.
pub fn pinned_roots(pem: &[u8]) -> Result<Arc<rustls::ClientConfig>, String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| format!("is not parseable as PEM certificates: {e}"))?;
    if certs.is_empty() {
        return Err("holds no certificate — a declared trust root that pins nothing".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    for c in certs {
        roots
            .add(c)
            .map_err(|e| format!("was rejected as a trust root: {e}"))?;
    }
    Ok(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// The bundled public trust roots, for a client that declared no pin.
///
/// Separate from [`pinned_roots`] on purpose: a declaration REPLACES these,
/// and a function that quietly merged the two would turn every pin into an
/// addition.
pub fn webpki_roots() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Read a CA file and turn it into pinned roots, classing both failures.
pub fn pinned_roots_from_file(
    what: &'static str,
    path: &str,
) -> Result<Arc<rustls::ClientConfig>, NetError> {
    let pem = std::fs::read(path).map_err(|e| NetError::BadPin {
        what,
        path: path.to_string(),
        reason: format!("could not be read: {e}"),
    })?;
    pinned_roots(&pem).map_err(|reason| NetError::BadPin {
        what,
        path: path.to_string(),
        reason,
    })
}

/// A declared CA file **already resolved** into trust roots.
///
/// Exists so a caller can pay the read-and-parse ONCE, at the moment it is
/// allowed to refuse, and hand the result to every later request. A client
/// that resolves its pin per outbound call turns a configuration error into
/// a runtime one: the process binds its port, reports healthy, and then
/// fails every request — which is precisely the shape
/// `RateLimiter::from_env` was moved in front of the bind to avoid.
///
/// Opaque on purpose. The `rustls` types stay inside this crate so a
/// consumer can hold a resolved pin without taking a TLS dependency of its
/// own, and so nothing outside here can assemble a `ClientConfig` that
/// skipped [`pinned_roots`]' refusals.
#[derive(Clone)]
pub struct Pin(Arc<rustls::ClientConfig>);

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pin(<resolved trust roots>)")
    }
}

/// Resolve a declared CA path into a [`Pin`], refusing here rather than later.
pub fn resolve_pin(what: &'static str, path: &str) -> Result<Pin, NetError> {
    pinned_roots_from_file(what, path).map(Pin)
}

/// What a DECLARED CA setting resolves to — the one place the four pins
/// agree about what an empty value means.
///
/// They did not agree. `UNDERCROFT_ORCH_ENGINE_CA=""` refused explicitly,
/// `UNDERCROFT_INDEX_CA=""` refused by accident (via `fs::read("")`), and
/// `UNDERCROFT_EMBED_CA=""` / `UNDERCROFT_LLM_CA=""` were **silently treated
/// as no pin** — un-pinning at exactly the moment an operator believes they
/// pinned, which is the failure mode all four doc comments name in the same
/// words. Three behaviours, one rule, four copies of the decision.
///
/// Unset is not a declaration and resolves to the public roots. An empty or
/// whitespace-only value IS a declaration, and it names no file, so it
/// refuses — the same verdict [`pinned_roots`] gives a file that holds no
/// certificate.
pub fn declared_pin(what: &'static str, declared: Option<&str>) -> Result<Option<Pin>, NetError> {
    match declared {
        None => Ok(None),
        Some(p) if p.trim().is_empty() => Err(NetError::Config {
            what,
            reason: "a declared trust root is set to an empty value. It names no file, so it \
                     pins nothing; unset it to use the public roots, or point it at a PEM. \
                     There is no silent fallback"
                .to_string(),
        }),
        Some(p) => resolve_pin(what, p.trim()).map(Some),
    }
}

/// A declared outward ENDPOINT, resolved once so the pre-flight and the run
/// cannot answer differently. `None` when nothing was declared — the
/// documented default, which for every hop in this workspace means the
/// process contacts nobody.
///
/// The sibling of [`declared_pin`], and it exists for the same reason: an
/// endpoint is **opaque payload**, so an empty declaration cannot express
/// intent. It is a `${VAR}` that did not interpolate in a compose file or a
/// systemd unit, and there is no third thing it could mean. Reading it as
/// "unset" grants the conservative default while the operator's own
/// configuration says an endpoint was named.
///
/// The transport policy runs here too, so a caller that resolves an endpoint
/// cannot forget to police it — the refusal is the one an operator cannot fix
/// by editing a file, and it must arrive before anything is built.
///
/// **Written because the OTLP hop had both halves wrong at once**, in
/// opposite directions: `undercroft config check` refused
/// `UNDERCROFT_OTLP_ENDPOINT=` by handing the empty string to
/// [`require_secure_transport`], which reports an unparseable URL as
/// cleartext — so an operator was told to use https about a value that names
/// no host at all, the empty parenthesis in the message being the only tell.
/// The exporter meanwhile read the same value through an
/// `.ok().filter(|s| !s.is_empty())` and started with traces silently off,
/// four lines above a comment saying telemetry that silently does not export
/// is worse than telemetry that refuses to start.
///
/// The value is **never trimmed**: emptiness is a question about whether
/// anything was named, and the answer does not license editing what was.
pub fn declared_endpoint(
    what: &'static str,
    declared: Option<&str>,
) -> Result<Option<String>, NetError> {
    match declared {
        None => Ok(None),
        Some(u) if u.trim().is_empty() => Err(NetError::Config {
            what,
            reason: "is set but names no endpoint (it is empty or only whitespace). It is most \
                     often an unset shell variable interpolated into a compose file or a systemd \
                     unit. There is no silent fallback: reading it as unset would disable the hop \
                     the declaration asks for, and leave no signal that it had been asked for. \
                     Point it at a URL, or unset the variable to disable the hop deliberately"
                .to_string(),
        }),
        Some(u) => {
            require_secure_transport(what, u)?;
            Ok(Some(u.to_string()))
        }
    }
}

type PinCache = std::sync::Mutex<std::collections::HashMap<String, Result<Option<Pin>, String>>>;
static PINS: std::sync::OnceLock<PinCache> = std::sync::OnceLock::new();

/// [`declared_pin`] read from the environment and resolved **once per
/// process**, keyed by variable name.
///
/// Resolving a pin per outbound call was a defect on the orchestrator hop —
/// a bad declaration bound the port and then failed every request — and the
/// remote-index hop had the same shape. Caching the `Result`, not just the
/// success, is the point: a declaration that does not resolve must keep
/// refusing identically for the life of the process, and re-reading the file
/// per call makes the pin mutable at runtime by anything that can rewrite
/// it, which is silent un-pinning by another name.
///
/// **The operational consequence, stated: rotating a pinned CA now needs a
/// process restart.** That is the trade — a pin that reloads itself is a pin
/// an attacker with write access to the file can replace without anyone
/// restarting anything, and a certificate rotation is a planned event while
/// silent un-pinning is not.
pub fn pin_from_env(what: &'static str, var: &str) -> Result<Option<Pin>, NetError> {
    let cache = PINS.get_or_init(Default::default);
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cached) = map.get(var) {
        return cached
            .clone()
            .map_err(|reason| NetError::Config { what, reason });
    }
    let resolved = declared_pin(what, std::env::var(var).ok().as_deref());
    map.insert(
        var.to_string(),
        resolved
            .as_ref()
            .map(Clone::clone)
            .map_err(|e| e.to_string()),
    );
    resolved
}

/// The resolved trust roots for a hop that does **not** speak through `ureq`,
/// taken from `var` and resolved once per process.
///
/// [`agent_from_env`] is the constructor for every hop that does. The
/// pgvector backend is the one that cannot use it: it speaks the postgres
/// wire protocol through `tokio_postgres_rustls`, which wants a
/// `rustls::ClientConfig` rather than an agent. So it read `UNDERCROFT_INDEX_CA`
/// with a bare `std::env::var` and built its own config — which meant one
/// declaration got **two answers across five backends** (the other four trim
/// the value and refuse a whitespace-only one through [`declared_pin`]; this
/// did neither) and, worse, **re-read the PEM per connection**, so the
/// restart-to-rotate property [`pin_from_env`] documents above did not hold
/// for the one hop reachable per request (ROADMAP O82c).
///
/// Returning the config from INSIDE this crate is what keeps [`Pin`]'s
/// guarantee intact — its field stays private, so no caller can assemble a
/// `ClientConfig` that skipped [`pinned_roots`]' refusals; it can only
/// receive one that did not.
pub fn rustls_config_from_env(
    what: &'static str,
    var: &str,
) -> Result<Arc<rustls::ClientConfig>, NetError> {
    Ok(match pin_from_env(what, var)? {
        Some(pin) => pin.0.clone(),
        None => webpki_roots(),
    })
}

/// [`agent_pinned`] with the pin taken from `var`, resolved once per process.
///
/// The one constructor every hop that reads a `*_CA` variable should use.
pub fn agent_from_env(
    what: &'static str,
    base: &str,
    ca_var: &str,
    timeout: std::time::Duration,
) -> Result<ureq::Agent, NetError> {
    // Transport policy FIRST: an operator with both a cleartext base and a
    // bad pin needs to be told about the cleartext, which is the refusal
    // that cannot be fixed by editing a file.
    require_secure_transport(what, base)?;
    let pin = pin_from_env(what, ca_var)?;
    agent_pinned(what, base, pin.as_ref(), timeout)
}

/// A `ureq` agent that obeys the policy: refuses cleartext beyond loopback,
/// and pins `ca_path` when one is declared.
///
/// One function so a new HTTP client cannot ship with the check half-made.
pub fn agent(
    what: &'static str,
    base: &str,
    ca_path: Option<&str>,
    timeout: std::time::Duration,
) -> Result<ureq::Agent, NetError> {
    // The cleartext refusal is reported BEFORE a pin failure: it is the one
    // an operator cannot fix by editing a file, and reporting the pin first
    // sends them to correct a certificate and then hit the real refusal.
    require_secure_transport(what, base)?;
    let pin = ca_path.map(|p| resolve_pin(what, p)).transpose()?;
    agent_pinned(what, base, pin.as_ref(), timeout)
}

/// [`agent`] with the pin already resolved.
///
/// The two share ONE body — the cleartext refusal and the root replacement
/// happen here and nowhere else — so a caller that pre-resolves its pin
/// cannot end up under a different policy from one that does not. That is
/// the whole reason this crate exists as a crate.
pub fn agent_pinned(
    what: &'static str,
    base: &str,
    pin: Option<&Pin>,
    timeout: std::time::Duration,
) -> Result<ureq::Agent, NetError> {
    require_secure_transport(what, base)?;
    let mut builder = ureq::AgentBuilder::new().timeout(timeout);
    if let Some(Pin(roots)) = pin {
        builder = builder.tls_config(roots.clone());
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two spellings that inverted this gate in production, plus the
    /// ordinary cases. Kept as behaviour rather than as an enumeration of
    /// attacker strings: the predicate delegates to `url`, so what is
    /// asserted here is that it AGREES with the transport.
    #[test]
    fn loopback_is_decided_by_the_transports_own_parser() {
        for yes in [
            "http://127.0.0.1:8080",
            "http://localhost:11434/v1",
            "https://[::1]:443",
            "http://127.255.255.254/x",
        ] {
            assert!(is_loopback(yes), "{yes}");
        }
        for no in [
            "http://evil.com",
            // userinfo that LOOKS like loopback
            "http://127.0.0.1:8080@evil.com/",
            // backslash is a path separator for a special scheme
            "http://evil.com\\@127.0.0.1/v1",
            "http://10.0.0.1",
            "not a url",
            "",
        ] {
            assert!(!is_loopback(no), "{no}");
        }
    }

    #[test]
    fn cleartext_beyond_loopback_is_refused_and_names_the_client() {
        let err = require_secure_transport("the remote index", "http://qdrant.internal:6333")
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("the remote index"), "{msg}");
        assert!(msg.contains("no override"), "{msg}");
        // The two allowed shapes.
        assert!(require_secure_transport("x", "https://qdrant.internal:6333").is_ok());
        assert!(require_secure_transport("x", "http://127.0.0.1:6333").is_ok());
        // And the userinfo spoof does not buy an exemption.
        assert!(require_secure_transport("x", "http://127.0.0.1:6333@evil.com/").is_err());
    }

    /// **One rule for what an empty declaration means, across all four
    /// `*_CA` variables.** They had three behaviours: the orchestrator hop
    /// refused explicitly, the index hop refused by accident (via
    /// `fs::read("")`), and the embedder and LLM hops treated it as NO PIN —
    /// silently un-pinning at exactly the moment an operator believes they
    /// pinned, which is the failure mode all four doc comments name in the
    /// same words.
    ///
    /// Unset is not a declaration. Empty IS one, and it names no file.
    #[test]
    fn an_empty_declaration_is_a_declaration_that_pins_nothing() {
        assert!(declared_pin("x", None)
            .expect("unset is not a refusal")
            .is_none());
        for empty in ["", "   ", "\t", "\n"] {
            let err = declared_pin("x", Some(empty)).expect_err("must refuse");
            assert!(err.to_string().contains("pins nothing"), "{err}");
            assert!(err.to_string().contains("no silent fallback"), "{err}");
        }
        // A real path still resolves, and a bad one still refuses — so this
        // is a rule about the empty case, not a blanket.
        let dir = tempfile::TempDir::new().unwrap();
        let missing = dir.path().join("nope.pem");
        assert!(declared_pin("x", Some(missing.to_str().unwrap())).is_err());
    }

    /// The same rule for the ENDPOINT, and the counterfactual is the reason
    /// this is a separate test rather than a line in its sibling: before
    /// [`declared_endpoint`] existed, an empty endpoint reached
    /// [`require_secure_transport`] directly, which parses it, fails, and
    /// reports an unparseable URL as CLEARTEXT. So the empty case was not
    /// unhandled — it was handled, loudly, with the wrong diagnosis, and an
    /// assertion that merely required a refusal would have passed against the
    /// defect. What is asserted is therefore the DIAGNOSIS, and that the old
    /// wrong one is gone.
    #[test]
    fn an_empty_endpoint_is_a_failed_interpolation_not_a_cleartext_url() {
        assert!(declared_endpoint("x", None)
            .expect("unset is not a refusal")
            .is_none());
        for empty in ["", "   ", "\t", "\n"] {
            let err = declared_endpoint("x", Some(empty)).expect_err("must refuse");
            assert!(err.to_string().contains("names no endpoint"), "{err}");
            assert!(err.to_string().contains("no silent fallback"), "{err}");
            assert!(
                !err.to_string().contains("cleartext"),
                "an empty declaration is not a cleartext URL — this is the \
                 pre-fix diagnosis, which sent an operator to configure TLS \
                 for a value that names no host: {err}"
            );
        }
        // The policy still runs on a value that IS one, in both directions —
        // so this is a rule about the empty case and not a bypass around it.
        assert!(declared_endpoint("x", Some("http://collector:4318")).is_err());
        assert_eq!(
            declared_endpoint("x", Some("https://collector:4318")).unwrap(),
            Some("https://collector:4318".to_string())
        );
        assert_eq!(
            declared_endpoint("x", Some("http://127.0.0.1:4318")).unwrap(),
            Some("http://127.0.0.1:4318".to_string())
        );
        // Never trimmed: emptiness is a question about whether anything was
        // named, and the answer does not license editing what was.
        assert_eq!(
            declared_endpoint("x", Some("https://collector:4318 "))
                .unwrap()
                .as_deref(),
            Some("https://collector:4318 ")
        );
    }

    /// The cleartext refusal is reported BEFORE a pin failure. An operator
    /// with both cannot fix the cleartext one by editing a file, so telling
    /// them about the certificate first sends them to correct the wrong
    /// thing and hit the real refusal afterwards.
    #[test]
    fn the_cleartext_refusal_is_reported_before_a_pin_failure() {
        let dir = tempfile::TempDir::new().unwrap();
        let empty_pem = dir.path().join("empty.pem");
        std::fs::write(&empty_pem, b"").unwrap();
        let err = agent(
            "x",
            "http://engine.internal:8800",
            Some(empty_pem.to_str().unwrap()),
            std::time::Duration::from_secs(1),
        )
        .expect_err("both are wrong; one must be reported");
        assert!(
            matches!(err, NetError::Cleartext { .. }),
            "the unfixable-by-file refusal comes first: {err}"
        );
    }

    #[test]
    fn a_declared_root_that_pins_nothing_refuses_rather_than_falling_back() {
        assert!(pinned_roots(b"").is_err());
        assert!(pinned_roots(b"-----BEGIN CERTIFICATE-----\nnot base64\n").is_err());
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("empty.pem");
        std::fs::write(&p, b"").unwrap();
        let err = pinned_roots_from_file("x", p.to_str().unwrap()).expect_err("must refuse");
        assert!(err.to_string().contains("pins nothing"), "{err}");
    }
}
