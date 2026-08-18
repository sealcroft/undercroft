//! An [`Embedder`] backed by a local embeddings endpoint.
//!
//! The engine could previously embed in exactly three ways: the built-in
//! [`HashEmbedder`](undercroft_core::HashEmbedder), an ONNX file loaded from
//! disk (`onnx`/`ort`), or not at all —
//! [`ExternalEmbedder`](undercroft_core::ExternalEmbedder) is an *identity* for
//! vaults whose vectors the caller computes elsewhere, and its `embed()` is
//! documented as unreachable. A model served over HTTP — Ollama, llama.cpp
//! server, LM Studio, vLLM, text-embeddings-inference — had no route in, even
//! though the same runtimes have been usable for `refine` since v0.5.0.
//!
//! This closes that, reusing the conventions of [`LlmClient`](crate::LlmClient)
//! rather than inventing new ones: the same two API shapes, the same
//! `*_URL` / `*_MODEL` / `*_API` / `*_KEY` variables, the same default-off
//! posture. Nothing is contacted unless `UNDERCROFT_EMBED_URL` is set.
//!
//! # Transport policy: TLS or loopback, nothing else
//!
//! **Cleartext HTTP to a non-loopback host is refused at construction** —
//! not warned about, refused, with no override of any kind (operator
//! decision, 2026-08-03). Drawer text on a network wire readable by anyone
//! on the path is not a configuration this store will run. The error names
//! the fix: serve the endpoint over TLS (the compose `embeddings-tls`
//! terminator ships ready) and, for self-signed infrastructure, declare its
//! root with `UNDERCROFT_EMBED_CA=<pem>`. Loopback HTTP stays allowed — the
//! wire never leaves the machine, local runtimes serve plain HTTP by
//! default, and the in-process test harness rides it.
//!
//! **A declared CA is a pin, not an addition.** When `UNDERCROFT_EMBED_CA`
//! is set, the file's certificates become the ONLY roots this client
//! trusts — the bundled public roots are out. A declared root that fails to
//! parse refuses construction rather than falling back, because a silent
//! fallback would un-pin exactly when the operator believes they pinned.
//! Certificate verification itself has no bypass: an unknown issuer is a
//! construction error (`invalid peer certificate: UnknownIssuer`), and no
//! skip-verify knob exists or will.
//!
//! # The hazard that remains, stated
//!
//! **The endpoint reads drawer text in plaintext.** TLS protects the wire,
//! not the destination: every embed hands the content to the serving
//! process, which holds it in memory outside the vault's crypto boundary
//! with none of this store's guarantees. Sealing protects data *at rest*,
//! not data you hand to someone. Construction says so at warning level for
//! any non-loopback endpoint; if that trade is unacceptable, the
//! in-process `onnx`/`ort` embedders keep the text in this process.
//!
//! **A failed embed cannot fail the write.** [`Embedder::embed`] returns a
//! vector with no error channel, so a network blip yields a zero vector — a
//! drawer that is stored verbatim and remains findable by every lexical
//! channel, but is invisible to the semantic one until re-embedded. Each
//! failure is logged at error level and counted
//! ([`HttpEmbedder::failures`]); an ingest run that reports a non-zero count
//! has holes in its vector space and should be re-embedded
//! (`UNDERCROFT_FORCE_EMBEDDER=1` + `repair`).

use std::cell::Cell;

use serde_json::{json, Value};
use undercroft_core::embed::Embedder;

use crate::{ApiKind, LlmError};

/// Retries per embed before a zero vector is returned. One retry, because the
/// target is a local runtime: the failure worth surviving is a model still
/// warming up, not a flaky WAN.
const ATTEMPTS: usize = 2;

/// The text sent once at construction to learn the endpoint's dimension.
const PROBE: &str = "dimension probe";

pub struct HttpEmbedder {
    base: String,
    model: String,
    kind: ApiKind,
    key: String,
    dim: usize,
    /// `http:<model>` — recorded as the vault's embedder identity, so a
    /// silent swap of the served model is refused by the existing check
    /// exactly as an ONNX swap is.
    identity: String,
    agent: ureq::Agent,
    failures: Cell<u64>,
}

impl HttpEmbedder {
    /// Build from `UNDERCROFT_EMBED_URL`, `UNDERCROFT_EMBED_MODEL`, optional
    /// `UNDERCROFT_EMBED_API` (`openai` | `ollama`; guessed from the URL like
    /// the LLM client does), optional `UNDERCROFT_EMBED_KEY`, and optional
    /// `UNDERCROFT_EMBED_DIM`.
    ///
    /// Without a declared dimension the endpoint is **asked** — one probe
    /// embed at construction, whose length is the dimension. Reading it is
    /// evidence; assuming 768 because the model name contains `base` would be
    /// inference, and this project does not infer.
    pub fn from_env() -> Result<Self, LlmError> {
        let base = std::env::var("UNDERCROFT_EMBED_URL").map_err(|_| LlmError::NotConfigured)?;
        let model = std::env::var("UNDERCROFT_EMBED_MODEL")
            .unwrap_or_else(|_| "nomic-embed-text".to_string());
        let api = std::env::var("UNDERCROFT_EMBED_API").ok();
        let kind = crate::resolve_api_kind("UNDERCROFT_EMBED_API", api.as_deref(), &base);
        let key = std::env::var("UNDERCROFT_EMBED_KEY").unwrap_or_default();
        // ROADMAP O52: an unreadable dimension used to be swallowed and the
        // endpoint probed instead, so a declaration meant to PIN the vector
        // width silently became a suggestion. It still falls back to probing —
        // that is what absence gives — but it says so first.
        let dim_raw = std::env::var("UNDERCROFT_EMBED_DIM").ok();
        let declared = match undercroft_core::config::positive_usize(
            "UNDERCROFT_EMBED_DIM",
            dim_raw.as_deref(),
        ) {
            Ok(d) => d,
            Err(f) => {
                undercroft_obs::diag_warn!("{}", f.why);
                f.value
            }
        };
        Self::connect(&base, &model, kind, &key, declared)
    }

    /// As [`Self::from_env`], with everything supplied. `dim` of `None` probes
    /// the endpoint.
    pub fn connect(
        base_url: &str,
        model: &str,
        kind: ApiKind,
        key: &str,
        dim: Option<usize>,
    ) -> Result<Self, LlmError> {
        let base = base_url.trim_end_matches('/').to_string();
        let loopback = is_loopback(&base);
        let tls = base.starts_with("https://");
        // Transport policy (module header): TLS or loopback, nothing else,
        // no override. The wire class is closed by refusal, the endpoint
        // class is stated by warning — and the two must not be conflated.
        if !tls && !loopback {
            return Err(LlmError::Refused(format!(
                "cleartext http to non-loopback {base} — drawer text would cross \
                 the network readable by anyone on the path, and no override \
                 exists. Serve the endpoint over TLS (the compose \
                 `embeddings-tls` terminator ships ready) and declare a \
                 self-signed root with UNDERCROFT_EMBED_CA=<pem>."
            )));
        }
        if loopback {
            undercroft_obs::diag_info!("embedder: {model} via {base} (loopback)");
        } else {
            undercroft_obs::diag_warn!(
                "embedder: {model} via {base} — TLS protects the wire, but the \
                 ENDPOINT still reads drawer text in plaintext on every write \
                 and every search. Sealing protects a vault at rest, not \
                 content handed to another process; if that trade is \
                 unacceptable, use the in-process onnx/ort embedders."
            );
        }
        // **This crate stopped building its own client.** The transport
        // policy lives in `undercroft-net` — which was EXTRACTED FROM this
        // crate — and two copies of a rule are two places for it to drift.
        // They had: the local copy applied a declared pin only `if tls`, so
        // a loopback-http base never read or validated the CA file while the
        // shared path does, and it treated `UNDERCROFT_EMBED_CA=""` as no
        // pin at all — silently un-pinning exactly when the operator
        // believes they pinned. It also re-read and re-parsed the PEM on
        // every construction. One call now, resolved once per process.
        let agent = undercroft_net::agent_from_env(
            "the embedder",
            &base,
            "UNDERCROFT_EMBED_CA",
            std::time::Duration::from_secs(120),
        )
        .map_err(|e| LlmError::Refused(e.to_string()))?;
        let mut me = Self {
            base,
            model: model.to_string(),
            kind,
            key: key.to_string(),
            dim: dim.unwrap_or(0),
            identity: format!("http:{model}"),
            agent,
            failures: Cell::new(0),
        };
        if me.dim == 0 {
            let probe = me.request(PROBE)?;
            if probe.is_empty() {
                return Err(LlmError::BadOutput(
                    "embeddings endpoint returned an empty vector for the dimension probe".into(),
                ));
            }
            me.dim = probe.len();
        }
        Ok(me)
    }

    /// How many embeds have failed and returned a zero vector. Non-zero means
    /// the vector space has holes — the drawers are intact and lexically
    /// findable, but their semantic leg is dead until a re-embed.
    pub fn failures(&self) -> u64 {
        self.failures.get()
    }

    /// One embedding, or the transport/shape error that prevented it.
    fn request(&self, text: &str) -> Result<Vec<f32>, LlmError> {
        let (url, body) = match self.kind {
            // Ollama native. `/api/embed` (newer, batch-shaped) and
            // `/api/embeddings` (older, single) differ in both request and
            // response; ask the older one and read either response.
            ApiKind::Ollama => (
                format!("{}/api/embeddings", self.base),
                json!({ "model": self.model, "prompt": text }),
            ),
            ApiKind::OpenAi => (
                format!("{}/embeddings", self.base),
                json!({ "model": self.model, "input": text }),
            ),
        };
        let mut req = self.agent.post(&url);
        if !self.key.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.key));
        }
        let resp: Value = req
            .send_json(body)
            .map_err(|e| LlmError::Http(e.to_string()))?
            .into_json()
            .map_err(|e| LlmError::BadOutput(e.to_string()))?;
        parse_embedding(&resp)
            .ok_or_else(|| LlmError::BadOutput(format!("no embedding in response: {resp}")))
    }
}

/// Pull a vector out of any of the four shapes these runtimes answer with:
/// OpenAI `{data:[{embedding:[..]}]}`, Ollama `/api/embeddings`
/// `{embedding:[..]}`, Ollama `/api/embed` `{embeddings:[[..]]}`, and a bare
/// `[..]`. Defensive on purpose — the same reason the refinement parser is.
fn parse_embedding(resp: &Value) -> Option<Vec<f32>> {
    // Each arm takes an `Option<&Value>`: a `?` on the pointer would return
    // from the whole function on the first shape that does not match, so only
    // the first candidate would ever be tried.
    let floats = |v: Option<&Value>| -> Option<Vec<f32>> {
        let arr = v?.as_array()?;
        if arr.is_empty() {
            return None;
        }
        arr.iter()
            .map(|x| x.as_f64().map(|f| f as f32))
            .collect::<Option<Vec<f32>>>()
    };
    floats(resp.pointer("/data/0/embedding"))
        .or_else(|| floats(resp.pointer("/embedding")))
        .or_else(|| floats(resp.pointer("/embeddings/0")))
        .or_else(|| floats(Some(resp)))
}

// The transport policy — the loopback predicate and the CA pin — lives in
// `undercroft-net` since 2026-08-05 and is re-exported here so this module's
// callers and tests are unchanged. It moved because the remote INDEX
// backends had no transport policy at all (ROADMAP C8) while every push
// carries embeddings, which are plaintext-derived: two copies of one rule
// is two places for it to drift, which is the defect class this branch is
// closing. Nothing about the behaviour changed in the move; the tests below
// still exercise it through these names.
pub(crate) use undercroft_net::is_loopback;

impl Embedder for HttpEmbedder {
    fn model_name(&self) -> &str {
        &self.identity
    }

    fn dimension(&self) -> usize {
        self.dim
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        let mut last = String::new();
        for _ in 0..ATTEMPTS {
            match self.request(text) {
                Ok(v) if v.len() == self.dim => return v,
                Ok(v) => {
                    last = format!("expected {} dimensions, got {}", self.dim, v.len());
                    break; // A shape change is not worth retrying.
                }
                Err(e) => last = e.to_string(),
            }
        }
        self.failures.set(self.failures.get() + 1);
        undercroft_obs::diag_error!(
            "embed failed ({last}); storing a zero vector — this drawer is \
             lexically findable but semantically invisible until re-embedded. \
             Failures so far: {}",
            self.failures.get()
        );
        vec![0.0; self.dim.max(1)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A one-shot embeddings server that answers `body` to every POST, and
    /// counts the requests it saw.
    fn serve(body: &'static str) -> (String, Arc<AtomicUsize>, std::thread::JoinHandle<()>) {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let handle = std::thread::spawn(move || {
            for request in server.incoming_requests() {
                counter.fetch_add(1, Ordering::SeqCst);
                let req = request;
                let resp = tiny_http::Response::from_string(body).with_header(
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                        .unwrap(),
                );
                let _ = req.respond(resp);
            }
        });
        (url, hits, handle)
    }

    #[test]
    fn every_runtime_response_shape_parses() {
        let openai = json!({"data": [{"embedding": [0.5, -0.25, 0.125]}]});
        let ollama_single = json!({"embedding": [0.5, -0.25, 0.125]});
        let ollama_batch = json!({"embeddings": [[0.5, -0.25, 0.125]]});
        let bare = json!([0.5, -0.25, 0.125]);
        for (name, shape) in [
            ("openai", openai),
            ("ollama /api/embeddings", ollama_single),
            ("ollama /api/embed", ollama_batch),
            ("bare array", bare),
        ] {
            assert_eq!(
                parse_embedding(&shape),
                Some(vec![0.5, -0.25, 0.125]),
                "{name} response must parse"
            );
        }
        // Shapes that carry no vector must be refused, not coerced to empty.
        assert_eq!(parse_embedding(&json!({"error": "no such model"})), None);
        assert_eq!(parse_embedding(&json!({"data": []})), None);
        assert_eq!(parse_embedding(&json!({"embedding": []})), None);
    }

    /// The dimension is read off the endpoint, and the identity records the
    /// served model so the store's existing swap check covers it.
    #[test]
    fn dimension_is_probed_and_identity_is_recorded() {
        let (url, hits, _h) = serve(r#"{"data":[{"embedding":[1.0,2.0,3.0,4.0]}]}"#);
        let e = HttpEmbedder::connect(&url, "some-model", ApiKind::OpenAi, "", None).unwrap();
        assert_eq!(e.dimension(), 4, "dimension comes from the endpoint");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "exactly one probe");
        assert_eq!(e.model_name(), "http:some-model");
        assert_eq!(e.embed("anything"), vec![1.0, 2.0, 3.0, 4.0]);
        assert_eq!(e.failures(), 0);

        // A declared dimension skips the probe entirely.
        let (url2, hits2, _h2) = serve(r#"{"data":[{"embedding":[1.0,2.0]}]}"#);
        let e2 = HttpEmbedder::connect(&url2, "m", ApiKind::OpenAi, "", Some(2)).unwrap();
        assert_eq!(e2.dimension(), 2);
        assert_eq!(hits2.load(Ordering::SeqCst), 0, "declared ⇒ no probe");
    }

    /// A failing endpoint must degrade to a zero vector — never a panic, never
    /// a wrong-length vector that would corrupt the index — and must say so.
    #[test]
    fn a_failed_embed_degrades_loudly_to_zero() {
        let (url, _hits, _h) = serve(r#"{"data":[{"embedding":[1.0,2.0,3.0]}]}"#);
        let e = HttpEmbedder::connect(&url, "m", ApiKind::OpenAi, "", None).unwrap();
        assert_eq!(e.dimension(), 3);

        // Point it at a dead port: every attempt fails.
        let dead = HttpEmbedder::connect("http://127.0.0.1:1", "m", ApiKind::OpenAi, "", Some(3))
            .expect("a declared dimension means construction does not contact anything");
        let v = dead.embed("text");
        assert_eq!(v, vec![0.0, 0.0, 0.0], "zero vector of the right shape");
        assert_eq!(dead.failures(), 1, "and the failure is counted, not hidden");
    }

    /// The wrong-length case is the dangerous one: a served model swapped
    /// under a running vault would write vectors the store cannot compare.
    #[test]
    fn a_dimension_change_mid_flight_is_refused_not_stored() {
        let (url, _hits, _h) = serve(r#"{"data":[{"embedding":[1.0,2.0]}]}"#);
        let e = HttpEmbedder::connect(&url, "m", ApiKind::OpenAi, "", Some(5)).unwrap();
        assert_eq!(e.embed("text"), vec![0.0; 5], "never a short vector");
        assert_eq!(e.failures(), 1);
    }

    /// The transport policy, both arms: cleartext to a non-loopback host is
    /// refused at construction with the fix in the message and no override;
    /// loopback cleartext still constructs (the wire never leaves the
    /// machine — and every `serve()`-based test above is the standing proof).
    #[test]
    fn cleartext_to_a_non_loopback_host_is_refused_with_the_fix_named() {
        let err = match HttpEmbedder::connect(
            "http://embeddings:11434",
            "m",
            ApiKind::Ollama,
            "",
            Some(3),
        ) {
            Err(e) => e,
            Ok(_) => panic!("a non-loopback http URL must refuse at construction"),
        };
        let msg = err.to_string();
        for needle in ["cleartext", "TLS", "UNDERCROFT_EMBED_CA", "no override"] {
            assert!(msg.contains(needle), "refusal must carry {needle:?}: {msg}");
        }
    }

    /// A declared CA is a pin: parseable roots build a config, and every
    /// failure shape (garbage, empty, PEM with no certificate) errors
    /// instead of falling back to the bundled public roots.
    #[test]
    fn a_declared_ca_pins_or_refuses_never_falls_back() {
        // A real self-signed certificate (openssl, CN=undercroft-test-ca).
        const TEST_CA: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDGzCCAgOgAwIBAgIUHGKbVzszbE5K6CpU896egUr+MwAwDQYJKoZIhvcNAQEL\n\
BQAwHTEbMBkGA1UEAwwSdW5kZXJjcm9mdC10ZXN0LWNhMB4XDTI2MDgwODIyMzg0\n\
MVoXDTM2MDgwNTIyMzg0MVowHTEbMBkGA1UEAwwSdW5kZXJjcm9mdC10ZXN0LWNh\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtG0x6fHJEivyAUK3teJC\n\
ZWflj7WNug52LTbWJ8kdShYkpFoSqBHNjxlZDJQL00GC2iF1LL1WmmKrkA2SvXky\n\
ofqfX8ieugtiu6aAuEu3jqy3jJYAxpYxrq+HJXa2brSKrJ1ZTOWToqmsqNySrcmN\n\
a3Dd1f7wj4gXPzv44hd9eOdAhumaSfzaNElBjbgO2VN0wv0emhSkmJcApXrNf1JX\n\
1buGR9P31dBo5p/51/bjPidzWbleHR+ouA1Nakf/dFOWiPAb57ZANXi01ktqMyX9\n\
WwgiBLcoeSTprh9JrsdKrRXnp30xY6o1g5Cp58CztvjiDuHDHTvpFlzZMZdEoFGE\n\
dwIDAQABo1MwUTAdBgNVHQ4EFgQUKYs6Blb5Cvri4m46cQ6xS6Cp2/4wHwYDVR0j\n\
BBgwFoAUKYs6Blb5Cvri4m46cQ6xS6Cp2/4wDwYDVR0TAQH/BAUwAwEB/zANBgkq\n\
hkiG9w0BAQsFAAOCAQEAeK4DAzdblDSN//IusD8IrB4vfSwvo+NC5kNCw1p/tsHP\n\
PM8BiQh59ty7tDsqx5Nsl18Kol2KjQoeR7nuP5EjH9R0HNnbaaqhv7Fbb6Pkgies\n\
FYXk9pTBROKyVeNP+3niyzKeSzxXUOzY5D/IxSREyY8C+fG93ya1NwwFlpYiPWYA\n\
F3GuPqnwpg/8ilY224lY53T6wLkqwG/lQNXjVjOLmqpEmz94JavS8vPXLuyPGd3n\n\
XJe04q/5oCD050fMeJFyrKm5Uo41tVBhRggcN2IUvdF/ra8YeQjtj+OMgJVrOwIq\n\
3zqoWLvt0tGY61aaH2u2ulH33/SJGuksaewVLQP9qA==\n\
-----END CERTIFICATE-----\n";
        assert!(
            undercroft_net::pinned_roots(TEST_CA.as_bytes()).is_ok(),
            "a real certificate must pin"
        );
        for (name, bad) in [
            ("empty", &b""[..]),
            ("garbage", &b"not a pem at all"[..]),
            (
                "pem with no certificate",
                &b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"[..],
            ),
        ] {
            assert!(
                undercroft_net::pinned_roots(bad).is_err(),
                "{name} must refuse, never fall back to public roots"
            );
        }
    }

    #[test]
    fn loopback_is_recognised_and_anything_else_is_not() {
        for local in [
            "http://localhost:1234/v1",
            "http://127.0.0.1:11434",
            "http://[::1]:8080/v1",
            "https://localhost",
        ] {
            assert!(is_loopback(local), "{local} is this machine");
        }
        for remote in [
            "http://embeddings:8080/v1", // a container on the compose network
            "https://api.example.com/v1",
            "http://192.168.1.10:1234",
        ] {
            assert!(!is_loopback(remote), "{remote} is not this machine");
        }
    }

    /// A loopback-looking USERINFO must not make a remote host local.
    ///
    /// `http://127.0.0.1:8080@evil.com/v1` has username `127.0.0.1`, password
    /// `8080` and host `evil.com` (RFC 3986), which is how ureq resolves it —
    /// but this predicate split the authority on `:` and read `127.0.0.1`.
    /// The gate then passed, so "TLS or loopback, nothing else, no override"
    /// shipped drawer text in cleartext to an attacker-chosen host AND
    /// suppressed the plaintext-endpoint warning.
    #[test]
    fn userinfo_cannot_impersonate_loopback() {
        for spoof in [
            "http://127.0.0.1:8080@evil.com/v1",
            "http://localhost@evil.com/v1",
            "http://localhost:11434@evil.com",
            "http://[::1]:8080@evil.com/v1",
            "http://user@127.0.0.1.evil.com/v1",
            // userinfo containing its own `@` — the split must take the last
            "http://a@b:127.0.0.1@evil.com/v1",
            // For a special scheme the WHATWG parser treats a backslash as a
            // path separator, so the host here is evil.com. The first fix
            // enumerated userinfo spellings and missed this one entirely,
            // which is why the predicate now asks the transport's own parser.
            r"http://evil.com\@127.0.0.1/v1",
        ] {
            assert!(
                !is_loopback(spoof),
                "{spoof} resolves to a REMOTE host and must not read as loopback"
            );
        }
        // Premise, so this cannot pass by breaking loopback detection: real
        // loopback URLs still read as loopback, including with real userinfo.
        assert!(is_loopback("http://127.0.0.1:11434"));
        assert!(is_loopback("http://user:pass@127.0.0.1:11434/v1"));
        assert!(is_loopback("http://user@localhost:1234/v1"));
        assert!(is_loopback("http://user@[::1]:8080/v1"));
        // And the mirror of the backslash case, which the FIRST draft of this
        // test got wrong: here the backslash ends the authority at
        // , so  is PATH and the request really does go
        // to loopback. Asserting it the other way would have pinned a false
        // expectation into the suite — the parser is right and the hand
        // reasoning was wrong, which is the whole argument for using it.
        assert!(is_loopback(r"http://localhost\@evil.com/v1"));
    }
    /// What the parser change did to the EDGES, pinned so it is a decision
    /// rather than a side effect.
    ///
    /// The old predicate compared the host string to three literals, so only
    /// `127.0.0.1` counted. `Ipv4Addr::is_loopback` covers all of 127/8,
    /// which is what RFC 1122 actually says — a widening, and a correct one:
    /// `127.0.0.2` is this machine, and cleartext to it never leaves it.
    ///
    /// The other edges must NOT widen, and this is where a parser swap could
    /// have quietly cost something: an IPv4-mapped IPv6 address, a bare
    /// wildcard, and a hostname that merely resolves to loopback are all
    /// still NOT loopback — the last one deliberately, because resolution is
    /// not something this predicate can see and guessing would be inference.
    #[test]
    fn loopback_edges_are_decided_not_incidental() {
        // Widened, correctly: the whole 127/8 block is this machine.
        assert!(is_loopback("http://127.0.0.2:8080/v1"));
        assert!(is_loopback("http://127.255.255.254/v1"));

        // NOT widened. Each of these would be a cleartext leak if it were.
        for remote in [
            "http://0.0.0.0:8080/v1",       // wildcard bind, not a destination
            "http://[::ffff:127.0.0.1]/v1", // IPv4-mapped IPv6 is not ::1
            "http://127.0.0.1.evil.com/v1", // a domain that merely starts with it
            "http://localhost.evil.com/v1",
            "http://169.254.169.254/latest", // cloud metadata, a classic SSRF target
        ] {
            assert!(!is_loopback(remote), "{remote} must not read as loopback");
        }
    }
}
