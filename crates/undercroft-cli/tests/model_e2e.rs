//! ROADMAP O157 — the model backends joined to the SURFACES a deployment
//! actually reads.
//!
//! O122 and O131 made every model role count the failures it used to
//! swallow, and O134a executed the nine counted degrade arms inside the two
//! model crates. Nothing drove a real backend through the binary to what an
//! operator sees: `stats` on the CLI, `/v1`, and MCP. This file is that join,
//! over the fixture the model crates GENERATE (no committed bytes) and the
//! real `undercroft` binary, spawned out of process.
//!
//! **Run BY NAME, from the `ort-build` leg only:** `cargo test --release -p
//! undercroft-cli --features onnx,ort,undercroft-embed-onnx/test-fixture
//! --test model_e2e`. The manifest's `required-features` lists all three, so a
//! leg that loses one is refused by Cargo (exit 101) rather than silently
//! skipped or half compiled, and the unnamed default `test` suite skips this
//! target. The fixture is reached through the CLI's OPTIONAL dependency and
//! never a dev-dependency, because this crate is a default member and a
//! dev-dependency would be compiled by every default build over it. The file
//! therefore carries no feature cfg: each arm proves on the SPAWNED binary
//! which loader it reached.
//!
//! **What the counts are.** A failure count belongs to one embedder, reranker
//! or encoder INSTANCE, never to a database. On the CLI each command is its
//! own process, so `stats` reports its own open and never an earlier
//! command's write — which is why the CLI arms read the working process's own
//! stderr, and the long-lived surfaces assert exact DELTAS inside one process.
//! `UNDERCROFT_SEMANTIC_GATE=off` plus `UNDERCROFT_SEMANTIC_FLOOR=0.0` skip
//! every calibration embed, so those deltas are functions of the requests
//! alone; exact `+1` rather than "greater" is what catches a double count.
//!
//! **`fixture::OUT_OF_TABLE_WORD` is driven, and every process must SURVIVE
//! it** (ROADMAP O150). Under `UNDERCROFT_EMBEDDER=onnx` that word panicked,
//! and the panic unwound out of the single-threaded `/v1` and MCP stdio loops
//! and ended the process — which read as a bare 500 on `/v1` (`tiny_http`
//! answers a request dropped during the unwind) and an EOF on MCP, never as a
//! count. O150 contains it, and the three `*_survives_*` arms drive it on
//! every surface that reaches each role, asserting in this order: the degrade
//! line says WHICH failure it was (a contained panic on tract, a typed refusal
//! on ORT — so a fixture that stopped panicking fails there, first), the count
//! moved, the drawer is verbatim, and the same process still answers. The
//! other arms drive `fixture::REFUSED_WORD`, which fails in the tokenizer on
//! both backends.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{json, Value};
use undercroft_embed_onnx::fixture;

/// The binary Cargo built for THIS invocation — the documented contract, so
/// the features it carries are the ones this target was named with.
const BIN: &str = env!("CARGO_BIN_EXE_undercroft");

const EMBED_FAILED: &str = "error: embed failed (";
const RERANK_FAILED: &str = "error: rerank failed (";
const DOC_ENCODE_FAILED: &str = "error: late-interaction doc encode failed (";
const QUERY_ENCODE_FAILED: &str = "error: late-interaction query encode failed (";
const NOT_BUILT: &str = "requires a build with";
/// The `Panicked` variant's display: what a degrade line carries when the
/// failure was a CONTAINED panic (ROADMAP O150). tract reports an out-of-table
/// id this way.
const CONTAINED_PANIC: &str = "inference panicked: ";
/// The `Inference` variant's display: a TYPED refusal. ONNX Runtime refuses an
/// out-of-table id this way, and must never report it as a panic.
const TYPED_REFUSAL: &str = "inference failed: ";

/// The tests spawn servers and load models: run them one at a time, so a port
/// chosen free cannot be taken before it is bound and two model runtimes never
/// compete for the same cores.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

type Env = Vec<(&'static str, String)>;

/// A child with NO inherited `UNDERCROFT_*` declaration and no locale, then
/// exactly the declarations its arm names. An inherited admission screen,
/// assertion secret or reranker would move the counts this file asserts
/// exactly, and an enumerated removal list rots where a prefix sweep does not.
fn child(home: &Path, env: &Env) -> Command {
    let mut c = Command::new(BIN);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("UNDERCROFT_") {
            c.env_remove(&key);
        }
    }
    for locale in ["LANG", "LC_ALL", "LC_MESSAGES"] {
        c.env_remove(locale);
    }
    c.env("UNDERCROFT_HOME", home);
    for (k, v) in env {
        c.env(k, v);
    }
    c
}

/// `env` with `extra` layered over it, an `extra` key replacing the original.
fn with(env: &Env, extra: &[(&'static str, String)]) -> Env {
    let mut out: Env = env
        .iter()
        .filter(|(k, _)| !extra.iter().any(|(x, _)| x == k))
        .cloned()
        .collect();
    out.extend(extra.iter().cloned());
    out
}

/// The two declarations that skip every calibration embed.
fn declared(env: &Env) -> Env {
    with(
        env,
        &[
            ("UNDERCROFT_SEMANTIC_GATE", "off".to_string()),
            ("UNDERCROFT_SEMANTIC_FLOOR", "0.0".to_string()),
        ],
    )
}

/// Run to completion under a bounded wait — a hung child fails the test
/// instead of hanging the leg.
fn run(c: Command, stdin: Option<String>) -> Output {
    let mut cmd = assert_cmd::Command::from_std(c);
    cmd.timeout(Duration::from_secs(300));
    if let Some(input) = stdin {
        cmd.write_stdin(input);
    }
    cmd.output().expect("the binary runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// stdout and stderr of a run that must succeed.
fn succeeds(out: &Output, what: &str) -> (String, String) {
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert!(
        out.status.success(),
        "{what}: exit {:?}\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        out.status.code()
    );
    (stdout, stderr)
}

fn cli(home: &Path, env: &Env, args: &[&str]) -> Output {
    let mut c = child(home, env);
    c.args(args);
    run(c, None)
}

/// The trailing field of `semantic: gate … · floor … · <source>`. The gate
/// VALUE prints `refused` in BOTH arms (a declared `off` is also no gate), so
/// only the source discriminates — a substring match would pass both.
fn semantic_source(stdout: &str) -> String {
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.starts_with("semantic: "))
        .collect();
    assert_eq!(lines.len(), 1, "exactly one semantic line:\n{stdout}");
    let parts: Vec<&str> = lines[0].split(" \u{b7} ").collect();
    assert_eq!(parts.len(), 3, "three fields: {}", lines[0]);
    assert_eq!(
        parts[0], "semantic: gate refused",
        "a model embedder whose calibration cannot run has no gate: {}",
        lines[0]
    );
    parts[2].to_string()
}

/// `embed failures: N (…)`, or `None` when the line is absent — which it is
/// exactly when N is zero.
fn embed_failures_line(stdout: &str) -> Option<u64> {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("embed failures: "))
        .map(|rest| {
            rest.split(' ')
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("unparseable embed failures line: {rest}"))
        })
}

/// The completion witness: `stats` printed its taxonomy, so the process got
/// past every line this file reads.
fn has_wings_line(stdout: &str) -> bool {
    stdout.lines().any(|l| l.starts_with("wings:"))
}

fn count(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not a count in {v}"))
}

fn poison() -> String {
    format!("alpha {}", fixture::REFUSED_WORD)
}

/// The generated model and tokenizer, plus a path that does NOT exist for the
/// routing premise.
struct Files {
    model: String,
    tokenizer: String,
    missing: String,
    _dir: tempfile::TempDir,
}

fn fixture_files() -> Files {
    let dir = tempfile::tempdir().expect("tempdir");
    let (model, tokenizer) = fixture::write_into(dir.path()).expect("write the fixture");
    let missing = dir.path().join("absent.onnx");
    assert!(!missing.exists(), "premise: the refusal path is absent");
    Files {
        model: model.display().to_string(),
        tokenizer: tokenizer.display().to_string(),
        missing: missing.display().to_string(),
        _dir: dir,
    }
}

/// Which backend the SPAWNED binary routes this declaration to. Pointed at a
/// model that does not exist, the named loader must be the one that refuses:
/// a binary without the feature says `requires a build with` instead, a
/// silent fallback would not refuse at all, and the other backend's loader
/// would name itself.
fn assert_routes_to(home: &Path, env: &Env, loader: &str, other_loader: &str) {
    let out = cli(home, env, &["stats"]);
    let stderr = text(&out.stderr);
    assert!(
        !out.status.success(),
        "a missing model must refuse to open ({loader}):\n{stderr}"
    );
    assert!(stderr.contains(loader), "expected {loader:?}:\n{stderr}");
    assert!(
        !stderr.contains(other_loader),
        "routed to the other backend ({other_loader:?}):\n{stderr}"
    );
    assert!(
        !stderr.contains(NOT_BUILT),
        "the binary lacks the feature:\n{stderr}"
    );
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// A `serve-http` child that is killed however the test ends, whose output
/// lands in a FILE (a pipe nobody drains can block it), and whose readiness
/// wait is bounded and says why it gave up.
struct Server {
    child: std::process::Child,
    addr: String,
    log: PathBuf,
}

impl Server {
    fn spawn(mut c: Command, log_dir: &Path) -> Server {
        let port = free_port();
        let log = log_dir.join(format!("serve-http-{port}.log"));
        let file = std::fs::File::create(&log).expect("server log");
        c.args([
            "serve-http",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(file.try_clone().expect("server log handle"))
        .stderr(file);
        let child = c.spawn().expect("serve-http spawns");
        let mut server = Server {
            child,
            addr: format!("127.0.0.1:{port}"),
            log,
        };
        for _ in 0..600 {
            if let Some(status) = server.child.try_wait().expect("poll serve-http") {
                panic!(
                    "serve-http exited before answering ({status}):\n{}",
                    server.log_text()
                );
            }
            if matches!(server.try_request("GET", "/healthz", None), Ok((200, _))) {
                return server;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "serve-http did not answer /healthz within 60 s:\n{}",
            server.log_text()
        );
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn try_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> std::io::Result<(u16, String)> {
        let payload = body.map(Value::to_string).unwrap_or_default();
        let raw = format!(
            "{method} {path} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
            self.addr,
            payload.len()
        );
        let mut stream = TcpStream::connect(&self.addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(120)))?;
        stream.write_all(raw.as_bytes())?;
        let mut resp = String::new();
        stream.read_to_string(&mut resp)?;
        let code = resp
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| std::io::Error::other(format!("no status line in {resp:?}")))?;
        Ok((
            code,
            resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
        ))
    }

    /// A `/v1` call that must answer `expect` with a JSON body.
    fn call(&self, method: &str, path: &str, body: Option<Value>, expect: u16) -> Value {
        let (code, raw) = self
            .try_request(method, path, body.as_ref())
            .unwrap_or_else(|e| {
                panic!(
                    "{method} {path}: {e} — the server may have died:\n{}",
                    self.log_text()
                )
            });
        assert_eq!(
            code,
            expect,
            "{method} {path} answered {code}: {raw}\n--- server log\n{}",
            self.log_text()
        );
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("{method} {path}: body is not JSON ({e}): {raw}"))
    }

    fn stats(&self, vault: &str) -> Value {
        self.call("GET", &format!("/v1/vaults/{vault}/stats"), None, 200)
    }

    /// A `/v1` save that must file, answering with the id it filed under.
    fn save(&self, content: &str) -> String {
        let saved = self.call(
            "POST",
            "/v1/vaults/default/drawers",
            Some(json!({ "text": content, "wing": "w" })),
            200,
        );
        assert_eq!(saved["quarantined"], json!(false), "{saved}");
        saved["id"]
            .as_str()
            .unwrap_or_else(|| panic!("a save answered with no id: {saved}"))
            .to_string()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One `serve-mcp` stdio session: each call on its own line, the process exits
/// at EOF, and every reply is matched by id. Returns each call's text, having
/// asserted that none of them is an error.
fn mcp(home: &Path, env: &Env, calls: &[(&str, Value)]) -> Vec<String> {
    let mut input = String::new();
    for (i, (name, args)) in calls.iter().enumerate() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": i + 1,
            "method": "tools/call",
            "params": { "name": name, "arguments": args },
        });
        input.push_str(&msg.to_string());
        input.push('\n');
    }
    let mut c = child(home, env);
    c.arg("serve-mcp");
    let out = run(c, Some(input));
    let (stdout, _) = succeeds(&out, "serve-mcp");
    let mut texts: Vec<Option<String>> = vec![None; calls.len()];
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let reply: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("MCP reply is not JSON ({e}): {line}"));
        let id = reply["id"]
            .as_u64()
            .filter(|id| (1..=calls.len() as u64).contains(id))
            .unwrap_or_else(|| panic!("MCP reply with no known id: {line}"))
            as usize;
        assert_eq!(
            reply["result"]["isError"],
            json!(false),
            "{} failed: {line}",
            calls[id - 1].0
        );
        let body = reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("MCP reply with no text: {line}"));
        texts[id - 1] = Some(body.to_string());
    }
    texts
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            t.unwrap_or_else(|| panic!("no reply to call {} ({}):\n{stdout}", i + 1, calls[i].0))
        })
        .collect()
}

fn status(text: &str) -> Value {
    serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("undercroft_status is not JSON ({e}): {text}"))
}

fn hits(v: &Value) -> Vec<Value> {
    v["hits"]
        .as_array()
        .unwrap_or_else(|| panic!("no hits array: {v}"))
        .clone()
}

fn is_poisoned(hit: &Value) -> bool {
    hit["content"]
        .as_str()
        .unwrap_or_else(|| panic!("hit without content: {hit}"))
        .contains(fixture::REFUSED_WORD)
}

/// A memory carrying the word whose id is past the fixture's embedding table
/// (ROADMAP O150).
fn out_of_table() -> String {
    format!("alpha {}", fixture::OUT_OF_TABLE_WORD)
}

/// The id in an MCP `saved drawer <id> in <wing>/<room>` reply.
fn saved_id(reply: &str) -> String {
    reply
        .strip_prefix("saved drawer ")
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_else(|| panic!("not a save reply: {reply}"))
        .to_string()
}

/// **ROADMAP O150's premise, read before any count.** The degrade lines in
/// `log` carrying `prefix`, each required to say WHICH failure it was: tract
/// CONTAINS a panic on an out-of-table id, ONNX Runtime REFUSES it with a
/// typed error. A line on the wrong side means the arm reached a different
/// failure than it claims to test, and a fixture that stopped panicking
/// produces no line at all — both fail HERE, by name, rather than as a count
/// that did not move. `exactly` is `None` where the number of lines is the
/// backend's own business: a reranked window (ROADMAP O151).
fn assert_out_of_table_lines(
    panics: bool,
    prefix: &str,
    log: &str,
    exactly: Option<usize>,
    what: &str,
) {
    let lines: Vec<&str> = log.lines().filter(|l| l.contains(prefix)).collect();
    // Zero lines first, in both modes, so a trigger that stopped triggering is
    // named as that rather than as a count that came out one short.
    assert!(
        !lines.is_empty(),
        "{what}: PREMISE — the out-of-table trigger reached no `{prefix}` degrade, so this arm tested nothing (did the fixture stop failing?):\n{log}"
    );
    if let Some(n) = exactly {
        assert_eq!(
            lines.len(),
            n,
            "{what}: expected exactly {n} `{prefix}` line(s):\n{log}"
        );
    }
    for line in lines {
        if panics {
            assert!(
                line.contains(CONTAINED_PANIC),
                "{what}: tract must report a CONTAINED panic: {line}"
            );
        } else {
            assert!(
                line.contains(TYPED_REFUSAL) && !line.contains(CONTAINED_PANIC),
                "{what}: ONNX Runtime must refuse with a typed error, never a panic: {line}"
            );
        }
    }
}

/// A `serve-mcp` stdio session driven one call at a time, so a later call can
/// name an id an earlier one returned — which `mcp` cannot, because it writes
/// every call before it reads any reply. stderr lands in a FILE (a pipe nobody
/// drains can block the child), stdout is read on a thread so every wait is
/// bounded, and the child is killed however the test ends.
struct McpSession {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    replies: std::sync::mpsc::Receiver<String>,
    log: PathBuf,
    next_id: u64,
}

impl McpSession {
    fn spawn(mut c: Command, log_dir: &Path, label: &str) -> McpSession {
        let log = log_dir.join(format!("serve-mcp-{label}.log"));
        let file = std::fs::File::create(&log).expect("serve-mcp log");
        c.arg("serve-mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(file);
        let mut child = c.spawn().expect("serve-mcp spawns");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("serve-mcp stdout");
        let (tx, replies) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        McpSession {
            child,
            stdin,
            replies,
            log,
            next_id: 0,
        }
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// One tool call, answering with its reply text, asserted not to be an
    /// error. A reply that never comes fails naming why: EOF means the process
    /// ended, which is what an uncontained panic does to this loop.
    fn call(&mut self, name: &str, args: Value) -> String {
        self.next_id += 1;
        let id = self.next_id;
        let msg = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": args },
        });
        let written = match self.stdin.as_mut() {
            Some(stdin) => writeln!(stdin, "{msg}").and_then(|()| stdin.flush()),
            None => Err(std::io::Error::other("stdin is already closed")),
        };
        if let Err(e) = written {
            panic!(
                "{name}: writing to serve-mcp failed ({e}) — the process may have ended:\n{}",
                self.log_text()
            );
        }
        loop {
            match self.replies.recv_timeout(Duration::from_secs(120)) {
                Ok(line) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let reply: Value = serde_json::from_str(&line)
                        .unwrap_or_else(|e| panic!("MCP reply is not JSON ({e}): {line}"));
                    if reply["id"].as_u64() != Some(id) {
                        continue;
                    }
                    assert_eq!(
                        reply["result"]["isError"],
                        json!(false),
                        "{name} failed: {line}\n--- serve-mcp log\n{}",
                        self.log_text()
                    );
                    return reply["result"]["content"][0]["text"]
                        .as_str()
                        .unwrap_or_else(|| panic!("MCP reply with no text: {line}"))
                        .to_string();
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!(
                    "{name}: EOF — serve-mcp closed its stdout without replying, so the process ended:\n{}",
                    self.log_text()
                ),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                    "{name}: no reply within 120 s:\n{}",
                    self.log_text()
                ),
            }
        }
    }

    fn count(&mut self, key: &str) -> u64 {
        count(&status(&self.call("undercroft_status", json!({}))), key)
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// **The embedder.** A failed embed stores a zero vector — lexically findable,
/// semantically invisible — and the count is the only thing that says so.
#[test]
fn model_embedder_failures_reach_cli_v1_and_mcp() {
    let _serial = serial();
    for (backend, loader, other) in [
        ("onnx", "loading ONNX embedder:", "loading ORT embedder:"),
        ("ort", "loading ORT embedder:", "loading ONNX embedder:"),
    ] {
        let home = tempfile::tempdir().expect("home");
        let h = home.path();
        let fx = fixture_files();
        let undeclared: Env = vec![
            ("UNDERCROFT_EMBEDDER", backend.to_string()),
            ("UNDERCROFT_ONNX_MODEL", fx.model.clone()),
            ("UNDERCROFT_ONNX_TOKENIZER", fx.tokenizer.clone()),
            ("UNDERCROFT_ONNX_NAME", format!("fixture-{backend}")),
        ];
        let declared = declared(&undeclared);
        let poison = poison();

        succeeds(&cli(h, &undeclared, &["init"]), "init");
        assert_routes_to(
            h,
            &with(
                &undeclared,
                &[("UNDERCROFT_ONNX_MODEL", fx.missing.clone())],
            ),
            loader,
            other,
        );

        // Undeclared: the open calibrates, the fixture refuses the probe
        // words, and this process's own count reaches `stats`. The count is
        // compared to this process's own degrade lines rather than to a
        // constant, which would be a fact about the probe table.
        let (p2, p2_err) = succeeds(&cli(h, &undeclared, &["stats"]), "stats, undeclared");
        assert_eq!(semantic_source(&p2), "refused", "{backend}:\n{p2}");
        let n = embed_failures_line(&p2).unwrap_or_else(|| {
            panic!("{backend}: calibration degraded and stats printed no count:\n{p2}\n{p2_err}")
        });
        assert!(n > 0, "{backend}");
        assert_eq!(
            p2_err.matches(EMBED_FAILED).count() as u64,
            n,
            "{backend}: the printed count and this process's degrade lines must agree:\n{p2_err}"
        );
        assert!(
            has_wings_line(&p2),
            "{backend}: stats did not complete:\n{p2}"
        );

        // Declared: the SAME binary and model, two variables apart — nothing
        // is embedded, so there is no line and no degrade.
        let (p3, p3_err) = succeeds(&cli(h, &declared, &["stats"]), "stats, declared");
        assert_eq!(semantic_source(&p3), "declared-off", "{backend}:\n{p3}");
        assert_eq!(embed_failures_line(&p3), None, "{backend}:\n{p3}");
        assert_eq!(
            p3_err.matches(EMBED_FAILED).count(),
            0,
            "{backend}:\n{p3_err}"
        );
        assert!(
            has_wings_line(&p3),
            "{backend}: stats did not complete:\n{p3}"
        );
        assert_ne!(
            semantic_source(&p2),
            semantic_source(&p3),
            "premise: the discriminator separates the two arms"
        );

        // CLI writes and a query: the working process's own stderr is the
        // only CLI evidence, because `stats` is a different process.
        let (_, w1) = succeeds(
            &cli(h, &declared, &["remember", fixture::HEALTHY, "--wing", "w"]),
            "remember, healthy",
        );
        assert_eq!(w1.matches(EMBED_FAILED).count(), 0, "{backend}:\n{w1}");
        let (_, w2) = succeeds(
            &cli(h, &declared, &["remember", &poison, "--wing", "w"]),
            "remember, poisoned",
        );
        assert_eq!(
            w2.matches(EMBED_FAILED).count(),
            1,
            "{backend}: one poisoned write embeds once:\n{w2}"
        );
        let (w3_out, w3) = succeeds(
            &cli(h, &declared, &["search", fixture::REFUSED_WORD]),
            "search, poisoned",
        );
        assert!(
            w3_out.contains(fixture::REFUSED_WORD),
            "{backend}: the poisoned drawer is still found lexically:\n{w3_out}"
        );
        assert_eq!(
            w3.matches(EMBED_FAILED).count(),
            1,
            "{backend}: the query embeds once:\n{w3}"
        );

        // /v1: exact deltas inside one server, with a healthy control.
        succeeds(
            &cli(h, &declared, &["vault", "create", "other"]),
            "vault create",
        );
        {
            let server = Server::spawn(child(h, &declared), h);
            let s = server.stats("default");
            assert_eq!(s["semantic"]["gate_source"], json!("declared-off"), "{s}");
            let e0 = count(&s, "embed_failures");
            server.save(fixture::HEALTHY);
            assert_eq!(
                count(&server.stats("default"), "embed_failures"),
                e0,
                "{backend}: a healthy /v1 write moved the count"
            );
            let o0 = count(&server.stats("other"), "embed_failures");
            server.save(&poison);
            assert_eq!(
                count(&server.stats("default"), "embed_failures"),
                e0 + 1,
                "{backend}: one poisoned /v1 write counts exactly once"
            );
            // The identity premise for the served embedder: under ort every
            // vault on the server embeds through ONE shared model, so the
            // other vault's count moves too; under onnx each vault has its own.
            assert_eq!(
                count(&server.stats("other"), "embed_failures"),
                o0 + u64::from(backend == "ort"),
                "{backend}: the served embedder's sharing contract"
            );
        }

        // MCP stdio: the same exact deltas, through `VaultStats` serialized whole.
        let replies = mcp(
            h,
            &declared,
            &[
                ("undercroft_status", json!({})),
                (
                    "undercroft_save",
                    json!({ "content": fixture::HEALTHY, "wing": "w" }),
                ),
                ("undercroft_status", json!({})),
                ("undercroft_save", json!({ "content": poison, "wing": "w" })),
                ("undercroft_status", json!({})),
            ],
        );
        for saved in [&replies[1], &replies[3]] {
            assert!(saved.starts_with("saved drawer "), "{backend}: {saved}");
        }
        let (s1, s3, s5) = (
            status(&replies[0]),
            status(&replies[2]),
            status(&replies[4]),
        );
        assert_eq!(s1["semantic"]["gate_source"], json!("declared-off"), "{s1}");
        assert_eq!(
            count(&s3, "embed_failures"),
            count(&s1, "embed_failures"),
            "{backend}: a healthy MCP save moved the count"
        );
        assert_eq!(
            count(&s5, "embed_failures"),
            count(&s3, "embed_failures") + 1,
            "{backend}: one poisoned MCP save counts exactly once"
        );
    }
}

/// **The reranker.** A failed pass scores `0.0`, which sinks a real memory
/// below irrelevant ones and leaves no artifact at all. The scenario is the
/// filed one: a poisoned STORED passage, searched later. Deltas are "greater",
/// never exact, and no order is asserted: tract degrades per passage and ORT
/// the whole window (ROADMAP O151), and pinning either here would pin O151 a
/// second time.
#[test]
fn model_reranker_failures_reach_v1_mcp_and_cli() {
    let _serial = serial();
    let poison = poison();
    assert!(
        fixture::HEALTHY.split(' ').any(|w| w == "beta") && !poison.contains("beta"),
        "premise: only the healthy drawer answers 'beta'"
    );
    for (backend, loader, other) in [
        ("onnx", "loading ONNX reranker:", "loading ORT reranker:"),
        ("ort", "loading ORT reranker:", "loading ONNX reranker:"),
    ] {
        let home = tempfile::tempdir().expect("home");
        let h = home.path();
        let fx = fixture_files();
        let mut env: Env = vec![
            ("UNDERCROFT_SEMANTIC_GATE", "off".to_string()),
            ("UNDERCROFT_RERANKER", backend.to_string()),
            ("UNDERCROFT_RERANK_MODEL", fx.model.clone()),
            ("UNDERCROFT_RERANK_TOKENIZER", fx.tokenizer.clone()),
            ("UNDERCROFT_RERANK_NAME", format!("fixture-{backend}")),
        ];
        if backend == "ort" {
            env.push(("UNDERCROFT_ORT_POOL", "1".to_string()));
        }

        succeeds(&cli(h, &env, &["init"]), "init");
        assert_routes_to(
            h,
            &with(&env, &[("UNDERCROFT_RERANK_MODEL", fx.missing.clone())]),
            loader,
            other,
        );

        {
            let server = Server::spawn(child(h, &env), h);
            server.save(fixture::HEALTHY);
            server.save(&poison);
            let r0 = count(&server.stats("default"), "rerank_failures");

            let healthy = server.call(
                "POST",
                "/v1/vaults/default/search",
                Some(json!({ "query": "beta" })),
                200,
            );
            assert!(!hits(&healthy).is_empty(), "{backend}: {healthy}");
            assert!(
                !hits(&healthy).iter().any(is_poisoned),
                "premise: the healthy query must not admit the poisoned drawer: {healthy}"
            );
            assert_eq!(
                count(&server.stats("default"), "rerank_failures"),
                r0,
                "{backend}: a healthy rerank moved the count"
            );

            let poisoned = server.call(
                "POST",
                "/v1/vaults/default/search",
                Some(json!({ "query": "alpha" })),
                200,
            );
            let bad: Vec<Value> = hits(&poisoned).into_iter().filter(is_poisoned).collect();
            assert_eq!(bad.len(), 1, "{backend}: {poisoned}");
            assert_eq!(
                bad[0]["score"].as_f64(),
                Some(0.0),
                "{backend}: a failed rerank scores 0.0: {poisoned}"
            );
            assert!(
                count(&server.stats("default"), "rerank_failures") > r0,
                "{backend}: the failed rerank reached /v1 stats"
            );
        }

        let replies = mcp(
            h,
            &env,
            &[
                ("undercroft_status", json!({})),
                ("undercroft_search", json!({ "query": "beta" })),
                ("undercroft_status", json!({})),
                ("undercroft_search", json!({ "query": "alpha" })),
                ("undercroft_status", json!({})),
            ],
        );
        let (s1, s3, s5) = (
            status(&replies[0]),
            status(&replies[2]),
            status(&replies[4]),
        );
        assert_eq!(
            count(&s3, "rerank_failures"),
            count(&s1, "rerank_failures"),
            "{backend}: a healthy MCP rerank moved the count"
        );
        assert!(
            count(&s5, "rerank_failures") > count(&s3, "rerank_failures"),
            "{backend}: the failed rerank reached MCP status"
        );

        let (_, healthy_err) = succeeds(&cli(h, &env, &["search", "beta"]), "search beta");
        assert_eq!(
            healthy_err.matches(RERANK_FAILED).count(),
            0,
            "{backend}:\n{healthy_err}"
        );
        let (out, err) = succeeds(&cli(h, &env, &["search", "alpha"]), "search alpha");
        assert!(out.contains(fixture::REFUSED_WORD), "{backend}:\n{out}");
        assert!(
            err.matches(RERANK_FAILED).count() >= 1,
            "{backend}: the CLI's own degrade line:\n{err}"
        );
    }
}

/// **The ColBERT late stage.** A doc-side failure leaves a drawer with no
/// token matrix at rest; a query-side failure retires the stage for one
/// search. Both encode once per call on both backends, so the deltas are
/// exact. `/v1` cannot carry the stage at all — `serve-http` refuses it at
/// start-up — and that refusal is pinned here as a BOUNDARY, so it cannot
/// silently become a gap.
#[test]
fn model_late_failures_reach_mcp_and_cli_and_v1_refuses_the_stage() {
    let _serial = serial();
    let poison = poison();
    for (backend, loader, other) in [
        (
            "colbert",
            "loading ColBERT encoder:",
            "loading ORT ColBERT encoder:",
        ),
        (
            "colbert-ort",
            "loading ORT ColBERT encoder:",
            "loading ColBERT encoder:",
        ),
    ] {
        let home = tempfile::tempdir().expect("home");
        let h = home.path();
        let fx = fixture_files();
        let env: Env = vec![
            ("UNDERCROFT_SEMANTIC_GATE", "off".to_string()),
            ("UNDERCROFT_RERANKER", backend.to_string()),
            ("UNDERCROFT_COLBERT_MODEL", fx.model.clone()),
            ("UNDERCROFT_COLBERT_QUERY_MODEL", fx.model.clone()),
            ("UNDERCROFT_COLBERT_TOKENIZER", fx.tokenizer.clone()),
            ("UNDERCROFT_COLBERT_NAME", format!("fixture-{backend}")),
        ];

        succeeds(&cli(h, &env, &["init"]), "init");
        assert_routes_to(
            h,
            &with(
                &env,
                &[
                    ("UNDERCROFT_COLBERT_MODEL", fx.missing.clone()),
                    ("UNDERCROFT_COLBERT_QUERY_MODEL", fx.missing.clone()),
                ],
            ),
            loader,
            other,
        );

        let replies = mcp(
            h,
            &env,
            &[
                ("undercroft_status", json!({})),
                (
                    "undercroft_save",
                    json!({ "content": fixture::HEALTHY, "wing": "w" }),
                ),
                ("undercroft_status", json!({})),
                ("undercroft_save", json!({ "content": poison, "wing": "w" })),
                ("undercroft_status", json!({})),
                ("undercroft_search", json!({ "query": "alpha" })),
                ("undercroft_status", json!({})),
                ("undercroft_search", json!({ "query": poison })),
                ("undercroft_status", json!({})),
            ],
        );
        let late: Vec<u64> = [0, 2, 4, 6, 8]
            .iter()
            .map(|&i| count(&status(&replies[i]), "late_failures"))
            .collect();
        assert_eq!(
            late[1], late[0],
            "{backend}: a healthy doc encode moved the count"
        );
        assert_eq!(
            late[2],
            late[1] + 1,
            "{backend}: one poisoned doc encodes once"
        );
        assert_eq!(
            late[3], late[2],
            "{backend}: a healthy query encode moved the count"
        );
        assert_eq!(
            late[4],
            late[3] + 1,
            "{backend}: one poisoned query encodes once"
        );

        let (_, e) = succeeds(
            &cli(h, &env, &["remember", "alpha gamma", "--wing", "w"]),
            "remember, healthy",
        );
        assert_eq!(e.matches(DOC_ENCODE_FAILED).count(), 0, "{backend}:\n{e}");
        let doc = format!("gamma {}", fixture::REFUSED_WORD);
        let (_, e) = succeeds(
            &cli(h, &env, &["remember", &doc, "--wing", "w"]),
            "remember, poisoned",
        );
        assert_eq!(e.matches(DOC_ENCODE_FAILED).count(), 1, "{backend}:\n{e}");
        let (_, e) = succeeds(&cli(h, &env, &["search", "gamma"]), "search, healthy");
        assert_eq!(e.matches(QUERY_ENCODE_FAILED).count(), 0, "{backend}:\n{e}");
        let (_, e) = succeeds(&cli(h, &env, &["search", &doc]), "search, poisoned");
        assert_eq!(e.matches(QUERY_ENCODE_FAILED).count(), 1, "{backend}:\n{e}");

        // The /v1 boundary: the multi-tenant server refuses the stage before
        // it binds. A server that started instead is killed by the timeout
        // and fails the message check.
        let port = free_port().to_string();
        let mut c = child(h, &env);
        c.args(["serve-http", "--host", "127.0.0.1", "--port", &port]);
        let mut cmd = assert_cmd::Command::from_std(c);
        cmd.timeout(Duration::from_secs(120));
        let out = cmd.output().expect("serve-http runs");
        let stderr = text(&out.stderr);
        assert!(
            !out.status.success(),
            "{backend}: serve-http must refuse:\n{stderr}"
        );
        assert!(
            stderr.contains(
                "the ColBERT late-interaction stage is not available on the multi-tenant server"
            ),
            "{backend}: the multi-tenant server did not name its refusal of the late stage:\n{stderr}"
        );
    }
}

/// **The embedder SURVIVES an out-of-table write** (ROADMAP O150, the O157
/// follow-on). Before O150 this write ended the `/v1` server and the MCP
/// session under `onnx`. On each surface, in order: the degrade line says
/// which failure it was, the count moved by exactly one, the drawer is
/// verbatim, and the SAME process files and finds a healthy memory afterwards.
#[test]
fn model_embedder_survives_an_out_of_table_write_on_v1_mcp_and_cli() {
    let _serial = serial();
    let word = out_of_table();
    for (backend, panics) in [("onnx", true), ("ort", false)] {
        let home = tempfile::tempdir().expect("home");
        let h = home.path();
        let fx = fixture_files();
        let env = declared(&vec![
            ("UNDERCROFT_EMBEDDER", backend.to_string()),
            ("UNDERCROFT_ONNX_MODEL", fx.model.clone()),
            ("UNDERCROFT_ONNX_TOKENIZER", fx.tokenizer.clone()),
            ("UNDERCROFT_ONNX_NAME", format!("fixture-{backend}")),
        ]);
        succeeds(&cli(h, &env, &["init"]), "init");

        {
            let server = Server::spawn(child(h, &env), h);
            let e0 = count(&server.stats("default"), "embed_failures");
            let id = server.save(&word);
            assert_out_of_table_lines(
                panics,
                EMBED_FAILED,
                &server.log_text(),
                Some(1),
                &format!("{backend}, /v1 save"),
            );
            assert_eq!(
                count(&server.stats("default"), "embed_failures"),
                e0 + 1,
                "{backend}: the out-of-table /v1 write counts exactly once"
            );
            let got = server.call(
                "GET",
                &format!("/v1/vaults/default/drawers/{id}"),
                None,
                200,
            );
            assert_eq!(
                got["drawer"]["content"],
                json!(word),
                "{backend}: the drawer is verbatim despite its degraded embed: {got}"
            );
            server.save(fixture::HEALTHY);
            let found = server.call(
                "POST",
                "/v1/vaults/default/search",
                Some(json!({ "query": "beta" })),
                200,
            );
            assert!(
                hits(&found)
                    .iter()
                    .any(|hit| hit["content"] == json!(fixture::HEALTHY)),
                "{backend}: the server must still file and find a healthy memory: {found}"
            );
            assert_eq!(
                count(&server.stats("default"), "embed_failures"),
                e0 + 1,
                "{backend}: the healthy write and search after it moved the count"
            );
        }

        {
            let mut mcp = McpSession::spawn(child(h, &env), h, &format!("embed-{backend}"));
            let s0 = mcp.count("embed_failures");
            let id =
                saved_id(&mcp.call("undercroft_save", json!({ "content": word, "wing": "w" })));
            assert_out_of_table_lines(
                panics,
                EMBED_FAILED,
                &mcp.log_text(),
                Some(1),
                &format!("{backend}, MCP save"),
            );
            assert_eq!(
                mcp.count("embed_failures"),
                s0 + 1,
                "{backend}: the out-of-table MCP save counts exactly once"
            );
            let got: Value =
                serde_json::from_str(&mcp.call("undercroft_get_drawer", json!({ "id": id })))
                    .expect("get_drawer answers with the drawer as JSON");
            assert_eq!(
                got["content"],
                json!(word),
                "{backend}: the drawer is verbatim despite its degraded embed: {got}"
            );
            let healthy = mcp.call(
                "undercroft_save",
                json!({ "content": fixture::HEALTHY, "wing": "w" }),
            );
            assert!(healthy.starts_with("saved drawer "), "{backend}: {healthy}");
            let found = mcp.call("undercroft_search", json!({ "query": "beta" }));
            assert!(
                found.contains(fixture::HEALTHY),
                "{backend}: the session must still find a healthy memory: {found}"
            );
            assert_eq!(
                mcp.count("embed_failures"),
                s0 + 1,
                "{backend}: the healthy save and search after it moved the count"
            );
        }

        let (_, err) = succeeds(
            &cli(h, &env, &["remember", &word, "--wing", "w"]),
            "remember, out-of-table",
        );
        assert_out_of_table_lines(
            panics,
            EMBED_FAILED,
            &err,
            Some(1),
            &format!("{backend}, CLI remember"),
        );
    }
}

/// **The late stage SURVIVES an out-of-table write** (ROADMAP O150). The worst
/// path before O150: the doc encode runs AFTER the drawer commits, so a panic
/// there left a stored drawer and no reply, and a client's retry filed a
/// duplicate. MCP and the CLI only — `/v1` refuses the stage at start-up,
/// which `model_late_failures_reach_mcp_and_cli_and_v1_refuses_the_stage` pins.
#[test]
fn model_late_stage_survives_an_out_of_table_write_on_mcp_and_cli() {
    let _serial = serial();
    let word = out_of_table();
    for (backend, panics) in [("colbert", true), ("colbert-ort", false)] {
        let home = tempfile::tempdir().expect("home");
        let h = home.path();
        let fx = fixture_files();
        let env: Env = vec![
            ("UNDERCROFT_SEMANTIC_GATE", "off".to_string()),
            ("UNDERCROFT_RERANKER", backend.to_string()),
            ("UNDERCROFT_COLBERT_MODEL", fx.model.clone()),
            ("UNDERCROFT_COLBERT_QUERY_MODEL", fx.model.clone()),
            ("UNDERCROFT_COLBERT_TOKENIZER", fx.tokenizer.clone()),
            ("UNDERCROFT_COLBERT_NAME", format!("fixture-{backend}")),
        ];
        succeeds(&cli(h, &env, &["init"]), "init");

        {
            let mut mcp = McpSession::spawn(child(h, &env), h, &format!("late-{backend}"));
            let l0 = mcp.count("late_failures");
            let id =
                saved_id(&mcp.call("undercroft_save", json!({ "content": word, "wing": "w" })));
            assert_out_of_table_lines(
                panics,
                DOC_ENCODE_FAILED,
                &mcp.log_text(),
                Some(1),
                &format!("{backend}, MCP save"),
            );
            assert_eq!(
                mcp.count("late_failures"),
                l0 + 1,
                "{backend}: the out-of-table doc encode counts exactly once"
            );
            let got: Value =
                serde_json::from_str(&mcp.call("undercroft_get_drawer", json!({ "id": id })))
                    .expect("get_drawer answers with the drawer as JSON");
            assert_eq!(
                got["content"],
                json!(word),
                "{backend}: the drawer is verbatim despite its missing token matrix: {got}"
            );
            let healthy = mcp.call(
                "undercroft_save",
                json!({ "content": fixture::HEALTHY, "wing": "w" }),
            );
            assert!(healthy.starts_with("saved drawer "), "{backend}: {healthy}");
            let found = mcp.call("undercroft_search", json!({ "query": "beta" }));
            assert!(
                found.contains(fixture::HEALTHY),
                "{backend}: the session must still find a healthy memory: {found}"
            );
            assert_eq!(
                mcp.count("late_failures"),
                l0 + 1,
                "{backend}: the healthy save and search after it moved the count"
            );
        }

        let (out, err) = succeeds(
            &cli(h, &env, &["remember", &word, "--wing", "w"]),
            "remember, out-of-table",
        );
        assert_out_of_table_lines(
            panics,
            DOC_ENCODE_FAILED,
            &err,
            Some(1),
            &format!("{backend}, CLI remember"),
        );
        let id = out
            .lines()
            .find_map(|l| l.strip_prefix("Filed drawer "))
            .and_then(|rest| rest.split(' ').next())
            .unwrap_or_else(|| panic!("{backend}: remember named no drawer id:\n{out}"))
            .to_string();
        let (got, _) = succeeds(&cli(h, &env, &["drawer", "get", &id]), "drawer get");
        assert!(
            got.ends_with(&format!("---\n{word}\n")),
            "{backend}: `drawer get` must print the drawer verbatim:\n{got}"
        );
    }
}

/// **The reranker SURVIVES an out-of-table passage** (ROADMAP O150). A search
/// over a stored drawer carrying the word ended the `/v1` server under `onnx`.
/// The count only has to RISE: tract degrades per passage and ORT the whole
/// window (ROADMAP O151), and pinning either here would pin O151 twice.
#[test]
fn model_reranker_survives_an_out_of_table_passage_on_v1_and_mcp() {
    let _serial = serial();
    let word = out_of_table();
    for (backend, panics) in [("onnx", true), ("ort", false)] {
        let home = tempfile::tempdir().expect("home");
        let h = home.path();
        let fx = fixture_files();
        let mut env: Env = vec![
            ("UNDERCROFT_SEMANTIC_GATE", "off".to_string()),
            ("UNDERCROFT_RERANKER", backend.to_string()),
            ("UNDERCROFT_RERANK_MODEL", fx.model.clone()),
            ("UNDERCROFT_RERANK_TOKENIZER", fx.tokenizer.clone()),
            ("UNDERCROFT_RERANK_NAME", format!("fixture-{backend}")),
        ];
        if backend == "ort" {
            env.push(("UNDERCROFT_ORT_POOL", "1".to_string()));
        }
        succeeds(&cli(h, &env, &["init"]), "init");

        {
            let server = Server::spawn(child(h, &env), h);
            server.save(fixture::HEALTHY);
            server.save(&word);
            let r0 = count(&server.stats("default"), "rerank_failures");
            let found = server.call(
                "POST",
                "/v1/vaults/default/search",
                Some(json!({ "query": "alpha" })),
                200,
            );
            assert_out_of_table_lines(
                panics,
                RERANK_FAILED,
                &server.log_text(),
                None,
                &format!("{backend}, /v1 search"),
            );
            assert!(
                hits(&found).iter().any(|hit| hit["content"] == json!(word)),
                "{backend}: the search must answer with the drawer it failed to rerank: {found}"
            );
            assert!(
                count(&server.stats("default"), "rerank_failures") > r0,
                "{backend}: the failed rerank reached /v1 stats"
            );
            let healthy = server.call(
                "POST",
                "/v1/vaults/default/search",
                Some(json!({ "query": "beta" })),
                200,
            );
            assert!(
                !hits(&healthy).is_empty(),
                "{backend}: the server must still answer a healthy search: {healthy}"
            );
        }

        {
            let mut mcp = McpSession::spawn(child(h, &env), h, &format!("rerank-{backend}"));
            let r0 = mcp.count("rerank_failures");
            let found = mcp.call("undercroft_search", json!({ "query": "alpha" }));
            assert_out_of_table_lines(
                panics,
                RERANK_FAILED,
                &mcp.log_text(),
                None,
                &format!("{backend}, MCP search"),
            );
            assert!(
                found.contains(&word),
                "{backend}: the search must answer with the drawer it failed to rerank: {found}"
            );
            assert!(
                mcp.count("rerank_failures") > r0,
                "{backend}: the failed rerank reached MCP status"
            );
            let healthy = mcp.call("undercroft_search", json!({ "query": "beta" }));
            assert!(
                healthy.contains(fixture::HEALTHY),
                "{backend}: the session must still answer a healthy search: {healthy}"
            );
        }
    }
}
