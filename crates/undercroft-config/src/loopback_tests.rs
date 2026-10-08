//! **ROADMAP O177's source gate: the loopback literals live in ONE function.**
//!
//! Two implementations of one security predicate drifted apart once already,
//! and a second copy is the observable this class moves: a test that only
//! calls the function cannot see a copy that never calls it. So this reads
//! every `.rs` under `crates/` and finds every string literal whose contents
//! are exactly `127.0.0.1`, `localhost` or `::1` in code compiled outside
//! tests. Comparison, `.eq`, `matches!`, `eq_ignore_ascii_case`, a `const`, an
//! `if let`, a match arm, an array, a raw or a byte string are all one token
//! to it. This replaced a first version that recognised `==`, `!=`, a match
//! arm and a line naming two of the literals, and that an independent review
//! walked past with six single-literal spellings.
//!
//! **Test code** is what the module tree says it is, never a file name: every
//! crate's `tests/` and `benches/` targets, every file a `mod` declaration
//! under a `cfg` naming `test` brings in (and everything below it), and every
//! item under such a `cfg` (`#[cfg(test)] mod tests`, `cfg(any(test, …))`;
//! `cfg(not(test))` is production). A file no module tree reaches is scanned as
//! production, so a stray copy is seen rather than excused.
//!
//! Four sites hold the literals in production, each REQUIRED to be reached
//! with exactly the count named, so a rename or a rewrite cannot silently
//! widen it:
//! - `undercroft-config`'s `host_is_loopback`, each literal once: the
//!   listen-host predicate.
//! - `undercroft-net`'s `is_loopback`, `localhost` once, against a parsed
//!   `url::Host::Domain`. It is an OUTBOUND URL predicate that asks the
//!   transport's own parser and reads a parsed address through its own
//!   `is_loopback` (O92's rule). It cannot share the listen-host predicate,
//!   because a URL has a scheme, userinfo and a typed host.
//! - `undercroft-index`'s `dsn_is_loopback`, `localhost` once, against the
//!   connector's own parsed `Host::Tcp` (O90's rule), for the same reason one
//!   protocol over.
//! - `undercroft-cli`'s `ServeHttp` arguments, `127.0.0.1` once: the default
//!   `--host`, which is a value bound, not a decision about one.
//!
//! What it cannot see, stated: a copy that never writes the literal as one
//! token (`concat!`, `Ipv6Addr::LOCALHOST`, a byte-by-byte comparison), a copy
//! outside `crates/`, and production code a `cfg(any(test, feature = …))` item
//! compiles under that feature.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The spellings `host_is_loopback` holds, in its order.
const LOOPBACK: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

/// Rust source with every comment, string literal and char literal blanked to
/// spaces (newlines kept, so byte offsets still line up with the text), and
/// every string literal's offset and raw contents.
struct Lexed {
    code: String,
    strings: Vec<(usize, String)>,
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn blank(code: &mut [u8], from: usize, to: usize) {
    let to = to.min(code.len());
    for c in &mut code[from..to] {
        if *c != b'\n' {
            *c = b' ';
        }
    }
}

fn lex(text: &str) -> Lexed {
    let b = text.as_bytes();
    let mut code = b.to_vec();
    let mut strings = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        // A line comment, doc comments included.
        if c == b'/' && next == Some(b'/') {
            let end = b[i..]
                .iter()
                .position(|&x| x == b'\n')
                .map_or(b.len(), |p| i + p);
            blank(&mut code, i, end);
            i = end;
            continue;
        }
        // A block comment, which nests.
        if c == b'/' && next == Some(b'*') {
            let (mut depth, mut j) = (1, i + 2);
            while j < b.len() && depth > 0 {
                if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut code, i, j);
            i = j;
            continue;
        }
        // A raw string: r"…", r#"…"#, br"…". The `r` must start a token.
        let starts_token = i == 0 || !is_ident(b[i - 1]);
        if starts_token && (c == b'r' || (c == b'b' && next == Some(b'r'))) {
            let r = if c == b'b' { i + 1 } else { i };
            let mut j = r + 1;
            while b.get(j) == Some(&b'#') {
                j += 1;
            }
            let hashes = j - r - 1;
            if b.get(j) == Some(&b'"') {
                let start = j + 1;
                let mut k = start;
                while k < b.len()
                    && !(b[k] == b'"'
                        && b[k + 1..]
                            .iter()
                            .take(hashes)
                            .filter(|&&x| x == b'#')
                            .count()
                            == hashes)
                {
                    k += 1;
                }
                let end = k.min(b.len());
                strings.push((i, text[start..end].to_string()));
                let close = end + 1 + hashes;
                blank(&mut code, i, close);
                i = close;
                continue;
            }
        }
        // A string, or the body of a byte string whose `b` stays code.
        if c == b'"' {
            let start = i + 1;
            let mut k = start;
            while k < b.len() && b[k] != b'"' {
                if b[k] == b'\\' {
                    k += 1;
                }
                k += 1;
            }
            let end = k.min(b.len());
            strings.push((i, text[start..end].to_string()));
            blank(&mut code, i, end + 1);
            i = end + 1;
            continue;
        }
        // A char literal; a lifetime stays code.
        if c == b'\'' {
            if next == Some(b'\\') {
                let mut k = i + 3;
                while k < b.len() && b[k] != b'\'' {
                    k += 1;
                }
                blank(&mut code, i, k + 1);
                i = k + 1;
                continue;
            }
            if let Some(ch) = text[i + 1..].chars().next() {
                let after = i + 1 + ch.len_utf8();
                if b.get(after) == Some(&b'\'') {
                    blank(&mut code, i, after + 1);
                    i = after + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    Lexed {
        code: String::from_utf8(code).expect("blanking replaces whole characters"),
        strings,
    }
}

/// The offset of the bracket that closes the one at `open`.
fn close_of(b: &[u8], open: usize) -> usize {
    let (o, c) = match b[open] {
        b'[' => (b'[', b']'),
        b'(' => (b'(', b')'),
        _ => (b'{', b'}'),
    };
    let mut depth = 0i32;
    for (k, &x) in b.iter().enumerate().skip(open) {
        if x == o {
            depth += 1;
        } else if x == c {
            depth -= 1;
            if depth == 0 {
                return k;
            }
        }
    }
    b.len().saturating_sub(1)
}

/// Where the item starting at `from` ends: its block, its `;`, or, for a
/// field, an argument or a match arm, its `,`. Leading attributes belong to it.
fn item_end(b: &[u8], from: usize) -> usize {
    let mut depth = 0i32;
    let mut k = from;
    while k < b.len() {
        match b[k] {
            b'#' if depth == 0 && b.get(k + 1) == Some(&b'[') => {
                k = close_of(b, k + 1) + 1;
                continue;
            }
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => {
                if depth == 0 {
                    return k;
                }
                depth -= 1;
                if depth == 0 && b[k] == b'}' {
                    return k + 1;
                }
            }
            b';' | b',' if depth == 0 => return k + 1,
            _ => {}
        }
        k += 1;
    }
    b.len()
}

/// Whether a `cfg` attribute compiles its item for tests only.
fn names_test(attr: &str) -> bool {
    if attr.contains("not(test") {
        return false;
    }
    let edge = |c: Option<u8>| c.is_none_or(|c| !is_ident(c));
    attr.match_indices("test").any(|(i, _)| {
        edge(i.checked_sub(1).map(|p| attr.as_bytes()[p]))
            && edge(attr.as_bytes().get(i + 4).copied())
    })
}

/// Byte ranges of a source file.
type Ranges = Vec<(usize, usize)>;

/// `mod name;` declarations, each with whether it is test-only.
type ModDecls = Vec<(String, bool)>;

/// The byte ranges of `code` compiled for tests only, and every `mod name;`
/// declared in it with whether that declaration is test-only.
fn test_regions(code: &str) -> (Ranges, ModDecls) {
    let b = code.as_bytes();
    let mut regions = Vec::new();
    for (at, _) in code.match_indices("#![cfg(") {
        if names_test(&code[at..=close_of(b, at + 2)]) {
            regions.push((0, b.len()));
        }
    }
    for (at, _) in code.match_indices("#[cfg(") {
        let attr_end = close_of(b, at + 1);
        if names_test(&code[at..=attr_end]) {
            regions.push((at, item_end(b, attr_end + 1)));
        }
    }
    let mut mods = Vec::new();
    let mut offset = 0;
    for line in code.split_inclusive('\n') {
        if let Some(at) = line.rfind("mod ") {
            let head_ok = at == 0 || !is_ident(line.as_bytes()[at - 1]);
            if let Some(name) = line[at + 4..].trim().strip_suffix(';') {
                if head_ok && !name.is_empty() && name.bytes().all(is_ident) {
                    let pos = offset + at;
                    let in_test = regions.iter().any(|&(s, e)| (s..e).contains(&pos));
                    mods.push((name.to_string(), in_test));
                }
            }
        }
        offset += line.len();
    }
    (regions, mods)
}

/// The byte range of the braced body that follows the first `anchor` in code.
fn brace_region(code: &str, anchor: &str) -> Option<(usize, usize)> {
    let at = code.find(anchor)?;
    let open = at + code[at..].find('{')?;
    Some((at, close_of(code.as_bytes(), open) + 1))
}

/// Where a loopback literal sits.
#[derive(Debug, PartialEq)]
enum Seen {
    /// In code compiled for tests only.
    Test,
    /// Inside the allowed body handed in.
    Allowed,
    /// Anywhere else: a copy.
    Copy,
}

/// Every loopback literal in `text`: its offset, which spelling, and where.
fn sightings(text: &str, file_is_test: bool, anchor: Option<&str>) -> Vec<(usize, usize, Seen)> {
    let lexed = lex(text);
    let (regions, _) = test_regions(&lexed.code);
    let body = anchor
        .map(|a| brace_region(&lexed.code, a).unwrap_or_else(|| panic!("no longer holds `{a}`")));
    let mut out = Vec::new();
    for (at, content) in &lexed.strings {
        let Some(which) = LOOPBACK.iter().position(|l| l == content) else {
            continue;
        };
        let seen = if file_is_test || regions.iter().any(|&(s, e)| (s..e).contains(at)) {
            Seen::Test
        } else if body.is_some_and(|(s, e)| (s..e).contains(at)) {
            Seen::Allowed
        } else {
            Seen::Copy
        };
        out.push((*at, which, seen));
    }
    out
}

/// Every `.rs` under `crates/`, and the test status the module tree gives each
/// file it reaches, from every crate's roots down every `mod` declaration.
fn classify(crates: &Path) -> (Vec<PathBuf>, HashMap<PathBuf, bool>) {
    let mut files = Vec::new();
    let mut stack = vec![crates.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("crates/ is readable") {
            let path = entry.expect("a readable entry").path();
            if path.is_dir() {
                if !path.ends_with("target") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    // (file, test only, a crate root)
    let mut queue: Vec<(PathBuf, bool, bool)> = Vec::new();
    for entry in std::fs::read_dir(crates).expect("crates/ is readable") {
        let krate = entry.expect("a readable entry").path();
        if !krate.join("Cargo.toml").is_file() {
            continue;
        }
        for root in ["src/lib.rs", "src/main.rs", "build.rs"] {
            if krate.join(root).is_file() {
                queue.push((krate.join(root), false, true));
            }
        }
        for (dir, is_test) in [
            ("src/bin", false),
            ("examples", false),
            ("tests", true),
            ("benches", true),
        ] {
            let Ok(listing) = std::fs::read_dir(krate.join(dir)) else {
                continue;
            };
            for e in listing {
                let p = e.expect("a readable entry").path();
                if p.extension().is_some_and(|x| x == "rs") {
                    queue.push((p, is_test, true));
                }
            }
        }
    }
    let mut test = HashMap::new();
    while let Some((file, is_test, root)) = queue.pop() {
        if test.contains_key(&file) {
            continue;
        }
        test.insert(file.clone(), is_test);
        let text = std::fs::read_to_string(&file).expect("a readable source");
        let (_, mods) = test_regions(&lex(&text).code);
        let dir = file.parent().expect("a file has a directory");
        let moddir = if root || file.file_name().is_some_and(|n| n == "mod.rs") {
            dir.to_path_buf()
        } else {
            dir.join(file.file_stem().expect("a file has a stem"))
        };
        for (name, decl_test) in mods {
            let flat = moddir.join(format!("{name}.rs"));
            let child = if flat.is_file() {
                flat
            } else {
                moddir.join(&name).join("mod.rs")
            };
            if child.is_file() {
                queue.push((child, is_test || decl_test, false));
            }
        }
    }
    (files, test)
}

/// The lexer, the test-region reader and the module reader, on planted text:
/// every spelling a copy could take is a copy, and everything else is not.
#[test]
fn the_loopback_gate_sees_every_spelling_of_a_copy() {
    let copies = [
        r#"fn a(host: &str) -> bool { host == "::1" }"#,
        r#"fn a(host: &str) -> bool { host.eq("::1") }"#,
        r#"fn a(host: &str) -> bool { matches!(host, "localhost") }"#,
        r#"fn a(host: &str) -> bool { host.eq_ignore_ascii_case("localhost") }"#,
        "const LOOP6: &str = \"::1\";\nfn a(host: &str) -> bool { host == LOOP6 }",
        r#"fn a(host: &str) { if let "127.0.0.1" = host {} }"#,
        r#"fn a(h: Option<&str>) -> bool { match h { Some("localhost") => true, _ => false } }"#,
        r#"fn a(h: &str) -> bool { "127.0.0.1" != h }"#,
        r##"fn a(h: &str) -> bool { h == r#"::1"# }"##,
        r#"fn a(h: &[u8]) -> bool { h == b"::1" }"#,
        "fn a<'a>(h: &'a str) -> bool { let _q = '\"'; h == \"::1\" }",
        "#[cfg(not(test))]\nfn a(h: &str) -> bool { h == \"::1\" }",
        "/* a comment */ fn a(h: &str) -> bool { h == \"localhost\" } // and one after",
    ];
    for copy in copies {
        let seen = sightings(copy, false, None);
        assert_eq!(
            seen.iter().filter(|s| s.2 == Seen::Copy).count(),
            1,
            "premise: one copy in {copy:?}, saw {seen:?}"
        );
    }
    let two = r#"fn a(h: &str) -> bool { ["127.0.0.1", "::1"].contains(&h) }"#;
    assert_eq!(sightings(two, false, None).len(), 2, "premise: an array");

    let quiet = [
        "// host == \"::1\"\nfn a() {}",
        "/// \"localhost\"\nfn a() {}",
        "/* \"127.0.0.1\" /* nested \"::1\" */ \"localhost\" */\nfn a() {}",
        "fn a() -> &'static str { \"[::1]:9900\" }",
        "fn a() -> &'static str { \"say \\\"::1\\\" twice\" }",
        "fn a() -> &'static str { \"127.0.0.1:8765\" }",
        "fn a() -> String { \"a\\\n   ::1\".into() }",
    ];
    for text in quiet {
        assert!(
            sightings(text, false, None).is_empty(),
            "premise: no loopback literal in {text:?}"
        );
    }
    let tests_only = [
        "#[cfg(test)]\nmod t {\n    fn a(h: &str) -> bool { h == \"::1\" }\n}",
        "#[cfg(test)]\nfn a(h: &str) -> bool { h == \"localhost\" }",
        "#[cfg(any(test, feature = \"x\"))]\nconst L: &str = \"::1\";",
        "fn a() { let _c = '{'; }\n#[cfg(test)]\nmod t {\n    const L: &str = \"::1\";\n}",
        "#![cfg(test)]\nfn a(h: &str) -> bool { h == \"127.0.0.1\" }",
    ];
    for text in tests_only {
        let seen = sightings(text, false, None);
        assert!(
            !seen.is_empty() && seen.iter().all(|s| s.2 == Seen::Test),
            "premise: test code in {text:?}, saw {seen:?}"
        );
    }
    // A region ends with its item: production code after a test item is seen.
    let after = "#[cfg(test)]\nmod t {\n    const L: &str = \"::1\";\n}\nfn a(h: &str) -> bool { h == \"::1\" }";
    let seen = sightings(after, false, None);
    assert_eq!(
        seen.iter().map(|s| &s.2).collect::<Vec<_>>(),
        [&Seen::Test, &Seen::Copy],
        "premise: the test region closes with its item"
    );
    // The allowed body counts its own literals and nothing outside it.
    let allowed = "pub fn host_is_loopback(host: &str) -> bool {\n    host == \"127.0.0.1\" || host == \"localhost\" || host == \"::1\"\n}\nconst X: &str = \"::1\";";
    let seen = sightings(allowed, false, Some("fn host_is_loopback("));
    assert_eq!(
        seen.iter().map(|s| &s.2).collect::<Vec<_>>(),
        [&Seen::Allowed, &Seen::Allowed, &Seen::Allowed, &Seen::Copy],
        "premise: the allowed body ends at its brace"
    );
    // The module reader: which `mod` lines bring in a test-only file.
    let (_, mods) = test_regions(
        &lex("/// doc\n#[cfg(test)]\nmod t;\nmod u;\npub(crate) mod v;\n#[cfg(not(test))]\nmod w;\nmod x {}\n").code,
    );
    assert_eq!(
        mods,
        [
            ("t".to_string(), true),
            ("u".to_string(), false),
            ("v".to_string(), false),
            ("w".to_string(), false),
        ],
        "premise: the module reader"
    );
}

/// The gate itself, over the workspace.
#[test]
fn the_loopback_literals_live_in_one_function() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ is this crate's parent");
    let (files, test) = classify(crates);
    assert!(
        files.len() > 60,
        "the walk found {} files — the scan, not the tree, is broken",
        files.len()
    );
    // Premise: the module tree, not a file name, decides what is test code.
    for (rel, want) in [
        ("undercroft-config/src/loopback_tests.rs", true),
        ("undercroft-store/src/anchor_tests.rs", true),
        ("undercroft-cli/src/open_race_surface_tests.rs", true),
        ("undercroft-cli/tests/cli.rs", true),
        ("undercroft-embed-onnx/src/fixture.rs", true),
        ("undercroft-cli/src/parity.rs", false),
        ("undercroft-cli/src/http.rs", false),
        ("undercroft-config/src/lib.rs", false),
    ] {
        assert_eq!(
            test.get(&crates.join(rel)).copied(),
            Some(want),
            "premise: the module tree classifies {rel}"
        );
    }

    // (file, anchor of the body that may hold literals, exact counts)
    let allowed: [(&str, &str, [usize; 3]); 4] = [
        (
            "undercroft-config/src/lib.rs",
            "fn host_is_loopback(",
            [1, 1, 1],
        ),
        ("undercroft-net/src/lib.rs", "fn is_loopback(", [0, 1, 0]),
        (
            "undercroft-index/src/lib.rs",
            "fn dsn_is_loopback(",
            [0, 1, 0],
        ),
        ("undercroft-cli/src/main.rs", "ServeHttp {", [1, 0, 0]),
    ];
    let mut offenders = Vec::new();
    let mut reached = [false; 4];
    let mut excluded = 0;
    let mut orphans = 0;
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a readable source");
        let file_is_test = match test.get(file) {
            Some(&t) => t,
            None => {
                orphans += 1;
                false
            }
        };
        let site = allowed
            .iter()
            .position(|(rel, _, _)| *file == crates.join(rel));
        let mut inside = [0usize; 3];
        for (at, which, seen) in sightings(&text, file_is_test, site.map(|k| allowed[k].1)) {
            match seen {
                Seen::Test => excluded += 1,
                Seen::Allowed => inside[which] += 1,
                Seen::Copy => {
                    let line = text[..at].matches('\n').count() + 1;
                    let shown = text.lines().nth(line - 1).unwrap_or("").trim();
                    offenders.push(format!("{}:{line}: {shown}", file.display()));
                }
            }
        }
        if let Some(k) = site {
            assert_eq!(
                inside, allowed[k].2,
                "{} must hold exactly these counts of [127.0.0.1, localhost, ::1] in \
                 `{}`: one more widens the exemption, one fewer moved a literal elsewhere",
                allowed[k].0, allowed[k].1
            );
            reached[k] = true;
        }
    }
    assert!(
        reached.iter().all(|&r| r),
        "the walk must reach every allowed site: {reached:?}"
    );
    assert!(
        excluded > 0,
        "premise: test code holding the literals was found and excluded"
    );
    assert!(
        offenders.is_empty(),
        "a loopback literal outside the one predicate ({orphans} file(s) no module tree \
         reaches were scanned as production) — call `undercroft_config::host_is_loopback` \
         (a host) or `addr_is_loopback` (an address) instead (ROADMAP O177):\n{}",
        offenders.join("\n")
    );
}
