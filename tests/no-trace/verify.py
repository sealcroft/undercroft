"""Trace check for the former project name — six file-content classes.

**Why this is TRACKED and the `.handover/` original was not** (ROADMAP O10).
The original was run by hand, from a gitignored directory a fresh clone does
not carry, invoked by no suite, no preflight and no workflow. A verifier
nobody runs is a verifier you do not have — and that is not hypothetical: the
comment written into `docker-compose.yml` to explain the derived-name defect
quoted the former name while explaining that quoting it is how it gets back
in. Nothing in the repository could have seen it and the battery was green
across it.

**A tracked scanner scans itself, so every needle is SPLIT.** The fragments
below are joined at run time; no matchable literal exists in this file. That
is the `concat!` idiom `undercroft-obs`'s gauge gate already uses, and it is
deliberately not the alternative — excluding this file by path would be the
unfalsifiable-second-direction defect round three found, where the file
holding an inventory sat inside the tree its gate scanned. `probe()` below
asserts the split needles still match, so the splitting cannot silently
disarm them.

**It runs in a container**, never on a host interpreter: this project builds
and tests in Docker, and a gate needing Python on the host is a gate that does
not run on the next machine. A preflight that SKIPS when its interpreter is
absent reports exactly what a clean tree reports.

Exit 0 = clean, 1 = a hit or a failed premise. Usage:
    python tests/no-trace/verify.py [extra_path ...]
Extra paths are scanned in addition to the tracked set — that is how the
preflight's self-test feeds it a known-positive file.
"""

import base64
import io
import re
import subprocess
import sys

# ── the needles, in fragments ───────────────────────────────────────────────
# Split so that NO fragment, and no two fragments as they appear here
# (separated by quotes and commas), forms any pattern below. The shortest
# pattern is four characters, so fragments are kept to three where the
# alphabet allows.
def _j(*parts):
    return "".join(parts)


_LATIN = _j("mne", "mos", "yne")
_ROOT = _j("mne", "mo")
_GREEK = "|".join([_j("ΜΝ", "ΗΜ"), _j("Μν", "ημ"), _j("μν", "ημ")])
_B64 = "|".join([_j("bW5l", "bW9z", "eW5l"), _j("TW5l", "bW9z", "eW5l"), _j("bmVt", "b3N5", "bW")])
_DER = _j("nem", "osy", "ne")
_MYTH = "|".join(
    [
        _j("tita", "ness"),
        _j("mother of ", "the nine"),
        _j("river ", "lethe"),
        _j("orp", "hic"),
        _j("pete", "lia"),
        _j("method of ", "loci"),
    ]
)

# `(?!nic)` keeps the ordinary English word that shares the root from firing.
CHECKS = [
    ("latin name", re.compile("(?i)" + _LATIN)),
    ("truncated root", re.compile("(?i)" + _ROOT + "(?!nic)")),
    ("greek name", re.compile(_GREEK)),
    ("base64 of name", re.compile(_B64)),
    ("mythic identity", re.compile("(?i)" + _MYTH)),
]

SKIP_BIN = re.compile(r"\.(png|ico|jpg|jpeg|woff2?)$")
# Vendored third-party code, and benchmark fixture prose in natural languages
# where these words are ordinary vocabulary rather than a trace.
ALLOW = ("website/assets/mermaid.min.js", "benchmarks/model_eval/datasets/")


def probe():
    """Every pattern fires on a synthesized positive; none fires on clean text.

    **The original had no probe** — it was probed by hand, once, in a session,
    which is a property of that session and not of the artifact. Without this,
    a needle split one character too far returns zero hits, and a zero from a
    needle that matches nothing reads exactly like a clean tree.
    """
    positives = {
        "latin name": _LATIN,
        "truncated root": _ROOT + " stem",
        "greek name": _j("ΜΝ", "ΗΜ"),
        "base64 of name": _j("bW5l", "bW9z", "eW5l"),
        "mythic identity": _j("tita", "ness"),
    }
    clean = "undercroft sealcroft vault drawer wing room mnemonic memory palace"
    bad = []
    if not CHECKS:
        return ["the pattern set is EMPTY — this scanner would report any tree clean"]
    for label, pat in CHECKS:
        if label not in positives:
            bad.append(f"{label}: no known-positive is defined, so it is unprobed")
            continue
        if not pat.search(positives[label]):
            bad.append(f"{label}: does NOT match its own known-positive — the needle is disarmed")
        if pat.search(clean):
            bad.append(f"{label}: fires on clean control text, including the word it must not")
    return bad


def scan(paths):
    failures = []
    for f in paths:
        if SKIP_BIN.search(f) or any(f.startswith(a) or a in f for a in ALLOW):
            continue
        try:
            s = io.open(f, encoding="utf8", errors="ignore").read()
        except Exception:
            continue
        for label, pat in CHECKS:
            for m in pat.finditer(s):
                failures.append((label, f, s[: m.start()].count("\n") + 1))
        # Class six: inside a certificate. A pinned test certificate carried
        # the name in base64-encoded DER while the comment above it asserted
        # the new one — invisible to every byte scan, plain to anyone who
        # decoded it.
        for m in re.finditer(r"BEGIN CERTIFICATE-----(.*?)-----END", s, re.S):
            b = re.sub(r"[^A-Za-z0-9+/=]", "", m.group(1))
            try:
                der = base64.b64decode(b + "=" * (-len(b) % 4))
            except Exception:
                continue
            if re.search(("(?i)" + _DER).encode(), der):
                failures.append(("name inside a certificate", f, s[: m.start()].count("\n") + 1))
    return failures


def main():
    bad = probe()
    if bad:
        print("PREMISE FAILED — this scanner cannot be believed:")
        for b in bad:
            print(f"    {b}")
        return 1

    # `--stdin` takes the tracked list on standard input so the container
    # needs neither `git` nor an `apt-get`. The caller is the preflight, which
    # already has git on the host; without it this image would install a
    # package manager's worth of dependencies on every run.
    args = [a for a in sys.argv[1:] if a != "--stdin"]
    if "--stdin" in sys.argv[1:]:
        tracked = sys.stdin.read().split()
    else:
        tracked = subprocess.run(
            ["git", "ls-files"], capture_output=True, text=True
        ).stdout.split()
    if len(tracked) < 100:
        print(f"PREMISE FAILED — the tracked list held {len(tracked)} files; the walk is broken")
        return 1

    paths = tracked + args
    failures = scan(paths)

    print(f"  files scanned: {len(paths)}  (patterns probed: {len(CHECKS)} + certificate)")
    by_label = {}
    for label, f, line in failures:
        by_label.setdefault(label, []).append((f, line))
    labels = [c[0] for c in CHECKS] + ["name inside a certificate"]
    for label in labels:
        hits = by_label.get(label, [])
        print(f"  {label:<26} {len(hits)}")
        for f, line in hits[:6]:
            print(f"      {f}:{line}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
