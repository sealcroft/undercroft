"""Trace check for the former project name — seven file-content classes.

**The seventh is a compressed PDF stream** (ROADMAP O26), and it is the class
`CLAUDE.md`'s own rule was written about: 17 historical PDF blobs passed a
clean `grep` while carrying the name inside Flate-compressed content streams.
The rule says such a claim must *decompress rather than grep*; until this
landed, the scanner implementing the rule did not decompress. Worse than the
honest skip the entry described — `SKIP_BIN` names no `.pdf`, so all eleven
tracked PDFs were opened in TEXT mode, scanned for needles that cannot survive
DEFLATE, and COUNTED in `files scanned`. Reported coverage it did not have.

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
import os
import re
import subprocess
import sys
import tempfile
import zlib

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

IS_PDF = re.compile(r"(?i)\.pdf$")
# A stream payload runs from the `stream` keyword — which the spec requires be
# followed by CRLF or LF, never a bare CR — to the next `endstream`.
STREAM = re.compile(rb"stream\r?\n(.*?)endstream", re.S)


def pdf_streams(data):
    """Every `stream`/`endstream` payload of a PDF, inflated where Flated.

    **This is the class `CLAUDE.md` was written about** (ROADMAP O26): 17
    historical PDF blobs passed a clean `grep` while carrying the former name
    inside Flate-compressed content streams — invisible to a byte scan, plain
    to anyone who opened the file. The rule that instance produced is that
    such a claim must *decompress rather than grep*.

    Returns `(texts, unexamined)`. A stream that will not inflate is COUNTED,
    never dropped: an uncounted skip is this scanner's own defect one level
    down, where "0 hits" silently means "0 hits in what I managed to read".

    No PDF parser. A needle scan does not need one, and a partial parser that
    misreads an object would fail exactly the way this gate exists to prevent.

    **Inflation is TRIED on every payload, and the dictionary is consulted
    only to classify a failure.** The first version asked a 512-byte lookback
    window whether `/FlateDecode` was declared and inflated only then — so a
    stream whose dictionary ran longer than the window was scanned raw and
    COUNTED AS EXAMINED, which is this unit's own defect at smaller scale
    behind a magic number. Trying first removes the window from the
    correctness path entirely: whatever inflates is read, and the declaration
    decides only whether a refusal is a compressed stream this could not
    open (`unexamined`) or an ordinary uncompressed one (its bytes are
    already themselves).
    """
    texts, unexamined = [], 0
    for m in STREAM.finditer(data):
        payload = m.group(1)
        got = None
        # zlib-wrapped first, then raw deflate. `decompressobj` rather than
        # `decompress` because a payload whose `endstream` boundary lands a
        # byte early must yield what it can instead of raising.
        for wbits in (15, -15):
            try:
                out = zlib.decompressobj(wbits).decompress(payload)
            except zlib.error:
                continue
            if out:
                got = out
                break
        if got is not None:
            texts.append((m.start(), got))
            continue
        window = data[max(0, m.start() - 512) : m.start()]
        if b"FlateDecode" in window:
            unexamined += 1
        else:
            texts.append((m.start(), payload))
    return texts, unexamined


def synth_pdf(body):
    """A minimal PDF whose one stream is Flate-compressed — the probe's input.

    Built in memory and run through `pdf_streams` itself, so what is proved is
    that THIS extractor reaches a compressed stream, not that zlib works.
    """
    z = zlib.compress(body)
    return (
        b"%PDF-1.7\n1 0 obj\n<< /Length "
        + str(len(z)).encode()
        + b" /Filter /FlateDecode >>\nstream\n"
        + z
        + b"\nendstream\nendobj\n%%EOF\n"
    )


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

    # **The PDF arm** (ROADMAP O26), and it probes the EXTRACTOR rather than
    # the needles: the plant is placed where only inflation can reach it, so a
    # stream walk that silently reads nothing fails here instead of printing a
    # reassuring zero. This is the arm whose absence made the defect invisible
    # — `SKIP_BIN` did not name `.pdf`, so every tracked PDF was opened in TEXT
    # mode, decoded lossily, scanned for needles that cannot survive DEFLATE,
    # and COUNTED in `files scanned`. Reported coverage the scan did not have,
    # which is worse than the honest skip the ROADMAP entry described.
    #
    # It runs through `scan()` on a real file rather than through
    # `pdf_streams` directly, and that choice is the whole value of the arm.
    # What can silently fail is the ROUTING: an `IS_PDF` that does not match
    # sends every PDF down the text path and `pdf_streams` is never called,
    # while a probe of the extractor alone passes cleanly. Measuring the
    # component instead of the path is the mistake this tree keeps paying for.
    if "latin name" not in dict(CHECKS):
        bad.append("the PDF arm cannot run: no check is labelled 'latin name'")
        return bad
    planted = synth_pdf(("BT (" + _LATIN + ") Tj ET").encode())
    if _LATIN.encode() in planted:
        # Then a hit would prove only that the TEXT scan works, which it
        # already did. The plant has to be unreachable without inflating.
        bad.append("the planted needle survived compression as a literal — the probe proves nothing")
        return bad
    with tempfile.TemporaryDirectory() as d:
        hit_path = os.path.join(d, "planted.pdf")
        with open(hit_path, "wb") as fh:
            fh.write(planted)
        hits, st = scan([hit_path])
        if st["pdfs"] != 1 or st["streams"] != 1:
            bad.append(
                f"a .pdf was not routed to the stream walk "
                f"(pdfs={st['pdfs']}, streams={st['streams']}, unexamined={st['unexamined']}) "
                f"— PDF content streams are unexamined"
            )
        if not any(label == "latin name" for label, _, _ in hits):
            bad.append(
                "a needle planted inside a Flate-compressed PDF stream was NOT found — "
                "PDF content streams are unexamined"
            )
        clean_path = os.path.join(d, "control.pdf")
        with open(clean_path, "wb") as fh:
            fh.write(synth_pdf(clean.encode()))
        for label, _, _ in scan([clean_path])[0]:
            bad.append(f"{label}: fires on a clean PDF stream")
    return bad


def scan(paths):
    """Returns `(failures, stats)` — the hits, and what the walk actually read.

    `stats` exists because the count this printed was `files scanned`, and a
    PDF was among them while every compressed byte in it went unread. A number
    that counts files rather than what was examined inside them is the same
    reassuring zero one level up.
    """
    failures = []
    stats = {"files": 0, "skipped": 0, "unread": 0, "pdfs": 0, "streams": 0, "unexamined": 0}
    stats["blind"] = []
    for f in paths:
        if SKIP_BIN.search(f) or any(f.startswith(a) or a in f for a in ALLOW):
            stats["skipped"] += 1
            continue
        try:
            # BYTES, then a lossy decode — the same text the previous version
            # scanned, so the coverage this had over a PDF's UNcompressed
            # regions (metadata, object dictionaries, unfiltered streams) is
            # kept rather than traded for the compressed ones.
            raw = io.open(f, "rb").read()
        except Exception:
            stats["unread"] += 1
            continue
        stats["files"] += 1
        s = raw.decode("utf8", errors="ignore")
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

        # Class seven: inside a compressed PDF stream (ROADMAP O26). The text
        # scan above cannot reach one by construction — DEFLATE is exactly the
        # transform that destroys a literal — so the needles run again over
        # what inflation returns. The hit keeps its ORDINARY label so it groups
        # with its class in the report; the path already says it is a PDF, and
        # the line is where the stream's object sits in the file.
        if not IS_PDF.search(f):
            continue
        stats["pdfs"] += 1
        texts, unexamined = pdf_streams(raw)
        stats["streams"] += len(texts)
        stats["unexamined"] += unexamined
        if b"FlateDecode" in raw and not texts:
            # The file plainly HAS compressed streams and the walk read none
            # of them. That is a broken extractor, not a clean file, and the
            # two must never print the same thing.
            stats["blind"].append(f)
        for off, payload in texts:
            body = payload.decode("utf8", errors="ignore")
            line = raw[:off].count(b"\n") + 1
            for label, pat in CHECKS:
                if pat.search(body):
                    failures.append((label, f, line))
    return failures, stats


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
    failures, stats = scan(paths)

    # **Report what was READ, not what was listed.** This line counted
    # `len(paths)` — every path handed in, skipped ones included — and called
    # it "files scanned". Same shape as the PDF defect one level up: a number
    # that describes the input rather than the work.
    print(
        f"  files scanned: {stats['files']}  "
        f"(skipped {stats['skipped']}, unreadable {stats['unread']}; "
        f"patterns probed: {len(CHECKS)} + certificate)"
    )
    print(
        f"  pdf streams:   {stats['streams']} examined, {stats['unexamined']} "
        f"unexamined, across {stats['pdfs']} pdf(s)"
    )
    if stats["blind"]:
        # Not a hit and not a clean file — an extractor that did not run. It
        # exits the same way a hit does, with a DIFFERENT first line, because
        # the caller distinguishes the two on `PREMISE FAILED`.
        print("PREMISE FAILED — a pdf declares FlateDecode and no stream of it was read:")
        for f in stats["blind"]:
            print(f"    {f}")
        return 1
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
