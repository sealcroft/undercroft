"""Gate for the platform-views diagram set. Read-only, stdlib only, python3.

Run by the `arch-check` compose service, which mounts `architecture/`
READ-ONLY — so this script must never write. It is the verify half of a set
that has no build step: unlike `diagrams/`, nothing derives these files, so
the only thing that can keep them honest is a checker.

WHAT IT CHECKS, and why each one is here rather than assumed:

  inventory   every diagram is linked from index.html and every link resolves,
              counted in BOTH directions. A diagram nobody links is invisible;
              a link to a deleted file is a broken page.
  contract    role="img", aria-labelledby, <title> before <defs>, and slug-
              prefixed ids. Bare id="title" would collide if two diagrams were
              ever inlined on one page, and the second would be announced with
              the first one's name.
  offline     NO external request, without exception. These pages must render
              from a checkout with no network — and until 2026-08-30 they did
              not: an allowlist here exempted the Google Fonts hosts, all
              thirteen pages carried that stylesheet, and they were the only
              font-CDN reference in the tree. The two sentences this docstring
              used to carry contradicted each other, which is how it survived
              review (ROADMAP O78). The fonts are system stacks now, matching
              the GOVERNED architecture/index.html beside them; the allowlist
              is deleted, so this arm is the gate rather than a formality.
  encoding    no CRLF. `.gitattributes` declares LF and the repo has been
              broken by text-mode edits on Windows before.
  budget      <=9 node boxes and <=2 accent (teal) nodes per diagram. The
              accent is editorial; on five nodes it stops being a signal.
  geometry    no diagonal connector; no connector passing behind a box that is
              not its endpoint; no label mask covered by a node painted later
              (the node fill clips the text and it renders as a fragment).

WHY THERE IS A PREMISE PROBE: a checker that examines nothing prints exactly
what a clean tree prints. Before any result is believed, the geometry checks
are run against a known-BAD fixture and must fail on it. If they do not, this
script exits non-zero without reporting on the real files.

CALIBRATION NOTE, learned the expensive way: `rx` is the discriminator between
a NODE and a ZONE. Zones are rx=8 containers painted BEFORE arrows precisely
so connectors may cross them; nodes are rx=6. A first version of this checker
treated every large stroked rect as a node and reported 96 breaches across a
set whose exemplar had already been verified by eye. Any check that flags
01-platform-overview.html is wrong about the check, not about the diagram.
"""
import glob
import os
import re
import sys

NUM = r"-?\d+(?:\.\d+)?"
PAPER = ("#04080a", "#071014")
ACCENT = "#35e0c2"

HERE = os.path.dirname(os.path.abspath(__file__))


# ----------------------------------------------------------------- parsing
def _attrs(frag):
    return dict(re.findall(r'([\w:-]+)="([^"]*)"', frag))


def rects(svg):
    out = []
    for m in re.finditer(r"<rect\b([^>]*?)/?>", svg):
        g = _attrs(m.group(1))
        if "x" not in g or "width" not in g or "height" not in g:
            continue
        try:
            box = (float(g["x"]), float(g.get("y", 0)),
                   float(g["width"]), float(g["height"]))
        except ValueError:
            continue
        out.append((m.start(), box, g))
    return out


def nodes_of(svg):
    """Styled rx=6 boxes of node size. NOT zones (rx=8), NOT legend swatches."""
    return [(o, b, g) for o, b, g in rects(svg)
            if g.get("rx") == "6" and g.get("stroke", "none") != "none"
            and b[2] >= 80 and b[3] >= 40]


def masks_of(svg):
    """Opaque label masks: unstroked, paper-filled, label-sized."""
    return [(o, b, g) for o, b, g in rects(svg)
            if g.get("stroke", "none") == "none" or "stroke" not in g
            if g.get("fill", "").lower() in PAPER and b[3] <= 16 and b[2] <= 160]


def segments(svg):
    """Axis-aligned connector segments, plus any diagonal <line> found."""
    segs, diagonals = [], []
    for m in re.finditer(r"<line\b([^>]*?)/?>", svg):
        g = _attrs(m.group(1))
        if "marker-end" not in g:
            continue
        try:
            x1, y1 = float(g["x1"]), float(g["y1"])
            x2, y2 = float(g["x2"]), float(g["y2"])
        except (KeyError, ValueError):
            continue
        if x1 != x2 and y1 != y2:
            diagonals.append((x1, y1, x2, y2))
        segs.append((x1, y1, x2, y2))
    for m in re.finditer(r'<path\b([^>]*?)/?>', svg):
        frag = m.group(1)
        if "marker-end" not in frag:
            continue
        g = _attrs(frag)
        d = g.get("d", "")
        cx = cy = None
        for tok in re.finditer(r"([MHVQ])\s*((?:%s[\s,]*)+)" % NUM, d):
            cmd = tok.group(1)
            nums = [float(v) for v in re.findall(NUM, tok.group(2))]
            if cmd == "M" and len(nums) >= 2:
                cx, cy = nums[0], nums[1]
            elif cmd == "H" and cx is not None:
                segs.append((cx, cy, nums[-1], cy)); cx = nums[-1]
            elif cmd == "V" and cy is not None:
                segs.append((cx, cy, cx, nums[-1])); cy = nums[-1]
            elif cmd == "Q" and len(nums) >= 4:
                cx, cy = nums[-2], nums[-1]
    return segs, diagonals


def _hit(ax, ay, aw, ah, bx, by, bw, bh, pad=0.5):
    return (ax < bx + bw - pad and ax + aw > bx + pad
            and ay < by + bh - pad and ay + ah > by + pad)


# ------------------------------------------------------------------ checks
def geometry(svg):
    bad = []
    ns = nodes_of(svg)
    segs, diagonals = segments(svg)
    for d in diagonals:
        bad.append("diagonal connector %s" % (d,))
    for mo, (mx, my, mw, mh), _ in masks_of(svg):
        for no, (nx, ny, nw, nh), _ in ns:
            if no > mo and _hit(mx, my, mw, mh, nx, ny, nw, nh):
                bad.append("label mask at (%g,%g) is painted over by a later node at (%g,%g)"
                           % (mx, my, nx, ny))
                break
    for x1, y1, x2, y2 in segs:
        lox, hix = min(x1, x2), max(x1, x2)
        loy, hiy = min(y1, y2), max(y1, y2)
        for _, (nx, ny, nw, nh), _ in ns:
            if lox < nx + nw - 2 and hix > nx + 2 and loy < ny + nh - 2 and hiy > ny + 2:
                bad.append("connector (%g,%g)-(%g,%g) passes behind node at (%g,%g)"
                           % (x1, y1, x2, y2, nx, ny))
                break
    return bad


def inspect(path):
    raw = open(path, "rb").read()
    s = raw.decode("utf-8")
    svg = s[s.find("<svg"):s.find("</svg>")]
    bad = []
    if b"\r" in raw:
        bad.append("CRLF line endings (.gitattributes declares LF)")
    for url in re.findall(r'(?:src|href)="(https?://[^"]+)"', s):
        bad.append("external request: %s" % url)
    if "JetBrains" in s:
        bad.append("JetBrains Mono is banned as a blanket dev font")
    if 'role="img"' not in svg or "aria-labelledby" not in svg:
        bad.append("svg is missing role=img / aria-labelledby")
    if re.search(r'id="(?:title|desc)"', svg):
        bad.append("bare id=title/desc — must be slug-prefixed")
    ti, di = svg.find("<title"), svg.find("<defs")
    if ti < 0:
        bad.append("no <title>")
    elif 0 <= di < ti:
        bad.append("<title> must be the first child of <svg>, before <defs>")
    desc = re.search(r"<desc[^>]*>(.*?)</desc>", svg, re.S)
    if not desc or len(desc.group(1).strip()) < 40:
        bad.append("<desc> missing or too short to describe the diagram")
    ns = nodes_of(svg)
    if len(ns) > 9:
        bad.append("%d node boxes — budget is 9" % len(ns))
    accent = [1 for _, b, g in ns if g.get("stroke", "").lower() == ACCENT]
    if len(accent) > 2:
        bad.append("%d accent nodes — the editorial budget is 2" % len(accent))
    bad += geometry(svg)
    slug = re.search(r'id="([a-z0-9-]+)-title"', svg)
    return (slug.group(1) if slug else None), len(ns), len(accent), bad


# ------------------------------------------------------- premise probe
BAD_FIXTURE = (
    '<svg role="img" aria-labelledby="p-title p-desc">'
    '<title id="p-title">p</title><desc id="p-desc">'
    'a deliberately broken fixture used only to prove this checker can see a fault</desc>'
    '<defs></defs>'
    '<rect x="0" y="0" width="40" height="12" fill="#04080a"/>'
    '<line x1="0" y1="6" x2="300" y2="6" marker-end="url(#a)"/>'
    '<line x1="0" y1="0" x2="90" y2="70" marker-end="url(#a)"/>'
    '<rect x="10" y="0" width="100" height="60" rx="6" fill="#071014" stroke="#d9f0ea"/>'
    '</svg>')


def probe():
    faults = geometry(BAD_FIXTURE)
    need = ("diagonal", "painted over", "passes behind")
    missing = [n for n in need if not any(n in f for f in faults)]
    return missing


def main():
    missing = probe()
    if missing:
        print("PREMISE FAILURE: the checker cannot see %s on a known-bad fixture."
              % ", ".join(missing))
        print("Its zero-results would be meaningless. Fix the checker.")
        return 2
    print("premise probe: all three geometry faults detected on a known-bad fixture")

    files = sorted(glob.glob(os.path.join(HERE, "[0-9][0-9]-*.html")))
    if not files:
        print("PREMISE FAILURE: no diagrams found — this gate examined nothing.")
        return 2

    index_path = os.path.join(HERE, "index.html")
    if not os.path.exists(index_path):
        print("FAIL index.html is missing — the set has no entry point")
        return 1
    index = open(index_path, encoding="utf-8").read()
    linked = set(re.findall(r'href="([0-9][0-9]-[a-z-]+\.html)"', index))
    present = {os.path.basename(f) for f in files}

    failures = 0
    print()
    print("%-34s %6s %7s  %s" % ("diagram", "nodes", "accent", "verdict"))
    slugs = {}
    for f in files:
        slug, n, a, bad = inspect(f)
        name = os.path.basename(f)
        if slug:
            slugs.setdefault(slug, []).append(name)
        print("%-34s %6d %7d  %s" % (name, n, a, "ok" if not bad else "FAIL"))
        for b in bad:
            print("      - %s" % b)
        failures += len(bad)

    print()
    dupes = {k: v for k, v in slugs.items() if len(v) > 1}
    if dupes:
        print("FAIL duplicate slug ids: %s" % dupes)
        failures += 1
    # inventory, both directions
    unlinked = sorted(present - linked)
    dangling = sorted(linked - present)
    if unlinked:
        print("FAIL not linked from index.html: %s" % ", ".join(unlinked))
        failures += 1
    if dangling:
        print("FAIL index.html links a file that does not exist: %s" % ", ".join(dangling))
        failures += 1
    if not unlinked and not dangling:
        print("inventory: %d diagrams, each linked from index.html, no dangling links"
              % len(files))

    print()
    if failures:
        print("platform-views: %d problem(s)" % failures)
        return 1
    print("platform-views: %d diagrams, all clean" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
