#!/usr/bin/env sh
# Rebuild architecture/pdf/*.pdf AND the inlined copies in index.html from
# architecture/diagrams/*.svg. `diagrams/` is the single source; everything
# else here is derived, so edit an SVG and re-run this.
#
# The SVG sources are theme-aware: every colour is `var(--d-x, #light)` so the
# inlined copies in index.html follow the page theme. librsvg does NOT
# implement CSS custom properties — it renders unresolved var() as black — so
# the PDFs are produced from a flattened copy where each var() collapses to its
# light fallback. Print output is deliberately always light.
#
# **The inline step strips each diagram's own dark media query**, and that is
# not cosmetic. A standalone SVG needs it to be readable when opened directly,
# but inlined it sets `--d-*` on the `svg` element, which beats the `:root`
# values the page sets — so the diagram would follow the SYSTEM theme while the
# rest of the page follows the manual toggle, and the two would disagree.
# Inlining by hand reintroduces it every time; that is why this is a script.
#
# ── TWO MODES, and the second is ROADMAP M14 ────────────────────────────────
#
#   sh build.sh           REBUILD: regenerate the PDFs and rewrite index.html.
#   sh build.sh --check   VERIFY: derive everything in memory and fail if what
#                         is on disk differs. Writes nothing at all.
#
# `--check` exists because for its whole life nothing invoked this script —
# no battery suite, no CI job, no compose service. Every mention of it in the
# tree was prose telling a human to remember. So a stale inlined diagram, a
# reintroduced dark media query, or a hand-added <h3> with no id could ship
# under a fully green battery, which is the M7/M10 shape this project has now
# paid for three times: a check that is correct and never executed.
#
# **`--check` needs python3 and nothing else** — it neither renders nor
# flattens, because those need librsvg plus the Noto families and because PDF
# bytes are not a stable comparison target. What it verifies of the PDFs is
# COVERAGE (every diagram has one, and no orphan pdf survives a deleted
# diagram), which is the part that rots silently. Byte-level PDF verification
# is deliberately out of scope and is stated here rather than implied.
#
# Run from the repo root:
#   docker run --rm -v "$PWD/architecture:/a" -w /a debian:bookworm-slim sh build.sh
# or, for the verify half, `docker compose run --rm arch-check`.
set -eu

MODE=build
for a in "$@"; do
  case "$a" in
    --check) MODE=check ;;
    # Exit 1, never 2 — exit 2 is this project's integrity verdict on every
    # command, and a mistyped flag must not borrow it.
    *) echo "unknown option: $a" >&2; exit 1 ;;
  esac
done
export ARCH_MODE="$MODE"

if [ "$MODE" = build ]; then
  # Noto core + CJK are not decoration: the language diagrams carry Thai, Han,
  # Kana and Devanagari, and without those families librsvg renders every one
  # of them as a tofu box. The browser has the fonts and the PDF does not, so
  # this is a defect only the PDF shows — check a rendered page, never just
  # the SVG.
  command -v rsvg-convert >/dev/null 2>&1 || {
    apt-get -qq update >/dev/null 2>&1
    apt-get -qq install -y librsvg2-bin python3 fonts-noto-core fonts-noto-cjk >/dev/null 2>&1
  }

  mkdir -p pdf .flat

  python3 - <<'PY'
import glob, io, os, re

os.makedirs('.flat', exist_ok=True)
srcs = sorted(glob.glob('diagrams/*.svg'))
if not srcs:
    raise SystemExit('premise: no diagrams/*.svg found — nothing was flattened')
for p in srcs:
    s = io.open(p, encoding='utf-8').read()
    # Innermost-first, repeatedly: var(--name, #rrggbb) -> #rrggbb.
    # Handles the nested var(--d-on, var(--d-card, #ffffff)) case.
    while 'var(' in s:
        new = re.sub(r'var\(\s*--[A-Za-z0-9-]+\s*,\s*(#[0-9a-fA-F]{6})\s*\)', r'\1', s)
        if new == s:
            break
        s = new
    # The dark media query is meaningless for print and only risks confusing
    # a renderer with partial CSS support.
    s = re.sub(r'\s*@media \(prefers-color-scheme: dark\) \{.*?\n  \}\n', '\n', s, flags=re.S)
    leftover = re.findall(r'var\(', s)
    if leftover:
        raise SystemExit('unflattened var() remains in %s' % p)
    io.open('.flat/' + os.path.basename(p), 'w', encoding='utf-8', newline='\n').write(s)
    print('flattened', p)
PY

  for f in .flat/*.svg; do
    n=$(basename "$f" .svg)
    rsvg-convert -f pdf -o "pdf/$n.pdf" "$f"
    echo "pdf/$n.pdf"
  done

  rm -rf .flat
fi

# ── PDF coverage, both modes ────────────────────────────────────────────────
# Set equality in BOTH directions. A diagram with no PDF is the obvious half;
# an orphan PDF left behind by a deleted diagram is the half that reads as
# coverage while describing something that no longer exists.
python3 - <<'PY'
import glob, os

diagrams = {os.path.basename(p)[:-4] for p in glob.glob('diagrams/*.svg')}
pdfs = {os.path.basename(p)[:-4] for p in glob.glob('pdf/*.pdf')}
# PREMISE. Empty sets compare equal, so a wrong working directory or a moved
# folder would report perfect coverage having examined nothing.
if not diagrams:
    raise SystemExit('premise: no diagrams/*.svg found — this examined nothing')
missing = sorted(diagrams - pdfs)
orphan = sorted(pdfs - diagrams)
if missing or orphan:
    raise SystemExit(
        'pdf/ does not match diagrams/: missing %s, orphaned %s' % (missing, orphan))
print('pdf: %d diagram(s), %d pdf(s), sets equal' % (len(diagrams), len(pdfs)))
PY

# ── Heading ids and the sidebar ─────────────────────────────────────────────
# The rail is generated, not written by hand. Adding an <h3> by hand gives it
# no id and no rail entry, and nothing complains — the page just quietly grows
# a heading nobody can link to or find. That already happened once.
#
# **The old gate here could not disagree with itself, and that is M14's other
# half.** It stamped a fresh id onto every <h3>, collected those same ids into
# `kids`, built the rail from `kids`, substituted it into the document, and
# THEN re-read the ids and the rail refs out of that same rewritten document
# and compared them. Both sides came from one list built in one pass, so the
# comparison could not fail — its protection came entirely from the
# regeneration silently fixing the problem, never from the check. It also
# WROTE index.html before the comparison, so a firing gate left the file
# already mutated, and it had no premise probe: with zero sections both sets
# are empty and it passed having examined nothing.
#
# Now there is one derivation and two things done with it: compare it against
# what is on disk (`--check`), or write it (rebuild). Comparing DERIVED
# against ON-DISK is a comparison that can actually fail.
python3 - <<'PY'
import io, os, re, unicodedata

mode = os.environ.get('ARCH_MODE', 'build')
path = 'index.html'
doc = io.open(path, encoding='utf-8').read()
original = doc

def slug(text):
    text = re.sub(r'<[^>]+>', '', text)
    text = unicodedata.normalize('NFKD', text)
    text = re.sub(r'[^a-zA-Z0-9]+', '-', text).strip('-').lower()
    return re.sub(r'-+', '-', text)[:44]

tree = []
drifted = []

def visit(m):
    sid, block = m.group(1), m.group(0)
    title = re.search(r'<h2 id="h_%s">(.*?)</h2>' % sid, block, re.S).group(1)
    kids = []

    def stamp(hm):
        had, body = hm.group(1), hm.group(2)
        hid = '%s-%s' % (sid, slug(body))
        kids.append((hid, re.sub(r'<[^>]+>', '', body)))
        # Recorded, not silently corrected. In rebuild mode the write fixes it
        # anyway; the POINT is that `--check` can name it.
        if had != hid:
            drifted.append((sid, re.sub(r'<[^>]+>', '', body)[:60], had, hid))
        return '<h3 id="%s">%s</h3>' % (hid, body)

    block = re.sub(r'<h3(?: id="([^"]*)")?>(.*?)</h3>', stamp, block, flags=re.S)
    tree.append((sid, re.sub(r'<[^>]+>', '', title), kids))
    return block

doc = re.sub(r'<section class="doc-section" id="([a-z-]+)".*?</section>', visit, doc, flags=re.S)

# PREMISE, both directions. A boundary rule that matched no section, or
# sections with no headings, makes every comparison below vacuous — and a
# vacuous comparison reports exactly what a correct page reports.
if not tree:
    raise SystemExit('premise: no <section class="doc-section"> matched — this examined nothing')
total_h3 = sum(len(k) for _, _, k in tree)
if total_h3 == 0:
    raise SystemExit('premise: %d sections matched but they hold no <h3> at all' % len(tree))

nav = ['<nav class="sb-nav" aria-label="Sections"><ol>']
for sid, title, kids in tree:
    nav.append('  <li class="sb-sec" data-sec="%s">' % sid)
    nav.append('    <a class="sb-link" href="#%s">%s</a>' % (sid, title))
    if kids:
        nav.append('    <ul class="sb-sub">')
        for hid, ktitle in kids:
            nav.append('      <li><a class="sb-sublink" href="#%s">%s</a></li>' % (hid, ktitle))
        nav.append('    </ul>')
    nav.append('  </li>')
nav.append('</ol></nav>')

doc, nsub = re.subn(r'<nav class="sb-nav".*?</nav>', '\n'.join(nav), doc, count=1, flags=re.S)
# The substitution silently doing nothing is a real failure mode: `count=1`
# reports success whether it replaced one or zero.
if nsub != 1:
    raise SystemExit('the <nav class="sb-nav"> block was not found — nothing was substituted')

if mode == 'check':
    if drifted:
        for sid, text, had, want in drifted:
            print('  heading id drift in section %s: %r has id %r, derives to %r'
                  % (sid, text, had, want))
    if doc != original:
        raise SystemExit(
            'index.html is not what diagrams/ and its own headings derive to '
            '(rail or heading ids are stale) — run `sh build.sh` and commit the result')
    print('rail: %d sections, %d headings — on disk matches what they derive to'
          % (len(tree), total_h3))
else:
    for sid, text, had, want in drifted:
        print('  regenerated heading id in %s: %r %r -> %r' % (sid, text, had, want))
    io.open(path, 'w', encoding='utf-8', newline='\n').write(doc)
    print('rail: %d sections, %d headings' % (len(tree), total_h3))
PY

# ── The inlined copies ──────────────────────────────────────────────────────
# Same shape: derive, then compare or write. The old version wrote first and
# checked afterwards.
python3 - <<'PY'
import glob, io, os, re

mode = os.environ.get('ARCH_MODE', 'build')
idx_path = 'index.html'
idx = io.open(idx_path, encoding='utf-8').read()
original = idx
inlined = 0
skipped = []

srcs = sorted(glob.glob('diagrams/*.svg'))
if not srcs:
    raise SystemExit('premise: no diagrams/*.svg found — this examined nothing')

for p in srcs:
    name = os.path.basename(p)[:-4]
    slug = name.replace('-', '')
    svg = io.open(p, encoding='utf-8').read().strip()
    # Unique ids: several diagrams share `t`/`d` and duplicate ids in one
    # document make aria-labelledby resolve to whichever came first.
    svg = svg.replace('aria-labelledby="t d"', 'aria-labelledby="t_%s d_%s"' % (slug, slug))
    svg = svg.replace('<title id="t">', '<title id="t_%s">' % slug)
    svg = svg.replace('<desc id="d">', '<desc id="d_%s">' % slug)
    # See the header: inlined, this block would outrank the page's own theme.
    svg = re.sub(r'\s*@media \(prefers-color-scheme: dark\) \{.*?\n  \}\n', '\n', svg, flags=re.S)
    pat = re.compile(r'<svg [^>]*aria-labelledby="t_%s d_%s".*?</svg>' % (slug, slug), re.S)
    n = len(pat.findall(idx))
    if n == 0:
        skipped.append(name)
        continue
    if n != 1:
        raise SystemExit('%s is inlined %d times in index.html' % (name, n))
    idx = pat.sub(lambda _m: svg, idx, count=1)
    inlined += 1

# PREMISE. If nothing was inlined, every comparison below is between a
# document and itself.
if inlined == 0:
    raise SystemExit('premise: no diagram is inlined in index.html — this examined nothing')

# An inlined copy that kept its media query is the bug this step exists to
# prevent, so fail loudly rather than shipping a diagram that ignores the
# toggle. Checked on the DERIVED document in both modes, and on the on-disk
# one in check mode, because those are different questions: the first asks
# whether this script would produce one, the second whether the page has one.
for label, text in (('derived', idx), ('on disk', original)):
    for m in re.finditer(r'<svg .*?</svg>', text, re.S):
        if 'prefers-color-scheme' in m.group(0):
            raise SystemExit('an inlined diagram carries a dark media query (%s)' % label)

if mode == 'check':
    if idx != original:
        raise SystemExit(
            'an inlined diagram in index.html differs from its source in diagrams/ '
            '— run `sh build.sh` and commit the result')
    print('index.html: %d inlined diagram(s) match diagrams/, none carries a dark media query'
          % inlined)
else:
    io.open(idx_path, 'w', encoding='utf-8', newline='\n').write(idx)
    for name in skipped:
        print('  (not inlined, skipped) %s' % name)
    print('index.html: %d inlined, all following the page theme' % inlined)
PY
