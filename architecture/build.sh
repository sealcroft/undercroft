#!/usr/bin/env sh
# Rebuild architecture/pdf/*.pdf from architecture/diagrams/*.svg.
#
# The SVG sources are theme-aware: every colour is `var(--d-x, #light)` so the
# inlined copies in index.html follow the page theme. librsvg does NOT
# implement CSS custom properties — it renders unresolved var() as black — so
# the PDFs are produced from a flattened copy where each var() collapses to its
# light fallback. Print output is deliberately always light.
#
# Run from the repo root:
#   docker run --rm -v "$PWD/architecture:/a" -w /a debian:bookworm-slim sh build.sh
set -eu

command -v rsvg-convert >/dev/null 2>&1 || {
  apt-get -qq update >/dev/null 2>&1
  apt-get -qq install -y librsvg2-bin python3 >/dev/null 2>&1
}

mkdir -p pdf .flat

python3 - <<'PY'
import glob, io, os, re

os.makedirs('.flat', exist_ok=True)
for p in sorted(glob.glob('diagrams/*.svg')):
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
