#!/usr/bin/env bash
# Assemble the published site, then check the things that are only true of
# the ASSEMBLED result.
#
#   bash website/build-site.sh [outdir]      # default: _site
#
# **One implementation, two callers.** `.github/workflows/pages.yml` deploys
# what this produces and `docker compose run --rm site` previews it. They
# used to assemble the site with their own `cp` lines, which meant the local
# preview could not see a path that only breaks in the deployed layout — and
# the deployed layout is precisely where the cross-directory font and asset
# references below resolve differently.
#
# Layout, which the checks depend on:
#   <out>/            landing page  (website/landing/.)   -> /undercroft/
#   <out>/assets/     landing assets, including fonts/
#   <out>/docs/       the mdBook manual                   -> /undercroft/docs/
set -u

cd "$(dirname "$0")/.."
OUT=${1:-_site}

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1"; }

echo "═══ build ═══"
rm -rf "$OUT"
if ! mdbook build website; then
  echo "  FAIL  mdbook build"
  echo ""
  echo "site results: 0 passed, 1 failed"
  exit 1
fi
mkdir -p "$OUT/docs"
# The whole landing directory, so its assets/ (images, fonts) ship with it.
cp -r website/landing/. "$OUT/"
cp -r website/book/* "$OUT/docs/"
echo "  ok    assembled $OUT"

echo "═══ checks ═══"

# ── 1. no page fetches a font from a third party ──────────────────────────
# The product contacts nothing by default; the site that says so should not
# either, and serving Google Fonts hands every visitor's IP to Google (LG
# Munchen I, 3 O 17493/20). `-I` skips the woff2 binaries.
CDN=$(grep -rIl -e "fonts.googleapis.com" -e "fonts.gstatic.com" "$OUT" 2>/dev/null || true)
if [ -n "$CDN" ]; then
  bad "the assembled site still references a font CDN:"
  printf '        %s\n' $CDN
else
  ok "no page references a font CDN"
fi

# ── 2. the fonts are actually there, and every face resolves ──────────────
FONTCSS="$OUT/assets/fonts/fonts.css"
if [ ! -f "$FONTCSS" ]; then
  bad "$FONTCSS is missing — self-hosting is declared and not shipped"
else
  missing=0
  faces=0
  while IFS= read -r name; do
    faces=$((faces + 1))
    [ -f "$OUT/assets/fonts/$name" ] || { missing=$((missing + 1)); echo "        missing: $name"; }
  done < <(grep -oE 'url\("\./[^"]+\.woff2"\)' "$FONTCSS" | sed 's|url("\./||; s|")||')
  # The premise: a stylesheet naming no faces would pass the loop silently.
  # Eight is one full subset across the declared family/weight combinations,
  # so anything under it means the stylesheet or this loop is broken rather
  # than the font set being small.
  if [ "$faces" -lt 8 ]; then
    bad "fonts.css names only $faces faces — the stylesheet or this check is broken"
  elif [ "$missing" -gt 0 ]; then
    bad "$missing of $faces font files named by fonts.css are not in the site"
  else
    ok "all $faces font faces resolve"
  fi
fi

# ── 3. no rendered text needs a subset we chose not to vendor ─────────────
# The font API offers seven subsets and only three are used by rendered
# text, so four are not vendored (357 KB, 23 faces). That trim is only safe
# while it stays true: text in a dropped range would fall back to a system
# font silently, mid-paragraph, with nothing anywhere reporting it.
#
# **Rendered `.html` only, and that scope is the whole point.** A scan that
# includes the vendored scripts finds characters from all seven subsets —
# `mermaid.min.js` carries Unicode parser tables and `mark.min.js` a
# diacritic map — and concludes every subset is in use. Those are data
# inside a script, never glyphs a browser paints. Measuring the bytes next
# to the observable instead of the observable is how this check would have
# been born useless.
#
# The scan is NUMERIC — perl parses `U+0102-0103` into integers and compares
# codepoints — and it walks the tree itself. The first version built a regex
# character class in the shell with sed, and sed ate the backslashes: the
# class came out `[x{0102}-x{0103}…]`, perl died on it, `2>/dev/null` ate the
# error, and the check reported "no dropped subset is used" having examined
# nothing. It passed a counterfactual with real Vietnamese and Polish text on
# the page. **Nothing here suppresses stderr, a tool failure is a FAIL rather
# than a pass, and the scanner is probed against a range that must match
# before its zero-results are believed.**
# No modules: the site image carries `perl-base`, which does not include
# File::Find. `opendir`/`readdir` are built-ins and always there.
scan_range() { # <unicode-range> <root> — prints matching files; non-zero on tool failure
  perl -CSD -e '
    my ($spec, $root) = @ARGV;
    my @r;
    for my $part (split /,/, $spec) {
      $part =~ s/\s+//g;
      $part =~ s/^U\+//i;
      next unless length $part;
      my ($a, $b) = split /-/, $part;
      $b = $a unless defined $b && length $b;
      push @r, [hex $a, hex $b];
    }
    die "parsed no ranges from: $spec\n" unless @r;
    my @hit;
    my @stack = ($root);
    while (my $dir = pop @stack) {
      opendir(my $dh, $dir) or next;
      for my $e (readdir $dh) {
        next if $e eq "." || $e eq "..";
        my $p = "$dir/$e";
        if (-d $p) { push @stack, $p; next }
        next unless $p =~ /\.html$/;
        open my $fh, "<:utf8", $p or next;
        LINE: while (my $line = <$fh>) {
          for my $ch (split //, $line) {
            my $cp = ord $ch;
            next if $cp < 0x80;
            for my $x (@r) {
              if ($cp >= $x->[0] && $cp <= $x->[1]) { push @hit, $p; last LINE }
            }
          }
        }
        close $fh;
      }
      closedir $dh;
    }
    print "$_\n" for @hit;
  ' "$1" "$2"
}

DROPPED="$OUT/assets/fonts/dropped-subsets.txt"
if [ ! -f "$DROPPED" ]; then
  bad "$DROPPED is missing — the subset trim has no safety net"
elif ! command -v perl >/dev/null 2>&1; then
  bad "perl is unavailable, so the dropped-subset check cannot run (it must not silently skip)"
else
  # The premise, and it is not optional. A scanner that cannot run reports
  # exactly what a clean site reports. Probe it with a KEPT subset's own
  # range, taken from the stylesheet: `latin` is on every page of an English
  # site, so finding nothing means the tool is broken, not the site clean.
  probe_range=$(awk '/^\/\* latin \*\/$/{f=1} f && /unicode-range:/{sub(/.*unicode-range: */,""); sub(/;.*/,""); print; exit}' "$FONTCSS")
  probe_out=$(scan_range "$probe_range" "$OUT" 2>&1)
  probe_code=$?
  if [ "$probe_code" -ne 0 ] || [ -z "$probe_out" ]; then
    bad "the codepoint scanner did not work (exit $probe_code) — its zero-results below would be meaningless:"
    printf '        %s\n' "${probe_out:-no output, and no file matched the latin range}"
  else
    used=0
    checked=0
    while IFS="$(printf '\t')" read -r subset range; do
      case "$subset" in ''|\#*) continue ;; esac
      checked=$((checked + 1))
      found=$(scan_range "$range" "$OUT" 2>&1)
      code=$?
      if [ "$code" -ne 0 ]; then
        bad "scanning for the '$subset' subset failed: $found"
        used=$((used + 1))
      elif [ -n "$found" ]; then
        used=$((used + 1))
        bad "rendered text uses the '$subset' subset, which is not vendored:"
        printf '        %s\n' $(printf '%s\n' "$found" | head -3)
        echo "        Add it to KEEP in website/tools/vendor-fonts.sh and re-run it,"
        echo "        or that text falls back to a system font mid-paragraph."
      fi
    done < "$DROPPED"
    if [ "$checked" -eq 0 ]; then
      bad "$DROPPED lists no subsets — either nothing was dropped, or the parse is broken"
    elif [ "$used" -eq 0 ]; then
      ok "no rendered text needs any of the $checked dropped subset(s)"
    fi
  fi
fi

# ── 4. the manual's stylesheet reaches the fonts ACROSS directories ───────
# The book's skin `@import`s the font stylesheet by a relative path that
# leaves the book and re-enters the landing assets. That path is correct
# only in the assembled layout, which is why it is checked here and cannot
# be checked in either half alone.
SKIN=$(ls "$OUT"/docs/assets/undercroft-*.css 2>/dev/null | head -1)
if [ -z "$SKIN" ]; then
  bad "the manual's skin stylesheet is not in $OUT/docs/assets/"
else
  REL=$(grep -oE "@import url\('[^']+'\)" "$SKIN" | sed "s|@import url('||; s|')||" | head -1)
  if [ -z "$REL" ]; then
    bad "$SKIN has no @import — the manual would render in fallback faces"
  else
    RESOLVED=$(cd "$(dirname "$SKIN")" && cd "$(dirname "$REL")" 2>/dev/null && pwd)/$(basename "$REL")
    if [ -f "$RESOLVED" ]; then
      ok "the manual's @import resolves ($REL)"
    else
      bad "the manual imports $REL, which does not exist in the assembled site"
    fi
  fi
fi

# ── 5. the 404 page's assets are absolute under the deployed prefix ───────
# A 404 is rendered for a URL at ANY depth, so its links cannot be relative.
# mdBook builds them from `site-url` in book.toml; with that unset they came
# out as if the book were at the domain root, and the one page a lost
# visitor sees was the one page with no stylesheet.
SITE_URL=$(grep -oE '^site-url *= *"[^"]*"' website/book.toml | sed 's/.*"\(.*\)"/\1/')
if [ -z "$SITE_URL" ]; then
  bad "book.toml declares no site-url, so the generated 404 resolves its assets from the domain root"
elif [ ! -f "$OUT/docs/404.html" ]; then
  bad "$OUT/docs/404.html was not generated"
elif grep -q "href=\"$SITE_URL" "$OUT/docs/404.html"; then
  ok "404.html resolves its assets under $SITE_URL"
else
  bad "404.html does not reference $SITE_URL — its assets will 404 from any subdirectory"
fi

# ── 6. the landing page is at the root and the manual under /docs ─────────
[ -f "$OUT/index.html" ] && ok "landing page at the site root" \
  || bad "no index.html at the site root"
[ -f "$OUT/docs/index.html" ] && ok "manual under /docs" \
  || bad "no manual under /docs"

echo ""
echo "site results: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
