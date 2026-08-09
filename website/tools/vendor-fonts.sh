#!/usr/bin/env bash
# Vendor the web fonts the site uses, so no page fetches anything from a
# third party.
#
#   bash website/tools/vendor-fonts.sh
#
# **Run by hand, not by the build.** The point of self-hosting is that
# building and serving the site touch no external host; a build step that
# fetched fonts would defeat it exactly. The outputs are committed, and this
# script exists so their provenance is reproducible rather than remembered.
#
# Why self-host at all — two independent reasons, either sufficient:
#   * Serving Google Fonts transmits every visitor's IP address to Google.
#     LG Munchen I, 3 O 17493/20 (20 Jan 2022) awarded damages against a site
#     operator for exactly that, under GDPR. Our binary phones home to
#     nobody; the website should hold the same line.
#   * A page that renders only when a CDN answers is a page with a
#     dependency it did not choose.
#
# What it does: asks the Google CSS API what faces the site's font stack
# needs, downloads the `.woff2` for every subset in KEEP, and rewrites the
# stylesheet with local URLs. Only the `src:` line is substituted —
# everything else in each block, above all `unicode-range`, is passed through
# UNCHANGED, so the browser still fetches only what a page needs and coverage
# for the kept subsets is identical to what the site served before.
# Hand-authoring those blocks is how a vendoring pass quietly drops a script.
#
# **KEEP is a MEASURED list, not a guess.** The API offers seven subsets;
# three are used by rendered text and four are not, and the difference is not
# obvious — a naive scan of the built site finds characters from all seven,
# because `mermaid.min.js` carries Unicode parser tables and `mark.min.js`
# carries a diacritic map. Those are *data inside a script*, never glyphs a
# browser paints. Measured over the rendered `.html` of the assembled site:
#
#     latin        used     greek        used     cyrillic      used
#     latin-ext    unused   greek-ext    unused   cyrillic-ext  unused
#     vietnamese   unused
#
# The four unused ones are 23 faces and 357 KB. They are recorded with their
# ranges in `dropped-subsets.txt`, and `website/build-site.sh` FAILS if any
# character in one of those ranges ever appears in rendered text — so adding
# a page with Polish or Vietnamese in it is a failing build that names this
# script, not a silent fallback to a system font.
#
# Licences: IBM Plex and GFS Didot are both SIL Open Font License 1.1, which
# permits redistribution and requires the licence to travel with the fonts.
# It is fetched alongside them into OFL-*.txt and referenced from NOTICE.
set -euo pipefail

cd "$(dirname "$0")/../.."

OUT=website/landing/assets/fonts
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
# The stack declared in website/landing/index.html (--didot/--sans/--mono)
# and website/assets/undercroft.css. Keep in step with them.
SPEC="family=GFS+Didot&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap"
KEEP="latin greek cyrillic"

rm -rf "$OUT"
mkdir -p "$OUT"
SRC=$(mktemp)
trap 'rm -f "$SRC"' EXIT

# A modern User-Agent is what makes the API answer with woff2 rather than
# ttf; without it this silently vendors a format twice the size.
curl -fsS -A "$UA" "https://fonts.googleapis.com/css2?$SPEC" -o "$SRC"
grep -q "woff2" "$SRC" || { echo "the API did not return woff2 — check the User-Agent" >&2; exit 1; }

CSS="$OUT/fonts.css"
DROPPED="$OUT/dropped-subsets.txt"
cat > "$CSS" <<'HEADER'
/* Self-hosted web fonts — see website/tools/vendor-fonts.sh, which
   generated this file. Do not edit by hand; re-run the script.

   Every face below is served from this directory. Nothing here, and
   nothing on any page of this site, requests a font from a third party:
   website/build-site.sh fails the build if the assembled site references
   a font CDN at all.

   Subsets no rendered page uses are not vendored; they are listed with
   their ranges in dropped-subsets.txt, and build-site.sh fails if text in
   one of those ranges ever appears.

   IBM Plex (IBM) and GFS Didot (Greek Font Society) are both under the SIL
   Open Font License 1.1; the licence text sits beside this file. */
HEADER
cat > "$DROPPED" <<'HEADER'
# Subsets the font API offers that this site does not vendor, because no
# rendered page uses them. One `subset<TAB>unicode-range` per line, written
# by website/tools/vendor-fonts.sh.
#
# website/build-site.sh reads this and fails if any character in one of
# these ranges appears in the assembled site's rendered HTML. That is the
# whole safety net for the trim: text in a dropped range would otherwise
# fall back to a system font with nothing reporting it.
HEADER

subset=""; family=""; weight=""; url=""; urange=""; buf=""
kept=0; dropped=0

flush() {
  [ -n "$subset" ] || return 0
  case " $KEEP " in
    *" $subset "*)
      local slug name
      slug=$(printf '%s' "$family" | tr '[:upper:] ' '[:lower:]-')
      name="$slug-$weight-$subset.woff2"
      curl -fsS "$url" -o "$OUT/$name"
      # Only the src line changes. Everything else — including
      # unicode-range — is the API's own text.
      printf '%s\n' "$buf" \
        | sed "s|^ *src: url(.*|  src: url(\"./$name\") format(\"woff2\");|" >> "$CSS"
      kept=$((kept + 1))
      ;;
    *)
      grep -q "^$subset	" "$DROPPED" 2>/dev/null \
        || printf '%s\t%s\n' "$subset" "$urange" >> "$DROPPED"
      dropped=$((dropped + 1))
      ;;
  esac
  subset=""; buf=""
}

while IFS= read -r line; do
  case "$line" in
    "/* "*)
      flush
      subset=${line#/\* }; subset=${subset%% \*/}
      buf="$line"
      continue
      ;;
    *"font-family:"*)
      family=$(printf '%s' "$line" | sed "s/.*font-family: *'\([^']*\)'.*/\1/") ;;
    *"font-weight:"*)
      weight=$(printf '%s' "$line" | sed 's/[^0-9]*\([0-9]*\).*/\1/') ;;
    *"src: url("*)
      url=$(printf '%s' "$line" | sed 's|.*src: url(\([^)]*\)).*|\1|') ;;
    *"unicode-range:"*)
      urange=$(printf '%s' "$line" | sed 's/.*unicode-range: *//; s/;.*//') ;;
  esac
  buf="$buf
$line"
done < "$SRC"
flush

# Licences, from the repository that publishes the fonts Google serves.
# They arrive with CRLF endings, which `.gitattributes` forbids across this
# repo and `tests/battery.sh` fails on; `tr -d '\r'` normalises them on the
# way in. Line endings are not licence terms, and leaving it to git's own
# normalisation would leave the working copy failing the preflight until the
# next checkout.
for dir in ibmplexsans ibmplexmono gfsdidot; do
  curl -fsS "https://raw.githubusercontent.com/google/fonts/main/ofl/$dir/OFL.txt" \
    | tr -d '\r' > "$OUT/OFL-$dir.txt"
done

echo "vendored $kept face(s); skipped $dropped face(s) in unused subsets"
echo "kept subsets: $KEEP"
printf 'dropped subsets: '; grep -v '^#' "$DROPPED" | cut -f1 | tr '\n' ' '; echo
du -sh "$OUT" | cut -f1 | xargs echo "directory:"
