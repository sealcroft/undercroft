#!/bin/sh
# Calibration's record of the render image (ROADMAP O189, V3). Runs inside
#   minlag/mermaid-cli:10.9.1@sha256:f0e8d29ef5385d797724d78c2a1bb00c8398476e8370f0219c0da86cce07d44c
# as root, `architecture/` read-only at /a and the run folder at /r, and installs nothing.
#
# It writes /r/platform/:
#   chromium.txt      `chromium-browser --version`
#   packages.txt      every apk package and version, and harfbuzz.txt the HarfBuzz the
#                     Chromium binary links, resolved through the library symlink
#   fc-list.tsv       every face fontconfig knows: PostScript name, collection index, family,
#                     style, file and the file's sha256. The judges find the CJK exception here.
#   cjk/<collection>  a copy of each collection cjk.tsv declares, so the fixture generator can
#                     read which codepoints its CJK face maps without the render image
set -eu
OUT=/r/platform
TAB=$(printf '\t')
mkdir -p "$OUT/cjk"
chromium-browser --version > "$OUT/chromium.txt"
apk info -v > "$OUT/packages.txt"
{
  grep '^harfbuzz-' "$OUT/packages.txt"
  ldd /usr/lib/chromium/chromium | grep -i harfbuzz
  readlink -f /usr/lib/libharfbuzz.so.0
} > "$OUT/harfbuzz.txt"

fc-list -f '%{file}\n' | sort -u > /tmp/files.txt
: > /tmp/digests.tsv
while IFS= read -r file; do
  printf '%s\t%s\n' "$file" "$(sha256sum "$file" | cut -d' ' -f1)" >> /tmp/digests.tsv
done < /tmp/files.txt
printf 'psname\tindex\tfamily\tstyle\tfile\tsha256\n' > "$OUT/fc-list.tsv"
fc-list -f '%{postscriptname}\t%{index}\t%{family}\t%{style}\t%{file}\n' | sort > /tmp/faces.tsv
awk -F "$TAB" -v OFS="$TAB" 'NR == FNR { sha[$1] = $2; next } { print $0, sha[$5] }' \
  /tmp/digests.tsv /tmp/faces.tsv >> "$OUT/fc-list.tsv"

grep -v '^#' /a/textfit/calibrate/cjk.tsv | awk -F "$TAB" 'NR > 1 && NF == 4 { print $2 }' > /tmp/cjk-ps.txt
if [ ! -s /tmp/cjk-ps.txt ]; then
  echo "platform: cjk.tsv declares no CJK face" >&2
  exit 1
fi
while IFS= read -r ps; do
  file=$(awk -F "$TAB" -v ps="$ps" '$1 == ps { print $5 }' "$OUT/fc-list.tsv")
  if [ -z "$file" ]; then
    echo "platform: fontconfig has no face $ps" >&2
    exit 1
  fi
  cp "$file" "$OUT/cjk/"
done < /tmp/cjk-ps.txt
echo "platform: $(cat "$OUT/chromium.txt"); $(grep -c . /tmp/faces.tsv) faces in $(grep -c . /tmp/files.txt) files; CJK collections copied: $(ls "$OUT/cjk" | tr '\n' ' ')"
