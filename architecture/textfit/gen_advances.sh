#!/usr/bin/env sh
# Regenerate architecture/textfit/advances.tsv — the per-glyph advance table the
# text-fit gate reads (ROADMAP O189).
#
# Run BY HAND, never by the build, the way website/tools/vendor-fonts.sh is: the
# gate must run offline on a stock python image, so the table is data checked
# into the tree and this script is how that data is made. It is also the ONE place
# the network is used: the second slot's font files are fetched here, inside the
# container, into a directory outside the tree, and no build or gate fetches
# anything. Re-running it on the same pins reproduces the file byte for byte — it
# carries no date — so "regenerate and compare" is a valid way to audit it.
#
# Every input is pinned, and a pin that no longer holds fails loudly here instead
# of silently moving the standard the gate enforces; moving one is then a
# decision, recorded in ROADMAP:
#   - the base image, by digest, in the command below;
#   - every apt package, by version, on the install line;
#   - every font file, by slot and sha256, in textfit/fonts.tsv — the one fetch
#     list the generator and the calibration harness share. Slot debian comes from
#     the packages below; slot noto-23.7.1 is fetched per file from its release tag.
# textfit/pins.py, which build.sh runs in both modes, compares the table header
# with this install line and with fonts.tsv in both directions.
#
# The fetch refuses a failed download, an oversized one and a digest fonts.tsv does
# not pin, before the generator reads a byte. The generator can REFUSE too: a file
# whose digest or source disagrees with fonts.tsv, an unmodelled feature or lookup
# type, a ligature it cannot trace to codepoints or flatten, a joining model
# ArabicShaping.txt contradicts. gen_advances.py lists every refusal. A refusal
# exits non-zero and leaves the existing table untouched, with no partial file
# beside it.
#
# From the repo root (Git Bash needs the MSYS prefix, or the container path is
# rewritten into a Windows one):
#   MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD/architecture:/a" -w /a \
#     debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 \
#     sh textfit/gen_advances.sh
set -eu

FETCHED=/tmp/textfit-fonts

apt-get -qq update >/dev/null
apt-get -qq install -y --no-install-recommends \
  ca-certificates=20250419~deb12u1 \
  fonts-dejavu-core=2.37-6 \
  fonts-dejavu-extra=2.37-6 \
  fonts-noto-core=20201225-1 \
  python3-fonttools=4.38.0-1+deb12u1 \
  unicode-data=15.0.0-1 >/dev/null

rm -rf "$FETCHED"
if ! PYTHONDONTWRITEBYTECODE=1 python3 - "$FETCHED" <<'PY'
import hashlib
import os
import sys
import urllib.request

sys.path.insert(0, "textfit")
import pins  # noqa: E402  the one reader of fonts.tsv

LIMIT = 32 * 1024 * 1024
root = sys.argv[1]
try:
    rows = pins.read_fonts(open("textfit/fonts.tsv", encoding="utf-8").read())
except (OSError, ValueError) as e:
    sys.exit("REFUSED: fonts.tsv: %s" % e)
fetched = 0
for row in rows:
    if not row.source.startswith("https://"):
        continue
    try:
        with urllib.request.urlopen(row.source, timeout=60) as response:
            data = response.read(LIMIT + 1)
    except OSError as e:
        sys.exit("REFUSED: %s:%s could not be fetched from %s: %s" % (row.slot, row.file, row.source, e))
    if len(data) > LIMIT:
        sys.exit("REFUSED: %s:%s from %s is larger than %d bytes" % (row.slot, row.file, row.source, LIMIT))
    got = hashlib.sha256(data).hexdigest()
    if got != row.sha256:
        sys.exit("REFUSED: %s:%s from %s has sha256 %s, and fonts.tsv pins %s"
                 % (row.slot, row.file, row.source, got, row.sha256))
    dest = os.path.join(root, row.slot, row.file)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as out:
        out.write(data)
    with open(dest + ".source", "w", encoding="utf-8") as out:
        out.write(row.source + "\n")
    fetched += 1
print("fetched %d font file(s), each matching its fonts.tsv sha256" % fetched)
PY
then
  echo "fetch refused: textfit/advances.tsv left unchanged" >&2
  exit 1
fi

if ! PYTHONDONTWRITEBYTECODE=1 python3 textfit/gen_advances.py "$FETCHED" > textfit/advances.tsv.new; then
  rm -f textfit/advances.tsv.new
  echo "generation refused: textfit/advances.tsv left unchanged" >&2
  exit 1
fi
mv textfit/advances.tsv.new textfit/advances.tsv
echo "wrote textfit/advances.tsv ($(grep -vc '^#' textfit/advances.tsv) lines including the five section headers)"
