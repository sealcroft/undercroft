"""The text-fit table's pins, compared with what regenerates it. Stdlib only, reads no font.

ROADMAP O189, V2 item 8 of the font-version ruling. `build.sh` runs this in both of its
modes before the text-fit arm, so the `arch-check` service runs it on every battery and
every pull request, on a stock python image with `architecture/` mounted read-only. It
writes nothing.

The table header records what made it: a `# package:` line per apt package the
regeneration installed, a `# slot` line per font file with its version, upm, sha256 and
source, and the `# unicode-version:` the categories come from. Three places pin the same
facts, and each can move without the others:

  gen_advances.sh  the apt pins (`name=version` on its install line) and the base image,
                   by digest, in the command it documents;
  fonts.tsv        the font files, by slot, sha256 and source;
  advances.tsv     the header the generator wrote after checking each of those.

Every comparison runs in BOTH directions: a pin the header does not record, and a header
line nothing pins, both fail. So do an unpinned package on the install line, an image
named without a digest, a Debian font row whose package the script does not pin, and a
Unicode version other than the pinned unicode-data's.

WHY THERE IS A PREMISE FIXTURE: a comparison that parsed nothing reports exactly what
agreement reports. Before the real files are read, a synthetic script, fetch list and
header that agree must pass, and each copy of them with one line changed or removed must
fail. If either does not happen this exits 2 without reporting on the real files.

`read_fonts` is the one reader of fonts.tsv: gen_advances.sh's fetch step and
gen_advances.py both import it.
"""
import collections
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FONTS_TSV = os.path.join(HERE, "fonts.tsv")
TABLE = os.path.join(HERE, "advances.tsv")
SCRIPT = os.path.join(HERE, "gen_advances.sh")

FIELDS = ("slot", "file", "sha256", "source")
Pin = collections.namedtuple("Pin", FIELDS)

SLOT = re.compile(r"[a-z0-9][a-z0-9.-]*")
FILE = re.compile(r"[a-z0-9]+/[A-Za-z0-9][A-Za-z0-9._-]*\.ttf")
SHA256 = re.compile(r"[0-9a-f]{64}")
DEBIAN_SOURCE = re.compile(r"debian:([a-z0-9][a-z0-9.+-]*)=([A-Za-z0-9.+~:-]+)")
HTTPS_SOURCE = re.compile(r"https://[A-Za-z0-9.-]+/[!-~]+")


# ------------------------------------------------------------------ fonts.tsv
def read_fonts(text):
    """[Pin] in file order. Raises ValueError, naming the line, on anything malformed."""
    rows, header, seen = [], False, set()
    for n, line in enumerate(text.split("\n"), 1):
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split("\t")
        if not header:
            if tuple(parts) != FIELDS:
                raise ValueError("fonts.tsv line %d: expected the column header %s, got %r"
                                 % (n, "\\t".join(FIELDS), line))
            header = True
            continue
        if len(parts) != len(FIELDS):
            raise ValueError("fonts.tsv line %d: %d fields, expected %d" % (n, len(parts), len(FIELDS)))
        pin = Pin(*parts)
        if not SLOT.fullmatch(pin.slot):
            raise ValueError("fonts.tsv line %d: slot %r is not a slot name" % (n, pin.slot))
        if not FILE.fullmatch(pin.file):
            raise ValueError("fonts.tsv line %d: file %r is not a <directory>/<name>.ttf name" % (n, pin.file))
        if not SHA256.fullmatch(pin.sha256):
            raise ValueError("fonts.tsv line %d: %r is not a lowercase sha256" % (n, pin.sha256))
        if not (DEBIAN_SOURCE.fullmatch(pin.source) or HTTPS_SOURCE.fullmatch(pin.source)):
            raise ValueError("fonts.tsv line %d: source %r is neither debian:<package>=<version> nor an https URL"
                             % (n, pin.source))
        if (pin.slot, pin.file) in seen:
            raise ValueError("fonts.tsv line %d: %s:%s is listed twice" % (n, pin.slot, pin.file))
        seen.add((pin.slot, pin.file))
        rows.append(pin)
    if not header:
        raise ValueError("fonts.tsv has no column header")
    if not rows:
        raise ValueError("fonts.tsv has no rows")
    return rows


# ------------------------------------------------------------ gen_advances.sh
def apt_pins(script):
    """({package: version} from every `apt-get ... install` command, [problems])."""
    pins, problems, commands = {}, [], 0
    lines = [l for l in script.split("\n") if not l.lstrip().startswith("#")]
    joined = re.sub(r"\\\n", " ", "\n".join(lines))
    for command in joined.split("\n"):
        words = command.split()
        if "apt-get" not in words or "install" not in words:
            continue
        commands += 1
        for word in words[words.index("install") + 1:]:
            if word[0] in ">|&;<" or word[:2] == "2>":
                break
            if word.startswith("-"):
                continue
            name, eq, version = word.partition("=")
            if not eq or not version:
                problems.append("gen_advances.sh installs %s with no version pin" % word)
            elif name in pins and pins[name] != version:
                problems.append("gen_advances.sh pins %s twice, to %s and %s" % (name, pins[name], version))
            else:
                pins[name] = version
    if not commands:
        problems.append("gen_advances.sh has no apt-get install command: nothing was compared")
    return pins, problems


def images(script):
    """[(reference, digest or None)] for every debian image the script names, comments included."""
    return re.findall(r"\b(debian:[a-z0-9][a-z0-9._-]*)(?:@sha256:([0-9a-f]{64}))?", script)


# --------------------------------------------------------------- table header
def header(table):
    """({package: version}, {Pin}, [unicode versions], [problems]) from the '#' lines."""
    packages, slots, versions, problems = {}, set(), [], []
    for line in table.split("\n"):
        if not line.startswith("#"):
            continue
        if line.startswith("# package:"):
            m = re.fullmatch(r"# package: (\S+) (\S+)", line)
            if not m:
                problems.append("malformed header line %r" % line)
            elif m.group(1) in packages:
                problems.append("the table header records package %s twice" % m.group(1))
            else:
                packages[m.group(1)] = m.group(2)
        elif line.startswith("# slot "):
            m = re.fullmatch(r"# slot ([^\s:]+): (\S+) .*\bupm=\d+ sha256=([0-9a-f]{64}) source=(\S+)", line)
            if not m:
                problems.append("malformed header line %r" % line)
            else:
                slots.add(Pin(*m.groups()))
        elif line.startswith("# unicode-version:"):
            m = re.fullmatch(r"# unicode-version: (\d+\.\d+\.\d+)", line)
            if not m:
                problems.append("malformed header line %r" % line)
            else:
                versions.append(m.group(1))
    return packages, slots, versions, problems


def upstream(version):
    """A Debian version's upstream part: no epoch, no revision."""
    return version.split(":", 1)[-1].rsplit("-", 1)[0]


# ------------------------------------------------------------------- compare
def compare(script, fonts_text, table):
    """Every disagreement between the three, in both directions. Empty means they agree."""
    problems = []
    try:
        fonts = read_fonts(fonts_text)
    except ValueError as e:
        return [str(e)]
    pins, p = apt_pins(script)
    problems += p
    packages, slots, versions, p = header(table)
    problems += p
    if not packages or not slots:
        problems.append("the table header records %d package line(s) and %d slot line(s): nothing was compared"
                        % (len(packages), len(slots)))

    for name in sorted(set(pins) | set(packages)):
        if name not in packages:
            problems.append("gen_advances.sh pins %s=%s and the table header records no such package"
                            % (name, pins[name]))
        elif name not in pins:
            problems.append("the table header records package %s %s and gen_advances.sh pins no such package"
                            % (name, packages[name]))
        elif pins[name] != packages[name]:
            problems.append("gen_advances.sh pins %s=%s and the table header records %s %s"
                            % (name, pins[name], name, packages[name]))

    rows = set(fonts)
    for pin in sorted(rows - slots):
        problems.append("fonts.tsv pins %s:%s sha256=%s source=%s and the table header has no such slot line"
                        % pin)
    for pin in sorted(slots - rows):
        problems.append("the table header records %s:%s sha256=%s source=%s and fonts.tsv has no such row" % pin)
    for pin in fonts:
        m = DEBIAN_SOURCE.fullmatch(pin.source)
        if m and pins.get(m.group(1)) != m.group(2):
            problems.append("fonts.tsv takes %s:%s from %s=%s, which gen_advances.sh does not pin"
                            % (pin.slot, pin.file, m.group(1), m.group(2)))

    if len(versions) != 1:
        problems.append("the table header declares %d Unicode versions, expected exactly one" % len(versions))
    elif "unicode-data" not in pins:
        problems.append("gen_advances.sh does not pin unicode-data, which the declared Unicode version comes from")
    elif upstream(pins["unicode-data"]) != versions[0]:
        problems.append("the table header declares Unicode %s and gen_advances.sh pins unicode-data=%s"
                        % (versions[0], pins["unicode-data"]))

    named = images(script)
    if not named:
        problems.append("gen_advances.sh names no debian image: the base image pin was not compared")
    for reference, sha in named:
        if not sha:
            problems.append("gen_advances.sh names %s without an @sha256 digest" % reference)
    return problems


# ------------------------------------------------------------ premise fixture
FIXTURE_A, FIXTURE_B = "a" * 64, "b" * 64
FIXTURE_SCRIPT = (
    "#!/usr/bin/env sh\n"
    "#   docker run --rm -w /a debian:bookworm-slim@sha256:%s sh gen.sh\n"
    "apt-get -qq update >/dev/null\n"
    "apt-get -qq install -y --no-install-recommends \\\n"
    "  fonts-x=1.0-1 \\\n"
    "  unicode-data=15.0.0-1 >/dev/null\n" % ("c" * 64))
FIXTURE_FONTS = (
    "# comment\n"
    "slot\tfile\tsha256\tsource\n"
    "debian\tx/X.ttf\t%s\tdebian:fonts-x=1.0-1\n"
    "up-1\tx/X.ttf\t%s\thttps://example.invalid/X.ttf\n" % (FIXTURE_A, FIXTURE_B))
FIXTURE_TABLE = (
    "# generated\n"
    "# package: fonts-x 1.0-1\n"
    "# package: unicode-data 15.0.0-1\n"
    "# unicode-version: 15.0.0\n"
    "# slot debian: x/X.ttf Version 1.0 upm=1000 sha256=%s source=debian:fonts-x=1.0-1\n"
    "# slot up-1: x/X.ttf Version 1.0 upm=1000 sha256=%s source=https://example.invalid/X.ttf\n"
    "cp\tsans400\n" % (FIXTURE_A, FIXTURE_B))
# (what, which input, old text, new text). Each must change its input and each must fail.
MUTATIONS = (
    ("a header package line changed", "table", "# package: fonts-x 1.0-1", "# package: fonts-x 1.0-2"),
    ("a header package line missing", "table", "# package: unicode-data 15.0.0-1\n", ""),
    ("a header slot digest changed", "table", "sha256=%s source=https" % FIXTURE_B, "sha256=%s source=https" % ("d" * 64)),
    ("a header slot line missing", "table", "# slot debian: x/X.ttf Version 1.0 upm=1000 sha256=%s "
                                            "source=debian:fonts-x=1.0-1\n" % FIXTURE_A, ""),
    ("a header Unicode version changed", "table", "# unicode-version: 15.0.0", "# unicode-version: 15.1.0"),
    ("a fonts.tsv digest changed", "fonts", "\t%s\tdebian:" % FIXTURE_A, "\t%s\tdebian:" % ("e" * 64)),
    ("a fonts.tsv row added", "fonts", "\thttps://example.invalid/X.ttf\n",
     "\thttps://example.invalid/X.ttf\nup-1\tx/Y.ttf\t%s\thttps://example.invalid/Y.ttf\n" % FIXTURE_B),
    ("an apt pin changed", "script", "fonts-x=1.0-1", "fonts-x=1.0-3"),
    ("an apt package unpinned", "script", "unicode-data=15.0.0-1", "unicode-data"),
    ("the image named without a digest", "script", "@sha256:%s" % ("c" * 64), ""),
)


def probe():
    """Empty when the comparison passes agreeing inputs and fails every one-line change."""
    missing = []
    base = {"script": FIXTURE_SCRIPT, "fonts": FIXTURE_FONTS, "table": FIXTURE_TABLE}
    got = compare(base["script"], base["fonts"], base["table"])
    if got:
        missing.append("agreeing fixture inputs passing (got %s)" % got)
    for what, which, old, new in MUTATIONS:
        changed = dict(base)
        changed[which] = base[which].replace(old, new)
        if changed[which] == base[which]:
            missing.append("the fixture mutation '%s' applying (its anchor is gone)" % what)
        elif not compare(changed["script"], changed["fonts"], changed["table"]):
            missing.append("%s failing" % what)
    return missing


def main():
    missing = probe()
    if missing:
        print("PREMISE FAILURE: the pins check cannot see %s." % "; ".join(missing))
        print("Its zero-results would be meaningless. Fix the checker.")
        return 2
    print("premise probe: the pins check passes agreeing inputs and fails each of %d one-line changes"
          % len(MUTATIONS))
    try:
        script = open(SCRIPT, encoding="utf-8").read()
        fonts_text = open(FONTS_TSV, encoding="utf-8").read()
        table = open(TABLE, encoding="utf-8").read()
    except OSError as e:
        print("PREMISE FAILURE: %s" % e)
        return 2
    problems = compare(script, fonts_text, table)
    if problems:
        for p in problems:
            print("  - %s" % p)
        print("pins: %d disagreement(s) between gen_advances.sh, fonts.tsv and the advance table header"
              % len(problems))
        return 1
    pins, _ = apt_pins(script)
    print("pins: %d apt pins, %d font files over %d slots and the Unicode version agree with the table header, "
          "both ways" % (len(pins), len(read_fonts(fonts_text)), len({p.slot for p in read_fonts(fonts_text)})))
    return 0


if __name__ == "__main__":
    sys.exit(main())
