"""Write the text-fit advance table to stdout. Run through gen_advances.sh only.

The standard is ROADMAP O189's ruling: a line fits under the per-glyph MAXIMUM of
the faces a reader can get for its family. Each column below is that maximum over
the faces listed for it, the in-block script and fallback faces, and the face every
modelled reader draws the codepoint with, in 1/10000 em, rounded UP so the table
never prices a glyph narrower than any of those faces renders it.

  sans400  DejaVu Sans Book, Noto Sans Regular      (weights below 600)
  sans600  DejaVu Sans Bold, Noto Sans Bold          (600 and above)
  mono     DejaVu Sans Mono Book and Bold            (1233/2048 em for both)
  serif    DejaVu Serif Book and Italic, Noto Serif Regular and Italic

TWO SLOTS, ONE FETCH LIST (the font-version ruling, V1). Every face above and below is
taken from EVERY slot that pins it in textfit/fonts.tsv, and each column is the maximum
over all of them: slot `debian`, the Debian bookworm packages gen_advances.sh installs by
version, which pins every file; and slot `noto-23.7.1`, the notofonts monthly release
23.7.1, which gen_advances.sh fetches per file into a directory outside the tree and
passes here. DejaVu comes from Debian only. Before any file is opened as a font its
sha256 must equal fonts.tsv's, a Debian file must belong to the package and version its
row names, and a fetched file must carry the URL gen_advances.sh fetched it from. The
header records each slot's files with version, upm, sha256 and source.

The Noto script faces price their own blocks in EVERY column, because a renderer
falls back to them whatever family the text asked for: Noto Sans Arabic, Noto Sans
Thai and Noto Looped Thai, Noto Sans Devanagari. Noto Sans Math is the same kind of
fallback for the arrow and mathematical blocks it maps. Looped Thai and Math are
the faces headless Chromium fell back to in O189's P-A run. CJK has no face here
and is priced by textfit.py's declared rule instead.

EVERY MODELLED READER MUST DRAW A CELL, OR IT IS '-' (panel 2's QM ruling). readers.py is
the one reader model: for each slot's page, each of its four stack variants (DejaVu or Noto
primary, then Noto Sans Arabic, Noto Sans Thai or Noto Looped Thai, Noto Sans Devanagari,
Noto Sans Math) and each style a column renders in (sans400 sans-serif 400; sans600
sans-serif 700; mono monospace 400 and 700; serif serif 400 upright and italic), the face
the browser's @font-face matching selects in each family. A reader draws a codepoint with
the FIRST face of its stack that maps it, where mapping has rendered()'s meaning below: the
codepoint, or every part of its full canonical decomposition. For every (slot, reader) of a
column:
  - where some reader has no such face, the cell is '-', whatever the column's own faces
    map: that reader draws the codepoint with a face outside the table, at a width nobody
    measured (Noto Sans lacks U+2307, and headless Chromium drew it at 1 em in a CJK face);
  - otherwise the advance of every reader's drawing face joins the maximum, beside the
    column's faces and the in-block script and fallback faces, which are kept.
The codepoints considered are every codepoint any stack face maps, within in_domain, so a
cell can be ADDED where no column face mapped it. The CJK blocks follow the same rule, and
their cells are counted apart in the header, because textfit.py prices them by rule and never
reads their rows. An Arabic letter's cells in the arabic section follow it too: where some
reader of a column draws the letter with no face, its four form cells there are '-', since
textfit.py prices a letter from those rows and never from its codepoint row; and where every
reader draws it, each reader's face must be one the section prices, or generation refuses.
The header records, per column and against the rule before the ruling computed in the same
run, the cells withdrawn, added and raised, and which readers lacked a face; and, per column,
the Arabic letters whose form cells were withdrawn. A codepoint no reader-complete stack
draws gets '-' or no row, and textfit.py fails closed on it: change the reader model through
a ruling, never a cell by hand.

JOINERS ARE PRICED IN EVERY COLUMN. U+200C and U+200D take a row in each column, at every
reader's first mapper. The rule before this one priced a column whose own faces map neither
at the widest script or fallback face that maps it; that price is kept where it is wider, and
the header says where. Generation refuses if some reader of a column draws either with no face.

UNICODE comes from one version, the pinned unicode-data package: UnicodeData.txt
gives the general categories, combining classes and canonical decompositions,
ArabicShaping.txt the joining types, CompositionExclusions.txt the composition
exclusions. Python's own unicodedata is not read here, because it can be a different
Unicode version. The version both text files declare on their first line must equal
the unicode-data package's, and the header declares it: textfit.py refuses to run under
a Python whose unicodedata is another.

A FACE THAT LACKS A PRECOMPOSED CODEPOINT but maps its full canonical decomposition
renders the decomposition, because a shaper decomposes before it falls back to
another face. The ligature fixture measured it: DejaVu Sans has no U+06C0 and drew
U+06D5 + U+0654, 0.585 px wider at 11 px than the table priced. So a codepoint's
row also takes that sum in such a face, and an Arabic letter's forms take its base
letter's forms plus its marks' advances there.

A SHAPER ALSO RECOMPOSES: given a base and a mark the face maps precomposed, it can draw
the precomposed glyph, which can be far wider than the parts (U+1F9C in Noto Sans Bold,
1.462 em against 0.837 em). That is not priced. A fourth section lists every canonical
composition pair (base, mark, composite) whose composite has a row, from the two-codepoint
canonical decompositions less the composition exclusions, the singletons and the
non-starter decompositions, and textfit.py refuses a line that holds one outside Arabic.

ARABIC IS PRICED BY POSITIONAL FORM, in a second section. The letters are the
characters of 0600-06FF, 0750-077F, 0870-089F and 08A0-08FF whose category is Lo
or Lm and which an Arabic face maps. Each carries its ArabicShaping.txt joining type
(D, R, L, C or U). A shaper picks the form by that type, not by the glyphs a font
carries, so the fonts are only CROSS-CHECKED against it, in the header. For each of
the four forms, in each face of a column that maps the letter (the column's own
faces that map Arabic, plus Noto Sans Arabic), the generator reads the GSUB lookups
of script `arab`, default language system:

  features    ccmp and locl before the forms; isol, init, medi, fina; rlig, calt,
              liga, clig and rclt after. Reachable includes lookups a contextual or
              chaining lookup names and lookups behind an extension.
  form price  the maximum over those faces of the form glyph's advance and the
              advance of every single substitution reachable from it. A direct
              single substitution of the form's feature replaces its input; a
              contextual one keeps it. A face without the form contributes its base
              glyph, which is what it renders.

LIGATURES ARE PRICED BY THE WIDEST READING, in a third section. Every ligature
substitution reachable in an Arabic face is traced back to the codepoint sequences
a text could spell it with. The trace runs from each letter through every glyph its
form closure holds, and from every other codepoint the face maps through every
reachable single substitution, and it flattens a ligature that consumes another
ligature. Each sequence keeps its base characters only, each with the positional
form its glyph appears in ('*' for a character that takes none): marks and ZWJ are
dropped, and both the precomposed and the canonically decomposed spelling are
kept. The form matters because a shaper runs ccmp and locl, then the positional
features, then the rest: DejaVu Sans composes YEH + HAMZA ABOVE in liga, which only
ever sees an isolated YEH, and a row keyed on YEH alone would price every medial
YEH at an isolated ligature. A row is the widest ligature over the column's faces,
closed over the single substitutions that can still apply after the lookup that
made it: all of them after ccmp or locl, its own positional feature and the later
features otherwise. A reading made of marks alone is
not a row: textfit.py prices those marks one by one, which holds only because such
a ligature advances nothing, closed over every substitution but the positional
features, which a shaper applies only to characters that join. textfit.py matches
the sequences skipping marks, ZWJ and the GDEF mark set below. It prices a line at its
widest reading, taking each match at max(its components, the ligature plus what the
ligature does not consume). A false match can only over-read.

A SHAPER SKIPS MARKS BY GLYPH CLASS, NOT BY UNICODE CATEGORY. An IgnoreMarks lookup skips
every glyph GDEF classes 3, and a face can class a Lo or Sk codepoint that way (Noto Sans
Arabic 2.005 classes U+FC5E-U+FC63 as marks). The fifth section lists every codepoint
whose glyph any Arabic face of any column, in either slot, classes 3; textfit.py's
ligature matcher skips them as well. Such a codepoint can also BE a component — a lookup
without IgnoreMarks consumes it, and Noto Sans Arabic 2.005's sequences hold U+FC5E-U+FC63
— so the matcher tries both readings where a row names it: skipped, and consumed. Joining
still follows Unicode.

GENERATION REFUSES, writing nothing, on:
  - fonts.tsv malformed; a file the generator prices that slot debian does not pin, or a
    row it does not price; a Debian source outside slot debian, or DejaVu outside it;
  - a slot whose page lacks a family some reader's stack names, or a reader drawing with a
    file the generator did not load;
  - a reader drawing an Arabic letter with a face that prices none of its positional forms;
  - a file whose sha256 differs from fonts.tsv, a Debian file owned by another package
    or installed at another version, or a fetched file without the URL its row names;
  - UnicodeData.txt, ArabicShaping.txt or CompositionExclusions.txt absent, or a Unicode
    version the text files and the unicode-data package do not agree on;
  - a feature in the arab default language system that is neither modelled nor off
    by default;
  - a required feature, or GSUB feature variations;
  - a reachable lookup type other than single, ligature, contextual, chaining or
    extension;
  - a reachable ligature lookup whose LookupFlag uses a mark filtering set or a mark
    attachment type, which the matcher's one skip set does not model;
  - a ligature consuming a glyph no codepoint and no ligature produces, a ligature
    chain that is circular or has more than 4096 readings, and a ligature a text
    can spell with marks alone that advances more than zero;
  - a letter whose joining type is T;
  - a non-letter in those blocks that textfit.py would join differently from
    ArabicShaping.txt;
  - an isolated form priced below its codepoint row;
  - U+200C or U+200D that some reader of a column draws with no face of its stack.
Every claim in the table header is written after the check it reports.

The serif column is this build's reading of the ruling for platform-views' 26
serif callouts, which the ruling's sans wording did not name; it applies the same
principle — the widest faces a reader can get for that family.
"""
import collections
import hashlib
import itertools
import math
import os
import re
import subprocess
import sys
from collections import defaultdict

from fontTools.ttLib import TTFont

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pins  # noqa: E402  the one reader of fonts.tsv
import readers  # noqa: E402  the one reader model
from textfit import CJK_BLOCKS  # noqa: E402  textfit prices these by rule and never reads their rows

FONTS_TSV = os.path.join(HERE, "fonts.tsv")
DEBIAN_FONTS = "/usr/share/fonts/truetype"
DEBIAN_SLOT = "debian"
UNICODE_DATA = "/usr/share/unicode/UnicodeData.txt"
ARABIC_SHAPING = "/usr/share/unicode/ArabicShaping.txt"
COMPOSITION_EXCLUSIONS = "/usr/share/unicode/CompositionExclusions.txt"
# Installed by gen_advances.sh beside the Debian font packages fonts.tsv names.
TOOL_PACKAGES = ("ca-certificates", "python3-fonttools", "unicode-data")

COLUMNS = {
    "sans400": ["dejavu/DejaVuSans.ttf", "noto/NotoSans-Regular.ttf"],
    "sans600": ["dejavu/DejaVuSans-Bold.ttf", "noto/NotoSans-Bold.ttf"],
    "mono": ["dejavu/DejaVuSansMono.ttf", "dejavu/DejaVuSansMono-Bold.ttf"],
    "serif": ["dejavu/DejaVuSerif.ttf", "dejavu/DejaVuSerif-Italic.ttf",
              "noto/NotoSerif-Regular.ttf", "noto/NotoSerif-Italic.ttf"],
}

ARABIC_FACES = ["noto/NotoSansArabic-Regular.ttf", "noto/NotoSansArabic-Bold.ttf"]
ARABIC_BLOCKS = [(0x0600, 0x06FF), (0x0750, 0x077F), (0x0870, 0x089F), (0x08A0, 0x08FF)]

# (header label, faces, blocks). Every entry prices its blocks in every column.
FALLBACKS = [
    ("script arabic", ARABIC_FACES, ARABIC_BLOCKS + [(0xFB50, 0xFDFF), (0xFE70, 0xFEFF)]),
    ("script thai", ["noto/NotoSansThai-Regular.ttf", "noto/NotoSansThai-Bold.ttf",
                     "noto/NotoLoopedThai-Regular.ttf", "noto/NotoLoopedThai-Bold.ttf"],
     [(0x0E00, 0x0E7F)]),
    ("script devanagari", ["noto/NotoSansDevanagari-Regular.ttf", "noto/NotoSansDevanagari-Bold.ttf"],
     [(0x0900, 0x097F), (0xA8E0, 0xA8FF)]),
    ("fallback math", ["noto/NotoSansMath-Regular.ttf"],
     [(0x2190, 0x21FF), (0x2200, 0x22FF), (0x2300, 0x23FF), (0x27C0, 0x27FF),
      (0x2900, 0x2AFF), (0x2B00, 0x2BFF)]),
]

FORMS = ("isol", "init", "medi", "fina")
PRE = ("ccmp", "locl")
POST = ("rlig", "calt", "liga", "clig", "rclt")
MODELLED = PRE + FORMS + POST
# Features no shaper applies unless asked. Anything else in the arab default
# language system may be on by default, and is refused unless modelled.
OFF_BY_DEFAULT = frozenset(
    "aalt afrc c2pc c2sc case cpsp cswh dlig expt falt fwid hist hkna hlig hngl hojo hwid ital "
    "jalt jp04 jp78 jp83 jp90 lnum nalt nlck onum ordn ornm palt pcap pkna pnum pwid qwid ruby "
    "salt sinf smcp smpl subs sups swsh titl tnam tnum trad twid unic vert vhal vkna vpal vrt2 "
    "zero".split()) | {"ss%02d" % i for i in range(1, 21)} | {"cv%02d" % i for i in range(1, 100)}
USES = {"D": ("init", "medi", "fina"), "C": ("init", "medi", "fina"), "R": ("fina",), "L": ("init",), "U": ()}
READING_LIMIT = 4096
ZWJ, ZWNJ = 0x200D, 0x200C
USE_MARK_FILTERING_SET, MARK_ATTACHMENT_TYPE = 0x0010, 0xFF00
GDEF_MARK = 3


def refuse(message):
    sys.exit("REFUSED: %s — nothing written" % message)


def units(em):
    return str(math.ceil(em * 10000 - 1e-9))


def in_blocks(cp, blocks):
    return any(lo <= cp <= hi for lo, hi in blocks)


in_domain = readers.in_domain


def ranges(cps):
    """Codepoints as compact hex ranges: `2190-21FF 2307`."""
    runs = []
    for cp in sorted(cps):
        if runs and cp == runs[-1][1] + 1:
            runs[-1][1] = cp
        else:
            runs.append([cp, cp])
    return " ".join("%04X" % a if a == b else "%04X-%04X" % (a, b) for a, b in runs) or "none"


def in_cjk(cp):
    return in_blocks(cp, CJK_BLOCKS)


def digest(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def dpkg_query(args):
    try:
        return subprocess.run(["dpkg-query"] + args, capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        refuse("dpkg-query %s failed: %s" % (" ".join(args), getattr(e, "stderr", "") or e))


def verified_pins(fetched):
    """([(pin, path)] in fonts.tsv order, {package: installed version}), every file checked
    against fonts.tsv before any byte of it is read as a font."""
    try:
        rows = pins.read_fonts(open(FONTS_TSV, encoding="utf-8").read())
    except (OSError, ValueError) as e:
        refuse("fonts.tsv: %s" % e)
    priced = {rel for files in COLUMNS.values() for rel in files} | \
             {rel for _, files, _ in FALLBACKS for rel in files}
    missing = sorted(priced - {p.file for p in rows if p.slot == DEBIAN_SLOT})
    if missing:
        refuse("slot %s does not pin %s, which the generator prices" % (DEBIAN_SLOT, ", ".join(missing)))
    unused = sorted({p.file for p in rows} - priced)
    if unused:
        refuse("fonts.tsv pins %s, which the generator does not price" % ", ".join(unused))

    checked, packages = [], {}
    for p in rows:
        debian = pins.DEBIAN_SOURCE.fullmatch(p.source)
        if (p.slot == DEBIAN_SLOT) != bool(debian):
            refuse("%s:%s takes its file from %s: slot %s, and only it, comes from Debian packages"
                   % (p.slot, p.file, p.source, DEBIAN_SLOT))
        if p.slot != DEBIAN_SLOT and p.file.startswith("dejavu/"):
            refuse("%s:%s: DejaVu comes from Debian only (ROADMAP O189)" % (p.slot, p.file))
        path = os.path.join(DEBIAN_FONTS, p.file) if debian else os.path.join(fetched, p.slot, p.file)
        if not os.path.isfile(path):
            sys.exit("PREMISE: %s:%s is not at %s — nothing written" % (p.slot, p.file, path))
        got = digest(path)
        if got != p.sha256:
            refuse("%s:%s at %s has sha256 %s, and fonts.tsv pins %s" % (p.slot, p.file, path, got, p.sha256))
        if debian:
            packages.setdefault(debian.group(1), set()).add(debian.group(2))
        checked.append((p, path, debian))

    for name, versions in packages.items():
        if len(versions) != 1:
            refuse("fonts.tsv names package %s at %s" % (name, " and ".join(sorted(versions))))
    names = sorted(set(packages) | set(TOOL_PACKAGES))
    installed = {}
    for line in dpkg_query(["-W", "-f=${Package} ${Version}\\n"] + names).split("\n"):
        if line.strip():
            name, version = line.split(" ", 1)
            installed[name] = version
    if sorted(installed) != names:
        refuse("dpkg-query reported %s for %s" % (sorted(installed), names))

    out = []
    for p, path, debian in checked:
        if debian:
            owners = set()
            for line in dpkg_query(["-S", path]).split("\n"):
                if line.endswith(": " + path):
                    owners.update(line[:-len(": " + path)].split(", "))
            if debian.group(1) not in owners:
                refuse("%s:%s names package %s, and dpkg says %s is owned by %s"
                       % (p.slot, p.file, debian.group(1), path, ", ".join(sorted(owners)) or "nothing"))
            if installed[debian.group(1)] != debian.group(2):
                refuse("%s:%s names %s=%s, and %s is installed"
                       % (p.slot, p.file, debian.group(1), debian.group(2), installed[debian.group(1)]))
        else:
            manifest = path + ".source"
            fetched_from = open(manifest, encoding="utf-8").read().strip() if os.path.isfile(manifest) else None
            if fetched_from != p.source:
                refuse("%s:%s was fetched from %s, and fonts.tsv names %s" % (p.slot, p.file, fetched_from, p.source))
        out.append((p, path))
    return out, installed


def first_line_version(path):
    stem = re.escape(os.path.basename(path)[:-len(".txt")])
    m = re.fullmatch(r"# %s-(\d+\.\d+\.\d+)\.txt" % stem, open(path, encoding="utf-8").readline().strip())
    return m.group(1) if m else None


class Unicode:
    """General categories, combining classes, canonical decompositions, composition
    exclusions and joining types, all from the one pinned Unicode version."""

    def __init__(self, package_version):
        for path in (UNICODE_DATA, ARABIC_SHAPING, COMPOSITION_EXCLUSIONS):
            if not os.path.exists(path):
                sys.exit("PREMISE: %s is not installed — nothing written" % path)
        declared = {os.path.basename(p): first_line_version(p) for p in (ARABIC_SHAPING, COMPOSITION_EXCLUSIONS)}
        declared["the unicode-data package"] = pins.upstream(package_version)
        if None in declared.values() or len(set(declared.values())) != 1:
            refuse("the Unicode versions disagree: %s" % ", ".join("%s %s" % kv for kv in sorted(declared.items())))
        self.version = declared["the unicode-data package"]
        self.gc, self.ccc, self.decomposition, self.ranges, first = {}, {}, {}, [], None
        for line in open(UNICODE_DATA, encoding="utf-8"):
            f = line.rstrip("\n").split(";")
            cp = int(f[0], 16)
            if f[1].endswith(", First>"):
                first = (cp, f[2])
            elif f[1].endswith(", Last>"):
                self.ranges.append((first[0], cp, first[1]))
            else:
                self.gc[cp] = f[2]
                self.ccc[cp] = int(f[3])
                if f[5] and not f[5].startswith("<"):
                    self.decomposition[cp] = [int(x, 16) for x in f[5].split()]
        self.joining = {}
        for line in open(ARABIC_SHAPING, encoding="utf-8"):
            fields = [x.strip() for x in line.split("#")[0].split(";")]
            if len(fields) >= 3:
                self.joining[int(fields[0], 16)] = fields[2]
        self.exclusions = set()
        for line in open(COMPOSITION_EXCLUSIONS, encoding="utf-8"):
            field = line.split("#")[0].strip()
            if field:
                lo, _, hi = field.partition("..")
                self.exclusions.update(range(int(lo, 16), int(hi or lo, 16) + 1))
        if not self.exclusions:
            refuse("%s lists no exclusion: it was not read" % COMPOSITION_EXCLUSIONS)
        self.provenance = "# unicode: %s" % ", ".join(
            "%s sha256=%s" % (os.path.basename(p), digest(p)) for p in (UNICODE_DATA, ARABIC_SHAPING,
                                                                     COMPOSITION_EXCLUSIONS))

    def category(self, cp):
        if cp in self.gc:
            return self.gc[cp]
        return next((c for lo, hi, c in self.ranges if lo <= cp <= hi), "Cn")

    def joining_type(self, cp):
        """ArabicShaping.txt's own rule for a codepoint it does not list."""
        return self.joining.get(cp) or ("T" if self.category(cp) in ("Mn", "Me", "Cf") else "U")

    def skippable(self, cp):
        return cp == ZWJ or self.category(cp) in ("Mn", "Me")

    def is_letter(self, cp):
        return in_blocks(cp, ARABIC_BLOCKS) and self.category(cp) in ("Lo", "Lm")

    def decompose(self, cp):
        """The full canonical decomposition of one codepoint."""
        if cp not in self.decomposition:
            return [cp]
        return [c for part in self.decomposition[cp] for c in self.decompose(part)]

    def spellings(self, cp):
        """The base-character tuples a text can spell this codepoint with: itself, and
        its full canonical decomposition, marks and ZWJ dropped. () for a mark."""
        out = set()
        if not self.skippable(cp):
            out.add((cp,))
        full = self.decompose(cp)
        if full != [cp] or not out:
            out.add(tuple(c for c in full if not self.skippable(c)))
        return out

    def compositions(self):
        """(base, mark, composite) for every primary composite: a two-codepoint canonical
        decomposition that is not excluded and does not start with, or decompose from, a
        non-starter. A singleton decomposes to one codepoint and never recomposes."""
        return sorted((parts[0], parts[1], cp) for cp, parts in self.decomposition.items()
                      if len(parts) == 2 and cp not in self.exclusions
                      and self.ccc.get(cp, 0) == 0 and self.ccc.get(parts[0], 0) == 0)


class Face:
    """One verified font file of one slot: its advances by codepoint and its provenance."""

    def __init__(self, pin, path):
        self.slot, self.rel = pin.slot, pin.file
        self.key = "%s:%s" % (pin.slot, pin.file)
        self.name = "%s:%s" % (pin.slot, os.path.basename(pin.file))
        self.font = TTFont(path)
        self.upm = self.font["head"].unitsPerEm
        self.hmtx = self.font["hmtx"].metrics
        self.cmap = self.font.getBestCmap()
        self.advances = {cp: self.hmtx[glyph][0] / self.upm for cp, glyph in self.cmap.items()}
        version = (self.font["name"].getDebugName(5) or "").split(";")[0].strip()
        self.desc = "%s %s upm=%d sha256=%s source=%s" % (pin.file, version, self.upm, pin.sha256, pin.source)
        self.shaping = None

    def em(self, glyph):
        return self.hmtx[glyph][0] / self.upm


def context_refs(kind, st):
    """The lookups a contextual (5) or chaining contextual (6) subtable names."""
    chain = "Chain" if kind == 6 else ""
    if st.Format == 1:
        sets = getattr(st, chain + "SubRuleSet") or []
        rules = [r for s in sets if s for r in (getattr(s, chain + "SubRule") or [])]
    elif st.Format == 2:
        sets = getattr(st, chain + "SubClassSet") or []
        rules = [r for s in sets if s for r in (getattr(s, chain + "SubClassRule") or [])]
    elif st.Format == 3:
        rules = [st]
    else:
        refuse("contextual lookup format %d is not modelled" % st.Format)
    return [rec.LookupListIndex for r in rules for rec in (r.SubstLookupRecord or [])]


class Shaping:
    """The GSUB lookups one face applies to Arabic, as far as pricing needs them."""

    def __init__(self, face):
        self.face = face
        if "GSUB" not in face.font:
            refuse("%s maps Arabic letters and has no GSUB table" % face.name)
        self.gsub = face.font["GSUB"].table
        if getattr(self.gsub, "FeatureVariations", None) is not None:
            refuse("%s carries GSUB feature variations, which are not modelled" % face.name)
        script = next((r.Script for r in self.gsub.ScriptList.ScriptRecord if r.ScriptTag == "arab"), None)
        if script is None or script.DefaultLangSys is None:
            refuse("%s maps Arabic letters and has no default language system for script arab" % face.name)
        langsys = script.DefaultLangSys
        if langsys.ReqFeatureIndex != 0xFFFF:
            refuse("%s declares a required feature, which is not modelled" % face.name)
        self.direct = {tag: [] for tag in MODELLED}
        for index in langsys.FeatureIndex:
            record = self.gsub.FeatureList.FeatureRecord[index]
            if record.FeatureTag in self.direct:
                self.direct[record.FeatureTag].extend(record.Feature.LookupListIndex)
            elif record.FeatureTag not in OFF_BY_DEFAULT:
                refuse("%s: feature %s is in the arab default language system, may be on by default, "
                       "and is not modelled" % (face.name, record.FeatureTag))
        self.parsed = {}
        self.everything = self.reach(MODELLED)      # parses all of it: an unmodelled type refuses here

    def lookup(self, index):
        """(single substitutions, ligatures, named lookups) of one lookup."""
        if index not in self.parsed:
            singles, ligatures, refs = {}, [], []
            lookup = self.gsub.LookupList.Lookup[index]
            for st in lookup.SubTable:
                kind = lookup.LookupType
                if kind == 7:
                    kind, st = st.ExtSubTable.LookupType, st.ExtSubTable
                if kind == 1:
                    for a, b in st.mapping.items():
                        singles.setdefault(a, set()).add(b)
                elif kind == 4:
                    if lookup.LookupFlag & (USE_MARK_FILTERING_SET | MARK_ATTACHMENT_TYPE):
                        refuse("%s: ligature lookup %d has LookupFlag 0x%04X, which uses a mark filtering set "
                               "or a mark attachment type: textfit.py's matcher skips marks by one set and "
                               "models neither" % (self.face.name, index, lookup.LookupFlag))
                    for first, group in st.ligatures.items():
                        for lig in group:
                            ligatures.append((lig.LigGlyph, [first] + list(lig.Component)))
                elif kind in (5, 6):
                    refs.extend(context_refs(kind, st))
                else:
                    refuse("%s: lookup %d is type %d, reachable from Arabic shaping and not modelled"
                           % (self.face.name, index, kind))
            self.parsed[index] = (singles, ligatures, refs)
        return self.parsed[index]

    def reach(self, tags):
        seen, todo = set(), [i for tag in tags for i in self.direct[tag]]
        while todo:
            index = todo.pop()
            if index not in seen:
                seen.add(index)
                todo.extend(self.lookup(index)[2])
        return sorted(seen)

    def closure(self, glyphs, lookups):
        out, todo = set(glyphs), list(glyphs)
        while todo:
            glyph = todo.pop()
            for index in lookups:
                for o in self.lookup(index)[0].get(glyph, ()):
                    if o not in out:
                        out.add(o)
                        todo.append(o)
        return out

    def forms(self, cp):
        """({form: price in em}, {forms this face has for the letter},
        {form: every glyph the letter can render as in that form})."""
        base = self.closure({self.face.cmap[cp]}, self.reach(PRE))
        prices, present, glyphs = {}, set(), {}
        for form in FORMS:
            own = self.reach((form,))
            if any(glyph in self.lookup(i)[0] for i in own for glyph in base):
                present.add(form)
            start = set()
            for glyph in base:
                replaced = set()
                for i in self.direct[form]:
                    replaced |= self.lookup(i)[0].get(glyph, set())
                start |= replaced or {glyph}
            glyphs[form] = self.closure(start, self.reach((form,) + PRE + POST))
            prices[form] = max(self.face.em(g) for g in glyphs[form])
        return prices, present, glyphs

    def after(self, index):
        """(lookups that can still apply to what lookup `index` outputs, the same
        without the positional features). A shaper runs ccmp and locl, then each
        positional feature, then the rest, so only a ccmp or locl output meets them all."""
        if index in self.reach(PRE):
            return self.everything, self.reach(PRE + POST)
        forms = tuple(f for f in FORMS if index in self.reach((f,)))
        return self.reach(forms + POST), self.reach(POST)

    def ligatures(self, unicode, letters):
        """[(lookup, ligature glyph, component glyphs, width in em, width without the
        positional features, {readings})] for every reachable ligature substitution.
        `letters` is {codepoint: {form: glyphs}} from forms(); a reading is a tuple of
        (base codepoint, the form its glyph appears in, or '*' for a character that
        takes no positional form)."""
        produced = defaultdict(set)
        for cp, glyph in self.face.cmap.items():
            if cp not in letters:
                spellings = unicode.spellings(cp)
                for g in self.closure({glyph}, self.everything):
                    produced[g] |= {tuple((c, "*") for c in sp) for sp in spellings}
        for cp, forms in letters.items():          # includes letters this face renders decomposed
            spellings = unicode.spellings(cp)
            for form, glyphs in forms.items():
                for g in glyphs:
                    produced[g] |= {tuple((c, form) for c in sp) for sp in spellings}
        found = [(index, lig, comps) for index in self.everything for lig, comps in self.lookup(index)[1]]
        made = defaultdict(list)
        for index, lig, comps in found:
            for g in self.closure({lig}, self.after(index)[0]):
                made[g].append(comps)
        memo, active = {}, set()

        def readings(glyph):
            if glyph in memo:
                return memo[glyph]
            if glyph in active:
                refuse("%s: the ligature chain through %s is circular and cannot be flattened"
                       % (self.face.name, glyph))
            active.add(glyph)
            out = set(produced.get(glyph, ()))
            for comps in made.get(glyph, ()):
                parts = [readings(c) for c in comps]
                if all(parts):
                    if math.prod(len(p) for p in parts) > READING_LIMIT:
                        refuse("%s: the ligature chain through %s has more than %d readings"
                               % (self.face.name, glyph, READING_LIMIT))
                    out |= {tuple(cp for part in combo for cp in part) for combo in itertools.product(*parts)}
            active.discard(glyph)
            memo[glyph] = out
            return out

        result = []
        for index, lig, comps in found:
            for c in comps:
                if not readings(c):
                    refuse("%s lookup %d: ligature %s consumes %s, which no codepoint and no ligature produces"
                           % (self.face.name, index, lig, c))
            later, unpositioned = self.after(index)
            width = max(self.face.em(g) for g in self.closure({lig}, later))
            # A mark joins nothing, so no positional feature ever applies to a ligature of marks.
            bare = max(self.face.em(g) for g in self.closure({lig}, unpositioned))
            result.append((index, lig, comps, width, bare, readings(lig)))
        return result


def build(fetched):
    problems = []
    checked, installed = verified_pins(fetched)
    unicode = Unicode(installed["unicode-data"])
    header = ["# Undercroft text-fit advance table. GENERATED by textfit/gen_advances.sh — do not edit.",
              "# ROADMAP O189. Unit: 1/10000 em, rounded up. Each column is the maximum over its faces in every slot.",
              "# Five sections, each after its own column header:",
              "#   cp        one row per codepoint; '-' where some reader draws it with no face of its stack",
              "#             (readers.py; textfit.py fails closed).",
              "#   arabic    four rows per Arabic letter: its ArabicShaping.txt joining type and, per positional",
              "#             form, the widest form glyph or reachable single substitution over the Arabic faces;",
              "#             '-' in a column where some reader draws the letter with no face of its stack.",
              "#   ligature  one row per base-character sequence an Arabic ligature can spell: the widest",
              "#             ligature over the column's faces; '-' where none of them forms it.",
              "#   compose   one row per canonical composition pair whose composite has a row: base, mark,",
              "#             composite (textfit.py refuses a line holding one outside Arabic).",
              "#   gdefmark  one row per codepoint an Arabic face classes as a mark (textfit.py's ligature",
              "#             matcher skips it).",
              "# See gen_advances.py for the rules, fonts.tsv for the slots and textfit.py for how each section is read."]
    header += ["# package: %s %s" % (name, installed[name]) for name in sorted(installed)]
    header.append("# unicode-version: %s" % unicode.version)
    header.append(unicode.provenance)

    faces, by_rel = [], defaultdict(list)
    for pin, path in checked:
        f = Face(pin, path)
        faces.append(f)
        by_rel[pin.file].append(f)
    header += ["# slot %s: %s" % (f.slot, f.desc) for f in faces]
    columns = {}
    for name, files in COLUMNS.items():
        columns[name] = [f for rel in files for f in by_rel[rel]]
        header.append("# column %s: %s" % (name, " ".join(f.key for f in columns[name])))
    fallbacks = []
    for label, files, blocks in FALLBACKS:
        fs = [f for rel in files for f in by_rel[rel]]
        header.append("# %s (every column, blocks %s): %s" % (
            label, " ".join("%04X-%04X" % b for b in blocks), " ".join(f.key for f in fs)))
        fallbacks.append((fs, blocks))
    arabic_faces = [f for rel in ARABIC_FACES for f in by_rel[rel]]

    def rendered(f, cp):
        """What face f renders cp as, in em: its own glyph, or where it has none, the full
        canonical decomposition, which a shaper tries before it falls back to another face."""
        if cp in f.advances:
            return f.advances[cp]
        parts = unicode.decompose(cp)
        if len(parts) > 1 and all(p in f.advances for p in parts):
            return sum(f.advances[p] for p in parts)
        return None

    # ------------------------------------------------------------ the reader model
    # readers.py: every slot's page, every stack variant, every style a column renders in.
    face_by_key = {f.key: f for f in faces}
    pinned = [pin for pin, _ in checked]
    slots = []
    for pin in pinned:
        if pin.slot not in slots:
            slots.append(pin.slot)
    stacks = {name: [] for name in COLUMNS}
    for slot in slots:
        page = readers.page_pins(slot, pinned)
        for name in COLUMNS:
            try:
                for label, keys in readers.column_readers(page, name):
                    unpriced = [k for k in keys if k not in face_by_key]
                    if unpriced:
                        refuse("slot %s reader %s draws with %s, which the generator does not load"
                               % (slot, label, ", ".join(unpriced)))
                    stacks[name].append(("%s %s" % (slot, label), keys))
            except ValueError as e:
                refuse("slot %s cannot model every reader of column %s: %s" % (slot, name, e))
    for name in COLUMNS:
        header += ["# reader %s %s: %s" % (name, label, " ".join(keys)) for label, keys in stacks[name]]
    maps = readers.mapper(lambda key, cp: cp in face_by_key[key].advances, unicode.decomposition.get)

    def drawn(name, cp):
        """[(reader label, face key or None)]: the face every reader of a column draws cp with."""
        return [(label, readers.first_mapper(keys, cp, maps)) for label, keys in stacks[name]]

    stack_faces = [face_by_key[k] for k in sorted({k for name in COLUMNS for _, keys in stacks[name] for k in keys})]
    codepoints = {ZWNJ, ZWJ}
    for fs in columns.values():
        for f in fs:
            codepoints.update(f.advances)
    for fs, blocks in fallbacks:
        for f in fs:
            codepoints.update(cp for cp in f.advances if in_blocks(cp, blocks))
    for f in stack_faces:                       # a cell a stack face prices can be added
        codepoints.update(f.advances)
    decomposed = set()
    for cp in unicode.decomposition:
        for fs, blocks in [(fs, None) for fs in columns.values()] + fallbacks + [(stack_faces, None)]:
            if (blocks is None or in_blocks(cp, blocks)) and \
                    any(cp not in f.advances and rendered(f, cp) is not None for f in fs):
                decomposed.add(cp)
    codepoints |= decomposed
    codepoints = sorted(cp for cp in codepoints if in_domain(cp))
    header.append("# decomposition: %d codepoints are also priced as the canonical decomposition "
                  "that a face lacking them renders" % sum(1 for cp in decomposed if cp in codepoints))

    # Each cell: '-' where some reader draws the codepoint with no face of its stack; otherwise the
    # maximum over the column's faces, the in-block script and fallback faces, and every reader's
    # first mapper. `previous` is the rule before the ruling, computed here for the header only.
    rows, base, filled, previous = [], {}, [], {}
    moved = {name: {"withdrawn": [], "added": [], "raised": [], "lacking": collections.Counter()}
             for name in COLUMNS}
    for cp in codepoints:
        row, old = [], []
        for name in COLUMNS:
            ems = [e for e in (rendered(f, cp) for f in columns[name]) if e is not None]
            for fs, blocks in fallbacks:
                if in_blocks(cp, blocks):
                    ems += [e for e in (rendered(f, cp) for f in fs) if e is not None]
            old.append("-" if not ems else units(max(ems)))
            readers_ = drawn(name, cp)
            lacking = [label for label, key in readers_ if key is None]
            if lacking:
                row.append("-")
                if not in_cjk(cp):
                    moved[name]["lacking"].update(lacking)
            else:
                row.append(units(max(ems + [rendered(face_by_key[key], cp) for _, key in readers_])))
        if cp in (ZWNJ, ZWJ):
            # The previous rule drew a joiner a column's own faces do not map with the widest script or
            # fallback face that maps it. It is kept where it is wider than every first mapper.
            fill = [f.advances[cp] for fs, _ in fallbacks for f in fs if cp in f.advances]
            for i, name in enumerate(COLUMNS):
                own = [f for f in columns[name] if rendered(f, cp) is not None]
                if old[i] == "-" and fill:
                    old[i] = units(max(fill))
                if row[i] != "-" and not own and fill and int(units(max(fill))) > int(row[i]):
                    row[i] = units(max(fill))
                    filled.append("%s U+%04X" % (name, cp))
            missing = [name for name, v in zip(COLUMNS, row) if v == "-"]
            if missing:
                problems.append("U+%04X: some reader of column %s draws it with no face of its stack: %s"
                                % (cp, ", ".join(missing), "; ".join(label for name in missing
                                                                    for label, key in drawn(name, cp) if key is None)))
        for i, name in enumerate(COLUMNS):
            if old[i] != "-" and row[i] == "-":
                moved[name]["withdrawn"].append(cp)
            elif old[i] == "-" and row[i] != "-":
                moved[name]["added"].append(cp)
            elif old[i] != "-" and int(row[i]) > int(old[i]):
                moved[name]["raised"].append(cp)
        previous[cp] = old
        if any(v != "-" for v in row):
            rows.append("%04X\t%s" % (cp, "\t".join(row)))
            base[cp] = row
    header.append("# joiners: U+200C and U+200D are priced in every column at every reader's first mapper; where a "
                  "column's own faces map neither, the previous rule's widest script or fallback face is kept where "
                  "it is wider: %s" % (", ".join(filled) or "it is wider nowhere"))
    for name in COLUMNS:
        m = moved[name]
        for kind in ("withdrawn", "added", "raised"):
            text = [cp for cp in m[kind] if not in_cjk(cp)]
            cjk = [cp for cp in m[kind] if in_cjk(cp)]
            header.append("# %s %s: %d cells against the previous rule: %s%s" % (
                kind, name, len(text), ranges(text),
                "; and %d in CJK_BLOCKS, which textfit prices by rule and never reads: %s" % (len(cjk), ranges(cjk))
                if cjk else ""))
        header.append("# lacking %s, readers drawing a withdrawn or unpriced cell outside CJK_BLOCKS with no face: %s"
                      % (name, ", ".join("%s %d" % kv for kv in sorted(m["lacking"].items())) or "none"))

    # ----------------------------------------------------- Arabic positional forms
    arabic, shaped = {}, []
    for name in COLUMNS:
        fs = []
        for f in columns[name] + arabic_faces:
            if f not in fs and any(unicode.is_letter(cp) for cp in f.cmap):
                fs.append(f)
        arabic[name] = fs
        header.append("# arabic faces %s: %s" % (name, " ".join(f.name for f in fs)))
        for f in fs:
            if f.shaping is None:
                f.shaping = Shaping(f)
                shaped.append(f)

    for cp, want in ((ZWJ, "C"), (ZWNJ, "U")):
        if unicode.joining_type(cp) != want:
            problems.append("U+%04X: textfit.py treats it as %s, ArabicShaping.txt says %s"
                            % (cp, want, unicode.joining_type(cp)))
    for cp in sorted({cp for f in shaped for cp in f.cmap if in_blocks(cp, ARABIC_BLOCKS)}):
        if unicode.is_letter(cp):
            continue
        category = unicode.category(cp)
        if category == "Cf":
            continue                   # textfit.py refuses to price it beside an Arabic letter
        modelled = "T" if category in ("Mn", "Me") else "U"
        if modelled != unicode.joining_type(cp):
            problems.append("U+%04X: textfit.py treats it as %s, ArabicShaping.txt says %s"
                            % (cp, modelled, unicode.joining_type(cp)))

    def decomposed_letter(f, cp):
        """The parts of a letter face f lacks but renders decomposed: a letter it maps
        followed by marks it maps. None otherwise."""
        parts = unicode.decompose(cp)
        if cp in f.cmap or len(parts) < 2 or parts[0] not in f.cmap or not unicode.is_letter(parts[0]) \
                or not all(p in f.cmap and unicode.skippable(p) for p in parts[1:]):
            return None
        return parts

    def letter_forms(f, cp):
        if cp in f.cmap:
            return f.shaping.forms(cp)
        parts = decomposed_letter(f, cp)
        prices, present, glyphs = f.shaping.forms(parts[0])
        marks = sum(max(f.em(g) for g in f.shaping.closure({f.cmap[m]}, f.shaping.reach(PRE + POST)))
                    for m in parts[1:])
        return {form: price + marks for form, price in prices.items()}, present, glyphs

    letters = sorted({cp for f in shaped for cp in f.cmap if unicode.is_letter(cp)}
                     | {cp for cp in unicode.decomposition if unicode.is_letter(cp)
                        and any(decomposed_letter(f, cp) for f in shaped)})
    memo, form_rows, unused = {}, [], []
    forms_withdrawn = {name: [] for name in COLUMNS}
    for cp in letters:
        joining = unicode.joining_type(cp)
        if joining not in USES:
            problems.append("U+%04X is a letter with joining type %s, which is not modelled" % (cp, joining))
            continue
        present, prices = set(), {}
        for name, fs in arabic.items():
            for f in fs:
                if cp not in f.cmap and not decomposed_letter(f, cp):
                    continue
                if (f.key, cp) not in memo:
                    memo[(f.key, cp)] = letter_forms(f, cp)
                face_prices, face_present, _ = memo[(f.key, cp)]
                present |= face_present
                for form in FORMS:
                    prices[(name, form)] = max(prices.get((name, form), 0.0), face_prices[form])
        missing = [form for form in USES[joining] if form not in present]
        if missing:
            unused.append("U+%04X %s" % (cp, "/".join(missing)))
        # The reader rule, on the cells textfit actually reads for a letter: where some reader of a
        # column draws the letter with no face of its stack, all four of its form cells there are '-'.
        # Where every reader draws it, the face each draws with must be one this section priced.
        blank = set()
        for name in COLUMNS:
            readers_ = drawn(name, cp)
            if any(key is None for _, key in readers_):
                blank.add(name)
                if any((name, form) in prices for form in FORMS):
                    forms_withdrawn[name].append(cp)
                continue
            priced = {f.key for f in arabic[name]}
            stray = sorted({key for _, key in readers_ if key not in priced})
            if stray:
                problems.append("U+%04X: a reader of column %s draws it with %s, which prices none of its "
                                "positional forms" % (cp, name, ", ".join(stray)))
        for form in FORMS:
            cells = ["-" if name in blank or (name, form) not in prices else units(prices[(name, form)])
                     for name in COLUMNS]
            form_rows.append("%04X\t%s\t%s\t%s" % (cp, joining, form, "\t".join(cells)))
            if form == "isol":
                for name, cell, row in zip(COLUMNS, cells, base.get(cp, ["-"] * len(COLUMNS))):
                    if row != "-" and (cell == "-" or int(cell) < int(row)):
                        problems.append("U+%04X: isolated form %s prices below the codepoint row %s in %s"
                                        % (cp, cell, row, name))
    header.append("# arabic letters: %d, joining types from ArabicShaping.txt; %d join in a form no Arabic "
                  "face carries, priced at the base glyph there: %s"
                  % (len(letters), len(unused), ", ".join(unused) or "none"))
    for name in COLUMNS:
        header.append("# withdrawn arabic forms %s: %d letters whose four form cells are '-' because some reader "
                      "draws the letter with no face: %s" % (name, len(forms_withdrawn[name]),
                                                             ranges(forms_withdrawn[name])))

    # ----------------------------------------------------------------- ligatures
    widest, traced, wider = defaultdict(dict), 0, 0
    for f in shaped:
        f.traced = f.shaping.ligatures(unicode, {cp: memo[(f.key, cp)][2] for cp in letters
                                                 if (f.key, cp) in memo})
        traced += len(f.traced)
        for index, lig, comps, width, bare, tuples in f.traced:
            if f.hmtx[lig][0] > sum(f.hmtx[c][0] for c in comps):
                wider += 1
            if () in tuples and bare > 0:
                problems.append("%s lookup %d: ligature %s can be spelled by marks alone and advances %.4f em"
                                % (f.name, index, lig, bare))
    for name, fs in arabic.items():
        for f in fs:
            for index, lig, comps, width, bare, tuples in f.traced:
                for t in tuples:
                    if t:
                        widest[t][name] = max(widest[t].get(name, 0.0), width)
    lig_rows = ["%s\t%s" % (" ".join("%04X:%s" % element for element in t),
                            "\t".join(units(widest[t][name]) if name in widest[t] else "-" for name in COLUMNS))
                for t in sorted(widest)]
    header.append("# ligatures: %d substitutions in the Arabic faces, traced to %d sequences of base characters "
                  "and forms; %d are wider than the glyphs they replace" % (traced, len(lig_rows), wider))

    # ------------------------------------------------------------- compositions
    comp_rows = ["%04X\t%04X\t%04X" % t for t in unicode.compositions() if t[2] in base]
    header.append("# compositions: %d canonical pairs whose composite has a row, from UnicodeData.txt less "
                  "CompositionExclusions.txt, singletons and non-starter decompositions" % len(comp_rows))

    # ---------------------------------------------------------------- GDEF marks
    marks = set()
    for f in shaped:
        gdef = f.font["GDEF"].table if "GDEF" in f.font else None
        classes = gdef.GlyphClassDef.classDefs if gdef is not None and gdef.GlyphClassDef else {}
        marks |= {cp for cp, glyph in f.cmap.items() if classes.get(glyph) == GDEF_MARK and in_domain(cp)}
    beyond = sorted(cp for cp in marks if not unicode.skippable(cp))
    mark_rows = ["%04X" % cp for cp in sorted(marks)]
    header.append("# gdef marks: %d codepoints whose glyph an Arabic face of any column and slot classes as a mark "
                  "(GDEF class 3); %d are not Mn or Me: %s"
                  % (len(marks), len(beyond), " ".join("U+%04X" % cp for cp in beyond) or "none"))
    return header, rows, form_rows, lig_rows, comp_rows, mark_rows, problems


def main(argv):
    if len(argv) != 1:
        sys.exit("PREMISE: give the directory gen_advances.sh fetched the other slots into — nothing written")
    header, rows, form_rows, lig_rows, comp_rows, mark_rows, problems = build(argv[0])
    if problems:
        for p in problems:
            print("  - %s" % p, file=sys.stderr)
        refuse("%d problem(s) above" % len(problems))
    print("\n".join(header))
    print("cp\t" + "\t".join(COLUMNS))
    print("\n".join(rows))
    print("arabic\tjoining\tform\t" + "\t".join(COLUMNS))
    print("\n".join(form_rows))
    print("ligature\t" + "\t".join(COLUMNS))
    if lig_rows:
        print("\n".join(lig_rows))
    print("compose\tmark\tcomposite")
    if comp_rows:
        print("\n".join(comp_rows))
    print("gdefmark")
    if mark_rows:
        print("\n".join(mark_rows))


if __name__ == "__main__":
    main(sys.argv[1:])
