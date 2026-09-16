"""The calibration harness's shared rules, each stated once (ROADMAP O189, V3 and panel 2).

Every Python step of the harness runs with `architecture/` read-only at /a and the run folder
at /r, and imports this module for the decisions more than one step makes: which files a page
embeds, how a file becomes an @font-face alias, which stack a pass names, how the CJK exception
is identified, how a font CDP reports is classified, which faces a render is predicted to use,
and which codepoints a face maps. The fetch step builds a page from these rules and both judges
check a page against the SAME rules, so the two cannot disagree about what a page should hold.

THE READER MODEL IS NOT DEFINED HERE. `architecture/textfit/readers.py` is the one model
gen_advances.py prices the table from: which files a page holds (`page_pins`), the four stack
variants, the face a style selects inside a family, and the first face that maps a codepoint.
This module takes the stacks, the page rule and the file-name rule from it, and only adds what
calibration alone needs: the @font-face alias, the declared CJK family at the end of every
stack, and the prediction a judge compares with CDP.

A PAGE is one slot of fonts.tsv rendered alone, because CDP reports a font's PostScript name
and no version: two slots on one page could not be told apart. The canary page is the newest
upstream Noto release, with DejaVu again from debian.

PREDICTED FACES (the judges' `faces` arm). A row's text is cut into clusters: a base character
and the marks (Mn, Mc, Me) that follow it; a joiner (U+200C, U+200D) joins the cluster only right
after a virama (canonical combining class 9), and otherwise is a cluster of its own. A cluster
draws from the first face of the reader's stack that maps every codepoint of it that is not
default-ignorable, with readers.py's decomposition rule, so a cluster of joiners alone draws from
the stack's first face whether or not that face maps a joiner. A cluster whose base is in
textfit's CJK blocks and that no stack face maps draws from the declared CJK face for its weight
(Regular below 600, Bold otherwise). Any other cluster no face maps is predicted as NO_FACE, which
no CDP row can report. CDP names a face by PostScript name, so a reported font is compared as
embedded only when CDP says it is a web font, and as the declared CJK face only when it is not; a
platform font is compared under a name no prediction carries.

The model is DECLARED, not observed (ROADMAP O195); `faces` is how a run observes where it is
wrong, and two of its rules came from that observation in run v3d (2026-09-16), each matching every
row that showed it and changing no prediction elsewhere:
  - joiners: the first model put every joiner in the preceding cluster. A ZWJ after an Arabic
    letter the stack's first face does not map, or after such a letter and its hamza or madda, was
    reported on that first face as well as on Noto Sans Arabic (DejaVu Sans, DejaVu Serif, DejaVu
    Sans Mono, which maps no joiner, Noto Sans, Noto Serif): 4,036 fixture rows over both gating
    pages, every row of that shape. A ZWJ after a Devanagari virama was reported on Noto Sans
    Devanagari alone, in all 740 rows. Whether the virama or the script decides this is not settled
    by those rows: every observed joiner after a virama was Devanagari, and no Arabic one was.
  - CJK: the first model sent every CJK-block cluster to the declared CJK face. CJK-block codepoints
    Noto Sans Math maps were reported on Noto Sans Math, which the stack names before the CJK family.
"""
import collections
import hashlib
import json
import os
import sys
import unicodedata

TREE = os.environ.get("CAL_TREE", "/a")
RUN = os.environ.get("CAL_RUN", "/r")
TEXTFIT = os.path.join(TREE, "textfit")
CALIBRATE = os.path.join(TEXTFIT, "calibrate")
sys.path.insert(0, TEXTFIT)
sys.path.insert(0, CALIBRATE)
import pins  # noqa: E402  the one reader of fonts.tsv
import readers  # noqa: E402  the one reader model
import sfnt  # noqa: E402
import textfit as tf  # noqa: E402

DEBIAN = readers.DEBIAN
CANARY = readers.CANARY
GENERICS = readers.GENERICS
SIZE = 11
TOLERANCE = 0.05
# The per-character bound on a CJK advance rendered with font-kerning:none. The PRICE of a CJK
# character is textfit.CJK_EM; this is what a face's own advance may be.
CJK_ADVANCE_EM = 1.0
CANARY_MANIFEST = os.path.join(RUN, "fonts", CANARY, "manifest.tsv")
CJK_FONT_DATA = os.path.join(RUN, "platform", "cjk-font-data.json")
NO_FACE = "(no face)"
ZWNJ, ZWJ = 0x200C, 0x200D

# Default_Ignorable_Code_Point, from DerivedCoreProperties-15.0.0.txt of the pinned unicode-data
# package (the Unicode version textfit asserts). A shaper hides these; no face need map them.
DEFAULT_IGNORABLE = ((0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
                     (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
                     (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
                     (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
                     (0xE0000, 0xE0FFF))

CjkFace = collections.namedtuple("CjkFace", "family psname collection sha256")


def refuse(message, code=1):
    print("REFUSED: %s" % message)
    sys.exit(code)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_fonts_tsv():
    with open(os.path.join(TEXTFIT, "fonts.tsv"), encoding="utf-8") as fh:
        return pins.read_fonts(fh.read())


def read_canary():
    """(tag, [Pin]) from the canary manifest, or (None, []) when no canary was fetched."""
    if not os.path.isfile(CANARY_MANIFEST):
        return None, []
    with open(CANARY_MANIFEST, encoding="utf-8") as fh:
        text = fh.read()
    tags = [line.split(":", 1)[1].strip() for line in text.split("\n") if line.startswith("# tag:")]
    if len(tags) != 1:
        raise ValueError("%s declares %d tags, expected one" % (CANARY_MANIFEST, len(tags)))
    rows = pins.read_fonts(text)
    if {p.slot for p in rows} != {CANARY}:
        raise ValueError("%s holds a row outside slot %s" % (CANARY_MANIFEST, CANARY))
    return tags[0], rows


def page_ids(rows, canary_rows):
    out = []
    for p in rows:
        if p.slot not in out:
            out.append(p.slot)
    if DEBIAN not in out:
        raise ValueError("fonts.tsv has no %s slot" % DEBIAN)
    return out + ([CANARY] if canary_rows else [])


def gating_pages(rows):
    """Every slot of fonts.tsv: the pages the table is priced from and a calibration gates on."""
    return page_ids(rows, [])


page_pins = readers.page_pins
group_of = readers.group_of


def fetched_path(pin):
    """Where the fetch step put a row's file, under the run folder."""
    return os.path.join(RUN, "fonts", pin.slot, pin.file)


def alias(page, group):
    return "uc-%s-%s" % (page, group)


def stacks(page, groups, cjk_family):
    """{variant: {generic: [family, ...]}} for every variant every group of which the page holds,
    each stack readers.py's, as aliases, then the declared CJK family."""
    out, missing = {}, {}
    for variant, (primary, _) in readers.VARIANTS.items():
        lacking, roles, resolved = [], [], {}
        for generic in GENERICS:
            names, short = readers.stack_groups(groups, variant, generic)
            lacking += [s for s in short if s == readers.PRIMARY[primary][generic]]
            roles += [s for s in short if s != readers.PRIMARY[primary][generic] and s not in roles]
            resolved[generic] = names
        lacking += roles
        if lacking:
            missing[variant] = lacking
            continue
        out[variant] = {generic: [alias(page, g) for g in resolved[generic]] + [cjk_family] for generic in GENERICS}
    return out, missing


def read_cjk():
    path = os.path.join(CALIBRATE, "cjk.tsv")
    rows, header = [], False
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh.read().split("\n"), 1):
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if not header:
                if tuple(parts) != CjkFace._fields:
                    raise ValueError("cjk.tsv line %d: expected the header %s" % (n, "\\t".join(CjkFace._fields)))
                header = True
                continue
            if len(parts) != 4 or not pins.SHA256.fullmatch(parts[3]):
                raise ValueError("cjk.tsv line %d is malformed" % n)
            rows.append(CjkFace(*parts))
    if not rows or len({r.family for r in rows}) != 1 or len({r.psname for r in rows}) != len(rows):
        raise ValueError("cjk.tsv must declare one family over distinct PostScript names")
    return rows


def cjk_by_weight(cjk):
    """{400: psname, 700: psname}: the declared CJK face a weight selects, by the PostScript name's
    suffix and readers.SUFFIX. Raises ValueError unless exactly one upright Regular and one Bold."""
    out = {}
    for face in cjk:
        _, weight, style = readers.group_of(face.psname)
        if style != "normal" or weight in out:
            raise ValueError("cjk.tsv: %s is not one upright face per weight" % face.psname)
        out[weight] = face.psname
    if set(out) != {400, 700}:
        raise ValueError("cjk.tsv declares weights %s, expected 400 and 700" % sorted(out))
    return out


def is_cjk(cp):
    return any(lo <= cp <= hi for lo, hi in tf.CJK_BLOCKS)


def cjk_count(text):
    return sum(1 for ch in text if is_cjk(ord(ch)))


def is_default_ignorable(cp):
    return any(lo <= cp <= hi for lo, hi in DEFAULT_IGNORABLE)


def read_tsv(path, fields):
    """Rows of a tab-separated file this harness wrote, as dicts; the first line is the header."""
    with open(path, encoding="utf-8") as fh:
        lines = [l for l in fh.read().split("\n") if l]
    if not lines or tuple(lines[0].split("\t")) != tuple(fields):
        raise ValueError("%s: expected the header %s" % (path, "\\t".join(fields)))
    out = []
    for n, line in enumerate(lines[1:], 2):
        parts = line.split("\t")
        if len(parts) != len(fields):
            raise ValueError("%s line %d: %d fields, expected %d" % (path, n, len(parts), len(fields)))
        out.append(dict(zip(fields, parts)))
    return out


EMBEDDED_FIELDS = ("page", "key", "alias", "weight", "style", "psname", "sha256", "bytes")
FC_FIELDS = ("psname", "index", "family", "style", "file", "sha256")


def identity(page, expected, embedded):
    """(failures, {psname: (key, sha256)}) for one page.

    `expected` is page_pins(); `embedded` the rows the renderer wrote, each sha256 taken from
    the bytes it embedded. Both directions: every expected file embedded once with its pinned
    digest, and nothing embedded that is not expected. PostScript names must be distinct on a
    page, or a CDP row could not name its file."""
    failures = []
    want = {"%s:%s" % (p.slot, p.file): p.sha256 for p in expected}
    got = collections.defaultdict(list)
    for r in embedded:
        if r["page"] == page:
            got[r["key"]].append(r)
    for key in sorted(set(want) - set(got)):
        failures.append(("identity", "page %s: %s is pinned and was not embedded" % (page, key)))
    for key in sorted(set(got) - set(want)):
        failures.append(("identity", "page %s: %s was embedded and is not pinned for this page" % (page, key)))
    psmap = {}
    for key in sorted(set(got) & set(want)):
        rows = got[key]
        if len(rows) != 1:
            failures.append(("identity", "page %s: %s embedded %d times" % (page, key, len(rows))))
            continue
        r = rows[0]
        if r["sha256"] != want[key]:
            failures.append(("identity", "page %s: %s embedded with sha256 %s, pinned %s"
                             % (page, key, r["sha256"], want[key])))
        if r["psname"] in psmap:
            failures.append(("identity", "page %s: PostScript name %s names two files, %s and %s"
                             % (page, r["psname"], psmap[r["psname"]][0], key)))
        psmap[r["psname"]] = (key, r["sha256"])
    return failures, psmap


def cjk_pairs(cjk, fc_rows):
    """(failures, {psname: sha256}): each declared CJK face, found in the render image's fc-list
    exactly once, in the declared collection, with the declared digest."""
    failures, pairs = [], {}
    for face in cjk:
        hits = [r for r in fc_rows if r["psname"] == face.psname]
        if len(hits) != 1:
            failures.append(("cjk-identity", "fc-list reports %s %d times, expected once" % (face.psname, len(hits))))
            continue
        hit = hits[0]
        if os.path.basename(hit["file"]) != face.collection or hit["sha256"] != face.sha256:
            failures.append(("cjk-identity", "%s is in %s sha256 %s; cjk.tsv declares %s sha256 %s"
                             % (face.psname, hit["file"], hit["sha256"], face.collection, face.sha256)))
            continue
        pairs[face.psname] = hit["sha256"]
    return failures, pairs


def classify(font, psmap, pairs):
    """'embedded', 'cjk', or None for a font outside both — a platform font or an unknown web font."""
    if font["custom"]:
        return "embedded" if font["ps"] in psmap else None
    return "cjk" if font["ps"] in pairs else None


def cjk_foreign(fonts, text, pairs):
    """Glyphs the declared CJK faces drew in a row beyond the row's CJK codepoints (0 when none)."""
    drawn = sum(f["glyphs"] for f in fonts if not f["custom"] and f["ps"] in pairs)
    return max(0, drawn - cjk_count(text))


def category(ch):
    return unicodedata.category(ch)


# ------------------------------------------------------------ cmaps from font bytes
class Cmaps:
    """The codepoints each face of one page maps, read with sfnt.py from the run folder's own
    files. Each file's sha256 is checked against its pin before a byte of it is parsed; a CJK
    face is selected inside its collection by PostScript name. `drop` removes codepoints from a
    face's set, for a judge's planted copy only."""

    def __init__(self, pins_, cjk):
        self.files = {readers.face_key(p): (fetched_path(p), p.sha256, None) for p in pins_}
        self.cjk = {f.psname: (os.path.join(RUN, "platform", "cjk", f.collection), f.sha256, f.psname) for f in cjk}
        self.memo = {}
        self.drop = {}

    def _load(self, source):
        path, sha, psname = source
        if source not in self.memo:
            data = open(path, "rb").read()
            if sha256_bytes(data) != sha:
                raise ValueError("%s has sha256 %s, pinned %s" % (path, sha256_bytes(data), sha))
            offsets = sfnt.faces(data)
            if psname is not None:
                offsets = [o for o in offsets if sfnt.ps_name(data, o) == psname]
            if len(offsets) != 1:
                raise ValueError("%s holds %s %d times" % (path, psname or "a face", len(offsets)))
            self.memo[source] = frozenset(sfnt.codepoints(data, offsets[0]))
        return self.memo[source]

    def key(self, key):
        return self._load(self.files[key]) - self.drop.get(key, frozenset())

    def font(self, font, psmap):
        """The set for a font CDP reports, or None when the judge cannot read it. A web font is read as
        the embedded file its PostScript name maps to; a font that is not a web font only as a declared
        CJK face. A platform font can share a PostScript name with an embedded file (the render image
        carries its own DejaVu Sans) and is never read as that file."""
        if font["custom"]:
            return self.key(psmap[font["ps"]][0]) if font["ps"] in psmap else None
        if font["ps"] in self.cjk:
            return self._load(self.cjk[font["ps"]]) - self.drop.get(font["ps"], frozenset())
        return None


def maps_set(cmap, cp):
    """readers.py's decomposition rule over one codepoint set."""
    if cp in cmap:
        return True
    parts = readers.full_decomposition(cp, readers.unicodedata_decomposition)
    return len(parts) > 1 and all(p in cmap for p in parts)


def unmapped(text, fonts, cmaps, psmap):
    """The codepoints of a row, other than default-ignorables, that no face CDP reports for it
    maps. A font the judge cannot read (a platform font) maps nothing here; it already fails
    `platform`."""
    sets = [s for s in (cmaps.font(f, psmap) for f in fonts) if s is not None]
    return [ord(ch) for ch in text
            if not is_default_ignorable(ord(ch)) and not any(maps_set(s, ord(ch)) for s in sets)]


def reported_faces(fonts, pairs):
    """The faces CDP reports for a row, as predicted_faces names them: a web font or a declared CJK face by
    its PostScript name, any other font under a name no prediction carries."""
    return {f["ps"] if f["custom"] or f["ps"] in pairs else "%s (not embedded)" % f["ps"] for f in fonts}


def clusters(chars):
    """[[(ch, style), ...]]: a base, then the marks (Mn, Mc, Me) that follow it, and a joiner that follows
    a virama. Any other joiner is a cluster of its own."""
    out = []
    for ch, style in chars:
        mark = unicodedata.category(ch) in ("Mn", "Mc", "Me")
        joiner = ord(ch) in (ZWNJ, ZWJ)
        if out and (mark or (joiner and unicodedata.combining(out[-1][-1][0]) == 9)):
            out[-1].append((ch, style))
        else:
            out.append([(ch, style)])
    return out


def predicted_faces(chars, stack_of, cmaps, key_ps, cjk_weights):
    """The set of PostScript names (and NO_FACE) the reader model predicts for one row.

    `chars` is [(ch, (generic, weight, style))]; `stack_of(generic, weight, style)` the reader's
    face keys in stack order; `key_ps` maps a face key to its PostScript name; `cjk_weights` is
    cjk_by_weight()."""
    out = set()
    for cluster in clusters(chars):
        base, (generic, weight, style) = cluster[0][0], cluster[0][1]
        need = [ord(ch) for ch, _ in cluster if not is_default_ignorable(ord(ch))]
        stack = stack_of(generic, weight, style)
        hit = next((k for k in stack if all(maps_set(cmaps.key(k), cp) for cp in need)), None)
        if hit is not None:
            out.add(key_ps[hit])
        elif is_cjk(ord(base)):
            out.add(cjk_weights[700 if weight >= 600 else 400])
        else:
            out.add(NO_FACE)
    return out


def reader_style(style):
    """(generic, weight, style) a textfit style dict renders in. Raises ValueError otherwise."""
    family = style.get("font-family") or ""
    generic = family.split(",")[-1].strip().strip("'\"").lower()
    if generic not in GENERICS:
        raise ValueError("font-family %r ends in no generic family" % family)
    weight = style.get("font-weight", "400").strip().lower()
    w = {"normal": 400, "bold": 700}.get(weight, int(weight) if weight.isdigit() else None)
    if w is None:
        raise ValueError("font-weight %r" % weight)
    italic = style.get("font-style", "normal").strip().lower() in ("italic", "oblique")
    return generic, w, "italic" if italic else "normal"


# ------------------------------------------------------------ CJK font data
def cjk_font_data_verdict(cjk, data, cjk_em):
    """[(category, message)] for the declared CJK faces' data (calibrate/cjk_font_data.py's output):
    cjk-font-data when the file is absent or describes other files, cjk-kern when `cjk_em` is below
    1 + the largest positive default-on adjustment, cjk-advance when a reachable glyph advances
    more than 1 em. `data` is the parsed file, or None when it is absent."""
    if data is None:
        return [("cjk-font-data", "%s is absent: the CJK price cannot be checked against the faces' own data"
                 % CJK_FONT_DATA)]
    failures = []
    faces = {f.get("psname"): f for f in data.get("faces", [])}
    for face in cjk:
        got = faces.get(face.psname)
        if got is None:
            failures.append(("cjk-font-data", "%s describes no face %s" % (CJK_FONT_DATA, face.psname)))
            continue
        if got.get("collection") != face.collection or got.get("sha256") != face.sha256:
            failures.append(("cjk-font-data", "%s describes %s in %s sha256 %s; cjk.tsv declares %s sha256 %s"
                             % (CJK_FONT_DATA, face.psname, got.get("collection"), got.get("sha256"),
                                face.collection, face.sha256)))
            continue
        path = os.path.join(RUN, "platform", "cjk", face.collection)
        if not os.path.isfile(path) or sha256_file(path) != face.sha256:
            failures.append(("cjk-font-data", "%s is absent or does not have the sha256 cjk.tsv declares" % path))
            continue
        kern = got["gpos"]["max_positive"]
        if kern is not None and cjk_em + 1e-12 < 1 + kern["em"]:
            failures.append(("cjk-kern", "%s: textfit.CJK_EM %.4f is below 1 + the largest positive default-on "
                             "adjustment, %+d units = %+.4f em (feature %s, lookup %s, %s)"
                             % (face.psname, cjk_em, kern["units"], kern["em"], kern["feature"], kern["lookup"],
                                kern["glyphs"])))
        for over in got["advance"]["over_1em"]:
            failures.append(("cjk-advance", "%s: glyph %s advances %.4f em, over 1 em" % (face.psname, over[0], over[1])))
    return failures


def read_cjk_font_data():
    if not os.path.isfile(CJK_FONT_DATA):
        return None
    with open(CJK_FONT_DATA, encoding="utf-8") as fh:
        return json.load(fh)
