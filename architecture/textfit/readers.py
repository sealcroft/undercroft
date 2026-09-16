"""The one reader model of the text-fit standard. Stdlib only.

ROADMAP O189, panel 2's QM ruling (2026-09-15): "price each cell from the face every
modelled reader actually draws with, and refuse a cell where some reader draws with none".
gen_advances.py prices each cell from this model, and the calibration harness
(calibrate/common.py) builds its pages and predicts which faces a render uses from it.
Keeping both in one file means the table and its calibration cannot model different readers.

A PAGE is one slot of fonts.tsv, and `page_pins` gives the files it holds. Slot debian holds
its own files. Every other page, the calibration canary included, holds its own files plus
DejaVu from slot debian (the font-version ruling: DejaVu comes from Debian in both slots).

A READER is one page read through one stack VARIANT in one rendered STYLE:

  variants  dejavu         DejaVu primary, then Noto Sans Arabic, Noto Sans Thai,
                           Noto Sans Devanagari, Noto Sans Math
            noto           Noto primary, then the same script faces
            dejavu-looped  as dejavu, with Noto Looped Thai in Noto Sans Thai's place
            noto-looped    as noto, with Noto Looped Thai in Noto Sans Thai's place
            The primary is DejaVu Sans, DejaVu Sans Mono or DejaVu Serif for dejavu, and Noto
            Sans, DejaVu Sans Mono or Noto Serif for noto: no Noto monospace face is pinned, so
            a monospace reader's noto stack equals its dejavu stack. The CJK face is NOT part of
            the model. textfit.py prices CJK by rule, and calibration appends the declared CJK
            family to every stack itself.
  styles    per table column: sans400 is sans-serif 400 normal; sans600 is sans-serif 700
            normal; mono is monospace 400 and monospace 700; serif is serif 400 normal and
            serif 400 italic.

WHICH FILE A STACK ENTRY DRAWS WITH is the browser's @font-face matching (CSS Fonts 4,
section 5.2) over the files of that entry's family, each declared under the weight and
style its name gives (`SUFFIX`). Italic takes an italic file where the family has one, else
the upright file, which a browser slants. Weights between 400 and 500 look upward to 500,
then downward, then above 500. Weights above 500 look upward, then downward, and weights
below 400 look downward, then upward. For these families that means a weight of 600 or more
takes the Bold file where there is one and the Regular file otherwise, which a browser
emboldens. Noto Sans Math has a Regular file only.

A reader DRAWS a codepoint with the FIRST face of its stack that maps it. A face maps it when
its cmap has it, or has every part of its full canonical decomposition, because a shaper
decomposes before it falls back to the next face (`mapper`). A reader whose stack has no such
face draws it with a face outside the model. That is what the generator refuses by writing '-'.
"""
import os
import unicodedata

DEBIAN = "debian"
CANARY = "canary"

# A file's stem suffix -> the @font-face weight and style it is declared under.
SUFFIX = {"Regular": (400, "normal"), "Bold": (700, "normal"), "Italic": (400, "italic"),
          "BoldItalic": (700, "italic")}
# The face a stack starts with, per generic family, per primary of a variant.
PRIMARY = {
    "dejavu": {"sans-serif": "DejaVuSans", "monospace": "DejaVuSansMono", "serif": "DejaVuSerif"},
    "noto": {"sans-serif": "NotoSans", "monospace": "DejaVuSansMono", "serif": "NotoSerif"},
}
# Script roles and the file groups that can fill them. Looped Thai was renamed upstream after
# 23.7.1; the second spelling exists for the calibration canary only.
SCRIPT_GROUPS = {
    "arabic": ("NotoSansArabic",),
    "thai": ("NotoSansThai",),
    "looped-thai": ("NotoLoopedThai", "NotoSansThaiLooped"),
    "devanagari": ("NotoSansDevanagari",),
    "math": ("NotoSansMath",),
}
# A stack variant: (primary, script roles in stack order).
VARIANTS = {
    "dejavu": ("dejavu", ("arabic", "thai", "devanagari", "math")),
    "noto": ("noto", ("arabic", "thai", "devanagari", "math")),
    "dejavu-looped": ("dejavu", ("arabic", "looped-thai", "devanagari", "math")),
    "noto-looped": ("noto", ("arabic", "looped-thai", "devanagari", "math")),
}
GENERICS = ("sans-serif", "monospace", "serif")
# Table column -> the (generic, weight, style) every reader of it renders in.
COLUMN_STYLES = {
    "sans400": (("sans-serif", 400, "normal"),),
    "sans600": (("sans-serif", 700, "normal"),),
    "mono": (("monospace", 400, "normal"), ("monospace", 700, "normal")),
    "serif": (("serif", 400, "normal"), ("serif", 400, "italic")),
}


def in_domain(cp):
    """The Basic Multilingual Plane only, without surrogates or the private-use area."""
    return cp <= 0xFFFF and not 0xD800 <= cp <= 0xF8FF


def face_key(pin):
    return "%s:%s" % (pin.slot, pin.file)


def group_of(file):
    """(group, weight, style) from a file name: `NotoSans-Bold.ttf` -> ('NotoSans', 700, 'normal')."""
    stem = os.path.basename(file)[:-len(".ttf")] if file.endswith(".ttf") else os.path.basename(file)
    head, _, tail = stem.rpartition("-")
    if head and tail in SUFFIX:
        return (head,) + SUFFIX[tail]
    return stem, 400, "normal"


def page_pins(page, rows, canary_rows=()):
    """The fonts.tsv rows (or canary manifest rows) one page holds, in file order."""
    dejavu = [p for p in rows if p.slot == DEBIAN and p.file.startswith("dejavu/")]
    if page == DEBIAN:
        out = [p for p in rows if p.slot == DEBIAN]
    elif page == CANARY:
        out = dejavu + list(canary_rows)
    elif page in {p.slot for p in rows}:
        out = dejavu + [p for p in rows if p.slot == page]
    else:
        raise ValueError("no page %r" % page)
    if not out:
        raise ValueError("page %r holds nothing" % page)
    return out


def families(pins):
    """{group: [(weight, style, pin)]} over one page's files."""
    out = {}
    for p in pins:
        group, weight, style = group_of(p.file)
        out.setdefault(group, []).append((weight, style, p))
    return out


def stack_groups(present, variant, generic):
    """([group, ...] in stack order, [what is lacking]) for one variant and generic family."""
    primary, roles = VARIANTS[variant]
    groups, lacking = [], []
    first = PRIMARY[primary][generic]
    if first in present:
        groups.append(first)
    else:
        lacking.append(first)
    for role in roles:
        hits = [g for g in SCRIPT_GROUPS[role] if g in present]
        if len(hits) != 1:
            lacking.append("%s (%s)" % (role, " or ".join(SCRIPT_GROUPS[role])))
        else:
            groups.append(hits[0])
    return groups, lacking


def match(entries, weight, style):
    """The entry CSS font matching selects from one family's [(weight, style, item)]."""
    order = {"italic": ("italic", "oblique", "normal"), "oblique": ("oblique", "italic", "normal"),
             "normal": ("normal", "oblique", "italic")}[style]
    pool = next(([e for e in entries if e[1] == s] for s in order if any(e[1] == s for e in entries)), [])
    if not pool:
        raise ValueError("a family with no faces")
    weights = sorted({e[0] for e in pool})
    if weight in weights:
        chosen = weight
    elif 400 <= weight <= 500:
        up = [w for w in weights if weight < w <= 500]
        down = [w for w in weights if w < weight]
        chosen = min(up) if up else max(down) if down else min(weights)
    elif weight < 400:
        down = [w for w in weights if w < weight]
        chosen = max(down) if down else min(weights)
    else:
        up = [w for w in weights if w > weight]
        chosen = min(up) if up else max(weights)
    hits = [e for e in pool if e[0] == chosen]
    if len(hits) != 1:
        raise ValueError("%d faces declared at weight %d style %s" % (len(hits), chosen, hits[0][1]))
    return hits[0]


def reader_faces(pins, variant, generic, weight, style):
    """[face key, ...]: the files one reader's stack draws with, in stack order. Raises
    ValueError when the page lacks a family the variant names."""
    by = families(pins)
    groups, lacking = stack_groups(set(by), variant, generic)
    if lacking:
        raise ValueError("variant %s, %s: the page lacks %s" % (variant, generic, ", ".join(lacking)))
    return [face_key(match(by[g], weight, style)[2]) for g in groups]


def column_readers(pins, column):
    """[(reader label, [face key, ...])] for every distinct stack that renders a table column."""
    out, seen = [], set()
    for variant in VARIANTS:
        for generic, weight, style in COLUMN_STYLES[column]:
            faces = reader_faces(pins, variant, generic, weight, style)
            if tuple(faces) not in seen:
                seen.add(tuple(faces))
                out.append(("%s %s %d %s" % (variant, generic, weight, style), faces))
    return out


def full_decomposition(cp, decomposition):
    """The full canonical decomposition of one codepoint. `decomposition(cp)` gives its
    one-level canonical decomposition as a list, or None."""
    parts = decomposition(cp)
    if not parts:
        return [cp]
    return [c for part in parts for c in full_decomposition(part, decomposition)]


def mapper(has, decomposition):
    """maps(face key, cp): the face's cmap has cp, or has every part of its full canonical
    decomposition. `has(face key, cp)` reads a cmap; `decomposition` is as above."""
    def maps(key, cp):
        if has(key, cp):
            return True
        parts = full_decomposition(cp, decomposition)
        return len(parts) > 1 and all(has(key, p) for p in parts)
    return maps


def first_mapper(faces, cp, maps):
    """The first face key of a stack that maps cp, or None: the face a reader draws cp with."""
    return next((key for key in faces if maps(key, cp)), None)


def unicodedata_decomposition(cp):
    """One-level canonical decomposition from Python's unicodedata, for callers that assert its
    Unicode version equals the table's. gen_advances.py reads the pinned UnicodeData.txt instead."""
    d = unicodedata.decomposition(chr(cp))
    if not d or d.startswith("<"):
        return None
    return [int(x, 16) for x in d.split()]
