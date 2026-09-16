"""Text fit for the architecture diagrams: one implementation, stdlib only.

ROADMAP O189, ruled 2026-09-15 by three lenses and an adversarial refuter, and
revised the same day on the P-A evidence and again on the refuter's second
addendum. A line fits when it fits under the per-glyph MAXIMUM of the faces a
reader can get for its family, read from advances.tsv (see gen_advances.py for the
faces). It is a declared worst case over faces the tree can install and measure,
NOT a bound over every reader: platform UI fonts, other Arabic faces and a reader's
own default fonts are unmeasured.

Both diagram sets use it. `build.sh` runs it over `diagrams/*.svg` in both of its
modes, before a rebuild renders anything, and `platform-views/check.py` imports
it for the 22 hand-authored views. It replaced two flat estimates: 0.56 em for
proportional text, which flagged 83 lines and missed 3 that really spill, and
0.60 em for monospace, which was called a bound while DejaVu Sans Mono advances
1233/2048 = 0.60205.

THE RULES, each from the ruling:

  budget   Every line must end PAD (4) units inside its box. That padding is the
           table's declared ERROR BUDGET, not decoration: a sum of advances has
           no kerning, no GPOS and no integer rounding, so it can read a line
           narrower than a renderer draws it.
  holder   A line is bounded by the smallest rect holding its anchor point, else
           by the viewBox. Past the viewBox is also reported as a CLIP, which is
           worse than an overlap: the words are cut, not merely crowded.
  arabic   A letter in the table's arabic section is priced at the positional
           form its joining context forces, never at its isolated form. Joining
           types come from the table (ArabicShaping.txt), ZWJ causes joining,
           marks (Mn, Me) are transparent, ZWNJ and every other character break
           it. A D, R or C letter joins the character before it when that one is
           D, L or C; a D, L or C letter joins the one after it when that one is
           D, R or C. Both give medi, before alone fina, after alone init, neither
           isol.
  ligature A sequence in the table's ligature section is matched wherever its
           characters occur, each in the positional form the row records ('*'
           for any character that takes none), with only skippable characters
           between them and one font and size across them. Skippable is a mark
           (Mn, Me), ZWJ, or a codepoint in the table's gdefmark section: a
           shaper skips marks by GDEF glyph class, and an Arabic face can class a
           Lo or Sk codepoint as a mark. A match is priced at max(its components,
           the widest ligature plus the characters it skipped), and the line at
           the widest of all non-overlapping readings, never a greedy one.
  compose  A shaper can recompose a base and a following mark into the
           precomposed glyph a face maps, which can be far wider than the parts.
           That is not priced, so a line holding a pair from the table's compose
           section is refused: a character that composes with the last starter
           before it (the precomposed character so far, when the text spells part
           of it precomposed). A superset of where a shaper composes: blocking by
           an intervening mark is ignored, and only a starter (combining class 0)
           ends the sequence, as it ends canonical composition. A starter that is
           an Arabic letter is exempt: its decomposed spellings are priced by form
           and mark, and measured.
  cjk      A character of the CJK blocks is priced at CJK_EM, one em plus the
           largest positive adjustment the declared CJK faces apply by default,
           because no face in the table covers CJK; its derivation is beside the
           constant. An unassigned codepoint there is not priced (below).
  unicode  Categories and combining classes come from Python's unicodedata, so it
           must be the Unicode version the table declares, or nothing runs.
  closed   Anything the table cannot price FAILS rather than passing:
           - a codepoint with no row, or a '-' cell: some reader the table models
             draws it with no face of its stack (see readers.py);
           - an unassigned codepoint inside the CJK blocks;
           - a table without its positional, ligature, compose or gdefmark
             section, or without a declared Unicode version;
           - a line a shaper can recompose (above);
           - an Arabic letter (Lo or Lm in 0600-06FF, 0750-077F, 0870-089F,
             08A0-08FF) with no positional form row;
           - a format character other than ZWJ and ZWNJ in a line holding an
             Arabic letter, whose joining behaviour is not modelled;
           - a class with no parsed rule, or a font property set outside a
             plain class rule;
           - an inline `style`;
           - a transform on the text or an ancestor;
           - a `tspan` that is positioned or letter-spaced;
           - a family with no generic fallback, and bold serif or italic sans.
           A checker that cannot measure must not report clean.

What these rules have been measured against is recorded in ROADMAP O189, not here.
"""
import json
import os
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
TABLE_PATH = os.path.join(HERE, "advances.tsv")
PAD = 4.0
COLUMNS = ("sans400", "sans600", "mono", "serif")
FONT_PROPS = ("font-family", "font-size", "font-weight", "font-style",
              "letter-spacing", "text-anchor")
POSITIONED = ("x", "y", "dx", "dy", "rotate", "textLength", "lengthAdjust")

# CJK is priced by rule because no face the generator installs covers it. The rule is
# one em per character PLUS the largest positive adjustment the declared CJK faces
# apply by default: Noto Sans CJK SC's default-on GPOS (kern, in both collections
# cjk.tsv pins by sha256) moves a pair apart by at most +50/1000 em, so a run of CJK
# characters can render 0.05 em wider per character than its advances sum to
# (ROADMAP O189, panel 2's QC ruling). The figure is measured from the font data by
# calibration's cjk-font-data step, whose judge fails if this constant falls below
# it; arch-check reads this constant and never a font.
CJK_EM = 1.05
CJK_BLOCKS = ((0x2E80, 0x2FDF), (0x3000, 0x303F), (0x3040, 0x30FF), (0x3100, 0x312F),
              (0x3190, 0x31FF), (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF),
              (0xFF00, 0xFF60), (0xFFE0, 0xFFE6))

ARABIC_BLOCKS = ((0x0600, 0x06FF), (0x0750, 0x077F), (0x0870, 0x089F), (0x08A0, 0x08FF))
FORMS = ("isol", "init", "medi", "fina")
JOINING = ("D", "R", "L", "C", "U")
ZWNJ, ZWJ = 0x200C, 0x200D


class Unmeasurable(ValueError):
    """A line the table cannot price. The gate reports it as a failure."""


class PremiseFailure(Exception):
    """The table cannot be applied here at all. Every consumer stops, exit 2."""


class AdvanceTable(dict):
    """codepoint -> per-column advances in em (None where no face maps it), plus
    `forms[cp][form]` and `joining[cp]` for every Arabic letter, and
    `ligatures[((cp, form), ...)]` -> per-column widest ligature (None where no face
    of the column forms it; form '*' matches a character that takes no positional
    form), indexed by first codepoint in `ligature_starts`; `compositions[(base,
    mark)]` -> composite; `marks`, the codepoints the ligature matcher skips beyond
    Mn, Me and ZWJ; and the `unicode_version` the table declares."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.forms = {}
        self.joining = {}
        self.ligatures = None
        self.ligature_starts = None
        self.compositions = None
        self.marks = None
        self.unicode_version = None

    def set_ligatures(self, ligatures):
        self.ligatures = dict(ligatures)
        self.ligature_starts = {}
        for seq in sorted(self.ligatures):
            self.ligature_starts.setdefault(seq[0][0], []).append(seq)


# ------------------------------------------------------------------- table
def load_table(path=TABLE_PATH):
    table, section, ligatures, compositions, marks, versions = AdvanceTable(), None, None, None, None, []

    def cells(values):
        return tuple(None if v == "-" else int(v) / 10000.0 for v in values)

    def codepoint(value, n):
        if not re.fullmatch(r"[0-9A-F]{4,6}", value):
            raise Unmeasurable("advance table line %d: %r is not a codepoint" % (n, value))
        return int(value, 16)

    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.startswith("# unicode-version:"):
                versions.append(line[len("# unicode-version:"):].strip())
                continue
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if parts[0] == "cp":
                if section is not None or tuple(parts[1:]) != COLUMNS:
                    raise Unmeasurable("advance table line %d: columns %s, expected %s first"
                                       % (n, tuple(parts[1:]), COLUMNS))
                section = "cp"
            elif parts[0] == "arabic":
                if section != "cp" or tuple(parts[1:]) != ("joining", "form") + COLUMNS:
                    raise Unmeasurable("advance table line %d: the arabic section header is malformed "
                                       "or out of place" % n)
                section = "arabic"
            elif parts[0] == "ligature":
                if section != "arabic" or tuple(parts[1:]) != COLUMNS:
                    raise Unmeasurable("advance table line %d: the ligature section header is malformed "
                                       "or out of place" % n)
                section, ligatures = "ligature", {}
            elif parts[0] == "compose":
                if section != "ligature" or tuple(parts[1:]) != ("mark", "composite"):
                    raise Unmeasurable("advance table line %d: the compose section header is malformed "
                                       "or out of place" % n)
                section, compositions = "compose", {}
            elif parts[0] == "gdefmark":
                if section != "compose" or len(parts) != 1:
                    raise Unmeasurable("advance table line %d: the gdefmark section header is malformed "
                                       "or out of place" % n)
                section, marks = "gdefmark", set()
            elif section == "compose" and len(parts) == 3:
                base, mark = codepoint(parts[0], n), codepoint(parts[1], n)
                compositions[(base, mark)] = codepoint(parts[2], n)
            elif section == "gdefmark" and len(parts) == 1:
                marks.add(codepoint(parts[0], n))
            elif section == "cp" and len(parts) == 1 + len(COLUMNS):
                table[int(parts[0], 16)] = cells(parts[1:])
            elif section == "arabic" and len(parts) == 3 + len(COLUMNS) \
                    and parts[1] in JOINING and parts[2] in FORMS:
                cp = int(parts[0], 16)
                if table.joining.setdefault(cp, parts[1]) != parts[1]:
                    raise Unmeasurable("advance table line %d: U+%04X has two joining types" % (n, cp))
                table.forms.setdefault(cp, {})[parts[2]] = cells(parts[3:])
            elif section == "ligature" and len(parts) == 1 + len(COLUMNS) and parts[0].strip():
                seq = []
                for element in parts[0].split(" "):
                    cp, _, form = element.partition(":")
                    if form not in FORMS + ("*",):
                        raise Unmeasurable("advance table line %d: ligature element %r has no form" % (n, element))
                    seq.append((int(cp, 16), form))
                ligatures[tuple(seq)] = cells(parts[1:])
            else:
                raise Unmeasurable("advance table line %d is not a row this reader knows" % n)
    if not table:
        raise Unmeasurable("advance table %s has no rows" % path)
    if not table.forms or ligatures is None:
        raise Unmeasurable("advance table %s has no positional Arabic or ligature section: it predates "
                           "them, regenerate it with gen_advances.sh" % path)
    if compositions is None or marks is None:
        raise Unmeasurable("advance table %s has no compose or gdefmark section: it predates them, regenerate "
                           "it with gen_advances.sh" % path)
    if len(versions) != 1:
        raise Unmeasurable("advance table %s declares %d Unicode versions, expected one: regenerate it with "
                           "gen_advances.sh" % (path, len(versions)))
    partial = sorted(cp for cp, f in table.forms.items() if set(f) != set(FORMS))
    if partial:
        raise Unmeasurable("advance table: U+%04X lacks one of the four positional forms" % partial[0])
    if unicodedata.unidata_version != versions[0]:
        raise PremiseFailure("Python's unicodedata is Unicode %s and the advance table declares Unicode %s: "
                             "categories and combining classes would come from a different version than the "
                             "table's" % (unicodedata.unidata_version, versions[0]))
    table.set_ligatures(ligatures)
    table.compositions, table.marks, table.unicode_version = compositions, frozenset(marks), versions[0]
    return table


# ------------------------------------------------------------------ styles
def css_rules(source):
    """Plain `.class { ... }` rules, in stylesheet order. A font property anywhere
    else — another selector, or inside @media — is not modelled and fails closed."""
    rules = {}
    for block in re.findall(r"<style[^>]*>(.*?)</style>", source, re.S):
        media = re.compile(r"@media[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}", re.S)
        for m in media.findall(block):
            if re.search(r"font|letter-spacing|text-anchor", m):
                raise Unmeasurable("a font property inside @media is not modelled")
        for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", media.sub("", block)):
            props = {}
            for decl in body.split(";"):
                if ":" in decl:
                    k, v = decl.split(":", 1)
                    props[k.strip().lower()] = v.strip()
            for one in (s.strip() for s in sel.split(",")):
                if re.fullmatch(r"\.[A-Za-z_][\w-]*", one):
                    rules.setdefault(one[1:], {}).update(props)
                elif any(k in props for k in FONT_PROPS):
                    raise Unmeasurable("selector %r sets a font property and is not a plain class" % one)
    return rules


def own_style(el, rules):
    if el.get("style") is not None:
        raise Unmeasurable("inline style=%r is not modelled" % el.get("style"))
    props = {k: el.get(k) for k in FONT_PROPS if el.get(k) is not None}
    classes = set((el.get("class") or "").split())
    unknown = classes - set(rules)
    if unknown:
        raise Unmeasurable("class %s has no rule" % ", ".join(sorted(unknown)))
    for name, body in rules.items():          # stylesheet order: a class rule
        if name in classes:                   # outranks a presentation attribute
            props.update({k: v for k, v in body.items() if k in FONT_PROPS})
    return props


def local(tag):
    return tag.rsplit("}", 1)[-1]


def px(value, size=None, what="length"):
    v = value.strip().lower()
    if v in ("normal", "0"):
        return 0.0
    m = re.fullmatch(r"(-?\d+(?:\.\d+)?)(px|em)?", v)
    if not m or (m.group(2) == "em" and size is None):
        raise Unmeasurable("%s %r is not modelled" % (what, value))
    n = float(m.group(1))
    return n * size if m.group(2) == "em" else n


def column(style):
    family = style.get("font-family")
    if not family:
        raise Unmeasurable("no font-family")
    generic = family.split(",")[-1].strip().strip("'\"").lower()
    weight = style.get("font-weight", "400").strip().lower()
    w = {"normal": 400, "bold": 700}.get(weight, int(weight) if weight.isdigit() else None)
    if w is None:
        raise Unmeasurable("font-weight %r" % weight)
    italic = style.get("font-style", "normal").strip().lower() in ("italic", "oblique")
    if generic == "monospace":
        return "mono"                 # Book and Bold advance alike
    if generic == "serif":
        if w >= 600:
            raise Unmeasurable("bold serif is not in the table")
        return "serif"                # upright and italic faces are both in the column
    if generic == "sans-serif":
        if italic:
            raise Unmeasurable("italic sans is not in the table")
        return "sans600" if w >= 600 else "sans400"
    raise Unmeasurable("font-family %r ends in no generic family" % family)


# ------------------------------------------------------------------- text
def glyphs(text_el, rules, inherited_style):
    """(character, style) pairs after SVG's default whitespace collapse."""
    runs = []

    def walk(el, inherited, root):
        tag = local(el.tag)
        if tag not in ("text", "tspan"):
            raise Unmeasurable("<%s> inside <text> is not modelled" % tag)
        own = own_style(el, rules)
        if root:
            for k in ("dx", "dy", "rotate", "textLength", "lengthAdjust", "transform"):
                if el.get(k) is not None:
                    raise Unmeasurable("<text %s> is not modelled" % k)
        else:
            for k in POSITIONED + ("transform",):
                if el.get(k) is not None:
                    raise Unmeasurable("a <tspan> carrying %s is not modelled" % k)
            if "letter-spacing" in own:
                raise Unmeasurable("a letter-spaced <tspan> is not modelled")
        style = dict(inherited)
        style.update(own)
        if el.text:
            runs.append((el.text, style))
        for child in el:
            walk(child, style, False)
            if child.tail:
                runs.append((child.tail, style))

    walk(text_el, inherited_style, True)
    out, space = [], True
    for s, style in runs:
        for ch in s:
            if ch in " \t\r\n":
                if not space:
                    out.append((" ", style))
                space = True
            else:
                out.append((ch, style))
                space = False
    while out and out[-1][0] == " ":
        out.pop()
    return out


def is_arabic_letter(ch, table):
    cp = ord(ch)
    return cp in getattr(table, "joining", {}) or (
        any(lo <= cp <= hi for lo, hi in ARABIC_BLOCKS) and unicodedata.category(ch) in ("Lo", "Lm"))


def skippable(ch, marks):
    """Characters a ligature may span: marks (Mn, Me), ZWJ, and `marks`, the codepoints an
    Arabic face classes as a mark in GDEF whatever their Unicode category."""
    return ord(ch) == ZWJ or ord(ch) in marks or unicodedata.category(ch) in ("Mn", "Me")


def recomposition(chars, table):
    """Refuse a line where a character composes with the last starter before it: a
    shaper can draw the pair as the precomposed glyph, which the table does not price
    there. The starter is the precomposed character so far when the text spells part of
    it precomposed. A starter that is an Arabic letter is exempt."""
    pairs, starter = table.compositions, None
    for ch, _ in chars:
        cp = ord(ch)
        if starter is not None and (starter, cp) in pairs:
            raise Unmeasurable("U+%04X U+%04X can be recomposed into U+%04X, which a shaper may draw as one "
                               "glyph wider than its parts: a recomposed spelling is not priced (ROADMAP O194)"
                               % (starter, cp, pairs[(starter, cp)]))
        if unicodedata.combining(ch) == 0:
            starter = None if is_arabic_letter(ch, table) else cp


def arabic_forms(chars, table):
    """{index: form} for every Arabic letter in `chars`, the (character, style)
    pairs of one line: the positional form its joining context forces."""
    if not any(is_arabic_letter(ch, table) for ch, _ in chars):
        return {}
    joining = getattr(table, "joining", {})
    types = []
    for ch, _ in chars:
        cp, category = ord(ch), unicodedata.category(ch)
        if cp == ZWJ:
            types.append("C")
        elif cp in joining:
            types.append(joining[cp])
        elif category in ("Mn", "Me"):
            types.append("T")
        elif is_arabic_letter(ch, table):
            raise Unmeasurable("U+%04X %r is an Arabic letter with no positional form row" % (cp, ch))
        elif category == "Cf" and cp != ZWNJ:
            raise Unmeasurable("format character U+%04X in a line with Arabic letters: "
                               "its joining behaviour is not modelled" % cp)
        else:
            types.append("U")
    solid = [k for k, t in enumerate(types) if t != "T"]
    forms = {}
    for p, k in enumerate(solid):
        if ord(chars[k][0]) not in joining:
            continue
        before = types[solid[p - 1]] if p else "U"
        after = types[solid[p + 1]] if p + 1 < len(solid) else "U"
        joins_before = types[k] in ("D", "R", "C") and before in ("D", "L", "C")
        joins_after = types[k] in ("D", "L", "C") and after in ("D", "R", "C")
        forms[k] = ("medi" if joins_before and joins_after else "fina" if joins_before
                    else "init" if joins_after else "isol")
    return forms


def ligature_spans(chars, table, fonts, forms):
    """{end index: [(start, sequence, consumed indices)]}: every place a sequence of
    the ligature section occurs, each character in the form it records, with only
    skippable characters between them, in one font and size. A skippable character
    the sequence itself names — a GDEF mark a lookup without IgnoreMarks consumes — is
    tried both ways, consumed and skipped, so no reading is lost to the skip set."""
    starts = getattr(table, "ligature_starts", None) or {}
    marks = table.marks
    spans = {}

    def fits(k, cp, form):
        return ord(chars[k][0]) == cp and (form == "*" or forms.get(k) == form)

    def extend(seq, n, k, consumed, found):
        if n == len(seq):
            found.append(list(consumed))
            return
        cp, form = seq[n]
        while k < len(chars):
            if fits(k, cp, form):
                consumed.append(k)
                extend(seq, n + 1, k + 1, consumed, found)
                consumed.pop()
            if not skippable(chars[k][0], marks):
                break
            k += 1

    for s, (ch, _) in enumerate(chars):
        for seq in starts.get(ord(ch), ()):
            if not fits(s, *seq[0]):
                continue
            found = []
            extend(seq, 1, s + 1, [s], found)
            for consumed in found:
                if len({fonts[k] for k in consumed}) == 1:
                    spans.setdefault(consumed[-1], []).append((s, seq, consumed))
    return spans


def width(chars, table, spacing_style):
    spacing_size = px(spacing_style.get("font-size", ""), what="font-size") if chars else 0.0
    spacing = px(spacing_style.get("letter-spacing", "normal"), spacing_size, "letter-spacing")
    if getattr(table, "compositions", None) is None:
        raise Unmeasurable("the advance table has no compose section to refuse a recomposed line with")
    recomposition(chars, table)
    forms = arabic_forms(chars, table)
    if forms and getattr(table, "ligature_starts", None) is None:
        raise Unmeasurable("the advance table has no ligature section to price Arabic with")
    if forms and getattr(table, "marks", None) is None:
        raise Unmeasurable("the advance table has no gdefmark section to match ligatures with")
    prices, fonts = [], []
    for k, (ch, style) in enumerate(chars):
        size = px(style.get("font-size", ""), what="font-size")
        cp = ord(ch)
        if any(lo <= cp <= hi for lo, hi in CJK_BLOCKS):
            if unicodedata.category(ch) == "Cn":
                raise Unmeasurable("U+%04X is unassigned inside the CJK blocks: no face draws it, so the CJK "
                                   "rule does not price it" % cp)
            em, col = CJK_EM, None
        elif k in forms:
            col = COLUMNS.index(column(style))
            em = table.forms[cp][forms[k]][col]
            if em is None:
                raise Unmeasurable("U+%04X %r has no %s advance for %s" % (cp, ch, forms[k], column(style)))
        else:
            col = COLUMNS.index(column(style))
            row = table.get(cp)
            em = row[col] if row else None
            if em is None:
                raise Unmeasurable("U+%04X %r has no advance for %s" % (cp, ch, column(style)))
        prices.append(em * size + spacing)
        fonts.append((col, size))
    # The widest reading: best[i] prices chars[:i] at the widest non-overlapping
    # choice of ligature matches, each at max(components, ligature + skipped).
    spans = ligature_spans(chars, table, fonts, forms)
    best = [0.0] * (len(chars) + 1)
    for i in range(len(chars)):
        best[i + 1] = best[i] + prices[i]
        for s, seq, consumed in spans.get(i, ()):
            col, size = fonts[s]
            em = table.ligatures[seq][col] if col is not None else None
            if em is None:
                continue
            components = sum(prices[s:i + 1])
            ligature = em * size + spacing * len(consumed) + sum(
                prices[k] for k in range(s, i + 1) if k not in consumed)
            best[i + 1] = max(best[i + 1], best[s] + max(components, ligature))
    return best[-1]


# -------------------------------------------------------------------- fit
def texts(source, table):
    """Yield one dict per <text> with content: its measured width, its box and how
    far it spills. Raises Unmeasurable for the first line it cannot price."""
    root = ET.fromstring(source)
    rules = css_rules(source)
    parent = {c: p for p in root.iter() for c in p}
    vb = [float(v) for v in re.split(r"[\s,]+", root.get("viewBox", "0 0 0 0").strip())]
    boxes = []
    for r in root.iter():
        if local(r.tag) != "rect":
            continue
        try:
            b = (float(r.get("x", 0)), float(r.get("y", 0)), float(r.get("width")), float(r.get("height")))
        except (TypeError, ValueError):
            continue
        if b[2] > 0 and b[3] > 0:
            boxes.append(b)
    for t in (e for e in root.iter() if local(e.tag) == "text"):
        label = " ".join("".join(t.itertext()).split())
        if not label:
            continue
        inherited, a = {}, parent.get(t)
        chain = []
        while a is not None:
            if a.get("transform") is not None:
                raise Unmeasurable("a transform above <text> %r is not modelled" % label[:40])
            chain.append(a)
            a = parent.get(a)
        for a in reversed(chain):
            inherited.update(own_style(a, rules))
        try:
            chars = glyphs(t, rules, inherited)
            style = dict(inherited)
            style.update(own_style(t, rules))
            w = width(chars, table, style)
            x, y = float(t.get("x")), float(t.get("y"))
            size = px(style.get("font-size", ""), what="font-size")
        except (TypeError, ValueError) as e:
            if isinstance(e, Unmeasurable):
                raise
            raise Unmeasurable("%s: %r" % (e, label[:40]))
        anchor = style.get("text-anchor", "start").strip()
        left = x - (w / 2 if anchor == "middle" else w if anchor == "end" else 0.0)
        mid = y - 0.35 * size
        holding = [b for b in boxes if b[0] <= x <= b[0] + b[2] and b[1] <= mid <= b[1] + b[3]]
        box = min(holding, key=lambda b: b[2] * b[3]) if holding else (vb[0], vb[1], vb[2], vb[3])
        over = max(box[0] + PAD - left, left + w - (box[0] + box[2] - PAD))
        clip = max(vb[0] - left, left + w - (vb[0] + vb[2])) if vb[2] else 0.0
        yield {"label": label, "width": w, "left": left, "box": box, "anchor": anchor,
               "holder": "rect" if holding else "viewBox", "over": over, "clip": clip}


def spills(source, table):
    """The lines that do not fit, as printable problems. Unmeasurable is a problem too."""
    bad = []
    try:
        for t in texts(source, table):
            if t["over"] > 0:
                kind = "CLIPPED past the viewBox by ~%d" % round(t["clip"]) if t["clip"] > 0 else \
                    "spills its box by ~%d" % round(t["over"])
                bad.append("text %s: %r" % (kind, t["label"][:60]))
    except Unmeasurable as e:
        bad.append("text unmeasurable (fails closed): %s" % e)
    return bad


def svg_of(path):
    raw = open(path, encoding="utf-8").read()
    if path.endswith(".svg"):
        return raw
    return raw[raw.find("<svg"):raw.find("</svg>") + len("</svg>")]


# ---------------------------------------------------------- premise probe
PROBE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 100"><style>'
    '.f { font-family: "DejaVu Sans", sans-serif; } .s { font-size: 11px; }'
    '</style>'
    '<rect x="10" y="10" width="200" height="80"/>'
    '<text x="20" y="40" class="f s">fits</text>'
    '<text x="20" y="60" class="f s">a line far too long to fit inside this two-hundred box</text>'
    '</svg>')
PROBE_CLOSED = (                       # U+E000 is private use: no face maps it, no row
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 100">'
    '<rect x="10" y="10" width="300" height="80"/>'
    '<text x="20" y="40" font-family="sans-serif" font-size="11"></text>'
    '</svg>')
# HEH is dual-joining and every one of its positional forms prices wider than its
# isolated form, so this line is wider priced by position than priced in isolation.
# The forms are declared here by hand, independently of arabic_forms(): a mark that
# does not break a join (1), a space that does (4), a right-joining ALEF that joins
# only before (6), ZWNJ breaking (7) and ZWJ causing (9, 11) a join.
PROBE_ARABIC_TEXT = "هَهه ها‌ه‍ه‍ ه"
PROBE_ARABIC_FORMS = {0: "init", 2: "medi", 3: "fina", 5: "init", 6: "fina",
                      8: "init", 10: "medi", 13: "isol"}
# LAM + ALEF WITH MADDA ABOVE forms a ligature wider than its two positional forms.
PROBE_LIGATURE_TEXT = "لآ"
PROBE_LIGATURE_FORMS = {0: "init", 1: "fina"}
# BEH TEH THEH under two synthetic, overlapping ligatures: the later one is the
# wider, so a greedy left-to-right match reads the line narrower than it can render.
PROBE_READING_TEXT = "بتث"
PROBE_READING_FORMS = {0: "init", 1: "medi", 2: "fina"}
# ETA + COMBINING COMMA ABOVE, and ETA WITH PSILI AND OXIA + YPOGEGRAMMENI: a shaper can
# recompose each into one precomposed glyph (U+1F28, U+1F9C), from a base and from the
# precomposed character so far. Escaped, so no editor can normalise them away.
PROBE_RECOMPOSED = ("Ἠ", "ᾜ")
# ETA + COMBINING MACRON BELOW composes into nothing, and ALEF + MADDA ABOVE composes
# into U+0622 behind an Arabic starter, which is exempt: both must be measured.
PROBE_MEASURED = (("Η̱", False), ("آ", True))
# LAM, U+FC5E, ALEF. U+FC5E is Lo, so under a synthetic LAM-ALEF ligature only a skip set
# taken from GDEF lets the ligature span it; and under a synthetic ligature naming it,
# only a matcher that also CONSUMES a skippable character matches at all.
PROBE_SKIP_TEXT = "لﱞا"
PROBE_SKIP_FORMS = {0: "isol", 2: "isol"}
# U+3040 lies in the Hiragana block and is unassigned in Unicode 15.0: the CJK rule must refuse
# it. U+3042 HIRAGANA LETTER A is assigned: the same rule must price it at CJK_EM.
PROBE_CJK_UNASSIGNED = "぀"
PROBE_CJK_ASSIGNED = "あ"
PROBE_SIZE = 11.0


def probe_svg(width_px, text):
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 100"><style>'
            '.f { font-family: "DejaVu Sans", "Noto Sans", sans-serif; } .s { font-size: %gpx; }</style>'
            '<rect x="10" y="10" width="%.4f" height="80"/>'
            '<text x="%g" y="40" class="f s">%s</text></svg>' % (PROBE_SIZE, width_px, 10 + PAD, text))


def declared(table, text, forms):
    """Per-character prices in px under hand-declared forms, sans400: None if the
    table cannot supply one."""
    col, out = COLUMNS.index("sans400"), []
    for k, ch in enumerate(text):
        row = table.get(ord(ch))
        if k in forms:
            cells = getattr(table, "forms", {}).get(ord(ch), {}).get(forms[k])
        else:
            cells = row
        if cells is None or cells[col] is None:
            return None
        out.append(cells[col] * PROBE_SIZE)
    return out


def probe_between(table, text, narrow, wide, what):
    """The arm must measure `text` at `wide` and flag it in a box that holds `narrow`."""
    missing = []
    svg = probe_svg(2 * PAD + (narrow + wide) / 2, text)
    measured = [t["width"] for t in texts(svg, table)]
    if len(measured) != 1 or abs(measured[0] - wide) > 1e-6:
        missing.append("%s priced at %.3f (got %s)" % (what, wide, measured))
    found = spills(svg, table)
    if len(found) != 1 or "spills its box" not in found[0]:
        missing.append("%s spilling a box that holds %.3f (got %s)" % (what, narrow, found))
    return missing


def variant(table, **replace):
    """A copy of `table` with named sections replaced, for the probe's synthetic tables.
    Every section is carried unless replaced, so a variant fails for its own reason."""
    fields = {"forms": table.forms, "joining": table.joining, "ligatures": table.ligatures,
              "compositions": table.compositions, "marks": table.marks}
    unknown = set(replace) - set(fields)
    if unknown:
        raise KeyError("no section %s" % ", ".join(sorted(unknown)))
    fields.update(replace)
    out = AdvanceTable(table)
    out.forms, out.joining = fields["forms"], fields["joining"]
    out.compositions, out.marks = fields["compositions"], fields["marks"]
    if fields["ligatures"] is not None:
        out.set_ligatures(fields["ligatures"])
    return out


def probe(table):
    """Empty when the arm can see a spill, a line it cannot price, a line priced by
    position, a ligature priced above its components, a widest reading that a
    greedy match would miss, a line a shaper can recompose, a ligature across and
    through a GDEF mark, a CJK character at CJK_EM, and an unassigned CJK codepoint."""
    missing = []
    found = spills(PROBE, table)
    if len(found) != 1 or "far too long" not in found[0]:
        missing.append("exactly one spilling line in the probe (got %s)" % found)
    if not any("fails closed" in b for b in spills(PROBE_CLOSED, table)):
        missing.append("a codepoint with no row failing closed")

    col = COLUMNS.index("sans400")
    positional = declared(table, PROBE_ARABIC_TEXT, PROBE_ARABIC_FORMS)
    isolated = declared(table, PROBE_ARABIC_TEXT, {})
    if positional is None or isolated is None or sum(positional) < sum(isolated) + 0.1 * PROBE_SIZE:
        missing.append("an Arabic fixture wider by position than in isolation: the table no longer discriminates")
    else:
        got = arabic_forms([(ch, {}) for ch in PROBE_ARABIC_TEXT], table)
        if got != PROBE_ARABIC_FORMS:
            missing.append("the declared joining forms %s (got %s)" % (PROBE_ARABIC_FORMS, got))
        missing += probe_between(table, PROBE_ARABIC_TEXT, sum(isolated), sum(positional),
                                 "the Arabic fixture by position")
        stripped = variant(table, forms={}, joining={})
        if not any("positional form row" in b for b in spills(probe_svg(500, PROBE_ARABIC_TEXT), stripped)):
            missing.append("an Arabic letter with no positional form row failing closed")
        unlisted = variant(table, ligatures=None)
        if not any("no ligature section" in b for b in spills(probe_svg(500, PROBE_ARABIC_TEXT), unlisted)):
            missing.append("a table with no ligature section failing closed")
        unmarked = variant(table, marks=None)
        if not any("no gdefmark section" in b for b in spills(probe_svg(500, PROBE_ARABIC_TEXT), unmarked)):
            missing.append("a table with no gdefmark section failing closed")

    components = declared(table, PROBE_LIGATURE_TEXT, PROBE_LIGATURE_FORMS)
    ligature = (getattr(table, "ligatures", None) or {}).get(
        tuple((ord(ch), PROBE_LIGATURE_FORMS[k]) for k, ch in enumerate(PROBE_LIGATURE_TEXT)))
    if components is None or ligature is None or ligature[col] is None \
            or ligature[col] * PROBE_SIZE < sum(components) + 0.05 * PROBE_SIZE:
        missing.append("a ligature wider than its components in the table: it no longer discriminates")
    else:
        missing += probe_between(table, PROBE_LIGATURE_TEXT, sum(components), ligature[col] * PROBE_SIZE,
                                 "the ligature fixture at its ligature width")

    prices = declared(table, PROBE_READING_TEXT, PROBE_READING_FORMS)
    if prices is None:
        missing.append("the widest-reading fixture's letters in the table")
    else:
        first = (sum(prices[0:2]) / PROBE_SIZE + 0.5)
        second = (sum(prices[1:3]) / PROBE_SIZE + 1.0)
        seq = tuple((ord(ch), PROBE_READING_FORMS[k]) for k, ch in enumerate(PROBE_READING_TEXT))
        synthetic = variant(table, ligatures={seq[0:2]: (first,) * 4, seq[1:3]: (second,) * 4})
        greedy = first * PROBE_SIZE + prices[2]
        widest = prices[0] + second * PROBE_SIZE
        missing += probe_between(synthetic, PROBE_READING_TEXT, greedy, widest,
                                 "the overlapping-ligature fixture at its widest reading")

    # Recomposition: refused from a base and from a precomposed character so far; not
    # refused where nothing composes or the starter is an Arabic letter.
    pairs = getattr(table, "compositions", None) or {}
    for text in PROBE_RECOMPOSED:
        pair = (ord(text[0]), ord(text[1]))
        if pair not in pairs:
            missing.append("the composition U+%04X U+%04X in the table: it no longer discriminates" % pair)
            continue
        found = spills(probe_svg(500, text), table)
        if len(found) != 1 or "recomposed" not in found[0]:
            missing.append("U+%04X U+%04X, which a shaper can recompose, failing closed (got %s)" % (pair + (found,)))
    for text, composes in PROBE_MEASURED:
        pair = (ord(text[0]), ord(text[1]))
        if (pair in pairs) != composes:
            missing.append("U+%04X U+%04X %s in the table: the fixture no longer discriminates"
                           % (pair + ("as a composition" if composes else "absent",)))
            continue
        found = spills(probe_svg(500, text), table)
        if found:
            missing.append("U+%04X U+%04X measured rather than refused (got %s)" % (pair + (found,)))
    if not any("no compose section" in b for b in spills(probe_svg(500, PROBE_RECOMPOSED[0]),
                                                         variant(table, compositions=None))):
        missing.append("a table with no compose section failing closed")

    # The GDEF skip set: a ligature ACROSS a mark Unicode does not call one, and a ligature
    # that consumes it.
    beyond = [cp for cp in (getattr(table, "marks", None) or ()) if unicodedata.category(chr(cp)) not in ("Mn", "Me")]
    if not beyond:
        missing.append("a codepoint outside Mn and Me in the gdefmark section: the skip set no longer adds anything")
    prices = declared(table, PROBE_SKIP_TEXT, PROBE_SKIP_FORMS)
    skip = ord(PROBE_SKIP_TEXT[1])
    if prices is None or unicodedata.category(PROBE_SKIP_TEXT[1]) in ("Mn", "Me"):
        missing.append("the GDEF-mark fixture's characters in the table, its middle one outside Mn and Me")
    elif arabic_forms([(ch, {}) for ch in PROBE_SKIP_TEXT], table) != PROBE_SKIP_FORMS:
        missing.append("the GDEF-mark fixture's declared forms %s" % PROBE_SKIP_FORMS)
    else:
        components = sum(prices)
        across = tuple((ord(PROBE_SKIP_TEXT[k]), form) for k, form in sorted(PROBE_SKIP_FORMS.items()))
        across_em = (prices[0] + prices[2]) / PROBE_SIZE + 1.0
        reading = across_em * PROBE_SIZE + prices[1]
        missing += probe_between(variant(table, ligatures={across: (across_em,) * 4}, marks=frozenset({skip})),
                                 PROBE_SKIP_TEXT, components, reading,
                                 "a ligature across a GDEF mark at its ligature reading")
        emptied = [t["width"] for t in texts(probe_svg(500, PROBE_SKIP_TEXT),
                                             variant(table, ligatures={across: (across_em,) * 4}, marks=frozenset()))]
        if len(emptied) != 1 or abs(emptied[0] - components) > 1e-6:
            missing.append("the same line at its components %.3f once the skip set is emptied (got %s): the skip set "
                           "makes no difference the arm can see" % (components, emptied))
        through = (across[0], (skip, "*"), across[1])
        through_em = components / PROBE_SIZE + 1.0
        missing += probe_between(variant(table, ligatures={through: (through_em,) * 4}, marks=frozenset({skip})),
                                 PROBE_SKIP_TEXT, components, through_em * PROBE_SIZE,
                                 "a ligature that consumes a GDEF mark at its ligature reading")

    # The CJK rule: an assigned CJK codepoint priced at CJK_EM, an unassigned one refused.
    if unicodedata.category(PROBE_CJK_UNASSIGNED) != "Cn" or unicodedata.category(PROBE_CJK_ASSIGNED) == "Cn":
        missing.append("U+%04X unassigned and U+%04X assigned in this Unicode version: the CJK fixture no longer "
                       "discriminates" % (ord(PROBE_CJK_UNASSIGNED), ord(PROBE_CJK_ASSIGNED)))
    else:
        found = spills(probe_svg(500, PROBE_CJK_UNASSIGNED), table)
        if len(found) != 1 or "unassigned inside the CJK blocks" not in found[0]:
            missing.append("an unassigned codepoint inside the CJK blocks failing closed (got %s)" % found)
        measured = [t["width"] for t in texts(probe_svg(500, PROBE_CJK_ASSIGNED), table)]
        if len(measured) != 1 or abs(measured[0] - CJK_EM * PROBE_SIZE) > 1e-6:
            missing.append("an assigned CJK codepoint priced at CJK_EM %.2f em (got %s)" % (CJK_EM, measured))
    return missing


def main(argv):
    widths = "--widths" in argv
    files = [a for a in argv if not a.startswith("--")]
    try:
        table = load_table()
    except PremiseFailure as e:
        print("PREMISE FAILURE: %s" % e)
        return 2
    except (OSError, Unmeasurable) as e:
        print("PREMISE FAILURE: the advance table cannot be read: %s" % e)
        return 2
    missing = probe(table)
    if missing:
        print("PREMISE FAILURE: the text-fit arm cannot see %s." % "; ".join(missing))
        print("Its zero-results would be meaningless. Fix the checker.")
        return 2
    if not files:
        print("PREMISE FAILURE: no files given — this examined nothing.")
        return 2
    if widths:                                  # calibration output, JSON lines
        for f in files:
            for i, t in enumerate(texts(svg_of(f), table)):
                print(json.dumps({"file": os.path.basename(f), "i": i, "label": t["label"],
                                  "width": round(t["width"], 3), "over": round(t["over"], 3),
                                  "left": round(t["left"], 3), "anchor": t["anchor"],
                                  "box": [round(v, 3) for v in t["box"]]},
                                 ensure_ascii=False))
        return 0
    print("premise probe: the text-fit arm flags a spilling line, prices Arabic by positional form and "
          "ligatures at the widest reading, spans and consumes a GDEF mark, refuses a recomposable line, "
          "prices CJK at %.2f em and refuses an unassigned CJK codepoint, and fails closed on an unpriced line"
          % CJK_EM)
    failures, measured = 0, 0
    for f in files:
        bad = spills(svg_of(f), table)
        measured += 1
        print("%-34s %s" % (os.path.basename(f), "ok" if not bad else "FAIL"))
        for b in bad:
            print("      - %s" % b)
        failures += len(bad)
    if failures:
        print("text fit: %d problem(s) across %d file(s)" % (failures, measured))
        return 1
    print("text fit: %d file(s), every line inside its box" % measured)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
