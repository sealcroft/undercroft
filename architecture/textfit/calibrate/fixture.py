"""Calibration's fixture generator (ROADMAP O189, V3). python:3.12-slim, `architecture/` read-only
at /a, the run folder at /r. Writes /r/fixture/strings.json: every string, every pass, and each
string's price in every column from the TREE's advance table through textfit.py.

THE STRINGS, all generated from the tree's table and the pinned Unicode data textfit asserts:
  arabic      every ligature sequence in the table, spelled isolated, final, between two BEH,
              with a fatha, with a fatha after BEH, and decomposed (plain and final); Allah in
              three spellings, plain and final; the R letters U+0759, U+08AC, U+08B1 after and
              between D letters; every letter in all four positions (ZWJ forcing the form) and,
              where it decomposes, decomposed in all four; and the F3 strings, LAM + U+FC5E +
              ALEF presentation forms, plain and final.
  thai        every Thai codepoint with a row: a spacing character alone, a leading vowel
              before a consonant, a following vowel after one; every mark on a plain, a tall
              and a descending consonant; every above or below vowel with every tone mark; every
              tone mark before SARA AM. The same strings render in the Looped Thai passes.
  devanagari  every Devanagari codepoint with a row: a spacing character alone, every sign on
              KA; every consonant in a conjunct with ten second consonants, with and without the
              I sign; every consonant under a reph, as a dead consonant and as an explicit half
              form; ten three-consonant clusters, with and without the I sign.
  math        every codepoint of the Noto Sans Math blocks with a row, alone.
  cjk         every codepoint of textfit's CJK blocks that BOTH declared CJK faces map, other
              than marks, controls, format characters and unassigned codepoints, in groups of
              64 per text element. The renderer reads each group's width with default kerning
              and each character's own advance with font-kerning:none.

A script string is a whole cluster (a base, then its marks), never a lone mark. A generated
string that textfit refuses BY RULE — one a shaper can recompose (ROADMAP O194) — is not
emitted and is counted under `skipped`, because it would measure the rule rather than the
table.

THE TABLE'S '-' CELLS ARE NOT RENDERED (panel 2's QM ruling). A '-' cell means some reader the
table models draws that character with no face of its stack, so a render would measure a face
outside the page. For every string of every script, a (string, column) is left out when one of
its characters has a '-' cell in that column: the codepoint cell, or for an Arabic letter the
form cell its context forces; a character with no row is '-' in every column; CJK is priced by
rule and never left out. Each (string, column) left out is listed under `skipped` with the cells
that caused it. Every other textfit refusal stays in as an unmeasurable price, and the judge fails
the run on it.

THE '-' CELLS ARE CHECKED BOTH WAYS against the font bytes before anything is written: for every
codepoint any staged face of a gating page maps (itself or its full canonical decomposition), and
every codepoint with a row, readers.py's readers of each column on every gating page must all
draw it with some face exactly where the table prices the cell, reading each face's cmap with
sfnt.py from the run's own sha256-checked files and decompositions from Python's unicodedata,
which must be the table's Unicode version. Fixture columns map to table columns: sans400 and
sans600 to themselves, mono400 and mono700 to mono, serif and serif-italic to serif. A '-' cell
every reader draws, a priced cell some reader cannot draw, or an Arabic letter's form cells
disagreeing with that, refuses the fixture (exit 2) and names the cells: the table and the
fonts calibration renders with would be describing different readers.

THE PASSES, per page: each primary face (DejaVu, Noto) at sans400, sans600 (weight 700),
serif and serif-italic, plus DejaVu Sans Mono at 400 and at 700; each of those ten again with
Looped Thai in Noto Sans Thai's place, over the Thai strings only.
"""
import hashlib
import json
import os
import re
import sys
import unicodedata
from xml.sax.saxutils import escape

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  # noqa: E402
import sfnt  # noqa: E402

tf = c.tf
readers = c.readers
TABLE_COLUMN = {"sans400": "sans400", "sans600": "sans600", "mono400": "mono", "mono700": "mono",
                "serif": "serif", "serif-italic": "serif"}
SHOW = 20
COLUMNS = {
    "sans400": {"generic": "sans-serif", "weight": 400, "style": "normal"},
    "sans600": {"generic": "sans-serif", "weight": 700, "style": "normal"},
    "mono400": {"generic": "monospace", "weight": 400, "style": "normal"},
    "mono700": {"generic": "monospace", "weight": 700, "style": "normal"},
    "serif": {"generic": "serif", "weight": 400, "style": "normal"},
    "serif-italic": {"generic": "serif", "weight": 400, "style": "italic"},
}
CJK_GROUP = 64
BEH, FATHA, ZWJ = "ب", "َ", "‍"
KO, PO, YO, SARA_AM = "ก", "ป", "ญ", "ำ"
KA, RA, VIRAMA, SIGN_I = "क", "र", "्", "ि"
DEVANAGARI_SECONDS = "कतनमयरलवसष"
DEVANAGARI_TRIPLES = ("स्त्र", "क्ष्म",
                      "न्त्र", "ष्ट्र",
                      "ङ्क्ष", "द्ध्य",
                      "ह्म", "ह्य", "ज्ञ",
                      "र्क्ष")
MATH_BLOCKS = ((0x2190, 0x21FF), (0x2200, 0x22FF), (0x2300, 0x23FF), (0x27C0, 0x27FF),
               (0x2900, 0x2AFF), (0x2B00, 0x2BFF))


def blank_cells(text, table):
    """{table column: [cell]}: the characters of a string whose cell the table leaves '-', each as
    `U+XXXX` or, for an Arabic letter, `U+XXXX <form>` under the form its context forces. CJK is
    priced by rule and never listed. Empty when textfit cannot tell a letter's form: it refuses the
    string, which then stays in as an unmeasurable price."""
    chars = [(ch, {}) for ch in text]
    out = {col: [] for col in tf.COLUMNS}
    try:
        forms = tf.arabic_forms(chars, table)
    except tf.Unmeasurable:
        return out
    for k, (ch, _) in enumerate(chars):
        cp = ord(ch)
        if c.is_cjk(cp):
            continue
        for i, col in enumerate(tf.COLUMNS):
            if k in forms:
                if table.forms[cp][forms[k]][i] is None:
                    out[col].append("U+%04X %s" % (cp, forms[k]))
            elif cp not in table or table[cp][i] is None:
                out[col].append("U+%04X" % cp)
    return out


def coverage(table, rows):
    """(cells checked, [problem]): the table's '-' cells against readers.py's readers of every gating
    page, each face's cmap read from the run's own files. See the module docstring."""
    if unicodedata.unidata_version != table.unicode_version:
        c.refuse("Python's unicodedata is Unicode %s and the table declares %s" % (unicodedata.unidata_version,
                                                                                table.unicode_version), 2)
    decomposable = []
    for cp in range(0x110000):
        if readers.in_domain(cp):
            parts = readers.full_decomposition(cp, readers.unicodedata_decomposition)
            if len(parts) > 1:
                decomposable.append((cp, parts))
    stacks = {col: [] for col in tf.COLUMNS}
    domain = set(cp for cp in table if readers.in_domain(cp)) | set(table.joining)
    for page in c.gating_pages(rows):
        page_rows = c.page_pins(page, rows)
        cmaps = c.Cmaps(page_rows, [])
        drawn = {}
        for key in cmaps.files:
            cmap = cmaps.key(key)
            drawn[key] = frozenset(cmap | {cp for cp, parts in decomposable if all(p in cmap for p in parts)})
            domain |= {cp for cp in drawn[key] if readers.in_domain(cp)}
        for col in tf.COLUMNS:
            try:
                for label, keys in readers.column_readers(page_rows, col):
                    stacks[col].append(("%s %s" % (page, label), [drawn[k] for k in keys]))
            except ValueError as e:
                c.refuse("page %s cannot model every reader of column %s: %s" % (page, col, e), 2)
    problems, checked = [], 0
    for cp in sorted(domain):
        row = table.get(cp)
        for i, col in enumerate(tf.COLUMNS):
            lacking = [label for label, faces in stacks[col] if not any(cp in f for f in faces)]
            priced = row is not None and row[i] is not None
            checked += 1
            if priced and lacking:
                problems.append("U+%04X %s is priced and %d reader(s) draw it with no face, first %s"
                                % (cp, col, len(lacking), lacking[0]))
            elif not priced and not lacking:
                problems.append("U+%04X %s is '-' and every reader draws it with some face" % (cp, col))
            if cp in table.joining:
                cells = [table.forms[cp][form][i] for form in tf.FORMS]
                checked += 1
                if any(v is None for v in cells) and any(v is not None for v in cells):
                    problems.append("U+%04X %s: its form cells are partly '-'" % (cp, col))
                elif (cells[0] is not None) == bool(lacking):
                    problems.append("U+%04X %s: its form cells are %s and %d reader(s) draw it with no face"
                                    % (cp, col, "priced" if cells[0] is not None else "'-'", len(lacking)))
    return checked, problems


def main():
    table = tf.load_table()
    checked, problems = coverage(table, c.read_fonts_tsv())
    if problems:
        for p in problems[:SHOW]:
            print("  - %s" % p)
        if len(problems) > SHOW:
            print("  ... and %d more" % (len(problems) - SHOW))
        c.refuse("the table's '-' cells disagree with the readers the staged fonts give in %d of %d cells checked: "
                 "nothing written" % (len(problems), checked), 2)
    print("coverage: %d cells checked against readers.py's readers of every gating page, read from the font bytes; "
          "the table's '-' cells agree both ways" % checked)
    strings, seen, skipped, normalized = [], set(), {}, [0]

    def add(script, kind, text):
        # SVG and textfit both collapse runs of space, tab and newline and drop them at either end, so a
        # spelling holding them is emitted as what is rendered; the character counts would disagree otherwise.
        collapsed = " ".join(t for t in re.split(r"[ \t\r\n]+", text) if t)
        if collapsed != text:
            normalized[0] += 1
            text = collapsed
        if not text or text in seen:
            return
        seen.add(text)
        try:
            tf.recomposition([(ch, {}) for ch in text], table)
        except tf.Unmeasurable:
            skipped.setdefault("recomposable", []).append(" ".join("%04X" % ord(ch) for ch in text))
            return
        strings.append((script, kind, text))

    def rows_in(blocks):
        return [cp for cp in sorted(table) if any(lo <= cp <= hi for lo, hi in blocks)
                and any(v is not None for v in table[cp])]

    # arabic, the earlier fixture's spellings
    for seq in sorted(table.ligatures):
        t = "".join(chr(cp) for cp, _ in seq)
        add("arabic", "ligature isolated", t)
        add("arabic", "ligature final", BEH + t)
        add("arabic", "ligature between", BEH + t + BEH)
        add("arabic", "ligature harakat", t[0] + FATHA + t[1:])
        add("arabic", "ligature harakat final", BEH + t[0] + FATHA + t[1:])
        d = unicodedata.normalize("NFD", t)
        if d != t:
            add("arabic", "ligature decomposed", d)
            add("arabic", "ligature decomposed final", BEH + d)
    for t in ("الله", "اللّه", "اللّٰه"):
        add("arabic", "allah", t)
        add("arabic", "allah final", BEH + t)
    for cp in (0x0759, 0x08AC, 0x08B1):
        add("arabic", "R after D", BEH + chr(cp))
        add("arabic", "R between D", BEH + chr(cp) + BEH)
    for cp in sorted(table.joining):
        ch = chr(cp)
        add("arabic", "letter isol", ch)
        add("arabic", "letter init", ch + ZWJ)
        add("arabic", "letter medi", ZWJ + ch + ZWJ)
        add("arabic", "letter fina", ZWJ + ch)
    for cp in sorted(table.joining):
        d = unicodedata.normalize("NFD", chr(cp))
        if d != chr(cp):
            add("arabic", "decomposed isol", d)
            add("arabic", "decomposed init", d + ZWJ)
            add("arabic", "decomposed medi", ZWJ + d + ZWJ)
            add("arabic", "decomposed fina", ZWJ + d)
    for lam, alef in ((0xFEDF, 0xFE82), (0xFEE0, 0xFE8E), (0xFEDF, 0xFE8E), (0xFEE0, 0xFE82)):
        t = chr(lam) + "ﱞ" + chr(alef)
        add("arabic", "F3 lam+FC5E+alef", t)
        add("arabic", "F3 lam+FC5E+alef final", BEH + t)

    # thai
    thai = rows_in(((0x0E00, 0x0E7F),))
    tones = [cp for cp in thai if 0x0E48 <= cp <= 0x0E4B]
    for cp in thai:
        ch = chr(cp)
        if unicodedata.category(ch) == "Mn":
            add("thai", "thai mark on ko", KO + ch)
            add("thai", "thai mark on po", PO + ch)
            add("thai", "thai mark on yo", YO + ch)
            if cp in (0x0E31, 0x0E34, 0x0E35, 0x0E36, 0x0E37, 0x0E38, 0x0E39):
                for tone in tones:
                    add("thai", "thai vowel and tone", KO + ch + chr(tone))
                    add("thai", "thai vowel and tone on po", PO + ch + chr(tone))
        else:
            add("thai", "thai spacing", ch)
            if 0x0E40 <= cp <= 0x0E44:
                add("thai", "thai leading vowel", ch + KO)
            if cp in (0x0E30, 0x0E32, 0x0E33, 0x0E45):
                add("thai", "thai following vowel", KO + ch)
    for tone in tones:
        add("thai", "thai tone and sara am", KO + chr(tone) + SARA_AM)

    # devanagari
    devanagari = rows_in(((0x0900, 0x097F), (0xA8E0, 0xA8FF)))
    consonants = [chr(cp) for cp in devanagari if 0x0915 <= cp <= 0x0939]
    for cp in devanagari:
        ch = chr(cp)
        if unicodedata.category(ch) in ("Mn", "Mc"):
            if cp != 0x094D:
                add("devanagari", "devanagari sign on ka", KA + ch)
        else:
            add("devanagari", "devanagari spacing", ch)
    for first in consonants:
        for second in DEVANAGARI_SECONDS:
            add("devanagari", "devanagari conjunct", first + VIRAMA + second)
            add("devanagari", "devanagari conjunct and i", first + VIRAMA + second + SIGN_I)
        add("devanagari", "devanagari reph", RA + VIRAMA + first)
        add("devanagari", "devanagari reph and i", RA + VIRAMA + first + SIGN_I)
        add("devanagari", "devanagari dead consonant", first + VIRAMA)
        add("devanagari", "devanagari half form", first + VIRAMA + ZWJ)
    for t in DEVANAGARI_TRIPLES:
        add("devanagari", "devanagari cluster", t)
        add("devanagari", "devanagari cluster and i", t + SIGN_I)

    # math
    for cp in rows_in(MATH_BLOCKS):
        add("math", "math symbol", chr(cp))

    # cjk
    maps = None
    for face in c.read_cjk():
        data = open(os.path.join(c.RUN, "platform", "cjk", face.collection), "rb").read()
        offsets = [o for o in sfnt.faces(data) if sfnt.ps_name(data, o) == face.psname]
        if len(offsets) != 1:
            c.refuse("%s holds %s %d times" % (face.collection, face.psname, len(offsets)), 2)
        got = sfnt.codepoints(data, offsets[0])
        maps = got if maps is None else maps & got
    cjk_cps = sorted(cp for cp in maps if c.is_cjk(cp)
                     and unicodedata.category(chr(cp)) not in ("Mn", "Me", "Mc", "Cc", "Cf", "Cs", "Co", "Cn"))
    cjk = ["".join(chr(cp) for cp in cjk_cps[k:k + CJK_GROUP]) for k in range(0, len(cjk_cps), CJK_GROUP)]

    def price(text, column):
        col = COLUMNS[column]
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 9000 100"><style>'
               '.f { font-family: %s; font-size: %dpx; font-weight: %d; font-style: %s; }'
               '</style><rect x="0" y="0" width="9000" height="100"/>'
               '<text x="10" y="50" class="f">%s</text></svg>'
               % (col["generic"], c.SIZE, col["weight"], col["style"], escape(text)))
        try:
            widths = [t["width"] for t in tf.texts(svg, table)]
        except tf.Unmeasurable as e:
            return "unmeasurable: %s" % e
        return widths[0] if len(widths) == 1 else "unmeasurable: %d rows" % len(widths)

    passes = []
    for looped, subset in (("", "all"), ("-looped", "thai")):
        for face in ("dejavu", "noto"):
            for column in ("sans400", "sans600", "serif", "serif-italic"):
                passes.append({"id": "%s%s/%s" % (face, looped, column), "variant": face + looped,
                               "column": column, "set": subset})
        for column in ("mono400", "mono700"):
            passes.append({"id": "mono%s/%s" % (looped, column), "variant": "dejavu" + looped,
                           "column": column, "set": subset})
    records = []
    for i, (script, kind, text) in enumerate(strings):
        cps = " ".join("%04X" % ord(ch) for ch in text)
        prices = {column: price(text, column) for column in COLUMNS}
        blank = blank_cells(text, table)
        columns = []
        for col in COLUMNS:
            cells = blank[TABLE_COLUMN[col]]
            if not cells:
                columns.append(col)
                continue
            reason = "'-' form cell" if any(" " in cell for cell in cells) else "'-' codepoint cell"
            skipped.setdefault("%s, %s" % (script, reason), []).append("%s %s: %s" % (cps, col, ", ".join(cells)))
        records.append({"i": i, "script": script, "kind": kind, "text": text, "cps": cps,
                        "sets": ["all", "thai"] if script == "thai" else ["all"], "columns": columns,
                        "price": prices})
    out = {
        # cjk_em is textfit's PRICE per CJK character; cjk_advance_em bounds each character's own advance,
        # which the renderer measures with font-kerning:none (sub_nokern).
        "size": c.SIZE, "tolerance": c.TOLERANCE, "cjk_em": tf.CJK_EM, "cjk_advance_em": c.CJK_ADVANCE_EM,
        "coverage": {"cells_checked": checked, "disagreements": 0},
        "table_sha256": hashlib.sha256(open(tf.TABLE_PATH, "rb").read()).hexdigest(),
        "unicode_version": table.unicode_version, "columns": COLUMNS, "passes": passes,
        "strings": records,
        "cjk": [{"i": i, "text": text, "cps": " ".join("%04X" % ord(ch) for ch in text),
                 "price": {column: price(text, column) for column in COLUMNS}}
                for i, text in enumerate(cjk)],
        "skipped": {k: {"count": len(v), "cps": v} for k, v in skipped.items()},
        "whitespace_collapsed": normalized[0],
    }
    os.makedirs(os.path.join(c.RUN, "fixture"), exist_ok=True)
    with open(os.path.join(c.RUN, "fixture", "strings.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, ensure_ascii=False)
    scripts = {}
    for script, _, _ in strings:
        scripts[script] = scripts.get(script, 0) + 1
    bad = sum(1 for s in out["strings"] for col in s["columns"] if isinstance(s["price"][col], str)) + \
        sum(1 for g in out["cjk"] for v in g["price"].values() if isinstance(v, str))
    print("fixture: %d strings %s, %d CJK groups over %d codepoints, %d passes; unmeasurable prices %d; skipped %s"
          % (len(strings), scripts, len(cjk), len(cjk_cps), len(passes), bad,
             {k: len(v) for k, v in skipped.items()} or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
