"""Calibration's CJK font data (ROADMAP O189, panel 2's QC ruling): how wide the declared CJK faces
can draw a CJK character, read from the faces' own tables rather than from a render.

Runs in the pinned Debian image (calibrate.sh's `cjk-font-data` step) with python3-fonttools and
unicode-data installed at exactly the versions gen_advances.sh pins, `architecture/` read-only at /a
and the run folder at /r. The versions come from /r/fetch/cjk-font-data-packages.txt, which
`fetch.py plan` writes from gen_advances.sh through pins.apt_pins, and are checked again here
against what dpkg installed. Categories come from the pinned UnicodeData.txt through
gen_advances.Unicode, the reader the table is generated with.

  python3 cjk_font_data.py

For each face cjk.tsv declares, it reads the collection under /r/platform/cjk/ only after its
sha256 equals cjk.tsv's, selects the face by PostScript name, and computes:

  reachable   the cmap glyphs of every ASSIGNED codepoint of textfit.CJK_BLOCKS, closed over the
              default-on GSUB features of every script and language system: single, multiple,
              alternate, ligature (when every component is reachable) and reverse-chaining
              outputs, through the lookups a contextual, chaining or extension lookup names;
  advance     the widest hmtx advance over that set, in em, and every glyph over 1 em;
  gpos        every positive XAdvance the default-on GPOS features apply to that set: SinglePos
              values; PairPos Value1 and Value2 in both formats, ClassDef class 0 included, with
              both glyphs reachable; through contextual, chaining and extension lookups. The
              largest, with its feature, lookup and glyphs. Cursive lookups are listed, because a
              cursive attachment moves an advance. As a residual figure, the widest sum one glyph
              can collect: its largest SinglePos value, plus the largest Value2 it takes as the
              second of a pair, plus the largest Value1 it takes as the first; and the same summed
              over every lookup that can adjust it.
  off         every non-default-on GPOS feature that carries a positive XAdvance over the set,
              as information.

A feature is default-on when some HarfBuzz shaper applies it without being asked, is off when no
shaper does unless asked, and any other feature REFUSES the run, as gen_advances.py refuses one.
It writes /r/platform/cjk-font-data.json and prints the figures. Exit 0 when written, 1 on any
refusal.
"""
import collections
import json
import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  # noqa: E402
import gen_advances as g  # noqa: E402  the pinned Unicode reader and the off-by-default feature list
from fontTools.ttLib import TTCollection  # noqa: E402

PACKAGES = os.path.join(c.RUN, "fetch", "cjk-font-data-packages.txt")
OUT = c.CJK_FONT_DATA

# Features some HarfBuzz shaper applies unasked (hb-ot-shape.cc common and horizontal features,
# direction and fraction features, and the Arabic, Indic, USE, Khmer, Myanmar and Hangul shapers).
# A superset is the conservative side: more reachable glyphs and more adjustments, never fewer.
DEFAULT_ON_GSUB = frozenset(
    "rvrn ltra ltrm rtla rtlm frac numr dnom ccmp locl rlig calt clig liga rclt "
    "isol fina fin2 fin3 medi med2 init stch mset "
    "nukt akhn rphf rkrf pref blwf abvf half pstf vatu cjct pres abvs blws psts haln cfar "
    "ljmo vjmo tjmo".split())
DEFAULT_ON_GPOS = frozenset("kern dist curs mark mkmk abvm blwm".split())
# Off unless asked, beyond gen_advances.OFF_BY_DEFAULT: the vertical and alternate-width
# positioning features, which apply only in vertical text or on request, and the size feature,
# which carries no lookup.
EXTRA_OFF = frozenset("halt vkrn valt vchw chws size".split())
OFF = g.OFF_BY_DEFAULT | EXTRA_OFF


def refuse(message):
    print("REFUSED: %s" % message)
    sys.exit(1)


def installed_versions():
    """{package: version} for the packages this step was asked to install, each checked against
    gen_advances.sh's pin and against dpkg."""
    script = open(os.path.join(c.TEXTFIT, "gen_advances.sh"), encoding="utf-8").read()
    apt, problems = c.pins.apt_pins(script)
    if problems:
        refuse("gen_advances.sh: %s" % "; ".join(problems))
    if not os.path.isfile(PACKAGES):
        refuse("%s is absent: run the plan step first" % PACKAGES)
    asked = dict(line.split("=", 1) for line in open(PACKAGES, encoding="utf-8").read().split() if line)
    if set(asked) != {"python3-fonttools", "unicode-data"}:
        refuse("%s names %s, expected python3-fonttools and unicode-data" % (PACKAGES, sorted(asked)))
    out = {}
    for name, version in sorted(asked.items()):
        if apt.get(name) != version:
            refuse("%s asks for %s=%s and gen_advances.sh pins %s" % (PACKAGES, name, version, apt.get(name)))
        got = g.dpkg_query(["-W", "-f=${Version}", name]).strip()
        if got != version:
            refuse("dpkg reports %s %s, and the pin is %s" % (name, got, version))
        out[name] = got
    return out


def nested(st, chain, set_prefix, record):
    """The lookup indices a contextual or chaining subtable names."""
    head = "Chain" if chain else ""
    try:
        if st.Format == 1:
            sets = getattr(st, head + set_prefix + "RuleSet") or []
            rules = [r for s in sets if s for r in (getattr(s, head + set_prefix + "Rule") or [])]
        elif st.Format == 2:
            sets = getattr(st, head + set_prefix + "ClassSet") or []
            rules = [r for s in sets if s for r in (getattr(s, head + set_prefix + "ClassRule") or [])]
        elif st.Format == 3:
            rules = [st]
        else:
            refuse("contextual format %d is not modelled" % st.Format)
        return [rec.LookupListIndex for r in rules for rec in (getattr(r, record) or [])]
    except AttributeError as e:
        refuse("a contextual subtable does not carry the fields this reader expects: %s" % e)


def features(table, face, on):
    """({tag: [lookup index]} over every script and language system, required features included
    as default-on, [tags off by default]). Refuses a tag it cannot classify."""
    if getattr(table, "FeatureVariations", None) is not None:
        refuse("%s carries feature variations, which are not modelled" % face)
    reached, off = collections.defaultdict(set), set()
    for script in table.ScriptList.ScriptRecord:
        systems = [script.Script.DefaultLangSys] + [r.LangSys for r in script.Script.LangSysRecord]
        for langsys in (s for s in systems if s is not None):
            required = [] if langsys.ReqFeatureIndex == 0xFFFF else [langsys.ReqFeatureIndex]
            for index in list(langsys.FeatureIndex) + required:
                record = table.FeatureList.FeatureRecord[index]
                tag = record.FeatureTag
                if tag in on or index in required:
                    reached[tag] |= set(record.Feature.LookupListIndex)
                elif tag in OFF:
                    off.add(tag)
                else:
                    refuse("%s: feature %s is neither a default-on feature nor one off by default" % (face, tag))
    return reached, sorted(off)


def reach(table, starts, subtables_of):
    """{lookup index: [features reaching it]} closed over nested lookups."""
    out = collections.defaultdict(set)
    todo = [(i, tag) for tag, idx in starts.items() for i in idx]
    while todo:
        index, tag = todo.pop()
        if tag in out[index]:
            continue
        out[index].add(tag)
        for ref in subtables_of(index)[-1]:
            todo.append((ref, tag))
    return out


def gsub_parser(gsub, face):
    memo = {}

    def parse(index):
        if index not in memo:
            maps, ligatures, refs = collections.defaultdict(set), [], []
            lookup = gsub.LookupList.Lookup[index]
            for st in lookup.SubTable:
                kind = lookup.LookupType
                if kind == 7:
                    kind, st = st.ExtensionLookupType, st.ExtSubTable
                if kind == 1:
                    for a, b in st.mapping.items():
                        maps[a].add(b)
                elif kind in (2, 3):
                    for a, bs in (st.mapping if kind == 2 else st.alternates).items():
                        maps[a].update(bs)
                elif kind == 4:
                    for first, group in st.ligatures.items():
                        for lig in group:
                            ligatures.append((lig.LigGlyph, [first] + list(lig.Component)))
                elif kind in (5, 6):
                    refs += nested(st, kind == 6, "Sub", "SubstLookupRecord")
                elif kind == 8:
                    for a, b in zip(st.Coverage.glyphs, st.Substitute):
                        maps[a].add(b)
                else:
                    refuse("%s: GSUB lookup %d is type %d, which is not modelled" % (face, index, kind))
            memo[index] = (maps, ligatures, refs)
        return memo[index]
    return parse


def gpos_parser(gpos, face):
    memo = {}

    def parse(index):
        if index not in memo:
            parts, refs = [], []
            lookup = gpos.LookupList.Lookup[index]
            for st in lookup.SubTable:
                kind = lookup.LookupType
                if kind == 9:
                    kind, st = st.ExtensionLookupType, st.ExtSubTable
                if kind in (1, 2, 3):
                    parts.append((kind, st))
                elif kind in (4, 5, 6):
                    continue                        # anchors: offsets, never an advance
                elif kind in (7, 8):
                    refs += nested(st, kind == 8, "Pos", "PosLookupRecord")
                else:
                    refuse("%s: GPOS lookup %d is type %d, which is not modelled" % (face, index, kind))
            memo[index] = (parts, refs)
        return memo[index]
    return parse


def xadv(value):
    return (getattr(value, "XAdvance", 0) or 0) if value is not None else 0


def adjustments(parse, lookups, glyphs):
    """(candidates, cursive, {glyph: {role: max}}, {glyph: {lookup: max}}): every positive XAdvance
    the lookups apply to reachable glyphs. A candidate is (units, lookup, kind, glyphs)."""
    candidates, cursive = [], []
    role = collections.defaultdict(lambda: collections.defaultdict(int))
    per_lookup = collections.defaultdict(lambda: collections.defaultdict(int))

    def note(units, index, kind, gl, who, part):
        if units > 0:
            candidates.append((units, index, kind, gl))
            role[who][part] = max(role[who][part], units)
            per_lookup[who][index] = max(per_lookup[who][index], units)

    for index in sorted(lookups):
        for kind, st in parse(index)[0]:
            if kind == 1:
                covered = st.Coverage.glyphs
                for k, gl in enumerate(covered):
                    if gl in glyphs:
                        value = st.Value if st.Format == 1 else st.Value[k]
                        note(xadv(value), index, "SinglePos", gl, gl, "single")
            elif kind == 2 and st.Format == 1:
                for k, first in enumerate(st.Coverage.glyphs):
                    if first not in glyphs:
                        continue
                    for rec in st.PairSet[k].PairValueRecord:
                        if rec.SecondGlyph in glyphs:
                            pair = "%s %s" % (first, rec.SecondGlyph)
                            note(xadv(rec.Value1), index, "PairPos1 Value1", pair, first, "to_right")
                            note(xadv(rec.Value2), index, "PairPos1 Value2", pair, rec.SecondGlyph, "from_left")
            elif kind == 2 and st.Format == 2:
                cd1, cd2 = st.ClassDef1.classDefs, st.ClassDef2.classDefs
                firsts, seconds = collections.defaultdict(list), collections.defaultdict(list)
                for gl in st.Coverage.glyphs:
                    if gl in glyphs:
                        firsts[cd1.get(gl, 0)].append(gl)
                for gl in glyphs:
                    seconds[cd2.get(gl, 0)].append(gl)
                for c1, f_glyphs in firsts.items():
                    if c1 >= len(st.Class1Record):
                        refuse("PairPos lookup %d names class %d past its Class1Record" % (index, c1))
                    records = st.Class1Record[c1].Class2Record
                    for c2, s_glyphs in seconds.items():
                        if c2 >= len(records):
                            refuse("PairPos lookup %d names class %d past its Class2Record" % (index, c2))
                        v1, v2 = xadv(records[c2].Value1), xadv(records[c2].Value2)
                        if v1 <= 0 and v2 <= 0:
                            continue
                        pair = "class %d (%s) x class %d (%s)" % (c1, f_glyphs[0], c2, s_glyphs[0])
                        if v1 > 0:
                            candidates.append((v1, index, "PairPos2 Value1", pair))
                            for gl in f_glyphs:
                                role[gl]["to_right"] = max(role[gl]["to_right"], v1)
                                per_lookup[gl][index] = max(per_lookup[gl][index], v1)
                        if v2 > 0:
                            candidates.append((v2, index, "PairPos2 Value2", pair))
                            for gl in s_glyphs:
                                role[gl]["from_left"] = max(role[gl]["from_left"], v2)
                                per_lookup[gl][index] = max(per_lookup[gl][index], v2)
            elif kind == 3:
                hits = [gl for gl in st.Coverage.glyphs if gl in glyphs]
                cursive.append({"lookup": index, "covered_reachable": len(hits)})
    return candidates, cursive, role, per_lookup


def face_data(face, assigned, versions):
    path = os.path.join(c.RUN, "platform", "cjk", face.collection)
    if not os.path.isfile(path):
        refuse("%s is absent: run the platform step first" % path)
    got = c.sha256_file(path)
    if got != face.sha256:
        refuse("%s has sha256 %s, and cjk.tsv declares %s" % (path, got, face.sha256))
    fonts = [f for f in TTCollection(path).fonts if f["name"].getDebugName(6) == face.psname]
    if len(fonts) != 1:
        refuse("%s holds %s %d times" % (path, face.psname, len(fonts)))
    font = fonts[0]
    upm = font["head"].unitsPerEm
    hmtx = font["hmtx"].metrics
    cmap = font.getBestCmap()
    start = {cmap[cp] for cp in assigned if cp in cmap}
    unmapped = [cp for cp in assigned if cp not in cmap]

    gsub = font["GSUB"].table if "GSUB" in font else None
    glyphs, sub_on, sub_off, sub_lookups = set(start), {}, [], {}
    if gsub is not None:
        sub_on, sub_off = features(gsub, face.psname, DEFAULT_ON_GSUB)
        parse = gsub_parser(gsub, face.psname)
        sub_lookups = reach(gsub, sub_on, parse)
        changed = True
        while changed:
            changed = False
            for index in sorted(sub_lookups):
                maps, ligatures, _ = parse(index)
                for a, bs in maps.items():
                    if a in glyphs and not bs <= glyphs:
                        glyphs |= bs
                        changed = True
                for lig, comps in ligatures:
                    if lig not in glyphs and all(x in glyphs for x in comps):
                        glyphs.add(lig)
                        changed = True
    widest = max(glyphs, key=lambda gl: (hmtx[gl][0], gl))
    over = sorted(([gl, hmtx[gl][0] / upm] for gl in glyphs if hmtx[gl][0] > upm), key=lambda x: (-x[1], x[0]))

    gpos = font["GPOS"].table if "GPOS" in font else None
    result = {"max_positive": None, "combined": None, "combined_every_lookup": None, "cursive_lookups": [],
              "default_on": [], "off_by_default": [], "lookups": 0, "non_default_positive": []}
    if gpos is not None:
        pos_on, pos_off = features(gpos, face.psname, DEFAULT_ON_GPOS)
        parse = gpos_parser(gpos, face.psname)
        lookups = reach(gpos, pos_on, parse)
        candidates, cursive, role, per_lookup = adjustments(parse, lookups, glyphs)
        result.update(default_on=sorted(pos_on), off_by_default=pos_off, lookups=len(lookups), cursive_lookups=cursive)
        if candidates:
            units, index, kind, gl = max(candidates, key=lambda x: (x[0], -x[1], x[2], x[3]))
            result["max_positive"] = {"units": units, "em": units / upm, "feature": " ".join(sorted(lookups[index])),
                                      "lookup": index, "kind": kind, "glyphs": gl,
                                      "candidates": len(candidates)}
        if role:
            gl = max(role, key=lambda x: (sum(role[x].values()), x))
            total = sum(role[gl].values())
            result["combined"] = {"units": total, "em": total / upm, "glyph": gl, "single": role[gl]["single"],
                                  "from_left": role[gl]["from_left"], "to_right": role[gl]["to_right"]}
            gl = max(per_lookup, key=lambda x: (sum(per_lookup[x].values()), x))
            total = sum(per_lookup[gl].values())
            result["combined_every_lookup"] = {"units": total, "em": total / upm, "glyph": gl,
                                               "lookups": dict(sorted(per_lookup[gl].items()))}
        # Information only: positive adjustments behind features no shaper applies unasked.
        off_starts = collections.defaultdict(set)
        for script in gpos.ScriptList.ScriptRecord:
            systems = [script.Script.DefaultLangSys] + [r.LangSys for r in script.Script.LangSysRecord]
            for langsys in (s for s in systems if s is not None):
                for index in langsys.FeatureIndex:
                    record = gpos.FeatureList.FeatureRecord[index]
                    if record.FeatureTag not in pos_on:
                        off_starts[record.FeatureTag] |= set(record.Feature.LookupListIndex)
        for tag in sorted(off_starts):
            found = adjustments(parse, reach(gpos, {tag: off_starts[tag]}, parse), glyphs)[0]
            if found:
                units, index, kind, gl = max(found, key=lambda x: (x[0], -x[1], x[2], x[3]))
                result["non_default_positive"].append({"feature": tag, "units": units, "em": units / upm,
                                                       "lookup": index, "kind": kind, "glyphs": gl})
    return {"psname": face.psname, "collection": face.collection, "sha256": got, "upm": upm,
            "assigned_cjk": len(assigned), "mapped_assigned": len(assigned) - len(unmapped),
            "unmapped_assigned": g.ranges(unmapped),
            "gsub": {"default_on": sorted(sub_on), "off_by_default": sub_off, "lookups": len(sub_lookups),
                     "cmap_glyphs": len(start), "reachable_glyphs": len(glyphs)},
            "advance": {"max_units": hmtx[widest][0], "max_em": hmtx[widest][0] / upm, "max_glyph": widest,
                        "over_1em": over},
            "gpos": result}


def main():
    versions = installed_versions()
    unicode = g.Unicode(versions["unicode-data"])
    assigned = [cp for lo, hi in c.tf.CJK_BLOCKS for cp in range(lo, hi + 1) if unicode.category(cp) != "Cn"]
    if not assigned:
        refuse("no assigned codepoint in textfit.CJK_BLOCKS: the categories were not read")
    faces = [face_data(face, assigned, versions) for face in c.read_cjk()]
    kerns = [f["gpos"]["max_positive"]["em"] for f in faces if f["gpos"]["max_positive"]]
    out = {"packages": versions, "unicode_version": unicode.version,
           "cjk_blocks": ["%04X-%04X" % b for b in c.tf.CJK_BLOCKS],
           "default_on_gsub": sorted(DEFAULT_ON_GSUB), "default_on_gpos": sorted(DEFAULT_ON_GPOS),
           "faces": faces,
           "max_positive_em": max(kerns) if kerns else 0.0,
           "max_advance_em": max(f["advance"]["max_em"] for f in faces)}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".part"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    os.replace(tmp, OUT)
    print("cjk-font-data: %s, Unicode %s, %d assigned codepoints in textfit.CJK_BLOCKS"
          % (", ".join("%s=%s" % kv for kv in sorted(versions.items())), unicode.version, len(assigned)))
    for f in faces:
        gp = f["gpos"]
        print("  %s (%s, sha256 %s, upm %d): %d of the assigned codepoints mapped; GSUB %s over %d lookups: "
              "%d cmap glyphs -> %d reachable; widest advance %.4f em (%s), %d glyphs over 1 em"
              % (f["psname"], f["collection"], f["sha256"][:16], f["upm"], f["mapped_assigned"],
                 " ".join(f["gsub"]["default_on"]) or "none", f["gsub"]["lookups"], f["gsub"]["cmap_glyphs"],
                 f["gsub"]["reachable_glyphs"], f["advance"]["max_em"], f["advance"]["max_glyph"],
                 len(f["advance"]["over_1em"])))
        print("    GPOS default-on %s over %d lookups; off by default %s; cursive lookups %s"
              % (" ".join(gp["default_on"]) or "none", gp["lookups"], " ".join(gp["off_by_default"]) or "none",
                 gp["cursive_lookups"] or "none"))
        print("    largest positive default-on XAdvance: %s" % (
            "%+d units = %+.4f em (feature %s, lookup %d, %s, %s; %d positive candidates)"
            % (gp["max_positive"]["units"], gp["max_positive"]["em"], gp["max_positive"]["feature"],
               gp["max_positive"]["lookup"], gp["max_positive"]["kind"], gp["max_positive"]["glyphs"],
               gp["max_positive"]["candidates"]) if gp["max_positive"] else "none"))
        if gp["combined"]:
            print("    residual, one glyph's largest single + Value2 + Value1: %+d units = %+.4f em (%s: %s); "
                  "summed over every lookup: %+d units = %+.4f em (%s: %s)"
                  % (gp["combined"]["units"], gp["combined"]["em"], gp["combined"]["glyph"],
                     {k: gp["combined"][k] for k in ("single", "from_left", "to_right")},
                     gp["combined_every_lookup"]["units"], gp["combined_every_lookup"]["em"],
                     gp["combined_every_lookup"]["glyph"], gp["combined_every_lookup"]["lookups"]))
        print("    non-default-on features with a positive XAdvance: %s" % (
            "; ".join("%s %+d units (lookup %d, %s, %s)" % (x["feature"], x["units"], x["lookup"], x["kind"], x["glyphs"])
                      for x in gp["non_default_positive"]) or "none"))
    print("largest positive default-on adjustment %.4f em, widest reachable advance %.4f em -> %s"
          % (out["max_positive_em"], out["max_advance_em"], OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
