"""Calibration's fixture judge (ROADMAP O189, V3 and panel 2). python:3.12-slim, stdlib only,
`architecture/` read-only at /a, the run folder at /r.

  python3 judge_fixture.py            every gating page in /r/pages.json
  python3 judge_fixture.py <page>...  the pages named

The run FAILS, per page and per pass, on:
  over          a string rendering more than 0.05 px wider than textfit prices it;
  unmeasurable  a price textfit could not give (the generator keeps every such string in);
  platform      a font CDP reports that is neither an embedded face of the page (a web font
                whose PostScript name maps to an embedded file) nor a declared CJK face;
  coverage      an embedded face of the page — a header face of its slot, or DejaVu from
                debian — that no row used;
  unmapped      a codepoint of a row, other than a default-ignorable one, that no face CDP reports
                for the row maps, itself or by its full canonical decomposition, read from the
                run's own sha256-checked files (a declared CJK face from its collection). CDP
                credits a .notdef to the face that drew it, so this is how a box is seen. A font
                the judge cannot read — a platform font — maps nothing here and also fails platform;
  cjk-foreign   a declared CJK face drawing more glyphs in a row than the row has codepoints in
                textfit's CJK blocks;
  faces         the faces the reader model predicts for a row (common.py's clusters and
                readers.py's stacks) differing from the faces CDP reports;
  cjk-em        a CJK character whose own advance, rendered with font-kerning:none, exceeds 1 em +
                0.05 px (a row measured without font-kerning:none is a join failure);
  cjk-font-data the declared CJK faces' data (/r/platform/cjk-font-data.json) absent, or describing
                a collection other than the one cjk.tsv declares and the run holds;
  cjk-kern      textfit.CJK_EM below 1 + the largest positive default-on adjustment in that data;
  cjk-advance   a glyph reachable from a CJK codepoint advancing more than 1 em in that data;
  stale         strings.json priced against another table than the tree's, or another CJK_EM;
  identity      an embedded file whose sha256, taken from the bytes embedded, is not the
                pinned one, a pinned file not embedded, or a file embedded twice;
  cjk-identity  a declared CJK face fontconfig does not report once, in its declared collection,
                with its declared sha256;
  join          a declared (pass, string) with no render row, a row nobody declared, a
                duplicate, or a character count other than the string's.

PREMISE ARMS, before any verdict is believed: a copy of the real data with one planted defect
per category must fail on that category more often than the real data does. An arm that does not
is a PREMISE FAILURE (exit 2), because a judge that cannot see a defect reports the same thing as
a clean run. The plants: an over-tolerance row, a platform font, a removed face, an unmeasurable
price, a join gap, a CJK advance over 1 em, a changed digest, a codepoint removed from the cmap of
the faces a clean row reports, a CJK glyph count beyond a clean row's CJK codepoints, the face a
clean row was predicted to draw with removed from its stack, font data whose adjustment exceeds
CJK_EM, font data with a glyph over 1 em, absent font data, and a strings.json priced against
another table.

Exit 0 clean, 1 on any failure, 2 on a premise failure. Figures go to stdout and /r/fixture/judge.json.
"""
import collections
import copy
import json
import os
import sys
import unicodedata

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  # noqa: E402

tf, readers = c.tf, c.readers
SHOW = 12


def load(pages):
    fx = json.load(open(os.path.join(c.RUN, "fixture", "strings.json"), encoding="utf-8"))
    rows_tsv = c.read_fonts_tsv()
    _, canary_rows = c.read_canary()
    cjk = c.read_cjk()
    try:
        font_data, font_data_error = c.read_cjk_font_data(), None
    except (OSError, ValueError) as e:
        font_data, font_data_error = None, str(e)
    data = {"fx": fx, "pages": {}, "cjk": cjk, "cjk_weights": c.cjk_by_weight(cjk),
            "fc": c.read_tsv(os.path.join(c.RUN, "platform", "fc-list.tsv"), c.FC_FIELDS),
            "table_sha256": c.sha256_file(tf.TABLE_PATH), "font_data": font_data,
            "font_data_error": font_data_error, "drop": {}, "memo": {}}
    for page in pages:
        base = os.path.join(c.RUN, "fixture", page)
        rows, dups = {}, []
        with open(os.path.join(base, "render.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                key = (r["pass"], r["kind"], r["i"])
                if key in rows:
                    dups.append(key)
                rows[key] = r
        expected = c.page_pins(page, rows_tsv, canary_rows)
        data["pages"][page] = {"rows": rows, "dups": dups, "expected": expected, "cmaps": c.Cmaps(expected, cjk),
                               "embedded": c.read_tsv(os.path.join(base, "embedded.tsv"), c.EMBEDDED_FIELDS)}
    return data


def units(text):
    return len(text.encode("utf-16-le")) // 2


def family(ps):
    return c.NO_FACE if ps == c.NO_FACE else readers.group_of(ps)[0]


def row_checks(data, page, pd, p, kind, s, r, psmap, pairs):
    """(unmapped codepoints, CJK glyphs beyond the row's CJK codepoints, predicted, reported) for one row."""
    fx, col = data["fx"], data["fx"]["columns"][p["column"]]
    style = (col["generic"], col["weight"], col["style"])
    cmaps = pd["cmaps"]
    drop = tuple(sorted(data["drop"].get((page, p["variant"]), ())))
    signature = tuple(sorted((k, tuple(sorted(v))) for k, v in cmaps.drop.items()))
    fonts = tuple(sorted((f["ps"], f["custom"], f["glyphs"]) for f in r["fonts"]))
    memo = data["memo"]
    key = ("row", page, p["variant"], style, s["text"], fonts, drop, signature)
    if key not in memo:
        stack_key = ("stack", page, p["variant"], style, drop)
        if stack_key not in memo:
            memo[stack_key] = [k for k in readers.reader_faces(pd["expected"], p["variant"], *style) if k not in drop]
        key_ps = {v[0]: ps for ps, v in psmap.items()}
        chars = [(ch, style) for ch in s["text"]]
        predicted = c.predicted_faces(chars, lambda *_: memo[stack_key], cmaps, key_ps, data["cjk_weights"])
        memo[key] = (c.unmapped(s["text"], r["fonts"], cmaps, psmap), c.cjk_foreign(r["fonts"], s["text"], pairs),
                     predicted, c.reported_faces(r["fonts"], pairs))
    return memo[key]


def verdict(data):
    fx = data["fx"]
    tol, em = fx["tolerance"], fx["size"] * c.CJK_ADVANCE_EM
    failures, figures = [], {}
    f, pairs = c.cjk_pairs(data["cjk"], data["fc"])
    failures += f
    if fx["table_sha256"] != data["table_sha256"]:
        failures.append(("stale", "strings.json was priced against table sha256 %s and the tree's table is %s"
                         % (fx["table_sha256"], data["table_sha256"])))
    if fx["cjk_em"] != tf.CJK_EM:
        failures.append(("stale", "strings.json was priced with CJK_EM %s and textfit declares %s" % (fx["cjk_em"], tf.CJK_EM)))
    if data["font_data_error"]:
        failures.append(("cjk-font-data", "%s cannot be read: %s" % (c.CJK_FONT_DATA, data["font_data_error"])))
    else:
        failures += c.cjk_font_data_verdict(data["cjk"], data["font_data"], tf.CJK_EM)
    for page, pd in data["pages"].items():
        f, psmap = c.identity(page, pd["expected"], pd["embedded"])
        failures += f
        failures += [("join", "page %s: duplicate row %s" % (page, key)) for key in pd["dups"]]
        rows, declared = pd["rows"], set()
        used, cjk_faces = collections.Counter(), collections.Counter()
        fig = {"passes": {}, "coverage": {}, "cjk": {}, "faces_groups": collections.Counter(),
               "unmapped_groups": collections.Counter()}
        glyphs, worst_glyph = 0, None
        for p in fx["passes"]:
            col = p["column"]
            pf = {"strings": 0, "over": 0, "unmeasurable": 0, "worst": None}
            items = [("string", s) for s in fx["strings"] if p["set"] in s["sets"] and col in s["columns"]]
            if p["set"] == "all":
                items += [("cjk", g) for g in fx["cjk"]]
            no_nokern = 0
            for kind, s in items:
                key = (p["id"], kind, s["i"])
                declared.add(key)
                r = rows.get(key)
                label = "page %s pass %s %s %d [%s]" % (page, p["id"], kind, s["i"], s["cps"][:48])
                if r is None:
                    failures.append(("join", "%s: no render row" % label))
                    continue
                if r["n"] != units(s["text"]):
                    failures.append(("join", "%s: rendered %d characters, the string has %d" % (label, r["n"], units(s["text"]))))
                for font in r["fonts"]:
                    k = c.classify(font, psmap, pairs)
                    if k is None:
                        failures.append(("platform", "%s: %s font %s (%s)" % (
                            label, "an unknown web" if font["custom"] else "a platform", font["ps"], font["family"])))
                    elif k == "embedded":
                        used[font["ps"]] += 1
                    else:
                        cjk_faces[font["ps"]] += font["glyphs"]
                lost, foreign, predicted, reported = row_checks(data, page, pd, p, kind, s, r, psmap, pairs)
                script = s.get("script", "cjk")
                if lost:
                    failures.append(("unmapped", "%s: %s mapped by none of the faces CDP reports, %s" % (
                        label, " ".join("U+%04X" % cp for cp in lost), sorted(reported))))
                    fig["unmapped_groups"][(p["id"].split("/")[0], script, " ".join(sorted(family(x) for x in reported)))] += 1
                if foreign:
                    failures.append(("cjk-foreign", "%s: a declared CJK face drew %d glyph(s) beyond the row's %d CJK "
                                     "codepoints" % (label, foreign, c.cjk_count(s["text"]))))
                if predicted != reported:
                    failures.append(("faces", "%s: the reader model predicts %s, CDP reports %s"
                                     % (label, sorted(predicted), sorted(reported))))
                    fig["faces_groups"][(p["id"].split("/")[0], script,
                                         "+".join(sorted({family(x) for x in predicted})),
                                         "+".join(sorted({family(x) for x in reported})))] += 1
                pf["strings"] += 1
                price = s["price"][col]
                if isinstance(price, str):
                    pf["unmeasurable"] += 1
                    failures.append(("unmeasurable", "%s: %s" % (label, price)))
                    continue
                d = r["w"] - price
                if pf["worst"] is None or d > pf["worst"][0]:
                    pf["worst"] = (round(d, 4), s.get("kind", "cjk group"), s["cps"][:48])
                if d > tol:
                    pf["over"] += 1
                    failures.append(("over", "%s %s: renders %.3f px, priced %.3f px (%+.3f)"
                                     % (label, s.get("kind", "cjk group"), r["w"], price, d)))
                if kind == "cjk":
                    sub = r.get("sub_nokern")
                    cps = s["cps"].split()
                    if sub is None:
                        no_nokern += 1
                        continue
                    if len(sub) != len(cps):
                        failures.append(("join", "%s: %d character advances for %d characters" % (label, len(sub), len(cps))))
                    for cp, advance in zip(cps, sub):
                        glyphs += 1
                        dd = advance - em
                        if worst_glyph is None or dd > worst_glyph[0]:
                            worst_glyph = (round(dd, 4), cp, p["id"])
                        if dd > tol:
                            failures.append(("cjk-em", "%s: U+%s advances %.3f px with font-kerning:none, over 1 em "
                                             "(%.1f px) by %.3f" % (label, cp, advance, em, dd)))
            if no_nokern:
                failures.append(("join", "page %s pass %s: %d CJK rows carry no sub_nokern, so no advance was measured "
                                 "with font-kerning:none (rendered by an earlier render.js)" % (page, p["id"], no_nokern)))
            fig["passes"][p["id"]] = pf
        for key in sorted(set(rows) - declared):
            failures.append(("join", "page %s: render row %s was not declared by strings.json" % (page, key)))
        for e in pd["embedded"]:
            if e["page"] != page:
                continue
            fig["coverage"][e["psname"]] = {"key": e["key"], "sha256": e["sha256"], "rows": used.get(e["psname"], 0)}
            if used.get(e["psname"], 0) == 0:
                failures.append(("coverage", "page %s: %s (%s) was used by no fixture row" % (page, e["key"], e["psname"])))
        fig["cjk"] = {"groups": len(fx["cjk"]), "codepoints": sum(len(g["cps"].split()) for g in fx["cjk"]),
                      "advances_measured": glyphs, "worst_advance_minus_em": worst_glyph,
                      "glyphs_by_face": dict(cjk_faces)}
        figures[page] = fig
    return failures, figures


def counts(failures):
    return collections.Counter(cat for cat, _ in failures)


def arms(data, real):
    """[(arm, expected category, fired, detail)] — each arm plants one defect in a copy."""
    fx = data["fx"]
    page = next(iter(data["pages"]))
    pd = data["pages"][page]
    names = {e["psname"] for e in pd["embedded"] if e["page"] == page}
    _, psmap = c.identity(page, pd["expected"], pd["embedded"])
    _, pairs = c.cjk_pairs(data["cjk"], data["fc"])

    def clean(p, s):
        """A row the real verdict holds nothing against, so a planted defect can only add a failure."""
        col = p["column"]
        r = pd["rows"].get((p["id"], "string", s["i"]))
        price = s["price"][col]
        if not (r is not None and not isinstance(price, str) and r["n"] == units(s["text"])
                and r["w"] - price <= fx["tolerance"] and all(f["custom"] and f["ps"] in names for f in r["fonts"])
                and any(not c.is_default_ignorable(ord(ch)) for ch in s["text"])):
            return False
        lost, foreign, predicted, reported = row_checks(data, page, pd, p, "string", s, r, psmap, pairs)
        return not lost and not foreign and predicted == reported and c.NO_FACE not in predicted

    p0, s0 = next((p, s) for p in fx["passes"] if p["set"] == "all" for s in fx["strings"]
                  if p["column"] in s["columns"] and clean(p, s))
    col = p0["column"]
    key0 = (p0["id"], "string", s0["i"])
    r0 = pd["rows"][key0]

    def variant(rows=None, embedded=None, strings=None, cmaps=None, **top):
        d = dict(data, **top)
        d["pages"] = dict(data["pages"])
        q = dict(pd)
        if rows is not None:
            q["rows"] = rows
        if embedded is not None:
            q["embedded"] = embedded
        if cmaps is not None:
            q["cmaps"] = cmaps
        d["pages"][page] = q
        if strings is not None:
            d["fx"] = dict(fx, strings=strings)
        return d

    out = []

    def fire(name, category, d, baseline=None):
        """The plant must add a failure: against the real run, or, for a condition the real run may already
        fail (a stale strings.json, absent font data), against `baseline`, a copy with that condition clean."""
        got = counts(verdict(d)[0])
        against = real if baseline is None else counts(verdict(baseline)[0])
        out.append((name, category, got[category] > against[category],
                    "%d %s failure(s) against %d in the %s" % (got[category], category, against[category],
                                                              "real run" if baseline is None else "clean copy")))

    rows = dict(pd["rows"])
    rows[key0] = dict(r0, w=s0["price"][col] + fx["tolerance"] + 0.01)
    fire("over-tolerance row", "over", variant(rows=rows))

    rows = dict(pd["rows"])
    rows[key0] = dict(r0, fonts=r0["fonts"] + [
        {"family": "Planted", "ps": "PlantedPlatform-Regular", "custom": False, "glyphs": 1}])
    fire("platform font", "platform", variant(rows=rows))

    ps = next(e["psname"] for e in pd["embedded"] if e["page"] == page)
    rows = {k: (dict(r, fonts=[f for f in r["fonts"] if f["ps"] != ps]) if any(f["ps"] == ps for f in r["fonts"]) else r)
            for k, r in pd["rows"].items()}
    fire("removed face %s" % ps, "coverage", variant(rows=rows))

    strings = [dict(s, price=dict(s["price"], **{col: "unmeasurable: planted"})) if s is s0 else s for s in fx["strings"]]
    fire("unmeasurable price", "unmeasurable", variant(strings=strings))

    rows = dict(pd["rows"])
    del rows[key0]
    fire("join gap", "join", variant(rows=rows))

    cjk_pass = next((p for p in fx["passes"] if p["set"] == "all"), None)
    if fx["cjk"] and cjk_pass and (cjk_pass["id"], "cjk", fx["cjk"][0]["i"]) in pd["rows"]:
        key = (cjk_pass["id"], "cjk", fx["cjk"][0]["i"])
        rows = dict(pd["rows"])
        sub = list(rows[key].get("sub_nokern") or [0.0] * len(fx["cjk"][0]["cps"].split()))
        sub[0] = fx["size"] * c.CJK_ADVANCE_EM + fx["tolerance"] + 0.01
        rows[key] = dict(rows[key], sub_nokern=sub)
        fire("CJK advance over 1 em with kerning off", "cjk-em", variant(rows=rows))
    else:
        out.append(("CJK advance over 1 em with kerning off", "cjk-em", False,
                    "the fixture holds no rendered CJK group to plant it in"))

    embedded = [dict(e, sha256="0" * 64) if i == 0 else e for i, e in enumerate(pd["embedded"])]
    fire("embedded digest changed", "identity", variant(embedded=embedded))

    target = next(ord(ch) for ch in s0["text"] if not c.is_default_ignorable(ord(ch)))
    planted = copy.copy(pd["cmaps"])
    planted.drop = dict(pd["cmaps"].drop)
    for font in r0["fonts"]:
        planted.drop[psmap[font["ps"]][0]] = frozenset({target})
    fire("U+%04X removed from the cmap of the faces a clean row reports" % target, "unmapped", variant(cmaps=planted))

    rows = dict(pd["rows"])
    rows[key0] = dict(r0, fonts=r0["fonts"] + [{"family": data["cjk"][0].family, "ps": data["cjk"][0].psname,
                                                "custom": False, "glyphs": c.cjk_count(s0["text"]) + 1}])
    fire("CJK glyphs beyond a clean row's CJK codepoints", "cjk-foreign", variant(rows=rows))

    drawn = sorted(psmap[f["ps"]][0] for f in r0["fonts"])
    fire("%s removed from the stack of pass %s" % (drawn[0], p0["id"]), "faces",
         variant(drop={(page, p0["variant"]): frozenset({drawn[0]})}))

    # A clean font-data document describing the declared faces, so an arm can prove its category fires even on a
    # run whose real font data is absent or already failing.
    clean_data = {"faces": [{"psname": f.psname, "collection": f.collection, "sha256": f.sha256,
                             "gpos": {"max_positive": None}, "advance": {"over_1em": []}} for f in data["cjk"]]}
    kern = copy.deepcopy(clean_data)
    kern["faces"][0]["gpos"]["max_positive"] = {"units": 1, "em": tf.CJK_EM - 1 + 0.01, "feature": "planted",
                                                "lookup": -1, "glyphs": "planted"}
    clean_fd = variant(font_data=clean_data, font_data_error=None)
    fire("font data adjusting beyond CJK_EM", "cjk-kern", variant(font_data=kern, font_data_error=None), clean_fd)
    wide = copy.deepcopy(clean_data)
    wide["faces"][0]["advance"]["over_1em"] = [["planted", 1.01]]
    fire("font data with a glyph over 1 em", "cjk-advance", variant(font_data=wide, font_data_error=None), clean_fd)
    fire("font data absent", "cjk-font-data", variant(font_data=None, font_data_error=None), clean_fd)
    fresh = dict(fx, table_sha256=data["table_sha256"], cjk_em=tf.CJK_EM)
    fire("strings.json priced against another table", "stale", variant(fx=dict(fresh, table_sha256="0" * 64)),
         variant(fx=fresh))
    return out


def main(argv):
    spec = json.load(open(os.path.join(c.RUN, "pages.json"), encoding="utf-8"))
    pages = argv or [p["id"] for p in spec["pages"] if p["gating"]]
    try:
        data = load(pages)
    except (OSError, ValueError, KeyError) as e:
        print("PREMISE FAILURE: the fixture run cannot be read: %s" % e)
        return 2
    fx = data["fx"]
    if unicodedata.unidata_version != fx["unicode_version"]:
        print("PREMISE FAILURE: Python's unicodedata is Unicode %s and the fixture was priced under %s"
              % (unicodedata.unidata_version, fx["unicode_version"]))
        return 2
    failures, figures = verdict(data)
    real = counts(failures)
    fired = arms(data, real)
    print("fixture judge: table sha256 %s (tree %s), Unicode %s, %d strings, %d CJK groups, %d passes per page, "
          "tolerance %.2f px, CJK_EM %s" % (fx["table_sha256"], data["table_sha256"], fx["unicode_version"],
                                            len(fx["strings"]), len(fx["cjk"]), len(fx["passes"]), fx["tolerance"],
                                            tf.CJK_EM))
    print("skipped by rule: %s" % ({k: v["count"] for k, v in fx.get("skipped", {}).items()} or "none"))
    fd = data["font_data"]
    print("CJK font data: %s" % ("largest positive default-on adjustment %.4f em, widest reachable advance %.4f em"
                                 % (fd["max_positive_em"], fd["max_advance_em"]) if fd else "absent"))
    for page, fig in figures.items():
        print("\n== page %s" % page)
        for pid, pf in fig["passes"].items():
            w = pf["worst"]
            print("  %-28s strings %5d  over %3d  unmeasurable %3d  worst render-table %s"
                  % (pid, pf["strings"], pf["over"], pf["unmeasurable"],
                     "%+.4f px (%s %s)" % w if w else "-"))
        print("  coverage (embedded face -> rows):")
        for ps, cov in sorted(fig["coverage"].items()):
            print("    %-30s %-44s rows %6d  sha256 %s" % (ps, cov["key"], cov["rows"], cov["sha256"][:16]))
        cj = fig["cjk"]
        print("  CJK: %d groups over %d codepoints, %d advances measured with font-kerning:none, worst advance - 1 em %s, "
              "glyphs by face %s" % (cj["groups"], cj["codepoints"], cj["advances_measured"],
                                     "%+.4f px (U+%s, %s)" % cj["worst_advance_minus_em"] if cj["worst_advance_minus_em"]
                                     else "-", cj["glyphs_by_face"]))
        print("  faces mismatches by (pass family, script, predicted -> reported): %s"
              % ("none" if not fig["faces_groups"] else ""))
        for (fam, script, pred, rep), n in sorted(fig["faces_groups"].items(), key=lambda x: (-x[1], x[0])):
            print("    %6d  %-14s %-11s %s -> %s" % (n, fam, script, pred, rep))
        print("  unmapped rows by (pass family, script, reported faces): %s" % ("none" if not fig["unmapped_groups"] else ""))
        for (fam, script, rep), n in sorted(fig["unmapped_groups"].items(), key=lambda x: (-x[1], x[0])):
            print("    %6d  %-14s %-11s %s" % (n, fam, script, rep))
    print("\n== premise arms")
    bad_arms = []
    for name, category, ok, detail in fired:
        print("  %-60s -> %-13s %s (%s)" % (name, category, "FAILED as required" if ok else "DID NOT FAIL", detail))
        if not ok:
            bad_arms.append(name)
    print("\n== failures by category: %s" % (dict(real) or "none"))
    shown = collections.Counter()
    for cat, msg in failures:
        shown[cat] += 1
        if shown[cat] <= SHOW:
            print("  %-13s %s" % (cat, msg))
    for cat, n in real.items():
        if n > SHOW:
            print("  %-13s ... and %d more" % (cat, n - SHOW))
    code = 2 if bad_arms else 1 if failures else 0
    for fig in figures.values():
        fig["faces_groups"] = [list(k) + [n] for k, n in sorted(fig["faces_groups"].items(), key=lambda x: (-x[1], x[0]))]
        fig["unmapped_groups"] = [list(k) + [n] for k, n in sorted(fig["unmapped_groups"].items(), key=lambda x: (-x[1], x[0]))]
    with open(os.path.join(c.RUN, "fixture", "judge.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"pages": pages, "figures": figures, "failures": dict(real), "arms": fired, "exit": code,
                   "first_failures": failures[:200]}, fh, ensure_ascii=False, indent=1)
    if bad_arms:
        print("PREMISE FAILURE: the fixture judge cannot see %s; its verdict is meaningless" % ", ".join(bad_arms))
    else:
        print("fixture verdict: %s" % ("FAIL (%d)" % len(failures) if failures else "every string within tolerance, "
                                                                            "every face embedded, used, identified "
                                                                            "and predicted"))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
