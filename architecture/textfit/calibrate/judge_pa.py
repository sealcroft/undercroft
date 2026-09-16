"""Calibration's P-A judge (ROADMAP O189, V3 and panel 2): does the tree's advance table agree with a
real render of today's diagram text? python:3.12-slim, stdlib only, `architecture/` read-only at /a,
the run folder at /r.

  python3 judge_pa.py <page>

It prices every <text> of diagrams/*.svg and the 22 numbered platform views with textfit and the
tree's table, and joins each render row of /r/pa/<page>/render.jsonl to it by (file, per-svg index)
— an index.html row by its svg's <title> — requiring the label to be equal. It FAILS on:
  condition-1   render - table >= 4 px (the padding) on any row: the table under-reads it;
  condition-2a  a miss at the 4-unit padding: a line some pass spills that the table passes;
  condition-2b  table-only flags above 7% of the table's flagged lines, per set (svg, html);
  platform      a font that is neither an embedded face of the page nor a declared CJK face;
  unmapped      a codepoint of a row, other than a default-ignorable one, that no face CDP reports for
                the row maps, as in judge_fixture.py;
  cjk-foreign   a declared CJK face drawing more glyphs in a row than the line has CJK codepoints;
  faces         the faces the reader model predicts for a row differing from the faces CDP reports:
                each character takes the style textfit's own glyph walk gives it, and the pass's
                primary face picks the stack variant (common.py's clusters, readers.py's stacks);
  unmeasurable  a file textfit refuses;
  identity, cjk-identity, join — as in judge_fixture.py.
It records every face the rows used, and the page's embedded faces no row used (P-A over today's
text is not expected to use them all; coverage is the fixture's).

PREMISE ARMS, as in judge_fixture.py: a planted condition-1 row, a planted miss, planted table-only
flags, a planted platform font, a codepoint removed from the cmap of the faces a clean row reports,
a planted CJK glyph count, the face a clean row was predicted to draw with removed from its stack, a
planted unmeasurable file, a join gap and a changed embedded digest must each fail on their category.

Exit 0 clean, 1 on any failure, 2 on a premise failure. Figures go to stdout and /r/pa/<page>/judge.json.
"""
import collections
import copy
import glob
import json
import os
import sys
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  # noqa: E402

tf, readers = c.tf, c.readers
PAD = tf.PAD
SHARE = 0.07
PASSES = {(face, dsf) for face in ("dejavu", "noto") for dsf in (1, 2)}
SHOW = 12


def styled_texts(src):
    """[[(character, style)]] for every <text> with content, in the order textfit.texts yields them,
    each from textfit's own glyph walk."""
    root = ET.fromstring(src)
    rules = tf.css_rules(src)
    parent = {ch: p for p in root.iter() for ch in p}
    out = []
    for t in (e for e in root.iter() if tf.local(e.tag) == "text"):
        if not " ".join("".join(t.itertext()).split()):
            continue
        chain, a = [], parent.get(t)
        while a is not None:
            chain.append(a)
            a = parent.get(a)
        inherited = {}
        for a in reversed(chain):
            inherited.update(tf.own_style(a, rules))
        out.append(tf.glyphs(t, rules, inherited))
    return out


def textfit_rows():
    table = tf.load_table()
    rows, chars, title2file, refused = {}, {}, {}, []
    sources = [(p, open(p, encoding="utf-8").read()) for p in sorted(glob.glob(os.path.join(c.TREE, "diagrams", "*.svg")))]
    sources += [(p, tf.svg_of(p)) for p in sorted(glob.glob(os.path.join(c.TREE, "platform-views", "[0-9][0-9]-*.html")))]
    for path, src in sources:
        f = os.path.basename(path)
        if f.endswith(".svg"):
            root = ET.fromstring(src)
            title = next((" ".join("".join(e.itertext()).split()) for e in root if tf.local(e.tag) == "title"), None)
            title2file[title] = f
        try:
            for i, t in enumerate(tf.texts(src, table)):
                rows[(f, i)] = t
            for i, walked in enumerate(styled_texts(src)):
                chars[(f, i)] = walked
        except tf.Unmeasurable as e:
            refused.append((f, str(e)))
    return rows, chars, title2file, refused, len(sources)


def load(page):
    rows_tsv = c.read_fonts_tsv()
    tag, canary_rows = c.read_canary()
    base = os.path.join(c.RUN, "pa", page)
    with open(os.path.join(base, "render.jsonl"), encoding="utf-8") as fh:
        render = [json.loads(line) for line in fh]
    T, chars, title2file, refused, files = textfit_rows()
    expected = c.page_pins(page, rows_tsv, canary_rows)
    cjk = c.read_cjk()
    return {"page": page, "canary_tag": tag if page == c.CANARY else None, "render": render, "T": T, "chars": chars,
            "title2file": title2file, "refused": refused, "files": files,
            "embedded": c.read_tsv(os.path.join(base, "embedded.tsv"), c.EMBEDDED_FIELDS),
            "expected": expected, "cjk": cjk, "cjk_weights": c.cjk_by_weight(cjk), "cmaps": c.Cmaps(expected, cjk),
            "fc": c.read_tsv(os.path.join(c.RUN, "platform", "fc-list.tsv"), c.FC_FIELDS), "drop": {}, "memo": {}}


def over(t, w, pad):
    x = t["left"] + (t["width"] / 2 if t["anchor"] == "middle" else t["width"] if t["anchor"] == "end" else 0)
    left = x - (w / 2 if t["anchor"] == "middle" else w if t["anchor"] == "end" else 0)
    b = t["box"]
    return max(b[0] + pad - left, left + w - (b[0] + b[2] - pad))


def klass(label):
    cps = [ord(ch) for ch in label]
    if any(c.is_cjk(cp) for cp in cps):
        return "cjk"
    if any(0x0600 <= cp <= 0x08FF or 0xFB50 <= cp <= 0xFEFF for cp in cps):
        return "arabic"
    if any(0x0E00 <= cp <= 0x0E7F for cp in cps):
        return "thai"
    if any(0x0900 <= cp <= 0x097F for cp in cps):
        return "devanagari"
    if any(0x2190 <= cp <= 0x2BFF for cp in cps):
        return "arrow/math"
    return "other"


def family(ps):
    return c.NO_FACE if ps == c.NO_FACE else readers.group_of(ps)[0]


def row_checks(data, key, r, psmap, pairs):
    """(unmapped codepoints, CJK glyphs beyond the line's CJK codepoints, predicted, reported, problem)."""
    cmaps, memo = data["cmaps"], data["memo"]
    variant = r["face"]
    drop = tuple(sorted(data["drop"].get(variant, ())))
    signature = tuple(sorted((k, tuple(sorted(v))) for k, v in cmaps.drop.items()))
    fonts = tuple(sorted((f["ps"], f["custom"], f["glyphs"]) for f in r["fonts"]))
    mkey = ("row", key, r["label"], variant, fonts, drop, signature)
    if mkey not in memo:
        walked = data["chars"].get(key)
        problem, predicted = None, set()
        if walked is None or " ".join("".join(ch for ch, _ in walked).split()) != r["label"]:
            problem = "textfit's glyph walk does not spell the render label"
        else:
            key_ps = {v[0]: ps for ps, v in psmap.items()}
            try:
                styled = [(ch, c.reader_style(style)) for ch, style in walked]

                def stack_of(generic, weight, style):
                    skey = ("stack", variant, generic, weight, style, drop)
                    if skey not in memo:
                        memo[skey] = [k for k in readers.reader_faces(data["expected"], variant, generic, weight, style)
                                      if k not in drop]
                    return memo[skey]
                predicted = c.predicted_faces(styled, stack_of, cmaps, key_ps, data["cjk_weights"])
            except ValueError as e:
                problem = "no reader for its style: %s" % e
        memo[mkey] = (c.unmapped(r["label"], r["fonts"], cmaps, psmap), c.cjk_foreign(r["fonts"], r["label"], pairs),
                      predicted, c.reported_faces(r["fonts"], pairs), problem)
    return memo[mkey]


def verdict(data):
    page, T = data["page"], data["T"]
    failures, fig = [], {}
    f, pairs = c.cjk_pairs(data["cjk"], data["fc"])
    failures += f
    f, psmap = c.identity(page, data["expected"], data["embedded"])
    failures += f
    failures += [("unmeasurable", "textfit refuses %s: %s" % r) for r in data["refused"]]

    R = collections.defaultdict(dict)
    for r in data["render"]:
        f = data["title2file"].get(r["title"]) if r["file"] == "index.html" else r["file"]
        key = (f, r["i"])
        t = T.get(key)
        where = "%s[%s] (%s) %s dsf %s" % (r["file"], r["i"], f, r["face"], r["dsf"])
        if f is None or t is None:
            failures.append(("join", "%s: no textfit row for %r" % (where, r["label"][:40])))
            continue
        if t["label"] != r["label"]:
            failures.append(("join", "%s: textfit %r, render %r" % (where, t["label"][:40], r["label"][:40])))
            continue
        p = (r["face"], r["dsf"])
        if p in R[key]:
            failures.append(("join", "%s: two render rows" % where))
        R[key][p] = r
    for key in sorted(T):
        if set(R.get(key, {})) != PASSES:
            failures.append(("join", "%s[%d]: render passes %s, expected all four" % (key + (sorted(R.get(key, {})),))))

    gaps = collections.defaultdict(list)
    used, cjk_used = collections.Counter(), collections.Counter()
    faces_groups, unmapped_groups = collections.Counter(), collections.Counter()
    for key, ws in R.items():
        t = T[key]
        for p, r in sorted(ws.items()):
            d = r["w"] - t["width"]
            gaps[klass(t["label"])].append((round(d, 4), "%s dsf %d" % p, "%s[%d]" % key, t["label"][:50]))
            if d >= PAD:
                failures.append(("condition-1", "%s[%d] %s dsf %d: render %.3f, table %.3f (%+.3f) | %s"
                                 % (key + p + (r["w"], t["width"], d, t["label"][:50]))))
            for font in r["fonts"]:
                k = c.classify(font, psmap, pairs)
                if k is None:
                    failures.append(("platform", "%s[%d] %s dsf %d: %s font %s (%s) | %s" % (
                        key + p + ("an unknown web" if font["custom"] else "a platform", font["ps"], font["family"],
                                   t["label"][:40]))))
                elif k == "embedded":
                    used[font["ps"]] += 1
                else:
                    cjk_used[font["ps"]] += 1
            lost, foreign, predicted, reported, problem = row_checks(data, key, r, psmap, pairs)
            where = "%s[%d] %s dsf %d" % (key + p)
            if lost:
                failures.append(("unmapped", "%s: %s mapped by none of the faces CDP reports, %s | %s" % (
                    where, " ".join("U+%04X" % cp for cp in lost), sorted(reported), t["label"][:40])))
                unmapped_groups[(r["face"], klass(t["label"]), " ".join(sorted(family(x) for x in reported)))] += 1
            if foreign:
                failures.append(("cjk-foreign", "%s: a CJK face drew %d glyph(s) beyond the line's %d CJK codepoints | %s"
                                 % (where, foreign, c.cjk_count(r["label"]), t["label"][:40])))
            if problem:
                failures.append(("faces", "%s: %s | %s" % (where, problem, t["label"][:40])))
            elif predicted != reported:
                failures.append(("faces", "%s: the reader model predicts %s, CDP reports %s | %s"
                                 % (where, sorted(predicted), sorted(reported), t["label"][:40])))
                faces_groups[(r["face"], klass(t["label"]), "+".join(sorted({family(x) for x in predicted})),
                              "+".join(sorted({family(x) for x in reported})))] += 1
    fig["classes"] = {k: {"rows": len(v), "worst": max(v)} for k, v in sorted(gaps.items())}
    fig["condition_1_worst"] = max((g for v in gaps.values() for g in v), default=None)
    fig["sets"] = {}
    for s in ("svg", "html"):
        keys = [k for k in R if k[0].endswith("." + s)]
        tab = {k for k in keys if T[k]["over"] > 0}
        rend = {k for k in keys if any(over(T[k], r["w"], PAD) > 0 for r in R[k].values())}
        misses, only = sorted(rend - tab), sorted(tab - rend)
        share = len(only) / len(tab) if tab else 0.0
        for k in misses:
            failures.append(("condition-2a", "MISS %s[%d]: table over %+.2f, passes %s | %s" % (
                k + (T[k]["over"], {"%s/%d" % p: round(over(T[k], r["w"], PAD), 2) for p, r in R[k].items()},
                     T[k]["label"][:50]))))
        if share > SHARE:
            failures.append(("condition-2b", "%s: table-only flags %d of %d = %.1f%%, over %.0f%%"
                             % (s, len(only), len(tab), 100 * share, 100 * SHARE)))
        fig["sets"][s] = {"lines": len(keys), "table_flags": len(tab), "pass_flags": len(rend), "misses": len(misses),
                          "table_only": len(only), "table_only_share": round(share, 4),
                          "table_only_rows": ["%s[%d] table over %+.2f | %s" % (k + (T[k]["over"], T[k]["label"][:50]))
                                              for k in only]}
    fig["faces_used"] = {ps: {"key": psmap[ps][0], "sha256": psmap[ps][1], "rows": n} for ps, n in sorted(used.items())}
    fig["cjk_faces_used"] = {ps: {"sha256": pairs.get(ps), "rows": n} for ps, n in sorted(cjk_used.items())}
    fig["embedded_unused"] = sorted("%s (%s)" % (e["key"], e["psname"]) for e in data["embedded"]
                                    if e["page"] == page and e["psname"] not in used)
    fig["faces_groups"] = faces_groups
    fig["unmapped_groups"] = unmapped_groups
    fig["rows"] = sum(len(v) for v in R.values())
    fig["textfit_rows"] = len(T)
    return failures, fig


def counts(failures):
    return collections.Counter(cat for cat, _ in failures)


def arms(data, real):
    T = data["T"]
    out = []

    def fire(name, category, **replace):
        d = dict(data, **replace)
        got = counts(verdict(d)[0])
        out.append((name, category, got[category] > real[category],
                    "%d %s failure(s) against %d in the real run" % (got[category], category, real[category])))

    def keyed(r):
        f = data["title2file"].get(r["title"]) if r["file"] == "index.html" else r["file"]
        return (f, r["i"])

    names = {e["psname"] for e in data["embedded"] if e["page"] == data["page"]}
    _, psmap = c.identity(data["page"], data["expected"], data["embedded"])
    _, pairs = c.cjk_pairs(data["cjk"], data["fc"])

    def clean(r):
        """A row the real verdict holds nothing against, so a planted defect can only add a failure."""
        t = T.get(keyed(r))
        if not (t is not None and t["label"] == r["label"] and t["over"] <= 0 and r["w"] - t["width"] < PAD - 1
                and over(t, r["w"], PAD) <= 0 and c.cjk_count(r["label"]) == 0
                and all(f["custom"] and f["ps"] in names for f in r["fonts"])):
            return False
        lost, foreign, predicted, reported, problem = row_checks(data, keyed(r), r, psmap, pairs)
        return not lost and not foreign and not problem and predicted == reported and c.NO_FACE not in predicted

    k0, r0 = next((i, r) for i, r in enumerate(data["render"]) if clean(r))
    t0 = T[keyed(r0)]

    def replaced(new):
        render = list(data["render"])
        render[k0] = new
        return render

    fire("condition-1 row", "condition-1", render=replaced(dict(r0, w=t0["width"] + PAD + 0.5)))
    # Wider than twice its box: it spills whatever its anchor, where the table does not flag it.
    fire("miss at the padding", "condition-2a", render=replaced(dict(r0, w=t0["width"] + 2 * t0["box"][2] + 10)))
    flagged = [k for k in sorted(T) if k[0].endswith(".svg")][:20]
    fire("table-only flags", "condition-2b", T={k: (dict(v, over=1.0) if k in flagged else v) for k, v in T.items()})
    fire("platform font", "platform", render=replaced(dict(r0, fonts=r0["fonts"] + [
        {"family": "Planted", "ps": "PlantedPlatform-Regular", "custom": False, "glyphs": 1}])))
    target = next(ord(ch) for ch in r0["label"] if not c.is_default_ignorable(ord(ch)))
    planted = copy.copy(data["cmaps"])
    planted.drop = dict(data["cmaps"].drop)
    for font in r0["fonts"]:
        planted.drop[psmap[font["ps"]][0]] = frozenset({target})
    fire("U+%04X removed from the cmap of the faces a clean row reports" % target, "unmapped", cmaps=planted)
    cjk_ps = data["cjk"][0].psname
    fire("CJK glyphs beyond the line's codepoints", "cjk-foreign", render=replaced(dict(r0, fonts=r0["fonts"] + [
        {"family": data["cjk"][0].family, "ps": cjk_ps, "custom": False, "glyphs": c.cjk_count(r0["label"]) + 1}])))
    drawn = sorted(psmap[f["ps"]][0] for f in r0["fonts"])
    fire("%s removed from the %s stacks" % (drawn[0], r0["face"]), "faces", drop={r0["face"]: frozenset({drawn[0]})})
    fire("unmeasurable file", "unmeasurable", refused=data["refused"] + [("planted.svg", "planted")])
    fire("join gap", "join", render=[r for i, r in enumerate(data["render"]) if i != k0])
    fire("embedded digest changed", "identity",
         embedded=[dict(e, sha256="0" * 64) if i == 0 else e for i, e in enumerate(data["embedded"])])
    return out


def main(argv):
    if len(argv) != 1:
        print("usage: judge_pa.py <page>")
        return 2
    page = argv[0]
    try:
        data = load(page)
    except tf.PremiseFailure as e:
        print("PREMISE FAILURE: %s" % e)
        return 2
    except (OSError, ValueError, KeyError) as e:
        print("PREMISE FAILURE: the P-A run for page %s cannot be read: %s" % (page, e))
        return 2
    failures, fig = verdict(data)
    real = counts(failures)
    fired = arms(data, real)
    print("P-A judge, page %s%s: %d files priced, %d textfit rows, %d render rows joined over %d passes"
          % (page, " (canary tag %s)" % data["canary_tag"] if data["canary_tag"] else "", data["files"],
             fig["textfit_rows"], fig["rows"], len(PASSES)))
    for k, v in fig["classes"].items():
        print("  class %-10s rows %5d  render-table worst %+.4f %s %s | %s" % ((k, v["rows"]) + v["worst"]))
    w = fig["condition_1_worst"]
    print("  condition 1 (render - table < %g on every row): %s; worst %+.4f px (%s %s | %s)"
          % ((PAD, "FAILED" if real["condition-1"] else "met") + (w if w else (0, "-", "-", "-"))))
    for s, v in fig["sets"].items():
        print("  %-4s lines %4d: table flags %d, a pass flags %d; 2a misses %d (%s); 2b table-only %d = %.1f%% (%s)"
              % (s, v["lines"], v["table_flags"], v["pass_flags"], v["misses"], "met" if not v["misses"] else "FAILED",
                 v["table_only"], 100 * v["table_only_share"], "met" if v["table_only_share"] <= SHARE else "FAILED"))
        for row in v["table_only_rows"]:
            print("      TABLE-ONLY %s" % row)
    print("  faces used (embedded):")
    for ps, v in fig["faces_used"].items():
        print("    %-30s %-44s rows %6d  sha256 %s" % (ps, v["key"], v["rows"], v["sha256"][:16]))
    print("  CJK faces used: %s" % ({ps: v["rows"] for ps, v in fig["cjk_faces_used"].items()} or "none"))
    print("  embedded, used by no row: %s" % (", ".join(fig["embedded_unused"]) or "none"))
    print("  faces mismatches by (pass, class, predicted -> reported): %s" % ("none" if not fig["faces_groups"] else ""))
    for (face, cls, pred, rep), n in sorted(fig["faces_groups"].items(), key=lambda x: (-x[1], x[0])):
        print("    %6d  %-7s %-11s %s -> %s" % (n, face, cls, pred, rep))
    print("  unmapped rows by (pass, class, reported faces): %s" % ("none" if not fig["unmapped_groups"] else ""))
    for (face, cls, rep), n in sorted(fig["unmapped_groups"].items(), key=lambda x: (-x[1], x[0])):
        print("    %6d  %-7s %-11s %s" % (n, face, cls, rep))
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
    fig["faces_groups"] = [list(k) + [n] for k, n in sorted(fig["faces_groups"].items(), key=lambda x: (-x[1], x[0]))]
    fig["unmapped_groups"] = [list(k) + [n] for k, n in sorted(fig["unmapped_groups"].items(), key=lambda x: (-x[1], x[0]))]
    with open(os.path.join(c.RUN, "pa", page, "judge.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"page": page, "canary_tag": data["canary_tag"], "figures": fig, "failures": dict(real),
                   "arms": fired, "exit": code, "first_failures": failures[:200]}, fh, ensure_ascii=False, indent=1)
    if bad_arms:
        print("PREMISE FAILURE: the P-A judge cannot see %s; its verdict is meaningless" % ", ".join(bad_arms))
    else:
        print("P-A verdict, page %s: %s" % (page, "FAIL (%d)" % len(failures) if failures else
                                            "conditions 1, 2a and 2b met, every font embedded or declared, "
                                            "every codepoint mapped and every face predicted"))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
