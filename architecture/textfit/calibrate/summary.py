"""Calibration's record (ROADMAP O189, V3). python:3.12-slim, `architecture/` read-only at /a, the
run folder at /r. Writes /r/summary.json and /r/summary.txt: what a ROADMAP record of this run
needs, every figure read from a file the run wrote rather than restated.

  the tree       the advance table's sha256, the sha256 of textfit.py, readers.py, fonts.tsv, pins.py,
                 gen_advances.py, gen_advances.sh and every harness file, the commit
                 (`git rev-parse HEAD`) and whether the tree was dirty;
  the images     each image by digest, as calibrate.sh ran it, with its repo digests;
  the renderer   the Chromium version and the HarfBuzz the binary links;
  the fonts      every embedded file per page with the sha256 taken from its bytes at embedding,
                 the canary tag, and the CJK faces fontconfig reported with their collection digest;
  the verdicts   every step's exit code and each judge's failure counts;
  the outputs    the sha256 of every file the run wrote, except the fetched fonts (listed above)
                 and the downloaded packages (their digests are in fetch/debs.sha256).
"""
import json
import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  # noqa: E402


def read_kv(path):
    return {r["key"]: r["value"] for r in c.read_tsv(path, ("key", "value"))} if os.path.isfile(path) else {}


def text(path):
    return open(path, encoding="utf-8").read().strip() if os.path.isfile(path) else None


def main():
    run = c.RUN
    # The run folder is mounted at /r, so its own name is not visible here; calibrate.sh passes the id.
    out = {"run": os.environ.get("CAL_RUN_ID") or "unknown (CAL_RUN_ID not set)"}
    out["git"] = read_kv(os.path.join(run, "meta", "git.tsv"))
    images = os.path.join(run, "meta", "images.tsv")
    out["images"] = c.read_tsv(images, ("role", "reference", "repo_digests")) if os.path.isfile(images) else []
    out["tree"] = {"architecture/textfit/advances.tsv": c.sha256_file(c.tf.TABLE_PATH)}
    for name in ("textfit.py", "readers.py", "fonts.tsv", "pins.py", "gen_advances.py", "gen_advances.sh"):
        out["tree"]["architecture/textfit/" + name] = c.sha256_file(os.path.join(c.TEXTFIT, name))
    for name in sorted(os.listdir(c.CALIBRATE)):
        path = os.path.join(c.CALIBRATE, name)
        if os.path.isfile(path):
            out["tree"]["architecture/textfit/calibrate/" + name] = c.sha256_file(path)
    out["renderer"] = {"chromium": text(os.path.join(run, "platform", "chromium.txt")),
                       "harfbuzz": text(os.path.join(run, "platform", "harfbuzz.txt"))}

    spec = json.load(open(os.path.join(run, "pages.json"), encoding="utf-8"))
    out["canary_tag"] = spec.get("canary_tag")
    fonts = {}
    for page in spec["pages"]:
        fonts[page["id"]] = {"gating": page["gating"], "files": {}}
        for f in page["faces"]:
            fonts[page["id"]]["files"][f["key"]] = {"psname": f["psname"], "pinned_sha256": f["sha256"], "embedded": {}}
    for sub in ("fixture", "pa"):
        base = os.path.join(run, sub)
        if not os.path.isdir(base):
            continue
        for page in sorted(os.listdir(base)):
            emb = os.path.join(base, page, "embedded.tsv")
            if not os.path.isfile(emb):
                continue
            for r in c.read_tsv(emb, c.EMBEDDED_FIELDS):
                entry = fonts.get(r["page"], {}).get("files", {}).get(r["key"])
                if entry is not None:
                    entry["embedded"][sub] = r["sha256"]
    out["fonts"] = fonts
    fc = os.path.join(run, "platform", "fc-list.tsv")
    if os.path.isfile(fc):
        rows = c.read_tsv(fc, c.FC_FIELDS)
        out["cjk_faces"] = [{"psname": r["psname"], "file": r["file"], "sha256": r["sha256"]}
                            for f in c.read_cjk() for r in rows if r["psname"] == f.psname]

    codes = os.path.join(run, "meta", "exit-codes.tsv")
    # A resumed run appends; the step's verdict is its LAST execution, and how many there were is kept.
    steps = {}
    for line in (open(codes, encoding="utf-8").read().split("\n") if os.path.isfile(codes) else []):
        if line:
            step, code = line.split("\t")
            prev = steps.get(step, {"step": step, "executions": 0, "earlier_exits": []})
            if prev["executions"]:
                prev["earlier_exits"].append(prev["exit"])
            prev.update(exit=code, executions=prev["executions"] + 1)
            steps[step] = prev
    out["steps"] = list(steps.values())
    judges = {}
    for path in [os.path.join(run, "fixture", "judge.json")] + sorted(
            os.path.join(run, "pa", p, "judge.json") for p in (os.listdir(os.path.join(run, "pa"))
                                                                 if os.path.isdir(os.path.join(run, "pa")) else [])):
        if os.path.isfile(path):
            j = json.load(open(path, encoding="utf-8"))
            judges[os.path.relpath(path, run)] = {"exit": j["exit"], "failures": j["failures"],
                                                  "arms": [{"arm": a[0], "category": a[1], "fired": a[2]} for a in j["arms"]]}
    out["judges"] = judges

    outputs = {}
    for root, dirs, files in os.walk(run):
        rel_root = os.path.relpath(root, run)
        if rel_root.split(os.sep)[0] in ("fonts", "fetch"):
            continue
        for name in sorted(files):
            rel = os.path.normpath(os.path.join(rel_root, name))
            if rel in ("summary.json", "summary.txt"):
                continue
            outputs[rel.replace(os.sep, "/")] = c.sha256_file(os.path.join(root, name))
    debs = os.path.join(run, "fetch", "debs.sha256")
    if os.path.isfile(debs):
        outputs["fetch/debs.sha256"] = c.sha256_file(debs)
    out["outputs"] = dict(sorted(outputs.items()))

    with open(os.path.join(run, "summary.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=1, sort_keys=False, ensure_ascii=False)
    lines = ["calibration run %s" % out["run"],
             "commit %s, dirty %s (%s changed paths)" % (out["git"].get("head"), out["git"].get("dirty"),
                                                         out["git"].get("changed_paths")),
             "table sha256 %s" % out["tree"]["architecture/textfit/advances.tsv"],
             "readers.py sha256 %s" % out["tree"]["architecture/textfit/readers.py"],
             "chromium: %s" % out["renderer"]["chromium"],
             "harfbuzz: %s" % (out["renderer"]["harfbuzz"] or "").replace("\n", " | "),
             "canary tag: %s" % out["canary_tag"]]
    lines += ["image %s: %s %s" % (i["role"], i["reference"], i["repo_digests"]) for i in out["images"]]
    for page, v in fonts.items():
        lines.append("page %s (%s):" % (page, "gating" if v["gating"] else "canary, not gating"))
        for key, f in v["files"].items():
            lines.append("  %-46s %-30s %s%s" % (key, f["psname"], f["pinned_sha256"],
                                                   "" if all(s == f["pinned_sha256"] for s in f["embedded"].values())
                                                   else "  EMBEDDED %s" % f["embedded"]))
    lines += ["cjk %s %s %s" % (r["psname"], r["file"], r["sha256"]) for r in out.get("cjk_faces", [])]
    lines += ["step %-24s exit %s%s" % (s["step"], s["exit"], "  (earlier executions exited %s)"
                                         % ", ".join(s["earlier_exits"]) if s["earlier_exits"] else "")
              for s in out["steps"]]
    lines += ["judge %-28s exit %s failures %s" % (k, v["exit"], v["failures"] or "none") for k, v in judges.items()]
    lines += ["output %s %s" % (v, k) for k, v in out["outputs"].items()]
    with open(os.path.join(run, "summary.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines[:6 + len(out["images"])]))
    print("summary: %d font files over %d pages, %d outputs digested -> summary.json, summary.txt"
          % (sum(len(v["files"]) for v in fonts.values()), len(fonts), len(out["outputs"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
