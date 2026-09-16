"""Calibration's fetch steps (ROADMAP O189, V3). python:3.12-slim, `architecture/` read-only at
/a, the run folder at /r. Every file is checked against its pinned sha256 before it is written
where the renderer reads it; nothing here reads a byte of a font as a font except `pages`,
which reads a PostScript name out of files already verified.

  python3 fetch.py plan --debian-image <ref>
      Checks the image calibrate.sh extracts Debian fonts from against gen_advances.sh's pin,
      and every debian row of fonts.tsv against gen_advances.sh's apt pins; writes
      /r/fetch/debian-packages.txt (package=version, one per line) for the extraction step, and
      /r/fetch/cjk-font-data-packages.txt, gen_advances.sh's pins of python3-fonttools and
      unicode-data, for the cjk-font-data step.
  python3 fetch.py stage
      Fetches every https row of fonts.tsv and takes every debian row from the packages the
      extraction step unpacked under /r/fetch/debian-root; writes each to /r/fonts/<slot>/<file>
      once its sha256 matches.
  python3 fetch.py canary
      Finds the newest noto-monthly-release tag, fetches the newest non-debian slot's files at
      that tag, and writes /r/fonts/canary/manifest.tsv in fonts.tsv's own format, with the tag
      and every file's sha256. Not pinned: the canary is judged and recorded, never gating.
  python3 fetch.py pages
      Writes /r/pages.json: for every page, the files it embeds (key, path, alias, weight,
      style, PostScript name, sha256) and the stacks its passes name.

Exit 1 on any refusal, with the reason; nothing is left half-written under /r/fonts.
"""
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  # noqa: E402
import sfnt  # noqa: E402

LIMIT = 32 * 1024 * 1024
TAGS_API = "https://api.github.com/repos/notofonts/notofonts.github.io/tags?per_page=100&page=%d"
LATEST_API = "https://api.github.com/repos/notofonts/notofonts.github.io/releases/latest"
TAG = re.compile(r"noto-monthly-release-(\d+)\.(\d+)\.(\d+)")
# Upstream renames after 23.7.1, tried only when the 23.7.1 spelling is absent at the canary tag.
RENAMES = (("NotoLoopedThai", "NotoSansThaiLooped"),)


def get(url, limit=LIMIT):
    request = urllib.request.Request(url, headers={"User-Agent": "undercroft-textfit-calibrate"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise OSError("%s is larger than %d bytes" % (url, limit))
    return data


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".part"
    with open(tmp, "wb") as out:
        out.write(data)
    os.replace(tmp, path)


def plan(argv):
    if len(argv) != 2 or argv[0] != "--debian-image":
        c.refuse("usage: fetch.py plan --debian-image <ref>")
    image = argv[1]
    script = open(os.path.join(c.TEXTFIT, "gen_advances.sh"), encoding="utf-8").read()
    apt, problems = c.pins.apt_pins(script)
    if problems:
        c.refuse("gen_advances.sh: %s" % "; ".join(problems))
    named = {"%s@sha256:%s" % (ref, digest) if digest else ref for ref, digest in c.pins.images(script)}
    if named != {image}:
        c.refuse("calibrate.sh extracts Debian fonts from %s and gen_advances.sh names %s"
                 % (image, ", ".join(sorted(named)) or "no image"))
    packages = {}
    for p in c.read_fonts_tsv():
        m = c.pins.DEBIAN_SOURCE.fullmatch(p.source)
        if not m:
            continue
        if apt.get(m.group(1)) != m.group(2):
            c.refuse("fonts.tsv takes %s:%s from %s=%s and gen_advances.sh pins %s"
                     % (p.slot, p.file, m.group(1), m.group(2), apt.get(m.group(1), "nothing")))
        packages[m.group(1)] = m.group(2)
    if not packages:
        c.refuse("fonts.tsv names no Debian package")
    out = os.path.join(c.RUN, "fetch", "debian-packages.txt")
    write(out, "".join("%s=%s\n" % kv for kv in sorted(packages.items())).encode())
    # The cjk-font-data step reads the CJK faces with the fontTools and the Unicode data the table is
    # generated with, installed at gen_advances.sh's pins and never at a version written anywhere else.
    tools = {}
    for name in ("python3-fonttools", "unicode-data"):
        if name not in apt:
            c.refuse("gen_advances.sh pins no %s, which the cjk-font-data step installs" % name)
        tools[name] = apt[name]
    write(os.path.join(c.RUN, "fetch", "cjk-font-data-packages.txt"),
          "".join("%s=%s\n" % kv for kv in sorted(tools.items())).encode())
    print("plan: image %s agrees with gen_advances.sh; %d Debian packages at the versions it pins: %s; the "
          "cjk-font-data step installs %s" % (image, len(packages), ", ".join("%s=%s" % kv for kv in sorted(packages.items())),
                                              ", ".join("%s=%s" % kv for kv in sorted(tools.items()))))


def stage(argv):
    rows = c.read_fonts_tsv()
    root = os.path.join(c.RUN, "fetch", "debian-root", "usr", "share", "fonts", "truetype")
    done = {"https": 0, "debian": 0}
    for p in rows:
        if p.source.startswith("https://"):
            try:
                data = get(p.source)
            except (OSError, urllib.error.URLError) as e:
                c.refuse("%s:%s could not be fetched from %s: %s" % (p.slot, p.file, p.source, e))
            kind = "https"
        else:
            src = os.path.join(root, p.file)
            if not os.path.isfile(src):
                c.refuse("%s:%s is not in the unpacked packages at %s" % (p.slot, p.file, src))
            data = open(src, "rb").read()
            kind = "debian"
        got = c.sha256_bytes(data)
        if got != p.sha256:
            c.refuse("%s:%s from %s has sha256 %s, and fonts.tsv pins %s" % (p.slot, p.file, p.source, got, p.sha256))
        write(c.fetched_path(p), data)
        done[kind] += 1
    shutil.rmtree(os.path.join(c.RUN, "fetch", "debian-root"))
    print("stage: %d files fetched over https and %d taken from the pinned Debian packages, each matching "
          "its fonts.tsv sha256; the unpacked packages removed, the .deb files and their digests kept"
          % (done["https"], done["debian"]))


def tag_key(name):
    m = TAG.fullmatch(name)
    if not m:
        return None
    y, mo, d = (int(g) for g in m.groups())
    return (y + 2000 if y < 100 else y, mo, d)


def canary(argv):
    rows = c.read_fonts_tsv()
    tags, page = [], 1
    while True:
        try:
            batch = json.loads(get(TAGS_API % page, 8 * 1024 * 1024))
        except (OSError, urllib.error.URLError, ValueError) as e:
            c.refuse("the tag list could not be read from %s: %s" % (TAGS_API % page, e))
        tags += [t["name"] for t in batch]
        if len(batch) < 100 or page == 10:
            break
        page += 1
    monthly = sorted((k, t) for t in tags for k in [tag_key(t)] if k)
    if not monthly:
        c.refuse("no noto-monthly-release tag among %d tags" % len(tags))
    newest = monthly[-1][1]
    try:
        latest = json.loads(get(LATEST_API, 8 * 1024 * 1024)).get("tag_name")
    except (OSError, urllib.error.URLError, ValueError) as e:
        latest = "unreadable (%s)" % e

    upstream = [p for p in rows if p.slot != c.DEBIAN]
    slots = sorted({p.slot for p in upstream})
    if len(slots) != 1:
        c.refuse("the canary mirrors one non-debian slot; fonts.tsv has %s" % (slots or "none"))
    lines = ["# The calibration canary (ROADMAP O189, V3): the newest upstream Noto monthly release, in",
             "# fonts.tsv's format. Recorded, never pinned and never gating.",
             "# tag: %s" % newest,
             "# releases/latest: %s" % latest,
             "# mirrors slot: %s" % slots[0],
             "\t".join(c.pins.FIELDS)]
    fetched, absent = 0, []
    for p in upstream:
        m = TAG.search(p.source)
        if not m:
            c.refuse("%s:%s: %s names no monthly release tag" % (p.slot, p.file, p.source))
        candidates = [(p.source.replace(m.group(0), newest), p.file)]
        for old, new in RENAMES:
            if old in p.source:
                candidates.append((p.source.replace(m.group(0), newest).replace(old, new), p.file.replace(old, new)))
        for url, file in candidates:
            try:
                data = get(url)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    continue
                c.refuse("%s could not be fetched: %s" % (url, e))
            except (OSError, urllib.error.URLError) as e:
                c.refuse("%s could not be fetched: %s" % (url, e))
            pin = c.pins.Pin(c.CANARY, file, c.sha256_bytes(data), url)
            write(c.fetched_path(pin), data)
            lines.append("\t".join(pin))
            fetched += 1
            break
        else:
            absent.append(p.file)
            lines.insert(5, "# absent at %s: %s (tried %s)" % (newest, p.file, ", ".join(u for u, _ in candidates)))
    write(c.CANARY_MANIFEST, ("\n".join(lines) + "\n").encode())
    print("canary: tag %s (releases/latest %s), %d files fetched, %d absent%s"
          % (newest, latest, fetched, len(absent), (": " + ", ".join(absent)) if absent else ""))


def pages(argv):
    rows = c.read_fonts_tsv()
    tag, canary_rows = c.read_canary()
    cjk = c.read_cjk()
    out = {"size": c.SIZE, "cjk_family": cjk[0].family, "canary_tag": tag, "pages": []}
    for page in c.page_ids(rows, canary_rows):
        faces, groups = [], set()
        for p in c.page_pins(page, rows, canary_rows):
            path = c.fetched_path(p)
            data = open(path, "rb").read()
            if c.sha256_bytes(data) != p.sha256:
                c.refuse("%s:%s at %s no longer matches its sha256" % (p.slot, p.file, path))
            offsets = sfnt.faces(data)
            if len(offsets) != 1:
                c.refuse("%s:%s holds %d faces; a page embeds single-face files" % (p.slot, p.file, len(offsets)))
            group, weight, style = c.group_of(p.file)
            groups.add(group)
            faces.append({"key": "%s:%s" % (p.slot, p.file), "path": os.path.relpath(path, c.RUN),
                          "alias": c.alias(page, group), "group": group, "weight": weight, "style": style,
                          "psname": sfnt.ps_name(data, offsets[0]), "sha256": p.sha256})
        slots_, missing = c.stacks(page, groups, cjk[0].family)
        out["pages"].append({"id": page, "gating": page != c.CANARY, "faces": faces, "stacks": slots_,
                             "missing_variants": missing})
        print("pages: %-12s %2d faces, stack variants %s%s" % (
            page, len(faces), ", ".join(sorted(slots_)),
            ("; missing %s" % missing) if missing else ""))
    write(os.path.join(c.RUN, "pages.json"), json.dumps(out, indent=1, sort_keys=True).encode())
    write(os.path.join(c.RUN, "pages.tsv"), ("page\tgating\n" + "".join(
        "%s\t%s\n" % (p["id"], "true" if p["gating"] else "false") for p in out["pages"])).encode())


def main(argv):
    steps = {"plan": plan, "stage": stage, "canary": canary, "pages": pages}
    if not argv or argv[0] not in steps:
        c.refuse("usage: fetch.py {%s} ..." % ",".join(steps))
    steps[argv[0]](argv[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
