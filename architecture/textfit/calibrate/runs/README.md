# Calibration runs

Each subfolder is one run of `../calibrate.sh`, named by its run id (a UTC timestamp unless
`--run-id` named it). The subfolders are gitignored and this file is not: a run holds downloaded
font files, Debian packages and hundreds of megabytes of render rows, and none of it belongs in
the repository. What a later session needs from a run is copied into ROADMAP from `summary.txt`.

A run folder keeps:

| path | what it is |
|---|---|
| `summary.txt`, `summary.json` | the record: table sha256, harness sha256s, commit and dirty flag, image digests, Chromium and HarfBuzz, every font's sha256 as pinned and as embedded, the canary tag, every step's exit code, every output's sha256 |
| `meta/` | `git.tsv`, `git-status.txt`, `images.tsv`, and `exit-codes.tsv`, one line per step |
| `logs/<step>.log` | each step's full output |
| `fetch/` | `debian-packages.txt`, the downloaded `.deb` files and `debs.sha256`, and `cjk-font-data-packages.txt`, the fontTools and unicode-data pins the `cjk-font-data` step installs |
| `fonts/<slot>/` | every `fonts.tsv` file, each checked against its sha256 before it was written |
| `fonts/canary/` | the newest upstream release's files, and `manifest.tsv` with the tag and sha256s |
| `pages.json`, `pages.tsv` | which files each page embeds, their PostScript names, and the stacks |
| `platform/` | `chromium.txt`, `harfbuzz.txt`, `packages.txt`, `fc-list.tsv` with each file's sha256, copies of the declared CJK collections, and `cjk-font-data.json`: per declared CJK face, the reachable glyphs, the widest advance and every positive default-on adjustment |
| `fixture/strings.json` | the fixture: strings, passes, each string's price in every column, the (string, column) cells left out for a `-` table cell under `skipped`, and the count of cells the both-ways check read |
| `fixture/<page>/` | `render.jsonl`, one row per string per pass (a CJK group also carries `w_nokern` and `sub_nokern`, measured with `font-kerning:none`), and `embedded.tsv`, with sha256s taken from the bytes embedded |
| `fixture/judge.json` | the fixture judge's figures, failure counts and premise arms |
| `pa/<page>/` | `render.jsonl`, `embedded.tsv` and `judge.json` for the P-A run on that page, the canary included |

To judge a run again without rendering it again, resume it at a judge step and stop there:
`bash ../calibrate.sh --run-id <id> --from fixture-judge --to fixture-judge`. Without `--to`,
a resumed run carries on through every later step, P-A renders included.
