# Text-fit calibration

The harness that checks `architecture/textfit/advances.tsv` against real renders, built for
ROADMAP O189 (V3 of the font-version ruling, and panel 2's QM and QC rulings). The table is a
per-glyph maximum over the faces pinned in `../fonts.tsv`, with a cell withdrawn where some modelled
reader draws the codepoint with no face of its stack; this harness renders text in headless Chromium
with exactly those files and fails when a render comes out wider than the table prices it, or draws
with a face the reader model does not predict.

**It is run by hand, and never by CI or the battery**, on `gen_advances.sh`'s precedent. It
fetches fonts from the network and drives Chromium for a long time. It changes nothing in the
tree: the table, `textfit.py`, `readers.py` and the diagrams are inputs. Everything it writes goes
to a gitignored run folder under `runs/`.

## Running it

From the repository root, in Git Bash or any POSIX shell with Docker:

```sh
bash architecture/textfit/calibrate/calibrate.sh
bash architecture/textfit/calibrate/calibrate.sh --no-canary
bash architecture/textfit/calibrate/calibrate.sh --run-id 20260915T120000Z --from fixture-judge --to fixture-judge
```

`--from STEP` resumes an existing run at a step, and `--to STEP` stops after one, so the third
line judges a finished run again and renders nothing. A resumed step appends its exit code, and
`summary.txt` reports each step's last execution with the earlier ones beside it.

The script exports `MSYS_NO_PATHCONV=1` itself, so Git Bash needs no prefix. It needs network
access to the Debian mirror, `raw.githubusercontent.com` and `api.github.com`. Every step runs in
a container pinned by digest:

| image | used for |
|---|---|
| `python:3.12-slim@sha256:423ed6ab…` | every Python step but one. `textfit.py` requires its Unicode 15.0.0. |
| `debian:bookworm-slim@sha256:7b140f37…` | downloading the pinned Debian font packages, and the `cjk-font-data` step, which installs `python3-fonttools` and `unicode-data` at the versions `gen_advances.sh` pins. `fetch.py plan` checks this digest against `gen_advances.sh`. |
| `minlag/mermaid-cli:10.9.1@sha256:f0e8d29e…` | Chromium 124 with HarfBuzz 8.3.0, run as root, with nothing installed. |

The exit code is 0 when every gating judge is clean. It is 1 when a judge fails or a step
cannot run, and 2 when a judge's premise arm does not fire. The canary never changes it.

## The reader model

`../readers.py` is the one reader model, and both the table and this harness read it. A page is
one slot of `fonts.tsv`; every page but Debian's also holds DejaVu from slot `debian`. A reader is
a page read through one of four stack variants in one style:

- **Variants.** DejaVu primary or Noto primary, then Noto Sans Arabic, Noto Sans Thai (or Noto
  Looped Thai), Noto Sans Devanagari and Noto Sans Math. A monospace reader's Noto variant is its
  DejaVu variant, since no Noto monospace face is pinned. The CJK family is not part of the model;
  this harness appends it to every stack itself.
- **Styles, per table column.** sans400: sans-serif 400; sans600: sans-serif 700; mono: monospace
  400 and 700; serif: serif 400 upright and italic.
- **The face a style draws with inside a family** is the browser's @font-face matching over the
  files declared under their names' weight and style: a Bold file at 600 and above where one
  exists, else Regular; an Italic file where one exists, else the upright one.
- **The face a reader draws a codepoint with** is the first face of its stack that maps it, or
  every part of its full canonical decomposition.

The generator prices each cell from every reader's drawing face and writes `-` where some reader
has none. `fetch.py pages` builds each page's stacks from the same model, and the judges predict
the faces a row uses from it.

## What each part checks

- **`fetch.py plan`, `extract`, `stage`.** Every file of both `fonts.tsv` slots goes into the run
  folder. Debian rows come from the pinned packages, at the versions `gen_advances.sh` pins.
  Noto 23.7.1 rows come from their URLs. Each file's sha256 must match `fonts.tsv` before it is
  written where the renderer reads it. `pins.read_fonts` is the only reader of `fonts.tsv`.
  `plan` also writes `gen_advances.sh`'s pins of `python3-fonttools` and `unicode-data` for the
  `cjk-font-data` step.
- **`fetch.py canary`.** It finds the newest `noto-monthly-release` tag through the GitHub API.
  It fetches the 23.7.1 slot's files at that tag (Looped Thai is tried under its later name too).
  It records the tag and every file's sha256 in `fonts/canary/manifest.tsv`. It is not pinned
  and not gating.
- **`fetch.py pages`.** A page is one slot, rendered alone, because CDP reports a PostScript
  name and never a version. A page embeds the files `readers.page_pins` gives it. Each stack is
  `readers.py`'s, as aliases, then the declared CJK family.
- **`platform.sh`.** It records the Chromium version, the HarfBuzz library Chromium links, and
  every face fontconfig knows with its file's sha256. It copies out the CJK collections that
  `cjk.tsv` declares.
- **`cjk_font_data.py`, the `cjk-font-data` step.** From both declared CJK collections, each
  checked against `cjk.tsv` by sha256 and each face selected by PostScript name, it computes:
  - the glyphs reachable from every assigned codepoint of textfit's CJK blocks through default-on
    GSUB in every script and language system;
  - the widest hmtx advance over those glyphs;
  - every positive XAdvance the default-on GPOS features apply to them: SinglePos, PairPos Value1
    and Value2 in both formats, through contextual, chaining and extension lookups;
  - cursive lookups, a per-glyph residual sum, and positive adjustments behind features no shaper
    applies unasked, all as information.

  A feature it cannot classify as default-on or off by default refuses the step. It writes
  `platform/cjk-font-data.json`.
- **`fixture.py`, the fixture.** Strings are generated from the tree's table:
  - every ligature sequence in the earlier spellings, Allah, the R letters after D, every Arabic
    letter in four positions and decomposed, and the F3 LAM + U+FC5E + ALEF strings;
  - Thai, Devanagari and Math cluster strings (a base then its marks, never a lone mark);
  - every CJK codepoint both declared CJK faces map, in groups of 64.

  Each is priced with `textfit.py` in six columns: sans400, sans600 at weight 700, mono at 400
  and at 700, serif, and serif italic. Ten passes per page, each primary face in each column,
  plus the same ten with Looped Thai over the Thai strings. A (string, column) is not rendered
  where one of its characters has a `-` cell in that column: the codepoint cell, or an Arabic
  letter's form cell under the form its context forces. Each one left out is listed under
  `skipped`. Before anything is written, those `-` cells are checked both ways against coverage
  computed from the staged font bytes, over every gating page's readers. A `-` cell every reader
  draws, or a priced cell some reader cannot draw, refuses the fixture.
- **`judge_fixture.py`.** Per page and pass, the run fails on:
  - a string more than 0.05 px wider than its price, or a price textfit cannot give;
  - a font that is neither an embedded face (web font, PostScript name mapped to its file and
    the sha256 taken from the bytes embedded) nor a declared CJK face;
  - an embedded face no row used;
  - `unmapped`: a codepoint of a row, other than a default-ignorable one, that no face CDP reports
    maps, read from the run's own files. CDP credits a `.notdef` to the face that drew it;
  - `cjk-foreign`: a declared CJK face drawing more glyphs than the row has CJK codepoints;
  - `faces`: the faces the reader model predicts for the row differing from the faces CDP reports;
  - a CJK character whose own advance, measured with `font-kerning:none`, exceeds 1 em + 0.05 px;
  - `cjk-kern`: `textfit.CJK_EM` below 1 + the largest positive default-on adjustment in
    `cjk-font-data.json`; `cjk-advance`: a reachable glyph over 1 em there; `cjk-font-data`: that
    file absent or describing other collections;
  - `stale`: `strings.json` priced against another table or another `CJK_EM`;
  - a pinned file not embedded, or embedded with another digest;
  - any join gap.
- **`render.js pa`, the P-A run.** It renders `architecture/index.html` with its scripts
  stripped, and the 22 numbered platform views. Every text is forced to the page's stack by the
  generic family it asked for: DejaVu primary and Noto primary, at device scale 1 and 2.
- **`judge_pa.py`.** Rows are joined to textfit by (file, or svg title for `index.html`, and
  per-svg index), with equal labels. Per page the run fails on:
  - condition 1, render − table ≥ 4 px on any row;
  - condition 2a, a line a render spills at the 4-unit padding that the table passes;
  - condition 2b, table-only flags above 7% of flagged lines, each listed;
  - a platform font other than the declared CJK faces;
  - `unmapped` and `cjk-foreign`, as in the fixture judge;
  - `faces`, with each character's style taken from textfit's own glyph walk and the pass's
    primary face choosing the stack variant;
  - a file textfit refuses, or a join gap.

  It records which faces the rows used. The canary page is judged the same way.
- **Premise arms.** Before a judge's verdict is believed, it plants one defect per category in a
  copy of the real data. Each copy must fail on that category more often than the real data
  does, or the judge exits 2. A condition the real data can already fail (a stale fixture, absent
  font data) is planted against a copy with that condition clean instead. The planted defects:
  - an over-tolerance row, a platform font, a removed face, an unmeasurable price, a join gap;
  - a CJK advance over 1 em, a changed digest;
  - a codepoint removed from the cmap of the faces a clean row reports;
  - extra CJK glyphs in a clean row;
  - the face a clean row was predicted to draw with, removed from its stack;
  - font data adjusting past `CJK_EM`, font data with a glyph over 1 em, absent font data, and a
    stale fixture;
  - for P-A, also a miss and table-only flags.
- **`summary.py`.** It writes what a ROADMAP record needs:
  - the table's sha256, and those of `readers.py` and every harness file;
  - `git rev-parse HEAD` and the dirty flag;
  - the three images with their repo digests, Chromium and HarfBuzz;
  - every font's sha256 as pinned and as embedded, and the canary tag;
  - every step's exit code, and each output's sha256.

## The faces prediction

The `faces` arm is the harness's observation of the reader model. `common.py` documents how a
row is cut into clusters. Two of its rules came from run `v3d`'s rows, where the first model
disagreed with every row of a shape:
- A joiner after an Arabic letter is drawn from the stack's first face. A joiner after a
  Devanagari virama stays with the virama's cluster.
- A CJK-block codepoint an earlier stack face maps is drawn from that face.

What a set comparison cannot see is stated there too: it compares the faces a row used, and
never which codepoint each face drew.

## The CJK exception

No face in the table covers CJK, so `textfit.py` prices each CJK character by rule at `CJK_EM`.
That is one em plus the largest positive adjustment the declared faces apply by default. The
`cjk-font-data` step measures that adjustment from the faces' GPOS, and the fixture judge fails
when `CJK_EM` is below it. Every stack names the family `cjk.tsv` declares, and the render image
supplies it. That is the one face calibration does not embed. It is identified by the pair
(collection sha256, PostScript name) from fc-list. Weight 400 selects the Regular collection and
700 the Bold, so `cjk.tsv` declares two pairs.

The renderer measures a CJK group twice. The first measurement keeps default kerning: its whole
width is compared with the `CJK_EM` price. The second sets `font-kerning:none`: each character's
own advance must be at most 1 em + 0.05 px, since with kerning on, a pair adjustment would be read
as a wider glyph.

## Where outputs go

`runs/<run id>/`, gitignored; `runs/README.md` lists what a run folder holds. A run folder is
evidence for a ROADMAP record, and `summary.txt` is the part to copy into one.

## Files

| file | role |
|---|---|
| `calibrate.sh` | the entry script: every step, in order, with its exit code recorded |
| `common.py` | the rules both judges and the fetch step share, the faces prediction included; the reader model is `../readers.py` |
| `sfnt.py` | a stdlib reader of a font's PostScript name and cmap |
| `fetch.py` | plan, stage, canary and pages |
| `platform.sh` | the render image's record |
| `cjk_font_data.py` | the declared CJK faces' advances and default-on adjustments, from their tables |
| `fixture.py` | fixture strings, passes, prices, and the both-ways check of the table's `-` cells |
| `render.js` | the renderer, fixture and P-A |
| `judge_fixture.py`, `judge_pa.py` | the judges and their premise arms |
| `summary.py` | the run's record |
| `cjk.tsv` | the declared CJK faces |
