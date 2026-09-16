// Calibration's renderer (ROADMAP O189, V3), one file for both instruments so the fonts are
// embedded one way. Runs inside
//   minlag/mermaid-cli:10.9.1@sha256:f0e8d29ef5385d797724d78c2a1bb00c8398476e8370f0219c0da86cce07d44c
// as root, `architecture/` read-only at /a and the run folder at /r, and installs nothing.
//
//   CAL_MODE=fixture CAL_PAGES=<page>[,<page>] CAL_OUT=/r/fixture
//   CAL_MODE=pa      CAL_PAGES=<page>          CAL_OUT=/r/pa/<page>
//
// A page is one slot, rendered alone (/r/pages.json says which files and which stacks): every
// face is an @font-face data URI under an alias, and the sha256 written to embedded.tsv is taken
// from the bytes embedded. Every FontFace must report `loaded` before anything is measured.
// Stacks name aliases and then the one CJK family; nothing here chooses a font.
//
// fixture: each pass of /r/fixture/strings.json lays its strings out in one SVG under one class
//   rule, reads getComputedTextLength per string, and records the fonts CDP reports per text node.
//   A CJK group is then measured a second time with font-kerning:none: `w` stays the whole group
//   with default kerning, which the judge compares with textfit's CJK_EM price, and `sub_nokern`
//   holds each character's own advance with kerning off, which the judge bounds at 1 em. Kerning is
//   a pair adjustment, so a per-character substring measured with it on is not the face's advance.
// pa: architecture/index.html with its scripts stripped and the 22 numbered platform views, each
//   <text> and descendant forced to the page's stack for the generic family it asked for, both
//   primary faces at device scale 1 and 2; rows are keyed for the judge's join to textfit.
const puppeteer = require('/home/mermaidcli/node_modules/puppeteer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MODE = process.env.CAL_MODE;
const PAGES = (process.env.CAL_PAGES || '').split(',').filter(Boolean);
const OUT = process.env.CAL_OUT;
if (!['fixture', 'pa'].includes(MODE) || PAGES.length === 0 || !OUT) {
  console.error('set CAL_MODE=fixture|pa, CAL_PAGES and CAL_OUT');
  process.exit(2);
}
const RUN = '/r';
const TREE = '/a';
const spec = JSON.parse(fs.readFileSync(`${RUN}/pages.json`, 'utf8'));
const familyList = (names) => names.map((n) => JSON.stringify(n)).join(', ');
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function pageSpec(id) {
  const page = spec.pages.find((p) => p.id === id);
  if (!page) throw new Error(`no page ${id} in pages.json`);
  return page;
}

// The @font-face rules for a page, and one embedded.tsv row per file with the digest of its bytes.
function embed(page, emb) {
  let css = '';
  for (const face of page.faces) {
    const bytes = fs.readFileSync(path.join(RUN, face.path));
    const sha = crypto.createHash('sha256').update(bytes).digest('hex');
    emb.write([page.id, face.key, face.alias, face.weight, face.style, face.psname, sha, bytes.length].join('\t') + '\n');
    css += `@font-face{font-family:${JSON.stringify(face.alias)};font-weight:${face.weight};` +
           `font-style:${face.style};src:url(data:font/ttf;base64,${bytes.toString('base64')}) format("truetype")}\n`;
  }
  return css;
}

async function loadFaces(tab, page) {
  const status = await tab.evaluate(async () => {
    const faces = [...document.fonts];
    await Promise.all(faces.map((f) => f.load().catch(() => null)));
    await document.fonts.ready;
    return faces.map((f) => [f.family.replace(/^["']|["']$/g, ''), f.weight, f.style, f.status]);
  });
  const aliases = new Set(page.faces.map((f) => f.alias));
  const ours = status.filter((s) => aliases.has(s[0]));
  if (ours.length !== page.faces.length || ours.some((s) => s[3] !== 'loaded')) {
    throw new Error(`page ${page.id}: ${ours.length} of ${page.faces.length} faces, not all loaded: ${JSON.stringify(status)}`);
  }
  return status.filter((s) => !aliases.has(s[0]));
}

async function fontsOf(client, nodeIds) {
  const merged = new Map();
  for (const n of nodeIds) {
    const res = await client.send('CSS.getPlatformFontsForNode', { nodeId: n });
    for (const f of res.fonts) {
      const k = `${f.familyName}|${f.postScriptName}|${f.isCustomFont}`;
      const prev = merged.get(k);
      merged.set(k, { family: f.familyName, ps: f.postScriptName, custom: f.isCustomFont,
                      glyphs: (prev ? prev.glyphs : 0) + f.glyphCount });
    }
  }
  return [...merged.values()];
}

async function fixture(tab, client, page, out, emb) {
  const fx = JSON.parse(fs.readFileSync(`${RUN}/fixture/strings.json`, 'utf8'));
  const css = embed(page, emb);
  let rows = 0;
  for (const pass of fx.passes) {
    const stack = page.stacks[pass.variant];
    if (!stack) throw new Error(`page ${page.id} has no stack variant ${pass.variant}`);
    const col = fx.columns[pass.column];
    const items = fx.strings.filter((s) => s.sets.includes(pass.set) && s.columns.includes(pass.column))
      .map((s) => ['string', s])
      .concat(pass.set === 'all' ? fx.cjk.map((g) => ['cjk', g]) : []);
    const rule = `.t{font-family:${familyList(stack[col.generic])};font-size:${fx.size}px;` +
                 `font-weight:${col.weight};font-style:${col.style}}`;
    const texts = items.map(([kind, s], k) =>
      `<text class="t" x="10" y="${30 + 24 * k}" data-kind="${kind}" data-i="${s.i}">${esc(s.text)}</text>`);
    const html = `<!doctype html><html><head><meta charset="utf-8"><style>${css}${rule}</style></head><body>` +
      `<svg xmlns="http://www.w3.org/2000/svg" width="9000" height="${60 + 24 * texts.length}">${texts.join('')}</svg></body></html>`;
    await tab.setContent(html, { waitUntil: 'load' });
    const others = await loadFaces(tab, page);
    const measured = await tab.evaluate(() => Array.from(document.querySelectorAll('text')).map((t) => ({
      kind: t.getAttribute('data-kind'), i: Number(t.getAttribute('data-i')), n: t.getNumberOfChars(),
      w: t.getComputedTextLength() })));
    await client.send('DOM.enable');
    await client.send('CSS.enable');
    const { root } = await client.send('DOM.getDocument', { depth: -1 });
    const { nodeIds } = await client.send('DOM.querySelectorAll', { nodeId: root.nodeId, selector: 'text' });
    if (nodeIds.length !== measured.length || measured.length !== items.length) {
      throw new Error(`pass ${pass.id}: ${nodeIds.length} nodes, ${measured.length} measured, ${items.length} items`);
    }
    const fontsByNode = [];
    for (let k = 0; k < nodeIds.length; k++) fontsByNode.push(await fontsOf(client, [nodeIds[k]]));
    await client.send('CSS.disable');
    await client.send('DOM.disable');
    // The second measurement, with kerning off, only after the default-kerning width and the fonts are read.
    const nokern = await tab.evaluate(() => Array.from(document.querySelectorAll('text')).map((t) => {
      if (t.getAttribute('data-kind') !== 'cjk') return null;
      t.style.setProperty('font-kerning', 'none');
      const kerning = getComputedStyle(t).fontKerning;
      const n = t.getNumberOfChars();
      return { kerning, w_nokern: t.getComputedTextLength(),
               sub_nokern: Array.from({ length: n }, (_, k) => t.getSubStringLength(k, 1)) };
    }));
    for (let k = 0; k < nodeIds.length; k++) {
      const extra = {};
      if (nokern[k]) {
        if (nokern[k].kerning !== 'none') throw new Error(`pass ${pass.id}: font-kerning computed as ${nokern[k].kerning}`);
        extra.w_nokern = nokern[k].w_nokern;
        extra.sub_nokern = nokern[k].sub_nokern;
      }
      out.write(JSON.stringify(Object.assign({ page: page.id, pass: pass.id }, measured[k], extra,
                                             { fonts: fontsByNode[k] })) + '\n');
      rows += 1;
    }
    if (others.length) console.error(`pass ${pass.id}: other faces in the document: ${JSON.stringify(others)}`);
  }
  return rows;
}

function paFiles() {
  const views = fs.readdirSync(`${TREE}/platform-views`).filter((f) => /^\d\d-.*\.html$/.test(f)).sort();
  if (views.length === 0) throw new Error('no platform views');
  return [{ file: 'index.html', path: `${TREE}/index.html` }]
    .concat(views.map((f) => ({ file: f, path: `${TREE}/platform-views/${f}` })));
}

async function pa(tab, client, page, out, emb) {
  const css = embed(page, emb);
  let rows = 0;
  for (const doc of paFiles()) {
    const raw = fs.readFileSync(doc.path, 'utf8').replace(/<script\b[\s\S]*?<\/script>/gi, '');
    if (!/<head[^>]*>/i.test(raw)) throw new Error(`${doc.file} has no <head> to embed the faces in`);
    const html = raw.replace(/<head[^>]*>/i, (m) => `${m}<style>${css}</style>`);
    for (const face of ['dejavu', 'noto']) {
      const variant = page.stacks[face];
      if (!variant) throw new Error(`page ${page.id} has no stack variant ${face}`);
      const stack = {};
      for (const [generic, names] of Object.entries(variant)) stack[generic] = familyList(names);
      for (const dsf of [1, 2]) {
        await tab.setViewport({ width: 1600, height: 1200, deviceScaleFactor: dsf });
        await tab.setContent(html, { waitUntil: 'load' });
        const others = await loadFaces(tab, page);
        const measured = await tab.evaluate((forced) => {
          const collapse = (s) => s.split(/\s+/).filter(Boolean).join(' ');
          const generic = (el) => getComputedStyle(el).fontFamily.split(',').pop().trim()
            .replace(/^["']|["']$/g, '').toLowerCase();
          const svgs = Array.from(document.querySelectorAll('svg'));
          const plan = [];
          Array.from(document.querySelectorAll('text')).forEach((t, g) => {
            const label = collapse(t.textContent);
            if (!label) return;
            const els = [t].concat(Array.from(t.querySelectorAll('*')));
            plan.push({ g, t, label, svg: t.closest('svg'), els: els.map((e) => [e, generic(e)]) });
          });
          for (const p of plan) {
            for (const [e, gen] of p.els) {
              if (!forced[gen]) throw new Error(`a <text> asks for generic family ${gen}, which no stack covers`);
              e.style.setProperty('font-family', forced[gen], 'important');
            }
          }
          const perSvg = new Map();
          return plan.map((p) => {
            const s = svgs.indexOf(p.svg);
            const i = perSvg.get(s) || 0;
            perSvg.set(s, i + 1);
            const title = p.svg.querySelector(':scope > title');
            return { g: p.g, svg: s, title: title ? collapse(title.textContent) : null, i, label: p.label,
                     generics: [...new Set(p.els.map((x) => x[1]))],
                     w: p.t.getComputedTextLength(), bw: p.t.getBBox().width };
          });
        }, stack);
        await client.send('DOM.enable');
        await client.send('CSS.enable');
        const { root } = await client.send('DOM.getDocument', { depth: -1 });
        const { nodeIds } = await client.send('DOM.querySelectorAll', { nodeId: root.nodeId, selector: 'text' });
        for (const r of measured) {
          const node = nodeIds[r.g];
          const { nodeIds: kids } = await client.send('DOM.querySelectorAll', { nodeId: node, selector: '*' });
          const fonts = await fontsOf(client, [node].concat(kids));
          out.write(JSON.stringify({ page: page.id, face, dsf, file: doc.file, svg: r.svg, title: r.title, i: r.i,
                                     label: r.label, generics: r.generics, w: r.w, bw: r.bw, fonts }) + '\n');
          rows += 1;
        }
        await client.send('CSS.disable');
        await client.send('DOM.disable');
        if (others.length) console.error(`${doc.file} ${face} dsf ${dsf}: other faces in the document: ${JSON.stringify(others)}`);
      }
    }
  }
  return rows;
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium-browser', headless: 'new',
                                           args: ['--no-sandbox', '--disable-gpu'] });
  const tab = await browser.newPage();
  const client = await tab.target().createCDPSession();
  for (const id of PAGES) {
    const page = pageSpec(id);
    const dir = MODE === 'fixture' ? `${OUT}/${id}` : OUT;
    fs.mkdirSync(dir, { recursive: true });
    const out = fs.createWriteStream(`${dir}/render.jsonl`);
    const emb = fs.createWriteStream(`${dir}/embedded.tsv`);
    emb.write('page\tkey\talias\tweight\tstyle\tpsname\tsha256\tbytes\n');
    const started = Date.now();
    const rows = MODE === 'fixture' ? await fixture(tab, client, page, out, emb) : await pa(tab, client, page, out, emb);
    await Promise.all([new Promise((ok) => out.end(ok)), new Promise((ok) => emb.end(ok))]);
    console.log(`${MODE} page ${id}: ${rows} rows in ${Math.round((Date.now() - started) / 1000)} s`);
  }
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
