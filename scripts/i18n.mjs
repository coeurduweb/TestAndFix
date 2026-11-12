#!/usr/bin/env node
// Translation catalogs (gettext style: the French sentence is the key).
//
//   node scripts/i18n.mjs extract        list the msgids of the code into i18n/{web,server}.msgids.json
//   node scripts/i18n.mjs todo [size] [web|server]  write what each language lacks into i18n/todo/<side>.<lang>.<n>.json
//   node scripts/i18n.mjs merge          merge the filled todo files into i18n/<side>.<lang>.json, then delete them
//   node scripts/i18n.mjs verify <todo file>  one filled file: values present, same placeholders and tags, no dash
//   node scripts/i18n.mjs check          exit 1 if a message is missing or its {placeholders} / <tags> differ
//
// The knowledge base has its own files (knowledge/i18n/<lang>/<file>.yaml) and its own check (server test).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const I18N = path.join(root, 'i18n');
const TODO = path.join(I18N, 'todo');
export const LANGS = ['en', 'es', 'de', 'ja', 'pt'];
const SIDES = { web: path.join(root, 'web', 'src'), server: path.join(root, 'server', 'src') };

const LIT = String.raw`('(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|\x60(?:[^\x60\\$]|\\.)*\x60)`;
// t('…'), tIn(lang, '…'), msg('…'), rich('…'); plural(n, '…', '…'), tn(n, '…', '…'), tPlural(n, '…', '…')
const ONE = new RegExp(String.raw`(?<![\w.$])(?:t|msg|rich)\(\s*` + LIT, 'g');
const IN = new RegExp(String.raw`(?<![\w.$])tIn\(\s*[\w.]+\s*,\s*` + LIT, 'g');
const TWO = new RegExp(String.raw`(?<![\w.$])(?:plural|tn|tPlural)\(\s*[^,()]+(?:\([^()]*\))?[^,()]*,\s*` + LIT + String.raw`\s*,\s*` + LIT, 'g');

const unquote = (lit) => Function(`"use strict"; return (${lit});`)();

function files(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...files(p));
    else if (/\.(ts|tsx)$/.test(e.name) && !/\.test\.tsx?$|test-setup|test-helpers|\.fixture\.|^i18n\.tsx?$/.test(e.name)) out.push(p);
  }
  return out;
}

export function extract(side, withFiles = false) {
  const ids = new Map();
  for (const f of files(SIDES[side])) {
    const src = fs.readFileSync(f, 'utf8');
    const add = (lit) => {
      const s = unquote(lit);
      if (s && !ids.has(s)) ids.set(s, path.relative(root, f));
    };
    for (const m of src.matchAll(ONE)) add(m[1]);
    for (const m of src.matchAll(IN)) add(m[1]);
    for (const m of src.matchAll(TWO)) {
      add(m[1]);
      add(m[2]);
    }
  }
  const keys = [...ids.keys()].sort((a, b) => a.localeCompare(b, 'fr'));
  return withFiles ? keys.map((k) => [k, ids.get(k)]) : keys;
}

const read = (p, d) => (fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : d);
const write = (p, v) => fs.writeFileSync(p, JSON.stringify(v, null, 2) + '\n');
const placeholders = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
// markup rendered by rich() (and the literal <title> element name); <domaine>-style example values are free text
const TAGS = /<\/?([a-z]|em|strong|code|title|desc|svg|kbd|br)>/g;
const tags = (s) => [...s.matchAll(TAGS)].map((m) => m[0]).sort().join('');

function cmdExtract() {
  for (const side of Object.keys(SIDES)) {
    const ids = extract(side);
    write(path.join(I18N, `${side}.msgids.json`), ids);
    console.log(`${side}: ${ids.length} messages`);
  }
}

function cmdTodo(size = 250, only) {
  fs.mkdirSync(TODO, { recursive: true });
  for (const side of Object.keys(SIDES).filter((x) => !only || x === only)) {
    // grouped by source file, so that a chunk keeps the messages of one screen together
    const where = new Map(extract(side, true));
    const ids = [...where.keys()].sort((a, b) => where.get(a).localeCompare(where.get(b)) || a.localeCompare(b, 'fr'));
    for (const lang of LANGS) {
      const cat = read(path.join(I18N, `${side}.${lang}.json`), {});
      const missing = ids.filter((id) => !cat[id]);
      for (let i = 0; i * size < missing.length; i++) {
        const part = missing.slice(i * size, (i + 1) * size);
        const name = `${side}.${lang}.${String(i + 1).padStart(2, '0')}`;
        write(path.join(TODO, `${name}.json`), Object.fromEntries(part.map((id) => [id, ''])));
        fs.writeFileSync(path.join(TODO, `${name}.where.txt`), part.map((id) => `${where.get(id)}\t${JSON.stringify(id)}`).join("\n") + "\n");
      }
      console.log(`${side} ${lang}: ${missing.length} to translate`);
    }
  }
}

function cmdMerge() {
  if (!fs.existsSync(TODO)) return;
  for (const f of fs.readdirSync(TODO).filter((x) => x.endsWith('.json')).sort()) {
    const hints = path.join(TODO, f.replace(/\.json$/, '.where.txt'));
    const [side, lang] = f.split('.');
    const p = path.join(I18N, `${side}.${lang}.json`);
    const cat = read(p, {});
    const done = read(path.join(TODO, f), {});
    let n = 0;
    for (const [id, tr] of Object.entries(done)) if (typeof tr === 'string' && tr.trim()) (cat[id] = tr), n++;
    write(p, Object.fromEntries(Object.entries(cat).sort(([a], [b]) => a.localeCompare(b, 'fr'))));
    if (n === Object.keys(done).length) {
      fs.unlinkSync(path.join(TODO, f));
      if (fs.existsSync(hints)) fs.unlinkSync(hints);
    }
    console.log(`${f}: ${n}/${Object.keys(done).length} merged`);
  }
}

export function check() {
  const problems = [];
  for (const side of Object.keys(SIDES)) {
    const ids = extract(side);
    for (const lang of LANGS) {
      const cat = read(path.join(I18N, `${side}.${lang}.json`), {});
      for (const id of ids) {
        const tr = cat[id];
        if (!tr) problems.push(`${side}.${lang}: missing ${JSON.stringify(id)}`);
        else if (placeholders(tr) !== placeholders(id)) problems.push(`${side}.${lang}: placeholders differ ${JSON.stringify(id)} -> ${JSON.stringify(tr)}`);
        else if (tags(tr) !== tags(id)) problems.push(`${side}.${lang}: tags differ ${JSON.stringify(id)} -> ${JSON.stringify(tr)}`);
      }
    }
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [cmd, arg, arg2] = process.argv.slice(2);
  if (cmd === 'extract') cmdExtract();
  else if (cmd === 'todo') cmdTodo(arg ? Number(arg) : undefined, arg2);
  else if (cmd === 'merge') cmdMerge();
  else if (cmd === 'verify') {
    // one filled todo file: every value present, same {placeholders} and <tags> as its key
    const done = read(path.resolve(arg), {});
    const bad = Object.entries(done).filter(([id, tr]) => !tr || !String(tr).trim() || placeholders(tr) !== placeholders(id) || tags(tr) !== tags(id) || /[\u2013\u2014]/.test(tr));
    for (const [id, tr] of bad.slice(0, 40)) console.log(`${JSON.stringify(id)} -> ${JSON.stringify(tr)}`);
    console.log(bad.length ? `${bad.length} to fix (empty, placeholders, tags or dash)` : 'ok');
    process.exit(bad.length ? 1 : 0);
  }
  else if (cmd === 'check') {
    const p = check();
    for (const x of p.slice(0, 50)) console.log(x);
    console.log(p.length ? `${p.length} problems` : 'all messages translated');
    process.exit(p.length ? 1 : 0);
  } else {
    console.log('usage: node scripts/i18n.mjs extract|todo [size]|merge|check');
    process.exit(2);
  }
}
