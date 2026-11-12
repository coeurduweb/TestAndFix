#!/usr/bin/env node
// Checks the translations of the knowledge base (knowledge/i18n/<lang>/<file>.yaml) against the French
// source (knowledge/situations/<file>.yaml): every situation present, same number of fixes, same
// providers, same {placeholders} in each field.
//   node scripts/kb-check.mjs [lang ...] [--files a.yaml,b.yaml]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(root, 'knowledge', 'situations');
const DST = path.join(root, 'knowledge', 'i18n');
const ph = (s) => [...String(s ?? '').matchAll(/(?<!%)\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');

export function checkKb(langs = ['en', 'es', 'de', 'ja', 'pt'], only) {
  const problems = [];
  const files = fs.readdirSync(SRC).filter((f) => f.endsWith('.yaml') && (!only || only.includes(f))).sort();
  for (const lang of langs) {
    for (const f of files) {
      const src = YAML.parse(fs.readFileSync(path.join(SRC, f), 'utf8')).filter((s) => s?.id && s.title);
      const p = path.join(DST, lang, f);
      if (!fs.existsSync(p)) {
        problems.push(`${lang}/${f}: file missing`);
        continue;
      }
      let tr;
      try {
        tr = YAML.parse(fs.readFileSync(p, 'utf8')) ?? {};
      } catch (e) {
        problems.push(`${lang}/${f}: invalid YAML (${e.message.split('\n')[0]})`);
        continue;
      }
      for (const s of src) {
        const t = tr[s.id];
        const where = `${lang}/${f} ${s.id}`;
        if (!t) {
          problems.push(`${where}: missing`);
          continue;
        }
        const fix = Array.isArray(s.fix) ? s.fix : s.fix ? [s.fix] : [];
        if (!t.title || !t.why === !!(s.why ?? '').trim()) problems.push(`${where}: title or why missing`);
        if (ph(t.title) !== ph(s.title)) problems.push(`${where}: title placeholders ${ph(s.title)} vs ${ph(t.title)}`);
        if (ph(t.why) !== ph(s.why)) problems.push(`${where}: why placeholders ${ph(s.why)} vs ${ph(t.why)}`);
        if (!Array.isArray(t.fix) || t.fix.length !== fix.length) problems.push(`${where}: fix has ${t.fix?.length ?? 0} items, source ${fix.length}`);
        else fix.forEach((x, i) => ph(x) !== ph(t.fix[i]) && problems.push(`${where}: fix[${i}] placeholders ${ph(x)} vs ${ph(t.fix[i])}`));
        for (const [k, v] of Object.entries(s.fix_by_provider ?? {})) {
          const tv = t.fix_by_provider?.[k];
          if (!tv) problems.push(`${where}: fix_by_provider.${k} missing`);
          else if (ph(tv) !== ph(v)) problems.push(`${where}: fix_by_provider.${k} placeholders ${ph(v)} vs ${ph(tv)}`);
        }
      }
    }
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const fi = args.indexOf('--files');
  const only = fi >= 0 ? args[fi + 1].split(',') : undefined;
  const langs = args.filter((a, i) => !a.startsWith('--') && (fi < 0 || i !== fi + 1));
  const p = checkKb(langs.length ? langs : undefined, only);
  for (const x of p.slice(0, 60)) console.log(x);
  console.log(p.length ? `${p.length} problems` : 'knowledge translations complete');
  process.exit(p.length ? 1 : 0);
}
