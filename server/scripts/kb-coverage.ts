// Lists situation ids used in the server code that have no entry in knowledge/situations.
// Usage: npm run kb:coverage -w server
import fs from 'node:fs';
import path from 'node:path';
import { loadKnowledge } from '../src/knowledge/engine.js';

const FAMILIES = [
  'spf', 'dkim', 'dmarc', 'arc', 'bimi', 'alignment', 'rdns', 'helo', 'blacklist', 'tls', 'mta-sts', 'dnssec', 'mx',
  'headers', 'content', 'html', 'links', 'images', 'attachments', 'unsubscribe', 'bulk-sender', 'reputation',
  'infrastructure', 'dmarc-report', 'ip', 'phishing', 'redirects', 'link', 'subdomains',
];
const kb = loadKnowledge();
const root = path.resolve(import.meta.dirname, '..', 'src');
const used = new Map<string, string[]>();
const passedOnly = new Set<string>(); // ids seen in pass(...) or PassedCheck objects
const asFinding = new Set<string>();
const re = new RegExp(`['"\`]((?:${FAMILIES.map((f) => f.replace('-', '\\-')).join('|')})\\.[a-z0-9_]+)['"\`]`, 'g');
function walk(dir: string) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name !== 'fixtures') walk(p);
    } else if (/\.ts$/.test(e.name) && !/\.test\.ts$/.test(e.name)) {
      const src = fs.readFileSync(p, 'utf8');
      for (const m of src.matchAll(re)) {
        const id = m[1];
        const before = src.slice(Math.max(0, m.index! - 40), m.index!);
        if (/pass(ed)?\s*\(\s*$|\bpass[A-Za-z]*\(\s*$|passed\.push\(\s*\{\s*id:\s*$/.test(before)) passedOnly.add(id);
        else asFinding.add(id);
        if (/\.(ts|js|json|yaml|com|org|net|fr)$/.test(id)) continue;
        used.set(id, [...(used.get(id) ?? []), path.relative(root, p)]);
      }
    }
  }
}
walk(root);
const missing = [...used.keys()].filter((id) => !kb.has(id) && !(passedOnly.has(id) && !asFinding.has(id))).sort();
console.log(`Base : ${kb.size} situations. Ids cités dans le code : ${used.size}. Sans fiche : ${missing.length}.`);
for (const id of missing) console.log(`  ${id}  (${[...new Set(used.get(id))].join(', ')})`);
process.exitCode = 0;
