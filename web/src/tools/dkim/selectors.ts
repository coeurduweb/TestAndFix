// DKIM selectors typed by hand: tolerant parsing and per-domain memory (browser convenience only).

const VALID = /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/i;

/**
 * Selectors found in what was typed or pasted: "s1, s2", "s1._domainkey.example.fr",
 * a whole DKIM-Signature header (its s= tag), with quotes, spaces and case tolerated.
 */
export function parseSelectors(input: string): string[] {
  const out: string[] = [];
  const add = (s: string) => {
    const v = s.trim().toLowerCase().replace(/^["']|["';]$/g, '');
    if (v && v.length <= 63 * 3 && VALID.test(v) && !out.includes(v)) out.push(v);
  };
  const text = input.trim();
  if (!text) return out;
  // DKIM-Signature header or tag list: take the s= tags only
  if (/(^|[;\s])(v|a|d|b|bh|h)=/i.test(text) && /(^|[;\s])s=/i.test(text)) {
    for (const m of text.matchAll(/(?:^|[;\s])s=\s*([^;\s]+)/gi)) add(m[1]);
    return out;
  }
  for (const tok of text.split(/[\s,;]+/)) {
    if (!tok) continue;
    const dk = /^([^.]+(?:\.[^.]+)*?)\._domainkey(\.|$)/i.exec(tok);
    add(dk ? dk[1] : tok);
  }
  return out;
}

const KEY = 'check:dkim-selectors';
type Memory = Record<string, { s: string[]; at: number }>;

function read(): Memory {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? '{}') as Memory;
  } catch {
    return {};
  }
}
function write(m: Memory) {
  try {
    localStorage.setItem(KEY, JSON.stringify(m));
  } catch {
    /* storage unavailable: the page works without memory */
  }
}

export function rememberedFor(domain: string): string[] {
  return read()[domain]?.s ?? [];
}
export function remember(domain: string, selectors: string[]) {
  const m = read();
  const s = [...new Set([...(m[domain]?.s ?? []), ...selectors])].slice(0, 20);
  m[domain] = { s, at: Date.now() };
  write(m);
}
export function forget(domain: string, selector: string) {
  const m = read();
  if (!m[domain]) return;
  m[domain].s = m[domain].s.filter((x) => x !== selector);
  if (!m[domain].s.length) delete m[domain];
  write(m);
}
/** Selectors typed for other domains, most recent first: agencies reuse their own names. */
export function rememberedElsewhere(domain: string): { selector: string; domain: string }[] {
  const m = read();
  const out: { selector: string; domain: string }[] = [];
  for (const [d, v] of Object.entries(m).sort((a, b) => b[1].at - a[1].at)) {
    if (d === domain) continue;
    for (const s of v.s) if (!out.some((o) => o.selector === s)) out.push({ selector: s, domain: d });
  }
  return out.slice(0, 12);
}
