// Light HTML reading for e-mail bodies: tags and attributes, anchors, images, visible text.
// E-mail HTML is checked for a handful of elements; a tolerant tokenizer is enough and keeps the
// analyzer free of a DOM dependency.

export interface Tag {
  name: string;
  attrs: Record<string, string>;
  /** offset in the source */
  at: number;
}

const ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  eacute: 'é',
  egrave: 'è',
  ecirc: 'ê',
  agrave: 'à',
  acirc: 'â',
  ccedil: 'ç',
  ocirc: 'ô',
  ucirc: 'û',
  ugrave: 'ù',
  icirc: 'î',
  iuml: 'ï',
  euml: 'ë',
  laquo: '«',
  raquo: '»',
  rsquo: '’',
  lsquo: '‘',
  ldquo: '“',
  rdquo: '”',
  hellip: '…',
  euro: '€',
  copy: '©',
  reg: '®',
  trade: '™',
  zwnj: '‌',
  zwj: '‍',
  shy: '­',
};

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);?/gi, (m, e: string) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

function parseAttrs(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out[m[1].toLowerCase()] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? '');
  return out;
}

export function tags(html: string, names?: string[]): Tag[] {
  const want = names ? new Set(names) : undefined;
  const out: Tag[] = [];
  const re = /<([a-zA-Z][a-zA-Z0-9:-]*)(\s[^<>]*?)?\/?>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    const name = m[1].toLowerCase();
    if (want && !want.has(name)) continue;
    out.push({ name, attrs: parseAttrs(m[2] ?? ''), at: m.index });
  }
  return out;
}

export interface Anchor {
  href: string;
  text: string;
  /** inner HTML has an <img> */
  hasImage: boolean;
}

export function anchors(html: string): Anchor[] {
  const out: Anchor[] = [];
  const re = /<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    const attrs = parseAttrs(m[1]);
    if (attrs.href === undefined) continue;
    out.push({ href: attrs.href.trim(), text: visibleText(m[2]).trim(), hasImage: /<img\b/i.test(m[2]) });
  }
  return out;
}

/** Text a reader sees: no head, style, script or comments; entities decoded; spaces collapsed. */
export function visibleText(html: string): string {
  return decodeEntities(
    html
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<(head|style|script|title|noscript)\b[\s\S]*?<\/\1\s*>/gi, ' ')
      .replace(/<br\s*\/?>|<\/(p|div|tr|li|h[1-6]|td|table)>/gi, '\n')
      .replace(/<[^>]+>/g, ' '),
  )
    .replace(/[ \t\r\f\v]+/g, ' ')
    .replace(/\n\s*/g, '\n')
    .trim();
}

export function words(text: string): string[] {
  return text.toLowerCase().match(/[\p{L}\p{N}][\p{L}\p{N}'’-]*/gu) ?? [];
}

/** Jaccard similarity of the word sets, URLs removed. */
export function similarity(a: string, b: string): number {
  const strip = (s: string) => s.replace(/https?:\/\/\S+/g, ' ');
  const A = new Set(words(strip(a)));
  const B = new Set(words(strip(b)));
  if (!A.size && !B.size) return 1;
  let inter = 0;
  for (const w of A) if (B.has(w)) inter++;
  return inter / (A.size + B.size - inter);
}

export function urlsInText(text: string): string[] {
  return [...new Set((text.match(/\bhttps?:\/\/[^\s<>"'()\[\]]+/gi) ?? []).map((u) => u.replace(/[.,;:!?]+$/, '')))];
}
