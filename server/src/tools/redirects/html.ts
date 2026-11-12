// What the HTML of a hop says about where it goes, read WITHOUT running anything:
// meta refresh, plain JavaScript location changes, canonical link, robots meta, title.

export type Attrs = Record<string, string>;

/** Remove comments; optionally the content of <script>, <style>, <noscript>, <template>. */
function strip(html: string, blocks: string[]): string {
  let s = html.replace(/<!--[\s\S]*?-->/g, ' ');
  for (const b of blocks) s = s.replace(new RegExp(`<${b}\\b[^>]*>[\\s\\S]*?</${b}\\s*>`, 'gi'), ' ');
  return s;
}

function attrsOf(tag: string): Attrs {
  const out: Attrs = {};
  const re = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  const body = tag.replace(/^<\s*[\w:-]+/, '').replace(/\/?>$/, '');
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) out[m[1].toLowerCase()] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? '');
  return out;
}

export function decodeEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-f]+);?/gi, (_, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);?/g, (_, d: string) => String.fromCodePoint(Number(d)))
    .replace(/&quot;/g, '"')
    .replace(/&apos;|&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

export function tags(html: string, name: string): Attrs[] {
  const re = new RegExp(`<${name}\\b[^>]*>`, 'gi');
  return [...html.matchAll(re)].map((m) => attrsOf(m[0]));
}

/** Parse a Refresh value ("0; url=/x", "5,https://...", "3"). */
export function parseRefresh(v: string): { delay: number; url?: string } | undefined {
  const m = /^\s*(\d+)(?:\.\d*)?\s*(?:[;,]\s*(?:url\s*=\s*)?(.*))?$/i.exec(v);
  if (!m) return undefined;
  let url = m[2]?.trim();
  if (url && /^['"]/.test(url)) url = url.slice(1).replace(/['"]\s*$/, '');
  return { delay: Number(m[1]), url: url || undefined };
}

export function metaRefresh(html: string): { delay: number; url?: string; raw: string } | undefined {
  // a refresh inside <noscript> does not apply in a browser that runs scripts
  for (const a of tags(strip(html, ['script', 'style', 'noscript', 'template']), 'meta')) {
    if ((a['http-equiv'] ?? '').toLowerCase() !== 'refresh' || !a.content) continue;
    const r = parseRefresh(a.content);
    if (r) return { ...r, raw: a.content };
  }
  return undefined;
}

export interface JsRedirect {
  url: string;
  /** The statement as written. */
  code: string;
  /** Followed only when the page has almost no content of its own (an interstitial). */
  followed: boolean;
}

const JS_PATTERNS = [
  /\b(?:(?:window|document|top|self|parent)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=\s*(["'`])([^"'`\n]{1,2000}?)\1/g,
  /\b(?:(?:window|document|top|self|parent)\s*\.\s*)?location\s*\.\s*(?:replace|assign)\s*\(\s*(["'`])([^"'`\n]{1,2000}?)\1\s*\)/g,
];

/** Visible text length, scripts and styles removed. */
export function visibleTextLength(html: string): number {
  return strip(html, ['script', 'style', 'noscript', 'template', 'head']).replace(/<[^>]+>/g, ' ').replace(/&\w+;/g, ' ').replace(/\s+/g, ' ').trim().length;
}

export function jsRedirect(html: string): JsRedirect | undefined {
  const scripts = [...html.replace(/<!--[\s\S]*?-->/g, ' ').matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)]
    .filter((m) => !/\bsrc\s*=/i.test(m[1]) && !/type\s*=\s*["']?(application\/(ld\+)?json|text\/template)/i.test(m[1]))
    .map((m) => m[2].replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:"'])\/\/[^\n]*/g, '$1'));
  for (const code of scripts) {
    for (const re of JS_PATTERNS) {
      re.lastIndex = 0;
      const m = re.exec(code);
      if (!m) continue;
      const url = decodeEntities(m[2].trim());
      if (!url || url.includes('${') || /^(javascript|data):/i.test(url) || url === '#') continue;
      // short statement context, to show what was read
      const at = m.index;
      const snippet = code.slice(Math.max(0, at - 40), Math.min(code.length, at + m[0].length + 10)).replace(/\s+/g, ' ').trim();
      return { url, code: snippet, followed: visibleTextLength(html) < 1500 };
    }
  }
  return undefined;
}

export function canonicalLink(html: string): string | undefined {
  const head = /<\/head\s*>/i.exec(html);
  const scope = strip(head ? html.slice(0, head.index) : html, ['script', 'style', 'noscript', 'template']);
  for (const a of tags(scope, 'link')) {
    if ((a.rel ?? '').toLowerCase().split(/\s+/).includes('canonical') && a.href !== undefined) return a.href.trim();
  }
  return undefined;
}

/** Link: <https://x/>; rel="canonical", <...>; rel=alternate */
export function canonicalFromLinkHeader(values: string[]): string | undefined {
  for (const v of values) {
    for (const part of v.split(/,(?=\s*<)/)) {
      const m = /^\s*<([^>]*)>\s*(.*)$/.exec(part);
      if (!m) continue;
      const rel = /;\s*rel\s*=\s*"?([^";]+)"?/i.exec(m[2])?.[1];
      if (rel && rel.toLowerCase().split(/\s+/).includes('canonical')) return m[1].trim();
    }
  }
  return undefined;
}

export function metaRobots(html: string): string[] {
  return tags(strip(html, ['script', 'style', 'template']), 'meta')
    .filter((a) => /^(robots|googlebot|bingbot)$/i.test(a.name ?? '') && a.content)
    .map((a) => `${a.name.toLowerCase()}: ${a.content}`);
}

export function titleOf(html: string): string | undefined {
  const m = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(html);
  return m ? decodeEntities(m[1]).replace(/\s+/g, ' ').trim().slice(0, 300) || undefined : undefined;
}
