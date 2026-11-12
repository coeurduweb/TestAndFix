// Reading of a fetched HTML page without executing anything: title, meta refresh, simple
// JavaScript redirects, password and card forms.

export interface PageFacts {
  title?: string;
  /** Target of <meta http-equiv="refresh">, with its delay in seconds. */
  metaRefresh?: { url: string; delay: number };
  /** Target of a plain `location.href = "..."` style redirect. */
  jsRedirect?: { url: string; code: string };
  passwordForm: boolean;
  cardForm: boolean;
  /** Evidence of the card form (field names, labels). */
  cardHints: string[];
  /** Actions of the forms of the page (absolute when possible). */
  formActions: string[];
  /** Length of the visible text, a hint of a transition page. */
  textLength: number;
}

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', eacute: 'é', egrave: 'è', agrave: 'à', ccedil: 'ç', ecirc: 'ê' };

export function decodeEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_m, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_m, d: string) => String.fromCodePoint(Number(d)))
    .replace(/&([a-z]+);/gi, (m, n: string) => ENTITIES[n.toLowerCase()] ?? m);
}

function attr(tag: string, name: string): string | undefined {
  const m = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag);
  return m ? decodeEntities(m[1] ?? m[2] ?? m[3] ?? '') : undefined;
}

function resolve(href: string, base: string): string | undefined {
  try {
    return new URL(href.trim(), base).toString();
  } catch {
    return undefined;
  }
}

/** Visible text: scripts, styles and tags removed. */
export function visibleText(html: string): string {
  return decodeEntities(
    html
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<(script|style|noscript|template)\b[\s\S]*?<\/\1\s*>/gi, ' ')
      .replace(/<[^>]+>/g, ' '),
  )
    .replace(/\s+/g, ' ')
    .trim();
}

// location = "..."; window.location.href = '...'; top.location.replace("..."); location.assign('...')
const JS_ASSIGN = /\b(?:(?:window|document|top|self|parent)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=\s*(["'`])([^"'`\s]{1,2000})\1/;
const JS_CALL = /\b(?:(?:window|document|top|self|parent)\s*\.\s*)?location\s*\.\s*(?:replace|assign)\s*\(\s*(["'`])([^"'`\s]{1,2000})\1\s*\)/;

/** Pages longer than this are real pages, not transition pages: a location= in them is not followed. */
export const JS_REDIRECT_MAX_TEXT = 1500;

const CARD_FIELD = /autocomplete\s*=\s*["']?cc-(number|csc|exp)|name\s*=\s*["']?[^"'>]*(card.?num|cardnumber|cc.?num|ccnumber|num.?carte|cvv|cvc|cryptogramme|card.?code|expiry|expiration)/i;
const CARD_TEXT = /num[eé]ro de (?:la )?carte|cryptogramme|code de s[ée]curit[ée] (?:de la carte|à 3 chiffres)|\bcvv\b|\bcvc\b|date d.expiration|card number|security code/i;

export function readPage(html: string, baseUrl: string): PageFacts {
  const facts: PageFacts = { passwordForm: false, cardForm: false, cardHints: [], formActions: [], textLength: 0 };
  const t = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(html);
  if (t) facts.title = decodeEntities(t[1]).replace(/\s+/g, ' ').trim().slice(0, 300) || undefined;

  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = m[0];
    if (!/^refresh$/i.test(attr(tag, 'http-equiv') ?? '')) continue;
    const content = attr(tag, 'content') ?? '';
    const r = /^\s*(\d+(?:\.\d+)?)?\s*[;,]?\s*(?:url\s*=\s*)?(['"]?)(.+?)\2\s*$/i.exec(content);
    if (r && r[3] && /url\s*=|^\s*\d+\s*[;,]/i.test(content)) {
      const url = resolve(r[3], baseUrl);
      if (url) facts.metaRefresh = { url, delay: Number(r[1] ?? 0) };
    }
    break;
  }

  const text = visibleText(html);
  facts.textLength = text.length;
  if (text.length <= JS_REDIRECT_MAX_TEXT) {
    const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi)].map((m) => m[1]).join('\n');
    const handlers = [...html.matchAll(/\bon(?:load|pageshow)\s*=\s*(["'])([\s\S]*?)\1/gi)].map((m) => m[2]).join('\n');
    for (const code of [scripts, handlers]) {
      const m = JS_CALL.exec(code) ?? JS_ASSIGN.exec(code);
      if (!m) continue;
      const target = m[2];
      if (/^(javascript:|#|data:)/i.test(target)) continue;
      const url = resolve(target, baseUrl);
      if (url && /^https?:/i.test(url)) {
        facts.jsRedirect = { url, code: m[0].slice(0, 200) };
        break;
      }
    }
  }

  facts.passwordForm = /<input\b[^>]*\btype\s*=\s*["']?password\b/i.test(html);
  const fields = [...html.matchAll(/<input\b[^>]*>/gi)].map((m) => m[0]).filter((tag) => CARD_FIELD.test(tag));
  const textHit = CARD_TEXT.exec(text);
  facts.cardHints = [...fields.slice(0, 3).map((f) => f.slice(0, 120)), ...(textHit ? [`texte : « ${textHit[0]} »`] : [])];
  // a card form needs a field; a sentence alone (an FAQ about payments) is not one
  // or a form with input fields whose text asks for the card's security code
  facts.cardForm = fields.length > 0 || (!!textHit && /<form\b/i.test(html) && /<input\b/i.test(html) && /\bcvv\b|\bcvc\b|cryptogramme|security code/i.test(text));
  for (const m of html.matchAll(/<form\b[^>]*>/gi)) {
    const action = attr(m[0], 'action');
    const abs = action ? resolve(action, baseUrl) : undefined;
    if (abs) facts.formActions.push(abs);
  }
  facts.formActions = [...new Set(facts.formActions)].slice(0, 10);
  return facts;
}
