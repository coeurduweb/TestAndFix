// Redirect chain (US-069, US-071): every hop requested for real with lib/http-trace (SSRF check
// at each hop, iterative DNS, no cache), followed through HTTP 3xx + Location, the Refresh header,
// meta refresh and plain JavaScript location changes read in the HTML without running it.
import { browserAcceptLanguage, msg, t } from '../../i18n.js';
import { InvalidInputError } from '../../lib/email-auth/common.js';
import {
  ACCEPT_ENCODING, getHeader, getHeaders, probeH2, traceRequest,
  type AddressResolver, type HttpExchange, type NetworkSeam,
} from '../../lib/http-trace.js';
import { CookieJar } from './cookies.js';
import { canonicalFromLinkHeader, canonicalLink, jsRedirect, metaRefresh, metaRobots, parseRefresh, titleOf, type JsRedirect } from './html.js';

/* ---------- user agents ---------- */

export type UaId = 'chrome' | 'mobile' | 'googlebot' | 'bingbot' | 'curl' | 'custom';

/** Replaced at request time by the reader's languages (i18n.ts): a site answers like it would to them. */
const ACCEPT_LANGUAGE_OF_READER = '<reader>';
const BROWSER_ACCEPT = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8';
// Chrome's reduced user-agent strings (minor version always 0.0.0). Update the major version
// once in a while; the Googlebot and Bingbot strings follow their documented shapes.
const CHROME = '142.0.0.0';

export const USER_AGENTS: Record<Exclude<UaId, 'custom'>, { label: string; value: string; headers: [string, string][] }> = {
  chrome: {
    label: msg('Chrome ordinateur'),
    value: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${CHROME} Safari/537.36`,
    headers: [
      ['Accept', BROWSER_ACCEPT],
      ['Accept-Language', ACCEPT_LANGUAGE_OF_READER],
      ['Accept-Encoding', ACCEPT_ENCODING],
      ['Upgrade-Insecure-Requests', '1'],
    ],
  },
  mobile: {
    label: msg('Chrome mobile'),
    value: `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${CHROME} Mobile Safari/537.36`,
    headers: [
      ['Accept', BROWSER_ACCEPT],
      ['Accept-Language', ACCEPT_LANGUAGE_OF_READER],
      ['Accept-Encoding', ACCEPT_ENCODING],
      ['Upgrade-Insecure-Requests', '1'],
    ],
  },
  googlebot: {
    label: 'Googlebot',
    value: `Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${CHROME} Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`,
    headers: [
      ['Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
      ['Accept-Encoding', 'gzip, deflate, br'],
    ],
  },
  bingbot: {
    label: 'Bingbot',
    value: `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/${CHROME} Safari/537.36`,
    headers: [
      ['Accept', '*/*'],
      ['Accept-Encoding', 'gzip, deflate, br'],
    ],
  },
  curl: { label: 'curl', value: 'curl/8.11.1', headers: [['Accept', '*/*']] },
};

export function resolveUa(ua?: string): { id: UaId; label: string; value: string; headers: [string, string][] } {
  const key = (ua ?? '').trim();
  if (!key || key === 'chrome') return { id: 'chrome', ...USER_AGENTS.chrome };
  if (key in USER_AGENTS) return { id: key as UaId, ...USER_AGENTS[key as Exclude<UaId, 'custom'>] };
  if (/[\r\n\0]/.test(key)) throw new InvalidInputError(t('Agent utilisateur invalide (retour à la ligne).'));
  return { id: 'custom', label: msg('Personnalisé'), value: key.slice(0, 500), headers: [['Accept', '*/*'], ['Accept-Encoding', ACCEPT_ENCODING]] };
}

/* ---------- input ---------- */

/** Tolerant input: bare domain → https://domain/, quotes and angle brackets removed. */
export function normalizeUrlInput(raw: string): { url: string; bare: boolean } {
  let s = String(raw ?? '').trim().replace(/^[<"'(\[]+|[>"')\]]+$/g, '').trim();
  if (!s) throw new InvalidInputError(t('Saisissez une URL ou un nom de domaine.'));
  if (/\s/.test(s)) s = s.replace(/\s/g, '%20');
  let bare = false;
  if (s.startsWith('//')) s = 'https:' + s;
  else if (!/^[a-z][a-z0-9+.-]*:/i.test(s) || /^[^/:]+:\d+(\/|$)/.test(s)) {
    s = 'https://' + s;
    bare = true;
  }
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new InvalidInputError(t("« {raw} » n'est pas une URL valide.", { raw }));
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new InvalidInputError(t('Seules les adresses http:// et https:// se suivent (reçu {protocol}).', { protocol: u.protocol }));
  if (!u.hostname || (!u.hostname.includes('.') && !u.hostname.startsWith('['))) throw new InvalidInputError(t("« {raw} » n'a pas de nom de domaine complet.", { raw }));
  u.hostname = u.hostname.replace(/\.$/, '');
  u.hash = '';
  return { url: u.toString(), bare };
}

/* ---------- chain ---------- */

export type RedirectKind = 'http' | 'refresh' | 'meta' | 'js';

export interface Redirect {
  kind: RedirectKind;
  /** Absolute target. */
  to: string;
  /** Value as written (Location, Refresh, meta content, script statement). */
  raw: string;
  delay?: number;
}

export interface Hop {
  index: number;
  url: string;
  method: 'GET' | 'HEAD';
  exchange: HttpExchange;
  redirect?: Redirect;
  /** A JavaScript redirect seen on a page with real content: shown, not followed. */
  jsSeen?: JsRedirect;
  cookiesSent: number;
  /** ms since the start of the trace when this hop started. */
  startedAt: number;
}

export type StopReason = 'final' | 'loop' | 'max' | 'error' | 'unsafe' | 'scheme' | 'aborted';

export interface Hsts {
  raw: string;
  maxAge?: number;
  includeSubDomains: boolean;
  preload: boolean;
}

export interface FinalPage {
  canonical?: string;
  canonicalRaw?: string;
  canonicalSource?: 'html' | 'header';
  robots: string[];
  title?: string;
  hsts?: Hsts;
  h2?: boolean;
}

export interface TraceData {
  input: string;
  start: string;
  bare: boolean;
  final: string;
  finalStatus?: number;
  hops: Hop[];
  redirects: number;
  stoppedBy: StopReason;
  stopDetail?: string;
  totalMs: number;
  ua: { id: UaId; label: string; value: string };
  method: 'GET' | 'HEAD';
  cookies: boolean;
  extraHeaders: [string, string][];
  max: number;
  finalPage?: FinalPage;
}

export interface TraceOptions {
  ua?: string;
  method?: 'GET' | 'HEAD';
  cookies?: boolean;
  headers?: [string, string][];
  max?: number;
  dns?: AddressResolver;
  network?: NetworkSeam;
  signal?: AbortSignal;
  onHop?: (hop: Hop) => void;
  /** Skip the HTTP/2 probe (batch). */
  light?: boolean;
}

export function parseHsts(v: string): Hsts {
  const parts = v.split(';').map((p) => p.trim()).filter(Boolean);
  const ma = parts.map((p) => /^max-age\s*=\s*"?(\d+)"?$/i.exec(p)?.[1]).find(Boolean);
  return {
    raw: v,
    maxAge: ma !== undefined ? Number(ma) : undefined,
    includeSubDomains: parts.some((p) => p.toLowerCase() === 'includesubdomains'),
    preload: parts.some((p) => p.toLowerCase() === 'preload'),
  };
}

function abs(target: string, base: string): string | undefined {
  try {
    const u = new URL(target.trim(), base);
    u.hash = '';
    return u.toString();
  } catch {
    return undefined;
  }
}

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

function nextOf(ex: HttpExchange, url: string): { redirect?: Redirect; jsSeen?: JsRedirect; bad?: string } {
  const st = ex.status ?? 0;
  if (REDIRECT_STATUS.has(st) || (st >= 300 && st < 400 && getHeader(ex.rawHeaders, 'location'))) {
    const loc = getHeader(ex.rawHeaders, 'location');
    if (!loc) return {};
    const to = abs(loc, url);
    return to ? { redirect: { kind: 'http', to, raw: loc } } : { bad: loc };
  }
  const refresh = getHeader(ex.rawHeaders, 'refresh');
  if (refresh) {
    const r = parseRefresh(refresh);
    const to = r?.url ? abs(r.url, url) : undefined;
    if (to && to !== url) return { redirect: { kind: 'refresh', to, raw: refresh, delay: r!.delay } };
  }
  const html = ex.body?.isText && ex.body.mime?.includes('html') ? ex.body.text : undefined;
  if (html && st >= 200 && st < 300) {
    const m = metaRefresh(html);
    const to = m?.url ? abs(m.url, url) : undefined;
    if (to && to !== url) return { redirect: { kind: 'meta', to, raw: m!.raw, delay: m!.delay } };
    const js = jsRedirect(html);
    if (js) {
      const t = abs(js.url, url);
      if (t && t !== url && js.followed) return { redirect: { kind: 'js', to: t, raw: js.code } };
      if (t && t !== url) return { jsSeen: { ...js, url: t } };
    }
  }
  return {};
}

function finalPageOf(ex: HttpExchange, url: string): FinalPage {
  const fp: FinalPage = { robots: getHeaders(ex.rawHeaders, 'x-robots-tag').map((v) => `X-Robots-Tag: ${v}`) };
  const html = ex.body?.isText && ex.body.mime?.includes('html') ? ex.body.text : undefined;
  const fromHeader = canonicalFromLinkHeader(getHeaders(ex.rawHeaders, 'link'));
  const fromHtml = html ? canonicalLink(html) : undefined;
  const raw = fromHtml ?? fromHeader;
  if (raw !== undefined) {
    fp.canonicalRaw = raw;
    fp.canonical = abs(raw, url);
    fp.canonicalSource = fromHtml !== undefined ? 'html' : 'header';
  }
  if (html) {
    fp.robots.push(...metaRobots(html));
    fp.title = titleOf(html);
  }
  const sts = url.startsWith('https:') ? getHeader(ex.rawHeaders, 'strict-transport-security') : undefined;
  if (sts) fp.hsts = parseHsts(sts);
  return fp;
}

export async function traceChain(input: string, o: TraceOptions = {}): Promise<TraceData> {
  const { url: start, bare } = normalizeUrlInput(input);
  const ua = resolveUa(o.ua);
  const method = o.method === 'HEAD' ? 'HEAD' : 'GET';
  const max = Math.min(30, Math.max(1, Math.floor(o.max ?? 15)));
  const jar = o.cookies === false ? undefined : new CookieJar();
  const extra = o.headers ?? [];
  const userCookie = extra.find(([k]) => k.toLowerCase() === 'cookie')?.[1];
  const t0 = performance.now();
  const hops: Hop[] = [];
  const seen = new Set<string>();
  let url = start;
  let stoppedBy: StopReason = 'final';
  let stopDetail: string | undefined;

  for (let i = 0; ; i++) {
    if (o.signal?.aborted) {
      stoppedBy = 'aborted';
      break;
    }
    const fromJar = jar?.header(url);
    const cookie = [userCookie, fromJar?.value].filter(Boolean).join('; ') || undefined;
    const headers: [string, string][] = [
      ['User-Agent', ua.value],
      ...ua.headers.filter(([k]) => !extra.some(([e]) => e.toLowerCase() === k.toLowerCase())).map(([k, v]): [string, string] => [k, v === ACCEPT_LANGUAGE_OF_READER ? browserAcceptLanguage() : v]),
      ...extra.filter(([k]) => k.toLowerCase() !== 'cookie'),
      ...(cookie ? ([['Cookie', cookie]] as [string, string][]) : []),
    ];
    const key = `${method} ${url} ${cookie ?? ''}`;
    seen.add(key);
    const startedAt = Math.round(performance.now() - t0);
    const ex = await traceRequest(url, { method, headers, dns: o.dns, network: o.network, signal: o.signal });
    if (jar && ex.status !== undefined) jar.store(url, getHeaders(ex.rawHeaders, 'set-cookie'));
    const hop: Hop = { index: i + 1, url, method, exchange: ex, cookiesSent: fromJar?.count ?? 0, startedAt };
    if (ex.error && ex.status === undefined) {
      stoppedBy = ex.error.code === 'UNSAFE_TARGET' ? 'unsafe' : ex.error.code === 'ABORTED' ? 'aborted' : 'error';
      stopDetail = ex.error.message;
      hops.push(hop);
      o.onHop?.(hop);
      break;
    }
    const n = nextOf(ex, url);
    if (n.redirect) hop.redirect = n.redirect;
    if (n.jsSeen) hop.jsSeen = n.jsSeen;
    hops.push(hop);
    o.onHop?.(hop);
    if (n.bad) {
      stoppedBy = 'error';
      stopDetail = `Location illisible : ${n.bad.slice(0, 200)}`;
      break;
    }
    if (!n.redirect) break;
    const to = n.redirect.to;
    if (!/^https?:/i.test(to)) {
      stoppedBy = 'scheme';
      stopDetail = t('Redirection vers une adresse non web : {to}', { to: to.slice(0, 200) });
      break;
    }
    const nextCookie = [userCookie, jar?.header(to).value].filter(Boolean).join('; ') || '';
    if (seen.has(`${method} ${to} ${nextCookie}`)) {
      stoppedBy = 'loop';
      stopDetail = t('{to} renvoie vers une adresse déjà visitée dans cette chaîne.', { to });
      break;
    }
    if (hops.length >= max) {
      stoppedBy = 'max';
      stopDetail = t('Arrêt après {max} requêtes : la chaîne continue vers {to}.', { max, to });
      break;
    }
    url = to;
  }

  const last = hops[hops.length - 1];
  const data: TraceData = {
    input,
    start,
    bare,
    final: last.url,
    finalStatus: last.exchange.status,
    hops,
    redirects: hops.filter((h) => h.redirect).length,
    stoppedBy,
    stopDetail,
    totalMs: Math.round(performance.now() - t0),
    ua: { id: ua.id, label: t(ua.label), value: ua.value },
    method,
    cookies: !!jar,
    extraHeaders: extra,
    max,
  };
  if (stoppedBy === 'final' && last.exchange.status !== undefined) {
    data.finalPage = finalPageOf(last.exchange, last.url);
    if (!o.light && last.url.startsWith('https:')) data.finalPage.h2 = await probeH2(last.url, { dns: o.dns, network: o.network, ip: last.exchange.ip });
  }
  return data;
}
