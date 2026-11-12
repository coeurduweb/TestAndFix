// Shapes returned by /api/redirects/* (mirror of server/src/tools/redirects and lib/http-trace)
// and the small helpers the page needs: URL parameters, status wording, formatting.
import { msg, t } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';

export interface CertInfo {
  subject: string;
  subjectOrg?: string;
  issuer: string;
  issuerOrg?: string;
  san: string[];
  validFrom: string;
  validTo: string;
  daysLeft: number;
  serial?: string;
  fingerprint256?: string;
  keyBits?: number;
  chain: string[];
}
export interface TlsInfo {
  protocol?: string;
  cipher?: string;
  alpn?: string;
  chainValid: boolean;
  chainError?: string;
  nameValid: boolean;
  nameError?: string;
  cert?: CertInfo;
}
export interface BodyInfo {
  size: number;
  sizeComplete: boolean;
  truncated: boolean;
  contentEncoding?: string;
  decodedSize: number;
  decodeError?: string;
  contentType?: string;
  mime?: string;
  charset?: string;
  charsetSource?: 'header' | 'meta' | 'bom' | 'default';
  isText: boolean;
  text?: string;
  hexPreview?: string;
  storedCut?: boolean;
}
export interface Timings {
  dns: number;
  connect: number;
  tls: number;
  wait: number;
  download: number;
  total: number;
}
export interface HttpExchange {
  url: string;
  method: 'GET' | 'HEAD';
  host: string;
  requestLine: string;
  requestHeaders: [string, string][];
  ip?: string;
  port: number;
  cnames?: string[];
  httpVersion?: string;
  status?: number;
  statusText?: string;
  rawHeaders: [string, string][];
  body?: BodyInfo;
  timings: Timings;
  tls?: TlsInfo;
  error?: { code: string; message: string };
}
export type RedirectKind = 'http' | 'refresh' | 'meta' | 'js';
export interface Hop {
  index: number;
  url: string;
  method: 'GET' | 'HEAD';
  exchange: HttpExchange;
  redirect?: { kind: RedirectKind; to: string; raw: string; delay?: number };
  jsSeen?: { url: string; code: string };
  cookiesSent: number;
  startedAt: number;
}
export type StopReason = 'final' | 'loop' | 'max' | 'error' | 'unsafe' | 'scheme' | 'aborted';
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
  ua: { id: string; label: string; value: string };
  method: 'GET' | 'HEAD';
  cookies: boolean;
  extraHeaders: [string, string][];
  max: number;
  finalPage?: {
    canonical?: string;
    canonicalRaw?: string;
    canonicalSource?: 'html' | 'header';
    robots: string[];
    title?: string;
    hsts?: { raw: string; maxAge?: number; includeSubDomains: boolean; preload: boolean };
    h2?: boolean;
  };
}
export type TraceResult = CheckResult<TraceData>;

export interface VariantRow {
  label: string;
  url: string;
  hops: { status?: number; url: string; kind?: RedirectKind; error?: string }[];
  final: string;
  finalStatus?: number;
  redirects: number;
  /** Redirects that count: language negotiation left out. */
  effective: number;
  language: number;
  permanent: boolean;
  conform: boolean;
  reasons: string[];
  error?: string;
  ms: number;
}
export interface VariantsData {
  input: string;
  host: string;
  canonical?: string;
  allSame: boolean;
  conform: boolean;
  variants: VariantRow[];
}

export interface BatchRow {
  input: string;
  start?: string;
  final?: string;
  finalStatus?: number;
  redirects: number;
  statuses: (number | string)[];
  kinds: string[];
  ms: number;
  score?: number;
  alert?: string;
  alertId?: string;
  alerts: number;
  error?: string;
}

/* ---------- options carried by the page URL ---------- */

export const UAS = [
  { id: 'chrome', label: 'Chrome', long: msg('Chrome ordinateur') },
  { id: 'mobile', label: msg('Mobile'), long: msg('Chrome mobile') },
  { id: 'googlebot', label: 'Googlebot', long: 'Googlebot' },
  { id: 'bingbot', label: 'Bingbot', long: 'Bingbot' },
  { id: 'curl', label: 'curl', long: 'curl' },
  { id: 'custom', label: msg('Personnalisé'), long: msg('Agent personnalisé') },
] as const;

export interface TraceOptions {
  ua: string; // preset id or 'custom'
  uaText: string; // custom user agent
  method: 'GET' | 'HEAD';
  cookies: boolean;
  headers: [string, string][];
}

export function readOptions(p: URLSearchParams): TraceOptions {
  const ua = p.get('ua') ?? 'chrome';
  let headers: [string, string][] = [];
  try {
    const raw = p.get('h');
    if (raw) headers = (JSON.parse(raw) as [string, string][]).filter((x) => Array.isArray(x) && x.length === 2);
  } catch {
    headers = [];
  }
  return {
    ua: UAS.some((u) => u.id === ua) ? ua : 'custom',
    uaText: UAS.some((u) => u.id === ua) ? (p.get('uat') ?? '') : ua,
    method: p.get('methode') === 'HEAD' ? 'HEAD' : 'GET',
    cookies: p.get('cookies') !== '0',
    headers,
  };
}

/** Write options into search params; defaults are left out to keep the link short. */
export function writeOptions(p: URLSearchParams, o: TraceOptions): URLSearchParams {
  const n = new URLSearchParams(p);
  for (const k of ['ua', 'uat', 'methode', 'cookies', 'h']) n.delete(k);
  if (o.ua === 'custom') {
    n.set('ua', 'custom');
    if (o.uaText) n.set('uat', o.uaText);
  } else if (o.ua !== 'chrome') n.set('ua', o.ua);
  if (o.method === 'HEAD') n.set('methode', 'HEAD');
  if (!o.cookies) n.set('cookies', '0');
  const h = o.headers.filter(([k]) => k.trim());
  if (h.length) n.set('h', JSON.stringify(h));
  return n;
}

export function apiQuery(url: string, o: TraceOptions): string {
  const q = new URLSearchParams({ url });
  const ua = o.ua === 'custom' ? o.uaText.trim() : o.ua;
  if (ua && ua !== 'chrome') q.set('ua', ua);
  if (o.method === 'HEAD') q.set('method', 'HEAD');
  if (!o.cookies) q.set('cookies', '0');
  const h = o.headers.filter(([k]) => k.trim());
  if (h.length) q.set('headers', JSON.stringify(h));
  return q.toString();
}

/* ---------- wording ---------- */

const REASON: Record<number, string> = {
  200: 'OK', 201: 'Created', 204: 'No Content', 206: 'Partial Content', 300: 'Multiple Choices', 301: 'Moved Permanently', 302: 'Found',
  303: 'See Other', 304: 'Not Modified', 307: 'Temporary Redirect', 308: 'Permanent Redirect', 400: 'Bad Request', 401: 'Unauthorized',
  403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed', 410: 'Gone', 429: 'Too Many Requests', 451: 'Unavailable For Legal Reasons',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout',
};

const MEANING: Record<number, string> = {
  301: msg('définitive'), 308: msg('définitive, méthode conservée'), 302: msg('temporaire'), 303: msg('temporaire, en GET'), 307: msg('temporaire, méthode conservée'),
  304: msg('non modifiée'), 401: msg('authentification requise'), 403: msg('accès refusé'), 404: msg('introuvable'), 410: msg('supprimée'), 429: msg('trop de requêtes'),
  451: msg('bloquée pour raison légale'), 500: msg('erreur serveur'), 502: msg('passerelle en erreur'), 503: msg('indisponible'), 504: msg('passerelle sans réponse'),
};

export const reasonOf = (s: number, given?: string) => given || REASON[s] || '';
export const meaningOf = (s: number) => t(MEANING[s] ?? (s >= 500 ? msg('erreur serveur') : s >= 400 ? msg('erreur') : ''));

export type Tone = 'ok' | 'lab' | 'out' | 'muted';
export function toneOf(s?: number | string): Tone {
  if (typeof s !== 'number') return 'out';
  if (s >= 200 && s < 300) return 'ok';
  if (s >= 300 && s < 400) return 'lab';
  if (s >= 400) return 'out';
  return 'muted';
}

/** msg() ids: pass through t() where shown. */
export const KIND_LABEL: Record<RedirectKind, string> = {
  http: msg('en-tête Location'),
  refresh: msg('en-tête Refresh'),
  meta: 'meta refresh',
  js: 'JavaScript',
};

export function hostOf(u: string): string {
  try {
    return new URL(u).host;
  } catch {
    return u;
  }
}

/** Display URL without the trailing slash of a bare host. */
export function shortUrl(u: string): string {
  return u.replace(/^(https?:\/\/[^/]+)\/$/, '$1');
}

export const uaLabel = (id: string) => t(UAS.find((u) => u.id === id)?.long ?? id);

export function csvCell(v: unknown): string {
  const s = v === undefined || v === null ? '' : String(v);
  return /[",;\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
