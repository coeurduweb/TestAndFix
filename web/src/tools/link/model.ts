// Link check: shapes of server/src/tools/link/analyze.ts, the stream reducer, live alerts, and the
// helpers that keep a suspicious URL as inert text (never a link, never fetched by the browser).
import { msg, t, tn } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';

export interface Hop {
  index: number;
  url: string;
  host: string;
  domain: string;
  ip?: string;
  port?: number;
  status?: number;
  ms: number;
  via: 'start' | 'http' | 'meta' | 'js';
  next?: 'http' | 'meta' | 'js';
  location?: string;
  contentType?: string;
  bytes?: number;
  truncated?: boolean;
  server?: string;
  error?: string;
}

export interface TlsInfo {
  host: string;
  ip: string;
  port: number;
  protocol?: string;
  authorized: boolean;
  authorizationError?: string;
  subject?: string;
  san: string[];
  issuer?: string;
  issuerOrg?: string;
  validFrom?: string;
  validTo?: string;
  ageDays?: number;
  daysLeft?: number;
  expired: boolean;
  selfSigned: boolean;
  nameMatches: boolean;
  freeCa: boolean;
  error?: string;
}

export interface Lookalike {
  host: string;
  unicode?: string;
  brand: string;
  brandName: string;
  kind: 'homoglyph' | 'typo' | 'subdomain' | 'word' | 'contains';
  matched: string;
  distance?: number;
  phishingWord?: string;
  official: string[];
}

export interface PageFacts {
  title?: string;
  passwordForm: boolean;
  cardForm: boolean;
  cardHints: string[];
  formActions: string[];
  textLength: number;
  brandsInTitle: string[];
  contentType?: string;
  bytes?: number;
  truncated?: boolean;
}

export interface DomainHit {
  zone: string;
  name: string;
  target: string;
  query: string;
  status: 'listed' | 'clean' | 'refused' | 'error';
  codes: string[];
  meaning?: string;
  delistUrl?: string;
}

export interface VtUrlData {
  url: string;
  found: boolean;
  stats?: { malicious: number; suspicious: number; harmless: number; undetected: number };
  flagged: { engine: string; category: string; result?: string }[];
  lastAnalysisDate?: string;
  submitted?: boolean;
  link: string;
}

export interface Intel {
  safebrowsing?: { checked: string[]; matches: { url: string; threatType: string; platformType: string }[] };
  virustotal?: VtUrlData[];
  urlhaus?: { urls: { url: string; listed: boolean; status?: string; threat?: string; tags: string[]; dateAdded?: string }[]; host?: { host: string; listed: boolean; urlCount: number; onlineCount: number } };
  openphish?: { feedSize: number; fetchedAt: string; stale?: string; exact: string[]; sameHost: { url: string; feedUrls: string[] }[] };
  urlscan?: { host: string; total: number; scans: { time: string; url: string; title?: string }[]; searchLink: string }[];
  dnsbl?: { queried: string[]; listed: DomainHit[]; refused: DomainHit[]; errors: { zone: string; target: string; error?: string }[]; clean: number };
}

export interface RdapAge {
  ageDays?: number;
  created?: string;
  registrar?: string;
  unavailable?: string;
  notRegistered?: boolean;
}

export interface LinkReport {
  url: string;
  verdict: 'sûr' | 'suspect' | 'dangereux';
  level: 'safe' | 'suspicious' | 'dangerous';
  reason: string;
  start: string;
  final: string;
  chain: { hops: Hop[]; stoppedBy?: 'max_hops' | 'loop' | 'error' | 'unsafe' | 'budget'; jsRedirects: number; metaRefreshes: number; domains: string[] };
  domains: { domain: string; ageDays?: number; created?: string; registrar?: string; ageSource?: 'rdap' | 'urlscan.io'; unavailable?: string }[];
  tls: TlsInfo[];
  page?: PageFacts;
  lookalikes: Lookalike[];
  punycode: { host: string; label: string; unicode: string; mixedScripts: boolean }[];
  intel: Intel;
}

export interface StepEvent {
  step: string;
  label: string;
  status: 'ok' | 'unavailable' | 'skipped';
  ms?: number;
  reason?: string;
  data?: unknown;
}

export interface LinkState {
  url?: string;
  steps: { id: string; label: string }[];
  hops: Hop[];
  events: Record<string, StepEvent>;
  result?: CheckResult<LinkReport>;
}

export const initialLink = (): LinkState => ({ steps: [], hops: [], events: {} });

export function linkReducer(s: LinkState, e: { type: string; data: unknown }): LinkState {
  if (e.type === 'start') {
    const d = e.data as { url: string; steps: LinkState['steps'] };
    return { ...s, url: d.url, steps: d.steps ?? [] };
  }
  if (e.type === 'step') {
    const ev = e.data as StepEvent;
    if (ev.step === 'hop') {
      const h = ev.data as Hop;
      return { ...s, hops: [...s.hops.filter((x) => x.index !== h.index), h].sort((a, b) => a.index - b.index) };
    }
    return { ...s, events: { ...s.events, [ev.step]: ev } };
  }
  if (e.type === 'done') return { ...s, result: e.data as CheckResult<LinkReport> };
  return s;
}

/** Sources that already say "malicious" while the measure is running (the verdict comes at the end). */
export function liveAlerts(events: Record<string, StepEvent>): string[] {
  const out: string[] = [];
  const data = (id: string) => (events[id]?.status === 'ok' ? events[id].data : undefined);
  const gsb = data('safebrowsing') as Intel['safebrowsing'];
  if (gsb?.matches.length) out.push('Google Safe Browsing');
  const vt = data('virustotal') as Intel['virustotal'];
  if (vt?.some((v) => (v.stats?.malicious ?? 0) >= 2)) out.push('VirusTotal');
  const uh = data('urlhaus') as Intel['urlhaus'];
  if (uh?.urls.some((u) => u.listed)) out.push('URLhaus');
  const op = data('openphish') as Intel['openphish'];
  if (op?.exact.length) out.push('OpenPhish');
  const dl = data('dnsbl') as Intel['dnsbl'];
  if (dl?.listed.length) out.push(...new Set(dl.listed.map((h) => h.name)));
  return out;
}

/** Undo the usual "defanging" of shared malicious links: hxxp, [.], (.), [:], spaces. */
export function refang(raw: string): string {
  return raw
    .trim()
    .replace(/^<|>$/g, '')
    .replace(/^h[xX]{2}p(s?)/i, 'http$1')
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}/g, '.')
    .replace(/\[\s*:\s*\]/g, ':')
    .replace(/\[\s*\/\s*\]/g, '/')
    .replace(/\s+/g, '');
}

/** A URL cut into parts for display: the registrable domain is the part that says who owns it. */
export function splitUrl(url: string, domain?: string): { scheme: string; userinfo: string; sub: string; domain: string; rest: string } {
  const m = /^([a-z][a-z0-9+.-]*:\/\/)([^/?#]*)(.*)$/i.exec(url);
  if (!m) return { scheme: '', userinfo: '', sub: '', domain: url, rest: '' };
  let auth = m[2];
  let userinfo = '';
  const at = auth.lastIndexOf('@');
  if (at >= 0) {
    userinfo = auth.slice(0, at + 1);
    auth = auth.slice(at + 1);
  }
  const port = /:\d+$/.exec(auth)?.[0] ?? '';
  const host = port ? auth.slice(0, -port.length) : auth;
  const d = domain && host.toLowerCase().endsWith(domain.toLowerCase()) ? host.slice(host.length - domain.length) : host;
  return { scheme: m[1], userinfo, sub: host.slice(0, host.length - d.length), domain: d, rest: port + m[3] };
}

export const VIA_LABEL: Record<Hop['via'], string> = { start: msg('départ'), http: msg('redirection HTTP'), meta: msg('balise meta refresh'), js: msg('script de la page') };

export const STOP_LABEL: Record<string, string> = {
  max_hops: msg('Arrêt à la quinzième requête : la chaîne est trop longue pour un lien normal.'),
  loop: msg('Arrêt sur une boucle : la page renvoie vers une adresse déjà visitée.'),
  error: msg('Arrêt sur une erreur : la requête suivante n’a pas pu aboutir.'),
  unsafe: msg('Arrêt volontaire : la redirection suivante vise une adresse privée ou locale, que TestAndFix ne visite pas.'),
  budget: msg('Arrêt au bout de 45 secondes : les serveurs de la chaîne répondent trop lentement.'),
};

/** "6 972 jours" -> "19 ans". */
export function fmtAge(days: number): string {
  if (days < 1) return t('moins d’un jour');
  if (days < 60) return tn(days, '{n} jour', '{n} jours');
  if (days < 730) return t('{n} mois', { n: Math.floor(days / 30.44) });
  return tn(Math.floor(days / 365.25), '{n} an', '{n} ans');
}

/** Check page of a link: the URL travels in the query string. */
export const linkPath = (url: string, submit = false) => `/lien?url=${encodeURIComponent(url)}${submit ? '&soumettre=1' : ''}`;

const SCRIPTS: [string, RegExp][] = [
  [msg('latin'), /\p{Script=Latin}/u],
  [msg('cyrillique'), /\p{Script=Cyrillic}/u],
  [msg('grec'), /\p{Script=Greek}/u],
  [msg('arménien'), /\p{Script=Armenian}/u],
  [msg('arabe'), /\p{Script=Arabic}/u],
  [msg('hébreu'), /\p{Script=Hebrew}/u],
  [msg('chinois ou japonais'), /\p{Script=Han}|\p{Script=Hiragana}|\p{Script=Katakana}/u],
  [msg('coréen'), /\p{Script=Hangul}/u],
  [msg('thaï'), /\p{Script=Thai}/u],
];
/** Writing systems used by a label, to say "cyrillique" next to a name that reads as Latin. */
export function scriptsOf(label: string): string[] {
  return SCRIPTS.filter(([, re]) => [...label].some((c) => re.test(c))).map(([n]) => t(n));
}

/** One row per imitated name: "www.аррӏе.com" and "аррӏе.com" are the same look-alike. */
export function dedupeLookalikes<T extends { host: string; unicode?: string; brand: string }>(list: T[]): { item: T; hosts: string[] }[] {
  const m = new Map<string, { item: T; hosts: string[] }>();
  for (const l of list) {
    const k = l.brand + '|' + (l.unicode ?? l.host).replace(/^www\./, '');
    const prev = m.get(k);
    if (prev) prev.hosts.push(l.host);
    else m.set(k, { item: l, hosts: [l.host] });
  }
  return [...m.values()];
}

const HTTP_TEXT: Record<number, string> = { 400: msg('requête refusée'), 401: msg('accès protégé'), 403: msg('accès refusé'), 404: msg('page introuvable'), 410: msg('page supprimée'), 429: msg('trop de requêtes'), 451: msg('bloquée pour raison légale') };

/** The final request of the chain did not reach a page: HTTP 4xx / 5xx, or no answer at all. */
export function brokenDestination(hops: Hop[]): { code: string; text: string; url: string } | null {
  const last = hops[hops.length - 1];
  if (!last) return null;
  if (last.error) return { code: t('aucune réponse'), text: last.error, url: last.url };
  if (last.status !== undefined && last.status >= 400)
    return { code: `HTTP ${last.status}`, text: t(HTTP_TEXT[last.status] ?? (last.status >= 500 ? msg('erreur du serveur') : msg('requête refusée'))), url: last.url };
  return null;
}
