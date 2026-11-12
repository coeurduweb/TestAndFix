// DNS lookup page: shapes returned by GET /api/dns/:name (mirror of server/src/tools/dns/lookup.ts)
// and the pure helpers of the page. Unit tested in lookup.test.ts.
import { isIp } from '../../lib/detect';
import { t } from '../../lib/i18n';
import { DNS_TYPES, cleanName, pickType } from './rrtypes';

export interface RecordOut {
  name: string;
  ttl: number;
  type: string;
  value: string;
}

export interface TraceStep {
  zone: string;
  server: string;
  serverName?: string;
  rtt: number;
  outcome: 'referral' | 'answer' | 'nxdomain' | 'nodata' | 'cname' | 'error';
  detail?: string;
}

export interface AuthServerAnswer {
  ns: string;
  ip: string;
  rcode: string;
  aa: boolean;
  rtt?: number;
  answers: RecordOut[];
  serial?: number;
  error?: string;
}

export interface AllAuthoritative {
  zone: string;
  servers: AuthServerAnswer[];
  consistent: boolean;
  serials: number[];
  serialsConsistent: boolean;
  lame: string[];
  variants: { answers: string[]; servers: string[] }[];
}

export interface DnsLookupData {
  name: string;
  type: string;
  mode: 'authoritative' | 'resolver' | 'all';
  rcode: string;
  answers: RecordOut[];
  signatures: RecordOut[];
  cnames: string[];
  zone?: string;
  answeredBy?: string;
  trace: TraceStep[];
  flags?: { aa: boolean; ra: boolean; ad: boolean; tc: boolean };
  server?: string;
  rtt?: number;
  authoritative?: AllAuthoritative;
  ptr?: { ip: string; names: string[]; fcrdns: { name: string; ips: string[]; matches: boolean }[] };
  dig: string;
  ms: number;
}

export type Mode = 'authoritative' | 'all' | 'resolver';

/** Public resolvers suggested in "resolver" mode, in the order asked for. */
export const SUGGESTED_RESOLVERS = [
  { ip: '8.8.8.8', label: 'Google' },
  { ip: '1.1.1.1', label: 'Cloudflare' },
  { ip: '9.9.9.9', label: 'Quad9' },
] as const;

export interface LookupQuery {
  name: string;
  type: string;
  mode: Mode;
  server?: string;
  dnssec: boolean;
}

/** Read the page state from the route: /dns/:name?type=MX&mode=tous | ?serveur=1.1.1.1 | &dnssec=1 */
export function readQuery(nameParam: string | undefined, params: URLSearchParams): LookupQuery | null {
  const name = cleanName(nameParam);
  if (!name) return null;
  const server = params.get('serveur')?.trim() || undefined;
  const m = params.get('mode');
  const mode: Mode = server || m === 'resolveur' ? 'resolver' : m === 'tous' ? 'all' : 'authoritative';
  return {
    name,
    type: pickType(params.get('type'), name, DNS_TYPES),
    mode,
    server: mode === 'resolver' ? server ?? SUGGESTED_RESOLVERS[0].ip : undefined,
    dnssec: params.get('dnssec') === '1',
  };
}

/** Page URL of a query (what the address bar and the share link carry). */
export function pagePath(q: LookupQuery): string {
  const p = new URLSearchParams();
  p.set('type', q.type);
  if (q.mode === 'all') p.set('mode', 'tous');
  if (q.mode === 'resolver') p.set('serveur', q.server ?? SUGGESTED_RESOLVERS[0].ip);
  if (q.dnssec) p.set('dnssec', '1');
  return `/dns/${encodeURIComponent(q.name)}?${p.toString()}`;
}

/** API URL of a query. */
export function apiUrl(q: LookupQuery): string {
  const p = new URLSearchParams();
  p.set('type', q.type);
  if (q.mode === 'all') p.set('all', '1');
  if (q.mode === 'resolver' && q.server) p.set('server', q.server);
  if (q.dnssec) p.set('dnssec', '1');
  return `/api/dns/${encodeURIComponent(q.name)}?${p.toString()}`;
}

/** "Racine", "TLD .com", "Zone gmail.com". */
export function zoneLabel(zone: string): string {
  if (zone === '.' || zone === '') return t('Racine');
  if (!zone.includes('.')) return t('TLD .{zone}', { zone });
  return t('Zone {zone}', { zone });
}

/** What a step of the resolution trace did, in one short phrase. */
export function outcomeLabel(s: TraceStep): string {
  switch (s.outcome) {
    case 'referral':
      return s.detail ? t('délègue {detail}', { detail: s.detail }) : t('délègue la zone');
    case 'answer':
      return t('répond avec autorité');
    case 'nxdomain':
      return t('NXDOMAIN : le nom n’existe pas');
    case 'nodata':
      return t('aucun enregistrement de ce type');
    case 'cname':
      return s.detail ? t('alias vers {detail}', { detail: s.detail }) : t('alias (CNAME)');
    case 'error':
      return s.detail ? t('erreur : {detail}', { detail: s.detail }) : t('erreur');
  }
}

const sigOf = (rs: RecordOut[]) => rs.map((r) => `${r.type} ${r.value}`).sort();

export type ServerVerdict =
  | { kind: 'ok' }
  | { kind: 'out'; text: string }
  | { kind: 'warn'; text: string };

/**
 * Verdict of one authoritative server against the others: no answer, not authoritative,
 * an answer that differs from the majority, or an older serial.
 */
export function serverVerdict(s: AuthServerAnswer, all: AllAuthoritative): ServerVerdict {
  if (s.error || s.rcode === 'TIMEOUT') return { kind: 'out', text: t('sans réponse') };
  if (!s.aa) return { kind: 'out', text: t('non autoritaire') };
  if (s.rcode !== 'NOERROR' && s.rcode !== 'NXDOMAIN') return { kind: 'out', text: s.rcode };
  const majority = [...all.variants].sort((a, b) => b.servers.length - a.servers.length)[0];
  const mine = s.rcode === 'NXDOMAIN' ? ['NXDOMAIN'] : sigOf(s.answers);
  if (majority && all.variants.length > 1 && JSON.stringify(majority.answers) !== JSON.stringify(mine)) return { kind: 'out', text: t('diverge') };
  const top = all.serials.length ? Math.max(...all.serials) : undefined;
  if (top !== undefined && s.serial !== undefined && s.serial < top) return { kind: 'warn', text: t('serial ancien') };
  return { kind: 'ok' };
}

/** Is this input an IP address (reverse lookup)? */
export const isAddress = (name: string) => isIp(name);

/** Headline of the answer: count of records of the asked type, and what the rcode means. */
export function answerHeadline(d: Pick<DnsLookupData, 'rcode' | 'answers' | 'type' | 'cnames'>): { count: number; text: string; tone: 'ok' | 'out' | 'warn' } {
  const own = d.answers.filter((a) => a.type === d.type).length;
  if (d.rcode === 'NXDOMAIN') return { count: 0, text: t('NXDOMAIN : ce nom n’existe pas'), tone: 'out' };
  if (d.rcode === 'NOERROR' && own === 0)
    return { count: 0, text: d.cnames.length ? t('alias sans enregistrement {type} au bout', { type: d.type }) : t('aucun enregistrement {type}', { type: d.type }), tone: 'warn' };
  if (d.rcode !== 'NOERROR') return { count: own, text: t('{rcode} : pas de réponse exploitable', { rcode: d.rcode }), tone: 'out' };
  return { count: own, text: own > 1 ? t('enregistrements {type}', { type: d.type }) : t('enregistrement {type}', { type: d.type }), tone: 'ok' };
}

/** MX by preference, SRV by priority then weight; other types keep the server's order. */
export function sortRecords(rows: RecordOut[]): RecordOut[] {
  const key = (r: RecordOut): number[] | null => {
    const n = r.value.split(/\s+/).map(Number);
    if (r.type === 'MX') return [n[0]];
    if (r.type === 'SRV') return [n[0], -n[1]];
    return null;
  };
  return rows
    .map((r, i) => ({ r, i, k: key(r) }))
    .sort((a, b) => {
      if (a.r.type !== b.r.type) return a.r.type === 'RRSIG' ? 1 : b.r.type === 'RRSIG' ? -1 : 0;
      if (a.k && b.k) for (let j = 0; j < a.k.length; j++) if (a.k[j] !== b.k[j]) return a.k[j] - b.k[j];
      return a.i - b.i;
    })
    .map((x) => x.r);
}

/** The answer most servers give (signature form "MX 10 mx.example.com."). */
export function majorityAnswer(all: AllAuthoritative): string[] | null {
  const m = [...all.variants].sort((a, b) => b.servers.length - a.servers.length)[0];
  return m ? m.answers : null;
}

export const answerSig = (s: AuthServerAnswer) => (s.rcode === 'NXDOMAIN' ? ['NXDOMAIN'] : s.answers.map((r) => `${r.type} ${r.value}`).sort());
