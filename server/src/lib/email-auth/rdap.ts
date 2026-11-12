// RDAP (RFC 9082/9083) through the IANA bootstrap registry (RFC 9224): registrar, dates, statuses.
import type { PassedCheck } from '../../tools/types.js';
import type { SafeFetchResult } from '../net.js';
import { httpGet } from './http.js';
import { daysBetween, issue, orgDomain, pass, type Analysis, type Issue , type Resolver } from './common.js';
import { t } from '../../i18n.js';

export const IANA_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json';

export interface RdapData {
  domain: string;
  /** Registered domain actually queried (RDAP knows registrable names only). */
  queried: string;
  tld: string;
  server?: string;
  url?: string;
  ldhName?: string;
  handle?: string;
  registrar?: { name?: string; ianaId?: string; url?: string; abuseEmail?: string };
  status: string[];
  events: { action: string; date: string }[];
  created?: string;
  updated?: string;
  expires?: string;
  ageDays?: number;
  expiresInDays?: number;
  nameservers: string[];
  dnssecDelegated?: boolean;
}

export interface RdapAnalysis extends Analysis {
  data: RdapData;
}

export type Fetcher = (url: string, headers?: Record<string, string>) => Promise<SafeFetchResult>;

async function getJson(fetcher: Fetcher, url: string, accept: string): Promise<{ json: unknown; url: string; status: number }> {
  let current = url;
  for (let hop = 0; hop < 5; hop++) {
    const r = await fetcher(current, { accept });
    if (r.status >= 300 && r.status < 400 && r.headers.location) {
      current = new URL(r.headers.location, current).toString();
      continue;
    }
    if (r.status === 404) return { json: undefined, url: current, status: 404 };
    if (r.status !== 200) throw new Error(t('HTTP {status} sur {url}', { status: r.status, url: current }));
    return { json: JSON.parse(r.body.toString('utf8')), url: current, status: 200 };
  }
  throw new Error(t('trop de redirections depuis {url}', { url }));
}

interface VcardEntity {
  roles?: string[];
  vcardArray?: [string, [string, Record<string, unknown>, string, unknown][]];
  publicIds?: { type: string; identifier: string }[];
  links?: { rel?: string; href?: string }[];
  entities?: VcardEntity[];
}

function vcard(e: VcardEntity, field: string): string | undefined {
  const item = e.vcardArray?.[1]?.find((x) => x[0] === field);
  return item ? String(item[3]) : undefined;
}

export function parseRdapDomain(domain: string, json: Record<string, unknown>, now = Date.now()): Omit<RdapData, 'domain' | 'queried' | 'tld'> {
  const events = ((json.events as { eventAction: string; eventDate: string }[]) ?? []).map((e) => ({ action: e.eventAction, date: e.eventDate }));
  const ev = (a: string) => events.find((e) => e.action === a)?.date;
  const entities = (json.entities as VcardEntity[]) ?? [];
  const reg = entities.find((e) => e.roles?.includes('registrar'));
  const abuse = reg?.entities?.find((e) => e.roles?.includes('abuse'));
  const created = ev('registration');
  const expires = ev('expiration');
  return {
    ldhName: (json.ldhName as string | undefined)?.toLowerCase(),
    handle: json.handle as string | undefined,
    registrar: reg
      ? {
          name: vcard(reg, 'fn'),
          ianaId: reg.publicIds?.find((p) => /iana/i.test(p.type))?.identifier,
          url: reg.links?.find((l) => l.href && !/rdap/i.test(l.href))?.href,
          abuseEmail: abuse ? vcard(abuse, 'email') : undefined,
        }
      : undefined,
    status: ((json.status as string[]) ?? []).map((s) => s.toLowerCase()),
    events,
    created,
    updated: ev('last changed'),
    expires,
    ageDays: created ? daysBetween(now, Date.parse(created)) : undefined,
    expiresInDays: expires ? daysBetween(Date.parse(expires), now) : undefined,
    nameservers: ((json.nameservers as { ldhName?: string }[]) ?? []).map((n) => (n.ldhName ?? '').toLowerCase().replace(/\.$/, '')).filter(Boolean),
    dnssecDelegated: (json.secureDNS as { delegationSigned?: boolean } | undefined)?.delegationSigned,
  };
}

export interface RdapOptions {
  fetcher?: Fetcher;
  session?: Resolver;
  now?: number;
}

const HOLD = ['client hold', 'server hold'];
const DELETING = ['pending delete', 'redemption period'];

export async function analyzeRdap(domain: string, opts: RdapOptions = {}): Promise<RdapAnalysis> {
  const fetcher: Fetcher = opts.fetcher ?? ((url, headers) => httpGet(url, { session: opts.session, headers, maxBytes: 1024 * 1024 }));
  const queried = orgDomain(domain);
  const tld = queried.split('.').pop()!;
  const data: RdapData = { domain, queried, tld, status: [], events: [], nameservers: [] };
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  let boot: { services: [string[], string[]][] };
  try {
    boot = (await getJson(fetcher, IANA_BOOTSTRAP, 'application/json')).json as typeof boot;
  } catch (e) {
    return { issues, passed, unavailable: [{ source: 'rdap', reason: t('registre IANA injoignable : {error}', { error: (e as Error).message }) }], data };
  }
  // longest matching suffix (multi-label entries exist)
  const labels = queried.split('.');
  let base: string | undefined;
  for (let i = 0; i < labels.length && !base; i++) {
    const suffix = labels.slice(i).join('.');
    const svc = boot.services.find(([tlds]) => tlds.includes(suffix));
    if (svc) base = svc[1].find((u) => u.startsWith('https://')) ?? svc[1][0];
  }
  if (!base) return { issues, passed, unavailable: [{ source: 'rdap', reason: t('le registre de .{tld} ne propose pas de service RDAP inscrit à l’IANA', { tld }) }], data };
  data.server = base;
  try {
    const r = await getJson(fetcher, new URL(`domain/${queried}`, base.endsWith('/') ? base : base + '/').toString(), 'application/rdap+json');
    data.url = r.url;
    if (r.status === 404) {
      issues.push(issue('infrastructure.domain_not_registered', { domain: queried }));
      return { issues, passed, data };
    }
    Object.assign(data, parseRdapDomain(queried, r.json as Record<string, unknown>, opts.now));
  } catch (e) {
    return { issues, passed, unavailable: [{ source: 'rdap', reason: t('{name} : {error}', { name: base, error: (e as Error).message }) }], data };
  }
  const v = { domain: queried };
  if (data.status.some((s) => HOLD.includes(s))) issues.push(issue('infrastructure.domain_hold', { ...v, value: data.status.join(', ') }, { evidence: data.status.join(', ') }));
  if (data.status.some((s) => DELETING.includes(s))) issues.push(issue('infrastructure.domain_pending_delete', { ...v, value: data.status.join(', ') }, { evidence: data.status.join(', ') }));
  if (data.expiresInDays !== undefined) {
    if (data.expiresInDays < 0) issues.push(issue('infrastructure.domain_expired', { ...v, value: data.expires }, { evidence: t('expiration : {date}', { date: data.expires }) }));
    else if (data.expiresInDays < 30) issues.push(issue('infrastructure.domain_expiring', { ...v, value: data.expiresInDays }, { evidence: t('expiration : {date}', { date: data.expires }) }));
    else passed.push(pass('rdap.expiration', 'infrastructure', t('Domaine payé jusqu’au {date}', { date: data.expires!.slice(0, 10) })));
  }
  if (data.ageDays !== undefined && data.ageDays < 30) issues.push(issue('reputation.domain_very_new', { ...v, value: data.ageDays }, { evidence: t('création : {date}', { date: data.created }) }));
  if (data.status.includes('client transfer prohibited') || data.status.includes('server transfer prohibited'))
    passed.push(pass('rdap.transfer_lock', 'infrastructure', t('Domaine verrouillé contre les transferts')));
  return { issues, passed, data };
}
