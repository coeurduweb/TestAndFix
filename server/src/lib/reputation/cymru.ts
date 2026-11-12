// Team Cymru IP to ASN mapping over DNS (https://www.team-cymru.com/ip-asn-mapping), queried
// through our iterative resolver: origin ASN, announced prefix, country, registry, allocation
// date, upstream peers (IPv4 only) and the AS name. Team Cymru asks not to use it for geolocation.
import { lookupTxt, type Resolver } from '../email-auth/common.js';
import { dnsblName } from '../net.js';
import { SourceUnavailable } from './source.js';
import { t } from '../../i18n.js';

export interface CymruOrigin {
  asn: number;
  prefix: string;
  country?: string;
  registry?: string;
  allocated?: string;
}

export interface CymruAs {
  asn: number;
  name?: string;
  country?: string;
  registry?: string;
  allocated?: string;
}

export interface CymruData {
  ip: string;
  origins: CymruOrigin[];
  peers: number[];
  as: CymruAs[];
}

const fields = (s: string) => s.split('|').map((x) => x.trim());

/** "15169 | 8.8.8.0/24 | US | arin | 2023-12-28" (origin field may hold several ASNs). */
export function parseOrigin(txt: string): CymruOrigin[] {
  const [asns, prefix, country, registry, allocated] = fields(txt);
  return (asns ?? '')
    .split(/\s+/)
    .filter((a) => /^\d+$/.test(a))
    .map((a) => ({ asn: Number(a), prefix: prefix ?? '', country: country || undefined, registry: registry || undefined, allocated: allocated || undefined }));
}

/** "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US" */
export function parseAs(txt: string): CymruAs | undefined {
  const [asn, country, registry, allocated, ...name] = fields(txt);
  if (!/^\d+$/.test(asn ?? '')) return undefined;
  return { asn: Number(asn), country: country || undefined, registry: registry || undefined, allocated: allocated || undefined, name: name.join(' | ') || undefined };
}

export async function cymruOrigin(dns: Resolver, ip: string): Promise<CymruOrigin[]> {
  const zone = ip.includes(':') ? 'origin6.asn.cymru.com' : 'origin.asn.cymru.com';
  const r = await lookupTxt(dns, dnsblName(ip, zone));
  if (r.error) throw new SourceUnavailable('error', t('Team Cymru sans réponse ({error})', { error: r.error }));
  const out = r.records.flatMap(parseOrigin);
  // most specific prefix first
  return out.sort((a, b) => Number(b.prefix.split('/')[1] ?? 0) - Number(a.prefix.split('/')[1] ?? 0) || a.asn - b.asn);
}

export async function cymruAsInfo(dns: Resolver, asn: number): Promise<CymruAs | undefined> {
  const r = await lookupTxt(dns, `AS${asn}.asn.cymru.com`);
  return r.records.map(parseAs).find((x) => x?.asn === asn);
}

export async function cymru(dns: Resolver, ip: string): Promise<CymruData> {
  const origins = await cymruOrigin(dns, ip);
  const peersP = ip.includes(':')
    ? Promise.resolve([] as number[])
    : lookupTxt(dns, dnsblName(ip, 'peer.asn.cymru.com')).then((r) => [...new Set(r.records.flatMap((t) => (fields(t)[0] ?? '').split(/\s+/)).filter((a) => /^\d+$/.test(a)).map(Number))]);
  const asns = [...new Set(origins.map((o) => o.asn))];
  const [peers, as] = await Promise.all([peersP.catch(() => [] as number[]), Promise.all(asns.map((a) => cymruAsInfo(dns, a).catch(() => undefined)))]);
  return { ip, origins, peers, as: as.filter((x): x is CymruAs => !!x) };
}
