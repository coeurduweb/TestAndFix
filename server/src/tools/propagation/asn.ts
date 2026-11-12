// Origin ASN of an address, from Team Cymru's DNS service (origin.asn.cymru.com, no key).
// Queried through the action's ResolveSession (iterative, from the root): one query per /24
// (IPv4) or /48 (IPv6) and per verification, memoised only for that verification.
// Used to tell a regional answer of a CDN (same ASN as the authoritative answer, e.g. Cloudflare
// serving 8.47.69.0 to Russian resolvers for example.com) from an outdated one.
import ipaddr from 'ipaddr.js';
import type { ResolveSession } from '../../dns/iterative.js';

const txt = (data: unknown) => (Array.isArray(data) ? data.map((b) => (Buffer.isBuffer(b) ? b.toString('utf8') : String(b))).join('') : String(data));

/** Query name for the prefix holding `ip`: /24 for IPv4, /48 for IPv6. */
export function originQueryName(ip: string): string | null {
  try {
    const a = ipaddr.parse(ip);
    if (a.kind() === 'ipv4') return `${(a as ipaddr.IPv4).octets.slice(0, 3).reverse().join('.')}.origin.asn.cymru.com`;
    const hex = (a as ipaddr.IPv6).parts.map((p) => p.toString(16).padStart(4, '0')).join('').slice(0, 12);
    return `${hex.split('').reverse().join('.')}.origin6.asn.cymru.com`;
  } catch {
    return null;
  }
}

/** "13335 | 104.20.0.0/20 | US | arin | 2014-03-28" (several origins: "13335 4808 | …"). */
export function parseOrigin(line: string): number[] {
  const first = line.split('|')[0] ?? '';
  return first.trim().split(/\s+/).map(Number).filter((n) => Number.isInteger(n) && n > 0);
}

export class AsnLookup {
  private byPrefix = new Map<string, Promise<number[]>>();
  private names = new Map<number, Promise<string | null>>();
  public queries = 0;
  constructor(private session: ResolveSession) {}

  /** Origin ASNs of the prefix holding `ip` (empty when unknown). */
  asnsOf(ip: string): Promise<number[]> {
    const qn = originQueryName(ip);
    if (!qn) return Promise.resolve([]);
    let p = this.byPrefix.get(qn);
    if (!p) {
      this.queries++;
      p = this.session
        .resolve(qn, 'TXT')
        .then((r) => [...new Set(r.answers.filter((a) => a.type === 'TXT').flatMap((a) => parseOrigin(txt(a.data))))])
        .catch(() => []);
      this.byPrefix.set(qn, p);
    }
    return p;
  }

  /** Holder name, e.g. "CLOUDFLARENET - Cloudflare, Inc., US". */
  nameOf(asn: number): Promise<string | null> {
    let p = this.names.get(asn);
    if (!p) {
      this.queries++;
      p = this.session
        .resolve(`AS${asn}.asn.cymru.com`, 'TXT')
        .then((r) => {
          const a = r.answers.find((x) => x.type === 'TXT');
          return a ? (txt(a.data).split('|')[4]?.trim() ?? null) : null;
        })
        .catch(() => null);
      this.names.set(asn, p);
    }
    return p;
  }
}
