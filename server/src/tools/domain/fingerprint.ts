// "Fix loop" (2026-11-12): a light fingerprint of the records that decide a domain's email, read from
// the authoritative servers (iterative resolution from the root, no cache). The page polls it while
// someone applies a fix and runs the full scan again only when it changes, so that a 30-minute watch
// costs a few dozen DNS queries, not thirty blocklist rounds.
import { createHash } from 'node:crypto';
import type { RRType } from '../../dns/client.js';
import { toNodeShape, type ResolveSession } from '../../dns/iterative.js';

export interface WatchedRecord {
  name: string;
  type: RRType;
  rcode: string;
  values: string[];
  /** TTL announced by the authoritative server: how long a resolver may keep the previous value. */
  ttl: number | null;
}

export interface Fingerprint {
  domain: string;
  at: string;
  /** Changes when one of the watched records changes (the SOA serial is left out: Route 53 never bumps it). */
  hash: string;
  serial: number | null;
  /** false when a server did not answer: the hash is then not comparable and the page waits for the next poll */
  complete: boolean;
  records: WatchedRecord[];
}

export const MAX_SELECTORS = 10;
const SELECTOR = /^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?)*$/i;

/** The DKIM selectors to watch, from the query string: known names only, at most ten. */
export function parseSelectors(value: string | undefined): string[] {
  return [...new Set((value ?? '').split(',').map((s) => s.trim().toLowerCase()).filter((s) => s && SELECTOR.test(s)))].slice(0, MAX_SELECTORS);
}

function canonical(type: string, values: unknown[]): string[] {
  return values
    .map((v) => {
      if (type === 'TXT') return (v as string[]).join('');
      if (type === 'MX') return `${(v as { priority: number }).priority} ${(v as { exchange: string }).exchange}`;
      if (typeof v === 'string') return v;
      return JSON.stringify(v);
    })
    .sort();
}

export async function domainFingerprint(session: ResolveSession, domain: string, selectors: string[] = []): Promise<Fingerprint> {
  const asks: [string, RRType][] = [
    [domain, 'SOA'],
    [domain, 'MX'],
    [domain, 'TXT'],
    [`_dmarc.${domain}`, 'TXT'],
    [`_mta-sts.${domain}`, 'TXT'],
    [`_smtp._tls.${domain}`, 'TXT'],
    [`default._bimi.${domain}`, 'TXT'],
    [domain, 'CAA' as RRType],
    ...selectors.map((s): [string, RRType] => [`${s}._domainkey.${domain}`, 'TXT']),
  ];
  const records = await Promise.all(
    asks.map(async ([name, type]): Promise<WatchedRecord> => {
      try {
        const r = await session.resolve(name, type);
        const own = r.answers.filter((a) => a.type === type);
        // a DKIM key published through a CNAME: the chain is part of what can change
        const values = [...r.cnames.map((c) => `CNAME ${c}`), ...canonical(type, toNodeShape(type, own))];
        return { name, type, rcode: r.rcode, values, ttl: own.length ? Math.min(...own.map((a) => a.ttl)) : null };
      } catch (e) {
        return { name, type, rcode: (e as { code?: string }).code ?? 'ERROR', values: [], ttl: null };
      }
    }),
  );
  const soa = records[0].rcode === 'NOERROR' ? records[0].values[0] : undefined;
  let serial: number | null = null;
  try {
    serial = soa ? Number((JSON.parse(soa) as { serial?: number }).serial ?? NaN) : null;
    if (!Number.isFinite(serial)) serial = null;
  } catch {
    serial = null;
  }
  const answered = (r: WatchedRecord) => r.rcode === 'NOERROR' || r.rcode === 'NXDOMAIN';
  const stable = records.slice(1);
  const hash = createHash('sha256')
    .update(JSON.stringify(stable.map((r) => [r.name, r.type, r.rcode, r.values])))
    .digest('hex')
    .slice(0, 16);
  return { domain, at: new Date().toISOString(), hash, serial, complete: stable.every(answered), records };
}
