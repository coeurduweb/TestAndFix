// Status of one resolver answer against the reference, and the summary of a run.
import type { DnsResponse } from '../../dns/client.js';
import { hasNonPublic } from './addresses.js';
import { extract, sameValues, type PropType } from './normalize.js';

/**
 * rewritten: the resolver answered a non-public address (127.0.0.1, 0.0.0.0, RFC 1918…) where the
 * zone publishes public ones. Not a propagation state: never fresh, no refresh time.
 */
/**
 * regional: different from the reference, but every address is in the ASN of the authoritative
 * answer (a CDN answering by region) with a TTL within the zone's: up to date, no refresh time.
 */
export type Status = 'fresh' | 'stale' | 'missing' | 'regional' | 'rewritten' | 'error' | 'timeout';

export interface Reference {
  source: 'authority' | 'expected';
  /** false when the name or the type does not exist at the authoritative servers. */
  exists: boolean;
  /**
   * 'cname': the name is an alias (and the type asked is not CNAME). Resolvers are compared on
   * the alias target only, because the records at the end of a cross-zone chain (CDN) may
   * legitimately differ by location. 'records': compared on the records of the type asked.
   */
  kind: 'records' | 'cname';
  values: string[];
  cname: string | null;
  /** 'subset' when the zone answers dynamically: any non-empty subset of `values` is up to date. */
  match?: 'exact' | 'subset';
}

export interface Observation {
  status: Status;
  rcode: string | null;
  cname: string | null;
  values: string[];
  /** Remaining TTL at this resolver for what decides the status (seconds). */
  ttl: number | null;
  /** For stale and missing: when this resolver should ask again (ISO), now + remaining TTL. */
  refreshAt: string | null;
  error?: string;
  /** For status 'rewritten': a non-public address, or NXDOMAIN while the zone has data. */
  reason?: 'non_public' | 'nxdomain_lie';
}

const ERROR_RCODES = new Set(['SERVFAIL', 'REFUSED', 'FORMERR', 'NOTIMP', 'NOTAUTH', 'NOTZONE', 'YXDOMAIN', 'YXRRSET', 'NXRRSET']);

export function observe(
  t: PropType,
  name: string,
  ref: Reference,
  res: DnsResponse | null,
  err?: unknown,
  at = Date.now(),
): Observation {
  if (!res) {
    const timeout = (err as { code?: string } | undefined)?.code === 'ETIMEOUT';
    return {
      status: timeout ? 'timeout' : 'error',
      rcode: null,
      cname: null,
      values: [],
      ttl: null,
      refreshAt: null,
      error: timeout ? 'timeout' : String((err as Error | undefined)?.message ?? err ?? 'error'),
    };
  }
  if (ERROR_RCODES.has(res.rcode)) {
    return { status: 'error', rcode: res.rcode, cname: null, values: [], ttl: null, refreshAt: null, error: res.rcode };
  }
  const x = extract(t, name, res.answers, res.authorities);
  const empty = res.rcode === 'NXDOMAIN' || (x.cname === null && x.values.length === 0);
  let status: Status;
  let ttl: number | null;
  if ((t === 'A' || t === 'AAAA') && !empty && ref.exists && hasNonPublic(x.values) && !hasNonPublic(ref.values)) {
    return { status: 'rewritten', rcode: res.rcode, cname: x.cname, values: x.values, ttl: x.cname !== null ? x.valuesTtl : x.ttl, refreshAt: null, reason: 'non_public' };
  }
  if (empty) {
    status = ref.exists ? 'missing' : 'fresh';
    ttl = x.negativeTtl;
  } else if (!ref.exists) {
    status = 'stale';
    ttl = x.ttl;
  } else if (ref.kind === 'cname') {
    status = x.cname === ref.cname ? 'fresh' : 'stale';
    ttl = x.ttl;
  } else {
    // records: an alias where the reference has records is stale, unless the user's expected
    // value is checked against the end of the chain (source 'expected').
    const same =
      ref.match === 'subset' ? x.values.length > 0 && x.values.every((v) => ref.values.includes(v)) : sameValues(t, x.values, ref.values);
    const ok = same && (x.cname === null || ref.source === 'expected' || t === 'CNAME');
    status = ok ? 'fresh' : 'stale';
    ttl = x.cname !== null && ref.source === 'expected' ? x.valuesTtl : x.ttl;
  }
  const refreshAt = (status === 'stale' || status === 'missing') && ttl != null ? new Date(at + ttl * 1000).toISOString() : null;
  return { status, rcode: res.rcode, cname: x.cname, values: x.values, ttl, refreshAt };
}

export interface Counts {
  total: number;
  answered: number;
  fresh: number;
  stale: number;
  missing: number;
  /** Counted in answered and as up to date for percentFresh. */
  regional: number;
  rewritten: number;
  error: number;
  timeout: number;
  /** (fresh + regional) / answered (fresh + regional + stale + missing; rewritten excluded), in %, one decimal. */
  percentFresh: number | null;
}

export const emptyCounts = (): Counts => ({ total: 0, answered: 0, fresh: 0, stale: 0, missing: 0, regional: 0, rewritten: 0, error: 0, timeout: 0, percentFresh: null });

export function addTo(c: Counts, s: Status) {
  c.total++;
  c[s]++;
  if (s === 'fresh' || s === 'regional' || s === 'stale' || s === 'missing') c.answered++;
  c.percentFresh = c.answered ? Math.round(((c.fresh + c.regional) / c.answered) * 1000) / 10 : null;
}
