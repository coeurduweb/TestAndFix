// RIPEstat Data API without a key (https://stat.ripe.net/docs/02.data-api/): abuse contact,
// geolocation (MaxMind GeoLite), announced prefix and routing visibility. Four calls in
// parallel; the source is unavailable only when all of them fail.
import { apiFetch, httpProblem, parseJson, SourceUnavailable, type ApiFetch } from './source.js';

export const RIPESTAT_BASE = 'https://stat.ripe.net';

export interface RipestatData {
  ip: string;
  abuseContacts: string[];
  authoritativeRir?: string;
  country?: string;
  city?: string;
  prefix?: string;
  announced?: boolean;
  holders: { asn: number; holder: string }[];
  block?: string;
  visibility?: { v4?: { seeing: number; total: number }; v6?: { seeing: number; total: number } };
  firstSeen?: string;
  /** Calls that failed (partial answer). */
  missing: string[];
  link: string;
}

type Call = 'abuse-contact-finder' | 'maxmind-geo-lite' | 'prefix-overview' | 'routing-status';

export async function ripestat(ip: string, opts: { base?: string; fetch?: ApiFetch } = {}): Promise<RipestatData> {
  const get = async (call: Call) => {
    const res = await (opts.fetch ?? apiFetch)(`${opts.base ?? RIPESTAT_BASE}/data/${call}/data.json?resource=${encodeURIComponent(ip)}&sourceapp=check-reputation`);
    const problem = httpProblem(res.status, 'RIPEstat', res.text);
    if (problem) throw problem;
    return parseJson<{ data?: Record<string, unknown> }>(res.text, 'RIPEstat').data ?? {};
  };
  const calls: Call[] = ['abuse-contact-finder', 'maxmind-geo-lite', 'prefix-overview', 'routing-status'];
  const settled = await Promise.allSettled(calls.map(get));
  const ok = (i: number) => (settled[i].status === 'fulfilled' ? (settled[i] as PromiseFulfilledResult<Record<string, unknown>>).value : undefined);
  const missing = calls.filter((_, i) => settled[i].status === 'rejected');
  if (missing.length === calls.length) {
    const first = (settled[0] as PromiseRejectedResult).reason as Error;
    throw first instanceof SourceUnavailable ? first : new SourceUnavailable('error', `RIPEstat injoignable (${first.message})`);
  }
  const abuse = ok(0);
  const geo = ok(1);
  const prefix = ok(2);
  const routing = ok(3);
  const loc = (geo?.located_resources as { locations?: { country?: string; city?: string }[] }[] | undefined)?.[0]?.locations?.[0];
  const vis = routing?.visibility as Record<string, { ris_peers_seeing?: number; total_ris_peers?: number }> | undefined;
  const v = (k: 'v4' | 'v6') => (vis?.[k] && vis[k].total_ris_peers ? { seeing: Number(vis[k].ris_peers_seeing ?? 0), total: Number(vis[k].total_ris_peers) } : undefined);
  return {
    ip,
    abuseContacts: Array.isArray(abuse?.abuse_contacts) ? (abuse!.abuse_contacts as string[]) : [],
    authoritativeRir: abuse?.authoritative_rir as string | undefined,
    country: loc?.country || undefined,
    city: loc?.city || undefined,
    prefix: prefix?.resource as string | undefined,
    announced: typeof prefix?.announced === 'boolean' ? (prefix.announced as boolean) : undefined,
    holders: ((prefix?.asns as { asn?: number; holder?: string }[] | undefined) ?? []).map((a) => ({ asn: Number(a.asn), holder: String(a.holder ?? '') })),
    block: (prefix?.block as { desc?: string } | undefined)?.desc,
    visibility: routing ? { v4: v('v4'), v6: v('v6') } : undefined,
    firstSeen: (routing?.first_seen as { time?: string } | undefined)?.time,
    missing,
    link: `https://stat.ripe.net/app/${ip}`,
  };
}
