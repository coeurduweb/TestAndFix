// AbuseIPDB v2 check endpoint (https://docs.abuseipdb.com/#check-endpoint). Free plan: 1 000
// checks per day (https://www.abuseipdb.com/pricing); the API answers 429 past the quota.
import { apiFetch, httpProblem, noKey, parseJson, type ApiFetch } from './source.js';

export const ABUSEIPDB_BASE = 'https://api.abuseipdb.com';

export interface AbuseIpdbData {
  ip: string;
  /** 0 to 100: AbuseIPDB's confidence that the address is abusive. */
  score: number;
  totalReports: number;
  distinctUsers: number;
  lastReportedAt?: string;
  isWhitelisted?: boolean;
  isTor?: boolean;
  usageType?: string;
  isp?: string;
  domain?: string;
  countryCode?: string;
  hostnames: string[];
  maxAgeDays: number;
  /** Requests left today, from the X-RateLimit-Remaining header. */
  remaining?: number;
  link: string;
}

export async function abuseIpdbCheck(ip: string, opts: { key: string; base?: string; fetch?: ApiFetch; maxAgeDays?: number }): Promise<AbuseIpdbData> {
  if (!opts.key) throw noKey('ABUSEIPDB_API_KEY', 'AbuseIPDB');
  const maxAgeDays = opts.maxAgeDays ?? 90;
  const q = new URLSearchParams({ ipAddress: ip, maxAgeInDays: String(maxAgeDays) });
  const res = await (opts.fetch ?? apiFetch)(`${opts.base ?? ABUSEIPDB_BASE}/api/v2/check?${q}`, { headers: { Key: opts.key, accept: 'application/json' } });
  const problem = httpProblem(res.status, 'AbuseIPDB', res.text);
  if (problem) throw problem;
  const d = parseJson<{ data?: Record<string, unknown> }>(res.text, 'AbuseIPDB').data ?? {};
  const remaining = res.headers['x-ratelimit-remaining'];
  return {
    ip,
    score: Number(d.abuseConfidenceScore ?? 0),
    totalReports: Number(d.totalReports ?? 0),
    distinctUsers: Number(d.numDistinctUsers ?? 0),
    lastReportedAt: (d.lastReportedAt as string | null) ?? undefined,
    isWhitelisted: (d.isWhitelisted as boolean | null) ?? undefined,
    isTor: (d.isTor as boolean | undefined) ?? undefined,
    usageType: (d.usageType as string | null) ?? undefined,
    isp: (d.isp as string | null) ?? undefined,
    domain: (d.domain as string | null) ?? undefined,
    countryCode: (d.countryCode as string | null) ?? undefined,
    hostnames: Array.isArray(d.hostnames) ? (d.hostnames as string[]) : [],
    maxAgeDays,
    remaining: remaining !== undefined && /^\d+$/.test(remaining) ? Number(remaining) : undefined,
    link: `https://www.abuseipdb.com/check/${ip}`,
  };
}
