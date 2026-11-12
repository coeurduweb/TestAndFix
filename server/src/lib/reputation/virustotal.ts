// VirusTotal API v3 (free key: 4 requests per minute, 500 per day, no commercial use;
// everything sent joins VirusTotal's dataset). IP report and URL report by identifier; a URL
// is submitted for analysis only when the caller asks for it explicitly.
import { createHash } from 'node:crypto';
import { RateLimiter } from './limiter.js';
import { apiFetch, httpProblem, noKey, parseJson, SourceUnavailable, type ApiFetch } from './source.js';
import { t } from '../../i18n.js';

export const VT_BASE = 'https://www.virustotal.com';

/** One queue for the whole process: the quota belongs to the key, not to a request. */
export const vtLimiter = new RateLimiter(4, 500, 'VirusTotal');

export interface VtOptions {
  key: string;
  base?: string;
  fetch?: ApiFetch;
  limiter?: RateLimiter;
  /** Longest wait in the local queue before giving up with a "quota" reason. */
  maxWaitMs?: number;
}

export interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout?: number;
}

export interface VtEngineVerdict {
  engine: string;
  category: string;
  result?: string;
}

export interface VtIpData {
  ip: string;
  stats: VtStats;
  /** Community score (negative = reported as harmful). */
  reputation?: number;
  asOwner?: string;
  asn?: number;
  country?: string;
  lastAnalysisDate?: string;
  /** Engines that said malicious or suspicious. */
  flagged: VtEngineVerdict[];
  link: string;
}

export interface VtUrlData {
  url: string;
  found: boolean;
  stats?: VtStats;
  flagged: VtEngineVerdict[];
  lastAnalysisDate?: string;
  firstSubmissionDate?: string;
  finalUrl?: string;
  title?: string;
  categories?: string[];
  /** Set when the URL was unknown and submitted on request. */
  submitted?: boolean;
  analysisId?: string;
  link: string;
}

/** URL identifier of the v3 API: base64url of the URL, without padding. */
export function vtUrlId(url: string): string {
  return Buffer.from(url).toString('base64url');
}

function dateOf(epoch: unknown): string | undefined {
  return typeof epoch === 'number' && epoch > 0 ? new Date(epoch * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z') : undefined;
}

function flaggedOf(results: unknown): VtEngineVerdict[] {
  if (!results || typeof results !== 'object') return [];
  return Object.entries(results as Record<string, { category?: string; result?: string; engine_name?: string }>)
    .filter(([, r]) => r.category === 'malicious' || r.category === 'suspicious')
    .map(([name, r]) => ({ engine: r.engine_name ?? name, category: r.category!, result: r.result ?? undefined }))
    .sort((a, b) => a.engine.localeCompare(b.engine));
}

function statsOf(s: Partial<VtStats> | undefined): VtStats {
  return {
    malicious: Number(s?.malicious ?? 0),
    suspicious: Number(s?.suspicious ?? 0),
    harmless: Number(s?.harmless ?? 0),
    undetected: Number(s?.undetected ?? 0),
    timeout: s?.timeout === undefined ? undefined : Number(s.timeout),
  };
}

async function call(opts: VtOptions, path: string, init: { method?: 'GET' | 'POST'; body?: string } = {}) {
  if (!opts.key) throw noKey('VT_API_KEY', 'VirusTotal');
  const limiter = opts.limiter ?? vtLimiter;
  await limiter.acquire(opts.maxWaitMs ?? 15000);
  const res = await (opts.fetch ?? apiFetch)(`${opts.base ?? VT_BASE}${path}`, {
    method: init.method,
    body: init.body,
    headers: { 'x-apikey': opts.key, ...(init.body ? { 'content-type': 'application/x-www-form-urlencoded' } : {}) },
  });
  if (res.status === 429) {
    limiter.saturate();
    throw new SourceUnavailable('quota', t('quota de VirusTotal épuisé (HTTP 429) : 4 requêtes par minute et 500 par jour avec une clé gratuite'));
  }
  return res;
}

export async function vtIp(ip: string, opts: VtOptions): Promise<VtIpData> {
  const res = await call(opts, `/api/v3/ip_addresses/${encodeURIComponent(ip)}`);
  const link = `https://www.virustotal.com/gui/ip-address/${ip}`;
  if (res.status === 404) return { ip, stats: statsOf(undefined), flagged: [], link };
  const problem = httpProblem(res.status, 'VirusTotal', res.text);
  if (problem) throw problem;
  const a = parseJson<{ data?: { attributes?: Record<string, unknown> } }>(res.text, 'VirusTotal').data?.attributes ?? {};
  return {
    ip,
    stats: statsOf(a.last_analysis_stats as Partial<VtStats>),
    reputation: typeof a.reputation === 'number' ? a.reputation : undefined,
    asOwner: a.as_owner as string | undefined,
    asn: typeof a.asn === 'number' ? a.asn : undefined,
    country: a.country as string | undefined,
    lastAnalysisDate: dateOf(a.last_analysis_date),
    flagged: flaggedOf(a.last_analysis_results),
    link,
  };
}

export async function vtUrl(url: string, opts: VtOptions & { submit?: boolean }): Promise<VtUrlData> {
  const sha = createHash('sha256').update(url).digest('hex');
  const res = await call(opts, `/api/v3/urls/${vtUrlId(url)}`);
  if (res.status === 404) {
    const base: VtUrlData = { url, found: false, flagged: [], link: `https://www.virustotal.com/gui/url/${sha}` };
    if (!opts.submit) return base;
    const sub = await call(opts, '/api/v3/urls', { method: 'POST', body: new URLSearchParams({ url }).toString() });
    const problem = httpProblem(sub.status, 'VirusTotal', sub.text);
    if (problem) throw problem;
    const id = parseJson<{ data?: { id?: string } }>(sub.text, 'VirusTotal').data?.id;
    return { ...base, submitted: true, analysisId: id };
  }
  const problem = httpProblem(res.status, 'VirusTotal', res.text);
  if (problem) throw problem;
  const d = parseJson<{ data?: { id?: string; attributes?: Record<string, unknown> } }>(res.text, 'VirusTotal').data;
  const a = d?.attributes ?? {};
  const cats = a.categories && typeof a.categories === 'object' ? [...new Set(Object.values(a.categories as Record<string, string>))] : undefined;
  return {
    url,
    found: true,
    stats: statsOf(a.last_analysis_stats as Partial<VtStats>),
    flagged: flaggedOf(a.last_analysis_results),
    lastAnalysisDate: dateOf(a.last_analysis_date),
    firstSubmissionDate: dateOf(a.first_submission_date),
    finalUrl: a.last_final_url as string | undefined,
    title: a.title as string | undefined,
    categories: cats,
    link: `https://www.virustotal.com/gui/url/${d?.id ?? sha}`,
  };
}

export interface VtDomainData {
  domain: string;
  /** false when VirusTotal has no report for the domain (404). */
  found: boolean;
  stats: VtStats;
  flagged: VtEngineVerdict[];
  reputation?: number;
  categories?: string[];
  lastAnalysisDate?: string;
  link: string;
}

/** Domain report (GET /api/v3/domains/{domain}). */
export async function vtDomain(domain: string, opts: VtOptions): Promise<VtDomainData> {
  const res = await call(opts, `/api/v3/domains/${encodeURIComponent(domain)}`);
  const link = `https://www.virustotal.com/gui/domain/${domain}`;
  if (res.status === 404) return { domain, found: false, stats: statsOf(undefined), flagged: [], link };
  const problem = httpProblem(res.status, 'VirusTotal', res.text);
  if (problem) throw problem;
  const a = parseJson<{ data?: { attributes?: Record<string, unknown> } }>(res.text, 'VirusTotal').data?.attributes ?? {};
  const cats = a.categories && typeof a.categories === 'object' ? [...new Set(Object.values(a.categories as Record<string, string>))] : undefined;
  return {
    domain,
    found: true,
    stats: statsOf(a.last_analysis_stats as Partial<VtStats>),
    flagged: flaggedOf(a.last_analysis_results),
    reputation: typeof a.reputation === 'number' ? a.reputation : undefined,
    categories: cats,
    lastAnalysisDate: dateOf(a.last_analysis_date),
    link,
  };
}
