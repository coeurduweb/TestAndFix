// URLhaus (abuse.ch) lookups. An Auth-Key is mandatory since abuse.ch closed anonymous access
// (tested 2026-11-10: 401 without it); it is free from https://auth.abuse.ch/.
import { apiFetch, httpProblem, noKey, parseJson, type ApiFetch } from './source.js';

export const URLHAUS_BASE = 'https://urlhaus-api.abuse.ch';

export interface UrlhausUrlData {
  url: string;
  listed: boolean;
  status?: 'online' | 'offline' | 'unknown' | string;
  threat?: string;
  tags: string[];
  dateAdded?: string;
  reference?: string;
}

export interface UrlhausHostData {
  host: string;
  listed: boolean;
  urlCount: number;
  onlineCount: number;
  firstSeen?: string;
  reference?: string;
  /** Up to five URLs of the host known to URLhaus, the online ones first. */
  urls: { url: string; status: string; threat?: string; dateAdded?: string }[];
}

interface UrlhausOptions {
  key: string;
  base?: string;
  fetch?: ApiFetch;
}

async function post(path: string, form: Record<string, string>, opts: UrlhausOptions) {
  if (!opts.key) throw noKey('URLHAUS_AUTH_KEY', 'URLhaus');
  const res = await (opts.fetch ?? apiFetch)(`${opts.base ?? URLHAUS_BASE}${path}`, {
    method: 'POST',
    headers: { 'Auth-Key': opts.key, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
  });
  const problem = httpProblem(res.status, 'URLhaus', res.text);
  if (problem) throw problem;
  return parseJson<Record<string, unknown>>(res.text, 'URLhaus');
}

export async function urlhausUrl(url: string, opts: UrlhausOptions): Promise<UrlhausUrlData> {
  const j = await post('/v1/url/', { url }, opts);
  if (j.query_status !== 'ok') return { url, listed: false, tags: [] };
  return {
    url,
    listed: true,
    status: j.url_status as string | undefined,
    threat: j.threat as string | undefined,
    tags: Array.isArray(j.tags) ? (j.tags as string[]) : [],
    dateAdded: j.date_added as string | undefined,
    reference: j.urlhaus_reference as string | undefined,
  };
}

export async function urlhausHost(host: string, opts: UrlhausOptions): Promise<UrlhausHostData> {
  const j = await post('/v1/host/', { host }, opts);
  if (j.query_status !== 'ok') return { host, listed: false, urlCount: 0, onlineCount: 0, urls: [] };
  const urls = (Array.isArray(j.urls) ? (j.urls as Record<string, unknown>[]) : []).map((u) => ({
    url: String(u.url ?? ''),
    status: String(u.url_status ?? 'unknown'),
    threat: u.threat as string | undefined,
    dateAdded: u.date_added as string | undefined,
  }));
  return {
    host,
    listed: true,
    urlCount: Number(j.url_count ?? urls.length),
    onlineCount: urls.filter((u) => u.status === 'online').length,
    firstSeen: j.firstseen as string | undefined,
    reference: j.urlhaus_reference as string | undefined,
    urls: urls.sort((a, b) => Number(b.status === 'online') - Number(a.status === 'online')).slice(0, 5),
  };
}
