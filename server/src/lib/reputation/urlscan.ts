// urlscan.io search without a key (https://docs.urlscan.io/pages/api-intro: unauthenticated
// users have "minor quotas"). Search only: a scan would be public by default, so this tool
// never submits one. The search lists past scans of the host by other people; it gives no
// verdict on the free API, only what the pages looked like (title, certificate, domain age).
import { apiFetch, httpProblem, parseJson, type ApiFetch } from './source.js';

export const URLSCAN_BASE = 'https://urlscan.io';

export interface UrlscanScan {
  time: string;
  url: string;
  pageUrl?: string;
  title?: string;
  ip?: string;
  asn?: string;
  country?: string;
  status?: string;
  tlsIssuer?: string;
  tlsAgeDays?: number;
  domainAgeDays?: number;
  apexDomainAgeDays?: number;
  link: string;
}

export interface UrlscanData {
  host: string;
  total: number;
  scans: UrlscanScan[];
  searchLink: string;
}

export async function urlscanSearch(host: string, opts: { base?: string; fetch?: ApiFetch; size?: number } = {}): Promise<UrlscanData> {
  const q = `page.domain:${host}`;
  const res = await (opts.fetch ?? apiFetch)(`${opts.base ?? URLSCAN_BASE}/api/v1/search/?q=${encodeURIComponent(q)}&size=${opts.size ?? 5}`);
  const problem = httpProblem(res.status, 'urlscan.io', res.text);
  if (problem) throw problem;
  const j = parseJson<{ total?: number; results?: Record<string, Record<string, unknown>>[] }>(res.text, 'urlscan.io');
  const num = (v: unknown) => (typeof v === 'number' ? v : undefined);
  const scans = (j.results ?? []).map((r) => {
    const task = r.task ?? {};
    const page = r.page ?? {};
    const id = String((r as { _id?: string })._id ?? task.uuid ?? '');
    return {
      time: String(task.time ?? ''),
      url: String(task.url ?? ''),
      pageUrl: page.url as string | undefined,
      title: page.title as string | undefined,
      ip: page.ip as string | undefined,
      asn: page.asn as string | undefined,
      country: page.country as string | undefined,
      status: page.status as string | undefined,
      tlsIssuer: page.tlsIssuer as string | undefined,
      tlsAgeDays: num(page.tlsAgeDays),
      domainAgeDays: num(page.domainAgeDays),
      apexDomainAgeDays: num(page.apexDomainAgeDays),
      link: `https://urlscan.io/result/${id}/`,
    };
  });
  return { host, total: Number(j.total ?? scans.length), scans, searchLink: `https://urlscan.io/search/#${encodeURIComponent(q)}` };
}
