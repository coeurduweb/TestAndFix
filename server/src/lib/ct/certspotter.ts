// Cert Spotter (SSLMate) issuances API, used without a key. Documentation read on 2026-11-11:
// https://sslmate.com/help/reference/ct_search_api_v1
//   GET https://api.certspotter.com/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names&expand=issuer
//   "list all unexpired certificate issuances for a domain": expired certificates never come back.
//   Pagination: add &after=<id of the last issuance>, "Repeat until the issuances endpoint returns
//   an empty array". No serial number in the issuance object (only tbs_sha256 / cert_sha256).
//   Unauthenticated use: "a limited number" of queries per hour; observed x-ratelimit-limit: 10.
//   Over the limit: a 4xx with code "rate_limited" (documented); 429 + Retry-After observed elsewhere,
//   not documented: both are handled.
import { fetchErrorReason, retryAfterSeconds } from './http.js';
import { cleanName, utcIso } from './names.js';
import type { CtCert, CtFetch, CtSourceResult } from './types.js';
import { t, tPlural } from '../../i18n.js';

export const CERTSPOTTER_TIMEOUT_MS = 15000;
/** Each page costs one query of the small hourly quota. */
export const CERTSPOTTER_MAX_PAGES = 4;
const MAX_BYTES = 8 * 1024 * 1024;

export function certSpotterUrl(domain: string, after?: string): string {
  return (
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer` +
    (after ? `&after=${encodeURIComponent(after)}` : '')
  );
}

interface Issuance {
  id?: string;
  cert_sha256?: string;
  dns_names?: string[];
  issuer?: { friendly_name?: string; name?: string };
  not_before?: string;
  not_after?: string;
  revoked?: boolean;
}

export async function searchCertSpotter(fetch: CtFetch, domain: string, signal?: AbortSignal): Promise<CtSourceResult> {
  const started = performance.now();
  const ms = () => Math.round(performance.now() - started);
  const certs: CtCert[] = [];
  let after: string | undefined;
  let pages = 0;
  let partial: string | undefined;
  let complete = false;
  for (; pages < CERTSPOTTER_MAX_PAGES; ) {
    let res;
    try {
      res = await fetch(certSpotterUrl(domain, after), { timeoutMs: CERTSPOTTER_TIMEOUT_MS, maxBytes: MAX_BYTES, signal });
    } catch (e) {
      partial = fetchErrorReason(e);
      break;
    }
    pages++;
    const body = res.body.toString('utf8');
    let json: unknown;
    try {
      json = JSON.parse(body);
    } catch {
      json = undefined;
    }
    const code = (json as { code?: string } | undefined)?.code;
    if (res.status === 429 || code === 'rate_limited') {
      const s = retryAfterSeconds(res.headers);
      partial = s !== undefined ? t('quota sans clé atteint, nouvel essai possible dans {min} min', { min: Math.max(1, Math.ceil(s / 60)) }) : t('quota sans clé atteint');
      break;
    }
    if (res.status !== 200) {
      const apiMessage = (json as { message?: string } | undefined)?.message;
      partial = apiMessage ? t('réponse HTTP {status} : {text}', { status: res.status, text: apiMessage }) : t('réponse HTTP {status}', { status: res.status });
      break;
    }
    if (!Array.isArray(json)) {
      partial = t('réponse illisible (liste JSON attendue)');
      break;
    }
    if (!json.length) {
      complete = true;
      break;
    }
    for (const it of json as Issuance[]) {
      const notBefore = utcIso(it.not_before);
      const notAfter = utcIso(it.not_after);
      const names = Array.from(
        new Set((it.dns_names ?? []).map((n) => cleanName(n, domain)).filter((c) => !!c).map((c) => (c!.wildcard ? `*.${c!.name}` : c!.name))),
      );
      if (!notBefore || !notAfter || !names.length) continue;
      const issuer = it.issuer?.name ?? it.issuer?.friendly_name ?? '';
      certs.push({
        source: 'certspotter',
        id: String(it.id ?? it.cert_sha256),
        issuer,
        issuerShort: it.issuer?.friendly_name ?? issuer,
        notBefore,
        notAfter,
        names,
        sha256: it.cert_sha256,
        revoked: it.revoked,
      });
    }
    const last = (json as Issuance[])[json.length - 1]?.id;
    if (!last || last === after) {
      complete = true;
      break;
    }
    after = String(last);
  }
  if (partial && !certs.length) return { source: 'certspotter', status: 'error', certs: [], names: [], error: partial, pages, ms: ms() };
  return {
    source: 'certspotter',
    status: 'ok',
    certs,
    names: [],
    pages,
    // a page limit or a quota hit after the first pages: what was read is kept, the rest is said
    error: partial
      ? tPlural(pages, 'lecture arrêtée après {n} page : {partial}', 'lecture arrêtée après {n} pages : {partial}', { partial })
      : !complete
        ? t('lecture limitée à {pages} pages pour ménager le quota', { pages })
        : undefined,
    truncated: !complete || undefined,
    ms: ms(),
  };
}
