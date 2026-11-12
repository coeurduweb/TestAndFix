// crt.name (Defendio): passive subdomain index fed by the CT logs. Checked on 2026-11-11:
//   GET https://crt.name/v1/search?apex=<eTLD+1>&format=json&dates=1
//   200 application/json  [{"sub":"www.example.com","first_seen":"2026-01-08T00:00:00Z"}, ...]
//   400 text/plain        "invalid apex: not an apex (eTLD+1 is example.com)" for a subdomain
//   free, no token, 100 requests per IP per day (x-ratelimit-limit / x-ratelimit-remaining)
// Names only: "No certificate metadata, and nothing is ever deleted" (https://crt.name/). The index
// also holds names "that never showed up in a certificate".
import { fetchErrorReason, retryAfterSeconds } from './http.js';
import { cleanName } from './names.js';
import type { CtFetch, CtName, CtSourceResult } from './types.js';
import { t } from '../../i18n.js';

export const CRTNAME_TIMEOUT_MS = 15000;
const MAX_BYTES = 16 * 1024 * 1024;

export function crtNameUrl(apex: string): string {
  return `https://crt.name/v1/search?apex=${encodeURIComponent(apex)}&format=json&dates=1`;
}

/**
 * @param apex registrable domain (eTLD+1) sent to the index
 * @param domain searched domain (apex or a subdomain): only names at or under it are kept
 */
export async function searchCrtName(fetch: CtFetch, apex: string, domain: string, signal?: AbortSignal): Promise<CtSourceResult> {
  const started = performance.now();
  const ms = () => Math.round(performance.now() - started);
  const fail = (error: string): CtSourceResult => ({ source: 'crt.name', status: 'error', certs: [], names: [], error, ms: ms() });
  let res;
  try {
    res = await fetch(crtNameUrl(apex), { timeoutMs: CRTNAME_TIMEOUT_MS, maxBytes: MAX_BYTES, signal });
  } catch (e) {
    return fail(fetchErrorReason(e));
  }
  if (res.status === 429) {
    const s = retryAfterSeconds(res.headers);
    return fail(s !== undefined ? t('quota gratuit atteint (100 requêtes par jour et par IP), nouvel essai possible dans {min} min', { min: Math.ceil(s / 60) }) : t('quota gratuit atteint (100 requêtes par jour et par IP)'));
  }
  if (res.status !== 200) {
    const text = res.body.toString('utf8').trim().slice(0, 160);
    return fail(text && !text.startsWith('<') ? t('réponse HTTP {status} : {text}', { status: res.status, text }) : t('réponse HTTP {status}', { status: res.status }));
  }
  let list: unknown;
  try {
    list = JSON.parse(res.body.toString('utf8'));
  } catch {
    return fail(res.truncated ? t('réponse trop volumineuse, coupée') : t('réponse illisible (JSON attendu)'));
  }
  if (!Array.isArray(list)) return fail(t('réponse inattendue (liste attendue)'));
  const names: CtName[] = [];
  for (const item of list as { sub?: string; first_seen?: string }[]) {
    const c = item && typeof item.sub === 'string' ? cleanName(item.sub, domain) : undefined;
    if (!c) continue;
    names.push({ name: c.wildcard ? `*.${c.name}` : c.name, firstSeen: typeof item.first_seen === 'string' ? item.first_seen : undefined });
  }
  return { source: 'crt.name', status: 'ok', certs: [], names, ms: ms() };
}
