// crt.sh (Sectigo): full-text search over the CT logs. Checked on 2026-11-11:
//   GET https://crt.sh/?q=%25.<domain>&output=json
//   200 application/json  [{"issuer_ca_id":..,"issuer_name":"C=US, O=Let's Encrypt, CN=YR2",
//        "common_name":"x.example.com","name_value":"x.example.com\nwww.x.example.com","id":..,
//        "not_before":"2026-09-21T07:56:41","not_after":"2026-12-20T07:56:40","serial_number":"06ae..",
//        "result_count":2}, ...]
//   Often slow (5 to 14 s before the first byte on a small domain), 502 Bad Gateway under load.
// A precertificate and its final certificate share serial and issuer: one entry is kept.
import { fetchErrorReason } from './http.js';
import { cleanName, issuerShortName, utcIso } from './names.js';
import type { CtCert, CtFetch, CtSourceResult } from './types.js';
import { t } from '../../i18n.js';

export const CRTSH_TIMEOUT_MS = 25000;
const MAX_BYTES = 24 * 1024 * 1024;

export function crtShUrl(domain: string): string {
  return `https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`;
}

interface CrtShRow {
  id?: number | string;
  issuer_ca_id?: number;
  issuer_name?: string;
  common_name?: string;
  name_value?: string;
  not_before?: string;
  not_after?: string;
  serial_number?: string;
}

/** Parse a JSON array cut in the middle: keep every complete object before the cut. */
export function salvageArray(text: string): unknown[] | undefined {
  const t = text.trimEnd();
  for (let end = t.lastIndexOf('},'); end > 0; end = t.lastIndexOf('},', end - 1)) {
    try {
      const v = JSON.parse(t.slice(0, end + 1) + ']');
      if (Array.isArray(v)) return v;
    } catch {
      /* the cut is inside a string: try the previous object boundary */
    }
    if (t.length - end > 1_000_000) break;
  }
  return undefined;
}

export async function searchCrtSh(fetch: CtFetch, domain: string, signal?: AbortSignal): Promise<CtSourceResult> {
  const started = performance.now();
  const ms = () => Math.round(performance.now() - started);
  const fail = (error: string): CtSourceResult => ({ source: 'crt.sh', status: 'error', certs: [], names: [], error, ms: ms() });
  let res;
  try {
    // one attempt only: crt.sh is slow when loaded, a retry would only double the wait
    res = await fetch(crtShUrl(domain), { timeoutMs: CRTSH_TIMEOUT_MS, maxBytes: MAX_BYTES, signal });
  } catch (e) {
    return fail(fetchErrorReason(e));
  }
  if (res.status === 429) return fail(t('trop de requêtes (HTTP 429), réessayez plus tard'));
  if (res.status === 502 || res.status === 503 || res.status === 504) return fail(t('service surchargé (HTTP {status}), fréquent sur crt.sh', { status: res.status }));
  if (res.status !== 200) return fail(t('réponse HTTP {status}', { status: res.status }));
  const text = res.body.toString('utf8');
  let rows: unknown;
  try {
    rows = JSON.parse(text);
  } catch {
    rows = res.truncated ? salvageArray(text) : undefined;
    if (!rows) return fail(res.truncated ? t('réponse trop volumineuse, coupée') : t('réponse illisible (JSON attendu)'));
  }
  if (!Array.isArray(rows)) return fail(t('réponse inattendue (liste attendue)'));
  const bySerial = new Map<string, CtCert>();
  for (const r of rows as CrtShRow[]) {
    if (!r || typeof r !== 'object') continue;
    const notBefore = utcIso(r.not_before);
    const notAfter = utcIso(r.not_after);
    if (!notBefore || !notAfter) continue;
    const raw = [...String(r.name_value ?? '').split('\n'), String(r.common_name ?? '')];
    const names = Array.from(
      new Set(raw.map((n) => cleanName(n, domain)).filter((c) => !!c).map((c) => (c!.wildcard ? `*.${c!.name}` : c!.name))),
    );
    if (!names.length) continue;
    const issuer = String(r.issuer_name ?? '');
    const serial = r.serial_number ? String(r.serial_number).toLowerCase() : undefined;
    const key = serial ? `${r.issuer_ca_id ?? issuer}|${serial}` : `id|${r.id}`;
    const prev = bySerial.get(key);
    if (prev) {
      for (const n of names) if (!prev.names.includes(n)) prev.names.push(n);
      continue;
    }
    bySerial.set(key, {
      source: 'crt.sh',
      id: String(r.id ?? key),
      serial,
      issuer,
      issuerShort: issuerShortName(issuer),
      notBefore,
      notAfter,
      names,
    });
  }
  return { source: 'crt.sh', status: 'ok', certs: [...bySerial.values()], names: [], truncated: res.truncated || undefined, ms: ms() };
}
