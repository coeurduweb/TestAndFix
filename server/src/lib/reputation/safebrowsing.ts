// Google Safe Browsing Lookup API v4 (https://developers.google.com/safe-browsing/v4/lookup-api).
// v4 rather than v5: research/sources-de-donnees.md has the v4 quota and terms (non commercial,
// 500 URLs per request), the v5 ones were not read.
import { apiFetch, httpProblem, noKey, parseJson, type ApiFetch } from './source.js';
import { t, msg } from '../../i18n.js';

export const GSB_BASE = 'https://safebrowsing.googleapis.com';

export const GSB_THREAT_TYPES = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'];

export interface GsbMatch {
  url: string;
  threatType: string;
  platformType: string;
}

export interface GsbData {
  checked: string[];
  matches: GsbMatch[];
}

export async function safeBrowsingLookup(urls: string[], opts: { key: string; base?: string; fetch?: ApiFetch }): Promise<GsbData> {
  if (!opts.key) throw noKey('GSB_API_KEY', 'Google Safe Browsing');
  const checked = [...new Set(urls)].slice(0, 500);
  const body = {
    client: { clientId: 'check-reputation', clientVersion: '1.0' },
    threatInfo: {
      threatTypes: GSB_THREAT_TYPES,
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: checked.map((url) => ({ url })),
    },
  };
  const res = await (opts.fetch ?? apiFetch)(`${opts.base ?? GSB_BASE}/v4/threatMatches:find?key=${encodeURIComponent(opts.key)}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const problem = httpProblem(res.status, 'Google Safe Browsing', res.text);
  if (problem) throw problem;
  const json = parseJson<{ matches?: { threatType?: string; platformType?: string; threat?: { url?: string } }[] }>(res.text || '{}', 'Google Safe Browsing');
  return {
    checked,
    matches: (json.matches ?? []).map((m) => ({ url: m.threat?.url ?? '', threatType: m.threatType ?? 'THREAT_TYPE_UNSPECIFIED', platformType: m.platformType ?? 'ANY_PLATFORM' })),
  };
}

/** French label of a Safe Browsing threat type. */
export function gsbThreatLabel(threat: string): string {
  const label: string | undefined = (
    {
      MALWARE: msg('logiciel malveillant'),
      SOCIAL_ENGINEERING: msg('hameçonnage ou tromperie'),
      UNWANTED_SOFTWARE: msg('logiciel indésirable'),
      POTENTIALLY_HARMFUL_APPLICATION: msg('application potentiellement dangereuse'),
    } as Record<string, string>
  )[threat];
  return label ? t(label) : threat;
}
