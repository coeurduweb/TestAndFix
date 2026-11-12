// AlienVault OTX, general section of an IP indicator. Tested 2026-11-10: readable without a key
// (research/sources-de-donnees.md); quotas are not published. Pulses are community collections
// of indicators: being in one is a hint, not a verdict (public resolvers appear in many).
import { apiFetch, httpProblem, parseJson, type ApiFetch } from './source.js';

export const OTX_BASE = 'https://otx.alienvault.com';

export interface OtxData {
  ip: string;
  pulseCount: number;
  /** Names of a few pulses, most recent first as OTX returns them. */
  pulses: string[];
  /** OTX's own allow-list marks ("Known False Positive", "Whitelisted IP"...). */
  validation: string[];
  reputation?: number;
  link: string;
}

export async function otxIp(ip: string, opts: { base?: string; fetch?: ApiFetch } = {}): Promise<OtxData> {
  const kind = ip.includes(':') ? 'IPv6' : 'IPv4';
  const res = await (opts.fetch ?? apiFetch)(`${opts.base ?? OTX_BASE}/api/v1/indicators/${kind}/${encodeURIComponent(ip)}/general`);
  if (res.status === 404) return { ip, pulseCount: 0, pulses: [], validation: [], link: `https://otx.alienvault.com/indicator/ip/${ip}` };
  const problem = httpProblem(res.status, 'OTX AlienVault', res.text);
  if (problem) throw problem;
  const j = parseJson<{
    pulse_info?: { count?: number; pulses?: { name?: string }[] };
    validation?: { name?: string; message?: string }[];
    reputation?: number;
  }>(res.text, 'OTX AlienVault');
  return {
    ip,
    pulseCount: Number(j.pulse_info?.count ?? 0),
    pulses: (j.pulse_info?.pulses ?? []).map((p) => String(p.name ?? '')).filter(Boolean).slice(0, 5),
    validation: (j.validation ?? []).map((v) => String(v.name ?? v.message ?? '')).filter(Boolean),
    reputation: typeof j.reputation === 'number' ? j.reputation : undefined,
    link: `https://otx.alienvault.com/indicator/ip/${ip}`,
  };
}
