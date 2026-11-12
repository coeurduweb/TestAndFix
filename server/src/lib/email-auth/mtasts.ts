// MTA-STS (RFC 8461) and SMTP TLS Reporting (RFC 8460).
import type { PassedCheck } from '../../tools/types.js';
import type { SafeFetchResult } from '../net.js';
import { httpGet } from './http.js';
import { issue, lookupMx, lookupTxt, parseTags, pass, type Analysis, type Issue, type Resolver } from './common.js';
import { t } from '../../i18n.js';

export interface MtaStsPolicy {
  version?: string;
  mode?: string;
  mx: string[];
  maxAge?: number;
  errors: string[];
  raw: string;
}

export interface MtaStsData {
  domain: string;
  record?: string;
  records: string[];
  id?: string;
  policyUrl: string;
  fetch?: { status?: number; contentType?: string; location?: string; ms?: number; error?: string; certError?: string; bytes?: number };
  policy?: MtaStsPolicy;
  mx: { host: string; preference: number; covered: boolean | null }[];
  tlsrpt: { record?: string; records: string[]; rua: string[]; errors: string[] };
  /** Corrected policy file (every line), when the published one needs a change. */
  suggestedPolicy?: string;
  /** New _mta-sts TXT with a fresh id: senders refetch the policy only when the id changes (RFC 8461 §3.1). */
  suggestedTxt?: string;
}

export interface MtaStsAnalysis extends Analysis {
  data: MtaStsData;
}

const MAX_AGE_MAX = 31557600; // RFC 8461 §3.2

export function parsePolicy(text: string): MtaStsPolicy {
  const p: MtaStsPolicy = { mx: [], errors: [], raw: text };
  const seen = new Set<string>();
  let maxAgeInvalid = false;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const m = /^([A-Za-z0-9_]+)\s*:\s*(.*?)\s*$/.exec(line);
    if (!m) {
      p.errors.push(t('ligne illisible « {line} »', { line: line.slice(0, 80) }));
      continue;
    }
    const key = m[1].toLowerCase();
    const val = m[2];
    if (key !== 'mx' && seen.has(key)) p.errors.push(t('clé {key} répétée', { key }));
    seen.add(key);
    if (key === 'version') p.version = val;
    else if (key === 'mode') p.mode = val;
    else if (key === 'mx') p.mx.push(val.toLowerCase().replace(/\.$/, ''));
    else if (key === 'max_age') {
      if (/^\d{1,10}$/.test(val)) p.maxAge = Number(val);
      else {
        maxAgeInvalid = true;
        p.errors.push(t("max_age « {value} » n'est pas un nombre de secondes", { value: val }));
      }
    }
  }
  if (p.version !== 'STSv1') p.errors.push(p.version ? t('version « {value} » au lieu de STSv1', { value: p.version }) : t('ligne version: STSv1 absente'));
  if (!p.mode) p.errors.push(t('ligne mode: absente'));
  else if (!['enforce', 'testing', 'none'].includes(p.mode)) p.errors.push(t('mode « {value} » inconnu (enforce, testing ou none)', { value: p.mode }));
  if (p.maxAge === undefined && !maxAgeInvalid) p.errors.push(t('ligne max_age: absente'));
  if (p.mode && p.mode !== 'none' && !p.mx.length) p.errors.push(t('aucune ligne mx: alors que le mode n’est pas none'));
  return p;
}

/** RFC 8461 §4.1: "*.example.com" matches exactly one extra label. */
export function mxMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const p = pattern.toLowerCase().replace(/\.$/, '');
  if (p.startsWith('*.')) {
    const rest = p.slice(2);
    const i = h.indexOf('.');
    return i > 0 && h.slice(i + 1) === rest;
  }
  return h === p;
}

export interface MtaStsOptions {
  /** Injected for tests: fetch the policy. */
  fetchPolicy?: (url: string) => Promise<SafeFetchResult>;
  /** Session used by safeGet to resolve the policy host (no cache). */
  session?: Resolver;
}

export async function analyzeMtaSts(dns: Resolver, domain: string, opts: MtaStsOptions = {}): Promise<MtaStsAnalysis> {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  const [txt, mxr, rpt] = await Promise.all([lookupTxt(dns, `_mta-sts.${domain}`), lookupMx(dns, domain), lookupTxt(dns, `_smtp._tls.${domain}`)]);
  const records = txt.records.filter((r) => /^v\s*=\s*STSv1\b/i.test(r.trim()));
  const data: MtaStsData = {
    domain,
    records,
    record: records[0],
    policyUrl,
    mx: mxr.mx.filter((m) => m.exchange && m.exchange !== '.').map((m) => ({ host: m.exchange, preference: m.preference, covered: null })),
    tlsrpt: { records: [], rua: [], errors: [] },
  };
  const unavailable: { source: string; reason: string }[] = [];
  if (txt.error) unavailable.push({ source: 'dns', reason: t('{name} : {error}', { name: `_mta-sts.${domain}`, error: txt.error }) });

  // TLS-RPT
  const rptRecs = rpt.records.filter((r) => /^v\s*=\s*TLSRPTv1\b/i.test(r.trim()));
  data.tlsrpt.records = rptRecs;
  data.tlsrpt.record = rptRecs[0];
  if (rptRecs.length) {
    const { tags, errors } = parseTags(rptRecs[0]);
    data.tlsrpt.errors.push(...errors.map((e) => t('balise illisible « {value} »', { value: e })));
    if (rptRecs.length > 1) data.tlsrpt.errors.push(t('{n} enregistrements v=TLSRPTv1', { n: rptRecs.length }));
    if (tags[0]?.name !== 'v' || tags[0].value !== 'TLSRPTv1') data.tlsrpt.errors.push(t('v=TLSRPTv1 doit être la première balise'));
    const rua = tags.find((t) => t.name === 'rua')?.value;
    data.tlsrpt.rua = rua ? rua.split(',').map((s) => s.trim()).filter(Boolean) : [];
    if (!data.tlsrpt.rua.length) data.tlsrpt.errors.push(t('balise rua= absente'));
    for (const u of data.tlsrpt.rua) if (!/^(mailto:[^@\s]+@[^@\s]+|https:\/\/\S+)$/i.test(u)) data.tlsrpt.errors.push(t('destination « {value} » invalide (mailto: ou https:)', { value: u }));
    if (data.tlsrpt.errors.length)
      issues.push(issue('mta-sts.tlsrpt_malformed', { domain, value: data.tlsrpt.errors.join(' ; ') }, { evidence: `_smtp._tls.${domain} : ${rptRecs.join(' | ')}`, suggested: `v=TLSRPTv1; rua=mailto:tlsrpt@${domain}` }));
    else passed.push(pass('mta-sts.tlsrpt', 'mta-sts', t('Rapports TLS (TLS-RPT) demandés'), data.tlsrpt.rua.join(', ')));
  }

  if (!records.length) {
    if (txt.records.some((r) => /sts/i.test(r)))
      issues.push(issue('mta-sts.txt_malformed', { domain, value: t('le record doit commencer par v=STSv1') }, { evidence: txt.records.join(' | ') }));
    // mta-sts.tlsrpt_missing says "publishes MTA-STS without TLS-RPT": only when MTA-STS exists
    issues.push(issue('mta-sts.missing', { domain }));
    return { issues, passed, unavailable: unavailable.length ? unavailable : undefined, data };
  }
  if (!rptRecs.length) issues.push(issue('mta-sts.tlsrpt_missing', { domain }, { suggested: `v=TLSRPTv1; rua=mailto:tlsrpt@${domain}` }));

  // TXT record
  const { tags } = parseTags(records[0]);
  data.id = tags.find((t) => t.name === 'id')?.value;
  const txtErrors: string[] = [];
  if (records.length > 1) txtErrors.push(t('{n} enregistrements v=STSv1 (un seul est permis)', { n: records.length }));
  if (!data.id) txtErrors.push(t('balise id= absente'));
  else if (!/^[A-Za-z0-9]{1,32}$/.test(data.id)) txtErrors.push(t('id « {value} » invalide (1 à 32 lettres ou chiffres)', { value: data.id }));
  if (txtErrors.length)
    issues.push(issue('mta-sts.txt_malformed', { domain, value: txtErrors.join(' ; ') }, { evidence: records.join(' | '), suggested: `v=STSv1; id=${newPolicyId()}` }));
  else passed.push(pass('mta-sts.txt', 'mta-sts', t('Enregistrement _mta-sts valide'), records[0]));

  // policy
  let res: SafeFetchResult | undefined;
  try {
    res = await (opts.fetchPolicy ?? ((u) => httpGet(u, { maxBytes: 64 * 1024, session: opts.session, headers: { accept: 'text/plain' } })))(policyUrl);
  } catch (e) {
    const err = e as Error & { code?: string; cause?: { code?: string; message?: string } };
    const code = err.cause?.code ?? err.code ?? '';
    const certError = /CERT|SELF_SIGNED|UNABLE_TO|ALTNAME|ERR_TLS/i.test(code) ? `${code} ${err.cause?.message ?? ''}`.trim() : undefined;
    data.fetch = { error: err.cause?.message ?? err.message, certError };
    if (certError) issues.push(issue('mta-sts.policy_cert_invalid', { domain, value: certError }, { evidence: policyUrl }));
    else issues.push(issue('mta-sts.policy_unreachable', { domain, value: data.fetch.error }, { evidence: `${policyUrl} : ${data.fetch.error}` }));
    return { issues, passed, unavailable: unavailable.length ? unavailable : undefined, data };
  }
  data.fetch = { status: res.status, contentType: res.headers['content-type'], location: res.headers.location, ms: res.ms, bytes: res.body.length };
  if (res.status >= 300 && res.status < 400) {
    issues.push(issue('mta-sts.policy_redirect', { domain, value: res.headers.location }, { evidence: `${policyUrl} → ${res.status} ${res.headers.location ?? ''}` }));
    return { issues, passed, unavailable: unavailable.length ? unavailable : undefined, data };
  }
  if (res.status !== 200) {
    issues.push(issue('mta-sts.policy_unreachable', { domain, value: `HTTP ${res.status}` }, { evidence: `${policyUrl} : HTTP ${res.status}` }));
    return { issues, passed, unavailable: unavailable.length ? unavailable : undefined, data };
  }
  passed.push(pass('mta-sts.policy_https', 'mta-sts', t('Politique servie en HTTPS avec un certificat valide'), policyUrl));
  const ct = (res.headers['content-type'] ?? '').toLowerCase();
  if (!ct.startsWith('text/plain')) issues.push(issue('mta-sts.wrong_content_type', { domain, value: ct || t('(absent)') }, { evidence: `Content-Type: ${ct || t('(absent)')}` }));
  const policy = parsePolicy(res.body.toString('utf8'));
  data.policy = policy;
  if (res.truncated) policy.errors.push(t('fichier de politique trop volumineux'));
  const ev = policy.raw.trim().slice(0, 600);
  if (policy.errors.length) issues.push(issue('mta-sts.policy_malformed', { domain, value: policy.errors.join(' ; ') }, { evidence: ev }));
  if (policy.mode === 'testing') issues.push(issue('mta-sts.testing_mode', { domain }, { evidence: ev }));
  else if (policy.mode === 'none') issues.push(issue('mta-sts.mode_none', { domain }, { evidence: ev }));
  else if (policy.mode === 'enforce') passed.push(pass('mta-sts.enforce', 'mta-sts', t('Politique MTA-STS en mode enforce')));
  if (policy.maxAge !== undefined) {
    if (policy.maxAge > MAX_AGE_MAX) issues.push(issue('mta-sts.max_age_too_long', { domain, value: policy.maxAge }, { evidence: `max_age: ${policy.maxAge}` }));
    else if (policy.mode === 'enforce' && policy.maxAge < 604800) issues.push(issue('mta-sts.max_age_short', { domain, value: policy.maxAge }, { evidence: `max_age: ${policy.maxAge}` }));
  }
  for (const m of data.mx) m.covered = policy.mx.some((p) => mxMatches(m.host, p));
  const uncovered = data.mx.filter((m) => m.covered === false);

  // Corrected policy file and new TXT, given whole (review of 2026-11-10: the fix showed only the
  // max_age line as measured).
  const needsMx = policy.mode !== 'none' && uncovered.length > 0;
  const fixedMaxAge = policy.maxAge === undefined ? 604800 : policy.maxAge > MAX_AGE_MAX ? MAX_AGE_MAX : policy.mode === 'enforce' && policy.maxAge < 604800 ? 604800 : policy.maxAge;
  if (needsMx || fixedMaxAge !== policy.maxAge || policy.errors.length) {
    const mode = policy.mode && ['enforce', 'testing', 'none'].includes(policy.mode) ? policy.mode : 'testing';
    const mxLines = [...new Set([...policy.mx, ...(mode === 'none' ? [] : uncovered.map((m) => m.host))])];
    if (mode !== 'none' && !mxLines.length) mxLines.push(...data.mx.map((m) => m.host));
    data.suggestedPolicy = ['version: STSv1', `mode: ${mode}`, ...mxLines.map((p) => `mx: ${p}`), `max_age: ${fixedMaxAge}`].join('\n');
    data.suggestedTxt = `v=STSv1; id=${newPolicyId()}`;
  }
  const fullFix = data.suggestedPolicy
    ? `# ${policyUrl}\n${data.suggestedPolicy}\n\n# ${t('puis, pour que les expéditeurs relisent la politique :')}\n_mta-sts.${domain}. IN TXT "${data.suggestedTxt}"`
    : undefined;
  for (const i of issues) if (!i.suggested && fullFix && ['mta-sts.policy_malformed', 'mta-sts.max_age_short', 'mta-sts.max_age_too_long'].includes(i.id)) i.suggested = fullFix;
  if (policy.mode && policy.mode !== 'none' && uncovered.length) {
    const sev = policy.mode === 'enforce' ? {} : { severity: 'medium' as const, penalty: 0.3 };
    issues.push(
      issue('mta-sts.mx_not_covered', { domain, value: uncovered.map((m) => m.host).join(', ') }, {
        evidence: `MX : ${data.mx.map((m) => m.host).join(', ')}\n${t('Politique : {list}', { list: policy.mx.map((p) => `mx: ${p}`).join(', ') })}`,
        suggested: fullFix,
        ...sev,
      }),
    );
  } else if (data.mx.length && policy.mx.length) passed.push(pass('mta-sts.mx_covered', 'mta-sts', t('Tous les MX sont couverts par la politique')));
  return { issues, passed, unavailable: unavailable.length ? unavailable : undefined, data };
}

/** UTC timestamp id (YYYYMMDDHHMMSS), always different from the published one. */
export function newPolicyId(d = new Date()): string {
  return d.toISOString().replace(/[-:T]/g, '').slice(0, 14);
}
