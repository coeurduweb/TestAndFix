// DMARC (RFC 7489): record discovery with the organizational-domain fallback (Public Suffix List),
// every tag checked and explained, effective subdomain policy, external report authorization
// (RFC 7489 §7.1), and a progressive suggested record.
import type { PassedCheck } from '../../tools/types.js';
import { issue, lookupTxt, orgDomain, parseTags, pass, type Analysis, type Issue, type Resolver } from './common.js';
import { msg, t } from '../../i18n.js';

export type DmarcPolicy = 'none' | 'quarantine' | 'reject';

export interface DmarcTag {
  name: string;
  value: string;
  /** Human explanation in French of what this value does. */
  meaning: string;
  valid: boolean;
  error?: string;
  /** true when the tag was not written and its default applies. */
  implicit?: boolean;
}

export interface DmarcReportUri {
  tag: 'rua' | 'ruf';
  uri: string;
  scheme: string;
  address?: string;
  domain?: string;
  maxSize?: string;
  external: boolean;
  /** For an external destination: was <domain>._report._dmarc.<dest> found with v=DMARC1? */
  authorized?: boolean;
  authorizationRecord?: string;
  error?: string;
}

export interface DmarcData {
  domain: string;
  orgDomain: string;
  /** Name where the record was found (_dmarc.<domain> or _dmarc.<org>). */
  foundAt?: string;
  inherited: boolean;
  record?: string;
  records: string[];
  tags: DmarcTag[];
  policy?: DmarcPolicy;
  /** Policy applied to mail from this exact domain. */
  effectivePolicy?: DmarcPolicy;
  /** Policy applied to subdomains of the domain where the record lives. */
  subdomainPolicy?: DmarcPolicy;
  /** Policy for non-existent subdomains (np, DMARCbis), when published. */
  nonExistentPolicy?: DmarcPolicy;
  pct: number;
  alignment: { dkim: 'r' | 's'; spf: 'r' | 's' };
  reports: DmarcReportUri[];
  suggested?: string;
  /** Next steps of the progressive plan, from the current state. */
  plan: { record: string; when: string }[];
}

export interface DmarcAnalysis extends Analysis {
  data: DmarcData;
}

const POLICIES = ['none', 'quarantine', 'reject'];
const KNOWN = ['v', 'p', 'sp', 'np', 'adkim', 'aspf', 'pct', 'rua', 'ruf', 'fo', 'rf', 'ri', 'psd', 't'];

const POLICY_TEXT: Record<string, string> = {
  none: msg('aucune action : les messages en échec sont livrés normalement, seuls les rapports sont envoyés'),
  quarantine: msg('les messages en échec sont placés en spam (quarantaine)'),
  reject: msg('les messages en échec sont refusés'),
};

function explainTag(name: string, value: string): { meaning: string; error?: string } {
  const v = value.trim();
  switch (name) {
    case 'v':
      return v === 'DMARC1' ? { meaning: t('version du protocole') } : { meaning: t('version du protocole'), error: t('la valeur doit être exactement DMARC1') };
    case 'p':
    case 'sp':
    case 'np': {
      const who = name === 'p' ? t('Politique du domaine') : name === 'sp' ? t('Politique des sous-domaines') : t('Politique des sous-domaines inexistants');
      return POLICIES.includes(v.toLowerCase())
        ? { meaning: t('{who} : {policy}', { who, policy: t(POLICY_TEXT[v.toLowerCase()]) }) }
        : { meaning: who, error: t('valeur « {value} » inconnue (none, quarantine ou reject)', { value: v }) };
    }
    case 'adkim':
    case 'aspf': {
      const what = name === 'adkim' ? 'DKIM' : 'SPF';
      if (v === 'r') return { meaning: t('Alignement {what} souple : un sous-domaine du même domaine organisationnel suffit', { what }) };
      if (v === 's') return { meaning: t('Alignement {what} strict : le domaine doit être identique à celui du From', { what }) };
      return { meaning: t('Alignement {what}', { what }), error: t('valeur « {value} » inconnue (r ou s)', { value: v }) };
    }
    case 'pct':
      return /^\d{1,3}$/.test(v) && Number(v) <= 100
        ? { meaning: Number(v) < 100 ? t("La politique s'applique à {pct} % des messages en échec, les autres reçoivent la politique inférieure", { pct: v }) : t("La politique s'applique à {pct} % des messages en échec", { pct: v }) }
        : { meaning: t('Pourcentage de messages soumis à la politique'), error: t('un entier de 0 à 100 est attendu') };
    case 'rua':
      return { meaning: t('Adresses qui reçoivent les rapports agrégés quotidiens') };
    case 'ruf':
      return { meaning: t('Adresses qui reçoivent les rapports d’échec message par message (peu de fournisseurs les envoient)') };
    case 'fo': {
      const parts = v.split(':').map((s) => s.trim());
      const bad = parts.filter((p) => !['0', '1', 'd', 's'].includes(p));
      const m: Record<string, string> = { '0': t('si SPF et DKIM échouent tous deux'), '1': t('si SPF ou DKIM échoue'), d: t('si la signature DKIM échoue'), s: t('si SPF échoue') };
      return bad.length
        ? { meaning: t('Options des rapports d’échec'), error: t('valeur « {value} » inconnue (0, 1, d, s)', { value: bad.join(':') }) }
        : { meaning: t('Rapports d’échec envoyés {when}', { when: parts.map((p) => m[p]).join(t(', ou ')) }) };
    }
    case 'rf':
      return v.toLowerCase().split(':').every((x) => x.trim() === 'afrf')
        ? { meaning: t('Format des rapports d’échec (afrf)') }
        : { meaning: t('Format des rapports d’échec'), error: t('seul afrf est défini') };
    case 'ri':
      return /^\d+$/.test(v)
        ? { meaning: v === '86400' ? t('Intervalle demandé entre deux rapports agrégés : {v} secondes (un jour)', { v }) : t('Intervalle demandé entre deux rapports agrégés : {v} secondes', { v }) }
        : { meaning: t('Intervalle entre rapports'), error: t('un nombre de secondes est attendu') };
    case 'psd':
      return ['y', 'n', 'u'].includes(v) ? { meaning: t('Domaine de suffixe public (DMARCbis)') } : { meaning: t('Domaine de suffixe public (DMARCbis)'), error: t('y, n ou u attendu') };
    case 't':
      return ['y', 'n'].includes(v) ? { meaning: v === 'y' ? t('Mode test (DMARCbis) : la politique est appliquée un cran en dessous') : t('Mode test désactivé (DMARCbis)') } : { meaning: t('Mode test (DMARCbis)'), error: t('y ou n attendu') };
    default:
      return { meaning: t('Balise inconnue, ignorée par les destinataires') };
  }
}

export function parseReportUris(tag: 'rua' | 'ruf', value: string, policyOrg: string): DmarcReportUri[] {
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((raw) => {
      const m = /^([a-z][a-z0-9+.-]*):([^!]*)(?:!(\d+[kmgt]?))?$/i.exec(raw);
      if (!m) return { tag, uri: raw, scheme: '', external: false, error: t('URI illisible (mailto:adresse@domaine attendu)') };
      const scheme = m[1].toLowerCase();
      const out: DmarcReportUri = { tag, uri: raw, scheme, maxSize: m[3], external: false };
      if (scheme !== 'mailto') {
        if (scheme !== 'https') out.error = scheme === 'http' ? t('http: non chiffré ; utilisez mailto: (ou https:)') : t('schéma {scheme}: inconnu', { scheme });
        return out;
      }
      const addr = decodeURIComponent(m[2]).trim();
      const at = addr.lastIndexOf('@');
      if (at <= 0 || !/^[^\s@]+@[a-z0-9.-]+\.[a-z0-9-]{2,}$/i.test(addr)) {
        out.error = t('adresse « {addr} » invalide', { addr });
        return out;
      }
      out.address = addr;
      out.domain = addr.slice(at + 1).toLowerCase();
      out.external = orgDomain(out.domain) !== policyOrg;
      return out;
    });
}

async function fetchDmarc(dns: Resolver, name: string) {
  const txt = await lookupTxt(dns, `_dmarc.${name}`);
  const recs = txt.records.filter((r) => /^v\s*=\s*DMARC1\s*(;|$)/i.test(r.trim()));
  const near = txt.records.filter((r) => !recs.includes(r) && /dmarc/i.test(r));
  return { txt, recs, near };
}

export async function analyzeDmarc(dns: Resolver, domain: string): Promise<DmarcAnalysis> {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const org = orgDomain(domain);
  const data: DmarcData = {
    domain,
    orgDomain: org,
    inherited: false,
    records: [],
    tags: [],
    pct: 100,
    alignment: { dkim: 'r', spf: 'r' },
    reports: [],
    plan: [],
  };
  const [first, apexTxt] = await Promise.all([fetchDmarc(dns, domain), lookupTxt(dns, domain)]);
  let found = first;
  const apexDmarc = apexTxt.records.find((r) => /^v\s*=\s*DMARC1/i.test(r.trim()));
  if (found.txt.error) {
    issues.push(issue('dmarc.temperror', { domain }, { evidence: found.txt.error }));
    return { issues, passed, data };
  }
  data.foundAt = `_dmarc.${domain}`;
  if (!found.recs.length && !found.near.length && org !== domain) {
    const up = await fetchDmarc(dns, org);
    if (up.recs.length || up.near.length) {
      found = up;
      data.inherited = true;
      data.foundAt = `_dmarc.${org}`;
    }
  }
  data.records = found.recs;
  if (!found.recs.length) {
    data.foundAt = undefined;
    if (found.near.length) issues.push(issue('dmarc.syntax_invalid', { domain, value: t('le record doit commencer par v=DMARC1;') }, { evidence: found.near.join('\n') }));
    const suggested = `v=DMARC1; p=none; rua=mailto:dmarc@${org}`;
    data.suggested = suggested;
    data.plan = progressivePlan(undefined, org);
    issues.push(issue(org !== domain ? 'dmarc.subdomain_no_policy' : 'dmarc.missing', { domain, value: org, suggested_record: suggested }, { suggested }));
    if (apexDmarc) issues.push(issue('dmarc.record_at_apex', { domain }, { evidence: `${domain} : ${apexDmarc}` }));
    return { issues, passed, data };
  }
  if (found.recs.length > 1) {
    issues.push(issue('dmarc.multiple_records', { domain, value: found.recs.length }, { evidence: found.recs.join('\n') }));
  }
  const record = found.recs[0];
  data.record = record;
  const ev = `${data.foundAt} : ${record}`;
  const vars = { domain, dmarc_record: record };
  if (data.inherited) issues.push(issue('dmarc.inherited', { domain, value: org }, { evidence: ev }));

  const { tags, errors } = parseTags(record);
  if (errors.length) issues.push(issue('dmarc.syntax_invalid', { ...vars, value: t('balise illisible « {value} »', { value: errors.join(' ; ') }) }, { evidence: ev }));
  if (/;\s*;|=\s*;/.test(record) || /[,]\s*$/.test(record)) {
    /* empty values are tolerated; nothing to flag */
  }
  const seen = new Set<string>();
  for (const t of tags) {
    if (seen.has(t.name)) issues.push(issue('dmarc.duplicate_tag', { ...vars, value: t.name }, { evidence: ev }));
    seen.add(t.name);
    const ex = explainTag(t.name, t.value);
    data.tags.push({ name: t.name, value: t.value, meaning: ex.meaning, valid: !ex.error, error: ex.error });
    if (ex.error) issues.push(issue(['p', 'sp', 'np'].includes(t.name) ? 'dmarc.policy_invalid' : t.name === 'v' ? 'dmarc.syntax_invalid' : 'dmarc.invalid_tag_value', { ...vars, value: `${t.name}=${t.value} : ${ex.error}` }, { evidence: ev }));
    if (!KNOWN.includes(t.name)) issues.push(issue('dmarc.unknown_tags', { ...vars, value: t.raw }, { evidence: ev }));
  }
  if (tags[0]?.name !== 'v') issues.push(issue('dmarc.syntax_invalid', { ...vars, value: t('v=DMARC1 doit être la première balise') }, { evidence: ev }));
  const get = (n: string) => tags.find((t) => t.name === n)?.value.trim();
  const pRaw = get('p')?.toLowerCase();
  if (!pRaw) {
    issues.push(issue('dmarc.policy_invalid', vars, { evidence: ev }));
  } else if (tags[1]?.name !== 'p') {
    issues.push(issue('dmarc.syntax_invalid', { ...vars, value: t('p= doit suivre immédiatement v=DMARC1') }, { evidence: ev, severity: 'low' }));
  }
  const pol = (v?: string): DmarcPolicy | undefined => (v && POLICIES.includes(v.toLowerCase()) ? (v.toLowerCase() as DmarcPolicy) : undefined);
  const rua = get('rua');
  // RFC 7489 §6.6.3: an invalid or missing p with a valid rua is treated as p=none
  data.policy = pol(pRaw) ?? (rua ? 'none' : undefined);
  data.subdomainPolicy = pol(get('sp')) ?? data.policy;
  data.nonExistentPolicy = pol(get('np'));
  const pct = get('pct');
  data.pct = pct && /^\d{1,3}$/.test(pct) && Number(pct) <= 100 ? Number(pct) : 100;
  data.alignment = { dkim: get('adkim') === 's' ? 's' : 'r', spf: get('aspf') === 's' ? 's' : 'r' };
  data.effectivePolicy = data.inherited ? data.subdomainPolicy : data.policy;
  for (const [n, def, meaning] of [
    ['sp', data.policy ?? 'none', t('Sous-domaines : même politique que p= ({policy})', { policy: data.policy ?? 'none' })],
    ['adkim', 'r', t('Alignement DKIM souple (valeur par défaut)')],
    ['aspf', 'r', t('Alignement SPF souple (valeur par défaut)')],
    ['pct', '100', t('La politique s’applique à 100 % des messages en échec (valeur par défaut)')],
    ['fo', '0', t('Rapports d’échec seulement si SPF et DKIM échouent tous deux (valeur par défaut)')],
    ['ri', '86400', t('Rapports agrégés quotidiens (valeur par défaut)')],
  ] as const) {
    if (!seen.has(n)) data.tags.push({ name: n, value: def, meaning, valid: true, implicit: true });
  }

  const rank = (p?: DmarcPolicy) => (p ? POLICIES.indexOf(p) : -1);
  // policy strength
  if (data.effectivePolicy === 'none') issues.push(issue('dmarc.policy_none', vars, { evidence: ev }));
  else if (data.effectivePolicy) passed.push(pass('dmarc.policy', 'dmarc', t('Politique {policy} appliquée à {domain}', { policy: data.effectivePolicy, domain })));
  if (data.policy && data.policy !== 'none' && data.pct === 0) issues.push(issue('dmarc.pct_zero', { ...vars, value: data.pct }, { evidence: ev }));
  else if (data.policy && data.policy !== 'none' && data.pct < 100) issues.push(issue('dmarc.pct_partial', { ...vars, value: data.pct }, { evidence: ev }));
  if (data.policy && data.policy !== 'none' && !seen.has('np') && rank(data.subdomainPolicy) < 2) issues.push(issue('dmarc.np_absent', vars, { evidence: ev }));
  if (get('ruf')) issues.push(issue('dmarc.ruf_present', { ...vars, value: get('ruf') }, { evidence: ev }));
  else if (seen.has('fo')) issues.push(issue('dmarc.fo_without_ruf', { ...vars, value: get('fo') }, { evidence: ev }));
  const obsolete = ['ri', 'rf'].filter((n) => seen.has(n));
  if (obsolete.length) issues.push(issue('dmarc.obsolete_tags', { ...vars, value: obsolete.join(', ') }, { evidence: ev }));
  if (!data.inherited && seen.has('sp') && rank(data.subdomainPolicy) < rank(data.policy))
    issues.push(issue('dmarc.sp_weaker', { ...vars, value: `sp=${data.subdomainPolicy}` }, { evidence: ev }));
  if (get('t') === 'y') issues.push(issue('dmarc.testing_flag', vars, { evidence: ev }));

  // reports
  const policyOrg = orgDomain(data.foundAt!.replace(/^_dmarc\./, ''));
  data.reports = [...parseReportUris('rua', rua ?? '', policyOrg), ...parseReportUris('ruf', get('ruf') ?? '', policyOrg)];
  if (!rua) issues.push(issue('dmarc.rua_missing', vars, { evidence: ev }));
  for (const r of data.reports) if (r.error) issues.push(issue('dmarc.rua_invalid_uri', { ...vars, value: `${r.tag}=${r.uri} : ${r.error}` }, { evidence: ev }));
  const polDomain = data.foundAt!.replace(/^_dmarc\./, '');
  await Promise.all(
    data.reports
      .filter((r) => r.external && r.domain)
      .map(async (r) => {
        const name = `${polDomain}._report._dmarc.${r.domain}`;
        const txt = await lookupTxt(dns, name);
        const rec = txt.records.find((x) => /^v\s*=\s*DMARC1/i.test(x.trim()));
        r.authorized = !!rec;
        r.authorizationRecord = rec;
        if (txt.error) r.authorized = undefined;
      }),
  );
  for (const r of data.reports.filter((x) => x.external)) {
    if (r.authorized === false)
      issues.push(issue('dmarc.rua_external_unauthorized', { ...vars, value: r.domain }, { evidence: t('{name} : aucun TXT v=DMARC1', { name: `${polDomain}._report._dmarc.${r.domain}` }), suggested: 'v=DMARC1' }));
    else if (r.authorized) passed.push(pass(`dmarc.external_report.${r.domain}`, 'dmarc', t('{domain} accepte les rapports de {polDomain}', { domain: r.domain, polDomain })));
  }
  if (rua && data.reports.some((r) => r.tag === 'rua' && !r.error)) passed.push(pass('dmarc.rua', 'dmarc', t('Rapports agrégés demandés'), data.reports.filter((r) => r.tag === 'rua').map((r) => r.address ?? r.uri).join(', ')));
  if (data.alignment.dkim === 's' || data.alignment.spf === 's')
    issues.push(issue('dmarc.strict_alignment', { ...vars, value: [data.alignment.dkim === 's' ? 'adkim=s' : '', data.alignment.spf === 's' ? 'aspf=s' : ''].filter(Boolean).join(' ') }, { evidence: ev }));

  const broken = issues.some((i) => ['dmarc.syntax_invalid', 'dmarc.invalid_tag_value', 'dmarc.policy_invalid', 'dmarc.multiple_records', 'dmarc.duplicate_tag', 'dmarc.rua_invalid_uri', 'dmarc.unknown_tags'].includes(i.id));
  data.plan = progressivePlan(data, policyOrg, broken);
  data.suggested = data.plan[0]?.record;
  if (data.suggested) {
    for (const i of issues)
      if (!i.suggested && ['dmarc.policy_none', 'dmarc.pct_partial', 'dmarc.rua_missing', 'dmarc.syntax_invalid', 'dmarc.invalid_tag_value', 'dmarc.policy_invalid', 'dmarc.multiple_records', 'dmarc.duplicate_tag', 'dmarc.sp_weaker', 'dmarc.rua_invalid_uri', 'dmarc.testing_flag'].includes(i.id))
        i.suggested = data.suggested;
  }
  if (!issues.some((i) => i.id === 'dmarc.syntax_invalid' || i.id === 'dmarc.invalid_tag_value' || i.id === 'dmarc.multiple_records'))
    passed.push(pass('dmarc.syntax', 'dmarc', t('Syntaxe DMARC valide'), record));
  return { issues, passed, data };
}

/**
 * Next steps none -> quarantine -> reject, built from the published tags: sp, np, adkim, aspf,
 * ruf, fo, t... are kept as they are and in their order (review of 2026-11-10: a suggestion that
 * dropped sp=quarantine weakened the subdomains of gmail.com). Only p and pct change; the measured
 * rua is kept, and an address is proposed only when the record has none. Invalid, unknown and
 * obsolete tags (ri, rf) are dropped.
 */
function progressivePlan(d: DmarcData | undefined, org: string, broken = false): DmarcData['plan'] {
  const measuredRua = d?.reports.filter((r) => r.tag === 'rua' && !r.error).map((r) => r.uri) ?? [];
  const validRuf = d?.reports.filter((r) => r.tag === 'ruf' && !r.error).map((r) => r.uri) ?? [];
  const kept: string[] = [];
  let ruaAt = -1;
  for (const t of d?.tags ?? []) {
    if (t.implicit || !t.valid || ['v', 'p', 'pct', 'ri', 'rf'].includes(t.name) || !KNOWN.includes(t.name)) continue;
    if (kept.some((k) => k.startsWith(`${t.name}=`))) continue;
    if (t.name === 'rua') {
      if (measuredRua.length) {
        ruaAt = kept.length;
        kept.push(`rua=${measuredRua.join(',')}`);
      }
      continue;
    }
    if (t.name === 'ruf') {
      if (validRuf.length) kept.push(`ruf=${validRuf.join(',')}`);
      continue;
    }
    kept.push(`${t.name}=${t.value.trim()}`);
  }
  if (ruaAt < 0) kept.unshift(`rua=mailto:dmarc@${org}`);
  // Decision of 2026-11-10 (orchestrator), do not undo: the plan never proposes a record that our
  // own base flags (dmarc.sp_weaker). The published sp is kept as long as it is at least as strict
  // as the proposed p; once the proposed p is stricter, sp is dropped (subdomains then inherit p)
  // and the step says so in one sentence. Before that decision, sp was always kept, and earlier
  // still always dropped, which weakened the subdomains of gmail.com (sp=quarantine lost).
  const sp = kept.find((k) => k.startsWith('sp='))?.slice(3).toLowerCase();
  const strength = (x?: string) => (x ? POLICIES.indexOf(x) : -1);
  const tagsFor = (p: DmarcPolicy) => (sp && strength(sp) < strength(p) ? kept.filter((k) => !k.startsWith('sp=')) : kept);
  // a separate sentence: `when` is a fragment (« Étape 2, après… »), closed by a period before it
  const spNote = (p: DmarcPolicy) => (sp && strength(sp) < strength(p) ? t('sp={sp} est retiré : les sous-domaines suivent désormais p={p}.', { sp, p }) : '');
  const build = (p: DmarcPolicy, pct = 100) => ['v=DMARC1', `p=${p}`, pct < 100 ? `pct=${pct}` : '', ...tagsFor(p)].filter(Boolean).join('; ');
  const cur = d?.record ? d.policy : undefined;
  const pct = d?.pct ?? 100;
  const plan: DmarcData['plan'] = [];
  if (!cur || cur === 'none') {
    if (!d?.record || broken) plan.push({ record: build('none'), when: d?.record ? t('enregistrement corrigé, toujours en observation') : t('maintenant : collecter les rapports sans rien bloquer') });
    plan.push({ record: build('quarantine'), when: t('quand les rapports ne montrent plus d’envois légitimes en échec') });
    plan.push({ record: build('reject'), when: t('après quelques semaines en quarantaine sans faux positif') });
  } else if (cur === 'quarantine') {
    if (pct < 100 || broken) plan.push({ record: build('quarantine'), when: pct < 100 ? t('étendre la quarantaine à tous les messages en échec') : t('enregistrement corrigé') });
    plan.push({ record: build('reject'), when: t('quand les rapports ne montrent plus de faux positifs') });
  } else if (pct < 100 || broken) {
    plan.push({ record: build('reject'), when: pct < 100 ? t('appliquer le rejet à 100 % des messages') : t('enregistrement corrigé') });
  }
  for (const step of plan) {
    const p = /p=(none|quarantine|reject)/.exec(step.record)![1] as DmarcPolicy;
    const note = spNote(p);
    if (note) step.when = `${step.when.replace(/[.\s]+$/, '')}. ${note}`;
  }
  // never propose what is already published
  return plan.filter((s) => !d?.record || normalizeRecord(s.record) !== normalizeRecord(d.record));
}

function normalizeRecord(r: string): string {
  return r.toLowerCase().replace(/\s+/g, '').replace(/;$/, '');
}
