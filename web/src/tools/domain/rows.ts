// Pure logic shared by the domain pages: measured rows per section, findings attached to the row
// they stand for, ranking of what costs points, the SSE reducer of the scanner. Unit tested.
import type { Deviation, DevKind } from '../../components/Report';
import { fmtInt, fmtPenalty } from '../../lib/format';
import { msg, t, tn } from '../../lib/i18n';
import type { CheckResult, Finding } from '../../lib/types';
import {
  SECTIONS,
  type BimiData, type BlacklistData, type CaaData, type DkimData, type DkimKey, type DmarcData, type DnssecData, type MtaStsData,
  type MxData, type NsData, type RdapData, type ScanData, type ScanSection, type SectionId, type SmtpData, type SoaData, type SpfSummary,
} from './model';

/* ---------- measured rows ---------- */
export interface Metric {
  key: string;
  label: string;
  /** Label is a technical name (host, selector): set in mono. */
  mono?: boolean;
  /** Second line under the label, muted. */
  sub?: string;
  /** Nesting level (chain of zones): the label is shifted and marked as a child. */
  depth?: number;
  measured?: string;
  reference?: string;
  dev: Deviation;
  /** Findings this row stands for. */
  ids?: string[];
  /** Text the finding evidence must contain to belong to this row (a host, a selector). */
  evidence?: string;
}
export interface AttachedMetric extends Metric {
  findings: Finding[];
}

const RANK: Record<DevKind, number> = { pending: 0, ok: 1, info: 2, warn: 3, out: 4 };

export function findingKind(f: Finding): DevKind {
  if (f.penalty <= 0) return 'info';
  return f.severity === 'critical' || f.severity === 'high' ? 'out' : 'warn';
}

/** Each finding goes to the first row that stands for it; the others are returned in `rest`. */
export function attach(rows: Metric[], findings: Finding[]): { rows: AttachedMetric[]; rest: Finding[] } {
  const out: AttachedMetric[] = rows.map((r) => ({ ...r, findings: [] }));
  const rest: Finding[] = [];
  for (const f of findings) {
    const row = out.find((r) => r.ids?.includes(f.id) && (!r.evidence || (f.evidence ?? '').includes(r.evidence)));
    if (row) row.findings.push(f);
    else rest.push(f);
  }
  return { rows: out, rest };
}

/** Deviation shown for a row: its own measure, made heavier by the findings it carries. */
export function rowDeviation(r: AttachedMetric): Deviation {
  const penalized = r.findings.filter((f) => f.penalty > 0);
  if (!penalized.length) {
    // a finding without penalty never turns a conforming measure red
    return r.dev;
  }
  const worst = penalized.reduce((a, f) => (RANK[findingKind(f)] > RANK[a] ? findingKind(f) : a), 'info' as DevKind);
  const total = penalized.reduce((s, f) => s + f.penalty, 0);
  const label = t('Retire {n} point de la note', { n: fmtPenalty(total) });
  if ((r.dev.kind === 'out' || r.dev.kind === 'warn') && r.dev.text) {
    return { ...r.dev, kind: RANK[worst] > RANK[r.dev.kind] ? worst : r.dev.kind, label: r.dev.label ?? label };
  }
  return { kind: worst, text: fmtPenalty(total), direction: 'down', label };
}

/** Penalty carried by a row (to pick the one opened by default). */
export const rowPenalty = (r: AttachedMetric) => r.findings.reduce((s, f) => s + Math.max(0, f.penalty), 0);

/* ---------- what costs points ---------- */
export interface LostPoint {
  finding: Finding;
  section: SectionId;
  sectionTitle: string;
}

const SEV: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

/** Findings with a penalty, heaviest first, identical ones (same id and evidence) once. */
export function lostPoints(sections: Pick<ScanSection, 'id' | 'title' | 'findings'>[]): LostPoint[] {
  const seen = new Set<string>();
  const out: LostPoint[] = [];
  for (const s of sections) {
    for (const f of s.findings) {
      if (f.penalty <= 0) continue;
      const k = `${f.id}|${f.evidence ?? ''}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ finding: f, section: s.id, sectionTitle: s.title });
    }
  }
  return out.sort((a, b) => b.finding.penalty - a.finding.penalty || (SEV[b.finding.severity] ?? 0) - (SEV[a.finding.severity] ?? 0));
}

/** Short subject of an evidence ("m1._domainkey.cnn.com : k=rsa…" gives "m1._domainkey.cnn.com"). */
export function evidenceSubject(evidence?: string): string | undefined {
  if (!evidence) return undefined;
  const first = evidence.split('\n')[0].trim();
  const cut = first.split(/ : | → /)[0].trim();
  if (cut && cut !== first && cut.length <= 56) return cut;
  return first.length <= 56 ? first : undefined;
}

/* ---------- SSE reducer of the scanner ---------- */
export interface ScanState {
  domain?: string;
  order: { id: SectionId; title: string }[];
  sections: Partial<Record<SectionId, ScanSection>>;
  result?: CheckResult<ScanData>;
  error?: string;
}
export const initialScan: ScanState = { order: SECTIONS.map((s) => ({ id: s.id, title: s.title })), sections: {} };

export function scanReducer(state: ScanState, ev: { type: string; data: unknown }): ScanState {
  switch (ev.type) {
    case 'start': {
      const d = ev.data as { domain: string; sections: { id: SectionId; title: string }[] };
      return { ...state, domain: d.domain, order: d.sections?.length ? d.sections : state.order };
    }
    case 'section': {
      const s = ev.data as ScanSection;
      return { ...state, sections: { ...state.sections, [s.id]: s } };
    }
    case 'done': {
      const r = ev.data as CheckResult<ScanData>;
      const sections = { ...state.sections };
      for (const s of r.data?.sections ?? []) sections[s.id] = s;
      return { ...state, result: r, sections };
    }
    case 'error': {
      const message = (ev.data as { message?: string } | undefined)?.message;
      return message ? { ...state, error: message } : state;
    }
    default:
      return state;
  }
}

/* ---------- formatting ---------- */
export function fmtDuration(days: number): string {
  if (days < 0) return t('{n} j dépassés', { n: -days });
  if (days < 60) return tn(days, '{n} jour', '{n} jours');
  const years = Math.floor(days / 365.25);
  const months = Math.floor((days - years * 365.25) / 30.44);
  if (!years) return t('{n} mois', { n: months });
  const y = tn(years, '{n} an', '{n} ans');
  return months ? `${y} ${t('{n} mois', { n: months })}` : y;
}
export const isoDay = (iso?: string) => (iso ? iso.slice(0, 10).split('-').reverse().join('/') : '');

const ALL_LABEL: Record<string, string> = { '-': msg('-all (rejet)'), '~': msg('~all (échec souple)'), '?': msg('?all (neutre)'), '+': msg('+all (tout autorisé)') };
const POLICY_RANK: Record<string, number> = { none: 0, quarantine: 1, reject: 2 };

/** Name of the registrable-looking part of a host (last two labels). */
export const tailOf = (host: string) => host.replace(/\.$/, '').split('.').slice(-2).join('.');

/** Who signs with this key: CNAME target first, then the provider the selector is known for. */
/** Provider label, readable even for keys the shared list does not name. */
export function readableProvider(key: string, name: (p: string) => string): string {
  const n = name(key);
  if (n !== key) return n;
  return key.split('_').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

export function keyProvider(k: DkimKey, raw: (p: string) => string): string | undefined {
  const name = (p: string) => readableProvider(p, raw);
  if (k.cnameProvider) return t('{provider}, d’après le CNAME', { provider: name(k.cnameProvider) });
  if (k.cnames.length) return t('CNAME vers {target}', { target: tailOf(k.cnames[k.cnames.length - 1]) });
  if (k.knownFor?.length) return t('sélecteur habituel de {providers}', { providers: k.knownFor.map(name).join(', ') });
  return undefined;
}

function bimiCertMeasure(v: NonNullable<BimiData['vmc']>): string {
  const kind = v.kind ?? t('certificat');
  if (v.daysLeft === undefined) return kind;
  return v.expired ? t('{kind}, expiré', { kind }) : t('{kind}, {n} j restants', { kind, n: v.daysLeft });
}

export function keyMetric(k: DkimKey, name: (p: string) => string): Metric {
  const type = k.keyType === 'ed25519' ? 'Ed25519' : k.keyType.toUpperCase();
  const flags = [k.testing && 't=y (test)', k.strictSubdomains && 't=s (strict)', k.revoked && t('révoquée')].filter(Boolean).join(', ');
  const measured = k.error ? k.error : k.revoked ? t('clé révoquée (p= vide)') : `${k.bits ? t('{type} {bits} bits', { type, bits: k.bits }) : type}${flags ? ` · ${flags}` : ''}`;
  let dev: Deviation;
  if (k.error) dev = { kind: 'out', text: t('illisible'), direction: 'down' };
  else if (k.revoked) dev = { kind: 'info', text: t('révoquée') };
  else if (k.keyType === 'ed25519') dev = { kind: 'ok' };
  else if (k.bits !== undefined && k.bits < 1024) dev = { kind: 'out', text: fmtInt(2048 - k.bits), direction: 'down' };
  else if (k.bits !== undefined && k.bits < 2048) dev = { kind: 'warn', text: fmtInt(2048 - k.bits), direction: 'down' };
  else dev = { kind: 'ok' };
  return {
    key: `key-${k.selector}`,
    label: k.selector,
    mono: true,
    sub: keyProvider(k, name),
    measured,
    reference: k.keyType === 'ed25519' ? t('Ed25519 ou RSA ≥ 2048') : t('RSA ≥ 2048 bits'),
    dev,
    ids: ['dkim.key_1024', 'dkim.key_below_1024', 'dkim.key_revoked', 'dkim.key_testing_flag', 'dkim.key_syntax_error', 'dkim.key_service_type', 'dkim.key_algorithm_mismatch', 'dkim.multiple_key_records', 'dkim.ed25519_only'],
    evidence: k.name,
  };
}

/* ---------- section rows ---------- */
export interface SectionContext {
  domain: string;
  /** The domain itself does not exist (NXDOMAIN on MX). */
  nx?: boolean;
  providerName: (p: string) => string;
}

function mxRows(d: MxData): Metric[] {
  if (d.rcode === 'NXDOMAIN') return [{ key: 'nx', label: t('Existence du domaine'), measured: 'NXDOMAIN', reference: t('le nom existe'), dev: { kind: 'out', text: t('inexistant'), direction: 'down' }, ids: ['mx.domain_nxdomain'] }];
  const rows: Metric[] = [];
  if (d.nullMx) rows.push({ key: 'null', label: t('MX nul (« . »)'), measured: t('le domaine ne reçoit aucun courrier'), dev: { kind: 'info', text: t('déclaré') }, ids: ['mx.null_mx_mixed', 'mx.null_mx_on_sending_domain'] });
  const hosts = [...d.hosts].sort((a, b) => a.preference - b.preference);
  if (!d.nullMx) {
    rows.push({
      key: 'count',
      label: t('Serveurs MX publiés'),
      measured: hosts.length ? fmtInt(hosts.length) : d.implicit?.length ? t('aucun (adresse du domaine utilisée)') : t('aucun'),
      reference: '≥ 1',
      dev: hosts.length ? { kind: 'ok', text: hosts.length === 1 ? t('un seul') : t('conforme') } : { kind: 'out', text: t('absent'), direction: 'down' },
      ids: ['mx.missing', 'mx.unreachable'],
    });
  }
  for (const h of hosts.slice(0, 6)) {
    const addr = h.ipv4.length + h.ipv6.length;
    let dev: Deviation = { kind: 'ok' };
    if (h.ipLiteral) dev = { kind: 'out', text: t('IP littérale'), direction: 'down' };
    else if (h.privateIps.length) dev = { kind: 'out', text: t('IP privée'), direction: 'down' };
    else if (!addr) dev = { kind: 'out', text: t('sans adresse'), direction: 'down' };
    else if (h.cname?.length) dev = { kind: 'warn', text: 'CNAME', direction: 'down' };
    rows.push({
      key: `mx-${h.host}`,
      label: h.host,
      mono: true,
      measured: t('priorité {pref} · {v4} IPv4, {v6} IPv6', { pref: h.preference, v4: h.ipv4.length, v6: h.ipv6.length }),
      reference: t('≥ 1 adresse publique'),
      dev,
      ids: ['mx.target_nxdomain', 'mx.some_target_without_address', 'mx.host_unreachable', 'mx.cname_target', 'mx.private_address', 'mx.ip_literal'],
      evidence: h.host,
    });
  }
  if (hosts.length > 6) rows.push({ key: 'more', label: t('{n} autres MX', { n: hosts.length - 6 }), dev: { kind: 'info', text: t('non détaillés') } });
  return rows;
}

function spfRows(d: SpfSummary): Metric[] {
  if (!d.records?.length)
    return [{ key: 'missing', label: t('Enregistrement SPF'), measured: t('absent'), reference: t('1 exactement'), dev: { kind: 'out', text: t('absent'), direction: 'down' }, ids: ['spf.missing', 'spf.domain_nxdomain'] }];
  const all = d.allQualifier;
  const viaRedirect = !all && /\bredirect=/.test(d.record ?? '');
  return [
    {
      key: 'records', label: t('Enregistrements SPF publiés'), measured: fmtInt(d.records.length), reference: t('1 exactement'),
      dev: d.records.length === 1 ? { kind: 'ok' } : { kind: 'out', text: fmtInt(d.records.length - 1), direction: 'up' }, ids: ['spf.multiple_records'],
    },
    {
      key: 'lookups', label: t('Requêtes DNS déclenchées'), measured: fmtInt(d.lookupCount), reference: `≤ ${d.lookupLimit}`,
      dev: d.lookupCount > d.lookupLimit ? { kind: 'out', text: fmtInt(d.lookupCount - d.lookupLimit), direction: 'up' } : { kind: 'ok', text: d.lookupCount >= 8 ? t('limite proche') : t('conforme') },
      ids: ['spf.lookup_limit', 'spf.lookup_limit_near'],
    },
    {
      key: 'voids', label: t('Requêtes sans réponse'), measured: fmtInt(d.voidCount), reference: `≤ ${d.voidLimit}`,
      dev: d.voidCount > d.voidLimit ? { kind: 'out', text: fmtInt(d.voidCount - d.voidLimit), direction: 'up' } : { kind: 'ok' }, ids: ['spf.void_lookup_limit'],
    },
    {
      key: 'all', label: t('Règle finale'), measured: all ? (ALL_LABEL[all] ? t(ALL_LABEL[all]) : all) : viaRedirect ? t('celle du redirect=') : t('absente'), reference: '-all ou ~all',
      dev: all === '-' || all === '~' ? { kind: 'ok' } : viaRedirect ? { kind: 'info', text: t('déléguée') } : { kind: 'out', text: all ? t('trop permissive') : t('absente'), direction: 'down' },
      ids: ['spf.no_all', 'spf.plus_all', 'spf.neutral_all', 'spf.redirect_with_all', 'spf.terms_after_all'],
    },
  ];
}

function dkimRows(d: DkimData, ctx: SectionContext): Metric[] {
  const rows: Metric[] = [
    {
      key: 'found', label: t('Clés trouvées'), measured: t('{keys} sur {tried} sélecteurs essayés', { keys: d.keys.length, tried: d.tried }), reference: '≥ 1',
      dev: d.keys.length ? { kind: 'ok' } : { kind: 'info', text: t('non trouvée') }, ids: ['dkim.selector_not_discovered', 'dkim.key_not_found', 'dkim.wildcard'],
    },
  ];
  return rows.concat(d.keys.map((k) => keyMetric(k, ctx.providerName)));
}

export function policyDev(p: string | undefined): Deviation {
  if (!p) return { kind: 'out', text: t('absente'), direction: 'down' };
  if (p === 'none') return { kind: 'warn', text: 'none', direction: 'down' };
  return { kind: 'ok' };
}

function dmarcRows(d: DmarcData): Metric[] {
  if (!d.record) return [{ key: 'missing', label: t('Enregistrement _dmarc'), measured: t('absent'), reference: t('v=DMARC1 publié'), dev: { kind: 'out', text: t('absent'), direction: 'down' }, ids: ['dmarc.missing', 'dmarc.temperror', 'dmarc.record_at_apex'] }];
  const rua = d.reports.filter((r) => r.tag === 'rua');
  const unauthorized = d.reports.filter((r) => r.external && r.authorized === false);
  const rows: Metric[] = [
    { key: 'p', label: t('Politique (p=)'), measured: d.policy ?? t('invalide'), reference: t('quarantine ou reject'), dev: policyDev(d.policy), ids: ['dmarc.policy_none', 'dmarc.policy_invalid', 'dmarc.syntax_invalid', 'dmarc.multiple_records'] },
    {
      key: 'sp', label: t('Sous-domaines (sp=)'), measured: d.subdomainPolicy ?? d.policy ?? '', reference: t('au moins p='),
      dev: (POLICY_RANK[d.subdomainPolicy ?? ''] ?? 0) < (POLICY_RANK[d.policy ?? ''] ?? 0) ? { kind: 'warn', text: t('plus faible'), direction: 'down' } : { kind: 'ok' },
      ids: ['dmarc.sp_weaker'],
    },
    { key: 'pct', label: t('Part des messages (pct=)'), measured: `${d.pct} %`, reference: '100 %', dev: d.pct < 100 ? { kind: 'warn', text: `${100 - d.pct} %`, direction: 'down' } : { kind: 'ok' }, ids: ['dmarc.pct_partial', 'dmarc.pct_zero', 'dmarc.testing_flag'] },
    {
      key: 'rua', label: t('Rapports agrégés (rua=)'), measured: rua.length ? tn(rua.length, '{n} adresse', '{n} adresses') : t('aucune'), reference: t('≥ 1 adresse'),
      dev: !rua.length ? { kind: 'warn', text: t('absent'), direction: 'down' } : unauthorized.length ? { kind: 'warn', text: tn(unauthorized.length, '{n} non autorisée', '{n} non autorisées'), direction: 'down' } : { kind: 'ok' },
      ids: ['dmarc.rua_missing', 'dmarc.rua_invalid_uri', 'dmarc.rua_external_unauthorized'],
    },
  ];
  if (d.inherited) rows.unshift({ key: 'inherited', label: t('Enregistrement hérité'), measured: d.foundAt, reference: `_dmarc.${d.domain}`, dev: { kind: 'info', text: t('hérité') }, ids: ['dmarc.inherited'] });
  return rows;
}

function bimiRows(d: BimiData): Metric[] {
  if (!d.record) return [{ key: 'missing', label: t('Enregistrement {name}', { name: d.name }), measured: d.declined ? t('refus déclaré') : t('absent'), reference: t('v=BIMI1 publié'), dev: { kind: 'info', text: d.declined ? t('refusé') : t('absent') }, ids: ['bimi.missing', 'bimi.missing_dmarc_not_enforced', 'bimi.declined', 'bimi.syntax_invalid'] }];
  const rows: Metric[] = [];
  const svg = d.svg;
  rows.push({
    key: 'svg', label: t('Logo SVG Tiny PS'),
    measured: !d.logoUrl ? t('aucun l=') : !svg ? t('non lu') : svg.error ? svg.error : svg.problems.length ? tn(svg.problems.length, '{n} écart au profil', '{n} écarts au profil') : svg.bytes ? t('conforme, {size} Ko', { size: Math.round(svg.bytes / 102.4) / 10 }) : t('conforme'),
    reference: t('0 écart, HTTPS'),
    dev: !svg || svg.error ? { kind: 'out', text: t('illisible'), direction: 'down' } : svg.problems.length ? { kind: 'warn', text: fmtInt(svg.problems.length), direction: 'up' } : { kind: 'ok' },
    ids: ['bimi.svg_not_tiny_ps', 'bimi.svg_forbidden_content', 'bimi.logo_unreachable', 'bimi.logo_not_https', 'bimi.logo_size', 'bimi.svg_recommendation'],
  });
  const v = d.vmc;
  rows.push({
    key: 'vmc', label: t('Certificat de marque (a=)'),
    measured: !d.authorityUrl ? t('aucun') : !v ? t('non lu') : v.error ? v.error : bimiCertMeasure(v),
    reference: t('VMC ou CMC valide'),
    dev: !d.authorityUrl ? { kind: 'warn', text: t('absent'), direction: 'down' } : !v || v.error || v.expired ? { kind: 'out', text: v?.expired ? t('expiré') : t('illisible'), direction: 'down' } : v.daysLeft !== undefined && v.daysLeft < 30 ? { kind: 'warn', text: t('{n} j', { n: v.daysLeft }), direction: 'down' } : { kind: 'ok' },
    ids: ['bimi.no_certificate', 'bimi.certificate_invalid', 'bimi.certificate_logo_mismatch', 'bimi.cmc_no_checkmark'],
  });
  rows.push({
    key: 'dmarc', label: t('Prérequis DMARC'), measured: d.dmarc?.effectivePolicy ? `p=${d.dmarc.effectivePolicy}${d.dmarc.pct < 100 ? `, pct=${d.dmarc.pct}` : ''}` : t('absent'), reference: t('quarantine ou reject, pct=100'),
    dev: d.dmarcEligible ? { kind: 'ok' } : { kind: 'out', text: t('insuffisant'), direction: 'down' },
    ids: ['bimi.dmarc_not_enforced', 'bimi.dmarc_pct_below_100', 'bimi.dmarc_subdomain_none'],
  });
  return rows;
}

function mtaStsRows(d: MtaStsData): Metric[] {
  const covered = d.mx.filter((m) => m.covered === true).length;
  const known = d.mx.filter((m) => m.covered !== null).length;
  const rows: Metric[] = [
    { key: 'txt', label: t('Enregistrement _mta-sts'), measured: d.record ? `id=${d.id ?? '?'}` : t('absent'), reference: 'v=STSv1; id=…', dev: d.record ? { kind: 'ok' } : { kind: 'info', text: t('absent') }, ids: ['mta-sts.missing', 'mta-sts.txt_malformed'] },
  ];
  if (d.record) {
    rows.push({
      key: 'policy', label: t('Fichier de politique'), measured: d.policy?.mode ? t('mode {mode}', { mode: d.policy.mode }) : d.fetch?.error ?? (d.fetch?.status ? `HTTP ${d.fetch.status}` : t('non lu')), reference: 'mode enforce',
      dev: d.policy?.mode === 'enforce' ? { kind: 'ok' } : d.policy?.mode === 'testing' ? { kind: 'warn', text: 'testing', direction: 'down' } : { kind: 'out', text: d.policy?.mode ?? t('introuvable'), direction: 'down' },
      ids: ['mta-sts.policy_unreachable', 'mta-sts.policy_cert_invalid', 'mta-sts.policy_malformed', 'mta-sts.policy_redirect', 'mta-sts.wrong_content_type', 'mta-sts.testing_mode', 'mta-sts.mode_none', 'mta-sts.max_age_short', 'mta-sts.max_age_too_long'],
    });
    if (known) rows.push({ key: 'mx', label: t('MX couverts par la politique'), measured: `${covered} / ${d.mx.length}`, reference: t('tous'), dev: covered === d.mx.length ? { kind: 'ok' } : { kind: 'out', text: fmtInt(d.mx.length - covered), direction: 'down' }, ids: ['mta-sts.mx_not_covered'] });
  }
  rows.push({
    key: 'tlsrpt', label: t('Rapports TLS (TLS-RPT)'), measured: d.tlsrpt.rua.length ? d.tlsrpt.rua.join(', ') : t('absent'), reference: t('≥ 1 adresse'),
    dev: d.tlsrpt.rua.length ? { kind: 'ok' } : { kind: 'info', text: t('absent') }, ids: ['mta-sts.tlsrpt_missing', 'mta-sts.tlsrpt_malformed'],
  });
  return rows;
}

const DNSSEC_LABEL: Record<string, string> = { secure: msg('signée et validée'), insecure: msg('non signée'), bogus: msg('chaîne cassée'), indeterminate: msg('indéterminée') };

export function dnssecDev(status: string): Deviation {
  if (status === 'secure') return { kind: 'ok', text: t('validée') };
  if (status === 'bogus') return { kind: 'out', text: t('cassée'), direction: 'down' };
  if (status === 'insecure') return { kind: 'info', text: t('non signée') };
  return { kind: 'warn', text: t('indéterminée'), direction: 'down' };
}

/** The zone the server measured is a parent of the domain: the domain is not delegated. */
export const notDelegated = (domain: string, zone: string | undefined, nx?: boolean) =>
  !!zone && zone !== domain && nx === true && domain.endsWith(`.${zone}`);

function dnssecRows(d: DnssecData, ctx: SectionContext): Metric[] {
  if (notDelegated(ctx.domain, d.zone, ctx.nx))
    return [{ key: 'zone', label: t('Zone mesurée'), measured: t('{zone} (parent)', { zone: d.zone }), reference: ctx.domain, dev: { kind: 'out', text: t('non déléguée'), direction: 'down' } }];
  return [
    {
      key: 'status', label: t('Zone {zone}', { zone: d.zone }), measured: DNSSEC_LABEL[d.status] ? t(DNSSEC_LABEL[d.status]) : d.status, reference: t('signée et validée'),
      dev: dnssecDev(d.status), ids: ['dnssec.bogus', 'dnssec.ds_mismatch', 'dnssec.ds_missing', 'dnssec.dnskey_missing', 'dnssec.rrsig_expired', 'dnssec.rrsig_expiring', 'dnssec.unsigned'],
    },
    { key: 'chain', label: t('Chaîne de confiance'), measured: ['.', ...d.chain.map((c) => c.zone)].join(' → '), dev: { kind: 'info', text: tn(d.chain.length + 1, '{n} maillon', '{n} maillons') } },
  ];
}

function nsRows(d: NsData, ctx: SectionContext): Metric[] {
  if (notDelegated(ctx.domain, d.zone, ctx.nx))
    return [{ key: 'zone', label: t('Zone mesurée'), measured: t('{zone} (parent)', { zone: d.zone }), reference: ctx.domain, dev: { kind: 'out', text: t('non déléguée'), direction: 'down' } }];
  const n = d.parent.length;
  return [
    { key: 'count', label: t('Serveurs de noms délégués'), measured: fmtInt(n), reference: '≥ 2', dev: n >= 2 ? { kind: 'ok' } : { kind: 'out', text: fmtInt(2 - n), direction: 'down' }, ids: ['infrastructure.ns_single', 'infrastructure.ns_unresolvable'] },
    { key: 'net', label: t('Réseaux /24 distincts'), measured: fmtInt(d.networks.length), reference: '≥ 2', dev: d.networks.length >= 2 ? { kind: 'ok' } : { kind: 'warn', text: t('un seul'), direction: 'down' }, ids: ['infrastructure.ns_same_network'] },
    {
      key: 'coherent', label: t('Parent et zone d’accord'), measured: d.child.length ? t('{n} au parent, {m} dans la zone', { n, m: d.child.length }) : t('NS de la zone non lus'), reference: t('mêmes noms'),
      dev: d.child.length && sameSet(d.parent.map((p) => p.name), d.child) ? { kind: 'ok' } : { kind: 'warn', text: t('écart'), direction: 'down' },
      ids: ['infrastructure.ns_parent_child_mismatch', 'infrastructure.dns_lame_server'],
    },
  ];
}
const sameSet = (a: string[], b: string[]) => {
  const n = (x: string) => x.toLowerCase().replace(/\.$/, '');
  const A = new Set(a.map(n));
  return b.length === A.size && b.every((x) => A.has(n(x)));
};

function soaRows(d: SoaData, ctx: SectionContext): Metric[] {
  if (notDelegated(ctx.domain, d.zone, ctx.nx))
    return [{ key: 'zone', label: t('Zone mesurée'), measured: t('{zone} (parent)', { zone: d.zone }), reference: ctx.domain, dev: { kind: 'out', text: t('non déléguée'), direction: 'down' } }];
  if (!d.record) return [{ key: 'missing', label: t('Enregistrement SOA'), measured: t('absent'), reference: t('présent'), dev: { kind: 'out', text: t('absent'), direction: 'down' }, ids: ['infrastructure.soa_missing'] }];
  const serials = d.authoritative?.serials ?? [];
  const f = d.record.split(/\s+/);
  return [
    {
      key: 'serial', label: t('Serial identique partout'), measured: serials.length ? serials.join(', ') : f[2], reference: t('1 valeur'),
      dev: serials.length > 1 ? { kind: 'warn', text: fmtInt(serials.length), direction: 'up' } : { kind: 'ok' }, ids: ['infrastructure.dns_inconsistent'],
    },
    { key: 'timers', label: t('Rafraîchissement, expiration'), measured: f.length >= 7 ? `${f[3]} s, ${f[5]} s` : d.record, dev: { kind: 'info', text: t('noté') } },
  ];
}

function caaRows(d: CaaData): Metric[] {
  return [
    {
      key: 'caa', label: t('Autorités de certification'), measured: d.issuers.length ? d.issuers.join(', ') : t('aucune restriction'), reference: t('≥ 1 autorité nommée'),
      dev: d.records.length ? { kind: 'ok' } : { kind: 'info', text: t('absent') }, ids: ['infrastructure.caa_missing', 'infrastructure.caa_unknown_critical'],
    },
  ];
}

function blacklistRows(d: BlacklistData): Metric[] {
  const listed = d.listed.filter((h) => h.weight !== 'info');
  const rows: Metric[] = [
    {
      key: 'ips', label: t('Adresses de MX contrôlées'), measured: d.ips.length ? d.ips.join(', ') : t('aucune'), reference: '≥ 1',
      dev: d.ips.length ? { kind: 'ok', text: fmtInt(d.ips.length) } : { kind: 'warn', text: t('aucune'), direction: 'down' },
    },
    {
      key: 'listed', label: t('Inscriptions'), measured: t('{n} / {total} listes', { n: d.listed.length, total: d.listsQueried }), reference: '0',
      dev: listed.length ? { kind: 'out', text: fmtInt(listed.length), direction: 'up' } : d.listed.length ? { kind: 'info', text: t('informatives') } : { kind: 'ok' },
    },
  ];
  if (d.refused.length) rows.push({ key: 'refused', label: t('Listes qui ont refusé la requête'), measured: d.refused.map((h) => h.name).join(', '), dev: { kind: 'info', text: t('non mesuré') } });
  return rows;
}

function smtpRows(d: SmtpData): Metric[] {
  if (!d.port25.reachable && !d.probes.length)
    return [{ key: 'port25', label: t('Connexion au port 25'), measured: t('non vérifiable depuis cette machine'), reference: t('STARTTLS sur chaque MX'), dev: { kind: 'info', text: t('non mesuré') } }];
  return d.probes.slice(0, 6).map((p) => {
    const cert = p.tls?.cert;
    let dev: Deviation = { kind: 'ok' };
    if (p.status !== 'ok') dev = { kind: 'out', text: p.status === 'timeout' ? t('muet') : t('refusé'), direction: 'down' };
    else if (!p.starttls) dev = { kind: 'out', text: t('sans TLS'), direction: 'down' };
    else if (p.tls && !p.tls.ok) dev = { kind: 'out', text: t('TLS en échec'), direction: 'down' };
    else if (cert && (!cert.trusted || !cert.nameMatches)) dev = { kind: 'warn', text: t('certificat'), direction: 'down' };
    return {
      key: `probe-${p.host}-${p.ip}`,
      label: p.host,
      mono: true,
      sub: p.ip,
      measured: p.status !== 'ok' ? p.error ?? p.status : [p.starttls ? 'STARTTLS' : t('pas de STARTTLS'), p.tls?.protocol, cert?.daysLeft !== undefined ? t('certificat {n} j', { n: cert.daysLeft }) : ''].filter(Boolean).join(' · '),
      reference: 'STARTTLS, TLS 1.2+',
      dev,
      ids: ['tls.mx_no_starttls', 'tls.mx_starttls_broken', 'tls.mx_old_version_only', 'tls.mx_cert_expired', 'tls.mx_cert_expiring', 'tls.mx_cert_name_mismatch', 'tls.mx_cert_self_signed', 'tls.mx_cert_chain_incomplete', 'infrastructure.smtp_banner_mismatch'],
      evidence: p.host,
    };
  });
}

export function rdapRows(d: RdapData): Metric[] {
  const rows: Metric[] = [];
  if (d.ageDays !== undefined)
    rows.push({
      key: 'age', label: t('Âge du domaine'), sub: d.created ? t('créé le {date}', { date: isoDay(d.created) }) : undefined, measured: fmtDuration(d.ageDays), reference: t('≥ 30 jours'),
      dev: d.ageDays < 30 ? { kind: 'warn', text: t('{n} j', { n: 30 - d.ageDays }), direction: 'down' } : { kind: 'ok' }, ids: ['reputation.domain_very_new'],
    });
  if (d.expiresInDays !== undefined)
    rows.push({
      key: 'exp', label: t('Expiration'), sub: d.expires ? t('le {date}', { date: isoDay(d.expires) }) : undefined, measured: d.expiresInDays < 0 ? t('expiré') : t('dans {duration}', { duration: fmtDuration(d.expiresInDays) }), reference: t('≥ 30 jours'),
      dev: d.expiresInDays < 0 ? { kind: 'out', text: t('expiré'), direction: 'down' } : d.expiresInDays < 30 ? { kind: 'out', text: t('{n} j', { n: d.expiresInDays }), direction: 'down' } : { kind: 'ok', text: d.expiresInDays < 90 ? t('à renouveler') : t('conforme') },
      ids: ['infrastructure.domain_expired', 'infrastructure.domain_expiring'],
    });
  if (d.registrar?.name) rows.push({ key: 'registrar', label: t('Registrar'), measured: d.registrar.name, sub: d.registrar.ianaId ? `IANA ${d.registrar.ianaId}` : undefined, dev: { kind: 'info', text: t('noté') } });
  const hold = d.status.filter((s) => /hold|pending delete|redemption/.test(s));
  const locked = d.status.some((s) => /transfer prohibited/.test(s));
  if (d.status.length || d.ageDays !== undefined)
    rows.push({
      key: 'status', label: t('Statuts'), measured: d.status.length ? d.status.join(', ') : t('aucun'), reference: t('transfert verrouillé'),
      dev: hold.length ? { kind: 'out', text: t('bloquant'), direction: 'down' } : locked ? { kind: 'ok' } : { kind: 'warn', text: t('non verrouillé'), direction: 'down' },
      ids: ['infrastructure.domain_hold', 'infrastructure.domain_pending_delete'],
    });
  if (!rows.length) rows.push({ key: 'nr', label: t('Domaine enregistré'), measured: t('introuvable au registre'), reference: t('enregistré'), dev: { kind: 'out', text: t('absent'), direction: 'down' }, ids: ['infrastructure.domain_not_registered'] });
  return rows;
}

/** Measured rows of a scan section; empty when the section has no data. */
export function sectionMetrics(s: Pick<ScanSection, 'id' | 'data'>, ctx: SectionContext): Metric[] {
  const d = s.data as never;
  if (!d) return [];
  switch (s.id) {
    case 'mx': return mxRows(d);
    case 'spf': return spfRows(d);
    case 'dkim': return dkimRows(d, ctx);
    case 'dmarc': return dmarcRows(d);
    case 'bimi': return bimiRows(d);
    case 'mta-sts': return mtaStsRows(d);
    case 'dnssec': return dnssecRows(d, ctx);
    case 'ns': return nsRows(d, ctx);
    case 'soa': return soaRows(d, ctx);
    case 'caa': return caaRows(d);
    case 'blacklist': return blacklistRows(d);
    case 'smtp': return smtpRows(d);
    case 'rdap': return rdapRows(d);
    default: return [];
  }
}

/** Detailed page of each section (null: no page of its own). */
export const SECTION_PAGE: Record<SectionId, string | null> = {
  mx: '/dns/{d}?type=MX', spf: '/spf/{d}', dkim: '/dkim/{d}', dmarc: '/dmarc/{d}', bimi: '/bimi/{d}', 'mta-sts': '/mta-sts/{d}',
  dnssec: '/dnssec/{d}', ns: '/dns/{d}?type=NS', soa: '/dns/{d}?type=SOA', caa: '/dns/{d}?type=CAA', blacklist: null, smtp: '/smtp/{d}', rdap: '/whois/{d}',
};

/* ---------- pasted records (no server analysis) ---------- */
/** Tags of a pasted "k=v; k=v" record, as written. */
export function parseTagList(record: string): { name: string; value: string }[] {
  return record
    .replace(/^"|"$/g, '')
    .split(';')
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const i = p.indexOf('=');
      return i < 0 ? { name: p, value: '' } : { name: p.slice(0, i).trim(), value: p.slice(i + 1).trim() };
    });
}

/** Domains a pasted record may belong to (rua/ruf addresses): offered, never assumed. */
export function guessDomains(record: string): string[] {
  const out = new Set<string>();
  for (const m of record.matchAll(/mailto:[^@,;\s]+@([a-z0-9.-]+\.[a-z]{2,})/gi)) out.add(m[1].toLowerCase());
  return [...out].slice(0, 3);
}

/** The measured name does not exist (NXDOMAIN): one verdict replaces the whole report. */
export function isNxResult(r: { findings: Finding[]; data: unknown }): boolean {
  const d = r.data as { rcode?: string; nxdomain?: boolean } | null;
  return r.findings.some((f) => /\.domain_nxdomain$/.test(f.id)) || d?.nxdomain === true || d?.rcode === 'NXDOMAIN';
}

/** Findings really out of range (red), the others being "à surveiller", as in the score summary. */
export const outCount = (findings: Finding[]) => findings.filter((f) => findingKind(f) === 'out').length;
export const warnCount = (findings: Finding[]) => findings.filter((f) => findingKind(f) === 'warn').length;

/* ---------- scanner tiles (v2) ---------- */
export type TileState = 'out' | 'warn' | 'ok' | 'info' | 'pending' | 'unavailable';

export function tileState(s?: Pick<ScanSection, 'status' | 'findings'>): TileState {
  if (!s) return 'pending';
  if (s.findings.some((f) => findingKind(f) === 'out')) return 'out';
  if (s.findings.some((f) => findingKind(f) === 'warn')) return 'warn';
  if (s.status === 'unavailable') return 'unavailable';
  return s.findings.length ? 'info' : 'ok';
}

/** One line that says what was measured in a section, in plain words. */
export function tileSummary(s: Pick<ScanSection, 'id' | 'data' | 'status'>, ctx: SectionContext): string {
  const d = s.data as never;
  if (!d) return s.status === 'unavailable' ? t('non mesuré') : '';
  switch (s.id) {
    case 'mx': {
      const x = d as MxData;
      if (x.rcode === 'NXDOMAIN') return t('le domaine n’existe pas');
      if (x.nullMx) return t('MX nul : ne reçoit aucun courrier');
      const bad = x.hosts.filter((h) => !h.ipv4.length && !h.ipv6.length).length;
      const hosts = tn(x.hosts.length, '{n} serveur', '{n} serveurs');
      return bad ? t('{hosts}, {bad} sans adresse', { hosts, bad }) : hosts;
    }
    case 'spf': {
      const x = d as SpfSummary;
      if (!x.records?.length) return t('aucun enregistrement');
      const base = t('{n} requêtes sur {limit}', { n: x.lookupCount, limit: x.lookupLimit });
      return x.allQualifier ? t('{base}, {rule}', { base, rule: `${x.allQualifier}all` }) : base;
    }
    case 'dkim': {
      const x = d as DkimData;
      if (!x.keys.length) return t('aucune clé parmi {n} sélecteurs', { n: x.tried });
      const bits = x.keys.filter((k) => k.keyType === 'rsa' && k.bits).map((k) => k.bits!);
      const keys = tn(x.keys.length, '{n} clé', '{n} clés');
      return bits.length ? t('{keys}, la plus petite {bits} bits', { keys, bits: Math.min(...bits) }) : keys;
    }
    case 'dmarc': {
      const x = d as DmarcData;
      if (!x.record) return t('aucune politique');
      const rua = x.reports.filter((r) => r.tag === 'rua').length;
      return `p=${x.effectivePolicy ?? '?'}, ${rua ? t('rapports demandés') : t('sans rapports')}`;
    }
    case 'bimi': {
      const x = d as BimiData;
      if (!x.record) return x.declined ? t('refus déclaré') : t('pas de logo publié');
      return t('logo {state}, {cert}', { state: x.svg?.problems.length ? t('hors profil') : t('conforme'), cert: x.vmc ? x.vmc.kind ?? t('certificat') : t('sans certificat') });
    }
    case 'mta-sts': {
      const x = d as MtaStsData;
      if (!x.record) return x.tlsrpt.rua.length ? t('absent, TLS-RPT demandé') : t('absent');
      const what = x.policy?.mode ? t('mode {mode}', { mode: x.policy.mode }) : t('fichier introuvable');
      return x.tlsrpt.rua.length ? t('{what}, TLS-RPT', { what }) : what;
    }
    case 'dnssec': {
      const x = d as DnssecData;
      if (notDelegated(ctx.domain, x.zone, ctx.nx)) return t('zone non déléguée');
      return ({ secure: t('zone signée et validée'), insecure: t('zone non signée'), bogus: t('chaîne de confiance cassée'), indeterminate: t('état indéterminé') } as Record<string, string>)[x.status] ?? x.status;
    }
    case 'ns': {
      const x = d as NsData;
      if (notDelegated(ctx.domain, x.zone, ctx.nx)) return t('zone non déléguée');
      return t('{servers}, {networks}', { servers: tn(x.parent.length, '{n} serveur', '{n} serveurs'), networks: tn(x.networks.length, '{n} réseau', '{n} réseaux') });
    }
    case 'soa': {
      const x = d as SoaData;
      if (notDelegated(ctx.domain, x.zone, ctx.nx)) return t('zone non déléguée');
      if (!x.record) return t('absent');
      const serials = x.authoritative?.serials ?? [];
      return serials.length > 1 ? t('{n} serials différents', { n: serials.length }) : t('serial identique partout');
    }
    case 'caa': {
      const x = d as CaaData;
      return x.issuers.length ? t('autorisé : {issuers}', { issuers: x.issuers.join(', ') }) : t('aucune restriction');
    }
    case 'blacklist': {
      const x = d as BlacklistData;
      if (!x.ips.length) return t('aucune IP de MX contrôlée');
      const listed = x.listed.filter((h) => h.weight !== 'info').length;
      return listed ? tn(listed, '{n} inscription sur {total} listes', '{n} inscriptions sur {total} listes', { total: x.listsQueried }) : t('0 inscription sur {total} listes', { total: x.listsQueried });
    }
    case 'smtp': {
      const x = d as SmtpData;
      if (!x.port25.reachable && !x.probes.length) return t('non vérifiable depuis cette machine');
      const ok = x.probes.filter((p) => p.status === 'ok' && p.starttls).length;
      return t('{ok} sur {total} en STARTTLS', { ok, total: x.probes.length });
    }
    case 'rdap': {
      const x = d as RdapData;
      if (x.ageDays === undefined) return t('non enregistré ou registre muet');
      const age = fmtDuration(x.ageDays);
      return x.expiresInDays !== undefined ? t('{age}, expire dans {duration}', { age, duration: fmtDuration(Math.max(0, x.expiresInDays)) }) : age;
    }
    default:
      return '';
  }
}
