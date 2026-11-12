// Subdomains tool: shapes returned by /api/subdomains (mirror of server/src/tools/subdomains),
// the reducer of the live stream, filters, sort and CSV export.
import { msg, t } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';

export type SourceId = 'crt.name' | 'crt.sh' | 'certspotter';

export interface CertBrief {
  source: SourceId;
  id: string;
  serial?: string;
  issuer: string;
  issuerShort: string;
  notBefore: string;
  notAfter: string;
  viaWildcard?: string;
  nameCount: number;
  sha256?: string;
}

export interface DnsState {
  status: 'active' | 'dead' | 'dangling' | 'error' | 'skipped';
  rcode: string;
  a: string[];
  aaaa: string[];
  cname: string[];
  error?: string;
  viaWildcardDns?: boolean;
}

export interface ServedCert {
  ip: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysLeft?: number;
  expired: boolean;
  authorized: boolean;
  nameMatches: boolean;
  authorizationError?: string;
  newerThanCt?: boolean;
  error?: string;
}

export interface TakeoverState {
  service: string;
  level: 'vulnerable' | 'edge';
  target: string;
  evidence: string;
}

export interface SubRow {
  name: string;
  sources: SourceId[];
  certCount: number;
  firstSeen?: string;
  lastSeen?: string;
  lastCert?: CertBrief;
  certs?: CertBrief[];
  validUntil?: string;
  internal?: string;
  dns?: DnsState;
  served?: ServedCert;
  takeover?: TakeoverState;
}

export interface WildcardRow {
  name: string;
  certCount: number;
  firstSeen?: string;
  lastSeen?: string;
  lastCert?: CertBrief;
  validUntil?: string;
}

export interface SourceSummary {
  source: SourceId;
  label: string;
  status: 'ok' | 'error' | 'skipped';
  names: number;
  certs: number;
  ms: number;
  error?: string;
  truncated?: boolean;
}

export interface SubdomainsData {
  domain: string;
  sources: SourceSummary[];
  subdomains: SubRow[];
  wildcards: WildcardRow[];
  total: number;
  resolved: number;
  limit: number;
  notResolved: number;
  wildcardDns?: { name: string; ips: string[] };
  certSource?: SourceId;
  servedNewerThanCt: number;
  counts: { active: number; dead: number; dangling: number; risk: number; error: number; wildcards: number };
}

/* ---------- live stream ---------- */
export interface StreamState {
  sources: SourceSummary[];
  rows: SubRow[];
  wildcards: WildcardRow[];
  /** Names to resolve, and how many were resolved so far. */
  toResolve: number;
  resolvedSoFar: number;
  inventory: boolean;
  result: CheckResult<SubdomainsData> | null;
  error: string | null;
}

export const initialStream: StreamState = { sources: [], rows: [], wildcards: [], toResolve: 0, resolvedSoFar: 0, inventory: false, result: null, error: null };

export function reduce(s: StreamState, ev: { type: string; data: unknown }): StreamState {
  switch (ev.type) {
    case 'source': {
      const src = ev.data as SourceSummary;
      return { ...s, sources: [...s.sources.filter((x) => x.source !== src.source), src] };
    }
    case 'inventory': {
      const d = ev.data as { rows: SubRow[]; wildcards: WildcardRow[]; toResolve: number };
      return { ...s, inventory: true, rows: d.rows, wildcards: d.wildcards, toResolve: d.toResolve };
    }
    case 'subdomain': {
      const u = ev.data as Pick<SubRow, 'name' | 'dns' | 'served' | 'takeover'>;
      const i = s.rows.findIndex((r) => r.name === u.name);
      if (i < 0) return s;
      const rows = s.rows.slice();
      rows[i] = { ...rows[i], dns: u.dns, served: u.served, takeover: u.takeover };
      return { ...s, rows, resolvedSoFar: s.resolvedSoFar + 1 };
    }
    case 'done': {
      const r = ev.data as CheckResult<SubdomainsData>;
      return { ...s, result: r, rows: r.data.subdomains, wildcards: r.data.wildcards, sources: r.data.sources, resolvedSoFar: r.data.resolved };
    }
    case 'error':
      return { ...s, error: (ev.data as { message?: string })?.message ?? t('Erreur pendant la mesure.') };
    default:
      return s;
  }
}

/* ---------- status of a row ---------- */
export type RowStatus = 'risk' | 'active' | 'dangling' | 'dead' | 'error' | 'skipped' | 'pending';

export function rowStatus(r: SubRow): RowStatus {
  if (r.takeover) return 'risk';
  if (!r.dns) return 'pending';
  return r.dns.status;
}

export const STATUS_LABEL: Record<RowStatus, string> = {
  risk: msg('À risque'),
  active: msg('Actif'),
  dangling: msg('CNAME orphelin'),
  dead: msg('Ne résout plus'),
  error: msg('Erreur DNS'),
  skipped: msg('Non résolu'),
  pending: msg('En cours'),
};

/** Line under the name: what it resolves to now. */
export function resolvesTo(r: SubRow): string {
  const d = r.dns;
  if (!d) return '';
  if (d.status === 'skipped') return t('au-delà des 500 noms résolus');
  if (d.status === 'error') return d.error ? t('résolution impossible ({error})', { error: shortDnsError(d.error) }) : t('résolution impossible');
  const target = d.cname.length ? `CNAME ${d.cname[d.cname.length - 1]}` : '';
  const ips = [...d.a, ...d.aaaa];
  if (d.status === 'dangling') return t('{target} : cette cible n’existe pas', { target });
  if (d.status === 'dead') return target ? t('{target}, sans adresse', { target }) : d.rcode === 'NXDOMAIN' ? t('n’existe plus dans le DNS') : t('existe sans adresse IP');
  const shown = ips.slice(0, 2).join(', ') + (ips.length > 2 ? ` +${ips.length - 2}` : '');
  return [target, shown].filter(Boolean).join(' → ');
}

function shortDnsError(e: string): string {
  if (/timeout|took more than|pas de réponse/i.test(e)) return t('délai dépassé');
  if (/servfail/i.test(e)) return 'SERVFAIL';
  return e.length > 40 ? e.slice(0, 40) + '…' : e;
}

/* ---------- filters and sort ---------- */
export type Filter = 'all' | 'active' | 'dead' | 'risk' | 'wildcards';
export type SortKey = 'name' | 'recent' | 'first';

export function matchesFilter(r: SubRow, f: Filter): boolean {
  const st = rowStatus(r);
  if (f === 'active') return st === 'active';
  if (f === 'dead') return st === 'dead' || st === 'dangling';
  if (f === 'risk') return st === 'risk' || st === 'dangling' || !!(r.served && r.served.nameMatches && (r.served.expired || (r.served.daysLeft ?? 99) < 14));
  return true;
}

export function filterRows(rows: SubRow[], f: Filter, q: string, sort: SortKey): SubRow[] {
  const needle = q.trim().toLowerCase();
  const out = rows.filter((r) => matchesFilter(r, f) && (!needle || r.name.includes(needle) || resolvesTo(r).toLowerCase().includes(needle)));
  const recent = (r: SubRow) => r.served?.validFrom ?? r.lastSeen ?? '';
  if (sort === 'recent') out.sort((a, b) => recent(b).localeCompare(recent(a)) || a.name.localeCompare(b.name));
  else if (sort === 'first') out.sort((a, b) => (a.firstSeen ?? '9').localeCompare(b.firstSeen ?? '9') || a.name.localeCompare(b.name));
  else out.sort((a, b) => sortableName(a.name).localeCompare(sortableName(b.name)));
  return out;
}

/** Sort by parent first (b.a.example.com after a.example.com), like a zone file. */
const sortableName = (n: string) => n.split('.').reverse().join('.');

export function countFilters(rows: SubRow[], wildcards: number): Record<Filter, number> {
  return {
    all: rows.length,
    active: rows.filter((r) => matchesFilter(r, 'active')).length,
    dead: rows.filter((r) => matchesFilter(r, 'dead')).length,
    risk: rows.filter((r) => matchesFilter(r, 'risk')).length,
    wildcards,
  };
}

/* ---------- certificate shown in the list ---------- */
export interface ShownCert {
  kind: 'served' | 'published';
  issuer: string;
  from?: string;
  to?: string;
  expired: boolean;
  daysLeft?: number;
}

const DAY = 86400000;

/** The served certificate when we read one (the truth), else the last one published in CT. */
export function shownCert(r: SubRow, now = Date.now()): ShownCert | undefined {
  const s = r.served;
  if (s && !s.error && s.validTo && s.nameMatches) return { kind: 'served', issuer: s.issuer ?? '', from: s.validFrom, to: s.validTo, expired: s.expired, daysLeft: s.daysLeft };
  const c = r.lastCert;
  if (!c) return undefined;
  const left = Math.floor((Date.parse(c.notAfter) - now) / DAY);
  return { kind: 'published', issuer: c.issuerShort, from: c.notBefore, to: c.notAfter, expired: left < 0, daysLeft: left };
}

/** What to say when no certificate can be shown for a name. */
export function noCertNote(r: SubRow): { text: string; warn?: boolean } {
  const s = r.served;
  if (s?.error) return { text: t('HTTPS injoignable sur le port 443') };
  if (s && !s.nameMatches) return { text: t('le serveur présente le certificat d’un autre nom'), warn: true };
  return { text: r.certCount ? t('certificats anciens seulement') : t('aucun certificat retrouvé par les sources') };
}

/* ---------- CSV ---------- */
const cell = (v: unknown) => {
  const s = v === undefined || v === null ? '' : String(v);
  return /[";\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const day = (iso?: string) => (iso ? iso.slice(0, 10) : '');

/** CSV with a semicolon separator and a BOM: opens as columns in a French spreadsheet. */
export function toCsv(rows: SubRow[]): string {
  const head = ['nom', 'etat', 'cname', 'ipv4', 'ipv6', 'certificat_servi_emetteur', 'certificat_servi_expire', 'dernier_certificat_publie', 'emetteur_publie', 'expire_publie', 'nombre_certificats', 'premiere_apparition', 'sources', 'risque', 'nom_interne'];
  const lines = rows.map((r) =>
    [
      r.name,
      t(STATUS_LABEL[rowStatus(r)]),
      r.dns?.cname.join(' > '),
      r.dns?.a.join(' '),
      r.dns?.aaaa.join(' '),
      r.served && !r.served.error ? r.served.issuer : '',
      r.served && !r.served.error ? day(r.served.validTo) : '',
      day(r.lastCert?.notBefore),
      r.lastCert?.issuerShort,
      day(r.lastCert?.notAfter),
      r.certCount,
      day(r.firstSeen),
      r.sources.join(' '),
      r.takeover ? `${r.takeover.service} : ${r.takeover.evidence}` : '',
      r.internal ?? '',
    ]
      .map(cell)
      .join(';'),
  );
  return '﻿' + [head.join(';'), ...lines].join('\r\n') + '\r\n';
}
