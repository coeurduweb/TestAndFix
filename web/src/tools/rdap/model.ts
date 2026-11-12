// Whois tool, pure logic: shapes returned by the server (mirror of server/src/lib/whois/types.ts),
// the comparison rows, the list parsing, the SSE reducer of a list and its exports. Unit tested.
import { toDomain } from '../../lib/detect';
import { msg, t, tn } from '../../lib/i18n';
import type { SseEvent } from '../ip/sse';

export type Party = 'registry' | 'registrar';
export type Protocol = 'rdap' | 'whois';
export type ContactRole = 'registrant' | 'admin' | 'tech';

export interface Contact {
  role: ContactRole;
  name?: string;
  org?: string;
  email?: string;
  contactUrl?: string;
  redacted: ('name' | 'org' | 'email')[];
  privacyService?: boolean;
}

export interface Registrar {
  name?: string;
  ianaId?: string;
  url?: string;
  whoisServer?: string;
  rdapBase?: string;
  abuseEmail?: string;
}

export interface PartyRecord {
  party: Party;
  protocol: Protocol;
  server: string;
  url?: string;
  created?: string;
  updated?: string;
  expires?: string;
  status: string[];
  registryStatus: string[];
  registrar?: Registrar;
  reseller?: string;
  contacts: Contact[];
  nameservers: string[];
  dnssec?: boolean;
  raw: string;
  rawTruncated?: boolean;
}

export interface Attempt {
  party: Party;
  protocol: Protocol;
  server: string;
  status: 'ok' | 'not_found' | 'error' | 'rate_limited' | 'unsupported';
  reason?: string;
  ms?: number;
}

export interface Divergence {
  field: string;
  label: string;
  registry: string;
  registrar: string;
  expected?: boolean;
}

export interface StatusInfo {
  code: string;
  epp: boolean;
  setBy?: 'registre' | 'bureau';
  kind: 'lock' | 'bad' | 'info';
  meaning: string;
}

export interface WhoisMerged {
  statusDetails: StatusInfo[];
  created?: string;
  updated?: string;
  expires?: string;
  ageDays?: number;
  expiresInDays?: number;
  status: string[];
  registryStatus: string[];
  registrar?: Registrar;
  reseller?: string;
  contacts: Contact[];
  nameservers: string[];
  dnssec?: boolean;
}

export interface WhoisReport {
  domain: string;
  queried: string;
  unicode: string;
  tld: string;
  registry?: PartyRecord;
  registrar?: PartyRecord;
  attempts: Attempt[];
  merged: WhoisMerged;
  divergences: Divergence[];
  notFound?: boolean;
  registrarNotAnnounced?: boolean;
  registrarUnknown?: boolean;
  /** IPv4 addresses (A records) from DNS: [] when none, absent when DNS did not answer. */
  a?: string[];
  cachedAt?: string;
  lookedUpAt: string;
}

export interface WhoisRow {
  domain: string;
  unicode: string;
  ok: boolean;
  notFound?: boolean;
  error?: string;
  registrar?: string;
  ianaId?: string;
  reseller?: string;
  created?: string;
  updated?: string;
  expires?: string;
  ageDays?: number;
  expiresInDays?: number;
  status: string[];
  registryStatus: string[];
  nameservers: string[];
  dnssec?: boolean;
  a?: string[];
  contacts: Contact[];
  registrySource?: string;
  registrarSource?: string;
  divergences: Divergence[];
  cachedAt?: string;
}

/* ---------- formatting ---------- */

export const ROLE_LABEL: Record<ContactRole, string> = { registrant: msg('Titulaire'), admin: msg('Administratif'), tech: msg('Technique') };
export const PROTOCOL_LABEL: Record<Protocol, string> = { rdap: 'RDAP', whois: 'WHOIS' };

/** 12/03/2027 */
export const frDay = (iso?: string) => (iso ? iso.slice(0, 10).split('-').reverse().join('/') : '');

/** "il y a 6 794 jours" style counts, with years for long spans. */
export function fmtDays(days: number): string {
  const n = Math.abs(days);
  const base = tn(n, '{n} jour', '{n} jours');
  if (n < 365) return base;
  const years = Math.floor(n / 365.25);
  return t('{days} ({years})', { days: base, years: tn(years, '{n} an', '{n} ans') });
}

/** What a contact field shows: the value, « masqué », or nothing to say. */
export function contactField(c: Contact | undefined, f: 'name' | 'org' | 'email'): { text: string; hidden: boolean } | undefined {
  if (!c) return undefined;
  const v = c[f];
  if (v) return { text: v, hidden: false };
  if (c.redacted.includes(f)) return { text: t('masqué'), hidden: true };
  return undefined;
}

/** One line per contact for the table and the CSV: "Nom, Organisation, e-mail" or « masqué ». */
export function contactLine(c: Contact | undefined): string {
  if (!c) return '';
  const parts = (['name', 'org', 'email'] as const).map((f) => contactField(c, f)).filter((x): x is { text: string; hidden: boolean } => !!x);
  if (!parts.length) return '';
  if (c.privacyService && c.org) return t('masqué (service d’anonymat : {org})', { org: c.org });
  if (parts.every((p) => p.hidden)) return t('masqué');
  const visible = parts.filter((p) => !p.hidden).map((p) => p.text);
  return parts.some((p) => p.hidden) ? t('{names} (en partie masqué)', { names: visible.join(', ') }) : visible.join(', ');
}

/** Comparison of the two parties, field by field, divergences marked. */
export interface CompareRow {
  key: string;
  label: string;
  registry?: string;
  registrar?: string;
  diverges: boolean;
  expected?: boolean;
}

export function compareRows(r: WhoisReport): CompareRow[] {
  const a = r.registry;
  const b = r.registrar;
  const div = (k: string) => r.divergences.find((d) => d.field === k);
  const row = (key: string, label: string, f: (p: PartyRecord) => string | undefined, divKey = key): CompareRow => {
    const d = div(divKey);
    return { key, label, registry: a ? f(a) : undefined, registrar: b ? f(b) : undefined, diverges: !!d, expected: d?.expected };
  };
  const rows = [
    row('registrar', t('Bureau d’enregistrement'), (p) => p.registrar?.name),
    row('ianaId', t('Identifiant IANA'), (p) => p.registrar?.ianaId),
    row('created', t('Création'), (p) => frDay(p.created)),
    row('updated', t('Dernière modification'), (p) => frDay(p.updated)),
    row('expires', t('Expiration'), (p) => frDay(p.expires)),
    row('status', t('Statuts'), (p) => [...p.status, ...p.registryStatus].join(', ')),
    row('reseller', t('Revendeur'), (p) => p.reseller, 'reseller'),
    row('nameservers', t('Serveurs de noms'), (p) => p.nameservers.join(', ')),
    row('dnssec', 'DNSSEC', (p) => (p.dnssec === undefined ? undefined : p.dnssec ? t('signé') : t('non signé'))),
  ];
  return rows.filter((x) => x.registry || x.registrar);
}

/* ---------- list input ---------- */

export const BATCH_MAX = 100;

/** A pasted list as the page sees it: ASCII names, deduplicated, "www." dropped, junk set aside. */
export function parseList(raw: string): { domains: string[]; invalid: string[] } {
  const domains: string[] = [];
  const invalid: string[] = [];
  for (const tok of raw.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean)) {
    const d = toDomain(tok)?.replace(/^www\./, '');
    if (!d) invalid.push(tok);
    else if (!domains.includes(d)) domains.push(d);
  }
  return { domains, invalid };
}

/** /whois?liste=a,b,c, or /whois/<domain> for a single name. */
export function listPath(domains: string[]): string {
  if (domains.length === 1) return `/whois/${encodeURIComponent(domains[0])}`;
  return `/whois?liste=${domains.map(encodeURIComponent).join(',')}`;
}

/* ---------- list stream ---------- */

export interface BatchState {
  expected: string[];
  rows: Record<string, WhoisRow>;
  count?: number;
  invalid: { value: string; reason: string }[];
  duplicates: number;
  resultId?: string;
}

export const initialBatch = (expected: string[]) => (): BatchState => ({ expected, rows: {}, invalid: [], duplicates: 0 });

export function batchReducer(s: BatchState, e: SseEvent): BatchState {
  if (e.type === 'start') {
    const d = e.data as { count: number; domains: string[]; invalid?: { value: string; reason: string }[]; duplicates?: number };
    return { ...s, count: d.count, expected: d.domains, invalid: d.invalid ?? [], duplicates: d.duplicates ?? 0 };
  }
  if (e.type === 'row') {
    const r = e.data as WhoisRow;
    return { ...s, rows: { ...s.rows, [r.domain]: r } };
  }
  if (e.type === 'done') return { ...s, resultId: (e.data as { resultId?: string }).resultId };
  return s;
}

/* ---------- exports ---------- */

const COLUMNS: [string, (r: WhoisRow) => unknown][] = [
  ['domaine', (r) => r.domain],
  ['domaine_unicode', (r) => r.unicode],
  ['etat', (r) => (r.notFound ? t('non enregistré') : r.ok ? t('trouvé') : t('registre injoignable'))],
  ['bureau_enregistrement', (r) => r.registrar],
  ['iana_id', (r) => r.ianaId],
  ['revendeur', (r) => r.reseller],
  ['creation', (r) => r.created?.slice(0, 10)],
  ['derniere_modification', (r) => r.updated?.slice(0, 10)],
  ['expiration', (r) => r.expires?.slice(0, 10)],
  ['jours_depuis_creation', (r) => r.ageDays],
  ['jours_avant_expiration', (r) => r.expiresInDays],
  ['statuts_epp', (r) => r.status.join(' | ')],
  ['statuts_registre', (r) => r.registryStatus.join(' | ')],
  ['serveurs_de_noms', (r) => r.nameservers.join(' | ')],
  ['dnssec', (r) => (r.dnssec === undefined ? '' : r.dnssec ? t('oui') : t('non'))],
  ['ipv4_a', (r) => (r.a === undefined ? '' : r.a.length ? r.a.join(' | ') : t('aucune'))],
  ...(['registrant', 'admin', 'tech'] as const).flatMap((role): [string, (r: WhoisRow) => unknown][] => {
    const p = role === 'registrant' ? 'titulaire' : role === 'admin' ? 'admin' : 'tech';
    const c = (r: WhoisRow) => r.contacts.find((x) => x.role === role);
    return [
      [`${p}_nom`, (r) => contactField(c(r), 'name')?.text],
      [`${p}_organisation`, (r) => contactField(c(r), 'org')?.text],
      [`${p}_email`, (r) => contactField(c(r), 'email')?.text ?? (c(r)?.contactUrl ? t('formulaire : {url}', { url: c(r)!.contactUrl }) : '')],
    ];
  }),
  ['source_registre', (r) => r.registrySource],
  ['source_bureau', (r) => r.registrarSource],
  ['ecarts', (r) => r.divergences.filter((d) => !d.expected).map((d) => t('{label} : registre {registry} / bureau {registrar}', { label: d.label, registry: d.registry, registrar: d.registrar })).join(' | ')],
  ['erreur', (r) => r.error],
];

function csvCell(v: unknown, sep: string): string {
  const s = v === undefined || v === null ? '' : String(v);
  // a leading = + - @ would be read as a formula by a spreadsheet
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return safe.includes(sep) || /["\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/**
 * CSV of the rows in the order given. "excel": semicolon and a UTF-8 BOM, what a French Excel opens
 * as columns with accents intact; "standard": comma, no BOM (RFC 4180 style).
 */
export function toCsv(rows: WhoisRow[], flavour: 'excel' | 'standard' = 'excel'): string {
  const sep = flavour === 'excel' ? ';' : ',';
  const lines = [COLUMNS.map(([h]) => h).join(sep), ...rows.map((r) => COLUMNS.map(([, f]) => csvCell(f(r), sep)).join(sep))];
  return (flavour === 'excel' ? '﻿' : '') + lines.join('\r\n') + '\r\n';
}

export function toJson(rows: WhoisRow[]): string {
  return JSON.stringify(rows, null, 2) + '\n';
}
