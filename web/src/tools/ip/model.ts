// IP reputation: shapes of the server (server/src/tools/ip/analyze.ts, mail/dnsbl.ts), stream
// reducers, the batch table (sort, filter, CSV) and the input parsing of the form.
import type { CheckResult, Finding } from '../../lib/types';
import { msg, t } from '../../lib/i18n';

export type Weight = 'major' | 'minor' | 'info';

export const WEIGHT_LABEL: Record<Weight, string> = { major: msg('majeure'), minor: msg('mineure'), info: msg('informative') };
export const WEIGHT_ORDER: Record<string, number> = { major: 0, minor: 1, info: 2 };

export interface DnsblHit {
  zone: string;
  name: string;
  weight: Weight;
  target: string;
  query: string;
  status: 'listed' | 'clean' | 'refused' | 'error';
  codes: string[];
  meaning?: string;
  txt?: string;
  delistUrl?: string;
  error?: string;
  ms: number;
}

export interface DnsblListing extends DnsblHit {
  situation: string;
  procedure: string[];
}

export interface PtrData {
  ip: string;
  query: string;
  rcode: string;
  names: string[];
  fcrdns: { name: string; ips: string[]; matches: boolean }[];
  confirmed?: string;
  error?: string;
  generic?: 'dynamic' | 'hosting';
}

export interface AbuseIpdbData {
  ip: string;
  score: number;
  totalReports: number;
  distinctUsers: number;
  lastReportedAt?: string;
  isWhitelisted?: boolean;
  isTor?: boolean;
  usageType?: string;
  isp?: string;
  domain?: string;
  maxAgeDays: number;
  link: string;
}
export interface VtIpData {
  ip: string;
  stats: { malicious: number; suspicious: number; harmless: number; undetected: number };
  reputation?: number;
  flagged: { engine: string; category: string; result?: string }[];
  lastAnalysisDate?: string;
  link: string;
}
export interface OtxData {
  ip: string;
  pulseCount: number;
  pulses: string[];
  validation: string[];
  link: string;
}
export interface CymruData {
  ip: string;
  origins: { asn: number; prefix: string; country?: string; registry?: string; allocated?: string }[];
  peers: number[];
  as: { asn: number; name?: string }[];
}
export interface RipestatData {
  ip: string;
  abuseContacts: string[];
  country?: string;
  city?: string;
  prefix?: string;
  announced?: boolean;
  holders: { asn: number; holder: string }[];
  block?: string;
  visibility?: { v4?: { seeing: number; total: number }; v6?: { seeing: number; total: number } };
  firstSeen?: string;
  missing: string[];
  link: string;
}

export interface IpReport {
  ip: string;
  version: 4 | 6;
  public: boolean;
  range?: { range: string; label: string };
  dnsbl?: {
    source: 'research' | 'fallback';
    queried: number;
    listed: DnsblListing[];
    refused: DnsblHit[];
    errors: { zone: string; name: string; error?: string }[];
    clean: { zone: string; name: string; weight: Weight }[];
    scoringOnly: DnsblHit[];
    skipped: { zone: string; name: string; reason: string }[];
  };
  ptr?: PtrData;
  network?: {
    asn?: number;
    asName?: string;
    prefix?: string;
    country?: string;
    registry?: string;
    allocated?: string;
    peers: number[];
    city?: string;
    abuseContacts: string[];
    announced?: boolean;
    visibility?: { seeing: number; total: number };
  };
  sources: { cymru?: CymruData; ripestat?: RipestatData; abuseipdb?: AbuseIpdbData; virustotal?: VtIpData; otx?: OtxData };
}

/* ---------- single IP stream ---------- */

export interface SourceEvent {
  source: string;
  label: string;
  ok: boolean;
  ms: number;
  reason?: string;
  data?: unknown;
}

export interface SingleState {
  ip?: string;
  lists: { zone: string; name: string; weight: Weight }[];
  sources: { id: string; label: string }[];
  hits: Record<string, DnsblHit>;
  events: Record<string, SourceEvent>;
  result?: CheckResult<IpReport>;
}

export const initialSingle = (): SingleState => ({ lists: [], sources: [], hits: {}, events: {} });

export function singleReducer(s: SingleState, e: { type: string; data: unknown }): SingleState {
  if (e.type === 'start') {
    const d = e.data as { ip: string; sources: { id: string; label: string }[]; lists: SingleState['lists'] };
    return { ...s, ip: d.ip, sources: d.sources ?? [], lists: sortLists(d.lists ?? []) };
  }
  if (e.type === 'source') {
    const ev = e.data as SourceEvent;
    if (ev.source.startsWith('dnsbl:')) {
      const zone = ev.source.slice(6);
      const hit = (ev.data as DnsblHit | undefined) ?? { zone, name: ev.label, weight: 'info', target: '', query: '', status: 'error', codes: [], error: ev.reason, ms: ev.ms };
      return { ...s, hits: { ...s.hits, [zone]: hit } };
    }
    return { ...s, events: { ...s.events, [ev.source]: ev } };
  }
  if (e.type === 'done') return { ...s, result: e.data as CheckResult<IpReport> };
  return s;
}

/** Major lists first, then minor, then informative; alphabetical inside a weight. */
export function sortLists<T extends { name: string; weight: string }>(lists: T[]): T[] {
  return [...lists].sort((a, b) => (WEIGHT_ORDER[a.weight] ?? 9) - (WEIGHT_ORDER[b.weight] ?? 9) || a.name.localeCompare(b.name, 'fr'));
}

/**
 * Mirror of isScoringOnly (server/src/lib/reputation/dnsbl-lists.ts): SPFBL answers .3 / .4 for
 * almost every address. Needed while streaming, before the final report sorts them out.
 */
export function isScoringOnly(h: Pick<DnsblHit, 'zone' | 'codes'>): boolean {
  return h.zone === 'dnsbl.spfbl.net' && h.codes.length > 0 && h.codes.every((c) => c === '127.0.0.3' || c === '127.0.0.4');
}

export type HitKind = 'listed' | 'clean' | 'refused' | 'error' | 'scoring' | 'pending';

export function hitKind(h: DnsblHit | undefined): HitKind {
  if (!h) return 'pending';
  if (h.status === 'listed') return isScoringOnly(h) ? 'scoring' : 'listed';
  return h.status;
}

export interface ListingSummary {
  answered: number;
  total: number;
  listed: number;
  majorListed: number;
  minorListed: number;
  infoListed: number;
  majorTotal: number;
  refused: number;
  errors: number;
}

export function listingSummary(lists: SingleState['lists'], hits: Record<string, DnsblHit>): ListingSummary {
  const out: ListingSummary = { answered: 0, total: lists.length, listed: 0, majorListed: 0, minorListed: 0, infoListed: 0, majorTotal: 0, refused: 0, errors: 0 };
  for (const l of lists) {
    if (l.weight === 'major') out.majorTotal++;
    const k = hitKind(hits[l.zone]);
    if (k !== 'pending') out.answered++;
    if (k === 'listed') {
      out.listed++;
      if (l.weight === 'major') out.majorListed++;
      else if (l.weight === 'minor') out.minorListed++;
      else out.infoListed++;
    }
    if (k === 'refused') out.refused++;
    if (k === 'error') out.errors++;
  }
  return out;
}

/** The finding of a DNSBL answer: same situation id, evidence starting with the query name. */
export function findingsOfQuery(findings: Finding[], query: string): Finding[] {
  return query ? findings.filter((f) => f.evidence?.startsWith(query + ' ')) : [];
}

/* ---------- batch ---------- */

export interface BatchRow {
  ip: string;
  status: 'clean' | 'listed' | 'private' | 'error';
  score?: number;
  ptr?: string;
  fcrdns?: boolean;
  asn?: number;
  asName?: string;
  prefix?: string;
  country?: string;
  listed: { zone: string; name: string; weight: Weight; codes: string[]; meaning?: string; delistUrl?: string; situation: string }[];
  majorListed: number;
  refused: string[];
  errors: string[];
  range?: string;
  findings: Finding[];
}

export interface BatchState {
  expected: string[];
  count?: number;
  invalid: { value: string; reason: string }[];
  lists: { zone: string; name: string }[];
  rows: Record<string, BatchRow>;
  /** IPs in arrival order, for those not in `expected`. */
  extra: string[];
  result?: CheckResult<unknown>;
}

export const initialBatch = (expected: string[]) => (): BatchState => ({ expected, invalid: [], lists: [], rows: {}, extra: [] });

export function batchReducer(s: BatchState, e: { type: string; data: unknown }): BatchState {
  if (e.type === 'start') {
    const d = e.data as { count: number; invalid?: BatchState['invalid']; lists?: BatchState['lists'] };
    return { ...s, count: d.count, invalid: d.invalid ?? [], lists: d.lists ?? [] };
  }
  if (e.type === 'row') {
    const r = e.data as BatchRow;
    const known = s.expected.includes(r.ip) || s.extra.includes(r.ip);
    return { ...s, rows: { ...s.rows, [r.ip]: r }, extra: known ? s.extra : [...s.extra, r.ip] };
  }
  if (e.type === 'done') return { ...s, result: e.data as CheckResult<unknown> };
  return s;
}

export type SortKey = 'ip' | 'status' | 'major' | 'ptr' | 'asn' | 'country' | 'score';
export interface Sort {
  key: SortKey;
  dir: 'asc' | 'desc';
}

/** Numeric value of an IPv4 (or a string fallback for IPv6) for sorting. */
export function ipKey(ip: string): string {
  const p = ip.split('.');
  if (p.length === 4 && p.every((x) => /^\d{1,3}$/.test(x))) return '4' + p.map((x) => x.padStart(3, '0')).join('');
  return '6' + ip;
}

const STATUS_RANK: Record<string, number> = { listed: 0, error: 1, clean: 2, private: 3 };

/** Sort rows; rows still pending (undefined) always go last. Stable on ties (IP order). */
export function sortRows(ips: string[], rows: Record<string, BatchRow>, sort: Sort): string[] {
  const dir = sort.dir === 'asc' ? 1 : -1;
  const val = (r: BatchRow): string | number | undefined => {
    switch (sort.key) {
      case 'ip':
        return ipKey(r.ip);
      case 'status':
        return STATUS_RANK[r.status] ?? 9;
      case 'major':
        return r.majorListed + r.listed.length / 100;
      case 'ptr':
        return r.ptr?.toLowerCase();
      case 'asn':
        return r.asn;
      case 'country':
        return r.country;
      case 'score':
        return r.score;
    }
  };
  return [...ips].sort((a, b) => {
    const ra = rows[a];
    const rb = rows[b];
    if (!ra || !rb) return ra ? -1 : rb ? 1 : ipKey(a).localeCompare(ipKey(b));
    const va = val(ra);
    const vb = val(rb);
    if (va === undefined || vb === undefined) {
      if (va !== vb) return va === undefined ? 1 : -1;
    } else if (va !== vb) return (va < vb ? -1 : 1) * dir;
    return ipKey(a).localeCompare(ipKey(b));
  });
}

/** One entry per list: ZEN answering CSS and XBL is one listing with two codes. */
export function byZone(listed: BatchRow['listed']): BatchRow['listed'] {
  const m = new Map<string, BatchRow['listed'][number]>();
  for (const l of listed) {
    const prev = m.get(l.zone);
    m.set(l.zone, prev ? { ...prev, codes: [...new Set([...prev.codes, ...l.codes])] } : l);
  }
  return [...m.values()];
}

const STATUS_TEXT: Record<BatchRow['status'], string> = { listed: msg('listée'), clean: msg('absente'), private: msg('non publique'), error: msg('sans réponse') };
export const statusText = (r: BatchRow) => t(STATUS_TEXT[r.status]);

function csvCell(v: unknown): string {
  const s = v === undefined || v === null ? '' : String(v);
  // a leading = + - @ would be read as a formula by a spreadsheet
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[";\n\r,]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/** CSV (semicolon, for French spreadsheets) of the rows in the order shown. */
export function toCsv(ips: string[], rows: Record<string, BatchRow>): string {
  const head = ['ip', 'statut', 'listes_majeures', 'listes', 'codes', 'reverse_dns', 'fcrdns', 'asn', 'operateur', 'prefixe', 'pays', 'note', 'requetes_refusees', 'sans_reponse'];
  const lines = [head.join(';')];
  for (const ip of ips) {
    const r = rows[ip];
    if (!r) {
      lines.push([ip, t('en attente'), '', '', '', '', '', '', '', '', '', '', '', ''].map(csvCell).join(';'));
      continue;
    }
    lines.push(
      [
        r.ip,
        statusText(r),
        r.status === 'private' ? '' : r.majorListed,
        byZone(r.listed).map((l) => l.name).join(' | '),
        byZone(r.listed).map((l) => `${l.name}: ${l.codes.join(' ')}${l.meaning ? ` (${l.meaning})` : ''}`).join(' | '),
        r.ptr,
        r.fcrdns === undefined ? '' : r.fcrdns ? t('oui') : t('non'),
        r.asn,
        r.asName,
        r.prefix,
        r.country,
        r.score === undefined ? '' : String(r.score).replace('.', ','),
        r.refused.join(' | '),
        r.errors.join(' | '),
      ]
        .map(csvCell)
        .join(';'),
    );
  }
  return '﻿' + lines.join('\r\n') + '\r\n';
}

/* ---------- input ---------- */

const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
export const isIpv4 = (s: string) => V4.test(s);
export function isIpv6(s: string): boolean {
  if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false;
  const dbl = s.split('::').length - 1;
  if (dbl > 1) return false;
  const parts = s.split(':');
  const tail = parts[parts.length - 1];
  const hasV4 = tail.includes('.');
  if (hasV4 && !isIpv4(tail)) return false;
  const groups = parts.filter((p, i) => !(hasV4 && i === parts.length - 1));
  if (groups.some((g) => g.length > 4)) return false;
  const n = groups.filter(Boolean).length + (hasV4 ? 2 : 0);
  return dbl ? n < 8 : n === 8 && groups.every(Boolean);
}
export const isIp = (s: string) => isIpv4(s) || isIpv6(s);

/** Tolerant cleaning of one token: brackets, trailing dot, "IP: " labels, a port after an IPv4. */
export function cleanToken(raw: string): string {
  let s = raw.trim();
  const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(s);
  if (bracketed) s = bracketed[1];
  s = s.replace(/^[[(<"']+|[\])>"',;.]+$/g, '');
  s = s.replace(/^(ip|ipv4|ipv6|adresse)\s*[:=]\s*/i, '');
  const port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(s);
  if (port) s = port[1];
  return s.toLowerCase();
}

export function isRange(s: string): boolean {
  const m = /^(.+)\/(\d{1,3})$/.exec(s);
  return !!m && isIpv4(m[1]) && Number(m[2]) >= 24 && Number(m[2]) <= 32;
}

/** "192.0.2.10/29" -> the 8 addresses of the block (same rule as server/src/tools/ip/input.ts). */
export function expandRange(s: string): string[] {
  const [base, len] = s.split('/');
  const prefix = Number(len);
  const b = base.split('.').map(Number);
  const n = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
  const size = 2 ** (32 - prefix);
  const start = n - (n % size);
  const out: string[] = [];
  for (let i = 0; i < size; i++) {
    const v = start + i;
    out.push([Math.floor(v / 2 ** 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.'));
  }
  return out;
}

export interface ParsedInput {
  /** Single addresses and ranges, cleaned, in order, without duplicates. */
  items: string[];
  invalid: string[];
}

/** Split what was typed or pasted: lines, commas, semicolons, spaces. */
export function parseInput(raw: string): ParsedInput {
  const items: string[] = [];
  const invalid: string[] = [];
  for (const tok of raw.split(/[\s,;]+/)) {
    if (!tok.trim()) continue;
    const c = cleanToken(tok);
    if (!c) continue;
    if (isIp(c) || isRange(c)) {
      if (!items.includes(c)) items.push(c);
    } else invalid.push(tok.trim());
  }
  return { items, invalid };
}

/** Addresses a batch will have, once ranges are expanded (the server dedups the same way). */
export function expectedIps(items: string[]): string[] {
  const seen = new Set<string>();
  for (const it of items) for (const ip of isRange(it) ? expandRange(it) : [it]) seen.add(ip);
  return [...seen];
}

/** Where an input leads: one IP, one range, or a list. */
export function inputPath(p: ParsedInput): string | null {
  if (!p.items.length) return null;
  if (p.items.length === 1) {
    // a range travels as one segment, 203.0.113.0%2F24, until the route /ip/:ip/:prefix exists
    return `/ip/${encodeURIComponent(p.items[0])}`;
  }
  return `/ip?liste=${p.items.map(encodeURIComponent).join(',')}`;
}

/**
 * Findings with unique ids for the score bar, which keys its slices by id: two listings of the same
 * situation (two lists answering "blacklist.ip_listed") would otherwise share a React key.
 */
export function uniqueIds<T extends { id: string }>(list: T[] | undefined): T[] | undefined {
  if (!list) return list;
  const seen = new Map<string, number>();
  return list.map((f) => {
    const n = seen.get(f.id) ?? 0;
    seen.set(f.id, n + 1);
    return n ? { ...f, id: `${f.id}~${n}` } : f;
  });
}
