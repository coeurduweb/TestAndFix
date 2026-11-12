// DNS blocklists: list catalogue (research/dnsbl.json, tested by hand) and parallel lookups
// through the iterative resolver. The lookups go straight to the lists' authoritative servers,
// never through a public resolver (Spamhaus answers 127.255.255.254 to those).
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { dnsblName } from '../lib/net.js';
import { t } from '../i18n.js';
/** dns.promises.resolve-like function (nodeStyleResolver over a ResolveSession in production). */
export type DnsblResolver = (name: string, rrtype?: string) => Promise<unknown[]>;

export type DnsblWeight = 'major' | 'minor' | 'info';

export interface DnsblList {
  zone: string;
  name: string;
  type: 'ip' | 'domain';
  weight: DnsblWeight;
  status: 'alive' | 'dead' | 'inconclusive' | 'restricted' | string;
  return_codes: Record<string, string>;
  delist_url: string;
  usage_policy?: string;
  notes?: string;
}

export interface DnsblHit {
  zone: string;
  name: string;
  type: 'ip' | 'domain';
  weight: DnsblWeight;
  /** IP or domain that was looked up. */
  target: string;
  query: string;
  status: 'listed' | 'clean' | 'refused' | 'error';
  codes: string[];
  /** Meaning of the return codes, from the list's documentation. */
  meaning?: string;
  /** TXT record of the listing, when the list publishes one. */
  txt?: string;
  delistUrl?: string;
  error?: string;
  ms: number;
}

const here = path.dirname(fileURLToPath(import.meta.url));
export const DNSBL_FILE = path.resolve(here, '..', '..', '..', 'research', 'dnsbl.json');

/** Used only while research/dnsbl.json is missing or unreadable. */
export const FALLBACK_LISTS: DnsblList[] = [
  {
    zone: 'zen.spamhaus.org',
    name: 'Spamhaus ZEN',
    type: 'ip',
    weight: 'major',
    status: 'alive',
    return_codes: {
      '127.0.0.2': 'SBL',
      '127.0.0.3': 'SBL CSS',
      '127.0.0.4': 'XBL (CBL)',
      '127.0.0.9': 'DROP',
      '127.0.0.10': 'PBL (FAI)',
      '127.0.0.11': 'PBL (Spamhaus)',
    },
    delist_url: 'https://check.spamhaus.org/',
  },
  { zone: 'b.barracudacentral.org', name: 'Barracuda BRBL', type: 'ip', weight: 'major', status: 'alive', return_codes: { '127.0.0.2': 'liste' }, delist_url: 'https://www.barracudacentral.org/lookups' },
  { zone: 'bl.spamcop.net', name: 'SpamCop', type: 'ip', weight: 'major', status: 'alive', return_codes: { '127.0.0.2': 'liste' }, delist_url: 'https://www.spamcop.net/bl.shtml' },
  { zone: 'psbl.surriel.com', name: 'PSBL', type: 'ip', weight: 'minor', status: 'alive', return_codes: { '127.0.0.2': 'liste' }, delist_url: 'https://psbl.org/' },
  { zone: 'bl.mailspike.net', name: 'Mailspike', type: 'ip', weight: 'minor', status: 'alive', return_codes: {}, delist_url: 'https://mailspike.org/' },
  {
    zone: 'dbl.spamhaus.org',
    name: 'Spamhaus DBL',
    type: 'domain',
    weight: 'major',
    status: 'alive',
    return_codes: { '127.0.1.2': 'domaine spam', '127.0.1.4': 'domaine phishing', '127.0.1.5': 'domaine malware', '127.0.1.6': 'domaine botnet C&C' },
    delist_url: 'https://check.spamhaus.org/',
  },
];

let cached: { mtimeMs: number; lists: DnsblList[] } | undefined;

/**
 * Lists to query: live ones of research/dnsbl.json (re-read when the file changes, so the
 * catalogue can be updated without restarting), or the built-in fallback.
 */
export function loadDnsblLists(file = DNSBL_FILE): { lists: DnsblList[]; source: 'research' | 'fallback' } {
  try {
    const st = fs.statSync(file);
    if (!cached || cached.mtimeMs !== st.mtimeMs) {
      const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as DnsblList[] | { lists?: DnsblList[] };
      const all = Array.isArray(raw) ? raw : (raw.lists ?? []);
      cached = { mtimeMs: st.mtimeMs, lists: all.filter((l) => l && l.zone && (l.type === 'ip' || l.type === 'domain')) };
    }
    const alive = cached.lists.filter((l) => l.status === 'alive');
    if (alive.length) return { lists: alive, source: 'research' };
  } catch {
    /* missing or invalid file: fallback */
  }
  return { lists: FALLBACK_LISTS, source: 'fallback' };
}

/** Meaning of a return code: exact key, or a range key "127.0.0.10..127.0.0.14" of the catalogue. */
export function codeLabel(code: string, list: DnsblList): string | undefined {
  if (list.return_codes[code]) return list.return_codes[code];
  const [a, b, c2, d] = code.split('.').map(Number);
  for (const [k, label] of Object.entries(list.return_codes)) {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\.\.(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(k);
    if (!m) continue;
    const lo = m.slice(1, 5).map(Number);
    const hi = m.slice(5, 9).map(Number);
    if (a === lo[0] && b === lo[1] && c2 === lo[2] && d >= lo[3] && d <= hi[3]) return label;
  }
  return undefined;
}

/** 127.255.255.x answers mean "query refused" on Spamhaus and most lists that follow its scheme. */
function isRefusalCode(code: string, list: DnsblList): boolean {
  if (/^127\.255\.255\.\d+$/.test(code)) return true;
  // 127.0.0.1 without a documented meaning is not a listing: listings start at 127.0.0.2 and lists
  // answer 127.0.0.1 to queries they block. Seen on nbl.0spam.org for a Gmail IP, 2026-11-11.
  if (code === '127.0.0.1' && !codeLabel(code, list)) return true;
  if (list.zone.endsWith('spamhaus.org') && /^127\.0\.1\.255$/.test(code)) return true;
  const label = codeLabel(code, list);
  return !!label && /bloqu|refus|erreur|ignorer|blocked|refused|error|test permanent/i.test(label);
}

/** Codes that say something good or neutral (reputation scales, allow lists): not a listing. */
function isPositiveCode(code: string, list: DnsblList): boolean {
  const label = codeLabel(code, list);
  return !!label && /bonne|neutre|liste blanche|confiance|trusted|whitelist|allow/i.test(label);
}

/** SURBL multi returns a bitmask in the last octet. */
function surblMeaning(code: string, list: DnsblList): string | undefined {
  if (!list.zone.endsWith('surbl.org')) return undefined;
  const last = Number(code.split('.')[3]);
  const parts: string[] = [];
  for (const [c, label] of Object.entries(list.return_codes)) {
    const bit = Number(c.split('.')[3]);
    if (bit > 1 && bit !== 254 && (last & bit) === bit) parts.push(label);
  }
  return parts.length ? parts.join(', ') : undefined;
}

export interface DnsblQueryOptions {
  /** Max lookups in flight. */
  concurrency?: number;
  /** Also fetch the TXT record of a listing (reason, delisting link). */
  withTxt?: boolean;
  /**
   * A resolver per lookup (a fresh resolution session each): lookups of different lists then
   * never wait on each other inside one shared session.
   */
  resolverFor?: () => DnsblResolver;
}

async function lookupOne(resolver: DnsblResolver, list: DnsblList, target: string, withTxt: boolean): Promise<DnsblHit> {
  const started = performance.now();
  const query = list.type === 'ip' ? dnsblName(target, list.zone) : `${target.replace(/\.$/, '')}.${list.zone}`;
  const base: DnsblHit = {
    zone: list.zone,
    name: list.name,
    type: list.type,
    weight: list.weight,
    target,
    query,
    status: 'clean',
    codes: [],
    delistUrl: list.delist_url || undefined,
    ms: 0,
  };
  try {
    let codes: string[] = [];
    try {
      codes = ((await resolver(query, 'A')) as unknown[]).map(String);
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code !== 'ENOTFOUND' && code !== 'ENODATA') throw e;
    }
    base.ms = Math.round(performance.now() - started);
    if (!codes.length) return base;
    base.codes = codes;
    const real = codes.filter((c) => !isRefusalCode(c, list));
    if (!real.length) {
      return { ...base, status: 'refused', meaning: codes.map((c) => codeLabel(c, list) ?? t('requête refusée')).join(', ') };
    }
    const bad = real.filter((c) => !isPositiveCode(c, list));
    if (!bad.length) return { ...base, status: 'clean', codes: real, meaning: real.map((c) => codeLabel(c, list)).join(', ') };
    const meaning = bad.map((c) => codeLabel(c, list) ?? surblMeaning(c, list) ?? t('code {code} (non documenté)', { code: c })).join(', ');
    let txt: string | undefined;
    if (withTxt) {
      try {
        txt = ((await resolver(query, 'TXT')) as unknown[])
          .map((r) => (Array.isArray(r) ? r.join('') : String(r)))
          .join(' ')
          .slice(0, 500);
      } catch {
        /* the TXT record is optional */
      }
    }
    return { ...base, status: 'listed', codes: bad, meaning, txt, ms: Math.round(performance.now() - started) };
  } catch (e) {
    return { ...base, status: 'error', error: (e as Error).message, ms: Math.round(performance.now() - started) };
  }
}

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const k = i++;
      out[k] = await fn(items[k]);
    }
  });
  await Promise.all(workers);
  return out;
}

/** Query every IP list for each IP and every domain list for each domain, in parallel. */
export async function checkDnsbl(
  resolver: DnsblResolver,
  targets: { ips?: string[]; domains?: string[] },
  opts: DnsblQueryOptions & { lists?: DnsblList[] } = {},
): Promise<{ results: DnsblHit[]; source: 'research' | 'fallback' | 'custom'; lists: number }> {
  const loaded = opts.lists ? { lists: opts.lists, source: 'custom' as const } : loadDnsblLists();
  const jobs: { list: DnsblList; target: string }[] = [];
  for (const ip of new Set((targets.ips ?? []).filter((x) => net.isIP(x)))) {
    for (const list of loaded.lists.filter((l) => l.type === 'ip')) jobs.push({ list, target: ip });
  }
  for (const d of new Set((targets.domains ?? []).map((x) => x.toLowerCase().replace(/\.$/, '')).filter(Boolean))) {
    for (const list of loaded.lists.filter((l) => l.type === 'domain')) jobs.push({ list, target: d });
  }
  const results = await pool(jobs, opts.concurrency ?? 16, (j) => lookupOne(opts.resolverFor ? opts.resolverFor() : resolver, j.list, j.target, opts.withTxt ?? true));
  return { results, source: loaded.source, lists: loaded.lists.length };
}
