// Domain reputation (US-069, /ip/<domaine>): shapes of GET /api/ip/domain/:domain/stream, the
// stream reducer and the list of the domain's addresses (web and mail) with their listing state.
// Contract fixed with the server agent on 2026-11-11 (names frozen).
import { msg } from '../../lib/i18n';
import type { CheckResult } from '../../lib/types';
import { hitKind, sortLists, type BatchRow, type DnsblHit, type SourceEvent, type Weight } from './model';

export interface DomainAddress {
  ip: string;
  family: 4 | 6;
  role: 'web' | 'mail';
  /** The domain itself for a web address, the MX host for a mail one. */
  host: string;
  row?: BatchRow;
}

export interface DomainReputation {
  domain: string;
  exists: boolean;
  nxdomain?: boolean;
  ageDays?: number;
  created?: string;
  registrar?: string;
  lists: { queried: number; listed: DnsblHit[]; refused: DnsblHit[]; errors: { zone: string; name?: string; error?: string }[]; clean: number | { zone: string; name: string }[] };
  addresses: DomainAddress[];
  intel?: Record<string, unknown>;
}

export interface DomainState {
  domain?: string;
  sources: { id: string; label: string }[];
  lists: { zone: string; name: string; weight: Weight }[];
  hits: Record<string, DnsblHit>;
  events: Record<string, SourceEvent>;
  rows: Record<string, BatchRow>;
  result?: CheckResult<DomainReputation>;
}

export const initialDomain = (): DomainState => ({ sources: [], lists: [], hits: {}, events: {}, rows: {} });

export function domainReducer(s: DomainState, e: { type: string; data: unknown }): DomainState {
  if (e.type === 'start') {
    const d = e.data as { domain: string; sources?: DomainState['sources']; lists?: DomainState['lists'] };
    return { ...s, domain: d.domain, sources: d.sources ?? [], lists: sortLists((d.lists ?? []).map((l) => ({ ...l, weight: l.weight ?? 'minor' }))) };
  }
  if (e.type === 'source') {
    const ev = e.data as SourceEvent;
    if (ev.source.startsWith('dnsbl:')) {
      const zone = ev.source.slice(6);
      const hit = (ev.data as DnsblHit | undefined) ?? { zone, name: ev.label, weight: 'info', target: '', query: '', status: 'error', codes: [], error: ev.reason, ms: ev.ms };
      return { ...s, hits: { ...s.hits, [zone]: hit } };
    }
    if (ev.source.startsWith('ip:')) {
      const row = ev.data as BatchRow | undefined;
      const ip = ev.source.slice(3);
      return row ? { ...s, rows: { ...s.rows, [ip]: row } } : s;
    }
    return { ...s, events: { ...s.events, [ev.source]: ev } };
  }
  if (e.type === 'done') return { ...s, result: e.data as CheckResult<DomainReputation> };
  return s;
}

/** Web addresses first, then each MX in preference order; live rows replace the pending ones. */
export function domainAddresses(s: DomainState): DomainAddress[] {
  const done = s.result?.data?.addresses;
  if (done) return done.map((a) => ({ ...a, row: a.row ?? s.rows[a.ip] }));
  const out: DomainAddress[] = [];
  const a = s.events.a?.ok ? (s.events.a.data as { ips?: { ip: string; family: 4 | 6 }[] }) : undefined;
  for (const x of a?.ips ?? []) out.push({ ip: x.ip, family: x.family, role: 'web', host: s.domain ?? '', row: s.rows[x.ip] });
  const mx = s.events.mx?.ok ? (s.events.mx.data as { hosts?: { host: string; preference?: number; ips: string[] }[] }) : undefined;
  for (const h of [...(mx?.hosts ?? [])].sort((p, q) => (p.preference ?? 0) - (q.preference ?? 0)))
    for (const ip of h.ips) out.push({ ip, family: ip.includes(':') ? 6 : 4, role: 'mail', host: h.host, row: s.rows[ip] });
  return out;
}

export interface DomainSummary {
  answered: number;
  total: number;
  listed: DnsblHit[];
  listedAddresses: number;
  addresses: number;
  pendingAddresses: number;
}

export function domainSummary(s: DomainState): DomainSummary {
  const listed: DnsblHit[] = [];
  let answered = 0;
  for (const l of s.lists) {
    const k = hitKind(s.hits[l.zone]);
    if (k !== 'pending') answered++;
    if (k === 'listed') listed.push(s.hits[l.zone]);
  }
  const addrs = domainAddresses(s);
  return {
    answered,
    total: s.lists.length,
    listed,
    listedAddresses: addrs.filter((a) => a.row?.status === 'listed').length,
    addresses: addrs.length,
    pendingAddresses: addrs.filter((a) => !a.row).length,
  };
}

export const ROLE_LABEL: Record<DomainAddress['role'], string> = { web: msg('Site web'), mail: msg('Serveur de mail') };

export interface AddressGroup {
  role: DomainAddress['role'];
  /** The domain for the site, the MX host for mail. */
  host: string;
  preference?: number;
  addresses: DomainAddress[];
  listed: number;
  pending: number;
}

/** The site's addresses in one group, then one group per MX, in preference order. */
export function addressGroups(s: DomainState): AddressGroup[] {
  const addrs = domainAddresses(s);
  const mx = s.events.mx?.ok ? (s.events.mx.data as { hosts?: { host: string; preference?: number }[] }) : undefined;
  const pref = new Map((mx?.hosts ?? []).map((h) => [h.host, h.preference]));
  const groups = new Map<string, AddressGroup>();
  for (const a of addrs) {
    const key = a.role === 'web' ? 'web' : `mail:${a.host}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = { role: a.role, host: a.host, preference: a.role === 'mail' ? pref.get(a.host) : undefined, addresses: [], listed: 0, pending: 0 }));
    if (g.addresses.some((x) => x.ip === a.ip)) continue;
    g.addresses.push(a);
    if (!a.row) g.pending++;
    else if (a.row.status === 'listed') g.listed++;
  }
  return [...groups.values()].sort((x, y) => (x.role === y.role ? (x.preference ?? 999) - (y.preference ?? 999) : x.role === 'web' ? -1 : 1));
}
