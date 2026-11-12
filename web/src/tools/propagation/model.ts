// Propagation page: shapes of the API (mirror of server/src/tools/propagation/{index,check,status}.ts)
// and the pure logic of the page: stream reducer, counts, grouping, sorting, filters, map spreading.
// Unit tested in model.test.ts.
import { locale, t } from '../../lib/i18n';

/**
 * rewritten: a non-public address (127.0.0.1, 0.0.0.0, RFC 1918) where the reference is public. The
 * resolver rewrites or blocks the name: not counted, not asked again, quarantined by the server.
 */
/**
 * regional: a different answer served by the same operator (same ASN) as the authoritative servers,
 * adapted to the resolver's region: up to date, without refresh time, never asked again.
 */
export type Status = 'fresh' | 'regional' | 'stale' | 'missing' | 'rewritten' | 'error' | 'timeout';
export type RowStatus = Status | 'pending';

export interface ResolverInfo {
  ip: string;
  name: string | null;
  provider: string | null;
  asn: number | null;
  country_code: string | null;
  continent: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  geoPrecision?: 'city' | 'country' | null;
  anycast: boolean;
  group: 'global' | 'local';
  filtering: string | null;
  dnssec: boolean | null;
  latencyMs: number | null;
  qualifiedAt?: string | null;
  source?: string | null;
}

export interface ResolverEvent extends ResolverInfo {
  status: Status;
  rcode: string | null;
  cname: string | null;
  values: string[];
  ttl: number | null;
  refreshAt: string | null;
  error?: string;
  geo: { authorityValues: string[]; authorityCname: string | null; scope: number; explained: boolean } | null;
  uncertain: boolean;
  /** Set with status regional: the operator shared with the authoritative servers. */
  regionalAsn?: { asn: number; name: string | null } | null;
  at: string;
}

export interface AuthorityServer {
  ns: string;
  ip: string;
  rcode: string | null;
  aa: boolean | null;
  cname: string | null;
  values: string[];
  ttl: number | null;
  serial: number | null;
  rtt: number | null;
  error: string | null;
}

export interface Reference {
  source: 'authority' | 'expected';
  exists: boolean;
  kind: 'records' | 'cname';
  values: string[];
  cname: string | null;
  match?: 'exact' | 'subset';
  ttl: number | null;
  serial: number | null;
  finalValues: string[];
  chain: string[];
}

export interface AuthorityEvent {
  zone: string;
  servers: AuthorityServer[];
  serials: number[];
  divergent: boolean;
  divergence: { answers: boolean; serials: boolean; dynamic: boolean; sameAnswerDifferentSerials: boolean };
  serialGroups: { serial: number; servers: string[] }[];
  reference: Reference;
  authority: { exists: boolean; cname: string | null; values: string[] };
  expectedMatchesAuthority: boolean | null;
  ms: number;
}

export interface StartEvent {
  name: string;
  type: string;
  expected: string | null;
  onlyPending: boolean;
  resolverCount: number;
  qualifiedAt: string | null;
  startedAt: string;
}

export interface DoneEvent {
  total: number;
  fresh: number;
  stale: number;
  missing: number;
  error: number;
  timeout: number;
  percentFresh: number | null;
  allFreshBy: string | null;
  pendingIps: string[];
  resultId?: string;
  startedAt: string;
  finishedAt: string;
  onlyPending: boolean;
}

export interface ResolversPayload {
  qualification: {
    status: string;
    startedAt: string;
    finishedAt: string;
    durationMs: number;
    tested: number;
    passed: number;
    qualified: number;
    qualifiedGlobal: number;
    qualifiedLocal: number;
    countries: number;
    dnssecValidating: number;
    failures: Record<string, number>;
    checkNames: string[];
    note: string | null;
    lastAttempt: { status: string; finishedAt: string; note: string | null } | null;
  } | null;
  running: { startedAt: string; manual: boolean; progress: { done?: number; total?: number; phase?: string } | null } | null;
  candidates: number;
  perCountry: number;
  serverLocation: { ip: string; country_code: string; city: string | null; lat: number | null; lon: number | null } | null;
  continents: Record<string, string>;
  global: { note: string; resolvers: ResolverInfo[] };
  countries: { country_code: string; continent: string | null; resolvers: ResolverInfo[] }[];
  total: number;
}

/* ---------- stream state ---------- */

export type Phase = 'idle' | 'connecting' | 'authority' | 'resolvers' | 'done' | 'error';

export interface RunState {
  phase: Phase;
  /** 0 for a full run, then 1, 2... for the rounds of the watch mode. */
  round: number;
  /** IPs asked in this round; null when every qualified resolver is asked. */
  scope: string[] | null;
  start?: StartEvent;
  authority?: AuthorityEvent;
  done?: DoneEvent;
  error?: { code: string; message: string };
  /** Latest answer of each resolver, kept across the rounds of the watch mode. */
  results: Record<string, ResolverEvent>;
  /** IPs that answered in the current round. */
  seen: Record<string, true>;
  /** Set when the authoritative reference changed between two rounds: everything must be asked again. */
  referenceChanged: boolean;
}

export const initialRun: RunState = { phase: 'idle', round: 0, scope: null, results: {}, seen: {}, referenceChanged: false };

export type RunAction =
  | { type: 'begin'; scope: string[] | null }
  | { type: 'start'; data: StartEvent }
  | { type: 'authority'; data: AuthorityEvent }
  | { type: 'resolvers'; data: ResolverEvent[] }
  | { type: 'done'; data: DoneEvent }
  | { type: 'error'; data: { code: string; message: string } };

/** What decides "up to date": two rounds with different signatures cannot be merged. */
export function referenceSig(a: AuthorityEvent | undefined): string {
  if (!a) return '';
  const r = a.reference;
  return JSON.stringify([r.source, r.exists, r.kind, r.cname, [...r.values].sort(), r.match ?? 'exact']);
}

/**
 * Decision of the coordinator (2026-11-10), applied before the engine ships it: a NXDOMAIN where the
 * authoritative servers have an answer is a rewritten (blocked) answer, not a late one. ("missing"
 * only reaches the client when the reference exists.) An empty NOERROR answer stays "missing".
 */
export function normalizeEvent(e: ResolverEvent): ResolverEvent {
  if (e.status === 'missing' && e.rcode === 'NXDOMAIN') return { ...e, status: 'rewritten', refreshAt: null };
  return e;
}

export function runReducer(s: RunState, a: RunAction): RunState {
  switch (a.type) {
    case 'begin':
      return a.scope
        ? { ...s, phase: 'connecting', round: s.round + 1, scope: a.scope, seen: {}, done: undefined, error: undefined, referenceChanged: false }
        : { ...initialRun, phase: 'connecting' };
    case 'start':
      return { ...s, start: a.data };
    case 'authority': {
      const changed = !!s.scope && !!s.authority && referenceSig(s.authority) !== referenceSig(a.data);
      return { ...s, phase: 'resolvers', authority: a.data, referenceChanged: changed };
    }
    case 'resolvers': {
      if (!a.data.length) return s;
      const results = { ...s.results };
      const seen = { ...s.seen };
      for (const raw of a.data) {
        const e = normalizeEvent(raw);
        results[e.ip] = e;
        seen[e.ip] = true;
      }
      return { ...s, results, seen };
    }
    case 'done':
      return { ...s, phase: 'done', done: a.data };
    case 'error':
      return { ...s, phase: 'error', error: a.data };
  }
}

/* ---------- rows ---------- */

export interface Row {
  info: ResolverInfo;
  ev?: ResolverEvent;
  /** Being asked again in the current round (watch mode): the previous answer is still shown. */
  remeasuring: boolean;
}

export const rowStatus = (r: Row): RowStatus => r.ev?.status ?? 'pending';

/** Merge the qualified list (skeleton rows) with the answers received. */
export function buildRows(list: ResolverInfo[], s: RunState): Row[] {
  const inRound = s.scope && s.phase !== 'done' && s.phase !== 'error' ? new Set(s.scope) : null;
  const seen = new Set<string>();
  const rows: Row[] = [];
  for (const info of list) {
    seen.add(info.ip);
    const ev = s.results[info.ip];
    rows.push({ info: ev ? { ...info, ...pickInfo(ev), geoPrecision: info.geoPrecision } : info, ev, remeasuring: !!ev && !!inRound?.has(info.ip) && !s.seen[info.ip] });
  }
  // answers from resolvers missing in the list (list read before a new qualification)
  for (const ev of Object.values(s.results)) if (!seen.has(ev.ip)) rows.push({ info: pickInfo(ev), ev, remeasuring: false });
  return rows;
}

function pickInfo(e: ResolverEvent): ResolverInfo {
  return {
    ip: e.ip, name: e.name, provider: e.provider, asn: e.asn, country_code: e.country_code, continent: e.continent, city: e.city,
    lat: e.lat, lon: e.lon, anycast: e.anycast, group: e.group, filtering: e.filtering, dnssec: e.dnssec, latencyMs: e.latencyMs,
  };
}

/** Flatten GET /api/propagation/resolvers into one list. */
export function resolverList(p: ResolversPayload | null | undefined): ResolverInfo[] {
  if (!p) return [];
  return [...p.global.resolvers, ...p.countries.flatMap((c) => c.resolvers)];
}

/* ---------- counts ---------- */

export interface Counts {
  total: number;
  fresh: number;
  /** Regional answers of the zone's own operator: up to date, counted with fresh in the percentages. */
  regional: number;
  stale: number;
  missing: number;
  /** Rewritten or blocked answers: outside every percentage. */
  rewritten: number;
  /** error + timeout */
  error: number;
  pending: number;
  answered: number;
  /** fresh / (fresh + stale + missing), one decimal; null when nobody answered. */
  percentFresh: number | null;
  /**
   * Same, leaving out the "uncertain" answers (a rotating or geographic zone may legitimately give
   * them): what the verdict shows, so that a legitimate answer never lowers it.
   */
  percentCertain: number | null;
  /** stale (not uncertain) + missing: what really is out of bounds. */
  late: number;
  uncertain: number;
  geoExplained: number;
}

export function countRows(rows: Row[]): Counts {
  const c: Counts = { total: rows.length, fresh: 0, regional: 0, stale: 0, missing: 0, rewritten: 0, error: 0, pending: 0, answered: 0, percentFresh: null, percentCertain: null, late: 0, uncertain: 0, geoExplained: 0 };
  for (const r of rows) {
    if (!r.ev) {
      c.pending++;
      continue;
    }
    const s = r.ev.status;
    if (s === 'timeout' || s === 'error') c.error++;
    else c[s]++;
    if (s === 'fresh' || s === 'regional' || s === 'stale' || s === 'missing') c.answered++;
    if (r.ev.uncertain && s === 'stale') c.uncertain++;
    if (r.ev.geo?.explained) c.geoExplained++;
  }
  const upToDate = c.fresh + c.regional;
  c.percentFresh = c.answered ? Math.round((upToDate / c.answered) * 1000) / 10 : null;
  const certain = c.answered - c.uncertain;
  c.percentCertain = certain ? Math.round((upToDate / certain) * 1000) / 10 : null;
  c.late = c.stale - c.uncertain + c.missing;
  return c;
}

/**
 * Latest refreshAt among the resolvers really late (stale or missing, uncertain ones left out):
 * when all should be up to date. null when nobody is really late.
 */
export function allFreshBy(rows: Row[]): string | null {
  let max: string | null = null;
  for (const r of rows) {
    const e = r.ev;
    if (e && !e.uncertain && (e.status === 'stale' || e.status === 'missing') && e.refreshAt && (!max || e.refreshAt > max)) max = e.refreshAt;
  }
  return max;
}

/** Resolvers to ask again in the watch mode: everything not up to date, failures included; rewriters are quarantined. */
const SETTLED: Status[] = ['fresh', 'regional', 'rewritten'];
export const pendingIps = (rows: Row[]) => rows.filter((r) => r.ev && !SETTLED.includes(r.ev.status)).map((r) => r.info.ip);

/**
 * Resolvers the watch mode asks again: the late ones (stale, missing) every round; a failure
 * (error, timeout) at most `maxFailures` rounds, then it is given up and named.
 */
export function watchTargets(rows: Row[], failures: Record<string, number>, maxFailures = 3): { ips: string[]; givenUp: string[] } {
  const ips: string[] = [];
  const givenUp: string[] = [];
  for (const r of rows) {
    const s = r.ev?.status;
    if (s === 'stale' || s === 'missing') ips.push(r.info.ip);
    else if (s === 'error' || s === 'timeout') ((failures[r.info.ip] ?? 0) < maxFailures ? ips : givenUp).push(r.info.ip);
  }
  return { ips, givenUp };
}

/**
 * The resolvers really late: stale or missing, not uncertain, and not serving an answer that other
 * resolvers have as up to date (that is a TTL-stretching cache or a regional answer, not a delay).
 */
export function realLate(rows: Row[]): ResolverEvent[] {
  const good = new Set(rows.filter((r) => r.ev && (r.ev.status === 'fresh' || r.ev.status === 'regional')).map((r) => answerKey(r.ev!)));
  return rows
    .map((r) => r.ev)
    .filter((e): e is ResolverEvent => !!e && !e.uncertain && (e.status === 'stale' || e.status === 'missing') && !(e.status === 'stale' && good.has(answerKey(e))));
}

export const answerKey = (e: Pick<ResolverEvent, 'cname' | 'values'>) => JSON.stringify([e.cname, [...e.values].sort()]);

export interface DistinctAnswer {
  key: string;
  cname: string | null;
  values: string[];
  count: number;
  fresh: number;
  regional: number;
  uncertain: number;
  ips: string[];
}

/** Distinct answers among those who answered (same rule as the server's summary), most frequent first. */
export function distinctAnswers(rows: Row[]): DistinctAnswer[] {
  const m = new Map<string, DistinctAnswer>();
  for (const r of rows) {
    const e = r.ev;
    if (!e || (e.status !== 'fresh' && e.status !== 'regional' && e.status !== 'stale' && e.status !== 'missing')) continue;
    const key = answerKey(e);
    const a = m.get(key) ?? { key, cname: e.cname, values: [...e.values].sort(), count: 0, fresh: 0, regional: 0, uncertain: 0, ips: [] };
    a.count++;
    if (e.status === 'fresh') a.fresh++;
    if (e.status === 'regional') a.regional++;
    if (e.uncertain) a.uncertain++;
    a.ips.push(e.ip);
    m.set(key, a);
  }
  return [...m.values()].sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

/* ---------- filters ---------- */

export type FilterId = 'all' | 'fresh' | 'regional' | 'stale' | 'missing' | 'rewritten' | 'error' | 'pending';

export function matchesFilter(r: Row, f: FilterId, answer?: string | null): boolean {
  if (answer && (!r.ev || answerKey(r.ev) !== answer)) return false;
  if (f === 'all') return true;
  const s = r.ev?.status;
  if (f === 'pending') return !r.ev;
  if (f === 'error') return s === 'error' || s === 'timeout';
  return s === f;
}

/* ---------- sorting and grouping ---------- */

export type SortKey = 'place' | 'name' | 'provider' | 'value' | 'ttl' | 'status' | 'latency';
export interface Sort {
  key: SortKey;
  dir: 'asc' | 'desc';
}

/** Severity first: what needs attention comes up. */
const STATUS_RANK: Record<RowStatus, number> = { stale: 0, missing: 1, rewritten: 2, error: 3, timeout: 4, regional: 5, fresh: 6, pending: 7 };

export const displayName = (i: ResolverInfo) => (i.name && i.name !== i.ip ? i.name : i.ip);

/** "PUBNIX2-ASN - PubNIX, Inc." becomes "PubNIX, Inc."; "AS12345 Orange" becomes "Orange". */
export function cleanProvider(p: string | null | undefined): string {
  if (!p) return '';
  const s = p.trim();
  // AS names read "HANDLE - Organisation": keep the organisation
  const parts = s.split(' - ');
  if (parts.length === 2 && parts[1].trim().length > 2) return parts[1].trim();
  return s.replace(/^AS\d+\s+/, '');
}

/** Remaining TTL in the resolver's cache now, from the TTL read at `at`. */
export function ttlLeft(e: Pick<ResolverEvent, 'ttl' | 'at'> | undefined, now = Date.now()): number | null {
  if (!e || e.ttl === null || e.ttl === undefined) return null;
  const elapsed = (now - new Date(e.at).getTime()) / 1000;
  return Math.max(0, Math.round(e.ttl - Math.max(0, elapsed)));
}

/** MX, SRV, CAA: by their leading number (preference, priority, flags), numerically; others as given. */
export function sortValues(values: string[]): string[] {
  if (values.length < 2 || !values.every((v) => /^\d+\s/.test(v))) return values;
  return [...values].sort((a, b) => parseInt(a, 10) - parseInt(b, 10) || a.localeCompare(b));
}

export function valueText(e: ResolverEvent | undefined): string {
  if (!e) return '';
  if (e.status === 'error' || e.status === 'timeout') return e.status === 'timeout' ? t('pas de réponse en 4 s') : e.rcode ?? e.error ?? t('erreur');
  if (e.cname && !e.values.length) return `→ ${e.cname}`;
  if (!e.values.length) return e.rcode === 'NXDOMAIN' ? 'NXDOMAIN' : t('aucune donnée');
  return (e.cname ? `→ ${e.cname}\n` : '') + sortValues(e.values).join('\n');
}

export function compareRows(a: Row, b: Row, key: SortKey): number {
  const pa = !a.ev;
  const pb = !b.ev;
  // skeleton rows stay at the end whatever the direction (handled by the caller for desc)
  if (pa !== pb && key !== 'name' && key !== 'provider' && key !== 'place') return pa ? 1 : -1;
  switch (key) {
    case 'status':
      return STATUS_RANK[rowStatus(a)] - STATUS_RANK[rowStatus(b)] || displayName(a.info).localeCompare(displayName(b.info));
    case 'latency':
      return (a.ev?.latencyMs ?? Infinity) - (b.ev?.latencyMs ?? Infinity);
    case 'ttl':
      return (a.ev?.ttl ?? -1) - (b.ev?.ttl ?? -1);
    case 'value':
      return valueText(a.ev).localeCompare(valueText(b.ev));
    case 'provider':
      return cleanProvider(a.info.provider).localeCompare(cleanProvider(b.info.provider), locale()) || a.info.ip.localeCompare(b.info.ip);
    case 'name':
    case 'place':
    default:
      return (a.info.city ?? '').localeCompare(b.info.city ?? '', locale()) || displayName(a.info).localeCompare(displayName(b.info), locale());
  }
}

export function sortRows(rows: Row[], sort: Sort): Row[] {
  const byName = sort.key === 'name' || sort.key === 'provider' || sort.key === 'place';
  const sorted = [...rows].sort((a, b) => compareRows(a, b, sort.key));
  if (byName) return sort.dir === 'desc' ? sorted.reverse() : sorted;
  // skeletons, and answers without the sorted value (no latency, no TTL), stay last both ways
  const missing = (r: Row) => !r.ev || (sort.key === 'latency' && r.ev.latencyMs === null) || (sort.key === 'ttl' && r.ev.ttl === null);
  const known = sorted.filter((r) => !missing(r));
  const rest = sorted.filter(missing);
  return [...(sort.dir === 'desc' ? known.reverse() : known), ...rest];
}

export interface CountryGroup {
  cc: string;
  name: string;
  rows: Row[];
  counts: Counts;
}
export interface ContinentGroup {
  code: string;
  name: string;
  countries: CountryGroup[];
  counts: Counts;
}

/** Continent, then country (French names, alphabetical), rows sorted inside each country. */
export function groupRows(rows: Row[], continents: Record<string, string>, countryName: (cc: string) => string, sort: Sort): ContinentGroup[] {
  const byCont = new Map<string, Map<string, Row[]>>();
  for (const r of rows) {
    const ct = r.info.continent ?? '??';
    const cc = r.info.country_code ?? '??';
    const m = byCont.get(ct) ?? new Map<string, Row[]>();
    m.set(cc, [...(m.get(cc) ?? []), r]);
    byCont.set(ct, m);
  }
  const contName = (c: string) => continents[c] ?? t('Autres');
  return [...byCont.entries()]
    .map(([code, m]) => {
      const countries = [...m.entries()]
        .map(([cc, rs]) => ({ cc, name: countryName(cc), rows: sortRows(rs, sort), counts: countRows(rs) }))
        .sort((a, b) => a.name.localeCompare(b.name, locale()));
      return { code, name: contName(code), countries, counts: countRows(countries.flatMap((c) => c.rows)) };
    })
    .sort((a, b) => (a.code === '??' ? 1 : b.code === '??' ? -1 : a.name.localeCompare(b.name, locale())));
}

/* ---------- map ---------- */

export interface MapPoint {
  ip: string;
  x: number;
  y: number;
}

/**
 * Resolvers placed at the same spot (same city, or the country centroid) would hide each other:
 * points closer than `r` are laid out on a small sunflower around their common centre.
 * Deterministic: the order inside a cluster is the IP order.
 */
export function spreadPoints(points: MapPoint[], r: number): MapPoint[] {
  if (r <= 0) return points;
  const clusters: { cx: number; cy: number; items: MapPoint[] }[] = [];
  const sorted = [...points].sort((a, b) => a.ip.localeCompare(b.ip));
  for (const p of sorted) {
    const c = clusters.find((k) => Math.hypot(k.cx - p.x, k.cy - p.y) < r);
    if (c) c.items.push(p);
    else clusters.push({ cx: p.x, cy: p.y, items: [p] });
  }
  const golden = Math.PI * (3 - Math.sqrt(5));
  const out: MapPoint[] = [];
  for (const c of clusters) {
    if (c.items.length === 1) {
      out.push(c.items[0]);
      continue;
    }
    c.items.forEach((p, i) => {
      const d = r * 1.15 * Math.sqrt(i + 0.5);
      out.push({ ip: p.ip, x: c.cx + d * Math.cos(i * golden), y: c.cy + d * Math.sin(i * golden) });
    });
  }
  return out;
}

/** Keyboard order of the map points: west to east, then north to south. */
export function keyboardOrder(points: MapPoint[]): string[] {
  return [...points].sort((a, b) => a.x - b.x || a.y - b.y).map((p) => p.ip);
}

/* ---------- URLs ---------- */

/** `where`: the selection query (scope, continents, regions, countries, family), for a full run only. */
export function streamUrl(name: string, type: string, expected: string | null, scope: string[] | null, where = ''): string {
  const p = new URLSearchParams({ name, type });
  if (expected?.trim()) p.set('expected', expected);
  if (scope) {
    p.set('onlyPending', '1');
    p.set('ips', scope.join(','));
  } else if (where) for (const [k, v] of new URLSearchParams(where)) p.set(k, v);
  return `/api/propagation/stream?${p.toString()}`;
}

/** Text for the "expected value" field: what the authoritative servers serve, one value per line. */
export function referenceText(a: AuthorityEvent | undefined): string {
  if (!a) return '';
  if (a.authority.cname && a.reference.kind === 'cname') return a.authority.cname;
  // a rotating or geographic zone: the whole pool the servers gave
  if (a.reference.match === 'subset' && a.reference.source === 'authority') return a.reference.values.join('\n');
  return sortValues(a.authority.values).join('\n');
}
