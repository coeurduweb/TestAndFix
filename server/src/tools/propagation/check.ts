// Live propagation check (US-055, US-056, US-057, US-060).
// 1. authority: every authoritative server of the zone is asked directly (RD=0), with its SOA serial.
// 2. resolver: every qualified resolver is asked (RD=1), one real query each, streamed as it answers.
// 3. done: summary by country and continent.
// Nothing is cached: each query is a new packet with a random id.
import { t } from '../../i18n.js';
import net from 'node:net';
import { query, type DnsResponse } from '../../dns/client.js';
import { ROOT_SERVERS, type ResolveSession } from '../../dns/iterative.js';
import { extract, formatRecord, host, normalizeExpected, sameValues, wireType, type PropType } from './normalize.js';
import type { AsnLookup } from './asn.js';
import { ecsQuery, type EcsResponse } from './ecs.js';
import { addTo, emptyCounts, observe, type Counts, type Observation, type Reference } from './status.js';
import { continentOf, familyOf, regionOf, type Candidate } from './store.js';
import { mapLimit, Semaphore } from './util.js';

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

export interface AuthorityEvent {
  zone: string;
  servers: AuthorityServer[];
  serials: number[];
  divergent: boolean;
  divergence: { answers: boolean; serials: boolean; dynamic: boolean; sameAnswerDifferentSerials: boolean };
  serialGroups: { serial: number; servers: string[] }[];
  reference: Reference & { ttl: number | null; serial: number | null; finalValues: string[]; chain: string[] };
  /** Authoritative answer as it stands, kept when `expected` replaces it as reference. */
  authority: { exists: boolean; cname: string | null; values: string[] };
  /** When `expected` is given: do the authoritative servers already serve it? */
  expectedMatchesAuthority: boolean | null;
  ms: number;
}

export interface ResolverEvent extends Observation {
  ip: string;
  name: string | null;
  provider: string | null;
  asn: number | null;
  country_code: string | null;
  continent: string | null;
  /** UN M49 sub-region, null for anycast. */
  region: { code: string; name: string } | null;
  family: 4 | 6;
  city: string | null;
  lat: number | null;
  lon: number | null;
  anycast: boolean;
  group: 'global' | 'local';
  filtering: string | null;
  dnssec: boolean | null;
  latencyMs: number | null;
  at: string;
  /**
   * Set when the answer differed and the authoritative servers were asked with this resolver's
   * /24 as client subnet (ECS). explained=true: the zone answers by location and this resolver
   * got what the zone gives its network, so it counts as fresh.
   */
  geo: { authorityValues: string[]; authorityCname: string | null; scope: number; explained: boolean } | null;
  /** stale in a zone that answers by location or rotation, not explained by the ECS check: may be a false alert. */
  uncertain: boolean;
  /** For status 'regional': the network shared by this answer and the authoritative one. */
  regionalAsn: { asn: number; name: string | null } | null;
  /** 2 when the first attempt timed out and this answer (or timeout) comes from the second one. */
  attempts: 1 | 2;
}

export interface Summary extends Counts {
  complete: boolean;
  global: Counts;
  local: Counts;
  byCountry: (Counts & { country_code: string; continent: string | null })[];
  byContinent: (Counts & { continent: string })[];
  byRegion: (Counts & { region: string; name: string })[];
  byFamily: (Counts & { family: 4 | 6 })[];
  /** Latest refreshAt among stale and missing resolvers: when all should be up to date. */
  allFreshBy: string | null;
  /** IPs not up to date (stale, missing, error, timeout): pass them back with onlyPending=1. */
  pendingIps: string[];
  /** stale results that may only be a location-dependent answer (see ResolverEvent.uncertain). */
  uncertain: number;
  /** stale results turned fresh by the ECS check (answer given by the zone to that network). */
  geoExplained: number;
  /** Resolvers asked twice (first attempt timed out), and those that answered the second time. */
  retried: number;
  answeredOnRetry: number;
  /** Distinct answers seen, most frequent first. */
  distinctAnswers: { cname: string | null; values: string[]; count: number; matchesReference: boolean }[];
}

export interface CheckInput {
  name: string;
  type: PropType;
  expected?: string;
}

export class CheckError extends Error {
  constructor(public code: string, message: string) {
    super(message);
  }
}

/** Validate and normalise the name; an IP with type PTR becomes its reverse name. */
export function normalizeName(raw: string, type: PropType): string {
  let n = raw.trim().toLowerCase().replace(/\.+$/, '');
  if (type === 'PTR' && net.isIP(n)) {
    if (net.isIPv4(n)) n = `${n.split('.').reverse().join('.')}.in-addr.arpa`;
    else {
      const full = n.includes('::') ? expandV6(n) : n.split(':').map((p) => p.padStart(4, '0')).join('');
      n = `${full.split('').reverse().join('.')}.ip6.arpa`;
    }
  }
  if (!n || n.length > 253 || !/^[a-z0-9_*]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$/.test(n)) {
    throw new CheckError('bad_name', t('Nom de domaine invalide'));
  }
  return n;
}

function expandV6(v: string): string {
  const [l, r] = v.split('::');
  const left = l ? l.split(':') : [];
  const right = r ? r.split(':') : [];
  const mid = Array(8 - left.length - right.length).fill('0');
  return [...left, ...mid, ...right].map((p) => p.padStart(4, '0')).join('');
}

/** Step 1: ask every authoritative server of the zone holding `name`. */
export async function checkAuthority(session: ResolveSession, input: CheckInput, signal?: AbortSignal): Promise<AuthorityEvent> {
  const t0 = performance.now();
  const wt = wireType(input.type);
  let full;
  try {
    full = await session.resolve(input.name, wt);
  } catch (e) {
    throw new CheckError('resolution_failed', t('La résolution de {name} depuis les serveurs racine a échoué ({code})', { name: input.name, code: (e as { code?: string }).code ?? t('erreur') }));
  }
  // zone that holds the name itself (first non-referral step, before any CNAME)
  const step = full.trace.find((s) => s.outcome !== 'referral' && s.outcome !== 'error');
  const zoneOfName = step?.zone ?? full.zone;
  if (!zoneOfName) throw new CheckError('no_zone', t('Aucune zone trouvée pour {name}', { name: input.name }));
  // the root zone (DS of a TLD) is served by the 13 root servers
  const { zone, servers } =
    zoneOfName === '.'
      ? { zone: '.', servers: Object.entries(ROOT_SERVERS).map(([name, ip]) => ({ name, ips: [ip] })) }
      : await session.findAuthorities(zoneOfName);

  const targets = servers.flatMap((s) => (s.ips.length ? s.ips.filter((ip) => net.isIPv4(ip)).map((ip) => ({ ns: s.name, ip })) : [{ ns: s.name, ip: '' }]));
  const results: AuthorityServer[] = await Promise.all(
    targets.map(async ({ ns, ip }) => {
      if (!ip) return { ns, ip, rcode: null, aa: null, cname: null, values: [], ttl: null, serial: null, rtt: null, error: t('adresse du serveur introuvable') };
      const [ans, soa] = await Promise.allSettled([
        query(ip, input.name, wt, { rd: false, timeoutMs: 3000, signal }),
        query(ip, zone, 'SOA', { rd: false, timeoutMs: 3000, signal }),
      ]);
      const serialOf = (r: PromiseSettledResult<DnsResponse>) => {
        if (r.status !== 'fulfilled') return null;
        const s = r.value.answers.find((a) => a.type === 'SOA');
        return s ? Number((s.data as { serial: number }).serial) : null;
      };
      if (ans.status !== 'fulfilled') {
        const e = ans.reason as { code?: string; message?: string };
        return { ns, ip, rcode: null, aa: null, cname: null, values: [], ttl: null, serial: serialOf(soa), rtt: null, error: e?.code === 'ETIMEOUT' ? 'timeout' : String(e?.message ?? e) };
      }
      const r = ans.value;
      const x = extract(input.type, input.name, r.answers, r.authorities);
      const bad = !['NOERROR', 'NXDOMAIN'].includes(r.rcode) || !r.flags.aa;
      return {
        ns,
        ip,
        rcode: r.rcode,
        aa: r.flags.aa,
        cname: x.cname,
        values: x.values,
        ttl: x.cname || x.values.length ? x.ttl : x.negativeTtl,
        serial: serialOf(soa),
        rtt: r.rtt,
        error: bad ? (r.flags.aa ? r.rcode : t('réponse non autoritaire ({rcode})', { rcode: r.rcode })) : null,
      };
    }),
  );

  const ok = results.filter((r) => !r.error);
  // an alias is compared on its target only: the in-zone records behind it may rotate
  const sig = (r: AuthorityServer) =>
    JSON.stringify(r.cname !== null && input.type !== 'CNAME' ? ['C', r.cname] : [r.rcode === 'NXDOMAIN' ? 'NX' : '', r.values]);
  const groups = new Map<string, AuthorityServer[]>();
  for (const r of ok) groups.set(sig(r), [...(groups.get(sig(r)) ?? []), r]);
  const serials = [...new Set(ok.map((r) => r.serial).filter((s): s is number => s != null))].sort((a, b) => b - a);
  // reference: the group served by the highest serial (the newest zone), then the largest group
  const ranked = [...groups.values()].sort(
    (a, b) => Math.max(...b.map((r) => r.serial ?? -1)) - Math.max(...a.map((r) => r.serial ?? -1)) || b.length - a.length,
  );
  const best = ranked[0]?.[0];
  // Same serial, different answers: the zone answers dynamically (round robin subsets, weighted
  // or geo routing). Then any non-empty subset of what the servers gave counts as up to date.
  // Different serials with different answers is an update in progress: the newest serial wins.
  const bySerial = new Map<number, Set<string>>();
  for (const r of ok) if (r.serial != null) bySerial.set(r.serial, (bySerial.get(r.serial) ?? new Set()).add(sig(r)));
  const dynamic =
    groups.size > 1 && [...bySerial.values()].some((g) => g.size > 1) && ok.every((r) => r.cname === null && r.values.length > 0);
  const unionSet = new Set(ok.flatMap((r) => r.values));
  if (dynamic) {
    // rotating answers: ask each server twice more to see more of the pool
    await Promise.all(
      ok.flatMap((r) => [0, 1].map(async () => {
        try {
          const again = await query(r.ip, input.name, wt, { rd: false, timeoutMs: 3000, signal });
          for (const v of extract(input.type, input.name, again.answers).values) unionSet.add(v);
        } catch {
          /* the first answer is enough */
        }
      })),
    );
  }
  const union = [...unionSet].sort();
  const serialGroups = [...bySerial.keys()]
    .sort((a, b) => b - a)
    .map((serial) => ({ serial, servers: [...new Set(ok.filter((r) => r.serial === serial).map((r) => r.ns))] }));
  if (!best && !input.expected) throw new CheckError('no_authority', t('Aucun serveur autoritaire n’a répondu'));

  const authExists = !!best && (best.cname !== null || best.values.length > 0);
  const authority = { exists: authExists, cname: best?.cname ?? null, values: best?.values ?? [] };
  // values at the end of the chain, from the iterative resolution (also authoritative)
  const finalValues = [...new Set(full.answers.filter((a) => a.type === wt).map((a) => formatRecord(input.type, a.data)))].sort();

  let reference: Reference;
  let expectedMatchesAuthority: boolean | null = null;
  if (input.expected?.trim()) {
    const exp = normalizeExpected(input.type, input.expected);
    const aliasExpected = (input.type === 'A' || input.type === 'AAAA') && exp.length === 1 && !net.isIP(exp[0]) && /[a-z]/.test(exp[0]);
    reference = aliasExpected
      ? { source: 'expected', exists: true, kind: 'cname', values: [], cname: host(exp[0]) }
      : { source: 'expected', exists: exp.length > 0, kind: 'records', values: exp, cname: null };
    if (best) {
      expectedMatchesAuthority =
        reference.kind === 'cname'
          ? best.cname === reference.cname
          : sameValues(input.type, best.cname !== null && input.type !== 'CNAME' ? finalValues : best.values, reference.values);
    }
  } else if (best && best.cname !== null && input.type !== 'CNAME') {
    reference = { source: 'authority', exists: true, kind: 'cname', values: finalValues, cname: best.cname };
  } else {
    reference = dynamic
      ? { source: 'authority', exists: true, kind: 'records', values: union, cname: null, match: 'subset' }
      : { source: 'authority', exists: authExists, kind: 'records', values: best?.values ?? [], cname: null };
  }

  return {
    zone,
    servers: results,
    serials,
    divergent: groups.size > 1 || serials.length > 1,
    divergence: {
      answers: groups.size > 1,
      serials: serials.length > 1,
      dynamic,
      // same answer everywhere but several serials: usually two DNS providers numbering the zone
      // each in its own way (seen on github.com: AWS serial 1, NS1 serial 1656468023)
      sameAnswerDifferentSerials: groups.size === 1 && serials.length > 1,
    },
    serialGroups,
    reference: { ...reference, ttl: best?.ttl ?? null, serial: serials[0] ?? null, finalValues, chain: full.cnames },
    authority,
    expectedMatchesAuthority,
    ms: Math.round(performance.now() - t0),
  };
}

/** Step 2: ask each resolver once, calling `onResult` as answers arrive. */
export async function checkResolvers(
  input: CheckInput,
  reference: Reference,
  resolvers: Candidate[],
  onResult: (e: ResolverEvent) => void,
  opts: {
    /** Resolvers asked at the same time (default 100, see LIVE_CONCURRENCY). */
    concurrency?: number;
    /** First attempt (default 4 s). */
    timeoutMs?: number;
    /** Second attempt for the first-attempt timeouts, after the first pass (default 6 s; 0 disables). */
    retryTimeoutMs?: number;
    signal?: AbortSignal;
    authorityIps?: string[];
    port?: number;
    /** Origin ASN lookups for the regional test (Team Cymru through the action's session). */
    asn?: AsnLookup;
    /** TTL of the authoritative answer: a regional answer never has a longer one. */
    referenceTtl?: number | null;
    /** Authoritative step, to tell an NXDOMAIN lie from a negative cache. */
    authority?: AuthorityEvent;
  } = {},
): Promise<ResolverEvent[]> {
  const wt = wireType(input.type);
  const out: ResolverEvent[] = [];
  const auths = opts.authorityIps?.filter((ip) => net.isIPv4(ip)) ?? [];
  let next = 0;
  let refAsns: Promise<Set<number>> | null = null;
  const referenceAsns = () =>
    (refAsns ??= Promise.all(reference.values.map((v) => opts.asn!.asnsOf(v))).then((l) => new Set(l.flat())));
  const retryMs = opts.retryTimeoutMs ?? 6000;
  const retry: Candidate[] = [];
  const ask = (r: Candidate, timeoutMs: number) =>
    // every live check shares one budget of packets in flight: two streams opened together
    // must not add up to a burst (448 at once lost 216 to 306 answers, see LIVE_CONCURRENCY)
    liveSlots.run(async () => {
      try {
        return { res: await query(r.ip, input.name, wt, { rd: true, timeoutMs, port: opts.port, signal: opts.signal }), err: undefined };
      } catch (e) {
        return { res: null, err: e };
      }
    });
  const isTimeout = (e: unknown) => (e as { code?: string } | undefined)?.code === 'ETIMEOUT';
  // Pass 1: every resolver once. A timeout is not reported yet: it is asked again in pass 2,
  // a few seconds later and with a longer wait (intermittent or rate-limiting resolvers).
  // Pass 2: only the timeouts; the event says `attempts: 2`.
  const pass = async (list: Candidate[], attempt: 1 | 2) =>
    mapLimit(
      list,
      opts.concurrency ?? LIVE_CONCURRENCY,
      async (r) => {
        const { res, err } = await ask(r, attempt === 1 ? (opts.timeoutMs ?? 4000) : retryMs);
        if (opts.signal?.aborted) return;
        if (attempt === 1 && !res && isTimeout(err) && retryMs > 0) {
          retry.push(r);
          return;
        }
        await finish(r, res, err, attempt);
      },
      opts.signal,
    );
  const finish = async (r: Candidate, res: DnsResponse | null, err: unknown, attempts: 1 | 2) => {
    {
      let obs: Observation = observe(input.type, input.name, reference, res, err);
      if (obs.status === 'missing' && res?.rcode === 'NXDOMAIN' && opts.authority && isNxLie(res, opts.authority)) {
        obs = { ...obs, status: 'rewritten', reason: 'nxdomain_lie', refreshAt: null };
      }
      let geo: ResolverEvent['geo'] = null;
      // A different answer from a unicast resolver: ask the authoritative servers what they give
      // to that resolver's network. Equal means a geographic answer, not an outdated one.
      if (obs.status === 'stale' && res && !r.anycast && reference.source === 'authority' && reference.exists && auths.length) {
        const answers: EcsResponse[] = [];
        for (let i = 0; i < 2; i++) {
          try {
            answers.push(await ecsQuery(auths[next++ % auths.length], input.name, wt, r.ip, { timeoutMs: 2000, signal: opts.signal }));
          } catch {
            /* unexplained, stays stale */
          }
        }
        geo = ecsVerdict(input.type, input.name, reference, res, answers);
        if (geo?.explained) obs = { ...observe(input.type, input.name, { ...reference, cname: geo.authorityCname, values: geo.authorityValues, match: 'subset' }, res), refreshAt: null };
      }
      // Still different: a CDN answering by region gives addresses of the same network as ours.
      let regionalAsn: ResolverEvent['regionalAsn'] = null;
      if (
        obs.status === 'stale' &&
        opts.asn &&
        (input.type === 'A' || input.type === 'AAAA') &&
        reference.source === 'authority' &&
        reference.kind === 'records' &&
        reference.exists &&
        obs.cname === null &&
        obs.values.length > 0 &&
        obs.ttl != null &&
        opts.referenceTtl != null &&
        obs.ttl <= opts.referenceTtl
      ) {
        const ours = await referenceAsns();
        const per = await Promise.all(obs.values.map((v) => opts.asn!.asnsOf(v)));
        const common = [...ours].find((asn) => per.every((l) => l.includes(asn)));
        if (common != null) {
          regionalAsn = { asn: common, name: await opts.asn.nameOf(common) };
          obs = { ...obs, status: 'regional', refreshAt: null };
        }
      }
      const ev: ResolverEvent = {
        ip: r.ip,
        name: r.name,
        provider: r.provider,
        asn: r.asn,
        country_code: r.country_code,
        continent: continentOf(r.country_code),
        region: r.anycast ? null : regionOf(r.country_code),
        family: familyOf(r.ip),
        city: r.city,
        lat: r.anycast ? null : r.lat,
        lon: r.anycast ? null : r.lon,
        anycast: !!r.anycast,
        group: r.anycast ? 'global' : 'local',
        filtering: r.filtering,
        dnssec: r.dnssec == null ? null : !!r.dnssec,
        ...obs,
        geo,
        uncertain: obs.status === 'stale' && reference.match === 'subset',
        regionalAsn,
        latencyMs: res?.rtt ?? null,
        attempts,
        at: new Date().toISOString(),
      };
      out.push(ev);
      onResult(ev);
    }
  };
  await pass(resolvers, 1);
  if (retry.length && !opts.signal?.aborted) await pass(retry, 2);
  return out;
}

/**
 * Live check parallelism. Measured on 2026-11-11 from the dev machine, example.com A, 448
 * qualified resolvers, twice each: 448 at once -> 306 and 273 timeouts in 4 s; 100 -> 182 and 184
 * in 8.7 s; 50 -> 186 and 180 in 17 s; 25 -> 188 and 172 in 31 to 33 s. Below 100 the loss does
 * not move (it comes from the resolvers, about 27 % already in a serial test that night) and
 * the check gets slower. CHECK_PROPAGATION_LIVE_CONCURRENCY overrides it.
 */
export const LIVE_CONCURRENCY = (() => {
  const v = process.env.CHECK_PROPAGATION_LIVE_CONCURRENCY;
  return v && /^\d+$/.test(v) ? Math.max(1, Math.min(Number(v), 400)) : 100;
})();
/** Shared by all live checks of this process. */
export const liveSlots = new Semaphore(LIVE_CONCURRENCY);

/**
 * Conclusion of the ECS re-check. Only NOERROR/NXDOMAIN answers with a non-zero scope count:
 * FORMERR or NOTIMP mean the server does not take ECS (some refuse any EDNS option), and a zero
 * scope means the answer does not depend on the subnet. Either way: no conclusion (null).
 */
export function ecsVerdict(t: PropType, name: string, reference: Reference, res: DnsResponse, answers: EcsResponse[]): ResolverEvent['geo'] {
  const usable = answers.filter((e) => (e.rcode === 'NOERROR' || e.rcode === 'NXDOMAIN') && (e.scope ?? 0) > 0);
  if (!usable.length) return null;
  let cname: string | null = null;
  const values = new Set<string>();
  for (const e of usable) {
    const x = extract(t, name, e.answers, e.authorities);
    cname ??= x.cname;
    for (const v of x.values) values.add(v);
  }
  const authorityValues = [...values].sort();
  const again = observe(t, name, { ...reference, cname, values: authorityValues, match: 'subset' }, res);
  return { authorityValues, authorityCname: cname, scope: Math.max(...usable.map((e) => e.scope ?? 0)), explained: again.status === 'fresh' };
}

/**
 * NXDOMAIN from a resolver is a lie when every authoritative server answered with data AND the
 * negative answer cannot come from an older version of the zone: no SOA at all, a SOA of another
 * zone, or a serial newer than the zone's. A SOA of the zone with an older serial (or the same:
 * Route 53 always serves serial 1) is a negative cache from before a creation: 'missing'.
 * Seen on 2026-11-10: 103.84.132.2 sends a forged "com." SOA serial 1, 94.26.221.100 no SOA.
 */
export function isNxLie(res: DnsResponse, authority: AuthorityEvent): boolean {
  const servers = authority.servers;
  if (!servers.length || !servers.every((s) => !s.error && s.rcode !== 'NXDOMAIN' && (s.cname !== null || s.values.length > 0))) return false;
  const soa = res.authorities.find((a) => a.type === 'SOA');
  if (!soa) return true;
  if (host(soa.name) !== host(authority.zone)) return true;
  const serial = Number((soa.data as { serial?: number }).serial);
  return authority.serials.length > 0 && serial > authority.serials[0];
}

/**
 * Called after the resolvers when the zone serial changed during the measurement: a creation may
 * be in progress, so NXDOMAIN lies become 'missing' again. Returns the events changed (to resend).
 */
export function revalidateNxLies(events: ResolverEvent[], serialChanged: boolean, at = Date.now()): ResolverEvent[] {
  if (!serialChanged) return [];
  const changed = events.filter((e) => e.status === 'rewritten' && e.reason === 'nxdomain_lie');
  for (const e of changed) {
    e.status = 'missing';
    e.reason = undefined;
    e.refreshAt = e.ttl != null ? new Date(at + e.ttl * 1000).toISOString() : null;
  }
  return changed;
}

/** Step 3. */
export function summarize(events: ResolverEvent[], reference: Reference): Summary {
  const total = emptyCounts();
  const global = emptyCounts();
  const local = emptyCounts();
  const countries = new Map<string, Counts & { country_code: string; continent: string | null }>();
  const conts = new Map<string, Counts & { continent: string }>();
  const regs = new Map<string, Counts & { region: string; name: string }>();
  const fams = new Map<number, Counts & { family: 4 | 6 }>();
  const answers = new Map<string, { cname: string | null; values: string[]; count: number; matchesReference: boolean }>();
  let allFreshBy: string | null = null;
  for (const e of events) {
    addTo(total, e.status);
    addTo(e.anycast ? global : local, e.status);
    const fam = (e.family ?? 4) as 4 | 6;
    const fc = fams.get(fam) ?? { ...emptyCounts(), family: fam };
    addTo(fc, e.status);
    fams.set(fam, fc);
    if (!e.anycast && e.country_code) {
      const c = countries.get(e.country_code) ?? { ...emptyCounts(), country_code: e.country_code, continent: e.continent };
      addTo(c, e.status);
      countries.set(e.country_code, c);
      const k = e.continent ?? '??';
      const ct = conts.get(k) ?? { ...emptyCounts(), continent: k };
      addTo(ct, e.status);
      conts.set(k, ct);
      if (e.region) {
        const rg = regs.get(e.region.code) ?? { ...emptyCounts(), region: e.region.code, name: e.region.name };
        addTo(rg, e.status);
        regs.set(e.region.code, rg);
      }
    }
    if (e.refreshAt && (!allFreshBy || e.refreshAt > allFreshBy)) allFreshBy = e.refreshAt;
    if (e.status === 'fresh' || e.status === 'regional' || e.status === 'stale' || e.status === 'missing') {
      const k = JSON.stringify([e.cname, e.values]);
      const a = answers.get(k) ?? { cname: e.cname, values: e.values, count: 0, matchesReference: e.status === 'fresh' };
      a.count++;
      answers.set(k, a);
    }
  }
  void reference;
  return {
    ...total,
    complete: total.total > 0 && total.fresh + total.regional === total.total,
    global,
    local,
    byCountry: [...countries.values()].sort((a, b) => a.country_code.localeCompare(b.country_code)),
    byContinent: [...conts.values()].sort((a, b) => a.continent.localeCompare(b.continent)),
    byRegion: [...regs.values()].sort((a, b) => a.region.localeCompare(b.region)),
    byFamily: [...fams.values()].sort((a, b) => a.family - b.family),
    allFreshBy,
    // rewritten resolvers are quarantined: asking them again is pointless
    pendingIps: events.filter((e) => e.status !== 'fresh' && e.status !== 'regional' && e.status !== 'rewritten').map((e) => e.ip),
    uncertain: events.filter((e) => e.uncertain).length,
    geoExplained: events.filter((e) => e.geo?.explained).length,
    retried: events.filter((e) => e.attempts === 2).length,
    answeredOnRetry: events.filter((e) => e.attempts === 2 && e.status !== 'timeout').length,
    distinctAnswers: [...answers.values()].sort((a, b) => b.count - a.count),
  };
}
