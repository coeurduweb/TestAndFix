// Daily qualification of candidate resolvers (US-058).
//
// A candidate is shown only if, today, from this server:
//   (a) it answers the check names exactly like the authoritative truth fetched at the same time
//       by a ResolveSession (truth read before AND after each round, either is accepted);
//   (b) it answers NXDOMAIN for a random label under .com (a TLD without wildcard);
//   (c) it passes (a) on 3 rounds out of 3, at least 1 s apart;
//   (d) its median latency is at most 600 ms; its RA flag is set.
// DNSSEC (SERVFAIL on dnssec-failed.org) is recorded, never eliminating.
// Then at most N per country (distinct ASN, DNSSEC first, then latency) and, for anycast
// services, at most one address per provider.
//
// Check names: their answer must not depend on where the resolver is. Measured on 2026-11-10
// against 8 resolvers on 4 continents (Google, Cloudflare, Quad9, Yandex, a Russian, a Zambian
// and a Korean ISP): identical to the authoritative answer everywhere. example.com is NOT usable:
// 549 resolvers got another view of it (see research/resolveurs.md).
import net from 'node:net';
import type { DnsResponse } from '../../dns/client.js';
import { query } from '../../dns/client.js';
import type { ResolveSession } from '../../dns/iterative.js';
import { formatRecord, wireType, type PropType } from './normalize.js';
import type { GeoPoint } from './geo.js';
import type { Candidate, Outcome, ServerLocation } from './store.js';
import type { CheckId } from './types.js';
import { distanceKm, mapLimit, median, minRttMs, randomLabel } from './util.js';
import { hasNonPublic } from './addresses.js';

export const CHECK_NAMES: { name: string; type: PropType }[] = [
  { name: 'a.root-servers.net', type: 'A' }, // root-servers.net zone, TTL 41 days, never geolocated
  { name: '_dmarc.ietf.org', type: 'TXT' }, // TTL 300: the resolver must have fetched it recently
  { name: '_dmarc.ripe.net', type: 'TXT' },
];
export const DNSSEC_BROKEN_NAME = 'dnssec-failed.org';

/**
 * Rewrite test: names whose real answer is public. A non-public address (127.0.0.1, 0.0.0.0,
 * RFC 1918…) or NXDOMAIN eliminates the resolver (`rewrites_answers`). Only the range is
 * checked, not the exact value: example.com has other views in some countries (research).
 * Seen live: 192.172.250.8 answered 127.0.0.1 for example.com and passed the other tests.
 */
export const REWRITE_NAMES: { name: string; type: PropType }[] = [
  { name: 'example.com', type: 'A' },
  { name: 'example.com', type: 'AAAA' },
  { name: 'example.org', type: 'A' },
];
/**
 * Filtering marker, positive only. Cloudflare documents *.testcategory.com as test domains for its
 * filters. Measured 2026-11-10: blocked (0.0.0.0) by 1.1.1.2 and 1.1.1.3 only; Quad9, AdGuard,
 * CleanBrowsing, SafeDNS, Control D and DNS4EU resolve it. So a block proves filtering, a normal
 * answer proves nothing: it never marks a resolver as unfiltered and never eliminates it.
 * No list of block page addresses is used: none was verified (DNS4EU answered 51.15.69.11 for
 * phishing.testcategory.com, a public address that we cannot tell from a real answer).
 */
export const FILTER_TEST_NAME = 'malware.testcategory.com';

export interface Progress {
  phase: string;
  done: number;
  total: number;
}

export interface QualifyOptions {
  dns: () => ResolveSession;
  concurrency?: number;
  timeoutMs?: number;
  rounds?: number;
  roundGapMs?: number;
  /** Destination port of every query (tests with a local resolver; 53 otherwise). */
  port?: number;
  /** Pause between two queries to the same resolver inside a round. */
  queryGapMs?: number;
  maxLatencyMs?: number;
  perCountry?: number;
  perProvider?: number;
  /** false when this server has no outgoing IPv6: IPv6 candidates are skipped, not failed. */
  ipv6Available?: boolean;
  /** false disables runtime geolocation (tests). */
  geolocate?: ((ip: string) => Promise<GeoPoint | null>) | false;
  serverLocation?: ServerLocation | null;
  signal?: AbortSignal;
  onProgress?: (p: Progress) => void;
}

export interface QualifyResult {
  outcomes: Outcome[];
  tested: number;
  skippedQuarantine: number;
  passed: number;
  failures: Record<string, number>;
  /** Truth fetched per round, for the record. */
  truth: Record<string, string[]>;
}

type Truth = Map<string, string[]>;
const key = (n: { name: string; type: string }) => `${n.name}|${n.type}`;

async function fetchTruth(dns: () => ResolveSession): Promise<Truth> {
  const s = dns();
  const t: Truth = new Map();
  await Promise.all(
    CHECK_NAMES.map(async (c) => {
      try {
        const r = await s.resolve(c.name, wireType(c.type));
        const values = r.answers.filter((a) => a.type === wireType(c.type)).map((a) => formatRecord(c.type, a.data));
        if (r.rcode === 'NOERROR' && values.length) t.set(key(c), [...new Set(values)].sort());
      } catch {
        /* this name is skipped for the round */
      }
    }),
  );
  return t;
}

interface RoundRaw {
  fail?: CheckId;
  rtts: number[];
  /** canonical values per check name */
  seen: Map<string, string[]>;
  nxLie?: boolean;
  dnssec?: boolean | null;
  rewrite?: boolean;
  filtering?: string | null;
}

function classify(res: DnsResponse): CheckId | null {
  if (res.rcode === 'REFUSED') return 'refused';
  if (res.rcode === 'SERVFAIL') return 'servfail';
  if (res.rcode !== 'NOERROR') return 'wrong_answer';
  if (!res.flags.ra) return 'no_recursion';
  return null;
}

const pause = (ms: number) => (ms > 0 ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve());

async function runRound(
  ip: string,
  first: boolean,
  names: { name: string; type: PropType }[],
  o: { timeoutMs: number; queryGapMs: number; port?: number; signal?: AbortSignal; rewriteExists: Set<string>; filterPublic: boolean },
): Promise<RoundRaw> {
  const raw: RoundRaw = { rtts: [], seen: new Map() };
  for (const [i, c] of names.entries()) {
    if (i > 0) await pause(o.queryGapMs);
    let res: DnsResponse;
    try {
      res = await query(ip, c.name, wireType(c.type), { timeoutMs: o.timeoutMs, port: o.port, signal: o.signal });
    } catch {
      raw.fail = 'no_answer';
      return raw;
    }
    const bad = classify(res);
    if (bad) {
      raw.fail = bad;
      return raw;
    }
    raw.rtts.push(res.rtt);
    const values = res.answers.filter((a) => a.type === wireType(c.type) && a.name.toLowerCase().replace(/\.$/, '') === c.name).map((a) => formatRecord(c.type, a.data));
    raw.seen.set(key(c), [...new Set(values)].sort());
  }
  if (first) {
    await pause(o.queryGapMs);
    try {
      const nx = await query(ip, `${randomLabel()}.com`, 'A', { timeoutMs: o.timeoutMs, port: o.port, signal: o.signal });
      if (nx.rcode !== 'NXDOMAIN') raw.nxLie = nx.rcode === 'NOERROR';
      if (nx.rcode !== 'NXDOMAIN' && nx.rcode !== 'NOERROR') raw.fail = 'unstable';
    } catch {
      raw.fail = 'unstable';
      return raw;
    }
    await pause(o.queryGapMs);
    try {
      const d = await query(ip, DNSSEC_BROKEN_NAME, 'A', { timeoutMs: o.timeoutMs, port: o.port, signal: o.signal });
      raw.dnssec = d.rcode === 'SERVFAIL' ? true : d.rcode === 'NOERROR' ? false : null;
    } catch {
      raw.dnssec = null;
    }
    for (const c of REWRITE_NAMES) {
      await pause(o.queryGapMs);
      try {
        const r = await query(ip, c.name, wireType(c.type), { timeoutMs: o.timeoutMs, port: o.port, signal: o.signal });
        const values = r.answers.filter((a) => a.type === c.type).map((a) => formatRecord(c.type, a.data));
        if (hasNonPublic(values) || (r.rcode === 'NXDOMAIN' && o.rewriteExists.has(key(c)))) raw.rewrite = true;
      } catch {
        /* a timeout here says nothing about rewriting */
      }
    }
    raw.filtering = null;
    if (o.filterPublic) {
      await pause(o.queryGapMs);
      try {
        const r = await query(ip, FILTER_TEST_NAME, 'A', { timeoutMs: o.timeoutMs, port: o.port, signal: o.signal });
        const values = r.answers.filter((a) => a.type === 'A').map((a) => formatRecord('A', a.data));
        // only a non-public answer (0.0.0.0, 127.0.0.1…) counts: NXDOMAIN or REFUSED were seen
        // once on 62.217.77.45, which answers normally when asked again (false mark, 2026-11-10)
        if (hasNonPublic(values)) raw.filtering = 'malware';
      } catch {
        /* unknown */
      }
    }
  }
  return raw;
}

/** Which rewrite names exist, and whether the filter test name has a public answer, right now. */
async function rewriteTruth(dns: () => ResolveSession): Promise<{ rewriteExists: Set<string>; filterPublic: boolean }> {
  const s = dns();
  const rewriteExists = new Set<string>();
  await Promise.all(
    REWRITE_NAMES.map(async (c) => {
      try {
        const r = await s.resolve(c.name, wireType(c.type));
        if (r.rcode === 'NOERROR' && r.answers.some((a) => a.type === c.type)) rewriteExists.add(key(c));
      } catch {
        /* unknown: NXDOMAIN from a resolver will not count */
      }
    }),
  );
  let filterPublic = false;
  try {
    const r = await s.resolve(FILTER_TEST_NAME, 'A');
    const values = r.answers.filter((a) => a.type === 'A').map((a) => String(a.data));
    filterPublic = values.length > 0 && !hasNonPublic(values);
  } catch {
    /* test skipped */
  }
  return { rewriteExists, filterPublic };
}

const sameList = (a: string[] | undefined, b: string[] | undefined) => !!a && !!b && a.length === b.length && a.every((v, i) => v === b[i]);

/** Test candidates (network) and pick the ones to show. Pure with respect to the database. */
export async function qualify(list: Candidate[], opts: QualifyOptions, at = Date.now()): Promise<QualifyResult> {
  const o = {
    concurrency: Math.min(opts.concurrency ?? 100, 100),
    timeoutMs: opts.timeoutMs ?? 2000,
    rounds: opts.rounds ?? 3,
    roundGapMs: opts.roundGapMs ?? 1000,
    queryGapMs: opts.queryGapMs ?? 0,
    maxLatencyMs: opts.maxLatencyMs ?? 600,
    perCountry: opts.perCountry ?? 4,
    perProvider: opts.perProvider ?? 1,
  };
  const progress = (phase: string, done: number, total: number) => opts.onProgress?.({ phase, done, total });

  const noV6 = opts.ipv6Available === false;
  const skippedV6 = noV6 ? list.filter((c) => net.isIPv6(c.ip)) : [];
  const usable = noV6 ? list.filter((c) => !net.isIPv6(c.ip)) : list;
  const quarantined = usable.filter((c) => c.quarantined_until != null && c.quarantined_until > at);
  const toTest = usable.filter((c) => !(c.quarantined_until != null && c.quarantined_until > at));
  const state = new Map<string, { fail?: CheckId; rtts: number[]; nxLie?: boolean; dnssec: boolean | null; rewrite?: boolean; filtering?: string | null }>();
  for (const c of toTest) state.set(c.ip, { rtts: [], dnssec: null });

  const truthLog: Record<string, string[]> = {};
  const refs = await rewriteTruth(opts.dns);
  let survivors = toTest;
  for (let round = 1; round <= o.rounds && survivors.length; round++) {
    if (opts.signal?.aborted) throw new Error('aborted');
    const started = Date.now();
    const before = await fetchTruth(opts.dns);
    if (before.size === 0) throw new Error('truth_unavailable: no check name could be resolved from the root');
    const names = CHECK_NAMES.filter((c) => before.has(key(c)));
    let done = 0;
    const raws = await mapLimit(
      survivors,
      o.concurrency,
      async (c) => {
        const r = await runRound(c.ip, round === 1, names, {
          timeoutMs: o.timeoutMs,
          queryGapMs: o.queryGapMs,
          port: opts.port,
          signal: opts.signal,
          rewriteExists: refs.rewriteExists,
          filterPublic: refs.filterPublic,
        });
        if (++done % 50 === 0 || done === survivors.length) progress(`round ${round}/${o.rounds}`, done, survivors.length);
        return r;
      },
      opts.signal,
    );
    const after = await fetchTruth(opts.dns);
    for (const [k, v] of before) truthLog[`${k}#${round}`] = v;
    const next: Candidate[] = [];
    survivors.forEach((c, i) => {
      const s = state.get(c.ip)!;
      const r = raws[i];
      if (!r) {
        s.fail = 'no_answer';
        return;
      }
      if (round === 1) {
        s.dnssec = r.dnssec ?? null;
        s.nxLie = r.nxLie;
        s.rewrite = r.rewrite;
        s.filtering = r.filtering ?? null;
      }
      if (r.fail) {
        s.fail = round === 1 ? r.fail : r.fail === 'no_answer' ? 'unstable' : r.fail;
        return;
      }
      for (const c2 of names) {
        const k = key(c2);
        const seen = r.seen.get(k);
        if (!sameList(seen, before.get(k)) && !sameList(seen, after.get(k))) {
          s.fail = 'wrong_answer';
          return;
        }
      }
      if (round === 1 && s.rewrite) {
        s.fail = 'rewrites_answers';
        return;
      }
      if (round === 1 && s.nxLie) {
        s.fail = 'nxdomain_lie';
        return;
      }
      s.rtts.push(...r.rtts);
      next.push(c);
    });
    survivors = next;
    const wait = o.roundGapMs - (Date.now() - started);
    if (round < o.rounds && wait > 0 && survivors.length) await new Promise((r) => setTimeout(r, wait));
  }

  // Per-resolver verdict before selection.
  const outcomes = new Map<string, Outcome>();
  const failures: Record<string, number> = {};
  for (const c of toTest) {
    const s = state.get(c.ip)!;
    const latency = median(s.rtts);
    const reasons: CheckId[] = [];
    if (s.fail) reasons.push(s.fail);
    else if (latency != null && latency > o.maxLatencyMs) reasons.push('too_slow');
    for (const r of reasons) failures[r] = (failures[r] ?? 0) + 1;
    outcomes.set(c.ip, {
      ip: c.ip,
      tested: true,
      passed: reasons.length === 0,
      qualified: false,
      reasons,
      latencyMs: latency,
      minRttMs: s.rtts.length ? Math.min(...s.rtts) : null,
      dnssec: s.dnssec,
      filteringDetected: s.filtering ?? null,
    });
  }
  for (const c of skippedV6) {
    outcomes.set(c.ip, { ip: c.ip, tested: false, passed: false, qualified: false, reasons: ['ipv6_unavailable'], latencyMs: c.latency_ms, minRttMs: c.min_rtt_ms, dnssec: c.dnssec == null ? null : !!c.dnssec });
  }
  for (const c of quarantined) {
    outcomes.set(c.ip, { ip: c.ip, tested: false, passed: false, qualified: false, reasons: ['quarantined'], latencyMs: c.latency_ms, minRttMs: c.min_rtt_ms, dnssec: c.dnssec == null ? null : !!c.dnssec });
  }

  const passed = toTest.filter((c) => outcomes.get(c.ip)!.passed);
  const better = (a: Candidate, b: Candidate) => {
    const oa = outcomes.get(a.ip)!;
    const ob = outcomes.get(b.ip)!;
    // DNSSEC first, then the ones shown yesterday (a stable list from one day to the next:
    // two runs 10 minutes apart kept only 258 of ~400 in common without this), then latency
    return Number(!!ob.dnssec) - Number(!!oa.dnssec) || b.qualified - a.qualified || (oa.latencyMs ?? 1e9) - (ob.latencyMs ?? 1e9);
  };

  // Anycast services: one address per provider, unfiltered first.
  const byProvider = new Map<string, Candidate[]>();
  for (const c of passed.filter((c) => c.anycast)) {
    // one address per provider and per IP family
    const k = `${(c.provider ?? c.ip).toLowerCase()}|${net.isIPv6(c.ip) ? 6 : 4}`;
    byProvider.set(k, [...(byProvider.get(k) ?? []), c]);
  }
  for (const group of byProvider.values()) {
    const filt = (c: Candidate) => outcomes.get(c.ip)!.filteringDetected ?? c.filtering;
    group.sort((a, b) => Number(filt(a) !== 'none') - Number(filt(b) !== 'none') || better(a, b));
    group.forEach((c, i) => {
      const out = outcomes.get(c.ip)!;
      if (i < o.perProvider) out.qualified = true;
      else out.reasons.push('not_selected_provider_cap');
    });
  }

  // Unicast: locate the ones without coordinates, reject impossible locations, cap per country.
  const locals = passed.filter((c) => !c.anycast);
  const geolocate = opts.geolocate;
  if (geolocate) {
    const missing = locals.filter((c) => c.lat == null);
    let done = 0;
    await mapLimit(missing, 4, async (c) => {
      const g = await geolocate(c.ip);
      if (g) {
        outcomes.get(c.ip)!.location = g;
        Object.assign(c, { country_code: g.country_code, city: g.city, lat: g.lat, lon: g.lon, geo_precision: g.geo_precision });
      }
      progress('geolocation', ++done, missing.length);
    });
  }
  const srv = opts.serverLocation;
  const byCountry = new Map<string, Candidate[]>();
  for (const c of locals) {
    const out = outcomes.get(c.ip)!;
    if (!c.country_code) {
      out.reasons.push('no_country');
      continue;
    }
    if (srv && c.lat != null && c.lon != null && out.minRttMs != null) {
      const slack = c.geo_precision === 'city' ? 300 : 1500;
      const km = Math.max(0, distanceKm(srv.lat, srv.lon, c.lat, c.lon) - slack);
      if (out.minRttMs < minRttMs(km)) {
        out.reasons.push('geo_implausible');
        continue;
      }
    }
    const ck = `${c.country_code}|${net.isIPv6(c.ip) ? 6 : 4}`; // the cap applies per IP family
    byCountry.set(ck, [...(byCountry.get(ck) ?? []), c]);
  }
  for (const group of byCountry.values()) {
    group.sort(better);
    const asns = new Set<string>();
    for (const c of group) {
      const out = outcomes.get(c.ip)!;
      const asnKey = String(c.asn ?? c.provider ?? c.ip).toLowerCase();
      if (asns.size < o.perCountry && !asns.has(asnKey)) {
        asns.add(asnKey);
        out.qualified = true;
      } else out.reasons.push('not_selected_country_cap');
    }
  }

  return {
    outcomes: [...outcomes.values()],
    tested: toTest.length,
    skippedQuarantine: quarantined.length,
    passed: passed.length,
    failures,
    truth: truthLog,
  };
}
