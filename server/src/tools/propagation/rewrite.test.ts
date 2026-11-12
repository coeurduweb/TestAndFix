// Resolvers that rewrite answers (defect seen live on 2026-11-10: 192.172.250.8 qualified, yet it
// answers 127.0.0.1 with a 3 h TTL for example.com, which pushed "all up to date" 3 h later).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { DnsAnswer, DnsResponse } from '../../dns/client.js';
import { openDb } from '../../db.js';
import { ResolveSession } from '../../dns/iterative.js';
import { isPublicAddress } from './addresses.js';
import { checkAuthority, checkResolvers, ecsVerdict, summarize, type ResolverEvent } from './check.js';
import type { EcsResponse } from './ecs.js';
import { qualify } from './qualify.js';
import { observe, type Reference } from './status.js';
import { candidates, loadSeed, quarantineRewriters, qualifiedResolvers } from './store.js';
import { startFakeResolver, type FakeResolver } from './testing/fake-resolver.js';
import type { SeedResolver } from './types.js';

const seed = (ip: string, provider: string): SeedResolver => ({
  ip, name: provider, provider, asn: null, country_code: 'XX', city: null, lat: null, lon: null,
  geo_precision: null, anycast: false, filtering: 'none', source: 'test', group: 'local',
});
const ans = (name: string, type: string, data: unknown, ttl = 300): DnsAnswer => ({ name, type, ttl, data });
const res = (rcode: string, answers: DnsAnswer[] = []): DnsResponse => ({
  server: 'x', transport: 'udp', rtt: 5, rcode,
  flags: { aa: false, tc: false, rd: true, ra: true, ad: false, cd: false },
  answers, authorities: [], additionals: [],
});
const ref = (values: string[], extra: Partial<Reference> = {}): Reference => ({
  source: 'authority', exists: values.length > 0, kind: 'records', values, cname: null, ...extra,
});

describe('isPublicAddress', () => {
  it('rejects loopback, private, link-local, unspecified, CGNAT, documentation and ULA ranges', () => {
    for (const ip of ['127.0.0.1', '0.0.0.0', '10.1.2.3', '192.168.1.1', '172.16.0.1', '172.31.255.255', '169.254.1.1', '100.64.0.1', '192.0.2.1', '255.255.255.255', '224.0.0.1', '::1', '::', 'fc00::1', 'fd12::1', 'fe80::1', '2001:db8::1', '::ffff:127.0.0.1'])
      expect(isPublicAddress(ip), ip).toBe(false);
  });
  it('accepts public unicast addresses', () => {
    for (const ip of ['104.20.23.154', '172.32.0.1', '8.8.8.8', '2606:4700::6810:84e5', '::ffff:8.8.8.8']) expect(isPublicAddress(ip), ip).toBe(true);
  });
});

describe('observe: rewritten answers', () => {
  it('a non-public answer where the reference is public is "rewritten", without refresh time', () => {
    const o = observe('A', 'example.com', ref(['104.20.23.154', '172.66.147.243']), res('NOERROR', [ans('example.com', 'A', '127.0.0.1', 10800)]));
    expect(o).toMatchObject({ status: 'rewritten', refreshAt: null, values: ['127.0.0.1'] });
    expect(observe('AAAA', 'example.com', ref(['2606:4700::1']), res('NOERROR', [ans('example.com', 'AAAA', '::')])).status).toBe('rewritten');
    // alias reference: a resolver answering 0.0.0.0 without the CNAME
    const alias = ref(['20.250.119.67'], { kind: 'cname', cname: 'github.com' });
    expect(observe('A', 'www.github.com', alias, res('NOERROR', [ans('www.github.com', 'A', '0.0.0.0')])).status).toBe('rewritten');
  });
  it('a private address published by the zone itself is compared normally', () => {
    expect(observe('A', 'intranet.example.com', ref(['10.0.0.5']), res('NOERROR', [ans('intranet.example.com', 'A', '10.0.0.5')])).status).toBe('fresh');
    expect(observe('A', 'x.example.com', ref(['192.168.1.9'], { source: 'expected' }), res('NOERROR', [ans('x.example.com', 'A', '192.168.1.9')])).status).toBe('fresh');
  });
  it('is neither up to date nor in allFreshBy nor in the pending list', () => {
    const ev = (ip: string, status: ResolverEvent['status'], refreshAt: string | null = null) =>
      ({ ip, status, country_code: 'FR', continent: 'EU', anycast: false, refreshAt, values: [], cname: null, geo: null, uncertain: false }) as unknown as ResolverEvent;
    const s = summarize([ev('1', 'fresh'), ev('2', 'rewritten'), ev('3', 'stale', '2026-11-10T12:05:00.000Z')], ref(['x']));
    expect(s).toMatchObject({ total: 3, answered: 2, fresh: 1, rewritten: 1, percentFresh: 50, allFreshBy: '2026-11-10T12:05:00.000Z', complete: false });
    expect(s.pendingIps).toEqual(['3']);
    expect(s.byCountry[0]).toMatchObject({ rewritten: 1 });
  });
});

describe('ECS verdict', () => {
  const ecs = (rcode: string, answers: DnsAnswer[], scope: number | null): EcsResponse => ({ ...res(rcode, answers), scope });
  it('FORMERR (ECS not supported) gives no conclusion', () => {
    const r = ref(['192.0.2.10']);
    const seen = res('NOERROR', [ans('example.com', 'A', '198.51.100.1')]);
    expect(ecsVerdict('A', 'example.com', r, seen, [ecs('FORMERR', [], null), ecs('FORMERR', [], null)])).toBeNull();
    expect(ecsVerdict('A', 'example.com', r, seen, [ecs('NOERROR', [ans('example.com', 'A', '198.51.100.1')], 0)])).toBeNull();
  });
  it('an answer the zone gives to that network explains the difference', () => {
    const v = ecsVerdict('A', 'example.com', ref(['192.0.2.10']), res('NOERROR', [ans('example.com', 'A', '198.51.100.1')]), [
      ecs('FORMERR', [], null),
      ecs('NOERROR', [ans('example.com', 'A', '198.51.100.1')], 24),
    ]);
    expect(v).toMatchObject({ explained: true, scope: 24, authorityValues: ['198.51.100.1'] });
  });
});

describe('qualification and live check against local resolvers (relaying to 1.1.1.1)', () => {
  let honest: FakeResolver;
  let rewriter: FakeResolver;
  let filtering: FakeResolver;
  beforeAll(async () => {
    honest = await startFakeResolver({});
    rewriter = await startFakeResolver({ 'example.com': { a: '127.0.0.1', ttl: 10800 } });
    filtering = await startFakeResolver({ 'malware.testcategory.com': { a: '0.0.0.0' } });
  });
  afterAll(async () => {
    await Promise.all([honest, rewriter, filtering].map((f) => f?.close()));
  });

  it('eliminates a resolver that rewrites answers, keeps an honest one, marks a filtering one', { timeout: 30000 }, async () => {
    const db = openDb(':memory:');
    loadSeed(db, [seed('127.0.0.1', 'local')]);
    const run = async (port: number) =>
      (await qualify(candidates(db), { dns: () => new ResolveSession(), geolocate: false, serverLocation: null, port })).outcomes[0];
    const h = await run(honest.port);
    expect(h.passed, String(h.reasons)).toBe(true);
    expect(h.filteringDetected).toBeNull();
    const r = await run(rewriter.port);
    expect(r).toMatchObject({ passed: false, qualified: false, reasons: ['rewrites_answers'] });
    const f = await run(filtering.port);
    expect(f.passed, String(f.reasons)).toBe(true);
    expect(f.filteringDetected).toBe('malware');
  });

  it('flags the rewritten answer live and quarantines the resolver', { timeout: 30000 }, async () => {
    const db = openDb(':memory:');
    loadSeed(db, [seed('127.0.0.1', 'local')]);
    db.prepare('UPDATE resolvers SET qualified = 1').run();
    const input = { name: 'example.com', type: 'A' as const };
    const auth = await checkAuthority(new ResolveSession(), input);
    const events = await checkResolvers(input, auth.reference, qualifiedResolvers(db), () => {}, { port: rewriter.port });
    expect(events[0]).toMatchObject({ status: 'rewritten', values: ['127.0.0.1'], ttl: 10800, refreshAt: null });
    quarantineRewriters(db, events.filter((e) => e.status === 'rewritten').map((e) => e.ip));
    const c = candidates(db, ['127.0.0.1'])[0];
    expect(c.qualified).toBe(0);
    expect(c.quarantined_until).toBeGreaterThan(Date.now());
    expect(JSON.parse(c.reasons!)).toEqual(['rewrites_answers']);
    expect(qualifiedResolvers(db)).toHaveLength(0);
  });
});

describe('authority RTT is measured per server', () => {
  it('the .jp servers answer from several places: their RTTs differ within one batch', { timeout: 20000 }, async () => {
    // measured on 2026-11-10 from France: c, d, e, h about 10 to 16 ms; a, b, f, g about 240 to 262 ms
    const a = await checkAuthority(new ResolveSession(), { name: 'jp', type: 'SOA' });
    const rtts = a.servers.map((s) => s.rtt).filter((x): x is number => x != null);
    expect(rtts.length).toBeGreaterThan(4);
    expect(Math.max(...rtts) - Math.min(...rtts)).toBeGreaterThan(100);
  });
});
