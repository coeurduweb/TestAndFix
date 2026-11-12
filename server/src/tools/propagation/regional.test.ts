// Regional answers of a CDN (false alert reproduced twice on 2026-11-10: example.com A, Yandex
// 77.88.8.1 -> 8.47.69.0/8.6.112.0, 1984.is -> 8.47.69.2, IRANET -> 188.114.98.0/.99.0, all
// Cloudflare AS13335 with a fresh TTL; they were shown "stale" and "all up to date" never came).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openDb } from '../../db.js';
import { ResolveSession } from '../../dns/iterative.js';
import { AsnLookup, originQueryName, parseOrigin } from './asn.js';
import { checkAuthority, checkResolvers, summarize, type ResolverEvent } from './check.js';
import { loadSeed, qualifiedResolvers } from './store.js';
import { startFakeResolver, type FakeResolver } from './testing/fake-resolver.js';
import type { SeedResolver } from './types.js';

const seed = (ip: string, provider: string): SeedResolver => ({
  ip, name: provider, provider, asn: null, country_code: 'RU', city: null, lat: null, lon: null,
  geo_precision: null, anycast: false, filtering: 'none', source: 'test', group: 'local',
});

describe('Team Cymru names', () => {
  it('builds the /24 and /48 query names and parses the origin line', () => {
    expect(originQueryName('104.20.23.154')).toBe('23.20.104.origin.asn.cymru.com');
    expect(originQueryName('2606:4700:10::6814:179a')).toBe('0.1.0.0.0.0.7.4.6.0.6.2.origin6.asn.cymru.com');
    expect(parseOrigin('13335 | 104.20.0.0/20 | US | arin | 2014-03-28')).toEqual([13335]);
    expect(parseOrigin('13335 4808 | 1.2.3.0/24 | CN | apnic |')).toEqual([13335, 4808]);
  });
  it('resolves from the root, one query per /24', { timeout: 20000 }, async () => {
    const l = new AsnLookup(new ResolveSession());
    expect(await l.asnsOf('104.20.23.154')).toEqual([13335]);
    expect(await l.asnsOf('8.47.69.0')).toEqual([13335]);
    expect(await l.asnsOf('8.47.69.2')).toEqual([13335]);
    expect(l.queries).toBe(2);
    expect(await l.nameOf(13335)).toMatch(/CLOUDFLARE/i);
  });
});

describe('summary with regional answers', () => {
  const ev = (ip: string, status: ResolverEvent['status'], refreshAt: string | null = null) =>
    ({ ip, status, country_code: 'RU', continent: 'EU', anycast: false, refreshAt, values: [], cname: null, geo: null, uncertain: false, regionalAsn: null }) as unknown as ResolverEvent;
  it('counts regional apart, as up to date, never pending, never in allFreshBy', () => {
    const s = summarize([ev('1', 'fresh'), ev('2', 'regional'), ev('3', 'regional')], { source: 'authority', exists: true, kind: 'records', values: [], cname: null });
    expect(s).toMatchObject({ total: 3, answered: 3, fresh: 1, regional: 2, percentFresh: 100, complete: true, allFreshBy: null, pendingIps: [] });
    expect(s.local).toMatchObject({ regional: 2, percentFresh: 100 });
    expect(s.byCountry[0]).toMatchObject({ regional: 2 });
    expect(s.byContinent[0]).toMatchObject({ regional: 2 });
    const t = summarize([ev('1', 'regional'), ev('2', 'stale', '2026-11-10T22:10:00.000Z')], { source: 'authority', exists: true, kind: 'records', values: [], cname: null });
    expect(t).toMatchObject({ percentFresh: 50, allFreshBy: '2026-11-10T22:10:00.000Z', pendingIps: ['2'], complete: false });
  });
});

describe('live check: regional vs stale', () => {
  const fakes: Record<string, FakeResolver> = {};
  beforeAll(async () => {
    fakes.cfShort = await startFakeResolver({ 'example.com': { a: '104.16.0.1', ttl: 100 } }); // Cloudflare, short TTL
    fakes.cfLong = await startFakeResolver({ 'example.com': { a: '104.16.0.1', ttl: 86400 } }); // TTL above the zone's
    fakes.other = await startFakeResolver({ 'example.com': { a: '9.9.9.9', ttl: 100 } }); // another ASN (Quad9)
  });
  afterAll(async () => {
    await Promise.all(Object.values(fakes).map((f) => f.close()));
  });

  const run = async (port: number | undefined, ips = ['127.0.0.1']) => {
    const db = openDb(':memory:');
    loadSeed(db, ips.map((ip) => seed(ip, ip)));
    db.prepare('UPDATE resolvers SET qualified = 1').run();
    const session = new ResolveSession();
    const input = { name: 'example.com', type: 'A' as const };
    const auth = await checkAuthority(session, input);
    return checkResolvers(input, auth.reference, qualifiedResolvers(db), () => {}, {
      port,
      asn: new AsnLookup(session),
      referenceTtl: auth.reference.ttl,
      authorityIps: auth.servers.filter((s) => !s.error).map((s) => s.ip),
    });
  };

  it('same ASN as the authoritative answer and TTL within the zone TTL: regional', { timeout: 20000 }, async () => {
    const [e] = await run(fakes.cfShort.port);
    expect(e).toMatchObject({ status: 'regional', refreshAt: null, values: ['104.16.0.1'], ttl: 100 });
    expect(e.regionalAsn).toMatchObject({ asn: 13335 });
    expect(e.regionalAsn!.name).toMatch(/CLOUDFLARE/i);
  });
  it('TTL above the authoritative TTL: stale', { timeout: 20000 }, async () => {
    const [e] = await run(fakes.cfLong.port);
    expect(e.status).toBe('stale');
    expect(e.regionalAsn).toBeNull();
  });
  it('another ASN: stale', { timeout: 20000 }, async () => {
    const [e] = await run(fakes.other.port);
    expect(e.status).toBe('stale');
    expect(e.regionalAsn).toBeNull();
  });
  it('real case: Yandex 77.88.8.1 gets a Cloudflare regional view of example.com', { timeout: 20000 }, async () => {
    const [e] = await run(undefined, ['77.88.8.1']);
    // seen all day on 2026-11-10: 8.47.69.0 and 8.6.112.0; accept "fresh" if Yandex ever gets the main view
    expect(['regional', 'fresh'], `${e.status} ${e.values}`).toContain(e.status);
    if (e.status === 'regional') expect(e.regionalAsn?.asn).toBe(13335);
  });
});
