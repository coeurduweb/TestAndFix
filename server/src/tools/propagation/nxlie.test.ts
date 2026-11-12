// NXDOMAIN lies during a live check (measured twice on 2026-11-10 by the reviewer, then by us
// with dig: 103.84.132.2 (MV) answers NXDOMAIN for example.com with a forged SOA of "com."
// serial 1, 94.26.221.100 (YE) answers NXDOMAIN with no SOA at all; both resolve google.com).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openDb } from '../../db.js';
import { ResolveSession } from '../../dns/iterative.js';
import { checkAuthority, checkResolvers, revalidateNxLies, summarize, type AuthorityEvent, type ResolverEvent } from './check.js';
import { candidates, loadSeed, qualifiedResolvers, quarantineRewriters } from './store.js';
import { startFakeResolver, type FakeResolver } from './testing/fake-resolver.js';
import type { SeedResolver } from './types.js';

const seed = (ip: string): SeedResolver => ({
  ip, name: ip, provider: ip, asn: null, country_code: 'MV', city: null, lat: null, lon: null,
  geo_precision: null, anycast: false, filtering: 'none', source: 'test', group: 'local',
});

let auth: AuthorityEvent;
const fakes: Record<string, FakeResolver> = {};
beforeAll(async () => {
  auth = await checkAuthority(new ResolveSession(), { name: 'example.com', type: 'A' });
  const serial = auth.serials[0];
  fakes.noSoa = await startFakeResolver({ 'example.com': { nxdomain: {} } });
  fakes.wrongZone = await startFakeResolver({ 'example.com': { nxdomain: { soa: { zone: 'com', serial: 1, ttl: 30 } } } });
  // a resolver that cached the NXDOMAIN before the record was created: SOA of the zone, older serial
  fakes.oldCache = await startFakeResolver({ 'example.com': { nxdomain: { soa: { zone: 'example.com', serial: serial - 10, ttl: 120 } } } });
});
afterAll(async () => {
  await Promise.all(Object.values(fakes).map((f) => f.close()));
});

async function ask(port: number | undefined, a: AuthorityEvent = auth, ips = ['127.0.0.1']) {
  const db = openDb(':memory:');
  loadSeed(db, ips.map(seed));
  db.prepare('UPDATE resolvers SET qualified = 1').run();
  return checkResolvers({ name: 'example.com', type: 'A' }, a.reference, qualifiedResolvers(db), () => {}, { port, authority: a });
}

describe('NXDOMAIN while every authoritative server has data', () => {
  it('no SOA in the negative answer: rewritten, reason nxdomain_lie, no refresh time', async () => {
    expect(auth.servers.every((s) => !s.error && s.values.length > 0)).toBe(true);
    const [e] = await ask(fakes.noSoa.port);
    expect(e).toMatchObject({ status: 'rewritten', reason: 'nxdomain_lie', refreshAt: null });
  }, 20000);
  it('forged SOA of another zone: rewritten, reason nxdomain_lie', async () => {
    const [e] = await ask(fakes.wrongZone.port);
    expect(e).toMatchObject({ status: 'rewritten', reason: 'nxdomain_lie' });
  }, 20000);
  it('SOA of the zone with an older serial (cached before a creation): missing, with refresh time', async () => {
    const [e] = await ask(fakes.oldCache.port);
    expect(e.status).toBe('missing');
    expect(e.reason).toBeUndefined();
    expect(e.refreshAt).toMatch(/^20/);
  }, 20000);
  it('stays missing when some authoritative servers also answer NXDOMAIN (creation in progress)', async () => {
    const partial: AuthorityEvent = {
      ...auth,
      servers: auth.servers.map((s, i) => (i === 0 ? { ...s, rcode: 'NXDOMAIN', values: [] } : s)),
    };
    const [e] = await ask(fakes.noSoa.port, partial);
    expect(e.status).toBe('missing');
  }, 20000);
  it('non-public rewrites carry reason non_public', async () => {
    const f = await startFakeResolver({ 'example.com': { a: '127.0.0.1' } });
    const [e] = await ask(f.port);
    await f.close();
    expect(e).toMatchObject({ status: 'rewritten', reason: 'non_public' });
  }, 20000);
});

describe('serial changed during the measurement', () => {
  it('turns nxdomain lies back into missing and they are not quarantined', () => {
    const lie = { ip: '1', status: 'rewritten', reason: 'nxdomain_lie', ttl: 60, refreshAt: null, values: [], cname: null, anycast: false, country_code: 'MV', continent: 'AS' } as unknown as ResolverEvent;
    const other = { ...lie, ip: '2', reason: 'non_public' } as ResolverEvent;
    const fixed = revalidateNxLies([lie, other], true, Date.parse('2026-11-10T12:00:00Z'));
    expect(fixed.map((e) => e.ip)).toEqual(['1']);
    expect(lie).toMatchObject({ status: 'missing', reason: undefined, refreshAt: '2026-11-10T12:01:00.000Z' });
    expect(other.status).toBe('rewritten');
    expect(revalidateNxLies([other], false)).toEqual([]);
    const s = summarize([lie, other], auth.reference);
    expect(s).toMatchObject({ missing: 1, rewritten: 1 });
  });
});

describe('real liars (2026-11-10)', () => {
  it('103.84.132.2 and 94.26.221.100 are flagged and quarantined', async () => {
    const db = openDb(':memory:');
    loadSeed(db, ['103.84.132.2', '94.26.221.100'].map(seed));
    db.prepare('UPDATE resolvers SET qualified = 1').run();
    const events = await checkResolvers({ name: 'example.com', type: 'A' }, auth.reference, qualifiedResolvers(db), () => {}, { authority: auth });
    for (const e of events) {
      // tolerate an unreachable resolver; anything else than a lie is a regression
      expect(['rewritten', 'timeout'], `${e.ip} ${e.status}`).toContain(e.status);
      if (e.status === 'rewritten') expect(e.reason).toBe('nxdomain_lie');
    }
    quarantineRewriters(db, events.filter((e) => e.status === 'rewritten').map((e) => e.ip));
    expect(candidates(db).filter((c) => c.qualified).length).toBe(events.filter((e) => e.status !== 'rewritten').length);
  }, 20000);
});
