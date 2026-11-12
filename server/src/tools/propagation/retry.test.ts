// Live check: bounded parallelism shared by all streams, and a second attempt for timeouts.
// Defect measured on 2026-11-11: 448 resolvers asked at once lost 216 to 306 answers (timeouts).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openDb } from '../../db.js';
import { ResolveSession } from '../../dns/iterative.js';
import { checkAuthority, checkResolvers, LIVE_CONCURRENCY, liveSlots, summarize, type AuthorityEvent } from './check.js';
import { loadSeed, qualifiedResolvers } from './store.js';
import { startFakeResolver, type FakeResolver } from './testing/fake-resolver.js';
import { Semaphore } from './util.js';

let auth: AuthorityEvent;
let flaky: FakeResolver;
beforeAll(async () => {
  auth = await checkAuthority(new ResolveSession(), { name: 'example.com', type: 'A' });
});
afterAll(async () => flaky?.close());

const one = () => {
  const db = openDb(':memory:');
  loadSeed(db, [{ ip: '127.0.0.1', name: 'l', provider: 'l', asn: null, country_code: 'FR', city: null, lat: null, lon: null, geo_precision: null, anycast: false, filtering: 'none', source: 't', group: 'local' }]);
  db.prepare('UPDATE resolvers SET qualified = 1').run();
  return qualifiedResolvers(db);
};

describe('second attempt', () => {
  it('a resolver that drops the first query answers on the second attempt, marked attempts: 2', { timeout: 20000 }, async () => {
    flaky = await startFakeResolver({ 'example.com': { dropFirst: 1 } });
    const ev = await checkResolvers({ name: 'example.com', type: 'A' }, auth.reference, one(), () => {}, { port: flaky.port, timeoutMs: 500, retryTimeoutMs: 3000 });
    expect(ev[0]).toMatchObject({ status: 'fresh', attempts: 2 });
    expect(summarize(ev, auth.reference)).toMatchObject({ retried: 1, answeredOnRetry: 1, timeout: 0 });
    await flaky.close();
  });
  it('without retry the same resolver is a timeout at the first attempt', { timeout: 20000 }, async () => {
    flaky = await startFakeResolver({ 'example.com': { dropFirst: 1 } });
    const ev = await checkResolvers({ name: 'example.com', type: 'A' }, auth.reference, one(), () => {}, { port: flaky.port, timeoutMs: 500, retryTimeoutMs: 0 });
    expect(ev[0]).toMatchObject({ status: 'timeout', attempts: 1 });
  });
  it('a dead resolver is reported once, after its second attempt', { timeout: 20000 }, async () => {
    const seen: string[] = [];
    const db = openDb(':memory:');
    loadSeed(db, [{ ip: '192.0.2.1', name: 'd', provider: 'd', asn: null, country_code: 'FR', city: null, lat: null, lon: null, geo_precision: null, anycast: false, filtering: 'none', source: 't', group: 'local' }]);
    db.prepare('UPDATE resolvers SET qualified = 1').run();
    const ev = await checkResolvers({ name: 'example.com', type: 'A' }, auth.reference, qualifiedResolvers(db), (e) => seen.push(e.status), { timeoutMs: 300, retryTimeoutMs: 600 });
    expect(seen).toEqual(['timeout']);
    expect(ev[0].attempts).toBe(2);
  });
});

describe('parallelism', () => {
  it('a semaphore never lets more than its limit run', async () => {
    const s = new Semaphore(3);
    await Promise.all(Array.from({ length: 20 }, () => s.run(() => new Promise((ok) => setTimeout(ok, 5)))));
    expect(s.peak).toBe(3);
  });
  it('all live checks share one budget (default 100)', () => {
    expect(LIVE_CONCURRENCY).toBe(100);
    expect(liveSlots.limit).toBe(100);
  });
});
