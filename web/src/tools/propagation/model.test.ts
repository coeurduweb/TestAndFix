import { describe, expect, it } from 'vitest';
import {
  allFreshBy, buildRows, cleanProvider, countRows, distinctAnswers, groupRows, initialRun, keyboardOrder, matchesFilter, pendingIps,
  referenceSig, runReducer, watchTargets, sortRows, sortValues, spreadPoints, streamUrl, ttlLeft,
  type AuthorityEvent, type ResolverEvent, type ResolverInfo, type Row, type RunState,
} from './model';

const info = (ip: string, o: Partial<ResolverInfo> = {}): ResolverInfo => ({
  ip, name: ip, provider: 'Op', asn: 1, country_code: 'FR', continent: 'EU', city: 'Paris', lat: 48.8, lon: 2.3,
  anycast: false, group: 'local', filtering: 'none', dnssec: true, latencyMs: 20, ...o,
});

const ev = (ip: string, status: ResolverEvent['status'], o: Partial<ResolverEvent> = {}): ResolverEvent => ({
  ...info(ip), status, rcode: status === 'error' ? 'SERVFAIL' : 'NOERROR', cname: null, values: status === 'fresh' ? ['1.1.1.1'] : status === 'stale' ? ['9.9.9.9'] : [],
  ttl: 300, refreshAt: null, geo: null, uncertain: false, at: '2026-11-10T18:00:00.000Z', ...o,
});

const authority = (values: string[]): AuthorityEvent => ({
  zone: 'exemple.fr',
  servers: [],
  serials: [1],
  divergent: false,
  divergence: { answers: false, serials: false, dynamic: false, sameAnswerDifferentSerials: false },
  serialGroups: [],
  reference: { source: 'authority', exists: true, kind: 'records', values, cname: null, ttl: 300, serial: 1, finalValues: values, chain: [] },
  authority: { exists: true, cname: null, values },
  expectedMatchesAuthority: null,
  ms: 10,
});

const rowsOf = (...evs: ResolverEvent[]): Row[] => evs.map((e) => ({ info: info(e.ip, { country_code: e.country_code, continent: e.continent, anycast: e.anycast }), ev: e, remeasuring: false }));

describe('stream reducer', () => {
  it('keeps the answers of earlier rounds and replaces those asked again', () => {
    let s: RunState = runReducer(initialRun, { type: 'begin', scope: null });
    s = runReducer(s, { type: 'authority', data: authority(['1.1.1.1']) });
    s = runReducer(s, { type: 'resolvers', data: [ev('a', 'fresh'), ev('b', 'stale')] });
    s = runReducer(s, { type: 'done', data: {} as never });
    expect(s.phase).toBe('done');
    s = runReducer(s, { type: 'begin', scope: ['b'] });
    expect(s.round).toBe(1);
    expect(Object.keys(s.results)).toEqual(['a', 'b']);
    const rows = buildRows([info('a'), info('b')], s);
    expect(rows.find((r) => r.info.ip === 'b')!.remeasuring).toBe(true);
    expect(rows.find((r) => r.info.ip === 'a')!.remeasuring).toBe(false);
    s = runReducer(s, { type: 'authority', data: authority(['1.1.1.1']) });
    expect(s.referenceChanged).toBe(false);
    s = runReducer(s, { type: 'resolvers', data: [ev('b', 'fresh')] });
    expect(s.results.b.status).toBe('fresh');
    expect(buildRows([info('a'), info('b')], s).every((r) => !r.remeasuring)).toBe(true);
  });

  it('flags a reference that changed between two rounds', () => {
    let s = runReducer(runReducer(initialRun, { type: 'begin', scope: null }), { type: 'authority', data: authority(['1.1.1.1']) });
    s = runReducer(s, { type: 'begin', scope: ['x'] });
    s = runReducer(s, { type: 'authority', data: authority(['2.2.2.2']) });
    expect(s.referenceChanged).toBe(true);
  });

  it('a full run starts from scratch', () => {
    let s = runReducer(initialRun, { type: 'resolvers', data: [ev('a', 'fresh')] });
    s = runReducer(s, { type: 'begin', scope: null });
    expect(s.results).toEqual({});
    expect(s.round).toBe(0);
  });

  it('reference signature ignores the order of values', () => {
    expect(referenceSig(authority(['b', 'a']))).toBe(referenceSig(authority(['a', 'b'])));
  });
});

describe('NXDOMAIN where the zone answers', () => {
  it('is a rewritten answer, an empty NOERROR stays absent', () => {
    let s = runReducer(initialRun, { type: 'begin', scope: null });
    s = runReducer(s, { type: 'resolvers', data: [ev('n', 'missing', { rcode: 'NXDOMAIN', refreshAt: '2026-11-10T18:05:00.000Z' }), ev('e', 'missing', { rcode: 'NOERROR' })] });
    expect(s.results.n).toMatchObject({ status: 'rewritten', refreshAt: null });
    expect(s.results.e.status).toBe('missing');
  });
  it('no convergence time for uncertain answers only', () => {
    expect(allFreshBy(rowsOf(ev('u', 'stale', { uncertain: true, refreshAt: '2026-11-10T18:05:00.000Z' })))).toBeNull();
  });
});

describe('rows and counts', () => {
  it('skeleton rows for every qualified resolver, answers merged in', () => {
    const s = runReducer(initialRun, { type: 'resolvers', data: [ev('a', 'fresh'), ev('z', 'stale')] });
    const rows = buildRows([info('a'), info('b')], s);
    expect(rows.map((r) => [r.info.ip, r.ev?.status ?? 'pending'])).toEqual([['a', 'fresh'], ['b', 'pending'], ['z', 'stale']]);
  });

  it('percentage over those who answered, failures apart', () => {
    const c = countRows([...rowsOf(ev('a', 'fresh'), ev('b', 'fresh'), ev('c', 'stale', { uncertain: true }), ev('d', 'missing'), ev('e', 'timeout'), ev('f', 'error'), ev('h', 'rewritten', { values: ['127.0.0.1'] })), { info: info('g'), remeasuring: false }]);
    expect(c).toMatchObject({ total: 8, rewritten: 1, fresh: 2, stale: 1, missing: 1, error: 2, pending: 1, answered: 4, percentFresh: 50, uncertain: 1, percentCertain: 66.7, late: 1 });
  });

  it('all up to date at the latest refresh of the late ones', () => {
    const rows = rowsOf(
      ev('a', 'stale', { refreshAt: '2026-11-10T18:05:00.000Z' }),
      ev('b', 'missing', { refreshAt: '2026-11-10T18:09:00.000Z' }),
      ev('c', 'fresh', { refreshAt: null }),
    );
    expect(allFreshBy(rows)).toBe('2026-11-10T18:09:00.000Z');
    expect(allFreshBy(rowsOf(ev('c', 'fresh')))).toBeNull();
  });

  it('watch mode asks again everything not up to date', () => {
    expect(pendingIps(rowsOf(ev('a', 'fresh'), ev('b', 'stale'), ev('c', 'timeout'), ev('d', 'missing'), ev('e', 'rewritten')))).toEqual(['b', 'c', 'd']);
  });

  it('distinct answers, most frequent first, failures left out', () => {
    const d = distinctAnswers(rowsOf(ev('a', 'fresh'), ev('b', 'fresh', { values: ['1.1.1.1'] }), ev('c', 'stale'), ev('d', 'error'), ev('e', 'rewritten', { values: ['127.0.0.1'] })));
    expect(d.map((x) => [x.values.join(), x.count, x.fresh])).toEqual([['1.1.1.1', 2, 2], ['9.9.9.9', 1, 0]]);
  });

  it('remaining TTL counts down from the moment of the answer', () => {
    const e = ev('a', 'fresh', { ttl: 300, at: '2026-11-10T18:00:00.000Z' });
    expect(ttlLeft(e, Date.parse('2026-11-10T18:01:00.000Z'))).toBe(240);
    expect(ttlLeft(e, Date.parse('2026-11-10T19:00:00.000Z'))).toBe(0);
    expect(ttlLeft(ev('b', 'timeout', { ttl: null }))).toBeNull();
  });
});

describe('watch rounds', () => {
  it('late ones every round, failures three rounds at most, settled ones never', () => {
    const rows = rowsOf(ev('s', 'stale'), ev('m', 'missing'), ev('t', 'timeout'), ev('e', 'error'), ev('f', 'fresh'), ev('g', 'regional'), ev('w', 'rewritten'));
    expect(watchTargets(rows, {})).toEqual({ ips: ['s', 'm', 't', 'e'], givenUp: [] });
    expect(watchTargets(rows, { t: 3, e: 2 })).toEqual({ ips: ['s', 'm', 'e'], givenUp: ['t'] });
  });
});

describe('regional answers', () => {
  const rows = rowsOf(
    ev('a', 'fresh'),
    ev('b', 'regional', { values: ['8.47.69.0'], regionalAsn: { asn: 13335, name: 'Cloudflare' } }),
    ev('c', 'stale', { refreshAt: '2026-11-10T18:05:00.000Z' }),
  );
  it('count as up to date, never late, never asked again', () => {
    expect(countRows(rows)).toMatchObject({ fresh: 1, regional: 1, answered: 3, percentFresh: 66.7, percentCertain: 66.7, late: 1 });
    expect(countRows(rows.slice(0, 2))).toMatchObject({ percentCertain: 100, late: 0 });
    expect(pendingIps(rows)).toEqual(['c']);
    expect(allFreshBy(rows.slice(0, 2))).toBeNull();
  });
  it('their own filter and their own distinct answer', () => {
    expect(rows.filter((r) => matchesFilter(r, 'regional')).map((r) => r.info.ip)).toEqual(['b']);
    expect(distinctAnswers(rows).find((x) => x.values[0] === '8.47.69.0')).toMatchObject({ count: 1, regional: 1, fresh: 0 });
  });
  it('sort between the failures and the up to date', () => {
    expect(sortRows([...rows, ...rowsOf(ev('d', 'timeout'))], { key: 'status', dir: 'asc' }).map((r) => r.info.ip)).toEqual(['c', 'd', 'b', 'a']);
  });
});

describe('filters', () => {
  const [fresh, stale, timeout] = rowsOf(ev('a', 'fresh'), ev('b', 'stale'), ev('c', 'timeout'));
  const pending: Row = { info: info('d'), remeasuring: false };
  it('by status, failures and timeouts together', () => {
    expect([fresh, stale, timeout, pending].filter((r) => matchesFilter(r, 'error')).map((r) => r.info.ip)).toEqual(['c']);
    expect([fresh, stale, timeout, pending].filter((r) => matchesFilter(r, 'pending')).map((r) => r.info.ip)).toEqual(['d']);
    expect([fresh, stale, timeout, pending].filter((r) => matchesFilter(r, 'all'))).toHaveLength(4);
  });
  it('rewritten apart from the failures', () => {
    const [w] = rowsOf(ev('w', 'rewritten', { values: ['0.0.0.0'] }));
    expect(matchesFilter(w, 'rewritten')).toBe(true);
    expect(matchesFilter(w, 'error')).toBe(false);
    expect(matchesFilter(timeout, 'rewritten')).toBe(false);
  });
  it('by answer', () => {
    const key = JSON.stringify([null, ['9.9.9.9']]);
    expect([fresh, stale].filter((r) => matchesFilter(r, 'all', key)).map((r) => r.info.ip)).toEqual(['b']);
  });
});

describe('sorting and grouping', () => {
  const rows = rowsOf(
    ev('1.0.0.1', 'fresh', { latencyMs: 50, ttl: 100 }),
    ev('1.0.0.2', 'stale', { latencyMs: 10, ttl: 50 }),
    ev('1.0.0.3', 'missing', { latencyMs: 30, ttl: 900 }),
  );
  const pending: Row = { info: info('1.0.0.9'), remeasuring: false };
  it('status: what needs attention first, skeletons last', () => {
    const w = rowsOf(ev('1.0.0.5', 'rewritten'))[0];
    expect(sortRows([w, ...rows, pending], { key: 'status', dir: 'asc' }).map((r) => r.info.ip)).toEqual(['1.0.0.2', '1.0.0.3', '1.0.0.5', '1.0.0.1', '1.0.0.9']);
    expect(sortRows([...rows, pending], { key: 'status', dir: 'asc' }).map((r) => r.info.ip)).toEqual(['1.0.0.2', '1.0.0.3', '1.0.0.1', '1.0.0.9']);
  });
  it('latency and TTL, skeletons last in both directions', () => {
    expect(sortRows([pending, ...rows], { key: 'latency', dir: 'asc' }).map((r) => r.info.ip)).toEqual(['1.0.0.2', '1.0.0.3', '1.0.0.1', '1.0.0.9']);
    expect(sortRows([pending, ...rows], { key: 'ttl', dir: 'desc' }).map((r) => r.info.ip)).toEqual(['1.0.0.3', '1.0.0.1', '1.0.0.2', '1.0.0.9']);
  });
  it('answers without latency (timeouts) stay last in both directions', () => {
    const t = rowsOf(ev('1.0.0.7', 'timeout', { latencyMs: null, ttl: null }))[0];
    expect(sortRows([t, ...rows], { key: 'latency', dir: 'desc' }).map((r) => r.info.ip)).toEqual(['1.0.0.1', '1.0.0.3', '1.0.0.2', '1.0.0.7']);
    expect(sortRows([t, ...rows], { key: 'latency', dir: 'asc' }).at(-1)!.info.ip).toBe('1.0.0.7');
  });
  it('MX values by preference', () => {
    expect(sortValues(['20 b.', '5 a.', '10 c.'])).toEqual(['5 a.', '10 c.', '20 b.']);
    expect(sortValues(['b', 'a'])).toEqual(['b', 'a']);
  });
  it('continent then country, French names in alphabetical order', () => {
    const g = groupRows(
      rowsOf(
        ev('a', 'fresh', { country_code: 'DE', continent: 'EU' }),
        ev('b', 'stale', { country_code: 'AT', continent: 'EU' }),
        ev('c', 'fresh', { country_code: 'JP', continent: 'AS' }),
        ev('d', 'fresh', { country_code: 'XX', continent: null }),
      ),
      { EU: 'Europe', AS: 'Asie' },
      (cc) => ({ DE: 'Allemagne', AT: 'Autriche', JP: 'Japon' })[cc] ?? cc,
      { key: 'name', dir: 'asc' },
    );
    expect(g.map((c) => c.name)).toEqual(['Asie', 'Europe', 'Autres']);
    expect(g[1].countries.map((c) => c.name)).toEqual(['Allemagne', 'Autriche']);
    expect(g[1].counts).toMatchObject({ total: 2, fresh: 1, stale: 1 });
  });
});

describe('map spreading', () => {
  it('points at the same spot are spread, isolated points untouched', () => {
    const out = spreadPoints(
      [
        { ip: 'b', x: 100, y: 100 },
        { ip: 'a', x: 100, y: 100 },
        { ip: 'c', x: 100.5, y: 100 },
        { ip: 'z', x: 400, y: 200 },
      ],
      6,
    );
    const at = (ip: string) => out.find((p) => p.ip === ip)!;
    expect(at('z')).toEqual({ ip: 'z', x: 400, y: 200 });
    const cluster = ['a', 'b', 'c'].map(at);
    for (let i = 0; i < cluster.length; i++)
      for (let j = i + 1; j < cluster.length; j++) expect(Math.hypot(cluster[i].x - cluster[j].x, cluster[i].y - cluster[j].y)).toBeGreaterThan(3);
    // deterministic
    expect(spreadPoints([{ ip: 'a', x: 1, y: 1 }, { ip: 'b', x: 1, y: 1 }], 6)).toEqual(spreadPoints([{ ip: 'b', x: 1, y: 1 }, { ip: 'a', x: 1, y: 1 }], 6));
  });
  it('keyboard goes west to east', () => {
    expect(keyboardOrder([{ ip: 'tokyo', x: 800, y: 150 }, { ip: 'paris', x: 480, y: 100 }, { ip: 'lima', x: 250, y: 300 }])).toEqual(['lima', 'paris', 'tokyo']);
  });
});

describe('helpers', () => {
  it('operator names without the AS handle', () => {
    expect(cleanProvider('PUBNIX2-ASN - PubNIX, Inc.')).toBe('PubNIX, Inc.');
    expect(cleanProvider('MEDIANETPVTLTD-AS-AP - Media Net Pvt Ltd')).toBe('Media Net Pvt Ltd');
    expect(cleanProvider('Andorra Telecom, S.a.u.')).toBe('Andorra Telecom, S.a.u.');
    expect(cleanProvider('ALPHA TELECOMMUNICATION MALI-ATEL-S.A - ALPHA TELECOMMUNICATION MALI-ATEL-S.A')).toBe('ALPHA TELECOMMUNICATION MALI-ATEL-S.A');
    expect(cleanProvider(null)).toBe('');
  });
  it('stream URL of a full run and of a watch round', () => {
    expect(streamUrl('exemple.fr', 'MX', null, null)).toBe('/api/propagation/stream?name=exemple.fr&type=MX');
    expect(streamUrl('exemple.fr', 'A', '1.2.3.4', ['8.8.8.8', '1.1.1.1'])).toBe('/api/propagation/stream?name=exemple.fr&type=A&expected=1.2.3.4&onlyPending=1&ips=8.8.8.8%2C1.1.1.1');
  });
});
