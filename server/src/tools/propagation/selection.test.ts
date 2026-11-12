// US-061 / US-062: default selection, geographic filters, IP family.
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../../app.js';
import { COOKIE, makeToken } from '../../auth.js';
import { openDb, setDb, type DB } from '../../db.js';
import { CheckError } from './check.js';
import { tool } from './index.js';
import { detectIpv6 } from './job.js';
import { computeDefaultSelection, filterCounts, parseFilters, selectResolvers } from './selection.js';
import { loadSeed, regionOf, type Candidate } from './store.js';
import type { SeedResolver } from './types.js';

const c = (ip: string, cc: string | null, extra: Partial<Candidate> = {}): Candidate =>
  ({ ip, name: ip, provider: ip, country_code: cc, anycast: 0, filtering: 'none', qualified: 1, dnssec: 1, latency_ms: 50, group: 'local', ...extra }) as Candidate;

const POOL: Candidate[] = [
  c('8.8.8.8', 'US', { anycast: 1, provider: 'Google', latency_ms: 10 }),
  c('2001:4860:4860::8888', 'US', { anycast: 1, provider: 'Google', latency_ms: 10 }),
  c('1.1.1.1', 'US', { anycast: 1, provider: 'Cloudflare', latency_ms: 9 }),
  c('2606:4700:4700::1111', 'US', { anycast: 1, provider: 'Cloudflare' }),
  c('2620:fe::fe', 'CH', { anycast: 1, provider: 'Quad9' }),
  c('2a10:50c0::ad1:ff', 'CY', { anycast: 1, provider: 'AdGuard' }),
  c('1.1.1.2', 'US', { anycast: 1, provider: 'Cloudflare malware', filtering: 'malware' }),
  c('10.0.0.1', 'FR', { latency_ms: 10 }), // 155 Europe occidentale
  c('10.0.0.2', 'DE', { latency_ms: 12 }), // 155 again: same region, skipped
  c('10.0.0.3', 'ES', { latency_ms: 30 }), // 039 Europe méridionale
  c('10.0.0.4', 'IT', { latency_ms: 20 }), // 039
  c('10.0.0.5', 'JP', { latency_ms: 250 }),
  c('10.0.0.6', 'BR', { latency_ms: 200 }),
  c('2001:db8::5', 'FR', {}),
];

describe('regions', () => {
  it('maps countries to UN M49 sub-regions with French names', () => {
    expect(regionOf('FR')).toEqual({ code: '155', name: 'Europe occidentale' });
    expect(regionOf('ES')).toEqual({ code: '039', name: 'Europe méridionale' });
    expect(regionOf('MX')).toEqual({ code: '013', name: 'Amérique centrale' });
    expect(regionOf('NG')?.code).toBe('011');
    expect(regionOf('TW')?.code).toBe('030');
  });
});

describe('parseFilters', () => {
  it('defaults to the default selection, switches to all with a geographic filter', () => {
    expect(parseFilters({})).toEqual({ scope: 'default', continents: [], regions: [], countries: [], family: 'any' });
    expect(parseFilters({ continents: 'eu, na' })).toMatchObject({ scope: 'all', continents: ['EU', 'NA'] });
    expect(parseFilters({ countries: 'fr', scope: 'default' })).toMatchObject({ scope: 'default', countries: ['FR'] });
    expect(parseFilters({ regions: '39,155', family: '6' })).toMatchObject({ regions: ['039', '155'], family: '6' });
  });
  it('rejects unknown values', () => {
    expect(() => parseFilters({ continents: 'XX' })).toThrow(CheckError);
    expect(() => parseFilters({ regions: '999' })).toThrow(/999/);
    expect(() => parseFilters({ family: '5' })).toThrow(/family/);
    expect(() => parseFilters({ scope: 'some' })).toThrow(/scope/);
  });
});

describe('selectResolvers', () => {
  const ips = (f: Record<string, string>) => selectResolvers(POOL, parseFilters({ scope: 'all', ...f }), []).map((r) => r.ip);
  it('geographic filters are a union and keep unicast resolvers only', () => {
    expect(ips({ countries: 'FR' })).toEqual(['10.0.0.1', '2001:db8::5']);
    expect(ips({ regions: '039', countries: 'JP' })).toEqual(['10.0.0.3', '10.0.0.4', '10.0.0.5']);
    expect(ips({ continents: 'SA' })).toEqual(['10.0.0.6']);
  });
  it('filters by IP family', () => {
    expect(ips({ family: '6' })).toEqual(['2001:4860:4860::8888', '2606:4700:4700::1111', '2620:fe::fe', '2a10:50c0::ad1:ff', '2001:db8::5']);
    expect(ips({ family: '4', countries: 'FR' })).toEqual(['10.0.0.1']);
  });
  it('scope default keeps only the default selection', () => {
    expect(selectResolvers(POOL, parseFilters({}), ['8.8.8.8', '10.0.0.5']).map((r) => r.ip)).toEqual(['8.8.8.8', '10.0.0.5']);
  });
});

describe('computeDefaultSelection', () => {
  it('unfiltered anycast in IPv4, up to 3 in IPv6, 2 per continent from distinct regions', () => {
    const s = computeDefaultSelection(POOL, []);
    expect(s).toContain('8.8.8.8');
    expect(s).toContain('1.1.1.1');
    expect(s).not.toContain('1.1.1.2'); // filtering
    expect(s.filter((ip) => ip.includes(':') && POOL.find((p) => p.ip === ip)!.anycast)).toHaveLength(3);
    expect(s).toContain('10.0.0.1'); // FR, lowest latency in 155
    expect(s).not.toContain('10.0.0.2'); // DE, same region as FR
    expect(s).toContain('10.0.0.4'); // IT before ES (latency) in 039
    expect(s).toContain('10.0.0.5');
    expect(s).toContain('10.0.0.6');
  });
  it('keeps yesterday members while they are qualified (stable list)', () => {
    const s = computeDefaultSelection(POOL, ['10.0.0.2', '10.0.0.3']);
    expect(s).toContain('10.0.0.2');
    expect(s).toContain('10.0.0.3');
    expect(s).not.toContain('10.0.0.1');
    expect(s).not.toContain('10.0.0.4');
  });
  it('counts per filter value', () => {
    const k = filterCounts(POOL);
    expect(k.families).toEqual({ '4': 9, '6': 5 });
    expect(k.regions['155']).toBe(3);
    expect(k.continents.EU).toBe(5);
    expect(k.countries.FR).toBe(2);
  });
});

describe('HTTP: filters and IPv6', () => {
  let db: DB;
  let base: string;
  let close: () => Promise<void>;
  const cookie = () => `${COOKIE}=${makeToken()}`;
  const seed = (ip: string, cc: string, anycast = false): SeedResolver => ({
    ip, name: ip, provider: ip, asn: null, country_code: cc, city: null, lat: null, lon: null,
    geo_precision: null, anycast, filtering: 'none', source: 'test', group: anycast ? 'global' : 'local',
  });
  beforeAll(async () => {
    db = openDb(':memory:');
    setDb(db);
    loadSeed(db, [seed('8.8.8.8', 'US', true), seed('2001:4860:4860::8888', 'US', true), seed('9.9.9.10', 'CH')]);
    db.prepare('UPDATE resolvers SET qualified = 1').run();
    const { app } = await buildApp({ db, tools: [tool] });
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
    close = () => app.close();
  });
  afterAll(async () => close?.());

  it('rejects a bad filter with 400', async () => {
    const r = await fetch(`${base}/api/propagation/stream?name=example.com&continents=XX`, { headers: { cookie: cookie() } });
    expect(r.status).toBe(400);
    expect(await r.json()).toMatchObject({ error: 'bad_filter' });
  });
  it('family=6 depends on outgoing IPv6, with a clear error when absent', { timeout: 30000 }, async () => {
    const v6 = await detectIpv6();
    const r = await fetch(`${base}/api/propagation/stream?name=example.com&family=6&scope=all`, { headers: { cookie: cookie() } });
    if (!v6.available) {
      expect(r.status).toBe(503);
      expect(await r.json()).toEqual({ error: 'ipv6_unavailable', message: 'IPv6 non disponible depuis ce serveur' });
    } else {
      const t = await r.text();
      expect(t).toContain('"ip":"2001:4860:4860::8888"');
      expect(t).toContain('"family":6');
      expect(t).not.toContain('"ip":"8.8.8.8"');
    }
  });
  it('resolvers endpoint exposes region, family, default selection and counts', async () => {
    const r = await (await fetch(`${base}/api/propagation/resolvers`, { headers: { cookie: cookie() } })).json();
    expect(r.countries[0].resolvers[0]).toMatchObject({ ip: '9.9.9.10', region: { code: '155', name: 'Europe occidentale' }, family: 4 });
    expect(r.defaultSelection.sort()).toEqual(['2001:4860:4860::8888', '8.8.8.8', '9.9.9.10']);
    expect(r.counts).toEqual({ continents: { EU: 1 }, regions: { '155': 1 }, countries: { CH: 1 }, families: { '4': 2, '6': 1 } });
    expect(r.regions['155']).toEqual({ name: 'Europe occidentale', continent: 'EU' });
  });
});
