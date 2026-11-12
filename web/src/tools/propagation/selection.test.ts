import { describe, expect, it } from 'vitest';
import type { ResolverInfo, ResolversPayload } from './model';
import {
  facets, fallbackDefaults, familyOf, hasPlaces, readSelection, regionNamesOf, regionOf, selectResolvers, serverDefaults, streamQuery, writeSelection,
} from './selection';

const r = (ip: string, o: Partial<ResolverInfo> & { region?: unknown; family?: number } = {}): ResolverInfo =>
  ({
    ip, name: ip, provider: 'Op ' + ip, asn: 1, country_code: 'FR', continent: 'EU', city: 'Paris', lat: 1, lon: 1, geoPrecision: 'city',
    anycast: false, group: 'local', filtering: 'none', dnssec: true, latencyMs: 20, ...o,
  }) as ResolverInfo;

const list = [
  r('8.8.8.8', { anycast: true, group: 'global', provider: 'Google', country_code: 'US', continent: 'NA' }),
  r('2001:4860:4860::8888', { anycast: true, group: 'global', provider: 'Google', country_code: 'US', continent: 'NA', family: 6 }),
  r('1.1.1.1', { anycast: true, group: 'global', provider: 'Cloudflare', country_code: 'US', continent: 'NA' }),
  r('10.0.0.1', { region: { code: '155', name: 'Europe occidentale' } }),
  r('10.0.0.2', { country_code: 'DE', region: { code: '155', name: 'Europe occidentale' }, latencyMs: 5 }),
  r('10.0.0.3', { country_code: 'IT', region: '039' }),
  r('10.0.0.4', { country_code: 'JP', continent: 'AS', region: '030' }),
];

describe('selection in the URL', () => {
  it('reads and writes back, other parameters kept', () => {
    const p = new URLSearchParams('type=MX&continents=na,eu&pays=fr&ip=6&tout=1');
    const s = readSelection(p);
    expect(s).toEqual({ all: true, continents: ['EU', 'NA'], regions: [], countries: ['FR'], family: '6' });
    expect(writeSelection(p, { ...s, all: false, continents: [], family: 'any' }).toString()).toBe('type=MX&pays=FR');
    expect(readSelection(new URLSearchParams('ip=5')).family).toBe('any');
  });
  it('stream query: default without places, all with them or on request', () => {
    expect(streamQuery(readSelection(new URLSearchParams('')))).toBe('scope=default');
    expect(streamQuery(readSelection(new URLSearchParams('tout=1&ip=4')))).toBe('scope=all&family=4');
    expect(streamQuery(readSelection(new URLSearchParams('regions=155&pays=FR,DE')))).toBe('scope=all&regions=155&countries=DE%2CFR');
    expect(hasPlaces(readSelection(new URLSearchParams('regions=155')))).toBe(true);
  });
});

describe('who is asked', () => {
  it('default list from the server, any of its shapes', () => {
    expect(serverDefaults({ defaultSelection: ['8.8.8.8', '10.0.0.1'] } as unknown as ResolversPayload, list)).toEqual(['8.8.8.8', '10.0.0.1']);
    expect(serverDefaults({ default: { resolvers: [{ ip: '1.1.1.1' }] } } as unknown as ResolversPayload, list)).toEqual(['1.1.1.1']);
    expect(serverDefaults({} as ResolversPayload, list)).toBeNull();
  });
  it('places are an union and keep the unicast resolvers only', () => {
    const s = readSelection(new URLSearchParams('regions=155&pays=JP'));
    expect(selectResolvers(list, s, null).map((x) => x.ip)).toEqual(['10.0.0.1', '10.0.0.2', '10.0.0.4']);
  });
  it('family filters every scope, anycast included', () => {
    expect(selectResolvers(list, readSelection(new URLSearchParams('tout=1&ip=6')), null).map((x) => x.ip)).toEqual(['2001:4860:4860::8888']);
    expect(familyOf({ ip: '9.9.9.9', family: 6 })).toBe('6');
    expect(familyOf({ ip: '2620:fe::fe' })).toBe('6');
  });
  it('representative fallback: big publics first, one per country per continent', () => {
    const d = fallbackDefaults(list, 6);
    expect(d.slice(0, 2)).toEqual(['8.8.8.8', '1.1.1.1']);
    expect(d).toContain('10.0.0.4');
    expect(new Set(d.filter((ip) => ip.startsWith('10.')).map((ip) => list.find((x) => x.ip === ip)!.country_code)).size).toBe(d.filter((ip) => ip.startsWith('10.')).length);
  });
});

describe('filter panel counts', () => {
  it('per continent, sub-region and country, unicast only; names from the server', () => {
    const f = facets(list, { EU: 'Europe', AS: 'Asie' }, (cc) => cc, regionNamesOf({ regions: { '155': { name: 'Europe occidentale', continent: 'EU' } } } as unknown as ResolversPayload));
    expect(f.continents).toEqual([{ code: 'AS', name: 'Asie', count: 1 }, { code: 'EU', name: 'Europe', count: 3 }]);
    expect(f.regions.find((x) => x.code === '155')).toEqual({ code: '155', name: 'Europe occidentale', count: 2 });
    expect(f.regions.find((x) => x.code === '039')?.name).toBe('Europe du Sud');
    expect(f.families).toEqual({ '4': 6, '6': 1 });
    expect(regionOf(list[3])).toBe('155');
  });
});
