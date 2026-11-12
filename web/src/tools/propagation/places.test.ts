import { describe, expect, it } from 'vitest';
import { chipOf, continentChips, countryOptions, fold, regionOptions, searchPlaces } from './places';
import type { ResolverInfo } from './model';

const r = (ip: string, cc: string, continent: string, extra: Partial<ResolverInfo> & { region?: { code: string } } = {}): ResolverInfo =>
  ({ ip, name: null, provider: null, asn: null, country_code: cc, continent, city: null, lat: null, lon: null, anycast: false, group: 'local', filtering: null, dnssec: null, latencyMs: null, ...extra }) as ResolverInfo;

const names: Record<string, string> = { FR: 'France', DE: 'Allemagne', IT: 'Italie', ES: 'Espagne', US: 'États-Unis', BR: 'Brésil', EC: 'Équateur', AL: 'Albanie', JP: 'Japon' };
const cn = (cc: string) => names[cc] ?? cc;
const all = [
  r('1', 'FR', 'EU', { region: { code: '155' } }), r('2', 'FR', 'EU', { region: { code: '155' } }), r('3', 'DE', 'EU', { region: { code: '155' } }),
  r('4', 'IT', 'EU'), r('5', 'ES', 'EU'), r('6', 'ES', 'EU'), r('7', 'AL', 'EU'),
  r('8', 'US', 'NA'), r('9', 'BR', 'SA'), r('10', 'EC', 'SA'), r('11', 'JP', 'AS'),
  r('12', 'US', 'NA', { anycast: true, group: 'global' }),
];

describe('continent chips', () => {
  const chips = continentChips(all, {}, cn);
  it('one chip per continent with local resolvers, the Americas together', () => {
    expect(chips.map((c) => [c.id, c.count])).toEqual([['EU', 7], ['AM', 3], ['AS', 1]]);
    expect(chips.find((c) => c.id === 'AM')!.codes).toEqual(['NA', 'SA']);
    expect(chipOf('SA')).toBe('AM');
  });
  it('shows the three countries with the most resolvers, most first, then by name', () => {
    expect(chips[0].flags).toEqual(['ES', 'FR', 'AL']);
  });
});

describe('country search', () => {
  const chips = continentChips(all, {}, cn);
  const facets = [...new Set(all.filter((x) => !x.anycast).map((x) => x.country_code!))].map((code) => ({ code, name: cn(code), count: all.filter((x) => !x.anycast && x.country_code === code).length }));
  const countries = countryOptions(facets, all, chips);
  const regions = regionOptions([{ code: '155', name: 'Europe de l’Ouest', count: 3 }], all, chips);
  const names = (q: string, cont = '') => searchPlaces(countries, regions, q, cont).map((o) => o.name);
  it('ignores accents and case', () => {
    expect(names('equateur')).toEqual(['Équateur']);
    expect(names('ÉTATS')).toEqual(['États-Unis']);
  });
  it('matches the ISO code and the continent', () => {
    expect(names('jp')).toEqual(['Japon']);
    expect(names('amér')).toEqual(['Brésil', 'Équateur', 'États-Unis']);
  });
  it('puts the names that start with the query first', () => {
    expect(names('al')).toEqual(['Albanie', 'Allemagne', 'Italie']);
  });
  it('offers a sub-region when the search names it', () => {
    expect(searchPlaces(countries, regions, 'ouest').map((o) => `${o.kind}:${o.code}`)).toEqual(['region:155']);
    expect(searchPlaces(countries, regions, 'ou').some((o) => o.kind === 'region')).toBe(false);
  });
  it('filters by continent chip', () => {
    expect(names('', 'AM')).toEqual(['Brésil', 'Équateur', 'États-Unis']);
  });
  it('folds', () => expect(fold('Côte d’Ivoire')).toBe('cote d’ivoire'));
});
