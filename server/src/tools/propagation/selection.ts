// Which resolvers a check asks (US-061, US-062): default selection, geographic filters, IP family.
import { t } from '../../i18n.js';
import type { DB } from '../../db.js';
import { getSetting, setSetting } from '../../db.js';
import { CheckError } from './check.js';
import { continentNames, continentOf, familyOf, qualifiedResolvers, regionOf, regionTable, type Candidate } from './store.js';

export interface Filters {
  scope: 'default' | 'all';
  continents: string[];
  regions: string[];
  countries: string[];
  family: 'any' | '4' | '6';
}

const list = (v: unknown) =>
  String(v ?? '')
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

/**
 * scope: 'default' (about 30 representative resolvers) or 'all' (every qualified one). When
 * omitted: 'default' without geographic filter, 'all' as soon as one is given.
 * continents, regions (UN M49 codes), countries (ISO 3166 alpha-2): comma lists, combined as a
 * union; they select unicast resolvers only (an anycast address has no country).
 * family: 4, 6 or any (default).
 */
export function parseFilters(q: Record<string, unknown>): Filters {
  const continents = list(q.continents).map((c) => c.toUpperCase());
  const regions = list(q.regions).map((r) => r.padStart(3, '0'));
  const countries = list(q.countries).map((c) => c.toUpperCase());
  const knownContinents = continentNames();
  const bad = [
    ...continents.filter((c) => !knownContinents[c]),
    ...regions.filter((r) => !regionTable().regions[r]),
    ...countries.filter((c) => !/^[A-Z]{2}$/.test(c)),
  ];
  if (bad.length) throw new CheckError('bad_filter', t('Filtre inconnu : {list}', { list: bad.join(', ') }));
  const fam = String(q.family ?? 'any').toLowerCase();
  if (!['any', '4', '6'].includes(fam)) throw new CheckError('bad_filter', t('family doit valoir 4, 6 ou any'));
  const geo = continents.length + regions.length + countries.length > 0;
  const scopeRaw = q.scope == null || q.scope === '' ? (geo ? 'all' : 'default') : String(q.scope);
  if (scopeRaw !== 'default' && scopeRaw !== 'all') throw new CheckError('bad_filter', t('scope doit valoir default ou all'));
  return { scope: scopeRaw, continents, regions, countries, family: fam as Filters['family'] };
}

export function selectResolvers(qualified: Candidate[], f: Filters, defaultIps: string[]): Candidate[] {
  const def = new Set(defaultIps);
  const geo = f.continents.length + f.regions.length + f.countries.length > 0;
  return qualified.filter((r) => {
    if (f.scope === 'default' && !def.has(r.ip)) return false;
    if (f.family !== 'any' && String(familyOf(r.ip)) !== f.family) return false;
    if (!geo) return true;
    if (r.anycast) return false;
    return (
      f.countries.includes(r.country_code ?? '') ||
      f.regions.includes(regionOf(r.country_code)?.code ?? '') ||
      f.continents.includes(continentOf(r.country_code) ?? '')
    );
  });
}

const DEFAULT_KEY = 'propagation.defaultSelection';
const CONTINENTS = ['AF', 'AS', 'EU', 'NA', 'OC', 'SA'];

/**
 * About 30 resolvers: every unfiltered anycast service in IPv4, up to 3 of them in IPv6, and per
 * continent 2 unicast IPv4 resolvers from different sub-regions. Yesterday's members are kept
 * while they stay qualified, so the list is stable from one day to the next; then DNSSEC, then
 * latency.
 */
export function computeDefaultSelection(qualified: Candidate[], previous: string[]): string[] {
  const prev = new Set(previous);
  const rank = (a: Candidate, b: Candidate) =>
    Number(prev.has(b.ip)) - Number(prev.has(a.ip)) || (b.dnssec ?? 0) - (a.dnssec ?? 0) || (a.latency_ms ?? 1e9) - (b.latency_ms ?? 1e9);
  const unfiltered = (r: Candidate) => !r.filtering || r.filtering === 'none';
  const out: string[] = [];
  out.push(...qualified.filter((r) => r.anycast && unfiltered(r) && familyOf(r.ip) === 4).sort(rank).map((r) => r.ip));
  out.push(...qualified.filter((r) => r.anycast && unfiltered(r) && familyOf(r.ip) === 6).sort(rank).slice(0, 3).map((r) => r.ip));
  for (const c of CONTINENTS) {
    const pool = qualified.filter((r) => !r.anycast && familyOf(r.ip) === 4 && continentOf(r.country_code) === c).sort(rank);
    const seenRegions = new Set<string>();
    for (const r of pool) {
      const reg = regionOf(r.country_code)?.code ?? r.country_code ?? r.ip;
      if (seenRegions.has(reg)) continue;
      seenRegions.add(reg);
      out.push(r.ip);
      if (seenRegions.size >= 2) break;
    }
  }
  return out;
}

export function refreshDefaultSelection(db: DB): string[] {
  const prev = getSetting<{ ips: string[] } | null>(DEFAULT_KEY, null, db)?.ips ?? [];
  const ips = computeDefaultSelection(qualifiedResolvers(db), prev);
  setSetting(DEFAULT_KEY, { ips, computedAt: new Date().toISOString() }, db);
  return ips;
}

/** Stored selection restricted to resolvers still qualified (computed once if absent). */
export function defaultSelection(db: DB): string[] {
  const stored = getSetting<{ ips: string[] } | null>(DEFAULT_KEY, null, db);
  if (!stored) return refreshDefaultSelection(db);
  const q = new Set(qualifiedResolvers(db).map((r) => r.ip));
  return stored.ips.filter((ip) => q.has(ip));
}

export interface FilterCounts {
  continents: Record<string, number>;
  regions: Record<string, number>;
  countries: Record<string, number>;
  families: Record<string, number>;
}

/** Qualified resolvers per filter value (geographic counts: unicast only). */
export function filterCounts(qualified: Candidate[]): FilterCounts {
  const c: FilterCounts = { continents: {}, regions: {}, countries: {}, families: {} };
  const inc = (m: Record<string, number>, k: string | null | undefined) => {
    if (k) m[k] = (m[k] ?? 0) + 1;
  };
  for (const r of qualified) {
    inc(c.families, String(familyOf(r.ip)));
    if (r.anycast) continue;
    inc(c.continents, continentOf(r.country_code));
    inc(c.regions, regionOf(r.country_code)?.code);
    inc(c.countries, r.country_code);
  }
  return c;
}
