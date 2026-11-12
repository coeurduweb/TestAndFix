// "Où" filters of the propagation page (Signal, 2026-11-11): one chip per continent with the
// flags of its three countries that have the most resolvers, and the options of the "Pays…"
// popover (countries, and UN sub-regions when the search names one), with an accent-blind search
// on the name, the ISO code or the continent. Pure, unit tested in places.test.ts.
import { locale, msg, t } from '../../lib/i18n';
import type { ResolverInfo } from './model';
import type { Facet } from './selection';

export interface ContinentChip {
  /** chip id: a continent code, or AM for both Americas */
  id: string;
  name: string;
  /** continent codes of the stream this chip selects */
  codes: string[];
  count: number;
  /** the three countries with the most local resolvers, most first */
  flags: string[];
}

/** The Americas are one chip, as in the validated mockup; any other code keeps its own chip. */
const GROUPS: { id: string; name: string; codes: string[] }[] = [
  { id: 'EU', name: msg('Europe'), codes: ['EU'] },
  { id: 'AM', name: msg('Amériques'), codes: ['NA', 'SA'] },
  { id: 'AS', name: msg('Asie'), codes: ['AS'] },
  { id: 'AF', name: msg('Afrique'), codes: ['AF'] },
  { id: 'OC', name: msg('Océanie'), codes: ['OC'] },
];

/** Chip of a continent code ("NA" belongs to "AM"). */
export function chipOf(code: string | null | undefined): string | null {
  if (!code) return null;
  return GROUPS.find((g) => g.codes.includes(code))?.id ?? code;
}

export function continentChips(all: ResolverInfo[], names: Record<string, string> = {}, countryName: (cc: string) => string = (cc) => cc): ContinentChip[] {
  const local = all.filter((r) => !r.anycast && r.continent);
  const groups = GROUPS.map((g) => ({ ...g, name: t(g.name) }));
  for (const c of new Set(local.map((r) => r.continent!))) if (!groups.some((g) => g.codes.includes(c))) groups.push({ id: c, name: names[c] ?? c, codes: [c] });
  const out: ContinentChip[] = [];
  for (const g of groups) {
    const rs = local.filter((r) => g.codes.includes(r.continent!));
    if (!rs.length) continue;
    const per = new Map<string, number>();
    for (const r of rs) if (r.country_code) per.set(r.country_code, (per.get(r.country_code) ?? 0) + 1);
    const flags = [...per.entries()].sort((a, b) => b[1] - a[1] || countryName(a[0]).localeCompare(countryName(b[0]), locale())).slice(0, 3).map(([cc]) => cc);
    out.push({ ...g, count: rs.length, flags });
  }
  return out;
}

/** Lower case, accents removed: "Équateur" and "equateur" match. */
export const fold = (s: string) => s.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();

export interface PlaceOption {
  kind: 'country' | 'region';
  code: string;
  name: string;
  count: number;
  /** chip id of its continent (EU, AM, AS...), '' when unknown */
  cont: string;
  contName: string;
}

/** Countries of the popover, with their continent chip. */
export function countryOptions(countries: Facet[], all: ResolverInfo[], chips: ContinentChip[]): PlaceOption[] {
  const contOf = new Map<string, string>();
  for (const r of all) if (!r.anycast && r.country_code && r.continent && !contOf.has(r.country_code)) contOf.set(r.country_code, chipOf(r.continent)!);
  return countries.map((c) => {
    const cont = contOf.get(c.code) ?? '';
    return { kind: 'country', code: c.code, name: c.name, count: c.count, cont, contName: chips.find((x) => x.id === cont)?.name ?? '' };
  });
}

/** UN sub-regions, offered only when the search names one (or when already picked). */
export function regionOptions(regions: Facet[], all: ResolverInfo[], chips: ContinentChip[]): PlaceOption[] {
  type R = ResolverInfo & { region?: string | { code: string } | null };
  const contOf = new Map<string, string>();
  for (const r of all as R[]) {
    const code = typeof r.region === 'string' ? r.region : r.region?.code;
    if (code && r.continent && !contOf.has(code)) contOf.set(code, chipOf(r.continent)!);
  }
  return regions.map((g) => {
    const cont = contOf.get(g.code) ?? '';
    return { kind: 'region', code: g.code, name: g.name, count: g.count, cont, contName: chips.find((x) => x.id === cont)?.name ?? '' };
  });
}

/**
 * What the popover lists for a query: countries whose name contains it, whose ISO code is it, or
 * whose continent starts with it; regions only when their name contains it (3 letters at least)
 * or when picked. Names that start with the query come first, then alphabetical order.
 */
export function searchPlaces(countries: PlaceOption[], regions: PlaceOption[], query: string, cont = '', picked: ReadonlySet<string> = new Set()): PlaceOption[] {
  const q = fold(query.trim());
  const inCont = (o: PlaceOption) => !cont || o.cont === cont;
  const hit = (o: PlaceOption) => !q || fold(o.name).includes(q) || o.code.toLowerCase() === q || (!!o.contName && fold(o.contName).startsWith(q));
  const regs = regions.filter((o) => inCont(o) && ((q.length >= 3 && fold(o.name).includes(q)) || (!q && picked.has(`region:${o.code}`))));
  const list = countries.filter((o) => inCont(o) && hit(o));
  const order = (a: PlaceOption, b: PlaceOption) =>
    q ? Number(fold(b.name).startsWith(q)) - Number(fold(a.name).startsWith(q)) || a.name.localeCompare(b.name, locale()) : a.name.localeCompare(b.name, locale());
  return [...regs.sort(order), ...list.sort(order)];
}

export const optionKey = (o: Pick<PlaceOption, 'kind' | 'code'>) => `${o.kind}:${o.code}`;
