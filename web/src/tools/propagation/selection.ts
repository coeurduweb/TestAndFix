// Where to measure (US-061, US-062): a representative selection by default, everybody on request,
// or chosen continents, UN sub-regions and countries, IPv4 and/or IPv6. The page URL carries it,
// the stream receives it (scope, continents, regions, countries, family) and the page applies the
// same rule to its list, so it stays right even against a server that ignores a parameter.
// Pure, unit tested in selection.test.ts.
import { locale, msg, t } from '../../lib/i18n';
import type { ResolverInfo, ResolversPayload } from './model';

export type Family = 'any' | '4' | '6';

export interface Selection {
  /** "Tout le monde" instead of the representative selection (ignored when places are chosen). */
  all: boolean;
  continents: string[];
  regions: string[];
  countries: string[];
  family: Family;
}

export const emptySelection: Selection = { all: false, continents: [], regions: [], countries: [], family: 'any' };

const list = (v: string | null, upper = true) =>
  [...new Set((v ?? '').split(/[\s,]+/).map((x) => (upper ? x.toUpperCase() : x)).filter(Boolean))].sort();

/** Page URL: ?tout=1&continents=EU,NA&regions=155&pays=FR,DE&ip=6 */
export function readSelection(p: URLSearchParams): Selection {
  const ip = p.get('ip');
  return {
    all: p.get('tout') === '1',
    continents: list(p.get('continents')),
    regions: list(p.get('regions'), false),
    countries: list(p.get('pays')),
    family: ip === '4' || ip === '6' ? ip : 'any',
  };
}

/** Write the selection into the page query string (other parameters kept). */
export function writeSelection(p: URLSearchParams, s: Selection): URLSearchParams {
  const q = new URLSearchParams(p);
  const set = (k: string, v: string[] | string | null) => {
    const val = Array.isArray(v) ? v.join(',') : v;
    if (val) q.set(k, val);
    else q.delete(k);
  };
  set('tout', s.all ? '1' : null);
  set('continents', s.continents);
  set('regions', s.regions);
  set('pays', s.countries);
  set('ip', s.family === 'any' ? null : s.family);
  return q;
}

export const hasPlaces = (s: Selection) => s.continents.length + s.regions.length + s.countries.length > 0;

/** Query of the stream for this selection. */
export function streamQuery(s: Selection): string {
  const q = new URLSearchParams();
  q.set('scope', s.all || hasPlaces(s) ? 'all' : 'default');
  if (s.continents.length) q.set('continents', s.continents.join(','));
  if (s.regions.length) q.set('regions', s.regions.join(','));
  if (s.countries.length) q.set('countries', s.countries.join(','));
  if (s.family !== 'any') q.set('family', s.family);
  return q.toString();
}

export function familyOf(r: Pick<ResolverInfo, 'ip'> & { family?: number | string | null }): '4' | '6' {
  if (r.family === 6 || r.family === '6') return '6';
  if (r.family === 4 || r.family === '4') return '4';
  return r.ip.includes(':') ? '6' : '4';
}

type WithExtras = ResolverInfo & { region?: string | { code: string; name?: string } | null; inDefault?: boolean; default?: boolean };

/** UN M49 sub-region code of a resolver (the server sends {code, name}; a bare code is accepted). */
export function regionOf(r: ResolverInfo): string | null {
  const x = (r as WithExtras).region;
  return typeof x === 'string' ? x : x?.code ?? null;
}

/** IPs of the representative selection, as the server publishes it (several shapes accepted). */
export function serverDefaults(p: ResolversPayload | null | undefined, all: ResolverInfo[]): string[] | null {
  if (!p) return null;
  const o = p as unknown as Record<string, unknown>;
  const raw = o.defaultSelection ?? o.default ?? o.defaultIps ?? o.defaults;
  const pick = (v: unknown): string[] | null => {
    if (Array.isArray(v)) return v.map((x) => (typeof x === 'string' ? x : (x as { ip?: string })?.ip)).filter((x): x is string => !!x);
    if (v && typeof v === 'object' && Array.isArray((v as { resolvers?: unknown }).resolvers)) return pick((v as { resolvers: unknown }).resolvers);
    if (v && typeof v === 'object' && Array.isArray((v as { ips?: unknown }).ips)) return pick((v as { ips: unknown }).ips);
    return null;
  };
  const fromField = pick(raw);
  if (fromField?.length) return fromField;
  const flagged = (all as WithExtras[]).filter((r) => r.inDefault || r.default).map((r) => r.ip);
  return flagged.length ? flagged : null;
}

/**
 * Representative selection when the server publishes none: the big public resolvers, then per
 * continent the fastest resolvers with a known city, one per country, about 30 in all.
 */
export function fallbackDefaults(all: ResolverInfo[], target = 30): string[] {
  const majors = ['Google', 'Cloudflare', 'Quad9', 'OpenDNS', 'AdGuard', 'Control D'];
  const global = all
    .filter((r) => r.anycast)
    .sort((a, b) => rank(a.provider, majors) - rank(b.provider, majors) || (a.latencyMs ?? 999) - (b.latencyMs ?? 999));
  const picked: string[] = [];
  const seenProv = new Set<string>();
  for (const r of global) {
    if (picked.length >= 6) break;
    if (seenProv.has(r.provider ?? r.ip)) continue;
    seenProv.add(r.provider ?? r.ip);
    picked.push(r.ip);
  }
  const local = all.filter((r) => !r.anycast && r.continent);
  const byCont = new Map<string, ResolverInfo[]>();
  for (const r of local) byCont.set(r.continent!, [...(byCont.get(r.continent!) ?? []), r]);
  const conts = [...byCont.keys()].sort();
  const perCont = Math.max(2, Math.ceil((target - picked.length) / Math.max(1, conts.length)));
  for (const c of conts) {
    const seenCc = new Set<string>();
    const sorted = byCont.get(c)!.sort((a, b) => (a.geoPrecision === 'city' ? 0 : 1) - (b.geoPrecision === 'city' ? 0 : 1) || (a.latencyMs ?? 999) - (b.latencyMs ?? 999));
    let n = 0;
    for (const r of sorted) {
      if (n >= perCont) break;
      if (seenCc.has(r.country_code ?? '')) continue;
      seenCc.add(r.country_code ?? '');
      picked.push(r.ip);
      n++;
    }
  }
  return picked;
}

function rank(provider: string | null, order: string[]): number {
  const i = order.findIndex((m) => provider?.toLowerCase().includes(m.toLowerCase()));
  return i < 0 ? order.length : i;
}

/** Resolvers this selection asks, in the list order. */
export function selectResolvers(all: ResolverInfo[], s: Selection, defaults: string[] | null): ResolverInfo[] {
  const fam = (r: ResolverInfo) => s.family === 'any' || familyOf(r as WithExtras) === s.family;
  if (hasPlaces(s)) {
    return all.filter((r) => {
      if (!fam(r) || r.anycast) return false;
      const x = r;
      return (
        (!!r.continent && s.continents.includes(r.continent)) ||
        (!!regionOf(x) && s.regions.includes(regionOf(x)!)) ||
        (!!r.country_code && s.countries.includes(r.country_code))
      );
    });
  }
  if (s.all) return all.filter(fam);
  const d = new Set(defaults ?? fallbackDefaults(all));
  return all.filter((r) => d.has(r.ip) && fam(r));
}

/** Sub-region names published by the server ({"155": {name, continent}}), or the built-in table. */
export function regionNamesOf(p: ResolversPayload | null | undefined): Record<string, string> {
  const raw = (p as unknown as { regions?: Record<string, { name?: string } | string> } | null)?.regions;
  const builtin = Object.fromEntries(Object.entries(REGION_NAMES).map(([k, v]) => [k, t(v)]));
  if (!raw || typeof raw !== 'object') return builtin;
  const out: Record<string, string> = { ...builtin };
  for (const [k, v] of Object.entries(raw)) out[k] = typeof v === 'string' ? v : v?.name ?? out[k] ?? k;
  return out;
}

/** false when the server says it cannot reach IPv6 resolvers. */
export const ipv6Available = (p: ResolversPayload | null | undefined) => (p as unknown as { ipv6Available?: boolean | null } | null)?.ipv6Available !== false;

/** UN M49 sub-regions, French names (used when the server sends codes only): msg() ids, see builtinRegionNames(). */
export const REGION_NAMES: Record<string, string> = {
  '011': msg('Afrique de l’Ouest'),
  '014': msg('Afrique de l’Est'),
  '015': msg('Afrique du Nord'),
  '017': msg('Afrique centrale'),
  '018': msg('Afrique australe'),
  '005': msg('Amérique du Sud'),
  '013': msg('Amérique centrale'),
  '021': msg('Amérique septentrionale'),
  '029': msg('Caraïbes'),
  '030': msg('Asie de l’Est'),
  '034': msg('Asie du Sud'),
  '035': msg('Asie du Sud-Est'),
  '143': msg('Asie centrale'),
  '145': msg('Asie de l’Ouest'),
  '039': msg('Europe du Sud'),
  '151': msg('Europe de l’Est'),
  '154': msg('Europe du Nord'),
  '155': msg('Europe de l’Ouest'),
  '053': msg('Australie et Nouvelle-Zélande'),
  '054': msg('Mélanésie'),
  '057': msg('Micronésie'),
  '061': msg('Polynésie'),
};

export interface Facet {
  code: string;
  name: string;
  count: number;
}

/** Counts for the filter panel (anycast resolvers have no place). */
export function facets(all: ResolverInfo[], continentNames: Record<string, string>, countryName: (cc: string) => string, regionNames: Record<string, string> = regionNamesOf(null)) {
  const local = all.filter((r) => !r.anycast);
  const count = (key: (r: ResolverInfo) => string | null | undefined) => {
    const m = new Map<string, number>();
    for (const r of local) {
      const k = key(r);
      if (k) m.set(k, (m.get(k) ?? 0) + 1);
    }
    return m;
  };
  const toList = (m: Map<string, number>, name: (k: string) => string): Facet[] =>
    [...m.entries()].map(([code, n]) => ({ code, name: name(code), count: n })).sort((a, b) => a.name.localeCompare(b.name, locale()));
  return {
    continents: toList(count((r) => r.continent), (k) => continentNames[k] ?? k),
    regions: toList(count(regionOf), (k) => regionNames[k] ?? k),
    countries: toList(count((r) => r.country_code), countryName),
    families: { '4': all.filter((r) => familyOf(r as WithExtras) === '4').length, '6': all.filter((r) => familyOf(r as WithExtras) === '6').length },
  };
}
