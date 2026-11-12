// Shapes shared by the propagation engine, its routes and the seed builder.

/** One entry of server/data-seed/resolvers.json (a candidate, never trusted as such). */
export interface SeedResolver {
  ip: string;
  name: string;
  provider: string;
  asn: number | null;
  country_code: string;
  city: string | null;
  lat: number | null;
  lon: number | null;
  /** 'city' when the coordinates are a city, 'country' when they are the country centroid. */
  geo_precision: 'city' | 'country' | null;
  /** Set when the current geolocation disagrees with the older public-dns.info one. */
  geo_note?: string;
  anycast: boolean;
  /** none | malware | ads | adult | family */
  filtering: string;
  source: string;
  /** 'global': documented anycast public resolver; 'local': unicast resolver in its country. */
  group: 'global' | 'local';
}

/** A resolver as stored in the `resolvers` table, joined with the tool's own state. */
export interface ResolverRow {
  ip: string;
  name: string | null;
  provider: string | null;
  country_code: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  anycast: number;
  filtering: string | null;
  source: string | null;
  created_at: number;
  qualified_at: number | null;
  qualified: number;
  latency_ms: number | null;
  reasons: string | null;
}

export type CheckId =
  | 'no_answer'
  | 'refused'
  | 'servfail'
  | 'no_recursion'
  | 'wrong_answer'
  | 'nxdomain_lie'
  | 'rewrites_answers'
  | 'ipv6_unavailable'
  | 'unstable'
  | 'too_slow'
  | 'geo_implausible'
  | 'not_selected_country_cap'
  | 'not_selected_provider_cap'
  | 'quarantined'
  | 'no_country';
