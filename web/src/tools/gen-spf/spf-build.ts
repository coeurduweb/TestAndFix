// SPF generator model: parse an existing record, accept typed addresses, build the record and
// count its DNS lookups (RFC 7208 §4.6.4: include, a, mx, ptr, exists and redirect count, limit 10).
// Pure functions, unit tested in spf-build.test.ts.
import { isIp } from '../../lib/detect';

export const SPF_LOOKUP_LIMIT = 10;
export type AllQualifier = '~' | '-';

/** Where a cost comes from, said next to the figure. */
export type CostSource =
  | 'fixed' // a, mx, ptr, exists: exactly one lookup
  | 'reference' // official include, measured on COSTS_MEASURED_ON
  | 'dns' // read from the live SPF tree of the domain, or measured just now
  | 'estimated'; // unknown include: 1 for itself, its own lookups unknown

export interface SpfInclude {
  domain: string;
  /** Lookups of the include: 1 + those of its target. */
  cost: number;
  source: CostSource;
  providerKey?: string;
}

export interface SpfModel {
  ip4: string[];
  ip6: string[];
  a: boolean;
  mx: boolean;
  includes: SpfInclude[];
  /** Terms kept verbatim from the existing record (ptr, exists:, a:host, mx:host, redirect=, exp=). */
  others: string[];
  all: AllQualifier;
  /** The domain never sends mail: v=spf1 -all. */
  noMail: boolean;
}

export interface BuiltTerm {
  term: string;
  cost: number;
  source: CostSource | 'free';
}

export interface BuiltSpf {
  record: string;
  terms: BuiltTerm[];
  lookups: number;
  /** Some costs are estimates: the true total may be higher. */
  estimated: boolean;
  overLimit: boolean;
  /** redirect= kept: the final all is left out (RFC 7208 §6.1, it would make redirect useless). */
  redirect?: string;
}

const MECH = /^([+~?-]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?=$|[:/])/i;

/** Lookups caused by a raw term other than include (whose cost depends on its target). */
export function rawTermCost(term: string): number {
  const t = term.toLowerCase();
  if (/^redirect=/.test(t)) return 1;
  if (/^exp=/.test(t)) return 0;
  const m = MECH.exec(t);
  if (!m) return 0;
  return ['a', 'mx', 'ptr', 'exists', 'include'].includes(m[2]) ? 1 : 0;
}

export function emptyModel(): SpfModel {
  return { ip4: [], ip6: [], a: false, mx: false, includes: [], others: [], all: '~', noMail: false };
}

export interface ParsedSpf {
  ip4: string[];
  ip6: string[];
  a: boolean;
  mx: boolean;
  includes: string[];
  others: string[];
  all?: string;
}

/** Split an existing record into the parts the generator edits. Unknown terms are kept as is. */
export function parseSpfRecord(record: string): ParsedSpf {
  const out: ParsedSpf = { ip4: [], ip6: [], a: false, mx: false, includes: [], others: [] };
  const terms = record.trim().replace(/^"|"$/g, '').split(/\s+/).filter(Boolean);
  for (const raw of terms) {
    if (/^v=spf1$/i.test(raw)) continue;
    const m = MECH.exec(raw);
    const q = m?.[1] ?? '';
    const mech = m?.[2]?.toLowerCase();
    const rest = m ? raw.slice(m[0].length) : '';
    if (mech === 'all') {
      out.all = q || '+';
      continue;
    }
    if ((q === '' || q === '+') && mech === 'ip4' && rest.startsWith(':')) out.ip4.push(rest.slice(1));
    else if ((q === '' || q === '+') && mech === 'ip6' && rest.startsWith(':')) out.ip6.push(rest.slice(1));
    else if ((q === '' || q === '+') && mech === 'include' && rest.startsWith(':')) out.includes.push(rest.slice(1).toLowerCase().replace(/\.$/, ''));
    else if ((q === '' || q === '+') && mech === 'a' && rest === '') out.a = true;
    else if ((q === '' || q === '+') && mech === 'mx' && rest === '') out.mx = true;
    else out.others.push(raw);
  }
  return out;
}

const V4_CIDR = /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/;

export interface IpParse {
  ip4: string[];
  ip6: string[];
  errors: string[];
  /** Ranges wider than /16 (IPv4) or /32 (IPv6): see knowledge spf.range_too_broad. */
  broad: string[];
}

/** Tolerant address input: spaces, commas, new lines, "ip4:" prefixes, CIDR ranges. */
export function parseIpInput(raw: string): IpParse {
  const out: IpParse = { ip4: [], ip6: [], errors: [], broad: [] };
  for (let tok of raw.split(/[\s,;]+/).filter(Boolean)) {
    tok = tok.replace(/^\+?ip[46]:/i, '');
    const v4 = V4_CIDR.exec(tok);
    if (v4) {
      const prefix = v4[2] === undefined ? 32 : Number(v4[2]);
      if (!isIp(v4[1]) || prefix > 32) {
        out.errors.push(tok);
        continue;
      }
      const value = prefix === 32 ? v4[1] : `${v4[1]}/${prefix}`;
      if (prefix < 16) out.broad.push(value);
      out.ip4.push(value);
      continue;
    }
    const [addr, pre, extra] = tok.split('/');
    if (extra === undefined && addr.includes(':') && isIp(addr)) {
      const prefix = pre === undefined ? 128 : Number(pre);
      if (!/^\d{1,3}$/.test(pre ?? '128') || prefix > 128) {
        out.errors.push(tok);
        continue;
      }
      const value = prefix === 128 ? addr.toLowerCase() : `${addr.toLowerCase()}/${prefix}`;
      if (prefix < 32) out.broad.push(value);
      out.ip6.push(value);
      continue;
    }
    out.errors.push(tok);
  }
  return out;
}

const uniq = <T,>(xs: T[], key: (x: T) => string = String) => {
  const seen = new Set<string>();
  return xs.filter((x) => {
    const k = key(x);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
};

/** Compose the record. Order: addresses (free), a, mx, includes, other terms, then all or redirect. */
export function buildSpf(m: SpfModel): BuiltSpf {
  if (m.noMail) return { record: 'v=spf1 -all', terms: [{ term: '-all', cost: 0, source: 'free' }], lookups: 0, estimated: false, overLimit: false };
  const terms: BuiltTerm[] = [];
  for (const ip of uniq(m.ip4)) terms.push({ term: `ip4:${ip}`, cost: 0, source: 'free' });
  for (const ip of uniq(m.ip6)) terms.push({ term: `ip6:${ip}`, cost: 0, source: 'free' });
  if (m.a) terms.push({ term: 'a', cost: 1, source: 'fixed' });
  if (m.mx) terms.push({ term: 'mx', cost: 1, source: 'fixed' });
  for (const inc of uniq(m.includes, (i) => i.domain.toLowerCase())) terms.push({ term: `include:${inc.domain}`, cost: inc.cost, source: inc.source });
  const others = uniq(m.others, (o) => o.toLowerCase());
  const redirect = others.find((o) => /^redirect=/i.test(o));
  for (const o of others) {
    if (o === redirect || /^[+~?-]?all$/i.test(o)) continue;
    const c = rawTermCost(o);
    terms.push({ term: o, cost: c, source: c ? 'estimated' : 'free' });
  }
  if (redirect) terms.push({ term: redirect, cost: 1, source: 'estimated' });
  else terms.push({ term: `${m.all}all`, cost: 0, source: 'free' });
  const lookups = terms.reduce((n, t) => n + t.cost, 0);
  return {
    record: ['v=spf1', ...terms.map((t) => t.term)].join(' '),
    terms,
    lookups,
    estimated: terms.some((t) => t.source === 'estimated'),
    overLimit: lookups > SPF_LOOKUP_LIMIT,
    redirect: redirect?.slice('redirect='.length),
  };
}

/** Valid include target: a DNS name, macros allowed (they cost one lookup like any include). */
export function cleanIncludeTarget(raw: string): string | undefined {
  const s = raw.trim().replace(/^\+?include:/i, '').replace(/\.$/, '').toLowerCase();
  if (/^(?=.{1,253}$)(%\{[a-z0-9._-]+\}\.?)?((?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{1,62}$/.test(s)) return s;
  return undefined;
}
