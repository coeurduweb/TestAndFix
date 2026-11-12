// Merge what the CT sources returned into one row per unique name: certificates (issuer, serial,
// dates, wildcard), first and last appearance, sources. Wildcard names ("*.x") are kept apart.
import { covers } from '../../lib/ct/names.js';
import type { CtCert, CtSourceId, CtSourceResult } from '../../lib/ct/types.js';

/** A certificate as shown for one name. */
export interface CertBrief {
  source: CtSourceId;
  id: string;
  serial?: string;
  issuer: string;
  issuerShort: string;
  notBefore: string;
  notAfter: string;
  /** The name is covered through a wildcard ("*.parent") rather than written as such. */
  viaWildcard?: string;
  /** Number of names on the certificate. */
  nameCount: number;
  sha256?: string;
}

export type DnsStatus = 'active' | 'dead' | 'dangling' | 'error' | 'skipped';

export interface DnsState {
  status: DnsStatus;
  rcode: string;
  a: string[];
  aaaa: string[];
  /** CNAME chain followed, in order. */
  cname: string[];
  error?: string;
  /** The domain answers any name (wildcard DNS) and this name gets that same answer. */
  viaWildcardDns?: boolean;
}

export interface TakeoverState {
  service: string;
  level: 'vulnerable' | 'edge';
  target: string;
  /** What proves it: NXDOMAIN on the target, or the error text of the page. */
  evidence: string;
}

/** Certificate served right now on port 443, read by a TLS handshake (the truth, CT logs can lag). */
export interface ServedCert {
  ip: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysLeft?: number;
  expired: boolean;
  /** Chain trusted and name covered. */
  authorized: boolean;
  nameMatches: boolean;
  authorizationError?: string;
  fingerprint256?: string;
  /** Newer than every certificate the CT sources returned for this name (false when they returned none). */
  newerThanCt?: boolean;
  error?: string;
}

export interface SubRow {
  name: string;
  sources: CtSourceId[];
  /** Certificates naming it exactly (wildcards excluded). */
  certCount: number;
  firstSeen?: string;
  /** Start of validity of the most recent certificate naming it. */
  lastSeen?: string;
  lastCert?: CertBrief;
  /** Most recent certificates naming it (exact or through a wildcard), newest first, at most 10. */
  certs: CertBrief[];
  /** Latest end of validity among the certificates that cover it (exact or wildcard). */
  validUntil?: string;
  validUntilCert?: CertBrief;
  /** Internal-looking label (dev, staging, admin...), when one is found. */
  internal?: string;
  dns?: DnsState;
  /** Certificate served on port 443 (active names only). */
  served?: ServedCert;
  takeover?: TakeoverState;
}

export interface WildcardRow {
  /** "*.x" */
  name: string;
  certCount: number;
  firstSeen?: string;
  lastSeen?: string;
  lastCert?: CertBrief;
  validUntil?: string;
}

const brief = (c: CtCert, viaWildcard?: string): CertBrief => ({
  source: c.source,
  id: c.id,
  serial: c.serial,
  issuer: c.issuer,
  issuerShort: c.issuerShort,
  notBefore: c.notBefore,
  notAfter: c.notAfter,
  viaWildcard,
  nameCount: c.names.length,
  sha256: c.sha256,
});

const minIso = (a?: string, b?: string) => (!a ? b : !b ? a : a < b ? a : b);
const maxIso = (a?: string, b?: string) => (!a ? b : !b ? a : a > b ? a : b);

// Labels that name an environment or a tool not meant for the public. RFC 9162 §11.5: "Some
// subdomain labels may reveal information about the service and software for which the subdomain
// is used, which in turn might facilitate targeted attacks."
const INTERNAL = new Set([
  'dev', 'devel', 'develop', 'development', 'staging', 'stage', 'stg', 'preprod', 'recette', 'test', 'tests', 'testing', 'qa', 'uat', 'sandbox',
  'admin', 'administration', 'intranet', 'internal', 'interne', 'vpn', 'jenkins', 'gitlab', 'grafana', 'kibana', 'prometheus', 'phpmyadmin',
  'pma', 'cpanel', 'whm', 'plesk', 'backup', 'backups', 'db', 'mysql', 'postgres', 'redis',
]);

export function internalLabel(name: string, domain: string): string | undefined {
  if (name === domain) return undefined;
  const labels = name.slice(0, -(domain.length + 1)).split('.');
  for (const l of labels) {
    if (INTERNAL.has(l)) return l;
    const parts = l.split('-');
    const hit = parts.length > 1 && parts.find((p) => INTERNAL.has(p.replace(/\d+$/, '')));
    if (hit) return hit;
    const m = /^([a-z]+)\d+$/.exec(l);
    if (m && INTERNAL.has(m[1])) return m[1];
  }
  return undefined;
}

export interface Inventory {
  rows: SubRow[];
  wildcards: WildcardRow[];
  /** At least one source gave certificate details (crt.sh or Cert Spotter). */
  certSource: CtSourceId | undefined;
}

export function buildInventory(domain: string, results: CtSourceResult[]): Inventory {
  const rows = new Map<string, SubRow & { _certs: CertBrief[] }>();
  const wild = new Map<string, WildcardRow>();
  const row = (name: string) => {
    let r = rows.get(name);
    if (!r) rows.set(name, (r = { name, sources: [], certCount: 0, certs: [], _certs: [] }));
    return r;
  };
  const addSource = (r: { sources: CtSourceId[] }, s: CtSourceId) => {
    if (!r.sources.includes(s)) r.sources.push(s);
  };
  const certs: CtCert[] = [];
  for (const res of results) {
    if (res.status !== 'ok') continue;
    for (const n of res.names) {
      if (n.name.startsWith('*.')) {
        const w = wild.get(n.name) ?? { name: n.name, certCount: 0 };
        w.firstSeen = minIso(w.firstSeen, n.firstSeen);
        wild.set(n.name, w);
        continue;
      }
      const r = row(n.name);
      addSource(r, res.source);
      r.firstSeen = minIso(r.firstSeen, n.firstSeen);
    }
    certs.push(...res.certs);
  }
  // exact names first, so that wildcard coverage applies to the full list of names
  for (const c of certs) {
    for (const n of c.names) {
      if (n.startsWith('*.')) {
        const w = wild.get(n) ?? { name: n, certCount: 0 };
        w.certCount++;
        w.firstSeen = minIso(w.firstSeen, c.notBefore);
        if (!w.lastSeen || c.notBefore > w.lastSeen) {
          w.lastSeen = c.notBefore;
          w.lastCert = brief(c);
        }
        w.validUntil = maxIso(w.validUntil, c.notAfter);
        wild.set(n, w);
        continue;
      }
      const r = row(n);
      addSource(r, c.source);
      r.certCount++;
      r.firstSeen = minIso(r.firstSeen, c.notBefore);
      const b = brief(c);
      r._certs.push(b);
      if (!r.lastSeen || c.notBefore > r.lastSeen) {
        r.lastSeen = c.notBefore;
        r.lastCert = b;
      }
    }
  }
  // wildcard certificates cover the names one label below their parent
  const wildCerts = certs.filter((c) => c.names.some((n) => n.startsWith('*.')));
  for (const r of rows.values()) {
    for (const c of wildCerts) {
      const w = c.names.find((n) => n.startsWith('*.') && covers(n, r.name));
      if (w && !c.names.includes(r.name)) r._certs.push(brief(c, w));
    }
    r._certs.sort((a, b) => (a.notBefore < b.notBefore ? 1 : a.notBefore > b.notBefore ? -1 : 0));
    for (const b of r._certs) {
      if (!r.validUntil || b.notAfter > r.validUntil) {
        r.validUntil = b.notAfter;
        r.validUntilCert = b;
      }
    }
    r.certs = r._certs.slice(0, 10);
    r.internal = internalLabel(r.name, domain);
  }
  const list = [...rows.values()].map(({ _certs, ...r }) => r as SubRow);
  list.sort((a, b) => a.name.localeCompare(b.name));
  const certSource = results.find((r) => r.status === 'ok' && r.source !== 'crt.name')?.source;
  return { rows: list, wildcards: [...wild.values()].sort((a, b) => a.name.localeCompare(b.name)), certSource };
}

/** Order in which names are resolved when there are more than the limit: the domain, then the most recently seen. */
export function resolutionOrder(rows: SubRow[], domain: string): SubRow[] {
  const recent = (r: SubRow) => r.lastSeen ?? r.firstSeen ?? '';
  return [...rows].sort((a, b) => (a.name === domain ? -1 : b.name === domain ? 1 : recent(b).localeCompare(recent(a)) || a.name.localeCompare(b.name)));
}
