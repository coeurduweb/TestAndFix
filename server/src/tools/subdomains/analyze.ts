// Subdomains revealed by Certificate Transparency (US-051): sources in relay, one row per name,
// current DNS resolution from the root (no cache), takeover check on CNAMEs to third-party
// services, certificates about to expire, internal names exposed, names that no longer resolve.
import { t, locale } from '../../i18n.js';
import { lookupAddresses, pass, issue, type Issue, type Resolver, type Analysis } from '../../lib/email-auth/common.js';
import { collectCt, SOURCE_LABEL, type CtFetch, type CtSourceResult, type CtSourceId } from '../../lib/ct/sources.js';
import type { PassedCheck } from '../types.js';
import type { TlsProbe } from '../link/tls.js';
import { buildInventory, resolutionOrder, type DnsState, type ServedCert, type SubRow, type TakeoverState, type WildcardRow } from './inventory.js';
import { matchFingerprint, serviceOfChain } from './takeover.js';

export const RESOLVE_LIMIT = 500;
export const RESOLVE_CONCURRENCY = 20;
const PROBE_CONCURRENCY = 6;
const PROBE_TIMEOUT_MS = 10000;
const EXPIRY_DAYS = 14;
const DAY = 86400000;

export interface ProbeResult {
  status: number;
  body: string;
}

export interface SubdomainsDeps {
  fetch: CtFetch;
  dns: Resolver;
  /** GET of http(s)://<name>/ to look for a takeover fingerprint (safeGet in production). */
  probe: (url: string) => Promise<ProbeResult>;
  /** TLS handshake on port 443 to read the certificate served now (probeTls in production). */
  tls?: TlsProbe;
  now?: () => number;
  /** Random label for the wildcard DNS test (fixed in tests). */
  randomLabel?: () => string;
}

export interface SourceSummary {
  source: CtSourceId;
  label: string;
  status: CtSourceResult['status'];
  names: number;
  certs: number;
  ms: number;
  error?: string;
  truncated?: boolean;
}

export interface SubdomainsData {
  domain: string;
  sources: SourceSummary[];
  subdomains: SubRow[];
  wildcards: WildcardRow[];
  total: number;
  resolved: number;
  limit: number;
  /** Names beyond the limit, listed but not resolved. */
  notResolved: number;
  wildcardDns?: { name: string; ips: string[] };
  certSource?: CtSourceId;
  /** Active names whose served certificate is missing from the CT answers (the sources lag). */
  servedNewerThanCt: number;
  counts: { active: number; dead: number; dangling: number; risk: number; error: number; wildcards: number };
}

export interface InventoryEvent {
  domain: string;
  total: number;
  toResolve: number;
  limit: number;
  wildcards: WildcardRow[];
  /** Rows without their certificate list (sent before resolution, to draw the list at once). */
  rows: Omit<SubRow, 'certs'>[];
}

export interface AnalyzeHooks {
  onSource?: (s: SourceSummary) => void;
  onInventory?: (e: InventoryEvent) => void;
  onSubdomain?: (r: SubRow) => void;
  signal?: AbortSignal;
}

export function summarize(r: CtSourceResult): SourceSummary {
  return {
    source: r.source,
    label: SOURCE_LABEL[r.source],
    status: r.status,
    names: r.names.length || new Set(r.certs.flatMap((c) => c.names)).size,
    certs: r.certs.length,
    ms: r.ms,
    error: r.error,
    truncated: r.truncated,
  };
}

function limiter(n: number) {
  let active = 0;
  const queue: (() => void)[] = [];
  return async <T>(fn: () => Promise<T>): Promise<T> => {
    if (active >= n) await new Promise<void>((r) => queue.push(r));
    active++;
    try {
      return await fn();
    } finally {
      active--;
      queue.shift()?.();
    }
  };
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let t: NodeJS.Timeout;
  return Promise.race([p, new Promise<never>((_, rej) => (t = setTimeout(() => rej(new Error('délai dépassé')), ms)))]).finally(() => clearTimeout(t));
}

export async function resolveName(dns: Resolver, name: string): Promise<DnsState> {
  const r = await lookupAddresses(dns, name, ['A', 'AAAA']);
  const cname = Array.from(new Set(r.cnames));
  const a = r.ips.filter((x) => !x.includes(':'));
  const aaaa = r.ips.filter((x) => x.includes(':'));
  if (r.ips.length) return { status: 'active', rcode: 'NOERROR', a, aaaa, cname };
  if (r.rcode === 'NXDOMAIN') return { status: cname.length ? 'dangling' : 'dead', rcode: 'NXDOMAIN', a, aaaa, cname };
  if (r.error) return { status: 'error', rcode: r.rcode, a, aaaa, cname, error: r.error };
  // the name (or the CNAME target) exists but has no address
  return { status: 'dead', rcode: 'NOERROR', a, aaaa, cname };
}

async function checkTakeover(row: SubRow, deps: SubdomainsDeps, probeSlot: ReturnType<typeof limiter>): Promise<TakeoverState | undefined> {
  const d = row.dns;
  if (!d || !d.cname.length) return undefined;
  const hit = serviceOfChain(d.cname);
  if (!hit) return undefined;
  const { service, target } = hit;
  if (service.nxdomain) {
    if (d.status !== 'dangling') return undefined;
    return { service: service.service, level: service.level, target, evidence: t("{target} : NXDOMAIN (la ressource n'existe plus chez {service})", { target, service: service.service }) };
  }
  if (d.status !== 'active' || !service.fingerprint) return undefined;
  for (const scheme of ['http', 'https']) {
    try {
      const res = await probeSlot(() => withTimeout(deps.probe(`${scheme}://${row.name}/`), PROBE_TIMEOUT_MS));
      const m = matchFingerprint(service, res.body);
      if (m) return { service: service.service, level: service.level, target, evidence: t('{url} répond HTTP {status} : « {m} »', { url: `${scheme}://${row.name}/`, status: res.status, m }) };
      return undefined; // the page answered without the error text: the resource is claimed
    } catch {
      /* connection refused or TLS error: try the other scheme */
    }
  }
  return undefined;
}

async function readServed(row: SubRow, probe: TlsProbe): Promise<ServedCert | undefined> {
  const ip = row.dns!.a[0] ?? row.dns!.aaaa[0];
  if (!ip) return undefined;
  const t = await withTimeout(probe(row.name, ip, 443), PROBE_TIMEOUT_MS);
  if (t.error) return { ip, expired: false, authorized: false, nameMatches: false, error: t.error };
  const known = row.certs.map((c) => c.notBefore).sort().at(-1);
  return {
    ip,
    issuer: t.issuerOrg ?? t.issuer,
    validFrom: t.validFrom,
    validTo: t.validTo,
    daysLeft: t.daysLeft,
    expired: t.expired,
    authorized: t.authorized,
    nameMatches: t.nameMatches,
    authorizationError: t.authorizationError,
    fingerprint256: t.fingerprint256,
    // one day of margin: CT timestamps and notBefore backdating differ slightly
    // a name the sources hold no certificate for says nothing about their lag (Cert Spotter keeps
    // only unexpired certificates, crt.name keeps no certificate at all)
    newerThanCt: !!t.validFrom && !!known && Date.parse(t.validFrom) > Date.parse(known) + DAY,
  };
}

const fmtDate = (iso: string) => new Date(iso).toLocaleDateString(locale(), { timeZone: 'UTC' });
const listOf = (names: string[], max = 15) => names.slice(0, max).join('\n') + (names.length > max ? '\n' + t('… et {n} autres', { n: names.length - max }) : '');

/** Renewal threshold: a third of the lifetime, half for certificates under 10 days (Let's Encrypt integration guide), capped at 14 days. */
export function expiryThresholdMs(notBefore: string, notAfter: string): number {
  const life = Date.parse(notAfter) - Date.parse(notBefore);
  const share = life < 10 * DAY ? life / 2 : life / 3;
  return Math.min(EXPIRY_DAYS * DAY, share);
}

export async function analyzeSubdomains(domain: string, deps: SubdomainsDeps, hooks: AnalyzeHooks = {}): Promise<Analysis & { data: SubdomainsData }> {
  const now = deps.now?.() ?? Date.now();
  const results = await collectCt(domain, deps.fetch, { onSource: (r) => hooks.onSource?.(summarize(r)), signal: hooks.signal });
  const sources = results.map(summarize);
  const inv = buildInventory(domain, results);
  const okSources = results.filter((r) => r.status === 'ok');
  const unavailable = results
    .filter((r) => r.status === 'error' || (r.status === 'ok' && r.truncated && r.error))
    .map((r) => ({ source: SOURCE_LABEL[r.source], reason: r.error ?? t('indisponible') }));

  const ordered = resolutionOrder(inv.rows, domain);
  const toResolve = ordered.slice(0, RESOLVE_LIMIT);
  const skipped = ordered.slice(RESOLVE_LIMIT);
  hooks.onInventory?.({
    domain,
    total: inv.rows.length,
    toResolve: toResolve.length,
    limit: RESOLVE_LIMIT,
    wildcards: inv.wildcards,
    rows: inv.rows.map(({ certs: _c, ...r }) => r),
  });

  // wildcard DNS: a random name that resolves means every name does, dead ones included
  let wildcardDns: SubdomainsData['wildcardDns'];
  if (toResolve.length) {
    const probeName = `${deps.randomLabel?.() ?? `check-${Math.random().toString(36).slice(2, 10)}`}.${domain}`;
    const w = await resolveName(deps.dns, probeName).catch(() => undefined);
    if (w?.status === 'active') wildcardDns = { name: probeName, ips: [...w.a, ...w.aaaa].sort() };
  }

  const probeSlot = limiter(PROBE_CONCURRENCY);
  let next = 0;
  const workers = Array.from({ length: Math.min(RESOLVE_CONCURRENCY, toResolve.length) }, async () => {
    while (next < toResolve.length) {
      if (hooks.signal?.aborted) return;
      const row = toResolve[next++];
      try {
        row.dns = await resolveName(deps.dns, row.name);
      } catch (e) {
        row.dns = { status: 'error', rcode: 'SERVFAIL', a: [], aaaa: [], cname: [], error: (e as Error).message };
      }
      if (wildcardDns && row.dns.status === 'active') {
        const ips = [...row.dns.a, ...row.dns.aaaa].sort().join(',');
        if (ips === wildcardDns.ips.join(',')) row.dns.viaWildcardDns = true;
      }
      if (row.dns.status === 'active' && deps.tls) row.served = await readServed(row, deps.tls).catch(() => undefined);
      row.takeover = await checkTakeover(row, deps, probeSlot).catch(() => undefined);
      hooks.onSubdomain?.(row);
    }
  });
  await Promise.all(workers);
  for (const r of skipped) r.dns = { status: 'skipped', rcode: '', a: [], aaaa: [], cname: [] };

  // ---- findings
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const resolved = toResolve.filter((r) => r.dns && r.dns.status !== 'skipped');
  const risky = resolved.filter((r) => r.takeover);
  const dangling = resolved.filter((r) => r.dns?.status === 'dangling' && !r.takeover);
  const dead = resolved.filter((r) => r.dns?.status === 'dead' || r.dns?.status === 'dangling');
  const active = resolved.filter((r) => r.dns?.status === 'active');
  const errors = resolved.filter((r) => r.dns?.status === 'error');

  for (const r of risky) {
    const tk = r.takeover!;
    issues.push(
      issue(tk.level === 'vulnerable' ? 'subdomains.takeover_risk' : 'subdomains.takeover_possible', { domain, subdomain: r.name, service: tk.service, target: tk.target }, {
        evidence: `${r.name}. CNAME ${r.dns!.cname[0]}.${r.dns!.cname.length > 1 ? `\n${t('chaîne : {chain}', { chain: r.dns!.cname.join(' → ') })}` : ''}\n${tk.evidence}`,
      }),
    );
  }
  if (dangling.length) {
    issues.push(
      issue('subdomains.cname_dangling', { domain, value: dangling.length, subdomain: dangling[0].name, target: dangling[0].dns!.cname.at(-1) }, {
        evidence: listOf(dangling.map((r) => `${r.name}. CNAME ${r.dns!.cname.at(-1)}. (NXDOMAIN)`)),
      }),
    );
  }
  // Expiry is judged on the certificate served now: crt.sh can miss recent certificates (seen on
  // 2026-11-11: a subdomain served a certificate of 2026-09-19 that crt.sh did not return), so
  // the CT data alone would flag renewed names. A name without HTTPS is not judged.
  const served = active.filter((r) => r.served?.validTo && r.served.validFrom && r.served.nameMatches);
  const expiring = served.filter((r) => {
    const c = r.served!;
    const left = Date.parse(c.validTo!) - now;
    return left > 0 && left <= expiryThresholdMs(c.validFrom!, c.validTo!);
  });
  const expired = served.filter((r) => r.served!.expired && !r.dns?.viaWildcardDns);
  if (expiring.length) {
    const days = (r: SubRow) => Math.max(0, Math.floor((Date.parse(r.served!.validTo!) - now) / DAY));
    issues.push(
      issue('subdomains.cert_expiring', { domain, value: expiring.length, subdomain: expiring[0].name }, {
        evidence: listOf(expiring.map((r) => t('{name} : expire le {date} (dans {days} j), {issuer}', { name: r.name, date: fmtDate(r.served!.validTo!), days: days(r), issuer: r.served!.issuer ?? t('émetteur inconnu') }))),
      }),
    );
  }
  if (expired.length)
    issues.push(
      issue('subdomains.cert_expired_active', { domain, value: expired.length, subdomain: expired[0].name }, {
        evidence: listOf(expired.map((r) => t('{name} : certificat servi expiré le {date}, {issuer}', { name: r.name, date: fmtDate(r.served!.validTo!), issuer: r.served!.issuer ?? t('émetteur inconnu') }))),
      }),
    );
  if (served.length && !expiring.length && !expired.length)
    passed.push(pass('subdomains.cert_ok', 'subdomains', t("Aucun certificat servi n'expire dans les {days} jours", { days: EXPIRY_DAYS }), t('{n} sous-domaines en https vérifiés', { n: served.length })));
  const internal = inv.rows.filter((r) => r.internal);
  if (internal.length)
    issues.push(
      issue('subdomains.internal_names', { domain, value: internal.length, subdomain: internal[0].name }, {
        evidence: listOf(internal.map((r) => `${r.name} (${r.internal})${r.dns?.status === 'active' ? ', ' + t('actif') : ''}`)),
      }),
    );
  if (dead.length)
    issues.push(
      issue('subdomains.dead_names', { domain, value: dead.length }, { evidence: listOf(dead.map((r) => r.name), 20) }),
    );
  if (wildcardDns)
    issues.push(issue('subdomains.wildcard_dns', { domain, value: wildcardDns.ips.join(', ') }, { evidence: `${wildcardDns.name} → ${wildcardDns.ips.join(', ')}` }));
  if (skipped.length)
    issues.push(issue('subdomains.resolution_capped', { domain, value: skipped.length }, { evidence: t('{n} noms résolus sur {total}', { n: resolved.length, total: inv.rows.length }) }));
  if (okSources.length && !inv.rows.length) issues.push(issue('subdomains.none_found', { domain }));

  if (okSources.length) {
    passed.push(
      pass('subdomains.sources', 'subdomains', t('Journaux de certificats lus'), okSources.map((r) => `${SOURCE_LABEL[r.source]} (${r.certs.length ? t('{n} certificats', { n: r.certs.length }) : t('{n} noms', { n: r.names.length })})`).join(', ')),
    );
  }
  if (resolved.length) {
    const cnames = resolved.filter((r) => r.dns?.cname.length && serviceOfChain(r.dns.cname)).length;
    if (!risky.length)
      passed.push(
        pass('subdomains.no_takeover', 'subdomains', t('Aucun sous-domaine exposé à une prise de contrôle'), cnames ? t('{n} CNAME vers des services tiers, ressources présentes', { n: cnames }) : t('{n} noms résolus', { n: resolved.length })),
      );
    if (!dangling.length && !risky.some((r) => r.dns?.status === 'dangling'))
      passed.push(pass('subdomains.no_dangling', 'subdomains', t("Aucun CNAME vers une cible qui n'existe plus")));
  }

  const certSource = okSources.find((r) => r.source !== 'crt.name')?.source;
  return {
    issues,
    passed,
    unavailable,
    data: {
      domain,
      sources,
      subdomains: inv.rows,
      wildcards: inv.wildcards,
      total: inv.rows.length,
      resolved: resolved.length,
      limit: RESOLVE_LIMIT,
      notResolved: skipped.length,
      wildcardDns,
      certSource,
      servedNewerThanCt: active.filter((r) => r.served?.newerThanCt).length,
      counts: { active: active.length, dead: dead.length, dangling: dangling.length + risky.filter((r) => r.dns?.status === 'dangling').length, risk: risky.length, error: errors.length, wildcards: inv.wildcards.length },
    },
  };
}
