// Reputation of a domain on the IP reputation page (US-069): domain blocklists (tools/link/domain),
// age and registrar (RDAP), the IPs of the site (A, AAAA) and of the mail servers (MX) on the
// major IP lists, Safe Browsing, VirusTotal (domain report) and URLhaus (host). Every step
// reports as soon as it answers; a missing key goes to `unavailable`.
import { t, tPlural, msg } from '../../i18n.js';
import net from 'node:net';
import type { DnsblResolver } from '../../mail/dnsbl.js';
import { explain } from '../../knowledge/engine.js';
import { issue, lookupAddresses, lookupMx, pass, type Analysis, type Issue, type Resolver } from '../../lib/email-auth/common.js';
import { analyzeRdap, type RdapAnalysis } from '../../lib/email-auth/rdap.js';
import { selectLists, type ListSelection } from '../../lib/reputation/dnsbl-lists.js';
import type { RateLimiter } from '../../lib/reputation/limiter.js';
import { gsbThreatLabel, safeBrowsingLookup, type GsbData } from '../../lib/reputation/safebrowsing.js';
import { runSource, type ApiFetch, type SourceResult } from '../../lib/reputation/source.js';
import { urlhausHost, type UrlhausHostData } from '../../lib/reputation/urlhaus.js';
import { vtDomain, type VtDomainData } from '../../lib/reputation/virustotal.js';
import { analyzeDomainLists, type DomainListsReport } from '../link/domain.js';
import type { PassedCheck } from '../types.js';
import { analyzeBatch, type IpBatchRow, type IpDeps, type IpSourceEvent } from './analyze.js';

/** IPs looked up at most (web and mail together), to keep one check within the IP batch budget. */
const MAX_ADDRESSES = 16;
const MAX_MX = 5;

export interface DomainReputation {
  domain: string;
  exists: boolean;
  nxdomain?: boolean;
  ageDays?: number;
  created?: string;
  registrar?: string;
  lists: Pick<DomainListsReport, 'queried' | 'listed' | 'refused' | 'errors' | 'clean'>;
  addresses: { ip: string; family: 4 | 6; role: 'web' | 'mail'; host: string; row: IpBatchRow }[];
  intel: { safebrowsing?: GsbData; virustotal?: VtDomainData; urlhaus?: UrlhausHostData };
}

export interface DomainDeps {
  /** DNS session of the action (A, AAAA, MX). */
  dns: Resolver;
  /** Dependencies of the IP rows (major lists, PTR, ASN). */
  ipDeps: IpDeps;
  /** A resolver per domain list lookup. */
  domainListResolverFor: () => DnsblResolver;
  domainLists?: ListSelection;
  rdap?: (domain: string) => Promise<RdapAnalysis>;
  keys: { safeBrowsing: string; virusTotal: string; urlhaus: string };
  fetch?: ApiFetch;
  bases?: Partial<Record<'safebrowsing' | 'virustotal' | 'urlhaus', string>>;
  vtLimiter?: RateLimiter;
  /** Turn off the keyed HTTP sources (tests). */
  http?: boolean;
}

const LABELS: Record<string, string> = {
  rdap: msg('Âge et bureau d’enregistrement (RDAP)'),
  a: msg('Adresses du site (A, AAAA)'),
  mx: msg('Serveurs de mail (MX)'),
  safebrowsing: 'Google Safe Browsing',
  virustotal: 'VirusTotal',
  urlhaus: 'URLhaus',
};
export const DOMAIN_SOURCES = Object.entries(LABELS).map(([id, label]) => ({ id, label }));

const ROLE_LABEL = { web: msg('site web'), mail: msg('serveur de mail') } as const;

const familyOf = (ip: string): 4 | 6 => (net.isIPv6(ip) ? 6 : 4);

export async function analyzeDomainReputation(
  domain: string,
  deps: DomainDeps,
  opts: { onEvent?: (e: IpSourceEvent) => void; signal?: AbortSignal } = {},
): Promise<Analysis & { data: DomainReputation }> {
  const emit = (e: IpSourceEvent) => {
    if (!opts.signal?.aborted) opts.onEvent?.(e);
  };
  const track = async <T>(id: string, fn: () => Promise<T>, timeoutMs?: number): Promise<SourceResult<T>> => {
    const r = await runSource(id, t(LABELS[id]), fn, timeoutMs);
    emit({ source: id, label: r.label, ok: r.ok, ms: r.ms, reason: r.reason, data: r.data });
    return r;
  };
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const unavailable: { source: string; reason: string }[] = [];
  const http = deps.http !== false;

  // Domain lists and RDAP do not depend on the addresses: started at once.
  const listsP = analyzeDomainLists(domain, deps.domainListResolverFor, {
    lists: deps.domainLists ?? selectLists('domain', 'all'),
    onHit: (h) => emit({ source: `dnsbl:${h.zone}`, label: h.name, ok: h.status !== 'error', ms: h.ms, reason: h.error, data: h }),
  });
  const rdapP = track('rdap', () => (deps.rdap ?? ((d) => analyzeRdap(d, { session: deps.dns })))(domain), 25000);

  // Web addresses: the name itself, or www.<name> when the name has none.
  const aR = await track('a', async () => {
    let host = domain;
    let r = await lookupAddresses(deps.dns, domain, ['A', 'AAAA']);
    if (!r.ips.length && r.rcode !== 'NXDOMAIN' && !domain.startsWith('www.')) {
      const www = await lookupAddresses(deps.dns, `www.${domain}`, ['A', 'AAAA']);
      if (www.ips.length) {
        host = `www.${domain}`;
        r = { ...www, rcode: r.rcode };
      }
    }
    return { ips: r.ips.map((ip) => ({ ip, family: familyOf(ip) })), host, rcode: r.rcode, error: r.error };
  });
  const nxdomain = aR.ok && aR.data!.rcode === 'NXDOMAIN';

  const mxR = nxdomain
    ? undefined
    : await track('mx', async () => {
        const m = await lookupMx(deps.dns, domain);
        const hosts = await Promise.all(
          m.mx
            .filter((x) => x.exchange && x.exchange !== '.')
            .slice(0, MAX_MX)
            .map(async (x) => ({ host: x.exchange, preference: x.preference, ips: (await lookupAddresses(deps.dns, x.exchange, ['A', 'AAAA'])).ips })),
        );
        return { hosts, nullMx: m.mx.some((x) => !x.exchange || x.exchange === '.') };
      });

  // IPs of the site and of the mail servers, on the major lists (one row each, as a batch)
  const targets: { ip: string; role: 'web' | 'mail'; host: string }[] = [];
  if (aR.ok) for (const a of aR.data!.ips) targets.push({ ip: a.ip, role: 'web', host: aR.data!.host });
  if (mxR?.ok) for (const h of mxR.data!.hosts) for (const ip of h.ips) targets.push({ ip, role: 'mail', host: h.host });
  const uniqueIps = [...new Set(targets.map((t) => t.ip))].slice(0, MAX_ADDRESSES);
  if (targets.length && new Set(targets.map((t) => t.ip)).size > MAX_ADDRESSES)
    unavailable.push({ source: 'ip', reason: t('{n} adresses trouvées : seules les {max} premières sont vérifiées', { n: new Set(targets.map((x) => x.ip)).size, max: MAX_ADDRESSES }) });
  const rowsP = uniqueIps.length
    ? analyzeBatch(uniqueIps, deps.ipDeps, {
        signal: opts.signal,
        onRow: (row) => emit({ source: `ip:${row.ip}`, label: row.ip, ok: row.status !== 'error', ms: 0, data: row }),
      })
    : undefined;

  const intelOn = http && !nxdomain;
  const gsbP = intelOn ? track('safebrowsing', () => safeBrowsingLookup([`http://${domain}/`, `https://${domain}/`], { key: deps.keys.safeBrowsing, fetch: deps.fetch, base: deps.bases?.safebrowsing })) : undefined;
  const vtP = intelOn ? track('virustotal', () => vtDomain(domain, { key: deps.keys.virusTotal, fetch: deps.fetch, base: deps.bases?.virustotal, limiter: deps.vtLimiter }), 30000) : undefined;
  const uhP = intelOn ? track('urlhaus', () => urlhausHost(domain, { key: deps.keys.urlhaus, fetch: deps.fetch, base: deps.bases?.urlhaus })) : undefined;

  const [lists, rdap, batch, gsb, vt, uh] = await Promise.all([listsP, rdapP, rowsP, gsbP, vtP, uhP]);

  const data: DomainReputation = {
    domain,
    exists: !nxdomain,
    nxdomain: nxdomain || undefined,
    lists: { queried: lists.data.queried, listed: lists.data.listed, refused: lists.data.refused, errors: lists.data.errors, clean: lists.data.clean },
    addresses: [],
    intel: {},
  };

  if (nxdomain) issues.push(issue('ip.domain_not_found', { domain }, { evidence: t('{domain} A et AAAA → NXDOMAIN', { domain }) }));
  if (!aR.ok) unavailable.push({ source: 'a', reason: aR.reason! });
  else if (aR.data!.error && !aR.data!.ips.length && !nxdomain) unavailable.push({ source: 'a', reason: t('adresses de {domain} illisibles ({error})', { domain, error: aR.data!.error }) });
  if (mxR && !mxR.ok) unavailable.push({ source: 'mx', reason: mxR.reason! });
  else if (mxR?.ok && mxR.data!.hosts.length) passed.push(pass('ip.domain_mx', 'ip', tPlural(mxR.data!.hosts.length, '{n} serveur de mail : {hosts}', '{n} serveurs de mail : {hosts}', { hosts: mxR.data!.hosts.map((h) => h.host).join(', ') })));

  // Domain lists (findings and checks of tools/link/domain, gravity by list weight)
  issues.push(...lists.issues);
  passed.push(...lists.passed);
  unavailable.push(...(lists.unavailable ?? []));

  // RDAP: age and registrar. Its own "very new" and "not registered" entries talk about a
  // sending domain or are covered by ip.domain_not_found: replaced here.
  if (rdap.ok) {
    const r = rdap.data!;
    Object.assign(data, { ageDays: r.data.ageDays, created: r.data.created, registrar: r.data.registrar?.name });
    issues.push(...r.issues.filter((i) => i.id !== 'reputation.domain_very_new' && i.id !== 'infrastructure.domain_not_registered'));
    passed.push(...r.passed);
    unavailable.push(...(r.unavailable ?? []));
    if (r.data.ageDays !== undefined && r.data.ageDays < 30)
      issues.push(issue('ip.domain_recent', { domain: r.data.queried, value: tPlural(r.data.ageDays, '{n} jour', '{n} jours') }, { evidence: `${t('création : {date}', { date: r.data.created })}${r.data.registrar?.name ? `, ${r.data.registrar.name}` : ''}` }));
    else if (r.data.ageDays !== undefined) {
      const y = Math.floor(r.data.ageDays / 365);
      passed.push(pass('ip.domain_age', 'ip', t('{domain} existe depuis {age}', { domain: r.data.queried, age: y >= 1 ? tPlural(y, '{n} an', '{n} ans') : t('{n} jours', { n: r.data.ageDays }) }), r.data.created));
    }
  } else unavailable.push({ source: 'rdap', reason: rdap.reason! });

  // Addresses: one finding per listed IP and list, the role in the title
  const rows = new Map((batch?.data.rows ?? []).map((r) => [r.ip, r]));
  for (const t of targets) {
    const row = rows.get(t.ip);
    if (row) data.addresses.push({ ip: t.ip, family: familyOf(t.ip), role: t.role, host: t.host, row });
  }
  for (const [ip, row] of rows) {
    if (!row.listed.length) continue;
    const of = data.addresses.filter((a) => a.ip === ip);
    const roles = [...new Set(of.map((a) => a.role))];
    const value = roles.length > 1 ? t('{a} et du {b}', { a: t(ROLE_LABEL[roles[0]]), b: t(ROLE_LABEL[roles[1]]) }) : t(ROLE_LABEL[roles[0]]);
    const hostList = [...new Set(of.map((a) => a.host))];
    const host = hostList.length > 1 ? t('{a} et {b}', { a: hostList.slice(0, -1).join(', '), b: hostList[hostList.length - 1] }) : hostList[0];
    for (const l of row.listed) {
      const base = explain({ id: l.situation, vars: { ip } });
      issues.push(
        issue('ip.domain_ip_listed', { ip, host, value, domain, list_name: l.name, delist_url: l.delistUrl }, {
          severity: base.severity,
          penalty: base.penalty,
          evidence: `${t('{ip} ({roles}) sur {zone}', { ip, roles: roles.map((r) => t(ROLE_LABEL[r])).join(', '), zone: l.zone })} → ${l.codes.join(', ')}${l.meaning ? ` (${l.meaning})` : ''}`,
        }),
      );
    }
  }
  if (rows.size && ![...rows.values()].some((r) => r.listed.length))
    passed.push(pass('ip.domain_ips_clean', 'ip', tPlural(rows.size, '{n} adresse du site et des serveurs de mail absente des listes principales', '{n} adresses du site et des serveurs de mail absentes des listes principales'), [...rows.keys()].join(', ')));
  unavailable.push(...(batch?.unavailable ?? []));

  // Threat sources
  if (gsb?.ok) {
    data.intel.safebrowsing = gsb.data;
    const m = gsb.data!.matches;
    if (m.length) issues.push(issue('ip.domain_safe_browsing', { domain, value: [...new Set(m.map((x) => gsbThreatLabel(x.threatType)))].join(', ') }, { evidence: m.map((x) => `${x.url} : ${x.threatType}`).join('\n') }));
    else passed.push(pass('ip.domain_safe_browsing', 'ip', t('Google Safe Browsing : aucune menace connue sur la page d’accueil')));
  } else if (gsb) unavailable.push({ source: 'safebrowsing', reason: gsb.reason! });
  if (vt?.ok) {
    const v = vt.data!;
    data.intel.virustotal = v;
    const { malicious, suspicious } = v.stats;
    if (malicious >= 1 || suspicious >= 2)
      issues.push(
        issue('ip.domain_virustotal', { domain, value: malicious, url: v.link }, {
          ...(malicious >= 3 ? { severity: 'high' as const, penalty: 1.5 } : { severity: 'medium' as const, penalty: 0.5 }),
          evidence: `${t('{malicious} malveillant, {suspicious} suspect', { malicious, suspicious })}${v.flagged.length ? ` : ${v.flagged.map((f) => `${f.engine} (${f.result ?? f.category})`).join(', ')}` : ''}\n${v.link}`,
        }),
      );
    else passed.push(pass('ip.domain_virustotal', 'ip', v.found ? t('VirusTotal : aucun moteur ne signale ce domaine') : t('VirusTotal : domaine jamais analysé'), v.link));
  } else if (vt) unavailable.push({ source: 'virustotal', reason: vt.reason! });
  if (uh?.ok) {
    const u = uh.data!;
    data.intel.urlhaus = u;
    if (u.listed)
      issues.push(
        issue('ip.domain_urlhaus', { domain, value: u.urlCount, url: u.reference }, {
          ...(u.onlineCount > 0 ? { severity: 'high' as const, penalty: 1.5 } : { severity: 'low' as const, penalty: 0.3 }),
          evidence: `${t('{n} adresse(s), dont {online} en ligne', { n: u.urlCount, online: u.onlineCount })}\n${u.urls.map((x) => `${x.url} (${x.status})`).join('\n')}`,
        }),
      );
    else passed.push(pass('ip.domain_urlhaus', 'ip', t('URLhaus : aucune adresse malveillante recensée sur ce domaine')));
  } else if (uh) unavailable.push({ source: 'urlhaus', reason: uh.reason! });

  return { issues, passed, unavailable, data };
}
