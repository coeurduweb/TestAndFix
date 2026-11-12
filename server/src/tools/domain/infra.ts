// Zone infrastructure checks of the domain scanner: NS (count, networks, parent/child coherence,
// lame servers), SOA serials across servers, CAA, and the DNS blocklists of the MX addresses.
import { t, tPlural } from '../../i18n.js';
import net from 'node:net';
import { nodeStyleResolver, type ResolveSession } from '../../dns/iterative.js';
import type { AuthorityResolver } from '../../lib/email-auth/common.js';
import { knowledge } from '../../knowledge/engine.js';
import { DeadlineError, deadline, issue, lookupType, norm, pass, type Analysis, type Issue } from '../../lib/email-auth/common.js';
import { checkDnsbl, type DnsblHit } from '../../mail/dnsbl.js';
import type { PassedCheck } from '../types.js';
import { authoritativeIssues, queryAllAuthoritative, type AllAuthoritative, type QueryFn } from '../dns/lookup.js';

export interface NsData {
  zone: string;
  /** NS set given by the parent zone (delegation). */
  parent: { name: string; ips: string[] }[];
  /** NS set published in the zone itself. */
  child: string[];
  networks: string[];
  authoritative?: AllAuthoritative;
}

export async function analyzeNs(session: AuthorityResolver, domain: string, q?: QueryFn): Promise<Analysis & { data: NsData }> {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const auth = await session.findAuthorities(domain);
  const all = await queryAllAuthoritative(session, auth.zone, 'NS', q);
  const parent = auth.servers.map((s) => ({ name: norm(s.name), ips: s.ips }));
  const childSets = all.servers.filter((s) => s.aa).map((s) => s.answers.filter((a) => a.type === 'NS').map((a) => norm(a.value)).sort());
  const child = [...new Set(childSets.flat())].sort();
  const ipv4 = parent.flatMap((p) => p.ips.filter((ip) => net.isIPv4(ip)));
  const networks = [...new Set(ipv4.map((ip) => ip.split('.').slice(0, 3).join('.') + '.0/24'))];
  const data: NsData = { zone: auth.zone, parent, child, networks, authoritative: all };
  const v = { domain: auth.zone };
  const list = `${t('parent : {names}', { names: parent.map((p) => p.name).join(', ') })}\n${t('zone : {names}', { names: child.join(', ') || t('(aucun)') })}`;
  if (parent.length < 2) issues.push(issue('infrastructure.ns_single', { ...v, value: parent.length }, { evidence: list }));
  else passed.push(pass('ns.count', 'infrastructure', t('{n} serveurs de noms', { n: parent.length }), parent.map((p) => p.name).join(', ')));
  const noIp = parent.filter((p) => !p.ips.length);
  if (noIp.length) issues.push(issue('infrastructure.ns_unresolvable', { ...v, value: noIp.map((p) => p.name).join(', ') }, { evidence: list }));
  if (parent.length >= 2 && networks.length === 1) issues.push(issue('infrastructure.ns_same_network', { ...v, value: networks[0] }, { evidence: parent.map((p) => `${p.name} : ${p.ips.join(', ')}`).join('\n') }));
  else if (networks.length > 1) passed.push(pass('ns.networks', 'infrastructure', t('Serveurs de noms répartis sur {n} réseaux /24', { n: networks.length })));
  const parentNames = parent.map((p) => p.name).sort();
  if (child.length && (parentNames.join() !== child.join() || childSets.some((s) => s.join() !== child.join())))
    issues.push(issue('infrastructure.ns_parent_child_mismatch', v, { evidence: list }));
  else if (child.length) passed.push(pass('ns.coherent', 'infrastructure', t('Délégation du parent identique aux NS de la zone')));
  const lame = authoritativeIssues(auth.zone, all).issues.filter((i) => i.id === 'infrastructure.dns_lame_server');
  issues.push(...lame);
  return { issues, passed, data };
}

export interface SoaData {
  zone: string;
  record?: string;
  authoritative?: AllAuthoritative;
}

export async function analyzeSoa(session: AuthorityResolver, zone: string, q?: QueryFn): Promise<Analysis & { data: SoaData }> {
  const all = await queryAllAuthoritative(session, zone, 'SOA', q);
  const x = authoritativeIssues(zone, all);
  const record = all.servers.find((s) => s.answers.length)?.answers.find((a) => a.type === 'SOA')?.value;
  const issues = x.issues.filter((i) => i.id !== 'infrastructure.dns_lame_server' && i.id !== 'infrastructure.dns_inconsistent');
  if (!record) issues.push(issue('infrastructure.soa_missing', { domain: zone }));
  return { issues, passed: x.passed, data: { zone, record, authoritative: all } };
}

export interface CaaData {
  /** Name where the relevant CAA set was found (RFC 8659 §3: climbing the tree). */
  foundAt?: string;
  records: { flags: number; tag: string; value: string }[];
  issuers: string[];
  wildcardIssuers: string[];
  iodef: string[];
}

export async function analyzeCaa(session: AuthorityResolver, domain: string, stopAt: string): Promise<Analysis & { data: CaaData }> {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const data: CaaData = { records: [], issuers: [], wildcardIssuers: [], iodef: [] };
  const labels = domain.split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    const name = labels.slice(i).join('.');
    const r = await lookupType(session, name, 'CAA');
    if (r.error) return { issues, passed, unavailable: [{ source: 'dns', reason: `CAA ${name} : ${r.error}` }], data };
    if (r.data.length) {
      data.foundAt = name;
      data.records = r.data.map((d) => {
        const x = d as { flags?: number; tag: string; value: string; issuerCritical?: boolean };
        return { flags: x.flags ?? (x.issuerCritical ? 128 : 0), tag: String(x.tag).toLowerCase(), value: String(x.value) };
      });
      break;
    }
    if (name === stopAt) break;
  }
  const issuer = (v: string) => v.split(';')[0].trim();
  data.issuers = data.records.filter((r) => r.tag === 'issue').map((r) => issuer(r.value) || t('(aucune autorité)'));
  data.wildcardIssuers = data.records.filter((r) => r.tag === 'issuewild').map((r) => issuer(r.value) || t('(aucune autorité)'));
  data.iodef = data.records.filter((r) => r.tag === 'iodef').map((r) => r.value);
  if (!data.records.length) issues.push(issue('infrastructure.caa_missing', { domain }));
  else {
    const unknown = data.records.filter((r) => !['issue', 'issuewild', 'iodef', 'issuemail', 'issuevmc', 'contactemail', 'contactphone'].includes(r.tag));
    const critical = unknown.filter((r) => r.flags & 128);
    if (critical.length) issues.push(issue('infrastructure.caa_unknown_critical', { domain, value: critical.map((r) => r.tag).join(', ') }, { evidence: critical.map((r) => `${r.flags} ${r.tag} "${r.value}"`).join('\n') }));
    passed.push(pass('caa.present', 'infrastructure', t('CAA publié sur {name}', { name: data.foundAt }), t('autorités : {list}', { list: data.issuers.join(', ') || t('aucune pour issue') })));
  }
  return { issues, passed, data };
}

// --- blocklists

export interface BlacklistData {
  ips: string[];
  domains: string[];
  /** Lists in the catalogue (all types). */
  listsQueried: number;
  /** Lists actually queried for IPs and for domains (distinct zones in the results). */
  ipLists: number;
  domainLists: number;
  /** Lookups sent (lists × targets). */
  lookups: number;
  listed: DnsblHit[];
  refused: DnsblHit[];
  errors: number;
}

function situationFor(hit: DnsblHit): string | undefined {
  const cands = [...knowledge().values()].filter((s) => s.family === 'blacklist' && s.detect?.signal?.includes(`'${hit.zone}'`));
  const byCode = cands.find((s) => hit.codes.some((c) => s.detect!.signal!.includes(c)));
  return (byCode ?? (cands.length === 1 ? cands[0] : undefined))?.id;
}

export async function analyzeBlacklists(
  session: AuthorityResolver,
  ips: string[],
  domains: string[],
  makeSession?: () => ResolveSession,
): Promise<Analysis & { data: BlacklistData }> {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
    // one session per lookup, as the mail analysis does: list lookups never wait on each other
  // Each lookup gets a deadline and one retry on a new session: a resolution can stall inside a
  // session when the lists' name servers have no glue (see the report on dns/iterative.ts).
  const guarded = (mk: () => ReturnType<typeof nodeStyleResolver>) => async (name: string, type?: string) => {
    try {
      return await deadline(mk()(name, type), 3000, name);
    } catch (e) {
      if (!(e instanceof DeadlineError)) throw e;
      return deadline(nodeStyleResolver(makeSession ? makeSession() : (session as unknown as ResolveSession))(name, type), 3000, name);
    }
  };
  const r = await checkDnsbl(guarded(() => nodeStyleResolver(session as unknown as ResolveSession)), { ips, domains }, makeSession ? { resolverFor: () => guarded(() => nodeStyleResolver(makeSession())) } : {});
  const listed = r.results.filter((h) => h.status === 'listed');
  const refused = r.results.filter((h) => h.status === 'refused');
  const errors = r.results.filter((h) => h.status === 'error').length;
  for (const h of listed) {
    const id = situationFor(h) ?? 'blacklist.listed';
    const vars = { domain: domains[0], ip: h.type === 'ip' ? h.target : undefined, value: h.target, list_name: h.name, delist_url: h.delistUrl };
    issues.push(issue(id, vars, { evidence: `${h.query} → ${h.codes.join(', ')}${h.meaning ? ` (${h.meaning})` : ''}${h.txt ? `\n${h.txt}` : ''}`, ...(h.weight === 'info' ? { severity: 'info' as const, penalty: 0 } : {}) }));
  }
  const clean = r.results.filter((h) => h.status === 'clean');
  const ipLists = new Set(r.results.filter((h) => h.type === 'ip').map((h) => h.zone)).size;
  const domainLists = new Set(r.results.filter((h) => h.type === 'domain').map((h) => h.zone)).size;
    if (clean.length && !listed.length) {
    const parts = [
      ips.length ? t('{n} IP de MX ({ips}) sur {lists}', { n: ips.length, ips: ips.join(', '), lists: tPlural(ipLists, '{n} liste d’IP', '{n} listes d’IP') }) : t('aucune IP de MX à contrôler'),
      domains.length ? t('{domains} sur {lists}', { domains: domains.join(', '), lists: tPlural(domainLists, '{n} liste de domaines', '{n} listes de domaines') }) : '',
    ].filter(Boolean);
    passed.push(pass('blacklist.clean', 'blacklist', t('Aucune inscription : {parts}', { parts: parts.join(', ') }), t('{n} requêtes, dont {clean} sans inscription', { n: r.results.length, clean: clean.length })));
  }
  const unavailable = [
    ...(refused.length ? [{ source: 'dnsbl', reason: tPlural(refused.length, '{n} requête refusée par la liste ({names})', '{n} requêtes refusées par la liste ({names})', { names: [...new Set(refused.map((h) => h.name))].join(', ') }) }] : []),
    ...(errors ? [{ source: 'dnsbl', reason: tPlural(errors, '{n} requête sans réponse', '{n} requêtes sans réponse') }] : []),
  ];
  return { issues, passed, unavailable, data: { ips, domains, listsQueried: r.lists, ipLists, domainLists, lookups: r.results.length, listed, refused, errors } };
}
