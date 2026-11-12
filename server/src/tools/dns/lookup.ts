// DNS lookup engine of the dns tool (US-047, US-049): authoritative answer with the full trace,
// a chosen resolver, or every authoritative server compared.
import { t } from '../../i18n.js';
import net from 'node:net';
import { query as rawQuery, type DnsResponse, type QueryOptions, type RRType } from '../../dns/client.js';
import type { NameServer, TraceStep } from '../../dns/iterative.js';
import { isPublicIp, reverseName } from '../../lib/net.js';
import { InvalidInputError, issue, type AuthorityResolver, lookupAddresses, norm, normalizeDomain, pass, type Analysis, type Issue } from '../../lib/email-auth/common.js';
import { measuredAt } from '../../lib/email-auth/report.js';
import type { PassedCheck } from '../types.js';
import { QUERY_TYPES, WIRE_TYPE, digText, toRecord, type RecordOut } from './format.js';

export type QueryFn = (server: string, name: string, type: RRType, opts: QueryOptions) => Promise<DnsResponse>;

export interface AuthServerAnswer {
  ns: string;
  ip: string;
  rcode: string;
  aa: boolean;
  rtt?: number;
  answers: RecordOut[];
  serial?: number;
  error?: string;
}

export interface AllAuthoritative {
  zone: string;
  servers: AuthServerAnswer[];
  /** Every server gave the same record set. */
  consistent: boolean;
  serials: number[];
  serialsConsistent: boolean;
  /** Servers that do not answer authoritatively (lame delegation). */
  lame: string[];
  /** Distinct answer sets, with the servers giving each. */
  variants: { answers: string[]; servers: string[] }[];
}

export interface DnsLookupData {
  name: string;
  type: string;
  mode: 'authoritative' | 'resolver' | 'all';
  rcode: string;
  answers: RecordOut[];
  /** RRSIG returned with the answer (dnssec=1). */
  signatures: RecordOut[];
  cnames: string[];
  zone?: string;
  answeredBy?: string;
  trace: TraceStep[];
  /** Resolver mode: header flags of the resolver's answer. */
  flags?: { aa: boolean; ra: boolean; ad: boolean; tc: boolean };
  server?: string;
  rtt?: number;
  authoritative?: AllAuthoritative;
  ptr?: { ip: string; names: string[]; fcrdns: { name: string; ips: string[]; matches: boolean }[] };
  /** Copyable dig-like text. */
  dig: string;
  ms: number;
}

const sig = (rs: RecordOut[]) => rs.map((r) => `${r.type} ${r.value}`).sort();

function v4(ns: NameServer[]): { ns: string; ip: string }[] {
  return ns.flatMap((s) => s.ips.filter((ip) => net.isIPv4(ip)).map((ip) => ({ ns: s.name, ip })));
}

/** Ask every authoritative server of the zone enclosing `name`, compare answers and SOA serials. */
export async function queryAllAuthoritative(
  session: AuthorityResolver,
  name: string,
  type: RRType,
  q: QueryFn = rawQuery,
): Promise<AllAuthoritative> {
  const auth = await session.findAuthorities(name);
  const targets = v4(auth.servers);
  const servers = await Promise.all(
    targets.map(async (t): Promise<AuthServerAnswer> => {
      try {
        const [res, soa] = await Promise.all([
          q(t.ip, name, type, { rd: false, timeoutMs: 3000 }),
          q(t.ip, auth.zone, 'SOA', { rd: false, timeoutMs: 3000 }).catch(() => undefined),
        ]);
        const s = soa?.answers.find((a) => a.type === 'SOA')?.data as { serial?: number } | undefined;
        return {
          ns: t.ns,
          ip: t.ip,
          rcode: res.rcode,
          aa: res.flags.aa,
          rtt: res.rtt,
          answers: res.answers.filter((a) => a.type === type || a.type === 'CNAME').map(toRecord),
          serial: s?.serial,
        };
      } catch (e) {
        return { ns: t.ns, ip: t.ip, rcode: 'TIMEOUT', aa: false, answers: [], error: (e as Error).message };
      }
    }),
  );
  const answering = servers.filter((s) => !s.error && s.aa && ['NOERROR', 'NXDOMAIN'].includes(s.rcode));
  const groups = new Map<string, { answers: string[]; servers: string[] }>();
  for (const s of answering) {
    const k = s.rcode + '|' + sig(s.answers).join('\n');
    const g = groups.get(k) ?? { answers: s.rcode === 'NXDOMAIN' ? ['NXDOMAIN'] : sig(s.answers), servers: [] };
    g.servers.push(`${s.ns} (${s.ip})`);
    groups.set(k, g);
  }
  const serials = [...new Set(servers.map((s) => s.serial).filter((x): x is number => x !== undefined))];
  return {
    zone: auth.zone,
    servers,
    consistent: groups.size <= 1,
    serials,
    serialsConsistent: serials.length <= 1,
    lame: servers.filter((s) => s.error || !s.aa || s.rcode === 'REFUSED' || s.rcode === 'SERVFAIL').map((s) => `${s.ns} (${s.ip})${s.error ? ' : ' + s.error : s.rcode !== 'NOERROR' ? ' : ' + s.rcode : ' : ' + t('réponse non autoritaire')}`),
    variants: [...groups.values()],
  };
}

export function authoritativeIssues(name: string, a: AllAuthoritative): { issues: Issue[]; passed: PassedCheck[] } {
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const v = { domain: a.zone, value: name };
  if (!a.consistent)
    issues.push(issue('infrastructure.dns_inconsistent', v, { evidence: a.variants.map((g) => `${g.servers.join(', ')} :\n  ${g.answers.join('\n  ') || t('(aucune donnée)')}`).join('\n') }));
  else if (a.servers.length > 1) passed.push(pass('dns.authoritative_consistent', 'infrastructure', t('Les {n} serveurs autoritaires donnent la même réponse', { n: a.servers.length })));
  if (!a.serialsConsistent)
    issues.push(issue('infrastructure.soa_serial_mismatch', { ...v, value: a.serials.join(', ') }, { evidence: a.servers.map((s) => t('{ns} ({ip}) : serial {serial}', { ns: s.ns, ip: s.ip, serial: s.serial ?? '?' })).join('\n') }));
  else if (a.serials.length) passed.push(pass('dns.soa_serial', 'infrastructure', `Serial SOA identique partout (${a.serials[0]})`));
  if (a.lame.length) issues.push(issue('infrastructure.dns_lame_server', { ...v, value: a.lame.length }, { evidence: a.lame.join('\n') }));
  return { issues, passed };
}

export interface LookupOptions {
  type?: string;
  server?: string;
  all?: boolean;
  dnssec?: boolean;
}

export async function dnsLookup(
  makeSession: (o?: { dnssec?: boolean }) => AuthorityResolver,
  input: string,
  opts: LookupOptions,
  q: QueryFn = rawQuery,
): Promise<Analysis & { data: DnsLookupData }> {
  const started = performance.now();
  const raw = String(input ?? '').trim();
  const isIp = net.isIP(raw) !== 0;
  const type = (opts.type ?? (isIp ? 'PTR' : 'A')).toUpperCase();
  if (type === 'ANY')
    throw new InvalidInputError(t('Le type ANY n’est plus servi par la plupart des serveurs (RFC 8482) : choisissez un type précis, ou lancez le scanner de domaine pour tout voir.'));
  if (!(QUERY_TYPES as readonly string[]).includes(type)) throw new InvalidInputError(t('Type « {type} » non pris en charge. Types : {list}.', { type, list: QUERY_TYPES.join(', ') }));
  const name = isIp ? reverseName(raw) : type === 'SRV' || type === 'TLSA' || type === 'PTR' ? normalizeUnderscore(raw) : normalizeDomain(raw);
  const wire = (WIRE_TYPE[type] ?? type) as RRType;
  const session = makeSession({ dnssec: opts.dnssec });
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  const unavailable: { source: string; reason: string }[] = [];
  const data: DnsLookupData = { name, type, mode: opts.server ? 'resolver' : opts.all ? 'all' : 'authoritative', rcode: '', answers: [], signatures: [], cnames: [], trace: [], dig: '', ms: 0 };
  const when = measuredAt();

  if (opts.server) {
    const server = opts.server.trim();
    if (!net.isIP(server)) throw new InvalidInputError(t("« {server} » n'est pas une adresse IP de serveur DNS.", { server }));
    if (!isPublicIp(server)) throw new InvalidInputError(t('« {server} » est une adresse privée ou locale : seuls les résolveurs publics sont interrogés.', { server }));
    try {
      const res = await q(server, name, wire, { rd: true, dnssec: opts.dnssec, timeoutMs: 4000 });
      data.rcode = res.rcode;
      data.flags = { aa: res.flags.aa, ra: res.flags.ra, ad: res.flags.ad, tc: res.flags.tc };
      data.server = server;
      data.rtt = res.rtt;
      data.answers = res.answers.filter((a) => a.type !== 'RRSIG').map(toRecord);
      data.signatures = res.answers.filter((a) => a.type === 'RRSIG').map(toRecord);
      data.cnames = res.answers.filter((a) => a.type === 'CNAME').map((a) => norm(String(a.data)));
      const flags = Object.entries(data.flags).filter(([, v]) => v).map(([k]) => k);
      data.dig = digText({ name, type, rcode: res.rcode, flags: ['qr', 'rd', ...flags], answers: [...data.answers, ...data.signatures], authority: res.authorities.map(toRecord), server: `${server}#53 (${res.transport.toUpperCase()})`, ms: res.rtt, when, comment: t('résolveur choisi, réponse issue de son cache éventuel') });
    } catch (e) {
      data.rcode = 'TIMEOUT';
      unavailable.push({ source: server, reason: (e as Error).message });
      data.dig = `;; connection timed out; no servers could be reached (${server})`;
    }
  } else if (type === 'DS') {
    // DS lives in the parent zone: ask the parent's servers directly.
    const auth = await session.findAuthorities(name);
    const parentName = auth.zone === name ? name.split('.').slice(1).join('.') : auth.zone;
    const parent = parentName ? await session.findAuthorities(parentName) : undefined;
    const servers = parent ? v4(parent.servers) : [];
    let res: DnsResponse | undefined;
    for (const s of servers.slice(0, 4)) {
      try {
        res = await q(s.ip, name, 'DS', { rd: false, dnssec: opts.dnssec, timeoutMs: 3000 });
        data.answeredBy = `${s.ns} (${s.ip})`;
        break;
      } catch {
        /* next server */
      }
    }
    data.zone = parent?.zone;
    data.rcode = res?.rcode ?? 'TIMEOUT';
    data.rtt = res?.rtt;
    data.answers = (res?.answers ?? []).filter((a) => a.type === 'DS').map(toRecord);
    data.signatures = (res?.answers ?? []).filter((a) => a.type === 'RRSIG').map(toRecord);
    data.dig = digText({ name, type, rcode: data.rcode, flags: res?.flags.aa ? ['qr', 'aa'] : ['qr'], answers: [...data.answers, ...data.signatures], server: data.answeredBy, ms: res?.rtt, when, comment: t('serveur autoritaire du parent {zone}', { zone: data.zone ?? '?' }) });
  } else {
    try {
      const r = await session.resolve(name, wire);
      data.rcode = r.rcode;
      data.answers = r.answers.filter((a) => a.type !== 'RRSIG').map(toRecord);
      data.signatures = r.answers.filter((a) => a.type === 'RRSIG').map(toRecord);
      data.cnames = r.cnames;
      data.zone = r.zone;
      data.answeredBy = r.answeredBy;
      data.trace = r.trace;
      data.rtt = r.trace.at(-1)?.rtt;
      const auth = r.soa ? [toRecord(r.soa)] : [];
      data.dig = digText({ name, type, rcode: r.rcode, flags: ['qr', 'aa'], answers: [...data.answers, ...data.signatures], authority: data.answers.length ? [] : auth, server: r.answeredBy, ms: r.ms, when, comment: r.cnames.length ? t('réponse autoritaire, résolue depuis la racine, CNAME suivis : {cnames}', { cnames: r.cnames.join(' → ') }) : t('réponse autoritaire, résolue depuis la racine') });
    } catch (e) {
      data.rcode = (e as { code?: string }).code ?? 'SERVFAIL';
      data.trace = (e as { result?: { trace: TraceStep[] } }).result?.trace ?? [];
      unavailable.push({ source: 'dns', reason: (e as Error).message });
      data.dig = `;; ${data.rcode} ${(e as Error).message}`;
    }
    if (opts.all) {
      try {
        data.authoritative = await queryAllAuthoritative(session, name, wire, q);
        const x = authoritativeIssues(name, data.authoritative);
        issues.push(...x.issues);
        passed.push(...x.passed);
      } catch (e) {
        unavailable.push({ source: 'autoritaires', reason: (e as Error).message });
      }
    }
  }

  if (isIp && type === 'PTR') {
    const names = data.answers.filter((a) => a.type === 'PTR').map((a) => norm(a.value));
    const fcrdns = await Promise.all(
      names.map(async (n) => {
        const a = await lookupAddresses(session, n);
        return { name: n, ips: a.ips, matches: a.ips.some((ip) => sameIp(ip, raw)) };
      }),
    );
    data.ptr = { ip: raw, names, fcrdns };
    const v = { ip: raw, ptr: names[0] };
    // no sender domain here: a valid example domain, and the PTR line ready to copy (same as tools/ip)
    if (!names.length)
      issues.push(
        issue('rdns.missing', { ...v, domain: 'exemple.fr' }, {
          evidence: `${name} : ${data.rcode}`,
          suggested: `${name.replace(/\.$/, '')}. IN PTR mail.exemple.fr.`,
        }),
      );
    else {
      if (names.length > 1) issues.push(issue('rdns.multiple_ptr', { ...v, value: names.length }, { evidence: names.join('\n') }));
      const dead = fcrdns.filter((f) => !f.ips.length);
      if (dead.length) issues.push(issue('rdns.ptr_target_nxdomain', { ...v, ptr: dead[0].name }, { evidence: dead.map((d) => d.name).join(', ') }));
      if (!fcrdns.some((f) => f.matches) && dead.length < fcrdns.length)
        issues.push(issue('rdns.fcrdns_mismatch', v, { evidence: fcrdns.map((f) => `${f.name} → ${f.ips.join(', ') || t('aucune adresse')}`).join('\n') }));
      if (fcrdns.some((f) => f.matches)) passed.push(pass('rdns.fcrdns', 'rdns', t('Reverse DNS confirmé (FCrDNS) : {name}', { name: fcrdns.find((f) => f.matches)!.name })));
    }
  }
  data.ms = Math.round(performance.now() - started);
  return { issues, passed, unavailable: unavailable.length ? unavailable : undefined, data };
}

function sameIp(a: string, b: string): boolean {
  try {
    return reverseName(a) === reverseName(b);
  } catch {
    return false;
  }
}

/** Service names (_sip._tcp.example.com, _25._tcp.mx.example.com) keep their underscores. */
function normalizeUnderscore(raw: string): string {
  const s = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!/^[a-z0-9_.-]+$/.test(s) || s.length > 253 || s.split('.').some((l) => !l || l.length > 63))
    throw new InvalidInputError(t("« {raw} » n'est pas un nom DNS valide.", { raw }));
  return s;
}
