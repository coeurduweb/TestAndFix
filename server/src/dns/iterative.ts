// Iterative resolution from the root servers, without any recursive resolver in between.
// This is how the tool gets the authoritative truth with no network cache: each lookup walks
// root -> TLD -> zone itself. A ResolveSession memoizes delegations for the duration of ONE
// user action only (a domain scan, a mail analysis) and is then discarded.
import net from 'node:net';
import ipaddr from 'ipaddr.js';
import { query, type DnsAnswer, type DnsResponse, type RRType } from './client.js';

export const ROOT_SERVERS: Record<string, string> = {
  'a.root-servers.net': '198.41.0.4',
  'b.root-servers.net': '170.247.170.2',
  'c.root-servers.net': '192.33.4.12',
  'd.root-servers.net': '199.7.91.13',
  'e.root-servers.net': '192.203.230.10',
  'f.root-servers.net': '192.5.5.241',
  'g.root-servers.net': '192.112.36.4',
  'h.root-servers.net': '198.97.190.53',
  'i.root-servers.net': '192.36.148.17',
  'j.root-servers.net': '192.58.128.30',
  'k.root-servers.net': '193.0.14.129',
  'l.root-servers.net': '199.7.83.42',
  'm.root-servers.net': '202.12.27.33',
};

export interface NameServer {
  name: string;
  ips: string[];
}

export interface TraceStep {
  zone: string;
  server: string;
  serverName?: string;
  rtt: number;
  outcome: 'referral' | 'answer' | 'nxdomain' | 'nodata' | 'cname' | 'error';
  detail?: string;
}

export interface ResolveResult {
  name: string;
  type: RRType;
  rcode: 'NOERROR' | 'NXDOMAIN' | 'SERVFAIL' | 'TIMEOUT' | string;
  answers: DnsAnswer[];
  /** CNAME chain followed, in order. */
  cnames: string[];
  /** Zone that answered authoritatively, and its name servers. */
  zone?: string;
  authority?: NameServer[];
  /** Server that gave the final answer. */
  answeredBy?: string;
  authenticated?: boolean;
  soa?: DnsAnswer;
  trace: TraceStep[];
  ms: number;
}

export class DnsLookupError extends Error {
  constructor(public code: string, message: string, public result?: ResolveResult) {
    super(message);
  }
}

const norm = (n: string) => n.replace(/\.$/, '').toLowerCase();

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/** Public unicast address (IPv4-mapped IPv6 judged as IPv4). Local copy of lib/net isPublicIp: lib/net imports this module. */
function isPublicAddress(ip: string): boolean {
  if (!ipaddr.isValid(ip)) return false;
  let a = ipaddr.parse(ip);
  if (a.kind() === 'ipv6' && (a as ipaddr.IPv6).isIPv4MappedAddress()) a = (a as ipaddr.IPv6).toIPv4Address();
  return a.range() === 'unicast';
}

export interface SessionOptions {
  timeoutMs?: number;
  /** Max servers tried per zone before giving up. */
  maxServersPerZone?: number;
  ipv6?: boolean;
  dnssec?: boolean;
  /** Upper bound for one top-level resolution (default 15 s). */
  deadlineMs?: number;
}

export class ResolveSession {
  /** zone -> name servers with resolved IPs. Lives only as long as this session. */
  private delegations = new Map<string, NameServer[]>();
  private inflight = new Map<string, Promise<ResolveResult>>();
  public queries = 0;
  constructor(private opts: SessionOptions = {}) {
    this.delegations.set(
      '',
      Object.entries(ROOT_SERVERS).map(([name, ip]) => ({ name, ips: [ip] })),
    );
  }

  /** Deepest known zone enclosing `name`. */
  private closestZone(name: string, excludeSelf = false): string {
    const labels = norm(name).split('.');
    for (let i = excludeSelf ? 1 : 0; i < labels.length; i++) {
      const z = labels.slice(i).join('.');
      if (this.delegations.has(z)) return z;
    }
    return '';
  }

  /**
   * A name-server address worth asking: the right family, and public. Glue or a resolved address
   * pointing at a private, loopback or reserved network would make the server query its own network
   * (code review of 2026-11-12; tools/dns refuses such a `server` typed by hand).
   */
  private usable(ip: string) {
    return (net.isIPv4(ip) || (!!this.opts.ipv6 && net.isIPv6(ip))) && isPublicAddress(ip);
  }

  private async serverIps(ns: NameServer, depth: number, chain: ReadonlySet<string> = new Set()): Promise<string[]> {
    if (ns.ips.length) return ns.ips.filter((ip) => this.usable(ip));
    try {
      const r = await this.resolve(ns.name, 'A', depth + 1, chain);
      ns.ips = r.answers.filter((a) => a.type === 'A').map((a) => String(a.data));
    } catch {
      ns.ips = [];
    }
    return ns.ips.filter((ip) => this.usable(ip));
  }

  /** Ask the servers of `zone` about name/type, trying them in random order. */
  private async askZone(
    zone: string,
    name: string,
    type: RRType,
    depth: number,
    trace: TraceStep[],
    chain: ReadonlySet<string>,
  ): Promise<{ res: DnsResponse; ns: NameServer }> {
    const servers = shuffle(this.delegations.get(zone) ?? []);
    const max = this.opts.maxServersPerZone ?? 4;
    let lastErr: unknown;
    let tried = 0;
    for (const ns of servers) {
      if (tried >= max) break;
      const ips = await this.serverIps(ns, depth, chain);
      for (const ip of ips.slice(0, 1)) {
        tried++;
        try {
          this.queries++;
          const res = await query(ip, name, type, {
            rd: false,
            dnssec: this.opts.dnssec,
            timeoutMs: this.opts.timeoutMs ?? 2000,
          });
          if (res.rcode === 'SERVFAIL' || res.rcode === 'REFUSED' || res.rcode === 'FORMERR' || res.rcode === 'NOTIMP') {
            trace.push({ zone, server: ip, serverName: ns.name, rtt: res.rtt, outcome: 'error', detail: res.rcode });
            lastErr = new DnsLookupError(res.rcode, `${ns.name} answered ${res.rcode}`);
            continue;
          }
          return { res, ns };
        } catch (e) {
          trace.push({ zone, server: ip, serverName: ns.name, rtt: 0, outcome: 'error', detail: (e as Error).message });
          lastErr = e;
        }
      }
    }
    throw lastErr instanceof Error ? lastErr : new DnsLookupError('SERVFAIL', `No server of zone "${zone || '.'}" answered`);
  }

  async resolve(name: string, type: RRType, depth = 0, chain: ReadonlySet<string> = new Set()): Promise<ResolveResult> {
    const key = `${norm(name)}|${type}`;
    if (chain.has(key)) throw new DnsLookupError('ELOOP', `Circular dependency resolving ${name}`);
    const next = new Set(chain).add(key);
    // Nested lookups (name servers without glue) are never deduplicated: two parallel lookups whose
    // name servers depend on each other would otherwise wait on each other forever.
    if (depth > 0) return this.withDeadline(this.doResolve(name, type, depth, next), name);
    const pending = this.inflight.get(key);
    if (pending) return pending;
    const p = this.withDeadline(this.doResolve(name, type, depth, next), name);
    this.inflight.set(key, p);
    try {
      return await p;
    } finally {
      // in-flight dedup only: a finished lookup is never served again
      this.inflight.delete(key);
    }
  }

  private withDeadline<T>(p: Promise<T>, name: string): Promise<T> {
    const ms = this.opts.deadlineMs ?? 15000;
    let timer: NodeJS.Timeout;
    return Promise.race([
      p,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new DnsLookupError('TIMEOUT', `Resolution of ${name} took more than ${ms} ms`)), ms);
        timer.unref?.();
      }),
    ]).finally(() => clearTimeout(timer));
  }

  private async doResolve(name: string, type: RRType, depth: number, chain: ReadonlySet<string>): Promise<ResolveResult> {
    const started = performance.now();
    if (depth > 12) throw new DnsLookupError('ELOOP', `Resolution depth exceeded for ${name}`);
    const trace: TraceStep[] = [];
    const cnames: string[] = [];
    let current = norm(name);
    for (let hop = 0; hop < 30; hop++) {
      // DS records live in the parent zone: never ask the child for them
      const zone = this.closestZone(current, type === 'DS');
      let res: DnsResponse;
      let ns: NameServer;
      try {
        ({ res, ns } = await this.askZone(zone, current, type, depth, trace, chain));
      } catch (e) {
        const code = (e as { code?: string }).code ?? 'SERVFAIL';
        throw new DnsLookupError(code === 'ETIMEOUT' ? 'TIMEOUT' : code, (e as Error).message, {
          name, type, rcode: code === 'ETIMEOUT' ? 'TIMEOUT' : 'SERVFAIL', answers: [], cnames, trace,
          ms: Math.round(performance.now() - started),
        });
      }
      const step: TraceStep = { zone: zone || '.', server: res.server, serverName: ns.name, rtt: res.rtt, outcome: 'answer' };
      const ofName = (a: DnsAnswer) => norm(a.name) === current;
      const direct = res.answers.filter((a) => ofName(a) && a.type === type);
      const cname = res.answers.find((a) => ofName(a) && a.type === 'CNAME');

      const finalResult = (rcode: string, answers: DnsAnswer[]): ResolveResult => ({
        name,
        type,
        rcode,
        answers,
        cnames,
        zone: zone || '.',
        authority: this.delegations.get(zone),
        answeredBy: `${ns.name} (${res.server})`,
        authenticated: res.flags.ad,
        soa: res.authorities.find((a) => a.type === 'SOA'),
        trace,
        ms: Math.round(performance.now() - started),
      });

      if (res.rcode === 'NXDOMAIN') {
        trace.push({ ...step, outcome: 'nxdomain' });
        return finalResult('NXDOMAIN', []);
      }
      if (direct.length) {
        trace.push(step);
        // keep RRSIGs when asked
        const sigs = this.opts.dnssec ? res.answers.filter((a) => a.type === 'RRSIG' && ofName(a)) : [];
        return finalResult('NOERROR', [...direct, ...sigs]);
      }
      if (cname && type !== 'CNAME') {
        trace.push({ ...step, outcome: 'cname', detail: String(cname.data) });
        cnames.push(norm(String(cname.data)));
        current = norm(String(cname.data));
        // the same response may already contain the target records (in-zone CNAME)
        const inline = res.answers.filter((a) => norm(a.name) === current && a.type === type);
        if (inline.length && res.flags.aa) {
          return finalResult('NOERROR', inline);
        }
        continue;
      }
      const nsRecords = res.authorities.filter((a) => a.type === 'NS');
      const referralZone = nsRecords.length ? norm(nsRecords[0].name) : undefined;
      const isReferral = !res.flags.aa && referralZone !== undefined && referralZone !== zone && current.endsWith(referralZone);
      if (isReferral && type === 'DS' && referralZone === current) {
        // the parent delegates the name itself: it holds no DS for it (insecure delegation)
        trace.push({ ...step, outcome: 'nodata', detail: 'no DS at parent' });
        return finalResult('NOERROR', []);
      }
      if (isReferral) {
        // referral: record the delegation with glue
        const glue = new Map<string, string[]>();
        for (const a of res.additionals) {
          if (a.type === 'A' || (a.type === 'AAAA' && this.opts.ipv6)) {
            const k = norm(a.name);
            glue.set(k, [...(glue.get(k) ?? []), String(a.data)]);
          }
        }
        this.delegations.set(
          referralZone,
          nsRecords.map((r) => {
            const n = norm(String(r.data));
            return { name: n, ips: glue.get(n) ?? [] };
          }),
        );
        trace.push({ ...step, outcome: 'referral', detail: referralZone });
        continue;
      }
      // authoritative, no data of this type
      trace.push({ ...step, outcome: 'nodata' });
      if (res.flags.aa && zone !== '' && !this.delegations.has(current)) {
        // remember that `zone` is authoritative for this name
      }
      return finalResult('NOERROR', []);
    }
    throw new DnsLookupError('ELOOP', `Too many referrals or CNAMEs for ${name}`);
  }

  /**
   * Find the zone apex enclosing `name` and its authoritative servers (with IPs).
   * Used to query every authoritative server directly and compare them.
   */
  async findAuthorities(name: string): Promise<{ zone: string; servers: NameServer[] }> {
    const soa = await this.resolve(name, 'SOA');
    let zone = soa.zone && soa.zone !== '.' ? soa.zone : undefined;
    if (soa.soa) zone = norm(soa.soa.name);
    if (soa.answers[0]?.type === 'SOA') zone = norm(soa.answers[0].name);
    if (!zone) throw new DnsLookupError('ENOTFOUND', `No zone found for ${name}`);
    const servers = this.delegations.get(zone) ?? [];
    await Promise.all(servers.map((s) => this.serverIps(s, 0)));
    return { zone, servers };
  }
}

/** Convert raw answers to the shapes Node's dns.promises.resolve returns (used by mailauth). */
export function toNodeShape(type: string, answers: DnsAnswer[]): unknown[] {
  const recs = answers.filter((a) => a.type === type);
  switch (type) {
    case 'TXT':
      return recs.map((a) => (a.data as Buffer[]).map((b) => (Buffer.isBuffer(b) ? b.toString('utf8') : String(b))));
    case 'MX':
      return recs.map((a) => {
        const d = a.data as { preference: number; exchange: string };
        return { priority: d.preference, exchange: norm(d.exchange) };
      });
    case 'A':
    case 'AAAA':
      return recs.map((a) => String(a.data));
    case 'CNAME':
    case 'NS':
    case 'PTR':
      return recs.map((a) => norm(String(a.data)));
    case 'SOA':
      return recs.map((a) => {
        const d = a.data as Record<string, unknown>;
        return { nsname: d.mname, hostmaster: d.rname, serial: d.serial, refresh: d.refresh, retry: d.retry, expire: d.expire, minttl: d.minimum };
      });
    default:
      return recs.map((a) => a.data);
  }
}

/**
 * A resolver with the signature of dns.promises.resolve(name, rrtype), backed by a session.
 * Errors mimic Node's codes so libraries (mailauth) behave as with the system resolver.
 */
export function nodeStyleResolver(session: ResolveSession) {
  return async (name: string, rrtype = 'A'): Promise<unknown[]> => {
    let r: ResolveResult;
    try {
      r = await session.resolve(name, rrtype as RRType);
    } catch (e) {
      const err = new Error(`queryTxt ESERVFAIL ${name}`) as Error & { code: string };
      err.code = (e as DnsLookupError).code === 'TIMEOUT' ? 'ETIMEOUT' : 'ESERVFAIL';
      throw err;
    }
    if (r.rcode === 'NXDOMAIN') {
      const err = new Error(`query ENOTFOUND ${name}`) as Error & { code: string };
      err.code = 'ENOTFOUND';
      throw err;
    }
    // A request for TXT that ended on a CNAME chain still returns records of the target
    const out = toNodeShape(rrtype, r.answers);
    if (!out.length) {
      const err = new Error(`query ENODATA ${name}`) as Error & { code: string };
      err.code = 'ENODATA';
      throw err;
    }
    return out;
  };
}
