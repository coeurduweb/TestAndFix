// Shared plumbing for the e-mail authentication analyzers (SPF, DKIM, DMARC, BIMI, MTA-STS, DNSSEC).
// The analyzers never talk to node:dns: they take a Resolver (a ResolveSession in production,
// a fake in tests) and return plain data plus "issues" that the caller turns into findings.
import { domainToASCII } from 'node:url';
import net from 'node:net';
import psl from 'psl';
import type { RRType } from '../../dns/client.js';
import { DnsLookupError, type NameServer, type ResolveResult, type ResolveSession } from '../../dns/iterative.js';
import type { ExplainInput, Finding, Severity } from '../../knowledge/engine.js';
import { explain, fill, knowledge } from '../../knowledge/engine.js';
import type { PassedCheck } from '../../tools/types.js';
import { FALLBACKS } from './situations.js';
import { t } from '../../i18n.js';

/** What the analyzers need from a DNS session. ResolveSession satisfies it. */
export interface Resolver {
  resolve(name: string, type: RRType): Promise<ResolveResult>;
}

/** A session able to locate the authoritative servers of a zone (ResolveSession, GuardedResolver). */
export interface AuthorityResolver extends Resolver {
  findAuthorities(name: string): Promise<{ zone: string; servers: NameServer[] }>;
}

/** A detected situation, before it is turned into a Finding by the knowledge engine. */
export type Issue = ExplainInput & {
  /** Replace the references of the base entry (sources that fit the detected provider). */
  references?: string[];
  /** Other detected providers (the DNS host…) whose fix_by_provider step is appended to fix. */
  alsoProviders?: string[];
};

export interface Analysis {
  issues: Issue[];
  passed: PassedCheck[];
  unavailable?: { source: string; reason: string }[];
  /** Highest score allowed whatever the penalties (a bogus DNSSEC chain…). */
  scoreCap?: number;
}

/** Build an issue with the fallback text of the catalogue (used when the base has no entry yet). */
export function issue(
  id: string,
  vars: ExplainInput['vars'] = {},
  extra: Partial<Omit<Issue, 'id' | 'vars'>> = {},
): Issue {
  // explain() lets a fallback's severity/penalty override the base entry: attach the fallback
  // only for ids the base does not hold, so that a new base entry wins as soon as it exists.
  if (knowledge().has(id)) return { id, vars, ...extra };
  const fb = FALLBACKS[id];
  return {
    id,
    vars,
    ...extra,
    fallback: extra.fallback ?? (fb ? { ...fb, family: fb.family ?? id.split('.')[0], title: t(fb.title), why: fb.why ? t(fb.why) : undefined, fix: fb.fix?.map((x) => t(x)) } : { title: id }),
  };
}

export function pass(id: string, family: string, title: string, detail?: string): PassedCheck {
  return detail ? { id, family, title, detail } : { id, family, title };
}

export function toFindings(issues: Issue[]): Finding[] {
  return issues.map((i) => {
    const f = explain(i);
    // A correction computed for this domain replaces the generic example of the base, whose
    // placeholder values (rua=mailto:dmarc@{domain}…) would contradict it.
    if (f.suggested) delete f.exampleGood;
    if (i.references) f.references = i.references;
    const entry = knowledge().get(i.id);
    for (const p of i.alsoProviders ?? []) {
      const text = entry?.fix_by_provider?.[p];
      if (text) f.fix.push(fill(text, { ...i.vars, suggested_record: i.suggested }));
    }
    return f;
  });
}

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ---------------------------------------------------------------------------------------------
// Names

export class InvalidInputError extends Error {
  code = 'INVALID_INPUT';
}

const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;

/** Lower-case, IDNA (punycode), no trailing dot. Throws InvalidInputError on a malformed name. */
export function normalizeDomain(input: string): string {
  let s = String(input ?? '').trim().toLowerCase();
  // tolerate a pasted URL or address
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^[^@/]*@/, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '');
  s = s.replace(/\.$/, '');
  if (!s) throw new InvalidInputError(t('Nom de domaine vide.'));
  if (net.isIP(s)) throw new InvalidInputError(t('« {value} » est une adresse IP, pas un nom de domaine.', { value: s }));
  const ascii = domainToASCII(s);
  if (!ascii) throw new InvalidInputError(t("« {value} » n'est pas un nom de domaine valide.", { value: input }));
  if (ascii.length > 253 || !ascii.split('.').every((l) => LABEL.test(l)))
    throw new InvalidInputError(t("« {value} » n'est pas un nom de domaine valide.", { value: input }));
  return ascii;
}

export const norm = (n: string) => String(n).replace(/\.$/, '').toLowerCase();

/** Organizational domain from the Public Suffix List (RFC 7489 §3.2). */
export function orgDomain(domain: string): string {
  const d = norm(domain);
  return psl.get(d) ?? d;
}

// ---------------------------------------------------------------------------------------------
// DNS helpers

export interface TxtLookup {
  name: string;
  rcode: string;
  /** Each record with its character-strings joined (RFC 7208 §3.3). */
  records: string[];
  /** Each record as its raw character-strings, to check splitting. */
  chunks: string[][];
  cnames: string[];
  ttl?: number;
  /** Set when the lookup failed (SERVFAIL, timeout): result is temporary. */
  error?: string;
  /** Rough size of the DNS response carrying every TXT record of the name (octets). */
  responseSize: number;
}

export function txtStrings(data: unknown): string[] {
  const arr = Array.isArray(data) ? data : [data];
  return arr.map((b) => (Buffer.isBuffer(b) ? b.toString('utf8') : b instanceof Uint8Array ? Buffer.from(b).toString('utf8') : String(b)));
}

function nameWireLength(name: string): number {
  const n = norm(name);
  return n ? n.split('.').reduce((s, l) => s + 1 + Buffer.byteLength(l), 1) : 1;
}

export async function lookupTxt(dns: Resolver, name: string): Promise<TxtLookup> {
  try {
    const r = await dns.resolve(name, 'TXT');
    const txt = r.answers.filter((a) => a.type === 'TXT');
    const chunks = txt.map((a) => txtStrings(a.data));
    // header 12 + question + per answer (compressed name 2 + type/class/ttl/len 10 + rdata) + OPT 11
    const rdata = (c: string[]) => c.reduce((s, x) => s + 1 + Buffer.byteLength(x), 0);
    const responseSize = 12 + nameWireLength(name) + 4 + chunks.reduce((s, c) => s + 12 + rdata(c), 0) + 11;
    return {
      name,
      rcode: r.rcode,
      records: chunks.map((c) => c.join('')),
      chunks,
      cnames: r.cnames,
      ttl: txt[0]?.ttl,
      responseSize,
    };
  } catch (e) {
    return { name, rcode: (e as { code?: string }).code ?? 'SERVFAIL', records: [], chunks: [], cnames: [], error: (e as Error).message, responseSize: 0 };
  }
}

export interface AddrLookup {
  rcode: string;
  ips: string[];
  error?: string;
  cnames: string[];
}

export async function lookupType(dns: Resolver, name: string, type: RRType): Promise<{ rcode: string; data: unknown[]; error?: string; cnames: string[]; ttl?: number }> {
  try {
    const r = await dns.resolve(name, type);
    const recs = r.answers.filter((a) => a.type === type);
    return { rcode: r.rcode, data: recs.map((a) => a.data), cnames: r.cnames, ttl: recs[0]?.ttl };
  } catch (e) {
    return { rcode: (e as { code?: string }).code ?? 'SERVFAIL', data: [], error: (e as Error).message, cnames: [] };
  }
}

export async function lookupAddresses(dns: Resolver, name: string, families: ('A' | 'AAAA')[] = ['A', 'AAAA']): Promise<AddrLookup> {
  const res = await Promise.all(families.map((t) => lookupType(dns, name, t)));
  const ips = res.flatMap((r) => r.data.map(String));
  const err = res.find((r) => r.error);
  const nx = res.every((r) => r.rcode === 'NXDOMAIN');
  return {
    rcode: ips.length ? 'NOERROR' : err ? err.rcode : nx ? 'NXDOMAIN' : 'NOERROR',
    ips,
    error: ips.length ? undefined : err?.error,
    cnames: res.flatMap((r) => r.cnames),
  };
}

export interface MxRecord {
  preference: number;
  exchange: string;
}

export async function lookupMx(dns: Resolver, name: string): Promise<{ rcode: string; mx: MxRecord[]; error?: string }> {
  const r = await lookupType(dns, name, 'MX');
  const mx = r.data
    .map((d) => d as { preference: number; exchange: string })
    .map((d) => ({ preference: Number(d.preference), exchange: norm(d.exchange) }))
    .sort((a, b) => a.preference - b.preference || a.exchange.localeCompare(b.exchange));
  return { rcode: r.rcode, mx, error: r.error };
}

/** Parse "k=v; k2=v2" tag lists (DKIM, DMARC, BIMI, MTA-STS, TLS-RPT). Keeps order and duplicates. */
export function parseTags(record: string): { tags: { name: string; value: string; raw: string }[]; errors: string[] } {
  const tags: { name: string; value: string; raw: string }[] = [];
  const errors: string[] = [];
  for (const part of record.split(';')) {
    const raw = part.trim();
    if (!raw) continue;
    const eq = raw.indexOf('=');
    if (eq <= 0) {
      errors.push(raw);
      continue;
    }
    const name = raw.slice(0, eq).trim();
    const value = raw.slice(eq + 1).trim();
    if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(name)) {
      errors.push(raw);
      continue;
    }
    tags.push({ name: name.toLowerCase(), value, raw });
  }
  return { tags, errors };
}

/** Run async jobs with a concurrency limit, keeping the input order. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

/** Split a long TXT value into quoted 255-octet strings, as a zone file or DNS panel expects. */
export function splitTxt(value: string, size = 255): string {
  const parts: string[] = [];
  for (let i = 0; i < value.length; i += size) parts.push(value.slice(i, i + size));
  return parts.map((p) => `"${p.replace(/(["\\])/g, '\\$1')}"`).join(' ');
}

export function daysBetween(a: number, b: number): number {
  return Math.floor((a - b) / 86400000);
}

export class DeadlineError extends Error {
  code = 'DEADLINE';
}

/**
 * Reject after `ms`. A resolution can stall forever inside a ResolveSession (in-flight
 * deduplication loop on name servers without glue): no check may hang a request because of it.
 */
export function deadline<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout;
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new DeadlineError(t('{label} : pas de réponse en {s} s', { label, s: Math.round(ms / 1000) }))), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

/**
 * Wraps the session of one action with a deadline per query. When parallel lookups of one
 * ResolveSession wait on each other forever (in-flight deduplication across name servers
 * without glue: request filed against dns/iterative.ts), the stalled query is retried on a new
 * session obtained from ctx.dns(), which then serves the rest of the action. No answer is ever
 * reused: the new session starts from the root like the first one.
 */
export class GuardedResolver implements AuthorityResolver {
  public stalls = 0;
  constructor(
    private session: ResolveSession,
    private fresh: () => ResolveSession,
    private ms = 4000,
  ) {}

  private async guarded<T>(label: string, run: (s: ResolveSession) => Promise<T>): Promise<T> {
    const first = this.session;
    try {
      return await deadline(run(first), this.ms, label);
    } catch (e) {
      if (!(e instanceof DeadlineError)) throw e;
      this.stalls++;
      if (this.session === first) this.session = this.fresh();
      try {
        return await deadline(run(this.session), this.ms * 2, label);
      } catch (e2) {
        if (e2 instanceof DeadlineError) throw new DnsLookupError('TIMEOUT', e2.message);
        throw e2;
      }
    }
  }

  resolve(name: string, type: RRType): Promise<ResolveResult> {
    return this.guarded(`${name} ${type}`, (s) => s.resolve(name, type));
  }

  findAuthorities(name: string): Promise<{ zone: string; servers: NameServer[] }> {
    return this.guarded(`serveurs de ${name}`, (s) => s.findAuthorities(name));
  }

  /** The current underlying session (for APIs that need a ResolveSession). */
  get current(): ResolveSession {
    return this.session;
  }
}
