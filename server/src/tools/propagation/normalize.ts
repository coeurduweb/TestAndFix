// Normalised comparison of DNS answers, per record type.
// Every record is turned into one canonical presentation string; two RRsets are equal when
// their sets of canonical strings are equal (order ignored, duplicates ignored).
import ipaddr from 'ipaddr.js';
import type { DnsAnswer, RRType } from '../../dns/client.js';

export const SUPPORTED_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'PTR', 'SRV', 'DS', 'DNSKEY', 'HTTPS'] as const;
export type PropType = (typeof SUPPORTED_TYPES)[number];

export function isPropType(t: string): t is PropType {
  return (SUPPORTED_TYPES as readonly string[]).includes(t);
}

/** dns-packet 5.6 has no HTTPS (65) codec: it is sent and decoded as an unknown type. */
export function wireType(t: PropType): RRType {
  return (t === 'HTTPS' ? 'UNKNOWN_65' : t) as RRType;
}

export const host = (n: unknown) => String(n ?? '').trim().replace(/\.+$/, '').toLowerCase() || '.';

function ip(v: string): string {
  try {
    return ipaddr.parse(v.trim()).toString();
  } catch {
    return v.trim().toLowerCase();
  }
}

const hex = (b: unknown) => (Buffer.isBuffer(b) ? b.toString('hex').toUpperCase() : String(b ?? '').replace(/\s+/g, '').toUpperCase());
const b64 = (b: unknown) => (Buffer.isBuffer(b) ? b.toString('base64') : String(b ?? '').replace(/\s+/g, ''));

/** Decode an SVCB/HTTPS RDATA (RFC 9460) into presentation format. */
export function svcbToText(buf: Buffer): string {
  try {
    let o = 0;
    const priority = buf.readUInt16BE(o);
    o += 2;
    const labels: string[] = [];
    while (o < buf.length) {
      const len = buf[o++];
      if (len === 0) break;
      labels.push(buf.subarray(o, o + len).toString('ascii'));
      o += len;
    }
    const target = labels.length ? labels.join('.').toLowerCase() : '.';
    const params: string[] = [];
    while (o + 4 <= buf.length) {
      const key = buf.readUInt16BE(o);
      const len = buf.readUInt16BE(o + 2);
      const v = buf.subarray(o + 4, o + 4 + len);
      o += 4 + len;
      switch (key) {
        case 0: {
          const keys: number[] = [];
          for (let i = 0; i + 1 < v.length; i += 2) keys.push(v.readUInt16BE(i));
          params.push(`mandatory=${keys.map(keyName).join(',')}`);
          break;
        }
        case 1: {
          const ids: string[] = [];
          for (let i = 0; i < v.length; ) {
            const l = v[i++];
            ids.push(v.subarray(i, i + l).toString('ascii'));
            i += l;
          }
          params.push(`alpn=${ids.join(',')}`);
          break;
        }
        case 2:
          params.push('no-default-alpn');
          break;
        case 3:
          params.push(`port=${v.readUInt16BE(0)}`);
          break;
        case 4: {
          const ips: string[] = [];
          for (let i = 0; i + 3 < v.length; i += 4) ips.push([...v.subarray(i, i + 4)].join('.'));
          params.push(`ipv4hint=${ips.join(',')}`);
          break;
        }
        case 5:
          params.push(`ech=${v.toString('base64')}`);
          break;
        case 6: {
          const ips: string[] = [];
          for (let i = 0; i + 15 < v.length; i += 16) ips.push(ipaddr.fromByteArray([...v.subarray(i, i + 16)]).toString());
          params.push(`ipv6hint=${ips.join(',')}`);
          break;
        }
        default:
          params.push(`${keyName(key)}=${v.toString('hex')}`);
      }
    }
    return [String(priority), target, ...params].join(' ');
  } catch {
    return hex(buf);
  }
}

function keyName(k: number): string {
  return ['mandatory', 'alpn', 'no-default-alpn', 'port', 'ipv4hint', 'ech', 'ipv6hint'][k] ?? `key${k}`;
}

const txtOf = (data: unknown): string => {
  if (Array.isArray(data)) return data.map((b) => (Buffer.isBuffer(b) ? b.toString('utf8') : String(b))).join('');
  return Buffer.isBuffer(data) ? data.toString('utf8') : String(data ?? '');
};

/** Canonical presentation of one record decoded by dns-packet. */
export function formatRecord(t: PropType, data: unknown): string {
  const d = data as Record<string, unknown>;
  switch (t) {
    case 'A':
    case 'AAAA':
      return ip(String(data));
    case 'CNAME':
    case 'NS':
    case 'PTR':
      return host(data);
    case 'MX':
      return `${Number(d.preference)} ${host(d.exchange)}`;
    case 'TXT':
      return txtOf(data);
    case 'SOA':
      return `${host(d.mname)} ${host(d.rname)} ${d.serial} ${d.refresh} ${d.retry} ${d.expire} ${d.minimum}`;
    case 'CAA':
      return `${Number(d.flags ?? 0)} ${String(d.tag).toLowerCase()} "${String(d.value)}"`;
    case 'SRV':
      return `${d.priority} ${d.weight} ${d.port} ${host(d.target)}`;
    case 'DS':
      return `${d.keyTag} ${d.algorithm} ${d.digestType} ${hex(d.digest)}`;
    case 'DNSKEY':
      return `${d.flags} 3 ${d.algorithm} ${b64(d.key)}`;
    case 'HTTPS':
      return Buffer.isBuffer(data) ? svcbToText(data) : String(data);
  }
}

/** Parse a TXT value typed by a user: `"a" "b"` is the concatenation ab; unquoted text is kept as is. */
function parseTxt(line: string): string {
  const s = line.trim();
  if (!s.startsWith('"')) return s;
  const parts = [...s.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, '$1'));
  return parts.length ? parts.join('') : s;
}

/**
 * Turn the user's `expected` value into canonical strings for type t.
 * Several values: one per line; for address and host types, commas and spaces also separate.
 */
export function normalizeExpected(t: PropType, input: string): string[] {
  const lines = input
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const out: string[] = [];
  for (const line of lines) {
    switch (t) {
      case 'A':
      case 'AAAA':
        for (const p of line.split(/[\s,;]+/).filter(Boolean)) out.push(ip(p));
        break;
      case 'CNAME':
      case 'NS':
      case 'PTR':
        for (const p of line.split(/[\s,;]+/).filter(Boolean)) out.push(host(p));
        break;
      case 'MX':
        for (const p of line.split(/[,;]+/).map((x) => x.trim()).filter(Boolean)) {
          const m = p.match(/^(\d+)\s+(\S+)$/);
          out.push(m ? `${Number(m[1])} ${host(m[2])}` : host(p));
        }
        break;
      case 'TXT':
        out.push(parseTxt(line));
        break;
      case 'CAA': {
        const m = line.match(/^(\d+)\s+(\S+)\s+(.+)$/);
        out.push(m ? `${Number(m[1])} ${m[2].toLowerCase()} "${m[3].trim().replace(/^"|"$/g, '')}"` : line);
        break;
      }
      case 'SOA': {
        const p = line.split(/\s+/);
        out.push(p.length >= 7 ? `${host(p[0])} ${host(p[1])} ${p.slice(2, 7).map(Number).join(' ')}` : line);
        break;
      }
      case 'SRV': {
        const p = line.split(/\s+/);
        out.push(p.length === 4 ? `${Number(p[0])} ${Number(p[1])} ${Number(p[2])} ${host(p[3])}` : line);
        break;
      }
      case 'DS': {
        const p = line.split(/\s+/);
        out.push(p.length >= 4 ? `${Number(p[0])} ${Number(p[1])} ${Number(p[2])} ${p.slice(3).join('').toUpperCase()}` : line);
        break;
      }
      case 'DNSKEY': {
        const p = line.split(/\s+/);
        out.push(p.length >= 4 ? `${Number(p[0])} ${Number(p[1])} ${Number(p[2])} ${p.slice(3).join('')}` : line);
        break;
      }
      case 'HTTPS': {
        const p = line.split(/\s+/);
        out.push(p.length >= 2 ? [p[0], host(p[1]), ...p.slice(2).map((x) => x.replace(/"/g, ''))].join(' ') : line);
        break;
      }
    }
  }
  return [...new Set(out)].sort();
}

/** Set equality on canonical strings. For MX, an expected value without priority matches on hosts only. */
export function sameValues(t: PropType, observed: string[], reference: string[]): boolean {
  let a = [...new Set(observed)];
  let b = [...new Set(reference)];
  if (t === 'MX' && b.some((v) => !/^\d+ /.test(v))) {
    a = [...new Set(a.map((v) => v.replace(/^\d+ /, '')))];
    b = [...new Set(b.map((v) => v.replace(/^\d+ /, '')))];
  }
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((v) => set.has(v));
}

export interface Extracted {
  /** First CNAME target of the queried name, when the name is an alias. */
  cname: string | null;
  /** Names followed through CNAMEs, in order. */
  chain: string[];
  /** Canonical records of the requested type at the end of the chain (sorted). */
  values: string[];
  /** TTL that drives the cache: of the CNAME when the name is an alias, else of the records. */
  ttl: number | null;
  /** TTL of the records at the end of the chain. */
  valuesTtl: number | null;
  /** SOA in the authority section (negative answers): its TTL bounds the negative cache. */
  negativeTtl: number | null;
}

/** Follow CNAMEs from `name` inside one answer section and pick the records of type t. */
export function extract(t: PropType, name: string, answers: DnsAnswer[], authorities: DnsAnswer[] = []): Extracted {
  const wt = wireType(t);
  const chain: string[] = [];
  let current = host(name);
  let cname: string | null = null;
  let cnameTtl: number | null = null;
  if (t !== 'CNAME') {
    for (let i = 0; i < 16; i++) {
      const c = answers.find((a) => a.type === 'CNAME' && host(a.name) === current);
      if (!c) break;
      const target = host(c.data);
      if (cname === null) {
        cname = target;
        cnameTtl = c.ttl;
      }
      chain.push(target);
      current = target;
    }
  }
  const recs = answers.filter((a) => a.type === wt && host(a.name) === current);
  const values = [...new Set(recs.map((r) => formatRecord(t, r.data)))].sort();
  const valuesTtl = recs.length ? Math.min(...recs.map((r) => r.ttl)) : null;
  const soa = authorities.find((a) => a.type === 'SOA');
  const negativeTtl = soa
    ? Math.min(soa.ttl, Number((soa.data as { minimum?: number }).minimum ?? soa.ttl))
    : null;
  return { cname, chain, values, ttl: cname !== null ? cnameTtl : valuesTtl, valuesTtl, negativeTtl };
}
