// Presentation format of DNS records (RFC 1035 §5.1 and each type's RFC), and dig-like output.
import type { DnsAnswer } from '../../dns/client.js';
import { txtStrings } from '../../lib/email-auth/common.js';

export const QUERY_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'SRV', 'PTR', 'DS', 'DNSKEY', 'TLSA', 'HTTPS', 'SVCB', 'NAPTR'] as const;
export type QueryType = (typeof QUERY_TYPES)[number];

/** dns-packet has no codec for these: they travel as UNKNOWN_<n> with raw RDATA. */
export const WIRE_TYPE: Record<string, string> = { HTTPS: 'UNKNOWN_65', SVCB: 'UNKNOWN_64' };
export const DISPLAY_TYPE: Record<string, string> = { UNKNOWN_65: 'HTTPS', UNKNOWN_64: 'SVCB', UNKNOWN_51: 'NSEC3PARAM', UNKNOWN_99: 'SPF' };

const fqdn = (n: unknown) => {
  const s = String(n ?? '');
  return s === '' || s === '.' ? '.' : s.endsWith('.') ? s : s + '.';
};
const quote = (s: string) => `"${s.replace(/(["\\])/g, '\\$1')}"`;
const hex = (b: unknown) => (Buffer.isBuffer(b) ? b.toString('hex').toUpperCase() : String(b));
const b64 = (b: unknown) => (Buffer.isBuffer(b) ? b.toString('base64') : String(b));

function readName(buf: Buffer, off: number): { name: string; next: number } {
  const labels: string[] = [];
  let i = off;
  while (i < buf.length) {
    const len = buf[i];
    if (len === 0) {
      i++;
      break;
    }
    labels.push(buf.subarray(i + 1, i + 1 + len).toString('ascii'));
    i += len + 1;
  }
  return { name: labels.length ? labels.join('.') + '.' : '.', next: i };
}

const SVC_KEYS: Record<number, string> = { 0: 'mandatory', 1: 'alpn', 2: 'no-default-alpn', 3: 'port', 4: 'ipv4hint', 5: 'ech', 6: 'ipv6hint' };

/** RFC 9460 SVCB/HTTPS RDATA. */
export function formatSvcb(buf: Buffer): string {
  if (buf.length < 3) return hex(buf);
  const prio = buf.readUInt16BE(0);
  const { name, next } = readName(buf, 2);
  const params: string[] = [];
  let i = next;
  while (i + 4 <= buf.length) {
    const key = buf.readUInt16BE(i);
    const len = buf.readUInt16BE(i + 2);
    const v = buf.subarray(i + 4, i + 4 + len);
    i += 4 + len;
    const k = SVC_KEYS[key] ?? `key${key}`;
    switch (key) {
      case 1: {
        const ids: string[] = [];
        for (let j = 0; j < v.length; ) {
          ids.push(v.subarray(j + 1, j + 1 + v[j]).toString('ascii'));
          j += v[j] + 1;
        }
        params.push(`alpn="${ids.join(',')}"`);
        break;
      }
      case 2:
        params.push(k);
        break;
      case 3:
        params.push(`port=${v.readUInt16BE(0)}`);
        break;
      case 4: {
        const ips: string[] = [];
        for (let j = 0; j + 4 <= v.length; j += 4) ips.push([...v.subarray(j, j + 4)].join('.'));
        params.push(`ipv4hint=${ips.join(',')}`);
        break;
      }
      case 6: {
        const ips: string[] = [];
        for (let j = 0; j + 16 <= v.length; j += 16) {
          const parts: string[] = [];
          for (let p = 0; p < 16; p += 2) parts.push(v.readUInt16BE(j + p).toString(16));
          ips.push(parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::'));
        }
        params.push(`ipv6hint=${ips.join(',')}`);
        break;
      }
      case 5:
        params.push(`ech=${v.toString('base64')}`);
        break;
      default:
        params.push(`${k}=${v.toString('hex')}`);
    }
  }
  return [prio, name, ...params].join(' ');
}

export function formatRdata(type: string, data: unknown): string {
  const d = data as Record<string, unknown>;
  switch (type) {
    case 'A':
    case 'AAAA':
      return String(data);
    case 'CNAME':
    case 'NS':
    case 'PTR':
    case 'DNAME':
      return fqdn(data);
    case 'MX':
      return `${d.preference} ${fqdn(d.exchange)}`;
    case 'TXT':
    case 'SPF':
      return txtStrings(data).map(quote).join(' ');
    case 'SOA':
      return `${fqdn(d.mname)} ${fqdn(d.rname)} ${d.serial} ${d.refresh} ${d.retry} ${d.expire} ${d.minimum}`;
    case 'CAA':
      return `${d.flags ?? (d.issuerCritical ? 128 : 0)} ${d.tag} ${quote(String(d.value ?? ''))}`;
    case 'SRV':
      return `${d.priority} ${d.weight} ${d.port} ${fqdn(d.target)}`;
    case 'DS':
      return `${d.keyTag} ${d.algorithm} ${d.digestType} ${hex(d.digest)}`;
    case 'DNSKEY':
      return `${d.flags} 3 ${d.algorithm} ${b64(d.key)}`;
    case 'RRSIG': {
      const t = (n: unknown) => new Date(Number(n) * 1000).toISOString().replace(/[-:T]/g, '').slice(0, 14);
      return `${d.typeCovered} ${d.algorithm} ${d.labels} ${d.originalTTL} ${t(d.expiration)} ${t(d.inception)} ${d.keyTag} ${fqdn(d.signersName)} ${b64(d.signature)}`;
    }
    case 'TLSA':
      return `${d.usage} ${d.selector} ${d.matchingType} ${hex(d.certificate)}`;
    case 'NAPTR':
      return `${d.order} ${d.preference} ${quote(String(d.flags ?? ''))} ${quote(String(d.services ?? ''))} ${quote(String(d.regexp ?? ''))} ${fqdn(d.replacement)}`;
    case 'UNKNOWN_65':
    case 'UNKNOWN_64':
      return Buffer.isBuffer(data) ? formatSvcb(data) : String(data);
    default:
      return Buffer.isBuffer(data) ? `\\# ${data.length} ${data.toString('hex')}` : JSON.stringify(data);
  }
}

export interface RecordOut {
  name: string;
  ttl: number;
  type: string;
  value: string;
}

export function toRecord(a: DnsAnswer): RecordOut {
  return { name: fqdn(a.name), ttl: a.ttl, type: DISPLAY_TYPE[a.type] ?? a.type, value: formatRdata(a.type, a.data) };
}

export function digText(opts: {
  name: string;
  type: string;
  rcode: string;
  flags?: string[];
  answers: RecordOut[];
  authority?: RecordOut[];
  server?: string;
  ms?: number;
  when: string;
  comment?: string;
}): string {
  const line = (r: RecordOut) => `${r.name}\t${r.ttl}\tIN\t${r.type}\t${r.value}`;
  const out = [
    `; <<>> check <<>> ${opts.name} ${opts.type}${opts.comment ? `  (${opts.comment})` : ''}`,
    `;; ->>HEADER<<- status: ${opts.rcode}${opts.flags?.length ? `, flags: ${opts.flags.join(' ')}` : ''}; ANSWER: ${opts.answers.length}`,
    '',
    ';; QUESTION SECTION:',
    `;${fqdn(opts.name)}\t\tIN\t${opts.type}`,
  ];
  if (opts.answers.length) out.push('', ';; ANSWER SECTION:', ...opts.answers.map(line));
  if (opts.authority?.length) out.push('', ';; AUTHORITY SECTION:', ...opts.authority.map(line));
  out.push('');
  if (opts.ms !== undefined) out.push(`;; Query time: ${opts.ms} msec`);
  if (opts.server) out.push(`;; SERVER: ${opts.server}`);
  out.push(`;; WHEN: ${opts.when}`);
  return out.join('\n');
}
