// Network helpers: IP classification and SSRF-safe HTTP fetch.
import ipaddr from 'ipaddr.js';
import net from 'node:net';
import { Agent, fetch as ufetch, type Dispatcher } from 'undici';
import { ResolveSession } from '../dns/iterative.js';
import { t } from '../i18n.js';

export function isPublicIp(ip: string): boolean {
  if (!ipaddr.isValid(ip)) return false;
  let addr = ipaddr.parse(ip);
  if (addr.kind() === 'ipv6' && (addr as ipaddr.IPv6).isIPv4MappedAddress()) addr = (addr as ipaddr.IPv6).toIPv4Address();
  return addr.range() === 'unicast';
}

export function reverseName(ip: string): string {
  const addr = ipaddr.parse(ip);
  if (addr.kind() === 'ipv4') return addr.toByteArray().reverse().join('.') + '.in-addr.arpa';
  const hex = (addr as ipaddr.IPv6).toNormalizedString().split(':').map((p) => p.padStart(4, '0')).join('');
  return hex.split('').reverse().join('.') + '.ip6.arpa';
}

/** Name used to query an IP-based DNSBL: reversed octets / nibbles, without the arpa suffix. */
export function dnsblName(ip: string, zone: string): string {
  return reverseName(ip).replace(/\.(in-addr|ip6)\.arpa$/, '') + '.' + zone;
}

export class UnsafeTargetError extends Error {
  code = 'UNSAFE_TARGET';
}

/**
 * Agent whose DNS lookups go through the iterative resolver (no cache) and refuse non-public IPs.
 */
export function safeAgent(session = new ResolveSession()): Dispatcher {
  return new Agent({
    connect: {
      lookup(hostname, opts, callback) {
        // undici calls lookup with { all: true } and expects an array of addresses
        const cb = callback as (err: Error | null, address: string | { address: string; family: number }[], family?: number) => void;
        const reply = (ip: string, family: number) =>
          (opts as { all?: boolean })?.all ? cb(null, [{ address: ip, family }]) : cb(null, ip, family);
        const fail = (e: Error) => cb(e, '', 4);
        if (net.isIP(hostname)) {
          if (!isPublicIp(hostname)) return fail(new UnsafeTargetError(t('Adresse non publique refusée : {host}', { host: hostname })));
          return reply(hostname, net.isIPv6(hostname) ? 6 : 4);
        }
        (async () => {
          let r = await session.resolve(hostname, 'A');
          let ip = r.answers.find((a) => a.type === 'A')?.data as string | undefined;
          let family = 4;
          if (!ip) {
            r = await session.resolve(hostname, 'AAAA');
            ip = r.answers.find((a) => a.type === 'AAAA')?.data as string | undefined;
            family = 6;
          }
          if (!ip) return fail(Object.assign(new Error(`ENOTFOUND ${hostname}`), { code: 'ENOTFOUND' }));
          if (!isPublicIp(ip)) return fail(new UnsafeTargetError(t('Adresse non publique refusée : {host}', { host: ip })));
          reply(ip, family);
        })().catch(fail);
      },
      timeout: 8000,
    },
    headersTimeout: 10000,
    bodyTimeout: 10000,
  });
}

export interface SafeFetchResult {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  truncated: boolean;
  ms: number;
}

/** GET a URL with a size limit, no redirect following (callers follow redirects themselves). */
export async function safeGet(
  url: string,
  opts: { maxBytes?: number; session?: ResolveSession; method?: 'GET' | 'HEAD'; headers?: Record<string, string> } = {},
): Promise<SafeFetchResult> {
  const u = new URL(url);
  if (!['http:', 'https:'].includes(u.protocol)) throw new UnsafeTargetError(t('Protocole refusé : {protocol}', { protocol: u.protocol }));
  // Node skips lookup() when the host is an IP literal: check it here, brackets of IPv6 removed
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host) && !isPublicIp(host)) throw new UnsafeTargetError(t('Adresse non publique refusée : {host}', { host }));
  const started = performance.now();
  const res = await ufetch(u, {
    method: opts.method ?? 'GET',
    redirect: 'manual',
    dispatcher: safeAgent(opts.session),
    headers: {
      'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36',
      accept: '*/*',
      'cache-control': 'no-cache',
      pragma: 'no-cache',
      ...opts.headers,
    },
  });
  const max = opts.maxBytes ?? 2 * 1024 * 1024;
  const chunks: Buffer[] = [];
  let size = 0;
  let truncated = false;
  if (res.body && opts.method !== 'HEAD') {
    for await (const chunk of res.body as AsyncIterable<Uint8Array>) {
      size += chunk.length;
      if (size > max) {
        truncated = true;
        break;
      }
      chunks.push(Buffer.from(chunk));
    }
  }
  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => (headers[k] = v));
  return { url: u.toString(), status: res.status, headers, body: Buffer.concat(chunks), truncated, ms: Math.round(performance.now() - started) };
}
