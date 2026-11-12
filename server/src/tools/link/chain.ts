// Live redirect chain: each hop is fetched for real (HTTP 3xx, meta refresh, plain JavaScript
// redirects read in the HTML without running it), up to 15 hops, 2 MB per response at most.
// In production the fetch is safeGet (private addresses refused, iterative DNS, no cache);
// tests inject their own fetch and resolver to reach a local server.
import { t } from '../../i18n.js';
import net from 'node:net';
import { orgDomain } from '../../lib/email-auth/common.js';
import type { SafeFetchResult } from '../../lib/net.js';
import { readPage, type PageFacts } from './page.js';

export const MAX_HOPS = 15;
export const MAX_BYTES = 2 * 1024 * 1024;

export type HopFetch = (url: string, opts: { maxBytes: number }) => Promise<SafeFetchResult>;
/** IP the host name points to, or why it cannot be visited. */
export type HostResolver = (host: string) => Promise<{ ip?: string; error?: string; unsafe?: boolean }>;

export interface Hop {
  index: number;
  url: string;
  host: string;
  /** Registrable domain (public suffix list), or the IP for an IP host. */
  domain: string;
  ip?: string;
  port?: number;
  status?: number;
  ms: number;
  /** How the chain reached this hop. */
  via: 'start' | 'http' | 'meta' | 'js';
  /** How this hop sends to the next one. */
  next?: 'http' | 'meta' | 'js';
  location?: string;
  contentType?: string;
  bytes?: number;
  truncated?: boolean;
  server?: string;
  error?: string;
}

export interface ChainResult {
  start: string;
  final: string;
  hops: Hop[];
  stoppedBy?: 'max_hops' | 'loop' | 'error' | 'unsafe' | 'budget';
  /** Body, headers and facts of the last page fetched. */
  finalBody?: Buffer;
  finalHeaders?: Record<string, string>;
  finalPage?: PageFacts;
}

export function hostOf(url: URL): string {
  return url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

export function domainOf(host: string): string {
  return net.isIP(host) ? host : orgDomain(host);
}

const isHtml = (ct: string | undefined, body: Buffer) => /html|xml/i.test(ct ?? '') || (!ct && /<html|<head|<meta|<script/i.test(body.subarray(0, 2048).toString('latin1')));

export async function followChain(
  start: string,
  deps: { fetch: HopFetch; resolveHost: HostResolver; maxHops?: number; budgetMs?: number; onHop?: (h: Hop) => void },
): Promise<ChainResult> {
  const maxHops = deps.maxHops ?? MAX_HOPS;
  const startedAt = performance.now();
  const budget = deps.budgetMs ?? 45000;
  const hops: Hop[] = [];
  const seen = new Set<string>();
  const out: ChainResult = { start, final: start, hops };
  let current = start;
  let via: Hop['via'] = 'start';
  for (let i = 0; i < maxHops; i++) {
    const u = new URL(current);
    const host = hostOf(u);
    const hop: Hop = { index: i + 1, url: current, host, domain: domainOf(host), via, ms: 0, port: u.port ? Number(u.port) : undefined };
    hops.push(hop);
    out.final = current;
    seen.add(current);
    const t0 = performance.now();
    const target = await deps.resolveHost(host);
    hop.ip = target.ip;
    if (target.error) {
      hop.error = target.error;
      hop.ms = Math.round(performance.now() - t0);
      out.stoppedBy = target.unsafe ? 'unsafe' : 'error';
      deps.onHop?.(hop);
      return out;
    }
    const left = budget - (performance.now() - startedAt);
    if (left <= 0) {
      hop.error = t('temps total alloué à la chaîne épuisé');
      out.stoppedBy = 'budget';
      deps.onHop?.(hop);
      return out;
    }
    let res: SafeFetchResult;
    try {
      res = await Promise.race([
        deps.fetch(current, { maxBytes: MAX_BYTES }),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error(t('pas de réponse en {s} s', { s: Math.round(left / 1000) }))), left).unref()),
      ]);
    } catch (e) {
      const err = e as Error & { cause?: { code?: string; message?: string }; code?: string };
      hop.error = err.cause?.message ?? err.message;
      hop.ms = Math.round(performance.now() - t0);
      out.stoppedBy = err.code === 'UNSAFE_TARGET' || (err.cause as { code?: string } | undefined)?.code === 'UNSAFE_TARGET' ? 'unsafe' : 'error';
      deps.onHop?.(hop);
      return out;
    }
    hop.ms = Math.round(performance.now() - t0);
    hop.status = res.status;
    hop.contentType = res.headers['content-type'];
    hop.bytes = res.body.length;
    hop.truncated = res.truncated || undefined;
    hop.server = res.headers.server;
    out.finalBody = res.body;
    out.finalHeaders = res.headers;
    out.finalPage = undefined;

    let next: string | undefined;
    if (res.status >= 300 && res.status < 400 && res.headers.location) {
      try {
        next = new URL(res.headers.location, current).toString();
        hop.next = 'http';
      } catch {
        hop.error = t('en-tête Location invalide : {value}', { value: res.headers.location.slice(0, 200) });
      }
    } else if (res.status >= 200 && isHtml(hop.contentType, res.body)) {
      // an error page is read too (title, forms): a phishing kit often answers 404 to robots
      const page = readPage(res.body.toString('utf8'), current);
      out.finalPage = page;
      if (res.status >= 300) {
        // redirects of an error page are not followed
      } else if (page.metaRefresh && page.metaRefresh.delay <= 30) {
        next = page.metaRefresh.url;
        hop.next = 'meta';
      } else if (page.jsRedirect) {
        next = page.jsRedirect.url;
        hop.next = 'js';
      }
    }
    if (next && !/^https?:/i.test(next)) {
      hop.error = t('redirection vers un protocole non suivi : {value}', { value: next.slice(0, 100) });
      next = undefined;
    }
    hop.location = next;
    deps.onHop?.(hop);
    if (!next) return out;
    if (seen.has(next)) {
      out.stoppedBy = 'loop';
      return out;
    }
    via = hop.next!;
    current = next;
  }
  out.stoppedBy = 'max_hops';
  return out;
}
