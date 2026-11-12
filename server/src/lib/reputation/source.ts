// Shared plumbing for the external reputation sources (AbuseIPDB, VirusTotal, Safe Browsing,
// URLhaus, OpenPhish, urlscan.io, OTX, RIPEstat): an HTTP helper, a typed "unavailable" error
// and a runner that turns any failure into a reason shown to the user, never an exception.
//
// The sources are fixed public APIs, not URLs typed by the user. They still go through
// safeAgent: host names are resolved by our iterative resolver (no node:dns, no cache) and a
// private address is refused. Tests inject their own ApiFetch to reach a local fake server.
import { fetch as ufetch } from 'undici';
import { ResolveSession } from '../../dns/iterative.js';
import net from 'node:net';
import { isPublicIp, safeAgent, UnsafeTargetError } from '../net.js';
import { t } from '../../i18n.js';

/**
 * safeAgent's lookup is not called for a host written as an IP (Node connects directly), so a
 * private IP literal would get through it (verified 2026-11-10 on safeGet with 127.0.0.1 and
 * ::ffff:127.0.0.1). Checked here before any connection.
 */
export function assertPublicUrl(url: string): void {
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host) && !isPublicIp(host)) throw new UnsafeTargetError(t('Adresse non publique refusée : {host}', { host }));
}

export interface ApiRequest {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxBytes?: number;
}

export interface ApiResponse {
  status: number;
  headers: Record<string, string>;
  text: string;
  truncated: boolean;
  ms: number;
}

export type ApiFetch = (url: string, req?: ApiRequest) => Promise<ApiResponse>;

/** Generic client name: no personal detail is ever sent to the sources. */
export const USER_AGENT = 'check-reputation/1.0';

export const apiFetch: ApiFetch = async (url, req = {}) => {
  assertPublicUrl(url);
  const started = performance.now();
  const dispatcher = safeAgent(new ResolveSession({ timeoutMs: 3000 }));
  try {
    const res = await ufetch(url, {
      method: req.method ?? 'GET',
      redirect: 'manual',
      dispatcher,
      body: req.body,
      signal: AbortSignal.timeout(req.timeoutMs ?? 12000),
      headers: { 'user-agent': USER_AGENT, accept: 'application/json', 'cache-control': 'no-cache', pragma: 'no-cache', ...req.headers },
    });
    const max = req.maxBytes ?? 5 * 1024 * 1024;
    const chunks: Buffer[] = [];
    let size = 0;
    let truncated = false;
    if (res.body) {
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
    return { status: res.status, headers, text: Buffer.concat(chunks).toString('utf8'), truncated, ms: Math.round(performance.now() - started) };
  } finally {
    void (dispatcher as { close?: () => Promise<void> }).close?.().catch(() => {});
  }
};

export type UnavailableKind = 'no_key' | 'quota' | 'refused' | 'error' | 'timeout' | 'not_applicable';

/** A source that could not answer. The message is shown as is (French, vouvoiement). */
export class SourceUnavailable extends Error {
  constructor(
    public kind: UnavailableKind,
    message: string,
  ) {
    super(message);
  }
}

export interface SourceResult<T> {
  source: string;
  label: string;
  ok: boolean;
  data?: T;
  reason?: string;
  kind?: UnavailableKind;
  ms: number;
}

export function noKey(envVar: string, label: string): SourceUnavailable {
  return new SourceUnavailable('no_key', t('clé {envVar} absente : ajoutez-la au fichier .env pour interroger {label}', { envVar, label }));
}

/** Map an HTTP status of a keyed API to the reason shown. Returns undefined for 2xx. */
export function httpProblem(status: number, label: string, text = ''): SourceUnavailable | undefined {
  if (status >= 200 && status < 300) return undefined;
  if (status === 401 || status === 403) return new SourceUnavailable('refused', t('{label} a refusé la clé (HTTP {status})', { label, status }));
  if (status === 429) return new SourceUnavailable('quota', t('quota de {label} épuisé pour le moment (HTTP 429)', { label }));
  const detail = text.replace(/\s+/g, ' ').trim().slice(0, 120);
  return new SourceUnavailable('error', detail ? t('{label} a répondu HTTP {status} ({detail})', { label, status, detail }) : t('{label} a répondu HTTP {status}', { label, status }));
}

export function parseJson<T>(text: string, label: string): T {
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new SourceUnavailable('error', t('réponse illisible de {label}', { label }));
  }
}

/** Run a source with a time limit; any failure becomes { ok: false, reason }. */
export async function runSource<T>(source: string, label: string, fn: () => Promise<T>, timeoutMs = 20000): Promise<SourceResult<T>> {
  const started = performance.now();
  let timer: NodeJS.Timeout | undefined;
  try {
    const data = await Promise.race([
      fn(),
      new Promise<never>((_, rej) => {
        timer = setTimeout(() => rej(new SourceUnavailable('timeout', t('{label} : pas de réponse en {s} s', { label, s: Math.round(timeoutMs / 1000) }))), timeoutMs);
      }),
    ]);
    return { source, label, ok: true, data, ms: Math.round(performance.now() - started) };
  } catch (e) {
    const ms = Math.round(performance.now() - started);
    if (e instanceof SourceUnavailable) return { source, label, ok: false, reason: e.message, kind: e.kind, ms };
    const err = e as Error & { code?: string; cause?: { code?: string; message?: string } };
    const name = err.name === 'TimeoutError' || err.name === 'AbortError' ? 'timeout' : 'error';
    const detail = err.cause?.code ?? err.cause?.message ?? err.code ?? err.message;
    return { source, label, ok: false, kind: name, reason: name === 'timeout' ? t('{label} : délai dépassé', { label }) : t('{label} injoignable ({detail})', { label, detail }), ms };
  }
}
