// HTTP GET of the CT clients. Same guarantees as safeGet (lib/net.ts): host names resolved from the
// root by our own resolver, non-public addresses refused, no redirect followed, size limit, no
// cache (no-cache headers, a new agent per call). One difference: the delay is set per call.
//
// Why not safeGet itself (2026-11-11): safeGet's agent stops at 10 s without response headers, and
// crt.sh often takes longer (14 s measured on a small domain with deduplicate=Y). The tool needs
// 25 s for crt.sh. A `timeoutMs` option on safeGet has been requested; once it exists, this file
// becomes a call to safeGet. The SSRF guard is safeAgent from net.ts, not a copy.
import type { Dispatcher } from 'undici';
import { fetch as ufetch } from 'undici';
import type { ResolveSession } from '../../dns/iterative.js';
import { safeAgent } from '../net.js';
import type { CtFetch, CtResponse } from './types.js';
import { t } from '../../i18n.js';

const UA = 'check (diagnostic DNS personnel; recherche Certificate Transparency)';

/** Raise undici's headers/body timeouts of this one request to `ms` (the agent's default is 10 s). */
function withTimeouts(agent: Dispatcher, ms: number): Dispatcher {
  return agent.compose((dispatch) => (opts, handler) => dispatch({ ...opts, headersTimeout: ms, bodyTimeout: ms }, handler));
}

export function ctFetcher(session?: () => ResolveSession): CtFetch {
  return async (url, { timeoutMs, maxBytes, signal }): Promise<CtResponse> => {
    const u = new URL(url);
    if (u.protocol !== 'https:') throw new Error(t('Protocole refusé : {protocol}', { protocol: u.protocol }));
    const deadline = AbortSignal.timeout(timeoutMs);
    const sig = signal ? AbortSignal.any([signal, deadline]) : deadline;
    const agent = safeAgent(session?.());
    try {
      const res = await ufetch(u, {
        method: 'GET',
        redirect: 'manual',
        dispatcher: withTimeouts(agent, timeoutMs),
        signal: sig,
        headers: { 'user-agent': UA, accept: 'application/json, text/plain;q=0.8, */*;q=0.5', 'cache-control': 'no-cache', pragma: 'no-cache' },
      });
      const chunks: Buffer[] = [];
      let size = 0;
      let truncated = false;
      if (res.body) {
        for await (const chunk of res.body as AsyncIterable<Uint8Array>) {
          size += chunk.length;
          if (size > maxBytes) {
            truncated = true;
            break;
          }
          chunks.push(Buffer.from(chunk));
        }
      }
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => (headers[k] = v));
      return { status: res.status, headers, body: Buffer.concat(chunks), truncated };
    } catch (e) {
      if (deadline.aborted) throw Object.assign(new Error(t('pas de réponse en {s} s', { s: Math.round(timeoutMs / 1000) })), { code: 'TIMEOUT' });
      throw e;
    } finally {
      void agent.close().catch(() => {});
    }
  };
}

/** French reason for a failed request (network error, timeout, aborted). */
export function fetchErrorReason(e: unknown): string {
  const err = e as { code?: string; cause?: { code?: string; message?: string }; message?: string };
  if (err?.code === 'TIMEOUT') return err.message ?? t('délai dépassé');
  const code = err?.cause?.code ?? err?.code;
  if (code === 'ENOTFOUND') return t('nom du service introuvable dans le DNS');
  if (code === 'ECONNREFUSED') return t('connexion refusée');
  if (code === 'ECONNRESET') return t('connexion coupée par le service');
  if (code === 'UND_ERR_HEADERS_TIMEOUT' || code === 'UND_ERR_BODY_TIMEOUT' || code === 'UND_ERR_CONNECT_TIMEOUT') return t('délai dépassé');
  if (code === 'UNSAFE_TARGET') return t('adresse non publique refusée');
  return err?.cause?.message ?? err?.message ?? t('erreur réseau');
}

/** Value of Retry-After in seconds, when the header holds a number of seconds or a date. */
export function retryAfterSeconds(headers: Record<string, string>): number | undefined {
  const v = headers['retry-after'];
  if (!v) return undefined;
  if (/^\d+$/.test(v.trim())) return Number(v.trim());
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : Math.max(0, Math.round((t - Date.now()) / 1000));
}
