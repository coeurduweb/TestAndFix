// WHOIS client (RFC 3912): TCP port 43, the query followed by CRLF, the answer until the server
// closes the connection. The server name is resolved from the root like every name in check (no
// system resolver) and only public addresses are contacted. A name with several addresses is
// several servers: when one does not answer, the next address is tried before giving up.
import net from 'node:net';
import type { Resolver } from '../email-auth/common.js';
import { isPublicIp } from '../net.js';
import { t } from '../../i18n.js';

export interface WhoisAnswer {
  text: string;
  address: string;
  ms: number;
  truncated: boolean;
}

export class WhoisError extends Error {
  constructor(
    message: string,
    public readonly code: 'timeout' | 'refused' | 'unreachable' | 'no_address' | 'empty',
  ) {
    super(message);
  }
}

const MAX_BYTES = 256 * 1024;
export const WHOIS_TIMEOUT_MS = 10_000;

/** Text of an answer: UTF-8 when valid, Latin-1 otherwise (older servers). */
export function decodeWhois(buf: Buffer): string {
  const utf8 = buf.toString('utf8');
  return utf8.includes('�') ? buf.toString('latin1') : utf8;
}

function ask(address: string, query: string, timeoutMs: number): Promise<WhoisAnswer> {
  const started = performance.now();
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let truncated = false;
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      fn();
    };
    const sock = net.connect({ host: address, port: 43 }, () => sock.write(`${query}\r\n`));
    const timer = setTimeout(() => done(() => reject(new WhoisError(t('délai dépassé'), 'timeout'))), timeoutMs);
    sock.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BYTES) {
        truncated = true;
        done(() => resolve({ text: decodeWhois(Buffer.concat(chunks)), address, ms: Math.round(performance.now() - started), truncated }));
        return;
      }
      chunks.push(c);
    });
    sock.on('end', () => {
      const buf = Buffer.concat(chunks);
      done(() =>
        buf.length
          ? resolve({ text: decodeWhois(buf), address, ms: Math.round(performance.now() - started), truncated })
          : reject(new WhoisError(t('réponse vide'), 'empty')),
      );
    });
    sock.on('error', (e: NodeJS.ErrnoException) =>
      done(() => reject(new WhoisError(e.code === 'ECONNREFUSED' ? t('connexion refusée') : e.code === 'ECONNRESET' ? t('connexion coupée par le serveur') : t('injoignable ({error})', { error: e.code ?? t('erreur réseau') }), e.code === 'ECONNREFUSED' ? 'refused' : 'unreachable'))),
    );
  });
}

async function addresses(session: Resolver, host: string): Promise<string[]> {
  if (net.isIP(host)) return isPublicIp(host) ? [host] : [];
  const out: string[] = [];
  for (const type of ['A', 'AAAA'] as const) {
    const r = await session.resolve(host, type).catch(() => undefined);
    for (const a of r?.answers ?? []) if (a.type === type && typeof a.data === 'string' && isPublicIp(a.data)) out.push(a.data);
  }
  return out;
}

/** Query a WHOIS server; each public address of its name is tried in turn. */
export async function whoisQuery(host: string, query: string, opts: { session: Resolver; timeoutMs?: number }): Promise<WhoisAnswer> {
  const list = await addresses(opts.session, host);
  if (!list.length) throw new WhoisError(t('aucune adresse publique pour ce serveur'), 'no_address');
  let last: unknown;
  // at most two addresses: a third attempt would only add load on a server already in trouble
  for (const address of list.slice(0, 2)) {
    try {
      return await ask(address, query, opts.timeoutMs ?? WHOIS_TIMEOUT_MS);
    } catch (e) {
      last = e;
      if (e instanceof WhoisError && e.code === 'empty') break;
    }
  }
  throw last instanceof Error ? last : new WhoisError('injoignable', 'unreachable');
}
