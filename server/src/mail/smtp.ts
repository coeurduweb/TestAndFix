// SMTP reception of test messages: accepts only RCPT TO of an active test address on our
// domain, never relays, STARTTLS with the configured certificate (or a self-signed one generated
// at start), records what the client showed (IP, HELO, MAIL FROM, TLS) and hands the message on.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import type { TLSSocket } from 'node:tls';
import { SMTPServer, type SMTPServerOptions, type SMTPServerSession } from 'smtp-server';
import { nodeStyleResolver } from '../dns/iterative.js';
import { isPublicIp, reverseName } from '../lib/net.js';
import type { ToolContext } from '../tools/types.js';
import type { MailService } from './service.js';
import { activeAddress, normaliseAddressId } from './store.js';
import { headerValues, parseRaw } from './mime.js';
import ipaddr from 'ipaddr.js';

export interface SmtpHandle {
  server: SMTPServer;
  port: number;
  host: string;
  tls: 'configured' | 'self-signed' | 'builtin';
  close(): Promise<void>;
}

/** PEM given inline (literal \n accepted for new lines) or as a file path. */
export function readPem(v: string): string | undefined {
  if (!v) return undefined;
  if (v.includes('-----BEGIN')) return v.replace(/\\n/g, '\n');
  return fs.readFileSync(v, 'utf8');
}

/** Self-signed certificate for the mail domain, made with openssl at start. */
export function selfSigned(domain: string): { key: string; cert: string } | undefined {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'check-smtp-'));
  try {
    const key = path.join(dir, 'key.pem');
    const cert = path.join(dir, 'cert.pem');
    execFileSync(
      'openssl',
      ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '825', '-subj', `/CN=${domain}`, '-addext', `subjectAltName=DNS:${domain}`],
      { stdio: 'ignore', timeout: 20000 },
    );
    return { key: fs.readFileSync(key, 'utf8'), cert: fs.readFileSync(cert, 'utf8') };
  } catch {
    return undefined;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function cleanIp(ip: string): string {
  const v = ip.replace(/^ipv6:/i, '');
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(v);
  return m ? m[1] : v;
}

/** "172.16.0.0/12", "127.0.0.1" (a bare address is a /32 or /128). */
export function inCidrs(ip: string, cidrs: string[]): boolean {
  const addr = cleanIp(ip);
  if (!ipaddr.isValid(addr)) return false;
  const a = ipaddr.process(addr);
  return cidrs.some((c) => {
    try {
      const [range, bits] = c.includes('/') ? ipaddr.parseCIDR(c) : [ipaddr.process(c), ipaddr.process(c).kind() === 'ipv4' ? 32 : 128];
      const r = range.kind() === 'ipv6' && (range as ipaddr.IPv6).isIPv4MappedAddress() ? (range as ipaddr.IPv6).toIPv4Address() : range;
      return r.kind() === a.kind() && a.match(r as never, bits as number);
    } catch {
      return false;
    }
  });
}

/**
 * TLS of the original connection, read in the Received field the relay (Postfix) added on top:
 * "(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))". used is null when the
 * relay wrote no Received.
 */
export function relayTls(body: Buffer): { used: boolean | null; protocol?: string; cipher?: string } {
  const received = headerValues(parseRaw(body).headers, 'received');
  if (!received.length) return { used: null };
  const top = received[0];
  const m = /\busing\s+(TLSv?[\d.]+|SSLv3)\s+with\s+cipher\s+([A-Za-z0-9_-]+)/i.exec(top);
  if (m) return { used: true, protocol: m[1].replace(/^TLS(?=\d)/i, 'TLSv'), cipher: m[2] };
  if (/\bwith\s+(e?smtps|esmtpsa|utf8smtps)\b/i.test(top)) return { used: true };
  return { used: false };
}

function rfc2822(d: Date): string {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const p = (n: number) => String(n).padStart(2, '0');
  return `${days[d.getUTCDay()]}, ${d.getUTCDate()} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
}

/** PTR of the client, forward-confirmed, as Postfix writes it in Received ("unknown" otherwise). */
async function verifiedPtr(ctx: ToolContext, ip: string): Promise<string | undefined> {
  if (!isPublicIp(ip)) return undefined;
  const resolve = nodeStyleResolver(ctx.dns({ timeoutMs: 1500 }));
  try {
    const names = ((await resolve(reverseName(ip), 'PTR')) as string[]).slice(0, 3);
    for (const n of names) {
      const fwd = (await resolve(n, net.isIPv6(ip) ? 'AAAA' : 'A').catch(() => [])) as string[];
      if (fwd.map((x) => x.toLowerCase()).includes(ip.toLowerCase())) return n;
    }
  } catch {
    /* no PTR */
  }
  return undefined;
}

export interface SmtpOptions {
  host?: string;
  port?: number;
}

export async function startSmtp(ctx: ToolContext, service: MailService, opts: SmtpOptions = {}): Promise<SmtpHandle> {
  const cfg = ctx.config.mail;
  const domain = cfg.domain;
  let tlsMode: SmtpHandle['tls'] = 'builtin';
  let key: string | undefined;
  let cert: string | undefined;
  try {
    key = readPem(cfg.tlsKey);
    cert = readPem(cfg.tlsCert);
    if (key && cert) tlsMode = 'configured';
  } catch {
    key = cert = undefined;
  }
  if (tlsMode !== 'configured') {
    const ss = selfSigned(domain);
    if (ss) {
      ({ key, cert } = ss);
      tlsMode = 'self-signed';
    }
  }
  const tlsInfo = new Map<string, { protocol?: string; cipher?: string }>();
  const ptrs = new Map<string, Promise<string | undefined>>();
  /** address of the peer that opened the connection (XFORWARD ADDR replaces remoteAddress) */
  const peers = new Map<string, string>();
  const trusted = cfg.trustedRelays ?? [];

  const options: SMTPServerOptions = {
    name: domain,
    banner: cfg.smtpBanner || 'check mail test',
    size: cfg.maxSize,
    authOptional: true,
    disabledCommands: ['AUTH'],
    disableReverseLookup: true,
    logger: false,
    secure: false,
    ...(key && cert ? { key, cert } : {}),
    socketTimeout: 120_000,
    // XFORWARD is offered to every peer here, then restricted per connection to the trusted
    // relays (smtp-server only matches exact addresses, CHECK_SMTP_TRUSTED_RELAYS holds CIDR)
    useXForward: trusted.length > 0,
    onConnect(session, cb) {
      // called again after XFORWARD ADDR, with the original client's address
      const ip = cleanIp(session.remoteAddress);
      if (!peers.has(session.id)) peers.set(session.id, ip);
      ptrs.set(session.id, verifiedPtr(ctx, ip));
      cb();
    },
    onSecure(socket, session, cb) {
      const s = socket as TLSSocket;
      tlsInfo.set(session.id, { protocol: s.getProtocol?.() ?? undefined, cipher: s.getCipher?.()?.name });
      cb();
    },
    onMailFrom(_address, _session, cb) {
      cb();
    },
    onRcptTo(address, _session, cb) {
      const addr = address.address.toLowerCase();
      const at = addr.lastIndexOf('@');
      const local = addr.slice(0, at);
      const dom = addr.slice(at + 1);
      if (at < 1 || dom !== domain) {
        const err = new Error('5.7.1 Relay access denied') as Error & { responseCode: number };
        err.responseCode = 550;
        return cb(err);
      }
      const id = normaliseAddressId(local);
      if (!id || !activeAddress(ctx.db, id)) {
        const err = new Error('5.1.1 Unknown or expired test address') as Error & { responseCode: number };
        err.responseCode = 550;
        return cb(err);
      }
      cb();
    },
    onData(stream, session, cb) {
      const chunks: Buffer[] = [];
      stream.on('data', (d: Buffer) => chunks.push(d));
      stream.on('error', (e) => cb(e));
      stream.on('end', () => {
        if ((stream as unknown as { sizeExceeded?: boolean }).sizeExceeded) {
          const err = new Error('5.3.4 Message too big') as Error & { responseCode: number };
          err.responseCode = 552;
          return cb(err);
        }
        const body = Buffer.concat(chunks);
        handle(session, body)
          .then(() => cb())
          .catch((e) => {
            const err = new Error(`4.3.0 ${(e as Error).message}`) as Error & { responseCode: number };
            err.responseCode = 451;
            cb(err);
          });
      });
    },
    onClose(session) {
      tlsInfo.delete(session.id);
      ptrs.delete(session.id);
      peers.delete(session.id);
    },
  };

  async function handle(session: SMTPServerSession, body: Buffer) {
    const xf = (session as unknown as { xForward?: Map<string, string> }).xForward;
    const peer = peers.get(session.id) ?? cleanIp(session.remoteAddress);
    // the client is the one XFORWARD names only when a trusted relay said so
    const relayed = !!xf?.get('ADDR') && inCidrs(peer, trusted);
    const ip = relayed ? cleanIp(xf!.get('ADDR')!) : peer;
    const helo = (relayed ? xf!.get('HELO') : undefined) || session.hostNameAppearsAs || undefined;
    const mailFrom = session.envelope.mailFrom ? session.envelope.mailFrom.address : '';
    const rcpts = session.envelope.rcptTo.map((r) => r.address.toLowerCase());
    const own = session.secure ? (tlsInfo.get(session.id) ?? { cipher: (session.tlsOptions as { name?: string } | undefined)?.name }) : null;
    // behind the relay, our session is Postfix to us: the sender's TLS is in Postfix's Received
    const rt = relayed ? relayTls(body) : undefined;
    const tls = relayed
      ? { ...(rt!.used === true ? { protocol: rt!.protocol, cipher: rt!.cipher } : {}), used: rt!.used ?? undefined, source: 'relay' as const, ipSource: 'xforward' as const }
      : own;
    const announced = relayed ? xf!.get('NAME') : undefined;
    const ptr = (announced && !/unavailable|unknown/i.test(announced) ? announced.toLowerCase() : undefined) ?? (await (ptrs.get(session.id) ?? Promise.resolve(undefined)));
    const when = new Date();
    for (const rcpt of rcpts) {
      const id = normaliseAddressId(rcpt.slice(0, rcpt.lastIndexOf('@')));
      if (!id) continue;
      // trace fields of the final delivery (RFC 5321 §4.4): Return-Path and our Received
      const received =
        `Received: from ${helo ?? 'unknown'} (${ptr ?? 'unknown'} [${ip}])\r\n` +
        `\tby ${domain} (check) with ${(relayed && xf!.get('PROTO')) || session.transmissionType || 'ESMTP'} id ${session.id}\r\n` +
        (tls && (tls as { used?: boolean }).used !== false && (tls.protocol || tls.cipher || !relayed) ? `\t(using ${tls.protocol ?? 'TLS'}${tls.cipher ? ` with cipher ${tls.cipher}` : ''})\r\n` : '') +
        `\tfor <${rcpt}>; ${rfc2822(when)}\r\n`;
      const raw = Buffer.concat([Buffer.from(`Return-Path: <${mailFrom}>\r\n${received}`, 'latin1'), body]);
      service.ingest({ via: 'smtp', addressId: id, raw, clientIp: ip, clientPtr: ptr, helo, mailFrom, rcptTo: [rcpt], tls });
    }
  }

  const server = new SMTPServer(options);
  // per connection: XFORWARD (advertised in EHLO and accepted) only for a trusted relay
  const connect = server.connect.bind(server);
  server.connect = ((socket: unknown, opts: unknown) => {
    connect(socket as never, opts as never);
    const conns = (server as unknown as { connections: Set<Record<string, unknown>> }).connections;
    const conn = [...conns].pop();
    if (!conn || typeof conn._proxyCommandAllowed !== 'function') return;
    const orig = (conn._proxyCommandAllowed as (c: string, o: string) => boolean).bind(conn);
    conn._proxyCommandAllowed = (command: string, option: string) =>
      orig(command, option) && (command !== 'XFORWARD' || inCidrs(String(conn._originalRemoteAddress ?? ''), trusted));
  }) as typeof server.connect;
  server.on('error', () => {
    /* client errors are per connection */
  });
  const host = opts.host ?? cfg.smtpHost;
  const port = opts.port ?? cfg.smtpPort;
  await new Promise<void>((resolve, reject) => {
    const onErr = (e: Error) => reject(e);
    server.server.once('error', onErr);
    server.listen(port, host, () => {
      server.server.off('error', onErr);
      resolve();
    });
  });
  const addr = server.server.address();
  return {
    server,
    host,
    port: typeof addr === 'object' && addr ? addr.port : port,
    tls: tlsMode,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
