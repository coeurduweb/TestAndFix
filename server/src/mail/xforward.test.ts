// Reception behind the host's Postfix (decision 2026-11-11): XFORWARD from a trusted relay gives
// the original client; from any other peer it is neither offered nor accepted.
import net from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openDb } from '../db.js';
import { config } from '../config.js';
import { ResolveSession } from '../dns/iterative.js';
import { MailService } from './service.js';
import { startSmtp, inCidrs, relayTls, type SmtpHandle } from './smtp.js';
import { createAddress, listMessages, getMessage } from './store.js';
import { fakeResolver, fixture, goodZone } from './test-helpers.js';
import type { ToolContext } from '../tools/types.js';
import type { MailReport } from './analyze/index.js';

/** Minimal SMTP client: sends each line, collects every reply. */
async function talk(port: number, lines: (string | Buffer)[]): Promise<string[]> {
  const sock = net.createConnection({ host: '127.0.0.1', port });
  const replies: string[] = [];
  let buf = '';
  let waiting: (() => void) | undefined;
  sock.on('data', (d) => {
    buf += d.toString('latin1');
    // a complete reply ends with "NNN text" (no dash after the code)
    let m: RegExpExecArray | null;
    while ((m = /^(?:\d{3}-[^\n]*\n)*\d{3}(?: [^\n]*)?\n/.exec(buf))) {
      replies.push(m[0].trim());
      buf = buf.slice(m[0].length);
      waiting?.();
    }
  });
  const next = () => new Promise<void>((r) => (waiting = r));
  await next(); // banner
  for (const l of lines) {
    const p = next();
    sock.write(typeof l === 'string' ? l + '\r\n' : l);
    await p;
  }
  sock.end('QUIT\r\n');
  return replies;
}

const POSTFIX_TLS =
  'Received: from mail.atelier-exemple.fr (mail.atelier-exemple.fr [93.184.215.14])\r\n' +
  '\t(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)\r\n' +
  '\t key-exchange X25519 server-signature RSA-PSS (2048 bits))\r\n' +
  '\t(No client certificate requested)\r\n' +
  '\tby mx.exemple-agence.com (Postfix) with ESMTPS id 4Xq1;\r\n' +
  '\tTue, 10 Nov 2026 16:00:02 +0100 (CET)\r\n';
const POSTFIX_PLAIN =
  'Received: from mail.atelier-exemple.fr (mail.atelier-exemple.fr [93.184.215.14])\r\n' +
  '\tby mx.exemple-agence.com (Postfix) with ESMTP id 4Xq2;\r\n' +
  '\tTue, 10 Nov 2026 16:00:02 +0100 (CET)\r\n';

function server(trustedRelays: string[]) {
  const db = openDb(':memory:');
  const cfg = { ...config, mail: { ...config.mail, domain: 'check.localhost', trustedRelays } };
  const ctx: ToolContext = { db, config: cfg, dns: (o) => new ResolveSession(o) };
  const svc = new MailService(ctx, { spamd: false, fetcher: false, dnsbl: false, resolver: () => fakeResolver(goodZone()) });
  return { db, ctx, svc };
}

async function waitDone(db: ReturnType<typeof openDb>, addressId: string): Promise<MailReport> {
  for (let i = 0; i < 100; i++) {
    const m = listMessages(db, addressId)[0];
    if (m?.status === 'done') return JSON.parse(getMessage(db, m.id)!.report!);
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('analysis not finished');
}

const send = (port: number, addr: string, body: string, xforward?: string) =>
  talk(port, ['EHLO mx.exemple-agence.com', ...(xforward ? [xforward] : []), 'MAIL FROM:<bounce@atelier-exemple.fr>', `RCPT TO:<${addr}>`, 'DATA', Buffer.from(body + '\r\n.\r\n', 'latin1')]);

describe('XFORWARD from the host relay', () => {
  const trustedSrv = server(['172.16.0.0/12', '127.0.0.1/32']);
  const untrustedSrv = server(['10.0.0.0/8']);
  let trusted: SmtpHandle;
  let untrusted: SmtpHandle;
  beforeAll(async () => {
    trusted = await startSmtp(trustedSrv.ctx, trustedSrv.svc, { host: '127.0.0.1', port: 0 });
    untrusted = await startSmtp(untrustedSrv.ctx, untrustedSrv.svc, { host: '127.0.0.1', port: 0 });
  });
  afterAll(async () => {
    await trusted?.close();
    await untrusted?.close();
  });

  const XF = 'XFORWARD NAME=mail.atelier-exemple.fr ADDR=93.184.215.14 PROTO=ESMTP HELO=mail.atelier-exemple.fr';

  it('trusted relay: the original client, its HELO and the TLS read in the Postfix Received', async () => {
    const a = createAddress(trustedSrv.db, 'check.localhost', 1);
    const body = POSTFIX_TLS + fixture('clean.eml').toString('latin1').replace(/t-abcd2345@check\.localhost/g, a.address);
    const replies = await send(trusted.port, a.address, body, XF);
    expect(replies.find((r) => r.includes('XFORWARD NAME ADDR'))).toBeDefined();
    expect(replies.slice(-1)[0]).toMatch(/^250/);
    const r = await waitDone(trustedSrv.db, a.id);
    expect(r.data.envelope).toMatchObject({ clientIp: '93.184.215.14', ipSource: 'xforward', helo: 'mail.atelier-exemple.fr' });
    expect(r.data.envelope.tls).toMatchObject({ used: true, protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', source: 'relay' });
    expect((r.data.auth as { spf: { result: string } }).spf.result).toBe('pass');
    const row = listMessages(trustedSrv.db, a.id)[0];
    expect(row.client_ip).toBe('93.184.215.14');
    expect(row.client_ptr).toBe('mail.atelier-exemple.fr');
    // the relay never appears as the sender
    const text = JSON.stringify(r) + getMessage(trustedSrv.db, row.id)!.raw.toString('latin1').split('\r\n\r\n')[0];
    expect(text).not.toMatch(/127\.0\.0\.1|172\.(1[6-9]|2\d|3[01])\./);
    expect(text).not.toContain('adresse privée');
  });

  it('trusted relay, original connection in clear: plaintext reported from the Received', async () => {
    const a = createAddress(trustedSrv.db, 'check.localhost', 1);
    const body = POSTFIX_PLAIN + fixture('no-message-id.eml').toString('latin1');
    await send(trusted.port, a.address, body, XF);
    const r = await waitDone(trustedSrv.db, a.id);
    expect(r.data.envelope.tls).toMatchObject({ used: false, source: 'relay' });
    expect(r.findings.map((f) => f.id)).toContain('tls.inbound_plaintext');
  });

  it('peer outside the trusted relays: XFORWARD neither offered nor accepted, the peer is the client', async () => {
    const a = createAddress(untrustedSrv.db, 'check.localhost', 1);
    const body = POSTFIX_TLS + fixture('no-message-id.eml').toString('latin1');
    const replies = await send(untrusted.port, a.address, body, XF);
    expect(replies.some((r) => r.includes('XFORWARD NAME'))).toBe(false);
    expect(replies.find((r) => /^550/.test(r))).toBeDefined();
    const r = await waitDone(untrustedSrv.db, a.id);
    expect(r.data.envelope).toMatchObject({ clientIp: '127.0.0.1', ipSource: 'smtp', helo: 'mx.exemple-agence.com' });
    expect(r.data.envelope.tls?.source).toBe('smtp');
  });

  it('CIDR matching and Received parsing', () => {
    expect(inCidrs('172.22.0.1', ['172.16.0.0/12'])).toBe(true);
    expect(inCidrs('::ffff:172.22.0.1', ['172.16.0.0/12'])).toBe(true);
    expect(inCidrs('127.0.0.1', ['127.0.0.1/32'])).toBe(true);
    expect(inCidrs('192.168.1.1', ['172.16.0.0/12', '127.0.0.1'])).toBe(false);
    expect(inCidrs('127.0.0.1', [])).toBe(false);
    expect(relayTls(Buffer.from(POSTFIX_TLS + '\r\nx'))).toEqual({ used: true, protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384' });
    expect(relayTls(Buffer.from(POSTFIX_PLAIN + '\r\nx'))).toEqual({ used: false });
    expect(relayTls(Buffer.from('Subject: x\r\n\r\nx')).used).toBeNull();
  });
});
