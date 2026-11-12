// IMAP reception against a real server. Runs only when one is given, for example GreenMail.
//
// Clear text (plus STARTTLS when offered):
//   docker run -d --name check-greenmail -p 127.0.0.1:3025:3025 -p 127.0.0.1:3143:3143 \
//     -e GREENMAIL_OPTS='-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users=catch:secret@check.localhost' \
//     greenmail/standalone:2.1.3
//   CHECK_TEST_IMAP_PORT=3143 CHECK_TEST_IMAP_SMTP_PORT=3025 npx vitest run src/mail/imap.test.ts
//
// Implicit TLS (imaps, 3993) with a self-signed certificate for 127.0.0.1 and localhost. GreenMail's
// own certificate names no host, so it is replaced by one made here (the test needs its PEM as CA):
//   D=$(mktemp -d) && cd "$D" && openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
//     -days 30 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
//     && openssl pkcs12 -export -in cert.pem -inkey key.pem -out greenmail.p12 -passout pass:changeit -name greenmail \
//     && chmod 644 greenmail.p12
//   docker run -d --name check-greenmail -v "$D/greenmail.p12:/certs/greenmail.p12:ro" \
//     -p 127.0.0.1:3025:3025 -p 127.0.0.1:3143:3143 -p 127.0.0.1:3993:3993 \
//     -e GREENMAIL_OPTS='-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users=catch:secret@check.localhost -Dgreenmail.tls.keystore.file=/certs/greenmail.p12 -Dgreenmail.tls.keystore.password=changeit' \
//     greenmail/standalone:2.1.3
//   CHECK_TEST_IMAP_PORT=3143 CHECK_TEST_IMAPS_PORT=3993 CHECK_TEST_IMAPS_CA="$D/cert.pem" CHECK_TEST_IMAP_SMTP_PORT=3025 \
//     npx vitest run src/mail/imap.test.ts
//   docker rm -f check-greenmail
import fs from 'node:fs';
import net from 'node:net';
import { describe, expect, it } from 'vitest';
import nodemailer from 'nodemailer';
import { ImapFlow } from 'imapflow';
import { openDb } from '../db.js';
import { config } from '../config.js';
import { ResolveSession } from '../dns/iterative.js';
import { ImapReceiver } from './imap.js';
import { MailService } from './service.js';
import { createAddress, listMessages } from './store.js';
import { fakeResolver, fixture, goodZone } from './test-helpers.js';
import type { ToolContext } from '../tools/types.js';

const imapPort = Number(process.env.CHECK_TEST_IMAP_PORT ?? 0);
const imapsPort = Number(process.env.CHECK_TEST_IMAPS_PORT ?? 0);
const imapsCa = process.env.CHECK_TEST_IMAPS_CA ?? '';
const smtpPort = Number(process.env.CHECK_TEST_IMAP_SMTP_PORT ?? 0);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function setup(imap: Partial<typeof config.imap>) {
  const db = openDb(':memory:');
  const cfg = {
    ...config,
    mail: { ...config.mail, domain: 'check.localhost' },
    imap: { ...config.imap, host: '127.0.0.1', user: 'catch', pass: 'secret', mailbox: 'INBOX', domain: 'check.localhost', tlsCa: '', ...imap },
  };
  const ctx: ToolContext = { db, config: cfg, dns: (o) => new ResolveSession(o) };
  const svc = new MailService(ctx, { spamd: false, fetcher: false, dnsbl: false, resolver: () => fakeResolver(goodZone()) });
  return { db, ctx, svc };
}

/** One message for the test address and one for nobody, both into the catch-all mailbox. */
async function deliver(address: string) {
  const raw = fixture('via-mailbox.eml').toString('latin1').replace(/t-abcd2345@check\.localhost/g, address);
  const t = nodemailer.createTransport({ host: '127.0.0.1', port: smtpPort, secure: false, ignoreTLS: true });
  await t.sendMail({ envelope: { from: 'bounce@atelier-exemple.fr', to: ['catch@check.localhost'] }, raw });
  await t.sendMail({ envelope: { from: 'x@ailleurs.fr', to: ['catch@check.localhost'] }, raw: 'From: x@ailleurs.fr\r\nTo: personne@ailleurs.fr\r\nSubject: hors test\r\n\r\nrien\r\n' });
  t.close();
}

async function waitDone(db: ReturnType<typeof openDb>, addressId: string, rx: ImapReceiver) {
  let done = false;
  for (let i = 0; i < 100 && !done; i++) {
    const m = listMessages(db, addressId);
    done = m.length === 1 && m[0].status === 'done' && rx.status.skipped >= 1;
    if (!done) await sleep(100);
  }
  return done;
}

describe.skipIf(!imapPort || !smtpPort)('IMAP catch-all mailbox', () => {
  it('picks up a new message, matches its address, analyses it and flags it seen', async () => {
    const { db, ctx, svc } = setup({ port: imapPort, secure: false });
    const addr = createAddress(db, 'check.localhost', 1);
    const rx = new ImapReceiver(ctx, svc, 500);
    rx.start();
    for (let i = 0; i < 50 && !rx.status.connected; i++) await sleep(100);
    expect(rx.status.connected).toBe(true);

    await deliver(addr.address);
    expect(await waitDone(db, addr.id, rx), JSON.stringify(rx.status)).toBe(true);
    const m = listMessages(db, addr.id)[0];
    expect(m.via).toBe('imap');
    expect(m.client_ip).toBe('93.184.215.14');
    expect(rx.status.skipped).toBeGreaterThanOrEqual(1);

    // both messages are flagged \Seen on the server
    const c = new ImapFlow({ host: '127.0.0.1', port: imapPort, secure: false, auth: { user: 'catch', pass: 'secret' }, logger: false });
    await c.connect();
    await c.mailboxOpen('INBOX');
    const unseen = await c.search({ seen: false });
    await c.logout();
    expect(unseen).toEqual([]);
    await rx.stop();
  });
});

describe.skipIf(!imapsPort || !imapsCa || !smtpPort)('IMAP catch-all mailbox over implicit TLS', () => {
  it('refuses a self-signed certificate it was not told to trust (verification stays on)', async () => {
    const { ctx, svc } = setup({ port: imapsPort, secure: true });
    const rx = new ImapReceiver(ctx, svc, 500);
    rx.start();
    for (let i = 0; i < 50 && !rx.status.lastError; i++) await sleep(100);
    await rx.stop();
    expect(rx.status.connected).toBe(false);
    expect(rx.status.lastConnectAt).toBeUndefined();
    expect(rx.status.lastError ?? '').toMatch(/self[- ]signed|certificate/i);
  });

  it('refuses the trusted certificate when the host name does not match it', async () => {
    // 127.0.0.2 (loopback on Linux) forwards to the same server but is not in the certificate
    const relay = net.createServer((s) => {
      const up = net.connect(imapsPort, '127.0.0.1');
      s.pipe(up).pipe(s);
      s.on('error', () => up.destroy());
      up.on('error', () => s.destroy());
    });
    await new Promise<void>((r, j) => relay.once('error', j).listen(0, '127.0.0.2', () => r()));
    const port = (relay.address() as net.AddressInfo).port;
    const { ctx, svc } = setup({ host: '127.0.0.2', port, secure: true, tlsCa: imapsCa });
    const rx = new ImapReceiver(ctx, svc, 500);
    rx.start();
    for (let i = 0; i < 50 && !rx.status.lastError; i++) await sleep(100);
    await rx.stop();
    relay.close();
    expect(rx.status.connected).toBe(false);
    expect(rx.status.lastError ?? '').toMatch(/IP: 127\.0\.0\.2|altnames|does not match/i);
  });

  it('with CHECK_IMAP_TLS_CA: connects over TLS, verified, and ingests the message', async () => {
    // the CA is given as a file path here; inline PEM text works too
    expect(fs.readFileSync(imapsCa, 'utf8')).toContain('BEGIN CERTIFICATE');
    const { db, ctx, svc } = setup({ port: imapsPort, secure: true, tlsCa: imapsCa });
    const addr = createAddress(db, 'check.localhost', 1);
    const rx = new ImapReceiver(ctx, svc, 500);
    rx.start();
    for (let i = 0; i < 50 && !rx.status.connected; i++) await sleep(100);
    expect(rx.status.connected, JSON.stringify(rx.status)).toBe(true);
    expect(rx.status.tls).toMatchObject({ authorized: true });
    expect((rx.status.tls as { protocol?: string }).protocol).toMatch(/^TLSv1\.[23]$/);

    await deliver(addr.address);
    expect(await waitDone(db, addr.id, rx), JSON.stringify(rx.status)).toBe(true);
    expect(listMessages(db, addr.id)[0].via).toBe('imap');
    await rx.stop();
  });
});
