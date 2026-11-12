// Notebooks (owner.ts): each browser sees only its own data, through every route that returns or
// acts on personal data. A row of another notebook (or a legacy row) answers exactly like a missing one.
import dgram from 'node:dgram';
import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import nodemailer from 'nodemailer';
import { saveResult } from './db.js';
import { currentOwnerId, sha256 } from './owner.js';
import { resetLinkAttempts } from './me.js';
import { openSse } from './lib/sse.js';
import { twoAgents, type Agent, type TestApp } from './test-helpers.js';
import type { ServerTool } from './tools/types.js';
import { tool as historyTool } from './tools/history/index.js';
import { configureMailService, mailService, tool as mailTool } from './tools/mail/index.js';
import { tool as dmarcTool } from './tools/dmarc-reports/index.js';
import { startSmtp, type SmtpHandle } from './mail/smtp.js';
import { fakeResolver, fixture, goodZone } from './mail/test-helpers.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const dmarcXml = fs.readFileSync(path.join(here, 'tools', 'dmarc-reports', 'fixtures', 'google.xml'));

/** A UDP round trip on the loopback: the same kind of async work as a DNS query. */
let echo: dgram.Socket;
function udpRoundTrip(): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4');
    s.once('message', (m) => {
      s.close();
      resolve(m.toString());
    });
    s.once('error', reject);
    s.send('ping', (echo.address() as { port: number }).port, '127.0.0.1');
  });
}

/** Test tool: saves results after async work, reports the owner seen deep inside the handler. */
const probe: ServerTool = {
  id: 'probe',
  register(app) {
    app.get<{ Querystring: { input?: string } }>('/api/probe/save', async (req) => {
      await new Promise((r) => setTimeout(r, 5));
      const afterTimer = currentOwnerId();
      const pong = await udpRoundTrip();
      const afterUdp = currentOwnerId();
      await Promise.resolve();
      const resultId = saveResult('probe', req.query.input ?? 'exemple.fr', { pong });
      return { resultId, seen: { afterTimer, afterUdp, end: currentOwnerId() } };
    });
    app.post<{ Body: { x?: number } }>('/api/probe/body', async (req) => {
      await new Promise((r) => setTimeout(r, 5));
      return { seen: currentOwnerId(), x: req.body?.x };
    });
    app.get<{ Querystring: { id?: string } }>('/api/probe/echo', async (req) => ({ resultId: req.query.id }));
    app.get('/api/probe/stream', async (req, reply) => {
      const sse = openSse(req, reply);
      setTimeout(async () => {
        await udpRoundTrip();
        const resultId = saveResult('probe', 'sse.exemple.fr', {});
        sse.send('done', { seen: currentOwnerId(), resultId });
        sse.close();
      }, 5);
    });
  },
};

let t: TestApp & { A: Agent; B: Agent };
let A: Agent;
let B: Agent;
let smtp: SmtpHandle;

const ownerOf = (a: Agent) => (t.db.prepare('SELECT owner_id FROM devices WHERE token_hash = ?').get(sha256(a.jar.get('check_device')!)) as { owner_id: string } | undefined)?.owner_id;

beforeAll(async () => {
  echo = dgram.createSocket('udp4');
  echo.on('message', (m, r) => echo.send(m, r.port, r.address));
  await new Promise<void>((r) => echo.bind(0, '127.0.0.1', () => r()));
  configureMailService({ spamd: false, fetcher: false, dnsbl: false, resolver: () => fakeResolver(goodZone()) });
  t = await twoAgents({ tools: [historyTool, mailTool, dmarcTool, probe] });
  ({ A, B } = t);
  smtp = await startSmtp(t.ctx, mailService(t.ctx), { host: '127.0.0.1', port: 0 });
});

afterAll(async () => {
  await smtp?.close();
  await t?.close();
  echo?.close();
});

beforeEach(() => resetLinkAttempts());

async function sendMail(to: string, subject = 'Votre devis pour la terrasse') {
  const transport = nodemailer.createTransport({ host: '127.0.0.1', port: smtp.port, secure: false, ignoreTLS: true });
  const raw = fixture('clean.eml').toString('latin1').replace(/t-abcd2345@check\.localhost/g, to).replace('Votre devis pour la terrasse', subject);
  await transport.sendMail({ envelope: { from: 'bounce@atelier-exemple.fr', to: [to] }, raw });
  transport.close();
}

async function waitDone(a: Agent, addressId: string, n: number) {
  for (let i = 0; i < 100; i++) {
    const r = await a.get(`/api/mail/addresses/${addressId}`);
    if (r.json.messages?.length >= n && r.json.messages.every((m: { status: string }) => m.status === 'done')) return r.json.messages;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('messages not analysed');
}

describe('device cookie', () => {
  it('is set at login, httpOnly, lax, path /, 400 days, and only its hash is stored', async () => {
    const C = await t.agent();
    const fresh = new (C.constructor as typeof Agent)(t.base);
    const r = await fresh.post('/api/auth/login', { password: 'mot-de-passe-de-test' });
    const set = r.setCookies.find((c) => c.startsWith('check_device='))!;
    expect(set).toBeTruthy();
    expect(set).toMatch(/HttpOnly/i);
    expect(set).toMatch(/SameSite=Lax/i);
    expect(set).toMatch(/Path=\//);
    expect(set).toMatch(/Max-Age=34560000/);
    expect(set).not.toMatch(/Secure/i); // publicUrl is http:// in tests
    const token = fresh.jar.get('check_device')!;
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const rows = t.db.prepare('SELECT * FROM devices').all() as Record<string, unknown>[];
    expect(JSON.stringify(rows)).not.toContain(token);
    expect(rows.some((d) => d.token_hash === sha256(token))).toBe(true);
    expect(rows.every((d) => !String(d.label).includes('Mozilla'))).toBe(true);
  });

  it('is secure when the public URL is https', async () => {
    const { config } = await import('./config.js');
    const { deviceCookieOptions } = await import('./owner.js');
    const before = config.publicUrl;
    config.publicUrl = 'https://check.exemple.fr';
    try {
      expect(deviceCookieOptions().secure).toBe(true);
    } finally {
      config.publicUrl = before;
    }
  });

  it('is never set without a session, and an unknown cookie starts a new notebook', async () => {
    const anon = new (A.constructor as typeof Agent)(t.base);
    const s = await anon.get('/api/auth/status');
    expect(s.setCookies.some((c) => c.startsWith('check_device'))).toBe(false);
    expect((await anon.get('/api/me')).status).toBe(401);
    const C = await t.agent();
    C.jar.set('check_device', 'x'.repeat(43));
    const me = await C.get('/api/me');
    expect(me.status).toBe(200);
    expect(C.jar.get('check_device')).not.toBe('x'.repeat(43));
    expect(me.json.counts).toEqual({ results: 0, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 });
  });

  it('GET /api/me describes the notebook and slides the cookie', async () => {
    const me = await B.get('/api/me');
    expect(me.status).toBe(200);
    expect(me.json.device).toMatchObject({ label: 'Safari sur iPhone' });
    expect(me.json.devices).toHaveLength(1);
    expect(me.json.devices[0]).toMatchObject({ current: true, id: me.json.device.id });
    expect(me.json.retentionDays).toBe(90);
    expect(Date.parse(me.json.device.createdAt)).toBeGreaterThan(0);
    expect(me.setCookies.some((c) => c.startsWith('check_device=') && /Max-Age=34560000/.test(c))).toBe(true);
    const labelA = (await A.get('/api/me')).json.device.label;
    expect(labelA).toBe('Firefox sur Linux');
  });
});

describe('owner inside handlers (AsyncLocalStorage)', () => {
  it('survives timers, a UDP round trip, a JSON body and an SSE handler', async () => {
    const owner = ownerOf(A);
    const r = await A.get('/api/probe/save?input=als.exemple.fr');
    expect(r.json.seen).toEqual({ afterTimer: owner, afterUdp: owner, end: owner });
    expect(t.db.prepare('SELECT owner_id FROM results WHERE id = ?').get(r.json.resultId)).toEqual({ owner_id: owner });
    // a body big enough to arrive in many chunks
    const b = await B.post('/api/probe/body', { x: 1, pad: 'y'.repeat(1_000_000) });
    expect(b.json).toEqual({ seen: ownerOf(B), x: 1 });
    const s = await A.sse('/api/probe/stream', (evs) => evs.some((e) => e.event === 'done'));
    const done = (await s.done).find((e) => e.event === 'done')!;
    expect(done.data.seen).toBe(owner);
    expect(t.db.prepare('SELECT owner_id FROM results WHERE id = ?').get(done.data.resultId)).toEqual({ owner_id: owner });
  });

  it('concurrent requests of two notebooks never mix', async () => {
    const rs = await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? A : B).get(`/api/probe/save?input=mix${i}.fr`)));
    rs.forEach((r, i) => expect(r.json.seen.end).toBe(ownerOf(i % 2 ? A : B)));
  });
});

describe('history', () => {
  it('lists, searches, counts and shows only the notebook rows', async () => {
    const saved = (await A.get('/api/probe/save?input=secret-a.fr')).json.resultId;
    const listA = await A.get('/api/history?q=secret-a');
    expect(listA.json.items.map((i: { id: string }) => i.id)).toContain(saved);
    const listB = await B.get('/api/history?q=secret-a');
    expect(listB.json).toEqual({ total: 0, items: [] });
    const byTool = await B.get('/api/history?tool=probe');
    expect(byTool.json.items.every((i: { input: string }) => !i.input.startsWith('secret-a'))).toBe(true);
    const all = await B.get('/api/history');
    expect(all.json.items.map((i: { id: string }) => i.id)).not.toContain(saved);
    expect(all.json.total).toBe(all.json.items.length);

    const missing = await B.get('/api/history/zzzzzzzzzz');
    const other = await B.get(`/api/history/${saved}`);
    expect(other.status).toBe(404);
    expect(other.text).toBe(missing.text);
    expect((await A.get(`/api/history/${saved}`)).status).toBe(200);

    const statsA = (await A.get('/api/history/stats')).json;
    const statsB = (await B.get('/api/history/stats')).json;
    expect(statsA.results).toBe((t.db.prepare('SELECT COUNT(*) AS n FROM results WHERE owner_id = ?').get(ownerOf(A)) as { n: number }).n);
    expect(statsB.results).toBe((t.db.prepare('SELECT COUNT(*) AS n FROM results WHERE owner_id = ?').get(ownerOf(B)) as { n: number }).n);
  });

  it('DELETE /api/history/:id removes only a row of the notebook', async () => {
    const id = (await A.get('/api/probe/save?input=to-delete.fr')).json.resultId;
    const missing = await B.del('/api/history/zzzzzzzzzz');
    const other = await B.del(`/api/history/${id}`);
    expect(other.status).toBe(404);
    expect(other.text).toBe(missing.text);
    expect((await A.del(`/api/history/${id}`)).status).toBe(204);
    expect((await A.get(`/api/history/${id}`)).status).toBe(404);
    expect((await A.del(`/api/history/${id}`)).status).toBe(404);
  });

  it('?historique=0 drops only the result of this request, in its own notebook', async () => {
    const id = (await A.get('/api/probe/save?input=keep.fr')).json.resultId;
    await B.get(`/api/probe/echo?id=${id}&historique=0`);
    expect(t.db.prepare('SELECT id FROM results WHERE id = ?').get(id)).toBeTruthy();
    const dropped = await A.get('/api/probe/save?input=prefill.fr&historique=0');
    expect(dropped.json.resultId).toBeUndefined();
    expect(t.db.prepare("SELECT id FROM results WHERE input = 'prefill.fr'").get()).toBeUndefined();
  });

  it('legacy rows without notebook are invisible to everyone', async () => {
    const now = Date.now();
    t.db.prepare("INSERT INTO results(id, tool, input, created_at, data) VALUES('legacy0001', 'spf', 'legacy.fr', ?, '{}')").run(now);
    t.db.prepare("INSERT INTO mail_addresses(id, address, created_at, expires_at) VALUES('t-legacy01', 't-legacy01@check.localhost', ?, ?)").run(now, now + 3600_000);
    t.db.prepare("INSERT INTO mail_messages(id, address_id, created_at, via, raw, status, subject) VALUES('m-legacy00001', 't-legacy01', ?, 'smtp', x'00', 'done', 'legacy')").run(now);
    t.db.prepare("INSERT INTO dmarc_reports(id, created_at, domain, org_name, report_id, messages, data) VALUES('legacyrep1', ?, 'legacy.fr', 'x', 'y', 1, '{}')").run(now);
    for (const a of [A, B]) {
      expect((await a.get('/api/history?q=legacy')).json.total).toBe(0);
      expect((await a.get('/api/history/legacy0001')).status).toBe(404);
      expect((await a.get('/api/mail/addresses/t-legacy01')).status).toBe(404);
      expect((await a.get('/api/mail/messages/m-legacy00001')).status).toBe(404);
      expect((await a.get('/api/mail/history?q=legacy')).json.total).toBe(0);
      expect((await a.get('/api/dmarc-reports/domains')).json.domains.map((d: { domain: string }) => d.domain)).not.toContain('legacy.fr');
      expect((await a.del('/api/dmarc-reports/legacyrep1')).status).toBe(404);
      expect((await a.del('/api/history/m-legacy00001')).status).toBe(404);
    }
  });
});

describe('mail tests', () => {
  let addr: { id: string; address: string };
  let msgs: { id: string }[];

  beforeAll(async () => {
    addr = (await A.post('/api/mail/addresses', { label: 'essai' })).json;
    const stream = await A.sse(`/api/mail/addresses/${addr.id}/events`, (evs) => evs.filter((e) => e.event === 'report').length >= 1);
    await new Promise((r) => setTimeout(r, 50));
    await sendMail(addr.address, 'Premier envoi confidentiel');
    const events = await stream.done;
    expect(events.map((e) => e.event)).toContain('report');
    await sendMail(addr.address, 'Second envoi confidentiel');
    msgs = await waitDone(A, addr.id, 2);
  });

  it('SMTP ingestion into an address of A lands in the notebook of A', () => {
    for (const m of msgs) expect(t.db.prepare('SELECT owner_id FROM mail_messages WHERE id = ?').get(m.id)).toEqual({ owner_id: ownerOf(A) });
  });

  it('B gets the not-found answer on the address, its stream, and every message route', async () => {
    const [m1, m2] = msgs;
    const same = async (path: string, missingPath: string, method = 'GET') => {
      const init = { method } as RequestInit;
      const other = await B.req(path, init);
      const missing = await B.req(missingPath, init);
      expect(other.status).toBe(404);
      expect(other.status).toBe(missing.status);
      expect(other.text).toBe(missing.text);
    };
    await same(`/api/mail/addresses/${addr.id}`, '/api/mail/addresses/t-zzzzzzzz');
    await same(`/api/mail/messages/${m1.id}`, '/api/mail/messages/m-zzzzzzzzzzzz');
    await same(`/api/mail/messages/${m1.id}/raw`, '/api/mail/messages/m-zzzzzzzzzzzz/raw');
    await same(`/api/mail/messages/${m1.id}/reanalyze`, '/api/mail/messages/m-zzzzzzzzzzzz/reanalyze', 'POST');
    await same(`/api/mail/messages/${m1.id}/share`, '/api/mail/messages/m-zzzzzzzzzzzz/share', 'POST');
    await same(`/api/mail/messages/${m1.id}/share`, '/api/mail/messages/m-zzzzzzzzzzzz/share', 'DELETE');
    await same(`/api/mail/compare?a=${m1.id}&b=${m2.id}`, '/api/mail/compare?a=m-zzzzzzzzzzzz&b=m-yyyyyyyyyyyy');
    await same(`/api/history/${m1.id}`, '/api/history/m-zzzzzzzzzzzz', 'DELETE');
    // the SSE stream is refused before it opens
    const s = await B.sse(`/api/mail/addresses/${addr.id}/events`, () => true);
    expect(s.status).toBe(404);
    expect(s.body).toBe((await B.get('/api/mail/addresses/t-zzzzzzzz')).text);
    // compare mixing one own message and one of A
    const up = await B.req('/api/mail/analyze', { method: 'POST', body: fixture('via-mailbox.eml').toString('latin1'), headers: { 'content-type': 'text/plain' } });
    expect((await B.get(`/api/mail/compare?a=${up.json.messageId}&b=${m1.id}`)).status).toBe(404);
  });

  it('B sees none of them in its lists; A sees everything', async () => {
    // B has an upload of its own from the same domain: only that one is listed
    const byDomain = (await B.get('/api/mail/history?domain=atelier-exemple.fr')).json;
    expect(byDomain.items.map((m: { id: string }) => m.id)).not.toEqual(expect.arrayContaining([msgs[0].id]));
    expect(byDomain.items.every((m: { via: string }) => m.via === 'upload')).toBe(true);
    expect(byDomain.total).toBe(byDomain.items.length);
    expect((await B.get('/api/mail/history?q=confidentiel')).json).toEqual({ total: 0, items: [] });
    const idsB = (await B.get('/api/history?q=atelier-exemple')).json.items.map((i: { id: string }) => i.id);
    for (const m of msgs) expect(idsB).not.toContain(m.id);
    expect((await B.get('/api/history/stats')).json.mails).toBe((t.db.prepare('SELECT COUNT(*) AS n FROM mail_messages WHERE owner_id = ?').get(ownerOf(B)) as { n: number }).n);

    expect((await A.get('/api/mail/history?q=confidentiel')).json.total).toBe(2);
    expect((await A.get(`/api/mail/messages/${msgs[0].id}`)).json.report).toBeTruthy();
    expect((await A.get(`/api/mail/messages/${msgs[0].id}/raw`)).text).toContain('confidentiel');
    expect((await A.get(`/api/mail/compare?a=${msgs[1].id}&b=${msgs[0].id}`)).status).toBe(200);
    const re = await A.post(`/api/mail/messages/${msgs[0].id}/reanalyze`);
    expect(re.status).toBe(200);
    expect(re.json.report.score).toBeTypeOf('number');
  });

  it('uploads go to the request notebook; the shared upload address lists only its own', async () => {
    const before = (await A.get('/api/mail/addresses/upload')).json.messages.length;
    // B listens on the shared pseudo-address while A uploads
    const s = await B.sse('/api/mail/addresses/upload/events', (evs) => evs.some((e) => e.event !== 'state'), 1500);
    const up = await A.req('/api/mail/analyze', { method: 'POST', body: fixture('attachment-exe.eml').toString('latin1'), headers: { 'content-type': 'text/plain' } });
    expect(up.status).toBe(200);
    expect(t.db.prepare('SELECT owner_id FROM mail_messages WHERE id = ?').get(up.json.messageId)).toEqual({ owner_id: ownerOf(A) });
    const evs = await s.done;
    expect(evs.map((e) => e.event)).toEqual(['state']);
    const listA = (await A.get('/api/mail/addresses/upload')).json.messages.map((m: { id: string }) => m.id);
    const listB = (await B.get('/api/mail/addresses/upload')).json.messages.map((m: { id: string }) => m.id);
    expect(listA).toHaveLength(before + 1);
    expect(listA).toContain(up.json.messageId);
    expect(listB).not.toContain(up.json.messageId);
    expect((await B.get(`/api/mail/messages/${up.json.messageId}`)).status).toBe(404);
  });

  it('a share link shows the report to another browser until it is revoked', async () => {
    const m = msgs[0];
    expect((await A.get(`/api/mail/messages/${m.id}`)).json.share).toBeNull();
    const s1 = await A.post(`/api/mail/messages/${m.id}/share`);
    expect(s1.status).toBe(200);
    expect(s1.json.token).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(s1.json.path).toBe(`/partage/${s1.json.token}`);
    expect((await A.post(`/api/mail/messages/${m.id}/share`)).json).toEqual(s1.json);
    expect((await A.get(`/api/mail/messages/${m.id}`)).json.share).toEqual(s1.json);
    expect(t.db.prepare('SELECT token_hash FROM shares WHERE target_id = ?').get(m.id)).toEqual({ token_hash: sha256(s1.json.token) });

    const own = (await A.get(`/api/mail/messages/${m.id}`)).json;
    const shared = await B.get(`/api/shared/${s1.json.token}`);
    expect(shared.status).toBe(200);
    // same report, without the share, the address id and the recipients, the test address masked
    const { addressId: _a, rcptTo: _r, ...ownMessage } = own.message;
    void _a;
    void _r;
    const masked = JSON.parse(JSON.stringify({ message: ownMessage, report: own.report }).replaceAll(addr.id, 't-00000000'));
    expect(shared.json).toEqual(masked);
    expect(shared.text).not.toContain(addr.id);
    expect(shared.json.report.score).toBe(own.report.score);
    const raw = await B.get(`/api/shared/${s1.json.token}/raw`);
    expect(raw.headers.get('content-type')).toMatch(/message\/rfc822/);
    expect(raw.text).toContain('confidentiel');
    expect(raw.text).not.toContain(addr.id);
    expect(raw.text).toContain('t-00000000@');
    // still behind the password
    const anon = new (A.constructor as typeof Agent)(t.base);
    expect((await anon.get(`/api/shared/${s1.json.token}`)).status).toBe(401);
    // B owns nothing of it
    expect((await B.get(`/api/mail/messages/${m.id}`)).status).toBe(404);

    expect((await A.del(`/api/mail/messages/${m.id}/share`)).status).toBe(204);
    expect((await B.get(`/api/shared/${s1.json.token}`)).status).toBe(404);
    expect((await B.get(`/api/shared/${s1.json.token}/raw`)).status).toBe(404);
    expect((await B.get('/api/shared/nope')).status).toBe(404);
  });

  it('deleting a message from the history removes it and its share', async () => {
    const m = msgs[1];
    const share = (await A.post(`/api/mail/messages/${m.id}/share`)).json;
    expect((await A.del(`/api/history/${m.id}`)).status).toBe(204);
    expect((await A.get(`/api/mail/messages/${m.id}`)).status).toBe(404);
    expect((await B.get(`/api/shared/${share.token}`)).status).toBe(404);
    expect(t.db.prepare('SELECT COUNT(*) AS n FROM shares WHERE target_id = ?').get(m.id)).toEqual({ n: 0 });
  });
});

describe('DMARC reports', () => {
  const upload = (a: Agent, gz = false) =>
    a.req('/api/dmarc-reports/upload', {
      method: 'POST',
      body: gz ? zlib.gzipSync(dmarcXml) : dmarcXml,
      headers: { 'content-type': gz ? 'application/gzip' : 'application/xml' },
    });

  it('are listed, aggregated and deleted per notebook; the duplicate check is per notebook', async () => {
    const C = await t.agent();
    const D = await t.agent();
    const up = await upload(C);
    expect(up.json.data.summary.imported).toBe(1);
    const id = up.json.data.files[0].id;
    expect((await upload(C, true)).json.data.summary.duplicates).toBe(1);

    expect((await D.get('/api/dmarc-reports/domains')).json).toEqual({ domains: [] });
    const listD = (await D.get('/api/dmarc-reports')).json;
    expect(listD.reports).toEqual([]);
    expect(listD.domain).toBeNull();
    expect((await D.get(`/api/dmarc-reports?domain=${up.json.data.domain}`)).json.reports).toEqual([]);
    const missing = await D.del('/api/dmarc-reports/zzzzzzzzzz');
    const other = await D.del(`/api/dmarc-reports/${id}`);
    expect(other.status).toBe(404);
    expect(other.text).toBe(missing.text);

    // the same report uploaded by another browser is a new import there, not "already there"
    const upD = await upload(D);
    expect(upD.json.data.summary).toMatchObject({ imported: 1, duplicates: 0 });
    expect((await C.get('/api/dmarc-reports')).json.reports.map((r: { id: string }) => r.id)).toEqual([id]);
    expect((await C.get('/api/dmarc-reports/domains')).json.domains[0].reports).toBe(1);
    expect((await C.del(`/api/dmarc-reports/${id}`)).json).toEqual({ deleted: true, id });
    expect((await D.get('/api/dmarc-reports')).json.reports).toHaveLength(1);
    // the upload is also a history entry of its own notebook
    expect((await D.get('/api/history?tool=dmarc-reports')).json.total).toBe(1);
    expect((await C.get('/api/history?tool=dmarc-reports')).json.total).toBe(1);
  });
});

describe('linking two browsers', () => {
  it('links with a code once; the data of a lone browser joins the target notebook', async () => {
    const X = await t.agent();
    const Y = await t.agent();
    const ox = ownerOf(X)!;
    const oy = ownerOf(Y)!;
    const xr = (await X.get('/api/probe/save?input=x-data.fr')).json.resultId;
    await Y.get('/api/probe/save?input=y-data.fr');
    await Y.post('/api/mail/addresses', {});
    const code = await X.post('/api/me/link-code');
    expect(code.json.code).toMatch(/^[ABCDEFGHJKMNPQRSTUVWXYZ2-9]{4}-[ABCDEFGHJKMNPQRSTUVWXYZ2-9]{4}$/);
    const ttl = Date.parse(code.json.expiresAt) - Date.now();
    expect(ttl).toBeGreaterThan(4.9 * 60_000);
    expect(ttl).toBeLessThanOrEqual(5 * 60_000);
    expect(t.db.prepare('SELECT code_hash FROM link_codes WHERE owner_id = ?').get(ox)).toEqual({ code_hash: sha256(code.json.code.replace('-', '')) });

    // own code is refused like any wrong code
    expect((await X.post('/api/me/link', { code: code.json.code })).json).toEqual({ error: 'invalid_or_expired_code' });
    const linked = await Y.post('/api/me/link', { code: `  ${code.json.code.replace('-', '').toLowerCase()} `, confirmMerge: true });
    expect(linked.status).toBe(200);
    expect(linked.json).toEqual({ linked: true, moved: { results: 1, mailMessages: 0, mailAddresses: 1, dmarcReports: 0 } });
    expect(ownerOf(Y)).toBe(ox);
    expect(t.db.prepare('SELECT id FROM owners WHERE id = ?').get(oy)).toBeUndefined();
    // Y now sees the notebook of X, with its own former data
    expect((await Y.get(`/api/history/${xr}`)).status).toBe(200);
    expect((await Y.get('/api/history?q=y-data')).json.total).toBe(1);
    expect((await X.get('/api/history?q=y-data')).json.total).toBe(1);
    const me = (await Y.get('/api/me')).json;
    expect(me.devices).toHaveLength(2);
    expect(me.devices.filter((d: { current: boolean }) => d.current)).toHaveLength(1);
    // single use
    const Z = await t.agent();
    const again = await Z.post('/api/me/link', { code: code.json.code });
    expect(again.status).toBe(400);
    expect(again.json).toEqual({ error: 'invalid_or_expired_code' });
  });

  it('a browser whose notebook has another device leaves its data there', async () => {
    const C = await t.agent();
    const D = await t.agent();
    const T = await t.agent();
    await C.get('/api/probe/save?input=c-data.fr');
    const oc = ownerOf(C)!;
    await D.post('/api/me/link', { code: (await C.post('/api/me/link-code')).json.code });
    expect(ownerOf(D)).toBe(oc);
    const r = await D.post('/api/me/link', { code: (await T.post('/api/me/link-code')).json.code, confirmMerge: true });
    expect(r.json).toEqual({ linked: true, moved: { results: 0, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 } });
    expect(ownerOf(D)).toBe(ownerOf(T));
    expect((await C.get('/api/history?q=c-data')).json.total).toBe(1);
    expect((await D.get('/api/history?q=c-data')).json.total).toBe(0);
  });

  it('refuses wrong and expired codes with one answer, a new code replaces the previous one', async () => {
    const C = await t.agent();
    const D = await t.agent();
    const first = (await C.post('/api/me/link-code')).json.code;
    const second = (await C.post('/api/me/link-code')).json.code;
    expect(t.db.prepare('SELECT COUNT(*) AS n FROM link_codes WHERE owner_id = ?').get(ownerOf(C))).toEqual({ n: 1 });
    const bad = await D.post('/api/me/link', { code: first });
    expect(bad.status).toBe(400);
    expect(bad.json).toEqual({ error: 'invalid_or_expired_code' });
    expect((await D.post('/api/me/link', { code: 'pas un code' })).json).toEqual({ error: 'invalid_or_expired_code' });
    expect((await D.post('/api/me/link', {})).json).toEqual({ error: 'invalid_or_expired_code' });
    t.db.prepare('UPDATE link_codes SET expires_at = ? WHERE owner_id = ?').run(Date.now() - 1, ownerOf(C));
    expect((await D.post('/api/me/link', { code: second })).json).toEqual({ error: 'invalid_or_expired_code' });
  });

  it('limits failed attempts to 5 per IP and minute', async () => {
    const C = await t.agent();
    for (let i = 0; i < 5; i++) expect((await C.post('/api/me/link', { code: 'AAAA-AAAA' })).status).toBe(400);
    const r = await C.post('/api/me/link', { code: 'AAAA-AAAA' });
    expect(r.status).toBe(429);
    expect(r.json.error).toBe('too_many_attempts');
    expect(r.json.retryAfter).toBeGreaterThan(0);
    expect(r.json.retryAfter).toBeLessThanOrEqual(60);
  });
});

describe('devices and erasing', () => {
  it('deletes another device of the notebook; the browser behind it starts a new empty notebook', async () => {
    const C = await t.agent();
    const D = await t.agent();
    await C.get('/api/probe/save?input=c-keep.fr');
    await D.post('/api/me/link', { code: (await C.post('/api/me/link-code')).json.code });
    const devD = (await D.get('/api/me')).json.device.id;
    const missing = await B.del('/api/me/devices/zzzzzzzzzzzz');
    const other = await B.del(`/api/me/devices/${devD}`);
    expect(other.status).toBe(404);
    expect(other.text).toBe(missing.text);
    expect((await C.del(`/api/me/devices/${devD}`)).status).toBe(204);
    expect((await C.get('/api/me')).json.devices).toHaveLength(1);
    expect((await C.get('/api/history?q=c-keep')).json.total).toBe(1);
    const meD = (await D.get('/api/me')).json;
    expect(meD.counts).toEqual({ results: 0, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 });
    expect((await D.get('/api/history?q=c-keep')).json.total).toBe(0);
  });

  it('deleting the last device erases the notebook at once and clears the cookie', async () => {
    const C = await t.agent();
    await C.get('/api/probe/save?input=c-gone.fr');
    const a = (await C.post('/api/mail/addresses', {})).json;
    const up = await C.req('/api/mail/analyze', { method: 'POST', body: fixture('via-mailbox.eml').toString('latin1'), headers: { 'content-type': 'text/plain' } });
    expect((await C.post(`/api/mail/messages/${up.json.messageId}/share`)).status).toBe(200);
    const oc = ownerOf(C)!;
    const dev = (await C.get('/api/me')).json.device.id;
    const r = await C.del(`/api/me/devices/${dev}`);
    expect(r.status).toBe(204);
    expect(r.setCookies.some((c) => c.startsWith('check_device=;') || /check_device=.*(Max-Age=0|Expires=Thu, 01 Jan 1970)/i.test(c))).toBe(true);
    for (const tb of ['results', 'mail_addresses', 'mail_messages', 'dmarc_reports', 'shares', 'link_codes', 'devices'])
      expect(t.db.prepare(`SELECT COUNT(*) AS n FROM ${tb} WHERE owner_id = ?`).get(oc)).toEqual({ n: 0 });
    expect(t.db.prepare('SELECT id FROM owners WHERE id = ?').get(oc)).toBeUndefined();
    expect((await C.get(`/api/mail/addresses/${a.id}`)).status).toBe(404);
    expect(C.jar.has('check_device')).toBe(false);
    await C.get('/api/me');
    expect(ownerOf(C)).not.toBe(oc);
  });

  it("erase 'data' empties the notebook and keeps its devices", async () => {
    const C = await t.agent();
    const D = await t.agent();
    await D.post('/api/me/link', { code: (await C.post('/api/me/link-code')).json.code });
    await C.get('/api/probe/save?input=c1.fr');
    await C.get('/api/probe/save?input=c2.fr');
    await C.post('/api/mail/addresses', {});
    await D.req('/api/mail/analyze', { method: 'POST', body: fixture('via-mailbox.eml').toString('latin1'), headers: { 'content-type': 'text/plain' } });
    const keepB = (await B.get('/api/me')).json.counts;
    expect((await C.post('/api/me/erase', { scope: 'nope' })).status).toBe(400);
    const r = await C.post('/api/me/erase', { scope: 'data' });
    expect(r.json).toEqual({ erased: { results: 2, mailMessages: 1, mailAddresses: 1, dmarcReports: 0 } });
    const me = (await D.get('/api/me')).json;
    expect(me.devices).toHaveLength(2);
    expect(me.counts).toEqual({ results: 0, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 });
    expect(me.oldest).toBeNull();
    expect((await B.get('/api/me')).json.counts).toEqual(keepB);
  });

  it("erase 'all' removes the notebook and its devices; the next request opens a new one", async () => {
    const C = await t.agent();
    const D = await t.agent();
    await D.post('/api/me/link', { code: (await C.post('/api/me/link-code')).json.code });
    await C.get('/api/probe/save?input=c-all.fr');
    const oc = ownerOf(C)!;
    const r = await C.post('/api/me/erase', { scope: 'all' });
    expect(r.json.erased.results).toBe(1);
    expect(r.setCookies.some((c) => c.startsWith('check_device='))).toBe(true);
    expect(C.jar.has('check_device')).toBe(false);
    expect(t.db.prepare('SELECT COUNT(*) AS n FROM devices WHERE owner_id = ?').get(oc)).toEqual({ n: 0 });
    expect(t.db.prepare('SELECT id FROM owners WHERE id = ?').get(oc)).toBeUndefined();
    const meC = await C.get('/api/me');
    expect(meC.json.counts.results).toBe(0);
    expect(ownerOf(C)).not.toBe(oc);
    // the other browser of the erased notebook gets a new one too
    const meD = await D.get('/api/me');
    expect(meD.json.devices).toHaveLength(1);
    expect(ownerOf(D)).not.toBe(oc);
  });
});
