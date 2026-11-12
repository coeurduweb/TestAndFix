// Regression tests of the adversarial review of the notebooks (2026-11-11): link takeover, streams
// and grants of a removed device, link rate limits and client IP, error logs, cross-site requests
// and framing, notebook creation, the shared view.
import { Writable } from 'node:stream';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import nodemailer from 'nodemailer';
import { config } from './config.js';
import { saveResult } from './db.js';
import { DEVICE_COOKIE, openStreamCount, sha256 } from './owner.js';
import { MAX_FAILED_GLOBAL, resetLinkAttempts } from './me.js';
import { Agent, startTestApp, type TestApp } from './test-helpers.js';
import type { ServerTool } from './tools/types.js';
import { tool as historyTool } from './tools/history/index.js';
import { configureMailService, mailService, tool as mailTool } from './tools/mail/index.js';
import { startSmtp, type SmtpHandle } from './mail/smtp.js';
import { fakeResolver, fixture, goodZone } from './mail/test-helpers.js';

const lines: string[] = [];
const sink = new Writable({
  write(c, _e, cb) {
    lines.push(...String(c).split('\n').filter(Boolean));
    cb();
  },
});

const probe: ServerTool = {
  id: 'sec-probe',
  register(app) {
    app.get('/api/sec/ip', async (req) => ({ ip: req.ip }));
    app.get<{ Params: { d: string } }>('/api/sec/boom/:d', async (req) => {
      throw new Error(`lookup failed for ${req.params.d}`, { cause: new Error(`cause about ${req.params.d}`) });
    });
    app.post('/api/sec/write', async () => ({ ok: true }));
    app.get('/api/sec/save', async () => ({ resultId: saveResult('sec', 'quiet.fr', {}) }));
  },
};

let t: TestApp;
let smtp: SmtpHandle;
const ownerOf = (a: Agent) => (t.db.prepare('SELECT owner_id FROM devices WHERE token_hash = ?').get(sha256(a.jar.get(DEVICE_COOKIE) ?? '')) as { owner_id: string } | undefined)?.owner_id;
const owners = () => (t.db.prepare('SELECT COUNT(*) AS n FROM owners').get() as { n: number }).n;
const upload = (a: Agent, eml = 'clean.eml') =>
  a.req('/api/mail/analyze', { method: 'POST', body: fixture(eml).toString('latin1'), headers: { 'content-type': 'text/plain' } });

beforeAll(async () => {
  configureMailService({ spamd: false, fetcher: false, dnsbl: false, resolver: () => fakeResolver(goodZone()) });
  t = await startTestApp({ tools: [historyTool, mailTool, probe], logStream: sink });
  smtp = await startSmtp(t.ctx, mailService(t.ctx), { host: '127.0.0.1', port: 0 });
});
afterAll(async () => {
  await smtp?.close();
  await t?.close();
});
beforeEach(() => resetLinkAttempts());

async function sendMail(to: string, subject: string) {
  const tr = nodemailer.createTransport({ host: '127.0.0.1', port: smtp.port, secure: false, ignoreTLS: true });
  const raw = fixture('clean.eml').toString('latin1').replace(/t-abcd2345@check\.localhost/g, to).replace('Votre devis pour la terrasse', subject);
  await tr.sendMail({ envelope: { from: 'bounce@atelier-exemple.fr', to: [to] }, raw });
  tr.close();
}

/** A second browser of the notebook of `a`. */
async function linkedTo(a: Agent): Promise<Agent> {
  const b = await t.agent();
  const r = await b.post('/api/me/link', { code: (await a.post('/api/me/link-code')).json.code });
  expect(r.status).toBe(200);
  return b;
}

describe('1. linking a browser that holds data needs a confirmation', () => {
  it('a code sent by someone else no longer takes the data in one click', async () => {
    const A = await t.agent();
    const B = await t.agent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36');
    saveResult('dns', 'client-secret-de-a.fr', { x: 1 }, { ownerId: ownerOf(A)! }, t.db);
    const oa = ownerOf(A);
    const code = (await B.post('/api/me/link-code')).json.code;

    const preview = await A.post('/api/me/link/preview', { code });
    expect(preview.status).toBe(200);
    expect(preview.json.devices).toEqual([{ label: 'Chrome sur Windows', lastSeenAt: expect.any(String) }]);
    expect(preview.json.joining).toEqual({ results: 1, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 });

    const r = await A.post('/api/me/link', { code });
    expect(r.status).toBe(409);
    expect(r.json).toEqual({ error: 'confirm_merge', joining: { results: 1, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 } });
    expect(ownerOf(A)).toBe(oa);
    expect((await B.get('/api/history?q=client-secret')).json.total).toBe(0);
    // nothing consumed: the code still works, and confirmMerge must be exactly true
    expect((await A.post('/api/me/link', { code, confirmMerge: 'yes' })).status).toBe(409);
    const ok = await A.post('/api/me/link', { code, confirmMerge: true });
    expect(ok.json).toEqual({ linked: true, moved: { results: 1, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 } });
  });

  it('an empty browser links without confirmation; preview does not consume the code', async () => {
    const A = await t.agent();
    const E = await t.agent();
    const code = (await A.post('/api/me/link-code')).json.code;
    expect((await E.post('/api/me/link/preview', { code })).json.joining).toEqual({ results: 0, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 });
    expect((await E.post('/api/me/link/preview', { code })).status).toBe(200);
    expect((await E.post('/api/me/link', { code })).json.linked).toBe(true);
    expect((await E.post('/api/me/link/preview', { code })).json).toEqual({ error: 'invalid_or_expired_code' });
  });

  it('preview failures share the attempt counter of /link', async () => {
    const C = await t.agent();
    for (let i = 0; i < 5; i++) expect((await C.post('/api/me/link/preview', { code: 'AAAA-AAAA' })).status).toBe(400);
    expect((await C.post('/api/me/link', { code: 'AAAA-AAAA' })).status).toBe(429);
    expect((await C.post('/api/me/link/preview', { code: 'AAAA-AAAA' })).status).toBe(429);
  });
});

describe('2. a removed device loses its open streams', () => {
  const streamOf = async (a: Agent, addressId: string) => {
    const s = await a.sse(`/api/mail/addresses/${addressId}/events`, (evs) => evs.some((e) => e.event === 'report'), 6000);
    expect(s.status).toBe(200);
    await new Promise((r) => setTimeout(r, 50));
    return s;
  };

  for (const how of ['deleted', 'linked away', 'erased'] as const) {
    it(`closes the stream when the device is ${how}`, async () => {
      const A = await t.agent();
      const B = await linkedTo(A);
      const addr = (await A.post('/api/mail/addresses', {})).json;
      const s = await streamOf(B, addr.id);
      const devB = (await B.get('/api/me')).json.device.id;
      expect(openStreamCount(devB)).toBe(1);
      if (how === 'deleted') expect((await A.del(`/api/me/devices/${devB}`)).status).toBe(204);
      if (how === 'linked away') {
        const other = await t.agent();
        expect((await B.post('/api/me/link', { code: (await other.post('/api/me/link-code')).json.code, confirmMerge: true })).status).toBe(200);
      }
      if (how === 'erased') expect((await A.post('/api/me/erase', { scope: 'all' })).status).toBe(200);
      const evs = await s.done;
      expect(openStreamCount(devB)).toBe(0);
      if (how !== 'erased') {
        await sendMail(addr.address, 'Secret apres revocation');
        await new Promise((r) => setTimeout(r, 300));
      }
      expect(evs.map((e) => e.event)).toEqual(['state']);
    });
  }

  it('checks the device again before each event', async () => {
    const A = await t.agent();
    const B = await linkedTo(A);
    const addr = (await A.post('/api/mail/addresses', {})).json;
    const s = await streamOf(B, addr.id);
    const devB = (await B.get('/api/me')).json.device.id;
    // the device leaves behind the registry's back: the next event must not be delivered
    const stranger = ownerOf(await t.agent());
    t.db.prepare('UPDATE devices SET owner_id = ? WHERE id = ?').run(stranger, devB);
    await sendMail(addr.address, 'Secret apres depart');
    const evs = await s.done;
    expect(evs.map((e) => e.event)).toEqual(['state']);
  });
});

describe('3. a removed device keeps no grant', () => {
  it('its link codes and its share links are revoked; the others stay', async () => {
    const A = await t.agent();
    const up = await upload(A);
    const mine = (await A.post(`/api/mail/messages/${up.json.messageId}/share`)).json.token;
    const up2 = await upload(A, 'no-message-id.eml');
    const B = await linkedTo(A);
    const byB = (await B.post(`/api/mail/messages/${up2.json.messageId}/share`)).json.token;
    const back = (await B.post('/api/me/link-code')).json.code;
    const devB = (await A.get('/api/me')).json.devices.find((d: { current: boolean }) => !d.current).id;
    expect((await A.del(`/api/me/devices/${devB}`)).status).toBe(204);
    expect((await B.get(`/api/shared/${byB}/raw`)).status).toBe(404);
    expect((await B.get(`/api/shared/${mine}`)).status).toBe(200);
    await B.get('/api/me');
    const r = await B.post('/api/me/link', { code: back });
    expect(r.status).toBe(400);
    expect((await A.get('/api/me')).json.devices).toHaveLength(1);
  });

  it('a device linked away leaves its link codes and share links behind', async () => {
    const A = await t.agent();
    const B = await linkedTo(A);
    const up = await upload(A);
    const byB = (await B.post(`/api/mail/messages/${up.json.messageId}/share`)).json.token;
    const back = (await B.post('/api/me/link-code')).json.code;
    const other = await t.agent();
    await B.post('/api/me/link', { code: (await other.post('/api/me/link-code')).json.code, confirmMerge: true });
    expect((await other.get(`/api/shared/${byB}`)).status).toBe(404);
    const C = await t.agent();
    expect((await C.post('/api/me/link', { code: back })).status).toBe(400);
    expect(t.db.prepare('SELECT COUNT(*) AS n FROM link_codes WHERE owner_id = ?').get(ownerOf(A))).toEqual({ n: 0 });
  });
});

describe('4. link attempt limits and client address', () => {
  it('a success does not reset the failure counter', async () => {
    const D = await t.agent();
    let fails = 0;
    let limited = 0;
    for (let cycle = 0; cycle < 4; cycle++) {
      for (let i = 0; i < 4; i++) {
        const r = await D.post('/api/me/link', { code: 'AAAA-AAAA' });
        if (r.status === 400) fails++;
        if (r.status === 429) limited++;
      }
      const helper = await t.agent();
      await D.post('/api/me/link', { code: (await helper.post('/api/me/link-code')).json.code, confirmMerge: true });
    }
    expect(fails).toBe(5);
    expect(limited).toBe(11);
  });

  it('req.ip is the address appended by the proxy, not the leftmost one the client wrote', async () => {
    const A = await t.agent();
    const ip = (xff?: string) => A.req('/api/sec/ip', { headers: xff ? { 'x-forwarded-for': xff } : {} }).then((r) => r.json.ip);
    expect(await ip()).toBe('127.0.0.1');
    expect(await ip('6.6.6.6, 198.51.100.7')).toBe('198.51.100.7');
    expect(await ip('10.9.9.9, 198.51.100.7')).toBe('198.51.100.7');
    expect(await ip('1.2.3.4, 5.6.7.8, 198.51.100.7')).toBe('198.51.100.7');
  });

  it('rotating a spoofed leftmost X-Forwarded-For does not bypass the per-IP limit', async () => {
    const B = await t.agent();
    const st: number[] = [];
    for (let i = 0; i < 8; i++) {
      const r = await B.req('/api/me/link', { method: 'POST', body: JSON.stringify({ code: 'AAAA-AAAA' }), headers: { 'x-forwarded-for': `10.0.${i}.1, 198.51.100.9` } });
      st.push(r.status);
    }
    expect(st).toEqual([400, 400, 400, 400, 400, 429, 429, 429]);
  });

  it('caps failed attempts for the whole server', async () => {
    const B = await t.agent();
    const st: number[] = [];
    for (let i = 0; i < MAX_FAILED_GLOBAL + 2; i++) {
      const r = await B.req('/api/me/link', { method: 'POST', body: JSON.stringify({ code: 'AAAA-AAAA' }), headers: { 'x-forwarded-for': `203.0.${i >> 2}.${i % 4}` } });
      st.push(r.status);
    }
    expect(st.slice(0, MAX_FAILED_GLOBAL).every((s) => s === 400)).toBe(true);
    expect(st.slice(MAX_FAILED_GLOBAL)).toEqual([429, 429]);
  });
});

describe('5. error logs', () => {
  it('keep type, status and stack frames, never the message', async () => {
    lines.length = 0;
    const A = await t.agent();
    const r = await A.get('/api/sec/boom/secret-client.fr');
    expect(r.status).toBe(500);
    await A.req('/api/sec/write', { method: 'POST', body: '{"domain":"secret-json.fr", oops', headers: { 'content-type': 'application/json' } });
    const all = lines.join('\n');
    expect(all).not.toMatch(/secret/);
    const err = lines.map((l) => JSON.parse(l)).find((l) => l.level === 50);
    expect(err.msg).toBe('request error');
    expect(err.err.type).toBe('Error');
    expect(err.err.message).toBeUndefined();
    expect(err.err.stack.length).toBeGreaterThan(0);
    expect(err.err.stack.every((f: string) => f.startsWith('at '))).toBe(true);
    expect(err.err.cause.type).toBe('Error');
    const bad = lines.map((l) => JSON.parse(l)).find((l) => l.err?.code === 'FST_ERR_CTP_INVALID_JSON_BODY');
    expect(bad).toMatchObject({ msg: 'request error', err: { statusCode: 400 } });
  });
});

describe('6. cross-site requests and framing', () => {
  it('refuses state-changing API requests that do not come from our pages', async () => {
    const A = await t.agent();
    const w = (headers: Record<string, string>) => A.req('/api/sec/write', { method: 'POST', body: '{}', headers });
    expect((await w({ 'sec-fetch-site': 'same-origin' })).status).toBe(200);
    expect((await w({ 'sec-fetch-site': 'same-site' })).json).toEqual({ error: 'cross_site_request' });
    expect((await w({ 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    expect((await w({ 'sec-fetch-site': 'none' })).status).toBe(403);
    expect((await w({})).status).toBe(200);
    expect((await w({ origin: new URL(config.publicUrl).origin })).status).toBe(200);
    expect((await w({ origin: 'https://autre.exemple-agence.com' })).status).toBe(403);
    expect((await A.req('/api/me/erase', { method: 'POST', body: '{"scope":"all"}', headers: { 'sec-fetch-site': 'same-site' } })).status).toBe(403);
    expect((await A.get('/api/me')).status).toBe(200);
    // reads stay open (a link followed from elsewhere)
    expect((await A.req('/api/me', { headers: { 'sec-fetch-site': 'cross-site' } })).status).toBe(200);
  });

  it('every response forbids framing by another site', async () => {
    const A = await t.agent();
    for (const r of [await A.get('/api/me'), await A.get('/api/rien'), await new Agent(t.base).get('/api/auth/status')]) {
      expect(r.headers.get('x-frame-options')).toBe('SAMEORIGIN');
      expect(r.headers.get('content-security-policy')).toBe("frame-ancestors 'self'");
    }
  });
});

describe('7. notebooks are created only at login, status and /api/me', () => {
  it('other routes without a known device run without notebook and create nothing', async () => {
    const A = await t.agent();
    const session = A.jar.get('check_session')!;
    const bare = new Agent(t.base);
    bare.jar.set('check_session', session);
    const before = owners();
    for (const path of ['/api/history', '/api/sec/save', '/api/history/stats']) {
      const r = await bare.get(path);
      expect(r.status).toBe(200);
      expect(r.setCookies.some((c) => c.startsWith(DEVICE_COOKIE))).toBe(false);
    }
    const addr = await bare.post('/api/mail/addresses', {});
    expect(addr.status).toBe(201);
    expect(t.db.prepare('SELECT owner_id FROM mail_addresses WHERE id = ?').get(addr.json.id)).toEqual({ owner_id: null });
    expect(t.db.prepare("SELECT COUNT(*) AS n FROM results WHERE input = 'quiet.fr' AND owner_id IS NULL").get()).toEqual({ n: 1 });
    expect((await bare.post('/api/me/link-code')).json).toEqual({ error: 'device_required' });
    expect(owners()).toBe(before);
    // forged cookies do not create notebooks either, except on the three entry points
    bare.jar.set(DEVICE_COOKIE, 'A'.repeat(43));
    expect((await bare.get('/api/history')).setCookies).toEqual([]);
    expect(owners()).toBe(before);
    const st = await bare.get('/api/auth/status');
    expect(st.setCookies.some((c) => c.startsWith(`${DEVICE_COOKIE}=`))).toBe(true);
    expect(owners()).toBe(before + 1);
    const me = await bare.get('/api/me');
    expect(me.setCookies.every((c) => !c.includes('A'.repeat(43)))).toBe(true);
    expect(owners()).toBe(before + 1);
  });
});

describe('8 and 9. shared view and share state', () => {
  it('the shared report hides the test address; GET share gives the share state alone', async () => {
    const A = await t.agent();
    const B = await t.agent();
    const addr = (await A.post('/api/mail/addresses', {})).json;
    await sendMail(addr.address, 'Rapport partage');
    let id: string | undefined;
    for (let i = 0; i < 100 && !id; i++) {
      const m = (await A.get(`/api/mail/addresses/${addr.id}`)).json.messages[0];
      if (m?.status === 'done') id = m.id;
      else await new Promise((r) => setTimeout(r, 50));
    }
    expect((await A.get(`/api/mail/messages/${id}/share`)).json).toEqual({ share: null });
    expect((await B.get(`/api/mail/messages/${id}/share`)).status).toBe(404);
    expect((await B.get(`/api/mail/messages/${id}/share`)).text).toBe((await B.get('/api/mail/messages/m-zzzzzzzzzzzz/share')).text);
    const s = (await A.post(`/api/mail/messages/${id}/share`)).json;
    expect((await A.get(`/api/mail/messages/${id}/share`)).json).toEqual({ share: s });
    const shared = await B.get(`/api/shared/${s.token}`);
    expect(shared.json.message).not.toHaveProperty('addressId');
    expect(shared.json.message).not.toHaveProperty('rcptTo');
    expect(shared.json.message.subject).toBe('Rapport partage');
    expect(shared.json.report.score).toBeTypeOf('number');
    expect(shared.text.toLowerCase()).not.toContain(addr.id);
    const raw = await B.get(`/api/shared/${s.token}/raw`);
    expect(raw.text.toLowerCase()).not.toContain(addr.id);
    expect(raw.text).toContain('Rapport partage');
    // the owner still sees everything
    expect((await A.get(`/api/mail/messages/${id}`)).json.message.addressId).toBe(addr.id);
  });
});
