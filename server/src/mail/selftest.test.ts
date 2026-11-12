// Reception self-test (US-099), end to end against the application's own SMTP server: hidden
// address, message over SMTP with STARTTLS, rows invisible to every notebook and removed after the
// check, outcome recorded, public health endpoint.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SMTPServer } from 'smtp-server';
import { config } from '../config.js';
import { startTestApp, type Agent, type TestApp } from '../test-helpers.js';
import { configureMailService, mailService, tool as mailTool } from '../tools/mail/index.js';
import { tool as historyTool } from '../tools/history/index.js';
import { tool as dmarcTool } from '../tools/dmarc-reports/index.js';
import { mailBus, type MailEvent } from './events.js';
import { startSmtp, type SmtpHandle } from './smtp.js';
import { cleanupSelfTest, receptionHealth, runSelfTest, selfTestState, SELFTEST_LABEL, startSelfTestJob } from './selftest.js';
import { fakeResolver, goodZone } from './test-helpers.js';

let t: TestApp;
let A: Agent;
let smtp: SmtpHandle;
const saved = { ...config.selftest };

const count = (sql: string) => (t.db.prepare(sql).get() as { n: number }).n;
const selfTestRows = () =>
  count(`SELECT COUNT(*) AS n FROM mail_addresses WHERE label = '${SELFTEST_LABEL}'`) +
  count(`SELECT COUNT(*) AS n FROM mail_messages WHERE address_id IN (SELECT id FROM mail_addresses WHERE label = '${SELFTEST_LABEL}')`);

/** An SMTP server that is not ours: it accepts (or refuses) and keeps nothing. */
async function foreignSmtp(refuse?: number): Promise<{ port: number; close(): Promise<void> }> {
  const s = new SMTPServer({
    authOptional: true,
    disabledCommands: ['AUTH', 'STARTTLS'],
    logger: false,
    onRcptTo(_a, _s, cb) {
      if (!refuse) return cb();
      cb(Object.assign(new Error('5.1.1 nope'), { responseCode: refuse }));
    },
    onData(stream, _s, cb) {
      stream.resume();
      stream.on('end', () => cb());
    },
  });
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r()));
  return { port: (s.server.address() as { port: number }).port, close: () => new Promise<void>((r) => s.close(() => r())) };
}

beforeAll(async () => {
  configureMailService({ spamd: false, fetcher: false, dnsbl: false, resolver: () => fakeResolver(goodZone()) });
  t = await startTestApp({ tools: [mailTool, historyTool, dmarcTool] });
  A = await t.agent();
  smtp = await startSmtp(t.ctx, mailService(t.ctx), { host: '127.0.0.1', port: 0 });
  config.selftest.smtpHost = '127.0.0.1';
  config.selftest.smtpPort = smtp.port;
});

afterAll(async () => {
  Object.assign(config.selftest, saved);
  await smtp?.close();
  await t?.close();
});

describe('reception self-test', () => {
  it('sends to a hidden address through our SMTP server (STARTTLS), invisible to every notebook, then removes it', async () => {
    // A also has a real test address: only the self-test may stay out of sight
    const own = await A.post('/api/mail/addresses', {});
    expect(own.status).toBe(201);
    const events: MailEvent[] = [];
    const onAny = (e: MailEvent) => events.push(e);
    mailBus.on('any', onAny);
    let seen = false;
    let failure: unknown;
    const o = await runSelfTest(t.ctx, {
      timeoutMs: 10_000,
      beforeCleanup: (addressId) => inspect(addressId).catch((e) => (failure = e)),
    });
    async function inspect(addressId: string) {
      seen = true;
      const a = t.db.prepare('SELECT * FROM mail_addresses WHERE id = ?').get(addressId) as { owner_id: string | null; label: string };
      expect(a).toMatchObject({ owner_id: null, label: SELFTEST_LABEL });
      const msgs = t.db.prepare('SELECT * FROM mail_messages WHERE address_id = ?').all(addressId) as { id: string; owner_id: string | null; status: string; report: string | null; raw: Buffer }[];
      expect(msgs).toHaveLength(1);
      const m = msgs[0];
      expect(m).toMatchObject({ owner_id: null, status: 'done', report: null });
      // our own Received line: the session went through STARTTLS
      expect(Buffer.from(m.raw).toString('latin1')).toMatch(/\(using TLSv1\.[23]/);
      // nothing of it through any route of a notebook
      expect((await A.get('/api/mail/history')).json).toEqual({ total: 0, items: [] });
      expect((await A.get('/api/history')).json).toMatchObject({ total: 0, items: [] });
      expect((await A.get(`/api/mail/addresses/${addressId}`)).status).toBe(404);
      expect((await A.get(`/api/mail/addresses/${addressId}/events`)).status).toBe(404);
      expect((await A.get(`/api/mail/messages/${m.id}`)).status).toBe(404);
      expect((await A.get(`/api/mail/messages/${m.id}/raw`)).status).toBe(404);
      expect((await A.post(`/api/mail/messages/${m.id}/share`)).status).toBe(404);
      expect((await A.post(`/api/mail/messages/${m.id}/reanalyze`)).status).toBe(404);
      expect((await A.get(`/api/mail/compare?a=${m.id}&b=${m.id}`)).status).toBe(404);
      expect((await A.get('/api/dmarc-reports/domains')).json).toEqual({ domains: [] });
      const me = (await A.get('/api/me')).json;
      expect(me.counts.mailMessages).toBe(0);
      expect(me.counts.mailAddresses).toBe(1);
    }
    mailBus.off('any', onAny);
    if (failure) throw failure;
    expect(seen).toBe(true);
    expect(o).toMatchObject({ ok: true });
    expect(o.error).toBeUndefined();
    expect(o.durationMs).toBeGreaterThanOrEqual(0);
    // neither analysed nor announced on the event bus
    expect(events).toEqual([]);
    expect(selfTestRows()).toBe(0);
    expect(selfTestState(t.db)).toEqual({ lastRun: o, lastSuccess: o.at });
    // A's own address is untouched
    expect((await A.get(`/api/mail/addresses/${own.json.id}`)).status).toBe(200);
  });

  it('records a refused connection, without touching the last success', async () => {
    const before = selfTestState(t.db).lastSuccess;
    const gone = await foreignSmtp();
    await gone.close();
    const o = await runSelfTest(t.ctx, { port: gone.port, timeoutMs: 5000 });
    expect(o.ok).toBe(false);
    expect(o.error).toMatch(/^(ECONNECTION|ECONNREFUSED|ESOCKET)$/);
    expect(selfTestState(t.db)).toEqual({ lastRun: o, lastSuccess: before });
    expect(selfTestRows()).toBe(0);
  });

  it('records an SMTP refusal as its reply code only', async () => {
    const s = await foreignSmtp(550);
    const o = await runSelfTest(t.ctx, { port: s.port, timeoutMs: 5000 });
    await s.close();
    expect(o).toMatchObject({ ok: false, error: 'smtp_550' });
    expect(selfTestRows()).toBe(0);
  });

  it('fails with not_received when the message is accepted elsewhere and never arrives', async () => {
    const s = await foreignSmtp();
    const o = await runSelfTest(t.ctx, { port: s.port, timeoutMs: 1500 });
    await s.close();
    expect(o).toMatchObject({ ok: false, error: 'not_received' });
    expect(o.durationMs).toBeGreaterThanOrEqual(1400);
    expect(selfTestRows()).toBe(0);
  });

  it('removes rows left by an interrupted run before the next one', async () => {
    t.db.prepare('INSERT INTO mail_addresses(id, address, label, created_at, expires_at, owner_id) VALUES(?,?,?,?,?,NULL)').run('t-leftover9', 't-leftover9@x', SELFTEST_LABEL, Date.now(), Date.now() + 3600_000);
    expect(selfTestRows()).toBe(1);
    expect(cleanupSelfTest(t.db)).toBe(1);
    expect(selfTestRows()).toBe(0);
  });
});

describe('GET /api/health/reception', () => {
  const anon = (path: string) => fetch(t.base + path).then(async (r) => ({ status: r.status, json: await r.json(), text: '' }));

  it('is public, and says enabled:false when the self-test is not configured', async () => {
    config.selftest.smtpHost = '';
    try {
      const r = await anon('/api/health/reception');
      expect(r.status).toBe(200);
      expect(r.json).toEqual({ enabled: false });
    } finally {
      config.selftest.smtpHost = '127.0.0.1';
    }
  });

  it('answers 200 with ok:true while the last success is recent, with nothing personal in it', async () => {
    const o = await runSelfTest(t.ctx, { timeoutMs: 10_000 });
    expect(o.ok).toBe(true);
    const res = await fetch(t.base + '/api/health/reception');
    const text = await res.text();
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toMatch(/no-store/);
    const body = JSON.parse(text);
    expect(body).toEqual({
      enabled: true,
      ok: true,
      lastSuccess: o.at,
      lastRun: { at: o.at, ok: true, durationMs: o.durationMs },
      intervalHours: config.selftest.intervalHours,
      maxAgeMinutes: config.selftest.maxAgeMinutes,
    });
    // no host, port, domain or address
    expect(text).not.toMatch(/127\.0\.0\.1|t-[a-z0-9]{8}|@|localhost/);
    expect(text).not.toContain(String(smtp.port));
  });

  it('answers 503 once the last success is older than the threshold, or after failures only', async () => {
    const later = Date.now() + (config.selftest.maxAgeMinutes + 1) * 60_000;
    const stale = receptionHealth(t.db, config, later);
    expect(stale.status).toBe(503);
    expect(stale.body.ok).toBe(false);
    // a recent failure does not hide a recent success, the status follows the last success
    const gone = await foreignSmtp();
    await gone.close();
    await runSelfTest(t.ctx, { port: gone.port, timeoutMs: 3000 });
    const now = await anon('/api/health/reception');
    expect(now.status).toBe(200);
    expect(now.json.lastRun.ok).toBe(false);
    // never succeeded: 503
    t.db.prepare("DELETE FROM settings WHERE key = 'reception_selftest'").run();
    const never = await anon('/api/health/reception');
    expect(never.status).toBe(503);
    expect(never.json).toMatchObject({ enabled: true, ok: false, lastSuccess: null, lastRun: null });
  });

  it('the job runs shortly after start and logs only a status, a code and a duration', async () => {
    const logs: unknown[] = [];
    const log = { info: (o: object, m: string) => logs.push([o, m]), warn: (o: object, m: string) => logs.push([o, m]) };
    const job = startSelfTestJob(t.ctx, log, { firstDelayMs: 10, everyMs: 3_600_000 })!;
    for (let i = 0; i < 100 && !job.running(); i++) await new Promise((r) => setTimeout(r, 10));
    const o = await job.running();
    job.stop();
    expect(o?.ok).toBe(true);
    expect(logs).toEqual([[{ selftest: 'ok', ms: o!.durationMs }, 'reception self-test']]);
    expect(receptionHealth(t.db, config).status).toBe(200);
    config.selftest.smtpHost = '';
    expect(startSelfTestJob(t.ctx, log)).toBeUndefined();
    config.selftest.smtpHost = '127.0.0.1';
  });
});
