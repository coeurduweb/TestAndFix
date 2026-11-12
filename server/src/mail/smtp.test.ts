// End to end: test address through the API, message sent over SMTP with STARTTLS, report in the
// database, events on the SSE stream, raw source, re-analysis, history, comparison, import.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import nodemailer from 'nodemailer';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app.js';
import { openDb, setDb } from '../db.js';
import { COOKIE, makeToken } from '../auth.js';
import { configureMailService, mailService, tool } from '../tools/mail/index.js';
import { startSmtp, type SmtpHandle } from './smtp.js';
import { fakeResolver, fixture, goodZone, rsaKey, sign } from './test-helpers.js';
import type { ToolContext } from '../tools/types.js';

const key = rsaKey();
let app: FastifyInstance;
let ctx: ToolContext;
let smtp: SmtpHandle;
let base: string;
let cookie: string;

beforeAll(async () => {
  const db = openDb(':memory:');
  setDb(db); // the session secret is stored in this database, not in data/
  configureMailService({ spamd: false, fetcher: false, dnsbl: false, resolver: () => fakeResolver(goodZone(key.record)) });
  ({ app, ctx } = await buildApp({ db, tools: [tool] }));
  await app.listen({ host: '127.0.0.1', port: 0 });
  const addr = app.server.address() as { port: number };
  base = `http://127.0.0.1:${addr.port}`;
  cookie = `${COOKIE}=${makeToken()}`;
  // one notebook for the whole file: the device cookie set on the first request is kept
  const first = await fetch(`${base}/api/auth/status`, { headers: { cookie } });
  const device = /check_device=([^;]+)/.exec(first.headers.get('set-cookie') ?? '')?.[1];
  cookie += `; check_device=${device}`;
  smtp = await startSmtp(ctx, mailService(ctx), { host: '127.0.0.1', port: 0 });
});

afterAll(async () => {
  await smtp?.close();
  await app?.close();
});

const api = async (path: string, init: RequestInit = {}) => {
  const res = await fetch(base + path, { ...init, headers: { cookie, ...(init.body && typeof init.body === 'string' ? { 'content-type': 'application/json' } : {}), ...init.headers } });
  const text = await res.text();
  let json: any;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { status: res.status, json, text, headers: res.headers };
};

/** Read SSE events from a stream until `until` returns true. */
async function sse(path: string, until: (events: { event: string; data: any }[]) => boolean, timeoutMs = 15000) {
  const ac = new AbortController();
  const res = await fetch(base + path, { headers: { cookie, accept: 'text/event-stream' }, signal: ac.signal });
  expect(res.headers.get('content-type')).toMatch(/text\/event-stream/);
  const events: { event: string; data: any }[] = [];
  const reader = res.body!.getReader();
  const dec = new TextDecoder();
  let buf = '';
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  const ready = { opened: Promise.resolve() };
  const done = (async () => {
    try {
      for (;;) {
        const { value, done: end } = await reader.read();
        if (end) break;
        buf += dec.decode(value, { stream: true });
        let i: number;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const chunk = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const ev = /^event: (.*)$/m.exec(chunk)?.[1];
          const data = /^data: (.*)$/m.exec(chunk)?.[1];
          if (ev && data) events.push({ event: ev, data: JSON.parse(data) });
          if (until(events)) {
            ac.abort();
            return events;
          }
        }
      }
    } catch {
      /* aborted */
    } finally {
      clearTimeout(timer);
    }
    return events;
  })();
  return { ready, done };
}

describe('mail test over SMTP', () => {
  it('refuses unauthenticated requests', async () => {
    const res = await fetch(base + '/api/mail/addresses', { method: 'POST' });
    expect(res.status).toBe(401);
  });

  it('receives a message, analyses it and streams the report', async () => {
    const created = await api('/api/mail/addresses', { method: 'POST', body: JSON.stringify({ label: 'essai' }) });
    expect(created.status).toBe(201);
    const { id, address } = created.json;
    expect(id).toMatch(/^t-[a-z0-9]{8}$/);
    expect(address).toBe(`${id}@${ctx.config.mail.domain}`);

    const stream = await sse(`/api/mail/addresses/${id}/events`, (evs) => evs.some((e) => e.event === 'report'));
    await new Promise((r) => setTimeout(r, 100));

    const raw = fixture('clean.eml').toString('latin1').replace(/t-abcd2345@check\.localhost/g, address);
    const signed = await sign(Buffer.from(raw, 'latin1'), 'atelier-exemple.fr', 's1', key.privateKey);
    const transport = nodemailer.createTransport({ host: '127.0.0.1', port: smtp.port, secure: false, requireTLS: true, tls: { rejectUnauthorized: false }, name: 'mail.atelier-exemple.fr' });
    const info = await transport.sendMail({ envelope: { from: 'bounce@atelier-exemple.fr', to: [address] }, raw: signed });
    expect(info.accepted).toEqual([address]);

    const events = await stream.done;
    const names = events.map((e) => e.event);
    expect(names[0]).toBe('state');
    expect(names).toContain('message');
    expect(names.filter((n) => n === 'progress').length).toBeGreaterThan(4);
    expect(names.indexOf('message')).toBeLessThan(names.indexOf('report'));
    const steps = events.filter((e) => e.event === 'progress').map((e) => e.data.step);
    expect(steps).toEqual(expect.arrayContaining(['auth', 'infrastructure', 'spamassassin', 'blacklists', 'compliance']));
    const report = events.find((e) => e.event === 'report')!.data.report;
    expect(report.tool).toBe('mail');
    expect(report.data.envelope).toMatchObject({ clientIp: '127.0.0.1', ipSource: 'smtp', helo: 'mail.atelier-exemple.fr', mailFrom: 'bounce@atelier-exemple.fr' });
    expect(report.data.envelope.tls.used).toBe(true);
    expect(report.data.envelope.tls.protocol).toMatch(/^TLSv1\.[23]$/);
    // the DKIM signature survives our Received / Return-Path
    expect(report.data.auth.dkim[0].result).toBe('pass');

    const got = await api(`/api/mail/addresses/${id}`);
    expect(got.json.messages).toHaveLength(1);
    const msg = got.json.messages[0];
    expect(msg).toMatchObject({ status: 'done', via: 'smtp', from: 'contact@atelier-exemple.fr', subject: 'Votre devis pour la terrasse', helo: 'mail.atelier-exemple.fr' });
    expect(msg.tls.protocol).toMatch(/^TLSv1/);
    expect(msg).not.toHaveProperty('raw');

    const full = await api(`/api/mail/messages/${msg.id}`);
    expect(full.json.report.score).toBe(report.score);

    const eml = await api(`/api/mail/messages/${msg.id}/raw`);
    expect(eml.headers.get('content-type')).toMatch(/message\/rfc822/);
    expect(eml.text.startsWith('Return-Path: <bounce@atelier-exemple.fr>\r\nReceived: from mail.atelier-exemple.fr')).toBe(true);
    expect(eml.text).toContain('Votre devis pour la terrasse');

    // a second message on the same address is a second test (US-039)
    await transport.sendMail({ envelope: { from: 'bounce@atelier-exemple.fr', to: [address] }, raw: fixture('no-message-id.eml').toString('latin1').replace(/t-abcd2345@check\.localhost/g, address) });
    for (let i = 0; i < 50; i++) {
      const l = await api(`/api/mail/addresses/${id}`);
      if (l.json.messages.length === 2 && l.json.messages.every((m: { status: string }) => m.status === 'done')) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const both = (await api(`/api/mail/addresses/${id}`)).json.messages;
    expect(both).toHaveLength(2);
    const [second, first] = both;

    const re = await api(`/api/mail/messages/${first.id}/reanalyze`, { method: 'POST' });
    expect(re.json.report.data.previous.score).toBe(report.score);

    const cmp = await api(`/api/mail/compare?a=${first.id}&b=${second.id}`);
    expect(cmp.json.sameSender).toBe(true);
    expect(cmp.json.added.map((f: { id: string }) => f.id)).toContain('headers.message_id_missing');

    const hist = await api('/api/mail/history?domain=atelier-exemple.fr');
    expect(hist.json.total).toBe(2);
    expect((await api('/api/mail/history?q=terrasse')).json.items.map((m: { id: string }) => m.id)).toEqual([first.id]);
    transport.close();
  });

  it('refuses unknown or expired addresses and relaying (550)', async () => {
    const transport = nodemailer.createTransport({ host: '127.0.0.1', port: smtp.port, secure: false, ignoreTLS: true });
    await expect(transport.sendMail({ envelope: { from: 'a@atelier-exemple.fr', to: [`t-zzzzzzzz@${ctx.config.mail.domain}`] }, raw: fixture('no-message-id.eml') })).rejects.toMatchObject({ responseCode: 550 });
    await expect(transport.sendMail({ envelope: { from: 'a@atelier-exemple.fr', to: ['quelquun@gmail.com'] }, raw: fixture('no-message-id.eml') })).rejects.toMatchObject({ responseCode: 550 });
    const created = await api('/api/mail/addresses', { method: 'POST', body: '{}' });
    ctx.db.prepare('UPDATE mail_addresses SET expires_at = 1 WHERE id = ?').run(created.json.id);
    await expect(transport.sendMail({ envelope: { from: 'a@atelier-exemple.fr', to: [created.json.address] }, raw: fixture('no-message-id.eml') })).rejects.toMatchObject({ responseCode: 550 });
    // plain-text session is accepted and recorded as such
    const ok = await api('/api/mail/addresses', { method: 'POST', body: '{}' });
    await transport.sendMail({ envelope: { from: 'a@atelier-exemple.fr', to: [ok.json.address] }, raw: fixture('no-message-id.eml') });
    let plain: any;
    for (let i = 0; i < 50 && !plain; i++) {
      const m = (await api(`/api/mail/addresses/${ok.json.id}`)).json.messages[0];
      if (m?.status === 'done') plain = (await api(`/api/mail/messages/${m.id}`)).json.report;
      else await new Promise((r) => setTimeout(r, 100));
    }
    expect(plain.findings.map((f: { id: string }) => f.id)).toContain('tls.inbound_plaintext');
    expect(plain.data.envelope.tls.used).toBe(false);
    transport.close();
  });
});

describe('import of a message', () => {
  it('analyses a pasted message and a multipart .eml upload', async () => {
    const pasted = fixture('via-mailbox.eml').toString('latin1').replace(/\r\n/g, '\n');
    const r1 = await api('/api/mail/analyze', { method: 'POST', body: pasted, headers: { 'content-type': 'text/plain' } });
    expect(r1.status).toBe(200);
    expect(r1.json.message.via).toBe('upload');
    expect(r1.json.report.data.envelope).toMatchObject({ clientIp: '93.184.215.14', ipSource: 'received' });

    const form = new FormData();
    form.append('file', new Blob([fixture('attachment-exe.eml')], { type: 'message/rfc822' }), 'facture.eml');
    const r2 = await fetch(base + '/api/mail/analyze', { method: 'POST', body: form, headers: { cookie } });
    const j2 = await r2.json();
    expect(r2.status).toBe(200);
    expect(j2.report.findings.map((f: { id: string }) => f.id)).toContain('attachments.dangerous_extension');

    const bad = await api('/api/mail/analyze', { method: 'POST', body: 'bonjour', headers: { 'content-type': 'text/plain' } });
    expect(bad.status).toBe(400);
  });

  it('reports the receivers status', async () => {
    const s = await api('/api/mail/status');
    expect(s.json).toMatchObject({ domain: ctx.config.mail.domain, imap: { enabled: false } });
  });
});
