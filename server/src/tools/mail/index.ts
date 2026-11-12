// Mail test tool: test addresses, SMTP and IMAP reception, import of a message, live events,
// reports, raw source, re-analysis, history and comparison.
// Every route filters on the notebook of the request (owner.ts): a message or an address of another
// notebook answers exactly like a missing one. Read-only share links (/api/shared/:token) are the
// only way to show a report outside its notebook.
import { t } from '../../i18n.js';
import { randomBytes } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { DB } from '../../db.js';
import { now } from '../../lib/time.js';
import { deviceInNotebook, randomId, sha256, trackStream } from '../../owner.js';
import type { ServerTool, ToolContext } from '../types.js';
import { openSse } from '../../lib/sse.js';
import { MailService, summary, type MailServiceOptions } from '../../mail/service.js';
import { startSmtp, type SmtpHandle } from '../../mail/smtp.js';
import { ImapReceiver } from '../../mail/imap.js';
import { mailBus, type MailEvent } from '../../mail/events.js';
import { spamdPing } from '../../mail/spamd.js';
import { receptionHealth, SELFTEST_LABEL } from '../../mail/selftest.js';
import type { MailReport } from '../../mail/analyze/index.js';
import { stepLabels } from '../../mail/analyze/index.js';
import {
  createAddress,
  ensureUploadAddress,
  getMessage,
  getOwnedAddress,
  getOwnedMessage,
  history,
  listOwnedMessages,
  UPLOAD_ADDRESS_ID,
  type AddressRow,
  type MessageRow,
} from '../../mail/store.js';

let service: MailService | undefined;
let serviceOptions: MailServiceOptions = {};
let smtp: SmtpHandle | undefined;
let imap: ImapReceiver | undefined;

/** Options of the analysis service (tests: fake spamd, no link visits…). Call before start. */
export function configureMailService(opts: MailServiceOptions) {
  serviceOptions = opts;
  if (service) service.opts = opts;
}

export function mailService(ctx: ToolContext): MailService {
  if (!service) service = new MailService(ctx, serviceOptions);
  return service;
}

export function smtpHandle() {
  return smtp;
}

function addressJson(a: AddressRow, at = Date.now()) {
  return {
    id: a.id,
    address: a.address,
    // the shared pseudo-address of imported messages is named in the reader's language
    label: a.id === 'upload' ? t('Messages importés') : a.label,
    createdAt: new Date(a.created_at).toISOString(),
    expiresAt: new Date(a.expires_at).toISOString(),
    expired: a.expires_at <= at,
  };
}

function reportOf(raw: string | null): MailReport | { error: string } | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/** Plain text pasted from a mail client often has LF line ends: SMTP wants CRLF. */
function normaliseEol(buf: Buffer): Buffer {
  if (buf.includes('\r\n')) return buf;
  return Buffer.from(buf.toString('latin1').replace(/\n/g, '\r\n'), 'latin1');
}

async function readUpload(req: FastifyRequest): Promise<Buffer | undefined> {
  if (req.isMultipart()) {
    for await (const part of req.parts()) {
      if (part.type === 'file') return part.toBuffer();
      if (part.type === 'field' && (part.fieldname === 'raw' || part.fieldname === 'text') && typeof part.value === 'string') return Buffer.from(part.value, 'utf8');
    }
    return undefined;
  }
  const body = req.body as unknown;
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  if (body && typeof body === 'object' && typeof (body as { raw?: unknown }).raw === 'string') return Buffer.from((body as { raw: string }).raw, 'utf8');
  return undefined;
}

function diffReports(a: MailReport, b: MailReport) {
  const fa = new Map(a.findings.map((f) => [f.id, f]));
  const fb = new Map(b.findings.map((f) => [f.id, f]));
  const pa = new Set(a.passed.map((p) => p.id));
  const pb = new Set(b.passed.map((p) => p.id));
  const brief = (f: MailReport['findings'][number]) => ({ id: f.id, title: f.title, severity: f.severity, penalty: f.penalty, family: f.family });
  return {
    scoreDelta: Math.round(((b.score ?? 0) - (a.score ?? 0)) * 10) / 10,
    /** anomalies present in b only (new problems) */
    added: [...fb.values()].filter((f) => !fa.has(f.id)).map(brief),
    /** anomalies of a gone in b (fixed) */
    removed: [...fa.values()].filter((f) => !fb.has(f.id)).map(brief),
    changed: [...fb.values()]
      .filter((f) => fa.has(f.id) && (fa.get(f.id)!.penalty !== f.penalty || fa.get(f.id)!.severity !== f.severity))
      .map((f) => ({ id: f.id, title: f.title, before: { penalty: fa.get(f.id)!.penalty, severity: fa.get(f.id)!.severity }, after: { penalty: f.penalty, severity: f.severity } })),
    unchanged: [...fb.keys()].filter((id) => fa.has(id)),
    passedAdded: [...pb].filter((id) => !pa.has(id)),
    passedRemoved: [...pa].filter((id) => !pb.has(id)),
  };
}

const SHARE_KIND = 'mail-message';

interface ShareRow {
  id: string;
  token: string;
  owner_id: string;
  target_id: string;
}

const shareJson = (s: ShareRow) => ({ token: s.token, path: `/partage/${s.token}` });

function shareOf(db: DB, messageId: string, ownerId: string): ShareRow | undefined {
  return db.prepare('SELECT id, token, owner_id, target_id FROM shares WHERE kind = ? AND target_id = ? AND owner_id = ?').get(SHARE_KIND, messageId, ownerId) as
    | ShareRow
    | undefined;
}

/** The message behind a share token, whatever its notebook; undefined when missing or revoked. */
function sharedMessage(db: DB, token: string): MessageRow | undefined {
  if (!/^[A-Za-z0-9_-]{32}$/.test(token)) return undefined;
  const s = db.prepare('SELECT target_id, owner_id FROM shares WHERE token_hash = ? AND kind = ?').get(sha256(token), SHARE_KIND) as
    | { target_id: string; owner_id: string }
    | undefined;
  return s ? getOwnedMessage(db, s.target_id, s.owner_id) : undefined;
}

/**
 * Replace the local part of a test address ("t-7k2m9q4x") by "t-00000000": same length, and never a
 * real address (ids are drawn without 0). The upload pseudo-address receives nothing: left as is.
 */
export function maskAddress(text: string, addressId: string): string {
  if (!/^t-[a-z0-9]+$/.test(addressId)) return text;
  return text.replace(new RegExp(addressId, 'gi'), 't-' + '0'.repeat(addressId.length - 2));
}

function sendRaw(reply: FastifyReply, m: MessageRow) {
  reply.header('Content-Type', 'message/rfc822');
  reply.header('Content-Disposition', `attachment; filename="${m.id}.eml"`);
  return reply.send(Buffer.from(m.raw));
}

function register(app: FastifyInstance, ctx: ToolContext) {
  const svc = mailService(ctx);
  const db = ctx.db;
  const ownerOf = (req: FastifyRequest) => req.owner?.ownerId ?? null;

  // the raw source of a message, pasted as text/plain or posted as message/rfc822
  app.removeContentTypeParser('text/plain');
  app.addContentTypeParser(['text/plain', 'message/rfc822', 'application/octet-stream'], { parseAs: 'buffer', bodyLimit: 30 * 1024 * 1024 }, (_req, body, done) => done(null, body));

  app.post<{ Body: { label?: string } | undefined }>('/api/mail/addresses', async (req, reply) => {
    const asked = typeof req.body === 'object' && req.body ? req.body.label : undefined;
    // the self-test label is reserved: a visitor's address never passes for the self-test one
    const label = asked === SELFTEST_LABEL ? undefined : asked;
    const a = createAddress(db, ctx.config.mail.domain, ctx.config.mail.addressTtlHours, label, ownerOf(req));
    return reply.code(201).send({ ...addressJson(a), ttlHours: ctx.config.mail.addressTtlHours });
  });

  app.get<{ Params: { id: string } }>('/api/mail/addresses/:id', async (req, reply) => {
    const owner = ownerOf(req);
    const a = getOwnedAddress(db, req.params.id, owner);
    if (!a) return reply.code(404).send({ error: 'address_not_found' });
    return { ...addressJson(a), messages: listOwnedMessages(db, a.id, owner).map(summary) };
  });

  app.get<{ Params: { id: string } }>('/api/mail/addresses/:id/events', async (req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    const owner = ownerOf(req);
    // refused before the stream opens, with the same answer as a missing address
    const a = getOwnedAddress(db, req.params.id, owner);
    if (!a) return reply.code(404).send({ error: 'address_not_found' });
    const device = req.owner?.deviceId;
    const sse = openSse(req, reply);
    sse.send('state', { address: addressJson(a), messages: listOwnedMessages(db, a.id, owner).map(summary), steps: stepLabels() });
    // closed as soon as this device leaves the notebook (deleted, linked away, erased): owner.ts
    const untrack = device ? trackStream(device, () => sse.close()) : () => {};
    const onEvent = (ev: MailEvent) => {
      // the 'upload' pseudo-address is shared: only this notebook's messages are forwarded
      if (owner === null || !device || ev.ownerId !== owner) return;
      // checked again before each event: the device may have left the notebook since the stream opened
      if (!deviceInNotebook(db, device, owner)) {
        sse.close();
        return;
      }
      sse.send(ev.type, { messageId: ev.messageId, ...(ev.type === 'message' || ev.type === 'report' ? { [ev.type]: ev.data } : ev.data) });
    };
    mailBus.on(`address:${a.id}`, onEvent);
    sse.signal.addEventListener('abort', () => {
      mailBus.off(`address:${a.id}`, onEvent);
      untrack();
    });
  });

  app.post('/api/mail/analyze', async (req, reply) => {
    let raw: Buffer | undefined;
    try {
      raw = await readUpload(req);
    } catch (e) {
      return reply.code(400).send({ error: 'invalid_upload', detail: (e as Error).message });
    }
    if (!raw || !raw.toString('latin1').trim()) return reply.code(400).send({ error: 'empty_message' });
    raw = normaliseEol(raw);
    if (!/^[\x21-\x39\x3b-\x7e]+:/m.test(raw.subarray(0, 4096).toString('latin1')))
      return reply.code(400).send({ error: 'not_a_message', detail: t("Aucun en-tête reconnu : collez le source complet du message (« Afficher l'original »).") });
    const addressId = ensureUploadAddress(db, ctx.config.mail.domain);
    const { id, done } = svc.ingest({ via: 'upload', addressId, raw, ownerId: ownerOf(req) });
    const report = await done;
    const row = getMessage(db, id)!;
    return { messageId: id, message: summary(row), report: report ?? reportOf(row.report) };
  });

  app.get<{ Params: { id: string } }>('/api/mail/messages/:id', async (req, reply) => {
    const owner = ownerOf(req);
    const m = getOwnedMessage(db, req.params.id, owner);
    if (!m) return reply.code(404).send({ error: 'message_not_found' });
    const s = shareOf(db, m.id, owner!);
    return { message: summary(m), report: reportOf(m.report), share: s ? shareJson(s) : null };
  });

  app.get<{ Params: { id: string } }>('/api/mail/messages/:id/raw', async (req, reply) => {
    const m = getOwnedMessage(db, req.params.id, ownerOf(req));
    if (!m) return reply.code(404).send({ error: 'message_not_found' });
    return sendRaw(reply, m);
  });

  // read-only link to one report: one active link per message, the same one is returned again
  app.post<{ Params: { id: string } }>('/api/mail/messages/:id/share', async (req, reply) => {
    const owner = ownerOf(req);
    const m = getOwnedMessage(db, req.params.id, owner);
    if (!m) return reply.code(404).send({ error: 'message_not_found' });
    const existing = shareOf(db, m.id, owner!);
    if (existing) return shareJson(existing);
    const token = randomBytes(24).toString('base64url');
    const row: ShareRow = { id: randomId(), token, owner_id: owner!, target_id: m.id };
    // the creating device is kept: its links are revoked when it leaves the notebook
    db.prepare('INSERT INTO shares(id, token_hash, token, owner_id, kind, target_id, created_at, created_by_device) VALUES(?,?,?,?,?,?,?,?)').run(
      row.id,
      sha256(token),
      token,
      owner,
      SHARE_KIND,
      m.id,
      now(),
      req.owner?.deviceId ?? null,
    );
    return shareJson(row);
  });

  // the share state alone, without the whole report
  app.get<{ Params: { id: string } }>('/api/mail/messages/:id/share', async (req, reply) => {
    const owner = ownerOf(req);
    const m = getOwnedMessage(db, req.params.id, owner);
    if (!m) return reply.code(404).send({ error: 'message_not_found' });
    const s = shareOf(db, m.id, owner!);
    return { share: s ? shareJson(s) : null };
  });

  app.delete<{ Params: { id: string } }>('/api/mail/messages/:id/share', async (req, reply) => {
    const owner = ownerOf(req);
    const m = getOwnedMessage(db, req.params.id, owner);
    if (!m) return reply.code(404).send({ error: 'message_not_found' });
    db.prepare('DELETE FROM shares WHERE kind = ? AND target_id = ? AND owner_id = ?').run(SHARE_KIND, m.id, owner);
    return reply.code(204).send();
  });

  // a shared report: same shape as /api/mail/messages/:id without `share`, `message.addressId` and
  // `message.rcptTo`, and with the test address masked everywhere (report and raw source): the
  // reader must not learn an address that still delivers into the owner's notebook. Still behind the password.
  app.get<{ Params: { token: string } }>('/api/shared/:token', async (req, reply) => {
    const m = sharedMessage(db, req.params.token);
    if (!m) return reply.code(404).send({ error: 'not_found' });
    const { addressId: _a, rcptTo: _r, ...message } = summary(m);
    void _a;
    void _r;
    reply.type('application/json; charset=utf-8');
    return reply.send(maskAddress(JSON.stringify({ message, report: reportOf(m.report) }), m.address_id));
  });

  app.get<{ Params: { token: string } }>('/api/shared/:token/raw', async (req, reply) => {
    const m = sharedMessage(db, req.params.token);
    if (!m) return reply.code(404).send({ error: 'not_found' });
    const raw = Buffer.from(maskAddress(Buffer.from(m.raw).toString('latin1'), m.address_id), 'latin1');
    return sendRaw(reply, { ...m, raw });
  });

  app.post<{ Params: { id: string } }>('/api/mail/messages/:id/reanalyze', async (req, reply) => {
    const m = getOwnedMessage(db, req.params.id, ownerOf(req));
    if (!m) return reply.code(404).send({ error: 'message_not_found' });
    const report = await svc.analyze(m.id);
    const row = getMessage(db, m.id)!;
    return { messageId: m.id, message: summary(row), report: report ?? reportOf(row.report) };
  });

  app.get<{ Querystring: { domain?: string; q?: string; from?: string; to?: string; limit?: string; offset?: string } }>('/api/mail/history', async (req) => {
    const q = req.query;
    const ts = (v?: string) => (v ? (/^\d+$/.test(v) ? Number(v) : Date.parse(v)) || undefined : undefined);
    const { items, total } = history(db, {
      ownerId: ownerOf(req),
      domain: q.domain?.trim() || undefined,
      q: q.q?.trim() || undefined,
      from: ts(q.from),
      to: ts(q.to),
      limit: q.limit ? Number(q.limit) : undefined,
      offset: q.offset ? Number(q.offset) : undefined,
    });
    return { total, items: items.map(summary) };
  });

  app.get<{ Querystring: { a?: string; b?: string } }>('/api/mail/compare', async (req, reply) => {
    const { a, b } = req.query;
    if (!a || !b) return reply.code(400).send({ error: 'a_and_b_required' });
    const owner = ownerOf(req);
    const ma = getOwnedMessage(db, a, owner);
    const mb = getOwnedMessage(db, b, owner);
    if (!ma || !mb) return reply.code(404).send({ error: 'message_not_found' });
    const ra = reportOf(ma.report);
    const rb = reportOf(mb.report);
    if (!ra || !rb || 'error' in ra || 'error' in rb) return reply.code(409).send({ error: 'report_not_ready' });
    const head = (m: typeof ma, r: MailReport) => ({ ...summary(m), score: r.score ?? null, measuredAt: r.measuredAt });
    return {
      a: head(ma, ra),
      b: head(mb, rb),
      sameSender: !!ma.from_domain && ma.from_domain === mb.from_domain,
      ...diffReports(ra, rb),
    };
  });

  app.get('/api/mail/status', async () => ({
    domain: ctx.config.mail.domain,
    addressTtlHours: ctx.config.mail.addressTtlHours,
    smtp: smtp ? { listening: true, host: smtp.host, port: smtp.port, tls: smtp.tls } : { listening: false },
    imap: imap ? imap.status : { enabled: false, connected: false, processed: 0, skipped: 0 },
    spamd: { host: ctx.config.spamd.host, port: ctx.config.spamd.port, reachable: await spamdPing({ host: ctx.config.spamd.host, port: ctx.config.spamd.port, timeoutMs: 2000 }) },
  }));
}

export const tool: ServerTool = {
  id: 'mail',
  register,
  // public on purpose, for an external monitor: times, durations and short codes only (selftest.ts)
  registerPublic(app, ctx) {
    app.get('/api/health/reception', async (_req, reply) => {
      const { status, body } = receptionHealth(ctx.db, ctx.config);
      return reply.code(status).send(body);
    });
  },
  async start(ctx) {
    const svc = mailService(ctx);
    ensureUploadAddress(ctx.db, ctx.config.mail.domain);
    smtp = await startSmtp(ctx, svc);
    if (ctx.config.imap.host) {
      imap = new ImapReceiver(ctx, svc);
      imap.start();
    }
  },
  async stop() {
    await smtp?.close();
    smtp = undefined;
    await imap?.stop();
    imap = undefined;
  },
};

export { UPLOAD_ADDRESS_ID };
