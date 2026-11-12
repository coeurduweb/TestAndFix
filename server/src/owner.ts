// Per-browser notebooks. The site sits behind ONE shared password, so the session cookie only
// proves the password was typed. Each browser also carries a random secret (cookie check_device);
// the server keeps only its sha256. A device belongs to an owner (a "notebook"); every personal row
// (results, mail addresses and messages, DMARC reports, shares) carries owner_id, and every route
// filters on the owner of the request.
//
// Decision of the owner (2026-11-11, do not reconsider): a random secret per browser in a cookie.
// NOT device fingerprinting, NOT the IP address. No accounts. Linking two browsers goes through a
// short single-use code (POST /api/me/link-code, POST /api/me/link).
import { t } from './i18n.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, randomBytes } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { config } from './config.js';
import type { DB } from './db.js';
import { now } from './lib/time.js';

export const DEVICE_COOKIE = 'check_device';
export const DEVICE_MAX_AGE_DAYS = 400;
/** last_seen_at is written at most once per hour. */
const SEEN_EVERY_MS = 3600 * 1000;
/** 32 random bytes in base64url. */
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export interface Owner {
  ownerId: string;
  deviceId: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    /** Notebook of this request: set only for requests carrying a valid session. */
    owner: Owner | null;
  }
}

interface Store {
  owner: Owner | null;
}

const als = new AsyncLocalStorage<Store>();

/** Owner of the request being served, also deep inside tool code (saveResult). Null outside a request. */
export function currentOwner(): Owner | null {
  return als.getStore()?.owner ?? null;
}

export function currentOwnerId(): string | null {
  return currentOwner()?.ownerId ?? null;
}

export function sha256(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

export function randomId(bytes = 9): string {
  return randomBytes(bytes).toString('base64url');
}

/** Short and generic: "Chrome sur Linux", "Safari sur iPhone". The User-Agent itself is never stored. */
export function deviceLabel(ua: string | undefined): string {
  const s = ua ?? '';
  const browser = /Edg(e|A|iOS)?\//.test(s)
    ? 'Edge'
    : /OPR\/|Opera/.test(s)
      ? 'Opera'
      : /Firefox\/|FxiOS\//.test(s)
        ? 'Firefox'
        : /SamsungBrowser\//.test(s)
          ? 'Samsung Internet'
          : /Chrome\/|CriOS\//.test(s)
            ? 'Chrome'
            : /Safari\//.test(s)
              ? 'Safari'
              : t('Navigateur');
  const os = /iPhone/.test(s)
    ? 'iPhone'
    : /iPad/.test(s)
      ? 'iPad'
      : /Android/.test(s)
        ? 'Android'
        : /Windows/.test(s)
          ? 'Windows'
          : /CrOS/.test(s)
            ? 'ChromeOS'
            : /Mac OS X|Macintosh/.test(s)
              ? 'macOS'
              : /Linux/.test(s)
                ? 'Linux'
                : '';
  return os ? t('{browser} sur {os}', { browser, os }) : browser;
}

export function deviceCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: config.publicUrl.startsWith('https://'),
    path: '/',
    maxAge: DEVICE_MAX_AGE_DAYS * 24 * 3600,
  };
}

export function setDeviceCookie(reply: FastifyReply, token: string) {
  reply.setCookie(DEVICE_COOKIE, token, deviceCookieOptions());
}

export function clearDeviceCookie(reply: FastifyReply) {
  const { maxAge: _m, ...opts } = deviceCookieOptions();
  void _m;
  reply.clearCookie(DEVICE_COOKIE, opts);
}

interface DeviceRow {
  id: string;
  owner_id: string;
  last_seen_at: number;
}

export function findDevice(db: DB, token: string | undefined): DeviceRow | undefined {
  if (!token || !TOKEN_RE.test(token)) return undefined;
  return db.prepare('SELECT id, owner_id, last_seen_at FROM devices WHERE token_hash = ?').get(sha256(token)) as DeviceRow | undefined;
}

/** A new empty notebook with this browser as its only device. Returns the secret for the cookie. */
export function createOwnerWithDevice(db: DB, ua: string | undefined): { owner: Owner; token: string } {
  const token = randomBytes(32).toString('base64url');
  const t = now();
  const owner: Owner = { ownerId: randomId(12), deviceId: randomId(9) };
  db.transaction(() => {
    db.prepare('INSERT INTO owners(id, created_at) VALUES(?, ?)').run(owner.ownerId, t);
    db.prepare('INSERT INTO devices(id, owner_id, token_hash, label, created_at, last_seen_at) VALUES(?,?,?,?,?,?)').run(
      owner.deviceId,
      owner.ownerId,
      sha256(token),
      deviceLabel(ua),
      t,
      t,
    );
  })();
  return { owner, token };
}

/** Owner of the device of the cookie, without creating anything; null when the cookie is missing or unknown. */
export function resolveDevice(db: DB, req: FastifyRequest): Owner | null {
  if (req.owner) return req.owner;
  const dev = findDevice(db, req.cookies?.[DEVICE_COOKIE]);
  if (!dev) return null;
  const t = now();
  if (t - dev.last_seen_at >= SEEN_EVERY_MS) db.prepare('UPDATE devices SET last_seen_at = ? WHERE id = ?').run(t, dev.id);
  return setOwner(req, { ownerId: dev.owner_id, deviceId: dev.id });
}

function setOwner(req: FastifyRequest, owner: Owner): Owner {
  req.owner = owner;
  const store = als.getStore();
  if (store) store.owner = owner;
  return owner;
}

/**
 * Owner of this request: the device of the cookie, or a new notebook (and the cookie) when the
 * cookie is missing or unknown. Only for a request that carries a valid session, and only on the
 * routes of DEVICE_CREATING_ROUTES and the login (2026-11-11 review: any other route creating a
 * notebook let one client create notebooks without limit).
 */
export function ensureDevice(db: DB, req: FastifyRequest, reply: FastifyReply): Owner {
  const found = resolveDevice(db, req);
  if (found) return found;
  const created = createOwnerWithDevice(db, req.headers['user-agent']);
  setDeviceCookie(reply, created.token);
  return setOwner(req, created.owner);
}

/**
 * Routes that may create a device (besides POST /api/auth/login): the web app calls
 * /api/auth/status at boot, before any other API call. Everywhere else a request without a known
 * device runs with owner null: it reads nothing, and what it writes is stored without notebook
 * (visible to nobody).
 */
export const DEVICE_CREATING_ROUTES = new Set(['GET /api/auth/status', 'GET /api/me']);

/**
 * Bind the owner of every request: `resolve` runs in onRequest; the owner is then on req.owner and
 * in the AsyncLocalStorage for the whole request (hooks, handler, and every promise or timer they
 * start), the Fastify way (as @fastify/request-context does). The store is entered again in
 * preValidation, after the body is read: a guard for body parsers that consume the stream outside
 * the context (none seen with Fastify 5 on Node 22, a 1 MB JSON body keeps it; kept defensive).
 */
export function bindOwner(app: FastifyInstance, resolve: (req: FastifyRequest, reply: FastifyReply) => Owner | null) {
  if (!app.hasRequestDecorator('owner')) app.decorateRequest('owner', null);
  app.addHook('onRequest', (req, reply, done) => {
    const store: Store = { owner: null };
    try {
      const o = resolve(req, reply);
      if (o) req.owner = o;
      store.owner = req.owner;
    } catch (e) {
      done(e as Error);
      return;
    }
    als.run(store, done);
  });
  app.addHook('preValidation', (req, _reply, done) => {
    als.run({ owner: req.owner }, done);
  });
}

/** Production binding: the device of the cookie for every request with a valid session; created only on a few routes. */
export function registerOwnerContext(app: FastifyInstance, db: DB, isAuthenticated: (req: FastifyRequest) => boolean) {
  bindOwner(app, (req, reply) => {
    if (!isAuthenticated(req)) return null;
    return DEVICE_CREATING_ROUTES.has(`${req.method} ${req.routeOptions?.url}`) ? ensureDevice(db, req, reply) : resolveDevice(db, req);
  });
}

// ---------------------------------------------------------------------------------------------
// Live streams of a device. A device removed from its notebook (deleted, linked away, erased) must
// not keep receiving that notebook's events through a stream opened before (2026-11-11 review).

const streams = new Map<string, Set<() => void>>();

/** Register the close function of a stream opened by this device; returns the unregister function. */
export function trackStream(deviceId: string, close: () => void): () => void {
  let set = streams.get(deviceId);
  if (!set) streams.set(deviceId, (set = new Set()));
  set.add(close);
  return () => {
    set.delete(close);
    if (!set.size && streams.get(deviceId) === set) streams.delete(deviceId);
  };
}

export function closeDeviceStreams(deviceIds: Iterable<string>) {
  for (const id of deviceIds) {
    const set = streams.get(id);
    if (!set) continue;
    streams.delete(id);
    for (const close of [...set]) {
      try {
        close();
      } catch {
        /* already closed */
      }
    }
  }
}

export function openStreamCount(deviceId: string): number {
  return streams.get(deviceId)?.size ?? 0;
}

/** Is this device still in this notebook? Checked again before each event of a live stream. */
export function deviceInNotebook(db: DB, deviceId: string, ownerId: string): boolean {
  return Boolean(db.prepare('SELECT 1 FROM devices WHERE id = ? AND owner_id = ?').get(deviceId, ownerId));
}

export function devicesOf(db: DB, ownerId: string): string[] {
  return (db.prepare('SELECT id FROM devices WHERE owner_id = ?').all(ownerId) as { id: string }[]).map((d) => d.id);
}

// ---------------------------------------------------------------------------------------------
// Data of one owner

export interface Counts {
  results: number;
  mailMessages: number;
  mailAddresses: number;
  dmarcReports: number;
}

export function countOwnerData(db: DB, ownerId: string): Counts {
  const n = (sql: string) => (db.prepare(sql).get(ownerId) as { n: number }).n;
  return {
    results: n('SELECT COUNT(*) AS n FROM results WHERE owner_id = ?'),
    mailMessages: n('SELECT COUNT(*) AS n FROM mail_messages WHERE owner_id = ?'),
    mailAddresses: n('SELECT COUNT(*) AS n FROM mail_addresses WHERE owner_id = ?'),
    dmarcReports: n('SELECT COUNT(*) AS n FROM dmarc_reports WHERE owner_id = ?'),
  };
}

/** Delete every row of the owner, keep the owner and its devices. Call inside a transaction. */
export function eraseOwnerData(db: DB, ownerId: string): Counts {
  db.prepare('DELETE FROM shares WHERE owner_id = ?').run(ownerId);
  db.prepare('DELETE FROM link_codes WHERE owner_id = ?').run(ownerId);
  // messages first, so the count is exact (the address FK would cascade them silently)
  const mailMessages = db.prepare('DELETE FROM mail_messages WHERE owner_id = ?').run(ownerId).changes;
  const mailAddresses = db.prepare('DELETE FROM mail_addresses WHERE owner_id = ?').run(ownerId).changes;
  const results = db.prepare('DELETE FROM results WHERE owner_id = ?').run(ownerId).changes;
  const dmarcReports = db.prepare('DELETE FROM dmarc_reports WHERE owner_id = ?').run(ownerId).changes;
  return { results, mailMessages, mailAddresses, dmarcReports };
}

/** Move every row of `from` to `to` (link of a browser whose notebook has no other device). */
export function moveOwnerData(db: DB, from: string, to: string): Counts {
  const results = db.prepare('UPDATE results SET owner_id = ? WHERE owner_id = ?').run(to, from).changes;
  const mailMessages = db.prepare('UPDATE mail_messages SET owner_id = ? WHERE owner_id = ?').run(to, from).changes;
  const mailAddresses = db.prepare('UPDATE mail_addresses SET owner_id = ? WHERE owner_id = ?').run(to, from).changes;
  // the same DMARC report already in the target notebook stays there once
  const dmarcReports = db.prepare('UPDATE OR IGNORE dmarc_reports SET owner_id = ? WHERE owner_id = ?').run(to, from).changes;
  db.prepare('DELETE FROM dmarc_reports WHERE owner_id = ?').run(from);
  db.prepare('UPDATE shares SET owner_id = ? WHERE owner_id = ?').run(to, from);
  db.prepare('DELETE FROM link_codes WHERE owner_id = ?').run(from);
  return { results, mailMessages, mailAddresses, dmarcReports };
}

/**
 * A device leaves a notebook that goes on existing (deleted, or linked to another notebook): every
 * link code of the notebook goes (one prepared by the leaving device would let it come back), and
 * so do the share links this device created. Call inside a transaction.
 */
export function revokeDeviceGrants(db: DB, deviceId: string, ownerId: string) {
  db.prepare('DELETE FROM link_codes WHERE owner_id = ?').run(ownerId);
  db.prepare('DELETE FROM shares WHERE owner_id = ? AND created_by_device = ?').run(ownerId, deviceId);
}

/** Erase the data of the owner, then the owner and its devices. Call inside a transaction. */
export function deleteOwner(db: DB, ownerId: string): Counts {
  const erased = eraseOwnerData(db, ownerId);
  db.prepare('DELETE FROM devices WHERE owner_id = ?').run(ownerId);
  db.prepare('DELETE FROM owners WHERE id = ?').run(ownerId);
  return erased;
}
