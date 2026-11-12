// Routes of the notebook of this browser (owner.ts): what it holds, its devices, linking another
// browser with a short code, deleting a device, erasing. All behind the password.
import { randomInt } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { config } from './config.js';
import type { DB } from './db.js';
import { now } from './lib/time.js';
import {
  clearDeviceCookie,
  closeDeviceStreams,
  countOwnerData,
  deleteOwner,
  DEVICE_COOKIE,
  eraseOwnerData,
  findDevice,
  devicesOf,
  moveOwnerData,
  revokeDeviceGrants,
  setDeviceCookie,
  sha256,
  type Counts,
} from './owner.js';

/** No 0/O/1/I/L: the code is read on one screen and typed on another. */
export const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
export const CODE_TTL_MS = 5 * 60 * 1000;

const iso = (t: number | null | undefined) => (t ? new Date(t).toISOString() : null);

export function newLinkCode(): string {
  let s = '';
  for (let i = 0; i < 8; i++) s += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return s;
}

/** "abcd-efgh ", "ABCDEFGH" → "ABCDEFGH"; anything else → undefined. */
export function normaliseCode(input: unknown): string | undefined {
  if (typeof input !== 'string') return undefined;
  const s = input.trim().toUpperCase().replace(/[-\s]/g, '');
  return s.length === 8 && [...s].every((c) => CODE_ALPHABET.includes(c)) ? s : undefined;
}

// Failed link attempts (wrong, expired, used or own code), sliding one-minute window, per IP and for
// the whole server. A success does NOT reset the counter (2026-11-11 review: a success between
// guesses gave unlimited guesses). req.ip is the address nginx saw (trustProxy: 1 in app.ts).
export const MAX_FAILED_PER_IP = 5;
export const MAX_FAILED_GLOBAL = 60;
const MAX_TRACKED_IPS = 10_000;
const WINDOW_MS = 60_000;
const failedByIp = new Map<string, number[]>();
let failedAll: number[] = [];

export function resetLinkAttempts() {
  failedByIp.clear();
  failedAll = [];
}

/** Seconds to wait, or 0 when an attempt is allowed. */
function linkRetryAfter(ip: string, t: number): number {
  failedAll = failedAll.filter((x) => t - x < WINDOW_MS);
  const mine = (failedByIp.get(ip) ?? []).filter((x) => t - x < WINDOW_MS);
  if (mine.length) failedByIp.set(ip, mine);
  else failedByIp.delete(ip);
  const wait = (oldest: number) => Math.max(1, Math.ceil((WINDOW_MS - (t - oldest)) / 1000));
  if (mine.length >= MAX_FAILED_PER_IP) return wait(mine[mine.length - MAX_FAILED_PER_IP]);
  if (failedAll.length >= MAX_FAILED_GLOBAL) return wait(failedAll[failedAll.length - MAX_FAILED_GLOBAL]);
  return 0;
}

function recordFailure(ip: string, t: number) {
  failedAll.push(t);
  const mine = failedByIp.get(ip) ?? [];
  mine.push(t);
  failedByIp.delete(ip); // re-inserted last: Map order is then the order of the last failure
  failedByIp.set(ip, mine);
  // bounded: the entries whose last failure is the oldest go first (the global cap still applies)
  for (const k of failedByIp.keys()) {
    if (failedByIp.size <= MAX_TRACKED_IPS) break;
    failedByIp.delete(k);
  }
}

export function trackedLinkIps() {
  return failedByIp.size;
}

/**
 * The notebook a code points to, after the attempt limits; sends the error itself otherwise.
 * Unknown, expired, already used, or a code of this very notebook: one single answer.
 */
function targetOfCode(db: DB, req: FastifyRequest<{ Body: { code?: unknown } | undefined }>, reply: FastifyReply): { target: string; code: string } | undefined {
  const owner = req.owner!;
  const ip = req.ip;
  const t = now();
  const retryAfter = linkRetryAfter(ip, t);
  if (retryAfter) {
    reply.code(429).send({ error: 'too_many_attempts', retryAfter });
    return undefined;
  }
  const code = normaliseCode(req.body && typeof req.body === 'object' ? req.body.code : undefined);
  const row = code
    ? (db.prepare('SELECT owner_id, expires_at FROM link_codes WHERE code_hash = ?').get(sha256(code)) as { owner_id: string; expires_at: number } | undefined)
    : undefined;
  if (!code || !row || row.expires_at <= t || row.owner_id === owner.ownerId) {
    recordFailure(ip, t);
    reply.code(400).send({ error: 'invalid_or_expired_code' });
    return undefined;
  }
  return { target: row.owner_id, code };
}

const hasData = (c: Counts) => c.results + c.mailMessages + c.mailAddresses + c.dmarcReports > 0;

const ZERO: Counts = { results: 0, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 };

export function registerMe(app: FastifyInstance, db: DB) {
  // a request whose browser has no known device (only GET /api/me creates one) has no notebook to act on
  app.addHook('preHandler', async (req, reply) => {
    if (!req.owner && !(req.method === 'GET' && req.routeOptions.url === '/api/me')) return reply.code(409).send({ error: 'device_required' });
  });

  app.get('/api/me', async (req, reply) => {
    const owner = req.owner!;
    const devices = db
      .prepare('SELECT id, label, created_at, last_seen_at FROM devices WHERE owner_id = ? ORDER BY created_at')
      .all(owner.ownerId) as { id: string; label: string | null; created_at: number; last_seen_at: number }[];
    const view = (d: (typeof devices)[number]) => ({ id: d.id, label: d.label, createdAt: iso(d.created_at), lastSeenAt: iso(d.last_seen_at) });
    const me = devices.find((d) => d.id === owner.deviceId);
    const oldest = (
      db
        .prepare(
          `SELECT MIN(t) AS t FROM (
             SELECT MIN(created_at) AS t FROM results WHERE owner_id = @o
             UNION ALL SELECT MIN(created_at) FROM mail_messages WHERE owner_id = @o
             UNION ALL SELECT MIN(created_at) FROM mail_addresses WHERE owner_id = @o
             UNION ALL SELECT MIN(created_at) FROM dmarc_reports WHERE owner_id = @o)`,
        )
        .get({ o: owner.ownerId }) as { t: number | null }
    ).t;
    // the device cookie slides: a browser in use keeps its notebook
    const token = req.cookies?.[DEVICE_COOKIE];
    if (token && findDevice(db, token)?.id === owner.deviceId) setDeviceCookie(reply, token);
    return {
      device: me ? view(me) : null,
      devices: devices.map((d) => ({ ...view(d), current: d.id === owner.deviceId })),
      counts: countOwnerData(db, owner.ownerId),
      oldest: iso(oldest),
      retentionDays: config.retentionDays,
    };
  });

  app.post('/api/me/link-code', async (req) => {
    const owner = req.owner!;
    const code = newLinkCode();
    const t = now();
    db.transaction(() => {
      db.prepare('DELETE FROM link_codes WHERE owner_id = ?').run(owner.ownerId);
      db.prepare('INSERT INTO link_codes(code_hash, owner_id, created_at, expires_at) VALUES(?,?,?,?)').run(sha256(code), owner.ownerId, t, t + CODE_TTL_MS);
    })();
    return { code: `${code.slice(0, 4)}-${code.slice(4)}`, expiresAt: iso(t + CODE_TTL_MS) };
  });

  // what a link would do, before doing it: who is in the target notebook, what this browser brings
  app.post<{ Body: { code?: unknown } | undefined }>('/api/me/link/preview', async (req, reply) => {
    const owner = req.owner!;
    const found = targetOfCode(db, req, reply);
    if (!found) return reply;
    const devices = db.prepare('SELECT label, last_seen_at FROM devices WHERE owner_id = ? ORDER BY created_at').all(found.target) as {
      label: string | null;
      last_seen_at: number;
    }[];
    return { devices: devices.map((d) => ({ label: d.label, lastSeenAt: iso(d.last_seen_at) })), joining: countOwnerData(db, owner.ownerId) };
  });

  app.post<{ Body: { code?: unknown; confirmMerge?: unknown } | undefined }>('/api/me/link', async (req, reply) => {
    const owner = req.owner!;
    const found = targetOfCode(db, req, reply);
    if (!found) return reply;
    const { target, code } = found;
    // a browser that holds data joins another notebook only once the person confirmed it (a code
    // sent by someone else would otherwise hand them this browser's data in one click)
    const joining = countOwnerData(db, owner.ownerId);
    const confirmed = Boolean(req.body && typeof req.body === 'object' && req.body.confirmMerge === true);
    if (hasData(joining) && !confirmed) return reply.code(409).send({ error: 'confirm_merge', joining });
    let moved = ZERO;
    db.transaction(() => {
      db.prepare('DELETE FROM link_codes WHERE code_hash = ?').run(sha256(code));
      db.prepare('UPDATE devices SET owner_id = ? WHERE id = ?').run(target, owner.deviceId);
      const left = (db.prepare('SELECT COUNT(*) AS n FROM devices WHERE owner_id = ?').get(owner.ownerId) as { n: number }).n;
      if (left === 0) {
        // this browser was the only way into its notebook: its data joins the target notebook
        moved = moveOwnerData(db, owner.ownerId, target);
        db.prepare('DELETE FROM owners WHERE id = ?').run(owner.ownerId);
      } else {
        revokeDeviceGrants(db, owner.deviceId, owner.ownerId);
      }
    })();
    closeDeviceStreams([owner.deviceId]);
    return { linked: true, moved };
  });

  app.delete<{ Params: { id: string } }>('/api/me/devices/:id', async (req, reply) => {
    const owner = req.owner!;
    const dev = db.prepare('SELECT id FROM devices WHERE id = ? AND owner_id = ?').get(req.params.id, owner.ownerId) as { id: string } | undefined;
    if (!dev) return reply.code(404).send({ error: 'not_found' });
    db.transaction(() => {
      db.prepare('DELETE FROM devices WHERE id = ?').run(dev.id);
      const left = (db.prepare('SELECT COUNT(*) AS n FROM devices WHERE owner_id = ?').get(owner.ownerId) as { n: number }).n;
      // nobody can open this notebook any more: no orphan data is kept
      if (left === 0) deleteOwner(db, owner.ownerId);
      else revokeDeviceGrants(db, dev.id, owner.ownerId);
    })();
    closeDeviceStreams([dev.id]);
    if (dev.id === owner.deviceId) clearDeviceCookie(reply);
    return reply.code(204).send();
  });

  app.post<{ Body: { scope?: unknown } | undefined }>('/api/me/erase', async (req, reply) => {
    const owner = req.owner!;
    const scope = req.body && typeof req.body === 'object' ? req.body.scope : undefined;
    if (scope !== 'data' && scope !== 'all') return reply.code(400).send({ error: 'invalid_scope' });
    let erased = ZERO;
    const devices = devicesOf(db, owner.ownerId);
    db.transaction(() => {
      erased = scope === 'all' ? deleteOwner(db, owner.ownerId) : eraseOwnerData(db, owner.ownerId);
    })();
    // the live streams of the notebook showed data that no longer exists
    closeDeviceStreams(devices);
    if (scope === 'all') clearDeviceCookie(reply);
    return { erased };
  });
}
