// Single-password authentication with a stateless signed cookie.
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { config } from './config.js';
import { getDb, getSetting, setSetting, type DB } from './db.js';
import { ensureDevice } from './owner.js';
import { days, now } from './lib/time.js';

export const COOKIE = 'check_session';

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [alg, saltHex, hashHex] = stored.split('$');
  if (alg !== 'scrypt' || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const got = scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return timingSafeEqual(got, expected);
}

/** Secret used to sign cookies: env, or one generated once and stored in the database. */
function secret(): string {
  if (config.sessionSecret) return config.sessionSecret;
  let s = getSetting<string>('session_secret', '');
  if (!s) {
    s = randomBytes(32).toString('hex');
    setSetting('session_secret', s);
  }
  return s;
}

function sign(payload: string) {
  return createHmac('sha256', secret()).update(payload).digest('base64url');
}

export function makeToken(at = now()): string {
  const exp = String(at + days(config.sessionDays));
  return `${exp}.${sign(exp)}`;
}

export function checkToken(token: string | undefined, at = now()): boolean {
  if (!token) return false;
  const [exp, sig] = token.split('.');
  if (!exp || !sig || !/^\d+$/.test(exp)) return false;
  const expected = sign(exp);
  if (expected.length !== sig.length) return false;
  if (!timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return false;
  return Number(exp) > at;
}

export function passwordConfigured(): boolean {
  return Boolean(config.passwordHash || config.password);
}

function passwordMatches(input: string): boolean {
  if (config.passwordHash) return verifyPassword(input, config.passwordHash);
  if (config.password) {
    const a = Buffer.from(input);
    const b = Buffer.from(config.password);
    return a.length === b.length && timingSafeEqual(a, b);
  }
  return false;
}

export function isAuthenticated(req: FastifyRequest): boolean {
  return checkToken(req.cookies?.[COOKIE]);
}

/** Login attempts per IP, sliding one-minute window. */
const attempts = new Map<string, number[]>();
const MAX_ATTEMPTS = 5;

export function registerAuth(app: FastifyInstance, db: DB = getDb()) {
  app.get('/api/auth/status', async (req) => ({
    authenticated: isAuthenticated(req),
    configured: passwordConfigured(),
  }));

  app.post<{ Body: { password?: string } }>('/api/auth/login', async (req, reply) => {
    const ip = req.ip;
    const t = now();
    const recent = (attempts.get(ip) ?? []).filter((x) => t - x < 60_000);
    if (recent.length >= MAX_ATTEMPTS) {
      const wait = Math.ceil((60_000 - (t - recent[0])) / 1000);
      return reply.code(429).send({ error: 'too_many_attempts', retryAfter: wait });
    }
    if (!passwordConfigured()) {
      return reply.code(503).send({ error: 'password_not_configured' });
    }
    if (!passwordMatches(String(req.body?.password ?? ''))) {
      recent.push(t);
      attempts.set(ip, recent);
      return reply.code(401).send({ error: 'wrong_password', remaining: MAX_ATTEMPTS - recent.length });
    }
    attempts.delete(ip);
    reply.setCookie(COOKIE, makeToken(), {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.publicUrl.startsWith('https://'),
      path: '/',
      maxAge: config.sessionDays * 24 * 3600,
    });
    // the notebook of this browser (owner.ts): its cookie is set together with the session
    ensureDevice(db, req, reply);
    return { authenticated: true };
  });

  // the device cookie stays: logging in again on this browser reopens the same notebook
  app.post('/api/auth/logout', async (_req, reply) => {
    reply.clearCookie(COOKIE, { path: '/' });
    return { authenticated: false };
  });
}

/** preHandler for protected routes. */
export async function requireAuth(req: FastifyRequest, reply: FastifyReply) {
  if (!isAuthenticated(req)) {
    return reply.code(401).send({ error: 'auth_required' });
  }
}
