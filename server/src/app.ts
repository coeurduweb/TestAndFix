// Fastify application: auth, tool discovery, static UI.
import fs from 'node:fs';
import { STATUS_CODES } from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import Fastify, { type FastifyError, type FastifyInstance, type FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import multipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import { config } from './config.js';
import { getDb, type DB } from './db.js';
import { isAuthenticated, registerAuth, requireAuth } from './auth.js';
import { registerOwnerContext } from './owner.js';
import { registerLang } from './i18n.js';
import { registerMe } from './me.js';
import { ResolveSession } from './dns/iterative.js';
import { isPublicIp } from './lib/net.js';
import type { ServerTool, ToolContext } from './tools/types.js';

const here = path.dirname(fileURLToPath(import.meta.url));

export async function loadTools(dir = path.join(here, 'tools')): Promise<ServerTool[]> {
  const tools: ServerTool[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const file = ['index.ts', 'index.js'].map((f) => path.join(dir, entry.name, f)).find((f) => fs.existsSync(f));
    if (!file) continue;
    const mod = (await import(pathToFileURL(file).href)) as { tool?: ServerTool };
    if (mod.tool) tools.push(mod.tool);
  }
  return tools.sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * Request logs keep the method, the route PATTERN, the status and the time. Never the real URL,
 * its query string, parameters, headers or cookies: they hold the domains, IPs and URLs checked
 * and the share tokens of the people using the tool.
 */
export const logSerializers = {
  req(req: FastifyRequest) {
    return { method: req.method, route: req.routeOptions?.url ?? '(inconnue)' };
  },
  res(reply: { statusCode: number }) {
    return { statusCode: reply.statusCode };
  },
  /**
   * Errors: type, code, status and the stack frames, never the message (nor the first stack line,
   * which repeats it): messages often quote what was typed, a domain, an address (2026-11-11 review).
   */
  err(e: unknown) {
    return serializeError(e, 0);
  },
};

function serializeError(e: unknown, depth: number): Record<string, unknown> {
  if (!e || typeof e !== 'object') return { type: typeof e };
  const err = e as { name?: string; code?: unknown; statusCode?: unknown; stack?: unknown; cause?: unknown; constructor?: { name?: string } };
  const out: Record<string, unknown> = { type: err.constructor?.name || err.name || 'Error' };
  if (typeof err.code === 'string' || typeof err.code === 'number') out.code = err.code;
  if (typeof err.statusCode === 'number') out.statusCode = err.statusCode;
  if (typeof err.stack === 'string') out.stack = err.stack.split('\n').filter((l) => /^\s+at /.test(l)).map((l) => l.trim());
  if (err.cause !== undefined && depth < 3) out.cause = serializeError(err.cause, depth + 1);
  return out;
}

/**
 * ONE trusted hop: production nginx (on the host, reaching the container through the published
 * 127.0.0.1:3000, so from a private address) appends the client address to X-Forwarded-For
 * ($proxy_add_x_forwarded_for). Only the rightmost value is then ours. With `trustProxy: true`
 * req.ip was the leftmost value, which the client writes itself (2026-11-11 review: rate limits
 * bypassed). `trustProxy: 1` is not usable: Fastify 5.12 reads a number as "trust nothing" (every
 * client would then share nginx's address, and one limit). Hence: trust the direct peer only, and
 * only when it is a private or loopback address.
 */
export function trustOneHop(address: string, hop: number): boolean {
  return hop === 0 && !isPublicIp(address);
}

/**
 * State-changing API requests must come from our own pages. A browser says where a request comes
 * from (Sec-Fetch-Site): anything but same-origin is refused, which also covers a sibling site under
 * the same domain (same-site). Without that header (curl, scripts), a foreign Origin is refused.
 */
const STATE_CHANGING = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);
export function crossSiteRefused(method: string, url: string, headers: Record<string, string | string[] | undefined>): boolean {
  if (!STATE_CHANGING.has(method) || !url.startsWith('/api/')) return false;
  const site = headers['sec-fetch-site'];
  if (site !== undefined) return site !== 'same-origin';
  const origin = headers.origin;
  if (origin === undefined) return false;
  let own = '';
  try {
    own = new URL(config.publicUrl).origin;
  } catch {
    /* no public URL: every Origin is foreign */
  }
  return origin !== own;
}

export async function buildApp(
  opts: { db?: DB; tools?: ServerTool[]; logger?: boolean; logStream?: NodeJS.WritableStream } = {},
): Promise<{
  app: FastifyInstance;
  ctx: ToolContext;
  tools: ServerTool[];
}> {
  const logging = opts.logger ?? Boolean(opts.logStream);
  const app = Fastify({
    // the serializers return less than pino's defaults on purpose (no message, no URL)
    logger: logging ? ({ serializers: logSerializers, ...(opts.logStream ? { stream: opts.logStream } : {}) } as never) : false,
    bodyLimit: 30 * 1024 * 1024,
    trustProxy: trustOneHop,
  });
  app.setErrorHandler((err: FastifyError & { status?: number; headers?: Record<string, string> }, _req, reply) => {
    if (err.headers) reply.headers(err.headers);
    const code = err.statusCode ?? err.status;
    reply.code(code && code >= 400 ? code : reply.statusCode >= 400 ? reply.statusCode : 500);
    // a constant log message: err.message (what the default handler logs) may quote user input
    if (reply.statusCode >= 500) reply.log.error({ req: _req, res: reply, err }, 'request error');
    else reply.log.info({ res: reply, err }, 'request error');
    // the body Fastify's default handler sends (sending `err` itself would log it again, message included)
    const status = reply.statusCode;
    return reply.send({ statusCode: status, ...(err.code ? { code: err.code } : {}), error: STATUS_CODES[status] ?? 'Error', message: err.message });
  });
  app.addHook('onRequest', async (req, reply) => {
    if (crossSiteRefused(req.method, req.url, req.headers)) return reply.code(403).send({ error: 'cross_site_request' });
  });
  const db = opts.db ?? getDb();
  const ctx: ToolContext = { db, config, dns: (o) => new ResolveSession(o) };

  await app.register(cookie);
  // the notebook of every request with a valid session (owner.ts), before any route
  registerOwnerContext(app, db, isAuthenticated);
  // the language of every request (i18n.ts): the interface's `lang` cookie, else Accept-Language, else English
  registerLang(app);
  await app.register(multipart, { limits: { fileSize: 30 * 1024 * 1024, files: 50 } });

  // Nothing the API returns may be cached anywhere.
  app.addHook('onSend', async (req, reply, payload) => {
    // ?historique=0: a read made to pre-fill a form (generators) is not a measurement worth keeping
    if ((req.query as Record<string, string> | undefined)?.historique === '0' && typeof payload === 'string' && payload.includes('"resultId"')) {
      try {
        const body = JSON.parse(payload) as { resultId?: string };
        if (body.resultId) {
          // only the result this very request stored, in its own notebook
          db.prepare('DELETE FROM results WHERE id = ? AND owner_id IS ?').run(body.resultId, req.owner?.ownerId ?? null);
          delete body.resultId;
          payload = JSON.stringify(body);
        }
      } catch {
        /* not JSON */
      }
    }
    if (req.url.startsWith('/api/')) {
      reply.header('Cache-Control', 'no-store, max-age=0');
      reply.header('Pragma', 'no-cache');
    }
    // our pages may be framed only by our own pages (the mail preview frames are srcdoc, not fetched)
    reply.header('X-Frame-Options', 'SAMEORIGIN');
    const csp = reply.getHeader('Content-Security-Policy');
    if (!csp) reply.header('Content-Security-Policy', "frame-ancestors 'self'");
    else if (!/frame-ancestors/.test(String(csp))) reply.header('Content-Security-Policy', `${String(csp)}; frame-ancestors 'self'`);
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'same-origin');
    return payload;
  });

  registerAuth(app, db);
  app.get('/api/health', async () => ({ ok: true, time: new Date().toISOString() }));
  await app.register(async (scope) => {
    scope.addHook('preHandler', requireAuth);
    registerMe(scope, db);
  });

  const tools = opts.tools ?? (await loadTools());
  for (const tool of tools) {
    if (tool.registerPublic) await app.register(async (scope) => tool.registerPublic!(scope, ctx));
    if (tool.register)
      await app.register(async (scope) => {
        scope.addHook('preHandler', requireAuth);
        await tool.register!(scope, ctx);
      });
  }
  app.get('/api/tools', async () => tools.map((t) => t.id));

  // Production: serve the built UI and fall back to index.html for client routes.
  const webDist = path.resolve(here, '..', '..', 'web', 'dist');
  if (fs.existsSync(webDist)) {
    await app.register(fastifyStatic, { root: webDist, wildcard: false, maxAge: '1y', immutable: true, index: false });
    app.setNotFoundHandler((req, reply) => {
      if (req.url.startsWith('/api/')) return reply.code(404).send({ error: 'not_found' });
      reply.header('Cache-Control', 'no-cache');
      return reply.sendFile('index.html', { maxAge: 0, immutable: false });
    });
  } else {
    // the default handler would log "Route GET:<full url> not found"
    app.setNotFoundHandler((_req, reply) => reply.code(404).send({ error: 'not_found' }));
  }
  return { app, ctx, tools };
}
