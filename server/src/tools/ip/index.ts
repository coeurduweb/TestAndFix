// IP reputation tool (US-065) and batch check (US-068).
//
// GET  /api/ip/:ip                 one IPv4 / IPv6, or an IPv4 range written 192.0.2.0%2F24
// GET  /api/ip/:ip/:prefix         IPv4 range from /24 to /32: /api/ip/192.0.2.0/24
// GET  /api/ip/:ip/stream          SSE: `start`, one `source` per source as it answers, `done`
// GET  /api/ip/:ip/:prefix/stream  SSE for a range: `start`, one `row` per address, `done`
// POST /api/ip/batch               { ips: string[] | string } up to 256 addresses, ranges included
// POST /api/ip/batch/stream        same, as SSE (`start`, `row`, `done`)
// GET  /api/ip/domain/:domain      reputation of a domain (US-069): lists, RDAP, IPs of A/AAAA and MX
// GET  /api/ip/domain/:domain/stream  SSE: `start`, one `source` per step as it answers, `done`
import { t } from '../../i18n.js';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { InvalidInputError, normalizeDomain } from '../../lib/email-auth/common.js';
import { actionDns, buildResult, respond, store } from '../../lib/email-auth/report.js';
import { guardedDnsblResolver, selectLists } from '../../lib/reputation/dnsbl-lists.js';
import { openSse } from '../../lib/sse.js';
import type { ServerTool, ToolContext } from '../types.js';
import { analyzeBatch, analyzeIp, IP_SOURCES, type IpBatchRow, type IpDeps } from './analyze.js';
import { analyzeDomainReputation, DOMAIN_SOURCES, type DomainDeps } from './domain.js';
import { isRange, parseBatch, parseIp } from './input.js';

function singleDeps(ctx: ToolContext): IpDeps {
  return {
    dns: actionDns(ctx),
    dnsblResolverFor: guardedDnsblResolver(() => ctx.dns()),
    keys: { abuseIpdb: ctx.config.keys.abuseIpdb, virusTotal: ctx.config.keys.virusTotal },
  };
}

/** A batch shares one session for its DNSBL lookups (delegations walked once), with a fresh one on a stall. */
function batchDeps(ctx: ToolContext): IpDeps {
  const shared = ctx.dns();
  return { ...singleDeps(ctx), dnsblResolverFor: guardedDnsblResolver(() => shared, () => ctx.dns()) };
}

function domainDeps(ctx: ToolContext): DomainDeps {
  return {
    dns: actionDns(ctx),
    ipDeps: batchDeps(ctx),
    domainListResolverFor: guardedDnsblResolver(() => ctx.dns()),
    keys: { safeBrowsing: ctx.config.keys.safeBrowsing, virusTotal: ctx.config.keys.virusTotal, urlhaus: ctx.config.keys.urlhaus },
  };
}

async function runDomain(ctx: ToolContext, raw: string) {
  const started = performance.now();
  const domain = normalizeDomain(raw);
  return store(ctx, buildResult('ip', domain, started, await analyzeDomainReputation(domain, domainDeps(ctx))));
}

async function streamDomain(ctx: ToolContext, req: FastifyRequest, reply: FastifyReply, raw: string) {
  let domain: string;
  try {
    domain = normalizeDomain(raw);
  } catch (e) {
    return badRequest(reply, e);
  }
  const sse = openSse(req, reply);
  const lists = selectLists('domain', 'all');
  sse.send('start', { domain, sources: DOMAIN_SOURCES.map((s) => ({ id: s.id, label: t(s.label) })), lists: lists.lists.map((l) => ({ zone: l.zone, name: l.name, weight: l.weight })) });
  try {
    const started = performance.now();
    const a = await analyzeDomainReputation(domain, domainDeps(ctx), { onEvent: (e) => sse.send('source', e), signal: sse.signal });
    if (!sse.closed) sse.send('done', store(ctx, buildResult('ip', domain, started, a)));
  } catch (e) {
    sse.send('error', { message: (e as Error).message });
  } finally {
    sse.close();
  }
}

async function runSingle(ctx: ToolContext, raw: string) {
  const started = performance.now();
  const a = await analyzeIp(raw, singleDeps(ctx));
  return store(ctx, buildResult('ip', a.data.ip, started, a, { score: a.data.public }));
}

async function runBatch(ctx: ToolContext, input: string[] | string, label: string, onRow?: (r: IpBatchRow) => void, signal?: AbortSignal) {
  const started = performance.now();
  const { ips, invalid } = parseBatch(input);
  const a = await analyzeBatch(ips, batchDeps(ctx), { invalid, onRow, signal });
  return store(ctx, buildResult('ip', label, started, a, { score: false }));
}

function badRequest(reply: FastifyReply, e: unknown) {
  if (e instanceof InvalidInputError) return reply.code(400).send({ error: 'invalid_input', message: e.message });
  throw e;
}

async function streamSingle(ctx: ToolContext, req: FastifyRequest, reply: FastifyReply, raw: string) {
  let ip: string;
  try {
    ip = parseIp(raw).ip;
  } catch (e) {
    return badRequest(reply, e);
  }
  const sse = openSse(req, reply);
  const lists = selectLists('ip', 'all');
  sse.send('start', { ip, sources: IP_SOURCES.map((s) => ({ id: s.id, label: t(s.label) })), lists: lists.lists.map((l) => ({ zone: l.zone, name: l.name, weight: l.weight })) });
  try {
    const started = performance.now();
    const a = await analyzeIp(ip, singleDeps(ctx), { onEvent: (e) => sse.send('source', e), signal: sse.signal });
    if (!sse.closed) sse.send('done', store(ctx, buildResult('ip', a.data.ip, started, a, { score: a.data.public })));
  } catch (e) {
    sse.send('error', { message: (e as Error).message });
  } finally {
    sse.close();
  }
}

async function streamBatch(ctx: ToolContext, req: FastifyRequest, reply: FastifyReply, input: string[] | string, label: string) {
  let parsed: ReturnType<typeof parseBatch>;
  try {
    parsed = parseBatch(input);
  } catch (e) {
    return badRequest(reply, e);
  }
  const sse = openSse(req, reply);
  const lists = selectLists('ip', 'major');
  sse.send('start', { count: parsed.ips.length, invalid: parsed.invalid, lists: lists.lists.map((l) => ({ zone: l.zone, name: l.name })) });
  try {
    const started = performance.now();
    const a = await analyzeBatch(parsed.ips, batchDeps(ctx), { invalid: parsed.invalid, onRow: (r) => sse.send('row', r), signal: sse.signal });
    if (!sse.closed) sse.send('done', store(ctx, buildResult('ip', label, started, a, { score: false })));
  } catch (e) {
    sse.send('error', { message: (e as Error).message });
  } finally {
    sse.close();
  }
}

export const tool: ServerTool = {
  id: 'ip',
  register(app, ctx) {
    app.get<{ Params: { domain: string } }>('/api/ip/domain/:domain', (req, reply) => respond(reply, () => runDomain(ctx, req.params.domain), 90000));
    app.get<{ Params: { domain: string } }>('/api/ip/domain/:domain/stream', (req, reply) => streamDomain(ctx, req, reply, req.params.domain));
    app.get<{ Params: { ip: string } }>('/api/ip/:ip', (req, reply) =>
      respond<unknown>(reply, () => (isRange(req.params.ip) ? runBatch(ctx, [req.params.ip], req.params.ip) : runSingle(ctx, req.params.ip)), 90000),
    );
    app.get<{ Params: { ip: string; prefix: string } }>('/api/ip/:ip/:prefix', (req, reply) =>
      respond(reply, async () => {
        if (!/^\d{1,3}$/.test(req.params.prefix)) throw new InvalidInputError(t('« {prefix} » n’est pas une longueur de préfixe.', { prefix: req.params.prefix }));
        const range = `${req.params.ip}/${req.params.prefix}`;
        return runBatch(ctx, [range], range);
      }, 120000),
    );
    app.get<{ Params: { ip: string } }>('/api/ip/:ip/stream', (req, reply) =>
      isRange(req.params.ip) ? streamBatch(ctx, req, reply, [req.params.ip], req.params.ip) : streamSingle(ctx, req, reply, req.params.ip),
    );
    app.get<{ Params: { ip: string; prefix: string } }>('/api/ip/:ip/:prefix/stream', (req, reply) => {
      const range = `${req.params.ip}/${req.params.prefix}`;
      return streamBatch(ctx, req, reply, [range], range);
    });
    app.post<{ Body: { ips?: string[] | string } }>('/api/ip/batch', (req, reply) =>
      respond(reply, () => {
        const ips = req.body?.ips;
        if (!ips || (Array.isArray(ips) && !ips.length)) throw new InvalidInputError(t('Champ « ips » attendu : une liste d’adresses IP.'));
        return runBatch(ctx, ips, batchLabel(ips));
      }, 120000),
    );
    app.post<{ Body: { ips?: string[] | string } }>('/api/ip/batch/stream', (req, reply) => {
      const ips = req.body?.ips;
      if (!ips || (Array.isArray(ips) && !ips.length)) return reply.code(400).send({ error: 'invalid_input', message: t('Champ « ips » attendu : une liste d’adresses IP.') });
      return streamBatch(ctx, req, reply, ips, batchLabel(ips));
    });
  },
};

/** History label of a batch: the first entries, then a count. */
function batchLabel(ips: string[] | string): string {
  const list = (Array.isArray(ips) ? ips : String(ips).split(/[\s,;]+/)).map((s) => String(s).trim()).filter(Boolean);
  return list.length <= 3 ? list.join(', ') : t('{list} et {n} autres', { list: list.slice(0, 2).join(', '), n: list.length - 2 });
}
