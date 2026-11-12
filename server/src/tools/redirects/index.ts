// Redirect checker (US-069 to US-072).
//
// GET  /api/redirects/trace?url=&ua=&method=GET|HEAD&cookies=1&headers=<json>&max=15
//        Accept: text/event-stream (or stream=1) → SSE: `hop` (each hop once finished, body
//        included), `done` (complete CheckResult<TraceData>), `error` ({ message })
//        otherwise → the CheckResult as JSON
//      ua: chrome (default) | mobile | googlebot | bingbot | curl | any other text = custom UA
//      headers: {"Name":"value"} or [["Name","value"]]; cookies=0 drops cookies between hops
// POST /api/redirects/variants {url, ua?}   → CheckResult<VariantsData>
// POST /api/redirects/batch {urls: string[] (≤ 100), ua?, method?} → { rows: BatchRow[] }, 6 at a time
import { t } from '../../i18n.js';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { saveResult } from '../../db.js';
import { InvalidInputError, mapLimit } from '../../lib/email-auth/common.js';
import { actionDns, buildResult, respond, store } from '../../lib/email-auth/report.js';
import { cleanHeaders } from '../../lib/http-trace.js';
import { UnsafeTargetError } from '../../lib/net.js';
import { openSse } from '../../lib/sse.js';
import { explain, scoreOf, sortFindings } from '../../knowledge/engine.js';
import type { CheckResult, ServerTool, ToolContext } from '../types.js';
import { analyzeTrace } from './analyze.js';
import { normalizeUrlInput, traceChain, type Hop, type TraceData } from './trace.js';
import { analyzeVariants } from './variants.js';

interface TraceQuery {
  url?: string;
  ua?: string;
  method?: string;
  cookies?: string;
  headers?: string;
  max?: string;
  stream?: string;
}

const BATCH_MAX = 100;
/** Body text kept per hop in the history copy (the live answer keeps up to 2 MB). */
const STORED_BODY = 256 * 1024;

export function parseHeaderParam(raw?: string): [string, string][] {
  if (!raw?.trim()) return [];
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    throw new InvalidInputError(t('Paramètre « headers » illisible : JSON attendu, par exemple {"Accept-Language":"en"}.'));
  }
  const list: [string, string][] = Array.isArray(v)
    ? v.filter((p): p is [string, string] => Array.isArray(p) && p.length >= 2).map(([k, x]) => [String(k), String(x)])
    : v && typeof v === 'object'
      ? Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, String(x)])
      : [];
  if (list.length > 30) throw new InvalidInputError(t('30 en-têtes ajoutés au plus.'));
  try {
    return cleanHeaders(list);
  } catch (e) {
    throw new InvalidInputError((e as Error).message);
  }
}

function traceOptions(q: TraceQuery) {
  const method = (q.method ?? 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') throw new InvalidInputError(t('Méthode GET ou HEAD.'));
  const max = q.max ? Number(q.max) : 15;
  if (!Number.isFinite(max) || max < 1 || max > 30) throw new InvalidInputError(t('max : entre 1 et 30 requêtes.'));
  return {
    ua: q.ua,
    method: method as 'GET' | 'HEAD',
    cookies: !(q.cookies === '0' || q.cookies === 'false'),
    headers: parseHeaderParam(q.headers),
    max,
  };
}

function resultOf(d: TraceData, started: number): CheckResult<TraceData> {
  const a = analyzeTrace(d);
  return buildResult('redirects', d.start, started, { ...a, data: d });
}

/** History copy: same result, bodies cut to 256 KB per hop. */
function storeTrace(ctx: ToolContext, r: CheckResult<TraceData>): CheckResult<TraceData> {
  try {
    const hops = r.data.hops.map((h): Hop => {
      const b = h.exchange.body;
      if (!b?.text || b.text.length <= STORED_BODY) return h;
      return { ...h, exchange: { ...h.exchange, body: { ...b, text: b.text.slice(0, STORED_BODY), storedCut: true } as typeof b } };
    });
    const counts: Record<string, number> = {};
    for (const f of r.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    r.resultId = saveResult('redirects', r.input, { ...r, data: { ...r.data, hops } }, {
      score: r.score ?? null,
      summary: { findings: counts, passed: r.passed.length, final: r.data.final, redirects: r.data.redirects },
    }, ctx.db);
  } catch {
    /* history is a convenience */
  }
  return r;
}

function badInput(reply: FastifyReply, e: unknown) {
  if (e instanceof InvalidInputError || e instanceof UnsafeTargetError) return reply.code(400).send({ error: 'invalid_input', message: e.message });
  throw e;
}

export interface BatchRow {
  input: string;
  start?: string;
  final?: string;
  finalStatus?: number;
  redirects: number;
  statuses: (number | string)[];
  kinds: string[];
  ms: number;
  score?: number;
  alert?: string;
  alertId?: string;
  alerts: number;
  error?: string;
}

export const tool: ServerTool = {
  id: 'redirects',
  register(app, ctx) {
    app.get<{ Querystring: TraceQuery }>('/api/redirects/trace', async (req: FastifyRequest<{ Querystring: TraceQuery }>, reply) => {
      let opts: ReturnType<typeof traceOptions>;
      try {
        normalizeUrlInput(req.query.url ?? ''); // 400 before opening the stream
        opts = traceOptions(req.query);
      } catch (e) {
        return badInput(reply, e);
      }
      const wantsStream = req.query.stream === '1' || (req.headers.accept ?? '').includes('text/event-stream');
      if (!wantsStream) {
        return respond(reply, async () => {
          const started = performance.now();
          const d = await traceChain(req.query.url!, { ...opts, dns: actionDns(ctx) });
          return storeTrace(ctx, resultOf(d, started));
        }, 240000);
      }
      const sse = openSse(req, reply);
      try {
        const started = performance.now();
        const d = await traceChain(req.query.url!, { ...opts, dns: actionDns(ctx), signal: sse.signal, onHop: (h) => sse.send('hop', h) });
        if (!sse.closed) sse.send('done', storeTrace(ctx, resultOf(d, started)));
      } catch (e) {
        sse.send('error', { message: (e as Error).message });
      } finally {
        sse.close();
      }
    });

    app.post<{ Body: { url?: string; ua?: string } }>('/api/redirects/variants', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const raw = req.body?.url?.trim();
        if (!raw) throw new InvalidInputError(t('Champ « url » attendu.'));
        const a = await analyzeVariants(raw, { ua: req.body.ua, dnsFor: () => actionDns(ctx) });
        return store(ctx, buildResult('redirects', t('variantes {host}', { host: a.data.host }), started, a));
      }, 120000),
    );

    app.post<{ Body: { urls?: unknown; ua?: string; method?: string } }>('/api/redirects/batch', (req, reply) =>
      respond(reply, async () => {
        const list = Array.isArray(req.body?.urls) ? req.body.urls.map((x) => String(x).trim()).filter(Boolean) : [];
        if (!list.length) throw new InvalidInputError(t('Champ « urls » attendu : une liste d’URL.'));
        if (list.length > BATCH_MAX) throw new InvalidInputError(t('{max} URL au plus par lot (reçu {n}).', { max: BATCH_MAX, n: list.length }));
        const opts = traceOptions({ ua: req.body.ua, method: req.body.method });
        const rows = await mapLimit(list, 6, async (input): Promise<BatchRow> => {
          const t0 = performance.now();
          try {
            const d = await traceChain(input, { ...opts, dns: actionDns(ctx), light: true });
            const a = analyzeTrace(d);
            const findings = sortFindings(a.issues.map((i) => explain(i)));
            const top = findings.find((f) => f.penalty > 0);
            return {
              input,
              start: d.start,
              final: d.final,
              finalStatus: d.finalStatus,
              redirects: d.redirects,
              statuses: d.hops.map((h) => h.exchange.status ?? h.exchange.error?.code ?? t('erreur')),
              kinds: d.hops.map((h) => h.redirect?.kind ?? ''),
              ms: d.totalMs,
              // an URL that could not be reached gets no score, only its error
              score: d.stoppedBy === 'error' || d.stoppedBy === 'unsafe' ? undefined : scoreOf(findings),
              alert: top?.title,
              alertId: top?.id,
              alerts: findings.filter((f) => f.penalty > 0).length,
              error: d.stoppedBy === 'error' || d.stoppedBy === 'unsafe' ? (d.stopDetail ?? undefined) : undefined,
            };
          } catch (e) {
            return { input, redirects: 0, statuses: [], kinds: [], ms: Math.round(performance.now() - t0), alerts: 0, error: (e as Error).message };
          }
        });
        return { rows, measuredAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') };
      }, 300000),
    );
  },
};
