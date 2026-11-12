// Whois and RDAP (US-050, extended on 2026-11-12): the registry AND the registrar of a domain, by
// RDAP first and WHOIS port 43 in fallback, for one domain or a list.
//
// GET  /api/whois/:domain          one domain; ?frais=1 skips the 10-minute politeness cache
// POST /api/whois/batch/stream     { domains: string[] | string }, up to 100, SSE `start`, `row`, `done`
// GET  /api/rdap/:domain           the former registry-only RDAP check, kept for existing links
import { t } from '../../i18n.js';
import { saveResult } from '../../db.js';
import { InvalidInputError, normalizeDomain } from '../../lib/email-auth/common.js';
import { httpGet } from '../../lib/email-auth/http.js';
import { analyzeRdap } from '../../lib/email-auth/rdap.js';
import { actionDns, buildResult, respond, store } from '../../lib/email-auth/report.js';
import { openSse } from '../../lib/sse.js';
import { BATCH_MAX, lookupMany, lookupWhois, parseDomainList, sharedCache, whoisAnalysis, type WhoisDeps } from '../../lib/whois/lookup.js';
import { whoisQuery } from '../../lib/whois/port43.js';
import { currentOwnerId } from '../../owner.js';
import type { ServerTool, ToolContext } from '../types.js';

/** A records: [] for a name without any (NXDOMAIN, no data), a rejection when DNS did not answer. */
async function resolveA(session: ReturnType<typeof actionDns>, name: string): Promise<string[]> {
  const r = await session.resolve(name, 'A');
  if (r.rcode === 'NXDOMAIN') return [];
  if (r.rcode !== 'NOERROR') throw new Error(r.rcode);
  return r.answers.filter((x) => x.type === 'A').map((x) => String(x.data));
}

function deps(ctx: ToolContext, extra: Partial<WhoisDeps> = {}): WhoisDeps {
  const session = actionDns(ctx);
  return {
    resolveA: (name) => resolveA(session, name),
    http: (url, headers) => httpGet(url, { session, headers, maxBytes: 4 * 1024 * 1024 }),
    whois43: (host, query) => whoisQuery(host, query, { session }),
    cache: sharedCache,
    scope: currentOwnerId() ?? '',
    ...extra,
  };
}

/** History label of a list: the first names, then a count. */
function batchLabel(domains: string[]): string {
  return domains.length <= 3 ? domains.join(', ') : t('{list} et {n} autres', { list: domains.slice(0, 2).join(', '), n: domains.length - 2 });
}

export const tool: ServerTool = {
  id: 'rdap',
  register(app, ctx) {
    app.get<{ Params: { domain: string } }>('/api/rdap/:domain', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const domain = normalizeDomain(req.params.domain);
        return store(ctx, buildResult('rdap', domain, started, await analyzeRdap(domain, { session: actionDns(ctx) })));
      }),
    );

    app.get<{ Params: { domain: string }; Querystring: { frais?: string } }>('/api/whois/:domain', (req, reply) =>
      respond(
        reply,
        async () => {
          const started = performance.now();
          const domain = normalizeDomain(req.params.domain);
          const report = await lookupWhois(domain, deps(ctx, { fresh: !!req.query.frais }));
          return store(ctx, buildResult('rdap', domain, started, whoisAnalysis(report)));
        },
        75_000,
      ),
    );

    app.post<{ Body: { domains?: string[] | string } }>('/api/whois/batch/stream', async (req, reply) => {
      const input = req.body?.domains;
      const parsed = parseDomainList(input ?? '');
      if (!parsed.domains.length)
        return reply.code(400).send({ error: 'invalid_input', message: t('Aucun nom de domaine dans la liste. Collez un domaine par ligne.') });
      if (parsed.domains.length > BATCH_MAX)
        return reply.code(400).send({ error: 'invalid_input', message: t('{max} domaines au plus par liste ({n} reçus) : découpez la liste.', { max: BATCH_MAX, n: parsed.domains.length }) });
      const sse = openSse(req, reply);
      const started = performance.now();
      sse.send('start', { count: parsed.domains.length, domains: parsed.domains, invalid: parsed.invalid, duplicates: parsed.duplicates, max: BATCH_MAX });
      try {
        // one DNS session for the whole list; a host queue may hold the list for a while
        const d = deps(ctx, { maxWaitMs: 180_000, signal: sse.signal });
        const rows = await lookupMany(parsed.domains, (name) => lookupWhois(name, d), { onRow: (r) => sse.send('row', r), signal: sse.signal });
        if (sse.closed) return;
        const result = buildResult('rdap', batchLabel(parsed.domains), started, { issues: [], passed: [], data: { domains: parsed.domains, rows, invalid: parsed.invalid } }, { score: false });
        try {
          result.resultId = saveResult('rdap', result.input, result, { score: null, summary: { domains: parsed.domains, count: parsed.domains.length } }, ctx.db);
        } catch {
          /* history is a convenience */
        }
        sse.send('done', result);
      } catch (e) {
        sse.send('error', { message: e instanceof InvalidInputError ? e.message : t('La mesure de la liste a échoué.') });
      } finally {
        sse.close();
      }
    });
  },
};
