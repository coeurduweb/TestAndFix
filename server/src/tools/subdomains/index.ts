// Subdomains revealed by Certificate Transparency (US-051).
//
// GET /api/subdomains/:domain          JSON CheckResult<SubdomainsData>
// GET /api/subdomains/:domain/stream   SSE: `source` (one per CT source, as it answers),
//                                      `inventory` (every name found, before resolution),
//                                      `subdomain` (one per name, as soon as it is resolved),
//                                      `done` (the stored CheckResult), `error`
// Nothing is cached: each call asks the CT sources and resolves every name from the root again.
import type { FastifyReply } from 'fastify';
import { InvalidInputError, normalizeDomain } from '../../lib/email-auth/common.js';
import { actionDns, buildResult, respond, store } from '../../lib/email-auth/report.js';
import { ctFetcher } from '../../lib/ct/sources.js';
import { safeGet } from '../../lib/net.js';
import { probeTls } from '../link/tls.js';
import { openSse } from '../../lib/sse.js';
import type { ServerTool, ToolContext } from '../types.js';
import { analyzeSubdomains, type SubdomainsDeps } from './analyze.js';

export function subdomainsDeps(ctx: ToolContext): SubdomainsDeps {
  const dns = actionDns(ctx);
  return {
    // the CT services are fixed hosts; their names are resolved from the root like any other
    fetch: ctFetcher(() => dns.current),
    dns,
    probe: async (url) => {
      const r = await safeGet(url, { session: dns.current, maxBytes: 256 * 1024, headers: { accept: 'text/html,*/*;q=0.8' } });
      return { status: r.status, body: r.body.toString('utf8') };
    },
    // TLS handshake on the address our resolver found (public addresses only, checked by probeTls)
    tls: probeTls,
  };
}

type DepsFactory = (ctx: ToolContext) => SubdomainsDeps;

async function run(domain: string, deps: SubdomainsDeps, hooks: Parameters<typeof analyzeSubdomains>[2] = {}) {
  const started = performance.now();
  const a = await analyzeSubdomains(domain, deps, hooks);
  // no CT source answered: nothing was measured, a score would be meaningless
  const measured = a.data.sources.some((s) => s.status === 'ok');
  return buildResult('subdomains', domain, started, a, { score: measured });
}

export function createTool(makeDeps: DepsFactory = subdomainsDeps): ServerTool {
  return {
    id: 'subdomains',
    register(app, ctx) {
      app.get<{ Params: { domain: string } }>('/api/subdomains/:domain', (req, reply) =>
        respond(reply, async () => store(ctx, await run(normalizeDomain(req.params.domain), makeDeps(ctx))), 240000),
      );
      app.get<{ Params: { domain: string } }>('/api/subdomains/:domain/stream', async (req, reply: FastifyReply) => {
        let domain: string;
        try {
          domain = normalizeDomain(req.params.domain);
        } catch (e) {
          if (e instanceof InvalidInputError) return reply.code(400).send({ error: 'invalid_input', message: e.message });
          throw e;
        }
        const sse = openSse(req, reply);
        sse.send('start', { domain });
        try {
          const r = await run(domain, makeDeps(ctx), {
            signal: sse.signal,
            onSource: (s) => sse.send('source', s),
            onInventory: (e) => sse.send('inventory', e),
            onSubdomain: (row) => sse.send('subdomain', { name: row.name, dns: row.dns, served: row.served, takeover: row.takeover }),
          });
          if (!sse.closed) sse.send('done', store(ctx, r));
        } catch (e) {
          sse.send('error', { message: (e as Error).message });
        } finally {
          sse.close();
        }
      });
    },
  };
}

export const tool = createTool();
