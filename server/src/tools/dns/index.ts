// DNS lookup (US-047), reverse DNS with FCrDNS (US-049) and DNSSEC chain of trust.
import type { ServerTool } from '../types.js';
import { normalizeDomain } from '../../lib/email-auth/common.js';
import { analyzeDnssec } from '../../lib/email-auth/dnssec.js';
import { actionDns, buildResult, respond, store } from '../../lib/email-auth/report.js';
import { dnsLookup } from './lookup.js';

const yes = (v?: string) => v === '1' || v === 'true' || v === 'yes';

export const tool: ServerTool = {
  id: 'dns',
  register(app, ctx) {
    app.get<{ Params: { name: string }; Querystring: { type?: string; server?: string; all?: string; dnssec?: string } }>('/api/dns/:name', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const a = await dnsLookup((o) => actionDns(ctx, o), req.params.name, {
          type: req.query.type,
          server: req.query.server?.trim() || undefined,
          all: yes(req.query.all),
          dnssec: yes(req.query.dnssec),
        });
        return store(ctx, buildResult('dns', `${a.data.name} ${a.data.type}`, started, a, { score: false }));
      }),
    );
    app.get<{ Params: { name: string } }>('/api/dns/:name/dnssec', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const domain = normalizeDomain(req.params.name);
        // recorded under the dnssec tool with the bare domain, so that the history reopens /dnssec/:domain
        return store(ctx, buildResult('dnssec', domain, started, await analyzeDnssec(actionDns(ctx, { dnssec: true }), domain)));
      }),
    );
  },
};
