// DKIM checker with selector discovery (US-043).
import type { ServerTool } from '../types.js';
import { normalizeDomain } from '../../lib/email-auth/common.js';
import { analyzeDkim } from '../../lib/email-auth/dkim.js';
import { actionDns, buildResult, nxdomainResult, respond, store } from '../../lib/email-auth/report.js';

export const tool: ServerTool = {
  id: 'dkim',
  register(app, ctx) {
    app.get<{ Params: { domain: string }; Querystring: { selectors?: string; selector?: string; only?: string } }>('/api/dkim/:domain', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const domain = normalizeDomain(req.params.domain);
        const selectors = [req.query.selectors, req.query.selector].filter(Boolean).join(',').split(/[\s,]+/).filter(Boolean);
        const dns = actionDns(ctx);
        const nx = await nxdomainResult(dns, 'dkim', domain, started);
        if (nx) return store(ctx, nx);
        const a = await analyzeDkim(dns, domain, { selectors, only: req.query.only === '1' || req.query.only === 'true' });
        return store(ctx, buildResult('dkim', domain, started, a));
      }),
    );
  },
};
