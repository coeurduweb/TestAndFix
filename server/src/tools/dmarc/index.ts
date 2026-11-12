// DMARC checker (US-044).
import type { ServerTool } from '../types.js';
import { normalizeDomain } from '../../lib/email-auth/common.js';
import { analyzeDmarc } from '../../lib/email-auth/dmarc.js';
import { actionDns, buildResult, nxdomainResult, respond, store } from '../../lib/email-auth/report.js';

export const tool: ServerTool = {
  id: 'dmarc',
  register(app, ctx) {
    app.get<{ Params: { domain: string } }>('/api/dmarc/:domain', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const domain = normalizeDomain(req.params.domain);
        const dns = actionDns(ctx);
        const nx = await nxdomainResult(dns, 'dmarc', domain, started);
        if (nx) return store(ctx, nx);
        return store(ctx, buildResult('dmarc', domain, started, await analyzeDmarc(dns, domain)));
      }),
    );
  },
};
