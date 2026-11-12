// MTA-STS and TLS-RPT checker (US-046).
import type { ServerTool } from '../types.js';
import { normalizeDomain } from '../../lib/email-auth/common.js';
import { analyzeMtaSts } from '../../lib/email-auth/mtasts.js';
import { actionDns, buildResult, nxdomainResult, respond, store } from '../../lib/email-auth/report.js';

export const tool: ServerTool = {
  id: 'mta-sts',
  register(app, ctx) {
    app.get<{ Params: { domain: string } }>('/api/mta-sts/:domain', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const domain = normalizeDomain(req.params.domain);
        const session = actionDns(ctx);
        const nx = await nxdomainResult(session, 'mta-sts', domain, started);
        if (nx) return store(ctx, nx);
        return store(ctx, buildResult('mta-sts', domain, started, await analyzeMtaSts(session, domain, { session })));
      }),
    );
  },
};
