// SMTP connection test of the MX (US-048). Port 25 outbound blocked here: reported as unavailable.
import type { ServerTool } from '../types.js';
import { normalizeDomain } from '../../lib/email-auth/common.js';
import { analyzeSmtp } from '../../lib/email-auth/smtp-probe.js';
import { actionDns, buildResult, respond, store } from '../../lib/email-auth/report.js';

export const tool: ServerTool = {
  id: 'smtp',
  register(app, ctx) {
    app.get<{ Params: { domain: string }; Querystring: { host?: string } }>('/api/smtp/:domain', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const domain = normalizeDomain(req.params.domain);
        const host = req.query.host ? normalizeDomain(req.query.host) : undefined;
        const a = await analyzeSmtp(actionDns(ctx), domain, { host, ehloName: ctx.config.mail.domain });
        return store(ctx, buildResult('smtp', host ? `${domain} ${host}` : domain, started, a));
      }),
    );
  },
};
