// BIMI checker (US-045).
import { t } from '../../i18n.js';
import type { ServerTool } from '../types.js';
import { InvalidInputError, normalizeDomain } from '../../lib/email-auth/common.js';
import { analyzeBimi } from '../../lib/email-auth/bimi.js';
import { actionDns, buildResult, nxdomainResult, respond, store } from '../../lib/email-auth/report.js';

export const tool: ServerTool = {
  id: 'bimi',
  register(app, ctx) {
    app.get<{ Params: { domain: string }; Querystring: { selector?: string } }>('/api/bimi/:domain', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const domain = normalizeDomain(req.params.domain);
        const selector = req.query.selector?.trim() || 'default';
        if (!/^[a-z0-9_-]{1,63}$/i.test(selector)) throw new InvalidInputError(t('Sélecteur BIMI « {selector} » invalide.', { selector }));
        const session = actionDns(ctx);
        const nx = await nxdomainResult(session, 'bimi', domain, started);
        if (nx) return store(ctx, nx);
        return store(ctx, buildResult('bimi', domain, started, await analyzeBimi(session, domain, { selector, session })));
      }),
    );
  },
};
