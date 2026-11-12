// Domain scanner (US-040): JSON in one response, or SSE with each section as soon as it is ready.
import { t } from '../../i18n.js';
import type { ServerTool } from '../types.js';
import { InvalidInputError, normalizeDomain } from '../../lib/email-auth/common.js';
import { actionDns, respond, store } from '../../lib/email-auth/report.js';
import { openSse } from '../../lib/sse.js';
import { SECTIONS, scanDomain } from './scan.js';
import { domainFingerprint, parseSelectors } from './fingerprint.js';

export const tool: ServerTool = {
  id: 'domain',
  register(app, ctx) {
    app.get<{ Params: { domain: string } }>('/api/domain/:domain', (req, reply) =>
      respond(reply, async () => {
        const domain = normalizeDomain(req.params.domain);
        return store(ctx, await scanDomain(actionDns(ctx), domain, { ehloName: ctx.config.mail.domain, makeSession: () => ctx.dns() }));
      }),
    );
    // Fix loop: the records that decide the domain's email, as the authoritative servers serve them now
    app.get<{ Params: { domain: string }; Querystring: { selectors?: string } }>('/api/domain/:domain/fingerprint', (req, reply) =>
      respond(reply, async () => {
        const domain = normalizeDomain(req.params.domain);
        return domainFingerprint(ctx.dns(), domain, parseSelectors(req.query.selectors));
      }),
    );
    app.get<{ Params: { domain: string } }>('/api/domain/:domain/stream', async (req, reply) => {
      let domain: string;
      try {
        domain = normalizeDomain(req.params.domain);
      } catch (e) {
        if (e instanceof InvalidInputError) return reply.code(400).send({ error: 'invalid_input', message: e.message });
        throw e;
      }
      const sse = openSse(req, reply);
      sse.send('start', { domain, sections: SECTIONS.map((s) => ({ id: s.id, title: t(s.title) })) });
      try {
        const result = await scanDomain(actionDns(ctx), domain, {
          ehloName: ctx.config.mail.domain,
          makeSession: () => ctx.dns(),
          signal: sse.signal,
          onSection: (s) => sse.send('section', s),
        });
        if (!sse.closed) sse.send('done', store(ctx, result));
      } catch (e) {
        sse.send('error', { message: (e as Error).message });
      } finally {
        sse.close();
      }
    });
  },
};
