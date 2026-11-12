// Link (phishing) check (US-066) and domain lists (US-067).
//
// GET /api/link/check?url=...[&submit=1]   JSON result
// GET /api/link/stream?url=...[&submit=1]  SSE: `start`, `step` (one per hop, then one per
//                                          source or stage), `done`
// GET /api/link/domain/:domain             domain on Spamhaus DBL, SURBL, URIBL...
// submit=1 sends an URL unknown to VirusTotal for analysis (it then becomes public there).
import { browserAcceptLanguage, t } from '../../i18n.js';
import net from 'node:net';
import type { FastifyReply } from 'fastify';
import { InvalidInputError, lookupAddresses, normalizeDomain } from '../../lib/email-auth/common.js';
import { analyzeRdap } from '../../lib/email-auth/rdap.js';
import { actionDns, buildResult, respond, store } from '../../lib/email-auth/report.js';
import { isPublicIp, safeGet } from '../../lib/net.js';
import { guardedDnsblResolver } from '../../lib/reputation/dnsbl-lists.js';
import { assertPublicUrl } from '../../lib/reputation/source.js';
import { openSse } from '../../lib/sse.js';
import type { ServerTool, ToolContext } from '../types.js';
import { analyzeLink, LINK_STEPS, normalizeLinkInput, type LinkDeps } from './analyze.js';
import { analyzeDomainLists } from './domain.js';

// the page is read in the reader's language, as their browser would (i18n.ts)
const pageHeaders = () => ({ accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'accept-language': browserAcceptLanguage() });

export function linkDeps(ctx: ToolContext, submit = false): LinkDeps {
  const dns = actionDns(ctx);
  return {
    // safeGet refuses private addresses behind a host name; an IP written in the URL bypasses
    // its lookup, hence assertPublicUrl first (resolveHost below checks it too)
    fetch: async (url, o) => {
      assertPublicUrl(url);
      return safeGet(url, { session: dns.current, maxBytes: o.maxBytes, headers: pageHeaders() });
    },
    resolveHost: async (host) => {
      if (net.isIP(host)) return isPublicIp(host) ? { ip: host } : { ip: host, unsafe: true, error: t('Adresse non publique refusée : {ip}', { ip: host }) };
      const a = await lookupAddresses(dns, host, ['A', 'AAAA']);
      const ip = a.ips.find((x) => net.isIPv4(x)) ?? a.ips[0];
      if (!ip) return { error: a.rcode === 'NXDOMAIN' ? t('le domaine {host} n’existe pas (NXDOMAIN)', { host }) : t('aucune adresse IP pour {host}', { host }) + (a.error ? ` (${a.error})` : '') };
      if (!isPublicIp(ip)) return { ip, unsafe: true, error: t('Adresse non publique refusée : {ip}', { ip }) };
      return { ip };
    },
    rdap: async (d) => {
      const a = await analyzeRdap(d, { session: dns });
      return {
        ageDays: a.data.ageDays,
        created: a.data.created,
        registrar: a.data.registrar?.name,
        unavailable: a.unavailable?.[0]?.reason,
        notRegistered: a.issues.some((i) => i.id === 'infrastructure.domain_not_registered'),
      };
    },
    dnsblResolverFor: guardedDnsblResolver(() => ctx.dns()),
    keys: { safeBrowsing: ctx.config.keys.safeBrowsing, virusTotal: ctx.config.keys.virusTotal, urlhaus: ctx.config.keys.urlhaus },
    submitToVirusTotal: submit,
  };
}

const yes = (v?: string) => v === '1' || v === 'true' || v === 'yes';

function missingUrl(): never {
  throw new InvalidInputError(t('Paramètre « url » attendu : le lien à vérifier.'));
}

export const tool: ServerTool = {
  id: 'link',
  register(app, ctx) {
    app.get<{ Querystring: { url?: string; submit?: string } }>('/api/link/check', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const raw = req.query.url?.trim() || missingUrl();
        const a = await analyzeLink(raw, linkDeps(ctx, yes(req.query.submit)));
        return store(ctx, buildResult('link', a.data.url, started, a));
      }, 120000),
    );
    app.get<{ Querystring: { url?: string; submit?: string } }>('/api/link/stream', async (req, reply: FastifyReply) => {
      let url: string;
      try {
        url = normalizeLinkInput(req.query.url?.trim() || missingUrl()).url;
      } catch (e) {
        if (e instanceof InvalidInputError) return reply.code(400).send({ error: 'invalid_input', message: e.message });
        throw e;
      }
      const sse = openSse(req, reply);
      sse.send('start', { url, steps: LINK_STEPS.map((s) => ({ id: s.id, label: t(s.label) })) });
      try {
        const started = performance.now();
        const a = await analyzeLink(url, linkDeps(ctx, yes(req.query.submit)), { onStep: (s) => sse.send('step', s), signal: sse.signal });
        if (!sse.closed) sse.send('done', store(ctx, buildResult('link', a.data.url, started, a)));
      } catch (e) {
        sse.send('error', { message: (e as Error).message });
      } finally {
        sse.close();
      }
    });
    app.get<{ Params: { domain: string } }>('/api/link/domain/:domain', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const domain = normalizeDomain(req.params.domain);
        return store(ctx, buildResult('link', domain, started, await analyzeDomainLists(domain, guardedDnsblResolver(() => ctx.dns()))));
      }),
    );
  },
};
