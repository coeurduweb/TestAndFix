// SPF checker (US-041) and IP evaluation against a domain's SPF (US-042).
import { t } from '../../i18n.js';
import net from 'node:net';
import type { ServerTool } from '../types.js';
import { InvalidInputError, issue, normalizeDomain, pass } from '../../lib/email-auth/common.js';
import { analyzeSpf, evaluateSpf } from '../../lib/email-auth/spf.js';
import { actionDns, buildResult, nxdomainResult, respond, store } from '../../lib/email-auth/report.js';

type Q = { record?: string; ip?: string; sender?: string; helo?: string };

const EVAL_ID: Record<string, string> = {
  fail: 'spf.fail',
  softfail: 'spf.softfail',
  neutral: 'spf.eval_neutral',
  none: 'spf.missing',
  permerror: 'spf.permerror',
  temperror: 'spf.temperror',
};

export const tool: ServerTool = {
  id: 'spf',
  register(app, ctx) {
    const check = async (domainIn: string, record?: string) => {
      const started = performance.now();
      const domain = normalizeDomain(domainIn);
      const dns = actionDns(ctx);
      // a pasted draft record may target a domain not created yet: test it anyway
      if (!record?.trim()) {
        const nx = await nxdomainResult(dns, 'spf', domain, started);
        if (nx) return store(ctx, nx);
      }
      const a = await analyzeSpf(dns, domain, { record: record?.trim() || undefined });
      return store(ctx, buildResult('spf', domain, started, a));
    };
    app.get<{ Params: { domain: string }; Querystring: Q }>('/api/spf/:domain', (req, reply) =>
      respond(reply, () => check(req.params.domain, req.query.record)),
    );
    app.post<{ Body: { domain?: string; record?: string } }>('/api/spf/check', (req, reply) =>
      respond(reply, () => check(req.body?.domain ?? '', req.body?.record)),
    );
    app.get<{ Params: { domain: string }; Querystring: Q }>('/api/spf/:domain/eval', (req, reply) =>
      respond(reply, async () => {
        const started = performance.now();
        const domain = normalizeDomain(req.params.domain);
        const ip = String(req.query.ip ?? '').trim();
        if (!net.isIP(ip)) throw new InvalidInputError(t("« {ip} » n'est pas une adresse IP.", { ip }));
        const sender = req.query.sender?.trim() || undefined;
        if (sender && !/^[^\s@]+@[^\s@]+$/.test(sender)) throw new InvalidInputError(t("« {sender} » n'est pas une adresse e-mail.", { sender }));
        const dns = actionDns(ctx);
        const nx = await nxdomainResult(dns, 'spf', domain, started);
        if (nx) return store(ctx, nx);
        const r = await evaluateSpf(dns, { ip, domain, sender, helo: req.query.helo?.trim() || undefined });
        const id = EVAL_ID[r.result];
        const vars = { domain, envelope_domain: domain, ip, value: r.reason };
        const issues = id ? [issue(id, vars, { evidence: r.mechanism ? `${r.mechanism.domain} : ${r.mechanism.term}` : r.reason })] : [];
        const passed = r.result === 'pass' ? [pass('spf.eval_pass', 'spf', t('{ip} est autorisée par le SPF de {domain}', { ip, domain }), r.reason)] : [];
        return store(ctx, buildResult('spf', `${domain} ${ip}`, started, { issues, passed, data: r }, { score: false }));
      }),
    );
  },
};
