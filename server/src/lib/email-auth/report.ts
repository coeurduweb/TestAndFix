// Turns an analysis into the CheckResult envelope, stores it in the history, and maps input errors
// to HTTP 400. Shared by the domain tools (spf, dkim, dmarc, bimi, mta-sts, dns, smtp, rdap, domain).
import type { FastifyReply } from 'fastify';
import { saveResult } from '../../db.js';
import { scoreOf, sortFindings } from '../../knowledge/engine.js';
import type { CheckResult, ToolContext } from '../../tools/types.js';
import { DeadlineError, GuardedResolver, InvalidInputError, deadline, issue, toFindings, type Analysis, type Resolver } from './common.js';

export function measuredAt(d = new Date()): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function buildResult<D>(
  tool: string,
  input: string,
  started: number,
  a: Analysis & { data: D },
  opts: { score?: boolean } = {},
): CheckResult<D> {
  const findings = sortFindings(toFindings(a.issues));
  return {
    tool,
    input,
    measuredAt: measuredAt(),
    score: opts.score === false ? undefined : Math.min(scoreOf(findings), a.scoreCap ?? 10),
    findings,
    passed: a.passed,
    unavailable: a.unavailable?.length ? a.unavailable : undefined,
    data: a.data,
    ms: Math.round(performance.now() - started),
  };
}

/** Store the result in the history (90-day retention) and return it with its id. */
export function store<D>(ctx: ToolContext, r: CheckResult<D>): CheckResult<D> {
  try {
    const counts: Record<string, number> = {};
    for (const f of r.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    r.resultId = saveResult(r.tool, r.input, r, { score: r.score ?? null, summary: { findings: counts, passed: r.passed.length } }, ctx.db);
  } catch {
    /* history is a convenience: a storage failure never hides the result */
  }
  return r;
}

export async function respond<T>(reply: FastifyReply, fn: () => Promise<T>, timeoutMs = 45000): Promise<T | FastifyReply> {
  try {
    return await deadline(fn(), timeoutMs, 'Analyse');
  } catch (e) {
    if (e instanceof InvalidInputError) return reply.code(400).send({ error: 'invalid_input', message: e.message });
    if (e instanceof DeadlineError) return reply.code(504).send({ error: 'timeout', message: e.message });
    throw e;
  }
}

/** The DNS session of one user action (ctx.dns()), guarded against stalled lookups. */
export function actionDns(ctx: ToolContext, opts?: { dnssec?: boolean }): GuardedResolver {
  return new GuardedResolver(ctx.dns(opts), () => ctx.dns(opts));
}

/**
 * Same existence test as the domain scanner: a name that does not exist gets one verdict, a score
 * of 0 and no proposal (review of 2026-11-10: /dmarc/<NXDOMAIN> gave 8.5/10 and a record to publish).
 * Returns undefined when the name exists or the test is inconclusive.
 */
export async function nxdomainResult(dns: Resolver, tool: string, domain: string, started: number): Promise<CheckResult<{ domain: string; exists: false }> | undefined> {
  const r = await dns.resolve(domain, 'SOA').catch(() => undefined);
  if (r?.rcode !== 'NXDOMAIN') return undefined;
  const res = buildResult(tool, domain, started, {
    issues: [issue('mx.domain_nxdomain', { domain })],
    passed: [],
    data: { domain, exists: false as const },
  });
  res.score = 0;
  return res;
}
