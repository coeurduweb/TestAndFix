// One real measurement against the public CT services and the real DNS. Outside the automatic suite
// (crt.name allows 100 requests per IP per day, Cert Spotter a few per hour without a key):
//   CHECK_LIVE=1 npx vitest run src/tools/subdomains/live.test.ts
// A source that is down is tolerated: the test only requires that one source answered.
import { describe, expect, it } from 'vitest';
import { config } from '../../config.js';
import { ResolveSession } from '../../dns/iterative.js';
import { openDb } from '../../db.js';
import type { ToolContext } from '../types.js';
import { analyzeSubdomains } from './analyze.js';
import { subdomainsDeps } from './index.js';

const domain = process.env.CHECK_LIVE_DOMAIN ?? 'exemple-agence.com';

describe.skipIf(!process.env.CHECK_LIVE)(`live: ${domain}`, () => {
  it('lists subdomains from at least one CT source and resolves them', { timeout: 240000 }, async () => {
    const ctx: ToolContext = { db: openDb(':memory:'), config, dns: (o) => new ResolveSession(o) };
    const started = Date.now();
    const a = await analyzeSubdomains(domain, subdomainsDeps(ctx));
    const d = a.data;
    console.log(
      JSON.stringify(
        {
          seconds: Math.round((Date.now() - started) / 1000),
          sources: d.sources.map((s) => `${s.label}: ${s.status} ${s.names} noms ${s.certs} certs ${s.ms} ms${s.error ? ` (${s.error})` : ''}`),
          total: d.total,
          resolved: d.resolved,
          counts: d.counts,
          wildcardDns: d.wildcardDns,
          issues: a.issues.map((i) => `${i.id} ${JSON.stringify(i.vars)}`),
          sample: d.subdomains.slice(0, 5).map((r) => `${r.name} ${r.dns?.status} ${[...(r.dns?.cname ?? []), ...(r.dns?.a ?? [])].join(' ')} ${r.lastCert?.issuerShort ?? ''}`),
        },
        null,
        2,
      ),
    );
    expect(d.sources.some((s) => s.status === 'ok')).toBe(true);
    expect(d.total).toBeGreaterThan(0);
    expect(d.resolved).toBeGreaterThan(0);
  });
});
