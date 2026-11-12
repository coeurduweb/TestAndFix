// Second review (dig + curl) of 2026-11-10: wrong corrections and scores.
import { generateKeyPairSync } from 'node:crypto';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { config } from '../../config.js';
import { openDb } from '../../db.js';
import { ResolveSession } from '../../dns/iterative.js';
import type { CheckResult, ServerTool } from '../../tools/types.js';
import { GuardedResolver, toFindings } from './common.js';
import { analyzeDkim } from './dkim.js';
import { analyzeDmarc } from './dmarc.js';
import { analyzeDnssec } from './dnssec.js';
import { FakeDns } from './fake-dns.js';
import { analyzeMtaSts } from './mtasts.js';
import { buildResult } from './report.js';
import { analyzeSmtp, port25Reachable } from './smtp-probe.js';
import { tool as spfTool } from '../../tools/spf/index.js';
import { tool as dkimTool } from '../../tools/dkim/index.js';
import { tool as dmarcTool } from '../../tools/dmarc/index.js';
import { tool as bimiTool } from '../../tools/bimi/index.js';
import { tool as mtaStsTool } from '../../tools/mta-sts/index.js';

const rsa = (bits: number) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const live = () => new GuardedResolver(new ResolveSession(), () => new ResolveSession());

describe('review 2, 2026-11-10', () => {
  it('1. DMARC suggestion keeps sp, np, alignment and ruf, moves p up and keeps the measured rua', async () => {
    const a = await analyzeDmarc(new FakeDns({ '_dmarc.gmail.test': { TXT: ['v=DMARC1; p=none; sp=quarantine; np=reject; adkim=s; rua=mailto:reports@google.test; ruf=mailto:f@google.test'] } }), 'gmail.test');
    expect(a.data.suggested).toBe('v=DMARC1; p=quarantine; sp=quarantine; np=reject; adkim=s; rua=mailto:reports@google.test; ruf=mailto:f@google.test');
    expect(a.data.plan.map((p) => p.record)).toEqual([
      'v=DMARC1; p=quarantine; sp=quarantine; np=reject; adkim=s; rua=mailto:reports@google.test; ruf=mailto:f@google.test',
      // sp=quarantine is weaker than p=reject: dropped (arbitration of 2026-11-10)
      'v=DMARC1; p=reject; np=reject; adkim=s; rua=mailto:reports@google.test; ruf=mailto:f@google.test',
    ]);
    const f = toFindings(a.issues).find((x) => x.id === 'dmarc.policy_none')!;
    expect(f.suggested).toBe(a.data.suggested);
    // no generic example with an invented address next to a computed correction
    expect(f.exampleGood ?? '').not.toMatch(/dmarc@gmail\.test/);
  });

  it('2. a domain that does not exist: verdict, score 0, no proposal, in every checker', async () => {
    const tools: ServerTool[] = [spfTool, dkimTool, dmarcTool, bimiTool, mtaStsTool];
    const app = Fastify();
    const ctx = { db: openDb(':memory:'), config, dns: (o?: object) => new ResolveSession(o) };
    for (const t of tools) await t.register!(app, ctx);
    const nx = `check-nx-${Date.now().toString(36)}.fr`;
    for (const t of ['spf', 'dkim', 'dmarc', 'bimi', 'mta-sts']) {
      const r = (await app.inject(`/api/${t}/${nx}`)).json() as CheckResult<{ exists?: boolean }>;
      expect(r.score, t).toBe(0);
      expect(r.data.exists, t).toBe(false);
      expect(r.findings.map((f) => f.id), t).toEqual(['mx.domain_nxdomain']);
      expect(r.findings.every((f) => !f.suggested), t).toBe(true);
    }
  }, 60000);

  it('3. a dangling Microsoft 365 CNAME next to a valid selector1: provider steps, DNS host from NS, lower severity', async () => {
    const dns = new FakeDns({
      'example.fr': { NS: ['ns-1.awsdns-01.org', 'ns-2.awsdns-02.com'] },
      'selector1._domainkey.example.fr': { CNAME: ['selector1-example-fr._domainkey.contoso.n-v1.dkim.mail.microsoft'] },
      'selector1-example-fr._domainkey.contoso.n-v1.dkim.mail.microsoft': { TXT: [`v=DKIM1; k=rsa; p=${rsa(2048)}`] },
      'selector2._domainkey.example.fr': { CNAME: ['selector2-example-fr._domainkey.contoso.n-v1.dkim.mail.microsoft'] },
    });
    const a = await analyzeDkim(dns, 'example.fr');
    const f = toFindings(a.issues).find((x) => x.title.includes('selector2'))!;
    expect(f.severity).toBe('medium');
    const text = [f.why, ...f.fix, f.providerFix?.text ?? ''].join('\n');
    expect(text).toMatch(/Route 53/);
    expect(text).toMatch(/Defender/);
    expect(text).not.toMatch(/Cloudflare|SES/);
    expect(text).not.toMatch(/la signature .*échoue/);
    expect(f.references.join(' ')).not.toMatch(/amazon|cloudflare/);
  });

  it('3. the Cloudflare step appears only when the zone is at Cloudflare', async () => {
    const dns = new FakeDns({ 'example.fr': { NS: ['ada.ns.cloudflare.com'] }, 'k1._domainkey.example.fr': { CNAME: ['dkim.gone.test'] } });
    const f = toFindings((await analyzeDkim(dns, 'example.fr')).issues).find((x) => x.title.includes('k1'))!;
    expect(f.severity).toBe('high');
    expect(f.fix.join('\n')).toMatch(/DNS only/);
  });

  it('4. MTA-STS: the suggestion is the complete corrected policy and a new _mta-sts TXT', async () => {
    const a = await analyzeMtaSts(
      new FakeDns({ '_mta-sts.example.fr': { TXT: ['v=STSv1; id=1'] }, '_smtp._tls.example.fr': { TXT: ['v=TLSRPTv1; rua=mailto:t@example.fr'] }, 'example.fr': { MX: [{ preference: 10, exchange: 'mx1.example.fr' }] } }),
      'example.fr',
      { fetchPolicy: async () => ({ url: '', status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('version: STSv1\nmode: enforce\nmx: *.example.fr\nmax_age: 86400\n'), truncated: false, ms: 1 }) },
    );
    const s = toFindings(a.issues).find((x) => x.id === 'mta-sts.max_age_short')!.suggested!;
    expect(s).toContain('version: STSv1\nmode: enforce\nmx: *.example.fr\nmax_age: 604800');
    expect(s).toMatch(/_mta-sts\.example\.fr\. IN TXT "v=STSv1; id=\d{14}"/);
    expect(a.data.suggestedTxt).not.toBe('v=STSv1; id=1');
  });

  it('5. a bogus chain caps the score at 2 and the DS to publish is copyable (live)', async () => {
    const a = await analyzeDnssec(live(), 'dnssec-failed.org');
    expect(a.data.status).toBe('bogus');
    const r = buildResult('dns', 'dnssec-failed.org', performance.now(), a);
    expect(r.score!).toBeLessThanOrEqual(2);
    const f = r.findings.find((x) => x.id === 'dnssec.ds_mismatch')!;
    expect(f.suggested).toMatch(/^dnssec-failed\.org\. IN DS \d+ 13 2 [0-9A-F]{64}$/m);
  });

  it('6. SMTP evidence names the Gmail and iCloud reference MX', async () => {
    const r = await port25Reachable([{ name: 'gmail-smtp-in.l.google.com', label: 'MX de référence Gmail', ip: '192.0.2.1' }], 300);
    expect(r.detail).toMatch(/^gmail-smtp-in\.l\.google\.com \(MX de référence Gmail, 192\.0\.2\.1\)/);
    const a = await analyzeSmtp(new FakeDns({ 'example.fr': { MX: [] }, 'gmail-smtp-in.l.google.com': { A: ['192.0.2.1'] }, 'mx1.mail.icloud.com': { A: ['192.0.2.2'] } }), 'example.fr', { timeoutMs: 300 });
    expect(a.unavailable?.[0].reason).toMatch(/Gmail/);
    expect(a.unavailable?.[0].reason).toMatch(/iCloud/);
  });
});

describe('review 2, sp arbitration (2026-11-10)', () => {
  it('keeps sp while it is at least as strict as p, drops it with a sentence once p is stricter', async () => {
    const a = await analyzeDmarc(new FakeDns({ '_dmarc.x.test': { TXT: ['v=DMARC1; p=none; sp=quarantine; rua=mailto:r@x.test'] } }), 'x.test');
    expect(a.data.plan.map((p) => p.record)).toEqual(['v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:r@x.test', 'v=DMARC1; p=reject; rua=mailto:r@x.test']);
    expect(a.data.plan[1].when).toBe('après quelques semaines en quarantaine sans faux positif. sp=quarantine est retiré : les sous-domaines suivent désormais p=reject.');
    // the step without a note stays a fragment, with no stray punctuation
    expect(a.data.plan[0].when).toBe('quand les rapports ne montrent plus d’envois légitimes en échec');
    // no step is flagged by our own base
    for (const step of a.data.plan) {
      const b = await analyzeDmarc(new FakeDns({ '_dmarc.x.test': { TXT: [step.record] } }), 'x.test');
      expect(b.issues.map((i) => i.id)).not.toContain('dmarc.sp_weaker');
    }
  });
  it('applies to gmail.com (live, sp=quarantine published on 2026-11-10)', async () => {
    const a = await analyzeDmarc(live(), 'gmail.com');
    const sp = /sp=(\w+)/.exec(a.data.record ?? '')?.[1];
    for (const step of a.data.plan) {
      const p = /p=(\w+)/.exec(step.record)![1];
      const rank = ['none', 'quarantine', 'reject'];
      if (sp && rank.indexOf(sp) < rank.indexOf(p)) {
        expect(step.record).not.toMatch(/sp=/);
        expect(step.when).toContain(`sp=${sp} est retiré`);
      } else if (sp) expect(step.record).toContain(`sp=${sp}`);
    }
  });
});
