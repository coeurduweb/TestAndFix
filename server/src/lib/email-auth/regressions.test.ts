// False alarms found by hand (dig) on 2026-11-10 by the agent who built the domain pages.
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { explain } from '../../knowledge/engine.js';
import { analyzeBimi } from './bimi.js';
import { GuardedResolver, toFindings } from './common.js';
import { analyzeDkim } from './dkim.js';
import { FakeDns } from './fake-dns.js';
import { analyzeMtaSts } from './mtasts.js';
import { analyzeMx } from './mx.js';

const rsa = (bits: number) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const live = () => new GuardedResolver(new ResolveSession(), () => new ResolveSession());

describe('regressions 2026-11-10', () => {
  it('1. cnn.com: the Microsoft 365 MX resolves (EDNS FORMERR retry)', async () => {
    const a = await analyzeMx(live(), 'cnn.com');
    expect(a.issues.map((i) => i.id)).not.toContain('mx.target_nxdomain');
    expect(a.data.hosts.length).toBeGreaterThan(0);
    expect(a.data.hosts.every((h) => h.ipv4.length > 0)).toBe(true);
  });
  it('2. no "MTA-STS without TLS-RPT" when MTA-STS is absent', async () => {
    const a = await analyzeMtaSts(new FakeDns({ 'example.fr': { MX: [] } }), 'example.fr');
    expect(a.issues.map((i) => i.id)).toEqual(['mta-sts.missing']);
  });
  it('3. bimi.missing does not claim DMARC is enforced when p=none, and paths agree', async () => {
    const a = await analyzeBimi(new FakeDns({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=none'] } }), 'example.fr');
    const f = toFindings(a.issues);
    expect(f.map((x) => x.id)).not.toContain('bimi.missing');
    expect(f.map((x) => x.why).join(' ')).not.toMatch(/Votre DMARC est appliqué/);
    const ok = toFindings((await analyzeBimi(new FakeDns({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject'] } }), 'example.fr')).issues);
    const m = ok.find((x) => x.id === 'bimi.missing')!;
    const paths = [...[...m.fix, m.suggested ?? '', m.exampleGood ?? ''].join(' ').matchAll(/https:\/\/example\.fr(\/[^\s;"]+\.svg)/g)].map((x) => x[1]);
    expect(new Set(paths).size).toBe(1);
  });
  it('5. DKIM: titles name the selector; a CNAME provider wins over the selector list', async () => {
    const dns = new FakeDns({
      's1._domainkey.example.fr': { CNAME: ['s1.example.custdkim.salesforce.com'] },
      's1.example.custdkim.salesforce.com': { TXT: [`v=DKIM1; p=${rsa(1024)}`] },
      's2._domainkey.example.fr': { TXT: [`v=DKIM1; p=${rsa(1024)}`] },
    });
    const a = await analyzeDkim(dns, 'example.fr');
    const titles = toFindings(a.issues).filter((f) => f.id === 'dkim.key_1024').map((f) => f.title);
    expect(titles.length).toBe(2);
    expect(new Set(titles).size).toBe(2);
    const s1 = a.data.keys.find((k) => k.selector === 's1')!;
    expect(s1.cnameProvider).toBe('salesforce');
    expect(s1.knownFor).toEqual(['salesforce']);
  });
  it('6. a revoked key next to valid ones costs nothing; alone it is penalised', async () => {
    const both = await analyzeDkim(new FakeDns({ 'old._domainkey.example.fr': { TXT: ['v=DKIM1; p='] }, 'google._domainkey.example.fr': { TXT: [`v=DKIM1; p=${rsa(2048)}`] } }), 'example.fr', { selectors: ['old'] });
    expect(toFindings(both.issues).find((f) => f.id === 'dkim.key_revoked')).toMatchObject({ severity: 'info', penalty: 0 });
    const alone = await analyzeDkim(new FakeDns({ 'old._domainkey.example.fr': { TXT: ['v=DKIM1; p='] } }), 'example.fr', { selectors: ['old'] });
    expect(toFindings(alone.issues).find((f) => f.id === 'dkim.key_revoked')!.penalty).toBeGreaterThan(0);
  });
  it('6. gmail.com: revoked rotation keys cost at most one penalty (live)', async () => {
    // 2026-11-10: 20230601, 20221208, 20210112 and 20161025 are all revoked on gmail.com and the
    // active selector is none of the known ones
    const a = await analyzeDkim(live(), 'gmail.com', { selectors: ['20230601'] });
    const revoked = toFindings(a.issues).filter((x) => x.id === 'dkim.key_revoked');
    expect(revoked.length).toBeGreaterThan(0);
    const lost = revoked.reduce((n, f) => n + f.penalty, 0);
    if (a.data.keys.some((k) => !k.revoked && !k.error)) expect(lost).toBe(0);
    else expect(lost).toBeLessThanOrEqual(1.5);
  });
  it('explain keeps the base severity when the analyzer does not override it', () => {
    expect(explain({ id: 'dkim.key_1024', vars: {} }).penalty).toBe(0.3);
  });
});

describe('regressions 2026-11-10, DNSSEC of a missing name', () => {
  it('4. does not measure the parent zone of a name that does not exist (live)', async () => {
    const { analyzeDnssec } = await import('./dnssec.js');
    const a = await analyzeDnssec(live(), `check-nx-${Date.now().toString(36)}.fr`);
    expect(a.data.chain).toEqual([]);
    expect(a.passed).toEqual([]);
    expect(a.unavailable?.[0].reason).toMatch(/n’existe pas/);
  });
});
