import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { GuardedResolver, orgDomain } from './common.js';
import { analyzeDmarc, parseReportUris } from './dmarc.js';
import { FakeDns, type FakeZone } from './fake-dns.js';

const ids = (a: { issues: { id: string }[] }) => a.issues.map((i) => i.id).sort();
const dm = (zone: FakeZone, domain = 'example.fr') => analyzeDmarc(new FakeDns(zone), domain);
const live = () => new GuardedResolver(new ResolveSession(), () => new ResolveSession());

describe('DMARC (simulated DNS)', () => {
  it('reads a complete record and explains every tag', async () => {
    const a = await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject; rua=mailto:dmarc@example.fr; adkim=r'] } });
    expect(a.issues).toEqual([]);
    expect(a.data).toMatchObject({ policy: 'reject', effectivePolicy: 'reject', subdomainPolicy: 'reject', pct: 100 });
    expect(a.data.tags.find((t) => t.name === 'p')?.meaning).toMatch(/refusés/);
    expect(a.data.tags.find((t) => t.name === 'sp')).toMatchObject({ implicit: true });
    expect(a.data.suggested).toBeUndefined();
  });
  it('suggests a first record when missing, and uses the org domain for a subdomain', async () => {
    const a = await dm({});
    expect(ids(a)).toEqual(['dmarc.missing']);
    expect(a.data.suggested).toBe('v=DMARC1; p=none; rua=mailto:dmarc@example.fr');
    expect(ids(await dm({ 'news.example.fr': {} }, 'news.example.fr'))).toEqual(['dmarc.subdomain_no_policy']);
    const inh = await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.fr'] } }, 'news.example.fr');
    expect(inh.data).toMatchObject({ inherited: true, foundAt: '_dmarc.example.fr', effectivePolicy: 'quarantine' });
    expect(ids(inh)).toEqual(['dmarc.inherited', 'dmarc.np_absent']);
  });
  it('flags several records, bad syntax and a record at the apex', async () => {
    expect(ids(await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=none', 'v=DMARC1; p=reject'] } }))).toContain('dmarc.multiple_records');
    expect(ids(await dm({ '_dmarc.example.fr': { TXT: ['v=dmarc1 p=reject'] } }))).toContain('dmarc.syntax_invalid');
    const apex = await dm({ 'example.fr': { TXT: ['v=DMARC1; p=reject'] } });
    expect(ids(apex)).toEqual(['dmarc.missing', 'dmarc.record_at_apex']);
    const bad = await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=block; pct=150; adkim=x; foo=bar; rua=mailto:a@example.fr'] } });
    expect(ids(bad)).toEqual(expect.arrayContaining(['dmarc.policy_invalid', 'dmarc.invalid_tag_value', 'dmarc.unknown_tags']));
    // RFC 7489 §6.6.3: an invalid p with a valid rua is treated as none
    expect(bad.data.policy).toBe('none');
    expect(ids(await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=none; p=reject'] } }))).toContain('dmarc.duplicate_tag');
  });
  it('flags weak policies and plans the next step', async () => {
    const none = await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=none; rua=mailto:d@example.fr'] } });
    expect(ids(none)).toEqual(['dmarc.policy_none']);
    expect(none.data.suggested).toBe('v=DMARC1; p=quarantine; rua=mailto:d@example.fr');
    expect(none.data.plan.map((p) => p.record)).toEqual(['v=DMARC1; p=quarantine; rua=mailto:d@example.fr', 'v=DMARC1; p=reject; rua=mailto:d@example.fr']);
    const pct = await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=quarantine; pct=20; rua=mailto:d@example.fr'] } });
    expect(ids(pct)).toEqual(['dmarc.np_absent', 'dmarc.pct_partial']);
    expect(pct.data.suggested).toBe('v=DMARC1; p=quarantine; rua=mailto:d@example.fr');
    expect(ids(await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject; pct=0; rua=mailto:d@example.fr'] } }))).toContain('dmarc.pct_zero');
    const sp = await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject; sp=none; rua=mailto:d@example.fr'] } });
    expect(ids(sp)).toContain('dmarc.sp_weaker');
    expect(sp.data.subdomainPolicy).toBe('none');
    expect(ids(await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject'] } }))).toEqual(['dmarc.rua_missing']);
    expect(ids(await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject; t=y; rua=mailto:d@example.fr'] } }))).toContain('dmarc.testing_flag');
  });
  it('checks external report destinations (RFC 7489 §7.1)', async () => {
    const zone: FakeZone = {
      '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject; rua=mailto:a@reports.test,mailto:b@other.test,mailto:c@example.fr; ruf=mailto:f@example.fr; ri=3600'] },
      'example.fr._report._dmarc.reports.test': { TXT: ['v=DMARC1'] },
    };
    const a = await dm(zone);
    expect(a.data.reports.map((r) => [r.address, r.external, r.authorized])).toEqual([
      ['a@reports.test', true, true],
      ['b@other.test', true, false],
      ['c@example.fr', false, undefined],
      ['f@example.fr', false, undefined],
    ]);
    expect(ids(a)).toEqual(['dmarc.obsolete_tags', 'dmarc.ruf_present', 'dmarc.rua_external_unauthorized'].sort());
    expect(ids(await dm({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject; rua=dmarc@example.fr'] } }))).toContain('dmarc.rua_invalid_uri');
  });
  it('parses report URIs with size limits', () => {
    expect(parseReportUris('rua', 'mailto:a@x.test!10m, https://r.test/dmarc', 'example.fr')).toMatchObject([
      { address: 'a@x.test', maxSize: '10m', external: true },
      { scheme: 'https', external: false },
    ]);
    expect(orgDomain('a.b.example.co.uk')).toBe('example.co.uk');
  });
  it('turns a DNS failure into temperror', async () => {
    expect(ids(await dm({ '_dmarc.example.fr': 'SERVFAIL' }))).toEqual(['dmarc.temperror']);
  });
});

describe('DMARC live', () => {
  it('reads google.com (reject) and the inherited policy of a subdomain', async () => {
    const a = await analyzeDmarc(live(), 'google.com');
    expect(a.data.policy).toBe('reject');
    const sub = await analyzeDmarc(live(), 'mail.google.com');
    expect(sub.data.inherited || sub.data.foundAt === '_dmarc.mail.google.com').toBe(true);
  });
  it('reports a domain without DMARC (nginx.org, checked 2026-11-10)', async () => {
    const a = await analyzeDmarc(live(), 'nginx.org');
    if (!a.data.record) expect(a.issues.map((i) => i.id)).toContain('dmarc.missing');
    else expect(a.data.record).toMatch(/^v=DMARC1/i);
  });
});
