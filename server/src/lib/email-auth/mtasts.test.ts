import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import type { SafeFetchResult } from '../net.js';
import { GuardedResolver } from './common.js';
import { FakeDns, type FakeZone } from './fake-dns.js';
import { analyzeMtaSts, mxMatches, parsePolicy } from './mtasts.js';

const res = (body: string, status = 200, headers: Record<string, string> = { 'content-type': 'text/plain' }): SafeFetchResult => ({ url: '', status, headers, body: Buffer.from(body), truncated: false, ms: 1 });
const ids = (a: { issues: { id: string }[] }) => a.issues.map((i) => i.id).sort();
const zone: FakeZone = {
  '_mta-sts.example.fr': { TXT: ['v=STSv1; id=20261110'] },
  '_smtp._tls.example.fr': { TXT: ['v=TLSRPTv1; rua=mailto:tls@example.fr'] },
  'example.fr': { MX: [{ preference: 10, exchange: 'mx1.example.fr' }, { preference: 20, exchange: 'backup.other.test' }] },
};

describe('MTA-STS', () => {
  it('parses a policy and matches MX patterns (RFC 8461 §4.1)', () => {
    const p = parsePolicy('version: STSv1\r\nmode: enforce\r\nmx: *.example.fr\r\nmx: mail.other.test\r\nmax_age: 604800\r\n');
    expect(p).toMatchObject({ version: 'STSv1', mode: 'enforce', mx: ['*.example.fr', 'mail.other.test'], maxAge: 604800, errors: [] });
    expect(mxMatches('mx1.example.fr', '*.example.fr')).toBe(true);
    expect(mxMatches('a.b.example.fr', '*.example.fr')).toBe(false);
    expect(mxMatches('example.fr', '*.example.fr')).toBe(false);
    expect(parsePolicy('mode: strict\n').errors.length).toBeGreaterThan(1);
  });
  it('flags MX not covered, short max_age and wrong content type', async () => {
    const a = await analyzeMtaSts(new FakeDns(zone), 'example.fr', {
      fetchPolicy: async () => res('version: STSv1\nmode: enforce\nmx: *.example.fr\nmax_age: 86400\n', 200, { 'content-type': 'text/html' }),
    });
    expect(ids(a)).toEqual(['mta-sts.max_age_short', 'mta-sts.mx_not_covered', 'mta-sts.wrong_content_type']);
    expect(a.data.mx.map((m) => m.covered)).toEqual([true, false]);
    expect(a.issues.find((i) => i.id === 'mta-sts.mx_not_covered')?.suggested).toContain('mx: backup.other.test');
  });
  it('flags redirects, HTTP errors, malformed records and missing TLS-RPT', async () => {
    expect(ids(await analyzeMtaSts(new FakeDns(zone), 'example.fr', { fetchPolicy: async () => res('', 301, { location: 'https://x.test/' }) }))).toEqual(['mta-sts.policy_redirect']);
    expect(ids(await analyzeMtaSts(new FakeDns(zone), 'example.fr', { fetchPolicy: async () => res('', 404) }))).toEqual(['mta-sts.policy_unreachable']);
    const z2: FakeZone = { ...zone, '_mta-sts.example.fr': { TXT: ['v=STSv1; id=bad-id!'] }, '_smtp._tls.example.fr': {} };
    const a = await analyzeMtaSts(new FakeDns(z2), 'example.fr', { fetchPolicy: async () => res('version: STSv1\nmode: testing\nmx: *.example.fr\nmx: backup.other.test\nmax_age: 604800\n') });
    expect(ids(a)).toEqual(['mta-sts.testing_mode', 'mta-sts.tlsrpt_missing', 'mta-sts.txt_malformed']);
    const err = await analyzeMtaSts(new FakeDns(zone), 'example.fr', { fetchPolicy: async () => Promise.reject(Object.assign(new Error('fetch failed'), { cause: { code: 'CERT_HAS_EXPIRED', message: 'certificate has expired' } })) });
    expect(ids(err)).toEqual(['mta-sts.policy_cert_invalid']);
    expect(ids(await analyzeMtaSts(new FakeDns({}), 'example.fr'))).toEqual(['mta-sts.missing']);
  });
});

describe('MTA-STS live', () => {
  it('reads the gmail.com policy over HTTPS and covers its MX', async () => {
    const s = new GuardedResolver(new ResolveSession(), () => new ResolveSession());
    const a = await analyzeMtaSts(s, 'gmail.com', { session: s });
    expect(a.data.record).toMatch(/^v=STSv1/);
    expect(a.data.fetch?.status).toBe(200);
    expect(['enforce', 'testing']).toContain(a.data.policy?.mode);
    expect(a.data.mx.every((m) => m.covered)).toBe(true);
    expect(a.data.tlsrpt.record).toMatch(/^v=TLSRPTv1/);
  });
});
