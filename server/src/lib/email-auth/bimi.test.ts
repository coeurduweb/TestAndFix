import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import type { SafeFetchResult } from '../net.js';
import { analyzeBimi, checkSvgTinyPs, checkVmc, markTypeOf } from './bimi.js';
import { GuardedResolver } from './common.js';
import { FakeDns, type FakeZone } from './fake-dns.js';

const GOOD_SVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100" width="100" height="100">
  <title>Exemple</title><desc>Logo Exemple</desc>
  <rect width="100" height="100" fill="#ffffff"/><circle cx="50" cy="50" r="40" fill="#cc0000"/>
</svg>`;

const ids = (a: { issues: { id: string }[] }) => a.issues.map((i) => i.id).sort();
const res = (body: string, status = 200, headers: Record<string, string> = {}): SafeFetchResult => ({ url: '', status, headers, body: Buffer.from(body), truncated: false, ms: 1 });

describe('SVG Tiny PS profile', () => {
  it('accepts a conforming logo', () => {
    const r = checkSvgTinyPs(GOOD_SVG);
    expect(r.problems).toEqual([]);
    expect(r).toMatchObject({ baseProfile: 'tiny-ps', version: '1.2', title: 'Exemple', square: true });
  });
  it('reports every forbidden construct', () => {
    const bad = `<svg xmlns="http://www.w3.org/2000/svg" version="1.1" x="0" y="0" viewBox="0 0 200 100" zoomAndPan="magnify">
      <script>alert(1)</script><image href="https://evil.test/a.png"/><animate attributeName="x"/><a href="https://x.test">x</a>
      <rect onclick="x()" width="1" height="1"/></svg>`;
    const r = checkSvgTinyPs(bad);
    const text = r.problems.join('\n');
    for (const p of ['baseProfile', 'version="1.1"', 'x= ou y=', '<title>', '<script>', '<image>', '<animate>', '<a>', 'zoomAndPan', 'événement', 'référence externe'])
      expect(text).toContain(p);
    expect(r.warnings.join('\n')).toMatch(/non carré/);
  });
});

describe('BIMI (simulated DNS and HTTP)', () => {
  const zone = (dmarc: string): FakeZone => ({
    'default._bimi.example.fr': { TXT: ['v=BIMI1; l=https://example.fr/logo.svg; a=https://example.fr/vmc.pem'] },
    '_dmarc.example.fr': { TXT: [dmarc] },
  });
  const fetcher = async (url: string) => (url.endsWith('.svg') ? res(GOOD_SVG) : res('not a pem'));
  it('checks DMARC prerequisites', async () => {
    const a = await analyzeBimi(new FakeDns(zone('v=DMARC1; p=none; rua=mailto:d@example.fr')), 'example.fr', { fetcher });
    expect(ids(a)).toContain('bimi.dmarc_not_enforced');
    const q = await analyzeBimi(new FakeDns(zone('v=DMARC1; p=quarantine; pct=50; rua=mailto:d@example.fr')), 'example.fr', { fetcher });
    expect(ids(q)).toContain('bimi.dmarc_pct_below_100');
    const sp = await analyzeBimi(new FakeDns(zone('v=DMARC1; p=reject; sp=none; rua=mailto:d@example.fr')), 'example.fr', { fetcher });
    expect(ids(sp)).toContain('bimi.dmarc_subdomain_none');
    const ok = await analyzeBimi(new FakeDns(zone('v=DMARC1; p=reject; rua=mailto:d@example.fr')), 'example.fr', { fetcher });
    expect(ok.data.dmarcEligible).toBe(true);
    expect(ids(ok)).toEqual(['bimi.certificate_invalid']);
    expect(ok.passed.map((p) => p.id)).toEqual(expect.arrayContaining(['bimi.dmarc', 'bimi.svg']));
  });
  it('reports missing, declined, non-https and unreachable logos', async () => {
    expect(ids(await analyzeBimi(new FakeDns({}), 'example.fr', { fetcher }))).toEqual(['bimi.missing_dmarc_not_enforced']);
    expect(ids(await analyzeBimi(new FakeDns({ '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject'] } }), 'example.fr', { fetcher }))).toEqual(['bimi.missing']);
    expect(ids(await analyzeBimi(new FakeDns({ 'default._bimi.example.fr': { TXT: ['v=BIMI1; l=; a=;'] } }), 'example.fr', { fetcher }))).toEqual(['bimi.declined']);
    const http = await analyzeBimi(new FakeDns({ 'default._bimi.example.fr': { TXT: ['v=BIMI1; l=http://example.fr/l.svg'] }, '_dmarc.example.fr': { TXT: ['v=DMARC1; p=reject'] } }), 'example.fr', { fetcher });
    expect(ids(http)).toEqual(['bimi.logo_not_https', 'bimi.no_certificate']);
    const down = await analyzeBimi(new FakeDns(zone('v=DMARC1; p=reject')), 'example.fr', { fetcher: async () => res('', 404) });
    expect(ids(down)).toEqual(['bimi.certificate_invalid', 'bimi.logo_unreachable']);
  });
  it('reads the mark type of a certificate', () => {
    // SEQUENCE { OID 1.3.6.1.4.1.53087.1.13, UTF8String "Registered Mark" }
    const der = Buffer.concat([Buffer.from('060a2b06010401839e5f010d0c0f', 'hex'), Buffer.from('Registered Mark')]);
    expect(markTypeOf(der)).toBe('Registered Mark');
    expect(checkVmc('garbage', 'example.fr').problems[0]).toMatch(/aucun certificat/);
  });
});

describe('BIMI live', () => {
  it('validates the BIMI of cnn.com, its SVG and its VMC (published 2026-11-10)', async () => {
    const s = new GuardedResolver(new ResolveSession(), () => new ResolveSession());
    const a = await analyzeBimi(s, 'cnn.com', { session: s });
    if (!a.data.record) return; // record withdrawn since: nothing left to check
    expect(a.data.svg?.status).toBe(200);
    expect(a.data.svg?.baseProfile).toBe('tiny-ps');
    if (a.data.vmc?.status === 200) {
      expect(a.data.vmc.certificates.length).toBeGreaterThan(0);
      expect(a.data.vmc.bimiEku).toBe(true);
      expect(['VMC', 'CMC']).toContain(a.data.vmc.kind);
    }
  });
});
