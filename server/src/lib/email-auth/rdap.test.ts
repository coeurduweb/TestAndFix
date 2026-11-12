import { describe, expect, it } from 'vitest';
import type { SafeFetchResult } from '../net.js';
import { analyzeRdap, parseRdapDomain } from './rdap.js';

const json = (o: unknown, status = 200): SafeFetchResult => ({ url: '', status, headers: {}, body: Buffer.from(JSON.stringify(o)), truncated: false, ms: 1 });
const NOW = Date.parse('2026-11-10T00:00:00Z');
const BOOT = { services: [[['fr'], ['https://rdap.test/']], [['com'], ['https://rdap.verisign.test/com/v1/']]] };
const DOMAIN = {
  ldhName: 'EXAMPLE.FR',
  status: ['client transfer prohibited'],
  events: [
    { eventAction: 'registration', eventDate: '2026-11-01T00:00:00Z' },
    { eventAction: 'expiration', eventDate: '2026-11-20T00:00:00Z' },
  ],
  entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Registrar Test']]], publicIds: [{ type: 'IANA Registrar ID', identifier: '9999' }] }],
  nameservers: [{ ldhName: 'NS1.EXAMPLE.FR' }],
  secureDNS: { delegationSigned: true },
};

describe('RDAP', () => {
  it('parses registrar, dates and statuses', () => {
    expect(parseRdapDomain('example.fr', DOMAIN, NOW)).toMatchObject({
      registrar: { name: 'Registrar Test', ianaId: '9999' },
      ageDays: 9,
      expiresInDays: 10,
      nameservers: ['ns1.example.fr'],
      dnssecDelegated: true,
    });
  });
  it('uses the IANA bootstrap and flags a young domain about to expire', async () => {
    const urls: string[] = [];
    const fetcher = async (url: string) => {
      urls.push(url);
      return url.includes('iana') ? json(BOOT) : json(DOMAIN);
    };
    const a = await analyzeRdap('www.example.fr', { fetcher, now: NOW });
    expect(urls).toEqual(['https://data.iana.org/rdap/dns.json', 'https://rdap.test/domain/example.fr']);
    expect(a.issues.map((i) => i.id).sort()).toEqual(['infrastructure.domain_expiring', 'reputation.domain_very_new']);
  });
  it('reports holds, unknown domains and TLDs without RDAP', async () => {
    const hold = await analyzeRdap('example.fr', { fetcher: async (u) => (u.includes('iana') ? json(BOOT) : json({ ...DOMAIN, status: ['server hold'] })), now: NOW });
    expect(hold.issues.map((i) => i.id)).toContain('infrastructure.domain_hold');
    const nf = await analyzeRdap('example.fr', { fetcher: async (u) => (u.includes('iana') ? json(BOOT) : json({}, 404)), now: NOW });
    expect(nf.issues.map((i) => i.id)).toEqual(['infrastructure.domain_not_registered']);
    const de = await analyzeRdap('example.de', { fetcher: async () => json(BOOT), now: NOW });
    expect(de.unavailable?.[0].reason).toMatch(/\.de/);
  });
  it('reads google.com live', async () => {
    const a = await analyzeRdap('google.com');
    if (a.unavailable) return expect(a.unavailable[0].source).toBe('rdap');
    expect(a.data.created?.startsWith('1997')).toBe(true);
    expect(a.data.registrar?.name).toBeTruthy();
    expect(a.data.expiresInDays).toBeGreaterThan(0);
  });
});
