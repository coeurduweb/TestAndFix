// Clients of the reputation sources against a local fake server (no call to a keyed API),
// the VirusTotal queue with a fake clock, and Team Cymru for real on 8.8.8.8.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { FakeDns } from '../email-auth/fake-dns.js';
import { GuardedResolver } from '../email-auth/common.js';
import { abuseIpdbCheck } from './abuseipdb.js';
import { cymru, cymruOrigin, parseAs, parseOrigin } from './cymru.js';
import { fakeServer, type FakeReply, type FakeRequest, type FakeServer } from './fake-server.js';
import { RateLimiter } from './limiter.js';
import { normalizeFeedUrl, openPhishCheck, resetOpenPhishFeed } from './openphish.js';
import { otxIp } from './otx.js';
import { ripestat } from './ripestat.js';
import { safeBrowsingLookup } from './safebrowsing.js';
import { apiFetch, runSource } from './source.js';
import { urlhausHost, urlhausUrl } from './urlhaus.js';
import { urlscanSearch } from './urlscan.js';
import { vtIp, vtUrl, vtUrlId } from './virustotal.js';

let srv: FakeServer;
let handler: (r: FakeRequest) => FakeReply | Promise<FakeReply> = () => ({ status: 404 });
beforeAll(async () => {
  srv = await fakeServer((r) => handler(r));
});
afterAll(() => srv.close());
beforeEach(() => {
  srv.requests.length = 0;
});

const free = () => new RateLimiter(1000, 100000, 'VirusTotal');

describe('source runner', () => {
  it('turns a missing key, a refused key, a quota and a timeout into reasons, never exceptions', async () => {
    const noKey = await runSource('abuseipdb', 'AbuseIPDB', () => abuseIpdbCheck('192.0.2.1', { key: '', fetch: srv.fetch, base: srv.base }));
    expect(noKey).toMatchObject({ ok: false, kind: 'no_key' });
    expect(noKey.reason).toMatch(/ABUSEIPDB_API_KEY/);
    expect(srv.requests).toHaveLength(0);

    handler = () => ({ status: 401, body: { errors: [{ detail: 'Authentication failed' }] } });
    const refused = await runSource('abuseipdb', 'AbuseIPDB', () => abuseIpdbCheck('192.0.2.1', { key: 'k', fetch: srv.fetch, base: srv.base }));
    expect(refused).toMatchObject({ ok: false, kind: 'refused' });

    handler = () => ({ status: 429, body: {} });
    expect(await runSource('x', 'AbuseIPDB', () => abuseIpdbCheck('192.0.2.1', { key: 'k', fetch: srv.fetch, base: srv.base }))).toMatchObject({ ok: false, kind: 'quota' });

    const slow = await runSource('x', 'Lente', () => new Promise((r) => setTimeout(r, 500)), 50);
    expect(slow).toMatchObject({ ok: false, kind: 'timeout' });
  });

  it('keeps the SSRF protection: the production fetch refuses a private address', async () => {
    const r = await runSource('x', 'Test', () => apiFetch(`${srv.base}/`));
    expect(r.ok).toBe(false);
    expect(srv.requests).toHaveLength(0);
  });
});

describe('AbuseIPDB', () => {
  it('sends the key and reads the check report', async () => {
    handler = (r) => ({
      headers: { 'x-ratelimit-remaining': '997' },
      body: { data: { ipAddress: r.query.get('ipAddress'), abuseConfidenceScore: 87, totalReports: 12, numDistinctUsers: 5, lastReportedAt: '2026-11-09T10:00:00+00:00', isp: 'Exemple SAS', usageType: 'Data Center/Web Hosting/Transit', countryCode: 'FR', isWhitelisted: false, hostnames: [] } },
    });
    const d = await abuseIpdbCheck('192.0.2.1', { key: 'secret', fetch: srv.fetch, base: srv.base });
    expect(srv.requests[0].headers.key).toBe('secret');
    expect(srv.requests[0].query.get('maxAgeInDays')).toBe('90');
    expect(d).toMatchObject({ score: 87, totalReports: 12, distinctUsers: 5, remaining: 997, countryCode: 'FR', link: 'https://www.abuseipdb.com/check/192.0.2.1' });
  });
});

describe('VirusTotal', () => {
  it('reads an IP report with the engines that flag it', async () => {
    handler = (r) => {
      expect(r.headers['x-apikey']).toBe('vt');
      return {
        body: {
          data: {
            attributes: {
              last_analysis_stats: { malicious: 3, suspicious: 1, harmless: 60, undetected: 30 },
              last_analysis_results: { Fortinet: { category: 'malicious', result: 'spam', engine_name: 'Fortinet' }, Other: { category: 'harmless', result: 'clean' } },
              as_owner: 'Exemple',
              asn: 64500,
              country: 'FR',
              reputation: -12,
              last_analysis_date: 1794300000,
            },
          },
        },
      };
    };
    const d = await vtIp('192.0.2.1', { key: 'vt', fetch: srv.fetch, base: srv.base, limiter: free() });
    expect(srv.requests[0].path).toBe('/api/v3/ip_addresses/192.0.2.1');
    expect(d.stats.malicious).toBe(3);
    expect(d.flagged).toEqual([{ engine: 'Fortinet', category: 'malicious', result: 'spam' }]);
    expect(d.lastAnalysisDate).toMatch(/^2026-/);
  });

  it('looks an URL up by its identifier, submits only on request', async () => {
    const url = 'https://exemple.test/page';
    handler = (r) => (r.method === 'POST' ? { body: { data: { id: 'u-123' } } } : { status: 404, body: { error: { code: 'NotFoundError' } } });
    const unknown = await vtUrl(url, { key: 'vt', fetch: srv.fetch, base: srv.base, limiter: free() });
    expect(srv.requests[0].path).toBe(`/api/v3/urls/${vtUrlId(url)}`);
    expect(vtUrlId(url)).not.toMatch(/=/);
    expect(unknown).toMatchObject({ found: false });
    expect(srv.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
    const sub = await vtUrl(url, { key: 'vt', fetch: srv.fetch, base: srv.base, limiter: free(), submit: true });
    expect(sub).toMatchObject({ found: false, submitted: true, analysisId: 'u-123' });
    expect(srv.requests.find((r) => r.method === 'POST')!.body).toBe(`url=${encodeURIComponent(url)}`);
  });

  it('a 429 marks the minute as spent in the local queue', async () => {
    handler = () => ({ status: 429, body: {} });
    const lim = new RateLimiter(4, 500, 'VirusTotal');
    const r = await runSource('virustotal', 'VirusTotal', () => vtIp('192.0.2.1', { key: 'vt', fetch: srv.fetch, base: srv.base, limiter: lim }));
    expect(r).toMatchObject({ ok: false, kind: 'quota' });
    await expect(lim.acquire(0)).rejects.toThrow(/4 requêtes par minute/);
  });
});

describe('local queue (4 per minute, 500 per day)', () => {
  it('lets 4 through, makes the 5th wait for the oldest slot, refuses when the wait is too long', async () => {
    let t = Date.parse('2026-11-10T10:00:00Z');
    const slept: number[] = [];
    const lim = new RateLimiter(4, 500, 'VirusTotal', () => t, async (ms) => {
      slept.push(ms);
      t += ms;
    });
    for (let i = 0; i < 4; i++) await lim.acquire(0);
    expect(slept).toEqual([]);
    await expect(lim.acquire(10000)).rejects.toThrow(/réessayez dans 60 s/);
    t += 50000;
    await lim.acquire(15000);
    expect(slept).toEqual([10000]);
  });

  it('stops at the daily quota and starts again the next day (UTC)', async () => {
    let t = Date.parse('2026-11-10T23:00:00Z');
    const lim = new RateLimiter(1000, 3, 'VirusTotal', () => t);
    for (let i = 0; i < 3; i++) await lim.acquire(0);
    await expect(lim.acquire(0)).rejects.toThrow(/quota quotidien/);
    t = Date.parse('2026-11-11T00:00:01Z');
    await expect(lim.acquire(0)).resolves.toBeUndefined();
  });
});

describe('Google Safe Browsing v4', () => {
  it('posts the URLs and reads the matches', async () => {
    handler = (r) => {
      const body = JSON.parse(r.body);
      const urls = body.threatInfo.threatEntries.map((e: { url: string }) => e.url);
      return { body: { matches: urls.filter((u: string) => u.includes('mauvais')).map((u: string) => ({ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threat: { url: u } })) } };
    };
    const d = await safeBrowsingLookup(['https://bon.test/', 'https://mauvais.test/'], { key: 'g', fetch: srv.fetch, base: srv.base });
    expect(srv.requests[0].path).toBe('/v4/threatMatches:find');
    expect(srv.requests[0].query.get('key')).toBe('g');
    expect(d.matches).toEqual([{ url: 'https://mauvais.test/', threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM' }]);
    handler = () => ({ body: {} });
    expect((await safeBrowsingLookup(['https://bon.test/'], { key: 'g', fetch: srv.fetch, base: srv.base })).matches).toEqual([]);
  });
});

describe('URLhaus', () => {
  it('sends the Auth-Key and a form, reads a listed URL and a clean one', async () => {
    handler = (r) => {
      expect(r.headers['auth-key']).toBe('abuse');
      const url = new URLSearchParams(r.body).get('url');
      if (r.path === '/v1/url/' && url?.includes('malware'))
        return { body: { query_status: 'ok', url, url_status: 'online', threat: 'malware_download', tags: ['elf', 'mirai'], date_added: '2026-11-09 10:00:00 UTC', urlhaus_reference: 'https://urlhaus.abuse.ch/url/1/' } };
      if (r.path === '/v1/host/') return { body: { query_status: 'ok', host: 'malware.test', url_count: 2, urls: [{ url: 'http://malware.test/a', url_status: 'offline' }, { url: 'http://malware.test/b', url_status: 'online', threat: 'malware_download' }] } };
      return { body: { query_status: 'no_results' } };
    };
    const bad = await urlhausUrl('http://malware.test/x.sh', { key: 'abuse', fetch: srv.fetch, base: srv.base });
    expect(bad).toMatchObject({ listed: true, status: 'online', threat: 'malware_download', tags: ['elf', 'mirai'] });
    expect(await urlhausUrl('https://propre.test/', { key: 'abuse', fetch: srv.fetch, base: srv.base })).toMatchObject({ listed: false });
    const host = await urlhausHost('malware.test', { key: 'abuse', fetch: srv.fetch, base: srv.base });
    expect(host).toMatchObject({ listed: true, urlCount: 2, onlineCount: 1 });
    expect(host.urls[0].status).toBe('online');
  });
});

describe('OpenPhish feed', () => {
  it('matches exactly or by host, and downloads the feed at most once per hour', async () => {
    resetOpenPhishFeed();
    let downloads = 0;
    handler = (r) => {
      if (r.path !== '/feed.txt') return { status: 404 };
      downloads++;
      return { body: 'https://phish.test/login/\nhttp://autre.test/a?b=1\n# commentaire\n' };
    };
    let now = Date.parse('2026-11-10T10:00:00Z');
    const opts = { fetch: srv.fetch, feedUrl: `${srv.base}/feed.txt`, now: () => now };
    const d = await openPhishCheck(['https://phish.test/login', 'https://phish.test/autre', 'https://propre.test/'], opts);
    expect(d.feedSize).toBe(2);
    expect(d.exact).toEqual(['https://phish.test/login']);
    expect(d.sameHost.map((s) => s.url)).toEqual(['https://phish.test/autre']);
    now += 30 * 60 * 1000;
    await openPhishCheck(['https://propre.test/'], opts);
    expect(downloads).toBe(1);
    now += 31 * 60 * 1000;
    await openPhishCheck(['https://propre.test/'], opts);
    expect(downloads).toBe(2);
    // download failure: the copy of less than 12 hours is used and said so
    handler = () => ({ status: 503 });
    now += 2 * 60 * 60 * 1000;
    const stale = await openPhishCheck(['https://phish.test/login/'], opts);
    expect(stale.exact).toHaveLength(1);
    expect(stale.stale).toMatch(/copie de/);
    expect(normalizeFeedUrl('HTTPS://Phish.Test/Login/#x')).toBe('https://phish.test/Login');
    resetOpenPhishFeed();
  });
});

describe('urlscan.io, OTX, RIPEstat', () => {
  it('urlscan.io: searches by page domain and reads past scans', async () => {
    handler = (r) => ({
      body: { total: 1, results: [{ _id: 'abc', task: { time: '2026-11-10T09:00:00Z', url: `https://${r.query.get('q')!.split(':')[1]}/` }, page: { title: 'Connexion', domainAgeDays: 3, apexDomainAgeDays: 3, tlsIssuer: 'R11', ip: '192.0.2.10' } }] },
    });
    const d = await urlscanSearch('nouveau.test', { fetch: srv.fetch, base: srv.base });
    expect(srv.requests[0].query.get('q')).toBe('page.domain:nouveau.test');
    expect(d.scans[0]).toMatchObject({ title: 'Connexion', apexDomainAgeDays: 3, link: 'https://urlscan.io/result/abc/' });
  });

  it('OTX: pulse count and allow-list marks', async () => {
    handler = (r) => (r.path.includes('/IPv6/') ? { status: 404 } : { body: { pulse_info: { count: 2, pulses: [{ name: 'Spam botnet' }, { name: 'Scanners' }] }, validation: [], reputation: 0 } });
    expect(await otxIp('192.0.2.1', { fetch: srv.fetch, base: srv.base })).toMatchObject({ pulseCount: 2, pulses: ['Spam botnet', 'Scanners'], validation: [] });
    expect(srv.requests[0].path).toBe('/api/v1/indicators/IPv4/192.0.2.1/general');
    expect(await otxIp('2001:db8::1', { fetch: srv.fetch, base: srv.base })).toMatchObject({ pulseCount: 0 });
  });

  it('RIPEstat: merges the four calls and survives a partial failure', async () => {
    handler = (r) => {
      if (r.path.includes('abuse-contact-finder')) return { body: { data: { abuse_contacts: ['abuse@exemple.test'], authoritative_rir: 'ripe' } } };
      if (r.path.includes('maxmind-geo-lite')) return { body: { data: { located_resources: [{ locations: [{ country: 'FR', city: 'Paris' }] }] } } };
      if (r.path.includes('prefix-overview')) return { body: { data: { announced: true, resource: '192.0.2.0/24', asns: [{ asn: 64500, holder: 'EXEMPLE-AS' }] } } };
      return { status: 500, body: 'erreur' };
    };
    const d = await ripestat('192.0.2.1', { fetch: srv.fetch, base: srv.base });
    expect(d).toMatchObject({ abuseContacts: ['abuse@exemple.test'], country: 'FR', city: 'Paris', prefix: '192.0.2.0/24', announced: true, holders: [{ asn: 64500, holder: 'EXEMPLE-AS' }], missing: ['routing-status'] });
    expect(srv.requests.every((r) => r.query.get('sourceapp') === 'check-reputation')).toBe(true);
    handler = () => ({ status: 503 });
    expect(await runSource('ripestat', 'RIPEstat', () => ripestat('192.0.2.1', { fetch: srv.fetch, base: srv.base }))).toMatchObject({ ok: false });
  });
});

describe('Team Cymru', () => {
  it('parses origin and AS records', () => {
    expect(parseOrigin('15169 | 8.8.8.0/24 | US | arin | 2023-12-28')).toEqual([{ asn: 15169, prefix: '8.8.8.0/24', country: 'US', registry: 'arin', allocated: '2023-12-28' }]);
    expect(parseOrigin('64500 64501 | 192.0.2.0/24 | FR | ripencc | ').map((o) => o.asn)).toEqual([64500, 64501]);
    expect(parseAs('15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US')).toMatchObject({ asn: 15169, name: 'GOOGLE - Google LLC, US' });
  });

  it('builds the IPv4 and IPv6 query names', async () => {
    const dns = new FakeDns({
      '1.2.0.192.origin.asn.cymru.com': { TXT: [['64500 | 192.0.2.0/24 | FR | ripencc | 2010-01-01']] },
      '1.2.0.192.peer.asn.cymru.com': { TXT: [['3257 6939 | 192.0.2.0/24 | FR | ripencc | 2010-01-01']] },
      'as64500.asn.cymru.com': { TXT: [['64500 | FR | ripencc | 2010-01-01 | EXEMPLE-AS, FR']] },
    });
    const d = await cymru(dns, '192.0.2.1');
    expect(d).toMatchObject({ origins: [{ asn: 64500, prefix: '192.0.2.0/24' }], peers: [3257, 6939], as: [{ asn: 64500, name: 'EXEMPLE-AS, FR' }] });
    const six = new FakeDns({});
    await cymruOrigin(six, '2001:db8::1');
    expect(six.queries[0]).toBe('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com TXT');
  });

  it('real: 8.8.8.8 is announced by AS15169 (Google)', async () => {
    const dns = new GuardedResolver(new ResolveSession(), () => new ResolveSession());
    const d = await cymru(dns, '8.8.8.8');
    expect(d.origins.map((o) => o.asn)).toContain(15169);
    expect(d.origins[0].prefix).toMatch(/^8\.8\.8\.0\/\d+$/);
    expect(d.as.find((a) => a.asn === 15169)?.name).toMatch(/GOOGLE/i);
  });
});
