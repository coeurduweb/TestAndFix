// Reputation of a domain (US-069): fake DNS, fake lists, fake RDAP and a fake server for the
// keyed APIs; real runs on gmail.com and github.com; routes.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import type { AddressInfo } from 'node:net';
import { config } from '../../config.js';
import { openDb } from '../../db.js';
import { ResolveSession } from '../../dns/iterative.js';
import { GuardedResolver, toFindings } from '../../lib/email-auth/common.js';
import { FakeDns } from '../../lib/email-auth/fake-dns.js';
import type { RdapAnalysis } from '../../lib/email-auth/rdap.js';
import { buildResult } from '../../lib/email-auth/report.js';
import { guardedDnsblResolver, type ListSelection } from '../../lib/reputation/dnsbl-lists.js';
import { fakeServer, type FakeServer } from '../../lib/reputation/fake-server.js';
import { RateLimiter } from '../../lib/reputation/limiter.js';
import { fakeResolver } from '../../mail/test-helpers.js';
import type { ToolContext } from '../types.js';
import { analyzeDomainReputation, type DomainDeps } from './domain.js';
import { tool } from './index.js';

const ipLists: ListSelection = {
  source: 'research',
  skipped: [],
  lists: [{ zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN', type: 'ip', weight: 'major', status: 'alive', return_codes: { '127.0.0.2': 'SBL' }, delist_url: 'https://check.spamhaus.org/' }],
};
const domainLists: ListSelection = {
  source: 'research',
  skipped: [],
  lists: [
    { zone: 'dbl.spamhaus.org', name: 'Spamhaus DBL', type: 'domain', weight: 'major', status: 'alive', return_codes: { '127.0.1.2': 'domaine spam' }, delist_url: 'https://check.spamhaus.org/' },
    { zone: 'dbl.nordspam.com', name: 'NordSpam DBL', type: 'domain', weight: 'minor', status: 'alive', return_codes: { '127.0.0.2': 'domaine liste' }, delist_url: 'https://www.nordspam.com/delist' },
  ],
};

const dns = new FakeDns({
  'boutique-exemple.fr': { A: ['93.184.215.20'], MX: [{ preference: 10, exchange: 'mx1.boutique-exemple.fr' }] },
  'mx1.boutique-exemple.fr': { A: ['93.184.215.21'] },
  'sans-site.fr': { MX: [{ preference: 0, exchange: '.' }] },
  'www.sans-site.fr': { A: ['93.184.215.30'] },
});
const lists = fakeResolver({
  'boutique-exemple.fr.dbl.spamhaus.org': { A: ['127.0.1.2'] },
  '21.215.184.93.zen.spamhaus.org': { A: ['127.0.0.2'] },
});
const rdapOf = (ageDays: number): ((d: string) => Promise<RdapAnalysis>) => async (d) => ({
  issues: [],
  passed: [],
  data: { domain: d, queried: d, tld: 'fr', status: [], events: [], nameservers: [], ageDays, created: '2026-11-06T00:00:00Z', registrar: { name: 'Registrar Test' } },
});
const deps = (extra: Partial<DomainDeps> = {}): DomainDeps => ({
  dns,
  ipDeps: { dns, dnsblResolverFor: () => lists, keys: { abuseIpdb: '', virusTotal: '' }, lists: ipLists, http: false },
  domainListResolverFor: () => lists,
  domainLists,
  rdap: rdapOf(5),
  keys: { safeBrowsing: '', virusTotal: '', urlhaus: '' },
  http: false,
  ...extra,
});

describe('domain reputation, fake sources', () => {
  let srv: FakeServer;
  beforeAll(async () => {
    srv = await fakeServer((r) => {
      if (r.path.startsWith('/v4/threatMatches')) return { body: { matches: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threat: { url: 'https://boutique-exemple.fr/' } }] } };
      if (r.path === '/api/v3/domains/boutique-exemple.fr') return { body: { data: { attributes: { last_analysis_stats: { malicious: 4, suspicious: 0, harmless: 60, undetected: 20 } } } } };
      if (r.path === '/v1/host/') return { body: { query_status: 'ok', host: 'boutique-exemple.fr', url_count: 1, urlhaus_reference: 'https://urlhaus.abuse.ch/host/boutique-exemple.fr/', urls: [{ url: 'http://boutique-exemple.fr/x.exe', url_status: 'online' }] } };
      return { status: 404 };
    });
  });
  afterAll(() => srv.close());

  it('lists, age, the IPs of the site and of the MX with their role, the threat sources; one event per step', async () => {
    const events: string[] = [];
    const a = await analyzeDomainReputation(
      'boutique-exemple.fr',
      deps({ http: true, fetch: srv.fetch, bases: { safebrowsing: srv.base, virustotal: srv.base, urlhaus: srv.base }, keys: { safeBrowsing: 'g', virusTotal: 'v', urlhaus: 'u' }, vtLimiter: new RateLimiter(100, 100, 'VirusTotal') }),
      { onEvent: (e) => events.push(e.source) },
    );
    expect(events).toEqual(expect.arrayContaining(['dnsbl:dbl.spamhaus.org', 'dnsbl:dbl.nordspam.com', 'rdap', 'a', 'mx', 'ip:93.184.215.20', 'ip:93.184.215.21', 'safebrowsing', 'virustotal', 'urlhaus']));
    expect(a.data).toMatchObject({ domain: 'boutique-exemple.fr', exists: true, ageDays: 5, registrar: 'Registrar Test' });
    expect(a.data.addresses.map((x) => `${x.role} ${x.host} ${x.ip} ${x.family} ${x.row.status}`)).toEqual([
      'web boutique-exemple.fr 93.184.215.20 4 clean',
      'mail mx1.boutique-exemple.fr 93.184.215.21 4 listed',
    ]);
    const f = toFindings(a.issues);
    const by = (id: string) => f.find((x) => x.id === id);
    expect(by('link.domain_listed')).toMatchObject({ severity: 'high', penalty: 1.5 });
    expect(by('ip.domain_ip_listed')!.title).toBe("L'IP 93.184.215.21 du serveur de mail mx1.boutique-exemple.fr est inscrite sur Spamhaus ZEN");
    expect(by('ip.domain_ip_listed')).toMatchObject({ severity: 'critical', penalty: 2.5 });
    expect(by('ip.domain_recent')!.title).toBe('Le domaine boutique-exemple.fr a été créé il y a 5 jours');
    expect(by('ip.domain_safe_browsing')).toMatchObject({ severity: 'critical' });
    expect(by('ip.domain_virustotal')).toMatchObject({ severity: 'high', penalty: 1.5 });
    expect(by('ip.domain_urlhaus')).toMatchObject({ severity: 'high' });
    for (const x of f) expect(x.fallback, x.id).toBeFalsy();
    expect(a.data.intel.virustotal?.stats.malicious).toBe(4);
    expect(buildResult('ip', 'boutique-exemple.fr', 0, a).score).toBe(0);
  });

  it('without keys, the keyed sources are unavailable, never an error; www is used when the name has no address', async () => {
    const a = await analyzeDomainReputation('sans-site.fr', deps({ http: true, fetch: srv.fetch, rdap: rdapOf(4000) }));
    expect(a.unavailable!.map((u) => u.source)).toEqual(expect.arrayContaining(['safebrowsing', 'virustotal', 'urlhaus']));
    expect(a.data.addresses).toEqual([expect.objectContaining({ role: 'web', host: 'www.sans-site.fr', ip: '93.184.215.30' })]);
    expect(a.passed.map((p) => p.id)).toEqual(expect.arrayContaining(['ip.domain_age', 'ip.domain_ips_clean', 'blacklist.domain_clean']));
    expect(buildResult('ip', 'sans-site.fr', 0, a).score).toBe(10);
  });

  it('a domain that does not exist: clear finding, score 0, no address and no threat source queried', async () => {
    const events: string[] = [];
    const before = srv.requests.length;
    const a = await analyzeDomainReputation('inexistant.fr', deps({ http: true, fetch: srv.fetch, keys: { safeBrowsing: 'g', virusTotal: 'v', urlhaus: 'u' } }), { onEvent: (e) => events.push(e.source) });
    expect(a.data).toMatchObject({ exists: false, nxdomain: true, addresses: [] });
    const r = buildResult('ip', 'inexistant.fr', 0, a);
    expect(r.findings[0]).toMatchObject({ id: 'ip.domain_not_found', title: "Le domaine inexistant.fr n'existe pas" });
    expect(r.score).toBe(0);
    expect(events.some((e) => e.startsWith('ip:') || e === 'mx' || e === 'safebrowsing')).toBe(false);
    expect(srv.requests.length).toBe(before);
  });
});

describe('domain reputation, real', () => {
  const real = (): DomainDeps => {
    const g = () => new GuardedResolver(new ResolveSession(), () => new ResolveSession());
    const shared = new ResolveSession();
    return {
      dns: g(),
      ipDeps: { dns: g(), dnsblResolverFor: guardedDnsblResolver(() => shared, () => new ResolveSession()), keys: { abuseIpdb: '', virusTotal: '' } },
      domainListResolverFor: guardedDnsblResolver(() => new ResolveSession()),
      keys: { safeBrowsing: '', virusTotal: '', urlhaus: '' },
      http: false,
    };
  };

  for (const [domain, mx] of [
    ['gmail.com', /gmail-smtp-in\.l\.google\.com$/],
    ['github.com', /mail\.protection\.outlook\.com$/],
  ] as const)
    it(`${domain}: exists, old domain, web and MX addresses checked, on no domain list`, async () => {
      const a = await analyzeDomainReputation(domain, real());
      expect(a.data.exists).toBe(true);
      expect(a.data.ageDays ?? 9999).toBeGreaterThan(3650);
      expect(a.data.addresses.some((x) => x.role === 'web')).toBe(true);
      expect(a.data.addresses.filter((x) => x.role === 'mail').some((x) => mx.test(x.host))).toBe(true);
      expect(a.data.lists.listed).toEqual([]);
    }, 60000);
});

describe('routes', () => {
  let app: FastifyInstance;
  let base: string;
  beforeAll(async () => {
    const ctx: ToolContext = { db: openDb(':memory:'), config, dns: (o) => new ResolveSession(o) };
    app = Fastify();
    await app.register(async (scope) => tool.register!(scope, ctx));
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });
  afterAll(() => app.close());

  it('a domain on /api/ip/:ip answers 400 and points to /api/ip/domain/:domain; an IP on the domain route answers 400', async () => {
    const r = await app.inject({ url: '/api/ip/gmail.com' });
    expect(r.statusCode).toBe(400);
    expect(r.json().message).toContain('/api/ip/domain/gmail.com');
    expect((await app.inject({ url: '/api/ip/gmail.com/stream' })).statusCode).toBe(400);
    expect((await app.inject({ url: '/api/ip/domain/8.8.8.8' })).statusCode).toBe(400);
    expect((await app.inject({ url: '/api/ip/10.0.0.1' })).statusCode).toBe(200);
  });

  it('GET /api/ip/domain/:domain and its stream on a name that does not exist (real DNS), saved under the tool ip', async () => {
    const name = `nexistepas-${Date.now()}.fr`;
    const j = (await app.inject({ url: `/api/ip/domain/${name}` })).json();
    expect(j).toMatchObject({ tool: 'ip', input: name, score: 0, data: { domain: name, exists: false }, findings: [{ id: 'ip.domain_not_found' }] });
    expect(j.resultId).toBeTruthy();
    const text = await (await fetch(`${base}/api/ip/domain/${name}/stream`)).text();
    const events = text.split('\n\n').filter((b) => b.startsWith('event:')).map((b) => ({ event: b.split('\n')[0].slice(7), data: JSON.parse(b.split('\n')[1].slice(6)) }));
    expect(events[0]).toMatchObject({ event: 'start', data: { domain: name } });
    expect(events[0].data.sources.map((s: { id: string }) => s.id)).toEqual(['rdap', 'a', 'mx', 'safebrowsing', 'virustotal', 'urlhaus']);
    expect(events.filter((e) => e.event === 'source').map((e) => e.data.source)).toEqual(expect.arrayContaining(['a', 'rdap']));
    expect(events[events.length - 1]).toMatchObject({ event: 'done', data: { score: 0 } });
  }, 60000);
});
