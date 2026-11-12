// IP reputation: input parsing, private addresses (no network), DNS blocklists for real on the
// RFC 5782 test point 127.0.0.2 and on a clean address, return codes on a fake resolver,
// reverse DNS, batch, HTTP routes and SSE.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import type { AddressInfo } from 'node:net';
import { openDb } from '../../db.js';
import { config } from '../../config.js';
import { ResolveSession } from '../../dns/iterative.js';
import { GuardedResolver } from '../../lib/email-auth/common.js';
import { FakeDns } from '../../lib/email-auth/fake-dns.js';
import { guardedDnsblResolver, selectLists, type ListSelection } from '../../lib/reputation/dnsbl-lists.js';
import { fakeServer, type FakeServer } from '../../lib/reputation/fake-server.js';
import { RateLimiter } from '../../lib/reputation/limiter.js';
import { fakeResolver } from '../../mail/test-helpers.js';
import { toFindings } from '../../lib/email-auth/common.js';
import { explain } from '../../knowledge/engine.js';
import type { ToolContext } from '../types.js';
import { analyzeBatch, analyzeIp, analyzePublicIp, type IpDeps } from './analyze.js';
import { expandRange, nonPublicRange, parseBatch, parseIp } from './input.js';
import { genericKind } from './ptr.js';
import { tool } from './index.js';

const realDeps = (): IpDeps => ({
  dns: new GuardedResolver(new ResolveSession(), () => new ResolveSession()),
  dnsblResolverFor: guardedDnsblResolver(() => new ResolveSession()),
  keys: { abuseIpdb: '', virusTotal: '' },
  http: false,
});

const forbidden = (): IpDeps => ({
  dns: { resolve: () => Promise.reject(new Error('network used')) },
  dnsblResolverFor: () => () => Promise.reject(new Error('network used')),
  keys: { abuseIpdb: 'k', virusTotal: 'k' },
  fetch: () => Promise.reject(new Error('network used')),
});

describe('input', () => {
  it('normalises IPv4, IPv6 and IPv4-mapped addresses, refuses partial forms', () => {
    expect(parseIp(' 8.8.8.8 ')).toEqual({ ip: '8.8.8.8', version: 4 });
    expect(parseIp('[2001:DB8:0:0::1]')).toEqual({ ip: '2001:db8::1', version: 6 });
    expect(parseIp('::ffff:192.0.2.1')).toEqual({ ip: '192.0.2.1', version: 4 });
    expect(() => parseIp('1.2')).toThrow(/quatre nombres/);
    expect(() => parseIp('exemple.fr')).toThrow(/pas une adresse IP/);
  });

  it('expands /24 to /32 ranges only', () => {
    expect(expandRange('192.0.2.77/30')).toEqual(['192.0.2.76', '192.0.2.77', '192.0.2.78', '192.0.2.79']);
    expect(expandRange('198.51.100.0/24')).toHaveLength(256);
    expect(expandRange('198.51.100.9/32')).toEqual(['198.51.100.9']);
    expect(() => expandRange('198.51.100.0/23')).toThrow(/de \/24 à \/32/);
    expect(() => expandRange('2001:db8::/120')).toThrow(/IPv6/);
  });

  it('a batch: lines, commas, ranges, duplicates, 256 at most, invalid entries kept aside', () => {
    const b = parseBatch('8.8.8.8\n1.1.1.1, 8.8.8.8\nbonjour\n192.0.2.0/31');
    expect(b.ips).toEqual(['8.8.8.8', '1.1.1.1', '192.0.2.0', '192.0.2.1']);
    expect(b.invalid).toEqual([{ value: 'bonjour', reason: expect.stringMatching(/pas une adresse IP/) }]);
    expect(parseBatch(['198.51.100.0/24']).ips).toHaveLength(256);
    expect(() => parseBatch(['198.51.100.0/24', '8.8.8.8'])).toThrow(/256 au plus/);
    expect(() => parseBatch(['bonjour'])).toThrow(/Aucune adresse valide/);
  });

  it('recognises private and reserved ranges', () => {
    expect(nonPublicRange('10.1.2.3')?.range).toBe('private');
    expect(nonPublicRange('127.0.0.2')?.range).toBe('loopback');
    expect(nonPublicRange('100.64.0.1')?.range).toBe('carrierGradeNat');
    expect(nonPublicRange('fd00::1')?.range).toBe('uniqueLocal');
    expect(nonPublicRange('8.8.8.8')).toBeUndefined();
  });
});

describe('private address', () => {
  it('answers clearly without any network request', async () => {
    const a = await analyzeIp('192.168.1.10', forbidden());
    expect(a.data).toMatchObject({ ip: '192.168.1.10', public: false, range: { range: 'private' } });
    const f = toFindings(a.issues);
    expect(f[0]).toMatchObject({ id: 'ip.not_public', severity: 'info', penalty: 0 });
    expect(f[0].why).toMatch(/plage privée/);
  });
});

describe('DNS blocklists, real', () => {
  it('the test point 127.0.0.2 is listed on the major lists; UCEPROTECT 2 and 3 stay informative', async () => {
    const a = await analyzePublicIp('127.0.0.2', 4, realDeps());
    const listed = a.data.dnsbl!.listed;
    const zones = new Set(listed.map((l) => l.zone));
    // at least ZEN and one other major list must answer; a slow list may be missing
    expect(zones.has('zen.spamhaus.org') || a.data.dnsbl!.errors.some((e) => e.zone === 'zen.spamhaus.org')).toBe(true);
    if (zones.has('zen.spamhaus.org')) {
      const zen = listed.filter((l) => l.zone === 'zen.spamhaus.org').map((l) => l.situation);
      expect(zen).toEqual(expect.arrayContaining(['blacklist.spamhaus_sbl', 'blacklist.spamhaus_xbl', 'blacklist.spamhaus_pbl']));
      expect(listed.find((l) => l.situation === 'blacklist.spamhaus_sbl')!.codes).toEqual(['127.0.0.2']);
    }
    expect(zones.size).toBeGreaterThan(5);
    const f = toFindings(a.issues);
    for (const id of ['blacklist.uceprotect_level2', 'blacklist.uceprotect_level3'])
      for (const x of f.filter((y) => y.id === id)) expect(x).toMatchObject({ severity: 'info', penalty: 0 });
    // every listing carries its delisting procedure, link filled in
    const sbl = listed.find((l) => l.situation === 'blacklist.spamhaus_sbl');
    if (sbl) expect(sbl.procedure.join(' ')).toContain('https://check.spamhaus.org/');
    // a refusal is never a listing
    for (const r of a.data.dnsbl!.refused) expect(listed.some((l) => l.zone === r.zone)).toBe(false);
    // redundant zones and zones whose terms need a key are not queried
    expect(a.data.dnsbl!.skipped.map((s) => s.zone)).toEqual(expect.arrayContaining(['sbl.spamhaus.org', 'cbl.abuseat.org', 'spam.spamrats.com']));
    expect(listed.some((l) => l.zone === 'sbl.spamhaus.org' || l.zone === 'cbl.abuseat.org')).toBe(false);
  }, 60000);

  it('a clean address (8.8.8.8) is on no major list, with its network from Team Cymru and FCrDNS', async () => {
    const a = await analyzePublicIp('8.8.8.8', 4, realDeps());
    expect(a.data.dnsbl!.listed.filter((l) => l.weight === 'major')).toEqual([]);
    expect(a.data.dnsbl!.clean.length).toBeGreaterThan(10);
    expect(a.data.network?.asn).toBe(15169);
    expect(a.data.ptr?.confirmed).toBe('dns.google');
    expect(a.passed.map((p) => p.id)).toEqual(expect.arrayContaining(['blacklist.clean', 'rdns.fcrdns', 'ip.asn']));
  }, 60000);
});

describe('return codes and reverse DNS on a fake resolver', () => {
  const lists: ListSelection = {
    source: 'research',
    skipped: [],
    lists: [
      { zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN', type: 'ip', weight: 'major', status: 'alive', return_codes: { '127.0.0.2': 'SBL', '127.0.0.10': 'PBL (ISP)' }, delist_url: 'https://check.spamhaus.org/' },
      { zone: 'b.barracudacentral.org', name: 'Barracuda BRBL', type: 'ip', weight: 'major', status: 'alive', return_codes: { '127.0.0.2': 'liste' }, delist_url: 'https://www.barracudacentral.org/lookups' },
      { zone: 'dnsbl-3.uceprotect.net', name: 'UCEPROTECT niveau 3', type: 'ip', weight: 'info', status: 'alive', return_codes: { '127.0.0.2': 'liste' }, delist_url: 'https://www.uceprotect.net/en/index.php?m=7&s=0' },
      { zone: 'dnsbl.spfbl.net', name: 'SPFBL', type: 'ip', weight: 'info', status: 'alive', return_codes: { '127.0.0.4': 'pas de service mail identifie' }, delist_url: 'https://matrix.spfbl.net/' },
      { zone: 'bl.nordspam.com', name: 'NordSpam IP', type: 'ip', weight: 'minor', status: 'alive', return_codes: { '127.0.0.2': 'liste' }, delist_url: 'https://www.nordspam.com/delist' },
    ],
  };
  const ip = '93.184.215.7';
  const dnsbl = fakeResolver({
    '7.215.184.93.zen.spamhaus.org': { A: ['127.0.0.10'] },
    '7.215.184.93.b.barracudacentral.org': { A: ['127.255.255.254'] },
    '7.215.184.93.dnsbl-3.uceprotect.net': { A: ['127.0.0.2'] },
    '7.215.184.93.dnsbl.spfbl.net': { A: ['127.0.0.4'] },
    '7.215.184.93.bl.nordspam.com': { A: ['127.0.0.2'], TXT: [['listed']] },
  });
  const dns = new FakeDns({
    '7.215.184.93.in-addr.arpa': { PTR: ['abo-7-215-184-93.dsl.fai.test'] },
    'abo-7-215-184-93.dsl.fai.test': { A: ['93.184.215.8'] },
    '7.215.184.93.origin.asn.cymru.com': { TXT: [['64500 | 93.184.215.0/24 | FR | ripencc | 2010-01-01']] },
    'as64500.asn.cymru.com': { TXT: [['64500 | FR | ripencc | 2010-01-01 | FAI-TEST, FR']] },
  });
  const deps: IpDeps = { dns, dnsblResolverFor: () => dnsbl, keys: { abuseIpdb: '', virusTotal: '' }, lists, http: false };

  it('PBL is a listing, 127.255.255.254 a refusal, SPFBL .4 scoring only, UCEPROTECT 3 informative', async () => {
    const a = await analyzePublicIp(ip, 4, deps);
    const f = toFindings(a.issues);
    expect(f.find((x) => x.id === 'blacklist.spamhaus_pbl')).toBeTruthy();
    expect(f.find((x) => x.id === 'blacklist.barracuda')).toBeUndefined();
    expect(f.find((x) => x.id === 'blacklist.query_blocked')?.why).not.toMatch(/inscrit/);
    expect(a.data.dnsbl!.scoringOnly.map((h) => h.zone)).toEqual(['dnsbl.spfbl.net']);
    expect(f.find((x) => x.id === 'blacklist.uceprotect_level3')).toMatchObject({ severity: 'info', penalty: 0 });
    const nord = a.data.dnsbl!.listed.find((l) => l.zone === 'bl.nordspam.com')!;
    expect(nord.situation).toBe('blacklist.ip_listed');
    expect(nord.procedure.join(' ')).toContain('https://www.nordspam.com/delist');
    expect(a.unavailable?.find((u) => u.source === 'dnsbl')?.reason).toMatch(/refusé/);
    // reverse DNS: residential name that does not resolve back
    expect(f.map((x) => x.id)).toEqual(expect.arrayContaining(['rdns.fcrdns_mismatch', 'rdns.generic_dynamic']));
    expect(a.data.network).toMatchObject({ asn: 64500, asName: 'FAI-TEST, FR', prefix: '93.184.215.0/24' });
  });

  it('keyed sources: missing keys go to unavailable, answers become findings', async () => {
    const srv: FakeServer = await fakeServer((r) => {
      if (r.path.startsWith('/api/v2/check')) return { body: { data: { abuseConfidenceScore: 100, totalReports: 40, numDistinctUsers: 12 } } };
      if (r.path.startsWith('/api/v3/ip_addresses/')) return { body: { data: { attributes: { last_analysis_stats: { malicious: 5, suspicious: 0, harmless: 50, undetected: 30 } } } } };
      if (r.path.includes('/indicators/')) return { body: { pulse_info: { count: 0 }, validation: [] } };
      return { body: { data: {} } };
    });
    try {
      const bases = { abuseipdb: srv.base, virustotal: srv.base, otx: srv.base, ripestat: srv.base };
      const withKeys = await analyzePublicIp(ip, 4, { ...deps, http: true, fetch: srv.fetch, bases, keys: { abuseIpdb: 'a', virusTotal: 'v' }, vtLimiter: new RateLimiter(100, 100, 'VirusTotal') });
      const f = toFindings(withKeys.issues);
      expect(f.find((x) => x.id === 'ip.abuseipdb_reported')).toMatchObject({ severity: 'high', penalty: 2 });
      expect(f.find((x) => x.id === 'ip.virustotal_flagged')).toMatchObject({ severity: 'high' });
      expect(withKeys.passed.map((p) => p.id)).toContain('ip.otx');
      const noKeys = await analyzePublicIp(ip, 4, { ...deps, http: true, fetch: srv.fetch, bases });
      expect(noKeys.unavailable!.map((u) => u.source)).toEqual(expect.arrayContaining(['abuseipdb', 'virustotal']));
      expect(noKeys.unavailable!.find((u) => u.source === 'virustotal')!.reason).toMatch(/VT_API_KEY/);
    } finally {
      await srv.close();
    }
  });

  it('missing reverse DNS: the record to ask for uses the reverse name of the measured IP and a valid host name', async () => {
    const a = await analyzePublicIp('93.184.215.9', 4, deps);
    const f = toFindings(a.issues).find((x) => x.id === 'rdns.missing')!;
    expect(f.suggested).toBe('9.215.184.93.in-addr.arpa. IN PTR mail.exemple.fr.');
    // a computed record replaces the generic example of the base
    expect(f.exampleGood).toBeUndefined();
    expect(f.fix[0]).toContain('mail.exemple.fr');
    expect(`${f.suggested} ${f.fix.join(' ')}`).not.toMatch(/mail\.votre domaine|votre valeur|203\.0\.113/);
    // the mail test uses the same entry with the sender's domain: still right
    const mail = explain({ id: 'rdns.missing', vars: { ip: '93.184.215.14', domain: 'atelier-exemple.fr' } });
    expect(mail.exampleGood).toBe('PTR de 93.184.215.14 : mail.atelier-exemple.fr.  et  mail.atelier-exemple.fr. IN A 93.184.215.14');
    expect(mail.fix[0]).toContain('mail.atelier-exemple.fr');
  });

  it('streams each source as it answers', async () => {
    const events: string[] = [];
    await analyzePublicIp(ip, 4, { ...deps, http: false }, { onEvent: (e) => events.push(e.source) });
    expect(events).toEqual(expect.arrayContaining(['dnsbl:zen.spamhaus.org', 'dnsbl:bl.nordspam.com', 'ptr', 'cymru']));
  });

  it('a batch gives one row per address, private ones without lookup', async () => {
    const rows: string[] = [];
    const b = await analyzeBatch([ip, '10.0.0.1', '93.184.215.9'], deps, { onRow: (r) => rows.push(r.ip) });
    expect(rows.sort()).toEqual(['10.0.0.1', '93.184.215.7', '93.184.215.9']);
    const by = Object.fromEntries(b.data.rows.map((r) => [r.ip, r]));
    expect(by['10.0.0.1'].status).toBe('private');
    expect(by[ip]).toMatchObject({ status: 'listed', majorListed: 1, refused: ['Barracuda BRBL'], asn: 64500, ptr: 'abo-7-215-184-93.dsl.fai.test', fcrdns: false });
    expect(by[ip].score).toBeLessThan(10);
    expect(by['93.184.215.9'].status).toBe('clean');
    expect(b.data.listedCount).toBe(1);
  });
});

describe('reverse DNS names', () => {
  it('tells residential names from default hosting names', () => {
    expect(genericKind('203.0.113.5', 'abo-5-113-0-203.dsl.fai.test')).toBe('dynamic');
    expect(genericKind('203.0.113.5', 'ec2-203-0-113-5.compute-1.amazonaws.com')).toBe('hosting');
    expect(genericKind('203.0.113.5', 'mail.exemple.fr')).toBeUndefined();
    expect(genericKind('8.8.8.8', 'dns.google')).toBeUndefined();
  });
});

describe('selection of the lists', () => {
  it('queries every live IP zone of the catalogue except the redundant ones; ranges use the major ones', () => {
    const all = selectLists('ip', 'all');
    expect(all.lists.length).toBeGreaterThan(15);
    expect(all.lists.every((l) => l.status === 'alive' && l.type === 'ip')).toBe(true);
    const major = selectLists('ip', 'major');
    expect(major.lists.every((l) => l.weight === 'major')).toBe(true);
    expect(major.lists.map((l) => l.zone)).toContain('zen.spamhaus.org');
  });
});

describe('HTTP routes', () => {
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

  it('GET /api/ip/:ip on a private address, saved in the history', async () => {
    const r = await app.inject({ url: '/api/ip/10.1.2.3' });
    expect(r.statusCode).toBe(200);
    const j = r.json();
    expect(j).toMatchObject({ tool: 'ip', input: '10.1.2.3', data: { public: false }, findings: [{ id: 'ip.not_public' }] });
    expect(j.score).toBeUndefined();
    expect(j.resultId).toMatch(/^[a-z0-9]{10}$/);
    expect((await app.inject({ url: '/api/ip/pas-une-ip' })).statusCode).toBe(400);
  });

  it('ranges: /api/ip/192.0.2.0/30 and the encoded form, batch POST', async () => {
    const r = await app.inject({ url: '/api/ip/192.0.2.0/30' });
    expect(r.statusCode).toBe(200);
    expect(r.json().data.rows.map((x: { ip: string; status: string }) => `${x.ip} ${x.status}`)).toEqual(['192.0.2.0 private', '192.0.2.1 private', '192.0.2.2 private', '192.0.2.3 private']);
    const enc = await app.inject({ url: '/api/ip/192.0.2.0%2F31' });
    expect(enc.json().data.count).toBe(2);
    expect((await app.inject({ url: '/api/ip/192.0.2.0/16' })).statusCode).toBe(400);
    const b = await app.inject({ method: 'POST', url: '/api/ip/batch', payload: { ips: ['10.0.0.1', 'nimporte', '172.16.0.1'] } });
    expect(b.json().data).toMatchObject({ count: 2, privateCount: 2, invalid: [{ value: 'nimporte' }] });
    expect((await app.inject({ method: 'POST', url: '/api/ip/batch', payload: {} })).statusCode).toBe(400);
  });

  it('SSE: start then done for a private address; row events for a range', async () => {
    const read = async (path: string, init?: RequestInit) => {
      const res = await fetch(base + path, init);
      expect(res.headers.get('content-type')).toMatch(/text\/event-stream/);
      return (await res.text())
        .split('\n\n')
        .filter((b) => b.startsWith('event:'))
        .map((b) => ({ event: b.split('\n')[0].slice(7), data: JSON.parse(b.split('\n')[1].slice(6)) }));
    };
    const single = await read('/api/ip/10.9.8.7/stream');
    expect(single.map((e) => e.event)).toEqual(['start', 'done']);
    expect(single[1].data.data.public).toBe(false);
    const range = await read('/api/ip/192.0.2.4/31/stream');
    expect(range.map((e) => e.event)).toEqual(['start', 'row', 'row', 'done']);
    const batch = await read('/api/ip/batch/stream', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ips: '10.0.0.1\n10.0.0.2' }) });
    expect(batch.filter((e) => e.event === 'row')).toHaveLength(2);
  });
});
