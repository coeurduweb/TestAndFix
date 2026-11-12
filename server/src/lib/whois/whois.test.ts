// Whois tool: parsing of recorded answers (fixtures/, recorded on 2026-11-12), redaction,
// divergences, the lookup order with its fallbacks, the politeness limiter. No live network.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { SafeFetchResult } from '../net.js';
import { canonicalStatus, normalizeStatuses, statusInfo } from './epp.js';
import { PoliteLimiter, RateLimitedError, parseRetryAfter } from './limiter.js';
import { divergences, lookupWhois, lookupMany, merge, parseDomainList, sameRegistrar, toRow, whoisAnalysis, WhoisCache, type WhoisDeps } from './lookup.js';
import { parseWhoisDate, parseWhoisText } from './parse.js';
import type { WhoisAnswer } from './port43.js';
import { parseRdapJson } from './rdap.js';
import { isPlaceholder, isPrivacyOrg } from './redaction.js';
import { lifetime, parseRegistrarIds, WhoisDirectory } from './sources.js';
import type { PartyRecord } from './types.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (n: string) => fs.readFileSync(path.join(here, 'fixtures', n), 'utf8');
const fxJson = (n: string) => JSON.parse(fx(n)) as Record<string, unknown>;
const NOW = Date.parse('2026-11-12T10:00:00Z');

const resp = (body: string | object, status = 200, headers: Record<string, string> = {}): SafeFetchResult => ({
  url: '',
  status,
  headers,
  body: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)),
  truncated: false,
  ms: 1,
});
const answer = (text: string): WhoisAnswer => ({ text, address: '192.0.2.1', ms: 1, truncated: false });

/** A fake clock: sleep() moves time forward instead of waiting. */
function clock(start = NOW) {
  let t = start;
  return { now: () => t, sleep: async (ms: number) => void (t += ms), advance: (ms: number) => void (t += ms) };
}

const REGISTRAR_IDS = `<registry><record><value>1519</value><name>NETIM SAS</name><status>Accredited</status><rdapurl><server>https://netim.rdap.services/</server></rdapurl></record>
<record><value>9999</value><name>Reserved</name><status>Reserved</status></record></registry>`;

interface Net {
  http: string[];
  whois: string[];
}

function fakeDeps(over: { http?: Record<string, () => SafeFetchResult>; whois?: Record<string, () => string> } = {}, extra: Partial<WhoisDeps> = {}) {
  const net: Net = { http: [], whois: [] };
  const http: Record<string, () => SafeFetchResult> = {
    'https://data.iana.org/rdap/dns.json': () => resp(fx('iana-bootstrap.json'), 200, { 'cache-control': 'max-age=86400' }),
    'https://rdap.verisign.com/com/v1/domain/exemple-agence.com': () => resp(fx('rdap-verisign.json')),
    'https://netim.rdap.services/domain/EXEMPLE-AGENCE.COM': () => resp(fx('rdap-netim.json')),
    'https://netim.rdap.services/domain/exemple-agence.com': () => resp(fx('rdap-netim.json')),
    'https://rdap.nic.fr/domain/afnic.fr': () => resp(fx('rdap-afnic.json')),
    'https://www.iana.org/assignments/registrar-ids/registrar-ids.xml': () => resp(REGISTRAR_IDS, 200, { 'cache-control': 'max-age=3600' }),
    ...over.http,
  };
  const whois: Record<string, () => string> = {
    'whois.iana.org com': () => fx('iana-referral-com.txt'),
    'whois.iana.org de': () => 'domain: DE\nwhois: whois.denic.de\n',
    'whois.iana.org fr': () => 'domain: FR\nwhois: whois.nic.fr\n',
    'whois.verisign-grs.com exemple-agence.com': () => fx('verisign-com-thin.txt'),
    'whois.netim.com exemple-agence.com': () => fx('netim-registrar.txt'),
    'whois.denic.de wikipedia.de': () => 'Domain: wikipedia.de\nStatus: connect\n',
    ...over.whois,
  };
  const c = clock();
  const deps: WhoisDeps = {
    http: async (url) => {
      net.http.push(url);
      const f = http[url];
      if (!f) throw Object.assign(new Error('fetch failed'), { code: 'ENOTFOUND' });
      return f();
    },
    whois43: async (host, q) => {
      net.whois.push(`${host} ${q}`);
      const f = whois[`${host} ${q}`];
      if (!f) throw Object.assign(new Error('délai dépassé'), { code: 'timeout' });
      return answer(f());
    },
    limiter: new PoliteLimiter({ now: c.now, sleep: c.sleep }),
    directory: new WhoisDirectory(c.now),
    now: c.now,
    ...extra,
  };
  return { deps, net, clock: c };
}

describe('EPP statuses', () => {
  it('maps WHOIS and RDAP spellings to one EPP code', () => {
    expect(canonicalStatus('clientTransferProhibited https://icann.org/epp#clientTransferProhibited')).toBe('clientTransferProhibited');
    expect(canonicalStatus('client transfer prohibited')).toBe('clientTransferProhibited');
    expect(canonicalStatus('SERVER_HOLD')).toBe('serverHold');
    expect(canonicalStatus('active')).toBe('ok');
    expect(canonicalStatus('connect')).toBe('connect');
    expect(normalizeStatuses(['active', 'client transfer prohibited'])).toEqual(['clientTransferProhibited']);
    expect(normalizeStatuses(['ok https://icann.org/epp#ok'])).toEqual(['ok']);
    expect(statusInfo('clientTransferProhibited')).toMatchObject({ epp: true, kind: 'lock', setBy: 'bureau' });
    expect(statusInfo('serverHold').kind).toBe('bad');
    expect(statusInfo('connect')).toMatchObject({ epp: false, meaning: 'statut propre à ce registre' });
  });
});

describe('WHOIS text', () => {
  it('reads a thin gTLD registry answer (Verisign .com)', () => {
    const p = parseWhoisText(fx('verisign-com-thin.txt'), 'registry');
    expect(p).toMatchObject({
      created: '2008-04-05T17:48:51Z',
      updated: '2026-03-28T23:35:18Z',
      expires: '2027-04-05T17:48:51Z',
      status: ['clientTransferProhibited'],
      registrar: { name: 'NETIM SAS', ianaId: '1519', whoisServer: 'whois.netim.com', abuseEmail: 'abuse@netim.net', url: 'http://www.netim.com/domain-name/' },
      nameservers: ['ns1.netim.net', 'ns2.netim.net', 'ns3.netim.net'],
      dnssec: false,
      contacts: [],
      notFound: false,
      rateLimited: false,
    });
  });
  it('reads a gTLD registry with several locks (PIR .org)', () => {
    const p = parseWhoisText(fx('pir-org.txt'), 'registry');
    expect(p.status).toEqual(['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited']);
    expect(p.registrar).toMatchObject({ name: 'MarkMonitor Inc.', ianaId: '292', whoisServer: 'whois.markmonitor.com' });
    expect(p.created).toBe('2001-01-13T00:12:14Z');
  });
  it('reads a thick registrar answer with redacted contacts and a contact form (Netim)', () => {
    const p = parseWhoisText(fx('netim-registrar.txt'), 'registrar');
    expect(p.expires).toBe('2027-04-05T21:00:00Z');
    expect(p.created).toBe('2008-04-05T00:00:00Z');
    expect(p.status).toEqual(['clientTransferProhibited']);
    const reg = p.contacts.find((c) => c.role === 'registrant')!;
    expect(reg.redacted).toEqual(expect.arrayContaining(['name', 'email']));
    expect(reg.name).toBeUndefined();
    expect(reg.contactUrl).toBe('https://www.whoisprivacy.domains/');
    expect(p.contacts.map((c) => c.role)).toEqual(['registrant', 'admin', 'tech']);
  });
  it('prefers the registrar expiration date in a registrar answer (MarkMonitor)', () => {
    const p = parseWhoisText(fx('markmonitor-registrar.txt'), 'registrar');
    expect(p.expires).toBe('2027-01-13T00:12:14Z');
    expect(p.registrar?.name).toBe('Markmonitor Inc.');
    expect(p.contacts.find((c) => c.role === 'registrant')).toMatchObject({ redacted: ['name', 'org', 'email'], contactUrl: 'https://domains.markmonitor.com/whois/contact/wikipedia.org' });
  });
  it('reads Afnic blocks: visible organisation contacts, EPP and registry statuses, DS records', () => {
    const p = parseWhoisText(fx('afnic-public.txt'), 'registry');
    expect(p).toMatchObject({
      created: '2001-12-10T23:00:00Z',
      expires: '2029-07-18T08:26:59Z',
      status: ['ok'],
      registryStatus: ['ACTIVE'],
      registrar: { name: 'Registry Operations', url: 'https://www.afnic.fr' },
      nameservers: ['g.ext.nic.fr', 'ns1.nic.fr', 'ns2.nic.fr', 'ns3.nic.fr'],
      dnssec: true,
    });
    expect(p.contacts).toEqual([
      { role: 'registrant', org: 'ASS FRANC NOMMAGE INTERNET EN COOP', email: 'contact@nic.fr', redacted: [] },
      { role: 'admin', org: 'ASS FRANC NOMMAGE INTERNET EN COOP', email: 'contact@nic.fr', redacted: [] },
      { role: 'tech', org: 'AFNIC', email: 'dnsops@afnic.fr', redacted: [] },
    ]);
  });
  it('reads Afnic anonymised holders and a proxy organisation', () => {
    const p = parseWhoisText(fx('afnic-anonymous.txt'), 'registry');
    expect(p.status).toEqual(['clientTransferProhibited']);
    expect(p.registrar?.name).toBe('NETIM');
    expect(p.contacts[0]).toEqual({ role: 'registrant', redacted: ['name', 'org', 'email'] });
    expect(p.contacts[2]).toMatchObject({ role: 'tech', org: 'ProxyDom', privacyService: true, email: 'tld@proxydom.net' });
  });
  it('recognises "not found" and rate-limit answers, and odd date formats', () => {
    expect(parseWhoisText('No match for "EXAMPLE-FREE.COM".\r\n>>> Last update of whois database: 2026-11-12T09:51:48Z <<<\r\n', 'registry').notFound).toBe(true);
    expect(parseWhoisText('%% NOT FOUND\n', 'registry').notFound).toBe(true);
    expect(parseWhoisText('Query rate limit exceeded. Try again later.\n', 'registry').rateLimited).toBe(true);
    expect(parseWhoisDate('12-Jan-2009')).toBe('2009-01-12T00:00:00Z');
    expect(parseWhoisDate('2009.01.12 10:00:00')).toBe('2009-01-12T10:00:00Z');
    expect(parseWhoisDate('2027-01-13T00:12:14.000+00:00')).toBe('2027-01-13T00:12:14Z');
    expect(parseWhoisDate('2026-06-05T06:59:15.743011Z')).toBe('2026-06-05T06:59:15Z');
    expect(parseWhoisDate('31/12/2026')).toBe('2026-12-31T00:00:00Z');
  });
});

describe('redaction', () => {
  it('tells placeholders and privacy services from real values', () => {
    for (const v of ['REDACTED FOR PRIVACY', 'REDACTED REGISTRANT', 'Ano Nymous', 'Data Protected', 'Please query the RDDS service of the Registrar of Record']) expect(isPlaceholder(v), v).toBe(true);
    for (const v of ['NETIM SAS', 'Wikimedia Foundation', 'Jean Dupont']) expect(isPlaceholder(v), v).toBe(false);
    expect(isPrivacyOrg('Withheld for Privacy ehf')).toBe(true);
    expect(isPrivacyOrg('Domains By Proxy, LLC')).toBe(true);
    expect(isPrivacyOrg('ProxyDom')).toBe(true);
    expect(isPrivacyOrg('Association Française pour le Nommage Internet')).toBe(false);
  });
  it('reads RFC 9537 "redacted" members, by name (Netim) and by entity path (Afnic)', () => {
    const netim = parseRdapJson(fxJson('rdap-netim.json'), 'registrar');
    expect(netim.contacts.find((c) => c.role === 'registrant')).toMatchObject({ redacted: ['name', 'org', 'email'], contactUrl: 'https://www.netim.com/registrant-contact-form.html' });
    const afnic = parseRdapJson(fxJson('rdap-afnic-anonymous.json'), 'registry');
    expect(afnic.contacts.find((c) => c.role === 'registrant')).toEqual({ role: 'registrant', redacted: ['name', 'org', 'email'] });
    expect(afnic.contacts.find((c) => c.role === 'tech')).toMatchObject({ name: 'ProxyDom', privacyService: true });
    const open = parseRdapJson(fxJson('rdap-afnic.json'), 'registry');
    expect(open.contacts.find((c) => c.role === 'tech')).toMatchObject({ name: 'AFNIC', email: 'dnsops@afnic.fr', redacted: [] });
  });
});

describe('RDAP answers', () => {
  it('reads the registry answer and its link to the registrar (Verisign)', () => {
    const p = parseRdapJson(fxJson('rdap-verisign.json'), 'registry');
    expect(p).toMatchObject({
      created: '2008-04-05T17:48:51Z',
      expires: '2027-04-05T17:48:51Z',
      status: ['clientTransferProhibited'],
      registrar: { name: 'NETIM SAS', ianaId: '1519', rdapBase: 'https://netim.rdap.services/', url: 'http://www.netim.com/domain-name/' },
      registrarRdapUrl: 'https://netim.rdap.services/domain/EXEMPLE-AGENCE.COM',
      dnssec: false,
    });
  });
  it('reads the registrar answer: its own expiration event, "active" folded into the EPP codes', () => {
    const p = parseRdapJson(fxJson('rdap-netim.json'), 'registrar');
    expect(p.expires).toBe('2027-04-05T21:00:00Z');
    expect(p.status).toEqual(['clientTransferProhibited']);
    expect(p.reseller).toBeUndefined(); // reseller entity present, name empty
    expect(p.registrarRdapUrl).toBeUndefined();
  });
});

describe('registry against registrar', () => {
  const rec = (o: Partial<PartyRecord>): PartyRecord => ({ party: 'registry', protocol: 'rdap', server: 'x', status: [], registryStatus: [], contacts: [], nameservers: [], raw: '', ...o });
  it('flags only real differences', () => {
    const reg = rec({ ...parseRdapJson(fxJson('rdap-verisign.json'), 'registry') });
    const rar = rec({ party: 'registrar', ...parseRdapJson(fxJson('rdap-netim.json'), 'registrar') });
    const d = divergences(reg, rar);
    // same day for creation and expiration, same IANA id, same name servers once lowercased
    expect(d).toEqual([{ field: 'updated', label: 'Dernière modification', registry: '2026-03-28T23:35:18Z', registrar: '2024-09-02T08:08:38Z', expected: true }]);
    const late = divergences(reg, { ...rar, expires: '2028-04-05T00:00:00Z', nameservers: ['ns1.other.net'], status: ['clientHold'], registrar: { ...rar.registrar, ianaId: '292' } });
    expect(late.map((x) => x.field).sort()).toEqual(['expires', 'ianaId', 'nameservers', 'status', 'updated']);
  });
  it('compares registrar names without legal forms', () => {
    expect(sameRegistrar('NETIM SAS', 'NETIM')).toBe(true);
    expect(sameRegistrar('MarkMonitor Inc.', 'Markmonitor Inc.')).toBe(true);
    expect(sameRegistrar('OVH SAS', 'Gandi SAS')).toBe(false);
  });
  it('merges: registry dates and statuses, the most visible contact per role', () => {
    const reg = rec({ created: '2001-01-01T00:00:00Z', expires: '2027-01-01T00:00:00Z', contacts: [{ role: 'tech', org: 'Registre', redacted: [] }] });
    const rar = rec({ party: 'registrar', expires: '2027-06-01T00:00:00Z', reseller: 'Revendeur', contacts: [{ role: 'tech', redacted: ['name', 'org', 'email'] }, { role: 'registrant', name: 'Jean', redacted: [] }] });
    const m = merge(reg, rar, NOW);
    expect(m.expires).toBe('2027-01-01T00:00:00Z');
    expect(m.reseller).toBe('Revendeur');
    expect(m.contacts).toEqual([{ role: 'registrant', name: 'Jean', redacted: [] }, { role: 'tech', org: 'Registre', redacted: [] }]);
    expect(m.expiresInDays).toBe(49);
  });
});

describe('A records beside the Whois', () => {
  it('asks DNS for the registrable name, deduplicates, and carries the addresses to the row', async () => {
    const { deps } = fakeDeps();
    const asked: string[] = [];
    const r = await lookupWhois('www.exemple-agence.com', { ...deps, resolveA: async (n) => (asked.push(n), ['203.0.113.7', '203.0.113.7', '198.51.100.2']) });
    expect(asked).toEqual(['exemple-agence.com']);
    expect(r.a).toEqual(['203.0.113.7', '198.51.100.2']);
    expect(toRow(r).a).toEqual(['203.0.113.7', '198.51.100.2']);
  });

  it('keeps [] for a name without A records and leaves the field out when DNS failed', async () => {
    const { deps } = fakeDeps();
    expect((await lookupWhois('exemple-agence.com', { ...deps, fresh: true, resolveA: async () => [] })).a).toEqual([]);
    const failed = await lookupWhois('exemple-agence.com', { ...deps, fresh: true, resolveA: async () => Promise.reject(new Error('SERVFAIL')) });
    expect(failed.a).toBeUndefined();
    expect('a' in toRow(failed)).toBe(false);
    expect(failed.merged.registrar?.name).toBe('NETIM SAS');
  });
});

describe('lookup order and fallbacks', () => {
  it('asks the registry then the registrar by RDAP, with the related link', async () => {
    const { deps, net } = fakeDeps();
    const r = await lookupWhois('www.exemple-agence.com', deps);
    expect(net.http).toEqual(['https://data.iana.org/rdap/dns.json', 'https://rdap.verisign.com/com/v1/domain/exemple-agence.com', 'https://netim.rdap.services/domain/EXEMPLE-AGENCE.COM']);
    expect(net.whois).toEqual([]);
    expect(r.attempts.map((a) => `${a.party}:${a.protocol}:${a.status}`)).toEqual(['registry:rdap:ok', 'registrar:rdap:ok']);
    expect(r.queried).toBe('exemple-agence.com');
    expect(r.merged.registrar?.name).toBe('NETIM SAS');
    const a = whoisAnalysis(r);
    expect(a.unavailable).toEqual([]);
    expect(a.passed.map((p) => p.id)).toEqual(['rdap.expiration', 'rdap.transfer_lock', 'whois.sources_agree']);
  });

  it('falls back to WHOIS when the registry RDAP says 429, honours Retry-After, finds the registrar from its IANA id', async () => {
    const { deps, net, clock: c } = fakeDeps({ http: { 'https://rdap.verisign.com/com/v1/domain/exemple-agence.com': () => resp('{}', 429, { 'retry-after': '120' }) } });
    const r = await lookupWhois('exemple-agence.com', deps);
    expect(r.attempts.map((a) => `${a.party}:${a.protocol}:${a.server}:${a.status}`)).toEqual([
      'registry:rdap:rdap.verisign.com:rate_limited',
      'registry:whois:whois.verisign-grs.com:ok',
      'registrar:rdap:netim.rdap.services:ok',
    ]);
    expect(r.attempts[0].reason).toMatch(/120 s/);
    expect(net.whois).toEqual(['whois.iana.org com', 'whois.verisign-grs.com exemple-agence.com']);
    expect(net.http).toContain('https://www.iana.org/assignments/registrar-ids/registrar-ids.xml');
    expect(deps.limiter!.blockedFor('rdap.verisign.com')).toBe(120_000);
    // the next lookup does not knock on the blocked server again: straight to WHOIS
    c.advance(5000);
    const again = await lookupWhois('exemple-agence.com', { ...deps, fresh: true });
    expect(again.attempts[0]).toMatchObject({ server: 'rdap.verisign.com', status: 'rate_limited' });
    expect(net.http.filter((u) => u.includes('verisign')).length).toBe(1);
  });

  it('uses the registrar WHOIS when its RDAP fails, and says which source answered', async () => {
    const { deps } = fakeDeps({ http: { 'https://netim.rdap.services/domain/EXEMPLE-AGENCE.COM': () => resp('oops', 503) } });
    const r = await lookupWhois('exemple-agence.com', deps);
    expect(r.attempts.map((a) => `${a.party}:${a.protocol}:${a.status}`)).toEqual(['registry:rdap:ok', 'registrar:rdap:error', 'registry:whois:ok', 'registrar:whois:ok']);
    expect(r.registrar).toMatchObject({ protocol: 'whois', server: 'whois.netim.com' });
    expect(toRow(r)).toMatchObject({ registrySource: 'RDAP rdap.verisign.com', registrarSource: 'WHOIS whois.netim.com' });
  });

  it('queries a TLD without RDAP over WHOIS only, and says no registrar server is named', async () => {
    const { deps } = fakeDeps();
    const r = await lookupWhois('wikipedia.de', deps);
    expect(r.attempts.map((a) => `${a.protocol}:${a.status}`)).toEqual(['rdap:unsupported', 'whois:ok']);
    expect(r.registry?.status).toEqual(['connect']);
    expect(r.registrarNotAnnounced).toBe(true);
    expect(whoisAnalysis(r).unavailable).toEqual([]);
  });

  it('stops at the registry for an unregistered name', async () => {
    const { deps, net } = fakeDeps({ http: { 'https://rdap.verisign.com/com/v1/domain/libre-123.com': () => resp({ errorCode: 404 }, 404) } });
    const r = await lookupWhois('libre-123.com', deps);
    expect(r.notFound).toBe(true);
    expect(net.http.length).toBe(2);
    expect(whoisAnalysis(r).issues.map((i) => i.id)).toEqual(['infrastructure.domain_not_registered']);
  });

  it('keeps a registrar 404 as final (no WHOIS behind it)', async () => {
    const { deps, net } = fakeDeps({ http: { 'https://netim.rdap.services/domain/EXEMPLE-AGENCE.COM': () => resp({}, 404) } });
    const r = await lookupWhois('exemple-agence.com', deps);
    expect(r.registrarUnknown).toBe(true);
    expect(net.whois).toEqual([]);
    expect(whoisAnalysis(r).unavailable).toEqual([]);
  });

  it('gives a provisional result when every registry source fails', async () => {
    const { deps } = fakeDeps({ http: { 'https://rdap.verisign.com/com/v1/domain/exemple-agence.com': () => resp('', 500) }, whois: { 'whois.verisign-grs.com exemple-agence.com': () => '' } });
    deps.whois43 = async (host, q) => {
      if (host === 'whois.iana.org') return answer(fx('iana-referral-com.txt'));
      throw Object.assign(new Error(`délai dépassé ${q}`), { code: 'timeout' });
    };
    const r = await lookupWhois('exemple-agence.com', { ...deps, maxWaitMs: 60_000 });
    expect(r.registry).toBeUndefined();
    const a = whoisAnalysis(r);
    expect(a.unavailable?.[0].source).toBe('whois-registre');
    expect(a.unavailable?.[0].reason).toMatch(/rdap\.verisign\.com \(RDAP\) : HTTP 500/);
    expect(a.unavailable?.[0].reason).not.toMatch(/exemple-agence/);
    expect(toRow(r)).toMatchObject({ ok: false, domain: 'exemple-agence.com' });
  });

  it('keeps an answer 10 minutes per notebook, unless asked fresh', async () => {
    const cache = new WhoisCache(10 * 60_000, 10, () => NOW);
    const { deps, net } = fakeDeps({}, { cache, scope: 'carnet-a' });
    await lookupWhois('exemple-agence.com', deps);
    const n = net.http.length;
    const hit = await lookupWhois('exemple-agence.com', deps);
    expect(net.http.length).toBe(n);
    expect(hit.cachedAt).toBe(hit.lookedUpAt);
    await lookupWhois('exemple-agence.com', { ...deps, scope: 'carnet-b' });
    expect(net.http.length).toBeGreaterThan(n);
    const m = net.http.length;
    await lookupWhois('exemple-agence.com', { ...deps, fresh: true });
    expect(net.http.length).toBeGreaterThan(m);
  });

  it('runs a list a few at a time, rows in input order', async () => {
    const { deps } = fakeDeps();
    const seen: string[] = [];
    const rows = await lookupMany(['exemple-agence.com', 'wikipedia.de', 'afnic.fr'], (d) => lookupWhois(d, deps), { onRow: (r) => seen.push(r.domain), concurrency: 2 });
    expect(rows.map((r) => r.domain)).toEqual(['exemple-agence.com', 'wikipedia.de', 'afnic.fr']);
    expect(seen.sort()).toEqual(['afnic.fr', 'exemple-agence.com', 'wikipedia.de']);
    expect(rows[2]).toMatchObject({ registrar: 'Registry Operations', registrySource: 'RDAP rdap.nic.fr' });
  });
});

describe('domain lists', () => {
  it('deduplicates on the registrable name, converts IDN, rejects junk', () => {
    const p = parseDomainList('exemple-agence.com\nwww.exemple-agence.com, https://café.fr/menu ; pas un domaine ; fr ;;');
    expect(p.domains).toEqual(['exemple-agence.com', 'xn--caf-dma.fr']);
    expect(p.duplicates).toBe(1);
    expect(p.invalid.map((i) => i.value)).toEqual(['pas', 'un', 'domaine', 'fr']);
  });
});

describe('politeness limiter', () => {
  it('spaces requests to one host and runs them one at a time', async () => {
    const c = clock();
    const l = new PoliteLimiter({ now: c.now, sleep: c.sleep });
    const starts: number[] = [];
    let running = 0;
    let maxRunning = 0;
    const job = () => l.run('whois.example', { minIntervalMs: 3000 }, async () => {
      starts.push(c.now());
      running++;
      maxRunning = Math.max(maxRunning, running);
      await Promise.resolve();
      running--;
    }, 60_000);
    await Promise.all([job(), job(), job()]);
    expect(starts.map((s) => s - NOW)).toEqual([0, 3000, 6000]);
    expect(maxRunning).toBe(1);
  });
  it('refuses at once when the queue is longer than the caller accepts', async () => {
    const c = clock();
    const l = new PoliteLimiter({ now: c.now, sleep: c.sleep });
    l.penalize('rdap.example', 120_000);
    await expect(l.run('rdap.example', { minIntervalMs: 1000 }, async () => 1, 15_000)).rejects.toBeInstanceOf(RateLimitedError);
    await expect(l.run('rdap.example', { minIntervalMs: 1000 }, async () => 1, 200_000)).resolves.toBe(1);
    expect(c.now() - NOW).toBe(120_000);
  });
  it('doubles the pause after each failure, up to 5 minutes, and forgets on success', () => {
    const c = clock();
    const l = new PoliteLimiter({ now: c.now, sleep: c.sleep });
    const waits = [1, 2, 3, 4, 5, 6, 7, 8, 9].map(() => (l.penalize('h'), l.blockedFor('h')));
    expect(waits.slice(0, 4)).toEqual([5000, 10000, 20000, 40000]);
    expect(Math.max(...waits)).toBe(300_000);
    l.succeed('h');
    c.advance(300_000);
    l.penalize('h');
    expect(l.blockedFor('h')).toBe(5000);
  });
  it('caps a Retry-After at 10 minutes and reads both of its forms', () => {
    const c = clock();
    const l = new PoliteLimiter({ now: c.now, sleep: c.sleep });
    l.penalize('h', 3600_000);
    expect(l.blockedFor('h')).toBe(600_000);
    expect(parseRetryAfter('30', NOW)).toBe(30_000);
    expect(parseRetryAfter(new Date(NOW + 90_000).toUTCString(), NOW)).toBe(90_000);
    expect(parseRetryAfter('bientôt', NOW)).toBeUndefined();
  });
  it('keeps at most N requests in flight for the whole process', async () => {
    const c = clock();
    const l = new PoliteLimiter({ now: c.now, sleep: c.sleep, globalMax: 2 });
    let running = 0;
    let maxRunning = 0;
    const gates: (() => void)[] = [];
    const job = (h: string) =>
      l.run(h, { minIntervalMs: 0 }, async () => {
        running++;
        maxRunning = Math.max(maxRunning, running);
        await new Promise<void>((r) => gates.push(r));
        running--;
      }, 1000);
    const all = Promise.all(['a', 'b', 'c', 'd'].map(job));
    for (let i = 0; i < 20 && gates.length < 4; i++) {
      await new Promise((r) => setTimeout(r, 0));
      gates.shift()?.();
    }
    while (gates.length) gates.shift()!();
    await all;
    expect(maxRunning).toBe(2);
  });
});

describe('IANA lists', () => {
  it('reads registrar RDAP bases and file lifetimes', () => {
    expect(parseRegistrarIds(REGISTRAR_IDS)).toEqual(new Map([['1519', 'https://netim.rdap.services/']]));
    expect(lifetime({ expires: new Date(NOW + 3600_000).toUTCString() }, NOW, 1, 300_000)).toBe(3600_000);
    expect(lifetime({ expires: new Date(NOW + 60_000).toUTCString() }, NOW, 1, 300_000)).toBe(300_000);
    expect(lifetime({ 'cache-control': 'public, max-age=86400' }, NOW, 1, 0)).toBe(86_400_000);
    expect(lifetime({}, NOW, 42, 0)).toBe(42);
  });
  it('downloads the RDAP bootstrap once, and keeps the old copy when a refresh fails', async () => {
    const c = clock();
    const dir = new WhoisDirectory(c.now);
    let calls = 0;
    let fail = false;
    const http = async () => {
      calls++;
      if (fail) throw new Error('réseau coupé');
      return resp(fx('iana-bootstrap.json'), 200, { 'cache-control': 'max-age=86400' });
    };
    expect(await dir.rdapBase(http, 'exemple-agence.com')).toBe('https://rdap.verisign.com/com/v1/');
    expect(await dir.rdapBase(http, 'afnic.fr')).toBe('https://rdap.nic.fr/');
    expect(await dir.rdapBase(http, 'wikipedia.de')).toBeNull();
    expect(calls).toBe(1);
    c.advance(86_400_001);
    fail = true;
    expect(await dir.rdapBase(http, 'exemple-agence.com')).toBe('https://rdap.verisign.com/com/v1/');
    expect(calls).toBe(2);
  });
});
