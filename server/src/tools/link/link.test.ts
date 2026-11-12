// Link check: input, brand look-alikes and homoglyphs, page reading, the redirect chain on a
// local fake server (fetch injected: safeGet refuses private addresses and that protection is
// never turned off), the SSRF guard of the production dependencies, threat sources on a fake
// server, and real chains (http://github.com, a shortener) and real domain lists.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { fetch as ufetch } from 'undici';
import type { AddressInfo } from 'node:net';
import { domainToASCII } from 'node:url';
import { config } from '../../config.js';
import { openDb } from '../../db.js';
import { ResolveSession } from '../../dns/iterative.js';
import { toFindings } from '../../lib/email-auth/common.js';
import { explain } from '../../knowledge/engine.js';
import { guardedDnsblResolver } from '../../lib/reputation/dnsbl-lists.js';
import { fakeServer, type FakeReply, type FakeRequest, type FakeServer } from '../../lib/reputation/fake-server.js';
import { RateLimiter } from '../../lib/reputation/limiter.js';
import { resetOpenPhishFeed } from '../../lib/reputation/openphish.js';
import type { SafeFetchResult } from '../../lib/net.js';
import type { ToolContext } from '../types.js';
import { analyzeLink, normalizeLinkInput, type LinkDeps } from './analyze.js';
import { brandsInTitle, editDistance, findLookalikes, skeleton } from './brands.js';
import { followChain } from './chain.js';
import { analyzeDomainLists } from './domain.js';
import { linkDeps, tool } from './index.js';
import { readPage } from './page.js';
import { describeCert } from './tls.js';

const ctx: ToolContext = { db: openDb(':memory:'), config, dns: (o) => new ResolveSession(o) };

describe('input', () => {
  it('adds the scheme, refuses other protocols, flags dangerous ones without fetching', () => {
    expect(normalizeLinkInput('exemple.fr/promo').url).toBe('http://exemple.fr/promo');
    expect(normalizeLinkInput('https://Exemple.FR').url).toBe('https://exemple.fr/');
    expect(normalizeLinkInput('javascript:alert(1)').unsafe).toBe('javascript:');
    expect(normalizeLinkInput('data:text/html,<h1>x</h1>').unsafe).toBe('data:');
    expect(() => normalizeLinkInput('ftp://exemple.fr/')).toThrow(/ftp/);
    expect(() => normalizeLinkInput('  ')).toThrow(/vide/);
  });
});

describe('brands and homoglyphs', () => {
  const kinds = (host: string) => findLookalikes(host).map((l) => `${l.brand}:${l.kind}`);

  it('catches homoglyphs, typos, the brand in front of another domain, brand plus phishing word', () => {
    const cyr = domainToASCII('pаypal.com'); // Cyrillic а
    expect(cyr.startsWith('xn--')).toBe(true);
    expect(kinds(cyr)).toEqual(['paypal:homoglyph']);
    expect(findLookalikes(cyr)[0].unicode).toBe('pаypal.com');
    expect(kinds('paypa1.com')).toEqual(['paypal:homoglyph']);
    expect(kinds('arnazon.fr')).toEqual(['amazon:homoglyph']);
    expect(kinds('micrsoft.com')).toEqual(['microsoft:typo']);
    expect(kinds('paypai.com')).toEqual(['paypal:typo']);
    expect(kinds('paypal.com.verif-compte.ru')).toContain('paypal:subdomain');
    expect(kinds('laposte-colis-suivi.com')).toEqual(['laposte:word']);
    expect(findLookalikes('laposte-colis-suivi.com')[0].phishingWord).toBe('colis');
    expect(kinds('credit-agricole-securite.fr')).toEqual(['creditagricole:contains']);
    expect(kinds('lcl-connexion.fr')).toEqual(['lcl:word']);
  });

  it('leaves official domains and ordinary names alone', () => {
    for (const h of ['www.paypal.com', 'login.microsoftonline.com', 'www.impots.gouv.fr', 'mabanque.bnpparibas', 'www.google.de', 'colis.laposte.fr', 'accounts.google.com'])
      expect(findLookalikes(h), h).toEqual([]);
    for (const h of ['amelie-fleurs.fr', 'pineapple.fr', 'orange-mecanique.fr', 'cicada.org', 'github.com', 'lemonde.fr', 'appleton.example'])
      expect(findLookalikes(h), h).toEqual([]);
  });

  it('skeleton and distance', () => {
    expect(skeleton('Ρаураl')).toBe('paypal'); // Greek Ρ, Cyrillic а у
    expect(editDistance('paypal', 'paypla')).toBe(1);
    expect(editDistance('microsoft', 'micrsoft')).toBe(1);
  });

  it('brands named in a title', () => {
    expect(brandsInTitle('Connexion - Crédit Agricole').map((b) => b.id)).toEqual(['creditagricole']);
    expect(brandsInTitle('Votre colis Colissimo est en attente').map((b) => b.id)).toEqual(['colissimo']);
    expect(brandsInTitle('Recette de la tarte aux pommes')).toEqual([]);
  });
});

describe('page reading (nothing executed)', () => {
  it('meta refresh, simple JavaScript redirects on short pages only, forms, title', () => {
    expect(readPage('<meta http-equiv="refresh" content="0; url=/suite">', 'https://a.test/x').metaRefresh).toEqual({ url: 'https://a.test/suite', delay: 0 });
    expect(readPage(`<meta content='3;URL="https://b.test/"' http-equiv='Refresh'>`, 'https://a.test/').metaRefresh?.url).toBe('https://b.test/');
    expect(readPage('<meta http-equiv="refresh" content="30">', 'https://a.test/').metaRefresh).toBeUndefined();
    expect(readPage('<script>window.location.href = "https://c.test/p";</script>', 'https://a.test/').jsRedirect?.url).toBe('https://c.test/p');
    expect(readPage("<script>top.location.replace('/q')</script>", 'https://a.test/').jsRedirect?.url).toBe('https://a.test/q');
    const long = `<p>${'texte '.repeat(400)}</p><script>function go(){ location.href = "https://d.test/"; }</script>`;
    expect(readPage(long, 'https://a.test/').jsRedirect).toBeUndefined();
    const p = readPage(
      '<title>PayPal &amp; vous</title><form action="https://collecte.test/post"><input type="email"><input type="password" name="pw"></form><form><input name="cardNumber"><input autocomplete="cc-csc"></form>',
      'https://a.test/',
    );
    expect(p).toMatchObject({ title: 'PayPal & vous', passwordForm: true, cardForm: true, formActions: ['https://collecte.test/post'] });
    expect(readPage('<p>Où trouver le cryptogramme de ma carte ?</p>', 'https://a.test/').cardForm).toBe(false);
  });
});

describe('certificate description', () => {
  it('age, expiry, free authority, name check', () => {
    const now = Date.parse('2026-11-10T00:00:00Z');
    const cert = {
      subject: { CN: 'connexion.test' },
      issuer: { O: "Let's Encrypt", CN: 'R11' },
      subjectaltname: 'DNS:connexion.test, DNS:www.connexion.test',
      valid_from: 'Nov  8 00:00:00 2026 GMT',
      valid_to: 'Feb  6 00:00:00 2027 GMT',
      fingerprint256: 'AA:BB',
    } as unknown as import('node:tls').PeerCertificate;
    const t = describeCert('www.connexion.test', '192.0.2.1', 443, cert, true, undefined, 'TLSv1.3', now);
    expect(t).toMatchObject({ ageDays: 2, freeCa: true, nameMatches: true, expired: false, selfSigned: false, issuerOrg: "Let's Encrypt" });
    expect(describeCert('autre.test', '192.0.2.1', 443, cert, false, 'ERR_TLS_CERT_ALTNAME_INVALID', 'TLSv1.3', now).nameMatches).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
// Redirect chain on a local server. The production fetch (safeGet) refuses 127.0.0.1, so the
// tests inject a fetch that maps fake host names to the local server.

let site: FakeServer;
const pages: Record<string, (r: FakeRequest) => FakeReply> = {
  'go.test/start': () => ({ status: 301, headers: { location: '/etape' } }),
  'go.test/etape': () => ({ headers: { 'content-type': 'text/html' }, body: '<html><head><meta http-equiv="refresh" content="0; url=http://relais.test/js"></head></html>' }),
  'relais.test/js': () => ({ headers: { 'content-type': 'text/html' }, body: '<html><script>window.location = "http://paypal-verification-compte.test/login";</script></html>' }),
  'paypal-verification-compte.test/login': () => ({
    headers: { 'content-type': 'text/html; charset=utf-8' },
    body: '<html><head><title>PayPal - Connexion à votre compte</title></head><body><form action="/vol"><input type="email" name="e"><input type="password" name="p"></form></body></html>',
  }),
  'boucle.test/a': () => ({ status: 302, headers: { location: '/b' } }),
  'boucle.test/b': () => ({ status: 302, headers: { location: '/a' } }),
  'gros.test/': () => ({ headers: { 'content-type': 'application/octet-stream' }, body: 'x'.repeat(3 * 1024 * 1024) }),
  'propre.test/': () => ({ headers: { 'content-type': 'text/html' }, body: '<title>Atelier</title><p>Bienvenue</p>' }),
  'retire.test/': () => ({ status: 404, headers: { 'content-type': 'text/html' }, body: '<title>Colissimo - Suivi</title><form><input type="password"></form><meta http-equiv="refresh" content="0; url=/ailleurs">' }),
  'court.test/x': () => ({ status: 301, headers: { location: 'http://port.test:8080/' } }),
  'port.test/': () => ({ status: 500, headers: { 'content-type': 'application/json' }, body: '{}' }),
};
beforeAll(async () => {
  site = await fakeServer((r) => {
    const host = String(r.headers['x-fake-host'] ?? '');
    const sauts = /^\/saut\/(\d+)$/.exec(r.path);
    if (host === 'sans-fin.test' && sauts) return { status: 302, headers: { location: `/saut/${Number(sauts[1]) + 1}` } };
    return (pages[`${host}${r.path}`] ?? (() => ({ status: 404, body: 'absent' })))(r);
  });
});
afterAll(() => site.close());

/** Fetch of the tests: the host name goes in a header, the connection to the local server. */
const localFetch = async (url: string, opts: { maxBytes: number }): Promise<SafeFetchResult> => {
  const u = new URL(url);
  const started = performance.now();
  const res = await ufetch(`${site.base}${u.pathname}${u.search}`, { redirect: 'manual', headers: { 'x-fake-host': u.hostname } });
  const chunks: Buffer[] = [];
  let size = 0;
  let truncated = false;
  for await (const c of res.body as AsyncIterable<Uint8Array>) {
    size += c.length;
    if (size > opts.maxBytes) {
      truncated = true;
      break;
    }
    chunks.push(Buffer.from(c));
  }
  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => (headers[k] = v));
  return { url, status: res.status, headers, body: Buffer.concat(chunks), truncated, ms: Math.round(performance.now() - started) };
};
const fakeDeps = (extra: Partial<LinkDeps> = {}): LinkDeps => ({
  fetch: localFetch,
  resolveHost: async () => ({ ip: '192.0.2.80' }),
  keys: { safeBrowsing: '', virusTotal: '', urlhaus: '' },
  http: false,
  ...extra,
});

describe('redirect chain, local server', () => {
  it('follows HTTP 3xx, meta refresh and a JavaScript redirect, each hop with status, time, IP and domain', async () => {
    const hops: number[] = [];
    const c = await followChain('http://go.test/start', { fetch: localFetch, resolveHost: async () => ({ ip: '192.0.2.80' }), onHop: (h) => hops.push(h.index) });
    expect(c.hops.map((h) => `${h.status} ${h.via}>${h.next ?? '-'} ${h.url}`)).toEqual([
      '301 start>http http://go.test/start',
      '200 http>meta http://go.test/etape',
      '200 meta>js http://relais.test/js',
      '200 js>- http://paypal-verification-compte.test/login',
    ]);
    expect(hops).toEqual([1, 2, 3, 4]);
    expect(c.hops.every((h) => h.ip === '192.0.2.80' && h.ms >= 0)).toBe(true);
    expect(c.hops[2].domain).toBe('relais.test');
    expect(c.final).toBe('http://paypal-verification-compte.test/login');
    expect(c.finalPage?.passwordForm).toBe(true);
  });

  it('stops on a loop, at 15 hops, and never reads more than 2 MB', async () => {
    const dep = { fetch: localFetch, resolveHost: async () => ({ ip: '192.0.2.80' }) };
    expect((await followChain('http://boucle.test/a', dep)).stoppedBy).toBe('loop');
    const endless = await followChain('http://sans-fin.test/saut/1', dep);
    expect(endless.stoppedBy).toBe('max_hops');
    expect(endless.hops).toHaveLength(15);
    const big = await followChain('http://gros.test/', dep);
    expect(big.hops[0].truncated).toBe(true);
    expect(big.hops[0].bytes).toBeLessThanOrEqual(2 * 1024 * 1024);
  });

  it('a phishing page at the end of the chain is "dangereux" with the reason in one sentence', async () => {
    const steps: string[] = [];
    const a = await analyzeLink('http://go.test/start', fakeDeps({ rdap: async (d) => (d.startsWith('paypal') ? { ageDays: 2, created: '2026-11-08T00:00:00Z' } : { ageDays: 4000 }) }), { onStep: (s) => steps.push(s.step) });
    expect(a.data.verdict).toBe('dangereux');
    expect(a.data.level).toBe('dangerous');
    expect(a.data.reason).toMatch(/mot de passe.*\.$/);
    const ids = toFindings(a.issues).map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(['phishing.credential_form', 'phishing.brand_lookalike', 'link.domain_recent', 'phishing.js_redirect']));
    expect(steps.filter((s) => s === 'hop')).toHaveLength(4);
    expect(steps).toEqual(expect.arrayContaining(['chain', 'rdap', 'page', 'heuristics']));
    expect(a.data.page?.brandsInTitle).toEqual(['paypal']);
  });

  it('a plain page is "sûr", and the reason says which sources were not consulted', async () => {
    const a = await analyzeLink('http://propre.test/', fakeDeps({ rdap: async () => ({ ageDays: 3000 }) }));
    expect(a.data.verdict).toBe('sûr');
    expect(a.data.reason).toMatch(/Aucune source de réputation n’a pu être consultée|sources de réputation consultées/);
  });

  it('reads the final page even in 4xx when it is HTML, exposes the final status, does not follow its redirects', async () => {
    const a = await analyzeLink('http://retire.test/', fakeDeps({ rdap: async () => ({ ageDays: 3000 }) }));
    expect(a.data.finalStatus).toBe(404);
    expect(a.data.chain.hops).toHaveLength(1);
    expect(a.data.page).toMatchObject({ title: 'Colissimo - Suivi', passwordForm: true, brandsInTitle: ['colissimo'] });
    const f = toFindings(a.issues);
    expect(f.find((x) => x.id === 'link.unreachable')).toMatchObject({ severity: 'info', penalty: 0 });
    expect(f.map((x) => x.id)).toContain('phishing.credential_form');
    const json = await analyzeLink('http://port.test:8080/', fakeDeps({ rdap: async () => ({ ageDays: 3000 }) }));
    expect(json.data.finalStatus).toBe(500);
    expect(json.data.page).toBeUndefined();
  });

  it('the link page has its own texts: none of them talks about a message', async () => {
    const a = await analyzeLink('http://court.test/x', fakeDeps({ rdap: async () => ({ ageDays: 3, created: '2026-11-07T00:00:00Z' }) }));
    const f = toFindings(a.issues);
    const ids = f.map((x) => x.id);
    expect(ids).toEqual(expect.arrayContaining(['link.nonstandard_port', 'link.unreachable', 'link.domain_recent']));
    for (const x of f) {
      expect(x.fallback, x.id).toBeFalsy();
      expect(`${x.title} ${x.why} ${x.fix.join(' ')}`, x.id).not.toMatch(/message|newsletter|destinataire/i);
    }
    expect(f.find((x) => x.id === 'link.unreachable')!.fix.join(' ')).toMatch(/curl -I/);
  });

  it('no step of the link page invites to open, click or visit the link', async () => {
    const invite = /(?<![Nn]['’])\b(ouvrez|cliquez|visitez|suivez)\s+(le|ce)\s+lien|dans un navigateur pour confirmer|si vous ne connaissez pas le site/i;
    const runs = [
      await analyzeLink('http://court.test/x', fakeDeps({ rdap: async () => ({ ageDays: 3 }) })),
      await analyzeLink('http://go.test/start', fakeDeps({ rdap: async () => ({ ageDays: 2 }) })),
      await analyzeLink('http://retire.test/', fakeDeps({ rdap: async () => ({ ageDays: 3000 }) })),
    ];
    const ids = ['link.shortener', 'link.nonstandard_port', 'link.domain_listed', 'link.domain_recent', 'link.unreachable', 'link.redirect_chain', 'link.punycode_lookalike', 'link.private_target'];
    const all = [...runs.flatMap((a) => toFindings(a.issues)), ...ids.map((id) => explain({ id, vars: { url: 'http://x.test/', domain: 'x.test', value: 'v', list_name: 'L', delist_url: 'https://l.test/' } }))];
    for (const x of all) for (const step of x.fix) expect(step, x.id).not.toMatch(invite);
  });

  it('javascript: is dangerous without any request', async () => {
    const a = await analyzeLink('javascript:document.location="https://x.test/"', fakeDeps({ fetch: () => Promise.reject(new Error('no network')) }));
    expect(a.data.verdict).toBe('dangereux');
    expect(toFindings(a.issues)[0].id).toBe('links.unsafe_scheme');
  });
});

describe('SSRF guard of the production dependencies', () => {
  it('a private IP literal or a host resolving to one is never fetched', async () => {
    const before = site.requests.length;
    const a = await analyzeLink(`http://127.0.0.1:${site.port}/`, { ...linkDeps(ctx), http: false, dnsblResolverFor: undefined, rdap: undefined });
    expect(a.data.chain.stoppedBy).toBe('unsafe');
    expect(a.data.chain.hops[0].error).toMatch(/non publique/);
    expect(site.requests.length).toBe(before);
    const deps = linkDeps(ctx);
    await expect(deps.fetch(`http://[::ffff:127.0.0.1]:${site.port}/`, { maxBytes: 100 })).rejects.toThrow(/non publique/);
    expect(await deps.resolveHost('10.0.0.1')).toMatchObject({ error: expect.stringMatching(/non publique/) });
    expect(site.requests.length).toBe(before);
  });
});

describe('threat sources, fake server', () => {
  let intel: FakeServer;
  beforeAll(async () => {
    resetOpenPhishFeed();
    intel = await fakeServer((r) => {
      if (r.path === '/feed.txt') return { body: 'http://propre.test/\n' };
      if (r.path.startsWith('/v4/threatMatches')) return { body: { matches: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threat: { url: 'http://propre.test/' } }] } };
      if (r.path.startsWith('/api/v3/urls/')) return { status: 404, body: {} };
      if (r.path === '/v1/url/' || r.path === '/v1/host/') return { body: { query_status: 'no_results' } };
      if (r.path.startsWith('/api/v1/search/')) return { body: { total: 0, results: [] } };
      return { status: 404 };
    });
  });
  afterAll(async () => {
    await intel.close();
    resetOpenPhishFeed();
  });

  it('Safe Browsing and OpenPhish matches make the link dangerous; every source is queried on the start and the final URL', async () => {
    const steps: { step: string; status: string }[] = [];
    const a = await analyzeLink(
      'http://propre.test/',
      fakeDeps({
        http: true,
        apiFetch: intel.fetch,
        bases: { safebrowsing: intel.base, virustotal: intel.base, urlhaus: intel.base, urlscan: intel.base },
        openPhishFeed: `${intel.base}/feed.txt`,
        keys: { safeBrowsing: 'g', virusTotal: 'v', urlhaus: 'u' },
        vtLimiter: new RateLimiter(100, 100, 'VirusTotal'),
        rdap: async () => ({ ageDays: 3000 }),
      }),
      { onStep: (s) => steps.push({ step: s.step, status: s.status }) },
    );
    expect(a.data.verdict).toBe('dangereux');
    const ids = toFindings(a.issues).map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(['phishing.safe_browsing', 'phishing.openphish']));
    expect(a.data.reason).toMatch(/Google Safe Browsing|OpenPhish/);
    for (const id of ['safebrowsing', 'virustotal', 'urlhaus', 'openphish', 'urlscan']) expect(steps.find((s) => s.step === id)?.status, id).toBe('ok');
    expect(a.passed.map((p) => p.id)).toEqual(expect.arrayContaining(['phishing.virustotal_unknown', 'phishing.urlhaus']));
    const vtCalls = intel.requests.filter((r) => r.path.startsWith('/api/v3/urls/'));
    expect(vtCalls.every((r) => r.method === 'GET')).toBe(true);
  });

  it('without keys, the keyed sources are listed as unavailable, never an error', async () => {
    const a = await analyzeLink('http://propre.test/', fakeDeps({ http: true, apiFetch: intel.fetch, bases: { urlscan: intel.base }, openPhishFeed: `${intel.base}/feed.txt` }));
    const un = a.unavailable!.map((u) => u.source);
    expect(un).toEqual(expect.arrayContaining(['safebrowsing', 'virustotal', 'urlhaus']));
    expect(a.unavailable!.find((u) => u.source === 'safebrowsing')!.reason).toMatch(/GSB_API_KEY/);
  });
});

// ---------------------------------------------------------------------------------------------
// Real network

describe('real chains and lists', () => {
  it('http://github.com redirects to https://github.com/, certificate valid, verdict "sûr"', async () => {
    const a = await analyzeLink('http://github.com', { ...linkDeps(ctx), http: false });
    const hops = a.data.chain.hops;
    expect(hops[0]).toMatchObject({ url: 'http://github.com/', status: 301, location: 'https://github.com/' });
    expect(hops[1].url).toBe('https://github.com/');
    expect(hops.every((h) => h.ip && h.domain === 'github.com')).toBe(true);
    expect(a.data.final.startsWith('https://github.com/')).toBe(true);
    expect(a.data.tls[0]).toMatchObject({ host: 'github.com', authorized: true, nameMatches: true });
    expect(a.data.domains[0].ageDays).toBeGreaterThan(5000);
    expect(a.data.verdict).toBe('sûr');
  }, 60000);

  it('a known shortener: https://bit.ly/ leads to bitly.com and is flagged as a shortener', async () => {
    const a = await analyzeLink('https://bit.ly/', { ...linkDeps(ctx), http: false });
    expect(a.data.chain.hops.map((h) => h.host)).toEqual(['bit.ly', 'bitly.com']);
    expect(toFindings(a.issues).map((f) => f.id)).toContain('link.shortener');
  }, 60000);

  it('domain lists: the Spamhaus DBL test domain is listed, google.com is not', async () => {
    const resolverFor = guardedDnsblResolver(() => new ResolveSession());
    const bad = await analyzeDomainLists('dbltest.com', resolverFor);
    const dbl = bad.data.listed.find((h) => h.zone === 'dbl.spamhaus.org');
    if (!bad.data.errors.some((e) => e.zone === 'dbl.spamhaus.org')) expect(dbl?.codes).toContain('127.0.1.2');
    expect(toFindings(bad.issues).map((f) => f.id)).toContain('link.domain_listed');
    const good = await analyzeDomainLists('google.com', resolverFor);
    expect(good.data.listed).toEqual([]);
    expect(good.passed[0]?.id).toBe('blacklist.domain_clean');
  }, 60000);
});

describe('HTTP routes', () => {
  let app: FastifyInstance;
  let base: string;
  beforeAll(async () => {
    app = Fastify();
    await app.register(async (scope) => tool.register!(scope, ctx));
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });
  afterAll(() => app.close());

  it('GET /api/link/check and /api/link/stream', async () => {
    expect((await app.inject({ url: '/api/link/check' })).statusCode).toBe(400);
    const r = await app.inject({ url: `/api/link/check?url=${encodeURIComponent('javascript:alert(1)')}` });
    expect(r.json()).toMatchObject({ tool: 'link', data: { verdict: 'dangereux' }, findings: [{ id: 'links.unsafe_scheme' }] });
    expect(r.json().resultId).toBeTruthy();
    const res = await fetch(`${base}/api/link/stream?url=${encodeURIComponent('data:text/html,<b>x</b>')}`);
    const events = (await res.text()).split('\n\n').filter((b) => b.startsWith('event:')).map((b) => b.split('\n')[0].slice(7));
    expect(events).toEqual(['start', 'done']);
    expect((await fetch(`${base}/api/link/stream?url=ftp://x.test/`)).status).toBe(400);
  });
});
