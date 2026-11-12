import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { explain } from '../../knowledge/engine.js';
import { startTestSite, type TestSite } from '../../lib/http-trace.fixture.js';
import { analyzeTrace, canonicalRules, detectWordPress, isLanguageRedirect, permanentLooking } from './analyze.js';
import { canonicalFromLinkHeader, canonicalLink, jsRedirect, metaRefresh, parseRefresh } from './html.js';
import { normalizeUrlInput, traceChain, type TraceOptions } from './trace.js';
import { variantUrls } from './variants.js';
import { parseHeaderParam } from './index.js';

let site: TestSite;
beforeAll(async () => {
  site = await startTestSite();
});
afterAll(() => site.close());
const H = () => `http://site.test:${site.http}`;
const S = () => `https://site.test:${site.https}`;
const run = (u: string, o: TraceOptions = {}) => traceChain(u, { network: site.network, light: true, ...o });
const ids = (d: Awaited<ReturnType<typeof run>>) => analyzeTrace(d).issues.map((i) => i.id);

describe('traceChain on a local site', () => {
  it.each([301, 302, 307, 308])('follows a %i', async (code) => {
    const d = await run(`${H()}/${code}`);
    expect(d.hops.map((h) => h.exchange.status)).toEqual([code, 200]);
    expect(d.final).toBe(`${H()}/final`);
    expect(d.stoppedBy).toBe('final');
    expect(d.redirects).toBe(1);
  });

  it('resolves a relative Location', async () => {
    const d = await run(`${H()}/relative`);
    expect(d.hops[0].redirect?.raw).toBe('../final');
    expect(d.final).toBe(`${H()}/final`);
  });

  it('follows meta refresh, the Refresh header and a plain JavaScript redirect', async () => {
    expect((await run(`${H()}/meta`)).hops[0].redirect?.kind).toBe('meta');
    expect((await run(`${H()}/refresh`)).hops[0].redirect).toMatchObject({ kind: 'refresh', delay: 2 });
    const js = await run(`${H()}/js`);
    expect(js.hops[0].redirect?.kind).toBe('js');
    expect(js.final).toBe(`${H()}/final`);
    expect(ids(js)).toContain('redirects.js_redirect');
  });

  it('does not follow a script on a page with real content', async () => {
    const d = await run(`${H()}/js-content`);
    expect(d.hops).toHaveLength(1);
    expect(d.hops[0].jsSeen?.url).toBe(`${H()}/ailleurs`);
    expect(ids(d)).toContain('redirects.js_seen');
  });

  it('detects a loop', async () => {
    const d = await run(`${H()}/loop-a`);
    expect(d.stoppedBy).toBe('loop');
    expect(d.hops).toHaveLength(2);
    expect(ids(d)).toContain('redirects.loop');
    expect((await run(`${H()}/self`)).stoppedBy).toBe('loop');
  });

  it('keeps cookies from hop to hop, or not', async () => {
    const withC = await run(`${H()}/cookie`);
    expect(withC.hops.map((h) => h.exchange.status)).toEqual([302, 302, 200]);
    expect(withC.hops[1].cookiesSent).toBe(1);
    const without = await run(`${H()}/cookie`, { cookies: false });
    expect(without.stoppedBy).toBe('loop');
  });

  it('flags a long chain with a temporary hop', async () => {
    const d = await run(`${H()}/chain`);
    expect(d.redirects).toBe(3);
    expect(ids(d)).toContain('redirects.chain_long');
  });

  it('flags http → https done right, and https → http', async () => {
    const up = await run(`${H()}/to-https`);
    expect(up.final).toBe(`${S()}/final`);
    expect(up.hops[1].exchange.tls).toBeDefined();
    const a = analyzeTrace(up);
    expect(a.passed.map((p) => p.id)).toContain('redirects.https_upgrade');
    expect(a.passed.map((p) => p.id)).toContain('redirects.hsts_ok');
    expect(a.issues.map((i) => i.id)).toContain('redirects.cert_invalid'); // self-signed
    const down = await run(`${S()}/to-http`);
    expect(ids(down)).toContain('redirects.https_to_http');
    expect(ids(down)).toContain('redirects.http_not_redirected');
  });

  it('flags a 302 used to add the www', async () => {
    const d = await run(`${H()}/www`);
    expect(ids(d)).toContain('redirects.temporary_for_permanent');
  });

  it('stops before a private address reached by a redirect', async () => {
    const d = await run(`${H()}/to-private`);
    expect(d.stoppedBy).toBe('unsafe');
    expect(d.hops[1].exchange.error?.code).toBe('UNSAFE_TARGET');
    expect(ids(d)).toContain('redirects.private_target');
  });

  it('flags a redirect to a 404 and a 3xx without Location', async () => {
    expect(ids(await run(`${H()}/to-404`))).toContain('redirects.redirect_to_error');
    expect(ids(await run(`${H()}/missing`))).toContain('redirects.final_error');
    expect(ids(await run(`${H()}/no-location`))).toContain('redirects.redirect_without_location');
  });

  it('stops at the maximum', async () => {
    const d = await run(`${H()}/chain`, { max: 2 });
    expect(d.stoppedBy).toBe('max');
    expect(ids(d)).toContain('redirects.too_many');
  });

  it('reads the canonical of the final page', async () => {
    const d = await run(`${H()}/301`);
    expect(d.finalPage?.canonical).toBe(`${H()}/final`);
    expect(analyzeTrace(d).passed.map((p) => p.id)).toContain('redirects.canonical_ok');
    expect(d.finalPage?.robots).toEqual(['X-Robots-Tag: index']);
  });

  it('sends the chosen user agent and extra headers', async () => {
    const d = await run(`${H()}/`, { ua: 'googlebot', headers: [['X-Test', '1']] });
    const sent = d.hops[0].exchange.requestHeaders;
    expect(sent.find(([k]) => k === 'User-Agent')?.[1]).toContain('Googlebot/2.1');
    expect(sent.find(([k]) => k === 'X-Test')?.[1]).toBe('1');
  });

  it('keeps typed credentials on the starting origin, like a browser', async () => {
    const d = await run(`${H()}/www`, { headers: [['Authorization', 'Bearer secret'], ['Cookie', 'session=1'], ['X-Test', '1']] });
    const [first, second] = d.hops.map((h) => h.exchange.requestHeaders);
    expect(first.find(([k]) => k === 'Authorization')?.[1]).toBe('Bearer secret');
    expect(first.find(([k]) => k === 'Cookie')?.[1]).toBe('session=1');
    expect(second.find(([k]) => k === 'Authorization')).toBeUndefined();
    expect(second.find(([k]) => k === 'Cookie')).toBeUndefined();
    expect(second.find(([k]) => k === 'X-Test')?.[1]).toBe('1');
  });

  it('every finding has its entry in the base', async () => {
    const all = await Promise.all(['/chain', '/loop-a', '/to-private', '/to-404', '/meta', '/js', '/refresh', '/www', '/big'].map((p) => run(`${H()}${p}`)));
    for (const d of all) for (const i of analyzeTrace(d).issues) expect(explain(i).fallback, i.id).toBeFalsy();
  });
});

describe('parsing', () => {
  it('normalises tolerant input', () => {
    expect(normalizeUrlInput('Exemple.FR')).toEqual({ url: 'https://exemple.fr/', bare: true });
    expect(normalizeUrlInput(' <http://a.fr/x#y> ').url).toBe('http://a.fr/x');
    expect(normalizeUrlInput('a.fr:8080/x').url).toBe('https://a.fr:8080/x');
    expect(() => normalizeUrlInput('ftp://a.fr')).toThrow();
    expect(() => normalizeUrlInput('localhost')).toThrow();
  });
  it('parses refresh values', () => {
    expect(parseRefresh('0; URL=\'/a\'')).toEqual({ delay: 0, url: '/a' });
    expect(parseRefresh('5,https://b.fr')).toEqual({ delay: 5, url: 'https://b.fr' });
    expect(metaRefresh('<noscript><meta http-equiv="refresh" content="0;url=/x"></noscript>')).toBeUndefined();
    expect(metaRefresh('<META HTTP-EQUIV=Refresh CONTENT="3;url=/y">')?.url).toBe('/y');
  });
  it('reads JavaScript redirects without running them', () => {
    expect(jsRedirect('<script>location.replace("https://x.fr/")</script>')?.url).toBe('https://x.fr/');
    expect(jsRedirect('<script>window.location = `/a/${id}`</script>')).toBeUndefined();
    expect(jsRedirect('<script src="a.js"></script>')).toBeUndefined();
  });
  it('reads canonicals from the head and the Link header', () => {
    expect(canonicalLink('<head><link href="/c" rel="canonical"></head><body><link rel=canonical href=/no></body>')).toBe('/c');
    expect(canonicalFromLinkHeader(['<https://a.fr/p>; rel="alternate", <https://a.fr/c>; rel="canonical"'])).toBe('https://a.fr/c');
  });
  it('classifies permanent-looking changes', () => {
    expect(permanentLooking('http://a.fr/', 'https://a.fr/')).toBe('passage de http à https');
    expect(permanentLooking('https://a.fr/x', 'https://www.a.fr/x')).toBe('ajout du www');
    expect(permanentLooking('https://old.fr/p', 'https://new.fr/p')).toBe('changement de domaine');
    expect(permanentLooking('https://bit.ly/abc', 'https://new.fr/page')).toBeUndefined();
    expect(permanentLooking('https://a.fr/', 'https://a.fr/fr/')).toBeUndefined();
  });
  it('writes one rule for all variants', () => {
    const r = canonicalRules('https://www.a.fr/');
    expect(r).toContain('RewriteCond %{HTTP_HOST} !^www\\.a\\.fr$ [NC]');
    expect(r).toContain('return 301 https://www.a.fr$request_uri;');
    expect(r).not.toMatch(/[—–]/);
  });
  it('builds the variants of a site', () => {
    expect(variantUrls('a.fr').list.map((v) => v.url)).toEqual(['http://a.fr/', 'https://a.fr/', 'http://www.a.fr/', 'https://www.a.fr/']);
    expect(variantUrls('blog.a.fr/x').list.map((v) => v.url)).toEqual(['http://blog.a.fr/x', 'https://blog.a.fr/x']);
  });
  it('parses the headers parameter', () => {
    expect(parseHeaderParam('{"Accept-Language":"en"}')).toEqual([['Accept-Language', 'en']]);
    expect(parseHeaderParam('[["X-A","1"]]')).toEqual([['X-A', '1']]);
    expect(() => parseHeaderParam('{"Host":"x"}')).toThrow();
    expect(() => parseHeaderParam('nope')).toThrow();
  });
});

describe('real sites (network)', () => {
  it('http://github.com goes to https in one 301', async () => {
    const { ResolveSession } = await import('../../dns/iterative.js');
    const d = await traceChain('http://github.com', { dns: new ResolveSession(), light: true });
    expect(d.hops[0].exchange.status).toBe(301);
    expect(d.hops[1].url.startsWith('https://github.com/')).toBe(true);
    expect(d.stoppedBy).toBe('final');
  }, 40000);
  it('http://google.fr reaches a google page over https', async () => {
    const { ResolveSession } = await import('../../dns/iterative.js');
    const d = await traceChain('http://google.fr', { dns: new ResolveSession(), light: true });
    expect(d.redirects).toBeGreaterThanOrEqual(1);
    expect(d.final).toMatch(/^https:\/\/www\.google\./);
  }, 40000);
  it('a bit.ly link is followed to its destination', async () => {
    const { ResolveSession } = await import('../../dns/iterative.js');
    // bit.ly/3Abcdef style links are user content; the bare bit.ly root redirects to bitly.com
    const d = await traceChain('https://bit.ly/', { dns: new ResolveSession(), light: true });
    expect(d.redirects).toBeGreaterThanOrEqual(1);
    expect(d.final).toMatch(/bitly\.com/);
  }, 40000);
});

describe('language negotiation and WordPress', () => {
  const hop = (url: string, to: string, status = 302, headers: [string, string][] = []) =>
    ({ index: 1, url, method: 'GET', cookiesSent: 0, startedAt: 0, redirect: { kind: 'http', to, raw: to }, exchange: { url, method: 'GET', host: '', requestLine: '', requestHeaders: [], port: 443, status, rawHeaders: headers, timings: { dns: 0, connect: 0, tls: 0, wait: 0, download: 0, total: 0 } } }) as never;
  it('exempts a 302 that only picks a language', () => {
    expect(isLanguageRedirect(hop('https://github.com/', 'https://github.com/?locale=fr-fr'))).toBe(true);
    expect(isLanguageRedirect(hop('https://a.fr/', 'https://a.fr/fr/'))).toBe(true);
    expect(isLanguageRedirect(hop('https://a.fr/x', 'https://a.fr/en-gb/x'))).toBe(true);
    expect(isLanguageRedirect(hop('https://a.fr/', 'https://a.fr/accueil', 302, [['Vary', 'Accept-Language']]))).toBe(true);
    expect(isLanguageRedirect(hop('http://a.fr/', 'https://a.fr/?lang=fr'))).toBe(false);
    expect(isLanguageRedirect(hop('https://a.fr/', 'https://a.fr/?utm=1'))).toBe(false);
    expect(isLanguageRedirect(hop('https://a.fr/', 'https://a.fr/fr/', 301))).toBe(false);
  });
  it('shows the WordPress step only on a WordPress site', async () => {
    const wp = analyzeTrace(await run(`${H()}/wp`)).issues.map((i) => explain(i)).find((f) => f.id === 'redirects.canonical_missing');
    expect(wp?.providerFix?.provider).toBe('wordpress');
    const plain = analyzeTrace(await run(`${H()}/`)).issues.map((i) => explain(i)).find((f) => f.id === 'redirects.canonical_missing');
    expect(plain).toBeDefined();
    expect(plain?.providerFix).toBeUndefined();
    expect(plain!.fix.join(' ')).not.toMatch(/WordPress/);
  });
  it('detects WordPress from headers or HTML only', () => {
    const wp = hop('https://a.fr/', 'https://a.fr/x', 301, [['X-Redirect-By', 'WordPress']]);
    expect(detectWordPress([wp])).toBe(true);
    expect(detectWordPress([hop('https://a.fr/', 'https://a.fr/x', 301, [['Server', 'nginx']])])).toBe(false);
  });
});
