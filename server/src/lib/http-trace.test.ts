// Real local HTTP and HTTPS servers (self-signed certificate generated here). The SSRF check
// refuses 127.0.0.1, so these tests pass a `network` seam, which only Vitest may use.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { analyzeBody, cleanHeaders, getHeader, traceRequest } from './http-trace.js';
import { startTestSite, type TestSite } from './http-trace.fixture.js';

describe('traceRequest', () => {
  let site: TestSite;
  beforeAll(async () => {
    site = await startTestSite();
  });
  afterAll(() => site.close());
  const H = () => `http://site.test:${site.http}`;
  const S = () => `https://site.test:${site.https}`;

  it('records the exact request head, the raw response headers and the timings', async () => {
    const ex = await traceRequest(`${H()}/301`, { network: site.network, headers: [['User-Agent', 'test/1'], ['X-Custom', 'A']] });
    expect(ex.status).toBe(301);
    expect(ex.statusText).toBe('Moved Permanently');
    expect(ex.httpVersion).toBe('1.1');
    expect(ex.ip).toBe('127.0.0.1');
    expect(ex.requestLine).toBe('GET /301 HTTP/1.1');
    expect(ex.requestHeaders.map(([k]) => k)).toEqual(['Host', 'User-Agent', 'X-Custom', 'Cache-Control', 'Pragma', 'Connection']);
    expect(getHeader(ex.requestHeaders, 'cache-control')).toBe('no-cache');
    expect(getHeader(ex.requestHeaders, 'host')).toBe(`site.test:${site.http}`);
    expect(ex.rawHeaders[0][0]).toBe('Location');
    expect(ex.timings.total).toBeGreaterThan(0);
    expect(ex.tls).toBeUndefined();
  });

  it('decodes gzip and brotli and keeps both sizes', async () => {
    for (const p of ['/gzip', '/br']) {
      const ex = await traceRequest(`${H()}${p}`, { network: site.network, headers: [['Accept-Encoding', 'gzip, br']] });
      expect(ex.body?.contentEncoding).toBe(p === '/gzip' ? 'gzip' : 'br');
      expect(ex.body!.decodedSize).toBeGreaterThan(ex.body!.size);
      expect(ex.body!.text).toContain('compressé');
      expect(ex.body!.mime).toBe('text/html');
    }
  });

  it('honours the declared charset', async () => {
    const ex = await traceRequest(`${H()}/latin1`, { network: site.network });
    expect(ex.body?.charset).toBe('windows-1252');
    expect(ex.body?.text).toBe('café');
  });

  it('keeps 2 MB and reports the real size of a larger body', async () => {
    const ex = await traceRequest(`${H()}/big`, { network: site.network });
    expect(ex.body?.truncated).toBe(true);
    expect(ex.body!.size).toBeGreaterThan(3 * 1024 * 1024);
    expect(ex.body!.text!.length).toBe(2 * 1024 * 1024);
  });

  it('measures TLS and reads a self-signed certificate without trusting it', async () => {
    const ex = await traceRequest(`${S()}/final`, { network: site.network });
    expect(ex.status).toBe(200);
    expect(ex.tls?.protocol).toMatch(/^TLSv1\.[23]$/);
    expect(ex.tls?.chainValid).toBe(false);
    expect(ex.tls?.nameValid).toBe(true);
    expect(ex.tls?.cert?.san).toContain('www.site.test');
    expect(ex.tls?.cert?.daysLeft).toBeLessThanOrEqual(2);
    expect(ex.timings.tls).toBeGreaterThan(0);
  });

  it('flags a certificate that does not cover the name', async () => {
    const ex = await traceRequest(`https://autre.test:${site.https}/`, { network: site.network });
    expect(ex.tls?.nameValid).toBe(false);
  });

  it('HEAD reads no body', async () => {
    const ex = await traceRequest(`${H()}/final`, { network: site.network, method: 'HEAD' });
    expect(ex.requestLine.startsWith('HEAD ')).toBe(true);
    expect(ex.body?.size).toBe(0);
  });

  it('refuses a private address resolved for a name', async () => {
    const ex = await traceRequest('http://private.test/', { network: site.network });
    expect(ex.error?.code).toBe('UNSAFE_TARGET');
    expect(ex.status).toBeUndefined();
  });

  it('refuses loopback and private addresses without the test seam (production path)', async () => {
    const ex = await traceRequest(`http://127.0.0.1:${site.http}/`);
    expect(ex.error?.code).toBe('UNSAFE_TARGET');
    const fake = { resolve: async () => ({ answers: [{ type: 'A', data: '192.168.1.10' }] }) };
    const ex2 = await traceRequest('http://intranet.example.com/', { dns: fake });
    expect(ex2.error?.code).toBe('UNSAFE_TARGET');
  });

  it('refuses the test seam outside Vitest', async () => {
    const saved = process.env.VITEST;
    delete process.env.VITEST;
    try {
      await expect(traceRequest(`${H()}/`, { network: site.network })).rejects.toThrow(/tests only/);
    } finally {
      process.env.VITEST = saved;
    }
  });

  it('reports a refused connection', async () => {
    const ex = await traceRequest('http://site.test:1/', { network: site.network });
    expect(ex.error?.code).toBe('ECONNREFUSED');
  });
});

describe('helpers', () => {
  it('rejects hop-by-hop or malformed extra headers', () => {
    expect(() => cleanHeaders([['Host', 'x']])).toThrow();
    expect(() => cleanHeaders([['X-A', 'a\r\nB: c']])).toThrow();
    expect(() => cleanHeaders([['Bad Name', 'x']])).toThrow();
    expect(cleanHeaders([['Accept-Language', ' en ']])).toEqual([['Accept-Language', 'en']]);
  });
  it('sniffs an untyped HTML body', () => {
    const b = analyzeBody(Buffer.from('<!DOCTYPE html><html><head><meta charset="iso-8859-1"></head></html>'), { size: 10, sizeComplete: true, truncated: false });
    expect(b.mime).toBe('text/html');
    expect(b.charsetSource).toBe('meta');
  });
});
