// CT clients against a fake HTTP layer: no request ever leaves the machine.
import { describe, expect, it } from 'vitest';
import { searchCertSpotter } from './certspotter.js';
import { searchCrtName } from './crtname.js';
import { salvageArray, searchCrtSh } from './crtsh.js';
import { cleanName, covers, issuerShortName, utcIso } from './names.js';
import { collectCt } from './sources.js';
import type { CtFetch, CtResponse } from './types.js';

type Handler = (url: URL) => Partial<CtResponse> & { json?: unknown; text?: string };

/** Fake server: routes by host name, records every URL asked. */
function fakeFetch(routes: Record<string, Handler>): CtFetch & { calls: string[]; timeouts: number[] } {
  const calls: string[] = [];
  const timeouts: number[] = [];
  const f = (async (url, opts) => {
    calls.push(url);
    timeouts.push(opts.timeoutMs);
    const u = new URL(url);
    const h = routes[u.hostname];
    if (!h) throw Object.assign(new Error('fetch failed'), { cause: { code: 'ENOTFOUND' } });
    const r = h(u);
    const body = r.body ?? Buffer.from(r.json !== undefined ? JSON.stringify(r.json) : (r.text ?? ''));
    return { status: r.status ?? 200, headers: r.headers ?? {}, body, truncated: r.truncated ?? false };
  }) as CtFetch & { calls: string[]; timeouts: number[] };
  f.calls = calls;
  f.timeouts = timeouts;
  return f;
}

const crtshRow = (id: number, names: string, serial: string, nb = '2026-09-01T00:00:00', na = '2026-11-30T00:00:00') => ({
  issuer_ca_id: 1,
  issuer_name: "C=US, O=Let's Encrypt, CN=R10",
  common_name: names.split('\n')[0],
  name_value: names,
  id,
  not_before: nb,
  not_after: na,
  serial_number: serial,
});

describe('names', () => {
  it('keeps only DNS names under the domain, lower case, wildcards apart', () => {
    expect(cleanName('WWW.Example.com.', 'example.com')).toEqual({ name: 'www.example.com', wildcard: false });
    expect(cleanName('*.dev.example.com', 'example.com')).toEqual({ name: 'dev.example.com', wildcard: true });
    expect(cleanName('admin@example.com', 'example.com')).toBeUndefined();
    expect(cleanName('example.org', 'example.com')).toBeUndefined();
    expect(cleanName('badexample.com', 'example.com')).toBeUndefined();
    expect(cleanName('192.0.2.1', 'example.com')).toBeUndefined();
    expect(cleanName('café.example.com', 'example.com')?.name).toBe('xn--caf-dma.example.com');
  });
  it('matches a wildcard on the left-most label only', () => {
    expect(covers('*.example.com', 'www.example.com')).toBe(true);
    expect(covers('*.example.com', 'a.b.example.com')).toBe(false);
    expect(covers('*.example.com', 'example.com')).toBe(false);
  });
  it('shortens issuer names and dates', () => {
    expect(issuerShortName("C=US, O=Let's Encrypt, CN=R10")).toBe("Let's Encrypt");
    expect(issuerShortName('CN=Some CA')).toBe('Some CA');
    expect(utcIso('2026-09-21T07:56:41')).toBe('2026-09-21T07:56:41Z');
  });
});

describe('crt.name', () => {
  it('asks the apex with dates and keeps names under the searched domain', async () => {
    const f = fakeFetch({
      'crt.name': () => ({ json: [{ sub: 'example.com', first_seen: '2010-01-01T00:00:00Z' }, { sub: 'a.dev.example.com' }, { sub: 'www.example.com' }] }),
    });
    const r = await searchCrtName(f, 'example.com', 'dev.example.com');
    expect(f.calls[0]).toBe('https://crt.name/v1/search?apex=example.com&format=json&dates=1');
    expect(r.status).toBe('ok');
    expect(r.names.map((n) => n.name)).toEqual(['a.dev.example.com']);
  });
  it('reports the daily quota on 429', async () => {
    const r = await searchCrtName(fakeFetch({ 'crt.name': () => ({ status: 429, text: 'rate limited' }) }), 'example.com', 'example.com');
    expect(r.status).toBe('error');
    expect(r.error).toMatch(/quota gratuit/);
  });
  it('reports the message of a 400', async () => {
    const r = await searchCrtName(fakeFetch({ 'crt.name': () => ({ status: 400, text: 'invalid apex: not an apex' }) }), 'x.example.com', 'x.example.com');
    expect(r.error).toBe('réponse HTTP 400 : invalid apex: not an apex');
  });
});

describe('crt.sh', () => {
  it('uses 25 s, merges precertificate and certificate by serial', async () => {
    const f = fakeFetch({
      'crt.sh': () => ({
        json: [crtshRow(1, 'www.example.com\nexample.com', 'AB01'), crtshRow(2, 'www.example.com', 'ab01'), crtshRow(3, '*.example.com', 'cd02'), crtshRow(4, 'mail@example.com', 'ef03')],
      }),
    });
    const r = await searchCrtSh(f, 'example.com');
    expect(f.calls[0]).toBe('https://crt.sh/?q=%25.example.com&output=json');
    expect(f.timeouts[0]).toBe(25000);
    expect(r.status).toBe('ok');
    expect(r.certs).toHaveLength(2);
    expect(r.certs[0]).toMatchObject({ serial: 'ab01', issuerShort: "Let's Encrypt", notAfter: '2026-11-30T00:00:00Z' });
    expect(r.certs[1].names).toEqual(['*.example.com']);
  });
  it('keeps what a truncated answer holds', async () => {
    const full = JSON.stringify([crtshRow(1, 'a.example.com', '01'), crtshRow(2, 'b.example.com', '02'), crtshRow(3, 'c.example.com', '03')]);
    const cut = full.slice(0, full.length - 40);
    expect(salvageArray(cut)).toHaveLength(2);
    const r = await searchCrtSh(fakeFetch({ 'crt.sh': () => ({ body: Buffer.from(cut), truncated: true }) }), 'example.com');
    expect(r.status).toBe('ok');
    expect(r.truncated).toBe(true);
    expect(r.certs).toHaveLength(2);
  });
  it('turns a 502 and a timeout into an unavailable source', async () => {
    expect((await searchCrtSh(fakeFetch({ 'crt.sh': () => ({ status: 502, text: '<html>' }) }), 'example.com')).error).toMatch(/surchargé \(HTTP 502\)/);
    const slow: CtFetch = async () => {
      throw Object.assign(new Error('pas de réponse en 25 s'), { code: 'TIMEOUT' });
    };
    expect((await searchCrtSh(slow, 'example.com')).error).toBe('pas de réponse en 25 s');
  });
});

describe('Cert Spotter', () => {
  const issuance = (id: string, names: string[]) => ({
    id,
    cert_sha256: 'ff' + id,
    dns_names: names,
    issuer: { friendly_name: "Let's Encrypt", name: "C=US, O=Let's Encrypt, CN=E6" },
    not_before: '2026-10-01T00:00:00Z',
    not_after: '2026-12-30T00:00:00Z',
    revoked: false,
  });
  it('follows `after` until an empty page', async () => {
    const f = fakeFetch({
      'api.certspotter.com': (u) => ({ json: u.searchParams.get('after') === '2' ? [] : u.searchParams.get('after') === '1' ? [issuance('2', ['b.example.com'])] : [issuance('1', ['a.example.com', '*.example.com'])] }),
    });
    const r = await searchCertSpotter(f, 'example.com');
    expect(f.calls).toHaveLength(3);
    expect(f.calls[0]).toContain('include_subdomains=true&expand=dns_names&expand=issuer');
    expect(r.status).toBe('ok');
    expect(r.truncated).toBeUndefined();
    expect(r.certs.map((c) => c.names)).toEqual([['a.example.com', '*.example.com'], ['b.example.com']]);
    expect(r.certs[0].serial).toBeUndefined();
  });
  it('handles the quota: 429 with Retry-After, and the documented rate_limited code', async () => {
    const r = await searchCertSpotter(fakeFetch({ 'api.certspotter.com': () => ({ status: 429, headers: { 'retry-after': '600' }, json: { code: 'rate_limited' } }) }), 'example.com');
    expect(r.status).toBe('error');
    expect(r.error).toBe('quota sans clé atteint, nouvel essai possible dans 10 min');
    let n = 0;
    const r2 = await searchCertSpotter(
      fakeFetch({ 'api.certspotter.com': () => (n++ === 0 ? { json: [issuance('1', ['a.example.com'])] } : { status: 400, json: { code: 'rate_limited', message: 'x' } }) }),
      'example.com',
    );
    expect(r2.status).toBe('ok');
    expect(r2.certs).toHaveLength(1);
    expect(r2.error).toMatch(/lecture arrêtée après 2 pages : quota sans clé atteint/);
  });
});

describe('relay', () => {
  const names = { 'crt.name': () => ({ json: [{ sub: 'a.example.com' }] }) };
  it('skips Cert Spotter when crt.sh answers', async () => {
    const f = fakeFetch({ ...names, 'crt.sh': () => ({ json: [crtshRow(1, 'a.example.com', '01')] }), 'api.certspotter.com': () => ({ json: [] }) });
    const seen: string[] = [];
    const r = await collectCt('example.com', f, { onSource: (s) => seen.push(`${s.source}:${s.status}`) });
    expect(r.map((s) => s.status)).toEqual(['ok', 'ok', 'skipped']);
    expect(f.calls.some((c) => c.includes('certspotter'))).toBe(false);
    expect(seen).toContain('certspotter:skipped');
  });
  it('asks Cert Spotter when crt.sh fails, and keeps going when crt.name fails too', async () => {
    const f = fakeFetch({ 'crt.sh': () => ({ status: 503 }), 'api.certspotter.com': () => ({ json: [] }) });
    const r = await collectCt('example.com', f);
    expect(r.map((s) => `${s.source}:${s.status}`)).toEqual(['crt.name:error', 'crt.sh:error', 'certspotter:ok']);
    expect(r[0].error).toBe('nom du service introuvable dans le DNS');
  });
});
