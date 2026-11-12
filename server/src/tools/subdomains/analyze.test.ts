// Subdomain analysis with fake CT sources, a fake zone and a fake web: no real network.
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../../app.js';
import { COOKIE, makeToken } from '../../auth.js';
import { openDb, setDb, type DB } from '../../db.js';
import { FakeDns, type FakeZone } from '../../lib/email-auth/fake-dns.js';
import type { CtFetch } from '../../lib/ct/types.js';
import { analyzeSubdomains, expiryThresholdMs, RESOLVE_LIMIT, type SubdomainsDeps } from './analyze.js';
import { buildInventory, internalLabel } from './inventory.js';
import { createTool } from './index.js';
import { serviceOf, serviceOfChain } from './takeover.js';
import type { TlsProbe } from '../link/tls.js';

const NOW = Date.parse('2026-11-11T12:00:00Z');
const day = 86400000;
const iso = (t: number) => new Date(t).toISOString().replace(/\.\d{3}Z$/, '');

const cert = (id: number, names: string, nbDays: number, naDays: number, serial = `s${id}`) => ({
  issuer_ca_id: 1,
  issuer_name: "C=US, O=Let's Encrypt, CN=R10",
  common_name: names.split('\n')[0],
  name_value: names,
  id,
  not_before: iso(NOW + nbDays * day),
  not_after: iso(NOW + naDays * day),
  serial_number: serial,
});

function ctFetch(opts: { crtsh?: unknown[] | 'down'; crtname?: unknown[] | 'down'; certspotter?: unknown[] } = {}): CtFetch & { calls: string[] } {
  const calls: string[] = [];
  const f = (async (url: string) => {
    calls.push(url);
    const host = new URL(url).hostname;
    const json = (v: unknown, status = 200) => ({ status, headers: {}, body: Buffer.from(JSON.stringify(v)), truncated: false });
    if (host === 'crt.name') return opts.crtname === 'down' ? json('x', 503) : json(opts.crtname ?? []);
    if (host === 'crt.sh') return opts.crtsh === 'down' ? json('x', 502) : json(opts.crtsh ?? []);
    if (host === 'api.certspotter.com') return json(new URL(url).searchParams.get('after') ? [] : (opts.certspotter ?? []));
    throw new Error('unexpected host ' + host);
  }) as CtFetch & { calls: string[] };
  f.calls = calls;
  return f;
}

const ZONE: FakeZone = {
  'example.com': { A: ['203.0.113.1'] },
  'www.example.com': { A: ['203.0.113.1'], AAAA: ['2001:db8::1'] },
  'old.example.com': { CNAME: ['gone.example.net'] },
  'assets.example.com': { CNAME: ['example-assets.s3.amazonaws.com'] },
  'example-assets.s3.amazonaws.com': { A: ['52.0.0.1'] },
  'app.example.com': { CNAME: ['example-app.azurewebsites.net'] },
  'docs.example.com': { CNAME: ['example.github.io'] },
  'example.github.io': { A: ['185.199.108.153'] },
  'shop.example.com': { CNAME: ['shops.myshopify.com'] },
  'shops.myshopify.com': { A: ['23.227.38.65'] },
  'staging.example.com': { A: ['203.0.113.9'] },
  'broken.example.com': 'SERVFAIL',
};

const PAGES: Record<string, string> = {
  'http://assets.example.com/': '<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>',
  'http://docs.example.com/': "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>",
  'http://shop.example.com/': '<html>Welcome to our shop</html>',
};

/** Served certificates: 60 days left everywhere, except the names listed. */
const SERVED: Record<string, { from: number; to: number } | 'none'> = {};
const fakeTls: TlsProbe = async (host, ip, port) => {
  const s = SERVED[host] ?? { from: -30, to: 60 };
  const base = { host, ip, port, san: [host], selfSigned: false, freeCa: true };
  if (s === 'none') return { ...base, authorized: false, expired: false, nameMatches: false, error: 'connect ECONNREFUSED' };
  return {
    ...base, authorized: s.to > 0, nameMatches: true, issuer: 'R10', issuerOrg: "Let's Encrypt",
    validFrom: new Date(NOW + s.from * day).toISOString(), validTo: new Date(NOW + s.to * day).toISOString(),
    daysLeft: Math.floor(s.to), expired: s.to < 0,
  };
};

function deps(over: Partial<SubdomainsDeps> = {}, fetch = ctFetch()): SubdomainsDeps & { probes: string[] } {
  const probes: string[] = [];
  return {
    fetch,
    dns: new FakeDns(ZONE),
    probe: async (url) => {
      probes.push(url);
      if (url in PAGES) return { status: 404, body: PAGES[url] };
      throw new Error('ECONNREFUSED');
    },
    now: () => NOW,
    randomLabel: () => 'check-random',
    tls: async (host, ip, port) => fakeTls(host, ip, port),
    probes,
    ...over,
  };
}

const ALL = [
  'example.com\nwww.example.com',
  'old.example.com',
  'assets.example.com',
  'app.example.com',
  'docs.example.com',
  'shop.example.com',
  'staging.example.com',
  'broken.example.com',
  'gone2.example.com',
];
const crtshAll = ALL.map((n, i) => cert(i + 1, n, -60, 30));

describe('takeover table', () => {
  it('recognises the services along a CNAME chain', () => {
    expect(serviceOf('bucket.s3.amazonaws.com')?.service).toBe('Amazon S3');
    expect(serviceOf('bucket.s3-website-eu-west-1.amazonaws.com')?.service).toBe('Amazon S3');
    expect(serviceOf('bucket.s3.eu-west-3.amazonaws.com')?.service).toBe('Amazon S3');
    expect(serviceOf('ec2-1-2-3-4.compute.amazonaws.com')).toBeUndefined();
    expect(serviceOf('x.azurewebsites.net')).toMatchObject({ service: 'Microsoft Azure', nxdomain: true });
    expect(serviceOf('notgithub.io')).toBeUndefined();
    expect(serviceOfChain(['cdn.example.net', 'user.github.io'])?.target).toBe('user.github.io');
  });
  it('finds internal labels', () => {
    expect(internalLabel('staging.example.com', 'example.com')).toBe('staging');
    expect(internalLabel('api-dev.example.com', 'example.com')).toBe('dev');
    expect(internalLabel('dev2.example.com', 'example.com')).toBe('dev');
    expect(internalLabel('developers.example.com', 'example.com')).toBeUndefined();
    expect(internalLabel('example.com', 'example.com')).toBeUndefined();
  });
  it('uses a third of the lifetime, capped at 14 days, half under 10 days', () => {
    expect(expiryThresholdMs('2026-01-01T00:00:00Z', '2026-04-01T00:00:00Z')).toBe(14 * day);
    expect(expiryThresholdMs('2026-01-01T00:00:00Z', '2026-01-07T00:00:00Z')).toBe(3 * day);
  });
});

describe('inventory', () => {
  it('merges sources, keeps wildcards apart, applies wildcard coverage', () => {
    const inv = buildInventory('example.com', [
      { source: 'crt.name', status: 'ok', certs: [], names: [{ name: 'www.example.com', firstSeen: '2010-01-01T00:00:00Z' }, { name: 'api.example.com' }], ms: 1 },
      {
        source: 'crt.sh', status: 'ok', names: [], ms: 1,
        certs: [
          { source: 'crt.sh', id: '1', serial: 'a', issuer: 'x', issuerShort: 'X', notBefore: '2026-01-01T00:00:00Z', notAfter: '2026-04-01T00:00:00Z', names: ['www.example.com'] },
          { source: 'crt.sh', id: '2', serial: 'b', issuer: 'x', issuerShort: 'X', notBefore: '2026-06-01T00:00:00Z', notAfter: '2026-09-01T00:00:00Z', names: ['*.example.com', 'example.com'] },
        ],
      },
    ]);
    expect(inv.rows.map((r) => r.name)).toEqual(['api.example.com', 'example.com', 'www.example.com']);
    const www = inv.rows.find((r) => r.name === 'www.example.com')!;
    expect(www).toMatchObject({ certCount: 1, firstSeen: '2010-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z', validUntil: '2026-09-01T00:00:00Z', sources: ['crt.name', 'crt.sh'] });
    expect(www.certs[0].viaWildcard).toBe('*.example.com');
    expect(inv.wildcards).toEqual([expect.objectContaining({ name: '*.example.com', certCount: 1 })]);
    expect(inv.certSource).toBe('crt.sh');
  });
});

describe('analyzeSubdomains', () => {
  it('classifies every name and raises the findings', async () => {
    const d = deps({}, ctFetch({ crtsh: crtshAll }));
    const seen: string[] = [];
    const a = await analyzeSubdomains('example.com', d, { onSubdomain: (r) => seen.push(r.name) });
    const by = Object.fromEntries(a.data.subdomains.map((r) => [r.name, r]));
    expect(by['www.example.com'].dns).toMatchObject({ status: 'active', a: ['203.0.113.1'], aaaa: ['2001:db8::1'] });
    expect(by['old.example.com'].dns).toMatchObject({ status: 'dangling', cname: ['gone.example.net'] });
    expect(by['gone2.example.com'].dns?.status).toBe('dead');
    expect(by['broken.example.com'].dns?.status).toBe('error');
    expect(by['assets.example.com'].takeover).toMatchObject({ service: 'Amazon S3', level: 'vulnerable' });
    expect(by['app.example.com'].takeover).toMatchObject({ service: 'Microsoft Azure', evidence: expect.stringContaining('NXDOMAIN') });
    expect(by['docs.example.com'].takeover).toMatchObject({ service: 'GitHub Pages', level: 'edge' });
    expect(by['shop.example.com'].takeover).toBeUndefined();
    expect(seen.sort()).toEqual(a.data.subdomains.map((r) => r.name).sort());
    // the probe only goes to names whose CNAME points to a service with a page fingerprint
    expect(d.probes.sort()).toEqual(['http://assets.example.com/', 'http://docs.example.com/', 'http://shop.example.com/']);

    const ids = a.issues.map((i) => i.id);
    expect(ids.filter((i) => i === 'subdomains.takeover_risk')).toHaveLength(2);
    expect(ids).toContain('subdomains.takeover_possible');
    expect(ids).toContain('subdomains.cname_dangling');
    expect(ids).toContain('subdomains.internal_names');
    expect(ids).toContain('subdomains.dead_names');
    expect(ids).not.toContain('subdomains.cert_expiring');
    const s3 = a.issues.find((i) => i.vars?.subdomain === 'assets.example.com')!;
    expect(s3.evidence).toContain('assets.example.com. CNAME example-assets.s3.amazonaws.com.');
    expect(s3.evidence).toContain('NoSuchBucket');
    expect(a.data.counts).toMatchObject({ risk: 3, dangling: 2, error: 1 });
    expect(a.passed.map((p) => p.id)).toEqual(['subdomains.cert_ok', 'subdomains.sources']);
  });

  it('judges expiry on the served certificate, not on CT data that may lag', async () => {
    // CT says www expired long ago, but the server presents a fresh one: no alert (false positive of 2026-11-11)
    const certs = [cert(1, 'example.com', -80, 10), cert(2, 'www.example.com', -200, -110), cert(3, 'staging.example.com', -80, 10)];
    SERVED['example.com'] = { from: -80, to: 10 };
    SERVED['staging.example.com'] = { from: -100, to: -10 };
    SERVED['docs.example.com'] = 'none';
    try {
      const a = await analyzeSubdomains('example.com', deps({}, ctFetch({ crtsh: certs })));
      const f = a.issues.find((i) => i.id === 'subdomains.cert_expiring')!;
      expect(f.vars).toMatchObject({ value: 1, subdomain: 'example.com' });
      expect(f.evidence).toMatch(/example\.com : expire le 21\/11\/2026 \(dans 10 j\), Let's Encrypt/);
      const e = a.issues.find((i) => i.id === 'subdomains.cert_expired_active')!;
      expect(e.vars).toMatchObject({ value: 1, subdomain: 'staging.example.com' });
      const www = a.data.subdomains.find((r) => r.name === 'www.example.com')!;
      expect(www.served).toMatchObject({ expired: false, issuer: "Let's Encrypt", newerThanCt: true });
      expect(a.data.servedNewerThanCt).toBeGreaterThan(0);
    } finally {
      for (const k of Object.keys(SERVED)) delete SERVED[k];
    }
  });

  it('does not flag a short-lived certificate renewed on time', async () => {
    SERVED['example.com'] = { from: -2, to: 4 };
    try {
      const a = await analyzeSubdomains('example.com', deps({}, ctFetch({ crtsh: [cert(1, 'example.com', -2, 4)] })));
      expect(a.issues.map((i) => i.id)).not.toContain('subdomains.cert_expiring');
    } finally {
      delete SERVED['example.com'];
    }
  });

  it('notes wildcard DNS and marks the names that only get the wildcard answer', async () => {
    const zone: FakeZone = { ...ZONE, 'check-random.example.com': { A: ['198.51.100.7'] }, 'gone2.example.com': { A: ['198.51.100.7'] } };
    const a = await analyzeSubdomains('example.com', deps({ dns: new FakeDns(zone) }, ctFetch({ crtsh: crtshAll })));
    expect(a.issues.map((i) => i.id)).toContain('subdomains.wildcard_dns');
    expect(a.data.subdomains.find((r) => r.name === 'gone2.example.com')?.dns?.viaWildcardDns).toBe(true);
  });

  it('resolves at most 500 names and says how many are left', async () => {
    const names = Array.from({ length: RESOLVE_LIMIT + 7 }, (_, i) => ({ sub: `h${i}.example.com` }));
    const a = await analyzeSubdomains('example.com', deps({}, ctFetch({ crtname: names })));
    expect(a.data).toMatchObject({ total: RESOLVE_LIMIT + 7, resolved: RESOLVE_LIMIT, notResolved: 7 });
    expect(a.data.subdomains.filter((r) => r.dns?.status === 'skipped')).toHaveLength(7);
    expect(a.issues.find((i) => i.id === 'subdomains.resolution_capped')?.vars?.value).toBe(7);
  });

  it('keeps working when sources fail, and says so', async () => {
    const f = ctFetch({ crtsh: 'down', crtname: [{ sub: 'www.example.com' }], certspotter: [] });
    const a = await analyzeSubdomains('example.com', deps({}, f));
    expect(a.unavailable).toEqual([{ source: 'crt.sh', reason: 'service surchargé (HTTP 502), fréquent sur crt.sh' }]);
    expect(f.calls.some((c) => c.includes('certspotter'))).toBe(true);
    expect(a.data.sources.map((s) => s.status)).toEqual(['ok', 'error', 'ok']);
    expect(a.data.subdomains).toHaveLength(1);
  });
});

describe('routes', () => {
  let db: DB;
  let base: string;
  let close: () => Promise<void>;
  let cookie: string;
  beforeAll(async () => {
    db = openDb(':memory:');
    setDb(db);
    const { app } = await buildApp({ db, tools: [createTool(() => deps({}, ctFetch({ crtsh: crtshAll, crtname: [{ sub: 'www.example.com', first_seen: '2010-01-01T00:00:00Z' }] })))] });
    await app.listen({ port: 0, host: '127.0.0.1' });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
    close = () => app.close();
    cookie = `${COOKIE}=${makeToken()}`;
  });
  afterAll(async () => close?.());

  it('GET /api/subdomains/:domain returns a stored, scored CheckResult, never cached', async () => {
    const r = await fetch(`${base}/api/subdomains/EXAMPLE.com.`, { headers: { cookie: `${cookie}; lang=fr` } });
    expect(r.status).toBe(200);
    expect(r.headers.get('cache-control')).toMatch(/no-store/);
    const body = (await r.json()) as { input: string; score: number; resultId: string; findings: { id: string; title: string }[]; data: { total: number } };
    expect(body.input).toBe('example.com');
    expect(body.data.total).toBe(10);
    expect(body.resultId).toBeTruthy();
    expect(body.score).toBeLessThan(5);
    const risk = body.findings.find((f) => f.id === 'subdomains.takeover_risk')!;
    expect(risk.title).toMatch(/peut être repris par un inconnu chez (Amazon S3|Microsoft Azure)/);
    expect(db.prepare("SELECT count(*) n FROM results WHERE tool = 'subdomains'").get()).toEqual({ n: 1 });
  });

  it('streams source, inventory, subdomain and done events', async () => {
    const r = await fetch(`${base}/api/subdomains/example.com/stream`, { headers: { cookie } });
    expect(r.headers.get('content-type')).toMatch(/text\/event-stream/);
    const events = (await r.text())
      .split('\n\n')
      .filter((b) => b.startsWith('event:'))
      .map((b) => b.split('\n')[0].slice(7));
    expect(events[0]).toBe('start');
    expect(events.filter((e) => e === 'source')).toHaveLength(3);
    expect(events.indexOf('inventory')).toBeGreaterThan(events.lastIndexOf('source'));
    expect(events.filter((e) => e === 'subdomain')).toHaveLength(10);
    expect(events.at(-1)).toBe('done');
  });

  it('refuses a malformed name with 400', async () => {
    const r = await fetch(`${base}/api/subdomains/not_a..domain/stream`, { headers: { cookie } });
    expect(r.status).toBe(400);
  });
});
