// End-to-end: HTTP server, login cookie, SSE stream on example.com against real resolvers.
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../../app.js';
import { COOKIE, makeToken } from '../../auth.js';
import { openDb, setDb, type DB } from '../../db.js';
import { tool } from './index.js';
import { loadSeed } from './store.js';
import type { SeedResolver } from './types.js';

const s = (ip: string, provider: string, anycast: boolean, cc: string, lat: number | null = null, lon: number | null = null): SeedResolver => ({
  ip,
  name: provider,
  provider,
  asn: null,
  country_code: cc,
  city: null,
  lat,
  lon,
  geo_precision: lat == null ? null : 'city',
  anycast,
  filtering: 'none',
  source: 'test',
  group: anycast ? 'global' : 'local',
});

let db: DB;
let base: string;
let close: () => Promise<void>;
let cookie: string;

beforeAll(async () => {
  db = openDb(':memory:');
  setDb(db);
  loadSeed(db, [s('8.8.8.8', 'Google', true, 'US'), s('1.1.1.1', 'Cloudflare', true, 'US'), s('9.9.9.10', 'Quad9', false, 'CH', 46.95, 7.45), s('192.0.2.1', 'Nobody', false, 'FR')]);
  // qualification itself is tested elsewhere: mark the set as qualified directly
  db.prepare('UPDATE resolvers SET qualified = 1, qualified_at = ?').run(Date.now());
  const { app } = await buildApp({ db, tools: [tool] });
  await app.listen({ port: 0, host: '127.0.0.1' });
  base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  close = () => app.close();
  cookie = `${COOKIE}=${makeToken()}`;
});
afterAll(async () => close?.());

async function stream(qs: string) {
  const r = await fetch(`${base}/api/propagation/stream?${qs}`, { headers: { cookie } });
  expect(r.headers.get('content-type')).toMatch(/text\/event-stream/);
  expect(r.headers.get('cache-control')).toMatch(/no-store/);
  const text = await r.text();
  return text
    .split('\n\n')
    .filter((b) => b.startsWith('event:'))
    .map((b) => {
      const [ev, data] = b.split('\n');
      return { event: ev.slice(7), data: JSON.parse(data.slice(6)) };
    });
}

describe('GET /api/propagation/stream', () => {
  it('streams authority, each resolver, then a summary saved in the history', async () => {
    const events = await stream('name=example.com&type=A&scope=all');
    const names = events.map((e) => e.event);
    expect(names[0]).toBe('start');
    expect(names[1]).toBe('authority');
    expect(names.at(-1)).toBe('done');
    expect(names.filter((n) => n === 'resolver')).toHaveLength(4);

    const auth = events[1].data;
    expect(auth.zone).toBe('example.com');
    expect(auth.servers.length).toBeGreaterThan(1);
    expect(auth.servers.every((x: { serial: number | null }) => typeof x.serial === 'number')).toBe(true);
    expect(auth.reference).toMatchObject({ source: 'authority', exists: true, kind: 'records' });
    expect(auth.reference.values.length).toBeGreaterThan(0);

    const res = events.filter((e) => e.event === 'resolver').map((e) => e.data);
    const dead = res.find((r) => r.ip === '192.0.2.1');
    expect(dead.status).toBe('timeout');
    for (const r of res.filter((r) => r.ip !== '192.0.2.1')) {
      // example.com is served by Cloudflare-hosted authoritative servers: identical everywhere
      expect(['fresh', 'stale']).toContain(r.status);
      expect(r.ttl).toBeGreaterThanOrEqual(0);
      expect(r.latencyMs).toBeGreaterThan(0);
    }
    expect(res.find((r) => r.ip === '9.9.9.10')).toMatchObject({ lat: 46.95, lon: 7.45, group: 'local', continent: 'EU' });
    expect(res.find((r) => r.ip === '8.8.8.8')).toMatchObject({ lat: null, group: 'global', anycast: true });

    const done = events.at(-1)!.data;
    expect(done).toMatchObject({ total: 4, timeout: 1 });
    expect(done.pendingIps).toContain('192.0.2.1');
    const row = db.prepare('SELECT tool, input, summary FROM results WHERE id = ?').get(done.resultId) as { tool: string; input: string; summary: string };
    expect(row).toMatchObject({ tool: 'propagation', input: 'example.com a' });
    expect(JSON.parse(row.summary)).toMatchObject({ name: 'example.com', type: 'A', total: 4 });
  }, 30000);

  it('compares with an expected value and re-asks only the pending resolvers', async () => {
    const events = await stream('name=example.com&type=A&expected=192.0.2.200&onlyPending=1&ips=8.8.8.8,192.0.2.1,203.0.113.5');
    const auth = events.find((e) => e.event === 'authority')!.data;
    expect(auth.reference).toMatchObject({ source: 'expected', values: ['192.0.2.200'] });
    expect(auth.expectedMatchesAuthority).toBe(false);
    const res = events.filter((e) => e.event === 'resolver').map((e) => e.data);
    // 203.0.113.5 is not a qualified resolver: never queried
    expect(res.map((r) => r.ip).sort()).toEqual(['192.0.2.1', '8.8.8.8']);
    expect(res.find((r) => r.ip === '8.8.8.8').status).toBe('stale');
    expect(res.find((r) => r.ip === '8.8.8.8').refreshAt).toMatch(/^20\d\d-/);
  }, 30000);

  it('TXT, MX and a missing name', async () => {
    const txt = await stream('name=_dmarc.ietf.org&type=TXT&onlyPending=1&ips=8.8.8.8');
    expect(txt.find((e) => e.event === 'resolver')!.data.status).toBe('fresh');
    const nx = await stream(`name=nx-${Date.now()}.example.com&type=A&onlyPending=1&ips=1.1.1.1`);
    const a = nx.find((e) => e.event === 'authority')!.data;
    expect(a.reference.exists).toBe(false);
    expect(nx.find((e) => e.event === 'resolver')!.data.status).toBe('fresh');
  }, 30000);

  it('rejects bad input and requires the password', async () => {
    expect((await fetch(`${base}/api/propagation/stream?name=example.com&type=ANY`, { headers: { cookie } })).status).toBe(400);
    expect((await fetch(`${base}/api/propagation/stream?name=exa%20mple&type=A`, { headers: { cookie } })).status).toBe(400);
    expect((await fetch(`${base}/api/propagation/stream?name=example.com&type=A&onlyPending=1`, { headers: { cookie } })).status).toBe(400);
    expect((await fetch(`${base}/api/propagation/resolvers`)).status).toBe(401);
  });

  it('lists the qualified resolvers by group and country', async () => {
    const r = await (await fetch(`${base}/api/propagation/resolvers`, { headers: { cookie } })).json();
    expect(r.global.resolvers.map((x: { ip: string }) => x.ip).sort()).toEqual(['1.1.1.1', '8.8.8.8']);
    expect(r.global.note).toMatch(/anycast/);
    expect(r.countries.map((c: { country_code: string }) => c.country_code)).toEqual(['CH', 'FR']);
    expect(r.candidates).toBe(4);
  });

  it('POST /api/propagation/qualify runs one qualification at a time', async () => {
    const post = () => fetch(`${base}/api/propagation/qualify`, { method: 'POST', headers: { cookie } });
    expect((await post()).status).toBe(202);
    const second = await post();
    expect(second.status).toBe(409);
    expect(await second.json()).toMatchObject({ error: 'already_running' });
    let r;
    for (let i = 0; i < 60; i++) {
      r = await (await fetch(`${base}/api/propagation/resolvers`, { headers: { cookie } })).json();
      if (!r.running) break;
      await new Promise((ok) => setTimeout(ok, 500));
    }
    expect(r.running).toBeNull();
    expect(r.qualification).toMatchObject({ status: 'ok', tested: 4 });
    expect(r.global.resolvers.map((x: { ip: string }) => x.ip).sort()).toEqual(['1.1.1.1', '8.8.8.8']);
    expect(r.countries.flatMap((c: { resolvers: { ip: string }[] }) => c.resolvers.map((x) => x.ip))).not.toContain('192.0.2.1');
  }, 60000);
});
