// Live network test: real queries to Google, Cloudflare, Quad9 and a documentation address
// that never answers (192.0.2.1, RFC 5737).
import { describe, expect, it } from 'vitest';
import { openDb } from '../../db.js';
import { ResolveSession } from '../../dns/iterative.js';
import { qualify } from './qualify.js';
import { candidates, loadSeed, qualifiedResolvers, saveOutcomes } from './store.js';
import type { SeedResolver } from './types.js';

const seed = (ip: string, provider: string, anycast: boolean, extra: Partial<SeedResolver> = {}): SeedResolver => ({
  ip,
  name: provider,
  provider,
  asn: null,
  country_code: 'US',
  city: null,
  lat: null,
  lon: null,
  geo_precision: null,
  anycast,
  filtering: 'none',
  source: 'test',
  group: anycast ? 'global' : 'local',
  ...extra,
});

const SMALL = [
  seed('8.8.8.8', 'Google', true),
  seed('8.8.4.4', 'Google', true),
  seed('1.1.1.1', 'Cloudflare', true),
  seed('9.9.9.9', 'Quad9', true, { filtering: 'malware', country_code: 'CH' }),
  // unicast, unreachable: must fail and, after 2 runs, be quarantined
  seed('192.0.2.1', 'Nobody', false, { country_code: 'FR', lat: 48.85, lon: 2.35, geo_precision: 'city' }),
];

describe('qualification on a small real set', () => {
  it('keeps the honest resolvers, drops the dead one, quarantines it after 2 failures', { timeout: 60000 }, async () => {
    const db = openDb(':memory:');
    loadSeed(db, SMALL);
    const opts = { dns: () => new ResolveSession(), geolocate: false as const, serverLocation: null };
    const r1 = await qualify(candidates(db), opts);
    const by = new Map(r1.outcomes.map((o) => [o.ip, o]));

    for (const ip of ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']) {
      expect(by.get(ip)!.passed, `${ip}: ${by.get(ip)!.reasons}`).toBe(true);
      expect(by.get(ip)!.latencyMs).toBeGreaterThan(0);
      expect(by.get(ip)!.dnssec).toBe(true); // all four validate (SERVFAIL on dnssec-failed.org)
    }
    expect(by.get('192.0.2.1')).toMatchObject({ passed: false, qualified: false, reasons: ['no_answer'] });
    // one address per anycast provider
    expect([by.get('8.8.8.8')!.qualified, by.get('8.8.4.4')!.qualified].filter(Boolean)).toHaveLength(1);
    expect(by.get('1.1.1.1')!.qualified).toBe(true);
    expect(by.get('9.9.9.9')!.qualified).toBe(true);
    expect(r1.failures).toEqual({ no_answer: 1 });
    expect(Object.keys(r1.truth)).toContain('a.root-servers.net|A#3');

    saveOutcomes(db, r1.outcomes);
    expect(qualifiedResolvers(db).map((r) => r.ip).sort()).toHaveLength(3);
    const row = db.prepare('SELECT qualified, qualified_at, latency_ms, reasons FROM resolvers WHERE ip = ?').get('192.0.2.1') as Record<string, unknown>;
    expect(row).toMatchObject({ qualified: 0, reasons: '["no_answer"]' });
    expect(row.qualified_at).toBeTypeOf('number');

    // second consecutive failure: quarantine, then the next run skips it
    const dead = candidates(db, ['192.0.2.1']);
    expect(dead[0].fails).toBe(1);
    const r2 = await qualify(dead, { ...opts, rounds: 1 });
    saveOutcomes(db, r2.outcomes);
    const q = candidates(db, ['192.0.2.1'])[0];
    expect(q.fails).toBe(2);
    expect(q.quarantined_until).toBeGreaterThan(Date.now());
    const r3 = await qualify(candidates(db, ['192.0.2.1']), opts);
    expect(r3).toMatchObject({ tested: 0, skippedQuarantine: 1 });
    expect(r3.outcomes[0].reasons).toEqual(['quarantined']);
  });

  it('caps unicast resolvers per country with distinct ASNs and rejects impossible locations', async () => {
    // Real resolvers with made-up locations: selection and the light-speed check run on real RTTs.
    const db = openDb(':memory:');
    loadSeed(db, [
      seed('8.8.8.8', 'Google', false, { asn: 15169, country_code: 'JP', lat: 35.68, lon: 139.69, geo_precision: 'city' }),
      seed('1.1.1.1', 'Cloudflare', false, { asn: 13335, country_code: 'FR', lat: 48.85, lon: 2.35, geo_precision: 'city' }),
      seed('1.0.0.1', 'Cloudflare', false, { asn: 13335, country_code: 'FR', lat: 48.85, lon: 2.35, geo_precision: 'city' }),
    ]);
    // our "server" is in Paris: an answer from Tokyo (9 700 km) in a few ms is impossible
    const r = await qualify(candidates(db), {
      dns: () => new ResolveSession(),
      geolocate: false,
      serverLocation: { ip: null, country_code: 'FR', city: 'Paris', lat: 48.85, lon: 2.35, source: 'test' },
      rounds: 1,
    });
    const by = new Map(r.outcomes.map((o) => [o.ip, o]));
    if (by.get('8.8.8.8')!.passed && by.get('8.8.8.8')!.minRttMs! < 90) expect(by.get('8.8.8.8')!.reasons).toContain('geo_implausible');
    const fr = ['1.1.1.1', '1.0.0.1'].map((ip) => by.get(ip)!).filter((o) => o.passed);
    // same ASN: only one of the two French entries is kept
    expect(fr.filter((o) => o.qualified).length).toBe(fr.length ? 1 : 0);
  }, 30000);
});
