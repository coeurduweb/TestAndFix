import { describe, expect, it } from 'vitest';
import type { DnssecData } from '../domain/model';
import { chainMetrics, fmtHours } from './chain';

// dnssec-failed.org, measured 2026-11-10 (trimmed)
const failed: DnssecData = {
  domain: 'dnssec-failed.org',
  zone: 'dnssec-failed.org',
  status: 'bogus',
  chain: [
    {
      zone: 'org', parent: '.', status: 'secure', problems: [], servers: {},
      ds: [{ keyTag: 26974, algorithm: 8, digestType: 2, digest: 'ab', matches: 26974 }],
      dnskey: [{ flags: 257, protocol: 3, algorithm: 8, algorithmName: 'RSASHA256', keyTag: 26974, ksk: true, revoked: false }],
      rrsig: [{ typeCovered: 'DNSKEY', algorithm: 8, keyTag: 26974, signer: 'org', inception: '', expiration: '', current: true, expiresInHours: 478, verified: true }],
    },
    {
      zone: 'dnssec-failed.org', parent: 'org', status: 'bogus', problems: ['aucun DS ne correspond à une DNSKEY de la zone'], servers: {},
      ds: [{ keyTag: 42069, algorithm: 13, digestType: 2, digest: 'cd', matches: null }],
      dnskey: [{ flags: 257, protocol: 3, algorithm: 13, algorithmName: 'ECDSAP256SHA256', keyTag: 50719, ksk: true, revoked: false }],
      rrsig: [
        { typeCovered: 'DNSKEY', algorithm: 13, keyTag: 32784, signer: 'dnssec-failed.org', inception: '', expiration: '', current: true, expiresInHours: 31, verified: true },
        { typeCovered: 'DNSKEY', algorithm: 13, keyTag: 50719, signer: 'dnssec-failed.org', inception: '', expiration: '', current: false, expiresInHours: -3140, verified: true },
      ],
    },
  ],
};

describe('chainMetrics', () => {
  it('lists the root then each link, top to bottom, findings on the zone of the domain', () => {
    const rows = chainMetrics(failed, 'dnssec-failed.org');
    expect(rows.map((r) => r.label)).toEqual(['.', 'org', 'dnssec-failed.org']);
    expect(rows.map((r) => r.depth ?? 0)).toEqual([0, 1, 2]);
    expect(rows[1].dev.kind).toBe('ok');
    expect(rows[2]).toMatchObject({ measured: '0/1 DS reliés · 1 DNSKEY · 1/2 signatures valides', dev: { kind: 'out' } });
    expect(rows[1].ids).toBeUndefined();
    expect(rows[2].ids).toContain('dnssec.ds_mismatch');
  });
});

describe('fmtHours', () => {
  it('hours up to 48 h, days beyond', () => {
    expect(fmtHours(31)).toBe('dans 31 h');
    expect(fmtHours(-3140)).toBe('il y a 131 j');
  });
});
