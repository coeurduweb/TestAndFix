import { describe, expect, it } from 'vitest';
import { changedRecords, fmtTtl, type Fingerprint } from './FixLoop';

const fp = (dmarc: string[], ttl = 3600, rcode = 'NOERROR'): Fingerprint => ({
  domain: 'example.com', at: '', hash: '', serial: 1, complete: true,
  records: [
    { name: 'example.com', type: 'SOA', rcode: 'NOERROR', values: [JSON.stringify({ serial: 1, minttl: 300 })], ttl: 3600 },
    { name: 'example.com', type: 'MX', rcode: 'NOERROR', values: ['10 mx.example.com'], ttl: 3600 },
    { name: '_dmarc.example.com', type: 'TXT', rcode, values: dmarc, ttl: dmarc.length ? ttl : null },
  ],
});

describe('Fix loop', () => {
  it('names the records that changed, with the TTL of the previous answer', () => {
    expect(changedRecords(fp(['v=DMARC1; p=none']), fp(['v=DMARC1; p=quarantine']))).toEqual([{ name: '_dmarc.example.com', type: 'TXT', heldFor: 3600 }]);
    expect(changedRecords(fp(['v=DMARC1; p=none']), fp(['v=DMARC1; p=none']))).toEqual([]);
  });
  it('uses the negative TTL of the zone when the record did not exist before (RFC 2308)', () => {
    expect(changedRecords(fp([], 3600, 'NXDOMAIN'), fp(['v=DMARC1; p=none']))).toEqual([{ name: '_dmarc.example.com', type: 'TXT', heldFor: 300 }]);
  });
  it('says a TTL in words', () => {
    expect(fmtTtl(45)).toBe('45 secondes');
    expect(fmtTtl(300)).toBe('5 minutes');
    expect(fmtTtl(3600)).toBe('1 heure');
    expect(fmtTtl(86400)).toBe('24 heures');
  });
});
