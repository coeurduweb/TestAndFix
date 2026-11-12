import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { GuardedResolver } from './common.js';
import { analyzeDnssec, dnskeyRdata, dsDigest, keyTag, nameToWire, verifyDnskeyRrsig } from './dnssec.js';

const live = () => new GuardedResolver(new ResolveSession(), () => new ResolveSession());

describe('DNSSEC primitives', () => {
  it('encodes names and computes key tags and DS digests', () => {
    expect(nameToWire('Example.COM.').toString('hex')).toBe('076578616d706c6503636f6d00');
    const k = { flags: 257, algorithm: 15, key: Buffer.alloc(32, 1) };
    const rd = dnskeyRdata(k);
    expect(rd.subarray(0, 4).toString('hex')).toBe('0101030f');
    expect(keyTag(rd)).toBeGreaterThan(0);
    expect(dsDigest('example.com', rd, 2)).toMatch(/^[0-9a-f]{64}$/);
    expect(dsDigest('example.com', rd, 99)).toBeUndefined();
  });
  it('verifies an Ed25519 DNSKEY RRset signature it produced itself', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
    const key = { flags: 257, algorithm: 15, key: Buffer.from(raw) };
    const tag = keyTag(dnskeyRdata(key));
    const sig = { typeCovered: 'DNSKEY', algorithm: 15, labels: 2, originalTTL: 3600, expiration: 2000000000, inception: 1700000000, keyTag: tag, signersName: 'example.com', signature: Buffer.alloc(0) };
    // build the signed data exactly as RFC 4034 §3.1.8.1 says, then sign it
    const head = Buffer.alloc(18);
    head.writeUInt16BE(48, 0); head.writeUInt8(15, 2); head.writeUInt8(2, 3); head.writeUInt32BE(3600, 4);
    head.writeUInt32BE(2000000000, 8); head.writeUInt32BE(1700000000, 12); head.writeUInt16BE(tag, 16);
    const rd = dnskeyRdata(key);
    const fixed = Buffer.alloc(10);
    fixed.writeUInt16BE(48, 0); fixed.writeUInt16BE(1, 2); fixed.writeUInt32BE(3600, 4); fixed.writeUInt16BE(rd.length, 8);
    const data = Buffer.concat([head, nameToWire('example.com'), nameToWire('example.com'), fixed, rd]);
    sig.signature = sign(null, data, privateKey);
    expect(verifyDnskeyRrsig('example.com', [key], sig)).toBe(true);
    sig.signature[0] ^= 1;
    expect(verifyDnskeyRrsig('example.com', [key], sig)).toBe(false);
  });
});

describe('DNSSEC live', () => {
  it('validates the chain of cloudflare.com', async () => {
    const a = await analyzeDnssec(live(), 'cloudflare.com');
    expect(a.data.zone).toBe('cloudflare.com');
    expect(a.data.status).toBe('secure');
    const apex = a.data.chain.at(-1)!;
    expect(apex.ds.some((d) => d.matches !== null)).toBe(true);
    expect(apex.rrsig.some((r) => r.typeCovered === 'DNSKEY' && r.verified)).toBe(true);
    expect(a.issues.map((i) => i.id)).not.toContain('dnssec.bogus');
  });
  it('detects the broken chain of dnssec-failed.org', async () => {
    const a = await analyzeDnssec(live(), 'dnssec-failed.org');
    expect(a.data.status).toBe('bogus');
    expect(a.issues.map((i) => i.id)).toEqual(expect.arrayContaining(['dnssec.ds_mismatch']));
  });
  it('reports an unsigned zone (google.com)', async () => {
    const a = await analyzeDnssec(live(), 'google.com');
    expect(a.data.status).toBe('insecure');
    expect(a.issues.map((i) => i.id)).toContain('dnssec.unsigned');
  });
});
