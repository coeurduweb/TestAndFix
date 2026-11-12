// @vitest-environment node
import { afterAll, describe, expect, it } from 'vitest';
import { b64, cleanSelector, dkimRecord, generateDkimKey, keyName, SELECTOR, suggestSelectors, toPem } from './keys';
import { splitTxt } from '../gen-spf/txt';

// Node modules loaded by name: the web tsconfig carries no Node types.
const load = (name: string) => import(/* @vite-ignore */ name);
const { execFileSync } = await load('node:child_process');
const { mkdtempSync, rmSync, writeFileSync } = await load('node:fs');
const { tmpdir } = await load('node:os');
const { join } = await load('node:path');

const hasOpenssl = (() => {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();
const dir = mkdtempSync(join(tmpdir(), 'dkim-test-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

describe('key encoding', () => {
  it('base64 and PEM armour at 64 columns', () => {
    expect(b64(new Uint8Array([0, 1, 2, 250]))).toBe('AAEC+g==');
    const pem = toPem(new Uint8Array(100), 'PUBLIC KEY');
    const lines = pem.trim().split('\n');
    expect(lines[0]).toBe('-----BEGIN PUBLIC KEY-----');
    expect(lines.at(-1)).toBe('-----END PUBLIC KEY-----');
    expect(lines.slice(1, -1).every((l) => l.length <= 64)).toBe(true);
    expect(lines[1].length).toBe(64);
  });

  it('RSA 2048: SPKI in p=, PKCS#8 private key, record split in two strings', async () => {
    const k = await generateDkimKey('rsa2048');
    expect(k.k).toBe('rsa');
    const der = fromB64(k.publicB64);
    // SEQUENCE of length 0x0122 = 294 bytes: the DER of a 2048-bit RSA SubjectPublicKeyInfo
    expect([...der.slice(0, 4)]).toEqual([0x30, 0x82, 0x01, 0x22]);
    expect(k.privatePem.startsWith('-----BEGIN PRIVATE KEY-----\n')).toBe(true);
    const rec = dkimRecord(k.k, k.publicB64);
    expect(rec.startsWith('v=DKIM1; k=rsa; p=MIIBIjAN')).toBe(true);
    const parts = splitTxt(rec);
    expect(parts.length).toBe(2);
    expect(parts.join('')).toBe(rec);
    if (hasOpenssl) {
      writeFileSync(join(dir, 'pub.pem'), toPem(der, 'PUBLIC KEY'));
      writeFileSync(join(dir, 'priv.pem'), k.privatePem);
      const text = execFileSync('openssl', ['pkey', '-pubin', '-in', join(dir, 'pub.pem'), '-noout', '-text'], { encoding: 'utf8' });
      expect(text).toMatch(/Public-Key: \(2048 bit\)/);
      // the private key matches the published public key
      const derived = execFileSync('openssl', ['pkey', '-in', join(dir, 'priv.pem'), '-pubout'], { encoding: 'utf8' });
      expect(derived.replace(/\s/g, '')).toBe(k.publicPem.replace(/\s/g, ''));
    }
  }, 30_000);

  it('RSA 4096 gives a 4096-bit key', async () => {
    const k = await generateDkimKey('rsa4096');
    expect(k.bits).toBe(4096);
    expect([...fromB64(k.publicB64).slice(0, 4)]).toEqual([0x30, 0x82, 0x02, 0x22]);
    expect(splitTxt(dkimRecord(k.k, k.publicB64)).length).toBe(3);
  }, 60_000);

  it('Ed25519: raw 32-byte public key in p= (RFC 8463)', async () => {
    const k = await generateDkimKey('ed25519');
    expect(k.k).toBe('ed25519');
    expect(fromB64(k.publicB64).length).toBe(32);
    expect(k.publicB64.length).toBe(44);
    if (hasOpenssl) {
      writeFileSync(join(dir, 'ed.pem'), k.publicPem);
      const text = execFileSync('openssl', ['pkey', '-pubin', '-in', join(dir, 'ed.pem'), '-noout', '-text'], { encoding: 'utf8' });
      expect(text).toMatch(/ED25519 Public-Key/);
    }
  });
});

describe('selectors', () => {
  it('suggests date-based selectors', () => {
    expect(suggestSelectors(new Date(2026, 10, 10))).toEqual(['s202611', 'mail2026', 'check2026']);
  });
  it('validates and cleans selectors', () => {
    expect(SELECTOR.test('s202611')).toBe(true);
    expect(SELECTOR.test('mail 2026')).toBe(false);
    expect(SELECTOR.test('-bad')).toBe(false);
    expect(cleanSelector(' Mail 2026._domainkey.exemple.fr ')).toBe('mail2026');
    expect(keyName('s202611', 'exemple.fr')).toBe('s202611._domainkey.exemple.fr');
  });
});
