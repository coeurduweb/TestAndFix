import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { GuardedResolver } from './common.js';
import { analyzeDkim, keyBits, parseDkimKey } from './dkim.js';
import { FakeDns } from './fake-dns.js';
import { COMMON_SELECTORS } from './selectors.js';

const rsa = (bits: number) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const ed = () => generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64');
const ids = (a: { issues: { id: string }[] }) => a.issues.map((i) => i.id).sort();
const live = () => new GuardedResolver(new ResolveSession(), () => new ResolveSession());

describe('DKIM key parsing', () => {
  it('measures the real key size', () => {
    expect(keyBits(rsa(1024), 'rsa')).toBe(1024);
    expect(keyBits(rsa(2048), 'rsa')).toBe(2048);
    expect(keyBits(ed(), 'ed25519')).toBe(256);
    // bare PKCS#1 RSAPublicKey is accepted too
    const pkcs1 = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'pkcs1', format: 'der' }).toString('base64');
    expect(keyBits(pkcs1, 'rsa')).toBe(1024);
    expect(() => keyBits('AAAA', 'rsa')).toThrow();
  });
  it('reads flags and tags', () => {
    const k = parseDkimKey('s1', 'example.fr', `v=DKIM1; k=rsa; t=y:s; h=sha256; s=email; p=${rsa(1024)}`);
    expect(k).toMatchObject({ testing: true, strictSubdomains: true, hashAlgorithms: ['sha256'], serviceTypes: ['email'], bits: 1024, revoked: false });
    expect(parseDkimKey('s1', 'example.fr', 'v=DKIM1; p=').revoked).toBe(true);
    expect(parseDkimKey('s1', 'example.fr', 'k=rsa; v=DKIM1; p=abc').error).toMatch(/première balise/);
  });
  it('has a source for every common selector', () => {
    expect(COMMON_SELECTORS.every((s) => s.source.length > 5)).toBe(true);
    expect(new Set(COMMON_SELECTORS.map((s) => s.selector)).size).toBe(COMMON_SELECTORS.length);
  });
});

describe('DKIM discovery (simulated DNS)', () => {
  it('finds keys among the common selectors and follows CNAME to the ESP', async () => {
    const dns = new FakeDns({
      'google._domainkey.example.fr': { TXT: [`v=DKIM1; k=rsa; p=${rsa(2048)}`] },
      'selector1._domainkey.example.fr': { CNAME: ['selector1-example-fr._domainkey.contoso.onmicrosoft.com'] },
      'selector1-example-fr._domainkey.contoso.onmicrosoft.com': { TXT: [`v=DKIM1; k=rsa; p=${rsa(2048)}`] },
      's1._domainkey.example.fr': { TXT: [`v=DKIM1; k=ed25519; p=${ed()}`] },
    });
    const a = await analyzeDkim(dns, 'example.fr');
    expect(a.data.keys.map((k) => k.selector).sort()).toEqual(['google', 's1', 'selector1']);
    const ms = a.data.keys.find((k) => k.selector === 'selector1')!;
    expect(ms.cnameProvider).toBe('microsoft_365');
    expect(ms.knownFor).toEqual(['microsoft_365']);
    expect(a.issues).toEqual([]);
    expect(a.data.tried).toBe(COMMON_SELECTORS.length);
  });
  it('reports each key defect', async () => {
    const dns = new FakeDns({
      'k1._domainkey.example.fr': { TXT: [`v=DKIM1; p=${rsa(512)}`] },
      'k2._domainkey.example.fr': { TXT: [`v=DKIM1; t=y; h=sha1; p=${rsa(1024)}`] },
      'k3._domainkey.example.fr': { TXT: [`v=DKIM1; s=tlsrpt; p=${rsa(2048)}`] },
      'mail._domainkey.example.fr': { TXT: ['v=DKIM1; p=bm90IGEga2V5'] },
      'default._domainkey.example.fr': { TXT: ['v=DKIM1; p='] },
      'dkim._domainkey.example.fr': { TXT: [`v=DKIM1; p=${rsa(2048)}`, `v=DKIM1; p=${rsa(2048)}`] },
      'pm._domainkey.example.fr': { CNAME: ['pm.dangling.test'] },
    });
    const a = await analyzeDkim(dns, 'example.fr');
    expect(ids(a)).toEqual(
      ['dkim.key_1024', 'dkim.key_algorithm_mismatch', 'dkim.key_below_1024', 'dkim.selector_cname_dangling', 'dkim.key_revoked', 'dkim.key_service_type', 'dkim.key_syntax_error', 'dkim.key_testing_flag', 'dkim.multiple_key_records'].sort(),
    );
    // a revoked key next to active ones is a rotation leftover, not a penalty
    expect(a.issues.find((i) => i.id === 'dkim.key_revoked')?.penalty).toBe(0);
  });
  it('says when nothing is found, and when a given selector is missing', async () => {
    expect(ids(await analyzeDkim(new FakeDns({}), 'example.fr'))).toEqual(['dkim.selector_not_discovered']);
    const a = await analyzeDkim(new FakeDns({}), 'example.fr', { selectors: ['custom2024'], only: true });
    expect(a.data.tried).toBe(1);
    expect(ids(a)).toEqual(['dkim.key_not_found']);
  });
  it('flags a wildcard answering every selector', async () => {
    const zone: Record<string, Record<string, unknown[]>> = {};
    const key = `v=DKIM1; p=${rsa(2048)}`;
    const dns = new FakeDns(zone);
    // every name under _domainkey answers
    dns.resolve = async (name, type) => ({ name, type, rcode: 'NOERROR', answers: name.endsWith('._domainkey.example.fr') ? [{ name, type, ttl: 1, data: [Buffer.from(key)] }] : [], cnames: [], trace: [], ms: 0 });
    const a = await analyzeDkim(dns, 'example.fr');
    expect(a.data.wildcard).toBe(true);
    expect(ids(a)).toContain('dkim.wildcard');
  });
});

describe('DKIM live', () => {
  it('reads the Gmail key of gmail.com (selector 20230601, seen 2026-11-10)', async () => {
    const a = await analyzeDkim(live(), 'gmail.com', { selectors: ['20230601'], only: true });
    const k = a.data.keys.find((x) => x.selector === '20230601');
    if (k && !k.revoked) expect(k.bits ?? 0).toBeGreaterThanOrEqual(1024);
    else expect(a.issues.map((i) => i.id)).toEqual(expect.arrayContaining([k ? 'dkim.key_revoked' : 'dkim.key_not_found']));
  });
  it('follows the Microsoft 365 CNAME of microsoft.com', async () => {
    const a = await analyzeDkim(live(), 'microsoft.com', { selectors: ['selector1', 'selector2'], only: true });
    expect(a.data.keys.some((k) => k.cnames.length > 0 && k.cnameProvider === 'microsoft_365') || a.issues.some((i) => i.id.endsWith('_dangling'))).toBe(true);
  });
});
