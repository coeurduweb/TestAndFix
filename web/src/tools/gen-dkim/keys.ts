// DKIM key pairs generated in the browser with WebCrypto: nothing leaves the page.
// RSA: public key published as SubjectPublicKeyInfo in base64 (RFC 6376 §3.6.1, k=rsa).
// Ed25519: public key published as the raw 32 bytes in base64 (RFC 8463 §4.2, k=ed25519).
// Private key exported as PKCS#8 PEM. Unit tested in keys.test.ts (Node WebCrypto).

export type KeyKind = 'rsa2048' | 'rsa4096' | 'ed25519';

export interface DkimKeyPair {
  kind: KeyKind;
  /** k= tag value. */
  k: 'rsa' | 'ed25519';
  bits: number;
  /** p= tag value: base64, no line breaks. */
  publicB64: string;
  /** SubjectPublicKeyInfo PEM, to check the key with openssl. */
  publicPem: string;
  /** PKCS#8 PEM: the file to install in the signing software. */
  privatePem: string;
  createdAt: string;
}

export function b64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

/** PEM armour, 64 columns (RFC 7468 §2). */
export function toPem(der: ArrayBuffer | Uint8Array, label: string): string {
  const body = b64(der).replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

export async function generateDkimKey(kind: KeyKind, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<DkimKeyPair> {
  const createdAt = new Date().toISOString();
  if (kind === 'ed25519') {
    const pair = (await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    const raw = await subtle.exportKey('raw', pair.publicKey);
    const spki = await subtle.exportKey('spki', pair.publicKey);
    const pkcs8 = await subtle.exportKey('pkcs8', pair.privateKey);
    return { kind, k: 'ed25519', bits: 256, publicB64: b64(raw), publicPem: toPem(spki, 'PUBLIC KEY'), privatePem: toPem(pkcs8, 'PRIVATE KEY'), createdAt };
  }
  const bits = kind === 'rsa4096' ? 4096 : 2048;
  const pair = (await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const spki = await subtle.exportKey('spki', pair.publicKey);
  const pkcs8 = await subtle.exportKey('pkcs8', pair.privateKey);
  return { kind, k: 'rsa', bits, publicB64: b64(spki), publicPem: toPem(spki, 'PUBLIC KEY'), privatePem: toPem(pkcs8, 'PRIVATE KEY'), createdAt };
}

export const dkimRecord = (k: 'rsa' | 'ed25519', p: string) => `v=DKIM1; k=${k}; p=${p}`;

/** RFC 6376 §3.1: a selector is a DNS name (letters, digits, hyphens, dots between labels). */
export const SELECTOR = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/;

/** Tolerant selector: spaces and "._domainkey..." pasted by mistake removed, lower case. */
export function cleanSelector(raw: string): string {
  return raw.trim().replace(/\._domainkey(\..*)?$/i, '').replace(/\s+/g, '').toLowerCase();
}

/** Date-based selectors: rotation friendly (one per period, never reused). */
export function suggestSelectors(d = new Date()): string[] {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  return [`s${y}${m}`, `mail${y}`, `check${y}`];
}

/** A signing key name: s202611._domainkey.exemple.fr */
export const keyName = (selector: string, domain: string) => `${selector}._domainkey.${domain}`;
