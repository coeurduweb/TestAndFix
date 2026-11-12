// Helpers for the mail tests: simulated DNS, DKIM signing with a local key, fixtures.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { dkimSign } from 'mailauth';
import { config } from '../config.js';
import type { AnalyzeDeps, NodeResolver } from './analyze/types.js';

const here = path.dirname(fileURLToPath(import.meta.url));

export function fixture(name: string): Buffer {
  return fs.readFileSync(path.join(here, 'fixtures', name));
}

export type Zone = Record<string, Partial<Record<'A' | 'AAAA' | 'TXT' | 'MX' | 'PTR' | 'CNAME' | 'NS', unknown[]>>>;

/** dns.promises.resolve-like resolver over a fixed zone; unknown names are NXDOMAIN. */
export function fakeResolver(zone: Zone): NodeResolver & { queries: string[] } {
  const queries: string[] = [];
  const fn = (async (name: string, type = 'A') => {
    const n = name.toLowerCase().replace(/\.$/, '');
    queries.push(`${n} ${type}`);
    const rec = zone[n];
    const err = (code: string) => Object.assign(new Error(`${code} ${n}`), { code });
    if (!rec) throw err('ENOTFOUND');
    const v = rec[type as keyof typeof rec];
    if (!v || !v.length) throw err('ENODATA');
    return v;
  }) as NodeResolver & { queries: string[] };
  fn.queries = queries;
  return fn;
}

export function rsaKey(bits = 2048) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  return { privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), record: `v=DKIM1; k=rsa; p=${spki}` };
}

export async function sign(raw: Buffer, domain: string, selector: string, privateKey: string, headerList?: string): Promise<Buffer> {
  const r = await dkimSign(raw, { signatureData: [{ signingDomain: domain, selector, privateKey }], headerList });
  if (r.errors.length) throw r.errors[0].err;
  return Buffer.concat([Buffer.from(r.signatures, 'latin1'), raw]);
}

export const SENDER_IP = '93.184.215.14';

/** A domain set up correctly: SPF for SENDER_IP, DMARC reject, PTR and A of mail.atelier-exemple.fr. */
export function goodZone(dkimRecord?: string): Zone {
  const z: Zone = {
    'atelier-exemple.fr': { TXT: [['v=spf1 ip4:93.184.215.14 -all']], A: ['93.184.215.14'], MX: [{ exchange: 'mail.atelier-exemple.fr', priority: 10 }] },
    '_dmarc.atelier-exemple.fr': { TXT: [['v=DMARC1; p=reject; rua=mailto:dmarc@atelier-exemple.fr']] },
    'mail.atelier-exemple.fr': { A: ['93.184.215.14'] },
    '14.215.184.93.in-addr.arpa': { PTR: ['mail.atelier-exemple.fr'] },
    'www.atelier-exemple.fr': { A: ['93.184.215.14'] },
  };
  if (dkimRecord) z['s1._domainkey.atelier-exemple.fr'] = { TXT: [[dkimRecord]] };
  return z;
}

export function deps(resolver: NodeResolver, extra: Partial<AnalyzeDeps> = {}): AnalyzeDeps {
  return {
    config: { ...config, mail: { ...config.mail, domain: 'check.localhost' } },
    resolver,
    spamd: false,
    fetcher: false,
    dnsbl: false,
    now: () => new Date('2026-11-10T15:00:00Z'),
    ...extra,
  };
}
