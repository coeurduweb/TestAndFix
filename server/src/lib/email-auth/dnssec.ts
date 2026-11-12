// DNSSEC, basic chain of trust (RFC 4033-4035): DS at the parent, DNSKEY at the zone, the DS
// digest recomputed from the DNSKEY, the DNSKEY RRset self-signature verified with node:crypto,
// RRSIG validity dates and algorithms. Every query goes straight to the authoritative servers
// found by the session, with the DO bit set.
import type { PassedCheck } from '../../tools/types.js';
import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { query as rawQuery, type DnsAnswer, type DnsResponse, type QueryOptions, type RRType } from '../../dns/client.js';
import { ROOT_SERVERS, type NameServer, type ResolveResult } from '../../dns/iterative.js';
import { issue, norm, pass, type Analysis, type AuthorityResolver, type Issue } from './common.js';
import { t } from '../../i18n.js';

export type { AuthorityResolver } from './common.js';

export type QueryFn = (server: string, name: string, type: RRType, opts: QueryOptions) => Promise<DnsResponse>;

export const ALGORITHMS: Record<number, { name: string; status: 'ok' | 'not_recommended' | 'forbidden' }> = {
  // RFC 8624 §3.1 (signing)
  1: { name: 'RSAMD5', status: 'forbidden' },
  3: { name: 'DSA', status: 'forbidden' },
  5: { name: 'RSASHA1', status: 'not_recommended' },
  6: { name: 'DSA-NSEC3-SHA1', status: 'forbidden' },
  7: { name: 'RSASHA1-NSEC3-SHA1', status: 'not_recommended' },
  8: { name: 'RSASHA256', status: 'ok' },
  10: { name: 'RSASHA512', status: 'not_recommended' },
  12: { name: 'ECC-GOST', status: 'forbidden' },
  13: { name: 'ECDSAP256SHA256', status: 'ok' },
  14: { name: 'ECDSAP384SHA384', status: 'ok' },
  15: { name: 'ED25519', status: 'ok' },
  16: { name: 'ED448', status: 'ok' },
};
const DIGESTS: Record<number, string> = { 1: 'sha1', 2: 'sha256', 4: 'sha384' };

export interface DnskeyInfo {
  flags: number;
  protocol: number;
  algorithm: number;
  algorithmName: string;
  keyTag: number;
  /** Key-signing key (SEP bit). */
  ksk: boolean;
  revoked: boolean;
  bits?: number;
  /** DS record to publish at the parent for this key (SHA-256, RFC 4034 §5.1.4), for key-signing keys. */
  dsRecord?: string;
}

export interface DsInfo {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string;
  /** keyTag of the DNSKEY whose digest matches, or null. */
  matches: number | null;
}

export interface RrsigInfo {
  typeCovered: string;
  algorithm: number;
  keyTag: number;
  signer: string;
  inception: string;
  expiration: string;
  /** Inside its validity window now. */
  current: boolean;
  expiresInHours: number;
  /** Cryptographic check against the DNSKEY set (DNSKEY RRset only). */
  verified?: boolean;
  verifyError?: string;
}

export interface ZoneChain {
  zone: string;
  parent: string;
  ds: DsInfo[];
  dnskey: DnskeyInfo[];
  rrsig: RrsigInfo[];
  status: 'secure' | 'insecure' | 'bogus' | 'indeterminate';
  problems: string[];
  servers: { parent?: string; zone?: string };
}

export interface DnssecData {
  domain: string;
  zone: string;
  chain: ZoneChain[];
  status: ZoneChain['status'];
  nsec3?: { iterations: number; saltLength: number; algorithm: number };
}

export interface DnssecAnalysis extends Analysis {
  data: DnssecData;
}

// ---------------------------------------------------------------------------------------------
// Wire helpers

export function nameToWire(name: string): Buffer {
  const n = norm(name);
  if (!n) return Buffer.from([0]);
  const parts: Buffer[] = [];
  for (const l of n.split('.')) {
    const b = Buffer.from(l, 'ascii');
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

export function dnskeyRdata(k: { flags: number; algorithm: number; key: Buffer }): Buffer {
  const head = Buffer.alloc(4);
  head.writeUInt16BE(k.flags, 0);
  head.writeUInt8(3, 2);
  head.writeUInt8(k.algorithm, 3);
  return Buffer.concat([head, k.key]);
}

/** RFC 4034 Appendix B. */
export function keyTag(rdata: Buffer): number {
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) ac += i & 1 ? rdata[i] : rdata[i] << 8;
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

export function dsDigest(owner: string, rdata: Buffer, digestType: number): string | undefined {
  const alg = DIGESTS[digestType];
  if (!alg) return undefined;
  return createHash(alg).update(Buffer.concat([nameToWire(owner), rdata])).digest('hex');
}

function b64url(b: Buffer) {
  return b.toString('base64url');
}

/** Public key of a DNSKEY as a node KeyObject (RSA, ECDSA P-256/P-384, Ed25519). */
export function dnskeyToKey(algorithm: number, key: Buffer): KeyObject {
  if ([5, 7, 8, 10].includes(algorithm)) {
    let off = 1;
    let elen = key[0];
    if (elen === 0) {
      elen = key.readUInt16BE(1);
      off = 3;
    }
    const e = key.subarray(off, off + elen);
    const n = key.subarray(off + elen);
    return createPublicKey({ key: { kty: 'RSA', n: b64url(n), e: b64url(e) }, format: 'jwk' });
  }
  if (algorithm === 13 || algorithm === 14) {
    const half = key.length / 2;
    return createPublicKey({
      key: { kty: 'EC', crv: algorithm === 13 ? 'P-256' : 'P-384', x: b64url(key.subarray(0, half)), y: b64url(key.subarray(half)) },
      format: 'jwk',
    });
  }
  if (algorithm === 15) return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64url(key) }, format: 'jwk' });
  if (algorithm === 16) return createPublicKey({ key: { kty: 'OKP', crv: 'Ed448', x: b64url(key) }, format: 'jwk' });
  throw new Error(t('algorithme {algorithm} non pris en charge', { algorithm }));
}

function keyBits(algorithm: number, key: Buffer): number | undefined {
  try {
    const k = dnskeyToKey(algorithm, key);
    return k.asymmetricKeyDetails?.modulusLength ?? ({ 13: 256, 14: 384, 15: 256, 16: 456 } as Record<number, number>)[algorithm];
  } catch {
    return undefined;
  }
}

const TYPE_NUM: Record<string, number> = { DNSKEY: 48, SOA: 6, DS: 43 };

interface RrsigData {
  typeCovered: string;
  algorithm: number;
  labels: number;
  originalTTL: number;
  expiration: number;
  inception: number;
  keyTag: number;
  signersName: string;
  signature: Buffer;
}

/** Verify the RRSIG over a DNSKEY RRset (RFC 4034 §3.1.8.1 and §6). */
export function verifyDnskeyRrsig(owner: string, keys: { flags: number; algorithm: number; key: Buffer }[], sig: RrsigData): boolean {
  const signer = keys.find((k) => keyTag(dnskeyRdata(k)) === sig.keyTag && k.algorithm === sig.algorithm);
  if (!signer) throw new Error(t('aucune DNSKEY avec le keytag {keyTag}', { keyTag: sig.keyTag }));
  const head = Buffer.alloc(18);
  head.writeUInt16BE(TYPE_NUM[sig.typeCovered] ?? 48, 0);
  head.writeUInt8(sig.algorithm, 2);
  head.writeUInt8(sig.labels, 3);
  head.writeUInt32BE(sig.originalTTL >>> 0, 4);
  head.writeUInt32BE(sig.expiration >>> 0, 8);
  head.writeUInt32BE(sig.inception >>> 0, 12);
  head.writeUInt16BE(sig.keyTag, 16);
  const ownerWire = nameToWire(owner);
  const rrs = keys
    .map((k) => dnskeyRdata(k))
    .sort(Buffer.compare)
    .map((rd) => {
      const fixed = Buffer.alloc(10);
      fixed.writeUInt16BE(48, 0); // type
      fixed.writeUInt16BE(1, 2); // class IN
      fixed.writeUInt32BE(sig.originalTTL >>> 0, 4);
      fixed.writeUInt16BE(rd.length, 8);
      return Buffer.concat([ownerWire, fixed, rd]);
    });
  const data = Buffer.concat([head, nameToWire(sig.signersName), ...rrs]);
  const pub = dnskeyToKey(signer.algorithm, signer.key);
  const hash = ({ 5: 'sha1', 7: 'sha1', 8: 'sha256', 10: 'sha512', 13: 'sha256', 14: 'sha384' } as Record<number, string>)[sig.algorithm];
  if (sig.algorithm === 13 || sig.algorithm === 14) return cryptoVerify(hash, data, { key: pub, dsaEncoding: 'ieee-p1363' }, sig.signature);
  if (sig.algorithm === 15 || sig.algorithm === 16) return cryptoVerify(null, data, pub, sig.signature);
  return cryptoVerify(hash, data, pub, sig.signature);
}

// ---------------------------------------------------------------------------------------------

async function askAny(q: QueryFn, servers: NameServer[], name: string, type: RRType): Promise<{ res?: DnsResponse; server?: string; error?: string }> {
  let error: string | undefined;
  for (const s of servers.slice(0, 4)) {
    for (const ip of s.ips.filter((x) => !x.includes(':')).slice(0, 1)) {
      try {
        const res = await q(ip, name, type, { rd: false, dnssec: true, timeoutMs: 2500 });
        if (res.rcode === 'SERVFAIL' || res.rcode === 'REFUSED') {
          error = `${s.name} : ${res.rcode}`;
          continue;
        }
        return { res, server: `${s.name} (${ip})` };
      } catch (e) {
        error = `${s.name} : ${(e as Error).message}`;
      }
    }
  }
  return { error: error ?? t('aucun serveur joignable') };
}

const rootServers = (): NameServer[] => Object.entries(ROOT_SERVERS).map(([name, ip]) => ({ name, ips: [ip] }));

function parentOf(zone: string): string {
  const i = zone.indexOf('.');
  return i < 0 ? '' : zone.slice(i + 1);
}

async function zoneChain(dns: AuthorityResolver, q: QueryFn, zone: string, servers: NameServer[], now: number): Promise<ZoneChain> {
  const parentName = parentOf(zone);
  const parent = parentName ? await dns.findAuthorities(parentName) : { zone: '', servers: rootServers() };
  const out: ZoneChain = { zone, parent: parent.zone || '.', ds: [], dnskey: [], rrsig: [], status: 'indeterminate', problems: [], servers: {} };
  const [dsr, kr] = await Promise.all([askAny(q, parent.servers, zone, 'DS'), askAny(q, servers, zone, 'DNSKEY')]);
  out.servers = { parent: dsr.server, zone: kr.server };
  if (!dsr.res) out.problems.push(`DS : ${dsr.error}`);
  if (!kr.res) out.problems.push(`DNSKEY : ${kr.error}`);
  const isOf = (a: DnsAnswer, type: string) => a.type === type && norm(a.name) === zone;
  const rawKeys = (kr.res?.answers ?? []).filter((a) => isOf(a, 'DNSKEY')).map((a) => a.data as { flags: number; algorithm: number; key: Buffer });
  out.dnskey = rawKeys.map((k) => {
    const rd = dnskeyRdata(k);
    return {
      flags: k.flags,
      protocol: 3,
      algorithm: k.algorithm,
      algorithmName: ALGORITHMS[k.algorithm]?.name ?? `algorithme ${k.algorithm}`,
      keyTag: keyTag(rd),
      ksk: (k.flags & 1) === 1,
      revoked: (k.flags & 0x80) !== 0,
      bits: keyBits(k.algorithm, k.key),
      dsRecord: (k.flags & 1) === 1 ? `${zone}. IN DS ${keyTag(rd)} ${k.algorithm} 2 ${dsDigest(zone, rd, 2)!.toUpperCase()}` : undefined,
    };
  });
  out.ds = (dsr.res?.answers ?? [])
    .filter((a) => isOf(a, 'DS'))
    .map((a) => {
      const d = a.data as { keyTag: number; algorithm: number; digestType: number; digest: Buffer };
      const hex = Buffer.from(d.digest).toString('hex');
      const m = rawKeys.find((k) => {
        const rd = dnskeyRdata(k);
        return keyTag(rd) === d.keyTag && k.algorithm === d.algorithm && dsDigest(zone, rd, d.digestType) === hex;
      });
      return { keyTag: d.keyTag, algorithm: d.algorithm, digestType: d.digestType, digest: hex, matches: m ? keyTag(dnskeyRdata(m)) : null };
    });
  const sigs = (kr.res?.answers ?? []).filter((a) => a.type === 'RRSIG' && norm(a.name) === zone).map((a) => a.data as RrsigData);
  // SOA signature, for the dates of ordinary zone data
  const soa = await askAny(q, servers, zone, 'SOA');
  const soaSigs = (soa.res?.answers ?? []).filter((a) => a.type === 'RRSIG' && norm(a.name) === zone).map((a) => a.data as RrsigData);
  for (const s of [...sigs, ...soaSigs]) {
    const info: RrsigInfo = {
      typeCovered: s.typeCovered,
      algorithm: s.algorithm,
      keyTag: s.keyTag,
      signer: norm(s.signersName),
      inception: new Date(s.inception * 1000).toISOString(),
      expiration: new Date(s.expiration * 1000).toISOString(),
      current: s.inception * 1000 <= now && now <= s.expiration * 1000,
      expiresInHours: Math.floor((s.expiration * 1000 - now) / 3600000),
    };
    if (s.typeCovered === 'DNSKEY') {
      try {
        info.verified = verifyDnskeyRrsig(zone, rawKeys, s);
      } catch (e) {
        info.verified = false;
        info.verifyError = (e as Error).message;
      }
    }
    out.rrsig.push(info);
  }
  // verdict
  if (!dsr.res || !kr.res) out.status = 'indeterminate';
  else if (!out.ds.length) out.status = 'insecure';
  else if (!out.dnskey.length) {
    out.status = 'bogus';
    out.problems.push(t('DS publié au parent mais aucune DNSKEY dans la zone'));
  } else if (!out.ds.some((d) => d.matches !== null)) {
    out.status = 'bogus';
    out.problems.push(t('aucun DS ne correspond à une DNSKEY de la zone'));
  } else {
    const dnskeySigs = out.rrsig.filter((r) => r.typeCovered === 'DNSKEY');
    const matchedTags = new Set(out.ds.filter((d) => d.matches !== null).map((d) => d.matches));
    const good = dnskeySigs.some((r) => r.current && r.verified && matchedTags.has(r.keyTag));
    if (!dnskeySigs.length) {
      out.status = 'bogus';
      out.problems.push(t('l’ensemble DNSKEY n’est pas signé'));
    } else if (!good) {
      out.status = 'bogus';
      out.problems.push(
        dnskeySigs.some((r) => !r.current)
          ? t('la signature de l’ensemble DNSKEY est hors de sa période de validité')
          : t('la signature de l’ensemble DNSKEY par la clé désignée au parent ne se vérifie pas'),
      );
    } else if (out.rrsig.some((r) => r.typeCovered === 'SOA' && !r.current)) {
      out.status = 'bogus';
      out.problems.push(t('la signature du SOA est hors de sa période de validité'));
    } else out.status = 'secure';
  }
  return out;
}

export interface DnssecOptions {
  query?: QueryFn;
  now?: number;
}

export async function analyzeDnssec(dns: AuthorityResolver, domain: string, opts: DnssecOptions = {}): Promise<DnssecAnalysis> {
  const q = opts.query ?? rawQuery;
  const now = opts.now ?? Date.now();
  const issues: Issue[] = [];
  const passed: PassedCheck[] = [];
  // a name that does not exist would be measured on its parent zone
  const exists = await dns.resolve(domain, 'SOA').catch(() => undefined);
  if (exists?.rcode === 'NXDOMAIN')
    return { issues, passed, unavailable: [{ source: 'dnssec', reason: t('Non mesuré : {domain} n’existe pas dans le DNS.', { domain }) }], data: { domain, zone: '', chain: [], status: 'indeterminate' } };
  const auth = await dns.findAuthorities(domain);
  const zone = auth.zone;
  const parentZone = parentOf(zone);
  const chain: ZoneChain[] = [];
  const [apex, parentChain] = await Promise.all([
    zoneChain(dns, q, zone, auth.servers, now),
    parentZone ? dns.findAuthorities(parentZone).then((p) => zoneChain(dns, q, p.zone, p.servers, now)).catch(() => undefined) : Promise.resolve(undefined),
  ]);
  if (parentChain) chain.push(parentChain);
  chain.push(apex);
  const data: DnssecData = { domain, zone, chain, status: apex.status };
  // a zone below an unsigned parent cannot be secure, whatever it publishes
  if (parentChain && parentChain.status === 'insecure' && apex.status === 'secure') data.status = 'insecure';

  const ev = (z: ZoneChain) =>
    [
      t('DS au parent ({parent}) : {list}', { parent: z.parent, list: z.ds.map((d) => `${d.keyTag} alg ${d.algorithm} digest ${d.digestType}`).join(', ') || t('aucun') }),
      `DNSKEY : ${z.dnskey.map((k) => `${k.keyTag} ${k.ksk ? 'KSK' : 'ZSK'} ${k.algorithmName}`).join(', ') || t('aucune')}`,
      ...z.problems,
    ].join('\n');

  const vars = { domain: zone };
  if (apex.status === 'indeterminate') {
    return { issues, passed, unavailable: [{ source: 'dnssec', reason: apex.problems.join(' ; ') || t('serveurs injoignables') }], data };
  }
  if (apex.status === 'insecure') {
    if (apex.dnskey.length) issues.push(issue('dnssec.ds_missing', vars, { evidence: ev(apex) }));
    else issues.push(issue('dnssec.unsigned', vars, { evidence: ev(apex) }));
  } else if (apex.status === 'bogus') {
    if (!apex.dnskey.length) issues.push(issue('dnssec.dnskey_missing', vars, { evidence: ev(apex) }));
    else if (!apex.ds.some((d) => d.matches !== null)) {
      // the DS to publish, computed from the key-signing keys actually served by the zone
      const ds = apex.dnskey.filter((k) => k.ksk && k.dsRecord && !k.revoked).map((k) => k.dsRecord!);
      issues.push(issue('dnssec.ds_mismatch', vars, { evidence: ev(apex), suggested: ds.length ? ds.join('\n') : undefined }));
    } else if (apex.rrsig.some((r) => !r.current && r.expiresInHours < 0)) issues.push(issue('dnssec.rrsig_expired', vars, { evidence: ev(apex) }));
    else issues.push(issue('dnssec.bogus', vars, { evidence: ev(apex) }));
  } else {
    passed.push(pass('dnssec.chain', 'dnssec', t('Chaîne de confiance valide pour {zone}', { zone }), t('DS {tags} → DNSKEY signée', { tags: apex.ds.filter((d) => d.matches !== null).map((d) => d.keyTag).join(', ') })));
    // Online signers (Cloudflare, NS1…) sign each answer with a validity of a day or two: a short
    // remaining time is their normal state. Only a signature in the last quarter of its window,
    // with less than 3 days left, means that re-signing has stalled.
    const soon = apex.rrsig.filter((r) => {
      const windowH = (Date.parse(r.expiration) - Date.parse(r.inception)) / 3600000;
      return r.current && r.expiresInHours < 72 && r.expiresInHours < windowH / 4;
    });
    if (soon.length) issues.push(issue('dnssec.rrsig_expiring', { ...vars, value: Math.min(...soon.map((r) => r.expiresInHours)) }, { evidence: soon.map((r) => t('RRSIG {type} expire le {date}', { type: r.typeCovered, date: r.expiration })).join('\n') }));
  }
  const algs = new Set([...apex.dnskey.map((k) => k.algorithm), ...apex.ds.map((d) => d.algorithm)]);
  const weak = [...algs].filter((a) => ALGORITHMS[a]?.status !== 'ok');
  if (weak.length) issues.push(issue('dnssec.algorithm_not_recommended', { ...vars, value: weak.map((a) => ALGORITHMS[a]?.name ?? a).join(', ') }, { evidence: ev(apex) }));
  else if (algs.size) passed.push(pass('dnssec.algorithm', 'dnssec', t('Algorithme {names}', { names: [...algs].map((a) => ALGORITHMS[a]?.name ?? a).join(', ') })));
  if (apex.ds.some((d) => d.digestType === 1) && !apex.ds.some((d) => d.digestType !== 1 && d.matches !== null))
    issues.push(issue('dnssec.ds_sha1', vars, { evidence: ev(apex) }));

  if (apex.dnskey.length) {
    const n = await askAny(q, auth.servers, zone, 'NSEC3PARAM');
    const p = n.res?.answers.find((a) => a.type === 'NSEC3PARAM');
    if (p && Buffer.isBuffer(p.data)) {
      const b = p.data as Buffer;
      data.nsec3 = { algorithm: b[0], iterations: b.readUInt16BE(2), saltLength: b[4] };
    } else if (p) {
      const d = p.data as { iterations?: number; salt?: Buffer; algorithm?: number };
      if (d.iterations !== undefined) data.nsec3 = { algorithm: d.algorithm ?? 1, iterations: d.iterations, saltLength: d.salt?.length ?? 0 };
    }
    if (data.nsec3 && data.nsec3.iterations > 0) issues.push(issue('dnssec.nsec3_iterations', { ...vars, value: data.nsec3.iterations }, { evidence: t('NSEC3PARAM : {n} itérations', { n: data.nsec3.iterations }) }));
  }
  // a bogus chain makes validating resolvers answer SERVFAIL: the whole domain disappears for them
  return { issues, passed, data, ...(data.status === 'bogus' ? { scoreCap: BOGUS_SCORE_CAP } : {}) };
}

/** Highest score of a domain whose DNSSEC chain is bogus (review of 2026-11-10: it got 7.0). */
export const BOGUS_SCORE_CAP = 2;
