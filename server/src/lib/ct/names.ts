// Name hygiene for CT data: certificates carry e-mail addresses, upper case, trailing dots, IDN in
// U-labels, IP addresses and names of other domains. Only names at or under the searched domain
// are kept, in lower-case A-labels, with wildcards ("*.x") recognised.
import net from 'node:net';
import { domainToASCII } from 'node:url';

const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;

export interface CleanName {
  /** Name without the "*." of a wildcard. */
  name: string;
  wildcard: boolean;
}

/** Normalise one name from a certificate; undefined when it is not a DNS name under `domain`. */
export function cleanName(raw: string, domain: string): CleanName | undefined {
  let s = String(raw ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (!s || s.includes('@') || s.includes(' ') || s.includes('/')) return undefined;
  let wildcard = false;
  if (s.startsWith('*.')) {
    wildcard = true;
    s = s.slice(2);
  }
  if (s.includes('*') || net.isIP(s)) return undefined;
  const ascii = /^[\x00-\x7f]*$/.test(s) ? s : domainToASCII(s);
  if (!ascii || ascii.length > 253 || !ascii.split('.').every((l) => LABEL.test(l))) return undefined;
  if (ascii !== domain && !ascii.endsWith('.' + domain)) return undefined;
  return { name: ascii, wildcard };
}

/** Display form of a cleaned name. */
export const displayName = (c: CleanName) => (c.wildcard ? `*.${c.name}` : c.name);

/** Does the certificate name `certName` ("*.a.b" or "x.a.b") cover the host `host`? (RFC 6125 §6.4.3, left-most label only) */
export function covers(certName: string, host: string): boolean {
  if (certName === host) return true;
  if (!certName.startsWith('*.')) return false;
  const parent = certName.slice(2);
  const i = host.indexOf('.');
  return i > 0 && host.slice(i + 1) === parent;
}

/** Short issuer name from a distinguished name: O= when present, else CN=. */
export function issuerShortName(dn: string): string {
  const pick = (k: string) => new RegExp(`(?:^|,\\s*)${k}=("([^"]*)"|[^,]*)`).exec(dn);
  const o = pick('O');
  const cn = pick('CN');
  const v = (m: RegExpExecArray | null) => (m ? (m[2] ?? m[1]).trim() : '');
  return v(o) || v(cn) || dn;
}

/** "2026-09-21T07:56:41" (crt.sh, UTC without zone) or ISO with Z: always ISO with Z. */
export function utcIso(s: string | undefined): string | undefined {
  if (!s) return undefined;
  const withZone = /[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`;
  const t = Date.parse(withZone);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString().replace(/\.\d{3}Z$/, 'Z');
}
