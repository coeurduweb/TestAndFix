// Record types offered by the DNS lookup and the propagation pages, most used first,
// and the smart default type of a name. Pure, unit tested in rrtypes.test.ts.
import { isIp } from '../../lib/detect';
import { msg } from '../../lib/i18n';

/** Shown as segments: the everyday types. */
export const COMMON_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'] as const;

/** Mirror of server/src/tools/dns/format.ts QUERY_TYPES. */
export const DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'SRV', 'PTR', 'DS', 'DNSKEY', 'TLSA', 'HTTPS', 'SVCB', 'NAPTR'] as const;

/** Mirror of server/src/tools/propagation/normalize.ts SUPPORTED_TYPES. */
export const PROPAGATION_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'SRV', 'PTR', 'DS', 'DNSKEY', 'HTTPS'] as const;

/** One line per type, shown in the "other type" list. */
export const TYPE_HINT: Record<string, string> = {
  A: msg('adresse IPv4'),
  AAAA: msg('adresse IPv6'),
  CNAME: msg('alias'),
  MX: msg('serveurs de messagerie'),
  TXT: msg('texte (SPF, DMARC, vérifications)'),
  NS: msg('serveurs de noms'),
  SOA: msg('origine de la zone, serial'),
  CAA: msg('autorités de certification permises'),
  SRV: msg('service (_sip._tcp, _imaps._tcp)'),
  PTR: msg('reverse DNS'),
  DS: msg('empreinte DNSSEC chez le parent'),
  DNSKEY: msg('clés DNSSEC de la zone'),
  TLSA: msg('DANE (_25._tcp.mx)'),
  HTTPS: msg('paramètres HTTPS (ALPN, ECH)'),
  SVCB: msg('liaison de service'),
  NAPTR: msg('réécriture (ENUM, SIP)'),
};

/** Normalise a name typed or pasted in the URL: lower case, no trailing dot, no scheme or path. */
export function cleanName(raw: string | undefined | null): string {
  let s = (raw ?? '').trim().toLowerCase();
  if (!s) return '';
  if (isIp(s)) return s;
  s = s.replace(/^[a-z]+:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '');
  const at = s.lastIndexOf('@');
  if (at >= 0) s = s.slice(at + 1);
  return s.replace(/\.+$/, '');
}

/** Type to ask when none is given: PTR for an IP, TXT for policy names, SRV or TLSA for service names. */
export function defaultType(name: string): string {
  const n = cleanName(name);
  if (!n) return 'A';
  if (isIp(n) || /\.(in-addr|ip6)\.arpa$/.test(n)) return 'PTR';
  if (/^_\d+\._(tcp|udp|sctp)\./.test(n)) return 'TLSA';
  if (/^_[a-z0-9-]+\._(tcp|udp|tls|sctp)\./.test(n)) return 'SRV';
  if (/^_(dmarc|mta-sts|smtp\._tls|bimi|acme-challenge)\./.test(n) || /\._domainkey\./.test(n) || /^[^.]+\._bimi\./.test(n)) return 'TXT';
  return 'A';
}

/** Type from the query string, upper-cased and checked against the allowed list; default otherwise. */
export function pickType(raw: string | null, name: string, allowed: readonly string[]): string {
  const t = (raw ?? '').trim().toUpperCase();
  if (t && allowed.includes(t)) return t;
  const d = defaultType(name);
  return allowed.includes(d) ? d : 'A';
}

/** Same rule as the server (propagation normalizeName): labels of letters, digits, _ and -, 253 characters at most. */
export function isDnsName(name: string): boolean {
  if (isIp(name)) return true;
  return name.length > 0 && name.length <= 253 && /^[a-z0-9_*]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$/.test(name);
}
