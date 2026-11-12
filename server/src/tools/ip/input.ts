// Parsing of what the user types: one IPv4 or IPv6, an IPv4 range from /24 to /32, or a list of
// them (one per line, commas or spaces), up to 256 addresses once ranges are expanded.
import { t, msg } from '../../i18n.js';
import ipaddr from 'ipaddr.js';
import { InvalidInputError } from '../../lib/email-auth/common.js';
import { isPublicIp } from '../../lib/net.js';

export const MAX_BATCH = 256;

export interface ParsedIp {
  ip: string;
  version: 4 | 6;
}

/** Canonical form; an IPv4-mapped IPv6 address becomes the IPv4 address. Throws InvalidInputError. */
export function parseIp(input: string): ParsedIp {
  const raw = String(input ?? '').trim().replace(/^\[|\]$/g, '');
  if (!raw) throw new InvalidInputError(t('Adresse IP vide.'));
  if (!ipaddr.isValid(raw)) {
    // a domain typed in the IP field: its reputation has its own route on the same page
    if (/^(?=.*[a-z])[a-z0-9_-]+(\.[a-z0-9_-]+)+\.?$/i.test(raw) || /[^\x00-\x7f]/.test(raw))
      throw new InvalidInputError(t('« {raw} » est un nom de domaine, pas une adresse IP : sa réputation se mesure sur /api/ip/domain/{path}.', { raw, path: encodeURIComponent(raw.toLowerCase().replace(/\.$/, '')) }));
    throw new InvalidInputError(t('« {input} » n’est pas une adresse IP valide.', { input }));
  }
  // ipaddr accepts "1.2" or "0x7f.1" (inet_aton forms): only the four dotted decimal parts are accepted
  if (!raw.includes(':') && !ipaddr.IPv4.isValidFourPartDecimal(raw)) throw new InvalidInputError(t('« {input} » n’est pas une adresse IPv4 complète (quatre nombres séparés par des points).', { input }));
  let addr = ipaddr.parse(raw);
  if (addr.kind() === 'ipv6' && (addr as ipaddr.IPv6).isIPv4MappedAddress()) addr = (addr as ipaddr.IPv6).toIPv4Address();
  return addr.kind() === 'ipv4' ? { ip: addr.toString(), version: 4 } : { ip: (addr as ipaddr.IPv6).toString(), version: 6 };
}

/** "192.0.2.0/24" -> the 256 addresses. IPv4 only, prefix 24 to 32. */
export function expandRange(input: string): string[] {
  const [base, len] = input.trim().split('/');
  const prefix = Number(len);
  if (!/^\d+$/.test(len ?? '')) throw new InvalidInputError(t('« {input} » : longueur de préfixe invalide.', { input }));
  const { ip, version } = parseIp(base);
  if (version === 6) throw new InvalidInputError(t('Les plages IPv6 ne sont pas prises en charge : saisissez les adresses une par une.'));
  if (prefix < 24 || prefix > 32) throw new InvalidInputError(t('« {input} » : seules les plages de /24 à /32 sont acceptées (256 adresses au plus).', { input }));
  const bytes = ipaddr.IPv4.parse(ip).toByteArray();
  const n = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];
  const size = 2 ** (32 - prefix);
  const start = (n >>> 0) - ((n >>> 0) % size);
  const out: string[] = [];
  for (let i = 0; i < size; i++) {
    const v = start + i;
    out.push([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.'));
  }
  return out;
}

export function isRange(s: string): boolean {
  return /\/\d+$/.test(s.trim());
}

export interface BatchInput {
  ips: string[];
  invalid: { value: string; reason: string }[];
}

/** A list of IPs and ranges, as an array or a pasted text. Duplicates are dropped. */
export function parseBatch(input: string[] | string): BatchInput {
  const items = (Array.isArray(input) ? input : String(input ?? '').split(/[\s,;]+/)).map((s) => String(s).trim()).filter(Boolean);
  const ips: string[] = [];
  const seen = new Set<string>();
  const invalid: BatchInput['invalid'] = [];
  for (const item of items) {
    try {
      for (const ip of isRange(item) ? expandRange(item) : [parseIp(item).ip]) {
        if (seen.has(ip)) continue;
        seen.add(ip);
        ips.push(ip);
      }
    } catch (e) {
      invalid.push({ value: item, reason: (e as Error).message });
    }
    if (ips.length > MAX_BATCH) throw new InvalidInputError(t('Trop d’adresses : {max} au plus par vérification, plages comprises.', { max: MAX_BATCH }));
  }
  if (!ips.length) throw new InvalidInputError(invalid.length ? t('Aucune adresse valide : {reason}', { reason: invalid[0].reason }) : t('Aucune adresse IP saisie.'));
  return { ips, invalid };
}

const RANGE_LABELS: Record<string, string> = {
  private: msg('plage privée (RFC 1918), utilisée seulement à l’intérieur d’un réseau local'),
  loopback: msg('adresse de boucle locale : elle désigne la machine elle-même'),
  linkLocal: msg('adresse de lien local, attribuée automatiquement sans serveur DHCP'),
  carrierGradeNat: msg('plage partagée des opérateurs (RFC 6598, NAT d’opérateur)'),
  uniqueLocal: msg('adresse IPv6 locale unique (équivalent IPv6 d’une plage privée)'),
  multicast: msg('adresse de multidiffusion'),
  broadcast: msg('adresse de diffusion'),
  unspecified: msg('adresse non spécifiée'),
  reserved: msg('plage réservée (documentation, tests ou usage futur)'),
  benchmarking: msg('plage réservée aux tests de performance (RFC 2544)'),
  as112: msg('plage réservée au service AS112'),
  amt: msg('plage réservée au protocole AMT'),
  deprecated: msg('plage abandonnée'),
  orchid2: msg('plage réservée (ORCHIDv2)'),
  '6to4': msg('adresse de transition 6to4'),
  teredo: msg('adresse de transition Teredo'),
  rfc6145: msg('adresse de traduction IPv4/IPv6 (RFC 6145)'),
  rfc6052: msg('adresse de traduction IPv4/IPv6 (RFC 6052)'),
  ipv4Mapped: msg('adresse IPv4 écrite en IPv6'),
  discard: msg('plage de rejet (RFC 6666)'),
};

/** undefined for a public address, else the range name and its French description. */
export function nonPublicRange(ip: string): { range: string; label: string } | undefined {
  if (isPublicIp(ip)) return undefined;
  const range = ipaddr.parse(ip).range();
  return { range, label: RANGE_LABELS[range] ? t(RANGE_LABELS[range]) : t('plage non publique ({range})', { range }) };
}
