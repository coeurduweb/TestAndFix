// Helpers shared by the record generators (SPF, DKIM, DMARC, MTA-STS): TXT strings of 255
// characters, zone-file formatting, tolerant domain and address parsing. Pure, unit tested.
import { toDomain } from '../../lib/detect';
import { t } from '../../lib/i18n';

/** RFC 1035 §3.3.14: one character-string holds at most 255 octets. */
export const TXT_STRING_MAX = 255;

/**
 * Cut a TXT value into strings of at most `max` characters. The receiver concatenates the
 * strings without adding anything (RFC 7208 §3.3, RFC 6376 §3.6.2.2), so any cut is valid;
 * we prefer to cut right after a space, for readability, when one falls in the last quarter.
 */
export function splitTxt(value: string, max = TXT_STRING_MAX): string[] {
  if (max < 1) throw new Error('max must be positive');
  const parts: string[] = [];
  let rest = value;
  while (rest.length > max) {
    let cut = max;
    const space = rest.lastIndexOf(' ', max - 1);
    if (space >= Math.floor(max * 0.75)) cut = space + 1;
    parts.push(rest.slice(0, cut));
    rest = rest.slice(cut);
  }
  parts.push(rest);
  return parts;
}

/** `"part 1" "part 2"`, quotes and backslashes escaped, as in a zone file. */
export function quoteTxt(parts: string[]): string {
  return parts.map((p) => `"${p.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join(' ');
}

/** One zone-file line: `name. IN TXT ( "a" "b" )` when several strings. */
export function zoneLine(name: string, value: string, ttl?: number): string {
  const parts = splitTxt(value);
  const head = `${name.replace(/\.?$/, '.')}${ttl ? ` ${ttl}` : ''} IN TXT`;
  if (parts.length === 1) return `${head} ${quoteTxt(parts)}`;
  return `${head} (\n${parts.map((p) => quoteTxt([p])).join('\n')} )`;
}

/** Tolerant domain: URL, e-mail address, capitals, spaces, trailing dot accepted. */
export function cleanDomain(raw: string | null | undefined): string | undefined {
  if (!raw) return undefined;
  return toDomain(raw);
}

// Two-label public suffixes frequent in our clients' domains. Not the full Public Suffix List:
// used only to tell "same organisation" from "other organisation" for report addresses.
const SECOND_LEVEL = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'com.br', 'com.mx',
  'co.za', 'com.tr', 'com.cn', 'co.in', 'gouv.fr', 'asso.fr', 'com.fr', 'nom.fr', 'tm.fr', 'gov.br', 'com.es', 'co.il',
]);

/** Organisational domain, approximated: last two labels, three under a known two-label suffix. */
export function orgDomain(domain: string): string {
  const labels = domain.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  const last2 = labels.slice(-2).join('.');
  return SECOND_LEVEL.has(last2) ? labels.slice(-3).join('.') : last2;
}

export const sameOrg = (a: string, b: string) => orgDomain(a) === orgDomain(b);

const EMAIL = /^[^\s@<>",;]+@([a-z0-9.-]+\.[a-z]{2,63})$/i;

/** Tolerant report address: "dmarc@x.fr", "mailto:dmarc@x.fr", "<dmarc@x.fr>" → normalised. */
export function parseMailto(raw: string): { uri: string; address: string; domain: string } | { error: string } {
  const s = raw.trim().replace(/^<|>$/g, '').replace(/^mailto:/i, '').trim();
  if (!s) return { error: t('Adresse vide.') };
  if (/^https:\/\//i.test(raw.trim())) {
    try {
      const u = new URL(raw.trim());
      return { uri: u.href, address: u.href, domain: u.hostname };
    } catch {
      return { error: t("« {value} » n'est pas une URL valide.", { value: raw.trim() }) };
    }
  }
  const m = EMAIL.exec(s);
  if (!m) return { error: t("« {value} » n'est pas une adresse e-mail.", { value: raw.trim() }) };
  const domain = m[1].toLowerCase().replace(/\.$/, '');
  const address = `${s.slice(0, s.lastIndexOf('@'))}@${domain}`;
  return { uri: `mailto:${address}`, address, domain };
}

/** Several addresses typed in one field, separated by commas, semicolons, spaces or new lines. */
export function parseMailtoList(raw: string) {
  return raw
    .split(/[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean)
    .map(parseMailto);
}

/** Date-based identifier, UTC, letters and digits only: 20261110T183400. */
export function stampId(d = new Date()): string {
  return d.toISOString().slice(0, 19).replace(/[-:]/g, '');
}
