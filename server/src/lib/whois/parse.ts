// WHOIS text (RFC 3912 gives no format) read into the fields of a PartyRecord. Two families:
//   - "Key: value" lines, the format of gTLD registries and registrars (Verisign, PIR, Netim,
//     MarkMonitor in fixtures/) and of many ccTLDs; a key with an empty value followed by indented
//     lines takes those lines as values (Nominet style);
//   - RPSL-like blocks separated by blank lines with contact handles (Afnic: "holder-c:",
//     "nic-hdl:", "anonymous:"), recognised by those keys.
import { normalizeStatuses } from './epp.js';
import { emailOrForm, isPlaceholder, isPrivacyOrg } from './redaction.js';
import type { Contact, ContactRole, Party, PartyRecord } from './types.js';

export type ParsedWhois = Omit<PartyRecord, 'party' | 'protocol' | 'server' | 'raw'> & { notFound: boolean; rateLimited: boolean };

type Multi = Map<string, string[]>;

const normKey = (k: string) => k.toLowerCase().replace(/\.+$/, '').replace(/[_\s]+/g, ' ').trim();

/** Lines "key: value" in order; continuation lines attached to the last key with an empty value. */
export function keyValues(text: string): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  let open: string | undefined;
  for (const line of text.replace(/\r\n?/g, '\n').split('\n')) {
    if (/^\s*([%#;]|>>>)/.test(line) || !line.trim()) {
      if (!line.trim()) open = undefined;
      continue;
    }
    const m = /^\s*([^:\n]{1,64}?)\s*:(?!\/\/)\s*(.*?)\s*$/.exec(line);
    if (m) {
      const key = normKey(m[1]);
      out.push({ key, value: m[2] });
      open = m[2] ? undefined : key;
      continue;
    }
    if (open) out.push({ key: open, value: line.trim() });
  }
  return out.filter((kv) => kv.value !== '');
}

function multi(kvs: { key: string; value: string }[]): Multi {
  const m: Multi = new Map();
  for (const { key, value } of kvs) m.set(key, [...(m.get(key) ?? []), value]);
  return m;
}

const first = (m: Multi, keys: string[]) => {
  for (const k of keys) {
    const v = m.get(k)?.find((x) => x.trim());
    if (v) return v.trim();
  }
  return undefined;
};
const all = (m: Multi, keys: string[]) => keys.flatMap((k) => m.get(k) ?? []);

const MONTHS: Record<string, string> = { jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06', jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12' };

/** Dates as written by WHOIS servers, to ISO 8601 (UTC when no zone is given). */
export function parseWhoisDate(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const s = raw.trim().replace(/\s+\(.*\)$/, '');
  let m = /^(\d{4})[-./](\d{2})[-./](\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(\.\d+)?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?)?/i.exec(s);
  if (m) {
    const [, y, mo, d, h = '00', mi = '00', se = '00', , z] = m;
    const zone = !z || /^(z|utc|gmt)$/i.test(z) ? 'Z' : z.length === 5 ? `${z.slice(0, 3)}:${z.slice(3)}` : z;
    const t = Date.parse(`${y}-${mo}-${d}T${h}:${mi}:${se}${zone}`);
    return Number.isNaN(t) ? undefined : new Date(t).toISOString().replace('.000Z', 'Z');
  }
  m = /^(\d{1,2})[-. /]([A-Za-z]{3})[a-z]*[-. /](\d{4})/.exec(s);
  if (m && MONTHS[m[2].toLowerCase()]) return `${m[3]}-${MONTHS[m[2].toLowerCase()]}-${m[1].padStart(2, '0')}T00:00:00Z`;
  m = /^(\d{2})[./-](\d{2})[./-](\d{4})/.exec(s);
  if (m) return `${m[3]}-${m[2]}-${m[1]}T00:00:00Z`;
  const t = Date.parse(s);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString().replace('.000Z', 'Z');
}

/** "whois.netim.com", from "http://whois.netim.com/" or "whois.netim.com:43". */
export function hostOf(v: string | undefined): string | undefined {
  if (!v) return undefined;
  const h = v.trim().replace(/^[a-z]+:\/\//i, '').replace(/[/:].*$/, '').toLowerCase();
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(h) ? h : undefined;
}

const NOT_FOUND =
  /^\s*[%#]*\s*(no match( for)?|not found|no data found|no entries found|no object found|domain not found|nothing found|the queried object does not exist|object does not exist|no information available|domain (name )?(is )?(available|free)|status:\s*(free|available))\b/im;
const RATE_LIMITED = /(limit exceeded|too many (requests|queries)|rate limit|query rate|quota exceeded|exceeded the maximum|try again later|temporarily blocked|access denied)/i;

const KEYS = {
  created: ['creation date', 'created', 'created on', 'created date', 'registered on', 'registration time', 'registration date', 'domain registration date', 'registered', 'domain create date', 'record created', 'domain created'],
  updated: ['updated date', 'last updated', 'last-update', 'last update', 'last modified', 'last-modified', 'modified', 'changed', 'updated', 'domain last updated date', 'last updated on'],
  expiresRegistry: ['registry expiry date', 'registry expiration date', 'expiry date', 'expiration date', 'expires', 'expires on', 'expire date', 'expiration time', 'paid-till', 'renewal date', 'domain expiration date', 'valid until', 'expiry', 'registrar registration expiration date'],
  expiresRegistrar: ['registrar registration expiration date', 'registry expiry date', 'registry expiration date', 'expiry date', 'expiration date', 'expires', 'expires on', 'expire date', 'expiration time', 'paid-till', 'renewal date', 'domain expiration date', 'valid until', 'expiry'],
  registrar: ['registrar', 'sponsoring registrar', 'registrar name', 'registrar organization'],
  ianaId: ['registrar iana id', 'sponsoring registrar iana id', 'registrar iana'],
  registrarUrl: ['registrar url', 'referral url', 'registrar website'],
  whoisServer: ['registrar whois server', 'whois server'],
  abuse: ['registrar abuse contact email', 'abuse contact email'],
  reseller: ['reseller', 'reseller name'],
  status: ['domain status', 'status', 'state', 'domain state', 'eppstatus', 'epp status'],
  nameservers: ['name server', 'nameserver', 'name servers', 'nameservers', 'nserver', 'host name'],
  dnssec: ['dnssec', 'dnssec signed', 'signed'],
};

const ROLE_PREFIX: Record<ContactRole, string[]> = {
  registrant: ['registrant'],
  admin: ['admin', 'administrative', 'administrative contact'],
  tech: ['tech', 'technical', 'technical contact'],
};

export function parseDnssec(v: string | undefined): boolean | undefined {
  if (!v) return undefined;
  if (/^(signed ?delegation|signed|yes|true|active)\b/i.test(v.trim())) return true;
  if (/^(unsigned|no|false|inactive|not signed)\b/i.test(v.trim())) return false;
  return undefined;
}

function nameserver(v: string): string | undefined {
  const h = v.trim().split(/[\s[,]+/)[0]?.toLowerCase().replace(/\.$/, '');
  return h && /^[a-z0-9.-]+\.[a-z0-9-]{2,}$/i.test(h) ? h : undefined;
}

function buildContact(role: ContactRole, name?: string, org?: string, emailRaw?: string, urlField?: string, anonymous = false): Contact | undefined {
  if (name === undefined && org === undefined && emailRaw === undefined && !urlField && !anonymous) return undefined;
  const c: Contact = { role, redacted: [] };
  const e = emailOrForm(emailRaw);
  if (anonymous) {
    c.redacted.push('name', 'org', 'email');
  } else {
    if (name !== undefined && name.trim()) (isPlaceholder(name) ? c.redacted.push('name') : (c.name = name.trim()));
    if (org !== undefined && org.trim()) {
      if (isPrivacyOrg(org) && !/redacted/i.test(org)) {
        c.org = org.trim();
        c.privacyService = true;
      } else if (isPlaceholder(org)) c.redacted.push('org');
      else c.org = org.trim();
    }
    if (e.email) c.email = e.email;
    else if (e.hidden) c.redacted.push('email');
  }
  const url = e.contactUrl ?? (urlField?.match(/https?:\/\/\S+/)?.[0]);
  if (url) c.contactUrl = url;
  return c;
}

function genericContacts(m: Multi): Contact[] {
  const out: Contact[] = [];
  for (const role of Object.keys(ROLE_PREFIX) as ContactRole[]) {
    const pick = (fields: string[]) => {
      for (const p of ROLE_PREFIX[role]) {
        for (const f of fields) {
          const v = m.get(`${p} ${f}`);
          if (v) return v[0] ?? '';
        }
      }
      return undefined;
    };
    const c = buildContact(role, pick(['name', 'contact name']), pick(['organization', 'organisation', 'org', 'contact organization']), pick(['email', 'e-mail', 'contact email']), pick(['contact url', 'contact form', 'web form']));
    if (c) out.push(c);
  }
  return out;
}

/** Afnic and other RPSL-like answers: a domain block, then blocks per handle. */
function rpslBlocks(text: string): Multi[] {
  return text
    .replace(/\r\n?/g, '\n')
    .split(/\n\s*\n/)
    .map((b) => multi(keyValues(b)))
    .filter((b) => b.size > 0);
}

function rpslContacts(blocks: Multi[], domainBlock: Multi): Contact[] {
  const refs: [ContactRole, string][] = [
    ['registrant', 'holder-c'],
    ['admin', 'admin-c'],
    ['tech', 'tech-c'],
  ];
  const out: Contact[] = [];
  for (const [role, key] of refs) {
    const handle = domainBlock.get(key)?.[0];
    if (!handle) continue;
    const b = blocks.find((x) => x.get('nic-hdl')?.[0]?.toLowerCase() === handle.toLowerCase());
    if (!b) continue;
    const anonymous = /^yes$/i.test(b.get('anonymous')?.[0] ?? '');
    const isOrg = /organi[sz]ation/i.test(b.get('type')?.[0] ?? '');
    const label = b.get('contact')?.[0] ?? b.get('person')?.[0] ?? b.get('name')?.[0];
    const c = buildContact(role, isOrg ? undefined : label, isOrg ? label : b.get('org')?.[0], b.get('e-mail')?.[0] ?? b.get('email')?.[0], undefined, anonymous);
    if (c) out.push(c);
  }
  return out;
}

export function parseWhoisText(text: string, party: Party): ParsedWhois {
  const kvs = keyValues(text);
  const m = multi(kvs);
  const rpsl = m.has('nic-hdl') || m.has('holder-c');
  const blocks = rpsl ? rpslBlocks(text) : [];
  // Afnic: the first "registrar:" is the domain's, the domain block holds dates and statuses
  const dom = rpsl ? blocks.find((b) => b.has('domain')) ?? m : m;
  const registrarBlock = rpsl ? blocks.find((b) => b.has('registrar') && (b.has('website') || b.has('registered')) && !b.has('domain')) : undefined;
  const statusRaw = rpsl ? all(dom, ['eppstatus']) : all(m, KEYS.status);
  const registryStatus = rpsl ? all(dom, ['status']).map((s) => s.trim()).filter(Boolean) : [];
  const hold = rpsl ? dom.get('hold')?.[0] : undefined;
  if (hold && /^yes$/i.test(hold)) registryStatus.push('HOLD');
  const nsKeys = rpsl ? ['nserver'] : KEYS.nameservers;
  const nameservers = [...new Set(all(m, nsKeys).map(nameserver).filter((x): x is string => !!x))];
  const dnssecRpsl = rpsl ? (m.has('key1-tag') || m.has('ds-rdata') ? true : undefined) : undefined;
  const registrarName = first(dom, KEYS.registrar);
  const registrar = {
    name: registrarName,
    ianaId: first(m, KEYS.ianaId),
    url: first(m, KEYS.registrarUrl) ?? registrarBlock?.get('website')?.[0],
    whoisServer: hostOf(first(m, KEYS.whoisServer)),
    abuseEmail: first(m, KEYS.abuse),
  };
  const hasRegistrar = Object.values(registrar).some(Boolean);
  const body = text.replace(/^\s*[%#].*$/gm, '').trim();
  const reseller = first(m, KEYS.reseller);
  return {
    created: parseWhoisDate(first(dom, KEYS.created)),
    updated: parseWhoisDate(first(dom, KEYS.updated)),
    expires: parseWhoisDate(first(dom, party === 'registrar' ? KEYS.expiresRegistrar : KEYS.expiresRegistry)),
    status: normalizeStatuses(statusRaw),
    registryStatus,
    registrar: hasRegistrar ? registrar : undefined,
    reseller: reseller && !isPlaceholder(reseller) ? reseller : undefined,
    contacts: rpsl ? rpslContacts(blocks, dom) : genericContacts(m),
    nameservers,
    dnssec: dnssecRpsl ?? parseDnssec(first(m, KEYS.dnssec)),
    notFound: kvs.length < 3 && NOT_FOUND.test(text),
    rateLimited: kvs.length < 3 && RATE_LIMITED.test(body),
  };
}
