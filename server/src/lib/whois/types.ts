// Shapes of the Whois tool: what each party (registry, registrar) said, how it was obtained, and
// the merged view shown first.
import type { StatusInfo } from './epp.js';

export type Party = 'registry' | 'registrar';
export type Protocol = 'rdap' | 'whois';

export type ContactRole = 'registrant' | 'admin' | 'tech';

export interface Contact {
  role: ContactRole;
  name?: string;
  org?: string;
  email?: string;
  /** A contact form given instead of an address (RFC 9537 replacementValue, "contact URL" lines). */
  contactUrl?: string;
  /** Fields hidden by the server (redaction, placeholder, anonymised handle). */
  redacted: ('name' | 'org' | 'email')[];
  /** The organisation is a privacy or proxy service, not the real holder. */
  privacyService?: boolean;
}

export interface PartyRecord {
  party: Party;
  protocol: Protocol;
  /** Host that answered (rdap.verisign.com, whois.nic.fr). */
  server: string;
  /** RDAP URL read, for links. */
  url?: string;
  created?: string;
  updated?: string;
  expires?: string;
  /** Canonical EPP codes (and RDAP or registry values) from the status fields. */
  status: string[];
  /** Registry statuses outside EPP (AFNIC "status: ACTIVE"). */
  registryStatus: string[];
  registrar?: { name?: string; ianaId?: string; url?: string; whoisServer?: string; rdapBase?: string; abuseEmail?: string };
  reseller?: string;
  contacts: Contact[];
  nameservers: string[];
  dnssec?: boolean;
  /** Link to the registrar's own RDAP answer (ICANN RDAP TIG §3.2, rel "related"). */
  registrarRdapUrl?: string;
  /** Raw answer (WHOIS text, RDAP JSON), capped. */
  raw: string;
  rawTruncated?: boolean;
}

export type AttemptStatus = 'ok' | 'not_found' | 'error' | 'rate_limited' | 'unsupported';

export interface Attempt {
  party: Party;
  protocol: Protocol;
  server: string;
  status: AttemptStatus;
  /** Why it failed, in French, without the domain. */
  reason?: string;
  ms?: number;
}

export interface Divergence {
  field: 'created' | 'updated' | 'expires' | 'status' | 'registrar' | 'ianaId' | 'nameservers' | 'dnssec';
  label: string;
  registry: string;
  registrar: string;
  /** "updated" differs often for a good reason (the two databases change at different times). */
  expected?: boolean;
}

export interface WhoisMerged {
  /** Each status with its meaning (epp.ts), so the page does not keep its own copy. */
  statusDetails: StatusInfo[];
  created?: string;
  updated?: string;
  expires?: string;
  ageDays?: number;
  expiresInDays?: number;
  status: string[];
  registryStatus: string[];
  registrar?: PartyRecord['registrar'];
  reseller?: string;
  contacts: Contact[];
  nameservers: string[];
  dnssec?: boolean;
}

export interface WhoisReport {
  /** Name as typed, ASCII. */
  domain: string;
  /** Registrable name actually queried. */
  queried: string;
  /** Same name for display (IDN in Unicode). */
  unicode: string;
  tld: string;
  registry?: PartyRecord;
  registrar?: PartyRecord;
  /** Every source tried, in order. */
  attempts: Attempt[];
  merged: WhoisMerged;
  divergences: Divergence[];
  /** The registry says the name is not registered. */
  notFound?: boolean;
  /** The registry names no registrar server to ask (DENIC answers for .de give none). */
  registrarNotAnnounced?: boolean;
  /** The registrar's servers answered but do not publish this name (common outside gTLDs, which ICANN's RDAP obligations cover). */
  registrarUnknown?: boolean;
  /** IPv4 addresses (A records) of the queried name, from DNS, not from Whois: [] when the name has none,
   *  absent when DNS did not answer. Asked by the user on 2026-11-12. */
  a?: string[];
  /** Set when served from the short politeness cache (ISO time of the original lookup). */
  cachedAt?: string;
  lookedUpAt: string;
}

/** One line of the multi-domain table and its CSV export. */
export interface WhoisRow {
  domain: string;
  unicode: string;
  ok: boolean;
  notFound?: boolean;
  error?: string;
  registrar?: string;
  ianaId?: string;
  reseller?: string;
  created?: string;
  updated?: string;
  expires?: string;
  ageDays?: number;
  expiresInDays?: number;
  status: string[];
  registryStatus: string[];
  nameservers: string[];
  dnssec?: boolean;
  /** A records, see WhoisReport.a. */
  a?: string[];
  contacts: Contact[];
  registrySource?: string;
  registrarSource?: string;
  divergences: Divergence[];
  cachedAt?: string;
}
