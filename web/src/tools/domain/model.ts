// Client mirror of the data returned by the domain tools (server/src/lib/email-auth/*.ts and
// server/src/tools/domain/*.ts). Only the fields the pages read are typed.
import { msg } from '../../lib/i18n';
import type { Finding, PassedCheck } from '../../lib/types';

export const SECTIONS = [
  { id: 'mx', title: msg('Serveurs MX') },
  { id: 'spf', title: msg('SPF') },
  { id: 'dkim', title: msg('DKIM') },
  { id: 'dmarc', title: msg('DMARC') },
  { id: 'bimi', title: msg('BIMI') },
  { id: 'mta-sts', title: msg('MTA-STS et TLS-RPT') },
  { id: 'dnssec', title: msg('DNSSEC') },
  { id: 'ns', title: msg('Serveurs de noms') },
  { id: 'soa', title: msg('SOA') },
  { id: 'caa', title: msg('CAA') },
  { id: 'blacklist', title: msg('Listes noires des MX') },
  { id: 'smtp', title: msg('Connexion SMTP aux MX') },
  { id: 'rdap', title: msg('Enregistrement du domaine') },
] as const;

export type SectionId = (typeof SECTIONS)[number]['id'];

export interface ScanSection {
  id: SectionId;
  title: string;
  status: 'ok' | 'info' | 'warning' | 'error' | 'unavailable';
  findings: Finding[];
  passed: PassedCheck[];
  unavailable?: { source: string; reason: string }[];
  data: unknown;
  ms: number;
}

export interface ScanData {
  domain: string;
  sections: ScanSection[];
  counts: Record<string, number>;
}

/* ---------- MX ---------- */
export interface MxHost {
  host: string;
  preference: number;
  ipv4: string[];
  ipv6: string[];
  cname?: string[];
  ipLiteral: boolean;
  privateIps: string[];
  error?: string;
}
export interface MxData {
  domain: string;
  rcode: string;
  hosts: MxHost[];
  nullMx: boolean;
  implicit?: string[];
}

/* ---------- SPF (subset) ---------- */
export interface SpfSummary {
  record?: string;
  records: string[];
  lookupCount: number;
  voidCount: number;
  lookupLimit: number;
  voidLimit: number;
  allQualifier?: string;
  providers: string[];
}

/* ---------- DKIM ---------- */
export interface DkimKey {
  selector: string;
  name: string;
  knownFor?: string[];
  record: string;
  cnames: string[];
  cnameProvider?: string;
  version?: string;
  keyType: string;
  bits?: number;
  hashAlgorithms?: string[];
  serviceTypes?: string[];
  flags: string[];
  testing: boolean;
  strictSubdomains: boolean;
  revoked: boolean;
  notes?: string;
  error?: string;
  ttl?: number;
  wildcard?: boolean;
}
export interface DkimData {
  domain: string;
  tried: number;
  selectorsTried: string[];
  keys: DkimKey[];
  other: { selector: string; record: string }[];
  errors: { selector: string; error: string }[];
  wildcard: boolean;
  limits: string[];
}

/* ---------- DMARC ---------- */
export type DmarcPolicy = 'none' | 'quarantine' | 'reject';
export interface DmarcTag {
  name: string;
  value: string;
  meaning: string;
  valid: boolean;
  error?: string;
  implicit?: boolean;
}
export interface DmarcReportUri {
  tag: 'rua' | 'ruf';
  uri: string;
  scheme: string;
  address?: string;
  domain?: string;
  maxSize?: string;
  external: boolean;
  authorized?: boolean;
  authorizationRecord?: string;
  error?: string;
}
export interface DmarcData {
  domain: string;
  orgDomain: string;
  foundAt?: string;
  inherited: boolean;
  record?: string;
  records: string[];
  tags: DmarcTag[];
  policy?: DmarcPolicy;
  effectivePolicy?: DmarcPolicy;
  subdomainPolicy?: DmarcPolicy;
  nonExistentPolicy?: DmarcPolicy;
  pct: number;
  alignment: { dkim: 'r' | 's'; spf: 'r' | 's' };
  reports: DmarcReportUri[];
  suggested?: string;
  plan: { record: string; when: string }[];
}

/* ---------- BIMI ---------- */
export interface SvgCheck {
  url: string;
  status?: number;
  contentType?: string;
  bytes?: number;
  sha256?: string;
  error?: string;
  baseProfile?: string;
  version?: string;
  title?: string;
  viewBox?: string;
  square?: boolean;
  problems: string[];
  warnings: string[];
  /** size and format advice among the warnings, already shown by the measured rows */
  sizeWarnings?: string[];
}
export interface VmcCert {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  san: string[];
  fingerprint256: string;
  ca: boolean;
}
export interface VmcCheck {
  url: string;
  status?: number;
  error?: string;
  certificates: VmcCert[];
  kind?: 'VMC' | 'CMC' | 'inconnu';
  markType?: string;
  markPolicy?: boolean;
  bimiEku?: boolean;
  logotype?: { found: boolean; sha256?: string; matchesSvg?: boolean };
  coversDomain?: boolean;
  chainLinked?: boolean;
  expired?: boolean;
  daysLeft?: number;
  problems: string[];
}
export interface BimiData {
  domain: string;
  selector: string;
  name: string;
  foundAt?: string;
  inherited: boolean;
  record?: string;
  records: string[];
  logoUrl?: string;
  authorityUrl?: string;
  declined: boolean;
  svg?: SvgCheck;
  vmc?: VmcCheck;
  dmarc?: { record?: string; policy?: DmarcPolicy; effectivePolicy?: DmarcPolicy; subdomainPolicy?: DmarcPolicy; pct: number; foundAt?: string };
  dmarcEligible?: boolean;
}

/* ---------- MTA-STS ---------- */
export interface MtaStsData {
  domain: string;
  record?: string;
  records: string[];
  id?: string;
  policyUrl: string;
  fetch?: { status?: number; contentType?: string; location?: string; ms?: number; error?: string; certError?: string; bytes?: number };
  policy?: { version?: string; mode?: string; mx: string[]; maxAge?: number; errors: string[]; raw: string };
  mx: { host: string; preference: number; covered: boolean | null }[];
  tlsrpt: { record?: string; records: string[]; rua: string[]; errors: string[] };
}

/* ---------- DNSSEC ---------- */
export interface DnskeyInfo {
  flags: number;
  protocol: number;
  algorithm: number;
  algorithmName: string;
  keyTag: number;
  ksk: boolean;
  revoked: boolean;
  bits?: number;
}
export interface DsInfo {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string;
  matches: number | null;
}
export interface RrsigInfo {
  typeCovered: string;
  algorithm: number;
  keyTag: number;
  signer: string;
  inception: string;
  expiration: string;
  current: boolean;
  expiresInHours: number;
  verified?: boolean;
  verifyError?: string;
}
export type ChainStatus = 'secure' | 'insecure' | 'bogus' | 'indeterminate';
export interface ZoneChain {
  zone: string;
  parent: string;
  ds: DsInfo[];
  dnskey: DnskeyInfo[];
  rrsig: RrsigInfo[];
  status: ChainStatus;
  problems: string[];
  servers: { parent?: string; zone?: string };
}
export interface DnssecData {
  domain: string;
  zone: string;
  chain: ZoneChain[];
  status: ChainStatus;
  nsec3?: { iterations: number; saltLength: number; algorithm: number };
}

/* ---------- SMTP ---------- */
export interface SmtpCert {
  subject?: string;
  altNames: string[];
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysLeft?: number;
  selfSigned: boolean;
  trusted: boolean;
  trustError?: string;
  nameMatches: boolean;
  nameError?: string;
}
export interface SmtpProbe {
  host: string;
  ip: string;
  port: number;
  status: 'ok' | 'timeout' | 'refused' | 'error';
  error?: string;
  connectMs?: number;
  bannerMs?: number;
  totalMs?: number;
  banner?: string;
  ehlo?: string[];
  extensions: string[];
  starttls: boolean;
  tls?: { ok: boolean; error?: string; protocol?: string; cipher?: string; ms?: number; cert?: SmtpCert; ehloAfter?: string[] };
  transcript: string[];
}
export interface SmtpData {
  domain: string;
  port25: { reachable: boolean; detail: string };
  mx: { host: string; preference: number; ips: string[] }[];
  probes: SmtpProbe[];
}

/* ---------- RDAP ---------- */
export interface RdapData {
  domain: string;
  queried: string;
  tld: string;
  server?: string;
  url?: string;
  registrar?: { name?: string; ianaId?: string; url?: string; abuseEmail?: string };
  status: string[];
  events: { action: string; date: string }[];
  created?: string;
  updated?: string;
  expires?: string;
  ageDays?: number;
  expiresInDays?: number;
  nameservers: string[];
  dnssecDelegated?: boolean;
}

/* ---------- infrastructure (scan only) ---------- */
export interface AuthServer {
  ns: string;
  ip: string;
  rcode: string;
  aa?: boolean;
  rtt?: number;
  serial?: number;
}
export interface Authoritative {
  zone: string;
  servers: AuthServer[];
  consistent?: boolean;
  serials?: number[];
  serialsConsistent?: boolean;
  lame?: string[];
}
export interface NsData {
  zone: string;
  parent: { name: string; ips: string[] }[];
  child: string[];
  networks: string[];
  authoritative?: Authoritative;
}
export interface SoaData {
  zone: string;
  record?: string;
  authoritative?: Authoritative;
}
export interface CaaData {
  foundAt?: string;
  records: { flags: number; tag: string; value: string }[];
  issuers: string[];
  wildcardIssuers: string[];
  iodef: string[];
}
export interface DnsblHit {
  zone: string;
  name: string;
  type: string;
  weight?: string;
  target: string;
  status: string;
  codes: string[];
  delistUrl?: string;
  meaning?: string;
}
export interface BlacklistData {
  ips: string[];
  domains: string[];
  listsQueried: number;
  listed: DnsblHit[];
  refused: DnsblHit[];
  errors: number;
}
