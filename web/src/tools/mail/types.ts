// Client mirror of the mail test responses (server/src/tools/mail/index.ts and
// server/src/mail/analyze/*). Only the fields the interface reads are typed; the rest stays open.
import type { CheckResult, Finding } from '../../lib/types';

export type Via = 'smtp' | 'imap' | 'upload';
export type MessageStatus = 'received' | 'analyzing' | 'done' | 'error';

export interface AddressInfo {
  id: string;
  address: string;
  label: string | null;
  createdAt: string;
  expiresAt: string;
  expired: boolean;
  ttlHours?: number;
}

export interface MessageSummary {
  id: string;
  addressId: string;
  receivedAt: string;
  via: Via;
  status: MessageStatus;
  score: number | null;
  clientIp: string | null;
  clientPtr: string | null;
  helo: string | null;
  mailFrom: string | null;
  rcptTo: string[];
  tls: { protocol?: string; cipher?: string } | null;
  from: string | null;
  fromDomain: string | null;
  subject: string | null;
  size: number | null;
}

export interface MailStatus {
  domain: string;
  addressTtlHours: number;
  smtp: { listening: boolean; host?: string; port?: number; tls?: string };
  imap: { enabled: boolean; connected: boolean; processed: number; skipped: number; lastError?: string; lastConnectAt?: string };
  spamd: { host: string; port: number; reachable: boolean };
}

export interface Hop {
  index: number;
  from?: string;
  fromPtr?: string;
  ip?: string;
  helo?: string;
  by?: string;
  with?: string;
  tls: boolean | null;
  tlsDetail?: string;
  for?: string;
  at?: string;
  delaySec?: number | null;
  raw: string;
}

export interface SectionSummary {
  id: string;
  title: string;
  lost: number;
  status: 'ok' | 'warning' | 'error' | 'info';
  findings: string[];
  passed: string[];
}

export interface DkimSig {
  domain: string;
  selector: string;
  algo?: string;
  result: string;
  comment?: string;
  keyBits?: number;
  signedHeaders: string[];
  testing: boolean;
  aligned: 'strict' | 'relaxed' | false;
}

export interface AuthData {
  spf?: {
    result?: string;
    domain?: string;
    identity?: string;
    comment?: string;
    record?: string;
    lookups?: { limit: number; count: number; void: number };
    helo?: { result?: string; comment?: string };
  };
  dkim?: DkimSig[];
  dmarc?: { result?: string; policy?: string; p?: string; record?: string; policyDomain?: string; policyRecordName?: string };
  alignment?: {
    fromDomain?: string;
    mode: { spf: 'relaxed' | 'strict'; dkim: 'relaxed' | 'strict' };
    spf: { domain?: string; pass: boolean; aligned: 'strict' | 'relaxed' | false; alignedUnderMode: boolean };
    dkim: { domain: string; selector: string; pass: boolean; aligned: 'strict' | 'relaxed' | false; alignedUnderMode: boolean }[];
    aligned: boolean;
  };
  arc?: { result: string; comment?: string; instance: number };
  bimi?: { result: string; comment?: string; location?: string; authority?: string; record?: string };
  authenticationResults?: string;
}

export interface InfraData {
  ip?: string;
  ipSource?: 'smtp' | 'received' | 'none';
  private?: boolean;
  ptr?: string[];
  fcrdns?: boolean;
  fcrdnsName?: string;
  helo?: string;
  tls?: { used: boolean | null; protocol?: string; cipher?: string; source: string };
  fromDomain?: { domain: string; nx: boolean; nullMx: boolean; canReceive: boolean };
}

export interface LinkCheck {
  status?: number;
  finalUrl?: string;
  redirects: string[];
  contentType?: string;
  bytes?: number;
  error?: string;
  /** the failure in plain words, written by the server */
  reason?: string;
  ms: number;
}
export interface LinkInfo {
  url: string;
  text?: string;
  source: 'html' | 'text';
  scheme: string;
  host?: string;
  shortener: boolean;
  mismatch?: string;
  check?: LinkCheck;
}
export interface ImageInfo {
  src: string;
  alt?: string;
  host?: string;
  width?: string;
  height?: string;
  tracking: boolean;
  check?: LinkCheck;
}

export interface SpamRule {
  score: number;
  name: string;
  description: string;
}
export interface SpamData {
  available: boolean;
  error?: string;
  score?: number;
  threshold?: number;
  isSpam?: boolean;
  rules?: SpamRule[];
  ms?: number;
}

export interface BlacklistHit {
  zone: string;
  name: string;
  target: string;
  type: 'ip' | 'domain';
}
export interface BlacklistData {
  source?: string;
  lists?: number;
  checked: number;
  listed: (BlacklistHit & { codes?: string[]; meaning?: string; delistUrl?: string })[];
  refused: (BlacklistHit & { meaning?: string })[];
  errors: { zone: string; target: string; error: string }[];
  clean: BlacklistHit[];
}

export interface UnsubscribeData {
  isBulk?: boolean;
  listUnsubscribe?: string;
  listUnsubscribePost?: string;
  uris?: string[];
  oneClick?: boolean;
  coveredByDkim?: boolean;
}

export type ProviderId = 'gmail' | 'yahoo' | 'microsoft';
export interface Requirement {
  id: string;
  label: string;
  providers: ProviderId[];
  scope: 'bulk' | 'all';
  ok: boolean | null;
  detail?: string;
  sources: string[];
  situation?: string;
}

export interface AttachmentInfo {
  filename?: string;
  contentType?: string;
  size?: number;
  extension?: string;
}

export interface MailReportData {
  via: Via;
  receivedAt: string;
  envelope: {
    clientIp?: string;
    ipSource: 'smtp' | 'received' | 'none';
    ipReason?: string;
    helo?: string;
    mailFrom?: string;
    rcptTo: string[];
    tls?: { used: boolean | null; protocol?: string; cipher?: string; source: string };
  };
  message: {
    from?: string;
    fromName?: string;
    fromDomain?: string;
    subject?: string;
    date?: string;
    messageId?: string;
    to?: string;
    replyTo?: string;
    size: number;
  };
  provider?: { key: string; name: string; confidence?: number; evidence?: string[] };
  isBulk: boolean;
  bulkReasons: string[];
  limits: { check: string; reason: string }[];
  hops: Hop[];
  sections: SectionSummary[];
  scoring: { total: number; lost: number; lines: { id: string; title: string; section: string; penalty: number }[] };
  auth?: AuthData;
  infrastructure?: InfraData;
  headers?: Record<string, unknown>;
  content?: { size?: number; visibleWords?: number; textHtmlSimilarity?: number; hasText?: boolean; hasHtml?: boolean; images?: number };
  preview?: { text?: string; html?: string; htmlTruncated?: boolean; inline?: { cid?: string; type?: string; dataUri: string }[] };
  attachments?: AttachmentInfo[];
  links?: LinkInfo[];
  images?: ImageInfo[];
  spamassassin?: SpamData;
  blacklists?: BlacklistData;
  unsubscribe?: UnsubscribeData;
  compliance?: { isBulk: boolean; bulkReasons: string[]; requirements: Requirement[] };
  /** the two indicators of the report (server/src/mail/analyze/impact.ts), absent from reports made before 2026-11-11 */
  indicators?: Indicators;
}

/** Mirror of server/src/mail/analyze/impact.ts: what one axis costs, counted by effect on delivery. */
export interface AxisSummary {
  lost: number;
  blocking: number;
  spam: number;
  advice: number;
  status: 'blocking' | 'spam' | 'advice' | 'ok';
}
export interface Indicators {
  verdict: 'blocking' | 'spam' | 'ok';
  sender: AxisSummary;
  message: AxisSummary;
}

export type MailReport = CheckResult<MailReportData>;
/** What the server stores when an analysis failed. */
export type StoredReport = MailReport | { error: string };

export const isReport = (r: StoredReport | null | undefined): r is MailReport => !!r && 'findings' in r;

export type MailFinding = Finding & { section?: string };

export interface CompareResult {
  a: MessageSummary & { score: number | null; measuredAt: string };
  b: MessageSummary & { score: number | null; measuredAt: string };
  sameSender: boolean;
  scoreDelta: number;
  added: { id: string; title: string; severity: string; penalty: number; family: string }[];
  removed: { id: string; title: string; severity: string; penalty: number; family: string }[];
  changed: { id: string; title: string; before: { penalty: number; severity: string }; after: { penalty: number; severity: string } }[];
  unchanged: string[];
  passedAdded: string[];
  passedRemoved: string[];
}

export interface StepState {
  label: string;
  state: 'start' | 'done' | 'skipped' | 'error';
  detail?: string;
}
