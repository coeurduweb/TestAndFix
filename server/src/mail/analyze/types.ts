// Shapes shared by the analysis steps.
import type { Config } from '../../config.js';
import type { SpamdOptions } from '../spamd.js';
import type { Collector } from './collect.js';
import type { ParsedRaw, MimePart, RawHeader } from '../mime.js';
import type { Hop } from '../received.js';
import type { DetectedProvider } from '../../lib/provider.js';

/** dns.promises.resolve-like function: arrays of records, Node error codes on failure. */
export type NodeResolver = (name: string, rrtype?: string) => Promise<unknown[]>;

export interface FetchResult {
  status: number;
  headers: Record<string, string>;
  bytes?: number;
}
/** HTTP fetch of one URL without following redirects (the analyzer follows them). */
export type Fetcher = (url: string, method: 'HEAD' | 'GET') => Promise<FetchResult>;

export type Via = 'smtp' | 'imap' | 'upload';

export interface AnalyzeInput {
  raw: Buffer;
  via: Via;
  /** IP of the client that connected to our SMTP server (smtp), or none. */
  clientIp?: string;
  helo?: string;
  mailFrom?: string;
  rcptTo?: string[];
  /** smtp: the session; source 'relay' = TLS of the original connection read from the relay's Received */
  tls?: { protocol?: string; cipher?: string; used?: boolean; source?: 'smtp' | 'relay'; ipSource?: 'smtp' | 'xforward' } | null;
  receivedAt?: Date;
  /** Domains of the mailbox host (IMAP), used to find the origin hop. */
  receiverDomains?: string[];
}

export interface AnalyzeDeps {
  config: Config;
  resolver: NodeResolver;
  /** false: SpamAssassin is not queried (tests, or disabled). */
  spamd?: SpamdOptions | false;
  fetcher?: Fetcher | false;
  /** false: no DNSBL lookups. */
  dnsbl?: boolean;
  /** Fresh resolver for each DNSBL lookup (production: one resolution session per lookup). */
  dnsblResolver?: () => NodeResolver;
  progress?: (step: string, label: string, state: 'start' | 'done' | 'skipped' | 'error', detail?: string) => void;
  now?: () => Date;
}

/** Everything the steps read, built once at the start of the analysis. */
export interface MessageFacts {
  input: AnalyzeInput;
  parsed: ParsedRaw;
  headers: RawHeader[];
  text?: MimePart;
  html?: MimePart;
  attachments: MimePart[];
  inline: MimePart[];
  fromAddress?: string;
  fromName?: string;
  fromDomain?: string;
  fromCount: number;
  envelopeFrom?: string;
  envelopeDomain?: string;
  /** false: imported message without Return-Path, the MAIL FROM is unknown */
  envelopeKnown: boolean;
  subject?: string;
  hops: Hop[];
  /** the IP whose reputation and DNS are checked, and where it comes from */
  ip?: string;
  ipSource: 'smtp' | 'xforward' | 'received' | 'none';
  ipReason?: string;
  helo?: string;
  tls?: { used: boolean | null; protocol?: string; cipher?: string; source: 'smtp' | 'relay' | 'received' | 'none' };
  isBulk: boolean;
  bulkReasons: string[];
  provider?: DetectedProvider;
  providers: DetectedProvider[];
  /** only the header block was provided (pasted headers): body checks are skipped */
  headersOnly: boolean;
  receivedAt: Date;
}

export interface StepContext {
  facts: MessageFacts;
  deps: AnalyzeDeps;
  c: Collector;
  data: Record<string, unknown>;
}
