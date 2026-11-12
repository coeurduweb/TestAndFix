// Reception to report: store the raw message, announce it, analyse it (a few at a time),
// publish progress and the report, keep the report in mail_messages.
import { nodeStyleResolver } from '../dns/iterative.js';
import { safeGet } from '../lib/net.js';
import type { ToolContext } from '../tools/types.js';
import type { ResolveSession } from '../dns/iterative.js';
import type { SpamdOptions } from './spamd.js';
import { analyzeMessage, type MailReport } from './analyze/index.js';
import type { Fetcher, NodeResolver, Via } from './analyze/types.js';
import { mailBus } from './events.js';
import { decodeWords, firstHeader, parseRaw } from './mime.js';
import { domainOf, firstAddress } from './analyze/headers.js';
import { getAddress, getMessage, insertMessage, newMessageId, updateMessage, type MessageMeta, type MessageRow } from './store.js';
import { now } from '../lib/time.js';
import { hasLangContext, withLang } from '../i18n.js';
import { isSelfTestAddress, selfTestReceived } from './selftest.js';

export interface MailServiceOptions {
  /** spamd to use; false disables SpamAssassin. Default: config.spamd. */
  spamd?: SpamdOptions | false;
  /** Builds the link fetcher for one analysis; false disables link visits. Default: safeGet. */
  fetcher?: ((session: ResolveSession) => Fetcher) | false;
  dnsbl?: boolean;
  /** Resolver for one analysis. Default: iterative resolution, a new session per analysis. */
  resolver?: (session: ResolveSession) => NodeResolver;
  /** Analyses running at the same time. */
  concurrency?: number;
}

export interface MessageSummary {
  id: string;
  addressId: string;
  receivedAt: string;
  via: Via;
  status: MessageRow['status'];
  score: number | null;
  clientIp: string | null;
  clientPtr: string | null;
  helo: string | null;
  mailFrom: string | null;
  rcptTo: string[];
  /** TLS of the connection, and how the client was known (smtp: our socket, xforward: the relay) */
  tls: { protocol?: string; cipher?: string; used?: boolean; source?: 'smtp' | 'relay'; ipSource?: 'smtp' | 'xforward' } | null;
  from: string | null;
  fromDomain: string | null;
  subject: string | null;
  size: number | null;
}

export function summary(m: MessageMeta): MessageSummary {
  let tls: MessageSummary['tls'] = null;
  try {
    tls = m.tls ? JSON.parse(m.tls) : null;
  } catch {
    tls = null;
  }
  return {
    id: m.id,
    addressId: m.address_id,
    receivedAt: new Date(m.created_at).toISOString(),
    via: m.via,
    status: m.status,
    score: m.score,
    clientIp: m.client_ip,
    clientPtr: m.client_ptr,
    helo: m.helo,
    mailFrom: m.mail_from,
    rcptTo: m.rcpt_to ? m.rcpt_to.split(',').filter(Boolean) : [],
    tls,
    from: m.from_addr,
    fromDomain: m.from_domain,
    subject: m.subject,
    size: m.size,
  };
}

/**
 * Bound every lookup in time. A lookup that never settles (seen with parallel lookups whose name
 * servers depend on each other) must not hold the whole analysis.
 */
export function withDeadline(resolver: NodeResolver, ms = 8000): NodeResolver {
  return (name, type) => {
    let t: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_r, rej) => {
      t = setTimeout(() => rej(Object.assign(new Error(`query ETIMEOUT ${name}`), { code: 'ETIMEOUT' })), ms);
    });
    return Promise.race([resolver(name, type), timeout]).finally(() => clearTimeout(t));
  };
}

/**
 * One more try with a new resolution session when a lookup times out: the name servers are tried
 * in a random order, so the second walk usually takes another path.
 */
export function retryOnTimeout(make: () => NodeResolver): NodeResolver {
  let current = make();
  return async (name, type) => {
    try {
      return await current(name, type);
    } catch (e) {
      if ((e as { code?: string }).code !== 'ETIMEOUT') throw e;
      current = make();
      return current(name, type);
    }
  };
}

export function safeFetcher(session: ResolveSession): Fetcher {
  return async (url, method) => {
    const r = await safeGet(url, { method, session, maxBytes: method === 'GET' ? 256 * 1024 : 1 });
    return { status: r.status, headers: r.headers, bytes: r.truncated ? undefined : r.body.length };
  };
}

export interface IngestInput {
  via: Via;
  addressId: string;
  raw: Buffer;
  clientIp?: string;
  clientPtr?: string;
  helo?: string;
  mailFrom?: string;
  rcptTo?: string[];
  tls?: { protocol?: string; cipher?: string; used?: boolean; source?: 'smtp' | 'relay'; ipSource?: 'smtp' | 'xforward' } | null;
  receiverDomains?: string[];
  /**
   * Notebook of the message. Upload: the request's. Omitted (SMTP, IMAP): the notebook of the
   * recipient address, null when the address is unknown or has none.
   */
  ownerId?: string | null;
}

export class MailService {
  private running = 0;
  private queue: (() => void)[] = [];
  private pending = new Map<string, Promise<MailReport | undefined>>();
  /** IMAP context per message (receiver domains), kept for reanalysis during this process. */
  private receiver = new Map<string, string[]>();

  constructor(
    private ctx: ToolContext,
    public opts: MailServiceOptions = {},
  ) {}

  private async slot<T>(fn: () => Promise<T>): Promise<T> {
    const max = this.opts.concurrency ?? 2;
    if (this.running >= max) await new Promise<void>((r) => this.queue.push(r));
    this.running++;
    try {
      return await fn();
    } finally {
      this.running--;
      this.queue.shift()?.();
    }
  }

  /** Store a received message, announce it and start its analysis. */
  ingest(input: IngestInput): { id: string; done: Promise<MailReport | undefined> } {
    const id = newMessageId();
    const address = getAddress(this.ctx.db, input.addressId);
    if (isSelfTestAddress(address)) {
      // reception self-test (selftest.ts): stored without a notebook, never analysed nor announced
      insertMessage(this.ctx.db, {
        owner_id: null,
        id,
        address_id: input.addressId,
        created_at: now(),
        via: input.via,
        client_ip: null,
        client_ptr: null,
        helo: null,
        mail_from: null,
        rcpt_to: null,
        tls: null,
        from_addr: null,
        from_domain: null,
        subject: null,
        size: input.raw.length,
        raw: input.raw,
        status: 'done',
      });
      selfTestReceived(input.addressId);
      return { id, done: Promise.resolve(undefined) };
    }
    const parsed = parseRaw(input.raw);
    const from = firstAddress(firstHeader(parsed.headers, 'from'))?.toLowerCase();
    const subjectRaw = firstHeader(parsed.headers, 'subject');
    const ownerId = input.ownerId !== undefined ? input.ownerId : (address?.owner_id ?? null);
    insertMessage(this.ctx.db, {
      owner_id: ownerId,
      id,
      address_id: input.addressId,
      created_at: now(),
      via: input.via,
      client_ip: input.clientIp ?? null,
      client_ptr: input.clientPtr ?? null,
      helo: input.helo ?? null,
      mail_from: input.mailFrom ?? null,
      rcpt_to: (input.rcptTo ?? []).join(',') || null,
      tls: input.tls ? JSON.stringify(input.tls) : null,
      from_addr: from ?? null,
      from_domain: domainOf(from) ?? null,
      subject: subjectRaw !== undefined ? decodeWords(subjectRaw).text.slice(0, 500) : null,
      size: input.raw.length,
      raw: input.raw,
      status: 'received',
    });
    if (input.receiverDomains?.length) this.receiver.set(id, input.receiverDomains);
    const row = getMessage(this.ctx.db, id)!;
    mailBus.publish({ type: 'message', addressId: input.addressId, messageId: id, ownerId, data: summary(row) });
    const done = this.analyze(id);
    return { id, done };
  }

  /** Analyse (or re-analyse with today's DNS) a stored message. */
  analyze(id: string): Promise<MailReport | undefined> {
    const inflight = this.pending.get(id);
    if (inflight) return inflight;
    // received by SMTP (no request): the report is written in the language of the address's interface
    const lang = hasLangContext() ? undefined : getAddress(this.ctx.db, getMessage(this.ctx.db, id)?.address_id ?? '')?.lang;
    const run = () => (lang ? withLang(lang, () => this.run(id)) : this.run(id));
    const p = this.slot(run).finally(() => this.pending.delete(id));
    this.pending.set(id, p);
    return p;
  }

  private async run(id: string): Promise<MailReport | undefined> {
    const row = getMessage(this.ctx.db, id);
    if (!row) return undefined;
    const previous = row.report ? (JSON.parse(row.report) as MailReport) : undefined;
    updateMessage(this.ctx.db, id, { status: 'analyzing' });
    const session = this.ctx.dns();
    const resolver = this.opts.resolver ? this.opts.resolver(session) : withDeadline(nodeStyleResolver(session));
    const fetcher = this.opts.fetcher === false ? false : (this.opts.fetcher ?? safeFetcher)(session);
    const publish = (step: string, label: string, state: 'start' | 'done' | 'skipped' | 'error', detail?: string) =>
      mailBus.publish({ type: 'progress', addressId: row.address_id, messageId: id, ownerId: row.owner_id, data: { step, label, state, detail } });
    try {
      const report = await analyzeMessage(
        {
          raw: Buffer.from(row.raw),
          via: row.via,
          clientIp: row.client_ip ?? undefined,
          helo: row.helo ?? undefined,
          mailFrom: row.mail_from ?? undefined,
          rcptTo: row.rcpt_to ? row.rcpt_to.split(',') : [],
          tls: row.tls ? JSON.parse(row.tls) : row.via === 'smtp' ? null : undefined,
          receivedAt: new Date(row.created_at),
          receiverDomains: this.receiver.get(id) ?? (previous?.data?.receiverDomains as string[] | undefined),
        },
        {
          config: this.ctx.config,
          resolver,
          spamd: this.opts.spamd === undefined ? { host: this.ctx.config.spamd.host, port: this.ctx.config.spamd.port, timeoutMs: 30000 } : this.opts.spamd,
          fetcher,
          dnsbl: this.opts.dnsbl,
          dnsblResolver: this.opts.resolver ? undefined : () => retryOnTimeout(() => withDeadline(nodeStyleResolver(this.ctx.dns({ timeoutMs: 2000 })), 4000)),
          progress: publish,
        },
      );
      report.resultId = id;
      const rd = this.receiver.get(id) ?? (previous?.data?.receiverDomains as string[] | undefined);
      if (rd) report.data.receiverDomains = rd;
      // kept in the report from now on: a re-analysis reads it there (code review of 2026-11-12: the map only grew)
      this.receiver.delete(id);
      if (previous) report.data.previous = { score: previous.score, measuredAt: previous.measuredAt };
      updateMessage(this.ctx.db, id, {
        status: 'done',
        score: report.score ?? null,
        report: JSON.stringify(report),
        client_ptr: (report.data.infrastructure as { ptr?: string[] } | undefined)?.ptr?.[0] ?? row.client_ptr,
        client_ip: row.client_ip ?? report.data.envelope.clientIp ?? null,
        helo: row.helo ?? report.data.envelope.helo ?? null,
        mail_from: row.mail_from ?? report.data.envelope.mailFrom ?? null,
        from_addr: report.data.message.from ?? row.from_addr,
        from_domain: report.data.message.fromDomain ?? row.from_domain,
        subject: report.data.message.subject ?? row.subject,
      });
      mailBus.publish({ type: 'report', addressId: row.address_id, messageId: id, ownerId: row.owner_id, data: report });
      return report;
    } catch (e) {
      updateMessage(this.ctx.db, id, { status: 'error', report: JSON.stringify({ error: (e as Error).message }) });
      mailBus.publish({ type: 'error', addressId: row.address_id, messageId: id, ownerId: row.owner_id, data: { error: (e as Error).message } });
      return undefined;
    }
  }
}
