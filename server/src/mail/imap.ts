// Fallback reception: a catch-all mailbox read over IMAP (IDLE), when the SMTP server cannot be
// reached from the Internet. Each unseen message is matched to its test address through
// Delivered-To / X-Original-To / Envelope-To / To / Cc, analysed, then flagged \Seen.
import { ImapFlow } from 'imapflow';
import type { ToolContext } from '../tools/types.js';
import type { MailService } from './service.js';
import { headerValues, parseRaw } from './mime.js';
import { activeAddress, normaliseAddressId } from './store.js';
import { readPem } from './smtp.js';

export interface ImapStatus {
  enabled: boolean;
  connected: boolean;
  lastError?: string;
  lastConnectAt?: string;
  processed: number;
  skipped: number;
  /** TLS of the current connection (protocol, certificate verified), false in clear text */
  tls?: { protocol?: string; authorized?: boolean } | false;
}

const ADDRESS_HEADERS = ['delivered-to', 'x-original-to', 'envelope-to', 'x-envelope-to', 'to', 'cc'];

/** Test address ids found in the delivery headers, most specific header first. */
export function addressIdsOf(raw: Buffer, domain: string): string[] {
  const { headers } = parseRaw(raw);
  const out: string[] = [];
  const re = new RegExp(`([a-z0-9._+-]+)@${domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
  for (const key of ADDRESS_HEADERS) {
    for (const v of headerValues(headers, key)) {
      for (const m of v.matchAll(re)) {
        const id = normaliseAddressId(m[1]);
        if (id && !out.includes(id)) out.push(id);
      }
    }
  }
  return out;
}

export class ImapReceiver {
  status: ImapStatus = { enabled: true, connected: false, processed: 0, skipped: 0 };
  private client?: ImapFlow;
  private stopped = false;
  private backoff = 1000;
  private timer?: NodeJS.Timeout;
  private draining = false;
  private again = false;
  private done = new Set<string>();
  private poll?: NodeJS.Timeout;

  /**
   * @param pollMs safety net for servers whose IDLE does not announce new messages: the
   * mailbox is also checked at this interval.
   */
  constructor(
    private ctx: ToolContext,
    private service: MailService,
    private pollMs = 60_000,
  ) {}

  private get domain() {
    return this.ctx.config.imap.domain || this.ctx.config.mail.domain;
  }

  /** Domains of the mailbox host, used to tell its own relays from the sender's. */
  private get receiverDomains(): string[] {
    return [this.ctx.config.imap.host, this.domain].filter(Boolean);
  }

  start() {
    this.stopped = false;
    void this.connect();
    this.poll = setInterval(() => void this.drain(), this.pollMs);
    this.poll.unref();
  }

  async stop() {
    this.stopped = true;
    clearTimeout(this.timer);
    clearInterval(this.poll);
    const c = this.client;
    this.client = undefined;
    if (c) await c.logout().catch(() => c.close());
  }

  private schedule() {
    if (this.stopped) return;
    clearTimeout(this.timer);
    const wait = this.backoff;
    this.backoff = Math.min(this.backoff * 2, 5 * 60 * 1000);
    this.timer = setTimeout(() => void this.connect(), wait);
    this.timer.unref();
  }

  private async connect() {
    if (this.stopped) return;
    const cfg = this.ctx.config.imap;
    let ca: string | undefined;
    try {
      ca = readPem(cfg.tlsCa);
    } catch {
      this.status.lastError = 'CHECK_IMAP_TLS_CA unreadable';
      this.schedule();
      return;
    }
    const client = new ImapFlow({
      host: cfg.host,
      port: cfg.port,
      // implicit TLS (993) when secure, otherwise STARTTLS when the server offers it
      secure: cfg.secure,
      // the certificate is always verified; CHECK_IMAP_TLS_CA only adds a CA to trust (self-signed server)
      tls: { rejectUnauthorized: true, ...(ca ? { ca } : {}) },
      auth: { user: cfg.user, pass: cfg.pass },
      logger: false,
    });
    this.client = client;
    client.on('error', (e: Error) => {
      this.status.lastError = e.message;
    });
    client.on('close', () => {
      this.status.connected = false;
      if (this.client === client) {
        this.client = undefined;
        this.schedule();
      }
    });
    client.on('exists', () => void this.drain());
    try {
      await client.connect();
      await client.mailboxOpen(cfg.mailbox);
      this.status.connected = true;
      this.status.tls = client.tls ? { protocol: client.tls.version, authorized: client.tls.authorized } : false;
      this.status.lastConnectAt = new Date().toISOString();
      this.status.lastError = undefined;
      this.backoff = 1000;
      await this.drain();
      // imapflow enters IDLE by itself when no command runs
    } catch (e) {
      this.status.lastError = (e as Error).message;
      this.status.connected = false;
      try {
        client.close();
      } catch {
        /* already closed */
      }
      if (this.client === client) {
        this.client = undefined;
        this.schedule();
      }
    }
  }

  /** Fetch every unseen message, process it, flag it \Seen. */
  private async drain() {
    const client = this.client;
    if (!client || !client.usable) return;
    if (this.draining) {
      this.again = true;
      return;
    }
    this.draining = true;
    try {
      do {
        this.again = false;
        const batch: { uid: number; source: Buffer }[] = [];
        const uids = (await client.search({ seen: false }, { uid: true })) || [];
        if (!uids.length) break;
        for await (const msg of client.fetch(uids.slice(0, 50), { uid: true, source: true }, { uid: true })) {
          if (msg.source) batch.push({ uid: msg.uid, source: msg.source });
        }
        const validity = String(client.mailbox && typeof client.mailbox === 'object' ? client.mailbox.uidValidity : '');
        for (const m of batch) {
          const key = `${validity}:${m.uid}`;
          if (!this.done.has(key)) {
            this.done.add(key);
            // only guards against a second pass before \Seen lands: the latest keys are enough (code review of 2026-11-12)
            if (this.done.size > 5000) this.done.delete(this.done.values().next().value as string);
            this.process(m.source);
          }
          await client.messageFlagsAdd(String(m.uid), ['\\Seen'], { uid: true });
        }
        if (uids.length > 50) this.again = true;
      } while (this.again);
    } catch (e) {
      this.status.lastError = (e as Error).message;
    } finally {
      this.draining = false;
    }
  }

  private process(raw: Buffer) {
    const ids = addressIdsOf(raw, this.domain).filter((id) => activeAddress(this.ctx.db, id));
    if (!ids.length) {
      this.status.skipped++;
      return;
    }
    for (const id of ids.slice(0, 1)) {
      this.status.processed++;
      this.service.ingest({ via: 'imap', addressId: id, raw, rcptTo: [`${id}@${this.domain}`], receiverDomains: this.receiverDomains });
    }
  }
}
