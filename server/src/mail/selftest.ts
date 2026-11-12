// Reception self-test (US-099): every few hours the application sends a small message to a test
// address of its own, through the public path real senders take (the public test
// domain on port 25, through the host's relay when there is one, back into our SMTP server), and checks it arrives. The outcome
// is kept in `settings` and read by GET /api/health/reception, which an external monitor watches.
//
// The self-test address belongs to NO notebook (owner_id NULL, like legacy rows): every route
// filters on owner_id = <notebook>, so it is invisible to everybody. Its message is stored like any
// other (the write to the database is part of what is tested) but is neither analysed nor announced
// on the event bus, and both rows are deleted right after the check. Nothing personal is ever sent,
// stored or logged: the message is ours, and an outcome holds a time, a duration and a short code.
import net from 'node:net';
import nodemailer from 'nodemailer';
import type { Config } from '../config.js';
import { getSetting, setSetting, type DB } from '../db.js';
import { nodeStyleResolver } from '../dns/iterative.js';
import type { ToolContext } from '../tools/types.js';
import { createAddress, type AddressRow } from './store.js';

/** Label of the self-test address; only rows without a notebook count (user addresses always have one). */
export const SELFTEST_LABEL = '__check_reception_selftest__';
const SETTING_KEY = 'reception_selftest';

export interface SelfTestOutcome {
  /** start of the run, ISO */
  at: string;
  ok: boolean;
  /** from the start of the sending to the reception (or to the failure) */
  durationMs: number;
  /** short constant code, never a server message: smtp_550, ECONNECTION, not_received, dns_ENOTFOUND… */
  error?: string;
}

export interface SelfTestState {
  lastRun?: SelfTestOutcome;
  /** ISO time of the last successful run */
  lastSuccess?: string;
}

export function isSelfTestAddress(a: Pick<AddressRow, 'label' | 'owner_id'> | undefined): boolean {
  return !!a && a.owner_id === null && a.label === SELFTEST_LABEL;
}

const waiters = new Map<string, () => void>();

/** Called by the mail service when a message for a self-test address has been stored. */
export function selfTestReceived(addressId: string) {
  waiters.get(addressId)?.();
}

/** Remove every self-test row (messages go with their address: ON DELETE CASCADE, and explicitly). */
export function cleanupSelfTest(db: DB): number {
  const ids = "SELECT id FROM mail_addresses WHERE label = ? AND owner_id IS NULL";
  return db.transaction(() => {
    db.prepare(`DELETE FROM mail_messages WHERE address_id IN (${ids})`).run(SELFTEST_LABEL);
    return db.prepare('DELETE FROM mail_addresses WHERE label = ? AND owner_id IS NULL').run(SELFTEST_LABEL).changes;
  })();
}

export function selfTestState(db: DB): SelfTestState {
  return getSetting<SelfTestState>(SETTING_KEY, {}, db);
}

/** A code safe to store and show: SMTP reply code, or the error code of the client, never a message. */
function codeOf(e: unknown): string {
  const err = (e ?? {}) as { responseCode?: unknown; code?: unknown };
  if (typeof err.responseCode === 'number') return `smtp_${err.responseCode}`;
  if (typeof err.code === 'string' && /^[A-Za-z0-9_]{1,40}$/.test(err.code)) return err.code;
  return 'error';
}

function message(domain: string, id: string, at: Date): string {
  return [
    `From: check <postmaster@${domain}>`,
    `To: <${id}@${domain}>`,
    'Subject: check: autotest de reception',
    `Date: ${at.toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: <${id}.selftest@${domain}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Auto-Submitted: auto-generated',
    '',
    'Message de controle envoye par check a lui-meme pour verifier la reception.',
    '',
  ].join('\r\n');
}

/**
 * One self-test: create the hidden address, send the message, wait for it, clean up, record the
 * outcome. Never throws.
 */
export async function runSelfTest(
  ctx: ToolContext,
  opts: { host?: string; port?: number; timeoutMs?: number; /** tests: look at the rows before they go */ beforeCleanup?: (addressId: string) => void | Promise<void> } = {},
): Promise<SelfTestOutcome> {
  const cfg: Config['selftest'] = ctx.config.selftest;
  const db = ctx.db;
  const domain = ctx.config.mail.domain;
  const host = opts.host ?? cfg.smtpHost;
  const port = opts.port ?? cfg.smtpPort;
  const timeoutMs = opts.timeoutMs ?? cfg.timeoutSec * 1000;
  const started = new Date();
  const t0 = Date.now();
  let error: string | undefined;
  let address: AddressRow | undefined;
  let timer: NodeJS.Timeout | undefined;
  try {
    cleanupSelfTest(db); // rows left by a run interrupted by a stop of the process
    address = createAddress(db, domain, Math.max(1, Math.ceil(timeoutMs / 3_600_000) + 1), SELFTEST_LABEL, null);
    const id = address.id;
    const received = new Promise<void>((resolve) => waiters.set(id, resolve));
    const deadline = new Promise<never>((_r, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error('not received'), { code: 'not_received' })), timeoutMs);
    });
    deadline.catch(() => {}); // may fire while the host is still being resolved: never unhandled
    // the host is resolved from the root servers like every lookup of the tool (CONVENTIONS.md)
    let ip = host;
    if (!net.isIP(host)) {
      try {
        const ips = (await nodeStyleResolver(ctx.dns({ timeoutMs: 3000 }))(host, 'A')) as string[];
        ip = ips[0];
      } catch (e) {
        throw Object.assign(new Error('dns'), { code: `dns_${(e as { code?: string }).code ?? 'error'}` });
      }
    }
    const transport = nodemailer.createTransport({
      host: ip,
      port,
      secure: false,
      // STARTTLS when offered, any certificate (the relay's is self-signed), clear text otherwise
      requireTLS: false,
      opportunisticTLS: true,
      tls: { rejectUnauthorized: false, ...(net.isIP(host) ? {} : { servername: host }) },
      name: domain,
      connectionTimeout: Math.min(timeoutMs, 30_000),
      greetingTimeout: Math.min(timeoutMs, 30_000),
      socketTimeout: Math.min(timeoutMs, 60_000),
      logger: false,
    });
    try {
      // null sender: a late copy refused once the address is gone bounces to nobody
      await Promise.race([transport.sendMail({ envelope: { from: '', to: [address.address] }, raw: message(domain, id, started) }), deadline]);
    } finally {
      transport.close();
    }
    await Promise.race([received, deadline]);
    await opts.beforeCleanup?.(id);
  } catch (e) {
    error = codeOf(e);
  } finally {
    clearTimeout(timer);
    try {
      cleanupSelfTest(db);
    } catch {
      /* the next run cleans up */
    }
    if (address) waiters.delete(address.id);
  }
  const outcome: SelfTestOutcome = { at: started.toISOString(), ok: !error, durationMs: Date.now() - t0, ...(error ? { error } : {}) };
  try {
    const prev = selfTestState(db);
    setSetting(SETTING_KEY, { lastRun: outcome, lastSuccess: outcome.ok ? outcome.at : prev.lastSuccess } satisfies SelfTestState, db);
  } catch {
    /* the outcome is still returned and logged */
  }
  return outcome;
}

/** Body and status of GET /api/health/reception. Public: times, durations and codes only. */
export function receptionHealth(db: DB, config: Config, at = Date.now()): { status: number; body: Record<string, unknown> } {
  const cfg = config.selftest;
  if (!cfg.smtpHost) return { status: 200, body: { enabled: false } };
  const state = selfTestState(db);
  const last = state.lastSuccess ? Date.parse(state.lastSuccess) : NaN;
  const ok = Number.isFinite(last) && at - last <= cfg.maxAgeMinutes * 60_000;
  const run = state.lastRun;
  return {
    status: ok ? 200 : 503,
    body: {
      enabled: true,
      ok,
      lastSuccess: state.lastSuccess ?? null,
      lastRun: run ? { at: run.at, ok: run.ok, durationMs: run.durationMs, ...(run.error ? { error: run.error } : {}) } : null,
      intervalHours: cfg.intervalHours,
      maxAgeMinutes: cfg.maxAgeMinutes,
    },
  };
}

export interface SelfTestJob {
  running(): Promise<SelfTestOutcome> | undefined;
  stop(): void;
}

/**
 * First run `firstDelayMs` after start, then every intervalHours; never two at the same time.
 * Undefined when the self-test is not configured.
 */
export function startSelfTestJob(
  ctx: ToolContext,
  log: { info(o: object, m: string): void; warn(o: object, m: string): void },
  opts: { firstDelayMs?: number; everyMs?: number } = {},
): SelfTestJob | undefined {
  const cfg = ctx.config.selftest;
  if (!cfg.smtpHost) return undefined;
  let current: Promise<SelfTestOutcome> | undefined;
  const run = () => {
    if (current) return;
    current = runSelfTest(ctx)
      .then((o) => {
        if (o.ok) log.info({ selftest: 'ok', ms: o.durationMs }, 'reception self-test');
        else log.warn({ selftest: 'fail', code: o.error, ms: o.durationMs }, 'reception self-test');
        return o;
      })
      .finally(() => {
        current = undefined;
      });
  };
  let every: NodeJS.Timeout | undefined;
  const first = setTimeout(() => {
    run();
    every = setInterval(run, opts.everyMs ?? cfg.intervalHours * 3_600_000);
    every.unref();
  }, opts.firstDelayMs ?? 60_000);
  first.unref();
  return {
    running: () => current,
    stop() {
      clearTimeout(first);
      clearInterval(every);
    },
  };
}
