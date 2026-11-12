// Politeness towards registry and registrar servers, shared by every request of the process.
import { t } from '../../i18n.js';
//
// No registry we query publishes a numeric limit for anonymous access: Verisign's and PIR's WHOIS
// terms only forbid "high-volume, automated" querying (text of their answers, recorded in
// fixtures/), Afnic limits "by IP" without a figure ("Publication and Access to the information",
// 1 January 2023, Article 4.2, https://www.afnic.fr/wp-media/uploads/2022/12/afnic-policy-access-data-2023-01-01.pdf).
// The numbers below are therefore conservative choices of ours, not published thresholds:
//
//   - one request at a time per host, never two in parallel to the same server;
//   - RDAP (HTTPS): at least 1 s between two requests to the same host;
//   - WHOIS (port 43): at least 3 s between two requests to the same host, because port 43 servers
//     are the ones that block bursts by IP and give no machine-readable signal before doing so;
//   - at most 6 requests in flight for the whole process, all hosts together;
//   - after a failure (timeout, refused connection, 5xx, rate-limit text) the host is left alone for
//     5 s, then 10, 20, 40 s... (doubling, at most 5 min), reset by the next success;
//   - an RDAP 429 answer (RFC 7480 §5.5) blocks the host for its Retry-After (RFC 9110 §10.2.3,
//     seconds or HTTP date), at most 10 min; without Retry-After, the doubling backoff applies.
//
// A caller gives the longest wait it accepts: when the queue or a block would exceed it, the call is
// refused at once with RateLimitedError, so the lookup moves to the other protocol instead of hanging.

export interface HostPolicy {
  minIntervalMs: number;
}

export const RDAP_POLICY: HostPolicy = { minIntervalMs: 1000 };
export const WHOIS_POLICY: HostPolicy = { minIntervalMs: 3000 };
export const GLOBAL_MAX_IN_FLIGHT = 6;
export const BACKOFF_BASE_MS = 5000;
export const BACKOFF_MAX_MS = 5 * 60_000;
export const RETRY_AFTER_MAX_MS = 10 * 60_000;

export class RateLimitedError extends Error {
  constructor(
    public readonly host: string,
    public readonly waitMs: number,
  ) {
    super(t('{host} demande d’attendre {s} s avant une nouvelle requête', { host, s: Math.ceil(waitMs / 1000) }));
  }
}

interface HostState {
  chain: Promise<void>;
  /** Requests waiting or running on this host. */
  pending: number;
  /** Earliest start of the next request (spacing). */
  nextAt: number;
  /** Earliest start after a failure or a 429. */
  blockedUntil: number;
  failures: number;
}

/** Retry-After as milliseconds: delta-seconds or an HTTP date (RFC 9110 §10.2.3). */
export function parseRetryAfter(value: string | undefined, now: number): number | undefined {
  if (!value) return undefined;
  const v = value.trim();
  if (/^\d+$/.test(v)) return Number(v) * 1000;
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : Math.max(0, t - now);
}

export class PoliteLimiter {
  private hosts = new Map<string, HostState>();
  private inFlight = 0;
  private waiters: (() => void)[] = [];

  constructor(
    private readonly opts: { globalMax?: number; now?: () => number; sleep?: (ms: number) => Promise<void> } = {},
  ) {}

  private get now() {
    return this.opts.now ?? Date.now;
  }

  private sleep(ms: number) {
    return (this.opts.sleep ?? ((x: number) => new Promise<void>((r) => setTimeout(r, x))))(ms);
  }

  private state(host: string): HostState {
    let s = this.hosts.get(host);
    if (!s) {
      s = { chain: Promise.resolve(), pending: 0, nextAt: 0, blockedUntil: 0, failures: 0 };
      this.hosts.set(host, s);
    }
    return s;
  }

  /** How long a new request to this host would wait before starting, at best. */
  expectedWait(host: string, policy: HostPolicy): number {
    const s = this.hosts.get(host);
    if (!s) return 0;
    const t = this.now();
    return Math.max(0, s.nextAt - t, s.blockedUntil - t) + s.pending * policy.minIntervalMs;
  }

  /** Is the host blocked (429 or failures) right now, and for how long. */
  blockedFor(host: string): number {
    const s = this.hosts.get(host);
    return s ? Math.max(0, s.blockedUntil - this.now()) : 0;
  }

  /**
   * Run fn when the host's turn comes. Throws RateLimitedError without waiting when the expected
   * wait exceeds maxWaitMs, or when the turn comes after the deadline.
   */
  async run<T>(host: string, policy: HostPolicy, fn: () => Promise<T>, maxWaitMs: number, signal?: AbortSignal): Promise<T> {
    const s = this.state(host);
    const expected = this.expectedWait(host, policy);
    if (expected > maxWaitMs) throw new RateLimitedError(host, expected);
    const deadline = this.now() + maxWaitMs;
    s.pending++;
    const turn = s.chain.then(async () => {
      const wait = Math.max(0, s.nextAt - this.now(), s.blockedUntil - this.now());
      if (this.now() + wait > deadline) throw new RateLimitedError(host, wait);
      if (wait > 0) await this.sleep(wait);
      if (signal?.aborted) throw new Error(t('requête annulée'));
      await this.acquireGlobal();
      s.nextAt = this.now() + policy.minIntervalMs;
      try {
        return await fn();
      } finally {
        this.releaseGlobal();
      }
    });
    // the next request on this host waits for this one to finish, success or not
    s.chain = turn.then(
      () => undefined,
      () => undefined,
    );
    try {
      return await turn;
    } finally {
      s.pending--;
    }
  }

  /** The host answered normally: forget past failures. */
  succeed(host: string) {
    const s = this.state(host);
    s.failures = 0;
  }

  /** The host failed or asked to slow down: block it for retryAfterMs, or the doubling backoff. */
  penalize(host: string, retryAfterMs?: number) {
    const s = this.state(host);
    s.failures++;
    const backoff = Math.min(BACKOFF_BASE_MS * 2 ** (s.failures - 1), BACKOFF_MAX_MS);
    const ms = retryAfterMs !== undefined ? Math.min(Math.max(retryAfterMs, 0), RETRY_AFTER_MAX_MS) : backoff;
    s.blockedUntil = Math.max(s.blockedUntil, this.now() + ms);
  }

  private acquireGlobal(): Promise<void> {
    const max = this.opts.globalMax ?? GLOBAL_MAX_IN_FLIGHT;
    if (this.inFlight < max) {
      this.inFlight++;
      return Promise.resolve();
    }
    return new Promise((resolve) => this.waiters.push(() => (this.inFlight++, resolve())));
  }

  private releaseGlobal() {
    this.inFlight--;
    const next = this.waiters.shift();
    if (next) next();
  }
}

/** The limiter of the process: every Whois lookup, single or batch, goes through it. */
export const sharedLimiter = new PoliteLimiter();
