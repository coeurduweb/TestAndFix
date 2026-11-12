// The qualification job: at start-up when the last run is older than 24 h, then daily.
// One run at a time (manual runs included).
import type { DB } from '../../db.js';
import type { ToolContext } from '../types.js';
import { geolocateIp, serverLocation } from './geo.js';
import { CHECK_NAMES, qualify, type Progress } from './qualify.js';
import { query } from '../../dns/client.js';
import { refreshDefaultSelection } from './selection.js';
import { candidates, lastRun, qualifiedResolvers, saveOutcomes, saveRun, type QualificationRun, type ServerLocation } from './store.js';

const DAY = 24 * 3600 * 1000;

const int = (v: string | undefined, d: number) => (v && /^\d+$/.test(v) ? Number(v) : d);
/** Read from the environment here because config.ts is shared (a request to move them is in the report). */
export const settings = () => ({
  perCountry: int(process.env.CHECK_PROPAGATION_PER_COUNTRY, 4),
  perProvider: int(process.env.CHECK_PROPAGATION_PER_PROVIDER, 1),
  concurrency: Math.min(int(process.env.CHECK_PROPAGATION_CONCURRENCY, 100), 100),
  intervalMs: DAY,
});

export interface RunningState {
  startedAt: string;
  progress: Progress | null;
  manual: boolean;
}

let running: { state: RunningState; promise: Promise<QualificationRun>; ac: AbortController } | null = null;
let timer: NodeJS.Timeout | null = null;
let server: ServerLocation | null = null;

export const runningState = () => running?.state ?? null;

/** Outgoing IPv6 from this server, tested against root servers (f, k, l) over IPv6. */
const ROOT_V6 = ['2001:500:2f::f', '2001:7fd::1', '2001:500:9f::42'];
let ipv6: { available: boolean; checkedAt: string } | null = null;
export const ipv6State = () => ipv6;
export async function detectIpv6(timeoutMs = 2000): Promise<{ available: boolean; checkedAt: string }> {
  const answers = await Promise.allSettled(ROOT_V6.map((ip) => query(ip, 'root-servers.net', 'NS', { rd: false, timeoutMs })));
  ipv6 = { available: answers.some((a) => a.status === 'fulfilled' && a.value.rcode === 'NOERROR'), checkedAt: new Date().toISOString() };
  return ipv6;
}
export const currentServerLocation = () => server;

export interface RunOptions {
  manual?: boolean;
  /** Restrict to these IPs (tests). */
  ips?: string[];
  geolocate?: false;
  perCountry?: number;
  onProgress?: (p: Progress) => void;
}

/** Start a run, or return null when one is already running. */
export function startQualification(ctx: ToolContext, opts: RunOptions = {}): Promise<QualificationRun> | null {
  if (running) return null;
  const ac = new AbortController();
  const state: RunningState = { startedAt: new Date().toISOString(), progress: null, manual: !!opts.manual };
  const promise = runQualification(ctx.db, ctx, opts, state, ac.signal).finally(() => {
    running = null;
  });
  running = { state, promise, ac };
  return promise;
}

async function runQualification(db: DB, ctx: ToolContext, opts: RunOptions, state: RunningState, signal: AbortSignal): Promise<QualificationRun> {
  const t0 = Date.now();
  const s = settings();
  const list = candidates(db, opts.ips);
  const previous = new Set(qualifiedResolvers(db).map((r) => r.ip));
  server = (await serverLocation(ctx.dns())) ?? server;
  const v6 = await detectIpv6();
  const base = {
    startedAt: state.startedAt,
    candidates: list.length,
    checkNames: CHECK_NAMES.map((c) => `${c.name} ${c.type}`),
    serverLocation: server,
  };
  let result;
  try {
    result = await qualify(list, {
      dns: () => ctx.dns(),
      concurrency: s.concurrency,
      perCountry: opts.perCountry ?? s.perCountry,
      perProvider: s.perProvider,
      geolocate: opts.geolocate === false ? false : (ip) => geolocateIp(ip),
      ipv6Available: v6.available,
      serverLocation: server,
      signal,
      onProgress: (p) => {
        state.progress = p;
        opts.onProgress?.(p);
      },
    });
  } catch (e) {
    const run: QualificationRun = {
      ...base,
      status: signal.aborted ? 'aborted' : 'error',
      finishedAt: new Date().toISOString(),
      durationMs: Date.now() - t0,
      tested: 0,
      skippedQuarantine: 0,
      passed: 0,
      qualified: 0,
      qualifiedGlobal: 0,
      qualifiedLocal: 0,
      countries: 0,
      dnssecValidating: 0,
      failures: {},
      note: (e as Error).message,
    };
    // keep the previous list: a failed run must not empty the display
    saveRun(db, { ...(lastRun(db) ?? run), lastAttempt: run });
    return run;
  }
  const qualifiedOutcomes = result.outcomes.filter((o) => o.qualified);
  const byIp = new Map(list.map((c) => [c.ip, c]));
  // A run where most of yesterday's resolvers fail says more about our network than about them.
  const kept = result.outcomes.filter((o) => o.passed && previous.has(o.ip)).length;
  const suspect = !opts.ips && previous.size >= 20 && kept / previous.size < 0.3;
  const run: QualificationRun = {
    ...base,
    status: suspect ? 'suspect' : 'ok',
    finishedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
    tested: result.tested,
    skippedQuarantine: result.skippedQuarantine,
    passed: result.passed,
    qualified: qualifiedOutcomes.length,
    qualifiedGlobal: qualifiedOutcomes.filter((o) => byIp.get(o.ip)?.anycast).length,
    qualifiedLocal: qualifiedOutcomes.filter((o) => !byIp.get(o.ip)?.anycast).length,
    countries: new Set(qualifiedOutcomes.filter((o) => !byIp.get(o.ip)?.anycast).map((o) => o.location?.country_code ?? byIp.get(o.ip)?.country_code)).size,
    dnssecValidating: qualifiedOutcomes.filter((o) => o.dnssec).length,
    failures: result.failures,
    note: suspect
      ? `Only ${kept} of the ${previous.size} resolvers qualified before passed: results not applied (network problem on our side?).`
      : undefined,
  };
  if (!suspect) {
    saveOutcomes(db, result.outcomes);
    refreshDefaultSelection(db);
  }
  saveRun(db, suspect ? { ...(lastRun(db) ?? run), lastAttempt: run } : run);
  return run;
}

/** Called by tool.start(): run now if the last successful run is older than 24 h, then check hourly. */
export function schedule(ctx: ToolContext, log: (msg: string) => void = () => {}) {
  const tick = () => {
    if (running) return;
    const last = lastRun(ctx.db);
    const attempt = last?.lastAttempt && Date.parse(last.lastAttempt.finishedAt) > Date.parse(last.finishedAt) ? last.lastAttempt : last;
    const age = attempt ? Date.now() - Date.parse(attempt.finishedAt) : Infinity;
    // a successful run is redone after 24 h, a failed or suspect one after 1 h
    if (age < (attempt?.status === 'ok' ? settings().intervalMs : 3600 * 1000)) return;
    const p = startQualification(ctx);
    p?.then(
      (r) => log(`propagation: qualification ${r.status}, ${r.tested} tested, ${r.qualified} qualified in ${Math.round(r.durationMs / 1000)} s`),
      (e) => log(`propagation: qualification failed: ${(e as Error).message}`),
    );
  };
  const first = setTimeout(tick, 5000);
  first.unref();
  timer = setInterval(tick, 3600 * 1000);
  timer.unref();
}

export async function stopJob() {
  if (timer) clearInterval(timer);
  timer = null;
  if (running) {
    running.ac.abort();
    await running.promise.catch(() => {});
  }
}
