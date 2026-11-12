// Daily online copy of the SQLite database, made by the application itself (US-098): no crontab on
// the host. better-sqlite3's backup() copies page by page while the app keeps writing, and the
// copy is a complete database at one point in time. Files are named check-YYYY-MM-DD.sqlite
// (UTC date); the newest `keep` are kept, older ones are removed.
import fs from 'node:fs';
import path from 'node:path';
import type { FastifyBaseLogger } from 'fastify';
import { config } from './config.js';
import type { DB } from './db.js';

const NAME = /^check-(\d{4}-\d{2}-\d{2})\.sqlite$/;

export const backupName = (at: Date) => `check-${at.toISOString().slice(0, 10)}.sqlite`;

/** Backups in the directory, oldest first (the UTC date in the name sorts as text). */
export function listBackups(dir: string): string[] {
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  return names.filter((n) => NAME.test(n)).sort();
}

/** Remove every backup but the newest `keep`. Returns the names removed. */
export function rotateBackups(dir: string, keep: number): string[] {
  const all = listBackups(dir);
  const gone = all.slice(0, Math.max(0, all.length - Math.max(1, keep)));
  for (const n of gone) fs.rmSync(path.join(dir, n), { force: true });
  return gone;
}

/**
 * Copy the database to <dir>/check-<UTC date>.sqlite, then rotate. The copy is written under a
 * temporary name and renamed when complete: a backup file is never a half-written one. A second
 * run the same day replaces that day's file.
 */
export async function backupDb(db: DB, opts: { dir: string; keep: number; at?: Date }): Promise<{ file: string; removed: string[] }> {
  fs.mkdirSync(opts.dir, { recursive: true });
  const file = path.join(opts.dir, backupName(opts.at ?? new Date()));
  const tmp = `${file}.part`;
  // left over by a copy interrupted by a stop of the process
  for (const n of fs.readdirSync(opts.dir)) if (/^check-[\d-]+\.sqlite\.part$/.test(n)) fs.rmSync(path.join(opts.dir, n), { force: true });
  try {
    await db.backup(tmp);
    // the copy holds the notebooks' data: readable by the application user only
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
  } catch (e) {
    fs.rmSync(tmp, { force: true });
    throw e;
  }
  return { file, removed: rotateBackups(opts.dir, opts.keep) };
}

/** What the logs may say about a failure: the error type and code, never its message (a path). */
function errorCode(e: unknown): string {
  const err = e as { code?: unknown; name?: unknown } | undefined;
  if (err && (typeof err.code === 'string' || typeof err.code === 'number')) return String(err.code);
  return typeof err?.name === 'string' ? err.name : 'Error';
}

export interface BackupJob {
  /** The run in progress, if any (tests). */
  running(): Promise<void> | undefined;
  stop(): void;
}

/**
 * First copy `firstDelayMs` after start, then every `everyMs`. Never two at the same time: a run
 * still going when the next one is due makes that one skipped. A failure is logged and the job
 * goes on.
 */
export function startBackupJob(
  db: DB,
  log: Pick<FastifyBaseLogger, 'info' | 'error'>,
  opts: { dir?: string; keep?: number; firstDelayMs?: number; everyMs?: number } = {},
): BackupJob | undefined {
  const dir = opts.dir ?? config.backup.dir;
  const keep = opts.keep ?? config.backup.keep;
  if (keep <= 0) return undefined;
  let current: Promise<void> | undefined;
  const run = () => {
    if (current) return;
    const started = Date.now();
    current = backupDb(db, { dir, keep })
      .then(({ file, removed }) => log.info({ backup: path.basename(file), removed: removed.length, ms: Date.now() - started }, 'database backup done'))
      .catch((e: unknown) => log.error({ backupError: errorCode(e) }, 'database backup failed'))
      .finally(() => {
        current = undefined;
      });
  };
  let every: NodeJS.Timeout | undefined;
  const first = setTimeout(() => {
    run();
    every = setInterval(run, opts.everyMs ?? 24 * 3600_000);
    every.unref();
  }, opts.firstDelayMs ?? 5 * 60_000);
  first.unref();
  return {
    running: () => current,
    stop() {
      clearTimeout(first);
      clearInterval(every);
    },
  };
}
