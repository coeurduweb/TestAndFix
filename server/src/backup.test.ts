// Daily database backup (US-098): a backup is a complete database that opens and holds the rows,
// rotation keeps the newest N, runs never overlap, a failure is logged without a path or message.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { backupDb, backupName, listBackups, rotateBackups, startBackupJob } from './backup.js';
import { openDb, saveResult, type DB } from './db.js';
import { createAddress } from './mail/store.js';

let dir: string;
let db: DB;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'check-backup-'));
  db = openDb(path.join(dir, 'check.sqlite'));
});
afterEach(() => {
  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('database backup', () => {
  it('writes a valid database, named with the UTC date, that opens and holds the rows', async () => {
    const id = saveResult('spf', 'exemple.fr', { ok: true }, { ownerId: null }, db);
    const a = createAddress(db, 'check.localhost', 1);
    const out = path.join(dir, 'backups');
    const { file, removed } = await backupDb(db, { dir: out, keep: 14, at: new Date('2026-11-11T23:59:59Z') });
    expect(path.basename(file)).toBe('check-2026-11-11.sqlite');
    expect(removed).toEqual([]);
    expect(fs.readdirSync(out)).toEqual(['check-2026-11-11.sqlite']); // no partial file left
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    const copy = new Database(file, { readonly: true });
    try {
      expect(copy.pragma('integrity_check', { simple: true })).toBe('ok');
      expect(copy.prepare('SELECT id, tool, input FROM results').all()).toEqual([{ id, tool: 'spf', input: 'exemple.fr' }]);
      expect(copy.prepare('SELECT id FROM mail_addresses').all()).toEqual([{ id: a.id }]);
    } finally {
      copy.close();
    }
  });

  it('names files with the UTC date, not the local one', () => {
    expect(backupName(new Date('2026-01-31T23:30:00-02:00'))).toBe('check-2026-02-01.sqlite');
  });

  it('keeps the newest N backups and leaves other files alone', async () => {
    const out = path.join(dir, 'backups');
    fs.mkdirSync(out);
    for (let d = 1; d <= 20; d++) fs.writeFileSync(path.join(out, `check-2026-10-${String(d).padStart(2, '0')}.sqlite`), 'x');
    fs.writeFileSync(path.join(out, 'notes.txt'), 'garder');
    fs.writeFileSync(path.join(out, 'check-2026-10-30.sqlite.part'), 'interrompu');
    const { removed } = await backupDb(db, { dir: out, keep: 14, at: new Date('2026-11-11T08:00:00Z') });
    expect(removed).toEqual(['check-2026-10-01.sqlite', 'check-2026-10-02.sqlite', 'check-2026-10-03.sqlite', 'check-2026-10-04.sqlite', 'check-2026-10-05.sqlite', 'check-2026-10-06.sqlite', 'check-2026-10-07.sqlite']);
    const left = listBackups(out);
    expect(left).toHaveLength(14);
    expect(left[0]).toBe('check-2026-10-08.sqlite');
    expect(left.at(-1)).toBe('check-2026-11-11.sqlite');
    expect(fs.existsSync(path.join(out, 'notes.txt'))).toBe(true);
    expect(fs.existsSync(path.join(out, 'check-2026-10-30.sqlite.part'))).toBe(false);
    expect(rotateBackups(out, 3)).toHaveLength(11);
    expect(listBackups(out)).toEqual(['check-2026-10-19.sqlite', 'check-2026-10-20.sqlite', 'check-2026-11-11.sqlite']);
  });

  it('a second run the same day replaces that day', async () => {
    const out = path.join(dir, 'backups');
    const at = new Date('2026-11-11T08:00:00Z');
    await backupDb(db, { dir: out, keep: 14, at });
    saveResult('dns', 'apres.fr', {}, { ownerId: null }, db);
    await backupDb(db, { dir: out, keep: 14, at });
    expect(listBackups(out)).toEqual(['check-2026-11-11.sqlite']);
    const copy = new Database(path.join(out, 'check-2026-11-11.sqlite'), { readonly: true });
    expect((copy.prepare('SELECT COUNT(*) AS n FROM results').get() as { n: number }).n).toBe(1);
    copy.close();
  });
});

describe('backup job', () => {
  const logger = () => {
    const lines: { level: string; obj: Record<string, unknown>; msg: string }[] = [];
    return {
      lines,
      info: (obj: Record<string, unknown>, msg: string) => lines.push({ level: 'info', obj, msg }),
      error: (obj: Record<string, unknown>, msg: string) => lines.push({ level: 'error', obj, msg }),
    };
  };

  it('runs shortly after start and logs the file name only', async () => {
    const log = logger();
    const out = path.join(dir, 'sauvegardes');
    const job = startBackupJob(db, log as never, { dir: out, keep: 14, firstDelayMs: 5, everyMs: 3_600_000 })!;
    for (let i = 0; i < 200 && !log.lines.length; i++) await sleep(10);
    job.stop();
    expect(listBackups(out)).toHaveLength(1);
    expect(log.lines).toHaveLength(1);
    expect(log.lines[0]).toMatchObject({ level: 'info', msg: 'database backup done', obj: { backup: backupName(new Date()), removed: 0 } });
    expect(JSON.stringify(log.lines)).not.toContain(dir);
  });

  it('never runs two copies at the same time', async () => {
    let calls = 0;
    let release!: () => void;
    const slow = { backup: () => ((calls++, new Promise<void>((r) => (release = r))) as never) } as unknown as DB;
    const log = logger();
    const job = startBackupJob(slow, log as never, { dir: path.join(dir, 'b'), keep: 14, firstDelayMs: 1, everyMs: 5 })!;
    await sleep(80); // about fifteen ticks while the first copy is still running
    expect(calls).toBe(1);
    release();
    for (let i = 0; i < 100 && calls < 2; i++) await sleep(5);
    job.stop();
    expect(calls).toBeGreaterThanOrEqual(2);
  });

  it('logs a failure with its code, without the path nor the message, and keeps going', async () => {
    const blocker = path.join(dir, 'pas-un-dossier');
    fs.writeFileSync(blocker, 'fichier');
    const log = logger();
    const job = startBackupJob(db, log as never, { dir: path.join(blocker, 'backups'), keep: 14, firstDelayMs: 1, everyMs: 20 })!;
    for (let i = 0; i < 200 && log.lines.length < 2; i++) await sleep(5);
    job.stop();
    expect(log.lines.length).toBeGreaterThanOrEqual(2); // the job goes on after a failure
    expect(log.lines[0]).toEqual({ level: 'error', obj: { backupError: 'ENOTDIR' }, msg: 'database backup failed' });
    expect(JSON.stringify(log.lines)).not.toContain('pas-un-dossier');
  });

  it('is off when keep is 0', () => {
    expect(startBackupJob(db, logger() as never, { dir, keep: 0 })).toBeUndefined();
  });
});
