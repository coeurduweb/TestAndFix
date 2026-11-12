// Migration of a database created before the notebooks, and the retention purge of notebooks.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { afterEach, describe, expect, it } from 'vitest';
import { openDb, purgeOld } from './db.js';
import { createOwnerWithDevice, sha256 } from './owner.js';
import { days } from './lib/time.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const OLD_SCHEMA = fs.readFileSync(path.join(here, 'fixtures', 'schema-2026-11-10.sql'), 'utf8');
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function oldDatabase(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'check-migration-'));
  dirs.push(dir);
  const file = path.join(dir, 'check.sqlite');
  const d = new Database(file);
  d.pragma('journal_mode = WAL');
  d.exec(OLD_SCHEMA);
  const t = Date.now();
  d.prepare("INSERT INTO results(id, tool, input, created_at, data) VALUES('r1', 'spf', 'ancien.fr', ?, '{}')").run(t);
  d.prepare("INSERT INTO mail_addresses(id, address, created_at, expires_at) VALUES('t-ancien01', 't-ancien01@x', ?, ?)").run(t, t + 1000);
  d.prepare("INSERT INTO mail_messages(id, address_id, created_at, via, raw, status) VALUES('m-ancien000001', 't-ancien01', ?, 'smtp', x'00', 'done')").run(t);
  d.prepare("INSERT INTO dmarc_reports(id, created_at, domain, org_name, report_id, messages, data) VALUES('d1', ?, 'ancien.fr', 'google.com', 'rep-1', 3, '{}')").run(t);
  d.close();
  return file;
}

const cols = (d: Database.Database, t: string) => (d.prepare(`PRAGMA table_info(${t})`).all() as { name: string }[]).map((c) => c.name);

describe('migration of a database created before the notebooks', () => {
  it('adds owner_id, keeps the rows with owner_id NULL, and makes the DMARC duplicate check per notebook', () => {
    const file = oldDatabase();
    const d = openDb(file);
    for (const t of ['results', 'mail_addresses', 'mail_messages', 'dmarc_reports']) expect(cols(d, t)).toContain('owner_id');
    for (const t of ['owners', 'devices', 'link_codes', 'shares']) expect(cols(d, t).length).toBeGreaterThan(0);
    expect(d.prepare('SELECT id, owner_id FROM results').all()).toEqual([{ id: 'r1', owner_id: null }]);
    expect(d.prepare('SELECT id, owner_id FROM mail_addresses').all()).toEqual([{ id: 't-ancien01', owner_id: null }]);
    expect(d.prepare('SELECT id, owner_id FROM mail_messages').all()).toEqual([{ id: 'm-ancien000001', owner_id: null }]);
    expect(d.prepare('SELECT id, domain, org_name, report_id, messages, owner_id FROM dmarc_reports').all()).toEqual([
      { id: 'd1', domain: 'ancien.fr', org_name: 'google.com', report_id: 'rep-1', messages: 3, owner_id: null },
    ]);
    const idx = (d.prepare("SELECT name FROM sqlite_master WHERE type = 'index'").all() as { name: string }[]).map((r) => r.name);
    expect(idx).toEqual(expect.arrayContaining(['results_owner', 'mail_messages_owner', 'mail_addresses_owner', 'dmarc_owner', 'dmarc_domain']));

    // the same report in two notebooks is allowed, twice in one notebook is not
    const ins = d.prepare("INSERT OR IGNORE INTO dmarc_reports(id, created_at, domain, org_name, report_id, data, owner_id) VALUES(?, 1, 'ancien.fr', 'google.com', 'rep-1', '{}', ?)");
    expect(ins.run('d2', 'o-a').changes).toBe(1);
    expect(ins.run('d3', 'o-b').changes).toBe(1);
    expect(ins.run('d4', 'o-a').changes).toBe(0);
    d.close();

    // running it again on every start changes nothing
    const again = openDb(file);
    expect(again.prepare('SELECT COUNT(*) AS n FROM dmarc_reports').get()).toEqual({ n: 3 });
    expect(again.prepare('SELECT owner_id FROM results').get()).toEqual({ owner_id: null });
    expect(again.pragma('foreign_key_check')).toEqual([]);
    again.close();
  });

  it('adds shares.created_by_device to a database made by the first version of the notebooks', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'check-migration-'));
    dirs.push(dir);
    const file = path.join(dir, 'check.sqlite');
    const d0 = new Database(file);
    d0.exec(OLD_SCHEMA);
    d0.exec(`CREATE TABLE owners (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
      CREATE TABLE shares (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, token TEXT NOT NULL,
        owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE, kind TEXT NOT NULL, target_id TEXT NOT NULL, created_at INTEGER NOT NULL);
      INSERT INTO owners VALUES('o', 1);
      INSERT INTO shares VALUES('s', 'h', 't', 'o', 'mail-message', 'm-x', 1);`);
    d0.close();
    const d = openDb(file);
    expect(cols(d, 'shares')).toContain('created_by_device');
    expect(d.prepare('SELECT id, created_by_device FROM shares').all()).toEqual([{ id: 's', created_by_device: null }]);
    d.close();
  });

  it('a fresh database gets the same final schema', () => {
    const fresh = openDb(':memory:');
    const file = oldDatabase();
    const migrated = openDb(file);
    for (const t of ['results', 'mail_addresses', 'mail_messages', 'dmarc_reports']) expect(cols(migrated, t).sort()).toEqual(cols(fresh, t).sort());
    migrated.close();
  });
});

describe('retention purge of notebooks', () => {
  it('drops expired link codes, stale devices, and notebooks left without device with their data', () => {
    const d = openDb(':memory:');
    const t = Date.now();
    const kept = createOwnerWithDevice(d, 'Firefox').owner;
    const lone = createOwnerWithDevice(d, 'Chrome').owner;
    d.prepare('UPDATE devices SET last_seen_at = ? WHERE id = ?').run(t - days(91), lone.deviceId);
    d.prepare("INSERT INTO results(id, tool, input, created_at, owner_id) VALUES('rk', 'spf', 'a.fr', ?, ?)").run(t, kept.ownerId);
    d.prepare("INSERT INTO results(id, tool, input, created_at, owner_id) VALUES('rl', 'spf', 'b.fr', ?, ?)").run(t - days(1), lone.ownerId);
    d.prepare('INSERT INTO link_codes(code_hash, owner_id, created_at, expires_at) VALUES(?,?,?,?)').run(sha256('OLD'), kept.ownerId, t - 600_000, t - 300_000);
    d.prepare('INSERT INTO link_codes(code_hash, owner_id, created_at, expires_at) VALUES(?,?,?,?)').run(sha256('NEW'), kept.ownerId, t, t + 300_000);
    const out = purgeOld(d, 90, t);
    expect(out.link_codes).toBe(1);
    expect(out.devices).toBe(1);
    expect(out.owners).toBe(1);
    expect(d.prepare('SELECT id FROM results').all()).toEqual([{ id: 'rk' }]);
    expect(d.prepare('SELECT id FROM owners').all()).toEqual([{ id: kept.ownerId }]);
    expect(d.prepare('SELECT code_hash FROM link_codes').all()).toEqual([{ code_hash: sha256('NEW') }]);
  });

  it('drops empty notebooks whose devices were not seen for 7 days, keeps the others', () => {
    const d = openDb(':memory:');
    const t = Date.now();
    const stale = createOwnerWithDevice(d, 'Firefox').owner;
    const recent = createOwnerWithDevice(d, 'Firefox').owner;
    const withData = createOwnerWithDevice(d, 'Firefox').owner;
    d.prepare('UPDATE devices SET last_seen_at = ? WHERE id IN (?, ?)').run(t - days(8), stale.deviceId, withData.deviceId);
    d.prepare('UPDATE devices SET last_seen_at = ? WHERE id = ?').run(t - days(6), recent.deviceId);
    d.prepare("INSERT INTO results(id, tool, input, created_at, owner_id) VALUES('r', 'spf', 'a.fr', ?, ?)").run(t, withData.ownerId);
    // a legacy row (owner_id NULL) must not stop the purge (NOT IN with a NULL)
    d.prepare("INSERT INTO results(id, tool, input, created_at) VALUES('legacy', 'spf', 'b.fr', ?)").run(t);
    const out = purgeOld(d, 90, t);
    expect(out.empty_owners).toBe(1);
    expect((d.prepare('SELECT id FROM owners ORDER BY id').all() as { id: string }[]).map((r) => r.id).sort()).toEqual([recent.ownerId, withData.ownerId].sort());
    expect(d.prepare('SELECT COUNT(*) AS n FROM devices WHERE owner_id = ?').get(stale.ownerId)).toEqual({ n: 0 });
  });

  it('drops shares whose message is gone', () => {
    const d = openDb(':memory:');
    const o = createOwnerWithDevice(d, 'Firefox').owner;
    d.prepare("INSERT INTO shares(id, token_hash, token, owner_id, kind, target_id, created_at) VALUES('s1', 'h', 't', ?, 'mail-message', 'm-gone', 1)").run(o.ownerId);
    expect(purgeOld(d, 90).shares).toBe(1);
  });
});
