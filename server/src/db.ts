// SQLite storage. Every row carries created_at (ms epoch) so the retention purge is one query per table.
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { config } from './config.js';
import { days, now } from './lib/time.js';
import { currentOwnerId } from './owner.js';

export type DB = Database.Database;

/** DMARC reports: the duplicate check (org_name + report_id) is per notebook. */
const dmarcTable = (name: string) => `CREATE TABLE IF NOT EXISTS ${name} (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  domain TEXT NOT NULL,
  org_name TEXT,
  report_id TEXT,
  date_begin INTEGER,
  date_end INTEGER,
  messages INTEGER,
  data TEXT NOT NULL,
  owner_id TEXT,
  UNIQUE(owner_id, org_name, report_id)
);`;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS mail_addresses (
  id TEXT PRIMARY KEY,            -- local part, e.g. "t-7k2m9q4x"
  address TEXT NOT NULL UNIQUE,
  label TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  owner_id TEXT,                  -- notebook (owner.ts); NULL: legacy row, visible to nobody
  lang TEXT                       -- language of the interface that made it: the report of a message received by SMTP is written in it
);
CREATE TABLE IF NOT EXISTS mail_messages (
  id TEXT PRIMARY KEY,
  address_id TEXT NOT NULL REFERENCES mail_addresses(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  via TEXT NOT NULL,              -- smtp | imap | upload
  client_ip TEXT,
  client_ptr TEXT,
  helo TEXT,
  mail_from TEXT,
  rcpt_to TEXT,
  tls TEXT,                       -- JSON: protocol, cipher
  from_addr TEXT,
  from_domain TEXT,
  subject TEXT,
  size INTEGER,
  raw BLOB NOT NULL,
  status TEXT NOT NULL,           -- received | analyzing | done | error
  score REAL,
  report TEXT,                    -- JSON
  owner_id TEXT                   -- notebook of the request (upload) or of the recipient address
);
CREATE INDEX IF NOT EXISTS mail_messages_address ON mail_messages(address_id, created_at);
CREATE INDEX IF NOT EXISTS mail_messages_created ON mail_messages(created_at);
CREATE INDEX IF NOT EXISTS mail_messages_domain ON mail_messages(from_domain, created_at);

CREATE TABLE IF NOT EXISTS results (
  id TEXT PRIMARY KEY,
  tool TEXT NOT NULL,
  input TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  score REAL,
  summary TEXT,                   -- JSON, small
  data TEXT,                      -- JSON, full result
  owner_id TEXT
);
CREATE INDEX IF NOT EXISTS results_tool ON results(tool, created_at);
CREATE INDEX IF NOT EXISTS results_input ON results(input, created_at);
CREATE INDEX IF NOT EXISTS results_created ON results(created_at);

${dmarcTable('dmarc_reports')}
CREATE INDEX IF NOT EXISTS dmarc_domain ON dmarc_reports(domain, date_begin);

CREATE TABLE IF NOT EXISTS resolvers (
  ip TEXT PRIMARY KEY,
  name TEXT,
  provider TEXT,
  country_code TEXT,
  city TEXT,
  lat REAL,
  lon REAL,
  anycast INTEGER NOT NULL DEFAULT 0,
  filtering TEXT,
  source TEXT,
  created_at INTEGER NOT NULL,
  qualified_at INTEGER,
  qualified INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER,
  reasons TEXT                    -- JSON array of failed checks
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Notebooks (owner.ts): one per browser, or several browsers linked by a code.
CREATE TABLE IF NOT EXISTS owners (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,  -- sha256 hex of the cookie secret; the secret is never stored
  label TEXT,                       -- "Chrome sur Linux", never the full User-Agent
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS devices_owner ON devices(owner_id);
CREATE TABLE IF NOT EXISTS link_codes (
  code_hash TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS link_codes_owner ON link_codes(owner_id);
-- Read-only links to one mail report. The token is also kept in clear (column token) so that the
-- owner's message view can show the link again: acceptable because only the owner reads it, and
-- the owner can already read the message itself. Lookups go through token_hash.
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  token TEXT NOT NULL,
  owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,               -- 'mail-message'
  target_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by_device TEXT            -- revoked when this device leaves the notebook
);
CREATE UNIQUE INDEX IF NOT EXISTS shares_target ON shares(kind, target_id);
`;

/** Indexes on owner_id: created after the migration, the column may not exist before it. */
const OWNER_INDEXES = `
CREATE INDEX IF NOT EXISTS results_owner ON results(owner_id, created_at);
CREATE INDEX IF NOT EXISTS mail_messages_owner ON mail_messages(owner_id, created_at);
CREATE INDEX IF NOT EXISTS mail_addresses_owner ON mail_addresses(owner_id);
CREATE INDEX IF NOT EXISTS dmarc_owner ON dmarc_reports(owner_id, domain);
`;

const columns = (d: DB, table: string) => (d.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]).map((c) => c.name);

/** Unique index (or constraint) on exactly these columns, in this order. */
function hasUnique(d: DB, table: string, cols: string[]): boolean {
  const idx = d.prepare(`PRAGMA index_list(${table})`).all() as { name: string; unique: number }[];
  return idx.some((i) => {
    if (!i.unique) return false;
    const c = (d.prepare(`PRAGMA index_info(${JSON.stringify(i.name)})`).all() as { seqno: number; name: string }[])
      .sort((a, b) => a.seqno - b.seqno)
      .map((x) => x.name);
    return c.length === cols.length && c.every((n, k) => n === cols[k]);
  });
}

/**
 * Guarded migration of a database created before the notebooks (2026-11-11): add owner_id where it
 * is missing, and make the DMARC duplicate check per notebook (the old UNIQUE(org_name, report_id)
 * is a table constraint: the table is rebuilt). Existing rows keep owner_id NULL: visible to nobody,
 * they leave with the normal retention purge. Safe to run on every start.
 */
export function migrate(d: DB) {
  d.transaction(() => {
    for (const t of ['results', 'mail_addresses', 'mail_messages', 'dmarc_reports']) {
      if (!columns(d, t).includes('owner_id')) d.exec(`ALTER TABLE ${t} ADD COLUMN owner_id TEXT`);
    }
    // shares created before 2026-11-11 (review): the device that made them is unknown, left NULL
    // language of the test address (i18n, 2026-11-12): legacy rows stay NULL, their reports are written in English
    if (!columns(d, 'mail_addresses').includes('lang')) d.exec('ALTER TABLE mail_addresses ADD COLUMN lang TEXT');
    if (!columns(d, 'shares').includes('created_by_device')) d.exec('ALTER TABLE shares ADD COLUMN created_by_device TEXT');
    if (hasUnique(d, 'dmarc_reports', ['org_name', 'report_id'])) {
      const cols = 'id, created_at, domain, org_name, report_id, date_begin, date_end, messages, data, owner_id';
      d.exec(`DROP TABLE IF EXISTS dmarc_reports_v2;
        ${dmarcTable('dmarc_reports_v2')}
        INSERT INTO dmarc_reports_v2(${cols}) SELECT ${cols} FROM dmarc_reports;
        DROP TABLE dmarc_reports;
        ALTER TABLE dmarc_reports_v2 RENAME TO dmarc_reports;
        CREATE INDEX IF NOT EXISTS dmarc_domain ON dmarc_reports(domain, date_begin);`);
    }
    d.exec(OWNER_INDEXES);
  })();
}

let db: DB | undefined;

export function openDb(file = path.join(config.dataDir, 'check.sqlite')): DB {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const d = new Database(file);
  d.pragma('journal_mode = WAL');
  d.pragma('foreign_keys = ON');
  d.exec(SCHEMA);
  migrate(d);
  return d;
}

export function getDb(): DB {
  if (!db) db = openDb();
  return db;
}

export function setDb(d: DB) {
  db = d;
}

/** An empty notebook whose devices have not been seen for this long is removed. */
export const EMPTY_NOTEBOOK_DAYS = 7;

/** Delete everything older than the retention window. Returns rows removed per table. */
export function purgeOld(d: DB = getDb(), retentionDays = config.retentionDays, at = now()) {
  const cutoff = at - days(retentionDays);
  const out: Record<string, number> = {};
  const tx = d.transaction(() => {
    out.mail_messages = d.prepare('DELETE FROM mail_messages WHERE created_at < ?').run(cutoff).changes;
    out.mail_addresses = d
      .prepare(
        'DELETE FROM mail_addresses WHERE created_at < ? AND id NOT IN (SELECT DISTINCT address_id FROM mail_messages)',
      )
      .run(cutoff).changes;
    out.results = d.prepare('DELETE FROM results WHERE created_at < ?').run(cutoff).changes;
    out.dmarc_reports = d.prepare('DELETE FROM dmarc_reports WHERE created_at < ?').run(cutoff).changes;
    out.link_codes = d.prepare('DELETE FROM link_codes WHERE expires_at < ?').run(at).changes;
    // a browser not seen for the whole retention window has no data left of its own
    out.devices = d.prepare('DELETE FROM devices WHERE last_seen_at < ?').run(cutoff).changes;
    // a notebook without any device can no longer be opened: its data goes with it (no orphan data)
    const orphan = 'SELECT id FROM owners WHERE id NOT IN (SELECT owner_id FROM devices)';
    for (const t of ['shares', 'link_codes', 'mail_messages', 'mail_addresses', 'results', 'dmarc_reports']) {
      out[t] = (out[t] ?? 0) + d.prepare(`DELETE FROM ${t} WHERE owner_id IN (${orphan})`).run().changes;
    }
    out.owners = d.prepare(`DELETE FROM owners WHERE id IN (${orphan})`).run().changes;
    // empty notebooks (no data at all) whose devices have not been seen for 7 days: a browser that
    // looked once and never came back, or a forged cookie (2026-11-11 review)
    const empty = `SELECT id FROM owners WHERE id NOT IN (SELECT owner_id FROM devices WHERE last_seen_at >= @seen)
      AND id NOT IN (SELECT owner_id FROM results WHERE owner_id IS NOT NULL)
      AND id NOT IN (SELECT owner_id FROM mail_messages WHERE owner_id IS NOT NULL)
      AND id NOT IN (SELECT owner_id FROM mail_addresses WHERE owner_id IS NOT NULL)
      AND id NOT IN (SELECT owner_id FROM dmarc_reports WHERE owner_id IS NOT NULL)`;
    const seen = at - days(EMPTY_NOTEBOOK_DAYS);
    for (const t of ['shares', 'link_codes', 'devices']) d.prepare(`DELETE FROM ${t} WHERE owner_id IN (${empty})`).run({ seen });
    out.empty_owners = d.prepare(`DELETE FROM owners WHERE id IN (${empty})`).run({ seen }).changes;
    out.shares += d.prepare("DELETE FROM shares WHERE kind = 'mail-message' AND target_id NOT IN (SELECT id FROM mail_messages)").run().changes;
  });
  tx();
  return out;
}

export function startRetentionJob(d: DB = getDb()) {
  purgeOld(d);
  const t = setInterval(() => purgeOld(d), days(1));
  t.unref();
  return t;
}

export function getSetting<T>(key: string, fallback: T, d: DB = getDb()): T {
  const row = d.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
  return row ? (JSON.parse(row.value) as T) : fallback;
}

export function setSetting(key: string, value: unknown, d: DB = getDb()) {
  d.prepare('INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(
    key,
    JSON.stringify(value),
  );
}

/** Store a tool result in the history and return its id. */
export function saveResult(
  tool: string,
  input: string,
  data: unknown,
  opts: { score?: number | null; summary?: unknown; id?: string; ownerId?: string | null } = {},
  d: DB = getDb(),
): string {
  const id = opts.id ?? newId();
  // the notebook of the request being served (AsyncLocalStorage); null for background jobs
  const ownerId = opts.ownerId !== undefined ? opts.ownerId : currentOwnerId();
  d.prepare('INSERT INTO results(id, tool, input, created_at, score, summary, data, owner_id) VALUES(?,?,?,?,?,?,?,?)').run(
    id,
    tool,
    input.toLowerCase().trim(),
    now(),
    opts.score ?? null,
    opts.summary === undefined ? null : JSON.stringify(opts.summary),
    JSON.stringify(data),
    ownerId,
  );
  return id;
}

const ALPHABET = '23456789abcdefghjkmnpqrstuvwxyz';
export function newId(len = 10): string {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let s = '';
  for (const b of bytes) s += ALPHABET[b % ALPHABET.length];
  return s;
}
