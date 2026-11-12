-- Schema of server/src/db.ts before the notebooks (commit 4f92b4a), for the migration test. Do not edit.
CREATE TABLE IF NOT EXISTS mail_addresses (
  id TEXT PRIMARY KEY,            -- local part, e.g. "t-7k2m9q4x"
  address TEXT NOT NULL UNIQUE,
  label TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
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
  report TEXT                     -- JSON
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
  data TEXT                       -- JSON, full result
);
CREATE INDEX IF NOT EXISTS results_tool ON results(tool, created_at);
CREATE INDEX IF NOT EXISTS results_input ON results(input, created_at);
CREATE INDEX IF NOT EXISTS results_created ON results(created_at);

CREATE TABLE IF NOT EXISTS dmarc_reports (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  domain TEXT NOT NULL,
  org_name TEXT,
  report_id TEXT,
  date_begin INTEGER,
  date_end INTEGER,
  messages INTEGER,
  data TEXT NOT NULL,
  UNIQUE(org_name, report_id)
);
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
