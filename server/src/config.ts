// Runtime configuration, read once from the environment (TESTANDFIX_* or the older CHECK_* names).
import './env-alias.js';
import path from 'node:path';

const env = process.env;
const int = (v: string | undefined, d: number) => (v && /^\d+$/.test(v) ? Number(v) : d);
const dataDir = path.resolve(env.CHECK_DATA_DIR ?? path.join(process.cwd(), '..', 'data'));
const selftestIntervalHours = Math.max(1, int(env.CHECK_SELFTEST_INTERVAL_HOURS, 6));

export const config = {
  host: env.CHECK_HOST ?? '0.0.0.0',
  port: int(env.CHECK_PORT, 3000),
  publicUrl: env.CHECK_PUBLIC_URL ?? 'http://localhost:3000',
  dataDir,
  retentionDays: int(env.CHECK_RETENTION_DAYS, 90),
  /**
   * Daily online copy of the SQLite database (backup.ts, US-098). Keep it inside the data volume:
   * the default is <data>/backups. keep = 0 disables the backups.
   */
  backup: {
    dir: path.resolve(env.CHECK_BACKUP_DIR ?? path.join(dataDir, 'backups')),
    keep: int(env.CHECK_BACKUP_KEEP, 14),
  },
  /** scrypt hash "scrypt$<salt hex>$<hash hex>" produced by `npm run hash-password`. */
  passwordHash: env.CHECK_PASSWORD_HASH ?? '',
  /** Plain password, accepted only when no hash is set (development). */
  password: env.CHECK_PASSWORD ?? '',
  sessionSecret: env.CHECK_SESSION_SECRET ?? '',
  sessionDays: int(env.CHECK_SESSION_DAYS, 30),
  mail: {
    domain: (env.CHECK_MAIL_DOMAIN ?? 'testandfix.localhost').toLowerCase(),
    smtpPort: int(env.CHECK_SMTP_PORT, 2525),
    smtpHost: env.CHECK_SMTP_HOST ?? '0.0.0.0',
    smtpBanner: env.CHECK_SMTP_BANNER ?? '',
    /**
     * Relays whose XFORWARD is trusted (client IP, name, HELO of the original connection), as a
     * list of CIDR separated by commas or spaces, e.g. "172.16.0.0/12,127.0.0.1/32". Empty: XFORWARD
     * is refused. Behind a host MTA, relay only the test domain to the container (see docs).
     */
    trustedRelays: (env.CHECK_SMTP_TRUSTED_RELAYS ?? '').split(/[\s,]+/).filter(Boolean),
    tlsKey: env.CHECK_SMTP_TLS_KEY ?? '',
    tlsCert: env.CHECK_SMTP_TLS_CERT ?? '',
    maxSize: int(env.CHECK_SMTP_MAX_SIZE, 25 * 1024 * 1024),
    addressTtlHours: int(env.CHECK_ADDRESS_TTL_HOURS, 24 * 7),
  },
  imap: {
    host: env.CHECK_IMAP_HOST ?? '',
    port: int(env.CHECK_IMAP_PORT, 993),
    secure: (env.CHECK_IMAP_SECURE ?? 'true') !== 'false',
    user: env.CHECK_IMAP_USER ?? '',
    pass: env.CHECK_IMAP_PASS ?? '',
    mailbox: env.CHECK_IMAP_MAILBOX ?? 'INBOX',
    /** Domain of the catch-all mailbox (addresses <id>@<domain> are matched there). */
    domain: (env.CHECK_IMAP_DOMAIN ?? '').toLowerCase(),
    /**
     * CA to trust for the IMAP server instead of the public ones (PEM text or path to a PEM file),
     * for a server with a self-signed or private certificate. The certificate is always verified
     * (chain and host name): there is no switch to turn verification off.
     */
    tlsCa: env.CHECK_IMAP_TLS_CA ?? '',
  },
  /**
   * Reception self-test (selftest.ts, US-099): every intervalHours a message is sent to a hidden
   * test address through smtpHost:smtpPort and must come back into our own SMTP server. Disabled
   * when smtpHost is empty. Production: the public name, port 25 (through the host's Postfix relay).
   */
  selftest: {
    smtpHost: env.CHECK_SELFTEST_SMTP_HOST ?? '',
    smtpPort: int(env.CHECK_SELFTEST_SMTP_PORT, 25),
    intervalHours: selftestIntervalHours,
    timeoutSec: int(env.CHECK_SELFTEST_TIMEOUT_SEC, 120),
    /** /api/health/reception answers 503 when the last success is older than this. */
    maxAgeMinutes: int(env.CHECK_SELFTEST_MAX_AGE_MINUTES, 2 * selftestIntervalHours * 60 + 30),
  },
  spamd: {
    host: env.SPAMD_HOST ?? '127.0.0.1',
    port: int(env.SPAMD_PORT, 783),
  },
  keys: {
    safeBrowsing: env.GSB_API_KEY ?? '',
    virusTotal: env.VT_API_KEY ?? '',
    abuseIpdb: env.ABUSEIPDB_API_KEY ?? '',
    urlhaus: env.URLHAUS_AUTH_KEY ?? '',
  },
  agent: {
    /** Agent on the host that runs the tool (server-side cache flush). */
    url: env.CHECK_AGENT_URL ?? 'http://127.0.0.1:47625',
    token: env.CHECK_AGENT_TOKEN ?? '',
  },
  isProd: env.NODE_ENV === 'production',
};

export type Config = typeof config;
