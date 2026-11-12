// Storage of test addresses and received messages (tables mail_addresses, mail_messages).
import { randomInt } from 'node:crypto';
import type { DB } from '../db.js';
import { currentLang } from '../i18n.js';
import { now } from '../lib/time.js';

export interface AddressRow {
  id: string;
  address: string;
  label: string | null;
  created_at: number;
  expires_at: number;
  /** notebook (owner.ts); null for the shared 'upload' pseudo-address and legacy rows */
  owner_id: string | null;
  /** language of the interface that created it (i18n.ts) */
  lang?: string | null;
}

export interface MessageRow {
  id: string;
  address_id: string;
  created_at: number;
  via: 'smtp' | 'imap' | 'upload';
  client_ip: string | null;
  client_ptr: string | null;
  helo: string | null;
  mail_from: string | null;
  rcpt_to: string | null;
  tls: string | null;
  from_addr: string | null;
  from_domain: string | null;
  subject: string | null;
  size: number | null;
  raw: Buffer;
  status: 'received' | 'analyzing' | 'done' | 'error';
  score: number | null;
  report: string | null;
  /** notebook: of the request for an upload, of the recipient address for SMTP / IMAP */
  owner_id: string | null;
}

export type MessageMeta = Omit<MessageRow, 'raw' | 'report'>;

const ID_ALPHABET = '23456789abcdefghjkmnpqrstuvwxyz';

/** Short, readable, unambiguous id: "t-" + 8 characters without 0/o/1/l/i. */
export function newAddressId(): string {
  let s = 't-';
  for (let i = 0; i < 8; i++) s += ID_ALPHABET[randomInt(ID_ALPHABET.length)];
  return s;
}

export function newMessageId(): string {
  let s = 'm-';
  for (let i = 0; i < 12; i++) s += ID_ALPHABET[randomInt(ID_ALPHABET.length)];
  return s;
}

/** Address ids are case-insensitive local parts; anything else is not ours. */
export function normaliseAddressId(local: string): string | undefined {
  const id = local.trim().toLowerCase();
  return /^t-[a-z0-9]{4,32}$/.test(id) ? id : undefined;
}

export function createAddress(db: DB, domain: string, ttlHours: number, label?: string, ownerId: string | null = null): AddressRow {
  for (let attempt = 0; attempt < 10; attempt++) {
    const id = newAddressId();
    const row: AddressRow = {
      id,
      address: `${id}@${domain}`,
      label: label?.slice(0, 120) || null,
      created_at: now(),
      expires_at: now() + ttlHours * 3600 * 1000,
      owner_id: ownerId,
      lang: currentLang(),
    };
    try {
      db.prepare('INSERT INTO mail_addresses(id, address, label, created_at, expires_at, owner_id, lang) VALUES(?,?,?,?,?,?,?)').run(
        row.id,
        row.address,
        row.label,
        row.created_at,
        row.expires_at,
        row.owner_id,
        row.lang,
      );
      return row;
    } catch (e) {
      if (!/UNIQUE/i.test((e as Error).message)) throw e;
    }
  }
  throw new Error('Could not allocate a unique address id');
}

/** Pseudo-address that holds imported messages (never active: it receives nothing by SMTP). */
export const UPLOAD_ADDRESS_ID = 'upload';

export function ensureUploadAddress(db: DB, domain: string): string {
  db.prepare('INSERT OR IGNORE INTO mail_addresses(id, address, label, created_at, expires_at) VALUES(?,?,?,?,0)').run(
    UPLOAD_ADDRESS_ID,
    `${UPLOAD_ADDRESS_ID}@${domain}`,
    'Messages importés',
    now(),
  );
  return UPLOAD_ADDRESS_ID;
}

export function getAddress(db: DB, id: string): AddressRow | undefined {
  return db.prepare('SELECT * FROM mail_addresses WHERE id = ?').get(id.toLowerCase()) as AddressRow | undefined;
}

/**
 * Address as seen by a notebook: its own addresses, plus the shared 'upload' pseudo-address (whose
 * messages are then filtered per notebook). Another notebook's address answers like a missing one.
 */
export function getOwnedAddress(db: DB, id: string, ownerId: string | null): AddressRow | undefined {
  const a = getAddress(db, id);
  if (!a) return undefined;
  if (a.id === UPLOAD_ADDRESS_ID) return a;
  return ownerId && a.owner_id === ownerId ? a : undefined;
}

/** Address that can still receive mail. */
export function activeAddress(db: DB, id: string, at = now()): AddressRow | undefined {
  const a = getAddress(db, id);
  return a && a.expires_at > at ? a : undefined;
}

const META_COLS =
  'id, address_id, created_at, via, client_ip, client_ptr, helo, mail_from, rcpt_to, tls, from_addr, from_domain, subject, size, status, score, owner_id';

/** Every message of an address, whatever its notebook: internal use only (routes use listOwnedMessages). */
export function listMessages(db: DB, addressId: string): MessageMeta[] {
  return db.prepare(`SELECT ${META_COLS} FROM mail_messages WHERE address_id = ? ORDER BY created_at DESC`).all(addressId) as MessageMeta[];
}

/** Messages of an address that belong to this notebook (always filtered on the message, never through the address). */
export function listOwnedMessages(db: DB, addressId: string, ownerId: string | null): MessageMeta[] {
  return db
    .prepare(`SELECT ${META_COLS} FROM mail_messages WHERE address_id = ? AND owner_id = ? ORDER BY created_at DESC`)
    .all(addressId, ownerId) as MessageMeta[];
}

/** Any message: internal use only (analysis, ingestion). Routes use getOwnedMessage. */
export function getMessage(db: DB, id: string): MessageRow | undefined {
  return db.prepare('SELECT * FROM mail_messages WHERE id = ?').get(id) as MessageRow | undefined;
}

/** A message of this notebook; another notebook's message (or a legacy one) answers like a missing one. */
export function getOwnedMessage(db: DB, id: string, ownerId: string | null): MessageRow | undefined {
  if (!ownerId) return undefined;
  return db.prepare('SELECT * FROM mail_messages WHERE id = ? AND owner_id = ?').get(id, ownerId) as MessageRow | undefined;
}

export function insertMessage(
  db: DB,
  row: Omit<MessageRow, 'score' | 'report' | 'owner_id'> & { score?: number | null; report?: string | null; owner_id?: string | null },
) {
  db.prepare(
    `INSERT INTO mail_messages(id, address_id, created_at, via, client_ip, client_ptr, helo, mail_from, rcpt_to, tls,
      from_addr, from_domain, subject, size, raw, status, score, report, owner_id)
     VALUES(@id, @address_id, @created_at, @via, @client_ip, @client_ptr, @helo, @mail_from, @rcpt_to, @tls,
      @from_addr, @from_domain, @subject, @size, @raw, @status, @score, @report, @owner_id)`,
  ).run({ score: null, report: null, owner_id: null, ...row });
}

export function updateMessage(db: DB, id: string, fields: Partial<Omit<MessageRow, 'id' | 'raw' | 'owner_id'>>) {
  const keys = Object.keys(fields);
  if (!keys.length) return;
  db.prepare(`UPDATE mail_messages SET ${keys.map((k) => `${k} = @${k}`).join(', ')} WHERE id = @id`).run({ ...fields, id });
}

/** History (US-037) of one notebook: newest first, filtered by From domain and free text (subject, sender, address). */
export function history(
  db: DB,
  opts: { ownerId: string | null; domain?: string; q?: string; from?: number; to?: number; limit?: number; offset?: number },
): { items: MessageMeta[]; total: number } {
  const where: string[] = ['owner_id = @ownerId'];
  const args: Record<string, unknown> = { ownerId: opts.ownerId };
  if (opts.domain) {
    where.push('(from_domain = @domain OR from_domain LIKE @domainSub)');
    args.domain = opts.domain.toLowerCase();
    args.domainSub = `%.${opts.domain.toLowerCase()}`;
  }
  if (opts.q) {
    where.push(
      "(subject LIKE @q ESCAPE '\\' OR from_addr LIKE @q ESCAPE '\\' OR mail_from LIKE @q ESCAPE '\\' OR address_id LIKE @q ESCAPE '\\' OR client_ip LIKE @q ESCAPE '\\')",
    );
    args.q = `%${opts.q.replace(/[%_]/g, (c) => '\\' + c)}%`;
  }
  if (opts.from) {
    where.push('created_at >= @fromTs');
    args.fromTs = opts.from;
  }
  if (opts.to) {
    where.push('created_at <= @toTs');
    args.toTs = opts.to;
  }
  const w = `WHERE ${where.join(' AND ')}`;
  const total = (db.prepare(`SELECT COUNT(*) AS n FROM mail_messages ${w}`).get(args) as { n: number }).n;
  const items = db
    .prepare(`SELECT ${META_COLS} FROM mail_messages ${w} ORDER BY created_at DESC LIMIT @limit OFFSET @offset`)
    .all({ ...args, limit: Math.min(opts.limit ?? 50, 200), offset: opts.offset ?? 0 }) as MessageMeta[];
  return { items, total };
}
