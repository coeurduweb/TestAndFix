import { describe, expect, it } from 'vitest';
import { openDb, purgeOld, saveResult, newId } from './db.js';
import { checkToken, hashPassword, makeToken, revokeSessions, verifyPassword } from './auth.js';
import { fill, scoreOf, sortFindings, type Finding } from './knowledge/engine.js';
import { dnsblName, isPublicIp, reverseName } from './lib/net.js';
import { days } from './lib/time.js';

describe('retention', () => {
  it('purges rows older than the window and keeps recent ones', () => {
    const db = openDb(':memory:');
    const t = Date.now();
    db.prepare('INSERT INTO results(id,tool,input,created_at) VALUES(?,?,?,?)').run('old', 'spf', 'a.fr', t - days(91));
    db.prepare('INSERT INTO results(id,tool,input,created_at) VALUES(?,?,?,?)').run('new', 'spf', 'a.fr', t - days(89));
    db.prepare('INSERT INTO mail_addresses(id,address,created_at,expires_at) VALUES(?,?,?,?)').run('a1', 'a1@x', t - days(100), 0);
    db.prepare(
      "INSERT INTO mail_messages(id,address_id,created_at,via,raw,status) VALUES('m1','a1',?, 'smtp', x'00', 'done')",
    ).run(t - days(95));
    const out = purgeOld(db, 90, t);
    expect(out.results).toBe(1);
    expect(out.mail_messages).toBe(1);
    expect(out.mail_addresses).toBe(1);
    expect(db.prepare('SELECT id FROM results').all()).toEqual([{ id: 'new' }]);
  });
  it('saves results with normalised input', () => {
    const db = openDb(':memory:');
    const id = saveResult('dmarc', '  Exemple.FR ', { ok: 1 }, { score: 8 }, db);
    expect(db.prepare('SELECT input, score FROM results WHERE id=?').get(id)).toEqual({ input: 'exemple.fr', score: 8 });
    expect(newId()).toMatch(/^[a-z0-9]{10}$/);
  });
});

describe('auth', () => {
  it('hashes and verifies passwords', () => {
    const h = hashPassword('s3cret');
    expect(verifyPassword('s3cret', h)).toBe(true);
    expect(verifyPassword('nope', h)).toBe(false);
  });
  it('signs session tokens that expire', () => {
    process.env.CHECK_SESSION_SECRET = 'x';
    const tok = makeToken(0);
    expect(checkToken(tok, 1000)).toBe(true);
    expect(checkToken(tok, days(31))).toBe(false);
    expect(checkToken(tok.replace(/.$/, 'A'), 1000)).toBe(false);
    expect(checkToken('garbage')).toBe(false);
  });
  it('revokes every open session on logout', () => {
    process.env.CHECK_SESSION_SECRET = 'x';
    const tok = makeToken(0);
    expect(checkToken(tok, days(29))).toBe(true);
    revokeSessions();
    expect(checkToken(tok, 1000)).toBe(false);
    expect(checkToken(makeToken(0), 1000)).toBe(true);
  });
});

describe('knowledge engine', () => {
  it('fills variables and words unknown ones', () => {
    expect(fill('Le SPF de {domain} a {lookup_count} requêtes', { domain: 'a.fr', lookup_count: 11 })).toBe(
      'Le SPF de a.fr a 11 requêtes',
    );
    expect(fill('Signez avec {selector}', {})).toBe('Signez avec votre sélecteur');
  });
  it('does not repeat the noun when an unknown variable follows it (message read over IMAP)', () => {
    expect(fill("L'IP {ip} est refusée par le SPF de {envelope_domain} (fail)", { envelope_domain: 'example.net' })).toBe(
      "L'IP d'envoi est refusée par le SPF de example.net (fail)",
    );
    expect(fill('Le domaine {domain} et le HELO {helo}', {})).toBe('Le domaine concerné et le HELO annoncé');
    expect(fill("L'IP {ip} est listée", { ip: '192.0.2.1' })).toBe("L'IP 192.0.2.1 est listée");
    expect(fill('Vérifiez {ip}', {})).toBe("Vérifiez l'IP d'envoi");
  });
  it('scores and sorts findings', () => {
    const f = (id: string, severity: Finding['severity'], penalty: number) =>
      ({ id, severity, penalty, family: 'x', title: id, why: '', fix: [], references: [] }) as Finding;
    const list = [f('b', 'low', 0.1), f('a', 'critical', 2), f('c', 'high', 1)];
    expect(sortFindings(list).map((x) => x.id)).toEqual(['a', 'c', 'b']);
    expect(scoreOf(list)).toBe(6.9);
    expect(scoreOf([f('z', 'critical', 20)])).toBe(0);
  });
});

describe('net helpers', () => {
  it('classifies IPs', () => {
    expect(isPublicIp('8.8.8.8')).toBe(true);
    expect(isPublicIp('10.0.0.1')).toBe(false);
    expect(isPublicIp('127.0.0.1')).toBe(false);
    expect(isPublicIp('::ffff:192.168.1.1')).toBe(false);
    expect(isPublicIp('2001:4860:4860::8888')).toBe(true);
  });
  it('builds reverse and DNSBL names', () => {
    expect(reverseName('203.0.113.7')).toBe('7.113.0.203.in-addr.arpa');
    expect(dnsblName('203.0.113.7', 'zen.spamhaus.org')).toBe('7.113.0.203.zen.spamhaus.org');
    expect(reverseName('2001:db8::1').endsWith('8.b.d.0.1.0.0.2.ip6.arpa')).toBe(true);
  });
});

describe('explain() priority', () => {
  it('top-level context overrides the base, fallback only fills missing ids', async () => {
    const { explain, knowledge } = await import('./knowledge/engine.js');
    const id = [...knowledge().keys()].find((k) => k.startsWith('blacklist.'))!;
    const base = explain({ id });
    expect(explain({ id, fallback: { title: 'x', severity: 'info', penalty: 0.1 } }).penalty).toBe(base.penalty);
    const ctx = explain({ id, severity: 'info', penalty: 0.1 });
    expect(ctx.penalty).toBe(0.1);
    expect(ctx.title).toBe(base.title);
    const missing = explain({ id: 'nope.nothing', fallback: { title: 'T', severity: 'low', penalty: 0.2 } });
    expect(missing).toMatchObject({ title: 'T', penalty: 0.2, fallback: true });
  });
});
