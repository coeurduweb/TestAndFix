import { describe, expect, it } from 'vitest';
import { analyzeMessage } from './index.js';
import { buildDmarc, suggestSpf, alignmentOf } from './auth.js';
import { parseListUnsubscribe } from './unsubscribe.js';
import { deps, fakeResolver, fixture, goodZone, rsaKey, sign, SENDER_IP } from '../test-helpers.js';
import type { AnalyzeInput } from './types.js';
import type { Fetcher } from './types.js';

const key = rsaKey();
const smtpInput = (raw: Buffer, extra: Partial<AnalyzeInput> = {}): AnalyzeInput => ({
  raw,
  via: 'smtp',
  clientIp: SENDER_IP,
  helo: 'mail.atelier-exemple.fr',
  mailFrom: 'bounce@atelier-exemple.fr',
  rcptTo: ['t-abcd2345@check.localhost'],
  tls: { protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384' },
  receivedAt: new Date('2026-11-10T15:00:00Z'),
  ...extra,
});
const ids = (r: { findings: { id: string }[] }) => r.findings.map((f) => f.id);

describe('analysis of a clean, signed message', () => {
  it('passes SPF, DKIM, DMARC with alignment and scores high', async () => {
    const raw = await sign(fixture('clean.eml'), 'atelier-exemple.fr', 's1', key.privateKey);
    const r = await analyzeMessage(smtpInput(raw), deps(fakeResolver(goodZone(key.record))));
    const auth = r.data.auth as {
      spf: { result: string };
      dkim: { result: string; keyBits: number; aligned: string; signedHeaders: string[] }[];
      dmarc: { result: string; p: string };
      alignment: { aligned: boolean; spf: { aligned: string } };
    };
    expect(auth.spf.result).toBe('pass');
    expect(auth.dkim[0]).toMatchObject({ result: 'pass', keyBits: 2048, aligned: 'strict' });
    expect(auth.dkim[0].signedHeaders).toContain('from');
    expect(auth.dmarc).toMatchObject({ result: 'pass', p: 'reject' });
    expect(auth.alignment.aligned).toBe(true);
    expect(r.score).toBeGreaterThanOrEqual(9.5);
    expect(r.findings.filter((f) => f.penalty >= 0.5)).toEqual([]);
    expect(r.passed.map((p) => p.id)).toEqual(expect.arrayContaining(['spf.pass', 'dmarc.pass', 'rdns.fcrdns', 'tls.inbound', 'alignment.ok']));
    // every point lost is explained by a finding (US-025)
    const lost = r.findings.reduce((n, f) => n + f.penalty, 0);
    expect(Math.round((10 - lost) * 10) / 10).toBe(r.score);
    expect(r.data.scoring.total).toBe(r.score);
  });

  it('reports a body changed after signing, a missing key and a short key', async () => {
    const raw = await sign(fixture('clean.eml'), 'atelier-exemple.fr', 's1', key.privateKey);
    const tampered = Buffer.from(raw.toString('latin1').replace('terrasse en bois', 'terrasse en pierre'), 'latin1');
    const r1 = await analyzeMessage(smtpInput(tampered), deps(fakeResolver(goodZone(key.record))));
    expect(ids(r1)).toContain('dkim.body_hash_mismatch');

    const r2 = await analyzeMessage(smtpInput(raw), deps(fakeResolver(goodZone())));
    expect(ids(r2)).toContain('dkim.key_not_found');
    expect(r2.findings.find((f) => f.id === 'dkim.key_not_found')?.evidence).toContain('s=s1');

    const small = rsaKey(1024);
    const raw3 = await sign(fixture('clean.eml'), 'atelier-exemple.fr', 's1', small.privateKey);
    const r3 = await analyzeMessage(smtpInput(raw3), deps(fakeResolver(goodZone(small.record))));
    expect(ids(r3)).toContain('dkim.key_1024');
  });

  it('flags l= and t=y signatures', async () => {
    const z = goodZone(key.record.replace('v=DKIM1;', 'v=DKIM1; t=y;'));
    const raw = await sign(fixture('clean.eml'), 'atelier-exemple.fr', 's1', key.privateKey);
    const r = await analyzeMessage(smtpInput(raw), deps(fakeResolver(z)));
    expect(ids(r)).toContain('dkim.key_testing_flag');
  });
});

describe('authentication failures and corrections', () => {
  it('suggests an SPF record with the detected provider include', async () => {
    const zone = goodZone(key.record);
    zone['atelier-exemple.fr'].TXT = [['v=spf1 mx ?all']];
    zone['atelier-exemple.fr'].MX = [{ exchange: 'mx.ailleurs.fr', priority: 10 }];
    const raw = Buffer.concat([Buffer.from('X-SG-EID: abc\r\n'), fixture('clean.eml')]);
    const r = await analyzeMessage(smtpInput(raw, { clientIp: '167.89.1.2', helo: 'o1.ptr1234.sendgrid.net' }), deps(fakeResolver(zone)));
    const f = r.findings.find((x) => x.id.startsWith('spf.neutral'));
    expect(f).toBeDefined();
    expect(f!.suggested).toBe('v=spf1 mx include:sendgrid.net ~all');
    expect(r.data.provider?.key).toBe('sendgrid');
  });

  it('suggests a DMARC record when none is published, and reports missing alignment', async () => {
    const zone = goodZone();
    delete zone['_dmarc.atelier-exemple.fr'];
    zone['atelier-exemple.fr'].TXT = [['v=spf1 -all']];
    const r = await analyzeMessage(smtpInput(fixture('clean.eml')), deps(fakeResolver(zone)));
    const dm = r.findings.find((x) => x.id === 'dmarc.missing');
    expect(dm?.suggested).toBe('v=DMARC1; p=none; rua=mailto:dmarc@atelier-exemple.fr');
    expect(ids(r)).toEqual(expect.arrayContaining(['spf.fail', 'dkim.missing', 'alignment.none_aligned']));
    expect(r.findings.find((x) => x.id === 'spf.fail')?.suggested).toBe('v=spf1 ip4:93.184.215.14 -all');
  });

  it('computes SPF and DMARC fixes', () => {
    expect(suggestSpf('v=spf1 include:_spf.google.com +all', { addSender: false })).toBe('v=spf1 include:_spf.google.com ~all');
    expect(suggestSpf('v=spf1 a mx -all', { include: 'spf.brevo.com', addSender: true })).toBe('v=spf1 a mx include:spf.brevo.com -all');
    expect(suggestSpf(undefined, { ip: '2001:db8::1', addSender: true })).toBe('v=spf1 ip6:2001:db8::1 ~all');
    expect(suggestSpf('v=spf1 include:spf.brevo.com -all', { include: 'spf.brevo.com', addSender: true })).toBeUndefined();
    expect(buildDmarc({ rua: 'mailto:a@b.fr', v: 'DMARC1', p: 'quarantine' })).toBe('v=DMARC1; p=quarantine; rua=mailto:a@b.fr');
    expect(alignmentOf('news.atelier-exemple.fr', 'atelier-exemple.fr')).toBe('relaxed');
    expect(alignmentOf('atelier-exemple.fr', 'atelier-exemple.fr')).toBe('strict');
    expect(alignmentOf('sendgrid.net', 'atelier-exemple.fr')).toBe(false);
  });
});

describe('content checks on real messages', () => {
  const run = async (name: string, extra: Partial<Parameters<typeof deps>[1]> = {}) => {
    const raw = await sign(fixture(name), 'atelier-exemple.fr', 's1', key.privateKey);
    return analyzeMessage(smtpInput(raw), deps(fakeResolver(goodZone(key.record)), extra));
  };

  it('message without a text part', async () => {
    const r = await run('no-text-part.eml');
    expect(ids(r)).toContain('content.no_text_part');
    expect((r.data.content as { hasText: boolean }).hasText).toBe(false);
  });

  it('shortener and a link whose text shows another site', async () => {
    const fetcher: Fetcher = async (url) =>
      url.includes('bit.ly') ? { status: 301, headers: { location: 'https://login.connexion-exemple.net/x' } } : { status: 200, headers: { 'content-type': 'text/html' } };
    const r = await run('shortener-mismatch.eml', { fetcher });
    expect(ids(r)).toEqual(expect.arrayContaining(['links.shortener', 'links.text_url_mismatch']));
    const mm = r.findings.find((f) => f.id === 'links.text_url_mismatch')!;
    expect(mm.evidence).toContain('https://www.paypal.com');
    expect(mm.evidence).toContain('login.connexion-exemple.net');
    const links = r.data.links as { url: string; check?: { finalUrl?: string; redirects: string[] } }[];
    expect(links.find((l) => l.url.includes('bit.ly'))?.check?.finalUrl).toBe('https://login.connexion-exemple.net/x');
  });

  it('broken links are found by visiting them', async () => {
    const fetcher: Fetcher = async () => ({ status: 404, headers: {} });
    const r = await run('clean.eml', { fetcher });
    expect(ids(r)).toContain('links.broken');
  });

  it('message without Message-ID', async () => {
    const r = await run('no-message-id.eml');
    expect(ids(r)).toContain('headers.message_id_missing');
  });

  it('newsletter without List-Unsubscribe-Post', async () => {
    const r = await run('newsletter-no-post.eml');
    expect(r.data.isBulk).toBe(true);
    const f = r.findings.find((x) => x.id === 'unsubscribe.one_click_post_missing');
    expect(f?.suggested).toBe('List-Unsubscribe-Post: List-Unsubscribe=One-Click');
    const req = (r.data.compliance as { requirements: { id: string; ok: boolean | null }[] }).requirements;
    expect(req.find((x) => x.id === 'one_click')?.ok).toBe(false);
    expect(req.find((x) => x.id === 'dkim')?.ok).toBe(true);
    expect(req.find((x) => x.id === 'spam_rate')?.ok).toBeNull();
  });

  it('one-click unsubscribe must be covered by DKIM', async () => {
    const base = fixture('newsletter-no-post.eml').toString('latin1').replace('Precedence: bulk\r\n', 'Precedence: bulk\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n');
    const signedWithout = await sign(Buffer.from(base, 'latin1'), 'atelier-exemple.fr', 's1', key.privateKey, 'From:To:Subject:Date:Message-ID');
    const r1 = await analyzeMessage(smtpInput(signedWithout), deps(fakeResolver(goodZone(key.record))));
    expect(ids(r1)).toContain('unsubscribe.not_dkim_signed');
    const signedWith = await sign(Buffer.from(base, 'latin1'), 'atelier-exemple.fr', 's1', key.privateKey, 'From:To:Subject:Date:Message-ID:List-Unsubscribe:List-Unsubscribe-Post');
    const r2 = await analyzeMessage(smtpInput(signedWith), deps(fakeResolver(goodZone(key.record))));
    expect(ids(r2)).not.toContain('unsubscribe.not_dkim_signed');
    expect(r2.passed.map((p) => p.id)).toContain('unsubscribe.one_click');
  });

  it('.exe attachment with a double extension', async () => {
    const r = await run('attachment-exe.eml');
    expect(ids(r)).toEqual(expect.arrayContaining(['attachments.dangerous_extension', 'attachments.double_extension']));
    expect((r.data.attachments as { filename: string }[])[0].filename).toBe('facture.pdf.exe');
    expect(r.score).toBeLessThan(6);
  });

  it('line longer than 998 characters', async () => {
    const raw = fixture('no-message-id.eml').toString('latin1') + 'x'.repeat(1200) + '\r\n';
    const r = await analyzeMessage(smtpInput(Buffer.from(raw, 'latin1')), deps(fakeResolver(goodZone())));
    expect(ids(r)).toContain('headers.line_too_long');
  });
});

describe('messages received through a mailbox or imported', () => {
  it('finds the origin IP in the Received chain and marks the deduced checks', async () => {
    const r = await analyzeMessage({ raw: fixture('via-mailbox.eml'), via: 'imap', receiverDomains: ['imap.mailhost.net'] }, deps(fakeResolver(goodZone())));
    expect(r.data.envelope).toMatchObject({ clientIp: SENDER_IP, ipSource: 'received', helo: 'mail.atelier-exemple.fr', mailFrom: 'bounce@atelier-exemple.fr' });
    expect(r.data.envelope.tls).toMatchObject({ used: true, protocol: 'TLSv1.3' });
    expect(r.data.limits.map((l) => l.check)).toEqual(expect.arrayContaining(['spf', 'dkim', 'spamassassin']));
    expect((r.data.auth as { spf: { result: string } }).spf.result).toBe('pass');
    expect(r.data.hops.map((h) => h.index)).toEqual([1, 2, 3]);
    expect(r.data.hops[1].delaySec).toBe(4);
  });

  it('pasted headers only: body checks are skipped and said so', async () => {
    const head = fixture('via-mailbox.eml').toString('latin1').split('\r\n\r\n')[0] + '\r\n';
    const r = await analyzeMessage({ raw: Buffer.from(head, 'latin1'), via: 'upload' }, deps(fakeResolver(goodZone())));
    expect(r.unavailable?.map((u) => u.source)).toContain('Contenu');
    expect(ids(r)).not.toContain('content.empty_message');
  });

  it('an import without Return-Path does not guess the envelope sender', async () => {
    const raw = fixture('via-mailbox.eml').toString('latin1').replace(/^Return-Path:.*\r\n/, '');
    const r = await analyzeMessage({ raw: Buffer.from(raw, 'latin1'), via: 'upload' }, deps(fakeResolver(goodZone())));
    expect(r.unavailable?.find((u) => u.source === 'SPF')?.reason).toMatch(/MAIL FROM/);
    expect(ids(r).filter((i) => i.startsWith('spf.') && !i.startsWith('spf.helo'))).toEqual([]);
  });
});

describe('List-Unsubscribe parsing', () => {
  it('reads RFC 2369 URIs', () => {
    expect(parseListUnsubscribe('<https://a.fr/u?x=1>, <mailto:u@a.fr>')).toEqual({ uris: ['https://a.fr/u?x=1', 'mailto:u@a.fr'], valid: true });
    expect(parseListUnsubscribe('https://a.fr/u').valid).toBe(false);
  });
});
