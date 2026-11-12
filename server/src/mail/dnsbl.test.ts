import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { checkDnsbl, loadDnsblLists, FALLBACK_LISTS, type DnsblList } from './dnsbl.js';
import { analyzeMessage } from './analyze/index.js';
import { parseHops, findOrigin } from './received.js';
import { detectProvider } from '../lib/provider.js';
import { addressIdsOf } from './imap.js';
import { deps, fakeResolver, fixture, goodZone, SENDER_IP } from './test-helpers.js';

const lists: DnsblList[] = [
  { zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN', type: 'ip', weight: 'major', status: 'alive', return_codes: { '127.0.0.2': 'SBL', '127.0.0.10': 'PBL (FAI)' }, delist_url: 'https://check.spamhaus.org/' },
  { zone: 'bl.spamcop.net', name: 'SpamCop', type: 'ip', weight: 'major', status: 'alive', return_codes: { '127.0.0.2': 'liste' }, delist_url: 'https://www.spamcop.net/bl.shtml' },
  { zone: 'rep.mailspike.net', name: 'Mailspike reputation', type: 'ip', weight: 'info', status: 'alive', return_codes: { '127.0.0.10..127.0.0.14': 'reputation mauvaise (L5 a L1)', '127.0.0.15': 'neutre', '127.0.0.16..127.0.0.20': 'bonne reputation' }, delist_url: '' },
  { zone: 'multi.surbl.org', name: 'SURBL', type: 'domain', weight: 'major', status: 'alive', return_codes: { '127.0.0.8': 'PH phishing', '127.0.0.16': 'MW malware', '127.0.0.1': 'acces bloque' }, delist_url: '' },
];

describe('DNSBL', () => {
  it('interprets listings, refusals and bitmasks', async () => {
    const r = fakeResolver({
      '14.215.184.93.zen.spamhaus.org': { A: ['127.0.0.10'], TXT: [['https://check.spamhaus.org/query/ip/93.184.215.14']] },
      '14.215.184.93.bl.spamcop.net': { A: ['127.255.255.254'] },
      'mauvais.fr.multi.surbl.org': { A: ['127.0.0.24'] },
      '14.215.184.93.rep.mailspike.net': { A: ['127.0.0.17'] },
      '15.215.184.93.rep.mailspike.net': { A: ['127.0.0.11'] },
    });
    const res = await checkDnsbl(r, { ips: [SENDER_IP], domains: ['mauvais.fr', 'propre.fr'] }, { lists });
    const by = (z: string, t: string) => res.results.find((x) => x.zone === z && x.target === t)!;
    expect(by('zen.spamhaus.org', SENDER_IP)).toMatchObject({ status: 'listed', meaning: 'PBL (FAI)', txt: 'https://check.spamhaus.org/query/ip/93.184.215.14' });
    expect(by('bl.spamcop.net', SENDER_IP).status).toBe('refused');
    expect(by('multi.surbl.org', 'mauvais.fr')).toMatchObject({ status: 'listed', meaning: 'PH phishing, MW malware' });
    expect(by('multi.surbl.org', 'propre.fr').status).toBe('clean');
    expect(r.queries).toContain('14.215.184.93.zen.spamhaus.org A');
    // a reputation scale: a good score is not a listing, a bad one is
    expect(by('rep.mailspike.net', SENDER_IP)).toMatchObject({ status: 'clean', meaning: 'bonne reputation' });
    const bad = await checkDnsbl(r, { ips: ['93.184.215.15'] }, { lists });
    expect(bad.results.find((x) => x.zone === 'rep.mailspike.net')).toMatchObject({ status: 'listed', meaning: 'reputation mauvaise (L5 a L1)' });
  });

  it('an undocumented 127.0.0.1 answer is a refusal, not a listing', async () => {
    const r = fakeResolver({ '14.215.184.93.bl.spamcop.net': { A: ['127.0.0.1'] } });
    const res = await checkDnsbl(r, { ips: [SENDER_IP] }, { lists });
    expect(res.results.find((x) => x.zone === 'bl.spamcop.net')?.status).toBe('refused');
  });

  it('reads research/dnsbl.json, falls back to the built-in lists without it', () => {
    const real = loadDnsblLists();
    expect(real.lists.length).toBeGreaterThan(0);
    expect(real.lists.every((l) => l.status === 'alive' || real.source === 'fallback')).toBe(true);
    const none = loadDnsblLists(path.join('/nonexistent', 'dnsbl.json'));
    expect(none.source).toBe('fallback');
    expect(none.lists).toBe(FALLBACK_LISTS);
    expect(FALLBACK_LISTS.map((l) => l.zone)).toEqual(expect.arrayContaining(['zen.spamhaus.org', 'b.barracudacentral.org', 'bl.spamcop.net', 'psbl.surriel.com', 'bl.mailspike.net']));
  });

  it('a listed IP becomes a finding with its delisting link; a refusal is signalled', async () => {
    const zone = {
      ...goodZone(),
      '14.215.184.93.zen.spamhaus.org': { A: ['127.0.0.2'] },
      '14.215.184.93.b.barracudacentral.org': { A: ['127.255.255.255'] },
    };
    const r = await analyzeMessage(
      { raw: fixture('no-message-id.eml'), via: 'smtp', clientIp: SENDER_IP, helo: 'mail.atelier-exemple.fr', mailFrom: 'paul@atelier-exemple.fr', tls: null },
      deps(fakeResolver(zone), { dnsbl: true }),
    );
    const sbl = r.findings.find((f) => f.id === 'blacklist.spamhaus_sbl');
    expect(sbl?.evidence).toContain('127.0.0.2');
    // a list that refused the query is a limit of the measurement, not an improvement (2026-11-12)
    expect(r.findings.some((f) => f.id === 'blacklist.query_blocked')).toBe(false);
    expect((r.data.limits as { check: string }[]).some((l) => l.check === 'Listes de blocage')).toBe(true);
  });
});

describe('Received chain', () => {
  it('parses hops oldest first with delays and finds the first external relay', () => {
    const hops = parseHops([
      'from mx1.hebergeur.fr (mx1.hebergeur.fr [10.1.1.1]) by imap.hebergeur.fr with LMTP; Tue, 10 Nov 2026 16:00:09 +0100',
      'from mail-wr1-f54.google.com (mail-wr1-f54.google.com [209.85.221.54]) by mx1.hebergeur.fr (Postfix) with ESMTPS id 1; Tue, 10 Nov 2026 16:00:05 +0100',
      'by 2002:a05:6000:1:b0:3:4 with SMTP id x; Tue, 10 Nov 2026 07:00:01 -0800 (PST)',
    ]);
    expect(hops.map((h) => h.index)).toEqual([1, 2, 3]);
    expect(hops[1]).toMatchObject({ ip: '209.85.221.54', fromPtr: 'mail-wr1-f54.google.com', tls: true, delaySec: 4 });
    // the origin stamp ("by … with SMTP id", no from clause) is not a network transfer: no TLS verdict
    expect(hops[0].tls).toBeNull();
    expect(findOrigin(hops, ['imap.hebergeur.fr'])?.ip).toBe('209.85.221.54');
  });
});

describe('provider detection', () => {
  it('recognises providers by DKIM, headers, reverse DNS', () => {
    expect(detectProvider({ dkimDomains: ['atelier-exemple.fr', 'sendinblue.com'] })?.key).toBe('brevo');
    expect(detectProvider({ headers: { 'x-ses-outgoing': '2026.11.10-54.240.1.1' } })?.key).toBe('amazon_ses');
    expect(detectProvider({ ptr: ['mail-am6eur05on2101.outbound.protection.outlook.com'] })?.key).toBe('microsoft_365');
    expect(detectProvider({ ptr: ['mail.o2switch.net'] })?.key).toBe('o2switch');
    expect(detectProvider({ spfRecord: 'v=spf1 include:mx.ovh.com ~all' })?.key).toBe('ovh');
    expect(detectProvider({ headers: { 'x-mailer': 'PHPMailer' } })).toBeUndefined();
  });
});

describe('IMAP address matching', () => {
  it('finds the test address in the delivery headers', () => {
    expect(addressIdsOf(fixture('via-mailbox.eml'), 'check.localhost')).toEqual(['t-abcd2345']);
    expect(addressIdsOf(Buffer.from('To: autre@ailleurs.fr\r\n\r\nx'), 'check.localhost')).toEqual([]);
  });
});
