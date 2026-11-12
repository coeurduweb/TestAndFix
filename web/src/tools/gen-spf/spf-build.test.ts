import { describe, expect, it } from 'vitest';
import { buildSpf, cleanIncludeTarget, emptyModel, parseIpInput, parseSpfRecord, rawTermCost } from './spf-build';
import { orgDomain, parseMailto, quoteTxt, sameOrg, splitTxt, stampId, zoneLine } from './txt';
import { providerOfInclude, providersFromMx, searchProviders } from './providers';

describe('SPF construction and lookup counter', () => {
  it('builds a minimal record with the recommended ~all', () => {
    const b = buildSpf(emptyModel());
    expect(b.record).toBe('v=spf1 ~all');
    expect(b.lookups).toBe(0);
  });

  it('orders addresses first, counts includes, a and mx', () => {
    const b = buildSpf({
      ...emptyModel(),
      ip4: ['203.0.113.10', '203.0.113.10'],
      ip6: ['2001:db8::1'],
      a: true,
      mx: true,
      includes: [
        { domain: '_spf.google.com', cost: 1, source: 'reference' },
        { domain: 'mx.ovh.com', cost: 3, source: 'reference' },
      ],
      all: '-',
    });
    expect(b.record).toBe('v=spf1 ip4:203.0.113.10 ip6:2001:db8::1 a mx include:_spf.google.com include:mx.ovh.com -all');
    expect(b.lookups).toBe(1 + 1 + 1 + 3);
    expect(b.overLimit).toBe(false);
    expect(b.estimated).toBe(false);
  });

  it('flags more than 10 lookups and estimated costs', () => {
    const includes = ['a.example', 'b.example', 'c.example'].map((d) => ({ domain: d, cost: 4, source: 'estimated' as const }));
    const b = buildSpf({ ...emptyModel(), includes });
    expect(b.lookups).toBe(12);
    expect(b.overLimit).toBe(true);
    expect(b.estimated).toBe(true);
  });

  it('keeps unknown terms, drops all when redirect is kept', () => {
    const b = buildSpf({ ...emptyModel(), others: ['exists:%{i}._spf.example.net', 'redirect=_spf.example.net'] });
    expect(b.record).toBe('v=spf1 exists:%{i}._spf.example.net redirect=_spf.example.net');
    expect(b.lookups).toBe(2);
    expect(b.redirect).toBe('_spf.example.net');
  });

  it('writes v=spf1 -all for a domain that never sends', () => {
    expect(buildSpf({ ...emptyModel(), noMail: true, includes: [{ domain: 'x.example', cost: 1, source: 'dns' }] }).record).toBe('v=spf1 -all');
  });

  it('counts raw terms like RFC 7208 §4.6.4', () => {
    expect(rawTermCost('ptr:mail.example')).toBe(1);
    expect(rawTermCost('exists:%{i}.x.example')).toBe(1);
    expect(rawTermCost('a:mail.example')).toBe(1);
    expect(rawTermCost('mx:example.fr/24')).toBe(1);
    expect(rawTermCost('ip4:1.2.3.4')).toBe(0);
    expect(rawTermCost('exp=explain.example')).toBe(0);
    expect(rawTermCost('-all')).toBe(0);
  });

  it('parses an existing record', () => {
    const p = parseSpfRecord('v=spf1 include:spf.mailjet.com a mx ip4:203.0.113.61 ip4:185.26.104.0/22 include:_spf.google.com include:spf.jabatus.fr ptr ~all');
    expect(p.includes).toEqual(['spf.mailjet.com', '_spf.google.com', 'spf.jabatus.fr']);
    expect(p.ip4).toEqual(['203.0.113.61', '185.26.104.0/22']);
    expect(p.a && p.mx).toBe(true);
    expect(p.others).toEqual(['ptr']);
    expect(p.all).toBe('~');
    expect(parseSpfRecord('v=spf1 -include:x.example ?all').others).toEqual(['-include:x.example']);
  });

  it('accepts addresses tolerantly', () => {
    const r = parseIpInput(' 203.0.113.10, ip4:198.51.100.0/24\n2001:DB8::1  10.0.0.0/8 999.1.1.1 nope 2001:db8::/16');
    expect(r.ip4).toEqual(['203.0.113.10', '198.51.100.0/24', '10.0.0.0/8']);
    expect(r.ip6).toEqual(['2001:db8::1', '2001:db8::/16']);
    expect(r.errors).toEqual(['999.1.1.1', 'nope']);
    expect(r.broad).toEqual(['10.0.0.0/8', '2001:db8::/16']);
    expect(parseIpInput('203.0.113.10/32').ip4).toEqual(['203.0.113.10']);
  });

  it('cleans include targets', () => {
    expect(cleanIncludeTarget(' include:SPF.Example.NET. ')).toBe('spf.example.net');
    expect(cleanIncludeTarget('%{i}._spf.example.net')).toBe('%{i}._spf.example.net');
    expect(cleanIncludeTarget('pas un domaine')).toBeUndefined();
  });
});

describe('providers of the knowledge base', () => {
  it('recognises official includes and old aliases', () => {
    expect(providerOfInclude('_spf.google.com')?.key).toBe('google_workspace');
    expect(providerOfInclude('spf.sendinblue.com')?.key).toBe('brevo');
    expect(providerOfInclude('123456.spf03.hubspotemail.net')?.key).toBe('hubspot');
    expect(providerOfInclude('spf.jabatus.fr')?.key).toBe('o2switch');
    expect(providerOfInclude('unknown.example')).toBeUndefined();
  });
  it('detects mailbox providers from MX hosts', () => {
    const r = providersFromMx(['aspmx.l.google.com.', 'exemple-fr.mail.protection.outlook.com']);
    expect(r.map((x) => x.provider.key)).toEqual(['google_workspace', 'microsoft_365']);
  });
  it('searches by name, keyword, accents ignored', () => {
    expect(searchProviders('sendin', new Set())[0].key).toBe('brevo');
    expect(searchProviders('Gmail', new Set())[0].key).toBe('google_workspace');
    expect(searchProviders('o365', new Set(['microsoft_365']))).toEqual([]);
  });
});

describe('TXT strings of 255 characters', () => {
  it('keeps short values whole', () => {
    expect(splitTxt('v=spf1 ~all')).toEqual(['v=spf1 ~all']);
  });
  it('cuts long values into strings of at most 255 that rejoin exactly', () => {
    const long = 'v=spf1 ' + Array.from({ length: 30 }, (_, i) => `include:spf${i}.example.net`).join(' ') + ' ~all';
    const parts = splitTxt(long);
    expect(parts.length).toBeGreaterThan(1);
    expect(parts.every((p) => p.length <= 255)).toBe(true);
    expect(parts.join('')).toBe(long);
    // cut after a space when one is near the end of the window
    expect(parts[0].endsWith(' ')).toBe(true);
  });
  it('cuts a value without spaces (DKIM key) at exactly 255', () => {
    const key = 'p=' + 'A'.repeat(600);
    const parts = splitTxt(key);
    expect(parts.map((p) => p.length)).toEqual([255, 255, 92]);
    expect(parts.join('')).toBe(key);
  });
  it('formats zone lines and quotes', () => {
    expect(quoteTxt(['a"b', 'c\\d'])).toBe('"a\\"b" "c\\\\d"');
    expect(zoneLine('exemple.fr', 'v=spf1 ~all')).toBe('exemple.fr. IN TXT "v=spf1 ~all"');
    expect(zoneLine('s._domainkey.exemple.fr.', 'x'.repeat(300))).toMatch(/^s\._domainkey\.exemple\.fr\. IN TXT \(\n"x{255}"\n"x{45}" \)$/);
  });
});

describe('addresses and organisational domains', () => {
  it('normalises report addresses', () => {
    expect(parseMailto('Dmarc@Exemple.FR')).toEqual({ uri: 'mailto:Dmarc@exemple.fr', address: 'Dmarc@exemple.fr', domain: 'exemple.fr' });
    expect(parseMailto('mailto:rua@dmarc.brevo.com')).toMatchObject({ domain: 'dmarc.brevo.com' });
    expect(parseMailto('pas une adresse')).toHaveProperty('error');
  });
  it('approximates the organisational domain', () => {
    expect(orgDomain('mail.exemple.fr')).toBe('exemple.fr');
    expect(orgDomain('shop.exemple.co.uk')).toBe('exemple.co.uk');
    expect(sameOrg('exemple.fr', 'dmarc.exemple.fr')).toBe(true);
    expect(sameOrg('exemple.fr', 'dmarc.brevo.com')).toBe(false);
  });
  it('stamps identifiers with letters and digits only', () => {
    expect(stampId(new Date('2026-11-10T18:34:05.123Z'))).toBe('20261110T183405');
  });
});
