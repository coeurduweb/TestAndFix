import { describe, expect, it } from 'vitest';
import { countryName, fmtClock, fmtIn, fmtPercent, fmtTtl } from './fmt';
import { answerHeadline, apiUrl, outcomeLabel, pagePath, readQuery, serverVerdict, sortRecords, zoneLabel, type AllAuthoritative } from './lookup';
import { DNS_TYPES, PROPAGATION_TYPES, cleanName, defaultType, pickType } from './rrtypes';

describe('record types', () => {
  it('smart default type from the name', () => {
    expect(defaultType('exemple.fr')).toBe('A');
    expect(defaultType('8.8.8.8')).toBe('PTR');
    expect(defaultType('2001:4860:4860::8888')).toBe('PTR');
    expect(defaultType('_dmarc.exemple.fr')).toBe('TXT');
    expect(defaultType('google._domainkey.exemple.fr')).toBe('TXT');
    expect(defaultType('_sip._tcp.exemple.fr')).toBe('SRV');
    expect(defaultType('_25._tcp.mx.exemple.fr')).toBe('TLSA');
  });
  it('type from the URL, tolerant, limited to what the tool takes', () => {
    expect(pickType('mx', 'exemple.fr', DNS_TYPES)).toBe('MX');
    expect(pickType('TLSA', '_25._tcp.mx.exemple.fr', PROPAGATION_TYPES)).toBe('A');
    expect(pickType(null, '_dmarc.exemple.fr', PROPAGATION_TYPES)).toBe('TXT');
  });
  it('names pasted with a scheme, a path or a trailing dot', () => {
    expect(cleanName(' HTTPS://Exemple.FR/contact ')).toBe('exemple.fr');
    expect(cleanName('exemple.fr.')).toBe('exemple.fr');
    expect(cleanName('contact@exemple.fr')).toBe('exemple.fr');
    expect(cleanName('8.8.8.8')).toBe('8.8.8.8');
  });
});

describe('formatting', () => {
  it('TTL at a glance', () => {
    expect(fmtTtl(45)).toBe('45 s');
    expect(fmtTtl(293)).toBe('4 min 53 s');
    expect(fmtTtl(300)).toBe('5 min');
    expect(fmtTtl(10800)).toBe('3 h');
    expect(fmtTtl(7500)).toBe('2 h 05');
    expect(fmtTtl(93600)).toBe('1 j 2 h');
    expect(fmtTtl(null)).toBe('');
  });
  it('time until the projected end', () => {
    const now = Date.parse('2026-11-10T18:00:00Z');
    expect(fmtIn('2026-11-10T18:00:30Z', now)).toBe('dans 30 s');
    expect(fmtIn('2026-11-10T18:12:00Z', now)).toBe('dans 12 min');
    expect(fmtIn('2026-11-10T21:00:10Z', now)).toBe('dans 3 h');
    expect(fmtIn('2026-11-10T20:59:50Z', now)).toBe('dans 3 h');
    expect(fmtIn('2026-11-10T19:10:00Z', now)).toBe('dans 1 h 10');
    expect(fmtIn('2026-11-10T17:00:00Z', now)).toBe('maintenant');
  });
  it('clock with the day when it is not today', () => {
    const now = new Date(2026, 10, 10, 12, 0).getTime();
    expect(fmtClock(new Date(2026, 10, 10, 21, 33).toISOString(), now)).toBe('21:33');
    expect(fmtClock(new Date(2026, 10, 11, 2, 5).toISOString(), now)).toBe('11/11 à 02:05');
  });
  it('French country names and percentages', () => {
    expect(countryName('FR')).toBe('France');
    expect(countryName(null)).toBe('Pays inconnu');
    expect(fmtPercent(96.9).replace(/\s/g, ' ')).toBe('96,9 %');
    expect(fmtPercent(100).replace(/\s/g, ' ')).toBe('100 %');
  });
});

describe('lookup page state', () => {
  const q = (path: string) => {
    const [name, qs] = path.split('?');
    return readQuery(name, new URLSearchParams(qs ?? ''));
  };
  it('reads the mode from the URL and writes it back', () => {
    expect(q('gmail.com?type=mx&mode=tous')).toEqual({ name: 'gmail.com', type: 'MX', mode: 'all', server: undefined, dnssec: false });
    expect(q('gmail.com?serveur=1.1.1.1')).toMatchObject({ mode: 'resolver', server: '1.1.1.1', type: 'A' });
    expect(q('gmail.com?mode=resolveur')).toMatchObject({ mode: 'resolver', server: '8.8.8.8' });
    expect(q('8.8.8.8')).toMatchObject({ type: 'PTR', mode: 'authoritative' });
    expect(q('')).toBeNull();
    const x = q('gmail.com?type=MX&mode=tous&dnssec=1')!;
    expect(pagePath(x)).toBe('/dns/gmail.com?type=MX&mode=tous&dnssec=1');
    expect(apiUrl(x)).toBe('/api/dns/gmail.com?type=MX&all=1&dnssec=1');
    expect(apiUrl(q('gmail.com?serveur=9.9.9.9')!)).toBe('/api/dns/gmail.com?type=A&server=9.9.9.9');
  });
  it('trace labels', () => {
    expect(zoneLabel('.')).toBe('Racine');
    expect(zoneLabel('com')).toBe('TLD .com');
    expect(zoneLabel('gmail.com')).toBe('Zone gmail.com');
    expect(outcomeLabel({ zone: 'com', server: '', rtt: 1, outcome: 'referral', detail: 'gmail.com' })).toBe('délègue gmail.com');
    expect(outcomeLabel({ zone: 'com', server: '', rtt: 1, outcome: 'nxdomain' })).toContain('NXDOMAIN');
  });
  it('MX by preference, SRV by priority, signatures last', () => {
    const r = (type: string, value: string) => ({ name: 'x.', ttl: 1, type, value });
    expect(sortRecords([r('MX', '20 b.'), r('RRSIG', 'MX 8 2'), r('MX', '5 a.'), r('MX', '10 c.')]).map((x) => x.value)).toEqual(['5 a.', '10 c.', '20 b.', 'MX 8 2']);
    expect(sortRecords([r('SRV', '10 5 5060 b.'), r('SRV', '10 60 5060 a.'), r('SRV', '0 0 5060 c.')]).map((x) => x.value.split(' ').pop())).toEqual(['c.', 'a.', 'b.']);
    expect(sortRecords([r('A', '2.2.2.2'), r('A', '1.1.1.1')]).map((x) => x.value)).toEqual(['2.2.2.2', '1.1.1.1']);
  });
  it('headline: count of the type asked, NXDOMAIN and NODATA told apart', () => {
    expect(answerHeadline({ rcode: 'NOERROR', type: 'MX', cnames: [], answers: [{ name: 'a', ttl: 1, type: 'MX', value: '1 a.' }] })).toMatchObject({ count: 1, tone: 'ok' });
    expect(answerHeadline({ rcode: 'NXDOMAIN', type: 'A', cnames: [], answers: [] })).toMatchObject({ count: 0, tone: 'out' });
    expect(answerHeadline({ rcode: 'NOERROR', type: 'AAAA', cnames: [], answers: [] })).toMatchObject({ count: 0, tone: 'warn' });
  });
  it('one authoritative server out of step', () => {
    const rec = (v: string) => [{ name: 'x.', ttl: 300, type: 'A', value: v }];
    const all: AllAuthoritative = {
      zone: 'x',
      servers: [
        { ns: 'ns1', ip: '1', rcode: 'NOERROR', aa: true, answers: rec('1.1.1.1'), serial: 2 },
        { ns: 'ns2', ip: '2', rcode: 'NOERROR', aa: true, answers: rec('1.1.1.1'), serial: 2 },
        { ns: 'ns3', ip: '3', rcode: 'NOERROR', aa: true, answers: rec('9.9.9.9'), serial: 1 },
        { ns: 'ns4', ip: '4', rcode: 'TIMEOUT', aa: false, answers: [], error: 'timeout' },
      ],
      consistent: false,
      serials: [2, 1],
      serialsConsistent: false,
      lame: [],
      variants: [
        { answers: ['A 1.1.1.1'], servers: ['ns1', 'ns2'] },
        { answers: ['A 9.9.9.9'], servers: ['ns3'] },
      ],
    };
    expect(all.servers.map((s) => serverVerdict(s, all).kind)).toEqual(['ok', 'ok', 'out', 'out']);
  });
});
