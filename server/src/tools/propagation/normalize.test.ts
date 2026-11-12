import { describe, expect, it } from 'vitest';
import type { DnsAnswer } from '../../dns/client.js';
import { extract, formatRecord, normalizeExpected, sameValues, svcbToText } from './normalize.js';

describe('formatRecord: one canonical string per record', () => {
  it('addresses and host names', () => {
    expect(formatRecord('A', '192.0.2.1')).toBe('192.0.2.1');
    expect(formatRecord('AAAA', '2001:0DB8:0000:0000:0000:0000:0000:0001')).toBe('2001:db8::1');
    expect(formatRecord('CNAME', 'Target.Example.NET.')).toBe('target.example.net');
    expect(formatRecord('NS', 'NS1.example.com.')).toBe('ns1.example.com');
    expect(formatRecord('PTR', 'host.example.')).toBe('host.example');
  });
  it('MX keeps priority and host', () => {
    expect(formatRecord('MX', { preference: 10, exchange: 'MX.Example.com.' })).toBe('10 mx.example.com');
  });
  it('TXT strings are concatenated', () => {
    expect(formatRecord('TXT', [Buffer.from('v=spf1 include:a '), Buffer.from('-all')])).toBe('v=spf1 include:a -all');
  });
  it('SOA, CAA, SRV, DS, DNSKEY', () => {
    expect(
      formatRecord('SOA', { mname: 'ns.example.', rname: 'Hostmaster.example.', serial: 2026111001, refresh: 7200, retry: 3600, expire: 1209600, minimum: 300 }),
    ).toBe('ns.example hostmaster.example 2026111001 7200 3600 1209600 300');
    expect(formatRecord('CAA', { flags: 0, tag: 'ISSUE', value: 'letsencrypt.org' })).toBe('0 issue "letsencrypt.org"');
    expect(formatRecord('SRV', { priority: 10, weight: 5, port: 5060, target: 'Sip.Example.com.' })).toBe('10 5 5060 sip.example.com');
    expect(formatRecord('DS', { keyTag: 370, algorithm: 13, digestType: 2, digest: Buffer.from('be74', 'hex') })).toBe('370 13 2 BE74');
    expect(formatRecord('DNSKEY', { flags: 257, algorithm: 13, key: Buffer.from([1, 2, 3]) })).toBe('257 3 13 AQID');
  });
  it('HTTPS (SVCB) wire format is decoded', () => {
    // priority 1, target ".", alpn=h2,h3, ipv4hint=192.0.2.1
    const buf = Buffer.from([0, 1, 0, 0, 1, 0, 6, 2, 0x68, 0x32, 2, 0x68, 0x33, 0, 4, 0, 4, 192, 0, 2, 1]);
    expect(svcbToText(buf)).toBe('1 . alpn=h2,h3 ipv4hint=192.0.2.1');
    expect(formatRecord('HTTPS', buf)).toBe('1 . alpn=h2,h3 ipv4hint=192.0.2.1');
  });
});

describe('normalizeExpected: what the user types', () => {
  it('splits addresses on commas, spaces and lines', () => {
    expect(normalizeExpected('A', '192.0.2.2, 192.0.2.1\n192.0.2.1')).toEqual(['192.0.2.1', '192.0.2.2']);
    expect(normalizeExpected('AAAA', '2001:DB8::0:1')).toEqual(['2001:db8::1']);
  });
  it('ignores case and final dots on hosts', () => {
    expect(normalizeExpected('CNAME', 'Target.Example.NET.')).toEqual(['target.example.net']);
    expect(normalizeExpected('MX', '10 MX1.example.com., 20 mx2.example.com')).toEqual(['10 mx1.example.com', '20 mx2.example.com']);
  });
  it('TXT: quoted chunks are concatenated, one value per line', () => {
    expect(normalizeExpected('TXT', '"v=spf1 include:a " "-all"\nhello world')).toEqual(['hello world', 'v=spf1 include:a -all']);
  });
  it('CAA and DS', () => {
    expect(normalizeExpected('CAA', '0 ISSUE "letsencrypt.org"')).toEqual(['0 issue "letsencrypt.org"']);
    expect(normalizeExpected('DS', '370 13 2 be74 ab')).toEqual(['370 13 2 BE74AB']);
  });
});

describe('sameValues', () => {
  it('ignores order and duplicates', () => {
    expect(sameValues('A', ['192.0.2.2', '192.0.2.1'], ['192.0.2.1', '192.0.2.2', '192.0.2.1'])).toBe(true);
    expect(sameValues('A', ['192.0.2.1'], ['192.0.2.1', '192.0.2.2'])).toBe(false);
  });
  it('MX without priority in the reference compares hosts only', () => {
    expect(sameValues('MX', ['10 mx1.example.com', '20 mx2.example.com'], ['mx2.example.com', 'mx1.example.com'])).toBe(true);
    expect(sameValues('MX', ['10 mx1.example.com'], ['20 mx1.example.com'])).toBe(false);
  });
});

describe('extract', () => {
  const a = (name: string, type: string, data: unknown, ttl = 300): DnsAnswer => ({ name, type, ttl, data });
  it('follows a CNAME chain and keeps the alias TTL', () => {
    const x = extract('A', 'www.example.com', [
      a('www.example.com', 'CNAME', 'cdn.example.net', 120),
      a('cdn.example.net', 'CNAME', 'edge.example.org', 60),
      a('edge.example.org', 'A', '192.0.2.9', 20),
    ]);
    expect(x).toMatchObject({ cname: 'cdn.example.net', chain: ['cdn.example.net', 'edge.example.org'], values: ['192.0.2.9'], ttl: 120, valuesTtl: 20 });
  });
  it('gives the negative TTL from the SOA of an empty answer', () => {
    const soa = a('example.com', 'SOA', { minimum: 60 }, 3600);
    expect(extract('A', 'nx.example.com', [], [soa]).negativeTtl).toBe(60);
  });
});
