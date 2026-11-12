import { describe, expect, it } from 'vitest';
import {
  batchReducer, cleanToken, expandRange, expectedIps, hitKind, initialBatch, inputPath, ipKey, isIpv6, listingSummary, parseInput, singleReducer, initialSingle,
  sortRows, toCsv, type BatchRow, type DnsblHit,
} from './model';

const row = (ip: string, o: Partial<BatchRow> = {}): BatchRow => ({ ip, status: 'clean', listed: [], majorListed: 0, refused: [], errors: [], findings: [], ...o });

describe('input', () => {
  it('cleans tolerant input', () => {
    expect(cleanToken(' [2001:DB8::1] ')).toBe('2001:db8::1');
    expect(cleanToken('203.0.113.5:25')).toBe('203.0.113.5');
    expect(cleanToken('[1.1.1.1]:25')).toBe('1.1.1.1');
    expect(cleanToken('[2001:db8::1]:587')).toBe('2001:db8::1');
    expect(cleanToken('IP: 203.0.113.5.')).toBe('203.0.113.5');
  });
  it('validates IPv6', () => {
    expect(isIpv6('2001:db8::1')).toBe(true);
    expect(isIpv6('::ffff:192.0.2.1')).toBe(true);
    expect(isIpv6('2001:db8::1::2')).toBe(false);
    expect(isIpv6('12345::1')).toBe(false);
  });
  it('splits a pasted list, keeps ranges, drops duplicates and reports the rest', () => {
    const p = parseInput('8.8.8.8\n1.1.1.1, 8.8.8.8 ; 203.0.113.0/29\nbonjour 10.0.0.0/8');
    expect(p.items).toEqual(['8.8.8.8', '1.1.1.1', '203.0.113.0/29']);
    expect(p.invalid).toEqual(['bonjour', '10.0.0.0/8']);
  });
  it('expands a range to its aligned block', () => {
    expect(expandRange('203.0.113.13/29')).toEqual(['203.0.113.8', '203.0.113.9', '203.0.113.10', '203.0.113.11', '203.0.113.12', '203.0.113.13', '203.0.113.14', '203.0.113.15']);
    expect(expandRange('250.1.2.3/32')).toEqual(['250.1.2.3']);
    expect(expandRange('192.0.2.0/24')).toHaveLength(256);
    expect(expectedIps(['192.0.2.1', '192.0.2.0/30'])).toEqual(['192.0.2.1', '192.0.2.0', '192.0.2.2', '192.0.2.3']);
  });
  it('routes one address, one range, or a list', () => {
    expect(inputPath(parseInput('8.8.8.8'))).toBe('/ip/8.8.8.8');
    expect(inputPath(parseInput('203.0.113.0/24'))).toBe('/ip/203.0.113.0%2F24');
    expect(inputPath(parseInput('8.8.8.8 1.1.1.1'))).toBe('/ip?liste=8.8.8.8,1.1.1.1');
    expect(inputPath(parseInput('nimporte'))).toBeNull();
  });
});

describe('single stream', () => {
  const hit = (zone: string, status: DnsblHit['status'], codes: string[] = [], weight: DnsblHit['weight'] = 'major'): DnsblHit => ({ zone, name: zone, weight, target: '', query: '', status, codes, ms: 1 });
  it('counts listings by weight, never a refusal or a scoring-only answer', () => {
    let s = singleReducer(initialSingle(), { type: 'start', data: { ip: '1.2.3.4', sources: [], lists: [
      { zone: 'zen', name: 'ZEN', weight: 'major' }, { zone: 'b', name: 'B', weight: 'major' }, { zone: 'dnsbl.spfbl.net', name: 'SPFBL', weight: 'info' }, { zone: 'm', name: 'M', weight: 'minor' },
    ] } });
    expect(s.lists.map((l) => l.zone)).toEqual(['b', 'zen', 'm', 'dnsbl.spfbl.net']);
    s = singleReducer(s, { type: 'source', data: { source: 'dnsbl:zen', label: 'ZEN', ok: true, ms: 1, data: hit('zen', 'refused', ['127.255.255.254']) } });
    s = singleReducer(s, { type: 'source', data: { source: 'dnsbl:b', label: 'B', ok: true, ms: 1, data: hit('b', 'listed', ['127.0.0.2']) } });
    s = singleReducer(s, { type: 'source', data: { source: 'dnsbl:dnsbl.spfbl.net', label: 'SPFBL', ok: true, ms: 1, data: hit('dnsbl.spfbl.net', 'listed', ['127.0.0.4'], 'info') } });
    expect(hitKind(s.hits.zen)).toBe('refused');
    expect(hitKind(s.hits['dnsbl.spfbl.net'])).toBe('scoring');
    expect(listingSummary(s.lists, s.hits)).toMatchObject({ answered: 3, total: 4, listed: 1, majorListed: 1, majorTotal: 2, refused: 1 });
  });
});

describe('batch', () => {
  const rows = {
    '10.0.0.1': row('10.0.0.1', { status: 'private' }),
    '9.9.9.9': row('9.9.9.9', { score: 10, country: 'CH' }),
    '89.1.1.1': row('89.1.1.1', { status: 'listed', majorListed: 2, score: 3, listed: [{ zone: 'z', name: 'Spamhaus ZEN', weight: 'major', codes: ['127.0.0.3'], situation: 'x' }] }),
    '100.1.1.1': row('100.1.1.1', { status: 'listed', majorListed: 1, score: 7 }),
  };
  const ips = ['100.1.1.1', '9.9.9.9', '89.1.1.1', '10.0.0.1', '1.2.3.4'];
  it('sorts IPv4 numerically, pending rows last', () => {
    expect(sortRows(ips, rows, { key: 'ip', dir: 'asc' })).toEqual(['9.9.9.9', '10.0.0.1', '89.1.1.1', '100.1.1.1', '1.2.3.4']);
    expect(sortRows(ips, rows, { key: 'ip', dir: 'desc' })).toEqual(['100.1.1.1', '89.1.1.1', '10.0.0.1', '9.9.9.9', '1.2.3.4']);
    expect(ipKey('9.9.9.9') < ipKey('10.0.0.1')).toBe(true);
  });
  it('sorts by listings, then by score; undefined values go last whatever the direction', () => {
    expect(sortRows(ips, rows, { key: 'major', dir: 'desc' }).slice(0, 2)).toEqual(['89.1.1.1', '100.1.1.1']);
    expect(sortRows(ips, rows, { key: 'score', dir: 'asc' })).toEqual(['89.1.1.1', '100.1.1.1', '9.9.9.9', '10.0.0.1', '1.2.3.4']);
    expect(sortRows(ips, rows, { key: 'score', dir: 'desc' })).toEqual(['9.9.9.9', '100.1.1.1', '89.1.1.1', '10.0.0.1', '1.2.3.4']);
    expect(sortRows(ips, rows, { key: 'country', dir: 'asc' })[0]).toBe('9.9.9.9');
  });
  it('keeps rows that were not expected, in arrival order', () => {
    let s = initialBatch(['1.1.1.1'])();
    s = batchReducer(s, { type: 'row', data: row('2.2.2.2') });
    s = batchReducer(s, { type: 'row', data: row('1.1.1.1') });
    expect(s.extra).toEqual(['2.2.2.2']);
    expect(Object.keys(s.rows)).toHaveLength(2);
  });
  it('exports a semicolon CSV, safe for spreadsheets', () => {
    const two = { zone: 'z', name: 'Spamhaus ZEN', weight: 'major' as const, codes: ['127.0.0.4'], situation: 'y' };
    const csv = toCsv(['89.1.1.1', '1.2.3.4'], { ...rows, '89.1.1.1': { ...rows['89.1.1.1'], ptr: '=cmd', listed: [...rows['89.1.1.1'].listed, two] } });
    const lines = csv.replace(/^﻿/, '').trim().split('\r\n');
    expect(lines[0].split(';')[0]).toBe('ip');
    expect(lines[1]).toContain('89.1.1.1;listée;2;Spamhaus ZEN;Spamhaus ZEN: 127.0.0.3 127.0.0.4;\'=cmd');
    expect(lines[1]).toContain(';3;');
    expect(lines[2]).toMatch(/^1\.2\.3\.4;en attente/);
  });
});
