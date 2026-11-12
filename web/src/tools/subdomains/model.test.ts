import { describe, expect, it } from 'vitest';
import { countFilters, filterRows, initialStream, noCertNote, reduce, resolvesTo, rowStatus, shownCert, toCsv, type SubRow } from './model';

const dns = (status: NonNullable<SubRow['dns']>['status'], extra: Partial<NonNullable<SubRow['dns']>> = {}) => ({ status, rcode: 'NOERROR', a: [], aaaa: [], cname: [], ...extra });
const rows: SubRow[] = [
  { name: 'www.example.com', sources: ['crt.sh'], certCount: 2, firstSeen: '2019-01-01T00:00:00Z', lastSeen: '2026-10-01T00:00:00Z', dns: dns('active', { a: ['203.0.113.1'] }) },
  { name: 'old.example.com', sources: ['crt.sh'], certCount: 1, firstSeen: '2015-01-01T00:00:00Z', dns: dns('dangling', { rcode: 'NXDOMAIN', cname: ['gone.example.net'] }) },
  { name: 'a.b.example.com', sources: ['crt.name'], certCount: 0, dns: dns('dead', { rcode: 'NXDOMAIN' }) },
  { name: 'docs.example.com', sources: ['crt.sh'], certCount: 1, dns: dns('active', { cname: ['x.github.io'], a: ['185.199.108.153'] }),
    takeover: { service: 'GitHub Pages', level: 'edge', target: 'x.github.io', evidence: 'There isn\'t a GitHub Pages site here.' } },
  { name: 'b.example.com', sources: ['crt.sh'], certCount: 1 },
];

describe('subdomain model', () => {
  it('derives the state and the resolution line', () => {
    expect(rows.map(rowStatus)).toEqual(['active', 'dangling', 'dead', 'risk', 'pending']);
    expect(resolvesTo(rows[0])).toBe('203.0.113.1');
    expect(resolvesTo(rows[1])).toBe('CNAME gone.example.net : cette cible n’existe pas');
    expect(resolvesTo(rows[3])).toBe('CNAME x.github.io → 185.199.108.153');
  });
  it('filters, searches and sorts like a zone file', () => {
    expect(countFilters(rows, 2)).toEqual({ all: 5, active: 1, dead: 2, risk: 2, wildcards: 2 });
    expect(filterRows(rows, 'all', '', 'name').map((r) => r.name)).toEqual(['b.example.com', 'a.b.example.com', 'docs.example.com', 'old.example.com', 'www.example.com']);
    expect(filterRows(rows, 'all', 'github', 'name').map((r) => r.name)).toEqual(['docs.example.com']);
    expect(filterRows(rows, 'all', '', 'first')[0].name).toBe('old.example.com');
  });
  it('prefers the served certificate and explains when none is shown', () => {
    const r: SubRow = { ...rows[0], lastCert: { source: 'crt.sh', id: '1', issuer: 'x', issuerShort: 'Old CA', notBefore: '2020-01-01T00:00:00Z', notAfter: '2020-04-01T00:00:00Z', nameCount: 1 },
      served: { ip: '203.0.113.1', issuer: "Let's Encrypt", validFrom: '2026-10-01T00:00:00Z', validTo: '2026-12-30T00:00:00Z', daysLeft: 49, expired: false, authorized: true, nameMatches: true } };
    expect(shownCert(r)).toMatchObject({ kind: 'served', issuer: "Let's Encrypt" });
    expect(shownCert({ ...r, served: undefined })).toMatchObject({ kind: 'published', expired: true });
    expect(noCertNote({ ...r, served: { ...r.served!, nameMatches: false } })).toEqual({ text: 'le serveur présente le certificat d’un autre nom', warn: true });
  });
  it('folds the stream events', () => {
    let s = reduce(initialStream, { type: 'inventory', data: { rows: rows.map(({ dns: _d, ...x }) => x), wildcards: [], toResolve: 5 } });
    s = reduce(s, { type: 'subdomain', data: { name: 'www.example.com', dns: rows[0].dns } });
    expect(s.resolvedSoFar).toBe(1);
    expect(rowStatus(s.rows.find((r) => r.name === 'www.example.com')!)).toBe('active');
  });
  it('exports a CSV that a French spreadsheet opens in columns', () => {
    const csv = toCsv(rows.slice(0, 2));
    expect(csv.startsWith('﻿nom;etat;cname')).toBe(true);
    expect(csv).toContain('old.example.com;CNAME orphelin;gone.example.net');
    expect(csv.split('\r\n')).toHaveLength(4);
  });
});
