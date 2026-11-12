import { describe, expect, it } from 'vitest';
import { detect } from '../../lib/detect';
import { batchReducer, compareRows, contactLine, fmtDays, initialBatch, listPath, parseList, toCsv, toJson, type WhoisReport, type WhoisRow } from './model';

const row = (o: Partial<WhoisRow> = {}): WhoisRow => ({
  domain: 'exemple-agence.com',
  unicode: 'exemple-agence.com',
  ok: true,
  registrar: 'NETIM SAS',
  ianaId: '1519',
  created: '2008-04-05T17:48:51Z',
  expires: '2027-04-05T17:48:51Z',
  ageDays: 6794,
  expiresInDays: 144,
  status: ['clientTransferProhibited'],
  registryStatus: [],
  nameservers: ['ns1.netim.net', 'ns2.netim.net'],
  dnssec: false,
  a: ['203.0.113.7', '198.51.100.2'],
  contacts: [{ role: 'registrant', redacted: ['name', 'org', 'email'], contactUrl: 'https://www.netim.com/registrant-contact-form.html' }],
  registrySource: 'RDAP rdap.verisign.com',
  registrarSource: 'RDAP netim.rdap.services',
  divergences: [{ field: 'updated', label: 'Dernière modification', registry: '2026-03-28T23:35:18Z', registrar: '2024-09-02T08:08:38Z', expected: true }],
  ...o,
});

describe('list input', () => {
  it('splits on lines, commas and spaces, converts IDN, drops www. and duplicates', () => {
    expect(parseList('exemple-agence.com\nwww.exemple-agence.com, café.fr ; pas@ok ;; https://afnic.fr/x')).toEqual({
      domains: ['exemple-agence.com', 'xn--caf-dma.fr', 'afnic.fr'],
      invalid: ['pas@ok'],
    });
    expect(listPath(['a.fr'])).toBe('/whois/a.fr');
    expect(listPath(['a.fr', 'b.com'])).toBe('/whois?liste=a.fr,b.com');
  });
  it('makes the universal input offer the Whois table for a pasted list', () => {
    const d = detect('exemple-agence.com\nafnic.fr\nwikipedia.org');
    expect(d.kind).toBe('domain-list');
    expect(d.actions[0]).toMatchObject({ tool: 'rdap', path: '/whois?liste=exemple-agence.com,afnic.fr,wikipedia.org', label: 'Whois de 3 domaines' });
    expect(detect('a.fr, b.fr').kind).toBe('domain-list');
    expect(detect('MX exemple.fr').kind).toBe('dns-query');
    expect(detect('1.2.3.4\n5.6.7.8\n9.9.9.9').kind).toBe('ip-list');
    expect(detect('exemple-agence.com').actions.find((a) => a.tool === 'rdap')?.path).toBe('/whois/exemple-agence.com');
  });
});

describe('display', () => {
  it('writes day counts with years', () => {
    expect(fmtDays(1)).toBe('1 jour');
    expect(fmtDays(144)).toBe('144 jours');
    expect(fmtDays(6794).replace(/\s/g, ' ')).toBe('6 794 jours (18 ans)');
  });
  it('says « masqué » for hidden contacts and names privacy services', () => {
    expect(contactLine({ role: 'registrant', redacted: ['name', 'org', 'email'] })).toBe('masqué');
    expect(contactLine({ role: 'tech', org: 'ProxyDom', privacyService: true, redacted: ['name'] })).toBe('masqué (service d’anonymat : ProxyDom)');
    expect(contactLine({ role: 'tech', org: 'AFNIC', email: 'dnsops@afnic.fr', redacted: [] })).toBe('AFNIC, dnsops@afnic.fr');
    expect(contactLine(undefined)).toBe('');
  });
  it('lines up both parties and marks the differences', () => {
    const rec = { status: [], registryStatus: [], contacts: [], nameservers: [], raw: '' };
    const r: WhoisReport = {
      domain: 'exemple-agence.com', queried: 'exemple-agence.com', unicode: 'exemple-agence.com', tld: 'com', attempts: [], lookedUpAt: '',
      merged: { statusDetails: [], status: [], registryStatus: [], contacts: [], nameservers: [] },
      registry: { ...rec, party: 'registry', protocol: 'rdap', server: 'rdap.verisign.com', expires: '2027-04-05T17:48:51Z', registrar: { name: 'NETIM SAS' } },
      registrar: { ...rec, party: 'registrar', protocol: 'whois', server: 'whois.netim.com', expires: '2028-04-05T00:00:00Z', registrar: { name: 'NETIM' } },
      divergences: [{ field: 'expires', label: 'Expiration', registry: '2027-04-05T17:48:51Z', registrar: '2028-04-05T00:00:00Z' }],
    };
    const rows = compareRows(r);
    expect(rows.map((x) => x.key)).toEqual(['registrar', 'expires']);
    expect(rows[1]).toMatchObject({ registry: '05/04/2027', registrar: '05/04/2028', diverges: true });
    expect(rows[0].diverges).toBe(false);
  });
});

describe('list stream', () => {
  it('takes the server order, then the rows as they come', () => {
    let s = initialBatch(['www.exemple-agence.com', 'afnic.fr'])();
    s = batchReducer(s, { type: 'start', data: { count: 2, domains: ['exemple-agence.com', 'afnic.fr'], invalid: [{ value: 'x', reason: 'r' }], duplicates: 1 } });
    expect(s.expected).toEqual(['exemple-agence.com', 'afnic.fr']);
    s = batchReducer(s, { type: 'row', data: row() });
    s = batchReducer(s, { type: 'done', data: { resultId: 'abc' } });
    expect(Object.keys(s.rows)).toEqual(['exemple-agence.com']);
    expect(s).toMatchObject({ count: 2, duplicates: 1, resultId: 'abc' });
  });
});

describe('exports', () => {
  it('writes a CSV for Excel: BOM, semicolons, one row per domain, formulas defused', () => {
    const csv = toCsv([row(), row({ domain: 'xn--caf-dma.fr', unicode: 'café.fr', registrar: '=HYPERLINK("x")', reseller: 'Revendeur; SAS' }), row({ domain: 'libre.fr', unicode: 'libre.fr', ok: false, notFound: true, registrar: undefined, a: undefined })]);
    expect(csv.startsWith('﻿domaine;domaine_unicode;etat;bureau_enregistrement;iana_id;revendeur;creation;')).toBe(true);
    const lines = csv.trimEnd().split('\r\n');
    expect(lines).toHaveLength(4);
    expect(lines[1]).toContain('exemple-agence.com;exemple-agence.com;trouvé;NETIM SAS;1519;;2008-04-05;;2027-04-05;6794;144;clientTransferProhibited;;ns1.netim.net | ns2.netim.net;non;203.0.113.7 | 198.51.100.2;masqué;masqué;masqué;');
    expect(lines[3]).toContain(';non;;'); // a name not registered: no address measured, an empty cell
    expect(lines[1]).toContain(';RDAP rdap.verisign.com;RDAP netim.rdap.services;;');
    expect(lines[2]).toContain(`café.fr;trouvé;"'=HYPERLINK(""x"")";1519;"Revendeur; SAS"`);
    expect(lines[3]).toContain('libre.fr;libre.fr;non enregistré;');
  });
  it('also writes a comma CSV without BOM, and JSON', () => {
    const csv = toCsv([row()], 'standard');
    expect(csv.startsWith('domaine,domaine_unicode,')).toBe(true);
    expect(csv).toContain('ns1.netim.net | ns2.netim.net');
    expect(JSON.parse(toJson([row()]))[0].domain).toBe('exemple-agence.com');
  });
});
