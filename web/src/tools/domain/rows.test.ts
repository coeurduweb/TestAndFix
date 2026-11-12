import { describe, expect, it } from 'vitest';
import { fmtInt } from '../../lib/format';
import type { Finding } from '../../lib/types';
import type { DkimData, MxData, ScanSection } from './model';
import { tileState, tileSummary, outCount, warnCount, attach, evidenceSubject, fmtDuration, guessDomains, initialScan, keyMetric, lostPoints, notDelegated, parseTagList, rowDeviation, scanReducer, sectionMetrics } from './rows';

const f = (id: string, penalty: number, severity: Finding['severity'] = 'low', evidence?: string): Finding => ({
  id, family: id.split('.')[0], severity, penalty, title: id, why: '', fix: [], references: [], evidence,
});
const name = (p: string) => p; // unknown to the shared list: made readable by the rows

describe('attach', () => {
  it('folds a finding under the row naming it, matching the evidence when the row asks', () => {
    const rows = [
      { key: 'a', label: 'google', dev: { kind: 'ok' as const }, ids: ['dkim.key_1024'], evidence: 'google._domainkey' },
      { key: 'b', label: 'mailjet', dev: { kind: 'ok' as const }, ids: ['dkim.key_1024'], evidence: 'mailjet._domainkey' },
    ];
    const out = attach(rows, [f('dkim.key_1024', 0.3, 'low', 'mailjet._domainkey.x.fr : k=rsa'), f('dkim.other', 1)]);
    expect(out.rows[0].findings).toHaveLength(0);
    expect(out.rows[1].findings.map((x) => x.id)).toEqual(['dkim.key_1024']);
    expect(out.rest.map((x) => x.id)).toEqual(['dkim.other']);
  });

  it('makes a conforming row heavy only when a finding costs points', () => {
    const [row] = attach([{ key: 'p', label: 'p', dev: { kind: 'ok' }, ids: ['x'] }], [f('x', 0)]).rows;
    expect(rowDeviation(row).kind).toBe('ok');
    const [row2] = attach([{ key: 'p', label: 'p', dev: { kind: 'ok' }, ids: ['x'] }], [f('x', 1.5, 'high')]).rows;
    expect(rowDeviation(row2)).toMatchObject({ kind: 'out', text: '1,5', direction: 'down' });
    const [row3] = attach([{ key: 'p', label: 'p', dev: { kind: 'warn', text: '1 024', direction: 'down' }, ids: ['x'] }], [f('x', 3, 'critical')]).rows;
    expect(rowDeviation(row3)).toMatchObject({ kind: 'out', text: '1 024' });
  });
});

describe('lostPoints', () => {
  it('keeps penalized findings only, heaviest first, identical ones once', () => {
    const sections = [
      { id: 'dkim' as const, title: 'DKIM', findings: [f('dkim.key_1024', 0.3, 'low', 'a'), f('dkim.key_1024', 0.3, 'low', 'a'), f('dkim.key_1024', 0.3, 'low', 'b')] },
      { id: 'mx' as const, title: 'Serveurs MX', findings: [f('mx.target_nxdomain', 1, 'high'), f('mx.info', 0, 'info')] },
    ];
    const out = lostPoints(sections);
    expect(out.map((l) => `${l.section}:${l.finding.evidence}`)).toEqual(['mx:undefined', 'dkim:a', 'dkim:b']);
  });
});

describe('evidenceSubject', () => {
  it('takes the name before the record', () => {
    expect(evidenceSubject('m1._domainkey.cnn.com : k=rsa; t=s; p=MIGf')).toBe('m1._domainkey.cnn.com');
    expect(evidenceSubject('selector2._domainkey.cnn.com → selector2-cnn-com._domainkey.turner')).toBe('selector2._domainkey.cnn.com');
    expect(evidenceSubject('max_age: 86400')).toBe('max_age: 86400');
    expect(evidenceSubject(undefined)).toBeUndefined();
  });
});

describe('scanReducer', () => {
  const section = (id: ScanSection['id']): ScanSection => ({ id, title: id, status: 'ok', findings: [], passed: [], data: null, ms: 10 });
  it('fills sections as they arrive, then takes the final result', () => {
    let s = scanReducer(initialScan, { type: 'start', data: { domain: 'x.fr', sections: [{ id: 'mx', title: 'MX' }, { id: 'spf', title: 'SPF' }] } });
    expect(s.order).toHaveLength(2);
    s = scanReducer(s, { type: 'section', data: section('spf') });
    expect(Object.keys(s.sections)).toEqual(['spf']);
    s = scanReducer(s, { type: 'done', data: { tool: 'domain', input: 'x.fr', measuredAt: '', findings: [], passed: [], score: 9, data: { domain: 'x.fr', sections: [section('mx'), section('spf')], counts: {} } } });
    expect(s.result?.score).toBe(9);
    expect(Object.keys(s.sections).sort()).toEqual(['mx', 'spf']);
  });
  it('keeps the server message of an error event, ignores a bare connection error', () => {
    expect(scanReducer(initialScan, { type: 'error', data: { message: 'boom' } }).error).toBe('boom');
    expect(scanReducer(initialScan, { type: 'error', data: undefined }).error).toBeUndefined();
  });
});

describe('sectionMetrics', () => {
  it('MX: one row per host by priority, a host without address is out of range', () => {
    const mx: MxData = {
      domain: 'cnn.com', rcode: 'NOERROR', nullMx: false,
      hosts: [
        { host: 'b.example', preference: 20, ipv4: ['192.0.2.1'], ipv6: [], ipLiteral: false, privateIps: [] },
        { host: 'a.example', preference: 10, ipv4: [], ipv6: [], ipLiteral: false, privateIps: [] },
      ],
    };
    const rows = sectionMetrics({ id: 'mx', data: mx }, { domain: 'cnn.com', providerName: name });
    expect(rows.map((r) => r.label)).toEqual(['Serveurs MX publiés', 'a.example', 'b.example']);
    expect(rows[1].dev.kind).toBe('out');
    expect(rows[2].dev.kind).toBe('ok');
  });

  it('MX: a domain that does not exist says so', () => {
    const rows = sectionMetrics({ id: 'mx', data: { domain: 'x.fr', rcode: 'NXDOMAIN', hosts: [], nullMx: false } }, { domain: 'x.fr', providerName: name });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ measured: 'NXDOMAIN', dev: { kind: 'out' } });
  });

  it('NS of a parent zone measured for a missing domain: not delegated', () => {
    const ns = { zone: 'fr', parent: [{ name: 'd.nic.fr', ips: ['194.0.9.1'] }], child: ['d.nic.fr'], networks: ['194.0.9.0/24'] };
    expect(sectionMetrics({ id: 'ns', data: ns }, { domain: 'absent.fr', nx: true, providerName: name })[0].dev).toMatchObject({ kind: 'out', text: 'non déléguée' });
    expect(notDelegated('absent.fr', 'fr', false)).toBe(false);
    expect(notDelegated('www.exemple.fr', 'exemple.fr', true)).toBe(true);
  });

  it('DKIM: key under 2048 bits shows the gap, provider from the CNAME before the selector list', () => {
    const d: DkimData = {
      domain: 'cnn.com', tried: 98, selectorsTried: [], other: [], errors: [], wildcard: false, limits: [],
      keys: [
        { selector: 's1', name: 's1._domainkey.cnn.com', record: '', cnames: ['s1.jvn6gt.custdkim.salesforce.com'], knownFor: ['sendgrid'], keyType: 'rsa', bits: 2048, flags: [], testing: false, strictSubdomains: false, revoked: false },
        { selector: 'm1', name: 'm1._domainkey.cnn.com', record: '', cnames: [], knownFor: ['sendgrid'], keyType: 'rsa', bits: 1024, flags: ['s'], testing: false, strictSubdomains: true, revoked: false },
      ],
    };
    const rows = sectionMetrics({ id: 'dkim', data: d }, { domain: 'cnn.com', providerName: name });
    expect(rows[0].measured).toBe('2 sur 98 sélecteurs essayés');
    expect(rows[1].sub).toBe('CNAME vers salesforce.com');
    expect(rows[2]).toMatchObject({ dev: { kind: 'warn', text: fmtInt(1024) }, sub: 'sélecteur habituel de Sendgrid' });
    expect(keyMetric({ ...d.keys[1], bits: 512 }, name).dev.kind).toBe('out');
  });

  it('SMTP: blocked port 25 is not a verdict', () => {
    const rows = sectionMetrics({ id: 'smtp', data: { domain: 'x.fr', port25: { reachable: false, detail: '' }, mx: [], probes: [] } }, { domain: 'x.fr', providerName: name });
    expect(rows[0]).toMatchObject({ measured: 'non vérifiable depuis cette machine', dev: { kind: 'info' } });
  });

  it('RDAP: expiration under 30 days is out of range', () => {
    const rows = sectionMetrics({ id: 'rdap', data: { domain: 'x.fr', queried: 'x.fr', tld: 'fr', status: [], events: [], nameservers: [], ageDays: 4000, expiresInDays: 12 } }, { domain: 'x.fr', providerName: name });
    expect(rows.find((r) => r.key === 'exp')?.dev).toMatchObject({ kind: 'out', text: '12 j' });
    expect(rows.find((r) => r.key === 'age')?.measured).toBe('10 ans 11 mois');
  });
});

describe('helpers', () => {
  it('fmtDuration', () => {
    expect(fmtDuration(1)).toBe('1 jour');
    expect(fmtDuration(145)).toBe('4 mois');
    expect(fmtDuration(6793)).toBe('18 ans 7 mois');
  });
  it('parseTagList and guessDomains read a pasted record', () => {
    expect(parseTagList('"v=DMARC1; p=none; rua=mailto:a@x.fr"')).toEqual([
      { name: 'v', value: 'DMARC1' }, { name: 'p', value: 'none' }, { name: 'rua', value: 'mailto:a@x.fr' },
    ]);
    expect(guessDomains('v=DMARC1; rua=mailto:a@x.fr,mailto:b@vendor.com; ruf=mailto:c@x.fr')).toEqual(['x.fr', 'vendor.com']);
  });
});

describe('counts', () => {
  it('separate red from amber as the score summary does', () => {
    const list = [f('a', 1.5, 'high'), f('b', 0.3, 'low'), f('c', 0.3, 'medium'), f('d', 0, 'info')];
    expect(outCount(list)).toBe(1);
    expect(warnCount(list)).toBe(2);
  });
});

describe('tiles', () => {
  it('state by the worst finding, one plain line per section', () => {
    expect(tileState(undefined)).toBe('pending');
    expect(tileState({ status: 'warning', findings: [f('x', 0.3, 'low')] })).toBe('warn');
    expect(tileState({ status: 'error', findings: [f('x', 1, 'high')] })).toBe('out');
    expect(tileState({ status: 'unavailable', findings: [] })).toBe('unavailable');
    const ctx = { domain: 'x.fr', providerName: (p: string) => p };
    expect(tileSummary({ id: 'smtp', status: 'unavailable', data: { domain: 'x.fr', port25: { reachable: false, detail: '' }, mx: [], probes: [] } }, ctx)).toBe('non vérifiable depuis cette machine');
    expect(tileSummary({ id: 'dmarc', status: 'warning', data: { domain: 'x.fr', orgDomain: 'x.fr', inherited: false, record: 'v=DMARC1; p=none', records: [], tags: [], effectivePolicy: 'none', pct: 100, alignment: { dkim: 'r', spf: 'r' }, reports: [], plan: [] } }, ctx)).toBe('p=none, sans rapports');
    expect(tileSummary({ id: 'ns', status: 'ok', data: { zone: 'fr', parent: [], child: [], networks: [] } }, { ...ctx, nx: true })).toBe('zone non déléguée');
  });
});
