import { describe, expect, it } from 'vitest';
import type { DmarcData } from '../domain/model';
import { authorizationName, dmarcTagMetric, reportMetric } from './tags';

const base: DmarcData = {
  domain: 'x.fr', orgDomain: 'x.fr', inherited: false, records: [], tags: [], policy: 'reject', pct: 100,
  alignment: { dkim: 'r', spf: 'r' }, reports: [], plan: [],
};

describe('dmarcTagMetric', () => {
  it('p=none is in observation, sp weaker than p is flagged, defaults are noted', () => {
    expect(dmarcTagMetric({ name: 'p', value: 'none', meaning: '', valid: true }, { ...base, policy: 'none' }).dev).toMatchObject({ kind: 'warn' });
    expect(dmarcTagMetric({ name: 'sp', value: 'none', meaning: '', valid: true }, base).dev).toMatchObject({ kind: 'warn', text: 'plus faible' });
    const ri = dmarcTagMetric({ name: 'ri', value: '86400', meaning: '', valid: true, implicit: true }, base);
    expect(ri).toMatchObject({ measured: '86400 (par défaut)', dev: { kind: 'info', text: 'défaut' } });
    expect(dmarcTagMetric({ name: 'p', value: 'bad', meaning: '', valid: false }, base).dev.kind).toBe('out');
  });
  it('missing rua is its own row carrying rua findings', () => {
    const m = dmarcTagMetric({ name: 'rua', value: '', meaning: '', valid: true, implicit: true }, base);
    expect(m).toMatchObject({ measured: 'absent', dev: { kind: 'warn' } });
    expect(m.ids).toContain('dmarc.rua_missing');
  });
});

describe('reportMetric', () => {
  it('an external address without authorization loses the reports', () => {
    const m = reportMetric({ tag: 'rua', uri: 'mailto:r@vendor.com', scheme: 'mailto', address: 'r@vendor.com', domain: 'vendor.com', external: true, authorized: false }, 0, 'x.fr');
    expect(m).toMatchObject({ measured: 'autorisation absente', dev: { kind: 'out' }, reference: 'TXT sur x.fr._report._dmarc.vendor.com' });
    expect(authorizationName('x.fr', 'vendor.com')).toBe('x.fr._report._dmarc.vendor.com');
  });
});
