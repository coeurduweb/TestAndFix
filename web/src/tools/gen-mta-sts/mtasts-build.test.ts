import { describe, expect, it } from 'vitest';
import { covered, defaultSts, mxMatches, parseMxList, policyFile, stsRecord, tlsRptRecord, validId } from './mtasts-build';

describe('MTA-STS generator', () => {
  it('parses MX lists tolerantly', () => {
    const r = parseMxList('10 MX1.Exemple.fr.\nmx2.exemple.fr, mx: *.mail.protection.outlook.com\npas un hôte !\nmx1.exemple.fr');
    expect(r.mx).toEqual(['mx1.exemple.fr', 'mx2.exemple.fr', '*.mail.protection.outlook.com']);
    expect(r.errors).toEqual(['pas un hôte !']);
  });
  it('matches wildcards on one label only (RFC 8461 §4.1)', () => {
    expect(mxMatches('exemple-fr.mail.protection.outlook.com', '*.mail.protection.outlook.com')).toBe(true);
    expect(mxMatches('a.b.mail.protection.outlook.com', '*.mail.protection.outlook.com')).toBe(false);
    expect(covered('mx1.exemple.fr.', ['MX1.exemple.fr'])).toBe(true);
  });
  it('writes the policy file and records', () => {
    const m = { ...defaultSts('exemple.fr', new Date('2026-11-10T18:34:05Z')), mx: ['mx1.exemple.fr', 'mx2.exemple.fr'] };
    expect(policyFile(m)).toBe('version: STSv1\nmode: testing\nmx: mx1.exemple.fr\nmx: mx2.exemple.fr\nmax_age: 604800\n');
    expect(stsRecord(m.id)).toBe('v=STSv1; id=20261110T183405');
    expect(validId(m.id)).toBe(true);
    expect(validId('2026-11-10.1')).toBe(false);
    expect(tlsRptRecord(m.tlsRua)).toBe('v=TLSRPTv1; rua=mailto:tlsrpt@exemple.fr');
  });
  it('caps max_age at 31557600', () => {
    expect(policyFile({ ...defaultSts(), mode: 'enforce', mx: ['mx.exemple.fr'], maxAge: 99999999 })).toContain('max_age: 31557600');
  });
});
