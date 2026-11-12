import { describe, expect, it } from 'vitest';
import { advise, buildDmarc, defaultModel, externalAuthorizations, parseDmarc, plan } from './dmarc-build';

describe('DMARC record', () => {
  it('starts in observation with dmarc@<domain>', () => {
    expect(buildDmarc(defaultModel('exemple.fr'))).toBe('v=DMARC1; p=none; rua=mailto:dmarc@exemple.fr');
  });
  it('omits defaults and redundant tags', () => {
    const m = { ...defaultModel('exemple.fr'), p: 'reject' as const, sp: 'reject' as const, np: 'reject' as const };
    expect(buildDmarc(m)).toBe('v=DMARC1; p=reject; rua=mailto:dmarc@exemple.fr');
  });
  it('writes every advanced tag in order', () => {
    const r = buildDmarc({
      p: 'quarantine', sp: 'none', np: 'reject', adkim: 's', aspf: 's', t: true,
      rua: ['Dmarc@Exemple.fr', 'mailto:rua@dmarc.brevo.com', 'pas une adresse'], ruf: ['ruf@exemple.fr'], fo: ['1', 'd'],
    });
    expect(r).toBe('v=DMARC1; p=quarantine; sp=none; np=reject; adkim=s; aspf=s; t=y; rua=mailto:Dmarc@exemple.fr,mailto:rua@dmarc.brevo.com; ruf=mailto:ruf@exemple.fr; fo=1:d');
  });
  it('drops fo without ruf and t=y with p=none', () => {
    expect(buildDmarc({ ...defaultModel(), fo: ['1'], t: true })).toBe('v=DMARC1; p=none');
  });
});

describe('external report addresses (RFC 9990 §4)', () => {
  it('needs an authorisation only outside the organisation', () => {
    const a = externalAuthorizations('exemple.fr', ['dmarc@exemple.fr', 'rapports@mail.exemple.fr', 'rua@dmarc.brevo.com', 'x@dmarc.brevo.com']);
    expect(a).toEqual([{ address: 'rua@dmarc.brevo.com', reportDomain: 'dmarc.brevo.com', name: 'exemple.fr._report._dmarc.dmarc.brevo.com', value: 'v=DMARC1' }]);
  });
});

describe('existing record', () => {
  it('reads tags back and lists the removed ones', () => {
    const { model, dropped } = parseDmarc('v=DMARC1; p=quarantine; pct=50; rua=mailto:a@exemple.fr,mailto:b@x.example!10m; ruf=mailto:f@exemple.fr; fo=1; adkim=s; ri=86400');
    expect(model.p).toBe('quarantine');
    expect(model.rua).toEqual(['a@exemple.fr', 'b@x.example']);
    expect(model.ruf).toEqual(['f@exemple.fr']);
    expect(model.fo).toEqual(['1']);
    expect(model.adkim).toBe('s');
    expect(dropped).toEqual(['pct=50', 'ri=86400']);
  });
});

describe('policy advice', () => {
  it('climbs one step from what is published', () => {
    expect(advise(null).policy).toBe('none');
    expect(advise('none').policy).toBe('quarantine');
    expect(advise('quarantine').policy).toBe('reject');
    expect(advise('reject').policy).toBe('reject');
  });
  it('says so when the DNS was not read', () => {
    expect(advise(null, null, false)).toMatchObject({ policy: 'none', basis: 'unread' });
  });
  it('follows the stored reports when there are some', () => {
    expect(advise('none', { target: 'none', headline: 'Rester en none' })).toEqual({ policy: 'none', reason: 'Rester en none', basis: 'reports' });
  });
  it('lays out the three steps', () => {
    expect(plan(defaultModel('exemple.fr')).map((s) => s.record)).toEqual([
      'v=DMARC1; p=none; rua=mailto:dmarc@exemple.fr',
      'v=DMARC1; p=quarantine; rua=mailto:dmarc@exemple.fr',
      'v=DMARC1; p=reject; rua=mailto:dmarc@exemple.fr',
    ]);
  });
});
