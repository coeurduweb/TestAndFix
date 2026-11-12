import { describe, expect, it } from 'vitest';
import { fmtAge, initialLink, linkReducer, liveAlerts, refang, splitUrl } from './model';

describe('link model', () => {
  it('refangs shared malicious links', () => {
    expect(refang('hxxps://evil[.]example(.)com/login')).toBe('https://evil.example.com/login');
    expect(refang(' <http://a.b/c d> ')).toBe('http://a.b/cd');
  });
  it('cuts an URL around its registrable domain, user info apart', () => {
    expect(splitUrl('https://login.paypal.com.secure.example.ru:8443/a?b', 'example.ru')).toEqual({ scheme: 'https://', userinfo: '', sub: 'login.paypal.com.secure.', domain: 'example.ru', rest: ':8443/a?b' });
    expect(splitUrl('http://paypal.com@evil.example/', 'evil.example')).toMatchObject({ userinfo: 'paypal.com@', domain: 'evil.example', sub: '' });
  });
  it('orders hops by index and lists live alerts', () => {
    let s = initialLink();
    s = linkReducer(s, { type: 'step', data: { step: 'hop', label: 'Saut 2', status: 'ok', data: { index: 2, url: 'b' } } });
    s = linkReducer(s, { type: 'step', data: { step: 'hop', label: 'Saut 1', status: 'ok', data: { index: 1, url: 'a' } } });
    s = linkReducer(s, { type: 'step', data: { step: 'openphish', label: 'OpenPhish', status: 'ok', data: { feedSize: 300, fetchedAt: '', exact: ['a'], sameHost: [] } } });
    s = linkReducer(s, { type: 'step', data: { step: 'safebrowsing', label: 'GSB', status: 'unavailable', reason: 'clé absente' } });
    expect(s.hops.map((h) => h.url)).toEqual(['a', 'b']);
    expect(liveAlerts(s.events)).toEqual(['OpenPhish']);
  });
  it('formats ages', () => {
    expect(fmtAge(3)).toBe('3 jours');
    expect(fmtAge(1)).toBe('1 jour');
    expect(fmtAge(200)).toBe('6 mois');
    expect(fmtAge(6972)).toBe('19 ans');
  });
});

import { brokenDestination } from './model';
describe('broken destination', () => {
  const hop = (o: object) => ({ index: 1, url: 'https://a.example/', host: 'a.example', domain: 'a.example', ms: 1, via: 'start' as const, ...o });
  it('reads the last request only', () => {
    expect(brokenDestination([hop({ status: 301, next: 'http' }), hop({ index: 2, status: 404 })])).toMatchObject({ code: 'HTTP 404', text: 'page introuvable' });
    expect(brokenDestination([hop({ status: 503 })])).toMatchObject({ text: 'erreur du serveur' });
    expect(brokenDestination([hop({ error: 'NXDOMAIN' })])).toMatchObject({ code: 'aucune réponse', text: 'NXDOMAIN' });
    expect(brokenDestination([hop({ status: 404, next: 'http' }), hop({ index: 2, status: 200 })])).toBeNull();
    expect(brokenDestination([])).toBeNull();
  });
});
