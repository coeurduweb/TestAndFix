import { describe, expect, it } from 'vitest';
import { detect, toDomain } from './detect';

const first = (s: string) => detect(s).actions[0]?.tool;

describe('universal input detection', () => {
  it('recognises domains, tolerantly', () => {
    expect(detect('exemple-agence.com').kind).toBe('domain');
    expect(first('exemple-agence.com')).toBe('domain');
    expect(toDomain('  HTTPS://www.Exemple.FR/contact?x=1 ')).toBe('www.exemple.fr');
    expect(toDomain('exemple.fr.')).toBe('exemple.fr');
    expect(toDomain('café.fr')).toBe('xn--caf-dma.fr');
    expect(toDomain('pas un domaine')).toBeUndefined();
  });
  it('recognises IPs and ranges', () => {
    expect(detect('198.51.100.20').kind).toBe('ip');
    expect(detect('2001:4860:4860::8888').kind).toBe('ip');
    expect(detect('198.51.100.0/24').kind).toBe('cidr');
    expect(detect('1.2.3.4\n5.6.7.8\n9.9.9.9').kind).toBe('ip-list');
    expect(detect('999.1.1.1').kind).not.toBe('ip');
  });
  it('recognises URLs and e-mail addresses', () => {
    expect(first('https://bit.ly/3abc')).toBe('link');
    const e = detect('Contact@Exemple-Agence.com');
    expect(e.kind).toBe('email');
    expect(e.domain).toBe('exemple-agence.com');
  });
  it('recognises DNS names with a role', () => {
    const k = detect('google._domainkey.exemple.fr');
    expect(k.kind).toBe('dkim-name');
    expect(k.actions[0].path).toBe('/dkim/exemple.fr?selecteur=google');
    expect(detect('_dmarc.exemple.fr').actions[0].tool).toBe('dmarc');
    expect(detect('MX exemple.fr').actions[0].path).toBe('/dns/exemple.fr?type=MX');
    expect(detect('exemple.fr txt').actions[0].path).toBe('/dns/exemple.fr?type=TXT');
  });
  it('recognises pasted records', () => {
    expect(detect('"v=spf1 include:_spf.google.com ~all"').kind).toBe('spf-record');
    expect(detect('v=DMARC1; p=none').kind).toBe('dmarc-record');
    expect(detect('v=DKIM1; k=rsa; p=MIGf').kind).toBe('dkim-record');
  });
  it('recognises headers, messages and DMARC XML', () => {
    const headers = 'Received: from a by b\nFrom: x@y.fr\nSubject: test';
    expect(detect(headers).kind).toBe('headers');
    expect(detect(headers + '\n\nBonjour').kind).toBe('eml');
    expect(detect('<?xml version="1.0"?><feedback><record></record></feedback>').kind).toBe('dmarc-xml');
  });
  it('returns no action for plain text', () => {
    expect(detect('bonjour tout le monde').actions).toEqual([]);
    expect(detect('   ').kind).toBe('empty');
  });
});
