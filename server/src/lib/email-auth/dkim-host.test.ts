import { describe, expect, it } from 'vitest';
import { dnsHostFromNs } from './dkim.js';

describe('DNS host named by the NS records', () => {
  it('names each host of a zone served by two, with its own servers', () => {
    const h = dnsHostFromNs(['dns1.p08.nsone.net', 'dns2.p08.nsone.net', 'ns-1283.awsdns-32.org', 'ns-421.awsdns-52.com']);
    expect(h.label).toBe('Amazon Route 53 et NS1');
    expect(h.ns).toEqual(['ns-1283.awsdns-32.org', 'dns1.p08.nsone.net']);
    expect(h.key).toBe('aws_route53');
  });
  it('keeps one host with two of its servers', () => {
    expect(dnsHostFromNs(['a.ns.cloudflare.com', 'b.ns.cloudflare.com'])).toEqual({ key: 'cloudflare_dns', label: 'Cloudflare', ns: ['a.ns.cloudflare.com', 'b.ns.cloudflare.com'] });
  });
  it('names no host when no NS is known', () => {
    expect(dnsHostFromNs(['ns1.example.net'])).toEqual({ ns: ['ns1.example.net'] });
  });
});
