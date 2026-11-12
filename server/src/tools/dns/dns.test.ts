import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { GuardedResolver, InvalidInputError } from '../../lib/email-auth/common.js';
import { formatRdata, formatSvcb } from './format.js';
import { dnsLookup } from './lookup.js';

const mk = (o?: { dnssec?: boolean }) => new GuardedResolver(new ResolveSession(o), () => new ResolveSession(o));

describe('DNS presentation format', () => {
  it('formats common records like dig', () => {
    expect(formatRdata('MX', { preference: 10, exchange: 'mx.example.fr' })).toBe('10 mx.example.fr.');
    expect(formatRdata('TXT', [Buffer.from('v=spf1 -all')])).toBe('"v=spf1 -all"');
    expect(formatRdata('SOA', { mname: 'ns1.example.fr', rname: 'hostmaster.example.fr', serial: 2026111001, refresh: 3600, retry: 600, expire: 1209600, minimum: 300 })).toBe(
      'ns1.example.fr. hostmaster.example.fr. 2026111001 3600 600 1209600 300',
    );
    expect(formatRdata('CAA', { flags: 0, tag: 'issue', value: 'letsencrypt.org' })).toBe('0 issue "letsencrypt.org"');
    expect(formatRdata('SRV', { priority: 0, weight: 5, port: 5060, target: 'sip.example.fr' })).toBe('0 5 5060 sip.example.fr.');
  });
  it('decodes SVCB/HTTPS RDATA (RFC 9460)', () => {
    // priority 1, target ".", alpn=h2, port=443
    const buf = Buffer.from('0001' + '00' + '0001' + '0003' + '026832' + '0003' + '0002' + '01bb', 'hex');
    expect(formatSvcb(buf)).toBe('1 . alpn="h2" port=443');
  });
});

describe('DNS lookup', () => {
  it('refuses ANY and unknown types clearly', async () => {
    await expect(dnsLookup(mk, 'example.com', { type: 'ANY' })).rejects.toThrow(/RFC 8482/);
    await expect(dnsLookup(mk, 'example.com', { type: 'WKS' })).rejects.toBeInstanceOf(InvalidInputError);
    await expect(dnsLookup(mk, 'example.com', { type: 'A', server: '192.168.1.1' })).rejects.toThrow(/privée/);
  });
  it('answers authoritatively with the trace from the root (live)', async () => {
    const r = await dnsLookup(mk, 'example.com', { type: 'A' });
    expect(r.data.rcode).toBe('NOERROR');
    expect(r.data.answers.length).toBeGreaterThan(0);
    expect(r.data.trace.map((t) => t.outcome)).toContain('referral');
    expect(r.data.dig).toContain(';; ANSWER SECTION:');
  });
  it('queries every authoritative server and compares them (live)', async () => {
    const r = await dnsLookup(mk, 'cloudflare.com', { type: 'MX', all: true });
    expect(r.data.authoritative?.servers.length).toBeGreaterThan(1);
    expect(r.data.authoritative?.serials.length).toBeGreaterThan(0);
  });
  it('asks a chosen resolver (live)', async () => {
    const r = await dnsLookup(mk, 'example.com', { type: 'A', server: '1.1.1.1' });
    if (r.unavailable) return;
    expect(r.data.flags?.ra).toBe(true);
    expect(r.data.server).toBe('1.1.1.1');
  });
  it('reads DS at the parent and PTR with FCrDNS (live)', async () => {
    const ds = await dnsLookup(mk, 'cloudflare.com', { type: 'DS' });
    expect(ds.data.zone).toBe('com');
    expect(ds.data.answers[0]?.type).toBe('DS');
    const ptr = await dnsLookup(mk, '8.8.8.8', {});
    expect(ptr.data.type).toBe('PTR');
    expect(ptr.data.ptr?.names).toContain('dns.google');
    expect(ptr.data.ptr?.fcrdns[0]?.matches).toBe(true);
  });
  it('decodes HTTPS records (live)', async () => {
    const r = await dnsLookup(mk, 'cloudflare.com', { type: 'HTTPS' });
    if (r.data.answers.length) expect(r.data.answers[0]).toMatchObject({ type: 'HTTPS' });
  });
});
