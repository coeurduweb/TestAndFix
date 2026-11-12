// Live network tests: they query the real root servers (port 53 must be open).
import { describe, expect, it } from 'vitest';
import { ResolveSession, nodeStyleResolver } from './iterative.js';

describe('iterative resolution (live)', () => {
  it('resolves an A record from the root, authoritatively', async () => {
    const s = new ResolveSession();
    const r = await s.resolve('example.com', 'A');
    expect(r.rcode).toBe('NOERROR');
    expect(r.answers.length).toBeGreaterThan(0);
    expect(r.trace.map((t) => t.outcome)).toContain('referral');
    expect(r.trace.at(-1)!.outcome).toBe('answer');
  });
  it('reports NXDOMAIN', async () => {
    const r = await new ResolveSession().resolve(`nx-${Date.now()}.example.com`, 'A');
    expect(r.rcode).toBe('NXDOMAIN');
  });
  it('follows CNAMEs across zones', async () => {
    const r = await new ResolveSession().resolve('www.github.com', 'A');
    expect(r.cnames).toContain('github.com');
    expect(r.answers.some((a) => a.type === 'A')).toBe(true);
  });
  it('exposes a node-compatible resolver for mailauth', async () => {
    const resolve = nodeStyleResolver(new ResolveSession());
    const txt = (await resolve('gmail.com', 'TXT')) as string[][];
    expect(txt.some((r) => r.join('').startsWith('v=spf1'))).toBe(true);
    await expect(resolve(`nx-${Date.now()}.example.com`, 'TXT')).rejects.toMatchObject({ code: 'ENOTFOUND' });
  });
  it('finds the authoritative servers of a zone', async () => {
    const a = await new ResolveSession().findAuthorities('www.example.com');
    expect(a.zone).toBe('example.com');
    expect(a.servers.length).toBeGreaterThan(1);
    expect(a.servers.every((s) => s.ips.length > 0)).toBe(true);
  });
});

describe('servers that reject EDNS (live)', () => {
  it('resolves names served by Microsoft o365filtering.com, which answers FORMERR to EDNS', async () => {
    const r = await new ResolveSession().resolve('cnn-com.mail.protection.outlook.com', 'A');
    expect(r.answers.filter((a) => a.type === 'A').length).toBeGreaterThan(0);
  });
});

describe('name-server addresses', () => {
  it('never asks a name server on a private, loopback or reserved address (glue or resolved)', () => {
    const usable = (ip: string) => (new ResolveSession() as unknown as { usable(ip: string): boolean }).usable(ip);
    expect(['10.0.0.53', '127.0.0.1', '172.17.0.1', '192.168.1.1', '169.254.169.254', '::ffff:10.0.0.1'].map(usable)).toEqual([false, false, false, false, false, false]);
    expect(usable('8.8.8.8')).toBe(true);
  });
});
