import type { AddressInfo } from 'node:net';
import { SMTPServer } from 'smtp-server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { GuardedResolver } from './common.js';
import { FakeDns } from './fake-dns.js';
import { UNAVAILABLE_PORT25, analyzeSmtp, probeSmtp, type SmtpProbe } from './smtp-probe.js';

let server: SMTPServer;
let port: number;

beforeAll(async () => {
  // smtp-server offers STARTTLS with its built-in self-signed certificate
  server = new SMTPServer({ name: 'mx.local.test', authOptional: true, disabledCommands: ['AUTH'], logger: false });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = ((server as unknown as { server: { address(): AddressInfo } }).server.address()).port;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe('SMTP probe (local server)', () => {
  it('reads banner, EHLO, STARTTLS and the certificate', async () => {
    const p = await probeSmtp('mx.example.fr', '127.0.0.1', { port, timeoutMs: 5000, ehloName: 'check.test' });
    expect(p.status).toBe('ok');
    expect(p.banner).toMatch(/^220 mx\.local\.test/);
    expect(p.extensions).toContain('STARTTLS');
    expect(p.tls?.ok).toBe(true);
    expect(p.tls?.protocol).toMatch(/^TLSv1\.[23]$/);
    expect(p.tls?.cert?.trusted).toBe(false);
    expect(p.tls?.cert?.nameMatches).toBe(false);
    expect(p.tls?.ehloAfter?.at(-1)).toMatch(/^250 /);
    expect(p.transcript.some((l) => l === 'C: QUIT')).toBe(true);
  });
  it('reports a refused connection', async () => {
    const p = await probeSmtp('mx.example.fr', '127.0.0.1', { port: 1, timeoutMs: 2000 });
    expect(p.status).toBe('refused');
  });
});

describe('SMTP analysis', () => {
  const dns = new FakeDns({ 'example.fr': { MX: [{ preference: 10, exchange: 'mx.example.fr' }] }, 'mx.example.fr': { A: ['192.0.2.25'] } });
  it('says "non vérifiable depuis cette machine" when port 25 is filtered', async () => {
    const a = await analyzeSmtp(dns, 'example.fr', { reachability: async () => ({ reachable: false, detail: 'délai dépassé' }) });
    expect(a.issues).toEqual([]);
    expect(a.unavailable?.[0].reason).toContain('non vérifiable depuis cette machine');
  });
  it('turns probe results into TLS findings', async () => {
    const probe = async (host: string, ip: string): Promise<SmtpProbe> => ({
      host, ip, port: 25, status: 'ok', banner: '220 mx.example.fr ESMTP', extensions: ['PIPELINING'], starttls: false, transcript: [],
    });
    const a = await analyzeSmtp(dns, 'example.fr', { reachability: async () => ({ reachable: true, detail: 'ok' }), probe });
    expect(a.issues.map((i) => i.id)).toEqual(['tls.mx_no_starttls']);
  });
  it('is honest about this machine (live)', async () => {
    const a = await analyzeSmtp(new GuardedResolver(new ResolveSession(), () => new ResolveSession()), 'gmail.com', { timeoutMs: 4000 });
    if (!a.data.port25.reachable) expect(a.unavailable?.[0].reason).toContain(UNAVAILABLE_PORT25);
    else expect(a.data.probes.length).toBeGreaterThan(0);
  });
});
