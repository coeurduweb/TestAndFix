import net from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseReportRules, parseSpamHeader, spamdPing, spamdReport } from './spamd.js';
import { analyzeMessage } from './analyze/index.js';
import { deps, fakeResolver, fixture, goodZone, SENDER_IP } from './test-helpers.js';

/** Fake spamd: reads a SPAMC/1.5 request and answers like spamd 4 does. */
function fakeSpamd(): Promise<{ port: number; requests: { command: string; headers: Record<string, string>; body: string }[]; close: () => Promise<void> }> {
  const requests: { command: string; headers: Record<string, string>; body: string }[] = [];
  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      const sep = buf.indexOf('\r\n\r\n');
      if (sep < 0) return;
      const head = buf.subarray(0, sep).toString('latin1').split('\r\n');
      const headers: Record<string, string> = {};
      for (const l of head.slice(1)) headers[l.split(':')[0].toLowerCase()] = l.slice(l.indexOf(':') + 1).trim();
      const len = Number(headers['content-length'] ?? 0);
      if (buf.length < sep + 4 + len) return;
      const body = buf.subarray(sep + 4, sep + 4 + len).toString('latin1');
      const command = head[0].split(' ')[0];
      requests.push({ command, headers, body });
      if (command === 'PING') return sock.end('SPAMD/1.5 0 PONG\r\n');
      const gtube = body.includes('GTUBE');
      const report = gtube
        ? '1000 GTUBE                  BODY: Generic Test for Unsolicited Bulk Email\n'
        : ' 0.1 MISSING_MID            Missing Message-Id: header\n 1.2 HTML_IMAGE_ONLY_08     BODY: HTML: images with 400-800 bytes of\n                            words\n-0.1 DKIM_VALID             Message has at least one valid DKIM or DK signature\n 0.0 NO_RELAYS              Informational: message was not relayed via SMTP\n';
      const score = gtube ? '1000.0' : '1.2';
      const out = Buffer.from(report, 'utf8');
      sock.end(`SPAMD/1.1 0 EX_OK\r\nContent-length: ${out.length}\r\nSpam: ${gtube ? 'True' : 'False'} ; ${score} / 5.0\r\n\r\n${report}`);
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve({ port: (server.address() as net.AddressInfo).port, requests, close: () => new Promise((r) => server.close(() => r())) }),
    ),
  );
}

let spamd: Awaited<ReturnType<typeof fakeSpamd>>;
beforeAll(async () => {
  spamd = await fakeSpamd();
});
afterAll(async () => {
  await spamd.close();
});

describe('spamc protocol', () => {
  it('sends REPORT with Content-length and parses score and rules', async () => {
    const msg = fixture('no-message-id.eml');
    const r = await spamdReport(msg, { host: '127.0.0.1', port: spamd.port });
    const req = spamd.requests.at(-1)!;
    expect(req.command).toBe('REPORT');
    expect(Number(req.headers['content-length'])).toBe(msg.length);
    expect(req.body).toBe(msg.toString('latin1'));
    expect(r).toMatchObject({ isSpam: false, score: 1.2, threshold: 5 });
    expect(r.rules.map((x) => [x.name, x.score])).toEqual([
      ['MISSING_MID', 0.1],
      ['HTML_IMAGE_ONLY_08', 1.2],
      ['DKIM_VALID', -0.1],
      ['NO_RELAYS', 0],
    ]);
    expect(r.rules[1].description).toBe('BODY: HTML: images with 400-800 bytes of words');
  });

  it('answers PING', async () => {
    expect(await spamdPing({ host: '127.0.0.1', port: spamd.port })).toBe(true);
    expect(await spamdPing({ host: '127.0.0.1', port: 1, timeoutMs: 500 })).toBe(false);
  });

  it('parses the stock report table and the Spam header', () => {
    const report = [
      'Content analysis details:   (6.1 points, 5.0 required)',
      '',
      ' pts rule name              description',
      '---- ---------------------- --------------------------------------------------',
      ' 2.5 URIBL_DBL_SPAM         Contains a spam URL listed in the Spamhaus DBL',
      '                            blocklist',
      '                            [URIs: exemple.fr]',
      ' 3.6 RCVD_IN_PBL            RBL: Received via a relay in Spamhaus PBL',
      '',
    ].join('\n');
    expect(parseReportRules(report)).toEqual([
      { score: 2.5, name: 'URIBL_DBL_SPAM', description: 'Contains a spam URL listed in the Spamhaus DBL blocklist [URIs: exemple.fr]' },
      { score: 3.6, name: 'RCVD_IN_PBL', description: 'RBL: Received via a relay in Spamhaus PBL' },
    ]);
    expect(parseSpamHeader('True ; 1000.0 / 5.0')).toEqual({ isSpam: true, score: 1000, threshold: 5 });
  });
});

describe('SpamAssassin in the analysis', () => {
  const input = () => ({ raw: fixture('no-message-id.eml'), via: 'smtp' as const, clientIp: SENDER_IP, helo: 'mail.atelier-exemple.fr', mailFrom: 'paul@atelier-exemple.fr', tls: null });

  it('turns each rule into a finding, negative rules into passed checks', async () => {
    const r = await analyzeMessage(input(), deps(fakeResolver(goodZone()), { spamd: { host: '127.0.0.1', port: spamd.port } }));
    const sa = r.data.spamassassin as { available: boolean; score: number; rules: unknown[] };
    expect(sa).toMatchObject({ available: true, score: 1.2 });
    const html = r.findings.find((f) => f.evidence?.includes('HTML_IMAGE_ONLY_08'));
    expect(html).toBeDefined();
    expect(r.passed.some((p) => p.id === 'sa.dkim_valid')).toBe(true);
    // MISSING_MID and our own Message-ID check end up in one finding when the base maps them
    expect(r.findings.filter((f) => f.id === 'headers.message_id_missing').length).toBeLessThanOrEqual(1);
  });

  it('is never blocking: spamd down gives an unavailable source and a score without it', async () => {
    const r = await analyzeMessage(input(), deps(fakeResolver(goodZone()), { spamd: { host: '127.0.0.1', port: 1, timeoutMs: 1000 } }));
    expect(r.unavailable?.find((u) => u.source === 'SpamAssassin')?.reason).toMatch(/injoignable/);
    expect(typeof r.score).toBe('number');
    expect((r.data.spamassassin as { available: boolean }).available).toBe(false);
  });

  it('GTUBE is reported as spam', async () => {
    const raw = Buffer.from(fixture('no-message-id.eml').toString('latin1') + 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n', 'latin1');
    const r = await analyzeMessage({ ...input(), raw }, deps(fakeResolver(goodZone()), { spamd: { host: '127.0.0.1', port: spamd.port } }));
    expect((r.data.spamassassin as { isSpam: boolean }).isSpam).toBe(true);
    const gtube = r.findings.find((f) => f.evidence?.includes('GTUBE'));
    expect(gtube?.penalty).toBeGreaterThan(0);
    expect(r.score).toBeLessThan(8);
  });
});
