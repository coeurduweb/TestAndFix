// Local HTTP and HTTPS test site for the redirect tracer tests (self-signed certificate generated
// on the fly with openssl). Used only by *.test.ts files.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { isPublicIp } from './net.js';
import type { NetworkSeam } from './http-trace.js';

export interface TestSite {
  http: number;
  https: number;
  network: NetworkSeam;
  close(): Promise<void>;
}

const page = (body: string, head = '') => `<!doctype html><html><head><meta charset="utf-8">${head}<title>t</title></head><body>${body}</body></html>`;

/** Shared by the redirect tests. Host names ending in .test resolve to 127.0.0.1, private.test to 10.0.0.1. */
export async function startTestSite(): Promise<TestSite> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'check-trace-'));
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=site.test',
    '-addext', 'subjectAltName=DNS:site.test,DNS:www.site.test',
    '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'),
  ], { stdio: 'ignore' });
  const ports = { http: 0, https: 0 };
  const handler = (secure: boolean) => (req: http.IncomingMessage, res: http.ServerResponse) => {
    const u = new URL(req.url ?? '/', 'http://x');
    const p = u.pathname;
    const go = (code: number, loc: string, extra: Record<string, string> = {}) => {
      res.writeHead(code, { Location: loc, ...extra });
      res.end();
    };
    if (secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    switch (p) {
      case '/301': return go(301, '/final');
      case '/302': return go(302, '/final');
      case '/307': return go(307, '/final');
      case '/308': return go(308, '/final');
      case '/relative': return go(301, '../final');
      case '/chain': return go(301, '/chain2');
      case '/chain2': return go(302, '/chain3');
      case '/chain3': return go(301, '/final');
      case '/loop-a': return go(302, '/loop-b');
      case '/loop-b': return go(302, '/loop-a');
      case '/self': return go(302, '/self');
      case '/to-https': return go(301, `https://site.test:${ports.https}/final`);
      case '/to-http': return go(301, `http://site.test:${ports.http}/final`);
      case '/www': return go(302, `http://www.site.test:${ports.http}/final`);
      case '/to-private': return go(301, 'http://private.test/');
      case '/to-404': return go(301, '/missing');
      case '/no-location': res.writeHead(302); return res.end();
      case '/cookie':
        if ((req.headers.cookie ?? '').includes('seen=1')) return go(302, '/final');
        return go(302, '/cookie', { 'Set-Cookie': 'seen=1; Path=/; HttpOnly' });
      case '/meta':
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(page('', '<meta http-equiv="refresh" content="0; url=/final">'));
      case '/js':
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(page('<script>window.location.href = "/final";</script>'));
      case '/js-content':
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(page(`<p>${'Contenu réel. '.repeat(200)}</p><script>function go(){ location.href = "/ailleurs"; }</script>`));
      case '/refresh':
        res.writeHead(200, { 'Content-Type': 'text/plain', Refresh: '2; url=/final' });
        return res.end('wait');
      case '/gzip':
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Encoding': 'gzip' });
        return res.end(zlib.gzipSync(page('<p>compressé gzip</p>'.repeat(50))));
      case '/br':
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Encoding': 'br' });
        return res.end(zlib.brotliCompressSync(Buffer.from(page('<p>compressé brotli</p>'.repeat(50)))));
      case '/latin1':
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=windows-1252' });
        return res.end(Buffer.from([0x63, 0x61, 0x66, 0xe9]));
      case '/big':
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(page('x'.repeat(3 * 1024 * 1024)));
      case '/wp':
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(page('<img src="/wp-content/uploads/a.png">'));
      case '/missing':
        res.writeHead(404, { 'Content-Type': 'text/html' });
        return res.end(page('introuvable'));
      case '/final':
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'index' });
        return res.end(page('<h1>Arrivée</h1>', `<link rel="canonical" href="${secure ? 'https' : 'http'}://${req.headers.host}/final">`));
      default:
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(page('accueil'));
    }
  };
  const h1 = http.createServer(handler(false));
  const h2 = https.createServer({ key: fs.readFileSync(path.join(dir, 'k.pem')), cert: fs.readFileSync(path.join(dir, 'c.pem')) }, handler(true));
  await new Promise<void>((r) => h1.listen(0, '127.0.0.1', r));
  await new Promise<void>((r) => h2.listen(0, '127.0.0.1', r));
  ports.http = (h1.address() as { port: number }).port;
  ports.https = (h2.address() as { port: number }).port;
  return {
    ...ports,
    network: {
      lookup: async (host) => {
        if (host === 'private.test') return { ip: '10.0.0.1' };
        if (host.endsWith('.test')) return { ip: '127.0.0.1' };
        throw Object.assign(new Error(`Le nom ${host} n'existe pas.`), { code: 'ENOTFOUND', own: true });
      },
      isAllowed: (ip) => ip === '127.0.0.1' || isPublicIp(ip),
    },
    close: async () => {
      await new Promise((r) => h1.close(r));
      await new Promise((r) => h2.close(r));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

