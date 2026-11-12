// Test helper: a local HTTP server that records requests and answers from a handler, and an
// ApiFetch that reaches it directly. The production ApiFetch refuses private addresses (SSRF
// protection) and is never weakened for tests: tests inject this one instead.
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { fetch as ufetch } from 'undici';
import type { ApiFetch } from './source.js';

export interface FakeRequest {
  method: string;
  url: string;
  path: string;
  query: URLSearchParams;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface FakeReply {
  status?: number;
  headers?: Record<string, string>;
  body?: string | object;
}

export interface FakeServer {
  base: string;
  port: number;
  requests: FakeRequest[];
  fetch: ApiFetch;
  close(): Promise<void>;
}

export async function fakeServer(handler: (req: FakeRequest) => FakeReply | Promise<FakeReply>): Promise<FakeServer> {
  const requests: FakeRequest[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', async () => {
      const u = new URL(req.url ?? '/', 'http://fake.local');
      const r: FakeRequest = { method: req.method ?? 'GET', url: req.url ?? '/', path: u.pathname, query: u.searchParams, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') };
      requests.push(r);
      try {
        const out = await handler(r);
        const body = typeof out.body === 'string' || out.body === undefined ? (out.body ?? '') : JSON.stringify(out.body);
        res.writeHead(out.status ?? 200, { 'content-type': typeof out.body === 'object' ? 'application/json' : 'text/plain', ...out.headers });
        res.end(body);
      } catch (e) {
        res.writeHead(500);
        res.end((e as Error).message);
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  const base = `http://127.0.0.1:${port}`;
  const fetch: ApiFetch = async (url, req = {}) => {
    const started = performance.now();
    const res = await ufetch(url, { method: req.method ?? 'GET', headers: req.headers, body: req.body, redirect: 'manual' });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k] = v));
    return { status: res.status, headers, text: await res.text(), truncated: false, ms: Math.round(performance.now() - started) };
  };
  return {
    base,
    port,
    requests,
    fetch,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
