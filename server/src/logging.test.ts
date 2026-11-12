// Request logs keep method, route pattern, status and time; never the URL, query, params or cookies.
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startTestApp, type Agent, type TestApp } from './test-helpers.js';
import type { ServerTool } from './tools/types.js';

const lines: string[] = [];
const sink = new Writable({
  write(chunk, _enc, cb) {
    lines.push(...String(chunk).split('\n').filter(Boolean));
    cb();
  },
});

const echo: ServerTool = {
  id: 'echo',
  register(app) {
    app.get<{ Params: { domain: string } }>('/api/echo/:domain', async (req) => ({ domain: req.params.domain }));
  },
};

let t: TestApp;
let A: Agent;
beforeAll(async () => {
  t = await startTestApp({ tools: [echo], logStream: sink });
  A = await t.agent();
});
afterAll(() => t?.close());

describe('request log', () => {
  it('logs the route pattern, never the real URL, query string or cookies', async () => {
    lines.length = 0;
    await A.get('/api/echo/secret-client.fr?ip=203.0.113.77&url=https%3A%2F%2Fprive.exemple%2Fpage');
    await A.del('/api/me/devices/jeton-secret');
    await A.get('/api/rien/ici-secret-404');
    const all = lines.join('\n');
    expect(all).not.toMatch(/secret|203\.0\.113\.77|prive\.exemple|jeton/);
    for (const [k, v] of A.jar) {
      expect(all).not.toContain(v);
      void k;
    }
    const logs = lines.map((l) => JSON.parse(l));
    const incoming = logs.filter((l) => l.msg === 'incoming request');
    expect(incoming.map((l) => l.req)).toEqual([
      { method: 'GET', route: '/api/echo/:domain' },
      { method: 'DELETE', route: '/api/me/devices/:id' },
      { method: 'GET', route: '(inconnue)' },
    ]);
    const completed = logs.filter((l) => l.msg === 'request completed');
    expect(completed.map((l) => l.res.statusCode)).toEqual([200, 404, 404]);
    expect(completed.every((l) => typeof l.responseTime === 'number')).toBe(true);
  });
});
