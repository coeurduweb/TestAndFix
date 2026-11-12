// Whois routes: behind the password, input errors answered without any network call, and nothing
// of the request (domain names) in the logs.
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Agent, startTestApp, type TestApp } from '../../test-helpers.js';
import { tool } from './index.js';

const lines: string[] = [];
const sink = new Writable({
  write(chunk, _enc, cb) {
    lines.push(...String(chunk).split('\n').filter(Boolean));
    cb();
  },
});

let t: TestApp;
beforeAll(async () => {
  t = await startTestApp({ tools: [tool], logStream: sink });
});
afterAll(() => t?.close());

describe('whois routes', () => {
  it('need the password', async () => {
    const anon = new Agent(t.base);
    expect((await anon.get('/api/whois/exemple.fr')).status).toBe(401);
    expect((await anon.post('/api/whois/batch/stream', { domains: ['exemple.fr'] })).status).toBe(401);
  });

  it('refuse bad input with a French message, and log no name', async () => {
    const A = await t.agent();
    lines.length = 0;
    const one = await A.get('/api/whois/secret-client..fr');
    expect(one.status).toBe(400);
    const empty = await A.post('/api/whois/batch/stream', { domains: 'secret-client pas-un-domaine' });
    expect(empty.status).toBe(400);
    expect(empty.json.message).toMatch(/Aucun nom de domaine/);
    const many = await A.post('/api/whois/batch/stream', { domains: Array.from({ length: 101 }, (_, i) => `secret-${i}.fr`) });
    expect(many.status).toBe(400);
    expect(many.json.message).toMatch(/100 domaines au plus/);
    expect(lines.join('\n')).not.toMatch(/secret/);
    const routes = lines.map((l) => JSON.parse(l)).filter((l) => l.msg === 'incoming request').map((l) => l.req.route);
    expect(routes).toEqual(['/api/whois/:domain', '/api/whois/batch/stream', '/api/whois/batch/stream']);
  });
});
