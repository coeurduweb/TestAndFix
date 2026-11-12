// Routes of the domain tools, mounted without the password layer.
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { config } from '../../config.js';
import { openDb } from '../../db.js';
import { ResolveSession } from '../../dns/iterative.js';
import type { CheckResult, ServerTool, ToolContext } from '../types.js';
import { tool as spf } from '../spf/index.js';
import { tool as dmarc } from '../dmarc/index.js';
import { tool as dns } from '../dns/index.js';
import { tool as domain } from './index.js';

async function app(...tools: ServerTool[]) {
  const db = openDb(':memory:');
  const ctx: ToolContext = { db, config, dns: (o) => new ResolveSession(o) };
  const a = Fastify();
  for (const t of tools) await t.register!(a, ctx);
  return { a, db };
}

describe('domain tool routes', () => {
  it('serves the SPF check and stores it in the history', async () => {
    const { a, db } = await app(spf);
    const r = await a.inject('/api/spf/gmail.com');
    expect(r.statusCode).toBe(200);
    const body = r.json() as CheckResult<{ record: string }>;
    expect(body).toMatchObject({ tool: 'spf', input: 'gmail.com' });
    expect(body.measuredAt).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    expect(body.data.record).toMatch(/^v=spf1/);
    expect(db.prepare('SELECT tool FROM results WHERE id = ?').get(body.resultId)).toEqual({ tool: 'spf' });
    const bad = await a.inject('/api/spf/not_a domain');
    expect(bad.statusCode).toBe(400);
    expect(bad.json()).toMatchObject({ error: 'invalid_input' });
    const ev = await a.inject('/api/spf/gmail.com/eval?ip=nope');
    expect(ev.statusCode).toBe(400);
  });
  it('serves DMARC and DNS', async () => {
    const { a } = await app(dmarc, dns);
    expect((await a.inject('/api/dmarc/google.com')).json()).toMatchObject({ tool: 'dmarc', data: { policy: 'reject' } });
    const r = await a.inject('/api/dns/example.com?type=ANY');
    expect(r.statusCode).toBe(400);
  });
  it('streams the domain scan section by section (SSE)', async () => {
    const { a } = await app(domain);
    const r = await a.inject('/api/domain/example.com/stream');
    const events = [...r.payload.matchAll(/^event: (\w+)$/gm)].map((m) => m[1]);
    expect(events[0]).toBe('start');
    expect(events.filter((e) => e === 'section').length).toBe(13);
    expect(events.at(-1)).toBe('done');
    const done = JSON.parse(r.payload.split('event: done\ndata: ')[1].split('\n')[0]) as CheckResult<{ sections: { id: string }[] }>;
    expect(done.score).toBeGreaterThanOrEqual(0);
    expect(done.data.sections.map((s) => s.id)).toContain('spf');
  }, 90000);
});
