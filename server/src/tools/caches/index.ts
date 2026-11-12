// Cache flush on the machine that hosts the tool, through the host agent (agent/check-agent.py).
// The user's own workstation is flushed by the browser calling its local agent directly.
import type { ServerTool } from '../types.js';
import { config } from '../../config.js';

interface FlushBody {
  dns?: boolean;
  page_cache?: boolean;
}

async function callAgent(path: string, init: RequestInit = {}) {
  const res = await fetch(new URL(path, config.agent.url), {
    ...init,
    headers: { authorization: `Bearer ${config.agent.token}`, 'content-type': 'application/json', ...init.headers },
    signal: AbortSignal.timeout(60_000),
  });
  const text = await res.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    /* keep text */
  }
  return { status: res.status, body };
}

export const tool: ServerTool = {
  id: 'caches',
  register(app) {
    app.get('/api/caches/server', async () => {
      if (!config.agent.token) return { available: false, reason: 'not_configured' };
      try {
        const r = await callAgent('/health');
        return { available: r.status === 200, health: r.body };
      } catch (e) {
        return { available: false, reason: 'unreachable', detail: (e as Error).message };
      }
    });
    app.post<{ Body: FlushBody }>('/api/caches/server/flush', async (req, reply) => {
      if (!config.agent.token) return reply.code(503).send({ error: 'agent_not_configured' });
      try {
        const r = await callAgent('/flush', {
          method: 'POST',
          body: JSON.stringify({ dns: req.body?.dns ?? true, page_cache: req.body?.page_cache ?? true }),
        });
        return reply.code(r.status).send(r.body);
      } catch (e) {
        return reply.code(502).send({ error: 'agent_unreachable', detail: (e as Error).message });
      }
    });
  },
};
