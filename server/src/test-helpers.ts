// Test helper: the whole app on an in-memory database, listening on a free port, and logged-in
// agents, each with its own cookie jar (so each one is a separate browser, hence a separate notebook).
import type { FastifyInstance } from 'fastify';
import { buildApp } from './app.js';
import { config } from './config.js';
import { openDb, setDb, type DB } from './db.js';
import type { ServerTool, ToolContext } from './tools/types.js';

export const TEST_PASSWORD = 'mot-de-passe-de-test';

export interface Res {
  status: number;
  json: any; // eslint-disable-line @typescript-eslint/no-explicit-any
  text: string;
  headers: Headers;
  setCookies: string[];
}

export class Agent {
  jar = new Map<string, string>();
  constructor(
    public base: string,
    public ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
  ) {}

  get cookie() {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  absorb(res: Response): string[] {
    const set = res.headers.getSetCookie();
    for (const c of set) {
      const [pair, ...attrs] = c.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i).trim();
      const value = pair.slice(i + 1).trim();
      const gone = attrs.some((a) => /^\s*max-age=0\s*$/i.test(a) || (/^\s*expires=/i.test(a) && Date.parse(a.split('=')[1]) < Date.now()));
      if (gone || !value) this.jar.delete(name);
      else this.jar.set(name, value);
    }
    return set;
  }

  async raw(path: string, init: RequestInit = {}): Promise<Response> {
    const headers: Record<string, string> = { 'user-agent': this.ua, ...(init.headers as Record<string, string>) };
    if (this.jar.size) headers.cookie = this.cookie;
    if (typeof init.body === 'string' && !Object.keys(headers).some((h) => h.toLowerCase() === 'content-type')) headers['content-type'] = 'application/json';
    return fetch(this.base + path, { ...init, headers });
  }

  async req(path: string, init: RequestInit = {}): Promise<Res> {
    const res = await this.raw(path, init);
    const setCookies = this.absorb(res);
    const text = await res.text();
    let json: unknown;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      json = undefined;
    }
    return { status: res.status, json, text, headers: res.headers, setCookies };
  }

  get = (path: string) => this.req(path);
  post = (path: string, body?: unknown) => this.req(path, { method: 'POST', body: JSON.stringify(body ?? {}) });
  del = (path: string) => this.req(path, { method: 'DELETE' });

  async login(): Promise<Res> {
    const r = await this.post('/api/auth/login', { password: TEST_PASSWORD });
    if (r.status !== 200) throw new Error(`login failed: ${r.status} ${r.text}`);
    return r;
  }

  /** Read SSE events until `until` returns true (or the timeout). */
  async sse(path: string, until: (events: { event: string; data: any }[]) => boolean, timeoutMs = 10000) {
    const ac = new AbortController();
    const res = await fetch(this.base + path, { headers: { cookie: this.cookie, accept: 'text/event-stream' }, signal: ac.signal });
    const events: { event: string; data: any }[] = []; // eslint-disable-line @typescript-eslint/no-explicit-any
    if (!/text\/event-stream/.test(res.headers.get('content-type') ?? '')) {
      return { status: res.status, body: await res.text(), events, done: Promise.resolve(events), close: () => ac.abort() };
    }
    const reader = res.body!.getReader();
    const dec = new TextDecoder();
    let buf = '';
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    const done = (async () => {
      try {
        for (;;) {
          const { value, done: end } = await reader.read();
          if (end) break;
          buf += dec.decode(value, { stream: true });
          let i: number;
          while ((i = buf.indexOf('\n\n')) >= 0) {
            const chunk = buf.slice(0, i);
            buf = buf.slice(i + 2);
            const ev = /^event: (.*)$/m.exec(chunk)?.[1];
            const data = /^data: (.*)$/m.exec(chunk)?.[1];
            if (ev && data) events.push({ event: ev, data: JSON.parse(data) });
            if (until(events)) {
              ac.abort();
              return events;
            }
          }
        }
      } catch {
        /* aborted */
      } finally {
        clearTimeout(timer);
      }
      return events;
    })();
    return { status: res.status, body: '', events, done, close: () => ac.abort() };
  }
}

export interface TestApp {
  app: FastifyInstance;
  ctx: ToolContext;
  db: DB;
  base: string;
  /** A new browser, logged in (it has its own notebook). */
  agent(ua?: string): Promise<Agent>;
  close(): Promise<void>;
}

export async function startTestApp(opts: { tools?: ServerTool[]; logStream?: NodeJS.WritableStream } = {}): Promise<TestApp> {
  config.password = TEST_PASSWORD;
  config.passwordHash = '';
  const db = openDb(':memory:');
  setDb(db); // the session secret is stored in this database, not in data/
  const { app, ctx } = await buildApp({ db, tools: opts.tools ?? [], logStream: opts.logStream });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  return {
    app,
    ctx,
    db,
    base,
    async agent(ua?: string) {
      const a = new Agent(base, ua);
      await a.login();
      return a;
    },
    close: () => app.close(),
  };
}

/** Two logged-in browsers, A and B, each in its own notebook. */
export async function twoAgents(opts: { tools?: ServerTool[] } = {}) {
  const t = await startTestApp(opts);
  const A = await t.agent();
  const B = await t.agent('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1');
  return { ...t, A, B };
}
