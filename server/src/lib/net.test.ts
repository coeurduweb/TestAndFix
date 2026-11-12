import { describe, expect, it } from 'vitest';
import http from 'node:http';
import { safeGet } from './net.js';
import { httpGet } from './email-auth/http.js';

describe('SSRF guard on IP literals', () => {
  it('refuses private IP literals before connecting', async () => {
    const srv = http.createServer((_q, r) => r.end('secret')).listen(0, '127.0.0.1');
    await new Promise((r) => srv.once('listening', r));
    const port = (srv.address() as { port: number }).port;
    try {
      for (const u of [`http://127.0.0.1:${port}/`, `http://[::ffff:127.0.0.1]:${port}/`, `http://10.0.0.1/`, `http://[::1]:${port}/`]) {
        await expect(safeGet(u)).rejects.toThrow(/non publique/);
        await expect(httpGet(u)).rejects.toThrow(/non publique/);
      }
    } finally {
      srv.close();
    }
  });
});
