// Server-Sent Events helper. Each event is a JSON payload with an event name.
import type { FastifyReply, FastifyRequest } from 'fastify';

export interface SseStream {
  send(event: string, data: unknown): void;
  close(): void;
  closed: boolean;
  signal: AbortSignal;
}

export function openSse(req: FastifyRequest, reply: FastifyReply): SseStream {
  const ac = new AbortController();
  reply.hijack();
  const res = reply.raw;
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(': ok\n\n');
  const heartbeat = setInterval(() => res.write(': ping\n\n'), 15000);
  const stream: SseStream = {
    closed: false,
    signal: ac.signal,
    send(event, data) {
      if (stream.closed) return;
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    },
    close() {
      if (stream.closed) return;
      stream.closed = true;
      clearInterval(heartbeat);
      res.end();
    },
  };
  // reply.raw closes when the client goes away; req.raw 'close' fires as soon as a POST body is read
  res.on('close', () => {
    stream.closed = true;
    clearInterval(heartbeat);
    ac.abort();
  });
  return stream;
}
