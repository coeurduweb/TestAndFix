// One query to an authoritative server with an EDNS Client Subnet option (RFC 7871).
// Used only to explain a resolver answer that differs from ours: zones with geographic routing
// (github.com on NS1 and Route 53, measured 2026-11-10) give each network its own answer. Asking
// the authoritative server "what would you answer to this resolver's /24" tells a geographic
// answer from an outdated one. dns/client.ts cannot send EDNS options, hence this small client.
// No cache: one socket, one random id, one packet per call.
import dgram from 'node:dgram';
import net from 'node:net';
import { randomInt } from 'node:crypto';
import * as packet from 'dns-packet';
import type { DnsAnswer, DnsResponse, RRType } from '../../dns/client.js';

export interface EcsResponse extends DnsResponse {
  /** Scope prefix returned by the server; 0 or null means the answer does not depend on the subnet. */
  scope: number | null;
}

export function ecsQuery(
  server: string,
  name: string,
  type: RRType,
  clientIp: string,
  opts: { timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<EcsResponse> {
  return new Promise((resolve, reject) => {
    if (!net.isIPv4(clientIp) || !net.isIPv4(server)) return reject(new Error('ECS check supports IPv4 only'));
    const subnet = clientIp.split('.').slice(0, 3).concat('0').join('.');
    const id = randomInt(0, 65536);
    const buf = packet.encode({
      type: 'query',
      id,
      flags: 0, // RD=0: authoritative server
      questions: [{ type, name, class: 'IN' }],
      additionals: [
        {
          type: 'OPT',
          name: '.',
          udpPayloadSize: 1232,
          options: [{ code: 'CLIENT_SUBNET', family: 1, sourcePrefixLength: 24, scopePrefixLength: 0, ip: subnet }],
        } as unknown as packet.Answer,
      ],
    });
    const sock = dgram.createSocket('udp4');
    const started = performance.now();
    let done = false;
    const finish = (err: Error | null, res?: EcsResponse) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      try {
        sock.close();
      } catch {
        /* closed */
      }
      if (err) reject(err);
      else resolve(res!);
    };
    const onAbort = () => finish(new Error('aborted'));
    const timer = setTimeout(() => finish(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), opts.timeoutMs ?? 2000);
    opts.signal?.addEventListener('abort', onAbort);
    sock.on('error', (e) => finish(e));
    sock.on('message', (msg) => {
      let d: packet.Packet;
      try {
        d = packet.decode(msg);
      } catch (e) {
        return finish(e as Error);
      }
      if (d.id !== id) return;
      const conv = (l: packet.Answer[] | undefined): DnsAnswer[] =>
        (l ?? []).filter((a) => a.type !== 'OPT').map((a) => ({ name: a.name, type: a.type, ttl: (a as { ttl?: number }).ttl ?? 0, data: (a as { data?: unknown }).data }));
      const opt = (d.additionals ?? []).find((a) => a.type === 'OPT') as { options?: { code: number; scopePrefixLength?: number }[] } | undefined;
      const ecs = opt?.options?.find((o) => o.code === 8);
      const f = d.flags ?? 0;
      finish(null, {
        server,
        transport: 'udp',
        rtt: Math.round(performance.now() - started),
        rcode: (d as { rcode?: string }).rcode ?? 'NOERROR',
        flags: { aa: !!(f & (1 << 10)), tc: !!(f & (1 << 9)), rd: false, ra: false, ad: false, cd: false },
        answers: conv(d.answers),
        authorities: conv(d.authorities),
        additionals: [],
        scope: ecs?.scopePrefixLength ?? null,
      });
    });
    sock.send(buf, 53, server, (err) => err && finish(err));
  });
}
