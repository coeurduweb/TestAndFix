// Test helper: a local recursive resolver that relays every query to a real one (1.1.1.1),
// except the names listed in `overrides`, answered with the given A records. It reproduces a
// resolver that rewrites some answers (seen live: 192.172.250.8 answers 127.0.0.1 for
// example.com with a 3 h TTL) without depending on that resolver being reachable.
import dgram from 'node:dgram';
import * as packet from 'dns-packet';

export interface FakeResolver {
  port: number;
  close(): Promise<void>;
}

export interface Override {
  a?: string;
  ttl?: number;
  /** Answer NXDOMAIN, with this SOA in the authority section (or none). */
  nxdomain?: { soa?: { zone: string; serial: number; ttl?: number } };
  /** Ignore the first N queries for this name (an intermittent resolver), then relay. */
  dropFirst?: number;
}

export async function startFakeResolver(overrides: Record<string, Override>, upstream = '1.1.1.1'): Promise<FakeResolver> {
  const sock = dgram.createSocket('udp4');
  sock.on('message', (msg, rinfo) => {
    let q: packet.Packet;
    try {
      q = packet.decode(msg);
    } catch {
      return;
    }
    const question = q.questions?.[0];
    const o = question && overrides[question.name.toLowerCase().replace(/\.$/, '')];
    if (question && o?.dropFirst) {
      o.dropFirst--;
      return;
    }
    if (question && o?.nxdomain) {
      const soa = o.nxdomain.soa;
      const authorities = soa
        ? [{ name: soa.zone, type: 'SOA' as const, ttl: soa.ttl ?? 300, data: { mname: 'ns.' + soa.zone, rname: 'hostmaster.' + soa.zone, serial: soa.serial, refresh: 3600, retry: 600, expire: 604800, minimum: 300 } }]
        : [];
      const flags = packet.RECURSION_DESIRED | packet.RECURSION_AVAILABLE | 3; // rcode 3 = NXDOMAIN
      sock.send(packet.encode({ type: 'response', id: q.id, flags, questions: [question], answers: [], authorities }), rinfo.port, rinfo.address);
      return;
    }
    if (question && o?.a) {
      const answers = question.type === 'A' ? [{ name: question.name, type: 'A' as const, ttl: o.ttl ?? 10800, data: o.a }] : [];
      const out = packet.encode({ type: 'response', id: q.id, flags: packet.RECURSION_DESIRED | packet.RECURSION_AVAILABLE, questions: [question], answers });
      sock.send(out, rinfo.port, rinfo.address);
      return;
    }
    // relay as is, the upstream answer keeps the query id
    const up = dgram.createSocket('udp4');
    const t = setTimeout(() => up.close(), 3000);
    up.on('message', (res) => {
      clearTimeout(t);
      up.close();
      sock.send(res, rinfo.port, rinfo.address);
    });
    up.send(msg, 53, upstream);
  });
  await new Promise<void>((ok) => sock.bind(0, '127.0.0.1', ok));
  return {
    port: sock.address().port,
    close: () => new Promise((ok) => sock.close(() => ok())),
  };
}
