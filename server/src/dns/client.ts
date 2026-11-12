// Minimal DNS client over UDP/TCP built on dns-packet.
// No cache of any kind: every call sends a real query on the wire.
import dgram from 'node:dgram';
import net from 'node:net';
import { randomInt } from 'node:crypto';
import * as packet from 'dns-packet';

export type RRType = packet.RecordType;

export interface DnsAnswer {
  name: string;
  type: string;
  ttl: number;
  class?: string;
  data: unknown;
}

export interface DnsResponse {
  server: string;
  transport: 'udp' | 'tcp';
  rtt: number;
  rcode: string;
  flags: { aa: boolean; tc: boolean; rd: boolean; ra: boolean; ad: boolean; cd: boolean };
  answers: DnsAnswer[];
  authorities: DnsAnswer[];
  additionals: DnsAnswer[];
}

export interface QueryOptions {
  /** Recursion desired. false when talking to authoritative servers. */
  rd?: boolean;
  /** Set the DNSSEC OK bit and ask for RRSIGs. */
  dnssec?: boolean;
  /** Checking disabled bit (ask a validating resolver not to validate). */
  cd?: boolean;
  timeoutMs?: number;
  port?: number;
  forceTcp?: boolean;
  /** Send no OPT record (for servers that answer FORMERR to EDNS). */
  noEdns?: boolean;
  signal?: AbortSignal;
}

export class DnsTimeoutError extends Error {
  code = 'ETIMEOUT';
  constructor(public server: string, public name: string) {
    super(`DNS timeout querying ${server} for ${name}`);
  }
}

const FLAG_AA = 1 << 10;
const FLAG_TC = 1 << 9;
const FLAG_RD = 1 << 8;
const FLAG_RA = 1 << 7;
const FLAG_AD = 1 << 5;
const FLAG_CD = 1 << 4;

function buildQuery(name: string, type: RRType, opts: QueryOptions): { id: number; buf: Buffer } {
  const id = randomInt(0, 65536);
  let flags = 0;
  if (opts.rd !== false) flags |= FLAG_RD;
  if (opts.cd) flags |= FLAG_CD;
  if (opts.dnssec) flags |= FLAG_AD;
  const buf = packet.encode({
    type: 'query',
    id,
    flags,
    questions: [{ type, name, class: 'IN' }],
    additionals: opts.noEdns ? [] : [
      {
        type: 'OPT',
        name: '.',
        udpPayloadSize: 1232,
        extendedRcode: 0,
        ednsVersion: 0,
        flags: opts.dnssec ? packet.DNSSEC_OK : 0,
        options: [],
      } as unknown as packet.Answer,
    ],
  });
  return { id, buf };
}

function toResponse(server: string, transport: 'udp' | 'tcp', rtt: number, msg: packet.Packet): DnsResponse {
  const f = msg.flags ?? 0;
  const conv = (list: packet.Answer[] | undefined): DnsAnswer[] =>
    (list ?? [])
      .filter((a) => a.type !== 'OPT')
      .map((a) => ({
        name: a.name,
        type: a.type,
        ttl: (a as { ttl?: number }).ttl ?? 0,
        class: (a as { class?: string }).class,
        data: (a as { data?: unknown }).data,
      }));
  return {
    server,
    transport,
    rtt,
    rcode: (msg as { rcode?: string }).rcode ?? 'NOERROR',
    flags: {
      aa: !!(f & FLAG_AA),
      tc: !!(f & FLAG_TC),
      rd: !!(f & FLAG_RD),
      ra: !!(f & FLAG_RA),
      ad: !!(f & FLAG_AD),
      cd: !!(f & FLAG_CD),
    },
    answers: conv(msg.answers),
    authorities: conv(msg.authorities),
    additionals: conv(msg.additionals),
  };
}

function queryUdp(server: string, name: string, type: RRType, opts: QueryOptions): Promise<DnsResponse> {
  return new Promise((resolve, reject) => {
    const { id, buf } = buildQuery(name, type, opts);
    const family = net.isIPv6(server) ? 'udp6' : 'udp4';
    const sock = dgram.createSocket(family);
    const started = performance.now();
    let done = false;
    const finish = (err: Error | null, res?: DnsResponse) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      try {
        sock.close();
      } catch {
        /* already closed */
      }
      if (err) reject(err);
      else resolve(res!);
    };
    const onAbort = () => finish(new Error('aborted'));
    const timer = setTimeout(() => finish(new DnsTimeoutError(server, name)), opts.timeoutMs ?? 2500);
    opts.signal?.addEventListener('abort', onAbort);
    sock.on('error', (e) => finish(e));
    sock.on('message', (msg) => {
      let decoded: packet.Packet;
      try {
        decoded = packet.decode(msg);
      } catch (e) {
        return finish(e as Error);
      }
      if (decoded.id !== id) return; // stray or spoofed packet: keep waiting
      finish(null, toResponse(server, 'udp', Math.round(performance.now() - started), decoded));
    });
    sock.send(buf, opts.port ?? 53, server, (err) => {
      if (err) finish(err);
    });
  });
}

function queryTcp(server: string, name: string, type: RRType, opts: QueryOptions): Promise<DnsResponse> {
  return new Promise((resolve, reject) => {
    const { id, buf } = buildQuery(name, type, opts);
    const started = performance.now();
    const sock = net.createConnection({ host: server, port: opts.port ?? 53 });
    let chunks = Buffer.alloc(0);
    let done = false;
    const finish = (err: Error | null, res?: DnsResponse) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      if (err) reject(err);
      else resolve(res!);
    };
    const timer = setTimeout(() => finish(new DnsTimeoutError(server, name)), (opts.timeoutMs ?? 2500) * 2);
    opts.signal?.addEventListener('abort', () => finish(new Error('aborted')), { once: true });
    sock.on('error', (e) => finish(e));
    sock.on('connect', () => {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(buf.length);
      sock.write(Buffer.concat([len, buf]));
    });
    sock.on('data', (d) => {
      chunks = Buffer.concat([chunks, Buffer.from(d as Buffer)]);
      if (chunks.length < 2) return;
      const need = chunks.readUInt16BE(0);
      if (chunks.length < need + 2) return;
      try {
        const decoded = packet.decode(chunks.subarray(2, need + 2));
        if (decoded.id !== id) return finish(new Error('DNS id mismatch over TCP'));
        finish(null, toResponse(server, 'tcp', Math.round(performance.now() - started), decoded));
      } catch (e) {
        finish(e as Error);
      }
    });
  });
}

/** Send one query to one server. Falls back to TCP when the UDP answer is truncated. */
export async function query(server: string, name: string, type: RRType, opts: QueryOptions = {}): Promise<DnsResponse> {
  const once = async (o: QueryOptions) => {
    if (o.forceTcp) return queryTcp(server, name, type, o);
    const res = await queryUdp(server, name, type, o);
    return res.flags.tc ? queryTcp(server, name, type, o) : res;
  };
  const res = await once(opts);
  // Some authoritative servers (e.g. Microsoft o365filtering.com) reject EDNS with FORMERR or NOTIMP:
  // retry once without the OPT record, as recursive resolvers do (RFC 6891 §7).
  if (!opts.noEdns && (res.rcode === 'FORMERR' || res.rcode === 'NOTIMP')) {
    return once({ ...opts, noEdns: true, dnssec: false });
  }
  return res;
}
