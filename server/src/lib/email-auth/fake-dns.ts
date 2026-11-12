// In-memory resolver for tests: a zone described as { name: { TYPE: [data] } }, with CNAME
// following, NXDOMAIN for unknown names and SERVFAIL on demand. Shapes match dns-packet's.
import { DnsLookupError, type ResolveResult } from '../../dns/iterative.js';
import type { RRType } from '../../dns/client.js';
import type { Resolver } from './common.js';

export type FakeZone = Record<string, Record<string, unknown[]> | 'SERVFAIL'>;

export class FakeDns implements Resolver {
  public queries: string[] = [];
  constructor(private zone: FakeZone) {}
  async resolve(name: string, type: RRType): Promise<ResolveResult> {
    const cnames: string[] = [];
    let current = name.toLowerCase().replace(/\.$/, '');
    this.queries.push(`${current} ${type}`);
    for (let i = 0; i < 10; i++) {
      const node = this.zone[current];
      const base = { name, type, cnames, trace: [], ms: 0, zone: 'fake.', answeredBy: 'fake' };
      if (node === 'SERVFAIL') throw new DnsLookupError('SERVFAIL', `fake SERVFAIL ${current}`);
      if (!node) return { ...base, rcode: 'NXDOMAIN', answers: [] };
      if (node.CNAME && type !== 'CNAME') {
        cnames.push(String(node.CNAME[0]));
        current = String(node.CNAME[0]);
        continue;
      }
      const data = node[type] ?? [];
      return {
        ...base,
        rcode: 'NOERROR',
        answers: data.map((d) => ({ name: current, type, ttl: 300, data: type === 'TXT' ? toTxt(d) : d })),
      };
    }
    throw new DnsLookupError('ELOOP', 'CNAME loop');
  }
}

/** TXT data as dns-packet returns it: an array of Buffers (one per character-string). */
function toTxt(d: unknown): Buffer[] {
  const parts = Array.isArray(d) ? d : [d];
  return parts.map((p) => Buffer.from(String(p)));
}
