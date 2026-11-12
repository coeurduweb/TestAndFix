import { describe, expect, it } from 'vitest';
import type { DnsAnswer, DnsResponse } from '../../dns/client.js';
import { DnsTimeoutError } from '../../dns/client.js';
import { summarize, type ResolverEvent } from './check.js';
import { observe, type Reference } from './status.js';

const ans = (name: string, type: string, data: unknown, ttl = 300): DnsAnswer => ({ name, type, ttl, data });
const res = (rcode: string, answers: DnsAnswer[] = [], authorities: DnsAnswer[] = []): DnsResponse => ({
  server: '192.0.2.53',
  transport: 'udp',
  rtt: 12,
  rcode,
  flags: { aa: false, tc: false, rd: true, ra: true, ad: false, cd: false },
  answers,
  authorities,
  additionals: [],
});
const ref = (values: string[], extra: Partial<Reference> = {}): Reference => ({
  source: 'authority',
  exists: values.length > 0,
  kind: 'records',
  values,
  cname: null,
  ...extra,
});
const AT = Date.parse('2026-11-10T12:00:00Z');

describe('observe: status of one resolver', () => {
  it('fresh when the records equal the reference, order ignored', () => {
    const o = observe('A', 'example.com', ref(['192.0.2.1', '192.0.2.2']), res('NOERROR', [ans('example.com', 'A', '192.0.2.2', 77), ans('example.com', 'A', '192.0.2.1', 77)]), undefined, AT);
    expect(o).toMatchObject({ status: 'fresh', ttl: 77, refreshAt: null });
  });
  it('stale with the refresh time: now + remaining TTL', () => {
    const o = observe('A', 'example.com', ref(['192.0.2.1']), res('NOERROR', [ans('example.com', 'A', '198.51.100.1', 120)]), undefined, AT);
    expect(o.status).toBe('stale');
    expect(o.values).toEqual(['198.51.100.1']);
    expect(o.refreshAt).toBe('2026-11-10T12:02:00.000Z');
  });
  it('missing on NXDOMAIN or NODATA while the reference exists, with the negative TTL', () => {
    const soa = ans('example.com', 'SOA', { minimum: 900 }, 600);
    expect(observe('A', 'new.example.com', ref(['192.0.2.1']), res('NXDOMAIN', [], [soa]), undefined, AT)).toMatchObject({
      status: 'missing',
      ttl: 600,
      refreshAt: '2026-11-10T12:10:00.000Z',
    });
    expect(observe('TXT', 'example.com', ref(['x']), res('NOERROR'), undefined, AT).status).toBe('missing');
  });
  it('fresh when both say the record does not exist; stale when the resolver still has a deleted record', () => {
    expect(observe('A', 'gone.example.com', ref([]), res('NXDOMAIN'), undefined, AT).status).toBe('fresh');
    expect(observe('A', 'gone.example.com', ref([]), res('NOERROR', [ans('gone.example.com', 'A', '192.0.2.1')]), undefined, AT).status).toBe('stale');
  });
  it('error on SERVFAIL or REFUSED, timeout on no answer', () => {
    expect(observe('A', 'example.com', ref(['192.0.2.1']), res('SERVFAIL')).status).toBe('error');
    expect(observe('A', 'example.com', ref(['192.0.2.1']), res('REFUSED')).error).toBe('REFUSED');
    expect(observe('A', 'example.com', ref(['192.0.2.1']), null, new DnsTimeoutError('192.0.2.53', 'example.com')).status).toBe('timeout');
    expect(observe('A', 'example.com', ref(['192.0.2.1']), null, new Error('EHOSTUNREACH')).status).toBe('error');
  });
  it('alias: compared on the CNAME target, not on the CDN addresses behind it', () => {
    const r = ref(['203.0.113.1'], { kind: 'cname', cname: 'new.cdn.example' });
    const fresh = res('NOERROR', [ans('www.example.com', 'CNAME', 'new.cdn.example.', 50), ans('new.cdn.example', 'A', '198.51.100.7', 20)]);
    expect(observe('A', 'www.example.com', r, fresh, undefined, AT)).toMatchObject({ status: 'fresh', ttl: 50 });
    const old = res('NOERROR', [ans('www.example.com', 'CNAME', 'old.cdn.example.', 50), ans('old.cdn.example', 'A', '198.51.100.7')]);
    expect(observe('A', 'www.example.com', r, old, undefined, AT).status).toBe('stale');
    const direct = res('NOERROR', [ans('www.example.com', 'A', '192.0.2.1', 30)]);
    expect(observe('A', 'www.example.com', r, direct, undefined, AT)).toMatchObject({ status: 'stale', ttl: 30 });
  });
  it('a resolver still serving an old CNAME where the zone now has records is stale', () => {
    const o = observe('A', 'www.example.com', ref(['192.0.2.1']), res('NOERROR', [ans('www.example.com', 'CNAME', 'old.example.net'), ans('old.example.net', 'A', '192.0.2.1')]));
    expect(o.status).toBe('stale');
  });
  it('expected value: compared with the end of the chain', () => {
    const r = ref(['192.0.2.1'], { source: 'expected' });
    const o = observe('A', 'www.example.com', r, res('NOERROR', [ans('www.example.com', 'CNAME', 'x.example.net'), ans('x.example.net', 'A', '192.0.2.1')]));
    expect(o.status).toBe('fresh');
  });
  it('TXT concatenation and MX normalisation', () => {
    expect(observe('TXT', 'example.com', ref(['v=spf1 -all']), res('NOERROR', [ans('example.com', 'TXT', [Buffer.from('v=spf1 '), Buffer.from('-all')])])).status).toBe('fresh');
    expect(observe('MX', 'example.com', ref(['10 mx.example.com']), res('NOERROR', [ans('example.com', 'MX', { preference: 10, exchange: 'MX.EXAMPLE.COM.' })])).status).toBe('fresh');
  });
});

describe('summarize', () => {
  const ev = (ip: string, status: ResolverEvent['status'], cc: string | null, anycast = false, refreshAt: string | null = null): ResolverEvent =>
    ({ ip, status, country_code: cc, continent: cc === 'FR' || cc === 'DE' ? 'EU' : cc === 'JP' ? 'AS' : null, anycast, refreshAt, values: [], cname: null }) as unknown as ResolverEvent;
  it('counts by status, country and continent; percentages over the resolvers that answered', () => {
    const s = summarize(
      [
        ev('1', 'fresh', 'FR'),
        ev('2', 'stale', 'FR', false, '2026-11-10T12:05:00.000Z'),
        ev('3', 'fresh', 'DE'),
        ev('4', 'timeout', 'JP'),
        ev('5', 'missing', 'JP', false, '2026-11-10T12:09:00.000Z'),
        ev('6', 'fresh', 'US', true),
      ],
      { source: 'authority', exists: true, kind: 'records', values: [], cname: null },
    );
    expect(s).toMatchObject({ total: 6, answered: 5, fresh: 3, stale: 1, missing: 1, timeout: 1, percentFresh: 60, complete: false });
    expect(s.global).toMatchObject({ total: 1, fresh: 1 });
    expect(s.byCountry.find((c) => c.country_code === 'FR')).toMatchObject({ total: 2, fresh: 1, percentFresh: 50 });
    expect(s.byContinent.find((c) => c.continent === 'EU')).toMatchObject({ total: 3, fresh: 2 });
    expect(s.byCountry.some((c) => c.country_code === 'US')).toBe(false); // anycast is not a country
    expect(s.allFreshBy).toBe('2026-11-10T12:09:00.000Z');
    expect(s.pendingIps).toEqual(['2', '4', '5']);
  });
});
