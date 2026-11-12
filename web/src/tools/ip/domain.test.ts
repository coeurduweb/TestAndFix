// The domain page developed against a fake stream that follows the contract of 2026-11-11.
import { describe, expect, it } from 'vitest';
import { domainAddresses, domainReducer, domainSummary, initialDomain } from './domain-model';
import { SseParser } from './sse';

const ev = (type: string, data: unknown) => `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
const row = (ip: string, status: string, listed: unknown[] = []) => ({ ip, status, listed, majorListed: listed.length, refused: [], errors: [], findings: [] });

function feed(text: string) {
  let s = initialDomain();
  const p = new SseParser((e) => (s = domainReducer(s, e)));
  // cut in small chunks, as the network does
  for (let i = 0; i < text.length; i += 37) p.push(text.slice(i, i + 37));
  p.end();
  return s;
}

const stream = [
  ev('start', { domain: 'exemple.fr', sources: [{ id: 'rdap', label: 'RDAP' }], lists: [{ zone: 'dbl.spamhaus.org', name: 'Spamhaus DBL', weight: 'major' }, { zone: 'multi.surbl.org', name: 'SURBL', weight: 'minor' }] }),
  ev('source', { source: 'dnsbl:multi.surbl.org', label: 'SURBL', ok: true, ms: 9, data: { zone: 'multi.surbl.org', name: 'SURBL', weight: 'minor', target: 'exemple.fr', query: 'exemple.fr.multi.surbl.org', status: 'listed', codes: ['127.0.0.8'], ms: 9 } }),
  ev('source', { source: 'a', label: 'A', ok: true, ms: 3, data: { ips: [{ ip: '192.0.2.10', family: 4 }] } }),
  ev('source', { source: 'mx', label: 'MX', ok: true, ms: 4, data: { hosts: [{ host: 'mx2.exemple.fr', preference: 20, ips: ['192.0.2.30'] }, { host: 'mx1.exemple.fr', preference: 10, ips: ['192.0.2.20'] }] } }),
  ev('source', { source: 'ip:192.0.2.20', label: '192.0.2.20', ok: true, ms: 50, data: row('192.0.2.20', 'listed', [{ zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN', weight: 'major', codes: ['127.0.0.2'], situation: 'blacklist.spamhaus_sbl' }]) }),
  ev('source', { source: 'rdap', label: 'RDAP', ok: true, ms: 80, data: { ageDays: 12 } }),
].join('');

describe('domain reputation stream', () => {
  it('folds the live events: listings, addresses web first then MX by preference, rows as they come', () => {
    const s = feed(stream);
    expect(s.domain).toBe('exemple.fr');
    expect(s.lists.map((l) => l.zone)).toEqual(['dbl.spamhaus.org', 'multi.surbl.org']);
    const addrs = domainAddresses(s);
    expect(addrs.map((a) => `${a.role}:${a.ip}`)).toEqual(['web:192.0.2.10', 'mail:192.0.2.20', 'mail:192.0.2.30']);
    expect(addrs[1].host).toBe('mx1.exemple.fr');
    expect(addrs[1].row?.status).toBe('listed');
    expect(domainSummary(s)).toMatchObject({ answered: 1, total: 2, listedAddresses: 1, addresses: 3, pendingAddresses: 2 });
    expect(domainSummary(s).listed.map((h) => h.name)).toEqual(['SURBL']);
  });

  it('takes the addresses of the final report once done', () => {
    const done = ev('done', {
      tool: 'ip', input: 'exemple.fr', measuredAt: '2026-11-11T10:00:00Z', score: 4, findings: [], passed: [],
      data: { domain: 'exemple.fr', exists: true, lists: { queried: 2, listed: [], refused: [], errors: [], clean: 2 }, addresses: [{ ip: '192.0.2.10', family: 4, role: 'web', host: 'exemple.fr', row: row('192.0.2.10', 'clean') }] },
    });
    const s = feed(stream + done);
    expect(s.result?.score).toBe(4);
    expect(domainAddresses(s).map((a) => a.row?.status)).toEqual(['clean']);
  });
});

import { addressGroups } from './domain-model';
describe('address groups', () => {
  it('puts the site first, then one group per MX by preference, with counts', () => {
    const g = addressGroups(feed(stream));
    expect(g.map((x) => `${x.role}:${x.host}:${x.preference ?? ''}`)).toEqual(['web:exemple.fr:', 'mail:mx1.exemple.fr:10', 'mail:mx2.exemple.fr:20']);
    expect(g[1]).toMatchObject({ listed: 1, pending: 0 });
    expect(g[2]).toMatchObject({ listed: 0, pending: 1 });
  });
});
