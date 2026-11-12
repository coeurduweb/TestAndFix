import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { domainFingerprint, parseSelectors } from './fingerprint.js';

describe('Fix loop fingerprint', () => {
  it('keeps valid selectors only, ten at most', () => {
    expect(parseSelectors('google, s1 ,bad sel,k1,../x,google')).toEqual(['google', 's1', 'k1']);
    expect(parseSelectors(Array.from({ length: 15 }, (_, i) => `s${i}`).join(','))).toHaveLength(10);
  });
  it('is the same twice in a row on a real domain, and names the records it read (live)', async () => {
    const a = await domainFingerprint(new ResolveSession(), 'gmail.com', ['20230601']);
    const b = await domainFingerprint(new ResolveSession(), 'gmail.com', ['20230601']);
    if (!a.complete || !b.complete) return; // no DNS from this machine: nothing to compare
    expect(a.hash).toBe(b.hash);
    expect(a.records.map((r) => `${r.type} ${r.name}`)).toContain('TXT _dmarc.gmail.com');
    expect(a.records.find((r) => r.name === 'gmail.com' && r.type === 'TXT')?.values.some((v) => v.startsWith('v=spf1'))).toBe(true);
  }, 30000);
});
