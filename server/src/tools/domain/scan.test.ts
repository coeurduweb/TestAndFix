import { describe, expect, it } from 'vitest';
import { ResolveSession } from '../../dns/iterative.js';
import { GuardedResolver } from '../../lib/email-auth/common.js';
import { analyzeBlacklists } from './infra.js';
import { scanDomain } from './scan.js';

const live = () => new GuardedResolver(new ResolveSession(), () => new ResolveSession());

describe('domain scan regressions (2026-11-10)', () => {
  it('4. a non-existent domain gets a clear verdict, not the parent zone measured', async () => {
    const domain = `check-nx-${Date.now().toString(36)}.fr`;
    const r = await scanDomain(live(), domain, { makeSession: () => new ResolveSession() });
    expect(r.score).toBe(0);
    expect((r.data as { exists?: boolean }).exists).toBe(false);
    expect(r.findings[0].severity).toBe('critical');
    for (const id of ['ns', 'soa', 'dnssec', 'caa', 'blacklist', 'spf', 'dkim']) {
      const s = r.data.sections.find((x) => x.id === id)!;
      expect(s.status, id).toBe('unavailable');
      expect(s.passed, id).toEqual([]);
    }
  }, 60000);
  it('4. the blocklist summary says how many lists and IPs were really queried', async () => {
    const a = await analyzeBlacklists(live(), [], ['example.com'], () => new ResolveSession());
    const text = a.passed.map((p) => `${p.title} ${p.detail ?? ''}`).join(' ');
    expect(text).toMatch(/aucune IP/i);
    expect(text).toMatch(new RegExp(`${a.data.domainLists} listes? de domaines`));
  }, 60000);
});
