import { describe, expect, it } from 'vitest';
import type { Finding } from '../../knowledge/engine.js';
import { impactOf, markOutOfReach } from './impact.js';

const f = (id: string, family: string, severity: Finding['severity'], penalty: number): Finding =>
  ({ id, family, severity, penalty, title: id, why: '', fix: [], references: [] }) as Finding;

describe('decision precision (2026-11-12)', () => {
  it('a small SpamAssassin rule on a clean message is advice; it weighs when the rule or the total does', () => {
    const rule = f('sa.html_image_only_20', 'spamassassin', 'medium', 0.8);
    const sa = (total: number, score = 0.7) => ({ failingRequirements: [], saOverThreshold: false, sa: { total, threshold: 5, ruleScore: new Map([[rule.id, score]]) } });
    expect(impactOf(rule, sa(0.5))).toBe('advice');
    expect(impactOf(rule, sa(2.5))).toBe('spam');
    expect(impactOf(rule, sa(0.5, 1.2))).toBe('spam');
  });
  it('marks advice only the sending service can act on, never a real problem', () => {
    const helo = { ...f('spf.helo_none', 'spf', 'low', 0.1), impact: 'advice' as const };
    const doctype = { ...f('html.no_doctype', 'html', 'low', 0.1), impact: 'advice' as const };
    const dkim = { ...f('dkim.key_1024', 'dkim', 'low', 0.3), impact: 'advice' as const };
    const blocking = { ...f('helo.not_resolving', 'helo', 'high', 1), impact: 'spam' as const };
    markOutOfReach([helo, doctype, dkim, blocking], { helo: 'mail-ed1-f46.google.com', headers: [{ key: 'message-id', value: '<CAB+x@mail.gmail.com>' }] });
    expect([helo.outOfReach, doctype.outOfReach, dkim.outOfReach, blocking.outOfReach]).toEqual(['Google', 'Gmail', undefined, undefined]);
  });
});
