import { describe, expect, it } from 'vitest';
import type { Finding } from '../../knowledge/engine.js';
import { axisOf, classifyFindings, foldRequirements, impactOf, indicatorsOf } from './impact.js';

const f = (id: string, family: string, severity: Finding['severity'], penalty: number): Finding => ({ id, family, severity, penalty, title: id, why: '', fix: [], references: [] });
const none = { failingRequirements: [], saOverThreshold: false };

describe('axis of a finding', () => {
  it('puts DNS, authentication and server on the sender, composition on the message', () => {
    expect(axisOf(f('dmarc.policy_none', 'dmarc', 'low', 0.3))).toBe('sender');
    expect(axisOf(f('rdns.missing', 'rdns', 'high', 1.5))).toBe('sender');
    expect(axisOf(f('images.missing_alt', 'images', 'low', 0.2))).toBe('message');
    expect(axisOf(f('headers.date_missing', 'headers', 'high', 1))).toBe('message');
  });
  it('files SpamAssassin rules by the theme of their entry, or by their name without one', () => {
    expect(axisOf(f('sa.html_image_only_12', 'spamassassin', 'high', 1))).toBe('message');
    expect(axisOf(f('sa.dkim_signed', 'spamassassin', 'info', 0))).toBe('sender');
    expect(axisOf(f('sa.rcvd_in_unknown_list', 'spamassassin', 'medium', 0.5))).toBe('sender');
    expect(axisOf(f('sa.some_body_rule', 'spamassassin', 'medium', 0.5))).toBe('message');
  });
  it('keeps the one-click unsubscribe requirement on the message', () => {
    expect(axisOf(f('bulk-sender.one_click_required', 'bulk-sender', 'high', 0))).toBe('message');
    expect(axisOf(f('bulk-sender.dmarc_missing', 'bulk-sender', 'critical', 0))).toBe('sender');
  });
});

describe('impact on delivery', () => {
  it('reads the report of 2026-11-11: nothing blocks, one spam risk, the rest is advice', () => {
    const list = classifyFindings(
      [
        f('sa.html_image_only_12', 'spamassassin', 'high', 1),
        f('images.image_heavy', 'images', 'medium', 0),
        f('dkim.key_1024', 'dkim', 'low', 0.3),
        f('dmarc.policy_none', 'dmarc', 'low', 0.3),
        f('dmarc.rua_missing', 'dmarc', 'low', 0.3),
        f('links.http_not_https', 'links', 'low', 0.3),
        f('html.no_doctype', 'html', 'low', 0.1),
      ],
      none,
    );
    expect(Object.fromEntries(list.map((x) => [x.id, x.impact]))).toEqual({
      'sa.html_image_only_12': 'spam',
      'images.image_heavy': 'advice',
      'dkim.key_1024': 'advice',
      'dmarc.policy_none': 'advice',
      'dmarc.rua_missing': 'advice',
      'links.http_not_https': 'advice',
      'html.no_doctype': 'advice',
    });
    const ind = indicatorsOf(list);
    expect(ind.verdict).toBe('spam');
    expect(ind.sender).toMatchObject({ lost: 0.9, blocking: 0, spam: 0, advice: 3, status: 'advice' });
    expect(ind.message).toMatchObject({ lost: 1.4, spam: 1, status: 'spam' });
  });
  it('blocks on a critical finding and on the causes of an unmet Gmail requirement', () => {
    expect(impactOf(f('dmarc.fail_reject', 'dmarc', 'critical', 3), none)).toBe('blocking');
    const ptr = { failingRequirements: ['ptr'], saOverThreshold: false };
    expect(impactOf(f('rdns.missing', 'rdns', 'high', 1.5), ptr)).toBe('blocking');
    expect(impactOf(f('rdns.missing', 'rdns', 'high', 1.5), none)).toBe('spam');
    // a low finding of the same family does not become blocking
    expect(impactOf(f('dmarc.rua_missing', 'dmarc', 'low', 0.3), { failingRequirements: ['dmarc'], saOverThreshold: false })).toBe('advice');
  });
  it('blocks on the serious SpamAssassin rules once the score is over the threshold', () => {
    const over = { failingRequirements: [], saOverThreshold: true };
    expect(impactOf(f('sa.some_body_rule', 'spamassassin', 'high', 2), over)).toBe('blocking');
    expect(impactOf(f('sa.some_body_rule', 'spamassassin', 'low', 0.2), over)).toBe('advice');
    expect(impactOf(f('spamassassin.over_threshold', 'spamassassin', 'critical', 0), none)).toBe('blocking');
  });
  it('never calls a finding that costs no point a risk', () => {
    expect(impactOf(f('spf.helo_none', 'spf', 'info', 0), none)).toBe('advice');
    expect(impactOf(f('links.empty_href', 'links', 'low', 0.1), none)).toBe('advice');
  });
});

describe('one cause, one card for an unmet requirement', () => {
  // report of 2026-11-14: « Le message a été transmis sans chiffrement TLS » twice, −1 then 0
  it('folds the requirement into the card that carries the points', () => {
    const tls = { ...f('tls.inbound_plaintext', 'tls', 'high', 1), evidence: 'en clair' };
    const req = { ...f('bulk-sender.tls_required', 'bulk-sender', 'high', 0), evidence: 'Gmail et Yahoo : TLS : non' };
    const list = classifyFindings([tls, req], { failingRequirements: ['tls'], saOverThreshold: false });
    expect(foldRequirements(list, [{ id: 'tls', situation: 'bulk-sender.tls_required' }])).toEqual(['bulk-sender.tls_required']);
    expect(tls.evidence).toBe('en clair\nGmail et Yahoo : TLS : non');
  });
  it('keeps the requirement card when nothing else names the cause', () => {
    const req = f('bulk-sender.one_click_required', 'bulk-sender', 'high', 0);
    const list = classifyFindings([req], { failingRequirements: ['one_click'], saOverThreshold: false });
    expect(foldRequirements(list, [{ id: 'one_click', situation: 'bulk-sender.one_click_required' }])).toEqual([]);
  });
});
