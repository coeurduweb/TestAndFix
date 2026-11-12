import { beforeEach, describe, expect, it } from 'vitest';
import { clearLocalTraces, countsText, isCode, normalizeCode } from './carnet';

describe('link code', () => {
  it('tolerates case, spaces and a missing dash', () => {
    expect(normalizeCode('abcd efgh')).toBe('ABCD-EFGH');
    expect(normalizeCode('ABCDEFGH')).toBe('ABCD-EFGH');
    expect(normalizeCode(' ab-cd-ef-gh ')).toBe('ABCD-EFGH');
    expect(normalizeCode('abc')).toBe('ABC');
    expect(isCode(normalizeCode('abcd-efgh'))).toBe(true);
    expect(isCode('ABCD-EFG')).toBe(false);
  });
});

describe('counts in words', () => {
  it('leaves out the empty kinds and joins with "et"', () => {
    expect(countsText({ results: 12, mailMessages: 1, mailAddresses: 0, dmarcReports: 2 })).toBe('12 mesures, 1 message reçu et 2 rapports DMARC');
    expect(countsText({ results: 1, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 })).toBe('1 mesure');
    expect(countsText({ results: 0, mailMessages: 0, mailAddresses: 0, dmarcReports: 0 }, 'aucune donnée')).toBe('aucune donnée');
  });
});

describe('local traces', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
  it('removes every check: key but the theme, and nothing else', () => {
    localStorage.setItem('check:recent', '[]');
    localStorage.setItem('check:dkim-selectors', '[]');
    localStorage.setItem('check:theme', 'dark');
    localStorage.setItem('other', 'x');
    sessionStorage.setItem('check:pending-message', 'Received: x');
    expect(clearLocalTraces()).toBe(3);
    expect(localStorage.getItem('check:recent')).toBeNull();
    expect(localStorage.getItem('check:dkim-selectors')).toBeNull();
    expect(sessionStorage.getItem('check:pending-message')).toBeNull();
    expect(localStorage.getItem('check:theme')).toBe('dark');
    expect(localStorage.getItem('other')).toBe('x');
  });
});
