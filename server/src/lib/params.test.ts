import { describe, expect, it } from 'vitest';
import { intParam, likeContains } from './params.js';

describe('query parameters', () => {
  it('reads bounded integers, and falls back on anything else', () => {
    expect(intParam('20', 50, 1, 200)).toBe(20);
    expect(intParam('-1', 50, 1, 200)).toBe(1);
    expect(intParam('5000', 50, 1, 200)).toBe(200);
    expect(intParam('abc', 50, 1, 200)).toBe(50);
    expect(intParam(undefined, 0, 0, 10)).toBe(0);
    expect(intParam('1e9', 50, 1, 200)).toBe(50);
  });
  it('escapes LIKE wildcards', () => {
    expect(likeContains('50%_a\\b')).toBe('%50\\%\\_a\\\\b%');
  });
});
