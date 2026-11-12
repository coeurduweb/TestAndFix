import { beforeEach, describe, expect, it } from 'vitest';
import { forget, parseSelectors, remember, rememberedElsewhere, rememberedFor } from './selectors';

describe('parseSelectors', () => {
  it('accepts lists, full names, case and quotes', () => {
    expect(parseSelectors(' S2024, s2025 ;"s2026"')).toEqual(['s2024', 's2025', 's2026']);
    expect(parseSelectors('mte1._domainkey.exemple.fr')).toEqual(['mte1']);
    expect(parseSelectors('ovhmo123-selector1._domainkey.exemple.fr.')).toEqual(['ovhmo123-selector1']);
  });
  it('reads the s= tag of a pasted DKIM-Signature header', () => {
    const h = 'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=exemple.fr; s=20230601; t=1700000000; h=from:to; bh=abc=; b=xyz';
    expect(parseSelectors(h)).toEqual(['20230601']);
  });
  it('drops what cannot be a selector', () => {
    expect(parseSelectors('')).toEqual([]);
    expect(parseSelectors('a@b')).toEqual([]);
  });
});

describe('memory', () => {
  beforeEach(() => localStorage.clear());
  it('remembers per domain and offers them elsewhere', () => {
    remember('a.fr', ['cdw1']);
    remember('a.fr', ['cdw2', 'cdw1']);
    expect(rememberedFor('a.fr')).toEqual(['cdw1', 'cdw2']);
    expect(rememberedElsewhere('b.fr').map((x) => x.selector)).toEqual(['cdw1', 'cdw2']);
    expect(rememberedElsewhere('a.fr')).toEqual([]);
    forget('a.fr', 'cdw1');
    expect(rememberedFor('a.fr')).toEqual(['cdw2']);
  });
});
