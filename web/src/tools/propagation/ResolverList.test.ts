import { describe, expect, it } from 'vitest';
import { lateCountries } from './ResolverList';
import type { Row } from './model';

const row = (ip: string, cc: string | null): Row => ({ info: { ip, country_code: cc } as Row['info'], remeasuring: false });

describe('folded continent line', () => {
  it('names each country with a real delay once, sorted', () => {
    const rows = [row('1', 'FR'), row('2', 'DE'), row('3', 'FR'), row('4', null), row('5', 'IT')];
    expect(lateCountries(rows, (r) => r.info.ip !== '5')).toEqual(['DE', 'FR']);
    expect(lateCountries(rows, () => false)).toEqual([]);
  });
});
