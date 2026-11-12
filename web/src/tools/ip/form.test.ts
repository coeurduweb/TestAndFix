import { describe, expect, it } from 'vitest';
import { invalidReason } from './Form';

describe('invalidReason', () => {
  it('lets addresses and /24 to /32 ranges through', () => {
    expect(invalidReason('8.8.8.8')).toBeNull();
    expect(invalidReason('2001:db8::1')).toBeNull();
    expect(invalidReason('203.0.113.0/29')).toBeNull();
  });
  it('says why the rest is refused, without calling the server', () => {
    expect(invalidReason('999.1.1.1')).toMatch(/de 0 à 255/);
    expect(invalidReason('10.0.0.0/8')).toMatch(/de \/24 à \/32/);
    expect(invalidReason('2001:db8::/64')).toMatch(/IPv6/);
    expect(invalidReason('bonjour')).toMatch(/ni une adresse IP ni un nom de domaine/);
  });
});
